// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "exif")]
//! Faithful port of `Image::ExifTool::Exif` (`lib/Image/ExifTool/Exif.pm`)
//! plus the TIFF-header front-end of `DoProcessTIFF` (`ExifTool.pm:8530-
//! 8730`).
//!
//! ## What Exif is — and why this is camera-metadata-core critical path
//!
//! Exif is the camera-tag IFD. Every camera maker / lens / model / GPS field
//! the product extracts flows through the Exif IFD machinery:
//!
//! - a standalone TIFF file (`File:FileType == "TIFF"`) IS an Exif/TIFF
//!   block — file-dispatchable directly;
//! - GPS is the coordinate sub-IFD reached through IFD0 tag `GPSInfo`
//!   (0x8825);
//! - vendor MakerNotes (Apple/Canon/Sony/…) are SubDirectories reached
//!   through the ExifIFD's `MakerNote` tag (0x927c);
//! - QuickTime / RIFF video files embed Exif/TIFF blocks.
//!
//! So this module is designed as a REUSABLE engine: [`parse_exif_block`]
//! takes an Exif/TIFF byte block and returns a typed [`ExifMeta`]. The IFD
//! walker is NOT locked to file-level dispatch — a future QuickTime/RIFF
//! port calls [`parse_exif_block`] on the embedded block.
//!
//! ## Structure (Exif.pm + ExifTool.pm)
//!
//! - **TIFF header** (`ExifTool.pm:8628-8645`): 2-byte byte order
//!   (`II`/`MM`), the 16-bit magic (0x2a for TIFF), the 32-bit IFD0 offset.
//!   The 0x2b magic is **BigTIFF** — a 16-byte header (offset-bytesize 8,
//!   8-byte IFD0 offset) walked by the dedicated [`parse_bigtiff`] path
//!   (8-byte counts, 20-byte entries), the faithful port of
//!   `Image::ExifTool::BigTIFF` (a SEPARATE walker reusing `Exif::Main`).
//! - **IFD walker** (`Exif.pm:6278-7240 ProcessExif`): each IFD is an
//!   entry-count (`int16u`) + N×12-byte entries + a next-IFD-offset
//!   (`int32u`). Each entry is `tag(u16) format(u16) count(u32)
//!   value-or-offset(u32)`. A value ≤ 4 bytes is stored inline; otherwise
//!   the 4 bytes are an offset into the TIFF block (`Exif.pm:6504-6510`).
//! - **IFD chain**: IFD0 → IFD1 (thumbnail, via the next-IFD pointer,
//!   `Exif.pm:7203-7240`) → ExifIFD (SubIFD via 0x8769) → GPS IFD (0x8825)
//!   → InteropIFD (0xa005).
//! - **Type decoders**: the 13 TIFF types — see [`ifd`] (`ReadValue`,
//!   `ExifTool.pm:6275-6321`).
//! - **Tag tables**: [`tables`] (`%Exif::Main`) + [`gps`] (`%GPS::Main`).
//!
//! ## MakerNote (0x927c) — deferred to the MakerNotes wave
//!
//! When the ExifIFD has a `MakerNote` tag, the walker captures the raw bytes
//! into [`ExifMeta`] and notes the deferral; it does NOT parse vendor
//! MakerNotes. The SubDirectory-dispatch seam ([`SubDirKind::MakerNote`]) is
//! designed so a MakerNotes port plugs in. See `docs/tracking.md`.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// the IFD walker (`walk_entry`, `walk_ifd`, the SubDirectory rebasers) is
// heavily guarded (entry-offset / value-window bounds checks); every raw
// index/slice below is converted to a checked `.get()` (or routed through the
// `ifd::get_u16/get_u32/read_value` bounds-checked helpers), landing on the
// same Step/Option recovery so the output stays byte-identical.
#![deny(clippy::indexing_slicing)]

pub mod ifd;
pub mod makernotes;
// `tables` / `gps` hold the const `%Exif::Main` / `%GPS::Main` tag-table
// rows (`ExifTag` / `GpsTag` — public fields for `const` struct-literal
// init). They are NOT public API surface (D8: no public struct fields on
// API types) — `pub(crate)`, matching `formats::matroska`'s private
// `TagDef` / `StdTagEntry` tag-table convention. `ifd` stays public: its
// `ByteOrder` / `Format` / `read_value` are the reusable IFD-decode infra
// a future QuickTime / RIFF port consumes.
pub(crate) mod tables;

// `ConvertExifText` (`Exif.pm:5554-5601`) lives in `Exif.pm`, not `GPS.pm`:
// it is the `RawConv` for ExifIFD's `UserComment` (0x9286) AND the GPS
// sub-IFD's `GPSProcessingMethod` / `GPSAreaInformation`. So it is gated on
// `feature = "exif"` (NOT `gps`) and the GPS table re-uses it.
pub(crate) mod exiftext;

#[cfg(feature = "gps")]
pub(crate) mod gps;

// `render` holds the single faithful default (no-PrintConv) `RawValue` →
// `TagValue` renderer (`render_value`) — the golden-pattern L3b shared
// renderer that consolidates `emit_raw`'s default path with the Apple
// MakerNote `to_default_tag_value`. `pub(crate)`: an internal emission helper,
// not API surface. Gated on `alloc` (matches the surrounding emission code).
#[cfg(feature = "alloc")]
pub(crate) mod render;

// `jpeg` is the JPEG-container front-end: the marker walk that reaches the
// embedded `APP1` Exif block and hands it to [`parse_exif_block`]. A camera
// JPEG (`File:FileType == "JPEG"`) is the primary camera-photo format; bundled
// reaches its Exif via `ProcessJPEG`'s `APP1` Exif arm (ExifTool.pm:7736-7783).
// Gated on `feature = "exif"` (it produces an `ExifMeta`, reusing the IFD
// walker); the GPS sub-IFD is decoded through the same block.
pub mod jpeg;

use std::{string::String, vec::Vec};

use crate::{
  format_parser::{FormatParser, parser_sealed},
  recovery::Step,
};
use ifd::{ByteOrder, Format, RawValue, get_u16, get_u32, get_u64, read_value};
use makernotes::subdir::{ByteOrderRule, FixBaseMode, ProcessProc, TableRef};
use tables::Conv;

// ====================================================================// IFD identity — the family-1 group an IFD's tags carry
// ====================================================================
/// The kind of IFD currently being walked — drives the family-1 group of
/// the tags it emits. `ProcessExif` sets `$$dirInfo{DirName}` to one of
/// these (`ExifTool.pm:8688` IFD0; `Exif.pm:7064-7077` `SubdirInfo{DirName}`
/// from the SubDirectory's `DirName`) and `SetGroup` then tags every
/// FoundTag with it (`Exif.pm:7184` `SetGroup($tagKey, $dirName)`).
///
/// D8: enum predicates + `as_str` (the family-1 group string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfdKind {
  /// IFD0 — the main image directory (`ExifTool.pm:8688`).
  Ifd0,
  /// A trailing IFD reached by following the next-IFD pointer chain — IFD1
  /// (the thumbnail), IFD2, IFD3… The payload is the 1-based directory
  /// number ExifTool assigns at `Exif.pm:7215-7216`
  /// (`$ifdNum = DirName =~ s/(\d+)$//; DirName .= $ifdNum + 1`): IFD0's
  /// next pointer yields `Trailing(1)`, IFD1's yields `Trailing(2)`, etc.
  /// The number is unbounded — ExifTool's `$ifdNum + 1` is plain Perl
  /// arithmetic with no cap, and `walk_ifd_chain` follows the chain with
  /// `for (;;)` faithfully (`Exif.pm:7211`). The discriminant is `u32` so a
  /// chain past IFD65535 keeps incrementing the decimal `DirName` (IFD65536,
  /// IFD65537…) instead of pinning at 65535 and mislabeling later IFDs.
  Trailing(u32),
  /// ExifIFD — the Exif sub-IFD (via IFD0 tag 0x8769).
  ExifIfd,
  /// GPS — the GPS sub-IFD (via IFD0 tag 0x8825).
  Gps,
  /// InteropIFD — the interoperability sub-IFD (via ExifIFD tag 0xa005).
  Interop,
}

/// An IFD family-1 group name (`"IFD0"`, `"IFD1"`, …, `"ExifIFD"`, `"GPS"`,
/// `"InteropIFD"`) rendered into a fixed inline buffer — no heap allocation,
/// no `alloc` dependency, and (unlike a `&'static str` literal table) no
/// upper bound on the trailing-IFD number it can spell.
///
/// `walk_ifd_chain` follows the next-IFD chain with `for (;;)`
/// (`Exif.pm:7211`); the trailing-IFD number is a `u32`, so a trailing name
/// can be up to `"IFD4294967295"` (13 bytes) and `"InteropIFD"` (10 bytes)
/// is the widest sub-IFD name — the 13-byte buffer covers both. [`Deref`]s
/// to `&str`, so it drops straight into the `write_*` sinks (which already
/// take `&str`).
#[derive(Debug, Clone, Copy)]
pub struct IfdName {
  /// UTF-8 bytes of the name; only `[..len]` is meaningful.
  buf: [u8; 13],
  /// Byte length of the rendered name. The widest name is the trailing-IFD
  /// name `"IFD4294967295"` (13 bytes); `"InteropIFD"` (10 bytes) is the
  /// widest sub-IFD name.
  len: u8,
}

impl IfdName {
  /// Render `"IFD{n}"` into the inline buffer (`n` decimal, no leading
  /// zeros) — the family-1 group of trailing-IFD number `n`
  /// (`Exif.pm:7215-7216`).
  #[must_use]
  fn ifd(n: u32) -> Self {
    let mut buf = [0u8; 13];
    buf[0] = b'I';
    buf[1] = b'F';
    buf[2] = b'D';
    // Decimal-render `n` (max `4294967295`, ten digits) after the `IFD`
    // prefix. `digits.iter_mut()` (least-significant first) is panic-safe by
    // construction — it visits at most 10 slots, so `ndigits` cannot exceed
    // `digits.len()`; the loop stops at `value == 0`, identical to the
    // index-write version.
    let mut digits = [0u8; 10];
    let mut value = n;
    let mut ndigits = 0usize;
    for slot in &mut digits {
      *slot = b'0' + (value % 10) as u8;
      value /= 10;
      ndigits += 1;
      if value == 0 {
        break;
      }
    }
    // Copy the `ndigits` digits MOST-significant first into `buf[3..]`. Both
    // `digits.get(..ndigits)` (ndigits ≤ 10) and `buf.get_mut(3..3+ndigits)`
    // (3+ndigits ≤ 13) are `Some` — the checked, byte-identical form of the
    // `buf[3 + i] = digits[ndigits - 1 - i]` reverse copy (the unreachable
    // `None` arm leaves `buf` zeroed, never taken).
    if let (Some(src), Some(dst)) = (digits.get(..ndigits), buf.get_mut(3..3 + ndigits)) {
      for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
        *d = *s;
      }
    }
    Self {
      buf,
      len: (3 + ndigits) as u8,
    }
  }

  /// Wrap a `&'static str` literal (the fixed sub-IFD names). The callers pass
  /// only `"IFD0"` / `"ExifIFD"` / `"GPS"` / `"InteropIFD"` (≤ 10 bytes), which
  /// fit the 13-byte buffer.
  #[must_use]
  fn literal(s: &str) -> Self {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 13];
    // Copy `bytes` into the buffer prefix. `min(buf.len())` clamps the copy to
    // the 13-byte capacity so `buf.get_mut(..n)` / `bytes.get(..n)` are both
    // `Some` — the checked, panic-safe form of the `while i < bytes.len() {
    // buf[i] = bytes[i] }` copy; for the ≤ 10-byte sub-IFD literals the clamp
    // never trims, so the rendered name is byte-identical.
    let n = bytes.len().min(buf.len());
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), bytes.get(..n)) {
      dst.copy_from_slice(src);
    }
    Self { buf, len: n as u8 }
  }

  /// The rendered name as a `&str`.
  #[must_use]
  #[inline]
  pub fn as_str(&self) -> &str {
    // SAFETY-free: `buf[..len]` is always ASCII (`IFD`, digits, or an
    // ASCII literal), so it is valid UTF-8 by construction. `len` is set to
    // `3+ndigits` / the clamped literal length — both ≤ 13 = `buf.len()` — so
    // `buf.get(..len)` is `Some` (the `.unwrap_or(&self.buf)` fallback is
    // unreachable): the checked, byte-identical form of `&self.buf[..len]`.
    let bytes = self.buf.get(..self.len as usize).unwrap_or(&self.buf);
    core::str::from_utf8(bytes).unwrap_or("IFD?")
  }
}

impl core::ops::Deref for IfdName {
  type Target = str;
  #[inline]
  fn deref(&self) -> &str {
    self.as_str()
  }
}

impl core::fmt::Display for IfdName {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl PartialEq<str> for IfdName {
  #[inline]
  fn eq(&self, other: &str) -> bool {
    self.as_str() == other
  }
}

impl PartialEq<&str> for IfdName {
  #[inline]
  fn eq(&self, other: &&str) -> bool {
    self.as_str() == *other
  }
}

impl PartialEq<IfdName> for IfdName {
  #[inline]
  fn eq(&self, other: &IfdName) -> bool {
    self.as_str() == other.as_str()
  }
}

impl Eq for IfdName {}

impl IfdKind {
  /// The family-1 group name this IFD's tags carry in `-G1` output.
  /// A trailing IFD numbered `n` renders `IFDn` (`Exif.pm:7215-7216`).
  /// Returns an inline-buffer [`IfdName`] (no heap allocation) so the
  /// trailing-IFD number is unbounded — faithful to ExifTool's uncapped
  /// `for (;;)` chain walk (`Exif.pm:7211`).
  #[must_use]
  #[inline]
  pub fn as_str(self) -> IfdName {
    match self {
      IfdKind::Ifd0 => IfdName::literal("IFD0"),
      IfdKind::Trailing(n) => IfdName::ifd(n),
      IfdKind::ExifIfd => IfdName::literal("ExifIFD"),
      IfdKind::Gps => IfdName::literal("GPS"),
      IfdKind::Interop => IfdName::literal("InteropIFD"),
    }
  }

  /// `true` for the GPS sub-IFD (its tags use the [`gps`] table).
  #[must_use]
  #[inline(always)]
  pub const fn is_gps(self) -> bool {
    matches!(self, IfdKind::Gps)
  }
}

/// The tag table a core IFD walks against, derived from its [`IfdKind`] — the
/// faithful `$tagTablePtr` each `ProcessExif` directory carries
/// (`Exif.pm:6341`). IFD0/ExifIFD/trailing IFDs and the Interop IFD use
/// `%Exif::Main` (Interop has no table of its own — `Exif.pm:6939`); the GPS
/// IFD uses `%GPS::Main`. This is the bridge that lets [`Walker::active_table`]
/// be seeded from an `IfdKind` so the table-keyed lookup reproduces the prior
/// `IfdKind::is_gps`-keyed selection byte-for-byte.
#[must_use]
#[inline]
const fn table_for_ifd_kind(kind: IfdKind) -> TableRef {
  match kind {
    IfdKind::Gps => TableRef::Gps,
    IfdKind::Interop => TableRef::Interop,
    IfdKind::Ifd0 | IfdKind::Trailing(_) | IfdKind::ExifIfd => TableRef::Exif,
  }
}

// ====================================================================// SubDirectory dispatch seam — `SubDirKind`
// ====================================================================
/// The SubDirectory a pointer tag dispatches into — the seam that keeps the
/// IFD walker reusable and lets a future MakerNotes port plug in.
///
/// ExifTool's SubDirectory dispatch (`Exif.pm:6913-7100`) recurses
/// `ProcessExif` on the pointed-to IFD with a new `DirName` + (for
/// MakerNotes) a new tag table. The four pointer tags
/// (0x8769/0x8825/0xa005/0x927c) map here.
///
/// D8: enum predicates; `#[non_exhaustive]` so a MakerNotes wave can add
/// vendor arms without breaking matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubDirKind {
  /// `ExifOffset` (0x8769) — recurse into the ExifIFD (`%Exif::Main`).
  ExifIfd,
  /// `GPSInfo` (0x8825) — recurse into the GPS IFD (`%GPS::Main`).
  Gps,
  /// `InteropOffset` (0xa005) — recurse into the InteropIFD (`%Exif::Main`).
  Interop,
  /// `MakerNote` (0x927c) — the vendor MakerNotes blob. **Vendor parsing is
  /// deferred to the MakerNotes wave** (`docs/tracking.md`); the Exif walker
  /// captures the raw bytes. This variant IS the plug-in seam: a MakerNotes
  /// port adds the per-vendor dispatch behind it.
  MakerNote,
}

impl SubDirKind {
  /// `true` for a SubIFD/offset pointer tag whose value MUST be an integer
  /// format (`$$tagInfo{IsOffset} or $$tagInfo{SubIFD}`, `Exif.pm:6747`).
  ///
  /// `ExifOffset` (0x8769, `SubIFD => 2`, `Exif.pm:2009`), `GPSInfo` (0x8825,
  /// `Flags => 'SubIFD'`, `Exif.pm:2134`) and `InteropOffset` (0xa005, `Flags
  /// => 'SubIFD'`, `Exif.pm:2723`) all carry the SubIFD flag, so a
  /// non-integer on-disk format triggers the `Wrong format` warning + skip.
  /// `MakerNote` (0x927c) is a plain `SubDirectory` reference with NEITHER
  /// `IsOffset` NOR `SubIFD` (`Exif.pm:2496`), so the check does NOT apply —
  /// a string-typed MakerNote is parsed as usual.
  #[must_use]
  #[inline(always)]
  pub const fn is_sub_ifd(self) -> bool {
    matches!(
      self,
      SubDirKind::ExifIfd | SubDirKind::Gps | SubDirKind::Interop
    )
  }

  /// The `$$tagInfo{Name}` of the pointer tag in the Exif main table — used
  /// in the `Wrong format` warning. The four pointer tags are NOT in the
  /// leaf-lookup [`tables`] table (they are handled structurally by the IFD
  /// walker), so their names live here: `ExifOffset` (`Exif.pm:2007`),
  /// `GPSInfo` (`Exif.pm:2131`), `InteropOffset` (`Exif.pm:2721`), `MakerNote`
  /// (`MakerNotes.pm` `%Main`, `Exif.pm:2496`).
  #[must_use]
  #[inline(always)]
  pub const fn tag_name(self) -> &'static str {
    match self {
      SubDirKind::ExifIfd => "ExifOffset",
      SubDirKind::Gps => "GPSInfo",
      SubDirKind::Interop => "InteropOffset",
      SubDirKind::MakerNote => "MakerNote",
    }
  }
}

// ====================================================================// Typed value carrier — `ExifValue<'a>`
// ====================================================================
/// One decoded Exif/GPS tag value — the post-Format-decode, pre-conversion
/// `$val`.
///
/// The IFD walker stores [`ifd::RawValue`] directly; conversions happen at
/// [`ExifMeta::serialize_tags`] time, faithful to ExifTool deferring
/// PrintConv/ValueConv to its `GetValue`/`PrintValue` layer.
///
/// `ExifValue` is fully OWNED — `RawValue::Text`/`Bytes` are decoded copies
/// (a TIFF `string` is NUL-trimmed and a value-data slice may sit outside
/// the inline 4-byte window). It carries no input-buffer lifetime; the
/// borrowed surface ([`MakerNote`]) lives on [`ExifMeta`].
#[derive(Debug, Clone)]
pub struct ExifValue {
  /// The raw decoded value.
  raw: RawValue,
}

impl ExifValue {
  /// Wrap a decoded [`RawValue`].
  #[must_use]
  #[inline(always)]
  const fn new(raw: RawValue) -> Self {
    Self { raw }
  }

  /// The raw decoded value (post-Format-decode, pre-conversion).
  #[must_use]
  #[inline(always)]
  pub const fn raw(&self) -> &RawValue {
    &self.raw
  }
}

// ====================================================================// One emitted tag — `ExifEntry<'a>`
// ====================================================================
/// One emitted Exif/GPS tag — the family-1 group, the on-disk tag ID, the
/// resolved name, and the decoded value. Faithful to a single ExifTool
/// `FoundTag` call (`Exif.pm:7181`). Fully OWNED (no input-buffer lifetime).
#[derive(Debug, Clone)]
pub struct ExifEntry {
  /// Which IFD this tag was found in (drives the `-G1` family-1 group).
  ifd: IfdKind,
  /// The on-disk tag ID.
  tag_id: u16,
  /// The resolved tag name (`%Exif::Main`/`%GPS::Main` `Name`).
  name: &'static str,
  /// The decoded value.
  value: ExifValue,
  /// The ON-DISK TIFF format the entry was written with (the `$format` a
  /// `Condition` reads, `GetTagInfo`), captured BEFORE any tag-table `Format`
  /// override re-interprets the value bytes. Threaded so the Sony `%Main`
  /// `$format`-gated single-HASH rows (0x1000/0x1001/0x1002) can be suppressed at
  /// emit time exactly as `parse_in_tiff` does (#243 phase 3); the core Exif/GPS
  /// emit + the other vendors ignore it.
  on_disk_format: Format,
  /// The RESOLVED on-disk value offset into the `Walker`'s buffer (`self.data`) —
  /// the inline `entry + 8` (size ≤ 4) or the out-of-line `raw_off +
  /// value_offset_base` (`Exif.pm:6510`/`:6546`), AFTER the relative-base shift.
  /// Carries ExifTool's `$valuePtr` so a vendor capture loop can re-slice the
  /// ON-DISK value bytes (the `RawValue`-shape-independent SPAN) exactly as the
  /// retired per-vendor walker did from its own `value_offset`/`value_size` —
  /// e.g. the Nikon sub-table emitters, which read
  /// `walk_data[value_offset .. value_offset + value_size]` regardless of how the
  /// leaf decoded (#243 phase 3-bis). The core Exif/GPS emit + every other consumer
  /// ignore it.
  value_offset: usize,
  /// The ON-DISK value byte size — `count * on_disk_format.byte_size()` BEFORE any
  /// tag-table `Format` override or the `undef[1] → int8u` carve-out re-shapes the
  /// decode (ExifTool's `$size`, `Exif.pm:6502`). Paired with [`value_offset`] to
  /// re-slice the verbatim value SPAN; faithful to the Nikon oracle's
  /// `NikonEntry { value_size: total_size }`. Ignored by every consumer but the
  /// vendor span re-slice.
  value_size: usize,
  /// The conversion ExifTool applies to this tag at serialize time.
  conv: ResolvedConv,
}

impl ExifEntry {
  /// Which IFD this tag belongs to.
  #[must_use]
  #[inline(always)]
  pub const fn ifd(&self) -> IfdKind {
    self.ifd
  }

  /// The family-1 group name (`"IFD0"`, `"ExifIFD"`, `"GPS"`, …). Returns
  /// an inline-buffer [`IfdName`] (no heap allocation) that [`Deref`]s to
  /// `&str` — a trailing IFD numbered `n` renders `IFDn` for any `n`.
  #[must_use]
  #[inline]
  pub fn group(&self) -> IfdName {
    self.ifd.as_str()
  }

  /// The on-disk tag ID.
  #[must_use]
  #[inline(always)]
  pub const fn tag_id(&self) -> u16 {
    self.tag_id
  }

  /// The resolved tag name.
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// The decoded value (borrow of the non-`Copy` [`ExifValue`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &ExifValue {
    &self.value
  }

  /// The ON-DISK TIFF format the entry was written with (pre-`Format`-override) —
  /// the `$format` a bundled `Condition` reads. Consumed by the Sony emit's
  /// `$format`-gated single-HASH rows; every other emit path ignores it.
  #[must_use]
  #[inline(always)]
  pub const fn on_disk_format(&self) -> Format {
    self.on_disk_format
  }

  /// The RESOLVED on-disk value offset into the `Walker`'s buffer — ExifTool's
  /// `$valuePtr` (inline `entry + 8` / out-of-line `raw_off + value_offset_base`).
  /// Paired with [`value_size`](Self::value_size) to re-slice the verbatim
  /// value SPAN (the Nikon sub-table-emitter feed, #243 phase 3-bis); ignored by
  /// the core Exif/GPS emit and every other consumer.
  #[must_use]
  #[inline(always)]
  pub const fn value_offset(&self) -> usize {
    self.value_offset
  }

  /// The ON-DISK value byte size (`count * on_disk_format.byte_size()`, ExifTool's
  /// `$size`) — captured BEFORE any `Format` override / `undef[1] → int8u`
  /// carve-out reshapes the decode, so the SPAN matches the bytes ExifTool's child
  /// `ProcessBinaryData` walker reads. Paired with [`value_offset`](Self::value_offset).
  #[must_use]
  #[inline(always)]
  pub const fn value_size(&self) -> usize {
    self.value_size
  }
}

/// Which tag-table descriptor an entry's value is converted under at serialize
/// time. Internal — `ExifEntry` carries the resolved `'static` descriptor so the
/// emit reads its golden [`ExifTag::value_conv`]/[`ExifTag::print_conv`] (the
/// `Walker`'s golden conversion-resolution point, #243 phase 0) without
/// re-looking-up, and reads its raw [`Conv`]/[`gps::GpsConv`] for the bespoke
/// `RawValue`-shaped fallback.
#[derive(Debug, Clone, Copy)]
enum ResolvedConv {
  /// An Exif IFD leaf (`%Exif::Main` descriptor).
  Exif(&'static tables::ExifTag),
  /// A GPS IFD leaf (`%GPS::Main` descriptor).
  #[cfg(feature = "gps")]
  Gps(&'static gps::GpsTag),
  /// A Canon maker-note leaf (`%Canon::Main` descriptor). Carries the resolved
  /// [`CanonTag`](makernotes::vendors::canon::tags::CanonTag) so the emit reapplies
  /// its [`CanonPrintConv`](makernotes::vendors::canon::printconv::CanonPrintConv)
  /// (the same render `parse_in_tiff` does at collection time, `canon/mod.rs`) and
  /// reads its `Unknown=>1` flag. Step A of the Canon engine migration (#243 phase
  /// 2): the shared `Walker` resolves Canon leaf names/convs here when
  /// `active_table == Canon`, while production still routes Canon through
  /// `parse_in_tiff` (so conformance is unchanged) — proven byte-identical by the
  /// differential test in `mod.rs`.
  Canon(&'static makernotes::vendors::canon::tags::CanonTag),
  /// An Apple maker-note leaf (`%Apple::Main` descriptor). Carries the resolved
  /// [`AppleTag`](makernotes::vendors::apple::tags::AppleTag) so the emit reapplies
  /// its [`ApplePrintConv`](makernotes::vendors::apple::printconv::ApplePrintConv)
  /// (the same render `parse_with_print_conv` does at collection time,
  /// `apple/mod.rs`) and reads its `Unknown=>1` flag. Apple is the SIMPLE vendor
  /// case (#243 phase 3): a BLOB-only table with no DataMember pre-scan, no binary
  /// sub-tables, and no model-conditionals — so the shared `Walker` walking the
  /// Apple Main IFD under `active_table == Apple` reproduces `walk_apple_body`
  /// exactly (base 0, out-of-line offsets resolve blob-relative).
  Apple(&'static makernotes::vendors::apple::tags::AppleTag),
  /// A Sony maker-note leaf (`%Sony::Main` descriptor). Carries the resolved
  /// [`SonyTag`](makernotes::vendors::sony::tags::SonyTag) so the emit reapplies
  /// its [`SonyPrintConv`](makernotes::vendors::sony::printconv::SonyPrintConv) —
  /// with the model + `AFAreaILCx` DataMember context for the four
  /// conditional-ARRAY AF tags — and the per-entry suppression gates
  /// (SubDirectory skip, single-HASH `Condition`, sentinel RawConv drop) the
  /// retired `parse_in_tiff` applied at collection time (`sony/mod.rs:311-404`).
  /// Sony is the COMPLEX vendor case (#243 phase 3): the shared `Walker` walks the
  /// Sony Main IFD under `active_table == Sony` (parent-TIFF data, base 0, parent
  /// order) reproducing `walk_sony_in_tiff`, but the per-leaf render lives in
  /// [`emit_sony_value`] (NOT `emit_entry`) because of those gates + the in-IFD
  /// af_area thread.
  Sony(&'static makernotes::vendors::sony::tags::SonyTag),
  /// A Panasonic maker-note leaf (`%Panasonic::Main` descriptor). Carries the
  /// resolved [`PanasonicTag`](makernotes::vendors::panasonic::tags::PanasonicTag)
  /// so the emit reapplies its
  /// [`PanasonicPrintConv`](makernotes::vendors::panasonic::printconv::PanasonicPrintConv)
  /// — with the model-conditional 0x0f AFAreaMode / 0x2c ContrastMode branch
  /// selection — and the per-entry suppression gates (SubDirectory skip, the
  /// `$format`-gated single-HASH `Condition` rows 0xc4/0xc5/0xe4, the 0x86/0xd1
  /// RawConv sentinel drop, the 0xc5/0xe4 LensTypeModel zero-drop) the retired
  /// `parse_in_tiff` applied at collection time (`panasonic/mod.rs:660-734`).
  /// Like Sony, the per-leaf render lives in [`emit_panasonic_value`] (NOT
  /// `emit_entry`) because of those gates; the shared `Walker` walks the
  /// Panasonic Main IFD under `active_table == Panasonic` reproducing
  /// `walk_panasonic_in_tiff` — including the DC-FT7 `Base => 12` out-of-line
  /// shift via [`value_offset_base`](Walker::value_offset_base) (#243 phase 3).
  Panasonic(&'static makernotes::vendors::panasonic::tags::PanasonicTag),
  /// A Nikon maker-note leaf (`%Nikon::Main` OR `%Nikon::Type2` descriptor).
  /// Carries the resolved [`NikonTag`](makernotes::vendors::nikon::tags::NikonTag)
  /// so the emit reapplies its [`NikonConv`](makernotes::vendors::nikon::NikonConv)
  /// — with the model + byte-order context — and reads its `Unknown=>1` flag, the
  /// same render `parse_in_tiff` does at collection time (`nikon/mod.rs:410-432`).
  /// Nikon is the MOST complex vendor case (#243 phase 3-bis): a decrypt-key
  /// prescan, model-conditional convs, RawConv drops, and binary sub-tables. The
  /// shared `Walker` walks the Nikon Main/Type2 IFD under `active_table ∈ {Nikon,
  /// NikonType2}` reproducing the entry-walk of `walk_nikon_ifd`, but (like Sony)
  /// the per-leaf render lives in [`emit_nikon_value`] (NOT `emit_entry`) because
  /// it must handle the `RawConv => … : undef` drop and thread the IFD byte order.
  /// Phase N1 wires the leaf resolve+render (production still walks
  /// `walk_nikon_ifd`); the sub-table dispatch + the dedicated capture loop land
  /// in N2 — proven byte-identical by the differential test in `mod.rs`.
  Nikon(&'static makernotes::vendors::nikon::tags::NikonTag),
}

impl ResolvedConv {
  /// The family-1 group OVERRIDE for a vendor maker-note leaf — `Some("Canon")`
  /// for a [`ResolvedConv::Canon`] leaf, `None` for a core Exif/GPS leaf (which
  /// keeps its kind-derived [`IfdName`] group). The bridge from the emit-time
  /// `ResolvedConv` discriminant to [`vendor_group1_of`] (the table-keyed rule
  /// the Walker applies during the walk).
  #[inline]
  fn vendor_group1(self) -> Option<&'static str> {
    match self {
      ResolvedConv::Exif(_) => vendor_group1_of(TableRef::Exif),
      #[cfg(feature = "gps")]
      ResolvedConv::Gps(_) => vendor_group1_of(TableRef::Gps),
      ResolvedConv::Canon(_) => vendor_group1_of(TableRef::Canon),
      ResolvedConv::Apple(_) => vendor_group1_of(TableRef::Apple),
      ResolvedConv::Sony(_) => vendor_group1_of(TableRef::Sony),
      ResolvedConv::Panasonic(_) => vendor_group1_of(TableRef::Panasonic),
      // A Nikon leaf (Main OR Type2) groups under `Nikon` — both `vendor_group1_of`
      // arms return `Some("Nikon")`; the discriminant carries no table, so the
      // `Nikon` arm covers it (the Type2 walk emits under the same vendor group).
      ResolvedConv::Nikon(_) => vendor_group1_of(TableRef::Nikon),
    }
  }
}

/// The family-1 group a leaf walked under `table` emits in, OR `None` when the
/// leaf keeps its kind-derived [`IfdName`] group (`IFD0`/`ExifIFD`/`GPS`/…).
///
/// ExifTool tags a maker-note leaf with the vendor's group1 (`Canon`/`Sony`/…),
/// not the `IfdName` of the directory it physically lives in — `parse_in_tiff`
/// pushes every Canon `VendorEmission` under `("MakerNotes","Canon")`
/// (`ExifMeta::push_maker_note_tags`). A CORE IFD table
/// ([`TableRef::is_core_ifd`]) returns `None`, so the emit keeps the existing
/// kind-derived family-1 group BYTE-IDENTICALLY (the conformance suite proves
/// this for Exif/GPS/Interop). Step A wires only `Canon`; the other vendor arms
/// land with the Phase-2 per-vendor migrations.
#[inline]
const fn vendor_group1_of(table: TableRef) -> Option<&'static str> {
  match table {
    TableRef::Canon => Some("Canon"),
    // `%Apple::Main` — phase 3 of the engine migration (#243). An Apple maker-note
    // leaf emits under the `Apple` family-1 group, exactly as
    // `parse_with_print_conv` + `push_maker_note_tags` push every Apple
    // `VendorEmission` under `("MakerNotes","Apple")`.
    TableRef::Apple => Some("Apple"),
    // `%Sony::Main` — phase 3 of the engine migration (#243). A Sony maker-note
    // leaf emits under the `Sony` family-1 group, exactly as `parse_in_tiff` +
    // `push_maker_note_tags` push every Sony `VendorEmission` under
    // `("MakerNotes","Sony")` (`Sony.pm:710` declares only `GROUPS => { 0 =>
    // 'MakerNotes' }`, so ExifTool derives family-1 from the vendor module).
    TableRef::Sony => Some("Sony"),
    // `%Panasonic::Main` — phase 3 of the engine migration (#243). A Panasonic
    // maker-note leaf emits under the `Panasonic` family-1 group, exactly as
    // `parse_in_tiff` + `push_maker_note_tags` push every Panasonic
    // `VendorEmission` under `("MakerNotes","Panasonic")` (`Panasonic.pm:268`
    // declares only `GROUPS => { 0 => 'MakerNotes', … }`, so ExifTool derives
    // family-1 from the vendor module — `exiftool -j -G1` emits
    // `Panasonic:ImageQuality` on a Lumix). The cross-table Leica1/Leica10 routes
    // (`Vendor::Leica`) ALSO emit `Panasonic:*` (their tags ARE `%Panasonic::Main`
    // tags); that dispatch arm keeps its own `parse_leica*_gated` oracle and
    // overrides `emission_group1` to `Panasonic` directly.
    TableRef::Panasonic => Some("Panasonic"),
    // `%Nikon::Main` / `%Nikon::Type2` — phase 3-bis of the engine migration
    // (#243). A Nikon maker-note leaf emits under the `Nikon` family-1 group,
    // exactly as `parse_in_tiff` + `push_maker_note_tags` push every Nikon
    // `VendorEmission` under `("MakerNotes","Nikon")` (`Nikon.pm:1238` declares
    // only `GROUPS => { 0 => 'MakerNotes', … }`, so ExifTool derives family-1 from
    // the vendor module — `exiftool -j -G1` emits `Nikon:Quality`). BOTH the Main
    // and the Type2 layout group under `Nikon` (Type2 is the same vendor's
    // headerless variant, `%Image::ExifTool::Nikon::Type2`).
    TableRef::Nikon | TableRef::NikonType2 => Some("Nikon"),
    // Core IFD tables keep their `IfdName` group; the not-yet-migrated vendor
    // tables never reach the emit through this walker.
    TableRef::Exif | TableRef::Gps | TableRef::Interop | TableRef::Samsung => None,
  }
}

// ====================================================================// MakerNote capture — the deferred-vendor-parsing seam
// ====================================================================
/// How to recompute a captured MakerNote's `-n` (ValueConv) vendor emissions on
/// demand — Golden-v2 P0 single-mode decode. The eager walk decodes each vendor
/// body ONCE (PrintConv), keeping the typed slot + the PrintConv emissions; this
/// captures the per-vendor decode INPUTS so the (rarely-needed) `-n` emissions
/// can be re-derived only when asked, instead of eagerly decoding the body a
/// second time and caching a result the `-j`/typed path never reads.
///
/// All inputs are `Copy` (the borrowed parent slice `&'a [u8]`, offsets, byte
/// order, `BaseRule`) or cheap owned `SmolStr` (the captured Make/Model/FileType,
/// which the walker owns and drops — so they must be retained here). Each
/// variant mirrors the eager PrintConv decode's call at the walk site; the
/// vendor decoders are deterministic across the PrintConv flag (the gated ones
/// route identically), so [`Self::recompute`] yields the SAME emissions the old
/// eager `-n` cache held.
#[derive(Debug, Clone)]
enum MakerNoteValueConvDecode<'a> {
  /// No `-n` emissions (vendor has no body parser yet, or a gated vendor whose
  /// `%Main` route did not match — its PrintConv decode produced none either).
  None,
  /// Apple — `apple_makernote_isolated(blob, order, ·, make)`. `make` is the
  /// parent IFD0 `Make`, retained so the `-n` recompute gates the format-16
  /// (`int64u`) Apple carve-out on `Make eq 'Apple'` identically to the `-j`
  /// decode (`Exif.pm:6464`) — mirrors how the `Canon` variant retains `model`.
  Apple {
    blob: &'a [u8],
    order: ByteOrder,
    make: Option<smol_str::SmolStr>,
  },
  /// Canon — re-drive the SHARED `Walker`'s Canon walk + emission capture
  /// ([`canon_recompute_value_conv`]) with `print_conv = false` (#243 phase 2
  /// step C). The Canon Main IFD walk is deterministic across the PrintConv flag
  /// (it reads the same bytes through the same machinery; only the per-leaf
  /// render differs), so the recomputed `-n` emissions are byte-identical to
  /// the old eager `-n` cache — exactly the contract the other gated vendors
  /// hold. Carries the parent-TIFF window + the `$$self{Model}` /
  /// `$$self{FILE_TYPE}` the walk + capture read.
  Canon {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    order: ByteOrder,
    model: Option<smol_str::SmolStr>,
    file_type: Option<smol_str::SmolStr>,
  },
  /// Sony — re-drive the SHARED `Walker`'s gated Sony Main walk + emission capture
  /// ([`sony_makernote_isolated`]) with `print_conv = false` (#243 phase 3). The
  /// walk is deterministic across the PrintConv flag (same `routes_to_main` gate,
  /// same bytes through the same machinery; only the per-leaf render + the
  /// conditional-AF gates differ on the flag), so the recomputed `-n` emissions are
  /// byte-identical to the old eager `-n` cache. Carries the parent-TIFF window +
  /// the `$$self{Make}`/`$$self{Model}` the gate + the AF-tag branches read.
  Sony {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    body_off: usize,
    order: ByteOrder,
    make: Option<smol_str::SmolStr>,
    model: Option<smol_str::SmolStr>,
  },
  /// Panasonic — `parse_main_gated(data, mn_offset, mn_len, order, ·, model, base_rule)`.
  Panasonic {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    order: ByteOrder,
    model: Option<smol_str::SmolStr>,
    base_rule: makernotes::BaseRule,
  },
  /// Leica1 — `parse_leica1_gated(data, mn_offset, mn_len, body_off, order, ·, make, model)`.
  Leica1 {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    body_off: usize,
    order: ByteOrder,
    make: Option<smol_str::SmolStr>,
    model: Option<smol_str::SmolStr>,
  },
  /// Leica10 — `parse_leica10_gated(data, mn_offset, mn_len, body_off, order, ·, model)`.
  Leica10 {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    body_off: usize,
    order: ByteOrder,
    model: Option<smol_str::SmolStr>,
  },
  /// DJI — `parse_in_tiff(data, mn_offset, mn_len, order, ·)`.
  Dji {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    order: ByteOrder,
  },
  /// Nikon — `parse_in_tiff(data, mn_offset, mn_len, order, ·, model)`.
  /// Type-3 is self-contained (embedded TIFF), but type-2 / headerless Nikon3
  /// resolve out-of-line offsets against the PARENT TIFF block, so the parent
  /// `data` + the MakerNote window are retained (not just the blob).
  Nikon {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    order: ByteOrder,
    model: Option<smol_str::SmolStr>,
  },
}

#[cfg(feature = "alloc")]
impl MakerNoteValueConvDecode<'_> {
  /// Re-run the vendor decoder for `-n` (ValueConv) and return its emissions.
  /// The gated variants `.expect(...)` a `Some` result — faithful to the eager
  /// walk's invariant that a route which matched in PrintConv matches in
  /// ValueConv too (same gate, PrintConv-independent).
  #[must_use]
  fn recompute(&self) -> std::vec::Vec<makernotes::VendorEmission> {
    use makernotes::vendors::{dji, panasonic};
    match self {
      MakerNoteValueConvDecode::None => std::vec::Vec::new(),
      MakerNoteValueConvDecode::Apple { blob, order, make } => {
        // The `-n` recompute is the isolated walk with `print_conv = false` and the
        // typed slot discarded (the `-n` path needs only the ValueConv emissions),
        // mirroring `canon_recompute_value_conv` (#243 phase 3). `make` is threaded
        // so the format-16 carve-out gate matches the `-j` decode (R4).
        apple_makernote_isolated(blob, *order, false, make.as_deref()).0
      }
      MakerNoteValueConvDecode::Canon {
        data,
        mn_offset,
        mn_len,
        order,
        model,
        file_type,
      } => canon_recompute_value_conv(
        data,
        *mn_offset,
        *mn_len,
        *order,
        model.as_deref(),
        file_type.as_deref(),
      ),
      MakerNoteValueConvDecode::Sony {
        data,
        mn_offset,
        mn_len,
        body_off,
        order,
        make,
        model,
      } => {
        // The `-n` recompute is the isolated walk with `print_conv = false` and the
        // typed slot discarded (the `-n` path needs only the ValueConv emissions),
        // mirroring `canon_recompute_value_conv` (#243 phase 3). The route matched
        // in PrintConv ⇒ it matches in ValueConv (same `routes_to_main` gate,
        // PrintConv-independent), so `Some` always holds; `unwrap_or_default` is the
        // defensive empty `Vec` for the impossible `None`.
        sony_makernote_isolated(
          data,
          *mn_offset,
          *mn_len,
          *body_off,
          *order,
          make.as_deref(),
          model.as_deref(),
          false,
        )
        .map(|(e, _)| e)
        .unwrap_or_default()
      }
      MakerNoteValueConvDecode::Panasonic {
        data,
        mn_offset,
        mn_len,
        order,
        model,
        base_rule,
      } => {
        // The `-n` recompute is the isolated walk with `print_conv = false` and the
        // typed slot discarded (the `-n` path needs only the ValueConv emissions),
        // mirroring `canon_recompute_value_conv` (#243 phase 3). The `base_rule` →
        // out-of-line-offset addend (the DC-FT7 `Base => 12` shift) is resolved the
        // SAME way the `-j` dispatch resolved it (`main_base_offset`). The route
        // matched in PrintConv ⇒ it matches in ValueConv (same `routes_to_main`
        // gate, PrintConv-independent), so `Some` always holds; `unwrap_or_default`
        // is the defensive empty `Vec` for the impossible `None`.
        panasonic_makernote_isolated(
          data,
          *mn_offset,
          *mn_len,
          panasonic::main_base_offset(*base_rule),
          *order,
          model.as_deref(),
          false,
        )
        .map(|(e, _)| e)
        .unwrap_or_default()
      }
      MakerNoteValueConvDecode::Leica1 {
        data,
        mn_offset,
        mn_len,
        body_off,
        order,
        make,
        model,
      } => {
        panasonic::parse_leica1_gated(
          data,
          *mn_offset,
          *mn_len,
          *body_off,
          *order,
          false,
          make.as_deref(),
          model.as_deref(),
        )
        .expect("routes_to_leica1 is deterministic across print_conv")
        .1
      }
      MakerNoteValueConvDecode::Leica10 {
        data,
        mn_offset,
        mn_len,
        body_off,
        order,
        model,
      } => {
        panasonic::parse_leica10_gated(
          data,
          *mn_offset,
          *mn_len,
          *body_off,
          *order,
          false,
          model.as_deref(),
        )
        .expect("routes_to_leica10 is deterministic across print_conv")
        .1
      }
      MakerNoteValueConvDecode::Dji {
        data,
        mn_offset,
        mn_len,
        order,
      } => dji::parse_in_tiff(data, *mn_offset, *mn_len, *order, false).1,
      MakerNoteValueConvDecode::Nikon {
        data,
        mn_offset,
        mn_len,
        order,
        model,
      } => {
        // The `-n` recompute is the isolated walk with `print_conv = false` and the
        // typed slot discarded (the `-n` path needs only the ValueConv emissions),
        // mirroring Sony/Panasonic (#243 phase 3-bis). A blob that resolved a layout
        // in PrintConv resolves the SAME layout in ValueConv (`resolve_layout` is
        // PrintConv-independent), so `Some` always holds here; `unwrap_or_default` is
        // the defensive empty `Vec` for the impossible `None`.
        nikon_makernote_isolated(data, *mn_offset, *mn_len, *order, model.as_deref(), false)
          .map(|(e, _)| e)
          .unwrap_or_default()
      }
    }
  }
}

/// The raw MakerNote (0x927c) blob captured by the Exif walker, together
/// with the Phase-1 dispatch outcome (vendor identification +
/// `SubDirectory` directives — see [`makernotes::dispatch`]).
///
/// Phase 1 carries the vendor identification + the `Start`/`Base`/
/// `ByteOrder`/`NotIFD` directives that bundled `MakerNotes.pm` computes
/// per dispatch (`MakerNotes.pm:35-1127`). Per-vendor TAG TABLE parsing
/// (Apple.pm, Canon.pm, Sony.pm, …) is deferred to Phase 2-4 (rescope
/// priority: Apple+Canon first, then Sony+Panasonic, then GoPro+DJI;
/// long-tail vendors after).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone)]
pub struct MakerNote<'a> {
  /// The raw MakerNote bytes (the value the ExifIFD's 0x927c tag pointed
  /// to). Borrowed from the input TIFF block.
  bytes: &'a [u8],
  /// The typed [`MakerNotesMeta`](makernotes::MakerNotesMeta) — carries
  /// the [`DetectedMakerNote`](makernotes::DetectedMakerNote) dispatch
  /// outcome (vendor identification + `SubDirectory` directives; the
  /// dispatcher is TOTAL so it is always present) plus the per-vendor
  /// decoded slots (`None` in Phase 1; populated Phase 2-4).
  meta: makernotes::MakerNotesMeta,
  /// Cached vendor emissions from the Phase-2 vendor body decoder in
  /// `-j` (print-conv) mode — each carries the rendered `(name, value)`
  /// plus the `Unknown => 1` flag (the emission engine suppresses the
  /// Unknown ones; the legacy `serialize_tags` path filters them on read).
  /// Computed once at walk time so the serializer doesn't need to
  /// re-resolve out-of-line offsets against the TIFF block. The PrintConv
  /// decode ALSO yields the typed vendor [`MakerNotesMeta`] slot, which the
  /// domain projection / dispatch tests read, so it stays EAGER.
  cached_emissions_print_conv: std::vec::Vec<makernotes::VendorEmission>,
  /// How to recompute the `-n` (post-ValueConv raw) emissions ON DEMAND —
  /// Golden-v2 P0 single-mode decode. The eager walk decodes the vendor body
  /// ONCE (PrintConv, above); the ValueConv emissions are needed only by the
  /// `-n` serialize path, so instead of eagerly decoding the body a SECOND
  /// time and caching the result (one wasted decode per parse — `-j`/the typed
  /// API never reads it), this captures the decode INPUTS (the borrowed parent
  /// slice + offsets/order/model/… — all `Copy` or cheap owned `SmolStr`s) and
  /// re-runs the vendor decoder for `-n` only when [`emissions_value_conv`] is
  /// actually called. The vendor decoders are deterministic across the
  /// PrintConv flag (the gated ones route identically), so the recomputed `-n`
  /// emissions are byte-identical to the old eager cache.
  value_conv_decode: MakerNoteValueConvDecode<'a>,
  /// The FAMILY-1 group under which the cached emissions serialize. Almost
  /// always [`Vendor::group1()`](makernotes::Vendor::group1) of
  /// [`Self::vendor`] (`Apple`/`Canon`/`Sony`/`Panasonic`), but the
  /// cross-table `MakerNoteLeica10` (`MakerNotes.pm:724-730`) is a
  /// `Vendor::Leica` blob decoded with the PANASONIC Main table, so bundled
  /// `exiftool -G1 -j` emits its tags under `Panasonic:*` (they ARE
  /// `%Panasonic::Main` tags) — for that case this is `"Panasonic"` even
  /// though `vendor()` is `Vendor::Leica`. Decoupling the EMISSION group
  /// from the dispatched vendor keeps the faithful vendor classification
  /// (`Vendor::Leica`) while matching bundled's `Panasonic:*` output.
  emission_group1: &'static str,
}

impl<'a> MakerNote<'a> {
  /// The raw MakerNote bytes (vendor-specific; unparsed — see the type docs).
  #[must_use]
  #[inline(always)]
  pub const fn bytes(&self) -> &'a [u8] {
    self.bytes
  }

  /// The byte length of the captured MakerNote blob.
  #[must_use]
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.bytes.len()
  }

  /// `true` if the captured MakerNote blob is empty.
  #[must_use]
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.bytes.is_empty()
  }

  /// The dispatched [`Vendor`](makernotes::Vendor) — Phase-1's primary
  /// surface. Even without per-vendor tag tables, vendor identification
  /// is camera-metadata-meaningful (it tells downstream code which
  /// vendor's IFD layout, byte-order, and offset semantics apply).
  #[must_use]
  #[inline(always)]
  pub const fn vendor(&self) -> makernotes::Vendor {
    self.meta.vendor()
  }

  /// The full Phase-1 dispatch outcome — vendor + body offset + base
  /// rule + byte-order directive + NotIFD flag. See
  /// [`DetectedMakerNote`](makernotes::DetectedMakerNote).
  #[must_use]
  #[inline(always)]
  pub const fn detected(&self) -> makernotes::DetectedMakerNote {
    self.meta.detected()
  }

  /// The typed [`MakerNotesMeta`](makernotes::MakerNotesMeta) — Phase 2-4
  /// will populate the matching per-vendor `Option<…>` slot. Phase 1
  /// gives only the vendor identification ([`Self::vendor`]).
  #[must_use]
  #[inline(always)]
  pub const fn meta(&self) -> &makernotes::MakerNotesMeta {
    &self.meta
  }

  /// The MakerNote BODY — `blob[detected.body_offset()..]`. After the
  /// dispatcher strips the vendor header, this is what a Phase 2+ vendor
  /// IFD parser walks. For Canon (no header) this equals
  /// [`Self::bytes`]; for Apple/Olympus/Pentax/etc. the header is
  /// excluded.
  #[must_use]
  #[inline]
  pub fn body(&self) -> &'a [u8] {
    let off = self.meta.detected().body_offset() as usize;
    // `bytes.get(off..)` folds the `off >= len` guard into the slice: it is
    // `None` (→ `&[]`) for an out-of-range `off` and otherwise the suffix —
    // byte-identical to the explicit `if off >= len { &[] } else { &bytes[off..] }`.
    self.bytes.get(off..).unwrap_or(&[])
  }

  /// The Phase-2 cached vendor emissions in `-j` (print-conv) mode —
  /// Apple/Canon vendor bodies are parsed at walk time and the emissions
  /// (each a [`VendorEmission`](makernotes::VendorEmission) carrying name +
  /// rendered value + the `Unknown => 1` flag) are stored for the
  /// emission engine / serializer.
  ///
  /// Empty for vendors other than Apple/Canon (Phase 3/4 vendors don't
  /// have a body parser yet).
  #[must_use]
  #[inline(always)]
  pub fn emissions_print_conv(&self) -> &[makernotes::VendorEmission] {
    &self.cached_emissions_print_conv
  }

  /// The Phase-2 vendor emissions in `-n` (post-ValueConv raw) mode, decoded ON
  /// DEMAND (Golden-v2 P0). Unlike [`Self::emissions_print_conv`] (eagerly
  /// cached because the PrintConv decode also yields the typed vendor slot),
  /// the `-n` emissions are re-derived from the stored decode inputs only when
  /// this is called — so a `-j`/typed-only consumer never pays the second
  /// vendor-body decode. Returns an OWNED `Vec` (the result is freshly built).
  /// Byte-identical to the old eager `-n` cache (the vendor decoders are
  /// deterministic across the PrintConv flag). Empty for vendors with no body
  /// parser yet (Phase 3/4) and for a gated vendor whose `%Main` route did not
  /// match (its PrintConv decode produced no emissions either).
  #[must_use]
  pub fn emissions_value_conv(&self) -> std::vec::Vec<makernotes::VendorEmission> {
    self.value_conv_decode.recompute()
  }

  /// The FAMILY-1 group under which the cached emissions serialize. Equal to
  /// [`Vendor::group1()`](makernotes::Vendor::group1) of [`Self::vendor`] for
  /// every same-vendor case (`Apple`/`Canon`/`Sony`/`Panasonic`), but
  /// `"Panasonic"` for the cross-table `MakerNoteLeica10`
  /// (`MakerNotes.pm:724-730`): its tags are `%Panasonic::Main` tags so
  /// bundled `exiftool -G1 -j` emits them as `Panasonic:*` even though the
  /// dispatched vendor is `Vendor::Leica`.
  #[must_use]
  #[inline(always)]
  pub const fn emission_group1(&self) -> &'static str {
    self.emission_group1
  }
}

/// A positioned AUXILIARY JPEG metadata block — an `APP`-segment payload other
/// than the EXIF (`APP1`) block, carried by an [`ExifMeta`] for a JPEG
/// container and emitted by [`Taggable::tags`](crate::emit::Taggable::tags) at
/// its marker position relative to the EXIF block.
///
/// ExifTool processes each `APP` segment inside its `Marker:` loop in file
/// (marker) order (`ExifTool.pm:7325`), so each block's tags render as one
/// contiguous group at the segment's position. `ExifMeta` reproduces that by
/// interleaving these aux blocks with the EXIF block by ascending marker
/// position (see the [`ExifMeta`] type docs and `Taggable::tags`).
///
/// Today the only variant is `GoPro` (the `APP6` `GoPro\0` GPMF stream,
/// `JPEG.pm:196-198`). The enum is the extension point for future
/// `APP`-segment extractors: adding XMP (`APP1` `http://ns.adobe.com/xap/1.0/`),
/// ICC_Profile (`APP2`), MPF (`APP2`), or IPTC is a new variant here plus a
/// [`push_jpeg_aux_block`](ExifMeta::push_jpeg_aux_block) call at the segment's
/// marker index — the position-sort then orders it against the EXIF block
/// automatically, with no new ordering code. (XMP/ICC/MPF/IPTC extraction
/// itself is separate backlog work; this models only the ordering seam.)
///
/// Gated on `quicktime`: the sole variant payload
/// ([`GoProMeta`](crate::metadata::GoProMeta)) and its GPMF parser live in the
/// `quicktime`-feature module ([`crate::formats::gopro`]); the `exif` feature
/// builds standalone with this enum absent. A future non-`quicktime` aux
/// variant (XMP/ICC/…) would drop the gate.
#[cfg(feature = "quicktime")]
#[derive(Debug, Clone)]
pub(crate) enum JpegAuxBlock {
  /// The `APP6` "GoPro" GPMF device-settings stream (`JPEG.pm:196-198` →
  /// `%GoPro::GPMF`), accumulated across every `GoPro\0`-prefixed `APP6`
  /// segment. Renders under group `APP6`:`GoPro` via
  /// [`emit_gopro_tags`](crate::formats::quicktime::emit_gopro_tags).
  GoPro(crate::metadata::GoProMeta),
}

#[cfg(feature = "quicktime")]
impl JpegAuxBlock {
  /// Append this block's tags to `out` as [`EmittedTag`](crate::emit::EmittedTag)s
  /// for `print_conv`, in the block's own internal (GPMF-walk) order — the
  /// contiguous group ExifTool emits at the segment's marker position.
  fn push_tags(&self, print_conv: bool, out: &mut std::vec::Vec<crate::emit::EmittedTag>) {
    match self {
      // The `APP6` "GoPro" GPMF stream renders the device-settings +
      // camera-identity tags under group `APP6`:`GoPro` (family-1 stays
      // `GoPro`; family-0 is the `APP6` parent the segment was reached
      // through).
      JpegAuxBlock::GoPro(gp) => {
        crate::formats::quicktime::emit_gopro_tags(gp, "APP6", "GoPro", print_conv, out);
      }
    }
  }
}

// ====================================================================// Typed Meta — `ExifMeta<'a>`
// ====================================================================
/// Typed Exif/TIFF metadata — the lib-first output of [`ProcessExif`] and
/// the reusable [`parse_exif_block`].
///
/// D8 convention: no public fields; accessors only.
///
/// `ExifMeta` carries an ordered list of [`ExifEntry`] tags (faithful to
/// ExifTool's `FoundTag` call order across the IFD chain), the TIFF byte
/// order (the engine's `File:ExifByteOrder` tag), and the captured-but-
/// unparsed [`MakerNote`] blob if one was present.
///
/// An `ExifMeta` with no [`byte_order`](Self::byte_order) is the
/// **JPEG-container-accepted-without-Exif** case: a valid JPEG (SOI present)
/// that carried no usable `APP1` Exif block. Bundled `ProcessJPEG`
/// (`ExifTool.pm:7304` `SetFileType`) finalizes `File:FileType == "JPEG"`
/// independently of whether the `APP1` Exif arm runs — so the JPEG container
/// front-end ([`jpeg::parse_jpeg_exif`]) always yields an `ExifMeta`; when no
/// TIFF block was processed it has empty entries and `byte_order == None`
/// (faithful: `File:ExifByteOrder` is `FoundTag`'d only inside `DoProcessTIFF`,
/// `ExifTool.pm:8691`), possibly with a `Malformed APP1 EXIF segment` warning.
///
/// ## JPEG metadata-block ordering
///
/// For a JPEG container, ExifTool emits a file's tags in this overall shape
/// (verified via `exiftool -G1 -j` on `XMP.jpg`/`Canon.jpg`/`ExifTool.jpg`):
///
/// 1. a synthetic prefix — the `File`-group tags (`File:ExifByteOrder`,
///    `File:PageCount`, …) lead UNCONDITIONALLY, ahead of every segment;
/// 2. the metadata blocks (the EXIF IFDs + the captured MakerNote; and any
///    auxiliary `APP`-segment block — GoPro GPMF today; XMP / ICC_Profile /
///    MPF / IPTC in future), each rendered as one CONTIGUOUS group, in the
///    order their `APP` segment is processed (file / marker order —
///    `ExifTool.pm:7325` runs each `Marker:` arm in segment order);
/// 3. the `Composite` group LAST (synthesized after every block — `ExifMeta`
///    itself emits no `Composite` tag; the engine appends that group).
///
/// `ExifMeta` models step 2 with a marker-POSITION-ordered block list rather
/// than a per-block boolean: the EXIF block sits at
/// [`exif_block_pos`](Self::exif_block_pos) and each positioned auxiliary block
/// ([`JpegAuxBlock`], at its own marker index) is interleaved with it by
/// ascending position (a STABLE sort — ties keep insertion order, a `None`
/// EXIF position sorts the block first). A future `APP`-segment extractor slots
/// in by adding a [`JpegAuxBlock`] variant and pushing it at its marker
/// position ([`push_jpeg_aux_block`](Self::push_jpeg_aux_block)); it then
/// auto-orders against the EXIF block with no further ordering logic. See
/// [`Taggable::tags`](crate::emit::Taggable::tags).
#[derive(Debug, Clone)]
pub struct ExifMeta<'a> {
  /// Every emitted tag, in IFD-walk order. Fully owned (the `'a` lifetime is
  /// carried solely by the borrowed [`MakerNote`]).
  entries: Vec<ExifEntry>,
  /// `$et->Warn(...)` messages raised by the IFD-bounds checks, in emission
  /// order. The engine surfaces these as `ExifTool:Warning` tags.
  warnings: Vec<String>,
  /// Per-warning `sub Warn` ignorable level, index-aligned with
  /// [`warnings`](Self::warnings) (Phase C). `2` ⇒ `[Minor]` (the
  /// excessive-count warning), `0` ⇒ normal. The prefix is applied by
  /// [`Diagnose`](crate::diagnostics::Diagnose) → `run_diagnostics`.
  warnings_ignorable: Vec<u8>,
  /// The TIFF header byte order (`ExifTool.pm:8628`). The engine emits it as
  /// `File:ExifByteOrder` (`ExifTool.pm:8691`). `None` only for a JPEG
  /// container accepted without a parsed `APP1` Exif TIFF block (see the type
  /// docs) — every standalone-TIFF / `APP1`-Exif parse sets `Some(order)`.
  byte_order: Option<ByteOrder>,
  /// The captured MakerNote (0x927c) blob, if the ExifIFD had one. Vendor
  /// parsing is deferred to the MakerNotes wave. Borrows from the input
  /// TIFF block — the sole reason `ExifMeta` carries a lifetime.
  maker_note: Option<MakerNote<'a>>,
  /// The synthesized `File:PageCount` value when this `ExifMeta` is the
  /// outer result of a standalone-TIFF walk that triggered the multi-page
  /// gate (`ExifTool.pm:8756-8757`). `Some(n)` ⇒ `serialize_tags` emits
  /// `File:PageCount = n`; `None` ⇒ no PageCount tag. The standalone-TIFF
  /// entries ([`parse_borrowed`] / [`parse_standalone_tiff_with_base`] /
  /// [`ProcessExif::parse`]) populate it from the walker's tracked
  /// SubfileType / OldSubfileType state; the embedded-block entries
  /// ([`parse_exif_block`] / [`parse_exif_block_with_base`]) always set
  /// `None`, faithful to bundled gating the emit on the OUTER file type
  /// being "TIFF" (`Parent='TIFF'`, `ExifTool.pm:8704`).
  multi_page_count: Option<u32>,
  /// The container's detected FILE_TYPE (`$$self{FILE_TYPE}`) — `Some("CRW")`
  /// for a CIFF/CRW raw, the standalone-TIFF candidate's `Parent`
  /// (`"TIFF"`/`"DNG"`/`"NEF"`/`"CR2"`/…) for a standalone TIFF, `None` for an
  /// embedded Exif block (JPEG `APP1`, PNG `eXIf`) or when unknown. WRITE-ONLY
  /// inside the engine except for ONE faithful read: `Canon::ShotInfo`
  /// position 22's RawConv (`Canon.pm:2977`/`:2990`) keeps a raw-0
  /// ExposureTime only when the container is a CRW. It does NOT affect any
  /// other tag — the Canon decoder threads it through to that single gate at
  /// MakerNote-capture time. (Because the port has no CIFF/CRW parser, no
  /// reachable input is a CRW, so the pos-22 behaviour — hence all output —
  /// is unchanged; only the gate is now spelled faithfully.)
  file_type: Option<smol_str::SmolStr>,
  /// IFD0's `Model` (`0x0110`) as the MakerNotes dispatcher records it —
  /// `$$self{Model}`, captured during the top-level Exif walk and TRIMMED of
  /// trailing whitespace (the `Exif.pm:599` `RawConv` `s/\s+$//`). The Canon CTMD
  /// `ProcessExifInfo` walker reads it from a `0x8769` `ExifIFD` block to hand
  /// off to the in-sample `0x927c` re-dispatch for model-conditional sub-tables
  /// (Canon.pm:10739-10751). `None` for a TIFF with no IFD0 `Model`. WRITE-ONLY
  /// inside the engine except for that single CTMD read (exposed via
  /// [`ExifMeta::dispatcher_model`]).
  captured_model: Option<smol_str::SmolStr>,
  /// `$$self{DNGVersion}` — `true` when IFD0 carried a TRUTHY `DNGVersion`
  /// (0xc612) value (the walker's [`Walker::dng_version`] tap; Perl-truthiness
  /// of the RawConv'd `$val`, so a count-0 / scalar-`0` value does NOT set it).
  /// The engine's TIFF finalization reads it via [`ExifMeta::has_dng_version`]
  /// to apply
  /// `DoProcessTIFF`'s `OverrideFileType('DNG')` (`ExifTool.pm:8763-8765`) when
  /// the container `$$self{FILE_TYPE}` is `TIFF` and the resolved type is not
  /// already `DNG`/`GPR`. Always `false` for an embedded Exif block (a JPEG /
  /// PNG / QuickTime / RIFF container is never `$$self{FILE_TYPE} eq 'TIFF'`,
  /// so the DNG override there is unreachable in bundled).
  dng_version: bool,
  /// `true` when this standalone-TIFF header carries the Canon CR2 magic
  /// `CR\x02\0` at byte 8 (`ExifTool.pm:8633-8641`): TIFF identifier 0x2a,
  /// IFD0 offset ≥ 16, the full 8-byte signature read at byte 8 succeeds
  /// (`data[8..16]` exists — `$raf->Read($sig, 8) == 8`, 8634), and its first
  /// four bytes are `CR\x02\0`. `DoProcessTIFF` sets
  /// `$fileType = 'CR2'` from this signature, so the engine finalizes
  /// `File:FileType = CR2` (`image/x-canon-cr2`) regardless of extension —
  /// including a CR2 body renamed to another RAW extension (`.dng`/`.nef`/
  /// `.arw`), since the read is gated on the standalone-TIFF `$raf` path
  /// (`standalone_tiff`, `ExifTool.pm:8629`), NOT on the extension-derived
  /// `TIFF_TYPE eq 'TIFF'` PageCount gate. Read via [`ExifMeta::is_cr2_magic`].
  /// Always `false` for an embedded Exif block (a JPEG `APP1` / PNG `eXIf` /
  /// QuickTime `EXIF` / RIFF `exif` TIFF, the Canon CTMD `0x8769` re-dispatch,
  /// the CR3 `CMT4` GPS block — none has a top-level `$raf`) — bundled never
  /// detects CR2 from an embedded block.
  cr2_magic: bool,
  /// The decoded GoPro GPMF metadata of a JPEG `APP6` "GoPro" segment
  /// (JPEG.pm:183-198 → `%GoPro::GPMF` via `ProcessGoPro`). A GoPro still
  /// (`GOPR*.JPG`) carries its device-settings GPMF stream in `APP6`; the
  /// marker walk ([`crate::exif::jpeg`]) recognizes the `GoPro\0`-prefixed
  /// segment, strips the 6-byte prefix, and runs the shared GPMF KLV walker
  /// into the aux block, which [`Taggable::tags`](crate::emit::Taggable::tags)
  /// emits under group `APP6`:`GoPro`.
  ///
  /// The marker (file) position of the EXIF metadata block — the index of the
  /// first `APP1` segment whose `ProcessTIFF` produced a MOVABLE (default-
  /// visible, non-`File`) EXIF tag ([`emits_movable_tag`](Self::emits_movable_tag)),
  /// the anchor [`jpeg_aux_blocks`](Self::jpeg_aux_blocks) interleave against.
  /// `None` for a standalone TIFF / an embedded eXIf block (no JPEG marker
  /// positions), and for a JPEG with no movable-tag-producing `APP1` (the EXIF
  /// block then has no position to order against — it sorts first, so a GoPro
  /// `APP6` still trails it, matching ExifTool with no `IFD0:*` to be
  /// before/after). ExifTool runs each `APP1`/`APP6` arm inside its `Marker:`
  /// loop in file order (`ExifTool.pm:7325`), so this position decides whether
  /// a GoPro block's tags emit BEFORE or AFTER the `IFD0:*` tags. `File:*`
  /// prefix tags do NOT participate (they lead unconditionally), so only the
  /// MOVABLE EXIF tag anchors the position.
  ///
  /// Gated on `quicktime`: positioned only against `quicktime`-gated aux blocks
  /// ([`JpegAuxBlock`]); the `exif` feature builds standalone with this field
  /// absent (a non-`quicktime` build has no aux blocks to order against).
  #[cfg(feature = "quicktime")]
  exif_block_pos: Option<usize>,
  /// The positioned AUXILIARY JPEG metadata blocks ([`JpegAuxBlock`]) — each an
  /// `APP`-segment payload other than the EXIF block (the `APP6` GoPro GPMF
  /// stream today), paired with its marker (file) position.
  /// [`Taggable::tags`](crate::emit::Taggable::tags) interleaves them with the
  /// EXIF block (at [`exif_block_pos`](Self::exif_block_pos)) by ascending
  /// position (a STABLE sort), reproducing ExifTool's `Marker:`-loop file order
  /// (`ExifTool.pm:7325`) where each block is one contiguous group.
  ///
  /// Currently holds at most the one GoPro block (at the first tag-producing
  /// `APP6` position); the overwhelming common case is EMPTY (a non-GoPro JPEG,
  /// a standalone TIFF, an embedded eXIf block). This is the extension point:
  /// a future XMP / ICC_Profile / MPF / IPTC extractor pushes its own
  /// [`JpegAuxBlock`] variant here at its segment's marker index
  /// ([`push_jpeg_aux_block`](Self::push_jpeg_aux_block)) and it auto-orders.
  ///
  /// A pathological `APP6`/`APP1`/`APP6` straddle (one block split around the
  /// EXIF block) is modeled as one block at its FIRST tag-producing position,
  /// not split into two — a real GoPro JPEG never straddles, and ExifTool's
  /// `-G1 -j` output co-locates the family-1 `IFD0` group, so the whole-block
  /// order this computes matches the oracle at the conformance target (the
  /// strict per-segment interleave never surfaces in JSON).
  ///
  /// Gated on `quicktime`: the sole current variant payload
  /// ([`GoProMeta`](crate::metadata::GoProMeta)) is `quicktime`-only.
  #[cfg(feature = "quicktime")]
  jpeg_aux_blocks: std::vec::Vec<(usize, JpegAuxBlock)>,
}

impl<'a> ExifMeta<'a> {
  /// Every emitted tag in IFD-walk order. (`Vec` slice — never expose
  /// `&Vec`, §3.)
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[ExifEntry] {
    &self.entries
  }

  /// The TIFF header byte order. The engine emits this as
  /// `File:ExifByteOrder` (`ExifTool.pm:8691`). `None` for a JPEG container
  /// accepted without a parsed `APP1` Exif TIFF block (see the type docs).
  #[must_use]
  #[inline(always)]
  pub const fn byte_order(&self) -> Option<ByteOrder> {
    self.byte_order
  }

  /// The captured MakerNote (0x927c) blob, if the ExifIFD had one. Vendor
  /// MakerNote parsing is DEFERRED to the MakerNotes wave; this exposes the
  /// raw bytes the future port will consume.
  #[must_use]
  #[inline(always)]
  pub const fn maker_note(&self) -> Option<&MakerNote<'a>> {
    self.maker_note.as_ref()
  }

  /// The structural warnings raised while walking the IFD chain, in
  /// emission order. The engine surfaces each as an `ExifTool:Warning`
  /// tag (`Slice` — never expose `&Vec`, §3).
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[String] {
    &self.warnings
  }

  /// The synthesized `File:PageCount` value for a multi-page standalone
  /// TIFF (`ExifTool.pm:8756-8757`). `Some(n)` when this `ExifMeta` is the
  /// result of a standalone-TIFF walk (`TIFF_TYPE == 'TIFF'`) whose IFD
  /// chain tripped the `MultiPage` flag — bundled emits the tag as
  /// `File:PageCount = n` (the count of SubfileType ∈ {0, 2} and
  /// OldSubfileType ∈ {1, 3} IFDs). `None` for an embedded TIFF block
  /// (PNG `eXIf`, JPEG `APP1`, QuickTime EXIF, RIFF `exif`) — bundled
  /// gates the emit on `Parent` so embedded blocks never produce it.
  #[must_use]
  #[inline(always)]
  pub const fn multi_page_count(&self) -> Option<u32> {
    self.multi_page_count
  }

  /// `$$self{DNGVersion}` — `true` when IFD0 carried a TRUTHY `DNGVersion`
  /// (0xc612) value (Perl-truthiness of the RawConv'd `$val`; a count-0 /
  /// scalar-`0` value is falsy and does NOT set it).
  /// `DoProcessTIFF` (`ExifTool.pm:8763`) reads this to override
  /// `File:FileType` to `DNG` for a TIFF-structured file whose container
  /// `$$self{FILE_TYPE}` is `TIFF` (regardless of extension). `false` for an
  /// embedded Exif block (a JPEG/PNG/QuickTime/RIFF container is never
  /// `FILE_TYPE eq 'TIFF'`, so the override is unreachable there).
  #[must_use]
  #[inline(always)]
  pub const fn has_dng_version(&self) -> bool {
    self.dng_version
  }

  /// `true` when this standalone-TIFF header carries the Canon CR2 magic
  /// `CR\x02\0` at byte 8 (`ExifTool.pm:8633-8641`). The engine reads this to
  /// finalize `File:FileType = CR2` (`image/x-canon-cr2`) regardless of
  /// extension. `false` for an embedded Exif block (the CR2 signature read is
  /// gated on `$raf`, which only the standalone-TIFF dispatch has).
  #[must_use]
  #[inline(always)]
  pub const fn is_cr2_magic(&self) -> bool {
    self.cr2_magic
  }

  /// The container's detected FILE_TYPE (`$$self{FILE_TYPE}`) — see the field
  /// docs. `Some("CRW")` for a CIFF/CRW raw, the candidate `Parent`
  /// (`"TIFF"`/`"DNG"`/…) for a standalone TIFF, `None` for an embedded Exif
  /// block (JPEG `APP1`, PNG `eXIf`) or when unknown. The sole faithful
  /// consumer is `Canon::ShotInfo` position 22's CRW-allows-0 RawConv
  /// (`Canon.pm:2977`/`:2990`); it does not influence any other output.
  #[must_use]
  #[inline]
  pub fn file_type(&self) -> Option<&str> {
    self.file_type.as_deref()
  }

  /// The first entry whose resolved name matches `name` (a small ergonomic
  /// helper for the common "probe one tag" library use, e.g. `Make`).
  #[must_use]
  pub fn entry(&self, name: &str) -> Option<&ExifEntry> {
    self.entries.iter().find(|e| e.name == name)
  }

  /// IFD0's `Model` (`0x0110`) as the MakerNotes dispatcher sees it —
  /// `$$self{Model}`, captured during the top-level Exif walk and TRIMMED of
  /// trailing whitespace (the `Exif.pm:599` `RawConv` `s/\s+$//`). This is the
  /// value that keys every model-conditional MakerNote sub-table (`Canon::Main`
  /// `Canon::ShotInfo`/`Canon::FileInfo` conditions, `MakerNotes.pm`'s
  /// `$$self{Model}` carve-outs). The Canon CTMD `ProcessExifInfo` walker reads
  /// it from a `0x8769` `ExifIFD` block to hand off to the in-sample `0x927c`
  /// re-dispatch (Canon.pm:10739-10751). `None` for a TIFF with no IFD0 `Model`.
  /// (`pub(crate)`: an internal dispatch input, not API surface.)
  #[must_use]
  #[inline]
  pub(crate) fn dispatcher_model(&self) -> Option<&str> {
    self.captured_model.as_deref()
  }

  /// Build an `ExifMeta` from the JPEG container front-end's merged parts —
  /// the entries / warnings collected across every independent `APP1` Exif
  /// block, the byte order of the first block that carried one (`None` when
  /// no `APP1` Exif TIFF block parsed, i.e. a JPEG accepted on its `SOI`
  /// marker alone — `ExifTool.pm:7304`), and the FIRST captured `MakerNote`
  /// (0x927c) across the merged segments. A normal camera JPEG carries its
  /// MakerNote in the ExifIFD of its `APP1` Exif block; threading it here
  /// makes [`ExifMeta::maker_note`](Self::maker_note) return it for JPEGs
  /// exactly as for a standalone TIFF (the MakerNotes-wave seam #75+ consumes
  /// the same accessor regardless of container). First-wins matches bundled
  /// keeping the PRIMARY MakerNote — the ExifIFD of the first independent
  /// `APP1` Exif block is the real-world carrier; a second block's MakerNote
  /// (multi-`APP1`, exotic) is not the primary. (`pub(crate)`: the JPEG
  /// front-end [`jpeg::parse_jpeg_exif`] is the sole constructor — not API
  /// surface.)
  #[must_use]
  pub(crate) fn from_jpeg_parts(
    entries: Vec<ExifEntry>,
    warnings: Vec<String>,
    warnings_ignorable: Vec<u8>,
    byte_order: Option<ByteOrder>,
    maker_note: Option<MakerNote<'a>>,
  ) -> Self {
    // JPEG `APP1` Exif blocks come through `ProcessTIFF` with
    // `Parent='APP1'` (`ExifTool.pm:7779-7783`), so `TIFF_TYPE='APP1'` and
    // the `ExifTool.pm:8757` PageCount synthesis is suppressed. A JPEG-
    // embedded multi-page TIFF block is exotic (the JPEG container itself
    // is single-page) but bundled behaviour is: no PageCount.
    ExifMeta {
      entries,
      warnings,
      warnings_ignorable,
      byte_order,
      maker_note,
      multi_page_count: None,
      // A JPEG container's `APP1` Exif block is embedded — `$$self{FILE_TYPE}`
      // is the JPEG ("JPEG"), never "CRW", so the ShotInfo pos-22 CRW clause is
      // correctly off. We model that as `None` (no CRW), matching the embedded
      // `parse_exif_block` path.
      file_type: None,
      // The Canon CTMD `ProcessExifInfo` model hand-off reads `dispatcher_model`
      // only from a standalone `0x8769` TIFF (`parse_standalone_tiff_with_base`),
      // never from a JPEG `APP1` merge — so `None` here is correct.
      captured_model: None,
      // A JPEG container's `$$self{FILE_TYPE}` is "JPEG", never "TIFF", and the
      // CR2 signature read is gated on the standalone-TIFF `$raf`, so neither
      // the DNG override (`ExifTool.pm:8763`) nor the CR2 magic
      // (`ExifTool.pm:8629`) is reachable for an `APP1` Exif merge.
      dng_version: false,
      cr2_magic: false,
      // The JPEG marker walk records the EXIF block position and attaches any
      // `APP`-segment aux block (an `APP6` GoPro GPMF stream) AFTER this
      // construction via [`set_jpeg_gopro`](Self::set_jpeg_gopro); a freshly
      // built JPEG `ExifMeta` starts with no recorded position and no aux
      // blocks (the realistic `APP1`-before-`APP6` order — GoPro tags emit
      // AFTER EXIF — is what the position-sort then yields).
      #[cfg(feature = "quicktime")]
      exif_block_pos: None,
      #[cfg(feature = "quicktime")]
      jpeg_aux_blocks: std::vec::Vec::new(),
    }
  }

  /// Record the marker (file) position of the EXIF metadata block — the index
  /// of the `APP1` segment whose `ProcessTIFF` emits the first MOVABLE EXIF tag
  /// ([`emits_movable_tag`](Self::emits_movable_tag)) — for the JPEG
  /// position-ordered block model. `None` when no `APP1` produced a movable tag
  /// (the EXIF block then sorts first, so aux blocks trail it). The general
  /// seam every positioned [`JpegAuxBlock`] interleaves against; see the
  /// [`ExifMeta`] type docs and [`Taggable::tags`](crate::emit::Taggable::tags).
  /// (`pub(crate)`: a JPEG-front-end construction-time internal.)
  #[cfg(feature = "quicktime")]
  pub(crate) fn set_jpeg_exif_block_pos(&mut self, pos: Option<usize>) {
    self.exif_block_pos = pos;
  }

  /// Push a positioned AUXILIARY JPEG metadata block ([`JpegAuxBlock`]) at its
  /// marker (file) `pos`. [`Taggable::tags`](crate::emit::Taggable::tags)
  /// interleaves it with the EXIF block (and any other aux block) by ascending
  /// position. This is the general extension point: a future XMP / ICC_Profile
  /// / MPF / IPTC extractor pushes its own variant here and it auto-orders with
  /// no further ordering code. (`pub(crate)`: a JPEG-front-end
  /// construction-time internal.)
  #[cfg(feature = "quicktime")]
  pub(crate) fn push_jpeg_aux_block(&mut self, pos: usize, block: JpegAuxBlock) {
    self.jpeg_aux_blocks.push((pos, block));
  }

  /// Attach the GoPro GPMF metadata decoded from a JPEG `APP6` "GoPro" segment
  /// (JPEG.pm:183-198) at its marker `gopro_pos`, recording the EXIF block's
  /// marker `exif_pos`. Called by the JPEG marker walk ([`crate::exif::jpeg`])
  /// after [`from_jpeg_parts`](Self::from_jpeg_parts) when an `APP6` segment
  /// whose payload began `GoPro\0` decoded at least one GPMF record. The tags
  /// emit under group `APP6`:`GoPro` from
  /// [`Taggable::tags`](crate::emit::Taggable::tags), interleaved with the EXIF
  /// block by marker position. A no-op-equivalent empty `GoProMeta` is simply
  /// stored as-is (it emits nothing).
  ///
  /// `gopro_pos` is the marker index of the first TAG-PRODUCING GoPro `APP6`;
  /// `exif_pos` the EXIF block position (`None` when no `APP1` produced a
  /// movable tag). When `gopro_pos < exif_pos` the GoPro block sorts BEFORE the
  /// EXIF + MakerNote tags (faithful to ExifTool's `Marker:`-loop file order,
  /// `ExifTool.pm:7325`); otherwise after (the realistic `APP1`-before-`APP6`
  /// layout). A thin GoPro-named wrapper over the general
  /// [`set_jpeg_exif_block_pos`](Self::set_jpeg_exif_block_pos) +
  /// [`push_jpeg_aux_block`](Self::push_jpeg_aux_block) seam.
  #[cfg(feature = "quicktime")]
  pub(crate) fn set_jpeg_gopro(
    &mut self,
    gopro: crate::metadata::GoProMeta,
    gopro_pos: usize,
    exif_pos: Option<usize>,
  ) {
    self.set_jpeg_exif_block_pos(exif_pos);
    self.push_jpeg_aux_block(gopro_pos, JpegAuxBlock::GoPro(gopro));
  }

  /// The GoPro GPMF metadata decoded from a JPEG `APP6` "GoPro" segment, if
  /// any (`None` for every non-GoPro-JPEG source). Exposes the full typed
  /// [`GoProMeta`](crate::metadata::GoProMeta) surface (per-sample lists, camera
  /// identity, settings) the `APP6`:`GoPro` tag stream is rendered from. Reads
  /// the GoPro [`JpegAuxBlock`] out of the positioned block list.
  #[cfg(feature = "quicktime")]
  #[must_use]
  #[inline]
  // `find_map` reads as degenerate while `JpegAuxBlock` has one variant (the
  // match cannot return `None`), but it is the SELECT-the-GoPro-block form: the
  // moment a second variant (XMP/ICC/…) lands the arm gains a `_ => None` and
  // the search becomes real. Keeping it now means adding a variant touches only
  // the match, not the iterator shape.
  #[allow(clippy::unnecessary_find_map)]
  pub fn gopro(&self) -> Option<&crate::metadata::GoProMeta> {
    self
      .jpeg_aux_blocks
      .iter()
      .find_map(|(_, block)| match block {
        JpegAuxBlock::GoPro(gp) => Some(gp),
      })
  }

  /// Decompose this `ExifMeta` into `(entries, warnings, byte_order,
  /// maker_note)` — the inverse of [`from_jpeg_parts`](Self::from_jpeg_parts),
  /// used by the JPEG front-end to merge one decoded `APP1` Exif block into
  /// the accumulating JPEG-level parts. The `MakerNote` borrows from the input
  /// TIFF block (the `'a` lifetime), so it threads through the merge unchanged.
  /// (`pub(crate)`: a merge-time internal, not API surface.)
  #[must_use]
  pub(crate) fn into_jpeg_parts(
    self,
  ) -> (
    Vec<ExifEntry>,
    Vec<String>,
    Vec<u8>,
    Option<ByteOrder>,
    Option<MakerNote<'a>>,
  ) {
    // `multi_page_count` is dropped — the JPEG-merge path constructs the
    // merged `ExifMeta` via `from_jpeg_parts`, which always sets
    // `multi_page_count = None` (`Parent='APP1'`, not 'TIFF', so bundled
    // suppresses the emit). Restoring it on merge would be incorrect.
    (
      self.entries,
      self.warnings,
      self.warnings_ignorable,
      self.byte_order,
      self.maker_note,
    )
  }
}

// ====================================================================// `ProcessExif` — the lib-first parser
// ====================================================================
/// Exif / TIFF parser — faithful port of `Image::ExifTool::Exif::ProcessExif`
/// (`Exif.pm:6278-7240`) plus the TIFF-header front-end of
/// `Image::ExifTool::DoProcessTIFF` (`ExifTool.pm:8628-8730`).
///
/// A standalone TIFF file (`File:FileType == "TIFF"`) is dispatched here by
/// [`crate::format_parser::any_parser_for`]. JPEG/MP4 embed Exif as a
/// SubDirectory — those container ports call [`parse_exif_block`] directly.
#[derive(Debug, Clone, Copy)]
pub struct ProcessExif;

impl parser_sealed::Sealed for ProcessExif {}

impl FormatParser for ProcessExif {
  type Meta<'a> = ExifMeta<'a>;
  type Context<'a> = &'a [u8];

  /// Dispatched by [`crate::format_parser::any_parser_for`] when
  /// `File:FileType == "TIFF"` — the standalone-TIFF entry. Sets
  /// `tiff_type_is_tiff = true` so the multi-page `File:PageCount`
  /// synthesis (`ExifTool.pm:8756-8757`) is active.
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    // Direct standalone-TIFF lib entry: no candidate `Parent` context (the
    // engine path through `AnyParser::Exif` carries the real type via
    // `parse_standalone_tiff_with_base`), so `file_type = None`. A `.tif` is
    // never a CRW, so the ShotInfo pos-22 CRW clause is correctly off.
    parse_tiff(
      data, /* tiff_type_is_tiff */ true, /* standalone_tiff */ true,
      /* file_type */ None,
    )
  }
}

/// Lib-first direct entry — parse a whole standalone TIFF file. The outer
/// `TIFF_TYPE` is "TIFF" (`ExifTool.pm:8704`), so a multi-page TIFF emits
/// `File:PageCount` (`ExifTool.pm:8757`).
///
/// Returns `None` when `data` is not a valid TIFF header (`DoProcessTIFF`
/// `return 0`); a malformed TIFF surfaces its diagnostics as `Warn`/`Error`
/// tags on the returned [`ExifMeta`], never as a fatal error.
#[must_use]
pub fn parse_borrowed(data: &[u8]) -> Option<ExifMeta<'_>> {
  // Direct standalone-TIFF lib entry — no candidate `Parent`, so `file_type =
  // None` (see [`ProcessExif::parse`]).
  parse_tiff(
    data, /* tiff_type_is_tiff */ true, /* standalone_tiff */ true,
    /* file_type */ None,
  )
}

/// **Reusable entry — the QuickTime/RIFF/MakerNotes seam.** Parse a raw
/// Exif/TIFF byte block (a complete TIFF: byte-order marker + magic + IFD0
/// offset, with all IFD offsets relative to the START of `block`).
///
/// This is the function a future QuickTime (`QuickTime.pm` `EXIF` atom),
/// RIFF (`RIFF.pm` `exif` chunk), or PNG (`PNG.pm` `eXIf` chunk) port calls
/// on the embedded Exif block — the IFD walker is deliberately NOT locked
/// to file-level dispatch. A JPEG `APP1` / QuickTime `EXIF` payload IS a
/// standalone TIFF structure (`ExifTool.pm:8624` `DoProcessTIFF` processes
/// the `$dataPt` block the same way regardless of container).
///
/// **PageCount note:** bundled gates the synthesized `File:PageCount` tag
/// (`ExifTool.pm:8757`) on `$$self{TIFF_TYPE} eq 'TIFF'`. The recursive
/// `ProcessTIFF` calls from PNG/JPEG/QuickTime/RIFF do NOT overwrite that
/// outer file type, so `PageCount` is NOT emitted from those container
/// paths even if the embedded TIFF block has multi-page SubfileType tags —
/// embedded TIFFs with multiple pages just emit per-page IFDx:* tags. This
/// entry mirrors that: `PageCount` is suppressed. Use [`parse_borrowed`] /
/// the `ProcessExif::parse` arm for standalone TIFFs that need it.
///
/// Returns `None` when `block` is not a valid TIFF header (bad byte-order
/// marker, IFD0 offset < 8 — `ExifTool.pm:8645`).
#[must_use]
pub fn parse_exif_block(block: &[u8]) -> Option<ExifMeta<'_>> {
  // Embedded Exif block (QuickTime/RIFF/PNG/MakerNotes seam) — the container's
  // `$$self{FILE_TYPE}` is the OUTER type, never "CRW", so `file_type = None`
  // (the ShotInfo pos-22 CRW clause stays off). `standalone_tiff = false`: an
  // embedded block has no `$raf`, so the CR2 magic is NOT checked here.
  parse_tiff(
    block, /* tiff_type_is_tiff */ false, /* standalone_tiff */ false,
    /* file_type */ None,
  )
}

/// Like [`parse_exif_block`], but for an Exif/TIFF block that does NOT start at
/// file offset 0 — `base` is the file offset of the TIFF block's first byte
/// (ExifTool's `$$dirInfo{Base}`).
///
/// A JPEG `APP1` Exif segment carries its TIFF block partway into the file, so
/// the container front-end ([`jpeg::parse_jpeg_exif`]) passes the block's file
/// offset here. `base` is added to `IsOffset` value tags (`ThumbnailOffset`,
/// `StripOffsets`) to convert them to absolute file offsets, faithful to
/// `Exif.pm:7156-7170`. All other tags are identical to [`parse_exif_block`].
/// (`base == 0` is exactly [`parse_exif_block`].) The `File:PageCount` gate
/// is OFF — see [`parse_exif_block`].
#[must_use]
pub fn parse_exif_block_with_base(block: &[u8], base: u32) -> Option<ExifMeta<'_>> {
  // Embedded Exif block (JPEG `APP1`, etc.) — the OUTER container type is never
  // "CRW", so `file_type = None` (the ShotInfo pos-22 CRW clause stays off).
  // `standalone_tiff = false`: an embedded `APP1` TIFF has no `$raf`, so the CR2
  // magic is NOT checked here (a JPEG's embedded TIFF must never become CR2).
  parse_tiff_with_base(
    block, base, /* tiff_type_is_tiff */ false, /* standalone_tiff */ false,
    /* file_type */ None,
  )
}

/// Like [`parse_exif_block_with_base`], but for the standalone-TIFF dispatch
/// path, with the `File:PageCount` emission gate (`$$self{TIFF_TYPE} eq 'TIFF'`,
/// `ExifTool.pm:8767`) supplied by the caller as `tiff_type_is_tiff`.
///
/// Bundled sets `$$self{TIFF_TYPE} = $$dirInfo{Parent} || ''` (`ExifTool.pm:8715`
/// / `:8546`) — the candidate's `Parent`, which is the literal `"TIFF"` for a
/// plain `.tif`/dotless/full-scan TIFF but the SUBTYPE (`DNG`/`NEF`/`CR2`/…) for
/// a TIFF-rooted RAW. `File:PageCount` (`ExifTool.pm:8767-8768`) is emitted ONLY
/// when `TIFF_TYPE eq 'TIFF'`, so a multi-page RAW must NOT gain it. The engine
/// dispatch ([`crate::format_parser::AnyParser::Exif`]) therefore passes
/// `tiff_type_is_tiff = (parent_type == "TIFF")`. The block may carry a non-zero
/// `header_skip` `base` for the "scan past unknown header for TIFF" detector
/// candidate (`ExifTool.pm:3026-3034`). The `MultiPage` flag itself comes from
/// the SubfileType / OldSubfileType `RawConv` (`Exif.pm:456`/`:473`).
///
/// `file_type` is that same candidate `Parent` (`$$self{FILE_TYPE}`,
/// `ExifTool.pm:8715`) — stored on the resulting [`ExifMeta`] and threaded to
/// the Canon MakerNote decoder for the `Canon::ShotInfo` pos-22 CRW-allows-0
/// RawConv (`Canon.pm:2977`/`:2990`). The engine dispatch passes
/// `Some(parent_type)`; it is WRITE-ONLY apart from that single pos-22 read.
/// (A standalone TIFF/RAW is never a CRW — the CRW path is the unported CIFF
/// front-end — so this changes no output today.)
///
/// `standalone_tiff` is the CR2-magic `$raf` gate (`ExifTool.pm:8629`): the
/// genuine top-level standalone-TIFF dispatch passes `true` (the CR2 magic IS
/// checked, regardless of the extension-derived subtype — see
/// [`parse_tiff_with_base_no_raf`]); the Canon CTMD `MakerNoteCanon`
/// IFD0-diagnostics re-dispatch passes `false` (an embedded MakerNote blob is
/// not a top-level `$raf`-backed file, and that caller reads only the IFD0
/// structural diagnostics — never `is_cr2_magic`).
#[must_use]
pub fn parse_standalone_tiff_with_base<'a>(
  block: &'a [u8],
  base: u32,
  tiff_type_is_tiff: bool,
  standalone_tiff: bool,
  file_type: Option<&str>,
) -> Option<ExifMeta<'a>> {
  // The returned `ExifMeta<'a>` borrows ONLY from `block` (the IFD bytes); the
  // `file_type` is copied into an owned `SmolStr` inside `parse_tiff_with_base`,
  // so its lifetime is independent and need not appear in the return type.
  parse_tiff_with_base(block, base, tiff_type_is_tiff, standalone_tiff, file_type)
}

/// The Canon CTMD `ProcessExifInfo` `0x8769` ExifIFD re-dispatch
/// (`Canon.pm:10745-10751` → `ProcessTIFF` with `TagTable => Exif::Main`).
///
/// IDENTICAL to [`parse_standalone_tiff_with_base`] (the 1:1 `ProcessExif`
/// port under `Exif::Main`) EXCEPT the block is re-dispatched FROM MEMORY with
/// NO RAF: bundled re-frames `$dataPt` to the embedded TIFF slice
/// (`ExifTool.pm:8585`) with no `RAF`, so an out-of-bounds out-of-line value
/// takes the no-RAF `else` branch (`Exif.pm:6616-6670`) — warn `Bad offset for
/// $dir $tagStr` (`Exif.pm:6660`, NON-minor since `$inMakerNotes = 0` for
/// `Exif::Main`) and CONTINUE the walk (the value is dropped, `$bad = 1`) —
/// rather than the RAF path's `Error reading value …` + directory abort
/// (`Exif.pm:6594-6602`) the standalone/JPEG/QuickTime callers correctly model
/// (their block IS the whole readable buffer). See [`Walker::no_raf`].
///
/// `base == 0` (the embedded TIFF is self-contained); `tiff_type_is_tiff` is
/// `false` (the CTMD container is never the standalone-TIFF dispatch) and
/// `file_type` is `None` (never "CRW").
#[must_use]
pub fn parse_ctmd_exif_ifd_redispatch(block: &[u8]) -> Option<ExifMeta<'_>> {
  parse_tiff_with_base_no_raf(
    block,
    /* base */ 0,
    /* tiff_type_is_tiff */ false,
    /* standalone_tiff */ false,
    /* file_type */ None,
    /* no_raf */ true,
    /* ifd0_kind */ IfdKind::Ifd0,
  )
}

/// Parse a standalone TIFF block whose TOP-LEVEL directory IS a GPS IFD —
/// the Canon CR3 `CMT4` box (Canon.pm:9719-9726
/// `SubDirectory { Name => 'GPSInfo', TagTable => GPS::Main, ProcessProc =>
/// ProcessTIFF, DirName => 'GPS' }`).
///
/// IDENTICAL to [`parse_exif_block`] (the embedded-block `ProcessTIFF` entry:
/// `base == 0`, `tiff_type_is_tiff == false`, `file_type == None`, RAF-backed)
/// EXCEPT IFD0 is walked against the `GPS::Main` table ([`IfdKind::Gps`]) instead
/// of `Exif::Main`. A standard [`parse_exif_block`] would mis-decode `CMT4`: its
/// IFD0 holds GPS tag IDs (`GPSVersionID` `0x0000`, …) that the `Exif::Main`
/// table reads as unrelated / unknown tags — so the GPS table MUST drive the top
/// directory, exactly as ExifTool's `CMT4` SubDirectory specifies. The recovered
/// tags carry the family-1 group `"GPS"`. `None` for a block with no valid TIFF
/// header (bad byte-order marker / IFD0 offset < 8).
#[must_use]
pub fn parse_gps_block(block: &[u8]) -> Option<ExifMeta<'_>> {
  parse_tiff_with_base_no_raf(
    block,
    /* base */ 0,
    /* tiff_type_is_tiff */ false,
    /* standalone_tiff */ false,
    /* file_type */ None,
    /* no_raf */ false,
    /* ifd0_kind */ IfdKind::Gps,
  )
}

// ====================================================================// TIFF header parser — DoProcessTIFF front-end (ExifTool.pm:8628-8645)
// ====================================================================
/// Parse a TIFF block: validate the header, then walk the IFD chain.
///
/// `ExifTool.pm:8628-8645`:
/// ```text
/// my $byteOrder = substr($$dataPt,0,2);  SetByteOrder($byteOrder) or return 0;
/// my $identifier = Get16u($dataPt, 2);   # 0x2a for TIFF
/// return 0 if length $$dataPt < 8;
/// my $offset = Get32u($dataPt, 4);       $offset >= 8 or return 0;
/// ```
///
/// We do NOT gate on `$identifier == 0x2a` — bundled explicitly removed that
/// check (`ExifTool.pm:8634-8637`: RW2/HDP/BigTIFF use other magics). The
/// gate is the byte-order marker + the IFD0-offset ≥ 8 sanity check.
///
/// The ONE magic we special-case is BigTIFF (0x2b): its on-disk layout differs
/// from classic TIFF (8-byte offsets, 64-bit counts, 20-byte entries), so the
/// classic walker would misdecode it. We cleanly skip it (return `None`) rather
/// than emit garbage — see [`parse_tiff_with_base`]. A full BigTIFF walker is a
/// deferred port.
fn parse_tiff<'a>(
  data: &'a [u8],
  tiff_type_is_tiff: bool,
  standalone_tiff: bool,
  file_type: Option<&str>,
) -> Option<ExifMeta<'a>> {
  parse_tiff_with_base(data, 0, tiff_type_is_tiff, standalone_tiff, file_type)
}

/// Parse a TIFF block whose start sits at file offset `base` (`$$dirInfo{Base}`).
///
/// `base` is added to `IsOffset` value tags (`Exif.pm:7156-7170`) to convert
/// them to absolute file offsets. The standalone-TIFF entries pass `base == 0`;
/// the JPEG `APP1` Exif path passes the file offset of the embedded TIFF block.
/// IFD offsets themselves are unchanged — they remain relative to `data`.
///
/// `tiff_type_is_tiff` controls the `File:PageCount` emission gate at
/// `ExifTool.pm:8756-8757`: bundled emits the synthesized `PageCount` tag
/// only when `$$self{TIFF_TYPE} eq 'TIFF'`, i.e. when the OUTER file type is
/// "TIFF" (the standalone `.tif`/`.tiff` dispatch path). Embedded-block
/// callers (`parse_exif_block` / `_with_base`) pass `false` — bundled gates
/// the emission via `Parent` ('PNG' / 'APP1' / 'QuickTime' / 'RIFF'), which
/// stays the outer container's name and never becomes "TIFF" in those
/// recursive `ProcessTIFF` calls.
///
/// `standalone_tiff` is the CR2-magic `$raf` gate (`ExifTool.pm:8629`): `true`
/// only for the standalone-TIFF dispatch, `false` for the embedded-block
/// callers — DISTINCT from `tiff_type_is_tiff` (see
/// [`parse_tiff_with_base_no_raf`]).
///
/// `file_type` is the container's detected `$$self{FILE_TYPE}` — stored on the
/// resulting [`ExifMeta`] and threaded to the Canon MakerNote decoder for the
/// `Canon::ShotInfo` pos-22 CRW-allows-0 RawConv (`Canon.pm:2977`/`:2990`).
/// The standalone-TIFF dispatch passes the candidate `Parent`
/// (`"TIFF"`/`"DNG"`/…); the embedded-block callers pass `None` (a JPEG/PNG
/// container is never "CRW"). It is otherwise WRITE-ONLY — it changes no
/// other tag, and no reachable input is a CRW today (no CIFF/CRW parser).
fn parse_tiff_with_base<'a>(
  data: &'a [u8],
  base: u32,
  tiff_type_is_tiff: bool,
  standalone_tiff: bool,
  file_type: Option<&str>,
) -> Option<ExifMeta<'a>> {
  parse_tiff_with_base_no_raf(
    data,
    base,
    tiff_type_is_tiff,
    standalone_tiff,
    file_type,
    /* no_raf */ false,
    /* ifd0_kind */ IfdKind::Ifd0,
  )
}

/// [`parse_tiff_with_base`] with the no-RAF framing made explicit. `no_raf` is
/// `false` for every caller except the Canon CTMD `0x8769` ExifIFD re-dispatch
/// ([`parse_ctmd_exif_ifd_redispatch`]) — see [`Walker::no_raf`].
///
/// `standalone_tiff` stands in for ExifTool's `$raf` gate on the CR2-magic read
/// (`ExifTool.pm:8629`): it is `true` ONLY for the standalone-TIFF parse path
/// (the top-level `$raf`-backed file — [`parse_tiff`] via [`ProcessExif::parse`]
/// / [`parse_borrowed`], and [`parse_standalone_tiff_with_base`]), and `false`
/// for every embedded block (a JPEG `APP1` / PNG `eXIf` / QuickTime `EXIF` /
/// RIFF `exif` TIFF, the Canon CTMD `0x8769` re-dispatch, the CR3 `CMT4` GPS
/// block). It is DISTINCT from `tiff_type_is_tiff` (the extension-derived
/// `$$self{TIFF_TYPE} eq 'TIFF'` PageCount gate, `ExifTool.pm:8767`): the CR2
/// magic must be computed for EVERY standalone TIFF regardless of the
/// extension-derived subtype, so a CR2 body renamed `.dng`/`.nef`/`.arw` (whose
/// extension maps to a RAW subtype ⇒ `tiff_type_is_tiff` false) STILL records
/// the byte-8 signature and finalizes `File:FileType = CR2` (oracle-verified).
///
/// `ifd0_kind` is the [`IfdKind`] the TOP-LEVEL directory is walked as — almost
/// always [`IfdKind::Ifd0`] (the standard `ProcessTIFF` entry, whose IFD0 uses
/// `Exif::Main` and reaches GPS/ExifIFD/Interop via SubIFD pointers). The Canon
/// CR3 `CMT4` box is the sole exception: ExifTool dispatches it through
/// `SubDirectory { TagTable => GPS::Main, ProcessProc => ProcessTIFF }`
/// (Canon.pm:9719-9726), so its top-level directory IS the GPS IFD —
/// [`parse_gps_block`] passes [`IfdKind::Gps`] to walk IFD0 against the GPS
/// table directly.
fn parse_tiff_with_base_no_raf<'a>(
  data: &'a [u8],
  base: u32,
  tiff_type_is_tiff: bool,
  standalone_tiff: bool,
  file_type: Option<&str>,
  no_raf: bool,
  ifd0_kind: IfdKind,
) -> Option<ExifMeta<'a>> {
  // `length $$dataPt < 8` — the TIFF header is 8 bytes.
  if data.len() < 8 {
    return None;
  }
  // `my $byteOrder = substr($$dataPt,0,2); SetByteOrder(...) or return 0`. The
  // `len < 8` guard above makes `data.get(..2)` `Some` — the checked,
  // byte-identical form of `&data[..2]` (the `?` short-circuit is unreachable).
  let order = ByteOrder::from_marker(data.get(..2)?)?;
  // `my $identifier = Get16u($dataPt, 2)` — the TIFF magic in `order`: classic
  // TIFF is 0x2a (42), BigTIFF is 0x2b (43). Classic TIFF stores the IFD0
  // pointer as a 32-bit offset at byte 4 and walks 16-bit entry counts /
  // 12-byte entries; BigTIFF uses an 8-byte offset, 64-bit counts and 20-byte
  // entries, so the classic layout below would misread it. BigTIFF has its OWN
  // module in bundled (`Image::ExifTool::BigTIFF::ProcessBTF` /
  // `ProcessBigIFD`, dispatched from `DoProcessTIFF`'s `$identifier == 0x2b`
  // arm, `ExifTool.pm:8661-8669`) — NOT `ProcessExif` — so we branch to the
  // dedicated [`parse_bigtiff`] walker (8-byte widths, the same `Exif::Main`
  // table + `ReadValue`), faithful to that module's separate-walker design.
  //
  // The `0x2b` arm is GATED on `standalone_tiff`: bundled reaches `ProcessBTF`
  // only from inside `DoProcessTIFF`'s `if ($raf)` block (`ExifTool.pm:8629`/
  // `:8661`), i.e. the top-level standalone-TIFF dispatch. An EMBEDDED block
  // (JPEG `APP1` / PNG `eXIf` / QuickTime `EXIF` / a MakerNote / GPS re-dispatch
  // — `standalone_tiff == false`) has no `$raf`, so a stray `0x2b` there never
  // becomes BigTIFF; it returns `None` (no Exif), as bundled (an `APP1` with a
  // non-`0x2a` identifier merely warns + falls through, never `ProcessBTF`).
  let magic = get_u16(data, 2, order)?;
  if magic == 0x2b {
    if !standalone_tiff {
      return None;
    }
    return parse_bigtiff(data, order, base, file_type, no_raf, ifd0_kind);
  }
  // `my $offset = Get32u($dataPt, 4); $offset >= 8 or return 0`.
  let ifd0_offset = get_u32(data, 4, order)? as usize;
  if ifd0_offset < 8 {
    return None;
  }
  // Canon CR2 magic (`ExifTool.pm:8629-8645`): gated on `$raf` (8629 — the
  // standalone-TIFF dispatch has one; embedded `APP1`/`eXIf` blocks do not, so
  // `standalone_tiff` stands in for it) and `$identifier == 0x2a and $offset
  // >= 16` (8633), then an 8-byte signature read at byte 8 (8634:
  // `$raf->Read($sig, 8) == 8 or return 0`). A leading `CR\x02\0` (8636/8641)
  // makes `$fileType = 'CR2'`, so the engine finalizes `File:FileType = CR2`
  // (`image/x-canon-cr2`) regardless of extension. The gate is
  // `standalone_tiff`, NOT `tiff_type_is_tiff`: the latter is the
  // extension-derived `TIFF_TYPE eq 'TIFF'` PageCount gate (false for a CR2
  // body renamed `.dng`/`.nef`/`.arw`, whose extension maps to a RAW subtype),
  // and ExifTool's `$raf` CR2 check runs for EVERY standalone TIFF before any
  // extension-derived subtype is consulted — so the magic wins over the RAW
  // extension (oracle: CanonRaw.cr2 as foo.dng/foo.nef → CR2). We detect ONLY
  // the `CR2` signature here (the `\xba\xb0\xac\xbb` "Canon 1D RAW" arm has no
  // bundled fixture / is out of #181 scope).
  //
  // The 8-byte read at 8634 is a HARD prerequisite — and ExifTool's `return 0`
  // there rejects the WHOLE TIFF, not merely the CR2 arm. Faithful to
  // `ExifTool.pm:8629-8634`:
  //
  // ```perl
  // if ($raf) {                                    # 8629
  //     if ($identifier == 0x2a and $offset >= 16) {  # 8633
  //         $raf->Read($sig, 8) == 8 or return 0;      # 8634
  // ```
  //
  // i.e. for a `$raf`-backed (standalone) classic TIFF whose IFD0 offset is
  // already ≥ 16, an 8-byte read at byte 8 that comes up short aborts
  // `DoProcessTIFF` BEFORE any IFD walk — yielding `File format error` / NO
  // `File:FileType`. So a standalone classic TIFF (`magic == 0x2a`) declaring
  // `ifd0_offset >= 16` yet shorter than 16 bytes must REJECT the candidate
  // (return `None`) here, rather than fall through to the lenient IFD walker
  // (which would recover it to a plain `TIFF` — a divergence). The reject is
  // PRECISE: it fires only for this malformed/truncated shape (the IFD0 offset
  // already points past EOF, so the walk would fail/recover anyway); a valid
  // small TIFF (`ifd0_offset < 16`, or ≥ 16 bytes present) is untouched, as is
  // every embedded `APP1`/`eXIf` block (gated by `standalone_tiff`). The engine
  // then exhausts the candidate loop and emits the same finalization `Error`
  // ExifTool does (`File format error` for a recognized `.tif`, `Unknown file
  // type` for a dotless name) — oracle-verified on a crafted 12/13/15-byte
  // `II*\0` + offset-16 header.
  if standalone_tiff && magic == 0x2a && ifd0_offset >= 16 && data.get(8..16).is_none() {
    return None;
  }
  // The CR2 signature: now that the 8-byte read at byte 8 is guaranteed
  // satisfiable under the same gate (the reject above bailed otherwise), test
  // only its leading four bytes for `CR\x02\0` (8636/8641 — `$fileType =
  // 'CR2'`, so the engine finalizes `File:FileType = CR2` regardless of
  // extension). The `data.get(8..16).is_some()` clause is retained so this stays
  // self-evidently panic-free in isolation (bounds-checked `.get()`, no slicing);
  // it is redundant after the reject but a cheap guard, not a behavior change.
  let cr2_magic = standalone_tiff
    && magic == 0x2a
    && ifd0_offset >= 16
    && data.get(8..16).is_some()
    && data.get(8..12) == Some(b"CR\x02\0".as_slice());

  // The container `$$self{FILE_TYPE}` — owned once so it can be both threaded
  // to the Canon MakerNote decoder (the pos-22 CRW gate, read at walk time)
  // and stored on the resulting `ExifMeta`.
  let file_type: Option<smol_str::SmolStr> = file_type.map(smol_str::SmolStr::new);
  let mut w = Walker {
    data,
    order,
    base,
    // Core / inherit-base walk — child `$dataPos == 0`, no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    captured_model: None,
    // COMMON path: a fresh per-block set ⇒ silent trailing-chain revisit
    // (no cross-source cycle-guard). Byte-identical to before.
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    file_type: file_type.clone(),
    // RAF-backed framing — every caller of this function has an effective RAF
    // (the block IS the whole readable buffer). The no-RAF CTMD `0x8769` hop
    // uses [`parse_ctmd_exif_ifd_redispatch`] instead.
    no_raf,
    // `$warnCount` starts at 0 (`Exif.pm:6453`); `walk_one_ifd_body` re-zeroes
    // it per directory.
    warn_count: 0,
    // The walk starts on the Exif table; `walk_ifd_chain` re-affirms it and
    // `process_subdir` swaps it for a sub-IFD's table (GPS) and restores it.
    active_table: TableRef::Exif,
    // The Canon DataMembers are meaningful only during a Canon sub-walk; the
    // pre-scan sets them when `process_subdir(TableRef::Canon)` runs.
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // Walk the IFD0 → IFD1 chain (the next-IFD pointer). ExifIFD/GPS/Interop
  // are reached as SubDirectories from inside the walk. `ifd0_kind` is `Ifd0`
  // for the standard `ProcessTIFF` entry; the CR3 `CMT4` GPS block passes
  // `Gps` so the top directory walks against the GPS table (Canon.pm:9719-9726).
  w.walk_ifd_chain(ifd0_offset, ifd0_kind);
  // The Owned guard never raises a cross-source cycle-guard warning, so this
  // is always empty on the common path — assert it to lock the invariant.
  debug_assert!(
    w.cycle_guard_warnings.is_empty(),
    "the common (Owned) path must never produce cross-source cycle-guard warnings"
  );

  // `File:PageCount` synthesis (`ExifTool.pm:8756-8757`): emitted ONLY when
  // `$$self{TIFF_TYPE} eq 'TIFF'`. The embedded paths (PNG `eXIf`, JPEG `APP1`,
  // QuickTime EXIF atom, RIFF `exif` chunk — for those `TIFF_TYPE` is
  // 'PNG'/'APP1'/'QuickTime'/'RIFF') call [`parse_exif_block`] / the
  // `_with_base` variant, which pass `tiff_type_is_tiff = false` and drop the
  // synthesized tag. The standalone entry passes `true`.
  //
  // A content-detected RAW subtype rewrites `$$self{TIFF_TYPE}` away from
  // "TIFF" BEFORE this `PageCount` check: the CR2 magic sets it directly
  // (`= 'CR2'`, `ExifTool.pm:8715`) and the `DNGVersion` override sets it to
  // 'DNG' (`ExifTool.pm:8765`). Both run before `ExifTool.pm:8767`, so neither
  // a CR2 nor a DNG ever emits `File:PageCount` — suppress it here when the
  // standalone walk detected either signature.
  let tiff_type_is_tiff = tiff_type_is_tiff && !cr2_magic && !w.dng_version;
  let multi_page_count = if tiff_type_is_tiff && w.multi_page {
    Some(w.page_count)
  } else {
    None
  };

  Some(ExifMeta {
    entries: w.entries,
    warnings: w.warnings,
    warnings_ignorable: w.warnings_ignorable,
    byte_order: Some(order),
    maker_note: w.maker_note,
    multi_page_count,
    file_type,
    captured_model: w.captured_model.map(smol_str::SmolStr::from),
    dng_version: w.dng_version,
    cr2_magic,
    // A standalone-TIFF walk has no JPEG marker positions and no `APP`-segment
    // aux blocks (no `APP6` GoPro).
    #[cfg(feature = "quicktime")]
    exif_block_pos: None,
    #[cfg(feature = "quicktime")]
    jpeg_aux_blocks: std::vec::Vec::new(),
  })
}

// ====================================================================// BigTIFF (0x2b) — Image::ExifTool::BigTIFF (ProcessBTF / ProcessBigIFD)
// ====================================================================
/// Parse a BigTIFF (`0x2b`) block — the faithful port of `ProcessBTF`
/// (`BigTIFF.pm:234-264`).
///
/// BigTIFF differs from classic TIFF ONLY in widths: a 16-byte header (8-byte
/// IFD0 offset), an 8-byte entry count, 20-byte entries
/// (`tag(2) format(2) count(8) value-or-offset(8)`), an 8-byte next-IFD
/// pointer, and the inline-value cutoff is 8 (not 4) bytes. ExifTool walks it
/// through the dedicated `ProcessBigIFD` (NOT `ProcessExif`), reusing the same
/// `Exif::Main` tag table + `ReadValue`; this mirrors that with the shared
/// [`Walker`] (so [`Walker::emit`] / [`Walker::dispatch_subdir`] and the
/// `Exif`/`GPS` tables are reused unchanged) and a focused 8-byte-width IFD
/// walk ([`Walker::walk_big_ifd_chain`]).
///
/// `ProcessBTF`'s header gate (`BigTIFF.pm:240-241`) is a strict 16-byte
/// signature: `^(MM\0\x2b\0\x08\0\0|II\x2b\0\x08\0\0\0)` — the byte order, the
/// `0x2b` magic, **offset-bytesize `0x0008`** (bytes 4-5) and the **`0x0000`
/// constant** (bytes 6-7) must ALL match. A non-8 offset-bytesize or a
/// non-zero constant is REJECTED (`return None`), faithful to the regex not
/// matching → `ProcessBTF return 0`.
///
/// `order` / `magic == 0x2b` were already decoded by the caller
/// ([`parse_tiff_with_base_no_raf`]); `base` / `no_raf` / `ifd0_kind` are
/// threaded for parity with the classic path. In practice BigTIFF is reachable
/// ONLY from the standalone-TIFF dispatch (`DoProcessTIFF`'s `$raf` arm,
/// `ExifTool.pm:8661`), so `base == 0`, `no_raf == false` and
/// `ifd0_kind == IfdKind::Ifd0` for every real caller.
fn parse_bigtiff<'a>(
  data: &'a [u8],
  order: ByteOrder,
  base: u32,
  file_type: Option<&str>,
  no_raf: bool,
  ifd0_kind: IfdKind,
) -> Option<ExifMeta<'a>> {
  // `$raf->Read($buff, 16) == 16` then the 16-byte signature regex
  // (`BigTIFF.pm:240-241`). The order + `0x2b` magic are already validated by
  // the caller; here we enforce the remaining two header fields in `order`:
  //   - offset-bytesize at byte 4 MUST be `0x0008` (`\x08\0` LE / `\0\x08` BE);
  //   - the constant at byte 6 MUST be `0x0000`.
  // A short (< 16-byte) header fails the `Read == 16` → `return None`.
  if get_u16(data, 4, order)? != 8 {
    return None;
  }
  if get_u16(data, 6, order)? != 0 {
    return None;
  }
  // `my $offset = Get64u(\$buff, 8)` (`BigTIFF.pm:248`) — the 8-byte IFD0
  // offset. (ExifTool does NOT gate it `>= 16` the way classic TIFF gates
  // `>= 8`; `ProcessBigIFD`'s seek/read bounds-check it.)
  let ifd0_offset = usize::try_from(get_u64(data, 8, order)?).ok()?;

  let file_type: Option<smol_str::SmolStr> = file_type.map(smol_str::SmolStr::new);
  let mut w = Walker {
    data,
    order,
    base,
    // Core / inherit-base walk — child `$dataPos == 0`, no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    captured_model: None,
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    file_type: file_type.clone(),
    no_raf,
    warn_count: 0,
    // The BigTIFF walker keys its leaf lookup off `kind` directly
    // (`big_tag_known`), not `active_table`; this just satisfies the struct.
    active_table: TableRef::Exif,
    // BigTIFF never dispatches the Canon sub-walk; these stay `None`.
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  w.walk_big_ifd_chain(ifd0_offset, ifd0_kind);
  debug_assert!(
    w.cycle_guard_warnings.is_empty(),
    "the common (Owned) path must never produce cross-source cycle-guard warnings"
  );

  Some(ExifMeta {
    entries: w.entries,
    warnings: w.warnings,
    warnings_ignorable: w.warnings_ignorable,
    // `DoProcessTIFF`'s BigTIFF arm (`ExifTool.pm:8661-8668`) is: call
    // `ProcessBTF`, then `FoundTag(PageCount => …) if $$self{MultiPage}` (`:8667`),
    // then `return 1` (`:8668`) — BEFORE the classic `File:ExifByteOrder`
    // `FoundTag` (`:8691`). So a BigTIFF emits `File:PageCount` (reached at :8667)
    // but NOT `File:ExifByteOrder` (after the :8668 return; oracle-confirmed — the
    // bundled `BigTIFF.btf` has none while a classic TIFF does). Leave `byte_order`
    // (the `File:ExifByteOrder` emission signal) `None`; the walk already used the
    // local `order`.
    byte_order: None,
    maker_note: w.maker_note,
    // `File:PageCount` IS emitted for a BigTIFF whose IFD chain tripped `MultiPage`
    // (a `SubfileType == 2` / `OldSubfileType == 3` `RawConv` tap in `Walker::emit`,
    // `Exif.pm:456`/`:473`) — the `:8667` `FoundTag` gates on `$$self{MultiPage}`
    // ALONE (unlike the classic `:8768` site it has NO `TIFF_TYPE eq 'TIFF'`
    // check), so mirror it on `w.multi_page`. The flat `BigTIFF.btf` has no
    // SubfileType ⇒ `multi_page == false` ⇒ `None`, matching its oracle.
    multi_page_count: if w.multi_page {
      Some(w.page_count)
    } else {
      None
    },
    // `ProcessBTF` `$et->SetFileType('BTF')` (`BigTIFF.pm:246`) FORCES the file
    // type to `BTF` on the 0x2b magic, REGARDLESS of extension — so a BigTIFF
    // named `.tif` / dotless still finalizes `File:FileType = BTF`. Carry that
    // signal HERE (the ExifMeta's `file_type`), overriding the passed detection
    // candidate (which is `TIFF` for a `.tif` BigTIFF); `finalize_file_type`'s
    // `AnyMeta::Exif` arm maps a `Some("BTF")` signal to an explicit BTF type +
    // `image/x-tiff-big` MIME. (The WALKER above keeps the passed container
    // `file_type` for the Canon-CRW RawConv gate — `BTF` ≠ `CRW`, so unaffected.)
    file_type: Some(smol_str::SmolStr::new("BTF")),
    captured_model: w.captured_model.map(smol_str::SmolStr::from),
    // `DNGVersion` (0xc612)'s RawConv still runs in `Walker::emit`, but a
    // BigTIFF is finalized as `BTF` (`ProcessBTF` `SetFileType('BTF')`), NOT
    // `TIFF`, so `DoProcessTIFF`'s `$$self{FILE_TYPE} eq 'TIFF'` DNG override
    // (`ExifTool.pm:8763`) is unreachable for it — the engine reads
    // `has_dng_version()` only when `base_type == "TIFF"`.
    dng_version: w.dng_version,
    // The Canon CR2 byte-8 magic is a CLASSIC-TIFF (`$identifier == 0x2a`)
    // signal only (`ExifTool.pm:8633`); never set for BigTIFF.
    cr2_magic: false,
    #[cfg(feature = "quicktime")]
    exif_block_pos: None,
    #[cfg(feature = "quicktime")]
    jpeg_aux_blocks: std::vec::Vec::new(),
  })
}

/// **PNG multi-EXIF-source seam — ExifTool's object-level `$$et{PROCESSED}`.**
/// Parse one Exif/TIFF block whose chain-IFD reprocess guard is the EXTERNAL
/// `processed` map, SHARED across every block in a single PNG file
/// (`ExifTool.pm:9061-9072`). Returns the parsed [`ExifMeta`] (whatever
/// directories were NOT blocked) plus the cross-source cycle-guard warnings
/// raised while walking THIS block.
///
/// This is a thin, ADDITIVE wrapper over [`parse_tiff_with_base`]: it injects a
/// [`ChainGuard::Shared`] over `processed` (instead of the common path's fresh
/// internal [`HashSet`](std::collections::HashSet)) and surfaces the collected
/// cycle-guard warnings. NOTHING else differs — the same TIFF-header gate, the
/// same IFD walk, the same tag decoding, the same `DirLen=0` sub-IFD skip
/// (ExifIFD/GPS/InteropIFD are STILL reprocessed across sources, matching
/// `ExifTool.pm:9052`). The common [`parse_exif_block`] /
/// [`parse_exif_block_with_base`] / `parse_tiff_with_base` entries keep their
/// behaviour EXACTLY (fresh [`ChainGuard::Owned`], silent revisit, no warning).
///
/// `processed` maps a chain-IFD `$addr` (the IFD0 pointer for IFD0; the
/// next-IFD pointer for a trailing IFD) to the `$dirName` that first claimed it
/// (`IFD0` / `IFD1` / …). A later block whose IFD0 lands on an `$addr` already
/// in the map is BLOCKED: its IFD0 directory is skipped (so it contributes NO
/// tags — ExifTool `return 0`s out of `ProcessExif` before the trailing scan,
/// so the whole block yields nothing), and a
/// `"IFD0 pointer references previous <prev> directory"` warning is returned
/// (`<prev>` = the recorded name, e.g. `IFD1` for a cross-source trailing-IFD
/// collision). A `ProcessProfile` source resets `$$et{PROCESSED}` BEFORE
/// calling this (`PNG.pm:1193`) — the caller clears `processed` first.
///
/// The block's OWN `$et->Warn` corpus (Bad-directory, suspicious-offset, …)
/// stays in the returned [`ExifMeta`]'s [`warnings`](ExifMeta::warnings); the
/// cycle-guard warnings are returned SEPARATELY so the PNG layer can sequence
/// them faithfully (ExifTool raises them from the `ProcessDirectory`
/// dispatcher, around the per-source warnings).
///
/// Returns `(None, vec![])` when `block` is not a valid TIFF header (same gate
/// as [`parse_exif_block`]) — a malformed block neither blocks itself nor a
/// later source and registers no `$addr`.
///
/// Gated on `feature = "exif"` only — exactly like [`parse_exif_block`] /
/// [`parse_exif_block_with_base`] (the surrounding walker uses `Vec` / `SmolStr`
/// freely; the whole module is de-facto `alloc`-requiring, so no extra `alloc`
/// gate is added here — keeping this in lock-step with its siblings avoids a
/// gating mismatch with the `exif`-gated PNG caller).
#[must_use]
pub fn parse_exif_block_with_shared_processed<'a>(
  block: &'a [u8],
  base: u32,
  processed: &mut std::collections::HashMap<usize, IfdName>,
) -> (Option<ExifMeta<'a>>, Vec<smol_str::SmolStr>) {
  parse_tiff_with_base_shared(block, base, processed)
}

/// The [`ChainGuard::Shared`] sibling of [`parse_tiff_with_base`] — see
/// [`parse_exif_block_with_shared_processed`]. Factored out so the public
/// wrapper stays a one-liner and the header gate / walk body is shared with the
/// common path verbatim.
fn parse_tiff_with_base_shared<'a>(
  data: &'a [u8],
  base: u32,
  processed: &mut std::collections::HashMap<usize, IfdName>,
) -> (Option<ExifMeta<'a>>, Vec<smol_str::SmolStr>) {
  // Same TIFF-header gate as `parse_tiff_with_base` (kept in lock-step). A
  // malformed header yields no meta and no warnings, and (crucially) does NOT
  // touch `processed` — so a broken block neither blocks itself nor a later
  // source.
  if data.len() < 8 {
    return (None, Vec::new());
  }
  // `data.get(..2)` is `Some` under the `len < 8` guard — the checked,
  // byte-identical form of `&data[..2]`.
  let Some(order) = data.get(..2).and_then(ByteOrder::from_marker) else {
    return (None, Vec::new());
  };
  let Some(magic) = get_u16(data, 2, order) else {
    return (None, Vec::new());
  };
  if magic == 0x2b {
    // BigTIFF — deferred, same as the common path.
    return (None, Vec::new());
  }
  let Some(ifd0_offset) = get_u32(data, 4, order).map(|o| o as usize) else {
    return (None, Vec::new());
  };
  if ifd0_offset < 8 {
    return (None, Vec::new());
  }

  let mut w = Walker {
    data,
    order,
    base,
    // Core / inherit-base walk — child `$dataPos == 0`, no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    captured_model: None,
    // SHARED path: the external `$$et{PROCESSED}` map. A chain-IFD revisit —
    // within this block or from an earlier source — warns + skips.
    chain_guard: ChainGuard::Shared(processed),
    cycle_guard_warnings: Vec::new(),
    active_ifd_offsets: Vec::new(),
    // The multi-page walk-state still ticks via the `SubfileType` RawConv tap,
    // but this SHARED path is only ever the embedded-block parse (PNG `eXIf`),
    // so the resulting `ExifMeta` is `multi_page_count: None` — `File:PageCount`
    // is gated to the standalone-TIFF dispatch (`tiff_type_is_tiff`).
    page_count: 0,
    multi_page: false,
    // The `DNGVersion` tap still ticks, but this SHARED path is the embedded
    // PNG `eXIf` / CTMD `0x8769` parse, never the standalone-TIFF dispatch, so
    // the DNG override (gated on `FILE_TYPE eq 'TIFF'`) is unreachable from it.
    dng_version: false,
    // Embedded block (PNG `eXIf`): `$$self{FILE_TYPE}` is "PNG", never "CRW",
    // so the ShotInfo pos-22 CRW clause is off — model it as `None`.
    file_type: None,
    // PNG `eXIf` is a self-contained block read into memory; its value offsets
    // resolve within the block (an effective RAF, like the standalone path), so
    // the RAF-backed framing is faithful. Only the CTMD `0x8769` hop is no-RAF.
    no_raf: false,
    // `$warnCount` starts at 0 (`Exif.pm:6453`); re-zeroed per directory.
    warn_count: 0,
    // Starts on the Exif table; `walk_ifd_chain` re-affirms it.
    active_table: TableRef::Exif,
    // The embedded PNG `eXIf` / CTMD path never dispatches the Canon sub-walk
    // through `process_subdir(TableRef::Canon)`; these stay `None`.
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  w.walk_ifd_chain(ifd0_offset, IfdKind::Ifd0);

  let cycle_guard_warnings = w.cycle_guard_warnings;
  let meta = ExifMeta {
    entries: w.entries,
    warnings: w.warnings,
    warnings_ignorable: w.warnings_ignorable,
    byte_order: Some(order),
    maker_note: w.maker_note,
    // Embedded block (PNG `eXIf`): never the standalone-TIFF dispatch, so no
    // synthesized `File:PageCount`.
    multi_page_count: None,
    // Embedded block (PNG `eXIf`) — never "CRW" (see the Walker field above).
    file_type: None,
    captured_model: w.captured_model.map(smol_str::SmolStr::from),
    // Embedded PNG `eXIf` / CTMD `0x8769` block: `$$self{FILE_TYPE}` is the
    // OUTER container ("PNG"/…), never "TIFF", so the DNG override is
    // unreachable; the CR2 magic read is gated on the standalone-TIFF `$raf`.
    dng_version: false,
    cr2_magic: false,
    // An embedded-Exif block (PNG `eXIf`) has no JPEG marker positions and no
    // `APP`-segment aux blocks (no `APP6` GoPro).
    #[cfg(feature = "quicktime")]
    exif_block_pos: None,
    #[cfg(feature = "quicktime")]
    jpeg_aux_blocks: std::vec::Vec::new(),
  };
  (Some(meta), cycle_guard_warnings)
}

// ====================================================================// IFD walker — ProcessExif (Exif.pm:6278-7240)
// ====================================================================
/// The chain-IFD (IFD0 / trailing-IFD) reprocess guard — the storage behind
/// ExifTool's `$$self{PROCESSED}` for the non-zero-`DirLen` directories
/// (`ExifTool.pm:9050-9072`). Two modes:
///
/// * [`ChainGuard::Owned`] — a fresh per-block `HashSet<usize>`. This is the
///   COMMON path ([`parse_exif_block`] / [`parse_exif_block_with_base`] /
///   [`parse_tiff_with_base`]): a chain-IFD revisit silently `return 0`s (no
///   warning), exactly the pre-existing trailing-chain loop breaker. Every
///   non-PNG format and every standalone TIFF takes this path, so its
///   behaviour is byte-identical to before this guard was made pluggable.
/// * [`ChainGuard::Shared`] — an EXTERNAL `HashMap<usize, IfdName>` borrowed
///   from the caller and SHARED across several TIFF blocks
///   ([`parse_exif_block_with_shared_processed`], used only by the PNG
///   multi-EXIF-source replay). This is ExifTool's OBJECT-level `$$et{PROCESSED}`:
///   one set spanning every `ProcessTIFF` call in the file, keyed on each
///   directory's `$addr` and mapping it to the `$dirName` that first claimed it
///   (`ExifTool.pm:9066-9071`). A revisit — within ONE block (a looping next-IFD
///   chain) OR across two PNG EXIF sources (a later source's IFD0 landing on an
///   earlier source's already-walked IFD0 *or trailing IFD*) — warns
///   `"<DirName> pointer references previous <prev> directory"` and `return 0`s
///   that directory (`ExifTool.pm:9068`). The map (not a bare `HashSet`) is
///   required to spell `<prev>`: the cross-source TRAILING-IFD case reports the
///   previous directory as `IFD1`/`IFD2`/… (the recorded name), not `IFD0`
///   (verified against bundled 13.59 — see `tests/png.rs`'s
///   `engine_cross_source_trailing_ifd_collision_*`).
enum ChainGuard<'g> {
  /// A fresh per-block set — silent collision (the common, behaviour-preserving
  /// path).
  Owned(std::collections::HashSet<usize>),
  /// An external map shared across TIFF blocks — collision warns + skips (the
  /// PNG multi-source path, ExifTool's object-level `$$et{PROCESSED}`).
  Shared(&'g mut std::collections::HashMap<usize, IfdName>),
}

/// IFD walker state. All IFD offsets are relative to the start of `data`
/// (the TIFF block) — i.e. `$base == 0`, `$dataPos == 0` in ExifTool terms
/// (`DoProcessTIFF` builds `%dirInfo` with `Base => $base` and the EXIF data
/// is the whole block — `ExifTool.pm:8703-8714`).
///
/// `'g` is the lifetime of the optional external `$$et{PROCESSED}` map borrowed
/// by [`ChainGuard::Shared`]; for the common [`ChainGuard::Owned`] path it is
/// unconstrained (the set is owned inline).
struct Walker<'a, 'g> {
  /// The TIFF block.
  data: &'a [u8],
  /// The TIFF byte order.
  order: ByteOrder,
  /// ExifTool's `$base` for the walk (`Exif.pm:6287` `$base = $$dirInfo{Base}
  /// || 0`). All IFD offsets remain relative to the start of `data`, but an
  /// `IsOffset` value tag (`StripOffsets` 0x0111, `ThumbnailOffset` 0x0201,
  /// both `IsOffset => 1`) is converted to an ABSOLUTE file offset by adding
  /// `$base + $$et{BASE}` (`Exif.pm:7156-7170`). For a standalone TIFF file
  /// `$base == 0` (the TIFF block IS the file); for a JPEG `APP1` Exif block
  /// `$base` is the file offset of the TIFF block (`DirStart(\%dirInfo,
  /// $hdrLen, $hdrLen)` sets `$$dirInfo{Base} = $$dirInfo{DataPos} + $base`,
  /// `ExifTool.pm:7780`). `$$et{BASE}` is 0 for the top-level Exif walk
  /// (set non-zero only for relative-base maker notes — out of scope), so we
  /// thread the single `$base` value.
  base: u32,
  /// The OUT-OF-LINE value-offset addend — ExifTool's `$base - $subdirBase`
  /// shift expressed in the port's buffer coordinates (the negative of the
  /// child `$dataPos`, `Exif.pm:6546`/`:7040`). The `size > 4` value pointer
  /// `off` resolves to `data[off + value_offset_base]`. It is `0` for every core
  /// IFD and every INHERIT-base maker note (data IS the parent TIFF, child
  /// `$dataPos == 0`), so the existing walks are byte-identical; it is the
  /// SubDirectory `Base => N` literal for a relative-base maker note — `12` for
  /// the `MakerNotePanasonic3` DC-FT7 (`Base => 12`, `MakerNotes.pm:758`),
  /// reproducing `walk_panasonic_in_tiff`'s `off + base_offset` (`panasonic/
  /// body.rs:150`). This is the value-pointer base the `process_subdir`
  /// `fix_base` hook anticipated threading (`base/data_pos mutation … applied by
  /// the Phase-2 vendor migration`); the Panasonic isolated walk is its first
  /// user (#243 phase 3). INLINE values (`size <= 4`) carry no pointer and are
  /// NEVER shifted (`Exif.pm:6504`). DISTINCT from [`base`](Self::base) (the
  /// `IsOffset` file-offset addend, which Panasonic Main never uses).
  value_offset_base: usize,
  /// Every emitted tag, in walk order (owned).
  entries: Vec<ExifEntry>,
  /// `$et->Warn(...)` messages collected during the walk, in emission
  /// order. Surfaced as `ExifTool:Warning` tags by [`ExifMeta`]. Only the
  /// structural warnings the IFD-bounds checks raise are modelled here
  /// (`Bad … directory`, `Suspicious … offset`, `Error reading value …`);
  /// the full ExifTool warning corpus is a Phase-2 forward-item.
  warnings: Vec<String>,
  /// Per-warning `sub Warn` ignorable level, index-aligned with
  /// [`warnings`](Self::warnings) (Phase C). `2` for the `[Minor]` excessive-
  /// count warning when the count is in `(100000, 2000000]`
  /// (`$minor = $count > 2000000 ? 0 : 2`, Exif.pm:6767); `0` otherwise. The
  /// `[Minor] ` prefix is applied by `run_diagnostics`, not stored.
  warnings_ignorable: Vec<u8>,
  /// The captured MakerNote (0x927c) blob, if seen.
  maker_note: Option<MakerNote<'a>>,
  /// IFD0's `Make` tag value (`Exif.pm:585`) — captured at emit time so
  /// the MakerNotes dispatcher (`MakerNotes.pm`'s `$$self{Make}`
  /// conditions) sees it when the ExifIFD's 0x927c is reached. For a
  /// well-formed IFD0 (`Make`/`Model` precede the ExifIFD pointer 0x8769
  /// in file order, matching ExifTool's `FoundTag` order), the walk has
  /// `Make` resolved before MakerNote dispatch; a malformed file that
  /// orders 0x8769 before `Make` would dispatch with `None`. `None` also
  /// for a file with no `Make` tag. LAST-WINS on a duplicate IFD0 `Make`
  /// (the `RawConv` `$$self{Make} = $val` runs each time — Exif.pm:585).
  /// Owned `String` (transient builder per SmolStr policy: this lives a
  /// few microseconds during one TIFF parse).
  captured_make: Option<String>,
  /// IFD0's `Model` tag value (`Exif.pm:599`) — same role as
  /// [`captured_make`](Self::captured_make), used for the Model-keyed
  /// dispatch conditions (`$$self{Model} eq "DC-FT7"` etc.,
  /// `MakerNotes.pm:735` Panasonic-DC-FT7 carve-out) AND the Canon CTMD
  /// `ProcessExifInfo` `0x8769` → `0x927c` model hand-off (read via
  /// [`ExifMeta::dispatcher_model`]). LAST-WINS on a duplicate IFD0 `Model`
  /// (the `RawConv` `$$self{Model} = $val` runs each time — Exif.pm:599), so
  /// a hostile two-`Model` IFD0 hands off the LATER value.
  captured_model: Option<String>,
  /// Chain-IFD (IFD0 / trailing-IFD) reprocess guard — the trailing-chain
  /// loop breaker AND (in [`ChainGuard::Shared`] mode) the cross-source
  /// `$$et{PROCESSED}` cycle-guard. ExifTool records every NON-zero-`DirLen`
  /// directory in `%PROCESSED` (`ExifTool.pm:9050-9061`); a trailing IFD
  /// carries its true extent as `DirLen`, so a malformed next-IFD chain
  /// that revisits an already-walked trailing IFD is caught by the
  /// `%PROCESSED` guard and `walk_ifd_chain`'s `loop {}` stays finite.
  /// Only chain IFDs are recorded here — IFD-pointer subdirectories
  /// (ExifIFD/GPS/InteropIFD) are NOT, because ExifTool reprocesses a
  /// shared subdirectory offset (see `active_ifd_offsets`).
  ///
  /// The membership store is either an inline `HashSet` (common path, silent
  /// revisit) or an external `HashMap` shared across TIFF blocks (PNG
  /// multi-source path, warning revisit) — see [`ChainGuard`]. Either way it
  /// is a pure membership lookup (`contains`/`insert`, never iterated for
  /// order) that grows with the trailing-IFD chain length, so the
  /// `HashSet`/`HashMap` keeps the revisit check O(1) over a long (or
  /// adversarial) chain. There is no ordering contract — the walk order is
  /// driven by the next-IFD pointers, not by this store.
  chain_guard: ChainGuard<'g>,
  /// Cross-source cycle-guard warnings collected during a
  /// [`ChainGuard::Shared`] walk — the
  /// `"<DirName> pointer references previous <prev> directory"` messages
  /// (`ExifTool.pm:9068`). EMPTY on the common [`ChainGuard::Owned`] path (a
  /// trailing-chain revisit there silently `return 0`s, matching pre-existing
  /// behaviour), so this never allocates for a standalone TIFF or any non-PNG
  /// format. The PNG replay drains these into the document warnings in source
  /// order. They are kept SEPARATE from [`Walker::warnings`] (the directory's
  /// own `$et->Warn` corpus) because ExifTool raises them from the
  /// `ProcessDirectory` dispatcher, not from inside `ProcessExif`.
  cycle_guard_warnings: Vec<smol_str::SmolStr>,
  /// IFD start offsets currently on the ACTIVE recursion path — the
  /// true-cycle guard for IFD-pointer subdirectories. Pushed when
  /// `walk_one_ifd` begins a directory and popped when it returns, so the
  /// vector always holds exactly the chain of directories the walker is
  /// nested inside. A subdirectory pointer that targets an offset already
  /// on this path is a genuine cycle (e.g. an ExifIFD whose 0x8769 tag
  /// points back at itself, or `ExifIFD → GPS → ExifIFD`) and is rejected;
  /// a subdirectory offset shared between two SIBLING / sequentially
  /// completed walks (the first walk has already popped its offset) is NOT
  /// on the path and IS reprocessed — faithful to ExifTool, which skips
  /// the `%PROCESSED` guard for the `DirLen 0` IFD-pointer subdirectories
  /// of a standalone TIFF (`ExifTool.pm:9052`; `Exif.pm:7020-7026` resets
  /// `$size`/`DirLen` to 0 for an out-of-buffer subdirectory start).
  active_ifd_offsets: Vec<usize>,
  /// `$$self{PageCount}` — incremented for every IFD whose `SubfileType`
  /// (0x00fe) value is in `{0, 2}` (the `$val == ($val & 0x02)` mask at
  /// `Exif.pm:453`) OR whose `OldSubfileType` (0x00ff) value is in `{1, 3}`
  /// (`Exif.pm:470`). The `File:PageCount` tag at `ExifTool.pm:8757` reads
  /// this counter. Standalone-TIFF entry only — embedded-block entries
  /// (PNG `eXIf`, JPEG `APP1`, future QuickTime/RIFF) keep it at 0 because
  /// bundled gates the emission on `TIFF_TYPE eq 'TIFF'` (an outer
  /// `Parent='TIFF'`, `ExifTool.pm:8704`) which only the standalone walk
  /// sets.
  page_count: u32,
  /// `$$self{MultiPage}` — sticky flag set when a `SubfileType` value is
  /// exactly `2` (`Exif.pm:456` `$val == 2`) OR an `OldSubfileType` value
  /// is exactly `3` (`Exif.pm:473`) OR a second SubfileType-counted IFD is
  /// reached (`$$self{PageCount} > 1`). Gates the `File:PageCount`
  /// emission at `ExifTool.pm:8757`.
  multi_page: bool,
  /// `$$self{DNGVersion}` — sticky flag set when a `DNGVersion` (0xc612) tag
  /// with a TRUTHY value is seen during the walk, mirroring its `RawConv`
  /// DataMember side effect (`Exif.pm:3365` `$$self{DNGVersion} = $val`) AND the
  /// `if ($$self{DNGVersion} and …)` Perl-truthiness gate of `DoProcessTIFF`
  /// (`ExifTool.pm:8763`), which tests it to override `File:FileType` to `DNG`
  /// for a TIFF-structured file regardless of extension. The tag is NOT in the
  /// port's leaf table, so the tap runs before the unknown-tag `return` in
  /// [`Walker::emit`]; the value is gated through
  /// [`RawValue::is_perl_truthy`](crate::exif::ifd::RawValue::is_perl_truthy)
  /// (a count-0 / scalar-`0` `DNGVersion` is falsy → not set) but never emitted.
  dng_version: bool,
  /// The container's detected `$$self{FILE_TYPE}` (`ExifTool.pm:8715`).
  /// Threaded into the Canon MakerNote decoder so `Canon::ShotInfo` position
  /// 22's RawConv (`Canon.pm:2977`/`:2990`) can keep a raw-0 ExposureTime for
  /// a CRW container. `None` for an embedded Exif block (PNG `eXIf`, JPEG
  /// `APP1` — never "CRW") or when the type is unknown. WRITE-ONLY apart from
  /// that single pos-22 read; it influences no other tag.
  file_type: Option<smol_str::SmolStr>,
  /// `true` when this TIFF block is re-dispatched FROM MEMORY with NO RAF —
  /// the Canon CTMD `ProcessExifInfo` `0x8769` ExifIFD hop (`Canon.pm:10745`
  /// → `ProcessTIFF` with `$dataPt` = the embedded block, no `RAF`). ExifTool's
  /// `ProcessExif` value read (`Exif.pm:6551-6670`) branches on `$raf`: with a
  /// RAF an out-of-bounds out-of-line value is read from the file and, on a
  /// short read, warns `Error reading value …` and ABORTS the directory
  /// (`Exif.pm:6594-6602`); with NO RAF it instead warns `Bad offset for $dir
  /// $tagStr` (`Exif.pm:6660`) and CONTINUES the walk (`$bad = 1`, the value is
  /// dropped). Every reachable caller of this walker EXCEPT the CTMD `0x8769`
  /// hop has an effective RAF (the standalone-TIFF / JPEG-`APP1` / QuickTime-
  /// `Exif` block IS the whole readable buffer, so a past-`data.len()` value is
  /// genuinely past EOF — the RAF read would fail identically), so this is
  /// `false` for all of them and the prior byte-identical behaviour is
  /// preserved. The CTMD `0x8769` hop sets it `true` (the embedded block is a
  /// slice of a larger CTMD payload; bundled re-frames `$dataPt` to that slice
  /// with no RAF). Independent of `$inMakerNotes` (the `0x8769` table is
  /// `Exif::Main`, GROUPS{0} = 'EXIF', so `$inMakerNotes = 0` ⇒ the `Bad offset`
  /// is NON-minor); the `0x927c` Canon-MakerNote hop does not use this walker.
  no_raf: bool,
  /// `$warnCount` — `ProcessExif`'s PER-DIRECTORY warning counter
  /// (`Exif.pm:6453`, `my ($warnCount, $lastID) = (0, -1)`). ExifTool bumps it
  /// for each per-entry validation warning it counts (`++$warnCount` at
  /// `Exif.pm:6472`/6507/6606/6661/6676) and, BEFORE processing each entry,
  /// `if ($warnCount > 10) { Warn("Too many warnings -- $dir parsing aborted",
  /// 2) and return 0 }` (`Exif.pm:6455-6456`) — so an IFD that piles up more
  /// than ten counted warnings is abandoned (with its later entries + next-IFD
  /// pointer NOT processed) after emitting one `[Minor]` abort warning. RESET
  /// to 0 at the start of every directory body ([`walk_one_ifd_body`]); the
  /// counted warnings funnel through [`warn_counted`](Self::warn_counted) and
  /// the cap is enforced in [`walk_entries`](Self::walk_entries). `u32` because
  /// the only entries that bump it are bounded by `num_entries` (≤ 65535).
  warn_count: u32,
  /// The tag table the walk currently resolves names/formats/conversions
  /// against — `$tagTablePtr` in `ProcessExif` (`Exif.pm:6341`). The shared
  /// `Walker` walks IFD0/ExifIFD/Interop/trailing IFDs against `%Exif::Main`
  /// and the GPS IFD against `%GPS::Main`; ExifTool keys the leaf lookup off
  /// the directory's OWN table, not its `DirName`. The pre-unification code
  /// derived the table implicitly from [`IfdKind`] at each lookup site
  /// ([`IfdKind::is_gps`]); threading it as state lets [`process_subdir`]
  /// (the ONE sub-directory entry point) save/set/restore it around a
  /// sub-IFD recursion so a GPS sub-IFD's table never leaks into the parent
  /// IFD0's remaining entries, and lets a future vendor maker note walk the
  /// same machinery against `%Canon::Main`/etc.
  ///
  /// INVARIANT (the Phase-0 byte-identity proof): on every REGULAR-walk
  /// lookup site this field equals [`table_for_ifd_kind`] of the `kind`
  /// being walked — `walk_ifd_chain` sets it to `Exif` for the IFD0→IFD1
  /// chain and `process_subdir` sets it to the sub-IFD's table for the
  /// duration of that recursion — so routing the lookups through it
  /// reproduces the prior `IfdKind`-keyed selection exactly.
  active_table: TableRef,
  /// `$$self{FocalUnits}` Canon DataMember (`%Canon::CameraSettings` position
  /// 25, `Canon.pm:2530-2537`) — captured by [`canon_prescan_datamembers`] from
  /// the CameraSettings (0x01) entry BEFORE the Canon Main IFD's main walk, then
  /// threaded into the `FocalLength` (0x02) sub-table's `ValueConv => '$val /
  /// ($$self{FocalUnits} || 1)'` at emit time (#243 phase 2 step B2). `None`
  /// outside a Canon sub-walk (every non-Canon directory and any Canon IFD with
  /// no readable position-25 FocalUnits); reset to `None` by the pre-scan on
  /// each `process_subdir(TableRef::Canon)` so a sibling/subsequent walk is
  /// unaffected. WRITE-ONLY apart from the [`emit_canon_subtable`] FocalLength
  /// read — it influences no other tag and is inert for the core Exif/GPS walk.
  canon_focal_units: Option<u16>,
  /// `$$self{LensType}` Canon DataMember (`%Canon::CameraSettings` position 22's
  /// `RawConv => '$val ? $$self{LensType} = $val : undef'`, `Canon.pm:2503`) —
  /// captured by [`canon_prescan_datamembers`] from the CameraSettings (0x01)
  /// entry BEFORE the main walk, then threaded into the `FileInfo` (0x93)
  /// sub-table's position-16 `MacroMagnification` `Condition` (`$$self{LensType}
  /// == 124`, `Canon.pm:7002-7005`) at emit time (#243 phase 2 step B2). Same
  /// lifecycle as [`canon_focal_units`](Self::canon_focal_units): `None` outside
  /// a Canon sub-walk, reset by the pre-scan per Canon `process_subdir`.
  canon_lens_type: Option<u16>,
  /// The LAST readable `CanonFocalLength` (0x02) record's reserialized `$$valPt`
  /// — captured by [`canon_prescan_datamembers`] (last-readable-wins, like the
  /// two DataMembers above) so the `FocalLength` sub-table emit decodes EVERY
  /// 0x02 entry from this ONE cached blob. This mirrors `parse_in_tiff`'s
  /// pre-pass, which overwrites `focal_length_data` for each readable 0x02
  /// (`canon/mod.rs:737`) and then renders every 0x02 SubDirectory from that
  /// FINAL cached blob (`canon/mod.rs:883-889`) — so a Canon IFD with two
  /// `CanonFocalLength` entries emits "last,last", NOT "first,last". Reset to
  /// `None` by the pre-scan on each `process_subdir(TableRef::Canon)`; read ONLY
  /// by [`emit_canon_subtable`]'s FocalLength arm. `None` when no readable 0x02
  /// exists ⇒ that arm (and the oracle) emit nothing for FocalLength.
  canon_focal_length_blob: Option<std::vec::Vec<u8>>,
}

impl Walker<'_, '_> {
  /// Record a NORMAL `$et->Warn(msg)` (ignorable `0`), keeping
  /// [`warnings`](Self::warnings) and [`warnings_ignorable`](Self::warnings_ignorable)
  /// index-aligned (the single push funnel for the structural warnings).
  fn warn(&mut self, message: String) {
    self.warnings.push(message);
    self.warnings_ignorable.push(0);
  }

  /// Record a MINOR-WITH-BEHAVIOURAL-CHANGE `$et->Warn(msg, 2)` (ignorable
  /// `2` ⇒ `[Minor]`, applied by `run_diagnostics`). Used for the
  /// excessive-count warning at the `$minor == 2` threshold (Exif.pm:6767).
  fn warn_minor_behavioral(&mut self, message: String) {
    self.warnings.push(message);
    self.warnings_ignorable.push(2);
  }

  /// Record a NORMAL `$et->Warn(msg)` that ALSO bumps `$warnCount`
  /// (`++$warnCount`) — the per-entry validation warnings ExifTool counts
  /// toward the [`warn_count`](Self::warn_count) abort cap: `Bad format …`
  /// (`Exif.pm:6471-6472`), `Invalid size …` (`:6506-6507`), `Error reading
  /// value …` (`:6604-6606`), `Bad offset …` (`:6660-6661`) and `Suspicious …
  /// offset …` (`:6675-6676`). These are exactly the `self.warn` callers inside
  /// the entry loop whose ExifTool site is immediately followed by
  /// `++$warnCount`; the directory-level (`Bad … directory`, `Illegal …
  /// directory size`), the SubIFD `Wrong format`, and the excessive-count
  /// warnings are NOT counted by ExifTool, so they keep using [`warn`](Self::warn)
  /// / [`warn_minor_behavioral`](Self::warn_minor_behavioral). All are NON-minor
  /// (`$inMakerNotes = 0` for every IFD this walker reaches), matching the
  /// generic-Exif frame.
  fn warn_counted(&mut self, message: String) {
    self.warn(message);
    self.warn_count = self.warn_count.saturating_add(1);
  }

  /// Walk an IFD and then follow its next-IFD pointer chain (IFD0 → IFD1 →
  /// …) — faithful to `ProcessExif`'s `$$dirInfo{Multi}` trailing-IFD scan
  /// (`Exif.pm:7202-7228`). `Multi` is set for IFD0 (`Exif.pm:6339`).
  fn walk_ifd_chain(&mut self, start: usize, first_kind: IfdKind) {
    // Seed the active table from the chain's FIRST kind. The IFD0 → IFD1 → …
    // chain re-enters `ProcessExif` with the SAME `$tagTablePtr` (`Exif.pm:7211`
    // `for (;;)`), so the whole chain shares the first kind's table. This is
    // `Exif` for a standard TIFF (`first_kind == Ifd0`), but `parse_gps_block`
    // walks a GPS-only top-level block (`first_kind == Gps`, e.g. a Canon CR3
    // CMT4 directory) against `%GPS::Main` — seeding from `first_kind` keeps that
    // routing correct (a hard-coded `Exif` would resolve the GPS tags in the Exif
    // table and drop/mis-name them). A sub-IFD recursion swaps the table for its
    // own via `process_subdir` (save/set/restore) and restores it on return, so a
    // GPS/Interop sub-IFD cannot leak its table into the chain's later entries.
    self.active_table = table_for_ifd_kind(first_kind);
    let mut offset = start;
    let mut kind = first_kind;
    // The 1-based number of the NEXT trailing IFD. ExifTool strips the
    // trailing digits off `DirName` and appends `$ifdNum + 1`
    // (`Exif.pm:7215-7216`): IFD0 → IFD1, IFD1 → IFD2, IFD2 → IFD3… The
    // chain always starts at IFD0, so the first hop produces `Trailing(1)`.
    // `u32` so the decimal `DirName` keeps incrementing past IFD65535 —
    // ExifTool's `$ifdNum + 1` is plain Perl arithmetic with no cap.
    let mut trailing_num: u32 = 1;
    // `for (;;)` (`Exif.pm:7211`) — ExifTool has NO fixed cap on the
    // trailing-IFD chain. Termination is faithful to the Perl loop:
    //   - `Get32u($dataPt, $dirEnd) or last` — a 0 next pointer ends it
    //     (`walk_one_ifd` returns `Some(0)`);
    //   - an invalid / unreadable directory aborts it (`Some`→`None`);
    //   - the chain-IFD seen-offset guard in `walk_one_ifd` breaks any
    //     cycle — a malformed TIFF that points a trailing IFD back at an
    //     already-walked chain-IFD offset terminates on the first revisit
    //     (every chain hop here is `Ifd0`/`Trailing`, the kinds recorded
    //     in `seen_ifd_offsets`), so the loop is always finite.
    loop {
      let Some(next) = self.walk_one_ifd(offset, kind) else {
        return;
      };
      if next == 0 {
        return; // `Get32u($dataPt, $dirEnd) or last` — a 0 pointer ends the chain.
      }
      // `$newDirInfo{DirName} .= $ifdNum + 1` — number the next trailing
      // IFD (IFD1, IFD2, IFD3…). Plain (unsaturating) `+ 1` on a `u32`,
      // faithful to ExifTool's uncapped Perl arithmetic: a finite chain
      // past IFD65535 emits IFD65536, IFD65537… The chain-IFD seen-offset
      // guard (`walk_one_ifd`) terminates any cycle, so the counter cannot
      // run away — a finite TIFF chain has at most one IFD per distinct
      // offset, far fewer than `u32::MAX`.
      kind = IfdKind::Trailing(trailing_num);
      trailing_num += 1;
      offset = next;
    }
  }

  /// Walk ONE IFD at `ifd_start`, emitting its leaf tags and recursing into
  /// its SubDirectories. Returns `Some(next_ifd_offset)` (0 ⇒ no next IFD)
  /// when the IFD was structurally valid, `None` to abort the chain.
  ///
  /// Faithful to the body of `ProcessExif` (`Exif.pm:6278-7240`).
  ///
  /// This wrapper applies the recursion / reprocess guard, then delegates to
  /// [`walk_one_ifd_body`]. ExifTool's guard is the `%PROCESSED` check at
  /// `ExifTool.pm:9050-9061`: a directory address is remembered, and a
  /// revisit warns `"$dirName pointer references previous $prev directory"`
  /// then `return 0 unless $dirName eq 'GPS' and $prev eq 'InteropIFD'`.
  ///
  /// Critically, that `%PROCESSED` block is GATED on `$$dirInfo{DirLen}`
  /// being non-zero (`($$dirInfo{DirLen} or not defined …)`,
  /// `ExifTool.pm:9052`, comment: "directories don't overlap if the length
  /// is zero"). For a STANDALONE TIFF — the file shape every exifast `TIFF`
  /// fixture uses, and the shape the golden oracle runs ExifTool against —
  /// an IFD-pointer SubDirectory (ExifIFD/GPS/InteropIFD via
  /// `Start => '$val'`) is built with `DirLen => $size`, and `$size` is
  /// forced to **0** at `Exif.pm:7020-7026`: the value-data buffer holds
  /// only the IFD currently being parsed, so the out-of-buffer subdirectory
  /// `$subdirStart` trips `$subdirStart + 2 > $subdirDataLen` and ExifTool
  /// resets `$subdirDataPt`/`$size` to re-read the directory from the file.
  /// With `DirLen 0` the `%PROCESSED` guard is SKIPPED entirely for every
  /// IFD-pointer subdirectory, so ExifTool reprocesses ANY shared
  /// subdirectory offset — emitting both groups, with NO warning. (The
  /// `%PROCESSED` GPS-after-InteropIFD carve-out at `ExifTool.pm:9059` is
  /// the `DirLen != 0` / embedded-EXIF behaviour; on a standalone TIFF the
  /// guard never reaches it because it is skipped — so the carve-out is
  /// just one instance of the general "reprocess the shared offset" rule.)
  /// Verified against bundled `perl exiftool`: a TIFF whose IFD0 ExifOffset
  /// and GPSInfo point at one shared IFD emits `ExifIFD:Orientation` AND
  /// `GPS:GPSVersionID` with no warning (`ProcessDirectory` trace: ExifIFD,
  /// InteropIFD & GPS all `DirLen=0`, `%PROCESSED` never set).
  ///
  /// Trailing IFDs are different: a trailing IFD carries its TRUE extent as
  /// `DirLen` (non-zero), so ExifTool's `%PROCESSED` guard DOES fire for
  /// them and `return 0` breaks a looping next-IFD chain. The port mirrors
  /// this split:
  ///
  /// * **Chain IFDs** (`Ifd0` / `Trailing`) — recorded in
  ///   [`chain_guard`](Self::chain_guard); a revisit aborts. This is the
  ///   trailing-chain loop breaker (`walk_ifd_chain`'s `loop {}` stays
  ///   finite). In [`ChainGuard::Owned`] mode the revisit is silent (the
  ///   common path); in [`ChainGuard::Shared`] mode it raises the
  ///   cross-source cycle-guard warning (the PNG multi-source path).
  /// * **IFD-pointer subdirectories** (`ExifIfd` / `Gps` / `Interop`) — NOT
  ///   recorded in `chain_guard`; a shared offset is reprocessed. The
  ///   only rejection is a genuine ancestor cycle: an offset already on the
  ///   ACTIVE recursion path ([`active_ifd_offsets`]) — e.g. an ExifIFD
  ///   whose 0x8769 tag points back at itself. ExifTool's standalone-TIFF
  ///   RAF re-read bounds such a cycle by failing to load the repeated
  ///   directory; the port reads the whole file into memory, so it needs
  ///   the explicit active-path check to stay finite.
  fn walk_one_ifd(&mut self, ifd_start: usize, kind: IfdKind) -> Option<usize> {
    let is_chain = matches!(kind, IfdKind::Ifd0 | IfdKind::Trailing(_));
    if is_chain {
      // Chain IFD: ExifTool records its non-zero-`DirLen` address in
      // `%PROCESSED` (`ExifTool.pm:9066-9071`); a revisit `return 0`s.
      // Break the looping chain.
      match &mut self.chain_guard {
        // COMMON path: a fresh per-block set; a revisit silently aborts (no
        // warning) — byte-identical to the pre-existing trailing-chain loop
        // breaker that every standalone TIFF / non-PNG format relies on.
        ChainGuard::Owned(set) => {
          if !set.insert(ifd_start) {
            return None;
          }
        }
        // PNG multi-source path: an EXTERNAL map shared across TIFF blocks
        // (ExifTool's object-level `$$et{PROCESSED}`). A revisit — within this
        // block OR from an earlier PNG EXIF source — warns
        // `"<DirName> pointer references previous <prev> directory"`
        // (`ExifTool.pm:9068`) and `return 0`s. `<prev>` is the recorded name
        // (`$$self{PROCESSED}{$addr}`), so a cross-source TRAILING-IFD hit
        // reports `IFD1`/`IFD2`/… — NOT necessarily `IFD0`. Keep the ORIGINAL
        // recorded name (do not overwrite): ExifTool sets `$$self{PROCESSED}
        // {$addr} = $dirName` only when not already present (the assignment is
        // skipped on the `return 0`).
        ChainGuard::Shared(processed) => {
          if let Some(prev) = processed.get(&ifd_start) {
            self
              .cycle_guard_warnings
              .push(smol_str::SmolStr::from(std::format!(
                "{} pointer references previous {} directory",
                kind.as_str(),
                prev
              )));
            return None;
          }
          processed.insert(ifd_start, kind.as_str());
        }
      }
    } else {
      // IFD-pointer subdirectory (ExifIFD/GPS/InteropIFD): ExifTool skips
      // the `%PROCESSED` guard (`DirLen 0`), so a shared offset reaching
      // here from a SIBLING / already-completed walk is reprocessed. Only
      // a true ancestor cycle — the offset is still on the active
      // recursion path — is rejected.
      if self.active_ifd_offsets.contains(&ifd_start) {
        return None;
      }
    }
    // Track the active recursion path so a nested subdirectory pointer
    // back to an ancestor IFD is caught above. Popped on every exit.
    self.active_ifd_offsets.push(ifd_start);
    let result = self.walk_one_ifd_body(ifd_start, kind);
    let popped = self.active_ifd_offsets.pop();
    debug_assert_eq!(popped, Some(ifd_start), "active-path stack imbalance");
    result
  }

  /// The body of [`walk_one_ifd`] — the structural walk of one IFD, AFTER
  /// the recursion / reprocess guard has admitted it. Faithful to the body
  /// of `ProcessExif` (`Exif.pm:6278-7240`).
  fn walk_one_ifd_body(&mut self, ifd_start: usize, kind: IfdKind) -> Option<usize> {
    let data = self.data;
    // `$warnCount` is a fresh `my` local per `ProcessExif` call (`Exif.pm:6453`):
    // each directory starts with a clean counter, so a sibling/earlier IFD's
    // warnings never carry into this one's abort cap. Reset here (the walker
    // reuses ONE `Walker` across the whole chain + every sub-IFD recursion, so
    // the field is shared state that must be re-zeroed per directory).
    self.warn_count = 0;
    // `$numEntries = Get16u($dataPt, $dirStart)` (Exif.pm:6344). The count
    // is readable only when `$dirStart <= $dataLen-2` (Exif.pm:6343); if
    // not, `$dirSize` is left undef and — with no RAF to read the IFD
    // from the file — `$success` stays 0, so ExifTool warns
    // `Bad $dir directory` (Exif.pm:6381) and aborts. For an IFD pointer
    // that lands past the end of the EXIF block the 2-byte count cannot
    // be read at all; emit the same warning + abort.
    //
    // All of the directory-extent arithmetic below is `checked_*`: on a
    // 32-bit / wasm target an attacker-controlled `ifd_start`/`num_entries`
    // near `u32::MAX` could overflow `usize` (debug panic / release wrap →
    // bounds checks would then run against a wrapped low address). An
    // overflow can never describe an in-range directory, so we treat it
    // exactly like an unreadable one: warn "Bad $dir directory" and abort
    // THIS directory BEFORE any slice access or entry walk — the same path
    // the count-past-EOF and IFD-overrun cases below take (Exif.pm:6381). On
    // 64-bit these checks never trip for an in-range value, so behavior is
    // unchanged there.
    if ifd_start.checked_add(2).is_none_or(|end| end > data.len()) {
      self.warn(std::format!("Bad {} directory", kind.as_str()));
      return None;
    }
    let num_entries = get_u16(data, ifd_start, self.order)? as usize;
    // `$dirSize = 2 + 12 * $numEntries; $dirEnd = $dirStart + $dirSize`,
    // each step checked (see the overflow note above) — overflow ⇒ the
    // Bad-directory abort.
    let Some(dir_end) = num_entries
      .checked_mul(12)
      .and_then(|body| body.checked_add(2))
      .and_then(|dir_size| ifd_start.checked_add(dir_size))
    else {
      self.warn(std::format!("Bad {} directory", kind.as_str()));
      return None;
    };
    // `$bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) { unless
    // ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn; return 0 } }`
    // (Exif.pm:6389-6395). If the IFD overruns the buffer entirely we
    // cannot read its entries — abort.
    if dir_end > data.len() {
      // The IFD's declared extent runs past the EXIF block. ExifTool's
      // "read what we can" salvage (`$numEntries = int(($dirSize-2)/12)`,
      // Exif.pm:6386-6388) is GATED to MakerNotes: `return 0 unless
      // $inMakerNotes and $dirLen >= 14 …` (Exif.pm:6381-6385). For a
      // normal IFD0/IFD1/ExifIFD/GPS/InteropIFD the count cannot be read
      // reliably (the file-seek fallback at Exif.pm:6362-6374 fails its
      // `Read` and yields `$success = 0`), so ExifTool warns
      // "Bad $dir directory" and aborts the WHOLE directory — no partial
      // tags. The exifast walker never recurses into a MakerNote IFD
      // (vendor parsing is deferred — see [`SubDirKind::MakerNote`]), so
      // every directory kind it handles takes the abort branch.
      // `$et->Warn("Bad $dir directory")` — Exif.pm:6381.
      self.warn(std::format!("Bad {} directory", kind.as_str()));
      return None;
    }

    // `my $bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) {
    // unless ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn("Illegal $dir
    // directory size ($numEntries entries)"); return 0 } }`
    // (Exif.pm:6394-6399). ExifTool reads the IFD body from the file via
    // RAF — the 2-byte count, then `Read($buf2, 12*n + 4)` capped at EOF
    // — so `$bytesFromEnd` is `min(file-bytes-after-$dirEnd, 4)`. The
    // legal residue is exactly the 4-byte next-IFD pointer (`>= 4` ⇒
    // clamped to 4), or a deliberately truncated tail of 2 or 0 bytes.
    // A residue of 1 or 3 bytes is a malformed directory: ExifTool warns
    // and aborts. `dir_end <= data.len()` is guaranteed by the branch
    // above, so the subtraction cannot underflow.
    let bytes_from_end = data.len() - dir_end;
    if bytes_from_end == 1 || bytes_from_end == 3 {
      self.warn(std::format!(
        "Illegal {} directory size ({num_entries} entries)",
        kind.as_str()
      ));
      return None;
    }

    // `walk_entries` returns `false` when entry 0 carried a bad format
    // code: ExifTool's `return 0` (Exif.pm:6477) exits `ProcessExif`
    // ENTIRELY — before the line-7202 trailing-IFD scan — so a corrupt
    // IFD0 must NOT leak its IFD1 thumbnail tags. Abort the whole chain.
    if !self.walk_entries(ifd_start, dir_end, num_entries, kind) {
      return None;
    }

    // `if ($$dirInfo{Multi} and $bytesFromEnd >= 4) { Get32u($dataPt,
    // $dirEnd) }` — the next-IFD pointer (`Exif.pm:7203-7204`/7212). The
    // `Multi` trailing-directory scan starts at IFD0 (`Multi => 1`,
    // `Exif.pm:6339`) and the `for (;;)` loop at `Exif.pm:7211-7232`
    // follows the chain through IFD1 → IFD2 → IFD3… reading a fresh
    // `Get32u($dataPt, $dirEnd)` at each hop. So the next-IFD pointer is
    // read for IFD0 AND every trailing IFD — but NOT for a sub-IFD
    // (ExifIFD/GPS/InteropIFD): those are reached by `ProcessDirectory`
    // WITHOUT `Multi`, so their trailing 4 bytes are not a next pointer.
    let follows_chain = matches!(kind, IfdKind::Ifd0 | IfdKind::Trailing(_));
    // `dir_end + 4` is `checked_add` for the 32-bit/wasm overflow class: a
    // `dir_end` within 4 of `usize::MAX` would wrap. (`dir_end <= data.len()`
    // here, so for a real buffer this never overflows — but the sweep keeps
    // every offset `+` on the IFD path checked.) Overflow ⇒ no next IFD,
    // matching the "trailing 4 bytes don't fit" branch.
    let next = if follows_chain && dir_end.checked_add(4).is_some_and(|end| end <= data.len()) {
      get_u32(data, dir_end, self.order).unwrap_or(0) as usize
    } else {
      0
    };
    Some(next)
  }

  // ==================================================================
  // BigTIFF IFD walk — ProcessBigIFD (BigTIFF.pm:26-228)
  // ==================================================================
  /// Walk a BigTIFF IFD0 → IFD1 → … chain — the faithful port of
  /// `ProcessBigIFD`'s `for (;;)` loop (`BigTIFF.pm:42-226`).
  ///
  /// Identical in shape to [`walk_ifd_chain`] but with BigTIFF widths: each IFD
  /// is an 8-byte entry count + N×20-byte entries + an 8-byte next-IFD pointer
  /// (`Get64u`, `BigTIFF.pm:216`). The chain re-visit guard
  /// ([`chain_guard`](Self::chain_guard)) breaks a looping next pointer
  /// (`$$et{PROCESSED}{$dirStart}`, `BigTIFF.pm:220-225`).
  fn walk_big_ifd_chain(&mut self, start: usize, first_kind: IfdKind) {
    let mut offset = start;
    let mut kind = first_kind;
    let mut trailing_num: u32 = 1;
    loop {
      let Some(next) = self.walk_big_one_ifd(offset, kind) else {
        return;
      };
      // `$dirStart or last` (`BigTIFF.pm:217`) — a 0 next pointer ends the
      // chain. `walk_big_one_ifd` returns `Some(0)` when the IFD had no (or a
      // zero) next pointer.
      if next == 0 {
        return;
      }
      kind = IfdKind::Trailing(trailing_num);
      trailing_num += 1;
      offset = next;
    }
  }

  /// Walk ONE BigTIFF IFD at `ifd_start`, applying the same chain / active-path
  /// reprocess guards as [`walk_one_ifd`] (they are shared [`Walker`] state),
  /// then delegating to [`walk_big_ifd_body`](Self::walk_big_ifd_body).
  /// Returns `Some(next_ifd_offset)` (0 ⇒ no next IFD) on success, `None` to
  /// abort the chain.
  fn walk_big_one_ifd(&mut self, ifd_start: usize, kind: IfdKind) -> Option<usize> {
    let is_chain = matches!(kind, IfdKind::Ifd0 | IfdKind::Trailing(_));
    if is_chain {
      // `if ($$et{PROCESSED}{$dirStart}) { Warn("… references previous …");
      // last }` (`BigTIFF.pm:220-225`) — a revisited chain address breaks the
      // loop. The common (Owned) path mirrors `walk_ifd_chain`'s silent
      // trailing-loop breaker.
      match &mut self.chain_guard {
        ChainGuard::Owned(set) => {
          if !set.insert(ifd_start) {
            return None;
          }
        }
        ChainGuard::Shared(processed) => {
          if let Some(prev) = processed.get(&ifd_start) {
            self
              .cycle_guard_warnings
              .push(smol_str::SmolStr::from(std::format!(
                "{} pointer references previous {} directory",
                kind.as_str(),
                prev
              )));
            return None;
          }
          processed.insert(ifd_start, kind.as_str());
        }
      }
    } else if self.active_ifd_offsets.contains(&ifd_start) {
      // A SubIFD (ExifIFD/GPS/InteropIFD) pointing back at an ancestor on the
      // active recursion path is a genuine cycle — reject (keeps the in-memory
      // walk finite, as in [`walk_one_ifd`]).
      return None;
    }
    self.active_ifd_offsets.push(ifd_start);
    let result = self.walk_big_ifd_body(ifd_start, kind);
    let popped = self.active_ifd_offsets.pop();
    debug_assert_eq!(popped, Some(ifd_start), "active-path stack imbalance");
    result
  }

  /// The body of [`walk_big_one_ifd`] — the structural walk of one BigTIFF IFD.
  /// Faithful to the per-directory work inside `ProcessBigIFD`'s loop
  /// (`BigTIFF.pm:47-217`): read the 8-byte count, the N×20-byte entry block
  /// and the 8-byte next-IFD pointer, then walk the entries. Returns the
  /// next-IFD offset (`Some(0)` ⇒ end of chain), or `None` to abort.
  fn walk_big_ifd_body(&mut self, ifd_start: usize, kind: IfdKind) -> Option<usize> {
    let data = self.data;
    let dir = kind.as_str();
    // `unless ($raf->Read($dirBuff, 8) == 8) { Warn("Truncated $dirName
    // count"); return 0 }` (`BigTIFF.pm:52-55`). The 8-byte count must be
    // readable; `checked_add` guards the 32-bit/wasm offset-overflow class
    // (an overflowing `ifd_start` describes no in-range directory → treat as
    // truncated). `ProcessBigIFD` first does `Seek($dirStart)` and on failure
    // warns `Bad $dirName offset` (`BigTIFF.pm:47-50`); for the whole-file
    // buffer here a start past EOF is exactly the unreadable-count case, so we
    // surface the single `Truncated $dirName count` warning.
    if ifd_start.checked_add(8).is_none_or(|end| end > data.len()) {
      self.warn(std::format!("Truncated {dir} count"));
      return None;
    }
    let num_entries = usize::try_from(get_u64(data, ifd_start, self.order)?).ok()?;
    // `my $bsize = $numEntries * 20; if ($bsize > $maxOffset) { Warn('Huge
    // directory counts not yet supported'); last }` (`BigTIFF.pm:58-62`).
    // `$maxOffset = 0x7fffffff`. `checked_mul` also covers the usize-overflow
    // class; either way an over-large count ends THIS directory (no entries,
    // no next pointer — `last`), so the chain stops here.
    let Some(bsize) = num_entries.checked_mul(20) else {
      self.warn(String::from("Huge directory counts not yet supported"));
      return Some(0);
    };
    if bsize > 0x7fff_ffff {
      self.warn(String::from("Huge directory counts not yet supported"));
      return Some(0);
    }
    // `my $bufPos = $raf->Tell()` is the file offset of the FIRST entry — the
    // 8 count bytes precede it. `unless ($raf->Read($dirBuff, $bsize) ==
    // $bsize) { Warn("Truncated $dirName directory"); return 0 }`
    // (`BigTIFF.pm:63-67`). `entries_start = ifd_start + 8`.
    let entries_start = ifd_start.checked_add(8)?;
    let Some(entries_end) = entries_start.checked_add(bsize) else {
      self.warn(std::format!("Truncated {dir} directory"));
      return None;
    };
    if entries_end > data.len() {
      self.warn(std::format!("Truncated {dir} directory"));
      return None;
    }
    // `$raf->Read($nextIFD, 8) == 8 or undef $nextIFD` (`BigTIFF.pm:69`) — the
    // next-IFD pointer is OPTIONAL (a truncated tail just yields no next IFD,
    // not an abort). It sits at `entries_end`.
    let next_ifd = entries_end
      .checked_add(8)
      .filter(|&end| end <= data.len())
      .and_then(|_| get_u64(data, entries_end, self.order))
      .and_then(|off| usize::try_from(off).ok());

    // Walk the entries. `walk_big_entry` returns a [`Step`]; `Reject`/`AbortDir`
    // (the `return 0` ExifTool takes on a bad format code) stops the whole
    // directory AND its chain — propagate `None` so the next pointer is NOT
    // followed (faithful to `ProcessBigIFD`'s `return 0` exiting before the
    // chain `last`).
    for index in 0..num_entries {
      // `my $entry = 20 * $index` (relative to `entries_start`).
      let Some(entry) = index
        .checked_mul(20)
        .and_then(|off| entries_start.checked_add(off))
      else {
        break;
      };
      // The 20-byte entry read is bounded by `entries_end <= data.len()`, but
      // keep it explicitly checked across the call boundary.
      if entry.checked_add(20).is_none_or(|end| end > data.len()) {
        break;
      }
      match self.walk_big_entry(entry, index, kind) {
        step if step.continues() => {}
        Step::AbortDir | Step::Reject => return None,
        Step::Keep | Step::Skip => {}
      }
    }

    // `last unless $dirName =~ /^(IFD|SubIFD)(\d*)$/` (`BigTIFF.pm:213`): only
    // the chain directories (IFD0 / trailing IFDn) follow a next pointer; a
    // SubIFD (ExifIFD/GPS/InteropIFD) does not. Plus `defined $nextIFD or
    // Warn("Bad $dirName pointer"), return 0` (`BigTIFF.pm:215`) — but `$dirName`
    // there is the INCREMENTED next name (e.g. `IFD1`), and the warning fires
    // only when a chain directory expected a next pointer it could not read.
    let follows_chain = matches!(kind, IfdKind::Ifd0 | IfdKind::Trailing(_));
    if !follows_chain {
      return Some(0);
    }
    match next_ifd {
      Some(off) => Some(off),
      // The next-pointer read came up short for a chain directory:
      // `Bad <next> pointer` then `return 0` (`BigTIFF.pm:215`). The name is
      // the NEXT directory's (`$dirName` after the `IFDn → IFDn+1` bump,
      // `BigTIFF.pm:214`).
      None => {
        let next_name = match kind {
          IfdKind::Ifd0 => IfdKind::Trailing(1),
          IfdKind::Trailing(n) => IfdKind::Trailing(n.saturating_add(1)),
          other => other,
        };
        self.warn(std::format!("Bad {} pointer", next_name.as_str()));
        None
      }
    }
  }

  /// Decode + emit ONE 20-byte BigTIFF IFD entry — the faithful port of
  /// `ProcessBigIFD`'s per-entry body (`BigTIFF.pm:81-211`).
  ///
  /// Entry layout (`BigTIFF.pm:83-85`/`:98`): `tag(2) format(2) count(8)
  /// value-or-offset(8)`. A value ≤ 8 bytes is inline at `$entry+12`; otherwise
  /// the 8 bytes there are an absolute file offset (`Get64u`, `BigTIFF.pm:105`)
  /// — and since the standalone BigTIFF block IS the whole file (`base == 0`),
  /// that offset indexes `data` directly.
  ///
  /// Returns a [`Step`]: [`Step::AbortDir`] for the bad-format `return 0`
  /// (`BigTIFF.pm:92`, abort the directory), [`Step::Skip`] for a per-entry
  /// `next` (unknown tag, huge size, unreadable value), [`Step::Keep`] for a
  /// processed entry (leaf emitted or SubIFD recursed).
  fn walk_big_entry(&mut self, entry: usize, index: usize, kind: IfdKind) -> Step {
    let data = self.data;
    let order = self.order;
    let dir = kind.as_str();
    // `Get16u($entry)` / `Get16u($entry+2)` / `Get64u($entry+4)` — the caller
    // proved `entry + 20 <= data.len()`, so these reads are in-range (the `?`
    // short-circuit is unreachable).
    let Some(tag_id) = get_u16(data, entry, order) else {
      return Step::Skip;
    };
    let Some(format_code) = get_u16(data, entry + 2, order) else {
      return Step::Skip;
    };
    let Some(count) = get_u64(data, entry + 4, order) else {
      return Step::Skip;
    };
    let count = match usize::try_from(count) {
      Ok(c) => c,
      // A 64-bit count that overflows `usize` cannot describe an in-range value
      // on this target; treat it like the huge-size `next` below.
      Err(_) => return Step::Skip,
    };

    // `my $formatSize = $formatSize[$format]; unless (defined $formatSize) {
    // … Warn("Unknown format ($format) for $dirName tag 0x%x"); return 0 }`
    // (`BigTIFF.pm:86-93`). `@formatSize` is defined for codes 1..=18 AND 129
    // (`Exif.pm:82-83`) — BigTIFF accepts the `int64u`/`int64s`/`ifd64`
    // additions (16/17/18) AND `unicode`/`complex` (14/15), unlike `ProcessExif`
    // (1..=13|129 only). An undefined size (code 0 = zero padding, or > 18) is a
    // corrupt IFD: warn (unconditionally — `ProcessBigIFD` does NOT silence the
    // zero-pad case the way `ProcessExif` does) and `return 0` (abort the dir).
    let format = Format::from_code(format_code);
    let elem_size = format.byte_size();
    if elem_size == 0 {
      self.warn(std::format!(
        "Unknown format ({format_code}) for {dir} tag 0x{tag_id:x}"
      ));
      return Step::AbortDir;
    }
    // `my $size = $count * $formatSize` (`BigTIFF.pm:95`).
    let size = count.saturating_mul(elem_size);

    // `next unless defined $tagInfo or $verbose` (`BigTIFF.pm:97`) — BigTIFF
    // SKIPS a tag absent from the table entirely (no Unknown-tag emit, no
    // large-array placeholder; `ProcessExif`'s 6760-6783 guards do NOT exist
    // here). Resolve known-ness against the IFD's own table (GPS vs Exif), the
    // same predicate [`emit`](Self::emit) uses to drop unknowns.
    //
    // EXCEPTION — `OldSubfileType` (0x00ff): it is absent from the port's leaf
    // table but IS in `%Exif::Main` (so ExifTool's `defined $tagInfo` is true and
    // it is NOT skipped), and it carries the `MultiPage` `RawConv` side-effect
    // (`Exif.pm:470`) that [`emit`](Self::emit) runs BEFORE dropping the unported
    // leaf — and `DoProcessTIFF` reads `MultiPage` to emit `File:PageCount` for a
    // BigTIFF (`ExifTool.pm:8667`). So let it past this leaf-known gate to reach
    // `emit`'s tap; the leaf itself is still dropped there. (`SubfileType` 0x00fe
    // is already a known leaf, so its tap already runs; `DNGVersion` 0xc612's DNG
    // override is unreachable for a BigTIFF — `ProcessBTF` finalizes `BTF` and
    // `return 1`s at `:8668`, before the `:8763` override — so it is not needed.)
    if !self.big_tag_known(kind, tag_id) && tag_id != tables::TAG_OLD_SUBFILE_TYPE {
      return Step::Skip;
    }

    // The value pointer + readable length. `if ($size > 8) { … $valuePtr =
    // Get64u($dirBuff, $valuePtr); … Seek+Read($valBuff,$size) … }` else `$valBuff
    // = substr($dirBuff, $valuePtr, $size)` (`BigTIFF.pm:98-118`). The inline
    // cutoff is 8 bytes (vs classic's 4); the value field is at `$entry+12`.
    let (value_offset, read_len) = if size > 8 {
      // `if ($size > $maxOffset) { Warn("Can't handle $dirName entry $index
      // (huge size)"); next }` (`BigTIFF.pm:101-104`). `$maxOffset = 0x7fffffff`.
      if size > 0x7fff_ffff {
        self.warn(std::format!("Can't handle {dir} entry {index} (huge size)"));
        return Step::Skip;
      }
      // `$valuePtr = Get64u($dirBuff, $entry+12)` — the 8-byte out-of-line
      // offset. (The classic `>= 8` header gate / suspicious-offset / IFD-overlap
      // checks of `ProcessExif` do NOT exist in `ProcessBigIFD`.)
      let off = match get_u64(data, entry + 12, order).and_then(|o| usize::try_from(o).ok()) {
        Some(o) => o,
        None => return Step::Skip,
      };
      // `unless ($raf->Seek($valuePtr,0) and $raf->Read($valBuff,$size) ==
      // $size) { Warn("Error reading $dirName entry $index"); next }`
      // (`BigTIFF.pm:110-113`). For the whole-file buffer, the read fails iff
      // `[off, off+size)` runs past EOF — a per-entry `next` (NOT a directory
      // abort, unlike `ProcessExif`'s RAF-read overrun). `checked_add` guards
      // the offset-overflow class.
      match off.checked_add(size) {
        Some(end) if end <= data.len() => (off, size),
        _ => {
          self.warn(std::format!("Error reading {dir} entry {index}"));
          return Step::Skip;
        }
      }
    } else {
      // Inline: `$valBuff = substr($dirBuff, $entry+12, $size)` — the value
      // occupies the first `$size` bytes at `$entry+12` (the caller proved
      // `entry + 20 <= len`, so `entry + 12 + size <= entry + 20 <= len`).
      let Some(value_offset) = entry.checked_add(12) else {
        return Step::Skip;
      };
      (value_offset, size)
    };

    // ---- SubIFD pointer tags (ExifOffset/GPSInfo/InteropOffset) ---------
    // `if ($tagInfo and $$tagInfo{SubIFD}) { … ProcessBigIFD on each offset }`
    // (`BigTIFF.pm:171-198`). ExifTool's `ProcessBigIFD` recurses a SubIFD as
    // BigTIFF REUSING the INHERITED `Exif::Main` table (`Table => $tagTablePtr`,
    // `:149`/`:172` — NOT switching to `GPS::Main` for a GPSInfo pointer) and
    // names the family-1 directory from the POINTER TAG (`ExifOffset`/`GPSInfo`/
    // `InteropOffset`, NOT `ExifIFD`/`GPS`/`InteropIFD`). Faithfully reproducing
    // that (the Exif-table-reuse + pointer-tag-group model) is DEFERRED to a
    // follow-up (it is crafted-only — the bundled `BigTIFF.btf` is a FLAT
    // single-IFD image with NO SubIFD pointers — and needs crafted ExifOffset/
    // GPSInfo fixtures). For now a BigTIFF SubIFD pointer is NOT recursed: the
    // pointer tag emits nothing (the SubDirectory bogus-parent rule), which
    // UNDER-emits a SubIFD-bearing BigTIFF rather than decoding it under the
    // WRONG table/group (R1 finding). (#168 follow-up: faithful BigTIFF SubIFDs.)
    if let Some(sub) = sub_dir_for(tag_id, kind)
      && sub.is_sub_ifd()
    {
      return Step::Keep; // deferred — emit nothing (no parent, no children)
    }

    // ---- Leaf tag — decode with the ON-DISK format + emit ---------------
    // `my $val = ReadValue(\$valBuff, 0, $formatStr, $count, $size, …)`
    // (`BigTIFF.pm:123`) — the on-disk format, NO tag-table `Format` override
    // (that is a `ProcessExif`-only step, `Exif.pm:6729`). `read_value`
    // shortens the count to the available window exactly as `ReadValue` does.
    // The single-`undef`-byte → int8u carve-out (`Exif.pm:6644`) lives in
    // `ReadValue`'s caller in `ProcessExif`, not `ProcessBigIFD`, so it is NOT
    // applied here.
    let Some(raw) = read_value(data, value_offset, format, count, read_len, order) else {
      return Step::Skip;
    };
    // `$et->HandleTag(...)` then `SetGroup($tagKey, $dirName)` (`BigTIFF.pm:
    // 200-210`). `emit` is the shared HandleTag/SetGroup path: it sets the
    // family-1 group from `kind`, applies the `IsOffset` base add, runs the
    // SubfileType/OldSubfileType/DNGVersion RawConv taps, and pushes the leaf —
    // itself dropping a tag absent from the table. Most unknowns are filtered by
    // the gate above; `OldSubfileType` (0x00ff) is admitted there expressly so
    // its MultiPage tap runs HERE, and emit then drops its unported leaf.
    // BigTIFF applies no tag-table `Format` override (`BigTIFF.pm` reads the
    // on-disk `$formatStr` directly), so the emitted on-disk format IS `format`.
    // `value_offset`/`read_len` are the resolved value pointer + on-disk byte
    // size — carried on the entry for the vendor span re-slice (inert for the
    // core BigTIFF walk, which has no vendor sub-tables).
    self.emit(kind, tag_id, format, value_offset, read_len, raw);
    Step::Keep
  }

  /// `defined $tagInfo` for a BigTIFF entry (`BigTIFF.pm:96-97`) — `true` when
  /// the tag id resolves in the IFD's own table (GPS vs Exif/Interop). The
  /// SubIFD pointer tags (ExifIFD/GPS/InteropIFD/MakerNote) are handled
  /// structurally and are NOT in the leaf-lookup tables, so they are admitted
  /// here explicitly (ExifTool has tagInfo for them, so it does not `next`).
  fn big_tag_known(&self, kind: IfdKind, tag_id: u16) -> bool {
    if sub_dir_for(tag_id, kind).is_some() {
      return true;
    }
    if kind.is_gps() {
      #[cfg(feature = "gps")]
      {
        return gps::lookup(tag_id).is_some();
      }
      #[cfg(not(feature = "gps"))]
      {
        return false;
      }
    }
    tables::lookup(tag_id).is_some()
  }

  /// Walk `num_entries` IFD entries starting at `ifd_start`. Each entry is
  /// 12 bytes at `$dirStart + 2 + 12*$index` (`Exif.pm:6452`). `dir_end` is
  /// the IFD's end offset (`$dirStart + $dirSize`) — the out-of-line value
  /// bounds checks need it to detect a value that overlaps the directory.
  ///
  /// The loop driver — the single Contract-1 recovery boundary that interprets
  /// the [`Step`] each `walk_entry` returns. A continuing step
  /// ([`Step::continues`], i.e. `Keep`/`Skip`) advances the entry loop, whereas
  /// an `AbortDir` ([`Step::AbortDir`]) stops it.
  ///
  /// Returns `false` to ABORT the whole directory (and its trailing-IFD
  /// chain) — the faithful `return 0` ExifTool takes either when entry 0
  /// carries a bad format code (`Exif.pm:6475-6477`) OR when an out-of-line
  /// value's RAF read overruns EOF (`Error reading value …`, `return 0
  /// unless $inMakerNotes or $htmlDump or $truncOK`, `Exif.pm:6602`). Both
  /// `return 0`s leave `ProcessExif` before the line-7202 next-IFD scan, so
  /// the caller must NOT read the next-IFD pointer when this is `false`.
  /// `true` otherwise.
  fn walk_entries(
    &mut self,
    ifd_start: usize,
    dir_end: usize,
    num_entries: usize,
    kind: IfdKind,
  ) -> bool {
    for index in 0..num_entries {
      // `if ($warnCount > 10) { Warn("Too many warnings -- $dir parsing
      // aborted", 2) and return 0 }` (Exif.pm:6455-6456) — checked at the TOP
      // of the loop body, BEFORE this entry is read. Once more than ten
      // per-entry validation warnings (`warn_counted`) have accumulated in THIS
      // directory, ExifTool abandons the rest of it: it emits one `[Minor]` (the
      // hard-coded `2` ignorable, NOT `$inMakerNotes`-derived) abort warning and
      // `return 0`s — so neither the remaining entries NOR the trailing next-IFD
      // pointer is processed. `Warn(..., 2)` returns true in normal mode (the
      // `and return 0` always fires), so this is an unconditional directory
      // abort. Returns `false` (the `Step::AbortDir` analogue) — the caller
      // (`walk_one_ifd_body`) then does NOT read the next-IFD pointer, matching
      // the Perl `return 0` exiting `ProcessExif` before the line-7202 `Multi`
      // scan. `$dir` is `kind.as_str()` for every IFD this walker reaches.
      if self.warn_count > 10 {
        self.warn_minor_behavioral(std::format!(
          "Too many warnings -- {} parsing aborted",
          kind.as_str()
        ));
        return false;
      }
      // `$entry = $dirStart + 2 + 12*$index` (Exif.pm:6452), `checked_*` for
      // the 32-bit/wasm overflow class. The caller's checked `dir_end =
      // ifd_start + 2 + 12*num_entries` already guarantees every `entry`
      // (index < num_entries) is `< dir_end <= data.len()` and so cannot
      // overflow — but keep the arithmetic explicitly checked so its
      // overflow-safety does not silently depend on that invariant. An
      // overflow stops the entry loop (treated as past-EOF, like the
      // 12-byte-entry-read guard below).
      let Some(entry) = index
        .checked_mul(12)
        .and_then(|off| off.checked_add(2))
        .and_then(|off| ifd_start.checked_add(off))
      else {
        break;
      };
      // Defend the 12-byte entry read (the caller bounded `num_entries`).
      if entry
        .checked_add(12)
        .is_none_or(|end| end > self.data.len())
      {
        break;
      }
      // `walk_entries` is the loop driver — the single recovery boundary that
      // interprets the [`Step`] `walk_entry` returns (golden pattern Contract
      // 1). `Keep`/`Skip` advance the entry loop (a normal entry, or a Perl
      // `next` single-entry skip); `AbortDir` stops the WHOLE directory — the
      // faithful `return 0` ExifTool takes when entry 0 has a bad format code
      // (`Exif.pm:6475`) or an out-of-line value's RAF read overruns EOF
      // (`Exif.pm:6602`) — which propagates to the caller (`return false`) so
      // the next-IFD pointer is NOT followed. `Reject` (a detect/file-level
      // `return 0`) is not produced inside the IFD entry loop; it stops the
      // directory identically here. This reproduces the prior `bool` control
      // flow exactly: old `true` == `Step::continues()`, old `false` ==
      // `Step::AbortDir`.
      match self.walk_entry(entry, index, ifd_start, dir_end, kind) {
        step if step.continues() => {}
        Step::AbortDir | Step::Reject => return false,
        // `continues()` already covered `Keep`/`Skip`; this arm is unreachable
        // but keeps the match exhaustive without a wildcard that could mask a
        // future variant.
        Step::Keep | Step::Skip => {}
      }
    }
    true
  }

  /// Resolve a tag NAME against `table` — the table the active (sub-)directory
  /// walks under. GPS and Interop/Exif tag IDs OVERLAP (e.g. 0x0002 is
  /// `GPSLatitude` in `%GPS::Main` but `InteropVersion`/`GPSLatitude` shape in
  /// `%Exif::Main`); ExifTool resolves `$$tagInfo{Name}` against the
  /// directory's OWN `$tagTablePtr` (`Exif.pm:6464`/6674), so the GPS IFD must
  /// look up `%GPS::Main`. `TableRef::Interop` reuses `%Exif::Main` for the
  /// lookup (the Interop IFD has no table of its own — `Exif.pm:6939`). The
  /// vendor arms are unreachable in Phase 1 (no maker note routes through this
  /// walker yet); they map to `%Exif::Main` as a faithful placeholder until
  /// Phase 2 wires their tables in. Returns `Some(name)` for a known tag,
  /// `None` for an unknown one (caller emits the `tag 0x%.4x` form).
  fn lookup_name_in(table: TableRef, tag_id: u16) -> Option<&'static str> {
    match table {
      TableRef::Gps => {
        #[cfg(feature = "gps")]
        {
          gps::lookup(tag_id).map(|t| t.name)
        }
        // `gps` feature OFF ⇒ the GPS module is "not loaded": ExifTool's
        // `GetTagInfo` yields nothing, so the warning uses the unknown-tag
        // form. Faithful to the module-not-loaded path (`docs/tracking.md`).
        #[cfg(not(feature = "gps"))]
        {
          let _ = tag_id;
          None
        }
      }
      // `%Canon::Main` — Step A of the Canon engine migration (#243 phase 2). An
      // unknown Canon tag yields `None` (the unknown-tag warning form), matching
      // `parse_in_tiff`'s `tags::lookup(...).is_none()` skip.
      TableRef::Canon => makernotes::vendors::canon::tags::lookup(tag_id).map(|t| t.name()),
      // `%Apple::Main` — phase 3 of the engine migration (#243). An unknown Apple
      // tag yields `None` (the unknown-tag warning form), matching
      // `parse_with_print_conv`'s `tags::lookup(...).is_none()` skip.
      TableRef::Apple => makernotes::vendors::apple::tags::lookup(tag_id).map(|t| t.name()),
      // `%Sony::Main` — phase 3 of the engine migration (#243). An unknown Sony
      // tag yields `None` (the unknown-tag warning form), matching
      // `parse_in_tiff`'s `tags::lookup(...).is_none()` skip.
      TableRef::Sony => makernotes::vendors::sony::tags::lookup(tag_id).map(|t| t.name()),
      // `%Panasonic::Main` — phase 3 of the engine migration (#243). An unknown
      // Panasonic tag yields `None` (the unknown-tag warning form), matching
      // `parse_in_tiff`'s `tags::lookup(...).is_none()` skip.
      TableRef::Panasonic => makernotes::vendors::panasonic::tags::lookup(tag_id).map(|t| t.name()),
      // `%Nikon::Main` / `%Nikon::Type2` — phase 3-bis of the engine migration
      // (#243). The two tables REUSE tag IDs 0x0003..0x000b for DIFFERENT tags, so
      // the name resolves against the ACTIVE table's own slice (`NikonTable::Main`
      // vs `NikonTable::Type2`). An unknown Nikon tag yields `None` (the
      // unknown-tag warning form), matching `parse_in_tiff`'s
      // `layout.table.lookup(...).is_none()` skip (`nikon/mod.rs:364`).
      TableRef::Nikon => makernotes::vendors::nikon::NikonTable::Main
        .lookup(tag_id)
        .map(|t| t.name()),
      TableRef::NikonType2 => makernotes::vendors::nikon::NikonTable::Type2
        .lookup(tag_id)
        .map(|t| t.name()),
      _ => tables::lookup(tag_id).map(|t| t.name),
    }
  }

  /// Decode + emit ONE 12-byte IFD entry (`Exif.pm:6453-7194`).
  ///
  /// Entry layout (`Exif.pm:6453-6456`):
  /// ```text
  /// tag    = Get16u($dataPt, $entry)       # tag ID
  /// format = Get16u($dataPt, $entry+2)     # format code
  /// count  = Get32u($dataPt, $entry+4)     # element count
  /// value/offset at $entry+8 (4 bytes)
  /// ```
  ///
  /// `index` is the 0-based entry position (used in the `Error reading
  /// value …` warning) and `ifd_start` / `dir_end` bound the IFD (used by
  /// the out-of-line value checks — see the `$size > 4` branch).
  ///
  /// Returns a [`Step`] (golden pattern Contract 1) naming what bundled
  /// ExifTool does at the point this entry reached, which the loop driver
  /// ([`walk_entries`](Self::walk_entries)) interprets:
  ///
  /// * [`Step::AbortDir`] — the faithful mid-walk `return 0` ExifTool takes
  ///   when entry 0 carries a bad format code (`Exif.pm:6475`) OR when an
  ///   out-of-line value's RAF read overruns EOF (`Error reading value …`,
  ///   `Exif.pm:6602`): stop the WHOLE directory.
  /// * [`Step::Skip`] — a Perl `next`: drop THIS entry and continue the IFD
  ///   (a `Suspicious offset` / `Wrong format` / oversized / excessive-count /
  ///   undecodable value, or an unreadable entry header).
  /// * [`Step::Keep`] — a normal entry processed (leaf emitted, or a
  ///   SubDirectory dispatched).
  ///
  /// (This walker never yields [`Step::Reject`] — that is the detect/file-level
  /// `return 0`, raised by format detection, not inside the IFD entry loop.)
  /// The mapping reproduces the prior `bool` return exactly: old `false` ==
  /// [`Step::AbortDir`], old `true` == a [`Step::continues`] variant
  /// ([`Step::Keep`]/[`Step::Skip`]).
  fn walk_entry(
    &mut self,
    entry: usize,
    index: usize,
    ifd_start: usize,
    dir_end: usize,
    kind: IfdKind,
  ) -> Step {
    let data = self.data;
    let order = self.order;
    // `my $tagID = Get16u($dataPt, $entry)` etc. An unreadable entry header
    // (the caller's bounds guard already proved `entry+12 <= len`, so this is
    // unreachable for an in-range entry) is a `next`-skip: [`Step::Skip`].
    let Some(tag_id) = get_u16(data, entry, order) else {
      return Step::Skip;
    };
    let Some(format_code) = get_u16(data, entry + 2, order) else {
      return Step::Skip;
    };
    let Some(count) = get_u32(data, entry + 4, order) else {
      return Step::Skip;
    };
    let count = count as usize;

    let format = Format::from_code(format_code);
    // `if (($format < 1 or $format > 13) and $format != 129 ...) { ... }`
    // (Exif.pm:6464-6477). An unrecognized format code is BAD: the
    // BigTIFF codes 16-18 ARE recognized by `Format`, but the standard
    // TIFF IFD entry only legitimately uses 1-13 + 129; a 16-18 in a
    // non-BigTIFF IFD is treated as bad (the standalone-TIFF fixtures
    // never use BigTIFF). ExifTool, with no `MAP_FORMAT` override:
    //   - warns `Bad format ($format) for $dir entry $index` and bumps
    //     `$warnCount` — but ONLY when `$format` is truthy (a 0 code is
    //     just zero-padding of the IFD, so it warns silently);
    //   - then `next if $index` — skip this one entry — ELSE (`$index ==
    //     0`) `return 0`, aborting the WHOLE directory ("assume corrupted
    //     IFD if this is our first entry"). The Sony-ILCE carve-out
    //     (`$$et{Model} =~ /^ILCE/`) is NOT modelled: exifast does not
    //     track `Model` during the IFD walk, and an ILCE camera with an
    //     empty first entry is a narrow Sony-specific case outside the
    //     standalone-TIFF camera-metadata scope (`docs/tracking.md`).
    // ExifTool ADMITS the BigTIFF `int64u` code 16 in a standard IFD entry ONLY
    // for Apple maker notes: `not ($format == 16 and $$et{Make} eq 'Apple' and
    // $inMakerNotes)` (`Exif.pm:6464`). `active_table == Apple` is the
    // `$inMakerNotes` (Apple MakerNote walk) context, and the `$$et{Make} eq
    // 'Apple'` condition is the parent IFD0 `Make`: Apple MakerNote dispatch is
    // SIGNATURE-based (an `"Apple iOS\0"` blob routes to `Vendor::Apple`
    // REGARDLESS of the container Make), so a crafted file with such a blob but
    // IFD0 Make != `"Apple"` reaches this gate; ExifTool then classifies code 16
    // as a BAD format (entry-0 abort / later-entry skip). The carve-out therefore
    // ALSO requires `captured_make == Some("Apple")`, threaded from IFD0. An Apple
    // ProRAW DNG (Make == "Apple") entry whose on-disk format is 16 (int64u,
    // byte_size 8) is recognized and decoded — never the `Bad format`
    // entry-0-abort that would lose the whole Apple walk. Every other table
    // (Exif/Gps/Interop/Canon) keeps rejecting 16. (#243 phase 3 Apple R1/R4.)
    let recognized = Format::is_valid_ifd_code(format_code)
      || (format_code == 16
        && self.active_table == TableRef::Apple
        && self.captured_make.as_deref() == Some("Apple"));
    if !recognized {
      // `if ($format or $validate) { Warn(...); ++$warnCount }` — a 0
      // code is silent padding; any other bad code warns AND counts toward the
      // `$warnCount` abort cap (`Exif.pm:6471-6472`).
      if format_code != 0 {
        let dir = kind.as_str();
        self.warn_counted(std::format!(
          "Bad format ({format_code}) for {dir} entry {index}"
        ));
      }
      // `next if $index` — skip this entry; ELSE (`$index == 0`) `return 0`
      // (abort the directory). The single `.pm` site is BOTH control words:
      // `next` (`Exif.pm:6476`) for entry index ≠ 0 ⇒ [`Step::Skip`], and the
      // first-entry `return 0` (`Exif.pm:6475`/6477) ⇒ [`Step::AbortDir`].
      // (The prior `bool` `index != 0` encoded exactly this: `true`==skip,
      // `false`==abort — now the two control words are named.)
      return if index != 0 {
        Step::Skip
      } else {
        Step::AbortDir
      };
    }

    // `my $size = $count * $formatSize[$format]` (Exif.pm:6502).
    let elem_size = format.byte_size();
    let size = count.saturating_mul(elem_size);

    // The value pointer. `$valuePtr = $entry + 8` for an inline value
    // (≤ 4 bytes); for `$size > 4` the 4 bytes at `$entry+8` are an OFFSET
    // into the TIFF block (Exif.pm:6504-6510).
    let (value_offset, read_len) = if size > 4 {
      // `if ($size > 0x7fffffff and (not $tagInfo or not $$tagInfo{ReadFromRAF}))
      // { Warn('Invalid size ...'); ++$warnCount; next }` (Exif.pm:6505-6509)
      // — the FIRST test inside the `$size > 4` block, BEFORE the offset is
      // even read. A `count` so large that `count * formatSize` exceeds the
      // signed-32-bit ceiling is rejected as the per-entry `next` (a SKIP, not
      // the directory-abort `return false`): bumping `$warnCount` and
      // continuing the entry loop. `$$tagInfo{ReadFromRAF}` is not carried by
      // any camera leaf tag this walker reaches (3 non-camera tags in
      // `Exif.pm`, none in `GPS.pm`), so the guard reduces to `size >
      // 0x7fffffff`. Without this an oversized count falls through to the
      // EOF/`Error reading value` abort below (`return false`), which would
      // kill the rest of the IFD — including the IFD1 thumbnail chain — even
      // though Perl merely skips the one bad entry. The tag name uses
      // `TagName` (`Exif.pm:6252`): `tag 0x%.4x` plus ` Name` for a known tag.
      if size > 0x7fff_ffff {
        let dir = kind.as_str();
        let tag = match Self::lookup_name_in(self.active_table, tag_id) {
          Some(name) => std::format!("tag 0x{tag_id:04x} {name}"),
          None => std::format!("tag 0x{tag_id:04x}"),
        };
        // `++$warnCount` (Exif.pm:6507) — counts toward the abort cap.
        self.warn_counted(std::format!("Invalid size ({size}) for {dir} {tag}"));
        return Step::Skip; // `next` — skip this entry, continue the IFD.
      }
      let raw_off = match get_u32(data, entry + 8, order) {
        Some(o) => o as usize,
        // Unreadable offset bytes (unreachable given the caller's `entry+12`
        // bounds guard) — a `next`-skip.
        None => return Step::Skip,
      };
      // `$valuePtr -= $dataPos` (`Exif.pm:6546`). For a core IFD / inherit-base
      // maker note `$dataPos == 0` (the whole block IS the EXIF data) and
      // `value_offset_base == 0`, so the pointer is `raw_off` unchanged. For a
      // relative-base maker note (`MakerNotePanasonic3` `Base => 12`) the
      // SubDirectory shifted `$dataPos` by `$base - $subdirBase` (`Exif.pm:7040`),
      // which in the port's buffer coordinates ADDS the `Base` literal — so the
      // resolved pointer is `raw_off + value_offset_base` (`= raw_off + 12`),
      // reproducing `walk_panasonic_in_tiff`'s `abs_off` (`panasonic/body.rs:150`).
      // The shift is applied HERE, BEFORE every bounds check, exactly as ExifTool
      // resolves `$valuePtr` before the `:6549` EOF / `:6675` suspect tests. A
      // `saturating_add` keeps a degenerate `raw_off`/base near `usize::MAX` from
      // wrapping the checks below (it lands past EOF ⇒ the read/bad-offset arm,
      // never a low-address false pass).
      let off = raw_off.saturating_add(self.value_offset_base);
      // An out-of-line value pointer is subject to two ExifTool bounds checks, in
      // this precedence:
      //
      //   1. `$valuePtr < 0 or $valuePtr + $size > $dataLen` ⇒ ExifTool
      //      reads the value from the file via `$raf` (Exif.pm:6549-6611).
      //      A standalone TIFF processed from a file ALWAYS carries a RAF —
      //      `DoProcessTIFF` builds the IFD dirInfo with `RAF => $raf`
      //      (ExifTool.pm:8717), and `ProcessExif` reads it as
      //      `$raf = $$dirInfo{RAF}` (Exif.pm:6289) — so the `if ($raf)`
      //      branch (Exif.pm:6552) is taken, NOT the no-RAF `else`. When the
      //      out-of-line value extends past EOF the `$raf->Read($buff,$size)
      //      != $size` (Exif.pm:6593) fails: ExifTool warns "Error reading
      //      value for $dir entry $index, ID 0x.... $Name" (Exif.pm:6594)
      //      and then `return 0 unless $inMakerNotes or $htmlDump or
      //      $truncOK` (Exif.pm:6602) — it ABORTS the WHOLE directory.
      //      `walk_entry` returns `false` to propagate that abort: the
      //      caller (`walk_entries`) stops the entry loop and
      //      `walk_one_ifd_body` does NOT read the trailing next-IFD pointer
      //      (the `return 0` exits `ProcessExif` before the line-7202
      //      `Multi` chain scan), so a crafted TIFF with a valid LATER entry
      //      and/or a next-IFD pointer after the overrun surfaces NO tags
      //      the oracle suppresses.
      //
      //      The `$inMakerNotes`/`$htmlDump`/`$truncOK` EXCEPTION (where
      //      ExifTool warns then CONTINUES the loop with `$bad = 1`) does
      //      NOT apply to any directory this walker reaches: the Exif walker
      //      DEFERS MakerNote (0x927c) parsing — it captures the raw blob
      //      and never recurses into a MakerNote IFD ([`SubDirKind::
      //      MakerNote`]), so `$inMakerNotes` is never true; no Exif/GPS
      //      table tag this port emits carries `TruncateOK` (that flag lives
      //      on vendor MakerNote / preview tags); and `htmlDump` is a
      //      verbose-only mode not modelled here. Every `IfdKind` admitted
      //      to this code — Ifd0/Trailing/ExifIfd/Gps/Interop — is thus a
      //      non-MakerNotes standalone-TIFF directory that takes the abort.
      //   2. else, `$valuePtr < 8` (offset into the 8-byte TIFF header —
      //      "offset shouldn't point into TIFF header", Exif.pm:6539) OR
      //      `$valuePtr < $dirEnd and $valuePtr+$size > $dirStart` (the
      //      value overlaps the IFD, Exif.pm:6549) ⇒ `$suspect` ⇒
      //      "Suspicious $dir offset for $Name" (Exif.pm:6675) and the tag
      //      is skipped (`next unless $verbose`) — a CONTINUE, not an abort.
      //
      // The EOF check is first because in ExifTool the read happens
      // (Exif.pm:6549-6611) BEFORE the trailing `$suspect == $warnCount`
      // test (Exif.pm:6672); for an overrun-AND-suspect value the read's
      // `return 0` fires first, so the suspect `next` is never reached.
      let dir = kind.as_str();
      // `$valuePtr + $size` (Exif.pm:6531) — `checked_add` so an out-of-line
      // `off`/`size` near `usize::MAX` on a 32-bit target cannot wrap the
      // EOF test (and so the wrapped sum cannot pass a low-address bounds
      // check). The validated end is reused for the IFD-overlap test below.
      let value_end = match off.checked_add(size) {
        Some(end) if end <= data.len() => end,
        // Two cases take the no-RAF `else` branch (`Exif.pm:6616-6670`) —
        // `Bad offset for $dir $tagStr` (`Exif.pm:6660`) + `$bad = 1` (the
        // value is dropped) + CONTINUE the loop. `$tagStr` is the name-if-known
        // form (`Exif.pm:6634`), NOT the RAF path's `ID 0x…` text. Takes
        // precedence over the suspect test below (the read happens first,
        // `Exif.pm:6660` before `:6672`).
        //   1. `self.no_raf` — the Canon CTMD `0x8769` ExifIFD hop (a buffer
        //      with no backing RAF), where ExifTool likewise has no `$raf`.
        //   2. `!active_table.is_core_ifd()` — a VENDOR maker-note walk
        //      (`%Canon::Main` via `process_subdir(.., TableRef::Canon, ..)`,
        //      #243 phase 2 step C). A maker-note directory IS `$inMakerNotes`,
        //      so even on the RAF-backed production path (`no_raf == false`)
        //      the abort below does NOT fire: `Exif.pm:6602` is
        //      `return 0 unless $inMakerNotes …`, i.e. inMakerNotes CONTINUES
        //      with `$bad = 1` rather than aborting. Routing this case to the
        //      same `Bad offset` + `warn_counted` + `Skip` path matches the
        //      retired `canon::body::classify_canon_entry`
        //      (`CanonEntryClass::BadOffset` → "Bad offset" warning + CONTINUE)
        //      so ONE malformed Canon entry no longer suppresses every later
        //      valid Canon tag. Core walks (Exif/GPS/Interop) keep aborting
        //      (`is_core_ifd()` is `true`, none are inMakerNotes) — see the RAF
        //      arm's precedence note for why their exception never applies.
        _ if self.no_raf || !self.active_table.is_core_ifd() => {
          let warning = match Self::lookup_name_in(self.active_table, tag_id) {
            Some(name) => std::format!("Bad offset for {dir} {name}"),
            None => std::format!("Bad offset for {dir} tag 0x{tag_id:04x}"),
          };
          // `++$warnCount` (Exif.pm:6661) — counts toward the abort cap.
          self.warn_counted(warning);
          return Step::Skip;
        }
        _ => {
          // RAF-backed (the standalone-TIFF / JPEG-`APP1` / QuickTime / PNG
          // path): the out-of-line value is past the readable buffer, so the
          // `$raf->Read` short-reads ⇒ `Error reading value` — the tag name is
          // appended only for a known, non-Unknown tag (Exif.pm:6596-6598).
          // The name is resolved against the IFD's OWN table (GPS vs
          // Exif/Interop — see `warn_tag_name`); a GPS IFD's 0x0002 is
          // `GPSLatitude`, not the Interop table's `InteropVersion`.
          let tag = match Self::lookup_name_in(self.active_table, tag_id) {
            Some(name) => std::format!(" {name}"),
            None => String::new(),
          };
          self.warn(std::format!(
            "Error reading value for {dir} entry {index}, ID 0x{tag_id:04x}{tag}"
          ));
          // `return 0 unless $inMakerNotes or $htmlDump or $truncOK`
          // (Exif.pm:6602) — abort the directory (see the precedence note
          // above for why the exception never applies to a RAF-backed walk).
          // [`Step::AbortDir`] = this mid-walk `return 0`.
          return Step::AbortDir;
        }
      };
      // `$valuePtr < $dirEnd and $valuePtr+$size > $dirStart` (Exif.pm:6549):
      // `value_end` is the already-validated, non-overflowing `off + size`.
      let overlaps_ifd = off < dir_end && value_end > ifd_start;
      if off < 8 || overlaps_ifd {
        // `$tagStr = $tagInfo ? $$tagInfo{Name} : sprintf('tag 0x%.4x', …)`
        // (Exif.pm:6674). The name is resolved against the IFD's own table
        // (`warn_tag_name`) — GPS IDs overlap the Interop table.
        let warning = match Self::lookup_name_in(self.active_table, tag_id) {
          Some(name) => std::format!("Suspicious {dir} offset for {name}"),
          None => std::format!("Suspicious {dir} offset for tag 0x{tag_id:04x}"),
        };
        // `if ($et->Warn(...)) { ++$warnCount; next unless $verbose }`
        // (Exif.pm:6675-6677) — `Warn` returns true in normal mode, so the
        // suspicious-offset warning counts toward the abort cap.
        self.warn_counted(warning);
        // `next unless $verbose` (Exif.pm:6675) — skip this entry, CONTINUE
        // the IFD: [`Step::Skip`].
        return Step::Skip;
      }
      (off, size)
    } else {
      // Inline: the value occupies the first `$size` bytes at `$entry+8`
      // (`$size <= 4`). The caller (`walk_entries`) already proved
      // `entry + 12 <= data.len()` with `checked_add`, so `entry + 8` cannot
      // overflow; `checked_add` keeps that explicit across the call boundary.
      // An overflow (impossible given the caller's guard) skips the entry
      // ([`Step::Skip`]).
      let Some(value_offset) = entry.checked_add(8) else {
        return Step::Skip;
      };
      (value_offset, size)
    };

    // ---- SubDirectory pointer tags (the IFD-chain seam) -----------------
    // Only IFD0 carries ExifIFD/GPS pointers; only ExifIFD carries Interop
    // + MakerNote (faithful: ExifTool resolves these by tag table + DirName,
    // Exif.pm:2006/2130/2496/2720).
    //
    // These pointer IDs (0x8769/0x8825/0xa005/0x927c) are SubDirectory entries
    // ONLY in the CORE `%Exif::Main` table. The shared `Walker` reaches this
    // body with the same `kind` (`IfdKind::ExifIfd`) for a vendor maker-note
    // walk (`%Canon::Main` is dispatched as `process_subdir(.., ExifIfd,
    // TableRef::Canon, ..)`, #243 phase 2 step C), where those IDs are ordinary
    // VENDOR leaves — e.g. `%Canon::Main` has no 0xa005, so `Canon.pm` (via
    // `tags::lookup`) treats 0xa005 as an unknown Canon tag, NEVER as the
    // Interop sub-IFD. Gating on `active_table.is_core_ifd()` keeps the core
    // IFD-chain seam byte-identical (it is `true` for Exif/GPS/Interop) while
    // routing a vendor table's pointer-ID-colliding tag PAST this block to the
    // vendor leaf / sub-table emit (`ResolvedConv::Canon`) or the unknown-skip
    // — exactly as the retired `canon::parse_in_tiff` did. Without the gate a
    // crafted Canon 0xa005/0x8769/0x927c would recurse into a CORE sub-IFD that
    // pushes `ResolvedConv::Exif` entries; those scalar entries then hit the
    // `VendorEmissionSink` capture path, whose core `write_*` writers are not a
    // Canon emission — a byte-identity break (and, before the sink was made
    // non-panicking below, a malformed-input DoS).
    if self.active_table.is_core_ifd()
      && let Some(sub) = sub_dir_for(tag_id, kind)
    {
      // `if (($$tagInfo{IsOffset} or $$tagInfo{SubIFD}) and not
      // $intFormat{$formatStr}) { Warn('Wrong format ...'); ... next unless
      // $verbose }` (Exif.pm:6747-6754). A SubIFD/offset pointer encoded with
      // a NON-integer on-disk format (e.g. a `GPSInfo` 0x8825 mis-written as
      // `string[4]`) is REJECTED before the subdir is followed: ExifTool
      // warns and, in default (non-verbose) mode, `next`-skips the entry — the
      // sub-IFD is NOT walked. Without this the port would decode the pointer
      // as text and silently drop it, making a corrupt GPS pointer
      // indistinguishable from no-GPS. The integer test is `%intFormat`
      // (`Format::is_int`, Exif.pm:124-135); `MakerNote` (0x927c) has neither
      // `IsOffset` nor `SubIFD`, so `is_sub_ifd()` is false and a string-typed
      // MakerNote is parsed as usual. The warning uses `$$tagInfo{Name}` via
      // `SubDirKind::tag_name` (these pointer tags are NOT in the leaf-lookup
      // `tables`) and the on-disk `$formatStr`; for these SubIFD tags no
      // `Format` override applies (Exif.pm:6733 gates the `undef` default on
      // `not SubIFD`), so the on-disk format name is reported verbatim.
      if sub.is_sub_ifd() && !format.is_int() {
        let dir = kind.as_str();
        let fmt = format.name();
        let name = sub.tag_name();
        self.warn(std::format!(
          "Wrong format ({fmt}) for {dir} 0x{tag_id:04x} {name}"
        ));
        // `next unless $verbose` (Exif.pm:6754) — skip the entry, the sub-IFD
        // is NOT walked: [`Step::Skip`].
        return Step::Skip;
      }
      self.dispatch_subdir(sub, value_offset, read_len, format, count);
      // The SubDirectory was dispatched (recursed/captured) — a normal entry:
      // [`Step::Keep`].
      return Step::Keep;
    }

    // ---- Canon LIST / Format-override specials (`0x28` / `0x96`) ---------
    // `%Canon::Main` carries two leaf tags whose VALUE bytes are rewritten at
    // walk time — `Format => 'undef'` (0x28 ImageUniqueID) and the model-
    // conditional `0x96` LIST (`Canon.pm:1726-1735`/`:1834-1846`) — reproducing
    // exactly what [`body::walk_canon_in_tiff`](makernotes::vendors::canon::walk_canon_in_tiff)
    // (`body.rs:395-468`) does BEFORE `parse_in_tiff` emits them. The rewrite
    // bypasses the `Format` override / large-array guards / numeric `read_value`
    // path below (the `undef`/`string` view is the faithful one — Canon's table
    // `Format`s override the on-disk numeric decode; a 0x28's Exif-table
    // `format_override` is irrelevant here), so it is taken FIRST, only for those
    // two tags and only under `%Canon::Main`. `read_len == size` is the on-disk
    // `format.byte_size() * count` (the body walker's `total_size`), and
    // `value_offset` is the same out-of-line / inline value pointer — so the
    // window read here is byte-identical to the body walker's. A `None` means
    // the entry is NOT one of these specials (or its 0x96 window is out of
    // bounds, matching the body walker's `get(..).is_some()` rewrite gate) — fall
    // through to the normal leaf decode.
    if self.active_table == TableRef::Canon
      && let Some(raw) = self.canon_special_leaf_value(tag_id, format, value_offset, read_len)
    {
      // The Canon specials keep their on-disk `$format` (no Sony `$format` gate
      // applies to a Canon walk). `value_offset`/`read_len` are the resolved value
      // pointer + on-disk byte size (the same SPAN `canon_special_leaf_value` read).
      self.emit(kind, tag_id, format, value_offset, read_len, raw);
      // The special-case value was decoded + emitted (FoundTag) — [`Step::Keep`].
      return Step::Keep;
    }

    // ---- Tag-table READ-side `Format` override --------------------------
    // `my $readFormat = $$tagInfo{Format}; ... if ($readFormat) { $formatStr
    // = $readFormat; ... $format = $newNum; ... $count = int($size /
    // $formatSize[$format]) }` (Exif.pm:6729-6744). The tag table's `Format`
    // is honored BEFORE `ReadValue`, OVERRIDING the on-disk format code. The
    // on-disk byte `$size` (= count × on-disk elem size, computed above) is
    // preserved; the new count is `int($size / new_elem_size)`. This is the
    // mechanism that forces `UserComment` (0x9286, `Format => 'undef'`,
    // Exif.pm:2500) through `undef` even when a camera mis-wrote it as
    // `string`/`int8u` (Exif.pm:2499) — without it `ReadValue`'s `string`
    // decode would NUL-trim `ASCII\0\0\0Hello World` to `ASCII` before the
    // `ConvertExifText` RawConv could strip the 8-byte charset prefix. The
    // override is resolved against the SAME tag table the leaf emits under
    // (Exif/Interop vs GPS): the GPS table carries its OWN `Format` override
    // for `GPSDateStamp` (0x001d, `Format => 'undef'`, GPS.pm:312) — without it
    // a `string`-on-disk `GPSDateStamp` (`2024\0 05\0 22\0`) would NUL-trim to
    // `2024` and collapse to just the year. Resolving per-table (rather than
    // gating all GPS entries off) honors 0x001d while leaving the GPS text
    // tags 0x001b/0x001c — `Writable => 'undef'` but NO `Format`, GPS.pm:296/
    // 304 — correctly NUL-trimmed, exactly as bundled does.
    // Resolved against the active table (`Exif.pm:6729-6744` reads the
    // override off the directory's `$tagTablePtr`). `Interop` inherits the
    // `%Exif::Main` override table; the Canon vendor table does NOT (see its arm).
    //
    // The ON-DISK format is captured BEFORE the override reshapes `format`, so the
    // emitted [`ExifEntry`] retains the `$format` a bundled `Condition` reads
    // (`GetTagInfo`). The Sony `%Main` `$format`-gated single-HASH rows
    // (0x1000/0x1001/0x1002) read it at emit time.
    let on_disk_format = format;
    let table_override = match self.active_table {
      TableRef::Gps => {
        #[cfg(feature = "gps")]
        {
          gps::format_override(tag_id)
        }
        // `gps` feature OFF ⇒ the GPS module is "not loaded": no GPS-table
        // `Format` override is resolvable (the leaf isn't decoded as a GPS tag
        // either), so fall through with the on-disk format unchanged.
        #[cfg(not(feature = "gps"))]
        {
          let _ = tag_id;
          None
        }
      }
      TableRef::Exif | TableRef::Interop => tables::format_override(tag_id),
      // `%Sony::Main` carries its OWN `Format =>` directives (0x0112/0x1000/
      // 0x200a/0x2037/0xb022/0xb02a — `Sony.pm`); ExifTool's `ProcessExif` reads
      // the override off the ACTIVE `$tagTablePtr` (`Exif.pm:6729`), so the Sony
      // table's directives apply on a Sony Main walk — reproducing
      // `walk_sony_in_tiff`'s `resolve_read_format` step (`sony/body.rs:119`).
      // Resolving them here keeps the shared-Walker walk byte-identical to the
      // retired `sony::parse_in_tiff` oracle for those six tags (#243 phase 3).
      TableRef::Sony => makernotes::vendors::sony::format_override(tag_id),
      // `%Panasonic::Main` carries its OWN `Format =>` directives (MANY rows are
      // `Writable => 'int16u'` but `Format => 'int16s'` so the on-disk unsigned
      // bytes are read SIGNED — 0x23 WhiteBalanceBias `ff fd` ⇒ -3 ⇒ -1, not
      // 65533 — plus the int32u-from-rational rows FilterEffect 0xa1 /
      // PostFocusMerging 0xbf and the int16s pairs Transform/HighlightShadow,
      // `Panasonic.pm`). ExifTool's `ProcessExif` reads the override off the ACTIVE
      // `$tagTablePtr` (`Exif.pm:6729`), so the Panasonic table's directives apply
      // on a Panasonic Main walk — reproducing `walk_panasonic_in_tiff`'s
      // `resolve_read_format` step (`panasonic/body.rs:163-164`). Resolving them
      // here keeps the shared-Walker walk byte-identical to the retired
      // `panasonic::parse_in_tiff` oracle for those rows (#243 phase 3).
      TableRef::Panasonic => makernotes::vendors::panasonic::format_override(tag_id),
      // `%Nikon::Main` / `%Nikon::Type2` (#243 phase 3-bis). Unlike Sony/Panasonic
      // (which carry only EXPLICIT `Format =>` directives), `nikon::format_override`
      // ALSO reproduces the IMPLICIT-`undef` SubDirectory override that
      // `walk_nikon_ifd` applies (`body.rs:592-600` / `Exif.pm:6733`): a non-SubIFD
      // SubDirectory tag with no explicit `Format` reads as `undef`, so the whole
      // binary block (AFInfo/ColorBalance/…) reaches the child walker AND is exempt
      // from the excessive-count guard (`undef` is an exemption). Both Nikon tables
      // share this override fn (keyed against `%Nikon::Main`); it is safe for the
      // Type2 walk because the tables do not collide on any SubDirectory ID (see
      // `nikon::format_override`). Resolving it here keeps the shared-Walker walk
      // byte-identical to the `walk_nikon_ifd` oracle.
      TableRef::Nikon | TableRef::NikonType2 => makernotes::vendors::nikon::format_override(tag_id),
      // VENDOR tables (Canon, #243 phase 2) inherit NO `%Exif::Main` `Format`
      // override: a Canon MakerNote tag colliding with an EXIF override id (e.g.
      // 0x9286 `UserComment`, `Format => 'undef'`) must keep its ON-DISK format —
      // `%Canon::Main` carries no such directive. Without this, a crafted numeric
      // Canon 0x9286 would be coerced to `undef`, BYPASS the excessive-count guard
      // (which exempts `undef`), and be read into a large allocation before `emit`
      // drops the unknown tag — a divergence from `parse_in_tiff` (which applies NO
      // EXIF override) AND an OOM vector (#243 phase 2 R11). The Canon table's OWN
      // format rewrites (0x28/0x96) run EARLIER via `canon_special_leaf_value`, so
      // `None` here is complete for Canon.
      _ => None,
    };
    let (format, count) = if let Some(over) = table_override {
      let new_elem = over.byte_size();
      if new_elem != 0 && over != format {
        // `$count = int($size / $formatSize[$format])` — `size` is the
        // on-disk byte size; re-shape the count for the override element.
        (over, size / new_elem)
      } else {
        (format, count)
      }
    } else {
      (format, count)
    };

    // ---- Excessive / large-array guards (Exif.pm:6760-6783) -------------
    // Two guards that "limit maximum length of data to reformat (avoids long
    // delays when processing some corrupted files)", BOTH applied to the
    // post-`Format`-override `format`/`count` (Exif.pm:6760+ runs after the
    // 6729-6744 override). The `$formatStr !~ /^(undef|string|binary)$/`
    // exclusion is `!matches!(format, Undef | Ascii)` — `binary` is a
    // synthetic ExifTool format never produced on this on-disk decode path,
    // and `string`==`Ascii`.
    if !matches!(format, Format::Undef | Format::Ascii) {
      // The dirName/tagName as Perl resolves them for these warnings:
      // `$tagName = $tagInfo ? $$tagInfo{Name} : sprintf('tag 0x%.4x',$tagID)`
      // (Exif.pm:6762). NOTE the excessive-count message uses `$dirName`
      // (Exif.pm:6766); `$dir == $dirName == kind.as_str()` for every
      // non-MakerNotes IFD this walker reaches (Exif.pm:6341).
      let known = Self::lookup_name_in(self.active_table, tag_id);

      // Guard (a) — `if ($count > 100000 and ...)` (Exif.pm:6760-6770).
      if count > 100_000 {
        // `if ($tagName ne 'TransferFunction' or $count != 196608)` — the
        // ColorMap-shaped 196608-count `TransferFunction` is the one tag
        // allowed an excessive count silently (Exif.pm:6764). An UNKNOWN tag
        // (`known == None`) is never named `TransferFunction`, so the carve-out
        // can only spare a KNOWN `TransferFunction`. (No ported tag is named
        // that, so the carve-out is currently inert, but it is modelled
        // faithfully for when 0x012d is added.)
        let transfer_function_carveout = known == Some("TransferFunction") && count == 196_608;
        if !transfer_function_carveout {
          // `my $minor = $count > 2000000 ? 0 : 2;`
          // `$et->Warn("Ignoring $dirName $tagName with excessive count", $minor)`
          // (Exif.pm:6766-6767), with `$tagName = $tagInfo ? Name : 'tag
          // 0x%.4x'`. In the default (non-HtmlDump) path `Warn` returns true
          // and Perl does `next` (Exif.pm:6768) — SKIP this entry, do NOT
          // decode. `$minor == 2` means `sub Warn` PREFIXES the message
          // `[Minor] ` even in normal mode (the `'2'` arm of ExifTool.pm:5630
          // — NOT only the `IgnoreMinorErrors`-suppressed case; oracle-verified
          // against `perl exiftool 13.59`: a known SHORT tag with count 150000
          // emits `"[Minor] Ignoring IFD0 Orientation with excessive count"`).
          // The `[Minor] ` prefix is applied centrally by `run_diagnostics`
          // from the ignorable level, not baked in here. `$warned` is set only
          // in the HtmlDump branch, which this port does not model.
          let dir = kind.as_str();
          let msg = match known {
            Some(name) => std::format!("Ignoring {dir} {name} with excessive count"),
            None => std::format!("Ignoring {dir} tag 0x{tag_id:04x} with excessive count"),
          };
          if count > 2_000_000 {
            self.warn(msg); // `$minor == 0` — no prefix
          } else {
            self.warn_minor_behavioral(msg); // `$minor == 2` ⇒ `[Minor] `
          }
          return Step::Skip; // `next` (Exif.pm:6768)
        }
      }

      // Guard (b) — `if ($count > 500 and ... and (not $tagInfo or
      // $$tagInfo{LongBinary} or $warned) and not IgnoreMinorErrors)`
      // (Exif.pm:6771-6779). In the port's world: `$warned` is never set
      // (no HtmlDump), `LongBinary` is not carried by any ported tag, and
      // `IgnoreMinorErrors` is not modelled (default off ⇒ the `not` is true),
      // so the gate reduces to `count > 500 and not $tagInfo` — i.e. a tag
      // ABSENT from this IFD's table. ExifTool then sets `$val = "(large array
      // of $count $formatStr values)"` instead of decoding (Exif.pm:6777).
      // Verified against bundled ExifTool 13.59: a KNOWN tag with a 600-element
      // int32u array (e.g. `LensInfo`) is decoded in FULL — the placeholder is
      // NOT used — precisely because `(not $tagInfo or LongBinary or $warned)`
      // is false; only an UNKNOWN tag takes the placeholder. The port emits no
      // unknown leaf tags (`emit` drops them, `next unless $verbose`), so the
      // placeholder value is observationally never surfaced — but it is
      // produced and routed through `emit` here to mirror Perl exactly (the
      // unknown tag is then dropped, matching bundled's verbose-only output).
      if count > 500 && known.is_none() {
        let placeholder = large_array_placeholder(count, format);
        let raw = placeholder.clone().into_bytes().into_boxed_slice();
        self.emit(
          kind,
          tag_id,
          on_disk_format,
          value_offset,
          read_len,
          RawValue::Text {
            text: placeholder,
            raw,
          },
        );
        // ExifTool sets `$val` to the placeholder and FALLS THROUGH to
        // FoundTag (Exif.pm:6778-6779) — it does NOT `next` (the lone `next`
        // is the `TAGS_FROM_FILE` copy-mode, not modelled). The placeholder
        // tag IS emitted, so this is a processed entry: [`Step::Keep`].
        return Step::Keep;
      }
    }

    // ---- Leaf tag — decode the value ------------------------------------
    // `$formatStr = 'int8u' if $format == 7 and $count == 1` (Exif.pm:6644)
    // — "treat single unknown byte as int8u". So a 1-element `undef` tag
    // decodes as an integer, not a 1-byte binary blob. This matters for the
    // `undef`-typed enumerations (SceneType / FileSource — Exif.pm:2812/
    // 2824) whose PrintConv hash needs a numeric key, not raw bytes.
    //
    // NOTE the int8u carve-out tests `$format`/`$count` AFTER the Format
    // override above (Exif.pm:6682 runs before the override, but for a 0x9286
    // forced to `undef` with count ≥ 1 the carve-out only fires at count==1 —
    // a 1-byte UserComment is degenerate and decodes as int8u in both, so the
    // ordering is observationally identical to bundled here).
    let decode_format = if matches!(format, Format::Undef) && count == 1 {
      Format::Int8u
    } else {
      format
    };
    // NIKON implicit-`undef` SubDirectory — the binary-block sub-tables (AFInfo /
    // ColorBalance / LensData / FlashInfo / ShotInfo) whose decoded leaf value is
    // DEAD: the Nikon capture loop dispatches them by re-slicing the on-disk SPAN
    // (`value_offset`/`read_len`) from `self.data`, never the `ExifEntry`'s value
    // (#243 phase 3-bis). So store a ZERO-COPY empty `RawValue::Bytes` instead of
    // `read_value`-cloning the (possibly crafted-huge, in-bounds) `undef[N]` block —
    // mirroring the oracle's own `RawValue::Bytes(Vec::new())` for the SAME
    // `implicit_undef` predicate (`body.rs` `walk_nikon_ifd`). The full extent is
    // already proven in-bounds (the out-of-line `value_end > data.len()` Bad-offset
    // drop / the inline `entry+12` bound above), so `read_value` here could only
    // return `Some` — skipping it changes NO walk decision, only the retained heap.
    // This CLOSES the heap-amplification the finding names: many SubDirectory
    // entries (e.g. duplicated 0x0098 LensData) pointing at ONE large in-bounds
    // block now retain NOTHING, where a per-entry materialized copy drove
    // `N * value_size` growth from a sub-MB MakerNote. A `SubIFD` pointer is NOT
    // implicit-`undef` (excluded by the predicate), so its real integer offset
    // value is unaffected; every non-Nikon table also skips this branch.
    let raw = if matches!(self.active_table, TableRef::Nikon | TableRef::NikonType2)
      && makernotes::vendors::nikon::is_implicit_undef_subdir(tag_id)
    {
      RawValue::Bytes(Vec::new())
    } else {
      let Some(raw) = read_value(data, value_offset, decode_format, count, read_len, order) else {
        // `next unless defined $val` (Exif.pm:7016) — [`Step::Skip`].
        return Step::Skip;
      };
      raw
    };

    // `value_offset`/`read_len` are the resolved value pointer + the ON-DISK byte
    // size (`$size`, BEFORE the `Format` override / `undef[1]→int8u` carve-out) —
    // carried on the entry so a vendor capture loop can re-slice the verbatim value
    // SPAN independent of the (possibly int8u-coerced) decoded `raw` shape
    // (the Nikon sub-table emitters, #243 phase 3-bis).
    self.emit(kind, tag_id, on_disk_format, value_offset, read_len, raw);
    // The leaf value was decoded + emitted (FoundTag) — a normal entry:
    // [`Step::Keep`].
    Step::Keep
  }

  /// The Canon `%Main` walk-time value rewrite for the two special leaves
  /// `0x28` (`ImageUniqueID`, `Format => 'undef'`) and `0x96` (the model-
  /// conditional `SerialInfo` / `InternalSerialNumber` LIST) — the
  /// shared-`Walker` reproduction of
  /// [`body::walk_canon_in_tiff`](makernotes::vendors::canon::walk_canon_in_tiff)'s
  /// per-entry value rewrites (`body.rs:395-468`), #243 phase 2 step B3.
  ///
  /// Returns `Some(raw)` with the rewritten value for those two tags (the value
  /// the [`emit`](Self::emit) → `ResolvedConv::Canon` arm then renders), or
  /// `None` when the tag is NOT one of the two specials — in which case
  /// [`walk_entry`](Self::walk_entry) falls through to the normal `Format`-
  /// override / large-array / numeric `read_value` leaf path (the path Steps
  /// A/B1/B2 use for every other Canon tag, unchanged).
  ///
  /// `value_offset` / `read_len` are the already-resolved (out-of-line OR
  /// inline) value pointer and on-disk byte size (`read_len == count *
  /// format.byte_size()`, the body walker's `total_size`), so the window read
  /// here is byte-for-byte the body walker's `value_data_offset ..
  /// value_data_offset + total_size`.
  ///
  /// ## `0x28` ImageUniqueID — `Format => 'undef'` (`Canon.pm:1726-1735`)
  ///
  /// ExifTool's `ProcessExif` overrides the entry's declared numeric format
  /// with `undef` and reads the ORIGINAL on-disk `$size` bytes VERBATIM
  /// (`int8u[16]` / `int16u[8]` / `undef[16]` / `float[4]` … all read the SAME
  /// literal bytes — `body.rs:369-402`). Capture that raw-byte view as
  /// [`RawValue::Bytes`], with `get(..).unwrap_or(&[])` so a truncated/oversized
  /// shape yields an empty (`undef`) value — never an OOB read — and a count-0
  /// entry yields empty bytes (oracle: `undef[0]` ⇒ `ImageUniqueID = ""`).
  ///
  /// ## `0x96` `SerialInfo` / `InternalSerialNumber` LIST (`Canon.pm:1834-1846`)
  ///
  /// Using the on-disk window (only when it is in bounds — matching the body
  /// walker's `get(..).is_some()` rewrite gate; an out-of-bounds window returns
  /// `None`, falling through to the normal numeric decode just as the body
  /// walker leaves `raw` untouched):
  /// - FIRST arm — `$$self{Model} =~ /EOS 5D/`
  ///   ([`model_matches_eos_5d`](makernotes::vendors::canon::printconv::model_matches_eos_5d)):
  ///   the `SerialInfo` SubDirectory blob, kept VERBATIM as [`RawValue::Bytes`]
  ///   (NO NUL-trim, NO `0xff` strip — those are second-arm `string` semantics).
  /// - SECOND arm — `string`-format `InternalSerialNumber` (`Canon.pm:1841-
  ///   1845`, `$val=~s/\xff+$//`): NUL-trim at the first NUL (the `string`
  ///   `ReadValue` decode), then strip one-or-more trailing `0xff` bytes, BOTH at
  ///   the RAW-byte level (BEFORE the lossy UTF-8 decode could turn a trailing
  ///   `0xff` into U+FFFD and defeat the strip), then surface as
  ///   [`RawValue::Text`]. Only a `string`-format 0x96 is rewritten; any other
  ///   on-disk format on a non-5D body returns `None` (normal decode), exactly
  ///   like the body walker's `matches!(format, Format::Ascii)` guard.
  ///
  /// The 5D arm keys on [`captured_model`](Self::captured_model) (IFD0's
  /// `$$self{Model}`, the SAME field the body walker's `model` parameter
  /// carries), so the arm selection is identical.
  #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
  fn canon_special_leaf_value(
    &self,
    tag_id: u16,
    format: Format,
    value_offset: usize,
    read_len: usize,
  ) -> Option<RawValue> {
    let data = self.data;
    if tag_id == 0x28 {
      // `Format => 'undef'`: the ORIGINAL on-disk bytes, read verbatim.
      // `value_offset + read_len` is the body walker's `value_data_offset +
      // format.byte_size() * count`; `get(..).unwrap_or(&[])` keeps a
      // truncated/oversized/count-0 shape an empty `undef`, never an OOB read.
      let window = value_offset
        .checked_add(read_len)
        .and_then(|end| data.get(value_offset..end))
        .unwrap_or(&[]);
      return Some(RawValue::Bytes(window.to_vec()));
    }
    if tag_id == 0x96 {
      use makernotes::vendors::canon::printconv;
      // The on-disk window — only rewrite when it is in bounds (the body
      // walker's `if let Some(window) = tiff_data.get(..)` gate); an out-of-bounds
      // window leaves the value to the normal numeric decode (`None`).
      let window = value_offset
        .checked_add(read_len)
        .and_then(|end| data.get(value_offset..end))?;
      if self
        .captured_model
        .as_deref()
        .is_some_and(printconv::model_matches_eos_5d)
      {
        // FIRST arm — `SerialInfo` SubDirectory blob: on-disk bytes verbatim.
        return Some(RawValue::Bytes(window.to_vec()));
      }
      if matches!(format, Format::Ascii) {
        // SECOND arm — `InternalSerialNumber` (`$val=~s/\xff+$//`). NUL-trim at
        // the first NUL (`s/\0.*//s`), then strip trailing `0xff`, BOTH at the
        // raw-byte level, then decode lossily for display while retaining the
        // post-RawConv bytes (`RawValue::Text { raw }`).
        let nul_trimmed = match window.iter().position(|&b| b == 0) {
          Some(nul) => window.get(..nul).unwrap_or(window),
          None => window,
        };
        let end = nul_trimmed
          .iter()
          .rposition(|&b| b != 0xff)
          .map_or(0, |i| i + 1);
        let stripped = nul_trimmed.get(..end).unwrap_or(nul_trimmed);
        return Some(RawValue::Text {
          text: std::string::String::from_utf8_lossy(stripped).into_owned(),
          raw: stripped.into(),
        });
      }
      // A non-5D body with a non-`string` 0x96 — the body walker leaves `raw`
      // as the numeric decode; fall through to the normal leaf path.
      return None;
    }
    None
  }

  /// THE one sub-directory entry point — the faithful
  /// `ProcessExif`-on-a-`SubDirectory` path (`Exif.pm:6919-7102`), parameterized
  /// by the `SubDirectory` directive set the engine unification models
  /// (`MakerNotes.pm:37-1127`). Every IFD-pointer subdirectory (ExifIFD/GPS/
  /// Interop today; every vendor maker note in Phase 2+) is processed here, so
  /// `FixBase`, `ByteOrder=Unknown` detection, the per-entry warnings, the
  /// `warn_count>10` abort, sub-IFD recursion and `run_emission` are shared
  /// engine features each directory inherits — not re-derived per vendor.
  ///
  /// It SAVES, sets, and RESTORES both [`active_table`](Self::active_table) (so
  /// a sub-IFD's table never leaks into the parent's remaining entries) and
  /// [`order`](Self::order) (so a `Fixed(other)` / `Unknown`-toggled child order
  /// is honored only for the duration of the child walk — `Exif.pm:7078`'s
  /// `SetByteOrder` is scoped to the subdirectory and the parent order is
  /// restored on return).
  ///
  /// ## Pre-walk hooks — provably INERT for the core Exif/GPS/Interop sub-IFDs
  ///
  /// The core descriptors pass `ByteOrder = Fixed(parent_order)`,
  /// `FixBase = No`, `Process = Exif`, so NONE of the three hooks fires and the
  /// `ifd_start`/`order` handed to [`walk_one_ifd`] are EXACTLY the values the
  /// pre-unification `self.walk_one_ifd(sub_offset, kind)` used — byte-identical
  /// by construction. The hooks (each faithful to the cited Perl) fire only for
  /// a maker-note descriptor (Phase 2+):
  ///
  /// - [`ByteOrderRule::Unknown`] → [`fixbase::detect_unknown_byte_order`]
  ///   (`Exif.pm:6982-6993`) — probe the entry-count word; fall back to the
  ///   parent order when fewer than 2 bytes are available.
  /// - [`FixBaseMode`] `!= No` → [`fixbase::fix_base`] (`MakerNotes.pm:1282-
  ///   1484`) — the offset-correction heuristic; relocates the value base.
  /// - [`ProcessProc::Unknown`] → [`fixbase::locate_ifd`] (`MakerNotes.pm:1486-
  ///   1663`) — scan for the real IFD start and resolve its order.
  ///
  /// `Fixed(parent_order)` resolves to `self.order` unchanged, `No` runs no
  /// `fix_base`, and `Exif` runs no `locate_ifd`, so the save/restore of
  /// `self.order` and the `ifd_start` passed on are no-ops for every current
  /// caller. The full base/`data_pos` mutation that a non-`No` `fix_base`
  /// implies is applied by the Phase-2 vendor migration (the Walker's `base`
  /// model is threaded then); here `fix_base` is INVOKED behind the
  /// `!= No` gate (wiring the feature in) but the core path never reaches it.
  #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
  fn process_subdir(
    &mut self,
    ifd_start: usize,
    kind: IfdKind,
    table: TableRef,
    byte_order: ByteOrderRule,
    fix_base: FixBaseMode,
    process: ProcessProc,
  ) {
    // ---- Pre-walk hook 1: resolve the child byte order (`Exif.pm:6982-6996`).
    // `Fixed(o)` keeps `o`; `Unknown` probes the entry-count word, falling back
    // to the parent order when the probe is inconclusive (`:6996`). For a core
    // sub-IFD this is `Fixed(self.order)` ⇒ `resolved_order == self.order`.
    let resolved_order = match byte_order {
      ByteOrderRule::Fixed(o) => o,
      ByteOrderRule::Unknown => {
        makernotes::fixbase::detect_unknown_byte_order(self.data, ifd_start, self.order)
          .unwrap_or(self.order)
      }
    };

    // ---- Pre-walk hook 2: ProcessUnknown's `LocateIFD` (`MakerNotes.pm:1816-
    // 1837`). Only `ProcessProc::Unknown` relocates the IFD start + order; the
    // other processors keep `ifd_start`/`resolved_order` as derived. A failed
    // locate leaves them unchanged (the walk then bounds-rejects, mirroring
    // `ProcessUnknown`'s `Unrecognized` warn arm). Inert for `Exif`/`Canon`.
    //
    // `locate_ifd` returns the located IFD offset RELATIVE to the `ifd_start` it
    // was handed (its scan runs `0..=32` from `dir_start`), so the ABSOLUTE
    // position in `self.data` is `ifd_start + located`. Adding it back is
    // essential for any maker note whose blob begins at a non-zero TIFF offset;
    // a `checked_add` overflow (degenerate input) falls back to the unrelocated
    // start, which the walk then bounds-rejects.
    let (ifd_start, resolved_order) = match process {
      ProcessProc::Unknown => makernotes::fixbase::locate_ifd(
        self.data,
        ifd_start,
        None,
        resolved_order,
        self.captured_make.as_deref(),
        self.captured_model.as_deref(),
      )
      .and_then(|(located, order)| ifd_start.checked_add(located).map(|abs| (abs, order)))
      .unwrap_or((ifd_start, resolved_order)),
      ProcessProc::Exif | ProcessProc::Canon | ProcessProc::BinaryData => {
        (ifd_start, resolved_order)
      }
    };

    // ---- Pre-walk hook 3: FixBase (`MakerNotes.pm:1282-1484`). The offset-
    // correction heuristic runs ONLY when a `FixBase` directive is present
    // (`!= No`); its base/`data_pos` mutation is applied by the Phase-2 vendor
    // migration (the Walker's `base` is threaded then). Computing it here wires
    // the feature behind the directive gate. INERT for `FixBaseMode::No` (every
    // core sub-IFD), so the result is discarded with no effect on the walk.
    if let Some(dir_fix_base) = fix_base.dir_fix_base() {
      let input = makernotes::fixbase::FixBaseInput::new(
        self.data,
        ifd_start,
        self.data.len().saturating_sub(ifd_start),
        i64::from(self.base),
        i64::from(self.base),
        resolved_order,
        self.captured_make.as_deref().unwrap_or(""),
        self.captured_model.as_deref().unwrap_or(""),
      )
      .with_file_types(self.file_type.as_deref(), None)
      .with_dir_fix_base(Some(dir_fix_base));
      // Phase-0/1: the heuristic is wired but its base shift is consumed by the
      // Phase-2 vendor migration; ignore it here (core never reaches this).
      let _ = makernotes::fixbase::fix_base(&input);
    }

    // ---- Pre-walk hook 4: the Canon `%CameraSettings` DataMember pre-pass
    // (#243 phase 2 step B2). ExifTool resolves a `ProcessBinaryData` table's
    // `DATAMEMBER` positions BEFORE the main walk, and `Canon::CameraSettings`
    // (`Canon.pm:2219` `DATAMEMBER => [ 22, 25 ]`) sets `$$self{FocalUnits}`
    // (pos 25) and `$$self{LensType}` (pos 22) — cross-entry inputs the
    // `FocalLength` (0x02) and `FileInfo` (0x93) sub-tables read. The Canon Main
    // IFD walk reaches those entries in tag order INDEPENDENT of CameraSettings
    // (0x01), so — exactly like `canon::parse_in_tiff`'s pre-pass
    // (`canon/mod.rs:718-739`) — capture them up front, here, before
    // `walk_one_ifd`, so the dependency holds regardless of IFD entry order.
    // `process` is `ProcessProc::Canon` for this table (the test's sole caller);
    // the pre-scan reads only the 0x01 entry and EMITS NOTHING. Re-scan per
    // Canon directory (it resets both members first), so a sibling/subsequent
    // walk is unaffected.
    if table == TableRef::Canon {
      self.canon_prescan_datamembers(ifd_start, resolved_order);
    }

    // ---- The walk: SAME `walk_one_ifd` machinery IFD0/ExifIFD/GPS use, under
    // the child table + resolved order, with all three restored on return.
    //
    // `$warnCount` is a `my` local PER `ProcessExif` call (`Exif.pm:6453`): a
    // sub-directory's warning count is independent of its parent's, and the
    // parent resumes its own loop with its own counter unchanged when the
    // sub-call returns. The shared `Walker` holds `warn_count` as ONE field that
    // [`walk_one_ifd_body`] re-zeroes per directory — so the child walk starts at
    // 0 (faithful), but on return it has CLOBBERED the parent's accumulated count
    // (the parent's `walk_entries` loop is suspended mid-iteration around this
    // sub-directory dispatch). Without the restore, the parent's `> 10` abort
    // (`Exif.pm:6455`) would test the CHILD's count: a maker-note / sub-IFD with
    // many bad entries could abort the PARENT directory (dropping its later
    // tags), or a clean child could reset a parent that was near the cap. Save
    // the caller's count before descending and restore it after, so the field
    // behaves like the per-call `my` local across the recursion boundary. (Core
    // sub-IFD recursions — GPS/Interop/ExifIFD via `dispatch_subdir` — share this
    // entry point, so they get the same per-directory scoping; byte-identical for
    // every walk whose sub-directory does not pile up > 10 warnings before the
    // parent's later entries, which the conformance suite confirms is all of them.)
    let saved_table = self.active_table;
    let saved_order = self.order;
    let saved_warn_count = self.warn_count;
    self.active_table = table;
    self.order = resolved_order;
    let _ = self.walk_one_ifd(ifd_start, kind);
    self.warn_count = saved_warn_count;
    self.order = saved_order;
    self.active_table = saved_table;
  }

  /// The Canon `%CameraSettings` DataMember pre-pass (#243 phase 2 step B2) —
  /// the emit-path reproduction of `canon::parse_in_tiff`'s sub-pass
  /// (`canon/mod.rs:717-739`). Walks the Canon Main IFD at `ifd_start` with the
  /// SAME entry classification the main walk uses, and for EVERY readable tag
  /// **0x01** (`CanonCameraSettings`) populates the two Canon DataMembers from
  /// its decoded value — `$$self{FocalUnits}` via
  /// [`read_focal_units`](makernotes::vendors::canon::read_focal_units)
  /// (position 25) and `$$self{LensType}` via
  /// [`camera_settings::parse_with_lens_id_capture`](makernotes::vendors::canon::camera_settings::parse_with_lens_id_capture)'s
  /// lens capture (position 22, `Canon.pm:2503`).
  ///
  /// ## Byte-identity argument
  ///
  /// The DataMembers must equal what `canon::parse_in_tiff` computes — that
  /// sub-pass loops over the `Read`-classified `CanonEntry`s
  /// [`walk_canon_in_tiff`](makernotes::vendors::canon::walk_canon_in_tiff)
  /// produced and, for each CameraSettings, OVERWRITES `focal_units`/`lens_type`
  /// — i.e. the LAST readable 0x01 in IFD order wins (a malformed/suspicious
  /// first 0x01 contributes no entry, so a valid later 0x01 still sets them).
  /// This pre-scan therefore drives the SHARED [`classify_canon_directory`] +
  /// [`classify_canon_entry`] predicates `walk_canon_in_tiff` (and, by the same
  /// `Exif.pm` line refs, the shared Walker's own [`walk_entry`]) use — same
  /// directory shape, same `> 10` warn-count abort, same index-0 bad-format
  /// directory abort, same skip set (bad-format / oversized / bad-offset /
  /// suspicious) — and decodes each surviving 0x01 with the identical ON-DISK
  /// `read_value` (Canon's `%Main` has no `Format` override on 0x01, and the
  /// `read_len = data.len() - value_offset` bound matches `walk_canon_in_tiff`).
  /// So the members it captures equal the oracle's for every input.
  ///
  /// EMITS NOTHING — it only populates [`canon_focal_units`](Self::canon_focal_units)
  /// and [`canon_lens_type`](Self::canon_lens_type), which it RESETS to `None`
  /// first so a re-scan (a second Canon directory, or a Canon walk after some
  /// other directory left them set) never carries a stale member.
  #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
  fn canon_prescan_datamembers(&mut self, ifd_start: usize, order: ByteOrder) {
    use makernotes::vendors::canon::body::{
      CanonDirShape, CanonEntryClass, classify_canon_directory, classify_canon_entry,
    };
    use makernotes::vendors::canon::{camera_settings, read_focal_units};
    // Reset first: the members are only meaningful for THIS Canon walk.
    self.canon_focal_units = None;
    self.canon_lens_type = None;
    self.canon_focal_length_blob = None;
    let data = self.data;
    // Directory shape — the SHARED `ProcessExif` gate (`Exif.pm:6343-6400`) the
    // emission walk uses. A degenerate/overrunning/`1`/`3`-byte-tail directory
    // walks no entries (so both members stay `None`); only the `Walk` arm walks.
    let CanonDirShape::Walk {
      num_entries,
      dir_end,
    } = classify_canon_directory(data, ifd_start, data.len(), order)
    else {
      return;
    };
    let entries_start = ifd_start + 2;
    // `$warnCount` — the SAME per-entry abort cap the emission walk honors
    // (`Exif.pm:6455-6456`): once it exceeds ten, ExifTool `return 0`s, so a 0x01
    // AFTER a >10-warning run is never reached. Counting matches the emission
    // walk's `CanonEntryClass::bumps_warn_count`.
    let mut warn_count: u32 = 0;
    for index in 0..num_entries {
      // `if ($warnCount > 10) { … return 0 }` — abort before reading any further
      // entry (the same point `walk_canon_in_tiff` / `walk_entries` stop).
      if warn_count > 10 {
        break;
      }
      let Some(entry) = entries_start.checked_add(12usize.wrapping_mul(index)) else {
        break;
      };
      // The `Walk` shape proved `dir_end <= data.len()`, so every `entry + 12` is
      // in range. Read the tag id; classify EVERY entry (so warn_count + the
      // index-0 abort track the emission walk) but only decode the 0x01 ones.
      let Some(tag_id) = get_u16(data, entry, order) else {
        continue;
      };
      let class = classify_canon_entry(data, entry, index, ifd_start, dir_end, data.len(), order);
      if class.bumps_warn_count() {
        warn_count = warn_count.saturating_add(1);
      }
      let value_offset = match class {
        CanonEntryClass::Read { value_offset } => value_offset,
        // `index == 0` bad/zero format ⇒ `return 0` (abort the whole directory,
        // no entries) — matching `walk_canon_in_tiff`'s `break`.
        CanonEntryClass::BadFormat { abort: true, .. }
        | CanonEntryClass::SilentBadFormat { abort: true } => break,
        // Every other bad class is a single-entry skip.
        _ => continue,
      };
      // Only the 0x01 (CameraSettings DataMembers) and 0x02 (the FocalLength
      // `$$valPt` cache) pre-pass entries are decoded here — every other tag is
      // surfaced by the main walk, not the pre-scan. (Both are captured in the
      // SAME pass, matching `parse_in_tiff`'s single sub-pass loop,
      // `canon/mod.rs:719-739`.)
      if tag_id != 0x01 && tag_id != 0x02 {
        continue;
      }
      let Some(format_code) = get_u16(data, entry + 2, order) else {
        continue;
      };
      let Some(count) = get_u32(data, entry + 4, order).map(|c| c as usize) else {
        continue;
      };
      let format = Format::from_code(format_code);
      // `if ($count > 100000 and $formatStr !~ /^(undef|string|binary)$/) { next }`
      // (`Exif.pm:6760-6770`) — the SAME excessive-count guard the emission walk
      // applies in `walk_entry`, PREDICATE-FOR-PREDICATE. The pre-scan is a SECOND
      // decode of the 0x01/0x02 entries, so it MUST skip a `count > 100000`
      // CameraSettings/FocalLength the emission walk skips (#243 phase 2 R9) — but
      // ONLY when the guard does, i.e. NOT for `undef`/`string`. The guard reads
      // the ON-DISK `format` (NOT the table format), so a crafted 0x01/0x02
      // mis-written as `undef[100001]` is DECODED by the emission walk (the format
      // exemption) and must be decoded here too — the pre-scan's blob must match
      // what the emit walk reads (#243 phase 2 R10 — an unconditional skip dropped
      // the FocalLength blob / DataMembers the emission walk still sets).
      if !matches!(format, Format::Undef | Format::Ascii) && count > 100_000 {
        continue;
      }
      // `read_len` = the on-disk byte size `$count * $formatSize[$format]`
      // (`Exif.pm:6502` `my $size = $count * $formatSize[$format]`) — the SAME
      // COUNT-based size the emission walk (`walk_entry`) passes to `read_value`,
      // NOT an EOF-bound read. This is the critical consistency: the pre-scan is a
      // SECOND decode of the 0x01/0x02 entries (the emission walk decodes them
      // AGAIN), so it MUST use the emission walk's value-decode policy. A count-0
      // 0x01/0x02 therefore decodes EMPTY here (`Exif.pm:6285-6288` `unless
      // ($count) { $count = int($size / $len) }` with `$size == 0` ⇒ `undef`),
      // setting NO DataMember — exactly as the emission walk emits no CameraSettings
      // positions for it. An EOF-bound bound would instead re-derive a bogus count
      // from the trailing buffer (`int($size / $len)` with `$size = EOF`) and set
      // `focal_units` / `lens_type` from bytes the emission walk never reads — a
      // divergence (#243 phase 2 R6). `read_value` clamps its window to
      // `data.len()` internally, so the count-based size can never read OOB.
      let read_len = count.saturating_mul(format.byte_size());
      // Decode with the ON-DISK format (no Canon `Format` override on 0x01/0x02)
      // — byte-identical to `walk_canon_in_tiff`'s `read_value` for this entry. A
      // decode failure `continue`s (the oracle drops such an entry before its
      // sub-pass, `body.rs:405-408` — so a later valid one can still win), NOT a
      // `return` that would abandon a subsequent readable record.
      let Some(raw) = read_value(data, value_offset, format, count, read_len, order) else {
        continue;
      };
      if tag_id == 0x02 {
        // `CanonFocalLength` (0x02): cache the reserialized `$$valPt`. LAST
        // readable 0x02 WINS — `parse_in_tiff`'s sub-pass overwrites
        // `focal_length_data` for EVERY readable 0x02 (`canon/mod.rs:735-738`,
        // no break), and its main pass then renders EVERY 0x02 SubDirectory from
        // that FINAL cached blob (`canon/mod.rs:883-889`). The emit reads
        // `self.canon_focal_length_blob` for every 0x02, so two 0x02 entries
        // emit "last,last" (the divergence this closes). The cached blob is the
        // SAME `reserialize_int_array` view `emit_canon_subtable` builds from a
        // walked entry's `RawValue`, since both decode the SAME bytes via the
        // SAME `read_value`.
        self.canon_focal_length_blob = Some(makernotes::vendors::canon::reserialize_int_array(
          &raw, order,
        ));
        continue;
      }
      // `read_focal_units` reads position 25 (FocalUnits); the lens capture
      // reads position 22's `RawConv` DataMember. Both operate on the SAME
      // decoded value the production sub-pass uses (`canon/mod.rs:723-733`).
      //
      // LAST-WINS, NOT first-wins: `parse_in_tiff`'s sub-pass overwrites
      // `focal_units`/`lens_type` for EACH CameraSettings it walks (it never
      // breaks after the first), so the LAST readable 0x01 in IFD order
      // determines both members. Do NOT `return` here — let a subsequent 0x01
      // overwrite. (Lens capture writes `lens_type` only for a truthy position-22
      // word — `Canon.pm:2503` `$val ? … : undef` — so a valid 0x01 with a 0
      // lens word leaves the prior value; matching the oracle, whose RawConv is
      // likewise a no-op for a 0 word.)
      self.canon_focal_units = read_focal_units(&raw, order);
      let blob = makernotes::vendors::canon::reserialize_int_array(&raw, order);
      let mut lens_type: Option<u16> = self.canon_lens_type;
      // PrintConv mode is irrelevant to the lens-id CAPTURE (the side channel is
      // written from the raw word, not the rendered string); pass `false` since
      // the returned position vector is discarded here.
      let _ = camera_settings::parse_with_lens_id_capture(&blob, order, false, &mut lens_type);
      self.canon_lens_type = lens_type;
    }
  }

  /// CAPTURE the Canon Main IFD's walked leaves into a `Vec<VendorEmission>` —
  /// the emit-time reproduction of `canon::parse_in_tiff`'s emission stream
  /// (#243 phase 2 step C). The Canon walk
  /// ([`process_subdir`](Self::process_subdir) under `TableRef::Canon`) appended
  /// each Canon leaf to `self.entries` as a [`ResolvedConv::Canon`] entry; this
  /// re-runs [`emit_entry`] over the contiguous run `self.entries[canon_start..]`
  /// with a [`VendorEmissionSink`], threading the SAME render context the walk
  /// resolved — `self.captured_model` (`$$self{Model}`), `self.file_type`
  /// (`$$self{FILE_TYPE}`), and the pre-scanned `%CameraSettings` DataMembers
  /// (`self.canon_focal_units` / `self.canon_lens_type`). The result is the
  /// vendor-emission `Vec` every other vendor's body parser produces, so the
  /// dispatch can store it in [`MakerNote::cached_emissions_print_conv`] (PrintConv)
  /// or hand it back from the `-n` recompute (ValueConv), driven by `print_conv`.
  ///
  /// Borrows `self` immutably for the entry slice + context but builds an owned
  /// `Vec` (the sink pushes into a fresh buffer), so it does NOT mutate the walk
  /// state — the caller decides whether to TRUNCATE `self.entries` back to
  /// `canon_start` afterward (the dispatch does, so the Canon leaves emit via the
  /// cached emissions, NOT inline in `push_exif_tags`).
  #[must_use]
  fn capture_canon_emissions(
    &self,
    canon_start: usize,
    print_conv: bool,
  ) -> std::vec::Vec<makernotes::VendorEmission> {
    let mut emissions = std::vec::Vec::new();
    let mut sink = VendorEmissionSink::new(&mut emissions);
    for entry in self.entries.get(canon_start..).unwrap_or(&[]) {
      // Only `ResolvedConv::Canon` entries live in this run; `emit_entry` routes
      // them through the Canon `PrintConv` / sub-table / special renderers, all
      // of which write through `write_vendor_value` into the capture sink. The
      // emit is infallible (`Infallible`).
      let Ok(()) = emit_entry(
        entry,
        self.order,
        print_conv,
        self.captured_model.as_deref(),
        self.file_type.as_deref(),
        self.canon_focal_units,
        self.canon_lens_type,
        self.canon_focal_length_blob.as_deref(),
        &mut sink,
      );
    }
    emissions
  }

  /// Dispatch a SubDirectory pointer tag.
  ///
  /// For ExifIFD/GPS/Interop the value is the 32-bit IFD offset
  /// (`SubDirectory => { Start => '$val' }`, `Exif.pm:2012`); we recurse
  /// `walk_one_ifd` at that offset with the SubDirectory's `DirName`.
  ///
  /// For MakerNote (0x927c) we CAPTURE the raw bytes and DEFER vendor
  /// parsing (the MakerNotes wave) — see [`SubDirKind::MakerNote`].
  fn dispatch_subdir(
    &mut self,
    sub: SubDirKind,
    value_offset: usize,
    read_len: usize,
    format: Format,
    count: usize,
  ) {
    match sub {
      SubDirKind::ExifIfd | SubDirKind::Gps | SubDirKind::Interop => {
        // The pointer value (`Start => '$val'`). For ExifIFD/GPS/Interop the
        // on-disk format is normally `int32u`/`ifd` with count 1, but
        // `%intFormat` (Exif.pm:125-136) also accepts the SIGNED integer
        // formats, so a pointer mis-encoded as e.g. `int32s` passes the
        // `Wrong format` gate (Exif.pm:6747) and is still used as the offset.
        // Decode it accepting both `U64` and `I64` shapes.
        let Some(raw) = read_value(self.data, value_offset, format, count, read_len, self.order)
        else {
          return;
        };
        let Some(sub_offset) = raw.first_subdir_offset() else {
          return;
        };
        let kind = match sub {
          SubDirKind::ExifIfd => IfdKind::ExifIfd,
          SubDirKind::Gps => IfdKind::Gps,
          SubDirKind::Interop => IfdKind::Interop,
          SubDirKind::MakerNote => unreachable!("MakerNote handled below"),
        };
        // `unless (IsInt($newStart)) { ... }` passes for a negative `$val`
        // (`IsInt` is `/^[+-]?\d+$/`, ExifTool.pm:5943), but the subsequent
        // `if ($subdirStart < 0 ...) { ... Bad $tagStr SubDirectory start }`
        // (Exif.pm:7017) rejects a NEGATIVE pointer. For a standalone TIFF
        // read via RAF the negative seek fails and ExifTool warns
        // `Bad $dir directory` (Exif.pm:6381) — the same warning
        // `walk_one_ifd` raises for an offset it cannot read. Route the
        // negative pointer through that path instead of walking it.
        let Ok(sub_offset) = usize::try_from(sub_offset) else {
          self.warn(std::format!("Bad {} directory", kind.as_str()));
          return;
        };
        // `$offset >= 8` is not enforced for sub-IFD `Start => '$val'`, but
        // an offset inside the TIFF header (< 8) or past EOF is degenerate;
        // `walk_one_ifd` bounds-checks and the reprocess guard handles a
        // self-pointer.
        // Sub-IFDs are NOT chained via a next-IFD pointer (`MaxSubdirs => 1`
        // for GPS/Interop, `Exif.pm:2138`; ExifIFD is a single IFD too) —
        // walk exactly one IFD, through THE shared sub-directory entry point.
        // The core descriptor (`Fixed(self.order)` + `No` + `Exif`) makes every
        // `process_subdir` pre-walk hook inert, so this is byte-identical to the
        // prior direct `walk_one_ifd(sub_offset, kind)` while routing GPS/
        // Interop/ExifIFD recursion through the same machinery a vendor maker
        // note will use — and it sets/restores `active_table` so the GPS table
        // does not leak into the parent IFD0's remaining entries.
        self.process_subdir(
          sub_offset,
          kind,
          table_for_ifd_kind(kind),
          ByteOrderRule::Fixed(self.order),
          FixBaseMode::No,
          ProcessProc::Exif,
        );
      }
      SubDirKind::MakerNote => {
        // **MakerNotes Phase 1: identify vendor + capture `SubDirectory`
        // directives; do NOT walk vendor IFDs (Phase 2-4).** Capture the
        // raw blob, dispatch it through [`makernotes::dispatch`] against
        // the IFD0-captured Make/Model, and store the outcome. Phase 2+
        // will consume the captured directives to walk the per-vendor table.
        //
        // `value_offset .. value_offset+read_len` is the MakerNote value
        // (bounds already checked by the caller). `saturating_add` keeps the
        // sum overflow-safe on a 32-bit target (per the #36 IFD-offset
        // hardening); an overflow clamps to EOF via `.min(data.len())`.
        let end = value_offset.saturating_add(read_len).min(self.data.len());
        if let Some(bytes) = self.data.get(value_offset..end) {
          // First MakerNote wins (a malformed TIFF with two 0x927c tags is
          // degenerate; ExifTool's `FoundTag` keeps the canonical name).
          if self.maker_note.is_none() {
            // `tiff_type` (`$$self{TIFF_TYPE}`, `ExifTool.pm:8715`
            // `$$self{TIFF_TYPE} = $fileType`) is read ONLY by
            // `MakerNoteSamsung2`'s SRW clause (`MakerNotes.pm:969`
            // `$$self{TIFF_TYPE} eq 'SRW'`). Thread the container's detected
            // file type so a Samsung `.srw` raw whose maker note LACKS the
            // EXIF-format magic header still dispatches to `MakerNoteSamsung2`
            // (#172). `self.file_type` is the finalized `$$self{FILE_TYPE}`
            // (`finalized_tiff_file_type`, the candidate `Parent` run through
            // `DoProcessTIFF`'s `$t` rule) — for an SRW candidate it equals
            // `"SRW"` exactly as `$$self{TIFF_TYPE}` does: `TIFF_TYPE` IS that
            // same `$fileType`/`Parent` (`ExifTool.pm:8715`/`:8730`), and SRW's
            // base module is `TIFF` (`fileTypeLookup{SRW} = ['TIFF', …]`,
            // `ExifTool.pm:536`), so `$t == $fileType == "SRW"` and the
            // finalized name stays `"SRW"`. The dispatcher reads `tiff_type`
            // ONLY in the Samsung2 arm, gated on `uc Make eq 'SAMSUNG'`, so
            // threading it changes dispatch for the SRW-Samsung case ALONE;
            // every other vendor/file-type path is byte-identical (additive —
            // it enables one previously-dead branch). The embedded-block
            // callers (`parse_exif_block`) still pass `file_type = None`, so a
            // JPEG/PNG-embedded Samsung body keeps relying on its magic clause.
            let detected = makernotes::dispatch(
              bytes,
              self.captured_make.as_deref(),
              self.captured_model.as_deref(),
              self.file_type.as_deref(),
            );
            // Phase 2: parse the Apple/Canon/Sony/Panasonic/Leica/DJI vendor
            // body here. P0 single-mode decode: the walker decodes the body
            // ONCE for PrintConv (-j) — yielding the typed slot + the cached
            // PrintConv emissions — and records the decode INPUTS needed to
            // re-derive the ValueConv (-n) emissions on demand (instead of
            // eagerly decoding the body a second time). The decode runs here so
            // out-of-line value offsets resolve against the parent TIFF block
            // (Canon/Sony/Panasonic), not the captured blob.
            let mut meta = makernotes::MakerNotesMeta::from_detected(detected);
            let mut cached_pc = std::vec::Vec::<makernotes::VendorEmission>::new();
            let mut value_conv_decode = MakerNoteValueConvDecode::None;
            // The family-1 group for the cached emissions. Defaults to the
            // dispatched vendor's `group1()`; the cross-table Leica10 arm
            // below overrides it to `"Panasonic"` (its tags ARE
            // `%Panasonic::Main` tags, so bundled emits them as `Panasonic:*`
            // even though the vendor is `Vendor::Leica`).
            let mut emission_group1 = detected.vendor().group1();
            match detected.vendor() {
              makernotes::Vendor::Apple => {
                // Apple: walk the Apple Main IFD in a FRESH, ISOLATED `Walker`
                // ([`apple_makernote_isolated`]) — NOT on `self` — then capture
                // its emissions into the cached-emission buffer exactly like the
                // other vendors (#243 phase 3, structural isolation, mirroring
                // Canon). The isolated walk builds its own `Walker` over the
                // captured `bytes` (base 0, the Apple Main IFD after the 14-byte
                // header), walks the IFD under `TableRef::Apple`, and DISCARDS its
                // `warnings` / `warn_count` / `active_ifd_offsets` — so a malformed
                // Apple entry cannot leak a core `ExifTool:Warning`, abort the
                // parent ExifIFD's warn-count, or be suppressed by the parent's
                // ancestor cycle guard. Apple's `Base => '$start - 14'`
                // (`MakerNotes.pm:43`) rebases out-of-line offsets to the start of
                // the BLOB, which `base: 0` over `data = bytes` reproduces exactly.
                //
                // `print_conv = true`: the eager single-mode decode yields the
                // cached PrintConv (`-j`) emissions AND the typed `MakerNotesApple`
                // slot. The `-n` (ValueConv) emissions are recomputed on demand via
                // `value_conv_decode` below, through the SAME isolated helper with
                // `print_conv = false` — so both modes share one walk path.
                // `self.captured_make` is the parent IFD0 `Make`: the isolated
                // walk's format-16 (`int64u`) carve-out gates on
                // `captured_make == Some("Apple")` (`Exif.pm:6464`
                // `$$et{Make} eq 'Apple'`), so a non-Apple container with an
                // Apple-signature blob rejects code 16 (R4).
                let (emissions, typed) =
                  apple_makernote_isolated(bytes, self.order, true, self.captured_make.as_deref());
                // `print_conv = true` always returns `Some(typed)`; the production
                // dispatch needs the typed surface.
                if let Some(typed) = typed {
                  meta.set_apple(typed);
                }
                cached_pc = emissions;
                value_conv_decode = MakerNoteValueConvDecode::Apple {
                  blob: bytes,
                  order: self.order,
                  // Retained so the `-n` recompute gates the format-16 carve-out
                  // identically (mirrors the `Canon` variant's `model`).
                  make: self.captured_make.as_deref().map(smol_str::SmolStr::new),
                };
              }
              makernotes::Vendor::Canon => {
                // Canon: walk the Canon Main IFD in a FRESH, ISOLATED `Walker`
                // ([`canon_makernote_isolated`]) — NOT on `self` — then capture
                // its emissions into the cached-emission buffer exactly like the
                // other vendors (#243 phase 2 step C, structural isolation). The
                // isolated walk builds its own `Walker` over `self.data` (base 0,
                // the Canon Main IFD at the MakerNote value offset), runs the
                // `%CameraSettings` DataMember pre-scan, walks the IFD under
                // `TableRef::Canon`, and DISCARDS its `warnings` / `warn_count` /
                // `active_ifd_offsets` / file-level RawConv-tap state — so a
                // malformed Canon entry cannot leak a core `ExifTool:Warning`,
                // abort the parent ExifIFD's warn-count, or suppress the walk via
                // the parent's ancestor cycle guard. Canon inherits the parent
                // order and (effectively) base — Canon's `%Main` has no
                // `IsOffset`/`SubIFD` tag, so out-of-line value offsets resolve
                // TIFF-relative against `self.data` regardless of base — exactly as
                // the retired `canon::parse_in_tiff` did.
                //
                // `print_conv = true`: the eager single-mode decode yields the
                // cached PrintConv (`-j`) emissions AND the typed `MakerNotesCanon`
                // slot. The `-n` (ValueConv) emissions are recomputed on demand via
                // `value_conv_decode` below, through the SAME isolated helper with
                // `print_conv = false` — so both modes share one walk path.
                let (emissions, typed) = canon_makernote_isolated(
                  self.data,
                  value_offset,
                  read_len,
                  self.order,
                  self.captured_model.as_deref(),
                  self.file_type.as_deref(),
                  true,
                );
                cached_pc = emissions;
                // `print_conv = true` always returns `Some(typed)`; the production
                // dispatch needs the typed surface.
                if let Some(typed) = typed {
                  meta.set_canon(typed);
                }
                // The `-n` (ValueConv) emissions are recomputed ON DEMAND by
                // re-driving the SAME isolated walk + capture with
                // `print_conv = false` ([`canon_recompute_value_conv`] →
                // [`canon_makernote_isolated`]) — the P0 single-mode-decode
                // contract every gated vendor holds.
                value_conv_decode = MakerNoteValueConvDecode::Canon {
                  data: self.data,
                  mn_offset: value_offset,
                  mn_len: read_len,
                  order: self.order,
                  model: self.captured_model.as_deref().map(smol_str::SmolStr::new),
                  file_type: self.file_type.as_deref().map(smol_str::SmolStr::new),
                };
              }
              // Sony: dispatcher gives us body_offset (12 for the
              // SONY DSC/CAM/MOBILE/VHAB/TF1 variants, 0 for headerless
              // Sony5). Both `Sony::Main` variants INHERIT the parent Base
              // (no `Base =>` override on MakerNoteSony / Sony5,
              // `MakerNotes.pm:1037-1041,1076-1080`), so out-of-line offsets
              // are TIFF-relative — parse with parent-TIFF context (no base
              // shift, unlike Panasonic3).
              //
              // The dispatcher collapses ALL seven Sony variants to
              // `Vendor::Sony`, and only `MakerNoteSony`/`Sony5` use
              // `%Sony::Main`. Sony2/Sony3 (`Olympus::Main`), Sony4
              // (`Sony::PIC`), SonyEricsson (`Sony::Ericsson`,
              // `Base => '$start - 8'`) and SonySRF (`Sony::SRF`) route
              // ELSEWHERE — running the Main walker on them is unfaithful (it
              // can decode a spurious tag on a coincidental tag-id collision).
              // The variant gate lives in `sony::parse_main_gated` (it applies
              // `routes_to_main`, mirroring `%Main` order): it runs the Main
              // parser ONLY for the two Main-routed variants and returns `None`
              // for the others, on which the Sony slot stays absent — blob
              // captured, vendor identified, Main parser intentionally not run
              // (deferred long-tail; their dedicated tables are unported — see
              // the sony mod docs). This is the SAME gated entry the public
              // `MakerNotesMeta::from_blob` constructor uses, so the gate
              // cannot be bypassed by a parallel code path.
              makernotes::Vendor::Sony => {
                let mn_offset = value_offset;
                let mn_len = read_len;
                let body_off = detected.body_offset() as usize;
                // The captured IFD0 `$$self{Make}`/`$$self{Model}` feed the
                // `routes_to_main` make-gate (headerless Sony5) and the
                // model-conditional 0x201c/0x201e/0x2020/0x2022 AF-tag
                // branches (Canon/Panasonic-style model threading).
                let make = self.captured_make.as_deref();
                let model = self.captured_model.as_deref();
                // Walk the Sony Main IFD in a FRESH, ISOLATED `Walker`
                // ([`sony_makernote_isolated`]) — NOT on `self` — then capture its
                // emissions into the cached-emission buffer (#243 phase 3,
                // structural isolation, mirroring Apple/Canon). The isolated walk
                // builds its own `Walker` over `self.data` (base 0, the Sony Main
                // IFD at `mn_offset + body_off`), walks under `TableRef::Sony`, and
                // DISCARDS its `warnings` / `warn_count` / `active_ifd_offsets` — so
                // a malformed Sony entry cannot leak a core `ExifTool:Warning`,
                // abort the parent ExifIFD's warn-count, or be suppressed by the
                // parent's ancestor cycle guard. The `routes_to_main` variant gate
                // runs INSIDE the helper (FIRST), returning `None` for the non-Main
                // variants — on which the Sony slot stays absent (blob captured,
                // vendor identified, Main parser intentionally not run; their
                // dedicated tables are unported). `print_conv = true` yields the
                // cached `-j` emissions + the typed `MakerNotesSony`; the `-n`
                // emissions are recomputed on demand via the SAME helper with
                // `print_conv = false`.
                if let Some((emi_pc, typed_pc)) = sony_makernote_isolated(
                  self.data, mn_offset, mn_len, body_off, self.order, make, model, true,
                ) {
                  meta.set_sony(typed_pc);
                  cached_pc = emi_pc;
                  value_conv_decode = MakerNoteValueConvDecode::Sony {
                    data: self.data,
                    mn_offset,
                    mn_len,
                    body_off,
                    order: self.order,
                    make: make.map(smol_str::SmolStr::new),
                    model: model.map(smol_str::SmolStr::new),
                  };
                }
              }
              // Panasonic has THREE dispatch variants (`MakerNotes.pm:
              // 732-761`), but only the two whose blob starts with
              // "Panasonic" use `%Panasonic::Main`:
              //   - `MakerNotePanasonic` (`:733`) — no `Base` ⇒ INHERIT the
              //     parent base (offsets TIFF-relative).
              //   - `MakerNotePanasonic3` (`:752`, DC-FT7) — `Base => 12`
              //     (`:758`) ⇒ out-of-line offsets shift +12 in buffer
              //     coordinates (`Exif.pm:7003`/`:7040`).
              // `MakerNotePanasonic2` (`:743`, "MKE") is a DIFFERENT structure
              // — `Panasonic::Type2` is a `ProcessBinaryData` table
              // (`Panasonic.pm:2259`), NOT an IFD over `%Panasonic::Main` — so
              // the Main parser must NOT run on it.
              //
              // Walk the Panasonic Main IFD in a FRESH, ISOLATED `Walker`
              // ([`panasonic_makernote_isolated`]) — NOT on `self` — then capture
              // its emissions into the cached-emission buffer (#243 phase 3,
              // structural isolation, mirroring Apple/Canon/Sony). The isolated
              // walk builds its own `Walker` over `self.data` (the Panasonic Main
              // IFD at `mn_offset + HEADER_LEN`), walks under
              // `TableRef::Panasonic`, and DISCARDS its `warnings` / `warn_count` /
              // `active_ifd_offsets` — so a malformed Panasonic entry cannot leak a
              // core `ExifTool:Warning`, abort the parent ExifIFD's warn-count, or
              // be suppressed by the parent's ancestor cycle guard. The
              // `routes_to_main` variant gate runs INSIDE the helper (FIRST),
              // returning `None` for the `MKE`/Type2 blob (Panasonic slot stays
              // absent — Type2 BinaryData is unported/deferred). The `base_rule`
              // distinguishes the inherit base (0) from DC-FT7's `Base => 12`
              // (`main_base_offset`); it is threaded into the Walker's
              // `value_offset_base` so a DC-FT7 out-of-line value resolves at `off +
              // 12` (a base-0 read would land 12 bytes early ⇒ corruption). This is
              // the SAME gated route the public `MakerNotesMeta::from_blob`
              // constructor uses, so the gate cannot be bypassed by a parallel code
              // path. `print_conv = true` yields the cached `-j` emissions + the
              // typed `MakerNotesPanasonic`; the `-n` emissions are recomputed on
              // demand via the SAME helper with `print_conv = false`.
              makernotes::Vendor::Panasonic => {
                let mn_offset = value_offset;
                let mn_len = read_len;
                let model = self.captured_model.as_deref();
                let base_rule = detected.base_rule();
                if let Some((emi_pc, typed_pc)) = panasonic_makernote_isolated(
                  self.data,
                  mn_offset,
                  mn_len,
                  makernotes::vendors::panasonic::main_base_offset(base_rule),
                  self.order,
                  model,
                  true,
                ) {
                  meta.set_panasonic(typed_pc);
                  cached_pc = emi_pc;
                  value_conv_decode = MakerNoteValueConvDecode::Panasonic {
                    data: self.data,
                    mn_offset,
                    mn_len,
                    order: self.order,
                    model: model.map(smol_str::SmolStr::new),
                    base_rule,
                  };
                }
              }
              // Leica — cross-vendor routing. The dispatcher collapses all
              // TEN Leica `MakerNotes.pm` variants (`:599-731`) to
              // `Vendor::Leica`, but TWO route to `%Panasonic::Main` (`:727`/
              // `:604`, the PANASONIC Main table):
              //   - `MakerNoteLeica` (Leica1, `:599-608`) — make-only
              //     `$$self{Make} eq "LEICA"` (`:602`), `Start =>
              //     '$valuePtr + 8'` (`:606`). Older Leica (Digilux / early
              //     D-Lux / V-Lux) that write a make-only `LEICA` MakerNote.
              //   - `MakerNoteLeica10` (`:724-730`, D-Lux7) — signature
              //     `$$valPt =~ /^LEICA CAMERA AG\0/` (`:725`), `Start =>
              //     '$valuePtr + 18'` (`:728`).
              // The other eight route to Leica-specific
              // `Panasonic::Leica2..Leica9` tables (`:615`/`:633`/`:643`/
              // `:659`/`:678`/`:696`/`:708`/`:718`), which are UNPORTED — so
              // the Main parser must NOT run on them (a `LEICA\0\0\0` blob
              // would coincidentally decode spurious Panasonic tags). The
              // variant gates live in `panasonic::parse_leica1_gated` (make
              // `== "LEICA"`) and `parse_leica10_gated` (`LEICA CAMERA AG\0`
              // signature); a body matching NEITHER leaves the Panasonic slot
              // absent — blob captured, vendor identified as Leica, Main
              // parser intentionally not run (deferred Leica-table long-tail).
              // Leica1 is tried FIRST, mirroring `%Main` order (Leica1 `:599`
              // precedes Leica10 `:724`): a make-`"LEICA"` body is claimed by
              // Leica1 (`Condition` has no blob term) regardless of its
              // signature. Bundled `exiftool -G1 -j` emits both routes' tags
              // as `Panasonic:*` (they ARE `%Panasonic::Main` tags), so the
              // emission group1 is overridden to `"Panasonic"`. The body
              // offset is the DISPATCHED `body_offset()` (8 for Leica1, 18 for
              // Leica10) — threaded, not hardcoded, the cross-vendor
              // generalization of the DC-FT7 base-threading. These are the
              // SAME gated entries the public `MakerNotesMeta::from_blob`
              // constructor uses, so the gates cannot be bypassed by a
              // parallel code path.
              makernotes::Vendor::Leica => {
                let mn_offset = value_offset;
                let mn_len = read_len;
                let body_off = detected.body_offset() as usize;
                let make = self.captured_make.as_deref();
                let model = self.captured_model.as_deref();
                // Leica1 FIRST (make-only `eq "LEICA"`, `%Main` order
                // `:599` < `:724`), then Leica10 (signature). The two are
                // mutually exclusive for real bodies (Leica1 make is exactly
                // "LEICA"; Leica10 bodies report "LEICA CAMERA AG"), and the
                // make-`"LEICA"` body the dispatcher gave `body_off = 8`
                // (Leica1 arm) never satisfies the Leica10 make either way.
                let leica1 = makernotes::vendors::panasonic::parse_leica1_gated(
                  self.data, mn_offset, mn_len, body_off, self.order, true, make, model,
                );
                // P0: capture which Leica route matched (Leica1 vs Leica10) so
                // the `-n` emissions are re-derived through the SAME gated
                // parser. The PrintConv decode determines the route; ValueConv
                // is deferred to that route's `recompute`.
                let parsed = match leica1 {
                  Some((typed_pc, emi_pc)) => Some((
                    typed_pc,
                    emi_pc,
                    MakerNoteValueConvDecode::Leica1 {
                      data: self.data,
                      mn_offset,
                      mn_len,
                      body_off,
                      order: self.order,
                      make: make.map(smol_str::SmolStr::new),
                      model: model.map(smol_str::SmolStr::new),
                    },
                  )),
                  None => makernotes::vendors::panasonic::parse_leica10_gated(
                    self.data, mn_offset, mn_len, body_off, self.order, true, model,
                  )
                  .map(|(typed_pc, emi_pc)| {
                    (
                      typed_pc,
                      emi_pc,
                      MakerNoteValueConvDecode::Leica10 {
                        data: self.data,
                        mn_offset,
                        mn_len,
                        body_off,
                        order: self.order,
                        model: model.map(smol_str::SmolStr::new),
                      },
                    )
                  }),
                };
                if let Some((typed_pc, emi_pc, vc_decode)) = parsed {
                  meta.set_panasonic(typed_pc);
                  cached_pc = emi_pc;
                  value_conv_decode = vc_decode;
                  // Both the Leica1 and Leica10 tags ARE `%Panasonic::Main`
                  // tags ⇒ bundled emits them under the `Panasonic` family-1
                  // group.
                  emission_group1 = makernotes::Vendor::Panasonic.group1();
                }
              }
              makernotes::Vendor::Dji => {
                // DJI: headerless body (Start => '$valuePtr',
                // MakerNotes.pm:104). DJI inherits the parent Base, so
                // out-of-line offsets in entries are TIFF-relative —
                // parse with parent-TIFF context.
                let mn_offset = value_offset;
                let mn_len = read_len;
                let (typed_pc, emi_pc) = makernotes::vendors::dji::parse_in_tiff(
                  self.data, mn_offset, mn_len, self.order, true,
                );
                meta.set_dji(typed_pc);
                cached_pc = emi_pc;
                value_conv_decode = MakerNoteValueConvDecode::Dji {
                  data: self.data,
                  mn_offset,
                  mn_len,
                  order: self.order,
                };
              }
              makernotes::Vendor::Nikon => {
                // Nikon has THREE layouts with DIFFERENT base semantics:
                //   - type-3 (`Nikon\0\x02…`, `MakerNotes.pm:51-58`) carries a
                //     SELF-CONTAINED embedded TIFF (`Base => '$start - 8'`
                //     rebases its out-of-line offsets to blob offset 10), so it
                //     decodes from the captured BLOB alone.
                //   - type-2 (`Nikon\0\x01`, `MakerNotes.pm:539-545`) and
                //     headerless Nikon3 (`MakerNotes.pm:546-554`) have NO `Base`
                //     override ⇒ their out-of-line value offsets are
                //     PARENT-TIFF-relative — they must resolve against the
                //     parent TIFF block, NOT the captured blob.
                // Walk the Nikon Main/Type2 IFD in a FRESH, ISOLATED `Walker`
                // ([`nikon_makernote_isolated`]) — NOT on `self` — then capture its
                // emissions into the cached-emission buffer (#243 phase 3-bis,
                // structural isolation, mirroring Sony/Panasonic). The isolated
                // helper resolves the layout (`resolve_layout`) and walks the blob
                // (type-3) or the parent TIFF (type-2/Nikon3) under
                // `TableRef::Nikon`/`NikonType2`, runs the decrypt-key prescan
                // (Option A), and DISCARDS its `warnings` / `warn_count` /
                // `active_ifd_offsets` / `chain_guard`. The byte order is read from
                // the embedded marker (type-3) / explicit LE (type-2) / inherited
                // (Nikon3), so `self.order` is only the Nikon3 fallback. `model`
                // threads `$$self{Model}` for the AFInfo BigEndian gate
                // (`$$self{Model} =~ /^NIKON D/i`, `Nikon.pm:2115`) + the LensData Z
                // telemetry. `nikon::parse_in_tiff` is RETAINED as the differential
                // oracle + the `from_blob` backing + the 146 unit tests.
                //
                // `print_conv = true` yields the cached `-j` emissions + the typed
                // `MakerNotesNikon`; the `-n` emissions are recomputed on demand via
                // the SAME helper with `print_conv = false`. A dispatcher-classified
                // Nikon blob always resolves a layout, so the typed slot is set
                // whenever the helper returns `Some`; the `None` arm (a degenerate
                // too-short blob) leaves the Nikon slot absent, matching
                // `parse_in_tiff`'s empty return.
                let mn_offset = value_offset;
                let mn_len = read_len;
                let model = self.captured_model.as_deref();
                if let Some((emi_pc, typed_pc)) =
                  nikon_makernote_isolated(self.data, mn_offset, mn_len, self.order, model, true)
                {
                  meta.set_nikon(typed_pc);
                  cached_pc = emi_pc;
                  value_conv_decode = MakerNoteValueConvDecode::Nikon {
                    data: self.data,
                    mn_offset,
                    mn_len,
                    order: self.order,
                    model: model.map(smol_str::SmolStr::new),
                  };
                }
              }
              _ => {}
            }
            self.maker_note = Some(MakerNote {
              bytes,
              meta,
              cached_emissions_print_conv: cached_pc,
              value_conv_decode,
              emission_group1,
            });
          }
        }
      }
    }
  }

  /// Emit one decoded leaf tag — the faithful equivalent of `FoundTag`
  /// (`Exif.pm:7181`) + `SetGroup($tagKey, $dirName)` (`Exif.pm:7184`).
  ///
  /// The tag NAME is resolved against the [`tables`] (Exif IFDs) or [`gps`]
  /// (GPS IFD) table. An UNKNOWN tag ID is dropped — faithful to
  /// `Exif.pm:6757` `next unless $verbose` (an unknown tag surfaces only in
  /// verbose mode; the default `-j` output omits it). Documented
  /// incremental-completion item in `docs/tracking.md`.
  fn emit(
    &mut self,
    kind: IfdKind,
    tag_id: u16,
    on_disk_format: Format,
    value_offset: usize,
    value_size: usize,
    raw: RawValue,
  ) {
    // PR #68 — `SubfileType` (0x00fe) / `OldSubfileType` (0x00ff) `RawConv`
    // taps (`Exif.pm:452-461` / `:469-475`). Bundled increments
    // `$$self{PageCount}` and sets `$$self{MultiPage}` BEFORE the tag value
    // reaches `FoundTag` — and the `RawConv` side effect runs even when the
    // tag is itself absent from the port's leaf table (an unknown-tag
    // `next` drops only the emit, not the table-level RawConv tracking
    // ExifTool keeps in `$$self{*}`). `OldSubfileType` is NOT in the
    // [`tables`] EXIF table (a deferred-table item), so its tracking MUST
    // run before the unknown-tag `return` below; for symmetry the
    // `SubfileType` tap also runs here (the order with respect to the leaf
    // emission is irrelevant — they touch disjoint state). Embedded-block
    // walks track the counter too, but `parse_tiff_with_base` only surfaces
    // it as `multi_page_count` when `tiff_type_is_tiff == true` (the
    // `TIFF_TYPE == 'TIFF'` gate at `ExifTool.pm:8757`), so this tracking
    // is safe to always run.
    //
    // The `SubfileType` table uses `int32u` / `int16u` (LONG/SHORT), so the
    // decoded value is the first element of an `RawValue::U64`. Read it via
    // `first_uint` and ignore non-integer shapes (a malformed encoding
    // matches bundled's silent `next` on the `Format::None` arm).
    //
    // TABLE-SCOPED to the CORE Exif/Interop directories (like the `DNGVersion`
    // tap below): `SubfileType`/`OldSubfileType`'s RawConvs live in `%Exif::Main`
    // (Exif.pm:452/469), which the walker applies to every IFD resolved against
    // it (IFD0 / ExifIFD / SubIFD / trailing / Interop — `active_table ∈ {Exif,
    // Interop}`). The GPS IFD (`%GPS::Main`) and a VENDOR maker-note directory
    // (`%Canon::Main` via `process_subdir(.., TableRef::Canon, ..)`, #243 phase 2
    // step C) have NO 0x00fe/0x00ff RawConv, so an unknown Canon/GPS tag whose ID
    // collides with these must NOT bump `page_count`/`multi_page` — on a
    // standalone TIFF that file-level state finalizes the synthesized
    // `File:PageCount` (`ExifTool.pm:8756-8757`), so a vendor-table leak could
    // emit a bogus PageCount or wrongly flip `multi_page`. `parse_in_tiff` (the
    // Canon oracle) has no such file-level side effect. Byte-identical for a
    // normal TIFF (where `active_table == table_for_ifd_kind(kind)` for every
    // core IFD that carries these tags).
    if matches!(self.active_table, TableRef::Exif | TableRef::Interop) {
      if tag_id == tables::TAG_SUBFILE_TYPE
        && let Some(v) = first_uint(&raw)
      {
        // `$val == ($val & 0x02)` ⇔ `$val ∈ {0, 2}` (per Exif.pm:453).
        if v == (v & 0x02) {
          self.page_count = self.page_count.saturating_add(1);
          if v == 2 || self.page_count > 1 {
            self.multi_page = true;
          }
        }
      } else if tag_id == tables::TAG_OLD_SUBFILE_TYPE
        && let Some(v) = first_uint(&raw)
      {
        // `$val == 1 or $val == 3` (per Exif.pm:470).
        if v == 1 || v == 3 {
          self.page_count = self.page_count.saturating_add(1);
          if v == 3 || self.page_count > 1 {
            self.multi_page = true;
          }
        }
      }
    }

    // `DNGVersion` (0xc612) `RawConv` DataMember tap (`Exif.pm:3365`
    // `$$self{DNGVersion} = $val`). Like `OldSubfileType`, the tag is absent
    // from the port's leaf table, so the side effect MUST run before the
    // unknown-tag `return` below. `DoProcessTIFF` (`ExifTool.pm:8763`) reads
    // `$$self{DNGVersion}` to override `File:FileType` to `DNG`. The DataMember
    // stores the RawConv'd `$val`, and the override gate is `if
    // ($$self{DNGVersion} and …)` (`ExifTool.pm:8763`) — PERL TRUTHINESS of that
    // value, NOT mere tag presence. So the flag must reflect the decoded value's
    // truthiness: an `int8u[4]` `1 1 0 0`/`0 0 0 0` is truthy → DNG, but a
    // count-0 (empty `$val == ''`) or scalar-`0` (`$val == '0'`) DNGVersion is
    // falsy → the file stays a plain TIFF (oracle-confirmed on ExifTool 13.59:
    // empty/`0` → `FileType TIFF` + `PageCount`; `0 0 0 0` → `DNG`). The OUTER
    // override is still gated separately on `$$self{FILE_TYPE} eq 'TIFF'`.
    //
    // ASSIGNMENT, NOT A LATCH: the RawConv `$$self{DNGVersion} = $val` runs each
    // time the tag is handled, so the DataMember holds the LAST-handled value;
    // `DoProcessTIFF` tests that final stored value. Mirror that — ASSIGN the
    // truthiness on every occurrence (so a later falsy duplicate, e.g. a
    // count-0/scalar-`0` 0xc612 after a truthy `1 1 0 0`, OVERWRITES the earlier
    // truthy and the file stays a plain TIFF; the reverse leaves DNG). A sticky
    // `set-true-only` latch would wrongly keep the earlier truthy.
    //
    // TABLE-SCOPED to the CORE Exif/Interop directories: DNGVersion's RawConv
    // lives in `%Exif::Main` (Exif.pm:3353), which the walker applies in the
    // IFD0 / ExifIFD / SubIFD / trailing-IFD / InteropIFD directories — every IFD
    // walked against the Exif main [`tables`] table (`active_table ∈ {Exif,
    // Interop}`). The GPS IFD ([`IfdKind::Gps`]) is walked against `%GPS::Main`
    // instead (the same split that routes the leaf lookup below to `gps::lookup`)
    // and a VENDOR maker-note directory against `%Canon::Main` (#243 phase 2 step
    // C) — NEITHER has a 0xc612 entry, so an unknown GPS / Canon tag whose ID
    // collides with DNGVersion must NOT touch the DataMember. `DoProcessTIFF`
    // (`ExifTool.pm:8763`) reads `$$self{DNGVersion}` to finalize a standalone
    // TIFF as `DNG`, so a vendor-table leak could wrongly re-type the file. Gate
    // on the ACTIVE TABLE being a core one (`Exif | Interop`), NOT `!= Gps`
    // (which would still fire under `%Canon::Main`) and NOT `kind` (`%GPS::Main`
    // is selected by `active_table == Gps`, which holds for the GPS IFD AND for
    // every IFD of a GPS-only chain — `parse_gps_block`, where the trailing dirs
    // are `kind = Trailing` but still walk `%GPS::Main`). Byte-identical for a
    // normal TIFF, where `active_table == table_for_ifd_kind(kind)`.
    if tag_id == tables::TAG_DNG_VERSION
      && matches!(self.active_table, TableRef::Exif | TableRef::Interop)
    {
      self.dng_version = raw.is_perl_truthy();
    }

    // `#### eval IsOffset ($val, $et) … $val += $offsetBase` (Exif.pm:7156-
    // 7170): convert an `IsOffset` tag's value(s) to ABSOLUTE file offsets by
    // adding `$base + $$et{BASE}`. `$$et{BASE}` is 0 for the top-level Exif
    // walk, so `offsetBase = self.base`. The two `IsOffset => 1` tags the port
    // decodes are `StripOffsets` (0x0111) and `ThumbnailOffset` (0x0201), both
    // `%Exif::Main` attributes (Exif.pm:608/1169). When `base == 0` (standalone
    // TIFF) this is a no-op, so the existing TIFF goldens are unaffected; for a
    // JPEG `APP1` block `base` is the TIFF block's file offset, matching
    // bundled's absolute `ThumbnailOffset`.
    //
    // CORE-TABLE-SCOPED (`Exif | Interop`): `IsOffset` is a `%Exif::Main` tag
    // attribute, so the base-add applies ONLY to a leaf resolved against the Exif
    // table. GPS (`%GPS::Main`) has no `IsOffset` tags, and a VENDOR maker-note
    // walk (`%Canon::Main`, #243 phase 2 step C) carries its OWN offset handling
    // — a Canon leaf must not be rebased by the core walk's `$base`. The Canon
    // production walk runs with `base != 0` (the JPEG `APP1` TIFF offset), so a
    // `!= Gps` gate would WRONGLY add the base to any Canon tag whose ID collides
    // with 0x0111/0x0201, mutating its emitted value (the oracle `parse_in_tiff`
    // applies no such rebase). Gating on the core tables (NOT `!= Gps`, NOT
    // `kind`) keeps this off both GPS-only chains (`kind = Trailing`,
    // `active_table = Gps`) and vendor walks; byte-identical for a normal TIFF
    // (where the IsOffset-bearing IFDs resolve against `Exif`/`Interop`).
    let raw = if self.base != 0
      && matches!(self.active_table, TableRef::Exif | TableRef::Interop)
      && is_offset_tag(tag_id)
    {
      add_offset_base(raw, self.base)
    } else {
      raw
    };
    // Leaf name + conversions come from the ACTIVE table (`$tagTablePtr`,
    // `Exif.pm:6464`). `Interop` and the Phase-1-unreachable vendor arms share
    // `%Exif::Main` (`Exif.pm:6939` — InteropOffset has no own table); only the
    // GPS IFD resolves against `%GPS::Main`.
    let (name, conv): (&'static str, ResolvedConv) = match self.active_table {
      TableRef::Gps => {
        #[cfg(feature = "gps")]
        {
          match gps::lookup(tag_id) {
            Some(t) => (t.name, ResolvedConv::Gps(t)),
            None => return, // unknown GPS tag — verbose-only, omit.
          }
        }
        // GPS IFD reached but the `gps` feature is OFF: faithful to ExifTool
        // "module not loaded ⇒ tags not decoded". The GPS IFD's leaf tags are
        // simply not emitted (the IFD walker still descended into it via the
        // 0x8825 dispatch, which is harmless). `docs/tracking.md`.
        #[cfg(not(feature = "gps"))]
        {
          return;
        }
      }
      // `%Canon::Main` — Step A of the Canon engine migration (#243 phase 2). The
      // resolved [`CanonTag`] rides in `ResolvedConv::Canon` so the emit reapplies
      // its `CanonPrintConv` exactly as `parse_in_tiff` does at collection time
      // (`canon/mod.rs:1018`). An unknown Canon tag is skipped here, matching
      // `parse_in_tiff`'s `tags::lookup(...).is_none()` `continue`.
      TableRef::Canon => match makernotes::vendors::canon::tags::lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Canon(t)),
        None => return,
      },
      // `%Apple::Main` — phase 3 of the engine migration (#243). The resolved
      // [`AppleTag`] rides in `ResolvedConv::Apple` so the emit reapplies its
      // `ApplePrintConv` exactly as `parse_with_print_conv` does at collection time
      // (`apple/mod.rs`). An unknown Apple tag is skipped here, matching
      // `parse_with_print_conv`'s `tags::lookup(...).is_none()` `continue`.
      TableRef::Apple => match makernotes::vendors::apple::tags::lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Apple(t)),
        None => return,
      },
      // `%Sony::Main` — phase 3 of the engine migration (#243). The resolved
      // [`SonyTag`] rides in `ResolvedConv::Sony` so the emit ([`emit_sony_value`])
      // reapplies its `SonyPrintConv` + per-entry suppression gates exactly as
      // `parse_in_tiff` does at collection time (`sony/mod.rs`). An unknown Sony tag
      // is skipped here, matching `parse_in_tiff`'s `tags::lookup(...).is_none()`
      // `continue`.
      TableRef::Sony => match makernotes::vendors::sony::tags::lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Sony(t)),
        None => return,
      },
      // `%Panasonic::Main` — phase 3 of the engine migration (#243). The resolved
      // [`PanasonicTag`] rides in `ResolvedConv::Panasonic` so the emit
      // ([`emit_panasonic_value`]) reapplies its `PanasonicPrintConv` + per-entry
      // suppression gates exactly as `parse_in_tiff` does at collection time
      // (`panasonic/mod.rs`). An unknown Panasonic tag is skipped here, matching
      // `parse_in_tiff`'s `tags::lookup(...).is_none()` `continue`.
      TableRef::Panasonic => match makernotes::vendors::panasonic::tags::lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Panasonic(t)),
        None => return,
      },
      // `%Nikon::Main` / `%Nikon::Type2` — phase 3-bis of the engine migration
      // (#243). The resolved [`NikonTag`] rides in `ResolvedConv::Nikon` so the
      // emit ([`emit_nikon_value`]) reapplies its `NikonConv` exactly as
      // `parse_in_tiff` does at collection time (`nikon/mod.rs:410-432`). The name
      // + conv resolve against the ACTIVE table's own slice (Main vs Type2 — the
      // two REUSE 0x0003..0x000b for different tags). An unknown Nikon tag is
      // skipped here, matching `parse_in_tiff`'s `layout.table.lookup(...).is_none()`
      // `continue` (`nikon/mod.rs:364`).
      TableRef::Nikon => match makernotes::vendors::nikon::NikonTable::Main.lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Nikon(t)),
        None => return,
      },
      TableRef::NikonType2 => match makernotes::vendors::nikon::NikonTable::Type2.lookup(tag_id) {
        Some(t) => (t.name(), ResolvedConv::Nikon(t)),
        None => return,
      },
      _ => match tables::lookup(tag_id) {
        Some(t) => (t.name, ResolvedConv::Exif(t)),
        None => return, // unknown Exif tag — verbose-only, omit.
      },
    };

    // Capture `Make` (0x010f) and `Model` (0x0110) — both are IFD0 string
    // tags (`Exif.pm:585`/`:599`) needed by the MakerNotes dispatcher
    // (`MakerNotes.pm`'s `$$self{Make}` / `$$self{Model}` conditions).
    // Bundled trims trailing whitespace via `RawConv => '$val =~ s/\s+$//'`
    // (Exif.pm:585/599 — `Conv::TrimTrailingWhitespace`); apply the same
    // trim here so the dispatcher sees the trimmed value, faithful to
    // bundled's view of `$$self{Make}` (which is the RawConv'd value).
    //
    // LAST-WINS: bundled's `RawConv` ends `… $$self{Make} = $val` (Exif.pm:585)
    // / `… $$self{Model} = $val` (Exif.pm:599) — the assignment runs EACH time
    // a Make/Model tag is handled, so a duplicate IFD0 Make/Model leaves the
    // LATER value in object state. A hostile IFD0 carrying two `0x0110` Model
    // tags (or two `0x8769` blocks each setting one — the CTMD ProcessExifInfo
    // hand-off) must end with the LAST-seen value, because a following
    // model-conditional MakerNote (`0x927c` → `Canon::Main`, or the dispatcher's
    // `$$self{Model}` carve-outs) keys on it. Overwrite unconditionally — NOT
    // first-wins (the `is_none()` guard this replaces was the R6 bug). This is a
    // separate captured-STATE field; the EMITTED `Make`/`Model` tags
    // (`self.entries`, pushed below) keep their own TagMap last-wins dedup, so
    // this does not disturb emitted-tag priority.
    //
    // `kind.is_ifd0()` gate: bundled stores `$$self{Make}` only from the
    // top-level Exif walk (IFD0); a trailing-IFD or maker-note re-emission
    // of 0x010f is NOT what the dispatcher sees. The walker keeps IFD0's
    // Make alone.
    if matches!(kind, IfdKind::Ifd0) && (tag_id == 0x010f || tag_id == 0x0110) {
      if let RawValue::Text { text: s, .. } = &raw {
        let trimmed = s.trim_end_matches(is_perl_space);
        if tag_id == 0x010f {
          self.captured_make = Some(trimmed.to_string());
        } else if tag_id == 0x0110 {
          self.captured_model = Some(trimmed.to_string());
        }
      }
    }

    self.entries.push(ExifEntry {
      ifd: kind,
      tag_id,
      name,
      value: ExifValue::new(raw),
      on_disk_format,
      value_offset,
      value_size,
      conv,
    });
  }
}

/// The large-array placeholder value — `"(large array of $count $formatStr
/// values)"` (`Exif.pm:6777`). `$formatStr` is ExifTool's format NAME (e.g.
/// `int32u`), supplied by [`Format::name`]. This is the literal string
/// ExifTool stores in place of decoding a `count > 500` array for a tag that
/// would otherwise take the large-array path (guard (b) in `walk_entry`).
fn large_array_placeholder(count: usize, format: Format) -> std::string::String {
  std::format!("(large array of {count} {} values)", format.name())
}

/// `true` for an Exif `IsOffset => 1` value tag whose decoded value is a file
/// offset that ExifTool rebases by `$base + $$et{BASE}` (`Exif.pm:7156-7170`).
///
/// The port's leaf-tag table carries exactly two such tags: `StripOffsets`
/// (0x0111) and `ThumbnailOffset` (0x0201) — both `IsOffset => 1` in
/// `%Exif::Main` (`Exif.pm:608`/`:1169`). The other `IsOffset` tags in
/// `Exif.pm` (TileOffsets, PreviewImageStart, JpgFromRawStart, …) are not in
/// the port's table yet, so they need no handling here; when they are added,
/// extend this predicate. GPS has no `IsOffset` tags, so the caller already
/// excludes the GPS IFD.
#[inline]
const fn is_offset_tag(tag_id: u16) -> bool {
  matches!(tag_id, 0x0111 | 0x0201)
}

/// Add the offset base to each integer of an `IsOffset` tag's value
/// (`foreach $val (@vals) { $val += $offsetBase }`, `Exif.pm:7166-7169`).
///
/// ExifTool splits the (string) value on spaces and adds `$offsetBase` to each
/// element, so a multi-strip `StripOffsets` gets every offset rebased. The port
/// holds the decoded integers directly; rebase each. `StripOffsets` /
/// `ThumbnailOffset` decode as `U64` (`int32u`/`int16u`); a degenerate signed
/// encoding (`I64`) is rebased too for parity with Perl's numeric `+`. Other
/// shapes are returned unchanged (an `IsOffset` tag is always integer-typed in
/// practice).
fn add_offset_base(raw: RawValue, base: u32) -> RawValue {
  let base = u64::from(base);
  match raw {
    RawValue::U64(v) => RawValue::U64(v.into_iter().map(|n| n.wrapping_add(base)).collect()),
    RawValue::I64(v) => RawValue::I64(v.into_iter().map(|n| n.wrapping_add(base as i64)).collect()),
    other => other,
  }
}

/// Resolve a SubDirectory pointer tag — the IFD-chain seam. Returns the
/// [`SubDirKind`] for a pointer tag in the given IFD, `None` for a leaf tag.
///
/// Faithful to ExifTool's tag-table dispatch: `ExifOffset`/`GPSInfo` are in
/// `%Exif::Main` (so reachable from IFD0 and ExifIFD alike — but in practice
/// IFD0 only); `InteropOffset`/`MakerNote` are ExifIFD tags.
fn sub_dir_for(tag_id: u16, kind: IfdKind) -> Option<SubDirKind> {
  // The GPS IFD's own tag table (`%GPS::Main`) has NO SubDirectory pointer
  // tags — a tag ID inside the GPS IFD is always a leaf.
  if kind.is_gps() {
    return None;
  }
  match tag_id {
    tables::TAG_EXIF_IFD => Some(SubDirKind::ExifIfd),
    tables::TAG_GPS_IFD => Some(SubDirKind::Gps),
    tables::TAG_INTEROP_IFD => Some(SubDirKind::Interop),
    tables::TAG_MAKER_NOTE => Some(SubDirKind::MakerNote),
    _ => None,
  }
}

// ====================================================================// `Taggable` — the golden-pattern emission path (EXIF entries + MakerNotes)
//
// EXIF no longer has an inherent `serialize_tags`: the full EXIF tag stream
// (`File:ExifByteOrder` first, then the IFD-walk entries, then the MakerNote
// vendor emissions) flows through the generic `Taggable`/`run_emission` engine,
// single-sourced by `AnyMeta::serialize_tags` / `AnyMeta::iter_tags`. The
// `$et->Warn(...)` channel flows through the sibling `Diagnose`/`run_diagnostics`
// engine (`ExifMeta::diagnostics`).
// ====================================================================
#[cfg(feature = "alloc")]
impl ExifMeta<'_> {
  /// Push this `ExifMeta`'s EXIF/GPS [`ExifEntry`] tags into `out` for the
  /// requested [`ConvMode`](crate::emit::ConvMode) — the golden-pattern parallel
  /// to the `emit_entry` loop in [`serialize_tags`](Self::serialize_tags).
  ///
  /// Each entry is converted by the SAME `emit_entry`/`emit_exif_value`/
  /// `emit_gps_value` logic the production path uses, but written into an
  /// [`EmittedTagSink`] (which produces the identical [`TagValue`]) instead of
  /// the [`TagMap`](crate::tagmap::TagMap). The pushed tags carry
  /// `Group{family0:"EXIF", family1:<IfdName>}`, `unknown:false`.
  ///
  /// Writes DIRECTLY into the caller's `out` buffer (P2 — no per-call temp `Vec`
  /// that [`tags`](crate::emit::Taggable::tags) then has to move). **EXIF
  /// entries only**: the `File:ExifByteOrder`/`File:PageCount` prefix + the
  /// MakerNote vendor emissions are pushed by [`tags`](crate::emit::Taggable::tags)
  /// into the SAME `out`; the `ExifTool:Warning` messages stay a separate channel
  /// yielded by [`ExifMeta::diagnostics`](crate::diagnostics::Diagnose::diagnostics).
  fn push_exif_tags(&self, print_conv: bool, out: &mut std::vec::Vec<crate::emit::EmittedTag>) {
    out.reserve(self.entries.len());
    let mut sink = EmittedTagSink::new(out);
    // The byte order threaded to `emit_entry` for `ConvertExifText`'s UTF-16
    // 'Unknown' guess — identical to `serialize_tags`'s `entry_order`. `None`
    // only for a JPEG accepted without a parsed Exif block, which then has NO
    // entries, so the fallback is unreachable-by-construction (same as
    // `serialize_tags`).
    let entry_order = self.byte_order.unwrap_or(ByteOrder::Little);
    // `self.entries` carries ONLY core Exif/GPS leaves — the Canon MakerNote
    // leaves the shared `Walker` decoded are CAPTURED into the `MakerNote`'s
    // cached emissions and TRUNCATED off `self.entries` at dispatch time (#243
    // phase 2 step C), so no `ResolvedConv::Canon` entry reaches this loop. The
    // core Exif/GPS arms ignore `model`/`file_type`/the Canon DataMembers, so
    // pass the inert `None`s.
    let model = None;
    let file_type = None;
    let (canon_focal_units, canon_lens_type) = (None, None);
    let canon_focal_length_blob: Option<&[u8]> = None;
    for entry in &self.entries {
      // `emit_entry` into the `EmittedTagSink` is infallible (`Infallible`).
      let Ok(()) = emit_entry(
        entry,
        entry_order,
        print_conv,
        model,
        file_type,
        canon_focal_units,
        canon_lens_type,
        canon_focal_length_blob,
        &mut sink,
      );
    }
  }

  /// Append the captured MakerNote's cached vendor emissions to `out` as
  /// [`EmittedTag`](crate::emit::EmittedTag)s — the golden-pattern parallel to
  /// the MakerNote branch of [`serialize_tags`](Self::serialize_tags). Emitted
  /// AFTER the EXIF/IFD leaves ([`push_exif_tags`]), faithful to ExifTool
  /// emitting the MakerNote stream after the parent IFD.
  ///
  /// Each [`VendorEmission`](makernotes::VendorEmission) becomes an `EmittedTag`
  /// under `Group{family0:"MakerNotes", family1:<vendor group1>}`
  /// (`Apple`/`Canon`/`Sony`/`Panasonic`/… —
  /// [`Vendor::group1`](makernotes::Vendor::group1)), carrying the emission's own
  /// `Unknown => 1` flag. The flag is NOT filtered here: the engine
  /// ([`run_emission`](crate::emit::run_emission)) drops the Unknown ones once.
  /// `-j` reads the eagerly-cached PrintConv emissions (borrowed); `-n` decodes
  /// the vendor body ONCE on demand (P0 — owned `Vec`). Canon's emissions are
  /// CAPTURED at dispatch time the same way (PrintConv eager, ValueConv on
  /// demand via [`MakerNoteValueConvDecode::Canon`]), so it flows through this
  /// shared cached-emission push exactly like the other vendors (#243 phase 2
  /// step C).
  fn push_maker_note_tags(
    &self,
    print_conv: bool,
    out: &mut std::vec::Vec<crate::emit::EmittedTag>,
  ) {
    let Some(mn) = &self.maker_note else { return };
    // The emission FAMILY-1 group (`Apple`/`Canon`/`Sony`/`Panasonic`, and
    // `Panasonic` for the cross-table Leica10 route); other vendors fall back
    // to `"MakerNotes"` and emit nothing here yet (empty cached emissions).
    let group1 = mn.emission_group1();
    // `-j` reads the eagerly-cached PrintConv emissions (borrowed); `-n` decodes
    // the vendor body ONCE on demand (P0 — owned `Vec`). A shared push folds
    // either slice into `out`.
    let push = |out: &mut std::vec::Vec<crate::emit::EmittedTag>,
                emissions: &[makernotes::VendorEmission]| {
      out.reserve(emissions.len());
      for e in emissions {
        out.push(crate::emit::EmittedTag::new(
          crate::value::Group::new("MakerNotes", group1),
          smol_str::SmolStr::new(e.name()),
          e.value().clone(),
          e.unknown(),
        ));
      }
    };
    if print_conv {
      push(out, mn.emissions_print_conv());
    } else {
      push(out, &mn.emissions_value_conv());
    }
  }

  /// `true` iff this `ExifMeta` would emit AT LEAST ONE default-visible tag in a
  /// family-0 group OTHER than `File` — a MOVABLE tag whose position in
  /// ExifTool's `FoundTag` stream participates in cross-segment ordering.
  ///
  /// This is the anchor predicate that fixes the EXIF block's marker position
  /// ([`exif_block_pos`](Self::exif_block_pos)) in the JPEG position-ordered
  /// block model — the position a positioned [`JpegAuxBlock`] (a GoPro `APP6`
  /// block today) interleaves against ([`attach_app6_gopro`](crate::exif::jpeg)):
  /// the EFFECTIVE EXIF block is the first `APP1` for which this returns `true`.
  /// ExifTool emits the `File`-group tags (`File:ExifByteOrder`,
  /// `File:PageCount`, ...) as an UNCONDITIONAL prefix ahead of every segment's
  /// content, so they never order against a `GoPro:*` block and MUST NOT count;
  /// the first non-`File` tag is ExifTool's first movable EXIF key, the thing a
  /// leading/trailing `APP6` is positioned relative to.
  ///
  /// ## Single source: this IS the `tags()` stream
  ///
  /// The predicate is computed by EMITTING this `ExifMeta`'s
  /// [`tags`](crate::emit::Taggable::tags) (the same source the `-G1` `-j` JSON
  /// path drives — [`EmitOptions::g1`]`(PrintConv, false)`) and asking whether
  /// any yielded tag is default-visible (NON-`Unknown`) in a family-0 group
  /// OTHER than `File`. There is no hand-maintained channel list: WHATEVER
  /// `tags` emits is what this sees, so a future default-visible non-`File`
  /// channel added to `tags` is covered automatically. This is the fix for the
  /// channel-by-channel drift that bit the earlier per-channel guesses — they
  /// missed `entries` (R8), then the MakerNote (R9); deriving from the real
  /// stream closes that loop for good.
  ///
  /// The `File` exclusion is faithful to ExifTool: it emits the `File`-group
  /// tags (`File:ExifByteOrder`, `File:PageCount`, …) as an UNCONDITIONAL prefix
  /// ahead of every segment's content, so they never order against a `GoPro:*`
  /// block. The `Unknown` exclusion mirrors [`run_emission`](crate::emit::run_emission),
  /// which drops `Unknown=>1` tags from `-j` output: a MakerNote that decodes to
  /// ONLY `Unknown` vendor leaves is NOT default-visible and must NOT anchor
  /// (ExifTool's first movable EXIF key then comes from a later segment).
  ///
  /// The movable-vs-`File` classification is MODE-INVARIANT — PrintConv vs
  /// ValueConv changes only the rendered VALUE, never a tag's group or its
  /// `Unknown` flag — so this single PrintConv pass answers the question for
  /// both `-j` and `-n`.
  ///
  /// ## Cost / where it runs
  ///
  /// The call is read-only and side-effect-free, but it materializes the full
  /// `tags` `Vec` (rendering values and cloning the MakerNote emissions — the
  /// price of being single-source). To keep that off the parse hot path, the
  /// SOLE caller (the JPEG `APP1` parse loop, first-wins) invokes it ONLY when
  /// the JPEG carries a GoPro `APP6` block (the anchor's only consumer) AND only
  /// until the first movable `APP1` is found — so a non-GoPro JPEG never pays
  /// it. The Golden-v2 C4 `alloc_budget` fixtures (none are GoPro JPEGs)
  /// therefore see no change.
  #[cfg(feature = "quicktime")]
  pub(crate) fn emits_movable_tag(&self) -> bool {
    use crate::emit::Taggable;
    self
      .tags(crate::emit::EmitOptions::g1(
        crate::emit::ConvMode::PrintConv,
        false,
      ))
      .any(|t| !t.unknown() && t.tag().group_ref().family0() != "File")
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for ExifMeta<'_> {
  /// Yield this `ExifMeta`'s EXIF/GPS tags then its MakerNote vendor tags as
  /// [`EmittedTag`](crate::emit::EmittedTag)s for `mode` — the golden-pattern
  /// emission path.
  ///
  /// Emission order (faithful to ExifTool's `FoundTag` call sequence):
  ///
  /// 1. `File:ExifByteOrder` — `FoundTag`'d FIRST inside `DoProcessTIFF`
  ///    (`ExifTool.pm:8691`), BEFORE the IFD walk. Emitted ONLY when a TIFF
  ///    block was processed ([`byte_order`](Self::byte_order) is `Some`): a
  ///    JPEG container accepted without a parsed `APP1` Exif block has no byte
  ///    order, so no `ExifByteOrder` (and no IFD entries). Group is family-1
  ///    `File` (`Group::new("File", "File")`); the `-j` PrintConv renders
  ///    `Little-endian (Intel, II)` / `Big-endian (Motorola, MM)`
  ///    (`ExifTool.pm:1833-1836`), `-n` the bare `II`/`MM` marker
  ///    (`unknown:false`). The `File:FileType`/`FileTypeExtension`/`MIMEType`
  ///    triplet stays the engine's job — different `File:*` names, no key
  ///    collision.
  /// 2. The metadata blocks in marker-POSITION order. The EXIF block — the IFD
  ///    entries (`IFD0`/`ExifIFD`/`GPS`/`IFD1`/…) in IFD-walk order, then the
  ///    captured MakerNote's vendor emissions (`Apple:*`/`Canon:*`, carrying
  ///    their `Unknown => 1` flag for the engine to suppress) — sits at
  ///    [`exif_block_pos`](Self::exif_block_pos); each positioned auxiliary
  ///    `APP`-segment block ([`JpegAuxBlock`] — the `APP6` "GoPro" GPMF stream
  ///    today) sits at its own marker index. They are INTERLEAVED by ascending
  ///    marker position (a STABLE sort; a `None` EXIF position sorts first), so
  ///    each block emits at its segment's file-order position, reproducing
  ///    ExifTool's `Marker:`-loop order (`ExifTool.pm:7325`). For the common
  ///    case (no aux blocks) this is just the EXIF block, unchanged.
  ///
  /// `ExifMeta` emits no `Composite` group; the engine appends that LAST,
  /// completing ExifTool's [`File`-prefix → marker-order blocks → `Composite`]
  /// JPEG structure (see the [`ExifMeta`] type docs).
  ///
  /// This is the SINGLE source of the EXIF tag stream: both `serialize_tags`
  /// (`-j`/`-n` JSON) and [`crate::format_parser::AnyMeta::iter_tags`] drive
  /// it. The `$et->Warn` messages are NOT tags — they stay a separate channel
  /// drained by `serialize_tags`.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    // `-j` (PrintConv) vs `-n` (ValueConv) maps to the `print_conv` bool the
    // EXIF emitters thread (identical to `serialize_tags`'s argument).
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: std::vec::Vec<crate::emit::EmittedTag> = std::vec::Vec::new();
    // `File:ExifByteOrder` FIRST (ExifTool.pm:8691), only when a TIFF block
    // was processed. `unknown:false` (a real extracted tag), family-1 `File`.
    if let Some(order) = self.byte_order {
      let value = if print_conv {
        order.print_conv()
      } else {
        order.as_str()
      };
      tags.push(crate::emit::EmittedTag::new(
        crate::value::Group::new("File", "File"),
        smol_str::SmolStr::new_static("ExifByteOrder"),
        crate::value::TagValue::Str(smol_str::SmolStr::new_static(value)),
        false,
      ));
    }
    // `File:PageCount` — bundled `FoundTag(PageCount => $$self{PageCount})`
    // (`ExifTool.pm:8757`) runs AFTER the IFD walk, but its
    // `%Image::ExifTool::Extra` entry has GROUPS `File,File,Image`
    // (`ExifTool.pm:1285`/`:2017`) so the family-1 group is `File`; emit it
    // right after `ExifByteOrder` to keep the typed path "File first" (matching
    // bundled's JSON grouping). `Some(n)` only for a standalone-TIFF walk that
    // tripped the `MultiPage` flag (the `tiff_type_is_tiff` gate); `None` for
    // an embedded-block parse (PNG `eXIf`, JPEG `APP1`, QuickTime/RIFF). A bare
    // integer in both `-j` and `-n` (no PrintConv), `unknown:false`.
    if let Some(n) = self.multi_page_count {
      tags.push(crate::emit::EmittedTag::new(
        crate::value::Group::new("File", "File"),
        smol_str::SmolStr::new_static("PageCount"),
        crate::value::TagValue::U64(u64::from(n)),
        false,
      ));
    }
    // Emit the metadata blocks in marker-POSITION order: the EXIF block (the
    // IFD entries + the captured MakerNote — one contiguous group, internal
    // order unchanged) at `exif_block_pos`, INTERLEAVED with each positioned
    // auxiliary `APP`-segment block ([`JpegAuxBlock`] — the `APP6` "GoPro"
    // GPMF stream today) at its own marker index. ExifTool runs each
    // `APP1`/`APP6` arm inside its `Marker:` loop in file order
    // (`ExifTool.pm:7325`), so a block's tags emit at its segment's position;
    // this reproduces that ordering. The `File:*` prefix already emitted above
    // leads unconditionally (it never participates), and any `Composite` group
    // is appended LATER by the engine (`ExifMeta` emits none), so this step is
    // exactly the marker-ordered middle of ExifTool's [File → blocks →
    // Composite] structure.
    #[cfg(feature = "quicktime")]
    {
      // A block reference paired with its marker position. The EXIF block's
      // position is `Option`: `None` (no movable-tag `APP1`) sorts FIRST via
      // `Option`'s `None < Some` ordering, so aux blocks (positive positions)
      // trail it — matching ExifTool with no `IFD0:*` to order against.
      enum Block<'b> {
        Exif,
        Aux(&'b JpegAuxBlock),
      }
      let mut order: std::vec::Vec<(Option<usize>, Block<'_>)> =
        std::vec::Vec::with_capacity(1 + self.jpeg_aux_blocks.len());
      // Push the EXIF block FIRST so a position tie resolves EXIF-before-aux
      // (the stable sort preserves insertion order on equal keys) — the
      // realistic `APP1`-before-`APP6` layout the retired `before_exif == false`
      // path produced.
      order.push((self.exif_block_pos, Block::Exif));
      for (pos, block) in &self.jpeg_aux_blocks {
        order.push((Some(*pos), Block::Aux(block)));
      }
      // STABLE sort by ascending marker position (`Option<usize>`: `None`
      // first, then ascending `Some`). Reproduces the old
      // `first_gopro_idx < effective_exif_idx` comparison: a GoPro block at a
      // position below the EXIF block sorts before it (GoPro-first), otherwise
      // after.
      order.sort_by_key(|(pos, _)| *pos);
      for (_, block) in order {
        match block {
          Block::Exif => {
            self.push_exif_tags(print_conv, &mut tags);
            self.push_maker_note_tags(print_conv, &mut tags);
          }
          Block::Aux(aux) => aux.push_tags(print_conv, &mut tags),
        }
      }
    }
    // Without `quicktime` there are no aux blocks, so the EXIF block is the only
    // metadata block — emitted in its normal position (unchanged).
    #[cfg(not(feature = "quicktime"))]
    {
      self.push_exif_tags(print_conv, &mut tags);
      self.push_maker_note_tags(print_conv, &mut tags);
    }
    tags.into_iter()
  }
}

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for ExifMeta<'_> {
  /// The EXIF `$et->Warn(...)` corpus (IFD-bounds checks, `Malformed APP1 EXIF
  /// segment`, suspicious-offset, …) as [`Diagnostic`](crate::diagnostics::Diagnostic)
  /// warnings, in emission order. `File:ExifByteOrder` is a real TAG emitted by
  /// [`tags`](crate::emit::Taggable::tags) (not a diagnostic), so only the
  /// warnings appear here — the same loop the retired `AnyMeta::drain_diagnostics`
  /// EXIF arm ran. EXIF raises no `$et->Error` (a rejected block returns
  /// `Ok(None)` ⇒ the engine emits its own `ExifTool:Error`).
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    use crate::diagnostics::Diagnostic;
    // Carry each warning's `sub Warn` ignorable level (index-aligned) so the
    // `[Minor] ` prefix on the excessive-count warning comes from
    // `run_diagnostics`, not a baked literal. INVARIANT: every warning is
    // recorded through `warn()` / `warn_minor_behavioral()`, which append to
    // BOTH vectors in lock-step, so `warnings_ignorable[i]` is the level of
    // `warnings[i]`. A bare `warnings.push` would desync them and shift a
    // `[Minor]` flag onto the wrong message (Phase-C regression fix).
    debug_assert_eq!(
      self.warnings().len(),
      self.warnings_ignorable.len(),
      "warnings/warnings_ignorable must stay index-aligned",
    );
    self
      .warnings()
      .iter()
      .enumerate()
      .map(
        |(i, w)| match self.warnings_ignorable.get(i).copied().unwrap_or(0) {
          1 => Diagnostic::warn_minor(w.as_str()),
          2 => Diagnostic::warn_minor_behavioral(w.as_str()),
          _ => Diagnostic::warn(w.as_str()),
        },
      )
      .collect()
  }
}

// ====================================================================// `ExifSink` — the value-emission sink seam (golden-pattern refactor)
// ====================================================================
/// The per-value sink the Exif/GPS emitters (`emit_exif_value` /
/// `emit_gps_value` + helpers) write a CONVERTED scalar into. Abstracting the
/// sink behind these five typed writers lets the conversion-logic bodies stay
/// destination-agnostic: each writer maps a `(group, name, scalar)` to the
/// [`TagValue`] shape the engine will emit.
///
/// The sole implementor is [`EmittedTagSink`] — the golden-pattern
/// [`Taggable`](crate::emit::Taggable) path ([`ExifMeta::tags`]), where each
/// writer pushes an [`EmittedTag`](crate::emit::EmittedTag) carrying the
/// rendered [`TagValue`] under `Group{family0:"EXIF", family1:<IfdName>}`,
/// `unknown:false`. The engine ([`run_emission`](crate::emit::run_emission))
/// then drives those [`EmittedTag`]s into the
/// [`TagMap`](crate::tagmap::TagMap) sink, so `serialize_tags` no longer writes
/// to `TagMap` directly.
///
/// The method set is exactly the `write_*` surface the emitters call.
/// `Result<(), Infallible>` preserves the emitters' `?`-propagation unchanged.
#[cfg(feature = "alloc")]
trait ExifSink {
  /// A `&str` value → [`TagValue::Str`].
  fn write_str(
    &mut self,
    group: &str,
    name: &str,
    value: &str,
  ) -> Result<(), core::convert::Infallible>;
  /// An `i64` value → [`TagValue::I64`].
  fn write_i64(
    &mut self,
    group: &str,
    name: &str,
    value: i64,
  ) -> Result<(), core::convert::Infallible>;
  /// A `u64` value → [`TagValue::U64`] (EXACT — no saturation).
  fn write_u64(
    &mut self,
    group: &str,
    name: &str,
    value: u64,
  ) -> Result<(), core::convert::Infallible>;
  /// An `f64` value → [`TagValue::F64`].
  fn write_f64(
    &mut self,
    group: &str,
    name: &str,
    value: f64,
  ) -> Result<(), core::convert::Infallible>;
  /// Raw bytes → [`TagValue::Bytes`] (the no-`-b` binary placeholder).
  fn write_bytes(
    &mut self,
    group: &str,
    name: &str,
    value: &[u8],
  ) -> Result<(), core::convert::Infallible>;
  /// Write an ALREADY-RENDERED vendor maker-note value under a FULL group
  /// (`family0`, `family1`) with its `Unknown=>1` flag.
  ///
  /// Unlike the scalar `write_*` writers (which fix `family0 = "EXIF"` and route
  /// a scalar through the terminal number gate), a vendor leaf's value is built
  /// directly by its vendor `PrintConv` as a complete [`TagValue`] (e.g.
  /// [`CanonPrintConv::apply`](makernotes::vendors::canon::printconv::CanonPrintConv::apply)),
  /// and lands under the vendor's own family-0 group (`MakerNotes`). The Canon
  /// engine migration (#243 phase 2) callers are [`emit_canon_value`] (a leaf),
  /// [`emit_canon_subtable`] (each WALKED binary sub-table position), and
  /// [`emit_canon_special`] (the 0x28 / 0x96 LIST specials). The `unknown` flag
  /// rides into the [`EmittedTag`](crate::emit::EmittedTag) so the shared engine
  /// ([`run_emission`](crate::emit::run_emission)) drops it centrally — exactly
  /// as a Canon `VendorEmission`'s flag flows today.
  fn write_vendor_value(
    &mut self,
    family0: &str,
    family1: &str,
    name: &str,
    value: crate::value::TagValue,
    unknown: bool,
  ) -> Result<(), core::convert::Infallible>;
}

/// Test-only sink: each writer delegates to the matching inherent
/// [`TagMap`](crate::tagmap::TagMap) method so the emitter unit tests can read
/// the routed scalar back through `TagMap`'s `get`/`get_str` accessors and
/// assert the exact [`TagValue`] variant the emitter chose. Production no
/// longer routes `emit_*` into a `TagMap` (the EXIF stream flows through the
/// [`Taggable`](crate::emit::Taggable) engine via [`EmittedTagSink`]), so this
/// impl is `#[cfg(test)]` — absent from the lib build, where it would be dead.
#[cfg(all(test, feature = "alloc"))]
impl ExifSink for crate::tagmap::TagMap {
  #[inline(always)]
  fn write_str(
    &mut self,
    group: &str,
    name: &str,
    value: &str,
  ) -> Result<(), core::convert::Infallible> {
    crate::tagmap::TagMap::write_str(self, group, name, value)
  }
  #[inline(always)]
  fn write_i64(
    &mut self,
    group: &str,
    name: &str,
    value: i64,
  ) -> Result<(), core::convert::Infallible> {
    crate::tagmap::TagMap::write_i64(self, group, name, value)
  }
  #[inline(always)]
  fn write_u64(
    &mut self,
    group: &str,
    name: &str,
    value: u64,
  ) -> Result<(), core::convert::Infallible> {
    crate::tagmap::TagMap::write_u64(self, group, name, value)
  }
  #[inline(always)]
  fn write_f64(
    &mut self,
    group: &str,
    name: &str,
    value: f64,
  ) -> Result<(), core::convert::Infallible> {
    crate::tagmap::TagMap::write_f64(self, group, name, value)
  }
  #[inline(always)]
  fn write_bytes(
    &mut self,
    group: &str,
    name: &str,
    value: &[u8],
  ) -> Result<(), core::convert::Infallible> {
    // Inlined former `TagMap::write_bytes` (the inherent helper was retired
    // with the provider `serialize_tags` paths that were its last callers;
    // this `ExifSink for TagMap` impl is the only remaining `write_bytes`
    // user and owns the insert directly now).
    crate::tagmap::TagMap::write_value(
      self,
      group,
      name,
      crate::value::TagValue::Bytes(value.to_vec()),
    )
  }
  #[inline(always)]
  fn write_vendor_value(
    &mut self,
    _family0: &str,
    family1: &str,
    name: &str,
    value: crate::value::TagValue,
    _unknown: bool,
  ) -> Result<(), core::convert::Infallible> {
    // The `TagMap` keys on family-1 only (`-G1`), so this test sink stores the
    // value under `family1:name` (the `Unknown=>1` suppression is the engine's
    // job and is not modelled by this raw test sink — a caller that wants the
    // gate tests it before writing).
    crate::tagmap::TagMap::write_value(self, family1, name, value)
  }
}

/// The golden-pattern sink: each writer pushes one
/// [`EmittedTag`](crate::emit::EmittedTag) carrying the SAME [`TagValue`]
/// shape the [`TagMap`](crate::tagmap::TagMap) sink would store, under
/// `Group{family0:"EXIF", family1:<the IfdName the emitter passed as group>}`.
/// Every EXIF/GPS tag table row is `Unknown => 0` (the EXIF tables carry no
/// `Unknown=>1`), so `unknown` is always `false`.
///
/// Drives [`ExifMeta::tags`]; the engine ([`run_emission`](crate::emit::run_emission))
/// then applies Unknown-suppression (a no-op here) + the sink dedup.
#[cfg(feature = "alloc")]
struct EmittedTagSink<'v> {
  /// The destination [`EmittedTag`] buffer (borrowed) — the EXIF emitters push
  /// in emission order. Borrowing (rather than owning) lets [`ExifMeta::tags`]
  /// fill ONE `Vec` in place (the `File:ExifByteOrder`/`PageCount` prefix, the
  /// IFD entries via this sink, and the MakerNote vendor tags), eliminating the
  /// per-call temp `Vec` the EXIF-entry pass used to allocate + move (P2).
  tags: &'v mut std::vec::Vec<crate::emit::EmittedTag>,
}

#[cfg(feature = "alloc")]
impl<'v> EmittedTagSink<'v> {
  /// Wrap a destination buffer.
  #[inline(always)]
  fn new(tags: &'v mut std::vec::Vec<crate::emit::EmittedTag>) -> Self {
    Self { tags }
  }

  /// Push one rendered [`EmittedTag`] — `Group{family0:"EXIF", family1:group}`,
  /// `unknown:false` (EXIF tables have no `Unknown=>1`).
  #[inline(always)]
  fn push(&mut self, group: &str, name: &str, value: crate::value::TagValue) {
    self.tags.push(crate::emit::EmittedTag::new(
      crate::value::Group::new("EXIF", group),
      smol_str::SmolStr::new(name),
      value,
      false,
    ));
  }
}

#[cfg(feature = "alloc")]
impl ExifSink for EmittedTagSink<'_> {
  #[inline(always)]
  fn write_str(
    &mut self,
    group: &str,
    name: &str,
    value: &str,
  ) -> Result<(), core::convert::Infallible> {
    // Contract B (#197): a string-origin EXIF scalar is stored as a
    // [`TagValue::Str`]; the SINGLE crate-wide terminal `EscapeJSON` number gate
    // ([`crate::value::TagValue`]'s serializer) then renders a numeric-looking
    // value (`escape_json_is_number`) as a BARE JSON number and a non-numeric
    // value (PrintConv label, joined array, `inf`/`undef`/`Inf`/`NaN`) as a
    // quoted string — the same gate `emit_gated_number` applies to the numeric
    // writers, now consolidated in one place (no separate EXIF-path gate, no
    // `force_string` opt-out: the oracle has NO tag that is quoted-despite-
    // numeric — the apparent cases are stale fixtures or the digit-cap the gate
    // already handles).
    self.push(group, name, crate::value::TagValue::Str(value.into()));
    Ok(())
  }
  #[inline(always)]
  fn write_i64(
    &mut self,
    group: &str,
    name: &str,
    value: i64,
  ) -> Result<(), core::convert::Infallible> {
    self.push(group, name, crate::value::TagValue::I64(value));
    Ok(())
  }
  #[inline(always)]
  fn write_u64(
    &mut self,
    group: &str,
    name: &str,
    value: u64,
  ) -> Result<(), core::convert::Infallible> {
    self.push(group, name, crate::value::TagValue::U64(value));
    Ok(())
  }
  #[inline(always)]
  fn write_f64(
    &mut self,
    group: &str,
    name: &str,
    value: f64,
  ) -> Result<(), core::convert::Infallible> {
    self.push(group, name, crate::value::TagValue::F64(value));
    Ok(())
  }
  #[inline(always)]
  fn write_bytes(
    &mut self,
    group: &str,
    name: &str,
    value: &[u8],
  ) -> Result<(), core::convert::Infallible> {
    self.push(group, name, crate::value::TagValue::Bytes(value.to_vec()));
    Ok(())
  }
  #[inline(always)]
  fn write_vendor_value(
    &mut self,
    family0: &str,
    family1: &str,
    name: &str,
    value: crate::value::TagValue,
    unknown: bool,
  ) -> Result<(), core::convert::Infallible> {
    // The vendor value is already a complete `TagValue` (built by the vendor
    // `PrintConv`), so it bypasses `Self::push`'s `EXIF`/`unknown:false` shape:
    // push the FULL group + flag, matching `push_maker_note_tags`'s
    // `EmittedTag::new(Group::new("MakerNotes", group1), …, e.unknown())`.
    self.tags.push(crate::emit::EmittedTag::new(
      crate::value::Group::new(family0, family1),
      smol_str::SmolStr::new(name),
      value,
      unknown,
    ));
    Ok(())
  }
}

/// The CAPTURE sink: each [`write_vendor_value`](ExifSink::write_vendor_value)
/// becomes one [`VendorEmission`](makernotes::VendorEmission), collected into a
/// borrowed `Vec`. This is how the shared `Walker`'s Canon walk lands its
/// emissions in the same `Vec<VendorEmission>` shape every other vendor's body
/// parser produces (#243 phase 2 step C): [`Walker::capture_canon_emissions`]
/// re-runs [`emit_entry`] over the walked `ResolvedConv::Canon` entries with
/// this sink, so the result is byte-identical to the retired
/// `canon::parse_in_tiff` emissions (the same `emit_canon_value` /
/// `emit_canon_subtable` / `emit_canon_special` render the values), and the
/// captured `Vec` populates [`MakerNote::cached_emissions_print_conv`] exactly
/// like Apple/Sony/Panasonic/Nikon/DJI.
///
/// A Canon emission's value is ALWAYS built as a complete [`TagValue`] by its
/// vendor `PrintConv` and written through `write_vendor_value`; the scalar
/// `write_*` writers (`family0` fixed to `"EXIF"`) are the CORE Exif/GPS leaf
/// path. The Canon walk now resolves only vendor leaves (`walk_entry` gates the
/// core sub-IFD pointer dispatch on [`TableRef::is_core_ifd`], so no
/// `ResolvedConv::Exif` entry is produced under `%Canon::Main`), so a scalar
/// `write_*` is unreachable in practice — but these writers DROP the value
/// (a safe no-op) rather than `unreachable!()`, so a stray core entry can never
/// turn into a malformed-input panic (defense in depth).
#[cfg(feature = "alloc")]
struct VendorEmissionSink<'v> {
  /// The destination [`VendorEmission`] buffer (borrowed) — pushed in walk
  /// (emission) order.
  emissions: &'v mut std::vec::Vec<makernotes::VendorEmission>,
}

#[cfg(feature = "alloc")]
impl<'v> VendorEmissionSink<'v> {
  /// Wrap a destination buffer.
  #[inline(always)]
  fn new(emissions: &'v mut std::vec::Vec<makernotes::VendorEmission>) -> Self {
    Self { emissions }
  }
}

#[cfg(feature = "alloc")]
impl ExifSink for VendorEmissionSink<'_> {
  // The scalar writers are the core Exif/GPS leaf path and are not reached by a
  // Canon walk (every Canon emission goes through `write_vendor_value`). They
  // DROP the value (`Ok(())`) instead of `unreachable!()` so a stray core entry
  // can never DoS the capture — see the type doc.
  fn write_str(
    &mut self,
    _group: &str,
    _name: &str,
    _value: &str,
  ) -> Result<(), core::convert::Infallible> {
    Ok(())
  }
  fn write_i64(
    &mut self,
    _group: &str,
    _name: &str,
    _value: i64,
  ) -> Result<(), core::convert::Infallible> {
    Ok(())
  }
  fn write_u64(
    &mut self,
    _group: &str,
    _name: &str,
    _value: u64,
  ) -> Result<(), core::convert::Infallible> {
    Ok(())
  }
  fn write_f64(
    &mut self,
    _group: &str,
    _name: &str,
    _value: f64,
  ) -> Result<(), core::convert::Infallible> {
    Ok(())
  }
  fn write_bytes(
    &mut self,
    _group: &str,
    _name: &str,
    _value: &[u8],
  ) -> Result<(), core::convert::Infallible> {
    Ok(())
  }
  #[inline(always)]
  fn write_vendor_value(
    &mut self,
    _family0: &str,
    _family1: &str,
    name: &str,
    value: crate::value::TagValue,
    unknown: bool,
  ) -> Result<(), core::convert::Infallible> {
    // The family-0/1 group is fixed (`("MakerNotes", "Canon")`) for every Canon
    // emission and re-applied by [`ExifMeta::push_maker_note_tags`] from
    // [`MakerNote::emission_group1`], so it is NOT stored on the
    // `VendorEmission` (which carries only `name` / `value` / `unknown`, exactly
    // as the vendor body parsers build it).
    self.emissions.push(makernotes::VendorEmission::new(
      smol_str::SmolStr::new(name),
      value,
      unknown,
    ));
    Ok(())
  }
}

/// Emit one [`ExifEntry`] into the [`crate::tagmap::TagMap`] sink, applying
/// the resolved conversion.
// The emit seam threads the full render context (entry, order, PrintConv mode,
// the MakerNote `model`/`file_type` context, the two Canon CameraSettings
// DataMembers, and the sink). Bundling them into a context struct would obscure
// the 1:1 mapping to `parse_in_tiff`'s collection-time render, not clarify it —
// the sibling `emit_canon_subtable` carries the same allow for the same reason.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
fn emit_entry<S: ExifSink>(
  entry: &ExifEntry,
  // The TIFF byte order threads to `ConvertExifText`'s UTF-16 'Unknown'
  // guess — consumed by the Exif `Conv::ExifText` arm (UserComment) AND the
  // GPS `GpsConv::ExifText` arm (GPSProcessingMethod/GPSAreaInformation).
  order: ByteOrder,
  print_conv: bool,
  // The parent body `$$self{Model}` (IFD0's Model) — threaded ONLY into a vendor
  // leaf's conditional `PrintConv` (Canon `SerialNumber`, `Canon.pm:1282-1306`)
  // and the Canon sub-table parsers; every Exif/GPS arm ignores it. The
  // core-IFD callers ([`push_exif_tags`]) pass `None` (their `self.entries` carry
  // no Canon leaf — those were captured + truncated at dispatch); the Canon
  // CAPTURE caller ([`Walker::capture_canon_emissions`]) passes the walk-time
  // value so the captured emissions match `parse_in_tiff`.
  model: Option<&str>,
  // The container `$$self{FILE_TYPE}` — threaded ONLY into the Canon `ShotInfo`
  // sub-table (position 22's CRW-allows-0 RawConv, `Canon.pm:2977`/`:2990`); the
  // core Exif/GPS arms and every other Canon arm ignore it. `None` for the
  // core-IFD callers; the Canon capture caller passes the container type.
  file_type: Option<&str>,
  // The two Canon `%CameraSettings` DataMembers the pre-scan captured (#243
  // phase 2 step B2): `$$self{FocalUnits}` (CameraSettings pos 25) threads into
  // the `FocalLength` (0x02) sub-table's `ValueConv`, and `$$self{LensType}`
  // (pos 22) into the `FileInfo` (0x93) position-16 `Condition`. Both are
  // consumed ONLY by [`emit_canon_subtable`] for those two sub-tables; every
  // core Exif/GPS arm, the Canon leaf arm, and the simple-sub-table arms ignore
  // them. `None` for the core-IFD callers; the Canon capture caller threads the
  // pre-scanned members so the FocalLength/FileInfo emissions match
  // `parse_in_tiff`.
  canon_focal_units: Option<u16>,
  canon_lens_type: Option<u16>,
  // The pre-scanned LAST readable `CanonFocalLength` (0x02) `$$valPt` (#243 phase
  // 2 step C, R4) — threaded ONLY into [`emit_canon_subtable`]'s FocalLength arm,
  // which decodes EVERY 0x02 entry from this ONE cached blob (last-wins, matching
  // `parse_in_tiff`'s `focal_length_data`). `None` for the core-IFD callers (no
  // Canon leaf) and for any Canon walk with no readable 0x02; every other arm
  // ignores it.
  canon_focal_length_blob: Option<&[u8]>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  // The kind-derived family-1 group (`IFD0`/`ExifIFD`/`GPS`/…). For a core
  // Exif/GPS leaf this IS the leaf's family-1 group (passed unchanged to the
  // scalar emitters — byte-identical, the conformance suite proves it); a Canon
  // vendor leaf OVERRIDES it to its vendor group via `vendor_group1()`.
  let kind_group = entry.group();
  let group = kind_group.as_str();
  let name = entry.name();
  let raw = entry.value.raw();
  // Emit the leaf through the bespoke `emit_exif_value` / `emit_gps_value`
  // renderer keyed on the entry's [`tables::Conv`] / [`gps::GpsConv`]. (The
  // Exif/GPS leaf convs operate on the RAW value's first scalar / exact rational
  // / byte shape, which the golden `convert::apply` runtime — written for the
  // already-rendered `TagValue` — cannot reproduce byte-identically for a
  // multi-element value or preserve in TagValue shape; #243 Codex R1/R2.)
  match entry.conv {
    ResolvedConv::Exif(tag) => emit_exif_value(group, name, raw, tag.conv, order, print_conv, out),
    #[cfg(feature = "gps")]
    ResolvedConv::Gps(tag) => emit_gps_value(group, name, raw, tag.conv, order, print_conv, out),
    // `%Canon::Main` vendor leaf (Step A, #243 phase 2) — render via the Canon
    // `PrintConv` (`CanonPrintConv::apply`) and emit under the vendor group
    // `("MakerNotes","Canon")`, mirroring `parse_in_tiff` + `push_maker_note_tags`.
    // `vendor_group1()` is `Some("Canon")` here by construction; the unreachable
    // `None` (a future vendor table not yet wired) falls back to `group` so a leaf
    // is never silently mis-grouped.
    ResolvedConv::Canon(canon_tag) => {
      let group1 = entry.conv.vendor_group1().unwrap_or(group);
      // The two Canon `%Main` LIST / Format-override specials (`0x28`
      // ImageUniqueID, `0x96` SerialInfo/InternalSerialNumber LIST), #243
      // phase 2 step B3. Their VALUE was already rewritten at walk time
      // ([`Walker::canon_special_leaf_value`]) — here the EMIT reproduces
      // `parse_in_tiff`'s matching emit branches (`canon/mod.rs:943-1010`):
      // 0x28's 16-NUL-drop / hex `ValueConv`, and the 5D-body 0x96's
      // `serial_info::parse`. (A non-5D 0x96 is the LIST's SECOND arm
      // `InternalSerialNumber`, whose value is the already-stripped `Text`; it
      // is NOT special-cased here — it falls through to the leaf renderer below,
      // matching `parse_in_tiff`'s `else` leaf branch.)
      if let Some(result) = emit_canon_special(group1, entry.tag_id, raw, print_conv, model, out) {
        return result;
      }
      // A WALKED binary sub-table pointer is decoded HERE at emit time and each
      // returned position emitted — reproducing `parse_in_tiff`'s SubDirectory
      // arm (`canon/mod.rs:762-911`) through the shared Walker. The SIMPLE set
      // (ShotInfo / AFInfo{,2,3} / SensorInfo / ColorBalance — NO DataMember,
      // NO 2-pass) joined the emit path in step B1; the DataMember 2-pass set
      // (CameraSettings 0x01 / FocalLength 0x02 / FileInfo 0x93) joins in step
      // B2, threading the pre-scanned `$$self{FocalUnits}` / `$$self{LensType}`
      // (see [`canon_prescan_datamembers`]).
      match canon_tag.sub_table() {
        Some(sub) if sub.is_walked() => emit_canon_subtable(
          group1,
          sub,
          raw,
          order,
          print_conv,
          model,
          file_type,
          canon_focal_units,
          canon_lens_type,
          canon_focal_length_blob,
          out,
        ),
        // A STILL-DEFERRED SubDirectory (`is_walked() == false` — CameraInfo /
        // CropInfo / ColorData / the #223 swept-from-`None` set, etc.) emits
        // NOTHING: ExifTool descends into the child table and never emits the
        // parent pointer as a value (`Exif.pm:7103-7104` `next` skips `FoundTag`
        // for a no-value SubDirectory), and the port defers the child walk — so
        // NEITHER the parent NOR the children are emitted. This reproduces
        // `parse_in_tiff`'s `_ =>` SubDirectory arm (`canon/mod.rs`), which
        // pushes no emission. Rendering it through `emit_canon_value` (the bug
        // this guards) would leak a bogus `Canon:CanonCameraInfo` / `Canon:ColorData`
        // / … parent that ExifTool never emits (#223).
        Some(_) => Ok(()),
        // A plain LEAF (`sub_table() == None`) — the Canon `PrintConv` renderer.
        None => emit_canon_value(group1, name, raw, canon_tag, print_conv, model, out),
      }
    }
    // `%Apple::Main` vendor leaf (#243 phase 3) — render via the Apple `PrintConv`
    // (`ApplePrintConv::apply`) and emit under the vendor group
    // `("MakerNotes","Apple")`, mirroring `parse_with_print_conv` +
    // `push_maker_note_tags`. Apple is the SIMPLE case: every `%Apple::Main` entry
    // is a plain LEAF (no sub-tables, no LIST / Format-override specials), so this
    // is JUST the leaf emit — no `emit_canon_special` / `emit_canon_subtable`
    // analogue. `vendor_group1()` is `Some("Apple")` here by construction; the
    // unreachable `None` falls back to `group` so a leaf is never silently
    // mis-grouped.
    ResolvedConv::Apple(apple_tag) => {
      let group1 = entry.conv.vendor_group1().unwrap_or(group);
      emit_apple_value(group1, name, raw, apple_tag, print_conv, out)
    }
    // `%Sony::Main` vendor leaf (#243 phase 3). Production routes a Sony Main walk
    // through the DEDICATED capture loop in [`sony_makernote_isolated`], which
    // calls [`emit_sony_value`] directly so it can thread the in-IFD `AFAreaILCx`
    // DataMember (set at 0x201c, read by 0x201e). `emit_entry` is therefore NOT the
    // Sony capture path — but the match must be exhaustive, and no core-IFD walk
    // produces a `ResolvedConv::Sony` entry (Sony leaves exist only under
    // `active_table == Sony`, set solely by the isolated Sony walk). This arm is a
    // panic-free fallback that renders every Sony leaf faithfully EXCEPT 0x201e's
    // af_area-dependent branch (it passes `af_area = None`), which only the
    // dedicated capture loop reaches; the `model` is still threaded.
    ResolvedConv::Sony(sony_tag) => {
      let group1 = entry.conv.vendor_group1().unwrap_or(group);
      emit_sony_value(group1, entry, sony_tag, model, None, print_conv, None, out)
    }
    // `%Panasonic::Main` vendor leaf (#243 phase 3). Production routes a Panasonic
    // Main walk through the DEDICATED capture loop in [`panasonic_makernote_isolated`],
    // which calls [`emit_panasonic_value`] directly (the per-entry gates need the
    // entry's on-disk format + the threaded model). `emit_entry` is therefore NOT
    // the Panasonic capture path — but the match must be exhaustive, and no
    // core-IFD walk produces a `ResolvedConv::Panasonic` entry (Panasonic leaves
    // exist only under `active_table == Panasonic`, set solely by the isolated
    // Panasonic walk). This arm is a panic-free fallback that renders every
    // Panasonic leaf faithfully (the gates + 0x0f/0x2c model branch are reached the
    // same way; the `model` is threaded, the typed sink is `None`).
    ResolvedConv::Panasonic(panasonic_tag) => {
      let group1 = entry.conv.vendor_group1().unwrap_or(group);
      emit_panasonic_value(group1, entry, panasonic_tag, model, print_conv, None, out)
    }
    // `%Nikon::Main` / `%Nikon::Type2` vendor leaf (#243 phase 3-bis). Production
    // routes a Nikon walk through the DEDICATED capture loop (N2), which calls
    // [`emit_nikon_value`] directly so it can thread the decrypt keys + the
    // positional `FocusMode` DataMember into the binary sub-tables. `emit_entry`
    // is therefore NOT the Nikon capture path — but the match must be exhaustive,
    // and no core-IFD walk produces a `ResolvedConv::Nikon` entry (Nikon leaves
    // exist only under `active_table ∈ {Nikon, NikonType2}`, set solely by the
    // isolated Nikon walk). This arm is a panic-free fallback that renders every
    // Nikon LEAF faithfully (the IFD `order` is threaded, the typed sink is
    // `None`); a binary SubDirectory row is N2's job, never routed here.
    ResolvedConv::Nikon(nikon_tag) => {
      let group1 = entry.conv.vendor_group1().unwrap_or(group);
      emit_nikon_value(
        group1, entry, nikon_tag, model, order, print_conv, None, out,
      )
    }
  }
}

/// Render ONE Canon maker-note leaf into the sink — the emit-time reproduction
/// of `parse_in_tiff`'s leaf branch (`canon/mod.rs:1018-1027`).
///
/// Applies the resolved tag's [`CanonPrintConv`](makernotes::vendors::canon::printconv::CanonPrintConv)
/// to `raw` EXACTLY as the collection-time path does
/// (`def.conv().apply(&entry.value, print_conv, model)`), then writes the
/// already-rendered [`TagValue`] under `("MakerNotes", group1)` carrying the
/// tag's `Unknown=>1` flag. The flag is NOT filtered here — it rides into the
/// [`EmittedTag`](crate::emit::EmittedTag) so the shared
/// [`run_emission`](crate::emit::run_emission) engine drops it ONCE, identical to
/// how a Canon `VendorEmission`'s `is_unknown()` flows through
/// [`ExifMeta::push_maker_note_tags`].
///
/// `model` is the parent body `$$self{Model}`, consumed only by the conditional
/// `SerialNumber` list (`Canon.pm:1282-1306`); every other Canon `PrintConv`
/// ignores it.
#[cfg(feature = "alloc")]
fn emit_canon_value<S: ExifSink>(
  group1: &str,
  name: &str,
  raw: &RawValue,
  canon_tag: &makernotes::vendors::canon::tags::CanonTag,
  print_conv: bool,
  model: Option<&str>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  let value = canon_tag.conv().apply(raw, print_conv, model);
  out.write_vendor_value("MakerNotes", group1, name, value, canon_tag.is_unknown())
}

/// Render ONE Apple maker-note leaf into the sink — the emit-time reproduction of
/// `apple::parse_with_print_conv`'s per-tag emit (`apple/mod.rs`), through the
/// shared `Walker` (#243 phase 3).
///
/// Applies the resolved tag's [`ApplePrintConv`](makernotes::vendors::apple::printconv::ApplePrintConv)
/// to `raw` EXACTLY as the oracle does (`def.conv().apply(&entry.value, print_conv)`),
/// then writes the already-rendered [`TagValue`] under `("MakerNotes", group1)`
/// carrying the tag's `Unknown=>1` flag. The flag is NOT filtered here — it rides
/// into the [`EmittedTag`](crate::emit::EmittedTag) so the shared
/// [`run_emission`](crate::emit::run_emission) engine drops it ONCE, identical to
/// how an Apple `VendorEmission`'s `is_unknown()` flows through
/// [`ExifMeta::push_maker_note_tags`].
///
/// `ApplePrintConv::apply` reads the decoded [`RawValue`] BY REFERENCE (like
/// `CanonPrintConv::apply`), so the Walker's borrowed `raw` is passed straight
/// through — NO per-tag clone (the redundant `ParsedValue` clone is gone, the
/// Apple leaf path now allocates exactly as Canon does).
#[cfg(feature = "alloc")]
fn emit_apple_value<S: ExifSink>(
  group1: &str,
  name: &str,
  raw: &RawValue,
  apple_tag: &makernotes::vendors::apple::tags::AppleTag,
  print_conv: bool,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  let value = apple_tag.conv().apply(raw, print_conv);
  out.write_vendor_value("MakerNotes", group1, name, value, apple_tag.is_unknown())
}

/// Render ONE Sony maker-note leaf into the sink — the emit-time reproduction of
/// `sony::parse_in_tiff`'s per-tag emit loop (`sony/mod.rs:311-404`) through the
/// shared `Walker` (#243 phase 3).
///
/// Sony is the COMPLEX vendor case: unlike Apple/Canon's plain leaf render, each
/// `%Sony::Main` entry passes through a chain of per-entry suppression gates that
/// reproduce ExifTool's `GetTagInfo` / `Condition` / `RawConv` outcome (an
/// absent tag, NOT a raw fallback). This emit reproduces, in `parse_in_tiff`
/// order:
///
/// 2. **SubDirectory skip** — a row with a `sub_table` (CameraInfo / CameraSettings
///    / ShotInfo / the 0x9xxx encrypted series / …) DESCENDS into a child table and
///    never emits the parent pointer as a value; the Phase-3 port defers the child
///    walk, so it emits NEITHER parent nor children (`sony/mod.rs:315-341`).
/// 4. **Single-HASH `Condition` suppression** — the model-gated rows
///    (0x201b/0x201d/0x2021/0x205c/0xb050) and the `$format`-gated MultiBurst rows
///    (0x1000/0x1001/0x1002, read off [`ExifEntry::on_disk_format`]) are dropped
///    when their `Condition` does not hold (`single_hash_condition_holds`).
/// 5. **RawConv sentinel drop** — the 0xb04x `$val == 65535` rows + 0xb048's
///    `-1`-on-DSLR-A100 drop are suppressed on the RAW value (`rawconv_drops`).
/// 6. **The value** — the four conditional-ARRAY AF tags (0x201c/0x201e/0x2020/
///    0x2022) render via `apply_with_context(.., model, af_area)` and SUPPRESS on a
///    `None` (no `Condition` branch matched); every other leaf renders via the
///    plain `apply`. The 0x201c `AFAreaILCx` DataMember CAPTURE is the caller's job
///    (it precedes 0x201e in the IFD; threaded in as `af_area`).
/// 7. **Emit** — `write_vendor_value("MakerNotes", group1, …)` carrying the row's
///    `Unknown=>1` flag (dropped ONCE by `run_emission`, like Apple/Canon).
///
/// A skipped gate writes NOTHING (no emission for that entry) AND populates no
/// typed field — the faithful port of ExifTool's absent-tag behaviour. `model` is
/// the parent `$$self{Model}`; `af_area` the `AFAreaILCx` DataMember the capture
/// loop set at 0x201c.
///
/// `typed` is the optional sink for step 7's
/// [`populate_typed`](makernotes::vendors::sony::populate_typed) — `Some` only for
/// the production capture (which builds the typed `MakerNotesSony` from the SAME
/// gate-passing entries the oracle does, so a gated tag like a rawconv-dropped
/// 0xb041 populates NEITHER the emission NOR `exposure_mode`). The `emit_entry`
/// defensive arm passes `None`.
// Threads the full render context (entry, the resolved `SonyTag`, the
// model/af_area gate inputs, the PrintConv mode, the optional typed sink, and the
// emit sink). Bundling them into a struct would obscure the 1:1 mapping to
// `parse_in_tiff`'s collection-time gates, not clarify it — the sibling
// `emit_entry`/`emit_canon_subtable` carry the same allow for the same reason.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
fn emit_sony_value<S: ExifSink>(
  group1: &str,
  entry: &ExifEntry,
  sony_tag: &makernotes::vendors::sony::tags::SonyTag,
  model: Option<&str>,
  af_area: Option<i64>,
  print_conv: bool,
  typed: Option<&mut makernotes::vendors::sony::MakerNotesSony>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  use makernotes::vendors::sony::{populate_typed, printconv};
  let tag_id = entry.tag_id;
  let raw = entry.value.raw();
  // Step 2 — deferred SubDirectory row: emit NEITHER parent nor children.
  if sony_tag.sub_table.is_some() {
    return Ok(());
  }
  // Step 4 — single-HASH `Condition` suppression. The `$format`-gated MultiBurst
  // rows read the ON-DISK format (the `$format` ExifTool's `Condition` reads, NOT
  // the post-override format), retained on the walked entry.
  if !printconv::single_hash_condition_holds(tag_id, entry.on_disk_format.name(), model) {
    return Ok(());
  }
  // Step 5 — RawConv sentinel drop (tests the RAW, pre-conv value + the Model).
  if printconv::rawconv_drops(tag_id, raw, model) {
    return Ok(());
  }
  // Step 6 — render. The four conditional-ARRAY AF tags need the model (+ the
  // af_area DataMember for 0x201e) and SUPPRESS on `None`; every other leaf
  // ignores both.
  let value = match tag_id {
    0x201c | 0x201e | 0x2020 | 0x2022 => {
      match sony_tag
        .conv
        .apply_with_context(raw, print_conv, model, af_area)
      {
        Some(v) => v,
        // No branch matched ⇒ suppress (no emission for this entry).
        None => return Ok(()),
      }
    }
    _ => sony_tag.conv.apply(raw, print_conv),
  };
  // Step 7 — populate the typed surface (gate-passing only, exactly where the
  // oracle does), THEN emit with the bundled `Unknown=>1` flag (run_emission drops
  // it once). The typed populate reads `value` only for 0xb020's string fallback.
  if let Some(typed) = typed {
    populate_typed(typed, tag_id, raw, &value);
  }
  out.write_vendor_value(
    "MakerNotes",
    group1,
    sony_tag.name(),
    value,
    sony_tag.is_unknown(),
  )
}

/// Render ONE Nikon maker-note LEAF into the sink — the emit-time reproduction of
/// `nikon::parse_in_tiff`'s leaf branch (`nikon/mod.rs:410-432`) through the
/// shared `Walker` (#243 phase 3-bis).
///
/// Phase N1 is LEAF-ONLY: the binary SubDirectory dispatch (AFInfo / ColorBalance
/// / LensData / FlashInfo / ShotInfo) + the decrypt-key thread land with the
/// dedicated capture loop in N2; here a SubDirectory tag never reaches this fn
/// (the Walker's table dispatch resolves the row, but only the dedicated N2 loop
/// routes sub-tables — `emit_entry`'s defensive arm and N1's lone unit test only
/// exercise leaves). Applies the resolved tag's
/// [`NikonConv`](makernotes::vendors::nikon::NikonConv) to the entry's RAW value:
///
/// - The conv returns `None` for a `RawConv => … : undef` drop (only
///   `JPGCompression` 0x0044's raw `0` among the ported tags) — the tag is then
///   NOT emitted (neither typed nor parity), reproducing
///   `parse_in_tiff`'s `let Some(value) = …apply(…) else { continue }`.
/// - `Some(value)` ⇒ populate the typed surface (Main only — the caller passes
///   `typed: Some` solely for the `%Nikon::Main` walk, since the Type2 layout
///   reuses the Main tag IDs for DIFFERENT tags), THEN emit with the row's
///   `Unknown=>1` flag (`run_emission` drops it once, like the other vendors).
///
/// UNLIKE [`emit_sony_value`], this TAKES the IFD byte `order`
/// ([`NikonConv::apply`](makernotes::vendors::nikon::NikonConv::apply) threads
/// `GetByteOrder()` into the few RawConvs that unpack multi-byte `undef` fields,
/// e.g. `PowerUpTime`) and handles the `Option` RawConv drop itself.
// Threads the full render context (entry, the resolved `NikonTag`, the
// model/order conv inputs, the PrintConv mode, the optional typed sink, and the
// emit sink). Bundling them into a struct would obscure the 1:1 mapping to
// `parse_in_tiff`'s leaf branch, not clarify it — the sibling `emit_sony_value`/
// `emit_panasonic_value` carry the same allow for the same reason.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
fn emit_nikon_value<S: ExifSink>(
  group1: &str,
  entry: &ExifEntry,
  nikon_tag: &makernotes::vendors::nikon::tags::NikonTag,
  model: Option<&str>,
  order: ByteOrder,
  print_conv: bool,
  typed: Option<&mut makernotes::vendors::nikon::MakerNotesNikon>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  use makernotes::vendors::nikon::{ParsedValue, populate_typed};
  // `parse_in_tiff` wraps the entry's decoded `RawValue` in a `ParsedValue` and
  // applies the conv (with the model + IFD order); a `None` is the `RawConv =>
  // … : undef` drop, NOT an emission.
  let parsed = ParsedValue::new(entry.value.raw().clone());
  let Some(value) = nikon_tag.conv().apply(&parsed, print_conv, model, order) else {
    return Ok(());
  };
  // Populate the typed surface (gate-passing only, exactly where the oracle does)
  // — Main only; the caller passes `typed: None` for the Type2 walk.
  if let Some(typed) = typed {
    populate_typed(typed, entry.tag_id, &value, nikon_tag.name());
  }
  out.write_vendor_value(
    "MakerNotes",
    group1,
    nikon_tag.name(),
    value,
    nikon_tag.is_unknown(),
  )
}

/// Render ONE Panasonic maker-note leaf into the sink — the emit-time
/// reproduction of `panasonic::parse_in_tiff`'s per-tag emit loop
/// (`panasonic/mod.rs:660-734`) through the shared `Walker` (#243 phase 3).
///
/// Like Sony, each `%Panasonic::Main` entry passes a chain of per-entry
/// suppression gates that reproduce ExifTool's `GetTagInfo` / `Condition` /
/// `RawConv` outcome (an absent tag, NOT a raw fallback). This emit reproduces,
/// in `parse_in_tiff` order:
///
/// 1. **SubDirectory skip** — a row with a `sub_table` (FaceDetInfo 0x4e /
///    FaceRecInfo 0x61 / PrintIM 0x0e00 / TimeInfo 0x2003) DESCENDS into a child
///    table and never emits the parent pointer as a value; Phase 3 defers the
///    child walk, so NEITHER parent nor children emit (`Exif.pm:7103-7104`).
/// 2. **Single-HASH `Condition` suppression** — the `$format`-gated LensType rows
///    0xc4/0xc5/0xe4 are dropped when `$format ne "int16u"` (and 0xc4 also drops
///    the `0xffff` `$$valPt` sentinel), read off [`ExifEntry::on_disk_format`].
/// 3. **RawConv sentinel drop** — 0x86 ManometerPressure (`$val==65535`) and 0xd1
///    ISO (`$val > 0xfffffff0`) are suppressed on the RAW value.
/// 4. **0xc5 / 0xe4 LensTypeModel** — `RawConv => 'return undef unless $val'`
///    drops a ZERO value (absent), else emits the byte-swap conv; rendered via
///    [`apply_lens_type_model`](makernotes::vendors::panasonic::printconv::PanasonicPrintConv::apply_lens_type_model)
///    (`Some` ⇒ emit, `None` ⇒ drop).
/// 5. **Model-conditional conv** — 0x0f AFAreaMode (FZ10 vs other) and 0x2c
///    ContrastMode (PrintHex / GF-G2 / TZ10-ZS7 / raw) select their branch by
///    `$$self{Model}`; every other leaf uses the table's default conv.
/// 6. **Emit** — `write_vendor_value("MakerNotes", group1, …)` carrying the row's
///    `Unknown=>1` flag (dropped ONCE by `run_emission`, like Apple/Canon/Sony).
///
/// A skipped gate writes NOTHING AND populates no typed field — the faithful port
/// of ExifTool's absent-tag behaviour. `model` is the parent `$$self{Model}`.
///
/// `typed` is the optional sink for the
/// [`populate_typed`](makernotes::vendors::panasonic::populate_typed) step —
/// `Some` only for the production capture (which builds the typed
/// `MakerNotesPanasonic` from the SAME gate-passing entries the oracle does, so a
/// gated tag like a rawconv-dropped 0xd1 populates NEITHER the emission NOR a
/// typed field). The `emit_entry` defensive arm passes `None`. Unlike Sony,
/// Panasonic's gates read the entry's on-disk format + raw value (NOT the model),
/// and there is no in-IFD DataMember thread.
// Threads the full render context (entry, the resolved `PanasonicTag`, the model
// gate input, the PrintConv mode, the optional typed sink, and the emit sink).
// Bundling them into a struct would obscure the 1:1 mapping to `parse_in_tiff`'s
// collection-time gates, not clarify it — the sibling `emit_sony_value`/`emit_entry`
// carry the same allow for the same reason.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
fn emit_panasonic_value<S: ExifSink>(
  group1: &str,
  entry: &ExifEntry,
  panasonic_tag: &makernotes::vendors::panasonic::tags::PanasonicTag,
  model: Option<&str>,
  print_conv: bool,
  typed: Option<&mut makernotes::vendors::panasonic::MakerNotesPanasonic>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  use makernotes::vendors::panasonic::{PanasonicPrintConv, populate_typed};
  let tag_id = entry.tag_id;
  let raw = entry.value.raw();
  // Step 1 — deferred SubDirectory row: emit NEITHER parent nor children.
  if panasonic_tag.sub_table.is_some() {
    return Ok(());
  }
  // Step 2 — single-HASH `Condition` suppression (0xc4/0xc5/0xe4 LensType rows).
  // Reads the ON-DISK format (the `$format` ExifTool's `Condition` reads, NOT the
  // post-override format) retained on the walked entry, + the RAW value (the
  // 0xc4 `$$valPt ne "\xff\xff"` test).
  if !PanasonicPrintConv::single_hash_condition_holds(tag_id, entry.on_disk_format.name(), raw) {
    return Ok(());
  }
  // Step 3 — RawConv sentinel drop (0x86/0xd1; tests the RAW, pre-conv value).
  if PanasonicPrintConv::rawconv_drops(tag_id, raw) {
    return Ok(());
  }
  // Step 4 — 0xc5 / 0xe4 LensTypeModel: the `RawConv => 'return undef unless $val'`
  // drops a ZERO value (no emission, no typed populate); else the byte-swap conv.
  if matches!(tag_id, 0xc5 | 0xe4) {
    let Some(value) = PanasonicPrintConv::apply_lens_type_model(raw, print_conv) else {
      return Ok(());
    };
    if let Some(typed) = typed {
      populate_typed(typed, tag_id, raw, &value);
    }
    return out.write_vendor_value(
      "MakerNotes",
      group1,
      panasonic_tag.name(),
      value,
      panasonic_tag.is_unknown(),
    );
  }
  // Step 5 — render. The model-conditional 0x0f / 0x2c rows override the table's
  // default conv with the branch ExifTool's `Condition` chain selects for this
  // body; every other leaf uses the table default.
  let conv = match tag_id {
    0x0f => PanasonicPrintConv::af_area_mode_for_model(model),
    0x2c => PanasonicPrintConv::contrast_mode_for_model(model),
    _ => panasonic_tag.conv,
  };
  let value = conv.apply(raw, print_conv);
  // Step 6 — populate the typed surface (gate-passing only, exactly where the
  // oracle does), THEN emit with the bundled `Unknown=>1` flag (run_emission drops
  // it once).
  if let Some(typed) = typed {
    populate_typed(typed, tag_id, raw, &value);
  }
  out.write_vendor_value(
    "MakerNotes",
    group1,
    panasonic_tag.name(),
    value,
    panasonic_tag.is_unknown(),
  )
}

/// Emit the two Canon `%Main` LIST / Format-override SPECIALS at emit time —
/// the emit-path reproduction of `canon::parse_in_tiff`'s 0x28 / 0x96 branches
/// (`canon/mod.rs:943-1010`) through the shared `Walker` (#243 phase 2 step B3).
///
/// Returns `Some(Ok(()))` when `tag_id` is one of the two specials this emit
/// handles — `0x28` (`ImageUniqueID`) or a 5D-body `0x96` (the `SerialInfo`
/// SubDirectory arm) — having written the resulting tag(s) (or NOTHING, for a
/// dropped 0x28). Returns `None` when `tag_id` is NOT such a special — including
/// a NON-5D `0x96`, which is the LIST's SECOND arm `InternalSerialNumber` and is
/// rendered by the normal [`emit_canon_value`] leaf path (its value is the
/// already-`0xff`-stripped `Text` the walk-time rewrite produced) — so the
/// caller falls through to its leaf / sub-table dispatch.
///
/// `raw` is the entry's walk-time-rewritten value
/// ([`Walker::canon_special_leaf_value`]): a [`RawValue::Bytes`] for both 0x28
/// (the `Format => 'undef'` on-disk bytes) and the 5D 0x96 (the `SerialInfo`
/// `$$valPt` blob, un-stripped). A defensive non-`Bytes` shape (the walker
/// always rewrites these two to `Bytes`) is treated as empty bytes — emit
/// nothing — mirroring `parse_in_tiff`'s same `_ => &[]` guards.
///
/// `0x28` `ImageUniqueID` (`Canon.pm:1726-1735`): `RawConv => '$val eq "\0" x 16
/// ? undef : $val'` drops the value ONLY when it is EXACTLY sixteen NUL bytes
/// (Perl string equality — a short all-zero value of any OTHER length survives);
/// the survivor renders through `ValueConv => 'unpack("H*", $val)'`
/// ([`hex_lower`](makernotes::vendors::canon::hex_lower)). No `PrintConv`, so
/// `-j` and `-n` agree; `Writable`, non-`Unknown` ⇒ `unknown = false`.
///
/// 5D `0x96` `SerialInfo` (`Canon.pm:1834-1846`): ExifTool descends into
/// `%Canon::SerialInfo` and emits ITS leaves (`InternalSerialNumber2` /
/// `InternalSerialNumber`) but never the parent — decode the captured blob via
/// [`serial_info::parse`](makernotes::vendors::canon::serial_info::parse). Each
/// position is an explicit `BinaryData` entry ⇒ `unknown = false`.
#[cfg(feature = "alloc")]
fn emit_canon_special<S: ExifSink>(
  group1: &str,
  tag_id: u16,
  raw: &RawValue,
  print_conv: bool,
  model: Option<&str>,
  out: &mut S,
) -> Option<Result<(), core::convert::Infallible>> {
  use makernotes::vendors::canon::{hex_lower, printconv, serial_info};
  if tag_id == 0x28 {
    // The faithful `Format => 'undef'` bytes captured at walk time.
    let val_bytes: &[u8] = match raw {
      RawValue::Bytes(b) => b,
      _ => &[],
    };
    // `$val eq "\0" x 16` — EXACTLY sixteen NUL bytes ⇒ RawConv undef (emit
    // NOTHING). A different length, or any non-NUL byte, survives.
    let is_undef = val_bytes.len() == 16 && val_bytes.iter().all(|&b| b == 0);
    if is_undef {
      return Some(Ok(()));
    }
    let hex = hex_lower(val_bytes);
    return Some(out.write_vendor_value(
      "MakerNotes",
      group1,
      "ImageUniqueID",
      crate::value::TagValue::Str(smol_str::SmolStr::from(hex)),
      false,
    ));
  }
  // `0x96` FIRST arm — `SerialInfo` SubDirectory, only for an EOS-5D body. A
  // non-5D 0x96 is the SECOND arm (`InternalSerialNumber`) and is NOT handled
  // here (`None` ⇒ the caller's normal leaf renderer takes it).
  if tag_id == 0x96 && model.is_some_and(printconv::model_matches_eos_5d) {
    // The `$$valPt` SerialInfo blob the walker captured verbatim for the 5D arm.
    let blob: &[u8] = match raw {
      RawValue::Bytes(b) => b,
      _ => &[],
    };
    for (name, value) in serial_info::parse(blob, print_conv) {
      // Explicit BinaryData positions are never `Unknown`. The sink write is
      // infallible (`Infallible`); propagating it would only ever be `Ok`.
      if let err @ Err(_) = out.write_vendor_value("MakerNotes", group1, &name, value, false) {
        return Some(err);
      }
    }
    return Some(Ok(()));
  }
  None
}

/// Decode a WALKED Canon binary sub-table at emit time and write each of its
/// positions into the sink — the emit-path reproduction of `parse_in_tiff`'s
/// SubDirectory arm (`canon/mod.rs:762-911`). Step B1 of the Canon engine
/// migration (#243 phase 2) routed the no-DataMember / no-2-pass tables
/// (`ShotInfo` / `AFInfo` / `AFInfo2` / `AFInfo3` / `SensorInfo` /
/// `ColorBalance`) here; step B2 adds the DataMember 2-pass tables
/// (`CameraSettings` 0x01 / `FocalLength` 0x02 / `FileInfo` 0x93), so the shared
/// `Walker` now decodes the FULL [`SubTable::is_walked`] set instead of through
/// the legacy `canon::parse_in_tiff` dispatch.
///
/// `raw` is the entry's DECODED value (the int16s/int16u word array or raw
/// bytes the Walker read for the SubDirectory pointer); it is reserialized to
/// the `$$valPt` byte blob via [`reserialize_int_array`](makernotes::vendors::canon::reserialize_int_array)
/// — the SAME helper, byte-for-byte, the collection-time dispatch uses — and
/// handed to the matching sub-parser. `model` threads the parent `$$self{Model}`
/// (ColorBalance position-29 name; AFInfo PrimaryAFPoint condition; ShotInfo
/// position-22 350D branch; FileInfo position-1 conditional list +
/// MacroMagnification exclusion; FocalLength FocalPlaneX/YSize `Condition`);
/// `file_type` threads the container `$$self{FILE_TYPE}` into ShotInfo
/// position-22's CRW-allows-0 RawConv (`Canon.pm:2977`/`:2990`).
///
/// `canon_focal_units` is the pre-scanned `$$self{FocalUnits}`
/// (`%CameraSettings` pos 25) — the `FocalLength` (0x02) `ValueConv => '$val /
/// ($$self{FocalUnits} || 1)'` divisor (`Canon.pm:2702`). `canon_lens_type` is
/// the pre-scanned `$$self{LensType}` (`%CameraSettings` pos 22's `RawConv`
/// DataMember, `Canon.pm:2503`) — the `FileInfo` (0x93) position-16
/// `MacroMagnification` `Condition` (`$$self{LensType} == 124`,
/// `Canon.pm:7002-7005`). Both come from [`canon_prescan_datamembers`], which
/// resolved them from the CameraSettings entry BEFORE the main walk — exactly as
/// `parse_in_tiff`'s pre-pass threads its own captured `focal_units` / `lens_type`
/// (`canon/mod.rs:707-739`). They are read ONLY by the FocalLength / FileInfo
/// arms; the CameraSettings arm itself recaptures its OWN lens-id (for emission)
/// and reads its OWN position-25 FocalUnits internally, so it does not consume
/// either parameter.
///
/// Every sub-table position is an explicit `BinaryData` entry — NEVER `Unknown`
/// (the `Unknown` scalars are excluded INSIDE each sub-parser), so each emits
/// with `unknown = false`, exactly as the legacy `VendorEmission::new(name,
/// value, false)` pushes do.
///
/// The AFInfo2 (0x26) `Condition => '$$valPt !~ /^\0\0\0\0/'` skip
/// (`Canon.pm:1713`) is preserved here via
/// [`first4_all_zero`](makernotes::vendors::canon::first4_all_zero): an all-zero
/// first four bytes means the SubDirectory is NOT entered and NOTHING is emitted
/// — identical to `parse_in_tiff`. AFInfo3 (0x3c) has no such `Condition`, so it
/// always decodes.
// The emit seam threads the full render context (group, value, order, PrintConv
// mode, the MakerNote `model`/`file_type` context, the two CameraSettings
// DataMembers, and the sink). Bundling them into a context struct would obscure
// the 1:1 mapping to `parse_in_tiff`'s sub-parser calls, not clarify it.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
fn emit_canon_subtable<S: ExifSink>(
  group1: &str,
  sub: makernotes::vendors::canon::tags::SubTable,
  raw: &RawValue,
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  file_type: Option<&str>,
  canon_focal_units: Option<u16>,
  canon_lens_type: Option<u16>,
  // The pre-scanned LAST readable `CanonFocalLength` (0x02) `$$valPt` (the SAME
  // cache `parse_in_tiff` builds in its pre-pass, `canon/mod.rs:737`). The
  // FocalLength arm decodes THIS blob for EVERY 0x02, NOT the current entry's
  // `raw` — so two 0x02 entries emit "last,last" (R4 finding 2). `None` when no
  // readable 0x02 exists; the FocalLength arm then emits nothing (the oracle's
  // `if let Some(ref bytes) = focal_length_data` is likewise a no-op).
  canon_focal_length_blob: Option<&[u8]>,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  use makernotes::vendors::canon::tags::SubTable;
  use makernotes::vendors::canon::{
    af_info, camera_settings, color_balance, file_info, first4_all_zero, focal_length,
    reserialize_int_array, sensor_info, shot_info,
  };

  let blob = reserialize_int_array(raw, order);
  // Each arm decodes the blob into `(name, value)` positions; the typed structs
  // the standalone sub-parsers also return are not needed here (the migrated
  // emit path only re-emits the tag stream — the typed accessors stay sourced by
  // `parse_in_tiff` until the Step C production switch).
  let positions: Vec<(smol_str::SmolStr, crate::value::TagValue)> = match sub {
    // CameraSettings (0x01): emit its positions. It captures its OWN lens-id
    // here (`&mut lens_id`, discarded — the emission needs only the rendered
    // `LensType` position, and the cross-entry DataMember was already pre-scanned
    // for FileInfo), and pre-reads its OWN position-25 FocalUnits internally for
    // Max/MinFocalLength — so it consumes neither threaded DataMember.
    SubTable::CameraSettings => {
      let mut lens_id: Option<u16> = None;
      camera_settings::parse_with_lens_id_capture(&blob, order, print_conv, &mut lens_id)
    }
    // FocalLength (0x02): the `$val / ($$self{FocalUnits} || 1)` divisor is the
    // pre-scanned CameraSettings position-25 value (`Canon.pm:2702`). The blob
    // decoded is NOT this entry's own `$$valPt` but the pre-scanned LAST readable
    // 0x02 (`canon_focal_length_blob`) — `parse_in_tiff` caches `focal_length_data`
    // in its pre-pass (last-wins, `canon/mod.rs:735-738`) and renders EVERY 0x02
    // SubDirectory from that FINAL blob (`canon/mod.rs:883-889`), so a Canon IFD
    // with two `CanonFocalLength` entries emits "last,last", not "first,last"
    // (R4 finding 2). The pre-scan always captures a value for any 0x02 the walk
    // also surfaced (same classification + `read_value`), so `None` here means no
    // readable 0x02 existed at all — then, like the oracle's `if let Some(ref
    // bytes) = focal_length_data`, emit nothing.
    SubTable::FocalLength => match canon_focal_length_blob {
      Some(bytes) => focal_length::parse(bytes, order, print_conv, canon_focal_units, model),
      None => Vec::new(),
    },
    // FileInfo (0x93): position 16 (`MacroMagnification`) gates on the
    // pre-scanned `$$self{LensType} == 124` (`Canon.pm:7002-7005`); `model` keys
    // its position-1 conditional list. Drop the typed `decoded` return.
    SubTable::FileInfo => {
      file_info::parse_with_model(&blob, order, print_conv, canon_lens_type, model).0
    }
    SubTable::ShotInfo => shot_info::parse(&blob, order, print_conv, model, file_type).1,
    SubTable::AfInfo => af_info::parse_af_info(&blob, order, print_conv, model).1,
    // `Canon::Main` 0x26 `Condition => '$$valPt !~ /^\0\0\0\0/'` (`Canon.pm:1713`):
    // skip the SubDirectory entirely when the first four bytes are all zero.
    SubTable::AfInfo2 => {
      if first4_all_zero(&blob) {
        Vec::new()
      } else {
        af_info::parse_af_info2(&blob, order, print_conv, model).1
      }
    }
    SubTable::AfInfo3 => af_info::parse_af_info3(&blob, order, print_conv, model).1,
    SubTable::SensorInfo => sensor_info::parse(&blob, order, print_conv),
    SubTable::ColorBalance => color_balance::parse(&blob, order, print_conv, model),
    // `emit_entry` only routes the `is_walked()` set here; any other variant is
    // a caller bug, not a malformed-input case — emit nothing.
    _ => Vec::new(),
  };

  for (name, value) in positions {
    out.write_vendor_value("MakerNotes", group1, &name, value, false)?;
  }
  Ok(())
}

/// Build the typed [`MakerNotesCanon`](makernotes::vendors::canon::MakerNotesCanon)
/// from the Canon Main IFD leaves the shared `Walker` produced (#243 phase 2
/// step C). `canon_entries` is the contiguous run of `ResolvedConv::Canon`
/// entries `process_subdir(TableRef::Canon)` appended to `self.entries`, IN WALK
/// ORDER. Maps each to its `(tag_id, &RawValue)` and hands them to
/// [`canon::build_typed_from_entries`](makernotes::vendors::canon::build_typed_from_entries),
/// which reproduces every `parse_in_tiff` typed-population site — so the typed
/// accessors (`model_id` / `lens_type` / `shot_info` / `af_info` / `file_info` /
/// …) are populated identically to the retired collection-time path.
///
/// `order` is the parent byte order; `model` the parent `$$self{Model}`;
/// `file_type` the container `$$self{FILE_TYPE}`; `lens_type` the pre-scanned
/// `%CameraSettings` pos-22 DataMember the FileInfo typed decode reads (the SAME
/// value the emission capture reads, so the typed surface and the JSON stream
/// agree). The `$$self{FocalUnits}` DataMember scales only emissions, never a
/// typed field, so it is not threaded here.
#[cfg(feature = "alloc")]
fn populate_canon_typed(
  canon_entries: &[ExifEntry],
  order: ByteOrder,
  model: Option<&str>,
  file_type: Option<&str>,
  lens_type: Option<u16>,
) -> makernotes::vendors::canon::MakerNotesCanon {
  let pairs: Vec<(u16, &RawValue)> = canon_entries
    .iter()
    .map(|e| (e.tag_id, e.value.raw()))
    .collect();
  makernotes::vendors::canon::build_typed_from_entries(&pairs, order, model, file_type, lens_type)
}

/// Re-drive the SHARED `Walker`'s Canon Main IFD walk + emission capture in `-n`
/// (ValueConv) mode — the on-demand `-n` recompute for
/// [`MakerNoteValueConvDecode::Canon`] (#243 phase 2 step C).
///
/// The walk-time PrintConv decode caches its emissions eagerly (it ALSO yields
/// the typed `MakerNotesCanon` slot), but the `-n` emissions are needed only by
/// the `-n` serialize path, so — exactly like the other gated vendors — this
/// captures the decode INPUTS (the borrowed parent slice + `mn_offset` / order /
/// model / file_type) and re-runs the walk only when
/// [`MakerNote::emissions_value_conv`] is called. It builds a fresh single-use
/// [`Walker`] over the parent TIFF block, walks the Canon Main IFD at `mn_offset`
/// through [`process_subdir`](Walker::process_subdir) under `TableRef::Canon`
/// (the SAME entry the dispatch used — so the `%CameraSettings` DataMember
/// pre-scan runs identically and `self.canon_focal_units` /
/// `self.canon_lens_type` are repopulated), then captures the walked leaves with
/// `print_conv = false` via [`capture_canon_emissions`](Walker::capture_canon_emissions).
///
/// Byte-identical to the old eager `-n` cache: the Canon walk reads the same
/// bytes through the same machinery regardless of the PrintConv flag (Canon's
/// `%Main` has no `IsOffset`/`SubIFD` tag, so the walk never consults
/// `Walker::base`, and a fresh `base: 0` Walker walks the same entries the
/// dispatch's parent-context Walker did — the retired `canon::parse_in_tiff`
/// likewise took no base).
///
/// `mn_len` is the MakerNote read length the dispatch captured (the 0x927c value
/// window); the Canon walk reads its own IFD entry-count + per-entry extents from
/// `data` at `mn_offset` (it does not slice to `mn_len`), so the parameter is
/// carried for symmetry with the dispatch capture inputs and the bounds it
/// documents, not consumed by the walk.
#[cfg(feature = "alloc")]
fn canon_recompute_value_conv(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  order: ByteOrder,
  model: Option<&str>,
  file_type: Option<&str>,
) -> std::vec::Vec<makernotes::VendorEmission> {
  // The `-n` recompute is the isolated walk with `print_conv = false` and the
  // typed slot discarded (the `-n` path needs only the ValueConv emissions).
  canon_makernote_isolated(data, mn_offset, mn_len, order, model, file_type, false).0
}

/// Walk the Apple Main IFD in a FRESH, ISOLATED [`Walker`] over the captured blob
/// and capture its emissions + typed surface — the single entry point BOTH the
/// `-j` production dispatch and the `-n` recompute drive (#243 phase 3, structural
/// isolation, mirroring [`canon_makernote_isolated`]).
///
/// Apple is the SIMPLE vendor case: BLOB-only (`Base => '$start - 14'` rebases
/// out-of-line offsets to the START of the blob, `MakerNotes.pm:43`), with no
/// DataMember pre-scan, no binary sub-tables, and no model-conditionals. So a
/// fresh `Walker` over `data = blob`, `base = 0`, walking the IFD at
/// `14 + header_size` under `active_table == TableRef::Apple` reproduces the oracle
/// [`walk_apple_body`](makernotes::vendors::apple::walk_apple_body) EXACTLY: an
/// inline value reads at `entry + 8`, and an out-of-line value at `blob[off]`
/// (`base = 0`, and `%Apple::Main` carries no `IsOffset`/`SubIFD` tag, so
/// [`is_offset_tag`] never adds `base`) — the SAME byte window the oracle's
/// `body[off - body_offset]` (= `blob[off]`) reads.
///
/// The byte ORDER + header size come from the body's own marker
/// ([`ByteOrder::from_marker`] of `blob[14..]`): `MM`/`II` ⇒ that order +
/// `header_size = 2`; no marker ⇒ the parent order + `header_size = 0` (degenerate
/// — every real-iPhone fixture starts with `MM`). A blob shorter than the 14-byte
/// `Apple iOS` header yields no emissions and an EMPTY `MakerNotesApple` — the
/// oracle's `blob.len() < 14` guard.
///
/// A FRESH `Walker` has its OWN `warnings` / `warn_count` / `active_ifd_offsets`,
/// populated by THIS walk and DISCARDED on return — so a malformed Apple entry
/// cannot leak a core `ExifTool:Warning`, abort the parent ExifIFD's warn-count,
/// or be suppressed by the parent's ancestor cycle guard (the oracle, an isolated
/// `walk_apple_body`, has none of these side effects either). `print_conv = true`
/// renders the `-j` (PrintConv) emissions; `print_conv = false` the `-n`
/// (ValueConv) emissions; the typed `MakerNotesApple` is the SAME for both modes
/// and is ALWAYS returned (non-Option — the oracle's `MakerNotesApple` is always
/// present, even empty).
#[cfg(feature = "alloc")]
fn apple_makernote_isolated(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  make: Option<&str>,
) -> (
  std::vec::Vec<makernotes::VendorEmission>,
  Option<makernotes::vendors::apple::MakerNotesApple>,
) {
  // The oracle's `blob.len() < 14` guard (`apple/mod.rs`): a blob too short to
  // hold the 14-byte `Apple iOS\0\0\x01` header yields nothing + an empty typed
  // slot. (`walk_apple_body` also returns nothing for `body_offset >= blob.len()`,
  // i.e. `blob.len() <= 14`; the explicit `< 14` here matches
  // `parse_with_print_conv`'s top guard exactly.) The typed slot is built ONLY
  // for `-j` (`print_conv.then(...)`, mirroring `canon_makernote_isolated`): the
  // `-n` recompute discards it, so building it there would waste the
  // SmolStr-allocating string-tag population (`burst_uuid` / `content_identifier`
  // / `image_unique_id`).
  if blob.len() < 14 {
    return (
      std::vec::Vec::new(),
      print_conv.then(makernotes::vendors::apple::MakerNotesApple::new),
    );
  }
  // Resolve the body byte order + header size from the body marker (the oracle's
  // `ByteOrder::from_marker(body)` at `body = &blob[14..]`). `MM`/`II` ⇒ that
  // order, the marker occupies 2 bytes; no marker ⇒ inherit the parent order, the
  // count word is at the body start. The `blob.len() >= 14` guard above makes
  // `blob.get(14..)` `Some`.
  let body = blob.get(14..).unwrap_or(&[]);
  let (order, header_size) = match ByteOrder::from_marker(body) {
    Some(o) => (o, 2usize),
    None => (parent_order, 0usize),
  };
  // The IFD count word sits at `14 + header_size` in the blob (the oracle reads it
  // at `header_size` in the `body` slice). The shared `Walker` walks `data = blob`
  // from this offset, so the absolute blob offset is used directly.
  let ifd_offset = 14usize.saturating_add(header_size);
  let mut w = Walker {
    data: blob,
    order,
    // `%Apple::Main` carries no `IsOffset`/`SubIFD` tag, so the walk never adds
    // `base` to a value — `base: 0` resolves an out-of-line offset at `blob[off]`,
    // byte-identical to the oracle's `Base => '$start - 14'` blob-relative read.
    base: 0,
    // Inherit-base vendor walk — out-of-line offsets are already TIFF-relative
    // (child `$dataPos == 0`), so no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    // FRESH warning channels: a malformed Apple entry warns into THESE, dropped on
    // return — never the parent's `ExifTool:Warning` stream (the oracle
    // `walk_apple_body` silently `next`s a bad entry, emitting no such warning).
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    // The parent IFD0 `Make`, threaded from the dispatch — the format-16
    // (`int64u`) Apple carve-out in the per-entry gate requires
    // `captured_make == Some("Apple")` (`Exif.pm:6464` `$$et{Make} eq 'Apple'`),
    // so a non-Apple container with an Apple-signature blob rejects code 16. The
    // real iPhone fixtures carry IFD0 Make == "Apple", so this stays admitted.
    captured_make: make.map(String::from),
    // Apple has no model-conditional tag, so `$$self{Model}` is irrelevant to the
    // walk; leave it unset.
    captured_model: None,
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    // EMPTY active path: the fresh walker has no ancestor on its recursion stack,
    // so an Apple value offset that coincides with a parent IFD offset is still
    // walked — the oracle, also pathless, always walks it.
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    // No Apple tag reads `$$self{FILE_TYPE}`.
    file_type: None,
    // The captured blob IS the readable buffer (an effective RAF), like the
    // dispatch walk.
    no_raf: false,
    warn_count: 0,
    // Starts on the Exif table; `process_subdir(TableRef::Apple)` swaps it to
    // `Apple` for the sub-walk and restores it.
    active_table: TableRef::Exif,
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // The Apple Main IFD walk — the SAME `process_subdir` entry the Canon walk uses,
  // but with `ProcessProc::Exif` (Apple needs NO Canon DataMember pre-scan; the
  // `if table == TableRef::Canon` pre-scan hook is therefore inert). `Fixed(order)`
  // keeps the body-marker order; `IfdKind::ExifIfd` is a non-Ifd0 kind so the
  // IFD0-only Make/Model capture tap never fires; `FixBaseMode::No` (the blob is
  // already body-relative). It appends the Apple leaves to `w.entries` from index
  // 0, isolating every core side effect from the parent.
  w.process_subdir(
    ifd_offset,
    IfdKind::ExifIfd,
    TableRef::Apple,
    ByteOrderRule::Fixed(order),
    FixBaseMode::No,
    ProcessProc::Exif,
  );
  // Capture the walked `ResolvedConv::Apple` leaves into the vendor-emission `Vec`
  // every other vendor body parser produces (the SAME `emit_entry` →
  // `emit_apple_value` path, driven by `print_conv`). The render context Apple
  // needs is empty (no model / file_type / DataMembers), so pass `None`s.
  let mut emissions = std::vec::Vec::new();
  let mut sink = VendorEmissionSink::new(&mut emissions);
  for entry in &w.entries {
    let Ok(()) = emit_entry(
      entry, order, print_conv, None, None, None, None, None, &mut sink,
    );
  }
  // Build the typed surface from the SAME walked entries, via the single-sourced
  // per-tag router the oracle uses ([`apple::populate_typed_value`]). ONLY for
  // `-j`: the production dispatch needs it, the `-n` recompute discards it, so
  // gating on `print_conv` (like `canon_makernote_isolated`) saves the
  // string-tag SmolStr allocations on the `-n` path.
  let typed = print_conv.then(|| {
    let mut typed = makernotes::vendors::apple::MakerNotesApple::new();
    for entry in &w.entries {
      makernotes::vendors::apple::populate_typed_value(&mut typed, entry.tag_id, entry.value.raw());
    }
    typed
  });
  (emissions, typed)
}

/// Walk the Sony `%Sony::Main` IFD in a FRESH, ISOLATED [`Walker`] over the parent
/// TIFF and capture its emissions + typed surface — the single GATED entry point
/// BOTH the `-j` production dispatch and the `-n` recompute drive (#243 phase 3,
/// structural isolation, mirroring [`apple_makernote_isolated`] /
/// [`canon_makernote_isolated`]).
///
/// ## The variant gate (FIRST)
///
/// The dispatcher collapses ALL seven Sony `MakerNotes.pm` variants
/// (`:1031-1099`) to [`Vendor::Sony`], but only `MakerNoteSony`/`MakerNoteSony5`
/// use `%Sony::Main`; the rest (`Sony2`/`Sony3` → `Olympus::Main`, `Sony4` →
/// `Sony::PIC`, `SonyEricsson` → `Sony::Ericsson`, `SonySRF` → `Sony::SRF`) route
/// to tables this Phase-3 port has not ported, so running the Main walker on them
/// is UNFAITHFUL (a coincidental tag-id collision decodes a bogus tag). This
/// function applies [`routes_to_main`](makernotes::vendors::sony::routes_to_main)
/// on the captured blob (`data[mn_offset .. mn_offset + mn_len]`, computed EXACTLY
/// as [`parse_main_gated`](makernotes::vendors::sony::parse_main_gated)) and
/// returns `None` for a non-Main blob — the caller leaves the Sony slot ABSENT.
/// This is the SAME gate the retired `parse_main_gated` oracle applies, so the
/// route classification cannot be bypassed.
///
/// ## The walk (byte-identity to `parse_in_tiff`)
///
/// Both Main variants INHERIT the parent base (no `Base =>` override,
/// `MakerNotes.pm:1037-1041,1076-1080`), so out-of-line value offsets are
/// TIFF-relative — a `base: 0` Walker over `data` (the parent TIFF) resolves them
/// at `data[off]`, byte-identical to the oracle's `walk_sony_in_tiff` (the bodies
/// carry no MM/II marker, so the byte order is the PARENT order). The IFD count
/// word sits at `mn_offset + body_offset` (`body_offset` is 12 for the prefixed
/// `SONY DSC`/CAM/MOBILE/VHAB/TF1 variants, 0 for headerless Sony5). The walk runs
/// under `active_table == TableRef::Sony` via [`process_subdir`](Walker::process_subdir)
/// with `ProcessProc::Exif` — which now resolves the Sony table's own `Format =>`
/// directives (0x0112/0x1000/0x200a/0x2037/0xb022/0xb02a, `Sony.pm`) just as
/// ExifTool's `ProcessExif` reads them off the active `$tagTablePtr`
/// (`Exif.pm:6729`), reproducing the oracle's `resolve_read_format` step. The
/// directory `kind` is `ExifIfd` (a non-Ifd0 kind, so the IFD0-only Make/Model tap
/// never fires).
///
/// ## The per-entry gates (the capture loop)
///
/// Sony's `%Main` render is gated per entry (an ABSENT tag, not a raw fallback),
/// so — unlike Apple/Canon's `emit_entry` capture — the loop drives the dedicated
/// [`emit_sony_value`] (reproducing `parse_in_tiff`'s SubDirectory-skip /
/// single-HASH `Condition` / RawConv-drop / conditional-AF gates), threading the
/// in-IFD `AFAreaILCx` DataMember: 0x201c sets `af_area` (in IFD-tag order it
/// precedes 0x201e, which reads it). The typed [`MakerNotesSony`] is built from
/// the SAME walked entries via
/// [`build_typed_from_pairs`](makernotes::vendors::sony::build_typed_from_pairs)
/// (the typed leaf set is disjoint from every gated tag, so it is a clean separate
/// pass, like Apple/Canon).
///
/// ## Isolation
///
/// A FRESH `Walker` has its OWN `warnings` / `warn_count` / `active_ifd_offsets`,
/// populated by THIS walk and DISCARDED on return — so a malformed Sony entry
/// cannot leak a core `ExifTool:Warning`, abort the parent ExifIFD's warn-count,
/// or be suppressed by the parent's ancestor cycle guard (the oracle, an isolated
/// `walk_sony_in_tiff`, has none of these side effects either). `print_conv = true`
/// renders the `-j` emissions + the typed slot; `print_conv = false` the `-n`
/// emissions (the typed slot is the SAME for both and ALWAYS returned, non-Option,
/// matching `parse_in_tiff`).
#[cfg(feature = "alloc")]
#[allow(clippy::too_many_arguments)]
fn sony_makernote_isolated(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  order: ByteOrder,
  make: Option<&str>,
  model: Option<&str>,
  print_conv: bool,
) -> Option<(
  std::vec::Vec<makernotes::VendorEmission>,
  makernotes::vendors::sony::MakerNotesSony,
)> {
  use makernotes::vendors::sony;
  // The variant gate FIRST — the captured MakerNote blob is the bytes the
  // dispatcher classified (`data[mn_offset .. mn_offset + mn_len]`), computed
  // EXACTLY as `parse_main_gated` (saturating end, clamped to the buffer). A blob
  // routing elsewhere ⇒ `None` (the Sony slot stays absent — no spurious tags).
  let blob_end = mn_offset.saturating_add(mn_len).min(data.len());
  let blob = data.get(mn_offset..blob_end)?;
  if !sony::routes_to_main(blob, make, model) {
    return None;
  }
  // Short-MakerNote guard (the oracle's `walk_sony_in_tiff:131` pre-check, in the
  // REVERSE direction): the dispatcher's variant-gate window must at least contain
  // the IFD count word INSIDE the declared MakerNote value (`mn_len >= body_offset
  // + 2`); below that the value has no room for an IFD. Without this, a truncated
  // MakerNote (e.g. value is only `SONY DSC`, `mn_len = 9`, `body_offset = 12`)
  // would still walk `data` at `mn_offset + body_offset` and read its count word
  // from the UNRELATED following parent-TIFF bytes — emitting spurious Sony tags
  // the oracle (`walk_sony_in_tiff`, which returns empty here) never does, and a
  // migration regression vs the pre-migration `walk_sony_in_tiff`. `routes_to_main`
  // already classified the blob as a Main variant, so the faithful result is
  // present-but-empty (`Some((empty, empty))`), NOT `None` (which would drop the
  // typed slot the oracle's `parse_in_tiff` still returns). `body_offset + 2` is
  // `checked_add`ed for the usize-overflow class — an overflow can never satisfy
  // `mn_len >=`, so it trips the guard exactly as the oracle's `<` test does.
  match body_offset.checked_add(2) {
    Some(min_len) if mn_len >= min_len => {}
    _ => return Some((std::vec::Vec::new(), sony::MakerNotesSony::new())),
  }
  // The IFD sits at `mn_offset + body_offset` in `data`. A body offset past the
  // buffer yields an empty walk (no entries) — the oracle's same out-of-bounds
  // guard (`walk_sony_in_tiff` returns empty); `process_subdir` is bounds-checked.
  let ifd_offset = mn_offset.saturating_add(body_offset);
  let mut w = Walker {
    data,
    order,
    // Both Main variants inherit the parent base (no `Base =>` override), so the
    // walk never adds `base` to a value — `base: 0` resolves an out-of-line offset
    // at `data[off]`, byte-identical to the oracle's TIFF-relative read.
    base: 0,
    // Inherit-base vendor walk — out-of-line offsets are already TIFF-relative
    // (child `$dataPos == 0`), so no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    // FRESH warning channels: a malformed Sony entry warns into THESE, dropped on
    // return — never the parent's `ExifTool:Warning` stream (the oracle
    // `walk_sony_in_tiff` silently `continue`s a bad entry, emitting no warning).
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    // `$$self{Model}` gates the four conditional-ARRAY AF tags + the single-HASH
    // `Condition` rows; the Sony walk itself reads no model-conditional structure,
    // but the captured model is threaded into the capture-loop gates below (not
    // into the walk), so leave it unset on the Walker.
    captured_model: None,
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    // EMPTY active path: the fresh walker has NO ancestor on its recursion stack,
    // so a Sony value offset that coincides with a PARENT IFD offset is still
    // walked — the oracle, also pathless, always walks it.
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    // No Sony Main leaf reads `$$self{FILE_TYPE}`.
    file_type: None,
    // The parent TIFF block IS the readable buffer (an effective RAF), like the
    // dispatch walk.
    no_raf: false,
    warn_count: 0,
    // Starts on the Exif table; `process_subdir(TableRef::Sony)` swaps it to `Sony`
    // for the sub-walk and restores it.
    active_table: TableRef::Exif,
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // The Sony Main IFD walk — `ProcessProc::Exif` (Sony needs NO Canon DataMember
  // pre-scan; the `if table == TableRef::Canon` hook is inert). `Fixed(order)` is
  // the parent order; `FixBaseMode::No` (offsets are already TIFF-relative). It
  // appends the Sony leaves to `w.entries` from index 0, isolating every core side
  // effect from the parent.
  w.process_subdir(
    ifd_offset,
    IfdKind::ExifIfd,
    TableRef::Sony,
    ByteOrderRule::Fixed(order),
    FixBaseMode::No,
    ProcessProc::Exif,
  );
  // Capture the walked `ResolvedConv::Sony` leaves into the vendor-emission `Vec`,
  // threading the `AFAreaILCx` DataMember 0x201c sets (read by 0x201e). Unlike
  // Apple/Canon this drives the dedicated `emit_sony_value` (the per-entry gates +
  // af_area + the gate-passing typed populate), NOT `emit_entry`. The family-1
  // group is the Sony vendor group (`vendor_group1_of(Sony)` = `"Sony"`);
  // `write_vendor_value` re-derives it from `MakerNote::emission_group1` for the
  // cached emissions, but pass the resolved value so the `EmittedTagSink` path (the
  // differential test) carries it too.
  //
  // The typed `MakerNotesSony` is built INSIDE this loop (via `emit_sony_value`'s
  // `Some(&mut typed)` step-7 populate) so a gated tag — e.g. a rawconv-dropped
  // 0xb041 — populates NEITHER the emission NOR `exposure_mode`, exactly as the
  // oracle's `parse_in_tiff` (which calls `populate_typed` only on a gate-passing
  // entry). A separate gate-free pass would diverge for the typed leaves that are
  // ALSO gated (0xb041 ∈ RAWCONV_DROP_IDS).
  let g1 = vendor_group1_of(TableRef::Sony).unwrap_or("Sony");
  let mut emissions = std::vec::Vec::new();
  let mut typed = sony::MakerNotesSony::new();
  let mut af_area: Option<i64> = None;
  {
    let mut sink = VendorEmissionSink::new(&mut emissions);
    for entry in &w.entries {
      // 0x201c's RawConv DataMember side-effect — captured BEFORE rendering so the
      // later 0x201e can read it (entries are in IFD-tag order, so 0x201c precedes
      // 0x201e), matching `parse_in_tiff`'s in-walk capture.
      if entry.tag_id == 0x201c {
        af_area = sony::af_area_data_member_from_raw(entry.value.raw(), model);
      }
      // Only `ResolvedConv::Sony` entries live in this run; the resolved `SonyTag`
      // rides in the entry's `conv`. A defensive non-Sony conv (never produced
      // under `TableRef::Sony`) is skipped — `emit_sony_value` needs the `SonyTag`.
      if let ResolvedConv::Sony(sony_tag) = entry.conv {
        let Ok(()) = emit_sony_value(
          g1,
          entry,
          sony_tag,
          model,
          af_area,
          print_conv,
          Some(&mut typed),
          &mut sink,
        );
      }
    }
  }
  Some((emissions, typed))
}

/// Walk the Panasonic `%Panasonic::Main` IFD in a FRESH, ISOLATED [`Walker`] over
/// the parent TIFF and capture its emissions + typed surface — the single GATED
/// entry point BOTH the `-j` production dispatch and the `-n` recompute drive
/// (#243 phase 3, structural isolation, mirroring [`sony_makernote_isolated`]).
///
/// ## The variant gate (FIRST)
///
/// The dispatcher collapses the THREE Panasonic `MakerNotes.pm` variants
/// (`:732-761`) to [`Vendor::Panasonic`], but only the two whose blob starts with
/// `Panasonic` use `%Panasonic::Main`: `MakerNotePanasonic` (no `Base` ⇒ inherit)
/// and `MakerNotePanasonic3` (DC-FT7, `Base => 12`). `MakerNotePanasonic2` (the
/// `MKE` Type2 blob) is a `ProcessBinaryData` table (`Panasonic.pm:2259`, NOT an
/// IFD over `%Panasonic::Main`), so running the Main walker on it is UNFAITHFUL.
/// This function applies
/// [`routes_to_main`](makernotes::vendors::panasonic::routes_to_main) on the
/// captured blob (`data[mn_offset .. mn_offset + mn_len]`, computed EXACTLY as
/// [`parse_main_gated`](makernotes::vendors::panasonic::parse_main_gated)) and
/// returns `None` for a non-Main blob — the caller leaves the Panasonic slot
/// ABSENT. This is the SAME gate the retired `parse_main_gated` oracle applies, so
/// the route classification cannot be bypassed. (The cross-table Leica1/Leica10
/// routes have their OWN make/signature gates on the `Vendor::Leica` arm, which
/// keeps its `parse_leica*_gated` oracle.)
///
/// ## The walk + the DYNAMIC BASE (byte-identity to `parse_in_tiff`)
///
/// The IFD count word sits at `mn_offset + HEADER_LEN` (12, the `Panasonic\0\0\0`
/// prefix — `MakerNotePanasonic`/`Panasonic3` both use it; the Leica 18/8 offsets
/// route elsewhere). The walk runs under `active_table == TableRef::Panasonic` via
/// [`process_subdir`](Walker::process_subdir) with `ProcessProc::Exif` — which
/// resolves the Panasonic table's own `Format =>` directives (the many `Writable
/// => 'int16u'` / `Format => 'int16s'` rows + the int32u-from-rational rows, just
/// as ExifTool's `ProcessExif` reads them off the active `$tagTablePtr`,
/// `Exif.pm:6729`), reproducing the oracle's `resolve_read_format` step.
///
/// `base_offset` is the KEY Panasonic difference from Sony/Canon/Apple: it is the
/// SubDirectory `Base =>` literal (0 for `MakerNotePanasonic`'s inherited base, 12
/// for `MakerNotePanasonic3`'s `Base => 12`), threaded into the Walker's
/// [`value_offset_base`](Walker::value_offset_base) so every OUT-OF-LINE value
/// pointer resolves at `data[off + base_offset]` — byte-identical to the oracle's
/// `walk_panasonic_in_tiff`'s `abs_off = off + base_offset` (`panasonic/
/// body.rs:150`). A base-0 read of a DC-FT7 value would land 12 bytes early
/// (corruption); the `value_offset_base` thread is what makes the shared-Walker
/// walk faithful for the `Base => 12` variant. Inline values (≤ 4 bytes) are never
/// shifted. The directory `kind` is `ExifIfd` (a non-Ifd0 kind, so the IFD0-only
/// Make/Model tap never fires); the bodies carry no MM/II marker, so the byte
/// order is the PARENT order.
///
/// ## The per-entry gates (the capture loop)
///
/// Panasonic's `%Main` render is gated per entry (an ABSENT tag, not a raw
/// fallback), so — unlike Apple/Canon's `emit_entry` capture — the loop drives the
/// dedicated [`emit_panasonic_value`] (reproducing `parse_in_tiff`'s
/// SubDirectory-skip / `$format`-gated single-HASH `Condition` / RawConv-drop /
/// 0xc5-0xe4-LensTypeModel-zero-drop / model-conditional-0x0f-0x2c gates). Unlike
/// Sony there is no in-IFD DataMember thread; the only context is the parent
/// `$$self{Model}` (for the 0x0f/0x2c branch selection). The typed
/// [`MakerNotesPanasonic`] is built INSIDE this loop (via `emit_panasonic_value`'s
/// `Some(&mut typed)` populate) so a gated tag — e.g. a rawconv-dropped 0xd1 —
/// populates NEITHER the emission NOR a typed field, exactly as the oracle.
///
/// ## Isolation
///
/// A FRESH `Walker` has its OWN `warnings` / `warn_count` / `active_ifd_offsets`,
/// populated by THIS walk and DISCARDED on return — so a malformed Panasonic entry
/// cannot leak a core `ExifTool:Warning`, abort the parent ExifIFD's warn-count,
/// or be suppressed by the parent's ancestor cycle guard (the oracle, an isolated
/// `walk_panasonic_in_tiff`, has none of these side effects either). `print_conv =
/// true` renders the `-j` emissions + the typed slot; `print_conv = false` the
/// `-n` emissions (the typed slot is the SAME for both and ALWAYS returned,
/// non-Option, matching `parse_in_tiff`).
#[cfg(feature = "alloc")]
fn panasonic_makernote_isolated(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  base_offset: usize,
  order: ByteOrder,
  model: Option<&str>,
  print_conv: bool,
) -> Option<(
  std::vec::Vec<makernotes::VendorEmission>,
  makernotes::vendors::panasonic::MakerNotesPanasonic,
)> {
  use makernotes::vendors::panasonic;
  // The variant gate FIRST — the captured MakerNote blob is the bytes the
  // dispatcher classified (`data[mn_offset .. mn_offset + mn_len]`), computed
  // EXACTLY as `parse_main_gated` (saturating end, clamped to the buffer). A blob
  // routing elsewhere (the `MKE` Type2 BinaryData) ⇒ `None` (the Panasonic slot
  // stays absent — no spurious Main tags).
  let blob_end = mn_offset.saturating_add(mn_len).min(data.len());
  let blob = data.get(mn_offset..blob_end)?;
  if !panasonic::routes_to_main(blob) {
    return None;
  }
  // Short-MakerNote guard (the oracle's `walk_panasonic_in_tiff:100` pre-check, in
  // the REVERSE direction): the dispatcher's variant-gate window must at least
  // contain the IFD count word INSIDE the declared MakerNote value (`mn_len >=
  // HEADER_LEN + 2`); below that the value has no room for an IFD. Without this, a
  // truncated MakerNote (e.g. the value is only `Panasonic\0\0\0`, `mn_len = 12`,
  // body offset `HEADER_LEN = 12`) would still walk `data` at `mn_offset +
  // HEADER_LEN` and read its count word from the UNRELATED following parent-TIFF
  // bytes — emitting spurious Panasonic tags the oracle (`walk_panasonic_in_tiff`,
  // which returns empty here) never does, and a migration regression vs the
  // pre-migration body walker. `routes_to_main` already classified the blob as a
  // Main variant, so the faithful result is present-but-empty (`Some((empty,
  // empty))`), NOT `None` (which would drop the typed slot the oracle's
  // `parse_in_tiff` still returns). The production body offset is always
  // [`HEADER_LEN`](panasonic::HEADER_LEN) (12 — the `Panasonic\0\0\0` prefix both
  // Main variants use); `HEADER_LEN + 2` is `checked_add`ed for the
  // usize-overflow class — an overflow can never satisfy `mn_len >=`, so it trips
  // the guard exactly as the oracle's `<` test does. (The cross-table Leica1/
  // Leica10 routes — body offset 8/18 — go through `parse_leica*_gated`, not this
  // helper, so the constant `HEADER_LEN` is the only body offset reachable here.)
  match panasonic::HEADER_LEN.checked_add(2) {
    Some(min_len) if mn_len >= min_len => {}
    _ => {
      return Some((std::vec::Vec::new(), panasonic::MakerNotesPanasonic::new()));
    }
  }
  // The IFD sits at `mn_offset + HEADER_LEN` (12) in `data` — the
  // `Panasonic\0\0\0` prefix both Main variants use (`MakerNotes.pm:738`/`:757`).
  // A body offset past the buffer yields an empty walk (no entries) — the oracle's
  // same out-of-bounds guard; `process_subdir` is bounds-checked.
  let ifd_offset = mn_offset.saturating_add(panasonic::HEADER_LEN);
  let mut w = Walker {
    data,
    order,
    // `%Panasonic::Main` carries no `IsOffset`/`SubIFD` tag, so the walk never adds
    // `base` to a value — `base: 0`. The DC-FT7 `Base => 12` out-of-line shift is
    // the SEPARATE `value_offset_base` below (the `$dataPos`-shift addend), NOT
    // `base` (the `IsOffset` file-offset addend, unused by Panasonic Main).
    base: 0,
    // THE DYNAMIC BASE — the SubDirectory `Base =>` literal: 0 for
    // `MakerNotePanasonic` (inherit), 12 for `MakerNotePanasonic3` (DC-FT7). Every
    // out-of-line value pointer resolves at `data[off + base_offset]`,
    // byte-identical to `walk_panasonic_in_tiff`'s `off + base_offset`
    // (`panasonic/body.rs:150`).
    value_offset_base: base_offset,
    entries: Vec::new(),
    // FRESH warning channels: a malformed Panasonic entry warns into THESE, dropped
    // on return — never the parent's `ExifTool:Warning` stream (the oracle
    // `walk_panasonic_in_tiff` silently `continue`s a bad entry, emitting no
    // warning).
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    // `$$self{Model}` selects the 0x0f AFAreaMode / 0x2c ContrastMode branches; the
    // Panasonic walk itself reads no model-conditional structure, but the captured
    // model is threaded into the capture-loop gates below (not into the walk), so
    // leave it unset on the Walker.
    captured_model: None,
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    // EMPTY active path: the fresh walker has NO ancestor on its recursion stack,
    // so a Panasonic value offset that coincides with a PARENT IFD offset is still
    // walked — the oracle, also pathless, always walks it.
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    // No Panasonic Main leaf reads `$$self{FILE_TYPE}`.
    file_type: None,
    // The parent TIFF block IS the readable buffer (an effective RAF), like the
    // dispatch walk.
    no_raf: false,
    warn_count: 0,
    // Starts on the Exif table; `process_subdir(TableRef::Panasonic)` swaps it to
    // `Panasonic` for the sub-walk and restores it.
    active_table: TableRef::Exif,
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // The Panasonic Main IFD walk — `ProcessProc::Exif` (Panasonic needs NO Canon
  // DataMember pre-scan; the `if table == TableRef::Canon` hook is inert).
  // `Fixed(order)` is the parent order; `FixBaseMode::No` (offsets are already
  // resolved via `value_offset_base`). It appends the Panasonic leaves to
  // `w.entries` from index 0, isolating every core side effect from the parent.
  w.process_subdir(
    ifd_offset,
    IfdKind::ExifIfd,
    TableRef::Panasonic,
    ByteOrderRule::Fixed(order),
    FixBaseMode::No,
    ProcessProc::Exif,
  );
  // Capture the walked `ResolvedConv::Panasonic` leaves into the vendor-emission
  // `Vec`. Unlike Apple/Canon this drives the dedicated `emit_panasonic_value` (the
  // per-entry gates + the gate-passing typed populate), NOT `emit_entry`. The
  // family-1 group is the Panasonic vendor group (`vendor_group1_of(Panasonic)` =
  // `"Panasonic"`); `write_vendor_value` re-derives it from
  // `MakerNote::emission_group1` for the cached emissions, but pass the resolved
  // value so the `EmittedTagSink` path (the differential test) carries it too.
  //
  // The typed `MakerNotesPanasonic` is built INSIDE this loop (via
  // `emit_panasonic_value`'s `Some(&mut typed)` populate) so a gated tag — e.g. a
  // rawconv-dropped 0xd1 — populates NEITHER the emission NOR a typed field,
  // exactly as the oracle's `parse_in_tiff` (which calls `populate_typed` only on a
  // gate-passing entry).
  let g1 = vendor_group1_of(TableRef::Panasonic).unwrap_or("Panasonic");
  let mut emissions = std::vec::Vec::new();
  let mut typed = panasonic::MakerNotesPanasonic::new();
  {
    let mut sink = VendorEmissionSink::new(&mut emissions);
    for entry in &w.entries {
      // Only `ResolvedConv::Panasonic` entries live in this run; the resolved
      // `PanasonicTag` rides in the entry's `conv`. A defensive non-Panasonic conv
      // (never produced under `TableRef::Panasonic`) is skipped —
      // `emit_panasonic_value` needs the `PanasonicTag`.
      if let ResolvedConv::Panasonic(panasonic_tag) = entry.conv {
        let Ok(()) = emit_panasonic_value(
          g1,
          entry,
          panasonic_tag,
          model,
          print_conv,
          Some(&mut typed),
          &mut sink,
        );
      }
    }
  }
  Some((emissions, typed))
}

/// Walk the Nikon `%Nikon::Main` (or `%Nikon::Type2`) IFD in a FRESH, ISOLATED
/// [`Walker`] over the parent TIFF / the captured blob and capture its emissions
/// + typed surface — the single entry point BOTH the `-j` production dispatch and
/// the `-n` recompute drive (#243 phase 3-bis, structural isolation, mirroring
/// [`sony_makernote_isolated`]).
///
/// ## Layout pre-parse (no new Walker mode)
///
/// [`resolve_layout`](makernotes::vendors::nikon::resolve_layout) classifies the
/// captured blob (`data[mn_offset .. mn_offset + mn_len]`, the bytes the
/// dispatcher saw) into the SAME `(slice, ifd_offset, order, value_base, table)`
/// the oracle [`parse_in_tiff`](makernotes::vendors::nikon::parse_in_tiff) walks:
/// the type-3 embedded-TIFF (MM/II marker @blob[10], fixed IFD@tiff_at+8,
/// value_base 10), type-2 (IFD @8, FIXED LittleEndian, base 0), and headerless
/// Nikon3 (IFD @0, parent order, base 0). `None` for a blob too short/malformed
/// to resolve — the caller leaves the Nikon slot ABSENT (no spurious tags), like
/// `parse_in_tiff` returning empties.
///
/// ## ★ CRUX #1 — the type-3 walk slice / value base (byte-identity stakes)
///
/// For **type-3** the Walker is built over the SAME `blob` SUB-SLICE
/// `walk_nikon_ifd` uses (NOT the full `data`), with the IFD at
/// `layout.ifd_offset` WITHIN that blob and
/// [`value_offset_base`](Walker::value_offset_base) `= layout.value_base` (10) —
/// reproducing the oracle's out-of-line resolution `abs = off + value_base`
/// (`body.rs:482`) AND preserving the directory-extent bound at `blob.len()`
/// (`walk_nikon_ifd` bounds type-3 to the captured blob, `body.rs:350`). Walking
/// the full `data` with a shifted base would bound to `data.len()` and DIVERGE
/// the suspicious-offset / dir-end gates. For **type-2 / headerless** the Walker
/// walks `data` at `mn_offset + layout.ifd_offset` with `value_offset_base = 0`
/// (Sony-identical, offsets are parent-TIFF-relative). `base: 0` always — Nikon's
/// `%Main`/`%Type2` carry no `Base =>`-driven `base` rebase (out-of-line
/// resolution is the `value_offset_base` addend, the Panasonic pattern).
/// `ByteOrderRule::Fixed(layout.order)` — [`parse_embedded_tiff`](makernotes::vendors::nikon::body::parse_embedded_tiff)
/// already probed the type-3 marker (LE is explicit for type-2, the parent order
/// inherited for headerless), so NO re-probe.
///
/// ## The decrypt-key prescan (Option A — NOT the shared Walker)
///
/// The keys are captured via the EXISTING
/// [`scan_decrypt_keys`](makernotes::vendors::nikon::scan_decrypt_keys) /
/// `body::prescan_decrypt_keys` UNCHANGED, called over the SAME
/// `(walk_data, ifd_offset, order, value_base, model)` the emit pass walks, for
/// the Main table only. This is faithful to ExifTool's `PrescanExif` (LOOSER
/// gates than `ProcessExif` — no suspicious-offset / excessive-count / warn-abort)
/// — the shared Walker's gates would DROP a key the prescan still captures (the
/// `prescan_captures_key_past_walk_warn_abort` proof). The keys are
/// identical-by-construction (same fn, same args as `parse_in_tiff`).
///
/// ## ★ CRUX #2 — feeding the sub-table emitters the value block (option (i))
///
/// The five sub-table emitters (`emit_af_info` / `emit_color_balance` /
/// `emit_flash_info` / `emit_shot_info` / `emit_lens_data`) take the value
/// `block: &[u8]` (the N2a refactor). The shared `Walker` MATERIALIZES that block
/// into `entry.value`: the Nikon implicit-`undef` `format_override`
/// (`Exif.pm:6733`) makes the Walker read a binary SubDirectory value as
/// `undef[N]`, and [`read_value`]'s `Format::Undef` arm yields
/// `RawValue::Bytes(data[value_offset .. value_offset + size])` — byte-FOR-byte
/// what `parse_in_tiff` slices (`walk_data[value_offset .. value_offset +
/// value_size]`, `mod.rs:380`). So the capture loop slices `block` straight off
/// `entry.value.raw()`'s `Bytes` (option (i): the Walker isn't zero-copying the
/// SubDirectory value away — `read_value` owns the decoded copy). A degenerate
/// 1-byte SubDirectory hits the int8u carve-out (`Format::Undef` + `count == 1` ⇒
/// `RawValue::U64`), which the slice helper treats as `&[]` — matching the oracle,
/// whose 1-byte block is too short for ANY sub-table member (every emitter's
/// `sub.get(0..4)` version read returns `None` ⇒ emits nothing). NOTE this
/// materialization is the ONE structural difference from the oracle's zero-copy
/// `RawValue::Bytes(Vec::new())` (`body.rs:659`): the shared-Walker path keeps the
/// decoded block in `entry.value` instead of re-slicing `walk_data`; the BYTES
/// the emitter sees are identical, only the lifetime/ownership differs.
///
/// ## The positional `FocusMode` DataMember
///
/// `$$self{FocusMode}` (tag 0x0007 RawConv, `Nikon.pm:1816`) gates the
/// LensData0800 Z telemetry; like the oracle (`mod.rs:352-363`) the capture loop
/// tracks the LAST 0x0007 text BEFORE the current entry, Main table only (the
/// Type2 table reuses 0x0007 for a different tag), and threads it into
/// `emit_lens_data`.
///
/// ## Isolation
///
/// A FRESH `Walker` has its OWN `warnings` / `warn_count` / `active_ifd_offsets` /
/// `chain_guard`, populated by THIS walk and DISCARDED on return (like Sony
/// `@7315-7359`, `captured_model` left `None`) — so a malformed Nikon entry cannot
/// leak a core `ExifTool:Warning`, abort the parent ExifIFD's warn-count, or be
/// suppressed by the parent's ancestor cycle guard (the oracle, an isolated
/// `walk_nikon_ifd`, has none of these side effects either). `print_conv = true`
/// renders the `-j` emissions + the typed slot; `print_conv = false` the `-n`
/// emissions (the typed slot is the SAME for both and ALWAYS returned, non-Option,
/// matching `parse_in_tiff`).
#[cfg(feature = "alloc")]
fn nikon_makernote_isolated(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  model: Option<&str>,
  print_conv: bool,
) -> Option<(
  std::vec::Vec<makernotes::VendorEmission>,
  makernotes::vendors::nikon::MakerNotesNikon,
)> {
  use makernotes::vendors::nikon::{self, MakerNotesNikon, ParsedValue, SubTable};
  // The captured MakerNote bytes the dispatcher classified (`data[mn_offset ..
  // mn_offset + mn_len]`, saturating end clamped to the buffer) — computed EXACTLY
  // as `parse_in_tiff` (`nikon/mod.rs:294-297`).
  let mn_end = mn_offset.saturating_add(mn_len).min(data.len());
  let blob = data.get(mn_offset..mn_end)?;
  // Layout pre-parse — the SAME `resolve_layout` the oracle runs. `None` for a
  // blob too short/malformed to walk (the Nikon slot stays absent).
  let layout = nikon::resolve_layout(blob, parent_order)?;
  // Short-MakerNote guard — the captured MakerNote VALUE must contain the IFD
  // count word, mirroring `parse_in_tiff`'s guard EXACTLY (so this isolated path
  // and the oracle stay byte-identical). For the type-2 / headerless layouts the
  // walk reads `data` at `mn_offset + ifd_offset`; the count word at
  // `[mn_offset+ifd_offset, +2)` must sit INSIDE the declared value
  // (`ifd_offset + 2 <= mn_len`), else a truncated `mn_len` lets the Walker read
  // its count word from the UNRELATED following parent-TIFF bytes — spurious tags
  // neither the oracle (`walk_nikon_ifd` over `data`, but `parse_in_tiff` now
  // guards it) nor ExifTool produces. The type-3 layout is self-contained (the
  // window IS `blob`, already bounds-checked by `parse_embedded_tiff`), so its
  // window measure is `blob.len()`. `resolve_layout` already classified the blob,
  // so the faithful result is present-but-empty (`Some((empty, empty))`), NOT
  // `None` (which would drop the typed slot the oracle still returns). The Sony
  // pattern (`sony_makernote_isolated` @ the `body_offset + 2` guard).
  let window = if layout.walk_in_blob() {
    blob.len()
  } else {
    mn_len
  };
  match layout.ifd_offset().checked_add(2) {
    Some(min) if window >= min => {}
    _ => {
      return Some((std::vec::Vec::new(), MakerNotesNikon::new()));
    }
  }
  // ★ CRUX #1 — choose the slice + IFD offset + value base the Walker operates on.
  // type-3 walks the captured BLOB (self-contained embedded TIFF, value_base 10,
  // directory bounded at `blob.len()`); type-2 / headerless walk the PARENT TIFF
  // `data` (offsets parent-TIFF-relative, value_base 0). This is byte-identical to
  // `parse_in_tiff`'s `(walk_data, ifd_offset)` choice (`nikon/mod.rs:307-311`),
  // with `value_offset_base = layout.value_base` reproducing the oracle's
  // `abs = off + value_base` out-of-line resolution (`body.rs:482`).
  let (walk_data, ifd_offset): (&[u8], usize) = if layout.walk_in_blob() {
    (blob, layout.ifd_offset())
  } else {
    (data, mn_offset.saturating_add(layout.ifd_offset()))
  };
  let order = layout.order();
  let table_ref = match layout.table() {
    nikon::NikonTable::Main => TableRef::Nikon,
    nikon::NikonTable::Type2 => TableRef::NikonType2,
  };
  // The decrypt-key PRESCAN (Option A) — the EXACT `scan_decrypt_keys` the oracle
  // runs (`nikon/mod.rs:327-337`), over the SAME `(walk_data, ifd_offset, order,
  // value_base, model)` the emit pass below walks, for the Main table ONLY (the
  // Type2 layout has no encrypted sub-tables / 0x001d/0x00a7 semantics). Faithful
  // to ExifTool's separate `PrescanExif` (looser gates than the shared Walker's
  // `ProcessExif`); keys are identical-by-construction to the oracle's.
  let decrypt_keys = if layout.table() == nikon::NikonTable::Main {
    nikon::scan_decrypt_keys(walk_data, ifd_offset, order, layout.value_base(), model)
  } else {
    None
  };
  // The EMIT pass — a FRESH isolated `Walker` over `walk_data` (base 0; the
  // out-of-line shift is the `value_offset_base` addend, the Panasonic pattern).
  // Its `warnings` / `warn_count` / `active_ifd_offsets` / `chain_guard` are
  // DISCARDED on return (Sony-identical isolation); `captured_model` stays `None`
  // (the IFD0-only Make/Model tap never fires under the non-Ifd0 `ExifIfd` kind).
  let mut w = Walker {
    data: walk_data,
    order,
    base: 0,
    // ★ CRUX #1 — the out-of-line value base: 10 for type-3 (embedded-TIFF
    // `Base => '$start - 8'`), 0 for type-2 / headerless. Reproduces the oracle's
    // `abs = off + value_base`.
    value_offset_base: layout.value_base(),
    entries: Vec::new(),
    // FRESH warning channels: a malformed Nikon entry warns into THESE, dropped on
    // return — never the parent's `ExifTool:Warning` stream (the oracle
    // `walk_nikon_ifd` silently `continue`s a bad entry, emitting no warning).
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    // `$$self{Model}` gates the AFInfo BigEndian read + the LensData Z telemetry;
    // it is threaded into the capture-loop emitters (NOT the walk), so leave it
    // unset on the Walker.
    captured_model: None,
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    // EMPTY active path: the fresh walker has NO ancestor on its recursion stack,
    // so a Nikon value offset that coincides with a PARENT IFD offset is still
    // walked — the oracle, also pathless, always walks it.
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    // No Nikon Main/Type2 leaf reads `$$self{FILE_TYPE}`.
    file_type: None,
    // The chosen walk buffer IS the readable buffer (an effective RAF), like the
    // dispatch walk.
    no_raf: false,
    warn_count: 0,
    // Starts on the Exif table; `process_subdir(table_ref)` swaps it to the Nikon
    // Main/Type2 table for the sub-walk and restores it.
    active_table: TableRef::Exif,
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // The Nikon Main/Type2 IFD walk — `ProcessProc::Exif` (Nikon needs NO Canon
  // DataMember pre-scan; the `if table == TableRef::Canon` hook is inert).
  // `Fixed(order)` is the resolved order (embedded marker / explicit LE /
  // inherited); `FixBaseMode::No` (the `value_offset_base` carries the rebase).
  // `IfdKind::ExifIfd` is a non-Ifd0 kind, so the IFD0-only Make/Model tap never
  // fires. It appends the Nikon leaves to `w.entries` from index 0, isolating
  // every core side effect from the parent. The Nikon table's implicit-`undef`
  // SubDirectory `format_override` materializes each binary sub-table value as
  // `undef[N]` into `entry.value` (CRUX #2).
  w.process_subdir(
    ifd_offset,
    IfdKind::ExifIfd,
    table_ref,
    ByteOrderRule::Fixed(order),
    FixBaseMode::No,
    ProcessProc::Exif,
  );
  // Capture the walked `ResolvedConv::Nikon` leaves + sub-tables into the
  // vendor-emission `Vec`. The typed `MakerNotesNikon` is built from the Main-table
  // LEAVES only (the Type2 walk passes `typed: None` — the IDs 0x0003..0x000b name
  // different tags, so populating the Main-semantic fields would mislabel them, the
  // oracle's `nikon/mod.rs:429` gate). Sub-tables push to `emissions` only (they
  // carry no typed convenience field).
  let g1 = vendor_group1_of(TableRef::Nikon).unwrap_or("Nikon");
  let typed_main = layout.table() == nikon::NikonTable::Main;
  // The positional `$$self{FocusMode}` (last 0x0007 BEFORE the current entry, Main
  // only) — the LensData0800 Z-telemetry gate, exactly as `parse_in_tiff`
  // (`nikon/mod.rs:351-363`).
  let track_focus_mode = typed_main;
  let mut focus_mode: Option<smol_str::SmolStr> = None;
  let mut emissions = std::vec::Vec::new();
  let mut typed = MakerNotesNikon::new();
  {
    let mut sink = VendorEmissionSink::new(&mut emissions);
    for entry in &w.entries {
      // Track the running `$$self{FocusMode}` the instant tag 0x0007 is walked,
      // BEFORE any later 0x0098 LensData reaches its emitter (entries are in IFD
      // walk order). A non-`Text` 0x0007 leaves the member unchanged (the oracle's
      // `as_text` → keep prior value).
      if track_focus_mode
        && entry.tag_id == 0x0007
        && let Some(s) = ParsedValue::new(entry.value.raw().clone()).as_text()
      {
        focus_mode = Some(smol_str::SmolStr::new(s));
      }
      // Only `ResolvedConv::Nikon` entries live in this run; the resolved
      // `NikonTag` rides in the entry's `conv`. A defensive non-Nikon conv (never
      // produced under `TableRef::Nikon`/`NikonType2`) is skipped.
      let ResolvedConv::Nikon(nikon_tag) = entry.conv else {
        continue;
      };
      if let Some(sub) = nikon_tag.sub_table() {
        // ★ CRUX #2 — the SubDirectory value block: re-slice the ON-DISK value SPAN
        // from the Walker's buffer at the entry's resolved `value_offset` +
        // on-disk `value_size`, EXACTLY as the oracle's
        // `walk_data[value_offset .. value_offset + value_size]`
        // (`nikon/mod.rs:449-452`). Reading the SPAN — not the decoded `entry.value`
        // — is the make-or-break correctness point: the shared Walker applies the
        // generic `undef[1] → int8u` carve-out (`Exif.pm:6644`) to a degenerate
        // `undef`-format, count-1 SubDirectory entry, so its `entry.value` is a
        // SCALAR int8u (NOT `RawValue::Bytes`); deriving `block` from the value
        // shape would pass `&[]` and the emitter would (wrongly) emit nothing,
        // whereas the oracle slices the 1 inline byte and `emit_af_info` reads its
        // offset-0 member. The span is shape-INDEPENDENT, so it matches the oracle
        // for inline / out-of-line / type-3 alike (`w.data` == the oracle's
        // `walk_data`, `value_offset` == its `value_data_offset`, `value_size` ==
        // its `total_size`; verified by the differential edge-matrix). An
        // out-of-bounds extent yields `&[]` (the emitter then emits nothing,
        // matching the oracle's `get(..)` → `None`). A deferred (encrypted /
        // unported) subdir emits NOTHING — neither parent nor children (the
        // #177/#223 bogus-parent rule), exactly like `parse_in_tiff`.
        let block: &[u8] = entry
          .value_offset()
          .checked_add(entry.value_size())
          .and_then(|end| w.data.get(entry.value_offset()..end))
          .unwrap_or(&[]);
        match sub {
          SubTable::AfInfo => nikon::emit_af_info(block, print_conv, model, &mut *sink.emissions),
          SubTable::ColorBalance0103 => {
            nikon::emit_color_balance(block, order, print_conv, &mut *sink.emissions);
          }
          SubTable::LensData => nikon::emit_lens_data(
            block,
            order,
            print_conv,
            decrypt_keys,
            focus_mode.as_deref(),
            &mut *sink.emissions,
          ),
          SubTable::FlashInfo => {
            nikon::emit_flash_info(block, order, print_conv, &mut *sink.emissions);
          }
          SubTable::ShotInfo => {
            nikon::emit_shot_info(block, print_conv, decrypt_keys, &mut *sink.emissions);
          }
          // Deferred (encrypted / unported child table): emit nothing.
          SubTable::ColorBalanceEncrypted | SubTable::OtherDeferred => {}
        }
        continue;
      }
      // Leaf tag — the dedicated `emit_nikon_value` (the `RawConv => … : undef`
      // drop + the byte-order/model thread + the gate-passing typed populate),
      // exactly as `parse_in_tiff`'s leaf branch. `typed: None` for the Type2 walk.
      let typed_sink = typed_main.then_some(&mut typed);
      let Ok(()) = emit_nikon_value(
        g1, entry, nikon_tag, model, order, print_conv, typed_sink, &mut sink,
      );
    }
  }
  Some((emissions, typed))
}

/// Walk the Canon Main IFD in a FRESH, ISOLATED [`Walker`] and capture its
/// emissions — the single entry point BOTH the `-j` production dispatch and the
/// `-n` recompute drive (#243 phase 2 step C, structural isolation).
///
/// ## Why a fresh Walker (the structural fix)
///
/// Canon's `%Main` is a vendor table whose walk must have NO effect on the
/// parent TIFF walk's CORE state. The earlier production switch reused the parent
/// `Walker` via `process_subdir`, which shared every mutable field — and each one
/// is a core-state leak the retired `canon::parse_in_tiff` oracle (an isolated
/// `walk_canon_in_tiff`) does not have:
///
/// * `warnings` / `warnings_ignorable` — a malformed Canon entry warns
///   `"Bad offset for ExifIFD <tag>"` (the directory `kind` is `ExifIfd`); on the
///   parent that core ExifIFD `$et->Warn` would surface as an `ExifTool:Warning`
///   the oracle never emits.
/// * `active_ifd_offsets` — the parent's ACTIVE recursion path holds the IFD0 /
///   ExifIFD offsets; a Canon MakerNote whose value offset coincides with an
///   ancestor (e.g. 8, the IFD0 offset) would hit the ancestor cycle guard in
///   [`walk_one_ifd`](Walker::walk_one_ifd) and be SUPPRESSED — the oracle, with
///   an empty path, always walks it.
/// * `warn_count` / `page_count` / `multi_page` / `dng_version` — the per-call
///   `$warnCount` abort cap and the file-level RawConv-tap DataMembers.
///
/// A fresh `Walker` over the SAME `data` (base 0, the Canon Main IFD at
/// `mn_offset`) has its OWN of every field; they are populated by THIS walk and
/// DISCARDED on return — none touches the parent. The within-walk Canon gates
/// (the `sub_dir_for`/bad-offset/SubfileType/DNGVersion `active_table` guards in
/// [`walk_entry`](Walker::walk_entry)) still apply, so the fresh walk is correct;
/// because it is isolated, even their effects (an empty `warnings`, an
/// untouched `dng_version`) never leave this function.
///
/// ## Byte-identity to `parse_in_tiff`
///
/// The Canon walk reads the same bytes through the same machinery regardless of
/// container: Canon's `%Main` has no `IsOffset`/`SubIFD` tag, so the walk never
/// consults [`Walker::base`] (a `base: 0` fresh walker walks the same entries the
/// parent-context walk did — the retired `canon::parse_in_tiff` likewise took no
/// base), and the directory `kind` is `ExifIfd` (so the IFD0-only Make/Model
/// capture tap never fires). The `%CameraSettings` DataMember pre-scan runs
/// inside `process_subdir` exactly as the oracle's pre-pass does, and
/// [`capture_canon_emissions`](Walker::capture_canon_emissions) reproduces the
/// oracle's leaf/sub-table/special render stream — for BOTH `print_conv` modes.
///
/// ## Return
///
/// The captured `Vec<VendorEmission>` for `print_conv` (PrintConv `-j` /
/// ValueConv `-n`), plus — only when `print_conv == true` (the production `-j`
/// dispatch, which also wants the typed surface) — the typed `MakerNotesCanon`
/// built from the SAME walked entries via [`populate_canon_typed`] (it reads the
/// post-walk `$$self{LensType}` the pre-scan captured). The `-n` recompute passes
/// `false` and ignores the `None` typed slot.
///
/// `mn_len` is the MakerNote read length the dispatch captured (the 0x927c value
/// window); the Canon walk reads its own IFD entry-count + per-entry extents from
/// `data` at `mn_offset` (it does not slice to `mn_len`), so the parameter is
/// carried for symmetry with the decode inputs, not consumed by the walk.
#[cfg(feature = "alloc")]
fn canon_makernote_isolated(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  order: ByteOrder,
  model: Option<&str>,
  file_type: Option<&str>,
  print_conv: bool,
) -> (
  std::vec::Vec<makernotes::VendorEmission>,
  Option<makernotes::vendors::canon::MakerNotesCanon>,
) {
  // The SAME entry-region guard `walk_canon_in_tiff` applies at its top
  // (`body.rs:299` `if mn_offset + 2 > tiff_data.len() || mn_len < 2 { return }`):
  // the IFD count word must be readable AND the captured `0x927c` value window
  // must hold at least that count word (`mn_len >= 2`). A short/truncated Canon
  // MakerNote (e.g. a 0x927c with count 0 or 1) is REJECTED here, exactly as the
  // oracle rejects it — so the fresh Walker never re-reads inline padding / the
  // following ExifIFD bytes as a Canon Main IFD and never emits bogus
  // MakerNotesCanon data past the declared MakerNote extent. (Inside the walk,
  // the directory extent + out-of-line value offsets bound against
  // `data.len()`, NOT `mn_len`, identically to the oracle, whose `data_len` is
  // likewise `tiff_data.len()`; `mn_len` only gates this `< 2` short-directory
  // check — `body.rs:308`.) The walk produces NO emissions either way, but the
  // typed surface is still installed to match the retired oracle: `parse_in_tiff`
  // ALWAYS returns a `MakerNotesCanon` (an EMPTY `MakerNotesCanon::new()` for a
  // short/rejected MakerNote — the walk yields no entries but the caller still
  // installs the typed slot), so a detected-but-short Canon MakerNote must keep
  // `canon() == Some(empty)`, NOT collapse to `None` — a typed-API divergence the
  // byte-identical JSON gate cannot see (#243 phase 2 R8). Mirror the non-short
  // policy below (`print_conv.then(...)`): an empty typed slot in `-j`, `None` in
  // `-n` (the `-n` recompute discards the typed slot regardless).
  if mn_len < 2 || mn_offset.checked_add(2).is_none_or(|end| end > data.len()) {
    let typed = print_conv.then(makernotes::vendors::canon::MakerNotesCanon::new);
    return (std::vec::Vec::new(), typed);
  }
  let mut w = Walker {
    data,
    order,
    // Canon's `%Main` carries no `IsOffset`/`SubIFD` tag, so the walk never adds
    // `base` to a value (`is_offset_tag` matches only 0x0111/0x0201, absent from
    // `%Canon::Main`) — `base: 0` is byte-identical to the parent-context walk.
    base: 0,
    // Inherit-base vendor walk — out-of-line offsets are already TIFF-relative
    // (child `$dataPos == 0`), so no value-pointer shift.
    value_offset_base: 0,
    entries: Vec::new(),
    // FRESH warning channels: a malformed Canon entry warns into THESE, which are
    // dropped on return — never the parent's `ExifTool:Warning` stream (the
    // oracle `parse_in_tiff` emits no such warning).
    warnings: Vec::new(),
    warnings_ignorable: Vec::new(),
    maker_note: None,
    captured_make: None,
    // `$$self{Model}` (the conditional `SerialNumber` PrintConv is `-j`-only, but
    // the model also gates the 0x96 SerialInfo LIST + ShotInfo branches the `-n`
    // walk traverses).
    captured_model: model.map(String::from),
    chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
    cycle_guard_warnings: Vec::new(),
    // EMPTY active path: the fresh walker has NO ancestor on its recursion stack,
    // so a Canon MakerNote whose value offset coincides with a PARENT IFD offset
    // (e.g. 8) is still walked — the oracle, also pathless, always walks it. The
    // parent's path-cycle guard cannot suppress this isolated walk.
    active_ifd_offsets: Vec::new(),
    page_count: 0,
    multi_page: false,
    dng_version: false,
    // `$$self{FILE_TYPE}` — the `Canon::ShotInfo` pos-22 CRW-allows-0 RawConv.
    file_type: file_type.map(smol_str::SmolStr::new),
    // The parent TIFF block IS the readable buffer (an effective RAF), like the
    // dispatch walk — only the CTMD `0x8769` hop is no-RAF.
    no_raf: false,
    warn_count: 0,
    // Starts on the Exif table; `process_subdir(TableRef::Canon)` swaps it to
    // `Canon` for the sub-walk and restores it.
    active_table: TableRef::Exif,
    // Repopulated by the Canon pre-scan inside `process_subdir`.
    canon_focal_units: None,
    canon_lens_type: None,
    canon_focal_length_blob: None,
  };
  // The Canon Main IFD walk — the SAME `process_subdir` entry the recompute used
  // (`IfdKind::ExifIfd` directory kind, fixed parent order, no FixBase, the Canon
  // ProcessProc that runs the DataMember pre-scan). It appends the Canon leaves
  // to `w.entries` from index 0. Running it on a FRESH walker is what isolates
  // every core side effect (warnings / active-path / warn_count / file-level
  // taps) from the parent.
  w.process_subdir(
    mn_offset,
    IfdKind::ExifIfd,
    TableRef::Canon,
    ByteOrderRule::Fixed(order),
    FixBaseMode::No,
    ProcessProc::Canon,
  );
  let emissions = w.capture_canon_emissions(0, print_conv);
  // The typed surface is only needed by the `-j` production dispatch; the `-n`
  // recompute discards it. Build it from the SAME walked entries (the pre-scanned
  // `$$self{LensType}` the FileInfo typed decode reads is on `w` post-walk).
  let typed = print_conv.then(|| {
    populate_canon_typed(
      &w.entries,
      order,
      w.captured_model.as_deref(),
      w.file_type.as_deref(),
      w.canon_lens_type,
    )
  });
  (emissions, typed)
}

// ====================================================================// Exif value emission — applies a `Conv` to a `RawValue`
// ====================================================================
/// Render a [`RawValue`] under a plain Exif [`Conv`] into the sink. This is
/// the serialize-time PrintConv/ValueConv application; the value stored in
/// the `ExifEntry` is post-Format-decode but pre-conversion.
///
/// `order` is the TIFF byte order in effect — threaded to the
/// `Conv::ExifText` UTF-16 `Unknown` order guess (`ConvertExifText`,
/// `Exif.pm:5554-5601`); every other arm ignores it.
#[cfg(feature = "alloc")]
fn emit_exif_value<S: ExifSink>(
  group: &str,
  name: &str,
  raw: &RawValue,
  conv: Conv,
  order: ByteOrder,
  print_conv: bool,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  match conv {
    Conv::None => emit_raw(group, name, raw, out),
    Conv::IntLabel(slice) => emit_int_label(group, name, raw, slice, print_conv, out, false),
    Conv::IntLabelHex(slice) => emit_int_label(group, name, raw, slice, print_conv, out, true),
    Conv::StrLabel(slice) => {
      // STRING-keyed HASH PrintConv (`InteropIndex` 0x0001, Exif.pm:417-427).
      // The on-disk value is a `string`; `read_value` already NUL-trimmed it.
      if let RawValue::Text { text: t, .. } = raw {
        // Trim a trailing NUL/space the on-disk `string` may carry.
        let key = t.trim_end_matches([' ', '\0']);
        if print_conv {
          match tables::str_label_for(slice, key) {
            Some(label) => out.write_str(group, name, label)?,
            // `sprintf('Unknown ($val)')` (no `OTHER`/`PrintHex` on these
            // string enums, ExifTool.pm:3627).
            None => out.write_str(group, name, &std::format!("Unknown ({key})"))?,
          }
        } else {
          // `-n` ⇒ the raw token.
          out.write_str(group, name, key)?;
        }
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::ExposureTime | Conv::ShutterSpeedApex => {
      // ExposureTime: raw rational seconds → PrintExposureTime.
      // ShutterSpeedValue: ValueConv `2 ** -$val` first (Exif.pm:2346),
      // then PrintExposureTime. `-n` mode emits the post-ValueConv scalar.
      let secs = match conv {
        Conv::ShutterSpeedApex => first_scalar(raw).map(shutter_speed_value_conv),
        _ => first_scalar(raw),
      };
      match secs {
        Some(s) if print_conv => {
          // PrintExposureTime → `1/724` (out of gate ⇒ string) or a whole/`%.1f`
          // second count like `30` (in gate ⇒ a bare JSON number). Gate it.
          emit_gated_number(group, name, &tables::print_exposure_time(s), out)?;
        }
        Some(s) => emit_gated_f64(group, name, s, out)?,
        None => emit_raw(group, name, raw, out)?,
      }
      Ok(())
    }
    Conv::FNumber => {
      // FNumber has no ValueConv — the raw rational quotient IS the f-number.
      match first_scalar(raw) {
        // PrintFNumber → `%.1f`/`%.2f` (`0.64`, `4.0`) — an in-gate JSON number.
        Some(v) if print_conv => {
          emit_gated_number(group, name, &tables::print_fnumber(v), out)?;
        }
        Some(_) | None => emit_raw(group, name, raw, out)?,
      }
      Ok(())
    }
    Conv::FocalLengthMm => {
      // `FocalLength` (0x920a) — `sprintf("%.1f mm",$val)` (Exif.pm:2425).
      // A rational64u; rendered with exactly one decimal place.
      match first_scalar(raw) {
        Some(v) if print_conv => {
          out.write_str(group, name, &std::format!("{v:.1} mm"))?;
        }
        Some(_) | None => emit_raw(group, name, raw, out)?,
      }
      Ok(())
    }
    Conv::FocalLength35mm => {
      // `FocalLengthIn35mmFormat` (0xa405) — `PrintConv => '"$val mm"'`
      // (Exif.pm:2896). `$val` is the post-ValueConv scalar (0xa405 has no
      // ValueConv) stringified by `ReadValue`. The tag is normally `int16u`,
      // so `$val` is the integer string (`75` → `"75 mm"`) — no decimal,
      // unlike 0x920a's `%.1f`. But a camera may write it as a rational/float;
      // Perl interpolates the value VERBATIM, so render the raw scalar with the
      // SAME `%g`/rational stringification the other focal-length convs use
      // (`first_rational_str`, == `ReadValue`'s output) rather than truncating
      // to an integer — a fractional `37.5` must surface as `"37.5 mm"`, not
      // `"37 mm"`.
      match first_rational_str(raw) {
        Some(v) if print_conv => {
          out.write_str(group, name, &std::format!("{v} mm"))?;
        }
        Some(_) | None => emit_raw(group, name, raw, out)?,
      }
      Ok(())
    }
    Conv::ExposureCompensation => match first_scalar(raw) {
      Some(v) if print_conv => {
        // PrintFraction → `-0.65` (in gate ⇒ a bare JSON number) or a `+1/2`
        // / `+1`-style signed fraction (a leading `+` or a `/` ⇒ out of gate
        // ⇒ a quoted string). Gate it.
        emit_gated_number(group, name, &tables::print_fraction(v), out)
      }
      Some(_) | None => emit_raw(group, name, raw, out),
    },
    Conv::ApertureApex => {
      // ValueConv `2 ** ($val / 2)` (Exif.pm:2356); PrintConv
      // `sprintf("%.1f",$val)` (Exif.pm:2358).
      match first_scalar(raw) {
        Some(apex) => {
          let v = 2f64.powf(apex / 2.0);
          if print_conv {
            // PrintConv `sprintf("%.1f",$val)` → `16.0` — an in-gate JSON
            // number. Gate it (the `%.1f` text is always in-gate, but the
            // gate keeps every numeric path uniform).
            emit_gated_number(group, name, &std::format!("{v:.1}"), out)?;
          } else {
            // `-n` ⇒ the post-ValueConv scalar, gated as ExifTool would
            // stringify-then-`EscapeJSON` it.
            emit_gated_f64(group, name, v, out)?;
          }
          Ok(())
        }
        None => emit_raw(group, name, raw, out),
      }
    }
    Conv::DateTime => {
      // `$self->ConvertDateTime($val)` — with default options ConvertDateTime
      // is identity (datetime.rs). The EXIF date string is emitted verbatim.
      emit_raw(group, name, raw, out)
    }
    Conv::LensInfo => {
      // PrintLensInfo (Exif.pm:5800) — 4 rationals → "12-20mm f/3.8-4.5".
      if print_conv
        && let RawValue::Rational(rs) = raw
        && let Some(s) = print_lens_info(rs)
      {
        out.write_str(group, name, &s)?;
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::Version => {
      // `undef` bytes → the raw ASCII version string, `\0`-stripped
      // (Exif.pm:2241 `$val=~s/\0+$//`). The Perl regex is anchored `$`, so it
      // strips ONLY TRAILING NULs — an INTERIOR NUL keeps the tail (e.g.
      // `b"02\x0010"` → `"02\x0010"`, not `"02"`). Same under -j and -n.
      if let RawValue::Bytes(b) = raw {
        // `end` is `rposition + 1` (≤ `b.len()`) or 0, so `b.get(..end)` is
        // always `Some` — the checked, byte-identical form of `&b[..end]`.
        let end = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
        let s = String::from_utf8_lossy(b.get(..end).unwrap_or(b.as_slice()));
        out.write_str(group, name, &s)?;
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::ComponentsConfiguration => {
      // Per-byte label join (Exif.pm:2304-2317): 0→"-", 1→"Y", 2→"Cb",
      // 3→"Cr", 4→"R", 5→"G", 6→"B". `-n` emits the space-joined integers.
      if let RawValue::Bytes(b) = raw {
        if print_conv {
          let parts: Vec<&str> = b
            .iter()
            .map(|&c| match c {
              0 => "-",
              1 => "Y",
              2 => "Cb",
              3 => "Cr",
              4 => "R",
              5 => "G",
              6 => "B",
              _ => "?",
            })
            .collect();
          out.write_str(group, name, &parts.join(", "))?;
        } else {
          let parts: Vec<String> = b.iter().map(|&c| std::format!("{c}")).collect();
          out.write_str(group, name, &parts.join(" "))?;
        }
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::MetersSuffix => {
      // `$val =~ /^(inf|undef)$/ ? $val : "$val m"` (Exif.pm:2388).
      if print_conv && let Some(v) = first_rational_str(raw) {
        if v == "inf" || v == "undef" {
          out.write_str(group, name, &v)?;
        } else {
          out.write_str(group, name, &std::format!("{v} m"))?;
        }
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::CelsiusSuffix => {
      // `AmbientTemperature` (0x9400) — `PrintConv => '"$val C"'`
      // (Exif.pm:2590). A `rational64s`; `$val` is the WHOLE post-ValueConv
      // value (0x9400 has no ValueConv) stringified by `ReadValue`. The string
      // interpolation `"$val C"` appends ` C` to the ENTIRE value, which for a
      // malformed count>1 rational is the space-joined element list (bundled
      // `exiftool 13.59` on a 2-element `235/10 -50/10` → `"23.5 -5 C"`), NOT
      // just the first element. The suffix is appended UNCONDITIONALLY (no
      // `inf`/`undef` guard, unlike `Conv::MetersSuffix`); a sign is preserved
      // (`-5.5` → `"-5.5 C"`).
      //
      // Like the 0xa462 RawConv, `"$val C"` is NOT gated on the on-disk format:
      // it interpolates whatever post-`ReadValue` scalar STRING `$val` it got.
      // A wrong-format value is therefore still suffixed (bundled `exiftool
      // 13.59`: ASCII-typed `"23.5\0"` → `ReadValue` NUL-trims to `"23.5"` →
      // `"23.5 C"`; `int16u`-typed `1234` → `"1234 C"`; AND an `undef`-typed
      // `-5.5` → `ReadValue` returns the raw byte string `"-5.5"` → `"-5.5 C"`).
      // The `undef`/`Bytes` shape is the one `value_space_joined` does NOT cover
      // (it never carries a numeric `ReadValue` form) — render those bytes as
      // their Perl-byte-string interpolation (`String::from_utf8_lossy`, the
      // realistic numeric-ASCII case is exact), so `-n` shows the bare string
      // and `-j` appends ` C` rather than falling to the binary `write_bytes`.
      if let RawValue::Bytes(b) = raw {
        let v = String::from_utf8_lossy(b);
        if print_conv {
          // `"$val C"` always yields a string (space + `C`) ⇒ quoted in `-j`.
          out.write_str(group, name, &std::format!("{v} C"))?;
        } else {
          // `-n` shows the post-`ReadValue` `$val` byte string verbatim, through
          // the `EscapeJSON` number gate: a numeric byte string (`-5.5`) emits
          // as a bare JSON number (matching bundled `-n -j`), a non-numeric one
          // stays a quoted string.
          emit_gated_number(group, name, &v, out)?;
        }
        return Ok(());
      }
      // Numeric / `string`-typed shapes: `-j` interpolates `"$val C"` over the
      // space-joined `ReadValue` string; `-n` shows the bare value via the
      // shared `emit_raw` (which keeps a single scalar as a bare JSON number —
      // NOT a quoted string — so the normal real-camera `-n` stays identical).
      //
      // #198 A4 audit: 0x9400 has NO `Format => 'undef'` override, so a
      // wrong-format `string` value DOES reach here as `RawValue::Text` (unlike
      // 0x9286). But `val_bytes()` is NOT needed: `"$val C"` interpolates a
      // STRING, and the JSON output is a Rust `String` either way, so the only
      // residual divergence on a high-bit `string` `$val` is the U+FFFD-vs-`?`
      // rendering of an INVALID byte (`value_space_joined`/`lossy_string` emit
      // U+FFFD; bundled ExifTool's JSON writer emits `?`) — the SAME pre-existing
      // charset-rendering gap `Conv::ExifText` has, NOT a byte-walk loss. The
      // byte-walk itself is already faithful (it reads `$val`'s exact value);
      // rerouting through `val_bytes()` would change nothing. So: no change here.
      if print_conv && let Some(v) = value_space_joined(raw) {
        out.write_str(group, name, &std::format!("{v} C"))?;
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    Conv::CompositeImageExposureTimes => {
      // `CompositeImageExposureTimes` (0xa462, Exif.pm:3068-3119). The on-disk
      // `undef` blob is decoded by a bespoke `RawConv` (`Exif.pm:3079-3098`)
      // that byte-walks `$val` then a `PrintConv` (`Exif.pm:3104-3115`).
      //
      // The RawConv byte-walks `$val` REGARDLESS of the on-disk `Format`
      // (ExifTool applies it to whatever `ReadValue` returned), so read the
      // bytes via `val_bytes()`: a real-camera `undef` blob borrows its bytes;
      // a camera that mis-wrote the format (`string`/numeric) byte-walks the
      // post-`ReadValue` `$val` rendering — `string`'s original bytes (not the
      // lossy display text — A1/A2) or the space-joined numeric `$val`. The
      // decoder bounds-checks every read, so a short/mis-formatted `$val` is
      // safe (closes #198).
      //
      // `composite_image_exposure_times` returns ONE token per decoded element.
      // ExifTool's JSON typing is element-count dependent (the `RawConv`/
      // `PrintConv` result is a single Perl scalar that `EscapeJSON`,
      // `exiftool:3809`, then number-gates):
      //   - EXACTLY ONE element ⇒ the lone token IS the whole `$val`, so a
      //     numeric token lands as a BARE JSON NUMBER and a non-numeric token
      //     (`undef`, a `1/N` `PrintExposureTime` fraction) stays a quoted
      //     STRING. Bundled `exiftool 13.59` on a short `undef` blob: `1/2` →
      //     `-j`/`-n` `0.5` (a number); `0/0` → `-j`/`-n` `"undef"`; `1/250` →
      //     `-j "1/250"` (a string) / `-n 0.004` (a number).
      //   - ZERO or 2+ elements ⇒ the space-joined string (a `0`-element walk
      //     yields the empty string `""`, bundled emits `""`; a 2+-element join
      //     has a space ⇒ out of the number gate ⇒ always a quoted STRING).
      // Route the SINGLE-token case through the shared `emit_gated_number`
      // (the same `EscapeJSON` number gate the rest of EXIF emission uses) so a
      // one-element numeric result is a bare number, not a type-wrong string;
      // keep `write_str` for the 0-/multi-token space-joined case.
      let bytes = raw.val_bytes();
      let parts = composite_image_exposure_times(&bytes, order, print_conv);
      if let [token] = parts.as_slice() {
        // One element: the lone token is the entire scalar — gate it so a
        // numeric token is a bare JSON number and `undef`/`1/N` stays a string.
        emit_gated_number(group, name, token, out)
      } else {
        // Zero (empty `""`) or multiple (space-joined) elements: always a string.
        out.write_str(group, name, &parts.join(" "))
      }
    }
    Conv::ExifText => {
      // `UserComment` (0x9286) — `RawConv => ConvertExifText($self,$val,1,$tag)`
      // (Exif.pm:2502). A RawConv runs BEFORE Value/PrintConv and applies in
      // BOTH -n and -j modes; UserComment has no further conversion. Like the
      // 0xa462 RawConv, `ConvertExifText` byte-walks `$val` REGARDLESS of the
      // on-disk `Format`, so read the bytes via `val_bytes()` (A2) — unifying on
      // the same format-agnostic byte view 0xa462 uses (#198 class).
      //
      // For 0x9286 specifically the `Format => 'undef'` override
      // (`tables::format_override`) forces the value through `undef` BEFORE
      // `ReadValue` (count != 1 ⇒ `RawValue::Bytes`; the degenerate 1-byte case
      // ⇒ `RawValue::U64` via the int8u carve-out), so the value never reaches
      // here as `RawValue::Text` — the prior per-shape `match` had a `Text` arm
      // that was unreachable for the only tag using this conv. `val_bytes()`
      // borrows the `Bytes` verbatim (byte-identical to the old `b.clone()`),
      // so every real-camera path is unchanged; the unification just removes the
      // dead/lossy `Text` arm and keeps the conv robust if a future `ExifText`
      // tag lacks the override (it would then byte-walk `Text.raw`, not the
      // lossy FixUTF8 text). NOTE: `convert_exif_text`'s ASCII branch renders an
      // invalid-UTF-8 payload byte via `from_utf8_lossy` (U+FFFD), whereas
      // bundled ExifTool's JSON writer emits `?` for it — a separate, pre-
      // existing charset-rendering gap (NOT a byte-walk loss), out of #198 scope.
      let bytes = raw.val_bytes();
      out.write_str(group, name, &exiftext::convert_exif_text(&bytes, order))?;
      Ok(())
    }
    Conv::TrimTrailingWhitespace => {
      // `Make`/`Model`/`Software`/`Artist` `RawConv => '$val =~ s/\s+$//'`
      // (Exif.pm:585/599/906/925). Strip EVERY trailing whitespace char
      // (Perl `\s` = ` \t\n\r\f` plus the vertical tab) from the `string`
      // value. A RawConv applies in BOTH -n and -j, so the trim happens at
      // the raw stage here for either output mode.
      match raw {
        RawValue::Text { text, .. } => {
          out.write_str(group, name, text.trim_end_matches(is_perl_space))
        }
        // The regex is a no-op on a non-string value; these tags are always
        // `string`, but emit any off-spec value faithfully unchanged.
        _ => emit_raw(group, name, raw, out),
      }
    }
    Conv::TrimTrailingSpaces => {
      // `SubSecTime`/`SubSecTimeOriginal`/`SubSecTimeDigitized`
      // `ValueConv => '$val=~s/ +$//'` (Exif.pm:2543/2552/2560). Trims
      // trailing SPACES ONLY (U+0020) — NOT `\s`, so a trailing tab/NL is
      // kept. A ValueConv result is what -n shows; the identity PrintConv
      // carries the same trimmed value through in -j.
      match raw {
        RawValue::Text { text, .. } => out.write_str(group, name, text.trim_end_matches(' ')),
        _ => emit_raw(group, name, raw, out),
      }
    }
  }
}

/// Perl `\s` character class (`Exif.pm` `s/\s+$//`) — ASCII whitespace:
/// space, tab, line feed, carriage return, form feed, and vertical tab.
/// (`char::is_whitespace` would over-match Unicode whitespace; `\s` without
/// `/u` on a byte string is exactly this ASCII set.)
#[cfg(feature = "alloc")]
const fn is_perl_space(c: char) -> bool {
  matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c' | '\x0b')
}

/// First unsigned integer of a [`RawValue`], or `None` for a non-integer
/// shape. Used by the `SubfileType` / `OldSubfileType` `RawConv` taps
/// (`Exif.pm:452-457` / `:469-475`) to read a scalar integer value
/// regardless of whether the encoder used `int8u`/`int16u`/`int32u`/`int64u`
/// (`RawValue::U64`) or one of the signed integer formats
/// (`RawValue::I64`; a negative encoding is treated as `None` since the
/// SubfileType RawConv branch comparing `$val == ($val & 0x02)` excludes
/// negatives anyway — Perl's bitwise `&` on a negative is undefined and
/// the gate effectively rejects them).
fn first_uint(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

// ====================================================================// GPS value emission — applies a `GpsConv` to a `RawValue`
// ====================================================================
/// Render a [`RawValue`] under a [`gps::GpsConv`] into the sink.
#[cfg(all(feature = "alloc", feature = "gps"))]
fn emit_gps_value<S: ExifSink>(
  group: &str,
  name: &str,
  raw: &RawValue,
  conv: gps::GpsConv,
  order: ByteOrder,
  print_conv: bool,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  use gps::GpsConv;
  match conv {
    GpsConv::Plain(c) => emit_exif_value(group, name, raw, c, order, print_conv, out),
    GpsConv::VersionId => {
      // `$val =~ tr/ /./; $val` (GPS.pm:61) — the int8u quadruple is the
      // space-joined integers under -n, dot-joined under -j.
      if let RawValue::U64(vals) = raw {
        let joined: Vec<String> = vals.iter().map(|v| std::format!("{v}")).collect();
        let sep = if print_conv { "." } else { " " };
        out.write_str(group, name, &joined.join(sep))?;
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
    GpsConv::Coordinate => {
      // %coordConv: ValueConv `ToDegrees($val)`, PrintConv `ToDMS($self,
      // $val, 1)`. The on-disk value is 3 rationals (D, M, S).
      let dms = rational_triple(raw);
      match gps::to_degrees(dms.0, dms.1, dms.2) {
        // PrintConv `ToDMS` → `54 deg 59' 22.80"` (spaces ⇒ out of gate ⇒ a
        // quoted string).
        Some(deg) if print_conv => out.write_str(group, name, &gps::to_dms(deg))?,
        // `-n` ⇒ the `ToDegrees` decimal-degrees scalar through the
        // `EscapeJSON` number gate — a bare JSON number when in-gate.
        Some(deg) => emit_gated_f64(group, name, deg, out)?,
        None => emit_raw(group, name, raw, out)?,
      }
      Ok(())
    }
    GpsConv::TimeStamp => {
      // GPSTimeStamp: 3 rationals (H, M, S) → ConvertTimeStamp (ValueConv)
      // → PrintTimeStamp (PrintConv).
      let hms = rational_triple(raw);
      match (hms.0, hms.1, hms.2) {
        (Some(h), m, s) => {
          let value_conv = gps::convert_time_stamp(h, m.unwrap_or(0.0), s.unwrap_or(0.0));
          if print_conv {
            out.write_str(group, name, &gps::print_time_stamp(&value_conv))?;
          } else {
            out.write_str(group, name, &value_conv)?;
          }
          Ok(())
        }
        _ => emit_raw(group, name, raw, out),
      }
    }
    GpsConv::DateStamp => {
      // GPSDateStamp: `undef[11]` → ExifDate (ValueConv, GPS.pm:319). The
      // RawConv `$val=~s/\0+$//` strips trailing NULs first.
      let text = match raw {
        RawValue::Bytes(b) => {
          let trimmed: Vec<u8> = {
            let mut v = b.clone();
            while v.last() == Some(&0) {
              v.pop();
            }
            v
          };
          String::from_utf8_lossy(&trimmed).into_owned()
        }
        RawValue::Text { text, .. } => text.clone(),
        _ => {
          return emit_raw(group, name, raw, out);
        }
      };
      out.write_str(group, name, &gps::exif_date(&text))?;
      Ok(())
    }
    GpsConv::ExifText => {
      // GPSProcessingMethod (0x001b) / GPSAreaInformation (0x001c):
      // `ConvertExifText` RawConv (Exif.pm:5554-5601) strips the 8-byte
      // charset-ID prefix and decodes the payload. A RawConv runs BEFORE
      // Value/PrintConv and applies in both -n and -j modes; these tags have
      // no further conversion.
      //
      // `ConvertExifText` byte-walks `$val` REGARDLESS of the on-disk
      // `Format`, so read the bytes via `val_bytes()` (#198 class, mirroring
      // the EXIF `Conv::ExifText` sibling for UserComment 0x9286). UNLIKE
      // 0x9286 these GPS tags have NO `Format => 'undef'` override
      // (`gps::format_override` covers only GPSDateStamp 0x001d; GPS.pm:296/304
      // give them `Writable => 'undef'` but leave `Format` unset), so a
      // wrong-format `string`-on-disk GPS value DOES reach here as
      // `RawValue::Text` — and `val_bytes()` returns its pre-FixUTF8 `raw`
      // bytes (the original on-disk `$val`), NOT the lossy FixUTF8 display
      // text the prior `text.as_bytes()` arm read. The real-camera path is
      // `undef` → `RawValue::Bytes`, which `val_bytes()` borrows verbatim, so
      // every real GPS path stays byte-identical. NOTE: `convert_exif_text`'s
      // ASCII branch renders an invalid-UTF-8 payload byte via
      // `from_utf8_lossy` (U+FFFD) whereas bundled ExifTool's JSON writer
      // emits `?` — a separate, pre-existing charset-rendering gap (#200), NOT
      // a byte-walk loss, out of #198 scope.
      let bytes = raw.val_bytes();
      out.write_str(group, name, &exiftext::convert_exif_text(&bytes, order))?;
      Ok(())
    }
    GpsConv::StrLabel(slice) => {
      // String → label (GPSStatus etc.). The on-disk value is a `string`.
      if let RawValue::Text { text: t, .. } = raw {
        // ExifTool's `string` count includes a NUL terminator; the decoded
        // `Text` is already NUL-trimmed. A trailing space is also possible
        // (Count => 2 strings) — match on the trimmed token.
        let key = t.trim_end_matches([' ', '\0']);
        if print_conv {
          // A HASH-PrintConv hit emits the label; a MISS emits `Unknown
          // ($val)` (`ExifTool.pm:3614-3634` — every GPS string enum here is
          // a plain hash with no `OTHER`/`PrintHex`, so the decimal/string
          // `Unknown ($val)` fallback applies, e.g. `GPSStatus "Z"` →
          // `"Unknown (Z)"`, matching the H264 module's `GPS:GPSStatus`).
          match gps::str_label_for(slice, key) {
            Some(label) => out.write_str(group, name, label)?,
            None => out.write_str(group, name, &std::format!("Unknown ({key})"))?,
          }
        } else {
          // `-n` ⇒ the raw token.
          out.write_str(group, name, key)?;
        }
        return Ok(());
      }
      emit_raw(group, name, raw, out)
    }
  }
}

// ====================================================================// `EscapeJSON` number gate — bundled `exiftool` script line 3809
// ====================================================================//
// Bundled ExifTool stringifies EVERY tag value (`$val`) and runs the JSON
// writer's `EscapeJSON` (`exiftool` script, sub `EscapeJSON`, line 3800). With
// the default `$quote` flag false (every non-`StructFormat=JSONQ` `-j`/`-n`
// run), a value whose ENTIRE stringified form matches the conservative number
// regex `^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$` (case-insensitive
// `e`, `exiftool:3809`) is printed as a BARE JSON NUMBER; anything else is
// quoted as a JSON string. So a numeric Exif/GPS PrintConv result
// (`ExifIFD:FNumber` → `0.64`, `ExifIFD:ApertureValue` → `16.0`) and a scalar
// rational (`IFD0:XResolution` → `300`) land as JSON NUMBERS, while an
// out-of-gate value — a `:`/`/`/space-bearing string, the words
// `inf`/`undef`/`Inf`/`NaN`, OR a `>16`-fraction-digit float such as a
// `ShutterSpeedValue` ValueConv `0.00138106793200498` — stays a JSON STRING.
//
// The shared `TagValue` serializer (`value.rs`) intentionally does NOT run
// this gate (it emits standard `serde_json` scalars and relies on the
// value-semantic `jsondiff` comparator); for the Exif/GPS port the gate IS
// load-bearing — bundled emits a bare number, exifast must too. So this module
// gates its own numeric output here.
//
// CONSOLIDATED (Contract B / #197): the number gate is now the SINGLE
// crate-wide [`crate::value::escape_json_is_number`] — the same predicate the
// terminal `TagValue::Str` serializer applies. The Exif/GPS emitter delegates
// to it (below) so the `exiftool:3809` regex lives in exactly one place; H264's
// `-n` classifier delegates likewise.

/// The `EscapeJSON` number gate (`exiftool:3809`) for the Exif/GPS scalar
/// emitter — a thin alias for the shared [`crate::value::escape_json_is_number`]
/// so this module's many call sites read unchanged while the regex is defined
/// once, crate-wide.
#[cfg(feature = "alloc")]
#[inline]
fn escape_json_is_number(s: &str) -> bool {
  crate::value::escape_json_is_number(s)
}

/// Emit a value ExifTool would stringify as `rendered` through the JSON
/// `EscapeJSON` number gate (`exiftool:3809`): if `rendered`'s ENTIRE text
/// matches the number regex it lands as a BARE JSON NUMBER (routed through the
/// matching `write_u64`/`write_i64`/`write_f64`); otherwise it stays a quoted
/// JSON STRING (`write_str`).
///
/// `rendered` MUST be the exact decimal text bundled ExifTool would produce for
/// the value — a rational's [`crate::value::Rational::exiftool_val_str`], a
/// float's `%.15g` ([`crate::value::format_g`] with precision 15 — ExifTool's
/// default NV stringification), a plain integer's decimal text, or a PrintConv
/// string. The gate then quotes vs bare-numbers it byte-identically to bundled.
///
/// An in-gate integer routes through `write_u64`/`write_i64` so serde emits an
/// exact integer token (`300`, not `300.0`); an in-gate fractional/exponent
/// value routes through `write_f64`. Because the gate already proved `rendered`
/// is a valid JSON number, the parse below never fails for an in-gate string;
/// the defensive fallback keeps any unreachable case a faithful quoted string.
#[cfg(feature = "alloc")]
fn emit_gated_number<S: ExifSink>(
  group: &str,
  name: &str,
  rendered: &str,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  if !escape_json_is_number(rendered) {
    // Out of gate ⇒ a quoted JSON string (a `:`/`/`-bearing value, the words
    // `inf`/`undef`/`Inf`/`NaN`, or a `>16`-fraction-digit float).
    return out.write_str(group, name, rendered);
  }
  // In gate ⇒ a bare JSON number. A pure integer (no `.`, no `e`/`E`) is an
  // exact integer token; route it through the integer writer. The gate caps
  // the integer part at 15 digits so it always fits `i64`/`u64`.
  let is_integer = !rendered
    .bytes()
    .any(|b| b == b'.' || b == b'e' || b == b'E');
  if is_integer {
    if let Some(rest) = rendered.strip_prefix('-') {
      if let Ok(n) = rest.parse::<i64>() {
        return out.write_i64(group, name, -n);
      }
    } else if let Ok(n) = rendered.parse::<u64>() {
      return out.write_u64(group, name, n);
    }
  }
  // Emit a value-equal bare number via `write_f64` ONLY when the f64 FAITHFULLY
  // represents its token ([`crate::value::f64_token_is_faithful`], the shared
  // f64-representation predicate). The gate admits an over-range exponent, so a
  // token outside finite-f64 range — `1e999` (OVERFLOW → `INFINITY`, which
  // `write_f64` would lower to `TagValue::F64`'s titlecase `"Inf"`) or `1e-999`
  // (nonzero-UNDERFLOW → finite `0.0`, a bare `0` rewriting the token to zero) —
  // instead emits the ORIGINAL `rendered` text as a quoted JSON string, sound on
  // every path (mirrors `value.rs::serialize_in_gate_number_str`, Contract B /
  // #197). Every current EXIF caller feeds a bounded format or a pre-finite
  // `format_g` render, so the string arm is unreachable today; the guard keeps
  // the gate class closed against a future caller passing such a token.
  match rendered.parse::<f64>() {
    Ok(f) if crate::value::f64_token_is_faithful(f, rendered) => out.write_f64(group, name, f),
    // Over-range exponent (overflow to non-finite OR nonzero-underflow to `0.0`)
    // or an unreachable non-parse: fall back to the faithful quoted source
    // string.
    _ => out.write_str(group, name, rendered),
  }
}

/// Emit an `f64` Exif/GPS value through the [`emit_gated_number`] gate.
///
/// A finite value is rendered with `%.15g` ([`crate::value::format_g`] with
/// precision 15 — ExifTool's default NV stringification, the same render
/// [`crate::value::TagValue`]'s serializer applies) and gated: in-gate ⇒ a bare
/// JSON number, out-of-gate (e.g. a `ShutterSpeedValue` ValueConv with a
/// 17-digit fraction) ⇒ a quoted string. A NON-finite value bypasses the gate
/// and is emitted via `write_f64` so [`crate::value::TagValue`]'s serializer
/// renders ExifTool's titlecase `Inf`/`-Inf`/`NaN` quoted word.
#[cfg(feature = "alloc")]
fn emit_gated_f64<S: ExifSink>(
  group: &str,
  name: &str,
  value: f64,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  if !value.is_finite() {
    // `TagValue::F64`'s serializer emits the titlecase `Inf`/`-Inf`/`NaN`
    // string; `EscapeJSON` would likewise quote those words.
    return out.write_f64(group, name, value);
  }
  emit_gated_number(group, name, &crate::value::format_g(value, 15), out)
}

// ====================================================================// Emission helpers
// ====================================================================
/// Emit a [`RawValue`] verbatim (the `Conv::None` path) — multi-element
/// numeric arrays are space-joined (ExifTool's `ReadValue` joins with
/// spaces, `ExifTool.pm:6319`); a string is emitted as-is; bytes become the
/// `(Binary data N bytes ...)` placeholder.
#[cfg(feature = "alloc")]
fn emit_raw<S: ExifSink>(
  group: &str,
  name: &str,
  raw: &RawValue,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  // Each singleton arm matches a one-element slice (`[v]`) on the Vec's
  // `as_slice()` rather than `len()==1` + `vals[0]`: the binding `v` IS the sole
  // element, so the read is checked by the pattern and stays byte-identical.
  match raw {
    RawValue::U64(vals) => {
      if let [v] = vals.as_slice() {
        // A scalar integer through the `EscapeJSON` number gate: an Exif
        // `int8u`/`int16u`/`int32u` (≤32-bit) is always in-gate ⇒ a bare JSON
        // number, but routing it keeps every numeric path uniform and quotes a
        // pathological `>15`-digit value exactly as bundled would.
        emit_gated_number(group, name, &std::format!("{v}"), out)
      } else {
        // A multi-element array space-joins (out of gate ⇒ a quoted string).
        out.write_str(group, name, &join_nums(vals))
      }
    }
    RawValue::I64(vals) => {
      if let [v] = vals.as_slice() {
        emit_gated_number(group, name, &std::format!("{v}"), out)
      } else {
        out.write_str(group, name, &join_nums(vals))
      }
    }
    RawValue::F64(vals) => {
      if let [v] = vals.as_slice() {
        emit_gated_f64(group, name, *v, out)
      } else {
        out.write_str(group, name, &join_floats(vals))
      }
    }
    RawValue::Rational(rs) => {
      if let [r] = rs.as_slice() {
        // A single rational — emit its ExifTool-rounded scalar
        // (`exiftool_val_str`) through the `EscapeJSON` number gate: a
        // non-zero-denominator quotient is always in-gate ⇒ a bare JSON number
        // (`IFD0:XResolution` → `300`), while a `0`-denominator yields the word
        // `inf`/`undef` ⇒ a quoted string. (Before R18 this used a bare
        // `write_str`, emitting an in-gate scalar rational as a JSON string.)
        emit_gated_number(group, name, &r.exiftool_val_str(), out)
      } else {
        let parts: Vec<String> = rs
          .iter()
          .map(crate::value::Rational::exiftool_val_str)
          .collect();
        out.write_str(group, name, &parts.join(" "))
      }
    }
    RawValue::Text { text, .. } => out.write_str(group, name, text),
    RawValue::Bytes(b) => out.write_bytes(group, name, b),
  }
}

/// Emit a [`RawValue`] under an integer→label conversion (a HASH PrintConv).
///
/// With print_conv ON, a hash MISS ALWAYS renders an `Unknown (…)` string —
/// faithful to ExifTool's HASH-PrintConv miss, which (with no `OTHER`/`BITMASK`
/// match) emits `sprintf('Unknown ($val)')`, or `sprintf('Unknown (0x%x)')`
/// when the tag carries `PrintHex => 1` (`ExifTool.pm:3614-3634`). `hex`
/// selects the hex form (e.g. `ColorSpace`/`Flash`). With print_conv OFF
/// (`-n`), or for a non-singleton / non-integer value that has no scalar key,
/// the raw value is emitted verbatim (the `emit_raw` path) — a bare DECIMAL
/// number even for a `PrintHex` tag, matching ExifTool's `-n` output.
#[cfg(feature = "alloc")]
fn emit_int_label<S: ExifSink>(
  group: &str,
  name: &str,
  raw: &RawValue,
  slice: &[(i64, &'static str)],
  print_conv: bool,
  out: &mut S,
  hex: bool,
) -> Result<(), core::convert::Infallible> {
  // The integer for the PrintConv lookup — works for U64 or I64 singletons.
  // The `if let [n] = v.as_slice()` guard binds the sole element (checked by the
  // slice pattern), byte-identical to `v.len() == 1` + `v[0]`.
  let code: Option<i64> = match raw {
    RawValue::U64(v) if let [n] = v.as_slice() => i64::try_from(*n).ok(),
    RawValue::I64(v) if let [n] = v.as_slice() => Some(*n),
    _ => None,
  };
  match code {
    Some(c) if print_conv => match tables::label_for(slice, c) {
      Some(label) => out.write_str(group, name, label),
      // `sprintf('Unknown (0x%x)', $val)` (PrintHex) / `sprintf('Unknown
      // ($val)')` (`ExifTool.pm:3623-3627`). `0x%x` is Perl's lowercase hex
      // with no width. `c` is non-negative here — the two PrintHex tags
      // (`ColorSpace`/`Flash`) are `int16u`, so the code comes from a `U64`
      // value through `i64::try_from`; `{:x}` on a non-negative `i64` prints
      // the same digits as Perl's unsigned `%x`.
      None if hex => out.write_str(group, name, &std::format!("Unknown (0x{c:x})")),
      None => out.write_str(group, name, &std::format!("Unknown ({c})")),
    },
    _ => emit_raw(group, name, raw, out),
  }
}

/// The first scalar of a [`RawValue`] as an `f64` — for the scalar-conv
/// paths (FNumber/ExposureTime/etc.). A `Rational` yields its quotient.
fn first_scalar(raw: &RawValue) -> Option<f64> {
  match raw {
    RawValue::U64(v) => v.first().map(|&n| n as f64),
    RawValue::I64(v) => v.first().map(|&n| n as f64),
    RawValue::F64(v) => v.first().copied(),
    RawValue::Rational(rs) => rs.first().map(rational_quotient),
    _ => None,
  }
}

/// The first rational of a [`RawValue`] as its ExifTool-rounded string (for
/// the `MetersSuffix` conv, which must preserve `inf`/`undef`).
fn first_rational_str(raw: &RawValue) -> Option<String> {
  match raw {
    RawValue::Rational(rs) => rs.first().map(crate::value::Rational::exiftool_val_str),
    RawValue::U64(v) => v.first().map(|&n| std::format!("{n}")),
    RawValue::I64(v) => v.first().map(|&n| std::format!("{n}")),
    RawValue::F64(v) => v.first().map(|&n| crate::value::format_g(n, 15)),
    _ => None,
  }
}

/// The COMPLETE value of a [`RawValue`] as the single string ExifTool's
/// `ReadValue` would hand a string-interpolating `PrintConv` (`"$val …"`):
/// every element rendered exactly as [`emit_raw`] renders it, space-joined.
/// A single element yields its bare scalar form; a multi-element value is the
/// space-joined list (e.g. a malformed 2-element `AmbientTemperature` `235/10
/// -50/10` → `"23.5 -5"`, matching bundled `exiftool`). `None` for a non-scalar
/// value (`Bytes`) — those tags never carry a `"$val …"` PrintConv.
fn value_space_joined(raw: &RawValue) -> Option<String> {
  match raw {
    RawValue::U64(v) => Some(join_nums(v)),
    RawValue::I64(v) => Some(join_nums(v)),
    RawValue::F64(v) => Some(join_floats(v)),
    RawValue::Rational(rs) => Some(
      rs.iter()
        .map(crate::value::Rational::exiftool_val_str)
        .collect::<Vec<_>>()
        .join(" "),
    ),
    RawValue::Text { text, .. } => Some(text.to_string()),
    RawValue::Bytes(_) => None,
  }
}

/// The first three rationals of a [`RawValue`] as `(D, M, S)` quotients —
/// for the GPS coordinate / timestamp conversions. A degenerate `inf`/`undef`
/// rational yields a non-finite `f64` so the conv's guard fires.
fn rational_triple(raw: &RawValue) -> (Option<f64>, Option<f64>, Option<f64>) {
  match raw {
    RawValue::Rational(rs) => (
      rs.first().map(rational_quotient),
      rs.get(1).map(rational_quotient),
      rs.get(2).map(rational_quotient),
    ),
    // A GPS coordinate could in theory be written with another numeric
    // type; map a numeric array's first three elements faithfully.
    RawValue::U64(v) => (
      v.first().map(|&n| n as f64),
      v.get(1).map(|&n| n as f64),
      v.get(2).map(|&n| n as f64),
    ),
    RawValue::F64(v) => (v.first().copied(), v.get(1).copied(), v.get(2).copied()),
    _ => (None, None, None),
  }
}

/// The quotient of a [`crate::value::Rational`] as an `f64` — `n/0` (n≠0) is
/// `inf`, `0/0` is `NaN` (`undef`), matching ExifTool's `GetRational*`
/// (`ExifTool.pm:6081-6109`). The GPS conv guards on `is_finite()`.
fn rational_quotient(r: &crate::value::Rational) -> f64 {
  if r.denominator() == 0 {
    return if r.numerator() != 0 {
      f64::INFINITY
    } else {
      f64::NAN
    };
  }
  r.numerator() as f64 / r.denominator() as f64
}

/// `PrintLensInfo` (`Exif.pm:5800-5817`) — 4 rationals → the lens string.
/// Returns `None` if the value is not exactly 4 valid rationals (ExifTool
/// `return $val` — render verbatim).
fn print_lens_info(rs: &[crate::value::Rational]) -> Option<String> {
  if rs.len() != 4 {
    return None;
  }
  // Each value is `IsFloat` (a number) or the words `inf`/`undef` → "?".
  let vals: Vec<String> = rs
    .iter()
    .map(|r| {
      let s = r.exiftool_val_str();
      if s == "inf" || s == "undef" {
        "?".to_string()
      } else {
        s
      }
    })
    .collect();
  // `$val = $vals[0]; $val .= "-$vals[1]" if $vals[1] and $vals[1] ne
  // $vals[0]; $val .= "mm f/$vals[2]"; $val .= "-$vals[3]" if $vals[3] and
  // $vals[3] ne $vals[2];`. `vals` has exactly 4 entries (one per the 4
  // rationals the `rs.len() != 4` guard required), so the `[v0, v1, v2, v3]`
  // slice pattern is total — the checked, byte-identical form of the
  // `vals[0..3]` index reads (the unreachable `_` arm returns `None`).
  let [v0, v1, v2, v3] = vals.as_slice() else {
    return None;
  };
  let mut out = v0.clone();
  if v1 != "0" && v1 != v0 {
    out.push('-');
    out.push_str(v1);
  }
  out.push_str("mm f/");
  out.push_str(v2);
  if v3 != "0" && v3 != v2 {
    out.push('-');
    out.push_str(v3);
  }
  Some(out)
}

/// `CompositeImageExposureTimes` (0xa462) `RawConv` + `PrintConv`
/// (`Exif.pm:3079-3115`). Decode the `undef` blob and return the per-element
/// rendered strings to space-join.
///
/// The `RawConv` (`Exif.pm:3079-3098`) walks the blob by BYTE OFFSET, reading
/// a `GetRational64u` (8 bytes) at every offset EXCEPT 56 and 58, where it
/// reads a `Get16u` (2 bytes); it stops as soon as the next field would run
/// past the end. The two `int16u` land at element indices 7 and 8 (the first
/// seven 8-byte rationals consume bytes 0..56). With `print_conv` ON the
/// `PrintConv` (`Exif.pm:3104-3115`) maps every element EXCEPT indices 7 and 8
/// through [`tables::print_exposure_time`]; with it OFF the `RawConv` join is
/// shown — each rational as its `GetRational64u` decimal (`RoundFloat(n/d, 10)`,
/// [`crate::value::Rational::rational64`]) and each count as a bare integer.
#[cfg(feature = "alloc")]
fn composite_image_exposure_times(blob: &[u8], order: ByteOrder, print_conv: bool) -> Vec<String> {
  let mut out: Vec<String> = Vec::new();
  let mut i: usize = 0;
  // `idx` is the ELEMENT index (0-based), distinct from the BYTE offset `i`;
  // the PrintConv carve-out (`unless $i == 7 or $i == 8`) is keyed on the
  // element index in Perl (`for ($i=0; ...; ++$i)`), which equals 7/8 exactly
  // when the byte offset is 56/58.
  let mut idx: usize = 0;
  loop {
    if i == 56 || i == 58 {
      // `Get16u` — an `int16u` count (number of sequences / source images).
      let Some(v) = ifd::get_u16(blob, i, order) else {
        break;
      };
      // Indices 7 and 8 are NEVER PrintExposureTime'd; the count is the bare
      // integer in both `-j` and `-n`.
      out.push(std::format!("{v}"));
      i += 2;
    } else {
      // `GetRational64u` — an exposure-time quotient.
      let (Some(num), Some(den)) = (
        ifd::get_u32(blob, i, order),
        ifd::get_u32(blob, i.wrapping_add(4), order),
      ) else {
        break;
      };
      let r = crate::value::Rational::rational64(i64::from(num), i64::from(den));
      // The `RawConv` (`Exif.pm:3079-3094`) stringifies each rational via
      // `GetRational64u` = `RoundFloat(n/d, 10)` (= `%.10g`, or the bare word
      // `inf`/`undef` for a zero denominator), then space-joins. The
      // `PrintConv` (`Exif.pm:3106-3115`) re-`split`s that joined string and
      // feeds each TOKEN to `PrintExposureTime`. So the print value is keyed on
      // the ALREADY-ROUNDED token, NOT the unrounded quotient — compute the
      // token FIRST for BOTH modes.
      let token = r.exiftool_val_str();
      if print_conv && idx != 7 && idx != 8 {
        // `PrintExposureTime($v[$i])` on the rounded token. ExifTool's
        // `PrintExposureTime` first checks `IsFloat($secs)` and returns the
        // value unchanged when it is not a float (`Exif.pm:5704`): the words
        // `inf`/`undef` (a degenerate rational) pass through verbatim — and so
        // do they here, since they never parse as a finite `f64`. A finite
        // token is re-parsed and `PrintExposureTime`'d on the ROUNDED value
        // (e.g. `2/19` → token `0.1052631579` → `1/9`, NOT the unrounded
        // `0.10526315789…` → `1/10`).
        match token.parse::<f64>() {
          Ok(secs) if secs.is_finite() => out.push(tables::print_exposure_time(secs)),
          _ => out.push(token),
        }
      } else {
        // `-n` (RawConv join) — the `GetRational64u` decimal token (`inf`/
        // `undef` for a zero denominator). (Indices 7/8 are the `int16u`
        // byte-offsets 56/58, never reached on this rational arm, so the
        // `idx != 7 && idx != 8` print-conv guard is the only carve-out.)
        out.push(token);
      }
      i += 8;
    }
    idx += 1;
  }
  out
}

/// `ShutterSpeedValue` ValueConv — `IsFloat($val) && abs($val)<100 ?
/// 2**(-$val) : 0` (`Exif.pm:2346`).
fn shutter_speed_value_conv(apex: f64) -> f64 {
  if apex.is_finite() && apex.abs() < 100.0 {
    2f64.powf(-apex)
  } else {
    0.0
  }
}

/// Space-join a slice of integers (ExifTool's multi-element `ReadValue`).
fn join_nums<T: core::fmt::Display>(vals: &[T]) -> String {
  let mut s = String::new();
  for (i, v) in vals.iter().enumerate() {
    if i > 0 {
      s.push(' ');
    }
    let _ = core::fmt::Write::write_fmt(&mut s, core::format_args!("{v}"));
  }
  s
}

/// Space-join a slice of floats — each rendered with `%.15g` (ExifTool's
/// default NV stringification, `value.rs`).
fn join_floats(vals: &[f64]) -> String {
  let mut s = String::new();
  for (i, v) in vals.iter().enumerate() {
    if i > 0 {
      s.push(' ');
    }
    s.push_str(&crate::value::format_g(*v, 15));
  }
  s
}

// ====================================================================// Table-codegen allowlist accessors (`cargo xtask gen-tables --kind exif`)
// ====================================================================
/// The Step-B binary-EXIF coverage-gap ids — genuine `%Exif::Main` leaf tags
/// (`Exif.pm`) that the camera-relevant hand subset ([`tables::EXIF_TAGS`]) does
/// NOT carry, so they were silently dropped on the binary IFD path (reachable
/// only via XMP before). The `--kind exif` generator adds these to its emitted
/// table (in ADDITION to the hand ids); since none is in [`tables::EXIF_TAGS`],
/// the hand-first [`tables::lookup`] falls through to the generated shadow and
/// they now emit, byte-identically to bundled ExifTool 13.59 (a crafted
/// conformance fixture is the gate). Each was verified against `Exif.pm` for its
/// `Writable`/`Format` + ValueConv/PrintConv:
///
/// * plain (`Conv::None`) — `ProcessingSoftware` (0x0b), `HostComputer` (0x13c
///   — the source assessment's "0x010c" was WRONG; `HostComputer` is `0x13c` /
///   316 in `Exif.pm:927`, and `0x010c` is not a `%Exif::Main` tag),
///   `TimeZoneOffset` (0x882a), `StandardOutputSensitivity` (0x8831),
///   `ISOSpeed` (0x8833), `ISOSpeedLatitudeyyy` (0x8834),
///   `ISOSpeedLatitudezzz` (0x8835), `ImageNumber` (0x9211),
///   `ImageHistory` (0x9213), `SubjectArea` (0x9214), `SubjectLocation`
///   (0xa214), `Humidity` (0x9401), `Pressure` (0x9402), `WaterDepth`
///   (0x9403), `Acceleration` (0x9404), `CameraElevationAngle` (0x9405),
///   `CompositeImageCount` (0xa461);
/// * `Opto-ElectricConvFactor` (0x8828, `Binary => 1`) — `Conv::None`; the
///   `undef` blob is `RawValue::Bytes`, so `emit_raw` renders the
///   `(Binary data N bytes, use -b option to extract)` placeholder bundled
///   emits for a `Binary` tag in both `-j` and `-n`;
/// * declarative HASH PrintConv (from `-listx <values>`) — `SecurityClassification`
///   (0x9212, string-keyed → `Conv::StrLabel`) and `CompositeImage` (0xa460,
///   int-keyed → `Conv::IntLabel`);
/// * code-valued (`EXIF_HANDPORTED` in `xtask/src/exif_conv.rs`) —
///   `AmbientTemperature` (0x9400, `Conv::CelsiusSuffix` for `'"$val C"'`) and
///   `CompositeImageExposureTimes` (0xa462, `Conv::CompositeImageExposureTimes`
///   for the bespoke undef-decode + per-element `PrintExposureTime`).
///
/// `0x0103` (the source assessment's "RenderingIntent") was REJECTED — it is
/// `Compression`, already a hand tag, NOT a gap.
const EXIF_MAIN_GAP_IDS: &[u16] = &[
  0x000b, 0x013c, 0x8828, 0x882a, 0x8831, 0x8833, 0x8834, 0x8835, 0x9211, 0x9212, 0x9213, 0x9214,
  0x9400, 0x9401, 0x9402, 0x9403, 0x9404, 0x9405, 0xa214, 0xa460, 0xa461, 0xa462,
];

/// The on-disk ids the `--kind exif` generator emits for `%Exif::Main`: the
/// ported camera-relevant hand subset ([`tables::EXIF_TAGS`]) PLUS the Step-B
/// binary-coverage-gap ids ([`EXIF_MAIN_GAP_IDS`]).
///
/// Step A was a byte-identical SHADOW (hand ids only); Step B turns on the gap
/// ids — these are NOT in the hand [`tables::EXIF_TAGS`], so the hand-first
/// [`tables::lookup`] falls through to the generated shadow and they emit. The
/// generated table therefore stays a SUPERSET of the hand table (the
/// `generated_shadow_matches_hand_table` parity test asserts hand ⊆ generated,
/// which the extra gap ids preserve). `#[doc(hidden)]`: this is the generator's
/// allowlist source, NOT public API — the hand table itself (`ExifTag`, with
/// its `const`-init public fields) stays `pub(crate)` per D8.
#[doc(hidden)]
#[must_use]
pub fn exif_main_tag_ids() -> Vec<u16> {
  tables::EXIF_TAGS
    .iter()
    .map(|t| t.id)
    .chain(EXIF_MAIN_GAP_IDS.iter().copied())
    .collect()
}

/// The on-disk ids of the ported `%GPS::Main` table ([`gps::GPS_TAGS`]), in
/// table order — the `--kind exif` generator's allowlist for `GPS::Main` (see
/// [`exif_main_tag_ids`]). Gated on `feature = "gps"` (the GPS table is).
#[cfg(feature = "gps")]
#[doc(hidden)]
#[must_use]
pub fn gps_main_tag_ids() -> Vec<u16> {
  gps::GPS_TAGS.iter().map(|t| t.id).collect()
}

// ====================================================================// Unit tests
// ====================================================================
#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test TIFF/IFD builders index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Build a minimal big-endian TIFF with one IFD0 entry: `Make = "Canon"`.
  fn minimal_tiff_with_make() -> Vec<u8> {
    // Header: MM, magic 0x002a, IFD0 offset 8.
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry.
    t.extend_from_slice(&[0x00, 0x01]);
    // Entry: tag 0x010f (Make), format 2 (ASCII), count 6, value-or-offset.
    // "Canon\0" is 6 bytes > 4 ⇒ stored at an offset. Put it right after the
    // next-IFD pointer.
    t.extend_from_slice(&[0x01, 0x0f]); // tag
    t.extend_from_slice(&[0x00, 0x02]); // format = ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count = 6
    // value offset — header(8) + count(2) + entry(12) + nextIFD(4) = 26.
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]);
    // next-IFD offset = 0 (no IFD1).
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // The "Canon\0" string at offset 26.
    t.extend_from_slice(b"Canon\0");
    t
  }

  #[test]
  fn rejects_short_buffer() {
    assert!(parse_exif_block(b"MM\0").is_none());
    assert!(parse_borrowed(b"").is_none());
  }

  #[test]
  fn rejects_bad_byte_order_marker() {
    // 8 bytes but a junk byte-order marker.
    assert!(parse_exif_block(b"XX\0\x2a\0\0\0\x08").is_none());
  }

  /// `Walker::lookup_name_in` resolves a Nikon tag NAME against the ACTIVE table's
  /// OWN slice — `TableRef::Nikon` → `%Nikon::Main`, `TableRef::NikonType2` →
  /// `%Nikon::Type2` — proving the table SPLIT is wired (#243 phase 3-bis, N1).
  /// The two tables REUSE tag ID 0x0003 for DIFFERENT tags (Main `ColorMode` vs
  /// Type2 `Quality`), so resolving the same ID against each yields DIFFERENT
  /// names; a single-table lookup would return the same name for both.
  #[test]
  fn nikon_lookup_name_in_splits_main_and_type2() {
    // Main 0x0004 is `Quality` (the canonical camera-indexing leaf).
    assert_eq!(
      Walker::lookup_name_in(TableRef::Nikon, 0x0004),
      Some("Quality")
    );
    // Type2 0x0003 resolves against `%Nikon::Type2` → `Quality`, which DIFFERS
    // from Main 0x0003 (`ColorMode`) — the split is live.
    assert_eq!(
      Walker::lookup_name_in(TableRef::NikonType2, 0x0003),
      Some("Quality")
    );
    assert_eq!(
      Walker::lookup_name_in(TableRef::Nikon, 0x0003),
      Some("ColorMode")
    );
    assert_ne!(
      Walker::lookup_name_in(TableRef::NikonType2, 0x0003),
      Walker::lookup_name_in(TableRef::Nikon, 0x0003)
    );
  }

  #[test]
  fn rejects_ifd0_offset_below_8() {
    // Valid MM marker but IFD0 offset = 4 (< 8 ⇒ DoProcessTIFF return 0).
    assert!(parse_exif_block(b"MM\0\x2a\0\0\0\x04").is_none());
  }

  /// `parse_gps_block` walks a GPS-ONLY top-level TIFF block (a Canon CR3 `CMT4`
  /// directory, `first_kind == Gps`) against `%GPS::Main`. The chain seeds its
  /// `active_table` from `first_kind`, so tag 0x0001 resolves as `GPSLatitudeRef`
  /// (its `%GPS::Main` name). A hard-coded `Exif` seed would look 0x0001 up in
  /// `%Exif::Main` and drop the GPS tag entirely. (Codex R1 finding 1.)
  #[test]
  fn parse_gps_block_resolves_top_directory_via_gps_table() {
    // MM, magic 0x002a, IFD0 offset 8.
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry = GPSLatitudeRef (0x0001), ASCII, count 2, "N\0" inline.
    t.extend_from_slice(&[0x00, 0x01]); // numEntries = 1
    t.extend_from_slice(&[0x00, 0x01]); // tag 0x0001
    t.extend_from_slice(&[0x00, 0x02]); // format = ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // count = 2
    t.extend_from_slice(b"N\0\0\0"); // inline value "N\0"
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    let meta = parse_gps_block(&t).expect("GPS block parses");
    assert!(
      meta.entry("GPSLatitudeRef").is_some(),
      "tag 0x0001 must resolve as GPSLatitudeRef via %GPS::Main, not the Exif table"
    );
  }

  /// A GPS-table directory (`parse_gps_block`, `first_kind == Gps`) must NOT
  /// apply Exif STRUCTURAL semantics — the `DNGVersion` 0xc612 RawConv
  /// DataMember tap — because that tap now follows [`Walker::active_table`]
  /// (`!= Gps`), NOT `kind` (`!is_gps()`). (Codex R2-1.)
  ///
  /// NOTE on the reachable shape: the R2-1 fix is written to also hold for a
  /// trailing directory of a GPS chain (`kind == Trailing`, `active_table` still
  /// `Gps`), but that exact shape is NOT reachable through the current walker —
  /// a GPS directory does not follow the next-IFD pointer (no `Multi`:
  /// [`Walker::walk_one_ifd_body`]'s `follows_chain` is `Ifd0`/`Trailing` only,
  /// `Exif.pm:7203`), and a GPS sub-IFD is walked as a SINGLE dir via
  /// [`Walker::process_subdir`]. So a GPS-only block is always one directory and
  /// `active_table == Gps ⟺ kind.is_gps()` for every reachable input. This test
  /// therefore pins the reachable analog: 0xc612 inside a GPS-table dir does NOT
  /// set the DNG DataMember (the tap is gated off whenever `active_table` is the
  /// GPS table), and the dir's leaves resolve via `%GPS::Main`.
  #[test]
  fn parse_gps_block_chain_trailing_dir_uses_gps_semantics() {
    // MM, magic 0x002a, IFD0 offset 8. IFD0 is the GPS dir (first_kind == Gps);
    // it holds a GPS leaf (0x0009 GPSStatus) AND tag 0xc612 (DNGVersion) with a
    // TRUTHY `1 1 0 0` value. The 0xc612 tap must stay off under the GPS table.
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x02]); // numEntries = 2
    // entry A: GPSStatus (0x0009), ASCII, count 2, "A\0" inline — a %GPS::Main
    // leaf, present iff the dir is walked under the GPS table.
    t.extend_from_slice(&[0x00, 0x09]); // tag 0x0009
    t.extend_from_slice(&[0x00, 0x02]); // format = ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // count = 2
    t.extend_from_slice(b"A\0\0\0"); // inline value "A\0"
    // entry B: DNGVersion (0xc612), int8u[4], TRUTHY `1 1 0 0` inline — the Exif
    // DNG RawConv tap, which must NOT fire because `active_table == Gps`.
    t.extend_from_slice(&[0xc6, 0x12]); // tag 0xc612
    t.extend_from_slice(&[0x00, 0x01]); // format = int8u
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count = 4
    t.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // truthy DNGVersion value
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    let meta = parse_gps_block(&t).expect("GPS block parses");
    // THE DISCRIMINATOR: the 0xc612 DNG tap was skipped because the dir's
    // `active_table == Gps`. (`%GPS::Main` has no 0xc612 entry; the Exif-only
    // tap must not run under the GPS table.)
    assert!(
      !meta.has_dng_version(),
      "0xc612 in a GPS-table dir must NOT fire the Exif DNGVersion tap \
       (the gate follows active_table == Gps)"
    );
    // Corroborate that the dir IS walked under %GPS::Main: its GPSStatus leaf
    // resolves (an Exif-table walk would read 0x0009 as a different/unknown tag).
    assert!(
      meta.entry("GPSStatus").is_some(),
      "tag 0x0009 must resolve as GPSStatus via %GPS::Main"
    );
    // And the 0xc612 DNGVersion tag is itself absent from the leaf output (it is
    // unknown to %GPS::Main — dropped, never emitted as an Exif DNGVersion).
    assert!(
      meta.entry("DNGVersion").is_none(),
      "0xc612 is not a %GPS::Main leaf, so no DNGVersion tag is emitted"
    );
  }

  #[test]
  fn embedded_bigtiff_magic_is_not_parsed() {
    // A BigTIFF (0x2b) magic in an EMBEDDED block (`parse_exif_block` =
    // `standalone_tiff == false`) is NOT parsed: bundled reaches `ProcessBTF`
    // only from `DoProcessTIFF`'s `$raf` arm (`ExifTool.pm:8629`/`:8661`), which
    // an embedded `APP1`/`eXIf`/MakerNote block lacks. Returns `None` (no Exif),
    // no panic — exactly as before this walker existed.

    // Big-endian BigTIFF: MM, magic 0x002b, bytesize 0x0008, reserved 0x0000,
    // then an 8-byte IFD0 offset (0x10).
    let mut be: Vec<u8> = vec![b'M', b'M', 0x00, 0x2b, 0x00, 0x08, 0x00, 0x00];
    be.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]);
    be.extend_from_slice(&[0u8; 32]);
    assert!(
      parse_exif_block(&be).is_none(),
      "embedded big-endian BigTIFF (0x2b) must not be parsed, no Exif"
    );

    // Little-endian BigTIFF: II, magic 0x2b00, bytesize 0x0800.
    let mut le: Vec<u8> = vec![b'I', b'I', 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00];
    le.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    le.extend_from_slice(&[0u8; 32]);
    assert!(
      parse_exif_block(&le).is_none(),
      "embedded little-endian BigTIFF (0x2b) must not be parsed, no Exif"
    );

    // A classic 0x2a header still parses normally (the gate is BigTIFF-only).
    let classic = minimal_tiff_with_make();
    let meta = parse_exif_block(&classic).expect("classic 0x2a TIFF still parses");
    assert_eq!(meta.byte_order(), Some(ByteOrder::Big));
    assert_eq!(
      meta.entry("Make").map(|e| e.tag_id()),
      Some(0x010f),
      "classic TIFF's IFD0:Make must still decode"
    );
  }

  /// Build a minimal little-endian BigTIFF (`0x2b`) in memory. `entries` are
  /// 20-byte BigTIFF IFD entries (`tag(2) format(2) count(8) value-or-offset(8)`);
  /// `trailing` is appended after the IFD0 block + its 8-byte next-IFD pointer
  /// (so an out-of-line value's offset can point into it). The 16-byte header is
  /// `II` + `0x002b` + offset-bytesize `0x0008` + `0x0000` + an 8-byte IFD0
  /// offset of 16. `order` selects endianness.
  fn minimal_bigtiff(order: ByteOrder, entries: &[[u8; 20]], trailing: &[u8]) -> Vec<u8> {
    let u16b = |v: u16| -> [u8; 2] {
      match order {
        ByteOrder::Little => v.to_le_bytes(),
        ByteOrder::Big => v.to_be_bytes(),
      }
    };
    let u64b = |v: u64| -> [u8; 8] {
      match order {
        ByteOrder::Little => v.to_le_bytes(),
        ByteOrder::Big => v.to_be_bytes(),
      }
    };
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(match order {
      ByteOrder::Little => b"II",
      ByteOrder::Big => b"MM",
    });
    out.extend_from_slice(&u16b(0x2b)); // magic 0x002b
    out.extend_from_slice(&u16b(0x0008)); // offset bytesize = 8
    out.extend_from_slice(&u16b(0x0000)); // constant 0
    out.extend_from_slice(&u64b(16)); // IFD0 offset = 16 (right after the header)
    // IFD0: 8-byte entry count.
    out.extend_from_slice(&u64b(entries.len() as u64));
    for e in entries {
      out.extend_from_slice(e);
    }
    out.extend_from_slice(&u64b(0)); // next-IFD pointer = 0
    out.extend_from_slice(trailing);
    out
  }

  /// A 20-byte BigTIFF IFD entry with an INLINE value (`size <= 8`): `value` is
  /// left-justified into the 8-byte value field.
  fn big_entry_inline(
    order: ByteOrder,
    tag: u16,
    format: u16,
    count: u64,
    value: &[u8],
  ) -> [u8; 20] {
    assert!(value.len() <= 8, "inline BigTIFF value must be <= 8 bytes");
    let (u16b, u64b): (fn(u16) -> [u8; 2], fn(u64) -> [u8; 8]) = match order {
      ByteOrder::Little => (u16::to_le_bytes, u64::to_le_bytes),
      ByteOrder::Big => (u16::to_be_bytes, u64::to_be_bytes),
    };
    let mut e = [0u8; 20];
    e[0..2].copy_from_slice(&u16b(tag));
    e[2..4].copy_from_slice(&u16b(format));
    e[4..12].copy_from_slice(&u64b(count));
    e[12..12 + value.len()].copy_from_slice(value);
    e
  }

  /// A 20-byte BigTIFF IFD entry with an OUT-OF-LINE value (`size > 8`): the
  /// 8-byte value field holds the absolute file `offset`.
  fn big_entry_offset(
    order: ByteOrder,
    tag: u16,
    format: u16,
    count: u64,
    offset: u64,
  ) -> [u8; 20] {
    let (u16b, u64b): (fn(u16) -> [u8; 2], fn(u64) -> [u8; 8]) = match order {
      ByteOrder::Little => (u16::to_le_bytes, u64::to_le_bytes),
      ByteOrder::Big => (u16::to_be_bytes, u64::to_be_bytes),
    };
    let mut e = [0u8; 20];
    e[0..2].copy_from_slice(&u16b(tag));
    e[2..4].copy_from_slice(&u16b(format));
    e[4..12].copy_from_slice(&u64b(count));
    e[12..20].copy_from_slice(&u64b(offset));
    e
  }

  #[test]
  fn bigtiff_header_parses_both_byte_orders() {
    // A single inline IFD0 entry: ImageWidth (0x0100), int16u (3), count 1,
    // value 8 — exercised in BOTH II and MM order. The standalone-TIFF entry
    // (`parse_borrowed`, `standalone_tiff == true`) must parse the 16-byte
    // BigTIFF header + the 8-byte-count IFD and decode the leaf.
    for order in [ByteOrder::Little, ByteOrder::Big] {
      let width = match order {
        ByteOrder::Little => big_entry_inline(order, 0x0100, 3, 1, &8u16.to_le_bytes()),
        ByteOrder::Big => big_entry_inline(order, 0x0100, 3, 1, &8u16.to_be_bytes()),
      };
      let data = minimal_bigtiff(order, &[width], &[]);
      let meta = parse_borrowed(&data).expect("BigTIFF parses");
      // BigTIFF emits NO `File:ExifByteOrder` (`FoundTag`'d only in DoProcessTIFF,
      // which `ProcessBTF` never reaches), so the emission signal is `None` in
      // BOTH orders — the order was still applied to the DECODE: the int16u value
      // below reads as 8, NOT the byte-swapped 0x0800 (2048).
      assert_eq!(meta.byte_order(), None);
      let w = meta.entry("ImageWidth").expect("ImageWidth decoded");
      assert_eq!(w.tag_id(), 0x0100);
      assert_eq!(w.value_ref().raw(), &RawValue::U64(vec![8]));
      assert!(
        meta.warnings().is_empty(),
        "a clean BigTIFF raises no warnings: {:?}",
        meta.warnings()
      );
    }
  }

  /// R3 finding: a multi-page BigTIFF DOES emit `File:PageCount`. An IFD0
  /// `NewSubfileType` (0x00fe) == 2 trips the `MultiPage` flag (`Exif.pm:456`),
  /// and `DoProcessTIFF` runs `FoundTag(PageCount => …) if $$self{MultiPage}`
  /// (`ExifTool.pm:8667`) RIGHT AFTER `ProcessBTF` (the `:8668` `return 1` is
  /// before the `:8691` ExifByteOrder site). So `parse_bigtiff` mirrors the
  /// classic synthesis on `w.multi_page` (the flat `BigTIFF.btf` has no
  /// SubfileType ⇒ no PageCount, asserted in the real-fixture test).
  #[test]
  fn bigtiff_multipage_subfiletype_emits_page_count() {
    let order = ByteOrder::Big;
    // IFD0: NewSubfileType (0x00fe, int32u, count 1) = 2 ⇒ MultiPage.
    let st = big_entry_inline(order, 0x00fe, 4, 1, &2u32.to_be_bytes());
    let data = minimal_bigtiff(order, &[st], &[]);
    let meta = parse_borrowed(&data).expect("BigTIFF parses");
    assert_eq!(
      meta.multi_page_count(),
      Some(1),
      "an IFD0 SubfileType==2 sets MultiPage ⇒ File:PageCount = 1: {:?}",
      meta.multi_page_count()
    );
  }

  /// R4 finding: `OldSubfileType` (0x00ff) BigTIFFs ALSO emit `File:PageCount`.
  /// 0x00ff is absent from the port's leaf table but IS in `%Exif::Main`, so
  /// the walk lets it past the leaf-known gate to reach [`emit`](Walker::emit),
  /// whose `MultiPage` RawConv tap (`Exif.pm:470`) trips on value 3 — exactly as
  /// the classic walker does. The unported leaf is still dropped (no spurious
  /// `OldSubfileType` tag), only the `DoProcessTIFF` `File:PageCount` synthesis
  /// (`ExifTool.pm:8667`) fires. Crafted (deprecated tag), but the divergence
  /// from the classic path was real.
  #[test]
  fn bigtiff_multipage_old_subfiletype_emits_page_count() {
    let order = ByteOrder::Big;
    // IFD0: OldSubfileType (0x00ff, int16u, count 1) = 3 ⇒ MultiPage.
    let st = big_entry_inline(order, 0x00ff, 3, 1, &3u16.to_be_bytes());
    let data = minimal_bigtiff(order, &[st], &[]);
    let meta = parse_borrowed(&data).expect("BigTIFF parses");
    assert_eq!(
      meta.multi_page_count(),
      Some(1),
      "an IFD0 OldSubfileType==3 sets MultiPage ⇒ File:PageCount = 1: {:?}",
      meta.multi_page_count()
    );
    assert!(
      meta.entry("OldSubfileType").is_none(),
      "0x00ff is unported — only the MultiPage side-effect runs, no leaf is emitted"
    );
  }

  #[test]
  fn bigtiff_rejects_bad_offset_bytesize_and_constant() {
    // `ProcessBTF`'s regex requires offset-bytesize 0x0008 (bytes 4-5) AND the
    // 0x0000 constant (bytes 6-7). A non-8 bytesize or a non-zero constant must
    // be REJECTED (`None`), not misparsed.
    let width = big_entry_inline(ByteOrder::Little, 0x0100, 3, 1, &8u16.to_le_bytes());

    // Good header parses (control).
    assert!(parse_borrowed(&minimal_bigtiff(ByteOrder::Little, &[width], &[])).is_some());

    // Bad offset-bytesize (4 instead of 8) at bytes 4-5.
    let mut bad_bytesize = minimal_bigtiff(ByteOrder::Little, &[width], &[]);
    bad_bytesize[4] = 0x04;
    assert!(
      parse_borrowed(&bad_bytesize).is_none(),
      "offset-bytesize != 8 must reject the BigTIFF header"
    );

    // Non-zero constant at bytes 6-7.
    let mut bad_constant = minimal_bigtiff(ByteOrder::Little, &[width], &[]);
    bad_constant[6] = 0x01;
    assert!(
      parse_borrowed(&bad_constant).is_none(),
      "a non-zero constant must reject the BigTIFF header"
    );

    // A header truncated before the full 16 bytes (the `Read == 16` gate).
    let short = &minimal_bigtiff(ByteOrder::Little, &[width], &[])[..15];
    assert!(
      parse_borrowed(short).is_none(),
      "a < 16-byte BigTIFF header must reject"
    );
  }

  #[test]
  fn bigtiff_walks_inline_and_out_of_line_values() {
    // IFD0 with TWO entries: an INLINE int16u (size 2 <= 8) and an OUT-OF-LINE
    // BitsPerSample int16u[3] (size 6 <= 8 would be inline, so use int32u[3] =>
    // size 12 > 8 to force the out-of-line path). The out-of-line value lives in
    // the trailing block, at an absolute offset.
    let order = ByteOrder::Little;
    // ImageWidth 0x0100 int16u count 1 = 8, inline.
    let width = big_entry_inline(order, 0x0100, 3, 1, &8u16.to_le_bytes());
    // StripByteCounts 0x0117 int32u[3] => 12 bytes > 8 => out-of-line. The
    // absolute offset is computed below once the layout is known.
    //
    // Layout: header(16) + count(8) + 2*entry(40) + nextptr(8) = 72. The
    // out-of-line value block starts at offset 72 (the trailing bytes).
    let value_off: u64 = 16 + 8 + 2 * 20 + 8;
    let counts = big_entry_offset(order, 0x0117, 4, 3, value_off);
    // Three int32u values 10, 20, 30 (little-endian) in the trailing block.
    let mut trailing: Vec<u8> = Vec::new();
    for v in [10u32, 20, 30] {
      trailing.extend_from_slice(&v.to_le_bytes());
    }
    let data = minimal_bigtiff(order, &[width, counts], &trailing);
    assert_eq!(data.len() as u64, value_off + 12, "layout sanity");

    let meta = parse_borrowed(&data).expect("BigTIFF parses");
    assert_eq!(
      meta.entry("ImageWidth").map(|e| e.tag_id()),
      Some(0x0100),
      "inline value decoded"
    );
    let sbc = meta
      .entry("StripByteCounts")
      .expect("out-of-line StripByteCounts decoded");
    assert_eq!(sbc.tag_id(), 0x0117);
    assert!(
      meta.warnings().is_empty(),
      "clean BigTIFF raises no warnings: {:?}",
      meta.warnings()
    );
  }

  #[test]
  fn bigtiff_truncated_directory_does_not_panic() {
    // An 8-byte count claiming more entries than the buffer holds must warn
    // "Truncated <dir> directory" and abort cleanly — no panic, no OOB
    // (the `#![deny(clippy::indexing_slicing)]` bounds-safety contract). Build a
    // valid header but truncate the body so `count*20` overruns.
    let order = ByteOrder::Little;
    let width = big_entry_inline(order, 0x0100, 3, 1, &8u16.to_le_bytes());
    let mut data = minimal_bigtiff(order, &[width], &[]);
    // Overwrite the IFD0 count (at offset 16) with a huge value; the body is
    // far shorter, so the entry block read overruns.
    data[16..24].copy_from_slice(&9999u64.to_le_bytes());
    let meta = parse_borrowed(&data).expect("header still parses (count is read later)");
    assert!(
      meta.entries().is_empty(),
      "a truncated BigTIFF directory yields no leaf tags"
    );
    assert!(
      meta.warnings().iter().any(|w| w.contains("Truncated")),
      "a truncated BigTIFF directory warns: {:?}",
      meta.warnings()
    );
  }

  #[test]
  fn ifd_name_renders_trailing_numbers_past_u16() {
    // Codex R12/F1 — the trailing-IFD number is a `u32` and `IfdName`
    // spells it with NO upper bound. A chain past IFD65535 must produce
    // DISTINCT decimal names (not pin at "IFD65535").
    assert_eq!(IfdKind::Trailing(1).as_str(), "IFD1");
    assert_eq!(IfdKind::Trailing(65535).as_str(), "IFD65535");
    assert_eq!(IfdKind::Trailing(65536).as_str(), "IFD65536");
    assert_eq!(IfdKind::Trailing(65537).as_str(), "IFD65537");
    // The widest name still fits the 13-byte inline buffer.
    assert_eq!(IfdKind::Trailing(u32::MAX).as_str(), "IFD4294967295");
  }

  #[test]
  fn parses_make_from_minimal_tiff() {
    let t = minimal_tiff_with_make();
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert_eq!(meta.byte_order(), Some(ByteOrder::Big));
    let make = meta.entry("Make").expect("Make tag");
    assert_eq!(make.group(), "IFD0");
    assert_eq!(make.tag_id(), 0x010f);
    match make.value_ref().raw() {
      RawValue::Text { text, .. } => assert_eq!(text, "Canon"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  #[test]
  fn little_endian_inline_value() {
    // II TIFF, one IFD0 entry: Orientation (0x0112) int16u count 1 = 6.
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x01, 0x00]); // 1 entry
    t.extend_from_slice(&[0x12, 0x01]); // tag 0x0112 (LE)
    t.extend_from_slice(&[0x03, 0x00]); // format 3 (int16u)
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    t.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // inline value 6
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next IFD 0
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert_eq!(meta.byte_order(), Some(ByteOrder::Little));
    let o = meta.entry("Orientation").expect("Orientation");
    assert_eq!(o.value_ref().raw(), &RawValue::U64(vec![6]));
  }

  #[test]
  fn unknown_tag_is_omitted() {
    // II TIFF, one entry with an unknown tag ID 0xdead — should be omitted
    // (faithful to `next unless $verbose`).
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x01, 0x00]); // 1 entry
    t.extend_from_slice(&[0xad, 0xde]); // tag 0xdead (LE)
    t.extend_from_slice(&[0x03, 0x00]); // format int16u
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    t.extend_from_slice(&[0x2a, 0x00, 0x00, 0x00]); // value 42
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next IFD 0
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert!(meta.entries().is_empty(), "unknown tag must be omitted");
  }

  #[test]
  fn bad_format_code_entry_skipped() {
    // An entry with format code 0 (invalid) is skipped, not fatal.
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x01, 0x00]); // 1 entry
    t.extend_from_slice(&[0x12, 0x01]); // tag Orientation
    t.extend_from_slice(&[0x00, 0x00]); // format 0 — INVALID
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert!(
      meta.entries().is_empty(),
      "bad-format entry must be skipped"
    );
  }

  #[test]
  fn sub_dir_resolution() {
    assert_eq!(
      sub_dir_for(0x8769, IfdKind::Ifd0),
      Some(SubDirKind::ExifIfd)
    );
    assert_eq!(sub_dir_for(0x8825, IfdKind::Ifd0), Some(SubDirKind::Gps));
    assert_eq!(
      sub_dir_for(0x927c, IfdKind::ExifIfd),
      Some(SubDirKind::MakerNote)
    );
    // A leaf tag ⇒ None.
    assert_eq!(sub_dir_for(0x010f, IfdKind::Ifd0), None);
    // Inside the GPS IFD, nothing is a SubDirectory.
    assert_eq!(sub_dir_for(0x8769, IfdKind::Gps), None);
  }

  /// A single-byte `undef` (format 7, count 1) decodes as an INTEGER, not a
  /// 1-byte binary blob — `Exif.pm:6644` `$formatStr = 'int8u' if $format
  /// == 7 and $count == 1`. Drives the `undef`-typed enumerations
  /// (SceneType / FileSource).
  #[test]
  fn single_byte_undef_decodes_as_int8u() {
    // II TIFF, ExifIFD with SceneType (0xa301, undef, count 1, value 1).
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    // IFD0: 1 entry (ExifOffset pointer).
    t.extend_from_slice(&[0x01, 0x00]);
    t.extend_from_slice(&[0x69, 0x87]); // tag 0x8769 ExifOffset (LE)
    t.extend_from_slice(&[0x04, 0x00]); // format LONG
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    // ExifIFD offset: header(8) + IFD0(2 + 12 + 4) = 26.
    t.extend_from_slice(&[0x1a, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next = 0
    // ExifIFD at 26: 1 entry (SceneType).
    t.extend_from_slice(&[0x01, 0x00]);
    t.extend_from_slice(&[0x01, 0xa3]); // tag 0xa301 SceneType (LE)
    t.extend_from_slice(&[0x07, 0x00]); // format UNDEF
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // inline value byte 1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next = 0
    let meta = parse_exif_block(&t).expect("valid TIFF");
    let st = meta.entry("SceneType").expect("SceneType");
    assert_eq!(st.ifd(), IfdKind::ExifIfd);
    // Decoded as int8u (a U64 singleton), NOT a Bytes blob.
    assert_eq!(st.value_ref().raw(), &RawValue::U64(vec![1]));
  }

  /// The MakerNote (0x927c) tag is CAPTURED — `ExifMeta::maker_note()`
  /// exposes the raw bytes — and vendor parsing is DEFERRED. No `MakerNote`
  /// leaf tag is emitted.
  #[test]
  fn maker_note_captured_not_parsed() {
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry (ExifOffset).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x87, 0x69]); // tag 0x8769 (MM)
    t.extend_from_slice(&[0x00, 0x04]); // format LONG
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // ExifIFD offset 26
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
    // ExifIFD at 26: 1 entry (MakerNote).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x92, 0x7c]); // tag 0x927c MakerNote (MM)
    t.extend_from_slice(&[0x00, 0x07]); // format UNDEF
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // count 8 (> 4 ⇒ offset)
    // MakerNote value offset: 26 + (2 + 12 + 4) = 44.
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
    // The 8-byte MakerNote blob at offset 44.
    t.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    // The MakerNote blob is captured, not parsed into tags.
    let mn = meta.maker_note().expect("MakerNote captured");
    assert_eq!(
      mn.bytes(),
      &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(mn.len(), 8);
    // No `MakerNote` leaf tag — vendor parsing deferred.
    assert!(meta.entry("MakerNote").is_none());
  }

  /// [`ExifMeta::emits_movable_tag`] is now DERIVED from the real
  /// [`tags`](crate::emit::Taggable::tags) stream (`any(non-`File`,
  /// non-`Unknown`)`), so a "does it match `tags`" oracle would be tautological.
  /// Instead this PINS the two boundary behaviors the predicate exists to
  /// enforce, against blocks built through the real parser:
  ///
  /// - the `File` exclusion — a byte-order-only block emits ONLY
  ///   `File:ExifByteOrder` ⇒ `false`;
  /// - the `Unknown` exclusion — a MakerNote that decodes to ONLY `Unknown=>1`
  ///   leaves is not default-visible ⇒ `false`;
  ///
  /// plus the two POSITIVE channels (`entries`, a default-visible MakerNote with
  /// empty `entries` — the R8 / R9 cases) ⇒ `true`. Because the predicate reads
  /// whatever `tags` yields, any future default-visible non-`File` channel added
  /// to `tags` is covered automatically — the channel-by-channel drift that
  /// missed `entries` (R8) then the MakerNote (R9) cannot recur.
  #[cfg(feature = "quicktime")]
  #[test]
  fn emits_movable_tag_excludes_file_and_unknown() {
    // A minimal big-endian TIFF: header + IFD0 (the given entry bytes) + extra.
    fn tiff(ifd0_entries: &[u8], n_entries: u16, extra: &[u8]) -> Vec<u8> {
      let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
      t.extend_from_slice(&n_entries.to_be_bytes());
      t.extend_from_slice(ifd0_entries);
      t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next = 0
      t.extend_from_slice(extra);
      t
    }

    // An Apple MakerNote-only TIFF: IFD0 → ExifIFD → MakerNote, no IFD0 entry,
    // the blob carrying a single `entry`. `entries` stays EMPTY; whether the
    // block is "movable" depends solely on whether the MakerNote's lone leaf is
    // default-visible. `entry` = (tag, format, inline-value) for a count-1 slot.
    fn apple_mn_only_tiff(tag: u16, format: u16, inline_value: u32) -> Vec<u8> {
      let mut apple_blob: Vec<u8> = Vec::new();
      apple_blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM"); // 14-byte header
      apple_blob.extend_from_slice(&1u16.to_be_bytes()); // 1 IFD entry
      apple_blob.extend_from_slice(&tag.to_be_bytes());
      apple_blob.extend_from_slice(&format.to_be_bytes());
      apple_blob.extend_from_slice(&1u32.to_be_bytes()); // count 1
      apple_blob.extend_from_slice(&inline_value.to_be_bytes());
      let exififd_off: u32 = 8 + (2 + 12 + 4); // 26
      let mn_off: u32 = exififd_off + (2 + 12 + 4); // 44
      let mut mn_ifd0: Vec<u8> = Vec::new();
      mn_ifd0.extend_from_slice(&[0x87, 0x69]); // ExifIFD pointer 0x8769
      mn_ifd0.extend_from_slice(&[0x00, 0x04]); // LONG
      mn_ifd0.extend_from_slice(&1u32.to_be_bytes());
      mn_ifd0.extend_from_slice(&exififd_off.to_be_bytes());
      let mut exififd: Vec<u8> = Vec::new();
      exififd.extend_from_slice(&1u16.to_be_bytes()); // 1 entry
      exififd.extend_from_slice(&[0x92, 0x7c]); // MakerNote 0x927c
      exififd.extend_from_slice(&[0x00, 0x07]); // UNDEFINED
      exififd.extend_from_slice(&(apple_blob.len() as u32).to_be_bytes());
      exififd.extend_from_slice(&mn_off.to_be_bytes());
      exififd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next = 0
      let mut extra = exififd;
      extra.extend_from_slice(&apple_blob);
      tiff(&mn_ifd0, 1, &extra)
    }

    // (a) byte-order-only / empty IFD0: `tags` emits ONLY `File:ExifByteOrder`
    // (family-0 `File`) ⇒ the `File` exclusion makes this NOT movable.
    let empty_tiff = tiff(&[], 0, &[]);
    let empty = parse_exif_block(&empty_tiff).expect("empty TIFF");
    assert!(
      !empty.emits_movable_tag(),
      "byte-order-only (File-prefix) ⇒ not movable"
    );

    // (b) one IFD0 ASCII entry (`Make`): the `entries` channel emits an `EXIF:*`
    // tag ⇒ movable.
    let mut make_entry: Vec<u8> = Vec::new();
    make_entry.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    make_entry.extend_from_slice(&[0x00, 0x02]); // ASCII
    make_entry.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    make_entry.extend_from_slice(b"AB\x00\x00"); // ASCII "AB" + NUL pad
    let make_tiff = tiff(&make_entry, 1, &[]);
    let with_make = parse_exif_block(&make_tiff).expect("Make TIFF");
    assert!(with_make.emits_movable_tag(), "IFD0 entry ⇒ movable");

    // (c) MakerNote-only IFD0, the lone leaf a DEFAULT-VISIBLE Apple tag
    // (`MakerNoteVersion`, 0x0001 int32s, `unknown:false`). `entries` is EMPTY,
    // yet the MakerNote channel emits a `MakerNotes:*` tag ⇒ movable (the R9
    // case the old `!entries.is_empty()` guess missed).
    let mn_visible_tiff = apple_mn_only_tiff(0x0001, 0x0009, 4);
    let mn_visible = parse_exif_block(&mn_visible_tiff).expect("MakerNote TIFF");
    assert!(
      mn_visible.entries().is_empty(),
      "the MakerNote-only block has NO IFD-walk entry"
    );
    assert!(
      mn_visible.maker_note().is_some(),
      "the MakerNote blob is captured"
    );
    assert!(
      mn_visible.emits_movable_tag(),
      "a default-visible MakerNote (no entries) ⇒ movable"
    );

    // (d) MakerNote-only IFD0, the lone leaf an `Unknown=>1` Apple tag
    // (`ImageProcessingFlags`, 0x0019 int32s — Apple.pm:147). `entries` is
    // EMPTY and the only emission is `Unknown`, which `run_emission` drops from
    // `-j` output, so `tags` yields NO default-visible non-`File` tag ⇒ NOT
    // movable. This pins the `Unknown` exclusion: an Unknown-only MakerNote must
    // not anchor (ExifTool's first movable EXIF key comes from a later segment).
    let mn_unknown_tiff = apple_mn_only_tiff(0x0019, 0x0009, 1);
    let mn_unknown = parse_exif_block(&mn_unknown_tiff).expect("Unknown-MN TIFF");
    assert!(
      mn_unknown.entries().is_empty(),
      "the Unknown-MakerNote block has NO IFD-walk entry"
    );
    assert!(
      mn_unknown.maker_note().is_some(),
      "the Unknown MakerNote blob is still captured"
    );
    assert!(
      mn_unknown
        .maker_note()
        .is_some_and(|mn| !mn.emissions_print_conv().is_empty()
          && mn.emissions_print_conv().iter().all(|e| e.unknown())),
      "the lone Apple emission is `Unknown=>1`"
    );
    assert!(
      !mn_unknown.emits_movable_tag(),
      "an Unknown-only MakerNote ⇒ not movable — the `Unknown` exclusion"
    );
  }

  /// A self-referencing IFD pointer (IFD0 → IFD0) is rejected by the
  /// reprocess guard (`Exif.pm:7195-7196`) — no infinite loop.
  #[test]
  fn self_referencing_ifd_does_not_loop() {
    // II TIFF: IFD0 at offset 8, ExifOffset pointing back to offset 8.
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x01, 0x00]); // 1 entry
    t.extend_from_slice(&[0x69, 0x87]); // ExifOffset
    t.extend_from_slice(&[0x04, 0x00]); // LONG
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    t.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // points back to IFD0 (8)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next 0
    // Must terminate (the guard rejects the second visit to offset 8).
    let meta = parse_exif_block(&t).expect("valid TIFF");
    // ExifOffset is a SubIFD pointer (no leaf tag); the self-loop is
    // rejected, so there are simply no entries.
    assert!(meta.entries().is_empty());
  }

  /// A standalone-TIFF round trip through the GPS sub-IFD: the 0x8825
  /// pointer reaches the GPS IFD and its tags get the `GPS` family-1 group.
  #[test]
  fn gps_subifd_walk() {
    // MM TIFF: IFD0 with a GPSInfo (0x8825) pointer to a GPS IFD that holds
    // one tag — GPSMapDatum (0x0012, ASCII "WGS84\0", 6 bytes).
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry (GPSInfo).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x88, 0x25]); // tag 0x8825 (MM)
    t.extend_from_slice(&[0x00, 0x04]); // LONG
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // GPS IFD offset 26
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
    // GPS IFD at 26: 1 entry (GPSMapDatum).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x12]); // tag 0x0012 (MM)
    t.extend_from_slice(&[0x00, 0x02]); // ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6 (> 4 ⇒ offset)
    // value offset: 26 + (2 + 12 + 4) = 44.
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // GPS IFD next 0
    t.extend_from_slice(b"WGS84\x00"); // the GPSMapDatum string at 44
    let meta = parse_exif_block(&t).expect("valid TIFF");
    let datum = meta.entry("GPSMapDatum").expect("GPSMapDatum");
    // The GPS sub-IFD's tags carry the family-1 group "GPS".
    assert_eq!(datum.ifd(), IfdKind::Gps);
    assert_eq!(datum.group(), "GPS");
    match datum.value_ref().raw() {
      RawValue::Text { text, .. } => assert_eq!(text, "WGS84"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// Codex R13/F1 — IFD0's `ExifOffset` (0x8769) and `GPSInfo` (0x8825)
  /// pointing at ONE shared sub-IFD. ExifTool's `%PROCESSED` reprocess guard
  /// is gated on a non-zero `DirLen` (`ExifTool.pm:9052`); a standalone
  /// TIFF's IFD-pointer subdirectories carry `DirLen 0`
  /// (`Exif.pm:7020-7026`), so the guard is skipped and the shared offset is
  /// walked TWICE — once as `ExifIFD`, once as `GPS` — with no warning.
  /// Verified against bundled `perl exiftool`: emits `ExifIFD:Orientation`
  /// AND `GPS:GPSVersionID`. The R12/F2 carve-out admitted only
  /// GPS-after-InteropIFD, so the GPS pass returned `None` and every GPS
  /// tag was dropped; the re-modelled guard reprocesses any IFD-pointer
  /// subdirectory revisit. (Fixture sibling: `Exif_gps_shared_pointer.tif`.)
  #[test]
  fn shared_exifoffset_gpsinfo_pointer_reprocesses() {
    // II TIFF. IFD0@8: Orientation + ExifOffset + GPSInfo; ExifOffset and
    // GPSInfo both point at the shared IFD@50, which holds Orientation
    // (an ExifIFD-table tag) and GPSVersionID (a GPS-table tag).
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x03, 0x00]); // IFD0: 3 entries
    t.extend_from_slice(&[0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Orientation = 1
    t.extend_from_slice(&[0x69, 0x87, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x32, 0x00, 0x00, 0x00]); // ExifOffset -> 50
    t.extend_from_slice(&[0x25, 0x88, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x32, 0x00, 0x00, 0x00]); // GPSInfo -> 50
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next = 0
    debug_assert_eq!(t.len(), 50, "shared IFD must start at offset 50");
    t.extend_from_slice(&[0x02, 0x00]); // shared IFD@50: 2 entries
    t.extend_from_slice(&[0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x07, 0x00, 0x00, 0x00]); // Orientation = 7
    t.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x02, 0x03, 0x00, 0x00]); // GPSVersionID = 2.3.0.0
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // shared IFD next = 0
    let meta = parse_exif_block(&t).expect("valid TIFF");
    // The shared offset is reprocessed: the ExifIFD pass emits Orientation,
    // the GPS pass emits GPSVersionID — exactly as bundled ExifTool.
    let exif_orient = meta
      .entries()
      .iter()
      .find(|e| e.ifd() == IfdKind::ExifIfd && e.name() == "Orientation")
      .expect("ExifIFD:Orientation from the ExifOffset pass");
    assert_eq!(exif_orient.group(), "ExifIFD");
    let gps_ver = meta
      .entries()
      .iter()
      .find(|e| e.ifd() == IfdKind::Gps && e.name() == "GPSVersionID")
      .expect("GPS:GPSVersionID from the reprocessed GPSInfo pass");
    assert_eq!(gps_ver.group(), "GPS");
    // IFD0's own Orientation is still there; no spurious warning.
    assert!(
      meta
        .entries()
        .iter()
        .any(|e| e.ifd() == IfdKind::Ifd0 && e.name() == "Orientation")
    );
    assert!(
      meta.warnings().is_empty(),
      "no warning for a DirLen-0 subdirectory revisit, got {:?}",
      meta.warnings()
    );
  }

  /// A subdirectory pointer that loops back onto an ANCESTOR IFD is a true
  /// cycle and must terminate. IFD0's `ExifOffset` reaches ExifIFD@26, whose
  /// own `ExifOffset` (0x8769) points back at offset 26 — ExifIFD is still
  /// on the active recursion path, so the revisit is rejected. (The
  /// general-reprocess rule only admits SIBLING / completed-walk revisits.)
  #[test]
  fn subdir_ancestor_cycle_terminates() {
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&[0x01, 0x00]); // IFD0: 1 entry
    t.extend_from_slice(&[0x69, 0x87, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x1a, 0x00, 0x00, 0x00]); // ExifOffset -> 26
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next = 0
    debug_assert_eq!(t.len(), 26, "ExifIFD must start at offset 26");
    t.extend_from_slice(&[0x01, 0x00]); // ExifIFD@26: 1 entry
    t.extend_from_slice(&[0x69, 0x87, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
    t.extend_from_slice(&[0x1a, 0x00, 0x00, 0x00]); // ExifOffset -> 26 (self)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next = 0
    // Must terminate (no infinite recursion through the self-pointer).
    let meta = parse_exif_block(&t).expect("valid TIFF");
    // ExifOffset is a SubIFD pointer (no leaf tag); the cycle is rejected,
    // so there are simply no entries.
    assert!(meta.entries().is_empty());
  }

  /// PR #68 — multi-page TIFF tracking via the `SubfileType` (0x00fe)
  /// `RawConv` tap (`Exif.pm:452-457`). IFD0 SubfileType=0 increments
  /// `PageCount` to 1 (val ∈ {0, 2}, MultiPage stays 0); IFD1 SubfileType=2
  /// increments PageCount to 2 AND sets MultiPage=1 (`$val == 2`). The
  /// standalone-TIFF entry [`parse_borrowed`] populates `multi_page_count`
  /// from this state; embedded-block entries ([`parse_exif_block`]) hold it
  /// at `None`.
  #[test]
  fn subfile_type_tracks_pagecount_on_standalone_tiff() {
    // MM TIFF: IFD0 SubfileType=0 (full-res) next->IFD1; IFD1 SubfileType=2
    // (single page of multi-page) next=0.
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0@8: 1 entry (SubfileType=0).
    t.extend_from_slice(&[0x00, 0x01]); // count
    t.extend_from_slice(&[0x00, 0xfe, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]); // tag 0x00fe LONG count=1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // value = 0 (full-res)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // next IFD = 26
    debug_assert_eq!(t.len(), 26);
    // IFD1@26: 1 entry (SubfileType=2).
    t.extend_from_slice(&[0x00, 0x01]); // count
    t.extend_from_slice(&[0x00, 0xfe, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]); // tag 0x00fe LONG count=1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // value = 2 (single page of multi-page)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next IFD = 0
    // Standalone entry: emits `multi_page_count = Some(2)`.
    let meta = parse_borrowed(&t).expect("valid TIFF");
    assert_eq!(meta.multi_page_count(), Some(2));
    // Embedded entry on the same bytes: `multi_page_count = None` (the
    // `TIFF_TYPE == 'TIFF'` gate at ExifTool.pm:8757 is off).
    let embedded = parse_exif_block(&t).expect("valid TIFF");
    assert_eq!(embedded.multi_page_count(), None);
  }

  /// PR #68 — a single-page TIFF (one IFD with SubfileType=0) does NOT
  /// emit PageCount because `MultiPage` is never set: `val == 0` does not
  /// trip `$val == 2`, and `PageCount` reaches 1 (not > 1). Faithful to
  /// `ExifTool.pm:8757` `if $$self{MultiPage}` gate — bundled does NOT
  /// emit `File:PageCount` for a single-page TIFF.
  #[test]
  fn subfile_type_single_page_does_not_emit_pagecount() {
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // IFD0: 1 entry
    t.extend_from_slice(&[0x00, 0xfe, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]); // SubfileType LONG count=1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // value = 0 (full-resolution)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next IFD = 0
    let meta = parse_borrowed(&t).expect("valid TIFF");
    assert_eq!(meta.multi_page_count(), None);
  }

  /// PR #68 — `OldSubfileType` (0x00ff) `RawConv` (`Exif.pm:469-475`): val
  /// ∈ {1, 3} increments `PageCount`; val == 3 sets `MultiPage`. The tag
  /// is NOT in the port's leaf table (an unknown-tag drop), but the
  /// walker's RawConv tap still runs for the PageCount side effect. IFD0
  /// OldSubfileType=1 ⇒ PageCount=1; IFD1 OldSubfileType=3 ⇒ PageCount=2
  /// AND MultiPage=1. `multi_page_count = Some(2)` on the standalone walk.
  #[test]
  fn old_subfile_type_tracks_pagecount() {
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0@8: 1 entry — OldSubfileType=1 (full-resolution image).
    t.extend_from_slice(&[0x00, 0x01]);
    // 0x00ff SHORT count=1 value=1 — SHORT is left-justified in the 4-byte field.
    t.extend_from_slice(&[0x00, 0xff, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // value SHORT=1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // next IFD = 26
    debug_assert_eq!(t.len(), 26);
    // IFD1@26: 1 entry — OldSubfileType=3 (single page of multi-page).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0xff, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // value SHORT=3
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next IFD = 0
    let meta = parse_borrowed(&t).expect("valid TIFF");
    assert_eq!(meta.multi_page_count(), Some(2));
  }

  /// PR #68 — SubfileType=1 (reduced-resolution image) does NOT count
  /// against PageCount: `$val == ($val & 0x02)` is false for val=1
  /// (`1 != (1 & 0x02)` ⇒ `1 != 0`). Faithful to `Exif.pm:453`. Three
  /// reduced-res IFDs in a row still emit no PageCount.
  #[test]
  fn subfile_type_reduced_res_does_not_count() {
    let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0@8: SubfileType=1 next->IFD1.
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0xfe, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // next IFD = 26
    // IFD1@26: SubfileType=1 next=0.
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0xfe, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let meta = parse_borrowed(&t).expect("valid TIFF");
    assert_eq!(meta.multi_page_count(), None);
  }

  /// Run one `Conv` over a `RawValue::Text` and read back the emitted string.
  #[cfg(feature = "alloc")]
  fn emit_text_conv(value: &str, conv: Conv) -> String {
    let mut map = crate::tagmap::TagMap::new();
    let raw = RawValue::Text {
      text: value.to_string(),
      raw: value.as_bytes().into(),
    };
    emit_exif_value("IFD0", "T", &raw, conv, ByteOrder::Big, true, &mut map).unwrap();
    map.get_str("IFD0", "T").expect("emitted")
  }

  #[test]
  fn is_perl_space_matches_perl_backslash_s() {
    // Perl `\s` (5.18+) = space, tab, LF, CR, FF, VT — verified against the
    // bundled Perl 5.34 (`perl -e '... =~ s/\s+$//'`). NBSP (U+00A0) is NOT
    // in `\s` without `/u`, and a digit is not whitespace.
    for c in [' ', '\t', '\n', '\r', '\x0c', '\x0b'] {
      assert!(is_perl_space(c), "{c:?} should be \\s");
    }
    for c in ['\u{00a0}', '0', 'x'] {
      assert!(!is_perl_space(c), "{c:?} should NOT be \\s");
    }
  }

  #[test]
  fn trim_trailing_whitespace_strips_all_whitespace() {
    // `Make`/`Model`/`Software`/`Artist` RawConv `s/\s+$//` (Exif.pm:585/599/
    // 906/925): EVERY trailing whitespace char is stripped, in both modes.
    let conv = Conv::TrimTrailingWhitespace;
    assert_eq!(emit_text_conv("Canon   ", conv), "Canon");
    // Trailing TAB + space — `\s` strips both (proves it is NOT space-only).
    assert_eq!(emit_text_conv("EOS R5\t ", conv), "EOS R5");
    assert_eq!(emit_text_conv("SW\n\r\x0c\x0b ", conv), "SW");
    // Leading / interior whitespace is preserved (the regex is anchored `$`).
    assert_eq!(emit_text_conv("  A  B  ", conv), "  A  B");
    // No trailing whitespace ⇒ unchanged; empty stays empty.
    assert_eq!(emit_text_conv("Nikon", conv), "Nikon");
    assert_eq!(emit_text_conv("", conv), "");
    // An all-whitespace value collapses to empty (EXIF-"unknown" blank field).
    assert_eq!(emit_text_conv("    ", conv), "");
  }

  #[test]
  fn trim_trailing_spaces_strips_spaces_only() {
    // `SubSecTime*` ValueConv `s/ +$//` (Exif.pm:2543/2552/2560): trailing
    // SPACES only — a trailing TAB/NL is NOT trimmed (this is the distinction
    // the minimal-TIFF fixture cannot carry, so it is pinned here).
    let conv = Conv::TrimTrailingSpaces;
    assert_eq!(emit_text_conv("123  ", conv), "123");
    assert_eq!(emit_text_conv("70  ", conv), "70");
    // Trailing run ends in a TAB ⇒ the trailing-SPACE run is empty ⇒ KEPT.
    assert_eq!(emit_text_conv("7 \t", conv), "7 \t");
    // A trailing TAB alone is kept; a trailing NL is kept.
    assert_eq!(emit_text_conv("9\t", conv), "9\t");
    assert_eq!(emit_text_conv("9\n", conv), "9\n");
    // Interior space preserved; no trailing space ⇒ unchanged.
    assert_eq!(emit_text_conv("1 2", conv), "1 2");
    assert_eq!(emit_text_conv("12", conv), "12");
  }

  #[test]
  fn trim_convs_passthrough_non_text() {
    // The Perl regex is a no-op on a non-string value; both trim convs must
    // emit a non-`Text` `RawValue` faithfully unchanged (these tags are always
    // `string`, but an off-spec numeric value must not be dropped/altered).
    let mut map = crate::tagmap::TagMap::new();
    let raw = RawValue::U64(vec![42]);
    emit_exif_value(
      "IFD0",
      "T",
      &raw,
      Conv::TrimTrailingWhitespace,
      ByteOrder::Big,
      true,
      &mut map,
    )
    .unwrap();
    assert_eq!(map.get_str("IFD0", "T").as_deref(), Some("42"));
  }

  /// PR #36 Codex R18/F1 — `escape_json_is_number` is the faithful port of
  /// bundled `EscapeJSON`'s number regex `^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?
  /// (e[-+]?\d{1,3})?$` (`exiftool:3809`). Pinned with the SAME corpus as
  /// `h264::escape_json_number_gate_matches_exiftool_regex` (the shared spec).
  #[cfg(feature = "alloc")]
  #[test]
  fn escape_json_number_gate_matches_exiftool_regex() {
    // In-gate: bare integers, a single `0`, signed, fractional, exponent.
    for s in [
      "0",
      "5",
      "300",
      "72",
      "-7",
      "16.0",
      "0.64",
      "0.26015625",
      "-0.65",
      "12.05078125",
      "-0.6500000006",
      "3.4e+38",
      "1e3",
      "2.5E-4",
      "13.58",
      "100000000000000",    // 15-digit integer (max)
      "0.1234567890123456", // 16-fraction-digit (max)
    ] {
      assert!(escape_json_is_number(s), "{s:?} must match the number gate");
    }
    // Out of gate: empty, words, `:`/`/`/space-bearing, a leading `+`, a
    // leading-zero multi-digit integer, a `>15`-digit integer, a `>16`-digit
    // fraction, a `>3`-digit exponent.
    for s in [
      "",
      "inf",
      "undef",
      "Inf",
      "NaN",
      "1/724",
      "0.0 mm",
      "14:58:24",
      "54 deg 59' 22.80\"",
      "+1",
      "+1/2",
      "01",
      "0123",
      "1000000000000000",    // 16-digit integer (no-leading-zero arm)
      "0.00138106793200498", // 17-fraction-digit ⇒ ShutterSpeedValue
      "1e1234",              // 4-digit exponent
      "1.",
      "1.2.3",
      "- 5",
      "0x1f",
    ] {
      assert!(
        !escape_json_is_number(s),
        "{s:?} must NOT match the number gate"
      );
    }
  }

  /// `emit_gated_number` routes an in-gate rendered string to the matching
  /// numeric `write_*` (a bare JSON number) and an out-of-gate one to
  /// `write_str` (a quoted JSON string).
  #[cfg(feature = "alloc")]
  #[test]
  fn emit_gated_number_routes_by_escape_json_gate() {
    use crate::value::TagValue;
    let mut map = crate::tagmap::TagMap::new();
    // In-gate integer ⇒ `U64` (exact integer token).
    emit_gated_number("IFD0", "XResolution", "300", &mut map).unwrap();
    assert_eq!(map.get("IFD0", "XResolution"), Some(&TagValue::U64(300)));
    // In-gate signed integer ⇒ `I64`.
    emit_gated_number("E", "Neg", "-7", &mut map).unwrap();
    assert_eq!(map.get("E", "Neg"), Some(&TagValue::I64(-7)));
    // In-gate fractional ⇒ `F64`.
    emit_gated_number("E", "FNumber", "0.64", &mut map).unwrap();
    assert_eq!(map.get("E", "FNumber"), Some(&TagValue::F64(0.64)));
    // Out-of-gate (a `/`) ⇒ a `Str` (quoted JSON string).
    emit_gated_number("E", "Shutter", "1/724", &mut map).unwrap();
    assert_eq!(
      map.get("E", "Shutter"),
      Some(&TagValue::Str("1/724".into()))
    );
    // The zero-denominator rational word stays a `Str`.
    emit_gated_number("E", "Inf", "inf", &mut map).unwrap();
    assert_eq!(map.get("E", "Inf"), Some(&TagValue::Str("inf".into())));
    // Contract B / #197 over-f64-gate class (same defect class as the H264
    // classifier + `value.rs::serialize_in_gate_number_str`): a gate-matching
    // exponent OUTSIDE finite-f64 range (`1e999`, `parse::<f64>()` ⇒ `INFINITY`)
    // must NOT route through `write_f64` to `TagValue::F64(INFINITY)` (which
    // serializes the titlecase `"Inf"`, silently corrupting the verbatim
    // token); it stays the quoted source `Str`. No real EXIF caller feeds such
    // a token, but the guard keeps the gate class closed.
    for tok in ["1e999", "-1e999", "1e309"] {
      emit_gated_number("E", "Over", tok, &mut map).unwrap();
      assert_eq!(
        map.get("E", "Over"),
        Some(&TagValue::Str(tok.into())),
        "{tok:?} (over-f64 exponent) must stay a quoted string, not F64(INFINITY)"
      );
    }
    // A FINITE exponent value still routes to the float writer (no regression).
    emit_gated_number("E", "Exp", "1e10", &mut map).unwrap();
    assert_eq!(map.get("E", "Exp"), Some(&TagValue::F64(1e10)));
    // Contract B / #197 SYMMETRIC (under) side: a gate-matching token whose
    // nonzero significand UNDERFLOWS to a finite `0.0` (`1e-999`, `parse::<f64>()`
    // ⇒ `Ok(0.0)`) must NOT route through `write_f64` to `TagValue::F64(0.0)`
    // (which serializes a bare `0`, rewriting the nonzero token to zero); it stays
    // the quoted source `Str`.
    for tok in ["1e-999", "-1e-999", "9e-400"] {
      emit_gated_number("E", "Under", tok, &mut map).unwrap();
      assert_eq!(
        map.get("E", "Under"),
        Some(&TagValue::Str(tok.into())),
        "{tok:?} (nonzero-underflow exponent) must stay a quoted string, not F64(0.0)"
      );
    }
    // A GENUINE zero token (significand is zero) stays a BARE number — it
    // legitimately denotes zero, so the predicate must NOT preserve it as a string.
    emit_gated_number("E", "Zero", "0e-5", &mut map).unwrap();
    assert_eq!(map.get("E", "Zero"), Some(&TagValue::F64(0.0)));
    // A FINITE tiny IN-RANGE value (nonzero, no underflow) still routes to the
    // float writer — the predicate must not over-trigger on small magnitudes.
    emit_gated_number("E", "Tiny", "1e-300", &mut map).unwrap();
    assert_eq!(map.get("E", "Tiny"), Some(&TagValue::F64(1e-300)));
  }

  /// `emit_gated_f64` renders a finite value with `%.15g` then gates it: an
  /// ordinary value lands as a number, a `>16`-fraction-digit ValueConv
  /// result (a `ShutterSpeedValue`) lands as a quoted string, and a
  /// non-finite value keeps `TagValue::F64`'s titlecase-string handling.
  #[cfg(feature = "alloc")]
  #[test]
  fn emit_gated_f64_quotes_out_of_gate_floats() {
    use crate::value::TagValue;
    let mut map = crate::tagmap::TagMap::new();
    // Ordinary finite value ⇒ a bare JSON number.
    emit_gated_f64("E", "Lat", 54.989_666_666_666_7, &mut map).unwrap();
    assert!(matches!(map.get("E", "Lat"), Some(TagValue::F64(_))));
    // A 17-significant-digit value renders (`%.15g`) to a 17-fraction-digit
    // string — out of the gate's `\.\d{1,16}` cap ⇒ a quoted JSON string,
    // byte-identical to bundled (`ExifIFD:ShutterSpeedValue` under `-n`).
    let shutter = 0.001_381_067_932_004_98_f64;
    emit_gated_f64("E", "Shutter", shutter, &mut map).unwrap();
    assert_eq!(
      map.get("E", "Shutter"),
      Some(&TagValue::Str("0.00138106793200498".into())),
      "a 17-fraction-digit float must be a quoted string"
    );
    // A non-finite value is left to `TagValue::F64`'s serializer (titlecase
    // `Inf`/`NaN` string); `emit_gated_f64` emits the `F64` variant itself.
    emit_gated_f64("E", "Bad", f64::INFINITY, &mut map).unwrap();
    assert_eq!(map.get("E", "Bad"), Some(&TagValue::F64(f64::INFINITY)));
  }

  /// Render one EXIF string-origin scalar through the production sink path
  /// (`EmittedTagSink::write_str` → [`crate::value::TagValue`]'s serializer) and
  /// return its JSON token. The string is stored as a `TagValue::Str` and the
  /// SINGLE consolidated `EscapeJSON` gate (in the serializer) decides
  /// bare-number-vs-quoted-string.
  #[cfg(all(feature = "alloc", feature = "serde"))]
  fn emit_str_scalar_json(value: &str) -> String {
    let mut tags: std::vec::Vec<crate::emit::EmittedTag> = std::vec::Vec::new();
    let mut sink = EmittedTagSink::new(&mut tags);
    sink.write_str("IFD0", "T", value).unwrap();
    serde_json::to_string(tags[0].tag().value_ref()).expect("scalar serializes")
  }

  /// Contract B (#197): an EXIF string-origin scalar lands as the JSON token
  /// ExifTool's terminal `EscapeJSON` gate produces — a numeric-looking value
  /// is a BARE number, a non-numeric value (incl. a leading-zero `01`, out of
  /// the number regex) stays a quoted string. No `force_string` opt-out exists:
  /// the oracle has no tag that is quoted-despite-numeric (proven against
  /// bundled 13.59 + the real-pipeline `M2TS.mts` golden).
  #[cfg(all(feature = "alloc", feature = "serde"))]
  #[test]
  fn exif_str_scalar_serializes_through_escape_json_gate() {
    // Numeric-looking ⇒ bare number.
    assert_eq!(emit_str_scalar_json("2"), "2");
    assert_eq!(emit_str_scalar_json("0.5"), "0.5");
    // Non-numeric ⇒ quoted string.
    assert_eq!(emit_str_scalar_json("abc"), "\"abc\"");
    // A leading-zero `01` is OUT of the `EscapeJSON` number regex ⇒ stays a
    // quoted string.
    assert_eq!(emit_str_scalar_json("01"), "\"01\"");
    // A `:`-bearing value (e.g. a TimeCode/GPS string) stays quoted.
    assert_eq!(emit_str_scalar_json("04:03:02:01"), "\"04:03:02:01\"");
  }

  // -- Shared helpers for the IFD-level guard tests -------------------------

  /// Render one `Conv` over a `RawValue` and read back the string, choosing
  /// `print_conv` on/off. Extends `emit_text_conv` to non-text values + `-n`.
  #[cfg(feature = "alloc")]
  fn emit_conv(raw: &RawValue, conv: Conv, print_conv: bool) -> String {
    let mut map = crate::tagmap::TagMap::new();
    emit_exif_value("IFD0", "T", raw, conv, ByteOrder::Big, print_conv, &mut map).unwrap();
    map.get_str("IFD0", "T").expect("emitted")
  }

  /// Build a big-endian one-IFD TIFF whose IFD0 holds `entries` (each a raw
  /// 12-byte entry record), with no IFD1. Out-of-line data is NOT supported by
  /// this helper — every entry must be inline (≤ 4-byte value or a self-
  /// describing offset the caller places). Used to exercise the IFD walker's
  /// excessive-count / invalid-size guards.
  #[cfg(feature = "alloc")]
  fn tiff_with_entries(entries: &[[u8; 12]]) -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
      t.extend_from_slice(e);
    }
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t
  }

  /// One 12-byte big-endian IFD entry: tag, format code, count, inline value.
  #[cfg(feature = "alloc")]
  fn entry(tag: u16, format: u16, count: u32, value: [u8; 4]) -> [u8; 12] {
    let mut e = [0u8; 12];
    e[0..2].copy_from_slice(&tag.to_be_bytes());
    e[2..4].copy_from_slice(&format.to_be_bytes());
    e[4..8].copy_from_slice(&count.to_be_bytes());
    e[8..12].copy_from_slice(&value);
    e
  }

  // -- Fix 1: excessive-count (a) + large-array (b) guards -------------------

  #[test]
  #[cfg(feature = "alloc")]
  fn large_array_placeholder_renders_exiftool_string() {
    // Guard (b)'s value string (Exif.pm:6777) — `(large array of $count
    // $formatStr values)` with ExifTool's format NAME.
    assert_eq!(
      large_array_placeholder(600, Format::Int32u),
      "(large array of 600 int32u values)"
    );
    assert_eq!(
      large_array_placeholder(1234, Format::Int16u),
      "(large array of 1234 int16u values)"
    );
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn known_large_int32u_array_is_decoded_in_full_not_placeholdered() {
    // FAITHFULNESS PIN (verified vs bundled ExifTool 13.59): a KNOWN tag with
    // a `count > 500` int32u array is DECODED IN FULL — guard (b) does NOT
    // fire, because `(not $tagInfo or LongBinary or $warned)` is false for a
    // known, non-LongBinary, non-HtmlDump tag. The placeholder only applies to
    // tags ABSENT from the table (which the port then drops as verbose-only).
    //
    // Use BitsPerSample (0x0102, a known IFD0 tag with `Conv::None`) as an
    // int16u array of 600 elements stored out-of-line. The whole 1200-byte
    // value lies inside the buffer, so it decodes fully (a space-joined list),
    // never the `(large array …)` placeholder.
    let count = 600usize;
    let header: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    let mut t = header;
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // value at offset = 8 + 2 + 12 + 4 = 26
    let val_off: u32 = 26;
    let e = entry(
      0x0102,
      3, /* int16u */
      count as u32,
      val_off.to_be_bytes(),
    );
    t.extend_from_slice(&e);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    // 600 int16u values (all 1) at offset 26.
    for _ in 0..count {
      t.extend_from_slice(&[0x00, 0x01]);
    }
    let meta = parse_exif_block(&t).expect("valid TIFF");
    let bps = meta.entry("BitsPerSample").expect("BitsPerSample decoded");
    // The value is the full array (count elements), NOT the placeholder.
    assert_eq!(bps.value_ref().raw().count(), count);
    let mut map = crate::tagmap::TagMap::new();
    // The EXIF tag stream flows through the golden-pattern engine (the same
    // `run_emission` over `ExifMeta::tags()` the document path drives).
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
      &mut map,
    );
    let s = map.get_str("IFD0", "BitsPerSample").expect("emitted");
    assert!(
      !s.starts_with("(large array"),
      "a known tag must decode fully, got {s:?}"
    );
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn excessive_count_int32u_is_skipped_with_warning() {
    // Guard (a) (Exif.pm:6760-6770): a `count > 100000` int32u tag is SKIPPED
    // (without decoding) and warns `Ignoring <dir> <tag> with excessive
    // count`. Use a KNOWN IFD0 tag (StripByteCounts 0x0117) so the warning
    // carries the Name. `size = 100001 * 4 = 400004 < 0x7fffffff`, so Fix 4
    // (invalid-size) does NOT fire. The out-of-line value region MUST be
    // present in the buffer: ExifTool's offset/EOF validation (Exif.pm:6549-
    // 6611) runs BEFORE the excessive-count guard, so an overrun would instead
    // hit `Error reading value` — exactly as bundled. We therefore lay the
    // full 400004-byte value region in-bounds (verified vs bundled 13.59,
    // which warns + drops the tag for an in-bounds 100001-int32u array).
    let count: u32 = 100_001;
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // value at offset = 8 + 2 + 12 + 4 = 26.
    let val_off: u32 = 26;
    let e = entry(0x0117, 4 /* int32u */, count, val_off.to_be_bytes());
    t.extend_from_slice(&e);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    // The full value region (in-bounds) — never decoded (the entry is skipped
    // by guard (a) before `read_value`), but the EOF check must pass.
    t.resize(26 + (count as usize) * 4, 0);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert!(
      meta.entry("StripByteCounts").is_none(),
      "the excessive-count entry must be skipped, not decoded"
    );
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w == "Ignoring IFD0 StripByteCounts with excessive count"),
      "warnings = {:?}",
      meta.warnings()
    );
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn excessive_count_does_not_apply_to_string_or_undef() {
    // The `$formatStr !~ /^(undef|string|binary)$/` exclusion: a `string` or
    // `undef` tag with a huge count is NOT subject to guard (a)/(b) (it would
    // instead be shortened by `read_value` to fit the buffer). Verify no
    // excessive-count warning is raised for a `string`-typed huge-count tag.
    let count: u32 = 200_000;
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]);
    // ImageDescription (0x010e), string, count 200000 stored at offset 26 but
    // only a few bytes present ⇒ read_value shortens it; NO excessive warning.
    let val_off: u32 = 26;
    let e = entry(0x010e, 2 /* string */, count, val_off.to_be_bytes());
    t.extend_from_slice(&e);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    t.extend_from_slice(b"Hi\0"); // a short string at offset 26
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("excessive count")),
      "a string tag must not trip the excessive-count guard: {:?}",
      meta.warnings()
    );
  }

  // -- Fix 4: invalid-size skip guard ---------------------------------------

  #[test]
  #[cfg(feature = "alloc")]
  fn invalid_size_entry_is_skipped_later_entries_parse() {
    // Fix 4 (Exif.pm:6505-6509): an entry whose `count * formatSize` exceeds
    // 0x7fffffff is SKIPPED (a per-entry `next`, NOT a directory abort), with
    // the warning `Invalid size (<size>) for <dir> tag 0x<id>[ <name>]`. A
    // LATER valid entry in the SAME IFD must still parse — proving the guard
    // does not route through the directory-killing `Error reading value` path.
    //
    // Entry 0: Make (0x010f), int32u, count 0x40000000 ⇒ size = 0x100000000
    //          (> 0x7fffffff). Entry 1: Orientation (0x0112), int16u, count 1,
    //          inline value 6.
    let huge_count: u32 = 0x4000_0000; // *4 = 0x1_0000_0000 > 0x7fffffff
    let bad = entry(0x010f, 4 /* int32u */, huge_count, 0u32.to_be_bytes());
    let good = entry(0x0112, 3 /* int16u */, 1, [0x00, 0x06, 0x00, 0x00]);
    let t = tiff_with_entries(&[bad, good]);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    // The oversized entry is skipped…
    assert!(
      meta.entry("Make").is_none(),
      "oversized entry must be skipped"
    );
    // …but the LATER Orientation entry still parses (directory NOT aborted).
    let o = meta
      .entry("Orientation")
      .expect("later entry must still parse");
    assert_eq!(o.value_ref().raw(), &RawValue::U64(std::vec![6]));
    // The Invalid size warning carries the size and the known tag name.
    let size = u64::from(huge_count) * 4;
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w == &std::format!("Invalid size ({size}) for IFD0 tag 0x010f Make")),
      "warnings = {:?}",
      meta.warnings()
    );
  }

  // -- R6-1: duplicate IFD0 Model is LAST-WINS for the dispatcher -------------

  /// A hostile IFD0 carrying TWO `Model` (`0x0110`) tags must leave the
  /// dispatcher's `$$self{Model}` ([`ExifMeta::dispatcher_model`]) set to the
  /// LAST one walked, not the first — bundled's `RawConv` `$val =~ s/\s+$//;
  /// $$self{Model} = $val` (Exif.pm:599) runs EACH time the tag is handled, so
  /// the later assignment wins. The pre-R6 first-wins (`is_none()`) guard kept
  /// the FIRST, which would decode a following model-conditional MakerNote
  /// (Canon CTMD `0x927c`) against the WRONG model. Same class for `Make`.
  #[test]
  #[cfg(feature = "alloc")]
  fn duplicate_ifd0_model_is_last_wins_for_dispatcher() {
    // Two out-of-line strings appended after the next-IFD pointer. The IFD0
    // header is 8 bytes; the directory is 2 (count) + 2*12 (Model x2) + 4
    // (next-IFD) = 30 bytes, so it ends at offset 38. Place "AAA\0" at 38 and
    // "Canon EOS R5\0" at 42.
    let s1 = b"AAA\0";
    let s2 = b"Canon EOS R5\0";
    let off1: u32 = 38;
    let off2: u32 = off1 + s1.len() as u32;
    let m1 = entry(
      0x0110,
      2, /* string */
      s1.len() as u32,
      off1.to_be_bytes(),
    );
    let m2 = entry(
      0x0110,
      2, /* string */
      s2.len() as u32,
      off2.to_be_bytes(),
    );
    let mut t = tiff_with_entries(&[m1, m2]);
    t.extend_from_slice(s1);
    t.extend_from_slice(s2);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    assert_eq!(
      meta.dispatcher_model(),
      Some("Canon EOS R5"),
      "the dispatcher Model must be the LAST IFD0 Model walked (Exif.pm:599 \
       $$self{{Model}} = $val runs each time), not the first"
    );
  }

  // -- Fix 2: HASH PrintConv miss → "Unknown (N)" / "Unknown (0xN)" ----------

  #[test]
  #[cfg(feature = "alloc")]
  fn int_label_miss_renders_unknown_decimal() {
    // Compression (no PrintHex): an off-table code → `Unknown (12)` with
    // print_conv ON (ExifTool.pm:3627), the bare `12` with it OFF.
    let raw = RawValue::U64(std::vec![12]);
    let conv = tables::lookup(0x0103).expect("Compression").conv;
    assert_eq!(emit_conv(&raw, conv, true), "Unknown (12)");
    assert_eq!(emit_conv(&raw, conv, false), "12");
    // A known code still maps through the hash.
    let known = RawValue::U64(std::vec![1]);
    assert_eq!(emit_conv(&known, conv, true), "Uncompressed");
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn int_label_hex_miss_renders_unknown_hex() {
    // ColorSpace (PrintHex => 1, Exif.pm:2693): an off-table code → `Unknown
    // (0xc)` with print_conv ON, the bare DECIMAL `12` with it OFF.
    let raw = RawValue::U64(std::vec![12]);
    let conv = tables::lookup(0xa001).expect("ColorSpace").conv;
    assert_eq!(emit_conv(&raw, conv, true), "Unknown (0xc)");
    assert_eq!(emit_conv(&raw, conv, false), "12");
    // Flash (PrintHex) miss → `Unknown (0x63)` for 99.
    let flash = tables::lookup(0x9209).expect("Flash").conv;
    assert_eq!(
      emit_conv(&RawValue::U64(std::vec![99]), flash, true),
      "Unknown (0x63)"
    );
    // A known ColorSpace value (0xffff) maps through the hash.
    let unc = RawValue::U64(std::vec![0xffff]);
    assert_eq!(emit_conv(&unc, conv, true), "Uncalibrated");
  }

  // -- Codex R2 Fix 1: complete `%flash` PrintConv map -----------------------

  /// The complete `%flash` enumerated hash (Exif.pm:175-209) is ported and the
  /// previously-wrong 0x18 entry is corrected. Values cross-checked against
  /// bundled `Image::ExifTool::Exif::flash` (perl, ExifTool 13.x).
  #[test]
  #[cfg(feature = "alloc")]
  fn flash_print_conv_matches_bundled_flash_hash() {
    let flash = tables::lookup(0x9209).expect("Flash").conv;
    let label = |code: u64| emit_conv(&RawValue::U64(std::vec![code]), flash, true);

    // The bug under fix: 0x18 is "Auto, Did not fire" in `%flash`, NOT the old
    // "Off, Did not fire, Return not detected" (that label is 0x14's).
    assert_eq!(label(0x18), "Auto, Did not fire");
    assert_eq!(label(0x14), "Off, Did not fire, Return not detected");

    // The required spot-checks.
    assert_eq!(label(0x00), "No Flash");
    assert_eq!(label(0x01), "Fired");
    // 0x47 — a red-eye value previously ABSENT from the partial table.
    assert_eq!(label(0x47), "Fired, Red-eye reduction, Return detected");

    // Every key newly added by the fix resolves (none falls through to
    // `Unknown`), confirming the table is the complete enumerated set.
    assert_eq!(label(0x30), "Off, No flash function");
    assert_eq!(label(0x45), "Fired, Red-eye reduction, Return not detected");
    assert_eq!(label(0x49), "On, Red-eye reduction");
    assert_eq!(label(0x4d), "On, Red-eye reduction, Return not detected");
    assert_eq!(label(0x4f), "On, Red-eye reduction, Return detected");
    assert_eq!(label(0x50), "Off, Red-eye reduction");
    assert_eq!(label(0x58), "Auto, Did not fire, Red-eye reduction");
    assert_eq!(
      label(0x5d),
      "Auto, Fired, Red-eye reduction, Return not detected"
    );
    assert_eq!(
      label(0x5f),
      "Auto, Fired, Red-eye reduction, Return detected"
    );

    // A code NOT in `%flash` → `Unknown (0x..)` (Flags => 'PrintHex',
    // Exif.pm:2417). `-n` (print_conv OFF) shows the bare decimal.
    assert_eq!(label(0x99), "Unknown (0x99)");
    assert_eq!(
      emit_conv(&RawValue::U64(std::vec![0x99]), flash, false),
      "153"
    );
  }

  /// EXHAUSTIVE guard: the ported `FLASH` table is EXACTLY the bundled
  /// `%Image::ExifTool::Exif::flash` enumerated set (Exif.pm:182-208) — every
  /// key maps to its bundled label, and EVERY other byte value (0x00..=0xff)
  /// is off-map (renders `Unknown`). This is the literal Perl hash transcribed
  /// here as the oracle, so any future edit to `FLASH` that drops, adds, or
  /// relabels a key trips this test.
  #[test]
  #[cfg(feature = "alloc")]
  fn flash_table_is_exactly_bundled_flash_set() {
    // The bundled `%flash` hash, key-for-key (Exif.pm:182-208).
    const BUNDLED: &[(u64, &str)] = &[
      (0x00, "No Flash"),
      (0x01, "Fired"),
      (0x05, "Fired, Return not detected"),
      (0x07, "Fired, Return detected"),
      (0x08, "On, Did not fire"),
      (0x09, "On, Fired"),
      (0x0d, "On, Return not detected"),
      (0x0f, "On, Return detected"),
      (0x10, "Off, Did not fire"),
      (0x14, "Off, Did not fire, Return not detected"),
      (0x18, "Auto, Did not fire"),
      (0x19, "Auto, Fired"),
      (0x1d, "Auto, Fired, Return not detected"),
      (0x1f, "Auto, Fired, Return detected"),
      (0x20, "No flash function"),
      (0x30, "Off, No flash function"),
      (0x41, "Fired, Red-eye reduction"),
      (0x45, "Fired, Red-eye reduction, Return not detected"),
      (0x47, "Fired, Red-eye reduction, Return detected"),
      (0x49, "On, Red-eye reduction"),
      (0x4d, "On, Red-eye reduction, Return not detected"),
      (0x4f, "On, Red-eye reduction, Return detected"),
      (0x50, "Off, Red-eye reduction"),
      (0x58, "Auto, Did not fire, Red-eye reduction"),
      (0x59, "Auto, Fired, Red-eye reduction"),
      (0x5d, "Auto, Fired, Red-eye reduction, Return not detected"),
      (0x5f, "Auto, Fired, Red-eye reduction, Return detected"),
    ];
    let flash = tables::lookup(0x9209).expect("Flash").conv;
    for code in 0u64..=0xff {
      let got = emit_conv(&RawValue::U64(std::vec![code]), flash, true);
      match BUNDLED.iter().find(|&&(k, _)| k == code) {
        Some(&(_, label)) => assert_eq!(got, label, "0x{code:02x} label mismatch"),
        None => assert_eq!(
          got,
          std::format!("Unknown (0x{code:x})"),
          "0x{code:02x} should be off-map"
        ),
      }
    }
  }

  // -- Codex R2 Fix 2: checked IFD-offset arithmetic (32-bit/wasm overflow) ---

  /// Build a `Walker` over `data` for a white-box directory-walk test. (All
  /// fields are private to this module; the `#[cfg(test)] mod tests` shares
  /// the module, so it can construct one directly.)
  #[cfg(feature = "alloc")]
  fn test_walker(data: &[u8]) -> Walker<'_, 'static> {
    Walker {
      data,
      order: ByteOrder::Big,
      base: 0,
      value_offset_base: 0,
      entries: Vec::new(),
      warnings: Vec::new(),
      warnings_ignorable: Vec::new(),
      maker_note: None,
      captured_make: None,
      captured_model: None,
      chain_guard: ChainGuard::Owned(std::collections::HashSet::new()),
      cycle_guard_warnings: Vec::new(),
      active_ifd_offsets: Vec::new(),
      page_count: 0,
      multi_page: false,
      dng_version: false,
      file_type: None,
      // RAF-backed (the standalone-TIFF model the existing tests assume); the
      // no-RAF CTMD `0x8769` path is covered via `parse_ctmd_exif_ifd_redispatch`.
      no_raf: false,
      warn_count: 0,
      active_table: TableRef::Exif,
      // The Canon DataMember pre-scan sets these when the white-box test drives
      // `process_subdir(TableRef::Canon)`; a fresh walker starts with neither.
      canon_focal_units: None,
      canon_lens_type: None,
      canon_focal_length_blob: None,
    }
  }

  /// A directory `ifd_start` so large that `ifd_start + 2` (the count read)
  /// would overflow `usize` must take the Bad-directory path — NOT panic
  /// (debug) or wrap to a low address and read garbage (release). On a 32-bit
  /// /wasm target `usize::MAX == u32::MAX`, so a TIFF IFD offset near `u32::
  /// MAX` reaches exactly this. We simulate that 32-bit boundary on any host
  /// by handing `walk_one_ifd_body` a `usize::MAX`-adjacent offset directly.
  #[test]
  #[cfg(feature = "alloc")]
  fn ifd_offset_count_read_overflow_is_bad_directory() {
    let data = minimal_tiff_with_make();
    for ifd_start in [usize::MAX, usize::MAX - 1] {
      let mut w = test_walker(&data);
      // Must not panic; aborts the directory with no next-IFD.
      let next = w.walk_one_ifd_body(ifd_start, IfdKind::Ifd0);
      assert_eq!(next, None, "overflowing ifd_start must abort the directory");
      assert_eq!(
        w.warnings,
        std::vec![String::from("Bad IFD0 directory")],
        "overflowing ifd_start must warn Bad <dir> directory"
      );
      assert!(
        w.entries.is_empty(),
        "no tags from an overflowing directory"
      );
    }
  }

  /// The directory-extent arithmetic (`2 + 12*num_entries`, then
  /// `ifd_start + dir_size`) is `checked_*`. With a giant `num_entries` AND a
  /// huge `ifd_start`, the sum overflows `usize` — the walk must abort via the
  /// Bad-directory path, never panic. (Here `ifd_start` is small enough that
  /// the count read succeeds, so the dir-end `checked_add` is what fires.)
  #[test]
  #[cfg(feature = "alloc")]
  fn ifd_dir_end_overflow_is_bad_directory() {
    // A 2-byte buffer holding num_entries = 0xFFFF at offset usize::MAX-2 is
    // not constructible, so drive the dir-end overflow through a real buffer:
    // place num_entries at offset 0, then ask the walker to treat offset
    // `usize::MAX - 1` as the directory — `ifd_start + 2` overflows first and
    // we already cover that. To isolate the dir-END overflow we instead assert
    // the checked expression the walker uses is `None` on overflow.
    let ifd_start = usize::MAX - 4;
    let num_entries = 0xFFFFusize;
    let dir_end = num_entries
      .checked_mul(12)
      .and_then(|body| body.checked_add(2))
      .and_then(|dir_size| ifd_start.checked_add(dir_size));
    assert_eq!(
      dir_end, None,
      "dir-end arithmetic must detect usize overflow"
    );
  }

  /// Regression (Golden-v2 Phase C): every EXIF warning push keeps `warnings`
  /// and `warnings_ignorable` index-aligned. The "Bad <dir> directory" abort
  /// (Exif.pm:6383) is a NORMAL warning — `$inMakerNotes` is structurally
  /// always 0 in this walker (MakerNote IFDs are never recursed), so its
  /// ignorable level is 0; a later excessive-count warning (Exif.pm:6767) is
  /// `[Minor]` (ignorable 2). `diagnostics()` pairs the two vectors BY INDEX,
  /// so if the normal push skipped `warnings_ignorable` the `2` would shift
  /// onto the "Bad directory" message and the excessive-count warning would
  /// render unprefixed. Assert the levels stay aligned.
  #[test]
  #[cfg(feature = "alloc")]
  fn warning_ignorable_levels_stay_index_aligned() {
    let data = minimal_tiff_with_make();
    let mut w = test_walker(&data);
    // A real bare-push site: an overflowing `ifd_start` aborts with
    // "Bad IFD0 directory" — a NORMAL (ignorable 0) warning.
    let next = w.walk_one_ifd_body(usize::MAX, IfdKind::Ifd0);
    assert_eq!(next, None);
    // A later minor-with-behavioural-change warning (the excessive-count arm).
    w.warn_minor_behavioral(String::from(
      "Ignoring IFD0 Orientation with excessive count",
    ));
    assert_eq!(
      w.warnings,
      std::vec![
        String::from("Bad IFD0 directory"),
        String::from("Ignoring IFD0 Orientation with excessive count"),
      ],
    );
    // The crux: ignorable levels are index-aligned — `0` for the normal
    // Bad-directory warning, `2` for the minor excessive-count warning. Before
    // the fix the normal push skipped this vector, yielding `[2]` and shifting
    // the `[Minor]` prefix onto the wrong message.
    assert_eq!(w.warnings_ignorable, std::vec![0u8, 2u8]);
  }

  /// CLASS SWEEP — the low-level byte readers (`get_u16`/`get_u32`/`get_u64`
  /// and the float readers) end their slice range with `pos.checked_add(N)`.
  /// A `pos` near `usize::MAX` (a wrapped offset on a 32-bit target) must
  /// yield `None`, NOT panic on the `pos + N` range bound (debug) or form an
  /// inverted range (release). This is the floor that makes every offset
  /// reaching a read overflow-safe.
  #[test]
  fn byte_readers_do_not_overflow_on_max_pos() {
    use ifd::{get_f32, get_f64, get_i16, get_i32, get_i64, get_u64};
    let data = [0u8; 16];
    for pos in [usize::MAX, usize::MAX - 1, usize::MAX - 7] {
      assert_eq!(get_u16(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_u32(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_u64(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_i16(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_i32(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_i64(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_f32(&data, pos, ByteOrder::Big), None);
      assert_eq!(get_f64(&data, pos, ByteOrder::Big), None);
    }
  }

  /// CLASS SWEEP — the next-IFD pointer (`dir_end + 4`), the per-entry offset
  /// (`ifd_start + 2 + 12*index`, `entry + 12`) and the inline value offset
  /// (`entry + 8`) all use `checked_add`. Drive a real chain walk whose IFD0
  /// offset sits right at the buffer end so the trailing-pointer and entry
  /// arithmetic run at the boundary: the walk must terminate cleanly (Bad
  /// directory / no next IFD), never panic.
  #[test]
  #[cfg(feature = "alloc")]
  fn boundary_offsets_do_not_panic_on_chain_walk() {
    let data = minimal_tiff_with_make();
    // An IFD0 offset exactly at data.len(): `ifd_start + 2 > data.len()` ⇒ Bad
    // directory, with the next-IFD read never attempted.
    let mut w = test_walker(&data);
    w.walk_ifd_chain(data.len(), IfdKind::Ifd0);
    assert_eq!(w.warnings, std::vec![String::from("Bad IFD0 directory")]);
    // And a usize::MAX-adjacent chain start must not panic either.
    let mut w2 = test_walker(&data);
    w2.walk_ifd_chain(usize::MAX - 1, IfdKind::Ifd0);
    assert_eq!(w2.warnings, std::vec![String::from("Bad IFD0 directory")]);
  }

  // -- Fix 3: InteropIndex string-keyed PrintConv ----------------------------

  /// A `RawValue::Text` from a UTF-8 `&str` (raw == the str's bytes, as the
  /// real `string` builder produces for valid UTF-8).
  #[cfg(feature = "alloc")]
  fn text_rv(s: &str) -> RawValue {
    RawValue::Text {
      text: s.to_string(),
      raw: s.as_bytes().into(),
    }
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn interop_index_string_keyed_print_conv() {
    let conv = tables::lookup(0x0001).expect("InteropIndex").conv;
    // Hits map to the full DCF label with print_conv ON, raw token with OFF.
    assert_eq!(
      emit_conv(&text_rv("R98"), conv, true),
      "R98 - DCF basic file (sRGB)"
    );
    assert_eq!(emit_conv(&text_rv("R98"), conv, false), "R98");
    assert_eq!(
      emit_conv(&text_rv("R03"), conv, true),
      "R03 - DCF option file (Adobe RGB)"
    );
    assert_eq!(
      emit_conv(&text_rv("THM"), conv, true),
      "THM - DCF thumbnail file"
    );
    // A miss → `Unknown ($val)` (ON) / the raw token (OFF).
    assert_eq!(emit_conv(&text_rv("XYZ"), conv, true), "Unknown (XYZ)");
    assert_eq!(emit_conv(&text_rv("XYZ"), conv, false), "XYZ");
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn interop_index_through_full_ifd_chain() {
    // End-to-end: IFD0 → ExifIFD(0x8769) → InteropIFD(0xa005) → 0x0001
    // InteropIndex `R98` (inline, count 4). Verify the InteropIFD-group entry
    // maps through its string PrintConv.
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0 @8: ExifOffset 0x8769 -> 26
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&entry(0x8769, 4, 1, 26u32.to_be_bytes()));
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // ExifIFD @26: InteropOffset 0xa005 -> 44
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&entry(0xa005, 4, 1, 44u32.to_be_bytes()));
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // InteropIFD @44: 0x0001 string count 4 inline "R98\0"
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&entry(0x0001, 2, 4, *b"R98\0"));
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let meta = parse_exif_block(&t).expect("valid TIFF");
    let ii = meta.entry("InteropIndex").expect("InteropIndex decoded");
    assert_eq!(ii.group(), "InteropIFD");
    let mut map = crate::tagmap::TagMap::new();
    // The EXIF tag stream flows through the golden-pattern engine (the same
    // `run_emission` over `ExifMeta::tags()` the document path drives).
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
      &mut map,
    );
    assert_eq!(
      map.get_str("InteropIFD", "InteropIndex").as_deref(),
      Some("R98 - DCF basic file (sRGB)")
    );
  }

  // -- Fix 5: FocalLengthIn35mmFormat faithful scalar ------------------------

  #[test]
  #[cfg(feature = "alloc")]
  fn focal_length_35mm_renders_raw_scalar_no_truncation() {
    let conv = Conv::FocalLength35mm;
    // The common int16u case: integer → `"75 mm"`, no decimal point.
    assert_eq!(
      emit_conv(&RawValue::U64(std::vec![75]), conv, true),
      "75 mm"
    );
    // An off-spec FRACTIONAL value (rational 75/2 = 37.5) must NOT truncate to
    // `37 mm` — it renders the true scalar `"37.5 mm"` (Exif.pm:2896 `"$val
    // mm"`, the value verbatim).
    let frac = RawValue::Rational(std::vec![crate::value::Rational::rational64(75, 2)]);
    assert_eq!(emit_conv(&frac, conv, true), "37.5 mm");
  }

  // -- Fix 7: Conv::Version strips only TRAILING NULs ------------------------

  #[test]
  #[cfg(feature = "alloc")]
  fn version_strips_only_trailing_nuls() {
    let conv = Conv::Version;
    // Trailing NULs stripped (`s/\0+$//`).
    assert_eq!(
      emit_conv(
        &RawValue::Bytes(std::vec![b'0', b'2', b'0', b'0']),
        conv,
        true
      ),
      "0200"
    );
    assert_eq!(
      emit_conv(
        &RawValue::Bytes(std::vec![b'0', b'2', b'0', b'0', 0, 0]),
        conv,
        true
      ),
      "0200"
    );
    // An INTERIOR NUL is KEPT (the old `take_while` truncated here, wrongly).
    assert_eq!(
      emit_conv(
        &RawValue::Bytes(std::vec![b'0', b'2', 0, b'1', b'0']),
        conv,
        true
      ),
      "02\u{0}10"
    );
    // All-NUL → empty string.
    assert_eq!(
      emit_conv(&RawValue::Bytes(std::vec![0, 0, 0]), conv, true),
      ""
    );
  }

  // -- JPEG positioned metadata-block ordering (issue 233) -------------------
  //
  // The general marker-position block model: `ExifMeta::tags` emits the
  // `File`-group prefix first, then the EXIF block (at `exif_block_pos`) and
  // each positioned `JpegAuxBlock` (at its marker index) INTERLEAVED by
  // ascending position. These tests pin that the model reproduces the retired
  // `gopro_before_exif` bool (both orders) and generalizes to more than one
  // aux block (a second positioned block falls on the other side of the EXIF
  // block purely by its marker position — exactly how a future XMP / ICC /
  // MPF / IPTC `JpegAuxBlock` variant would slot in).

  /// One GPMF `KLV` record (Key-Length-Value), 4-byte aligned (GoPro.pm).
  #[cfg(feature = "quicktime")]
  fn gpmf_klv(
    out: &mut std::vec::Vec<u8>,
    key: &[u8; 4],
    fmt: u8,
    size: u8,
    count: u16,
    payload: &[u8],
  ) {
    out.extend_from_slice(key);
    out.push(fmt);
    out.push(size);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
      out.push(0);
    }
  }

  /// A minimal `GoProMeta` whose sole tag is `DeviceName = name` — a single
  /// `DEVC` → `STRM` → `DVNM` GPMF stream decoded by `process_gopro`.
  #[cfg(feature = "quicktime")]
  fn gopro_device_name(name: &str) -> crate::metadata::GoProMeta {
    let mut dvnm = std::vec::Vec::new();
    gpmf_klv(
      &mut dvnm,
      b"DVNM",
      0x63,
      1,
      name.len() as u16,
      name.as_bytes(),
    );
    let mut strm = std::vec::Vec::new();
    gpmf_klv(&mut strm, b"STRM", 0x00, 1, dvnm.len() as u16, &dvnm);
    let mut devc = std::vec::Vec::new();
    gpmf_klv(&mut devc, b"DEVC", 0x00, 1, strm.len() as u16, &strm);
    let mut gp = crate::metadata::GoProMeta::new();
    assert!(
      crate::formats::gopro::process_gopro(&devc, &mut gp),
      "the crafted DEVC/STRM/DVNM stream decodes a record"
    );
    assert!(!gp.is_empty());
    gp
  }

  /// Collect `(family0, family1, name)` for each emitted tag, in order — the
  /// stream `ExifMeta::tags` yields for `-G1 -j`.
  #[cfg(feature = "quicktime")]
  fn ordered_groups(meta: &ExifMeta<'_>) -> std::vec::Vec<(String, String, String)> {
    use crate::emit::Taggable;
    meta
      .tags(crate::emit::EmitOptions::g1(
        crate::emit::ConvMode::PrintConv,
        false,
      ))
      .map(|t| {
        let g = t.tag().group_ref();
        (
          g.family0().to_string(),
          g.family1().to_string(),
          t.tag().name().to_string(),
        )
      })
      .collect()
  }

  /// The DeviceName VALUE of the first `GoPro:DeviceName` tag (to tell two
  /// GoPro aux blocks apart by position).
  #[cfg(feature = "quicktime")]
  fn device_name_values(meta: &ExifMeta<'_>) -> std::vec::Vec<String> {
    use crate::emit::Taggable;
    meta
      .tags(crate::emit::EmitOptions::g1(
        crate::emit::ConvMode::PrintConv,
        false,
      ))
      .filter(|t| t.tag().name() == "DeviceName")
      .map(|t| match t.tag().value_ref() {
        crate::value::TagValue::Str(s) => s.to_string(),
        other => std::format!("{other:?}"),
      })
      .collect()
  }

  /// A GoPro aux block at a position AFTER the EXIF block (the realistic
  /// `APP1`-before-`APP6` layout) emits `File:ExifByteOrder` → `IFD0:Make`
  /// (the EXIF block) → `GoPro:DeviceName` (the aux block) — i.e. the EXIF
  /// block then the aux block. Reproduces the old `before_exif == false`.
  #[test]
  #[cfg(feature = "quicktime")]
  fn jpeg_aux_block_after_exif_by_position() {
    let tiff = minimal_tiff_with_make();
    let mut meta = parse_exif_block(&tiff).expect("valid TIFF");
    // EXIF block at marker index 2; GoPro `APP6` at index 5 (after it).
    meta.set_jpeg_gopro(gopro_device_name("GoP-After"), 5, Some(2));
    let order = ordered_groups(&meta);
    assert_eq!(
      order,
      std::vec![
        (
          "File".to_string(),
          "File".to_string(),
          "ExifByteOrder".to_string()
        ),
        ("EXIF".to_string(), "IFD0".to_string(), "Make".to_string()),
        (
          "APP6".to_string(),
          "GoPro".to_string(),
          "DeviceName".to_string()
        ),
      ],
      "File prefix first, then EXIF block, then the later-positioned aux block"
    );
  }

  /// A GoPro aux block at a position BEFORE the EXIF block (a non-standard
  /// `APP6`-before-`APP1` JPEG) emits `File:ExifByteOrder` → `GoPro:DeviceName`
  /// (the aux block) → `IFD0:Make` (the EXIF block). The `File`-group prefix
  /// STILL leads; only the movable EXIF block reorders. Reproduces the old
  /// `before_exif == true`.
  #[test]
  #[cfg(feature = "quicktime")]
  fn jpeg_aux_block_before_exif_by_position() {
    let tiff = minimal_tiff_with_make();
    let mut meta = parse_exif_block(&tiff).expect("valid TIFF");
    // GoPro `APP6` at marker index 1; EXIF block at index 3 (after it).
    meta.set_jpeg_gopro(gopro_device_name("GoP-Before"), 1, Some(3));
    let order = ordered_groups(&meta);
    assert_eq!(
      order,
      std::vec![
        (
          "File".to_string(),
          "File".to_string(),
          "ExifByteOrder".to_string()
        ),
        (
          "APP6".to_string(),
          "GoPro".to_string(),
          "DeviceName".to_string()
        ),
        ("EXIF".to_string(), "IFD0".to_string(), "Make".to_string()),
      ],
      "File prefix first, then the earlier-positioned aux block, then the EXIF block"
    );
  }

  /// With NO recorded EXIF block position (`exif_block_pos == None`, the
  /// no-movable-`APP1` path), the EXIF block sorts FIRST (`Option`'s
  /// `None < Some`), so the GoPro aux block trails it — matching ExifTool with
  /// no `IFD0:*` to order against. Reproduces the old `_ => false` arm.
  #[test]
  #[cfg(feature = "quicktime")]
  fn jpeg_aux_block_with_no_exif_position_trails_exif_block() {
    // A byte-order-only TIFF (empty IFD0): the EXIF block emits ONLY the
    // `File:ExifByteOrder` prefix — no movable tag — so a real JPEG front-end
    // would leave `exif_block_pos == None`. Model that directly.
    let mut t: std::vec::Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x00]); // IFD0 with 0 entries
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    let mut meta = parse_exif_block(&t).expect("valid empty-IFD0 TIFF");
    meta.set_jpeg_gopro(gopro_device_name("GoP-NoExif"), 9, None);
    let order = ordered_groups(&meta);
    assert_eq!(
      order,
      std::vec![
        (
          "File".to_string(),
          "File".to_string(),
          "ExifByteOrder".to_string()
        ),
        (
          "APP6".to_string(),
          "GoPro".to_string(),
          "DeviceName".to_string()
        ),
      ],
      "no movable EXIF tag: File prefix, then the aux block trailing the \
       position-less EXIF block"
    );
  }

  /// GENERALITY: the model interleaves MORE than one positioned aux block — the
  /// EXIF block is sandwiched between two aux blocks purely by marker position.
  /// Pushed via the GENERAL `set_jpeg_exif_block_pos` + `push_jpeg_aux_block`
  /// seam (not the GoPro-named wrapper), out of marker order, to prove the sort
  /// — not insertion order — decides emission. A future non-GoPro
  /// `JpegAuxBlock` variant (XMP / ICC / MPF / IPTC) slots in identically: push
  /// it at its segment's marker index and it auto-orders.
  #[test]
  #[cfg(feature = "quicktime")]
  fn jpeg_multiple_aux_blocks_interleave_by_position() {
    let tiff = minimal_tiff_with_make();
    let mut meta = parse_exif_block(&tiff).expect("valid TIFF");
    // EXIF block at marker index 4. Two aux blocks straddle it: one at index 1
    // (before), one at index 7 (after). Pushed in REVERSE marker order to show
    // the position-sort (not push order) governs.
    meta.set_jpeg_exif_block_pos(Some(4));
    meta.push_jpeg_aux_block(7, JpegAuxBlock::GoPro(gopro_device_name("aux-late")));
    meta.push_jpeg_aux_block(1, JpegAuxBlock::GoPro(gopro_device_name("aux-early")));
    let order = ordered_groups(&meta);
    assert_eq!(
      order,
      std::vec![
        (
          "File".to_string(),
          "File".to_string(),
          "ExifByteOrder".to_string()
        ),
        (
          "APP6".to_string(),
          "GoPro".to_string(),
          "DeviceName".to_string()
        ),
        ("EXIF".to_string(), "IFD0".to_string(), "Make".to_string()),
        (
          "APP6".to_string(),
          "GoPro".to_string(),
          "DeviceName".to_string()
        ),
      ],
      "File prefix, then aux@1, then the EXIF block, then aux@7 — interleaved \
       by ascending marker position regardless of push order"
    );
    // The values confirm WHICH block landed where: the early block (index 1)
    // emits before the EXIF block, the late one (index 7) after.
    assert_eq!(
      device_name_values(&meta),
      std::vec!["aux-early".to_string(), "aux-late".to_string()],
      "the position-1 block sorts before the EXIF block, the position-7 after"
    );
  }

  // ====================================================================// Canon engine migration — Step A differential test (#243 phase 2)
  //
  // PROVES the shared `Walker`'s Canon LEAF path (`process_subdir` under
  // `TableRef::Canon` → `emit_entry`'s `ResolvedConv::Canon` arm → `emit_canon_value`)
  // is BYTE-IDENTICAL to the production `canon::parse_in_tiff` leaf rendering
  // (`canon/mod.rs:1018`). The same crafted Canon MakerNote IFD bytes are run
  // through BOTH paths; the emitted `(name, value, group, unknown)` tuples must
  // match, in order. Production keeps `parse_in_tiff`, so this is the leaf-path
  // proof WITHOUT switching production (conformance stays 416/0).
  // ====================================================================

  /// Push one little-endian 12-byte Canon IFD entry with an INLINE value
  /// (`size <= 4`, stored at `entry+8`). Inline values resolve to the SAME
  /// offset (`entry+8`) in both the shared walk (`walk_entry`) and the Canon
  /// body walk (`classify_canon_entry`'s inline arm), so `read_value` reads the
  /// identical bytes — the precondition for the leaf-path byte-identity this
  /// test asserts. `value` is the up-to-4 value bytes (zero-padded to 4).
  #[cfg(feature = "alloc")]
  fn push_canon_entry(buf: &mut Vec<u8>, tag: u16, format: u16, count: u32, value: &[u8]) {
    assert!(value.len() <= 4, "inline value must be <= 4 bytes");
    buf.extend_from_slice(&tag.to_le_bytes());
    buf.extend_from_slice(&format.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    let mut slot = [0u8; 4];
    slot[..value.len()].copy_from_slice(value);
    buf.extend_from_slice(&slot);
  }

  /// Build a crafted little-endian Canon MakerNote IFD holding ONLY plain leaf
  /// tags (no sub-tables, no `0x28`/`0x96` special cases — those are Step B).
  /// The chosen `%Canon::Main` leaves exercise: a `None` conv (string +
  /// integer), the four hash/format PrintConvs (`DateStampMode`, `ColorSpace`,
  /// `SerialNumberFormat`, `CanonModelID`), the model-conditional `SerialNumber`
  /// list, and one `Unknown=>1` tag (`CanonFlashInfo`) to prove unknown-gating
  /// flows identically.
  #[cfg(feature = "alloc")]
  fn crafted_canon_leaf_ifd() -> Vec<u8> {
    // ASCII=2, int16u=3, int32u=4.
    let entries: &[(u16, u16, u32, &[u8])] = &[
      // 0x03 CanonFlashInfo — Unknown=>1, conv None (int16u=7). Suppressed.
      (0x03, 3, 1, &[0x07, 0x00]),
      // 0x07 CanonFirmwareVersion — ASCII, conv None. Inline "1.0\0".
      (0x07, 2, 4, b"1.0\0"),
      // 0x09 OwnerName — ASCII, conv None. Inline "Al\0\0".
      (0x09, 2, 4, b"Al\0\0"),
      // 0x0c SerialNumber — int32u, conditional SerialNumber conv (uses model).
      (0x0c, 4, 1, &123_456u32.to_le_bytes()),
      // 0x10 CanonModelID — int32u, ModelId hash lookup (0x412 = EOS M50).
      (0x10, 4, 1, &0x0000_0412u32.to_le_bytes()),
      // 0x15 SerialNumberFormat — int32u, hash PrintConv (0x90000000 ⇒ Format 1).
      (0x15, 4, 1, &0x9000_0000u32.to_le_bytes()),
      // 0x1c DateStampMode — int16u, hash PrintConv (2 ⇒ "Date & Time").
      (0x1c, 3, 1, &[0x02, 0x00]),
      // 0xb4 ColorSpace — int16u, hash PrintConv (1 ⇒ "sRGB").
      (0xb4, 3, 1, &[0x01, 0x00]),
    ];
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for &(tag, format, count, value) in entries {
      push_canon_entry(&mut buf, tag, format, count, value);
    }
    // Next-IFD pointer word = 0 (no next IFD). A Canon MakerNote sub-IFD is
    // walked with `kind = ExifIfd`, so `walk_one_ifd_body`'s `follows_chain` is
    // false and this word is ignored — matching `walk_canon_in_tiff`, which also
    // never follows the chain.
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf
  }

  /// Drive the shared `Walker` through `process_subdir` under `TableRef::Canon`
  /// over `blob`, then render every collected entry through `emit_entry` (the
  /// `ResolvedConv::Canon` arm → `emit_canon_value` for a leaf, or
  /// `emit_canon_subtable` for a WALKED binary sub-table) into an
  /// `EmittedTagSink`. Returns the emitted tags in walk order — the NEW path's
  /// output. `model` threads the parent `$$self{Model}` and `file_type` the
  /// container `$$self{FILE_TYPE}` exactly as production would.
  ///
  /// `process_subdir` runs the Canon DataMember pre-scan
  /// ([`Walker::canon_prescan_datamembers`]) before the walk, so after it
  /// returns `w.canon_focal_units` / `w.canon_lens_type` hold the captured
  /// `$$self{FocalUnits}` / `$$self{LensType}` — threaded into the SAME
  /// `emit_entry` the production re-emit uses, so the FocalLength/FileInfo
  /// sub-tables decode against them (#243 phase 2 step B2).
  #[cfg(feature = "alloc")]
  fn drive_canon_subdir(
    blob: &[u8],
    order: ByteOrder,
    print_conv: bool,
    model: Option<&str>,
    file_type: Option<&str>,
  ) -> Vec<crate::emit::EmittedTag> {
    let mut w = test_walker(blob);
    w.order = order;
    // The Canon `SerialNumber` PrintConv reads `$$self{Model}`; set it on the
    // walker so the emit threads it (the differential oracle uses the SAME model).
    w.captured_model = model.map(std::string::String::from);
    // `kind = ExifIfd`: a non-Ifd0 kind, so the IFD0-only Make/Model capture tap
    // never fires for the maker-note walk; the leaf group is overridden to
    // `MakerNotes:Canon` regardless of kind. Fixed parent order, no FixBase,
    // ProcessCanon (the hooks are inert for a plain in-bounds leaf IFD) — but the
    // `TableRef::Canon` pre-scan hook DOES run, populating the DataMembers below.
    w.process_subdir(
      0,
      IfdKind::ExifIfd,
      TableRef::Canon,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Canon,
    );
    // The DataMembers the pre-scan captured — thread them exactly as the Step C
    // production switch will (the FocalLength/FileInfo emit reads them).
    let canon_focal_units = w.canon_focal_units;
    let canon_lens_type = w.canon_lens_type;
    let canon_focal_length_blob = w.canon_focal_length_blob.clone();
    let mut out: Vec<crate::emit::EmittedTag> = Vec::new();
    let mut sink = EmittedTagSink::new(&mut out);
    for entry in &w.entries {
      let Ok(()) = emit_entry(
        entry,
        order,
        print_conv,
        model,
        file_type,
        canon_focal_units,
        canon_lens_type,
        canon_focal_length_blob.as_deref(),
        &mut sink,
      );
    }
    out
  }

  /// The leaf-path differential proof: for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), the shared `Walker` Canon leaf path emits the EXACT same
  /// `(name, value, group="MakerNotes:Canon", unknown)` stream — in order — as
  /// `canon::parse_in_tiff`. This is the byte-identity oracle for Step A.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_leaf_emit_matches_parse_in_tiff() {
    let blob = crafted_canon_leaf_ifd();
    let order = ByteOrder::Little;
    // A model that exercises the `EOS-1D` SerialNumber branch (`%.6u`,
    // `Canon.pm:1295`) — proving the model threads through `emit_canon_value`.
    let model = Some("Canon EOS-1D Mark IV");

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (renders leaves at collection). The
      // blob IS the whole TIFF here (`mn_offset = 0`, inline values resolve within
      // it); `file_type = None` (irrelevant to these leaves).
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );

      // ---- New path: shared Walker → emit_canon_value.
      let emitted = drive_canon_subdir(&blob, order, print_conv, model, None);

      // Both streams are in IFD-tag order (ascending), so compare position-wise.
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: leaf COUNT must match \
         (every plain leaf the oracle emits, the shared path emits)"
      );
      for (i, (got, want)) in emitted.iter().zip(oracle.iter()).enumerate() {
        let tag = got.tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: NAME mismatch"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): rendered VALUE mismatch \
           (the new path must apply CanonPrintConv exactly as parse_in_tiff)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} leaf #{i} ({}): Unknown flag mismatch \
           (it must ride the EmittedTag for the engine's central drop)",
          want.name()
        );
        // The vendor group OVERRIDE — every Canon leaf is `MakerNotes:Canon`,
        // NOT the kind-derived `ExifIFD` group.
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} leaf #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Canon",
          "print_conv={print_conv} leaf #{i} ({}): family-1 must be Canon",
          want.name()
        );
      }
    }
  }

  /// The crafted blob carries the `Unknown=>1` `CanonFlashInfo` (0x03), and the
  /// differential stream INCLUDES it with `unknown=true` on BOTH sides (the
  /// shared engine's `run_emission` is what drops it later — neither leaf path
  /// pre-filters). Asserting it is present-and-flagged proves the unknown flag
  /// flows identically (not silently dropped early by the new path).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_leaf_unknown_flag_flows_like_parse_in_tiff() {
    let blob = crafted_canon_leaf_ifd();
    let order = ByteOrder::Little;
    let emitted = drive_canon_subdir(&blob, order, true, None, None);
    let flash = emitted
      .iter()
      .find(|t| t.tag().name() == "CanonFlashInfo")
      .expect("CanonFlashInfo (0x03) must be emitted (pre-drop) by the new path");
    assert!(
      flash.unknown(),
      "CanonFlashInfo carries Unknown=>1 — the flag must ride the EmittedTag \
       so run_emission drops it centrally, NOT a per-path pre-filter"
    );
  }

  /// The group OVERRIDE is scoped to the vendor table: `vendor_group1_of` is
  /// `Some(\"Canon\")` for `Canon` and `None` for every core IFD table — so the
  /// Exif/GPS/Interop leaf group derivation is UNCHANGED (the byte-identity the
  /// conformance suite enforces).
  #[test]
  fn vendor_group1_override_is_canon_only() {
    assert_eq!(vendor_group1_of(TableRef::Canon), Some("Canon"));
    assert_eq!(vendor_group1_of(TableRef::Exif), None);
    assert_eq!(vendor_group1_of(TableRef::Interop), None);
    #[cfg(feature = "gps")]
    assert_eq!(vendor_group1_of(TableRef::Gps), None);
  }

  // ====================================================================// Apple engine migration — differential test (#243 phase 3)
  //
  // PROVES the shared `Walker`'s Apple LEAF path (`apple_makernote_isolated` →
  // `process_subdir` under `TableRef::Apple` → `emit_entry`'s `ResolvedConv::Apple`
  // arm → `emit_apple_value`) is BYTE-IDENTICAL to the production oracle
  // `apple::parse_with_print_conv` (`walk_apple_body` + per-tag `ApplePrintConv`).
  // The same crafted Apple MakerNote blob is run through BOTH paths; the emitted
  // `(name, value, group="MakerNotes:Apple", unknown)` tuples must match, in order,
  // for `-j` (PrintConv) AND `-n` (ValueConv), and the typed `MakerNotesApple` must
  // agree. Apple is the SIMPLE vendor case — BLOB-only, no DataMember pre-scan, no
  // sub-tables, no specials — so this is the whole story (no Step B/C analogue).
  // ====================================================================

  /// Build a crafted big-endian Apple MakerNote blob: the 14-byte
  /// `Apple iOS\0\0\x01` header, then the body's `MM` marker + a BE entry count +
  /// the 12-byte IFD entries, then the next-IFD word, then any out-of-line value
  /// bytes appended after it. `entries` is `(tag, format, count, inline_or_empty,
  /// out_of_line_or_empty)`: an entry is INLINE when `out_of_line` is empty (the
  /// value, zero-padded to 4 bytes, sits at `entry+8`), else OUT-OF-LINE (the 4
  /// bytes at `entry+8` are the BLOB-relative offset — `Base => '$start - 14'` —
  /// and `out_of_line` holds the value bytes appended past the directory).
  ///
  /// Out-of-line data is appended AFTER the next-IFD word, so every value offset is
  /// past the directory extent — neither walker flags it `Suspicious`.
  #[cfg(feature = "alloc")]
  fn crafted_apple_blob(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    // Header (14 bytes) + body marker `MM` (2) + count (2). Out-of-line offsets are
    // blob-relative, so the value-data region begins right after the next-IFD word.
    let dir_bytes = 2 + 12 * entries.len(); // marker `MM` is BEFORE this; count+entries
    // Body layout from offset 14: [MM][count u16][entries...][next-IFD u32][values].
    // The first out-of-line value sits at blob offset 14 + 2 + dir_bytes + 4.
    let mut value_cursor = 14 + 2 + dir_bytes + 4;
    let mut header: Vec<u8> = Vec::new();
    // The 14-byte `Apple iOS\0\0\x01MM` header (the trailing `MM` IS part of the
    // fixed 14-byte header — `MakerNotes.pm`'s `Start => '$valuePtr + 14'`). The
    // BODY then begins with its OWN `MM`/`II` marker.
    header.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    header.extend_from_slice(b"MM"); // body byte-order marker (big-endian)
    header.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      header.extend_from_slice(&tag.to_be_bytes());
      header.extend_from_slice(&format.to_be_bytes());
      header.extend_from_slice(&count.to_be_bytes());
      if out_of_line.is_empty() {
        assert!(inline.len() <= 4, "inline value must be <= 4 bytes");
        let mut slot = [0u8; 4];
        slot[..inline.len()].copy_from_slice(inline);
        header.extend_from_slice(&slot);
      } else {
        header.extend_from_slice(&(value_cursor as u32).to_be_bytes());
        value_blob.extend_from_slice(out_of_line);
        value_cursor += out_of_line.len();
      }
    }
    header.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
    header.extend_from_slice(&value_blob);
    header
  }

  /// Drive the shared `Walker` through `apple_makernote_isolated`'s walk over
  /// `blob`, then render every collected entry through `emit_entry` (the
  /// `ResolvedConv::Apple` arm → `emit_apple_value`) into an `EmittedTagSink`.
  /// Returns the emitted tags in walk order — the NEW path's output WITH the full
  /// `MakerNotes:Apple` group (which the `VendorEmission` stream alone does not
  /// carry). Mirrors the production isolated walk exactly (base 0, body-marker
  /// order, `TableRef::Apple`, `ProcessProc::Exif`).
  #[cfg(feature = "alloc")]
  fn drive_apple_subdir(
    blob: &[u8],
    parent_order: ByteOrder,
    print_conv: bool,
  ) -> Vec<crate::emit::EmittedTag> {
    let body = blob.get(14..).unwrap_or(&[]);
    let (order, header_size) = match ByteOrder::from_marker(body) {
      Some(o) => (o, 2usize),
      None => (parent_order, 0usize),
    };
    let mut w = test_walker(blob);
    w.order = order;
    // Mirror the production Apple dispatch: the IFD0 Make is "Apple" for real
    // fixtures, which the per-entry format-16 carve-out gate requires.
    w.captured_make = Some(std::string::String::from("Apple"));
    w.process_subdir(
      14 + header_size,
      IfdKind::ExifIfd,
      TableRef::Apple,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Exif,
    );
    let mut out: Vec<crate::emit::EmittedTag> = Vec::new();
    let mut sink = EmittedTagSink::new(&mut out);
    for entry in &w.entries {
      let Ok(()) = emit_entry(
        entry, order, print_conv, None, None, None, None, None, &mut sink,
      );
    }
    out
  }

  /// The Apple leaf-path differential proof: for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), the shared `Walker` Apple leaf path emits the EXACT same
  /// `(name, value, group="MakerNotes:Apple", unknown)` stream — in order — as
  /// `apple::parse_with_print_conv`, AND the typed `MakerNotesApple` agrees.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_isolated_emit_matches_parse_with_print_conv() {
    // A 36-char UUID for the out-of-line BurstUUID (0x000b) — exercises an
    // OUT-OF-LINE ASCII value + the typed `burst_uuid` accessor. ExifTool stores
    // ASCII with a trailing NUL; `read_value` trims it, so the count includes it.
    let uuid = b"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\0";
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x000a HDRImageType — int32s, hash PrintConv (3 ⇒ "HDR Image"). INLINE.
      (0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
      // 0x000b BurstUUID — ASCII, conv None. OUT-OF-LINE (36 chars + NUL).
      (0x000b, 0x0002, uuid.len() as u32, &[], uuid),
      // 0x0014 ImageCaptureType — int32s, hash PrintConv miss (5 ⇒ "Unknown (5)").
      (0x0014, 0x0009, 1, &[0x00, 0x00, 0x00, 0x05], &[]),
      // 0x002e CameraType — int32s, hash PrintConv (1 ⇒ "Back Normal"). INLINE.
      (0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]),
      // 0x003F GreenGhostMitigationStatus — int32s, Unknown=>1, conv None. INLINE.
      // Present-and-flagged on BOTH sides (run_emission drops it later, not here).
      (0x003F, 0x0009, 1, &[0x00, 0x00, 0x00, 0x07], &[]),
    ];
    let blob = crafted_apple_blob(entries);
    // The parent IFD order is little-endian here, but the body marker is `MM`
    // (big-endian) — proving the body-marker order is what governs the walk, NOT
    // the parent order (the `from_marker` precedence in `apple_makernote_isolated`).
    let parent_order = ByteOrder::Little;

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_with_print_conv` (renders leaves at
      // collection). Returns `(typed, emissions)`; emissions carry (name, value,
      // unknown) but NOT a group.
      let (oracle_typed, oracle) = makernotes::vendors::apple::parse_with_print_conv(
        &blob,
        parent_order,
        print_conv,
        Some("Apple"),
      );

      // ---- New path A: the isolated helper the production dispatch drives.
      let (iso_emissions, iso_typed) =
        apple_makernote_isolated(&blob, parent_order, print_conv, Some("Apple"));
      // ---- New path B: the same walk emitted into an `EmittedTagSink` so the full
      // `MakerNotes:Apple` group is asserted (the `VendorEmission` stream omits it).
      let emitted = drive_apple_subdir(&blob, parent_order, print_conv);

      // Both streams are in IFD-tag order (the entries are ascending here), so
      // compare position-wise.
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "print_conv={print_conv}: isolated emission COUNT must match the oracle"
      );
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: EmittedTag COUNT must match the oracle"
      );
      for (i, want) in oracle.iter().enumerate() {
        // The `VendorEmission` stream the production dispatch caches.
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: VendorEmission NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): VendorEmission VALUE mismatch \
           (the new path must apply ApplePrintConv exactly as the oracle)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} leaf #{i} ({}): VendorEmission Unknown flag mismatch",
          want.name()
        );
        // The `EmittedTag` stream — same name/value/unknown PLUS the group override.
        let tag = emitted.get(i).expect("index in range").tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: EmittedTag NAME mismatch"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): EmittedTag VALUE mismatch",
          want.name()
        );
        assert_eq!(
          emitted.get(i).expect("index in range").unknown(),
          want.unknown(),
          "print_conv={print_conv} leaf #{i} ({}): EmittedTag Unknown flag mismatch",
          want.name()
        );
        // The vendor group OVERRIDE — every Apple leaf is `MakerNotes:Apple`.
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} leaf #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Apple",
          "print_conv={print_conv} leaf #{i} ({}): family-1 must be Apple",
          want.name()
        );
      }

      // The typed `MakerNotesApple` is built ONLY for `-j` (the `-n` recompute
      // discards it, so the isolated helper skips it — `None`, mirroring
      // `canon_makernote_isolated`). In `-j` it must equal the oracle's; compare
      // representative accessors across the surfaced shapes.
      if print_conv {
        let iso_typed = iso_typed.expect("print_conv=true must build the typed slot");
        assert_eq!(
          iso_typed, oracle_typed,
          "the isolated typed MakerNotesApple must equal the oracle's (-j)"
        );
        assert_eq!(
          iso_typed.hdr_image_type(),
          Some(3),
          "HDRImageType (0x000a) → typed accessor"
        );
        assert_eq!(
          iso_typed.image_capture_type(),
          Some(5),
          "ImageCaptureType (0x0014) → typed accessor"
        );
        assert_eq!(
          iso_typed.camera_type(),
          Some(1),
          "CameraType (0x002e) → typed accessor"
        );
        assert_eq!(
          iso_typed.burst_uuid(),
          Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
          "BurstUUID (0x000b) out-of-line ASCII → typed accessor"
        );
      } else {
        assert!(
          iso_typed.is_none(),
          "the -n recompute discards the typed slot (no wasted SmolStr allocation)"
        );
      }
    }
  }

  /// Assert the oracle (`apple::parse_with_print_conv`) and the shared-`Walker`
  /// isolated path (`apple_makernote_isolated`) emit BYTE-IDENTICAL
  /// `(name, value, unknown)` streams — in order — for BOTH `-j` and `-n`, over
  /// the SAME crafted Apple blob. The shared differential harness for the #243
  /// phase 3 Apple R2 oracle-alignment edges (undef[1]→int8u / count-0 /
  /// excessive-count): each edge crafts a blob, then `assert_apple_oracle_matches`
  /// proves the now-aligned `walk_apple_body` oracle agrees with the FAITHFUL
  /// shared Walker (the authority — Apple::Main IS processed by ProcessExif).
  #[cfg(feature = "alloc")]
  fn assert_apple_oracle_matches(blob: &[u8], parent_order: ByteOrder, label: &str) {
    // The differential edges here are real-Apple-blob decode equivalences, so
    // both paths run with the Apple Make ("Apple") — the format-16 carve-out is
    // exercised by its own dedicated gate tests.
    for print_conv in [true, false] {
      let (_oracle_typed, oracle) = makernotes::vendors::apple::parse_with_print_conv(
        blob,
        parent_order,
        print_conv,
        Some("Apple"),
      );
      let (iso_emissions, _iso_typed) =
        apple_makernote_isolated(blob, parent_order, print_conv, Some("Apple"));
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "{label} print_conv={print_conv}: shared-Walker emission COUNT must match the \
         aligned oracle"
      );
      for (i, want) in oracle.iter().enumerate() {
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "{label} print_conv={print_conv} leaf #{i}: NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "{label} print_conv={print_conv} leaf #{i} ({}): VALUE mismatch — the aligned \
           oracle must decode identically to the shared Walker",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "{label} print_conv={print_conv} leaf #{i} ({}): Unknown flag mismatch",
          want.name()
        );
      }
    }
  }

  /// #243 phase 3 Apple R2 [R2-1, FLAGGED] — the `undef[1]` → `int8u` carve-out
  /// (`Exif.pm:6644` `$formatStr = 'int8u' if $format == 7 and $count == 1`). A
  /// crafted Apple `RunTime` (0x0003) entry with on-disk format `undef` (7) and
  /// count 1, inline byte `0x2a`, must decode as an INTEGER (`int8u` ⇒
  /// `RawValue::U64([0x2a])`) in BOTH `walk_apple_body` (the now-aligned oracle)
  /// AND the shared `Walker` — NOT a 1-byte `RawValue::Bytes` blob. Before the
  /// alignment the oracle passed the on-disk `undef` through and decoded
  /// `RawValue::Bytes([0x2a])`, while the shared Walker coerced to int8u — the
  /// flagged divergence. Real Apple leaves are never `undef[1]`; this pins the
  /// crafted-edge consistency.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_undef_count1_leaf_coerces_int8u_like_shared_walker() {
    use crate::value::TagValue;
    // 0x0003 RunTime, on-disk format undef (7), count 1, inline byte 0x2a.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[(0x0003, 7, 1, &[0x2a], &[])];
    let blob = crafted_apple_blob(entries);

    // The oracle body walker's RAW shape — the truest expression of the
    // carve-out: a single `undef` byte becomes `int8u` (`RawValue::U64`), not
    // `RawValue::Bytes`. (`body_offset = 14`, parent order irrelevant — the body
    // marker `MM` governs.)
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(walked.len(), 1, "one RunTime entry");
    let raw = walked.get(0).expect("entry 0").value.raw();
    match raw {
      RawValue::U64(v) => assert_eq!(
        v.as_slice(),
        &[0x2a],
        "undef[1] must coerce to int8u (RawValue::U64([0x2a])), got {raw:?}"
      ),
      other => panic!(
        "undef[1] RunTime must decode as int8u (U64), NOT a 1-byte Bytes blob; got {other:?}"
      ),
    }

    // RunTime's `ConvertPLIST` ValueConv is deferred (`to_default_tag_value`), so
    // the int8u decode renders the scalar 0x2a (42) — a `Bytes` decode would
    // render the raw-bytes shape, so the rendered value also distinguishes the
    // two. `0x0003` is `Unknown => 0`, so it emits.
    let (_t, oracle) = makernotes::vendors::apple::parse_with_print_conv(
      &blob,
      ByteOrder::Big,
      false,
      Some("Apple"),
    );
    assert_eq!(oracle.len(), 1);
    let e = oracle.get(0).expect("emission 0");
    assert_eq!(e.name(), "RunTime");
    assert_eq!(
      e.value(),
      &TagValue::I64(42),
      "the int8u 0x2a renders as the scalar 42, not a bytes blob"
    );

    // BOTH paths agree, byte-identical, for -j and -n.
    assert_apple_oracle_matches(&blob, ByteOrder::Big, "undef[1]→int8u");
  }

  /// #243 phase 3 Apple R2 — count-based value size (`Exif.pm:6502` `$size =
  /// $count * $formatSize`, with the `:6285` count-0 expansion). A count-0
  /// `HDRImageType` (0x000a) followed by a VALID `CameraType` (0x002e) leaf:
  /// ExifTool reads `$count * $formatSize == 0` on-disk bytes, so `ReadValue`
  /// returns the empty `$val` (`Exif.pm:6285-6288`) — the count-0 leaf decodes
  /// EMPTY (`render_value` then drops it: a count-0 numeric is the empty string).
  /// The now-aligned oracle passes the COUNT-based `total_size` (not an EOF-bound
  /// `avail`), so it expands the SAME way as the shared Walker — instead of
  /// re-deriving a bogus count from the trailing buffer. The following valid leaf
  /// must STILL emit identically on both sides.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_count_zero_leaf_decodes_empty_like_shared_walker() {
    use crate::value::TagValue;
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x000a HDRImageType — int32s, COUNT 0 (inline slot is the zero word).
      (0x000a, 0x0009, 0, &[], &[]),
      // 0x002e CameraType — int32s, count 1, value 1 ⇒ "Back Normal". VALID.
      (0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]),
    ];
    let blob = crafted_apple_blob(entries);

    // The oracle body walker decodes the count-0 entry to the empty numeric value
    // (no trailing-buffer over-read): `read_value(.., count=0, size=0, ..)` ⇒
    // `empty_value` (an empty `U64`/`I64`). The CameraType leaf decodes normally.
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(
      walked.len(),
      2,
      "both entries are walked (count-0 is not skipped)"
    );
    let hdr = walked.get(0).expect("entry 0 HDRImageType");
    // Empty numeric ⇒ `first_i64()` is None (no element), proving NO trailing-byte
    // over-read produced a spurious scalar.
    assert_eq!(
      hdr.value.first_i64(),
      None,
      "a count-0 int32s must decode EMPTY (no trailing-buffer over-read), got {:?}",
      hdr.value.raw()
    );

    // In the emitted stream the count-0 HDRImageType renders as the empty string
    // on BOTH paths (a count-0 numeric `$val` is `''`); the CameraType leaf is
    // present. The two streams must be byte-identical.
    let (_t, oracle) = makernotes::vendors::apple::parse_with_print_conv(
      &blob,
      ByteOrder::Big,
      false,
      Some("Apple"),
    );
    assert_eq!(
      oracle.len(),
      2,
      "both leaves emit (the count-0 leaf renders the empty string, not dropped)"
    );
    assert_eq!(oracle.get(0).expect("0").name(), "HDRImageType");
    assert_eq!(
      oracle.get(0).expect("0").value(),
      &TagValue::Str("".into()),
      "count-0 numeric renders the empty string"
    );
    assert_eq!(oracle.get(1).expect("1").name(), "CameraType");

    assert_apple_oracle_matches(&blob, ByteOrder::Big, "count-0");
  }

  /// #243 phase 3 Apple R2 — the excessive-count `> 100000` guard
  /// (`Exif.pm:6760-6770` `if ($count > 100000 and $formatStr !~
  /// /^(undef|string|binary)$/) { next }`). A crafted `HDRHeadroom` (0x0021,
  /// int32s) with count `200000` (> 100000, NOT undef/ascii) — placed IN-BOUNDS
  /// (its out-of-line offset points at real appended bytes) — must be SKIPPED by
  /// BOTH the now-aligned oracle AND the shared Walker, before the value is read.
  /// A following VALID `CameraType` (0x002e) leaf must STILL emit on both sides.
  /// Before the alignment the oracle decoded such an entry (a large allocation +
  /// a leaked tag); the shared Walker has always applied the guard (ProcessExif
  /// has no `$inMakerNotes` exemption for it).
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_excessive_count_leaf_is_skipped_like_shared_walker() {
    // 0x0021 HDRHeadroom int32s, count 200000 (> 100000). The out-of-line value
    // region is FULLY IN-BOUNDS (200000 × 4 = 800000 real bytes appended), so the
    // skip is driven by the excessive-count guard — NOT a coincidental OOB read —
    // on BOTH paths (the shared Walker's offset bounds-check passes, then its
    // excessive-count guard fires, exactly as the now-aligned oracle's does).
    let big = std::vec![0u8; 200_000 * 4];
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x0021, 0x0009, 200_000, &[], &big),
      // 0x002e CameraType — int32s, count 1, value 1 ⇒ "Back Normal". VALID,
      // emitted AFTER the guard-skipped excessive-count entry.
      (0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]),
    ];
    let blob = crafted_apple_blob(entries);

    // The oracle body walker skips ONLY the excessive-count entry; the following
    // valid leaf survives.
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(
      walked.len(),
      1,
      "the excessive-count entry is guard-skipped; only the valid leaf walks"
    );
    assert_eq!(
      walked.get(0).expect("entry 0").tag_id,
      0x002e,
      "the surviving leaf is the post-guard CameraType (the over-count HDRHeadroom \
       was skipped, NOT decoded)"
    );

    // The emitted stream contains ONLY CameraType on both sides (HDRHeadroom is
    // skipped before render). The two streams must be byte-identical.
    let (_t, oracle) =
      makernotes::vendors::apple::parse_with_print_conv(&blob, ByteOrder::Big, true, Some("Apple"));
    assert_eq!(oracle.len(), 1, "only the valid CameraType leaf emits");
    assert_eq!(oracle.get(0).expect("0").name(), "CameraType");
    assert!(
      !oracle.iter().any(|e| e.name() == "HDRHeadroom"),
      "the excessive-count HDRHeadroom must NOT emit (guard-skipped)"
    );

    assert_apple_oracle_matches(&blob, ByteOrder::Big, "excessive-count");
  }

  /// The crafted blob carries the `Unknown=>1` `GreenGhostMitigationStatus`
  /// (0x003F), and the differential stream INCLUDES it with `unknown=true` on BOTH
  /// sides (the shared engine's `run_emission` is what drops it later — neither leaf
  /// path pre-filters). Asserting it is present-and-flagged proves the unknown flag
  /// flows identically (not silently dropped early by the new path).
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_leaf_unknown_flag_flows_like_oracle() {
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x000a HDRImageType — a normal leaf so the stream is non-trivial.
      (0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
      // 0x003F GreenGhostMitigationStatus — Unknown=>1.
      (0x003F, 0x0009, 1, &[0x00, 0x00, 0x00, 0x07], &[]),
    ];
    let blob = crafted_apple_blob(entries);
    let emitted = drive_apple_subdir(&blob, ByteOrder::Big, true);
    let ghost = emitted
      .iter()
      .find(|t| t.tag().name() == "GreenGhostMitigationStatus")
      .expect("GreenGhostMitigationStatus (0x003F) must be emitted (pre-drop) by the new path");
    assert!(
      ghost.unknown(),
      "GreenGhostMitigationStatus carries Unknown=>1 — the flag must ride the \
       EmittedTag so run_emission drops it centrally, NOT a per-path pre-filter"
    );
  }

  /// FIX (#243 phase 3 Apple R1/R4): the shared Walker's per-entry format gate
  /// admits the BigTIFF `int64u` code 16 for an Apple maker-note entry
  /// (`Exif.pm:6464` `not ($format == 16 and $$et{Make} eq 'Apple' and
  /// $inMakerNotes)`) — including when that entry is INDEX 0, which would
  /// otherwise be a `Bad format` entry-0-abort that loses the whole Apple walk
  /// (silent metadata loss on Apple ProRAW DNG MakerNotes). This is the POSITIVE
  /// case: the parent IFD0 Make IS `"Apple"` (passed to BOTH paths), so the
  /// carve-out is active. It proves the shared-Walker isolated path emits the
  /// SAME stream as the `apple::parse_with_print_conv` oracle (whose
  /// `walk_apple_body` admits code 16 under the same `Make == Some("Apple")`
  /// gate) for a blob with a format-16 entry BOTH at index 0 AND after a valid
  /// entry — i.e. the gate neither skips the int64u entry nor aborts the
  /// directory. The non-Apple-Make REJECTION is proven by
  /// [`apple_format16_int64u_rejected_when_make_not_apple`].
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_format16_int64u_admitted_at_index0_and_after_valid() {
    // int64u (format 16, 8 bytes) is always OUT-OF-LINE (> 4). Big-endian body.
    // `v0` has its top bit set (> i64::MAX) so the no-PrintConv default keeps the
    // exact `TagValue::U64` (render_value only narrows to I64 within i64 range) —
    // proving a genuine 8-byte int64u decode, not a coincidental int32.
    let v0 = 0x8899_AABB_CCDD_EEFFu64.to_be_bytes();
    let v2 = 0x1122_3344_5566_7788u64.to_be_bytes();
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // INDEX 0 — 0x0005 AETarget (conv None), format 16 int64u. The carve-out
      // must NOT abort the directory on this first entry.
      (0x0005, 16, 1, &[], &v0),
      // INDEX 1 — 0x000a HDRImageType, a VALID int32s entry (3 ⇒ "HDR Image").
      (0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
      // INDEX 2 — 0x0006 AEAverage (conv None), format 16 int64u AFTER a valid
      // entry. Admitted as a per-entry skip-or-decode, here decoded.
      (0x0006, 16, 1, &[], &v2),
    ];
    let blob = crafted_apple_blob(entries);
    let parent_order = ByteOrder::Big;

    for print_conv in [true, false] {
      // Make == "Apple" ⇒ the format-16 carve-out is ACTIVE on both paths.
      let (_oracle_typed, oracle) = makernotes::vendors::apple::parse_with_print_conv(
        &blob,
        parent_order,
        print_conv,
        Some("Apple"),
      );
      let (iso_emissions, _iso_typed) =
        apple_makernote_isolated(&blob, parent_order, print_conv, Some("Apple"));

      // The walk did NOT abort: all THREE leaves survive (the int64u index-0
      // entry did not trigger the entry-0 directory abort, and neither int64u
      // entry was skipped). The oracle (which accepts format 16) is the witness.
      assert_eq!(
        oracle.len(),
        3,
        "print_conv={print_conv}: oracle must emit all 3 leaves (int64u accepted, no abort)"
      );
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "print_conv={print_conv}: the shared-Walker path must NOT skip the int64u \
         entries or abort on the index-0 int64u (format-16 Apple carve-out)"
      );
      for (i, want) in oracle.iter().enumerate() {
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): VALUE mismatch — the int64u \
           value must decode as U64 identically on both paths",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} leaf #{i} ({}): Unknown flag mismatch",
          want.name()
        );
      }
      // The decoded int64u value, surfaced as the no-PrintConv default U64.
      let ae_target = iso_emissions
        .iter()
        .find(|e| e.name() == "AETarget")
        .expect("AETarget (the index-0 int64u entry) must be emitted");
      assert_eq!(
        ae_target.value(),
        &crate::value::TagValue::U64(0x8899_AABB_CCDD_EEFF),
        "print_conv={print_conv}: the index-0 int64u value decodes via Format::Int64u"
      );
    }
  }

  /// FIX (#243 phase 3 Apple R4 [high]): the format-16 (`int64u`) carve-out is
  /// gated on the PARENT IFD0 `Make` being exactly `"Apple"` — ExifTool's
  /// `not ($format == 16 and $$et{Make} eq 'Apple' and $inMakerNotes)`
  /// (`Exif.pm:6464`), NOT merely on the Apple MakerNote (`active_table == Apple`)
  /// context. Apple MakerNote dispatch is SIGNATURE-based, so a crafted file with
  /// an `"Apple iOS\0"`-signature blob but IFD0 Make != `"Apple"` reaches the gate;
  /// for a non-Apple Make ExifTool classifies code 16 as a BAD format and, at
  /// INDEX 0, ABORTS the directory ("assume corrupted IFD") — suppressing every
  /// later leaf. This NEGATIVE case reuses the SAME blob/shape as the positive
  /// [`apple_format16_int64u_admitted_at_index0_and_after_valid`] (format-16 at
  /// index 0 + a VALID Apple leaf after it) but passes `make = Some("Nikon")`: BOTH
  /// the shared-Walker isolated path AND the `parse_with_print_conv` oracle must
  /// emit NOTHING — the index-0 bad-format abort suppresses the later valid leaf —
  /// proving the Make gate (without it the index-0 code-16 would be admitted and
  /// all leaves would survive, the R4 divergence).
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_format16_int64u_rejected_when_make_not_apple() {
    let v0 = 0x8899_AABB_CCDD_EEFFu64.to_be_bytes();
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // INDEX 0 — format 16 int64u. For a NON-Apple Make this is a BAD format at
      // entry 0 ⇒ directory abort.
      (0x0005, 16, 1, &[], &v0),
      // INDEX 1 — a VALID 0x000a HDRImageType leaf that MUST be suppressed by the
      // entry-0 abort (it would emit if the directory were not aborted).
      (0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
    ];
    let blob = crafted_apple_blob(entries);
    let parent_order = ByteOrder::Big;

    // Sanity floor: with Make == "Apple" the SAME blob admits code 16 and emits
    // BOTH leaves (the carve-out is active) — so any difference below is the Make
    // gate, not the blob shape.
    let walked_apple =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, parent_order, Some("Apple"));
    assert_eq!(
      walked_apple.len(),
      2,
      "Make=Apple admits code 16 at index 0 ⇒ both leaves survive (control)"
    );

    for print_conv in [true, false] {
      // Non-Apple Make ⇒ code 16 is a BAD format; at index 0 the directory aborts.
      let (_oracle_typed, oracle) = makernotes::vendors::apple::parse_with_print_conv(
        &blob,
        parent_order,
        print_conv,
        Some("Nikon"),
      );
      let (iso_emissions, _iso_typed) =
        apple_makernote_isolated(&blob, parent_order, print_conv, Some("Nikon"));

      assert!(
        oracle.is_empty(),
        "print_conv={print_conv}: Make=Nikon ⇒ the index-0 format-16 entry is a bad \
         format that aborts the directory; the oracle must emit NOTHING (incl. the \
         later valid HDRImageType)"
      );
      assert!(
        iso_emissions.is_empty(),
        "print_conv={print_conv}: the shared-Walker path must ALSO abort at the \
         index-0 format-16 entry when Make != Apple — the carve-out requires \
         captured_make == Some(\"Apple\")"
      );
    }

    // The oracle body walker, with a non-Apple Make, aborts at the index-0 code-16
    // ⇒ NO surviving entries (the truest expression of the gate).
    let walked_nikon =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, parent_order, Some("Nikon"));
    assert!(
      walked_nikon.is_empty(),
      "Make=Nikon: the index-0 format-16 bad-format aborts the whole directory, got {walked_nikon:?}"
    );
    // A missing Make (None) is likewise NOT "Apple" ⇒ same abort.
    let walked_none = makernotes::vendors::apple::walk_apple_body(&blob, 14, parent_order, None);
    assert!(
      walked_none.is_empty(),
      "Make=None is not \"Apple\" ⇒ code 16 stays a bad format (index-0 abort), got {walked_none:?}"
    );
  }

  /// #243 phase 3 Apple R3 [classification] — a BAD (nonzero unrecognized)
  /// format code at ENTRY 0 ABORTS the whole Apple directory, exactly as the
  /// shared `Walker` does (`Exif.pm:6475` `return 0`, "assume corrupted IFD if
  /// this is our first entry"). A VALID leaf at index 1 must therefore emit
  /// NOTHING on BOTH paths — the now-aligned `walk_apple_body` oracle aborts the
  /// directory at the index-0 bad format just like `apple_makernote_isolated`'s
  /// ProcessExif walk. Before the alignment the oracle merely skipped the bad
  /// entry (`elem_size == 0 => continue`) and went on to emit the index-1 leaf —
  /// the R3 divergence (finding 1).
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_bad_format_at_index0_aborts_directory_like_shared_walker() {
    // Entry 0: tag 0x000a, format 0x00ff (255 — unrecognized, NONZERO), count 1,
    // inline. Entry 1: a VALID 0x002e CameraType (int32s, value 1). The crafted
    // builder lays entries inline (both have `byte_size 0`/`<= 4` ⇒ inline).
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x000a, 0x00ff, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
      (0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]),
    ];
    let blob = crafted_apple_blob(entries);

    // The oracle body walker ABORTS at the index-0 bad format ⇒ NO entries.
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert!(
      walked.is_empty(),
      "a bad format at entry 0 aborts the whole directory (no entries), got {walked:?}"
    );

    // Both emission paths produce an EMPTY stream — the index-1 CameraType is
    // NOT salvaged (the directory was aborted before reaching it).
    let (_t, oracle) =
      makernotes::vendors::apple::parse_with_print_conv(&blob, ByteOrder::Big, true, Some("Apple"));
    assert!(
      oracle.is_empty(),
      "the index-0 abort suppresses ALL leaves incl. the later valid CameraType"
    );
    assert_apple_oracle_matches(&blob, ByteOrder::Big, "bad-format-index0-abort");
  }

  /// #243 phase 3 Apple R3 [classification] — a BAD (nonzero unrecognized)
  /// format code at a LATER index is a per-entry SKIP (`Exif.pm:6476`
  /// `next if $index`), NOT a directory abort: the surrounding VALID leaves
  /// survive on BOTH paths. Entry 0 valid, entry 1 bad format, entry 2 valid ⇒
  /// the oracle and the shared `Walker` both emit the two valid leaves and skip
  /// the bad one.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_bad_format_at_later_index_skips_one_like_shared_walker() {
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // INDEX 0 — VALID 0x000a HDRImageType (int32s, 3 ⇒ "HDR Image").
      (0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]),
      // INDEX 1 — BAD format 0x00ff (255, nonzero), SKIPPED (not index 0).
      (0x0099, 0x00ff, 1, &[0x00, 0x00, 0x00, 0x00], &[]),
      // INDEX 2 — VALID 0x002e CameraType (int32s, 1 ⇒ "Back Normal").
      (0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]),
    ];
    let blob = crafted_apple_blob(entries);

    // The oracle walks both valid leaves, skips ONLY the bad-format entry.
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(
      walked.len(),
      2,
      "the two valid leaves survive; only the bad-format entry is skipped: {walked:?}"
    );
    assert_eq!(walked.get(0).expect("0").tag_id, 0x000a);
    assert_eq!(walked.get(1).expect("1").tag_id, 0x002e);

    // Both emission streams contain exactly the two valid leaves.
    let (_t, oracle) =
      makernotes::vendors::apple::parse_with_print_conv(&blob, ByteOrder::Big, true, Some("Apple"));
    assert_eq!(
      oracle.len(),
      2,
      "HDRImageType + CameraType emit; the bad entry is skipped"
    );
    assert_eq!(oracle.get(0).expect("0").name(), "HDRImageType");
    assert_eq!(oracle.get(1).expect("1").name(), "CameraType");
    assert_apple_oracle_matches(&blob, ByteOrder::Big, "bad-format-later-skip");
  }

  /// #243 phase 3 Apple R3 [classification, finding 2] — a SUSPICIOUS out-of-line
  /// offset (`$valuePtr < 8`, into the TIFF header — `Exif.pm:6539`; OR overlapping
  /// the IFD directory — `Exif.pm:6549`) is a per-entry SKIP (`Exif.pm:6675`
  /// "Suspicious offset" + `next`), NOT a decode. The now-aligned `walk_apple_body`
  /// applies the SAME gate in blob-absolute coordinates (the Apple IFD start =
  /// `14 + header_size`); a following VALID leaf survives on BOTH paths. Before the
  /// alignment the oracle only bounds-checked the offset (it decoded a `< 8` or
  /// IFD-overlapping value), diverging from the shared `Walker`.
  ///
  /// Builds the blob BY HAND so the out-of-line offset is forced to the suspicious
  /// value (the auto-offset `crafted_apple_blob` cannot point into the header/IFD).
  /// Two sub-cases: an offset of 4 (`< 8`) and an offset of 20 (overlaps the
  /// 1-entry IFD `[16, 30)`); each is IN-BOUNDS (passes the EOF check) so the SKIP
  /// is driven by the suspicious gate, not the bad-offset EOF gate.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_suspicious_offset_skips_one_like_shared_walker() {
    // Build a 2-entry Apple body where entry 0 is an out-of-line rational64u
    // (size 8 > 4) whose offset is `suspicious_off`, and entry 1 is a VALID inline
    // CameraType. `ifd_start = 16`; with 2 entries `dir_end = 16 + 2 + 24 = 42`.
    fn build(suspicious_off: u32) -> Vec<u8> {
      let mut blob: Vec<u8> = Vec::new();
      blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM"); // 14-byte header
      blob.extend_from_slice(b"MM"); // body marker
      blob.extend_from_slice(&2u16.to_be_bytes()); // 2 entries
      // Entry 0 — tag 0x0008 AccelerationVector, rational64s (10), count 1,
      // OUT-OF-LINE offset = suspicious_off.
      blob.extend_from_slice(&0x0008u16.to_be_bytes());
      blob.extend_from_slice(&0x000au16.to_be_bytes()); // rational64s
      blob.extend_from_slice(&1u32.to_be_bytes()); // count 1 ⇒ size 8 > 4
      blob.extend_from_slice(&suspicious_off.to_be_bytes());
      // Entry 1 — tag 0x002e CameraType, int32s (9), count 1, INLINE value 1.
      blob.extend_from_slice(&0x002eu16.to_be_bytes());
      blob.extend_from_slice(&0x0009u16.to_be_bytes());
      blob.extend_from_slice(&1u32.to_be_bytes());
      blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
      blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
      // Trailing value region so an in-bounds (but suspicious) offset+8 fits.
      blob.extend_from_slice(&[0u8; 16]);
      blob
    }

    // Sub-case 1: offset 4 (`< 8`). Sub-case 2: offset 20 (overlaps IFD [16,42)).
    for (suspicious_off, label) in [(4u32, "off<8"), (20u32, "overlaps-ifd")] {
      let blob = build(suspicious_off);
      let walked =
        makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
      assert_eq!(
        walked.len(),
        1,
        "{label}: the suspicious-offset entry is skipped; only the valid CameraType \
         survives, got {walked:?}"
      );
      assert_eq!(
        walked.get(0).expect("0").tag_id,
        0x002e,
        "{label}: the surviving leaf is CameraType (the suspicious AccelerationVector \
         was skipped, not decoded)"
      );
      let (_t, oracle) = makernotes::vendors::apple::parse_with_print_conv(
        &blob,
        ByteOrder::Big,
        true,
        Some("Apple"),
      );
      assert_eq!(oracle.len(), 1, "{label}: only CameraType emits");
      assert_eq!(oracle.get(0).expect("0").name(), "CameraType");
      assert!(
        !oracle.iter().any(|e| e.name() == "AccelerationVector"),
        "{label}: the suspicious-offset AccelerationVector must NOT emit"
      );
      assert_apple_oracle_matches(&blob, ByteOrder::Big, label);
    }
  }

  /// #243 phase 3 Apple R3 [classification, next-steps] — the warn-count abort
  /// (`Exif.pm:6455-6456` `if ($warnCount > 10) { Warn('Too many warnings');
  /// return 0 }`). Eleven consecutive bad-format entries (each `++$warnCount`)
  /// push the count to 11; the next entry trips the abort BEFORE it is processed,
  /// so a VALID leaf placed after them emits NOTHING. The now-aligned
  /// `walk_apple_body` mirrors the same per-entry warn cap as
  /// `apple_makernote_isolated`'s ProcessExif walk. A valid leaf at index 0
  /// (before any warning) emits on BOTH paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn apple_warn_count_abort_after_eleven_warnings_like_shared_walker() {
    // Index 0: VALID 0x000a HDRImageType (emits). Indices 1..=11: bad nonzero
    // format 0x00ff (each warns + counts; skipped, not index 0). Index 12: a VALID
    // 0x002e CameraType that must NOT emit (warn_count == 11 > 10 aborts first).
    let mut entries: Vec<(u16, u16, u32, &[u8], &[u8])> = Vec::new();
    entries.push((0x000a, 0x0009, 1, &[0x00, 0x00, 0x00, 0x03], &[]));
    for _ in 0..11 {
      entries.push((0x0099, 0x00ff, 1, &[0x00, 0x00, 0x00, 0x00], &[]));
    }
    entries.push((0x002e, 0x0009, 1, &[0x00, 0x00, 0x00, 0x01], &[]));
    let blob = crafted_apple_blob(&entries);

    // The oracle walks index 0 (HDRImageType), skips+counts indices 1..=11, then
    // aborts at index 12 BEFORE the CameraType — so ONLY HDRImageType survives.
    let walked =
      makernotes::vendors::apple::walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(
      walked.len(),
      1,
      "only the pre-warning HDRImageType survives; the >10-warning abort suppresses \
       the trailing CameraType, got {walked:?}"
    );
    assert_eq!(walked.get(0).expect("0").tag_id, 0x000a);

    let (_t, oracle) =
      makernotes::vendors::apple::parse_with_print_conv(&blob, ByteOrder::Big, true, Some("Apple"));
    assert_eq!(
      oracle.len(),
      1,
      "only HDRImageType emits (the warn-count abort)"
    );
    assert_eq!(oracle.get(0).expect("0").name(), "HDRImageType");
    assert!(
      !oracle.iter().any(|e| e.name() == "CameraType"),
      "the trailing CameraType is suppressed by the >10-warning directory abort"
    );
    assert_apple_oracle_matches(&blob, ByteOrder::Big, "warn-count-abort");
  }

  /// The group OVERRIDE is scoped to the Apple table too: `vendor_group1_of` is
  /// `Some(\"Apple\")` for `Apple` (so an Apple leaf emits as `Apple:*`) — phase 3
  /// of the engine migration (#243).
  #[test]
  fn vendor_group1_override_includes_apple() {
    assert_eq!(vendor_group1_of(TableRef::Apple), Some("Apple"));
  }

  // ====================================================================// Sony engine migration — differential test (#243 phase 3)
  //
  // PROVES the shared `Walker`'s Sony Main leaf path (`process_subdir` under
  // `TableRef::Sony` → the dedicated `emit_sony_value` capture, via
  // `sony_makernote_isolated`) is BYTE-IDENTICAL to the production oracle
  // `sony::parse_in_tiff` (`walk_sony_in_tiff` + the per-entry gates). The same
  // crafted Sony Main blob is run through BOTH paths; the emitted `(name, value,
  // group="MakerNotes:Sony", unknown)` tuples must match, in order, for `-j`
  // (PrintConv) AND `-n` (ValueConv), and the typed `MakerNotesSony` must agree.
  // Sony is the COMPLEX vendor case — the blob exercises every per-entry gate:
  // the af_area DataMember thread (0x201c sets it, 0x201e reads it), a single-HASH
  // `Condition` PASS (0x201b) + SUPPRESS (0xb050), a `$format`-gated row needing
  // the on-disk format (0x1000, which ALSO has a `Format =>` override), a RawConv
  // sentinel drop (0xb041 == 65535), a deferred SubDirectory row (0x0010), and a
  // plain typed leaf (0x0102). A routes-AWAY blob (SEMC) returns `None`.
  // ====================================================================

  /// Build a crafted little-endian Sony Main blob: the 12-byte `SONY DSC ` prefix
  /// (the `MakerNoteSony` offset-12 header so `routes_to_main` passes), then the
  /// body's entry count + the 12-byte IFD entries, then the next-IFD word, then any
  /// out-of-line value bytes. `entries` is `(tag, format, count, inline_or_empty,
  /// out_of_line_or_empty)`: INLINE when `out_of_line` is empty (value zero-padded
  /// to 4 bytes at `entry+8`), else OUT-OF-LINE (the 4 bytes at `entry+8` are the
  /// TIFF-relative offset — Sony inherits the parent base, and this blob IS the
  /// parent TIFF at `mn_offset = 0`, so the offset is blob-relative).
  ///
  /// Entries must be written in ASCENDING tag-id order (real cameras write sorted
  /// Sony IFDs — the oracle's 0x201c-before-0x201e af_area capture relies on it).
  #[cfg(feature = "alloc")]
  fn crafted_sony_blob(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    // Body layout (the blob, with the SONY DSC prefix at offset 0, body at 12):
    // [SONY DSC \0\0\0][count u16][entries...][next-IFD u32][values]. The first
    // out-of-line value sits right after the next-IFD word.
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let dir_bytes = 2 + 12 * entries.len(); // count + entries
    let mut value_cursor = 12 + dir_bytes + 4; // 12-byte prefix + dir + next-IFD
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"SONY DSC \x00\x00\x00"); // 12-byte prefix
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if out_of_line.is_empty() {
        // Only the 13 standard TIFF codes have a known element size; a crafted
        // BAD format (e.g. 255, or an inline 16) carries no `@formatSize` entry —
        // skip the fit-check for it and just emit the (≤4-byte) inline slot, the
        // same latitude `crafted_apple_blob` gives a bad-format inline entry.
        if let Some(&elem) = elem_sizes.get(format as usize) {
          assert!(
            elem * count as usize <= 4,
            "inline value must fit in 4 bytes"
          );
        }
        let mut slot = [0u8; 4];
        slot[..inline.len().min(4)].copy_from_slice(&inline[..inline.len().min(4)]);
        blob.extend_from_slice(&slot);
      } else {
        blob.extend_from_slice(&(value_cursor as u32).to_le_bytes());
        value_blob.extend_from_slice(out_of_line);
        value_cursor += out_of_line.len();
      }
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    blob.extend_from_slice(&value_blob);
    blob
  }

  /// Drive the shared `Walker` through `sony_makernote_isolated`'s walk over the
  /// blob (`mn_offset = 0`, body at 12, parent order), then render every collected
  /// entry through the dedicated `emit_sony_value` (threading af_area) into an
  /// `EmittedTagSink` — the NEW path's output WITH the full `MakerNotes:Sony` group
  /// (which the `VendorEmission` stream alone does not carry). Mirrors the
  /// production isolated walk exactly (base 0, parent order, `TableRef::Sony`,
  /// `ProcessProc::Exif`).
  #[cfg(feature = "alloc")]
  fn drive_sony_subdir(
    blob: &[u8],
    order: ByteOrder,
    model: Option<&str>,
    print_conv: bool,
  ) -> Vec<crate::emit::EmittedTag> {
    let mut w = test_walker(blob);
    w.order = order;
    w.process_subdir(
      12, // body offset for the SONY DSC prefix
      IfdKind::ExifIfd,
      TableRef::Sony,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Exif,
    );
    let g1 = vendor_group1_of(TableRef::Sony).unwrap_or("Sony");
    let mut out: Vec<crate::emit::EmittedTag> = Vec::new();
    let mut sink = EmittedTagSink::new(&mut out);
    let mut af_area: Option<i64> = None;
    for entry in &w.entries {
      if entry.tag_id == 0x201c {
        af_area = makernotes::vendors::sony::af_area_data_member_from_raw(entry.value.raw(), model);
      }
      if let ResolvedConv::Sony(sony_tag) = entry.conv {
        let Ok(()) = emit_sony_value(
          g1, entry, sony_tag, model, af_area, print_conv, None, &mut sink,
        );
      }
    }
    out
  }

  /// The Sony leaf-path differential proof: for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), the shared `Walker` Sony leaf path emits the EXACT same
  /// `(name, value, group="MakerNotes:Sony", unknown)` stream — in order — as
  /// `sony::parse_in_tiff`, AND the typed `MakerNotesSony` agrees. Every per-entry
  /// gate is exercised (see the section banner).
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_isolated_emit_matches_parse_in_tiff() {
    let order = ByteOrder::Little;
    let model = Some("ILCE-7M3"); // NEX/ILCE branch ⇒ 0x201c sets af_area, 0x201e reads it
    let make = Some("SONY");
    // ASCENDING tag-id order (real Sony IFDs are sorted; 0x201c must precede
    // 0x201e for the af_area thread). int16u=3, int8u=1, undef=7.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x0010 CameraInfo — a DEFERRED SubDirectory row (`sub_table=Some`). Use a
      // valid out-of-line int8u blob; the parent must be SUPPRESSED (no emission).
      (0x0010, 0x0001, 8, &[], &[1, 2, 3, 4, 5, 6, 7, 8]),
      // 0x0102 Quality — plain typed leaf. int16u 2 ⇒ "Fine"; typed.quality = 2.
      (0x0102, 0x0003, 1, &[0x02, 0x00], &[]),
      // 0x1000 MultiBurstMode — ON-DISK `undef` (single-HASH `$format eq "undef"`
      // HOLDS) AND a `Format => int8u` override (re-reads the byte as int8u). The
      // value byte 1 ⇒ OnOff "On". Proves the on-disk format reaches the gate AND
      // the Sony Format override is applied by the shared Walker.
      (0x1000, 0x0007, 1, &[0x01], &[]),
      // 0x201b FocusMode — single-HASH `Condition` HOLDS (Model not `DSC-`). int16u
      // 0 ⇒ FocusMode2 render. Proves a single-HASH PASS.
      (0x201b, 0x0003, 1, &[0x00, 0x00], &[]),
      // 0x201c AfAreaModeSetting — int8u 4 ⇒ branch-2 "Flexible Spot (LA-EA4)" AND
      // sets the AFAreaILCE DataMember to 4 (read by 0x201e below).
      (0x201c, 0x0001, 1, &[0x04], &[]),
      // 0x201e AfPointSelected — int8u 1 ⇒ branch-1 (ILCE && af_area==4) "Center".
      // Proves the in-IFD af_area thread (a DIFFERENT branch fires when af_area==4).
      (0x201e, 0x0001, 1, &[0x01], &[]),
      // 0xb041 ExposureMode — RawConv sentinel: int16u 65535 ⇒ DROPPED (no emission,
      // and typed.exposure_mode must stay None — it is ALSO a typed leaf).
      (0xb041, 0x0003, 1, &[0xff, 0xff], &[]),
      // 0xb050 HighISONoiseReduction2 — single-HASH `Condition` FAILS (Model is not
      // `DSC-`/`Stellar`) ⇒ SUPPRESSED. Proves a single-HASH SUPPRESS.
      (0xb050, 0x0003, 1, &[0x00, 0x00], &[]),
    ];
    let blob = crafted_sony_blob(entries);

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (returns `(typed, emissions)`).
      let (oracle_typed, oracle) = makernotes::vendors::sony::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        12,
        order,
        print_conv,
        model,
      );

      // ---- New path A: the gated isolated helper the production dispatch drives.
      let (iso_emissions, iso_typed) =
        sony_makernote_isolated(&blob, 0, blob.len(), 12, order, make, model, print_conv)
          .expect("SONY DSC prefix ⇒ routes_to_main ⇒ Some");
      // ---- New path B: the same walk emitted into an `EmittedTagSink` so the full
      // `MakerNotes:Sony` group is asserted (the `VendorEmission` stream omits it).
      let emitted = drive_sony_subdir(&blob, order, model, print_conv);

      // The emitted stream is in IFD-tag order (entries ascending), so compare
      // position-wise. The four SUPPRESSED entries (0x0010/0xb041/0xb050) leave the
      // stream with exactly four survivors: 0x0102, 0x1000, 0x201b, 0x201c, 0x201e.
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "print_conv={print_conv}: isolated emission COUNT must match the oracle"
      );
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: EmittedTag COUNT must match the oracle"
      );
      assert_eq!(
        oracle.len(),
        5,
        "print_conv={print_conv}: 5 survivors (0x0010/0xb041/0xb050 suppressed)"
      );
      for (i, want) in oracle.iter().enumerate() {
        // The `VendorEmission` stream the production dispatch caches.
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: VendorEmission NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): VendorEmission VALUE mismatch \
           (the new path must apply SonyPrintConv + gates exactly as the oracle)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} leaf #{i} ({}): VendorEmission Unknown flag mismatch",
          want.name()
        );
        // The `EmittedTag` stream — same name/value/unknown PLUS the group override.
        let tag = emitted.get(i).expect("index in range").tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} leaf #{i}: EmittedTag NAME mismatch"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} leaf #{i} ({}): EmittedTag VALUE mismatch",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} leaf #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Sony",
          "print_conv={print_conv} leaf #{i} ({}): family-1 must be Sony",
          want.name()
        );
      }

      // Position-wise survivor names (a guard against a same-length permutation).
      let names: Vec<&str> = iso_emissions.iter().map(|e| e.name()).collect();
      assert_eq!(
        names,
        std::vec![
          "Quality",
          "MultiBurstMode",
          "FocusMode",
          "AFAreaModeSetting",
          "AFPointSelected"
        ],
        "print_conv={print_conv}: survivor names + order"
      );

      // The typed `MakerNotesSony` is the SAME for both modes and must match the
      // oracle's — including that the rawconv-dropped 0xb041 left `exposure_mode`
      // None (the typed populate is gate-passing, like the oracle).
      assert_eq!(
        iso_typed, oracle_typed,
        "print_conv={print_conv}: the isolated typed MakerNotesSony must equal the oracle's"
      );
      assert_eq!(
        iso_typed.quality(),
        Some(2),
        "print_conv={print_conv}: Quality (0x0102) → typed accessor"
      );
      assert_eq!(
        iso_typed.exposure_mode(),
        None,
        "print_conv={print_conv}: rawconv-dropped 0xb041 must NOT populate exposure_mode"
      );
    }
  }

  /// A `Vendor::Sony` blob that routes AWAY from `%Sony::Main` (a `SEMC MS\0`
  /// SonyEricsson signature → `Sony::Ericsson`, unported) must yield `None` from
  /// `sony_makernote_isolated` — the variant gate (`routes_to_main`) keeps the Sony
  /// slot ABSENT rather than decoding a spurious tag on a tag-id collision. The
  /// Make is the real Ericsson `"Sony Ericsson"` (mixed case, NOT `/^SONY/`), so
  /// the `%Main`-order Sony5 gate (tested BEFORE SonyEricsson) does NOT claim it —
  /// the SEMC rejection fires. (An uppercase `SONY` Make would route to Main per
  /// `%Main` order — covered by `routes_to_main_gates_non_main_variants`.)
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_isolated_routes_away_blob_is_none() {
    // A `SEMC MS\0` body — enough bytes that the blob window is non-empty; the gate
    // rejects on the signature alone (no Main walk runs).
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"SEMC MS\x00");
    blob.extend_from_slice(&[0u8; 16]); // arbitrary trailing bytes
    for print_conv in [true, false] {
      let out = sony_makernote_isolated(
        &blob,
        0,
        blob.len(),
        20, // SonyEricsson body offset (irrelevant — the gate rejects first)
        ByteOrder::Little,
        Some("Sony Ericsson"),
        Some("C905"),
        print_conv,
      );
      assert!(
        out.is_none(),
        "print_conv={print_conv}: a SEMC (SonyEricsson) blob with a non-`^SONY` Make \
         routes away from %Sony::Main ⇒ sony_makernote_isolated must return None"
      );
    }
  }

  // ====================================================================
  // Sony engine migration — ProcessExif-classification crafted edges (#243
  // phase 3). The production Sony walk runs the shared `Walker` (faithful
  // ProcessExif) via `sony_makernote_isolated`; the retained oracle
  // `walk_sony_in_tiff` is now ProcessExif-classification-equivalent. These
  // tests pin the byte-identity of the two on the FULL crafted-edge class the
  // Apple migration discovered: `undef[1]`→int8u, count-0, excessive-count,
  // bad-format (index-0 ABORT + later-index SKIP), suspicious offset (`<8` and
  // IFD-overlap), and the warn-count>10 abort. Sony has NO ProRAW int64u, so the
  // Apple format-16/Make carve-out is NOT exercised (code 16 is a bad format).
  // ====================================================================

  /// Assert the production shared-`Walker` Sony path (`sony_makernote_isolated`)
  /// emits the EXACT same `(name, value, unknown)` stream — in order — as the
  /// oracle `sony::parse_in_tiff`, for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), AND that the typed `MakerNotesSony` agrees. The crafted blob
  /// carries the `SONY DSC ` prefix (`body_offset = 12`), so `routes_to_main`
  /// passes; `make`/`model` are threaded into both paths' per-entry gates.
  #[cfg(feature = "alloc")]
  fn assert_sony_oracle_matches(
    blob: &[u8],
    order: ByteOrder,
    make: Option<&str>,
    model: Option<&str>,
    label: &str,
  ) {
    for print_conv in [true, false] {
      let (oracle_typed, oracle) =
        makernotes::vendors::sony::parse_in_tiff(blob, 0, blob.len(), 12, order, print_conv, model);
      let (iso_emissions, iso_typed) =
        sony_makernote_isolated(blob, 0, blob.len(), 12, order, make, model, print_conv)
          .expect("SONY DSC prefix ⇒ routes_to_main ⇒ Some");
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "{label} print_conv={print_conv}: shared-Walker emission COUNT must match the \
         aligned oracle"
      );
      for (i, want) in oracle.iter().enumerate() {
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "{label} print_conv={print_conv} leaf #{i}: NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "{label} print_conv={print_conv} leaf #{i} ({}): VALUE mismatch — the aligned \
           oracle must decode identically to the shared Walker",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "{label} print_conv={print_conv} leaf #{i} ({}): Unknown flag mismatch",
          want.name()
        );
      }
      assert_eq!(
        iso_typed, oracle_typed,
        "{label} print_conv={print_conv}: the isolated typed MakerNotesSony must equal the \
         oracle's"
      );
    }
  }

  /// `undef[1]` → `int8u` (`Exif.pm:6644`). A crafted `0x2000`-region tag whose
  /// on-disk format is `undef` (7) with count 1 must decode as an INTEGER
  /// (`int8u` ⇒ `RawValue::U64`), NOT a 1-byte `RawValue::Bytes` blob, in BOTH
  /// `walk_sony_in_tiff` (the now-aligned oracle) AND the shared `Walker`. Uses
  /// `0x0102 Quality` (`undef[1]` inline byte 2): even though Quality's on-disk
  /// format is normally int16u, ExifTool's int8u carve-out applies to the
  /// post-read pair, so the value decodes as the scalar 2 (Quality "Fine") on
  /// both paths. Real Sony leaves are never `undef[1]`; this pins the
  /// crafted-edge consistency.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_undef_count1_leaf_coerces_int8u_like_shared_walker() {
    // 0x0102 Quality, on-disk format undef (7), count 1, inline byte 0x02.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[(0x0102, 7, 1, &[0x02], &[])];
    let blob = crafted_sony_blob(entries);

    // The oracle body walker's RAW shape — a single `undef` byte becomes `int8u`
    // (`RawValue::U64`), not `RawValue::Bytes`.
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert_eq!(walked.len(), 1, "one Quality entry");
    let raw = &walked.get(0).expect("entry 0").value;
    match raw {
      RawValue::U64(v) => assert_eq!(
        v.as_slice(),
        &[0x02],
        "undef[1] must coerce to int8u (RawValue::U64([2])), got {raw:?}"
      ),
      other => panic!(
        "undef[1] Quality must decode as int8u (U64), NOT a 1-byte Bytes blob; got {other:?}"
      ),
    }

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "undef[1]→int8u",
    );
  }

  /// Count-based value size (`Exif.pm:6502` `$size = $count * $formatSize`, with
  /// the `:6285` count-0 expansion). A count-0 `0x200a` (int16u) followed by a
  /// VALID `0x0102 Quality`: ExifTool reads `$count * $formatSize == 0` on-disk
  /// bytes, so `ReadValue` returns the empty `$val` — the count-0 leaf decodes
  /// EMPTY. The now-aligned oracle passes the COUNT-based `total_size` (not an
  /// EOF-bound `avail`), so it expands the SAME way as the shared Walker. The
  /// following valid leaf must STILL emit identically on both sides.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_count_zero_leaf_decodes_empty_like_shared_walker() {
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x200a AutoHDR — int16u, COUNT 0 (inline slot is the zero word). 0x200a
      // ALSO has a `Format =>` override; resolve_read_format keeps count 0.
      (0x200a, 0x0003, 0, &[], &[]),
      // 0x0102 Quality — int16u, count 1, value 2 ⇒ "Fine". VALID.
      (0x0102, 0x0003, 1, &[0x02, 0x00], &[]),
    ];
    let blob = crafted_sony_blob(entries);

    // The oracle body walker decodes BOTH entries (count-0 is not skipped); the
    // count-0 entry's value has zero elements (no trailing-buffer over-read).
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert_eq!(
      walked.len(),
      2,
      "both entries are walked (count-0 is not skipped): {walked:?}"
    );
    assert_eq!(
      walked.get(0).expect("entry 0").value.count(),
      0,
      "a count-0 int16u must decode EMPTY (no trailing-buffer over-read)"
    );

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "count-0",
    );
  }

  /// The excessive-count `> 100000` guard (`Exif.pm:6760-6770` `if ($count >
  /// 100000 and $formatStr !~ /^(undef|string|binary)$/) { next }`). A crafted
  /// `0x2001` (int32u) with count `200000` (> 100000, NOT undef/ascii) — placed
  /// IN-BOUNDS (its out-of-line offset points at real appended bytes) — must be
  /// SKIPPED by BOTH the now-aligned oracle AND the shared Walker, before the
  /// value is read. A following VALID `0x0102 Quality` must STILL emit on both
  /// sides. Before the alignment the oracle decoded such an entry (a large
  /// allocation + a leaked tag).
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_excessive_count_leaf_is_skipped_like_shared_walker() {
    // 0x2001 PreviewImage region tag id reused as a plain int32u count-200000
    // entry; the out-of-line value region is FULLY IN-BOUNDS (200000 × 4 real
    // bytes), so the skip is the excessive-count guard, NOT a coincidental OOB.
    let big = std::vec![0u8; 200_000 * 4];
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x2001, 0x0004, 200_000, &[], &big),
      // 0x0102 Quality — int16u, count 1, value 2 ⇒ "Fine". VALID, emitted AFTER
      // the guard-skipped excessive-count entry.
      (0x0102, 0x0003, 1, &[0x02, 0x00], &[]),
    ];
    let blob = crafted_sony_blob(entries);

    // The oracle body walker skips ONLY the excessive-count entry; the following
    // valid leaf survives.
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert_eq!(
      walked.len(),
      1,
      "the excessive-count entry is guard-skipped; only the valid leaf walks: {walked:?}"
    );
    assert_eq!(
      walked.get(0).expect("entry 0").tag_id,
      0x0102,
      "the surviving leaf is the post-guard Quality (the over-count entry was \
       skipped, NOT decoded)"
    );

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "excessive-count",
    );
  }

  /// Bad-format at ENTRY 0 ABORTS the whole Sony directory (`Exif.pm:6475`
  /// `return 0`, "assume corrupted IFD if this is our first entry"). A VALID leaf
  /// at index 1 must therefore emit NOTHING on BOTH paths — the now-aligned
  /// `walk_sony_in_tiff` oracle aborts the directory at the index-0 bad format
  /// just like `sony_makernote_isolated`'s ProcessExif walk. Code 16 (`int64u`,
  /// nonzero unrecognized — Sony has no Apple carve-out) is the bad format.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_bad_format_at_index0_aborts_directory_like_shared_walker() {
    // Entry 0: tag 0x0102, format 16 (int64u — unrecognized in a standard IFD,
    // NONZERO, NO Sony carve-out), count 1, OUT-OF-LINE (size 8 > 4). Entry 1: a
    // VALID inline 0x0114 (int16u). The directory aborts at index 0.
    let v0 = 0x0102_0304_0506_0708u64.to_le_bytes();
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x0102, 16, 1, &[], &v0),
      (0x0114, 0x0003, 1, &[0x01, 0x00], &[]),
    ];
    let blob = crafted_sony_blob(entries);

    // The oracle body walker ABORTS at the index-0 bad format ⇒ NO entries.
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert!(
      walked.is_empty(),
      "a bad format (code 16) at entry 0 aborts the whole directory (no entries), got {walked:?}"
    );

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "bad-format-index0-abort",
    );
  }

  /// Bad-format at a LATER index is a per-entry SKIP (`Exif.pm:6476` `next if
  /// $index`), NOT a directory abort: the surrounding VALID leaves survive on
  /// BOTH paths. Entry 0 valid, entry 1 bad format (code 16), entry 2 valid ⇒ the
  /// oracle and the shared `Walker` both emit the two valid leaves and skip the
  /// bad one.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_bad_format_at_later_index_skips_one_like_shared_walker() {
    let v1 = 0x0102_0304_0506_0708u64.to_le_bytes();
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // INDEX 0 — VALID 0x0102 Quality (int16u, 2 ⇒ "Fine").
      (0x0102, 0x0003, 1, &[0x02, 0x00], &[]),
      // INDEX 1 — BAD format 16 (int64u, nonzero, no Sony carve-out), SKIPPED.
      (0x0114, 16, 1, &[], &v1),
      // INDEX 2 — VALID 0x201b FocusMode (int16u, 0). Single-HASH condition holds
      // for a non-DSC model.
      (0x201b, 0x0003, 1, &[0x00, 0x00], &[]),
    ];
    let blob = crafted_sony_blob(entries);

    // The oracle walks both valid leaves, skips ONLY the bad-format entry.
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert_eq!(
      walked.len(),
      2,
      "the two valid leaves survive; only the bad-format entry is skipped: {walked:?}"
    );
    assert_eq!(walked.get(0).expect("0").tag_id, 0x0102);
    assert_eq!(walked.get(1).expect("1").tag_id, 0x201b);

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "bad-format-later-skip",
    );
  }

  /// A SUSPICIOUS out-of-line offset (`$valuePtr < 8`, into the TIFF header —
  /// `Exif.pm:6539`; OR overlapping the IFD directory — `Exif.pm:6549`) is a
  /// per-entry SKIP (`Exif.pm:6675` "Suspicious offset" + `next`), NOT a decode.
  /// The now-aligned `walk_sony_in_tiff` applies the SAME gate in TIFF-relative
  /// coordinates (the Sony IFD start = `mn_offset + body_offset == 12`); a
  /// following VALID leaf survives on BOTH paths. Built BY HAND so the
  /// out-of-line offset is forced to the suspicious value (the auto-offset
  /// `crafted_sony_blob` cannot point into the header/IFD). Two sub-cases: an
  /// offset of 4 (`< 8`) and an offset overlapping the IFD; each is IN-BOUNDS
  /// (passes the EOF check) so the SKIP is driven by the suspicious gate.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_suspicious_offset_skips_one_like_shared_walker() {
    // 2-entry Sony body (SONY DSC prefix at 0, IFD count word at 12). With 2
    // entries: ifd_start = 12, dir_end = 12 + 2 + 24 = 38. Entry 0 is an
    // out-of-line int32u (size > 4) whose offset is `suspicious_off`; entry 1 is
    // a VALID inline Quality.
    fn build(suspicious_off: u32) -> Vec<u8> {
      let mut blob: Vec<u8> = Vec::new();
      blob.extend_from_slice(b"SONY DSC \x00\x00\x00"); // 12-byte prefix
      blob.extend_from_slice(&2u16.to_le_bytes()); // 2 entries
      // Entry 0 — tag 0x2001, int32u (4), count 2 ⇒ size 8 > 4, OUT-OF-LINE
      // offset = suspicious_off.
      blob.extend_from_slice(&0x2001u16.to_le_bytes());
      blob.extend_from_slice(&0x0004u16.to_le_bytes());
      blob.extend_from_slice(&2u32.to_le_bytes());
      blob.extend_from_slice(&suspicious_off.to_le_bytes());
      // Entry 1 — tag 0x0102 Quality, int16u (3), count 1, INLINE value 2.
      blob.extend_from_slice(&0x0102u16.to_le_bytes());
      blob.extend_from_slice(&0x0003u16.to_le_bytes());
      blob.extend_from_slice(&1u32.to_le_bytes());
      blob.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
      blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
      // Trailing value region so an in-bounds (but suspicious) offset+8 fits.
      blob.extend_from_slice(&[0u8; 16]);
      blob
    }

    // Sub-case 1: offset 4 (`< 8`). Sub-case 2: offset 16 (overlaps IFD [12,38)).
    for (suspicious_off, label) in [(4u32, "off<8"), (16u32, "overlaps-ifd")] {
      let blob = build(suspicious_off);
      let walked =
        makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
      assert_eq!(
        walked.len(),
        1,
        "{label}: the suspicious-offset entry is skipped; only the valid Quality \
         survives, got {walked:?}"
      );
      assert_eq!(
        walked.get(0).expect("0").tag_id,
        0x0102,
        "{label}: the surviving leaf is Quality (the suspicious entry was skipped, \
         not decoded)"
      );
      assert_sony_oracle_matches(
        &blob,
        ByteOrder::Little,
        Some("SONY"),
        Some("ILCE-7M3"),
        label,
      );
    }
  }

  /// The warn-count abort (`Exif.pm:6455-6456` `if ($warnCount > 10) {
  /// Warn('Too many warnings'); return 0 }`). Eleven consecutive bad-format
  /// entries (each `++$warnCount`) push the count to 11; the next entry trips the
  /// abort BEFORE it is processed, so a VALID leaf placed after them emits
  /// NOTHING. The now-aligned `walk_sony_in_tiff` mirrors the same per-entry warn
  /// cap as `sony_makernote_isolated`'s ProcessExif walk. A valid leaf at index 0
  /// (before any warning) emits on BOTH paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_warn_count_abort_after_eleven_warnings_like_shared_walker() {
    // Index 0: VALID 0x0102 Quality (emits). Indices 1..=11: bad nonzero format
    // 0x00ff (each warns + counts; skipped, not index 0). Index 12: a VALID
    // 0x201b FocusMode that must NOT emit (warn_count == 11 > 10 aborts first).
    let mut entries: Vec<(u16, u16, u32, &[u8], &[u8])> = Vec::new();
    entries.push((0x0102, 0x0003, 1, &[0x02, 0x00], &[]));
    for _ in 0..11 {
      entries.push((0x0103, 0x00ff, 1, &[0x00, 0x00, 0x00, 0x00], &[]));
    }
    entries.push((0x201b, 0x0003, 1, &[0x00, 0x00], &[]));
    let blob = crafted_sony_blob(&entries);

    // The oracle walks index 0 (Quality), skips+counts indices 1..=11, then aborts
    // at index 12 BEFORE the FocusMode — so ONLY Quality survives.
    let walked =
      makernotes::vendors::sony::walk_sony_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little);
    assert_eq!(
      walked.len(),
      1,
      "only the pre-warning Quality survives; the >10-warning abort suppresses the \
       trailing FocusMode, got {walked:?}"
    );
    assert_eq!(walked.get(0).expect("0").tag_id, 0x0102);

    assert_sony_oracle_matches(
      &blob,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "warn-count-abort",
    );
  }

  /// Compare `sony_makernote_isolated` to the oracle `sony::parse_in_tiff` at an
  /// ARBITRARY `(mn_offset, mn_len, body_offset)` — the differential the fixed
  /// SHORT-MakerNote guard must hold (`assert_sony_oracle_matches` only covers the
  /// `mn_offset=0`, full-`mn_len`, body-12 case). Both paths must agree on the
  /// emission stream (`-j` AND `-n`) and the typed slot.
  #[cfg(feature = "alloc")]
  fn assert_sony_oracle_matches_at(
    data: &[u8],
    mn_offset: usize,
    mn_len: usize,
    body_offset: usize,
    order: ByteOrder,
    make: Option<&str>,
    model: Option<&str>,
    label: &str,
  ) {
    for print_conv in [true, false] {
      let (oracle_typed, oracle) = makernotes::vendors::sony::parse_in_tiff(
        data,
        mn_offset,
        mn_len,
        body_offset,
        order,
        print_conv,
        model,
      );
      let (iso_emissions, iso_typed) = sony_makernote_isolated(
        data,
        mn_offset,
        mn_len,
        body_offset,
        order,
        make,
        model,
        print_conv,
      )
      .expect("routes_to_main admits a SONY DSC prefix ⇒ Some (present, possibly empty)");
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "{label} print_conv={print_conv}: emission COUNT must match the oracle"
      );
      for (i, want) in oracle.iter().enumerate() {
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "{label} pc={print_conv} #{i}: NAME"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "{label} pc={print_conv} #{i} ({}): VALUE",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "{label} pc={print_conv} #{i} ({}): Unknown",
          want.name()
        );
      }
      assert_eq!(
        iso_typed, oracle_typed,
        "{label} pc={print_conv}: typed MakerNotesSony must equal the oracle's"
      );
    }
  }

  /// Finding 1 (reverse guard): a Sony MakerNote whose DECLARED value is too short
  /// for an IFD (`mn_len < body_offset + 2`) must yield NO Sony tags — EVEN when
  /// the parent-TIFF bytes at `mn_offset + body_offset` happen to form a valid Sony
  /// IFD. The oracle (`walk_sony_in_tiff`'s `mn_len < body_offset + 2` pre-check at
  /// `body.rs:131`) returns empty; before the fix `sony_makernote_isolated` walked
  /// `data` at `mn_offset + body_offset` and read the count word from the UNRELATED
  /// following bytes, emitting a spurious `Quality` (a migration regression vs the
  /// pre-migration `walk_sony_in_tiff`, which returned empty). Both paths must now
  /// be present-but-EMPTY (`Some((empty, empty))` — NOT `None`, since
  /// `routes_to_main` already classified the truncated blob as a Main variant).
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_isolated_short_makernote_yields_empty_like_oracle() {
    // Parent TIFF: the 12-byte `SONY DSC ` prefix, then a FULLY VALID Sony IFD at
    // offset 12 (1 entry: 0x0102 Quality int16u count 1 value 2 ⇒ "Fine") + the
    // next-IFD word. If the guard were absent, walking at offset 12 would decode
    // this IFD and emit Quality.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"SONY DSC \x00\x00\x00"); // 12-byte prefix (offset 0..12)
    data.extend_from_slice(&1u16.to_le_bytes()); // count = 1 (offset 12)
    data.extend_from_slice(&0x0102u16.to_le_bytes()); // tag 0x0102 Quality
    data.extend_from_slice(&0x0003u16.to_le_bytes()); // int16u
    data.extend_from_slice(&1u32.to_le_bytes()); // count 1
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // value 2 inline
    data.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    // Sanity: with the FULL `mn_len` the IFD IS walked (one Quality leaf) — proves
    // the trailing bytes form a real IFD, so the empty result below is the guard,
    // not a coincidental no-decode.
    let full =
      makernotes::vendors::sony::walk_sony_in_tiff(&data, 0, data.len(), 12, ByteOrder::Little);
    assert_eq!(
      full.len(),
      1,
      "with the full mn_len the trailing IFD decodes one Quality leaf: {full:?}"
    );

    // The DECLARED MakerNote value is only 9 bytes (`mn_len = 9 < body_offset + 2
    // == 14`): the blob window `data[0..9]` still starts with `SONY DSC` (so
    // `routes_to_main` admits it as a Main variant), but the value has no room for
    // the IFD count word — both paths return present-but-EMPTY.
    let mn_len_short = 9;
    let oracle =
      makernotes::vendors::sony::walk_sony_in_tiff(&data, 0, mn_len_short, 12, ByteOrder::Little);
    assert!(
      oracle.is_empty(),
      "the oracle's short-MakerNote guard (mn_len < body_offset + 2) returns empty, got {oracle:?}"
    );
    assert_sony_oracle_matches_at(
      &data,
      0,
      mn_len_short,
      12,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "short-makernote-no-ifd-room",
    );
  }

  /// A NORMAL empty Sony IFD (`mn_len >= body_offset + 2`, count word = 0) decodes
  /// to NO entries on BOTH paths — confirming the Finding-1 guard's present-but-
  /// empty return value (`Some((empty, empty))`) is byte-identical to the value the
  /// isolated path produces when a well-formed IFD simply yields zero leaves (so
  /// the differential holds for the truncated case AND a real empty IFD).
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_isolated_empty_ifd_yields_empty_like_oracle() {
    // `SONY DSC ` prefix + a 0-entry IFD + next-IFD word. mn_len = full (>= 14).
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"SONY DSC \x00\x00\x00");
    data.extend_from_slice(&0u16.to_le_bytes()); // count = 0
    data.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    let oracle =
      makernotes::vendors::sony::walk_sony_in_tiff(&data, 0, data.len(), 12, ByteOrder::Little);
    assert!(
      oracle.is_empty(),
      "a 0-entry Sony IFD walks to no entries: {oracle:?}"
    );
    assert_sony_oracle_matches(
      &data,
      ByteOrder::Little,
      Some("SONY"),
      Some("ILCE-7M3"),
      "empty-ifd",
    );
  }

  /// The group OVERRIDE is scoped to the Sony table too: `vendor_group1_of` is
  /// `Some(\"Sony\")` for `Sony` (so a Sony leaf emits as `Sony:*`) — phase 3 of the
  /// engine migration (#243).
  #[test]
  fn vendor_group1_override_includes_sony() {
    assert_eq!(vendor_group1_of(TableRef::Sony), Some("Sony"));
  }

  /// Class sweep (body.rs unchecked integer arithmetic): a `body_offset` near
  /// `usize::MAX` must NOT panic on EITHER Sony path. The oracle's short-MakerNote
  /// guard (`walk_sony_in_tiff`'s `body_offset + 2`) and every per-entry/per-field
  /// offset read now use `checked_add`, mirroring the production guard
  /// (`sony_makernote_isolated`'s `body_offset.checked_add(2)`); an overflow can
  /// never satisfy `mn_len >=`, so BOTH paths return present-but-EMPTY,
  /// byte-identically. Before the sweep, `walk_sony_in_tiff:131`'s `body_offset +
  /// 2` overflowed → a debug-assert panic (release: a wrap that skipped the guard),
  /// contradicting the R2-hardened production path. A plain `#[test]` runs with
  /// debug-assertions ON, so an arithmetic-overflow panic here would FAIL the test
  /// (not silently wrap), pinning the no-panic floor for the public low-level path.
  #[test]
  #[cfg(feature = "alloc")]
  fn sony_body_offset_near_usize_max_no_panic_empty_like_oracle() {
    // A real, fully-valid Sony body at offset 12 (so `routes_to_main` admits the
    // `SONY DSC ` prefix ⇒ `sony_makernote_isolated` returns `Some`, NOT `None`):
    // 1 entry 0x0102 Quality int16u count 1 value 2 + next-IFD word. With a SANE
    // `body_offset` this decodes one leaf — proving the empty results below are the
    // overflow guards, not a degenerate buffer.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"SONY DSC \x00\x00\x00"); // 12-byte prefix
    data.extend_from_slice(&1u16.to_le_bytes()); // count = 1
    data.extend_from_slice(&0x0102u16.to_le_bytes()); // tag 0x0102 Quality
    data.extend_from_slice(&0x0003u16.to_le_bytes()); // int16u
    data.extend_from_slice(&1u32.to_le_bytes()); // count 1
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // value 2 inline
    data.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    // Both adversarial offsets exercise the `body_offset + 2` overflow class:
    // `usize::MAX + 2` wraps, `(usize::MAX - 1) + 2` also wraps (== 0). Either way
    // the checked guard returns empty rather than panicking/wrapping-past the guard.
    for &body_offset in &[usize::MAX, usize::MAX - 1] {
      let oracle = makernotes::vendors::sony::walk_sony_in_tiff(
        &data,
        0,
        data.len(),
        body_offset,
        ByteOrder::Little,
      );
      assert!(
        oracle.is_empty(),
        "walk_sony_in_tiff must return empty (no panic) at body_offset={body_offset}, got {oracle:?}"
      );

      // The production path: `routes_to_main` admits the prefix ⇒ `Some`, and the
      // overflowing `body_offset.checked_add(2)` ⇒ present-but-empty (NOT `None`).
      let (iso_emissions, _typed) = sony_makernote_isolated(
        &data,
        0,
        data.len(),
        body_offset,
        ByteOrder::Little,
        Some("SONY"),
        Some("ILCE-7M3"),
        true,
      )
      .expect("SONY DSC prefix ⇒ routes_to_main ⇒ Some even when body_offset overflows");
      assert!(
        iso_emissions.is_empty(),
        "sony_makernote_isolated must emit nothing (no panic) at body_offset={body_offset}"
      );

      // And the two paths are byte-identical (emission stream + typed slot, -j AND
      // -n) at the overflow offset — the differential the class sweep preserves.
      assert_sony_oracle_matches_at(
        &data,
        0,
        data.len(),
        body_offset,
        ByteOrder::Little,
        Some("SONY"),
        Some("ILCE-7M3"),
        "body_offset-near-usize-max",
      );
    }
  }

  // ====================================================================// Panasonic engine migration — differential test (#243 phase 3)
  //
  // PROVES the shared `Walker`'s Panasonic Main leaf path (`process_subdir` under
  // `TableRef::Panasonic` → the dedicated `emit_panasonic_value` capture, via
  // `panasonic_makernote_isolated`) is BYTE-IDENTICAL to the production oracle
  // `panasonic::parse_in_tiff` (`walk_panasonic_in_tiff` + the per-entry gates).
  // The same crafted Panasonic Main blob is run through BOTH paths; the emitted
  // `(name, value, group="MakerNotes:Panasonic", unknown)` tuples must match, in
  // order, for `-j` (PrintConv) AND `-n` (ValueConv), and the typed
  // `MakerNotesPanasonic` must agree. Two blobs are exercised:
  //
  // - The DYNAMIC-BASE blob (`base_offset = 12`, `MakerNotePanasonic3` DC-FT7):
  //   an OUT-OF-LINE 0x51 LensType string PROVES the `value_offset_base` thread —
  //   it resolves at `off + 12`; a base-0 walk would read 12 bytes early.
  // - The gate blob (`base_offset = 0`, inherit `MakerNotePanasonic`): every
  //   per-entry gate — a deferred SubDirectory (0x4e), a `$format`-gated single-
  //   HASH LensType PASS (0xc4) + SUPPRESS (0xe4 non-int16u), a 0xc5 LensTypeModel
  //   byte-swap, a 0x86 ManometerPressure RawConv sentinel drop (65535), the
  //   model-conditional 0x0f AFAreaMode + 0x2c ContrastMode branches, and a plain
  //   typed leaf (0x01 ImageQuality).
  //
  // A routes-AWAY blob ("MKE" Type2) returns `None`.
  // ====================================================================

  /// Build a crafted little-endian Panasonic Main blob: the 12-byte
  /// `Panasonic\0\0\0` prefix (the `MakerNotePanasonic`/`Panasonic3` header, so
  /// `routes_to_main` passes), then the body's entry count + the 12-byte IFD
  /// entries, then the next-IFD word, then any out-of-line value bytes. `entries`
  /// is `(tag, format, count, inline_or_empty, out_of_line_or_empty)`: INLINE when
  /// `out_of_line` is empty (value zero-padded to 4 bytes at `entry+8`), else
  /// OUT-OF-LINE (the 4 bytes at `entry+8` are the stored offset).
  ///
  /// `base_offset` is the SubDirectory `Base =>` literal: the walker (both the
  /// oracle and the isolated path) resolves an out-of-line value at `stored +
  /// base_offset`, so the STORED offset is `real_pos - base_offset` (for
  /// `base_offset = 12` the DC-FT7 stores its offsets 12 LESS than the real buffer
  /// position; `base_offset = 0` stores the real position). Out-of-line values sit
  /// AFTER the next-IFD word (so the resolved `stored + base_offset` is past the
  /// IFD ⇒ never trips the shared Walker's suspect-offset/IFD-overlap check, which
  /// the simpler oracle omits — keeping the two byte-identical).
  ///
  /// Entries must be written in ASCENDING tag-id order (real cameras write sorted
  /// Panasonic IFDs).
  #[cfg(feature = "alloc")]
  fn crafted_panasonic_blob(
    entries: &[(u16, u16, u32, &[u8], &[u8])],
    base_offset: usize,
  ) -> Vec<u8> {
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let dir_bytes = 2 + 12 * entries.len(); // count + entries
    // The first out-of-line value's REAL buffer position (12-byte prefix + dir +
    // next-IFD word); the STORED offset is this minus `base_offset`.
    let mut real_cursor = 12 + dir_bytes + 4;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00"); // 12-byte prefix
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if out_of_line.is_empty() {
        let elem = elem_sizes[format as usize];
        assert!(
          elem * count as usize <= 4,
          "inline value must fit in 4 bytes"
        );
        let mut slot = [0u8; 4];
        slot[..inline.len().min(4)].copy_from_slice(&inline[..inline.len().min(4)]);
        blob.extend_from_slice(&slot);
      } else {
        // STORED = real - base_offset, so the walker's `stored + base_offset`
        // resolves to the real buffer position.
        let stored = (real_cursor - base_offset) as u32;
        blob.extend_from_slice(&stored.to_le_bytes());
        value_blob.extend_from_slice(out_of_line);
        real_cursor += out_of_line.len();
      }
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    blob.extend_from_slice(&value_blob);
    blob
  }

  /// Drive the shared `Walker` through the SAME walk `panasonic_makernote_isolated`
  /// uses (`mn_offset = 0`, body at 12, `value_offset_base = base_offset`, parent
  /// order, `TableRef::Panasonic`, `ProcessProc::Exif`), then render every
  /// collected entry through the dedicated `emit_panasonic_value` into an
  /// `EmittedTagSink` — the NEW path's output WITH the full `MakerNotes:Panasonic`
  /// group (which the `VendorEmission` stream alone does not carry).
  #[cfg(feature = "alloc")]
  fn drive_panasonic_subdir(
    blob: &[u8],
    base_offset: usize,
    order: ByteOrder,
    model: Option<&str>,
    print_conv: bool,
  ) -> Vec<crate::emit::EmittedTag> {
    let mut w = test_walker(blob);
    w.order = order;
    // The DYNAMIC BASE — the same addend the production isolated walk threads.
    w.value_offset_base = base_offset;
    w.process_subdir(
      12, // body offset for the Panasonic\0\0\0 prefix
      IfdKind::ExifIfd,
      TableRef::Panasonic,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Exif,
    );
    let g1 = vendor_group1_of(TableRef::Panasonic).unwrap_or("Panasonic");
    let mut out: Vec<crate::emit::EmittedTag> = Vec::new();
    let mut sink = EmittedTagSink::new(&mut out);
    for entry in &w.entries {
      if let ResolvedConv::Panasonic(panasonic_tag) = entry.conv {
        let Ok(()) =
          emit_panasonic_value(g1, entry, panasonic_tag, model, print_conv, None, &mut sink);
      }
    }
    out
  }

  /// Assert the THREE Panasonic paths agree for one crafted blob + base_offset:
  /// the oracle `parse_in_tiff`, the gated `panasonic_makernote_isolated`
  /// (`VendorEmission` stream + typed), and `drive_panasonic_subdir` (the
  /// `EmittedTag` stream carrying the full `MakerNotes:Panasonic` group). Returns
  /// the oracle emissions so the caller can pin survivor names/values.
  #[cfg(feature = "alloc")]
  fn assert_panasonic_paths_agree(
    blob: &[u8],
    base_offset: usize,
    order: ByteOrder,
    model: Option<&str>,
    print_conv: bool,
  ) -> Vec<makernotes::VendorEmission> {
    // Oracle: production `parse_in_tiff` (returns `(typed, emissions)`), body at
    // 12, the SAME base_offset.
    let (oracle_typed, oracle) = makernotes::vendors::panasonic::parse_in_tiff(
      blob,
      0,
      blob.len(),
      makernotes::vendors::panasonic::HEADER_LEN,
      order,
      print_conv,
      model,
      base_offset,
    );
    // New path A: the gated isolated helper the production dispatch drives.
    let (iso_emissions, iso_typed) =
      panasonic_makernote_isolated(blob, 0, blob.len(), base_offset, order, model, print_conv)
        .expect("Panasonic prefix ⇒ routes_to_main ⇒ Some");
    // New path B: the same walk emitted into an `EmittedTagSink` so the full
    // `MakerNotes:Panasonic` group is asserted.
    let emitted = drive_panasonic_subdir(blob, base_offset, order, model, print_conv);

    assert_eq!(
      iso_emissions.len(),
      oracle.len(),
      "pc={print_conv} base={base_offset}: isolated emission COUNT must match the oracle"
    );
    assert_eq!(
      emitted.len(),
      oracle.len(),
      "pc={print_conv} base={base_offset}: EmittedTag COUNT must match the oracle"
    );
    for (i, want) in oracle.iter().enumerate() {
      let got = iso_emissions.get(i).expect("index in range");
      assert_eq!(
        got.name(),
        want.name(),
        "pc={print_conv} base={base_offset} leaf #{i}: VendorEmission NAME mismatch"
      );
      assert_eq!(
        got.value(),
        want.value(),
        "pc={print_conv} base={base_offset} leaf #{i} ({}): VendorEmission VALUE mismatch \
         (the new path must apply PanasonicPrintConv + gates exactly as the oracle)",
        want.name()
      );
      assert_eq!(
        got.unknown(),
        want.unknown(),
        "pc={print_conv} base={base_offset} leaf #{i} ({}): VendorEmission Unknown flag mismatch",
        want.name()
      );
      let tag = emitted.get(i).expect("index in range").tag();
      assert_eq!(
        tag.name(),
        want.name(),
        "pc={print_conv} base={base_offset} leaf #{i}: EmittedTag NAME mismatch"
      );
      assert_eq!(
        tag.value_ref(),
        want.value(),
        "pc={print_conv} base={base_offset} leaf #{i} ({}): EmittedTag VALUE mismatch",
        want.name()
      );
      assert_eq!(
        tag.group_ref().family0(),
        "MakerNotes",
        "pc={print_conv} base={base_offset} leaf #{i} ({}): family-0 must be MakerNotes",
        want.name()
      );
      assert_eq!(
        tag.group_ref().family1(),
        "Panasonic",
        "pc={print_conv} base={base_offset} leaf #{i} ({}): family-1 must be Panasonic",
        want.name()
      );
    }
    assert_eq!(
      iso_typed, oracle_typed,
      "pc={print_conv} base={base_offset}: the isolated typed MakerNotesPanasonic must equal the oracle's"
    );
    oracle
  }

  /// The Panasonic leaf-path differential proof. For BOTH `-j` and `-n`, the shared
  /// `Walker` Panasonic leaf path emits the EXACT same `(name, value,
  /// group="MakerNotes:Panasonic", unknown)` stream — in order — as
  /// `panasonic::parse_in_tiff`, AND the typed `MakerNotesPanasonic` agrees. Two
  /// blobs: the gate blob (base 0) and the dynamic-base blob (base 12).
  #[test]
  #[cfg(feature = "alloc")]
  fn panasonic_isolated_emit_matches_parse_in_tiff() {
    let order = ByteOrder::Little;
    // Model "DMC-FZ10": 0x0f selects the FZ10 AFAreaMode branch; 0x2c selects the
    // PrintHex ContrastMode branch (FZ10 ∉ the GF/G2/TZ10/ZS7/FX10/G1/L1/L10/LC80
    // excluded set and is not a `DC-` body) — both deterministic.
    let model = Some("DMC-FZ10");

    // ---- Gate blob (base 0, inherit `MakerNotePanasonic`). ASCENDING tag order.
    // int16u=3, int8u=1, undef=7, string=2.
    let gate_entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x01 ImageQuality — plain typed leaf. int16u 2 ⇒ "High"; typed.* via 0x01
      // is not a typed field, but it proves the plain leaf path.
      (0x01, 0x03, 1, &[0x02, 0x00], &[]),
      // 0x0f AFAreaMode — model-conditional (FZ10 branch). int8u[2] = [0,16].
      (0x0f, 0x01, 2, &[0x00, 0x10], &[]),
      // 0x2c ContrastMode — model-conditional (PrintHex branch). int16u 0.
      (0x2c, 0x03, 1, &[0x00, 0x00], &[]),
      // 0x4e FaceDetInfo — a DEFERRED SubDirectory row (`sub_table=Some`). Valid
      // out-of-line int8u blob; the parent must be SUPPRESSED (no emission).
      (0x4e, 0x01, 8, &[], &[1, 2, 3, 4, 5, 6, 7, 8]),
      // 0x86 ManometerPressure — RawConv sentinel: int16u 65535 ⇒ DROPPED.
      (0x86, 0x03, 1, &[0xff, 0xff], &[]),
      // 0xc4 LensTypeMake — single-HASH `Condition` HOLDS (int16u, != 0xffff).
      // int16u 5 ⇒ raw passthrough (conv None). Proves a single-HASH PASS.
      (0xc4, 0x03, 1, &[0x05, 0x00], &[]),
      // 0xc5 LensTypeModel — single-HASH HOLDS (int16u); 0x1234 ⇒ byte-swap
      // "34 12". Proves the 0xc5 LensTypeModel special emit path.
      (0xc5, 0x03, 1, &[0x34, 0x12], &[]),
      // 0xe4 LensTypeModel — single-HASH FAILS (on-disk `string`, not int16u) ⇒
      // SUPPRESSED. (string[4] inline.) Proves a single-HASH SUPPRESS.
      (0xe4, 0x02, 4, b"abcd", &[]),
    ];
    let gate_blob = crafted_panasonic_blob(gate_entries, 0);

    for print_conv in [true, false] {
      let oracle = assert_panasonic_paths_agree(&gate_blob, 0, order, model, print_conv);
      // Survivors: 0x01, 0x0f, 0x2c, 0xc4, 0xc5 (0x4e/0x86/0xe4 suppressed).
      let names: Vec<&str> = oracle.iter().map(|e| e.name()).collect();
      assert_eq!(
        names,
        std::vec![
          "ImageQuality",
          "AFAreaMode",
          "ContrastMode",
          "LensTypeMake",
          "LensTypeModel"
        ],
        "pc={print_conv}: gate-blob survivor names + order (0x4e/0x86/0xe4 suppressed)"
      );
      // 0xc5 byte-swap is PrintConv-independent ⇒ "34 12" in both modes.
      let lens = oracle
        .iter()
        .find(|e| e.name() == "LensTypeModel")
        .expect("0xc5 survives");
      assert_eq!(
        lens.value(),
        &crate::value::TagValue::Str("34 12".into()),
        "pc={print_conv}: 0xc5 LensTypeModel byte-swap 0x1234 ⇒ \"34 12\""
      );
    }

    // ---- Dynamic-base blob (base 12, `MakerNotePanasonic3` DC-FT7). The 0x51
    // LensType is OUT-OF-LINE: it resolves at `stored + 12`. PROVES the dynamic
    // base — a base-0 walk reads 12 bytes early and does NOT recover the string.
    let lens_str = b"LUMIX-G\x00"; // 8 bytes (> 4 ⇒ out-of-line)
    let base12_entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x01 ImageQuality — a plain inline leaf to anchor the IFD.
      (0x01, 0x03, 1, &[0x02, 0x00], &[]),
      // 0x51 LensType — OUT-OF-LINE string. typed.lens_type = "LUMIX-G".
      (0x51, 0x02, lens_str.len() as u32, &[], lens_str),
    ];
    let base12_blob = crafted_panasonic_blob(base12_entries, 12);

    for print_conv in [true, false] {
      let oracle = assert_panasonic_paths_agree(&base12_blob, 12, order, model, print_conv);
      let names: Vec<&str> = oracle.iter().map(|e| e.name()).collect();
      assert_eq!(
        names,
        std::vec!["ImageQuality", "LensType"],
        "pc={print_conv}: base-12 survivor names"
      );
      // The dynamic base RESOLVED the out-of-line string at off+12.
      let (_, typed) = panasonic_makernote_isolated(
        &base12_blob,
        0,
        base12_blob.len(),
        12,
        order,
        model,
        print_conv,
      )
      .expect("routes_to_main");
      assert_eq!(
        typed.lens_type(),
        Some("LUMIX-G"),
        "pc={print_conv}: base-12 out-of-line 0x51 LensType resolves at off+12 ⇒ \"LUMIX-G\""
      );
    }

    // NEGATIVE oracle for the dynamic base: a base-0 walk of the SAME blob reads
    // the 0x51 out-of-line offset 12 bytes early ⇒ it does NOT recover "LUMIX-G"
    // (the +12 thread is load-bearing).
    let (_, typed_base0) =
      panasonic_makernote_isolated(&base12_blob, 0, base12_blob.len(), 0, order, model, true)
        .expect("routes_to_main");
    assert_ne!(
      typed_base0.lens_type(),
      Some("LUMIX-G"),
      "base_offset=0 must NOT recover the DC-FT7 out-of-line string (reads 12 bytes early)"
    );
  }

  /// A `Vendor::Panasonic` blob that routes AWAY from `%Panasonic::Main` (the
  /// `MKE` Type2 `ProcessBinaryData` blob, unported) must yield `None` from
  /// `panasonic_makernote_isolated` — the variant gate (`routes_to_main`) keeps the
  /// Panasonic slot ABSENT rather than decoding a spurious Main tag on a tag-id
  /// collision.
  #[test]
  #[cfg(feature = "alloc")]
  fn panasonic_isolated_routes_away_blob_is_none() {
    // An "MKE" Type2 body — enough bytes that the blob window is non-empty; the
    // gate rejects on the `Panasonic`-prefix miss alone (no Main walk runs).
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"MKED"); // Type2 "MKE" prefix
    blob.extend_from_slice(&[0u8; 24]); // arbitrary trailing bytes
    for print_conv in [true, false] {
      for base_offset in [0usize, 12] {
        let out = panasonic_makernote_isolated(
          &blob,
          0,
          blob.len(),
          base_offset,
          ByteOrder::Little,
          Some("DC-FT7"),
          print_conv,
        );
        assert!(
          out.is_none(),
          "pc={print_conv} base={base_offset}: an MKE (Type2) blob routes away from \
           %Panasonic::Main ⇒ panasonic_makernote_isolated must return None"
        );
      }
    }
  }

  /// Build a crafted little-endian `Panasonic\0\0\0`-prefixed Main blob with FULL
  /// control over each entry's `(tag, format_code, count, value-slot)` and the
  /// out-of-line payload — the edge-case builder for the ProcessExif-classification
  /// differential proofs (bad format codes, oversized counts, hand-placed
  /// out-of-line offsets) that `crafted_panasonic_blob` cannot express (it asserts
  /// inline-fit + only knows the 13 standard format sizes). Each entry's 4-byte
  /// value slot is written VERBATIM (an inline value, or a stored out-of-line
  /// offset). Trailing `payload` bytes are appended after the next-IFD word.
  #[cfg(feature = "alloc")]
  fn crafted_panasonic_raw(entries: &[(u16, u16, u32, [u8; 4])], payload: &[u8]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00"); // 12-byte prefix
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for &(tag, format, count, slot) in entries {
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      blob.extend_from_slice(&slot);
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    blob.extend_from_slice(payload);
    blob
  }

  /// Crafted-edge differential proof: for a range of hostile/degenerate Panasonic
  /// Main IFDs the oracle (`parse_in_tiff` → `walk_panasonic_in_tiff`) and the
  /// production shared-`Walker` path (`panasonic_makernote_isolated`) emit the
  /// BYTE-IDENTICAL `(name, value, unknown)` stream + typed surface, in BOTH `-j`
  /// and `-n`. Each case targets one ProcessExif-classification rule
  /// `walk_panasonic_in_tiff` mirrors: count-based size, `undef[1]`→int8u,
  /// excessive-count skip, bad-format index-0-abort-vs-later-skip, suspicious
  /// offset, the warn-count>10 abort, the short-MakerNote present-but-empty guard,
  /// and `usize::MAX` offset-overflow safety.
  #[test]
  #[cfg(feature = "alloc")]
  fn panasonic_isolated_matches_oracle_crafted_edges() {
    let order = ByteOrder::Little;
    let model = Some("DMC-FZ10");

    // ---- count = 0 (empty value, Exif.pm:6285) + undef[1]→int8u (Exif.pm:6644).
    // 0x01 ImageQuality int16u count 0 ⇒ empty value; 0x0f AFAreaMode undef[1] ⇒
    // decoded as int8u (the model-conditional 0x0f leaf renders the FZ10 branch).
    let count0_undef1 = crafted_panasonic_raw(
      &[
        (0x01, 0x03, 0, [0x00, 0x00, 0x00, 0x00]), // int16u, count 0 — empty
        (0x0f, 0x07, 1, [0x10, 0x00, 0x00, 0x00]), // undef[1] = 0x10 ⇒ int8u
      ],
      &[],
    );
    for print_conv in [true, false] {
      assert_panasonic_paths_agree(&count0_undef1, 0, order, model, print_conv);
    }

    // ---- excessive count > 100000 (Exif.pm:6760) ⇒ the entry is SKIPPED by the
    // post-override guard (a), which fires AFTER the out-of-line bounds check — so
    // the value must be IN BOUNDS to actually reach the guard (an out-of-bounds
    // excessive value would be caught earlier as a "Bad offset"). Build a payload
    // large enough that the count-100001 int16u value (200002 bytes) fits: stored
    // offset points just past the next-IFD word. A known anchor (0x01) survives;
    // the excessive 0x1f ShootingMode int16u is dropped by BOTH paths.
    {
      // header(12) + count(2) + 2*entry(24) + next-IFD(4) = 42 ⇒ payload at 42.
      let value_off = 12 + 2 + 24 + 4;
      let big_count = 100_001u32;
      let payload = std::vec![0u8; (big_count as usize) * 2];
      let excessive = crafted_panasonic_raw(
        &[
          (0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00]), // ImageQuality int16u 2
          (
            0x1f,
            0x03,
            big_count,
            (value_off as u32).to_le_bytes(), // in-bounds out-of-line offset
          ),
        ],
        &payload,
      );
      for print_conv in [true, false] {
        let oracle = assert_panasonic_paths_agree(&excessive, 0, order, model, print_conv);
        assert!(
          oracle.iter().all(|e| e.name() != "ShootingMode"),
          "pc={print_conv}: an excessive-count (>100000) 0x1f entry must be skipped"
        );
      }
    }

    // ---- bad format code at a LATER index (index != 0) ⇒ SKIP that one entry,
    // continue the IFD (Exif.pm:6476). Code 99 is unrecognized (not 1..=13/129);
    // code 16 (int64u, BigTIFF) is ALSO bad here (no Apple/Make carve-out for
    // Panasonic). Both follow a valid index-0 entry, so the IFD is NOT aborted.
    let bad_format_later = crafted_panasonic_raw(
      &[
        (0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00]), // valid index 0 — survives
        (0x1a, 0x63, 1, [0x00, 0x00, 0x00, 0x00]), // code 99 ⇒ skip this one
        (0x32, 0x10, 1, [0x00, 0x00, 0x00, 0x00]), // code 16 ⇒ skip this one
        (0x2c, 0x03, 1, [0x00, 0x00, 0x00, 0x00]), // valid ContrastMode — survives
      ],
      &[],
    );
    for print_conv in [true, false] {
      assert_panasonic_paths_agree(&bad_format_later, 0, order, model, print_conv);
    }

    // ---- bad format code at INDEX 0 ⇒ ABORT the whole directory (Exif.pm:6475,
    // "assume corrupted IFD if this is our first entry") ⇒ NO entries, even though
    // a perfectly valid 0x01 follows. Both paths must yield EMPTY.
    let bad_format_index0 = crafted_panasonic_raw(
      &[
        (0x1a, 0x63, 1, [0x00, 0x00, 0x00, 0x00]), // code 99 at index 0 ⇒ abort
        (0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00]), // valid — but never reached
      ],
      &[],
    );
    for print_conv in [true, false] {
      let oracle = assert_panasonic_paths_agree(&bad_format_index0, 0, order, model, print_conv);
      assert!(
        oracle.is_empty(),
        "pc={print_conv}: a bad format at index 0 aborts the whole Panasonic IFD"
      );
    }

    // ---- suspicious offset (Exif.pm:6549): an out-of-line value whose resolved
    // pointer OVERLAPS the IFD directory ⇒ "Suspicious offset" SKIP. 0x51 LensType
    // string count 8 (>4 ⇒ out-of-line), stored offset = 14 (lands inside the IFD
    // `[ifd_start=12 .. dir_end=12+2+12=26)`). Both paths must SKIP it; the 0x01
    // anchor survives.
    let suspicious = crafted_panasonic_raw(
      &[
        (0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00]), // ImageQuality — survives
        (0x51, 0x02, 8, [14, 0x00, 0x00, 0x00]),   // out-of-line off 14 ⇒ overlaps IFD
      ],
      b"ABCDEFG\x00",
    );
    for print_conv in [true, false] {
      let oracle = assert_panasonic_paths_agree(&suspicious, 0, order, model, print_conv);
      assert!(
        oracle.iter().all(|e| e.name() != "LensType"),
        "pc={print_conv}: a suspicious (IFD-overlapping) 0x51 offset must be skipped"
      );
    }

    // ---- warn-count > 10 abort (Exif.pm:6455): more than ten counted per-entry
    // warnings (here: bad format codes at indices 1..=12, after a valid index 0)
    // ABORT the directory before the remaining entries. The entry that pushes the
    // count to 11 is fully processed; the NEXT one trips the abort — so a valid
    // 0x2c placed AFTER the 12 bad entries must NOT survive. Both paths agree.
    let mut warn_entries: Vec<(u16, u16, u32, [u8; 4])> = Vec::new();
    warn_entries.push((0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00])); // valid index 0
    for k in 0..12u16 {
      // bad format code 99 at indices 1..=12 — each bumps warn_count.
      warn_entries.push((0x1a00 + k, 0x63, 1, [0x00, 0x00, 0x00, 0x00]));
    }
    warn_entries.push((0x2c, 0x03, 1, [0x00, 0x00, 0x00, 0x00])); // valid — past the abort
    let warn_blob = crafted_panasonic_raw(&warn_entries, &[]);
    for print_conv in [true, false] {
      let oracle = assert_panasonic_paths_agree(&warn_blob, 0, order, model, print_conv);
      assert!(
        oracle.iter().all(|e| e.name() != "ContrastMode"),
        "pc={print_conv}: the >10-warn-count abort must drop the post-abort 0x2c entry"
      );
    }

    // ---- the short-MakerNote guard. A MakerNote whose DECLARED value
    // length cannot hold the IFD count word past the 12-byte header (`mn_len <
    // HEADER_LEN + 2`) is present-but-EMPTY: the oracle returns no entries and the
    // isolated helper returns `Some((empty, empty))` (NOT None — the slot stays).
    // Build a 13-byte blob (`Panasonic\0\0\0` + 1 byte) and pass mn_len = 13.
    {
      let mut short = b"Panasonic\x00\x00\x00".to_vec();
      short.push(0x01);
      assert_eq!(short.len(), 13);
      for print_conv in [true, false] {
        let (oracle_typed, oracle) = makernotes::vendors::panasonic::parse_in_tiff(
          &short,
          0,
          short.len(),
          makernotes::vendors::panasonic::HEADER_LEN,
          order,
          print_conv,
          model,
          0,
        );
        let (iso, iso_typed) =
          panasonic_makernote_isolated(&short, 0, short.len(), 0, order, model, print_conv)
            .expect("routes_to_main ⇒ Some (present-but-empty), NOT None");
        assert!(
          oracle.is_empty() && iso.is_empty(),
          "pc={print_conv}: short MakerNote (mn_len < 14) ⇒ both paths empty"
        );
        assert_eq!(
          iso_typed, oracle_typed,
          "pc={print_conv}: short MakerNote ⇒ both typed surfaces equal (empty)"
        );
      }
    }

    // ---- `body_offset`/offset overflow (`usize::MAX`) — NO panic, both
    // paths empty. Pass mn_offset = usize::MAX so `mn_offset + HEADER_LEN`
    // saturates / `mn_offset + mn_len` overflows: the oracle's `checked_add`
    // guards and the isolated `saturating_add` ifd-offset both yield an empty walk
    // without panicking. Use a real `Panasonic`-prefixed blob (so the gate would
    // pass if reached) but an out-of-range offset.
    {
      let blob = crafted_panasonic_raw(&[(0x01, 0x03, 1, [0x02, 0x00, 0x00, 0x00])], &[]);
      for print_conv in [true, false] {
        // The oracle with a `usize::MAX` body offset: the short-MakerNote /
        // checked-add framing returns empty without panic.
        let (_oracle_typed, oracle) = makernotes::vendors::panasonic::parse_in_tiff(
          &blob,
          0,
          blob.len(),
          usize::MAX,
          order,
          print_conv,
          model,
          0,
        );
        assert!(
          oracle.is_empty(),
          "pc={print_conv}: oracle with body_offset = usize::MAX ⇒ empty, no panic"
        );
        // The isolated helper with mn_offset = usize::MAX: the blob window is
        // clamped empty (`mn_offset.saturating_add(mn_len).min(len)` ⇒ a `get(MAX..)`
        // ⇒ None) ⇒ `?` short-circuits to None. No panic.
        let iso =
          panasonic_makernote_isolated(&blob, usize::MAX, blob.len(), 0, order, model, print_conv);
        assert!(
          iso.is_none(),
          "pc={print_conv}: isolated with mn_offset = usize::MAX ⇒ None (empty window), no panic"
        );
      }
    }
  }

  /// The group OVERRIDE is scoped to the Panasonic table too: `vendor_group1_of` is
  /// `Some(\"Panasonic\")` for `Panasonic` (so a Panasonic leaf emits as
  /// `Panasonic:*`) — phase 3 of the engine migration (#243).
  #[test]
  fn vendor_group1_override_includes_panasonic() {
    assert_eq!(vendor_group1_of(TableRef::Panasonic), Some("Panasonic"));
  }

  // ====================================================================// Nikon engine migration — smoke differential test (#243 phase 3-bis)
  //
  // PROVES the shared `Walker`'s Nikon Main path (`nikon_makernote_isolated` —
  // `resolve_layout` + the prescan + `process_subdir` under `TableRef::Nikon` →
  // the `emit_nikon_value` leaf + the five sub-table emitters) is BYTE-IDENTICAL
  // to the production oracle `nikon::parse_in_tiff` (`walk_nikon_ifd` + the same
  // emit). The full edge-matrix (every gate × all three layouts) is N3; this smoke
  // test proves the PATH works on a crafted type-3 blob with leaves + ONE ENCRYPTED
  // sub-table, exercising the 2-pass prescan-before-decrypt ordering (0x00a7 LAST).
  // The same blob is run through BOTH paths; the emitted `(name, value,
  // group="MakerNotes:Nikon", unknown)` tuples must match, in order, for `-j`
  // (PrintConv) AND `-n` (ValueConv), and the typed `MakerNotesNikon` must agree.
  // ====================================================================

  /// Build a crafted big-endian type-3 Nikon blob (`"Nikon\0\x02\x10\0\0"` + an
  /// embedded `MM\0\x2a` TIFF with IFD0-offset 8 ⇒ the Main IFD at blob 18). Mirrors
  /// the `type3_blob_one_entry` helper in `nikon/body.rs` but takes MANY entries +
  /// trailing out-of-line value bytes. `entries` is `(tag, format, count,
  /// inline_or_empty, out_of_line_or_empty)`: INLINE when `out_of_line` is empty
  /// (the value is zero-padded to 4 bytes at `entry+8`), else OUT-OF-LINE (the 4
  /// bytes at `entry+8` are the EMBEDDED-TIFF-relative offset — type-3's
  /// `Base => '$start - 8'` makes out-of-line offsets relative to blob offset 10).
  /// Entries must be in ASCENDING tag-id order (real Nikon IFDs are sorted).
  #[cfg(feature = "alloc")]
  fn crafted_nikon_type3_blob(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    // Blob layout: [Nikon\0\x02\x10\0\0 (10)][MM\0\x2a + IFD0-off=8 (8)][IFD: count
    // u16 + 12-byte entries][next-IFD u32][out-of-line values]. The Main IFD sits at
    // blob 18 (= tiff_at 10 + 8). The first out-of-line value follows the next-IFD
    // word; its stored offset is EMBEDDED-relative (absolute blob offset − 10).
    let dir_bytes = 2 + 12 * entries.len();
    let values_at = 18 + dir_bytes + 4; // blob offset of the first out-of-line value
    let mut value_cursor = values_at;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    blob.extend_from_slice(b"MM"); // big-endian marker
    blob.extend_from_slice(&[0x00, 0x2a]); // 0x002a magic
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded-offset 8 ⇒ blob 18
    blob.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      blob.extend_from_slice(&tag.to_be_bytes());
      blob.extend_from_slice(&format.to_be_bytes());
      blob.extend_from_slice(&count.to_be_bytes());
      if out_of_line.is_empty() {
        let mut slot = [0u8; 4];
        let n = inline.len().min(4);
        slot[..n].copy_from_slice(&inline[..n]);
        blob.extend_from_slice(&slot);
      } else {
        // EMBEDDED-relative offset (the value_base-10 rebase): absolute − 10.
        blob.extend_from_slice(&((value_cursor - 10) as u32).to_be_bytes());
        value_blob.extend_from_slice(out_of_line);
        value_cursor += out_of_line.len();
      }
    }
    blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
    blob.extend_from_slice(&value_blob);
    blob
  }

  /// Drive the shared `Walker` through `nikon_makernote_isolated`'s LEAF emit path
  /// into an `EmittedTagSink` — proving the full `MakerNotes:Nikon` group override
  /// (which the `VendorEmission` stream alone does not carry). Mirrors the
  /// production isolated walk (type-3: blob slice, value_base 10, `TableRef::Nikon`,
  /// `ProcessProc::Exif`); only the LEAF entries are routed here (the sub-table
  /// emitters push `VendorEmission` directly + apply the group at
  /// `push_maker_note_tags` time identically for both paths, so the path-A
  /// `VendorEmission` equality covers them).
  #[cfg(feature = "alloc")]
  fn drive_nikon_type3_leaves(
    blob: &[u8],
    model: Option<&str>,
    print_conv: bool,
  ) -> Vec<crate::emit::EmittedTag> {
    let order = ByteOrder::Big;
    let mut w = test_walker(blob);
    w.order = order;
    w.value_offset_base = 10; // type-3 `Base => '$start - 8'` ⇒ blob offset 10
    w.process_subdir(
      18, // the Main IFD at blob 18 (tiff_at 10 + 8)
      IfdKind::ExifIfd,
      TableRef::Nikon,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Exif,
    );
    let g1 = vendor_group1_of(TableRef::Nikon).unwrap_or("Nikon");
    let mut out: Vec<crate::emit::EmittedTag> = Vec::new();
    let mut sink = EmittedTagSink::new(&mut out);
    for entry in &w.entries {
      if let ResolvedConv::Nikon(nikon_tag) = entry.conv
        && nikon_tag.sub_table().is_none()
      {
        let Ok(()) = emit_nikon_value(
          g1, entry, nikon_tag, model, order, print_conv, None, &mut sink,
        );
      }
    }
    out
  }

  /// The Nikon smoke differential proof: for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), `nikon_makernote_isolated` emits the EXACT same `(name, value,
  /// group="MakerNotes:Nikon", unknown)` stream — in order — as `nikon::parse_in_tiff`,
  /// AND the typed `MakerNotesNikon` agrees. The crafted type-3 blob carries two
  /// plain leaves (Quality 0x0004, LensType 0x0083) + a positional FocusMode (0x0007)
  /// + the decrypt keys (SerialNumber 0x001d) + ONE ENCRYPTED sub-table (LensData
  /// 0x0098, version `0201`) + the count key (ShutterCount 0x00a7) placed LAST in
  /// IFD order — so the in-walk 0x0098 decode would NOT yet have the count, proving
  /// the 2-pass prescan-before-decrypt (the prescan captures 0x00a7 ahead of the
  /// emit walk). The LensData sub-table emits its decrypted `%LensData01` members
  /// identically through both paths (same prescan keys, same cipher).
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_isolated_emit_matches_parse_in_tiff() {
    let order = ByteOrder::Big;
    let model = Some("NIKON D7000"); // AFInfo BigEndian gate (irrelevant here); a `D` DSLR
    // 16 bytes of (arbitrary) encrypted LensData payload after the `0201` version —
    // enough for `%LensData01`'s members (max read offset 0x12). The bytes are
    // decrypted by BOTH paths with the SAME prescan keys, so they agree.
    let lens_payload: &[u8] =
      b"0201\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
    // ASCENDING tag-id order. string=2, undef=7, int32u=9, int8u=1.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x0004 Quality — string[4] "FINE" inline ⇒ "Fine" (title-cased). Typed leaf.
      (0x0004, 0x0002, 4, b"FINE", &[]),
      // 0x0007 FocusMode — string[4] "AF-C" inline. The positional `$$self{FocusMode}`
      // RawConv DataMember (gates LensData0800 Z; here LensData is 0201, so it is
      // tracked but unused). Typed leaf ⇒ "Af-C".
      (0x0007, 0x0002, 4, b"AF-C", &[]),
      // 0x001d SerialNumber — string[8] "12345678" out-of-line (>4 bytes). The serial
      // decrypt key. `NikonConv::Raw` (PrintConv disabled) ⇒ the raw string.
      (0x001d, 0x0002, 8, &[], b"12345678"),
      // 0x0098 LensData — undef, the `0201` ENCRYPTED arm (out-of-line). Decrypted
      // with the prescan keys ⇒ emits LensDataVersion + the %LensData01 members.
      (0x0098, 0x0007, lens_payload.len() as u32, &[], lens_payload),
      // 0x00a7 ShutterCount — int32u 100 inline, LAST ⇒ the count key (captured by
      // the PRESCAN ahead of the 0x0098 emit). Typed leaf.
      (0x00a7, 0x0009, 1, &[0x00, 0x00, 0x00, 0x64], &[]),
    ];
    let blob = crafted_nikon_type3_blob(entries);

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (returns `(typed, emissions)`).
      let (oracle_typed, oracle) =
        makernotes::vendors::nikon::parse_in_tiff(&blob, 0, blob.len(), order, print_conv, model);

      // ---- Path A: the gated isolated helper the production dispatch drives.
      let (iso_emissions, iso_typed) =
        nikon_makernote_isolated(&blob, 0, blob.len(), order, model, print_conv)
          .expect("a type-3 Nikon blob resolves a layout ⇒ Some");
      // ---- Path B: the LEAF walk emitted into an `EmittedTagSink` so the full
      // `MakerNotes:Nikon` group is asserted (the `VendorEmission` stream omits it).
      let emitted_leaves = drive_nikon_type3_leaves(&blob, model, print_conv);

      // The full `VendorEmission` stream (leaves + the LensData sub-table members)
      // must match the oracle position-wise.
      assert_eq!(
        iso_emissions.len(),
        oracle.len(),
        "pc={print_conv}: isolated emission COUNT must match the oracle"
      );
      assert!(
        oracle.len() >= 4,
        "pc={print_conv}: at least Quality + FocusMode + SerialNumber + LensDataVersion emit"
      );
      for (i, want) in oracle.iter().enumerate() {
        let got = iso_emissions.get(i).expect("index in range");
        assert_eq!(
          got.name(),
          want.name(),
          "pc={print_conv} emission #{i}: VendorEmission NAME mismatch"
        );
        assert_eq!(
          got.value(),
          want.value(),
          "pc={print_conv} emission #{i} ({}): VendorEmission VALUE mismatch \
           (the shared Walker must apply NikonConv + the prescan/decrypt exactly as the oracle)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "pc={print_conv} emission #{i} ({}): VendorEmission Unknown flag mismatch",
          want.name()
        );
      }

      // The deferred SubDirectory PARENT (`LensData`) must NOT be emitted (the
      // #177/#223 bogus-parent rule) — only its decrypted children.
      assert!(
        iso_emissions.iter().all(|e| e.name() != "LensData"),
        "pc={print_conv}: the LensData SubDirectory parent pointer must be suppressed"
      );
      // The 2-pass prescan worked: the encrypted LensData decrypted (its version
      // child emits) even though the count key (0x00a7) is the LAST IFD entry.
      assert!(
        iso_emissions.iter().any(|e| e.name() == "LensDataVersion"),
        "pc={print_conv}: the encrypted LensData decrypted ⇒ LensDataVersion emits \
         (prescan captured the trailing 0x00a7 count key before the emit walk)"
      );

      // Path B — the LEAF `EmittedTag` stream carries the `MakerNotes:Nikon` group.
      // Filter the oracle to its LEAF emissions (the sub-table children are NOT in
      // this stream) by name: the four leaves Quality/FocusMode/SerialNumber/ShutterCount.
      let leaf_names = ["Quality", "FocusMode", "SerialNumber", "ShutterCount"];
      let oracle_leaves: Vec<&makernotes::VendorEmission> = oracle
        .iter()
        .filter(|e| leaf_names.contains(&e.name()))
        .collect();
      assert_eq!(
        emitted_leaves.len(),
        oracle_leaves.len(),
        "pc={print_conv}: EmittedTag LEAF count must match the oracle's leaf emissions"
      );
      for (i, want) in oracle_leaves.iter().enumerate() {
        let tag = emitted_leaves.get(i).expect("index in range").tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "pc={print_conv} leaf #{i}: EmittedTag NAME mismatch"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "pc={print_conv} leaf #{i} ({}): EmittedTag VALUE mismatch",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "pc={print_conv} leaf #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Nikon",
          "pc={print_conv} leaf #{i} ({}): family-1 must be Nikon",
          want.name()
        );
      }

      // The typed `MakerNotesNikon` is the SAME for both modes and must equal the
      // oracle's — including the title-cased Quality/FocusMode + the ShutterCount.
      assert_eq!(
        iso_typed, oracle_typed,
        "pc={print_conv}: the isolated typed MakerNotesNikon must equal the oracle's"
      );
      // Quality (`NikonConv::FormatString`) title-cases under PrintConv (`-j`),
      // verbatim under ValueConv (`-n`) — both paths agree (proven above); pin the
      // mode-correct value here as a sanity anchor.
      assert_eq!(
        iso_typed.quality(),
        Some(if print_conv { "Fine" } else { "FINE" }),
        "pc={print_conv}: Quality (0x0004) → typed accessor"
      );
      assert_eq!(
        iso_typed.serial_number(),
        Some("12345678"),
        "pc={print_conv}: SerialNumber (0x001d) → typed accessor (Raw conv, mode-independent)"
      );
      assert_eq!(
        iso_typed.shutter_count(),
        Some(100),
        "pc={print_conv}: ShutterCount (0x00a7) → typed accessor"
      );
    }
  }

  /// A degenerate Nikon MakerNote too short to resolve a layout (`resolve_layout`
  /// returns `None`) ⇒ `nikon_makernote_isolated` returns `None` (the Nikon slot
  /// stays absent), and `parse_in_tiff` returns empties — the two agree.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_isolated_unresolvable_blob_is_none() {
    // A `"Nikon\0\x02"` type-3 header with NO room for the embedded TIFF marker ⇒
    // `parse_embedded_tiff` fails ⇒ `resolve_layout` returns `None`.
    let blob = b"Nikon\x00\x02\x10";
    for print_conv in [true, false] {
      let (oracle_typed, oracle) = makernotes::vendors::nikon::parse_in_tiff(
        blob,
        0,
        blob.len(),
        ByteOrder::Big,
        print_conv,
        None,
      );
      assert!(
        oracle.is_empty() && oracle_typed == makernotes::vendors::nikon::MakerNotesNikon::new(),
        "pc={print_conv}: an unresolvable type-3 blob ⇒ the oracle emits nothing"
      );
      let iso = nikon_makernote_isolated(blob, 0, blob.len(), ByteOrder::Big, None, print_conv);
      assert!(
        iso.is_none(),
        "pc={print_conv}: an unresolvable blob ⇒ nikon_makernote_isolated returns None"
      );
    }
  }

  // ====================================================================
  // Nikon engine migration — full differential edge-matrix (#243 phase 3-bis)
  //
  // Every case below crafts a minimal Nikon MakerNote and asserts the gated
  // isolated helper (`nikon_makernote_isolated`, the production decode path) emits
  // a BYTE-IDENTICAL tag stream — `(name, value, group, unknown)` for `-j`
  // (PrintConv) AND `-n` (ValueConv) AND the typed `MakerNotesNikon` — to the
  // retired oracle `nikon::parse_in_tiff` (`walk_nikon_ifd` + the same emit). The
  // oracle zero-copies an EMPTY `RawValue::Bytes` for an undef SubDirectory while
  // the isolated Walker materializes the undef[N] block, so the comparison is on
  // the EMITTED tag stream (the children's tags), NOT internal `RawValue`
  // ownership — both feed the same emitters from the same bytes.
  // ====================================================================

  /// Build a headerless big-endian Nikon3 MakerNote (`%Nikon::Main`, no prefix,
  /// the blob IS the IFD at offset 0, offsets parent-TIFF-relative). `entries` is
  /// `(tag, format, count, inline_or_empty, out_of_line_or_empty)` exactly as
  /// [`crafted_nikon_type3_blob`]; out-of-line bytes are appended after the
  /// next-IFD word and their stored offset is BLOB-relative (the headerless
  /// layout's `value_base = 0`, and the differential helper passes `mn_offset =
  /// 0`, so blob-relative == data-relative).
  #[cfg(feature = "alloc")]
  fn crafted_nikon_headerless_blob(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    let dir_bytes = 2 + 12 * entries.len();
    let values_at = dir_bytes + 4; // first out-of-line value: past count+entries+next-IFD
    let mut value_cursor = values_at;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      blob.extend_from_slice(&tag.to_be_bytes());
      blob.extend_from_slice(&format.to_be_bytes());
      blob.extend_from_slice(&count.to_be_bytes());
      if out_of_line.is_empty() {
        let mut slot = [0u8; 4];
        let n = inline.len().min(4);
        slot[..n].copy_from_slice(&inline[..n]);
        blob.extend_from_slice(&slot);
      } else {
        blob.extend_from_slice(&(value_cursor as u32).to_be_bytes());
        value_blob.extend_from_slice(out_of_line);
        value_cursor += out_of_line.len();
      }
    }
    blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
    blob.extend_from_slice(&value_blob);
    blob
  }

  /// Build a type-2 Nikon MakerNote (`%Nikon::Type2`, `"Nikon\0\x01"` + a 2-byte
  /// pad, the IFD at blob offset 8, FIXED little-endian, offsets
  /// parent-TIFF-relative ⇒ `value_base = 0`). All entries are LITTLE-endian.
  /// Layout: `[Nikon\0\x01\0\0 (8)][count u16 + 12*N entries][next-IFD u32][values]`.
  #[cfg(feature = "alloc")]
  fn crafted_nikon_type2_blob(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    let dir_bytes = 2 + 12 * entries.len();
    let values_at = 8 + dir_bytes + 4; // blob offset of the first out-of-line value
    let mut value_cursor = values_at;
    let mut blob: Vec<u8> = Vec::new();
    // `"Nikon\0\x01"` (7 bytes) + a 1-byte pad ⇒ the IFD starts at the FIXED blob
    // offset 8 (`resolve_layout`'s type-2 `ifd_offset`, `MakerNotes.pm:539-545`).
    blob.extend_from_slice(b"Nikon\x00\x01\x00");
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut value_blob: Vec<u8> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if out_of_line.is_empty() {
        let mut slot = [0u8; 4];
        let n = inline.len().min(4);
        slot[..n].copy_from_slice(&inline[..n]);
        blob.extend_from_slice(&slot);
      } else {
        // value_base 0 ⇒ the stored offset is the absolute blob/data offset.
        blob.extend_from_slice(&(value_cursor as u32).to_le_bytes());
        value_blob.extend_from_slice(out_of_line);
        value_cursor += out_of_line.len();
      }
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    blob.extend_from_slice(&value_blob);
    blob
  }

  /// The differential oracle: for BOTH `-j` (PrintConv) and `-n` (ValueConv),
  /// the gated isolated helper `nikon_makernote_isolated` emits the EXACT same
  /// `(name, value, group="MakerNotes:Nikon", unknown)` `VendorEmission` stream —
  /// in order — as the oracle `nikon::parse_in_tiff`, AND the typed
  /// `MakerNotesNikon` agrees. Drives both over the SAME `(data, mn_offset, mn_len,
  /// parent_order, model)`. When the layout is unresolvable the isolated helper
  /// returns `None` and the oracle returns empties (the two still agree).
  #[cfg(feature = "alloc")]
  fn assert_nikon_isolated_eq_oracle(
    label: &str,
    data: &[u8],
    mn_offset: usize,
    mn_len: usize,
    parent_order: ByteOrder,
    model: Option<&str>,
  ) {
    for print_conv in [true, false] {
      let (oracle_typed, oracle) = makernotes::vendors::nikon::parse_in_tiff(
        data,
        mn_offset,
        mn_len,
        parent_order,
        print_conv,
        model,
      );
      match nikon_makernote_isolated(data, mn_offset, mn_len, parent_order, model, print_conv) {
        None => {
          // Unresolvable layout ⇒ the Nikon slot is absent; the oracle agrees by
          // emitting nothing (empty stream + default typed).
          assert!(
            oracle.is_empty() && oracle_typed == makernotes::vendors::nikon::MakerNotesNikon::new(),
            "{label} pc={print_conv}: isolated=None ⇒ the oracle must emit nothing"
          );
        }
        Some((iso_emissions, iso_typed)) => {
          assert_eq!(
            iso_emissions.len(),
            oracle.len(),
            "{label} pc={print_conv}: emission COUNT must match the oracle \
             (iso={:?}, oracle={:?})",
            iso_emissions.iter().map(|e| e.name()).collect::<Vec<_>>(),
            oracle.iter().map(|e| e.name()).collect::<Vec<_>>()
          );
          for (i, want) in oracle.iter().enumerate() {
            let got = iso_emissions.get(i).expect("index in range");
            assert_eq!(
              got.name(),
              want.name(),
              "{label} pc={print_conv} emission #{i}: NAME mismatch"
            );
            assert_eq!(
              got.value(),
              want.value(),
              "{label} pc={print_conv} emission #{i} ({}): VALUE mismatch",
              want.name()
            );
            assert_eq!(
              got.unknown(),
              want.unknown(),
              "{label} pc={print_conv} emission #{i} ({}): Unknown flag mismatch",
              want.name()
            );
          }
          assert_eq!(
            iso_typed, oracle_typed,
            "{label} pc={print_conv}: typed MakerNotesNikon must equal the oracle's"
          );
        }
      }
    }
  }

  /// TYPE-2 SPLIT: a `%Nikon::Type2` IFD names 0x0003 by the Type2 table (NOT the
  /// Main table), and walks under the parent-relative base. Proves the table split
  /// + the FIXED little-endian type-2 order. 0x0003 is `Quality` in `%Nikon::Type2`
  /// (`Nikon.pm`), a different tag than Main's 0x0003.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_type2_quality_uses_type2_table() {
    // 0x0003 Quality — string[7] "NORMAL\0" out-of-line (>4 ⇒ offset). Type2 names
    // it `Quality`; the value rides through unchanged.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[(0x0003, 0x0002, 7, &[], b"NORMAL\x00")];
    let blob = crafted_nikon_type2_blob(entries);
    // Sanity: the isolated path emits a tag named by `%Nikon::Type2`.
    let (emis, _typed) =
      nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Little, None, true)
        .expect("a type-2 blob resolves a layout");
    assert!(
      emis.iter().any(|e| e.name() == "Quality"),
      "0x0003 must be named `Quality` by %Nikon::Type2 (got {:?})",
      emis.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
    // The Type2 name is NOT the Main 0x0003 name (Main 0x0003 has no `Quality`).
    let main_0x0003 = makernotes::vendors::nikon::NikonTable::Main.lookup(0x0003);
    assert!(
      main_0x0003.is_none_or(|t| t.name() != "Quality"),
      "the Main table's 0x0003 is a DIFFERENT tag than Type2's Quality"
    );
    assert_nikon_isolated_eq_oracle(
      "type2-quality",
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      None,
    );
  }

  /// HEADERLESS Nikon3: no prefix, the blob IS the IFD at offset 0, INHERITED
  /// parent order, base 0. A plain `int8u` LensType (0x0083 = 6 ⇒ "G") byte-identical
  /// on both paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_headerless_inherited_order_base0() {
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x0004 Quality — string[4] "FINE" inline.
      (0x0004, 0x0002, 4, b"FINE", &[]),
      // 0x0083 LensType — int8u = 6 ⇒ "G" (a known leaf).
      (0x0083, 0x0001, 1, &[0x06], &[]),
    ];
    let blob = crafted_nikon_headerless_blob(entries);
    assert_nikon_isolated_eq_oracle(
      "headerless-base0",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: both leaves emit (Quality + LensType), proving the headerless
    // layout walks at offset 0 under the inherited order.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert_eq!(
      emis.iter().map(|e| e.name()).collect::<Vec<_>>(),
      vec!["Quality", "LensType"]
    );
  }

  /// EMBEDDED-TIFF wrong IFD0-offset field (type-3): the embedded TIFF header's
  /// 4-byte IFD0-offset field is set to a DECOY (0x40, not 8) — BOTH paths IGNORE
  /// it and walk the FIXED `tiff_at + 8` start (`MakerNotes.pm:54`,
  /// `Start => '$valuePtr + 18'`). The Main IFD at blob 18 carries a real leaf.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_type3_wrong_ifd0_offset_field_ignored() {
    // Build a type-3 blob with ONE leaf, then clobber the embedded IFD0-offset
    // field (blob[14..18]) to a decoy value — the fixed start must still win.
    let mut blob = crafted_nikon_type3_blob(&[(0x0004, 0x0002, 4, b"FINE", &[])]);
    blob[14] = 0x00;
    blob[15] = 0x00;
    blob[16] = 0x00;
    blob[17] = 0x40; // decoy IFD0 offset 0x40 (real IFD is at the fixed blob 18)
    assert_nikon_isolated_eq_oracle(
      "type3-decoy-ifd0-field",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: the leaf at the FIXED tiff_at+8 start still emits (the decoy
    // field was ignored) — exactly the Quality leaf.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert_eq!(emis.get(0).map(|e| e.name()), Some("Quality"));
  }

  /// SUSPICIOUS-OFFSET (raw stored offset < 8) + a trailing VALID leaf: BOTH paths
  /// DROP the suspicious entry and KEEP the valid leaf. A headerless IFD with a
  /// rational64u (8 bytes > 4 ⇒ out-of-line) at stored offset 0 (`< 8` ⇒ suspect),
  /// then an inline LensType.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_suspicious_offset_dropped_leaf_kept() {
    // Hand-build a headerless IFD (the builders can't store an offset of 0): entry 0
    // = rational64u @ stored offset 0 (< 8 ⇒ suspect), entry 1 = inline LensType = 6.
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&2u16.to_be_bytes()); // 2 entries
    // entry 0: tag 0x008c (ContrastCurve, known), rational64u, count 1, offset 0.
    blob.extend_from_slice(&0x008cu16.to_be_bytes());
    blob.extend_from_slice(&0x0005u16.to_be_bytes()); // rational64u
    blob.extend_from_slice(&1u32.to_be_bytes()); // count 1 ⇒ 8 bytes > 4 ⇒ out-of-line
    blob.extend_from_slice(&0u32.to_be_bytes()); // stored offset 0 (< 8 ⇒ suspect)
    // entry 1: tag 0x0083 LensType, int8u, count 1, inline = 6 ("G").
    blob.extend_from_slice(&0x0083u16.to_be_bytes());
    blob.extend_from_slice(&0x0001u16.to_be_bytes());
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD
    assert_nikon_isolated_eq_oracle(
      "suspicious-offset",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: the kept LensType leaf actually emits (the suspicious entry is
    // dropped, NOT the whole directory) — exactly ONE tag survives on both paths.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert_eq!(
      emis.len(),
      1,
      "the suspicious entry is dropped, the LensType leaf is KEPT (got {:?})",
      emis.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
    assert_eq!(emis.get(0).map(|e| e.name()), Some("LensType"));
  }

  /// EXCESSIVE-COUNT (> 100000 numeric): BOTH paths SKIP the entry. A headerless IFD
  /// with a known `int32u` leaf (0x0083 LensType is int8u, so use 0x00a7 ShutterCount
  /// int32u) at count 100001 (in-bounds inline-impossible ⇒ out-of-line) + a trailing
  /// valid LensType. Both drop the excessive entry, keep the leaf.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_excessive_count_skipped_leaf_kept() {
    // Build by hand: entry 0 = int32u 0x0019 (a known Main tag, NOT a subdir, NOT
    // undef/string) count 100001 out-of-line (in-bounds), entry 1 = inline LensType.
    let n_excess: u32 = 100_001;
    let dir_bytes = 2 + 12 * 2;
    let value_off = dir_bytes + 4; // out-of-line value sits past the next-IFD word
    let value_len = n_excess as usize * 4; // int32u
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&2u16.to_be_bytes()); // 2 entries
    // entry 0: 0x0019 (BracketingComp? — pick a KNOWN non-subdir Main tag), int32u,
    // count 100001, out-of-line at value_off.
    blob.extend_from_slice(&0x0019u16.to_be_bytes());
    blob.extend_from_slice(&0x0009u16.to_be_bytes()); // int32u
    blob.extend_from_slice(&n_excess.to_be_bytes());
    blob.extend_from_slice(&(value_off as u32).to_be_bytes());
    // entry 1: 0x0083 LensType int8u = 6 ("G") inline.
    blob.extend_from_slice(&0x0083u16.to_be_bytes());
    blob.extend_from_slice(&0x0001u16.to_be_bytes());
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD
    blob.resize(value_off + value_len, 0x00); // the in-bounds (huge) value
    assert_nikon_isolated_eq_oracle(
      "excessive-count",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: the excessive-count entry is skipped, the trailing LensType
    // leaf is KEPT — exactly ONE tag survives on both paths.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert_eq!(
      emis.len(),
      1,
      "the excessive-count entry is skipped, the LensType leaf is KEPT (got {:?})",
      emis.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
    assert_eq!(emis.get(0).map(|e| e.name()), Some("LensType"));
  }

  /// WARN-COUNT > 10 ABORT: 11 suspicious entries (stored offset 0, counted) then a
  /// trailing VALID LensType — BOTH paths abort at the top of the 12th iteration, so
  /// the late leaf is DROPPED by both.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_warn_count_abort_drops_late_leaf() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&12u16.to_be_bytes()); // 12 entries
    // 11 suspicious out-of-line entries: rational64u count 1 (8 bytes > 4) at stored
    // offset 0 (< 8 ⇒ suspect, ++warn_count). Use unknown ids (0x00f0..) — the
    // suspicious gate fires BEFORE the unknown-skip, so they still count.
    for i in 0..11u16 {
      blob.extend_from_slice(&(0x00f0u16 + i).to_be_bytes());
      blob.extend_from_slice(&0x0005u16.to_be_bytes()); // rational64u
      blob.extend_from_slice(&1u32.to_be_bytes());
      blob.extend_from_slice(&0u32.to_be_bytes()); // offset 0 ⇒ suspect
    }
    // 12th: a valid inline LensType (would emit "G" if reached after the abort).
    blob.extend_from_slice(&0x0083u16.to_be_bytes());
    blob.extend_from_slice(&0x0001u16.to_be_bytes());
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&0u32.to_be_bytes()); // next-IFD
    assert_nikon_isolated_eq_oracle("warn-abort", &blob, 0, blob.len(), ByteOrder::Big, None);
    // The abort really fired: the late LensType is ABSENT on the production path …
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert!(
      emis.iter().all(|e| e.name() != "LensType"),
      "the >10 warn-count abort drops the trailing LensType (got {:?})",
      emis.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
    // … CONTROL — with only ONE suspicious entry (no abort) the SAME trailing
    // LensType WOULD survive, proving the abort (not some other gate) drops it.
    let mut ctrl: Vec<u8> = Vec::new();
    ctrl.extend_from_slice(&2u16.to_be_bytes()); // 2 entries (1 suspicious + the leaf)
    ctrl.extend_from_slice(&0x00f0u16.to_be_bytes());
    ctrl.extend_from_slice(&0x0005u16.to_be_bytes()); // rational64u
    ctrl.extend_from_slice(&1u32.to_be_bytes());
    ctrl.extend_from_slice(&0u32.to_be_bytes()); // offset 0 ⇒ suspect (1 warn, no abort)
    ctrl.extend_from_slice(&0x0083u16.to_be_bytes());
    ctrl.extend_from_slice(&0x0001u16.to_be_bytes());
    ctrl.extend_from_slice(&1u32.to_be_bytes());
    ctrl.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    ctrl.extend_from_slice(&0u32.to_be_bytes());
    assert_nikon_isolated_eq_oracle(
      "warn-abort-control",
      &ctrl,
      0,
      ctrl.len(),
      ByteOrder::Big,
      None,
    );
    let (cemis, _) = nikon_makernote_isolated(&ctrl, 0, ctrl.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    assert_eq!(
      cemis.get(0).map(|e| e.name()),
      Some("LensType"),
      "CONTROL: without the abort the trailing LensType survives (got {:?})",
      cemis.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
  }

  /// DECRYPT-DISABLED: an ENCRYPTED 0x0098 LensData with NO 0x00a7 ShutterCount key
  /// present ⇒ `ProcessNikonEncrypted` returns 0 ⇒ BOTH paths emit NOTHING for the
  /// LensData subdir (the prescan finds no count key, so the `0204` arm cannot
  /// decrypt). A leading 0x001d serial alone is not enough for the count-keyed
  /// versions. Verifies the prescan→decrypt gate is identical on both paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_decrypt_disabled_subdir_emits_nothing() {
    // LensData `0204` (count-keyed) payload with NO 0x00a7 anywhere ⇒ no count key.
    let lens_payload: &[u8] =
      b"0204\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x001d SerialNumber out-of-line — the serial key IS present …
      (0x001d, 0x0002, 8, &[], b"12345678"),
      // 0x0098 LensData `0204` ENCRYPTED — but with NO 0x00a7 count key, the
      // count-keyed decrypt yields nothing (subdir silent).
      (0x0098, 0x0007, lens_payload.len() as u32, &[], lens_payload),
    ];
    let blob = crafted_nikon_type3_blob(entries);
    // The LensData subdir must emit NOTHING decryptable beyond (at most) the
    // plaintext version — assert the two paths AGREE on whatever that is.
    assert_nikon_isolated_eq_oracle(
      "decrypt-disabled",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      Some("NIKON D7000"),
    );
  }

  /// UNDEF[1] → int8u carve-out + COUNT=0 leaves: BOTH paths byte-identical. A
  /// headerless IFD with a 0x0083 LensType `undef[1]` (the degenerate 1-byte
  /// carve-out) and a `string` count-0 entry (empty value). Exercises the
  /// zero-length / single-byte edges of `read_value` / `resolve_read_format`.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_undef1_and_count0_leaves() {
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x0083 LensType — undef[1] inline = 6 (the int8u carve-out ⇒ "G").
      (0x0083, 0x0007, 1, &[0x06], &[]),
      // 0x0004 Quality — string count 0 (empty). Inline (0 bytes ≤ 4).
      (0x0004, 0x0002, 0, &[], &[]),
    ];
    let blob = crafted_nikon_headerless_blob(entries);
    assert_nikon_isolated_eq_oracle("undef1-count0", &blob, 0, blob.len(), ByteOrder::Big, None);
    // NON-VACUOUS + the carve-out fired: the undef[1] LensType decodes as int8u
    // (6 ⇒ "G") on BOTH paths — NOT a raw 1-byte blob — proving the oracle was
    // aligned to the shared Walker's `Exif.pm:6644` carve-out.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("layout resolves");
    let lens = emis
      .iter()
      .find(|e| e.name() == "LensType")
      .expect("LensType emits");
    assert_eq!(
      lens.value(),
      &crate::value::TagValue::Str("G".into()),
      "undef[1] LensType must coerce to int8u then render via the LensType conv ⇒ \"G\""
    );
  }

  /// REGRESSION (#243 R2): a 0x0088 AFInfo SubDirectory written with on-disk format
  /// `undef`, COUNT 1, ONE inline byte — the EXACT divergence the finding names. The
  /// shared `Walker` applies the generic `undef[1] → int8u` carve-out (`Exif.pm:6644`),
  /// so the entry's DECODED value is a scalar int8u, NOT `RawValue::Bytes`. Deriving
  /// the sub-table block from the decoded value (the pre-fix code) would pass `&[]` and
  /// `emit_af_info` would emit NOTHING — whereas the oracle slices the 1 on-disk byte
  /// and `emit_af_info` reads its offset-0 `AFAreaMode`. The fix feeds the emitter the
  /// on-disk value SPAN (`value_offset`/`value_size`), shape-independent, so the isolated
  /// path and the oracle BOTH read the byte and emit the identical `AFAreaMode`. This
  /// test FAILS before the fix (the oracle emits `AFAreaMode`, the isolated path emits
  /// nothing ⇒ a COUNT mismatch in `assert_nikon_isolated_eq_oracle`) and passes after.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_afinfo_undef1_subdir_reads_inline_byte() {
    // 0x0088 AFInfo — on-disk `undef` (7), count 1, the single inline byte `0x00`.
    // AFInfo offset 0 = `AFAreaMode` (int8u) ⇒ `0 => "Single Area"`; offsets 1/2 need
    // ≥ 2 / ≥ 4 bytes, so with a 1-byte block ONLY AFAreaMode emits.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[(0x0088, 0x0007, 1, &[0x00], &[])];
    let blob = crafted_nikon_type3_blob(entries);
    // A NON-DSLR model (None) ⇒ the AFInfo table reads LittleEndian; irrelevant for a
    // 1-byte offset-0 int8u, but pinned so the byte order is unambiguous.
    assert_nikon_isolated_eq_oracle(
      "afinfo-undef1-subdir",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: the 1-byte AFInfo block yields exactly `AFAreaMode = "Single Area"`
    // (PrintConv) on the isolated path — proving the SPAN, not the int8u-coerced decoded
    // value, fed the emitter. Before the fix this emission was absent.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, None, true)
      .expect("a type-3 AFInfo blob resolves a layout");
    let af = emis
      .iter()
      .find(|e| e.name() == "AFAreaMode")
      .expect("the undef[1] AFInfo SubDirectory must emit its offset-0 AFAreaMode");
    assert_eq!(
      af.value(),
      &crate::value::TagValue::Str("Single Area".into()),
      "the inline AFInfo byte 0x00 ⇒ AFAreaMode \"Single Area\" (offset-0 int8u)"
    );
    assert!(
      emis.iter().any(|e| e.name() == "AFAreaMode"),
      "the AFInfo SubDirectory must NOT be silently dropped (the R2 divergence)"
    );
  }

  /// HEAP + correctness: MANY 0x0098 LensData SubDirectory entries all pointing at ONE
  /// large in-bounds block. The amplification the finding names — the pre-fix code
  /// materialized each `undef[N]` block into `entry.value`, retaining `N` copies of the
  /// SAME block — is closed by storing an EMPTY `RawValue::Bytes` for the implicit-`undef`
  /// SubDirectory (the capture loop re-slices the on-disk SPAN from the buffer instead).
  /// Correctness is the priority: the isolated path's emission stream MUST still equal
  /// the oracle's (each LensData decrypts identically from the shared prescan keys). The
  /// heap assertion confirms NO per-entry copy is retained on the walked entries.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_repeated_lensdata_subdir_zero_copy() {
    // 16 bytes of LensData payload after the `0201` version — enough for `%LensData01`.
    let lens: &[u8] = b"0201\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
    // The decrypt key (SerialNumber 0x001d) + ShutterCount (0x00a7), then THREE 0x0098
    // LensData entries. Tag IDs ascend (real Nikon IFDs are sorted); duplicate 0x0098
    // entries are a crafted edge — each re-references its own out-of-line copy here, but
    // the per-entry MATERIALIZATION (now empty) is what the heap fix removes.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x001d, 0x0002, 8, &[], b"12345678"),
      (0x0098, 0x0007, lens.len() as u32, &[], lens),
      (0x0098, 0x0007, lens.len() as u32, &[], lens),
      (0x0098, 0x0007, lens.len() as u32, &[], lens),
      (0x00a7, 0x0009, 1, &[0x00, 0x00, 0x00, 0x64], &[]),
    ];
    let blob = crafted_nikon_type3_blob(entries);
    let model = Some("NIKON D7000");
    // CORRECTNESS: the full emission stream matches the oracle for `-j` AND `-n`.
    assert_nikon_isolated_eq_oracle(
      "repeated-lensdata",
      &blob,
      0,
      blob.len(),
      ByteOrder::Big,
      model,
    );
    // NON-VACUOUS: each LensData decrypted ⇒ LensDataVersion emits (3× — one per subdir),
    // proving the SPAN re-slice reaches the real block for every duplicate.
    let (emis, _) = nikon_makernote_isolated(&blob, 0, blob.len(), ByteOrder::Big, model, true)
      .expect("layout resolves");
    let versions = emis
      .iter()
      .filter(|e| e.name() == "LensDataVersion")
      .count();
    assert_eq!(
      versions, 3,
      "all three duplicated LensData SubDirectories must decrypt + emit (got {versions})"
    );
    // HEAP: drive the shared `Walker` directly and assert the implicit-`undef`
    // SubDirectory leaves retain a ZERO-LENGTH value (the block is NOT copied per entry;
    // the SPAN — re-sliced from the buffer — carries the bytes). Mirrors the oracle's
    // `RawValue::Bytes(Vec::new())` for the same predicate.
    let mut w = test_walker(&blob);
    w.order = ByteOrder::Big;
    w.value_offset_base = 10; // type-3 base
    w.process_subdir(
      18,
      IfdKind::ExifIfd,
      TableRef::Nikon,
      ByteOrderRule::Fixed(ByteOrder::Big),
      FixBaseMode::No,
      ProcessProc::Exif,
    );
    let mut subdir_entries = 0usize;
    for entry in &w.entries {
      if let ResolvedConv::Nikon(t) = entry.conv
        && t.sub_table().is_some()
      {
        subdir_entries += 1;
        // The materialized value is EMPTY (zero-copy) — the span carries the bytes.
        assert_eq!(
          entry.value_ref().raw(),
          &RawValue::Bytes(Vec::new()),
          "an implicit-undef SubDirectory leaf must store EMPTY bytes (no per-entry copy)"
        );
        // The recorded SPAN still points at the real in-bounds block (non-empty).
        assert!(
          entry.value_size() >= lens.len(),
          "the on-disk value SPAN must cover the full LensData block"
        );
        let block = w
          .data
          .get(entry.value_offset()..entry.value_offset() + entry.value_size());
        assert!(
          block.is_some_and(|b| b.len() == lens.len()),
          "the SPAN re-slices the real LensData block from the buffer"
        );
      }
    }
    assert_eq!(
      subdir_entries, 3,
      "three 0x0098 LensData SubDirectory entries must be walked (got {subdir_entries})"
    );
  }

  /// BAD-FORMAT at index 0 (DIRECTORY ABORT) vs a LATER index (SKIP + leaf survives):
  /// two crafted headerless IFDs prove both control-flow arms are byte-identical on
  /// the isolated path and the oracle.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_bad_format_entry0_abort_vs_later_skip() {
    // (a) entry 0 = format 99 (invalid) ⇒ ABORT the whole directory; the later
    // LensType is dropped by both paths.
    let abort: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x0083, 99, 1, &[0x00], &[]),     // bad format at index 0 ⇒ abort
      (0x0083, 0x0001, 1, &[0x06], &[]), // would be "G" but the dir aborts
    ];
    let blob_abort = crafted_nikon_headerless_blob(abort);
    assert_nikon_isolated_eq_oracle(
      "bad-format-entry0-abort",
      &blob_abort,
      0,
      blob_abort.len(),
      ByteOrder::Big,
      None,
    );
    // (b) a bad format at a LATER index ⇒ SKIP only that entry; the valid leaves
    // before/after survive on both paths.
    let skip: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x0083, 0x0001, 1, &[0x06], &[]), // LensType = "G" (valid, index 0)
      (0x0004, 99, 1, &[0x00], &[]),     // bad format at index 1 ⇒ skip
      (0x0007, 0x0002, 4, b"AF-C", &[]), // FocusMode "Af-C" (valid, index 2)
    ];
    let blob_skip = crafted_nikon_headerless_blob(skip);
    assert_nikon_isolated_eq_oracle(
      "bad-format-later-skip",
      &blob_skip,
      0,
      blob_skip.len(),
      ByteOrder::Big,
      None,
    );
    // NON-VACUOUS: the abort arm emits NOTHING; the skip arm keeps the 2 valid
    // leaves (LensType + FocusMode), dropping ONLY the bad middle entry.
    let (ea, _) =
      nikon_makernote_isolated(&blob_abort, 0, blob_abort.len(), ByteOrder::Big, None, true)
        .expect("layout resolves");
    assert!(
      ea.is_empty(),
      "entry-0 bad format aborts the whole directory"
    );
    let (es, _) =
      nikon_makernote_isolated(&blob_skip, 0, blob_skip.len(), ByteOrder::Big, None, true)
        .expect("layout resolves");
    assert_eq!(
      es.iter().map(|e| e.name()).collect::<Vec<_>>(),
      vec!["LensType", "FocusMode"],
      "a later bad format skips ONLY that entry; the valid leaves survive in order"
    );
  }

  /// SHORT-MAKERNOTE GUARD: a truncated type-2 MakerNote whose declared
  /// `mn_len` is too short to hold the IFD count word (the IFD starts at blob offset
  /// 8, so `mn_len < 10`) must NOT let the Walker read its count word from the
  /// UNRELATED following parent-TIFF bytes. The blob's type-2 header resolves a
  /// layout, but the guard returns present-but-empty — and the oracle (now carrying
  /// the SAME guard) agrees. The parent TIFF after the truncated value is a VALID
  /// IFD count + entries that, WITHOUT the guard, would be mis-walked as Nikon tags.
  #[test]
  #[cfg(feature = "alloc")]
  fn nikon_diff_short_makernote_guard_type2() {
    // A full parent buffer: [type-2 header "Nikon\0\x01\0\0" (8)][a tempting LE IFD:
    // 1 entry LensType=6][next-IFD]. The DECLARED MakerNote value is only the 8-byte
    // header (mn_len = 8 < 10), so the count word at offset 8 is OUTSIDE the value.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"Nikon\x00\x01\x00"); // 8-byte type-2 header (IFD @ offset 8)
    // A valid-looking LE Type2 IFD right after — these are PARENT-TIFF bytes that
    // a missing guard would mis-read as the Nikon IFD count + entries.
    data.extend_from_slice(&1u16.to_le_bytes()); // count word at offset 8 (OUTSIDE mn_len)
    data.extend_from_slice(&0x0003u16.to_le_bytes()); // Type2 Quality
    data.extend_from_slice(&0x0002u16.to_le_bytes()); // string
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(b"FINE");
    data.extend_from_slice(&0u32.to_le_bytes()); // next-IFD
    // The DECLARED MakerNote is just the 8-byte header (truncated value).
    assert_nikon_isolated_eq_oracle(
      "short-makernote-type2",
      &data,
      0,
      8, // mn_len = 8 < ifd_offset(8) + 2 = 10 ⇒ guard trips
      ByteOrder::Little,
      None,
    );
    // EXPLICIT: the isolated path returns present-but-empty (NOT None — the layout
    // resolved), and emits NO spurious tags from the parent-TIFF bytes.
    let iso = nikon_makernote_isolated(&data, 0, 8, ByteOrder::Little, None, true)
      .expect("a type-2 header resolves a layout ⇒ Some, even when the value is short");
    assert!(
      iso.0.is_empty(),
      "the short-MakerNote guard must emit NOTHING (no parent-TIFF leakage), got {:?}",
      iso.0.iter().map(|e| e.name()).collect::<Vec<_>>()
    );
  }

  /// The group OVERRIDE is scoped to the Nikon tables too: `vendor_group1_of` is
  /// `Some(\"Nikon\")` for BOTH `Nikon` and `NikonType2` (so a Nikon leaf emits as
  /// `Nikon:*` regardless of the Main/Type2 layout) — phase 3-bis of the engine
  /// migration (#243).
  #[test]
  fn vendor_group1_override_includes_nikon() {
    assert_eq!(vendor_group1_of(TableRef::Nikon), Some("Nikon"));
    assert_eq!(vendor_group1_of(TableRef::NikonType2), Some("Nikon"));
  }

  // ====================================================================// Canon engine migration — Step B1 differential test (#243 phase 2)
  //
  // PROVES the shared `Walker`'s SIMPLE binary sub-table path (`process_subdir`
  // under `TableRef::Canon` → `emit_entry`'s `ResolvedConv::Canon` SubDirectory
  // arm → `emit_canon_subtable`) is BYTE-IDENTICAL to the production
  // `canon::parse_in_tiff` SubDirectory dispatch (`canon/mod.rs:824-911`) for
  // the no-DataMember / no-2-pass tables (ShotInfo / AFInfo / AFInfo2 / AFInfo3
  // / SensorInfo / ColorBalance). The same crafted Canon Main IFD — carrying an
  // OUT-OF-LINE ShotInfo (0x04) record AND an OUT-OF-LINE AFInfo (0x12) record
  // PLUS plain inline leaves — is run through BOTH paths; the emitted
  // `(name, value, group, unknown)` tuples must match, in order, for `-j` AND
  // `-n`. Production keeps `parse_in_tiff`, so conformance stays 416/0.
  // ====================================================================

  /// Build a crafted little-endian Canon Main IFD mixing INLINE leaves and
  /// OUT-OF-LINE binary sub-table records. `entries` is `(tag, format, count,
  /// inline_value_or_empty, out_of_line_bytes_or_empty)`: an entry is inline
  /// when `out_of_line` is empty (value zero-padded to 4 bytes at `entry+8`),
  /// else out-of-line (the 4 bytes at `entry+8` are the blob-relative offset and
  /// `out_of_line` holds the value bytes).
  ///
  /// Out-of-line value data is appended AFTER the next-IFD word, so every value
  /// offset is `>= dir_end + 4` — past the directory extent
  /// (`dir_end == 2 + 12*N`) — and so is NOT flagged `Suspicious` by either
  /// walker (`off < dir_end` is false). The body walker (`walk_canon_in_tiff`,
  /// `mn_offset = 0`) and the shared `Walker` (`process_subdir(0, …)`,
  /// `base = 0`) both resolve offsets blob-relative, so they read the IDENTICAL
  /// value bytes — the precondition for the sub-table byte-identity this test
  /// asserts. Total out-of-line length stays even (int16 arrays), keeping
  /// `data_len - dir_end` clear of the body walker's `1`/`3` `Illegal directory`
  /// tail check.
  #[cfg(feature = "alloc")]
  fn crafted_canon_subtable_ifd(entries: &[(u16, u16, u32, &[u8], &[u8])]) -> Vec<u8> {
    let n = entries.len();
    // Header (2) + entries (12*N) + next-IFD word (4) = where value data starts.
    let value_base = 2 + 12 * n + 4;
    let mut buf = Vec::new();
    buf.extend_from_slice(&(n as u16).to_le_bytes());
    let mut next_value_off = value_base;
    // Collect the out-of-line payloads in entry order to append after the header.
    let mut payloads: Vec<&[u8]> = Vec::new();
    for &(tag, format, count, inline, out_of_line) in entries {
      buf.extend_from_slice(&tag.to_le_bytes());
      buf.extend_from_slice(&format.to_le_bytes());
      buf.extend_from_slice(&count.to_le_bytes());
      if out_of_line.is_empty() {
        // Inline value (<= 4 bytes), zero-padded to the 4-byte slot.
        assert!(inline.len() <= 4, "inline value must be <= 4 bytes");
        let mut slot = [0u8; 4];
        slot[..inline.len()].copy_from_slice(inline);
        buf.extend_from_slice(&slot);
      } else {
        // Out-of-line: store the blob-relative offset; stage the payload.
        buf.extend_from_slice(&(next_value_off as u32).to_le_bytes());
        next_value_off += out_of_line.len();
        payloads.push(out_of_line);
      }
    }
    // Next-IFD pointer word = 0 (ExifIfd-kind walk never follows the chain).
    buf.extend_from_slice(&0u32.to_le_bytes());
    for p in payloads {
      buf.extend_from_slice(p);
    }
    buf
  }

  /// Encode an `i16` word array as little-endian bytes — a Canon binary
  /// sub-table record (`int16s`, the on-disk `$$valPt`).
  #[cfg(feature = "alloc")]
  fn i16_words_le(words: &[i16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 2);
    for &w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  /// The sub-table differential proof: for BOTH `-j` (PrintConv) and `-n`
  /// (ValueConv), the shared `Walker` SIMPLE sub-table path emits the EXACT same
  /// `(name, value, group="MakerNotes:Canon", unknown)` stream — in order — as
  /// `canon::parse_in_tiff`, for a crafted IFD holding a ShotInfo (0x04) record,
  /// an AFInfo (0x12) record, and two plain leaves. This is the byte-identity
  /// oracle for Step B1.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_subtable_emit_matches_parse_in_tiff() {
    // EOS 300D fixture vectors (the real-input records the sub-parser unit tests
    // use): a 33-word ShotInfo and a 24-word AFInfo, both `int16s`. The 300D
    // model threads into ShotInfo position 22 (the non-350D branch) AND AFInfo
    // (EOS → serial stops before PrimaryAFPoint) — so model-threading is
    // meaningfully exercised, not inert.
    let shot_info_words: [i16; 33] = [
      66, 0, 160, -200, 244, -32768, 0, 0, 3, 0, 8, 8, 0, 0, 0, 0, 0, 0, 1, -1, 546, 244, -224, 38,
      40, 0, 252, 0, -1, 0, 0, 0, 0,
    ];
    let af_info_words: [i16; 24] = [
      7, 7, 3072, 2048, 3072, 2048, 151, 151, // scalars 0-7
      1014, 608, 0, 0, 0, -608, -1014, // AFAreaXPositions[7]
      0, 0, -506, 0, 506, 0, 0,  // AFAreaYPositions[7]
      0,  // AFPointsInFocus[1]
      -1, // trailing (EOS stops before consuming)
    ];
    let shot_info = i16_words_le(&shot_info_words);
    let af_info = i16_words_le(&af_info_words);
    // int16s=8, ASCII=2, int16u=3. Tag order ascending (the IFD walk order).
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x04 ShotInfo — SubDirectory, int16s[33], OUT-OF-LINE.
      (0x04, 8, shot_info_words.len() as u32, &[], &shot_info),
      // 0x07 CanonFirmwareVersion — ASCII, conv None. Inline "1.0\0".
      (0x07, 2, 4, b"1.0\0", &[]),
      // 0x12 AFInfo — SubDirectory, int16s[24], OUT-OF-LINE.
      (0x12, 8, af_info_words.len() as u32, &[], &af_info),
      // 0xb4 ColorSpace — int16u, hash PrintConv (1 ⇒ "sRGB"). Inline.
      (0xb4, 3, 1, &[0x01, 0x00], &[]),
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("EOS Digital Rebel / 300D / Kiss Digital");
    // `file_type = None` (these 300D records don't take the ShotInfo CRW
    // clause); threaded identically on both sides so the comparison is fair.
    let file_type = None;

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (renders sub-tables at
      // collection via the SubDirectory dispatch). The blob IS the whole TIFF
      // (`mn_offset = 0`), so out-of-line offsets resolve within it.
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        file_type,
      );

      // ---- New path: shared Walker → emit_canon_subtable (+ emit_canon_value
      // for the plain leaves).
      let emitted = drive_canon_subdir(&blob, order, print_conv, model, file_type);

      // Both streams are in IFD-tag order, each sub-table expanded in its
      // BinaryData position order at the parent tag's slot — compare position-wise.
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: emission COUNT must match \
         (every sub-table position + plain leaf the oracle emits, the shared \
         path emits — and NONE extra)"
      );
      // The crafted blob MUST actually exercise the sub-tables (guard against a
      // future refactor silently turning these into no-ops).
      assert!(
        oracle.iter().any(|e| e.name() == "AutoISO"),
        "the ShotInfo (0x04) record must decode (AutoISO is position 1)"
      );
      assert!(
        oracle.iter().any(|e| e.name() == "NumAFPoints"),
        "the AFInfo (0x12) record must decode (NumAFPoints is position 0)"
      );
      for (i, (got, want)) in emitted.iter().zip(oracle.iter()).enumerate() {
        let tag = got.tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} position #{i}: NAME mismatch \
           (sub-table position order must match parse_in_tiff)"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} position #{i} ({}): rendered VALUE mismatch \
           (the new path must reserialize + run the sub-parser exactly as \
           parse_in_tiff)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} position #{i} ({}): Unknown flag mismatch \
           (sub-table positions are never Unknown — both must emit false)",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} position #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Canon",
          "print_conv={print_conv} position #{i} ({}): family-1 must be Canon",
          want.name()
        );
      }
    }
  }

  /// The AFInfo2 (0x26) `Condition => '$$valPt !~ /^\0\0\0\0/'` skip
  /// (`Canon.pm:1713`) is preserved on the emit path: an all-zero first four
  /// bytes means the SubDirectory is NOT entered and the shared `Walker` emits
  /// NOTHING for it — byte-identical to `parse_in_tiff` (which also emits
  /// nothing). The differential count comparison covers the positive case; this
  /// pins the skip explicitly on BOTH paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_af_info2_first4_zero_skip_matches_parse_in_tiff() {
    // A 0x26 record whose first four bytes (NumAFPoints + ValidAFPoints) are all
    // zero — the all-zero MOV-thumbnail record Canon.pm:1713 skips. Pad to a
    // realistic length so only the `Condition`, not a short-blob accident,
    // governs.
    let af_info2_words = [0i16; 20];
    let af_info2 = i16_words_le(&af_info2_words);
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // 0x07 CanonFirmwareVersion — a plain leaf to anchor a non-empty stream.
      (0x07, 2, 4, b"1.0\0", &[]),
      // 0x26 AFInfo2 — SubDirectory, int16s[20], first 4 bytes all zero.
      (0x26, 8, af_info2_words.len() as u32, &[], &af_info2),
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;

    for print_conv in [true, false] {
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        None,
        None,
      );
      let emitted = drive_canon_subdir(&blob, order, print_conv, None, None);
      // The 0x26 all-zero record contributes NOTHING on either side: only the
      // CanonFirmwareVersion leaf survives.
      assert_eq!(
        oracle.len(),
        1,
        "print_conv={print_conv}: the all-zero AFInfo2 must be skipped by \
         parse_in_tiff (only the firmware leaf remains)"
      );
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: the shared Walker must ALSO skip the all-zero \
         AFInfo2 (the 0x26 first4-zero Condition holds on the emit path)"
      );
      assert!(
        emitted.iter().all(|t| t.tag().name() != "NumAFPoints"),
        "no AFInfo2 position may be emitted for the all-zero 0x26 record"
      );
    }
  }

  // ====================================================================// Canon engine migration — Step B2 differential test (#243 phase 2)
  //
  // PROVES the shared `Walker`'s DataMember 2-pass (CameraSettings 0x01 →
  // `$$self{FocalUnits}`/`$$self{LensType}` → FocalLength 0x02 + FileInfo 0x93),
  // routed through the pre-scan ([`Walker::canon_prescan_datamembers`]) + the
  // emit dispatch (`emit_canon_subtable`), is BYTE-IDENTICAL to the production
  // `canon::parse_in_tiff` pre-pass + SubDirectory dispatch (`canon/mod.rs:707-
  // 911`). A crafted Canon Main IFD carries an OUT-OF-LINE CameraSettings (0x01)
  // with a position-25 FocalUnits AND a position-22 LensType, an OUT-OF-LINE
  // FocalLength (0x02) whose `FocalLength` output DEPENDS on FocalUnits, and an
  // OUT-OF-LINE FileInfo (0x93) whose `MacroMagnification` output DEPENDS on
  // LensType — so a broken DataMember thread would DIVERGE. Run through BOTH
  // paths; the emitted `(name, value, group, unknown)` tuples must match, in
  // order, for `-j` AND `-n`. Production keeps `parse_in_tiff`, so conformance
  // stays 416/0.
  // ====================================================================

  /// Encode a `u16` word array as little-endian bytes — a FocalLength
  /// (`int16u`) on-disk `$$valPt`.
  #[cfg(feature = "alloc")]
  fn u16_words_le(words: &[u16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 2);
    for &w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  /// The DataMember 2-pass differential proof: for BOTH `-j` and `-n`, the
  /// shared `Walker`'s pre-scan + emit path threads `$$self{FocalUnits}` and
  /// `$$self{LensType}` from CameraSettings into FocalLength and FileInfo
  /// byte-identically to `canon::parse_in_tiff`.
  ///
  /// The crafted vectors make the dependency LOAD-BEARING:
  /// - CameraSettings (0x01) word 22 (`LensType`) = 124 (MP-E 65mm) and word 25
  ///   (`FocalUnits`) = 10 (also words 23/24 = 550/180 for MaxFocalLength /
  ///   MinFocalLength = 55 mm / 18 mm).
  /// - FocalLength (0x02) word 1 (`FocalLength` raw) = 550 ⇒ `550 / FocalUnits(10)`
  ///   = "55 mm". A broken FocalUnits thread (defaulting to 1) would render
  ///   "550 mm" — a DIVERGENCE.
  /// - FileInfo (0x93) word 16 (`MacroMagnification`) = 75 ⇒ emitted ONLY because
  ///   `$$self{LensType} == 124`; a broken LensType thread would SUPPRESS it (a
  ///   count + content DIVERGENCE). The model `Canon EOS 20D` additionally
  ///   exercises the FileInfo position-1 conditional `FileNumber` decode.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_datamember_two_pass_emit_matches_parse_in_tiff() {
    use crate::value::TagValue;
    // ---- CameraSettings (0x01), int16s. Word 0 is the blob byte-length (the
    // `Canon::Validate` word); data words start at position 1. 26 words reach
    // position 25 (FocalUnits).
    let mut cs_words = [0i16; 26];
    cs_words[0] = (cs_words.len() * 2) as i16; // 52-byte blob length word
    cs_words[22] = 124; // LensType = MP-E 65mm (the MacroMagnification gate)
    cs_words[23] = 550; // MaxFocalLength raw ⇒ 55 mm (÷ FocalUnits 10)
    cs_words[24] = 180; // MinFocalLength raw ⇒ 18 mm
    cs_words[25] = 10; // FocalUnits (the FocalLength divisor)
    let camera_settings = i16_words_le(&cs_words);

    // ---- FocalLength (0x02), int16u. [FocalType=2 ("Zoom"), FocalLength=550,
    // FocalPlaneXSize=0, FocalPlaneYSize=0]. With FocalUnits=10 ⇒ "55 mm";
    // positions 2/3 are 0 (< 40 RawConv threshold) so they never emit.
    let fl_words: [u16; 4] = [2, 550, 0, 0];
    let focal_length = u16_words_le(&fl_words);

    // ---- FileInfo (0x93), int16s. Position 1 is an int32u (bytes 2-5); the
    // 20D `FileNumber` vector 0x00451D87 ⇒ "118-1861". Word 16
    // (`MacroMagnification`) = 75 ⇒ "1.0x" (only with LensType 124). 17 words
    // (34 bytes) reach position 16.
    let mut fi_words = [0i16; 17];
    fi_words[16] = 75; // MacroMagnification raw 75 ⇒ exp(0) = 1.0 ⇒ "1.0x"
    let mut file_info = i16_words_le(&fi_words);
    // Overlay the position-1 int32u FileNumber (bytes 2..6, LE 0x00451D87).
    file_info[2..6].copy_from_slice(&0x0045_1D87u32.to_le_bytes());

    // int16s=8, int16u=3. Tag order ascending (the IFD walk order): 0x01, 0x02,
    // 0x93 — CameraSettings precedes FocalLength/FileInfo, but the pre-scan
    // resolves the DataMembers regardless of order.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x01, 8, cs_words.len() as u32, &[], &camera_settings),
      (0x02, 3, fl_words.len() as u32, &[], &focal_length),
      (0x93, 8, fi_words.len() as u32, &[], &file_info),
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    // `Canon EOS 20D`: NOT a MacroMagnification-excluded body (40D/450D/REBEL
    // XSi/Kiss X2), so position 16 emits; AND it keys the FileInfo position-1
    // `FileNumber` conditional — exercising the model thread on BOTH sub-tables.
    let model = Some("Canon EOS 20D");
    let file_type = None;

    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (pre-pass captures FocalUnits +
      // LensType, then the SubDirectory dispatch threads them). The blob IS the
      // whole TIFF (`mn_offset = 0`), so out-of-line offsets resolve within it.
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        file_type,
      );

      // ---- New path: shared Walker pre-scan + emit_canon_subtable.
      let emitted = drive_canon_subdir(&blob, order, print_conv, model, file_type);

      // The crafted blob MUST actually exercise the DataMember dependency —
      // guard against a future refactor silently turning these into no-ops. The
      // FocalUnits-scaled FocalLength is "55 mm" (`-j`) / `55.0` (`-n`); EITHER
      // shape proves `550 ÷ FocalUnits(10)` ran (a broken thread would yield
      // "550 mm" / `550.0`).
      let want_focal = if print_conv {
        TagValue::Str("55 mm".into())
      } else {
        TagValue::F64(55.0)
      };
      assert!(
        oracle
          .iter()
          .any(|e| e.name() == "FocalLength" && e.value() == &want_focal),
        "print_conv={print_conv}: FocalLength must decode to 55 mm (550 ÷ \
         FocalUnits 10) — the FocalUnits DataMember thread; got {oracle:?}"
      );
      assert!(
        oracle.iter().any(|e| e.name() == "MacroMagnification"),
        "MacroMagnification (FileInfo pos 16) must emit — proving the LensType \
         == 124 DataMember thread reached FileInfo; got {oracle:?}"
      );
      assert!(
        oracle.iter().any(|e| e.name() == "FileNumber"),
        "FileNumber (FileInfo pos 1, 20D) must emit — proving the model thread"
      );

      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: emission COUNT must match (every DataMember-\
         threaded sub-table position the oracle emits, the shared path emits — \
         and NONE extra)"
      );
      for (i, (got, want)) in emitted.iter().zip(oracle.iter()).enumerate() {
        let tag = got.tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} position #{i}: NAME mismatch \
           (DataMember 2-pass position order must match parse_in_tiff)"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} position #{i} ({}): rendered VALUE mismatch \
           (the new path must thread FocalUnits/LensType exactly as the \
           parse_in_tiff pre-pass)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} position #{i} ({}): Unknown flag mismatch",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} position #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Canon",
          "print_conv={print_conv} position #{i} ({}): family-1 must be Canon",
          want.name()
        );
      }
    }
  }

  /// The DataMember thread is LOAD-BEARING: feeding the FocalLength / FileInfo
  /// sub-tables a `None`/`None` DataMember pair (the bug a broken pre-scan would
  /// cause) DIVERGES from `parse_in_tiff` — FocalLength renders "550 mm" instead
  /// of "55 mm", and MacroMagnification disappears. This pins that the
  /// differential above would actually CATCH a regression (guards against the
  /// test passing vacuously).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_datamember_thread_is_load_bearing() {
    use crate::value::TagValue;
    // FocalLength (0x02): FocalType=2, FocalLength raw 550.
    let fl_words: [u16; 4] = [2, 550, 0, 0];
    let focal_length = u16_words_le(&fl_words);
    let raw_fl = RawValue::U64(fl_words.iter().map(|&w| u64::from(w)).collect());

    // ---- Correct thread (FocalUnits = Some(10)) ⇒ "55 mm".
    let mut out_correct: Vec<crate::emit::EmittedTag> = Vec::new();
    {
      let mut sink = EmittedTagSink::new(&mut out_correct);
      let Ok(()) = emit_canon_subtable(
        "Canon",
        makernotes::vendors::canon::tags::SubTable::FocalLength,
        &raw_fl,
        ByteOrder::Little,
        /* print_conv */ true,
        Some("Canon EOS 20D"),
        None,
        /* canon_focal_units */ Some(10),
        /* canon_lens_type */ Some(124),
        /* canon_focal_length_blob */ Some(focal_length.as_slice()),
        &mut sink,
      );
    }
    assert!(
      out_correct.iter().any(|t| t.tag().name() == "FocalLength"
        && t.tag().value_ref() == &TagValue::Str("55 mm".into())),
      "with FocalUnits=10 the shared emit must render 55 mm: {out_correct:?}"
    );

    // ---- Broken thread (FocalUnits = None ⇒ divisor 1) ⇒ "550 mm" — the
    // DIVERGENCE the differential above would catch.
    let mut out_broken: Vec<crate::emit::EmittedTag> = Vec::new();
    {
      let mut sink = EmittedTagSink::new(&mut out_broken);
      let Ok(()) = emit_canon_subtable(
        "Canon",
        makernotes::vendors::canon::tags::SubTable::FocalLength,
        &raw_fl,
        ByteOrder::Little,
        true,
        Some("Canon EOS 20D"),
        None,
        /* canon_focal_units */ None,
        None,
        /* canon_focal_length_blob */ Some(focal_length.as_slice()),
        &mut sink,
      );
    }
    assert!(
      out_broken.iter().any(|t| t.tag().name() == "FocalLength"
        && t.tag().value_ref() == &TagValue::Str("550 mm".into())),
      "with FocalUnits=None the divisor is 1 ⇒ 550 mm (the regression signature): \
       {out_broken:?}"
    );
    // The FocalLength arm now decodes the pre-scanned `canon_focal_length_blob`
    // (passed as `focal_length` above), NOT the `raw_fl` entry value — so neither
    // varies the on-disk bytes; only the DataMember thread differs.
    let _ = &raw_fl;
  }

  /// A count-0 `CanonCameraSettings` (0x01) followed by a `CanonFocalLength`
  /// (0x02) — the #243 phase 2 R6 scenario. ExifTool `ProcessExif` reads
  /// `$count * $formatSize` on-disk bytes (`Exif.pm:6502`); for count 0 that is
  /// `$size == 0`, so `ReadValue` returns `undef` (`Exif.pm:6285-6288`) — the
  /// CameraSettings SubDirectory is NEVER processed, so it emits NO positions AND
  /// sets NO `$$self{FocalUnits}` DataMember. A following FocalLength therefore
  /// scales by the DEFAULT divisor (1) ⇒ "550 mm", NOT by a bogus unit over-read
  /// from the count-0 entry's trailing bytes.
  ///
  /// LOAD-BEARING on BOTH count-based fixes (a regression to the old EOF-bound
  /// reads makes this FAIL):
  /// - The oracle `walk_canon_in_tiff` (`body.rs`) — its former EOF-bound `avail`
  ///   read expanded the count-0 entry from the trailing buffer and emitted
  ///   CameraSettings positions the shared `Walker` never does (a COUNT mismatch).
  /// - The pre-scan (`canon_prescan_datamembers`) — its former EOF-bound read
  ///   captured `FocalUnits` = 10 from the decoy word at blob offset 60 (word 25
  ///   of the count-0 entry's over-read from `entry+8` == offset 10), scaling
  ///   FocalLength to "55 mm" — a VALUE mismatch vs the oracle's "550 mm".
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_count_zero_camera_settings_does_not_leak_like_parse_in_tiff() {
    use crate::value::TagValue;
    // FocalLength (0x02), int16u, padded to 16 words so the blob reaches offset
    // 62. Word 0 = FocalType 2, word 1 = FocalLength raw 550. Word 15 = 10 lands
    // at blob offset 60 = word 25 of the count-0 0x01 entry's (`entry+8` == offset
    // 10) EOF-bound over-read — the bogus `FocalUnits` the OLD pre-scan would
    // capture. The FocalLength sub-table reads only words 0..4, so the decoy never
    // affects FocalLength's own decode (positions 2/3 = 0 ⇒ suppressed).
    let mut fl_words = [0u16; 16];
    fl_words[0] = 2;
    fl_words[1] = 550;
    fl_words[15] = 10;
    let focal_length = u16_words_le(&fl_words);
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      // count-0 CameraSettings FIRST (the pre-scan reads 0x01 before 0x02).
      (0x01, 8, 0, &[], &[]),
      (0x02, 3, fl_words.len() as u32, &[], &focal_length),
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    assert_eq!(
      blob.len(),
      62,
      "blob layout: the decoy FocalUnits must land at offset 60"
    );
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D");

    for print_conv in [true, false] {
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let emitted = drive_canon_subdir(&blob, order, print_conv, model, None);

      // FocalLength scaled by the DEFAULT divisor (1) ⇒ 550 — proving the count-0
      // CameraSettings set no FocalUnits (a leak would yield "55 mm" / 55.0).
      let want_focal = if print_conv {
        TagValue::Str("550 mm".into())
      } else {
        TagValue::F64(550.0)
      };
      assert!(
        oracle
          .iter()
          .any(|e| e.name() == "FocalLength" && e.value() == &want_focal),
        "print_conv={print_conv}: FocalLength must be 550 mm (default divisor — the \
         count-0 CameraSettings leaked no FocalUnits); got {oracle:?}"
      );
      // No CameraSettings position (e.g. MacroMode, position 1) leaked into the
      // stream from the count-0 entry.
      assert!(
        !oracle.iter().any(|e| e.name() == "MacroMode"),
        "print_conv={print_conv}: a count-0 CameraSettings must emit NO positions \
         (e.g. MacroMode); got {oracle:?}"
      );

      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: shared Walker emission COUNT must match \
         parse_in_tiff (count-0 CameraSettings contributes nothing on either side)"
      );
      for (i, (got, want)) in emitted.iter().zip(oracle.iter()).enumerate() {
        let tag = got.tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} #{i}: NAME"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} #{i} ({}): VALUE",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} #{i} ({}): Unknown",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Canon",
          "print_conv={print_conv} #{i} ({}): family-1",
          want.name()
        );
      }
    }
  }

  /// A crafted Canon leaf with on-disk format `undef` + count 1 — the
  /// `$formatStr = 'int8u' if $format == 7 and $count == 1` carve-out
  /// (`Exif.pm:6644`) the shared `Walker` applies in `walk_entry`. The retired
  /// oracle `walk_canon_in_tiff` now mirrors it (#243 phase 2 R6 audit of the
  /// generic core read rules reachable under `TableRef::Canon`), so a single
  /// `undef` byte decodes as an int8u in BOTH paths — here `DateStampMode` (0x1c)
  /// byte 2 ⇒ the hash render "Date & Time", NOT a raw-byte blob. Real Canon
  /// leaves are never `undef[1]`; this pins the crafted-edge consistency.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_undef_count1_leaf_coerces_int8u_like_parse_in_tiff() {
    use crate::value::TagValue;
    // 0x1c DateStampMode, on-disk format undef (7), count 1, inline byte 2.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[(0x1c, 7, 1, &[0x02], &[])];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D");

    for print_conv in [true, false] {
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let emitted = drive_canon_subdir(&blob, order, print_conv, model, None);

      // The int8u carve-out ⇒ DateStampMode hash key 2 ⇒ "Date & Time" (`-j`); a
      // raw-`undef`-bytes decode would NOT key the int hash. The `-n` shape is
      // pinned by the production-vs-oracle equality below (both coerce identically).
      if print_conv {
        assert!(
          oracle.iter().any(
            |e| e.name() == "DateStampMode" && e.value() == &TagValue::Str("Date & Time".into())
          ),
          "undef[1] DateStampMode must coerce to int8u 2 ⇒ Date & Time; got {oracle:?}"
        );
      }
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv}: shared Walker emission must match parse_in_tiff \
         for an undef[1] leaf"
      );
      for (i, (got, w)) in emitted.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(got.tag().name(), w.name(), "#{i} name");
        assert_eq!(
          got.tag().value_ref(),
          w.value(),
          "#{i} ({}) value",
          w.name()
        );
      }
    }
  }

  /// R9 (excessive-count guard): a crafted IN-BOUNDS Canon leaf with `count >
  /// 100000` is SKIPPED — matching ExifTool's `ProcessExif` excessive-count guard
  /// (`Exif.pm:6760-6770`), which has NO `$inMakerNotes` exemption and so applies
  /// to `%Canon::Main`. The shared `Walker` (production) applies it in `walk_entry`;
  /// the oracle `walk_canon_in_tiff` + the DataMember pre-scan now mirror it. So a
  /// `CanonModelID` (0x10) written with `count = 100001` emits NOTHING and
  /// populates no typed `model_id` — and a NORMAL leaf after it (OwnerName) STILL
  /// emits, proving the walk CONTINUES past the skip (the guard is `next`, not
  /// abort). Before the alignment, `parse_in_tiff` DECODED the over-count leaf — a
  /// public JSON + typed-API divergence (this test is LOAD-BEARING on both: the
  /// emission count + the `model_id == None` assertions fail without the fix).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_excessive_count_leaf_skipped_like_parse_in_tiff() {
    // 0x10 CanonModelID, on-disk int8u (1), count 100001 (> 100000), OUT-OF-LINE
    // (100001 filler bytes — exactly in-bounds, so the entry classifies `Read` and
    // REACHES the excessive-count guard, which skips it before the value is read).
    // Then 0x09 OwnerName, ASCII, count 4, inline — a NORMAL leaf the walk must
    // still reach AFTER the skip.
    let over_count: u32 = 100_001;
    let filler = std::vec![0u8; over_count as usize];
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x10, 1, over_count, &[], &filler), // int8u, excessive count, out-of-line
      (0x09, 2, 4, b"Al\0\0", &[]),        // OwnerName, normal inline leaf
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D");

    for print_conv in [true, false] {
      let (otyped, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let (emi, typed) =
        canon_makernote_isolated(&blob, 0, blob.len(), order, model, None, print_conv);

      // The excessive-count CanonModelID (0x10) is SKIPPED in BOTH paths.
      assert!(
        !oracle.iter().any(|e| e.name() == "CanonModelID"),
        "print_conv={print_conv}: count>100000 CanonModelID must be SKIPPED \
         (Exif.pm:6760 excessive-count guard); oracle={:?}",
        oracle
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      // The NORMAL leaf after it still emits — the walk continued past the skip.
      assert!(
        emi.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: OwnerName (after the skipped leaf) MUST emit — \
         the excessive-count guard is `next`, not abort"
      );
      // Emission byte-parity: production (shared Walker) == oracle.
      assert_eq!(
        emi.len(),
        oracle.len(),
        "print_conv={print_conv}: shared Walker emission must match parse_in_tiff \
         (both skip the count>100000 leaf)"
      );
      for (i, (g, w)) in emi.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv} #{i}: name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv} #{i}: value");
      }
      // TYPED parity: the skipped 0x10 populates NO `model_id` in EITHER path.
      assert_eq!(
        otyped.model_id(),
        None,
        "print_conv={print_conv}: parse_in_tiff typed model_id must be None \
         (the count>100000 CanonModelID was skipped, not decoded)"
      );
      if print_conv {
        assert_eq!(
          typed.expect("print_conv yields the typed slot").model_id(),
          None,
          "the shared-Walker typed model_id must ALSO be None (no silent divergence)"
        );
      }
    }
  }

  /// R10: the excessive-count guard EXEMPTS `undef`/`string` formats (the
  /// `$formatStr !~ /^(undef|string|binary)$/` predicate, `Exif.pm:6760`). A
  /// crafted `CanonFocalLength` (0x02) mis-written as `undef[100001]` (the ON-DISK
  /// format) is therefore DECODED — not skipped — by the emission walk AND the
  /// pre-scan + oracle. Pins that the pre-scan's `count > 100000` skip matches the
  /// guard PREDICATE: an UNCONDITIONAL skip (the R9 form) dropped the focal-length
  /// blob the emit walk still reads, so FocalLength vanished. The undef value's
  /// first words encode FocalLength raw 550 ⇒ "550 mm" (no FocalUnits 0x01 here, so
  /// the divisor is 1).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_excessive_count_undef_focal_length_decoded_like_parse_in_tiff() {
    use crate::value::TagValue;
    let over_count: u32 = 100_001;
    let mut value = std::vec![0u8; over_count as usize];
    value[0..2].copy_from_slice(&2u16.to_le_bytes()); // FocalType
    value[2..4].copy_from_slice(&550u16.to_le_bytes()); // FocalLength raw 550
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x02, 7, over_count, &[], &value), // undef, excessive count, out-of-line
      (0x09, 2, 4, b"Al\0\0", &[]),       // OwnerName, normal leaf
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D");

    for print_conv in [true, false] {
      let (_otyped, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let (emi, _typed) =
        canon_makernote_isolated(&blob, 0, blob.len(), order, model, None, print_conv);
      // The undef 0x02 is DECODED (NOT skipped) — FocalLength emits from the blob.
      let want = if print_conv {
        TagValue::Str("550 mm".into())
      } else {
        TagValue::F64(550.0)
      };
      assert!(
        oracle
          .iter()
          .any(|e| e.name() == "FocalLength" && e.value() == &want),
        "print_conv={print_conv}: an undef[100001] 0x02 is EXEMPT from the \
         excessive-count guard ⇒ FocalLength 550; oracle={:?}",
        oracle
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      assert_eq!(
        emi.len(),
        oracle.len(),
        "print_conv={print_conv}: production emission must match parse_in_tiff"
      );
      for (i, (g, w)) in emi.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv} #{i}: name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv} #{i}: value");
      }
    }
  }

  /// R10: a non-5D `0x96` with a NON-`Ascii` numeric format is NOT rewritten by
  /// `canon_special_leaf_value` (the `SerialInfo` arm needs 5D; the
  /// `InternalSerialNumber` strip arm needs `Ascii`), so it reaches the generic
  /// excessive-count guard in production and is SKIPPED for `count > 100000`. Pins
  /// that the oracle's 0x96 guard exemption matches: `tag_id != 0x96` (the R9 form)
  /// was too broad — it would DECODE this leaf and emit `InternalSerialNumber`, a
  /// public JSON divergence. With the EOS-5D-only exemption, BOTH skip.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_excessive_count_non5d_numeric_0x96_skipped_like_parse_in_tiff() {
    let over_count: u32 = 100_001;
    let filler = std::vec![0u8; over_count as usize];
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x96, 6, over_count, &[], &filler), // int8s (numeric, non-Ascii), excessive
      (0x09, 2, 4, b"Al\0\0", &[]),        // OwnerName, normal leaf
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D"); // NON-5D body

    for print_conv in [true, false] {
      let (_otyped, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let (emi, _typed) =
        canon_makernote_isolated(&blob, 0, blob.len(), order, model, None, print_conv);
      // The non-5D numeric 0x96 is SKIPPED in BOTH paths — no InternalSerialNumber.
      assert!(
        !oracle.iter().any(|e| e.name() == "InternalSerialNumber"),
        "print_conv={print_conv}: a non-5D numeric 0x96 with count>100000 must be \
         SKIPPED (not rewritten ⇒ the guard applies); oracle={:?}",
        oracle
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      // The normal leaf after it still emits — the walk continued past the skip.
      assert!(
        emi.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: OwnerName (after the skipped 0x96) MUST emit"
      );
      assert_eq!(
        emi.len(),
        oracle.len(),
        "print_conv={print_conv}: production emission must match parse_in_tiff \
         (both skip the non-5D numeric 0x96)"
      );
      for (i, (g, w)) in emi.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv} #{i}: name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv} #{i}: value");
      }
    }
  }

  /// R11: format overrides are SCOPED by active table — a VENDOR (Canon) table
  /// inherits NO `%Exif::Main` `Format` override. A crafted unknown Canon tag
  /// 0x9286 (collides with EXIF `UserComment`, `Format => 'undef'`) with a NUMERIC
  /// on-disk format + `count > 100000` keeps its numeric format, so the
  /// excessive-count guard SKIPS it — rather than the EXIF `undef` override
  /// exempting it from the guard and reading a large allocation before `emit`
  /// drops the unknown tag (a `parse_in_tiff` divergence + OOM vector). The
  /// EMISSION is unchanged either way (an unknown Canon tag is always dropped), so
  /// this pins the no-panic + walk-continues + production==oracle consistency; the
  /// fix's value is AVOIDING the over-count read.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_exif_override_id_not_applied_under_canon_table() {
    let over_count: u32 = 100_001;
    let filler = std::vec![0u8; over_count as usize];
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x9286, 6, over_count, &[], &filler), // EXIF UserComment id, int8s, excessive
      (0x09, 2, 4, b"Al\0\0", &[]),          // OwnerName, normal leaf
    ];
    let blob = crafted_canon_subtable_ifd(entries);
    let order = ByteOrder::Little;
    let model = Some("Canon EOS 20D");

    for print_conv in [true, false] {
      let (_otyped, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      let (emi, _typed) =
        canon_makernote_isolated(&blob, 0, blob.len(), order, model, None, print_conv);
      // The normal leaf after the over-count 0x9286 still emits — the walk
      // continued, no panic, and the unknown 0x9286 contributes no emission.
      assert!(
        emi.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: OwnerName (after the over-count 0x9286) MUST emit"
      );
      assert_eq!(
        emi.len(),
        oracle.len(),
        "print_conv={print_conv}: production == oracle (Canon applies NO EXIF \
         format override, so the numeric over-count 0x9286 is guard-skipped, NOT \
         undef-coerced and read)"
      );
      for (i, (g, w)) in emi.iter().zip(oracle.iter()).enumerate() {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv} #{i}: name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv} #{i}: value");
      }
    }
  }

  // ====================================================================
  // Canon 0x28 / 0x96 SPECIALS differential proof (#243 phase 2 step B3)
  //
  // PROVES the shared `Walker`'s Canon LIST / Format-override special path
  // (`process_subdir(TableRef::Canon)` → walk-time
  // [`Walker::canon_special_leaf_value`] rewrite → `emit_entry`'s
  // `ResolvedConv::Canon` arm → [`emit_canon_special`], or the leaf renderer
  // for the non-5D 0x96 second arm) is BYTE-IDENTICAL to the production
  // `canon::parse_in_tiff` 0x28 / 0x96 branches (`canon/mod.rs:943-1010`). Four
  // crafted Canon Main IFDs — covering BOTH 0x28 shapes (a non-NUL 16-byte
  // value ⇒ hex `ImageUniqueID`; exactly 16 NUL bytes ⇒ dropped) and BOTH 0x96
  // arms (an EOS-5D body + a SerialInfo-shaped blob ⇒ `serial_info` positions;
  // a NON-5D body + an Ascii value with trailing `0xff` ⇒ `InternalSerialNumber`
  // with the `0xff` stripped) — are run through BOTH paths; the emitted
  // `(name, value, group="MakerNotes:Canon", unknown)` tuples must match, in
  // order, for `-j` AND `-n`. Production keeps `parse_in_tiff`, so conformance
  // stays 416/0.
  // ====================================================================

  /// Assert the shared `Walker` 0x28/0x96 special path emits EXACTLY the same
  /// `(name, value, group, unknown)` stream — in order — as `parse_in_tiff`,
  /// for the crafted `blob` under `model`, for BOTH `-j` and `-n`. Returns the
  /// `-j` (PrintConv) emission so the caller can pin the concrete value(s)
  /// (guarding against a both-paths-identically-wrong drift).
  #[cfg(feature = "alloc")]
  fn assert_canon_special_matches(
    blob: &[u8],
    model: Option<&str>,
  ) -> Vec<crate::emit::EmittedTag> {
    let order = ByteOrder::Little;
    let mut print_conv_emission: Vec<crate::emit::EmittedTag> = Vec::new();
    for print_conv in [true, false] {
      // ---- Oracle: production `parse_in_tiff` (blob IS the whole TIFF,
      // `mn_offset = 0`; `file_type = None` — these specials don't read it).
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        blob,
        0,
        blob.len(),
        order,
        print_conv,
        model,
        None,
      );
      // ---- New path: shared Walker → walk-time rewrite + emit_canon_special.
      let emitted = drive_canon_subdir(blob, order, print_conv, model, None);
      assert_eq!(
        emitted.len(),
        oracle.len(),
        "print_conv={print_conv} model={model:?}: emission COUNT must match \
         (a dropped 0x28 emits NOTHING on both; a 5D 0x96 expands to its \
         SerialInfo positions on both)"
      );
      for (i, (got, want)) in emitted.iter().zip(oracle.iter()).enumerate() {
        let tag = got.tag();
        assert_eq!(
          tag.name(),
          want.name(),
          "print_conv={print_conv} #{i}: NAME mismatch"
        );
        assert_eq!(
          tag.value_ref(),
          want.value(),
          "print_conv={print_conv} #{i} ({}): VALUE mismatch (the rewrite + \
           emit must reproduce parse_in_tiff byte-for-byte)",
          want.name()
        );
        assert_eq!(
          got.unknown(),
          want.unknown(),
          "print_conv={print_conv} #{i} ({}): Unknown flag mismatch",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family0(),
          "MakerNotes",
          "print_conv={print_conv} #{i} ({}): family-0 must be MakerNotes",
          want.name()
        );
        assert_eq!(
          tag.group_ref().family1(),
          "Canon",
          "print_conv={print_conv} #{i} ({}): family-1 must be Canon",
          want.name()
        );
      }
      if print_conv {
        print_conv_emission = emitted;
      }
    }
    print_conv_emission
  }

  /// The 0x28 / 0x96 special-case differential proof — all four cases.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_special_0x28_0x96_emit_matches_parse_in_tiff() {
    use crate::value::TagValue;
    // int8u=1, ASCII=2. Every value here is > 4 bytes, so it is out-of-line
    // (`crafted_canon_subtable_ifd` stages it after the next-IFD word, past the
    // directory extent — never `Suspicious`), resolving to the IDENTICAL window
    // in both walkers (`mn_offset = 0` / `base = 0`).

    // ---- Case 1: 0x28 with a NON-NUL 16-byte value ⇒ hex ImageUniqueID.
    // `int8u[16]` "read as undef[16]"; bytes 0x00..0x0f hex to the 32-char
    // lowercase string below.
    let uid_bytes: [u8; 16] = [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
      0xff,
    ];
    let ifd1 = crafted_canon_subtable_ifd(&[(0x28, 1, 16, &[], &uid_bytes)]);
    let em1 = assert_canon_special_matches(&ifd1, None);
    assert_eq!(
      em1.len(),
      1,
      "a non-NUL 0x28 emits exactly one ImageUniqueID"
    );
    assert_eq!(em1[0].tag().name(), "ImageUniqueID");
    assert_eq!(
      em1[0].tag().value_ref(),
      &TagValue::Str("00112233445566778899aabbccddeeff".into()),
      "0x28 ValueConv is unpack(\"H*\", $val) — lowercase, separator-free hex"
    );

    // ---- Case 2: 0x28 with EXACTLY 16 NUL bytes ⇒ RawConv undef ⇒ DROPPED.
    let uid_zero = [0u8; 16];
    let ifd2 = crafted_canon_subtable_ifd(&[(0x28, 1, 16, &[], &uid_zero)]);
    let em2 = assert_canon_special_matches(&ifd2, None);
    assert!(
      em2.is_empty(),
      "exactly sixteen NUL bytes ⇒ RawConv undef ⇒ NOTHING emitted: {em2:?}"
    );

    // ---- Case 3: 0x96 on an EOS-5D body + a SerialInfo-shaped blob ⇒ the
    // SerialInfo positions (InternalSerialNumber2 / InternalSerialNumber). The
    // blob is the serial_info unit-test vector `"ABC123XYZ" + "DEF456\0"` so the
    // sub-parser actually decodes BOTH positions.
    let serial_blob = b"ABC123XYZDEF456\x00"; // 16 bytes, out-of-line.
    let ifd3 = crafted_canon_subtable_ifd(&[(0x96, 1, serial_blob.len() as u32, &[], serial_blob)]);
    let em3 = assert_canon_special_matches(&ifd3, Some("Canon EOS 5D"));
    assert_eq!(
      em3.len(),
      2,
      "the 5D SerialInfo arm emits InternalSerialNumber2 + InternalSerialNumber"
    );
    assert_eq!(em3[0].tag().name(), "InternalSerialNumber2");
    assert_eq!(em3[0].tag().value_ref(), &TagValue::Str("ABC123XYZ".into()));
    assert_eq!(em3[1].tag().name(), "InternalSerialNumber");
    assert_eq!(em3[1].tag().value_ref(), &TagValue::Str("DEF456".into()));

    // ---- Case 4: 0x96 on a NON-5D body + an Ascii value WITH trailing 0xff ⇒
    // InternalSerialNumber (the LIST's SECOND arm) with the `0xff` stripped
    // (`$val=~s/\xff+$//`). The value falls to the normal leaf renderer (the
    // walk-time rewrite already stripped it), proving the non-5D arm threads
    // through `emit_canon_value` unchanged.
    let serial_ff = b"SN12345\xff\xff\xff"; // 10 bytes, Ascii, out-of-line.
    let ifd4 = crafted_canon_subtable_ifd(&[(0x96, 2, serial_ff.len() as u32, &[], serial_ff)]);
    let em4 = assert_canon_special_matches(&ifd4, Some("Canon EOS Kiss X3"));
    assert_eq!(
      em4.len(),
      1,
      "the non-5D 0x96 emits one InternalSerialNumber"
    );
    assert_eq!(em4[0].tag().name(), "InternalSerialNumber");
    assert_eq!(
      em4[0].tag().value_ref(),
      &TagValue::Str("SN12345".into()),
      "the trailing 0xff bytes must be stripped at the raw-byte level \
       (s/\\xff+$//), leaving the bare serial"
    );
  }

  // ====================================================================// Canon engine migration — Step C isolation differential tests (#243 phase 2)
  //
  // The production switch routes `%Canon::Main` through the shared `Walker` as
  // `process_subdir(.., IfdKind::ExifIfd, TableRef::Canon, .., ProcessProc::Canon)`.
  // The `IfdKind` is `ExifIfd`, but the STRUCTURAL decisions must follow
  // maker-note (vendor-table) semantics, NOT core ExifIFD semantics. These two
  // tests pin the two places where a vendor walk diverges from a core walk —
  // each is asserted byte-identical to the retired `canon::parse_in_tiff` oracle
  // for `-j` AND `-n` (and, because `assert_canon_special_matches` drives BOTH
  // paths, neither panics).
  // ====================================================================

  /// The SubDirectory-pointer-ID collision proof: a `%Canon::Main` tag whose ID
  /// coincides with a CORE `%Exif::Main` pointer (0xa005 InteropOffset, 0x8769
  /// ExifOffset, 0x927c MakerNotes) must be treated as a Canon leaf, NEVER
  /// dispatched as a core sub-IFD.
  ///
  /// `walk_entry`'s SubDirectory dispatch (`sub_dir_for`) is gated on
  /// `active_table.is_core_ifd()`; under `TableRef::Canon` it does not fire, so
  /// the colliding ID flows to the Canon leaf path → `tags::lookup` finds no
  /// `%Canon::Main` def for it → it is OMITTED — exactly as the oracle's
  /// `walk_canon_in_tiff` collects it then `parse_in_tiff` drops it at the
  /// `tags::lookup(..) else continue` site (`canon/mod.rs:742`). Without the
  /// gate, 0xa005 (etc.) would recurse into a CORE Interop/ExifIFD sub-IFD that
  /// pushes `ResolvedConv::Exif` entries — a byte-identity break, and a panic
  /// once those scalar entries reach the `VendorEmissionSink` capture (now a
  /// no-op, but the gate keeps them off it entirely). The valid Canon leaves
  /// surrounding the collisions still emit, in order, on both paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_subdir_id_collision_matches_parse_in_tiff() {
    // int16u=3, int32u=4, ASCII=2. The three core pointer IDs are encoded as a
    // single int32u (count=1, inline ⇒ 4 bytes at `entry+8`) holding an
    // offset-SHAPED value (0x0000_0042) — the exact encoding a real
    // ExifIFD/Interop/MakerNote pointer uses, so the PRE-gate code path would
    // have dispatched them as core sub-IFDs. IFD entries must be tag-ascending,
    // so the colliding IDs sit between the low and high valid leaves.
    let pointer_value = 0x0000_0042u32.to_le_bytes();
    let ifd = crafted_canon_subtable_ifd(&[
      // 0x07 CanonFirmwareVersion — ASCII leaf, conv None. Emitted.
      (0x07, 2, 4, b"1.0\0", &[]),
      // 0x10 CanonModelID — int32u, ModelId hash (0x412 ⇒ EOS M50). Emitted.
      (0x10, 4, 1, &0x0000_0412u32.to_le_bytes(), &[]),
      // 0x8769 (ExifOffset) — NOT a %Canon::Main tag ⇒ OMITTED, never an ExifIFD.
      (0x8769, 4, 1, &pointer_value, &[]),
      // 0x927c (MakerNotes) — NOT a %Canon::Main tag ⇒ OMITTED, never recursed.
      (0x927c, 4, 1, &pointer_value, &[]),
      // 0xa005 (InteropOffset) — NOT a %Canon::Main tag ⇒ OMITTED, never Interop.
      (0xa005, 4, 1, &pointer_value, &[]),
      // 0xb4 ColorSpace — int16u, hash PrintConv (1 ⇒ "sRGB"). Emitted.
      (0xb4, 3, 1, &[0x01, 0x00], &[]),
    ]);
    // Drives BOTH paths for -j and -n and asserts the emitted stream matches in
    // order (a divergence — e.g. a core sub-IFD recursion — would change the
    // count/content; a panic on the collision would fail the test outright).
    let em = assert_canon_special_matches(&ifd, Some("Canon EOS M50"));
    // Exactly the three valid leaves survive; the three pointer-ID collisions
    // are dropped (not in %Canon::Main), proving none was taken as a sub-IFD.
    assert_eq!(
      em.len(),
      3,
      "only the 3 real %Canon::Main leaves emit; 0x8769/0x927c/0xa005 are \
       dropped as unknown Canon tags, NOT dispatched as core sub-IFDs: {em:?}"
    );
    let names: Vec<&str> = em.iter().map(|t| t.tag().name()).collect();
    assert_eq!(
      names,
      ["CanonFirmwareVersion", "CanonModelID", "ColorSpace"],
      "the surviving leaves are the non-colliding Canon tags, in IFD order"
    );
  }

  /// The bad-offset isolation proof: a `%Canon::Main` entry whose out-of-line
  /// value runs past EOF must SKIP (warn "Bad offset" + continue), NOT abort the
  /// maker-note walk — so a later valid Canon leaf still emits.
  ///
  /// A maker-note directory IS `$inMakerNotes`, so ExifTool's
  /// `return 0 unless $inMakerNotes …` (`Exif.pm:6602`) does NOT abort — it
  /// continues with `$bad = 1`. `walk_entry` routes the bad-offset case to the
  /// "Bad offset for {dir} {name}" + `warn_counted` + `Step::Skip` path whenever
  /// `self.no_raf || !active_table.is_core_ifd()`; the production Canon walk runs
  /// RAF-backed (`no_raf == false`) but with `TableRef::Canon`
  /// (`!is_core_ifd()`), so it takes the skip — matching the oracle's
  /// `classify_canon_entry` → `CanonEntryClass::BadOffset` (skip + continue). The
  /// FIRST entry is the bad one (largest blast radius if it aborted); the later
  /// inline OwnerName must still appear on both paths.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_bad_offset_then_valid_matches_parse_in_tiff() {
    use crate::value::TagValue;
    // Build a Canon Main IFD whose FIRST entry (0x06 CanonImageType, ASCII) is
    // out-of-line (size 8 > 4) with an offset PAST EOF, followed by a valid
    // inline OwnerName (0x09) leaf. `crafted_canon_subtable_ifd` only emits
    // in-bounds offsets, so this IFD is built by hand to plant the bad offset.
    let n = 2usize;
    let mut ifd = Vec::new();
    ifd.extend_from_slice(&(n as u16).to_le_bytes());
    // Entry 0: 0x06 CanonImageType, ASCII, count=8 ⇒ size 8 (> 4, out-of-line).
    // The 4 value bytes are an offset FAR past the end of the buffer.
    ifd.extend_from_slice(&0x0006u16.to_le_bytes());
    ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    ifd.extend_from_slice(&8u32.to_le_bytes()); // count = 8 ⇒ size 8
    ifd.extend_from_slice(&0x0000_8000u32.to_le_bytes()); // offset past EOF ⇒ Bad offset
    // Entry 1: 0x09 OwnerName, ASCII, count=4, INLINE "Al\0\0" — must survive.
    ifd.extend_from_slice(&0x0009u16.to_le_bytes());
    ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    ifd.extend_from_slice(&4u32.to_le_bytes()); // count = 4 (inline)
    ifd.extend_from_slice(b"Al\0\0");
    // Next-IFD pointer word = 0 (the ExifIfd-kind walk never follows the chain).
    ifd.extend_from_slice(&0u32.to_le_bytes());

    // Drives BOTH paths for -j and -n; an ABORT on the bad entry would drop
    // OwnerName from the new path (a COUNT mismatch vs the oracle, which skips
    // + continues), and any panic would fail outright.
    let em = assert_canon_special_matches(&ifd, None);
    assert_eq!(
      em.len(),
      1,
      "the bad-offset 0x06 is SKIPPED (not aborting); the later inline \
       OwnerName still emits: {em:?}"
    );
    assert_eq!(em[0].tag().name(), "OwnerName");
    assert_eq!(
      em[0].tag().value_ref(),
      &TagValue::Str("Al".into()),
      "OwnerName survives the bad-offset entry that precedes it"
    );
  }

  // ====================================================================// Canon engine migration — Step C core-state-leak isolation (#243 phase 2)
  //
  // The production switch shares the Walker's MUTABLE STATE between the parent
  // ExifIFD walk and the Canon (vendor) sub-walk. Three pieces of CORE state must
  // NOT be affected by the vendor walk; these tests pin each against the retired
  // `canon::parse_in_tiff` oracle (which has ZERO core/file-level side effects):
  //   1. file-level `page_count`/`multi_page`/`dng_version` (the SubfileType /
  //      OldSubfileType / DNGVersion RawConv taps) — core-table-gated, so a
  //      collision-id Canon leaf does not synthesize a bogus `File:PageCount` or
  //      finalize a standalone TIFF as DNG;
  //   2. the per-directory `warn_count` abort cap — saved/restored across the
  //      Canon sub-walk, so a Canon MakerNote full of bad entries does not abort
  //      the PARENT ExifIFD (dropping its later tags);
  //   3. the `%CameraSettings` DataMember pre-scan — last-readable-0x01-wins, so a
  //      malformed FIRST 0x01 then a valid 0x01 yields the VALID one's members.
  // ====================================================================

  /// Build a Canon Main IFD whose leaves include the three CORE file-level
  /// RawConv-tap collision IDs — `SubfileType` (0x00fe), `OldSubfileType`
  /// (0x00ff), `DNGVersion` (0xc612) — each carrying a value that WOULD trip the
  /// tap if it fired under `%Exif::Main`: SubfileType=2 (⇒ MultiPage),
  /// OldSubfileType=3 (⇒ MultiPage), DNGVersion `1 1 0 0` (truthy ⇒ DNG). None of
  /// these IDs is a `%Canon::Main` tag, so all three are dropped as unknown Canon
  /// leaves; the surrounding valid Canon leaves (0x07/0x09) emit. Tag-ascending.
  #[cfg(feature = "alloc")]
  fn crafted_canon_ifd_with_tap_collision_ids() -> Vec<u8> {
    crafted_canon_subtable_ifd(&[
      // 0x07 CanonFirmwareVersion — ASCII leaf, conv None. Emitted.
      (0x07, 2, 4, b"1.0\0", &[]),
      // 0x09 OwnerName — ASCII leaf, conv None. Emitted.
      (0x09, 2, 4, b"Al\0\0", &[]),
      // 0x00fe SubfileType, int32u=4, count 1, value 2 (the `$val == 2` MultiPage
      // trigger). NOT a %Canon::Main tag ⇒ dropped; the tap must NOT fire.
      (0x00fe, 4, 1, &2u32.to_le_bytes(), &[]),
      // 0x00ff OldSubfileType, int16u=3, count 1, value 3 (the `$val == 3`
      // MultiPage trigger). NOT a %Canon::Main tag ⇒ dropped; tap must NOT fire.
      (0x00ff, 3, 1, &[0x03, 0x00], &[]),
      // 0xc612 DNGVersion, int8u=1, count 4, TRUTHY `1 1 0 0` ⇒ would finalize as
      // DNG. NOT a %Canon::Main tag ⇒ dropped; the tap must NOT fire.
      (0xc612, 1, 4, &[0x01, 0x01, 0x00, 0x00], &[]),
    ])
  }

  /// Finding 2 (white-box): the three file-level RawConv taps (SubfileType /
  /// OldSubfileType / DNGVersion) are gated on the CORE Exif/Interop tables, so
  /// driving a Canon (`TableRef::Canon`) walk whose leaves carry the colliding
  /// IDs leaves `page_count` / `multi_page` / `dng_version` UNTOUCHED — and the
  /// emitted stream still matches `parse_in_tiff` (the collision IDs are dropped
  /// as unknown Canon tags on both paths, for `-j` and `-n`).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_walk_does_not_fire_core_file_level_taps() {
    let blob = crafted_canon_ifd_with_tap_collision_ids();
    let order = ByteOrder::Little;
    // Differential: the unknown collision IDs are dropped on BOTH paths, so only
    // the two valid leaves (0x07/0x09) emit — in order, for -j AND -n.
    let em = assert_canon_special_matches(&blob, Some("Canon EOS 5D"));
    let names: Vec<&str> = em.iter().map(|t| t.tag().name()).collect();
    assert_eq!(
      names,
      ["CanonFirmwareVersion", "OwnerName"],
      "the 0x00fe/0x00ff/0xc612 collision IDs are dropped as unknown Canon tags; \
       only the valid leaves emit: {em:?}"
    );
    // THE DISCRIMINATOR: run the SAME blob through `process_subdir(TableRef::Canon)`
    // and inspect the walker's file-level state directly. The taps must NOT have
    // fired (they are gated on `active_table ∈ {Exif, Interop}`), so the
    // standalone-TIFF finalization would synthesize neither a bogus PageCount nor
    // a DNG re-type.
    let mut w = test_walker(&blob);
    w.order = order;
    w.captured_model = Some("Canon EOS 5D".to_string());
    w.process_subdir(
      0,
      IfdKind::ExifIfd,
      TableRef::Canon,
      ByteOrderRule::Fixed(order),
      FixBaseMode::No,
      ProcessProc::Canon,
    );
    assert_eq!(
      w.page_count, 0,
      "SubfileType (0x00fe) / OldSubfileType (0x00ff) taps must NOT bump \
       page_count under %Canon::Main"
    );
    assert!(
      !w.multi_page,
      "neither SubfileType=2 nor OldSubfileType=3 may set multi_page under \
       %Canon::Main (the tap is Exif/Interop-scoped)"
    );
    assert!(
      !w.dng_version,
      "the DNGVersion (0xc612) tap must NOT set dng_version under %Canon::Main \
       (a vendor leaf must never re-type the file as DNG)"
    );
  }

  /// Build a LITTLE-ENDIAN standalone TIFF whose Canon MakerNote is `canon_ifd`:
  ///   IFD0@8: Make (0x010f) = "Canon\0" + ExifOffset (0x8769) -> ExifIFD.
  ///   ExifIFD: MakerNote (0x927c, UNDEF) -> `canon_ifd`, then (optionally) an
  ///   `extra` ExifIFD entry whose 12-byte record + out-of-line value bytes are
  ///   supplied by the caller (used to place a parent tag AFTER the maker note in
  ///   tag order). All values are out-of-line, appended after both IFDs.
  ///
  /// LITTLE-ENDIAN so the on-disk byte order matches the `to_le_bytes` Canon
  /// blobs (`crafted_canon_subtable_ifd`, etc.) — the Canon MakerNote INHERITS
  /// the parent order (`ByteOrderRule::Fixed(self.order)`), so a big-endian
  /// parent would misread an LE Canon count word and abort the sub-walk.
  ///
  /// `extra` is `(entry_record_12_bytes, out_of_line_value_bytes)`; the record's
  /// last 4 bytes (the value offset slot) are PATCHED to point at the appended
  /// value. Pass an empty record for "no extra entry".
  #[cfg(feature = "alloc")]
  fn le_tiff_canon_makernote(canon_ifd: &[u8], extra: (&[u8], &[u8])) -> Vec<u8> {
    let (extra_record, extra_value) = extra;
    let has_extra = !extra_record.is_empty();
    assert!(
      !has_extra || extra_record.len() == 12,
      "extra is one IFD entry"
    );
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    // IFD0@8: 2 entries (Make, ExifOffset).
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&0x010fu16.to_le_bytes()); // Make
    t.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    t.extend_from_slice(&6u32.to_le_bytes()); // count 6 ("Canon\0")
    let make_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // Make value offset (patch)
    t.extend_from_slice(&0x8769u16.to_le_bytes()); // ExifOffset
    t.extend_from_slice(&4u16.to_le_bytes()); // LONG
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    let exif_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD offset (patch)
    t.extend_from_slice(&0u32.to_le_bytes()); // IFD0 next = 0
    // "Canon\0" value.
    let make_val_off = t.len() as u32;
    t.extend_from_slice(b"Canon\0");
    t[make_ptr_pos..make_ptr_pos + 4].copy_from_slice(&make_val_off.to_le_bytes());
    // ExifIFD: MakerNote (+ optional extra entry).
    let exififd_off = t.len() as u32;
    t[exif_ptr_pos..exif_ptr_pos + 4].copy_from_slice(&exififd_off.to_le_bytes());
    let n_exif: u16 = if has_extra { 2 } else { 1 };
    t.extend_from_slice(&n_exif.to_le_bytes());
    // MakerNote (0x927c), UNDEFINED, count = blob len, value offset (patch).
    t.extend_from_slice(&0x927cu16.to_le_bytes());
    t.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
    t.extend_from_slice(&(canon_ifd.len() as u32).to_le_bytes());
    let mn_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes());
    let mut extra_ptr_pos = 0usize;
    if has_extra {
      // The caller's 12-byte record (tag/format/count + a placeholder offset).
      extra_ptr_pos = t.len() + 8; // the value-offset slot is the last 4 bytes
      t.extend_from_slice(extra_record);
    }
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD next = 0
    // The Canon MakerNote blob, then the extra value bytes; patch both pointers.
    let mn_val_off = t.len() as u32;
    t.extend_from_slice(canon_ifd);
    t[mn_ptr_pos..mn_ptr_pos + 4].copy_from_slice(&mn_val_off.to_le_bytes());
    if has_extra {
      let extra_val_off = t.len() as u32;
      t.extend_from_slice(extra_value);
      t[extra_ptr_pos..extra_ptr_pos + 4].copy_from_slice(&extra_val_off.to_le_bytes());
    }
    t
  }

  /// Finding 2 (end-to-end): a STANDALONE TIFF whose Canon MakerNote carries the
  /// 0x00fe / 0x00ff / 0xc612 collision IDs emits NO synthesized `File:PageCount`
  /// and is NOT finalized as DNG — proving the taps stay off through the real
  /// `parse_borrowed` dispatch (IFD0 Make="Canon" ⇒ the 0x927c MakerNote walks
  /// `%Canon::Main` via the shared Walker). A leak would set `multi_page_count` /
  /// `has_dng_version()` from the dropped vendor leaves.
  #[test]
  #[cfg(feature = "alloc")]
  fn standalone_tiff_canon_makernote_collision_ids_do_not_leak_file_state() {
    let canon_ifd = crafted_canon_ifd_with_tap_collision_ids();
    let t = le_tiff_canon_makernote(&canon_ifd, (&[], &[]));
    let meta = parse_borrowed(&t).expect("standalone TIFF parses");
    // SANITY: the Canon MakerNote WAS dispatched (Make="Canon" ⇒ Vendor::Canon)
    // AND its valid leaves emit — i.e. the collision-ID blob really walked
    // `%Canon::Main` (otherwise the assertions below would be vacuous).
    let mn = meta
      .maker_note()
      .expect("IFD0 Make=Canon + a 0x927c MakerNote must dispatch a Canon maker note");
    // The Canon leaves emit via the cached vendor emissions (truncated off
    // `entries`), so check there: the valid leaves must be present, proving the
    // collision-ID blob really walked `%Canon::Main` (else this test is vacuous).
    assert!(
      mn.emissions_print_conv()
        .iter()
        .any(|e| e.name() == "CanonFirmwareVersion"),
      "the Canon Main IFD's valid leaves must emit (the sub-walk really ran): {:?}",
      mn.emissions_print_conv()
        .iter()
        .map(makernotes::VendorEmission::name)
        .collect::<Vec<_>>()
    );
    // THE DISCRIMINATORS — the file-level state stays clean:
    assert_eq!(
      meta.multi_page_count(),
      None,
      "the Canon MakerNote's 0x00fe=2 / 0x00ff=3 collision leaves must NOT \
       synthesize a bogus File:PageCount (the taps are Exif/Interop-scoped)"
    );
    assert!(
      !meta.has_dng_version(),
      "the Canon MakerNote's 0xc612 collision leaf must NOT finalize the \
       standalone TIFF as DNG"
    );
  }

  /// Finding 1: a Canon MakerNote with 11+ bad (warn-counted) entries must NOT
  /// abort the PARENT ExifIFD. `warn_count` is saved/restored across the Canon
  /// sub-walk (it is a per-`ProcessExif`-call `my` local in bundled), so the
  /// child's accumulated count never reaches the parent's `> 10` abort — the
  /// parent's later `UserComment` leaf still emits. Without the restore the
  /// child's 11 warnings would trip the parent loop's abort and drop it.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_makernote_warn_count_does_not_abort_parent_exififd() {
    // A Canon Main IFD with TWELVE bad-offset entries (each an out-of-line value
    // past EOF ⇒ `CanonEntryClass::BadOffset` ⇒ ++warnCount, skip + continue).
    // Twelve > 10, so the Canon sub-walk hits its OWN abort cap — that must NOT
    // propagate to the parent. None is index-0 bad-FORMAT, so the Canon directory
    // is not aborted at entry 0 (the bad entries are skips, and the directory
    // shape itself is valid). Little-endian (inherits the parent order).
    let bad_n = 12u16;
    let mut canon_ifd = Vec::new();
    canon_ifd.extend_from_slice(&bad_n.to_le_bytes());
    for _ in 0..bad_n {
      // 0x9a (a valid %Canon::Main id) out-of-line ASCII count=8 ⇒ size 8 > 4,
      // offset far past EOF ⇒ Bad offset (warn-counted skip).
      canon_ifd.extend_from_slice(&0x009au16.to_le_bytes());
      canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
      canon_ifd.extend_from_slice(&8u32.to_le_bytes()); // count 8 ⇒ size 8
      canon_ifd.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // offset past EOF
    }
    canon_ifd.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    // UserComment (0x9286) is placed AFTER the maker note in the ExifIFD (0x927c <
    // 0x9286), so the parent loop reaches it AFTER returning from the Canon
    // sub-walk. UNDEFINED count 12: an 8-byte "ASCII\0\0\0" charset prefix + "Hi".
    let uc_bytes: &[u8] = b"ASCII\0\0\0Hi\0\0";
    let mut uc_record = Vec::new();
    uc_record.extend_from_slice(&0x9286u16.to_le_bytes());
    uc_record.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
    uc_record.extend_from_slice(&(uc_bytes.len() as u32).to_le_bytes());
    uc_record.extend_from_slice(&0u32.to_le_bytes()); // value offset (patched)

    let t = le_tiff_canon_makernote(&canon_ifd, (&uc_record, uc_bytes));
    let meta = parse_borrowed(&t).expect("standalone TIFF parses");
    // SANITY: the Canon MakerNote really dispatched (so the >10 warnings were
    // actually generated by the sub-walk, not skipped).
    assert!(
      meta.maker_note().is_some(),
      "the Canon MakerNote must dispatch (else the warn-count scenario is vacuous)"
    );
    // THE DISCRIMINATOR: the parent ExifIFD's UserComment survives — the Canon
    // sub-walk's 12 warnings were scoped to it (saved/restored), so the parent
    // loop's `> 10` abort never tripped.
    assert!(
      meta
        .entries()
        .iter()
        .any(|e| e.ifd() == IfdKind::ExifIfd && e.name() == "UserComment"),
      "UserComment (after the Canon MakerNote in tag order) must STILL emit — the \
       child Canon walk's warn_count must not abort the parent ExifIFD: {:?}",
      meta
        .entries()
        .iter()
        .map(|e| (e.ifd(), e.name()))
        .collect::<Vec<_>>()
    );
  }

  /// R3-1 (warnings isolation): a Canon MakerNote whose entry is malformed
  /// (out-of-line value past EOF ⇒ a `"Bad offset for ExifIFD <tag>"` warn-counted
  /// SKIP) must NOT surface that warning on the parent `ExifMeta` — the isolated
  /// Canon walk owns its own `warnings` channel, which is DISCARDED on return. The
  /// oracle `canon::parse_in_tiff` emits no such warning (it walks Canon with no
  /// core `$et->Warn` side effect), so the production stream must show none either,
  /// while the later VALID Canon leaf still emits.
  ///
  /// Pre-isolation the Canon walk ran on `self`, so the bad-offset warning landed
  /// in the parent's `warnings` and surfaced as a spurious `ExifTool:Warning` the
  /// oracle never produces — the R3-1 leak this structural fix closes.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_makernote_bad_offset_does_not_leak_core_warning() {
    // A Canon Main IFD: entry 0 is 0x06 CanonImageType (ASCII, count 8 ⇒ size 8 >
    // 4, out-of-line) with an offset FAR past EOF ⇒ "Bad offset for ExifIFD
    // CanonImageType" (warn-counted skip), then a valid inline OwnerName (0x09).
    let mut canon_ifd = Vec::new();
    canon_ifd.extend_from_slice(&2u16.to_le_bytes());
    canon_ifd.extend_from_slice(&0x0006u16.to_le_bytes()); // 0x06 CanonImageType
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&8u32.to_le_bytes()); // count 8 ⇒ size 8 (out-of-line)
    canon_ifd.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // offset past EOF
    canon_ifd.extend_from_slice(&0x0009u16.to_le_bytes()); // 0x09 OwnerName
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    canon_ifd.extend_from_slice(b"Al\0\0");
    canon_ifd.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    let t = le_tiff_canon_makernote(&canon_ifd, (&[], &[]));
    let meta = parse_borrowed(&t).expect("standalone TIFF parses");

    // SANITY: the Canon MakerNote really dispatched AND the valid leaf emitted —
    // so the bad-offset entry really walked `%Canon::Main` (else this is vacuous).
    let mn = meta
      .maker_note()
      .expect("IFD0 Make=Canon + a 0x927c MakerNote must dispatch a Canon maker note");
    assert!(
      mn.emissions_print_conv()
        .iter()
        .any(|e| e.name() == "OwnerName"),
      "the later valid Canon OwnerName leaf must still emit after the bad-offset \
       entry (a skip, not an abort): {:?}",
      mn.emissions_print_conv()
        .iter()
        .map(makernotes::VendorEmission::name)
        .collect::<Vec<_>>()
    );

    // THE DISCRIMINATOR: NO core warning leaked. The isolated Canon walk's
    // "Bad offset for ExifIFD CanonImageType" warning is discarded with the fresh
    // walker — it must NOT appear on the parent meta (the oracle emits none).
    assert!(
      !meta.warnings().iter().any(|w| w.contains("Bad offset")),
      "the isolated Canon walk's Bad-offset warning must NOT leak to the parent \
       ExifMeta (parse_in_tiff emits no such warning): {:?}",
      meta.warnings()
    );
    assert!(
      !meta.warnings().iter().any(|w| w.contains("ExifIFD")),
      "no Canon-walk ExifIFD-directory warning may surface on the parent: {:?}",
      meta.warnings()
    );
  }

  /// R3-2 (active-path isolation, end-to-end): a Canon MakerNote whose value
  /// offset coincides with a PARENT IFD offset on the active recursion path (here
  /// 8, the IFD0 offset) must STILL be walked — the production stream must match
  /// `canon::parse_in_tiff` driven at the SAME offset. The fresh, pathless walker
  /// has no ancestor to collide with, so its [`walk_one_ifd`] cycle guard cannot
  /// suppress the Canon Main IFD.
  ///
  /// IFD0@8 holds, in tag order, `OwnerName` (0x0009 — unknown to `%Exif::Main`
  /// so dropped by the parent, but a valid `%Canon::Main` LEAF), `Make` (0x010f =
  /// "Canon") and `ExifOffset` (0x8769). When the isolated Canon walk re-reads
  /// offset 8 as a Canon Main IFD it emits `OwnerName` — a NON-empty proof the
  /// walk proceeded. The MakerNote's out-of-line value window is kept small enough
  /// (10 bytes) that it ends before the ExifIFD, so the suspicious/overlap guard
  /// (`Exif.pm:6549`) admits the entry and the active-path guard is the only thing
  /// that could (wrongly) suppress the walk.
  ///
  /// Pre-isolation the Canon walk ran on `self`, whose `active_ifd_offsets` held
  /// {8, ExifIFD-offset}; a value offset of 8 hit the ancestor guard, the Canon
  /// Main IFD was SUPPRESSED, and `OwnerName` was DROPPED — diverging from the
  /// oracle (which always walks it). This is the R3-2 leak the structural fix
  /// closes.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_makernote_value_offset_at_ancestor_is_still_walked() {
    // A standalone LE TIFF built by hand so the MakerNote pointer can target
    // offset 8 (the helpers append the blob, so they cannot).
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    // IFD0@8: 3 entries (tag-ascending) — OwnerName(0x0009), Make(0x010f),
    // ExifOffset(0x8769). OwnerName is a %Canon::Main LEAF but unknown to
    // %Exif::Main (so the parent IFD0 walk drops it); the Canon re-read of
    // offset 8 emits it.
    t.extend_from_slice(&3u16.to_le_bytes());
    // 0x0009 OwnerName, ASCII, count 4, INLINE "Al\0\0".
    t.extend_from_slice(&0x0009u16.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    t.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    t.extend_from_slice(b"Al\0\0");
    // 0x010f Make, ASCII, count 6 ("Canon\0"), out-of-line (patched).
    t.extend_from_slice(&0x010fu16.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    t.extend_from_slice(&6u32.to_le_bytes()); // count 6
    let make_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // Make value offset (patch)
    // 0x8769 ExifOffset, LONG, count 1, value = ExifIFD offset (patched).
    t.extend_from_slice(&0x8769u16.to_le_bytes());
    t.extend_from_slice(&4u16.to_le_bytes()); // LONG
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    let exif_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD offset (patch)
    t.extend_from_slice(&0u32.to_le_bytes()); // IFD0 next = 0
    // "Canon\0" value.
    let make_val_off = t.len() as u32;
    t.extend_from_slice(b"Canon\0");
    t[make_ptr_pos..make_ptr_pos + 4].copy_from_slice(&make_val_off.to_le_bytes());
    // ExifIFD: ONE entry, MakerNote (0x927c) whose value offset = 8 (IFD0, an
    // ACTIVE ancestor during the maker-note walk). UNDEFINED count 10 ⇒ size 10
    // (> 4, out-of-line), and the window [8, 18) ends before this ExifIFD ⇒ the
    // suspicious/overlap guard admits it. The Canon walk reads its OWN entry-count
    // word at offset 8 (it is not limited to the 10-byte window).
    let exififd_off = t.len() as u32;
    t[exif_ptr_pos..exif_ptr_pos + 4].copy_from_slice(&exififd_off.to_le_bytes());
    assert!(
      exififd_off >= 18,
      "the MakerNote window [8,18) must end before the ExifIFD@{exififd_off} so the \
       overlap guard does not pre-empt the active-path scenario"
    );
    let mn_len = 10u32;
    t.extend_from_slice(&1u16.to_le_bytes()); // 1 ExifIFD entry
    t.extend_from_slice(&0x927cu16.to_le_bytes()); // MakerNote
    t.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
    t.extend_from_slice(&mn_len.to_le_bytes()); // count 10 ⇒ size 10
    t.extend_from_slice(&8u32.to_le_bytes()); // value offset = 8 (IFD0 — an ancestor)
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD next = 0

    let meta = parse_borrowed(&t).expect("standalone TIFF parses");
    // The MakerNote dispatched (Make=Canon ⇒ Vendor::Canon).
    let mn = meta
      .maker_note()
      .expect("IFD0 Make=Canon + a 0x927c MakerNote must dispatch a Canon maker note");

    // Oracle: walk the SAME bytes at the SAME offset (8) in isolation. parse_in_tiff
    // has no active path, so it always walks offset 8 and emits OwnerName; the
    // production walk must match it (proving the ancestor guard did not suppress it).
    for print_conv in [true, false] {
      let (_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &t,
        8,
        mn_len as usize,
        ByteOrder::Little,
        print_conv,
        Some("Canon"),
        None,
      );
      let got = if print_conv {
        mn.emissions_print_conv().to_vec()
      } else {
        mn.emissions_value_conv()
      };
      // SANITY: the walk really emitted OwnerName (offset 8 was walked, not
      // suppressed, and not vacuously empty).
      assert!(
        oracle.iter().any(|e| e.name() == "OwnerName"),
        "oracle must emit OwnerName from the Canon IFD at offset 8 (else vacuous)"
      );
      assert_eq!(
        got.len(),
        oracle.len(),
        "print_conv={print_conv}: the Canon Main IFD at the ancestor offset 8 must \
         be walked identically to parse_in_tiff (the active-path guard must NOT \
         suppress it). got={:?} oracle={:?}",
        got
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>(),
        oracle
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      for (g, w) in got.iter().zip(oracle.iter()) {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv}: leaf name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv}: leaf value");
      }
      assert!(
        got.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: production must emit OwnerName from offset 8 — \
         the active-path guard must not suppress the isolated Canon walk: {:?}",
        got
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
    }
  }

  /// R3-2 (active-path isolation, white-box): [`canon_makernote_isolated`] builds
  /// a FRESH walker, so it ignores any parent active recursion path. Driving it
  /// with an `mn_offset` that a HYPOTHETICAL parent would hold on its
  /// `active_ifd_offsets` still walks the Canon Main IFD and emits its leaves —
  /// the structural guarantee the end-to-end test exercises, pinned directly.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_isolated_helper_ignores_parent_active_path() {
    // A standalone Canon Main IFD with one valid inline leaf (OwnerName).
    let mut canon_ifd = Vec::new();
    canon_ifd.extend_from_slice(&1u16.to_le_bytes());
    canon_ifd.extend_from_slice(&0x0009u16.to_le_bytes()); // 0x09 OwnerName
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    canon_ifd.extend_from_slice(b"Al\0\0");
    canon_ifd.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0

    // A parent walker whose active path ALREADY contains offset 0 (the Canon Main
    // IFD start). The coupled (pre-fix) `process_subdir` on THIS walker would hit
    // the ancestor guard and walk nothing; the isolated helper does not consult
    // `parent`, so it walks regardless.
    let mut parent = test_walker(&canon_ifd);
    parent.active_ifd_offsets.push(0);

    let (emissions, typed) = canon_makernote_isolated(
      &canon_ifd,
      0,
      canon_ifd.len(),
      ByteOrder::Little,
      Some("Canon"),
      None,
      true,
    );
    assert!(typed.is_some(), "print_conv=true yields the typed slot");
    assert!(
      emissions.iter().any(|e| e.name() == "OwnerName"),
      "the isolated helper walks the Canon Main IFD even when offset 0 is on a \
       parent's active path (it uses a fresh, pathless walker): {:?}",
      emissions
        .iter()
        .map(makernotes::VendorEmission::name)
        .collect::<Vec<_>>()
    );
    // The parent's active path is UNTOUCHED by the isolated walk.
    assert_eq!(
      parent.active_ifd_offsets,
      std::vec![0usize],
      "the isolated walk must not mutate the parent's active path"
    );
  }

  /// R7 (verify-before-fix): the Canon maker-note IFD entry walk is bounded by the
  /// PARENT TIFF buffer (`data.len()` == ExifTool's `$dataLen`), NOT by the
  /// declared maker-note length `mn_len` (`$dirLen`). ExifTool's `ProcessExif`
  /// only undefs `$dirSize` — the abort/clamp trigger — when the claimed IFD ALSO
  /// exceeds `$dataLen` (`Exif.pm:6356`, INSIDE `if ($dirSize > $dirLen)` at 6349);
  /// `$dirLen` on its own drives only a VERBOSE-mode "Short directory size"
  /// warning (`6349-6354`), never the entry bound. (`$dataLen` for an inline maker
  /// note is the parent buffer — `$valueDataLen` defaults to the parent `$dataLen`,
  /// `Exif.pm:6483`/`7124`.) So a maker note whose count word claims entries
  /// extending past `mn_offset + mn_len`, but still within the parent buffer, is
  /// FULLY walked — emitting tags from beyond the declared value EXACTLY as
  /// ExifTool does. Bounding the walk by `mn_len` would make the port STRICTER
  /// than ExifTool (a divergence), so [`canon_makernote_isolated`] uses `mn_len`
  /// ONLY for the `< 2` count-word guard, never the walk extent. This pins that
  /// faithfulness: an UNDER-DECLARED `mn_len` does NOT truncate the walk, and the
  /// stream is byte-identical to `parse_in_tiff` (the retired oracle, likewise
  /// parent-bounded). (The narrow `$dirLen`-clamp SALVAGE at `Exif.pm:6384-6388` —
  /// reached only when the claim ALSO overruns the parent — is a SEPARATE
  /// pre-existing gap shared with `parse_in_tiff`, tracked as a follow-up.)
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_isolated_walk_is_parent_bounded_not_mn_len_bounded() {
    // A standalone Canon Main IFD with TWO inline ASCII leaves (count word = 2):
    // 0x07 CanonFirmwareVersion then 0x09 OwnerName. Extent = 2 + 24 + 4 = 30.
    let mut canon_ifd = Vec::new();
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // count word = 2 entries
    canon_ifd.extend_from_slice(&0x0007u16.to_le_bytes()); // 0x07 FirmwareVersion
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    canon_ifd.extend_from_slice(b"1.0\0");
    canon_ifd.extend_from_slice(&0x0009u16.to_le_bytes()); // 0x09 OwnerName @ offset 14
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    canon_ifd.extend_from_slice(b"Al\0\0");
    canon_ifd.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    assert_eq!(canon_ifd.len(), 30);

    // mn_len = 14 UNDER-DECLARES the IFD (14 bytes = count word + ONE entry); the
    // second entry (0x09 OwnerName) begins at offset 14 — ENTIRELY past mn_len.
    // The count word claims TWO and both fit within the parent (len 30), so the
    // parent-bounded walk (Exif.pm:6356) emits BOTH; an mn_len bound would
    // wrongly drop OwnerName.
    let under_declared_mn_len = 14;
    let order = ByteOrder::Little;
    let model = Some("Canon");

    for print_conv in [true, false] {
      let (emissions, _typed) = canon_makernote_isolated(
        &canon_ifd,
        0,
        under_declared_mn_len,
        order,
        model,
        None,
        print_conv,
      );
      // Oracle: parse_in_tiff at the SAME under-declared mn_len — likewise
      // parent-bounded (it uses tiff_data.len(), not mn_len, for the extent).
      let (_otyped, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &canon_ifd,
        0,
        under_declared_mn_len,
        order,
        print_conv,
        model,
        None,
      );
      // The SECOND leaf — which begins past mn_len=14 — MUST still emit (the walk
      // is parent-bounded, not mn_len-bounded).
      assert!(
        emissions.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: OwnerName (offset 14, past mn_len=14) MUST emit \
         — the walk is parent-bounded, not mn_len-bounded (Exif.pm:6356): {:?}",
        emissions
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      // Byte-identical to the retired oracle (both parent-bounded), proving the
      // shared Walker introduces no stricter bound than parse_in_tiff.
      assert_eq!(
        emissions.len(),
        oracle.len(),
        "print_conv={print_conv}: isolated walk must match parse_in_tiff \
         (both parent-bounded — neither truncates at mn_len)"
      );
      assert!(
        emissions.len() >= 2,
        "print_conv={print_conv}: BOTH leaves must walk (not truncated at mn_len)"
      );
      for (g, w) in emissions.iter().zip(oracle.iter()) {
        assert_eq!(g.name(), w.name(), "print_conv={print_conv}: leaf name");
        assert_eq!(g.value(), w.value(), "print_conv={print_conv}: leaf value");
      }
    }
  }

  /// Finding 3: the `%CameraSettings` DataMember pre-scan is LAST-readable-wins,
  /// matching `parse_in_tiff`'s sub-pass. A Canon IFD with a malformed FIRST 0x01
  /// (CameraSettings) — an out-of-line value past EOF (a `BadOffset` skip) —
  /// followed by a VALID 0x01 carrying FocalUnits=10 / LensType=124, then a
  /// FocalLength (0x02) and FileInfo (0x93), must thread the VALID 0x01's
  /// DataMembers: FocalLength renders "55 mm" (550 ÷ 10, NOT "550 mm") and
  /// FileInfo's MacroMagnification emits (gated on LensType==124). The old
  /// pre-scan stopped at / bailed on the first 0x01, leaving both members `None`
  /// (a DIVERGENCE). Both paths (`parse_in_tiff` oracle vs the shared Walker) must
  /// agree, for -j AND -n, AND the concrete values prove the VALID 0x01 won.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_prescan_bad_first_camerasettings_then_valid_uses_valid() {
    use crate::value::TagValue;
    // ---- The VALID CameraSettings (0x01), int16s. Word 0 = blob byte-length;
    // word 22 (LensType) = 124 (MP-E 65mm, the MacroMagnification gate); word 25
    // (FocalUnits) = 10 (the FocalLength divisor).
    let mut cs_words = [0i16; 26];
    cs_words[0] = (cs_words.len() * 2) as i16;
    cs_words[22] = 124;
    cs_words[25] = 10;
    let camera_settings = i16_words_le(&cs_words);
    // ---- FocalLength (0x02), int16u: [FocalType=2, FocalLength=550, 0, 0] ⇒
    // "55 mm" with FocalUnits=10 (a broken thread would yield "550 mm").
    let fl_words: [u16; 4] = [2, 550, 0, 0];
    let focal_length = u16_words_le(&fl_words);
    // ---- FileInfo (0x93), int16s: word 16 (MacroMagnification) = 75 ⇒ "1.0x",
    // emitted ONLY when LensType == 124.
    let mut fi_words = [0i16; 17];
    fi_words[16] = 75;
    let file_info = i16_words_le(&fi_words);

    // Hand-build the IFD: a bad FIRST 0x01 (out-of-line ASCII past EOF ⇒ skip),
    // then the valid 0x01 / 0x02 / 0x93 as in-bounds out-of-line records. The
    // `crafted_canon_subtable_ifd` helper can stage only in-bounds payloads, so
    // build by hand to plant the bad first 0x01.
    let n: u16 = 4;
    let header_len = 2 + 12 * (n as usize) + 4; // count + entries + next-IFD word
    // Stage the three valid payloads after the header, in entry order.
    let valid_payloads: [&[u8]; 3] = [&camera_settings, &focal_length, &file_info];
    let mut payload_offsets = [0u32; 3];
    {
      let mut off = header_len;
      for (i, p) in valid_payloads.iter().enumerate() {
        payload_offsets[i] = off as u32;
        off += p.len();
      }
    }
    let mut ifd = Vec::new();
    ifd.extend_from_slice(&n.to_le_bytes());
    // Entry 0: 0x01 CameraSettings, ASCII, count 8 ⇒ size 8 > 4, offset PAST EOF
    // ⇒ BadOffset (skip + continue) — the malformed FIRST 0x01.
    ifd.extend_from_slice(&0x0001u16.to_le_bytes());
    ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    ifd.extend_from_slice(&8u32.to_le_bytes()); // count 8 ⇒ size 8
    ifd.extend_from_slice(&0x0000_8000u32.to_le_bytes()); // offset past EOF
    // Entry 1: 0x01 CameraSettings (VALID), int16s, out-of-line at payload[0].
    ifd.extend_from_slice(&0x0001u16.to_le_bytes());
    ifd.extend_from_slice(&8u16.to_le_bytes()); // int16s
    ifd.extend_from_slice(&(cs_words.len() as u32).to_le_bytes());
    ifd.extend_from_slice(&payload_offsets[0].to_le_bytes());
    // Entry 2: 0x02 FocalLength, int16u, out-of-line at payload[1].
    ifd.extend_from_slice(&0x0002u16.to_le_bytes());
    ifd.extend_from_slice(&3u16.to_le_bytes()); // int16u
    ifd.extend_from_slice(&(fl_words.len() as u32).to_le_bytes());
    ifd.extend_from_slice(&payload_offsets[1].to_le_bytes());
    // Entry 3: 0x93 FileInfo, int16s, out-of-line at payload[2].
    ifd.extend_from_slice(&0x0093u16.to_le_bytes());
    ifd.extend_from_slice(&8u16.to_le_bytes()); // int16s
    ifd.extend_from_slice(&(fi_words.len() as u32).to_le_bytes());
    ifd.extend_from_slice(&payload_offsets[2].to_le_bytes());
    // Next-IFD word = 0.
    ifd.extend_from_slice(&0u32.to_le_bytes());
    for p in valid_payloads {
      ifd.extend_from_slice(p);
    }

    // `Canon EOS 20D`: keys the FileInfo position-1 FileNumber AND is NOT a
    // MacroMagnification-excluded body — exactly as the Step-B2 differential test.
    let em = assert_canon_special_matches(&ifd, Some("Canon EOS 20D"));
    // FocalLength scaled by the VALID 0x01's FocalUnits(10): 550 ÷ 10 = "55 mm".
    assert!(
      em.iter().any(|t| t.tag().name() == "FocalLength"
        && t.tag().value_ref() == &TagValue::Str("55 mm".into())),
      "FocalLength must be 55 mm (550 ÷ FocalUnits 10 from the VALID 0x01); a \
       bailed-on-first-bad-0x01 pre-scan would leave FocalUnits=None ⇒ 550 mm: {em:?}"
    );
    // MacroMagnification emits ONLY because the VALID 0x01's LensType == 124.
    assert!(
      em.iter().any(|t| t.tag().name() == "MacroMagnification"),
      "MacroMagnification must emit (LensType==124 from the VALID 0x01); a \
       bailed pre-scan would leave LensType=None ⇒ it is SUPPRESSED: {em:?}"
    );
  }

  // ====================================================================
  // Canon Step-C R4 finding 1: a SHORT MakerNote (`mn_len < 2`) must NOT be
  // walked — [`canon_makernote_isolated`] mirrors `walk_canon_in_tiff`'s
  // top-of-function guard (`body.rs:299`), so a malformed 0x927c with count 0/1
  // yields the SAME EMPTY result as the `parse_in_tiff` oracle (it never
  // re-reads inline padding / following ExifIFD bytes as a Canon Main IFD).
  // ====================================================================

  /// White-box: [`canon_makernote_isolated`] over a buffer that IS a fully
  /// walkable Canon Main IFD (one inline OwnerName leaf) returns EMPTY emissions
  /// + `None` typed when `mn_len < 2` (count 0 AND count 1) — byte-identical to
  /// `canon::parse_in_tiff` at the same `(offset, mn_len)`. A sanity pass with a
  /// sufficient `mn_len` proves the buffer is NOT vacuously empty (it DOES emit
  /// OwnerName when the short-directory guard does not fire).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_isolated_short_makernote_yields_empty_like_parse_in_tiff() {
    // A standalone Canon Main IFD: count 1 + one inline OwnerName(0x09) leaf +
    // next-IFD word 0. Walked in full, it emits `OwnerName` — so any non-empty
    // result below is a genuine leak, not vacuity.
    let mut canon_ifd: Vec<u8> = Vec::new();
    canon_ifd.extend_from_slice(&1u16.to_le_bytes());
    canon_ifd.extend_from_slice(&0x0009u16.to_le_bytes()); // 0x09 OwnerName
    canon_ifd.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    canon_ifd.extend_from_slice(&4u32.to_le_bytes()); // count 4 (inline)
    canon_ifd.extend_from_slice(b"Al\0\0");
    canon_ifd.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    let full_len = canon_ifd.len();

    // SANITY: a sufficient `mn_len` walks the IFD and BOTH paths emit OwnerName —
    // so the bytes are walkable and the emptiness below is the guard, not vacuity.
    let (sane_emi, sane_typed) = canon_makernote_isolated(
      &canon_ifd,
      0,
      full_len,
      ByteOrder::Little,
      Some("Canon"),
      None,
      true,
    );
    assert!(
      sane_emi.iter().any(|e| e.name() == "OwnerName"),
      "sanity: a full-length walk MUST emit OwnerName (else the short-mn_len \
       assertions below are vacuous): {:?}",
      sane_emi
        .iter()
        .map(makernotes::VendorEmission::name)
        .collect::<Vec<_>>()
    );
    assert!(
      sane_typed.is_some(),
      "sanity: print_conv=true yields the typed slot"
    );

    // The guard fires for mn_len 0 and 1 (the malformed-count cases). Both modes
    // return EMPTY emissions, MATCHING `parse_in_tiff` at the SAME `(0, mn_len)`;
    // the TYPED slot is `Some(empty)` in `-j` (parse_in_tiff always returns a
    // `MakerNotesCanon`, so the typed API must NOT drop to `None` — #243 phase 2
    // R8) and `None` in `-n` (discarded by the recompute).
    for mn_len in [0usize, 1usize] {
      for print_conv in [true, false] {
        let (emi, typed) = canon_makernote_isolated(
          &canon_ifd,
          0,
          mn_len,
          ByteOrder::Little,
          Some("Canon"),
          None,
          print_conv,
        );
        // Oracle: `parse_in_tiff` at the SAME short window — `body.rs:299`
        // returns empty for `mn_len < 2`.
        let (_oracle_typed, oracle) = makernotes::vendors::canon::parse_in_tiff(
          &canon_ifd,
          0,
          mn_len,
          ByteOrder::Little,
          print_conv,
          Some("Canon"),
          None,
        );
        assert!(
          oracle.is_empty(),
          "oracle parse_in_tiff must be EMPTY for a short mn_len={mn_len} \
           (body.rs:299 mn_len<2 guard)"
        );
        assert!(
          emi.is_empty(),
          "mn_len={mn_len} print_conv={print_conv}: a short MakerNote must yield \
           NO emissions (the fresh Walker must not re-read the buffer as a Canon \
           Main IFD) — got {:?}",
          emi
            .iter()
            .map(makernotes::VendorEmission::name)
            .collect::<Vec<_>>()
        );
        assert!(
          !emi.iter().any(|e| e.name() == "OwnerName"),
          "mn_len={mn_len} print_conv={print_conv}: the bogus OwnerName must NOT \
           leak from the under-declared MakerNote value"
        );
        // The TYPED surface is PRESERVED for a short MakerNote: `parse_in_tiff`
        // ALWAYS returns a `MakerNotesCanon` (here empty), which the dispatch
        // installs — so `canon() == Some(empty)`. The `-j` isolated helper must
        // likewise return `Some(empty)`, NOT collapse to `None` (#243 phase 2 R8);
        // the `-n` recompute discards the typed slot, so `None` there.
        if print_conv {
          assert!(
            typed.is_some(),
            "mn_len={mn_len}: a short MakerNote must KEEP the (empty) typed Canon \
             surface (Some), matching parse_in_tiff — not drop it to None"
          );
        } else {
          assert!(
            typed.is_none(),
            "mn_len={mn_len}: the -n recompute discards the typed slot"
          );
        }
      }
    }
  }

  /// End-to-end: a dispatched Canon TIFF whose 0x927c MakerNote declares count 1
  /// (so the dispatch passes `read_len == 1`) must produce an EMPTY Canon maker
  /// note — even though the bytes at the MakerNote value offset form a fully
  /// walkable Canon Main IFD (a 1-entry OwnerName IFD spilling out of the inline
  /// slot into the following ExifIFD/trailing bytes). The `mn_len < 2` guard
  /// rejects the walk; the oracle does too. A sanity pass with a sufficient
  /// `mn_len` proves those same bytes WOULD emit OwnerName, so the empty result
  /// is the guard at work, not vacuity.
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_short_inline_makernote_does_not_leak_following_bytes() {
    // Standalone LE TIFF: IFD0@8 = { Make="Canon", ExifOffset } ⇒ Vendor::Canon.
    let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    // IFD0@8: 2 entries — Make(0x010f, out-of-line "Canon\0"), ExifOffset(0x8769).
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&0x010fu16.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    t.extend_from_slice(&6u32.to_le_bytes()); // count 6
    let make_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // Make value offset (patch)
    t.extend_from_slice(&0x8769u16.to_le_bytes());
    t.extend_from_slice(&4u16.to_le_bytes()); // LONG
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    let exif_ptr_pos = t.len();
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD offset (patch)
    t.extend_from_slice(&0u32.to_le_bytes()); // IFD0 next = 0
    let make_val_off = t.len() as u32;
    t.extend_from_slice(b"Canon\0");
    t[make_ptr_pos..make_ptr_pos + 4].copy_from_slice(&make_val_off.to_le_bytes());
    // ExifIFD: ONE entry, MakerNote(0x927c), UNDEFINED, count 1 ⇒ size 1 ≤ 4 ⇒
    // INLINE. The dispatch reads `value_offset = entry+8` (the 4-byte inline
    // slot) with `read_len == 1`. We plant bytes so that a walk FROM that
    // value_offset (slot + the ExifIFD next-IFD word + appended trailing bytes)
    // is a valid 1-entry Canon Main IFD emitting OwnerName — the very leak the
    // guard must prevent.
    let exififd_off = t.len() as u32;
    t[exif_ptr_pos..exif_ptr_pos + 4].copy_from_slice(&exififd_off.to_le_bytes());
    t.extend_from_slice(&1u16.to_le_bytes()); // 1 ExifIFD entry
    let mn_entry_off = t.len();
    t.extend_from_slice(&0x927cu16.to_le_bytes()); // MakerNote
    t.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1 ⇒ size 1 ⇒ INLINE
    // Inline 4-byte value slot @ mn_entry_off+8 = the START of a bogus Canon IFD:
    // count word `1` + the first half of an OwnerName(0x09) entry.
    t.extend_from_slice(&1u16.to_le_bytes()); // [slot 0..2] Canon IFD count = 1
    t.extend_from_slice(&0x0009u16.to_le_bytes()); // [slot 2..4] entry tag = OwnerName
    // The ExifIFD next-IFD word doubles as the entry's format+count-low bytes.
    t.extend_from_slice(&2u16.to_le_bytes()); // [+0..2] format = ASCII
    t.extend_from_slice(&4u16.to_le_bytes()); // [+2..4] count low = 4
    // Trailing bytes complete the bogus entry: count high + inline "Al\0\0" +
    // the bogus IFD's next-IFD word.
    t.extend_from_slice(&0u16.to_le_bytes()); // count high (count = 4)
    t.extend_from_slice(b"Al\0\0"); // inline OwnerName value
    t.extend_from_slice(&0u32.to_le_bytes()); // bogus IFD next-IFD = 0
    let mn_value_offset = mn_entry_off + 8;

    // SANITY: walked with a SUFFICIENT mn_len (18 = the bogus IFD's full extent),
    // the oracle DOES emit OwnerName from these exact bytes — proving the bytes
    // are walkable and the empty result below is the short-mn_len guard.
    let (_st, sane) = makernotes::vendors::canon::parse_in_tiff(
      &t,
      mn_value_offset,
      18,
      ByteOrder::Little,
      true,
      Some("Canon"),
      None,
    );
    assert!(
      sane.iter().any(|e| e.name() == "OwnerName"),
      "sanity: the planted bytes MUST form a walkable Canon IFD emitting \
       OwnerName when mn_len is sufficient (else this test is vacuous): {:?}",
      sane
        .iter()
        .map(makernotes::VendorEmission::name)
        .collect::<Vec<_>>()
    );

    let meta = parse_borrowed(&t).expect("standalone TIFF parses");
    let mn = meta
      .maker_note()
      .expect("IFD0 Make=Canon + a 0x927c MakerNote must dispatch a Canon maker note");
    // The production dispatch passed `read_len == 1` (inline size 1) — the guard
    // fires, so the Canon walk is rejected and NOTHING leaks. Matches the oracle
    // at `(value_offset, 1)`.
    for print_conv in [true, false] {
      let (_ot, oracle) = makernotes::vendors::canon::parse_in_tiff(
        &t,
        mn_value_offset,
        1,
        ByteOrder::Little,
        print_conv,
        Some("Canon"),
        None,
      );
      assert!(
        oracle.is_empty(),
        "print_conv={print_conv}: oracle is EMPTY for mn_len=1"
      );
      let got = if print_conv {
        mn.emissions_print_conv().to_vec()
      } else {
        mn.emissions_value_conv()
      };
      assert!(
        got.is_empty(),
        "print_conv={print_conv}: a count-1 MakerNote must emit NOTHING — the \
         following ExifIFD/trailing bytes must NOT be walked as a Canon IFD: {:?}",
        got
          .iter()
          .map(makernotes::VendorEmission::name)
          .collect::<Vec<_>>()
      );
      assert!(
        !got.iter().any(|e| e.name() == "OwnerName"),
        "print_conv={print_conv}: the bogus OwnerName must NOT leak"
      );
    }
    // The typed Canon surface is PRESERVED for a short MakerNote: `parse_in_tiff`
    // ALWAYS returns a (here empty) `MakerNotesCanon`, so the migrated dispatch
    // must install `Some(empty)`, NOT drop it to `None` (#243 phase 2 R8 — a
    // typed-API divergence the byte-identical JSON gate cannot see). The emissions
    // above are empty; the typed slot is present-but-empty.
    assert!(
      mn.meta().canon().is_some(),
      "a short Canon MakerNote must KEEP the (empty) typed MakerNotesCanon \
       surface, matching parse_in_tiff (the typed API must not collapse to None)"
    );
  }

  // ====================================================================
  // Canon Step-C R4 finding 2: DUPLICATE CanonFocalLength (0x02) entries.
  // `parse_in_tiff`'s pre-pass caches the LAST readable 0x02 `$$valPt` and
  // renders EVERY 0x02 SubDirectory from that final blob ("last,last"). The
  // migrated emit must match — the pre-scan caches the last 0x02 into
  // `canon_focal_length_blob`, read by EVERY FocalLength emit.
  // ====================================================================

  /// Two `CanonFocalLength` (0x02) entries with DISTINCT blobs: both 0x02
  /// emissions must decode the LAST entry's blob ("last,last"), matching
  /// `parse_in_tiff` for `-j` AND `-n`. A "first,last" (current-entry) decode —
  /// the divergence this fix closes — would render the FIRST 0x02 from its own
  /// blob. The differential (`assert_canon_special_matches`) proves byte-identity
  /// to the oracle; the concrete value asserts pin that BOTH emissions are the
  /// LAST blob's (so the test cannot pass on a "first,last" emit).
  #[test]
  #[cfg(feature = "alloc")]
  fn canon_two_focal_length_entries_emit_last_blob_like_parse_in_tiff() {
    use crate::value::TagValue;
    // FocalLength A (FIRST 0x02): FocalType=Fixed(1), FocalLength raw 300.
    let fl_a: [u16; 4] = [1, 300, 0, 0];
    // FocalLength B (LAST 0x02): FocalType=Zoom(2), FocalLength raw 550.
    let fl_b: [u16; 4] = [2, 550, 0, 0];
    let blob_a = u16_words_le(&fl_a);
    let blob_b = u16_words_le(&fl_b);
    // A Canon Main IFD with TWO 0x02 entries (both int16u[4], out-of-line). No
    // CameraSettings ⇒ FocalUnits stays None ⇒ divisor 1 (the raw mm). Tag order
    // is non-decreasing (0x02, 0x02), and the helper stages each payload past the
    // directory extent so neither is `Suspicious`.
    let entries: &[(u16, u16, u32, &[u8], &[u8])] = &[
      (0x02, 3, fl_a.len() as u32, &[], &blob_a),
      (0x02, 3, fl_b.len() as u32, &[], &blob_b),
    ];
    let ifd = crafted_canon_subtable_ifd(entries);

    // Byte-identity to the oracle (parse_in_tiff) for -j AND -n.
    let em = assert_canon_special_matches(&ifd, None);

    // CONCRETE pins (PrintConv `-j`): BOTH FocalType emissions are the LAST
    // blob's "Zoom", BOTH FocalLength emissions the LAST blob's "550 mm". A
    // "first,last" emit would instead surface the FIRST blob's "Fixed"/"300 mm".
    let focal_types: Vec<&TagValue> = em
      .iter()
      .filter(|t| t.tag().name() == "FocalType")
      .map(|t| t.tag().value_ref())
      .collect();
    assert_eq!(
      focal_types,
      vec![&TagValue::Str("Zoom".into()), &TagValue::Str("Zoom".into())],
      "both FocalType emissions must be the LAST 0x02 blob's Zoom (last,last), \
       NOT the first blob's Fixed (first,last): {em:?}"
    );
    let focal_lengths: Vec<&TagValue> = em
      .iter()
      .filter(|t| t.tag().name() == "FocalLength")
      .map(|t| t.tag().value_ref())
      .collect();
    assert_eq!(
      focal_lengths,
      vec![
        &TagValue::Str("550 mm".into()),
        &TagValue::Str("550 mm".into())
      ],
      "both FocalLength emissions must be the LAST 0x02 blob's 550 mm \
       (last,last), NOT the first blob's 300 mm (first,last): {em:?}"
    );
  }
}
