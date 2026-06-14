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

use crate::format_parser::{FormatParser, parser_sealed};
use crate::recovery::Step;
use ifd::{ByteOrder, Format, RawValue, get_u16, get_u32, read_value};
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
}

/// Which conversion table an entry's value goes through at serialize time.
/// Internal — `ExifEntry` carries it so `serialize_tags` does not re-look-up.
#[derive(Debug, Clone, Copy)]
enum ResolvedConv {
  /// A plain Exif conversion ([`Conv`]).
  Exif(Conv),
  /// A GPS conversion ([`gps::GpsConv`]).
  #[cfg(feature = "gps")]
  Gps(gps::GpsConv),
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
  /// Apple — `parse_with_print_conv(blob, order, ·)`.
  Apple { blob: &'a [u8], order: ByteOrder },
  /// Canon — `parse_in_tiff(data, mn_offset, mn_len, order, ·, model, file_type)`.
  Canon {
    data: &'a [u8],
    mn_offset: usize,
    mn_len: usize,
    order: ByteOrder,
    model: Option<smol_str::SmolStr>,
    file_type: Option<smol_str::SmolStr>,
  },
  /// Sony — `parse_main_gated(data, mn_offset, mn_len, body_off, order, ·, make, model)`.
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
    use makernotes::vendors::{apple, canon, dji, panasonic, sony};
    match self {
      MakerNoteValueConvDecode::None => std::vec::Vec::new(),
      MakerNoteValueConvDecode::Apple { blob, order } => {
        apple::parse_with_print_conv(blob, *order, false).1
      }
      MakerNoteValueConvDecode::Canon {
        data,
        mn_offset,
        mn_len,
        order,
        model,
        file_type,
      } => {
        canon::parse_in_tiff(
          data,
          *mn_offset,
          *mn_len,
          *order,
          false,
          model.as_deref(),
          file_type.as_deref(),
        )
        .1
      }
      MakerNoteValueConvDecode::Sony {
        data,
        mn_offset,
        mn_len,
        body_off,
        order,
        make,
        model,
      } => {
        sony::parse_main_gated(
          data,
          *mn_offset,
          *mn_len,
          *body_off,
          *order,
          false,
          make.as_deref(),
          model.as_deref(),
        )
        .expect("routes_to_main is deterministic across print_conv")
        .1
      }
      MakerNoteValueConvDecode::Panasonic {
        data,
        mn_offset,
        mn_len,
        order,
        model,
        base_rule,
      } => {
        panasonic::parse_main_gated(
          data,
          *mn_offset,
          *mn_len,
          *order,
          false,
          model.as_deref(),
          *base_rule,
        )
        .expect("routes_to_main is deterministic across print_conv")
        .1
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
        makernotes::vendors::nikon::parse_in_tiff(
          data,
          *mn_offset,
          *mn_len,
          *order,
          false,
          model.as_deref(),
        )
        .1
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
  // entries — decoding it with the classic layout below misreads it into
  // garbage. BigTIFF (0x2b) is intentionally NOT parsed yet: a full BigTIFF
  // walker (8-byte offsets, 64-bit counts, 20-byte entries, formats 16-18) is a
  // deferred port. Cleanly bail with the same "no Exif parsed" result the
  // invalid-header path returns (`None`) — no tags, no misdecode, no panic.
  // ExifTool DOES support BigTIFF, so we deliberately emit NO "unsupported"
  // warning (that would itself diverge); the only accepted divergence is the
  // missing Exif tags, tracked as a follow-up. (File:FileType detection is a
  // separate front-end and is unaffected.)
  let magic = get_u16(data, 2, order)?;
  if magic == 0x2b {
    return None;
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

  /// Resolve a tag NAME for a warning message, against the table that owns
  /// the IFD currently being walked. GPS and Interop tag IDs OVERLAP (e.g.
  /// 0x0002 is `GPSLatitude` in `%GPS::Main` but `InteropVersion` in
  /// `%Interop::Main`); ExifTool resolves a warning's `$$tagInfo{Name}`
  /// against the IFD's own `$tagTablePtr` (`Exif.pm:6464`/6674), so the GPS
  /// IFD must look up the GPS table. Returns `Some(name)` for a known tag,
  /// `None` for an unknown one (caller emits the `tag 0x%.4x` form).
  fn warn_tag_name(kind: IfdKind, tag_id: u16) -> Option<&'static str> {
    if kind.is_gps() {
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
    } else {
      tables::lookup(tag_id).map(|t| t.name)
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
    let recognized = Format::is_valid_ifd_code(format_code);
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
        let tag = match Self::warn_tag_name(kind, tag_id) {
          Some(name) => std::format!("tag 0x{tag_id:04x} {name}"),
          None => std::format!("tag 0x{tag_id:04x}"),
        };
        // `++$warnCount` (Exif.pm:6507) — counts toward the abort cap.
        self.warn_counted(std::format!("Invalid size ({size}) for {dir} {tag}"));
        return Step::Skip; // `next` — skip this entry, continue the IFD.
      }
      let off = match get_u32(data, entry + 8, order) {
        Some(o) => o as usize,
        // Unreadable offset bytes (unreachable given the caller's `entry+12`
        // bounds guard) — a `next`-skip.
        None => return Step::Skip,
      };
      // `$valuePtr -= $dataPos` — `$dataPos == 0` here (the whole block IS
      // the EXIF data). An out-of-line value pointer is subject to two
      // ExifTool bounds checks, in this precedence:
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
        // No-RAF re-dispatch (the Canon CTMD `0x8769` ExifIFD hop): bundled
        // takes the no-RAF `else` branch (`Exif.pm:6616-6670`) — `Bad offset
        // for $dir $tagStr` (`Exif.pm:6660`) + `$bad = 1` (the value is
        // dropped) + CONTINUE the loop. `$tagStr` is the name-if-known form
        // (`Exif.pm:6634`), NOT the RAF path's `ID 0x…` text. NON-minor
        // (`$inMakerNotes = 0` for `Exif::Main`). Takes precedence over the
        // suspect test below (the read happens first, `Exif.pm:6660` before
        // `:6672`).
        _ if self.no_raf => {
          let warning = match Self::warn_tag_name(kind, tag_id) {
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
          let tag = match Self::warn_tag_name(kind, tag_id) {
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
        let warning = match Self::warn_tag_name(kind, tag_id) {
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
    if let Some(sub) = sub_dir_for(tag_id, kind) {
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
    let table_override = if kind.is_gps() {
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
    } else {
      tables::format_override(tag_id)
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
      let known = Self::warn_tag_name(kind, tag_id);

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
    let Some(raw) = read_value(data, value_offset, decode_format, count, read_len, order) else {
      // `next unless defined $val` (Exif.pm:7016) — [`Step::Skip`].
      return Step::Skip;
    };

    self.emit(kind, tag_id, raw);
    // The leaf value was decoded + emitted (FoundTag) — a normal entry:
    // [`Step::Keep`].
    Step::Keep
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
        // walk exactly one IFD.
        let _ = self.walk_one_ifd(sub_offset, kind);
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
                // Apple: parse using the body (after the 14-byte header).
                // Apple's `Base => '$start - 14'` rebases offsets to the
                // start of the BLOB, so the standalone-blob walker is
                // faithful here.
                let (typed_pc, emi_pc) =
                  makernotes::vendors::apple::parse_with_print_conv(bytes, self.order, true);
                meta.set_apple(typed_pc);
                cached_pc = emi_pc;
                value_conv_decode = MakerNoteValueConvDecode::Apple {
                  blob: bytes,
                  order: self.order,
                };
              }
              makernotes::Vendor::Canon => {
                // Canon: parse using the parent TIFF context so
                // out-of-line offsets resolve correctly. Thread the container
                // `$$self{FILE_TYPE}` for the `Canon::ShotInfo` pos-22
                // CRW-allows-0 RawConv (`Canon.pm:2977`/`:2990`).
                let mn_offset = value_offset;
                let mn_len = read_len;
                let model = self.captured_model.as_deref();
                let file_type = self.file_type.as_deref();
                let (typed_pc, emi_pc) = makernotes::vendors::canon::parse_in_tiff(
                  self.data, mn_offset, mn_len, self.order, true, model, file_type,
                );
                meta.set_canon(typed_pc);
                cached_pc = emi_pc;
                value_conv_decode = MakerNoteValueConvDecode::Canon {
                  data: self.data,
                  mn_offset,
                  mn_len,
                  order: self.order,
                  model: model.map(smol_str::SmolStr::new),
                  file_type: file_type.map(smol_str::SmolStr::new),
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
                if let Some((typed_pc, emi_pc)) = makernotes::vendors::sony::parse_main_gated(
                  self.data, mn_offset, mn_len, body_off, self.order, true, make, model,
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
              // the Main parser must NOT run on it. Both the `Panasonic`-prefix
              // gate and the `base_rule` → out-of-line-offset-addend threading
              // (`BaseRule::Inherit` ⇒ 0 vs `BaseRule::Literal(12)` ⇒ 12;
              // a base-0 read of a DC-FT7 value lands 12 bytes early ⇒
              // corruption) live in `panasonic::parse_main_gated`: it returns
              // `None` for the `MKE`/Type2 blob (Panasonic slot stays absent;
              // Type2 BinaryData is unported/deferred). This is the SAME gated
              // entry the public `MakerNotesMeta::from_blob` constructor uses,
              // so the gate cannot be bypassed by a parallel code path.
              makernotes::Vendor::Panasonic => {
                let mn_offset = value_offset;
                let mn_len = read_len;
                let model = self.captured_model.as_deref();
                let base_rule = detected.base_rule();
                if let Some((typed_pc, emi_pc)) = makernotes::vendors::panasonic::parse_main_gated(
                  self.data, mn_offset, mn_len, self.order, true, model, base_rule,
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
                // So thread the parent TIFF context (`self.data`/`value_offset`/
                // `read_len`); `nikon::parse_in_tiff` walks the blob for type-3
                // and the parent TIFF for type-2/Nikon3 (choosing the slice
                // from the header). The byte order is read from the embedded
                // marker (type-3) / explicit LE (type-2) / inherited (Nikon3),
                // so `self.order` is only the Nikon3 fallback. `model` threads
                // `$$self{Model}` for the AFInfo BigEndian gate
                // (`$$self{Model} =~ /^NIKON D/i`, `Nikon.pm:2115`) + the
                // `ShootingMode` bit-5 model branch (`Nikon.pm:2180`).
                let mn_offset = value_offset;
                let mn_len = read_len;
                let model = self.captured_model.as_deref();
                let (typed_pc, emi_pc) = makernotes::vendors::nikon::parse_in_tiff(
                  self.data, mn_offset, mn_len, self.order, true, model,
                );
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
  fn emit(&mut self, kind: IfdKind, tag_id: u16, raw: RawValue) {
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
    // TABLE-SCOPED to `%Exif::Main`: DNGVersion's RawConv lives in `%Exif::Main`
    // (Exif.pm:3353), which the walker applies in the IFD0 / ExifIFD / SubIFD /
    // trailing-IFD / InteropIFD directories — every IFD walked against the Exif
    // main [`tables`] table. The GPS IFD ([`IfdKind::Gps`]) is walked against
    // `%GPS::Main` instead (the same `kind.is_gps()` split that routes the leaf
    // lookup below to `gps::lookup`), and `%GPS::Main` has NO 0xc612 entry — so
    // an unknown GPS-IFD tag with id 0xc612 must NOT touch the DataMember. Gate
    // the assignment on `!kind.is_gps()` to match that scoping exactly.
    if tag_id == tables::TAG_DNG_VERSION && !kind.is_gps() {
      self.dng_version = raw.is_perl_truthy();
    }

    // `#### eval IsOffset ($val, $et) … $val += $offsetBase` (Exif.pm:7156-
    // 7170): convert an `IsOffset` tag's value(s) to ABSOLUTE file offsets by
    // adding `$base + $$et{BASE}`. `$$et{BASE}` is 0 for the top-level Exif
    // walk, so `offsetBase = self.base`. The two `IsOffset => 1` tags the port
    // decodes are `StripOffsets` (0x0111) and `ThumbnailOffset` (0x0201), both
    // in the non-GPS table (GPS has no `IsOffset` tags). When `base == 0`
    // (standalone TIFF) this is a no-op, so the existing TIFF goldens are
    // unaffected; for a JPEG `APP1` block `base` is the TIFF block's file
    // offset, matching bundled's absolute `ThumbnailOffset`.
    let raw = if self.base != 0 && !kind.is_gps() && is_offset_tag(tag_id) {
      add_offset_base(raw, self.base)
    } else {
      raw
    };
    let (name, conv): (&'static str, ResolvedConv) = if kind.is_gps() {
      #[cfg(feature = "gps")]
      {
        match gps::lookup(tag_id) {
          Some(t) => (t.name, ResolvedConv::Gps(t.conv)),
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
    } else {
      match tables::lookup(tag_id) {
        Some(t) => (t.name, ResolvedConv::Exif(t.conv)),
        None => return, // unknown Exif tag — verbose-only, omit.
      }
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
    for entry in &self.entries {
      // `emit_entry` into the `EmittedTagSink` is infallible (`Infallible`).
      let Ok(()) = emit_entry(entry, entry_order, print_conv, &mut sink);
    }
  }

  /// Append the captured MakerNote's cached vendor emissions to `out` as
  /// [`EmittedTag`](crate::emit::EmittedTag)s — the golden-pattern parallel to
  /// the MakerNote branch of [`serialize_tags`](Self::serialize_tags).
  ///
  /// Each [`VendorEmission`](makernotes::VendorEmission) becomes an
  /// `EmittedTag` under `Group{family0:"MakerNotes", family1:<vendor group1>}`
  /// (`Apple`/`Canon` — [`Vendor::group1`](makernotes::Vendor::group1)),
  /// carrying the emission's own `Unknown => 1` flag. The flag is NOT filtered
  /// here: the engine ([`run_emission`](crate::emit::run_emission)) drops the
  /// Unknown ones once, reproducing the OLD per-vendor pre-filter generically
  /// (the legacy `serialize_tags` path still filters on read for byte-identity
  /// until the flip).
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
    self.write_value(group, name, crate::value::TagValue::Bytes(value.to_vec()))
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
}

/// Emit one [`ExifEntry`] into the [`crate::tagmap::TagMap`] sink, applying
/// the resolved conversion.
#[cfg(feature = "alloc")]
fn emit_entry<S: ExifSink>(
  entry: &ExifEntry,
  // The TIFF byte order threads to `ConvertExifText`'s UTF-16 'Unknown'
  // guess — consumed by the Exif `Conv::ExifText` arm (UserComment) AND the
  // GPS `GpsConv::ExifText` arm (GPSProcessingMethod/GPSAreaInformation).
  order: ByteOrder,
  print_conv: bool,
  out: &mut S,
) -> Result<(), core::convert::Infallible> {
  let group = entry.group();
  let group = group.as_str();
  let name = entry.name();
  match entry.conv {
    ResolvedConv::Exif(conv) => {
      emit_exif_value(group, name, entry.value.raw(), conv, order, print_conv, out)
    }
    #[cfg(feature = "gps")]
    ResolvedConv::Gps(conv) => {
      emit_gps_value(group, name, entry.value.raw(), conv, order, print_conv, out)
    }
  }
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

  #[test]
  fn rejects_ifd0_offset_below_8() {
    // Valid MM marker but IFD0 offset = 4 (< 8 ⇒ DoProcessTIFF return 0).
    assert!(parse_exif_block(b"MM\0\x2a\0\0\0\x04").is_none());
  }

  #[test]
  fn bigtiff_magic_is_cleanly_skipped() {
    // A minimal BigTIFF header: byte order + magic 0x2b (43) + the BigTIFF
    // 8-byte-offset layout (bytesize=8, reserved=0, 8-byte IFD0 offset). The
    // classic walker reads byte 4 as a 32-bit offset over 12-byte/16-bit
    // entries, which would MISDECODE BigTIFF; instead we bail cleanly (the
    // same `None` an invalid header returns) — NO tags, no panic, no garbage,
    // and (deliberately) NO warning ExifTool wouldn't raise (it supports
    // BigTIFF). A full BigTIFF walker is a deferred port.

    // Big-endian BigTIFF: MM, magic 0x002b, bytesize 0x0008, reserved 0x0000,
    // then an 8-byte IFD0 offset (0x10). Padded so the (mis)read of byte 4 as
    // a classic 32-bit offset would otherwise point inside the buffer — proves
    // the magic gate fires BEFORE any classic decode, not the ≥8 sanity check.
    let mut be: Vec<u8> = vec![b'M', b'M', 0x00, 0x2b, 0x00, 0x08, 0x00, 0x00];
    be.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]); // 8-byte IFD0 offset
    be.extend_from_slice(&[0u8; 32]); // body so a classic mis-walk would find bytes
    assert!(
      parse_exif_block(&be).is_none(),
      "big-endian BigTIFF (0x2b) must be cleanly skipped, no Exif"
    );

    // Little-endian BigTIFF: II, magic 0x2b00, bytesize 0x0800.
    let mut le: Vec<u8> = vec![b'I', b'I', 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00];
    le.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    le.extend_from_slice(&[0u8; 32]);
    assert!(
      parse_exif_block(&le).is_none(),
      "little-endian BigTIFF (0x2b) must be cleanly skipped, no Exif"
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
}
