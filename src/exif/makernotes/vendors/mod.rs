// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-vendor MakerNote-decoded structs.
//!
//! - Phase 2 ports populate `apple::MakerNotesApple` and
//!   `canon::MakerNotesCanon` from real IFD bodies.
//! - Phase 3 ports populate `sony::MakerNotesSony` and
//!   `panasonic::MakerNotesPanasonic`.
//! - Phase 4 populates `dji::MakerNotesDji` (full Main IFD table — 10
//!   tags). GoPro is intentionally NOT a MakerNote vendor: bundled
//!   `MakerNotes.pm` carries no `MakerNoteGoPro` entry, so GoPro
//!   MakerNotes fall through to `Vendor::Unknown` (faithful) — GoPro
//!   files are identified by the standard IFD0 `Make` tag.
//!
//! Type aliases preserve the Phase-1 API names (`AppleMakerNote`,
//! `CanonMakerNote`, `SonyMakerNote`, `PanasonicMakerNote`,
//! `DjiMakerNote`) for downstream `match` arms —
//! `MakerNotesApple` / `MakerNotesCanon` / `MakerNotesSony` /
//! `MakerNotesPanasonic` / `MakerNotesDji` are the
//! canonical names per the [[exifast-api-conventions]] memory ("no
//! module-name stutter" naming).

// NOTE: no file-level `#![deny(clippy::indexing_slicing)]` here. This is a
// PARENT module (it declares `pub mod canon;` etc.), and an inner `#![deny]`
// lint attribute cascades into ALL descendant modules — including
// `canon`, owned by wave-2 slice D and not yet checked-indexing-clean.
// Matching the established Phase-C pattern (`src/formats/mod.rs` carries no
// such deny), the deny lives on the LEAF vendor files only; this parent has
// no raw indexing of its own.

pub mod apple;
pub mod canon;
pub mod dji;
pub mod nikon;
pub mod panasonic;
pub mod pentax;
pub mod sony;

pub use apple::MakerNotesApple;
pub use canon::MakerNotesCanon;
pub use dji::MakerNotesDji;
pub use nikon::MakerNotesNikon;
pub use panasonic::MakerNotesPanasonic;
pub use pentax::MakerNotesPentax;
pub use sony::MakerNotesSony;

/// Compatibility alias — Phase-1 API name preserved.
pub type AppleMakerNote = MakerNotesApple;
/// Compatibility alias — Phase-1 API name preserved.
pub type CanonMakerNote = MakerNotesCanon;

/// One vendor MakerNote emission — the rendered `(name, value)` pair plus the
/// `Unknown => 1` flag the emission engine uses to suppress it from default
/// output (`ExifTool.pm:9179-9185`).
///
/// This carries the `Unknown` flag THROUGH the cached emissions instead of the
/// vendor pre-filtering it at collection time: the vendor body decoder emits a
/// named/rendered tag for EVERY leaf it recognizes (Unknown or not), and the
/// shared engine ([`run_emission`](crate::emit::run_emission)) drops the
/// `Unknown` ones once — exactly as it does for every other format, so the
/// per-vendor `if def.is_unknown() { continue; }` is gone.
///
/// D8: no public fields; accessors only. The constructor is `pub(crate)` (only
/// the in-crate vendor body parsers build these), but the read accessors are
/// `pub` so the captured-MakerNote accessors
/// ([`MakerNote::emissions_print_conv`](crate::exif::MakerNote::emissions_print_conv))
/// remain usable from outside the crate.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
pub struct VendorEmission {
  /// The resolved tag name (the vendor table's `Name`).
  name: smol_str::SmolStr,
  /// The rendered value for the active [`ConvMode`](crate::emit::ConvMode).
  value: crate::value::TagValue,
  /// ExifTool's `Unknown => 1` flag — `true` ⇒ the engine suppresses this tag
  /// from default output.
  unknown: bool,
}

#[cfg(feature = "alloc")]
impl VendorEmission {
  /// Compose a vendor emission from its name, rendered value, and `Unknown`
  /// flag. (`pub(crate)`: only the in-crate vendor body parsers build these.)
  #[must_use]
  #[inline(always)]
  pub(crate) fn new(name: smol_str::SmolStr, value: crate::value::TagValue, unknown: bool) -> Self {
    Self {
      name,
      value,
      unknown,
    }
  }

  /// The resolved tag name.
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The rendered value.
  #[must_use]
  #[inline(always)]
  pub const fn value(&self) -> &crate::value::TagValue {
    &self.value
  }

  /// Whether this emission carries ExifTool's `Unknown => 1` flag — the
  /// emission engine suppresses such tags from default output
  /// (`ExifTool.pm:9179-9185`).
  #[must_use]
  #[inline(always)]
  pub const fn unknown(&self) -> bool {
    self.unknown
  }
}

/// Compatibility alias — Phase-1 API name preserved.
pub type SonyMakerNote = MakerNotesSony;
/// Compatibility alias — Phase-1 API name preserved.
pub type PanasonicMakerNote = MakerNotesPanasonic;
/// Compatibility alias — Phase-1 API name preserved.
pub type DjiMakerNote = MakerNotesDji;
/// Compatibility alias — Phase-1 API name preserved.
pub type PentaxMakerNote = MakerNotesPentax;

/// A `Format => '…'` (with an optional `Count => N`) directive on a vendor
/// Main-table tag row that OVERRIDES the entry's on-disk TIFF format when the
/// value is read.
///
/// ExifTool's `ProcessExif` reads an IFD entry's value with the on-disk
/// `$format` by default, but a tag's `Format` directive re-interprets the SAME
/// value bytes with a different format (`Exif.pm:6728-6745`): when the
/// directive's format number differs from the on-disk one, `$formatStr` is
/// switched to the directive, and the read count is RECOMPUTED from the on-disk
/// byte size — `$count = int($size / $formatSize[$format])` (`Exif.pm:6743`) —
/// NOT taken from the table `Count`. The bundled `Count` directive is a
/// writer/validation hint that, for well-formed bytes, equals that recomputed
/// count (e.g. Sony `0x200a HDR`: on-disk `int32u` ⇒ 4 bytes; `Format =>
/// 'int16u'` ⇒ `4/2 = 2` items = `Count => 2`).
///
/// [`format`](Self::format) is the directive's format (used for the value
/// re-read); [`count`](Self::count) is the bundled `Count` directive when
/// present (carried verbatim so the Format-override completeness oracle can
/// assert the Rust def matches the bundled `(Format, Count)` pair — the
/// walker's read count follows ExifTool's `int(size/elemsize)` rule, not this
/// field).
///
/// D8: no public fields; `Copy`; `const` accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOverride {
  /// The directive's TIFF format — what the value bytes are re-read AS.
  format: crate::exif::ifd::Format,
  /// The bundled `Count => N` directive, if any. `None` ⇒ the directive
  /// specifies no count (the recomputed `int(size/elemsize)` stands alone).
  count: Option<usize>,
}

impl FormatOverride {
  /// Build a Format-override from the directive's format and optional bundled
  /// `Count`.
  #[must_use]
  #[inline(always)]
  pub const fn new(format: crate::exif::ifd::Format, count: Option<usize>) -> Self {
    Self { format, count }
  }

  /// The directive's TIFF format — the format the value bytes are re-read as
  /// (`$formatStr = $readFormat`, `Exif.pm:6736`).
  #[must_use]
  #[inline(always)]
  pub const fn format(self) -> crate::exif::ifd::Format {
    self.format
  }

  /// The bundled `Count => N` directive, if any (for the oracle; the walker's
  /// read count is recomputed per `Exif.pm:6743`).
  #[must_use]
  #[inline(always)]
  pub const fn count(self) -> Option<usize> {
    self.count
  }
}

/// Resolve the `(format, count)` an IFD entry's value is READ with, applying a
/// tag's optional [`FormatOverride`] — the faithful port of ExifTool's Format
/// re-interpretation (`Exif.pm:6735-6744`).
///
/// `on_disk_format` / `on_disk_count` are the entry's TIFF format and element
/// count as written. With no override (`None`) the on-disk pair is returned
/// verbatim. With an override whose format maps to a known TIFF type **and**
/// differs from the on-disk format (`$newNum and $newNum != $format`,
/// `Exif.pm:6738`), the value bytes are re-interpreted: the format becomes the
/// directive's, and the read count is RECOMPUTED from the on-disk byte size —
/// `$count = int($size / $formatSize[$format])` (`Exif.pm:6743`, where `$size =
/// $count * $formatSize[$format]` is the on-disk byte size, `Exif.pm:6502`).
/// The bundled `Count` directive is NOT used as the read count (it is a
/// writer/validation hint that, for well-formed bytes, equals this recomputed
/// value).
///
/// This re-interprets the SAME value bytes; the inline-vs-out-of-line pointer
/// decision uses the ON-DISK byte size and happens BEFORE this (matching
/// ExifTool, which sizes/locates the value at `Exif.pm:6502-6510` before the
/// override block). The on-disk format is preserved separately by the caller
/// for the `$format`-based `Condition` gate (`GetTagInfo`).
#[must_use]
pub fn resolve_read_format(
  on_disk_format: crate::exif::ifd::Format,
  on_disk_count: usize,
  format_override: Option<FormatOverride>,
) -> (crate::exif::ifd::Format, usize) {
  let Some(ovr) = format_override else {
    return (on_disk_format, on_disk_count);
  };
  let new_format = ovr.format();
  let new_elem = new_format.byte_size();
  // `if ($newNum and $newNum != $format)` (Exif.pm:6738): apply only when the
  // directive maps to a sized TIFF type whose code DIFFERS from the on-disk
  // one. (Equal variants ⇒ equal format numbers ⇒ no change, count untouched.)
  if new_elem == 0 || new_format == on_disk_format {
    return (on_disk_format, on_disk_count);
  }
  // `$size = $count * $formatSize[$format]` (on-disk byte size, Exif.pm:6502);
  // `$count = int($size / $formatSize[$format])` with the NEW format
  // (Exif.pm:6743).
  let on_disk_size = on_disk_format.byte_size().saturating_mul(on_disk_count);
  let new_count = on_disk_size / new_elem;
  (new_format, new_count)
}
