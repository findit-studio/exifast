// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon MakerNote IFD directory-shape classifiers — Phase-2 port.
//!
//! The Canon Main-IFD walk itself is the shared `Walker`
//! (`crate::exif::canon_makernote_isolated`); the per-vendor
//! `walk_canon_in_tiff` oracle was deleted in #243 phase 5 (do not reintroduce
//! a second Canon walker). What survives here is the `ProcessExif`
//! directory-framing / per-entry classification ([`classify_canon_directory`] /
//! [`classify_canon_entry`]) shared by the shared `Walker`'s Canon emission and
//! the CTMD value-offset diagnostics, so both are driven by ONE predicate and
//! can never disagree.
//!
//! Canon's MakerNote (`MakerNoteCanon`, `MakerNotes.pm:60-68`) has NO header
//! and no `Base` override (it inherits the parent TIFF base), so out-of-line
//! value offsets resolve against the captured byte range.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length/count guard
// and converted to a checked `.get()` form (re-asserts the parent `exif`
// deny over the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, Format, get_u16, get_u32};

/// The directory-shape decision shared by the Canon `0x927c` emission walk
/// (the shared `Walker`'s Canon classification, `exif/mod.rs`) and the CTMD
/// diagnostic walk
/// ([`super::redispatch_ctmd_makernote_value_offset_diagnostics`]). This is the
/// 1:1 port of `ProcessExif`'s directory framing (`Exif.pm:6343-6400`) for the
/// in-memory, no-RAF, `$inMakerNotes = 1` Canon::Main re-dispatch — so the
/// emission SKIP and the WARNING are driven by ONE predicate and can never
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonDirShape {
  /// Walk `num_entries`; the directory ends at `dir_end` (`$dirEnd`,
  /// `Exif.pm:6391`). Reached for a readable directory whose
  /// `$bytesFromEnd` is `0`, `2`, or `>= 4` (`Exif.pm:6395-6399`).
  Walk { num_entries: usize, dir_end: usize },
  /// Abort with NO warning here — the structural path already raised
  /// `Bad <dir> directory` (`Exif.pm:6383`): the IFD0 count is unreadable, or
  /// the directory overruns the block (`$dirEnd > $dataLen`,
  /// `Exif.pm:6356`; for the `$inMakerNotes = 0` framing the generic walker
  /// reuses, an overrun aborts rather than salvages).
  AbortBadDirectory,
  /// Abort AND raise `Illegal <dir> directory size (<n> entries)`
  /// (`Exif.pm:6397`) — a `$bytesFromEnd` of `1` or `3`. NON-minor (the Perl
  /// `$et->Warn` carries no minor arg).
  AbortIllegalSize { num_entries: usize },
}

/// Classify the IFD directory shape for a Canon `0x927c` re-dispatch
/// (`ProcessExif`, `Exif.pm:6343-6400`). `dir_start` is the IFD0 offset within
/// `tiff_data`; `data_len` is the re-dispatched block length (`$dataLen`,
/// i.e. `tiff_data.len()` — the CTMD block is framed with `$dataPos == 0`).
///
/// Mirrors the in-memory, no-RAF path: an unreadable count or an overrunning
/// directory is [`CanonDirShape::AbortBadDirectory`] (the structural path warns
/// `Bad <dir> directory`); a `1`/`3`-byte tail is
/// [`CanonDirShape::AbortIllegalSize`]; a `0`/`2`/`>= 4`-byte tail is
/// [`CanonDirShape::Walk`].
pub(crate) fn classify_canon_directory(
  tiff_data: &[u8],
  dir_start: usize,
  data_len: usize,
  order: ByteOrder,
) -> CanonDirShape {
  // `$dirStart >= 0 and $dirStart <= $dataLen-2` (Exif.pm:6344) — the count
  // word must be readable. (Also guards the `data_len < 2` underflow.)
  if data_len < 2 || dir_start > data_len - 2 {
    return CanonDirShape::AbortBadDirectory;
  }
  let Some(num_entries) = get_u16(tiff_data, dir_start, order) else {
    return CanonDirShape::AbortBadDirectory;
  };
  let num_entries = num_entries as usize;
  // NO entry-count gate here: `ProcessExif` (`Exif.pm:6343-6400`) has no
  // zero-entry or maximum-count special case — it computes `$dirSize = 2 + 12 *
  // $numEntries` and is bounded only by `$dirEnd <= $dataLen` + the 0/1/2/3/>=4
  // tail rule. A zero-entry directory walks zero entries (and, with a 1/3-byte
  // tail, still warns `Illegal … directory size (0 entries)`, Exif.pm:6397); a
  // many-entry (>1024) directory that fits the block is fully walked. The
  // `checked_mul` below already keeps the extent arithmetic overflow-safe, and
  // `dir_end <= data_len` rejects an over-claimed count — so an explicit ceiling
  // would only DIVERGE from ExifTool (oracle-verified: a 0-entry valid-tail IFD
  // is silent, a 2000-entry in-bounds IFD is walked).
  // `$dirSize = 2 + 12 * $numEntries; $dirEnd = $dirStart + $dirSize`
  // (Exif.pm:6347-6348), each step checked for the 32-bit/wasm overflow class.
  let Some(dir_end) = num_entries
    .checked_mul(12)
    .and_then(|body| body.checked_add(2))
    .and_then(|size| dir_start.checked_add(size))
  else {
    return CanonDirShape::AbortBadDirectory;
  };
  // `undef $dirSize if $dirEnd > $dataLen` (Exif.pm:6356) ⇒ the no-RAF
  // `$success = 0` path ⇒ `Bad <dir> directory` + abort (the `$inMakerNotes`
  // salvage only changes the VERBOSE entry walk, which is not modelled).
  if dir_end > data_len {
    return CanonDirShape::AbortBadDirectory;
  }
  // `my $bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) { unless
  // ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn("Illegal …"); return 0 } }`
  // (Exif.pm:6394-6399). `dir_end <= data_len` above ⇒ no underflow.
  let bytes_from_end = data_len - dir_end;
  if bytes_from_end == 1 || bytes_from_end == 3 {
    return CanonDirShape::AbortIllegalSize { num_entries };
  }
  CanonDirShape::Walk {
    num_entries,
    dir_end,
  }
}

/// The per-entry classification shared by the Canon `0x927c` emission walk and
/// the diagnostic walk — the 1:1 port of `ProcessExif`'s per-entry handling
/// (`Exif.pm:6454-6679`) for the in-memory, no-RAF, `$inMakerNotes = 1` frame.
/// Each variant names exactly what bundled does at that entry, so the emission
/// SKIP and the WARNING agree by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonEntryClass {
  /// A normal entry: read the value at `value_offset` (`$valuePtr`). Covers both
  /// the inline (`$size <= 4`, value at `$entry+8`) and the valid out-of-line
  /// (`$size > 4`, in-bounds, not suspect) arms.
  Read { value_offset: usize },
  /// An unrecognized NONZERO format code (`Exif.pm:6463-6477`) ⇒ `Bad format
  /// (<code>) for <dir> entry <index>`. For `index == 0` ExifTool `return 0`s
  /// (aborts the directory); for `index != 0` it `next`-skips. Either way no
  /// value is read.
  BadFormat { code: u16, abort: bool },
  /// A format code of `0` — IFD zero-padding (`Exif.pm:6470` `if ($format …)`):
  /// SILENT (no warning). `index == 0` aborts the directory; `index != 0` skips.
  SilentBadFormat { abort: bool },
  /// `$size > 0x7fffffff` (`Exif.pm:6505`) ⇒ `Invalid size (<size>) for <dir>
  /// <tag>` + `next`-skip.
  InvalidSize { size: usize },
  /// An out-of-line value past EOF with NO RAF (`Exif.pm:6660`) ⇒ `Bad offset
  /// for <dir> <tag>` + `$bad = 1` (the value is dropped) + CONTINUE. Takes
  /// precedence over `Suspicious` (the `++$warnCount` makes `$suspect !=
  /// $warnCount`, `Exif.pm:6672`).
  BadOffset,
  /// An in-bounds out-of-line value whose offset is suspect — points into the
  /// TIFF header (`< 8`, `Exif.pm:6539`) or overlaps the IFD directory
  /// (`Exif.pm:6549`) ⇒ `Suspicious <dir> offset for <tag>` + `next`-skip
  /// (`Exif.pm:6675`, non-verbose).
  Suspicious,
}

impl CanonEntryClass {
  /// Whether this entry's classification bumps `$warnCount` (`++$warnCount`) —
  /// the per-entry warnings ExifTool counts toward the `$warnCount > 10` abort
  /// (`Exif.pm:6455-6456`). The counted classes are `BadFormat` (`:6472`),
  /// `InvalidSize` (`:6507`), `BadOffset` (`:6661`) and `Suspicious` (`:6676`);
  /// `SilentBadFormat` (a `0` code, NO `Warn`) and `Read` (a clean entry) do
  /// NOT. Shared by both Canon walks so the emission abort and the diagnostic
  /// abort fire on the same entry.
  #[must_use]
  pub(crate) const fn bumps_warn_count(self) -> bool {
    matches!(
      self,
      CanonEntryClass::BadFormat { .. }
        | CanonEntryClass::InvalidSize { .. }
        | CanonEntryClass::BadOffset
        | CanonEntryClass::Suspicious
    )
  }
}

/// Classify one Canon `0x927c` IFD entry (`ProcessExif`, `Exif.pm:6454-6679`,
/// in-memory no-RAF `$inMakerNotes = 1` frame). `entry_off` is the 12-byte
/// entry's offset within `tiff_data`; `index` its 0-based position; `dir_start`
/// / `dir_end` bound the IFD; `data_len` is `tiff_data.len()` (`$dataLen`).
///
/// The result drives BOTH walks: the emission walk reads
/// [`CanonEntryClass::Read`] and skips every other variant; the diagnostic walk
/// emits the corresponding warning. The entry-header read is checked (the caller
/// proved `entry_off + 12 <= data_len`); an unreadable header yields a silent,
/// non-aborting skip (unreachable for an in-range entry).
pub(crate) fn classify_canon_entry(
  tiff_data: &[u8],
  entry_off: usize,
  index: usize,
  dir_start: usize,
  dir_end: usize,
  data_len: usize,
  order: ByteOrder,
) -> CanonEntryClass {
  let (Some(format_code), Some(count)) = (
    get_u16(tiff_data, entry_off + 2, order),
    get_u32(tiff_data, entry_off + 4, order),
  ) else {
    // Unreachable for an in-range entry (the caller bounds `entry_off + 12`);
    // treat as a non-aborting skip.
    return CanonEntryClass::SilentBadFormat { abort: false };
  };
  let count = count as usize;
  // `if (($format < 1 or $format > 13) and $format != 129 …)` (Exif.pm:6463).
  // The BigTIFF codes 14-18 map to real `Format`s but are BAD in a standard
  // Canon IFD entry (the Apple-ProRaw `$format == 16` carve-out is Apple-only).
  let recognized = Format::is_valid_ifd_code(format_code);
  if !recognized {
    // `next if $index` (Exif.pm:6475) ⇒ skip for index ≠ 0; ELSE `return 0`
    // (abort). `if ($format or $validate)` (Exif.pm:6470) ⇒ a `0` code warns
    // SILENTLY (IFD zero-padding); any other code warns `Bad format (<code>)`.
    let abort = index == 0;
    return if format_code == 0 {
      CanonEntryClass::SilentBadFormat { abort }
    } else {
      CanonEntryClass::BadFormat {
        code: format_code,
        abort,
      }
    };
  }
  let elem_size = Format::from_code(format_code).byte_size();
  // `my $size = $count * $formatSize[$format]` (Exif.pm:6502).
  let size = count.saturating_mul(elem_size);
  if size > 4 {
    // `if ($size > 0x7fffffff …) { Warn('Invalid size …'); ++$warnCount; next }`
    // (Exif.pm:6505) — the FIRST test inside the `$size > 4` block, before the
    // offset is even read.
    if size > 0x7fff_ffff {
      return CanonEntryClass::InvalidSize { size };
    }
    let Some(value_ptr) = get_u32(tiff_data, entry_off + 8, order) else {
      return CanonEntryClass::SilentBadFormat { abort: false };
    };
    let value_ptr = value_ptr as usize;
    // `$valuePtr < 8 and not ZeroOffsetOK and $suspect = $warnCount`
    // (Exif.pm:6539) OR `$valuePtr < $dirEnd and $valuePtr+$size > $dirStart`
    // (Exif.pm:6549). Canon's MakerNote is NOT `ZeroOffsetOK`.
    let value_end = value_ptr.saturating_add(size);
    let suspect = value_ptr < 8 || (value_ptr < dir_end && value_end > dir_start);
    // OOB out-of-line + no RAF ⇒ `Bad offset` (Exif.pm:6660), `++$warnCount` ⇒
    // a co-incident suspect offset is NOT also reported (Exif.pm:6672). The OOB
    // test is FIRST (matches ExifTool's read-before-suspect ordering).
    if value_end > data_len {
      CanonEntryClass::BadOffset
    } else if suspect {
      CanonEntryClass::Suspicious
    } else {
      CanonEntryClass::Read {
        value_offset: value_ptr,
      }
    }
  } else {
    // Inline: the value occupies the first `$size` bytes at `$entry+8`.
    CanonEntryClass::Read {
      value_offset: entry_off + 8,
    }
  }
}
