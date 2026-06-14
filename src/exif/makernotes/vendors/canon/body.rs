// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon MakerNote IFD body walker — Phase-2 port.
//!
//! Canon's MakerNote (`MakerNoteCanon`, `MakerNotes.pm:60-68`) has NO
//! header; the IFD starts at the first byte of the blob. The byte
//! order is `Unknown` (`MakerNotes.pm:67`) — bundled probes; the port
//! falls back to the parent walk's order (every Canon JPEG I've seen
//! reuses the parent TIFF's byte order).
//!
//! Out-of-line value offsets are RELATIVE to the parent TIFF block
//! base (Canon has no `Base` override in `MakerNotes.pm`, so it inherits
//! the parent base). Since this port walks the captured MakerNote BLOB
//! independently, we re-interpret offsets RELATIVE TO THE BLOB — the
//! standard Canon convention for JPEG-embedded MakerNotes (the value
//! data is stored INSIDE the blob, and bundled's `Base` inheritance
//! makes those offsets resolvable against the captured byte range).

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length/count guard
// and converted to a checked `.get()` form (re-asserts the parent `exif`
// deny over the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use super::printconv;
use crate::exif::ifd::{ByteOrder, Format, RawValue, get_u16, get_u32, read_value};
use std::vec::Vec;

/// The directory-shape decision shared by the Canon `0x927c` emission walk
/// ([`walk_canon_in_tiff`]) and the CTMD diagnostic walk
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

/// One decoded Canon MakerNote IFD entry — the tag + format + the
/// post-Format-decode `RawValue`.
#[derive(Debug, Clone)]
pub struct CanonEntry {
  /// Tag ID (`Canon.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the Canon MakerNote body, resolving out-of-line value offsets
/// against the SAME tiff_data as the parent walk. Canon's MakerNotes
/// don't override `Base` (`MakerNotes.pm:60-68`), so an out-of-line
/// offset stored in a Canon IFD entry is RELATIVE to the parent TIFF
/// block's start — the same `$$et{BASE}` the parent uses.
///
/// `tiff_data` is the PARENT TIFF block (the same buffer the parent
/// walker reads from). `mn_offset` is the MakerNote blob's start offset
/// within `tiff_data` (the value-pointer at the parent's 0x927C entry).
/// `mn_len` is the MakerNote blob's byte length.
/// `parent_order` is the parent IFD walk's byte order.
/// `model` is the parent body's `$$self{Model}` (from IFD0); it gates the
/// Canon Main tag `0x96` LIST (`Canon.pm:1834-1846`): EOS-5D bodies route
/// `0x96` to the `SerialInfo` SubDirectory (raw blob, deferred), while all
/// other bodies decode it as `InternalSerialNumber` (the trailing-`0xff`
/// `ValueConv` strip applies ONLY to that arm).
///
/// Returns the entries in IFD walk order. Malformed entries are skipped
/// silently.
#[must_use]
pub fn walk_canon_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  model: Option<&str>,
) -> Vec<CanonEntry> {
  let mut out = Vec::new();
  if mn_offset + 2 > tiff_data.len() || mn_len < 2 {
    return out;
  }
  let order = parent_order;
  // `$dataLen` is the whole backing buffer (`length $$dataPt`, Exif.pm:6283):
  // for the CTMD `0x927c` re-dispatch `ProcessTIFF` re-frames `$dataPt` to the
  // embedded block, so `tiff_data.len()` IS that block length; for the
  // static-file Canon MakerNote `$dataPt` is the whole parent TIFF and value
  // offsets resolve against it (the `$dataPos == 0` frame). Either way it is
  // `tiff_data.len()`. (`mn_len` is the MakerNote `$dirLen`, which only changes
  // the VERBOSE short-directory salvage — not the non-verbose walk modelled
  // here.)
  let data_len = tiff_data.len();
  // The directory-shape gate — SHARED with the CTMD diagnostic walk
  // ([`super::redispatch_ctmd_makernote_value_offset_diagnostics`]) so the
  // emission SKIP and the WARNING are driven by ONE predicate (the R8 fix). An
  // unreadable / overrunning / `1`/`3`-byte-tail directory aborts the walk (the
  // diagnostic walk raises the matching `Bad`/`Illegal directory` warning);
  // a `0`/`2`/`>= 4`-byte tail walks `num_entries`.
  let CanonDirShape::Walk {
    num_entries,
    dir_end,
  } = classify_canon_directory(tiff_data, mn_offset, data_len, order)
  else {
    return out;
  };
  let entries_start = mn_offset + 2;
  // `$warnCount` (`Exif.pm:6453`) — counts the per-entry validation warnings
  // ([`CanonEntryClass::bumps_warn_count`]). Once it exceeds ten, ExifTool emits
  // `Too many warnings -- $dir parsing aborted` (the diagnostic walk raises it)
  // and `return 0`s (`Exif.pm:6455-6456`), so this emission walk must STOP
  // reading entries at the same point — otherwise a valid entry AFTER a >10-warning
  // run would leak (the OwnerName-after-bad-run bug). Checked at the top of the
  // loop, BEFORE this entry is classified, mirroring the Perl loop guard.
  let mut warn_count: u32 = 0;
  for i in 0..num_entries {
    // `if ($warnCount > 10) { … return 0 }` (`Exif.pm:6455-6456`) — abort the
    // directory before reading any further entry.
    if warn_count > 10 {
      break;
    }
    let entry_off = entries_start + 12 * i;
    let Some(tag_id) = read_u16(tiff_data, entry_off, order) else {
      continue;
    };
    let Some(count) = read_u32(tiff_data, entry_off + 4, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(read_u16(tiff_data, entry_off + 2, order).unwrap_or(0));
    let total_size = format.byte_size().saturating_mul(count);
    // The per-entry classification — SHARED with the diagnostic walk. The
    // emission reads ONLY a `Read` entry; every bad class (bad/zero format,
    // oversized count, out-of-bounds or suspect out-of-line offset) is skipped
    // here while the diagnostic walk raises the matching warning, so SKIP and
    // WARNING agree by construction. `index == 0` bad-format aborts the whole
    // directory (ExifTool `return 0`, Exif.pm:6475); every other bad class is a
    // single-entry `next`-skip.
    let class = classify_canon_entry(tiff_data, entry_off, i, mn_offset, dir_end, data_len, order);
    // `++$warnCount` for the counted classes (`Exif.pm:6472`/6507/6661/6676) so
    // the abort cap above fires on the SAME entry as the diagnostic walk's.
    if class.bumps_warn_count() {
      warn_count = warn_count.saturating_add(1);
    }
    let value_data_offset = match class {
      CanonEntryClass::Read { value_offset } => value_offset,
      CanonEntryClass::BadFormat { abort: true, .. }
      | CanonEntryClass::SilentBadFormat { abort: true } => break,
      _ => continue,
    };
    // `0x28` `ImageUniqueID` forces `Format => 'undef'` (`Canon.pm:1729`).
    // ExifTool's `ProcessExif` overrides the entry's declared numeric format
    // with `undef` (`Exif.pm:6735-6744`) and re-derives `$count = int($size /
    // $formatSize['undef'])` BEFORE `ReadValue` runs, so `ReadValue` reads the
    // ORIGINAL `$size` on-disk bytes (`$size = $count * $formatSize[$declared]`)
    // verbatim and NEVER runs the declared numeric decode — the verbose dump
    // literally reads `int8u[16] read as undef[16]`. Take that raw-byte view
    // HERE, BEFORE `read_value`, so the declared-format path is skipped
    // entirely: we never enter `read_value`'s count-zero expansion (which would
    // re-derive `$count` from the trailing buffer that ExifTool's `undef[0]`
    // view, `$size == 0`, never touches — ExifTool's `ReadValue` returns `''`
    // for a defined `$count == 0`, `ExifTool.pm:6296-6298`), and never allocate
    // the discarded numeric `Vec` a large declared count would build. The
    // window was already proved in-bounds by the `CanonEntryClass::Read`
    // classification (`$valuePtr + $size <= dataLen` for out-of-line, or the
    // ≤4-byte inline value inside the entry); recompute it with checked
    // arithmetic + `get` so a truncated/oversized shape can only yield an empty
    // (`undef`) value, never an OOB read or panic. The downstream
    // RawConv (`$val eq "\0" x 16 ? undef : $val`) + hex `ValueConv` then
    // operate on these original `undef` bytes — NOT on a lossy numeric decode
    // (which would truncate an `int16u[8]` element > 255, zero out a
    // `float`/`double`/`rational` shape, or NUL-trim the `Ascii` string). This
    // makes `int8u[16]` / `int16u[8]` / `int32u[4]` / `undef[16]` / `float[4]`
    // / `double[2]` / `rational[2]` all read the SAME bytes (oracle-verified
    // identical hex), keeps embedded NULs, and emits the empty string for a
    // count-0 entry (oracle: `undef[0]` ⇒ `Canon:ImageUniqueID = ""`).
    let mut raw = if tag_id == 0x28 {
      let window = format
        .byte_size()
        .checked_mul(count)
        .and_then(|size| value_data_offset.checked_add(size))
        .and_then(|end| tiff_data.get(value_data_offset..end))
        .unwrap_or(&[]);
      RawValue::Bytes(window.to_vec())
    } else {
      let avail = tiff_data.len() - value_data_offset;
      let Some(decoded) = read_value(tiff_data, value_data_offset, format, count, avail, order)
      else {
        continue;
      };
      decoded
    };
    // `0x96` is a MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`):
    //
    //   0x96 => [
    //     { Name => 'SerialInfo', Condition => '$$self{Model} =~ /EOS 5D/',
    //       SubDirectory => { TagTable => '...::SerialInfo' } },
    //     { Name => 'InternalSerialNumber', Writable => 'string',
    //       ValueConv => '$val=~s/\xff+$//; $val' },  # strip 0xff (Kiss X3)
    //   ]
    //
    // The `s/\xff+$//` strip belongs ONLY to the second arm
    // (InternalSerialNumber). For an EOS-5D body the first arm wins:
    // `0x96` is the `SerialInfo` SubDirectory — a deferred binary
    // sub-table (`Canon::SerialInfo`, like ShotInfo/ColorData), so we
    // keep the RAW bytes un-stripped and surface them as a blob (the
    // emit layer renames it `SerialInfo`; the sub-table decode is a
    // Phase-2+1 follow-up). For every other body the second arm applies
    // the strip below.
    if tag_id == 0x96
      && let Some(window) = tiff_data.get(value_data_offset..value_data_offset + total_size)
    {
      if model.is_some_and(printconv::model_matches_eos_5d) {
        // First arm — `SerialInfo` SubDirectory. Deferred binary blob:
        // preserve the on-disk bytes verbatim (NO NUL-trim, NO `0xff`
        // strip — those are `string`/`InternalSerialNumber` semantics).
        raw = RawValue::Bytes(window.to_vec());
      } else if matches!(format, Format::Ascii) {
        // Second arm — `InternalSerialNumber` (`Canon.pm:1841-1845`). The
        // `s/\xff+$//` MUST run at the raw-byte level, BEFORE the
        // `string` Format's lossy UTF-8 decode turns a trailing `0xff`
        // into U+FFFD — otherwise the strip can never match. Re-derive
        // from the on-disk bytes: NUL-trim (the `string` decode,
        // `Exif`/`ExifTool.pm:6296-6302`), then strip trailing `0xff`,
        // then decode. Only `string`-format 0x96 is rewritten.
        //
        // `s/\0.*//s` — trim at the first NUL (matches `Format::Ascii`
        // decode in `read_value`).
        let nul_trimmed = match window.iter().position(|&b| b == 0) {
          // `nul` is a NUL position (`< window.len()`), so `window.get(..nul)`
          // is `Some` — the checked, byte-identical form of `&window[..nul]`.
          Some(nul) => window.get(..nul).unwrap_or(window),
          None => window,
        };
        // `s/\xff+$//` — strip one-or-more trailing `0xff` bytes.
        let end = nul_trimmed
          .iter()
          .rposition(|&b| b != 0xff)
          .map_or(0, |i| i + 1);
        // `end` is `rposition + 1` (≤ len) or 0, so `nul_trimmed.get(..end)` is
        // `Some` — the checked, byte-identical form of `&nul_trimmed[..end]`.
        let stripped = nul_trimmed.get(..end).unwrap_or(nul_trimmed);
        // `stripped` is ExifTool's post-RawConv `$val` bytes; retain them so a
        // byte-walking conv reads the original bytes, not the lossy decode.
        raw = RawValue::Text {
          text: std::string::String::from_utf8_lossy(stripped).into_owned(),
          raw: stripped.into(),
        };
      }
    }
    out.push(CanonEntry {
      tag_id,
      format,
      count,
      value: raw,
    });
  }
  out
}

/// Compatibility wrapper — walk Canon body when we ONLY have the
/// captured blob (no surrounding TIFF context). Out-of-line offsets
/// resolve against the blob itself — only correct when the blob is
/// self-contained (Canon's offsets are normally TIFF-relative, so this
/// wrapper is used only for synthetic test bodies built with
/// blob-relative offsets). `model` gates the `0x96` LIST
/// (`Canon.pm:1834-1846`); pass `None` when there's no parent body context.
#[must_use]
pub fn walk_canon_body(
  blob: &[u8],
  parent_order: ByteOrder,
  model: Option<&str>,
) -> Vec<CanonEntry> {
  walk_canon_in_tiff(blob, 0, blob.len(), parent_order, model)
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // `get(pos..pos+2)` yields exactly 2 bytes, so `try_into()` to `[u8; 2]`
  // always succeeds — the checked, byte-identical form of `[b[0], b[1]]`.
  let arr: [u8; 2] = data.get(pos..pos + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // `get(pos..pos+4)` yields exactly 4 bytes, so `try_into()` to `[u8; 4]`
  // always succeeds — the checked, byte-identical form of `[b[0], b[1], b[2], b[3]]`.
  let arr: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Synthetic Canon body: 1 entry — `CanonImageType` (tag 0x06, ASCII,
  /// count 12, value "Canon EOS X\0").
  #[test]
  fn synthetic_canon_image_type_inline_offset() {
    let mut blob: Vec<u8> = Vec::new();
    // 1 entry, little-endian (Canon JPEG fixtures are mostly LE).
    blob.extend_from_slice(&[0x01, 0x00]);
    // Entry: tag 0x0006, ASCII (2), count 12, value-as-offset.
    blob.extend_from_slice(&[0x06, 0x00]); // tag
    blob.extend_from_slice(&[0x02, 0x00]); // ASCII
    blob.extend_from_slice(&[0x0c, 0x00, 0x00, 0x00]); // count 12
    blob.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]); // offset 14 (just after entry)
    // Data at offset 14: "Canon EOS X\0" (12 bytes).
    blob.extend_from_slice(b"Canon EOS X\x00");
    let entries = walk_canon_body(&blob, ByteOrder::Little, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0006);
    match &entries[0].value {
      RawValue::Text { text: s, .. } => assert_eq!(s, "Canon EOS X"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// Build a synthetic 1-entry Canon body holding tag `0x96`
  /// (InternalSerialNumber, ASCII) with the given raw value bytes,
  /// stored out-of-line just after the single IFD entry.
  fn body_with_0x96(value_bytes: &[u8]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry, LE
    blob.extend_from_slice(&[0x96, 0x00]); // tag 0x96
    blob.extend_from_slice(&[0x02, 0x00]); // ASCII
    let count = value_bytes.len() as u32;
    blob.extend_from_slice(&count.to_le_bytes()); // count
    blob.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]); // offset 14 (after entry)
    blob.extend_from_slice(value_bytes); // data at offset 14
    blob
  }

  /// `0x96` second arm — InternalSerialNumber (`Canon.pm:1841-1845`) for
  /// a NON-EOS-5D body (here Model absent): the `s/\xff+$//` ValueConv
  /// strips trailing `0xff` bytes at the RAW-byte level — BEFORE the
  /// lossy decode would turn them into U+FFFD.
  #[test]
  fn internal_serial_number_strips_trailing_ff() {
    let entries = walk_canon_body(
      &body_with_0x96(b"ABC123\xff\xff\xff"),
      ByteOrder::Little,
      None,
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x96);
    match &entries[0].value {
      RawValue::Text { text: s, .. } => {
        assert_eq!(s, "ABC123");
        assert!(!s.contains('\u{fffd}'), "must not contain U+FFFD: {s:?}");
        assert!(!s.ends_with('\u{00ff}'));
      }
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// `0x96` FIRST arm — `SerialInfo` SubDirectory (`Canon.pm:1835-1838`)
  /// for an EOS-5D body. The trailing-`0xff` strip MUST NOT apply (it's a
  /// second-arm `InternalSerialNumber`-only `ValueConv`); the deferred
  /// sub-table is surfaced as the RAW byte blob, un-stripped.
  #[test]
  fn eos_5d_0x96_is_raw_serialinfo_blob_not_stripped() {
    let raw = b"ABC123\xff\xff\xff";
    let entries = walk_canon_body(
      &body_with_0x96(raw),
      ByteOrder::Little,
      Some("Canon EOS 5D"),
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x96);
    match &entries[0].value {
      // Un-stripped, un-NUL-trimmed raw bytes — the deferred SerialInfo blob.
      RawValue::Bytes(b) => assert_eq!(b.as_slice(), raw),
      other => panic!("expected Bytes (deferred SerialInfo blob), got {other:?}"),
    }
  }

  /// `/EOS 5D/` is an UNANCHORED substring (`Canon.pm:1837`): "EOS 5D
  /// Mark II" matches too, so it also routes to the raw SerialInfo blob.
  /// Value is >4 bytes so `body_with_0x96`'s out-of-line layout applies.
  #[test]
  fn eos_5d_mark_ii_0x96_is_raw_serialinfo_blob() {
    let raw = b"WXYZ\xff";
    let entries = walk_canon_body(
      &body_with_0x96(raw),
      ByteOrder::Little,
      Some("Canon EOS 5D Mark II"),
    );
    match &entries[0].value {
      RawValue::Bytes(b) => assert_eq!(b.as_slice(), raw),
      other => panic!("expected Bytes, got {other:?}"),
    }
  }

  /// A clean `0x96` value (no trailing `0xff`), non-EOS-5D body, passes
  /// through unchanged as the decoded `InternalSerialNumber` string.
  #[test]
  fn internal_serial_number_clean_value_unchanged() {
    let entries = walk_canon_body(&body_with_0x96(b"H1234567"), ByteOrder::Little, None);
    match &entries[0].value {
      RawValue::Text { text: s, .. } => assert_eq!(s, "H1234567"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// Empty body — no entries.
  #[test]
  fn empty_blob_yields_no_entries() {
    let blob: Vec<u8> = Vec::new();
    assert!(walk_canon_body(&blob, ByteOrder::Little, None).is_empty());
  }

  /// A huge entry count whose directory OVERRUNS the block → no entries. This
  /// is the FAITHFUL `$dirEnd > $dataLen` gate (`Exif.pm:6356` ⇒ `Bad … directory`
  /// + abort), NOT a synthetic count ceiling: `dir_end = 8 + 2 + 12*9999` far
  /// exceeds the 2-byte block, so `classify_canon_directory` returns
  /// `AbortBadDirectory`. (An in-BOUNDS large count is walked — see
  /// [`large_in_bounds_count_is_walked`].)
  #[test]
  fn overrunning_count_aborts() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 LE — overruns the 2-byte block
    assert!(walk_canon_body(&blob, ByteOrder::Little, None).is_empty());
  }

  /// A directory whose entry count exceeds 1024 but whose extent FITS the block
  /// must be fully walked — `ProcessExif` has no count ceiling (`Exif.pm:6343-6400`),
  /// only `$dirEnd <= $dataLen`. Build a 1100-entry LE Canon IFD0 (every entry a
  /// valid inline ASCII tag) and assert all 1100 decode. Guards against
  /// re-introducing a synthetic max-entry reject (oracle: bundled walks a
  /// 2000-entry in-bounds IFD with no warning).
  #[test]
  fn large_in_bounds_count_is_walked() {
    let n: usize = 1100;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&(n as u16).to_le_bytes());
    for i in 0..n {
      // tag id ascending, ASCII (2), count 2, inline value "A\0".
      blob.extend_from_slice(&(0x1000u16.wrapping_add(i as u16)).to_le_bytes());
      blob.extend_from_slice(&2u16.to_le_bytes());
      blob.extend_from_slice(&2u32.to_le_bytes());
      blob.extend_from_slice(b"A\x00\x00\x00");
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD pointer (0)
    let entries = walk_canon_body(&blob, ByteOrder::Little, None);
    assert_eq!(
      entries.len(),
      n,
      "a >1024-entry in-bounds Canon IFD must be fully walked (no count ceiling)"
    );
  }

  /// Build a minimal TIFF-frame buffer for the SUSPECT/STATIC path: an 8-byte
  /// TIFF header, then a 1-entry Canon IFD0 at `mn_offset = 8` whose single
  /// out-of-line entry (tag 0x07 = CanonFirmwareVersion, ASCII, count
  /// `value_bytes.len()`) stores `value_ptr` as its offset. The IFD directory
  /// occupies `[8, 22)` (count word + one 12-byte entry); `value_data_region`
  /// is appended at the buffer tail so a LEGITIMATE pointer (≥ `dir_end`, in
  /// bounds) has real data to read. The header bytes (`[0,8)`) double as the
  /// readable region for a `value_ptr < 8` (TIFF-header) probe.
  fn tiff_with_one_outofline_entry(value_ptr: u32, value_len: usize) -> (Vec<u8>, usize, usize) {
    let mn_offset = 8usize;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"II\x2a\x00"); // TIFF header magic (II, 0x2a)
    buf.extend_from_slice(&8u32.to_le_bytes()); // IFD0 pointer → offset 8
    buf.extend_from_slice(&1u16.to_le_bytes()); // 1 entry (offset 8)
    buf.extend_from_slice(&0x07u16.to_le_bytes()); // tag 0x07 (CanonFirmwareVersion)
    buf.extend_from_slice(&0x02u16.to_le_bytes()); // ASCII
    buf.extend_from_slice(&(value_len as u32).to_le_bytes()); // count
    buf.extend_from_slice(&value_ptr.to_le_bytes()); // out-of-line value offset
    // Pad to `dir_end` (offset 22) so a legitimate pointer can land just past
    // the directory, then append `value_len` bytes of real value data there.
    while buf.len() < 22 {
      buf.push(0);
    }
    buf.extend(std::iter::repeat_n(b'A', value_len));
    let mn_len = buf.len() - mn_offset;
    (buf, mn_offset, mn_len)
  }

  /// SUSPECT — value byte-range overlaps the IFD directory (`Exif.pm:6549`).
  /// `value_ptr = 16` puts `[16, 16+8)` inside the directory's `[8, 22)`, so
  /// bundled `next`-SKIPS the entry (Exif.pm:6672-6678) and emits NO value. The
  /// shared walker must skip it too (no `CanonEntry`), matching bundled.
  #[test]
  fn suspect_offset_overlapping_directory_is_skipped() {
    let (buf, mn_offset, mn_len) = tiff_with_one_outofline_entry(16, 8);
    let entries = walk_canon_in_tiff(&buf, mn_offset, mn_len, ByteOrder::Little, None);
    assert!(
      entries.is_empty(),
      "in-bounds value overlapping the IFD directory must be next-skipped, got {entries:?}"
    );
  }

  /// SUSPECT — stored offset points into the 8-byte TIFF header (`< 8`,
  /// `Exif.pm:6539`; Canon has no `ZeroOffsetOK`). `value_ptr = 0`, count 5 ⇒
  /// `[0, 5)` lies wholly in the header and does NOT reach the directory
  /// (`[8, 22)`), isolating the header guard from the overlap guard. Bundled
  /// `next`-SKIPS; the walker must skip too.
  #[test]
  fn suspect_offset_into_tiff_header_is_skipped() {
    let (buf, mn_offset, mn_len) = tiff_with_one_outofline_entry(0, 5);
    let entries = walk_canon_in_tiff(&buf, mn_offset, mn_len, ByteOrder::Little, None);
    assert!(
      entries.is_empty(),
      "in-bounds value pointing into the TIFF header (<8) must be next-skipped, got {entries:?}"
    );
  }

  /// NOT SUSPECT (over-skip guard) — a legitimate out-of-line value pointing
  /// just PAST the directory (`value_ptr = dir_end = 22`, in bounds, no
  /// overlap, ≥ 8) must STILL be read & emitted. This pins that the suspect
  /// skip does NOT over-fire on the normal Canon out-of-line layout.
  #[test]
  fn valid_outofline_offset_past_directory_is_emitted() {
    let (buf, mn_offset, mn_len) = tiff_with_one_outofline_entry(22, 8);
    let entries = walk_canon_in_tiff(&buf, mn_offset, mn_len, ByteOrder::Little, None);
    assert_eq!(
      entries.len(),
      1,
      "a legitimate out-of-line value must be emitted"
    );
    assert_eq!(entries[0].tag_id, 0x07);
    match &entries[0].value {
      RawValue::Text { text: s, .. } => assert_eq!(s, "AAAAAAAA"),
      other => panic!("expected Text, got {other:?}"),
    }
  }
}
