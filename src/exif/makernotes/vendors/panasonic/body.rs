// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic MakerNote IFD body walker — Phase-3 port.
//!
//! Single-walker invariant (#243 phase 5): the automatic `%Panasonic::Main`
//! route walks through the shared `Walker`
//! (`crate::exif::panasonic_makernote_isolated`); the per-vendor standalone-blob
//! `walk_panasonic_body` wrapper + the `parse` / `parse_main_gated` oracle entry
//! points were deleted. `walk_panasonic_in_tiff` (+ `parse_in_tiff`) survive
//! SOLELY as the body the CROSS-VENDOR Leica gated entries
//! (`super::parse_leica1_gated` / `parse_leica10_gated`) call — Leica was not
//! migrated to an isolated path (a tracked follow-up). Do not route the
//! automatic Panasonic path back through this walker.
//!
//! Panasonic's MakerNote (`MakerNotePanasonic`, `MakerNotes.pm:732-740`)
//! starts with the 12-byte header `Panasonic\0\0\0` and is followed by a
//! standard IFD body (`count`, `entries[]`). `Start => '$valuePtr + 12'`,
//! `ByteOrder => 'Unknown'` (the byte order falls back to the parent IFD's
//! order since the body has no MM/II marker).
//!
//! ## Out-of-line value offsets and the `Base` directive
//!
//! There are TWO variants of `%Panasonic::Main`, distinguished only by
//! `Base` (`MakerNotes.pm:732-761`):
//!
//! - `MakerNotePanasonic` (`:733`) — NO `Base =>` line, so the child IFD
//!   INHERITS the parent walk's base. Out-of-line offsets are
//!   TIFF-relative (i.e. straight indices into the parent buffer).
//! - `MakerNotePanasonic3` (`:752`, the DC-FT7) — `Base => 12` (`:758`,
//!   the bundled comment literally reads `# crazy!`). The child IFD's
//!   `$$dirInfo{Base}` becomes `eval(12) + $base` (`Exif.pm:7003`); the
//!   value-offset resolver then reads `$valuePtr -= $dataPos`
//!   (`Exif.pm:6546`) where `$subdirDataPos += $base - $subdirBase`
//!   (`Exif.pm:7040`) has shifted `$dataPos` DOWN by 12. Net effect in
//!   the port's buffer coordinates (parent `base == 0`, `dataPos == 0`):
//!   a child out-of-line offset `off` resolves to buffer position
//!   `off + 12`. Reading it at `off` (base 0) lands 12 bytes EARLY ⇒ the
//!   value is corrupted/dropped — the bug this walker's `base_offset`
//!   parameter fixes.
//!
//! The walker takes the resolved `base_offset` (the buffer addend, = the
//! literal `Base` integer; 0 for the inherit variant) from the
//! [dispatcher](crate::exif::makernotes::dispatcher) and applies it to
//! every OUT-OF-LINE offset. Inline values (≤ 4 bytes, stored in the
//! entry) carry no offset and are unaffected (`Exif.pm:6504` only the
//! `$size > 4` branch reads/rebases a pointer).

#![deny(clippy::indexing_slicing)]

use super::tags;
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::vendors::resolve_read_format;
use std::string::String;
use std::vec::Vec;

/// Header byte length for `MakerNotePanasonic` and `MakerNotePanasonic3`
/// (the 12-byte `Panasonic\0\0\0` prefix) — bundled `Start => '$valuePtr +
/// 12'` (`MakerNotes.pm:738`/`:757`). It is the DEFAULT `body_offset`; the
/// cross-table `MakerNoteLeica10` (`:724-730`) instead routes a
/// `LEICA CAMERA AG\0` blob to `%Panasonic::Main` with `Start => '$valuePtr
/// + 18'` (`:728`), so the walker takes the `body_offset` as a PARAMETER
/// rather than hard-coding 12 (mirrors the Sony walker's `body_offset`).
pub const HEADER_LEN: usize = 12;

/// One decoded Panasonic MakerNote IFD entry.
#[derive(Debug, Clone)]
pub struct PanasonicEntry {
  /// Tag ID (`Panasonic.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the Panasonic MakerNote body in the parent TIFF context, so
/// out-of-line value offsets resolve against the parent TIFF block.
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the start of the
/// captured MakerNote within `tiff_data`; `mn_len` is its byte length;
/// `parent_order` is the parent IFD walk's byte order (Panasonic's body
/// has no MM/II marker so the byte order falls back to the parent).
///
/// `body_offset` is the BODY start offset within the captured MakerNote —
/// bundled `Start => '$valuePtr + N'`. It is [`HEADER_LEN`] (12) for
/// `MakerNotePanasonic`/`MakerNotePanasonic3` (the `Panasonic\0\0\0`
/// prefix, `MakerNotes.pm:738`/`:757`) and `18` for the cross-table
/// `MakerNoteLeica10` (`LEICA CAMERA AG\0` → `%Panasonic::Main`,
/// `:728`). Mirrors the Sony walker's `body_offset` parameter.
///
/// `base_offset` is the buffer addend applied to every OUT-OF-LINE value
/// offset — the bundled `SubDirectory{Base}` directive expressed in the
/// port's buffer coordinates (`Exif.pm:6546`/`:7003`/`:7040`; see the
/// module docs). It is `0` for `MakerNotePanasonic` (no `Base` ⇒ inherit
/// the parent base), `12` for `MakerNotePanasonic3` (`Base => 12`,
/// `MakerNotes.pm:758`), and `0` for `MakerNoteLeica10` (no `Base` line,
/// `:726-730` ⇒ inherit). Inline values are never rebased.
///
/// ## ProcessExif classification equivalence
///
/// This is the differential-test ORACLE for the production Panasonic walk, which
/// runs the shared `Walker` (the faithful `ProcessExif`) over the SAME
/// `tiff_data` at the SAME `mn_offset + body_offset`, `base == 0`,
/// `value_offset_base == base_offset`, `active_table == Panasonic`
/// (`exif::mod::panasonic_makernote_isolated`). To keep the two byte-identical on
/// crafted Panasonic MakerNotes, the per-entry / per-directory CONTROL FLOW here
/// mirrors `Walker::walk_one_ifd_body` / `walk_entries` / `walk_entry` exactly
/// under Panasonic's context (`is_core_ifd() == false` ⇒ a maker-note directory;
/// the parent TIFF block IS a readable buffer ⇒ the no-RAF path is false). Each
/// aligned rule cites the same `Exif.pm` line the shared `Walker` and
/// `walk_sony_in_tiff` cite:
///
/// * Directory shape (`Exif.pm:6343-6399`): a truncated count word, an
///   overflowing or past-EOF `dirEnd`, or a 1-/3-byte trailing residue
///   (`bytesFromEnd ∈ {1,3}`, "Illegal directory size") ABORTS the whole walk.
///   The framing bounds against `tiff_data.len()` — the whole TIFF — NOT
///   `mn_offset + mn_len` (`mn_len` is only the dispatcher's variant-gate window;
///   the shared `Walker` walks `data == tiff_data`). There is NO `> 1024`
///   entry-count cap (that was NOT ExifTool: a large-but-fitting IFD is walked;
///   the bound is the buffer).
/// * Bad format code (`Exif.pm:6464-6477`): a NONZERO unrecognized code warns
///   (and counts toward the warn cap); a ZERO code is silent padding. EITHER way
///   the directory is ABORTED when the bad entry is INDEX 0 (`return 0`, "assume
///   corrupted IFD"), and the single entry is SKIPPED otherwise (`next if
///   $index`). Panasonic has no ProRAW int64u, so the Apple format-16/Make
///   carve-out does NOT apply — code 16 (and 14/15/17/18) stays a BAD format
///   here. The validity gate is [`Format::is_valid_ifd_code`] (`1..=13`/`129`),
///   NOT `byte_size() != 0` (which would wrongly ADMIT the sized codes
///   14/15/16/17/18).
/// * Count-based value size (`Exif.pm:6502` `$size = $count * $formatSize`, with
///   the `:6285` count-0 expansion): the on-disk byte size sizes the value and
///   decides inline-vs-out-of-line BEFORE the `Format` override; a count-0 entry
///   reads zero bytes ⇒ the empty `$val`.
/// * Invalid size (`Exif.pm:6505-6509`): an out-of-line `size > 0x7fffffff`
///   warns (counts) + SKIPs the entry — the FIRST test in the out-of-line block.
/// * Out-of-line bounds (`Exif.pm:6549-6660`): the resolved value pointer is
///   `raw_off + base_offset` (the DC-FT7 `Base => 12` shift, applied BEFORE every
///   bounds check, `Exif.pm:6546`). An offset whose value runs past EOF takes the
///   maker-note "Bad offset" CONTINUE (`Exif.pm:6660`, warn + counts + SKIP), NOT
///   the core-IFD directory abort (`:6602` is `return 0 unless $inMakerNotes`).
///   An offset below 8 (`:6539`) or one overlapping the IFD (`:6549`) is a
///   "Suspicious offset" (warn, counts, SKIP).
/// * Format override (`Exif.pm:6729-6744`): the tag's `Format =>` re-reads the
///   SAME value bytes with the override format + recomputed count. The on-disk
///   `format`/`count` are preserved on the entry for the `$format`-based
///   single-HASH `Condition` gate (`PanasonicPrintConv::single_hash_condition_holds`,
///   the 0xc4/0xc5/0xe4 rows); only the VALUE READ + the post-override guards use
///   the override pair.
/// * Excessive count (`Exif.pm:6760-6770`): a post-override `count > 100000` and
///   not `undef`/`string` SKIPs; the large-array placeholder (`:6771-6779`)
///   replaces an unknown-tag `count > 500` decode.
/// * `undef[1]` → `int8u` (`Exif.pm:6644`): a single `undef` byte decodes as an
///   INTEGER, not a 1-byte blob.
/// * Warn-count cap (`Exif.pm:6455-6456`): once more than 10 counted per-entry
///   warnings accumulate, the directory is ABORTED before the next entry.
///
/// Returns the surviving entries in IFD walk order.
#[must_use]
pub fn walk_panasonic_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
  base_offset: usize,
) -> Vec<PanasonicEntry> {
  let mut out = Vec::new();
  // The dispatcher's variant-gate window must at least contain the count word
  // (`mn_len >= body_offset + 2`); below that there is no IFD. The shared
  // `Walker` walks `tiff_data` (not the `mn_len` slice) but is reached only when
  // the captured blob routed to `%Panasonic::Main`, so this guard mirrors the
  // dispatcher having a real Panasonic body — it does NOT clamp the directory
  // extent. `body_offset + 2` is `checked_add`ed for the usize-overflow class,
  // matching the production guard (`exif::mod::panasonic_makernote_isolated`, the
  // `match body_offset.checked_add(2)` reverse test): an overflow can never
  // satisfy `mn_len >=`, so it returns the SAME empty result the `<` test does —
  // keeping the oracle byte-identical to the production path on every input.
  match body_offset.checked_add(2) {
    Some(min_len) if mn_len >= min_len => {}
    _ => return out,
  }
  // TIFF-ABSOLUTE directory framing — the shared `Walker` walks `data ==
  // tiff_data` with the IFD count word at `ifd_start = mn_offset + body_offset`
  // (Panasonic's body has no II/MM marker; the parent order governs). The DC-FT7
  // `Base => 12` value-offset shift is the SEPARATE `base_offset` addend applied
  // to out-of-line pointers below, NOT the directory framing.
  let order = parent_order;
  let Some(ifd_start) = mn_offset.checked_add(body_offset) else {
    return out;
  };
  // `if ($dirStart + 2 > $dataLen) { Warn('Bad … directory'); return 0 }`
  // (`Exif.pm:6381`) — an unreadable count word aborts the directory.
  let Some(num_entries) = read_u16(tiff_data, ifd_start, order) else {
    return out;
  };
  let num_entries = num_entries as usize;
  // `$dirSize = 2 + 12*$numEntries; $dirEnd = $dirStart + $dirSize`
  // (`Exif.pm:6382`), each step `checked_*` for the 32-bit/wasm overflow class —
  // an overflow can never describe an in-range directory, so it takes the same
  // Bad-directory abort the shared `Walker` does (`walk_one_ifd_body`).
  let Some(dir_end) = num_entries
    .checked_mul(12)
    .and_then(|entry_bytes| entry_bytes.checked_add(2))
    .and_then(|dir_size| ifd_start.checked_add(dir_size))
  else {
    return out;
  };
  // `$dirEnd > $dataLen` ⇒ the IFD overruns the buffer; the `Walker` aborts the
  // whole directory (the MakerNotes "read what we can" salvage at `Exif.pm:6386`
  // is GATED to `$dirLen >= 14`, which the captured-blob walk never reaches). The
  // bound is `tiff_data.len()` — the whole TIFF — matching the shared `Walker`'s
  // `data.len()` (NOT `mn_offset + mn_len`, which is only the variant-gate window
  // the dispatcher used to classify the blob).
  if dir_end > tiff_data.len() {
    return out;
  }
  // `$bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) { unless
  // ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn('Illegal … directory size');
  // return 0 } }` (`Exif.pm:6394-6399`) — a 1- or 3-byte trailing residue is a
  // malformed directory: ABORT. `dir_end <= tiff_data.len()` (checked above) ⇒ no
  // underflow. The legal residue is the 4-byte next-IFD pointer (or a deliberate
  // 2-/0-byte truncation); Panasonic's Main IFD never chains, so we enforce the
  // abort but never read a next pointer.
  let bytes_from_end = tiff_data.len() - dir_end;
  if bytes_from_end == 1 || bytes_from_end == 3 {
    return out;
  }
  // `$warnCount` (`Exif.pm:6455`) — counted per-entry warnings; once it exceeds
  // 10 the shared `Walker` (`walk_entries`) aborts the directory BEFORE the next
  // entry. Mirror exactly: bump for the SAME conditions the `Walker`'s
  // `warn_counted` bumps (bad format / invalid size / bad offset / suspicious
  // offset), and abort the loop at `> 10`.
  let mut warn_count: u32 = 0;
  for index in 0..num_entries {
    // `if ($warnCount > 10) { Warn('Too many warnings'); return 0 }`
    // (`Exif.pm:6455-6456`) — checked at the TOP of the loop body, before this
    // entry, so the entry that pushed the count to 11 was fully processed and the
    // NEXT one trips the abort (the `Walker`'s `walk_entries` order).
    if warn_count > 10 {
      break;
    }
    // `$entry = $dirStart + 2 + 12*$index` (`Exif.pm:6452`), `checked_*` for the
    // 32-bit/wasm overflow class — IDENTICAL to the shared `Walker`'s
    // `walk_entries`. The checked `dir_end` above already proves every in-range
    // `entry_off` fits, but keep the arithmetic explicitly checked; an overflow
    // STOPS the entry loop (`break`), exactly as the shared `Walker` treats it.
    let Some(entry_off) = index
      .checked_mul(12)
      .and_then(|off| off.checked_add(2))
      .and_then(|off| ifd_start.checked_add(off))
    else {
      break;
    };
    let Some(tag_id) = read_u16(tiff_data, entry_off, order) else {
      continue;
    };
    let Some(format_off) = entry_off.checked_add(2) else {
      continue;
    };
    let Some(format_code) = read_u16(tiff_data, format_off, order) else {
      continue;
    };
    let Some(count_off) = entry_off.checked_add(4) else {
      continue;
    };
    let Some(count) = read_u32(tiff_data, count_off, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(format_code);

    // `if (($format < 1 or $format > 13) and $format != 129 …) { ... }`
    // (`Exif.pm:6464`). An unrecognized format code is BAD. Panasonic has no
    // ProRAW int64u, so the Apple format-16/Make carve-out does NOT apply — code
    // 16 (and any code outside `1..=13`/`129`, incl. the `byte_size 0` codes
    // 0/14/15 AND the sized-but-illegal codes 14/15/16/17/18) is a BAD format. A
    // nonzero bad code warns + counts; a zero code is silent padding. EITHER way:
    // ABORT the directory at index 0 (`return 0`), SKIP the single entry
    // otherwise (`next if $index`). This is the `is_valid_ifd_code` gate the
    // shared `Walker`'s `walk_entry` applies — NOT the old `byte_size() == 0`
    // test, which wrongly ADMITTED the sized illegal codes.
    if !Format::is_valid_ifd_code(format_code) {
      if format_code != 0 {
        // `if ($format or $validate) { Warn('Bad format …'); ++$warnCount }`
        // (`Exif.pm:6471-6472`).
        warn_count = warn_count.saturating_add(1);
      }
      // `next if $index` (`Exif.pm:6476`) vs the first-entry `return 0`
      // (`Exif.pm:6475`): index 0 ⇒ abort the whole walk, else skip.
      if index == 0 {
        break;
      }
      continue;
    }

    // `my $size = $count * $formatSize[$format]` (`Exif.pm:6502`) — the
    // count-based on-disk byte size (NOT an EOF-bound `avail`), so a count-0 entry
    // expands EMPTY (`Exif.pm:6285-6288`) exactly as `ProcessExif`. The valid-code
    // gate guarantees `byte_size() > 0` here.
    let elem_size = format.byte_size();
    let total_size = count.saturating_mul(elem_size);

    // Resolve the value pointer (TIFF-ABSOLUTE). `$valuePtr = $entry + 8` inline
    // (`size <= 4`); else the 4 bytes at `entry+8` are an out-of-line offset
    // (`Exif.pm:6504-6510`). The inline-vs-out-of-line decision + offset bounds
    // use the ON-DISK byte size, BEFORE the `Format` override (matching ExifTool,
    // which sizes/locates the value at `:6502-6510` before the `:6729` override).
    let value_data_offset = if total_size > 4 {
      // `if ($size > 0x7fffffff and not ReadFromRAF) { Warn('Invalid size …');
      // ++$warnCount; next }` (`Exif.pm:6505-6509`) — the FIRST test in the
      // out-of-line block, before the offset is even read. No Panasonic leaf
      // carries `ReadFromRAF`, so the guard reduces to `size > 0x7fffffff` ⇒ warn
      // (counts) + SKIP.
      if total_size > 0x7fff_ffff {
        warn_count = warn_count.saturating_add(1);
        continue;
      }
      // `$valuePtr = Get32u($dataPt, $entry + 8)` (`Exif.pm:6510`) — the
      // out-of-line offset word. `entry_off + 8` is `checked_add`ed for the
      // usize-overflow class; an overflow is unreadable ⇒ SKIP, exactly as
      // `read_u32` returning `None` does.
      let Some(value_ptr_off) = entry_off.checked_add(8) else {
        continue;
      };
      let Some(off) = read_u32(tiff_data, value_ptr_off, order) else {
        continue;
      };
      // `$valuePtr -= $dataPos` (`Exif.pm:6546`) where the maker-note
      // SubDirectory shifted `$dataPos` by `$base - $subdirBase`
      // (`Exif.pm:7040`); in the port's buffer coordinates that reduces to
      // ADDING the resolved `base_offset` (the `Base` integer) to the raw
      // out-of-line offset. The shift is applied HERE, BEFORE every bounds check,
      // exactly as the shared `Walker`'s `walk_entry` applies `value_offset_base`
      // before the `:6549` EOF / `:6675` suspect tests. `base_offset` is 0 for
      // the inherit variant (offsets TIFF-relative), 12 for DC-FT7's `Base => 12`.
      // `saturating_add` keeps a degenerate `off`/base near `usize::MAX` landing
      // past EOF (the bad-offset arm), never a low-address false pass — matching
      // the `Walker`'s `raw_off.saturating_add(self.value_offset_base)`.
      let off = (off as usize).saturating_add(base_offset);
      // `$valuePtr + $size > $dataLen` (`Exif.pm:6531`), `checked_add` for the
      // 32-bit/wasm overflow class. A Panasonic Main walk IS `$inMakerNotes` (and
      // `is_core_ifd() == false` in the shared `Walker`), so an out-of-line value
      // past EOF takes the "Bad offset" CONTINUE — warn (counts) + SKIP — NOT the
      // core-IFD directory abort (`Exif.pm:6602` `return 0 unless $inMakerNotes`).
      let value_end = match off.checked_add(total_size) {
        Some(end) if end <= tiff_data.len() => end,
        _ => {
          // `Bad offset for $dir $tagStr` + `++$warnCount` + `$bad = 1` / CONTINUE
          // (`Exif.pm:6660-6661`).
          warn_count = warn_count.saturating_add(1);
          continue;
        }
      };
      // `$valuePtr < 8` (offset into the TIFF header — `Exif.pm:6539`) OR
      // `$valuePtr < $dirEnd and $valuePtr + $size > $dirStart` (the value
      // overlaps the IFD — `Exif.pm:6549`) ⇒ "Suspicious offset" + `++$warnCount`
      // + `next` (`Exif.pm:6675`). `value_end` is the already-validated,
      // non-overflowing `off + size`. The suspect test uses the SHIFTED `off`
      // (post-`base_offset`), matching the `Walker` (which tests the shifted
      // pointer too).
      let overlaps_ifd = off < dir_end && value_end > ifd_start;
      if off < 8 || overlaps_ifd {
        warn_count = warn_count.saturating_add(1);
        continue;
      }
      off
    } else {
      // Inline: the value occupies the first `size` bytes at `entry + 8`. The
      // directory-framing guard above proved `entry_off + 12 <= tiff_data.len()`,
      // so `entry_off + 8` is in range; `checked_add` keeps that explicit (the
      // shared `Walker`'s inline arm does the same with `entry.checked_add(8)`).
      let Some(value_offset) = entry_off.checked_add(8) else {
        continue;
      };
      value_offset
    };

    // Apply the tag's `Format` directive (Exif.pm:6735-6744): re-interpret the
    // SAME value bytes with the override format + recomputed count. The on-disk
    // `format`/`count` are preserved on the entry for the `$format`-based
    // `Condition` gate; only the VALUE READ + the post-override guards use the
    // override pair.
    let table_override = tags::lookup(tag_id).and_then(|t| t.format);
    let (read_format, read_count) = resolve_read_format(format, count, table_override);

    // ---- Excessive / large-array guards (`Exif.pm:6760-6783`) ----------------
    // Both apply to the POST-`Format`-override `(read_format, read_count)`
    // (`Exif.pm:6760+` runs after the `:6729-6744` override). The
    // `$formatStr !~ /^(undef|string|binary)$/` exclusion is
    // `!matches!(read_format, Undef | Ascii)`.
    if !matches!(read_format, Format::Undef | Format::Ascii) {
      // The tag's known-ness, resolved against `%Panasonic::Main` (the shared
      // `Walker`'s `lookup_name_in(Panasonic, …)`), gates both guards.
      let known = tags::lookup(tag_id).is_some();

      // Guard (a) — `if ($count > 100000 …) { Warn('Ignoring … excessive count');
      // next }` (`Exif.pm:6760-6770`). No Panasonic tag is `TransferFunction`, so
      // the 196608 carve-out never applies ⇒ a `count > 100000` entry is SKIPPED
      // (the warning is `$minor` and does NOT count toward the warn cap).
      if read_count > 100_000 {
        continue;
      }

      // Guard (b) — the large-array placeholder (`Exif.pm:6771-6779`). In the
      // port's world the gate reduces to `count > 500 and not $tagInfo`
      // (`$warned`/`LongBinary`/`IgnoreMinorErrors` never apply): an UNKNOWN tag
      // with `count > 500` is NOT decoded; `$val` becomes the literal `(large
      // array of $count $formatStr values)` and FALLS THROUGH to FoundTag. The
      // shared `Walker` emits this placeholder, but an unknown Panasonic tag is
      // dropped at collection (`parse_in_tiff`'s `tags::lookup(...).is_none()`
      // skip), so the emit drops it — net: no emission. Producing the SAME
      // placeholder entry here (rather than decoding the large array) keeps
      // `walk_panasonic_in_tiff` decode-for-decode aligned with the `Walker` AND
      // avoids the large allocation; the unknown tag is then dropped at collection.
      if read_count > 500 && !known {
        let placeholder = large_array_placeholder(read_count, read_format);
        let raw = placeholder.clone().into_bytes().into_boxed_slice();
        out.push(PanasonicEntry {
          tag_id,
          format,
          count,
          value: RawValue::Text {
            text: placeholder,
            raw,
          },
        });
        continue;
      }
    }

    // Decode. The inline guard proved `entry_off + 12 <= tiff_data.len()`; an
    // out-of-line `value_data_offset` was bounds-validated above. `$formatStr =
    // 'int8u' if $format == 7 and $count == 1` (`Exif.pm:6644`) — a single `undef`
    // byte decodes as an INTEGER (`int8u`), not a 1-byte blob. The carve-out tests
    // the POST-override `(read_format, read_count)` (the value-read pair).
    let decode_format = if matches!(read_format, Format::Undef) && read_count == 1 {
      Format::Int8u
    } else {
      read_format
    };
    // Pass the COUNT-based on-disk `total_size` as `read_len` (`Exif.pm:6502`/
    // `:6503`, the SAME size the shared `Walker` passes — the override re-reads
    // within these same bytes), NOT an EOF-bound `avail`. For an in-bounds value
    // this equals `avail.min(total_size)`; it differs only for the degenerate
    // count-0 case, which expands to the empty `$val` (`Exif.pm:6285-6288`)
    // exactly as `ProcessExif`.
    let Some(raw) = read_value(
      tiff_data,
      value_data_offset,
      decode_format,
      read_count,
      total_size,
      order,
    ) else {
      // `next unless defined $val` (`Exif.pm:7016`).
      continue;
    };
    out.push(PanasonicEntry {
      tag_id,
      format,
      count,
      value: raw,
    });
  }
  out
}

/// The large-array placeholder value — `"(large array of $count $formatStr
/// values)"` (`Exif.pm:6777`), the literal string the shared `Walker`
/// (`large_array_placeholder` in `mod.rs`) stores in place of decoding an
/// unknown-tag `count > 500` array. `$formatStr` is the ExifTool format NAME
/// ([`Format::name`]). Reproduced here so `walk_panasonic_in_tiff` (guard (b)) is
/// decode-for-decode aligned with the `Walker`.
fn large_array_placeholder(count: usize, format: Format) -> String {
  std::format!("(large array of {count} {} values)", format.name())
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // `pos.checked_add(2)?` for the usize-overflow class — byte-identical to the
  // shared IFD helper `ifd::get_u16` and `walk_sony_in_tiff`'s `read_u16` (a `pos`
  // so large the slice end overflows is unreadable ⇒ `None`, which every caller
  // treats as a skip). The resulting slice has length 2, so `try_into::<[u8;2]>`
  // always succeeds; this is byte-identical to `[b[0], b[1]]` without raw indexing.
  let arr: [u8; 2] = data.get(pos..pos.checked_add(2)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // `pos.checked_add(4)?` for the usize-overflow class — byte-identical to the
  // shared IFD helper `ifd::get_u32` and `walk_sony_in_tiff`'s `read_u32` (a `pos`
  // so large the slice end overflows is unreadable ⇒ `None`, which every caller
  // treats as a skip). The resulting slice has length 4, so `try_into::<[u8;4]>`
  // always succeeds; this is byte-identical to `[b[0]..b[3]]` without raw indexing.
  let arr: [u8; 4] = data.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}
