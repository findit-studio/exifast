// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony MakerNote IFD body walker — Phase-3 port.
//!
//! Sony has SEVERAL signature variants (`MakerNotes.pm:1031-1099`):
//!
//! - `MakerNoteSony` — `SONY (DSC|CAM|MOBILE)`/`\0\0SONY PIC\0`/`VHAB     \0`
//!   prefix; body at `$valuePtr + 12`. No `Base` override (inherit parent).
//!   Routes to `Image::ExifTool::Sony::Main`.
//! - `MakerNoteSony5` — headerless body (`Start => '$valuePtr'`); no
//!   `Base` override. Routes to `Image::ExifTool::Sony::Main`.
//! - `MakerNoteSonyEricsson` — `SEMC MS\0` prefix; body at
//!   `$valuePtr + 20`, `Base => '$start - 8'`. Routes to `Sony::Ericsson`
//!   (Phase 3 ports the Sony Main table only — Ericsson decoding is a
//!   deferred long-tail item).
//!
//! Phase 3 walks the BODY for both `MakerNoteSony` and `MakerNoteSony5`
//! by accepting a body-offset argument from the dispatcher. Out-of-line
//! offsets in entries are TIFF-relative (since Sony inherits the parent
//! `Base`, no `Base =>` override): an offset indexes `tiff_data[off]`
//! directly (`base == 0`), and the directory extent is bounded by the
//! WHOLE TIFF buffer (`tiff_data.len()`), matching the shared `Walker`'s
//! `ProcessExif` walk over `data == tiff_data`.
//!
//! [`walk_sony_in_tiff`] is the differential-test ORACLE for the
//! production Sony walk (the shared `Walker` via
//! `exif::mod::sony_makernote_isolated`); its per-entry / per-directory
//! classification control flow is `ProcessExif`-equivalent (see the
//! function doc for the rule-by-rule `Exif.pm` citations).

#![deny(clippy::indexing_slicing)]

use super::tags;
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::vendors::resolve_read_format;
use std::string::String;
use std::vec::Vec;

/// One decoded Sony MakerNote IFD entry — the tag + format + the
/// post-Format-decode `RawValue`.
#[derive(Debug, Clone)]
pub struct SonyEntry {
  /// Tag ID (`Sony.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the Sony MakerNote body in the parent TIFF context. `tiff_data`
/// is the parent TIFF block; `mn_offset` is the start of the captured
/// MakerNote within `tiff_data`; `mn_len` is its byte length;
/// `body_offset` is the BODY start offset within the captured MakerNote
/// (12 for the `SONY DSC ` prefix variant, 0 for `MakerNoteSony5`).
/// `parent_order` is the parent IFD walk's byte order — Sony's bodies
/// have no MM/II marker so the byte order falls back to the parent
/// (`ChildByteOrder::Unknown` resolves to parent here).
///
/// Out-of-line value offsets in entries are TIFF-relative (Sony inherits
/// the parent `Base`, no `Base =>` override): an offset indexes
/// `tiff_data[off]` directly (`base == 0`).
///
/// ## ProcessExif classification equivalence
///
/// This is the differential-test ORACLE for the production Sony walk, which runs
/// the shared `Walker` (the faithful `ProcessExif`) over the SAME `tiff_data` at
/// the SAME `mn_offset + body_offset`, `base == 0`, `active_table == Sony`
/// (`exif::mod::sony_makernote_isolated`). To keep the two byte-identical on
/// crafted Sony MakerNotes, the per-entry / per-directory CONTROL FLOW here
/// mirrors `Walker::walk_one_ifd_body` / `walk_entries` / `walk_entry` exactly
/// under Sony's context (`is_core_ifd() == false` ⇒ a maker-note directory; the
/// parent TIFF block IS a readable buffer ⇒ the no-RAF path is false). Each
/// aligned rule cites the same `Exif.pm` line the shared `Walker` and
/// `walk_apple_body` cite:
///
/// * Directory shape (`Exif.pm:6343-6399`): a truncated count word, an
///   overflowing or past-EOF `dirEnd`, or a 1-/3-byte trailing residue
///   (`bytesFromEnd ∈ {1,3}`, "Illegal directory size") ABORTS the whole walk.
///   The framing bounds against `tiff_data.len()` — the whole TIFF — NOT
///   `mn_offset + mn_len` (`mn_len` is only the dispatcher's variant-gate window;
///   the shared `Walker` walks `data == tiff_data`).
/// * Bad format code (`Exif.pm:6464-6477`): a NONZERO unrecognized code warns
///   (and counts toward the warn cap); a ZERO code is silent padding. EITHER way
///   the directory is ABORTED when the bad entry is INDEX 0 (`return 0`, "assume
///   corrupted IFD"), and the single entry is SKIPPED otherwise (`next if
///   $index`). Sony has no ProRAW int64u, so the Apple format-16/Make carve-out
///   does NOT apply — code 16 stays a BAD format here.
/// * Count-based value size (`Exif.pm:6502` `$size = $count * $formatSize`, with
///   the `:6285` count-0 expansion): the on-disk byte size sizes the value and
///   decides inline-vs-out-of-line BEFORE the `Format` override; a count-0 entry
///   reads zero bytes ⇒ the empty `$val`.
/// * Invalid size (`Exif.pm:6505-6509`): an out-of-line `size > 0x7fffffff`
///   warns (counts) + SKIPs the entry — the FIRST test in the out-of-line block.
/// * Out-of-line bounds (`Exif.pm:6549-6660`): an offset whose value runs past
///   EOF takes the maker-note "Bad offset" CONTINUE (`Exif.pm:6660`, warn +
///   counts + SKIP), NOT the core-IFD directory abort (`:6602` is `return 0
///   unless $inMakerNotes`). An offset below 8 (`:6539`) or one overlapping the
///   IFD (`:6549`) is a "Suspicious offset" (warn, counts, SKIP).
/// * Format override (`Exif.pm:6729-6744`): the tag's `Format =>` re-reads the
///   SAME value bytes with the override format + recomputed count. The on-disk
///   `format`/`count` are preserved on the entry for the `$format`-based
///   single-HASH `Condition` gate (`super::def_format`); only the VALUE READ +
///   the post-override guards use the override pair.
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
pub fn walk_sony_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
) -> Vec<SonyEntry> {
  let mut out = Vec::new();
  // The dispatcher's variant-gate window must at least contain the count word
  // (`mn_len >= body_offset + 2`); below that there is no IFD. The shared
  // `Walker` walks `tiff_data` (not the `mn_len` slice) but is reached only when
  // the captured blob routed to `%Sony::Main`, so this guard mirrors the
  // dispatcher having a real Sony body — it does NOT clamp the directory extent.
  // `body_offset + 2` is `checked_add`ed for the usize-overflow class, matching
  // the production guard (`exif::mod::sony_makernote_isolated`, the
  // `match body_offset.checked_add(2)` reverse test): an overflow can never
  // satisfy `mn_len >=`, so it returns the SAME empty result the `<` test does —
  // keeping the oracle byte-identical to the production path on every input.
  match body_offset.checked_add(2) {
    Some(min_len) if mn_len >= min_len => {}
    _ => return out,
  }
  // TIFF-ABSOLUTE directory framing — the shared `Walker` walks `data ==
  // tiff_data` with the IFD count word at `ifd_start = mn_offset + body_offset`
  // (Sony's body has no II/MM marker; the parent order governs, `base == 0`).
  // `parent_order` is `MakerNotes.pm:44`'s `ByteOrder => 'Unknown'` resolved to
  // the parent (Sony's body carries no marker — `process_subdir`'s
  // `ByteOrderRule::Fixed(order)` is the same parent order).
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
  // Bad-directory abort the shared `Walker` does (`walk_one_ifd_body`). (The
  // prior `> 1024` cap is NOT ExifTool: a large-but-fitting IFD is walked; the
  // bound is the buffer, checked next.)
  let Some(dir_end) = num_entries
    .checked_mul(12)
    .and_then(|entry_bytes| entry_bytes.checked_add(2))
    .and_then(|dir_size| ifd_start.checked_add(dir_size))
  else {
    return out;
  };
  // `$dirEnd > $dataLen` ⇒ the IFD overruns the buffer; the `Walker` aborts the
  // whole directory (the MakerNotes "read what we can" salvage at `Exif.pm:6386`
  // is GATED to `$dirLen >= 14`, which the captured-blob walk never reaches — the
  // shared `Walker` always takes the abort for the directories it handles). The
  // bound is `tiff_data.len()` — the whole TIFF — matching the shared `Walker`'s
  // `data.len()` (NOT `mn_offset + mn_len`, which is only the variant-gate
  // window the dispatcher used to classify the blob).
  if dir_end > tiff_data.len() {
    return out;
  }
  // `$bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) { unless
  // ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn('Illegal … directory size');
  // return 0 } }` (`Exif.pm:6394-6399`) — a 1- or 3-byte trailing residue is a
  // malformed directory: ABORT. `dir_end <= tiff_data.len()` (checked above) ⇒ no
  // underflow. The legal residue is the 4-byte next-IFD pointer (or a deliberate
  // 2-/0-byte truncation); Sony's Main IFD never chains, so we enforce the abort
  // but never read a next pointer.
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
    // `walk_entries` (`exif::mod`, `index.checked_mul(12).and_then(+2).and_then(
    // ifd_start.checked_add)`). The checked `dir_end = ifd_start + 2 +
    // 12*num_entries` above already proves every in-range `entry_off` fits, but
    // keep the arithmetic explicitly checked so it does not silently depend on
    // that invariant; an overflow STOPS the entry loop (`break`), exactly as the
    // shared `Walker` treats it (past-EOF, like the 12-byte entry-read guard).
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
    // (`Exif.pm:6464`). An unrecognized format code is BAD. Sony has no ProRAW
    // int64u, so the Apple format-16/Make carve-out does NOT apply — code 16 (and
    // any code outside `1..=13`/`129`, incl. the `byte_size 0` codes 0/14/15) is
    // a BAD format. A nonzero bad code warns + counts; a zero code is silent
    // padding. EITHER way: ABORT the directory at index 0 (`return 0`), SKIP the
    // single entry otherwise (`next if $index`).
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
      // out-of-line block, before the offset is even read. No Sony leaf carries
      // `ReadFromRAF`, so the guard reduces to `size > 0x7fffffff` ⇒ warn (counts)
      // + SKIP.
      if total_size > 0x7fff_ffff {
        warn_count = warn_count.saturating_add(1);
        continue;
      }
      // `$valuePtr = Get32u($dataPt, $entry + 8)` (`Exif.pm:6510`) — the
      // out-of-line offset word. `entry_off + 8` is `checked_add`ed for the
      // usize-overflow class (the shared `Walker` reads it under the same
      // `entry+12 <= data.len()` invariant); an overflow is unreadable ⇒ SKIP,
      // exactly as `read_u32` returning `None` does.
      let Some(value_ptr_off) = entry_off.checked_add(8) else {
        continue;
      };
      let Some(off) = read_u32(tiff_data, value_ptr_off, order) else {
        continue;
      };
      let off = off as usize;
      // `$valuePtr + $size > $dataLen` (`Exif.pm:6531`), `checked_add` for the
      // 32-bit/wasm overflow class. A Sony Main walk IS `$inMakerNotes` (and
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
      // non-overflowing `off + size`.
      let overlaps_ifd = off < dir_end && value_end > ifd_start;
      if off < 8 || overlaps_ifd {
        warn_count = warn_count.saturating_add(1);
        continue;
      }
      off
    } else {
      // Inline: the value occupies the first `size` bytes at `entry + 8`. The
      // directory-framing guard above proved `entry_off + 12 <= tiff_data.len()`,
      // so `entry_off + 8` is in range; `checked_add` keeps that explicit across
      // the read (the shared `Walker`'s inline arm does the same with
      // `entry.checked_add(8)` ⇒ `Step::Skip` on the impossible overflow, which
      // is this `continue`).
      let Some(value_offset) = entry_off.checked_add(8) else {
        continue;
      };
      value_offset
    };

    // Apply the tag's `Format` directive (`Exif.pm:6735-6744`): re-interpret the
    // SAME value bytes with the override format + recomputed count. The on-disk
    // `format`/`count` are preserved on the entry; only the VALUE READ + the
    // post-override guards use the override pair.
    let table_override = tags::lookup(tag_id).and_then(|t| t.format);
    let (read_format, read_count) = resolve_read_format(format, count, table_override);

    // ---- Excessive / large-array guards (`Exif.pm:6760-6783`) ----------------
    // Both apply to the POST-`Format`-override `(read_format, read_count)`
    // (`Exif.pm:6760+` runs after the `:6729-6744` override). The
    // `$formatStr !~ /^(undef|string|binary)$/` exclusion is
    // `!matches!(read_format, Undef | Ascii)`.
    if !matches!(read_format, Format::Undef | Format::Ascii) {
      // The tag's known-ness, resolved against `%Sony::Main` (the shared
      // `Walker`'s `lookup_name_in(Sony, …)`), gates both guards.
      let known = tags::lookup(tag_id).is_some();

      // Guard (a) — `if ($count > 100000 …) { Warn('Ignoring … excessive count');
      // next }` (`Exif.pm:6760-6770`). No Sony tag is `TransferFunction`, so the
      // 196608 carve-out never applies ⇒ a `count > 100000` entry is SKIPPED (the
      // warning is `$minor` and does NOT count toward the warn cap).
      if read_count > 100_000 {
        continue;
      }

      // Guard (b) — the large-array placeholder (`Exif.pm:6771-6779`). In the
      // port's world the gate reduces to `count > 500 and not $tagInfo`
      // (`$warned`/`LongBinary`/`IgnoreMinorErrors` never apply): an UNKNOWN tag
      // with `count > 500` is NOT decoded; `$val` becomes the literal `(large
      // array of $count $formatStr values)` and FALLS THROUGH to FoundTag. The
      // shared `Walker` emits this placeholder, but an unknown Sony tag is dropped
      // at collection (`parse_in_tiff`'s `tags::lookup(...).is_none()` skip), so
      // the emit drops it — net: no emission. Producing the SAME placeholder entry
      // here (rather than decoding the large array) keeps `walk_sony_in_tiff`
      // decode-for-decode aligned with the `Walker` AND avoids the large
      // allocation; the unknown tag is then dropped at collection.
      if read_count > 500 && !known {
        let placeholder = large_array_placeholder(read_count, read_format);
        let raw = placeholder.clone().into_bytes().into_boxed_slice();
        out.push(SonyEntry {
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
    // within these same bytes) — NOT an EOF-bound `avail`. For an in-bounds value
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
    out.push(SonyEntry {
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
/// ([`Format::name`]). Reproduced here so `walk_sony_in_tiff` (guard (b)) is
/// decode-for-decode aligned with the `Walker`.
fn large_array_placeholder(count: usize, format: Format) -> String {
  std::format!("(large array of {count} {} values)", format.name())
}

/// Compatibility wrapper — walk Sony body when only the captured BLOB is
/// available (no parent TIFF context). Out-of-line offsets resolve
/// against the blob itself; only correct when the blob is self-contained.
#[must_use]
pub fn walk_sony_body(blob: &[u8], body_offset: usize, parent_order: ByteOrder) -> Vec<SonyEntry> {
  walk_sony_in_tiff(blob, 0, blob.len(), body_offset, parent_order)
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // `pos.checked_add(2)?` for the usize-overflow class — byte-identical to the
  // shared IFD helper `ifd::get_u16` (a `pos` so large the slice end overflows is
  // unreadable ⇒ `None`, which every caller treats as a skip). The resulting
  // slice has length 2, so `try_into::<[u8;2]>` always succeeds; this is
  // byte-identical to `[b[0], b[1]]` without raw indexing.
  let arr: [u8; 2] = data.get(pos..pos.checked_add(2)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // `pos.checked_add(4)?` for the usize-overflow class — byte-identical to the
  // shared IFD helper `ifd::get_u32` (a `pos` so large the slice end overflows is
  // unreadable ⇒ `None`, which every caller treats as a skip). The resulting
  // slice has length 4, so `try_into::<[u8;4]>` always succeeds; this is
  // byte-identical to `[b[0]..b[3]]` without raw indexing.
  let arr: [u8; 4] = data.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Synthetic Sony body — 1 entry — `Quality` (tag 0x0102, int32u, count
  /// 1, value 2 = "Fine"), little-endian, headerless (Sony5).
  #[test]
  fn synthetic_sony_quality_headerless() {
    let mut blob: Vec<u8> = Vec::new();
    // 1 entry LE
    blob.extend_from_slice(&[0x01, 0x00]);
    // Entry: tag 0x0102, int32u (4), count 1, value=2 inline.
    blob.extend_from_slice(&[0x02, 0x01]); // tag 0x0102 LE
    blob.extend_from_slice(&[0x04, 0x00]); // format 4 = int32u
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // value 2 inline
    let entries = walk_sony_body(&blob, 0, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0102);
    match &entries[0].value {
      RawValue::U64(v) => assert_eq!(v, &[2]),
      other => panic!("expected U64, got {other:?}"),
    }
  }

  /// Sony body with the 12-byte `SONY DSC \0` header.
  #[test]
  fn synthetic_sony_with_dsc_header() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"SONY DSC \x00\x00\x00");
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
    blob.extend_from_slice(&[0x02, 0x01]); // tag 0x0102
    blob.extend_from_slice(&[0x04, 0x00]); // int32u
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // value 3 inline
    let entries = walk_sony_body(&blob, 12, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0102);
  }

  #[test]
  fn empty_blob_yields_no_entries() {
    let blob: Vec<u8> = Vec::new();
    assert!(walk_sony_body(&blob, 0, ByteOrder::Little).is_empty());
  }

  #[test]
  fn implausible_count_short_circuits() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 entries LE
    assert!(walk_sony_body(&blob, 0, ByteOrder::Little).is_empty());
  }
}
