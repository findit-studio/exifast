// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Apple iOS MakerNote IFD body walker — Phase-2 port.
//!
//! After the dispatcher captures the raw blob and strips the 14-byte
//! `Apple iOS\0\0\x01MM` header (the `Start => '$valuePtr + 14'`
//! directive at `MakerNotes.pm:42`), this module walks the body as a
//! standard TIFF IFD.
//!
//! The body itself starts with another byte-order marker — `MM` for
//! big-endian (every Apple iPhone we've seen so far) — and the IFD entry
//! count immediately follows that marker (NOT a TIFF header — no
//! `0x002a` magic + IFD0 offset). The MakerNote `Base` directive
//! `'$start - 14'` (`MakerNotes.pm:43`) tells the walker that
//! out-of-line value offsets are RELATIVE to the start of the BLOB
//! (i.e. `body_offset - 14` from the body), so we resolve every
//! out-of-line offset against the BLOB (not just the body).

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::detected::ChildByteOrder;
use crate::value::TagValue;

/// One decoded Apple MakerNote IFD entry — the raw value plus the
/// post-PrintConv `TagValue` so the MakerNote struct can store both the
/// raw shape and the rendered string.
#[derive(Debug, Clone)]
pub struct ParsedValue {
  raw: RawValue,
}

impl ParsedValue {
  /// Wrap a decoded [`RawValue`].
  #[must_use]
  #[inline(always)]
  pub const fn new(raw: RawValue) -> Self {
    Self { raw }
  }

  /// Borrow the underlying raw value (the post-Format-decode `$val`).
  #[must_use]
  #[inline(always)]
  pub const fn raw(&self) -> &RawValue {
    &self.raw
  }

  /// The first scalar integer (signed) — works for `U64`/`I64`. Delegates to
  /// [`RawValue::first_i64`] on the wrapped value.
  #[must_use]
  pub fn first_i64(&self) -> Option<i64> {
    self.raw.first_i64()
  }

  /// The first two scalar integers (for `AFPerformance` which is `int32s[2]`).
  /// Delegates to [`RawValue::first_two_i64`].
  #[must_use]
  pub fn first_two_i64(&self) -> Option<(i64, i64)> {
    self.raw.first_two_i64()
  }

  /// The first two rational64 values as f64 — for `FocusDistanceRange`.
  /// Delegates to [`RawValue::rational_pair`].
  #[must_use]
  pub fn rational_pair(&self) -> Option<(f64, f64)> {
    self.raw.rational_pair()
  }

  /// Convert this raw value to a default [`TagValue`] (no PrintConv). Delegates
  /// to [`RawValue::to_default_tag_value`].
  #[must_use]
  pub fn to_default_tag_value(&self) -> TagValue {
    self.raw.to_default_tag_value()
  }
}

/// One IFD entry parsed from the Apple body — `(tag_id, value)`.
#[derive(Debug, Clone)]
pub struct AppleEntry {
  /// Apple tag ID (`Apple.pm:24-320` hash key).
  pub tag_id: u16,
  /// The decoded raw value.
  pub value: ParsedValue,
}

/// Walk the Apple MakerNote body and emit one [`AppleEntry`] per IFD
/// entry. The body starts with a 2-byte `II`/`MM` marker followed by
/// the 2-byte IFD entry count; the rest is a standard TIFF IFD.
///
/// `blob` is the WHOLE MakerNote blob (the raw bytes captured at
/// 0x927C). `body_offset` is the dispatcher's `Start => '$valuePtr +
/// 14'` directive, so the IFD count word sits at `body_offset +
/// header_size` and the entries follow.
///
/// Out-of-line value offsets are RELATIVE to the start of the BLOB
/// (`Base => '$start - 14'` ⇒ `base == 0`, an out-of-line offset indexes
/// the BLOB directly — `MakerNotes.pm:43`). The walk therefore reads
/// every value (inline OR out-of-line) from `blob` in BLOB-ABSOLUTE
/// coordinates, byte-identical to the shared `Walker`
/// ([`apple_makernote_isolated`](crate::exif::apple_makernote_isolated) walks
/// `data == blob`, `base == 0`, the IFD at `body_offset + header_size`).
///
/// ## ProcessExif classification equivalence
///
/// This is the differential-test ORACLE for the production Apple walk, which
/// runs the shared `Walker` (the faithful `ProcessExif`). To keep the two
/// byte-identical on crafted MakerNotes, the per-entry / per-directory CONTROL
/// FLOW here mirrors `Walker::walk_one_ifd_body` / `walk_entries` /
/// `walk_entry` exactly under Apple's context (`active_table == Apple` ⇒
/// `is_core_ifd() == false`; the captured blob IS a readable RAF ⇒ no-RAF is
/// false). Each aligned rule is cited to `Exif.pm`:
///
/// * Directory shape (`Exif.pm:6343-6399`): a truncated count word, an
///   overflowing or past-EOF `dirEnd`, or a 1-/3-byte trailing residue
///   (`bytesFromEnd ∈ {1,3}`, "Illegal directory size") ABORTS the whole walk.
/// * Bad format code (`Exif.pm:6464-6477`): a NONZERO unrecognized code warns
///   (and counts toward the warn cap); a ZERO code is silent padding. EITHER
///   way the directory is ABORTED when the bad entry is INDEX 0 (`return 0`,
///   "assume corrupted IFD"), and the single entry is SKIPPED otherwise
///   (`next if $index`). The Apple carve-out admits format code 16 (`int64u`)
///   ONLY when the PARENT IFD0 `Make` is exactly `"Apple"` —
///   `not ($format == 16 and $$et{Make} eq 'Apple' and $inMakerNotes)`. So
///   `make` MUST be threaded from the dispatch (the IFD0 Make): an Apple-SIGNATURE
///   blob whose container Make is NOT `"Apple"` (a crafted file) classifies code
///   16 as a BAD format — entry-0 abort, later-entry skip — just like the shared
///   `Walker`'s `captured_make == Some("Apple")` gate.
/// * Invalid size (`Exif.pm:6505-6509`): an out-of-line `size > 0x7fffffff`
///   warns (counts) + SKIPs the entry.
/// * Out-of-line bounds (`Exif.pm:6549-6611`/`:6660`): an offset whose value runs
///   past EOF takes the `$inMakerNotes` "Bad offset" path (warn, counts, SKIP) —
///   not the core-IFD directory abort (`:6602`). An offset below 8 (`:6539`) or
///   one overlapping the IFD (`:6549`) is a "Suspicious offset" (warn, counts,
///   SKIP).
/// * Excessive count (`Exif.pm:6760-6770`): `count > 100000` and not
///   `undef`/`string` SKIPs; the large-array placeholder (`:6771-6779`)
///   replaces an unknown-tag `count > 500` decode.
/// * Warn-count cap (`Exif.pm:6455-6456`): once more than 10 counted per-entry
///   warnings accumulate, the directory is ABORTED before the next entry.
///
/// Returns the surviving entries in IFD walk order.
#[must_use]
pub fn walk_apple_body(
  blob: &[u8],
  body_offset: usize,
  parent_order: ByteOrder,
  make: Option<&str>,
) -> Vec<AppleEntry> {
  let mut out = Vec::new();
  if body_offset >= blob.len() {
    return out;
  }
  // The guard above ⇒ `body_offset < blob.len()`, so `.get(body_offset..)` is
  // `Some`; this slice exists only to sniff the body marker.
  let Some(body) = blob.get(body_offset..) else {
    return out;
  };
  // Resolve byte order. `MakerNotes.pm:44` is `ByteOrder => 'Unknown'`,
  // so the body marker (II/MM at offset 0-1) decides; fall back to the
  // parent walk's order if the body has no marker (degenerate — every
  // real-iPhone fixture starts with `MM`).
  let (order, header_size) = match ByteOrder::from_marker(body) {
    Some(o) => (o, 2usize),
    None => (parent_order, 0usize),
  };
  // BLOB-ABSOLUTE directory framing — the shared `Walker` walks `data == blob`
  // with the IFD count word at `ifd_start = body_offset + header_size` (`MM`/`II`
  // occupies `header_size` bytes; the count word follows). Working in blob
  // coordinates makes every offset identical to the `Walker` (`base == 0`), so no
  // body/blob translation can drift.
  let ifd_start = body_offset.saturating_add(header_size);
  // `if ($dirStart + 2 > $dataLen) { Warn('Bad … directory'); return 0 }`
  // (`Exif.pm:6381`) — an unreadable count word aborts the directory.
  let Some(num_entries) = read_u16(blob, ifd_start, order) else {
    return out;
  };
  let num_entries = num_entries as usize;
  // `$dirSize = 2 + 12*$numEntries; $dirEnd = $dirStart + $dirSize`
  // (`Exif.pm:6382`), each step checked for the 32-bit/wasm overflow class — an
  // overflow can never describe an in-range directory, so it takes the same
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
  // is GATED to `$dirLen >= 14`, which the captured-blob walk never reaches — the
  // shared `Walker` always takes the abort for the directories it handles).
  if dir_end > blob.len() {
    return out;
  }
  // `$bytesFromEnd = $dataLen - $dirEnd; if ($bytesFromEnd < 4) { unless
  // ($bytesFromEnd==2 or $bytesFromEnd==0) { Warn('Illegal … directory size');
  // return 0 } }` (`Exif.pm:6394-6399`) — a 1- or 3-byte trailing residue is a
  // malformed directory: ABORT. `dir_end <= blob.len()` (checked above) ⇒ no
  // underflow. The legal residue is the 4-byte next-IFD pointer (or a deliberate
  // 2-/0-byte truncation); Apple's IFD never chains, so we enforce the abort but
  // never read a next pointer.
  let bytes_from_end = blob.len() - dir_end;
  if bytes_from_end == 1 || bytes_from_end == 3 {
    return out;
  }
  // `$warnCount` (`Exif.pm:6455`) — counted per-entry warnings; once it exceeds
  // 10 the shared `Walker` (`walk_entries`) aborts the directory BEFORE the next
  // entry. Mirror exactly: bump for the SAME conditions the `Walker`'s
  // `warn_counted` bumps (bad format / invalid size / bad offset / suspicious
  // offset), and abort the loop at `> 10`.
  let mut warn_count: u32 = 0;
  // Walk each 12-byte entry (blob-absolute).
  for index in 0..num_entries {
    // `if ($warnCount > 10) { Warn('Too many warnings'); return 0 }`
    // (`Exif.pm:6455-6456`) — checked at the TOP of the loop body, before this
    // entry, so the entry that pushed the count to 11 was fully processed and the
    // NEXT one trips the abort (the `Walker`'s `walk_entries` order).
    if warn_count > 10 {
      break;
    }
    let entry_off = ifd_start + 2 + 12 * index;
    let Some(tag_id) = read_u16(blob, entry_off, order) else {
      continue;
    };
    let Some(format_code) = read_u16(blob, entry_off + 2, order) else {
      continue;
    };
    let Some(count) = read_u32(blob, entry_off + 4, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(format_code);

    // `if (($format < 1 or $format > 13) and $format != 129 and not ($format ==
    // 16 and $$et{Make} eq 'Apple' and $inMakerNotes)) { ... }` (`Exif.pm:6464`).
    // An unrecognized format code is BAD; the Apple maker-note carve-out admits
    // the BigTIFF `int64u` code 16 (Apple ProRAW DNG) ONLY when the parent IFD0
    // `Make` is exactly `"Apple"` — the shared `Walker`'s
    // `format_code == 16 && active_table == Apple && captured_make == Some("Apple")`.
    // For a non-Apple Make an Apple-signature blob's code 16 stays a BAD format.
    // A nonzero bad code warns + counts; a zero code is silent padding. EITHER
    // way: ABORT the directory at index 0 (`return 0`), SKIP the single entry
    // otherwise (`next if $index`).
    let recognized =
      Format::is_valid_ifd_code(format_code) || (format_code == 16 && make == Some("Apple"));
    if !recognized {
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
    // expands EMPTY (`Exif.pm:6285-6288`) exactly as `ProcessExif`. The recognized
    // gate (incl. the format-16 carve-out) guarantees `byte_size() > 0` here.
    let elem_size = format.byte_size();
    let total_size = count.saturating_mul(elem_size);

    // Resolve the value pointer (BLOB-ABSOLUTE). `$valuePtr = $entry + 8` inline
    // (`size <= 4`); else the 4 bytes at `entry+8` are an out-of-line offset
    // (`Exif.pm:6504-6510`).
    let value_offset = if total_size > 4 {
      // `if ($size > 0x7fffffff and not ReadFromRAF) { Warn('Invalid size …');
      // ++$warnCount; next }` (`Exif.pm:6505-6509`) — the FIRST test in the
      // out-of-line block, before the offset is even read. No Apple leaf carries
      // `ReadFromRAF`, so the guard reduces to `size > 0x7fffffff` ⇒ warn (counts)
      // + SKIP. Without it an oversized count would fall through to the bad-offset
      // path; modelling it explicitly keeps the warn-count + control flow exact.
      if total_size > 0x7fff_ffff {
        warn_count = warn_count.saturating_add(1);
        continue;
      }
      let Some(off) = read_u32(blob, entry_off + 8, order) else {
        continue;
      };
      let off = off as usize;
      // `$valuePtr + $size > $dataLen` (`Exif.pm:6531`), `checked_add` for the
      // 32-bit/wasm overflow class. For Apple `$inMakerNotes` is true (and
      // `is_core_ifd() == false` in the shared `Walker`), so an out-of-line value
      // past EOF takes the "Bad offset" CONTINUE — warn (counts) + SKIP — NOT the
      // core-IFD directory abort (`Exif.pm:6602` `return 0 unless $inMakerNotes`).
      let value_end = match off.checked_add(total_size) {
        Some(end) if end <= blob.len() => end,
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
      // directory-framing guard above proved `entry_off + 12 <= blob.len()`, so
      // `entry_off + 8` is in range.
      entry_off + 8
    };

    // ---- Excessive / large-array guards (`Exif.pm:6760-6783`) ----------------
    // Both apply to the post-format `format`/`count`; Apple has no `Format`
    // override, so `format`/`count` are the on-disk pair. The
    // `$formatStr !~ /^(undef|string|binary)$/` exclusion is
    // `!matches!(format, Undef | Ascii)`.
    if !matches!(format, Format::Undef | Format::Ascii) {
      // The tag's known-ness, resolved against `%Apple::Main` (the shared
      // `Walker`'s `lookup_name_in(Apple, …)`), gates both guards.
      let known = super::tags::lookup(tag_id).is_some();

      // Guard (a) — `if ($count > 100000 …) { Warn('Ignoring … excessive count');
      // next }` (`Exif.pm:6760-6770`). No Apple tag is `TransferFunction`, so the
      // 196608 carve-out never applies ⇒ a `count > 100000` entry is SKIPPED (the
      // warning is `$minor` and does NOT count toward the warn cap).
      if count > 100_000 {
        continue;
      }

      // Guard (b) — the large-array placeholder (`Exif.pm:6771-6779`). In the
      // port's world the gate reduces to `count > 500 and not $tagInfo`
      // (`$warned`/`LongBinary`/`IgnoreMinorErrors` never apply): an UNKNOWN tag
      // with `count > 500` is NOT decoded; `$val` becomes the literal `(large
      // array of $count $formatStr values)` and FALLS THROUGH to FoundTag. The
      // shared `Walker` emits this placeholder, but `%Apple::Main` has no such tag
      // (`known == false`), so the emit drops it as an unknown tag — net: no
      // emission. Producing the SAME placeholder entry here (rather than decoding
      // the large array) keeps `walk_apple_body` decode-for-decode aligned with the
      // `Walker` AND avoids the large allocation; the unknown tag is then dropped
      // at collection (`parse_with_print_conv`'s `tags::lookup(...).is_none()`
      // skip), exactly as the `Walker`'s emit does.
      if count > 500 && !known {
        let placeholder = large_array_placeholder(count, format);
        let raw = placeholder.clone().into_bytes().into_boxed_slice();
        out.push(AppleEntry {
          tag_id,
          value: ParsedValue::new(RawValue::Text {
            text: placeholder,
            raw,
          }),
        });
        continue;
      }
    }

    // Decode. The inline guard proved `entry_off + 12 <= blob.len()`; an
    // out-of-line `value_offset` was bounds-validated above (so `read_value`'s
    // window is in range). `$formatStr = 'int8u' if $format == 7 and $count == 1`
    // (`Exif.pm:6644`) — a single `undef` byte decodes as an INTEGER (`int8u`),
    // not a 1-byte blob.
    let decode_format = if matches!(format, Format::Undef) && count == 1 {
      Format::Int8u
    } else {
      format
    };
    // Pass the COUNT-based `total_size` as `read_len` (`Exif.pm:6502`, the SAME
    // size the shared `Walker` passes) — NOT an EOF-bound `avail`. For count > 0
    // this is byte-identical to `avail`; it differs ONLY for the degenerate
    // count-0 case, which expands to `undef`/empty (`Exif.pm:6285-6288`) exactly
    // as `ProcessExif`.
    let Some(raw) = read_value(blob, value_offset, decode_format, count, total_size, order) else {
      // `next unless defined $val` (`Exif.pm:7016`).
      continue;
    };
    out.push(AppleEntry {
      tag_id,
      value: ParsedValue::new(raw),
    });
  }
  let _ = ChildByteOrder::Unknown; // keep import used; safe no-op.
  out
}

/// The large-array placeholder value — `"(large array of $count $formatStr
/// values)"` (`Exif.pm:6777`), the literal string the shared `Walker`
/// (`large_array_placeholder` in `mod.rs`) stores in place of decoding an
/// unknown-tag `count > 500` array. `$formatStr` is the ExifTool format NAME
/// ([`Format::name`]). Reproduced here so `walk_apple_body` (guard (b)) is
/// decode-for-decode aligned with the `Walker`.
fn large_array_placeholder(count: usize, format: Format) -> std::string::String {
  std::format!("(large array of {count} {} values)", format.name())
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // The `.get(pos..pos+2)?` slice has length 2, so `try_into::<[u8;2]>` always
  // succeeds; this is byte-identical to `[b[0], b[1]]` without raw indexing.
  let arr: [u8; 2] = data.get(pos..pos + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // The `.get(pos..pos+4)?` slice has length 4, so `try_into::<[u8;4]>` always
  // succeeds; this is byte-identical to `[b[0]..b[3]]` without raw indexing.
  let arr: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

use std::vec::Vec;

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Synthetic Apple MakerNote — `Apple iOS\0\0\x01MM` header + 1 IFD
  /// entry for `MakerNoteVersion` (tag 0x0001, int32s, count 1, inline
  /// value = 4).
  #[test]
  fn synthetic_apple_body_emits_makernoteversion() {
    let mut blob: Vec<u8> = Vec::new();
    // 14-byte Apple header.
    blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    // Body: `MM` marker + 1 entry.
    blob.extend_from_slice(b"MM");
    blob.extend_from_slice(&[0x00, 0x01]); // num_entries=1
    // Entry: tag 0x0001, format 0x0009 (int32s), count 1, value 4.
    blob.extend_from_slice(&[0x00, 0x01]); // tag
    blob.extend_from_slice(&[0x00, 0x09]); // int32s
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // value 4

    let entries = walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(entries.len(), 1, "one IFD entry parsed");
    let e = &entries[0];
    assert_eq!(e.tag_id, 0x0001);
    assert_eq!(e.value.first_i64(), Some(4));
  }

  /// Header is malformed (too short) → no entries.
  #[test]
  fn truncated_body_emits_no_entries() {
    let blob = b"Apple iOS\x00\x00\x01M";
    assert!(walk_apple_body(blob, 14, ByteOrder::Big, Some("Apple")).is_empty());
  }

  /// Empty body → no entries.
  #[test]
  fn empty_body_emits_no_entries() {
    let blob = b"Apple iOS\x00\x00\x01MM";
    let entries = walk_apple_body(blob, 14, ByteOrder::Big, Some("Apple"));
    assert!(entries.is_empty());
  }

  /// Three int32s + 1 rational value with an out-of-line offset.
  #[test]
  fn synthetic_body_with_offset_value() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    blob.extend_from_slice(b"MM");
    blob.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // Entry: tag 0x0008 (AccelerationVector), rational64s, count 3.
    blob.extend_from_slice(&[0x00, 0x08]);
    blob.extend_from_slice(&[0x00, 0x0a]); // rational64s = 10
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // count 3
    // Out-of-line offset: 14 (Apple header) + 2 (MM) + 2 (count) + 12 = 30.
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // 30
    // Append 3 rationals (24 bytes total).
    for n in [(-1i32, 100i32), (2i32, 100i32), (-7i32, 10i32)] {
      blob.extend_from_slice(&n.0.to_be_bytes());
      blob.extend_from_slice(&n.1.to_be_bytes());
    }
    let entries = walk_apple_body(&blob, 14, ByteOrder::Big, Some("Apple"));
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.tag_id, 0x0008);
    let raw = e.value.raw();
    if let RawValue::Rational(rs) = raw {
      assert_eq!(rs.len(), 3);
      assert_eq!(rs[0].numerator(), -1);
      assert_eq!(rs[1].numerator(), 2);
      assert_eq!(rs[2].numerator(), -7);
    } else {
      panic!("expected Rational, got {raw:?}");
    }

    // FIX 2: a no-PrintConv multi-rational renders as space-joined DECIMAL
    // scalars (`Rational::exiftool_val_str`), NOT `n/d` fractions. ExifTool
    // emits AccelerationVector (rational64s, no PrintConv) this way.
    match e.value.to_default_tag_value() {
      TagValue::Str(s) => {
        assert_eq!(s.as_str(), "-0.01 0.02 -0.7", "decimal, not fractions");
        assert!(!s.as_str().contains('/'), "no n/d fractions: {s}");
      }
      other => panic!("expected joined-decimal Str, got {other:?}"),
    }
  }
}
