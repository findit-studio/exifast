// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Nikon MakerNote IFD body walker — the embedded-TIFF / headerless IFD walk
//! that `%Image::ExifTool::Nikon::Main` (`Nikon.pm:1778`) runs over.
//!
//! ## Header layouts (`MakerNotes.pm:48-554`)
//!
//! Nikon writes three MakerNote layouts; the dispatcher
//! ([`crate::exif::makernotes::dispatch`]) classifies them and supplies the
//! `Start`/`Base`/`ByteOrder` directives:
//!
//! - **Type 3 (`MakerNoteNikon`, `MakerNotes.pm:51-58`)** — the modern DSLR
//!   layout: 6-byte `"Nikon\0"` + a 2-byte version (`\x02\x10`/`\x02\x00`) +
//!   2 pad bytes, then an EMBEDDED TIFF header at blob offset 10
//!   (`MM`/`II` + `0x002a` magic + the 4-byte IFD0 offset). `Start =>
//!   '$valuePtr + 18'` points at the IFD itself (`10 + 8`); the `Base =>
//!   '$start - 8'` directive makes out-of-line value offsets relative to the
//!   EMBEDDED TIFF header (blob offset 10), so the IFD is self-contained.
//! - **Type 2 (`MakerNoteNikon2`, `MakerNotes.pm:539-545`)** — `"Nikon\0\x01"`
//!   header; `Start => '$valuePtr + 8'`, no `Base` override (offsets
//!   blob-relative), explicit `LittleEndian`.
//! - **Type 1 / headerless (`MakerNoteNikon3`, `MakerNotes.pm:549-554`)** —
//!   no `"Nikon"` prefix; `Make =~ /^NIKON/i`; the blob IS the IFD (`Start`
//!   defaults to `$valuePtr`), `ByteOrder => 'Unknown'`.
//!
//! This module walks the IFD generically: the caller passes the IFD start
//! offset within the blob (`ifd_offset`), the byte order, and the
//! `value_base` (the blob offset that out-of-line value offsets are counted
//! from). Type-3 sets `value_base = 10`; the headerless / type-2 layouts set
//! `value_base = 0` (blob-relative). The walk is panic-free and bounded
//! (every read is a checked `.get()`), faithful to ExifTool's `Warn`+`next`
//! on a malformed entry.

#![deny(clippy::indexing_slicing)]

use super::tags::{NikonTable, NikonTag};
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::vendors::{FormatOverride, resolve_read_format};
use crate::value::TagValue;
use std::vec::Vec;

/// One decoded IFD value (the post-Format-decode `$val`), wrapping
/// [`RawValue`] with the Nikon conversion helpers.
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

  /// Borrow the underlying raw value.
  #[must_use]
  #[inline(always)]
  pub const fn raw(&self) -> &RawValue {
    &self.raw
  }

  /// The first scalar integer (signed), accepting `U64`/`I64`.
  #[must_use]
  pub fn first_i64(&self) -> Option<i64> {
    match &self.raw {
      RawValue::I64(v) => v.first().copied(),
      RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
      _ => None,
    }
  }

  /// The post-`ReadValue` `$val` as a SINGLE all-digit count key — the faithful,
  /// FORMAT-AGNOSTIC port of ExifTool's `$count =~ /^\d+$/` test applied to the
  /// prescan-captured `$val` (`ProcessNikonEncrypted`, `Nikon.pm:13948`; the
  /// `$val` is `PrescanExif`'s `ReadValue` result, `Nikon.pm:14122`).
  ///
  /// `/^\d+$/` matches the WHOLE rendered scalar against one-or-more ASCII
  /// digits, so it is independent of the TIFF storage format: an `int32u 100`
  /// renders `"100"` (matches), an ASCII `"100"` (`string`/`undef` `0x00a7`)
  /// also renders `"100"` (matches), while a multi-element value renders
  /// space-joined (`int32u[2]` ⇒ `"100 0"`, the space fails), a negative
  /// renders with a leading `-` (fails), and a non-digit string fails. The
  /// rendering is [`RawValue::val_bytes`] — ExifTool's exact `$val` bytes for
  /// every shape. Used for the `ShutterCount` (0x00a7) count key, so a malformed
  /// `int32u[2]`/`int32s` 0x00a7 must NOT unlock decryption, while an integer OR
  /// ASCII-digit 0x00a7 does.
  ///
  /// The returned value is the count's LOW 32 BITS: ExifTool keeps the count as a
  /// numeric scalar and the cipher consumes only its four low bytes
  /// (`$key ^= ($count >> $i*8) & 0xff foreach 0..3`, `Nikon.pm:13620-13621`), so
  /// an all-digit string exceeding `u32` — which ExifTool still accepts via
  /// `/^\d+$/` and decrypts — is KEYED (not REJECTED for not fitting `u32`). The
  /// coercion uses the shared 64-bit-saturating [`super::decrypt::digit_key_u64`],
  /// faithfully modeling Perl's 64-bit numeric model: exact across the whole
  /// `u64` range, saturating beyond it (a `> u64` decimal is a crafted value Perl
  /// itself resolves via platform-defined NV→UV — no portable oracle).
  #[must_use]
  pub fn single_digit_count(&self) -> Option<u32> {
    let rendered = self.raw.val_bytes();
    // `/^\d+$/`: non-empty AND every byte an ASCII digit (no sign, space, NUL,
    // or non-digit). A space-joined multi-element render fails here.
    if rendered.is_empty() || !rendered.iter().all(u8::is_ascii_digit) {
      return None;
    }
    // The cipher's four-byte XOR fold consumes the count's low 32 bits; coerce via
    // the shared 64-bit-saturating helper and keep the low 32 bits.
    Some(super::decrypt::digit_key_u64(&rendered) as u32)
  }

  /// The first two unsigned integers (for `int16u[2]` ISO/ISOSetting).
  #[must_use]
  pub fn first_two_u64(&self) -> Option<(u64, u64)> {
    match &self.raw {
      RawValue::U64(v) if let [a, b, ..] = v.as_slice() => Some((*a, *b)),
      RawValue::I64(v) if let [a, b, ..] = v.as_slice() => {
        let a = u64::try_from(*a).ok()?;
        let b = u64::try_from(*b).ok()?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// The display string of a `Text` value, or `None` for a non-text shape.
  #[must_use]
  pub fn as_text(&self) -> Option<&str> {
    match &self.raw {
      RawValue::Text { text, .. } => Some(text.as_str()),
      _ => None,
    }
  }

  /// The bytes of an `undef`/`string` value — for the `MakerNoteVersion`
  /// ValueConv (`unpack("CCCC", $val)`), which inspects the raw on-disk
  /// bytes. `Bytes` → verbatim; `Text` → the pre-FixUTF8 NUL-trimmed bytes.
  #[must_use]
  pub fn undef_or_text_bytes(&self) -> Vec<u8> {
    match &self.raw {
      RawValue::Bytes(b) => b.clone(),
      RawValue::Text { raw, .. } => raw.to_vec(),
      _ => Vec::new(),
    }
  }

  /// The integer-array `$val` rendered as the space-joined decimal string
  /// `ReadValue` produces (`join(' ', @vals)`, `ExifTool.pm:6319`) — for the
  /// multi-`int16u` tags (`CropHiSpeed`/`RetouchHistory`/`NEFBitDepth`) whose
  /// ValueConv/PrintConv operate on the whole space-joined record. Returns
  /// `None` for a non-integer shape.
  #[must_use]
  pub fn int_list_val_string(&self) -> Option<std::string::String> {
    let mut s = std::string::String::new();
    match &self.raw {
      RawValue::U64(v) => {
        for (i, n) in v.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          s.push_str(&n.to_string());
        }
      }
      RawValue::I64(v) => {
        for (i, n) in v.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          s.push_str(&n.to_string());
        }
      }
      _ => return None,
    }
    Some(s)
  }

  /// The shared Nikon `c3` signed-fraction ValueConv
  /// (`my ($a,$b,$c)=unpack("c3",$val); $c ? $a*($b/$c) : 0`,
  /// `Nikon.pm:1846` etc.). The value is a 4-byte `undef`; the first three
  /// bytes are SIGNED (`c` = int8s).
  #[must_use]
  pub fn signed_fraction_c3(&self) -> Option<f64> {
    let bytes = self.undef_or_text_bytes();
    let a = *bytes.first()? as i8 as f64;
    let b = *bytes.get(1)? as i8 as f64;
    let c = *bytes.get(2)? as i8 as f64;
    if c != 0.0 {
      Some(a * (b / c))
    } else {
      Some(0.0)
    }
  }

  /// A `rational64u`/`rational64s` array joined as space-separated DECIMAL
  /// scalars (`ReadValue`'s `join(' ', @vals)` with `Rational::exiftool_val_str`)
  /// — the `$val` `Exif::PrintLensInfo` splits on. `None` for a non-rational.
  #[must_use]
  pub fn rational_join_decimal(&self) -> Option<std::string::String> {
    let RawValue::Rational(rs) = &self.raw else {
      return None;
    };
    let mut s = std::string::String::new();
    for (i, r) in rs.iter().enumerate() {
      if i > 0 {
        s.push(' ');
      }
      s.push_str(&r.exiftool_val_str());
    }
    Some(s)
  }

  /// Convert to the default [`TagValue`] (no PrintConv) via the shared
  /// faithful `ReadValue` renderer (integers → `I64`/`U64`, floats → `F64`,
  /// rationals → joined decimals, text → `Str`, bytes → `Bytes`).
  #[must_use]
  pub fn to_default_tag_value(&self) -> TagValue {
    crate::exif::render::render_value(&self.raw, crate::emit::ConvMode::PrintConv)
  }
}

/// One IFD entry parsed from the Nikon body — `(tag_id, format, count, value)`.
#[derive(Debug, Clone)]
pub struct NikonEntry {
  /// Nikon tag ID (`Nikon::Main` hash key).
  pub tag_id: u16,
  /// On-disk format code (kept for `$format eq "undef"` conditions).
  pub format: Format,
  /// Element count (post-Format-override).
  pub count: usize,
  /// The decoded raw value.
  pub value: RawValue,
  /// The blob offset of the value's first byte (inline within the entry, or
  /// the out-of-line target) — SubDirectory processors re-read from here.
  pub value_offset: usize,
  /// The byte length of the value as stored on disk (`elem_size * count`,
  /// clamped to the buffer) — the SubDirectory's `$size`.
  pub value_size: usize,
}

/// Walk the Nikon MakerNote IFD over `blob`.
///
/// - `ifd_offset` — the blob offset of the IFD's 2-byte entry count (the
///   dispatcher's `Start` directive). Type-3 = 18; headerless = 0.
/// - `order` — the resolved byte order (type-3 reads it from the embedded
///   TIFF marker; type-2 is explicit LE; headerless probes/inherits).
/// - `value_base` — the blob offset out-of-line value offsets are counted
///   from (type-3 `Base => $start-8` ⇒ 10; else 0).
/// - `table` — the tag table the walk is keyed against ([`NikonTable::Main`]
///   for type-3 / headerless, [`NikonTable::Type2`] for the `"Nikon\0\x01"`
///   layout). Used for BOTH the per-tag `Format`-override decode AND the
///   unknown-tag value skip, so a type-2 IFD's 0x0003..0x000b resolve through
///   `%Nikon::Type2` (an id absent from the selected table is `None` ⇒
///   unknown ⇒ value decode skipped), keeping the gate set identical.
///
/// `blob` is the buffer the IFD lives in: the captured MakerNote (type-3,
/// self-contained) or the WHOLE parent TIFF (type-2 / headerless, whose
/// out-of-line offsets are parent-relative). The entry table is bounded to
/// `blob.len()` — ExifTool's `ProcessExif` bounds the directory to the
/// SubDirectory's `DataLen` (`Exif.pm:6394`), and for an in-place MakerNote
/// `DataLen` is the parent EXIF buffer (NOT the shorter declared MakerNote
/// length `DirLen`), so this matches ExifTool: a directory whose entry count
/// runs to within the parent buffer is walked (`DirLen` only drives a
/// "Short directory" *warning*, never a hard clamp, when `dirEnd <= DataLen`).
///
/// The DIRECTORY FRAMING is the SAME `ProcessExif` shape (`Exif.pm:6343-6400`)
/// Canon's [`super::super::canon::body::classify_canon_directory`] and the
/// shared EXIF walker (`src/exif/mod.rs`) run: the 2-byte `$numEntries` read,
/// `$dirEnd = $dirStart + 2 + 12*$numEntries` (NO entry-count ceiling), the
/// `$dirEnd > $dataLen` overrun reject (`:6394`), and the ILLEGAL-TAIL abort —
/// a `$bytesFromEnd` (`$dataLen - $dirEnd`) of exactly `1` or `3` aborts the
/// whole directory BEFORE any entry is walked (`:6394-6399`), while `0`/`2`/`>=
/// 4` walk. A zero-entry directory walks zero entries.
///
/// Each entry is validated through the SAME `ProcessExif` entry-loop gate set
/// the standalone-TIFF walker and Canon's `classify_canon_entry` run — the
/// [`Format::is_valid_ifd_code`] format-code gate (entry-0-abort vs later-skip,
/// rejecting codes `14..=18`), the `Invalid size` ceiling (`Exif.pm:6505`), the
/// full-value EOF / `Bad offset` bound (`Exif.pm:6552`/`:6660`), the
/// excessive-count guard (`Exif.pm:6763`), and the SUSPICIOUS-OFFSET gate
/// (`Exif.pm:6539` raw offset `< 8` + `:6549`
/// value-range-overlaps-the-IFD-entry-table, skipped non-verbose at
/// `:6673-6677`) — so Nikon inherits the whole gate set rather than re-deriving
/// a subset. (The validate-only `:6511-6529` checks are gated on `$validate and
/// not $inMakerNotes`, so they do NOT run for a MakerNote and are excluded.)
///
/// The LOOP TERMINATION mirrors Canon/shared too: a per-directory `$warnCount`
/// (`Exif.pm:6453`) is bumped for each counted per-entry warning (nonzero
/// `Bad format` `:6472`, `Invalid size` `:6507`, no-RAF `Bad offset` `:6661`,
/// `Suspicious … offset` `:6676` — NOT the excessive-count `:6767` plain `Warn`
/// nor the `0`-code silent padding) and, BEFORE reading each next entry, a
/// `$warnCount > 10` count aborts the directory (`:6455-6456`), returning only
/// the entries accumulated so far.
///
/// Returns the entries in IFD walk order. A bad format code at entry 0 ABORTS
/// the directory (only the entries accumulated BEFORE it are returned — for
/// entry 0 that is none); any other malformed entry is skipped while the walk
/// continues.
///
/// ## Malformed-entry warnings are intentionally DROPPED (engine-wide gap)
///
/// ExifTool's `ProcessExif` emits a `[minor] Bad format (N) for MakerNotes
/// entry M` (`Exif.pm:6472`) and `[minor] Ignoring MakerNotes <tag> with
/// excessive count` (`Exif.pm:6768`) for each malformed/over-count entry it
/// SKIPS. This walker reproduces the SKIP/ABORT control flow byte-exactly but
/// returns only `Vec<NikonEntry>` — it has no warning channel. That is
/// CONSISTENT with every other ordinary MakerNote vendor walker: Canon
/// ([`super::super::canon::body::walk_canon_in_tiff`]), Sony
/// ([`super::super::sony::body::walk_sony_in_tiff`]), Panasonic and Apple all
/// likewise `continue`/`break` on a malformed entry WITHOUT surfacing a
/// per-entry diagnostic into `ExifMeta`. (The only MakerNote diagnostics that
/// DO surface are Canon's CTMD `0x927c` re-dispatch STRUCTURAL warnings —
/// `redispatch_ctmd_makernote_diagnostics`, a separate timed-metadata path, not
/// the per-entry walk.) So this is an ENGINE-WIDE makernote-warning-channel gap,
/// not a Nikon-specific omission; threading a Nikon-only channel here would make
/// the diagnostics behavior INCONSISTENT across vendors. A real (valid) Nikon
/// file emits no such warnings, so its output is unaffected. Adding the channel
/// for ALL vendors uniformly is a deferred follow-up.
#[must_use]
pub fn walk_nikon_ifd(
  blob: &[u8],
  ifd_offset: usize,
  order: ByteOrder,
  value_base: usize,
  table: NikonTable,
) -> Vec<NikonEntry> {
  let mut out = Vec::new();
  let Some(num_entries) = read_u16(blob, ifd_offset, order) else {
    return out;
  };
  let num_entries = num_entries as usize;
  // NO entry-count ceiling: `ProcessExif` (`Exif.pm:6343-6400`) reads
  // `$numEntries = Get16u(...)` (so at most 65535) and processes ALL of them,
  // bounded ONLY by `$dirEnd <= $dataLen` (the `dir_end > blob.len()` gate
  // below) and the per-entry validity gates — there is no maximum-entry
  // special case. A formerly-imposed `num_entries > 1024` reject was
  // non-ExifTool and would TRUNCATE a valid >1024-entry IFD; it is gone
  // (oracle-verified against the Canon walker's `large_in_bounds_count_is_walked`
  // — bundled walks a 2000-entry in-bounds IFD with no warning). A zero-entry
  // directory walks zero entries (the loop runs zero times); the early return
  // is just the empty-`out` shortcut.
  if num_entries == 0 {
    return out;
  }
  let entries_start = ifd_offset.saturating_add(2);
  // The 12-byte entry array (`2 + 12*numEntries`, ExifTool's `$dirSize`,
  // `Exif.pm:6347`) must fit inside the buffer — ExifTool's `$dirEnd > $dataLen`
  // bound (`:6394`), where `$dataLen` is this same parent buffer.
  let dir_end = entries_start.saturating_add(12usize.saturating_mul(num_entries));
  if dir_end > blob.len() {
    return out;
  }
  // Illegal-directory-size tail gate (`my $bytesFromEnd = $dataLen - $dirEnd; if
  // ($bytesFromEnd < 4) { unless ($bytesFromEnd == 2 or $bytesFromEnd == 0) {
  // Warn("Illegal $dir directory size ($numEntries entries)"); return 0 } }`,
  // `Exif.pm:6394-6399`), checked BEFORE any entry is walked. ExifTool reads the
  // IFD body from the file via RAF — the 2-byte count then `Read(12*n + 4)`
  // capped at EOF — so the only LEGAL residue past `$dirEnd` is the 4-byte
  // next-IFD pointer (`>= 4` ⇒ clamped to 4) or a deliberately truncated tail of
  // `2` or `0` bytes; a residue of exactly `1` or `3` bytes is a malformed
  // directory that ExifTool aborts wholesale (no tags). `dir_end <= blob.len()`
  // above ⇒ the subtraction cannot underflow. Mirrors Canon's
  // [`super::super::canon::body::classify_canon_directory`]
  // (`CanonDirShape::AbortIllegalSize`, `body.rs` `bytes_from_end == 1 || == 3`)
  // and the shared EXIF walker (`src/exif/mod.rs` `walk_one_ifd_body`, the
  // `bytes_from_end == 1 || bytes_from_end == 3` abort): a `0`/`2`/`>= 4`-byte
  // tail walks `num_entries`. Without it a type-3 (blob-as-buffer) Nikon
  // MakerNote whose entry table is valid but is followed by a 1- or 3-byte tail
  // emits Nikon tags ExifTool suppresses. The matching `Illegal … directory
  // size` WARNING stays the engine-wide makernote-warning-channel gap (#230, see
  // the fn-level note); only the TAG-suppression abort is reproduced here.
  let bytes_from_end = blob.len() - dir_end;
  if bytes_from_end == 1 || bytes_from_end == 3 {
    return out;
  }
  // `$warnCount` (`Exif.pm:6453`, `my ($warnCount, $lastID) = (0, -1)`) — the
  // PER-DIRECTORY validation-warning counter. ExifTool bumps it for each
  // counted per-entry warning (`++$warnCount`) and, BEFORE reading each next
  // entry, `if ($warnCount > 10) { Warn("Too many warnings -- $dir parsing
  // aborted", 2); return 0 }` (`Exif.pm:6455-6456`) — so a directory that piles
  // up more than ten counted warnings is abandoned (its later entries + next-IFD
  // pointer NOT processed). Mirrors Canon's `walk_canon_in_tiff` per-directory
  // `warn_count` (`body.rs`) and the shared EXIF walker's `Walker::warn_count`
  // (`src/exif/mod.rs`). The counted classes are exactly those whose ExifTool
  // site is immediately followed by `++$warnCount`: nonzero `Bad format`
  // (`:6472`), `Invalid size` (`:6507`), the no-RAF `Bad offset` (`:6661`) and
  // `Suspicious … offset` (`:6676`) — NOT the excessive-count warning (`:6767`
  // uses a plain `Warn`, no `++$warnCount`) nor the `0`-code silent padding (no
  // `Warn` at all). Grounded against the shared walker's `warn_counted` doc
  // (`src/exif/mod.rs`) + Canon's [`CanonEntryClass::bumps_warn_count`].
  let mut warn_count: u32 = 0;
  for i in 0..num_entries {
    // `if ($warnCount > 10) { … return 0 }` (`Exif.pm:6455-6456`) — abort the
    // directory BEFORE reading any further entry, returning the entries
    // accumulated so far. Mirrors Canon's loop-top guard (`body.rs`); without it
    // a crafted Nikon MakerNote with >10 counted-malformed entries followed by a
    // valid tag would still emit that late tag, whereas ExifTool aborts.
    if warn_count > 10 {
      break;
    }
    // `$entry = $entryBased ? … : $dirStart + 2 + 12 * $index` (`Exif.pm:6459`):
    // the byte offset of the 12-byte entry. On 64-bit `i < num_entries <= 65535`
    // and `entries_start` is framing-bounded so this cannot overflow, but make the
    // `2 + 12*i + ifd_offset` chain explicit (the deny-overflow class) — an
    // overflow is unreachable, so `break` matches the in-bounds walk's tail
    // (mirrors `sony/body.rs`'s `index.checked_mul(12)…` with `break`).
    let Some(entry_off) = i
      .checked_mul(12)
      .and_then(|o| o.checked_add(2))
      .and_then(|o| ifd_offset.checked_add(o))
    else {
      break;
    };
    let Some(tag_id) = read_u16(blob, entry_off, order) else {
      continue;
    };
    let Some(fmt_pos) = entry_off.checked_add(2) else {
      continue;
    };
    let Some(format_code) = read_u16(blob, fmt_pos, order) else {
      continue;
    };
    let Some(count_pos) = entry_off.checked_add(4) else {
      continue;
    };
    let Some(count) = read_u32(blob, count_pos, order) else {
      continue;
    };
    let count = count as usize;
    // Per-entry format-validity gate — the shared `ProcessExif` entry classifier
    // (`Exif.pm:6463-6477`), the SAME predicate the standalone-TIFF walker
    // (`src/exif/mod.rs`) and Canon's `classify_canon_entry` use
    // ([`Format::is_valid_ifd_code`]). `ProcessExif` accepts ONLY the format
    // codes `1..=13 | 129`; ANY other nonzero code (incl. the BigTIFF/Unicode/
    // Complex codes `14..=18`, which `Format::from_code` maps to real `Format`s
    // with a NONZERO `byte_size`) is `Bad format`: `next if $index`
    // (`Exif.pm:6476`) — a LATER bad entry is SKIPPED — ELSE (`$index == 0`)
    // `return 0` (`Exif.pm:6475`), which ABORTS the whole directory ("assume
    // corrupted IFD if this is our first entry"). A `0` code is silent IFD
    // zero-padding (same abort-at-0 / skip-later control flow). This walk emits
    // no warnings (it returns the accumulated entries; the `Bad format` minor
    // warning is dropped, consistent with every vendor walker — see the
    // fn-level note), so both arms reduce to break-vs-continue. Ground-truthed
    // against `perl exiftool 13.59`: a Nikon MakerNote whose entry 0 has format
    // 99 (or 14..=18) followed by a valid `LensType` emits NOTHING from the
    // directory (abort); the same bad format at a LATER entry drops only that
    // entry while the valid ones before/after still emit.
    if !Format::is_valid_ifd_code(format_code) {
      // `if ($format or $validate) { Warn("Bad format …"); ++$warnCount }`
      // (`Exif.pm:6470-6472`): a NONZERO bad code counts toward the
      // `$warnCount > 10` abort cap; a `0` code is silent IFD zero-padding (NO
      // `Warn`, NO `++$warnCount`) — matching Canon's
      // [`CanonEntryClass::bumps_warn_count`] (`BadFormat` counts,
      // `SilentBadFormat` does not). The bump precedes the abort/skip just as
      // ExifTool's `++$warnCount` precedes the `next if $index` / `return 0`
      // (harmless on the entry-0 abort, which returns immediately).
      if format_code != 0 {
        warn_count = warn_count.saturating_add(1);
      }
      if i == 0 {
        return out; // `return 0` — abort the directory (entry-0 bad format).
      }
      continue; // `next` — skip this entry, keep walking the IFD.
    }
    let format = Format::from_code(format_code);
    // A `1..=13 | 129` code always has a nonzero `byte_size` (only `Unknown`
    // reports 0, and the gate above rejected every code that maps to it).
    let total_size = format.byte_size().saturating_mul(count);
    // Invalid-size guard (`if ($size > 0x7fffffff and (not $tagInfo or not
    // $$tagInfo{ReadFromRAF})) { Warn('Invalid size …'); ++$warnCount; next }`,
    // `Exif.pm:6505-6509`): a `count * formatSize` past the signed-32-bit
    // ceiling is the per-entry `next` (SKIP, not a directory abort) BEFORE the
    // offset is read or the value decoded. No Nikon MakerNote leaf carries
    // `ReadFromRAF` (it lives on 3 non-camera `Exif.pm` tags), so the guard
    // reduces to `total_size > 0x7fffffff`. ExifTool nests this inside its
    // `$size > 4` (out-of-line) block, but `total_size > 0x7fffffff` already
    // implies `total_size > 4`, so testing it here — ahead of the inline/
    // out-of-line split — is observationally identical: only an out-of-line
    // entry can ever trip it. Mirrors the shared EXIF walker's `if size >
    // 0x7fff_ffff` (`src/exif/mod.rs`) and Canon's `CanonEntryClass::InvalidSize`.
    if total_size > 0x7fff_ffff {
      warn_count = warn_count.saturating_add(1); // `++$warnCount` (Exif.pm:6507)
      continue; // `next` — skip the entry, keep walking the IFD.
    }
    // Inline if it fits in 4 bytes; else an out-of-line offset relative to
    // `value_base` (the embedded-TIFF base for type-3 / parent-TIFF-absolute
    // for type-2 / headerless). The out-of-line target resolves against the
    // PARENT TIFF (`blob.len()` is the parent TIFF length for those layouts),
    // NOT the MakerNote end — Nikon offsets are parent-relative.
    //
    // `raw_offset` is the u32 stored in the entry's value field (ExifTool's
    // `$valuePtr` at `Exif.pm:6510`, BEFORE the 6544/6546 conversion to a
    // buffer pointer) — the suspicious-offset gate below tests it RAW.
    let (value_data_offset, raw_offset) = if total_size <= 4 {
      let Some(inline) = entry_off.checked_add(8) else {
        continue;
      };
      (inline, None)
    } else {
      let Some(value_field) = entry_off.checked_add(8) else {
        continue;
      };
      let Some(off) = read_u32(blob, value_field, order) else {
        continue;
      };
      let Some(abs) = (off as usize).checked_add(value_base) else {
        continue;
      };
      (abs, Some(off as usize))
    };
    // The FULL value must fit in the buffer (`$valuePtr + $size <= $dataLen`,
    // `Exif.pm:6552`): when it does not and there is no RAF (the in-memory
    // MakerNote case), ExifTool sets `$bad = 1` and emits NOTHING for the tag
    // (`:6663-6668`) — it does NOT truncate to a partial tail. So reject the
    // overrunning entry (skip it) rather than reading `total_size.min(avail)`.
    // This is ExifTool's `Bad offset` path (`:6660`, `++$warnCount`); reaching
    // PAST it means the value is in-bounds and readable — the precondition for
    // the suspicious-offset gate's `$suspect == $warnCount` guard below.
    let Some(value_end) = value_data_offset.checked_add(total_size) else {
      // An offset/size that overflows `usize` is past EOF — the same Bad-offset
      // drop as below; count it too (`++$warnCount`, Exif.pm:6661).
      warn_count = warn_count.saturating_add(1);
      continue;
    };
    if value_end > blob.len() {
      // No-RAF `Bad offset for $dir $tagStr` (`Exif.pm:6660-6661`) — the
      // in-memory MakerNote has no RAF, so an out-of-line value past the buffer
      // is dropped (`$bad = 1`) and the walk CONTINUES, `++$warnCount` counting
      // it toward the abort cap (Canon's `CanonEntryClass::BadOffset`, which
      // `bumps_warn_count`).
      warn_count = warn_count.saturating_add(1);
      continue;
    }
    // Suspicious-offset gate (`Exif.pm:6537-6549` + the non-verbose skip at
    // `6673-6677`), which `ProcessExif` runs for MakerNotes (it is OUTSIDE the
    // `$validate and not $inMakerNotes` block). It applies ONLY to the
    // out-of-line (`$size > 4`) path — ExifTool's whole suspect block lives
    // inside `if ($size > 4)` (`:6504`), so an inline value is never suspect.
    // An entry is SUSPECT when EITHER:
    //   (a) the RAW stored offset is `< 8` (`:6539`) — it would point into the
    //       TIFF header. Nikon does NOT set `$$dirInfo{ZeroOffsetOK}` (that
    //       flag is Samsung-only, `Samsung.pm:1708`; Nikon.pm/MakerNotes.pm
    //       have none — verified), so the `< 8` test applies unconditionally; OR
    //   (b) the RESOLVED value range `[value_data_offset, value_data_offset +
    //       total_size)` OVERLAPS the CURRENT IFD entry table `[ifd_offset,
    //       dir_end)` (`:6549`, `$valuePtr < $dirEnd and $valuePtr+$size >
    //       $dirStart`). `dir_end = ifd_offset + 2 + 12*num_entries`
    //       (`$dirSize`, `:6347`) — the entry table only, NOT the trailing
    //       4-byte next-IFD pointer.
    // In the walker's coordinate model the buffer IS ExifTool's `$$dataPt`
    // (`$dataPos == 0`), so `value_data_offset` equals `$valuePtr` after the
    // `:6546` `-= $dataPos` (Nikon is not `EntryBased` — `Nikon.pm:14113`), and
    // `ifd_offset`/`dir_end` are the `$dirStart`/`$dirEnd` it is compared to.
    // When suspect AND the value is otherwise readable (we are past the
    // Bad-offset `continue`), ExifTool emits a minor `Suspicious <dir> offset`
    // warning and `next unless $verbose` — in non-verbose mode (this walker)
    // it SKIPS the entry, emitting NO tag (oracle `perl exiftool 13.59`: a
    // type-3 Nikon storing `Quality` as `ASCII[6]` at offset 0 emits ONLY
    // `[minor] Suspicious MakerNotes offset for Quality` and NO `Nikon:Quality`
    // — the pre-gate walk wrongly decoded the embedded `MM` header bytes as
    // Quality). The warning itself stays DROPPED (the engine-wide
    // makernote-warning-channel gap, consistent with the Bad-format / Bad-offset
    // / excessive-count paths above); only the TAG-SKIP is reproduced here, so
    // the emitted TAG set is byte-exact.
    if let Some(raw_offset) = raw_offset {
      let suspect_low = raw_offset < 8; // (a) Exif.pm:6539
      let suspect_overlap = value_data_offset < dir_end && value_end > ifd_offset; // (b) :6549
      if suspect_low || suspect_overlap {
        // `if ($et->Warn("Suspicious …")) { ++$warnCount; next unless $verbose }`
        // (`Exif.pm:6675-6677`) — counts toward the abort cap (Canon's
        // `CanonEntryClass::Suspicious`, which `bumps_warn_count`).
        warn_count = warn_count.saturating_add(1);
        continue; // `next unless $verbose` (Exif.pm:6677) — skip, keep walking.
      }
    }
    // SINGLE production-table lookup (against the layout-selected `table` —
    // `%Nikon::Type2` for the type-2 layout, `%Nikon::Main` otherwise),
    // reused for BOTH the per-tag `Format` override below AND the unknown-tag
    // skip after the excessive-count gate. `parse_in_tiff` (`mod.rs`) drops
    // any entry whose `table.lookup(tag_id)` is `None` — an UNKNOWN tag emits
    // NOTHING (ExifTool extracts no Unknown tag without the `-u` option; oracle
    // `perl exiftool 13.59`: a Nikon MakerNote whose only entry is an unknown
    // id emits no `Nikon:*` tag in default mode, only `Nikon 0x….` under `-u`).
    let tag_def = table.lookup(tag_id);
    // Determine the `$readFormat` (`Exif.pm:6730-6733`): the tag's explicit
    // `Format` directive, ELSE — for a SubDirectory tag that is NOT a `SubIFD`
    // and has NO explicit `Format` — the IMPLICIT `'undef'`:
    //   `$readFormat = 'undef' if $subdir and not $$tagInfo{SubIFD} and not
    //    $readFormat;`   (`Exif.pm:6733`)
    // "unless otherwise specified, all SubDirectory data except EXIF SubIFD
    // offsets should be unformatted". A binary-block sub-table (AFInfo 0x0088,
    // ColorBalance 0x0097, …) is read as `undef` so the WHOLE block reaches the
    // child `ProcessBinaryData` walker; a `SubIFD` pointer (PreviewIFD 0x0011,
    // NikonScanIFD 0x0e10 — `Flags => 'SubIFD'`, `Start => '$val'`) keeps its
    // INTEGER on-disk format because its value is an IFD OFFSET, not a block.
    // This MUST precede both the `Format`-override read AND the excessive-count
    // guard (`Exif.pm:6733` runs before `:6763`): `undef` is one of the
    // excessive-count exemptions (`$formatStr !~ /^(undef|string|binary)$/`,
    // `:6763`), so a binary sub-table declared with a huge numeric count is NOT
    // excessive-count-skipped — it is read as `undef` and its children still
    // emit. Oracle (`perl exiftool 13.59`, an AFInfo 0x0088 as `int32u` count
    // 100001 in-bounds): verbose `int32u[100001] read as undef[400004]` → the
    // AFInfo BinaryData directory is processed (AFAreaMode/AFPoint/… emitted),
    // whereas a non-SubDirectory `int32u` count 100001 (e.g. ContrastCurve
    // 0x008c) yields `[Minor] Ignoring MakerNotes ContrastCurve with excessive
    // count` and is dropped — the guard still fires for non-`undef` tags.
    //
    // NEUTRAL for real files: a REAL AFInfo/ColorBalance has a small count and
    // its on-disk format is already `undef`/`int8u`-ish, so forcing `undef`
    // produces the SAME `value_offset`/`value_size` block the child walker
    // reads (the block bytes are byte-identical) — the override only changes
    // the (here unused) leaf decode, never the sub-table dispatch. The
    // `value_offset`/`value_size` recorded on the `NikonEntry` come from the
    // ON-DISK `format`/`count` (computed above), independent of `read_format`,
    // so the child block is unchanged.
    let implicit_undef =
      tag_def.is_some_and(|t| t.format().is_none() && t.sub_table().is_some() && !t.is_sub_ifd());
    let table_override = match tag_def.and_then(NikonTag::format) {
      ovr @ Some(_) => ovr,
      // `$readFormat = 'undef'` (`Exif.pm:6733`): no `Count`, so the read count
      // is the recomputed `int(size/1)` per `resolve_read_format`.
      None if implicit_undef => Some(FormatOverride::new(Format::Undef, None)),
      None => None,
    };
    let (read_format, read_count) = resolve_read_format(format, count, table_override);
    // Excessive-count guard (`if ($count > 100000 and $formatStr !~
    // /^(undef|string|binary)$/) { … next }`, `Exif.pm:6763-6770`): a numeric
    // array with more than 100000 elements is SKIPPED (no decode, no
    // allocation) rather than reformatted — ExifTool's "limit maximum length
    // of data to reformat (avoids long delays … corrupted files)". Applied to
    // the POST-`Format`-override `read_format`/`read_count` (Exif.pm:6763 runs
    // after the 6729-6744 override), exactly like the shared EXIF walker. The
    // `$formatStr !~ /^(undef|string|binary)$/` exclusion is `!matches!(_,
    // Undef | Ascii)`: `string` == `Ascii`, `undef` == `Undef`, and `binary`
    // is a synthetic ExifTool format never produced on this on-disk decode
    // path (a `string`/`undef` huge count is instead shortened to the buffer
    // by `read_value`). The `TransferFunction`/196608 carve-out (Exif.pm:6764)
    // cannot apply — no Nikon tag is named `TransferFunction`. ExifTool then
    // `next`s (the value is never decoded), so a crafted Nikon MakerNote with
    // an in-bounds numeric entry of huge count emits NO tag from it while a
    // valid LATER entry still walks. Oracle (`perl exiftool 13.59`, a Nikon
    // `LensType` int32u count 100001 in-bounds): `[Minor] Ignoring MakerNotes
    // LensType with excessive count` + the bad entry dropped, the good one kept.
    if read_count > 100_000 && !matches!(read_format, Format::Undef | Format::Ascii) {
      continue; // `next` (Exif.pm:6768) — skip the entry, keep walking the IFD.
    }
    // UNKNOWN-TAG VALUE SKIP — placed AFTER every gate that affects skip/abort/
    // `warn_count` (`Bad format`, `Invalid size`, `Bad offset`, the suspicious
    // offset<8 / table-overlap gates AND their `++$warnCount`, and the
    // excessive-count `next`), so each STILL runs for an unknown entry and the
    // `warn_count > 10` abort stays byte-exact; only the VALUE DECODE is
    // skipped. An unknown tag id (`table.lookup` is `None`) is dropped by
    // `parse_in_tiff` regardless, so this changes NO emitted tag — it only
    // avoids cloning the (possibly large, in-bounds) value into a `RawValue`
    // that would then be discarded. CLOSES a memory-amplification vector: a
    // small MakerNote can hold MANY unknown `Ascii`/`Undef` entries (count
    // <= 100000 is faithfully EXEMPT from the excessive-count skip) ALL
    // pointing at one in-bounds ~100 KB value; without this skip each entry
    // would `read_value`-clone that value into `out`, driving N * value_size
    // heap growth from a sub-MB input even though those tags emit nothing.
    if tag_def.is_none() {
      continue; // Unknown tag — emits nothing (no `-u`); skip the value decode.
    }
    // For a binary-block SubDirectory (the implicit-`undef` path that feeds the
    // AFInfo / ColorBalance / LensData sub-decoders), the materialized `value`
    // is DEAD — those decoders re-read the block from `walk_data` at
    // `value_offset..value_offset + value_size`, never from this entry — so
    // store a ZERO-COPY empty `RawValue::Bytes` instead of cloning ANY of the
    // (possibly crafted-huge, in-bounds) value. The full value range is already
    // proven in-bounds (the `value_end > blob.len()` Bad-offset drop above), so
    // a `read_value` here could only ever return `Some` — skipping the read
    // changes NO walk decision. The recorded `count`/`value_size` below keep
    // ExifTool's faithful full `undef[N]` extent (the child walker reads the
    // real bytes from `walk_data`; the `undef[400004]` contract holds). This
    // CLOSES a memory-amplification vector independent of entry count: a u16's
    // worth of binary-subdir entries (e.g. a duplicated 0x0098 LensData) all
    // pointing at ONE in-bounds value now retains NOTHING, whereas a per-entry
    // clone — even a bounded window — drove `N * window` heap growth from a
    // sub-MB MakerNote. Leaf values and IFD-pointer SubDirectories (PreviewIFD
    // 0x0011, NikonScanIFD 0x0e10, `is_sub_ifd`) keep their real decoded value
    // (they are excluded from `implicit_undef`).
    let value = if implicit_undef {
      RawValue::Bytes(Vec::new())
    } else {
      // `$formatStr = 'int8u' if $format == 7 and $count == 1` (`Exif.pm:6644`,
      // "treat single unknown byte as int8u") — a single-element `undef` LEAF
      // decodes as an INTEGER (`int8u` ⇒ `RawValue::U64`), NOT a 1-byte
      // `RawValue::Bytes` blob. The shared `Walker`'s `ProcessExif` leaf path
      // (`src/exif/mod.rs`, the `decode_format` coercion) applies this on the
      // POST-`Format`-override `format`/`count`; this ORACLE must match it byte
      // for byte (the now-aligned oracle, mirroring the Apple migration's
      // `walk_apple_body` alignment — `apple_undef_count1_leaf_coerces_int8u…`),
      // so the differential `undef[1]` edge is byte-identical. The implicit-`undef`
      // SubDirectory branch above is NOT a leaf (its block is materialized for the
      // child walker, never coerced), so the carve-out is scoped to this leaf path
      // only. Real Nikon leaves are never `undef[1]`; this pins the crafted edge.
      let decode_format = if matches!(read_format, Format::Undef) && read_count == 1 {
        Format::Int8u
      } else {
        read_format
      };
      let Some(raw) = read_value(
        blob,
        value_data_offset,
        decode_format,
        read_count,
        total_size,
        order,
      ) else {
        continue;
      };
      raw
    };
    out.push(NikonEntry {
      tag_id,
      format,
      count: read_count,
      value,
      value_offset: value_data_offset,
      value_size: total_size,
    });
  }
  out
}

/// Faithful port of the Nikon `PrescanExif` decryption-key pre-scan
/// (`Nikon.pm:14067-14125`, invoked at `:14199-14203`): a SEPARATE pass over the
/// raw MakerNote IFD that captures ONLY the `SerialNumber` (0x001d) and
/// `ShutterCount` (0x00a7) DataMembers used to key the encrypted sub-tables,
/// BEFORE — and INDEPENDENT of — the main [`walk_nikon_ifd`] extraction.
///
/// ## Why a separate scan and not the walked entries
///
/// ExifTool runs `PrescanExif` with DIFFERENT, simpler entry gates than the main
/// `ProcessExif` walk: a `needTags` filter (only 0x001d / 0x00a7,
/// `Nikon.pm:14102`), a `format 1..=13` check (`:14104` — note this DROPS code
/// 129, which the main walk accepts), a 16 MB out-of-line size cap (`:14110`),
/// and an in-bounds check (`:14115`). It has NO suspicious-offset gate, NO
/// excessive-count (`> 100000`) skip, NO invalid-size (`> 0x7fffffff`) gate, and
/// NO `warnCount > 10` directory abort. So a 0x001d / 0x00a7 that the main walk
/// would DROP — at a suspicious offset, with an over-100000 count, or sitting
/// after ten earlier malformed entries tripped the abort — is STILL captured
/// here for the key, exactly as ExifTool. Sourcing the keys from the walked
/// entries (which have already passed the stricter gates) would suppress
/// decryption on those crafted layouts where ExifTool still decrypts.
///
/// Offsets resolve EXACTLY as the walk (inline at `entry + 8` for size ≤ 4, else
/// `offset + value_base`), so the captured value bytes are identical for any
/// well-formed file — the 0x001d / 0x00a7 of every real Nikon body passes both
/// scans, keeping decryption byte-identical. Returns the decoded 0x001d / 0x00a7
/// `ReadValue` results (`None` when absent, unreadable, or gated out); the caller
/// derives the serial/count keys ([`super::scan_decrypt_keys`]). Duplicate tags
/// keep the LAST occurrence (`$$tagHash{$tagID} = …` overwrites).
#[must_use]
pub fn prescan_decrypt_keys(
  blob: &[u8],
  ifd_offset: usize,
  order: ByteOrder,
  value_base: usize,
) -> (Option<RawValue>, Option<RawValue>) {
  let mut serial = None;
  let mut count = None;
  // numEntries (`Nikon.pm:14079-14082`): the 2-byte count plus the full 12-byte
  // entry table must fit the buffer; ExifTool otherwise falls back to the RAF,
  // and with no RAF (the in-memory MakerNote) captures nothing.
  let Some(num_entries) = read_u16(blob, ifd_offset, order) else {
    return (serial, count);
  };
  let num_entries = num_entries as usize;
  let Some(table_end) = ifd_offset.checked_add(2).and_then(|n| {
    12usize
      .checked_mul(num_entries)
      .and_then(|m| n.checked_add(m))
  }) else {
    return (serial, count);
  };
  if table_end > blob.len() {
    return (serial, count);
  }
  for index in 0..num_entries {
    // `$entry = $dirStart + 2 + 12 * $index` (`Nikon.pm:14094`): the entry byte
    // offset. Bounded `< table_end <= blob.len()` (framing-checked above), so this
    // never overflows on 64-bit; the explicit `checked_*` chain (deny-overflow
    // class) `break`s on the unreachable overflow, mirroring `walk_nikon_ifd`.
    let Some(entry_off) = index
      .checked_mul(12)
      .and_then(|o| o.checked_add(2))
      .and_then(|o| ifd_offset.checked_add(o))
    else {
      break;
    };
    let Some(tag_id) = read_u16(blob, entry_off, order) else {
      continue;
    };
    // `next unless exists $$tagHash{$tagID}` (`:14102`) — only the two needTags.
    let slot = match tag_id {
      0x001d => &mut serial,
      0x00a7 => &mut count,
      _ => continue,
    };
    let Some(fmt_pos) = entry_off.checked_add(2) else {
      continue;
    };
    let Some(format_code) = read_u16(blob, fmt_pos, order) else {
      continue;
    };
    // `next if $format < 1 or $format > 13` (`:14104`) — drops code 129, which
    // the main walk accepts; the prescan is format 1..=13 only.
    if !(1..=13).contains(&format_code) {
      continue;
    }
    let format = Format::from_code(format_code);
    let Some(count_pos) = entry_off.checked_add(4) else {
      continue;
    };
    let Some(count_n) = read_u32(blob, count_pos, order) else {
      continue;
    };
    let count_n = count_n as usize;
    let size = format.byte_size().saturating_mul(count_n);
    let value_off = if size <= 4 {
      // inline value (`$valuePtr = $entry + 8`)
      let Some(inline) = entry_off.checked_add(8) else {
        continue;
      };
      inline
    } else {
      if size > 0x0100_0000 {
        continue; // `next if $size > 0x1000000` — the 16 MB cap (`:14110`).
      }
      let Some(value_field) = entry_off.checked_add(8) else {
        continue;
      };
      let Some(off) = read_u32(blob, value_field, order) else {
        continue;
      };
      let Some(abs) = (off as usize).checked_add(value_base) else {
        continue;
      };
      // `next … if $valuePtr+$size > $dataLen` with no RAF (`:14115`) — the same
      // in-bounds rule the walk applies (`value_end > blob.len()`).
      match abs.checked_add(size) {
        Some(end) if end <= blob.len() => abs,
        _ => continue,
      }
    };
    // `ReadValue($dataPt, $valuePtr, $formatStr, $count, $size)` (`:14122`).
    if let Some(raw) = read_value(blob, value_off, format, count_n, size, order) {
      *slot = Some(raw);
    }
  }
  (serial, count)
}

/// Resolve the embedded-TIFF header for the type-3 layout. `blob` is the whole
/// MakerNote blob; the embedded TIFF starts at `tiff_at` (blob offset 10 for
/// the modern layout). Returns `(byte_order, ifd_offset_in_blob)`.
///
/// ## The IFD start is FIXED at `tiff_at + 8`, NOT the embedded IFD0-offset field
///
/// `MakerNotes.pm:51-57` gives the type-3 SubDirectory as `Start =>
/// '$valuePtr + 18'`, `Base => '$start - 8'`, `ByteOrder => 'Unknown'`.
/// With the embedded TIFF at blob offset 10 (`valuePtr + 10`), `$valuePtr + 18`
/// is `tiff_at + 8` — a FIXED offset. ExifTool reads the embedded `MM`/`II`
/// marker to resolve endianness (that is the entire effect of `ByteOrder =>
/// 'Unknown'`), but it does NOT consult the embedded TIFF header's 4-byte IFD0
/// offset field to locate the Main IFD: the IFD is ALWAYS walked at the fixed
/// `$valuePtr + 18`. Every real Nikon fixture happens to store `8` in that
/// field (so `tiff_at + field == tiff_at + 8`), but a crafted blob whose field
/// is some other in-bounds value must STILL be walked at `tiff_at + 8` — the
/// field is ignored. (`Base => '$start - 8'` = `tiff_at` sets the out-of-line
/// value base, which the caller passes as `value_base = 10`.)
///
/// `None` only when the marker is unreadable (no `MM`/`II`) or the fixed IFD
/// start (plus its 2-byte entry count) does not fit the blob.
#[must_use]
pub fn parse_embedded_tiff(blob: &[u8], tiff_at: usize) -> Option<(ByteOrder, usize)> {
  let header = blob.get(tiff_at..)?;
  // Bytes 0-1 are the `MM`/`II` byte-order marker — the only thing ExifTool
  // reads from the embedded header (`ByteOrder => 'Unknown'`). Bytes 2-3 are
  // the `0x002a` magic and bytes 4-7 the embedded IFD0 offset, both of which
  // ExifTool IGNORES for the type-3 layout (the IFD start is fixed below).
  let order = ByteOrder::from_marker(header)?;
  // The Main IFD always begins at the FIXED `$valuePtr + 18 == tiff_at + 8`
  // (`MakerNotes.pm:54`), regardless of the embedded IFD0-offset field.
  let ifd_offset = tiff_at.checked_add(8)?;
  // Bounds-check the fixed IFD start: its 2-byte entry count must fit the blob
  // (the walker re-checks the full entry table). A blob too short for even the
  // entry count has no Main IFD — return `None` (no panic / OOB).
  if ifd_offset.checked_add(2)? > blob.len() {
    return None;
  }
  Some((order, ifd_offset))
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // `pos + 2` via `checked_add` (deny-overflow class) — byte-identical to
  // `ifd::get_u16`'s bounds check: an out-of-range `pos` yields `None`, exactly
  // as the slice `get` does for an in-range `pos`.
  let end = pos.checked_add(2)?;
  let arr: [u8; 2] = data.get(pos..end)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // `pos + 4` via `checked_add` (deny-overflow class) — byte-identical to
  // `ifd::get_u32`'s bounds check (see [`read_u16`]).
  let end = pos.checked_add(4)?;
  let arr: [u8; 4] = data.get(pos..end)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::super::tags;
  use super::*;

  /// Build a minimal type-3 Nikon blob: `"Nikon\0\x02\x10\0\0"` + an embedded
  /// big-endian TIFF (`MM\0\x2a` + IFD0-offset 8) with one IFD entry.
  fn type3_blob_one_entry(tag: u16, format: u16, count: u32, value: [u8; 4]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    // Embedded TIFF at offset 10.
    b.extend_from_slice(b"MM"); // big-endian
    b.extend_from_slice(&[0x00, 0x2a]); // magic 0x002a
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded-offset 8
    // IFD0 is at blob offset 10 + 8 = 18 = right here (entry count).
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&tag.to_be_bytes());
    b.extend_from_slice(&format.to_be_bytes());
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(&value);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    b
  }

  /// The embedded-TIFF header parser resolves the order + IFD offset.
  #[test]
  fn parse_embedded_tiff_resolves_big_endian() {
    let blob = type3_blob_one_entry(0x0004, 0x0002, 4, *b"FINE");
    let (order, ifd_off) = parse_embedded_tiff(&blob, 10).expect("embedded TIFF");
    assert!(order.is_big());
    assert_eq!(ifd_off, 18); // 10 + 8
  }

  /// A type-3 IFD walk decodes an inline value at the correct base.
  #[test]
  fn type3_walk_decodes_inline_value() {
    // Quality = "FINE" (string, count 4, inline).
    let blob = type3_blob_one_entry(0x0004, 0x0002, 4, *b"FINE");
    let (order, ifd_off) = parse_embedded_tiff(&blob, 10).unwrap();
    let entries = walk_nikon_ifd(&blob, ifd_off, order, 10, NikonTable::Main);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0004);
    match &entries[0].value {
      RawValue::Text { text, .. } => assert_eq!(text, "FINE"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// An out-of-line value resolves against `value_base` (the embedded TIFF
  /// start, blob offset 10), NOT the IFD start — the `Base => '$start - 8'`
  /// rebase.
  #[test]
  fn type3_walk_resolves_out_of_line_against_embedded_base() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // header (10)
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded+8 = blob 18
    // IFD0 at blob 18:
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // Entry: tag 0x0084 (Lens), rational64u, count 4 (32 bytes > 4 ⇒ offset).
    b.extend_from_slice(&[0x00, 0x84]);
    b.extend_from_slice(&[0x00, 0x05]); // rational64u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    // Value offset: relative to embedded TIFF base (blob 10). The value will
    // live at blob offset 40, i.e. embedded-offset 30.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // 30 (embedded-relative)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Pad to blob offset 40.
    while b.len() < 40 {
      b.push(0);
    }
    // 4 rationals: 18/1 70/1 35/10 45/10.
    for (n, d) in [(18u32, 1u32), (70, 1), (35, 10), (45, 10)] {
      b.extend_from_slice(&n.to_be_bytes());
      b.extend_from_slice(&d.to_be_bytes());
    }
    let (order, ifd_off) = parse_embedded_tiff(&b, 10).unwrap();
    let entries = walk_nikon_ifd(&b, ifd_off, order, 10, NikonTable::Main);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0084);
    match &entries[0].value {
      RawValue::Rational(rs) => {
        assert_eq!(rs.len(), 4);
        assert_eq!(rs[0].numerator(), 18);
        assert_eq!(rs[3].denominator(), 10);
      }
      other => panic!("expected Rational, got {other:?}"),
    }
  }

  /// DIVERGENCE ORACLE: when the embedded IFD0-offset field is NOT 8 and points
  /// at a SECOND, valid-looking IFD, ExifTool (`MakerNotes.pm:54`, `Start =>
  /// '$valuePtr + 18'`) walks ONLY the IFD at the FIXED `tiff_at + 8` — the
  /// decoy IFD the field points to is never reached. This blob carries a real
  /// IFD (LensType 0x0083 = 6 → "G") at the fixed start and a decoy IFD
  /// (Quality 0x0004 = "FAKE") at the field-pointed offset; the walk must emit
  /// the real LensType and NONE of the decoy's tags.
  #[test]
  fn type3_walks_fixed_start_not_field_pointed_decoy() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // header (10)
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    // Embedded IFD0-offset field = 40 (NOT 8): if (wrongly) followed it points
    // the Main IFD at tiff_at(10) + 40 = blob 50 — the DECOY IFD below.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x28]);
    // REAL IFD at the FIXED start = blob 18: LensType (0x0083) int8u = 6 → "G".
    debug_assert_eq!(b.len(), 18);
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x83]); // tag LensType
    b.extend_from_slice(&[0x00, 0x01]); // int8u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // value 6 inline
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Pad to blob 50, then the DECOY IFD: Quality (0x0004) string[4] = "FAKE".
    while b.len() < 50 {
      b.push(0);
    }
    debug_assert_eq!(b.len(), 50); // == tiff_at(10) + field(40)
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x04]); // tag Quality
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    b.extend_from_slice(b"FAKE"); // inline value
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD

    let (order, ifd_off) = parse_embedded_tiff(&b, 10).expect("embedded TIFF");
    assert_eq!(
      ifd_off, 18,
      "IFD start is the FIXED tiff_at + 8, not field 40"
    );
    let entries = walk_nikon_ifd(&b, ifd_off, order, 10, NikonTable::Main);
    // ONLY the real fixed-start IFD is walked: LensType present, decoy absent.
    assert_eq!(entries.len(), 1, "only the fixed-start IFD is walked");
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[0].value, RawValue::U64(vec![6]));
    assert!(
      entries.iter().all(|e| e.tag_id != 0x0004),
      "the decoy IFD (field-pointed) Quality tag must NOT be walked"
    );
  }

  /// A truncated / implausible blob never panics and yields no entries.
  #[test]
  fn malformed_blob_is_bounded() {
    assert!(walk_nikon_ifd(b"", 0, ByteOrder::Big, 0, NikonTable::Main).is_empty());
    assert!(walk_nikon_ifd(b"Nikon\x00\x02", 18, ByteOrder::Big, 10, NikonTable::Main).is_empty());
    // An entry count (0xffff = 65535) whose 12-byte entry table OVERRUNS the
    // 6-byte buffer is rejected by the `dir_end > blob.len()` bound
    // (`Exif.pm:6394`) — NOT by any count ceiling (there is none). No panic.
    let blob = [0xff_u8, 0xff, 0, 0, 0, 0];
    assert!(walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main).is_empty());
    // parse_embedded_tiff on a non-marker header → None.
    assert!(parse_embedded_tiff(b"\x00\x00\x00\x00\x00\x00\x00\x00", 0).is_none());
  }

  /// A headerless Nikon IFD with MORE than 1024 valid entries whose table FITS
  /// the buffer is walked in FULL — `ProcessExif` (`Exif.pm:6343-6400`) imposes
  /// no entry-count ceiling, only `$dirEnd <= $dataLen`. Guards against
  /// re-introducing a non-ExifTool `num_entries > 1024` reject that would
  /// TRUNCATE a valid large IFD. Mirrors the Canon walker's
  /// `large_in_bounds_count_is_walked`; oracle: bundled walks a 2000-entry
  /// in-bounds IFD with no warning.
  #[test]
  fn over_1024_entries_in_bounds_all_walked() {
    let n: usize = 1500; // > 1024 — the former cap would have truncated to none
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&(n as u16).to_be_bytes());
    for _ in 0..n {
      // Each entry: KNOWN LensType (0x0083), int8u (1), count 1, inline value 6.
      // A KNOWN id is required so the walk-completeness signal survives the
      // unknown-tag value skip — every walked KNOWN entry pushes to `out`, so
      // `out.len() == n` proves the loop reached all `n` entries (no ceiling).
      // Duplicate ids are walked independently here (engine dedups later).
      b.extend_from_slice(&[0x00, 0x83]); // LensType (known)
      b.extend_from_slice(&[0x00, 0x01]); // int8u
      b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
      b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // value 6 inline
    }
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      entries.len(),
      n,
      "a >1024-entry in-bounds Nikon IFD must be fully walked (no count ceiling)"
    );
  }

  /// The embedded IFD0-offset field is IGNORED: the Main IFD is ALWAYS resolved
  /// at the FIXED `tiff_at + 8` (`$valuePtr + 18`, `MakerNotes.pm:54`), NOT at
  /// `tiff_at + field`. A non-8 in-bounds field that points at a DIFFERENT
  /// valid-looking IFD must NOT move the walk — `parse_embedded_tiff` still
  /// returns `tiff_at + 8`, so only that IFD is read and the decoy IFD the
  /// field points to is never reached. (`ByteOrder => 'Unknown'` means ONLY
  /// the `MM`/`II` marker is read from the embedded header; the offset field is
  /// not consulted.)
  #[test]
  fn type3_embedded_ifd0_offset_field_is_ignored_fixed_start() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    b.extend_from_slice(b"MM"); // big-endian embedded TIFF
    b.extend_from_slice(&[0x00, 0x2a]); // magic 0x002a
    // Embedded IFD0-offset field = 64 (NOT 8) — a value that, if (wrongly)
    // followed, would walk the Main IFD at tiff_at(10) + 64 = blob 74.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]);
    // Pad out so a 64-byte-offset target would be in bounds (proving rejection
    // is by the FIXED-start contract, not by the field running out of bounds).
    while b.len() < 100 {
      b.push(0);
    }
    let (order, ifd_off) = parse_embedded_tiff(&b, 10).expect("embedded TIFF");
    assert!(order.is_big(), "byte order read from the MM marker");
    assert_eq!(
      ifd_off, 18,
      "IFD start is the FIXED tiff_at + 8 (=18), ignoring the embedded field (64)"
    );

    // A blob too short to even hold the 2-byte entry count at the fixed start
    // is rejected (`None`) — no panic, no OOB.
    let short = b"Nikon\x00\x02\x10\x00\x00MM\x00\x2a\x00\x00\x00\x40"; // 18 bytes, IFD start = 18 == len
    assert!(
      parse_embedded_tiff(short, 10).is_none(),
      "a blob too short for the entry count at the fixed IFD start yields None"
    );
  }

  /// The directory entry table is bounded to the BUFFER length (ExifTool's
  /// `$dirEnd > $dataLen` bound, `Exif.pm:6394`), not to a shorter declared
  /// MakerNote length: an entry table that fits the buffer is walked in full
  /// (matching ExifTool — for an in-place MakerNote `DataLen` is the parent
  /// EXIF buffer, larger than the declared `DirLen`); an entry count that runs
  /// PAST the buffer is rejected wholesale (no panic, no partial read).
  #[test]
  fn directory_table_bounded_to_buffer() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&[0x00, 0x02]); // 2 entries
    // Entry 0: LensType 0x0083 int8u = 6 → "G".
    b.extend_from_slice(&[0x00, 0x83]);
    b.extend_from_slice(&[0x00, 0x01]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    // Entry 1: Quality 0x0004 string[4] "FINE".
    b.extend_from_slice(&[0x00, 0x04]);
    b.extend_from_slice(&[0x00, 0x02]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
    b.extend_from_slice(b"FINE");
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Both entries fit the buffer ⇒ both decode (ExifTool reads up to DataLen).
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[1].tag_id, 0x0004);

    // An entry count that runs PAST the buffer end is rejected wholesale.
    let mut over: Vec<u8> = Vec::new();
    over.extend_from_slice(&[0x00, 0x05]); // claims 5 entries (60 bytes) …
    over.extend_from_slice(&[0x00, 0x83, 0x00, 0x01, 0, 0, 0, 1, 6, 0, 0, 0]); // … but only 1 present
    assert!(walk_nikon_ifd(&over, 0, ByteOrder::Big, 0, NikonTable::Main).is_empty());
  }

  /// An out-of-line value whose START is in-bounds but whose FULL length runs
  /// past EOF is REJECTED (skipped), not truncated to a partial tail — matching
  /// ExifTool's `$valuePtr + $size > $dataLen` drop (`$bad = 1`, no emission,
  /// `Exif.pm:6663`; verified: ExifTool emits only a `[minor] Bad offset`
  /// warning and NO Lens tag), not a `total_size.min(avail)` partial read.
  #[test]
  fn out_of_line_value_past_eof_is_rejected_not_truncated() {
    let mut b: Vec<u8> = Vec::new();
    // Headerless IFD, 1 entry: Lens (0x0084) rational64u[4] = 32 bytes, stored
    // out-of-line at offset 18, but the buffer is truncated mid-value.
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x84]); // tag 0x0084
    b.extend_from_slice(&[0x00, 0x05]); // rational64u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4 (32 bytes > 4)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x12]); // value offset 18
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Value region begins at offset 18 but we only supply 8 of the 32 bytes.
    while b.len() < 18 {
      b.push(0);
    }
    b.extend_from_slice(&[0, 0, 0, 18, 0, 0, 0, 1]); // 8 bytes (one rational)
    // 18 (start) + 32 (full size) > buffer ⇒ the entry is dropped, not read as
    // a partial 1-rational tail.
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      entries.is_empty(),
      "a value running past EOF must be rejected, not truncated to a tail"
    );
  }

  /// SUSPICIOUS OFFSET, case (a) — RAW stored offset `< 8` (`Exif.pm:6539`,
  /// Nikon has no `ZeroOffsetOK`): a type-3 Nikon whose `Quality` (0x0004) is
  /// stored OUT-OF-LINE as `ASCII[6]` at offset 0 (which would resolve to the
  /// embedded-TIFF base, blob offset 10, and decode the `MM\0\x2a\0\0` header
  /// bytes) is SKIPPED — no `Nikon:Quality` entry, no header bytes decoded.
  ///
  /// Ground-truthed against `perl exiftool 13.59` on the equivalent crafted
  /// JPEG (`IFD0` Make=`NIKON CORPORATION` + a type-3 MakerNote whose only
  /// entry is this offset-0 `Quality`): the oracle emits ONLY `[minor]
  /// Suspicious MakerNotes offset for Quality` and NO `Nikon:Quality` — whereas
  /// the pre-gate walk wrongly surfaced `Nikon:Quality = "MM"` (the byte-order
  /// marker). The minor warning itself stays dropped (the engine-wide
  /// makernote-warning-channel gap); only the tag-skip is reproduced here.
  #[test]
  fn type3_out_of_line_offset_below_8_skipped() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    b.extend_from_slice(b"MM"); // big-endian embedded TIFF
    b.extend_from_slice(&[0x00, 0x2a]); // magic
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded+8 = blob 18
    // IFD at blob 18: Quality (0x0004) ASCII count 6 ⇒ 6 bytes > 4 ⇒ out-of-line.
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x04]); // tag Quality
    b.extend_from_slice(&[0x00, 0x02]); // ASCII
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stored offset 0 (< 8!)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // The resolved target (value_base 10 + 0 = blob 10) IS in bounds — so this
    // is the IN-BOUNDS-but-suspicious case, NOT the Bad-offset case.
    let (order, ifd_off) = parse_embedded_tiff(&b, 10).expect("embedded TIFF");
    let entries = walk_nikon_ifd(&b, ifd_off, order, 10, NikonTable::Main);
    assert!(
      entries.iter().all(|e| e.tag_id != 0x0004),
      "an out-of-line value at stored offset 0 (< 8) is suspicious ⇒ skipped"
    );
    assert!(
      entries.is_empty(),
      "the offset-0 Quality is the only entry; nothing is decoded"
    );
  }

  /// SUSPICIOUS OFFSET, case (b) — the resolved value range OVERLAPS the
  /// current IFD entry table `[ifd_offset, dir_end)` (`Exif.pm:6549`,
  /// `$valuePtr < $dirEnd and $valuePtr+$size > $dirStart`). A headerless IFD
  /// (value_base 0, ifd_offset 0, `dir_end = 2 + 12*num_entries`) with an
  /// out-of-line value at a stored offset `>= 8` (so case (a) does NOT fire)
  /// whose range lands INSIDE the entry table is SKIPPED — no tag.
  #[test]
  fn nikon_value_overlapping_ifd_table_skipped() {
    // 2 entries ⇒ dir_end = 2 + 24 = 26. Entry 0 is out-of-line at offset 14
    // (>= 8, so NOT case (a)) of size 8 ⇒ range [14, 22) ⊂ [0, 26) ⇒ overlaps
    // the entry table (case (b)). The buffer is laid long enough that the value
    // region is in-bounds (so this is suspicious, not Bad-offset).
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&[0x00, 0x02]); // 2 entries ⇒ dir_end = 26
    // Entry 0: Lens (0x0084) rational64u count 1 = 8 bytes (> 4 ⇒ out-of-line).
    b.extend_from_slice(&[0x00, 0x84]);
    b.extend_from_slice(&[0x00, 0x05]); // rational64u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1 (8 bytes)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x0e]); // stored offset 14 (>= 8)
    // Entry 1: LensType (0x0083) int8u count 1 = 6 → "G" (inline, valid, NOT
    // out-of-line ⇒ never suspicious — proves only the overlapping entry drops).
    b.extend_from_slice(&[0x00, 0x83]);
    b.extend_from_slice(&[0x00, 0x01]); // int8u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // value 6 inline
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD (blob 26..30)
    // Pad past offset 22 so [14,22) is fully in-bounds (in-bounds-but-suspect).
    while b.len() < 32 {
      b.push(0);
    }
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      entries.iter().all(|e| e.tag_id != 0x0084),
      "an out-of-line value overlapping the IFD entry table is suspicious ⇒ skipped"
    );
    // The inline LensType (never out-of-line, never suspect) still emits.
    assert_eq!(
      entries.len(),
      1,
      "only the suspicious out-of-line entry drops"
    );
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[0].value, RawValue::U64(vec![6]));
  }

  /// REGRESSION GUARD against OVER-SKIP — a LEGITIMATE out-of-line value at a
  /// stored offset `>= 8` that does NOT overlap the IFD entry table is STILL
  /// emitted (neither suspicious case fires). This mirrors every real Nikon
  /// out-of-line tag (LensData/ColorBalance/ShotInfo/Lens at offsets `>> 8`
  /// well past the entry table), which the gate must NOT touch.
  #[test]
  fn nikon_legitimate_out_of_line_value_still_emitted() {
    // Headerless IFD, 1 entry ⇒ dir_end = 2 + 12 = 14; next-IFD at [14,18).
    // Lens (0x0084) rational64u[4] = 32 bytes out-of-line at offset 18 — `>= 8`
    // (not case (a)) and range [18, 50) ∩ [0, 14) = ∅ (not case (b)).
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry ⇒ dir_end = 14
    b.extend_from_slice(&[0x00, 0x84]); // tag Lens
    b.extend_from_slice(&[0x00, 0x05]); // rational64u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4 (32 bytes)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x12]); // stored offset 18 (>= 8, past table)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD (blob 14..18)
    // 4 rationals at offset 18: 18/1 70/1 35/10 45/10 (the D70 18-70mm lens).
    debug_assert_eq!(b.len(), 18);
    for (n, d) in [(18u32, 1u32), (70, 1), (35, 10), (45, 10)] {
      b.extend_from_slice(&n.to_be_bytes());
      b.extend_from_slice(&d.to_be_bytes());
    }
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      entries.len(),
      1,
      "a legitimate out-of-line value (offset >= 8, no table overlap) still emits"
    );
    assert_eq!(entries[0].tag_id, 0x0084);
    match &entries[0].value {
      RawValue::Rational(rs) => {
        assert_eq!(rs.len(), 4);
        assert_eq!(rs[0].numerator(), 18);
        assert_eq!(rs[3].denominator(), 10);
      }
      other => panic!("expected Rational, got {other:?}"),
    }
  }

  /// The `signed_fraction_c3` ValueConv: `a*(b/c)` over the first 3 SIGNED
  /// bytes; `c == 0` → 0.
  #[test]
  fn signed_fraction_c3_value_conv() {
    // (-3, 1, 6) → -3*(1/6) = -0.5.
    let v = ParsedValue::new(RawValue::Bytes(vec![0xfd, 0x01, 0x06, 0x00]));
    assert!((v.signed_fraction_c3().unwrap() - (-0.5)).abs() < 1e-9);
    // c == 0 → 0.
    let v0 = ParsedValue::new(RawValue::Bytes(vec![0x05, 0x01, 0x00, 0x00]));
    assert_eq!(v0.signed_fraction_c3(), Some(0.0));
  }

  /// The excessive-count + invalid-size guards (`Exif.pm:6505-6509` /
  /// `6763-6770`) skip a hostile numeric entry BEFORE `read_value` — no large
  /// `Vec` is allocated, no `NikonEntry` is produced for the bad entry — while
  /// a valid LATER entry in the SAME IFD is still walked (a per-entry `next`,
  /// not a directory abort).
  ///
  /// Ground-truthed against `perl exiftool 13.59` on the equivalent crafted
  /// TIFF (a headerless Nikon MakerNote whose first `LensType` (0x0083) is an
  /// in-bounds `int32u` of count 100001, followed by a valid `int8u` LensType
  /// = 6): the oracle emits `[Minor] Ignoring MakerNotes LensType with
  /// excessive count` and drops the bad entry, surfacing only the good
  /// `Nikon:LensType = "G"`. The directory is NOT dropped.
  #[test]
  fn nikon_excessive_count_numeric_entry_skipped() {
    // -- Excessive count (count > 100000, in-bounds): the value region is
    //    fully present so ExifTool's EOF check (Exif.pm:6552) passes and the
    //    excessive-count guard (Exif.pm:6763), not `Error reading value`, is
    //    the deciding test — exactly as the oracle shows.
    let count: u32 = 100_001; // *4 = 400004 bytes (> 100000, < 0x7fffffff)
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&[0x00, 0x02]); // 2 entries
    // Entry 0: LensType (0x0083) int32u, huge count, OUT-OF-LINE at offset 30.
    let dir_end: u32 = 2 + 12 * 2 + 4; // 30 — value region starts right after.
    b.extend_from_slice(&[0x00, 0x83]);
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(&dir_end.to_be_bytes()); // value offset 30
    // Entry 1: LensType (0x0083) int8u count 1 = 6 → "G" (inline, valid).
    b.extend_from_slice(&[0x00, 0x83]);
    b.extend_from_slice(&[0x00, 0x01]); // int8u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // value 6 (inline)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(b.len() as u32, dir_end);
    // Lay the FULL 400004-byte value region in-bounds (so the EOF check passes;
    // the entry is dropped by the excessive-count guard, never decoded).
    b.resize(dir_end as usize + (count as usize) * 4, 0);
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    // The huge entry is skipped (no 100001-element Vec); only the valid small
    // entry survives — and it is the int8u LensType = 6.
    assert_eq!(
      entries.len(),
      1,
      "the excessive-count entry must be skipped, the valid entry kept"
    );
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[0].count, 1);
    assert_eq!(entries[0].value, RawValue::U64(vec![6]));

    // -- Invalid size (count * formatSize > 0x7fffffff): rejected BEFORE the
    //    offset is even read (Exif.pm:6505). A valid LATER entry still walks.
    let huge: u32 = 0x4000_0000; // *4 = 0x1_0000_0000 > 0x7fffffff
    let mut z: Vec<u8> = Vec::new();
    z.extend_from_slice(&[0x00, 0x02]); // 2 entries
    // Entry 0: Lens (0x0084) int32u, count 0x40000000 ⇒ size > 0x7fffffff.
    z.extend_from_slice(&[0x00, 0x84]);
    z.extend_from_slice(&[0x00, 0x04]); // int32u
    z.extend_from_slice(&huge.to_be_bytes());
    z.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // offset bytes (never read)
    // Entry 1: LensType (0x0083) int8u count 1 = 6 → "G" (inline, valid).
    z.extend_from_slice(&[0x00, 0x83]);
    z.extend_from_slice(&[0x00, 0x01]);
    z.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    z.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    z.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    let entries = walk_nikon_ifd(&z, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      entries.len(),
      1,
      "the invalid-size entry must be skipped, the valid entry kept"
    );
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[0].value, RawValue::U64(vec![6]));
  }

  /// IMPLICIT-`undef` SubDirectory override (`Exif.pm:6733`): a BINARY-block
  /// sub-table (AFInfo 0x0088) declared with a huge numeric on-disk format
  /// (`int32u` count > 100000) is read as `undef` and so is EXEMPT from the
  /// excessive-count guard (`:6763` `$formatStr !~ /^(undef|string|binary)$/`)
  /// — its `NikonEntry` IS produced (whole block preserved for the child
  /// walker), unlike a non-SubDirectory numeric entry of the same count, which
  /// IS excessive-count-skipped (the contrast already proven by
  /// `nikon_excessive_count_numeric_entry_skipped`; re-asserted here so the two
  /// sit side by side). Ground-truthed against `perl exiftool 13.59`: an AFInfo
  /// 0x0088 as `int32u[100001]` in-bounds → verbose `int32u[100001] read as
  /// undef[400004]` and the AFInfo BinaryData children are emitted, whereas a
  /// non-SubDirectory `int32u[100001]` (ContrastCurve 0x008c) yields `[Minor]
  /// Ignoring MakerNotes ContrastCurve with excessive count` and is dropped.
  #[test]
  fn nikon_subdir_high_count_read_as_undef_not_skipped() {
    let count: u32 = 100_001; // *4 = 400004 bytes (> 100000, < 0x7fffffff)
    // AFInfo (0x0088, a BINARY sub-table, NOT a SubIFD, no explicit Format) as
    // int32u with the huge count, OUT-OF-LINE; a valid LensType sentinel after.
    let af = entry_offset(0x0088, 4, count, 2 + 12 * 2 + 4);
    let lens = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]); // int8u = 6
    let mut b = headerless_ifd(&[af, lens]);
    // Lay the full 400004-byte value region in-bounds (EOF check at :6552 passes;
    // the deciding test is then the undef carve-out at :6763).
    b.resize(b.len() + (count as usize) * 4, 0);
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    // BOTH survive: AFInfo is read as `undef` (NOT skipped) + the LensType.
    assert_eq!(
      entries.len(),
      2,
      "an undef-overridden SubDirectory is EXEMPT from the excessive-count skip"
    );
    let af_entry = entries
      .iter()
      .find(|e| e.tag_id == 0x0088)
      .expect("AFInfo entry must be produced (read as undef, not skipped)");
    // Read as `undef`: the recorded `count` keeps the on-disk byte size (400004),
    // exactly ExifTool's `undef[400004]`, while the materialized `value` is a
    // ZERO-COPY empty block (the clone is dead for AFInfo/ColorBalance/LensData,
    // which re-read from `value_offset`/`value_size` in `walk_data`).
    assert_eq!(af_entry.count, count as usize * 4);
    match &af_entry.value {
      RawValue::Bytes(b) => assert_eq!(
        b.len(),
        0,
        "the binary-SubDirectory value is zero-copy empty, not the full 400004 bytes"
      ),
      other => panic!("an undef-read SubDirectory value is the raw byte block, got {other:?}"),
    }
    assert!(entries.iter().any(|e| e.tag_id == 0x0083));

    // CONTRAST: the SAME huge count on a NON-SubDirectory numeric tag
    // (ContrastCurve 0x008c — a leaf, no sub-table) IS excessive-count-skipped;
    // only the LensType sentinel survives. (The guard still fires for non-undef.)
    let cc = entry_offset(0x008c, 4, count, 2 + 12 * 2 + 4);
    let lens2 = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
    let mut z = headerless_ifd(&[cc, lens2]);
    z.resize(z.len() + (count as usize) * 4, 0);
    let zentries = walk_nikon_ifd(&z, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      zentries.len(),
      1,
      "a non-SubDirectory numeric entry of huge count is still excessive-count-skipped"
    );
    assert_eq!(zentries[0].tag_id, 0x0083);
  }

  /// A crafted LARGE in-bounds `0x0098` LensData value (declared
  /// `undef[200000]`) must NOT clone ANY of the declared block into the entry's
  /// `RawValue::Bytes`: the binary-SubDirectory value is ZERO-COPY empty (the
  /// sub-decoders re-read from `value_offset`/`value_size` in `walk_data`, so the
  /// clone is dead). The recorded `count` / `value_size` keep ExifTool's faithful
  /// full extent (it reads the in-bounds value too — the empty materialized value
  /// is OUTPUT-EQUIVALENT). A later valid `LensType` sentinel still decodes (the
  /// walk is not disturbed).
  #[test]
  fn nikon_subdir_large_value_zero_copy() {
    let big: u32 = 200_000; // declared `undef` byte count, < 0x7fffffff
    // 0x0098 LensData (binary SubDirectory, no explicit Format ⇒ implicit-undef),
    // OUT-OF-LINE; a valid inline LensType sentinel after it.
    let lens_data = entry_offset(0x0098, 7, big, 2 + 12 * 2 + 4); // undef, out-of-line
    let lens_type = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]); // int8u = 6
    let mut b = headerless_ifd(&[lens_data, lens_type]);
    // Lay the full 200000-byte value region in-bounds so ExifTool reads it.
    b.resize(b.len() + big as usize, 0);
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    let ld = entries
      .iter()
      .find(|e| e.tag_id == 0x0098)
      .expect("LensData entry must be produced (read as undef)");
    // The recorded extent is faithful (the full declared `undef[200000]`)…
    assert_eq!(ld.count, big as usize);
    assert_eq!(ld.value_size, big as usize);
    // …but the materialized value is ZERO-COPY empty, NOT 200000 bytes.
    match &ld.value {
      RawValue::Bytes(v) => assert_eq!(
        v.len(),
        0,
        "0x0098 LensData value must be zero-copy empty (got {} bytes)",
        v.len()
      ),
      other => panic!("LensData value is the raw byte block, got {other:?}"),
    }
    // The sentinel after the huge entry still decodes.
    let lt = entries
      .iter()
      .find(|e| e.tag_id == 0x0083)
      .expect("the LensType sentinel after the huge LensData still walks");
    assert_eq!(lt.value, RawValue::U64(vec![6]));
  }

  /// REPEAT-ENTRY AMPLIFICATION regression (the R8 finding): a crafted IFD can
  /// repeat a binary-SubDirectory tag (here `0x0098` LensData) MANY times, every
  /// entry pointing at the SAME in-bounds value. Because each implicit-`undef`
  /// entry stores a ZERO-COPY empty `RawValue::Bytes`, retained heap is bounded
  /// INDEPENDENT of entry count — a per-entry clone (even a bounded window) would
  /// instead drive `N * window` growth (a u16's worth of entries ⇒ hundreds of MB
  /// from a sub-MB MakerNote). Every repeated entry is still produced with the
  /// faithful full `value_size`, and all share one value region.
  #[test]
  fn nikon_repeated_subdir_value_is_bounded() {
    let big: u32 = 100_000; // shared in-bounds `undef` value, < 0x7fffffff
    const N: usize = 64; // many repeats of the SAME 0x0098 LensData subdir
    // All N entries point OUT-OF-LINE at the same value region just past the IFD.
    let value_at: u32 = 2 + 12 * N as u32 + 4;
    let dirs: Vec<_> = (0..N)
      .map(|_| entry_offset(0x0098, 7, big, value_at)) // undef, out-of-line, shared
      .collect();
    let mut b = headerless_ifd(&dirs);
    b.resize(b.len() + big as usize, 0); // lay the shared value in-bounds
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    // Every repeated subdir entry is produced with the faithful full extent…
    let lens = entries.iter().filter(|e| e.tag_id == 0x0098).count();
    assert_eq!(lens, N, "every repeated LensData subdir entry is walked");
    // …yet NONE retains the value bytes — total retained value heap is 0 across
    // all N, so retained memory is independent of entry count.
    let total_value_bytes: usize = entries
      .iter()
      .map(|e| match &e.value {
        RawValue::Bytes(v) => v.len(),
        _ => 0,
      })
      .sum();
    assert_eq!(
      total_value_bytes, 0,
      "repeated binary-subdir entries retain zero value bytes (got {total_value_bytes})"
    );
    for e in entries.iter().filter(|e| e.tag_id == 0x0098) {
      assert_eq!(
        e.value_size, big as usize,
        "each keeps the faithful full extent"
      );
    }
  }

  /// `single_digit_count` keys the count's LOW 32 BITS via the shared
  /// 64-bit-saturating coercion (the cipher's four-byte XOR fold), so an all-digit
  /// `ShutterCount` EXCEEDING `u32` — which ExifTool still accepts via `/^\d+$/`
  /// and decrypts — is keyed, NOT rejected for not fitting `u32`. Exact across the
  /// whole `u64` range; a `> u64` decimal saturates (Perl's NV→UV is platform
  /// UB — no portable oracle). (R9/R10 finding: the prior `parse::<u32>()`
  /// suppressed decryption, then an arbitrary-precision fold diverged from Perl's
  /// 64-bit model above `u64`.)
  #[test]
  fn single_digit_count_keys_low_32_bits() {
    let c = |s: &[u8]| ParsedValue::new(RawValue::Bytes(s.to_vec())).single_digit_count();
    assert_eq!(c(b"100"), Some(100)); // in range
    assert_eq!(c(b"4294967296"), Some(0)); // 2^32 ⇒ low 32 bits 0 (was rejected)
    assert_eq!(c(b"4294967297"), Some(1)); // 2^32 + 1 ⇒ low 32 bits 1
    // u64 boundary: u64::MAX = 0xffff_ffff_ffff_ffff ⇒ low 32 bits 0xffff_ffff;
    // u64::MAX + 1 / + 2 SATURATE to u64::MAX ⇒ same low 32 bits (Perl 64-bit
    // model; the cipher's XOR fold of 0xffff_ffff is key 0, matching 64-bit Perl).
    assert_eq!(c(b"18446744073709551615"), Some(0xffff_ffff)); // u64::MAX
    assert_eq!(c(b"18446744073709551616"), Some(0xffff_ffff)); // u64::MAX + 1
    assert_eq!(c(b"18446744073709551617"), Some(0xffff_ffff)); // u64::MAX + 2
    assert_eq!(c(b"100 0"), None); // space-joined multi-element render fails
    assert_eq!(c(b"-5"), None); // a sign fails
    assert_eq!(c(b""), None); // empty fails
  }

  /// `prescan_decrypt_keys` (ExifTool's `PrescanExif`) captures the decryption
  /// key with LOOSER gates than the main walk: it has NO `warnCount > 10` abort,
  /// so a trailing `ShutterCount` (0x00a7) the walk never reaches — because 11
  /// earlier bad-offset entries tripped the abort — is STILL keyed, exactly as
  /// ExifTool. (R9 finding: sourcing keys from the post-walk entries suppressed
  /// decryption on such crafted layouts.)
  #[test]
  fn prescan_captures_key_past_walk_warn_abort() {
    // 11 out-of-line entries whose value runs past EOF (each `++warnCount`).
    let mut entries: Vec<Vec<u8>> = (0..11u16)
      .map(|i| entry_offset(0x9000 + i, 2, 8, 0xffff)) // ascii[8] past EOF
      .collect();
    // A trailing ShutterCount (int32u 100, inline) after the 11 bad entries.
    entries.push(entry_inline(0x00a7, 4, 1, [0x00, 0x00, 0x00, 0x64])); // big-endian 100
    let b = headerless_ifd(&entries);
    // The main walk ABORTS (warnCount > 10) before 0x00a7 — it is never produced.
    let walked = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      walked.iter().all(|e| e.tag_id != 0x00a7),
      "the walk aborts before reaching the trailing 0x00a7"
    );
    // The prescan has no abort, so it still captures the ShutterCount key (100).
    let (_serial, count) = prescan_decrypt_keys(&b, 0, ByteOrder::Big, 0);
    let count = count.expect("PrescanExif captures the count key past the walk abort");
    assert_eq!(ParsedValue::new(count).single_digit_count(), Some(100));
  }

  /// `prescan_decrypt_keys` captures ONLY the two needTags (0x001d / 0x00a7) and
  /// reads them format-agnostically, matching `PrescanExif`'s `needTags` filter +
  /// `ReadValue`. An unrelated tag is ignored; a present SerialNumber + a present
  /// ShutterCount are both returned.
  #[test]
  fn prescan_captures_only_needtags() {
    let serial = entry_inline(0x001d, 2, 4, [b'9', b'9', b'9', 0]); // ascii "999"
    let other = entry_inline(0x0005, 4, 1, [0x00, 0x00, 0x00, 0x07]); // ignored
    let shutter = entry_inline(0x00a7, 4, 1, [0x00, 0x00, 0x00, 0x2a]); // int32u 42
    let b = headerless_ifd(&[serial, other, shutter]);
    let (serial_val, count_val) = prescan_decrypt_keys(&b, 0, ByteOrder::Big, 0);
    let s = serial_val.expect("0x001d captured");
    assert_eq!(std::string::String::from_utf8_lossy(&s.val_bytes()), "999");
    let count = count_val.expect("0x00a7 captured");
    assert_eq!(ParsedValue::new(count).single_digit_count(), Some(42));
  }

  /// A `SubIFD` pointer (PreviewIFD 0x0011, NikonScanIFD 0x0e10 —
  /// `Flags => 'SubIFD'`, `Start => '$val'`) is EXCLUDED from the
  /// implicit-`undef` override (`Exif.pm:6733` `not $$tagInfo{SubIFD}`): its
  /// value is an IFD OFFSET read with an INTEGER format. A PreviewIFD whose
  /// declared on-disk format were a huge numeric count WOULD therefore stay
  /// non-`undef` and be excessive-count-skipped — but a REAL PreviewIFD is a
  /// 4-byte `int32u[1]` offset (oracle `int32u[1]`), so its value reads as the
  /// integer offset, NOT a raw block. Here the int32u[1] offset value is
  /// decoded as a `U64`, proving the undef override did not fire for it.
  #[test]
  fn nikon_sub_ifd_pointer_excluded_from_undef_override() {
    // Both Main SubIFD tags carry the flag; no other sub-table does.
    assert!(tags::lookup(0x0011).unwrap().is_sub_ifd());
    assert!(tags::lookup(0x0e10).unwrap().is_sub_ifd());
    assert!(!tags::lookup(0x0088).unwrap().is_sub_ifd()); // AFInfo — binary block
    assert!(!tags::lookup(0x0097).unwrap().is_sub_ifd()); // ColorBalance — binary
    // PreviewIFD as a real int32u[1] offset (value 0x40) — read as the integer,
    // NOT forced to undef (which would yield a `Bytes` block instead).
    let preview = entry_inline(0x0011, 4, 1, [0x00, 0x00, 0x00, 0x40]);
    let b = headerless_ifd(&[preview]);
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0011);
    assert_eq!(
      entries[0].value,
      RawValue::U64(vec![0x40]),
      "a SubIFD offset is read with its integer format, NOT the undef override"
    );
  }

  /// UNKNOWN-TAG VALUE SKIP closes a MEMORY-AMPLIFICATION vector: a SMALL
  /// MakerNote with MANY unknown `Ascii`/`Undef` entries (count <= 100000 is
  /// faithfully EXEMPT from the excessive-count skip) ALL pointing at ONE
  /// in-bounds large value would, without the skip, `read_value`-clone that
  /// value into a `NikonEntry` for EACH entry — `N * value_size` heap from a
  /// sub-MB input — even though `parse_in_tiff` drops every one (unknown id ⇒
  /// emits nothing, no `-u`). With the skip the unknown entries decode no
  /// value, so the walk completes with ZERO entries. Here N = 300 unknown
  /// `ASCII[64KB]` entries share one 64 KB value: a pre-fix walk would
  /// allocate 300 * 64 KB ≈ 19 MB of `RawValue`s from a ~64 KB input; the fix
  /// allocates none.
  #[test]
  fn nikon_unknown_tags_not_allocated() {
    const N: u16 = 300; // many unknown entries …
    const VAL: usize = 64 * 1024; // … all pointing at ONE 64 KB value
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&N.to_be_bytes()); // headerless IFD, N entries
    // dir_end = 2 + 12*N; next-IFD at [dir_end, dir_end+4); the shared 64 KB
    // value lives just past the next-IFD pointer, fully in-bounds.
    let dir_end = 2 + 12 * (N as usize);
    let value_off = dir_end + 4;
    for i in 0..N {
      // tag id in the 0x00f0.. range (NONE are in `Nikon::Main` ⇒ all unknown),
      // ASCII count 64 KB > 4 ⇒ out-of-line at `value_off` (>= 8, well past the
      // entry table ⇒ NOT suspicious), pointing at the SAME shared value.
      let tag = 0x00f0u16.wrapping_add(i);
      b.extend_from_slice(&tag.to_be_bytes());
      b.extend_from_slice(&[0x00, 0x02]); // ASCII (string) — EXEMPT from the count skip
      b.extend_from_slice(&(VAL as u32).to_be_bytes()); // count 64 KB
      b.extend_from_slice(&(value_off as u32).to_be_bytes()); // shared offset
    }
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    debug_assert_eq!(b.len(), value_off);
    b.resize(value_off + VAL, 0x41); // one shared in-bounds 64 KB value
    let entries = walk_nikon_ifd(&b, 0, ByteOrder::Big, 0, NikonTable::Main);
    // Every entry is an UNKNOWN tag id ⇒ value decode skipped ⇒ no `NikonEntry`
    // (pre-fix this Vec held N clones of the 64 KB value). The emitted tag set
    // is UNCHANGED: `parse_in_tiff` would have dropped all N unknown ids anyway.
    assert!(
      entries.is_empty(),
      "unknown tags allocate no value (memory-amplification vector closed)"
    );
  }

  /// The unknown-tag VALUE skip is placed AFTER the `warn_count`-bumping gates,
  /// so UNKNOWN entries still bump `warn_count` and the `> 10` abort
  /// (`Exif.pm:6455`) fires exactly as for known entries. Here 11 UNKNOWN
  /// out-of-line entries each at stored offset 0 (`< 8` ⇒ suspicious,
  /// `++$warnCount`) precede a VALID KNOWN inline `LensType` — the abort fires
  /// at the top of the 12th iteration (before the lookup-skip even runs for the
  /// suspicious entries, which are skipped earlier), so the late LensType is
  /// ABSENT. Proves the gates precede the unknown-skip (the R8 ordering).
  #[test]
  fn nikon_unknown_entries_still_bump_warncount() {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    // 11 UNKNOWN (0x00f0..) out-of-line entries at offset 0 (< 8 ⇒ suspicious,
    // counted). rational64u count 1 = 8 bytes > 4 ⇒ out-of-line.
    for i in 0..11u16 {
      entries.push(entry_offset(0x00f0 + i, 5, 1, 0));
    }
    // 12th: a VALID KNOWN inline LensType (would emit "G" if reached).
    entries.push(entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]));
    let blob = headerless_ifd(&entries);
    let out = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      out.iter().all(|e| e.tag_id != 0x0083),
      "unknown entries still bump warn_count ⇒ the >10 abort drops the late KNOWN LensType"
    );
    assert!(
      out.is_empty(),
      "the 11 suspicious unknown entries are skipped before the abort ⇒ nothing emitted"
    );
  }

  /// A 12-byte IFD entry with an inline 4-byte value (helper for the
  /// bad-format tests).
  fn entry_inline(tag: u16, format: u16, count: u32, value: [u8; 4]) -> Vec<u8> {
    let mut e: Vec<u8> = Vec::new();
    e.extend_from_slice(&tag.to_be_bytes());
    e.extend_from_slice(&format.to_be_bytes());
    e.extend_from_slice(&count.to_be_bytes());
    e.extend_from_slice(&value);
    e
  }

  /// A headerless big-endian Nikon IFD: `numEntries` + the 12-byte entries +
  /// a `0` next-IFD pointer.
  fn headerless_ifd(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
      b.extend_from_slice(e);
    }
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    b
  }

  /// `ProcessExif` ABORTS the directory when ENTRY 0 carries a bad format code
  /// (`Exif.pm:6475` `return 0` — "assume corrupted IFD if this is our first
  /// entry"): a Nikon MakerNote whose entry 0 has format 99 (invalid) followed
  /// by a VALID `LensType` emits NOTHING from the directory — the later
  /// `LensType` is dropped with the bad entry.
  ///
  /// Ground-truthed against `perl exiftool 13.59` on the equivalent crafted
  /// TIFF (a `NIKON CORPORATION` IFD0 + a headerless Nikon MakerNote whose
  /// entry 0 is `format 99` and entry 1 is `int8u LensType = 6`): the oracle
  /// emits ONLY `[minor] Bad format (99) for MakerNotes entry 0` and NO
  /// `Nikon:*` tag — the directory is aborted, not merely the one entry.
  #[test]
  fn nikon_entry0_bad_format_aborts_directory() {
    let bad0 = entry_inline(0x0083, 99, 1, [0x00, 0x00, 0x00, 0x00]); // invalid fmt
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]); // int8u = 6 → "G"
    let blob = headerless_ifd(&[bad0, lenstype]);
    let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      entries.is_empty(),
      "an entry-0 bad format aborts the WHOLE directory (the later LensType is dropped)"
    );
  }

  /// `ProcessExif` SKIPS (does NOT abort on) a bad format code at a LATER entry
  /// (`Exif.pm:6476` `next if $index`): a Nikon MakerNote with a valid entry 0,
  /// an invalid entry 1 (format 99), and a valid entry 2 emits entries 0 and 2
  /// (the bad entry 1 is dropped, the directory is NOT aborted).
  ///
  /// Ground-truthed against `perl exiftool 13.59`: the equivalent crafted TIFF
  /// (entry 0 `int8u LensType = 6`, entry 1 `format 99`, entry 2 `string[4]
  /// Quality = "FINE"`) surfaces `Nikon:LensType = "G"` AND `Nikon:Quality`
  /// with only `[minor] Bad format (99) for MakerNotes entry 1`.
  #[test]
  fn nikon_later_bad_format_skipped_valid_kept() {
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]); // int8u = 6 → "G"
    let bad1 = entry_inline(0x0004, 99, 1, [0x00, 0x00, 0x00, 0x00]); // invalid fmt
    let quality = entry_inline(0x0004, 2, 4, *b"FINE"); // string[4] "FINE"
    let blob = headerless_ifd(&[lenstype, bad1, quality]);
    let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      entries.len(),
      2,
      "a LATER bad format skips only that entry; the valid entries before/after are kept"
    );
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[0].value, RawValue::U64(vec![6]));
    assert_eq!(entries[1].tag_id, 0x0004);
    match &entries[1].value {
      RawValue::Text { text, .. } => assert_eq!(text, "FINE"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  /// The BigTIFF / Unicode / Complex format codes `14..=18` are REJECTED on the
  /// IFD-walk decode path, exactly like any other invalid code — `ProcessExif`
  /// accepts ONLY `1..=13 | 129` ([`Format::is_valid_ifd_code`]), so a code
  /// `14`/`15`/`16`/`17`/`18` is `Bad format` (NOT decoded), even though
  /// `Format::from_code` maps each to a real `Format` with a nonzero
  /// `byte_size`. At entry 0 it aborts the directory.
  ///
  /// Ground-truthed against `perl exiftool 13.59`: each of `format 14..18` at
  /// entry 0 (followed by a valid `LensType`) emits ONLY `[minor] Bad format
  /// (<code>) for MakerNotes entry 0` and NO `Nikon:*` tag — identical to the
  /// `format 99` abort.
  #[test]
  fn nikon_format_14_to_18_rejected() {
    for code in [14u16, 15, 16, 17, 18] {
      let bad0 = entry_inline(0x0083, code, 1, [0x00, 0x00, 0x00, 0x00]);
      let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
      let blob = headerless_ifd(&[bad0, lenstype]);
      let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
      assert!(
        entries.is_empty(),
        "format code {code} must be rejected as Bad format (entry 0 ⇒ directory abort)"
      );
    }
    // …and a code 14..=18 at a LATER entry is skipped, not decoded, leaving the
    // valid entries (mirrors the format-99 later-skip arm).
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
    let bad1 = entry_inline(0x0004, 16, 1, [0x00, 0x00, 0x00, 0x00]); // int64u code
    let quality = entry_inline(0x0004, 2, 4, *b"FINE");
    let blob = headerless_ifd(&[lenstype, bad1, quality]);
    let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(
      entries.len(),
      2,
      "a code 14..=18 at a later entry is skipped (not decoded), the valid entries kept"
    );
    assert_eq!(entries[0].tag_id, 0x0083);
    assert_eq!(entries[1].tag_id, 0x0004);
  }

  /// A 12-byte IFD entry with an OUT-OF-LINE value (a 4-byte stored offset) —
  /// helper for the suspicious-offset / warnCount tests.
  fn entry_offset(tag: u16, format: u16, count: u32, offset: u32) -> Vec<u8> {
    let mut e: Vec<u8> = Vec::new();
    e.extend_from_slice(&tag.to_be_bytes());
    e.extend_from_slice(&format.to_be_bytes());
    e.extend_from_slice(&count.to_be_bytes());
    e.extend_from_slice(&offset.to_be_bytes());
    e
  }

  /// A headerless big-endian Nikon IFD whose buffer ENDS exactly `tail` bytes
  /// past the entry table — i.e. `blob.len() == dir_end + tail`, where `dir_end
  /// = 2 + 12*num_entries` (the count word + the entry array, ExifTool's
  /// `$dirSize`, NOT including a next-IFD pointer). This lets a test set
  /// `bytes_from_end` (`$dataLen - $dirEnd`) to an EXACT value (0/1/2/3/4…) to
  /// exercise the illegal-tail gate. (Distinct from `headerless_ifd`, which
  /// always appends a 4-byte next-IFD pointer ⇒ `bytes_from_end == 4`.)
  fn headerless_ifd_with_tail(entries: &[Vec<u8>], tail: usize) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
      b.extend_from_slice(e);
    }
    // `dir_end = 2 + 12*num_entries` is now `b.len()`. Append exactly `tail`
    // bytes so `bytes_from_end == tail`.
    b.resize(b.len() + tail, 0xAA);
    b
  }

  /// ILLEGAL-TAIL (Exif.pm:6394-6399): a directory whose `$bytesFromEnd`
  /// (`$dataLen - $dirEnd`) is exactly `1` is a malformed directory — ExifTool
  /// aborts it wholesale (`Illegal $dir directory size`, `return 0`) BEFORE
  /// walking any entry, so NO Nikon tag is emitted. Here a headerless Nikon IFD
  /// (the blob IS the buffer, `value_base = 0`) has a valid 1-entry table
  /// (LensType = 6 → "G"); `dir_end = 2 + 12 = 14`, and the buffer ends 1 byte
  /// past it (`bytes_from_end == 1`). The walk returns nothing.
  ///
  /// Ground-truthed against `perl exiftool 13.59`: the IDENTICAL `ProcessExif`
  /// directory-framing rule on a standalone TIFF whose IFD0 entry table is
  /// followed by exactly 1 trailing byte (`$bytesFromEnd == 1`) emits
  /// `[Warning] Illegal IFD0 directory size (1 entries)` and NO `IFD0:*` tag —
  /// whereas a 0- or 2-byte tail emits the tag (see the 0/2 control below). The
  /// Nikon walker mirrors Canon's `classify_canon_directory`
  /// (`AbortIllegalSize`) and the shared EXIF walker on this same `:6397` gate.
  /// The matching `Illegal …` WARNING stays #230-deferred; only the
  /// TAG-suppression abort is reproduced here.
  #[test]
  fn nikon_illegal_tail_1_byte_aborts() {
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
    let blob = headerless_ifd_with_tail(&[lenstype], 1); // bytes_from_end == 1
    let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      entries.is_empty(),
      "a 1-byte directory tail is illegal ⇒ the whole directory is aborted, no tags"
    );
  }

  /// ILLEGAL-TAIL (Exif.pm:6394-6399): a `$bytesFromEnd` of exactly `3` aborts
  /// the directory just like `1`. Same headerless 1-entry IFD as the `1`-byte
  /// case, with `bytes_from_end == 3`.
  ///
  /// Ground-truthed against `perl exiftool 13.59`: a standalone TIFF whose IFD0
  /// entry table is followed by exactly 3 trailing bytes emits `[Warning]
  /// Illegal IFD0 directory size (1 entries)` and NO `IFD0:*` tag (identical to
  /// the 1-byte case; the 0/2/≥4 tails all walk).
  #[test]
  fn nikon_illegal_tail_3_byte_aborts() {
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
    let blob = headerless_ifd_with_tail(&[lenstype], 3); // bytes_from_end == 3
    let entries = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      entries.is_empty(),
      "a 3-byte directory tail is illegal ⇒ the whole directory is aborted, no tags"
    );
  }

  /// REGRESSION GUARD against OVER-ABORT — a `$bytesFromEnd` of `0` or `2` is
  /// LEGAL (`Exif.pm:6395`, `unless ($bytesFromEnd == 2 or $bytesFromEnd == 0)`)
  /// and the directory is walked normally. The SAME headerless 1-entry IFD as
  /// the 1/3-byte cases, with `bytes_from_end == 0` (the buffer ends exactly at
  /// the entry table) and `bytes_from_end == 2`: the LensType STILL emits.
  ///
  /// Ground-truthed against `perl exiftool 13.59`: a standalone TIFF whose IFD0
  /// entry table is followed by a 0- or 2-byte tail emits `IFD0:Orientation`
  /// (no `Illegal …` warning) — only the 1- and 3-byte tails abort.
  #[test]
  fn nikon_legal_tail_0_and_2_bytes_walked() {
    let lenstype = entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]);
    // 0-byte tail: the buffer ends exactly at dir_end (= 2 + 12), so
    // dataLen - dirEnd == 0.
    let blob0 = headerless_ifd_with_tail(&[lenstype.clone()], 0);
    let e0 = walk_nikon_ifd(&blob0, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(e0.len(), 1, "a 0-byte tail is legal ⇒ the entry is walked");
    assert_eq!(e0[0].tag_id, 0x0083);
    assert_eq!(e0[0].value, RawValue::U64(vec![6]));
    // 2-byte tail.
    let blob2 = headerless_ifd_with_tail(&[lenstype], 2); // bytes_from_end == 2
    let e2 = walk_nikon_ifd(&blob2, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert_eq!(e2.len(), 1, "a 2-byte tail is legal ⇒ the entry is walked");
    assert_eq!(e2[0].tag_id, 0x0083);
  }

  /// warnCount > 10 ABORT (`Exif.pm:6455-6456`): once MORE than ten counted
  /// per-entry warnings (`++$warnCount`) accrue in a directory, `ProcessExif`
  /// aborts it (`Too many warnings -- $dir parsing aborted`, `return 0`),
  /// checked BEFORE reading each next entry — so a VALID entry that follows a
  /// >10-warning run is NOT emitted. Here a headerless Nikon IFD has 11
  /// out-of-line entries each with a stored offset of `0` (`< 8` ⇒ suspicious,
  /// `++$warnCount`), then a 12th VALID inline `LensType` (0x0083 = 6 → "G").
  /// The 11 suspicious entries push `warn_count` to 11; the guard fires at the
  /// top of the 12th iteration (`warn_count > 10`), aborting before the
  /// LensType — so it is ABSENT.
  ///
  /// Ground-truthed against `perl exiftool 13.59` on the equivalent crafted
  /// JPEG (`NIKON CORPORATION` IFD0 + a headerless Nikon MakerNote of 11
  /// offset-0 out-of-line entries then a valid `int8u LensType = 6`): the
  /// `-v3` trace shows eleven `[minor] Suspicious MakerNotes offset for …`
  /// warnings followed by `[Minor] Too many warnings -- MakerNotes parsing
  /// aborted`, and the JSON emits NO `Nikon:LensType` — whereas the 10-entry
  /// control (below) DOES emit `Nikon:LensType = "G"`. Mirrors Canon's
  /// `walk_canon_in_tiff` loop-top `if warn_count > 10 { break }`.
  #[test]
  fn nikon_warncount_over_10_aborts_directory() {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    // 11 out-of-line entries, each stored offset 0 (< 8 ⇒ suspicious, counted).
    // rational64u count 1 = 8 bytes > 4 ⇒ out-of-line.
    for i in 0..11u16 {
      entries.push(entry_offset(0x00a0 + i, 5, 1, 0));
    }
    // 12th: a VALID inline LensType (would emit "G" if reached).
    entries.push(entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00]));
    let blob = headerless_ifd(&entries);
    let out = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    assert!(
      out.iter().all(|e| e.tag_id != 0x0083),
      "after >10 counted warnings the directory aborts ⇒ the late LensType is dropped"
    );
    assert!(
      out.is_empty(),
      "every entry before the abort was suspicious (skipped) ⇒ nothing emitted"
    );
  }

  /// REGRESSION GUARD against OVER-ABORT — the cap is `> 10`, NOT `>= 10`
  /// (`Exif.pm:6455`, `if ($warnCount > 10)`): EXACTLY ten counted warnings do
  /// NOT trip it, so a valid entry after a 10-warning run STILL emits. Same
  /// shape as the >10 test but with TEN offset-0 entries before the LensType.
  ///
  /// Ground-truthed against `perl exiftool 13.59`: the 10-entry control JPEG
  /// emits `Nikon:LensType = "G"` (the directory is NOT aborted), confirming the
  /// boundary is strictly `> 10`.
  #[test]
  fn nikon_warncount_exactly_10_still_emits_valid_tag() {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    for i in 0..10u16 {
      entries.push(entry_offset(0x00a0 + i, 5, 1, 0)); // 10 suspicious (counted)
    }
    entries.push(entry_inline(0x0083, 1, 1, [0x06, 0x00, 0x00, 0x00])); // valid LensType
    let blob = headerless_ifd(&entries);
    let out = walk_nikon_ifd(&blob, 0, ByteOrder::Big, 0, NikonTable::Main);
    // The 10 suspicious entries are each skipped, but the cap (> 10) is NOT
    // tripped, so the 11th (valid) entry is reached and emitted.
    assert_eq!(
      out.len(),
      1,
      "exactly 10 warnings does not abort (> 10, not >= 10) ⇒ the valid entry emits"
    );
    assert_eq!(out[0].tag_id, 0x0083);
    assert_eq!(out[0].value, RawValue::U64(vec![6]));
  }
}
