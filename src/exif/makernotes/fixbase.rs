// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Shared maker-note offset / byte-order engine — the faithful port of the
//! cross-vendor helpers in `Image::ExifTool::MakerNotes` (Phil Harvey) plus
//! the one `Exif.pm` byte-order heuristic the maker-note path depends on.
//!
//! ## What this module owns
//!
//! Every camera vendor's private IFD lives inside the ExifIFD's 0x927C
//! `MakerNote` tag, but the LAYOUT of that IFD's value blocks is vendor- and
//! even model-specific: some put values 4 bytes past the IFD, some leave 24
//! padding bytes, some write value offsets relative to the IFD entry (not the
//! TIFF base), and some (Canon) append an 8-byte TIFF footer recording the
//! ORIGINAL file offset so a tool that bodily relocated the maker-note block
//! can recover the shift. ExifTool unifies all of this in a handful of shared
//! subs:
//!
//! - [`detect_unknown_byte_order`] — `ByteOrder => 'Unknown'` resolution from
//!   the IFD entry count (`Exif.pm:6982-6993`).
//! - [`get_maker_note_offset`] — the per-`Make` table of expected
//!   end-of-IFD-to-first-value offsets (`MakerNotes.pm:1149-1231`).
//! - [`get_value_blocks`] — walk the IFD entries and record every out-of-line
//!   value pointer → block size (`MakerNotes.pm:1241-1275`).
//! - [`fix_base`] — analyse the value-offset gaps and compute the base shift
//!   needed to make the offsets resolve (`MakerNotes.pm:1282-1484`).
//! - [`locate_ifd`] — scan unknown maker-note data for a plausible IFD start +
//!   byte order (`MakerNotes.pm:1486-1663` / `ProcessUnknown` `:1816-1837`).
//!
//! ## Phase scope (additive, NOT wired)
//!
//! These functions are PURE ports surfaced for the Phase-2+ MakerNote walker;
//! NOTHING in the production `ProcessExif` path calls them yet (the Phase-1
//! walker only IDENTIFIES the vendor — it does not recurse + re-base). Wiring
//! is a later task. Conformance therefore stays byte-identical. Each function
//! takes its inputs as plain values / a small input struct mirroring the
//! relevant `$$dirInfo{…}` and `$$et{…}` fields, so it has NO dependency on
//! the Walker.
//!
//! ## Faithfulness notes
//!
//! - ExifTool's `$$dirInfo{Base}` / `$$dirInfo{DataPos}` mutations are RETURNED
//!   here (the caller applies them), since these functions own no `$dirInfo`.
//!   The returned `shift` is exactly the Perl sub's scalar return; the result
//!   struct additionally surfaces the `EntryBased` / `Relative` / `FixedBy`
//!   side effects the Perl set on `$dirInfo`.
//! - ExifTool's `$et->Warn(...)` calls are NOT side-effecting here (no et
//!   object); the ones that change CONTROL FLOW (the early `return 0`s) are
//!   ported faithfully, and the purely-informational warnings are documented
//!   at their Perl line.

#![deny(clippy::indexing_slicing)]

use std::collections::BTreeMap;

use crate::exif::ifd::{ByteOrder, Format, get_u16, get_u32};

// ===========================================================================
// Small string predicates — faithful Perl-regex equivalents (no regex dep).
//
// The maker-note path's Make/Model tests are anchored prefixes (`/^Canon/`),
// case-insensitive prefixes (`/^…/i`), plain substrings (`/(PowerShot|…)/`),
// and `\b`-word-boundary alternations (`/\b(20D|…)\b/`). This crate ports
// every such test by hand (no `regex` dependency — see the vendor dispatcher
// + `canon::file_info`), so these helpers reproduce the exact semantics.
// ===========================================================================

/// A byte is a Perl `\w` "word" char (`[A-Za-z0-9_]`).
#[inline(always)]
const fn is_word_byte(c: u8) -> bool {
  c.is_ascii_alphanumeric() || c == b'_'
}

/// `$model =~ /\bNEEDLE\b/` — does `needle` occur in `hay` flanked by word
/// boundaries on BOTH sides? A `\b` exists between a word char and a non-word
/// char (or a string edge). Every `needle` here begins/ends with a word char,
/// so the boundary holds iff the char immediately before/after the match is
/// NOT a word char (or is a string edge).
fn word_match(hay: &str, needle: &str) -> bool {
  let nbytes = needle.as_bytes();
  let (Some(&nf), Some(&nl)) = (nbytes.first(), nbytes.last()) else {
    return false; // empty needle never matches under `\b…\b`
  };
  let need_lead_boundary = is_word_byte(nf);
  let need_trail_boundary = is_word_byte(nl);
  let hb = hay.as_bytes();
  let mut start = 0usize;
  while let Some(rel) = hay.get(start..).and_then(|tail| tail.find(needle)) {
    let i = start + rel;
    let end = i + needle.len();
    // `\b` before the match.
    let before_ok = if need_lead_boundary {
      i == 0 || hb.get(i.wrapping_sub(1)).is_some_and(|&c| !is_word_byte(c))
    } else {
      i != 0 && hb.get(i.wrapping_sub(1)).is_some_and(|&c| is_word_byte(c))
    };
    // `\b` after the match.
    let after_ok = if need_trail_boundary {
      end >= hb.len() || hb.get(end).is_some_and(|&c| !is_word_byte(c))
    } else {
      end < hb.len() && hb.get(end).is_some_and(|&c| is_word_byte(c))
    };
    if before_ok && after_ok {
      return true;
    }
    start = i + 1;
  }
  false
}

/// `$model =~ /^NEEDLE\b/` — `hay` STARTS with `needle` AND a `\b` follows the
/// match. `needle` ends in a word char here, so the trailing boundary holds
/// iff the next char (if any) is NOT a word char.
fn starts_with_word(hay: &str, needle: &str) -> bool {
  let Some(rest) = hay.strip_prefix(needle) else {
    return false;
  };
  match rest.as_bytes().first() {
    None => true, // string edge is a boundary
    Some(&c) => !is_word_byte(c),
  }
}

// ===========================================================================
// Feature 1 — Unknown byte-order entry-count heuristic (Exif.pm:6982-6993)
// ===========================================================================

/// `ByteOrder => 'Unknown'` resolution for a headerless sub-directory body
/// (`Exif.pm:6982-6993`): read the int16u entry-count at `dir_start` in the
/// PARENT order; if `(num & 0xff00) != 0 && (num>>8) > (num & 0xff)` the count
/// is implausibly large ⇒ the order is wrong ⇒ TOGGLE; else keep parent order.
///
/// Returns `None` if fewer than 2 bytes are available at `dir_start` — the
/// Perl guard `$subdirStart + 2 <= $subdirDataLen` (`:6982`) leaves
/// `$newByteOrder` unresolved, and the caller keeps the parent (`oldByteOrder`)
/// order (`:6996`). Surfacing `None` lets the caller reproduce that.
///
/// Faithful: `my $num = Get16u($subdirDataPt, $subdirStart)` is read in the
/// PARENT order (`SetByteOrder` has not been called for the child yet at
/// `:6986`); the toggle test is EXACTLY `($num & 0xff00) and (($num>>8) >
/// ($num & 0xff))` (`:6987`), and the toggle uses `%otherOrder` (`:6989`).
#[must_use]
pub fn detect_unknown_byte_order(
  data: &[u8],
  dir_start: usize,
  parent: ByteOrder,
) -> Option<ByteOrder> {
  // `$subdirStart + 2 <= $subdirDataLen` (`:6982`).
  let num = get_u16(data, dir_start, parent)?;
  // `if ($num & 0xff00 and ($num>>8) > ($num&0xff))` (`:6987`).
  if (num & 0xff00) != 0 && (num >> 8) > (num & 0xff) {
    // "This looks wrong, we shouldn't have this many entries" → toggle (`:6990`).
    Some(opposite_order(parent))
  } else {
    Some(parent) // "$newByteOrder = $oldByteOrder" (`:6992`).
  }
}

/// `%otherOrder = ( II=>'MM', MM=>'II' )` (`Exif.pm:6989`, `MakerNotes.pm`
/// `ToggleByteOrder`).
#[inline(always)]
const fn opposite_order(order: ByteOrder) -> ByteOrder {
  match order {
    ByteOrder::Little => ByteOrder::Big,
    ByteOrder::Big => ByteOrder::Little,
  }
}

// ===========================================================================
// Feature 2 — GetMakerNoteOffset (MakerNotes.pm:1149-1231)
// ===========================================================================

/// Resolved expected-offset table for one camera (the return of
/// `GetMakerNoteOffset`, `MakerNotes.pm:1145-1148`).
///
/// - `relative`: the `$relative` flag (element 0) — `None` for "no change"
///   (Perl `undef`), `Some(false)` only where a make FORCES absolute
///   addressing (PENTAX, `:1220`).
/// - `offsets`: the expected offsets from the end of the IFD to the first
///   value block (elements 1..N). The FIRST is the one used when writing;
///   offsets of 0 and 4 are always allowed even when not listed (`:1158-1159`).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakerNoteOffset {
  relative: Option<bool>,
  offsets: Vec<i32>,
}

impl MakerNoteOffset {
  /// The `$relative` flag (`None` = no change / `undef`).
  #[must_use]
  #[inline(always)]
  pub const fn relative(&self) -> Option<bool> {
    self.relative
  }

  /// The expected end-of-IFD-to-first-value offsets (first is canonical).
  #[must_use]
  #[inline(always)]
  pub fn offsets(&self) -> &[i32] {
    &self.offsets
  }

  /// The canonical (first) offset — `$offsets[0]`, the bundled `$makeDiff`
  /// (`MakerNotes.pm:1348`). `None` for the "no expected offset" makes (the
  /// weird Olympus list, `:1191-1194`), where Perl leaves `@offsets` empty and
  /// `$makeDiff` is `undef`.
  #[must_use]
  #[inline]
  pub fn make_diff(&self) -> Option<i32> {
    self.offsets.first().copied()
  }
}

/// `GetMakerNoteOffset($et)` — the per-`Make`/`Model` table of expected
/// offsets from the end of the maker-note IFD to its first value block
/// (`MakerNotes.pm:1149-1231`).
///
/// Inputs mirror the `$$et{…}` fields the Perl reads:
/// - `make` = `$$et{Make}`, `model` = `$$et{Model}`.
/// - `file_type` = `$$et{FILE_TYPE}` (drives CASIO + Leica-S2 padding) —
///   `None` if unknown.
/// - `tiff_type` = `$$et{TIFF_TYPE}` (drives the SAMSUNG EK-GN120 SRW patch) —
///   `None` if unknown.
///
/// NOTE (`$$et{OlympusCAMER}`, `:1201`): the SONY branch also pushes 4 when
/// the obscure internal `OlympusCAMER` flag is set (a Sony body wrapped in an
/// Olympus container). That flag is not part of this engine's input surface,
/// so this port omits it — a faithful omission for the standalone helper; the
/// model regex covers every documented Sony-4 body.
#[must_use]
pub fn get_maker_note_offset(
  make: &str,
  model: &str,
  file_type: Option<&str>,
  tiff_type: Option<&str>,
) -> MakerNoteOffset {
  let mut relative: Option<bool> = None;
  let mut offsets: Vec<i32> = Vec::new();

  // Normally value data starts 4 bytes after the end of the directory, so 4 is
  // the default; offsets 0 and 4 are always allowed even if not specified, but
  // the FIRST offset specified is the one used when writing (`:1157-1159`).
  if make.starts_with("Canon") {
    // `($model =~ /\b(20D|350D|REBEL XT|Kiss Digital N)\b/) ? 6 : 4` (`:1161`).
    let six = ["20D", "350D", "REBEL XT", "Kiss Digital N"]
      .iter()
      .any(|n| word_match(model, n));
    offsets.push(if six { 6 } else { 4 });
    // `push @offsets, 28 if $model =~ /\b(FV\b|OPTURA)/` (`:1164`). The outer
    // `\b` requires a leading boundary; the alternation is `FV\b` (FV + trailing
    // boundary) OR `OPTURA` (plain, no trailing boundary).
    if word_match(model, "FV") || word_match_lead_only(model, "OPTURA") {
      offsets.push(28);
    }
    // `push @offsets, 16 if $model =~ /(PowerShot|IXUS|IXY)/` (`:1166`) — plain
    // substring, NO word boundary.
    if model.contains("PowerShot") || model.contains("IXUS") || model.contains("IXY") {
      offsets.push(16);
    }
  } else if make.starts_with("CASIO") {
    // `$$et{FILE_TYPE} =~ /^(RIFF|MOV)$/ ? 0 : (4, 16, 2)` (`:1171`).
    if matches!(file_type, Some("RIFF" | "MOV")) {
      offsets.push(0);
    } else {
      offsets.extend_from_slice(&[4, 16, 2]);
    }
  } else if starts_with_ci(make, "General Imaging Co.")
    || starts_with_ci(make, "GEDSC IMAGING CORP.")
  {
    // `/^(General Imaging Co.|GEDSC IMAGING CORP.)/i` (`:1172`).
    offsets.push(0);
  } else if make.starts_with("KYOCERA") {
    offsets.push(12); // (`:1175`).
  } else if make.starts_with("Leica Camera AG") {
    // (`:1176-1188`).
    if model == "S2" {
      // `4, ($$et{FILE_TYPE} eq 'JPEG' ? 286 : 274)` (`:1179`).
      offsets.push(4);
      offsets.push(if file_type == Some("JPEG") { 286 } else { 274 });
    } else if model == "LEICA M MONOCHROM (Typ 246)" {
      offsets.extend_from_slice(&[4, 130]); // (`:1181`).
    } else if model == "LEICA M (Typ 240)" {
      offsets.extend_from_slice(&[4, 118]); // (`:1183`).
    } else if starts_with_word(model, "R8")
      || starts_with_word(model, "R9")
      || starts_with_word(model, "M8")
    {
      offsets.push(6); // `/^(R8|R9|M8)\b/` (`:1184`).
    } else {
      offsets.push(4); // (`:1187`).
    }
  } else if make.starts_with("OLYMPUS")
    && (starts_with_word(model, "E-1")
      || starts_with_word(model, "E-300")
      || starts_with_word(model, "E-330"))
  {
    // `/^OLYMPUS/ and $model =~ /^E-(1|300|330)\b/` (`:1189`).
    offsets.push(16);
  } else if make.starts_with("OLYMPUS") && is_weird_olympus(model) {
    // `/^OLYMPUS/ and $model =~ /^(C2500L|…)\b/` (`:1191-1194`): NO expected
    // offset → `@offsets` left empty → offset determined empirically by
    // `FixBase`. `$makeDiff` (`make_diff()`) is therefore `None`.
  } else if starts_with_word(make, "Panasonic") || starts_with_word(make, "JVC") {
    // `/^(Panasonic|JVC)\b/` (`:1196`).
    offsets.push(0);
  } else if make.starts_with("SONY") {
    // `/^SONY/` (`:1198`). `$model =~ /^(DSLR-.*|SLT-A(33|35|55V)|NEX-(3|5|C3|
    // VG10E))$/` ? 4 : 0 (`:1200-1206`). (`$$et{OlympusCAMER}` omitted — see
    // the function doc.)
    offsets.push(if sony_uses_offset_4(model) { 4 } else { 0 });
  } else if tiff_type == Some("SRW") && make == "SAMSUNG" && model == "EK-GN120" {
    offsets.push(40); // (`:1207`).
  } else if make == "FUJIFILM" {
    offsets.extend_from_slice(&[4, 6]); // (`:1209-1211`).
  } else if make.starts_with("TOSHIBA") {
    offsets.extend_from_slice(&[0, 24]); // (`:1212-1214`).
  } else if make.starts_with("PENTAX") {
    // (`:1215-1220`). Pentax always uses absolute addressing, so force it.
    offsets.push(4);
    relative = Some(false);
  } else if starts_with_ci(make, "Konica Minolta") {
    // `/^Konica Minolta/i` (`:1221-1223`). Patch for DiMAGE X50/Xg/Z2/Z10.
    offsets.extend_from_slice(&[4, -16]);
  } else if make.starts_with("Minolta") {
    // (`:1224-1226`). Patch for DiMAGE 7/X20/Z1.
    offsets.extend_from_slice(&[4, -8, -12]);
  } else {
    offsets.push(4); // the normal offset (`:1228`).
  }

  MakerNoteOffset { relative, offsets }
}

/// `$$self{Make} =~ /^prefix/i` — case-insensitive ASCII prefix (compared on
/// BYTES so a lossy-decoded `Make` never panics on a char boundary; the
/// bundled prefixes are pure ASCII).
fn starts_with_ci(s: &str, prefix: &str) -> bool {
  let sb = s.as_bytes();
  let pb = prefix.as_bytes();
  sb.get(..pb.len())
    .is_some_and(|h| h.eq_ignore_ascii_case(pb))
}

/// `/\bNEEDLE/` with a LEADING boundary only (no trailing `\b`) — used for the
/// `OPTURA` arm of `/\b(FV\b|OPTURA)/` (`MakerNotes.pm:1164`).
fn word_match_lead_only(hay: &str, needle: &str) -> bool {
  let nbytes = needle.as_bytes();
  let Some(&nf) = nbytes.first() else {
    return false;
  };
  let need_lead_boundary = is_word_byte(nf);
  let hb = hay.as_bytes();
  let mut start = 0usize;
  while let Some(rel) = hay.get(start..).and_then(|tail| tail.find(needle)) {
    let i = start + rel;
    let before_ok = if need_lead_boundary {
      i == 0 || hb.get(i.wrapping_sub(1)).is_some_and(|&c| !is_word_byte(c))
    } else {
      i != 0 && hb.get(i.wrapping_sub(1)).is_some_and(|&c| is_word_byte(c))
    };
    if before_ok {
      return true;
    }
    start = i + 1;
  }
  false
}

/// The "just weird" Olympus models that get NO expected offset
/// (`MakerNotes.pm:1193`): `/^(C2500L|C-1Z?|C-5000Z|X-2|C720UZ|C725UZ|C150|
/// C2Z|E-10|E-20|FerrariMODEL2003|u20D|u10D)\b/`. `C-1Z?` = `C-1` optionally
/// followed by `Z` (so both `C-1` and `C-1Z` match), each anchored at start
/// with a trailing word boundary.
fn is_weird_olympus(model: &str) -> bool {
  const PLAIN: [&str; 11] = [
    "C2500L",
    "C-5000Z",
    "X-2",
    "C720UZ",
    "C725UZ",
    "C150",
    "C2Z",
    "E-10",
    "E-20",
    "FerrariMODEL2003",
    "u20D",
  ];
  if PLAIN.iter().any(|n| starts_with_word(model, n)) {
    return true;
  }
  // `u10D` (the 12th literal alternative).
  if starts_with_word(model, "u10D") {
    return true;
  }
  // `C-1Z?` — `C-1Z` first (longer), else bare `C-1` (`\b` after).
  starts_with_word(model, "C-1Z") || starts_with_word(model, "C-1")
}

/// `$model =~ /^(DSLR-.*|SLT-A(33|35|55V)|NEX-(3|5|C3|VG10E))$/`
/// (`MakerNotes.pm:1200`) — the Sony models that use an offset of 4. The `$`
/// anchors the whole string (the `DSLR-.*` arm allows any suffix).
fn sony_uses_offset_4(model: &str) -> bool {
  // `DSLR-.*` — starts with `DSLR-` (then anything to end-of-string).
  if model.starts_with("DSLR-") {
    return true;
  }
  // `SLT-A(33|35|55V)$` — whole-string match.
  if model == "SLT-A33" || model == "SLT-A35" || model == "SLT-A55V" {
    return true;
  }
  // `NEX-(3|5|C3|VG10E)$` — whole-string match.
  matches!(model, "NEX-3" | "NEX-5" | "NEX-C3" | "NEX-VG10E")
}

// ===========================================================================
// Feature 3 — GetValueBlocks (MakerNotes.pm:1241-1275)
// ===========================================================================

/// The value-block maps from `GetValueBlocks` (`MakerNotes.pm:1237-1240`).
///
/// - `val_block`: offset → block size for every out-of-line value (keys are the
///   raw value pointers; the FixBase gap analysis sorts these).
/// - `val_blk_adj`: the same, but each key adjusted by `12 * index` to detect
///   ENTRY-BASED offsets; carries the running `MIN`/`MAX` of the adjusted span.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueBlocks {
  val_block: BTreeMap<usize, usize>,
  val_blk_adj: BTreeMap<usize, usize>,
  /// `$valBlkAdj{MIN}` — Perl stores it in the same hash under a string key;
  /// the port lifts it to its own field. `None` until the first out-of-line
  /// entry is seen.
  min_adj: Option<usize>,
  /// `$valBlkAdj{MAX}`.
  max_adj: Option<usize>,
}

impl ValueBlocks {
  /// `\%valBlock` — offset → longest block size at that offset.
  #[must_use]
  #[inline(always)]
  pub const fn val_block(&self) -> &BTreeMap<usize, usize> {
    &self.val_block
  }

  /// `\%valBlkAdj` — entry-position-adjusted offset → block size.
  #[must_use]
  #[inline(always)]
  pub const fn val_blk_adj(&self) -> &BTreeMap<usize, usize> {
    &self.val_blk_adj
  }

  /// `$valBlkAdj{MIN}` (`MakerNotes.pm:1264-1269`).
  #[must_use]
  #[inline(always)]
  pub const fn min_adj(&self) -> Option<usize> {
    self.min_adj
  }

  /// `$valBlkAdj{MAX}` (`MakerNotes.pm:1264-1269`).
  #[must_use]
  #[inline(always)]
  pub const fn max_adj(&self) -> Option<usize> {
    self.max_adj
  }

  /// `%$valBlock` truthiness — `false` when no out-of-line values were found
  /// (the `return 0 unless %$valBlock` guard, `MakerNotes.pm:1300`).
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.val_block.is_empty()
  }
}

/// `GetValueBlocks($dataPt, $dirStart, $tagPtr)` (`MakerNotes.pm:1241-1275`):
/// walk the IFD entries at `dir_start` (entry stride `2 + 12*index`) and record
/// every value whose decoded size exceeds 4 bytes (i.e. is stored OUT-OF-LINE)
/// as `value-pointer → size`.
///
/// Returns the [`ValueBlocks`] maps and the `tagPtr` map (tag-id → value
/// pointer) that the Perl populates via its third `$tagPtr` out-param — FixBase
/// uses `$tagPtr{0xe00}` (PrintIM) and `0xe00` lookups, so it is surfaced here.
///
/// Faithful: `$numEntries = Get16u($dataPt, $dirStart)` (`:1244`); per entry
/// `$format = Get16u($dataPt, $entry+2)`, `last if $format < 1 or $format > 13`
/// (`:1248-1249` — note the `1..=13` gate is NARROWER than the IFD walker's
/// `1..=18|129`: BigTIFF/Exif-3.0 codes terminate the scan here); `$count =
/// Get32u($dataPt, $entry+4)`; `$size = $count * formatSize[$format]` (`:1251`);
/// `next if $size <= 4` (`:1252`); `$valPtr = Get32u($dataPt, $entry+8)`
/// (`:1253`). The `unless defined … and … > $size` keeps the LONGEST block at
/// a shared offset (`:1256-1258`).
#[must_use]
pub fn get_value_blocks(
  data: &[u8],
  dir_start: usize,
  order: ByteOrder,
) -> (ValueBlocks, BTreeMap<u16, u32>) {
  let mut out = ValueBlocks::default();
  let mut tag_ptr: BTreeMap<u16, u32> = BTreeMap::new();
  // `my $numEntries = Get16u($dataPt, $dirStart)` (`:1244`). A truncated count
  // read yields 0 (no entries) — the Perl `unpack` would warn + read 0.
  let num_entries = get_u16(data, dir_start, order).unwrap_or(0);

  for index in 0..usize::from(num_entries) {
    // `my $entry = $dirStart + 2 + 12 * $index` (`:1247`). On arithmetic
    // overflow (a degenerate `dir_start`/`index` on a 32-bit/wasm `usize`),
    // STOP the walk — there is no in-bounds entry past the overflow point.
    let Some(entry) = 12usize
      .checked_mul(index)
      .and_then(|off| off.checked_add(2))
      .and_then(|off| dir_start.checked_add(off))
    else {
      break;
    };
    // `my $format = Get16u($dataPt, $entry+2)` (`:1248`).
    let Some(format_code) = entry.checked_add(2).and_then(|p| get_u16(data, p, order)) else {
      break;
    };
    // `last if $format < 1 or $format > 13` (`:1249`) — the GetValueBlocks gate
    // is the 13 standard TIFF types ONLY (no BigTIFF/Exif-3.0, unlike the IFD
    // walker's `1..=13 | 129`).
    if !matches!(format_code, 1..=13) {
      break;
    }
    // `my $count = Get32u($dataPt, $entry+4)` (`:1250`).
    let Some(count) = entry.checked_add(4).and_then(|p| get_u32(data, p, order)) else {
      break;
    };
    // `my $size = $count * formatSize[$format]` (`:1251`). `formatSize[1..=13]`
    // == `Format::byte_size`; the gate above guarantees code ∈ 1..=13.
    let size = u64::from(count).saturating_mul(Format::from_code(format_code).byte_size() as u64);
    // `next if $size <= 4` (`:1252`).
    if size <= 4 {
      continue;
    }
    let size = usize_from_u64(size);
    // `$valPtr = Get32u($dataPt, $entry+8)` (`:1253`).
    let Some(val_ptr_u32) = entry.checked_add(8).and_then(|p| get_u32(data, p, order)) else {
      break;
    };
    let val_ptr = val_ptr_u32 as usize;
    // `$tagPtr and $$tagPtr{Get16u($dataPt, $entry)} = $valPtr` (`:1254`).
    if let Some(tag_id) = get_u16(data, entry, order) {
      tag_ptr.insert(tag_id, val_ptr_u32);
    }
    // "save location and size of longest block at this offset" (`:1256-1258`):
    // `unless (defined $valBlock{$valPtr} and $valBlock{$valPtr} > $size)` —
    // keep when the slot is empty OR the existing block is not longer.
    let keep = out
      .val_block
      .get(&val_ptr)
      .is_none_or(|&existing| existing <= size);
    if keep {
      out.val_block.insert(val_ptr, size);
    }
    // "adjust for case of value-based offsets": `$valPtr += 12 * $index`
    // (`:1260`).
    let adj_ptr = val_ptr.wrapping_add(12usize.wrapping_mul(index));
    // `unless (defined $valBlkAdj{$valPtr} and $valBlkAdj{$valPtr} > $size)`
    // (`:1261`).
    let keep_adj = out
      .val_blk_adj
      .get(&adj_ptr)
      .is_none_or(|&existing| existing <= size);
    if keep_adj {
      out.val_blk_adj.insert(adj_ptr, size);
      // `my $end = $valPtr + $size` (`:1263`).
      let end = adj_ptr.wrapping_add(size);
      match out.min_adj {
        Some(min) => {
          // "save minimum only if it has a value of 12 or greater" (`:1265-
          // 1267`): `$valBlkAdj{MIN} = $valPtr if $valBlkAdj{MIN} < 12 or
          // $valBlkAdj{MIN} > $valPtr;`
          if min < 12 || min > adj_ptr {
            out.min_adj = Some(adj_ptr);
          }
          // `$valBlkAdj{MAX} = $end if $valBlkAdj{MAX} > $end;` (`:1267`).
          // `max_adj` is `Some` here (set with `min_adj` in the `None` arm).
          if out.max_adj.is_some_and(|max| max > end) {
            out.max_adj = Some(end);
          }
        }
        None => {
          // `$valBlkAdj{MIN} = $valPtr; $valBlkAdj{MAX} = $end;` (`:1269-1270`).
          out.min_adj = Some(adj_ptr);
          out.max_adj = Some(end);
        }
      }
    }
  }
  (out, tag_ptr)
}

/// `usize::try_from(u64)` saturating at `usize::MAX` — a value-block size that
/// overflows a 32-bit/wasm `usize` cannot be a real in-bounds offset; clamp so
/// no arithmetic below panics. On 64-bit hosts this never clamps.
#[inline(always)]
fn usize_from_u64(v: u64) -> usize {
  usize::try_from(v).unwrap_or(usize::MAX)
}

// ===========================================================================
// Feature 4 — FixBase (MakerNotes.pm:1282-1484)
// ===========================================================================

/// Inputs to [`fix_base`] — the `$$dirInfo{…}` + `$$et{…}` fields the Perl
/// `FixBase` reads. The function owns no `$dirInfo`/`$et`, so these are passed
/// explicitly.
///
/// D8: a plain input bag (no invariants to encapsulate); fields are
/// `pub(crate)`-free — construct via [`FixBaseInput::new`] + the setters so the
/// option fields default faithfully.
#[derive(Debug, Clone)]
pub struct FixBaseInput<'a> {
  data: &'a [u8],
  dir_start: usize,
  dir_len: usize,
  data_pos: i64,
  base: i64,
  order: ByteOrder,
  make: &'a str,
  model: &'a str,
  file_type: Option<&'a str>,
  tiff_type: Option<&'a str>,
  /// `$$dirInfo{EntryBased}` on entry (a caller may pre-seed it).
  entry_based: bool,
  /// `$$dirInfo{FixOffsets}` — early-return 0 when set (`:1287`).
  fix_offsets: bool,
  /// `$$dirInfo{NoFixBase}` — early-return 0 when set (`:1287`).
  no_fix_base: bool,
  /// `$$dirInfo{FixBase}` — the per-directory fix mode (1 = fix, 2 = "Unknown
  /// maker notes, allow a range"). `None` = absent.
  dir_fix_base: Option<u8>,
  /// The `FixBase` OPTION (`$et->Options('FixBase')`) → `$setBase` (`:1294-
  /// 1295`). `Some(n)` forces the fix to exactly `n`; `None` = unset.
  opt_fix_base: Option<i64>,
}

impl<'a> FixBaseInput<'a> {
  /// Construct with the required directory fields; option flags default to the
  /// Perl "absent" state (no early-return, no forced base).
  #[must_use]
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    data: &'a [u8],
    dir_start: usize,
    dir_len: usize,
    data_pos: i64,
    base: i64,
    order: ByteOrder,
    make: &'a str,
    model: &'a str,
  ) -> Self {
    Self {
      data,
      dir_start,
      dir_len,
      data_pos,
      base,
      order,
      make,
      model,
      file_type: None,
      tiff_type: None,
      entry_based: false,
      fix_offsets: false,
      no_fix_base: false,
      dir_fix_base: None,
      opt_fix_base: None,
    }
  }

  /// Set `$$et{FILE_TYPE}` / `$$et{TIFF_TYPE}` (feed `GetMakerNoteOffset`).
  #[must_use]
  #[inline]
  pub const fn with_file_types(
    mut self,
    file_type: Option<&'a str>,
    tiff_type: Option<&'a str>,
  ) -> Self {
    self.file_type = file_type;
    self.tiff_type = tiff_type;
    self
  }

  /// Pre-seed `$$dirInfo{EntryBased}` (`:1292`).
  #[must_use]
  #[inline]
  pub const fn with_entry_based(mut self, entry_based: bool) -> Self {
    self.entry_based = entry_based;
    self
  }

  /// Set `$$dirInfo{FixOffsets}` / `$$dirInfo{NoFixBase}` (`:1287`).
  #[must_use]
  #[inline]
  pub const fn with_early_returns(mut self, fix_offsets: bool, no_fix_base: bool) -> Self {
    self.fix_offsets = fix_offsets;
    self.no_fix_base = no_fix_base;
    self
  }

  /// Set `$$dirInfo{FixBase}` (1 = fix, 2 = allow-range; `:1408`/`:1457`).
  #[must_use]
  #[inline]
  pub const fn with_dir_fix_base(mut self, mode: Option<u8>) -> Self {
    self.dir_fix_base = mode;
    self
  }

  /// Set the `FixBase` OPTION → `$setBase` (`:1294-1295`).
  #[must_use]
  #[inline]
  pub const fn with_opt_fix_base(mut self, opt: Option<i64>) -> Self {
    self.opt_fix_base = opt;
    self
  }
}

/// The result of [`fix_base`] — the scalar return PLUS the `$$dirInfo`
/// mutations the Perl applies in place.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixBaseResult {
  /// The Perl sub's scalar return — the total base shift (`$fix + $shift`,
  /// or one of the early `return` values).
  shift: i64,
  /// New `$$dirInfo{Base}` after the in-place `$$dirInfo{Base} += …`.
  new_base: i64,
  /// New `$$dirInfo{DataPos}` after `$$dirInfo{DataPos} -= …`.
  new_data_pos: i64,
  /// `$$dirInfo{EntryBased}` after the run (set to 1 in the entry-based arm,
  /// undef'd in the "do NOT look entry-based" arm).
  entry_based: bool,
  /// `$$dirInfo{Relative}` after the run (`None` = undef).
  relative: Option<bool>,
  /// `$$dirInfo{FixedBy}` after the run (`None` = unset).
  fixed_by: Option<i64>,
}

impl FixBaseResult {
  /// The base shift returned by the Perl sub.
  #[must_use]
  #[inline(always)]
  pub const fn shift(&self) -> i64 {
    self.shift
  }

  /// `$$dirInfo{Base}` after the fix.
  #[must_use]
  #[inline(always)]
  pub const fn new_base(&self) -> i64 {
    self.new_base
  }

  /// `$$dirInfo{DataPos}` after the fix.
  #[must_use]
  #[inline(always)]
  pub const fn new_data_pos(&self) -> i64 {
    self.new_data_pos
  }

  /// `$$dirInfo{EntryBased}` after the fix.
  #[must_use]
  #[inline(always)]
  pub const fn entry_based(&self) -> bool {
    self.entry_based
  }

  /// `$$dirInfo{Relative}` after the fix (`None` = undef).
  #[must_use]
  #[inline(always)]
  pub const fn relative(&self) -> Option<bool> {
    self.relative
  }

  /// `$$dirInfo{FixedBy}` after the fix (`None` = unset).
  #[must_use]
  #[inline(always)]
  pub const fn fixed_by(&self) -> Option<i64> {
    self.fixed_by
  }
}

/// `FixBase($et, $dirInfo)` (`MakerNotes.pm:1282-1484`) — analyse the
/// maker-note IFD's value offsets and compute the base shift that makes them
/// resolve. See the block-by-block comments + the module doc for the
/// faithfulness contract.
///
/// The early `return 0`s, the Canon TIFF-footer special case (`:1306-1337`),
/// the value-offset gap analysis (`:1356-1414`), the entry-based base mutation
/// (`:1418-1436`), and the final base fix (`:1450-1483`) are all ported.
#[must_use]
pub fn fix_base(input: &FixBaseInput<'_>) -> FixBaseResult {
  let no_shift = FixBaseResult {
    shift: 0,
    new_base: input.base,
    new_data_pos: input.data_pos,
    entry_based: input.entry_based,
    relative: None,
    fixed_by: None,
  };

  // "don't fix base if fixing offsets individually or if we don't want to fix
  // them" — `return 0 if $$dirInfo{FixOffsets} or $$dirInfo{NoFixBase}`
  // (`:1286-1287`).
  if input.fix_offsets || input.no_fix_base {
    return no_shift;
  }

  let data = input.data;
  let data_pos = input.data_pos;
  let dir_start = input.dir_start;
  let mut entry_based = input.entry_based;
  let order = input.order;
  // `$setBase = (defined $fixBase and $fixBase ne '') ? 1 : 0` (`:1294-1295`).
  let set_base = input.opt_fix_base.is_some();

  // "get hash of value block positions" (`:1298-1299`).
  let (val_blocks, tag_ptr) = get_value_blocks(data, dir_start, order);
  // `return 0 unless %$valBlock` (`:1300`).
  if val_blocks.is_empty() {
    return no_shift;
  }
  // "get sorted list of value offsets" — BTreeMap keys are already ascending
  // (`:1302` `sort { $a <=> $b }`).
  let val_ptrs: Vec<usize> = val_blocks.val_block().keys().copied().collect();

  // -----------------------------------------------------------------------
  // Canon maker notes with TIFF footer containing original offset
  // (`:1304-1338`).
  // -----------------------------------------------------------------------
  // `my $footerPos = $dirStart + $$dirInfo{DirLen} - 8` (`:1307`).
  if input.make.starts_with("Canon")
    && input.dir_len > 8
    && let Some(footer_pos) = dir_start
      .checked_add(input.dir_len)
      .and_then(|p| p.checked_sub(8))
    && let Some(footer) = data.get(footer_pos..footer_pos.saturating_add(8))
  {
    // `$footer =~ /^(II\x2a\0|MM\0\x2a)/` (`:1309`) AND `substr($footer,0,2)
    // eq GetByteOrder()` (`:1310`).
    let footer_order = ByteOrder::from_marker(footer);
    let magic_ok = matches!(footer.get(..4), Some(b"II\x2a\0" | b"MM\x00\x2a"));
    if magic_ok && footer_order == Some(order) {
      // `my $oldOffset = Get32u(\$footer, 4)` (`:1312`).
      let old_offset = i64::from(get_u32(footer, 4, order).unwrap_or(0));
      // `my $newOffset = $dirStart + $dataPos` (`:1313`).
      let new_offset = dir_start as i64 + data_pos;
      let fix: i64 = if let Some(forced) = input.opt_fix_base {
        forced // `$fix = $fixBase` (`:1315`).
      } else {
        // `$fix = $newOffset - $oldOffset; return 0 unless $fix` (`:1317-1318`).
        let fix = new_offset - old_offset;
        if fix == 0 {
          return no_shift;
        }
        // Picasa/ACDSee footer-bug check (`:1319-1330`): `$maxPt = $valPtrs[-1]
        // + $valBlock{$valPtrs[-1]}` then `$endDiff = $dirStart + $$dirInfo
        // {DirLen} - ($maxPt - $dataPos) - 8`; ignore footer if `$endDiff` is 0
        // or 1.
        if let Some(&last_ptr) = val_ptrs.last() {
          let last_size = val_blocks.val_block().get(&last_ptr).copied().unwrap_or(0);
          let max_pt = last_ptr as i64 + last_size as i64;
          let end_diff = dir_start as i64 + input.dir_len as i64 - (max_pt - data_pos) - 8;
          if end_diff == 0 || end_diff == 1 {
            // `$et->Warn('Canon maker note footer may be invalid (ignored)')` →
            // `return 0` (`:1328-1329`).
            return no_shift;
          }
        }
        fix
      };
      // `$$dirInfo{FixedBy} = $fix; $$dirInfo{Base} += $fix; $$dirInfo{DataPos}
      // -= $fix; return $fix` (`:1332-1336`). (The "Adjusted … base by $fix"
      // warning is informational, `:1332`.)
      return FixBaseResult {
        shift: fix,
        new_base: input.base + fix,
        new_data_pos: data_pos - fix,
        entry_based,
        relative: None,
        fixed_by: Some(fix),
      };
    }
  }

  // -----------------------------------------------------------------------
  // analyse value offsets to find the minimum valid offset (`:1339-1414`).
  // -----------------------------------------------------------------------
  // `my $minPt = $$dirInfo{MinOffset} = $valPtrs[0]` (`:1344`). val_ptrs is
  // non-empty (val_block not empty), so `.first()` is `Some`.
  let mut min_pt = val_ptrs.first().copied().unwrap_or(0) as i64;
  // `my $ifdLen = 2 + 12 * Get16u($$dirInfo{DataPt}, $dirStart)` (`:1345`).
  let num_entries = i64::from(get_u16(data, dir_start, order).unwrap_or(0));
  let ifd_len = 2 + 12 * num_entries;
  // `my $ifdEnd = $dirStart + $ifdLen` (`:1346`).
  let ifd_end = dir_start as i64 + ifd_len;
  // `my ($relative, @offsets) = GetMakerNoteOffset($et)` (`:1347`).
  let mn_off = get_maker_note_offset(input.make, input.model, input.file_type, input.tiff_type);
  let mut relative = mn_off.relative();
  let mut offsets = mn_off.offsets().to_vec();
  // `my $makeDiff = $offsets[0]` (`:1348`) — `undef` for the weird-Olympus list.
  let mut make_diff = mn_off.make_diff();

  // `my $expected = $dataPos + $ifdEnd + (defined $makeDiff ? $makeDiff : 4)`
  // (`:1353`).
  let expected = data_pos + ifd_end + i64::from(make_diff.unwrap_or(4));

  // "zero our counters" (`:1357`).
  let mut count_neg12 = 0i64;
  let mut count_zero = 0i64;
  let mut count_overlap = 0i64;
  let mut last: Option<i64> = None;
  // `foreach $valPtr (@valPtrs)` (`:1359-1381`).
  for &vp in &val_ptrs {
    let val_ptr = vp as i64;
    if let Some(last_v) = last {
      // `my $gap = $valPtr - $last` (`:1363`).
      let gap = val_ptr - last_v;
      if gap == 0 || gap == 1 {
        count_zero += 1; // (`:1364-1365`).
      } else if gap == -12 && !entry_based {
        // "value offsets are relative to the IFD entry" (`:1366-1368`).
        count_neg12 += 1;
      } else if gap < 0 {
        // "any other negative difference indicates overlapping values"
        // (`:1369-1371`) — but ignore zero value pointers.
        if val_ptr != 0 {
          count_overlap += 1;
        }
      } else if gap >= ifd_len {
        // "ignore previous minimum if we took a jump to near the expected
        // value" (`:1372-1375`): `$minPt = $valPtr if abs($valPtr - $expected)
        // <= 4`.
        if (val_ptr - expected).abs() <= 4 {
          min_pt = val_ptr;
        }
      }
      // "an offset less than 12 is surely garbage, so ignore it" — `$minPt =
      // $valPtr if $minPt < 12` (`:1377-1378`).
      if min_pt < 12 {
        min_pt = val_ptr;
      }
    }
    // `$last = $valPtr + $$valBlock{$valPtr}` (`:1380`).
    let size = val_blocks.val_block().get(&vp).copied().unwrap_or(0) as i64;
    last = Some(val_ptr + size);
  }

  let mut diff: i64 = 0;
  let mut shift: i64 = 0;

  // "could this IFD be using entry-based offsets?" (`:1382-1414`). The
  // `$valBlkAdj{MIN}`/`MAX` come from `get_value_blocks`; a None MIN/MAX means
  // no out-of-line value contributed (can't be entry-based then).
  let min_adj = val_blocks.min_adj();
  let max_adj = val_blocks.max_adj();
  // `(($countNeg12 > $countZero and $$valBlkAdj{MIN} >= $ifdLen - 2) or
  //   ($$valBlkAdj{MIN} == $ifdLen - 2 or $$valBlkAdj{MIN} == $ifdLen + 2))
  //  and $$valBlkAdj{MAX} <= $$dirInfo{DirLen}-2` (`:1383-1385`).
  let entry_based_detected = {
    let min_ok_a = count_neg12 > count_zero && min_adj.is_some_and(|m| m as i64 >= ifd_len - 2);
    let min_ok_b = min_adj.is_some_and(|m| m as i64 == ifd_len - 2 || m as i64 == ifd_len + 2);
    let max_ok = max_adj.is_some_and(|m| m as i64 <= input.dir_len as i64 - 2);
    (min_ok_a || min_ok_b) && max_ok
  };

  if entry_based_detected {
    // "looks like these offsets are entry-based" (`:1387-1390`).
    entry_based = true;
  } else {
    // `$diff = ($minPt - $dataPos) - $ifdEnd; $shift = 0` (`:1393-1394`).
    diff = (min_pt - data_pos) - ifd_end;
    shift = 0;
    // `$countOverlap and $et->Warn("Overlapping … values")` (`:1395`) — info.
    if entry_based {
      // "do NOT look entry-based" — undef both (`:1396-1400`).
      entry_based = false;
      relative = None;
    }
    let _ = count_overlap;
    // PrintIM absolute-offset special check (`:1401-1406`): `if ($tagPtr
    // {0xe00}) { my $ptr = $tagPtr{0xe00} - $dataPos; return 0 if $ptr > 0 and
    // $ptr <= length($$dataPt) - 8 and substr($$dataPt, $ptr, 8) eq
    // "PrintIM\0"; }`.
    if let Some(&pim) = tag_ptr.get(&0x0e00) {
      let ptr = i64::from(pim) - data_pos;
      let data_len = data.len() as i64;
      if ptr > 0 && ptr <= data_len - 8 {
        let ptr_us = ptr as usize;
        if data.get(ptr_us..ptr_us.saturating_add(8)) == Some(b"PrintIM\0") {
          return no_shift;
        }
      }
    }
    // "allow a range of reasonable differences for Unknown maker notes"
    // (`:1407-1410`): `if ($$dirInfo{FixBase} and $$dirInfo{FixBase} == 2) {
    // return 0 if $diff >=0 and $diff <= 24; }`.
    if input.dir_fix_base == Some(2) && (0..=24).contains(&diff) {
      return no_shift;
    }
  }

  // -----------------------------------------------------------------------
  // handle entry-based offsets (`:1415-1436`).
  // -----------------------------------------------------------------------
  let mut new_base = input.base;
  let mut new_data_pos = data_pos;
  let mut fix_base_dir_active = input.dir_fix_base.is_some();
  if entry_based {
    // `$makeDiff = 0; push @offsets, 4` (`:1422-1423`).
    make_diff = Some(0);
    offsets.push(4);
    // "corrected entry-based offsets are relative to start of first entry":
    // `my $expected = 12 * Get16u(…); $diff = $$valBlkAdj{MIN} - $expected`
    // (`:1425-1426`).
    let expected_eb = 12 * num_entries;
    diff = min_adj.map_or(0, |m| m as i64) - expected_eb;
    // "set base to start of first entry": `$shift = $dataPos + $dirStart + 2`
    // (`:1429`).
    shift = data_pos + dir_start as i64 + 2;
    new_base += shift; // `$$dirInfo{Base} += $shift` (`:1430`).
    new_data_pos -= shift; // `$$dirInfo{DataPos} -= $shift` (`:1431`).
    entry_based = true; // `$$dirInfo{EntryBased} = 1` (`:1432`).
    relative = Some(true); // `$$dirInfo{Relative} = 1` (`:1433`).
    fix_base_dir_active = false; // `delete $$dirInfo{FixBase}` (`:1434`).
  }

  // -----------------------------------------------------------------------
  // return without doing shift if offsets look OK (`:1437-1449`).
  // -----------------------------------------------------------------------
  if !set_base {
    // `return $shift unless defined $makeDiff` (`:1442`).
    let Some(_md) = make_diff else {
      return FixBaseResult {
        shift,
        new_base,
        new_data_pos,
        entry_based,
        relative,
        fixed_by: None,
      };
    };
    // `return $shift if $diff == 0 or $diff == 4` (`:1444`).
    if diff == 0 || diff == 4 {
      return FixBaseResult {
        shift,
        new_base,
        new_data_pos,
        entry_based,
        relative,
        fixed_by: None,
      };
    }
    // `foreach (@offsets) { return $shift if $diff == $_ }` (`:1446-1448`).
    if offsets.iter().any(|&o| i64::from(o) == diff) {
      return FixBaseResult {
        shift,
        new_base,
        new_data_pos,
        entry_based,
        relative,
        fixed_by: None,
      };
    }
  }

  // -----------------------------------------------------------------------
  // apply the fix, or issue a warning (`:1450-1483`).
  // -----------------------------------------------------------------------
  // `$makeDiff = 4 unless defined $makeDiff` (`:1454`).
  let make_diff_val = i64::from(make_diff.unwrap_or(4));
  // `$fix = $makeDiff - $diff` (`:1455`).
  let mut fix = make_diff_val - diff;
  let mut fixed_by: Option<i64> = None;

  if fix_base_dir_active {
    // `if ($dataPos - $fix + $dirStart <= 0) { $$dirInfo{Relative} = (defined
    // $relative) ? $relative : 1; }` (`:1458-1461`).
    if data_pos - fix + dir_start as i64 <= 0 {
      relative = Some(relative.unwrap_or(true));
    }
    if let Some(forced) = input.opt_fix_base {
      // `$fixedBy = $fixBase; $fix += $fixBase` (`:1463-1464`).
      fixed_by = Some(forced);
      fix += forced;
    }
  } else if let Some(forced) = input.opt_fix_base {
    // `} elsif (defined $fixBase) { $fix = $fixBase if $fixBase ne '';
    // $fixedBy = $fix; }` (`:1466-1468`).
    fix = forced;
    fixed_by = Some(fix);
  } else {
    // "print warning unless difference looks reasonable" (`:1470-1472`): `if
    // ($diff < 0 or $diff > 16 or ($diff & 0x01))` → Warn (informational).
    // "don't do the fix (but we already adjusted base if entry-based)" —
    // `return $shift` (`:1474-1475`).
    return FixBaseResult {
      shift,
      new_base,
      new_data_pos,
      entry_based,
      relative,
      fixed_by: None,
    };
  }

  // `if (defined $fixedBy) { $$dirInfo{FixedBy} = $fixedBy; }` (`:1477-1480`).
  // `$$dirInfo{Base} += $fix; $$dirInfo{DataPos} -= $fix; return $fix + $shift`
  // (`:1481-1483`).
  new_base += fix;
  new_data_pos -= fix;
  FixBaseResult {
    shift: fix + shift,
    new_base,
    new_data_pos,
    entry_based,
    relative,
    fixed_by,
  }
}

// ===========================================================================
// Feature 5 — LocateIFD (MakerNotes.pm:1486-1663) + ProcessUnknown
// (:1816-1837)
// ===========================================================================

/// `LocateIFD($et, $dirInfo)` (`MakerNotes.pm:1486-1663`) — scan unknown
/// maker-note data for the start of a plausible IFD, trying the parent order
/// first and TOGGLING when the entry count's low byte is zero. The bundled sub
/// "Changes byte ordering!" (`:1493`) and updates `DirStart`/`DirLen`/`Base`/
/// `DataPos`; this port returns the located IFD start + the resolved order
/// (the caller applies the dir/base updates).
///
/// Returns `Some((ifd_start /* relative to dir_start */, order))` on success,
/// or `None` (the caller warns `Unrecognized <dir>`, `ProcessUnknown` `:1834`).
///
/// This is the SIMPLIFIED scan arm only — the bundled sub also has a
/// TagInfo/SubDirectory `Start`/`Base`/`OffsetPt` pre-positioning block
/// (`:1514-1565`). That block needs the `$dirInfo{TagInfo}{SubDirectory}`
/// directives (Perl `eval` of `Start`/`Base`/`OffsetPt` expressions) which are
/// dispatched separately in this port; here `first_try == last_try == 0`'s
/// extension is folded by accepting the default `(0, 32)` scan window
/// (`:1506`). When a vendor needs the pre-positioning, the dispatcher supplies
/// the resolved start and this scan runs from there. The standard-IFD
/// plausibility checks (`:1599-1659`) are ported faithfully below.
///
/// `make`/`model` thread the Samsung/Sony/Apple/Canon model-specific patches
/// (`:1624-1639`). The TIFF-header arm (`:1576-1598`) is ported too.
#[must_use]
pub fn locate_ifd(
  data: &[u8],
  dir_start: usize,
  dir_len: Option<usize>,
  parent_order: ByteOrder,
  make: Option<&str>,
  model: Option<&str>,
) -> Option<(usize, ByteOrder)> {
  // `my $size = $$dirInfo{DataLen} - $dirStart` (`:1500`) — "ignore MakerNotes
  // DirLen since sometimes this is incorrect".
  let size = data.len().checked_sub(dir_start)?;
  // `my $dirLen = defined $$dirInfo{DirLen} ? $$dirInfo{DirLen} : $size`
  // (`:1501`).
  let dir_len = dir_len.unwrap_or(size);
  // "the IFD should be within the first 32 bytes" — `my ($firstTry, $lastTry) =
  // (0, 32)` (`:1506`). (The TagInfo pre-positioning that narrows these is
  // handled by the dispatcher in this port; see the fn doc.)
  let first_try = 0usize;
  let last_try = 32usize;

  // `if ($dirLen >= 14 + $firstTry)` — "minimum size for an IFD" (`:1570`).
  if dir_len < 14 + first_try {
    return None;
  }

  let mut offset = first_try;
  // `IFD_TRY: for ($offset=$firstTry; $offset<=$lastTry; $offset+=2)`
  // (`:1572`).
  while offset <= last_try {
    // `last if $offset + 14 > $dirLen` (`:1573`).
    if offset.checked_add(14).is_none_or(|e| e > dir_len) {
      break;
    }
    let Some(pos) = dir_start.checked_add(offset) else {
      break;
    };

    // -------------------------------------------------------------------
    // standard TIFF header arm (`:1576-1598`).
    // -------------------------------------------------------------------
    // `if (SetByteOrder(substr($$dataPt,$pos,2)) and Get16u($dataPt,$pos+2) ==
    // 0x2a) { $ifdOffsetPos = 4; }` (`:1578-1582`). FAITHFUL SUBTLETY:
    // `SetByteOrder` is the FIRST `and` operand and runs UNCONDITIONALLY — for
    // an `II`/`MM` marker it SUCCEEDS and MUTATES the global order BEFORE the
    // `Get16u == 0x2a` short-circuits. So even when the `0x2a` check fails, the
    // order is left as the marker's, and the standard-IFD arm below reads its
    // entry count in THAT order. We mirror that by updating `order` whenever the
    // marker parses, but gating `ifd_offset_pos` on the full TIFF magic.
    let mut order = parent_order;
    let mut ifd_offset_pos: Option<usize> = None;
    if let Some(marker_order) = data
      .get(pos..pos.checked_add(2)?)
      .and_then(ByteOrder::from_marker)
    {
      order = marker_order; // `SetByteOrder` side effect (`:1578`).
      if get_u16(data, pos.checked_add(2)?, marker_order) == Some(0x2a) {
        ifd_offset_pos = Some(4);
      }
    }
    if let Some(iop) = ifd_offset_pos {
      // `my $ptr = Get32u($dataPt, $pos + $ifdOffsetPos)` (`:1585`).
      if let Some(ptr) = pos.checked_add(iop).and_then(|p| get_u32(data, p, order)) {
        let ptr = ptr as usize;
        // `if ($ptr >= $ifdOffsetPos + 4 and $ptr + $offset + 14 <= $dirLen)`
        // (`:1586`).
        let in_range = ptr >= iop + 4
          && ptr
            .checked_add(offset)
            .and_then(|s| s.checked_add(14))
            .is_some_and(|end| end <= dir_len);
        if in_range {
          // `return $ptr + $offset` (`:1595`) — relative to `dir_start`; the
          // TIFF-header base shift + `Relative` flag are applied by the caller.
          return Some((ptr + offset, order));
        }
      }
      // `undef $ifdOffsetPos` (`:1597`) — fall through to the standard-IFD arm
      // (which re-derives the order from the raw entry count).
    }

    // -------------------------------------------------------------------
    // standard IFD arm — starts with a 2-byte entry count (`:1599-1659`).
    // `order` is the live `GetByteOrder()` here: it carries the TIFF arm's
    // `SetByteOrder` side effect (the marker order when `$pos` held `II`/`MM`),
    // else the parent order. The `ToggleByteOrder` below mutates it further.
    // -------------------------------------------------------------------
    // `my $num = Get16u($dataPt, $pos); next unless $num` (`:1602-1603`).
    let Some(mut num) = get_u16(data, pos, order) else {
      offset += 2;
      continue;
    };
    if num == 0 {
      offset += 2;
      continue;
    }
    // `if (!($num & 0xff)) { ToggleByteOrder(); $num >>= 8; }` (`:1605-1608`).
    if (num & 0xff) == 0 {
      order = opposite_order(order);
      num >>= 8;
    } else if (num & 0xff00) != 0 {
      // "upper byte isn't zero -- not an IFD" — `next` (`:1609-1611`).
      offset += 2;
      continue;
    }
    let num = usize::from(num);
    // `my $bytesFromEnd = $size - ($offset + 2 + 12 * $num)` (`:1613`). Use i64
    // so a count past the end goes negative (Perl arithmetic), not a wrap.
    let bytes_from_end = size as i64 - (offset as i64 + 2 + 12 * num as i64);
    // `if ($bytesFromEnd < 4) { next unless $bytesFromEnd == 2 or == 0; }`
    // (`:1614-1616`).
    if bytes_from_end < 4 && !(bytes_from_end == 2 || bytes_from_end == 0) {
      offset += 2;
      continue;
    }
    // "do a quick validation of all format types" (`:1617-1656`).
    if !validate_ifd_entries(data, pos, num, size, order, make, model) {
      offset += 2;
      continue;
    }
    // `$$dirInfo{DirStart} += $offset; $$dirInfo{DirLen} -= $offset; return
    // $offset` (`:1657-1659`).
    return Some((offset, order));
  }
  // `return undef` (`:1662`).
  None
}

/// The per-entry format/count/offset plausibility loop inside `LocateIFD`'s
/// standard-IFD arm (`MakerNotes.pm:1617-1656`). Returns `false` to `next
/// IFD_TRY` (try the next `$offset`) — i.e. this candidate IFD is rejected.
///
/// `model`/`make` thread the documented per-camera patches: the Samsung NX200
/// 23-entry quirk (`:1624-1629` — the port DETECTS it but cannot mutate the
/// buffer; it accepts the candidate as the Perl does after `Set16u`), the
/// Canon EOS 40D zero-format last entry (`:1633-1634`), the Sony DSC-P10
/// 12-entry quirk (`:1636-1637`), and the Apple ProRaw format-16 entries
/// (`:1638-1639`).
#[allow(clippy::too_many_arguments)]
fn validate_ifd_entries(
  data: &[u8],
  pos: usize,
  num: usize,
  size: usize,
  order: ByteOrder,
  make: Option<&str>,
  model: Option<&str>,
) -> bool {
  for index in 0..num {
    // `my $entry = $pos + 2 + 12 * $index` (`:1620`).
    let Some(entry) = pos
      .checked_add(2)
      .and_then(|p| p.checked_add(12usize.checked_mul(index)?))
    else {
      return false;
    };
    // `my $format = Get16u($dataPt, $entry+2)` (`:1621`).
    let format = entry
      .checked_add(2)
      .and_then(|p| get_u16(data, p, order))
      .unwrap_or(0);
    // `my $count = Get32u($dataPt, $entry+4)` (`:1622`).
    let count = entry
      .checked_add(4)
      .and_then(|p| get_u32(data, p, order))
      .unwrap_or(0);
    if format == 0 {
      // Samsung NX200 23-entry patch (`:1624-1629`): really 21 entries. The
      // Perl mutates the buffer (`Set16u(21,…)`) + `last`s; this read-only port
      // accepts the candidate (stops validating) — the equivalent observable
      // outcome (the IFD is accepted) without mutating the borrowed slice.
      if num == 23 && index == 21 && make == Some("SAMSUNG") {
        break;
      }
      // "allow everything to be zero if not first entry" — `next unless $count
      // or $index == 0` (`:1630-1632`). A zero-format, zero-count, non-first
      // entry is padding ⇒ skip it. (When count != 0 OR index == 0 we fall
      // through: a first/with-count zero-format entry reaches the reject below,
      // except for the EOS-40D last-entry allowance.)
      if count == 0 && index != 0 {
        continue;
      }
      // Canon EOS 40D firmware 1.0.4: zero format allowed for the LAST entry —
      // `next if $index==$num-1 and $$et{Model}=~/EOS 40D/` (`:1633-1634`).
      if index == num - 1 && model.is_some_and(|m| m.contains("EOS 40D")) {
        continue;
      }
    }
    // Sony DSC-P10 invalid-entry patch — `next if $num == 12 and $$et{Make} eq
    // 'SONY' and $index >= 8` (`:1636-1637`).
    if num == 12 && make == Some("SONY") && index >= 8 {
      continue;
    }
    // Apple ProRaw DNG format-16 patch — `next if $format == 16 and $$et{Make}
    // eq 'Apple'` (`:1638-1639`).
    if format == 16 && make == Some("Apple") {
      continue;
    }
    // "verify format" — `next IFD_TRY if $format < 1 or $format > 13`
    // (`:1644`).
    if !matches!(format, 1..=13) {
      return false;
    }
    // "count must be reasonable" — `next IFD_TRY if $count & 0xff000000`
    // (`:1647`).
    if count & 0xff00_0000 != 0 {
      return false;
    }
    // "extra tests to avoid mis-identifying Samsung makernotes" — `next unless
    // $num == 1` (`:1649`). For `$num != 1` the per-entry value-size check
    // below is SKIPPED (the `next` continues the entry loop).
    if num != 1 {
      continue;
    }
    // `my $valueSize = $count * formatSize[$format]` (`:1650`); the gate above
    // guarantees `format ∈ 1..=13`.
    let value_size = u64::from(count).saturating_mul(Format::from_code(format).byte_size() as u64);
    if value_size > 4 {
      // `next IFD_TRY if $valueSize > $size` (`:1652`).
      if value_size > size as u64 {
        return false;
      }
      // `my $valuePtr = Get32u($dataPt, $entry+8); next IFD_TRY if $valuePtr >
      // 0x10000` (`:1653-1654`).
      let value_ptr = entry
        .checked_add(8)
        .and_then(|p| get_u32(data, p, order))
        .unwrap_or(0);
      if value_ptr > 0x1_0000 {
        return false;
      }
    }
  }
  true
}

#[cfg(test)]
mod tests;
