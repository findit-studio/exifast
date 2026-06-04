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
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use std::vec::Vec;

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
  let num_entries = read_u16(tiff_data, mn_offset, order).unwrap_or(0) as usize;
  if num_entries == 0 || num_entries > 1024 {
    return out;
  }
  let entries_start = mn_offset + 2;
  let dir_end = entries_start.saturating_add(12usize.saturating_mul(num_entries));
  let mn_end = mn_offset + mn_len;
  if dir_end > mn_end.min(tiff_data.len()) {
    return out;
  }
  for i in 0..num_entries {
    let entry_off = entries_start + 12 * i;
    let Some(tag_id) = read_u16(tiff_data, entry_off, order) else {
      continue;
    };
    let Some(format_code) = read_u16(tiff_data, entry_off + 2, order) else {
      continue;
    };
    let Some(count) = read_u32(tiff_data, entry_off + 4, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(format_code);
    let elem_size = format.byte_size();
    if elem_size == 0 {
      continue;
    }
    let total_size = elem_size.saturating_mul(count);
    // Inline if total ≤ 4 bytes — value sits at entry_off+8 (still
    // within tiff_data; we read directly from there).
    let value_data_offset = if total_size <= 4 {
      entry_off + 8
    } else {
      // Out-of-line: offset is RELATIVE to the TIFF block start.
      let Some(off) = read_u32(tiff_data, entry_off + 8, order) else {
        continue;
      };
      let abs_off = off as usize;
      if abs_off >= tiff_data.len() {
        continue;
      }
      if abs_off.saturating_add(total_size) > tiff_data.len() {
        continue;
      }
      abs_off
    };
    let avail = tiff_data.len() - value_data_offset;
    let Some(mut raw) = read_value(tiff_data, value_data_offset, format, count, avail, order)
    else {
      continue;
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

  /// Implausible entry count → return early.
  #[test]
  fn implausible_count_short_circuits() {
    let mut blob: Vec<u8> = Vec::new();
    // 9999 entries (huge) in 4 bytes of data — implausible.
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 LE
    assert!(walk_canon_body(&blob, ByteOrder::Little, None).is_empty());
  }
}
