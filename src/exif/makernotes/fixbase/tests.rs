// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Oracle tests for the shared maker-note engine. Every expected value is
//! HAND-DERIVED from the cited `MakerNotes.pm` / `Exif.pm` line (the bundled
//! subs are internal, so a live perl-oracle harness is impractical; the
//! fixture-less-port convention applies — see the module docs).

use super::*;

// ===========================================================================
// Feature 1 — detect_unknown_byte_order (Exif.pm:6982-6993)
// ===========================================================================

/// A sane LE entry count keeps the parent order. `num = 0x0003` read LE = 3.
/// `0x0003 & 0xff00 == 0` ⇒ the toggle test is false (`:6987`) ⇒ keep parent
/// (`:6992`).
#[test]
fn unknown_order_sane_le_count_keeps_parent() {
  let data = [0x03u8, 0x00]; // LE 3
  assert_eq!(
    detect_unknown_byte_order(&data, 0, ByteOrder::Little),
    Some(ByteOrder::Little)
  );
}

/// A byte-swapped count toggles. Bytes `00 03` read as parent-LE = 0x0300 =
/// 768. `0x0300 & 0xff00 != 0` AND `(0x0300>>8)=3 > (0x0300&0xff)=0` ⇒ "too
/// many entries" ⇒ TOGGLE to Big (`:6987-6990`). (Read as Big it would be 3 —
/// the plausible value — confirming the order was wrong.)
#[test]
fn unknown_order_byteswapped_count_toggles() {
  let data = [0x00u8, 0x03]; // parent-LE reads 0x0300
  assert_eq!(
    detect_unknown_byte_order(&data, 0, ByteOrder::Little),
    Some(ByteOrder::Big)
  );
}

/// Mirror case: a Big parent that reads an implausible count toggles to Little.
/// Bytes `03 00` read as parent-BE = 0x0300 = 768 ⇒ toggle to Little.
#[test]
fn unknown_order_byteswapped_count_toggles_be_parent() {
  let data = [0x03u8, 0x00]; // parent-BE reads 0x0300
  assert_eq!(
    detect_unknown_byte_order(&data, 0, ByteOrder::Big),
    Some(ByteOrder::Little)
  );
}

/// `num>>8 == num&0xff` does NOT toggle — the test is strict `>` (`:6987`).
/// `0x0303` (high == low byte) keeps parent even though the high byte is set.
#[test]
fn unknown_order_equal_bytes_keeps_parent() {
  let data = [0x03u8, 0x03]; // LE 0x0303
  assert_eq!(
    detect_unknown_byte_order(&data, 0, ByteOrder::Little),
    Some(ByteOrder::Little)
  );
}

/// Fewer than 2 bytes at `dir_start` ⇒ `None` — the `$subdirStart + 2 <=
/// $subdirDataLen` guard (`:6982`) leaves the order unresolved.
#[test]
fn unknown_order_too_short_is_none() {
  assert_eq!(
    detect_unknown_byte_order(&[0x03], 0, ByteOrder::Little),
    None
  );
  assert_eq!(detect_unknown_byte_order(&[], 0, ByteOrder::Big), None);
  // Also when dir_start pushes the read past the end.
  assert_eq!(
    detect_unknown_byte_order(&[0x03, 0x00], 1, ByteOrder::Little),
    None
  );
}

// ===========================================================================
// Feature 2 — get_maker_note_offset (MakerNotes.pm:1149-1231)
// ===========================================================================

/// Canon 20D ⇒ first offset 6 (`:1161`); a non-listed Canon ⇒ 4.
#[test]
fn canon_offsets() {
  let o = get_maker_note_offset("Canon", "Canon EOS 20D", None, None);
  assert_eq!(o.offsets(), &[6]);
  assert_eq!(o.make_diff(), Some(6));
  assert_eq!(o.relative(), None);

  let o = get_maker_note_offset("Canon", "Canon EOS 5D", None, None);
  assert_eq!(o.offsets(), &[4]);

  // PowerShot adds 16 (plain substring, `:1166`); OPTURA adds 28 (`:1164`).
  let o = get_maker_note_offset("Canon", "Canon PowerShot S30", None, None);
  assert_eq!(o.offsets(), &[4, 16]);
  let o = get_maker_note_offset("Canon", "Canon OPTURA60", None, None);
  assert_eq!(o.offsets(), &[4, 28]);
  // FV<boundary> adds 28 too (`FV\b`): "FV" then non-word.
  let o = get_maker_note_offset("Canon", "Canon FV M30", None, None);
  assert_eq!(o.offsets(), &[4, 28]);
}

/// PENTAX ⇒ offset 4 AND forces ABSOLUTE addressing (`relative = 0`, `:1215-
/// 1220`).
#[test]
fn pentax_forces_absolute() {
  let o = get_maker_note_offset("PENTAX Corporation", "PENTAX *ist DS", None, None);
  assert_eq!(o.offsets(), &[4]);
  assert_eq!(o.relative(), Some(false));
}

/// SONY DSLR ⇒ 4 (`:1200-1203`); a non-DSLR/SLT/NEX Sony ⇒ 0 (`:1205`).
#[test]
fn sony_offsets() {
  let o = get_maker_note_offset("SONY", "DSLR-A100", None, None);
  assert_eq!(o.offsets(), &[4]);
  let o = get_maker_note_offset("SONY", "SLT-A55V", None, None);
  assert_eq!(o.offsets(), &[4]);
  let o = get_maker_note_offset("SONY", "NEX-5", None, None);
  assert_eq!(o.offsets(), &[4]);
  let o = get_maker_note_offset("SONY", "DSC-RX100", None, None);
  assert_eq!(o.offsets(), &[0]);
}

/// FUJIFILM ⇒ `4, 6` (`:1209-1211`).
#[test]
fn fujifilm_offsets() {
  let o = get_maker_note_offset("FUJIFILM", "FinePix A345", None, None);
  assert_eq!(o.offsets(), &[4, 6]);
  assert_eq!(o.make_diff(), Some(4));
}

/// The "just weird" Olympus models get NO expected offset ⇒ empty list,
/// `make_diff() == None` (`:1191-1194`), so `FixBase` resolves empirically.
#[test]
fn weird_olympus_has_no_offset() {
  let o = get_maker_note_offset("OLYMPUS IMAGING CORP.", "C2500L", None, None);
  assert!(o.offsets().is_empty());
  assert_eq!(o.make_diff(), None);
  // C-1Z? matches both C-1 and C-1Z.
  assert!(
    get_maker_note_offset("OLYMPUS", "C-1", None, None)
      .offsets()
      .is_empty()
  );
  assert!(
    get_maker_note_offset("OLYMPUS", "C-1Z", None, None)
      .offsets()
      .is_empty()
  );
  // But a normal Olympus E-1 uses offset 16 (`:1189`), NOT the weird list.
  let e1 = get_maker_note_offset("OLYMPUS", "E-1", None, None);
  assert_eq!(e1.offsets(), &[16]);
}

/// CASIO RIFF/MOV ⇒ 0; CASIO JPEG ⇒ `4, 16, 2` (`:1171`).
#[test]
fn casio_offsets_depend_on_file_type() {
  assert_eq!(
    get_maker_note_offset("CASIO", "EX-Z70", Some("MOV"), None).offsets(),
    &[0]
  );
  assert_eq!(
    get_maker_note_offset("CASIO", "EX-Z70", Some("JPEG"), None).offsets(),
    &[4, 16, 2]
  );
}

/// Konica Minolta (CI prefix) ⇒ `4, -16` (`:1221-1223`); plain Minolta ⇒
/// `4, -8, -12` (`:1224-1226`); unknown make ⇒ `4` (`:1228`).
#[test]
fn minolta_and_default() {
  assert_eq!(
    get_maker_note_offset("KONICA MINOLTA", "DiMAGE X50", None, None).offsets(),
    &[4, -16]
  );
  assert_eq!(
    get_maker_note_offset("Minolta Co., Ltd.", "DiMAGE 7", None, None).offsets(),
    &[4, -8, -12]
  );
  assert_eq!(
    get_maker_note_offset("Acme", "Widget", None, None).offsets(),
    &[4]
  );
}

// ===========================================================================
// Feature 3 — get_value_blocks (MakerNotes.pm:1241-1275)
// ===========================================================================

/// Helper: write a single 12-byte IFD entry into `buf` at `off`.
fn put_entry(buf: &mut [u8], off: usize, tag: u16, format: u16, count: u32, val: u32) {
  buf[off..off + 2].copy_from_slice(&tag.to_le_bytes());
  buf[off + 2..off + 4].copy_from_slice(&format.to_le_bytes());
  buf[off + 4..off + 8].copy_from_slice(&count.to_le_bytes());
  buf[off + 8..off + 12].copy_from_slice(&val.to_le_bytes());
}

/// A crafted IFD with three entries — two out-of-line (size > 4), one inline
/// (size == 4, skipped per `:1252`). The block map records only the out-of-line
/// pointers → sizes; the adjusted map adds `12*index` (`:1260`).
#[test]
fn value_blocks_two_out_of_line() {
  // 3 entries: index0 ASCII×8 (size 8) @ 100; index1 INT32U×1 (size 4, inline,
  // skipped); index2 INT16U×10 (size 20) @ 200.
  let mut buf = vec![0u8; 256];
  buf[0..2].copy_from_slice(&3u16.to_le_bytes()); // numEntries = 3
  put_entry(&mut buf, 2, 0x0001, 2, 8, 100); // size 8  > 4 → recorded
  put_entry(&mut buf, 14, 0x0002, 4, 1, 999); // size 4 == 4 → skipped (:1252)
  put_entry(&mut buf, 26, 0x0003, 3, 10, 200); // size 20 > 4 → recorded

  let (vb, tag_ptr) = get_value_blocks(&buf, 0, ByteOrder::Little);

  // val_block: {100: 8, 200: 20}. The inline entry contributes nothing.
  assert_eq!(vb.val_block().get(&100), Some(&8));
  assert_eq!(vb.val_block().get(&200), Some(&20));
  assert_eq!(vb.val_block().len(), 2);

  // val_blk_adj: index0 → 100+0 = 100 (size 8); index2 → 200+24 = 224 (size 20).
  assert_eq!(vb.val_blk_adj().get(&100), Some(&8));
  assert_eq!(vb.val_blk_adj().get(&224), Some(&20));

  // MIN = 100 (first ≥ 12, never raised since 100 < 224). MAX is an ExifTool
  // QUIRK (`:1263-1270`): it is SEEDED by the FIRST out-of-line block's end
  // (`100 + 8 = 108`) and thereafter only ever LOWERED (`$valBlkAdj{MAX} = $end
  // if $valBlkAdj{MAX} > $end`) — it is NOT a running maximum. index2's end
  // (244) is larger, so `108 > 244` is false ⇒ MAX stays 108. The port
  // reproduces this faithfully.
  assert_eq!(vb.min_adj(), Some(100));
  assert_eq!(vb.max_adj(), Some(108));

  // tag_ptr records tag → raw valPtr ONLY for OUT-OF-LINE entries: the `next
  // if $size <= 4` (`:1252`) skips the inline entry BEFORE the `$$tagPtr{…} =
  // $valPtr` assignment (`:1254`), so the inline tag 0x0002 is absent.
  assert_eq!(tag_ptr.get(&0x0001), Some(&100));
  assert_eq!(tag_ptr.get(&0x0002), None);
  assert_eq!(tag_ptr.get(&0x0003), Some(&200));

  assert!(!vb.is_empty());
}

/// `last if $format < 1 or $format > 13` (`:1249`) — a BigTIFF code (16)
/// TERMINATES the walk; later entries are NOT recorded even if out-of-line.
#[test]
fn value_blocks_stops_at_out_of_range_format() {
  let mut buf = vec![0u8; 64];
  buf[0..2].copy_from_slice(&2u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 16, 4, 40); // format 16 (>13) → `last`
  put_entry(&mut buf, 14, 0x0002, 2, 8, 50); // never reached
  let (vb, _tp) = get_value_blocks(&buf, 0, ByteOrder::Little);
  assert!(vb.is_empty());
}

/// No entries / all inline ⇒ empty block map (the `return 0 unless %$valBlock`
/// guard, `:1300`).
#[test]
fn value_blocks_all_inline_is_empty() {
  let mut buf = vec![0u8; 32];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 4, 1, 7); // size 4 → skipped
  let (vb, _tp) = get_value_blocks(&buf, 0, ByteOrder::Little);
  assert!(vb.is_empty());
}

// ===========================================================================
// Feature 4 — fix_base (MakerNotes.pm:1282-1484)
// ===========================================================================

/// (a) Absolute offsets that land exactly 4 bytes past the IFD ⇒ shift 0.
///
/// One ASCII×8 entry whose value sits at offset 18. `ifdLen = 2 + 12 = 14`,
/// `ifdEnd = 14`. `diff = (minPt 18 - dataPos 0) - ifdEnd 14 = 4` ⇒ the `return
/// $shift if $diff == 0 or $diff == 4` early-out (`:1444`) returns shift 0 with
/// NO base mutation.
#[test]
fn fix_base_absolute_offsets_shift_zero() {
  let mut buf = vec![0u8; 26];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes()); // 1 entry
  put_entry(&mut buf, 2, 0x0001, 2, 8, 18); // ASCII×8 @ 18 (4 past IFD end)
  // bytes 14..18 = next-IFD ptr (0); 18..26 = the 8 value bytes.

  let input = FixBaseInput::new(&buf, 0, 26, 0, 0, ByteOrder::Little, "TestCam", "Model");
  let r = fix_base(&input);
  assert_eq!(r.shift(), 0);
  assert_eq!(r.new_base(), 0);
  assert_eq!(r.new_data_pos(), 0);
  assert!(!r.entry_based());
  assert_eq!(r.relative(), None);
  assert_eq!(r.fixed_by(), None);
}

/// (b) An entry-based layout ⇒ nonzero shift + `entry_based = true` +
/// `relative = Some(true)`.
///
/// Two ASCII×8 entries. `ifdLen = 2 + 24 = 26`, `ifdLen-2 = 24`. Stored
/// valPtrs: entry0 → 24, entry1 → 12. Adjusted (`+12*index`): adj0 = 24,
/// adj1 = 12+12 = 24 ⇒ `valBlkAdj{MIN} == 24 == ifdLen-2` ⇒ the second
/// entry-based-detection arm fires (`:1384`); `valBlkAdj{MAX} = 32 <= dirLen-2
/// = 32` (`:1385`). Entry arm (`:1418-1436`): `shift = dataPos 0 + dirStart 0 +
/// 2 = 2`; `expected = 12*2 = 24`; `diff = MIN 24 - 24 = 0`; base += 2,
/// dataPos -= 2, Relative = 1. Then `diff == 0` early-out (`:1444`) returns
/// `shift = 2`.
#[test]
fn fix_base_entry_based_layout() {
  let mut buf = vec![0u8; 40]; // dirLen = 34 ⇒ MAX 32 <= 32 ✓
  buf[0..2].copy_from_slice(&2u16.to_le_bytes()); // 2 entries
  put_entry(&mut buf, 2, 0x0001, 2, 8, 24); // entry0 valPtr = 24
  put_entry(&mut buf, 14, 0x0002, 2, 8, 12); // entry1 valPtr = 12

  let input = FixBaseInput::new(&buf, 0, 34, 0, 0, ByteOrder::Little, "TestCam", "Model");
  let r = fix_base(&input);
  assert_eq!(r.shift(), 2);
  assert_eq!(r.new_base(), 2); // base 0 + shift 2
  assert_eq!(r.new_data_pos(), -2); // dataPos 0 - shift 2
  assert!(r.entry_based());
  assert_eq!(r.relative(), Some(true));
}

/// (c) Canon TIFF-footer case (`:1304-1338`). A `II\x2a\0` footer whose
/// recorded `oldOffset = 1000` against `newOffset = dirStart 0 + dataPos 1100`
/// gives `fix = newOffset - oldOffset = 100` (`:1317`). The Picasa end-diff
/// guard (`:1322-1330`) computes `endDiff = 0 + 30 - (22 - 1100) - 8 = 1100`
/// (≠ 0,1) so the fix proceeds: base += 100, dataPos -= 100, FixedBy = 100,
/// return 100.
#[test]
fn fix_base_canon_footer() {
  // 1 entry (ASCII×8 @ 14), then 8 value bytes (14..22), then 8-byte footer.
  let mut buf = vec![0u8; 30];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 2, 8, 14); // value @ 14, size 8 → maxPt = 22
  // footer @ 22..30: "II\x2a\0" + oldOffset(4) = 1000.
  buf[22..26].copy_from_slice(b"II\x2a\x00");
  buf[26..30].copy_from_slice(&1000u32.to_le_bytes());

  let input = FixBaseInput::new(
    &buf,
    0,
    30,
    1100,
    0,
    ByteOrder::Little,
    "Canon",
    "Canon EOS 5D",
  );
  let r = fix_base(&input);
  assert_eq!(r.shift(), 100);
  assert_eq!(r.new_base(), 100); // base 0 + 100
  assert_eq!(r.new_data_pos(), 1000); // dataPos 1100 - 100
  assert_eq!(r.fixed_by(), Some(100));
  assert!(!r.entry_based());
}

/// The Canon footer's "no shift" early-out: when `fix == newOffset - oldOffset
/// == 0` the sub `return 0 unless $fix` (`:1318`). With `dataPos == oldOffset`,
/// newOffset == oldOffset ⇒ fix 0 ⇒ no mutation.
#[test]
fn fix_base_canon_footer_zero_fix_returns_zero() {
  let mut buf = vec![0u8; 30];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 2, 8, 14);
  buf[22..26].copy_from_slice(b"II\x2a\x00");
  buf[26..30].copy_from_slice(&1000u32.to_le_bytes());
  // dataPos == oldOffset (1000) ⇒ newOffset == oldOffset ⇒ fix 0.
  let input = FixBaseInput::new(
    &buf,
    0,
    30,
    1000,
    0,
    ByteOrder::Little,
    "Canon",
    "Canon EOS 5D",
  );
  let r = fix_base(&input);
  assert_eq!(r.shift(), 0);
  assert_eq!(r.new_base(), 0);
  assert_eq!(r.fixed_by(), None);
}

/// `FixOffsets` / `NoFixBase` short-circuit to 0 before any analysis
/// (`:1286-1287`).
#[test]
fn fix_base_early_returns() {
  let mut buf = vec![0u8; 26];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 2, 8, 18);
  let base = FixBaseInput::new(&buf, 0, 26, 0, 0, ByteOrder::Little, "TestCam", "Model");

  let r = fix_base(&base.clone().with_early_returns(true, false));
  assert_eq!(r.shift(), 0);
  let r = fix_base(&base.with_early_returns(false, true));
  assert_eq!(r.shift(), 0);
}

/// Empty value-block map ⇒ `return 0 unless %$valBlock` (`:1300`). An IFD with
/// only inline values produces no blocks.
#[test]
fn fix_base_no_value_blocks_returns_zero() {
  let mut buf = vec![0u8; 20];
  buf[0..2].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 2, 0x0001, 4, 1, 7); // INT32U×1, inline (size 4)
  let input = FixBaseInput::new(&buf, 0, 20, 0, 0, ByteOrder::Little, "TestCam", "Model");
  assert_eq!(fix_base(&input).shift(), 0);
}

// ===========================================================================
// Feature 5 — locate_ifd (MakerNotes.pm:1486-1663)
// ===========================================================================

/// A garbage-prefixed body: a valid 1-entry IFD begins after a 4-byte
/// non-IFD prefix. The scan steps `+2` and finds the IFD at offset 4 with the
/// parent order. (`num == 1` so the per-entry value-size check at `:1649-1655`
/// runs; the single ASCII×4 inline entry passes.)
#[test]
fn locate_ifd_found_after_prefix() {
  // offset 0..4: garbage that does NOT look like an IFD count/TIFF magic.
  // offset 4: IFD count = 1; entry @ 6: ASCII×4 (inline). bytesFromEnd check:
  // size = len - dirStart. We make the IFD self-terminate cleanly.
  let mut buf = vec![0u8; 64];
  // Prefix: 0xFFFF count would be "upper byte nonzero → not IFD" at offset 0,
  // and the high byte set keeps it from matching; also not II/MM.
  buf[0..2].copy_from_slice(&0x0707u16.to_le_bytes()); // not an IFD (high byte set)
  buf[2..4].copy_from_slice(&0x0707u16.to_le_bytes());
  // IFD at offset 4:
  buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // numEntries = 1
  put_entry(&mut buf, 6, 0x0100, 2, 4, 0); // ASCII×4 inline

  let got = locate_ifd(&buf, 0, Some(64), ByteOrder::Little, None, None);
  assert_eq!(got, Some((4, ByteOrder::Little)));
}

/// `locate_ifd` returns the located IFD offset RELATIVE to the `dir_start` it is
/// handed — NOT an absolute offset into the buffer. Here the scan begins at
/// `dir_start == 8` (a maker note whose blob starts 8 bytes into the TIFF) and
/// the IFD sits 4 bytes past that (absolute 12), so the return is the RELATIVE
/// `4`. `process_subdir` adds `dir_start` back to recover the absolute position;
/// a non-zero blob offset must not be dropped. (Codex R1 finding 2.)
#[test]
fn locate_ifd_returns_relative_to_nonzero_dir_start() {
  let mut buf = vec![0u8; 80];
  // bytes 0..8: leading TIFF content before the maker-note blob (dir_start == 8).
  // bytes 8..12: a 4-byte non-IFD prefix inside the blob; IFD at absolute 12.
  buf[8..10].copy_from_slice(&0x0707u16.to_le_bytes()); // not an IFD (high byte set)
  buf[10..12].copy_from_slice(&0x0707u16.to_le_bytes());
  buf[12..14].copy_from_slice(&1u16.to_le_bytes()); // numEntries = 1
  put_entry(&mut buf, 14, 0x0100, 2, 4, 0); // ASCII×4 inline
  // dir_len is measured from dir_start: 80 - 8 = 72.
  let got = locate_ifd(&buf, 8, Some(72), ByteOrder::Little, None, None);
  assert_eq!(
    got,
    Some((4, ByteOrder::Little)),
    "the offset is RELATIVE to dir_start=8 (the IFD is at absolute 12)"
  );
}

/// A standard TIFF header inside the body (`II\x2a\0` + IFD pointer) is located
/// via the TIFF-header arm (`:1576-1598`): the returned start is `ptr + offset`
/// and the order comes from the magic.
#[test]
fn locate_ifd_tiff_header() {
  let mut buf = vec![0u8; 64];
  // TIFF header at offset 0: "II", 0x002a, then 4-byte IFD pointer = 8.
  buf[0..2].copy_from_slice(b"II");
  buf[2..4].copy_from_slice(&0x002au16.to_le_bytes());
  buf[4..8].copy_from_slice(&8u32.to_le_bytes()); // IFD pointer = 8
  // IFD at offset 8: 1 entry.
  buf[8..10].copy_from_slice(&1u16.to_le_bytes());
  put_entry(&mut buf, 10, 0x0100, 2, 4, 0);

  // ptr 8 >= ifdOffsetPos(4)+4 = 8 ✓; ptr + offset 0 + 14 = 22 <= dirLen ✓ ⇒
  // returns ptr + offset = 8 (`:1595`).
  let got = locate_ifd(&buf, 0, Some(64), ByteOrder::Big, None, None);
  assert_eq!(got, Some((8, ByteOrder::Little))); // order from the "II" magic
}

/// The byte-order TOGGLE arm (`:1605-1608`): an IFD whose count's LOW byte is
/// zero (read in the parent order) is re-read in the toggled order. Count bytes
/// `00 01` read parent-LE = 0x0100 (low byte 0) ⇒ toggle to Big ⇒ count = 1.
#[test]
fn locate_ifd_toggles_byte_order() {
  let mut buf = vec![0u8; 32];
  // IFD at offset 0, count = 0x0100 in LE bytes (`00 01`): low byte 0 → toggle.
  buf[0..2].copy_from_slice(&[0x00, 0x01]);
  // After toggling to Big, count = 1. Entry @ 2 must validate in BIG order.
  buf[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // tag
  buf[4..6].copy_from_slice(&2u16.to_be_bytes()); // format ASCII
  buf[6..10].copy_from_slice(&4u32.to_be_bytes()); // count 4 (inline)
  buf[10..14].copy_from_slice(&0u32.to_be_bytes()); // value/offset

  let got = locate_ifd(&buf, 0, Some(32), ByteOrder::Little, None, None);
  assert_eq!(got, Some((0, ByteOrder::Big)));
}

/// Pure garbage ⇒ `None` (`:1662`) — no offset in `0..=32` yields a plausible
/// IFD. (Every 2-byte window's entry count fails the format/count validation
/// or the upper-byte-nonzero gate.)
#[test]
fn locate_ifd_garbage_is_none() {
  // 0xFF filler: every entry-count window has its upper byte set → "not an IFD"
  // (`:1609-1611`); the TIFF-magic arm fails (no II/MM). Result: None.
  let buf = vec![0xFFu8; 48];
  assert_eq!(
    locate_ifd(&buf, 0, Some(48), ByteOrder::Little, None, None),
    None
  );
}

/// Too small to hold an IFD (`dirLen < 14`) ⇒ `None` (`:1570`).
#[test]
fn locate_ifd_too_small_is_none() {
  let buf = vec![0u8; 10];
  assert_eq!(
    locate_ifd(&buf, 0, Some(10), ByteOrder::Little, None, None),
    None
  );
}
