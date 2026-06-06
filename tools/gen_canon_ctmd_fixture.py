#!/usr/bin/env python3
"""Build the crafted Canon `CTMD` (Canon Timed MetaData) timed-metadata `.mov` fixture.

exifast has no real Canon EOS R-line / Cinema-line CR3/CRM clip in
`tests/fixtures/` carrying a `CTMD` track; this script emits a *minimal* but
bundled-ExifTool-decodable `.mov` carrying a `CTMD` MetaFormat track so the
Canon timed-metadata `-ee` oracle goldens have a real on-disk input.

  python3 tools/gen_canon_ctmd_fixture.py            # -> tests/fixtures/QuickTime_canon_ctmd.mov
  python3 tools/gen_canon_ctmd_fixture.py <outdir>

CTMD byte layout (mirrored from `%Image::ExifTool::Canon::CTMD` +
`sub ProcessCTMD`, Canon.pm:9790-9887 / 10758-10804). The `CTMD` MetaFormat
dispatches through `QuickTime::Stream`'s `CTMD` SubDirectory → `Canon::CTMD`
(PROCESS_PROC `Canon::ProcessCTMD`). `ProcessSamples` opens ONE `Doc<N>` per
timed sample, then `ProcessCTMD` walks the sample's records:

    [size:int32u-LE][type:int16u-LE][header:6 bytes][payload]

where `size` covers the WHOLE record (incl. the 4-byte size field) and the
payload begins at offset `pos+12` (`size-12` bytes). `ProcessCTMD` enters with
`SetByteOrder('II')` (Canon.pm:10765) — every multi-byte int is LITTLE-ENDIAN
(the OPPOSITE of Sony rtmd's big-endian). The `CTMD` table is
`GROUPS => { 0 => 'MakerNotes', 1 => 'Canon', 2 => 'Image' }` and is extracted
ONLY under `-ee` (auto-applied for CR3, but this crafted `.mov` needs `-ee`).

Two samples are emitted, each carrying TimeStamp (type 1) + FocalInfo (type 4)
+ ExposureInfo (type 5). The samples are stored contiguously in `mdat`; the
sample table (stts/stsc/stsz/stco) describes both in a single chunk so
ExifTool's `ProcessSamples` opens one `Doc<N>` per sample.

The structural atoms (ftyp/mvhd/trak/mdia/hdlr=mhlr+meta/minf/stbl/stsd=CTMD)
mirror `gen_sony_rtmd_fixture.py`'s `build_rtmd_mov` verbatim except the stsd
4-byte format code is `CTMD` instead of `rtmd` (the ONLY structural change —
same `meta` handler the rtmd stsd dispatches through). After running,
regenerate the goldens with `EE=1 EXCLUDE="-x System:all -x Composite:all"
tools/gen_golden.sh QuickTime_canon_ctmd.mov` (bundled ExifTool).

Per-record encodings (Format looked up in `%Image::ExifTool::Canon::CTMD`):
  type 1 TimeStamp    [x2][year:u16LE][mon][day][hr][min][sec][centisec]
                      2018:02:21 12:08:56.21
  type 4 FocalInfo    FocalLength rational32u (u16 num / u16 denom, LE)
                      15/1 → "15.0 mm"
  type 5 ExposureInfo FNumber rational32u @0 + ExposureTime rational32u @4
                      + ISO int32u @8 (masked &0x7fffffff)
                      35/10 → f/3.5 ; 1/80 → "1/80" ; 12800
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


# ── CTMD sample records ──────────────────────────────────────────────────────
def ctmd_record(rec_type: int, payload: bytes, header: bytes = b"\x00\x00\x00\x01\xff\xff") -> bytes:
    """One CTMD record: `[size:int32u-LE][type:int16u-LE][6 header bytes][payload]`.

    `size` is the WHOLE record length incl. the 4-byte size field; the payload
    starts at offset 12 (after size + type + the opaque 6-byte header). All
    multi-byte ints are LITTLE-ENDIAN (`SetByteOrder('II')`, Canon.pm:10765).
    """
    assert len(header) == 6, header
    size = 12 + len(payload)
    return struct.pack("<I", size) + struct.pack("<H", rec_type) + header + payload


def ctmd_record_raw_size(rec_type: int, size: int, body: bytes) -> bytes:
    """A CTMD record with an EXPLICIT (possibly bogus) `size` field.

    Used by the warning fixtures: a `size < 12` record triggers `Short CTMD
    record` (Canon.pm:10781) and a `size > dirLen` one triggers `Truncated CTMD
    record` (Canon.pm:10782). `body` is everything after the 6-byte size+type
    header; the on-disk record is `[size:u32LE][type:u16LE][body]`.
    """
    return struct.pack("<I", size) + struct.pack("<H", rec_type) + body


def time_stamp_payload(year: int, month: int, day: int, hour: int, minute: int, sec: int, centisec: int) -> bytes:
    """type-1 TimeStamp payload for `unpack('x2vCCCCCC', $val)` (Canon.pm:9801).

    `x2` skips two bytes, then `v` reads the year as a LE u16, then six `C`
    bytes (month/day/hour/min/sec/centisec). Total = 10 bytes; real files pad
    to 12 (a trailing 2-byte zero), which we mirror.
    """
    return (
        b"\x00\x00"                       # x2 pad
        + struct.pack("<H", year)         # year (LE u16)
        + bytes([month, day, hour, minute, sec, centisec])
        + b"\x00\x00"                     # trailing pad seen in real CR3 (→ 12-byte payload)
    )


def rat32u_le(num: int, denom: int) -> bytes:
    """A `rational32u` value: u16 numerator + u16 denominator, LITTLE-ENDIAN.

    ExifTool's `Get16u(num) / Get16u(denom)` for a Canon CTMD `rational32u`
    (Canon.pm reads the two halves as 16-bit, ExifTool.pm:6089-6094) — note
    this is a 4-byte total, NOT the 8-byte `rational64u` Sony rtmd uses.
    """
    return struct.pack("<HH", num, denom)


def focal_info_payload(num: int, denom: int) -> bytes:
    """type-4 FocalInfo payload: one `rational32u` FocalLength at offset 0.

    Real CR3 files pad the binary subtable; we append the `ff ff ff ff …`
    residue seen in PH's dumps to mirror the on-disk shape (the parser only
    reads the first 4 bytes).
    """
    return rat32u_le(num, denom) + b"\xff\xff\xff\xff\xff\xff\xff\xff"


def exposure_info_payload(fn_num: int, fn_den: int, et_num: int, et_den: int, iso: int) -> bytes:
    """type-5 ExposureInfo payload (Canon.pm:9866-9887, `FORMAT => 'int32u'`).

    - FNumber `rational32u` @ offset 0 (4 bytes);
    - ExposureTime `rational32u` @ offset 4 (the int32u stride is 4 bytes);
    - ISO `int32u` @ offset 8 (LE).
    Real files carry a longer binary blob with `ff ff ff ff` residue between
    fields; we emit the minimal 12 bytes the table reads plus a residue tail
    so the on-disk shape matches PH's dumps.
    """
    return (
        rat32u_le(fn_num, fn_den)         # FNumber @0
        + rat32u_le(et_num, et_den)       # ExposureTime @4
        + struct.pack("<I", iso)          # ISO @8 (int32u LE)
        + b"\xff\xff\xff\xff"             # residue tail (real-file shape)
    )


def exif_info_entry(tag: int, tiff: bytes) -> bytes:
    """One `ProcessExifInfo` record: `[len:int32u-LE][tag:int32u-LE][TIFF]`.

    `len` covers the 8-byte (len + tag) prefix PLUS the `len - 8` TIFF bytes;
    `tag` is the `%Canon::ExifInfo` table tag (`0x8769` ExifIFD / `0x927c`
    MakerNoteCanon, Canon.pm:9838/9845). The TIFF data is a COMPLETE TIFF
    (header + IFD) re-dispatched via `ProcessTIFF` with `Base => pos+8`,
    `DataPos => -(pos+8)` (Canon.pm:10747-10750) — so its out-of-line value
    offsets are relative to the TIFF's OWN start (it walks at base 0).
    """
    return struct.pack("<II", 8 + len(tiff), tag) + tiff


def tiff_exif_ifd(et_num: int, et_den: int, iso: int) -> bytes:
    """A minimal valid LE TIFF carrying ExposureTime (0x829a) + ISO (0x8827).

    IFD0 holds both Exif::Main tags directly (ProcessExifInfo's 0x8769
    SubDirectory walks the whole TIFF via `Exif::Main`, naming the directory
    `ExifIFD` so every recovered tag groups under `EXIF:ExifIFD` regardless of
    physical IFD). ExposureTime is `rational64u` (type 5, 8 bytes, out-of-line);
    ISO is `int16u` (type 3) inline. Layout: header(8) | IFD0 | rational.
    """
    count = 2
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    rational_off = ifd0_off + ifd0_size
    e_et = struct.pack("<HHII", 0x829A, 5, 1, rational_off)   # ExposureTime, out-of-line
    e_iso = struct.pack("<HHII", 0x8827, 3, 1, iso)           # ISO int16u inline
    ifd0 = struct.pack("<H", count) + e_et + e_iso + struct.pack("<I", 0)
    rational = struct.pack("<II", et_num, et_den)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + rational


def tiff_exif_ifd_interop(et_num: int, et_den: int, iso: int, interop_index: bytes) -> bytes:
    """A LE TIFF whose IFD0 carries ExposureTime + ISO + an `InteropOffset` ptr.

    Like `tiff_exif_ifd`, but IFD0 ALSO holds `0xa005` InteropOffset (type 4
    LONG, `Exif.pm:2720-2730`) → a NESTED InteropIFD whose only entry is
    `InteropIndex` (`0x0001`, type 2 ASCII). When ProcessExifInfo's 0x8769
    SubDirectory re-dispatches this whole TIFF via `Exif::Main`, ExifTool names
    the 0x8769 directory `ExifIFD` (so IFD0's direct tags group `EXIF:ExifIFD`)
    but follows 0xa005 with `SET_GROUP1 => 'InteropIFD'` (`Exif.pm:416` +
    `Exif.pm:2720-2729`), preserving the NESTED directory's own DirName — so
    `InteropIndex` groups `EXIF:InteropIFD`, NOT `EXIF:ExifIFD`. This crafted
    input proves the 0x8769 re-dispatch must keep nested sub-IFD DirNames
    intact rather than collapse every recovered tag to `ExifIFD`.

    Layout: header(8) | IFD0(ExposureTime + ISO + InteropOffset) | ExposureTime
    rational | InteropIFD(InteropIndex) | InteropIndex string.
    """
    s = interop_index if interop_index.endswith(b"\x00") else interop_index + b"\x00"
    assert len(s) <= 4, "InteropIndex kept inline (count<=4 ASCII): %r" % s
    ifd0_off = 8
    ifd0_count = 3
    ifd0_size = 2 + ifd0_count * 12 + 4
    rational_off = ifd0_off + ifd0_size
    interop_off = rational_off + 8                 # after the 8-byte ExposureTime rational
    interop_count = 1
    e_et = struct.pack("<HHII", 0x829A, 5, 1, rational_off)   # ExposureTime, out-of-line
    e_iso = struct.pack("<HHII", 0x8827, 3, 1, iso)           # ISO int16u inline
    e_int = struct.pack("<HHII", 0xA005, 4, 1, interop_off)   # InteropOffset LONG ptr
    # IFD entries MUST be tag-ascending (ExifTool tolerates unsorted, but keep
    # the on-disk shape canonical): 0x829a < 0x8827 < 0xa005.
    ifd0 = struct.pack("<H", ifd0_count) + e_et + e_iso + e_int + struct.pack("<I", 0)
    rational = struct.pack("<II", et_num, et_den)
    # InteropIndex (type 2 ASCII, count<=4) is INLINE: the 4-byte value field
    # holds the NUL-padded string directly (matches the IFD0->ExifIFD->InteropIFD
    # chain in `src/exif/mod.rs::interop_index_through_full_ifd_chain`).
    e_ii = struct.pack("<HH", 0x0001, 2) + struct.pack("<I", len(s)) + s.ljust(4, b"\x00")
    interop_ifd = struct.pack("<H", interop_count) + e_ii + struct.pack("<I", 0)
    return (
        b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off)
        + ifd0 + rational + interop_ifd
    )


def tiff_bad_ifd0() -> bytes:
    """A VALID LE TIFF header (`II 0x2a`) whose IFD0 offset OVERRUNS the block.

    The 8-byte header is well-formed and the IFD0 pointer clears the `>= 8`
    gate (offset 64), so `ProcessTIFF` `SetByteOrder`s OK — bundled still
    surfaces the byte-order marker (`File:ExifByteOrder`, present for the
    0x8769 EXIF re-dispatch). But the IFD0 directory read overruns the tiny
    block (only 16 bytes total), so `ProcessExif` `$success = 0` and bundled
    raises `Bad $dir directory` (Exif.pm:6383) under the active Doc/Track
    scope: `Bad ExifIFD directory` for the 0x8769 path (`$inMakerNotes` = 0,
    non-minor) / `[minor] Bad MakerNotes directory` for the 0x927c path
    (`$inMakerNotes` = 1, minor). 8-byte header + 8 filler bytes = 16.
    """
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", 64) + b"\x00" * 8


def tiff_canon_makernote(firmware: bytes) -> bytes:
    """A minimal valid LE TIFF whose IFD0 IS the Canon MakerNote.

    ProcessExifInfo's 0x927c SubDirectory re-dispatches this complete TIFF via
    `ProcessTIFF` with `TagTable => Canon::Main`, so IFD0's tags are looked up
    in `%Canon::Main`. Carries CanonFirmwareVersion (0x0007, ASCII string,
    Canon.pm:1257). Layout: header(8) | IFD0 | string.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 1
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    str_off = ifd0_off + ifd0_size
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), str_off)
    ifd0 = struct.pack("<H", count) + e_fw + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s


def tiff_exif_ifd_model(model: bytes) -> bytes:
    """A minimal valid LE TIFF whose IFD0 carries Model (0x0110 ASCII, out-of-line).

    ProcessExifInfo's 0x8769 SubDirectory re-dispatches this whole TIFF via
    `Exif::Main`, which records IFD0's `Model` as `$$self{Model}` (Exif.pm:599,
    RawConv trims trailing whitespace). A LATER 0x927c (MakerNoteCanon) entry's
    `Canon::Main` decode then keys its MODEL-CONDITIONAL sub-tables on that value
    (e.g. `Canon::ShotInfo` CameraTemperature, `$$self{Model} =~ /EOS/`,
    Canon.pm:2866-2877). Layout: header(8) | IFD0(Model) | string.
    """
    s = model if model.endswith(b"\x00") else model + b"\x00"
    count = 1
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    str_off = ifd0_off + ifd0_size
    e_model = struct.pack("<HHII", 0x0110, 2, len(s), str_off)
    ifd0 = struct.pack("<H", count) + e_model + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s


def tiff_exif_ifd_two_models(m1: bytes, m2: bytes) -> bytes:
    """A LE TIFF whose IFD0 carries TWO Model (0x0110 ASCII) entries: m1 THEN m2.

    Exif.pm:599 `RawConv => '$val =~ s/\\s+$//; $$self{Model} = $val'` runs EACH
    time a Model tag is handled, so the SECOND (later) Model OVERWRITES the first
    in `$$self{Model}` (last-wins). A LATER 0x927c (MakerNoteCanon) entry's
    `Canon::Main` decode then keys its MODEL-CONDITIONAL sub-tables on the LAST
    Model (oracle-verified vs bundled 13.59: with m1 non-EOS and m2 "Canon EOS R5"
    the EOS-gated `Canon::ShotInfo` CameraTemperature, `$$self{Model} =~ /EOS/`,
    Canon.pm:2868, DOES fire). The emitted `Model` tag is ALSO last-wins (TagMap
    dedup), so bundled reports `Model` = m2. Layout: header(8) | IFD0(two Model
    entries) | m1 string | m2 string.
    """
    s1 = m1 if m1.endswith(b"\x00") else m1 + b"\x00"
    s2 = m2 if m2.endswith(b"\x00") else m2 + b"\x00"
    count = 2
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    str1_off = ifd0_off + ifd0_size
    str2_off = str1_off + len(s1)
    e1 = struct.pack("<HHII", 0x0110, 2, len(s1), str1_off)   # Model #1 (overwritten)
    e2 = struct.pack("<HHII", 0x0110, 2, len(s2), str2_off)   # Model #2 (LAST wins)
    ifd0 = struct.pack("<H", count) + e1 + e2 + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s1 + s2


def tiff_canon_makernote_shotinfo(temp_raw: int) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 holds CanonShotInfo (0x0004) — a
    SHORT array exercising the MODEL-CONDITIONAL CameraTemperature (position 12).

    `Canon::ShotInfo` is `ProcessBinaryData`, FORMAT int16s, FIRST_ENTRY 1, with a
    `Canon::Validate($dirData,$start,$size)` SubDirectory check: the FIRST 16-bit
    word MUST equal the data's byte length (Canon.pm:10322-10333) or bundled
    raises `Invalid CanonShotInfo data` and emits nothing. We emit 16 words (=32
    bytes), so word[0]=32; word[12] (byte offset 24) holds the CameraTemperature
    raw — `ValueConv => $val - 128`, `PrintConv => "$val C"` (Canon.pm:2866-2877),
    gated on `$$self{Model} =~ /EOS/ and !~ /EOS-1DS?$/`. So a `temp_raw` of 158
    renders "30 C" — but ONLY when a preceding 0x8769 set an EOS `$$self{Model}`.
    Layout: header(8) | IFD0(0x0004 SHORT[16] out-of-line) | array(32 bytes).
    """
    nwords = 16
    words = [0] * nwords
    words[0] = nwords * 2          # Canon::Validate: word[0] == byte length
    words[12] = temp_raw           # CameraTemperature raw (ValueConv $val-128)
    arr = b"".join(struct.pack("<H", w & 0xFFFF) for w in words)
    count = 1
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    arr_off = ifd0_off + ifd0_size
    e_shot = struct.pack("<HHII", 0x0004, 3, nwords, arr_off)  # 0x0004 SHORT[16]
    ifd0 = struct.pack("<H", count) + e_shot + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + arr


def tiff_canon_makernote_with_exif_ptr(firmware: bytes) -> bytes:
    """A valid LE Canon-MakerNote TIFF whose READABLE IFD0 ALSO carries a bogus
    `0x8769` (ExifIFD-style) pointer with an offset far past EOF.

    The 0x927c SubDirectory re-dispatches this via `ProcessTIFF` with
    `TagTable => Canon::Main` (Canon.pm:9845-9852). `%Canon::Main` has NO 0x8769
    key (Canon's MakerNote carries no ExifIFD pointer — its sub-tables are
    ProcessBinaryData, not ProcessExif IFD sub-dirs), so GetTagInfo never
    resolves 0x8769 to a SubDirectory and bundled NEVER follows it: IFD0 reads
    fine (CanonFirmwareVersion decodes) and NO `Bad ExifIFD directory` warning is
    raised. The generic Exif walker (`Exif::Main`) WOULD follow 0x8769 → a
    spurious nested warning — the bug the Canon-table diagnostics path fixes.
    Layout: header(8) | IFD0(firmware + 0x8769 ptr) | string.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 2
    ifd0_off = 8
    ifd0_size = 2 + count * 12 + 4
    str_off = ifd0_off + ifd0_size
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), str_off)        # firmware, out-of-line
    e_exif = struct.pack("<HHII", 0x8769, 4, 1, 0x70000000)       # 0x8769 LONG ptr past EOF
    ifd0 = struct.pack("<H", count) + e_fw + e_exif + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s


def tiff_canon_makernote_bad_value_offset(firmware: bytes) -> bytes:
    """A LE Canon-MakerNote TIFF whose READABLE IFD0 carries a 0x0007
    CanonFirmwareVersion whose OUT-OF-LINE value pointer OVERRUNS the block.

    The 0x927c SubDirectory re-dispatches this via `ProcessTIFF` →
    `ProcessExif` with `TagTable => Canon::Main` and `$inMakerNotes = 1`
    (Canon.pm:9845-9852). IFD0 parses fine (the directory is readable), but
    CanonFirmwareVersion's value pointer (0x70000000) lands far past
    `length($$dataPt)`. With NO `$raf` (the block is in-memory) ExifTool takes
    the no-RAF `else` branch and warns `Bad offset for $dir $tagStr`
    (Exif.pm:6660) — `$dir` re-mapped to `MakerNotes`, `$tagStr` the
    `%Canon::Main` name "CanonFirmwareVersion", level MINOR (`$inMakerNotes`):
    `[minor] Bad offset for MakerNotes CanonFirmwareVersion`. The walk CONTINUES
    (`$bad = 1`, NOT an abort). Oracle-verified vs bundled 13.59. Layout:
    header(8) | IFD0(0x0007 firmware ptr past EOF) | filler.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 1
    ifd0_off = 8
    bad_off = 0x70000000                                       # far past EOF
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), bad_off)   # firmware ptr OOB
    ifd0 = struct.pack("<H", count) + e_fw + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + b"\x00\x00\x00\x00"


def tiff_canon_makernote_suspicious_offset(firmware: bytes) -> bytes:
    """A LE Canon-MakerNote TIFF whose READABLE IFD0 carries a 0x0007
    CanonFirmwareVersion whose OUT-OF-LINE value pointer OVERLAPS the directory.

    Like [`tiff_canon_makernote_bad_value_offset`] but the value pointer (10)
    is IN bounds yet `$valuePtr < $dirEnd and $valuePtr + $size > $dirStart`
    (Exif.pm:6549) — it overlaps the IFD directory region. The bounds read is
    NOT triggered (in-bounds), so no `Bad offset`; instead the trailing
    `$suspect == $warnCount` test (Exif.pm:6672) warns `Suspicious $dir offset
    for $tagStr` (Exif.pm:6675), MINOR under `$inMakerNotes`:
    `[minor] Suspicious MakerNotes offset for CanonFirmwareVersion`. The walk
    CONTINUES. Oracle-verified vs bundled 13.59. Layout: header(8) | IFD0(0x0007
    firmware ptr=10, overlapping) | firmware string | filler.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 1
    ifd0_off = 8
    susp_off = 10                                              # inside the IFD directory
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), susp_off)
    ifd0 = struct.pack("<H", count) + e_fw + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s + b"\x00" * 8


def tiff_canon_makernote_susp_tail(firmware: bytes, tail: int) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 ends EXACTLY at the block boundary
    (`tail == 0`) or with a 2-byte tail (`tail == 2`), carrying a 0x0007
    CanonFirmwareVersion whose OUT-OF-LINE value pointer (10) OVERLAPS the
    directory (Exif.pm:6549) ⇒ SUSPICIOUS.

    The directory-tail case: ProcessExif's `$bytesFromEnd = $dataLen - $dirEnd`
    is `0` (or `2`) — BOTH legal (`Exif.pm:6396` `$bytesFromEnd==0 or ==2`), so
    the directory is WALKED and the suspect-offset entry is reached. Bundled
    raises `[minor] Suspicious MakerNotes offset for CanonFirmwareVersion`
    (Exif.pm:6675) and `next`-SKIPS the entry (no value emitted). The prior
    `dir_end + 4 <= data_len` diagnostic gate suppressed this warning while the
    emission still skipped — the SKIP and WARNING disagreed. Layout: header(8) |
    IFD0(1 entry, dir_end=22) | `tail` filler bytes (NO next-IFD pointer).
    Oracle-verified vs bundled 13.59.
    """
    assert tail in (0, 2)
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 1
    ifd0_off = 8
    susp_off = 10                                              # overlaps the IFD directory
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), susp_off)
    ifd0 = struct.pack("<H", count) + e_fw                    # 14 bytes [8,22); NO next-IFD ptr
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + (b"\x00" * tail)


def tiff_canon_makernote_illegal_tail(firmware: bytes, tail: int) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 has a 1-byte (`tail == 1`) or 3-byte
    (`tail == 3`) tail ⇒ an ILLEGAL directory size.

    ProcessExif's `$bytesFromEnd = $dataLen - $dirEnd` is `1` or `3` — neither
    `0` nor `2` (`Exif.pm:6396`), so bundled raises `Illegal MakerNotes
    directory size (1 entries)` (Exif.pm:6397) and `return 0`s (ABORTS the whole
    directory — no entry is read). The warning is NON-minor (the Perl `$et->Warn`
    carries no minor arg, even though `$inMakerNotes = 1`). The 0x0007 entry has
    a clean in-bounds offset; it is NEVER reached (the directory aborts first).
    Layout: header(8) | IFD0(1 entry, dir_end=22) | `tail` filler bytes.
    Oracle-verified vs bundled 13.59.
    """
    assert tail in (1, 3)
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 1
    ifd0_off = 8
    # Clean offset just past dir_end so the entry would decode IF reached.
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), 22)
    ifd0 = struct.pack("<H", count) + e_fw                    # 14 bytes [8,22)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + (b"\x00" * tail)


def tiff_canon_makernote_bad_format_entry0() -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0's FIRST entry carries a bad NONZERO
    format code (99) ⇒ `Bad format (99) for MakerNotes entry 0` + ABORT.

    ProcessExif (`Exif.pm:6463-6477`): an unrecognized format that is NONZERO
    warns `Bad format (<code>) for <dir> entry <index>` (`$inMakerNotes` ⇒
    MINOR) and, because it is `$index == 0`, `return 0`s ("assume corrupted IFD
    if this is our first entry"). No value is emitted. Layout: header(8) |
    IFD0(1 entry, format 99). Oracle-verified vs bundled 13.59.
    """
    count = 1
    ifd0_off = 8
    e_bad = struct.pack("<HHII", 0x0007, 99, 8, 26)           # format 99 (bad, nonzero)
    ifd0 = struct.pack("<H", count) + e_bad + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + b"FW1.0.0\x00"


def tiff_canon_makernote_bad_format_entry1(firmware: bytes) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 has a VALID entry 0
    (CanonFirmwareVersion) then a bad-format entry 1 ⇒ entry 0 emits + `Bad
    format (99) for MakerNotes entry 1` (`next`-skip, NOT abort).

    ProcessExif `next if $index` (`Exif.pm:6475`) — a bad format on entry
    `index != 0` skips JUST that entry and CONTINUES, so CanonFirmwareVersion
    (entry 0) still decodes AND bundled raises `[minor] Bad format (99) for
    MakerNotes entry 1`. Layout: header(8) | IFD0(2 entries) | firmware string.
    Oracle-verified vs bundled 13.59.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    count = 2
    ifd0_off = 8
    str_off = ifd0_off + 2 + count * 12 + 4
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), str_off)   # valid firmware, out-of-line
    e_bad = struct.pack("<HHII", 0x0008, 99, 1, 0)           # bad format 99 (entry 1)
    ifd0 = struct.pack("<H", count) + e_fw + e_bad + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s


def tiff_canon_makernote_invalid_size() -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0's 0x0007 entry has a count so large
    that `count * formatSize` exceeds the signed-32-bit ceiling ⇒ `Invalid size
    (<size>) for MakerNotes tag 0x0007 CanonFirmwareVersion`.

    ProcessExif (`Exif.pm:6505`): the FIRST test inside the `$size > 4` block is
    `if ($size > 0x7fffffff …) { Warn('Invalid size …'); ++$warnCount; next }` —
    BEFORE the offset is read, so it is reported as `Invalid size`, NOT `Bad
    offset`. The name uses `TagName` (`tag 0x%.4x Name`). MINOR (`$inMakerNotes`).
    `count = 0x40000000`, format int32u (4 bytes) ⇒ size `0x100000000`. Layout:
    header(8) | IFD0(1 entry) | filler. Oracle-verified vs bundled 13.59.
    """
    count = 1
    ifd0_off = 8
    # 0x0007 as int32u (format 4), count 0x40000000 ⇒ size = 0x100000000 > 0x7fffffff.
    e = struct.pack("<HHII", 0x0007, 4, 0x40000000, 26)
    ifd0 = struct.pack("<H", count) + e + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + b"\x00" * 8


def tiff_exif_ifd_oob_then_valid() -> bytes:
    """A LE 0x8769-ExifIFD TIFF whose IFD0 has an OUT-OF-BOUNDS entry 0 (Make,
    out-of-line ptr past EOF) then a VALID inline entry 1 (Software).

    The 0x8769 SubDirectory re-dispatches via `ProcessTIFF` → `ProcessExif`
    under `Exif::Main` FROM MEMORY with NO RAF (`$inMakerNotes = 0`). ExifTool's
    no-RAF value path (`Exif.pm:6616-6670`) warns `Bad offset for ExifIFD Make`
    (`Exif.pm:6660`, NON-minor) + `$bad = 1` and CONTINUES the loop — so the
    LATER valid Software (entry 1) STILL decodes (`Doc1:ExifIFD:Software = "SW"`).
    A RAF-modeled walk would instead `Error reading value` + ABORT, dropping
    Software. Layout: header(8) | IFD0(Make OOB + Software inline) | filler.
    Oracle-verified vs bundled 13.59.
    """
    ifd0_off = 8
    count = 2
    soft = b"SW\x00\x00"                                       # 4 bytes ⇒ INLINE
    e_make = struct.pack("<HHII", 0x010f, 2, 8, 0x70000000)  # Make ASCII count 8, ptr past EOF
    e_soft = struct.pack("<HH", 0x0131, 2) + struct.pack("<I", 4) + soft  # Software inline
    ifd0 = struct.pack("<H", count) + e_make + e_soft + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + b"\x00" * 8


def tiff_canon_makernote_many_warnings(firmware: bytes) -> bytes:
    """A LE Canon-MakerNote TIFF whose READABLE IFD0 piles up MORE THAN TEN
    counted per-entry warnings, then a VALID later entry — to exercise
    ProcessExif's `$warnCount > 10` abort (`Exif.pm:6455-6456`).

    Layout: entry 0 is a VALID out-of-line CanonFirmwareVersion (0x0007), then 12
    BAD-format entries (format code 255, nonzero ⇒ each warns `Bad format (255)
    for MakerNotes entry N` AND `++$warnCount`, `next`-skip since `index != 0`),
    then a VALID inline OwnerName (0x0009). ExifTool counts entries 1..11 (11
    warnings), and at entry 12 `$warnCount > 10` fires: it emits the `[Minor] Too
    many warnings -- MakerNotes parsing aborted` (`Warn(..., 2)`, capital-M minor)
    and `return 0`s — so the trailing valid OwnerName (entry 13) is NEVER read.
    The single surviving (first-distinct) warning in `-j` is `Bad format (255)
    for MakerNotes entry 1`; CanonFirmwareVersion (entry 0, BEFORE the bad run)
    still emits. Oracle-verified vs bundled 13.59.
    """
    s = firmware if firmware.endswith(b"\x00") else firmware + b"\x00"
    n_bad = 12
    count = 1 + n_bad + 1                       # firmware + 12 bad + OwnerName
    ifd0_off = 8
    str_off = ifd0_off + 2 + count * 12 + 4     # firmware string just past the dir
    e_fw = struct.pack("<HHII", 0x0007, 2, len(s), str_off)   # entry 0: valid firmware
    bad = b"".join(
        struct.pack("<HHII", 0x0200 + i, 255, 1, 0) for i in range(n_bad)  # bad format 255
    )
    owner = b"OW\x00\x00"                        # 4-byte inline OwnerName value
    e_owner = struct.pack("<HH", 0x0009, 2) + struct.pack("<I", 4) + owner  # entry 13: valid
    ifd0 = struct.pack("<H", count) + e_fw + bad + e_owner + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + s


def tiff_exif_ifd_many_warnings(et_num: int, et_den: int, iso: int) -> bytes:
    """A LE 0x8769-ExifIFD TIFF whose IFD0 piles up MORE THAN TEN counted
    warnings, then a VALID later entry — the `Exif::Main` (`$inMakerNotes = 0`)
    counterpart of [`tiff_canon_makernote_many_warnings`].

    Entry 0 is a VALID out-of-line ExposureTime (0x829a), then 12 BAD-format
    entries (format 255 ⇒ `Bad format (255) for ExifIFD entry N`, NON-minor under
    `$inMakerNotes = 0`, `++$warnCount`), then a VALID inline ISO (0x8827).
    ExifTool counts entries 1..11 then aborts at entry 12 with `[Minor] Too many
    warnings -- ExifIFD parsing aborted` (`Warn(..., 2)` ⇒ capital-M minor
    REGARDLESS of `$inMakerNotes`) and `return 0`s — so the trailing ISO is
    suppressed. ExposureTime (entry 0) still emits. Re-dispatched from memory
    with NO RAF (the no-RAF `else` path), but the bad-format + warn-count logic
    is RAF-independent. Oracle-verified vs bundled 13.59. Layout: header(8) |
    IFD0(ExposureTime + 12 bad + ISO) | rational.
    """
    n_bad = 12
    count = 1 + n_bad + 1                        # ExposureTime + 12 bad + ISO
    ifd0_off = 8
    rational_off = ifd0_off + 2 + count * 12 + 4
    e_et = struct.pack("<HHII", 0x829A, 5, 1, rational_off)   # entry 0: valid ExposureTime
    bad = b"".join(
        struct.pack("<HHII", 0x0200 + i, 255, 1, 0) for i in range(n_bad)
    )
    e_iso = struct.pack("<HHII", 0x8827, 3, 1, iso)          # entry 13: valid ISO inline
    ifd0 = struct.pack("<H", count) + e_et + bad + e_iso + struct.pack("<I", 0)
    rational = struct.pack("<II", et_num, et_den)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + rational


def tiff_canon_makernote_zero_entries(tail: int) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 declares ZERO entries with a 1-byte
    (`tail == 1`) or 3-byte (`tail == 3`) trailing residue ⇒ an ILLEGAL
    directory size for a 0-entry directory.

    ProcessExif (`Exif.pm:6343-6399`): `$numEntries = 0`, `$dirSize = 2`,
    `$dirEnd = $dirStart + 2`; `$bytesFromEnd = $dataLen - $dirEnd` is `1` or `3`
    — neither `0` nor `2` — so bundled raises `Illegal MakerNotes directory size
    (0 entries)` (`Exif.pm:6397`) and `return 0`s. NON-minor (no minor arg). This
    pins the R9-2 fix: removing the synthetic `num_entries == 0` reject must NOT
    swallow the legitimate zero-entry illegal-tail warning. Layout: header(8) |
    count(2)=0 | `tail` filler bytes. Oracle-verified vs bundled 13.59.
    """
    assert tail in (1, 3)
    ifd0_off = 8
    ifd0 = struct.pack("<H", 0)                   # 0 entries → dir_end = 10
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0 + (b"\x00" * tail)


def tiff_canon_makernote_many_entries(n: int) -> bytes:
    """A LE Canon-MakerNote TIFF whose IFD0 holds `n` (> 1024) VALID in-bounds
    entries — the R9-2 ">1024-entry directory must be walked" case.

    ProcessExif has NO entry-count ceiling (`Exif.pm:6343-6400`): it computes
    `$dirSize = 2 + 12*$numEntries` and walks every entry, bounded only by
    `$dirEnd <= $dataLen`. Each entry is a VALID inline tag (we reuse 0x0007
    CanonFirmwareVersion's ID with ASCII count-2 inline values so the FIRST one
    decodes to a real `CanonFirmwareVersion`; the rest share the ID and are
    same-name duplicates — last-wins — which is fine, the point is the WALK
    completes past 1024). The pre-R9-2 `MAX_SANE_ENTRIES = 1024` gate dropped the
    whole directory. Oracle-verified vs bundled 13.59 (a 2000-entry in-bounds IFD
    walks with no warning). Layout: header(8) | IFD0(`n` inline entries) | (none).
    """
    assert n > 1024
    ifd0_off = 8
    entries = b"".join(
        struct.pack("<HH", 0x0007, 2) + struct.pack("<I", 2) + b"V\x00\x00\x00"
        for _ in range(n)
    )
    ifd0 = struct.pack("<H", n) + entries + struct.pack("<I", 0)
    return b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", ifd0_off) + ifd0


def build_ctmd_mov(samples) -> bytes:
    """Minimal `.mov`: ftyp / mdat(samples) / moov(mvhd + trak[CTMD meta]).

    Identical to `gen_sony_rtmd_fixture.py:build_rtmd_mov` except the stsd
    4-byte format code is `CTMD` (the rtmd generator uses `rtmd`); the `meta`
    handler, `nmhd` minf, and the single-chunk N-sample stbl are unchanged.
    """
    # ftyp 'qt  '.
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))

    # mdat: all sample blobs stored back-to-back. The stco entry points at the
    # first sample (right after ftyp + the 8-byte mdat header).
    sample_blob = b"".join(samples)
    mdat = struct.pack(">I", len(sample_blob) + 8) + b"mdat" + sample_blob
    sample_base = len(ftyp) + 8  # file offset of the first sample
    sizes = [len(s) for s in samples]

    # mvhd (v0): timescale=1000, duration covers all samples.
    total_dur = 1000 * len(samples)
    mvhd_body = (
        b"\x00\x00\x00\x00"             # version+flags
        + b"\x00" * 8                   # create/modify
        + struct.pack(">I", 1000)       # timescale
        + struct.pack(">I", total_dur)  # duration
        + b"\x00" * 80                  # rest (rate/volume/matrix/…)
    )

    # hdlr: mhlr / meta (the meta_handler the CTMD stsd dispatches through).
    hdlr_body = (
        b"\x00\x00\x00\x00"  # version+flags
        + b"mhlr"            # pre_defined
        + b"meta"            # handler_type
        + b"\x00" * 12       # reserved
        + b"\x00"            # name (empty)
    )

    # mdhd (v0): timescale=1000, duration covers all samples.
    mdhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4  # language+quality
    )

    # stsd: 1 entry whose 4-byte format code is `CTMD`.
    stsd_entry = struct.pack(">I", 16) + b"CTMD" + b"\x00" * 6 + struct.pack(">H", 1)
    stsd_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + stsd_entry

    # stts: one run of N samples, delta=1000 each.
    stts_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)              # entry count
        + struct.pack(">II", len(samples), 1000)
    )

    # stsc: all samples in one chunk (first_chunk=1, samples_per_chunk=N, desc=1).
    stsc_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">III", 1, len(samples), 1)
    )

    # stsz: variable sizes (sample_size=0), explicit per-sample sizes.
    stsz_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)              # sample_size=0 → variable
        + struct.pack(">I", len(samples))   # count
        + b"".join(struct.pack(">I", s) for s in sizes)
    )

    # stco: single chunk offset at the first sample inside mdat.
    stco_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", sample_base)
    )

    stbl = atom(b"stbl",
                atom(b"stsd", stsd_body)
                + atom(b"stts", stts_body)
                + atom(b"stsc", stsc_body)
                + atom(b"stsz", stsz_body)
                + atom(b"stco", stco_body))
    minf = atom(b"minf", atom(b"nmhd", b"\x00\x00\x00\x00") + stbl)
    mdia = atom(b"mdia",
                atom(b"mdhd", mdhd_body)
                + atom(b"hdlr", hdlr_body)
                + minf)
    trak = atom(b"trak", atom(b"tkhd", b"\x00" * 84) + mdia)
    moov = atom(b"moov", atom(b"mvhd", mvhd_body) + trak)

    # ftyp / mdat / moov — the stco offset lands inside the mdat placed right
    # after ftyp.
    return ftyp + mdat + moov


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)

    # The shared CTMD record set (records ordered TimeStamp, FocalInfo,
    # ExposureInfo — the camera-indexing-relevant types). TimeStamp encodes
    # 2018:02:21 12:08:56.21 (the real CanonRaw.cr3 value PH documents).
    def ctmd_records(iso: int):
        return [
            ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),  # TimeStamp
            ctmd_record(4, focal_info_payload(15, 1)),                       # FocalLength 15.0 mm
            ctmd_record(5, exposure_info_payload(35, 10, 1, 80, iso)),       # F3.5, 1/80, ISO
        ]

    # Sample 0: ISO 12800 ; sample 1: ISO 6400 (proves the per-sample Doc<N>
    # axis and the -G1 first-wins collapse — Doc1's ISO 12800 wins).
    sample0 = b"".join(ctmd_records(12800))
    sample1 = b"".join(ctmd_records(6400))

    def write(name: str, data: bytes) -> None:
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    write("QuickTime_canon_ctmd.mov", build_ctmd_mov([sample0, sample1]))

    # ── Non-clean-rational fixture (FIX #3 -n %.7g precision) ────────────────
    # FocalLength 10/3, FNumber 1/3, ExposureTime 1/3 — non-terminating
    # quotients whose `GetRational32u` `-n` form is the %.7g rounding
    # (3.333333 / 0.3333333 / 0.3333333), NOT the 15-digit f64. The -j
    # PrintConvs round further (3.3 mm / 0.33 / 0.3). One sample is enough.
    rational_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(4, focal_info_payload(10, 3)),                 # FocalLength 10/3
        ctmd_record(5, exposure_info_payload(1, 3, 1, 3, 12800)),  # FN 1/3, ET 1/3
    ])
    write("QuickTime_canon_ctmd_rational.mov", build_ctmd_mov([rational_sample]))

 # ── Duplicate type-4/type-5 in ONE sample (last-wins) ──────────
    # Bundled HandleTags every CTMD record (Canon.pm:10790-10800); a repeated
    # type-4/type-5 in one sample is a same-Doc duplicate tag → the LATER value
    # wins (ExifTool.pm:9437-9519). So bundled reports FocalLength 24.0 mm,
    # FNumber 8.0, ExposureTime 1/250, ISO 6400 (the SECOND of each), never the
    # first 15.0 mm / 3.5 / 1/80 / 12800.
    dup_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(4, focal_info_payload(15, 1)),                    # 15.0 mm (overwritten)
        ctmd_record(4, focal_info_payload(24, 1)),                    # 24.0 mm (LAST wins)
        ctmd_record(5, exposure_info_payload(35, 10, 1, 80, 12800)),  # F3.5 1/80 ISO12800 (overwritten)
        ctmd_record(5, exposure_info_payload(80, 10, 1, 250, 6400)),  # F8.0 1/250 ISO6400 (LAST wins)
    ])
    write("QuickTime_canon_ctmd_dup.mov", build_ctmd_mov([dup_sample]))

    # ── Warning fixtures (FIX #2 ProcessCTMD Doc<N>:Track<N>:Warning) ────────
    # Three SEPARATE one-sample movies, each isolating one ProcessCTMD warning
    # so its Doc1:Track1:Warning text is byte-exact vs bundled:
    #   short    — a size=10 (<12) record ⇒ "Short CTMD record".
    #   trunc    — a valid TimeStamp then a size=100 (> dirLen) record ⇒
    #              "Truncated CTMD record" (the TimeStamp still emits).
    #   residue  — a valid TimeStamp then 5 trailing bytes (< 6, so the walk
    #              loop exits leaving pos != dirLen) ⇒ the MINOR
    #              "[minor] Error parsing Canon CTMD data".
    short_sample = ctmd_record_raw_size(1, 10, b"\x00\x00\x00\x00")
    write("QuickTime_canon_ctmd_warn_short.mov", build_ctmd_mov([short_sample]))

    trunc_sample = (
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21))
        + ctmd_record_raw_size(4, 100, b"\x00" * 14)
    )
    write("QuickTime_canon_ctmd_warn_trunc.mov", build_ctmd_mov([trunc_sample]))

    residue_sample = (
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)) + b"\x00\x00\x00\x00\x00"
    )
    write("QuickTime_canon_ctmd_warn_residue.mov", build_ctmd_mov([residue_sample]))

    # ── Short-TimeStamp fixture (FIX #4 partial unpack + RawConv warning) ────
    # Two samples whose type-1 TimeStamp payload is TRUNCATED below the 10-byte
    # complete length, exercising the `unpack('x2vCCCCCC')` + `sprintf` partial
    # path: a len-4 payload (year only → "2018:00:00 00:00:00.00" + RawConv
    # "Missing argument in sprintf") and a len-0 payload (the `x2` skip croaks →
    # NO TimeStamp + RawConv "'x' outside of string in unpack"). The full 12-byte
    # payload truncated at each length (00 00 | e2 07 | 02 15 0c 08 38 15 | 00 00).
    full_ts = (
        b"\x00\x00" + struct.pack("<H", 2018) + bytes([2, 21, 12, 8, 56, 21]) + b"\x00\x00"
    )
    shortts_sample0 = ctmd_record(1, full_ts[:4])   # partial string + Missing-argument warning
    shortts_sample1 = ctmd_record(1, full_ts[:0])   # dropped string + outside-of-string warning
    write("QuickTime_canon_ctmd_shortts.mov", build_ctmd_mov([shortts_sample0, shortts_sample1]))

    # ── ExifInfo7/8/9 re-dispatch fixture (#82 — types 7/8/9 ProcessExifInfo) ──
    # A type-7 record whose payload is the `[len][tag][TIFF]` ProcessExifInfo
    # stream: a 0x8769 (ExifIFD) entry carrying ExposureTime 1/80 + ISO 400,
    # FOLLOWED by a 0x927c (MakerNoteCanon) entry carrying CanonFirmwareVersion
    # — the "ExifIFD + MakerNotes" shape Canon.pm:9818 documents for a CR3
    # type-7. Bundled re-dispatches each embedded TIFF via ProcessTIFF; the
    # recovered tags emit under the sample's Doc<N>/Track<N> scope (the EXIF
    # tags re-scope to EXIF:ExifIFD, the MakerNote to MakerNotes:Track<N>,
    # ExifByteOrder to File:Track<N> — all oracle-verified vs bundled 13.59).
    # Records ordered TimeStamp/Focal/Exposure (the scalar types) THEN the
    # ExifInfo block, mirroring a real CR3 sample.
    def exifinfo_sample(iso_exif: int):
        exif_block = exif_info_entry(0x8769, tiff_exif_ifd(1, 80, iso_exif))
        mn_block = exif_info_entry(0x927c, tiff_canon_makernote(b"Firmware Version 1.0.0"))
        return b"".join([
            ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
            ctmd_record(4, focal_info_payload(15, 1)),
            ctmd_record(5, exposure_info_payload(35, 10, 1, 80, 12800)),
            ctmd_record(7, exif_block + mn_block),
        ])
    write(
        "QuickTime_canon_ctmd_exifinfo.mov",
        build_ctmd_mov([exifinfo_sample(400), exifinfo_sample(200)]),
    )

 # ── Nested EXIF sub-IFD in the 0x8769 re-dispatch ─────────────
    # A type-7 record whose 0x8769 (ExifIFD) ProcessExifInfo TIFF has IFD0
    # carrying ExposureTime + ISO AND a 0xa005 InteropOffset → a NESTED
    # InteropIFD with InteropIndex (0x0001 "R98"). When bundled re-dispatches the
    # 0x8769 TIFF via `Exif::Main`, it names the 0x8769 directory `ExifIFD` (so
    # IFD0's direct tags group `EXIF:ExifIFD`) but follows 0xa005 with SET_GROUP1
    # `InteropIFD` (Exif.pm:416 + 2720-2729), keeping the NESTED directory's
    # DirName — so `InteropIndex` emits `Doc1:InteropIFD:InteropIndex` /
    # `Track1:InteropIndex`, NOT under ExifIFD. The 0x8769 re-dispatch must keep
    # nested sub-IFD groups intact rather than collapse EVERY tag to ExifIFD.
    # A clean TimeStamp precedes the ExifInfo block (it still decodes).
    nested_exif_block = exif_info_entry(
        0x8769, tiff_exif_ifd_interop(1, 80, 400, b"R98")
    )
    nested_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, nested_exif_block),
    ])
    write(
        "QuickTime_canon_ctmd_exifinfo_nested.mov",
        build_ctmd_mov([nested_sample]),
    )

    # ── Bad embedded-TIFF fixture (drop embedded ExifInfo diagnostics) ───────
    # The CTMD type-7/8/9 re-dispatch parses each embedded TIFF; a malformed one
    # (VALID header + BAD IFD0 offset) raises a normal EXIF `Bad $dir directory`
    # warning UNDER the active Doc/Track scope (ProcessTIFF→ProcessExif,
    # Exif.pm:6383). Two separate one-sample movies isolate each re-dispatch tag:
    #   badexif — a type-7 carrying a 0x8769 (ExifIFD) block whose TIFF header is
    #             valid but IFD0 overruns. Bundled still emits ExifByteOrder AND
    #             raises `Bad ExifIFD directory` (non-minor; $inMakerNotes=0). A
    #             clean TimeStamp precedes it (it still decodes).
    #   badmn   — a type-7 carrying a 0x927c (MakerNoteCanon) block whose TIFF is
    #             likewise bad. Bundled emits NO ExifByteOrder (the MakerNote
    #             re-dispatch never surfaces it) and raises the MINOR
    #             `[minor] Bad MakerNotes directory` ($inMakerNotes=1). Clean
    #             TimeStamp precedes it.
    badexif_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(0x8769, tiff_bad_ifd0())),
    ])
    write("QuickTime_canon_ctmd_badexif.mov", build_ctmd_mov([badexif_sample]))

    badmn_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(0x927c, tiff_bad_ifd0())),
    ])
    write("QuickTime_canon_ctmd_badmn.mov", build_ctmd_mov([badmn_sample]))

 # ── 0x927c with a bogus 0x8769 pointer ──────────────────────
    # A type-7 carrying a 0x927c (MakerNoteCanon) block whose READABLE IFD0 holds
    # a CanonFirmwareVersion AND a 0x8769 (ExifIFD-style) pointer with a bad
    # offset. `Canon::Main` has no 0x8769 key, so bundled NEVER follows it: IFD0
    # decodes (CanonFirmwareVersion "FW1.0.0") and NO `Bad ExifIFD directory`
    # warning is raised (oracle: `-ee -warning` emits NOTHING). Proves the 0x927c
    # diagnostics route through `Canon::Main` (no spurious nested Exif walk). A
    # clean TimeStamp precedes it.
    badmn_nested_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(0x927c, tiff_canon_makernote_with_exif_ptr(b"FW1.0.0"))),
    ])
    write("QuickTime_canon_ctmd_badmn_nested.mov", build_ctmd_mov([badmn_nested_sample]))

 # ── Partial-duplicate type-5 ExposureInfo ───────────────────
    # ONE sample: a FULL type-5 (FNumber 3.5, ExposureTime 1/80, ISO 12800), then
    # an 8-byte type-5 (FNumber 8.0 + ExposureTime 1/250, NO ISO), then a 4-byte
    # type-5 (FNumber 5.6 only). Bundled HandleTags each record; ProcessBinaryData
    # emits only the fields that fit the payload (ExifTool.pm:9917-9918) and
    # resolves duplicates PER tag name (ExifTool.pm:9514-9565). So bundled reports
    # FNumber 5.6 (the LAST record), ExposureTime 1/250 (the 8-byte record — the
    # 4-byte one omitted it) and ISO 12800 (the FULL record — neither partial
    # record carried it). A partial record must NOT clobber the sibling fields.
    partialdup_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(5, exposure_info_payload(35, 10, 1, 80, 12800)),  # full: 3.5 / 1/80 / 12800
        ctmd_record(5, struct.pack("<HHHH", 80, 10, 1, 250)),         # 8-byte: 8.0 / 1/250 (no ISO)
        ctmd_record(5, struct.pack("<HH", 56, 10)),                   # 4-byte: 5.6 only
    ])
    write("QuickTime_canon_ctmd_partialdup.mov", build_ctmd_mov([partialdup_sample]))

 # ── 0x8769 Model hand-off to a 0x927c model-conditional tag ───
    # ProcessExifInfo processes a sample's ExifInfo entries IN ORDER
    # (Canon.pm:10739-10751): a 0x8769 (ExifIFD) entry's IFD0 Model sets
    # $$self{Model}, and a LATER 0x927c (MakerNoteCanon) entry's Canon::Main decode
    # keys its MODEL-CONDITIONAL sub-tables on it. $$self{Model} is OBJECT-level
    # state — sticky across records AND across SAMPLES (oracle-verified vs bundled
    # 13.59). Two samples prove both:
    #   Doc1: 0x8769(Model="Canon EOS R5") THEN 0x927c(ShotInfo CameraTemperature
    #         raw=158). The handed-off EOS Model passes ShotInfo CameraTemperature's
    #         Condition ($$self{Model} =~ /EOS/ and !~ /EOS-1DS?$/, Canon.pm:2868),
    #         so bundled emits Doc1 CameraTemperature = 158-128 = "30 C". Without
    #         the handoff (emitter passing None) the tag would NOT appear.
    #   Doc2: 0x927c-only(ShotInfo CameraTemperature raw=200). NO 0x8769 in this
    #         sample, but $$self{Model} STAYS "Canon EOS R5" from Doc1, so bundled
    #         STILL emits Doc2 CameraTemperature = 200-128 = "72 C" — proving the
    #         cross-sample stickiness. (AutoISO=100 is model-AGNOSTIC, present in
    #         both as the discriminator's control.)
    # A clean TimeStamp precedes each ExifInfo block (it still decodes).
    model_sample0 = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(0x8769, tiff_exif_ifd_model(b"Canon EOS R5"))
                       + exif_info_entry(0x927c, tiff_canon_makernote_shotinfo(158))),
    ])
    model_sample1 = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(0x927c, tiff_canon_makernote_shotinfo(200))),
    ])
    write(
        "QuickTime_canon_ctmd_exifinfo_model.mov",
        build_ctmd_mov([model_sample0, model_sample1]),
    )

 # ── DUPLICATE IFD0 Model in ONE 0x8769 — last-wins hand-off ──
    # A hostile 0x8769 (ExifIFD) whose IFD0 carries TWO Model tags — a non-EOS
    # "Canon PowerShot S100" FIRST, then "Canon EOS R5" — followed by a 0x927c
    # (MakerNoteCanon) ShotInfo CameraTemperature (raw=158). Exif.pm:599's RawConv
    # `$$self{Model} = $val` runs EACH time, so the LAST (EOS) Model is in effect
    # when the 0x927c re-dispatches (last-wins). The EOS Model passes ShotInfo
    # CameraTemperature's Condition (`$$self{Model} =~ /EOS/`, Canon.pm:2868), so
    # bundled emits Doc1 CameraTemperature = 158-128 = "30 C" AND Model =
    # "Canon EOS R5" (the emitted tag is ALSO last-wins). Under the pre-R6
    # FIRST-wins capture the non-EOS PowerShot would win, the Condition would
    # FAIL, and CameraTemperature would be ABSENT — so this fixture is a direct
    # last-vs-first discriminator (oracle-verified vs bundled 13.59). One sample
    # (a clean TimeStamp precedes the ExifInfo block).
    dup_model_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(
            0x8769, tiff_exif_ifd_two_models(b"Canon PowerShot S100", b"Canon EOS R5"))
            + exif_info_entry(0x927c, tiff_canon_makernote_shotinfo(158))),
    ])
    write(
        "QuickTime_canon_ctmd_exifinfo_dupmodel.mov",
        build_ctmd_mov([dup_model_sample]),
    )

 # ── 0x927c per-entry value-offset warnings ──────────────────
    # The 0x927c MakerNoteCanon re-dispatch (ProcessTIFF → ProcessExif under
    # Canon::Main, $inMakerNotes=1) raises a per-entry value-offset warning for a
    # READABLE IFD0 whose Canon tag has a bad OUT-OF-LINE value pointer. Two
    # one-sample movies isolate each:
    #   badmnval — value pointer far past EOF ⇒ the no-RAF `Bad offset for
    #              $dir $tagStr` (Exif.pm:6660), $dir re-mapped to MakerNotes,
    #              $tagStr the Canon::Main name, MINOR: `[minor] Bad offset for
    #              MakerNotes CanonFirmwareVersion`. (overrun-by-size is the same
    #              warning, so this one case covers it.)
    #   badmnsusp — value pointer IN bounds but overlapping the directory ⇒ the
    #              `Suspicious $dir offset for $tagStr` (Exif.pm:6675), MINOR:
    #              `[minor] Suspicious MakerNotes offset for CanonFirmwareVersion`.
    # Both surface under the active Doc1:Track1 scope on the SAME priority-0
    # first-wins `Warning` channel as the ProcessCTMD/ExifInfo diagnostics; the
    # IFD0 directory itself parses, so NO `Bad MakerNotes directory`. A clean
    # TimeStamp precedes each (it still decodes). Oracle-verified vs bundled 13.59.
    badmnval_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(
            0x927c, tiff_canon_makernote_bad_value_offset(b"FW1.0.0"))),
    ])
    write("QuickTime_canon_ctmd_badmnval.mov", build_ctmd_mov([badmnval_sample]))

    badmnsusp_sample = b"".join([
        ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
        ctmd_record(7, exif_info_entry(
            0x927c, tiff_canon_makernote_suspicious_offset(b"FW1.0.0"))),
    ])
    write("QuickTime_canon_ctmd_badmnsusp.mov", build_ctmd_mov([badmnsusp_sample]))

 # ── IFD-tail / per-entry validation crafted edges ──
    # The CTMD re-dispatch's IFD-validation must reproduce ProcessExif's
    # directory-shape gate AND per-entry checks BYTE-EXACTLY, with the emission
    # SKIP and the WARNING driven by ONE shared predicate (they must never
    # disagree — the R8 bug). One one-sample movie per distinct shape; a clean
    # TimeStamp precedes each (it still decodes). Oracle-verified vs bundled
    # 13.59 (`-ee -G3:1 -j` / `-n`).
    def mn_sample(tiff: bytes) -> bytes:
        return b"".join([
            ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
            ctmd_record(7, exif_info_entry(0x927c, tiff)),
        ])

    # R8: a 0x927c IFD ending EXACTLY at the block boundary (0-byte tail) with a
    # suspicious (directory-overlapping) value offset. `$bytesFromEnd == 0` is
    # LEGAL, so the directory is walked and the suspect entry is reached ⇒
    # `[minor] Suspicious MakerNotes offset for CanonFirmwareVersion` (the prior
    # `dir_end + 4 <= data_len` gate suppressed this — the WARNING now agrees
    # with the emission SKIP).
    write("QuickTime_canon_ctmd_badmnsusp_tail0.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_susp_tail(b"FW1.0.0", 0))]))
    # The 2-byte-tail variant — `$bytesFromEnd == 2` is also LEGAL, same warning.
    write("QuickTime_canon_ctmd_badmnsusp_tail2.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_susp_tail(b"FW1.0.0", 2))]))
    # Illegal 1-/3-byte tails — `$bytesFromEnd` ∈ {1,3} ⇒ NON-minor `Illegal
    # MakerNotes directory size (1 entries)` + ABORT (no entry read).
    write("QuickTime_canon_ctmd_badmn_tail1.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_illegal_tail(b"FW1.0.0", 1))]))
    write("QuickTime_canon_ctmd_badmn_tail3.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_illegal_tail(b"FW1.0.0", 3))]))
    # Bad NONZERO format code on entry 0 ⇒ `[minor] Bad format (99) for
    # MakerNotes entry 0` + ABORT (no value).
    write("QuickTime_canon_ctmd_badmnfmt0.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_bad_format_entry0())]))
    # Valid entry 0 + bad-format entry 1 ⇒ CanonFirmwareVersion emits AND
    # `[minor] Bad format (99) for MakerNotes entry 1` (`next`-skip, NOT abort).
    write("QuickTime_canon_ctmd_badmnfmt1.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_bad_format_entry1(b"FW1.0.0"))]))
    # Count overflow (`size > 0x7fffffff`) ⇒ `[minor] Invalid size (4294967296)
    # for MakerNotes tag 0x0007 CanonFirmwareVersion` (the FIRST `$size > 4`
    # test, before the offset is read).
    write("QuickTime_canon_ctmd_badmnsize.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_invalid_size())]))

    # 0x8769 ExifIFD no-RAF: an OUT-OF-BOUNDS Make (entry 0) then a VALID inline
    # Software (entry 1). The no-RAF re-dispatch warns `Bad offset for ExifIFD
    # Make` (NON-minor) + CONTINUES ⇒ Software STILL decodes
    # (`Doc1:ExifIFD:Software`). A RAF-modeled walk would `Error reading value` +
    # abort, dropping Software — this fixture pins the no-RAF branch.
    write("QuickTime_canon_ctmd_badexifval.mov",
          build_ctmd_mov([
              b"".join([
                  ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
                  ctmd_record(7, exif_info_entry(0x8769, tiff_exif_ifd_oob_then_valid())),
              ])
          ]))

 # ── warnCount > 10 abort ────────────────────────────────────
    # ProcessExif aborts a directory once more than ten COUNTED per-entry
    # warnings accumulate: `if ($warnCount > 10) { Warn("Too many warnings --
    # $dir parsing aborted", 2) and return 0 }` (Exif.pm:6455-6456). The abort is
    # `Warn(..., 2)` ⇒ a capital-M `[Minor]` REGARDLESS of $inMakerNotes, and the
    # `return 0` suppresses every LATER entry + the next-IFD pointer. Two movies
    # isolate the two re-dispatch tables:
    #   warnmany_mn — a 0x927c MakerNoteCanon IFD0: valid CanonFirmwareVersion
    #     (entry 0), 12 bad-format entries (entries 1..12), then a valid OwnerName
    #     (entry 13). Bundled emits CanonFirmwareVersion, the first-distinct `Bad
    #     format (255) for MakerNotes entry 1`, and `[Minor] Too many warnings --
    #     MakerNotes parsing aborted`; OwnerName is suppressed.
    #   warnmany_exif — the 0x8769 ExifIFD ($inMakerNotes=0) counterpart: valid
    #     ExposureTime (entry 0), 12 bad-format entries, then a valid ISO. Bundled
    #     emits ExposureTime, `Bad format (255) for ExifIFD entry 1`, and `[Minor]
    #     Too many warnings -- ExifIFD parsing aborted`; ISO is suppressed.
    # A clean TimeStamp precedes each (it still decodes). Oracle-verified vs
    # bundled 13.59 (`-ee -G3:1 -j` / `-n`).
    write("QuickTime_canon_ctmd_warnmany_mn.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_many_warnings(b"FW1.0.0"))]))
    write("QuickTime_canon_ctmd_warnmany_exif.mov",
          build_ctmd_mov([
              b"".join([
                  ctmd_record(1, time_stamp_payload(2018, 2, 21, 12, 8, 56, 21)),
                  ctmd_record(7, exif_info_entry(0x8769, tiff_exif_ifd_many_warnings(1, 80, 400))),
              ])
          ]))

    # ── R9-2: drop the synthetic zero-entry / >1024 directory rejects ────────
    # ProcessExif (Exif.pm:6343-6400) has NO zero-entry or maximum-count special
    # case — it is bounded only by `$dirEnd <= $dataLen` + the 0/1/2/3/>=4 tail
    # rule. Two movies pin the two ends:
    #   zero_tail1/3 — a 0x927c IFD0 declaring ZERO entries with a 1- or 3-byte
    #     tail ⇒ the NON-minor `Illegal MakerNotes directory size (0 entries)`
    #     (Exif.pm:6397) + abort. (The pre-R9-2 `num_entries == 0` reject would
    #     have swallowed this legitimate warning.)
    #   manyentries — a 0x927c IFD0 with 1100 (> 1024) VALID in-bounds entries ⇒
    #     bundled WALKS them all (the first decodes CanonFirmwareVersion; the rest
    #     are same-ID last-wins duplicates), NO warning. The pre-R9-2
    #     `MAX_SANE_ENTRIES = 1024` gate dropped the whole directory.
    # A clean TimeStamp precedes each. Oracle-verified vs bundled 13.59.
    write("QuickTime_canon_ctmd_badmn_zero_tail1.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_zero_entries(1))]))
    write("QuickTime_canon_ctmd_badmn_zero_tail3.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_zero_entries(3))]))
    write("QuickTime_canon_ctmd_mn_manyentries.mov",
          build_ctmd_mov([mn_sample(tiff_canon_makernote_many_entries(1100))]))


if __name__ == "__main__":
    main()
