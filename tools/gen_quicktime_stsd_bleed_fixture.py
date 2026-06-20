#!/usr/bin/env python3
"""Build the crafted multi-entry `stsd` fixed-field BLEED `.mov` fixture
(`QuickTime_stsd_fixed_field_bleed.mov`).

This pins exifast's faithful port of ExifTool's ProcessHybrid + ProcessBinaryData
fixed-field read over the WHOLE `stsd` box (#302). For a `vide`/`soun`
sample-description entry ExifTool reads each fixed field at the ABSOLUTE box
position `substr($$dataPt, off + dirStart, ...)` within
`$size = min($$dirInfo{DirLen}, dataLen - dirStart)`, where `DirLen` is the
ProcessHybrid child boundary (an ABSOLUTE box offset, QuickTime.pm:9680) clamped
by `maxLen` (ExifTool.pm:9889). Because `$size` is compared against the
entry-RELATIVE field offset, a NON-LAST entry (`dirStart > 8`) whose child
boundary exceeds its own extent reads a fixed field PAST the entry end — it
BLEEDS into the following entries' bytes.

The `vide` track's `stsd` carries THREE entries:

  * entry1 = a full 86-byte `avc1` (FIRST entry, `dirStart` 8 ⇒ no bleed): supplies
    `CompressorName "CompA"` (no later entry overrides it).
  * entry2 = a SHORT 36-byte `hvc1` with a single 20-byte child atom, so the
    ProcessHybrid child boundary is entry-relative offset 16 ⇒
    `DirLen = dirStart(94) + 16 = 110`, clamped by `maxLen = 194 - 94 = 100` ⇒
    `$size = 100`. Its `BitDepth` (entry-relative 82) satisfies `82 + 2 <= 100`,
    so ExifTool reads `payload[94+82 .. 94+84] = payload[176..178]` — which lands
    INSIDE entry3 (the cross-entry bleed). `0xBEEF` is planted there ⇒
    `BitDepth = 48879`.
  * entry3 = a 64-byte `avc3` (the LAST entry) with `0xBEEF` at entry-relative
    offset 46 (= box offset 176). Its own `BitDepth` (82) is past its 64-byte
    extent (`$size == 64`) and is omitted, so entry2's bled `48879` is the
    last-wins value emitted as `Track1:BitDepth`.

Verified byte-exact vs bundled ExifTool 13.59:
    exiftool -j -G1 -> Track1:BitDepth 48879, CompressorID avc3,
                       CompressorName CompA, SourceImageWidth/Height 200,
                       XResolution/YResolution 72.

System:/Composite: are excluded (the QuickTime Composite/System subsystem is a
deferred Phase-2 forward item), matching the MOV golden precedent.

  python3 tools/gen_quicktime_stsd_bleed_fixture.py            # -> tests/fixtures/
  python3 tools/gen_quicktime_stsd_bleed_fixture.py <outdir>

After running, regenerate the goldens with the bundled ExifTool:
  EXIFTOOL=/path/exiftool EXCLUDE="-x System:all -x Composite:all" \
    tools/gen_golden.sh QuickTime_stsd_fixed_field_bleed.mov
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def vide_entry_full(comp_id, w, h, comp_name, bit_depth, length, beef_at=None):
    """A full `vide` sample entry of `length` bytes with the standard
    %VisualSampleDesc fixed fields. `beef_at` plants `0xBEEF` at the given
    entry-relative offset (used to mark where a PRIOR entry's bled field lands)."""
    e = bytearray(length)
    struct.pack_into(">I", e, 0, length)
    e[4:8] = comp_id
    if length > 34:
        struct.pack_into(">H", e, 32, w)
        struct.pack_into(">H", e, 34, h)
    if length > 40:
        struct.pack_into(">I", e, 36, 72 << 16)
        struct.pack_into(">I", e, 40, 72 << 16)
    if length > 50 and comp_name:
        e[50] = len(comp_name)
        e[51:51 + len(comp_name)] = comp_name
    if length > 82:
        struct.pack_into(">H", e, 82, bit_depth)
    if beef_at is not None:
        e[beef_at:beef_at + 2] = b"\xBE\xEF"
    return bytes(e)


def vide_entry_short_with_child(comp_id, body_len):
    """A SHORT `vide` entry: `[size:4][format:4]` then a single child atom filling
    `[16 .. body_len]`, so ProcessHybrid finds a child boundary at entry-relative
    offset 16 (< the entry end). The fixed fields past 16 are then read OVER THE
    WHOLE box up to `maxLen` — the bleed."""
    # 16-byte fixed prefix ([size][format][reserved:6][dref:2]) then the child.
    fixed = bytearray(16)
    struct.pack_into(">I", fixed, 0, body_len)
    fixed[4:8] = comp_id
    child_len = body_len - 16
    child = struct.pack(">I", child_len) + b"glbl" + b"\x00" * (child_len - 8)
    e = bytes(fixed) + child
    assert len(e) == body_len, (len(e), body_len)
    return e


def build_mov(entries) -> bytes:
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))
    sample = b"\x00"
    mdat = struct.pack(">I", len(sample) + 8) + b"mdat" + sample
    sample_base = len(ftyp) + 8
    mvhd_body = (b"\x00\x00\x00\x00" + b"\x00" * 8 + struct.pack(">I", 1000)
                 + struct.pack(">I", 1000) + b"\x00" * 80)
    hdlr_body = b"\x00\x00\x00\x00" + b"mhlr" + b"vide" + b"\x00" * 12 + b"\x00"
    mdhd_body = (b"\x00\x00\x00\x00" + b"\x00" * 8 + struct.pack(">I", 1000)
                 + struct.pack(">I", 1000) + b"\x00" * 4)
    stsd_body = b"\x00\x00\x00\x00" + struct.pack(">I", len(entries)) + b"".join(entries)
    stts_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + struct.pack(">II", 1, 1000)
    stsc_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + struct.pack(">III", 1, 1, 1)
    stsz_body = b"\x00\x00\x00\x00" + struct.pack(">I", 0) + struct.pack(">I", 1) + struct.pack(">I", 1)
    stco_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + struct.pack(">I", sample_base)
    stbl = atom(b"stbl", atom(b"stsd", stsd_body) + atom(b"stts", stts_body)
                + atom(b"stsc", stsc_body) + atom(b"stsz", stsz_body) + atom(b"stco", stco_body))
    minf = atom(b"minf", atom(b"vmhd", b"\x00\x00\x00\x01" + b"\x00" * 8) + stbl)
    mdia = atom(b"mdia", atom(b"mdhd", mdhd_body) + atom(b"hdlr", hdlr_body) + minf)
    trak = atom(b"trak", atom(b"tkhd", b"\x00" * 84) + mdia)
    moov = atom(b"moov", atom(b"mvhd", mvhd_body) + trak)
    return ftyp + mdat + moov


def main() -> None:
    outdir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tests",
            "fixtures",
        )
    )
    os.makedirs(outdir, exist_ok=True)

    # stsd body layout: header 8, entry1 @8 (86B), entry2 @94 (36B), entry3 @130
    # (64B); total 194. entry2's BitDepth (rel 82) bleeds to box offset 176 =
    # entry3-relative 46, where 0xBEEF is planted.
    e1 = vide_entry_full(b"avc1", 100, 100, b"CompA", 24, 86)
    e2 = vide_entry_short_with_child(b"hvc1", 36)
    e3 = vide_entry_full(b"avc3", 200, 200, b"", 48, 64, beef_at=46)
    data = build_mov([e1, e2, e3])
    path = os.path.join(outdir, "QuickTime_stsd_fixed_field_bleed.mov")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
