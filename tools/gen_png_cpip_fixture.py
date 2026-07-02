#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal PNG fixture for the `cpIp` OLE compound-document decoder —
# issue #142 (PNG `cpIp` -> FlashPix `ProcessFPX`):
#
#   cpIp (PNG.pm:354-367) — "OLE information found in PNG Plus images written by
#   Picture It!". The chunk payload is a Windows Compound Binary File (an OLE
#   compound document: `d0cf11e0a1b11ae1` signature, 512-byte sectors, a FAT, a
#   directory tree, and a mini-FAT for small streams). PNG.pm routes it to
#   `Image::ExifTool::FlashPix::ProcessFPX` on the `%FlashPix::Main` table, and
#   its `Condition` mutates `File:FileType` from `PNG` to `PNG Plus`.
#
# This fixture is a HAND-BUILT minimal OLE (NOT ExifTool's full `FlashPix.ppt`),
# to bound the property-table scope to exactly the two summary-property tables the
# port covers — `%FlashPix::SummaryInfo` and `%FlashPix::DocumentInfo` — without
# dragging in the UserDefined dictionary, `_PID_HLINKS` hyperlinks, the
# `Current User` stream, mixed VT_VECTOR arrays, or code-page charset decoding.
#
# The OLE layout (4 main sectors, 512 bytes each, after the 512-byte header):
#   sector 0  mini-stream  (8 x 64-byte mini-sectors; holds the two property sets)
#   sector 1  mini-FAT     (mini-sector allocation table)
#   sector 2  directory    (4 x 128-byte entries: Root, Summary, DocSummary, free)
#   sector 3  FAT          (main-sector allocation table)
# Both property streams are < the 4096-byte mini-stream cutoff, so they live in
# the mini-FAT (exercising the mini-FAT read path in the golden). Everything is
# little-endian (`II`).
#
# The two property sets (all values ASCII / no code page, so no charset decode):
#   \x05SummaryInformation:
#     0x02 Title=VT_LPSTR "title"    0x04 Author=VT_LPSTR "author"
#     0x09 RevisionNumber=VT_LPSTR "1"  (EscapeJSON renders the string "1" bare)
#     0x0c CreateDate=VT_FILETIME 2007:02:09 16:23:23 (FILETIME->date path)
#     0x0f Words=VT_I4 4
#   \x05DocumentSummaryInformation:
#     0x02 Category=VT_LPSTR "category"   0x07 Slides=VT_I4 1
#
# Oracle (bundled ExifTool 13.59, `perl exiftool -j -G1 -struct`):
#   PNG_cpip.png -> File:FileType="PNG Plus", FlashPix:Title="title",
#     FlashPix:Author="author", FlashPix:RevisionNumber=1,
#     FlashPix:CreateDate="2007:02:09 16:23:23", FlashPix:Words=4,
#     FlashPix:Category="category", FlashPix:Slides=1
#
# The IHDR + IDAT (a deflated 1x1 RGB scanline) match PNG_meta.png / PNG_seal.png
# byte-for-byte, so this crafted PNG is part of the same family (and carries the
# ported Composite:ImageSize/Megapixels like every 1x1 PNG fixture).
#
# Usage: python3 tools/gen_png_cpip_fixture.py [OUTDIR]   (OUTDIR default: tests/fixtures)
# Regenerate the golden after: EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cpip.png
import calendar
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
IDAT_DATA = bytes.fromhex("789c63606060000000040001")  # deflated 1x1 RGB scanline

# ---- OLE sector-type sentinels (FlashPix.pm:43-46) --------------------------
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD

SECT = 512  # sector size (1 << 9)
MINI = 64  # mini-sector size (1 << 6)
MINI_CUTOFF = 4096


def u16(n: int) -> bytes:
    return struct.pack("<H", n)


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


def u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def png_chunk(typ: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def ihdr_1x1_rgb() -> bytes:
    return png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))


# ---- OLE property-set (ProcessProperties, FlashPix.pm:1691) -----------------
# A value is `[type u32][value bytes]`; ReadFPXValue (FlashPix.pm:1282) decodes it.
def val_lpstr(s: str):  # VT_LPSTR (type 30): [count u32][string+NUL, padded to 4]
    sb = s.encode("ascii") + b"\x00"
    pad = (-len(sb)) % 4
    return 30, u32(len(sb)) + sb + b"\x00" * pad


def val_i4(n: int):  # VT_I4 (type 3): int32s
    return 3, struct.pack("<i", n)


def val_filetime(unix_seconds: int):  # VT_FILETIME (type 64): 100ns since 1601
    ft = (unix_seconds + 11644473600) * 10_000_000
    return 64, u64(ft)


def build_section(props) -> bytes:
    # [size u32][numProps u32][(id u32, offset u32) * n][ [type u32][value] * n ]
    # `offset` is relative to the SECTION start and points to each `[type][value]`.
    n = len(props)
    header_len = 8 + 8 * n
    pairs = b""
    values = b""
    offset = header_len
    for pid, tc, vb in props:
        pairs += u32(pid) + u32(offset)
        prop = u32(tc) + vb
        values += prop
        offset += len(prop)
    body = pairs + values
    return u32(8 + len(body)) + u32(n) + body


def build_property_set(section: bytes, fmtid: bytes) -> bytes:
    # header (48 bytes): BOM=0xFFFE, version, OSver, CLSID, numPropSets=1,
    # FMTID, section-offset. Byte 44 (0x2C) is the offset ExifTool reads.
    section_offset = 48
    header = (
        u16(0xFFFE)
        + u16(0)
        + u32(0)
        + b"\x00" * 16
        + u32(1)
        + fmtid
        + u32(section_offset)
    )
    assert len(header) == 48
    return header + section


# FMTIDs are cosmetic here (ExifTool dispatches by stream NAME, not FMTID) but
# use the canonical GUIDs for realism.
FMTID_SUMMARY = bytes.fromhex("e085 9ff2 f94f 6810 ab91 0800 2b27 b3d9".replace(" ", ""))
FMTID_DOCSUMMARY = bytes.fromhex("02d5 cdd5 9c2e 1b10 9397 0800 2b2c f9ae".replace(" ", ""))


def pad_mini(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % MINI)


# ---- OLE directory entry (128 bytes, FlashPix.pm:2167-2217) -----------------
def dir_entry(name: str, etype: int, color: int, left: int, right: int, child: int,
              start: int, size: int) -> bytes:
    nb = name.encode("utf-16-le") + b"\x00\x00"  # UTF-16LE + NUL terminator
    name_field = nb + b"\x00" * (64 - len(nb))
    e = (
        name_field
        + u16(len(nb))          # 0x40 name length in bytes (incl NUL)
        + bytes([etype])        # 0x42 object type
        + bytes([color])        # 0x43 color (0=red,1=black)
        + u32(left)             # 0x44 left sibling
        + u32(right)            # 0x48 right sibling
        + u32(child)            # 0x4C child
        + b"\x00" * 16          # 0x50 CLSID
        + u32(0)                # 0x60 state bits
        + u64(0) + u64(0)       # 0x64/0x6C creation/modified time
        + u32(start)            # 0x74 starting sector (mini-sector for streams)
        + u64(size)             # 0x78 stream size
    )
    assert len(e) == 128, len(e)
    return e


def build_ole() -> bytes:
    unix = calendar.timegm((2007, 2, 9, 16, 23, 23, 0, 0, 0))
    summary = build_property_set(
        build_section([
            (0x02, *val_lpstr("title")),
            (0x04, *val_lpstr("author")),
            (0x09, *val_lpstr("1")),
            (0x0C, *val_filetime(unix)),
            (0x0F, *val_i4(4)),
        ]),
        FMTID_SUMMARY,
    )
    docsummary = build_property_set(
        build_section([
            (0x02, *val_lpstr("category")),
            (0x07, *val_i4(1)),
        ]),
        FMTID_DOCSUMMARY,
    )

    # Lay the two property sets into the mini-stream as consecutive runs of
    # 64-byte mini-sectors, and build their mini-FAT chains.
    s_ms = pad_mini(summary)
    d_ms = pad_mini(docsummary)
    n_s = len(s_ms) // MINI
    n_d = len(d_ms) // MINI
    assert n_s + n_d <= SECT // MINI, "property sets exceed one mini-stream sector"
    mini_stream = pad_mini(s_ms + d_ms)  # sector 0 (<= 512 bytes)
    mini_stream = mini_stream + b"\x00" * (SECT - len(mini_stream))

    minifat = [FREESECT] * (SECT // 4)
    for i in range(n_s):  # Summary chain: 0 -> 1 -> ... -> ENDOFCHAIN
        minifat[i] = i + 1 if i + 1 < n_s else ENDOFCHAIN
    for i in range(n_d):  # DocSummary chain starts at mini-sector n_s
        j = n_s + i
        minifat[j] = j + 1 if i + 1 < n_d else ENDOFCHAIN
    minifat_sect = b"".join(u32(x) for x in minifat)

    directory = (
        dir_entry("Root Entry", 5, 1, FREESECT, FREESECT, 1, 0, (n_s + n_d) * MINI)
        + dir_entry("\x05SummaryInformation", 2, 1, FREESECT, 2, FREESECT, 0, len(summary))
        + dir_entry("\x05DocumentSummaryInformation", 2, 1, FREESECT, FREESECT, FREESECT, n_s, len(docsummary))
        + b"\x00" * 128  # unused entry (type 0)
    )
    assert len(directory) == SECT

    fat = [FREESECT] * (SECT // 4)
    fat[0] = ENDOFCHAIN  # mini-stream (sector 0)
    fat[1] = ENDOFCHAIN  # mini-FAT (sector 1)
    fat[2] = ENDOFCHAIN  # directory (sector 2)
    fat[3] = FATSECT     # FAT itself (sector 3)
    fat_sect = b"".join(u32(x) for x in fat)

    difat = [3] + [FREESECT] * 108  # 109 header DIFAT entries; DIFAT[0]=FAT sector 3
    header = (
        bytes.fromhex("d0cf11e0a1b11ae1")     # 0x00 signature
        + b"\x00" * 16                          # 0x08 CLSID
        + u16(0x003E)                           # 0x18 minor version
        + u16(0x0003)                           # 0x1A major version (v3)
        + u16(0xFFFE)                           # 0x1C byte order (little-endian)
        + u16(9)                                # 0x1E sector shift (512)
        + u16(6)                                # 0x20 mini-sector shift (64)
        + b"\x00" * 6                           # 0x22 reserved
        + u32(0)                                # 0x28 num dir sectors (0 for v3)
        + u32(1)                                # 0x2C num FAT sectors
        + u32(2)                                # 0x30 first dir sector
        + u32(0)                                # 0x34 transaction sig
        + u32(MINI_CUTOFF)                      # 0x38 mini-stream cutoff
        + u32(1)                                # 0x3C first mini-FAT sector
        + u32(1)                                # 0x40 num mini-FAT sectors
        + u32(ENDOFCHAIN)                       # 0x44 first DIFAT sector
        + u32(0)                                # 0x48 num DIFAT sectors
        + b"".join(u32(x) for x in difat)       # 0x4C DIFAT (109 * 4 = 436)
    )
    assert len(header) == SECT, len(header)
    return header + mini_stream + minifat_sect + directory + fat_sect


def build_png() -> bytes:
    return (
        SIG
        + ihdr_1x1_rgb()
        + png_chunk(b"cpIp", build_ole())
        + png_chunk(b"IDAT", IDAT_DATA)
        + png_chunk(b"IEND", b"")
    )


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else None
    if outdir is None:
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        outdir = os.path.join(repo, "tests", "fixtures")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "PNG_cpip.png")
    with open(path, "wb") as f:
        f.write(build_png())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
