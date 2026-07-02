#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the PNG `cpIp` OLE fixture that exercises the DocumentSummaryInformation
# UserDefined property-dictionary section — issue #484 (FlashPix ProcessProperties
# 2-section loop, FlashPix.pm:1716-1811).
#
# Unlike `tools/gen_png_cpip_fixture.py` (`PNG_cpip.png`, single-section streams
# only), this fixture's `\x05DocumentSummaryInformation` stream carries TWO
# property sections:
#   * Section 1 (predefined `%FlashPix::DocumentInfo`): Company (PID 0x0f),
#     Slides (PID 0x07).
#   * Section 2 (UserDefined): a PID-0 property DICTIONARY naming custom PIDs
#     {2 => "MyCustomProp", 3 => "test prop", 4 => "_PID_LINKBASE",
#      5 => "_PID_HLINKS"}, plus the custom properties PID 2 = VT_LPSTR
#     "customvalue", PID 3 = VT_I4 42, PID 4 = VT_BLOB (UTF-16LE hyperlink base),
#     PID 5 = VT_BLOB (a hyperlink VT_VARIANT array).
# The `%FlashPix::Main` `DocumentInfo` entry sets `Multi => 1` (FlashPix.pm:179),
# so ExifTool loops into the 2nd section and reads the dictionary (FlashPix.pm:
# 1738-1759). PIDs 2/3 have non-colliding names → emit under their MANGLED
# dictionary names (`FlashPix:MyCustomProp`, `FlashPix:TestProp`; "test prop" →
# uppercase first-of-word + drop the space → "TestProp"). PIDs 4/5 name the
# predefined DocumentInfo STRING keys `_PID_LINKBASE`/`_PID_HLINKS`
# (FlashPix.pm:521-528) → the raw name collides with the table (`next if
# $$tagTablePtr{$name}` + the `$$tagTablePtr{$tag}` re-dispatch) so they emit the
# PREDEFINED `FlashPix:HyperlinkBase` (UTF-16 ValueConv) and `FlashPix:Hyperlinks`
# (ProcessHyperlinks RawConv), NOT mangled custom names.
#
# A single-section `\x05SummaryInformation` (Title/Author) rides alongside to
# confirm the single-section path still works next to the 2-section stream.
#
# Oracle (bundled ExifTool 13.59, `perl exiftool -j -G1 -struct`):
#   File:FileType="PNG Plus", FlashPix:Title="udtitle", FlashPix:Author="udauthor",
#   FlashPix:Company="acme", FlashPix:Slides=3,
#   FlashPix:MyCustomProp="customvalue", FlashPix:TestProp=42,
#   FlashPix:HyperlinkBase="http://example.com/base/",
#   FlashPix:Hyperlinks=["http://example.com/page.htm#section1",
#                        "mailto:test@example.com"]
#
# The IHDR + IDAT match PNG_cpip.png / PNG_meta.png / PNG_seal.png byte-for-byte,
# so this crafted PNG is part of the same 1x1-RGB family (carries the ported
# Composite:ImageSize/Megapixels).
#
# Usage: python3 tools/gen_png_cpip_userdef_fixture.py [OUTDIR]  (default:
#        tests/fixtures). Regenerate the golden after:
#        EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cpip_userdef.png
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
def val_lpstr(s: str):  # VT_LPSTR (type 30): [count u32][string+NUL, padded to 4]
    sb = s.encode("ascii") + b"\x00"
    pad = (-len(sb)) % 4
    return 30, u32(len(sb)) + sb + b"\x00" * pad


def val_i4(n: int):  # VT_I4 (type 3): int32s
    return 3, struct.pack("<i", n)


def val_dictionary(entries):
    # The property DICTIONARY (PID 0): the "type" field is the entry count and the
    # value bytes are `[PID u32][nameLen u32][name+NUL]` tuples with NO inter-entry
    # padding (ExifTool advances `$valPos += 8 + $len`, FlashPix.pm:1745).
    vb = b""
    for pid, name in entries:
        nb = name.encode("ascii") + b"\x00"  # NUL terminator, counted in nameLen
        vb += u32(pid) + u32(len(nb)) + nb
    return len(entries), vb  # type field = entry count


def val_blob(blob):  # VT_BLOB (type 65): [len u32][bytes, padded to 4]
    pad = (-len(blob)) % 4
    return 65, u32(len(blob)) + blob + b"\x00" * pad


def vt_variant_lpwstr(s):
    # A VT_VARIANT element of sub-type VT_LPWSTR (31): [subType u32][count u32]
    # [utf16le + NUL, padded to 4]. `count` is the WORD count (ReadFPXValue
    # multiplies VT_LPWSTR by 2, FlashPix.pm:1374).
    wb = s.encode("utf-16-le") + b"\x00\x00"  # NUL terminator (2 bytes)
    pad = (-len(wb)) % 4
    return u32(31) + u32(len(wb) // 2) + wb + b"\x00" * pad


def vt_variant_i4(n):  # a VT_VARIANT element of sub-type VT_I4 (3)
    return u32(3) + struct.pack("<i", n)


def val_hlinks(links):
    # `_PID_HLINKS` VT_BLOB: [num u32][VT_VARIANT * num] (ProcessHyperlinks,
    # FlashPix.pm:1251). Each hyperlink is a group of 6 VT_VARIANTs; only element 4
    # (address) and element 5 (subaddress) are extracted.
    body = u32(len(links) * 6)
    for addr, sub in links:
        body += vt_variant_i4(0)         # 0 hlink1 (ignored)
        body += vt_variant_i4(0)         # 1 hlink2 (ignored)
        body += vt_variant_lpwstr("")    # 2 (ignored)
        body += vt_variant_lpwstr("")    # 3 (ignored)
        body += vt_variant_lpwstr(addr)  # 4 address
        body += vt_variant_lpwstr(sub)   # 5 subaddress
    return val_blob(body)


def val_linkbase(s):
    # `_PID_LINKBASE` VT_BLOB holding a UTF-16LE string; the ValueConv decodes it
    # as `Decode($val, "UTF16", "II")` (FlashPix.pm:523).
    return val_blob(s.encode("utf-16-le") + b"\x00\x00")


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
    # Single-section header (48 bytes): BOM=0xFFFE, version, OSver, CLSID,
    # numPropSets=1, FMTID, section-offset. Byte 44 is the offset ExifTool reads.
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


def build_two_section_property_set(sec1: bytes, sec2: bytes, fmtid1: bytes,
                                   fmtid2: bytes) -> bytes:
    # Two-section header (68 bytes): the 28-byte common header + TWO (FMTID,
    # offset) descriptors. ExifTool reads ONLY byte 44 (offset[0]) then advances
    # `$pos += $size` to the 2nd section (FlashPix.pm:1811), so offset[1] must be
    # offset[0] + len(sec1) for a well-formed set.
    off1 = 28 + 2 * (16 + 4)  # = 68
    header = (
        u16(0xFFFE)
        + u16(0)
        + u32(0)
        + b"\x00" * 16
        + u32(2)          # num property sets
        + fmtid1
        + u32(off1)       # section 1 offset (byte 44)
        + fmtid2
        + u32(off1 + len(sec1))  # section 2 offset
    )
    assert len(header) == off1, len(header)
    return header + sec1 + sec2


# FMTIDs are cosmetic here (ExifTool dispatches by stream NAME) but use the
# canonical GUIDs for realism.
FMTID_SUMMARY = bytes.fromhex("e085 9ff2 f94f 6810 ab91 0800 2b27 b3d9".replace(" ", ""))
FMTID_DOCSUMMARY = bytes.fromhex("02d5 cdd5 9c2e 1b10 9397 0800 2b2c f9ae".replace(" ", ""))
# The UserDefined section's FMTID (FMTID_UserDefinedProperties).
FMTID_USERDEFINED = bytes.fromhex("05d5 cdd5 9c2e 1b10 9397 0800 2b2c f9ae".replace(" ", ""))


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
    summary = build_property_set(
        build_section([
            (0x02, *val_lpstr("udtitle")),
            (0x04, *val_lpstr("udauthor")),
        ]),
        FMTID_SUMMARY,
    )
    # DocumentSummaryInformation with a predefined section 1 + a UserDefined
    # section 2 (dictionary + custom PIDs).
    sec1 = build_section([
        (0x0F, *val_lpstr("acme")),  # Company
        (0x07, *val_i4(3)),          # Slides
    ])
    sec2 = build_section([
        (0x00, *val_dictionary([
            (2, "MyCustomProp"), (3, "test prop"),
            (4, "_PID_LINKBASE"), (5, "_PID_HLINKS"),
        ])),
        (0x02, *val_lpstr("customvalue")),  # -> FlashPix:MyCustomProp (mangled)
        (0x03, *val_i4(42)),                # -> FlashPix:TestProp (mangled)
        (0x04, *val_linkbase("http://example.com/base/")),  # -> HyperlinkBase
        (0x05, *val_hlinks([                                # -> Hyperlinks
            ("http://example.com/page.htm", "section1"),
            ("mailto:test@example.com", ""),
        ])),
    ])
    docsummary = build_two_section_property_set(
        sec1, sec2, FMTID_DOCSUMMARY, FMTID_USERDEFINED
    )

    # Lay the two property sets into the mini-stream as consecutive runs of
    # 64-byte mini-sectors, and build their mini-FAT chains. The mini-stream now
    # spans as many 512-byte sectors as its total mini-sector count requires.
    s_ms = pad_mini(summary)
    d_ms = pad_mini(docsummary)
    n_s = len(s_ms) // MINI
    n_d = len(d_ms) // MINI
    mini_stream = pad_mini(s_ms + d_ms)
    ms_sectors = max(1, (len(mini_stream) + SECT - 1) // SECT)
    mini_stream = mini_stream + b"\x00" * (ms_sectors * SECT - len(mini_stream))

    minifat_entries = [FREESECT] * (SECT // 4)
    for i in range(n_s):  # Summary chain: 0 -> 1 -> ... -> ENDOFCHAIN
        minifat_entries[i] = i + 1 if i + 1 < n_s else ENDOFCHAIN
    for i in range(n_d):  # DocSummary chain starts at mini-sector n_s
        j = n_s + i
        minifat_entries[j] = j + 1 if i + 1 < n_d else ENDOFCHAIN
    assert n_s + n_d <= SECT // 4, "mini-FAT exceeds one sector"
    minifat_sect = b"".join(u32(x) for x in minifat_entries)

    # Sector layout: [mini-stream x ms_sectors][mini-FAT][directory][FAT].
    minifat_start = ms_sectors
    dir_start = minifat_start + 1
    fat_start = dir_start + 1

    directory = (
        dir_entry("Root Entry", 5, 1, FREESECT, FREESECT, 1, 0, (n_s + n_d) * MINI)
        + dir_entry("\x05SummaryInformation", 2, 1, FREESECT, 2, FREESECT, 0, len(summary))
        + dir_entry("\x05DocumentSummaryInformation", 2, 1, FREESECT, FREESECT, FREESECT, n_s, len(docsummary))
        + b"\x00" * 128  # unused entry (type 0)
    )
    assert len(directory) == SECT

    fat = [FREESECT] * (SECT // 4)
    for i in range(ms_sectors):  # the mini-stream's main-FAT chain
        fat[i] = i + 1 if i + 1 < ms_sectors else ENDOFCHAIN
    fat[minifat_start] = ENDOFCHAIN  # mini-FAT
    fat[dir_start] = ENDOFCHAIN      # directory
    fat[fat_start] = FATSECT         # FAT itself
    fat_sect = b"".join(u32(x) for x in fat)

    difat = [fat_start] + [FREESECT] * 108  # 109 header DIFAT entries; DIFAT[0]=FAT
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
        + u32(dir_start)                        # 0x30 first dir sector
        + u32(0)                                # 0x34 transaction sig
        + u32(MINI_CUTOFF)                      # 0x38 mini-stream cutoff
        + u32(minifat_start)                    # 0x3C first mini-FAT sector
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
    path = os.path.join(outdir, "PNG_cpip_userdef.png")
    with open(path, "wb") as f:
        f.write(build_png())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
