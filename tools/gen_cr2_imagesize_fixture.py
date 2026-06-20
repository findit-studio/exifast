#!/usr/bin/env python3
"""Generate the crafted CR2 ImageSize-deferral fixture (#133 Finding 2).

A minimal Canon CR2: a little-endian TIFF whose header carries the `CR\\x02\\0`
magic at byte 8 (ExifTool.pm:8636-8641 → `$fileType = 'CR2'`, so
`File:FileType = CR2`). IFD0 declares `ImageWidth`/`ImageHeight` that DIFFER from
the ExifIFD's `ExifImageWidth`/`ExifImageHeight`. ExifTool's
`Composite:ImageSize` (Exif.pm:4759) takes its `$$self{TIFF_TYPE} =~
/^(CR2|...)$/`-gated branch and emits `ExifImageWidth x ExifImageHeight` for a
CR2 — so a faithful reader must NOT use `ImageWidth`/`ImageHeight` here.

exifast's Composite post-pass has no `TIFF_TYPE` handle (`File:FileType` is
finalized at the JSON-orchestration layer, after the composite pass), so it
DEFERS all composites for the CR2/IIQ/EIP/Canon-1D-RAW RAW subtypes (option b).
The golden is generated `-x Composite:all` (the documented deferral); the
conformance test asserts exifast emits NO `Composite:ImageSize`/`Megapixels`,
byte-matching that golden — and that it does NOT emit the WRONG
`ImageWidth`-based size.

The CR2 raw-IFD pointer at bytes 12-15 is set to 0 (no raw IFD): ExifTool reads
it but a 0 offset yields no extra directory, keeping the fixture minimal.
"""
import struct
import sys

# TIFF format codes.
SHORT = 3
LONG = 4
RATIONAL = 5
ASCII = 2
UNDEF = 7

BO = "<"  # little-endian (II), matching the real CanonRaw.cr2


def entry(tag, fmt, count, value_or_offset):
    return struct.pack(BO + "HHI", tag, fmt, count) + struct.pack(
        BO + "I", value_or_offset
    )


def make_cr2():
    # Layout: 16-byte CR2 header, then IFD0, then ExifIFD, then the value pool.
    # IFD0 starts at byte 16 (the header's IFD0 offset and the CR2 minimum).
    ifd0_off = 16

    # IFD0 entries (in ascending-tag order, as TIFF requires).
    #   0x0100 ImageWidth = 100   (DIFFERS from ExifImageWidth)
    #   0x0101 ImageHeight = 80   (DIFFERS from ExifImageHeight)
    #   0x010f Make = "Canon\0"   (CR2 dispatch wants Canon)
    #   0x0110 Model = "Canon EOS\0"
    #   0x8769 ExifOffset -> ExifIFD
    ifd0_entries = [
        (0x0100, SHORT, 1, 100),
        (0x0101, SHORT, 1, 80),
        (0x010F, ASCII, 6, "make"),
        (0x0110, ASCII, 10, "model"),
        (0x8769, LONG, 1, "exififd"),
    ]
    # ExifIFD entries:
    #   0x829a ExposureTime = 1/160   (so Composite:ShutterSpeed could build)
    #   0x829d FNumber = 4/1
    #   0xa002 ExifImageWidth = 200   (the value the CR2 ImageSize branch uses)
    #   0xa003 ExifImageHeight = 160
    exif_entries = [
        (0x829A, RATIONAL, 1, "exptime"),
        (0x829D, RATIONAL, 1, "fnumber"),
        (0xA002, SHORT, 1, 200),
        (0xA003, SHORT, 1, 160),
    ]

    ifd0_len = 2 + 12 * len(ifd0_entries) + 4
    exif_off = ifd0_off + ifd0_len
    exif_len = 2 + 12 * len(exif_entries) + 4
    pool_start = exif_off + exif_len

    pool = bytearray()
    blobs = {}

    def add_blob(key, data):
        # Word-align each out-of-line value (TIFF values are even-aligned).
        off = pool_start + len(pool)
        pool.extend(data)
        if len(pool) % 2:
            pool.append(0)
        blobs[key] = off
        return off

    add_blob("make", b"Canon\x00")
    add_blob("model", b"Canon EOS\x00")
    add_blob("exptime", struct.pack(BO + "II", 1, 160))
    add_blob("fnumber", struct.pack(BO + "II", 4, 1))

    out = bytearray()
    # CR2 header (16 bytes): II, 0x2A, IFD0 offset, "CR", 0x02, 0x00, raw-IFD off.
    out += b"II"
    out += struct.pack(BO + "H", 0x002A)
    out += struct.pack(BO + "I", ifd0_off)
    out += b"CR"
    out += bytes([0x02, 0x00])  # major=2, minor=0
    out += struct.pack(BO + "I", 0)  # CR2 raw-IFD offset = 0 (none)
    assert len(out) == 16

    def emit_ifd(entries, next_off):
        nonlocal out
        out += struct.pack(BO + "H", len(entries))
        for (tag, fmt, count, payload) in entries:
            if isinstance(payload, int):
                if fmt == SHORT:
                    field = struct.pack(BO + "H", payload) + b"\x00\x00"
                else:
                    field = struct.pack(BO + "I", payload)
                out += struct.pack(BO + "HHI", tag, fmt, count) + field
            elif payload == "exififd":
                out += entry(tag, fmt, count, exif_off)
            else:
                out += entry(tag, fmt, count, blobs[payload])
        out += struct.pack(BO + "I", next_off)

    emit_ifd(ifd0_entries, 0)  # IFD0, no next IFD (no thumbnail)
    emit_ifd(exif_entries, 0)  # ExifIFD
    out += pool
    return bytes(out)


def main():
    dst = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/CR2_imagesize.cr2"
    data = make_cr2()
    with open(dst, "wb") as f:
        f.write(data)
    print(f"wrote {dst} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
