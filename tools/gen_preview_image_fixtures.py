#!/usr/bin/env python3
"""Generate crafted fixtures for #352 — PreviewImage/JpgFromRaw via DataTag.

Generates 3 minimal fixtures:
1. CR2 with PreviewImage (0x0111/0x0117 → tiny JPEG in IFD0)
2. DNG with PreviewImage (0x0111/0x0117 → tiny JPEG in IFD0)
3. Sony ARW with PreviewImage (0x0201/0x0202 → tiny JPEG in IFD0)

Each fixture is a minimal TIFF with the offset-pair pointing to a tiny
JPEG blob (SOI + EOI = 2 bytes). ExifTool emits:
  PreviewImage : (Binary data 2 bytes, use -b option to extract)
"""
import struct
import sys

# TIFF format codes
BYTE = 1
ASCII = 2
SHORT = 3
LONG = 4
RATIONAL = 5
UNDEF = 7

BO = "<"  # little-endian


def entry(tag, fmt, count, value_or_offset):
    """Build a 12-byte IFD entry."""
    return struct.pack(BO + "HHI", tag, fmt, count) + struct.pack(
        BO + "I", value_or_offset
    )


def make_tiff(ifd0_entries, exif_entries=None, header_extra=b"", magic=b"II"):
    """Build a minimal TIFF with IFD0 + optional ExifIFD.

    Returns bytes.
    """
    # Header: 8 bytes (magic + IFD0 offset)
    header_len = 8 + len(header_extra)
    ifd0_off = header_len

    ifd0_len = 2 + 12 * len(ifd0_entries) + 4
    if exif_entries:
        exif_off = ifd0_off + ifd0_len
        exif_len = 2 + 12 * len(exif_entries) + 4
        pool_start = exif_off + exif_len
    else:
        exif_off = 0
        pool_start = ifd0_off + ifd0_len

    pool = bytearray()
    blobs = {}

    def add_blob(key, data):
        off = pool_start + len(pool)
        pool.extend(data)
        if len(pool) % 2:
            pool.append(0)
        blobs[key] = off
        return off

    # The tiny JPEG blob: SOI (FFD8) + EOI (FFD9) = 2 bytes
    jpeg_off = add_blob("jpeg", b"\xff\xd8\xff\xd9")

    # Build the IFD entries, resolving blob references
    resolved_ifd0 = []
    for (tag, fmt, count, payload) in ifd0_entries:
        if isinstance(payload, str) and payload == "jpeg":
            resolved_ifd0.append((tag, fmt, count, jpeg_off))
        elif isinstance(payload, str) and payload == "exififd":
            resolved_ifd0.append((tag, fmt, count, exif_off))
        else:
            resolved_ifd0.append((tag, fmt, count, payload))

    # Build output
    out = bytearray()
    out += magic
    out += struct.pack(BO + "H", 0x002A)  # TIFF magic number
    out += struct.pack(BO + "I", ifd0_off)  # IFD0 offset
    out += header_extra
    assert len(out) == header_len

    def emit_ifd(entries, next_off):
        nonlocal out
        out += struct.pack(BO + "H", len(entries))
        for (tag, fmt, count, payload) in entries:
            if isinstance(payload, int):
                if fmt == SHORT and count == 1:
                    field = struct.pack(BO + "H", payload) + b"\x00\x00"
                else:
                    field = struct.pack(BO + "I", payload)
                out += struct.pack(BO + "HHI", tag, fmt, count) + field
            else:
                out += entry(tag, fmt, count, payload)
        out += struct.pack(BO + "I", next_off)

    if exif_entries:
        emit_ifd(resolved_ifd0, 0)  # IFD0, no next IFD
        emit_ifd(exif_entries, 0)  # ExifIFD
    else:
        emit_ifd(resolved_ifd0, 0)  # IFD0 only

    out += pool
    return bytes(out)


def make_cr2_preview():
    """CR2 with PreviewImage: IFD0 0x0111/0x0117 → tiny JPEG."""
    ifd0 = [
        (0x0100, SHORT, 1, 100),       # ImageWidth
        (0x0101, SHORT, 1, 80),        # ImageHeight
        (0x010F, ASCII, 6, "make"),    # Make
        (0x0110, ASCII, 10, "model"),  # Model
        (0x0111, LONG, 1, "jpeg"),     # StripOffsets → PreviewImageStart
        (0x0117, LONG, 1, 4),          # StripByteCounts → PreviewImageLength = 4
        (0x8769, LONG, 1, "exififd"),  # ExifOffset
    ]
    exif = [
        (0x829A, RATIONAL, 1, "exptime"),  # ExposureTime
        (0x829D, RATIONAL, 1, "fnumber"),  # FNumber
    ]

    pool_extra = bytearray()

    def add_blob(key, data):
        pool_extra.extend(data)
        if len(pool_extra) % 2:
            pool_extra.append(0)
        return key

    add_blob("make", b"Canon\x00")
    add_blob("model", b"Canon EOS 5D\x00")
    add_blob("exptime", struct.pack(BO + "II", 1, 160))
    add_blob("fnumber", struct.pack(BO + "II", 8, 1))

    # CR2 header extra: "CR" + version + raw-IFD offset
    header_extra = b"CR" + bytes([0x02, 0x00]) + struct.pack(BO + "I", 0)

    # Build manually with pool merging
    ifd0_off = 8 + len(header_extra)
    ifd0_len = 2 + 12 * len(ifd0) + 4
    exif_off = ifd0_off + ifd0_len
    exif_len = 2 + 12 * len(exif) + 4
    pool_start = exif_off + exif_len

    pool = bytearray()

    def add_pool(key, data):
        off = pool_start + len(pool)
        pool.extend(data)
        if len(pool) % 2:
            pool.append(0)
        return off

    make_off = add_pool("make", b"Canon\x00")
    model_off = add_pool("model", b"Canon EOS 5D\x00")
    exptime_off = add_pool("exptime", struct.pack(BO + "II", 1, 160))
    fnumber_off = add_pool("fnumber", struct.pack(BO + "II", 8, 1))
    jpeg_off = add_pool("jpeg", b"\xff\xd8\xff\xd9")

    # Resolve IFD0 entries
    resolved_ifd0 = []
    for (tag, fmt, count, payload) in ifd0:
        if payload == "make":
            resolved_ifd0.append((tag, fmt, count, make_off))
        elif payload == "model":
            resolved_ifd0.append((tag, fmt, count, model_off))
        elif payload == "jpeg":
            resolved_ifd0.append((tag, fmt, count, jpeg_off))
        elif payload == "exififd":
            resolved_ifd0.append((tag, fmt, count, exif_off))
        else:
            resolved_ifd0.append((tag, fmt, count, payload))

    resolved_exif = []
    for (tag, fmt, count, payload) in exif:
        if payload == "exptime":
            resolved_exif.append((tag, fmt, count, exptime_off))
        elif payload == "fnumber":
            resolved_exif.append((tag, fmt, count, fnumber_off))
        else:
            resolved_exif.append((tag, fmt, count, payload))

    out = bytearray()
    out += b"II"
    out += struct.pack(BO + "H", 0x002A)
    out += struct.pack(BO + "I", ifd0_off)
    out += header_extra
    assert len(out) == 8 + len(header_extra)

    def emit_ifd(entries, next_off):
        nonlocal out
        out += struct.pack(BO + "H", len(entries))
        for (tag, fmt, count, payload) in entries:
            if isinstance(payload, int):
                if fmt == SHORT and count == 1:
                    field = struct.pack(BO + "H", payload) + b"\x00\x00"
                elif fmt == LONG and count == 1:
                    field = struct.pack(BO + "I", payload)
                else:
                    field = struct.pack(BO + "I", payload)
                out += struct.pack(BO + "HHI", tag, fmt, count) + field
            else:
                out += struct.pack(BO + "HHI", tag, fmt, count) + struct.pack(BO + "I", payload)
        out += struct.pack(BO + "I", next_off)

    emit_ifd(resolved_ifd0, 0)
    emit_ifd(resolved_exif, 0)
    out += pool
    return bytes(out)


def make_dng_preview():
    """DNG with PreviewImage: IFD0 0x0111/0x0117 → tiny JPEG."""
    ifd0 = [
        (0x0100, SHORT, 1, 100),       # ImageWidth
        (0x0101, SHORT, 1, 80),        # ImageHeight
        (0x010F, ASCII, 7, "make"),    # Make
        (0x0110, ASCII, 10, "model"),  # Model
        (0x0111, LONG, 1, "jpeg"),     # StripOffsets → PreviewImageStart
        (0x0117, LONG, 1, 4),          # StripByteCounts → PreviewImageLength = 4
        (0x011A, RATIONAL, 1, "xres"), # XResolution
        (0x011B, RATIONAL, 1, "yres"), # YResolution
    ]

    ifd0_off = 8
    ifd0_len = 2 + 12 * len(ifd0) + 4
    pool_start = ifd0_off + ifd0_len

    pool = bytearray()

    def add_pool(key, data):
        off = pool_start + len(pool)
        pool.extend(data)
        if len(pool) % 2:
            pool.append(0)
        return off

    make_off = add_pool("make", b"NIKON\x00")
    model_off = add_pool("model", b"NIKON D850\x00")
    xres_off = add_pool("xres", struct.pack(BO + "II", 300, 1))
    yres_off = add_pool("yres", struct.pack(BO + "II", 300, 1))
    jpeg_off = add_pool("jpeg", b"\xff\xd8\xff\xd9")

    resolved = []
    for (tag, fmt, count, payload) in ifd0:
        if payload == "make":
            resolved.append((tag, fmt, count, make_off))
        elif payload == "model":
            resolved.append((tag, fmt, count, model_off))
        elif payload == "xres":
            resolved.append((tag, fmt, count, xres_off))
        elif payload == "yres":
            resolved.append((tag, fmt, count, yres_off))
        elif payload == "jpeg":
            resolved.append((tag, fmt, count, jpeg_off))
        else:
            resolved.append((tag, fmt, count, payload))

    out = bytearray()
    out += b"II"
    out += struct.pack(BO + "H", 0x002A)
    out += struct.pack(BO + "I", ifd0_off)

    out += struct.pack(BO + "H", len(resolved))
    for (tag, fmt, count, payload) in resolved:
        if isinstance(payload, int):
            if fmt == SHORT and count == 1:
                field = struct.pack(BO + "H", payload) + b"\x00\x00"
            else:
                field = struct.pack(BO + "I", payload)
            out += struct.pack(BO + "HHI", tag, fmt, count) + field
        else:
            out += struct.pack(BO + "HHI", tag, fmt, count) + struct.pack(BO + "I", payload)
    out += struct.pack(BO + "I", 0)  # no next IFD

    out += pool
    return bytes(out)


def make_arw_preview():
    """Sony ARW with PreviewImage: IFD0 0x0201/0x0202 → tiny JPEG.

    0x0201 = JpgFromRawStart (PreviewImageStart in Sony context)
    0x0202 = JpgFromRawByteCount (PreviewImageLength)
    """
    ifd0 = [
        (0x0100, SHORT, 1, 100),       # ImageWidth
        (0x0101, SHORT, 1, 80),        # ImageHeight
        (0x010F, ASCII, 6, "make"),    # Make = SONY
        (0x0110, ASCII, 10, "model"),  # Model = ILCE-7M4
        (0x0201, LONG, 1, "jpeg"),     # JpgFromRawStart → PreviewImageStart
        (0x0202, LONG, 1, 4),          # JpgFromRawByteCount → PreviewImageLength = 4
    ]

    ifd0_off = 8
    ifd0_len = 2 + 12 * len(ifd0) + 4
    pool_start = ifd0_off + ifd0_len

    pool = bytearray()

    def add_pool(key, data):
        off = pool_start + len(pool)
        pool.extend(data)
        if len(pool) % 2:
            pool.append(0)
        return off

    make_off = add_pool("make", b"SONY\x00")
    model_off = add_pool("model", b"ILCE-7M4\x00")
    jpeg_off = add_pool("jpeg", b"\xff\xd8\xff\xd9")

    resolved = []
    for (tag, fmt, count, payload) in ifd0:
        if payload == "make":
            resolved.append((tag, fmt, count, make_off))
        elif payload == "model":
            resolved.append((tag, fmt, count, model_off))
        elif payload == "jpeg":
            resolved.append((tag, fmt, count, jpeg_off))
        else:
            resolved.append((tag, fmt, count, payload))

    out = bytearray()
    out += b"II"
    out += struct.pack(BO + "H", 0x002A)
    out += struct.pack(BO + "I", ifd0_off)

    out += struct.pack(BO + "H", len(resolved))
    for (tag, fmt, count, payload) in resolved:
        if isinstance(payload, int):
            if fmt == SHORT and count == 1:
                field = struct.pack(BO + "H", payload) + b"\x00\x00"
            else:
                field = struct.pack(BO + "I", payload)
            out += struct.pack(BO + "HHI", tag, fmt, count) + field
        else:
            out += struct.pack(BO + "HHI", tag, fmt, count) + struct.pack(BO + "I", payload)
    out += struct.pack(BO + "I", 0)  # no next IFD

    out += pool
    return bytes(out)


def main():
    fixtures = [
        ("tests/fixtures/CR2_preview_image.cr2", make_cr2_preview),
        ("tests/fixtures/DNG_preview_image.dng", make_dng_preview),
        ("tests/fixtures/ARW_preview_image.arw", make_arw_preview),
    ]
    for path, gen_fn in fixtures:
        data = gen_fn()
        with open(path, "wb") as f:
            f.write(data)
        print(f"wrote {path} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
