#!/usr/bin/env python3
"""Generate a minimal BigTIFF ColorMap fixture (#428, BigTIFF half).

The classic-TIFF `IFD0:ColorMap` (0x0140, `Format => 'binary'`, `Binary => 1`,
Exif.pm:961-965) decodes through ExifTool's `ProcessExif`, which APPLIES the
`$$tagInfo{Format} = 'binary'` table override: the on-disk SHORT[3*2^BPS] palette
is re-read as `int(size/1)` raw `undef` bytes, so `length($val)` is the on-disk
BYTE count (GeoTiff.tif: int16u[768] -> 1536 bytes).

A BigTIFF does NOT apply that override. `ProcessBigIFD`
(BigTIFF.pm:122/200-209) `ReadValue`s the value with the ON-DISK `$formatStr`
(`formatName[$format]`) and `HandleTag`s the resulting `$val` with
`Format => $formatStr` — it never re-reads through `$$tagInfo{Format}`. So a
BigTIFF ColorMap SHORT[N] decodes to `$val = join(' ', @vals)` (the
space-joined decimal int16u list), and `Binary => 1` reports
`length(join(' ', @vals))` bytes — NOT 2*N, NOT the classic undef reshape.

This fixture pins that BigTIFF behavior (oracle: bundled ExifTool 13.59). It is
a flat single-IFD little-endian BigTIFF carrying a small ColorMap (BitsPerSample
= 2 -> int16u[12] palette) plus the minimal image tags so the file is a valid
TIFF. Sibling of gen_geotiff_bigtiff_fixture.py (which has no ColorMap).

BigTIFF layout (BigTIFF.pm:26-228):
  header : byteorder(2) 0x002B(2) offsetsize=8(2) 0x0000(2) firstIFDoff(8)
  IFD    : count(8) + N x [tag(2) format(2) count(8) value/off(8)] + nextIFD(8)
  A value occupying <= 8 bytes is inline at entry+12; otherwise the 8 bytes
  there are an absolute file offset to the out-of-line value pool.
"""
import struct
import sys

# ---- TIFF format codes (Exif.pm formatName) --------------------------------
SHORT = 3
LONG = 4


def build_bigtiff_colormap():
    """A flat single-IFD (IFD0) little-endian BigTIFF carrying a ColorMap
    (0x0140) int16u[3*2^BitsPerSample] palette plus the minimal image tags."""
    bo = '<'
    pack = lambda f, *v: struct.pack(bo + f, *v)

    # BitsPerSample = 2 -> a 3 * 2^2 = 12-entry RGB palette (int16u[12], 24
    # on-disk bytes). A deterministic ascending ramp so the space-joined
    # decimal `$val` length is fixed (the placeholder byte count the BigTIFF
    # path reports). 4 colors x (R, G, B):
    color_map = [
        0, 0, 0,          # color 0 = black
        21845, 0, 0,      # color 1 = red-ish
        0, 21845, 0,      # color 2 = green-ish
        65535, 65535, 65535,  # color 3 = white
    ]

    def value_bytes(fmt, payload):
        if isinstance(payload, bytes):
            return payload
        if fmt == SHORT:
            return pack('H' * len(payload), *payload)
        if fmt == LONG:
            return pack('I' * len(payload), *payload)
        raise ValueError(fmt)

    # (tag, fmt, count, payload). The single 1-pixel strip lives at the end;
    # its absolute offset is patched into 0x0111.
    entries = [
        (0x0100, SHORT, 1, [1]),     # ImageWidth = 1
        (0x0101, SHORT, 1, [1]),     # ImageHeight = 1
        (0x0102, SHORT, 1, [2]),     # BitsPerSample = 2
        (0x0103, SHORT, 1, [1]),     # Compression = 1 (uncompressed)
        # PhotometricInterpretation = 3 (RGB Palette) — the value a palette
        # image carries; ColorMap is meaningful only for Palette images.
        (0x0106, SHORT, 1, [3]),
        (0x0111, LONG, 1, None),     # StripOffsets -> patched to strip offset
        (0x0115, SHORT, 1, [1]),     # SamplesPerPixel = 1
        (0x0116, SHORT, 1, [1]),     # RowsPerStrip = 1
        (0x0117, LONG, 1, [1]),      # StripByteCounts = 1
        (0x0140, SHORT, len(color_map), color_map),  # ColorMap palette
    ]
    entries.sort(key=lambda e: e[0])  # ascending tag order (TIFF spec)

    ifd0_off = 16
    n = len(entries)
    ifd0_size = 8 + 20 * n + 8
    pos = ifd0_off + ifd0_size

    # Lay out the out-of-line value pool (every > 8-byte value), then the strip.
    voff = {}
    for tag, fmt, count, payload in entries:
        if tag == 0x0111:
            continue  # offset patched after the strip is placed
        raw = value_bytes(fmt, payload)
        if len(raw) > 8:
            voff[tag] = pos
            pos += len(raw)
            if pos & 1:
                pos += 1
    strip_off = pos
    strip = b'\x00'  # the 1-byte image strip
    pos += len(strip)

    # ---- Emit. ----
    out = bytearray(b'II')
    out += pack('HHH', 0x002B, 8, 0x0000)
    out += pack('Q', ifd0_off)
    assert len(out) == ifd0_off, (len(out), ifd0_off)

    out += pack('Q', n)
    for tag, fmt, count, payload in entries:
        if tag == 0x0111:
            val8 = pack('I', strip_off) + b'\x00' * 4
        else:
            raw = value_bytes(fmt, payload)
            if len(raw) > 8:
                val8 = pack('Q', voff[tag])
            else:
                val8 = raw + b'\x00' * (8 - len(raw))
        out += pack('HHQ', tag, fmt, count) + val8
    out += pack('Q', 0)  # next-IFD pointer = 0

    for tag, fmt, count, payload in entries:
        if tag == 0x0111 or tag not in voff:
            continue
        raw = value_bytes(fmt, payload)
        assert len(out) == voff[tag], (hex(tag), len(out), voff[tag])
        out += raw
        if len(out) & 1:
            out += b'\x00'
    assert len(out) == strip_off, (len(out), strip_off)
    out += strip
    return bytes(out)


def main():
    if len(sys.argv) < 2:
        print('usage: gen_geotiff_bigtiff_colormap_fixture.py <out.tif>', file=sys.stderr)
        return 1
    blob = build_bigtiff_colormap()
    with open(sys.argv[1], 'wb') as f:
        f.write(blob)
    print(f'wrote {len(blob)} bytes to {sys.argv[1]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
