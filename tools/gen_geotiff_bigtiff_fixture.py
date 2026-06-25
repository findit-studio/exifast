#!/usr/bin/env python3
"""Generate a minimal BigTIFF GeoTIFF fixture (#150 GeoTiff, BigTIFF half).

The classic-TIFF GeoTiff fixtures (GeoTiff.tif / GeoTiff_mini.tif /
GeoTiff_projcs.tif) decode the GeoKey directory through ExifTool's `ProcessExif`
-> `Walker::emit` capture tap -> post-IFD `ProcessGeoTiff`. A BigTIFF does NOT:
`DoProcessTIFF`'s `$identifier == 0x2b` arm `return 1`s at `ExifTool.pm:8668`,
BEFORE the `:8740` `if ($$self{VALUE}{GeoTiffDirectory}) { ProcessGeoTiff }`
call (and `BigTIFF.pm` carries no GeoTiff reference). So a BigTIFF GeoTIFF emits
NO `GeoTiff:*` GeoKeys — the three `Binary => 1` block tags (0x87af
GeoTiffDirectory / 0x87b0 GeoTiffDoubleParams / 0x87b1 GeoTiffAsciiParams)
instead survive as the `(Binary data N bytes …)` placeholder under their IFD0
group (the `ProcessGeoTiff` `DeleteTag` cleanup that removes them on the classic
path never runs).

This fixture pins that BigTIFF behavior (oracle: bundled ExifTool 13.59 emits
`IFD0:GeoTiffDirectory`/`DoubleParams`/`AsciiParams` Binary placeholders, no
`GeoTiff:*`). It carries the same GeoKey block SHAPE as GeoTiff_mini.tif so the
on-disk block byte sizes are well-defined.

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
DOUBLE = 12
ASCII = 2


def build_bigtiff_geotiff():
    """A flat single-IFD (IFD0) little-endian BigTIFF carrying the GeoTiff_mini
    GeoKey block set plus the minimal image tags so the file is a valid TIFF."""
    bo = '<'
    pack = lambda f, *v: struct.pack(bo + f, *v)

    # The exact GeoKeyDirectory of GeoTiff_mini.tif (decoded from the fixture):
    #   version=1 rev=1 minor=0 NumberOfKeys=3 + three key triples.
    geo_dir = [1, 1, 0, 3, 1024, 0, 1, 1, 2049, 34737, 7, 0, 2057, 34736, 1, 0]
    geo_double = [6378137.0]
    geo_ascii = b'WGS 84|'
    pixel_scale = [10.0, 10.0, 0.0]              # 0x830e ModelPixelScale
    model_tie = [0.0, 0.0, 0.0, 100.0, 200.0, 0.0]  # 0x8482 ModelTiePoint

    def value_bytes(fmt, payload):
        if isinstance(payload, bytes):
            return payload
        if fmt == SHORT:
            return pack('H' * len(payload), *payload)
        if fmt == LONG:
            return pack('I' * len(payload), *payload)
        if fmt == DOUBLE:
            return pack('d' * len(payload), *payload)
        raise ValueError(fmt)

    # (tag, fmt, count, payload). The single 1-pixel strip lives at the end;
    # its absolute offset is patched into 0x0111.
    entries = [
        (0x0100, SHORT, 1, [1]),     # ImageWidth = 1
        (0x0101, SHORT, 1, [1]),     # ImageHeight = 1
        (0x0102, SHORT, 1, [8]),     # BitsPerSample = 8
        (0x0103, SHORT, 1, [1]),     # Compression = 1 (uncompressed)
        (0x0106, SHORT, 1, [1]),     # PhotometricInterpretation = 1 (BlackIsZero)
        (0x0111, LONG, 1, None),     # StripOffsets -> patched to strip offset
        (0x0115, SHORT, 1, [1]),     # SamplesPerPixel = 1
        (0x0116, SHORT, 1, [1]),     # RowsPerStrip = 1
        (0x0117, LONG, 1, [1]),      # StripByteCounts = 1
        (0x830e, DOUBLE, 3, pixel_scale),     # ModelPixelScale
        (0x8482, DOUBLE, 6, model_tie),       # ModelTiePoint
        (0x87af, SHORT, len(geo_dir), geo_dir),       # GeoKeyDirectory
        (0x87b0, DOUBLE, len(geo_double), geo_double),  # GeoDoubleParams
        (0x87b1, ASCII, len(geo_ascii), geo_ascii),   # GeoAsciiParams
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
        print('usage: gen_geotiff_bigtiff_fixture.py <out.tif>', file=sys.stderr)
        return 1
    blob = build_bigtiff_geotiff()
    with open(sys.argv[1], 'wb') as f:
        f.write(blob)
    print(f'wrote {len(blob)} bytes to {sys.argv[1]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
