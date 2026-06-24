#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal animated-PNG (APNG) fixture for issue #141 — the `acTL`
# Animation Control chunk (`PNG.pm:302-307`) and its `AnimationControl`
# ProcessBinaryData sub-table (`PNG.pm:766-782`, `FORMAT => 'int32u'`):
#
#   * PNG_apng.png — a 1x1 RGB PNG carrying:
#       - acTL [num_frames=2, num_plays=0]  → PNG:AnimationFrames=2,
#                                              PNG:AnimationPlays="inf" (0 ⇒ inf)
#       - fcTL (frame 0) + IDAT (frame 0 data)
#       - fcTL (frame 1) + fdAT (frame 1 data)
#       - IEND
#
# The `AnimationFrames` RawConv (`$self->OverrideFileType("APNG", undef,
# "PNG"); $val`, PNG.pm:776) promotes File:FileType → "APNG", MIMEType →
# "image/apng" (the %mimeType{APNG} lookup), and FileTypeExtension → the
# EXPLICIT "PNG" arg (png/PNG). The per-frame `fcTL`/`fdAT` chunks have NO
# bundled table (`PNG.pm:329-330` is comment-only), so they contribute NO tags —
# the APNG metadata is the `acTL` summary alone (oracle-verified vs 13.59;
# `exiftool -validate` = OK). Every chunk carries a valid CRC32.
#
# Usage: python3 tools/make_apng.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the golden after (re)building the fixture (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_apng.png
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"


def chunk(typ: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def build() -> bytes:
    out = SIG
    # IHDR: 1x1, 8-bit, color type 2 (RGB), compression 0, filter 0, interlace 0.
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    # acTL: num_frames=2, num_plays=0 (0 = infinite loop → AnimationPlays "inf").
    out += chunk(b"acTL", struct.pack(">II", 2, 0))
    # fcTL (frame 0): seq, width, height, x, y, delay_num(u16), delay_den(u16),
    #                 dispose_op(u8), blend_op(u8).
    out += chunk(b"fcTL", struct.pack(">IIIIIHHBB", 0, 1, 1, 0, 0, 1, 10, 0, 0))
    # IDAT (frame 0 data): one 1x1 RGB scanline (filter byte 0 + R,G,B).
    out += chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    # fcTL (frame 1).
    out += chunk(b"fcTL", struct.pack(">IIIIIHHBB", 1, 1, 1, 0, 0, 1, 10, 0, 0))
    # fdAT (frame 1 data): sequence_number(u32) + compressed frame data.
    out += chunk(b"fdAT", struct.pack(">I", 2) + zlib.compress(b"\x00\x00\x00\xff"))
    out += chunk(b"IEND", b"")
    return out


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else None
    if outdir is None:
        here = os.path.dirname(os.path.abspath(__file__))
        outdir = os.path.join(here, "..", "tests", "fixtures")
    path = os.path.join(outdir, "PNG_apng.png")
    data = build()
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {path}")


if __name__ == "__main__":
    main()
