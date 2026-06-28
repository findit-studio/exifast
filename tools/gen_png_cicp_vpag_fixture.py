#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal PNG fixtures for the PER-REGION/PER-FIELD storage of the
# two `ProcessBinaryData` PNG sub-table chunks — issue #142, Codex [medium]:
#
#   * cICP — the HDR "coding-independent code points" chunk (`CICodePoints`,
#     PNG.pm:471-541): four `int8u` fields ColorPrimaries / TransferCharacteristics
#     / MatrixCoefficients / VideoFullRangeFlag. family-1 group `PNG-cICP`.
#   * vpAg — ImageMagick's private virtual-page chunk (`VirtualPage`,
#     PNG.pm:561-573): VirtualImageWidth / VirtualImageHeight (int32u) +
#     VirtualPageUnits (int8u). Default family-1 group `PNG`.
#
# `ProcessBinaryData` emits each field IFF its byte offset is within the chunk,
# and NEVER clears a previously emitted tag. A post-`IEND` TRAILER chunk emits
# under the `Trailer` family-1 group (PNG.pm:1484 `SET_GROUP1 = 'Trailer'`)
# WITHOUT overwriting / re-grouping the pre-`IEND` (main) fields, and a TRUNCATED
# later same-region chunk updates only its present fields (the earlier values of
# the omitted fields survive). The previous singleton storage clobbered the main
# fields on a trailer chunk and cleared absent fields on a truncated chunk; the
# per-field+per-region `RegionValue` model keeps both regions and every field.
#
# These crafted fixtures pin those two behaviours against bundled ExifTool 13.59
# (the single-chunk `PNG_cicp.png` / `PNG_vpag.png` fixtures already cover the
# pre-`IEND` happy path and stay byte-exact — they are NOT regenerated here):
#
#   * PNG_cicp_trailer.png — a MAIN cICP (9/16/9/1, → `PNG-cICP:*`) + a post-`IEND`
#     TRAILER cICP (1/13/0/0, → `Trailer:*`). Both groups emit.
#   * PNG_vpag_trailer.png — a MAIN vpAg (100/200/0, → `PNG:*`) + a post-`IEND`
#     TRAILER vpAg (300/400/1, → `Trailer:*`). Both groups emit.
#   * PNG_cicp_vpag_truncated.png — a FULL cICP/vpAg then a TRUNCATED same-region
#     cICP/vpAg (cICP 5/8 → keeps Matrix 9 / FullRange 1; vpAg width 999 → keeps
#     height 200 / units 0). Present-only update, no trailer.
#
# The IDAT (a deflated 1x1 RGB scanline) and IHDR match the existing
# `PNG_cicp.png` / `PNG_vpag.png` fixtures byte-for-byte so the crafted PNGs are
# a consistent family.
#
# Usage: python3 tools/gen_png_cicp_vpag_fixture.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the goldens after (re)building the fixtures (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cicp_trailer.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_vpag_trailer.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cicp_vpag_truncated.png
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"

# The exact IDAT data the `PNG_cicp.png` / `PNG_vpag.png` fixtures use (a deflated
# 1x1 RGB scanline — filter byte 0 + a single black pixel).
IDAT_DATA = bytes.fromhex("789c63606060000000040001")


def chunk(typ: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def ihdr_1x1_rgb() -> bytes:
    # width=1, height=1, bit-depth=8, color-type=2 (RGB), compression/filter/
    # interlace = 0 — identical to PNG_cicp.png / PNG_vpag.png.
    return chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))


def cicp(*bytevals: int) -> bytes:
    return chunk(b"cICP", bytes(bytevals))


def vpag(width=None, height=None, units=None) -> bytes:
    payload = b""
    if width is not None:
        payload += struct.pack(">I", width)
        if height is not None:
            payload += struct.pack(">I", height)
            if units is not None:
                payload += bytes([units])
    return chunk(b"vpAg", payload)


# ── #142 / Codex [medium] — cICP BOTH before AND after IEND ─────────────────
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG-cICP:ColorPrimaries          = "BT.2020, BT.2100"  (9)
#   PNG-cICP:TransferCharacteristics = "SMPTE ST 2084, ITU BT.2100 PQ"  (16)
#   PNG-cICP:MatrixCoefficients      = "BT.2020 non-constant luminance, …" (9)
#   PNG-cICP:VideoFullRangeFlag      = 1
#   Trailer:ColorPrimaries           = "BT.709"  (1)
#   Trailer:TransferCharacteristics  = "sRGB or sYCC"  (13)
#   Trailer:MatrixCoefficients       = "Identity matrix"  (0)
#   Trailer:VideoFullRangeFlag       = 0
#   ExifTool:Warning                 = "[minor] Trailer data after PNG IEND chunk"
def build_cicp_trailer() -> bytes:
    return (
        SIG
        + ihdr_1x1_rgb()
        + cicp(9, 16, 9, 1)
        + chunk(b"IDAT", IDAT_DATA)
        + chunk(b"IEND", b"")
        + cicp(1, 13, 0, 0)
    )


# ── #142 / Codex [medium] — vpAg BOTH before AND after IEND ─────────────────
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG:VirtualImageWidth      = 100
#   PNG:VirtualImageHeight     = 200
#   PNG:VirtualPageUnits       = 0
#   Trailer:VirtualImageWidth  = 300
#   Trailer:VirtualImageHeight = 400
#   Trailer:VirtualPageUnits   = 1
#   ExifTool:Warning           = "[minor] Trailer data after PNG IEND chunk"
def build_vpag_trailer() -> bytes:
    return (
        SIG
        + ihdr_1x1_rgb()
        + vpag(100, 200, 0)
        + chunk(b"IDAT", IDAT_DATA)
        + chunk(b"IEND", b"")
        + vpag(300, 400, 1)
    )


# ── #142 / Codex [medium] — FULL then TRUNCATED cICP/vpAg (same region) ─────
# A 2-byte cICP after a full one keeps the absent fields; a 4-byte vpAg after a
# full one keeps the absent fields. Present fields overwrite (last-wins).
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG-cICP:MatrixCoefficients      = "BT.2020 non-constant luminance, …" (9, kept)
#   PNG-cICP:VideoFullRangeFlag      = 1   (kept)
#   PNG-cICP:ColorPrimaries          = "Unspecified"  (5, overwritten)
#   PNG-cICP:TransferCharacteristics = "BT.601"  (8, overwritten)
#   PNG:VirtualImageHeight           = 200   (kept)
#   PNG:VirtualPageUnits             = 0     (kept)
#   PNG:VirtualImageWidth            = 999   (overwritten)
def build_cicp_vpag_truncated() -> bytes:
    return (
        SIG
        + ihdr_1x1_rgb()
        + cicp(9, 16, 9, 1)
        + vpag(100, 200, 0)
        + cicp(5, 8)
        + chunk(b"vpAg", struct.pack(">I", 999))
        + chunk(b"IDAT", IDAT_DATA)
        + chunk(b"IEND", b"")
    )


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)
    fixtures = {
        "PNG_cicp_trailer.png": build_cicp_trailer(),
        "PNG_vpag_trailer.png": build_vpag_trailer(),
        "PNG_cicp_vpag_truncated.png": build_cicp_vpag_truncated(),
    }
    for name, data in fixtures.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
