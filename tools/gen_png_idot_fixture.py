#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal PNG fixtures for the two simple `Binary => 1` PNG vendor
# chunks (NO SubDirectory) — issue #142:
#
#   * PNG_idot.png — the Apple `iDOT` private chunk (`AppleDataOffsets`,
#     PNG.pm:331-342). A 1x1 RGB PNG whose only vendor chunk is `iDOT`. Bundled
#     stores its WHOLE 28-byte payload under `PNG:AppleDataOffsets`, rendered as
#     the universal `(Binary data 28 bytes, use -b option to extract)`
#     placeholder. `iDOT` is placed directly after IHDR (the real Apple layout).
#   * PNG_gdat.png — the `gdAT` gain-map chunk (`GainMapImage`,
#     `Groups => { 2 => 'Preview' }`, PNG.pm:374-378). The SAME simple shape as
#     `iDOT`; bundled stores the WHOLE payload under `PNG:GainMapImage`,
#     rendered as the `(Binary data N bytes, …)` placeholder.
#
# Both tags are `Binary => 1` with NO SubDirectory, so the `-j` value derives
# from the payload LENGTH alone (exifast retains the length, never the bytes).
#
# Usage: python3 tools/gen_png_idot_fixture.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the goldens after (re)building the fixtures (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_idot.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_gdat.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_idot_trailer.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_gdat_trailer.png
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"


def chunk(typ: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def ihdr(w: int, h: int, depth: int = 8, color: int = 2) -> bytes:
    # width, height, bit-depth, color-type(2=RGB), compression, filter, interlace
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, color, 0, 0, 0))


def idat_1x1_rgb() -> bytes:
    # One scanline: filter byte 0 + a single white RGB pixel.
    raw = b"\x00\xff\xff\xff"
    return chunk(b"IDAT", zlib.compress(raw))


# ── #142 — Apple `iDOT` (AppleDataOffsets) ───────────────────────────────────
# The 28-byte (7x int32u) layout documented at PNG.pm:334-341 (ref NealKrawetz):
#   Divisor, Unknown, TotalDividedHeight, Size(0x28), DividedHeight1,
#   DividedHeight2, IDAT_Offset2. Bundled never decodes the sub-fields (no
#   sub-table); the whole chunk is the `AppleDataOffsets` binary value.
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG:AppleDataOffsets = "(Binary data 28 bytes, use -b option to extract)"
def build_idot() -> bytes:
    idot_body = struct.pack(">7I", 2, 0, 1, 0x28, 1, 1, 0x100)
    assert len(idot_body) == 28
    return (
        SIG
        + ihdr(1, 1)
        + chunk(b"iDOT", idot_body)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
    )


# ── #142 — `gdAT` (GainMapImage) ─────────────────────────────────────────────
# A real gain-map image payload is itself an embedded image; bundled stores the
# WHOLE chunk as the `GainMapImage` binary value (no sub-table). The 20-byte
# stand-in below (an embedded-PNG signature + padding) is enough to pin the
# placeholder.
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG:GainMapImage = "(Binary data 20 bytes, use -b option to extract)"
def build_gdat() -> bytes:
    gdat_body = SIG + b"\x00" * 12
    assert len(gdat_body) == 20
    return (
        SIG
        + ihdr(1, 1)
        + chunk(b"gdAT", gdat_body)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
    )


# ── #142 / Codex [medium] — iDOT BOTH before AND after IEND ─────────────────
# A PNG can carry the same `Binary => 1` vendor chunk pre-`IEND` (emitted under
# the `PNG` family-1 group) AND as a post-`IEND` trailer chunk (emitted under
# the `Trailer` group, PNG.pm:1484 `SET_GROUP1 = 'Trailer'`). Bundled emits
# BOTH placeholders. A 1..8-byte read after IEND also fires the minor
# `Trailer data after PNG IEND chunk` warning (document-level), but a full
# (>=8-byte header) trailer chunk parses normally.
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG:AppleDataOffsets     = "(Binary data 28 bytes, use -b option to extract)"
#   Trailer:AppleDataOffsets = "(Binary data 4 bytes, use -b option to extract)"
#   ExifTool:Warning         = "[minor] Trailer data after PNG IEND chunk"
def build_idot_main_trailer() -> bytes:
    main_idot = struct.pack(">7I", 2, 0, 1, 0x28, 1, 1, 0x100)
    assert len(main_idot) == 28
    trailer_idot = struct.pack(">I", 0xDEADBEEF)  # 4-byte post-IEND iDOT
    assert len(trailer_idot) == 4
    return (
        SIG
        + ihdr(1, 1)
        + chunk(b"iDOT", main_idot)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
        + chunk(b"iDOT", trailer_idot)
    )


# ── #142 / Codex [medium] — gdAT BOTH before AND after IEND ────────────────
# The same per-group split for `gdAT` (GainMapImage).
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   PNG:GainMapImage     = "(Binary data 20 bytes, use -b option to extract)"
#   Trailer:GainMapImage = "(Binary data 8 bytes, use -b option to extract)"
#   ExifTool:Warning     = "[minor] Trailer data after PNG IEND chunk"
def build_gdat_main_trailer() -> bytes:
    main_gdat = SIG + b"\x00" * 12  # 20 bytes
    assert len(main_gdat) == 20
    trailer_gdat = b"\x01\x02\x03\x04\x05\x06\x07\x08"  # 8-byte post-IEND gdAT
    assert len(trailer_gdat) == 8
    return (
        SIG
        + ihdr(1, 1)
        + chunk(b"gdAT", main_gdat)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
        + chunk(b"gdAT", trailer_gdat)
    )


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)
    fixtures = {
        "PNG_idot.png": build_idot(),
        "PNG_gdat.png": build_gdat(),
        "PNG_idot_trailer.png": build_idot_main_trailer(),
        "PNG_gdat_trailer.png": build_gdat_main_trailer(),
    }
    for name, data in fixtures.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
