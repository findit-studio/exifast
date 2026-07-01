#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the two minimal PNG fixtures for the bare-XML XMP chunk decoders —
# issue #142 (PNG `meTa` + `seAl`):
#
#   * meTa (PNG.pm:368-372) — a UTF-16-BOM XML blob (as written by Picture It!)
#     routed to `ProcessXMP` on the `%XMP::XML` table (XMP.pm:958) with the outer
#     `<meta>` container `IgnoreProp`'d (PNG.pm:371). `%XMP::XML` has
#     `GROUPS => { 0 => 'XML' }`, so a namespaced property emits under family-0
#     `XML` / family-1 `XML-<ns>` via `FoundXMP`'s `$xmlGroups` path
#     (XMP.pm:3713-3715): `<dc:creator>` -> `XML-dc:Creator`.
#   * seAl (PNG.pm:380-382) — a SEAL (Secure Evidence Attribution Label) content-
#     authentication XML blob routed to `ProcessSEAL` -> `ProcessXMP` on the flat
#     `%XMP::SEAL` table (XMP2.pl:1876). `FoundSEAL` strips the outer `<seal>`
#     container (XMP2.pl:1911); the properties carry no namespace, so `FoundXMP`
#     looks each up directly in the SEAL table and the group stays the static
#     table default (family-0 `XML`, family-1 `SEAL`): `<ka>` -> `SEAL:KeyAlgorithm`.
#
# Both blobs are UTF-16 BE with a BOM; the XML declaration MUST carry a trailing
# space after `xml` (`<?xml ...`) so `ProcessXMP`'s data-pointer UTF-16 probe
# matches (XMP.pm:4315 `<\0*\?\0*x\0*m\0*l\0* `).
#
# Oracle (bundled ExifTool 13.59, `perl exiftool -j -G1 -struct`):
#   PNG_meta.png -> XML-dc:Creator="TestAuthor", XML-dc:Title="MyTitle"
#   PNG_seal.png -> SEAL:SEALVersion=1, SEAL:KeyAlgorithm="ES256",
#                   SEAL:KeyVersion=1, SEAL:DigestAlgorithm="sha256",
#                   SEAL:Signature="ABCsig123", SEAL:SEALComment="hello comment"
#
# The IHDR + IDAT (a deflated 1x1 RGB scanline) match the existing PNG_cicp.png /
# PNG_vpag.png fixtures byte-for-byte, so these crafted PNGs are a consistent
# family (and carry the ported `Composite:ImageSize`/`Megapixels` like every PNG
# fixture — they are NOT `XMP*`-named, so gen_golden.sh keeps Composite).
#
# Usage: python3 tools/gen_png_meta_seal_fixture.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the goldens after (re)building the fixtures (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_meta.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_seal.png
import os
import struct
import sys
import zlib

SIG = b"\x89PNG\r\n\x1a\n"

# The exact IDAT data the PNG_cicp.png / PNG_vpag.png fixtures use (a deflated
# 1x1 RGB scanline — filter byte 0 + a single black pixel).
IDAT_DATA = bytes.fromhex("789c63606060000000040001")


def chunk(typ: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def ihdr_1x1_rgb() -> bytes:
    # width=1, height=1, bit-depth=8, color-type=2 (RGB), compression/filter/
    # interlace = 0 — identical to PNG_cicp.png / PNG_vpag.png.
    return chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))


def utf16be_bom(text: str) -> bytes:
    # UTF-16 BE with a leading BOM (FE FF), the encoding Picture It! writes.
    return b"\xfe\xff" + text.encode("utf-16-be")


def build_png(chunk_type: bytes, xml: str) -> bytes:
    return (
        SIG
        + ihdr_1x1_rgb()
        + chunk(chunk_type, utf16be_bom(xml))
        + chunk(b"IDAT", IDAT_DATA)
        + chunk(b"IEND", b"")
    )


# meTa: two Dublin Core properties under the ignored `<meta>` container.
META_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>'
    "<meta>"
    '<dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">TestAuthor</dc:creator>'
    '<dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">MyTitle</dc:title>'
    "</meta>"
)

# seAl: six SEAL properties under the (FoundSEAL-stripped) `<seal>` container —
# a nested `<seal>1</seal>` exercises the SEALVersion tag AND the "strip only the
# OUTER container" rule (the inner `seal` still resolves to SEALVersion).
SEAL_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>'
    "<seal>"
    "<seal>1</seal>"
    "<ka>ES256</ka>"
    "<kv>1</kv>"
    "<da>sha256</da>"
    "<s>ABCsig123</s>"
    "<info>hello comment</info>"
    "</seal>"
)


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else None
    if outdir is None:
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        outdir = os.path.join(repo, "tests", "fixtures")
    os.makedirs(outdir, exist_ok=True)
    for name, chunk_type, xml in (
        ("PNG_meta.png", b"meTa", META_XML),
        ("PNG_seal.png", b"seAl", SEAL_XML),
    ):
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(build_png(chunk_type, xml))
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
