#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the JUMBF / C2PA conformance fixtures for the PNG caBX box-structure
# port (#142, Phase 1: structure + the jumd description layer + the bfdb/bidb/
# c2sh binary content).
#
# A PNG `caBX` chunk (`PNG.pm:343-346`: caBX -> Jpeg2000::Main) carries a JUMBF
# box stream (ISO-BMFF: 4-byte BE length INCLUDING the 8-byte header, 4-byte
# type, recursive). `jumb` superboxes nest jumb->jumd->content; `jumd` is the
# description box (16-byte type-UUID + toggles + optional label/id/sig). The
# Phase-1 binary content boxes are bfdb (BinaryDataType / MIME), bidb
# (BinaryData / preview placeholder), c2sh (C2PASaltHash / hex salt).
#
# IMPORTANT (Phase 1): the json/cbor CONTENT decoders are Phases 2-3, so these
# fixtures carry ONLY structure + binary boxes (NO json/cbor content boxes) —
# exifast (without the JSON/CBOR decoder) must match bundled byte-exact, and
# bundled WOULD decode a json/cbor content box.
#
#   * PNG_cabx_jumbf.png   — jumb -> jumd(label "c2pa.test", JSON type-UUID,
#     toggles Requestable+Label). Structure-only (no content box). Exercises the
#     JUMDType (json) PrintConv split, JUMDLabel, and the Doc1 axis.
#   * PNG_cabx_binary.png  — jumb -> jumd(raw JPEG type-UUID, no label) + bfdb
#     ("image/jpeg") + bidb (16-byte payload). Exercises the raw-UUID JUMDType
#     (non-ASCII first group, no parens), bfdb BinaryDataType, and the bidb
#     BinaryData byte-count placeholder under the Jpeg2000 group.
#   * PNG_cabx_label_rename.png — jumb -> jumd(label "c2pa.assertions") + bfdb +
#     c2sh. Exercises the JUMBFLabel rename: bfdb -> C2PAAssertionsType, c2sh ->
#     C2PAAssertionsSalt (both keeping the Jpeg2000 group).
#
# Usage: python3 tools/gen_jumbf_fixtures.py [OUTDIR]  (default: <repo>/tests/fixtures)
#
# Regenerate goldens after building (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_jumbf.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_binary.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_label_rename.png
import os
import struct
import sys
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# JSON content type-UUID (Jpeg2000.pm:754): ASCII "json" then the fixed tail.
JSON_UUID = b"json" + bytes.fromhex("00110010800000aa00389b71")
# Raw JPEG-image type-UUID (Jpeg2000.pm:756): a NON-ASCII first group.
JPEG_UUID = bytes.fromhex("6579d6fbdba2446bb2ac1b82feeb89d1")


def chunk(typ: bytes, data: bytes) -> bytes:
    assert len(typ) == 4
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


def ihdr(width=1, height=1, bitdepth=8, color=0) -> bytes:
    # The standard 13-byte PNG header (PNG.pm:387-423): a 1x1 grayscale image.
    body = struct.pack(">IIBBBBB", width, height, bitdepth, color, 0, 0, 0)
    return chunk(b"IHDR", body)


def box(typ: bytes, payload: bytes) -> bytes:
    # A JUMBF box: 4-byte BE length INCLUDING the 8-byte header + 4-char type.
    assert len(typ) == 4
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def jumd_content(type_uuid16: bytes, toggles: int, label=None,
                 idval=None, sig=None) -> bytes:
    # jumd description-box content (Jpeg2000.pm:803): 16-byte type-UUID +
    # 1-byte toggles + optional NUL-terminated label (bit 0x02) + optional
    # 4-byte id (bit 0x04) + optional 32-byte signature (bit 0x08).
    assert len(type_uuid16) == 16
    out = type_uuid16 + bytes([toggles])
    if toggles & 0x02:
        assert label is not None
        out += label + b"\x00"
    if toggles & 0x04:
        out += struct.pack(">I", idval)
    if toggles & 0x08:
        assert len(sig) == 32
        out += sig
    return out


def cabx_png(jumbf_stream: bytes) -> bytes:
    # A minimal 1x1 PNG carrying a single caBX chunk + the JUMBF box stream.
    return PNG_SIG + ihdr() + chunk(b"caBX", jumbf_stream) + chunk(b"IEND", b"")


def main(outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)

    # 1) Structure-only: jumb -> jumd(label, JSON uuid, Requestable+Label).
    j1 = jumd_content(JSON_UUID, 0x03, label=b"c2pa.test")
    f1 = cabx_png(box(b"jumb", box(b"jumd", j1)))
    open(os.path.join(outdir, "PNG_cabx_jumbf.png"), "wb").write(f1)

    # 2) Binary content: jumb -> jumd(raw JPEG uuid, no label) + bfdb + bidb.
    j2 = jumd_content(JPEG_UUID, 0x00)
    bfdb2 = bytes([0x00]) + b"image/jpeg\x00"   # toggle byte + MIME, NUL-padded
    bidb2 = b"\xff\xd8\xff\xe0FAKEJPEGDATA"      # 16 bytes -> placeholder
    inner2 = box(b"jumd", j2) + box(b"bfdb", bfdb2) + box(b"bidb", bidb2)
    f2 = cabx_png(box(b"jumb", inner2))
    open(os.path.join(outdir, "PNG_cabx_binary.png"), "wb").write(f2)

    # 3) Label rename: jumb -> jumd(label "c2pa.assertions") + bfdb + c2sh.
    j3 = jumd_content(JSON_UUID, 0x03, label=b"c2pa.assertions")
    bfdb3 = bytes([0x00]) + b"application/octet-stream\x00"
    c2sh3 = bytes.fromhex("deadbeefcafe")
    inner3 = box(b"jumd", j3) + box(b"bfdb", bfdb3) + box(b"c2sh", c2sh3)
    f3 = cabx_png(box(b"jumb", inner3))
    open(os.path.join(outdir, "PNG_cabx_label_rename.png"), "wb").write(f3)

    print(f"wrote 3 JUMBF fixtures to {outdir}")


if __name__ == "__main__":
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "tests", "fixtures")
    main(out)
