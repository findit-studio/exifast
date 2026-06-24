#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal MALFORMED PNG fixtures for the crafted-input hardening
# of issues #180 (post-IEND Trailer family-1 group on a warning raised while
# parsing a trailer chunk) and #178-item1 (nested-zXIf inner inflate recursion
# warning text). Each is a 1x1 RGB PNG; the default (well-formed) PNG path is
# unaffected by these decode-error edges.
#
# Usage: python3 tools/gen_png_harden_fixtures.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the goldens after (re)building a fixture (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_trailer_iccp_warn.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_nested_zxif.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_trailer_xmp_warn.png
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


# ── #180 — post-IEND Trailer family-1 group on a trailer-chunk warning ───────
# A complete (IEND-terminated) PNG followed by a TRAILER `iCCP` chunk whose zlib
# stream is corrupt. Bundled (`PNG.pm:1479-1484`) processes post-IEND chunks
# under `$$et{SET_GROUP1} = 'Trailer'`, so the `Error inflating iCCP` warning
# (`PNG.pm:942`, raised WHILE parsing the trailer chunk) gets the family-1
# `Trailer` group ⇒ the `Trailer:Warning` TAG, NOT the document-level
# `ExifTool:Warning`. The trailer-ENTRY warning `Trailer data after PNG IEND
# chunk` (`PNG.pm:1481`) is raised BEFORE `SET_GROUP1` is set, so it stays
# `ExifTool:Warning` (and is `[minor]`). `iCCP` is NOT a text chunk, so there is
# no competing "Text/EXIF chunk found after IDAT" warning — the only
# `Trailer:Warning` is the inflate error. The trailer iCCP's `ProfileName`
# ("ICC") rides the `Trailer` group too (`Trailer:ProfileName`). Bundled also
# emits a deferred `Trailer:ICC_Profile` binary placeholder (the still-compressed
# 3-byte body) that the port suppresses (no ICC_Profile sub-port) — the
# conformance check drops that one key.
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   ExifTool:Warning  = "[minor] Trailer data after PNG IEND chunk"
#   Trailer:Warning   = "Error inflating iCCP"
#   Trailer:ProfileName = "ICC"
def build_trailer_iccp_warn() -> bytes:
    # iCCP = keyword \0 compression_method(0) compressed_profile.
    # A 3-byte garbage "compressed profile" is not a valid zlib stream.
    iccp_body = b"ICC\x00\x00" + b"\xff\xff\xff"
    return (
        SIG
        + ihdr(1, 1)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
        + chunk(b"iCCP", iccp_body)
    )


# ── #178-item1 — nested-zXIf inner inflate recursion warning text ────────────
# A `zxIf` (compressed EXIF) chunk whose body is `\0` + a 4-byte length field +
# a zlib stream that inflates to a SECOND `\0`-typed (still "compressed") block
# of only 3 bytes. Bundled's `ProcessPNG_eXIf` (`PNG.pm:1378-1389`) re-enters
# `FoundPNG` (level 2) on the inflated buffer and, seeing the `\0` type again,
# does `substr($inner, 5)` — which on the 3-byte inner block is empty/`undef`,
# so the second inflate FAILS ⇒ `Error inflating zxIf` (with a harmless `substr
# outside of string` Perl notice on stderr). The port (pre-#178) treated the
# sub-5-byte inner `\0` block as a non-II/MM TIFF and warned `Invalid zxIf
# chunk`; it now bounded-recurses the inner inflate (depth-guarded against a
# nested-compression DoS) so the warning matches bundled. Both extract no EXIF.
#
# Oracle (bundled `perl exiftool -G1 -j` 13.59):
#   ExifTool:Warning = "Error inflating zxIf"
#   PNG:zxIf = "<err>"   (a binary placeholder the port suppresses — dropped)
def build_nested_zxif() -> bytes:
    inner = b"\x00\x00\x00"  # \0-typed, 3 bytes (< 5) -> inner substr empty
    comp = zlib.compress(inner)
    zxif_body = b"\x00" + struct.pack(">I", len(inner)) + comp
    return (
        SIG
        + ihdr(1, 1)
        + chunk(b"zxIf", zxif_body)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
    )


# ── #180 — TRAILER diagnostic re-scoping for an embedded XMP sub-Meta ─────────
# A `\n<type>\n<8-wide len>\n<hex>\n` ImageMagick "Raw profile type X" body, the
# tEXt framing `convert -profile` writes (PNG.pm:1166).
def raw_profile_text(profile_type: str, payload: bytes) -> bytes:
    body = "\n%s\n%8d\n%s\n" % (profile_type, len(payload), payload.hex())
    keyword = ("Raw profile type %s" % profile_type).encode("latin-1")
    return chunk(b"tEXt", keyword + b"\0" + body.encode("latin-1"))


# The double-UTF-encoded XMP packet (a RAW leading UTF-8 BOM directly before
# `<?xpacket`) that trips ExifTool's double-encoding probe (XMP.pm:4310) and
# raises the XMP `$et->Warn('XMP is double UTF-encoded')` (XMP.pm:4494). Same
# packet `gen_png_rawprofile_fixtures.py::XMP_DOUBLE_PACKET` uses for the #205
# pre-IEND walk-order fixture; here it rides a POST-IEND trailer chunk.
XMP_DOUBLE_PACKET = (
    b"\xef\xbb\xbf"
    b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>"
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
    b"<dc:format>image/png</dc:format>"
    b"</rdf:Description></rdf:RDF></x:xmpmeta>"
    b"<?xpacket end='w'?>"
)


# A complete (IEND-terminated) PNG followed by a TRAILER `Raw profile type xmp`
# tEXt chunk carrying the double-UTF packet. Bundled processes post-IEND chunks
# under `$$et{SET_GROUP1} = 'Trailer'` (PNG.pm:1479-1484), so the embedded XMP
# sub-Meta raises its `XMP is double UTF-encoded` `$et->Warn` (a DOCUMENT-level
# warning — empty `$grps[1]`) under that global ⇒ it resolves to the family-1
# `Trailer:Warning` TAG, NOT the document-level `ExifTool:Warning`
# (ExifTool.pm:9475). It then LOSES the priority-0 first-wins race
# (ExifTool.pm:5404-5417) to the EARLIER trailer `Trailer:Warning = "[minor]
# Text/EXIF chunk(s) found after PNG IDAT …"` (PNG.pm:1604, raised when the
# trailer tEXt chunk is first encountered), so it is SUPPRESSED — the observable
# proof that the XMP diagnostic was re-scoped to Trailer is the ABSENCE of a
# stray doc-level `ExifTool:Warning` for it. The decoded `XMP-dc:Format` tag
# keeps its EXPLICIT `XMP-dc` family-1 group (`SetGroup`, XMP.pm:3717 — the
# `$grps[1] or …` short-circuit, like the `Exif::Main` IFDs), NOT `Trailer`. The
# trailer-ENTRY warning `Trailer data after PNG IEND chunk` (PNG.pm:1481, raised
# BEFORE `SET_GROUP1`) stays the document `ExifTool:Warning` (and `[minor]`).
#
# Oracle (bundled `perl exiftool -G1 -j -struct` 13.59):
#   ExifTool:Warning = "[minor] Trailer data after PNG IEND chunk"
#   Trailer:Warning  = "[minor] Text/EXIF chunk(s) found after PNG IDAT …"
#   XMP-dc:Format    = "image/png"   (NOT Trailer:Format)
def build_trailer_xmp_warn() -> bytes:
    return (
        SIG
        + ihdr(1, 1)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
        + raw_profile_text("xmp", XMP_DOUBLE_PACKET)
    )


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)
    fixtures = {
        "PNG_trailer_iccp_warn.png": build_trailer_iccp_warn(),
        "PNG_nested_zxif.png": build_nested_zxif(),
        "PNG_trailer_xmp_warn.png": build_trailer_xmp_warn(),
    }
    for name, data in fixtures.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
