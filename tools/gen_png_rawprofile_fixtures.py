#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the minimal PNG fixtures for the ImageMagick "Raw profile type X"
# content decoders (issue #179). Each fixture is a 1x1 RGB PNG whose only
# non-structural chunk is a `tEXt` carrying an ImageMagick-style raw profile
# (`\n<type>\n<8-wide len>\n<hex bytes>`), exactly as `convert -profile` /
# `mogrify` writes them.
#
# Usage: python3 tools/gen_png_rawprofile_fixtures.py [OUTDIR]
#   OUTDIR defaults to <repo>/tests/fixtures
#
# Regenerate the goldens after (re)building a fixture:
#   EXIFTOOL=../exiftool/exiftool EXCLUDE="-x Composite:all" \
#     tools/gen_golden.sh PNG_rawprofile_xmp.png
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


def raw_profile_text(profile_type: str, payload: bytes) -> bytes:
    # ImageMagick body framing (PNG.pm:1166): "\n<type>\n  <len>\n<hex>\n".
    # The length field is %8d-padded; hex is the lowercase bytes.
    body = "\n%s\n%8d\n%s\n" % (profile_type, len(payload), payload.hex())
    keyword = ("Raw profile type %s" % profile_type).encode("latin-1")
    return chunk(b"tEXt", keyword + b"\0" + body.encode("latin-1"))


# A small, self-contained XMP packet carrying camera-relevant creator/title
# plus a couple of XMP-exif scalars, so both tag emission and the domain
# projection (CreatorTool / creator) are exercised.
XMP_PACKET = (
    b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="exifast 1.0">\n'
    b' <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
    b'  <rdf:Description rdf:about=""\n'
    b'    xmlns:dc="http://purl.org/dc/elements/1.1/"\n'
    b'    xmlns:xmp="http://ns.adobe.com/xap/1.0/"\n'
    b'    xmlns:exif="http://ns.adobe.com/exif/1.0/">\n'
    b"   <dc:format>image/png</dc:format>\n"
    b"   <dc:creator><rdf:Seq><rdf:li>Ansel Adams</rdf:li></rdf:Seq></dc:creator>\n"
    b'   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Moonrise</rdf:li></rdf:Alt></dc:title>\n'
    b"   <xmp:CreatorTool>exifast raw-profile demo</xmp:CreatorTool>\n"
    b"   <exif:DateTimeOriginal>2024-01-15T10:30:00+00:00</exif:DateTimeOriginal>\n"
    b"  </rdf:Description>\n"
    b" </rdf:RDF>\n"
    b"</x:xmpmeta>\n"
    b'<?xpacket end="w"?>'
)


def build_xmp_png() -> bytes:
    return (
        SIG
        + ihdr(1, 1)
        + raw_profile_text("xmp", XMP_PACKET)
        + idat_1x1_rgb()
        + chunk(b"IEND", b"")
    )


def raw_profile_text_odd_nibble(profile_type: str, payload: bytes) -> bytes:
    # A NONCANONICAL ImageMagick body: the hex string has a dangling odd nibble
    # (`a`) appended after the payload's clean hex. Perl `pack('H*')` pads it as
    # the HIGH half of a trailing `\xa0` byte (it does NOT drop it), so the
    # decoded profile is `payload + b"\xa0"` — one byte longer. The declared
    # length is set to that padded length so ExifTool reports NO wrong-size
    # warning; a decoder that truncates the dangling nibble would instead report
    # a spurious wrong-size mismatch. The trailing `\xa0` lands after the XMP
    # packet's `<?xpacket end>` and is tolerated by ExifTool's XMP parser, so the
    # XMP tags are identical to the canonical fixture's.
    hexstr = payload.hex() + "a"
    body = "\n%s\n%8d\n%s\n" % (profile_type, len(payload) + 1, hexstr)
    keyword = ("Raw profile type %s" % profile_type).encode("latin-1")
    return chunk(b"tEXt", keyword + b"\0" + body.encode("latin-1"))


def build_xmp_oddnibble_png() -> bytes:
    return (
        SIG
        + ihdr(1, 1)
        + raw_profile_text_odd_nibble("xmp", XMP_PACKET)
        + idat_1x1_rgb()
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
        "PNG_rawprofile_xmp.png": build_xmp_png(),
        "PNG_rawprofile_xmp_oddnibble.png": build_xmp_oddnibble_png(),
    }
    for name, data in fixtures.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
