#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the JUMBF / C2PA conformance fixtures for the PNG caBX box-structure
# port (#142). Phase 1: structure + the jumd description layer + the bfdb/bidb/
# c2sh binary content. Phase 2: the `json` content box (PNG_cabx_json.png).
# Phase 3: the `cbor` content box (PNG_cabx_cbor.png).
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
#   * PNG_cabx_json.png (Phase 2) — jumb -> jumd(label "c2pa.test", JSON uuid) +
#     json{...}. A representative C2PA-ish JSON document exercising the JSON::Main
#     flattening: top-level keys -> JSON:<legalized-key> (ucfirst, the C2PA-case
#     hack, the `Tag` prefix), a nested object emitted as a -struct Map (raw
#     inner keys), arrays (of scalars + of objects), string/number(int+float)/
#     bool/null scalars, and a >15-digit number (quoted by the EscapeJSON gate).
#     The json box keeps group JSON (the JUMBFLabel rename does NOT touch the
#     flattened tag names). NOTE: the three Phase-1 fixtures above carry NO `json`
#     CONTENT box (only a `jumd` whose type-UUID happens to be the (json) UUID),
#     so their goldens are UNCHANGED by Phase 2 — only this new fixture emits
#     JSON:* tags.
#
# Usage: python3 tools/gen_jumbf_fixtures.py [OUTDIR]  (default: <repo>/tests/fixtures)
#
# Regenerate goldens after building (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_jumbf.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_binary.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_label_rename.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_json.png
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh PNG_cabx_cbor.png
import os
import struct
import sys
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# JSON content type-UUID (Jpeg2000.pm:754): ASCII "json" then the fixed tail.
JSON_UUID = b"json" + bytes.fromhex("00110010800000aa00389b71")
# CBOR content type-UUID: ASCII "cbor" then the same fixed tail (the JUMBF
# content-type-box convention, so JUMDType renders the (cbor) PrintConv prefix).
CBOR_UUID = b"cbor" + bytes.fromhex("00110010800000aa00389b71")
# Raw JPEG-image type-UUID (Jpeg2000.pm:756): a NON-ASCII first group.
JPEG_UUID = bytes.fromhex("6579d6fbdba2446bb2ac1b82feeb89d1")


# ----- a minimal CBOR encoder (RFC 8949), enough for the Phase-3 fixture -----
def _cbor_head(major: int, n: int) -> bytes:
    # The initial byte + minimal big-endian argument for a non-negative count n.
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)


class CborTag:
    # Wrap a value in a CBOR semantic tag (major 6), e.g. tag 0 (date string) or
    # tag 18 (COSE_Sign1 — stays OPAQUE: the wrapped bytes render as a placeholder).
    def __init__(self, num, value):
        self.num = num
        self.value = value


class CborHalf:
    # A raw half-precision (major 7, ai 25) value carrying the 16 IEEE bits, so
    # the fixture can exercise CBOR.pm's (faithfully buggy) half-float decode.
    def __init__(self, bits):
        self.bits = bits


def cbor(v) -> bytes:
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])          # major 7: true / false
    if v is None:
        return bytes([0xF6])                          # major 7: null
    if isinstance(v, CborHalf):
        return bytes([0xF9]) + struct.pack(">H", v.bits)
    if isinstance(v, CborTag):
        return _cbor_head(6, v.num) + cbor(v.value)
    if isinstance(v, int):
        return _cbor_head(0, v) if v >= 0 else _cbor_head(1, -1 - v)
    if isinstance(v, float):
        return bytes([0xFB]) + struct.pack(">d", v)   # major 7: double
    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v              # major 2: byte string
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _cbor_head(3, len(b)) + b              # major 3: text string
    if isinstance(v, list):
        out = _cbor_head(4, len(v))                   # major 4: array
        for e in v:
            out += cbor(e)
        return out
    if isinstance(v, dict):
        out = _cbor_head(5, len(v))                   # major 5: map
        for k, val in v.items():
            out += cbor(k) + cbor(val)
        return out
    raise TypeError(type(v))


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

    # 4) JSON content (Phase 2): jumb -> jumd(label "c2pa.test", JSON uuid) +
    #    json{...}. A representative C2PA-ish document. The byte-exact key order
    #    is preserved (ExifTool emits in document-key order); the JSON.pm
    #    flattening + EscapeJSON gate are exercised across every value type.
    #    Authored as a compact (no-whitespace) UTF-8 byte string so the on-disk
    #    box is deterministic.
    json_doc = (
        b'{'
        b'"claim_generator":"exifast/1.0",'      # string -> JSON:Claim_generator
        b'"format":"image/png",'                 # string -> JSON:Format
        b'"title":"A Title",'                    # spaced string value (quoted)
        b'"instanceID":"xmp:iid:1234",'          # ucfirst -> JSON:InstanceID
        b'"thumbnail":{'                         # nested object -> -struct Map
        b'"format":"image/jpeg",'                #   (raw inner keys, recursive)
        b'"identifier":"self#jumbf=c2pa.thumb",'
        b'"width":256,'                          #   nested int  -> bare 256
        b'"verified":true,'                      #   nested bool -> bare true
        b'"caption":null'                        #   nested null -> quoted "null"
        b'},'
        b'"assertions":[{"label":"c2pa.hash"},{"label":"stds.exif"}],'  # array of objects
        b'"ingredients":["a","b","c"],'          # array of scalar strings
        b'"version":2,'                          # integer  -> bare 2
        b'"score":0.95,'                          # float    -> bare 0.95
        b'"validated":true,'                      # boolean  -> bare true
        b'"revoked":false,'                       # boolean  -> bare false
        b'"signature":null,'                      # null     -> quoted "null"
        b'"serial":1234567890123456789,'          # >15-digit -> quoted (EscapeJSON gate)
        b'"c2pa.manifest":"urn:c2pa:abc-123"'     # C2PA-case hack -> JSON:C2PAmanifest
        b'}'
    )
    j4 = jumd_content(JSON_UUID, 0x03, label=b"c2pa.test")
    inner4 = box(b"jumd", j4) + box(b"json", json_doc)
    f4 = cabx_png(box(b"jumb", inner4))
    open(os.path.join(outdir, "PNG_cabx_json.png"), "wb").write(f4)

    # 5) CBOR content (Phase 3): jumb -> jumd(label "c2pa.test", CBOR uuid) +
    #    cbor{...}. A representative C2PA-ish CBOR document exercising the full
    #    CBOR::Main / ProcessCBOR decoder + the JSON::ProcessTag flatten:
    #      * text keys -> CBOR:<legalized-key>, + the CBOR::Main predefined names
    #        (dc:title -> Title, dc:format -> Format, instanceID -> InstanceID);
    #      * a positive int (bare), a NEGATIVE int exercising the faithful
    #        `-1 * num` ExifTool quirk (wire -7 -> -6), a >15-digit int (quoted
    #        by the EscapeJSON number gate);
    #      * a byte string -> the (Binary data N bytes) placeholder;
    #      * a nested map -> a -struct Map (raw inner keys, recursive: a nested
    #        negative -6, a nested byte-string placeholder, a nested empty array
    #        preserved as []);
    #      * an array of scalars + an array of maps;
    #      * a double float (0.5), a half-float (0x3c00 -> the buggy 7.8886e-31),
    #        true / false / null;
    #      * a tag-0 date-time string (ConvertXMPDate, locale-INDEPENDENT) and a
    #        COSE_Sign1 tag(18) wrapping bytes -> OPAQUE placeholder (no crypto);
    #      * the C2PA-case hack key (c2pa.manifest -> C2PAmanifest).
    #    NO tag-1 epoch is used (ConvertUnixTime is LOCAL-time => not byte-stable).
    #    The cbor box keeps family-0 JUMBF / family-1 CBOR (the CBORData tag lacks
    #    BlockExtract, so the JUMBFLabel rename never fires). Dict insertion order
    #    is the on-disk + emission key order (Python 3.7+ preserves it).
    cbor_doc = {
        "claim_generator": "exifast/1.0",      # text -> CBOR:Claim_generator
        "dc:title": "A Title",                 # predefined -> CBOR:Title
        "dc:format": "image/jpeg",             # predefined -> CBOR:Format
        "instanceID": "xmp:iid:9999",          # predefined -> CBOR:InstanceID
        "count": 42,                           # uint -> bare 42
        "neg": -7,                             # nint -> the -1*num quirk: -6
        "score": 0.5,                          # double -> 0.5
        "half": CborHalf(0x3C00),              # half (true 1.0) -> buggy 7.8886e-31
        "active": True,                        # bool -> true
        "revoked": False,                      # bool -> false
        "absent": None,                        # null -> quoted "null"
        "raw": bytes.fromhex("deadbeef"),      # byte string -> placeholder
        "thumbnail": {                         # nested map -> -struct Map
            "format": "image/jpeg",            #   (raw inner keys, recursive)
            "neg": -7,                         #   nested -1*num quirk -> -6
            "blob": bytes.fromhex("cafe"),     #   nested byte-string placeholder
            "tags": [],                        #   nested empty array preserved as []
        },
        "ingredients": ["a", "b", "c"],        # array of scalar strings
        "assertions": [                        # array of maps
            {"label": "c2pa.hash"},
            {"label": "stds.exif"},
        ],
        "created": CborTag(0, "2021-06-15T12:30:45Z"),  # tag-0 date -> ConvertXMPDate
        "signature": CborTag(18, bytes.fromhex("84a0a0f6")),  # COSE_Sign1 -> opaque
        "serial": 1234567890123456789,         # >15-digit uint -> quoted
        "c2pa.manifest": "urn:c2pa:abc-123",   # C2PA-case hack -> CBOR:C2PAmanifest
    }
    j5 = jumd_content(CBOR_UUID, 0x03, label=b"c2pa.test")
    inner5 = box(b"jumd", j5) + box(b"cbor", cbor(cbor_doc))
    f5 = cabx_png(box(b"jumb", inner5))
    open(os.path.join(outdir, "PNG_cabx_cbor.png"), "wb").write(f5)

    print(f"wrote 5 JUMBF fixtures to {outdir}")


if __name__ == "__main__":
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, "tests", "fixtures")
    main(out)
