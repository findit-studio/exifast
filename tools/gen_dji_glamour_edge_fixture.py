#!/usr/bin/env python3
"""Build the DJI Glamour (`btec` UserData) EDGE fixture (#111 R2).

A companion to the happy-path `QuickTime_dji_glamour.mov`
(tools/gen_dji_glamour_fixture.py); this one exercises the byte-faithful edges
of `ProcessSettings` (DJI.pm:944-954) → the `%DJI::Glamour` table in ONE `btec`
body so the two Codex R1 findings are pinned by a golden:

  - a MALFORMED-HIGH-BYTE value (`beauty_enable=\\xff`): ExifTool's `EscapeJSON`
    classifies the raw bytes and `FixUTF8` turns the lone `0xff` into `?` — a
    quoted string, NOT `from_utf8_lossy`'s U+FFFD replacement char (Finding 1).
  - a NUL-SPLIT UTF-8 value (`smoother=\\xc2\\x00\\xa9` and the unknown
    `custom_thing=\\xc2\\x00\\xa9`): `EscapeJSON` DELETES the NUL first, so the
    `c2 a9` bytes rejoin and `FixUTF8` yields `©` — which `from_utf8_lossy` can
    never reassemble across the NUL (Finding 1; also covers an unknown key whose
    Name is derived via `HandleTag`/`MakeTagInfo`).
  - REPEATED keys (`whitening=1;…;whitening=2`): ExifTool's tag-dedup keeps the
    LAST-extracted value AT its file-order position — `Whitening=2` surfaces
    AFTER `EyeEnlarge` even though its first occurrence preceded it (Finding 2,
    bounding the sink to ≤ distinct Names).

Validated against bundled ExifTool 13.59 (`exiftool -j -G1`):
  DJI:BeautyEnable "?", DJI:Smoother "©", DJI:EyeEnlarge 10,
  DJI:Whitening 2, DJI:Custom_Thing "©".

The structural atoms (ftyp/mvhd/trak) are sliced verbatim from the known-good
QuickTime_sp2_keys_direction.mov template (only the `btec` udta atom is new).
After running, regenerate the goldens with tools/gen_golden.sh (bundled
ExifTool).

  python3 tools/gen_dji_glamour_edge_fixture.py
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXDIR = os.path.join(ROOT, "tests", "fixtures")

# Reusable structural atoms, sliced verbatim from the known-good SP2 template.
_TEMPLATE = open(os.path.join(FIXDIR, "QuickTime_sp2_keys_direction.mov"), "rb").read()
FTYP = _TEMPLATE[0:20]
MVHD = _TEMPLATE[28:136]
TRAK = _TEMPLATE[136:309]


def atom(typ: bytes, body: bytes) -> bytes:
    assert len(typ) == 4
    return struct.pack(">I", len(body) + 8) + typ + body


def build_mov(extra_moov_children: bytes) -> bytes:
    moov = atom(b"moov", MVHD + TRAK + extra_moov_children)
    mdat = atom(b"mdat", b"\x00" * 8)
    return FTYP + moov + mdat


def main():
    # The `btec` GlamourSettings body exercising all three edges (see module
    # docstring). `\xff` is a lone non-UTF8 byte; `\xc2\x00\xa9` is `©` split by
    # a NUL; `whitening` repeats with `eye_enlarge` between to prove the surviving
    # instance keeps the LAST file-order position.
    settings = (
        b"beauty_enable=\xff;"
        b"smoother=\xc2\x00\xa9;"
        b"whitening=1;"
        b"eye_enlarge=10;"
        b"whitening=2;"
        b"custom_thing=\xc2\x00\xa9;"
    )
    mov = build_mov(atom(b"udta", atom(b"btec", settings)))
    path = os.path.join(FIXDIR, "QuickTime_dji_glamour_edge.mov")
    with open(path, "wb") as f:
        f.write(mov)
    print(f"wrote {path} ({len(mov)} bytes)")


if __name__ == "__main__":
    main()
