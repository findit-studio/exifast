#!/usr/bin/env python3
"""Build the DJI Glamour MULTI-`btec` fixture (#111 R3).

A companion to the happy-path `QuickTime_dji_glamour.mov`
(tools/gen_dji_glamour_fixture.py) and the edge fixture
`QuickTime_dji_glamour_edge.mov` (tools/gen_dji_glamour_edge_fixture.py); this
one pins the Codex R2 finding that ExifTool's tag-dedup is GLOBAL across the
whole `udta` walk, NOT per-`btec`-atom: a `key` repeated in a LATER `btec` atom
overwrites the earlier value AND moves the surviving entry to its LAST
file-order position.

Two `btec` atoms in one `moov/udta`:
  - atom 1: `beauty_enable=1;smoother=2;`
  - atom 2: `beauty_enable=3;whitening=4;`

ExifTool's global dedup ⇒ `beauty_enable` survives with value 3 (atom 2) at its
atom-2 position, so the emitted order is:
  DJI:Smoother 2, DJI:BeautyEnable 3, DJI:Whitening 4.

Validated against bundled ExifTool 13.59 (`exiftool -j -G1`):
  DJI:Smoother 2, DJI:BeautyEnable 3, DJI:Whitening 4.

The structural atoms (ftyp/mvhd/trak) are sliced verbatim from the known-good
QuickTime_sp2_keys_direction.mov template (only the two `btec` udta atoms are
new). After running, regenerate the goldens with tools/gen_golden.sh (bundled
ExifTool).

  python3 tools/gen_dji_glamour_multi_fixture.py
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
    # Two `btec` GlamourSettings atoms; `beauty_enable` recurs across them, so
    # the global tag-dedup keeps the LAST value (3) at the LAST file-order
    # position. `smoother` (atom 1) and `whitening` (atom 2) each appear once.
    btec1 = atom(b"btec", b"beauty_enable=1;smoother=2;")
    btec2 = atom(b"btec", b"beauty_enable=3;whitening=4;")
    mov = build_mov(atom(b"udta", btec1 + btec2))
    path = os.path.join(FIXDIR, "QuickTime_dji_glamour_multi.mov")
    with open(path, "wb") as f:
        f.write(mov)
    print(f"wrote {path} ({len(mov)} bytes)")


if __name__ == "__main__":
    main()
