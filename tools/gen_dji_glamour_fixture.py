#!/usr/bin/env python3
"""Build the crafted QuickTime DJI Glamour (`btec` UserData) fixture (#111).

A minimal `.mov`: `ftyp` + `moov`>(`mvhd`, `trak`, `udta`>`btec`) + `mdat`. The
`btec` GlamourSettings atom (QuickTime.pm:2161-2164) is a `SubDirectory` to
`%Image::ExifTool::DJI::Glamour` (DJI.pm:213-232), processed by `ProcessSettings`
(DJI.pm:944-954): a `;`-separated list of `key=value` beauty settings.

The settings body exercises:
  - ALL 15 KNOWN keys (locking the non-obvious `mouth_beautify` -> MouthModify
    and `acne_spot_removal` -> AcneSpotRemoval),
  - a trailing `;` (Perl `split /;/` drops the trailing empty piece),
  - ONE UNKNOWN key (`custom_thing`), which drives HandleTag's `MakeTagInfo`
    derivation (ExifTool.pm:9310-9318) -> `DJI:Custom_Thing`.

The structural atoms (ftyp/mvhd/trak) are sliced verbatim from the known-good
QuickTime_sp2_keys_direction.mov template, so only the `btec` udta atom is new
(avoids any hand-transcription / malformed-atom error). After running,
regenerate the goldens with tools/gen_golden.sh (bundled ExifTool).

  python3 tools/gen_dji_glamour_fixture.py
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
    # The `btec` GlamourSettings body: every known key (distinct values so each
    # tag is unambiguous in the golden) + one unknown key + a trailing `;`.
    settings = (
        b"beauty_enable=1;smoother=2;whitening=3;face_slimming=4;eye_enlarge=5;"
        b"nose_slimming=6;mouth_beautify=7;teeth_whitening=8;leg_longer=9;"
        b"head_shrinking=10;lipstick=11;blush=12;dark_circle=13;"
        b"acne_spot_removal=14;eyebrows=15;custom_thing=99;"
    )
    mov = build_mov(atom(b"udta", atom(b"btec", settings)))
    path = os.path.join(FIXDIR, "QuickTime_dji_glamour.mov")
    with open(path, "wb") as f:
        f.write(mov)
    print(f"wrote {path} ({len(mov)} bytes)")


if __name__ == "__main__":
    main()
