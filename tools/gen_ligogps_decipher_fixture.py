#!/usr/bin/env python3
"""Build the crafted `gpmd`-Kingslim `.mov` fixture that exercises ExifTool's
LigoGPS *cipher-discovery* fallback — `DecipherLigoGPS` (LigoGPS.pm:143-221) +
`OrderCipherDigits` (:109-135) — ported in exifast #136.

Real dashcam clips decode their `####`-prefixed LigoGPS records via
`DecryptLigoGPS` (LigoGPS.pm:50-99) on the first record, so the deciphered
fallback never fires; exifast has no real *enciphered* clip. This script emits a
*minimal* but bundled-ExifTool-decodable `.mov` carrying a single `gpmd`
MetaFormat sample whose LigoGPS block holds 12 ENCIPHERED records, forcing the
discovery path:

  * Each record is `####` + a 4-byte counter of 0 (LE u32 < 4 ⇒ `DecryptLigoGPS`
    returns undef at LigoGPS.pm:54 ⇒ ExifTool falls through to `DecipherLigoGPS`,
    QuickTimeStream.pl/LigoGPS.pm:312-313) + the date/time/GPS text with every
    byte in `0x30..=0x5f` enciphered by a fixed rotation (the structural `/`,
    ` `, `.`, `-` bytes are outside that range and pass through).
  * The seconds advance 00..11, so the unit-digit transitions fill all 10 of
    ExifTool's `next` adjacency keys (LigoGPS.pm:176); record 11 triggers
    discovery (`OrderCipherDigits` + the millennium '2' anchor + the lat/lon
    quadrant), the 11 cached records decipher + parse, and record 12 exercises
    the post-discovery direct-decipher path (LigoGPS.pm:311).

The cipher rotation is K=11, chosen so the enciphered colon `E(':')` = 'E' is a
plain byte — NOT a Perl regex metacharacter. ExifTool interpolates `$colon` RAW
into its quadrant regex (LigoGPS.pm:191 `/ ([0-_])$colon(-?)…/`), so a colon that
enciphered to one of the in-range regex metacharacters (question-mark, open/close
bracket, backslash, caret) would make ExifTool's OWN detection misbehave; a clean
colon keeps bundled + exifast (which matches the colon as a literal byte)
byte-identical.

The container is the `gpmd`-Kingslim route shared with
`gen_freegps_gpmd_fixture.py::kingslim_sample` — `gpmd_Kingslim` Condition
`^.{21}\\0\\0\\0A[NS][EW]` (QuickTimeStream.pl:183) → `ProcessFreeGPS` → the
GPSType-5 `.{80}LIGOGPSINFO\\0` arm (:1843-1888) → `ProcessLigoGPS` with
`DirStart = 80`. The `LIGOGPSINFO\\0` block sits at offset 0x50 (80); its records
start at 0x50+0x14 (100). Preamble bytes 92..96 = `\\0\\0\\0\\x14` set
`ProcessLigoGPS`'s `noFuzz` (LigoGPS.pm:299), so the lat/lon are the raw
(un-defuzzed) coordinates and the speed uses the knots→km/h scale (1.852).

  python3 tools/gen_ligogps_decipher_fixture.py            # -> tests/fixtures/QuickTime_ligogps_decipher.mov
  python3 tools/gen_ligogps_decipher_fixture.py <outdir>

After running, regenerate the `-ee` goldens with bundled ExifTool 13.59:
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_ligogps_decipher.mov
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_freegps_gpmd_fixture import build_gpmd_mov

# Cipher: rotation by K on the enciphered byte range 0x30..=0x5f (a bijection;
# bytes outside the range pass through, matching ExifTool's `s/([0-_])/…/g`).
# K=11 keeps E(':') = 'E' a non-metacharacter (see module docstring).
CIPHER_K = 11


def encipher(text: str) -> bytes:
    out = bytearray()
    for c in text.encode("ascii"):
        out.append(0x30 + ((c - 0x30 + CIPHER_K) % 48) if 0x30 <= c <= 0x5F else c)
    return bytes(out)


def enciphered_record(body: str) -> bytes:
    """One 0x84-byte LigoGPS record: `####` + counter(0) + enciphered(body) + NUL
    pad. The counter LE u32 = 0 < 4 makes `DecryptLigoGPS` fail (LigoGPS.pm:54),
    routing the record to `DecipherLigoGPS`."""
    rec = b"####" + struct.pack("<I", 0) + encipher(body)
    assert len(rec) <= 0x84, len(rec)
    return rec + b"\x00" * (0x84 - len(rec))


def ligogps_decipher_sample(n_records: int = 12) -> bytes:
    """A `gpmd`-Kingslim sample whose LigoGPS block carries `n_records`
    enciphered records (seconds 00..n-1) at a fixed -31.285065 S / -124.759483 W
    fix. 12 records ⇒ discovery at record 11 + one post-discovery record."""
    size = 100 + n_records * 0x84
    d = bytearray(size)
    # gpmd_Kingslim Condition `^.{21}\0\0\0A[NS][EW]`: A@24 / N@25 / W@26.
    d[24], d[25], d[26] = ord("A"), ord("N"), ord("W")
    d[80:92] = b"LIGOGPSINFO\0"           # GPSType-5 block at offset 0x50.
    d[92:96] = b"\x00\x00\x00\x14"        # ProcessLigoGPS noFuzz (LigoGPS.pm:299).
    records = b"".join(
        enciphered_record(
            f"2024/06/27 12:34:{s:02d} S:-31.285065 W:-124.759483 20.50"
        )
        for s in range(n_records)
    )
    d[100 : 100 + len(records)] = records
    return bytes(d)


def main(outdir: str) -> None:
    mov = build_gpmd_mov([ligogps_decipher_sample(12)])
    path = os.path.join(outdir, "QuickTime_ligogps_decipher.mov")
    with open(path, "wb") as f:
        f.write(mov)
    print(f"wrote {path} ({len(mov)} bytes)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures"
    )
    main(os.path.abspath(out))
