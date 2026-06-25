#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the MNG/JNG conformance fixtures for the MNG.pm sub-table port (#143).
#
# MNG (Multi-image Network Graphics) and JNG (JPEG Network Graphics) are
# PNG-sibling containers (`PNG.pm:63-64`): a PNG-style 8-byte signature
# (`\x8aMNG…` / `\x8bJNG…`) followed by the same `length + 4-char-type + data +
# CRC` chunk stream. `PNG.pm`'s ProcessPNG walks BOTH; a chunk NOT in
# `%PNG::Main` is dispatched against the `%MNG::Main` FALLBACK table
# (`PNG.pm:1655`). The header chunk is `MHDR`/`JHDR`; the END chunk is
# `MEND` (MNG) / `IEND` (JNG, the same as PNG).
#
#   * MNG_mhdr.mng  — minimal MNG: MHDR (28B, 7x int32u) + MEND. Exercises the
#     MNGHeader sub-table (FORMAT int32u) incl. the SimplicityProfile
#     `sprintf("0x%.8x")` PrintConv hand-port.
#   * JNG_jhdr.jng  — minimal JNG: JHDR (16B) + IEND. Exercises the JNGHeader
#     sub-table (W/H int32u, then int8u fields) incl. the ColorType/Compression/
#     Interlace/AlphaCompression PrintConvs.
#   * MNG_chunks.mng — a kitchen-sink MNG: MHDR + one chunk per remaining
#     sub-table (BACK/BASI/CLIP/CLON/DEFI/DHDR/eXPi/fPRI/LOOP/MAGN/MOVE/PAST/
#     PROM/SHOW/TERM) + the inline ValueConvs (DISC/DROP/SEEK) + the Binary=>1
#     chunks (DBYK/FRAM/nEED/ORDR/PPLT/SAVE) + pHYg (→ PNG-pHYs) + MEND. Covers
#     all 17 ProcessBinaryData sub-tables, the 5 hand-ported conv traps, the 6
#     Binary placeholders, and the shared-pHYs routing in ONE file.
#   * MNG_embedded_ihdr.mng — a realistic mixed MNG: MHDR (ImageWidth=160,
#     ImageHeight=120) THEN an embedded PNG `IHDR` chunk (ImageWidth=320,
#     ImageHeight=240) THEN MEND. The header `MHDR` dispatches the MNGHeader
#     sub-table (`MNG:ImageWidth=160`); the embedded `IHDR` dispatches the PNG
#     ImageHeader sub-table (`PNG:ImageWidth=320`) — `ProcessPNG` resolves a
#     chunk against `%PNG::Main` BEFORE the `%MNG::Main` fallback (`PNG.pm:1653-
#     1656`), so IHDR wins PNG::Main. `Composite:ImageSize` Requires the bare
#     `ImageWidth`/`ImageHeight`: both the MNG (MHDR) and PNG-IHDR producers are
#     equal priority 1, and ExifTool keeps the LAST-walked of an equal-priority
#     duplicate, so the IHDR (walked AFTER MHDR) wins ⇒ `Composite:ImageSize`
#     = `320x240`. A regression guard that the realistic MHDR→IHDR case matches
#     bundled byte-for-byte (the crafted three-equal-producer Case-A composite-
#     priority divergence is deferred to #436).
#
# Usage: python3 tools/gen_mng_fixtures.py [OUTDIR]   (default: <repo>/tests/fixtures)
#
# Regenerate goldens after building (bundled ExifTool 13.59):
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh MNG_mhdr.mng
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh JNG_jhdr.jng
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh MNG_chunks.mng
#   EXIFTOOL=../exiftool/exiftool tools/gen_golden.sh MNG_embedded_ihdr.mng
import os
import struct
import sys
import zlib

MNG_SIG = b"\x8aMNG\r\n\x1a\n"
JNG_SIG = b"\x8bJNG\r\n\x1a\n"


def chunk(typ: bytes, data: bytes) -> bytes:
    assert len(typ) == 4
    crc = zlib.crc32(typ + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", crc)


# ── MHDR — MNGHeader (FORMAT int32u): 7 x int32u = 28 bytes ──────────────────
#   0 ImageWidth, 1 ImageHeight, 2 TicksPerSecond, 3 NominalLayerCount,
#   4 NominalFrameCount, 5 NominalPlayTime, 6 SimplicityProfile (0x%.8x).
def mhdr(width=160, height=120, ticks=30, layers=5, frames=10, play=0,
         simplicity=0x00000049) -> bytes:
    body = struct.pack(">7I", width, height, ticks, layers, frames, play, simplicity)
    assert len(body) == 28
    return chunk(b"MHDR", body)


# ── JHDR — JNGHeader: W/H int32u then int8u fields (16 bytes) ─────────────────
#   0 ImageWidth(int32u), 4 ImageHeight(int32u), 8 ColorType, 9 BitDepth,
#   10 Compression, 11 Interlace, 12 AlphaBitDepth, 13 AlphaCompression,
#   14 AlphaFilter, 15 AlphaInterlace.
def jhdr(width=320, height=240, color=10, bitdepth=8, compression=8,
         interlace=0, alpha_bitdepth=8, alpha_compression=8, alpha_filter=0,
         alpha_interlace=0) -> bytes:
    body = struct.pack(">II", width, height) + bytes(
        [color, bitdepth, compression, interlace, alpha_bitdepth,
         alpha_compression, alpha_filter, alpha_interlace]
    )
    assert len(body) == 16
    return chunk(b"JHDR", body)


# ── IHDR — PNG ImageHeader (PNG.pm:387-423), the standard 13-byte PNG header:
#   0 ImageWidth(int32u), 4 ImageHeight(int32u), 8 BitDepth, 9 ColorType,
#   10 Compression, 11 Filter, 12 Interlace.
def ihdr(width=320, height=240, bitdepth=8, color=6, compression=0, filt=0,
         interlace=0) -> bytes:
    body = struct.pack(">II", width, height) + bytes(
        [bitdepth, color, compression, filt, interlace]
    )
    assert len(body) == 13
    return chunk(b"IHDR", body)


def build_mng_mhdr() -> bytes:
    # Minimal MNG: signature + MHDR (the header chunk) + MEND (the END chunk).
    return MNG_SIG + mhdr() + chunk(b"MEND", b"")


def build_mng_embedded_ihdr() -> bytes:
    # Realistic mixed MNG: signature + MHDR (160x120, the header chunk) + an
    # embedded PNG IHDR (320x240) + MEND. The MHDR emits MNG:ImageWidth/Height;
    # the IHDR — resolved against %PNG::Main BEFORE the %MNG::Main fallback
    # (PNG.pm:1653-1656) — emits PNG:ImageWidth/Height. Both feed the bare-name
    # Composite:ImageSize; equal priority 1 ⇒ the LAST-walked (IHDR) wins ⇒
    # Composite:ImageSize = 320x240.
    return MNG_SIG + mhdr() + ihdr() + chunk(b"MEND", b"")


def build_jng_jhdr() -> bytes:
    # Minimal JNG: signature + JHDR (the header chunk) + IEND (the END chunk).
    return JNG_SIG + jhdr() + chunk(b"IEND", b"")


def _buf(size: int) -> bytearray:
    return bytearray(size)


def _u8(b: bytearray, off: int, v: int) -> None:
    b[off] = v & 0xFF


def _u16(b: bytearray, off: int, v: int) -> None:
    struct.pack_into(">H", b, off, v)


def _u32(b: bytearray, off: int, v: int) -> None:
    struct.pack_into(">I", b, off, v)


def build_mng_chunks() -> bytes:
    # The sub-table bodies are built as zero-filled buffers with each leaf poked
    # at its EXACT MNG.pm offset — several layouts gap or OVERLAP (e.g. BASI
    # Viewable@26 reads a byte inside AlphaSample's int32u @25-28), which the
    # poke model handles without offset arithmetic. The buffer is sized to the
    # largest leaf extent so every leaf is in range (per-field availability).
    parts = [MNG_SIG, mhdr()]

    # ── BACK — BackgroundColor int16u[3]@0, MandatoryBackground@6,
    #    BackgroundImageID int16u@7, BackgroundTiling@9. (extent 10)
    back = _buf(10)
    _u16(back, 0, 255); _u16(back, 2, 128); _u16(back, 4, 0)
    _u8(back, 6, 2); _u16(back, 7, 7); _u8(back, 9, 1)
    parts.append(chunk(b"BACK", bytes(back)))

    # ── BASI — W/H int32u@0/4, BitDepth@8, ColorType@9, Compression@10, Filter@11,
    #    Interlace@12, Red/Green/Blue/Alpha int32u@13/17/21/25, Viewable@26.
    #    AlphaSample@25 extends to 29 ⇒ buffer 29 (Viewable@26 is inside it).
    basi = _buf(29)
    _u32(basi, 0, 64); _u32(basi, 4, 48)
    _u8(basi, 8, 8); _u8(basi, 9, 6); _u8(basi, 10, 0); _u8(basi, 11, 0); _u8(basi, 12, 1)
    _u32(basi, 13, 1); _u32(basi, 17, 2); _u32(basi, 21, 3); _u32(basi, 25, 4)
    _u8(basi, 26, 1)
    parts.append(chunk(b"BASI", bytes(basi)))

    # ── CLIP — FirstObject int16u@0, LastObject int16u@2, DeltaType@4,
    #    ClipBoundary int32u[4]@5. (extent 21)
    clip = _buf(21)
    _u16(clip, 0, 1); _u16(clip, 2, 3); _u8(clip, 4, 1)
    _u32(clip, 5, 0); _u32(clip, 9, 100); _u32(clip, 13, 0); _u32(clip, 17, 200)
    parts.append(chunk(b"CLIP", bytes(clip)))

    # ── CLON — SourceID int16u@0, CloneID int16u@2, CloneType@4, DoNotShow@5,
    #    ConcreteFlag@6, LocalDeltaType@7, DeltaXY int32u[2]@8. (extent 16)
    clon = _buf(16)
    _u16(clon, 0, 5); _u16(clon, 2, 6); _u8(clon, 4, 1); _u8(clon, 5, 0)
    _u8(clon, 6, 1); _u8(clon, 7, 1); _u32(clon, 8, 10); _u32(clon, 12, 20)
    parts.append(chunk(b"CLON", bytes(clon)))

    # ── DEFI — ObjectID int16u@0, DoNotShow@2, ConcreteFlag@3,
    #    XYLocation int32u[2]@4, ClippingBoundary int32u[4]@12. (extent 28)
    defi = _buf(28)
    _u16(defi, 0, 7); _u8(defi, 2, 1); _u8(defi, 3, 0)
    _u32(defi, 4, 10); _u32(defi, 8, 20)
    _u32(defi, 12, 0); _u32(defi, 16, 100); _u32(defi, 20, 0); _u32(defi, 24, 200)
    parts.append(chunk(b"DEFI", bytes(defi)))

    # ── DHDR — ObjectID int16u@0, ImageType@2, DeltaType@3,
    #    BlockSize int32u[2]@4, BlockLocation int32u[2]@12. (extent 20)
    dhdr = _buf(20)
    _u16(dhdr, 0, 2); _u8(dhdr, 2, 1); _u8(dhdr, 3, 7)
    _u32(dhdr, 4, 32); _u32(dhdr, 8, 24); _u32(dhdr, 12, 0); _u32(dhdr, 16, 0)
    parts.append(chunk(b"DHDR", bytes(dhdr)))

    # ── eXPi — SnapshotID int16u@0, SnapshotName string@2 (to end of chunk).
    expi = struct.pack(">H", 9) + b"snap one"
    parts.append(chunk(b"eXPi", expi))

    # ── fPRI — DeltaType@0, Priority@2. (extent 3)
    fpri = _buf(3)
    _u8(fpri, 0, 1); _u8(fpri, 2, 200)
    parts.append(chunk(b"fPRI", bytes(fpri)))

    # ── LOOP — NestLevel@0, IterationCount int32u@1, TerminationCondition@5,
    #    IterationMinMax int32u[2]@6, SignalNumber int32u@14. (extent 18)
    loop = _buf(18)
    _u8(loop, 0, 2); _u32(loop, 1, 100); _u8(loop, 5, 3)
    _u32(loop, 6, 1); _u32(loop, 10, 10); _u32(loop, 14, 1)
    parts.append(chunk(b"LOOP", bytes(loop)))

    # ── MAGN — First/Last ObjectID int16u@0/2, XMethod@4, XMag int16u@5, YMag@7,
    #    LeftMag@9, RightMag@11, TopMag@13, BottomMag@15, YMethod@17. (extent 18)
    magn = _buf(18)
    _u16(magn, 0, 1); _u16(magn, 2, 5); _u8(magn, 4, 2)
    _u16(magn, 5, 2); _u16(magn, 7, 2); _u16(magn, 9, 1)
    _u16(magn, 11, 1); _u16(magn, 13, 1); _u16(magn, 15, 1); _u8(magn, 17, 3)
    parts.append(chunk(b"MAGN", bytes(magn)))

    # ── MOVE — First/Last int16u@0/2, DeltaType@4, DeltaXY int32u[2]@5. (extent 13)
    move = _buf(13)
    _u16(move, 0, 1); _u16(move, 2, 3); _u8(move, 4, 1)
    _u32(move, 5, 5); _u32(move, 9, 10)
    parts.append(chunk(b"MOVE", bytes(move)))

    # ── PAST — DestinationID int16u@0, TargetDeltaType@2, TargetXY int32u[2]@3,
    #    SourceID int16u@11, CompositionMode@13, Orientation@14, OffsetOrigin@15,
    #    OffsetXY int32u[2]@16, BoundaryOrigin@24, PastClippingBoundary
    #    int32u[4]@25. (extent 41)
    past = _buf(41)
    _u16(past, 0, 1); _u8(past, 2, 1); _u32(past, 3, 0); _u32(past, 7, 0)
    _u16(past, 11, 2); _u8(past, 13, 0); _u8(past, 14, 4); _u8(past, 15, 1)
    _u32(past, 16, 0); _u32(past, 20, 0); _u8(past, 24, 1)
    _u32(past, 25, 0); _u32(past, 29, 10); _u32(past, 33, 0); _u32(past, 37, 20)
    parts.append(chunk(b"PAST", bytes(past)))

    # ── PROM — NewColorType@0, NewBitDepth@1, FillMethod@2. (extent 3)
    prom = _buf(3)
    _u8(prom, 0, 6); _u8(prom, 1, 8); _u8(prom, 2, 1)
    parts.append(chunk(b"PROM", bytes(prom)))

    # ── SHOW — First/Last int16u@0/2, ShowMode@4. (extent 5)
    show = _buf(5)
    _u16(show, 0, 1); _u16(show, 2, 3); _u8(show, 4, 1)
    parts.append(chunk(b"SHOW", bytes(show)))

    # ── TERM — TerminationAction@0, IterationEndAction@1, Delay int32u@2,
    #    IterationMax int32u@6. (extent 10)
    term = _buf(10)
    _u8(term, 0, 3); _u8(term, 1, 0); _u32(term, 2, 1000); _u32(term, 6, 5)
    parts.append(chunk(b"TERM", bytes(term)))

    # ── DISC — DiscardObjects: inline ValueConv join(" ",unpack("n*",$val)).
    parts.append(chunk(b"DISC", struct.pack(">3H", 1, 2, 3)))

    # ── DROP — DropChunks: inline ValueConv join(" ",$val=~/..../g) (4-char split).
    parts.append(chunk(b"DROP", b"BACKMHDR"))

    # ── SEEK — SeekPoint: inline ValueConv $val=~s/\0.*//s (NUL-strip).
    parts.append(chunk(b"SEEK", b"point1\x00trailing"))

    # ── Binary => 1 chunks: emit the (Binary data N bytes …) placeholder.
    parts.append(chunk(b"DBYK", b"keyword\x00data"))  # 12 bytes
    parts.append(chunk(b"FRAM", b"\x01frame params"))  # 13 bytes
    parts.append(chunk(b"nEED", b"draft 84\x00"))       # 9 bytes
    parts.append(chunk(b"ORDR", b"\x00\x01\x02\x03"))   # 4 bytes
    parts.append(chunk(b"PPLT", b"\x00" * 6))           # 6 bytes
    parts.append(chunk(b"SAVE", b""))                   # 0 bytes (still a placeholder)

    # ── pHYg — GlobalPixelSize → PNG::PhysicalPixel (the shared pHYs decoder),
    #    emitting PixelsPerUnitX/Y + PixelUnits under family-1 PNG-pHYs. (9 bytes)
    parts.append(chunk(b"pHYg", struct.pack(">II", 2835, 2835) + bytes([1])))

    parts.append(chunk(b"MEND", b""))
    return b"".join(parts)


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures"
    )
    os.makedirs(outdir, exist_ok=True)
    for name, builder in [
        ("MNG_mhdr.mng", build_mng_mhdr),
        ("JNG_jhdr.jng", build_jng_jhdr),
        ("MNG_chunks.mng", build_mng_chunks),
        ("MNG_embedded_ihdr.mng", build_mng_embedded_ihdr),
    ]:
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(builder())
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
