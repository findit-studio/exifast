#!/usr/bin/env python3
"""Build the crafted Parrot ARCore `mett` timed-metadata `.mp4` fixture.

exifast ports the Parrot drone `mett` V1/V2/V3 + E1/E2/E3 records (real fixture
`MP4_parrot_anafi.mp4`), but the `application/arcore-*` MetaType branch
(Parrot.pm:60-83 → the `ARCoreAccel`/`ARCoreGyro` ProcessBinaryData subtables,
Parrot.pm:663-739) has no real on-disk ARCore-phone sample in either
`tests/fixtures/` or `exiftool/t/images`. This script emits a *minimal*
bundled-ExifTool-decodable `.mp4` carrying a `mett` track whose sample
description declares `MetaType = application/arcore-accel`, so the
timed-metadata `-ee` oracle goldens have a real input for the ARCore Accel
subtable (closes #123).

  python3 tools/gen_parrot_arcore_fixture.py        # -> tests/fixtures/QuickTime_parrot_arcore.mp4
  python3 tools/gen_parrot_arcore_fixture.py <outdir>

How ExifTool reaches the ARCore subtable
----------------------------------------
QuickTime.pm:7760-7774 (`%MetaSampleDesc`) decodes the `mett` `stsd` entry:
  * offset 4  -> `MetaFormat` (`undef[4]` = "mett");
  * offset 8  -> `MetaType` (`undef[$size-8]`, `RawConv` keeps the first
    `/(application[^\0]+)/` run). We place `application/arcore-accel\0` right
    after the 16-byte SampleDescription header so the scan picks it up.
`%QuickTime::Stream` routes a `mett` MetaFormat into `Parrot::Process_mett`,
which (Parrot.pm:802) takes the `if ($$tagTbl{$metaType})` branch for a known
`application/arcore-*` key and `HandleTag`s each `[0x0a][len:u8][payload]` TLV
record against `Parrot::ARCoreAccel`.

ARCore Accel record layout (Parrot.pm:663-693, ByteOrder => 'II')
-----------------------------------------------------------------
The record starts with the `0x0a` TLV tag byte, so the table offsets are
measured from THAT byte (the bundled comment `00-04: always 10 34 16 1 29`):
  * 0x00 = 0x0a (TLV tag)           0x01 = len (payload length, here 0x22 = 34)
  * 0x02..0x04 = 16 1 29            (the fixed `16 1 29` prefix)
  * @5  `Accelerometer` undef[14], RawConv joins three little-endian floats read
        at buffer offsets 0/5/10 (= record offsets 5/10/15) with single spaces;
  * @4  `AccelerometerUnknown` undef[16] (`Unknown => 1`, suppressed without -U).
The interleaved single bytes (records offsets 9/14/19 = `37 45 48`) are the
`AccelerometerUnknown` bytes the RawConv steps over.

Three samples (three distinct accel vectors) are stored contiguously in `mdat`,
each its own timed sample (stsz/stsc/stts describe three samples in one chunk),
so `ProcessSamples` opens one `Doc<N>` per sample and the ARCore Accelerometer
surfaces under `-ee` as `Track1:Accelerometer` (Doc1/2/3 at `-G3`). The vectors
are exact-in-f32 (0.125 / 0.25 / 9.8125 etc.) so the `%.15g` join is clean (no
uninitialized-value truncation).

After running, regenerate the goldens with
  EE=1 EXCLUDE="-x System:all -x Composite:all" tools/gen_golden.sh \
      QuickTime_parrot_arcore.mp4
(bundled ExifTool 13.59).
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def arcore_accel_record(fx: float, fy: float, fz: float) -> bytes:
    """One ARCore Accel TLV record `[0x0a][len][payload]` (Parrot.pm:663-693).

    `payload` is 34 bytes; the `Accelerometer` floats live at record offsets
    5/10/15 (buffer offsets 0/5/10 of the `undef[14]` value at @5). The bytes at
    record offsets 4/9/14/19 (`29 37 45 48`) are the `AccelerometerUnknown`
    samples the RawConv skips over.
    """
    body = bytearray(34)
    body[0] = 16          # record offset 2
    body[1] = 1           # record offset 3
    body[2] = 29          # record offset 4  (Unknown[0])
    body[3:7] = struct.pack("<f", fx)   # record offset 5  (Accelerometer X)
    body[7] = 37          # record offset 9  (Unknown[1])
    body[8:12] = struct.pack("<f", fy)  # record offset 10 (Accelerometer Y)
    body[12] = 45         # record offset 14 (Unknown[2])
    body[13:17] = struct.pack("<f", fz)  # record offset 15 (Accelerometer Z)
    body[17] = 48         # record offset 19 (Unknown[3])
    # record offsets 20..33: arbitrary trailing bytes (bundled: 128-255 etc.)
    for i in range(18, 34):
        body[i] = 200 + (i % 5)
    return b"\x0a" + bytes([len(body)]) + bytes(body)


def build_mett_mov(samples, meta_type: str) -> bytes:
    """Minimal `.mp4`: ftyp / mdat(samples) / moov(mvhd + trak[mett meta])."""
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))

    sample_blob = b"".join(samples)
    mdat = struct.pack(">I", len(sample_blob) + 8) + b"mdat" + sample_blob
    sample_base = len(ftyp) + 8  # file offset of the first sample
    sizes = [len(s) for s in samples]

    total_dur = 1000 * len(samples)
    mvhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 80
    )

    hdlr_body = (
        b"\x00\x00\x00\x00"
        + b"mhlr"
        + b"meta"
        + b"\x00" * 12
        + b"\x00"
    )

    mdhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4
    )

    # stsd: one entry whose format code is `mett`; the MetaType string is placed
    # after the standard 16-byte SampleDescription header (so the QuickTime.pm
    # offset-8 `/(application[^\0]+)/` scan finds it without colliding with the
    # 6 reserved bytes + DataReferenceIndex).
    meta_type_field = meta_type.encode("ascii") + b"\x00"
    stsd_entry_body = b"mett" + b"\x00" * 6 + struct.pack(">H", 1) + meta_type_field
    stsd_entry = struct.pack(">I", len(stsd_entry_body) + 4) + stsd_entry_body
    stsd_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + stsd_entry

    stts_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">II", len(samples), 1000)
    )

    stsc_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">III", 1, len(samples), 1)
    )

    stsz_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)
        + struct.pack(">I", len(samples))
        + b"".join(struct.pack(">I", s) for s in sizes)
    )

    stco_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", sample_base)
    )

    stbl = atom(
        b"stbl",
        atom(b"stsd", stsd_body)
        + atom(b"stts", stts_body)
        + atom(b"stsc", stsc_body)
        + atom(b"stsz", stsz_body)
        + atom(b"stco", stco_body),
    )
    minf = atom(b"minf", atom(b"nmhd", b"\x00\x00\x00\x00") + stbl)
    mdia = atom(
        b"mdia",
        atom(b"mdhd", mdhd_body) + atom(b"hdlr", hdlr_body) + minf,
    )
    trak = atom(b"trak", atom(b"tkhd", b"\x00" * 84) + mdia)
    moov = atom(b"moov", atom(b"mvhd", mvhd_body) + trak)

    return ftyp + mdat + moov


def main() -> None:
    outdir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tests",
            "fixtures",
        )
    )
    os.makedirs(outdir, exist_ok=True)

    # Three distinct ARCore Accel vectors, each exact in f32 (the `%.15g` join is
    # clean): a gravity-ish reading, then two small deltas.
    samples = [
        arcore_accel_record(0.125, -0.25, 9.8125),
        arcore_accel_record(0.5, 0.625, -0.75),
        arcore_accel_record(-1.5, 2.25, 9.75),
    ]

    data = build_mett_mov(samples, "application/arcore-accel")
    path = os.path.join(outdir, "QuickTime_parrot_arcore.mp4")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
