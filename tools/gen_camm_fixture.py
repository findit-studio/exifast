#!/usr/bin/env python3
"""Build the crafted Android CAMM (Camera Motion Metadata) `.mov` fixture.

exifast has no real Pixel/Samsung/Insta360 CAMM clip in `tests/fixtures/`
(only synthetic in-memory packets in `tests/quicktime_stream.rs`); this script
emits a *minimal* but bundled-ExifTool-decodable `.mov` carrying a `camm`
MetaFormat track so the timed-metadata `-ee` oracle goldens have a real on-disk
input (closes follow-up #60).

  python3 tools/gen_camm_fixture.py            # -> tests/fixtures/QuickTime_camm.mov
  python3 tools/gen_camm_fixture.py <outdir>

CAMM byte layout (Google Street View CAMM spec, mirrored from QuickTimeStream.pl
camm5/camm6 tables + the `build_mov_with_camm_track` / `camm5_packet` /
`camm6_packet` helpers in tests/quicktime_stream.rs). Each sample packet is

    [reserved:int16u(=0)][type:int16u-LE][payload…]      (little-endian)

so the offsets in the camm5/camm6 tables (4/12/20 ; 0x04/0x0c/0x10/0x18/0x20…)
are measured from the packet START (after the 4-byte reserved+type header):

  camm5 (24-byte payload, GROUPS=>Location):
    @4  double GPSLatitude   @12 double GPSLongitude   @20 double GPSAltitude
  camm6 (56-byte payload, GROUPS=>Location, GPSDateTime in Time):
    @0x04 double GPSDateTime  @0x0c int32u GPSMeasureMode
    @0x10 double GPSLatitude  @0x18 double GPSLongitude  @0x20 float GPSAltitude
    @0x24..0x38 float Horizontal/VerticalAccuracy, Velocity E/N/U, SpeedAccuracy

Three samples are emitted (two camm5 GPS fixes + one camm6 GPS+date+measure-mode
fix) so the fixture exercises the multi-fix `Doc<N>` document axis and the camm6
date/measure-mode columns. The samples are stored contiguously in `mdat`; the
sample table (stsz/stsc/stco/stts) describes all three in a single chunk so
ExifTool's `ProcessSamples` walks each as its own embedded document.

The structural atoms (ftyp/mvhd/trak/mdia/hdlr=mhlr+meta/minf/stbl/stsd=camm)
mirror `build_mov_with_camm_track` verbatim except the sample table is widened
from 1 to N samples. After running, regenerate the goldens with
`EE=1 EXCLUDE="-x System:all -x Composite:all" tools/gen_golden.sh
QuickTime_camm.mov` (bundled ExifTool).
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


# ── CAMM sample packets ──────────────────────────────────────────────────────
def camm_packet(type_id: int, payload: bytes) -> bytes:
    """`[reserved:2(=0)][type:int16u-LE][payload]`."""
    return b"\x00\x00" + struct.pack("<H", type_id) + payload


def camm5_packet(lat: float, lon: float, alt: float) -> bytes:
    """camm type 5: 3×double (GPSLatitude, GPSLongitude, GPSAltitude)."""
    return camm_packet(5, struct.pack("<ddd", lat, lon, alt))


def camm6_packet(
    gps_dt: float,
    measure_mode: int,
    lat: float,
    lon: float,
    alt: float,
    h_acc: float,
    v_acc: float,
    v_e: float,
    v_n: float,
    v_u: float,
    spd_acc: float,
) -> bytes:
    """camm type 6: double gps_dt, int32u measure_mode, double lat/lon,
    then float alt + 6 float accuracy/velocity columns."""
    payload = struct.pack(
        "<dIdd" + "f" * 7,
        gps_dt,
        measure_mode,
        lat,
        lon,
        alt,
        h_acc,
        v_acc,
        v_e,
        v_n,
        v_u,
        spd_acc,
    )
    return camm_packet(6, payload)


def build_camm_mov(samples) -> bytes:
    """Minimal `.mov`: ftyp / mdat(samples) / moov(mvhd + trak[camm meta])."""
    # ftyp 'qt  '.
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))

    # mdat: all sample packets stored back-to-back. The stco entry points at
    # the first packet (right after ftyp + the 8-byte mdat header).
    sample_blob = b"".join(samples)
    mdat = struct.pack(">I", len(sample_blob) + 8) + b"mdat" + sample_blob
    sample_base = len(ftyp) + 8  # file offset of the first sample
    sizes = [len(s) for s in samples]

    # mvhd (v0): timescale=1000, duration covers all samples.
    total_dur = 1000 * len(samples)
    mvhd_body = (
        b"\x00\x00\x00\x00"             # version+flags
        + b"\x00" * 8                   # create/modify
        + struct.pack(">I", 1000)       # timescale
        + struct.pack(">I", total_dur)  # duration
        + b"\x00" * 80                  # rest (rate/volume/matrix/…)
    )

    # hdlr: mhlr / meta (the meta_handler the camm stsd dispatches through).
    hdlr_body = (
        b"\x00\x00\x00\x00"  # version+flags
        + b"mhlr"            # pre_defined
        + b"meta"            # handler_type
        + b"\x00" * 12       # reserved
        + b"\x00"            # name (empty)
    )

    # mdhd (v0): timescale=1000, duration covers all samples.
    mdhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4  # language+quality
    )

    # stsd: 1 entry whose 4-byte format code is `camm`.
    stsd_entry = struct.pack(">I", 16) + b"camm" + b"\x00" * 6 + struct.pack(">H", 1)
    stsd_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + stsd_entry

    # stts: one run of N samples, delta=1000 each (>1 entry total so ExifTool's
    # ProcessSamples enters the time-grouping branch).
    stts_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)              # entry count
        + struct.pack(">II", len(samples), 1000)
    )

    # stsc: all samples in one chunk (first_chunk=1, samples_per_chunk=N, desc=1).
    stsc_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">III", 1, len(samples), 1)
    )

    # stsz: variable sizes (sample_size=0), explicit per-sample sizes.
    stsz_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)              # sample_size=0 → variable
        + struct.pack(">I", len(samples))   # count
        + b"".join(struct.pack(">I", s) for s in sizes)
    )

    # stco: single chunk offset at the first sample inside mdat.
    stco_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", sample_base)
    )

    stbl = atom(b"stbl",
                atom(b"stsd", stsd_body)
                + atom(b"stts", stts_body)
                + atom(b"stsc", stsc_body)
                + atom(b"stsz", stsz_body)
                + atom(b"stco", stco_body))
    minf = atom(b"minf", atom(b"nmhd", b"\x00\x00\x00\x00") + stbl)
    mdia = atom(b"mdia",
                atom(b"mdhd", mdhd_body)
                + atom(b"hdlr", hdlr_body)
                + minf)
    trak = atom(b"trak", atom(b"tkhd", b"\x00" * 84) + mdia)
    moov = atom(b"moov", atom(b"mvhd", mvhd_body) + trak)

    # ftyp / mdat / moov — the stco offset lands inside the mdat placed right
    # after ftyp.
    return ftyp + mdat + moov


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)

    # Two camm5 GPS fixes (Seattle-ish, then Sydney-ish) + one camm6 fix that
    # also carries GPSDateTime + a 3-D measure mode and the accuracy/velocity
    # columns. CreateDate is zero (0000:00:00) so the camm6 GPSDateTime
    # ValueConv leaves $val on the Unix epoch (≈ 2024-01-07) directly.
    samples = [
        camm5_packet(47.628423, -122.165016, 123.0),
        camm5_packet(33.752000, 151.205667, 80.0),
        camm6_packet(
            1704626355.0,  # 2024-01-07 11:19:15 UTC
            3,             # 3-Dimensional Measurement
            37.422000,     # lat
            -122.084000,   # lon
            5.5,           # alt (m)
            2.0,           # horizontal accuracy
            3.0,           # vertical accuracy
            0.25,          # velocity east
            -0.5,          # velocity north
            0.1,           # velocity up
            0.4,           # speed accuracy
        ),
    ]

    data = build_camm_mov(samples)
    path = os.path.join(outdir, "QuickTime_camm.mov")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
