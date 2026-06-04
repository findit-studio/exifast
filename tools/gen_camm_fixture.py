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


def camm1_packet(pixel_exposure_ns: int, rolling_shutter_skew_ns: int) -> bytes:
    """camm type 1: 2×int32s nanoseconds (PixelExposureTime, RollingShutter
    SkewTime). ExifTool ValueConv `$val * 1e-9` → seconds; PrintConv
    `sprintf("%.4g ms", $val * 1000)` (QuickTimeStream.pl:428-439)."""
    return camm_packet(1, struct.pack("<ii", pixel_exposure_ns, rolling_shutter_skew_ns))


def camm_vec3_packet(type_id: int, x: float, y: float, z: float) -> bytes:
    """camm types 2/3/4/7: a `float[3]` payload. The decoded value is the three
    floats space-joined via Perl's default `%.15g` stringification (`"@a"`):
    camm2 AngularVelocity, camm3 Acceleration, camm4 Position, camm7
    MagneticField (QuickTimeStream.pl:448/460/472/568)."""
    return camm_packet(type_id, struct.pack("<fff", x, y, z))


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

    # ── MOTION-only fixture (no GPS packets) ─────────────────────────────────
    # Each motion record is its own timed sample (one packet per sample, like
    # the GPS fixture), so `ProcessSamples` opens one `Doc<N>` per sample and the
    # camm MOTION telemetry surfaces under `-ee` as `Track1:AngularVelocity`
    # (Doc1) / `Track1:Acceleration` (Doc2) / `Track1:MagneticField` (Doc3) /
    # `Track1:PixelExposureTime`+`RollingShutterSkewTime` (Doc4). The vec3 values
    # are the three floats space-joined (`"@a"`, `%.15g`); the camm1 exposure
    # carries a `sprintf("%.4g ms", $val*1000)` PrintConv at `-j`. There are NO
    # GPS packets, so the no-`ee` path emits only the `Track1:Warning` (camm is a
    # handler `trak` = `-ee`-gated) — and this fixture canNOT populate
    # `Composite:GPSPosition`.
    motion_samples = [
        camm_vec3_packet(2, 0.1, -0.2, 0.3),       # AngularVelocity (rad/s)
        camm_vec3_packet(3, 0.01, 0.02, 9.81),     # Acceleration (m/s^2)
        camm_vec3_packet(7, 30.5, -15.25, 45.0),   # MagneticField (microtesla)
        camm1_packet(8_000_000, 1_500_000),        # 8 ms / 1.5 ms (ns in)
    ]
    motion = build_camm_mov(motion_samples)
    motion_path = os.path.join(outdir, "QuickTime_camm_motion.mov")
    with open(motion_path, "wb") as f:
        f.write(motion)
    print("wrote %s (%d bytes)" % (motion_path, len(motion)))

    # ── MULTI-PACKET single-sample fixture (two GPS packets in ONE sample) ───
    # ExifTool fires `FoundSomething` (++DOC_COUNT) ONCE per timed SAMPLE, then
    # `ProcessCAMM` `HandleTag`s EVERY packet of that sample under the SAME
    # `DOC_NUM` (QuickTimeStream.pl:1523/3493-3504). So two camm5 packets in one
    # sample share Doc1; a duplicate `GPSLatitude` WITHIN the doc REPLACES (last-
    # wins, ExifTool.pm:9564) — at `-ee -G1` the SECOND packet's coordinate
    # survives (40/50/60), NOT the first (10/20/30). This is the F2 within-doc-
    # last-wins pin (a pure first-wins collapse would wrongly keep 10/20/30).
    multi = build_camm_mov(
        [
            camm5_packet(10.0, 20.0, 30.0) + camm5_packet(40.0, 50.0, 60.0),
            camm5_packet(11.0, 21.0, 31.0),
        ]
    )
    multi_path = os.path.join(outdir, "QuickTime_camm_multipkt.mov")
    with open(multi_path, "wb") as f:
        f.write(multi)
    print("wrote %s (%d bytes)" % (multi_path, len(multi)))

    # ── FRACTIONAL-second camm6 GPSDateTime fixture (F1) ─────────────────────
    # The camm6 GPSDateTime ValueConv is `ConvertUnixTime($val, 0, -6) . 'Z'`
    # (QuickTimeStream.pl:522). The `-6` (NEGATIVE) format flag renders UP TO 6
    # fractional-second digits with trailing zeros stripped (a whole second →
    # no fractional part). Three camm6 GPS samples pin the rule against the
    # bundled oracle (`exiftool -ee -j -G3:1`):
    #   1704067200.789 -> Doc1 "2024:01:01 00:00:00.789Z"  (6-digit potential)
    #   1704067200.5   -> Doc2 "2024:01:01 00:00:00.5Z"    (NOT ".500000")
    #   1704067200.0   -> Doc3 "2024:01:01 00:00:00Z"      (whole second, none)
    # CreateDate is zero, so the GPS-vs-Unix-epoch heuristic does NOT shift —
    # each $val is taken as Unix-epoch seconds directly. (A pre-fix `as i64`
    # truncation would corrupt Doc1/Doc2 to `…00Z`.)
    frac = build_camm_mov(
        [
            camm6_packet(1704067200.789, 3, 37.5, -122.0, 100.0, 5.0, 10.0, 1.0, 2.0, 0.5, 0.1),
            camm6_packet(1704067200.5, 3, 37.6, -122.1, 101.0, 5.0, 10.0, 1.0, 2.0, 0.5, 0.1),
            camm6_packet(1704067200.0, 3, 37.7, -122.2, 102.0, 5.0, 10.0, 1.0, 2.0, 0.5, 0.1),
        ]
    )
    frac_path = os.path.join(outdir, "QuickTime_camm6_frac.mov")
    with open(frac_path, "wb") as f:
        f.write(frac)
    print("wrote %s (%d bytes)" % (frac_path, len(frac)))

    # ── camm0 / Unknown-record fixture (F2) ──────────────────────────────────
    # Type 0 (AngleAxis) is NOT in `ProcessCAMM`'s `%size` table, so the walk
    # `$et->Warn("Unknown camm record type 0"), last`s (QuickTimeStream.pl:3495)
    # — a PLAIN `$et->Warn` (no `ignorable` arg) ⇒ NO `[minor]` prefix. A single
    # camm0 sample pins the bundled `-ee` oracle `Track1:Warning "Unknown camm
    # record type 0"` (the camm0 AngleAxis itself is never decoded — R6). The
    # 12-byte float[3] body is unread (the walk stops on the type lookup).
    unknown = build_camm_mov([camm_packet(0, struct.pack("<fff", 1.0, 2.0, 3.0))])
    unknown_path = os.path.join(outdir, "QuickTime_camm0.mov")
    with open(unknown_path, "wb") as f:
        f.write(unknown)
    print("wrote %s (%d bytes)" % (unknown_path, len(unknown)))

    # ── Truncated-record fixture (F2) ────────────────────────────────────────
    # A camm5 declares 28 bytes (header included) but only 20 are present, so
    # `$pos + $size > $end and $et->Warn("Truncated camm record 5"), last`
    # (QuickTimeStream.pl:3496) — again NO `[minor]` prefix. Pins the bundled
    # `-ee` oracle `Track1:Warning "Truncated camm record 5"`.
    truncated = build_camm_mov([camm_packet(5, b"\x00" * 16)])
    truncated_path = os.path.join(outdir, "QuickTime_camm_trunc.mov")
    with open(truncated_path, "wb") as f:
        f.write(truncated)
    print("wrote %s (%d bytes)" % (truncated_path, len(truncated)))

    # ── MIXED warning+GPS-on-one-TRACK fixture (the -ee -G1 SampleTime gate) ──
    # Sample 0 is a camm0 (Unknown record type 0) → a `Track1:Warning` raised
    # INSIDE `ProcessCAMM` (QuickTimeStream.pl:3495); sample 1 is a camm5 GPS
    # fix. Both ride Track1 but DIFFERENT sample-table SampleTimes (Doc1 at
    # "0 s", Doc2 at "1.00 s" — the shared `stts` delta=1000 gives each sample
    # its own start). `FoundSomething` emits `SampleTime`/`SampleDuration` per
    # SAMPLE in sample order (QuickTimeStream.pl:967-972) BEFORE the ProcessCAMM
    # dispatch, and JSON `%noDups` is FIRST-wins (exiftool:2952-2953), so at
    # `-ee -G1` ExifTool keeps sample 0's `Track1:SampleTime "0 s"` (NOT sample
    # 1's "1.00 s"). Pins that exifast routes the warning-sample's SampleTime/
    # SampleDuration through the SAME first-seen timing gate the camm GPS/motion
    # emitters use (the warning emits first in `Meta::tags` order, so ITS timing
    # wins; the later GPS timing for Track1 is gated out). At `-ee -G3:1` each
    # doc keeps its own (Doc1 = "0 s"+Warning, Doc2 = "1.00 s"+GPS). All other
    # camm fixtures are GPS-only OR motion-only OR single-warning, so only this
    # one exercises the mixed warning+GPS-on-one-track timing collision.
    warn_gps = build_camm_mov(
        [
            camm_packet(0, struct.pack("<fff", 1.0, 2.0, 3.0)),  # Doc1: warning sample
            camm5_packet(47.628423, -122.165016, 123.0),          # Doc2: GPS fix
        ]
    )
    warn_gps_path = os.path.join(outdir, "QuickTime_camm_warn_gps.mov")
    with open(warn_gps_path, "wb") as f:
        f.write(warn_gps)
    print("wrote %s (%d bytes)" % (warn_gps_path, len(warn_gps)))

    # ── REVERSE-ORDER GPS-then-warning fixture (cross-kind min-doc -G1 timing) ─
    # The MIRROR of `QuickTime_camm_warn_gps.mov`: here sample 0 is the camm5 GPS
    # fix and sample 1 is the camm0 (Unknown record type 0) warning. The two ride
    # Track1 at DIFFERENT sample-table SampleTimes (Doc1 "0 s", Doc2 "1.00 s").
    # ExifTool processes camm samples SEQUENTIALLY (`FoundSomething` emits
    # SampleTime/SampleDuration in sample order BEFORE the ProcessCAMM dispatch,
    # QuickTimeStream.pl:1520-1523) and JSON `%noDups` is FIRST-wins, so at
    # `-ee -G1` ExifTool keeps SAMPLE 0's `Track1:SampleTime "0 s"` — the GPS
    # sample's — NOT the later warning's "1.00 s". This is the REVERSE of the
    # emitter-kind order exifast walks: `Meta::tags` drains the camm WARNING
    # records before the GPS records, so a per-kind first-wins gate would wrongly
    # record the warning sample's "1.00 s" first. Pins that the `-G1` timing is
    # the MINIMUM-doc camm sample's across ALL kinds (here the GPS sample, Doc1).
    # At `-ee -G3:1` each doc keeps its own (Doc1 = "0 s"+GPS, Doc2 = "1.00 s"+
    # Warning).
    gps_warn = build_camm_mov(
        [
            camm5_packet(47.628423, -122.165016, 123.0),          # Doc1: GPS fix
            camm_packet(0, struct.pack("<fff", 1.0, 2.0, 3.0)),  # Doc2: warning sample
        ]
    )
    gps_warn_path = os.path.join(outdir, "QuickTime_camm_gps_warn.mov")
    with open(gps_warn_path, "wb") as f:
        f.write(gps_warn)
    print("wrote %s (%d bytes)" % (gps_warn_path, len(gps_warn)))

    # ── REVERSE-ORDER motion-then-GPS fixture (cross-kind min-doc -G1 timing) ──
    # Sample 0 is a camm2 AngularVelocity MOTION packet; sample 1 is a camm5 GPS
    # fix. Both ride Track1 at DIFFERENT SampleTimes (Doc1 "0 s", Doc2 "1.00 s").
    # ExifTool keeps SAMPLE 0's `Track1:SampleTime "0 s"` (the MOTION sample's) at
    # `-ee -G1` — the minimum-doc camm sample regardless of packet kind. This is
    # the REVERSE of exifast's emitter-kind order: `Meta::tags` drains the camm
    # GPS records BEFORE the motion records, so a per-kind first-wins gate would
    # wrongly record the GPS sample's "1.00 s" first. Pins the cross-kind min-doc
    # timing where the FIRST (min-doc) sample is MOTION, not GPS. At `-ee -G3:1`
    # each doc keeps its own (Doc1 = "0 s"+AngularVelocity, Doc2 = "1.00 s"+GPS).
    motion_gps = build_camm_mov(
        [
            camm_vec3_packet(2, 0.1, -0.2, 0.3),                   # Doc1: AngularVelocity
            camm5_packet(47.628423, -122.165016, 123.0),          # Doc2: GPS fix
        ]
    )
    motion_gps_path = os.path.join(outdir, "QuickTime_camm_motion_gps.mov")
    with open(motion_gps_path, "wb") as f:
        f.write(motion_gps)
    print("wrote %s (%d bytes)" % (motion_gps_path, len(motion_gps)))

    # ── BAD-FIRST-PACKET-TYPE fixture (the dispatch gate) ─────────────────────
    # The `camm` MetaFormat dispatches through `GetTagInfo`, which evaluates the
    # camm0..camm7 SubDirectory `Condition`s `$$valPt =~ /^..\x0N\0/s` (N=0..7,
    # QuickTimeStream.pl:251-309) against the SAMPLE bytes. A first packet whose
    # int16u-LE type (byte +2) is >7 (here 8) matches NO camm<N> `Condition`, so
    # `GetTagInfo` returns undef → `FoundSomething` is NOT called (no `Doc<N>`, no
    # SampleTime/SampleDuration) and `ProcessCAMM` is NEVER dispatched (no
    # `Unknown camm record type 8` warning — that warning only fires AFTER a
    # Condition matched the FIRST packet, e.g. camm0). The buffer (here a full
    # 16-byte packet) does not start with `X` either, so the `$buff =~ /^X/`
    # text-camm fallback (QuickTimeStream.pl:1540) is also skipped. Bundled
    # `exiftool -ee -j -G1`/`-G3:1` emits NOTHING for this sample (verified
    # against the bundled 13.59 binary). Pins exifast's dispatch gate: a
    # first-packet type outside 0..7 (or a sample too short to read the +2 type)
    # must emit no doc, no SampleTime, no warning, and must NOT run `process_camm`.
    badtype = build_camm_mov([camm_packet(8, struct.pack("<fff", 1.0, 2.0, 3.0))])
    badtype_path = os.path.join(outdir, "QuickTime_camm_badtype.mov")
    with open(badtype_path, "wb") as f:
        f.write(badtype)
    print("wrote %s (%d bytes)" % (badtype_path, len(badtype)))

    # ── RECOGNIZED-EMPTY-PAYLOAD fixture (the timing-only marker) ─────────────
    # A recognized first packet (type 5 → camm5 `Condition` `/^..\x05\0/s`
    # matches the 4-byte header) but a 4-byte-ONLY sample (just the
    # `[reserved:2][type:2]` header, NO payload). `GetTagInfo` matches camm5 →
    # `FoundSomething` emits SampleTime/SampleDuration (QuickTimeStream.pl:1523),
    # THEN `ProcessCAMM` runs but its `while ($pos + 4 < $end)` loop is
    # `0 + 4 < 4` = FALSE → the body never iterates: NO packet is decoded, NO
    # `Unknown`/`Truncated` warning is raised. Bundled `exiftool -ee -j -G3:1`
    # emits `Doc1:Track1:SampleTime "0 s"` + `Doc1:Track1:SampleDuration "1.00 s"`
    # with NO GPS payload and NO Warning (verified against bundled 13.59); at
    # `-ee -G1` the same as `Track1:SampleTime`/`SampleDuration`. Pins exifast's
    # TIMING-ONLY marker: a recognized first-packet camm sample that decodes to
    # NO stored record STILL records a per-sample timing marker so it participates
    # in the `-G1` cross-kind min-doc timing AND emits its own `Doc<N>` SampleTime/
    # SampleDuration at `-G3`.
    emptypayload = build_camm_mov([camm_packet(5, b"")])
    emptypayload_path = os.path.join(outdir, "QuickTime_camm_emptypayload.mov")
    with open(emptypayload_path, "wb") as f:
        f.write(emptypayload)
    print("wrote %s (%d bytes)" % (emptypayload_path, len(emptypayload)))

    # ── DUPLICATE-WARNING-on-one-track fixture (the -ee -G3 timing-vs-dedup gate) ─
    # TWO warning-only camm0 samples carrying the SAME warning string. Sample 0 is
    # a camm0 (Unknown record type 0) at SampleTime "0 s" (Doc1); sample 1 is a
    # SECOND camm0 at SampleTime "1.00 s" (Doc2) — both `ProcessCAMM` walks
    # `$et->Warn("Unknown camm record type 0"), last` (QuickTimeStream.pl:3495).
    # `FoundSomething` emits `SampleTime`/`SampleDuration` per SAMPLE in sample
    # order BEFORE the `ProcessCAMM` dispatch (:1518-1523), so EACH sample's
    # `Doc<N>:Track1:SampleTime`/`SampleDuration` exists; but the second `Warn`
    # with the identical string is WAS_WARNED-deduped (`ExifTool.pm sub Warn`
    # records a message once file-wide), so only Doc1 carries the `Warning` TAG.
    # The `-ee -G3:1` oracle is therefore: Doc1 SampleTime "0 s" + SampleDuration
    # + Warning, then Doc2 SampleTime "1.00 s" + SampleDuration but NO Doc2 Warning.
    # At `-ee -G1` it collapses to one `Track1:SampleTime "0 s"` (the min-doc
    # sample) + one `Track1:Warning`. Pins that exifast emits the second warning
    # sample's `-G3` `Doc<N>` timing EVEN WHEN its `Warning` text is deduped
    # (RED before: the message-dedup `continue` skipped the whole second sample,
    # losing its Doc2 SampleTime/SampleDuration). The camm0 / camm_warn_gps /
    # camm_trunc fixtures each carry a SINGLE warning, so only this one exercises
    # the duplicate-warning timing-vs-dedup ordering.
    dup_warn = build_camm_mov(
        [
            camm_packet(0, struct.pack("<fff", 1.0, 2.0, 3.0)),  # Doc1: warning sample
            camm_packet(0, struct.pack("<fff", 4.0, 5.0, 6.0)),  # Doc2: same warning
        ]
    )
    dup_warn_path = os.path.join(outdir, "QuickTime_camm_dup_warn.mov")
    with open(dup_warn_path, "wb") as f:
        f.write(dup_warn)
    print("wrote %s (%d bytes)" % (dup_warn_path, len(dup_warn)))


if __name__ == "__main__":
    main()
