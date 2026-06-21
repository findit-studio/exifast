#!/usr/bin/env python3
"""Build the crafted `gpmd`-MetaFormat dashcam-GPS `.mov` fixtures for the
already-ported FMAS (Vantrue N2S) and Wolfbox (Redtiger F9 4K) freeGPS variants.

exifast has no real Vantrue N2S / Redtiger F9 4K clip in `tests/fixtures/` (#100);
these scripts emit *minimal* but bundled-ExifTool-decodable `.mov` files, each
carrying a single `gpmd` MetaFormat sample whose payload is one FMAS or Wolfbox
binary GPS record. The container is modeled VERBATIM on
`gen_sony_rtmd_fixture.py:build_rtmd_mov` (ftyp/mdat/moov + a single-sample
`meta`-handler trak); the ONLY structural change is the stsd 4-byte format code,
`gpmd` instead of `rtmd`.

The FMAS / Wolfbox blocks themselves mirror the byte layouts in
`src/formats/quicktime_freegps.rs` (`ProcessFMAS` QuickTimeStream.pl:3580-3609,
`ProcessWolfbox` :3615-3676). ExifTool's `gpmd` MetaFormat Condition cascade
(QuickTimeStream.pl:181-212) routes `^FMAS\\0\\0\\0\\0` to `ProcessFMAS` and the
`.{136}(0{16}[A-Z]{4}|https://www.redtiger\\0)` signature to `ProcessWolfbox` —
both `ProcessSamples`-dispatched, so the decoded GPS surfaces under `Track1:`
(the trak's `SET_GROUP1`) with the sample-table `SampleTime`/`SampleDuration`,
under `-ee` only.

  python3 tools/gen_freegps_gpmd_fixture.py            # -> tests/fixtures/QuickTime_{fmas_n2s,wolfbox_redtiger_f9}.mov
  python3 tools/gen_freegps_gpmd_fixture.py <outdir>

After running, regenerate the goldens with bundled ExifTool 13.59:
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_fmas_n2s.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_wolfbox_redtiger_f9.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_fmas_empty_then_valid.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_gpmd_kingslim_pure.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_gpmd_kingslim_fmas_mixed.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_gpmd_kingslim_fmas_valid.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_gpmd_kingslim_noligo_fmas.mov
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_text_empty_then_valid.mov
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def build_gpmd_mov(samples, fmt: bytes = b"gpmd", handler: bytes = b"meta") -> bytes:
    """Minimal `.mov`: ftyp / mdat(samples) / moov(mvhd + trak[<handler> <fmt>]).

    Identical to `gen_sony_rtmd_fixture.py:build_rtmd_mov` except the stsd 4-byte
    format code is `fmt` (`gpmd` by default; the rtmd generator uses `rtmd`) and
    the hdlr HandlerType is `handler` (`meta` by default). The Process_text
    dashcam fixtures pass `fmt=b"text"`, `handler=b"text"` — ExifTool's
    `ProcessSamples` routes a `text` HandlerType sample to `Process_text`
    (QuickTimeStream.pl:1467-1516), emitting the decoded GPS + the `Text` tag
    under `Track1:` with the sample-table `SampleTime`/`SampleDuration`, under
    `-ee` only. The `nmhd` minf and the single-chunk N-sample stbl are unchanged.
    """
    # ftyp 'qt  '.
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))

    # mdat: all sample blobs stored back-to-back. The stco entry points at the
    # first sample (right after ftyp + the 8-byte mdat header).
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

    # hdlr: mhlr / <handler> (the HandlerType the stsd dispatches through).
    hdlr_body = (
        b"\x00\x00\x00\x00"  # version+flags
        + b"mhlr"            # pre_defined
        + handler           # handler_type
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

    # stsd: 1 entry whose 4-byte format code is `fmt`.
    stsd_entry = struct.pack(">I", 16) + fmt + b"\x00" * 6 + struct.pack(">H", 1)
    stsd_body = b"\x00\x00\x00\x00" + struct.pack(">I", 1) + stsd_entry

    # stts: one run of N samples, delta=1000 each.
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

    return ftyp + mdat + moov


def fmas_sample() -> bytes:
    """A 160-byte FMAS (Vantrue N2S) record — `ProcessFMAS`, QuickTimeStream.pl:
    3580-3609 (regex `^FMAS\\0\\0\\0\\0.{72}SAMM.{36}A`).

    Decoded by `decode_fmas` (src/formats/quicktime_freegps.rs): yr u16-LE @0x60,
    mon/day/hr/min/sec u8 @0x62-0x66; E/W ref @0x79, N/S ref @0x7a; lon
    deg/min/frac @0x7b/0x7c/0x7e, lat deg/min/frac @0x80/0x81/0x82; speed u16
    (mph) @0x84, track u16 @0x86; 3× LE f32 accel @0x6c. Values picked so the
    decode lands at 47°37.7'N, 8°30.1'E, 2025:06:15 14:30:45, 50 mph, track 180.
    """
    d = bytearray(160)
    d[0:8] = b"FMAS\0\0\0\0"
    d[80:84] = b"SAMM"
    d[120] = ord("A")
    # Date/time @0x60.
    d[0x60:0x62] = struct.pack("<H", 2025)
    d[0x62] = 6
    d[0x63] = 15
    d[0x64] = 14
    d[0x65] = 30
    d[0x66] = 45
    # Markers @0x78..0x7a (A / E / N) → longitude E, latitude N.
    d[0x78] = ord("A")
    d[0x79] = ord("E")
    d[0x7a] = ord("N")
    # Longitude: deg=8, min=30, frac=600 (→ 30.1').
    d[0x7b] = 8
    d[0x7c] = 30
    d[0x7d] = 0
    d[0x7e:0x80] = struct.pack("<H", 600)
    # Latitude: deg=47, min=37, frac=4200 (→ 37.7').
    d[0x80] = 47
    d[0x81] = 37
    d[0x82:0x84] = struct.pack("<H", 4200)
    # Speed 50 mph, track 180.
    d[0x84:0x86] = struct.pack("<H", 50)
    d[0x86:0x88] = struct.pack("<H", 180)
    # Acceleration X/Y/Z f32 @0x6c.
    d[0x6c:0x70] = struct.pack("<f", 0.1)
    d[0x70:0x74] = struct.pack("<f", 0.2)
    d[0x74:0x78] = struct.pack("<f", 0.3)
    return bytes(d)


def fmas_matched_empty_sample() -> bytes:
    """A `gpmd` sample that MATCHES the FMAS `Condition` (`^FMAS\\0\\0\\0\\0`,
    QuickTimeStream.pl:197) but DECODES NOTHING: `ProcessFMAS`'s stricter full
    regex `^FMAS\\0\\0\\0\\0.{72}SAMM.{36}A` fails (no `SAMM`@80, no `A`@120, and
    the sample is only 100 bytes < the 160-byte minimum).

    ExifTool's `GetTagInfo` matches the gpmd_FMAS Condition on just the 8-byte
    prefix, so `FoundSomething` opens a `Doc<N>` + emits `SampleTime`/
    `SampleDuration` BEFORE `ProcessFMAS` runs and aborts — verified vs bundled
    ExifTool 13.59: with a valid FMAS sample following, this empty one is `Doc1`
    (`Doc1:Track1:SampleTime "0 s"`) and the GPS lands at `Doc2`; `-ee -G1` keeps
    the FIRST sample's `0 s` timing.
    """
    d = bytearray(100)
    d[0:8] = b"FMAS\0\0\0\0"  # Condition prefix only; no SAMM@80 / 'A'@120.
    return bytes(d)


def kingslim_sample() -> bytes:
    """A 240-byte Kingslim D4 `gpmd` sample — the `gpmd_Kingslim` Condition
    `^.{21}\\0\\0\\0A[NS][EW]` (QuickTimeStream.pl:183) → `ProcessFreeGPS` → the
    GPSType-5 `.{80}LIGOGPSINFO\\0` arm (:1843-1888) → `ProcessLigoGPS`.

    Mirrors the `dispatch_gpmd_routes_kingslim_to_ligogps` unit test layout
    (src/formats/quicktime_freegps.rs): the Condition signature `\\0\\0\\0A[NS][EW]`
    at 21..27 (`A`@24 / `N`@25 / `W`@26) only IDENTIFIES the variant; the GPS
    lives in the `LIGOGPSINFO\\0` block at offset 0x50 (80) whose plain-ASCII
    LigoGPS record sits at 0x50+0x14 (100). The record is the `####`-free path
    (LigoGPS.pm:303-307, `^.{4}\\d{4}/\\d{2}/\\d{2} `): a 4-byte counter then
    `YYYY/MM/DD HH:MM:SS N:<lat> E:<lon> <alt>`, flags 0x03 (no decrypt / no
    fuzz). Lands at 45.5 N, 170.5 E, 2024:01:15 10:00:00, alt 30 m — exactly the
    unit test's fix, so ExifTool decodes it to `…:LIGO:GPSLatitude 45.5` etc.

    A Kingslim sample consumes TWO docs: ExifTool's `FoundSomething` opens this
    sample's `SampleTime`/`SampleDuration` timing `Doc<N>` (the LOWER ordinal,
    `Track<N>` group while `$$et{SET_GROUP1}` is still active) the moment the
    Condition matches, THEN `ProcessLigoGPS` opens the LigoGPS sub-document (the
    NEXT ordinal) off the shared `DOC_COUNT`. So a leading Kingslim sample is
    `Doc1`-timing + `Doc2`-LIGO. `ProcessLigoGPS` then `delete`s `$$et{SET_GROUP1}`
    (LigoGPS.pm:266) WITHOUT restoring `Track$num`, so every FOLLOWING matched
    sample's timing rides the DEFAULT `QuickTime` group (ground-truth `-ee -G3:1`:
    pure `[kingslim, kingslim]` ⇒ `Doc1:Track1`-timing, `Doc2:LIGO`,
    `Doc3:QuickTime`-timing, `Doc4:LIGO`).
    """
    d = bytearray(240)
    d[24] = ord("A")
    d[25] = ord("N")
    d[26] = ord("W")
    d[80:92] = b"LIGOGPSINFO\0"
    rec = b"\x00\x00\x00\x00" + b"2024/01/15 10:00:00 N:45.5 E:170.5 30.0"
    d[100:100 + len(rec)] = rec
    return bytes(d)


def kingslim_no_ligo_record_sample() -> bytes:
    """A `gpmd` sample that MATCHES the Kingslim Condition (`^.{21}\\0\\0\\0A[NS][EW]`,
    QuickTimeStream.pl:183) and carries a `LIGOGPSINFO\\0` block (so `ProcessFreeGPS`
    routes to the GPSType-5 `ProcessLigoGPS` arm), but whose record region is
    UNPARSEABLE — `ProcessLigoGPS`'s per-record loop (LigoGPS.pm:301-316) matches
    neither the `####` encrypted prefix nor the `^.{4}\\d{4}/\\d{2}/\\d{2} ` plain
    ASCII date, so it decodes NOTHING and never reaches the `delete $$et{SET_GROUP1}`
    at LigoGPS.pm:266.

    This is the #328 Finding 2 ground-truth: a Kingslim Condition-match that yields
    NO LigoGPS output must NOT clear `$$et{SET_GROUP1}`. ExifTool's `FoundSomething`
    still opens this sample's timing `Doc<N>` (the Condition matched), but
    `ProcessLigoGPS` consumes NO second doc, so a FOLLOWING valid sample is `Doc2`
    (not `Doc3`) and rides `Track<N>` (not `QuickTime`) — verified vs bundled
    ExifTool 13.59 `-ee -G3:1`: `[this, valid FMAS]` ⇒ `Doc1:Track1`-timing,
    `Doc2:Track1`-timing + `Doc2:Track1` FMAS GPS (the SET_GROUP1 delete did NOT
    run, so the FMAS fix stays `Track1`). The record bytes are `0xFF`-filled so
    neither LigoGPS record form matches.
    """
    d = bytearray(240)
    d[24] = ord("A")
    d[25] = ord("N")
    d[26] = ord("W")
    d[80:92] = b"LIGOGPSINFO\0"  # routes to ProcessLigoGPS …
    for i in range(100, 240):     # … but the record region parses to nothing.
        d[i] = 0xFF
    return bytes(d)


def wolfbox_sample() -> bytes:
    """A 256-byte Wolfbox / Redtiger F9 4K record — `ProcessWolfbox`,
    QuickTimeStream.pl:3615-3676 (signature `.{136}(0{16}[A-Z]{4}|…redtiger\\0)`).

    Decoded by `process_wolfbox` (src/formats/quicktime_freegps.rs): the
    Condition marker (16 ASCII '0' + 4 uppercase, here `HYTH`) sits @136; date u32-
    LE @0x68/0x6c/0x70 (d/mo/yr), time u32-LE @0xa0/0xa4/0xa8 (h/m/s); value/divisor
    i64 pairs for speed @0x48/0x50, track @0x58/0x60, lat @0xb0/0xb8, lon
    @0xc0/0xc8, alt @0xe8/0xf0. lat/lon are DDDMM.MMMM (ConvertLatLon); speed is
    knots. Values land at 47°37.7053'N, 8°22.5076'E, 2025:06:15 14:30:45,
    25.5 knots, track 90, alt 412.5 m.
    """
    d = bytearray(0x100)
    # Condition marker @136: 16 '0' + 4 uppercase.
    for i in range(16):
        d[136 + i] = ord("0")
    d[152:156] = b"HYTH"
    # Date @0x68 (d, mo, yr).
    d[0x68:0x6c] = struct.pack("<I", 15)
    d[0x6c:0x70] = struct.pack("<I", 6)
    d[0x70:0x74] = struct.pack("<I", 2025)
    # Time @0xa0 (h, m, s).
    d[0xa0:0xa4] = struct.pack("<I", 14)
    d[0xa4:0xa8] = struct.pack("<I", 30)
    d[0xa8:0xac] = struct.pack("<I", 45)
    # Speed val/div (knots*1000): 25.5 → 25500 / 1000.
    d[0x48:0x50] = struct.pack("<q", 25500)
    d[0x50:0x58] = struct.pack("<q", 1000)
    # Track val/div: 90.0 → 9000 / 100.
    d[0x58:0x60] = struct.pack("<q", 9000)
    d[0x60:0x68] = struct.pack("<q", 100)
    # Lat val/div: 4737.7053 (DDDMM.MMMM) → 47377053 / 10000.
    d[0xb0:0xb8] = struct.pack("<q", 47377053)
    d[0xb8:0xc0] = struct.pack("<q", 10000)
    # Lon val/div: 822.5076 (DDDMM.MMMM) → 8225076 / 10000.
    d[0xc0:0xc8] = struct.pack("<q", 8225076)
    d[0xc8:0xd0] = struct.pack("<q", 10000)
    # Alt val/div: 412.5 → 4125 / 10.
    d[0xe8:0xf0] = struct.pack("<q", 4125)
    d[0xf0:0xf8] = struct.pack("<q", 10)
    return bytes(d)


# ── Process_text dashcam variants (text-handler timed-text samples) ──────────
# Each is a plain-ASCII timed-text sample whose bytes carry one vendor's
# Process_text fingerprint (QuickTimeStream.pl:1213-1294). They are modeled on
# the gpmd builder above but with a `text` HandlerType + `text` stsd 4cc, so
# ExifTool routes them to `Process_text`. The exact ground-truth GPS each yields
# (bundled ExifTool 13.59, `-ee -G3:1`) is in the test docs.


def mini_0806_sample() -> bytes:
    """Mini 0806 dashcam (QuickTimeStream.pl:1232-1248): `^A,DDMMYY,HHMMSS.sss,
    DDMM.MMMM,N/S,DDDMM.MMMM,E/W,speed,altM,accX,accY,accZ;`. Lands at
    33 deg 56' 53.55" N, 84 deg 20' 12.43" W, 2019:05:27 20:15:55.000, alt 331 m,
    speed 0, Accelerometer "+01.84 -09.80 -00.61"."""
    return b"A,270519,201555.000,3356.8925,N,08420.2071,W,000.0,331.0M,+01.84,-09.80,-00.61;\n"


def roadhawk_sample() -> bytes:
    """Roadhawk (QuickTimeStream.pl:1250-1269): the custom-substitution-encoded
    buffer ending `*HH~` (the verbatim bundled example) that decodes to
    `X0000.2340Y-000.0720Z0000.9900G0001.0400$GPRMC,082138,A,5330.6683,N,
    00641.9749,W,012.5,87.86,050213,002.1,A`. Lands at 53 deg 30' 40.10" N,
    6 deg 41' 58.49" W, 2013:02:05 08:21:38, speed 23.15, track 87.86,
    Accelerometer "0000.2340 -000.0720 0000.9900 0001.0400"."""
    return (
        b".;;;;D?JL;6+;;;D;R?;4;;;;DBB;;O;;;=D;L;;HO71G>F;-?=J-F:FNJJ;"
        b"DPP-JF3F;;PL=DBRLBF0F;=?DNF-RD-PF;N;?=JF;;?D=F:*6F~"
    )


def thinkware_sample() -> bytes:
    """Thinkware (QuickTimeStream.pl:1271-1286): `gsensori,...;<XX>RMC,...;CAR,
    ...` — a `GNRMC` (no leading `$`) with the day/mon/yr sanity gate, plus the
    `gsensori` → GSensor and `CAR` → Car extras. Lands at 45 deg 29' 52.49" N,
    73 deg 37' 0.73" W, 2019:08:31 16:13:13, speed 11.5287, track 35.34,
    GSensor "4,512,-67,-12,100", Car "0,0,0,0.0,0,0,0,0,0,0,0,0"."""
    return (
        b"gsensori,4,512,-67,-12,100;GNRMC,161313.00,A,4529.87489,N,07337.01215,W,"
        b"6.225,35.34,310819,,,A*52;CAR,0,0,0,0.0,0,0,0,0,0,0,0,0"
    )


def dji_telemetry_sample() -> bytes:
    """DJI telemetry (QuickTimeStream.pl:1213-1230): `F/<fn>, SS <ss>, ISO <iso>,
    EV <ev>, GPS (lon, lat, alt), D <d>m, H <h>m, H.S <hs>m/s, V.S <vs>m/s`.
    `GPS (lon, lat` is lon-then-lat; altitude is the H(eight), speed the H.S,
    distance the D field. Lands at 53 deg 9' 59.40" N, 8 deg 38' 59.64" E,
    GPSAltitude 6 m, speed 7.56 (2.10 m/s × 3.6), Distance "87.336 m"
    (24.26 × 3.6), FNumber 3.5, ExposureTime "1/1000", ExposureCompensation 0,
    ISO 100, VerticalSpeed "0.00 m/s"."""
    return (
        b"F/3.5, SS 1000, ISO 100, EV 0, GPS (8.6499, 53.1665, 18), "
        b"D 24.26m, H 6.00m, H.S 2.10m/s, V.S 0.00m/s \n"
    )


def empty_length_prefix_sample() -> bytes:
    """A zero-length length-prefixed `text` sample — the `next if $size == 2`
    shape (QuickTimeStream.pl:1474). The 2-byte big-endian prefix `\\x00\\x00`
    equals `size - 2 == 0`, so ExifTool strips nothing, fires the `next`, and
    stores NO `Text` and runs NO `Process_text` decode — BUT `FoundSomething`
    (:1461) already opened this sample's `Doc<N>` + emitted its `SampleTime`/
    `SampleDuration` ABOVE the `unless` block, so the empty sample STILL consumes
    a doc and surfaces its timing. Pins the size==2 escape-hatch close: an empty
    text sample MUST emit `Doc<N>:Track<N>:SampleTime`/`SampleDuration`."""
    return b"\x00\x00"


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)

    # Single-sample fixtures (one FMAS / one Wolfbox record).
    for name, sample in [
        ("QuickTime_fmas_n2s.mov", fmas_sample()),
        ("QuickTime_wolfbox_redtiger_f9.mov", wolfbox_sample()),
    ]:
        data = build_gpmd_mov([sample])
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    # Two-sample fixture: a matched-but-empty FMAS sample (Condition matches but
    # ProcessFMAS decodes nothing) FOLLOWED BY a valid FMAS sample. ExifTool's
    # `FoundSomething` still opens a `Doc<N>` for the empty sample (the Condition
    # matched), so the valid sample is `Doc2`, not `Doc1`, and `-ee -G1` keeps the
    # FIRST (empty) sample's `SampleTime "0 s"`. Pins the `gpmd` per-MATCHED-sample
    # Doc/timing semantics (the timing-only marker).
    #
    # PURE-Kingslim `gpmd` track: two Kingslim (LigoGPS) samples. Each consumes
    # TWO docs — a `FoundSomething` timing doc then a `ProcessLigoGPS` LigoGPS doc.
    # The FIRST sample's timing rides `Track1` (`$$et{SET_GROUP1}` still active),
    # but its `ProcessLigoGPS` `delete`s the key (LigoGPS.pm:266) WITHOUT restoring
    # `Track1`, so the SECOND sample's timing rides the DEFAULT `QuickTime` group:
    # `Doc1:Track1`-timing, `Doc2:LIGO`, `Doc3:QuickTime`-timing, `Doc4:LIGO`
    # (ground-truth `-ee -G3:1`). Proves the `Track<N>`→`QuickTime` SET_GROUP1 flip;
    # at `-ee -G1` it yields BOTH `Track1:SampleTime "0 s"` (min-doc of the `Track1`
    # group) AND `QuickTime:SampleTime "1.00 s"` (min-doc of the `QuickTime` group).
    #
    # MIXED-source `gpmd` track: a Kingslim (LigoGPS) sample, then a matched-empty
    # FMAS sample, then ANOTHER Kingslim sample. The Kingslim GPS lives in a
    # LigoGPS sub-document (`Doc2` / `Doc5`); the FIRST Kingslim sample's timing is
    # `Doc1:Track1`, the matched-empty FMAS sample emits a timing-only `Doc3`, and
    # — because the first Kingslim `ProcessLigoGPS` already `delete`d
    # `$$et{SET_GROUP1}` — BOTH the FMAS marker (`Doc3`) and the second Kingslim
    # sample's timing (`Doc4`) ride the DEFAULT `QuickTime` group (ground-truth
    # `-ee -G3:1`: `Doc1:Track1`-timing, `Doc2:LIGO`, `Doc3:QuickTime`-timing,
    # `Doc4:QuickTime`-timing, `Doc5:LIGO`). ExifTool's `ProcessSamples` emits each
    # sample in walk (= `Doc<N>`) order; exifast decodes the LigoGPS records and the
    # timing markers into SEPARATE typed sinks, so this is the order-sensitive proof
    # that the unified `gpmd` doc-ordered merge interleaves them (a Kingslim sample
    # BEFORE *and* AFTER the FMAS marker, with the SET_GROUP1 group flip).
    for name, samples in [
        (
            "QuickTime_fmas_empty_then_valid.mov",
            [fmas_matched_empty_sample(), fmas_sample()],
        ),
        (
            "QuickTime_gpmd_kingslim_pure.mov",
            [kingslim_sample(), kingslim_sample()],
        ),
        (
            "QuickTime_gpmd_kingslim_fmas_mixed.mov",
            [kingslim_sample(), fmas_matched_empty_sample(), kingslim_sample()],
        ),
        # KINGSLIM-then-VALID-FMAS `gpmd` track (#328 Finding 1): a Kingslim
        # (LigoGPS) sample FOLLOWED BY a VALID FMAS sample that decodes a REAL GPS
        # fix (NOT an empty marker). The first Kingslim `ProcessLigoGPS` emits its
        # fix (reaching LigoGPS.pm:266) and `delete`s `$$et{SET_GROUP1}` WITHOUT
        # restoring `Track1`, so the FOLLOWING FMAS sample's `FoundSomething`
        # timing AND its decoded GPS columns ride the DEFAULT `QuickTime` group —
        # NOT `Track1`. Ground-truth bundled ExifTool 13.59 `-ee -G3:1`:
        # `Doc1:Track1`-timing, `Doc2:LIGO`, then `Doc3:QuickTime:SampleTime`
        # +`Doc3:QuickTime:GPSLatitude`/`GPSLongitude`/`GPSSpeed`/`GPSTrack`/
        # `Accelerometer` (the FMAS fix, post-LigoGPS). At `-ee -G1` the `QuickTime`
        # group's min-doc is the FMAS sample, so it keeps `QuickTime:SampleTime
        # "1.00 s"` next to the FMAS `QuickTime:GPS*`; `Track1` keeps the Kingslim
        # `"0 s"` + `LIGO:GPS*`. Proves the SET_GROUP1 flip reaches a DECODED fix,
        # not only the matched-empty markers.
        (
            "QuickTime_gpmd_kingslim_fmas_valid.mov",
            [kingslim_sample(), fmas_sample()],
        ),
        # KINGSLIM-MATCH-but-NO-LIGOGPS-OUTPUT then VALID-FMAS (#328 Finding 2):
        # the first sample matches the Kingslim Condition + routes to
        # `ProcessLigoGPS` (it has a `LIGOGPSINFO\0` block) but its record is
        # unparseable, so NO fix is emitted and the `delete $$et{SET_GROUP1}`
        # (LigoGPS.pm:266) NEVER runs. ExifTool opens only the sample's timing
        # `Doc1` (no LigoGPS doc), so the FOLLOWING valid FMAS sample is `Doc2`
        # and — because SET_GROUP1 stayed active — rides `Track1`. Ground-truth
        # bundled `-ee -G3:1`: `Doc1:Track1`-timing, `Doc2:Track1`-timing +
        # `Doc2:Track1` FMAS GPS (NO Doc skipped for an un-emitted LigoGPS, NO
        # QuickTime flip). Proves the flag flips only AFTER LigoGPS actually ran.
        (
            "QuickTime_gpmd_kingslim_noligo_fmas.mov",
            [kingslim_no_ligo_record_sample(), fmas_sample()],
        ),
    ]:
        data = build_gpmd_mov(samples)
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    # The four Process_text dashcam fixtures — single `text`-handler timed-text
    # samples (#104 / #102). Each is built with `fmt=b"text"`, `handler=b"text"`.
    for name, sample in [
        ("QuickTime_text_mini0806.mov", mini_0806_sample()),
        ("QuickTime_text_roadhawk.mov", roadhawk_sample()),
        ("QuickTime_text_thinkware.mov", thinkware_sample()),
        ("QuickTime_text_dji_telemetry.mov", dji_telemetry_sample()),
    ]:
        data = build_gpmd_mov([sample], fmt=b"text", handler=b"text")
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    # Two-sample `text`-handler fixture: a zero-length length-prefixed sample
    # (`next if $size == 2`) FOLLOWED BY a valid Mini-0806 sample. ExifTool's
    # `FoundSomething` (QuickTimeStream.pl:1461) opens a `Doc<N>` + emits the
    # `SampleTime`/`SampleDuration` for EVERY text sample BEFORE the `next` /
    # `Process_text`, so the empty sample STILL consumes `Doc1` (timing-only) and
    # the valid Mini-0806 sample is renumbered `Doc2`; at `-ee -G1` the single
    # `Track1:SampleTime` is the FIRST (empty) sample's `0 s`. Pins the size==2
    # escape-hatch close of the per-text-sample-timing class (#104 R2 finding).
    data = build_gpmd_mov(
        [empty_length_prefix_sample(), mini_0806_sample()],
        fmt=b"text",
        handler=b"text",
    )
    path = os.path.join(outdir, "QuickTime_text_empty_then_valid.mov")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
