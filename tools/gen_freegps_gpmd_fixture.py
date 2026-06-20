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
  EE=1 EXCLUDE="-x System:all -x Composite:GPSPosition" tools/gen_golden.sh QuickTime_gpmd_kingslim_fmas_mixed.mov
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def build_gpmd_mov(samples) -> bytes:
    """Minimal `.mov`: ftyp / mdat(samples) / moov(mvhd + trak[gpmd meta]).

    Identical to `gen_sony_rtmd_fixture.py:build_rtmd_mov` except the stsd 4-byte
    format code is `gpmd` (the rtmd generator uses `rtmd`); the `meta` handler,
    `nmhd` minf, and the single-chunk N-sample stbl are unchanged.
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

    # hdlr: mhlr / meta (the meta_handler the gpmd stsd dispatches through).
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

    # stsd: 1 entry whose 4-byte format code is `gpmd`.
    stsd_entry = struct.pack(">I", 16) + b"gpmd" + b"\x00" * 6 + struct.pack(">H", 1)
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

    The Kingslim arm carries its GPS in a LigoGPS sub-document that opens its OWN
    `Doc<N>` off the shared `DOC_COUNT`; placed BEFORE the matched-empty FMAS
    sample it is `Doc1` (the FMAS marker is `Doc2`).
    """
    d = bytearray(240)
    d[24] = ord("A")
    d[25] = ord("N")
    d[26] = ord("W")
    d[80:92] = b"LIGOGPSINFO\0"
    rec = b"\x00\x00\x00\x00" + b"2024/01/15 10:00:00 N:45.5 E:170.5 30.0"
    d[100:100 + len(rec)] = rec
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
    # MIXED-source `gpmd` track: a Kingslim (LigoGPS) sample, then a matched-empty
    # FMAS sample, then ANOTHER Kingslim sample. The Kingslim GPS lives in a
    # LigoGPS sub-document (`Doc1` / `Doc3`); the matched-empty FMAS sample emits a
    # timing-only `Doc2`. ExifTool's `ProcessSamples` emits each sample in walk (=
    # `Doc<N>`) order, so `Doc1`-LIGO precedes `Doc2`-timing precedes `Doc3`-LIGO.
    # exifast decodes the LigoGPS records and the FMAS marker into SEPARATE typed
    # sinks, so this is the order-sensitive proof that the unified `gpmd`
    # doc-ordered merge interleaves the `gpmd`-dispatched LigoGPS records with the
    # timing-only markers (a Kingslim sample BEFORE *and* AFTER the FMAS marker).
    for name, samples in [
        (
            "QuickTime_fmas_empty_then_valid.mov",
            [fmas_matched_empty_sample(), fmas_sample()],
        ),
        (
            "QuickTime_gpmd_kingslim_fmas_mixed.mov",
            [kingslim_sample(), fmas_matched_empty_sample(), kingslim_sample()],
        ),
    ]:
        data = build_gpmd_mov(samples)
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
