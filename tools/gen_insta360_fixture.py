#!/usr/bin/env python3
"""Build the crafted Insta360 INSV-trailer `.mp4` fixture.

exifast has no real INSV/INSP clip in `tests/fixtures/` (follow-up #91); this
script emits a *minimal* but bundled-ExifTool-decodable `.mp4` carrying an
Insta360 file-end trailer so the timed-metadata `-ee` oracle goldens have a real
on-disk input.

  python3 tools/gen_insta360_fixture.py            # -> tests/fixtures/QuickTime_insta360.mp4
  python3 tools/gen_insta360_fixture.py <outdir>

## Trailer layout (Image::ExifTool::QuickTimeStream::ProcessInsta360,
QuickTimeStream.pl:3258-3478)

The trailer lives at file END. `ProcessInsta360` reads the last 78 bytes; the
last 32 are the ASCII magic `8db42d694ccc418790edff439fe026bf`, and a LE u32 at
buffer offset 38 is the total trailer length. The walker steps LAST-to-FIRST
through records, each laid out as

    [record body (len bytes)][footer: id:u16-LE  len:u32-LE]

and a fixed 72-byte TERMINAL block follows the LAST record's footer:

    [32 opaque][trailerLen:u32-LE][4 opaque][magic:32]   (=72 bytes)

so the LAST record's footer sits exactly at EOF-78 (72 + 6). trailerLen counts
every record+footer plus the 72-byte terminal.

Record types emitted here (QuickTimeStream.pl:3326-3453):
 - 0x101 Identity (INSV_MakerNotes): [tag:u8][len:u8][value] items — SerialNumber
   0x0a / Model 0x12 / Firmware 0x1a / Parameters 0x2a (`tr/_/ /`). FLAT (no Doc).
 - 0x300 Accelerometer: 56-byte rows = [TimeCode:u64][6×double] OR 20-byte rows =
   [TimeCode:u64][6×u16] (each `(v-0x8000)/1000`). Accelerometer="d0 d1 d2",
   AngularVelocity="d3 d4 d5". One Doc<N> per row.
 - 0x400 Exposure: 16-byte rows = [TimeCode:u64][ExposureTime:double]. One Doc per row.
 - 0x600 VideoTimeStamp: 8-byte rows = [VideoTimeStamp:u64]. One Doc per row.
 - 0x700 GPS: 53-byte rows = [unixtime:u32][unknown:u32][ms:u16][status:1]
   [lat:double][NS:1][lon:double][EW:1][speed:double][track:double][alt:double].
   Only status=='A' rows surface; one Doc per surfaced fix.

DOC_NUM is a SINGLE global counter incremented per surfaced timed row across ALL
record types in WALK order (last record first). File order below is chosen so
the GPS record (last) is walked first → GPS = Doc1/Doc2.

After running, regenerate goldens with
  EE=1 EXCLUDE="-x System:all -x Composite:all" tools/gen_golden.sh QuickTime_insta360.mp4
"""
import os
import struct
import sys

MAGIC = b"8db42d694ccc418790edff439fe026bf"  # 32 ASCII bytes


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


# ── Minimal MP4 container (ftyp + moov/mvhd) ─────────────────────────────────
def build_min_mp4() -> bytes:
    """A minimal MP4 the QuickTime parser accepts (ftyp + moov with mvhd).
    The Insta360 trailer is appended AFTER this by the caller."""
    ftyp = atom(b"ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42isom")
    # mvhd (v0): timescale=1000, duration=1000.
    mvhd_body = (
        b"\x00\x00\x00\x00"            # version+flags
        + b"\x00" * 8                  # create/modify
        + struct.pack(">I", 1000)      # timescale
        + struct.pack(">I", 1000)      # duration
        + b"\x00" * 80                 # rate/volume/matrix/predefined/next_track
    )
    moov = atom(b"moov", atom(b"mvhd", mvhd_body))
    return ftyp + moov


# ── Insta360 trailer records ─────────────────────────────────────────────────
def footer(rec_id: int, body: bytes) -> bytes:
    """The 6-byte per-record footer `[id:u16-LE][len:u32-LE]` that FOLLOWS body."""
    return struct.pack("<HI", rec_id, len(body))


def rec_with_footer(rec_id: int, body: bytes) -> bytes:
    return body + footer(rec_id, body)


def identity_item(tag: int, value: bytes) -> bytes:
    """One 0x101 item `[tag:u8][len:u8][value]`."""
    assert len(value) < 256
    return bytes([tag, len(value)]) + value


def build_identity() -> bytes:
    return (
        identity_item(0x0A, b"IXSE123ABC456")   # SerialNumber
        + identity_item(0x12, b"Insta360 X3")   # Model
        + identity_item(0x1A, b"1.0.07")        # Firmware
        + identity_item(0x2A, b"2_6_5760_2880") # Parameters (tr/_/ / -> "2 6 5760 2880")
    )


def accel56_row(tc_ms: int, a, w) -> bytes:
    """56-byte 0x300 row: [TimeCode:u64][3 accel doubles][3 angvel doubles]."""
    return struct.pack("<Q6d", tc_ms, a[0], a[1], a[2], w[0], w[1], w[2])


def accel20_row(tc_ms: int, vals) -> bytes:
    """20-byte 0x300 row: [TimeCode:u64][6×u16]. Each decodes (v-0x8000)/1000."""
    return struct.pack("<Q6H", tc_ms, *vals)


def exposure_row(tc_ms: int, exp_s: float) -> bytes:
    """16-byte 0x400 row: [TimeCode:u64][ExposureTime:double]."""
    return struct.pack("<Qd", tc_ms, exp_s)


def videotime_row(tc_ms: int) -> bytes:
    """8-byte 0x600 row: [VideoTimeStamp:u64]."""
    return struct.pack("<Q", tc_ms)


def gps_row(unixtime, unknown, ms, status, lat, ns, lon, ew, speed, track, alt) -> bytes:
    """53-byte 0x700 row."""
    row = (
        struct.pack("<IIH", unixtime, unknown, ms)
        + status
        + struct.pack("<d", lat)
        + ns
        + struct.pack("<d", lon)
        + ew
        + struct.pack("<ddd", speed, track, alt)
    )
    assert len(row) == 53, len(row)
    return row


def build_trailer() -> bytes:
    # 0x101 identity (flat).
    identity = rec_with_footer(0x101, build_identity())

    # 0x300 accelerometer: one 56-byte (doubles) + one 20-byte (u16) row.
    accel56 = rec_with_footer(0x300, accel56_row(1000, (0.1, 0.2, 9.8), (0.01, -0.02, 0.03)))
    # u16 picks: 32768->0, 33768->1, 31768->-1 (accel); 32868->0.1, 32668->-0.1, 41768->9 (angvel).
    accel20 = rec_with_footer(0x300, accel20_row(2000, (32768, 33768, 31768, 32868, 32668, 41768)))

    # 0x600 VideoTimeStamp: 2 rows.
    videotime = rec_with_footer(0x600, videotime_row(1000) + videotime_row(2000))

    # 0x400 Exposure: 2 rows.
    exposure = rec_with_footer(0x400, exposure_row(1000, 0.008) + exposure_row(2000, 0.004))

    # 0x700 GPS: row1 N/W normal fix, row2 S/E fix, row3 void ('V', skipped).
    # row1's speed/track are deliberately NON-CLEAN so the `%QuickTime::Stream`
    # GPSSpeed/GPSTrack PrintConv `sprintf("%.4f",$val)+0` rounding is exercised:
    # speed 5.137 m/s -> 5.137*3.6 = 18.4932 km/h; track 123.45678 -> 123.4568.
    gps_rows = (
        gps_row(1704626355, 0, 250, b"A", 37.7749, b"N", 122.4194, b"W", 5.137, 123.45678, 100.5)
        + gps_row(1704626356, 0, 0, b"A", 33.8688, b"S", 151.2093, b"E", 0.0, 0.0, 10.0)
        + gps_row(1704626357, 0, 0, b"V", 0.0, b"\x00", 0.0, b"\x00", 0.0, 0.0, 0.0)
    )
    gps = rec_with_footer(0x700, gps_rows)

    # File order: identity, accel56, accel20, videotime, exposure, GPS (LAST).
    # Walk is reverse → GPS=Doc1/2, exposure=Doc3/4, videotime=Doc5/6,
    # accel20=Doc7, accel56=Doc8; identity is flat.
    records = identity + accel56 + accel20 + videotime + exposure + gps

    # 72-byte terminal: [32 opaque][trailerLen:u32][4 opaque][magic:32].
    trailer_len = len(records) + 72
    term = b"\x00" * 32 + struct.pack("<I", trailer_len) + b"\x00" * 4 + MAGIC
    assert len(term) == 72, len(term)
    return records + term


def build_bad_size(valid: bytes) -> bytes:
    """Corrupt the valid fixture's `trailerLen` field so `trailerLen > file
    size` (the QuickTimeStream.pl:3277 bad-size branch).

    The LE u32 trailer-length field sits at buffer offset 38 within the 78-byte
    footer, i.e. at EOF-78+38 == EOF-40. Overwrite it with `len(valid) + 1000`,
    leaving every other byte (incl. the magic UUID) intact. ExifTool then emits
    the POSITIONAL trailer warning with the WRAPPED (file_size - trailerLen,
    negative->unsigned) offset and suppresses "Bad Insta360 trailer size" via
    priority-0 first-wins -- so the only `-j` warning is the positional one.
    """
    buf = bytearray(valid)
    bad_len = len(valid) + 1000
    off = len(buf) - 40  # EOF-78+38
    buf[off:off + 4] = struct.pack("<I", bad_len)
    return bytes(buf)


def build_malformed_stride() -> bytes:
    """A valid trailer carrying NON-MULTIPLE fixed-stride records — the
    QuickTimeStream.pl:3355-3357 `if ($len % $dlen and $id != 0x700)` branch.

    A fixed-stride record (0x400 stride 16, 0x600 stride 8; 0x700 EXEMPT) whose
    length is NOT a multiple of the stride emits ZERO rows in bundled ExifTool
    (the `elsif` decode is skipped) and only raises `Unexpected Insta360 record
    0x%x length` — which the POSITIONAL trailer warning suppresses in `-j`
    (priority-0 first-wins). So this fixture must surface NO ExposureTime /
    VideoTimeStamp / TimeCode rows from the malformed records, only the valid
    0x700 GPS fix + 0x101 identity + the positional trailer warning.

    Records (file order; walk is reverse):
     - 0x101 identity (flat).
     - 0x400 exposure of 17 bytes = one 16-byte row + 1 trailing byte (NOT a
       multiple of 16) → no rows.
     - 0x600 videotimestamp of 9 bytes = one 8-byte row + 1 trailing byte (NOT a
       multiple of 8) → no rows.
     - 0x700 GPS (LAST → walked FIRST → Doc1), one valid 'A' fix → surfaces.
    """
    identity = rec_with_footer(0x101, build_identity())

    # 0x400 of 17 bytes: one full exposure row + 1 trailing byte.
    bad_exposure_body = exposure_row(1000, 0.008) + b"\xff"
    assert len(bad_exposure_body) == 17, len(bad_exposure_body)
    bad_exposure = rec_with_footer(0x400, bad_exposure_body)

    # 0x600 of 9 bytes: one full videotime row + 1 trailing byte.
    bad_videotime_body = videotime_row(1000) + b"\xff"
    assert len(bad_videotime_body) == 9, len(bad_videotime_body)
    bad_videotime = rec_with_footer(0x600, bad_videotime_body)

    # 0x700 GPS: one valid 'A' fix (LAST in file → Doc1).
    gps = rec_with_footer(
        0x700,
        gps_row(1704626355, 0, 250, b"A", 37.7749, b"N", 122.4194, b"W", 5.0, 90.0, 100.5),
    )

    records = identity + bad_exposure + bad_videotime + gps
    trailer_len = len(records) + 72
    term = b"\x00" * 32 + struct.pack("<I", trailer_len) + b"\x00" * 4 + MAGIC
    assert len(term) == 72, len(term)
    return records + term


def build_short_0x300() -> bytes:
    """A trailer whose 0x300 accelerometer record has a SHORT 10-byte body — a
    length that is a multiple of NEITHER 20 nor 56 — followed by more records.

    This pins the QuickTimeStream.pl:3327-3346 else-branch stride probe, which is
    `$raf->Read($buff, 20)` against the RAF (the FILE), NOT the record's own
    body. Because the 0x300 here is followed by a 0x700 GPS record, a 0x101
    identity, and the 72-byte terminal, there are far more than 20 file bytes
    from the 0x300 body start to EOF — so the probe SUCCEEDS (reading past the
    short body into the following footer/record bytes), picks a stride (20 or
    56), and then `len(10) % stride != 0` raises the `Unexpected Insta360 record
    0x300 length` warning (a `Trailer`/`Insta360` `Warning`, priority-0
    first-wins). The other records still extract: the GPS 'A' fix + the identity.

    The genuine silent-skip path (`$dlen` stays 0) happens ONLY when that
    `Read(20)` FAILS — i.e. fewer than 20 bytes remain from the body start to EOF
    — which a short 0x300 followed by more records can NEVER trigger. So the
    `-ee` oracle for this fixture surfaces:
      - the positional `[minor] Insta360 trailer at offset 0x.. (.. bytes)`
        (`ExifTool:Warning`),
      - the GPS fix (GPSDateTime/Latitude/Longitude/Speed/Track/Altitude),
      - `Insta360:Warning = "Unexpected Insta360 record 0x300 length"`,
      - `Insta360:Model` (+ the rest of the identity),
    and NO Accelerometer/AngularVelocity/TimeCode rows from the 0x300.

    Records (file order; walk is reverse):
     - 0x300 accelerometer of 10 bytes (multiple of neither 20 nor 56) — FIRST in
       file, so from its body start to EOF the GPS + identity + 72-byte terminal
       all follow (far ≥ 20 bytes), guaranteeing the `Read(20)` probe SUCCEEDS.
     - 0x700 GPS (one valid 'A' fix; LAST data record → walked FIRST → Doc1).
     - 0x101 identity (flat; walked last, sticky Doc1).
    The walk (last-record-first) visits identity → GPS (Doc1) → 0x300 (warns
    under sticky Doc1).
    """
    # 0x300 with a 10-byte body — a multiple of neither stride. The bytes are
    # arbitrary (the record decodes no rows); zeros keep it simple.
    short_accel = rec_with_footer(0x300, b"\x00" * 10)

    # 0x700 GPS: one valid 'A' fix (walked FIRST → Doc1). Same clean values as
    # the badstride fixture so the GPS PrintConv output is identical there.
    gps = rec_with_footer(
        0x700,
        gps_row(1704626355, 0, 250, b"A", 37.7749, b"N", 122.4194, b"W", 5.137, 90.0, 100.5),
    )

    # 0x101 identity (flat).
    identity = rec_with_footer(0x101, build_identity())

    # File order: 0x300 FIRST, then GPS, then identity (LAST in file → walked
    # FIRST). The 0x300 leads so its body start has the GPS + identity + terminal
    # after it — far ≥ 20 bytes — so the `Read(20)` probe succeeds (warns), never
    # the silent-skip path.
    records = short_accel + gps + identity

    trailer_len = len(records) + 72
    term = b"\x00" * 32 + struct.pack("<I", trailer_len) + b"\x00" * 4 + MAGIC
    assert len(term) == 72, len(term)
    return records + term


def build_chained_ligogps(trailer: bytes) -> bytes:
    """The valid Insta360 trailer FOLLOWED BY an (empty) LigoGPS trailer — the
    multi-trailer linked-list case of `IdentifyTrailers` (QuickTime.pm:9897-9926).

    ExifTool's `IdentifyTrailers` walks the trailers BACKWARD from EOF: it reads
    40 bytes from `EOF-40`, recognizes the LigoGPS signature (`&&&&` at buffer
    offset 32, then a BE u32 length at offset 36), steps PAST it by that length,
    re-reads 40 bytes, and now recognizes the Insta360 signature (its 32-byte
    magic is the last 32 bytes of that window) — so the Insta360 trailer is found
    EVEN THOUGH it is not the final block. The earliest (Insta360) trailer is the
    linked-list HEAD, so `ProcessMOV` bounds its box walk to the Insta360 start
    and warns the Insta360 positional `[minor] Insta360 trailer at offset …`.

    The LigoGPS trailer here is the MINIMAL `&&&&` + BE-u32 length(=8) — exactly
    8 bytes, the smallest block whose 40-byte window still carries the `&&&&`
    signature (the preceding bytes are the Insta360 trailer's tail). exifast does
    NOT extract LigoGPS, and an empty LigoGPS has nothing to extract anyway, so
    the full output is byte-IDENTICAL to the standalone Insta360 fixture (same
    Insta360 metadata + the same positional warning, no LigoGPS tags).
    """
    ligogps = b"&&&&" + struct.pack(">I", 8)  # 4-byte magic + BE u32 len = 8 bytes
    assert len(ligogps) == 8, len(ligogps)
    return trailer + ligogps


def build_short_trailer() -> bytes:
    """A trailer-bearing QuickTime file SHORTER than the 78-byte ProcessInsta360
    footer: a recognized first atom (`ftyp`) followed by ONLY the 40-byte
    `IdentifyTrailers` locator `[trailerLen:u32-LE][4 opaque][32-byte magic]`.

    ExifTool's EOF-40 locator (QuickTime.pm:9897-9926) still IDENTIFIES the
    trailer (the positional `[minor] … trailer at offset …` warning + the box-
    walk bound), but `ProcessInsta360`'s `Seek(-78)` fails on the <78-byte file,
    so NO records decode. `trailerLen = 40` (the locator IS the whole trailer),
    so the trailer starts right after `ftyp`.
    """
    ftyp = atom(b"ftyp", b"mp42" + struct.pack(">I", 0) + b"mp42isom")  # 24 bytes
    trailer_len = 40  # the 40-byte locator spans the entire trailer
    locator = struct.pack("<I", trailer_len) + b"\x00" * 4 + MAGIC  # 4 + 4 + 32
    assert len(locator) == 40, len(locator)
    out = ftyp + locator
    assert len(out) < 78, len(out)  # shorter than the ProcessInsta360 footer
    return out


def build_atom_spans_trailer(trailer: bytes) -> bytes:
    """A QuickTime file whose `moov` declares a size that SPANS into the Insta360
    trailer — `[ftyp][moov(declared size > its real content)][trailer]`.

    ExifTool's `ProcessMOV` walks top-level atoms by their DECLARED size. The
    `moov` here declares a size larger than its real `mvhd` content but still
    within the file (its declared end lands INSIDE the trailer, < EOF), so the
    `$raf->Read($val, $size)` of the moov SUCCEEDS reading mvhd + the first
    trailer bytes. Walking that buffer, ExifTool reads `mvhd`, then the trailer's
    first record bytes (`0a 0d 49 58 | 53 45 31 32 …` = the 0x101 identity body)
    as a contained atom header `(size=0x0a0d4958, tag='SE12')` whose huge size
    overruns the buffer ⇒ `Truncated 'SE12' data at offset 0x8c` (the unknown
    atom takes the skip path, QuickTime.pm:10590). After the moov the cursor is
    PAST the trailer start, so the trailer-processing loop SKIPS it
    (`next if $lastPos > $$trailer[1]`, :10656) — NO Insta360 metadata is
    extracted, and the positional `[minor] Insta360 trailer …` warning (also
    emitted) is suppressed under `-j` by the earlier `Truncated 'SE12'` warning.

    The standard container is `ftyp(24) + moov(116)`, so the trailer starts at
    file offset 0x8c and `mvhd` ends exactly there. We declare the moov 40 bytes
    larger so it spans 40 bytes into the trailer (well within the 442-byte
    trailer, so the moov read does not overrun EOF — which would instead give
    `Truncated 'moov'` + a processed trailer).
    """
    base = build_min_mp4()  # ftyp(24) + moov(116); moov size field at offset 0x18
    # Inflate the moov's declared size by 40 bytes (spans 40 bytes into trailer).
    moov_off = 24  # ftyp is 24 bytes
    real_moov_size = struct.unpack(">I", base[moov_off:moov_off + 4])[0]  # 116
    spanned = real_moov_size + 40
    out = bytearray(base)
    out[moov_off:moov_off + 4] = struct.pack(">I", spanned)
    out += trailer
    # The spanned moov end must stay within the file (else it is `Truncated 'moov'`).
    assert moov_off + spanned < len(out), (moov_off + spanned, len(out))
    return bytes(out)


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)
    data = build_min_mp4() + build_trailer()
    path = os.path.join(outdir, "QuickTime_insta360.mp4")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))

    # Bad-size variant: the valid fixture with `trailerLen` overwritten to
    # exceed the file size. Pins the positional-warning-with-wrapped-offset
    # behaviour (the "Bad trailer size" warning is suppressed in `-j` output).
    bad = build_bad_size(data)
    bad_path = os.path.join(outdir, "QuickTime_insta360_badtrailer.mp4")
    with open(bad_path, "wb") as f:
        f.write(bad)
    print("wrote %s (%d bytes)" % (bad_path, len(bad)))

    # Short-trailer variant: a recognized `ftyp` + ONLY the 40-byte EOF-40
    # locator, in a file shorter than the 78-byte footer. Pins the EOF-40
    # identification (positional warning + box bound, no records decoded).
    short = build_short_trailer()
    short_path = os.path.join(outdir, "QuickTime_insta360_shorttrailer.mp4")
    with open(short_path, "wb") as f:
        f.write(short)
    print("wrote %s (%d bytes)" % (short_path, len(short)))

    # Malformed-stride variant: a valid trailer with a NON-MULTIPLE 0x400
    # (len 17) and 0x600 (len 9) record alongside a valid 0x700 GPS fix.
    # Pins that the non-multiple fixed-stride records emit NO rows
    # (QuickTimeStream.pl:3355-3357), only the GPS fix + identity + the
    # positional trailer warning surface.
    malformed = build_min_mp4() + build_malformed_stride()
    malformed_path = os.path.join(outdir, "QuickTime_insta360_badstride.mp4")
    with open(malformed_path, "wb") as f:
        f.write(malformed)
    print("wrote %s (%d bytes)" % (malformed_path, len(malformed)))

    # Short-0x300 variant: a 0x300 accelerometer record with a 10-byte body (a
    # multiple of NEITHER 20 nor 56) followed by a 0x700 GPS fix + 0x101 identity.
    # Pins the QuickTimeStream.pl:3327-3346 else-branch `Read(20)` probe reading
    # the FILE past the short body: with records after it (≥ 20 bytes to EOF) the
    # probe SUCCEEDS, so the 10-byte 0x300 is a non-multiple → emits no rows +
    # raises `Unexpected Insta360 record 0x300 length` (NOT a silent skip), while
    # the GPS fix + identity still extract.
    short300 = build_min_mp4() + build_short_0x300()
    short300_path = os.path.join(outdir, "QuickTime_insta360_short300.mp4")
    with open(short300_path, "wb") as f:
        f.write(short300)
    print("wrote %s (%d bytes)" % (short300_path, len(short300)))

    # Chained-trailer variant: the SAME valid Insta360 trailer followed by an
    # (empty) LigoGPS trailer, so the Insta360 trailer is NOT the final block.
    # Pins `IdentifyTrailers`' backward linked-list walk: bundled steps past the
    # 8-byte LigoGPS block, still finds + fully decodes the Insta360 trailer, and
    # warns its positional `[minor] Insta360 trailer at offset 0x8c (442 bytes)`.
    # The empty LigoGPS yields no tags, so the output is byte-identical to the
    # standalone fixture.
    chained = build_min_mp4() + build_chained_ligogps(build_trailer())
    chained_path = os.path.join(outdir, "QuickTime_insta360_chained.mp4")
    with open(chained_path, "wb") as f:
        f.write(chained)
    print("wrote %s (%d bytes)" % (chained_path, len(chained)))

    # Atom-spans-trailer variant: a `moov` whose DECLARED size overruns the
    # Insta360 trailer start (but stays within the file). Pins ExifTool's in-loop
    # trailer stop (QuickTime.pm:10597-10602) + the skip of a trailer already
    # consumed by an atom (:10656): bundled reads the spanning moov, warns
    # `Truncated 'SE12' data at offset 0x8c` (the trailer's first record bytes
    # read as a contained atom), and extracts NO Insta360 metadata.
    spanning = build_atom_spans_trailer(build_trailer())
    spanning_path = os.path.join(outdir, "QuickTime_insta360_atomspan.mp4")
    with open(spanning_path, "wb") as f:
        f.write(spanning)
    print("wrote %s (%d bytes)" % (spanning_path, len(spanning)))


if __name__ == "__main__":
    main()
