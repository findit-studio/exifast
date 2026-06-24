#!/usr/bin/env python3
"""Build the two MALFORMED Parrot ARCore `mett` timed-metadata `.mp4` fixtures.

These pin the bundled-ExifTool 13.59 behaviour of the ARCore `Process_mett`
WARNING paths (Parrot.pm:802-820 + the `ARCoreAccel` `Accelerometer` RawConv,
Parrot.pm:663-693) — the warning cases the well-formed `QuickTime_parrot_arcore.mp4`
(`gen_parrot_arcore_fixture.py`) deliberately avoids:

  python3 tools/gen_parrot_arcore_malformed_fixtures.py        # -> tests/fixtures/
  python3 tools/gen_parrot_arcore_malformed_fixtures.py <outdir>

QuickTime_parrot_arcore_trunc.mp4 — TRUNCATED-float Accelerometer
-----------------------------------------------------------------
One ARCore Accel TLV record whose payload is long enough to reach the
`Accelerometer` `undef[14]` value at record offset 5 (so the tag IS emitted) but
short enough that the THIRD `GetFloat` (buffer offset 10 = record offset 15)
runs past the value. The RawConv `GetFloat($val,0)." ".GetFloat($val,5)." ".
GetFloat($val,10)` then concatenates an `undef` third component, so bundled:
  * emits the partial `Accelerometer = "0.125 -0.25 "` (note the empty trailing
    slot — Perl's uninitialized-value concatenation); AND
  * raises `Warning = RawConv Accelerometer: Use of uninitialized value in
    concatenation (.) or string` (NON-minor) AHEAD of the value (the RawConv
    `Warn` fires as the value is built).
At `-ee -G3:1` the order is `Doc1:SampleTime`, `SampleDuration`, `Warning`,
`Accelerometer`; at `-ee -G1` it collapses to the single `Track1:` row set.

QuickTime_parrot_arcore_overflow.mp4 — OVERFLOW TLV (warning only)
-----------------------------------------------------------------
One ARCore TLV record whose declared length byte points past the sample end, so
`Process_mett` (Parrot.pm:807-810) `$et->Warn("Unexpected length for $metaType
record", 1)` then `last`s BEFORE any `HandleTag` — the sample decodes NO accel
vector and emits ONLY the warning. `Warn(.., 1)` is MINOR, so the rendered value
carries the `[minor] ` prefix AND interpolates `$metaType` verbatim:
`[minor] Unexpected length for application/arcore-accel record`.
At `-ee` the warning rides `Track1:Warning` (`Doc1:Warning` at `-G3:1`) after the
sample's `SampleTime`/`SampleDuration`; there is NO `Accelerometer`.

QuickTime_parrot_arcore_valid_overflow.mp4 — MULTI-TLV: valid vector THEN overflow
---------------------------------------------------------------------------------
ONE `mett` sample = a FULL-vector valid ARCore Accel TLV (all three floats in
range) FOLLOWED BY an overflow TLV. `Process_mett` `HandleTag`s the first TLV
(emitting `Accelerometer = "0.125 -0.25 9.8125"`) and only THEN, walking to the
second TLV, hits the overflow `Warn`. So the WALK ORDER is the vector BEFORE the
warning: bundled emits `Accelerometer` then `[minor] Unexpected length …`
(NOT warning-first). This pins the intra-sample ordering the prior
drain-all-warnings-then-vector shape got wrong.

QuickTime_parrot_arcore_trunc_overflow.mp4 — MULTI-TLV: RawConv-warn, partial vector, overflow-warn
---------------------------------------------------------------------------------------------------
ONE `mett` sample = a TRUNCATED-float TLV (the whole sample is short enough that
the third `GetFloat` overflows → a partial `Accelerometer = "0.125 -0.25 "` + the
NON-minor RawConv warning, AHEAD of the value) FOLLOWED by an overflow TLV. The
walk order is: RawConv `Warning` (TLV1, as the value is built), `Accelerometer`
(TLV1), then the MINOR overflow `Warning` (TLV2). All three are DISTINCT events
in walk order. BUT both `Warning`s share the `(Doc1,Track1,Warning)` tag key, so
ExifTool's priority-0 first-wins keeps only the FIRST (the RawConv) — verified vs
bundled `-ee -G1`/`-G3:1` (the JSON shows the RawConv `Warning` + the partial
`Accelerometer`; the later overflow `Warning` is suppressed by the same-key
first-wins, NOT re-emitted as a second row). This pins both the walk-order
interleave AND that a distinct later warning does NOT add a second `Warning` row.

After running, regenerate the goldens with (bundled ExifTool 13.59):
  EE=1 EE_N=1 tools/gen_golden.sh QuickTime_parrot_arcore_trunc.mp4
  EE=1 EE_N=1 tools/gen_golden.sh QuickTime_parrot_arcore_overflow.mp4
  EE=1 EE_N=1 tools/gen_golden.sh QuickTime_parrot_arcore_valid_overflow.mp4
  EE=1 EE_N=1 tools/gen_golden.sh QuickTime_parrot_arcore_trunc_overflow.mp4
(`gen_golden.sh` auto-applies `-x System:all` for these names.)
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def build_mett_mov(samples, meta_type: str) -> bytes:
    """Minimal `.mp4`: ftyp / mdat(samples) / moov(mvhd + trak[mett meta]).

    IDENTICAL container to `gen_parrot_arcore_fixture.py` (one `mett` track whose
    `stsd` MetaType is `meta_type`, one chunk of `len(samples)` timed samples) so
    the only difference from the well-formed fixture is the sample BYTES.
    """
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
        b"\x00\x00\x00\x00" + b"mhlr" + b"meta" + b"\x00" * 12 + b"\x00"
    )

    mdhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4
    )

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
        b"\x00\x00\x00\x00" + struct.pack(">I", 1) + struct.pack(">I", sample_base)
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


def truncated_record(fx: float, fy: float) -> bytes:
    """One TRUNCATED ARCore Accel TLV record (partial vector + RawConv warning).

    Payload is 15 bytes (record offsets 2..16). The `Accelerometer` `undef[14]`
    value sits at record offset 5, so `GetFloat($val,0)`=float[X]@5 (in range)
    and `GetFloat($val,5)`=float[Y]@10 (in range), but `GetFloat($val,10)`=
    float[Z]@15 has only 2 of its 4 bytes present (record offsets 15,16) ⇒
    `undef` ⇒ the empty trailing slot + the uninitialized-value RawConv warning.
    """
    body = bytearray(15)
    body[0] = 16  # record offset 2
    body[1] = 1  # record offset 3
    body[2] = 29  # record offset 4  (AccelerometerUnknown[0])
    body[3:7] = struct.pack("<f", fx)  # record offset 5  (Accelerometer X)
    body[7] = 37  # record offset 9  (Unknown[1])
    body[8:12] = struct.pack("<f", fy)  # record offset 10 (Accelerometer Y)
    body[12] = 45  # record offset 14 (Unknown[2])
    body[13] = 0  # record offset 15 (Accelerometer Z, byte 0 of 4)
    body[14] = 0  # record offset 16 (Accelerometer Z, byte 1 of 4 — truncated)
    return b"\x0a" + bytes([len(body)]) + bytes(body)


def overflow_record() -> bytes:
    """One OVERFLOW ARCore TLV record (declared length past the sample end).

    The `0x0a` tag byte + a length byte of 200 (far beyond the few payload bytes
    that follow) ⇒ `Process_mett`'s `$pos + $len + 2 > $dirEnd` fires, so it
    `$et->Warn`s the `[minor] Unexpected length …` and `last`s before any
    `HandleTag` — no accel vector decodes.
    """
    return b"\x0a" + bytes([200]) + b"\x10\x01\x1d\x00\x00"


def valid_accel_record(fx: float, fy: float, fz: float) -> bytes:
    """One FULL ARCore Accel TLV record — all three floats in range (offset-5).

    The `Accelerometer` `undef[14]` value sits at record offset 5, so
    `GetFloat($val,0)`=X@5, `GetFloat($val,5)`=Y@10, `GetFloat($val,10)`=Z@15 are
    all readable ⇒ the full `"X Y Z"` vector with NO RawConv warning. The 34-byte
    payload mirrors `gen_parrot_arcore_fixture.py`'s well-formed record.
    """
    body = bytearray(34)
    body[0] = 16
    body[1] = 1
    body[2] = 29  # record offset 4 (Unknown[0])
    body[3:7] = struct.pack("<f", fx)  # record offset 5
    body[7] = 37
    body[8:12] = struct.pack("<f", fy)  # record offset 10
    body[12] = 45
    body[13:17] = struct.pack("<f", fz)  # record offset 15
    body[17] = 48
    return b"\x0a" + bytes([len(body)]) + bytes(body)


def trunc_then_overflow_sample() -> bytes:
    """ONE sample = a TRUNCATED-float TLV + an overflow TLV (18 bytes total).

    Laid out so the FIRST (decoded) TLV's `Accelerometer` reads a CLEAN partial
    vector and the SECOND TLV overflows:

      idx 0  : 0x0a               TLV1 tag
      idx 1  : 12                 TLV1 declared length (so the walk steps pos
                                  0 -> 14 = the second TLV's 0x0a, clear of the
                                  float bytes below)
      idx 5..8  : float X = 0.125  (`Accelerometer` undef[14] @ record offset 5)
      idx 10..13: float Y = -0.25  (record offset 10)
      idx 14 : 0x0a               TLV2 tag
      idx 15 : 200                TLV2 declared length -> 14 + 200 + 2 > 18 ⇒
                                  overflow `Warn` + `last`

    The whole sample is 18 bytes, so `GetFloat($val,10)` (buffer offset 10 =
    record offset 15, bytes 15..18) runs past the end ⇒ the third component is
    `undef`: a partial `Accelerometer = "0.125 -0.25 "` + the NON-minor RawConv
    warning (AHEAD of the value). Walk order: RawConv `Warning`, `Accelerometer`,
    then the MINOR overflow `Warning`.
    """
    b = bytearray(18)
    b[0] = 0x0a
    b[1] = 12
    b[5:9] = struct.pack("<f", 0.125)
    b[10:14] = struct.pack("<f", -0.25)
    b[14] = 0x0a
    b[15] = 200
    return bytes(b)


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

    for name, samples in (
        ("QuickTime_parrot_arcore_trunc.mp4", [truncated_record(0.125, -0.25)]),
        ("QuickTime_parrot_arcore_overflow.mp4", [overflow_record()]),
        # Multi-TLV intra-sample ordering (#123 follow-up): ONE sample whose
        # records emit MORE THAN ONE event, in walk order.
        (
            "QuickTime_parrot_arcore_valid_overflow.mp4",
            [valid_accel_record(0.125, -0.25, 9.8125) + overflow_record()],
        ),
        (
            "QuickTime_parrot_arcore_trunc_overflow.mp4",
            [trunc_then_overflow_sample()],
        ),
    ):
        data = build_mett_mov(samples, "application/arcore-accel")
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
