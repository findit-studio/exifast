#!/usr/bin/env python3
"""Build the crafted MULTI-SOURCE timed-metadata `.mov` fixtures.

These exercise the GLOBAL `$$et{DOC_COUNT}` document axis ACROSS more than one
timed-metadata source / track in ONE file (issue #214) — the cases the
single-source fixtures (`QuickTime_camm.mov`, `QuickTime_mebx_*.mov`,
`QuickTime_gps_kenwood.mov`) cannot reach:

  QuickTime_camm_2track.mov   — two `camm` metadata `trak`s (Track1 + Track2),
      each with its own GPS fixes. Pins (a) the GLOBAL doc counter spanning two
      tracks at `-ee -G3:1` (Track2's first fix continues the ordinal after
      Track1's last, NOT a colliding Doc1) and (b) the group-aware `-ee -G1`
      collapse keeping BOTH `Track1:GPSLatitude` and `Track2:GPSLatitude`.

  QuickTime_mebx_camm.mov     — a `mebx` `trak` (Track1) FOLLOWED by a `camm`
      `trak` (Track2). Pins the cross-STRUCT global doc: the `mebx` sample opens
      Doc1, the camm fixes continue Doc2.. — they live in SEPARATE exifast
      structs (`QuickTimeStreamMeta` vs `CammMeta`) yet share ONE ordinal.

  QuickTime_mebx_2track.mov   — two `mebx` `trak`s emitting the SAME key name.
      Pins the group-aware `-ee -G1` mebx collapse: BOTH `Track1:SceneIlluminance`
      and `Track2:SceneIlluminance` survive (a name-only collapse would drop the
      2nd track's value), and the global doc spans the two tracks at `-G3:1`.

Run:
  python3 tools/gen_timed_multi_fixtures.py            # -> tests/fixtures/
Then regenerate goldens with the bundled ExifTool:
  for f in QuickTime_camm_2track QuickTime_mebx_camm QuickTime_mebx_2track; do
    EE=1 EXCLUDE="-x System:all -x Composite:all" tools/gen_golden.sh $f.mov
  done

The structural atoms mirror `tools/gen_camm_fixture.py` exactly (ftyp / mdat /
moov(mvhd + trak…)); the only additions are (1) a generic N-`trak` moov with
each `trak`'s `stco` pointed at its own slice of a shared `mdat`, and (2) a
`mebx`-track builder (a `mebx` `stsd` carrying a `keys` table + a sample of
`[len:u32][local_id:u32][value]` records — QuickTimeStream.pl:876-962 / 2644).
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


# ── CAMM sample packets (mirrors tools/gen_camm_fixture.py) ──────────────────
def camm_packet(type_id: int, payload: bytes) -> bytes:
    return b"\x00\x00" + struct.pack("<H", type_id) + payload


def camm5_packet(lat: float, lon: float, alt: float) -> bytes:
    return camm_packet(5, struct.pack("<ddd", lat, lon, alt))


# ── mebx keys-table + sample (QuickTimeStream.pl:876-962 / 2644) ─────────────
def keys_entry(local_id: int, tag_id: str, ns: int, fmt_code: bytes) -> bytes:
    """One `SaveMetaKeys` entry: `[size:u32][local_id:u32][keyd][dtyp]`.

    `keyd` value = `mdtacom.apple.quicktime.` + `tag_id` (the namespace the
    decoder strips). `dtyp` value = `[namespace:u32][format_code:4]`.
    """
    keyd_val = b"mdtacom.apple.quicktime." + tag_id.encode("ascii")
    keyd = atom(b"keyd", keyd_val)
    dtyp = atom(b"dtyp", struct.pack(">I", ns) + fmt_code)
    inner = keyd + dtyp
    return struct.pack(">II", len(inner) + 8, local_id) + inner


def keys_box(entries) -> bytes:
    """The `keys` box: `[version+flags:4][count:4]` then the entry table."""
    body = b"\x00\x00\x00\x00" + struct.pack(">I", len(entries)) + b"".join(entries)
    return atom(b"keys", body)


def mebx_sample_record(local_id: int, value: bytes) -> bytes:
    """One `Process_mebx` record: `[len:u32][local_id:u32][value]`."""
    return struct.pack(">II", len(value) + 8, local_id) + value


# ── generic structural atoms ─────────────────────────────────────────────────
def mvhd(total_dur: int) -> bytes:
    body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 80
    )
    return atom(b"mvhd", body)


def meta_hdlr() -> bytes:
    body = (
        b"\x00\x00\x00\x00"
        + b"mhlr"
        + b"meta"
        + b"\x00" * 12
        + b"\x00"
    )
    return atom(b"hdlr", body)


def mdhd(total_dur: int) -> bytes:
    body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4
    )
    return atom(b"mdhd", body)


def stbl(stsd_body: bytes, n_samples: int, sizes, chunk_off: int) -> bytes:
    stts_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">II", n_samples, 1000)
    )
    stsc_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">III", 1, n_samples, 1)
    )
    stsz_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)
        + struct.pack(">I", n_samples)
        + b"".join(struct.pack(">I", s) for s in sizes)
    )
    stco_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", chunk_off)
    )
    return atom(
        b"stbl",
        atom(b"stsd", stsd_body)
        + atom(b"stts", stts_body)
        + atom(b"stsc", stsc_body)
        + atom(b"stsz", stsz_body)
        + atom(b"stco", stco_body),
    )


def trak(stsd_body: bytes, samples, chunk_off: int, total_dur: int) -> bytes:
    sizes = [len(s) for s in samples]
    minf = atom(b"minf", atom(b"nmhd", b"\x00\x00\x00\x00")
                + stbl(stsd_body, len(samples), sizes, chunk_off))
    mdia = atom(b"mdia", mdhd(total_dur) + meta_hdlr() + minf)
    return atom(b"trak", atom(b"tkhd", b"\x00" * 84) + mdia)


def camm_stsd() -> bytes:
    entry = struct.pack(">I", 16) + b"camm" + b"\x00" * 6 + struct.pack(">H", 1)
    return b"\x00\x00\x00\x00" + struct.pack(">I", 1) + entry


def mebx_stsd(entries) -> bytes:
    kbox = keys_box(entries)
    entry_body = b"\x00" * 6 + struct.pack(">H", 1) + kbox  # 6 reserved + data_ref_idx
    entry = struct.pack(">I", len(entry_body) + 8) + b"mebx" + entry_body
    return b"\x00\x00\x00\x00" + struct.pack(">I", 1) + entry


def build_mov(tracks) -> bytes:
    """`tracks` is a list of `(stsd_body, [sample_bytes...])`.

    All samples of all tracks are stored back-to-back in one `mdat`; each
    track's `stco` points at its first sample. ftyp / mdat / moov layout
    (matches gen_camm_fixture.py so the stco offsets land inside the mdat
    placed right after ftyp).
    """
    ftyp = atom(b"ftyp", b"qt  " + struct.pack(">I", 0))

    # Lay out every track's samples contiguously in mdat, recording each
    # track's first-sample file offset.
    all_samples = []
    offsets = []
    sample_base = len(ftyp) + 8  # file offset of the first mdat sample
    cursor = sample_base
    for _stsd, samples in tracks:
        offsets.append(cursor)
        for s in samples:
            all_samples.append(s)
            cursor += len(s)

    sample_blob = b"".join(all_samples)
    mdat = struct.pack(">I", len(sample_blob) + 8) + b"mdat" + sample_blob

    total_dur = 1000 * max((len(s) for _, s in tracks), default=0)
    trak_atoms = b"".join(
        trak(stsd, samples, offsets[i], 1000 * len(samples))
        for i, (stsd, samples) in enumerate(tracks)
    )
    moov = atom(b"moov", mvhd(total_dur) + trak_atoms)
    return ftyp + mdat + moov


def main() -> None:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "fixtures",
    )
    os.makedirs(outdir, exist_ok=True)

    def write(name, data):
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (path, len(data)))

    # double-precision GPS format code for a namespace-0 dtyp: ExifTool's
    # %qtFmt maps int32u 0x0000001c (28) -> 'double'? No — the dtyp format is a
    # 4-CHAR code (see QuickTimeStream.pl:923-924 Get32u then qtFmtConv). We use
    # the int32u packet form via scene-illuminance (undef + ValueConv unpack N),
    # the canonical multi-record mebx key the existing fixtures use.

    # ── QuickTime_camm_2track.mov — two camm tracks ──────────────────────────
    track1 = (camm_stsd(), [
        camm5_packet(47.628423, -122.165016, 123.0),
        camm5_packet(33.752000, 151.205667, 80.0),
    ])
    track2 = (camm_stsd(), [
        camm5_packet(37.422000, -122.084000, 30.0),
    ])
    write("QuickTime_camm_2track.mov", build_mov([track1, track2]))

    # ── mebx key: scene-illuminance (local_id 1, namespace-0 'be32' undef,
    # ValueConv unpack N). dtyp namespace 0 + format code: the existing
    # mebx fixtures encode scene-illuminance as an undef 4-byte big-endian
    # int (the ValueConv does unpack 'N'). We give dtyp namespace 1 (=> undef)
    # so the raw 4 value bytes pass straight to the `unpack N` ValueConv. ──────
    se_key = keys_entry(1, "scene-illuminance", ns=1, fmt_code=b"\x00\x00\x00\x00")
    # value = big-endian int32u milli-lux.
    se_sample_a = mebx_sample_record(1, struct.pack(">I", 1234))
    se_sample_b = mebx_sample_record(1, struct.pack(">I", 5678))

    # ── QuickTime_mebx_camm.mov — mebx Track1 then camm Track2 ───────────────
    mebx_track = (mebx_stsd([se_key]), [se_sample_a])
    camm_after = (camm_stsd(), [
        camm5_packet(47.628423, -122.165016, 123.0),
        camm5_packet(33.752000, 151.205667, 80.0),
    ])
    write("QuickTime_mebx_camm.mov", build_mov([mebx_track, camm_after]))

    # ── QuickTime_mebx_2track.mov — two mebx tracks, same key ────────────────
    mebx_t1 = (mebx_stsd([se_key]), [se_sample_a])
    mebx_t2 = (mebx_stsd([se_key]), [se_sample_b])
    write("QuickTime_mebx_2track.mov", build_mov([mebx_t1, mebx_t2]))


if __name__ == "__main__":
    main()
