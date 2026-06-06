#!/usr/bin/env python3
"""Build the crafted MULTI-ENTRY `stsd` timed-metadata `.mov` fixture
(`QuickTime_sony_rtmd_multistsd.mov`).

This fixture pins the faithful port of ExifTool's multi-entry sample-description
handling for a `meta`-HandlerType timed-metadata track (Codex R14):

  * `ProcessSampleDesc` (QuickTime.pm:9640-9648) loops EVERY `stsd` entry and
    runs the per-entry `RawConv => '$$self{MetaFormat} = $val'`, so `$$et
    {MetaFormat}` ends as the LAST entry's format (last-wins) — that is the one
    value emitted as `Track<N>:MetaFormat`.
  * `ProcessSamples` then dispatches EVERY sample on that single track-wide
    `$$et{MetaFormat}` (QuickTimeStream.pl:1398). The `stsc`
    sample-description index is parsed but DELIBERATELY NOT consulted (explicit
    ExifTool TODO, QuickTimeStream.pl:1378 `# (eventually should use the
    description indices: $descIdx)`).

So a track whose `stsd` carries `[rtmd, camm]` (two entries, different formats)
and whose `stsc` points the chunk at description index 1 (the FIRST entry,
`rtmd`) STILL:
  - emits `Track1:MetaFormat = "camm"` (the LAST entry), and
  - decodes its sample as `camm` (the LAST format) — NOT `rtmd` — extracting the
    camm5 GPS fix, proving the desc-index is ignored and the last-wins format
    drives the decoder.

The `rtmd` (Sony) entry is the FIRST/decoy entry; `camm` (Android, a ported
decoder) is the LAST/active one, so the whole document is byte-exact against the
bundled oracle with NO excluded tags (rtmd's own payload decode stays deferred,
but it is never the active format here). Verified vs ExifTool 13.59:

    exiftool -ee -j -G1   -> Track1:MetaFormat "camm" + camm GPS + SampleTime
    exiftool -ee -j -G3:1 -> Doc1:Track1:… (one fix)

  python3 tools/gen_sony_rtmd_fixture.py            # -> tests/fixtures/
  python3 tools/gen_sony_rtmd_fixture.py <outdir>

After running, regenerate the goldens with the bundled ExifTool:
  EXIFTOOL=/path/exiftool EE=1 EXCLUDE="-x System:all -x Composite:all" \
    tools/gen_golden.sh QuickTime_sony_rtmd_multistsd.mov
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def camm_packet(type_id: int, payload: bytes) -> bytes:
    """`[reserved:2(=0)][type:int16u-LE][payload]`."""
    return b"\x00\x00" + struct.pack("<H", type_id) + payload


def camm5_packet(lat: float, lon: float, alt: float) -> bytes:
    """camm type 5: 3×double (GPSLatitude, GPSLongitude, GPSAltitude)."""
    return camm_packet(5, struct.pack("<ddd", lat, lon, alt))


def stsd_entry(fmt: bytes) -> bytes:
    """One sample-description entry: `[size:4][format:4][reserved:6][dref:2]`."""
    assert len(fmt) == 4, fmt
    return struct.pack(">I", 16) + fmt + b"\x00" * 6 + struct.pack(">H", 1)


def stsd_entry_8(fmt: bytes) -> bytes:
    """An UNDERSIZED 8-byte entry: just `[size=8:4][format:4]` — no room for the
    reserved/data-ref-index or child atoms. ExifTool stops the loop only at
    `$size < 8` (QuickTime.pm:9642), so an 8-byte entry STILL contributes its
    offset-4 format to the last-wins MetaFormat. Crafted (real entries are >=16)."""
    assert len(fmt) == 4, fmt
    return struct.pack(">I", 8) + fmt


def build_multistsd_mov(entries, desc_index_for_chunk: int, samples) -> bytes:
    """Minimal `.mov` with a `meta`-handler track carrying a MULTI-entry `stsd`.

    `entries` is the list of pre-built sample-description entry BYTES (in order);
    the LAST is the active (last-wins) MetaFormat. `desc_index_for_chunk` is the
    1-based sample-description index the `stsc` run points the chunk at — used to
    prove ExifTool ignores it (a value of 1 points at the FIRST/decoy entry).
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
    # hdlr: mhlr / meta (the meta_handler the stsd MetaFormat dispatches through).
    hdlr_body = b"\x00\x00\x00\x00" + b"mhlr" + b"meta" + b"\x00" * 12 + b"\x00"
    mdhd_body = (
        b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + struct.pack(">I", 1000)
        + struct.pack(">I", total_dur)
        + b"\x00" * 4
    )
    # stsd: N entries (the LAST is the active last-wins MetaFormat).
    stsd_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", len(entries))
        + b"".join(entries)
    )
    stts_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">II", len(samples), 1000)
    )
    # stsc: all samples in one chunk, sample-description index = the decoy entry.
    stsc_body = (
        b"\x00\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">III", 1, len(samples), desc_index_for_chunk)
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

    # stsd = [rtmd (decoy, entry 1), camm (active last-wins, entry 2)]; the
    # stsc run points the single chunk at description index 1 (the rtmd entry).
    # ExifTool decodes the sample as the LAST format (camm) regardless, and
    # emits MetaFormat = "camm".
    sample = camm5_packet(47.628423, -122.165016, 123.0)

    data = build_multistsd_mov(
        [stsd_entry(b"rtmd"), stsd_entry(b"camm")],
        1,
        [sample],
    )
    path = os.path.join(outdir, "QuickTime_sony_rtmd_multistsd.mov")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))

    # Same, but the active LAST entry is an UNDERSIZED 8-byte `camm`
    # (`[size=8][camm]`, no reserved/dref/children). ExifTool's stop condition is
    # `$size < 8` (NOT 16), so the 8-byte entry STILL sets last-wins
    # MetaFormat = "camm" and drives the camm decoder — pinning the `size >= 8`
    # (not `>= 16`) guard in walk_stsd / decode_stsd_meta_format.
    data8 = build_multistsd_mov(
        [stsd_entry(b"rtmd"), stsd_entry_8(b"camm")],
        1,
        [sample],
    )
    path8 = os.path.join(outdir, "QuickTime_sony_rtmd_multistsd8.mov")
    with open(path8, "wb") as f:
        f.write(data8)
    print("wrote %s (%d bytes)" % (path8, len(data8)))


if __name__ == "__main__":
    main()
