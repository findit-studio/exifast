#!/usr/bin/env python3
"""Build the crafted ProcessKeys cross-table / movie-derive fixtures (#361 R7).

Two faithful exercises of the COMPLETE `ProcessKeys` order (QuickTime.pm:9806-
9854 — active `%Keys`/`%AudioKeys` table -> `%ItemList` -> `%UserData` ->
derive) that the real camera fixtures never reach together:

  1. MP4_audiokeys_mute.mp4 (REGENERATED in place) — the audio-track `soun`
     `keys` box gains two RAW `0xA9`-prefixed 4-cc ids (`\xa9day` / `\xa9too`,
     the copyright-symbol ItemList ids) ON TOP of the existing 7 keys. The raw
     bytes must reach the cross-table for the literal id to match — a UTF-8
     decode would mangle the `0xA9` into U+FFFD. Resolves to
     `AudioKeys:ContentCreateDate` (the `%iso8601Date` ValueConv) +
     `AudioKeys:Encoder`. The pre-existing 7 keys are byte-for-byte unchanged, so
     every other AudioKeys tag (incl `AudioKeys:Make = CanonManu` from `manu`)
     stays identical.

  2. MP4_movie_keys.mov (NEW) — a movie-level `moov/meta`(`mdta`) `keys` box
     (the GENERIC `%QuickTime::Keys` table, NOT AudioKeys) carrying:
       - a NON-table key (`com.apple.quicktime.acme.totally.bogus.zzz`) that the
         DERIVE step must emit as `Keys:AcmeTotallyBogusZzz` (the [high] fix —
         previously dropped because `apply_key` had no derive fallback);
       - raw `0xA9` ids `\xa9day` -> `Keys:ContentCreateDate` (ItemList, ValueConv)
         and `\xa9xyz` -> `Keys:GPSCoordinates` (ItemList, ConvertISO6709 +
         PrintGPSCoordinates);
       - `manu` -> `Keys:Make` (UserData, conv-less) for cross-table coverage.

Run from anywhere:

  python3 tools/gen_keys_crosstable_fixtures.py

then regenerate the goldens with tools/gen_golden.sh (bundled ExifTool).
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXDIR = os.path.join(ROOT, "tests", "fixtures")


def atom(typ: bytes, body: bytes) -> bytes:
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


def keys_box(keys) -> bytes:
    """A `keys` box: version/flags + count + each `[size][ns][key]` entry.

    `keys` is a list of (namespace_bytes[4], key_bytes) — the key is RAW bytes so
    a non-UTF-8 `0xA9`-prefixed id can be written verbatim.
    """
    body = b"\x00\x00\x00\x00" + struct.pack(">I", len(keys))
    for ns, kb in keys:
        assert len(ns) == 4, ns
        body += struct.pack(">I", len(kb) + 8) + ns + kb
    return atom(b"keys", body)


def data_atom(flags: int, value: bytes) -> bytes:
    return atom(b"data", struct.pack(">I", flags) + b"\x00\x00\x00\x00" + value)


def ilst_item(index: int, flags: int, value: bytes) -> bytes:
    return atom(struct.pack(">I", index), data_atom(flags, value))


def ilst(items) -> bytes:
    return atom(b"ilst", b"".join(items))


def write(name: str, data: bytes):
    path = os.path.join(FIXDIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes)")


def regen_audiokeys_mute():
    """Rebuild MP4_audiokeys_mute.mp4 from its own structural atoms + 2 new
    raw-0xA9 audio keys. The structural atoms are sliced verbatim from the
    existing fixture so every non-keys/ilst byte is preserved."""
    src = open(os.path.join(FIXDIR, "MP4_audiokeys_mute.mp4"), "rb").read()
    # Atom offsets in the existing fixture (see the conformance comment):
    #   ftyp[0:28] mdat[28:52] moov(60..) mvhd[60:168] trak(168..)
    #   tkhd[176:268] mdia[268:529] meta[529:](keys+ilst, QT-style no hdlr).
    ftyp = src[0:28]
    mdat_body = src[36:52]  # the 16-byte mdat payload
    mvhd = src[60:168]
    tkhd = src[176:268]
    mdia = src[268:529]

    audio_keys = [
        (b"mdta", b"com.apple.quicktime.player.movie.audio.balance"),
        (b"mdta", b"com.apple.quicktime.player.movie.audio.mute"),
        (b"mdta", b"com.apple.quicktime.make"),
        (b"mdta", b"com.apple.quicktime.creationdate"),
        (b"mdta", b"com.acme.totally.bogus.zzz"),
        (b"mdta", b"manu"),
        (b"mdta", b"modl"),
        (b"mdta", b"\xa9day"),  # raw 0xA9 -> ItemList ContentCreateDate
        (b"mdta", b"\xa9too"),  # raw 0xA9 -> ItemList Encoder
    ]
    audio_items = [
        ilst_item(1, 0x01, b"0"),
        ilst_item(2, 0x16, b"\x01"),
        ilst_item(3, 0x01, b"SHOULD_DROP"),
        ilst_item(4, 0x01, b"2025-07-03T17:22:10-0400"),
        ilst_item(5, 0x01, b"ARBVAL"),
        ilst_item(6, 0x01, b"CanonManu"),
        ilst_item(7, 0x01, b"EOS SX280"),
        ilst_item(8, 0x01, b"2024-05-06T07:08:09-0500"),
        ilst_item(9, 0x01, b"MyEncoder"),
    ]
    audio_meta = atom(b"meta", keys_box(audio_keys) + ilst(audio_items))
    trak = atom(b"trak", tkhd + mdia + audio_meta)
    moov = atom(b"moov", mvhd + trak)
    out = ftyp + atom(b"mdat", mdat_body) + moov
    write("MP4_audiokeys_mute.mp4", out)


def gen_movie_keys():
    """A movie-level moov/meta(mdta) keys box -> the GENERIC %QuickTime::Keys
    resolver. Reuses the SP2 structural atoms (a video trak, so the meta is
    movie-level Keys, NOT AudioKeys)."""
    tmpl = open(os.path.join(FIXDIR, "QuickTime_sp2_keys_direction.mov"), "rb").read()
    ftyp = tmpl[0:20]
    mvhd = tmpl[28:136]
    trak = tmpl[136:309]
    meta_hdlr = tmpl[317:350]  # the `mdta` metadata hdlr

    movie_keys = [
        (b"mdta", b"com.apple.quicktime.acme.totally.bogus.zzz"),  # derive
        (b"mdta", b"\xa9day"),  # raw 0xA9 -> ItemList ContentCreateDate
        (b"mdta", b"\xa9xyz"),  # raw 0xA9 -> ItemList GPSCoordinates
        (b"mdta", b"manu"),     # -> UserData Make
    ]
    movie_items = [
        ilst_item(1, 0x01, b"MOVBOGUS"),
        ilst_item(2, 0x01, b"2023-11-12T13:14:15-0800"),
        ilst_item(3, 0x01, b"+48.8584+002.2945/"),
        ilst_item(4, 0x01, b"AcmeMovie"),
    ]
    moov_meta = atom(b"meta", meta_hdlr + keys_box(movie_keys) + ilst(movie_items))
    moov = atom(b"moov", mvhd + trak + moov_meta)
    mdat = atom(b"mdat", b"\x00" * 8)
    write("MP4_movie_keys.mov", ftyp + moov + mdat)


def main():
    regen_audiokeys_mute()
    gen_movie_keys()


if __name__ == "__main__":
    main()
