#!/usr/bin/env python3
"""Build the crafted QuickTime SP2 data-atom / international-text decode fixtures.

These minimal `.mov` files exercise the faithful `ProcessMOV` decode branches
that the real camera fixtures never reach (QuickTime.pm 10396-10416 conv-less
data-atom string->numeric->binary cascade, and 10461-10483 international-text
empty-entry continuation). Run from anywhere; writes into tests/fixtures/.

  python3 tools/gen_quicktime_sp2_decode_fixtures.py

The structural atoms (ftyp/mvhd/trak/meta-hdlr) are reused verbatim from
QuickTime_sp2_keys_direction.mov so only the exercised atom differs. After
running, regenerate the goldens with tools/gen_golden.sh (bundled ExifTool).
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXDIR = os.path.join(ROOT, "tests", "fixtures")

# ── Reusable structural atoms (sliced verbatim from the SP2 Keys template) ────
# Reading the exact byte ranges avoids any hand-transcription error and keeps
# every movie-level/track structural tag identical to the known-good fixture.
_TEMPLATE = open(os.path.join(FIXDIR, "QuickTime_sp2_keys_direction.mov"), "rb").read()
FTYP = _TEMPLATE[0:20]
MVHD = _TEMPLATE[28:136]
TRAK = _TEMPLATE[136:309]
META_HDLR = _TEMPLATE[317:350]


def atom(typ: bytes, body: bytes) -> bytes:
    assert len(typ) == 4
    return struct.pack(">I", len(body) + 8) + typ + body


def keys_box(keys):
    """A `keys` box: version/flags + count + each `[size][mdta][key]` entry."""
    body = b"\x00\x00\x00\x00" + struct.pack(">I", len(keys))
    for k in keys:
        kb = k.encode()
        body += struct.pack(">I", len(kb) + 8) + b"mdta" + kb
    return atom(b"keys", body)


def data_atom(flags: int, value: bytes) -> bytes:
    """An ilst `data` atom: flags(int32) + locale(int32) + value."""
    return atom(b"data", struct.pack(">I", flags) + b"\x00\x00\x00\x00" + value)


def ilst_item(index: int, *data_atoms) -> bytes:
    """An ilst item keyed by the 1-based big-endian key index."""
    return atom(struct.pack(">I", index), b"".join(data_atoms))


def meta_with_ilst(keys, items) -> bytes:
    return atom(b"meta", META_HDLR + keys_box(keys) + atom(b"ilst", b"".join(items)))


def udta(*atoms) -> bytes:
    return atom(b"udta", b"".join(atoms))


def build_mov(extra_moov_children: bytes) -> bytes:
    moov = atom(b"moov", MVHD + TRAK + extra_moov_children)
    mdat = atom(b"mdat", b"\x00" * 8)
    return FTYP + moov + mdat


def itext_entry(length: int, lang: int, text: bytes) -> bytes:
    """One international-text entry: int16u len, int16u lang, then text bytes.

    `length` is written verbatim (so a deliberately-zero header can be built);
    the caller controls whether it matches `len(text)`.
    """
    return struct.pack(">H", length) + struct.pack(">H", lang) + text


def write(name: str, data: bytes):
    path = os.path.join(FIXDIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes)")


def main():
    # 1. Keys conv-less atom with a BINARY flag (0x00, len 3 -> QuickTimeFormat
    #    returns undef for a 3-byte int8u/int16u -> binary scalar ref branch).
    #    `direction.facing` (CameraDirection) is conv-less + Format-less in the
    #    Keys table, so it hits the full cascade.
    bin_mov = build_mov(
        meta_with_ilst(
            ["com.apple.quicktime.direction.facing"],
            [ilst_item(1, data_atom(0x00, b"\x01\x02\x03"))],
        )
    )
    write("QuickTime_sp2_ilst_binary.mov", bin_mov)

    # 2. Keys conv-less atom with a NUMERIC flag (0x16 unsigned int, len 2 ->
    #    int16u -> a JSON number).
    num_mov = build_mov(
        meta_with_ilst(
            ["com.apple.quicktime.direction.facing"],
            [ilst_item(1, data_atom(0x16, b"\x01\x2c"))],  # 0x012c = 300
        )
    )
    write("QuickTime_sp2_ilst_numeric.mov", num_mov)

    # 2b. Float/double conv-less atoms (flag 0x17 / 0x18). `QuickTimeFormat`
    #     returns the float/double format from the FLAG ALONE (no length gate,
    #     QuickTime.pm:9562-9565), so ReadValue with an undef count
    #     (ExifTool.pm:6296-6331) reads int(len/elem) values: a payload shorter
    #     than one element -> '' (empty scalar); one element -> a JSON number;
    #     several -> a space-joined string. Clean values (1.5, 2.5) so the
    #     single-value JSON number token is unambiguous.
    def float_mov(name, flags, value):
        write(
            name,
            build_mov(
                meta_with_ilst(
                    ["com.apple.quicktime.direction.facing"],
                    [ilst_item(1, data_atom(flags, value))],
                )
            ),
        )

    # short: flag 0x17 (float, elem 4) with only 2 bytes -> ReadValue `return ''`.
    float_mov("QuickTime_sp2_ilst_float_short.mov", 0x17, b"\x3f\xc0")
    # single: one big-endian float 1.5 -> a single JSON number.
    float_mov("QuickTime_sp2_ilst_float_single.mov", 0x17, struct.pack(">f", 1.5))
    # multi: two floats 1.5, 2.5 -> "1.5 2.5" (space-joined string).
    float_mov(
        "QuickTime_sp2_ilst_float_multi.mov",
        0x17,
        struct.pack(">f", 1.5) + struct.pack(">f", 2.5),
    )
    # multi double: two doubles 1.5, 2.5 (elem 8) -> "1.5 2.5".
    float_mov(
        "QuickTime_sp2_ilst_double_multi.mov",
        0x18,
        struct.pack(">d", 1.5) + struct.pack(">d", 2.5),
    )

    # 2c. The REROUTED conv-less identity keys (Make / AndroidCaptureFPS) now run
    #     through the SAME string->numeric->binary cascade as direction.facing
    #     (QuickTime.pm:10387-10416), so a NON-default format flag on them no
    #     longer drops/truncates the value (the prior per-key typed paths handled
    #     only one flavor). Pin each shape against bundled 13.59.

    # `com.apple.quicktime.make` with a NUMERIC flag (0x16 unsigned int, len 2 ->
    # int16u 0x012c = 300) -> ExifTool emits `Keys:Make` = the JSON number 300
    # (the OLD typed-string Make path required a string flag and dropped this).
    write(
        "QuickTime_sp2_keys_make_numeric.mov",
        build_mov(
            meta_with_ilst(
                ["com.apple.quicktime.make"],
                [ilst_item(1, data_atom(0x16, b"\x01\x2c"))],
            )
        ),
    )

    # `com.android.capture.fps` with a UTF-8 STRING flag (0x01, "29.97") ->
    # ExifTool emits `Keys:AndroidCaptureFPS` = the string "29.97" (the OLD
    # typed-float path required a 0x17/0x18 flag and dropped a string flag).
    write(
        "QuickTime_sp2_keys_fps_string.mov",
        build_mov(
            meta_with_ilst(
                ["com.android.capture.fps"],
                [ilst_item(1, data_atom(0x01, b"29.97"))],
            )
        ),
    )

    # `com.android.capture.fps` SHORT (0x17 float, 2 bytes < one element) ->
    # ReadValue `return ''` -> `Keys:AndroidCaptureFPS` = "" (NOT dropped, NOT the
    # binary placeholder). Pins the float-undef-count short case on the rerouted
    # AndroidCaptureFPS specifically.
    write(
        "QuickTime_sp2_keys_fps_short.mov",
        build_mov(
            meta_with_ilst(
                ["com.android.capture.fps"],
                [ilst_item(1, data_atom(0x17, b"\x3f\xc0"))],
            )
        ),
    )

    # `com.android.capture.fps` MULTI (0x17 float, two floats 1.5 2.5) ->
    # "1.5 2.5" (space-joined; the OLD typed-float path read only the FIRST
    # element and truncated). Pins the float-undef-count multi case.
    write(
        "QuickTime_sp2_keys_fps_multi.mov",
        build_mov(
            meta_with_ilst(
                ["com.android.capture.fps"],
                [ilst_item(1, data_atom(0x17, struct.pack(">f", 1.5) + struct.pack(">f", 2.5)))],
            )
        ),
    )

    # 2d. The VALUECONV-BEARING Keys atoms (creationdate / location.ISO6709).
    #     These have a ValueConv (ConvertXMPDate / ConvertISO6709), so unlike the
    #     conv-less atoms a non-string flag is NOT the binary placeholder: ExifTool
    #     feeds the pre-ValueConv value (string flag -> decoded, numeric ->
    #     ReadValue number, else -> raw bytes) to the ValueConv, which passes a
    #     non-date / non-ISO6709 value through, so the tag ALWAYS emits for ANY
    #     flag (QuickTime.pm:10396-10416). Pin each against bundled 13.59.
    def keys_mov(name, key, flags, value):
        write(
            name,
            build_mov(
                meta_with_ilst([key], [ilst_item(1, data_atom(flags, value))]),
            ),
        )

    # creationdate NUMERIC flag (0x16 int16u 300) -> ConvertXMPDate passes the
    # number through -> `Keys:CreationDate` = the bare number 300 (OLD path, gated
    # on a string flag, DROPPED it).
    keys_mov("QuickTime_sp2_keys_cdate_numeric.mov",
             "com.apple.quicktime.creationdate", 0x16, b"\x01\x2c")
    # creationdate BINARY flag (0x00) with non-date raw bytes -> ConvertXMPDate
    # passes them through verbatim -> `Keys:CreationDate` = the raw string.
    keys_mov("QuickTime_sp2_keys_cdate_binary.mov",
             "com.apple.quicktime.creationdate", 0x00, b"\x01\x02\x03\x04")
    # location NUMERIC flag (0x16 int16u 300) -> ConvertISO6709 + PrintGPSCoordinates
    # render "300 deg 0' 0.00\" N, " (lat 300, no lon) (OLD path DROPPED it).
    keys_mov("QuickTime_sp2_keys_loc_numeric.mov",
             "com.apple.quicktime.location.ISO6709", 0x16, b"\x01\x2c")
    # location BINARY flag (0x00) whose raw bytes ARE a valid ISO6709 string ->
    # parsed coordinates (OLD path DROPPED a non-string flag).
    keys_mov("QuickTime_sp2_keys_loc_binary.mov",
             "com.apple.quicktime.location.ISO6709", 0x00, b"+12.3+045.6/")

    # 3a. A `©`-atom (©nam Title) whose FIRST international-text entry is empty
    #     (len 0) FOLLOWED BY a valid entry ("Hi", lang 0) -> ExifTool skips the
    #     empty entry and decodes the later one.
    empty_then_valid = udta(
        atom(b"\xa9nam", itext_entry(0, 0, b"") + itext_entry(2, 0, b"Hi"))
    )
    write("QuickTime_sp2_itext_empty_first.mov", build_mov(empty_then_valid))

    # 3b. A `©`-atom (©nam Title) whose ONLY entry is empty (len 0) -> ExifTool
    #     emits nothing for it.
    empty_only = udta(atom(b"\xa9nam", itext_entry(0, 0, b"")))
    write("QuickTime_sp2_itext_empty_only.mov", build_mov(empty_only))


if __name__ == "__main__":
    main()
