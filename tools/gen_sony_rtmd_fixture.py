#!/usr/bin/env python3
"""Build the crafted Sony `rtmd` (Real-Time MetaData) timed-metadata `.mov` fixture.

exifast has no real Sony A7/FX `rtmd` clip in `tests/fixtures/` (follow-up #76);
this script emits a *minimal* but bundled-ExifTool-decodable `.mov` carrying an
`rtmd` MetaFormat track so the Sony timed-metadata `-ee` oracle goldens have a
real on-disk input.

  python3 tools/gen_sony_rtmd_fixture.py            # -> tests/fixtures/QuickTime_sony_rtmd.mov
  python3 tools/gen_sony_rtmd_fixture.py <outdir>

rtmd byte layout (mirrored from `%Image::ExifTool::Sony::rtmd` +
`sub Process_rtmd`, Sony.pm:10727/11609). The `rtmd` MetaFormat dispatches
through `QuickTime::Stream`'s `rtmd` SubDirectory → `Sony::rtmd` (the
`Process_rtmd` PROCESS_PROC), and — unlike the NextBase `text` path —
`ProcessSamples` hands the raw sample to `HandleTag` WITHOUT stripping the
leading 2-byte length word (QuickTimeStream.pl:1518-1529). So `Process_rtmd`
reads its own 2-byte BE header-length word at offset 0 of each sample:

    [hdrLen:int16u-BE][ (hdrLen-2) header bytes, here zero-filled ][ record … ]

then walks records `[tag:int16u-BE][len:int16u-BE][value:len bytes]` starting AT
offset `hdrLen`. ALL multi-byte integers are BIG-ENDIAN (Sony default,
Sony.pm:55). The rtmd table is `GROUPS => {2=>'Video'}` (GPS tags override to
Location/Time) and is extracted ONLY under `-ee`.

Two samples are emitted, each carrying a realistic camera record set; sample 0
also carries a phone-paired GPS fix (GPSVersionID … GPSDateStamp). The samples
are stored contiguously in `mdat`; the sample table (stts/stsc/stsz/stco)
describes both in a single chunk so ExifTool's `ProcessSamples` opens one
`Doc<N>` per sample.

The structural atoms (ftyp/mvhd/trak/mdia/hdlr=mhlr+meta/minf/stbl/stsd=rtmd)
mirror `gen_camm_fixture.py`'s `build_camm_mov` verbatim except the stsd 4-byte
format code is `rtmd` instead of `camm` (the ONLY structural change — same
`meta` handler the camm stsd dispatches through). After running, regenerate the
goldens with `EE=1 EXCLUDE="-x System:all -x Composite:all" tools/gen_golden.sh
QuickTime_sony_rtmd.mov` (bundled ExifTool).

Per-tag encodings (Format looked up in `%Image::ExifTool::Sony::rtmd`):
  0x8000 FNumber     int16u       0xC000 → 2**(8-49152/8192)=2**2 → "4.0"
  0x8106 FrameRate   rational64u  30000/1001 → "29.97"
  0x8109 ExposureTime rational64u 1/60 → "1/60"
  0x810a MasterGain  int16u       600 → /100 → "6.00 dB"
  0x810b ISO         int16u       800 (sample 0) / 1600 (sample 1)
  0x810c ElectricalExtenderMagnification int16u 200 (no conv → "200")
  0x8114 SerialNumber string      "ILCE-7SM3 5072108"
  0xe303 WhiteBalance int8u       0 (no PrintConv key 0 → raw "0")
  0xe304 DateTime    undef        unpack "x1H4H2H2H2H2H2" → [pad][YYYY:2][MM][DD][hh][mm][ss] BCD
  0xe43b PitchRollYaw int16s+RawConv 8-byte header + int16s(100,-200,300); RawConv
                                  substr($val,8) on the WHOLE-record int16s rendering
                                  → "13091 4386 13124 100 -200 300"
  0xe44b Accelerometer int16s+RawConv same shape, int16s(-50,16384,-1)
                                  → "13091 4386 13124 -50 16384 -1"
  GPS (sample 0 only):
  0x8500 GPSVersionID  int8u ×4   2,2,0,0 → "2.2.0.0"
  0x8501 GPSLatitudeRef string    "N"
  0x8502 GPSLatitude   rational64u ×3  47/1, 37/1, 423/10 (D,M,S)
  0x8503 GPSLongitudeRef string   "W"
  0x8504 GPSLongitude  rational64u ×3  122/1, 9/1, 540/10 (D,M,S)
  0x8507 GPSTimeStamp  rational64u ×3  11/1, 19/1, 15/1 (H,M,S)
  0x8509 GPSStatus     string     "A"
  0x850a GPSMeasureMode string    "3"
  0x8512 GPSMapDatum    string    "WGS-84"
  0x851d GPSDateStamp   string    "2024:01:07"
"""
import os
import struct
import sys


def atom(typ: bytes, body: bytes) -> bytes:
    """Wrap `body` as a QuickTime atom `[size:u32 BE][type:4][body]`."""
    assert len(typ) == 4, typ
    return struct.pack(">I", len(body) + 8) + typ + body


# ── rtmd sample records ──────────────────────────────────────────────────────
def rtmd_record(tag: int, value: bytes) -> bytes:
    """One rtmd record: `[tag:int16u-BE][len:int16u-BE][value:len bytes]`."""
    return struct.pack(">HH", tag, len(value)) + value


def rtmd_sample(records, hdr_len: int = 0x1c) -> bytes:
    """A whole rtmd sample: `[hdrLen:int16u-BE][ (hdrLen-2) zero header bytes ][records]`.

    `Process_rtmd` reads `Get16u($dataPt, 0)` as the header length and begins
    the record walk at that offset, so the first `hdr_len` bytes (the 2-byte
    length word + `hdr_len-2` real-camera header bytes we don't model) are
    skipped. 0x1c (28) is the value seen in real ILCE-7S/RX100M6 files.
    """
    assert hdr_len >= 2, hdr_len
    return struct.pack(">H", hdr_len) + b"\x00" * (hdr_len - 2) + b"".join(records)


def rat(num: int, denom: int) -> bytes:
    """A single `rational64u` value: u32 numerator + u32 denominator, BE."""
    return struct.pack(">II", num, denom)


def int16s_be(*vals: int) -> bytes:
    """Pack a sequence of signed 16-bit big-endian shorts."""
    return b"".join(struct.pack(">h", v) for v in vals)


def datetime_bcd(year: int, month: int, day: int, hour: int, minute: int, sec: int) -> bytes:
    """0xe304 DateTime payload for the `unpack("x1H4H2H2H2H2H2",$val)` ValueConv.

    H4/H2 read NIBBLES big-endian, so each field is plain BCD: the year is two
    BCD bytes (e.g. 2024 → 0x20 0x24), month/day/hour/min/sec one BCD byte each.
    A single leading pad byte (`x1`) precedes the year. Total = 8 bytes.
    """
    def bcd2(n: int) -> int:
        return ((n // 10) << 4) | (n % 10)

    return bytes(
        [
            0x00,                 # x1 pad
            bcd2(year // 100),    # YYYY high pair (e.g. 20)
            bcd2(year % 100),     # YYYY low pair  (e.g. 24)
            bcd2(month),
            bcd2(day),
            bcd2(hour),
            bcd2(minute),
            bcd2(sec),
        ]
    )


def build_rtmd_mov(samples) -> bytes:
    """Minimal `.mov`: ftyp / mdat(samples) / moov(mvhd + trak[rtmd meta]).

    Identical to `gen_camm_fixture.py:build_camm_mov` except the stsd 4-byte
    format code is `rtmd` (the camm generator uses `camm`); the `meta` handler,
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

    # hdlr: mhlr / meta (the meta_handler the rtmd stsd dispatches through).
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

    # stsd: 1 entry whose 4-byte format code is `rtmd`.
    stsd_entry = struct.pack(">I", 16) + b"rtmd" + b"\x00" * 6 + struct.pack(">H", 1)
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

    # The shared camera record set (records ordered by ascending tag id, as in
    # real files). 0xe304 DateTime encodes 2024:01:07 11:19:15.
    # The 8-byte header the 0xe43b/0xe44b RawConv `substr($val,8)` skips (as a
    # STRING substr on the whole-record int16s rendering — see Sony.pm:10877).
    # `aabbccdd 11223344` decodes to int16s `-21829 -13091 4386 13124`, whose
    # rendered prefix yields the `13091 4386 13124 ` lead after substr(8).
    motion_hdr = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44])

    def camera_records(iso: int):
        return [
            rtmd_record(0x8000, struct.pack(">H", 0xC000)),                 # FNumber → 4.0
            rtmd_record(0x8106, rat(30000, 1001)),                         # FrameRate → 29.97
            rtmd_record(0x8109, rat(1, 60)),                               # ExposureTime → 1/60
            rtmd_record(0x810A, struct.pack(">H", 600)),                   # MasterGainAdjustment → 6.00 dB
            rtmd_record(0x810B, struct.pack(">H", iso)),                   # ISO
            rtmd_record(0x810C, struct.pack(">H", 200)),                   # ElectricalExtenderMagnification → 200
            rtmd_record(0x8114, b"ILCE-7SM3 5072108"),                     # SerialNumber
            rtmd_record(0xE303, struct.pack(">B", 0)),                     # WhiteBalance (raw 0)
            rtmd_record(0xE304, datetime_bcd(2024, 1, 7, 11, 19, 15)),     # DateTime
            rtmd_record(0xE43B, motion_hdr + int16s_be(100, -200, 300)),   # PitchRollYaw
            rtmd_record(0xE44B, motion_hdr + int16s_be(-50, 16384, -1)),   # Accelerometer
        ]

    # Sample 0: camera + a phone-paired GPS fix
    #   47°37'42.3"N, 122°09'54.0"W ; GPSTimeStamp 11:19:15 ; 2024:01:07.
    gps_records = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),                          # GPSVersionID → 2.2.0.0
        rtmd_record(0x8501, b"N"),                                         # GPSLatitudeRef
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),      # GPSLatitude D,M,S
        rtmd_record(0x8503, b"W"),                                         # GPSLongitudeRef
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),     # GPSLongitude D,M,S
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),       # GPSTimeStamp H,M,S
        rtmd_record(0x8509, b"A"),                                         # GPSStatus
        rtmd_record(0x850A, b"3"),                                         # GPSMeasureMode
        rtmd_record(0x8512, b"WGS-84"),                                    # GPSMapDatum
        rtmd_record(0x851D, b"2024:01:07"),                               # GPSDateStamp
    ]

    sample0 = rtmd_sample(camera_records(800) + gps_records)
    sample1 = rtmd_sample(camera_records(1600))

    data = build_rtmd_mov([sample0, sample1])
    path = os.path.join(outdir, "QuickTime_sony_rtmd.mov")
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))

    # ── Fractional-seconds GPSTimeStamp fixture (Codex finding 1) ────────────
    # `0x8507 GPSTimeStamp` has ValueConv=ConvertTimeStamp (stores up to 9
    # fractional digits) and PrintConv=PrintTimeStamp (GPS.pm:480), which ROUNDS
    # the fractional seconds to 6 digits (microseconds) at `-j`. Encode H=1, M=2,
    # S = 3.123456789 (as the rational 3123456789/1000000000) so ConvertTimeStamp
    # emits `01:02:03.123456789` (the `-n` form) and PrintTimeStamp rounds it to
    # `01:02:03.123457` (the `-j` form). One sample, GPS only.
    fract_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),                          # GPSVersionID → 2.2.0.0
        rtmd_record(0x8501, b"N"),                                         # GPSLatitudeRef
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),      # GPSLatitude D,M,S
        rtmd_record(0x8503, b"W"),                                         # GPSLongitudeRef
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),     # GPSLongitude D,M,S
        rtmd_record(0x8507, rat(1, 1) + rat(2, 1) + rat(3123456789, 1000000000)),  # GPSTimeStamp 01:02:03.123456789
        rtmd_record(0x8509, b"A"),                                         # GPSStatus
        rtmd_record(0x850A, b"3"),                                         # GPSMeasureMode
        rtmd_record(0x8512, b"WGS-84"),                                    # GPSMapDatum
        rtmd_record(0x851D, b"2024:01:07"),                               # GPSDateStamp
    ]
    fract_sample = rtmd_sample(camera_records(800) + fract_gps)
    fract_data = build_rtmd_mov([fract_sample])
    fract_path = os.path.join(outdir, "QuickTime_sony_rtmd_fractsec.mov")
    with open(fract_path, "wb") as f:
        f.write(fract_data)
    print("wrote %s (%d bytes)" % (fract_path, len(fract_data)))

    # ── Short-sample timing-Doc fixture (Codex finding 4) ───────────────────
    # `Process_rtmd` `return 0 if $end < 2` (Sony.pm:11614) is SILENT (no
    # warning, no tag), but `ProcessSamples` already opened a `Doc<N>` and
    # emitted that sample's SampleTime/SampleDuration before dispatch. So a
    # `< 2`-byte first sample must surface a TIMING-ONLY `Doc1` (just
    # SampleTime/SampleDuration), and the normal second sample becomes `Doc2`.
    # Sample 0 is a single byte (`< 2`); sample 1 is a full camera record set.
    short_sample = b"\x00"  # 1 byte — under the 2-byte minimum
    normal_sample = rtmd_sample(camera_records(1600))
    short_data = build_rtmd_mov([short_sample, normal_sample])
    short_path = os.path.join(outdir, "QuickTime_sony_rtmd_shortsample.mov")
    with open(short_path, "wb") as f:
        f.write(short_data)
    print("wrote %s (%d bytes)" % (short_path, len(short_data)))

    # ── Zero-denominator FrameRate / ExposureTime fixture (Codex finding 2) ──
    # `0x8106 FrameRate` (PrintConv `sprintf("%.2f",$val)`) and `0x8109
    # ExposureTime` (PrintConv `PrintExposureTime`) read `rational64u`. A zero
    # denominator makes `GetRational64u` return the WORD `"undef"` (0/0) or
    # `"inf"` (n/0) as the ValueConv result. At `-j`: FrameRate numifies that
    # word (`"undef"`→0→`0.00`, `"inf"`→Inf→`"Inf"`), ExposureTime passes it
    # through (`IsFloat` false). At `-n`: both emit the raw `"undef"`/`"inf"`.
    # Sample 0 = 0/0 pair, sample 1 = n/0 pair, so one fixture pins all four
    # combinations. (Verified empirically vs bundled ExifTool 13.59.)
    zd0 = [
        rtmd_record(0x8106, rat(0, 0)),     # FrameRate 0/0 → -j "0.00", -n "undef"
        rtmd_record(0x8109, rat(0, 0)),     # ExposureTime 0/0 → both "undef"
    ]
    zd1 = [
        rtmd_record(0x8106, rat(30000, 0)),  # FrameRate n/0 → -j "Inf", -n "inf"
        rtmd_record(0x8109, rat(1, 0)),      # ExposureTime n/0 → both "inf"
    ]
    zd_data = build_rtmd_mov([rtmd_sample(zd0), rtmd_sample(zd1)])
    zd_path = os.path.join(outdir, "QuickTime_sony_rtmd_zerodenom.mov")
    with open(zd_path, "wb") as f:
        f.write(zd_data)
    print("wrote %s (%d bytes)" % (zd_path, len(zd_data)))

    # ── Non-decimal-denominator GPSTimeStamp fixture (Codex finding 3) ───────
    # `0x8507 GPSTimeStamp` reads three `rational64u` (H,M,S) THROUGH
    # `GetRational64u` (which `RoundFloat(n/d, 10)`-rounds each) BEFORE
    # `GPS::ConvertTimeStamp`. A non-decimal seconds denominator
    # (1496725904/123456789 = 12.1234799327…) must round to `12.12347993`
    # first, so ConvertTimeStamp emits `12:00:12.12347993` at `-n` (NOT the
    # 11-digit raw quotient). PrintTimeStamp then rounds to microseconds at
    # `-j` → `12:00:12.12348`. (Verified empirically vs bundled ExifTool 13.59.)
    round_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),
        # H=12/1, M=0/1, S=1496725904/123456789 (non-decimal denom).
        rtmd_record(0x8507, rat(12, 1) + rat(0, 1) + rat(1496725904, 123456789)),
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    round_sample = rtmd_sample(camera_records(800) + round_gps)
    round_data = build_rtmd_mov([round_sample])
    round_path = os.path.join(outdir, "QuickTime_sony_rtmd_gpsts_round.mov")
    with open(round_path, "wb") as f:
        f.write(round_data)
    print("wrote %s (%d bytes)" % (round_path, len(round_data)))

    # ── Non-decimal-denominator GPS COORDINATE fixture (Codex finding) ───────
    # `0x8502 GPSLatitude` / `0x8504 GPSLongitude` each read three `rational64u`
    # (D,M,S) THROUGH `GetRational64u` (which `RoundFloat(n/d, 10)`-rounds each
    # component to 10 significant figures) BEFORE `GPS::ToDegrees` sums
    # `D + M/60 + S/3600`. A NON-DECIMAL seconds denominator (e.g. S = 1/3)
    # must be rounded to `0.3333333333` FIRST — so the `-n`/ValueConv coordinate
    # is the bundled `RoundFloat`-derived value, NOT a raw 15-digit f64 divide.
    #   Latitude  D=47/1 M=37/1 S=1/3 → 47 + 37/60 + 0.3333333333/3600
    #                                 → -n 47.6167592592592
    #   Longitude D=122/1 M=9/1 S=2/3 → 122 + 9/60 + 0.6666666667/3600
    #                                 → -n 122.150185185185
    # `GPS::ToDMS` (the `-j`/PrintConv) renders the rounded seconds field as
    # `0.33"` / `0.67"`. (Verified empirically vs bundled ExifTool 13.59.)
    coordround_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        # D=47/1, M=37/1, S=1/3 (non-decimal seconds denom).
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(1, 3)),
        rtmd_record(0x8503, b"W"),
        # D=122/1, M=9/1, S=2/3 (non-decimal seconds denom).
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(2, 3)),
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    coordround_sample = rtmd_sample(camera_records(800) + coordround_gps)
    coordround_data = build_rtmd_mov([coordround_sample])
    coordround_path = os.path.join(outdir, "QuickTime_sony_rtmd_coordround.mov")
    with open(coordround_path, "wb") as f:
        f.write(coordround_data)
    print("wrote %s (%d bytes)" % (coordround_path, len(coordround_data)))

    # ── Zero-denominator GPS COORDINATE fixture (Codex finding) ──────────────
    # When ANY D/M/S component of a coordinate has a ZERO denominator,
    # `GetRational64u` renders the WORD `"inf"` (n/0) or `"undef"` (0/0), and
    # `GPS::ToDegrees` (GPS.pm:585) `return ''` for any `\b(inf|undef)\b`
    # component — so the coordinate carries NO usable value. Bundled ExifTool
    # emits `GPSLatitude` as an EMPTY STRING (`""`, the `ToDegrees` `return ''`),
    # while the committed exifast fix `decode_gps_coordinate → None` DROPS the
    # tag entirely (no bogus Inf/NaN coordinate) — so `GPSLatitude` is the one
    # tag excluded from the byte-exact comparison for this fixture (it pins the
    # coordinate-drop, not the empty-string spelling). The lat ref / longitude /
    # timestamp still surface. Sample carries a latitude with S=423/0 (`inf`) so
    # the latitude drops while GPSLongitude (a normal 122/9/54 fix) survives.
    # (Verified empirically vs bundled ExifTool 13.59.)
    coordzero_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        # D=47/1, M=37/1, S=423/0 → seconds renders "inf" ⇒ coordinate dropped.
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 0)),
        rtmd_record(0x8503, b"W"),
        # Longitude is a normal fix and MUST still surface.
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    coordzero_sample = rtmd_sample(camera_records(800) + coordzero_gps)
    coordzero_data = build_rtmd_mov([coordzero_sample])
    coordzero_path = os.path.join(outdir, "QuickTime_sony_rtmd_coordzero.mov")
    with open(coordzero_path, "wb") as f:
        f.write(coordzero_data)
    print("wrote %s (%d bytes)" % (coordzero_path, len(coordzero_data)))

    # ── Non-finite (n/0) GPSTimeStamp DROP fixture (Codex finding) ────────────
    # `0x8507 GPSTimeStamp` reads three `rational64u` (H,M,S) THROUGH
    # `GetRational64u`. A SECONDS component with a ZERO denominator + non-zero
    # numerator (here S=423/0) renders the WORD `"inf"` (= `f64::INFINITY` when
    # parsed). `GPS::ConvertTimeStamp` has NO inf/undef guard (unlike
    # `GPS::ToDegrees`), so bundled ExifTool numifies the inf component into its
    # `(($h||0)*60+($m||0))*60+($s||0)` arithmetic and emits a BOGUS
    # `"Inf:NaN:…"`-shaped string. The committed exifast fix
    # (`decode_gps_time_stamp` → `None` when any H/M/S is non-finite) DROPS the
    # tag entirely (no bogus value) — consistent with the
    # GPSLatitude/GPSLongitude zero-denominator coordinate drop (the `coordzero`
    # fixture). So `GPSTimeStamp` is the ONE tag excluded from the byte-exact
    # comparison for this fixture (it pins the timestamp DROP, not the bogus
    # `Inf:NaN:…` spelling); a `0/0` `undef` component would instead numify to 0
    # (`($x||0)`) and is NOT dropped. The sample carries a valid lat/lon + the
    # usual camera tags so EVERYTHING ELSE stays byte-exact and only the
    # GPSTimeStamp diverges. (Verified empirically vs bundled ExifTool 13.59.)
    gpsts_inf_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        # A normal latitude fix (47°37'42.3"N) — MUST survive.
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),
        rtmd_record(0x8503, b"W"),
        # A normal longitude fix (122°09'54.0"W) — MUST survive.
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),
        # H=12/1, M=0/1, S=423/0 → seconds renders "inf" ⇒ timestamp dropped.
        rtmd_record(0x8507, rat(12, 1) + rat(0, 1) + rat(423, 0)),
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    gpsts_inf_sample = rtmd_sample(camera_records(800) + gpsts_inf_gps)
    gpsts_inf_data = build_rtmd_mov([gpsts_inf_sample])
    gpsts_inf_path = os.path.join(outdir, "QuickTime_sony_rtmd_gpsts_inf.mov")
    with open(gpsts_inf_path, "wb") as f:
        f.write(gpsts_inf_data)
    print("wrote %s (%d bytes)" % (gpsts_inf_path, len(gpsts_inf_data)))

    # ── Partial (1/2-component) GPS rational fixture (Codex finding) ─────────
    # `0x8502 GPSLatitude` / `0x8504 GPSLongitude` / `0x8507 GPSTimeStamp` are
    # `Format => 'rational64u'` with NO Count, so `ReadValue` derives the
    # component count from the RECORD SIZE (`int($size / 8)`): a 1-component
    # (8-byte) or 2-component (16-byte) record is valid. `GPS::ToDegrees` /
    # `GPS::ConvertTimeStamp` default a missing minute/second to 0. So:
    #   8-byte  GPSLatitude  "12/1"        → 12        ("12 deg 0' 0.00\"" at -j)
    #   16-byte GPSLongitude "122/1 30/1"  → 122.5     ("122 deg 30' 0.00\"")
    #   8-byte  GPSTimeStamp "12/1"        → "12:00:00" (both modes)
    # exifast must decode these partial records identically (the old `< 24`
    # guard dropped them). EVERYTHING is byte-exact (only the structural
    # MetaFormat is excluded). (Verified empirically vs bundled ExifTool 13.59.)
    partialgps_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(12, 1)),                  # 1-component lat → 12
        rtmd_record(0x8503, b"E"),
        rtmd_record(0x8504, rat(122, 1) + rat(30, 1)),    # 2-component lon → 122.5
        rtmd_record(0x8507, rat(12, 1)),                  # 1-component time → 12:00:00
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    partialgps_sample = rtmd_sample(camera_records(800) + partialgps_gps)
    partialgps_data = build_rtmd_mov([partialgps_sample])
    partialgps_path = os.path.join(outdir, "QuickTime_sony_rtmd_partialgps.mov")
    with open(partialgps_path, "wb") as f:
        f.write(partialgps_data)
    print("wrote %s (%d bytes)" % (partialgps_path, len(partialgps_data)))

    # ── Defined-empty string fixture (Codex finding) ─────────────────────────
    # A Sony rtmd `string` record of length >= 1 whose value truncates to empty
    # (a LEADING NUL, `b"\0"`) is a DEFINED EMPTY STRING — `ReadValue` returns
    # `""` and `FoundTag` stores it, so bundled EMITS the tag with an empty
    # value (a ZERO-LENGTH record is the only case bundled omits). exifast used
    # `None` to mean "tag absent" and dropped these; the fix emits them. The
    # PrintConv render of an empty value (verified vs bundled ExifTool 13.59):
    #   SerialNumber / GPSMapDatum / GPSDateStamp (no hash PrintConv): "" at -j AND -n
    #   GPSLatitudeRef / GPSLongitudeRef / GPSStatus / GPSMeasureMode (a bare
    #     inline hash PrintConv with NO OTHER handler): the DEFAULT hash-miss
    #     "Unknown ()" at -j, "" at -n (ExifTool.pm:3633 `"Unknown ($val)"`).
    # TWO samples prove the -G1 first-wins collapse with an EMPTY first-Doc
    # value: sample 0 (Doc1) carries the leading-NUL refs + empty SerialNumber;
    # sample 1 (Doc2) carries the normal values. Under -G1 (doc axis collapsed)
    # Doc1's empty values WIN. A valid latitude keeps the GPS sample present.
    emptystr_gps0 = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"\x00"),                     # leading-NUL lat ref → empty
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),  # valid lat
        rtmd_record(0x8503, b"\x00"),                     # leading-NUL lon ref → empty
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),  # valid lon
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),    # valid time
        rtmd_record(0x8509, b"\x00"),                     # leading-NUL status → empty
        rtmd_record(0x850A, b"\x00"),                     # leading-NUL measure mode → empty
        rtmd_record(0x8512, b"\x00"),                     # leading-NUL map datum → empty
        rtmd_record(0x851D, b"\x00"),                     # leading-NUL date stamp → empty
    ]
    # Sample 0: empty SerialNumber (leading NUL) + the empty GPS refs above.
    emptystr_cam0 = [
        rtmd_record(0x8000, struct.pack(">H", 0xC000)),
        rtmd_record(0x8106, rat(30000, 1001)),
        rtmd_record(0x8109, rat(1, 60)),
        rtmd_record(0x810A, struct.pack(">H", 600)),
        rtmd_record(0x810B, struct.pack(">H", 800)),
        rtmd_record(0x810C, struct.pack(">H", 200)),
        rtmd_record(0x8114, b"\x00"),                     # leading-NUL SerialNumber → empty
        rtmd_record(0xE303, struct.pack(">B", 0)),
        rtmd_record(0xE304, datetime_bcd(2024, 1, 7, 11, 19, 15)),
        rtmd_record(0xE43B, motion_hdr + int16s_be(100, -200, 300)),
        rtmd_record(0xE44B, motion_hdr + int16s_be(-50, 16384, -1)),
    ]
    # Sample 1: a NORMAL record set (proves non-empty strings stay byte-exact
    # AND that Doc1's empty values win the -G1 collapse).
    emptystr_gps1 = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    emptystr_sample0 = rtmd_sample(emptystr_cam0 + emptystr_gps0)
    emptystr_sample1 = rtmd_sample(camera_records(1600) + emptystr_gps1)
    emptystr_data = build_rtmd_mov([emptystr_sample0, emptystr_sample1])
    emptystr_path = os.path.join(outdir, "QuickTime_sony_rtmd_emptystr.mov")
    with open(emptystr_path, "wb") as f:
        f.write(emptystr_data)
    print("wrote %s (%d bytes)" % (emptystr_path, len(emptystr_data)))

    # ── Invalid-UTF8 string fixture (Codex R17) ──────────────────────────────
    # A Sony rtmd `string` record whose pre-NUL bytes are NOT valid UTF-8 is
    # STILL a DEFINED tag: bundled `ReadValue` does not validate UTF-8, and
    # `exiftool` FixUTF8's the value at JSON output (exiftool:3822), substituting
    # ONE ASCII `?` per malformed byte (XMP.pm:2949-2972) in BOTH -j and -n.
    # exifast used `from_utf8(...).ok()?` → None → the tag VANISHED (and a
    # GPS-only malformed string left saw_gps false). The fix routes decode_string
    # through the engine's faithful fix_utf8. One sample, a single 0xff in each
    # of: SerialNumber (raw string → "A?B"), GPSMapDatum (raw string → "WG?S"),
    # GPSLatitudeRef + GPSStatus (inline-hash PrintConv, miss → "Unknown (?)" at
    # -j / "?" at -n). Valid lat/lon keep the GPS sample well-formed.
    badutf8_cam = [
        rtmd_record(0x8000, struct.pack(">H", 0xC000)),   # FNumber (valid)
        rtmd_record(0x8114, b"A\xffB"),                   # SerialNumber 0xff → "A?B"
    ]
    badutf8_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),         # GPSVersionID
        rtmd_record(0x8501, b"\xff"),                     # GPSLatitudeRef 0xff → Unknown (?) / ?
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),  # valid lat
        rtmd_record(0x8503, b"E"),                        # valid lon ref
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),  # valid lon
        rtmd_record(0x8509, b"\xff"),                     # GPSStatus 0xff → Unknown (?) / ?
        rtmd_record(0x8512, b"WG\xffS"),                  # GPSMapDatum 0xff → "WG?S"
    ]
    badutf8_sample = rtmd_sample(badutf8_cam + badutf8_gps)
    badutf8_data = build_rtmd_mov([badutf8_sample])
    badutf8_path = os.path.join(outdir, "QuickTime_sony_rtmd_badutf8.mov")
    with open(badutf8_path, "wb") as f:
        f.write(badutf8_data)
    print("wrote %s (%d bytes)" % (badutf8_path, len(badutf8_data)))

    # ── Non-finite GPS by-position fixture ───────────────────────────────────
    # A PRESENT 0x8502/0x8504 GPSLatitude/GPSLongitude record always yields a
    # DEFINED tag: the decimal (all-finite) OR `""` (`GPS::ToDegrees` GPS.pm:585
    # `return '' if $val =~ /\b(inf|undef)\b/` — for ANY inf/undef component, in
    # ANY of the D/M/S positions). A 0x8507 GPSTimeStamp with an inf component
    # (in ANY H/M/S position) emits the CONSTANT bogus `"Inf:NaN:000000000NaN"`
    # (`GPS::ConvertTimeStamp` has no inf/undef guard). exifast emits ALL of
    # these byte-exact (a present `SonyRtmdCoord::Empty` → `""`; the bogus
    # timestamp constant verbatim), at both `-j` and `-n`.
    #
    # Three samples sweep the positions AND pin the `-G1` first-wins collapse
    # with a DEFINED-EMPTY first value:
    #   Doc1: lat inf@D, lon undef@M, time inf@H  (all present-empty / bogus)
    #   Doc2: lat inf@M, lon inf@S,   time inf@M  (all present-empty / bogus)
    #   Doc3: lat VALID,  lon VALID,  time inf@S  (a real coord pair + bogus ts)
    # Under `-G1` (doc axis collapsed) Doc1's EMPTY GPSLatitude `""` WINS over
    # Doc3's valid `47 deg…` — exactly bundled's first-extracted-wins. Under
    # `-G3:1` each Doc keeps its own value (Doc1 `""`, Doc3 the DMS). The valid
    # Doc3 coordinate also proves an Empty/bogus value never poisons a real fix.
    nonfinite_gps0 = [  # Doc1
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(423, 0) + rat(37, 1) + rat(15, 1)),    # inf@D → ""
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(0, 0) + rat(54, 1)),     # undef@M → ""
        rtmd_record(0x8507, rat(423, 0) + rat(0, 1) + rat(15, 1)),     # inf@H → bogus
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    nonfinite_gps1 = [  # Doc2
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(47, 1) + rat(423, 0) + rat(15, 1)),    # inf@M → ""
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(423, 0)),    # inf@S → ""
        rtmd_record(0x8507, rat(12, 1) + rat(423, 0) + rat(15, 1)),    # inf@M → bogus
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    nonfinite_gps2 = [  # Doc3 — a real coordinate pair + an inf@S timestamp
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),   # VALID → 47.628…
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),   # VALID → 122.165
        rtmd_record(0x8507, rat(12, 1) + rat(0, 1) + rat(423, 0)),     # inf@S → bogus
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    nonfinite_data = build_rtmd_mov([
        rtmd_sample(camera_records(800) + nonfinite_gps0),
        rtmd_sample(camera_records(1600) + nonfinite_gps1),
        rtmd_sample(camera_records(3200) + nonfinite_gps2),
    ])
    nonfinite_path = os.path.join(outdir, "QuickTime_sony_rtmd_nonfinite.mov")
    with open(nonfinite_path, "wb") as f:
        f.write(nonfinite_data)
    print("wrote %s (%d bytes)" % (nonfinite_path, len(nonfinite_data)))

    # ── NON-FINAL zero-length TLV fixture (Codex R12 finding 2) ──────────────
    # `Process_rtmd`'s walker (`while $pos+4 < $end`) processes a NON-FINAL
    # zero-length record (`Size => 0`) — `HandleTag(Size => 0)` is reached and
    # `ReadValue` returns `''` (the `unless ($count) { return '' if … $size < $len }`
    # branch, ExifTool.pm:6297). So a PRESENT zero-length record yields a DEFINED
    # value, NOT a dropped tag (the R9 "0-byte → absent" decision was WRONG for
    # NON-FINAL records). The ONLY case bundled omits is a FINAL bare 4-byte
    # header (`$pos+4 == $end` exits the walk before `HandleTag`).
    #
    # This fixture makes SerialNumber(0x8114), GPSLatitudeRef(0x8501),
    # GPSTimeStamp(0x8507) and GPSLatitude(0x8502) each ZERO-LENGTH and NON-FINAL
    # (every one is followed by further records, so the walker steps past it). The
    # bundled output (verified vs ExifTool 13.59):
    #   SerialNumber  → ""          (a `string`, `ReadValue ''`)
    #   GPSLatitudeRef→ "Unknown ()" at -j / "" at -n (bare-hash PrintConv miss)
    #   GPSTimeStamp  → "00:00:00"  (`ConvertTimeStamp('')` → every `($x||0)`=0)
    #   GPSLatitude   → ""          (`GPS::ToDegrees('')` extracts no $d → "")
    # The surviving GPSLongitude (a normal 122/9/54 fix), the LongitudeRef, the
    # timestamp-independent GPS strings and the full camera record set ALL stay
    # byte-exact, proving a zero-length record renders ONLY its own tag empty.
    # EVERYTHING is byte-exact; only the structural `MetaFormat` is excluded.
    zerolen_gps = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),         # GPSVersionID (valid)
        rtmd_record(0x8501, b""),                          # GPSLatitudeRef ZERO-LEN → ""
        rtmd_record(0x8502, b""),                          # GPSLatitude   ZERO-LEN → ""
        rtmd_record(0x8503, b"W"),                         # GPSLongitudeRef (valid)
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),  # GPSLongitude (valid fix)
        rtmd_record(0x8507, b""),                          # GPSTimeStamp  ZERO-LEN → 00:00:00
        rtmd_record(0x8509, b"A"),                         # GPSStatus (valid)
        rtmd_record(0x850A, b"3"),                         # GPSMeasureMode (valid)
        rtmd_record(0x8512, b"WGS-84"),                    # GPSMapDatum (valid)
        rtmd_record(0x851D, b"2024:01:07"),               # GPSDateStamp (valid)
    ]
    # Camera set with a ZERO-LENGTH SerialNumber (0x8114), non-final (the GPS
    # records follow it). Everything else is the normal camera record set.
    zerolen_cam = [
        rtmd_record(0x8000, struct.pack(">H", 0xC000)),    # FNumber → 4.0
        rtmd_record(0x8106, rat(30000, 1001)),            # FrameRate → 29.97
        rtmd_record(0x8109, rat(1, 60)),                  # ExposureTime → 1/60
        rtmd_record(0x810A, struct.pack(">H", 600)),       # MasterGainAdjustment → 6.00 dB
        rtmd_record(0x810B, struct.pack(">H", 800)),       # ISO
        rtmd_record(0x810C, struct.pack(">H", 200)),       # ElectricalExtenderMagnification
        rtmd_record(0x8114, b""),                          # SerialNumber ZERO-LEN → ""
        rtmd_record(0xE303, struct.pack(">B", 0)),         # WhiteBalance (raw 0)
        rtmd_record(0xE304, datetime_bcd(2024, 1, 7, 11, 19, 15)),  # DateTime
        rtmd_record(0xE43B, motion_hdr + int16s_be(100, -200, 300)),   # PitchRollYaw
        rtmd_record(0xE44B, motion_hdr + int16s_be(-50, 16384, -1)),   # Accelerometer
    ]
    zerolen_sample = rtmd_sample(zerolen_cam + zerolen_gps)
    zerolen_data = build_rtmd_mov([zerolen_sample])
    zerolen_path = os.path.join(outdir, "QuickTime_sony_rtmd_zerolen.mov")
    with open(zerolen_path, "wb") as f:
        f.write(zerolen_data)
    print("wrote %s (%d bytes)" % (zerolen_path, len(zerolen_data)))

    # ── PRESENT-but-sub-width NUMERIC fixture (Codex R12 short-numeric) ───────
    # `Process_rtmd`'s walker (`while $pos+4 < $end`) processes a NON-FINAL
    # numeric record even when its value is SHORTER than the tag's `Format`
    # width, and `ReadValue` returns the EMPTY STRING `''` for such a sub-width
    # (incl. zero-length) value (ExifTool.pm:6297). Each numeric tag's ValueConv
    # then NUMIFIES that `''`, so a PRESENT-but-sub-width record emits a DEFINED
    # value — NOT a dropped tag. The committed exifast fix carries this through a
    # `NumericRead{Valid,EmptyRead}` so the EMISSION renders the ValueConv-of-`''`
    # while the DOMAIN (CaptureSettings) skips the degenerate read.
    #
    # Sample 0 (Doc1) makes EACH numeric record sub-width and NON-FINAL (the
    # camera strings + GPS set follow every one, so the walker steps past it):
    #   0x8000 FNumber (int16u)   1-byte → `''`→0 → 2^(8-0/8192)=256
    #                             → -j 256.0   -n 256
    #   0x8106 FrameRate (rat64u) 4-byte → `''`(ValueConv) → -j 0.00 (sprintf
    #                             "%.2f",'' numifies 0)   -n "" (raw '')
    #   0x8109 ExposureTime(rat64u)4-byte→ `''` → -j "" (PrintExposureTime('')
    #                             passes through)   -n ""
    #   0x810a MasterGain (int16u)1-byte → `''`→0 → /100=0 → -j "0.00 dB"  -n 0
    #   0x810b ISO (int16u)       1-byte → `''` raw (no conv) → -j ""   -n ""
    #   0x810c EEM (int16u)       1-byte → `''` raw (no conv) → -j ""   -n ""
    # (every value byte 0x05 — verified the read is `''`, NOT a partial high
    # byte: a 1-byte FNumber 0xFF/0x10 both render 256.0). The non-numeric camera
    # records (SerialNumber/WhiteBalance/DateTime/PitchRollYaw/Accelerometer) and
    # the full GPS set stay VALID, keeping each sub-width numeric NON-FINAL AND
    # proving a sub-width numeric renders ONLY its own tag degenerate.
    #
    # Sample 1 (Doc2) is the FULL VALID camera + GPS set (ISO 1600): proves valid
    # numeric records stay byte-exact under the same emission. Under `-G1` (doc
    # axis collapsed) Doc1's empty-read numerics WIN (first-extracted); under
    # `-G3:1` each Doc keeps its own values (Doc1 empty-read, Doc2 valid). NO
    # numeric-tag exclusions — every numeric tag is byte-exact; only the
    # structural `MetaFormat` is excluded. (Verified vs bundled ExifTool 13.59.)
    SUBW16 = b"\x05"          # 1 byte for an int16u tag (< 2) → ReadValue ''
    SUBW64 = b"\x05\x06\x07\x08"  # 4 bytes for a rational64u tag (< 8) → ''
    shortnum_cam0 = [
        rtmd_record(0x8000, SUBW16),                      # FNumber   sub-width → 256
        rtmd_record(0x8106, SUBW64),                      # FrameRate sub-width → 0.00 / ""
        rtmd_record(0x8109, SUBW64),                      # ExposureTime sub-width → "" / ""
        rtmd_record(0x810A, SUBW16),                      # MasterGain sub-width → 0.00 dB / 0
        rtmd_record(0x810B, SUBW16),                      # ISO       sub-width → "" / ""
        rtmd_record(0x810C, SUBW16),                      # EEM       sub-width → "" / ""
        rtmd_record(0x8114, b"ILCE-7SM3 5072108"),        # SerialNumber (valid)
        rtmd_record(0xE303, struct.pack(">B", 0)),        # WhiteBalance (valid)
        rtmd_record(0xE304, datetime_bcd(2024, 1, 7, 11, 19, 15)),  # DateTime (valid)
        rtmd_record(0xE43B, motion_hdr + int16s_be(100, -200, 300)),    # PitchRollYaw (valid)
        rtmd_record(0xE44B, motion_hdr + int16s_be(-50, 16384, -1)),    # Accelerometer (valid)
    ]
    shortnum_gps0 = [
        rtmd_record(0x8500, bytes([2, 2, 0, 0])),
        rtmd_record(0x8501, b"N"),
        rtmd_record(0x8502, rat(47, 1) + rat(37, 1) + rat(423, 10)),  # valid lat
        rtmd_record(0x8503, b"W"),
        rtmd_record(0x8504, rat(122, 1) + rat(9, 1) + rat(540, 10)),  # valid lon
        rtmd_record(0x8507, rat(11, 1) + rat(19, 1) + rat(15, 1)),    # valid time
        rtmd_record(0x8509, b"A"),
        rtmd_record(0x850A, b"3"),
        rtmd_record(0x8512, b"WGS-84"),
        rtmd_record(0x851D, b"2024:01:07"),
    ]
    # Sample 1: the FULL valid camera + GPS set (proves valid numerics byte-exact).
    shortnum_sample0 = rtmd_sample(shortnum_cam0 + shortnum_gps0)
    shortnum_sample1 = rtmd_sample(camera_records(1600) + gps_records)
    shortnum_data = build_rtmd_mov([shortnum_sample0, shortnum_sample1])
    shortnum_path = os.path.join(outdir, "QuickTime_sony_rtmd_shortnum.mov")
    with open(shortnum_path, "wb") as f:
        f.write(shortnum_data)
    print("wrote %s (%d bytes)" % (shortnum_path, len(shortnum_data)))

    # ── DEGENERATE WhiteBalance + DateTime fixture (Codex R13 finding 2) ──────
    # A PRESENT-but-degenerate `0xe303 WhiteBalance` / `0xe304 DateTime` record
    # is walker-processed (NON-FINAL) and emits a DEFINED value — NOT a dropped
    # tag. The committed exifast fix carries WhiteBalance through a
    # `NumericRead{Valid,EmptyRead}` (a zero-length record → the PrintConv-of-`''`
    # `"Unknown ()"` at -j / `''` at -n) and reproduces DateTime's PARTIAL
    # `unpack("x1H4H2H2H2H2H2")` output for a short record. Verified byte-exact vs
    # bundled ExifTool 13.59 (each degenerate record made NON-FINAL by trailing
    # valid records, so the walker steps past it):
    #
    # Sample 0 (Doc1):
    #   0xe303 WhiteBalance len 0 → ReadValue '' → -j "Unknown ()"   -n ""
    #   0xe304 DateTime     len 4 → unpack partial → ":: ::"? no: 4-byte value is
    #                       [x1 pad][year hi][year lo][month] → "2024:03: ::"
    #   (both NON-FINAL: a valid SerialNumber + ISO follow.)
    # Sample 1 (Doc2): the FULL VALID camera set (ISO 1600) — proves a valid
    #   WhiteBalance (raw 0 → "Unknown (0)") + full DateTime stay byte-exact.
    #
    # NO exclusions for WhiteBalance / DateTime — both compare byte-exact; only
    # the structural `MetaFormat` would historically be excluded, but R13 also
    # implements `Track<N>:MetaFormat`, so NOTHING is excluded for this fixture.
    DT4 = datetime_bcd(2024, 3, 5, 10, 20, 30)[:4]  # 4-byte partial → "2024:03: ::"
    wbdt_cam0 = [
        rtmd_record(0xE303, b""),                          # WhiteBalance zero-len → "Unknown ()" / ""
        rtmd_record(0xE304, DT4),                          # DateTime 4-byte → "2024:03: ::"
        rtmd_record(0x810B, struct.pack(">H", 800)),       # ISO (valid, keeps WB/DT non-final)
        rtmd_record(0x8114, b"ILCE-7SM3 5072108"),         # SerialNumber (valid)
    ]
    wbdt_sample0 = rtmd_sample(wbdt_cam0)
    wbdt_sample1 = rtmd_sample(camera_records(1600))
    wbdt_data = build_rtmd_mov([wbdt_sample0, wbdt_sample1])
    wbdt_path = os.path.join(outdir, "QuickTime_sony_rtmd_wbdt.mov")
    with open(wbdt_path, "wb") as f:
        f.write(wbdt_data)
    print("wrote %s (%d bytes)" % (wbdt_path, len(wbdt_data)))


if __name__ == "__main__":
    main()
