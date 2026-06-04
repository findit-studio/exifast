#!/usr/bin/env python3
"""Generate minimal standalone-TIFF fixtures for the exifast Exif/GPS port.

The bundled t/images/*.tif fixtures pull IPTC / ICC_Profile / GeoTiff
SubDirectories that are NOT part of the Exif.pm port (separate modules).
So we synthesize minimal TIFFs that exercise ONLY the Exif IFD machinery:

  - Exif.tif  : TIFF header (MM) + IFD0 (camera tags: Make/Model/Software/
                Orientation/X/YResolution/ResolutionUnit/ModifyDate) +
                ExifIFD sub-IFD (FNumber/ExposureTime/ISO/FocalLength/
                ExifVersion/DateTimeOriginal/LensModel/ColorSpace) +
                IFD1 thumbnail (Compression + ThumbnailOffset/Length).
  - ExifGPS.tif : TIFF header (II) + IFD0 (Make/Model) + GPS sub-IFD
                  (GPSVersionID/Lat/Lon + refs/MapDatum/TimeStamp/DateStamp/
                  Altitude/AltitudeRef).

Both are valid standalone TIFFs (file type "TIFF"), file-dispatchable now.
"""
import struct
import sys

# ---- TIFF format codes -----------------------------------------------------
ASCII = 2
SHORT = 3
LONG = 4
RATIONAL = 5
UNDEF = 7
SSHORT = 8
SRATIONAL = 10


class TiffBuilder:
    """Builds a TIFF block in a chosen byte order.

    IFD entries with values > 4 bytes are placed in an out-of-line value
    pool that follows all IFDs. Offsets are patched at finalize().
    """

    def __init__(self, byte_order):
        # byte_order: '<' (II / little) or '>' (MM / big)
        self.bo = byte_order
        self.marker = b'II' if byte_order == '<' else b'MM'

    def _entry(self, tag, fmt, count, value_or_offset):
        return struct.pack(self.bo + 'HHI', tag, fmt, count) + \
            struct.pack(self.bo + 'I', value_or_offset)

    def build(self, ifds):
        """ifds: list of IFD dicts. Each IFD dict:
             { 'entries': [ (tag, fmt, count, payload) ... ],
               'sub': { tag: <index into ifds for the sub-IFD> } }
           payload is either an int (inline scalar, will be packed) OR
           bytes (out-of-line value pool blob).
           'sub' maps a SubIFD-pointer tag to another IFD index — the
           builder fills the pointer's value with that IFD's offset.
           IFD index 0 is IFD0; a 'next' key on an IFD dict gives the
           next-IFD index (for the thumbnail chain).
        """
        # Layout: 8-byte header, then each IFD (count + entries*12 + next),
        # then the out-of-line value pool.
        header_len = 8
        # First pass: compute each IFD's offset.
        ifd_offsets = []
        pos = header_len
        for ifd in ifds:
            ifd_offsets.append(pos)
            n = len(ifd['entries'])
            pos += 2 + 12 * n + 4
        pool_start = pos

        # Build the value pool + record per-(ifd,entry) the offset/inline.
        pool = bytearray()
        # entry_values[ifd_idx][entry_idx] = (value_int, is_offset)
        entry_values = []
        for ifd in ifds:
            ev = []
            for (tag, fmt, count, payload) in ifd['entries']:
                if isinstance(payload, int):
                    # Inline scalar — pack into the size dictated by fmt.
                    ev.append((payload, False))
                else:
                    blob = payload
                    if len(blob) <= 4:
                        # Inline — left-justified in 4 bytes (TIFF stores
                        # the value in the first `size` bytes of the field).
                        padded = blob + b'\x00' * (4 - len(blob))
                        ev.append((struct.unpack(self.bo + 'I', padded)[0],
                                   False))
                    else:
                        off = pool_start + len(pool)
                        pool += blob
                        # word-align the pool (TIFF values are even-aligned).
                        if len(pool) % 2:
                            pool += b'\x00'
                        ev.append((off, True))
            entry_values.append(ev)

        # Assemble.
        out = bytearray()
        out += self.marker
        out += struct.pack(self.bo + 'H', 0x002a)
        out += struct.pack(self.bo + 'I', ifd_offsets[0])

        for ifd_idx, ifd in enumerate(ifds):
            n = len(ifd['entries'])
            out += struct.pack(self.bo + 'H', n)
            for entry_idx, (tag, fmt, count, payload) in \
                    enumerate(ifd['entries']):
                # SubIFD pointer tags: value is the target IFD's offset.
                sub = ifd.get('sub', {})
                if tag in sub:
                    val = ifd_offsets[sub[tag]]
                    out += self._entry(tag, fmt, count, val)
                    continue
                val, is_off = entry_values[ifd_idx][entry_idx]
                if is_off:
                    out += self._entry(tag, fmt, count, val)
                else:
                    # Inline scalar — pack to the format width then 4-pad.
                    if fmt == SHORT:
                        field = struct.pack(self.bo + 'H', val) + b'\x00\x00'
                    elif fmt in (LONG,):
                        field = struct.pack(self.bo + 'I', val)
                    else:
                        # already a 4-byte-packed int (offset or blob inline)
                        field = struct.pack(self.bo + 'I', val)
                    out += struct.pack(self.bo + 'HHI', tag, fmt, count)
                    out += field
            # next-IFD pointer.
            nxt = ifd.get('next')
            out += struct.pack(self.bo + 'I',
                               ifd_offsets[nxt] if nxt is not None else 0)
        out += pool
        return bytes(out)


def rational(bo, num, den):
    return struct.pack(bo + 'II', num, den)


def make_exif_tif():
    """Camera TIFF: IFD0 + ExifIFD + IFD1 thumbnail, big-endian."""
    bo = '>'
    b = TiffBuilder(bo)

    # ExifIFD (index 1) — camera capture tags.
    exif_ifd = {
        'entries': [
            (0x829a, RATIONAL, 1, rational(bo, 1, 160)),   # ExposureTime 1/160
            (0x829d, RATIONAL, 1, rational(bo, 4, 1)),     # FNumber 4.0
            (0x8827, SHORT, 1, 100),                       # ISO 100
            (0x9000, UNDEF, 4, b'0231'),                   # ExifVersion 0231
            (0x9003, ASCII, 20, b'2021:08:14 16:45:09\x00'),  # DateTimeOriginal
            (0x9201, RATIONAL, 1, rational(bo, 7321928, 1000000)),  # ShutterSpeedValue
            (0x9202, RATIONAL, 1, rational(bo, 4, 1)),     # ApertureValue
            (0x920a, RATIONAL, 1, rational(bo, 50, 1)),    # FocalLength 50mm
            (0xa001, SHORT, 1, 1),                         # ColorSpace sRGB
            (0xa402, SHORT, 1, 0),                         # ExposureMode Auto
            (0xa434, ASCII, 18, b'EF50mm f/1.8 STM\x00'),  # LensModel
        ],
    }
    # IFD1 (index 2) — thumbnail.
    ifd1 = {
        'entries': [
            (0x0103, SHORT, 1, 6),                # Compression JPEG (old-style)
            (0x0201, LONG, 1, 0),                 # ThumbnailOffset (dummy)
            (0x0202, LONG, 1, 0),                 # ThumbnailLength 0
        ],
    }
    # IFD0 (index 0) — main image directory.
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 6, b'Canon\x00'),              # Make
            (0x0110, ASCII, 24, b'Canon EOS 5D Mark IV\x00'),  # Model
            (0x0112, SHORT, 1, 1),                         # Orientation
            (0x011a, RATIONAL, 1, rational(bo, 72, 1)),    # XResolution 72
            (0x011b, RATIONAL, 1, rational(bo, 72, 1)),    # YResolution 72
            (0x0128, SHORT, 1, 2),                         # ResolutionUnit inches
            (0x0131, ASCII, 18, b'exifast test 1.0\x00'),  # Software
            (0x0132, ASCII, 20, b'2021:08:14 16:45:09\x00'),  # ModifyDate
            (0x8769, LONG, 1, 0),                          # ExifOffset -> ExifIFD
        ],
        'sub': {0x8769: 1},
        'next': 2,
    }
    return b.build([ifd0, exif_ifd, ifd1])


def make_exif_gps_tif():
    """GPS TIFF: IFD0 + GPS sub-IFD, little-endian."""
    bo = '<'
    b = TiffBuilder(bo)

    def r(n, d):
        return rational(bo, n, d)

    # GPS IFD (index 1).
    # GPSVersionID is 4 int8u bytes "2.3.0.0" => bytes 02 03 00 00 (inline).
    gps_ifd = {
        'entries': [
            (0x0000, 1, 4, bytes([2, 3, 0, 0])),  # GPSVersionID (int8u[4])
            (0x0001, ASCII, 2, b'N\x00'),         # GPSLatitudeRef
            (0x0002, RATIONAL, 3, r(48, 1) + r(51, 1) + r(2934, 100)),  # GPSLatitude 48 51' 29.34"
            (0x0003, ASCII, 2, b'E\x00'),         # GPSLongitudeRef
            (0x0004, RATIONAL, 3, r(2, 1) + r(20, 1) + r(5616, 100)),   # GPSLongitude 2 20' 56.16"
            (0x0005, 1, 1, 0),                    # GPSAltitudeRef Above Sea Level
            (0x0006, RATIONAL, 1, r(3500, 100)),  # GPSAltitude 35 m
            (0x0007, RATIONAL, 3, r(16, 1) + r(45, 1) + r(9, 1)),  # GPSTimeStamp 16:45:09
            (0x0012, ASCII, 6, b'WGS84\x00'),     # GPSMapDatum
            (0x001d, ASCII, 11, b'2021:08:14\x00'),  # GPSDateStamp
        ],
    }
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 6, b'Apple\x00'),     # Make
            (0x0110, ASCII, 10, b'iPhone 12\x00'),  # Model
            (0x8825, LONG, 1, 0),                 # GPSInfo -> GPS IFD
        ],
        'sub': {0x8825: 1},
    }
    return b.build([ifd0, gps_ifd])


def make_exif_multipage_tif():
    """Codex R10/F1 — a multi-page TIFF whose next-IFD chain runs THREE deep:
    IFD0 -> IFD1 -> IFD2. ExifTool's `Multi` trailing-directory scan
    (Exif.pm:7202-7232) is a `for (;;)` loop: after processing a trailing
    directory it re-reads `Get32u($dataPt, $dirEnd)` and, increments the
    directory number (`DirName .= $ifdNum + 1`, Exif.pm:7215-7216), so a
    third linked IFD is processed as IFD2.

    The R10/F1 bug: the exifast walker only returned a non-zero next-IFD
    pointer when `kind == IfdKind::Ifd0`, so after IFD0->IFD1 the chain
    stopped — IFD2 (and any deeper IFD) silently lost ALL its tags. This
    fixture is the regression guard: IFD2 carries a distinctive Software
    string that MUST appear under family-1 group `IFD2`.

    Each IFD carries its own tags so the group-numbering (IFD0/IFD1/IFD2)
    is verifiable per-tag. Big-endian (MM)."""
    bo = '>'
    b = TiffBuilder(bo)

    # IFD2 (index 2) — a third page. Distinctive tags to prove it is walked.
    ifd2 = {
        'entries': [
            (0x0103, SHORT, 1, 1),                         # Compression none
            (0x0131, ASCII, 16, b'exifast IFD2\x00\x00\x00'),  # Software
            (0x0112, SHORT, 1, 8),                         # Orientation 8
        ],
    }
    # IFD1 (index 1) — the thumbnail page; links onward to IFD2.
    ifd1 = {
        'entries': [
            (0x0103, SHORT, 1, 6),                         # Compression JPEG
            (0x0201, LONG, 1, 0),                          # ThumbnailOffset
            (0x0202, LONG, 1, 0),                          # ThumbnailLength
        ],
        'next': 2,
    }
    # IFD0 (index 0) — main image directory; links to IFD1.
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 6, b'Canon\x00'),              # Make
            (0x0110, ASCII, 12, b'Canon EOS R\x00'),       # Model
            (0x0112, SHORT, 1, 1),                         # Orientation
        ],
        'next': 1,
    }
    return b.build([ifd0, ifd1, ifd2])


def make_exif_pagecount_tif():
    """PR #68 (TIFF standalone container) — a two-page TIFF whose IFDs carry
    `SubfileType` (0x00fe) values that trip the bundled `MultiPage` flag and
    the synthesized `File:PageCount` tag (`ExifTool.pm:8756-8757`).

    Bundled `Exif.pm:452-457` `RawConv` for SubfileType:
      if ($val == ($val & 0x02)) {            # $val ∈ {0, 2}
        $$self{PageCount} += 1;
        $$self{MultiPage} = 1 if $val == 2 or $$self{PageCount} > 1;
      }

    IFD0 carries SubfileType=0 (Full-resolution image) → PageCount=1.
    IFD1 carries SubfileType=2 (Single page of multi-page image) → PageCount=2
    AND MultiPage=1 (since `$val == 2`).

    The standalone-TIFF entry (`File:FileType == "TIFF"`) emits
    `File:PageCount = 2`. Embedded TIFF blocks (PNG `eXIf`, JPEG `APP1`)
    suppress the emit per `$$self{TIFF_TYPE} eq 'TIFF'`. Big-endian (MM)."""
    bo = '>'
    b = TiffBuilder(bo)
    # IFD1 (index 1) — the multi-page page; SubfileType=2 (single page of multi-page).
    ifd1 = {
        'entries': [
            (0x00fe, LONG, 1, 2),                          # SubfileType=2 (single page of multi-page)
            (0x0131, ASCII, 16, b'exifast IFD1\x00\x00\x00'),  # Software
            (0x0112, SHORT, 1, 2),                         # Orientation
        ],
    }
    # IFD0 (index 0) — the main image; SubfileType=0 (full-resolution).
    ifd0 = {
        'entries': [
            (0x00fe, LONG, 1, 0),                          # SubfileType=0 (full-resolution)
            (0x010f, ASCII, 6, b'Canon\x00'),              # Make
            (0x0112, SHORT, 1, 1),                         # Orientation
        ],
        'next': 1,
    }
    return b.build([ifd0, ifd1])


def make_exif_manyifd_tif():
    """Codex R11/F1 — a multi-page TIFF whose next-IFD chain runs 66 IFDs
    deep: IFD0 -> IFD1 -> ... -> IFD65. ExifTool's `Multi` trailing-directory
    scan (Exif.pm:7202-7232) is an UNCAPPED `for (;;)` loop — it follows the
    chain until a zero next pointer, an invalid directory, or the reprocess
    guard. It numbers each linked IFD `DirName .= $ifdNum + 1`
    (Exif.pm:7215-7216), so the 66th linked directory is processed as IFD65.

    The R11/F1 bug: the exifast walker capped the traversal at `0..MAX_IFDS`
    (64). Because the cap counted IFD0, the parser emitted at most IFD0..IFD63
    and silently dropped IFD64/IFD65. This fixture is the regression guard —
    IFD64 and IFD65 each carry a distinctive Software string that MUST appear
    under family-1 groups `IFD64` / `IFD65`.

    Every IFD carries its own per-page tags so the group-numbering
    (IFD0..IFD65) is verifiable per-tag. Big-endian (MM)."""
    bo = '>'
    b = TiffBuilder(bo)

    n_ifds = 66
    ifds = []
    for i in range(n_ifds):
        sw = f'exifast IFD{i}'.encode('ascii')
        # ASCII tag value includes the trailing NUL; `count` is its length.
        sw_field = sw + b'\x00'
        entries = [
            (0x0103, SHORT, 1, 1 if i else 6),         # Compression
            (0x0131, ASCII, len(sw_field), sw_field),  # Software — per-page
            (0x0112, SHORT, 1, (i % 8) + 1),           # Orientation — per-page
        ]
        ifd = {'entries': entries}
        if i + 1 < n_ifds:
            ifd['next'] = i + 1
        ifds.append(ifd)
    # IFD0 also carries Make/Model so the head of the chain looks like a
    # real camera directory.
    ifds[0]['entries'] = [
        (0x010f, ASCII, 6, b'Canon\x00'),          # Make
        (0x0110, ASCII, 12, b'Canon EOS R\x00'),   # Model
    ] + ifds[0]['entries']
    return b.build(ifds)


def make_exif_makernote_tif():
    """Camera TIFF whose ExifIFD has a MakerNote (0x927c) tag.

    The MakerNote payload here is a tiny Canon-style IFD blob. The point of
    this fixture is the DEFERRAL: bundled `perl exiftool` parses the vendor
    MakerNote (emitting MakerNotes:* / Canon:* tags), but the exifast Exif
    port CAPTURES the raw bytes and defers vendor parsing to the MakerNotes
    wave. So this fixture's conformance test is `#[ignore]`d and it is
    excluded from the typed-serde parity set (4-surface accept-defer).
    """
    bo = '>'
    b = TiffBuilder(bo)

    # A 16-byte opaque MakerNote blob (NOT a real vendor format — exifast
    # captures it verbatim; bundled treats an unrecognized 0x927c as binary
    # data, which keeps the fixture's bundled output stable).
    maker_blob = bytes(range(0x10))

    exif_ifd = {
        'entries': [
            (0x829d, RATIONAL, 1, rational(bo, 28, 10)),   # FNumber 2.8
            (0x8827, SHORT, 1, 200),                       # ISO 200
            (0x927c, UNDEF, len(maker_blob), maker_blob),  # MakerNote
        ],
    }
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 8, b'PENTAX\x00\x00'),         # Make
            (0x0110, ASCII, 10, b'PENTAX K1\x00'),         # Model
            (0x8769, LONG, 1, 0),                          # ExifOffset -> ExifIFD
        ],
        'sub': {0x8769: 1},
    }
    return b.build([ifd0, exif_ifd])


# ===========================================================================
# Adversarial fixtures — PR #36 Codex R1 (F1/F2/F3 conformance)
# ===========================================================================
# These are hand-laid raw TIFFs (the TiffBuilder above always lays valid
# offsets); each one exercises ONE bad-input edge against bundled ExifTool.


def _raw_entry(bo, tag, fmt, count, val):
    """One 12-byte IFD entry with a literal 4-byte value/offset word."""
    return struct.pack(bo + 'HHI', tag, fmt, count) + \
        struct.pack(bo + 'I', val)


def make_exif_badoffset_low_tif():
    """F1a — an out-of-line value whose offset (4) points into the 8-byte
    TIFF header. ExifTool warns `Suspicious IFD0 offset for Software`
    (value range overlaps the IFD) and drops the tag; the offset is also
    `< 8`. Make/Model are laid validly so the directory itself parses."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    pool_start = 8 + 2 + 3 * 12 + 4
    pool = bytearray()
    make_off = pool_start + len(pool)
    pool += b'Canon\x00'
    if len(pool) % 2:
        pool += b'\x00'
    model_off = pool_start + len(pool)
    pool += b'EOS R5\x00'
    if len(pool) % 2:
        pool += b'\x00'
    out += struct.pack(bo + 'H', 3)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)   # Make (valid)
    out += _raw_entry(bo, 0x0110, ASCII, 7, model_off)  # Model (valid)
    out += _raw_entry(bo, 0x0131, ASCII, 10, 4)         # Software off=4 (<8)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_badoffset_eof_tif():
    """F1b — an out-of-line value whose offset is inside the block but
    `offset + size` runs past EOF. ExifTool warns `Error reading value
    for IFD0 entry 2 … Software` and drops the tag."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    pool_start = 8 + 2 + 3 * 12 + 4  # 50
    pool = bytearray()
    make_off = pool_start + len(pool)
    pool += b'Canon\x00'
    if len(pool) % 2:
        pool += b'\x00'
    model_off = pool_start + len(pool)
    pool += b'EOS R5\x00'
    if len(pool) % 2:
        pool += b'\x00'
    out += struct.pack(bo + 'H', 3)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)   # Make (valid)
    out += _raw_entry(bo, 0x0110, ASCII, 7, model_off)  # Model (valid)
    # File length = 50 + 16 = 66; Software offset 60 (<66) but 60+20=80 > 66.
    out += _raw_entry(bo, 0x0131, ASCII, 20, 60)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_truncated_ifd_tif():
    """F2 — IFD0 declares 5 entries but the file ends after 2. ExifTool
    warns `Bad IFD0 directory` and aborts the WHOLE directory (no partial
    tags). A normal (non-MakerNote) IFD does NOT get the read-what-we-can
    salvage."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    out += struct.pack(bo + 'H', 5)  # claims 5 entries — only 2 follow
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1 << 16)  # Orientation = 1
    out += _raw_entry(bo, 0x0128, SHORT, 1, 2 << 16)  # ResolutionUnit = 2
    # Truncated: no further entries, no next-IFD pointer.
    return bytes(out)


def make_exif_focallength35_tif():
    """F3 — ExifIFD with FocalLengthIn35mmFormat (0xa405) only. The int16u
    PrintConv is `"$val mm"` (NO decimal: `75` → `"75 mm"`), distinct from
    FocalLength (0x920a) `sprintf("%.1f mm")`. No FocalLength tag is
    present so bundled emits no `Composite:FocalLength35efl`."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    exif_off = 8 + 2 + 12 + 4
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8769, LONG, 1, exif_off)  # ExifOffset -> ExifIFD
    out += struct.pack(bo + 'I', 0)
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0xa405, SHORT, 1, 75 << 16)  # FocalLengthIn35mm = 75
    out += struct.pack(bo + 'I', 0)
    return bytes(out)


def make_exif_badformat_entry0_tif():
    """R2/F1 — IFD0 whose FIRST entry (index 0) carries an unrecognized
    format code 99. ExifTool warns `Bad format (99) for IFD0 entry 0`
    (++$warnCount) and, because the bad format is at entry 0 (and the
    Model is not /^ILCE/), `return 0` — the WHOLE directory is aborted,
    NO tags emitted. Faithful to Exif.pm:6464-6477.

    Entry 0 is the bad-format entry; a valid Orientation entry follows it
    to prove it is NEVER reached (the directory aborts at entry 0)."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    out += struct.pack(bo + 'H', 2)  # 2 entries
    # Entry 0: tag 0x0112 (Orientation) with BAD format code 99.
    out += _raw_entry(bo, 0x0112, 99, 1, 1 << 16)
    # Entry 1: a valid Orientation — proves the directory aborted at 0.
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1 << 16)
    out += struct.pack(bo + 'I', 0)  # next-IFD = 0
    return bytes(out)


def make_exif_badformat_ifd1_tif():
    """R3/F1 — IFD0 whose FIRST entry (index 0) carries an unrecognized
    format code 99, AND a valid IFD1 (thumbnail directory) reachable via
    IFD0's next-IFD pointer. ExifTool's `return 0` (Exif.pm:6477) exits
    `ProcessExif` ENTIRELY — before the line-7202 trailing-IFD scan — so
    IFD1's tags must NOT be emitted. Bundled output: only the
    `Bad format (99) for IFD0 entry 0` warning, NO IFD1:* tags.

    Layout: header, IFD0 (1 bad entry) with a NON-zero next-IFD pointer to
    a structurally valid IFD1 carrying a real Orientation tag. A correct
    walker aborts at IFD0 entry 0 and never reads the next-IFD pointer."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    # IFD0: 1 entry, then a next-IFD pointer to IFD1.
    ifd1_off = 8 + 2 + 12 + 4
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x0112, 99, 1, 1 << 16)  # entry 0 — BAD format 99
    out += struct.pack(bo + 'I', ifd1_off)         # next-IFD -> valid IFD1
    # IFD1: a structurally valid thumbnail directory with one real tag.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x0112, SHORT, 1, 6 << 16)  # IFD1 Orientation = 6
    out += struct.pack(bo + 'I', 0)
    return bytes(out)


def make_exif_gps_proctext_tif():
    """R3/F2 — GPS sub-IFD carrying GPSProcessingMethod (0x001b) and
    GPSAreaInformation (0x001c), both `undef`-format with the 8-byte
    `ASCII\\0\\0\\0` character-set prefix. ExifTool's `ConvertExifText`
    RawConv (Exif.pm:5554-5601, wired GPS.pm:299/305) strips the prefix
    and decodes the payload — bundled emits `GPSProcessingMethod` = the
    payload text (e.g. "GPS"), NOT a binary placeholder.

    Layout: header, IFD0 (GPSInfo pointer), GPS IFD, value pool. The two
    text values are out-of-line (size > 4)."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 2 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    # GPSProcessingMethod: "ASCII\0\0\0" + "GPS" (8 + 3 = 11 bytes).
    proc_off = pool_start + len(pool)
    proc_val = b'ASCII\x00\x00\x00' + b'GPS'
    pool += proc_val
    if len(pool) % 2:
        pool += b'\x00'
    # GPSAreaInformation: "ASCII\0\0\0" + "Tokyo" (8 + 5 = 13 bytes).
    area_off = pool_start + len(pool)
    area_val = b'ASCII\x00\x00\x00' + b'Tokyo'
    pool += area_val
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0: GPSInfo pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # GPS IFD: GPSProcessingMethod + GPSAreaInformation (both out-of-line).
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x001b, UNDEF, len(proc_val), proc_off)
    out += _raw_entry(bo, 0x001c, UNDEF, len(area_val), area_off)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_gps_unicode_tif():
    r"""R4/F1 — GPS sub-IFD carrying UTF-16 `UNICODE\0`-prefixed text in a
    BIG-ENDIAN (MM) TIFF, with the payload itself written LITTLE-ENDIAN and
    NO BOM (the MicrosoftPhoto case, Exif.pm:5582-5583). ExifTool's
    `ConvertExifText` calls `Decode($str,'UTF16','Unknown')`, which seeds the
    byte-order guess from `GetByteOrder()` (== MM here) then FLIPS to LE when
    the byte-distribution heuristic (Charset.pm:213-234) shows the high byte
    carries all the variation. Bundled emits:
        GPSProcessingMethod = "MANUAL"   (no-BOM UTF-16LE, heuristic flip)
        GPSAreaInformation  = "Tokyo"    (UTF-16LE with a leading BOM)

    A naive big-endian-only UTF-16 reader would mojibake "MANUAL" — this
    fixture is the regression guard for that bug.

    Layout: MM header, IFD0 (GPSInfo pointer), GPS IFD, value pool. Both
    text values are out-of-line (size > 4)."""
    bo = '>'  # MM / big-endian TIFF
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 2 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    # GPSProcessingMethod: "UNICODE\0" + UTF-16LE "MANUAL\0" (NO BOM). The
    # LE code units inside a big-endian TIFF force the Unknown heuristic to
    # flip — exactly the bug R4/F1 guards.
    proc_off = pool_start + len(pool)
    proc_payload = b''.join(struct.pack('<H', c) for c in b'MANUAL') + b'\x00\x00'
    proc_val = b'UNICODE\x00' + proc_payload
    pool += proc_val
    if len(pool) % 2:
        pool += b'\x00'
    # GPSAreaInformation: "UNICODE\0" + LE BOM + UTF-16LE "Tokyo\0". The BOM
    # pins the order and disables the heuristic (Charset.pm:203-206).
    area_off = pool_start + len(pool)
    area_payload = b'\xff\xfe' + b''.join(struct.pack('<H', c) for c in b'Tokyo') + b'\x00\x00'
    area_val = b'UNICODE\x00' + area_payload
    pool += area_val
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0: GPSInfo pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # GPS IFD: GPSProcessingMethod + GPSAreaInformation (both out-of-line).
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x001b, UNDEF, len(proc_val), proc_off)
    out += _raw_entry(bo, 0x001c, UNDEF, len(area_val), area_off)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_gps_datestamp_tif():
    r"""R7/F1 — GPS sub-IFD carrying GPSDateStamp (0x001d) whose ON-DISK
    format code is `string` (2) but whose bytes use `\0` separators between
    the date fields (`2024\0 05\0 22\0`), the Casio EX-H20G variant noted in
    GPS.pm:312. ExifTool's GPS table sets `Format => 'undef'` (GPS.pm:312), a
    READ-side override applied BEFORE `ReadValue` (Exif.pm:6729-6744): it
    forces the value through `undef` so the interior NULs survive, then the
    RawConv `$val=~s/\0+$//` (GPS.pm:319) drops only the trailing run and
    `ExifDate` (GPS.pm:320) re-separates the 8 digits to `YYYY:MM:DD`.

    Without the override the `string` decode NUL-trims at the FIRST NUL
    (ifd.rs:469-472) to `2024`, collapsing GPSDateStamp to just the year —
    the exact regression this fixture guards. Bundled emits
    `GPS:GPSDateStamp` = "2024:05:22" in BOTH -j and -n (ValueConv, not
    PrintConv). A GPSVersionID is included so the GPS IFD resolves to group
    `GPS:` (family 1) as bundled does.

    Layout: MM header, IFD0 (GPSInfo pointer), GPS IFD (GPSVersionID inline +
    GPSDateStamp out-of-line), value pool."""
    bo = '>'  # MM / big-endian TIFF
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 2 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    # GPSDateStamp: 11 bytes "2024\0 05\0 22\0" with NUL separators (the
    # Casio EX-H20G variant). On-disk format code is `string` (2) — the
    # `Format => 'undef'` override forces the undef re-read.
    date_off = pool_start + len(pool)
    date_val = b'2024\x0005\x0022\x00'  # 11 bytes
    pool += date_val
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0: GPSInfo pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # GPS IFD: GPSVersionID (inline int8u[4]) + GPSDateStamp (string[11],
    # out-of-line). GPSVersionID pins the family-1 group to `GPS:`.
    out += struct.pack(bo + 'H', 2)
    # GPSVersionID int8u[4] = "2 3 0 0", the 4 inline bytes 02 03 00 00 packed
    # into the value word (big-endian => 0x02030000).
    out += struct.pack(bo + 'HHI', 0x0000, 1, 4) + bytes([2, 3, 0, 0])
    out += _raw_entry(bo, 0x001d, ASCII, len(date_val), date_off)  # GPSDateStamp
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_illegal_ifd0_size_tif():
    """R2/F2 — IFD0 whose declared extent leaves only 1 byte after
    `$dirEnd` (so `$bytesFromEnd == 1`, which is `< 4` and not 0/2).
    ExifTool warns `Illegal IFD0 directory size (1 entries)` and aborts
    the directory — NO tags. Faithful to Exif.pm:6393-6398.

    ExifTool reads the IFD from the file via RAF: it Reads the 2-byte
    count, then `Read($buf2, 12*n + 4)` — capped at end-of-file. With
    `n == 1` the directory body is 12 bytes; `$dirEnd = $dirStart + 2 +
    12`. To make `$bytesFromEnd == 1` the file must carry exactly 13
    bytes after the count word: 12 entry bytes + 1 trailing byte (and
    NO room for the 4-byte next-IFD pointer). dirEnd = 8 + 2 + 12 = 22,
    file length = 23."""
    bo = '>'
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    out += struct.pack(bo + 'H', 1)  # 1 entry
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1 << 16)  # Orientation
    out += b'\x00'  # 1 trailing byte (no next-IFD ptr) => bytesFromEnd == 1
    return bytes(out)


def make_exif_illegal_subifd_size_tif():
    """R2/F2 — IFD0 with a GPSInfo pointer to a GPS sub-IFD whose declared
    extent leaves only 3 bytes after `$dirEnd` (`$bytesFromEnd == 3`).
    ExifTool warns `Illegal GPS directory size (1 entries)` and aborts
    the GPS directory. IFD0 itself parses normally (Make emitted).
    Faithful to Exif.pm:6393-6398 reached from the 0x8825 sub-IFD.

    Layout: header, IFD0, Make value pool, GPS IFD LAST + 3 trailing
    bytes — so the GPS IFD's `$dirEnd` is 3 bytes from end-of-file."""
    bo = '<'
    out = bytearray()
    ifd0_off = 8
    ifd0_len = 2 + 2 * 12 + 4
    make_off = ifd0_off + ifd0_len
    make_bytes = b'Apple\x00'
    gps_off = make_off + len(make_bytes)
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    # IFD0.
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)   # Make (valid)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # Make value pool.
    out += make_bytes
    # GPS IFD: 1 entry (LAST in the file). dirEnd = gps_off + 2 + 12.
    # 3 trailing bytes after dirEnd and NO next-IFD pointer => the RAF
    # read yields `$bytesFromEnd == 3`.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x0000, 1, 4, struct.unpack(bo + 'I',
                      bytes([2, 3, 0, 0]))[0])          # GPSVersionID inline
    out += b'\x00\x00\x00'                             # 3 trailing bytes
    return bytes(out)


def make_exif_gps_baddir_tif():
    """R2/F2 — IFD0 with a GPSInfo pointer to an offset PAST end-of-file,
    so the GPS IFD's 2-byte entry count cannot even be read. ExifTool's
    RAF `Seek`/`Read` fails (`$success = 0`) and it warns `Bad GPS
    directory` (Exif.pm:6381). IFD0 itself parses normally (Orientation
    emitted). Faithful to Exif.pm:6342-6381."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1)          # Orientation = 1
    out += _raw_entry(bo, 0x8825, LONG, 1, 9999)        # GPSInfo -> past EOF
    out += struct.pack(bo + 'I', 0)
    return bytes(out)


def make_exif_gps_badoffset_tif():
    """R2/F3 — GPS sub-IFD with a GPSLatitude (0x0002) whose out-of-line
    offset (4) points into the 8-byte TIFF header. ExifTool warns
    `Suspicious GPS offset for GPSLatitude` — the tag name MUST resolve
    against the GPS table, not the Exif/Interop table (0x0002 is
    `InteropVersion` in %Interop::Main). Faithful to Exif.pm:6674 with
    the GPS tag table active for the GPS IFD."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    # IFD0: Make + GPSInfo pointer.
    ifd0_off = 8
    ifd0_len = 2 + 2 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 2 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    make_off = pool_start + len(pool)
    pool += b'Apple\x00'
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0.
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)   # Make (valid)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # GPS IFD.
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x0000, 1, 4, struct.unpack(bo + 'I',
                      bytes([2, 3, 0, 0]))[0])          # GPSVersionID inline
    # GPSLatitude 0x0002 RATIONAL[3] — size 24 > 4, offset 4 (< 8).
    out += _raw_entry(bo, 0x0002, RATIONAL, 3, 4)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_gps_wrongfmt_tif():
    """R8/F1 — IFD0 with a GPSInfo pointer (0x8825) mis-encoded as `string`
    (format code 2) instead of an integer. GPSInfo carries `Flags => 'SubIFD'`
    (Exif.pm:2134), so ExifTool's offset-integrality check fires:
    `Wrong format (string) for IFD0 0x8825 GPSInfo` (Exif.pm:6747-6748) and, in
    default (non-verbose) mode, `next`-skips the entry (Exif.pm:6753) — the GPS
    sub-IFD is NOT walked. IFD0 itself parses normally (Orientation emitted).

    Without the integrality check the port would decode the 4 inline bytes as
    text, `first_u64()` would fail, and the pointer would be dropped SILENTLY —
    a corrupt GPS pointer indistinguishable from no-GPS. The fixture pins the
    warning + skip. A would-be-valid GPS IFD (GPSVersionID) sits at the offset
    the inline bytes encode, so a regression that followed the pointer would
    leak GPS:GPSVersionID into the output. Verified against bundled
    `perl exiftool` 2026-05-22."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 2 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    # IFD0: Orientation + GPSInfo pointer mis-typed as string[4].
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1)          # Orientation = 1
    # GPSInfo 0x8825 as `string` (ASCII=2), count 4 ⇒ 4 inline bytes that
    # ALSO happen to encode `gps_off` (so a regression that followed the
    # pointer would actually reach a valid GPS IFD and leak its tags).
    out += _raw_entry(bo, 0x8825, ASCII, 4, gps_off)    # GPSInfo (wrong fmt)
    out += struct.pack(bo + 'I', 0)
    # GPS IFD at gps_off — never reached when the check is honored.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x0000, 1, 4, struct.unpack(bo + 'I',
                      bytes([2, 3, 0, 0]))[0])          # GPSVersionID inline
    out += struct.pack(bo + 'I', 0)
    return bytes(out)


def make_exif_gps_int32s_tif():
    """R9/F1 — IFD0 with a GPSInfo pointer (0x8825) encoded as `int32s`
    (format code 9, a SIGNED integer) carrying a POSITIVE offset to a valid
    GPS sub-IFD. `%intFormat` (Exif.pm:125-136) lists `int32s => 9`, so the
    SIGNED format passes the offset-integrality gate (Exif.pm:6747) WITHOUT a
    `Wrong format` warning — unlike the `string`-encoded R8 case. ExifTool then
    uses `$val` as `Start => '$val'`; `IsInt` (ExifTool.pm:5943) accepts it and,
    the value being non-negative, the `$subdirStart < 0` check (Exif.pm:7017)
    does NOT fire — the GPS sub-IFD is walked normally. Bundled emits
    `GPS:GPSVersionID` = "2.3.0.0".

    Without R9/F1's fix the port's SubIFD-pointer extraction took ONLY
    `RawValue::U64`; an `int32s` decodes to `RawValue::I64`, `first_u64()`
    returned `None`, and the GPS sub-IFD was SILENTLY dropped — a valid GPS
    pointer indistinguishable from no-GPS. The fixture pins the walk + the
    emitted GPSVersionID. Verified against bundled `perl exiftool` 2026-05-22.

    Layout mirrors `Exif_gps_wrongfmt.tif` (the R8 sibling) — only the GPSInfo
    entry's FORMAT CODE differs (int32s vs string)."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 2 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    # IFD0: Orientation + GPSInfo pointer encoded as int32s[1].
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x0112, SHORT, 1, 1)          # Orientation = 1
    # GPSInfo 0x8825 as `int32s` (format 9), count 1, signed value = gps_off
    # (a small POSITIVE offset, packed as a signed 32-bit int).
    out += struct.pack(bo + 'HHI', 0x8825, 9, 1) + struct.pack(bo + 'i', gps_off)
    out += struct.pack(bo + 'I', 0)
    # GPS IFD at gps_off — reached because the signed pointer is positive.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x0000, 1, 4, struct.unpack(bo + 'I',
                      bytes([2, 3, 0, 0]))[0])          # GPSVersionID inline
    out += struct.pack(bo + 'I', 0)
    return bytes(out)


def make_exif_gps_proctext_wrongfmt_tif():
    r"""Golden-value Contract A (#198 byte-walk class, GPS sibling) — a GPS
    sub-IFD whose GPSProcessingMethod (0x001b) is declared `string`
    (format code 2) instead of `undef` (7), the documented mis-writer
    (the same camera-vendor bug Exif.pm:2499 notes for UserComment).

    UNLIKE UserComment 0x9286, the GPS text tags have NO `Format => 'undef'`
    read-side override (`gps::format_override` covers only GPSDateStamp 0x001d;
    GPS.pm:296/304 give 0x001b/0x001c `Writable => 'undef'` but leave `Format`
    unset). So a `string`-on-disk GPSProcessingMethod is decoded as a STRING:
    ExifTool's `ReadValue` NUL-trims at the first interior NUL and the value
    reaches `ConvertExifText` as ordinary text (port: `RawValue::Text`, NOT
    `RawValue::Bytes`). This is the shape the `GpsConv::ExifText` arm must
    route through `RawValue::val_bytes()` — exercising the #198 reroute on a
    non-`Bytes` shape (mirroring the UserComment 0x9286 sibling fixed in the
    EXIF `Conv::ExifText` arm).

    To stay oracle-matchable AND avoid the `from_utf8_lossy`-vs-FixUTF8 charset
    gap (#200 — observable ONLY on invalid-UTF-8 bytes), the payload is a
    VALID, all-ASCII, NUL-free value: the 8-byte ASCII charset prefix is
    SPACE-padded (`ASCII   `, no NULs — `ConvertExifText`'s `/^(ASCII)?[\0 ]+$/`
    tolerates spaces for NULs, Exif.pm:5570) followed by printable "Manual".
    With no interior NUL the `string` decode keeps the whole value, then
    `ConvertExifText` strips the 8-byte prefix and trims trailing blanks ⇒
    bundled `exiftool 13.59` (`-G1`) emits `GPS:GPSProcessingMethod` = "Manual"
    in BOTH -j and -n. Because the payload is valid ASCII, the FixUTF8 display
    text and the pre-FixUTF8 `raw` bytes are byte-identical here, so the output
    matches the oracle exactly while the reroute itself is what carries the
    `Text`-shape bytes into `convert_exif_text`.

    Layout: II header, IFD0 (GPSInfo pointer), GPS IFD (one out-of-line
    GPSProcessingMethod), value pool."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 1 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    # GPSProcessingMethod: space-padded "ASCII   " prefix (8 bytes, NO NULs)
    # + "Manual" (no interior NUL ⇒ the `string` decode keeps it all).
    proc_off = pool_start + len(pool)
    proc_val = b'ASCII   ' + b'Manual'
    pool += proc_val
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0: GPSInfo pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    # GPS IFD: GPSProcessingMethod declared `string` (ASCII=2), out-of-line.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x001b, ASCII, len(proc_val), proc_off)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_gps_eofoverrun_tif():
    """R2/F3 — GPS sub-IFD with a GPSLatitude (0x0002) whose out-of-line
    offset is inside the block but `offset + size` runs past EOF.
    ExifTool warns `Error reading value for GPS entry 1, ID 0x0002
    GPSLatitude` — the tag name MUST resolve against the GPS table
    (0x0002 = GPSLatitude, not InteropVersion). Faithful to
    Exif.pm:6594-6598 with the GPS tag table active."""
    bo = '<'
    out = bytearray()
    out += b'II' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 2 * 12 + 4
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 2 * 12 + 4
    pool_start = gps_off + gps_len
    pool = bytearray()
    make_off = pool_start + len(pool)
    pool += b'Apple\x00'
    if len(pool) % 2:
        pool += b'\x00'
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)   # Make (valid)
    out += _raw_entry(bo, 0x8825, LONG, 1, gps_off)     # GPSInfo -> GPS IFD
    out += struct.pack(bo + 'I', 0)
    out += struct.pack(bo + 'H', 2)
    out += _raw_entry(bo, 0x0000, 1, 4, struct.unpack(bo + 'I',
                      bytes([2, 3, 0, 0]))[0])          # GPSVersionID inline
    # GPSLatitude 0x0002 RATIONAL[3] — size 24. File length = pool_start+6.
    # Offset = pool_start (inside block) but pool_start+24 overruns EOF.
    out += _raw_entry(bo, 0x0002, RATIONAL, 3, pool_start)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_eofoverrun_chain_tif():
    """Codex R14/F1 — IFD0 whose entry 1 is an out-of-line value (Software)
    that overruns EOF, with a VALID entry 2 (Orientation) AFTER it AND a
    NON-zero next-IFD pointer to a structurally valid IFD1 (thumbnail).

    A standalone TIFF processed from a file ALWAYS carries a RAF
    (`DoProcessTIFF` sets `RAF => $raf`, ExifTool.pm:8717; `ProcessExif`
    reads `$raf = $$dirInfo{RAF}`, Exif.pm:6289), so the out-of-line read
    takes the `if ($raf)` path (Exif.pm:6552). The value extends past EOF,
    so `$raf->Read($buff,$size) != $size` (Exif.pm:6593) fails: ExifTool
    warns `Error reading value for IFD0 entry 1, ID 0x0131 Software`
    (Exif.pm:6594) and then `return 0 unless $inMakerNotes or $htmlDump or
    $truncOK` (Exif.pm:6602) — it ABORTS the WHOLE directory. That `return 0`
    exits `ProcessExif` BEFORE the line-7202 `Multi` trailing-IFD scan, so
    the chain is never followed.

    Bundled emits ONLY `IFD0:Make` (entry 0, BEFORE the bad entry) + the
    `Error reading value` warning; `IFD0:Orientation` (entry 2, AFTER the
    bad entry) AND every IFD1 tag are SUPPRESSED. Verified against bundled
    `perl exiftool` 2026-05-22.

    The R14/F1 bug: the pre-fix walker recorded the `Error reading value`
    warning but returned `true` (continue), so `walk_entries` went on to
    emit `IFD0:Orientation` and `walk_one_ifd_body` followed the next-IFD
    pointer to emit IFD1:* — tags the oracle suppresses. This fixture pins
    the abort: it carries BOTH a later valid same-IFD entry and a trailing
    IFD, so a regression on either the entry-loop continue OR the next-IFD
    follow re-surfaces a tag.

    Layout (big-endian, MM): header, IFD0 (3 entries + next-IFD ptr -> IFD1),
    Make value pool, IFD1 (Software out-of-line + Orientation inline) + its
    Software pool. The IFD0 Software offset is `eof - 4` with size 40, so it
    is INSIDE the block but `offset + size` runs well past EOF."""
    bo = '>'  # MM / big-endian
    out = bytearray()
    out += b'MM' + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 3 * 12 + 4
    pool_start = ifd0_off + ifd0_len
    make_bytes = b'Canon\x00'
    make_off = pool_start
    pool = bytearray(make_bytes)
    if len(pool) % 2:
        pool += b'\x00'
    ifd1_off = pool_start + len(pool)
    # Build IFD1 (out-of-line Software + inline Orientation) to know the EOF.
    ifd1 = bytearray()
    ifd1 += struct.pack(bo + 'H', 2)
    sw = b'exifast IFD1 thumb\x00'
    ifd1_dir_len = 2 + 2 * 12 + 4
    sw_off = ifd1_off + ifd1_dir_len
    ifd1 += _raw_entry(bo, 0x0131, ASCII, len(sw), sw_off)  # IFD1 Software
    ifd1 += _raw_entry(bo, 0x0112, SHORT, 1, 7 << 16)       # IFD1 Orientation=7
    ifd1 += struct.pack(bo + 'I', 0)                        # next=0
    ifd1 += sw
    eof = ifd1_off + len(ifd1)
    # IFD0 Software (entry 1): offset INSIDE the block (eof-4) but size 40 so
    # `offset + size` overruns EOF -> the RAF read fails -> directory abort.
    sw0_off = eof - 4
    sw0_size = 40
    out += struct.pack(bo + 'H', 3)
    out += _raw_entry(bo, 0x010f, ASCII, 6, make_off)       # Make (valid) idx0
    out += _raw_entry(bo, 0x0131, ASCII, sw0_size, sw0_off)  # Software overrun idx1
    out += _raw_entry(bo, 0x0112, SHORT, 1, 5 << 16)        # Orientation=5 idx2
    out += struct.pack(bo + 'I', ifd1_off)                  # next-IFD -> IFD1
    out += pool
    out += ifd1
    assert len(out) == eof
    return bytes(out)


# ===========================================================================
# UserComment (0x9286) — PR #36 Codex R5 F1 (ConvertExifText for ExifIFD)
# ===========================================================================
# UserComment is `Format => 'undef'` with `RawConv =>
# ConvertExifText($self,$val,1,$tag)` (Exif.pm:2497-2507) — the SAME RawConv
# the GPS text tags use, but in the ExifIFD and WITHOUT the `gps` feature.
# These fixtures pin that the prefix is stripped + the payload decoded (ASCII
# / UTF-16 'Unknown' order / BOM), not emitted as a binary placeholder.


def _usercomment_tif(byte_order_marker, comment_val, fmt=UNDEF):
    """A TIFF (IFD0 -> ExifIFD) whose ExifIFD carries a single out-of-line
    UserComment (0x9286). `byte_order_marker` is b'II'/b'MM'; `comment_val`
    is the full value (8-byte charset prefix + payload); `fmt` is the on-disk
    TIFF format code written into the entry (UNDEF for a correct writer, or
    ASCII(2)/int8u(1) for the documented mis-writers, Exif.pm:2499).

    NOTE the format-code width is 1 byte/element for ALL of UNDEF/ASCII/int8u,
    so the entry's `count` field equals `len(comment_val)` in every case — only
    the format CODE differs. ExifTool's `Format => 'undef'` (Exif.pm:2500) is a
    read-side override that forces the value through `undef` regardless."""
    bo = '<' if byte_order_marker == b'II' else '>'
    out = bytearray()
    out += byte_order_marker + struct.pack(bo + 'H', 0x002a) + \
        struct.pack(bo + 'I', 8)
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    exif_off = ifd0_off + ifd0_len
    exif_len = 2 + 1 * 12 + 4
    pool_start = exif_off + exif_len
    pool = bytearray()
    uc_off = pool_start + len(pool)
    pool += comment_val
    if len(pool) % 2:
        pool += b'\x00'
    # IFD0: ExifOffset pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8769, LONG, 1, exif_off)    # ExifOffset -> ExifIFD
    out += struct.pack(bo + 'I', 0)
    # ExifIFD: UserComment (out-of-line; on-disk format = `fmt`).
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x9286, fmt, len(comment_val), uc_off)
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_usercomment_ascii_tif():
    r"""R5/F1 — ExifIFD UserComment with the 8-byte `ASCII\0\0\0` charset
    prefix in a little-endian (II) TIFF. ExifTool's `ConvertExifText`
    (Exif.pm:5554-5601) strips the prefix and truncates at the first NUL —
    bundled emits `ExifIFD:UserComment` = "Hello World", NOT a binary
    placeholder (the bug R5/F1 guards: 0x9286 was wired `Conv::None`)."""
    return _usercomment_tif(b'II', b'ASCII\x00\x00\x00' + b'Hello World\x00')


def make_exif_usercomment_unicode_tif():
    r"""R5/F1 — ExifIFD UserComment with the `UNICODE\0` prefix and a
    UTF-16LE payload (NO BOM) inside a BIG-ENDIAN (MM) TIFF — the
    MicrosoftPhoto case (Exif.pm:5582-5583). `ConvertExifText` calls
    `Decode($str,'UTF16','Unknown')`, which seeds the order from
    `GetByteOrder()` (MM) then FLIPS to LE via the Charset.pm:213-234
    distribution heuristic. Bundled emits `ExifIFD:UserComment` = "MANUAL";
    a big-endian-only UTF-16 reader would mojibake it. Proves the order is
    threaded to the ExifIFD UserComment, not just the GPS text tags."""
    payload = b''.join(struct.pack('<H', c) for c in b'MANUAL') + b'\x00\x00'
    return _usercomment_tif(b'MM', b'UNICODE\x00' + payload)


def make_exif_usercomment_bom_tif():
    r"""R5/F1 — ExifIFD UserComment with the `UNICODE\0` prefix and a
    UTF-16LE payload that begins with a little-endian BOM, inside a
    BIG-ENDIAN (MM) TIFF. The BOM pins the order and DISABLES the heuristic
    (Charset.pm:203-206), so `ConvertExifText` decodes LE regardless of the
    MM TIFF order — bundled emits `ExifIFD:UserComment` = "Tokyo"."""
    payload = b'\xff\xfe' + \
        b''.join(struct.pack('<H', c) for c in b'Tokyo') + b'\x00\x00'
    return _usercomment_tif(b'MM', b'UNICODE\x00' + payload)


def make_exif_usercomment_string_tif():
    r"""R6/F1 — ExifIFD UserComment (0x9286) whose ON-DISK format code is
    `string` (2) instead of `undef` (7) — the documented mis-writer
    (Exif.pm:2499 "I have seen other applications write it incorrectly as
    'string' or 'int8u'"). The value is the standard 8-byte `ASCII\0\0\0`
    charset prefix + "Hello World".

    ExifTool's `Format => 'undef'` (Exif.pm:2500) is a READ-side override
    applied BEFORE `ReadValue` (Exif.pm:6729-6744): it forces the value
    through `undef`, so `ReadValue` does NOT NUL-trim at the prefix's interior
    NULs. `ConvertExifText` then strips the 8-byte prefix ⇒ bundled emits
    `ExifIFD:UserComment` = "Hello World". WITHOUT the override the `string`
    decode trims `ASCII\0\0\0Hello World` at the first NUL to "ASCII" and the
    payload is lost — exactly the R6/F1 bug. Big-endian (MM) per R6/F1."""
    return _usercomment_tif(
        b'MM', b'ASCII\x00\x00\x00' + b'Hello World', fmt=ASCII)


def make_exif_usercomment_int8u_tif():
    r"""R6/F1 — ExifIFD UserComment (0x9286) whose ON-DISK format code is
    `int8u` (1) instead of `undef` (7) — the OTHER documented mis-writer
    (Exif.pm:2499). Same `ASCII\0\0\0Hello World` value. The `Format =>
    'undef'` read-side override (Exif.pm:6729-6744) forces it through `undef`
    ⇒ bundled emits `ExifIFD:UserComment` = "Hello World" (NOT a comma-joined
    int8u array, and NOT a NUL-truncated "ASCII"). Big-endian (MM)."""
    return _usercomment_tif(
        b'MM', b'ASCII\x00\x00\x00' + b'Hello World', fmt=1)


def make_exif_trailing_space_tif():
    r"""Codex R15/F1 — space-padded EXIF `string` fields, the normal way a
    camera/encoder fills a fixed-width or "unknown" ASCII field (EXIF spec).

    Two distinct trailing-trim conversions are exercised:

    IFD0 string tags carry a trailing-WHITESPACE `RawConv => '$val=~s/\s+$//'`
    (Exif.pm:585 Make, 599 Model, 906 Software, 925 Artist) — strips EVERY
    trailing whitespace char (`\s` = space/tab/NL/CR/FF/VT). A RawConv runs at
    the raw stage, so the trim shows in BOTH `-j` and `-n`:
      - Make    "Canon   "  -> "Canon"   (trailing spaces)
      - Model   "EOS R5\t " -> "EOS R5"  (trailing TAB + space — \s strips both)
      - Software "FW v2.0 "  -> "FW v2.0"
      - Artist  "Jane Doe  " -> "Jane Doe"

    ExifIFD SubSecTime* tags carry a trailing-SPACE `ValueConv => '$val=~s/ +$//'`
    (Exif.pm:2543/2552/2560) — trims trailing SPACES ONLY (not `\s`); a
    ValueConv result is what `-n` shows and the identity PrintConv carries it
    through in `-j`:
      - SubSecTime          "123  " -> "123"  (-> JSON number 123)
      - SubSecTimeOriginal  "45   " -> "45"
      - SubSecTimeDigitized "70  "  -> "70"   (-> JSON number 70)

    (The spaces-only-vs-`\s` distinction for SubSecTime* — a trailing TAB is
    NOT trimmed by `s/ +$//` — is pinned by a `src/exif` unit test rather than
    a fixture, because an embedded TAB byte trips an inline-value bounds check
    in this minimal-TIFF layout.)

    Little-endian (II)."""
    bo = '<'
    b = TiffBuilder(bo)

    exif_ifd = {
        'entries': [
            # DateTimeOriginal so the IFD looks like a real capture record.
            (0x9003, ASCII, 20, b'2021:08:14 16:45:09\x00'),
            (0x9290, ASCII, 6, b'123  \x00'),    # SubSecTime "123  " -> "123"
            (0x9291, ASCII, 6, b'45   \x00'),    # SubSecTimeOriginal -> "45"
            (0x9292, ASCII, 5, b'70  \x00'),     # SubSecTimeDigitized -> "70"
        ],
    }
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 9, b'Canon   \x00'),          # Make -> "Canon"
            # Model "EOS R5\t " — trailing TAB+space, \s strips both -> "EOS R5".
            (0x0110, ASCII, 9, b'EOS R5\t \x00'),
            (0x0131, ASCII, 9, b'FW v2.0 \x00'),          # Software -> "FW v2.0"
            (0x013b, ASCII, 11, b'Jane Doe  \x00'),       # Artist -> "Jane Doe"
            (0x8769, LONG, 1, 0),                          # ExifOffset -> ExifIFD
        ],
        'sub': {0x8769: 1},
    }
    return b.build([ifd0, exif_ifd])


def make_exif_ifd65536_tif():
    """Codex R12/F1 — a multi-page TIFF whose next-IFD chain runs 65537 IFDs
    deep: IFD0 -> IFD1 -> ... -> IFD65536. ExifTool's `Multi` trailing-
    directory scan (Exif.pm:7202-7232) numbers each linked IFD with plain
    Perl arithmetic `DirName .= $ifdNum + 1` (Exif.pm:7215-7216) — there is
    NO cap, so the 65537th linked directory is processed as IFD65536 and its
    tags carry family-1 group `IFD65536`.

    The R12/F1 bug: the exifast walker stored the trailing-IFD number in a
    `u16` and advanced it with `saturating_add`, so past IFD65535 it pinned
    at 65535 — IFD65536 (and any deeper IFD) was mislabeled `IFD65535`,
    overwriting the real IFD65535 tags. This fixture is the regression
    guard: IFD65535 and IFD65536 each carry a distinctive Software string
    that MUST appear under DISTINCT family-1 groups `IFD65535` / `IFD65536`.

    To keep the fixture (and its golden) small, ONLY the head (IFD0) and
    the tail (IFD65534/65535/65536) carry leaf tags; every interior IFD is a
    valid ZERO-ENTRY directory (a 2-byte count of 0 + the 4-byte next
    pointer). A zero-entry IFD still advances the chain — verified against
    bundled `perl exiftool` — so the chain length alone drives the
    numbering. Big-endian (MM)."""
    bo = '>'
    b = TiffBuilder(bo)

    n_ifds = 65537  # IFD0 .. IFD65536
    tail = {65534, 65535, 65536}
    ifds = []
    for i in range(n_ifds):
        if i == 0:
            # IFD0 — Make/Model + Compression so the head is a real dir.
            entries = [
                (0x010f, ASCII, 6, b'Canon\x00'),          # Make
                (0x0110, ASCII, 12, b'Canon EOS R\x00'),   # Model
                (0x0103, SHORT, 1, 6),                     # Compression
            ]
        elif i in tail:
            sw = f'exifast IFD{i}'.encode('ascii')
            sw_field = sw + b'\x00'
            entries = [
                (0x0103, SHORT, 1, 1),                     # Compression
                (0x0131, ASCII, len(sw_field), sw_field),  # Software
                (0x0112, SHORT, 1, (i % 8) + 1),           # Orientation
            ]
        else:
            entries = []  # interior IFD — zero entries, just chains onward
        ifd = {'entries': entries}
        if i + 1 < n_ifds:
            ifd['next'] = i + 1
        ifds.append(ifd)
    return b.build(ifds)


def make_exif_gps_after_interop_tif():
    """Codex R12/F2 — the Windows Phone 7.5 InteropIFD/GPS pointer-collision
    case. ExifTool's `ProcessDirectory` reprocess guard (ExifTool.pm:9050-
    9061) warns `"$dirName pointer references previous $prev directory"` on a
    duplicate directory address, then `return 0 unless $dirName eq 'GPS' and
    $prev eq 'InteropIFD'` — abort EXCEPT for the one case where a GPS
    pointer is mis-written to an already-processed InteropIFD offset (a
    Windows Phone 7.5 O/S bug), where it CONTINUES and reprocesses as GPS.
    The whole guard block is moreover gated on `$$dirInfo{DirLen}` being
    non-zero (ExifTool.pm:9052); an IFD-pointer SubDirectory carries
    `DirLen => 0`, so the guard never even fires — ExifTool just reprocesses
    the shared offset.

    Layout (little-endian, II):
      - IFD0: Make + ExifOffset(0x8769) + GPSInfo(0x8825). The GPSInfo
        pointer targets the SAME offset as the InteropIFD below.
      - ExifIFD: ISO + InteropOffset(0xa005) -> the shared sub-IFD.
      - shared sub-IFD: a valid GPS IFD. Walked FIRST as InteropIFD (via
        0xa005, processed before IFD0's 0x8825 since 0x8769 < 0x8825), then
        a SECOND time as GPS (via 0x8825).

    The shared directory deliberately carries ONLY GPS tag IDs that are
    NOT in the (tiny) %InteropIFD table — GPSVersionID (0x0000),
    GPSSatellites (0x0008), GPSMapDatum (0x0012) — so the InteropIFD pass
    resolves NO leaf tags (every ID is unknown there ⇒ verbose-only ⇒
    dropped) while the GPS pass emits all three. This keeps the fixture
    focused on the reprocess itself: no InteropIFD-PrintConv or Composite-
    GPS divergences (both separate ExifTool layers) muddy the golden.

    The R12/F2 bug: the exifast walker rejected ANY previously seen IFD
    offset, so the GPS pass returned `None` and ALL GPS tags were silently
    dropped — the Perl oracle still emits them. This fixture pins the
    GPS:* tags from the reprocess. Verified against bundled `perl exiftool`
    2026-05-22."""
    bo = '<'
    b = TiffBuilder(bo)

    # The shared sub-IFD — a valid GPS directory. Reached twice: once as
    # InteropIFD (via ExifIFD 0xa005) and once as GPS (via IFD0 0x8825).
    # All three tag IDs are GPS-table tags absent from %InteropIFD.
    shared = {
        'entries': [
            # GPSVersionID 0x0000 — int8u[4] = 2.3.0.0 (inline).
            (0x0000, 1, 4, b'\x02\x03\x00\x00'),
            (0x0008, ASCII, 9, b'GPS L1L2\x00'),           # GPSSatellites
            (0x0012, ASCII, 7, b'WGS-84\x00'),             # GPSMapDatum
        ],
    }
    # ExifIFD — ISO + InteropOffset pointing at the shared sub-IFD. The
    # pointer tag must appear in `entries`; `sub` patches its value word.
    exif_ifd = {
        'entries': [
            (0x8827, SHORT, 1, 100),                       # ISO
            (0xa005, LONG, 1, 0),                          # InteropOffset
        ],
        'sub': {0xa005: 2},
    }
    # IFD0 — Make + ExifOffset + GPSInfo (GPSInfo also points at `shared`).
    # Entries are emitted in tag-id order: 0x8769 (ExifOffset) is processed
    # BEFORE 0x8825 (GPSInfo), so the shared dir is walked as InteropIFD
    # first (via ExifIFD 0xa005) and as GPS second.
    ifd0 = {
        'entries': [
            (0x010f, ASCII, 6, b'Apple\x00'),              # Make
            (0x8769, LONG, 1, 0),                          # ExifOffset
            (0x8825, LONG, 1, 0),                          # GPSInfo
        ],
        'sub': {0x8769: 1, 0x8825: 2},
    }
    return b.build([ifd0, exif_ifd, shared])


def make_exif_gps_shared_pointer_tif():
    """Codex R13/F1 — IFD0's ExifOffset (0x8769) AND GPSInfo (0x8825)
    pointing at ONE shared sub-IFD. This is the general form of the
    pointer-collision the R12/F2 carve-out only handled for GPS-after-
    InteropIFD.

    ExifTool's `ProcessDirectory` reprocess guard (ExifTool.pm:9050-9061)
    warns + aborts on a duplicate directory address — but the whole guard
    block is GATED on `$$dirInfo{DirLen}` being non-zero (ExifTool.pm:9052,
    comment "directories don't overlap if the length is zero"). For a
    standalone TIFF — every exifast `TIFF` fixture, and the shape the golden
    oracle runs ExifTool against — an IFD-pointer SubDirectory's `DirLen` is
    forced to 0 at Exif.pm:7020-7026: the value-data buffer holds only the
    IFD being parsed, so the out-of-buffer `$subdirStart` trips
    `$subdirStart + 2 > $subdirDataLen` and ExifTool resets
    `$subdirDataPt`/`$size` to re-read the directory from the file. With
    `DirLen 0` the guard is SKIPPED for EVERY IFD-pointer subdirectory, so
    ExifTool reprocesses ANY shared subdirectory offset — not just the
    GPS-after-InteropIFD Windows Phone 7.5 carve-out (ExifTool.pm:9059),
    which is just one instance of the general rule.

    Layout (little-endian, II):
      - IFD0: Orientation(0x0112) + ExifOffset(0x8769) + GPSInfo(0x8825).
        ExifOffset and GPSInfo BOTH point at the shared sub-IFD.
      - shared sub-IFD: Orientation(0x0112) — an Exif-table tag — plus
        GPSVersionID(0x0000) — a GPS-table tag. Walked FIRST as ExifIFD
        (via 0x8769, processed before 0x8825 since 0x8769 < 0x8825), then
        a SECOND time as GPS (via 0x8825).

    The shared directory carries one tag resolvable in EACH pass: as the
    ExifIFD it emits `ExifIFD:Orientation` (0x0112 is an Exif-IFD tag), as
    the GPS IFD it emits `GPS:GPSVersionID` (0x0000 is a GPS tag); the
    cross-table tag in each pass is simply unknown there ⇒ verbose-only ⇒
    dropped. No PrintConv/Composite layers muddy the golden.

    The R13/F1 bug: the R12/F2 carve-out admitted ONLY a GPS-after-
    InteropIFD revisit, so the GPS pass over an ExifIFD-owned offset
    returned `None` and ALL GPS tags were silently dropped — the Perl
    oracle still emits `GPS:GPSVersionID`. This fixture pins both groups.
    Verified against bundled `perl exiftool` 2026-05-22:
    `ExifIFD:Orientation` AND `GPS:GPSVersionID` both emit, no warning."""
    bo = '<'
    b = TiffBuilder(bo)

    # The shared sub-IFD — walked once as ExifIFD (via 0x8769) and once as
    # GPS (via 0x8825). One tag resolves in each pass.
    shared = {
        'entries': [
            # Orientation 0x0112 — an Exif-IFD tag; resolves on the ExifIFD
            # pass, unknown on the GPS pass.
            (0x0112, SHORT, 1, 7),
            # GPSVersionID 0x0000 — a GPS tag; resolves on the GPS pass,
            # unknown on the ExifIFD pass. int8u[4] = 2.3.0.0 (inline).
            (0x0000, 1, 4, b'\x02\x03\x00\x00'),
        ],
    }
    # IFD0 — Orientation + ExifOffset + GPSInfo. ExifOffset and GPSInfo
    # BOTH target the shared sub-IFD (index 1). Entries are emitted in
    # tag-id order: 0x8769 (ExifOffset) before 0x8825 (GPSInfo), so the
    # shared dir is walked as ExifIFD first and GPS second.
    ifd0 = {
        'entries': [
            (0x0112, SHORT, 1, 1),                         # Orientation
            (0x8769, LONG, 1, 0),                          # ExifOffset
            (0x8825, LONG, 1, 0),                          # GPSInfo
        ],
        'sub': {0x8769: 1, 0x8825: 1},
    }
    return b.build([ifd0, shared])


def make_jpeg_unknown_header():
    """Codex R18/F2 — a valid JPEG preceded by a 4-byte unknown header.

    A recoverable / edited JPEG can carry junk before the SOI marker. The
    file-type detector's terminal candidate (ExifTool.pm:3026-3034) scans
    PAST the unknown `$skip`-byte header for `\\xff\\xd8\\xff`, sets the type
    to JPEG, `Warn`s `Processing JPEG-like data after unknown 4-byte header`,
    and — after ProcessJPEG succeeds — DELETES the whole `File:*` triplet
    ("Reset file type due to unknown header", ExifTool.pm:3069-3073).

    Pre-fix exifast's Exif dispatch only accepted a JPEG whose SOI was at
    byte 0, so this file was detected as a JPEG candidate then mis-rejected
    into a `File format error`.

    The embedded `APP1` Exif block carries IFD0 (Make) + IFD1 (Compression
    + ThumbnailOffset/ThumbnailLength). `ThumbnailOffset` is an `IsOffset`
    tag: its emitted value is the raw IFD value PLUS the TIFF block's file
    offset, which INCLUDES the 4 skipped header bytes — so this fixture also
    pins the `header_skip` base-rebase (bundled emits `IFD1:ThumbnailOffset`
    = raw + 4-junk + 2-SOI + 4-APP1-hdr + 6-`Exif\\0\\0`).
    """
    bo = '<'  # little-endian TIFF (II)
    # --- TIFF block: header + IFD0 + IFD1 + thumbnail data --------------
    # IFD0 at offset 8, one entry (Make, out-of-line 6-byte value).
    ifd0_off = 8
    n0 = 1
    make_val = b'Canon\x00'
    make_val_off = ifd0_off + 2 + n0 * 12 + 4         # after IFD0 dir+next-ptr
    ifd1_off = make_val_off + len(make_val)
    n1 = 3
    ifd1_len = 2 + n1 * 12 + 4
    thumb_data = b'\xff\xd8\xff\xd9'                   # 4-byte stand-in JPEG
    thumb_off = ifd1_off + ifd1_len                   # raw offset within TIFF

    tiff = bytearray()
    tiff += b'II*\x00' + struct.pack(bo + 'I', ifd0_off)
    # IFD0
    tiff += struct.pack(bo + 'H', n0)
    tiff += struct.pack(bo + 'HHII', 0x010f, ASCII, 6, make_val_off)  # Make
    tiff += struct.pack(bo + 'I', ifd1_off)           # next IFD -> IFD1
    tiff += make_val
    # IFD1
    tiff += struct.pack(bo + 'H', n1)
    tiff += struct.pack(bo + 'HHIHH', 0x0103, SHORT, 1, 6, 0)         # Compression
    tiff += struct.pack(bo + 'HHII', 0x0201, LONG, 1, thumb_off)      # ThumbnailOffset
    tiff += struct.pack(bo + 'HHII', 0x0202, LONG, 1, len(thumb_data))  # ThumbnailLength
    tiff += struct.pack(bo + 'I', 0)                  # no next IFD
    tiff += thumb_data

    # --- APP1 Exif segment + JPEG wrapper ------------------------------
    exif_payload = b'Exif\x00\x00' + bytes(tiff)
    app1 = b'\xff\xe1' + struct.pack('>H', len(exif_payload) + 2) + exif_payload
    # 4 junk bytes, then SOI, APP1, a minimal SOS, EOI.
    return b'JUNK' + b'\xff\xd8' + app1 + b'\xff\xda\x00\x02' + b'\xff\xd9'


# ===========================================================================
# Step-B binary-EXIF coverage-gap tags (table-codegen) — Exif.pm leaf tags the
# camera-relevant hand subset dropped, now emitted via the generated table.
# ===========================================================================


def _exififd_tif(bo, exif_entries):
    """A minimal standalone TIFF: IFD0 (ExifOffset only) -> ExifIFD carrying
    `exif_entries`. Each entry is `(tag, fmt, count, payload)` where payload is
    an int (inline scalar, packed into the 4-byte value word, hi-justified for
    SHORT) or bytes (<=4 inline left-justified, else out-of-line in a pool).

    Hand-laid (not via TiffBuilder) so the SubjectArea / CompositeImageExposureTimes
    rational / undef / multi-int payloads encode exactly. No Make/Model/IFD1 and
    no FNumber+FocalLength combo, so bundled emits NO Composite:* tags (mirrors
    `Exif_focallength35.tif`)."""
    marker = b'II' if bo == '<' else b'MM'
    ifd0_off = 8
    ifd0_len = 2 + 1 * 12 + 4
    exif_off = ifd0_off + ifd0_len
    n = len(exif_entries)
    exif_len = 2 + n * 12 + 4
    pool_start = exif_off + exif_len
    pool = bytearray()
    # Resolve each entry's 4-byte value word (inline) or pool offset.
    words = []
    for (tag, fmt, count, payload) in exif_entries:
        if isinstance(payload, int):
            if fmt == SHORT:
                words.append(struct.pack(bo + 'H', payload) + b'\x00\x00')
            else:
                words.append(struct.pack(bo + 'I', payload))
        else:
            blob = payload
            if len(blob) <= 4:
                words.append(blob + b'\x00' * (4 - len(blob)))
            else:
                off = pool_start + len(pool)
                pool += blob
                if len(pool) % 2:
                    pool += b'\x00'
                words.append(struct.pack(bo + 'I', off))
    out = bytearray()
    out += marker + struct.pack(bo + 'H', 0x002a) + struct.pack(bo + 'I', ifd0_off)
    # IFD0: ExifOffset pointer only.
    out += struct.pack(bo + 'H', 1)
    out += _raw_entry(bo, 0x8769, LONG, 1, exif_off)
    out += struct.pack(bo + 'I', 0)
    # ExifIFD.
    out += struct.pack(bo + 'H', n)
    for (tag, fmt, count, _payload), word in zip(exif_entries, words):
        out += struct.pack(bo + 'HHI', tag, fmt, count) + word
    out += struct.pack(bo + 'I', 0)
    out += pool
    return bytes(out)


def make_exif_gap_tags_tif():
    r"""Step-B binary-EXIF coverage gap — `%Exif::Main` leaf tags the
    camera-relevant hand subset (`src/exif/tables.rs` `EXIF_TAGS`) did NOT
    carry, so they were silently dropped on the binary IFD path. The
    `--kind exif` generator now emits them (they fall through the hand-first
    `lookup` to the generated shadow). This fixture exercises the
    declarative/plain ones + the two simple code-valued PrintConvs in ONE
    ExifIFD; the multi-element `CompositeImageExposureTimes` int16u carve-out
    is in the separate `Exif_composite_exposure.tif`.

    Tags + the bundled-ExifTool 13.59 rendering each pins (verified):
      - ProcessingSoftware (0x0b, IFD0 string)      "ACME RAW 2.1"
      - HostComputer       (0x13c, IFD0 string)     "studio-mac"
      - Opto-ElectricConvFactor (0x8828, Binary=>1) "(Binary data 8 bytes, ...)"
      - TimeZoneOffset     (0x882a, int16s[2])       "1 2"
      - StandardOutputSensitivity (0x8831, int32u)   400
      - ISOSpeed           (0x8833, int32u)          800
      - ISOSpeedLatitudeyyy (0x8834, int32u)         100
      - ISOSpeedLatitudezzz (0x8835, int32u)         200
      - ImageNumber        (0x9211, int32u)          42
      - SecurityClassification (0x9212, string PrintConv) "C" -> "Confidential"
      - ImageHistory       (0x9213, string)          "edit log"
      - SubjectArea        (0x9214, int16u[3])        "320 240 100"
      - AmbientTemperature (0x9400, srational PrintConv '"$val C"')  "23.5 C"
      - Humidity           (0x9401, rational64u)      "60"
      - Pressure           (0x9402, rational64u)      "1013"
      - WaterDepth         (0x9403, rational64s)      "-5.5"
      - Acceleration       (0x9404, rational64u)      "9800"
      - CameraElevationAngle (0x9405, rational64s)    "-12.5"
      - SubjectLocation    (0xa214, int16u[2])        "320 240"
      - CompositeImage     (0xa460, int16u PrintConv) 2 -> "General Composite Image"
      - CompositeImageCount (0xa461, int16u[2])       "4 3"

    Big-endian (MM). Note 0x0b/0x13c carry `WriteGroup => 'IFD0'` but are
    placed in the ExifIFD here purely to keep one directory; the family-1
    group is whatever IFD they are FOUND in (bundled resolves them by id in
    whatever table the directory uses — `%Exif::Main` covers both IFD0 and
    ExifIFD), so they emit under `ExifIFD:` here, matching bundled run on
    THIS file."""
    bo = '>'

    def srat64(num, den):
        return struct.pack(bo + 'iI', num, den)

    def rat64(num, den):
        return struct.pack(bo + 'II', num, den)

    entries = [
        (0x000b, ASCII, 13, b'ACME RAW 2.1\x00'),
        (0x013c, ASCII, 11, b'studio-mac\x00'),
        (0x8828, UNDEF, 8, bytes([1, 2, 3, 4, 5, 6, 7, 8])),  # OECF binary
        (0x882a, SSHORT, 2, struct.pack(bo + 'hh', 1, 2)),    # int16s[2] -> inline
        (0x8831, LONG, 1, 400),
        (0x8833, LONG, 1, 800),
        (0x8834, LONG, 1, 100),
        (0x8835, LONG, 1, 200),
        (0x9211, LONG, 1, 42),
        (0x9212, ASCII, 2, b'C\x00'),                          # SecurityClassification
        (0x9213, ASCII, 9, b'edit log\x00'),
        (0x9214, SHORT, 3, struct.pack(bo + 'HHH', 320, 240, 100)),  # SubjectArea
        (0x9400, SRATIONAL, 1, srat64(235, 10)),               # AmbientTemperature 23.5
        (0x9401, RATIONAL, 1, rat64(60, 1)),                   # Humidity
        (0x9402, RATIONAL, 1, rat64(1013, 1)),                 # Pressure
        (0x9403, SRATIONAL, 1, srat64(-55, 10)),               # WaterDepth -5.5
        (0x9404, RATIONAL, 1, rat64(9800, 1)),                 # Acceleration
        (0x9405, SRATIONAL, 1, srat64(-125, 10)),              # CameraElevationAngle -12.5
        (0xa214, SHORT, 2, struct.pack(bo + 'HH', 320, 240)),  # SubjectLocation -> inline
        (0xa460, SHORT, 1, 2),                                 # CompositeImage
        (0xa461, SHORT, 2, struct.pack(bo + 'HH', 4, 3)),      # CompositeImageCount -> inline
    ]
    return _exififd_tif(bo, entries)


def make_exif_composite_exposure_tif():
    r"""Step-B — `CompositeImageExposureTimes` (0xa462) only, exercising the
    bespoke `RawConv`/`PrintConv` (Exif.pm:3068-3119). The `undef` blob is a
    sequence of `rational64u` quotients EXCEPT at byte offsets 56 and 58 (the
    8th and 9th values, element indices 7 and 8) which are `int16u` counts;
    `PrintConv` applies `PrintExposureTime` to every element EXCEPT those two.

    11 values laid out to hit the carve-out (verified against bundled 13.59):
      idx 0..6  rational64u 1/160 1/200 1/250 1/320 1/400 1/500 1/640
      idx 7,8   int16u      3 2                 (counts — NOT PrintExposureTime'd)
      idx 9,10  rational64u 1/160 1/200
    -j  -> "1/160 1/200 1/250 1/320 1/400 1/500 1/640 3 2 1/160 1/200"
    -n  -> "0.00625 0.005 0.004 0.003125 0.0025 0.002 0.0015625 3 2 0.00625 0.005"

    Big-endian (MM)."""
    bo = '>'
    blob = bytearray()
    for (num, den) in [(1, 160), (1, 200), (1, 250), (1, 320), (1, 400), (1, 500), (1, 640)]:
        blob += struct.pack(bo + 'II', num, den)   # 7 rational64u -> bytes 0..56
    blob += struct.pack(bo + 'H', 3)               # idx7 int16u at offset 56
    blob += struct.pack(bo + 'H', 2)               # idx8 int16u at offset 58
    for (num, den) in [(1, 160), (1, 200)]:
        blob += struct.pack(bo + 'II', num, den)   # idx9,10 rational64u from offset 60
    return _exififd_tif(bo, [(0xa462, UNDEF, len(blob), bytes(blob))])


def make_exif_composite_exposure_edge_tif():
    r"""Step-B Codex follow-up — `CompositeImageExposureTimes` (0xa462) edge
    cases for the `RawConv`→`PrintConv` token pipeline (Exif.pm:3068-3119).

    ExifTool's `RawConv` stringifies each rational via `GetRational64u` =
    `RoundFloat(n/d, 10)` (= `%.10g`, or the bare word `undef`/`inf` for a zero
    denominator) and space-joins; the `PrintConv` then re-`split`s and feeds
    each TOKEN to `PrintExposureTime` (except element indices 7/8). So the print
    value is keyed on the ALREADY-ROUNDED token, not the unrounded quotient.

    Two cases that diverge if the unrounded `f64` quotient is used instead:
      idx 0  rational64u  2/19  — the rounded token `0.1052631579` feeds
             `PrintExposureTime` ⇒ `int(0.5 + 1/0.1052631579) = int(9.999…)
             = 9` ⇒ `"1/9"`. The UNROUNDED quotient `0.10526315789…` has
             `1/secs = 9.5` exactly ⇒ `int(10.0) = 10` ⇒ the WRONG `"1/10"`.
      idx 1  rational64u  0/0   — `GetRational64u` returns the word `undef`
             (zero denominator, zero numerator); `PrintExposureTime` is NOT a
             float ⇒ passes `undef` through unchanged. The unrounded path would
             divide `0/0 = NaN` ⇒ the WRONG `"NaN"`.
      idx 2..6 rational64u 1/250 1/320 1/400 1/500 1/640  (filler to byte 56)
      idx 7,8  int16u      3 2                 (counts — NOT PrintExposureTime'd)
      idx 9,10 rational64u 1/160 1/200
    -j -> "1/9 undef 1/250 1/320 1/400 1/500 1/640 3 2 1/160 1/200"
    -n -> "0.1052631579 undef 0.004 0.003125 0.0025 0.002 0.0015625 3 2 0.00625 0.005"
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    Big-endian (MM)."""
    bo = '>'
    blob = bytearray()
    for (num, den) in [(2, 19), (0, 0), (1, 250), (1, 320), (1, 400), (1, 500), (1, 640)]:
        blob += struct.pack(bo + 'II', num, den)   # 7 rational64u -> bytes 0..56
    blob += struct.pack(bo + 'H', 3)               # idx7 int16u at offset 56
    blob += struct.pack(bo + 'H', 2)               # idx8 int16u at offset 58
    for (num, den) in [(1, 160), (1, 200)]:
        blob += struct.pack(bo + 'II', num, den)   # idx9,10 rational64u from offset 60
    return _exififd_tif(bo, [(0xa462, UNDEF, len(blob), bytes(blob))])


def make_exif_ambient_multi_tif():
    r"""Step-B Codex follow-up — `AmbientTemperature` (0x9400) with a MALFORMED
    count>1 `rational64s` value, pinning the `PrintConv => '"$val C"'`
    string-interpolation over the WHOLE (space-joined) value (Exif.pm:2590).

    0x9400 is normally a single `rational64s`, but `"$val C"` interpolates the
    entire post-`ReadValue` `$val`; for count>1 that is the space-joined element
    list, with the ` C` suffix appended ONCE to the whole string (NOT per
    element, and NOT only the first element).

      0x9400 SRATIONAL count=2: 235/10, -50/10
    -j -> "23.5 -5 C"   (the joined value `23.5 -5` + one ` C`; `-50/10`
                         rounds via `GetRational64s` `%.10g` to `-5`, not `-5.0`)
    -n -> "23.5 -5"
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    Big-endian (MM)."""
    bo = '>'

    def srat64(num, den):
        return struct.pack(bo + 'iI', num, den)

    blob = srat64(235, 10) + srat64(-50, 10)       # 16 bytes -> out-of-line pool
    return _exififd_tif(bo, [(0x9400, SRATIONAL, 2, blob)])


def make_exif_composite_exposure_wrongfmt_tif():
    r"""#198 — `CompositeImageExposureTimes` (0xa462) written with the WRONG
    on-disk format (`string`/ASCII instead of `undef`), pinning that the
    bespoke `RawConv` byte-walks `$val` REGARDLESS of `Format` (Exif.pm:3079
    runs on whatever `ReadValue` returned). ExifTool reads the value per the
    on-disk `string` format (NUL-trim at the first NUL, no UTF-8 decode), then
    the RawConv byte-walks those bytes as `rational64u` quotients.

    Payload `b"ABCDEFGH"` (8 ASCII bytes, no NUL) = exactly ONE rational64u
    `0x41424344 / 0x45464748` = 1094861636 / 1162233672 ≈ 0.9420. One element
    ⇒ the lone token is the whole `$val`: `PrintExposureTime(0.9420…)` (> 0.25)
    ⇒ `sprintf("%.1f") = "0.9"` (`-j`, a string out of the number gate is still
    bare here as `0.9` is numeric ⇒ a BARE number); `-n` the RawConv token
    `0.942029…`. Values verified against bundled `perl exiftool 13.59`.

    Big-endian (MM)."""
    bo = '>'
    payload = b'ABCDEFGH'                          # string/ASCII, 8 bytes
    return _exififd_tif(bo, [(0xa462, ASCII, len(payload), payload)])


def make_exif_composite_exposure_wrongfmt_highbit_tif():
    r"""#198 R4 — the LOSSY-BYTES case: `CompositeImageExposureTimes` (0xa462)
    written as `string` with INVALID-UTF-8 high-bit bytes. Proves the byte-walk
    reads `$val`'s ORIGINAL bytes (A1's `RawValue::Text.raw`), NOT the lossy
    FixUTF8 display text (where each high byte → U+FFFD, a 3-byte re-encoding
    that would corrupt the rational decode).

    Payload `b"\x80\x81\x82\x83\x84\x85\x86\x87"` (8 bytes, no NUL, not valid
    UTF-8) = one rational64u `0x80818283 / 0x84858687` = 2155971203 / 2223078023
    ≈ 0.9698. `PrintExposureTime(0.9698…)` (> 0.25) ⇒ `-j "1.0"` (`%.1f` of
    0.9698 rounds to 1.0; `s/\.0$//` would strip → wait, `%.1f` of 0.96979 =
    "1.0" then `s/\.0$//` → "1"); `-n` the RawConv token. ALL values are taken
    verbatim from bundled `perl exiftool 13.59` (the generator docstring is
    descriptive; the GOLDEN is the oracle of record).

    Big-endian (MM)."""
    bo = '>'
    payload = bytes([0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87])
    return _exififd_tif(bo, [(0xa462, ASCII, len(payload), payload)])


def make_exif_composite_exposure_single_number_tif():
    r"""Codex R3 — `CompositeImageExposureTimes` (0xa462) decoding to EXACTLY
    ONE numeric element, pinning the single-element JSON TYPE (a BARE NUMBER,
    not a quoted string).

    ExifTool's bespoke `RawConv`/`PrintConv` (Exif.pm:3068-3119) produce a
    SINGLE Perl scalar; with one element that scalar IS the lone token, so
    `EscapeJSON` (exiftool:3809) number-gates it to a bare JSON number. A
    correctly `undef`-typed 8-byte blob = ONE `rational64u` 1/2 (the walk stops
    at offset 8: 8 + 8 > len 8):
      idx 0  rational64u 1/2  -> RawConv token `0.5`; PrintExposureTime(0.5):
             0.5 > 0.25001 -> sprintf("%.1f") = `0.5`.
    -j -> 0.5            (a BARE JSON number)
    -n -> 0.5            (the RawConv token; a BARE JSON number)
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    Pre-R3 the conv space-`join`-ed the single token through `write_str`, so a
    one-element NUMERIC result was emitted as a JSON STRING (`"0.5"`); the
    value-semantic conformance harness MASKED the type error. Big-endian (MM)."""
    bo = '>'
    blob = struct.pack(bo + 'II', 1, 2)             # one rational64u 1/2 = 0.5
    return _exififd_tif(bo, [(0xa462, UNDEF, len(blob), bytes(blob))])


def make_exif_composite_exposure_single_undef_tif():
    r"""Codex R3 — `CompositeImageExposureTimes` (0xa462) decoding to EXACTLY
    ONE `undef` element, pinning that a single NON-numeric token stays a quoted
    JSON STRING (NOT a number, NOT NaN).

    A correctly `undef`-typed 8-byte blob = ONE `rational64u` 0/0 (zero
    denominator). `GetRational64u` returns the bare word `undef`; the
    `PrintConv` `PrintExposureTime` is NOT a float (Exif.pm:5704) so it passes
    `undef` through unchanged.
      idx 0  rational64u 0/0  -> token `undef` (both modes).
    -j -> "undef"        (a quoted JSON string — out of the number gate)
    -n -> "undef"        (a quoted JSON string)
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    `emit_gated_number` keeps this a string (the word `undef` fails the
    `EscapeJSON` number regex). Big-endian (MM)."""
    bo = '>'
    blob = struct.pack(bo + 'II', 0, 0)             # one rational64u 0/0 = undef
    return _exififd_tif(bo, [(0xa462, UNDEF, len(blob), bytes(blob))])


def make_exif_composite_exposure_single_fraction_tif():
    r"""Codex R3 — `CompositeImageExposureTimes` (0xa462) decoding to EXACTLY
    ONE element whose PrintConv renders a `1/N` fraction, pinning the
    PER-TOKEN, PER-MODE JSON typing (the discriminating case): a single
    `PrintExposureTime` fraction is a STRING in `-j` but the SAME element's
    RawConv decimal is a NUMBER in `-n`.

    A correctly `undef`-typed 8-byte blob = ONE `rational64u` 1/250:
      -j: PrintExposureTime(0.004) = `1/250` (a string; 0.004 <= 0.25001 ->
          int(0.5 + 1/0.004) = 250 -> "1/250").
      -n: the RawConv token `0.004` (a bare number).
    -j -> "1/250"        (a quoted JSON string)
    -n -> 0.004          (a BARE JSON number)
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    This is the case that proves the single-element fix gates PER TOKEN (reusing
    `emit_gated_number`), NOT per element-count: the `-j` token `1/250` fails the
    number regex (the `/`) -> string, while the `-n` token `0.004` matches ->
    number. Big-endian (MM)."""
    bo = '>'
    blob = struct.pack(bo + 'II', 1, 250)           # one rational64u 1/250
    return _exififd_tif(bo, [(0xa462, UNDEF, len(blob), bytes(blob))])


def make_exif_ambient_wrongfmt_tif():
    r"""Codex R2/F class-sweep — `AmbientTemperature` (0x9400) written with the
    WRONG on-disk format (`undef` instead of `rational64s`), pinning that the
    `PrintConv => '"$val C"'` (Exif.pm:2590) is likewise NOT format-gated.

    ExifTool reads the value per the on-disk format first; for an `undef`-typed
    value `ReadValue` returns the raw byte string VERBATIM (no NUL-trim — only a
    `string` format trims, ExifTool.pm:6312). So the 4-byte `undef` blob `b"-5.5"`
    becomes the post-`ReadValue` `$val` = `"-5.5"`, and `"$val C"` appends ` C`:
      -j -> "-5.5 C"   (a quoted string — `"$val C"` has a space + letter)
      -n -> -5.5       (the bare `$val`; a BARE JSON number via the EscapeJSON gate)
    (both verified byte-identical against bundled `perl exiftool` 13.59.)

    This is the `undef`/`Bytes` shape that `value_space_joined` does NOT render
    (it carries no numeric `ReadValue` form); without the fix exifast would emit
    the value via the binary `write_bytes` path instead of `"-5.5 C"`.
    Big-endian (MM)."""
    bo = '>'
    payload = b'-5.5'                               # undef, 4 bytes -> inline word
    return _exififd_tif(bo, [(0x9400, UNDEF, len(payload), payload)])


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    with open(f'{out_dir}/Exif.tif', 'wb') as f:
        f.write(make_exif_tif())
    with open(f'{out_dir}/ExifGPS.tif', 'wb') as f:
        f.write(make_exif_gps_tif())
    with open(f'{out_dir}/Exif_multipage.tif', 'wb') as f:
        f.write(make_exif_multipage_tif())
    with open(f'{out_dir}/Exif_pagecount.tif', 'wb') as f:
        f.write(make_exif_pagecount_tif())
    with open(f'{out_dir}/Exif_manyifd.tif', 'wb') as f:
        f.write(make_exif_manyifd_tif())
    with open(f'{out_dir}/Exif_ifd65536.tif', 'wb') as f:
        f.write(make_exif_ifd65536_tif())
    with open(f'{out_dir}/Exif_gps_after_interop.tif', 'wb') as f:
        f.write(make_exif_gps_after_interop_tif())
    with open(f'{out_dir}/Exif_gps_shared_pointer.tif', 'wb') as f:
        f.write(make_exif_gps_shared_pointer_tif())
    with open(f'{out_dir}/Exif_makernote.tif', 'wb') as f:
        f.write(make_exif_makernote_tif())
    with open(f'{out_dir}/Exif_badoffset_low.tif', 'wb') as f:
        f.write(make_exif_badoffset_low_tif())
    with open(f'{out_dir}/Exif_badoffset_eof.tif', 'wb') as f:
        f.write(make_exif_badoffset_eof_tif())
    with open(f'{out_dir}/Exif_truncated_ifd.tif', 'wb') as f:
        f.write(make_exif_truncated_ifd_tif())
    with open(f'{out_dir}/Exif_focallength35.tif', 'wb') as f:
        f.write(make_exif_focallength35_tif())
    with open(f'{out_dir}/Exif_badformat_entry0.tif', 'wb') as f:
        f.write(make_exif_badformat_entry0_tif())
    with open(f'{out_dir}/Exif_badformat_ifd1.tif', 'wb') as f:
        f.write(make_exif_badformat_ifd1_tif())
    with open(f'{out_dir}/Exif_gps_proctext.tif', 'wb') as f:
        f.write(make_exif_gps_proctext_tif())
    with open(f'{out_dir}/Exif_gps_unicode.tif', 'wb') as f:
        f.write(make_exif_gps_unicode_tif())
    with open(f'{out_dir}/Exif_gps_datestamp.tif', 'wb') as f:
        f.write(make_exif_gps_datestamp_tif())
    with open(f'{out_dir}/Exif_illegal_ifd0_size.tif', 'wb') as f:
        f.write(make_exif_illegal_ifd0_size_tif())
    with open(f'{out_dir}/Exif_illegal_subifd_size.tif', 'wb') as f:
        f.write(make_exif_illegal_subifd_size_tif())
    with open(f'{out_dir}/Exif_gps_baddir.tif', 'wb') as f:
        f.write(make_exif_gps_baddir_tif())
    with open(f'{out_dir}/Exif_gps_badoffset.tif', 'wb') as f:
        f.write(make_exif_gps_badoffset_tif())
    with open(f'{out_dir}/Exif_gps_wrongfmt.tif', 'wb') as f:
        f.write(make_exif_gps_wrongfmt_tif())
    with open(f'{out_dir}/Exif_gps_int32s.tif', 'wb') as f:
        f.write(make_exif_gps_int32s_tif())
    with open(f'{out_dir}/Exif_gps_proctext_wrongfmt.tif', 'wb') as f:
        f.write(make_exif_gps_proctext_wrongfmt_tif())
    with open(f'{out_dir}/Exif_gps_eofoverrun.tif', 'wb') as f:
        f.write(make_exif_gps_eofoverrun_tif())
    with open(f'{out_dir}/Exif_eofoverrun_chain.tif', 'wb') as f:
        f.write(make_exif_eofoverrun_chain_tif())
    with open(f'{out_dir}/Exif_usercomment_ascii.tif', 'wb') as f:
        f.write(make_exif_usercomment_ascii_tif())
    with open(f'{out_dir}/Exif_usercomment_unicode.tif', 'wb') as f:
        f.write(make_exif_usercomment_unicode_tif())
    with open(f'{out_dir}/Exif_usercomment_bom.tif', 'wb') as f:
        f.write(make_exif_usercomment_bom_tif())
    with open(f'{out_dir}/Exif_usercomment_string.tif', 'wb') as f:
        f.write(make_exif_usercomment_string_tif())
    with open(f'{out_dir}/Exif_usercomment_int8u.tif', 'wb') as f:
        f.write(make_exif_usercomment_int8u_tif())
    with open(f'{out_dir}/Exif_trailing_space.tif', 'wb') as f:
        f.write(make_exif_trailing_space_tif())
    with open(f'{out_dir}/Exif_gap_tags.tif', 'wb') as f:
        f.write(make_exif_gap_tags_tif())
    with open(f'{out_dir}/Exif_composite_exposure.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_tif())
    with open(f'{out_dir}/Exif_composite_exposure_edge.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_edge_tif())
    with open(f'{out_dir}/Exif_composite_exposure_wrongfmt.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_wrongfmt_tif())
    with open(f'{out_dir}/Exif_composite_exposure_wrongfmt_highbit.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_wrongfmt_highbit_tif())
    with open(f'{out_dir}/Exif_ambient_multi.tif', 'wb') as f:
        f.write(make_exif_ambient_multi_tif())
    with open(f'{out_dir}/Exif_composite_exposure_single_number.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_single_number_tif())
    with open(f'{out_dir}/Exif_composite_exposure_single_undef.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_single_undef_tif())
    with open(f'{out_dir}/Exif_composite_exposure_single_fraction.tif', 'wb') as f:
        f.write(make_exif_composite_exposure_single_fraction_tif())
    with open(f'{out_dir}/Exif_ambient_wrongfmt.tif', 'wb') as f:
        f.write(make_exif_ambient_wrongfmt_tif())
    with open(f'{out_dir}/JPEG_unknown_header.jpg', 'wb') as f:
        f.write(make_jpeg_unknown_header())
    print(f'wrote {out_dir}/Exif.tif, {out_dir}/ExifGPS.tif, '
          f'{out_dir}/Exif_multipage.tif, '
          f'{out_dir}/Exif_pagecount.tif, '
          f'{out_dir}/Exif_manyifd.tif, '
          f'{out_dir}/Exif_ifd65536.tif, '
          f'{out_dir}/Exif_gps_after_interop.tif, '
          f'{out_dir}/Exif_gps_shared_pointer.tif, '
          f'{out_dir}/Exif_makernote.tif, {out_dir}/Exif_badoffset_low.tif, '
          f'{out_dir}/Exif_badoffset_eof.tif, '
          f'{out_dir}/Exif_truncated_ifd.tif, '
          f'{out_dir}/Exif_focallength35.tif, '
          f'{out_dir}/Exif_badformat_entry0.tif, '
          f'{out_dir}/Exif_badformat_ifd1.tif, '
          f'{out_dir}/Exif_gps_proctext.tif, '
          f'{out_dir}/Exif_gps_unicode.tif, '
          f'{out_dir}/Exif_gps_datestamp.tif, '
          f'{out_dir}/Exif_illegal_ifd0_size.tif, '
          f'{out_dir}/Exif_illegal_subifd_size.tif, '
          f'{out_dir}/Exif_gps_baddir.tif, '
          f'{out_dir}/Exif_gps_badoffset.tif, '
          f'{out_dir}/Exif_gps_wrongfmt.tif, '
          f'{out_dir}/Exif_gps_int32s.tif, '
          f'{out_dir}/Exif_gps_proctext_wrongfmt.tif, '
          f'{out_dir}/Exif_gps_eofoverrun.tif, '
          f'{out_dir}/Exif_eofoverrun_chain.tif, '
          f'{out_dir}/Exif_usercomment_ascii.tif, '
          f'{out_dir}/Exif_usercomment_unicode.tif, '
          f'{out_dir}/Exif_usercomment_bom.tif, '
          f'{out_dir}/Exif_usercomment_string.tif, '
          f'{out_dir}/Exif_usercomment_int8u.tif, '
          f'{out_dir}/Exif_trailing_space.tif, '
          f'{out_dir}/JPEG_unknown_header.jpg')
