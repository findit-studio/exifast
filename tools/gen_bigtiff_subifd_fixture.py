#!/usr/bin/env python3
"""Generate a minimal BigTIFF fixture exercising SubIFD pointer recursion.

The bundled BigTIFF.btf is a FLAT single-IFD image (no SubIFD pointers), so it
does not exercise ExifTool's `ProcessBigIFD` SubIFD recursion (BigTIFF.pm:171-198
— `if ($$tagInfo{SubIFD}) { ProcessBigIFD on each offset }`). This synthesizes a
hand-built BigTIFF (version 43, 8-byte offsets) carrying an ExifOffset (0x8769)
pointer to an ExifIFD with a few camera tags + a GPSInfo (0x8825) pointer to a
GPS IFD, so the SubIFD recursion path is covered.

BigTIFF layout (BigTIFF.pm:26-228):
  header : byteorder(2) 0x002B(2) offsetsize=8(2) 0x0000(2) firstIFDoff(8)
  IFD    : count(8) + N x [tag(2) format(2) count(8) value/off(8)] + nextIFD(8)
  A value occupying <= 8 bytes is inline at entry+12; otherwise the 8 bytes
  there are an absolute file offset to the value pool.
"""
import struct
import sys

# ---- TIFF format codes (Exif.pm formatName) --------------------------------
SHORT = 3
LONG = 4
RATIONAL = 5
UNDEF = 7
LONG8 = 16  # int64u (BigTIFF addition)


class BigTiffBuilder:
    """Builds a BigTIFF block in a chosen byte order.

    Entries whose value is > 8 bytes go into an out-of-line value pool that
    follows all IFDs; their 8-byte offsets are patched at finalize().
    """

    def __init__(self, byte_order):
        # byte_order: '<' (II / little) or '>' (MM / big)
        self.bo = byte_order
        self.marker = b'II' if byte_order == '<' else b'MM'

    def _pack_inline(self, fmt, count, payload):
        """Pack a <= 8-byte inline value into exactly 8 bytes (zero-padded)."""
        if isinstance(payload, bytes):
            raw = payload
        elif fmt == SHORT:
            raw = struct.pack(self.bo + 'H' * count, *payload)
        elif fmt in (LONG,):
            raw = struct.pack(self.bo + 'I' * count, *payload)
        elif fmt == LONG8:
            raw = struct.pack(self.bo + 'Q' * count, *payload)
        else:
            raise ValueError(f'inline pack unsupported for fmt {fmt}')
        assert len(raw) <= 8, (fmt, count, len(raw))
        return raw + b'\x00' * (8 - len(raw))

    def _value_bytes(self, fmt, count, payload):
        """The raw on-disk bytes for an out-of-line value."""
        if isinstance(payload, bytes):
            return payload
        if fmt == RATIONAL:
            # payload is a flat list of (num, den) ints
            return struct.pack(self.bo + 'I' * len(payload), *payload)
        if fmt == SHORT:
            return struct.pack(self.bo + 'H' * count, *payload)
        if fmt == LONG:
            return struct.pack(self.bo + 'I' * count, *payload)
        raise ValueError(f'value pack unsupported for fmt {fmt}')

    def build(self, ifds):
        """ifds: list of IFD dicts (index 0 == IFD0). Each:
             { 'entries': [ (tag, fmt, count, payload) ... ],
               'sub': { pointer_tag: <ifd index> } }
           A 'sub' entry's pointer value is filled with the target IFD offset.
           payload: an int/list (packed per fmt) OR raw bytes.
        """
        elem_size = {SHORT: 2, LONG: 4, RATIONAL: 8, UNDEF: 1, LONG8: 8}

        # ---- Layout pass: assign each IFD an offset. ----
        # header is 16 bytes. Each IFD is 8 (count) + 20*n + 8 (next ptr).
        offsets = []
        pos = 16
        for ifd in ifds:
            offsets.append(pos)
            n = len(ifd['entries']) + len(ifd.get('sub', {}))
            pos += 8 + 20 * n + 8

        # The out-of-line value pool starts after all IFDs. Assign each
        # > 8-byte value an offset.
        value_blobs = []  # (offset, bytes)
        value_off_for = {}  # (ifd_idx, entry_key) -> offset
        for i, ifd in enumerate(ifds):
            for j, (tag, fmt, count, payload) in enumerate(ifd['entries']):
                raw = self._value_bytes(fmt, count, payload)
                if len(raw) > 8:
                    value_off_for[(i, j)] = pos
                    value_blobs.append((pos, raw))
                    pos += len(raw)
                    if pos % 2:  # keep word alignment, harmless
                        pos += 1

        # ---- Emit pass. ----
        out = bytearray()
        out += self.marker
        out += struct.pack(self.bo + 'HHH', 0x002B, 8, 0x0000)
        out += struct.pack(self.bo + 'Q', offsets[0])

        for i, ifd in enumerate(ifds):
            assert len(out) == offsets[i], (len(out), offsets[i])
            rows = []
            # Leaf / value entries.
            for j, (tag, fmt, count, payload) in enumerate(ifd['entries']):
                raw = self._value_bytes(fmt, count, payload)
                if len(raw) > 8:
                    val8 = struct.pack(self.bo + 'Q', value_off_for[(i, j)])
                else:
                    val8 = raw + b'\x00' * (8 - len(raw))
                rows.append((tag, fmt, count, val8))
            # SubIFD pointer entries (format LONG8, count 1, value = IFD off).
            for tag, target in ifd.get('sub', {}).items():
                val8 = struct.pack(self.bo + 'Q', offsets[target])
                rows.append((tag, LONG8, 1, val8))
            # Entries MUST be written in ascending tag order (TIFF spec).
            rows.sort(key=lambda r: r[0])

            out += struct.pack(self.bo + 'Q', len(rows))
            for tag, fmt, count, val8 in rows:
                out += struct.pack(self.bo + 'HHQ', tag, fmt, count)
                out += val8
            out += struct.pack(self.bo + 'Q', 0)  # next-IFD pointer = 0

        for off, raw in value_blobs:
            assert len(out) == off, (len(out), off)
            out += raw
            if len(out) % 2:
                out += b'\x00'

        return bytes(out)


def build_exp_offset_variant(child_at, gps_ptr_text):
    """A BigTIFF whose GPSInfo (0x8825) SubIFD pointer is an ASCII STRING whose
    Perl numeric value is the child IFD's absolute offset — to pin `ProcessBigIFD`'s
    full Perl string→number coercion of the `split ' ', $val` offset token (#240
    round-2 follow-up, the Codex [medium] finding).

    The shared `BigTiffBuilder.build()` only emits a SubIFD pointer as a `LONG8`
    count=1 numeric offset, so it cannot express a `string`-format pointer placed
    at a chosen byte; this hand-lays IFD0 + a single GPS child at `child_at`, with
    the GPSInfo pointer the literal text `gps_ptr_text` (e.g. "1e3"). Ground-truthed
    against bundled ExifTool 13.59: with `gps_ptr_text="1e3"` and `child_at=1000`,
    `0 + "1e3" == 1000`, so bundled recurses the child at byte 1000 and emits the
    child's 0x0001/0x0002 as `GPSInfo:InteropIndex`/`InteropVersion` (reusing
    %Exif::Main) — NOT byte 1 (the digit-prefix-only mis-coercion this fixes).

    Layout: header(16) · IFD0 (Make/Model/GPSInfo-ASCII) · IFD0 value pool ·
    pad · GPS child IFD at `child_at` · child value pool.
    """
    bo = '<'
    pack = lambda f, *v: struct.pack(bo + f, *v)
    make, model = b'BigCam\x00', b'BTF-1\x00'
    gtext = gps_ptr_text.encode()
    ifd0_off = 16
    n0 = 3                      # Make, Model, GPSInfo
    ifd0_size = 8 + 20 * n0 + 8
    # IFD0 out-of-line pool for any > 8-byte value.
    pos = ifd0_off + ifd0_size
    voff = {}
    for key, raw in (('make', make), ('model', model), ('gtext', gtext)):
        if len(raw) > 8:
            voff[key] = pos
            pos += len(raw) + (len(raw) & 1)
    assert pos <= child_at, (pos, child_at)
    # GPS child entries (REAL GPS on-disk formats, walked vs inherited %Exif::Main).
    g0, g1 = bytes([2, 3, 0, 0]), b'N\x00'
    g2 = pack('I' * 6, 37, 1, 48, 1, 30, 1)            # GPSLatitude 37,48,30
    cn = 3
    child_size = 8 + 20 * cn + 8
    g2_off = child_at + child_size

    def val8(raw, key):
        return pack('Q', voff[key]) if len(raw) > 8 else raw + b'\x00' * (8 - len(raw))

    out = bytearray(b'II')
    out += pack('HHH', 0x002B, 8, 0) + pack('Q', ifd0_off)
    rows = sorted([
        (0x010f, 2, len(make), val8(make, 'make')),    # Make   (ASCII)
        (0x0110, 2, len(model), val8(model, 'model')),  # Model  (ASCII)
        (0x8825, 2, len(gtext), val8(gtext, 'gtext')),  # GPSInfo POINTER as ASCII text
    ], key=lambda r: r[0])
    out += pack('Q', len(rows))
    for tag, fmt, count, v in rows:
        out += pack('HHQ', tag, fmt, count) + v
    out += pack('Q', 0)                                 # next-IFD = 0
    for key, raw in (('make', make), ('model', model), ('gtext', gtext)):
        if len(raw) > 8:
            assert len(out) == voff[key], (len(out), voff[key])
            out += raw + (b'\x00' if len(raw) & 1 else b'')
    out += b'\x00' * (child_at - len(out))              # pad to the child offset
    assert len(out) == child_at, (len(out), child_at)
    crows = sorted([
        (0x0000, UNDEF, 4, g0 + b'\x00' * 4),           # GPSVersionID
        (0x0001, 2, 2, g1 + b'\x00' * 6),               # → GPSInfo:InteropIndex "N"
        (0x0002, RATIONAL, 3, pack('Q', g2_off)),       # → GPSInfo:InteropVersion
    ], key=lambda r: r[0])
    out += pack('Q', len(crows))
    for tag, fmt, count, v in crows:
        out += pack('HHQ', tag, fmt, count) + v
    out += pack('Q', 0)
    assert len(out) == g2_off, (len(out), g2_off)
    out += g2
    return bytes(out)


def build_jpegpreview_variant():
    """A BigTIFF whose IFD0 carries the EXACT `%Exif::Main` JPEG-preview shape
    that triggers the DNG/TIFF `PreviewImage`/`JpgFromRaw` arms for a CLASSIC
    TIFF — `SubfileType=1` (0xfe), `Compression=7` (0x103, JPEG), `StripOffsets`
    (0x111) + `StripByteCounts` (0x117) — to pin that a BigTIFF does NOT take
    those arms (the `$$self{TIFF_TYPE} =~ /^(DNG|TIFF)$/` gate, `Exif.pm:635`/
    `:735`).

    `ProcessBTF`/`ProcessBigIFD` (`BigTIFF.pm`) is dispatched from
    `DoProcessTIFF`'s `$identifier == 0x2b` arm and `return 1`s at
    `ExifTool.pm:8668` BEFORE `$$self{TIFF_TYPE} = $fileType` (`:8715`), so
    `$$self{TIFF_TYPE}` stays its constructor default `''` (`:4369`) for the
    WHOLE BigTIFF walk. `'' !~ /^(DNG|TIFF)$/`, so the `0x111`/`0x117` conditional
    tag lists fall to the DEFAULT `StripOffsets`/`StripByteCounts` arm
    (`Exif.pm:631-643`) — NOT the `PreviewImageStart`/`PreviewImageLength` arm a
    classic `TIFF`-typed file with this same shape takes. Oracle-verified on
    bundled ExifTool 13.59: this fixture emits `IFD0:StripOffsets` +
    `IFD0:StripByteCounts` (and `IFD0:SubfileType`/`IFD0:Compression`), with NO
    `PreviewImageStart`/`Length`/`PreviewImage` and NO `JpgFromRaw*`.

    Layout: header(16) · IFD0 (SubfileType/Compression/Make/Model/StripOffsets/
    StripByteCounts) · IFD0 value pool (Make/Model) · a 4-byte strip blob the
    StripOffsets points at (its absolute file offset).
    """
    bo = '<'
    pack = lambda f, *v: struct.pack(bo + f, *v)
    make, model = b'BigCam\x00', b'BTF-1\x00'
    strip = b'\xff\xd8\xff\xd9'  # a 4-byte fake JPEG (SOI .. EOI)
    ifd0_off = 16
    n0 = 6                       # SubfileType, Compression, Make, Model, StripOffsets, StripByteCounts
    ifd0_size = 8 + 20 * n0 + 8
    # IFD0 out-of-line pool for the > 8-byte Make/Model strings.
    pos = ifd0_off + ifd0_size
    voff = {}
    for key, raw in (('make', make), ('model', model)):
        if len(raw) > 8:
            voff[key] = pos
            pos += len(raw) + (len(raw) & 1)
    # The strip blob the StripOffsets (0x111) references, at its absolute offset.
    strip_off = pos
    pos += len(strip)

    def val8(raw, key):
        return pack('Q', voff[key]) if len(raw) > 8 else raw + b'\x00' * (8 - len(raw))

    out = bytearray(b'II')
    out += pack('HHH', 0x002B, 8, 0) + pack('Q', ifd0_off)
    rows = sorted([
        (0x00fe, LONG, 1, pack('I', 1) + b'\x00' * 4),            # SubfileType = 1 (reduced-res)
        (0x0103, SHORT, 1, pack('H', 7) + b'\x00' * 6),           # Compression = 7 (JPEG)
        (0x010f, 2, len(make), val8(make, 'make')),               # Make
        (0x0110, 2, len(model), val8(model, 'model')),            # Model
        (0x0111, LONG, 1, pack('I', strip_off) + b'\x00' * 4),    # StripOffsets -> strip blob
        (0x0117, LONG, 1, pack('I', len(strip)) + b'\x00' * 4),   # StripByteCounts = 4
    ], key=lambda r: r[0])
    out += pack('Q', len(rows))
    for tag, fmt, count, v in rows:
        out += pack('HHQ', tag, fmt, count) + v
    out += pack('Q', 0)                                           # next-IFD = 0
    for key, raw in (('make', make), ('model', model)):
        if len(raw) > 8:
            assert len(out) == voff[key], (len(out), voff[key])
            out += raw + (b'\x00' if len(raw) & 1 else b'')
    assert len(out) == strip_off, (len(out), strip_off)
    out += strip
    return bytes(out)


def main():
    if len(sys.argv) < 2:
        print('usage: gen_bigtiff_subifd_fixture.py <out.btf> [exp|jpegpreview]', file=sys.stderr)
        return 1

    # `exp` variant: the ASCII-exponent GPSInfo SubIFD pointer fixture (#240 R2
    # follow-up). `1e3` → child IFD at byte 1000 (Perl `0 + "1e3" == 1000`).
    if len(sys.argv) >= 3 and sys.argv[2] == 'exp':
        blob = build_exp_offset_variant(1000, '1e3')
        with open(sys.argv[1], 'wb') as f:
            f.write(blob)
        print(f'wrote {len(blob)} bytes to {sys.argv[1]} (exp variant, GPS ptr "1e3" → child@1000)')
        return 0

    # `jpegpreview` variant: IFD0 with the JPEG-preview shape (SubfileType=1 +
    # Compression=7 + StripOffsets/StripByteCounts) — pins that a BigTIFF
    # (`TIFF_TYPE == ''`) keeps the plain `StripOffsets`/`StripByteCounts` arm
    # instead of the classic-TIFF `PreviewImage`/`JpgFromRaw` arms.
    if len(sys.argv) >= 3 and sys.argv[2] == 'jpegpreview':
        blob = build_jpegpreview_variant()
        with open(sys.argv[1], 'wb') as f:
            f.write(blob)
        print(f'wrote {len(blob)} bytes to {sys.argv[1]} (jpegpreview variant, IFD0 StripOffsets not PreviewImage)')
        return 0

    b = BigTiffBuilder('<')  # little-endian (II)

    # ExifIFD (index 1): a few camera tags.
    exif_ifd = {
        'entries': [
            (0x829a, RATIONAL, 1, [1, 200]),     # ExposureTime  1/200
            (0x829d, RATIONAL, 1, [40, 10]),     # FNumber       4.0
            (0x8827, SHORT, 1, [400]),           # ISO           400
            (0x9000, UNDEF, 4, b'0232'),         # ExifVersion   0232
        ],
    }
    # GPS IFD (index 2): version + one lat/ref pair, using the REAL GPS on-disk
    # formats (GPSVersionID=UNDEF[4], GPSLatitudeRef=ASCII, GPSLatitude=RATIONAL).
    # ExifTool walks this child against the INHERITED %Exif::Main (BigTIFF.pm:172),
    # so 0x0000 is unknown-in-Exif (dropped) while 0x0001/0x0002 resolve as
    # InteropIndex (string "N" -> "Unknown (N)") / InteropVersion ("37 48 30").
    gps_ifd = {
        'entries': [
            (0x0000, UNDEF, 4, bytes([2, 3, 0, 0])),       # GPSVersionID 2.3.0.0
            (0x0001, 2, 2, b'N\x00'),                       # GPSLatitudeRef "N"
            (0x0002, RATIONAL, 3, [37, 1, 48, 1, 30, 1]),  # GPSLatitude 37,48,30
        ],
    }
    # IFD0: minimal camera id + the two SubIFD pointers.
    ifd0 = {
        'entries': [
            (0x010f, 2, len(b'BigCam\x00'), b'BigCam\x00'),    # Make
            (0x0110, 2, len(b'BTF-1\x00'), b'BTF-1\x00'),      # Model
        ],
        'sub': {
            0x8769: 1,  # ExifOffset -> ExifIFD
            0x8825: 2,  # GPSInfo    -> GPS IFD
        },
    }
    # NB: 0x010f/0x0110 use format ASCII (2); add it to value packers.
    blob = b.build([ifd0, exif_ifd, gps_ifd])

    with open(sys.argv[1], 'wb') as f:
        f.write(blob)
    print(f'wrote {len(blob)} bytes to {sys.argv[1]}')
    return 0


# ASCII (string) format code is 2; teach the value packer about it.
def _ascii_patch():
    orig = BigTiffBuilder._value_bytes

    def _value_bytes(self, fmt, count, payload):
        if fmt == 2:  # ASCII
            return payload if isinstance(payload, bytes) else payload.encode()
        return orig(self, fmt, count, payload)

    BigTiffBuilder._value_bytes = _value_bytes


_ascii_patch()


if __name__ == '__main__':
    sys.exit(main())
