//! Faithful port of `Image::ExifTool::FLAC` (lib/Image/ExifTool/FLAC.pm).
//! ProcessFLAC reads `fLaC` magic + a chain of metadata blocks
//! (FLAC.pm:239-280); the StreamInfo block is decoded by the shared
//! `bitstream::process_bit_stream`; VorbisComment blocks are decoded by an
//! inline faithful port of `Vorbis::ProcessComments` (Vorbis.pm:157-210).

use crate::parser::{FormatParser, ParseContext};
use crate::tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv};
use crate::value::TagValue;

// ----- %FLAC::StreamInfo (FLAC.pm:59-82) -----------------------------------

/// FLAC.pm:70,74 — `ValueConv => '$val + 1'`. Applied to Channels (Bit100-
/// 102) and BitsPerSample (Bit103-107). Pure on `TagValue::I64`; falls
/// through unchanged for any other variant (an unexpected non-I64 here
/// means the bit-stream integer-accumulation path didn't produce I64 —
/// propagate, don't panic).
fn streaminfo_add_one(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::I64(n.saturating_add(1)),
    other => other.clone(),
  }
}

/// FLAC.pm:80 — `ValueConv => 'unpack("H*",$val)'`. Bit144-271 (MD5Signature)
/// carries `Format => 'undef'` (FLAC.pm:79); `process_bit_stream` emits the
/// raw 16 bytes as `TagValue::Bytes`; this fn renders them as lowercase
/// hex exactly as Perl's `unpack("H*", ...)` does (two hex digits per byte).
fn streaminfo_unpack_h_star(v: &TagValue) -> TagValue {
  match v {
    TagValue::Bytes(b) => {
      use std::fmt::Write as _;
      let mut s = String::with_capacity(b.len() * 2);
      for x in b {
        // Lowercase, two hex digits per byte — exact Perl `unpack("H*",…)`.
        // `write!` into a pre-sized `String` is allocation-free (one byte
        // pair per iteration), unlike `format!` which allocates a fresh
        // `String` each call.
        let _ = write!(&mut s, "{x:02x}");
      }
      TagValue::Str(s.into())
    }
    other => other.clone(),
  }
}

// FLAC.pm:63  'Bit000-015' => 'BlockSizeMin'
static FLAC_BLOCK_SIZE_MIN: TagDef =
  TagDef::new("BlockSizeMin", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:64  'Bit016-031' => 'BlockSizeMax'
static FLAC_BLOCK_SIZE_MAX: TagDef =
  TagDef::new("BlockSizeMax", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:65  'Bit032-055' => 'FrameSizeMin'
static FLAC_FRAME_SIZE_MIN: TagDef =
  TagDef::new("FrameSizeMin", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:66  'Bit056-079' => 'FrameSizeMax'
static FLAC_FRAME_SIZE_MAX: TagDef =
  TagDef::new("FrameSizeMax", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:67  'Bit080-099' => 'SampleRate'
static FLAC_SAMPLE_RATE: TagDef =
  TagDef::new("SampleRate", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:68-71  'Bit100-102' => { Name => 'Channels', ValueConv => '$val + 1' }
static FLAC_CHANNELS: TagDef = TagDef::new(
  "Channels",
  "FLAC",
  ValueConv::Func(streaminfo_add_one),
  PrintConv::None,
);
// FLAC.pm:72-75  'Bit103-107' => { Name => 'BitsPerSample', ValueConv => '$val + 1' }
static FLAC_BITS_PER_SAMPLE: TagDef = TagDef::new(
  "BitsPerSample",
  "FLAC",
  ValueConv::Func(streaminfo_add_one),
  PrintConv::None,
);
// FLAC.pm:76  'Bit108-143' => 'TotalSamples'
static FLAC_TOTAL_SAMPLES: TagDef =
  TagDef::new("TotalSamples", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:77-81  'Bit144-271' => { Name => 'MD5Signature', Format => 'undef',
//                                   ValueConv => 'unpack("H*",$val)' }
static FLAC_MD5_SIGNATURE: TagDef = TagDef::new(
  "MD5Signature",
  "FLAC",
  ValueConv::Func(streaminfo_unpack_h_star),
  PrintConv::None,
)
.with_format("undef"); // FLAC.pm:79

fn flac_streaminfo_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("Bit000-015") => Some(&FLAC_BLOCK_SIZE_MIN),
    TagId::Str("Bit016-031") => Some(&FLAC_BLOCK_SIZE_MAX),
    TagId::Str("Bit032-055") => Some(&FLAC_FRAME_SIZE_MIN),
    TagId::Str("Bit056-079") => Some(&FLAC_FRAME_SIZE_MAX),
    TagId::Str("Bit080-099") => Some(&FLAC_SAMPLE_RATE),
    TagId::Str("Bit100-102") => Some(&FLAC_CHANNELS),
    TagId::Str("Bit103-107") => Some(&FLAC_BITS_PER_SAMPLE),
    TagId::Str("Bit108-143") => Some(&FLAC_TOTAL_SAMPLES),
    TagId::Str("Bit144-271") => Some(&FLAC_MD5_SIGNATURE),
    _ => None,
  }
}

/// Faithful `%Image::ExifTool::FLAC::StreamInfo` (FLAC.pm:59-82).
/// `group0 = "FLAC"`; family-1 also `"FLAC"` (the Perl module-name suffix —
/// confirmed by the bundled-ExifTool oracle on `FLAC.flac` → JSON keys
/// `"FLAC:BlockSizeMin"`, …). FLAC.pm:62 `GROUPS => { 2 => 'Audio' }` is
/// family-2 (category) and is not emitted under `-G1`.
pub static FLAC_STREAMINFO_TABLE: TagTable = TagTable::new("FLAC", flac_streaminfo_get);

// TEMPLATE: keep FLAC_STREAMINFO_BIT_KEYS in sync with flac_streaminfo_get's
// `Bit*` arms AND in ascending zero-padded bit-offset order —
// `bitstream::process_bit_stream`'s `i2 >= dirLen` early-exit silently
// skips later fields if mis-ordered (per the AAC-pathfinder template note).
/// The 9 `Bit<a>-<b>` keys of `%FLAC::StreamInfo` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order (required by
/// `bitstream::process_bit_stream`).
pub const FLAC_STREAMINFO_BIT_KEYS: &[&str] = &[
  "Bit000-015", // BlockSizeMin   (FLAC.pm:63)
  "Bit016-031", // BlockSizeMax   (FLAC.pm:64)
  "Bit032-055", // FrameSizeMin   (FLAC.pm:65)
  "Bit056-079", // FrameSizeMax   (FLAC.pm:66)
  "Bit080-099", // SampleRate     (FLAC.pm:67)
  "Bit100-102", // Channels       (FLAC.pm:68)
  "Bit103-107", // BitsPerSample  (FLAC.pm:72)
  "Bit108-143", // TotalSamples   (FLAC.pm:76)
  "Bit144-271", // MD5Signature   (FLAC.pm:77)
];

// ----- %FLAC::Picture (FLAC.pm:84-134) -------------------------------------
// R1-F3 port. ExifTool models a FLAC Picture metadata block (block_type 6)
// as a binary record processed by `ProcessBinaryData` with `FORMAT =>
// 'int32u'` (FLAC.pm:84-87). Layout (per FLAC spec + the `%FLAC::Picture`
// hash + the bundled `var_pstr32` Format handler at ExifTool.pm:10000):
//
//   index 0:  PictureType            int32u BE
//   index 1:  PictureMIMEType        var_pstr32 (4 BE len + UTF-8 bytes)
//   index 2:  PictureDescription     var_pstr32 (4 BE len + UTF-8 bytes)
//   index 3:  PictureWidth           int32u BE
//   index 4:  PictureHeight          int32u BE
//   index 5:  PictureBitsPerPixel    int32u BE
//   index 6:  PictureIndexedColors   int32u BE
//   index 7:  PictureLength          int32u BE
//   index 8:  Picture                undef[$val{7}]  (raw bytes)
//
// The same `%FLAC::Picture` table is also reused by Vorbis.pm's
// `METADATA_BLOCK_PICTURE` (Vorbis.pm:122-135), where the value is
// base64-decoded first then parsed via the same binary layout (R1-F3
// further down: `process_vorbis_metadata_block_picture`).

// FLAC.pm:88-113 — PictureType + 21-entry PrintConv. (Note: duplicated
// in ID3, ASF and FLAC modules, per the Perl comment at FLAC.pm:90.)
static FLAC_PICTURE_TYPE: TagDef = TagDef::new(
  "PictureType",
  "FLAC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Other")),
    ("1", PrintValue::Str("32x32 PNG Icon")),
    ("2", PrintValue::Str("Other Icon")),
    ("3", PrintValue::Str("Front Cover")),
    ("4", PrintValue::Str("Back Cover")),
    ("5", PrintValue::Str("Leaflet")),
    ("6", PrintValue::Str("Media")),
    ("7", PrintValue::Str("Lead Artist")),
    ("8", PrintValue::Str("Artist")),
    ("9", PrintValue::Str("Conductor")),
    ("10", PrintValue::Str("Band")),
    ("11", PrintValue::Str("Composer")),
    ("12", PrintValue::Str("Lyricist")),
    ("13", PrintValue::Str("Recording Studio or Location")),
    ("14", PrintValue::Str("Recording Session")),
    ("15", PrintValue::Str("Performance")),
    ("16", PrintValue::Str("Capture from Movie or Video")),
    ("17", PrintValue::Str("Bright(ly) Colored Fish")),
    ("18", PrintValue::Str("Illustration")),
    ("19", PrintValue::Str("Band Logo")),
    ("20", PrintValue::Str("Publisher Logo")),
  ])),
);
// FLAC.pm:115-117 — `1 => { Name => 'PictureMIMEType', Format => 'var_pstr32' }`.
static FLAC_PICTURE_MIME: TagDef =
  TagDef::new("PictureMIMEType", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:118-122 — `2 => { Name => 'PictureDescription', Format =>
// 'var_pstr32', ValueConv => '$self->Decode($val, "UTF8")' }`. The
// Decode is a no-op for our UTF-8 input (we already store strings as
// UTF-8); the per-spec faithful behavior matches.
static FLAC_PICTURE_DESC: TagDef = TagDef::new(
  "PictureDescription",
  "FLAC",
  ValueConv::None,
  PrintConv::None,
);
// FLAC.pm:123 — `3 => 'PictureWidth'` (int32u, default ValueConv/PrintConv).
static FLAC_PICTURE_WIDTH: TagDef =
  TagDef::new("PictureWidth", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:124 — `4 => 'PictureHeight'`.
static FLAC_PICTURE_HEIGHT: TagDef =
  TagDef::new("PictureHeight", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:125 — `5 => 'PictureBitsPerPixel'`.
static FLAC_PICTURE_BPP: TagDef = TagDef::new(
  "PictureBitsPerPixel",
  "FLAC",
  ValueConv::None,
  PrintConv::None,
);
// FLAC.pm:126 — `6 => 'PictureIndexedColors'`.
static FLAC_PICTURE_INDEXED: TagDef = TagDef::new(
  "PictureIndexedColors",
  "FLAC",
  ValueConv::None,
  PrintConv::None,
);
// FLAC.pm:127 — `7 => 'PictureLength'`.
static FLAC_PICTURE_LENGTH: TagDef =
  TagDef::new("PictureLength", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:128-133 — `8 => { Name => 'Picture', Groups => { 2 => 'Preview' },
// Format => 'undef[$val{7}]', Binary => 1 }`. Family-2 'Preview' is not
// emitted under `-G1`; the family-1 default is the module suffix "FLAC".
static FLAC_PICTURE_DATA: TagDef = TagDef::new("Picture", "FLAC", ValueConv::None, PrintConv::None);

/// Decode a FLAC Picture block body (the bytes BETWEEN the FLAC metadata-
/// block header and the next block — for `block_type==6`, OR the bytes of
/// a base64-decoded `METADATA_BLOCK_PICTURE` Vorbis comment). Faithful to
/// `%FLAC::Picture` (FLAC.pm:84-134) processed by `ProcessBinaryData` with
/// `FORMAT => 'int32u'` + the `var_pstr32` Format handler at
/// `ExifTool.pm:10000`.
///
/// Group identity: family-0 `"FLAC"`, family-1 `"FLAC"` (matches the
/// bundled-Perl JSON key prefix `"FLAC:Picture*"` observed via `perl
/// exiftool -j -G1`).
///
/// Returns `true` on a complete parse; `false` on a truncation (the FLAC
/// Picture handler in bundled ExifTool silently truncates — `last if
/// $more < 4` at `ExifTool.pm:10001` — and emits no warning). On
/// truncation any tags emitted BEFORE the truncated field stay; the
/// caller can ignore the bool.
fn process_flac_picture(
  payload: &[u8],
  into: &mut crate::value::Metadata,
  print_conv_enabled: bool,
) -> bool {
  use crate::convert::apply;
  use crate::value::Group;

  let g = || Group::new("FLAC", "FLAC");
  let end = payload.len();
  let mut pos: usize = 0;

  // -- index 0: PictureType (int32u BE) -------------------------------------
  if end < pos + 4 {
    return false;
  }
  let pic_type = u32::from_be_bytes([
    payload[pos],
    payload[pos + 1],
    payload[pos + 2],
    payload[pos + 3],
  ]) as i64;
  pos += 4;
  let shown = apply(
    &FLAC_PICTURE_TYPE,
    &TagValue::I64(pic_type),
    print_conv_enabled,
  );
  into.push(g(), FLAC_PICTURE_TYPE.name(), shown);

  // -- index 1: PictureMIMEType (var_pstr32) --------------------------------
  // ExifTool.pm:10001-10005 — `last if $more < 4`; `$count = Get32u`; advance
  // by `$count` bytes (faithful: a corrupt length silently truncates the
  // remaining fields).
  let Some(mime) = read_var_pstr32(payload, &mut pos) else {
    return false;
  };
  let shown = apply(
    &FLAC_PICTURE_MIME,
    &TagValue::Str(mime.into()),
    print_conv_enabled,
  );
  into.push(g(), FLAC_PICTURE_MIME.name(), shown);

  // -- index 2: PictureDescription (var_pstr32, UTF-8) ----------------------
  let Some(desc) = read_var_pstr32(payload, &mut pos) else {
    return false;
  };
  let shown = apply(
    &FLAC_PICTURE_DESC,
    &TagValue::Str(desc.into()),
    print_conv_enabled,
  );
  into.push(g(), FLAC_PICTURE_DESC.name(), shown);

  // -- indices 3..7: 5 × int32u BE -----------------------------------------
  let int_defs: [&'static TagDef; 5] = [
    &FLAC_PICTURE_WIDTH,
    &FLAC_PICTURE_HEIGHT,
    &FLAC_PICTURE_BPP,
    &FLAC_PICTURE_INDEXED,
    &FLAC_PICTURE_LENGTH,
  ];
  let mut picture_len: usize = 0;
  for (i, def) in int_defs.iter().enumerate() {
    if end < pos + 4 {
      return false;
    }
    let n = u32::from_be_bytes([
      payload[pos],
      payload[pos + 1],
      payload[pos + 2],
      payload[pos + 3],
    ]) as i64;
    pos += 4;
    if i == 4 {
      // PictureLength = $val{7}; remember for the Picture binary read.
      picture_len = n.max(0) as usize;
    }
    let shown = apply(def, &TagValue::I64(n), print_conv_enabled);
    into.push(g(), def.name(), shown);
  }

  // -- index 8: Picture (undef[$val{7}]) ------------------------------------
  // FLAC.pm:131 `Picture => undef[$val{7}]` routes through bundled
  // `ExifTool::ReadValue` (ExifTool.pm:6275-6321) with `$count = $val{7}`
  // (PictureLength) and `$len = 1` (undef byte). ExifTool.pm:6290-6293
  // clamps the count when `$len * $count > $size`:
  //     $count = int($size / $len);   # shorten count if necessary
  //     $count < 1 and return undef;  # return undefined if no data
  // So a too-large PictureLength does NOT drop the field — it emits the
  // partial bytes that actually fit (R2-F3 fix). Only when ZERO bytes
  // remain (count clamped to 0) does ReadValue return undef and no
  // Picture tag is emitted; and a `PictureLength == 0` separately falls
  // through the `unless ($count)` arm (ExifTool.pm:6285-6287) and returns
  // an empty string — still a valid emission.
  let remaining = end.saturating_sub(pos);
  let actual = picture_len.min(remaining);
  if actual == 0 && picture_len > 0 {
    // ExifTool.pm:6292 `count < 1 and return undef`: declared > 0 but no
    // payload byte left ⇒ no Picture tag at all.
  } else {
    let bytes = payload[pos..pos + actual].to_vec();
    // `Binary => 1` (FLAC.pm:132) ⇒ TagValue::Bytes — the serializer
    // renders it as `(Binary data N bytes, use -b option to extract)`.
    // (No trailing `pos += actual` — Picture is the last sub-field of the
    // Picture block, so further reads are gated by the next caller's own
    // `payload`/`end` setup.)
    into.push(g(), FLAC_PICTURE_DATA.name(), TagValue::Bytes(bytes));
  }

  true
}

/// Faithful Rust port of `Image::ExifTool::XMP::DecodeBase64` (XMP.pm:2978-
/// 3011). The Perl version applies TWO permissive passes before the actual
/// uudecode loop:
///
/// 1. `XMP.pm:2988` `$str =~ s/[^A-Za-z0-9+\/= \t\n\r\f].*//s`  — truncate
///    at the first character outside the `[A-Za-z0-9+/= \t\n\r\f]` set.
///    Everything from that character onward is discarded.
/// 2. `XMP.pm:2990` `$str =~ tr/A-Za-z0-9+\/= \t\n\r\f/ -_/d`  — translate
///    the surviving characters to their uuencoded equivalents. The `/d`
///    flag DELETES any source char whose target index falls past the end
///    of the 64-char target range ` ` (sp, 0x20) .. `_` (0x5F). The source
///    list has 71 chars; only the first 64 (`A-Za-z0-9+/`) get translated,
///    so the trailing 7 (`=`, space, tab, LF, CR, FF) are DELETED outright
///    before the uudecode runs. R2-F4 fix: this is why `"AA==AA"` decodes
///    to 3 zero bytes — the two internal `=`s are deleted, the cleaned
///    input becomes `"AAAA"`, and the uudecode loop produces 3 bytes.
///
/// Returns the decoded bytes. Always returns a `Vec` (never panics); an
/// empty or malformed input yields an empty / partial decode just as Perl
/// does (the binary placeholder serializes as 0 bytes — harmless).
fn decode_base64(s: &str) -> Vec<u8> {
  // Pass-1 truncate + pass-2 strip happen TOGETHER as a single linear scan:
  // for each byte, either it is a base64 alphabet char (kept), `=` or
  // whitespace (dropped — Perl's `tr/.../d` deletion), or anything else
  // (break — Perl's `s/[^...].*//s` truncate). This is byte-equivalent to
  // running the two Perl passes back-to-back over ASCII input. Non-ASCII
  // bytes are NOT in the allowed set, so they trigger truncate, matching
  // Perl's behavior on a raw byte stream.
  let val = |c: u8| -> Option<u8> {
    match c {
      b'A'..=b'Z' => Some(c - b'A'),
      b'a'..=b'z' => Some(26 + (c - b'a')),
      b'0'..=b'9' => Some(52 + (c - b'0')),
      b'+' => Some(62),
      b'/' => Some(63),
      _ => None,
    }
  };
  let mut quartet: [u8; 4] = [0; 4];
  let mut q_len: usize = 0;
  let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4);
  for &b in s.as_bytes() {
    // `=` AND whitespace (sp, tab, LF, CR, FF) are in the allowed alphabet
    // (XMP.pm:2988 truncate pass) BUT the `tr/.../d` (XMP.pm:2990) deletes
    // them before uudecoding. So they DON'T break the loop — they're
    // silently dropped, and decoding continues past them.
    if b == b'=' || matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
      continue;
    }
    let Some(v) = val(b) else {
      // First non-alphabet, non-`=`, non-whitespace char: faithful Perl
      // truncate (XMP.pm:2988 — everything from here on is discarded).
      break;
    };
    quartet[q_len] = v;
    q_len += 1;
    if q_len == 4 {
      out.push((quartet[0] << 2) | (quartet[1] >> 4));
      out.push((quartet[1] << 4) | (quartet[2] >> 2));
      out.push((quartet[2] << 6) | quartet[3]);
      q_len = 0;
    }
  }
  // Handle partial quartet (Perl's last-partial-chunk arm, XMP.pm:3005-
  // 3009). A 2-char tail → 1 byte; a 3-char tail → 2 bytes; q_len == 4
  // is already consumed above.
  if q_len >= 2 {
    out.push((quartet[0] << 2) | (quartet[1] >> 4));
  }
  if q_len >= 3 {
    out.push((quartet[1] << 4) | (quartet[2] >> 2));
  }
  out
}

/// Read a `var_pstr32` field: 4-byte BE length + that many UTF-8 bytes.
/// Returns the decoded `String` and advances `*pos` past the field, or
/// `None` if either the length-word or the payload is truncated.
fn read_var_pstr32(payload: &[u8], pos: &mut usize) -> Option<String> {
  let end = payload.len();
  if end < *pos + 4 {
    return None;
  }
  let len = u32::from_be_bytes([
    payload[*pos],
    payload[*pos + 1],
    payload[*pos + 2],
    payload[*pos + 3],
  ]) as usize;
  *pos += 4;
  if len > end.saturating_sub(*pos) {
    return None;
  }
  let bytes = &payload[*pos..*pos + len];
  *pos += len;
  // FLAC.pm:121 `$self->Decode($val, "UTF8")` — invalid UTF-8 falls back to
  // U+FFFD replacement (Perl's Decode with UTF8 is similarly lossy by
  // default in lax mode).
  Some(String::from_utf8_lossy(bytes).to_string())
}

// ----- %Vorbis::Comments (Vorbis.pm:72-135) -------------------------------
// Faithful named-tag subset for FLAC's VorbisComment block (block_type 4).
// COVERART (the deprecated base64 cover-art comment, Vorbis.pm:122-128) is
// implemented in `process_vorbis_comments` below: base64-decode +
// `TagValue::Bytes` emission, paired with the optional COVERARTMIME tag.
// METADATA_BLOCK_PICTURE (Vorbis.pm:130-134) emits the recursive-warning
// fallback (the embedded FLAC Picture block extraction is DEFERRED — needs
// XMP::DecodeBase64 + a recursive ProcessBinaryData call; the warning gates
// it faithfully). The auto-name path (Vorbis.pm:188-196) is implemented in
// `process_vorbis_comments` (the function below); it does not require a
// table entry.
//
// Family-0 group "Vorbis" (mirrors the Perl module-name suffix; confirmed
// by the bundled-ExifTool oracle on FLAC.flac: JSON keys "Vorbis:Vendor"
// etc.). Family-1 also "Vorbis" — none of these entries carry a Perl
// `Groups => { 1 => ... }` override (Vorbis.pm:80-121), so the family-1
// default (module-name suffix) applies.
//
// Vorbis.pm uses `Groups => { 2 => 'Author' | 'Time' | 'Location' |
// 'Preview' }` on a handful of entries (ARTIST/PERFORMER/COPYRIGHT/LICENSE/
// ORGANIZATION/CONTACT, DATE, LOCATION, COVERART). Family-2 is not emitted
// under `-G1`, so we record it only in the comment cites, not in `TagDef`.

static V_VENDOR: TagDef = TagDef::new("Vendor", "Vorbis", ValueConv::None, PrintConv::None);
static V_TITLE: TagDef = TagDef::new("Title", "Vorbis", ValueConv::None, PrintConv::None);
static V_VERSION: TagDef = TagDef::new("Version", "Vorbis", ValueConv::None, PrintConv::None);
static V_ALBUM: TagDef = TagDef::new("Album", "Vorbis", ValueConv::None, PrintConv::None);
static V_TRACKNUMBER: TagDef =
  TagDef::new("TrackNumber", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:85 — `ARTIST => { ..., List => 1 }` (R1-F2). Multiple ARTIST
// Vorbis comments accumulate into a TagValue::List via push_listable.
static V_ARTIST: TagDef =
  TagDef::new("Artist", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
// Vorbis.pm:86 — `PERFORMER => { ..., List => 1 }` (R1-F2).
static V_PERFORMER: TagDef =
  TagDef::new("Performer", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
static V_COPYRIGHT: TagDef = TagDef::new("Copyright", "Vorbis", ValueConv::None, PrintConv::None);
static V_LICENSE: TagDef = TagDef::new("License", "Vorbis", ValueConv::None, PrintConv::None);
static V_ORGANIZATION: TagDef =
  TagDef::new("Organization", "Vorbis", ValueConv::None, PrintConv::None);
static V_DESCRIPTION: TagDef =
  TagDef::new("Description", "Vorbis", ValueConv::None, PrintConv::None);
static V_GENRE: TagDef = TagDef::new("Genre", "Vorbis", ValueConv::None, PrintConv::None);
static V_DATE: TagDef = TagDef::new("Date", "Vorbis", ValueConv::None, PrintConv::None);
static V_LOCATION: TagDef = TagDef::new("Location", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:94 — `CONTACT => { ..., List => 1 }` (R1-F2).
static V_CONTACT: TagDef =
  TagDef::new("Contact", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
static V_ISRC: TagDef = TagDef::new("ISRCNumber", "Vorbis", ValueConv::None, PrintConv::None);
static V_COVERARTMIME: TagDef = TagDef::new(
  "CoverArtMIMEType",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_TRACK_PEAK: TagDef = TagDef::new(
  "ReplayGainTrackPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_TRACK_GAIN: TagDef = TagDef::new(
  "ReplayGainTrackGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_ALBUM_PEAK: TagDef = TagDef::new(
  "ReplayGainAlbumPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_ALBUM_GAIN: TagDef = TagDef::new(
  "ReplayGainAlbumGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_ENCODED_USING: TagDef =
  TagDef::new("EncodedUsing", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODED_BY: TagDef = TagDef::new("EncodedBy", "Vorbis", ValueConv::None, PrintConv::None);
static V_COMMENT: TagDef = TagDef::new("Comment", "Vorbis", ValueConv::None, PrintConv::None);
static V_DIRECTOR: TagDef = TagDef::new("Director", "Vorbis", ValueConv::None, PrintConv::None);
static V_PRODUCER: TagDef = TagDef::new("Producer", "Vorbis", ValueConv::None, PrintConv::None);
static V_COMPOSER: TagDef = TagDef::new("Composer", "Vorbis", ValueConv::None, PrintConv::None);
static V_ACTOR: TagDef = TagDef::new("Actor", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODER: TagDef = TagDef::new("Encoder", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODER_OPTIONS: TagDef =
  TagDef::new("EncoderOptions", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:97-105 — `COVERART => { Name => 'CoverArt', Binary => 1,
// Groups => { 2 => 'Preview' }, ValueConv => Image::ExifTool::XMP::
// DecodeBase64($val) }`. The base64 decode happens at push time; the
// TagDef itself just declares the destination name. R1-F3.
static V_COVERART: TagDef = TagDef::new("CoverArt", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:122-135 — `METADATA_BLOCK_PICTURE => { Name => 'Picture',
// Binary => 1, RawConv => DecodeBase64, SubDirectory => FLAC::Picture }`.
// We DO NOT actually parse the sub-fields here: bundled ExifTool's
// `ProcessDirectory` recursion guard (ExifTool.pm:9056-9059) ALWAYS
// fires on this SubDirectory ("Picture pointer references previous
// VorbisComment directory") because the base64-decoded data's DataPos
// collides with the parent VorbisComment directory's PROCESSED address.
// Faithful disposition (verified via `perl exiftool -j` on a synthetic
// `METADATA_BLOCK_PICTURE` fixture, 2026-05-20): emit ONLY the warning,
// NO sub-fields. We expose the tag in the lookup so the dispatch in
// `process_vorbis_comments` knows to switch to the warning branch.
static V_METADATA_BLOCK_PICTURE: TagDef =
  TagDef::new("Picture", "Vorbis", ValueConv::None, PrintConv::None);

/// Single source of truth for the named-key set of
/// `%Image::ExifTool::Vorbis::Comments` (Vorbis.pm:72-135), in spec order
/// (`vendor` first, then user-comment keys; R1-F3 binary-blob keys last).
///
/// Both `vorbis_comments_get` (the static `TagTable` lookup, fed `TagId::Str`
/// literals at call sites) and `lookup_vorbis_named` (the runtime-key
/// trampoline used when the source key arrives as an owned `String`) consult
/// this slice — adding/removing a key here automatically flows through both
/// pathways, eliminating the drift risk Copilot flagged.
const VORBIS_NAMED_TAGS: &[(&str, &TagDef)] = &[
  // Vorbis.pm:80 — `vendor` is the ONLY lowercase key (set as the first
  // entry of every comment block; not a user-comment key).
  ("vendor", &V_VENDOR),
  ("TITLE", &V_TITLE),
  ("VERSION", &V_VERSION),
  ("ALBUM", &V_ALBUM),
  ("TRACKNUMBER", &V_TRACKNUMBER),
  ("ARTIST", &V_ARTIST),
  ("PERFORMER", &V_PERFORMER),
  ("COPYRIGHT", &V_COPYRIGHT),
  ("LICENSE", &V_LICENSE),
  ("ORGANIZATION", &V_ORGANIZATION),
  ("DESCRIPTION", &V_DESCRIPTION),
  ("GENRE", &V_GENRE),
  ("DATE", &V_DATE),
  ("LOCATION", &V_LOCATION),
  ("CONTACT", &V_CONTACT),
  ("ISRC", &V_ISRC),
  ("COVERARTMIME", &V_COVERARTMIME),
  ("REPLAYGAIN_TRACK_PEAK", &V_REPLAYGAIN_TRACK_PEAK),
  ("REPLAYGAIN_TRACK_GAIN", &V_REPLAYGAIN_TRACK_GAIN),
  ("REPLAYGAIN_ALBUM_PEAK", &V_REPLAYGAIN_ALBUM_PEAK),
  ("REPLAYGAIN_ALBUM_GAIN", &V_REPLAYGAIN_ALBUM_GAIN),
  ("ENCODED_USING", &V_ENCODED_USING),
  ("ENCODED_BY", &V_ENCODED_BY),
  ("COMMENT", &V_COMMENT),
  ("DIRECTOR", &V_DIRECTOR),
  ("PRODUCER", &V_PRODUCER),
  ("COMPOSER", &V_COMPOSER),
  ("ACTOR", &V_ACTOR),
  ("ENCODER", &V_ENCODER),
  ("ENCODER_OPTIONS", &V_ENCODER_OPTIONS),
  // R1-F3 (Vorbis.pm:97-105,122-135). COVERART base64-decodes to a binary
  // image blob; METADATA_BLOCK_PICTURE emits the recursion warning (see
  // V_METADATA_BLOCK_PICTURE doc).
  ("COVERART", &V_COVERART),
  ("METADATA_BLOCK_PICTURE", &V_METADATA_BLOCK_PICTURE),
];

fn vorbis_comments_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str(key) => VORBIS_NAMED_TAGS
      .iter()
      .find(|(k, _)| *k == key)
      .map(|(_, def)| *def),
    _ => None,
  }
}

/// Faithful `%Image::ExifTool::Vorbis::Comments` (Vorbis.pm:72-135), subset.
/// `group0 = "Vorbis"`; family-1 also `"Vorbis"`. See `vorbis_comments_get`
/// for the named tag map and the in-code provenance comments.
pub static VORBIS_COMMENTS_TABLE: TagTable = TagTable::new("Vorbis", vorbis_comments_get);

// ----- Vorbis::ProcessComments (Vorbis.pm:157-210) -------------------------

/// Derive a tag name from an unknown Vorbis comment key per Vorbis.pm:190-193:
/// ```text
/// my $name = ucfirst(lc($tag));
/// $name =~ s/[^\w-]+(.?)/\U$1/sg;
/// $name =~ s/([a-z0-9])_([a-z])/$1\U$2/g;
/// ```
///
/// Perl `\w` here is ASCII word `[A-Za-z0-9_]`; `-` is literally allowed.
/// All operations are on the lowercased name; the trailing `g` flag means
/// the transform is applied to every non-overlapping match left-to-right.
fn vorbis_derive_name(tag: &str) -> String {
  // Step 1: lowercase, then ucfirst (uppercase the first character).
  let lc: String = tag.chars().flat_map(char::to_lowercase).collect();
  let ucfirst: String = {
    let mut cs = lc.chars();
    match cs.next() {
      Some(c) => c.to_uppercase().chain(cs).collect::<String>(),
      None => String::new(),
    }
  };
  // Step 2: s/[^\w-]+(.?)/\U$1/sg — for each run of non-word/non-`-` chars,
  // drop the run; if a follower exists, uppercase that single character
  // (the `(.?)` captures zero or one follower).
  let after_step2: String = {
    let chars: Vec<char> = ucfirst.chars().collect();
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
      if is_word(chars[i]) {
        out.push(chars[i]);
        i += 1;
      } else {
        // Skip the run.
        while i < chars.len() && !is_word(chars[i]) {
          i += 1;
        }
        // Uppercase the next char (if any) — the `(.?)` capture.
        if i < chars.len() {
          for c in chars[i].to_uppercase() {
            out.push(c);
          }
          i += 1;
        }
      }
    }
    out
  };
  // Step 3: s/([a-z0-9])_([a-z])/$1\U$2/g — iterate non-overlapping; the
  // matched `_` is dropped and the following lowercase letter is upper-
  // cased.
  let chars: Vec<char> = after_step2.chars().collect();
  let mut out = String::with_capacity(chars.len());
  let mut i = 0;
  while i < chars.len() {
    if i + 2 < chars.len()
      && (chars[i].is_ascii_lowercase() || chars[i].is_ascii_digit())
      && chars[i + 1] == '_'
      && chars[i + 2].is_ascii_lowercase()
    {
      out.push(chars[i]);
      for c in chars[i + 2].to_uppercase() {
        out.push(c);
      }
      i += 3;
    } else {
      out.push(chars[i]);
      i += 1;
    }
  }
  out
}

/// Lookup `tag` (uppercase, EXCEPT the literal `vendor`) against the
/// named entries of the static `VORBIS_COMMENTS_TABLE`. Returns
/// `Some(&'static TagDef)` only for the keys `vorbis_comments_get`
/// recognizes; otherwise `None`.
///
/// We can't pass an owned `String` directly to `TagId::Str(&'static str)`,
/// so this helper walks the [`VORBIS_NAMED_TAGS`] slice — the same single
/// source of truth that `vorbis_comments_get` consults — and re-routes
/// through the static table when a match is found, so the key set lives in
/// exactly one place.
fn lookup_vorbis_named(tag: &str) -> Option<&'static TagDef> {
  let static_key = VORBIS_NAMED_TAGS.iter().find(|(k, _)| *k == tag)?.0;
  (VORBIS_COMMENTS_TABLE.get())(TagId::Str(static_key))
}

/// Faithful port of `Image::ExifTool::Vorbis::ProcessComments` (Vorbis.pm:
/// 157-210), scoped to the FLAC VorbisComment-block consumer.
///
/// Returns `true` (Perl `return 1`, Vorbis.pm:205) on success, `false`
/// (`return 0`, :209) on a malformed comment (and pushes
/// `Warn('Format error in Vorbis comments')`, :208).
///
/// Layout per Vorbis spec + the Perl: u32 LE vendor-length, vendor bytes,
/// u32 LE count, then `count` comments each `u32 LE length + UTF-8 bytes`
/// of the form `KEY=VALUE` (split on the FIRST `=`).
///
/// Faithful to the Perl `last if $pos + 4 > $end` (Vorbis.pm:168) /
/// `last if $pos + 4 + $len > $end` (:170): a truncated payload terminates
/// the loop without emitting beyond the truncation point — and without
/// panicking under `#![forbid(unsafe_code)]`.
///
/// NOTE on the panic-free arithmetic: Vorbis.pm uses signed-Perl
/// `$pos + 4 + $len > $end`; transliterating that into `pos + 4 + len > end`
/// in Rust `usize` would overflow when `len` is near `u32::MAX`. Per
/// `[[exifast-phase2-forward-items]]` we reorder to subtraction on the
/// known-larger operand: `len > end.saturating_sub(pos)` (verified
/// value-equivalent to the Perl test for all `0 ≤ pos ≤ end` and
/// `0 ≤ len ≤ u32::MAX`).
pub(crate) fn process_vorbis_comments(
  payload: &[u8],
  into: &mut crate::value::Metadata,
  print_conv_enabled: bool,
) -> bool {
  use crate::convert::apply;
  use crate::value::Group;

  let end = payload.len();
  let mut pos: usize = 0;

  // -- Vendor (Vorbis.pm:181-187) -------------------------------------------
  // `$pos + 4 > $end` ⇒ terminate (loop's `last`). Without a vendor the
  // outer `for(;;)` exits and Warn+return 0 fires (Vorbis.pm:208-209).
  if pos + 4 > end {
    into.push_warning("Format error in Vorbis comments");
    return false;
  }
  let vendor_len = u32::from_le_bytes([
    payload[pos],
    payload[pos + 1],
    payload[pos + 2],
    payload[pos + 3],
  ]) as usize;
  pos += 4;
  // `$pos + $len > $end` (post-increment; equivalent to checking
  // `len > end - pos` panic-free).
  if vendor_len > end.saturating_sub(pos) {
    into.push_warning("Format error in Vorbis comments");
    return false;
  }
  let vendor_bytes = &payload[pos..pos + vendor_len];
  pos += vendor_len;
  // Decode as UTF-8 (Vorbis.pm:197 `$et->Decode($val,'UTF8')`).
  let vendor = String::from_utf8_lossy(vendor_bytes).to_string();
  // Push Vendor via the table so future ValueConv/PrintConv additions
  // funnel through `convert::apply`.
  let v_def = lookup_vorbis_named("vendor").expect("vendor entry is in the table");
  let shown = apply(v_def, &TagValue::Str(vendor.into()), print_conv_enabled);
  into.push(
    Group::new(VORBIS_COMMENTS_TABLE.group0(), v_def.group1()),
    v_def.name(),
    shown,
  );

  // -- Count (Vorbis.pm:184) ------------------------------------------------
  // `$num = ($pos + 4 < $end) ? Get32u($dataPt, $pos) : 0;` — STRICT `<` per
  // Vorbis.pm:184 (Round-1 codex F4). A payload with EXACTLY 4 trailing
  // bytes after the vendor satisfies `pos+4 == end` but `pos+4 < end` is
  // FALSE: $num stays 0, the loop body never runs, ProcessComments returns
  // 1 (Vorbis.pm:205 `num-- or return 1`). The earlier `<=` form treated
  // that exact-4-byte case as a real count → spurious "Format error in
  // Vorbis comments" warning. Faithful reorder to subtraction on the
  // known-non-negative side per [[exifast-phase2-forward-items]]: `pos+4
  // < end` ≡ `4 < end-pos` panic-free (no `usize` overflow).
  let num: usize = if 4 < end.saturating_sub(pos) {
    let n = u32::from_le_bytes([
      payload[pos],
      payload[pos + 1],
      payload[pos + 2],
      payload[pos + 3],
    ]) as usize;
    pos += 4;
    n
  } else {
    0
  };

  // -- Comments (Vorbis.pm:175-203) -----------------------------------------
  for _ in 0..num {
    if pos + 4 > end {
      // Vorbis.pm:168 — truncated mid-header: faithful `last` then Warn.
      into.push_warning("Format error in Vorbis comments");
      return false;
    }
    let len = u32::from_le_bytes([
      payload[pos],
      payload[pos + 1],
      payload[pos + 2],
      payload[pos + 3],
    ]) as usize;
    pos += 4;
    if len > end.saturating_sub(pos) {
      // Vorbis.pm:170 — truncated mid-value.
      into.push_warning("Format error in Vorbis comments");
      return false;
    }
    let comment = &payload[pos..pos + len];
    pos += len;
    // Vorbis.pm:176 `$buff =~ /(.*?)=(.*)/s or last` — split on FIRST `=`.
    let Some(eq) = comment.iter().position(|&b| b == b'=') else {
      into.push_warning("Format error in Vorbis comments"); // :208
      return false; // :209 return 0
    };
    let (key_bytes, val_bytes) = (&comment[..eq], &comment[eq + 1..]);
    // Vorbis.pm:177 `($tag, $val) = (uc $1, $2)` — uppercase the key.
    // ASCII-only (Vorbis tag keys are always ASCII per the spec).
    let tag_upper: String = key_bytes
      .iter()
      .map(|&b| {
        if b.is_ascii_lowercase() {
          (b - 0x20) as char
        } else {
          b as char
        }
      })
      .collect();
    let val = String::from_utf8_lossy(val_bytes).to_string();
    // R1-F3: COVERART + METADATA_BLOCK_PICTURE need pre-table-lookup special
    // handling because they perform base64 decoding (Vorbis.pm:97-105 +
    // :122-135). For COVERART the decoded bytes become a `TagValue::Bytes`
    // (rendered as `(Binary data N bytes, use -b option to extract)`).
    // For METADATA_BLOCK_PICTURE bundled ExifTool's recursion guard fires
    // on the SubDirectory (ExifTool.pm:9056-9059), emitting ONLY a Warning
    // — we mirror that exactly.
    if tag_upper == "COVERART" {
      let bytes = decode_base64(&val);
      // Family-1 default = module name "Vorbis"; no Groups override on
      // Vorbis.pm:97-99 affects family-1. CoverArt is family-2 "Preview"
      // which is not emitted under -G1.
      into.push(
        Group::new(VORBIS_COMMENTS_TABLE.group0(), V_COVERART.group1()),
        V_COVERART.name(),
        TagValue::Bytes(bytes),
      );
      continue;
    }
    if tag_upper == "METADATA_BLOCK_PICTURE" {
      // Bundled ExifTool ProcessDirectory recursion guard (ExifTool.pm:
      // 9057): the FLAC::Picture SubDirectory of a base64-decoded
      // METADATA_BLOCK_PICTURE invariably references the parent
      // VorbisComment directory's PROCESSED address, so the
      // `$dirName pointer references previous $$self{PROCESSED}{$addr}
      // directory` warning fires with $dirName = 'Picture' and the
      // previous-dirName 'VorbisComment'. Verified via `perl exiftool -j
      // -G1` on a synthetic fixture; the Picture sub-fields are NEVER
      // emitted under default options. Faithful disposition: emit only
      // the warning.
      into.push_warning("Picture pointer references previous VorbisComment directory");
      continue;
    }

    // Vorbis.pm:189 `unless ($$tagTablePtr{$tag}) { ... AddTagToTable(...) }`.
    // We don't actually mutate the table at runtime (it is `&'static`);
    // we emit with the derived name + group1 "Vorbis" — byte-equivalent JSON.
    let raw = TagValue::Str(val.into());
    if let Some(def) = lookup_vorbis_named(&tag_upper) {
      let shown = apply(def, &raw, print_conv_enabled);
      let group = Group::new(VORBIS_COMMENTS_TABLE.group0(), def.group1());
      if def.list() {
        // R1-F2: ExifTool.pm:9605-9606 / :9518-9520 — a `List => 1` tagInfo
        // accumulates same-(group, name) repeats into a single list-valued
        // tag. Vorbis.pm:85,86,94 flag ARTIST/PERFORMER/CONTACT as List.
        into.push_listable(group, def.name(), shown);
      } else {
        into.push(group, def.name(), shown);
      }
    } else {
      let derived = vorbis_derive_name(&tag_upper);
      // family-1 defaults to the module name (group0) when no Groups
      // override. The unknown-tag branch in Vorbis.pm:189-194 calls
      // `AddTagToTable($tagTablePtr, $tag, { Name => $name })` — the new
      // tagInfo carries `Name` ONLY, no `List` key, so repeats are
      // first-wins via `%noDups`. Plain `push` (not listable) preserves
      // that behavior faithfully.
      into.push(
        Group::new(
          VORBIS_COMMENTS_TABLE.group0(),
          VORBIS_COMMENTS_TABLE.group0(),
        ),
        derived,
        raw,
      );
    }
  }
  true // Vorbis.pm:205 `num-- or return 1` (after the last comment).
}

/// FLAC parser (faithful `ProcessFLAC`, FLAC.pm:239-280). D8 unit struct.
///
/// The `process` body:
///   1. If the payload starts with an `ID3` v2 tag (FLAC.pm:243-247), skip
///      the ID3v2 header (10 bytes + synchsafe payload length, plus the
///      v2.4 footer if its flag is set) and continue parsing the post-ID3
///      substream. Full ID3 content extraction is DEFERRED to the parallel
///      ID3 pathfinder PR (TODO(flac-id3-full)) — for now we extract the
///      FLAC tags only, but the file is no longer rejected outright.
///   2. Validates the `fLaC` magic (FLAC.pm:254).
///   3. Calls `SetFileType` (FLAC.pm:255) ⇒ pushes `File:FileType=FLAC`
///      + `File:FileTypeExtension=FLAC` + `File:MIMEType=audio/flac`.
///   4. Walks the metadata-block chain (FLAC.pm:258-277), dispatching by
///      block_type:
///        - 0 StreamInfo → shared `bitstream::process_bit_stream`.
///        - 1 Padding / 3 SeekTable / 5 CueSheet → skip (Binary+Unknown).
///        - 2 Application → ApplicationUnknown skip (the "riff" arm is
///          DEFERRED — RIFF.pm not ported; the FLAC.flac fixture has none).
///        - 4 VorbisComment → `process_vorbis_comments`.
///        - 6 Picture → `process_flac_picture` (hand-rolled
///          ProcessBinaryData substitute for the `%FLAC::Picture` table).
///        - 7..=126 Reserved, 127 Invalid → no entry in %FLAC::Main; skip.
///   5. On truncated block read, sets `err=1`, breaks (FLAC.pm:263).
///   6. Post-loop: `err ⇒ Warn('Format error in FLAC file')` (FLAC.pm:278).
///   7. Returns `true` unconditionally (FLAC.pm:279 `return 1`).
pub struct ProcessFlac;

impl FormatParser for ProcessFlac {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // -- ID3v2-prefix skip + magic check (no &mut ctx yet) --------------------
    // We compute the post-ID3 offset and validate the `fLaC` magic against
    // an immutable ctx.data() borrow that lives only for this block; the
    // mutating ctx.set_file_type / ctx.metadata() calls run after.
    //
    // R1-F1: ID3-in-FLAC dispatch (FLAC.pm:243-247).
    //
    //    unless ($$et{DoneID3}) {
    //        require Image::ExifTool::ID3;
    //        Image::ExifTool::ID3::ProcessID3($et, $dirInfo) and return 1;
    //    }
    //
    // Bundled `ID3::ProcessID3` consumes the ID3v2 header (10 bytes + the
    // synchsafe-encoded payload length, plus the extended-header bytes if
    // the extended-header flag is set in byte 5) and then either returns 1
    // (full-ID3 content extraction) OR falls through; on fall-through the
    // RAF is positioned just past the ID3v2 tag and `ProcessFLAC` continues
    // from there. exifast cannot port full ID3 content extraction here
    // (D11-deriving) — that's deferred to the ID3 pathfinder PR per
    // [[exifast-phase2-forward-items]]. But we CAN faithfully skip the
    // ID3v2 header so the `fLaC` magic check + metadata-block loop run on
    // the post-ID3 substream. JSON output of an ID3-prefixed FLAC then
    // reflects the FLAC tags WITHOUT the ID3 tags — but at least the file
    // is no longer rejected with no extraction.
    //
    // ID3v2 header (ID3v2.3/2.4 spec):
    //   bytes 0..3:  "ID3"
    //   byte  3:     major version (e.g. 3 or 4; reject 0xFF)
    //   byte  4:     revision     (reject 0xFF)
    //   byte  5:     flags (bit 6 = extended header)
    //   bytes 6..10: synchsafe 28-bit length — each byte's high bit is 0,
    //                low 7 bits combined big-endian.
    //
    // TODO(flac-id3-full): once the ID3 pathfinder PR lands, replace the
    // skip below with a call into ProcessID3 (which will emit ID3 content
    // tags before this loop), then continue parsing FLAC from the same
    // post-ID3 offset.
    //
    // TODO(flac-id3-ext-hdr): if byte-5 bit-6 (extended header flag) is
    // set, the extended header occupies 6-10 extra bytes whose length is
    // also synchsafe-encoded at bytes 10..14. We CURRENTLY treat that case
    // as "skip the basic 10+size only" — a faithful no-op for typical
    // ID3v2.3 tags (no extended header) and the bundled `FLAC.flac` etc.
    // Pre-ID3 PR test fixtures don't trip the extended-header bit; if a
    // real fixture lands here later the bundled-Perl golden will diverge
    // and we'll patch this arm.
    let (offset, flac_magic_ok) = {
      let data = ctx.data();
      let mut o: usize = 0;
      if data.len() >= 10 && data.starts_with(b"ID3") {
        // R1-F1 ID3-prefix skip. Reject impossible version/revision values
        // (matches ID3.pm's `if ($vers > 0xff) ...` pre-flight; we just
        // need to avoid being fooled by junk that happens to start "ID3").
        let major = data[3];
        let minor = data[4];
        // R2-F1 — capture the flags byte for the v2.4-footer test below
        // (ID3.pm:1455 `unpack('nCN', $hBuff)` ⇒ flags is the 6th byte of
        // the header, i.e. data[5]).
        let flags = data[5];
        // Synchsafe 28-bit size: bytes 6..10.
        let b6 = data[6];
        let b7 = data[7];
        let b8 = data[8];
        let b9 = data[9];
        // Each high bit MUST be 0 in synchsafe encoding; if any is set the
        // claimed length is not a synchsafe ID3 size — bail conservatively
        // (don't skip, let the `fLaC` magic check below reject normally).
        if major != 0xff && minor != 0xff && (b6 | b7 | b8 | b9) & 0x80 == 0 {
          let size =
            (u32::from(b6) << 21) | (u32::from(b7) << 14) | (u32::from(b8) << 7) | u32::from(b9);
          // 10-byte header + payload. Saturating to data.len() so a corrupt
          // size doesn't underflow on the post-skip read.
          let mut advance = 10usize.saturating_add(size as usize);
          // R2-F1: ID3.pm:1484-1487 — `if ($flags & 0x10) { $raf->Seek(10,
          // 1); }` — skip an additional 10 bytes for the optional v2.4
          // footer. ID3.pm applies this unconditionally on `$flags & 0x10`;
          // although the comment annotates it as "v2.4 footer", the code
          // does not gate on the version field. We mirror the CODE faithfully
          // (the comment is an author note, not a guard). The footer is
          // NOT counted in `id3Len` (ID3.pm:1496 = `length($hBuff) + 10`,
          // header bytes only) — that detail matters when File:ID3Size
          // becomes a thing in the ID3 pathfinder PR; here we only need
          // the seek to make sure the `fLaC` magic check at offset `o`
          // lands past the footer.
          if flags & 0x10 != 0 {
            advance = advance.saturating_add(10);
          }
          o = advance.min(data.len());
        }
      }
      // FLAC.pm:254 — `$raf->Read($buff, 4) == 4 and $buff eq 'fLaC' or
      // return 0`. After the ID3 skip (if any) the next 4 bytes must be
      // the `fLaC` magic; otherwise reject.
      let ok = data.len() >= o + 4 && &data[o..o + 4] == b"fLaC";
      (o, ok)
    };
    if !flac_magic_ok {
      return false;
    }

    // FLAC.pm:255 — `$et->SetFileType()` (no-arg ⇒ detected = "FLAC").
    ctx.set_file_type(None, None, None);
    // FLAC.pm:256 — `SetByteOrder('MM')`. No-op on our process_bit_stream
    // call (BitOrder::Mm passed explicitly below).

    let print_on = ctx.print_conv_enabled();
    let mut err = false;
    let mut pos: usize = offset + 4; // past optional-ID3-skip + 'fLaC'

    // FLAC.pm:258-277 — `for (;;) { ... last if $last; }`.
    //
    // Each iteration extracts the next block as a `(block_type, range,
    // is_last)` triple, releases the immutable `ctx.data()` borrow, then
    // dispatches via the match arms (which may borrow `ctx.metadata()`
    // mutably). This split is exactly how the AAC port handles the same
    // borrow constraint (see src/formats/aac.rs filler scan).
    loop {
      // Step 1: parse the header + payload range against an immutable
      // ctx.data() borrow that lives only for the scope of this block.
      let (block_type, payload_start, payload_end, is_last) = {
        let data = ctx.data();
        // FLAC.pm:260 — `$raf->Read($buff, 4) == 4 or last`. Truncated
        // header ⇒ silent exit (no $err set; Perl `or last`).
        if pos + 4 > data.len() {
          break;
        }
        let header = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
        pos += 4;
        // FLAC.pm:261 — `my $flag = unpack('C', $buff)`.
        let flag = header[0];
        // FLAC.pm:262 — `my $size = unpack('N', $buff) & 0x00ffffff`.
        let size = (u32::from_be_bytes(header) & 0x00ff_ffff) as usize;
        // FLAC.pm:264 — `$last = $flag & 0x80`.
        let last = (flag & 0x80) != 0;
        // FLAC.pm:265 — `$tag = $flag & 0x7f` (block_type).
        let btype = flag & 0x7f;
        // FLAC.pm:263 — `$raf->Read($buff, $size) == $size or $err = 1, last`.
        // Panic-free: saturating_sub avoids `usize` underflow per the
        // [[exifast-phase2-forward-items]] underflow-footgun guidance.
        if size > data.len().saturating_sub(pos) {
          err = true;
          break;
        }
        let start = pos;
        let end_ = pos + size;
        pos = end_;
        (btype, start, end_, last)
      };

      // Step 2: dispatch on block_type — these arms may borrow ctx mutably.
      // FLAC.pm:270 `$et->HandleTag($tagTablePtr, $tag, $buff, ...)`.
      match block_type {
        // FLAC.pm:27-30 — `0 => StreamInfo` (subdirectory to %FLAC::StreamInfo,
        // PROCESS_PROC = ProcessBitStream, GROUPS => { 2 => Audio }).
        0 => {
          // Split-borrow data + metadata simultaneously so process_bit_stream
          // gets the payload as a borrowed slice (no Vec clone).
          let (data, meta) = ctx.data_and_metadata();
          crate::bitstream::process_bit_stream(
            &data[payload_start..payload_end],
            crate::bitstream::BitOrder::Mm,
            FLAC_STREAMINFO_BIT_KEYS,
            &FLAC_STREAMINFO_TABLE,
            meta,
            print_on,
          );
        }
        // FLAC.pm:31 — `1 => Padding` (Binary+Unknown → skip).
        1 => {}
        // FLAC.pm:32-44 — `2 => Application` (two-arm Condition).
        // The "riff" arm (FLAC.pm:33-39 `$$valPt =~ /^riff(?!RIFF)/`) →
        // RIFF::Main subdirectory is DEFERRED (RIFF.pm not ported in
        // Phase-2; the FLAC.flac fixture has no Application block).
        // ApplicationUnknown (FLAC.pm:40-44) is Binary+Unknown → skip.
        // TODO(flac-riff-app): port the "riff" arm when RIFF.pm lands.
        2 => {}
        // FLAC.pm:45 — `3 => SeekTable` (Binary+Unknown → skip).
        3 => {}
        // FLAC.pm:46-49 — `4 => VorbisComment` (subdirectory to %Vorbis::Comments).
        4 => {
          // Vorbis.pm:208-209 already pushes the warning + returns 0 on
          // malformed input; the FLAC loop has no `last` after a sub-
          // directory error (FLAC.pm:270-275 is a plain HandleTag call),
          // so the loop continues to the next block.
          let (data, meta) = ctx.data_and_metadata();
          let _ok = process_vorbis_comments(&data[payload_start..payload_end], meta, print_on);
        }
        // FLAC.pm:50 — `5 => CueSheet` (Binary+Unknown → skip).
        5 => {}
        // FLAC.pm:51-54 — `6 => Picture` (subdirectory to %FLAC::Picture).
        // R1-F3 port: hand-rolled ProcessBinaryData substitute for the
        // FORMAT='int32u' + var_pstr32 table (FLAC.pm:84-134); see
        // `process_flac_picture`. The bundled ExifTool ProcessBinaryData
        // engine is not in Phase-2 yet, but the Picture record's binary
        // layout is fully derivable from the tagInfo offsets + Format
        // attribute — a single faithful by-derivation entry point.
        6 => {
          let (data, meta) = ctx.data_and_metadata();
          let _ok = process_flac_picture(&data[payload_start..payload_end], meta, print_on);
        }
        // FLAC.pm:55-56 — 7..=126 Reserved, 127 Invalid. Skip.
        _ => {}
      }

      // FLAC.pm:276 — `last if $last`.
      if is_last {
        break;
      }
    }

    // FLAC.pm:278 — `$err and $et->Warn('Format error in FLAC file')`.
    if err {
      ctx.metadata().push_warning("Format error in FLAC file");
    }
    // R2-F2: emit Composite:Duration faithfully per FLAC.pm:137-149
    // `%FLAC::Composite` — Duration = `($val[0] and $val[1]) ? $val[1] /
    // $val[0] : undef` (TotalSamples / SampleRate) with `PrintConv =>
    // 'ConvertDuration($val)'`. Only computed when BOTH FLAC:TotalSamples
    // and FLAC:SampleRate are truthy (>0) — matches the Perl `and`-guard.
    //
    // SCOPE: this is a SMALL format-local emission, NOT a shared composite
    // engine. The first multi-format composite-consumer port (e.g. RIFF,
    // QuickTime) will derive the shared shape — extracting the (group, name,
    // formula, value_conv, print_conv) tuple into a reusable table. Deferring
    // here keeps the seam tiny and avoids speculating on the table shape.
    emit_flac_composite_duration(ctx.metadata(), print_on);
    // FLAC.pm:279 — `return 1`.
    true
  }
}

/// Emit `Composite:Duration` per FLAC.pm:137-149 when both
/// `FLAC:TotalSamples` and `FLAC:SampleRate` were extracted (truthy ⇒ > 0).
/// `print_on` selects the PrintConv (default) vs raw `-n` value:
///
/// * `print_on == true` ⇒ `ConvertDuration($val)` (`ExifTool.pm:6866-6884`)
///   formatted string (`"S.SS s"` for `$time < 30`, `"H:MM:SS"` otherwise);
/// * `print_on == false` ⇒ raw float (`F64`) — `EscapeJSON`
///   (`exiftool:3809`) emits `30.0` as bare `30`, `1.543125` as bare
///   `1.543125`. Our serializer's `push_numeric_gated` handles that same
///   gate.
fn emit_flac_composite_duration(meta: &mut crate::value::Metadata, print_on: bool) {
  // Faithful lookup: scan tags() for the FLAC:TotalSamples and
  // FLAC:SampleRate just emitted from StreamInfo. The accessor returns
  // them in extraction order — finding both is O(N) but N is tiny (the
  // StreamInfo table has 9 entries total).
  let mut total_samples: Option<i64> = None;
  let mut sample_rate: Option<i64> = None;
  for tag in meta.tags() {
    if tag.group().family1() != "FLAC" {
      continue;
    }
    match tag.name() {
      "TotalSamples" => {
        if let TagValue::I64(n) = tag.value() {
          total_samples = Some(*n);
        }
      }
      "SampleRate" => {
        if let TagValue::I64(n) = tag.value() {
          sample_rate = Some(*n);
        }
      }
      _ => {}
    }
  }
  // FLAC.pm:143 `($val[0] and $val[1]) ? $val[1] / $val[0] : undef` —
  // BOTH must be truthy (non-zero). Negative values are not possible
  // for these fields (StreamInfo unpacks them from bit slices ⇒ always
  // non-negative), so the `> 0` test is faithful to Perl `and`.
  let (Some(ts), Some(sr)) = (total_samples, sample_rate) else {
    return;
  };
  if ts <= 0 || sr <= 0 {
    return;
  }
  // FLAC.pm:143 ValueConv: `$val[1] / $val[0]` ⇒ TotalSamples / SampleRate
  // as a Perl scalar (float-promoted by the `/` operator).
  let duration = (ts as f64) / (sr as f64);
  // FLAC.pm:138-145 emits as `Composite:Duration` (Composite group 0+1).
  // Group identity: family-0 "Composite", family-1 "Composite"
  // (ExifTool.pm:2293 `GROUPS => { 0 => 'Composite', 1 => 'Composite' }`).
  let group = crate::value::Group::new("Composite", "Composite");
  if print_on {
    // PrintConv: ConvertDuration (ExifTool.pm:6866-6884) — see the
    // `convert_duration` helper for the faithful arithmetic + format.
    let formatted = convert_duration(duration);
    meta.push(group, "Duration", TagValue::Str(formatted.into()));
  } else {
    // -n / raw mode: emit the bare numeric. The serializer's F64 path
    // routes through `push_numeric_gated` ⇒ `format_g(_, 15)` ⇒ bundled
    // EscapeJSON-compatible token (e.g. `30`, `1.543125`).
    meta.push(group, "Duration", TagValue::F64(duration));
  }
}

/// Faithful Rust port of `Image::ExifTool::ConvertDuration` (`ExifTool.pm:
/// 6866-6884`). Inputs `< 30` seconds format as `"S.SS s"`; otherwise as
/// `"[D days ][-]H:MM:SS"` after a `+0.5` rounding step.
fn convert_duration(time: f64) -> String {
  // ExifTool.pm:6869 `return $time unless IsFloat($time)`: our caller
  // already coerces to f64, and IsFloat accepts all finite numerics, so
  // there's no string-passthrough fallback to mirror here.
  if !time.is_finite() {
    return time.to_string();
  }
  // ExifTool.pm:6870 `return '0 s' if $time == 0`.
  if time == 0.0 {
    return "0 s".to_string();
  }
  // ExifTool.pm:6871 `my $sign = ($time > 0 ? '' : (($time = -$time), '-'))`.
  let (sign, mut t) = if time > 0.0 { ("", time) } else { ("-", -time) };
  // ExifTool.pm:6872 `return sprintf("$sign%.2f s", $time) if $time < 30`.
  if t < 30.0 {
    return format!("{sign}{t:.2} s");
  }
  // ExifTool.pm:6873 `$time += 0.5;   # to round off to nearest second`.
  t += 0.5;
  let mut h = (t / 3600.0).trunc() as i64;
  t -= (h as f64) * 3600.0;
  let m = (t / 60.0).trunc() as i64;
  t -= (m as f64) * 60.0;
  // ExifTool.pm:6878-6882 — multi-day formatting.
  let mut day_prefix = String::new();
  if h > 24 {
    let d = h / 24;
    h -= d * 24;
    day_prefix = format!("{sign}{d} days ");
  }
  let sec = t.trunc() as i64;
  // ExifTool.pm:6883 `return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time))`.
  if day_prefix.is_empty() {
    format!("{sign}{h}:{m:02}:{sec:02}")
  } else {
    format!("{day_prefix}{h}:{m:02}:{sec:02}")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn streaminfo_table_is_faithful_to_flac_pm() {
    // FLAC.pm:59-82: nine bit-field tags + the family-0 / family-1 group.
    let g = FLAC_STREAMINFO_TABLE.get();
    assert_eq!(FLAC_STREAMINFO_TABLE.group0(), "FLAC");
    // The 9 names + their bit-keys, in ASCENDING bit-offset order (required
    // by process_bit_stream's i2 >= dirLen early-exit).
    assert_eq!(g(TagId::Str("Bit000-015")).unwrap().name(), "BlockSizeMin"); // FLAC.pm:63
    assert_eq!(g(TagId::Str("Bit016-031")).unwrap().name(), "BlockSizeMax"); // FLAC.pm:64
    assert_eq!(g(TagId::Str("Bit032-055")).unwrap().name(), "FrameSizeMin"); // FLAC.pm:65
    assert_eq!(g(TagId::Str("Bit056-079")).unwrap().name(), "FrameSizeMax"); // FLAC.pm:66
    assert_eq!(g(TagId::Str("Bit080-099")).unwrap().name(), "SampleRate"); //   FLAC.pm:67
    assert_eq!(g(TagId::Str("Bit100-102")).unwrap().name(), "Channels"); //     FLAC.pm:68
    assert_eq!(g(TagId::Str("Bit103-107")).unwrap().name(), "BitsPerSample"); // FLAC.pm:72
    assert_eq!(g(TagId::Str("Bit108-143")).unwrap().name(), "TotalSamples"); //  FLAC.pm:76
    assert_eq!(g(TagId::Str("Bit144-271")).unwrap().name(), "MD5Signature"); //  FLAC.pm:77
                                                                             // Channels + BitsPerSample carry a ValueConv (`$val + 1`).
    assert!(matches!(
      g(TagId::Str("Bit100-102")).unwrap().value_conv(),
      ValueConv::Func(_)
    ));
    assert!(matches!(
      g(TagId::Str("Bit103-107")).unwrap().value_conv(),
      ValueConv::Func(_)
    ));
    // MD5Signature has Format=>'undef' + ValueConv (`unpack("H*",$val)`).
    assert_eq!(g(TagId::Str("Bit144-271")).unwrap().format(), Some("undef"));
    assert!(matches!(
      g(TagId::Str("Bit144-271")).unwrap().value_conv(),
      ValueConv::Func(_)
    ));
    // No PrintConv anywhere in %FLAC::StreamInfo.
    for k in FLAC_STREAMINFO_BIT_KEYS {
      assert!(matches!(
        g(TagId::Str(k)).unwrap().print_conv(),
        PrintConv::None
      ));
    }
    // Ascending order (required invariant).
    assert_eq!(
      FLAC_STREAMINFO_BIT_KEYS,
      &[
        "Bit000-015",
        "Bit016-031",
        "Bit032-055",
        "Bit056-079",
        "Bit080-099",
        "Bit100-102",
        "Bit103-107",
        "Bit108-143",
        "Bit144-271",
      ]
    );
    // Unknown keys ⇒ None.
    assert!(g(TagId::Str("Bit999")).is_none());
    assert!(g(TagId::Int(0)).is_none());
  }

  #[test]
  fn vorbis_comments_table_named_tags_are_faithful() {
    // Vorbis.pm:80-121 (subset; CoverArt + METADATA_BLOCK_PICTURE deferred).
    let g = VORBIS_COMMENTS_TABLE.get();
    assert_eq!(VORBIS_COMMENTS_TABLE.group0(), "Vorbis");
    // Direct named entries (all family-1 = "Vorbis", per Perl module-name
    // suffix and confirmed by the bundled oracle on FLAC.flac).
    let cases: &[(&str, &str)] = &[
      ("vendor", "Vendor"),                             // Vorbis.pm:80
      ("TITLE", "Title"),                               // Vorbis.pm:81
      ("VERSION", "Version"),                           // Vorbis.pm:82
      ("ALBUM", "Album"),                               // Vorbis.pm:83
      ("TRACKNUMBER", "TrackNumber"),                   // Vorbis.pm:84
      ("ARTIST", "Artist"),                             // Vorbis.pm:85
      ("PERFORMER", "Performer"),                       // Vorbis.pm:86
      ("COPYRIGHT", "Copyright"),                       // Vorbis.pm:87
      ("LICENSE", "License"),                           // Vorbis.pm:88
      ("ORGANIZATION", "Organization"),                 // Vorbis.pm:89
      ("DESCRIPTION", "Description"),                   // Vorbis.pm:90
      ("GENRE", "Genre"),                               // Vorbis.pm:91
      ("DATE", "Date"),                                 // Vorbis.pm:92
      ("LOCATION", "Location"),                         // Vorbis.pm:93
      ("CONTACT", "Contact"),                           // Vorbis.pm:94
      ("ISRC", "ISRCNumber"),                           // Vorbis.pm:95
      ("COVERARTMIME", "CoverArtMIMEType"),             // Vorbis.pm:96
      ("REPLAYGAIN_TRACK_PEAK", "ReplayGainTrackPeak"), // Vorbis.pm:106
      ("REPLAYGAIN_TRACK_GAIN", "ReplayGainTrackGain"), // Vorbis.pm:107
      ("REPLAYGAIN_ALBUM_PEAK", "ReplayGainAlbumPeak"), // Vorbis.pm:108
      ("REPLAYGAIN_ALBUM_GAIN", "ReplayGainAlbumGain"), // Vorbis.pm:109
      ("ENCODED_USING", "EncodedUsing"),                // Vorbis.pm:111
      ("ENCODED_BY", "EncodedBy"),                      // Vorbis.pm:112
      ("COMMENT", "Comment"),                           // Vorbis.pm:113
      ("DIRECTOR", "Director"),                         // Vorbis.pm:115
      ("PRODUCER", "Producer"),                         // Vorbis.pm:116
      ("COMPOSER", "Composer"),                         // Vorbis.pm:117
      ("ACTOR", "Actor"),                               // Vorbis.pm:118
      ("ENCODER", "Encoder"),                           // Vorbis.pm:120
      ("ENCODER_OPTIONS", "EncoderOptions"),            // Vorbis.pm:121
    ];
    // Vorbis.pm:85,86,94 declare ARTIST, PERFORMER, CONTACT as `List => 1`
    // — every OTHER ported tag has no List key (R1-F2 audit).
    let list_keys = ["ARTIST", "PERFORMER", "CONTACT"];
    for (k, expected_name) in cases {
      let d = g(TagId::Str(k)).unwrap_or_else(|| panic!("missing Vorbis tag {k}"));
      assert_eq!(d.name(), *expected_name, "wrong name for {k}");
      assert_eq!(d.group1(), "Vorbis", "wrong group1 for {k}");
      // None of the ported Vorbis tags carry a PrintConv (verified
      // against the FLAC.flac `-n` and PrintConv-on goldens, which are
      // byte-identical for every Vorbis tag).
      assert!(
        matches!(d.print_conv(), PrintConv::None),
        "{k} has unexpected PrintConv"
      );
      assert!(
        matches!(d.value_conv(), ValueConv::None),
        "{k} has unexpected ValueConv"
      );
      let expect_list = list_keys.contains(k);
      assert_eq!(
        d.list(),
        expect_list,
        "{k}: List flag mismatch (Vorbis.pm:80-121)"
      );
    }
    // R1-F3: COVERART + METADATA_BLOCK_PICTURE are now ported. Confirm
    // they resolve to the faithful tag names (CoverArt + Picture).
    assert_eq!(
      g(TagId::Str("COVERART")).unwrap().name(),
      "CoverArt",
      "Vorbis.pm:97 COVERART maps to Vorbis:CoverArt"
    );
    assert_eq!(
      g(TagId::Str("METADATA_BLOCK_PICTURE")).unwrap().name(),
      "Picture",
      "Vorbis.pm:122 METADATA_BLOCK_PICTURE maps to Vorbis:Picture"
    );
    // Lowercase non-`vendor` keys must miss (Perl uppercases user tags
    // via `uc $1` at Vorbis.pm:177; `vendor` is the only legitimate lc).
    assert!(g(TagId::Str("title")).is_none());
  }

  // Helper: build a synthetic VorbisComment payload (matches the wire
  // format Vorbis.pm:160-207 reads): u32 LE vendor-len, vendor bytes,
  // u32 LE count, then for each comment u32 LE len + UTF-8 bytes.
  fn make_vorbis_payload(vendor: &[u8], comments: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    v.extend_from_slice(vendor);
    v.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for c in comments {
      v.extend_from_slice(&(c.len() as u32).to_le_bytes());
      v.extend_from_slice(c);
    }
    v
  }

  #[test]
  fn vorbis_derive_name_matches_perl_regex_transforms() {
    // Step 3 alone: `s/([a-z0-9])_([a-z])/$1\U$2/g` → underscore drop +
    // next-char uppercase. FOO_BAR → lc=foo_bar → ucfirst=Foo_bar →
    // [no step2 hits, no non-word chars] → step3 'o_b' → 'oB' → 'FooBar'.
    assert_eq!(vorbis_derive_name("FOO_BAR"), "FooBar");
    // Step 2: `s/[^\w-]+(.?)/\U$1/sg` → drop the dot, uppercase 'y'.
    // X.Y → lc=x.y → ucfirst=X.y → step2 matches `.y` → drop `.`, upper 'Y'
    // → "XY". Step 3 has no match.
    assert_eq!(vorbis_derive_name("X.Y"), "XY");
    // Both steps: `FOO BAR_BAZ` → lc=foo bar_baz → ucfirst=Foo bar_baz →
    // step2: ` b` → uppercase B → `FooBar_baz` → step3 `r_b` → `rB` →
    // `FooBarBaz`.
    assert_eq!(vorbis_derive_name("FOO BAR_BAZ"), "FooBarBaz");
    // No transforms: simple lowercase + ucfirst.
    assert_eq!(vorbis_derive_name("HELLO"), "Hello");
    // Empty input: empty out.
    assert_eq!(vorbis_derive_name(""), "");
    // Trailing non-word — drops the run, no follower (the `(.?)` matches
    // zero characters).
    assert_eq!(vorbis_derive_name("FOO."), "Foo");
    // Underscores preserved as `\w` outside the step-3 `_letter` pattern.
    assert_eq!(vorbis_derive_name("FOO_"), "Foo_");
  }

  #[test]
  fn vorbis_process_comments_emits_vendor_and_named_tags() {
    use crate::value::Metadata;
    let payload = make_vorbis_payload(
      b"reference libFLAC 1.1.2 20050205",
      &[b"TITLE=ExifTool test", b"COPYRIGHT=Phil Harvey"],
    );
    let mut m = Metadata::new("FLAC.flac");
    let ok = process_vorbis_comments(&payload, &mut m, true);
    assert!(ok, "well-formed comments must accept");
    // Three tags pushed in order: Vendor, Title, Copyright.
    let names: Vec<_> = m
      .tags()
      .iter()
      .map(|t| (t.group().family1().to_string(), t.name().to_string()))
      .collect();
    assert_eq!(
      names,
      vec![
        ("Vorbis".into(), "Vendor".into()),
        ("Vorbis".into(), "Title".into()),
        ("Vorbis".into(), "Copyright".into()),
      ]
    );
    // Values as UTF-8 strings (Vorbis.pm:197 `$et->Decode($val,'UTF8')`).
    assert_eq!(
      m.tags()[0].value(),
      &TagValue::Str("reference libFLAC 1.1.2 20050205".into())
    );
    assert_eq!(m.tags()[1].value(), &TagValue::Str("ExifTool test".into()));
    assert_eq!(m.tags()[2].value(), &TagValue::Str("Phil Harvey".into()));
  }

  #[test]
  fn vorbis_process_comments_unknown_tag_derives_name() {
    // Vorbis.pm:188-196: unknown tag → derived name + group1 = "Vorbis".
    use crate::value::Metadata;
    let payload = make_vorbis_payload(b"v", &[b"FOO_BAR=42", b"X.Y=z"]);
    let mut m = Metadata::new("x.flac");
    assert!(process_vorbis_comments(&payload, &mut m, true));
    let names: Vec<_> = m
      .tags()
      .iter()
      .filter(|t| t.name() != "Vendor")
      .map(|t| t.name().to_string())
      .collect();
    assert_eq!(names, vec!["FooBar", "XY"]);
    assert_eq!(m.tags()[1].value(), &TagValue::Str("42".into()));
    assert_eq!(m.tags()[2].value(), &TagValue::Str("z".into()));
    // group1 = "Vorbis" for derived tags too (the module's GROUPS default).
    for t in m.tags() {
      assert_eq!(t.group().family1(), "Vorbis");
    }
  }

  #[test]
  fn vorbis_process_comments_format_error_returns_false_with_warning() {
    // Vorbis.pm:176 `$buff =~ /(.*?)=(.*)/s or last` then :208
    // `$et->Warn('Format error in Vorbis comments'); return 0`.
    use crate::value::Metadata;
    let payload = make_vorbis_payload(b"v", &[b"GOOD=ok", b"BADNOEQUALS"]);
    let mut m = Metadata::new("x.flac");
    let ok = process_vorbis_comments(&payload, &mut m, true);
    assert!(
      !ok,
      "missing '=' must return false (Vorbis.pm:208 `return 0`)"
    );
    // Vendor + the good comment got through before the bad one terminated.
    assert!(m.tags().iter().any(|t| t.name() == "Vendor"));
    assert!(m.tags().iter().any(|t| t.name() == "Good"));
    // Warning was pushed exactly once.
    assert_eq!(
      m.warnings()
        .iter()
        .filter(|w| w.as_str() == "Format error in Vorbis comments")
        .count(),
      1
    );
  }

  #[test]
  fn vorbis_process_comments_truncated_no_panic() {
    // A truncated payload (header claims N comments but bytes run out)
    // must NOT panic and must NOT push past the truncation.
    use crate::value::Metadata;
    let mut payload = make_vorbis_payload(b"v", &[b"TITLE=Hello"]);
    payload.truncate(payload.len() - 3); // chop 3 bytes off the value
    let mut m = Metadata::new("x.flac");
    let _ok = process_vorbis_comments(&payload, &mut m, true);
    // Vendor still pushed (it was complete); Title was NOT pushed (the
    // post-length truncation check fired).
    assert!(m.tags().iter().any(|t| t.name() == "Vendor"));
    assert!(!m.tags().iter().any(|t| t.name() == "Title"));
  }

  #[test]
  fn vorbis_process_comments_oversized_length_no_panic() {
    // u32 LE = 0xFFFF_FFFF claimed for a vendor that doesn't fit:
    // must not panic; vendor is not pushed.
    use crate::value::Metadata;
    let mut payload = Vec::new();
    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // huge vendor len
    payload.extend_from_slice(b"only-a-few-bytes");
    let mut m = Metadata::new("x.flac");
    let _ok = process_vorbis_comments(&payload, &mut m, true);
    // No tags pushed; no panic.
    assert!(!m.tags().iter().any(|t| t.name() == "Vendor"));
  }

  #[test]
  fn vorbis_process_comments_exact_4_trailing_bytes_is_clean() {
    // R1-F4 regression pin (Vorbis.pm:184 strict `<`).
    //
    // Layout: vendor_len(4)=1 + vendor(1)="v" + EXACTLY 4 trailing NON-ZERO
    // bytes interpreted (in the buggy `<=` branch) as count=1. Faithful Perl
    // `if ($pos + 4 < $end)` is FALSE here (`pos+4 == end`) so $num stays
    // 0 and the loop body never runs. The earlier `<=` form treated this as
    // a count read of `1`, entered the loop, hit `pos+4 > end` (truncated
    // mid-header), and pushed a spurious "Format error in Vorbis comments"
    // warning (Vorbis.pm:168, :208). Bundled `perl exiftool -j` emits the
    // Vendor only — no Warning.
    use crate::value::Metadata;
    let mut payload = Vec::new();
    payload.extend_from_slice(&(1u32).to_le_bytes()); // vendor len = 1
    payload.push(b'v'); // vendor "v"
                        // pos==5; append exactly 4 bytes — count slot if buggy `<=` is taken;
                        // non-zero so the buggy branch enters the comment loop.
    payload.extend_from_slice(&[0x01u8, 0, 0, 0]); // would-be count=1
    let mut m = Metadata::new("x.flac");
    let ok = process_vorbis_comments(&payload, &mut m, true);
    assert!(
      ok,
      "exact 4 trailing bytes ⇒ count=0 fallthrough ⇒ return 1"
    );
    assert!(m.tags().iter().any(|t| t.name() == "Vendor"));
    assert!(
      !m.warnings()
        .iter()
        .any(|w| w == "Format error in Vorbis comments"),
      "no Format error warning under Vorbis.pm:184 strict `<` (got: {:?})",
      m.warnings()
    );
  }

  #[test]
  fn vorbis_process_comments_empty_payload_warns() {
    // No vendor length at all — faithful to the `last if $pos+4 > $end`
    // loop exit + Warn+return 0 fallthrough.
    use crate::value::Metadata;
    let mut m = Metadata::new("x.flac");
    let ok = process_vorbis_comments(&[], &mut m, true);
    assert!(!ok);
    assert!(m.tags().is_empty());
    assert!(m
      .warnings()
      .iter()
      .any(|w| w == "Format error in Vorbis comments"));
  }

  #[test]
  fn process_flac_rejects_missing_magic() {
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let mut m = Metadata::new("x");
    let data = b"not-fLaC-magic-here";
    let mut c = ParseContext::new(data, "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(
      !ProcessFlac.process(&mut c),
      "missing magic must return false (FLAC.pm:254)"
    );
    // No File:* tags either (SetFileType happens only after magic accepts).
    assert!(m.tags().is_empty());
  }

  #[test]
  fn process_flac_id3_prefix_no_flac_after_rejects() {
    // ID3v2 header + nothing else ⇒ no `fLaC` magic at the post-ID3
    // offset ⇒ reject (FLAC.pm:254). Faithful: bundled ProcessID3
    // returns 0 here, then ProcessFLAC magic test fails.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    // 10-byte ID3v2.3 header with size=0 (no payload).
    let data: &[u8] = &[b'I', b'D', b'3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut m = Metadata::new("x.flac");
    let mut c = ParseContext::new(data, "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(
      !ProcessFlac.process(&mut c),
      "ID3-header with no fLaC after ⇒ reject"
    );
    assert!(m.tags().is_empty());
  }

  #[test]
  fn process_flac_id3_prefix_then_flac_extracts() {
    // R1-F1 regression pin (FLAC.pm:243-247). 10-byte ID3v2.3 header
    // (size=0) immediately followed by `fLaC` + StreamInfo block.
    // Faithful expectation (mirrors bundled `perl exiftool`): skip the
    // ID3 header, the `fLaC` magic test then PASSES, and FLAC tags are
    // emitted as usual.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&[b'I', b'D', b'3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Real FLAC body taken from the FLAC.flac fixture (just the first
    // block: magic + StreamInfo header + 34-byte StreamInfo body, set
    // last-block=1 so the loop exits cleanly).
    let root = env!("CARGO_MANIFEST_DIR");
    let flac = std::fs::read(format!("{root}/tests/fixtures/FLAC.flac")).unwrap();
    // Take the first 8 + 34 = 42 bytes (fLaC + 4-byte block header + 34-byte
    // StreamInfo body) and force the last-block bit so we don't try to
    // parse the subsequent VorbisComment block (it's truncated in this
    // slice).
    let mut prefix = flac[..42].to_vec();
    prefix[4] |= 0x80; // set last-block bit on the StreamInfo header
    data.extend_from_slice(&prefix);
    let mut m = Metadata::new("x.flac");
    let mut c = ParseContext::new(&data, "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(
      ProcessFlac.process(&mut c),
      "post-ID3 `fLaC` magic must accept and continue parsing"
    );
    // File:FileType=FLAC pushed.
    assert!(m
      .tags()
      .iter()
      .any(|t| t.name() == "FileType" && t.value() == &TagValue::Str("FLAC".into())));
    // StreamInfo tag(s) emitted from the post-ID3 body.
    assert!(
      m.tags().iter().any(|t| t.name() == "BlockSizeMin"),
      "must emit FLAC StreamInfo after ID3-prefix skip"
    );
    // No ExifTool:Error finalization should be triggered.
    assert!(m.errors().is_empty(), "no ExifTool:Error: {:?}", m.errors());
  }

  #[test]
  fn process_flac_streaminfo_only_emits_correct_tags() {
    // Real FLAC.flac fixture (282 bytes) — sanity-check that ProcessFlac
    // wires StreamInfo + VorbisComment correctly. Full conformance is
    // asserted by tests/conformance.rs against the bundled-Perl golden.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/FLAC.flac")).unwrap();
    let mut m = Metadata::new("FLAC.flac");
    let mut c = ParseContext::new(&data, "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(ProcessFlac.process(&mut c));
    let n = |s: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == s)
        .map(|t| t.value().clone())
    };
    // File:* triplet first (SetFileType, FLAC.pm:255).
    assert_eq!(n("FileType"), Some(TagValue::Str("FLAC".into())));
    // StreamInfo tags (FLAC.pm:59-82).
    assert_eq!(n("BlockSizeMin"), Some(TagValue::I64(4608)));
    assert_eq!(n("BlockSizeMax"), Some(TagValue::I64(4608)));
    assert_eq!(n("FrameSizeMin"), Some(TagValue::I64(16_777_215)));
    assert_eq!(n("FrameSizeMax"), Some(TagValue::I64(0)));
    assert_eq!(n("SampleRate"), Some(TagValue::I64(8000)));
    assert_eq!(n("Channels"), Some(TagValue::I64(2))); // raw 1 + 1
    assert_eq!(n("BitsPerSample"), Some(TagValue::I64(8))); // raw 7 + 1
    assert_eq!(n("TotalSamples"), Some(TagValue::I64(0)));
    assert_eq!(
      n("MD5Signature"),
      Some(TagValue::Str("d41d8cd98f00b204e9800998ecf8427e".into()))
    );
    // VorbisComment tags (Vorbis.pm:80-121).
    assert_eq!(
      n("Vendor"),
      Some(TagValue::Str("reference libFLAC 1.1.2 20050205".into()))
    );
    assert_eq!(n("Title"), Some(TagValue::Str("ExifTool test".into())));
    assert_eq!(n("Copyright"), Some(TagValue::Str("Phil Harvey".into())));
    // No warnings on a clean fixture.
    assert!(m.warnings().is_empty());
  }

  #[test]
  fn process_flac_truncated_block_emits_format_error_warning() {
    // FLAC.pm:263 `$raf->Read($buff,$size) == $size or $err = 1, last;`
    // FLAC.pm:278 `$err and $et->Warn('Format error in FLAC file')`.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/bad_flac.flac")).unwrap();
    let mut m = Metadata::new("bad_flac.flac");
    let mut c = ParseContext::new(&data, "FLAC", 0, "FLAC", None, true, &mut m);
    // FLAC.pm:279 — return 1 unconditionally after the loop.
    assert!(ProcessFlac.process(&mut c));
    // SetFileType fired (FLAC.pm:255).
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    // Warning recorded with the exact Perl string.
    assert!(m
      .warnings()
      .iter()
      .any(|w| w == "Format error in FLAC file"));
  }

  #[test]
  fn process_flac_panics_free_on_truncated_header() {
    // 4-byte file (just `fLaC`) → magic OK → loop reads, sees pos+4 > len
    // → silent exit → return 1 with no err warning, just the File:* triplet.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let mut m = Metadata::new("tiny.flac");
    let mut c = ParseContext::new(b"fLaC", "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(ProcessFlac.process(&mut c));
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    assert!(m.warnings().is_empty()); // no Format error: clean `or last`
  }

  #[test]
  fn process_flac_oversized_block_sets_err() {
    // `fLaC` + 4-byte header: flag=0x80 (is_last, StreamInfo), size=0xFFFFFF.
    // Body absent → err=1 → Warn fires.
    use crate::parser::ParseContext;
    use crate::value::Metadata;
    let mut m = Metadata::new("oversized.flac");
    let data: &[u8] = &[b'f', b'L', b'a', b'C', 0x80, 0xff, 0xff, 0xff];
    let mut c = ParseContext::new(data, "FLAC", 0, "FLAC", None, true, &mut m);
    assert!(ProcessFlac.process(&mut c));
    assert!(m
      .warnings()
      .iter()
      .any(|w| w == "Format error in FLAC file"));
  }

  #[test]
  fn convert_duration_matches_exiftool_pm() {
    // R2-F2: faithful port of ExifTool::ConvertDuration (ExifTool.pm:6866-
    // 6884). Cross-checked against bundled `perl -MImage::ExifTool -e
    // 'print Image::ExifTool::ConvertDuration(...)'` for each case.
    assert_eq!(convert_duration(0.0), "0 s");
    // < 30 s ⇒ '%.2f s'.
    assert_eq!(convert_duration(1.543125), "1.54 s");
    assert_eq!(convert_duration(29.999), "30.00 s"); // rounds up below 30
                                                     // == 30 ⇒ H:MM:SS arm (+0.5 round, int → 30s).
    assert_eq!(convert_duration(30.0), "0:00:30");
    // Hour boundary.
    assert_eq!(convert_duration(3600.0), "1:00:00");
    // Multi-day formatting (>24h).
    assert_eq!(convert_duration(86400.0 * 2.0 + 3661.0), "2 days 1:01:01");
    // Negative durations (sign-flag arm).
    assert_eq!(convert_duration(-1.543125), "-1.54 s");
    assert_eq!(convert_duration(-30.0), "-0:00:30");
  }

  #[test]
  fn decode_base64_matches_perl_decodebase64() {
    // R1-F3 + R2-F4: faithful XMP::DecodeBase64 (XMP.pm:2978-3011). Two
    // Perl-specific passes (XMP.pm:2988, :2990) before the actual decode:
    //   (1) `s/[^A-Za-z0-9+\/= \t\n\r\f].*//s`  — truncate at first char
    //       outside the alphabet set;
    //   (2) `tr/A-Za-z0-9+\/= \t\n\r\f/ -_/d`  — translate the kept chars
    //       to uuencoded form; with `/d`, both `=` and whitespace get
    //       DELETED before decoding.
    // That second pass is the key behaviour that R2-F4 callers depend on
    // (and that previously broke our `"AA==AA"` case): internal `=` is
    // dropped, decoding continues past it.
    assert_eq!(decode_base64(""), Vec::<u8>::new());
    // "Cat" → "Q2F0" (no padding needed for 3 bytes).
    assert_eq!(decode_base64("Q2F0"), b"Cat");
    // "fish" → "ZmlzaA==" (1 byte of padding); we accept the `=`.
    assert_eq!(decode_base64("ZmlzaA=="), b"fish");
    // Whitespace tolerance.
    assert_eq!(decode_base64("Q 2 F\n0"), b"Cat");
    // Truncate at first non-alphabet char (Perl `s/[^...].*//s`).
    assert_eq!(decode_base64("Q2F0!garbage"), b"Cat");
    // Missing padding still decodes the bytes we can: "Cat" → "Q2F0".
    assert_eq!(decode_base64("Q2F"), b"Ca"); // 3 base64 chars → 2 bytes
                                             // R2-F4: internal padding is DELETED, decoding continues past it.
                                             // "AA==AA" — Perl `tr/.../d` deletes both `=`s, leaving "AAAA" which
                                             // decodes to 3 zero bytes (verified against bundled Perl).
    assert_eq!(decode_base64("AA==AA"), [0u8, 0, 0]);
    // "AA==" — `tr/.../d` deletes both `=`s, leaving "AA" which decodes
    // to 1 zero byte (3-base64-char → 2-byte partial chunk halves).
    assert_eq!(decode_base64("AA=="), [0u8]);
    // Whitespace + padding: `tr/.../d` deletes spaces, tabs, newlines,
    // AND `=`s; "  A B \nC==" cleans to "ABC" which decodes to 2 bytes.
    assert_eq!(decode_base64("  A B \nC=="), [0u8, 0x10]);
  }

  #[test]
  fn process_flac_picture_emits_all_subfields() {
    // R1-F3 regression pin (FLAC.pm:84-134). Synthetic Picture block
    // body: pic_type=3, mime="image/png", desc="X", w=8, h=8, bpp=24,
    // indexed=0, data_len=4, data=[0xDE,0xAD,0xBE,0xEF]. Faithful order
    // must produce 9 tags exactly under family-1 = "FLAC".
    use crate::value::Metadata;
    fn be32(n: u32) -> [u8; 4] {
      n.to_be_bytes()
    }
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&be32(3));
    p.extend_from_slice(&be32(9));
    p.extend_from_slice(b"image/png");
    p.extend_from_slice(&be32(1));
    p.extend_from_slice(b"X");
    p.extend_from_slice(&be32(8));
    p.extend_from_slice(&be32(8));
    p.extend_from_slice(&be32(24));
    p.extend_from_slice(&be32(0));
    p.extend_from_slice(&be32(4));
    p.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut m = Metadata::new("x.flac");
    assert!(process_flac_picture(&p, &mut m, true));
    // 9 tags, in faithful FLAC.pm:84-134 order, all under group1="FLAC".
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      vec![
        "PictureType",
        "PictureMIMEType",
        "PictureDescription",
        "PictureWidth",
        "PictureHeight",
        "PictureBitsPerPixel",
        "PictureIndexedColors",
        "PictureLength",
        "Picture",
      ]
    );
    for t in m.tags() {
      assert_eq!(t.group().family1(), "FLAC");
    }
    // PrintConv on PictureType: 3 → "Front Cover".
    assert_eq!(m.tags()[0].value(), &TagValue::Str("Front Cover".into()));
    // Picture data is TagValue::Bytes (Binary placeholder at serialize).
    assert_eq!(
      m.tags()[8].value(),
      &TagValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
    );
  }

  #[test]
  fn process_flac_picture_truncated_clamps_to_remaining() {
    // R2-F3: bundled ExifTool::ReadValue (ExifTool.pm:6290-6298) clamps a
    // too-large `$count` to the remaining bytes and emits the partial
    // binary. A Picture body claiming a 1-MiB data segment but with only
    // 2 bytes available ⇒ Picture tag IS emitted, containing exactly
    // those 2 bytes; the placeholder renders as `(Binary data 2 bytes,
    // use -b option to extract)`. Pre-R2 we returned `false` and dropped
    // the tag — Codex R2-F3 caught the divergence.
    use crate::value::Metadata;
    fn be32(n: u32) -> [u8; 4] {
      n.to_be_bytes()
    }
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&be32(3));
    p.extend_from_slice(&be32(0)); // mime len 0
    p.extend_from_slice(&be32(0)); // desc len 0
    p.extend_from_slice(&be32(8));
    p.extend_from_slice(&be32(8));
    p.extend_from_slice(&be32(24));
    p.extend_from_slice(&be32(0));
    p.extend_from_slice(&be32(1_000_000)); // claimed 1 MB
    p.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes provided
    let mut m = Metadata::new("x.flac");
    let ok = process_flac_picture(&p, &mut m, true);
    assert!(
      ok,
      "truncated Picture data ⇒ still true (faithful clamp; tag emitted)"
    );
    // Sub-fields still emitted, and Picture is emitted with the clamped
    // 2 bytes (NOT the declared 1_000_000).
    assert!(m.tags().iter().any(|t| t.name() == "PictureWidth"));
    let pic = m
      .tags()
      .iter()
      .find(|t| t.name() == "Picture")
      .expect("Picture tag is emitted with clamped bytes");
    assert_eq!(pic.value(), &TagValue::Bytes(vec![0xAA, 0xBB]));
  }

  #[test]
  fn vorbis_coverart_decodes_base64_to_bytes() {
    // R1-F3: Vorbis.pm:97-105 COVERART base64-decode → Vorbis:CoverArt
    // as TagValue::Bytes. "AAEC" base64-decodes to bytes [0x00,0x01,0x02].
    use crate::value::Metadata;
    let payload = make_vorbis_payload(b"v", &[b"COVERART=AAEC"]);
    let mut m = Metadata::new("x.flac");
    assert!(process_vorbis_comments(&payload, &mut m, true));
    let coverart = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArt")
      .expect("CoverArt must be emitted");
    assert_eq!(coverart.value(), &TagValue::Bytes(vec![0x00, 0x01, 0x02]));
    assert_eq!(coverart.group().family1(), "Vorbis");
  }

  #[test]
  fn vorbis_metadata_block_picture_emits_recursion_warning() {
    // R1-F3: bundled ExifTool's ProcessDirectory recursion guard
    // (ExifTool.pm:9057) fires invariably on METADATA_BLOCK_PICTURE's
    // FLAC::Picture SubDirectory. exifast emits the warning only — NO
    // Picture sub-fields.
    use crate::value::Metadata;
    let payload = make_vorbis_payload(b"v", &[b"METADATA_BLOCK_PICTURE=AAAA"]);
    let mut m = Metadata::new("x.flac");
    assert!(process_vorbis_comments(&payload, &mut m, true));
    assert!(
      m.warnings()
        .iter()
        .any(|w| w == "Picture pointer references previous VorbisComment directory"),
      "warning must fire; got {:?}",
      m.warnings()
    );
    // No Picture* sub-fields under any group.
    assert!(
      !m.tags().iter().any(|t| t.name() == "PictureType"
        || t.name() == "PictureMIMEType"
        || t.name() == "PictureWidth"),
      "no Picture sub-fields under METADATA_BLOCK_PICTURE recursion-guard path"
    );
  }

  #[test]
  fn streaminfo_value_conv_fns_are_faithful() {
    // $val + 1: I64 → I64+1; non-I64 → unchanged.
    assert_eq!(streaminfo_add_one(&TagValue::I64(1)), TagValue::I64(2));
    assert_eq!(streaminfo_add_one(&TagValue::I64(7)), TagValue::I64(8));
    // unpack("H*",$val): Bytes → lowercase hex Str.
    assert_eq!(
      streaminfo_unpack_h_star(&TagValue::Bytes(vec![
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
      ])),
      TagValue::Str("d41d8cd98f00b204e9800998ecf8427e".into())
    );
    // Saturating semantic for the worst-case: i64::MAX + 1 stays i64::MAX.
    assert_eq!(
      streaminfo_add_one(&TagValue::I64(i64::MAX)),
      TagValue::I64(i64::MAX)
    );
  }
}
