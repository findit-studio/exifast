//! Seam-validation for the `Format`/raw-byte path in `process_bit_stream`.
//!
//! Scope: FLAC StreamInfo block ONLY (272 bits / 34 bytes).
//! This is NOT a FLAC format port — no `src/formats/flac.rs`, no registration
//! in `formats/mod.rs`. The faithful `%FLAC::StreamInfo` table and the minimal
//! block-header extraction live here, test-local.
//!
//! Ground truth: bundled Perl ExifTool output:
//!   FLAC:BlockSizeMin   4608
//!   FLAC:BlockSizeMax   4608
//!   FLAC:FrameSizeMin   16777215
//!   FLAC:FrameSizeMax   0
//!   FLAC:SampleRate     8000
//!   FLAC:Channels       2
//!   FLAC:BitsPerSample  8
//!   FLAC:TotalSamples   0
//!   FLAC:MD5Signature   "d41d8cd98f00b204e9800998ecf8427e"
//!
//! References:
//!   FLAC.pm:59-82  (%Image::ExifTool::FLAC::StreamInfo)
//!   FLAC.pm:239-280 (ProcessFLAC — magic + metadata-block-header structure)

use exifast::{
  bitstream::{process_bit_stream, BitOrder},
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
  value::{Metadata, TagValue},
};

// ---------------------------------------------------------------------------
// Faithful %FLAC::StreamInfo table (FLAC.pm:59-82)
// "FLAC is big-endian, so bit 0 is the high-order bit in this table."
// group0 = "FLAC" (family-0), group1 = "FLAC" (family-1 = ExifTool module-name
// convention, per `exiftool -G1`: "FLAC:BlockSizeMin" …). FLAC.pm `GROUPS =>
// { 2 => 'Audio' }` is family-2 (category) and is not emitted under -G1.
// ---------------------------------------------------------------------------

// Helper: `unpack("H*",$val)` (FLAC.pm:80) — convert raw bytes to lowercase hex.
// Faithful to Perl's `unpack("H*", ...)`: each byte becomes two lowercase hex chars.
fn hex_encode(v: &TagValue) -> TagValue {
  match v {
    TagValue::Bytes(b) => {
      let mut s = String::with_capacity(b.len() * 2);
      for x in b {
        s.push_str(&format!("{x:02x}"));
      }
      TagValue::Str(s.into())
    }
    other => other.clone(),
  }
}

// Helper: `$val + 1` (FLAC.pm:70, 74) — ValueConv for Channels and BitsPerSample.
fn add_one(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::I64(n + 1),
    other => other.clone(),
  }
}

// FLAC.pm:63  'Bit000-015' => 'BlockSizeMin'
static BLOCK_SIZE_MIN: TagDef =
  TagDef::new("BlockSizeMin", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:64  'Bit016-031' => 'BlockSizeMax'
static BLOCK_SIZE_MAX: TagDef =
  TagDef::new("BlockSizeMax", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:65  'Bit032-055' => 'FrameSizeMin'
static FRAME_SIZE_MIN: TagDef =
  TagDef::new("FrameSizeMin", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:66  'Bit056-079' => 'FrameSizeMax'
static FRAME_SIZE_MAX: TagDef =
  TagDef::new("FrameSizeMax", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:67  'Bit080-099' => 'SampleRate'
static SAMPLE_RATE: TagDef = TagDef::new("SampleRate", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:68-71  'Bit100-102' => { Name => 'Channels', ValueConv => '$val + 1' }
static CHANNELS: TagDef = TagDef::new(
  "Channels",
  "FLAC",
  ValueConv::Func(add_one),
  PrintConv::None,
);

// FLAC.pm:72-75  'Bit103-107' => { Name => 'BitsPerSample', ValueConv => '$val + 1' }
static BITS_PER_SAMPLE: TagDef = TagDef::new(
  "BitsPerSample",
  "FLAC",
  ValueConv::Func(add_one),
  PrintConv::None,
);

// FLAC.pm:76  'Bit108-143' => 'TotalSamples'
static TOTAL_SAMPLES: TagDef =
  TagDef::new("TotalSamples", "FLAC", ValueConv::None, PrintConv::None);

// FLAC.pm:77-81  'Bit144-271' => { Name => 'MD5Signature', Format => 'undef',
//                                   ValueConv => 'unpack("H*",$val)' }
static MD5_SIGNATURE: TagDef = TagDef::new(
  "MD5Signature",
  "FLAC",
  ValueConv::Func(hex_encode),
  PrintConv::None,
)
.with_format("undef"); // FLAC.pm:79

/// The 9 `Bit<a>-<b>` keys in ascending bit-offset order, mirroring
/// ExifTool's `sort keys %$tagTablePtr` (FLAC.pm:172).
/// Zero-padded three-digit offsets sort lexicographically in the correct
/// numeric order.
const FLAC_STREAMINFO_BIT_KEYS: &[&str] = &[
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

fn flac_streaminfo_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("Bit000-015") => Some(&BLOCK_SIZE_MIN),
    TagId::Str("Bit016-031") => Some(&BLOCK_SIZE_MAX),
    TagId::Str("Bit032-055") => Some(&FRAME_SIZE_MIN),
    TagId::Str("Bit056-079") => Some(&FRAME_SIZE_MAX),
    TagId::Str("Bit080-099") => Some(&SAMPLE_RATE),
    TagId::Str("Bit100-102") => Some(&CHANNELS),
    TagId::Str("Bit103-107") => Some(&BITS_PER_SAMPLE),
    TagId::Str("Bit108-143") => Some(&TOTAL_SAMPLES),
    TagId::Str("Bit144-271") => Some(&MD5_SIGNATURE),
    _ => None,
  }
}

// ---------------------------------------------------------------------------
// Minimal FLAC block-header extraction (FLAC.pm:253-275 ProcessFLAC)
// ---------------------------------------------------------------------------

/// Extract the StreamInfo payload from a FLAC byte buffer.
///
/// Per FLAC.pm:254: `$raf->Read($buff, 4) == 4 and $buff eq 'fLaC'` — magic check.
/// Per FLAC.pm:260-265: each metadata block header is 4 bytes:
///   - byte0: bit7 = last-metadata-block flag, bits6-0 = block type
///   - bytes1-3: 24-bit big-endian block length
///
/// StreamInfo is block type 0 and is always the first metadata block
/// (FLAC spec + FLAC.pm:27-29 block type mapping).
///
/// Returns the 34-byte StreamInfo payload slice on success.
fn extract_streaminfo(data: &[u8]) -> &[u8] {
  // Length check FIRST so a corrupted/truncated fixture fails with the
  // intended message, not an index-out-of-bounds panic from the magic
  // check (Copilot PR #2 reviews 4319223994 / 4323634334).
  assert!(
    data.len() >= 8,
    "FLAC fixture too short ({} bytes); expected >= 8 for magic+block header",
    data.len()
  );
  // FLAC.pm:254 — `starts_with` is panic-free on short input.
  assert!(data.starts_with(b"fLaC"), "FLAC magic must be 'fLaC'");

  // First metadata block header at offset 4 (FLAC.pm:260)
  let flag = data[4]; // FLAC.pm:261: `my $flag = unpack('C', $buff)`
  let block_type = flag & 0x7f; // FLAC.pm:265: `my $tag  = $flag & 0x7f`
  assert_eq!(
    block_type, 0,
    "first metadata block must be StreamInfo (type 0)"
  );

  // 24-bit big-endian length (FLAC.pm:262: `my $size = unpack('N', $buff) & 0x00ffffff`)
  // `unpack('N', ...)` reads 4 bytes as big-endian uint32; masking off the top
  // byte gives the 24-bit length in the lower 3 bytes.
  let len = (u32::from_be_bytes([0, data[5], data[6], data[7]])) as usize;
  assert_eq!(len, 34, "StreamInfo block must be 34 bytes (272 bits)");
  assert!(
    data.len() >= 8 + len,
    "FLAC StreamInfo payload truncated: need {} bytes, have {}",
    8 + len,
    data.len()
  );

  // StreamInfo payload: bytes 8 .. 8+len (FLAC.pm:263)
  &data[8..8 + len]
}

// ---------------------------------------------------------------------------
// Integration test: all 9 StreamInfo tags vs. bundled Perl ExifTool
// ---------------------------------------------------------------------------

#[test]
fn flac_streaminfo_matches_bundled_perl() {
  // Load the fixture copied from exiftool/t/images/FLAC.flac (Step 1).
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/FLAC.flac"
  ))
  .expect("tests/fixtures/FLAC.flac must exist");

  // Parse the StreamInfo payload (FLAC.pm:239-280).
  let payload = extract_streaminfo(&data);
  assert_eq!(
    payload.len(),
    34,
    "StreamInfo payload is 272 bits = 34 bytes"
  );

  // Build the tag table and run process_bit_stream.
  // BitOrder::Mm = big-endian / 'MM' (FLAC.pm:256: `SetByteOrder('MM')`).
  let table = TagTable::new("FLAC", flac_streaminfo_get);
  let mut m = Metadata::new("FLAC.flac");

  process_bit_stream(
    payload,
    BitOrder::Mm,
    FLAC_STREAMINFO_BIT_KEYS,
    &table,
    &mut m,
    true, // print_conv_enabled (matches `exiftool -j` default)
  );

  // All 9 tags must be present.
  assert_eq!(
    m.tags().len(),
    9,
    "expected 9 StreamInfo tags; got {}",
    m.tags().len()
  );

  // Build a lookup map for assertion clarity.
  let tag_map: std::collections::HashMap<&str, &TagValue> =
    m.tags().iter().map(|t| (t.name(), t.value())).collect();

  // --- Assertions vs. bundled Perl ExifTool output (Step 2) ---

  // FLAC:BlockSizeMin 4608  (FLAC.pm:63)
  assert_eq!(
    tag_map.get("BlockSizeMin"),
    Some(&&TagValue::I64(4608)),
    "BlockSizeMin"
  );

  // FLAC:BlockSizeMax 4608  (FLAC.pm:64)
  assert_eq!(
    tag_map.get("BlockSizeMax"),
    Some(&&TagValue::I64(4608)),
    "BlockSizeMax"
  );

  // FLAC:FrameSizeMin 16777215  (FLAC.pm:65)
  assert_eq!(
    tag_map.get("FrameSizeMin"),
    Some(&&TagValue::I64(16_777_215)),
    "FrameSizeMin"
  );

  // FLAC:FrameSizeMax 0  (FLAC.pm:66)
  assert_eq!(
    tag_map.get("FrameSizeMax"),
    Some(&&TagValue::I64(0)),
    "FrameSizeMax"
  );

  // FLAC:SampleRate 8000  (FLAC.pm:67)
  assert_eq!(
    tag_map.get("SampleRate"),
    Some(&&TagValue::I64(8000)),
    "SampleRate"
  );

  // FLAC:Channels 2  (raw 1, ValueConv '$val + 1' => 2) (FLAC.pm:68-71)
  assert_eq!(
    tag_map.get("Channels"),
    Some(&&TagValue::I64(2)),
    "Channels (raw 1 + ValueConv +1 = 2)"
  );

  // FLAC:BitsPerSample 8  (raw 7, ValueConv '$val + 1' => 8) (FLAC.pm:72-75)
  assert_eq!(
    tag_map.get("BitsPerSample"),
    Some(&&TagValue::I64(8)),
    "BitsPerSample (raw 7 + ValueConv +1 = 8)"
  );

  // FLAC:TotalSamples 0  (FLAC.pm:76)
  assert_eq!(
    tag_map.get("TotalSamples"),
    Some(&&TagValue::I64(0)),
    "TotalSamples"
  );

  // FLAC:MD5Signature "d41d8cd98f00b204e9800998ecf8427e"
  // Format => 'undef' + ValueConv => 'unpack("H*",$val)' (FLAC.pm:77-81)
  assert_eq!(
    tag_map.get("MD5Signature"),
    Some(&&TagValue::Str("d41d8cd98f00b204e9800998ecf8427e".into())),
    "MD5Signature (16 raw bytes -> lowercase hex)"
  );

  // Verify family-0 group is "FLAC" for all tags (FLAC.pm:59 group0 = "FLAC").
  for tag in m.tags() {
    assert_eq!(
      tag.group().family0(),
      "FLAC",
      "all StreamInfo tags must have family-0 = 'FLAC'"
    );
    assert_eq!(
      tag.group().family1(),
      "FLAC",
      "all StreamInfo tags must have family-1 = 'FLAC'"
    );
  }
}
