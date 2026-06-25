//! PNG container conformance: typed [`PngMeta`] decoding + the engine
//! [`extract_info`] dispatch on the bundled `t/images/PNG.png` fixture.
//!
//! Two layers exercised:
//!
//! 1. Direct [`exifast::formats::png::parse_borrowed`] — the lib-first entry
//!    used by callers that want the raw [`PngMeta`] without the engine's
//!    orchestration tags / serde rendering.
//! 2. The engine [`exifast::parser::extract_info`] entry — the full
//!    `detect → typed parse → serde-render` path that drives the
//!    `extract_info` document for downstream `perl exiftool -j -G1`
//!    conformance.
//!
//! Gated on `feature = "json"` (the engine entry returns JSON).

#![cfg(all(feature = "json", feature = "png"))]

use exifast::formats::png::parse_borrowed;
use exifast::parser::extract_info;

const FIXTURE: &str = "PNG.png";

fn read_fixture() -> Vec<u8> {
  let root = env!("CARGO_MANIFEST_DIR");
  std::fs::read(format!("{root}/tests/fixtures/{FIXTURE}"))
    .unwrap_or_else(|e| panic!("read fixture {FIXTURE}: {e}"))
}

#[test]
fn bundled_png_parses_ihdr_dimensions_and_color_type() {
  let data = read_fixture();
  let meta = parse_borrowed(&data).expect("PNG signature accepted");
  // PNG.png is 16x16, 1-bit grayscale (bundled `t/images/PNG.png`).
  assert_eq!(meta.dimensions(), Some((16, 16)));
  assert_eq!(meta.bit_depth(), Some(1));
  assert!(meta.color_type().expect("color type set").is_grayscale());
  assert_eq!(meta.compression(), Some(0));
  assert_eq!(meta.filter(), Some(0));
  assert_eq!(meta.interlace(), Some(0));
}

#[test]
fn bundled_png_captures_text_chunk_comment() {
  let data = read_fixture();
  let meta = parse_borrowed(&data).expect("png");
  // Bundled `perl exiftool -j t/images/PNG.png` emits `"Comment": "test
  // comment"` (tEXt chunk, PNG.pm:258-261). The on-disk keyword in this
  // fixture is lowercase `comment`; bundled's `ucfirst()` fallback
  // (PNG.pm:919-921) resolves it against the `Comment` table entry. The
  // typed [`PngMeta`] preserves the verbatim keyword — the
  // `ucfirst`-style fixup happens at `tags()` emission.
  let comment = meta
    .text_records()
    .iter()
    .find(|r| r.keyword().eq_ignore_ascii_case("Comment"))
    .expect("Comment tEXt record present");
  assert!(comment.kind().is_text());
  assert_eq!(comment.value(), "test comment");
}

#[test]
fn bundled_png_captures_xmp_itxt_with_keyword() {
  let data = read_fixture();
  let meta = parse_borrowed(&data).expect("png");
  // iTXt with keyword `XML:com.adobe.xmp` — the XMP payload (bundled
  // PNG.pm:680-688 routes it to XMP::Main). Our port captures the
  // keyword + the UTF-8 body but DEFERS XMP dispatch.
  let xmp = meta
    .text_records()
    .iter()
    .find(|r| r.keyword() == "XML:com.adobe.xmp")
    .expect("XMP iTXt record present");
  assert!(xmp.kind().is_itxt());
  assert!(xmp.value().contains("Phil Harvey"));
}

#[test]
fn bundled_png_warns_about_text_after_idat() {
  let data = read_fixture();
  let meta = parse_borrowed(&data).expect("png");
  // Bundled emits `Text/EXIF chunk(s) found after PNG IDAT (may be
  // ignored by some readers) [x2]` (PNG.pm:1595-1605) because the file
  // carries tEXt + iTXt AFTER the IDAT chunk.
  assert!(
    meta
      .warnings()
      .iter()
      .any(|w| w.contains("Text/EXIF chunk(s) found after PNG IDAT")),
    "expected post-IDAT warning, got {:?}",
    meta.warnings(),
  );
}

#[test]
fn engine_extract_info_emits_png_tags() {
  // The engine's full pipeline: detect → typed parse → serde-render.
  let data = read_fixture();
  let json = extract_info(FIXTURE, &data, /* print_conv */ true);
  // Parse to access keys via serde_json. Skip dependency on extra crates by
  // relying on substring search — the document is small + the bundled
  // fixture's tags are stable.
  assert!(json.contains("\"File:FileType\":\"PNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/png\""),
    "got {json}",
  );
  assert!(json.contains("\"PNG:ImageWidth\":16"), "got {json}");
  assert!(json.contains("\"PNG:ImageHeight\":16"), "got {json}");
  assert!(json.contains("\"PNG:BitDepth\":1"), "got {json}");
  assert!(
    json.contains("\"PNG:ColorType\":\"Grayscale\""),
    "got {json}",
  );
  assert!(
    json.contains("\"PNG:Compression\":\"Deflate/Inflate\""),
    "got {json}",
  );
  assert!(json.contains("\"PNG:Filter\":\"Adaptive\""), "got {json}");
  assert!(
    json.contains("\"PNG:Interlace\":\"Noninterlaced\""),
    "got {json}",
  );
  assert!(
    json.contains("\"PNG:Comment\":\"test comment\""),
    "got {json}"
  );
  // bKGD as 1-byte palette index = 0 (BackgroundColor numeric).
  assert!(json.contains("\"PNG:BackgroundColor\":0"), "got {json}",);
  // Bundled emits `ExifTool:Warning: "[minor] Text/EXIF chunk(s) found
  // after PNG IDAT ..."`. The minor-warning `[minor]` prefix is added
  // by bundled ExifTool's `Warn` machinery for category-2 warnings
  // (`PNG.pm:1604` `$et->Warn(..., 1)`); our port emits the warning
  // text without the prefix (faithful to the typed Meta's warning
  // emission). We assert the substring without the `[minor]` prefix.
  assert!(
    json.contains("Text/EXIF chunk(s) found after PNG IDAT"),
    "got {json}",
  );
}

#[test]
fn engine_extract_info_n_mode_emits_raw_color_type_byte() {
  let data = read_fixture();
  let json = extract_info(FIXTURE, &data, /* print_conv */ false);
  // -n mode: ColorType is the raw u8 (0 for Grayscale, PNG.pm:402).
  assert!(json.contains("\"PNG:ColorType\":0"), "got {json}");
  // Compression / Filter / Interlace are raw u8 too under -n.
  assert!(json.contains("\"PNG:Compression\":0"), "got {json}");
  assert!(json.contains("\"PNG:Filter\":0"), "got {json}");
  assert!(json.contains("\"PNG:Interlace\":0"), "got {json}");
}

#[test]
fn engine_extract_info_itxt_language_tag_standard_lang_case() {
  // A synthetic PNG with an `iTXt` `Title` whose language subtag is the
  // lowercase `en-us`. Bundled `FoundPNG` (PNG.pm:914-918) builds the tag ID
  // as `Title-` + `StandardLangCase("en-us")` = `Title-en-US` (the primary
  // subtag lower-cased, the 2-letter region UPPER-cased). The pre-golden port
  // blanket-lower-cased the language (`Title-en-us`) — this asserts the fix.
  //
  // Chunk layout: keyword `Title\0`, compressed=0, method=0, lang `en-us\0`,
  // translated `\0`, value `Hi`.
  fn chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    // CRC-32 (poly 0xedb88320, 1's-complement pre/post) over [type, data].
    fn crc32(bytes: &[u8]) -> u32 {
      let mut crc: u32 = 0xffff_ffff;
      for &b in bytes {
        let mut c = (crc ^ u32::from(b)) & 0xff;
        for _ in 0..8 {
          c = if (c & 1) != 0 {
            0xedb8_8320 ^ (c >> 1)
          } else {
            c >> 1
          };
        }
        crc = c ^ (crc >> 8);
      }
      crc ^ 0xffff_ffff
    }
    let len = u32::try_from(data.len()).expect("fits");
    let mut buf = Vec::new();
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    let mut crc_buf = Vec::new();
    crc_buf.extend_from_slice(chunk_type);
    crc_buf.extend_from_slice(data);
    buf.extend_from_slice(&crc32(&crc_buf).to_be_bytes());
    buf
  }

  let mut itxt = Vec::new();
  itxt.extend_from_slice(b"Title\0"); // keyword
  itxt.push(0); // compressed = 0
  itxt.push(0); // method = 0
  itxt.extend_from_slice(b"en-us\0"); // language tag
  itxt.extend_from_slice(b"\0"); // translated keyword (empty)
  itxt.extend_from_slice(b"Hi"); // value

  let mut ihdr = Vec::new();
  ihdr.extend_from_slice(&1u32.to_be_bytes());
  ihdr.extend_from_slice(&1u32.to_be_bytes());
  ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

  let mut bytes = Vec::new();
  bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
  bytes.extend_from_slice(&chunk(b"IHDR", &ihdr));
  bytes.extend_from_slice(&chunk(b"iTXt", &itxt));
  bytes.extend_from_slice(&chunk(b"IEND", &[]));

  let json = extract_info("synthetic.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:Title-en-US\":\"Hi\""),
    "expected StandardLangCase-normalized iTXt tag key PNG:Title-en-US, got {json}",
  );
  assert!(
    !json.contains("Title-en-us"),
    "language subtag region must be upper-cased (en-US), not en-us: {json}",
  );
}

// ===========================================================================
// Compressed-chunk inflate tests (zTXt / compressed iTXt / zXIf), each
// oracle-verified against bundled `perl exiftool -j -G1` (which has
// Compress::Zlib). The crafted payloads use a valid zlib (RFC 1950) wrapper
// around a STORED deflate block so the tests need no deflate encoder; bundled
// inflates them identically (Compress::Zlib accepts stored blocks).
// ===========================================================================

/// PNG CRC-32 (poly 0xedb88320, 1's-complement pre/post).
fn crc32(bytes: &[u8]) -> u32 {
  let mut crc: u32 = 0xffff_ffff;
  for &b in bytes {
    let mut c = (crc ^ u32::from(b)) & 0xff;
    for _ in 0..8 {
      c = if (c & 1) != 0 {
        0xedb8_8320 ^ (c >> 1)
      } else {
        c >> 1
      };
    }
    crc = c ^ (crc >> 8);
  }
  crc ^ 0xffff_ffff
}

/// Build a well-formed chunk: `[len BE][type][data][crc BE]`.
fn chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
  let len = u32::try_from(data.len()).expect("fits");
  let mut buf = Vec::new();
  buf.extend_from_slice(&len.to_be_bytes());
  buf.extend_from_slice(chunk_type);
  buf.extend_from_slice(data);
  let mut crc_buf = Vec::new();
  crc_buf.extend_from_slice(chunk_type);
  crc_buf.extend_from_slice(data);
  buf.extend_from_slice(&crc32(&crc_buf).to_be_bytes());
  buf
}

/// A minimal zlib (RFC 1950) wrapper around a STORED (uncompressed) deflate
/// block. Produces a stream `decompress_to_vec_zlib` (and Compress::Zlib)
/// inflate back to `data` byte-for-byte.
fn zlib_store(data: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  out.push(0x78); // CM=8, CINFO=7
  out.push(0x01); // FCHECK (78 01 is a valid zlib header)
  let len = u16::try_from(data.len()).expect("payload < 64KiB");
  out.push(0x01); // BFINAL=1, BTYPE=00 (stored)
  out.extend_from_slice(&len.to_le_bytes());
  out.extend_from_slice(&(!len).to_le_bytes());
  out.extend_from_slice(data);
  let mut a: u32 = 1;
  let mut b: u32 = 0;
  for &byte in data {
    a = (a + u32::from(byte)) % 65521;
    b = (b + a) % 65521;
  }
  out.extend_from_slice(&((b << 16) | a).to_be_bytes());
  out
}

fn ihdr_rgb_1x1() -> Vec<u8> {
  let mut d = Vec::new();
  d.extend_from_slice(&1u32.to_be_bytes()); // width
  d.extend_from_slice(&1u32.to_be_bytes()); // height
  d.extend_from_slice(&[8, 2, 0, 0, 0]); // depth 8, RGB, comp/filter/interlace 0
  chunk(b"IHDR", &d)
}

fn assemble(chunks: &[Vec<u8>]) -> Vec<u8> {
  let mut bytes = Vec::new();
  bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
  for c in chunks {
    bytes.extend_from_slice(c);
  }
  bytes.extend_from_slice(&chunk(b"IEND", &[]));
  bytes
}

/// A minimal little-endian TIFF/EXIF block: IFD0 = { Make(0x010f) ASCII,
/// Model(0x0110) ASCII }. `make`/`model` are NUL-terminated automatically.
/// This is the same TIFF a phone-camera `eXIf` chunk carries — used by the
/// zXIf and `Raw profile type {exif,APP1}` tests, all oracle-verified against
/// `perl exiftool -j -G1` (which decodes the embedded IFD0).
fn tiff_make_model(make: &str, model: &str) -> Vec<u8> {
  let mut make_b = make.as_bytes().to_vec();
  make_b.push(0);
  let mut model_b = model.as_bytes().to_vec();
  model_b.push(0);
  let ifd_start: u32 = 8;
  let n: u16 = 2;
  let data_start = ifd_start + 2 + u32::from(n) * 12 + 4;
  let make_off = data_start;
  let model_off = data_start + make_b.len() as u32;
  let mut t = Vec::new();
  t.extend_from_slice(b"II");
  t.extend_from_slice(&0x002a_u16.to_le_bytes());
  t.extend_from_slice(&ifd_start.to_le_bytes());
  t.extend_from_slice(&n.to_le_bytes());
  // Make 0x010f, type 2 (ASCII).
  t.extend_from_slice(&0x010f_u16.to_le_bytes());
  t.extend_from_slice(&0x0002_u16.to_le_bytes());
  t.extend_from_slice(&(make_b.len() as u32).to_le_bytes());
  t.extend_from_slice(&make_off.to_le_bytes());
  // Model 0x0110, type 2 (ASCII).
  t.extend_from_slice(&0x0110_u16.to_le_bytes());
  t.extend_from_slice(&0x0002_u16.to_le_bytes());
  t.extend_from_slice(&(model_b.len() as u32).to_le_bytes());
  t.extend_from_slice(&model_off.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  t.extend_from_slice(&make_b);
  t.extend_from_slice(&model_b);
  t
}

/// A minimal little-endian TIFF/EXIF block with a SINGLE ASCII IFD0 tag
/// (`tag_id` → `value`), value stored out-of-line, IFD0 at offset 8. `value`
/// must be > 4 bytes so the offset path is used (not the inline 4-byte value
/// field).
fn tiff_one_tag(tag_id: u16, value: &str) -> Vec<u8> {
  tiff_one_tag_at(8, tag_id, value)
}

/// Like [`tiff_one_tag`] but with IFD0 at the caller-chosen `ifd_start` (the
/// 8 bytes between the TIFF header and `ifd_start` are zero-filled padding).
/// Used by the offset-keyed cycle-guard tests: two sources whose IFD0 lives at
/// DIFFERENT offsets carry DIFFERENT `$addr`s and so do NOT collide
/// (`ExifTool.pm:9066-9070`), unlike two sources both at offset 8.
fn tiff_one_tag_at(ifd_start: u32, tag_id: u16, value: &str) -> Vec<u8> {
  assert!(ifd_start >= 8, "IFD0 cannot overlap the 8-byte TIFF header");
  let mut vb = value.as_bytes().to_vec();
  vb.push(0);
  assert!(
    vb.len() > 4,
    "tiff_one_tag value must be > 4 bytes (offset path)"
  );
  let n: u16 = 1;
  let val_off = ifd_start + 2 + u32::from(n) * 12 + 4;
  let mut t = Vec::new();
  t.extend_from_slice(b"II");
  t.extend_from_slice(&0x002a_u16.to_le_bytes());
  t.extend_from_slice(&ifd_start.to_le_bytes());
  // Zero-pad between the header and IFD0 when the offset is beyond 8.
  t.resize(ifd_start as usize, 0);
  t.extend_from_slice(&n.to_le_bytes());
  t.extend_from_slice(&tag_id.to_le_bytes());
  t.extend_from_slice(&0x0002_u16.to_le_bytes()); // ASCII
  t.extend_from_slice(&(vb.len() as u32).to_le_bytes());
  t.extend_from_slice(&val_off.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  t.extend_from_slice(&vb);
  t
}

/// A little-endian TIFF with IFD0 (Make=`make`) at offset 8 AND a trailing
/// IFD1 (Model=`model`) at offset `ifd1_off`, reached via IFD0's next-IFD
/// pointer. Used by the cross-source TRAILING-IFD cycle-guard test: source 1
/// is this block, so its shared `$$et{PROCESSED}` records BOTH the IFD0 `$addr`
/// (8) and the IFD1 `$addr` (`ifd1_off`); a second source whose IFD0 lands on
/// `ifd1_off` then collides with the recorded *trailing* IFD — the case the
/// IFD0-only model missed. Both tags ASCII, stored out-of-line.
fn tiff_make_with_trailing_ifd1(make: &str, model: &str, ifd1_off: u32) -> Vec<u8> {
  let mk = {
    let mut v = make.as_bytes().to_vec();
    v.push(0);
    v
  };
  let md = {
    let mut v = model.as_bytes().to_vec();
    v.push(0);
    v
  };
  let ifd0_start: u32 = 8;
  let n0: u16 = 1;
  let ifd0_val_off = ifd0_start + 2 + u32::from(n0) * 12 + 4; // = 26
  assert!(
    ifd1_off >= ifd0_val_off + mk.len() as u32,
    "IFD1 must sit past IFD0's Make value"
  );
  let mut t = Vec::new();
  t.extend_from_slice(b"II");
  t.extend_from_slice(&0x002a_u16.to_le_bytes());
  t.extend_from_slice(&ifd0_start.to_le_bytes());
  // IFD0: 1 entry (Make), next-IFD pointer -> ifd1_off.
  t.extend_from_slice(&n0.to_le_bytes());
  t.extend_from_slice(&0x010f_u16.to_le_bytes()); // Make
  t.extend_from_slice(&0x0002_u16.to_le_bytes()); // ASCII
  t.extend_from_slice(&(mk.len() as u32).to_le_bytes());
  t.extend_from_slice(&ifd0_val_off.to_le_bytes());
  t.extend_from_slice(&ifd1_off.to_le_bytes()); // next IFD -> IFD1
  t.extend_from_slice(&mk); // Make value
  // Zero-pad up to IFD1.
  t.resize(ifd1_off as usize, 0);
  // IFD1: 1 entry (Model), next = 0.
  let n1: u16 = 1;
  let ifd1_val_off = ifd1_off + 2 + u32::from(n1) * 12 + 4;
  t.extend_from_slice(&n1.to_le_bytes());
  t.extend_from_slice(&0x0110_u16.to_le_bytes()); // Model
  t.extend_from_slice(&0x0002_u16.to_le_bytes()); // ASCII
  t.extend_from_slice(&(md.len() as u32).to_le_bytes());
  t.extend_from_slice(&ifd1_val_off.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes()); // no further IFD
  t.extend_from_slice(&md); // Model value
  t
}

/// Wrap `raw` bytes as an ImageMagick `Raw profile type X` chunk BODY:
/// `\n<type>\n<8-wide len>\n<hex, 72-char lines>\n` (`ProcessProfile`'s
/// `^\n(.*?)\n\s*(\d+)\n(.*)` framing, `PNG.pm:1166`). `declared_len` overrides
/// the length line (use `raw.len()` for a correct profile, a different value to
/// exercise the wrong-size warning at `PNG.pm:1172`). Bundled hex-decodes the
/// body after stripping whitespace.
fn raw_profile_body(profile_type: &str, raw: &[u8], declared_len: usize) -> Vec<u8> {
  let hexstr: String = raw.iter().map(|b| format!("{b:02x}")).collect();
  let mut body = String::new();
  body.push('\n');
  body.push_str(profile_type);
  body.push('\n');
  // ImageMagick writes the length right-justified in an 8-wide field.
  body.push_str(&format!("{declared_len:8}"));
  body.push('\n');
  // Break the hex into 72-char lines (ImageMagick wraps the hex dump).
  let bytes = hexstr.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    let end = (i + 72).min(bytes.len());
    body.push_str(core::str::from_utf8(&bytes[i..end]).unwrap());
    body.push('\n');
    i = end;
  }
  body.into_bytes()
}

#[test]
fn engine_extract_info_emits_apple_data_offsets_binary() {
  // #142 — the Apple `iDOT` private chunk (`AppleDataOffsets`, `Binary => 1`,
  // NO SubDirectory, PNG.pm:331-342). A 1x1 RGB PNG with a single 28-byte `iDOT`
  // chunk directly after IHDR. Bundled stores the whole chunk under
  // `PNG:AppleDataOffsets` and renders the binary placeholder. Oracle
  // (`perl exiftool -j -G1` 13.59):
  //   "PNG:AppleDataOffsets": "(Binary data 28 bytes, use -b option to extract)"
  // 7x int32u (28 bytes), the layout documented at PNG.pm:334-341.
  let mut idot = Vec::new();
  for v in [2u32, 0, 1, 0x28, 1, 1, 0x100] {
    idot.extend_from_slice(&v.to_be_bytes());
  }
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iDOT", &idot)]);
  let json = extract_info("idot.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:AppleDataOffsets\":\"(Binary data 28 bytes, use -b option to extract)\""),
    "expected the AppleDataOffsets binary placeholder, got {json}",
  );
  // The structural tags are unaffected; no warning.
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
  assert!(!json.contains("Error inflating"), "got {json}");
}

#[test]
fn engine_extract_info_emits_idot_under_both_png_and_trailer_groups() {
  // #142 (Codex [medium]) — a PNG carrying `iDOT` BOTH before `IEND` and as a
  // post-`IEND` TRAILER chunk emits BOTH placeholders under their distinct
  // family-1 groups. Oracle (`perl exiftool -j -G1` 13.59):
  //   "PNG:AppleDataOffsets":     "(Binary data 28 bytes, …)"
  //   "Trailer:AppleDataOffsets": "(Binary data 4 bytes, …)"
  //   "ExifTool:Warning":         "[minor] Trailer data after PNG IEND chunk"
  let mut main_idot = Vec::new();
  for v in [2u32, 0, 1, 0x28, 1, 1, 0x100] {
    main_idot.extend_from_slice(&v.to_be_bytes());
  }
  let trailer_idot = 0xDEAD_BEEFu32.to_be_bytes(); // 4-byte post-IEND iDOT
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"iDOT", &main_idot)],
    &chunk(b"iDOT", &trailer_idot),
  );
  let json = extract_info("idot_trailer.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:AppleDataOffsets\":\"(Binary data 28 bytes, use -b option to extract)\""),
    "expected the pre-IEND PNG:AppleDataOffsets placeholder, got {json}",
  );
  assert!(
    json
      .contains("\"Trailer:AppleDataOffsets\":\"(Binary data 4 bytes, use -b option to extract)\""),
    "expected the post-IEND Trailer:AppleDataOffsets placeholder, got {json}",
  );
  // The trailer-entry warning is document-level (raised before SET_GROUP1).
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
}

// ===========================================================================
// acTL (`AnimationControl`, `ProcessBinaryData`, PNG.pm:766-782) per-field
// availability (#141 Codex [medium]; same class as #128 MPEG / #149 av1C). Each
// `int32u` field emits IFF its `offset+size` is within the chunk length:
//   AnimationFrames (offset 0) needs bytes 0..4 — and its RawConv fires
//   OverrideFileType("APNG", undef, "PNG") (the FileType→APNG promotion);
//   AnimationPlays  (offset 4) needs bytes 4..8.
// All assertions are oracle-verified against bundled `perl exiftool -j -G1`
// (and `-n`) 13.59 on crafted APNGs whose acTL is truncated to 2/4/7/8 bytes.
// ===========================================================================

/// Build an APNG: 1x1 RGB IHDR + an `acTL` chunk carrying `actl` raw bytes.
fn apng_with_actl(actl: &[u8]) -> Vec<u8> {
  assemble(&[ihdr_rgb_1x1(), chunk(b"acTL", actl)])
}

#[test]
fn engine_actl_4byte_emits_frames_and_apng_override_without_plays() {
  // A 4-byte acTL (AnimationFrames only). Oracle (`perl exiftool -j -G1` 13.59):
  //   "File:FileType": "APNG", "File:MIMEType": "image/apng",
  //   "File:FileTypeExtension": "png", "PNG:AnimationFrames": 2,
  //   and NO "PNG:AnimationPlays".
  let bytes = apng_with_actl(&2u32.to_be_bytes());
  let json = extract_info("apng_actl4.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/apng\""),
    "got {json}",
  );
  assert!(
    json.contains("\"File:FileTypeExtension\":\"png\""),
    "got {json}",
  );
  assert!(json.contains("\"PNG:AnimationFrames\":2"), "got {json}");
  // Bytes 4..8 absent ⇒ AnimationPlays must NOT emit.
  assert!(!json.contains("AnimationPlays"), "got {json}");
}

#[test]
fn engine_actl_7byte_emits_frames_and_apng_override_without_plays() {
  // A 7-byte acTL: byte 4 exists but bytes 4..8 are NOT fully present, so
  // ProcessBinaryData still skips AnimationPlays — identical output to the
  // 4-byte case (this is the key per-field boundary the old all-or-nothing
  // 8-byte gate got wrong). Oracle (13.59): AnimationFrames=2 + APNG, no plays.
  let mut actl = 2u32.to_be_bytes().to_vec(); // frames = 2
  actl.extend_from_slice(&[0x00, 0x00, 0x07]); // 3 of the 4 plays bytes
  assert_eq!(actl.len(), 7);
  let bytes = apng_with_actl(&actl);
  let json = extract_info("apng_actl7.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/apng\""),
    "got {json}",
  );
  assert!(json.contains("\"PNG:AnimationFrames\":2"), "got {json}");
  assert!(!json.contains("AnimationPlays"), "got {json}");
}

#[test]
fn engine_actl_8byte_emits_both_frames_and_plays() {
  // A full 8-byte acTL: both fields present. frames=2, plays=7 (non-zero ⇒ the
  // bare number under PrintConv). Oracle (13.59): AnimationFrames=2 +
  // AnimationPlays=7 + APNG/image/apng.
  let mut actl = 2u32.to_be_bytes().to_vec();
  actl.extend_from_slice(&7u32.to_be_bytes());
  let bytes = apng_with_actl(&actl);
  let json = extract_info("apng_actl8.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  assert!(json.contains("\"PNG:AnimationFrames\":2"), "got {json}");
  assert!(json.contains("\"PNG:AnimationPlays\":7"), "got {json}");
}

#[test]
fn engine_actl_8byte_zero_plays_renders_inf() {
  // A full 8-byte acTL whose play count is 0 — the APNG "infinite loop"
  // sentinel. PrintConv `$val || "inf"` (PNG.pm:780) renders it as the string
  // "inf" (matching the bundled PNG_apng.png golden); `-n` keeps the raw 0.
  let mut actl = 2u32.to_be_bytes().to_vec();
  actl.extend_from_slice(&0u32.to_be_bytes());
  let bytes = apng_with_actl(&actl);
  let json = extract_info("apng_actl8_inf.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:AnimationPlays\":\"inf\""),
    "got {json}",
  );
  let json_n = extract_info("apng_actl8_inf.png", &bytes, /* print_conv */ false);
  assert!(json_n.contains("\"PNG:AnimationPlays\":0"), "got {json_n}");
}

#[test]
fn engine_actl_runt_under_4_bytes_emits_no_animation_and_stays_png() {
  // A `< 4`-byte acTL (2 bytes): bytes 0..4 are NOT present, so
  // ProcessBinaryData extracts NOTHING — no AnimationFrames, the APNG override
  // does NOT fire, and File:FileType stays "PNG". Oracle (13.59): FileType=PNG,
  // image/png, no Animation* tags.
  let bytes = apng_with_actl(&[0x00, 0x02]);
  let json = extract_info("apng_actl2.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"PNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/png\""),
    "got {json}",
  );
  assert!(!json.contains("APNG"), "got {json}");
  assert!(!json.contains("Animation"), "got {json}");
}

#[test]
fn engine_actl_before_and_after_iend_keep_per_field_groups() {
  // #141 (Codex [medium]) — PER-FIELD provenance: a FULL pre-`IEND` `acTL`
  // (frames=2, plays=7 → PNG: group) PLUS a 4-byte post-`IEND` TRAILER `acTL`
  // (frames=9 only — bytes 4..8 absent → no plays) must NOT fabricate a
  // `Trailer:AnimationPlays`. AnimationFrames and AnimationPlays each carry
  // their OWN main/trailer occurrence (the iDOT/gdAT `BinaryChunkLengths`
  // pattern), so the trailer chunk sets only `Trailer:AnimationFrames` while
  // the main `PNG:AnimationPlays` stays under `PNG`. A single shared trailing
  // flag re-grouped the stale main plays value to `Trailer` — fixed here.
  // Oracle (`perl exiftool -j -G1` 13.59 on this exact byte layout):
  //   "PNG:AnimationFrames": 2, "PNG:AnimationPlays": 7,
  //   "Trailer:AnimationFrames": 9,  (and NO "Trailer:AnimationPlays")
  //   "ExifTool:Warning": "[minor] Trailer data after PNG IEND chunk"
  let main_actl = {
    let mut a = 2u32.to_be_bytes().to_vec(); // frames = 2
    a.extend_from_slice(&7u32.to_be_bytes()); // plays  = 7 (non-zero → bare int)
    a
  };
  let trailer_actl = 9u32.to_be_bytes(); // 4 bytes: frames = 9, no plays
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"acTL", &main_actl)],
    &chunk(b"acTL", &trailer_actl),
  );
  let json = extract_info("apng_actl_trailer.png", &bytes, /* print_conv */ true);
  // Main `acTL` → both fields under PNG.
  assert!(json.contains("\"PNG:AnimationFrames\":2"), "got {json}");
  assert!(json.contains("\"PNG:AnimationPlays\":7"), "got {json}");
  // Trailer `acTL` (4 bytes) → AnimationFrames ONLY, under Trailer.
  assert!(json.contains("\"Trailer:AnimationFrames\":9"), "got {json}",);
  // The missing trailer play count must NOT be fabricated/mis-grouped — the old
  // stale main plays value (7) must NOT appear under the Trailer group.
  assert!(
    !json.contains("\"Trailer:AnimationPlays\""),
    "a Trailer:AnimationPlays was fabricated from the stale main value, got {json}",
  );
  // The post-`IEND` entry warning is document-level (raised before SET_GROUP1).
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
}

#[test]
fn engine_post_idat_text_after_actl_warning_says_apng() {
  // #141 Codex [medium]: an `acTL` (≥4 bytes → the APNG FileType override)
  // BEFORE IDAT, then a tEXt AFTER IDAT. The post-IDAT warning interpolates the
  // CURRENT FileType (`$$et{FileType}`, PNG.pm:1604) — which is already `APNG`
  // because the `acTL` was dispatched earlier in the walk. Oracle (`perl
  // exiftool -j -G1` 13.59 on this exact byte layout):
  //   "File:FileType": "APNG",
  //   "ExifTool:Warning": "[minor] Text/EXIF chunk(s) found after APNG IDAT
  //                        (may be ignored by some readers)"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"acTL", &{
      let mut a = 2u32.to_be_bytes().to_vec();
      a.extend_from_slice(&0u32.to_be_bytes());
      a
    }),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"tEXt", b"Comment\0Hi"),
  ]);
  let json = extract_info(
    "apng_text_after_idat.png",
    &bytes,
    /* print_conv */ true,
  );
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  // The warning must name APNG (the post-override FileType), not PNG.
  assert!(
    json.contains("Text/EXIF chunk(s) found after APNG IDAT (may be ignored by some readers)"),
    "expected the APNG-form post-IDAT warning, got {json}",
  );
  assert!(
    !json.contains("found after PNG IDAT"),
    "must NOT emit the PNG-form warning for an APNG, got {json}",
  );
  // The minor classifier must still recognize the APNG form ⇒ `[minor]` prefix.
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Text/EXIF chunk(s) found after APNG IDAT"),
    "the APNG-form warning must keep its [minor] prefix, got {json}",
  );
}

#[test]
fn engine_post_idat_text_with_actl_after_warning_says_png_firing_point() {
  // #141 firing-point subtlety: the `acTL` (→ APNG) comes AFTER the post-IDAT
  // tEXt. When the text-after-IDAT warning fires, `$$et{FileType}` is STILL
  // `PNG` (the override has not run yet), so the warning says PNG — even though
  // the file's FINAL FileType is APNG. Oracle (`perl exiftool -j -G1` 13.59):
  //   "File:FileType": "APNG",
  //   "ExifTool:Warning": "[minor] Text/EXIF chunk(s) found after PNG IDAT …"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"tEXt", b"Comment\0Hi"),
    chunk(b"acTL", &{
      let mut a = 2u32.to_be_bytes().to_vec();
      a.extend_from_slice(&0u32.to_be_bytes());
      a
    }),
  ]);
  let json = extract_info(
    "apng_actl_after_text.png",
    &bytes,
    /* print_conv */ true,
  );
  // FileType finalizes to APNG (the acTL is still seen, just later).
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  // But the warning reflects the firing-point FileType = PNG.
  assert!(
    json.contains("Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)"),
    "expected the PNG-form warning (acTL not yet seen at firing point), got {json}",
  );
  assert!(
    !json.contains("found after APNG IDAT"),
    "must NOT say APNG when the acTL fires after the warning, got {json}",
  );
}

#[test]
fn engine_post_idat_exif_after_actl_warning_says_apng() {
  // The `eXIf` chunk is also an `isTxtChunk` member (PNG.pm:93), so an eXIf
  // after IDAT (with an earlier acTL) likewise raises the APNG-form warning.
  // Oracle (13.59): "File:FileType": "APNG" + the `found after APNG IDAT`
  // warning. We use a tiny valid II*-led TIFF as the eXIf payload.
  let tiff = tiff_make_model(" X", "Y");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"acTL", &{
      let mut a = 2u32.to_be_bytes().to_vec();
      a.extend_from_slice(&0u32.to_be_bytes());
      a
    }),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"eXIf", &tiff),
  ]);
  let json = extract_info(
    "apng_exif_after_idat.png",
    &bytes,
    /* print_conv */ true,
  );
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  assert!(
    json.contains("Text/EXIF chunk(s) found after APNG IDAT (may be ignored by some readers)"),
    "expected the APNG-form post-IDAT warning for an eXIf chunk, got {json}",
  );
}

#[test]
fn engine_ztxt_inflates_comment() {
  // Oracle (`perl exiftool -j -G1`) on a zTXt "Comment" chunk:
  //   "PNG:Comment": "decompressed comment value"
  let mut ztxt = Vec::new();
  ztxt.extend_from_slice(b"Comment\0"); // keyword
  ztxt.push(0); // compression method = deflate
  ztxt.extend_from_slice(&zlib_store(b"decompressed comment value"));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zTXt", &ztxt)]);
  let json = extract_info("z_ztxt.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:Comment\":\"decompressed comment value\""),
    "expected inflated zTXt Comment, got {json}",
  );
  // The retired deferral warning must NOT appear anywhere now.
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
}

#[test]
fn engine_itxt_compressed_inflates_title_with_lang() {
  // Oracle on a compressed iTXt "Title" (lang en-us):
  //   "PNG:Title-en-US": "Compressed Title Value"
  let mut itxt = Vec::new();
  itxt.extend_from_slice(b"Title\0"); // keyword
  itxt.push(1); // compressed flag = 1
  itxt.push(0); // method = deflate
  itxt.extend_from_slice(b"en-us\0"); // language
  itxt.extend_from_slice(b"\0"); // translated keyword (empty)
  itxt.extend_from_slice(&zlib_store("Compressed Title Value".as_bytes()));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info("z_itxt_title.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:Title-en-US\":\"Compressed Title Value\""),
    "expected inflated compressed-iTXt Title-en-US, got {json}",
  );
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
}

#[test]
fn engine_itxt_compressed_xmp_is_deferred() {
  // Oracle on a compressed iTXt whose keyword is `XML:com.adobe.xmp` emits NO
  // `PNG:XML...` tag — bundled routes it to XMP::Main (we defer XMP). The
  // chunk is still recognized (it inflates cleanly, no warning); the value is
  // simply not emitted as a PNG tag.
  let mut itxt = Vec::new();
  itxt.extend_from_slice(b"XML:com.adobe.xmp\0");
  itxt.push(1); // compressed
  itxt.push(0); // method
  itxt.extend_from_slice(b"\0\0"); // empty lang, empty translated
  itxt.extend_from_slice(&zlib_store(
    "<x:xmpmeta>Phil Harvey compressed</x:xmpmeta>".as_bytes(),
  ));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info("z_itxt_xmp.png", &bytes, /* print_conv */ true);
  // No XMP tag is emitted (deferred), but the structural PNG tags are present.
  assert!(!json.contains("com.adobe.xmp"), "got {json}");
  assert!(!json.contains("Phil Harvey"), "got {json}");
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
  // Clean inflate ⇒ no inflate warning.
  assert!(!json.contains("Error inflating"), "got {json}");
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
}

#[test]
fn engine_zxif_inflates_compressed_exif() {
  // A realistic zXIf (compressed `eXIf`) chunk carrying a real little-endian
  // EXIF IFD0 (Make/Model). The `\0`-typed body is `\0 + <4-byte uncompressed
  // length, big-endian> + zlib(TIFF)` (`PNG.pm:1100-1101` writes
  // `"\0" . pack('N',$len) . $deflated`; the reader skips the 5-byte header via
  // `substr($$dataPt, 5)`, `PNG.pm:1379`). We deliberately set the 4-byte
  // length field to the ACTUAL uncompressed length (NON-zero) to prove the
  // skip-5 decode ignores it (an off-by-one in the header skip would corrupt
  // the inflate). Oracle (`perl exiftool -j -G1`, which has Compress::Zlib):
  //   "File:ExifByteOrder": "Little-endian (Intel, II)"
  //   "IFD0:Make": "NIKON CORPORATION"
  //   "IFD0:Model": "NIKON D850"
  let tiff = tiff_make_model("NIKON CORPORATION", "NIKON D850");
  // zXIf body: `\0` type marker + 4-byte big-endian uncompressed length +
  // zlib(tiff). (`zlib_store` is a valid RFC-1950 stream that bundled inflates
  // identically; the test crate has no deflate encoder.)
  let mut body = Vec::new();
  body.push(0);
  body.extend_from_slice(&(tiff.len() as u32).to_be_bytes()); // realistic length
  body.extend_from_slice(&zlib_store(&tiff));
  // Dispatch the ACTUAL `zxIf` chunk type (`%stdCase` `PNG.pm:56`), not an
  // `eXIf` chunk with a compressed body — both route to ProcessPNG_eXIf.
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zxIf", &body)]);
  let json = extract_info("z_zxif.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"IFD0:Make\":\"NIKON CORPORATION\""),
    "got {json}",
  );
  assert!(json.contains("\"IFD0:Model\":\"NIKON D850\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
  // The decoded EXIF emits NO `PNG:` text record for the chunk.
  assert!(!json.contains("\"PNG:eXIf\""), "got {json}");
}

#[test]
fn engine_zxif_inflated_exif00_is_stripped_and_warns() {
  // R14 regression: a `zxIf` whose INFLATED bytes carry the improper `Exif\0\0`
  // prefix. Bundled re-enters `ProcessPNG_eXIf` on the inflated buffer
  // (`PNG.pm:1389`, `FoundPNG(..., level 2)`), so it strips the 6-byte `Exif00`
  // marker (warning `Improper "Exif00" header in EXIF chunk`) and STILL decodes
  // the TIFF. The inflate path must apply the SAME strip+validation as an
  // uncompressed `eXIf`, not push the raw inflated bytes (which would fail to
  // parse, dropping the EXIF). Oracle (`perl exiftool -j -G1`):
  //   "ExifTool:Warning": "Improper \"Exif00\" header in EXIF chunk"
  //   "IFD0:Make": "ZxifExif00Make"   "IFD0:Model": "ZxifExif00Model"
  let mut inner = b"Exif\0\0".to_vec();
  inner.extend_from_slice(&tiff_make_model("ZxifExif00Make", "ZxifExif00Model"));
  let mut body = Vec::new();
  body.push(0);
  body.extend_from_slice(&(inner.len() as u32).to_be_bytes());
  body.extend_from_slice(&zlib_store(&inner));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zxIf", &body)]);
  let json = extract_info("z_zxif_exif00.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("header in EXIF chunk"),
    "expected Improper Exif00 warning, got {json}",
  );
  assert!(
    json.contains("\"IFD0:Make\":\"ZxifExif00Make\""),
    "got {json}"
  );
  assert!(
    json.contains("\"IFD0:Model\":\"ZxifExif00Model\""),
    "got {json}"
  );
}

#[test]
fn engine_zxif_inflated_garbage_warns_invalid_zxif_chunk() {
  // R14 regression (the `$tag` interpolation): a `zxIf` whose inflated content
  // is NOT a TIFF (`II`/`MM`). Bundled's re-entry fails the `^(\0|II|MM)` check
  // (`PNG.pm:1374`) and warns `Invalid $tag chunk` — with `$tag` the ACTUAL
  // chunk type (`zxIf`, `PNG.pm:1364` `$tag = $$tagInfo{TagID}`), NOT a
  // hard-coded `eXIf`. Oracle (`perl exiftool -j -G1`):
  //   "ExifTool:Warning": "Invalid zxIf chunk"   (and NO IFD0 tags)
  let inner = b"NOTATIFFblock_xxxxxxxxxxxxxxxxxx".to_vec();
  let mut body = Vec::new();
  body.push(0);
  body.extend_from_slice(&(inner.len() as u32).to_be_bytes());
  body.extend_from_slice(&zlib_store(&inner));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zxIf", &body)]);
  let json = extract_info("z_zxif_garbage.png", &bytes, /* print_conv */ true);
  assert!(json.contains("Invalid zxIf chunk"), "got {json}");
  assert!(!json.contains("\"IFD0:Make\""), "got {json}");
}

#[test]
fn engine_ztxt_corrupt_stream_warns_error_inflating() {
  // Oracle on a zTXt "Comment" with a corrupt zlib stream:
  //   "ExifTool:Warning": "Error inflating Comment"
  let mut ztxt = Vec::new();
  ztxt.extend_from_slice(b"Comment\0");
  ztxt.push(0); // method = deflate
  ztxt.extend_from_slice(b"\x78\x9c\xde\xad\xbe\xef\xff"); // corrupt
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zTXt", &ztxt)]);
  let json = extract_info("z_ztxt_corrupt.png", &bytes, /* print_conv */ true);
  assert!(json.contains("Error inflating Comment"), "got {json}");
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
}

#[test]
fn engine_ztxt_unknown_method_warns() {
  // Oracle on a zTXt with a non-zero compression method (5):
  //   "ExifTool:Warning": "Unknown compression method 5 for Comment"
  let mut ztxt = Vec::new();
  ztxt.extend_from_slice(b"Comment\0");
  ztxt.push(5); // unknown method
  ztxt.extend_from_slice(b"\x01\x02\x03");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zTXt", &ztxt)]);
  let json = extract_info("z_ztxt_badmethod.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("Unknown compression method 5 for Comment"),
    "got {json}",
  );
}

#[test]
fn engine_extract_info_short_png_rejected() {
  // 7 bytes of the signature — short read.
  let short = b"\x89PNG\r\n\x1a".to_vec();
  let json = extract_info(FIXTURE, &short, true);
  // No `File:FileType=PNG` — the candidate was detected by magic but the
  // parse returned None, so the engine falls through.
  assert!(!json.contains("\"File:FileType\":\"PNG\""), "got {json}");
}

#[test]
fn engine_extract_info_truncated_after_signature_emits_warning() {
  // Signature only — a valid PNG signature but no chunks.
  let bytes = b"\x89PNG\r\n\x1a\n".to_vec();
  let json = extract_info(FIXTURE, &bytes, true);
  // The engine accepts the PNG candidate (signature matched) and emits
  // the `Truncated PNG image` warning.
  assert!(
    json.contains("\"File:FileType\":\"PNG\""),
    "PNG signature should be accepted: {json}",
  );
  assert!(
    json.contains("Truncated PNG image"),
    "expected Truncated PNG image warning: {json}",
  );
}

// ===========================================================================
// ImageMagick "Raw profile type X" chunks (PNG.pm:689-762 + ProcessProfile
// PNG.pm:1155-1281). Every assertion is verified against bundled
// `perl exiftool -j -G1` on the hand-built fixture (the hex-encoded EXIF is a
// real little-endian TIFF/EXIF block via `tiff_make_model`).
// ===========================================================================

#[test]
fn engine_raw_profile_exif_text_decodes_embedded_exif() {
  // `tEXt` keyword `Raw profile type exif`, body = `\nexif\n  <len>\n<hex TIFF>`.
  // Oracle:
  //   "File:ExifByteOrder": "Little-endian (Intel, II)"
  //   "IFD0:Make": "Canon"
  //   "IFD0:Model": "Canon EOS R5"
  // and crucially NO `PNG:"Raw profile type exif"` text tag (bundled emits the
  // DECODED EXIF or nothing — never the keyword=hex text record).
  let tiff = tiff_make_model("Canon", "Canon EOS R5");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_exif.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"Canon\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"Canon EOS R5\""),
    "got {json}"
  );
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // No plain-text record for the raw-profile keyword.
  assert!(!json.contains("Raw profile type exif"), "got {json}");
  assert!(!json.contains("EXIF_Profile"), "got {json}");
}

#[test]
fn engine_raw_profile_exif_itxt_decodes_embedded_exif() {
  // A `Raw profile type exif` keyword in an iTXt chunk (UTF-8) routes to
  // ProcessProfile via the shared PNG TextualData table — exactly like
  // tEXt/zTXt — so the embedded EXIF decodes and NO `PNG:"Raw profile type
  // exif"` text tag is emitted (the suppression holds for iTXt too). Oracle
  // (`perl exiftool -j -G1` on an equivalent crafted iTXt-raw-profile PNG):
  //   "IFD0:Make": "Sony", "IFD0:Model": "ILCE-7M4",
  //   "File:ExifByteOrder": "Little-endian (Intel, II)".
  let tiff = tiff_make_model("Sony", "ILCE-7M4");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  // iTXt layout: keyword\0 + compressed(0) + method(0) + lang\0 + translated\0
  // + value (the raw-profile body — ASCII, UTF-8-safe).
  let mut itxt = b"Raw profile type exif\0".to_vec();
  itxt.push(0); // uncompressed
  itxt.push(0); // method
  itxt.extend_from_slice(b"\0"); // language (empty)
  itxt.extend_from_slice(b"\0"); // translated keyword (empty)
  itxt.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info("rp_exif_itxt.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"Sony\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ILCE-7M4\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // Suppression: no plain-text record for the raw-profile keyword.
  assert!(!json.contains("Raw profile type exif"), "got {json}");
}

#[test]
fn engine_large_idat_reaches_post_idat_text() {
  // A large (256 KB) IDAT followed by a tEXt chunk: the walker must advance
  // past IDAT (which carries no metadata) and still extract the post-IDAT
  // text. The read path no longer copies chunk data into a CRC buffer (bundled
  // validates CRC only in verbose/validate mode, PNG.pm:123-124), so a multi-MB
  // IDAT is skipped without allocation. Reaching `PNG:Comment` proves the walk
  // advances correctly; the after-IDAT warning (PNG.pm:1598) also fires.
  let idat = vec![0u8; 256 * 1024];
  let mut text = b"Comment\0".to_vec();
  text.extend_from_slice(b"after idat");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"IDAT", &idat), chunk(b"tEXt", &text)]);
  let json = extract_info("large_idat.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"PNG:Comment\":\"after idat\""),
    "post-IDAT tEXt must be reached past a large IDAT, got {json}",
  );
  assert!(
    json.contains("found after PNG IDAT"),
    "expected the after-IDAT warning, got {json}",
  );
}

#[test]
fn engine_raw_profile_exif_ztxt_decodes_embedded_exif() {
  // SAME as above but carried in a COMPRESSED `zTXt` chunk (inflate → profile
  // → hex-decode → EXIF). Oracle decodes IFD0:Make/Model identically.
  let tiff = tiff_make_model("FUJIFILM", "X-T5");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  let mut ztxt = b"Raw profile type exif\0".to_vec();
  ztxt.push(0); // compression method = deflate
  ztxt.extend_from_slice(&zlib_store(&body));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zTXt", &ztxt)]);
  let json = extract_info("rp_exif_z.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"FUJIFILM\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"X-T5\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  assert!(!json.contains("Raw profile type exif"), "got {json}");
  assert!(!json.contains("Install Compress::Zlib"), "got {json}");
}

#[test]
fn engine_raw_profile_app1_with_exif00_decodes_embedded_exif() {
  // `Raw profile type APP1` carrying a `Exif\0\0`-prefixed TIFF (the JPEG APP1
  // layout). ProcessProfile's EXIF arm strips the 6-byte `Exif\0\0` marker
  // (`PNG.pm:1219-1221`, $exifAPP1hdr) then ProcessTIFF. Oracle: IFD0:Make/Model.
  let tiff = tiff_make_model("SONY", "ILCE-7M4");
  let mut app1 = b"Exif\0\0".to_vec();
  app1.extend_from_slice(&tiff);
  let body = raw_profile_body("APP1", &app1, app1.len());
  let mut text = b"Raw profile type APP1\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_app1.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"SONY\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ILCE-7M4\""), "got {json}");
  assert!(!json.contains("Raw profile type APP1"), "got {json}");
  assert!(!json.contains("APP1_Profile"), "got {json}");
}

#[test]
fn engine_raw_profile_app1_bare_tiff_decodes_embedded_exif() {
  // `Raw profile type APP1` carrying a BARE TIFF (no `Exif\0\0` prefix).
  // ProcessProfile's `^(MM\0\x2a|II\x2a\0)` arm (`PNG.pm:1250`) → ProcessTIFF.
  let tiff = tiff_make_model("Panasonic", "DC-S5M2");
  let body = raw_profile_body("APP1", &tiff, tiff.len());
  let mut text = b"Raw profile type APP1\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_app1_bare.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"Panasonic\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"DC-S5M2\""), "got {json}");
  assert!(!json.contains("Raw profile type APP1"), "got {json}");
}

#[test]
fn engine_raw_profile_exif_wrong_size_warns_and_continues() {
  // A declared `<len>` that disagrees with the actual decoded length triggers
  // the bundled wrong-size warning (`PNG.pm:1172`) using the SubDirectory tag
  // Name `EXIF_Profile`, then continues with the ACTUAL bytes (EXIF still
  // decodes). Oracle on a 57-byte TIFF declared as 62:
  //   "ExifTool:Warning": "EXIF_Profile is wrong size (should be 62 bytes but is 57)"
  //   "IFD0:Make": "TestMake"
  let tiff = tiff_make_model("TestMake", "TestModel");
  let wrong = tiff.len() + 5;
  let body = raw_profile_body("exif", &tiff, wrong);
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_exif_wrong.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains(&format!(
      "EXIF_Profile is wrong size (should be {wrong} bytes but is {})",
      tiff.len()
    )),
    "got {json}",
  );
  // Continues with the actual bytes — EXIF still decoded.
  assert!(json.contains("\"IFD0:Make\":\"TestMake\""), "got {json}");
}

#[test]
fn engine_raw_profile_app1_xmp_is_deferred_no_tag_no_warning() {
  // `Raw profile type APP1` whose decoded body starts with the XMP namespace
  // marker (`http://ns.adobe.com/xap/1.0/\0`) → ProcessProfile's XMP arm
  // (`PNG.pm:1236`). exifast has no XMP module (#37): suppress, emit NO tag and
  // NO warning. The structural PNG tags are unaffected.
  let mut xmp = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
  xmp.extend_from_slice(b"<x:xmpmeta>Phil Harvey</x:xmpmeta>");
  let body = raw_profile_body("APP1", &xmp, xmp.len());
  let mut text = b"Raw profile type APP1\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_app1_xmp.png", &bytes, /* print_conv */ true);
  assert!(!json.contains("Raw profile type APP1"), "got {json}");
  assert!(!json.contains("Phil Harvey"), "got {json}");
  assert!(!json.contains("com.adobe.xmp"), "got {json}");
  assert!(!json.contains("Unknown raw profile"), "got {json}");
  // Structural PNG tags still present.
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
}

#[test]
fn engine_raw_profile_icc_is_suppressed() {
  // `Raw profile type icc` → ICC_Profile::Main (no ported module). exifast
  // suppresses: NO `PNG:"Raw profile type icc"` text tag, no ICC tags. (Bundled
  // would emit ICC_Profile:* tags; that whole module is deferred like iCCP.)
  let body = raw_profile_body(
    "icc",
    b"\0\0\0\x0cfake-icc-data",
    b"\0\0\0\x0cfake-icc-data".len(),
  );
  let mut text = b"Raw profile type icc\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_icc.png", &bytes, /* print_conv */ true);
  assert!(!json.contains("Raw profile type icc"), "got {json}");
  assert!(!json.contains("\"PNG:ICC_Profile\""), "got {json}");
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
}

#[test]
fn engine_raw_profile_iptc_is_suppressed() {
  // `Raw profile type iptc` → Photoshop/IPTC (no ported module). Suppress: NO
  // `PNG:"Raw profile type iptc"` text tag, no IPTC tags. (Bundled would emit
  // IPTC:* tags.)
  let raw = b"\x1c\x02\x00\x00\x03ABC";
  let body = raw_profile_body("iptc", raw, raw.len());
  let mut text = b"Raw profile type iptc\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_iptc.png", &bytes, /* print_conv */ true);
  assert!(!json.contains("Raw profile type iptc"), "got {json}");
  assert!(!json.contains("IPTC"), "got {json}");
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
}

#[test]
fn engine_raw_profile_exif_garbage_warns_unknown_raw_profile() {
  // `Raw profile type exif` whose decoded body is neither TIFF nor XMP nor
  // `Exif\0\0` → ProcessProfile's final else (`PNG.pm:1266-1269`) warns
  // `Unknown raw profile '<type>'` (the profile-type string with control / high
  // bytes dotted). No EXIF, no text tag. Oracle:
  //   "ExifTool:Warning": "Unknown raw profile 'exif'"
  let raw = b"GARBAGE_NOT_TIFF";
  let body = raw_profile_body("exif", raw, raw.len());
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_exif_garbage.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("Unknown raw profile 'exif'"),
    "expected the Unknown-raw-profile warning, got {json}",
  );
  assert!(!json.contains("IFD0:Make"), "got {json}");
  assert!(!json.contains("Raw profile type exif"), "got {json}");
}

#[test]
fn engine_raw_profile_exif_wins_over_coexisting_exif_chunk() {
  // A pathological-but-real PNG with BOTH an `eXIf` chunk and an ImageMagick
  // `Raw profile type exif` tEXt. Bundled's `ProcessProfile` resets
  // `$$et{PROCESSED}` (`PNG.pm:1193`), so the raw-profile EXIF OVERWRITES the
  // `eXIf` chunk's IFD0 regardless of order. Oracle (eXIf chunk first, raw
  // profile second):
  //   "IFD0:Make": "ProfileMake"   (the RAW-PROFILE value, not the eXIf one)
  //   "IFD0:Model": "ProfileModel"
  let exif_tiff = tiff_make_model("EXIFchunkMake", "EXIFchunkModel");
  let prof_tiff = tiff_make_model("ProfileMake", "ProfileModel");
  let body = raw_profile_body("exif", &prof_tiff, prof_tiff.len());
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &exif_tiff),
    chunk(b"tEXt", &text),
  ]);
  let json = extract_info("rp_coexist.png", &bytes, /* print_conv */ true);
  // The raw-profile EXIF wins.
  assert!(json.contains("\"IFD0:Make\":\"ProfileMake\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"ProfileModel\""),
    "got {json}"
  );
  assert!(!json.contains("EXIFchunkMake"), "got {json}");
  assert!(!json.contains("Raw profile type exif"), "got {json}");
}

#[test]
fn engine_raw_profile_and_exif_chunk_merge_unique_tags() {
  // Bundled MERGES PNG EXIF sources (`ProcessProfile` resets `$$et{PROCESSED}`,
  // PNG.pm:1193): UNIQUE tags from BOTH the `eXIf` chunk and the raw-profile
  // survive — the raw-profile wins only on CONFLICT. Here the `eXIf` chunk
  // carries Model ONLY and the raw-profile Make ONLY (no overlap). Oracle
  // (`perl exiftool -j -G1`): BOTH `IFD0:Make` and `IFD0:Model` are emitted —
  // proving `tags()` must replay BOTH blocks, not pick one (the R2 bug).
  let exif_tiff = tiff_one_tag(0x0110, "ExifChunkOnlyModel"); // Model
  let prof_tiff = tiff_one_tag(0x010f, "ProfileOnlyMake"); // Make
  let body = raw_profile_body("exif", &prof_tiff, prof_tiff.len());
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &exif_tiff),
    chunk(b"tEXt", &text),
  ]);
  let json = extract_info("rp_merge.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"IFD0:Make\":\"ProfileOnlyMake\""),
    "raw-profile Make must be present, got {json}",
  );
  // The eXIf chunk's UNIQUE Model must survive the merge (the raw-profile has
  // no Model, so it must NOT be dropped).
  assert!(
    json.contains("\"IFD0:Model\":\"ExifChunkOnlyModel\""),
    "eXIf chunk's unique Model must survive the raw-profile merge, got {json}",
  );
}

// ===========================================================================
// SOURCE-ORDER-AWARE multi-EXIF-source handling — the OFFSET-KEYED cycle-guard
// (ExifTool.pm:9061-9072) + ProcessProfile PROCESSED-reset (PNG.pm:1193). A PNG
// can carry several EXIF sources — native `eXIf` chunks and ImageMagick `Raw
// profile type exif` tEXt chunks. Bundled processes them in CHUNK ORDER, keying
// its cycle-guard on each source's IFD0 `$addr` (the TIFF header's IFD0
// pointer): a source whose `$addr` was already processed is BLOCKED (it warns
// "IFD0 pointer references previous IFD0 directory" and `return 0`s), while a
// raw-profile source's `ProcessProfile` first CLEARS `$$et{PROCESSED}`. So
// order, provenance, AND the IFD0 offset jointly decide the winning set.
//
// Every expected value below was captured from the LOCAL bundled oracle
// (`/Users/al/Developer/findit-studio/exiftool/exiftool -j -G1` = 13.59, which
// has Compress::Zlib) run on the BYTE-IDENTICAL PNG these helpers build
// (`tiff_make_model` / `tiff_one_tag` always use the offset value path, so the
// crafted bytes match the oracle run exactly). Asserted against `extract_info`
// in print_conv mode (Make/Model are identity under PrintConv).
//
// Two DISCRIMINATORS prove offset-keying (not the retired boolean flag):
//   * `engine_raw_profile_then_exif_chunk_disjoint_drops_chunk` — profile
//     [Make]@8 THEN eXIf[Model]@8 (SAME offset) ⇒ Make present, Model ABSENT +
//     the cycle-guard WARNING (the eXIf's addr 8 collides);
//   * `engine_raw_profile_then_exif_chunk_different_offset_merges_both` — the
//     SAME ordering but eXIf[Model]@40 (DIFFERENT offset) ⇒ BOTH Make and Model
//     present, NO warning (no collision). The boolean flag wrongly blocked this.
// `engine_three_same_offset_sources_clean_values_not_garbage` documents the
// 3+-same-offset INFEASIBLE class (bundled emits control-char garbage; the port
// emits clean values + the warning instead).
// ===========================================================================

/// Build a `Raw profile type exif` tEXt chunk wrapping `tiff`.
fn raw_profile_exif_chunk(tiff: &[u8]) -> Vec<u8> {
  let body = raw_profile_body("exif", tiff, tiff.len());
  let mut text = b"Raw profile type exif\0".to_vec();
  text.extend_from_slice(&body);
  chunk(b"tEXt", &text)
}

#[test]
fn engine_exif_chunk_then_raw_profile_overlap_profile_wins() {
  // Case 1: eXIf[Make=ExifMake,Model=ExifModel] THEN profile[Make=ProfMake,
  // Model=ProfModel]. Both sources contribute (profile resets PROCESSED); the
  // profile is last so it wins on both overlapping tags.
  // Oracle (local 13.59): "IFD0:Make":"ProfMake", "IFD0:Model":"ProfModel".
  let exif = tiff_make_model("ExifMake", "ExifModel");
  let prof = tiff_make_model("ProfMake", "ProfModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &exif),
    raw_profile_exif_chunk(&prof),
  ]);
  let json = extract_info("c1_exif_then_prof.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"ProfMake\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ProfModel\""), "got {json}");
  assert!(!json.contains("ExifMake"), "got {json}");
  assert!(!json.contains("ExifModel"), "got {json}");
  // The profile RESETS PROCESSED before re-processing addr 8, so NO cycle-guard
  // warning fires (the eXIf processed, then the profile re-processed cleanly).
  assert!(
    !json.contains("references previous"),
    "no cycle-guard warning when the profile resets PROCESSED, got {json}",
  );
}

#[test]
fn engine_raw_profile_then_exif_chunk_overlap_profile_still_wins() {
  // Case 2: profile[Make=ProfMake,Model=ProfModel]@8 THEN eXIf[Make=ExifMake,
  // Model=ExifModel]@8. The profile is FIRST and resets PROCESSED, so it
  // processes IFD0 (addr 8); the eXIf is then BLOCKED — its IFD0 `$addr` (also
  // 8) collides with the already-processed directory (the offset-keyed
  // cycle-guard, ExifTool.pm:9067-9070) — so it contributes NOTHING and the
  // profile values still win, AND the cycle-guard warning fires.
  // Oracle (local 13.59): "IFD0:Make":"ProfMake", "IFD0:Model":"ProfModel",
  //   "ExifTool:Warning":"IFD0 pointer references previous IFD0 directory".
  let exif = tiff_make_model("ExifMake", "ExifModel");
  let prof = tiff_make_model("ProfMake", "ProfModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    raw_profile_exif_chunk(&prof),
    chunk(b"eXIf", &exif),
  ]);
  let json = extract_info("c2_prof_then_exif.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"ProfMake\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ProfModel\""), "got {json}");
  assert!(!json.contains("ExifMake"), "got {json}");
  assert!(!json.contains("ExifModel"), "got {json}");
  // The blocked eXIf source raises the offset-keyed cycle-guard warning.
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "blocked eXIf must emit the cycle-guard warning, got {json}",
  );
}

#[test]
fn engine_exif_chunk_then_raw_profile_disjoint_merges_both() {
  // Case 3: eXIf[Model only] THEN profile[Make only]. The eXIf processes its
  // IFD0 (Model), then the profile resets PROCESSED and processes its IFD0
  // (Make). Disjoint tags ⇒ BOTH survive.
  // Oracle (local 13.59): "IFD0:Make":"ProfileOnlyMake",
  //                       "IFD0:Model":"ExifChunkOnlyModel".
  let exif = tiff_one_tag(0x0110, "ExifChunkOnlyModel"); // Model only
  let prof = tiff_one_tag(0x010f, "ProfileOnlyMake"); // Make only
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &exif),
    raw_profile_exif_chunk(&prof),
  ]);
  let json = extract_info("c3_exif_model_then_prof_make.png", &bytes, true);
  assert!(
    json.contains("\"IFD0:Make\":\"ProfileOnlyMake\""),
    "got {json}"
  );
  assert!(
    json.contains("\"IFD0:Model\":\"ExifChunkOnlyModel\""),
    "got {json}"
  );
  // The profile RESETS PROCESSED before processing its addr 8, so NO
  // cycle-guard warning fires (both sources processed cleanly).
  assert!(
    !json.contains("references previous"),
    "no cycle-guard warning in the forward disjoint case, got {json}",
  );
}

#[test]
fn engine_raw_profile_then_exif_chunk_disjoint_drops_chunk() {
  // Case 4 — THE DISCRIMINATING (same-offset) CASE. profile[Make only]@8 THEN
  // eXIf[Model only]@8. The profile is FIRST: it resets PROCESSED and processes
  // IFD0 (Make, addr 8). The eXIf is then BLOCKED — its IFD0 `$addr` (also 8)
  // collides — and its Model is DROPPED even though the profile carries no
  // Model. This is what a fixed `[exif, profile]` replay gets WRONG (it would
  // emit the eXIf Model too). Crucially the IFD0 offsets MATCH (both @8), which
  // is what trips the offset-keyed cycle-guard; see the different-offset
  // discriminator `engine_raw_profile_then_exif_chunk_different_offset_*`.
  // Oracle (local 13.59): "IFD0:Make":"ProfileOnlyMake"; IFD0:Model ABSENT;
  //   "ExifTool:Warning":"IFD0 pointer references previous IFD0 directory".
  let exif = tiff_one_tag(0x0110, "ExifChunkOnlyModel"); // Model only (BLOCKED)
  let prof = tiff_one_tag(0x010f, "ProfileOnlyMake"); // Make only
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    raw_profile_exif_chunk(&prof),
    chunk(b"eXIf", &exif),
  ]);
  let json = extract_info("c4_prof_make_then_exif_model.png", &bytes, true);
  assert!(
    json.contains("\"IFD0:Make\":\"ProfileOnlyMake\""),
    "profile Make must survive, got {json}"
  );
  // The eXIf chunk's Model is BLOCKED — it must NOT appear at all.
  assert!(
    !json.contains("IFD0:Model"),
    "the BLOCKED eXIf Model must be dropped (PROCESSED already set), got {json}"
  );
  assert!(!json.contains("ExifChunkOnlyModel"), "got {json}");
  // The blocked eXIf source raises the offset-keyed cycle-guard warning.
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "blocked eXIf must emit the cycle-guard warning, got {json}",
  );
}

#[test]
fn engine_raw_profile_then_exif_chunk_different_offset_merges_both() {
  // Case 5 — THE OFFSET DISCRIMINATOR (proves offset-keying, not the retired
  // boolean flag). profile[Make only]@8 THEN eXIf[Model only]@40. SAME ordering
  // as the discriminating DROP case (Case 4), but the eXIf's IFD0 lives at a
  // DIFFERENT offset (40, not 8), so its `$addr` does NOT collide with the
  // profile's already-processed addr 8 (ExifTool.pm:9066-9070). Both sources
  // therefore process ⇒ BOTH Make and Model survive, and NO cycle-guard warning
  // fires. The retired boolean `processed` flag got this WRONG (it blocked ANY
  // later native source once IFD0 was processed, regardless of offset).
  // Oracle (local 13.59): "IFD0:Make":"ProfileOnlyMake",
  //   "IFD0:Model":"ExifChunkOnlyModel"; NO ExifTool:Warning.
  let prof = tiff_one_tag_at(8, 0x010f, "ProfileOnlyMake"); // Make only, IFD0 @8
  let exif = tiff_one_tag_at(40, 0x0110, "ExifChunkOnlyModel"); // Model only, IFD0 @40
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    raw_profile_exif_chunk(&prof),
    chunk(b"eXIf", &exif),
  ]);
  let json = extract_info("c5_prof8_then_exif40.png", &bytes, true);
  // Both survive — the different IFD0 offset means no collision.
  assert!(
    json.contains("\"IFD0:Make\":\"ProfileOnlyMake\""),
    "profile Make must survive, got {json}",
  );
  assert!(
    json.contains("\"IFD0:Model\":\"ExifChunkOnlyModel\""),
    "different-offset eXIf Model must NOT be blocked (offset-keyed guard), got {json}",
  );
  // No collision ⇒ no cycle-guard warning (the boolean-flag port would block
  // the eXIf here AND would not warn; this asserts the tag-merge half).
  assert!(
    !json.contains("references previous"),
    "different offsets must NOT trip the cycle-guard, got {json}",
  );
}

#[test]
fn engine_three_same_offset_sources_clean_values_not_garbage() {
  // INFEASIBLE-CLASS GUARD (documented, not chased). With 3+ sources sharing
  // ONE IFD0 `$addr`, bundled's emergent C-buffer/offset arithmetic yields
  // CONTROL-CHAR GARBAGE values (verified on local 13.59: three native eXIf@8
  // sources ⇒ "IFD0:Make":"&", "IFD0:Model":")" + the cycle-guard warning
  // "[x2]"). That garbage is BEYOND the documented cycle-guard
  // (ExifTool.pm:9066-9072, which simply warns + skips). This port faithfully
  // reproduces the DOCUMENTED algorithm: the FIRST source processes cleanly,
  // the next two are BLOCKED (each emitting the cycle-guard warning), and NO
  // garbage bytes are produced. So we assert CLEAN first-source values + the
  // warning, NOT the bundled garbage.
  let s1 = tiff_make_model("FirstMake", "FirstModel");
  let s2 = tiff_make_model("SecondMake", "SecondModel");
  let s3 = tiff_make_model("ThirdMake", "ThirdModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &s1),
    chunk(b"eXIf", &s2),
    chunk(b"eXIf", &s3),
  ]);
  let json = extract_info("g_three_same_offset.png", &bytes, true);
  // The first source processed cleanly; the other two are blocked.
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"FirstModel\""), "got {json}");
  assert!(!json.contains("SecondMake"), "got {json}");
  assert!(!json.contains("ThirdMake"), "got {json}");
  // The two blocked sources each raise the cycle-guard warning.
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "blocked sources must emit the cycle-guard warning, got {json}",
  );
  // We do NOT reproduce bundled's control-char garbage (e.g. Make = "\x1a"/"&").
  assert!(
    !json.contains("\"IFD0:Make\":\"&\""),
    "port must emit clean values, not bundled's offset garbage, got {json}",
  );
}

#[test]
fn engine_cross_source_trailing_ifd_collision_blocks_second_source() {
  // R9 — THE CROSS-SOURCE TRAILING-IFD CASE the IFD0-only model missed.
  // Source 1 = an EXIF block with IFD0(Make=S1Make)@8 AND a trailing thumbnail
  // IFD1(Model=S1Model)@40 (via IFD0's next-IFD pointer). Source 2 = an EXIF
  // block whose IFD0(Model=S2Model) is at offset 40 — i.e. ON source 1's IFD1
  // `$addr`. Bundled processes both sources over ONE shared `$$et{PROCESSED}`
  // set: source 1 records addr 8 → IFD0 AND addr 40 → IFD1; source 2's IFD0
  // (addr 40) then collides with the recorded TRAILING IFD, so bundled warns
  // and skips source 2's IFD0 (it contributes nothing). The IFD0-only replay
  // compared source 2's IFD0 (40) only against source 1's IFD0 (8) — no
  // collision — and WRONGLY emitted S2Model.
  //
  // Oracle (local bundled 13.59, `perl exiftool -j -G1`), CLEAN (no garbage):
  //   "IFD0:Make": "S1Make", "IFD1:Model": "S1Model",
  //   "ExifTool:Warning": "IFD0 pointer references previous IFD1 directory";
  //   IFD0:Model ABSENT (S2Model dropped).
  let src1 = tiff_make_with_trailing_ifd1("S1Make", "S1Model", 40);
  let src2 = tiff_one_tag_at(40, 0x0110, "S2Model"); // IFD0 @40, Model only
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"eXIf", &src1), chunk(b"eXIf", &src2)]);
  let json = extract_info(
    "r9_trailing_collision.png",
    &bytes,
    /* print_conv */ true,
  );
  // Source 1's IFD0 Make + trailing IFD1 Model survive.
  assert!(json.contains("\"IFD0:Make\":\"S1Make\""), "got {json}");
  assert!(json.contains("\"IFD1:Model\":\"S1Model\""), "got {json}");
  // Source 2's IFD0 (addr 40) is BLOCKED by source 1's trailing IFD1 — its
  // Model must NOT appear (the trailing-IFD cross-source collision).
  assert!(
    !json.contains("S2Model"),
    "blocked source-2 Model must be dropped, got {json}"
  );
  assert!(
    !json.contains("\"IFD0:Model\""),
    "source-2 IFD0:Model must be absent (blocked), got {json}"
  );
  // The cross-source cycle-guard warning names the PREVIOUS directory as IFD1
  // (the recorded trailing IFD), NOT IFD0 — the discriminating text.
  assert!(
    json.contains("IFD0 pointer references previous IFD1 directory"),
    "expected the trailing-IFD cross-source cycle-guard warning, got {json}",
  );
}

// ===========================================================================
// MATRIX CLASS 6 + 7 + the well-formed-profile RESET gate — the unified
// PngExifEvent model's load-bearing decisions, each oracle-verified against
// local bundled 13.59 (`perl exiftool -j -G1`):
//   * a WELL-FORMED non-EXIF raw profile (icc/iptc/8bim/xmp, or an exif/APP1
//     profile whose decoded content is XMP or unrecognized) runs through
//     `ProcessProfile` and so RESETS `$$et{PROCESSED}` (PNG.pm:1193) between two
//     eXIf sources — un-blocking the second (Class 6);
//   * a MALFORMED raw profile (whose `^\n(.*?)\n\s*(\d+)\n(.*)` framing fails,
//     PNG.pm:1166) makes `ProcessProfile` `return 0` BEFORE the reset, so it
//     does NOT reset — the second eXIf stays blocked (Class 7);
//   * an `iCCP` BINARY chunk does NOT go through `ProcessProfile` at all, so it
//     also does NOT reset (model decision, oracle-confirmed).
// These exercise the `ResetOnlyProfile` / no-event branches the boolean source
// flag could not represent.
// ===========================================================================

/// Build an ImageMagick `Raw profile type <kind>` tEXt chunk wrapping `raw`
/// (well-formed framing). Used for the non-EXIF reset-only kinds (icc/iptc/…).
fn raw_profile_chunk(kind: &str, raw: &[u8]) -> Vec<u8> {
  let body = raw_profile_body(kind, raw, raw.len());
  let mut text = format!("Raw profile type {kind}\0").into_bytes();
  text.extend_from_slice(&body);
  chunk(b"tEXt", &text)
}

/// Build a `Raw profile type <kind>` tEXt chunk with a MALFORMED body (the
/// `ProcessProfile` framing fails: no leading newline), so bundled's
/// `ProcessProfile` `return 0`s before the `$$et{PROCESSED}` reset.
fn malformed_raw_profile_chunk(kind: &str) -> Vec<u8> {
  let mut text = format!("Raw profile type {kind}\0").into_bytes();
  text.extend_from_slice(b"GARBAGE-NOT-A-PROFILE-FRAMING");
  chunk(b"tEXt", &text)
}

/// Build an `iCCP` chunk: `name \0 method(0) zlib(profile)`.
fn iccp_chunk(name: &str, profile: &[u8]) -> Vec<u8> {
  let mut d = name.as_bytes().to_vec();
  d.push(0); // NUL after keyword
  d.push(0); // compression method = deflate
  d.extend_from_slice(&zlib_store(profile));
  chunk(b"iCCP", &d)
}

#[test]
fn engine_class6_icc_profile_resets_between_two_exif_sources() {
  // CLASS 6 — eXIf[Make@8] → `Raw profile type icc` (well-formed) → eXIf[Model@8].
  // The icc `ProcessProfile` RESETS `$$et{PROCESSED}`, so the SECOND eXIf@8
  // (same IFD0 addr) is NO LONGER blocked ⇒ BOTH Make + Model survive, and NO
  // cycle-guard warning fires. (exifast emits no ICC tags — deferred — but the
  // reset is the load-bearing effect.)
  // Oracle (local 13.59): "IFD0:Make":"FirstMake", "IFD0:Model":"SecondModel";
  //   NO "references previous" warning.
  let mk = tiff_one_tag(0x010f, "FirstMake"); // eXIf #1 Make @8
  let md = tiff_one_tag(0x0110, "SecondModel"); // eXIf #2 Model @8
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    raw_profile_chunk("icc", b"\x00\x00\x00\x0cfake-icc-data"),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("class6_icc_reset.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"SecondModel\""),
    "the icc profile must RESET PROCESSED so the 2nd eXIf un-blocks, got {json}",
  );
  assert!(
    !json.contains("references previous"),
    "a well-formed non-EXIF profile resets PROCESSED ⇒ no cycle-guard, got {json}",
  );
  // No ICC tags emitted (deferred sub-module).
  assert!(
    !json.contains("ICC_Profile"),
    "ICC decode is deferred, got {json}"
  );
}

#[test]
fn engine_class6_xmp_and_iptc_profiles_also_reset() {
  // CLASS 6 (variants) — the SAME reset for an `xmp` profile and an `iptc`
  // profile between two same-addr eXIf sources. Both run through
  // `ProcessProfile` ⇒ both reset ⇒ BOTH Make+Model survive, no warning.
  // Oracle (local 13.59): both → "IFD0:Make":"FirstMake",
  //   "IFD0:Model":"SecondModel"; no "references previous".
  let mk = tiff_one_tag(0x010f, "FirstMake");
  let md = tiff_one_tag(0x0110, "SecondModel");
  for (kind, raw) in [
    ("xmp", b"<?xpacket?><x:xmpmeta/>".as_slice()),
    ("8bim", b"8BIM\x04\x04\x00\x00\x00\x00\x00\x00".as_slice()),
  ] {
    let bytes = assemble(&[
      ihdr_rgb_1x1(),
      chunk(b"eXIf", &mk),
      raw_profile_chunk(kind, raw),
      chunk(b"eXIf", &md),
    ]);
    let json = extract_info(&format!("class6_{kind}_reset.png"), &bytes, true);
    assert!(
      json.contains("\"IFD0:Make\":\"FirstMake\""),
      "{kind}: got {json}"
    );
    assert!(
      json.contains("\"IFD0:Model\":\"SecondModel\""),
      "{kind} profile must RESET PROCESSED, got {json}",
    );
    assert!(
      !json.contains("references previous"),
      "{kind} profile resets ⇒ no cycle-guard, got {json}",
    );
  }
}

#[test]
fn engine_class6_app1_xmp_profile_resets_between_two_exif_sources() {
  // CLASS 6 (model decision) — eXIf[Make@8] → `Raw profile type APP1` carrying
  // XMP → eXIf[Model@8]. The APP1 profile's content is XMP (no ported module),
  // but `ProcessProfile` STILL resets `$$et{PROCESSED}` before the XMP dispatch
  // ⇒ the 2nd eXIf un-blocks ⇒ BOTH Make+Model. This locks the "APP1-XMP resets"
  // modeling decision (ResetOnlyProfile, NOT suppress-without-reset).
  // Oracle (local 13.59): "IFD0:Make":"FirstMake", "IFD0:Model":"SecondModel";
  //   no "references previous".
  let mk = tiff_one_tag(0x010f, "FirstMake");
  let md = tiff_one_tag(0x0110, "SecondModel");
  let mut xmp_app1 = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
  xmp_app1.extend_from_slice(b"<?xpacket?><x:xmpmeta/>");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    raw_profile_chunk("APP1", &xmp_app1),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("class6_app1xmp_reset.png", &bytes, true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"SecondModel\""),
    "APP1-with-XMP must RESET PROCESSED, got {json}",
  );
  assert!(
    !json.contains("references previous"),
    "APP1-XMP profile resets ⇒ no cycle-guard, got {json}",
  );
}

#[test]
fn engine_class6_unknown_content_profile_resets_and_warns() {
  // CLASS 6 (model decision) — eXIf[Make@8] → `Raw profile type exif` whose
  // well-formed body decodes to UNRECOGNIZED content (not TIFF, not XMP) →
  // eXIf[Model@8]. Bundled emits `Unknown raw profile 'exif'` AND still resets
  // `$$et{PROCESSED}` ⇒ the 2nd eXIf un-blocks ⇒ BOTH Make+Model. This locks the
  // unknown-content arm as ResetOnlyProfile (reset + warn).
  // Oracle (local 13.59): "IFD0:Make":"FirstMake", "IFD0:Model":"SecondModel",
  //   "ExifTool:Warning":"Unknown raw profile 'exif'"; no "references previous".
  let mk = tiff_one_tag(0x010f, "FirstMake");
  let md = tiff_one_tag(0x0110, "SecondModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    raw_profile_chunk("exif", b"this-is-not-tiff-not-xmp-not-exif"),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("class6_unknown_reset.png", &bytes, true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"SecondModel\""),
    "unknown-content profile must RESET PROCESSED, got {json}",
  );
  assert!(
    json.contains("Unknown raw profile 'exif'"),
    "unknown-content profile must warn, got {json}",
  );
  assert!(
    !json.contains("references previous"),
    "unknown-content profile resets ⇒ no cycle-guard, got {json}",
  );
}

// ===========================================================================
// ucfirst keyword-resolution fallback (PNG.pm:919-921). ImageMagick writes
// LOWERCASE PNG keywords ("raw profile type exif"); bundled's FoundPNG tries
// `ucfirst($tag)` after a direct-lookup miss, so a lowercase-first REGISTERED
// raw profile still resolves to its SubDirectory (decode + PROCESSED reset),
// rather than falling to the dynamic binary-tag path. Only the first char is
// upper-cased — mid-word Title-case / all-caps variants do NOT resolve. Each
// value verbatim from local bundled 13.59 (`perl exiftool -j -G1`).
// ===========================================================================

#[test]
fn engine_lowercase_raw_profile_exif_decodes_via_ucfirst() {
  // tEXt keyword `raw profile type exif` (LOWERCASE) carrying a hex-EXIF TIFF →
  // ucfirst → registered `Raw profile type exif` → DECODE. Oracle: IFD0:Make
  // present; NO `PNG:RawProfileType*` dynamic tag.
  let tiff = tiff_make_model("LowerCaseMake", "LowerCaseModel");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  let mut text = b"raw profile type exif\0".to_vec(); // LOWERCASE keyword
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("lc_rp_exif.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"IFD0:Make\":\"LowerCaseMake\""),
    "got {json}"
  );
  assert!(
    json.contains("\"IFD0:Model\":\"LowerCaseModel\""),
    "got {json}"
  );
  assert!(
    !json.contains("RawProfileType"),
    "a lowercase REGISTERED keyword must DECODE (ucfirst), not emit a dynamic tag; got {json}",
  );
}

#[test]
fn engine_lowercase_raw_profile_icc_resets_processed() {
  // A LOWERCASE non-EXIF raw profile (`raw profile type icc`) also resolves via
  // ucfirst → ProcessProfile → RESETS `$$et{PROCESSED}`, un-blocking a second
  // same-addr eXIf. Oracle (eXIf[Make@8] → lc-icc → eXIf[Model@8]): BOTH
  // Make + Model; no `references previous`.
  let mk = tiff_one_tag(0x010f, "FirstMakeLc");
  let md = tiff_one_tag(0x0110, "SecondModelLc");
  let icc_raw: &[u8] = b"\x00\x00\x00\x0cfake-icc-data";
  let body = raw_profile_body("icc", icc_raw, icc_raw.len());
  let mut icc = b"raw profile type icc\0".to_vec(); // LOWERCASE keyword
  icc.extend_from_slice(&body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    chunk(b"tEXt", &icc),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("lc_rp_icc_reset.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMakeLc\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"SecondModelLc\""),
    "lowercase icc profile must RESET PROCESSED (ucfirst → ProcessProfile), got {json}",
  );
  assert!(!json.contains("references previous"), "got {json}");
}

#[test]
fn engine_class7_malformed_profile_does_not_reset_second_exif_blocked() {
  // CLASS 7 — eXIf[Make@8] → MALFORMED `Raw profile type icc` (framing fails) →
  // eXIf[Model@8]. `ProcessProfile` `return 0`s BEFORE the reset (PNG.pm:1166),
  // so `$$et{PROCESSED}` is NOT cleared ⇒ the 2nd eXIf@8 collides with the
  // recorded IFD0 addr ⇒ BLOCKED (Model dropped) + the cycle-guard warning.
  // Oracle (local 13.59): "IFD0:Make":"FirstMake"; IFD0:Model ABSENT;
  //   "ExifTool:Warning":"IFD0 pointer references previous IFD0 directory".
  let mk = tiff_one_tag(0x010f, "FirstMake");
  let md = tiff_one_tag(0x0110, "SecondModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    malformed_raw_profile_chunk("icc"),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("class7_malformed_noreset.png", &bytes, true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  assert!(
    !json.contains("IFD0:Model"),
    "a MALFORMED profile must NOT reset ⇒ the 2nd eXIf stays blocked, got {json}",
  );
  assert!(!json.contains("SecondModel"), "got {json}");
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "the blocked 2nd eXIf must emit the cycle-guard warning, got {json}",
  );
}

#[test]
fn engine_iccp_binary_chunk_does_not_reset_second_exif_blocked() {
  // MODEL DECISION (iCCP) — eXIf[Make@8] → `iCCP` BINARY chunk → eXIf[Model@8].
  // `iCCP` does NOT route through `ProcessProfile` (it is a binary chunk, not a
  // `Raw profile type` tEXt), so it does NOT reset `$$et{PROCESSED}` ⇒ the 2nd
  // eXIf@8 stays BLOCKED (Model dropped) + the cycle-guard warning. This locks
  // the "iCCP captures the NAME only and emits NO EXIF event" modeling decision.
  // Oracle (local 13.59): "IFD0:Make":"FirstMake", "PNG:ProfileName":"sRGB";
  //   IFD0:Model ABSENT; "ExifTool:Warning":"IFD0 pointer references previous
  //   IFD0 directory".
  let mk = tiff_one_tag(0x010f, "FirstMake");
  let md = tiff_one_tag(0x0110, "SecondModel");
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &mk),
    iccp_chunk("sRGB", b"\x00\x00\x00\x0cfake-icc-data"),
    chunk(b"eXIf", &md),
  ]);
  let json = extract_info("iccp_noreset.png", &bytes, true);
  assert!(json.contains("\"IFD0:Make\":\"FirstMake\""), "got {json}");
  // The iCCP NAME is still captured (the only thing exifast emits for iCCP).
  assert!(json.contains("\"PNG:ProfileName\":\"sRGB\""), "got {json}");
  assert!(
    !json.contains("IFD0:Model"),
    "iCCP must NOT reset ⇒ the 2nd eXIf stays blocked, got {json}",
  );
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "the blocked 2nd eXIf must emit the cycle-guard warning, got {json}",
  );
}

// ===========================================================================
// #205 — raw-profile XMP diagnostics WALK-ORDER. ExifTool dispatches `Raw
// profile type xmp` (PNG.pm:746) via `ProcessProfile` → `ProcessXMP` AT the
// chunk's walk position, so its `XMP is double UTF-encoded` warning (XMP.pm:4494)
// interleaves with every other chunk's warning in serial chunk order. Because
// `Warning` is `Priority=0` FIRST-wins (ExifTool.pm:5404-5417), the document
// `ExifTool:Warning` surface is the EARLIEST-walked warning. The PNG port
// previously drained the raw-profile-XMP decode warning dead-last, surfacing a
// LATER chunk's warning instead; the unified ordered diagnostic replay
// (`PngMeta::diag_order`) fixes this. Both orderings are oracle-verified against
// local bundled 13.59 (`perl exiftool -warning -a -G1`).
// ===========================================================================

/// A double-UTF-encoded XMP packet: a RAW leading UTF-8 BOM (`\xef\xbb\xbf`)
/// DIRECTLY before `<?xpacket`, which trips ExifTool's double-encoding probe
/// (XMP.pm:4310) → the `XMP is double UTF-encoded` warning (XMP.pm:4494). The
/// re-decoded body is valid UTF-8, so the `XMP-dc:Format` tag is still emitted.
#[cfg(feature = "xmp")]
fn double_utf_xmp_packet() -> Vec<u8> {
  let mut v = vec![0xef, 0xbb, 0xbf];
  v.extend_from_slice(
    b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\
      <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
      <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
      <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
      <dc:format>image/png</dc:format>\
      </rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end='w'?>",
  );
  v
}

#[cfg(feature = "xmp")]
#[test]
fn engine_raw_profile_xmp_warning_before_bad_exif_surfaces_xmp_warning_first() {
  // FORWARD — `Raw profile type xmp` (malformed: double-UTF) THEN a bad `eXIf`.
  // The XMP chunk is walked FIRST, so `XMP is double UTF-encoded` is the document
  // FIRST `ExifTool:Warning` — NOT the later `Invalid eXIf chunk` (the #205 bug).
  // Oracle (local 13.59, `-warning -a -G1`): the warnings are emitted in the
  // order [XMP is double UTF-encoded, Invalid eXIf chunk].
  let body = raw_profile_body(
    "xmp",
    &double_utf_xmp_packet(),
    double_utf_xmp_packet().len(),
  );
  let mut text = b"Raw profile type xmp\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"tEXt", &text),
    chunk(b"eXIf", b"XXXXbadexifheader"),
  ]);
  let json = extract_info(
    "rp_xmp_warnorder_fwd.png",
    &bytes,
    /* print_conv */ true,
  );
  // The document first-warning is the XMP one (the earlier chunk).
  assert!(
    json.contains("\"ExifTool:Warning\":\"XMP is double UTF-encoded\""),
    "the earlier XMP raw-profile warning must surface as the first ExifTool:Warning, got {json}",
  );
  // The later eXIf warning must NOT be the surfaced first-warning (it is the
  // SECOND walked, so first-wins keeps the XMP one).
  assert!(
    !json.contains("\"ExifTool:Warning\":\"Invalid eXIf chunk\""),
    "the LATER eXIf warning must not win first-occurrence over the earlier XMP one, got {json}",
  );
  // The XMP packet still decoded (valid after the BOM strip).
  assert!(
    json.contains("\"XMP-dc:Format\":\"image/png\""),
    "got {json}"
  );
}

#[cfg(feature = "xmp")]
#[test]
fn engine_bad_exif_before_raw_profile_xmp_warning_surfaces_exif_warning_first() {
  // REVERSE — a bad `eXIf` THEN `Raw profile type xmp` (double-UTF). Now the
  // eXIf chunk is walked FIRST, so `Invalid eXIf chunk` is the document FIRST
  // `ExifTool:Warning` (this proves the fix is a genuine walk-order interleave,
  // not a blanket "XMP wins" — the symmetric case must invert).
  // Oracle (local 13.59, `-warning -a -G1`): the warnings are emitted in the
  // order [Invalid eXIf chunk, XMP is double UTF-encoded].
  let body = raw_profile_body(
    "xmp",
    &double_utf_xmp_packet(),
    double_utf_xmp_packet().len(),
  );
  let mut text = b"Raw profile type xmp\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", b"XXXXbadexifheader"),
    chunk(b"tEXt", &text),
  ]);
  let json = extract_info(
    "rp_xmp_warnorder_rev.png",
    &bytes,
    /* print_conv */ true,
  );
  assert!(
    json.contains("\"ExifTool:Warning\":\"Invalid eXIf chunk\""),
    "the earlier eXIf warning must surface as the first ExifTool:Warning, got {json}",
  );
  assert!(
    !json.contains("\"ExifTool:Warning\":\"XMP is double UTF-encoded\""),
    "the LATER XMP warning must not win first-occurrence over the earlier eXIf one, got {json}",
  );
  assert!(
    json.contains("\"XMP-dc:Format\":\"image/png\""),
    "got {json}"
  );
}

#[test]
fn engine_single_exif_chunk_source_matches_oracle() {
  // Single native eXIf source — one source, always processed.
  // Oracle (local 13.59): "IFD0:Make":"SoloMake", "IFD0:Model":"SoloModel".
  let exif = tiff_make_model("SoloMake", "SoloModel");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"eXIf", &exif)]);
  let json = extract_info("s_exif_only.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"SoloMake\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"SoloModel\""), "got {json}");
}

#[test]
fn engine_single_raw_profile_source_matches_oracle() {
  // Single ImageMagick raw-profile source — one source, resets then processes.
  // Oracle (local 13.59): "IFD0:Make":"SoloMake", "IFD0:Model":"SoloModel".
  let prof = tiff_make_model("SoloMake", "SoloModel");
  let bytes = assemble(&[ihdr_rgb_1x1(), raw_profile_exif_chunk(&prof)]);
  let json = extract_info("s_prof_only.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"SoloMake\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"SoloModel\""), "got {json}");
}

// ===========================================================================
// "Creation Time" date conversion (ConvertPNGDate, PNG.pm:630-639 +
// :832-855). Every expected value is captured verbatim from the bundled
// `perl exiftool -j -G1` (= 13.59) oracle on a hand-built tEXt PNG. Each
// case was confirmed `-j` (print_conv)- and `-n`-IDENTICAL against the
// oracle (the `CreationTime` PrintConv `$self->ConvertDateTime` is identity
// for the default date format), so a single assertion covers both modes.
// ===========================================================================

/// Build a `tEXt` chunk for `keyword`=`value` (Latin-1).
fn text_chunk(keyword: &str, value: &str) -> Vec<u8> {
  let mut d = keyword.as_bytes().to_vec();
  d.push(0);
  d.extend_from_slice(value.as_bytes());
  chunk(b"tEXt", &d)
}

#[test]
fn engine_creation_time_named_tz_converts_to_exif() {
  // Oracle (`perl exiftool -j -G1` AND `-n -j -G1`, identical):
  //   "PNG:CreationTime": "2018:01:01 12:10:22-05:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 EST"),
  ]);
  for pc in [true, false] {
    let json = extract_info("ct_est.png", &bytes, pc);
    assert!(
      json.contains("\"PNG:CreationTime\":\"2018:01:01 12:10:22-05:00\""),
      "named-tz EST should convert (print_conv={pc}): {json}",
    );
  }
}

#[test]
fn engine_creation_time_numeric_tz_converts_to_exif() {
  // Oracle: "PNG:CreationTime": "2018:01:01 12:10:22+05:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 +05:00"),
  ]);
  for pc in [true, false] {
    let json = extract_info("ct_numeric.png", &bytes, pc);
    assert!(
      json.contains("\"PNG:CreationTime\":\"2018:01:01 12:10:22+05:00\""),
      "numeric +05:00 zone should convert (print_conv={pc}): {json}",
    );
  }
}

#[test]
fn engine_imagemagick_create_modify_date_convert_via_xmp_date() {
  // R15: the ImageMagick `create-date`/`modify-date` text keywords map to
  // `CreateDate`/`ModDate` (PNG.pm:658-677) AND convert their ISO-8601 values
  // via `XMP::ConvertXMPDate` (XMP.pm:3383-3394) — not left raw. Oracle
  // (`perl exiftool -j -G1` AND `-n -j -G1`, identical):
  //   "PNG:CreateDate": "2024:01:15 10:30:00+00:00"
  //   "PNG:ModDate":    "2024:02:20 08:05:59-05:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("create-date", "2024-01-15T10:30:00+00:00"),
    text_chunk("modify-date", "2024-02-20T08:05:59-05:00"),
  ]);
  for pc in [true, false] {
    let json = extract_info("im_dates.png", &bytes, pc);
    assert!(
      json.contains("\"PNG:CreateDate\":\"2024:01:15 10:30:00+00:00\""),
      "create-date ISO→EXIF (print_conv={pc}): {json}",
    );
    assert!(
      json.contains("\"PNG:ModDate\":\"2024:02:20 08:05:59-05:00\""),
      "modify-date ISO→EXIF (print_conv={pc}): {json}",
    );
  }
}

#[test]
fn engine_create_date_branch2_date_only_and_no_seconds() {
  // R15 branch coverage of `XMP::ConvertXMPDate`: a date-only value (no time)
  // takes the `tr/-/:/` elsif branch (XMP.pm:3390-3391); a datetime with no
  // seconds keeps the optional `$5` empty (XMP.pm:3387). Oracle (`-n -j -G1`):
  //   "2024-01-15"       → CreateDate "2024:01:15"
  //   "2024-01-15T10:30" → CreateDate "2024:01:15 10:30"
  for (raw, want) in [
    ("2024-01-15", "2024:01:15"),
    ("2024-01-15T10:30", "2024:01:15 10:30"),
  ] {
    let bytes = assemble(&[ihdr_rgb_1x1(), text_chunk("create-date", raw)]);
    let json = extract_info("cd_branch.png", &bytes, false);
    let needle = std::format!("\"PNG:CreateDate\":\"{want}\"");
    assert!(
      json.contains(&needle),
      "create-date {raw:?} → {want:?}: {json}"
    );
  }
}

#[test]
fn engine_creation_time_numeric_tz_no_colon_hhmm() {
  // No-colon `+0530` form: Perl's greedy `[-+]\d+` then backtracks two digits
  // for `(\d{2})` ⇒ `+05` `:` `30`. Oracle:
  //   "PNG:CreationTime": "2018:01:01 12:10:22+05:30"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 +0530"),
  ]);
  let json = extract_info("ct_0530.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"2018:01:01 12:10:22+05:30\""),
    "no-colon +0530 should split to +05:30: {json}",
  );
}

#[test]
fn engine_creation_time_numeric_tz_too_few_digits_stays_verbatim() {
  // `+05` has only two digits and no colon: `(\d{2})` would consume both,
  // leaving `[-+]\d+` with zero digits ⇒ the numeric-zone alternative FAILS,
  // and (no named-zone match either) bundled hits the `last` arm ⇒ verbatim.
  // Oracle: "PNG:CreationTime": "Mon, 1 Jan 2018 12:10:22 +05"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 +05"),
  ]);
  let json = extract_info("ct_plus05.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"Mon, 1 Jan 2018 12:10:22 +05\""),
    "an insufficient-digit numeric zone should leave the value verbatim: {json}",
  );
}

#[test]
fn engine_creation_time_freeform_value_stays_verbatim() {
  // A non-RFC-1123 free-form value matches no regex ⇒ returned verbatim.
  // Oracle: "PNG:CreationTime": "sometime last summer"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "sometime last summer"),
  ]);
  for pc in [true, false] {
    let json = extract_info("ct_freeform.png", &bytes, pc);
    assert!(
      json.contains("\"PNG:CreationTime\":\"sometime last summer\""),
      "free-form value should stay verbatim (print_conv={pc}): {json}",
    );
  }
}

#[test]
fn engine_creation_time_no_seconds_defaults_to_zero() {
  // No `:SS` group ⇒ `$sec || ':00'` defaults the seconds. GMT ⇒ +00:00.
  // Oracle: "PNG:CreationTime": "2019:03:05 08:09:00+00:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Tue, 5 Mar 2019 08:09 GMT"),
  ]);
  let json = extract_info("ct_nosec_gmt.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"2019:03:05 08:09:00+00:00\""),
    "missing seconds should default to :00 (GMT→+00:00): {json}",
  );
}

#[test]
fn engine_creation_time_military_letter_tz() {
  // RFC-822 single-letter military zone `A` ⇒ -01:00 (%tzConv, PNG.pm:818).
  // Oracle: "PNG:CreationTime": "2018:01:01 12:10:22-01:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 A"),
  ]);
  let json = extract_info("ct_military.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"2018:01:01 12:10:22-01:00\""),
    "military-letter zone A should map to -01:00: {json}",
  );
}

#[test]
fn engine_creation_time_two_digit_year_boosted() {
  // 2-digit year `99` (≤ 70? no → +1900). Oracle:
  //   "PNG:CreationTime": "1999:01:01 12:10:22-05:00"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "1 Jan 99 12:10:22 EST"),
  ]);
  let json = extract_info("ct_yr2.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"1999:01:01 12:10:22-05:00\""),
    "2-digit year 99 should boost to 1999: {json}",
  );
}

#[test]
fn engine_creation_time_unknown_alpha_tz_stays_verbatim() {
  // A complete regex match whose alpha zone is NOT in %tzConv hits bundled's
  // `last` arm ⇒ the value is returned verbatim (NOT partially converted).
  // Oracle: "PNG:CreationTime": "Mon, 1 Jan 2018 12:10:22 ZZZ"
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    text_chunk("Creation Time", "Mon, 1 Jan 2018 12:10:22 ZZZ"),
  ]);
  let json = extract_info("ct_unktz.png", &bytes, true);
  assert!(
    json.contains("\"PNG:CreationTime\":\"Mon, 1 Jan 2018 12:10:22 ZZZ\""),
    "unknown alpha zone should leave the value verbatim: {json}",
  );
}

// ===========================================================================
// %stdCase chunk-type normalization (PNG.pm:56 + :1640-1648). A chunk type
// that isn't a known table key but whose lower-case form is `exif`/`zxif` is
// case-normalized to `eXIf`/`zxIf` for EXIF extraction, AND (read mode) warns
// "<on-disk> chunk should be <canonical>". Oracle: `perl exiftool -j -G1`.
// ===========================================================================

#[test]
fn engine_stdcase_lowercase_exif_chunk_decodes_and_warns() {
  // A lowercase `exif` chunk carrying a real little-endian TIFF/EXIF block.
  // Oracle (`perl exiftool -j -G1`):
  //   "ExifTool:Warning": "[minor] exif chunk should be eXIf"
  //   "File:ExifByteOrder": "Little-endian (Intel, II)"
  //   "IFD0:Make": "NIKON CORPORATION"
  //   "IFD0:Model": "NIKON D850"
  // (the `[minor]` prefix is the Warn-machinery category-2 marker the port
  // omits, matching the existing PNG warning-substring assertions.)
  let tiff = tiff_make_model("NIKON CORPORATION", "NIKON D850");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"exif", &tiff)]);
  let json = extract_info("stdcase_exif.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("exif chunk should be eXIf"),
    "expected stdCase warning: {json}",
  );
  assert!(
    json.contains("\"IFD0:Make\":\"NIKON CORPORATION\""),
    "case-variant exif chunk's EXIF should decode: {json}",
  );
  assert!(json.contains("\"IFD0:Model\":\"NIKON D850\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // No `PNG:exif` text record is fabricated for the chunk.
  assert!(!json.contains("\"PNG:exif\""), "got {json}");
}

#[test]
fn engine_stdcase_uppercase_exif_warning_uses_on_disk_bytes() {
  // The warning uses the ON-DISK chunk bytes for `$chunk` (PNG.pm:1646), so an
  // uppercase `EXIF` chunk warns "EXIF chunk should be eXIf" — oracle-confirmed
  // — while still decoding the embedded EXIF.
  let tiff = tiff_make_model("SONY", "ILCE-7M4");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"EXIF", &tiff)]);
  let json = extract_info("stdcase_EXIF.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("EXIF chunk should be eXIf"),
    "warning must echo the on-disk chunk bytes (EXIF): {json}",
  );
  assert!(json.contains("\"IFD0:Make\":\"SONY\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ILCE-7M4\""), "got {json}");
}

#[test]
fn engine_canonical_exif_chunk_does_not_warn_stdcase() {
  // A correctly-cased `eXIf` chunk is a recognized table key ⇒ bundled's
  // `not $$tagTablePtr{$chunk}` guard excludes it ⇒ NO stdCase warning, just a
  // normal EXIF decode (regression guard for the std_case() canonical-skip).
  let tiff = tiff_make_model("FUJIFILM", "X-T5");
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"eXIf", &tiff)]);
  let json = extract_info("canonical_exif.png", &bytes, /* print_conv */ true);
  assert!(!json.contains("chunk should be"), "got {json}");
  assert!(json.contains("\"IFD0:Make\":\"FUJIFILM\""), "got {json}");
}

// ===========================================================================
// FoundPNG dynamic-tag `else` branch (PNG.pm:1116-1124) — a chunk keyword with
// NO resolved tagInfo becomes a dynamically-created tag. Two paths land here,
// BOTH oracle-verified against bundled `perl exiftool -j -G1` / `-b` 13.59:
//   (a) a REGISTERED `Raw profile type {exif,APP1,…}` SubDirectory keyword in
//       an `iTXt` WITH a non-empty language — `GetLangInfo` returns undef for a
//       SubDirectory tag (PNG.pm:895), so it is NOT routed to ProcessProfile;
//   (b) any UNREGISTERED `Raw profile type *` keyword (any chunk / language).
// In both, `$$tagInfo{Binary}=1` (PNG.pm:1122, keyed on `$tag =~ /^Raw profile
// type /`) renders `$val` (the DECODED chunk value) as the universal
// `(Binary data N bytes, use -b option to extract)` placeholder. NEITHER path
// touches `$$et{PROCESSED}` (no ProcessProfile ⇒ no cross-source reset).
// ===========================================================================

/// Build an `iTXt` chunk body: `keyword\0 comp meth lang\0 trans\0 value`.
/// `compressed` is the raw flag byte (0 = uncompressed); `value` is the literal
/// value bytes (uncompressed = the UTF-8 text; for a compressed chunk pass the
/// deflate stream).
fn itxt_chunk(
  keyword: &str,
  lang: &str,
  translated: &str,
  compressed: u8,
  value: &[u8],
) -> Vec<u8> {
  let mut d = keyword.as_bytes().to_vec();
  d.push(0);
  d.push(compressed); // compression flag
  d.push(0); // compression method
  d.extend_from_slice(lang.as_bytes());
  d.push(0);
  d.extend_from_slice(translated.as_bytes());
  d.push(0);
  d.extend_from_slice(value);
  d
}

#[test]
fn engine_raw_profile_exif_itxt_with_language_emits_binary_tag_no_decode() {
  // THE GAP (Codex R11): an `iTXt` whose keyword is the registered SubDirectory
  // `Raw profile type exif` BUT whose language subtag is NON-EMPTY (`en`).
  // `GetLangInfo` (PNG.pm:895) returns undef for the SubDirectory tag, so
  // FoundPNG does NOT route to ProcessProfile — it creates the dynamic
  // `Binary=>1` tag `RawProfileTypeExif` (no `-en` suffix) whose value is the
  // RAW iTXt value bytes rendered as binary-data. Oracle (`perl exiftool -j
  // -G1` on the byte-identical crafted PNG):
  //   "PNG:RawProfileTypeExif": "(Binary data 86 bytes, use -b option to extract)"
  // and crucially NO "IFD0:Make"/"IFD0:Model"/"File:ExifByteOrder" (the EXIF is
  // NOT decoded). The 86 bytes are the raw `\nexif\n  <len>\n<hex>` value text
  // (NOT the decoded TIFF) — `perl exiftool -b -RawProfileTypeExif` returns
  // exactly those 86 value bytes.
  let tiff = tiff_make_model("Sony", "ILCE-7M4");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  let itxt = itxt_chunk("Raw profile type exif", "en", "", 0, &body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info("rp_exif_itxt_lang.png", &bytes, /* print_conv */ true);
  // The dynamic binary-data tag, byte count = the raw value length.
  let expected = format!(
    "\"PNG:RawProfileTypeExif\":\"(Binary data {} bytes, use -b option to extract)\"",
    body.len()
  );
  assert!(json.contains(&expected), "got {json}");
  // NO EXIF decode: the language variant never reached ProcessProfile.
  assert!(!json.contains("IFD0:Make"), "got {json}");
  assert!(!json.contains("IFD0:Model"), "got {json}");
  assert!(!json.contains("File:ExifByteOrder"), "got {json}");
  assert!(!json.contains("ILCE-7M4"), "got {json}");
  // No `-en`-suffixed key, no plain-text raw-profile record.
  assert!(!json.contains("RawProfileTypeExif-en"), "got {json}");
  assert!(
    !json.contains("\"PNG:Raw profile type exif\""),
    "got {json}"
  );
}

#[test]
fn engine_raw_profile_exif_itxt_empty_language_still_decodes_control() {
  // CONTROL for the gap: the SAME `Raw profile type exif` iTXt with an EMPTY
  // language routes to ProcessProfile (the SubDirectory resolves) and DECODES
  // the embedded EXIF — the pre-existing behaviour, which MUST be preserved.
  // Oracle: "IFD0:Make":"Sony","IFD0:Model":"ILCE-7M4",
  //   "File:ExifByteOrder":"Little-endian (Intel, II)", and NO binary-data tag.
  let tiff = tiff_make_model("Sony", "ILCE-7M4");
  let body = raw_profile_body("exif", &tiff, tiff.len());
  let itxt = itxt_chunk("Raw profile type exif", "", "", 0, &body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info(
    "rp_exif_itxt_nolang.png",
    &bytes,
    /* print_conv */ true,
  );
  assert!(json.contains("\"IFD0:Make\":\"Sony\""), "got {json}");
  assert!(json.contains("\"IFD0:Model\":\"ILCE-7M4\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // No dynamic binary-data tag in the empty-language (ProcessProfile) path.
  assert!(!json.contains("RawProfileTypeExif"), "got {json}");
}

#[test]
fn engine_raw_profile_exif_itxt_with_language_does_not_reset_processed() {
  // The reset semantics of the gap: a language-tagged raw-profile-exif does NOT
  // reach ProcessProfile, so it does NOT reset `$$et{PROCESSED}`. Placed BETWEEN
  // two `eXIf` chunks whose IFD0 both live at offset 8, the SECOND eXIf is still
  // BLOCKED by the cross-source cycle-guard (the language variant did not
  // un-block it), so only the FIRST eXIf's Make wins and the cycle-guard warning
  // fires. Oracle (`perl exiftool -j -G1`): "IFD0:Make":"FirstMk",
  //   "PNG:RawProfileTypeExif":"(Binary data N bytes, …)",
  //   "ExifTool:Warning":"IFD0 pointer references previous IFD0 directory".
  // (Contrast the EMPTY-language profile, which DOES reset — covered by the
  //  `engine_exif_chunk_then_raw_profile_overlap_profile_wins` matrix.)
  let first = tiff_make_model("FirstMk", "FirstModel");
  let mid = tiff_make_model("MidMk", "MidModel");
  let third = tiff_make_model("ThirdMk", "ThirdModel");
  let mid_body = raw_profile_body("exif", &mid, mid.len());
  let mid_itxt = itxt_chunk("Raw profile type exif", "en", "", 0, &mid_body);
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"eXIf", &first),
    chunk(b"iTXt", &mid_itxt),
    chunk(b"eXIf", &third),
  ]);
  let json = extract_info(
    "rp_exif_itxt_lang_noreset.png",
    &bytes,
    /* print_conv */ true,
  );
  assert!(json.contains("\"IFD0:Make\":\"FirstMk\""), "got {json}");
  // The middle (blocked-from-decode) profile still emits its binary tag.
  assert!(json.contains("\"PNG:RawProfileTypeExif\""), "got {json}");
  // The language variant did NOT reset PROCESSED, so the THIRD eXIf stays
  // blocked: its Make never wins, and the cycle-guard warning fires.
  assert!(!json.contains("ThirdMk"), "got {json}");
  assert!(!json.contains("MidMk"), "got {json}");
  assert!(
    json.contains("IFD0 pointer references previous IFD0 directory"),
    "the un-reset 3rd eXIf must raise the cycle-guard warning, got {json}",
  );
}

#[test]
fn engine_raw_profile_apps_and_icc_itxt_with_language_all_emit_binary_tag() {
  // GetLangInfo is keyword-agnostic: EVERY registered raw-profile SubDirectory
  // keyword in a language-tagged iTXt becomes its own dynamic binary tag. Tag
  // names follow `s/\s+(.)/\u$1/g` (whitespace-collapse + uppercase-after):
  //   APP1 -> RawProfileTypeAPP1 (APP1 has no internal space, stays upper),
  //   icc  -> RawProfileTypeIcc, 8bim -> RawProfileType8bim, xmp -> …Xmp.
  // Oracle-verified per keyword (`perl exiftool -j -G1`).
  for (kw, ty, tag) in [
    ("Raw profile type APP1", "APP1", "RawProfileTypeAPP1"),
    ("Raw profile type icc", "icc", "RawProfileTypeIcc"),
    ("Raw profile type 8bim", "8bim", "RawProfileType8bim"),
    ("Raw profile type xmp", "xmp", "RawProfileTypeXmp"),
  ] {
    let tiff = tiff_make_model("Sony", "ILCE-7M4");
    let body = raw_profile_body(ty, &tiff, tiff.len());
    let itxt = itxt_chunk(kw, "en", "", 0, &body);
    let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
    let json = extract_info("rp_kw_itxt_lang.png", &bytes, /* print_conv */ true);
    let expected = format!(
      "\"PNG:{tag}\":\"(Binary data {} bytes, use -b option to extract)\"",
      body.len()
    );
    assert!(json.contains(&expected), "keyword {kw}: got {json}");
    // No EXIF decode for the APP1 language variant either.
    assert!(!json.contains("IFD0:Make"), "keyword {kw}: got {json}");
  }
}

#[test]
fn engine_unregistered_raw_profile_generic_text_emits_binary_tag() {
  // ADJACENT (same FoundPNG dynamic-tag mechanism): an UNREGISTERED keyword
  // `Raw profile type generic` in a plain `tEXt` (no language field) has no
  // table entry, so FoundPNG creates the dynamic `Binary=>1` tag
  // `RawProfileTypeGeneric` whose value is the DECODED tEXt value bytes.
  // Oracle (`perl exiftool -j -G1`):
  //   "PNG:RawProfileTypeGeneric": "(Binary data N bytes, use -b option to extract)"
  // and `-b` returns those exact value bytes (NOT a decoded profile — `generic`
  // has no SubDirectory). No EXIF, no warning.
  let tiff = tiff_make_model("Generic", "Body");
  let body = raw_profile_body("generic", &tiff, tiff.len());
  let mut text = b"Raw profile type generic\0".to_vec();
  text.extend_from_slice(&body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"tEXt", &text)]);
  let json = extract_info("rp_generic_text.png", &bytes, /* print_conv */ true);
  let expected = format!(
    "\"PNG:RawProfileTypeGeneric\":\"(Binary data {} bytes, use -b option to extract)\"",
    body.len()
  );
  assert!(json.contains(&expected), "got {json}");
  assert!(!json.contains("IFD0:Make"), "got {json}");
  // The verbatim keyword is NOT emitted as a plain-text record.
  assert!(
    !json.contains("\"PNG:Raw profile type generic\""),
    "got {json}"
  );
}

#[test]
fn engine_unregistered_raw_profile_generic_itxt_with_language_emits_binary_tag() {
  // The unregistered `Raw profile type generic` keyword in a LANGUAGE-tagged
  // iTXt also yields the dynamic binary tag (the dynamic-tag path is identical
  // whether the keyword was unregistered or de-localized by GetLangInfo).
  // Oracle: "PNG:RawProfileTypeGeneric":"(Binary data N bytes, …)".
  let tiff = tiff_make_model("Generic", "Body");
  let body = raw_profile_body("generic", &tiff, tiff.len());
  let itxt = itxt_chunk("Raw profile type generic", "en", "", 0, &body);
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"iTXt", &itxt)]);
  let json = extract_info(
    "rp_generic_itxt_lang.png",
    &bytes,
    /* print_conv */ true,
  );
  let expected = format!(
    "\"PNG:RawProfileTypeGeneric\":\"(Binary data {} bytes, use -b option to extract)\"",
    body.len()
  );
  assert!(json.contains(&expected), "got {json}");
  assert!(!json.contains("IFD0:Make"), "got {json}");
}

#[test]
fn engine_unregistered_raw_profile_generic_ztxt_emits_binary_tag() {
  // And in a `zTXt`: the INFLATED bytes feed the dynamic binary tag (FoundPNG
  // inflates first, then the unregistered keyword falls into the else branch).
  // Oracle: "PNG:RawProfileTypeGeneric":"(Binary data N bytes, …)" where N is
  // the inflated value length.
  let tiff = tiff_make_model("Generic", "Body");
  let body = raw_profile_body("generic", &tiff, tiff.len());
  let mut ztxt = b"Raw profile type generic\0".to_vec();
  ztxt.push(0); // compression method = deflate
  ztxt.extend_from_slice(&zlib_store(&body));
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"zTXt", &ztxt)]);
  let json = extract_info("rp_generic_ztxt.png", &bytes, /* print_conv */ true);
  let expected = format!(
    "\"PNG:RawProfileTypeGeneric\":\"(Binary data {} bytes, use -b option to extract)\"",
    body.len()
  );
  assert!(json.contains(&expected), "got {json}");
  assert!(!json.contains("IFD0:Make"), "got {json}");
}

// ===========================================================================
// Trailer (post-IEND) chunk processing — PNG.pm:1479-1484
//
// According to the PNG spec a file ends at IEND, but bundled CONTINUES past
// IEND when trailer bytes remain: it warns `Trailer data after PNG IEND chunk`
// (minor) and processes the trailing chunks under the `Trailer` family-1 group
// (`$$et{SET_GROUP1} = 'Trailer'`, PNG.pm:1484). The PNG-level tags
// (ExifByteOrder, the text-chunk values) AND the GPS sub-IFD shift to the
// `Trailer` group; the `Exif::Main`-table IFDs (IFD0/ExifIFD/IFD1/InteropIFD)
// keep their normal group. All assertions oracle-checked against
// `perl exiftool -j -G1` 13.59.
// ===========================================================================

/// Assemble a PNG with an explicit list of TRAILER chunks placed AFTER the IEND
/// end chunk (unlike [`assemble`], which always puts IEND last). `pre` are the
/// pre-IEND chunks (IHDR + IDAT + …); `trailer` are the raw bytes appended after
/// the IEND chunk (chunk(s) or junk).
fn assemble_with_trailer(pre: &[Vec<u8>], trailer: &[u8]) -> Vec<u8> {
  let mut bytes = Vec::new();
  bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
  for c in pre {
    bytes.extend_from_slice(c);
  }
  bytes.extend_from_slice(&chunk(b"IEND", &[]));
  bytes.extend_from_slice(trailer);
  bytes
}

/// A minimal 1x1 grayscale IDAT (a single zlib-stored scanline) — the pre-IEND
/// image data so the file is a structurally complete PNG before the trailer.
fn ihdr_gray_1x1() -> Vec<u8> {
  let mut d = Vec::new();
  d.extend_from_slice(&1u32.to_be_bytes()); // width
  d.extend_from_slice(&1u32.to_be_bytes()); // height
  d.extend_from_slice(&[8, 0, 0, 0, 0]); // depth 8, grayscale, comp/filter/interlace 0
  chunk(b"IHDR", &d)
}

/// A little-endian TIFF/EXIF block: IFD0 = { Make, Model } + a GPS-IFD pointer
/// (0x8825) → GPS IFD = { GPSLatitudeRef(0x0001) = "N" }. Used by the trailing
/// EXIF+GPS test to prove the GPS sub-IFD shifts to the `Trailer` group while
/// IFD0 Make/Model keep `IFD0`. All ASCII values out-of-line.
fn tiff_make_model_gps(make: &str, model: &str) -> Vec<u8> {
  let mut mk = make.as_bytes().to_vec();
  mk.push(0);
  let mut md = model.as_bytes().to_vec();
  md.push(0);
  let n0: u16 = 3; // Make, Model, GPSInfo
  let ifd0_start: u32 = 8;
  let ifd0_size: u32 = 2 + u32::from(n0) * 12 + 4;
  let data_start = ifd0_start + ifd0_size;
  let make_off = data_start;
  let model_off = make_off + mk.len() as u32;
  let gps_ifd_off = model_off + md.len() as u32;
  let mut t = Vec::new();
  t.extend_from_slice(b"II");
  t.extend_from_slice(&0x002a_u16.to_le_bytes());
  t.extend_from_slice(&ifd0_start.to_le_bytes());
  // IFD0
  t.extend_from_slice(&n0.to_le_bytes());
  t.extend_from_slice(&0x010f_u16.to_le_bytes()); // Make ASCII
  t.extend_from_slice(&0x0002_u16.to_le_bytes());
  t.extend_from_slice(&(mk.len() as u32).to_le_bytes());
  t.extend_from_slice(&make_off.to_le_bytes());
  t.extend_from_slice(&0x0110_u16.to_le_bytes()); // Model ASCII
  t.extend_from_slice(&0x0002_u16.to_le_bytes());
  t.extend_from_slice(&(md.len() as u32).to_le_bytes());
  t.extend_from_slice(&model_off.to_le_bytes());
  t.extend_from_slice(&0x8825_u16.to_le_bytes()); // GPSInfo LONG ptr
  t.extend_from_slice(&0x0004_u16.to_le_bytes());
  t.extend_from_slice(&1u32.to_le_bytes());
  t.extend_from_slice(&gps_ifd_off.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  // IFD0 data
  t.extend_from_slice(&mk);
  t.extend_from_slice(&md);
  // GPS IFD: 1 entry GPSLatitudeRef = "N\0" (inline, <= 4 bytes)
  let ng: u16 = 1;
  t.extend_from_slice(&ng.to_le_bytes());
  t.extend_from_slice(&0x0001_u16.to_le_bytes()); // GPSLatitudeRef ASCII
  t.extend_from_slice(&0x0002_u16.to_le_bytes());
  t.extend_from_slice(&2u32.to_le_bytes()); // count "N\0"
  t.extend_from_slice(b"N\0\0\0"); // inline value, padded
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  t
}

#[test]
fn engine_trailing_exif_decodes_under_trailer_group_with_warning() {
  // IHDR + IDAT + IEND + trailing eXIf (IFD0 Make). Oracle (perl exiftool -j
  // -G1) on this exact file:
  //   "ExifTool:Warning": "[minor] Trailer data after PNG IEND chunk"
  //   "Trailer:ExifByteOrder": "Little-endian (Intel, II)"
  //   "IFD0:Make": "TrailerMake"
  // i.e. the IFD0 Make keeps its IFD0 group; the PNG-level ExifByteOrder shifts
  // to the Trailer group; and the document-level warning fires.
  let exif = tiff_one_tag(0x010f, "TrailerMake");
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    &chunk(b"eXIf", &exif),
  );
  let json = extract_info("trail_exif.png", &bytes, /* print_conv */ true);
  // The embedded EXIF IFD0 tag is decoded AND keeps its IFD0 group.
  assert!(json.contains("\"IFD0:Make\":\"TrailerMake\""), "got {json}");
  // The PNG-level ExifByteOrder shifts to the Trailer family-1 group.
  assert!(
    json.contains("\"Trailer:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // It is NOT under the standard `File` group anymore.
  assert!(!json.contains("\"File:ExifByteOrder\""), "got {json}");
  // The document-level minor warning fires with its `[minor] ` prefix
  // (`PNG.pm:1481` `$et->Warn(..., 1)`, applied by the diagnostics mechanism —
  // matching bundled + the committed goldens).
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
  // Standard PNG structural tags still present and UNshifted (they are pre-IEND).
  assert!(json.contains("\"PNG:ImageWidth\":1"), "got {json}");
  assert!(
    json.contains("\"PNG:ColorType\":\"Grayscale\""),
    "got {json}",
  );
}

#[test]
fn engine_trailing_exif_gps_keeps_ifd_groups_byteorder_and_gps_shift_to_trailer() {
  // Trailing eXIf with IFD0 Make+Model + a GPS sub-IFD (GPSLatitudeRef). Oracle:
  //   "Trailer:ExifByteOrder": "Little-endian (Intel, II)"
  //   "Trailer:GPSLatitudeRef": "North"     <-- GPS sub-IFD SHIFTS to Trailer
  //   "IFD0:Make": "TrailerMake"            <-- Exif::Main IFD keeps IFD0
  //   "IFD0:Model": "TrailerModel"
  // This pins the precise SET_GROUP1 rule: the Exif::Main-table IFDs (IFD0) keep
  // their group, but the GPS sub-IFD (GPS::Main, no SET_GROUP1) is overridden.
  let exif = tiff_make_model_gps("TrailerMake", "TrailerModel");
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    &chunk(b"eXIf", &exif),
  );
  let json = extract_info("trail_exif_gps.png", &bytes, /* print_conv */ true);
  // EXIF IFD0 tags keep the IFD0 group.
  assert!(json.contains("\"IFD0:Make\":\"TrailerMake\""), "got {json}");
  assert!(
    json.contains("\"IFD0:Model\":\"TrailerModel\""),
    "got {json}",
  );
  // The byte-order AND the GPS sub-IFD shift to the Trailer group.
  assert!(
    json.contains("\"Trailer:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  assert!(
    json.contains("\"Trailer:GPSLatitudeRef\":\"North\""),
    "got {json}",
  );
  // GPS is NOT under the normal `GPS` group.
  assert!(!json.contains("\"GPS:GPSLatitudeRef\""), "got {json}");
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
}

#[test]
fn engine_trailing_text_comment_shifts_to_trailer_group() {
  // IHDR + IDAT + IEND + trailing tEXt "Comment". Oracle:
  //   "Trailer:Comment": "Hello trailer"   (PNG.pm Comment tEXt under Trailer)
  //   "ExifTool:Warning": "[minor] Trailer data after PNG IEND chunk"
  let mut text = b"Comment\0".to_vec();
  text.extend_from_slice(b"Hello trailer");
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    &chunk(b"tEXt", &text),
  );
  let json = extract_info("trail_text.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"Trailer:Comment\":\"Hello trailer\""),
    "got {json}",
  );
  // NOT under the standard PNG group.
  assert!(!json.contains("\"PNG:Comment\""), "got {json}");
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
}

#[test]
fn engine_trailing_junk_warns_without_bogus_tags() {
  // IHDR + IDAT + IEND + 4 random bytes (fewer than an 8-byte chunk header).
  // Oracle: only the `Trailer data after PNG IEND chunk` warning fires; NO
  // trailer tag is produced (the bytes are too short to form a chunk).
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    b"JUNK",
  );
  let json = extract_info("trail_junk.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
  // No Trailer-group tag fabricated from the junk.
  assert!(!json.contains("\"Trailer:"), "got {json}");
}

#[test]
fn engine_trailing_junk_8plus_bytes_warns_without_bogus_tags() {
  // >= 8 trailer bytes that do not form a recognized chunk: the header parses
  // (an unknown chunk type with a bogus length), but the declared length runs
  // past EOF so the walk stops without extracting a tag. Oracle: only the
  // `Trailer data after PNG IEND chunk` warning, no tag.
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    b"random trailer bytes that look like nothing",
  );
  let json = extract_info("trail_junk2.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"ExifTool:Warning\":\"[minor] Trailer data after PNG IEND chunk\""),
    "got {json}",
  );
  assert!(!json.contains("\"Trailer:"), "got {json}");
}

#[test]
fn engine_standard_exif_before_iend_path_is_unchanged() {
  // CONTROL: the SAME eXIf chunk placed BEFORE IEND must keep the standard
  // groups and the standard (non-Trailer) warning — proving the trailer support
  // did not perturb the IEND-last path. Oracle:
  //   "File:ExifByteOrder": "Little-endian (Intel, II)"
  //   "IFD0:Make": "TrailerMake"
  //   "ExifTool:Warning": "[minor] Text/EXIF chunk(s) found after PNG IDAT …"
  let exif = tiff_one_tag(0x010f, "TrailerMake");
  // eXIf BEFORE IEND (assemble appends IEND last).
  let bytes = assemble(&[
    ihdr_gray_1x1(),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"eXIf", &exif),
  ]);
  let json = extract_info("ctrl_exif.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"IFD0:Make\":\"TrailerMake\""), "got {json}");
  assert!(
    json.contains("\"File:ExifByteOrder\":\"Little-endian (Intel, II)\""),
    "got {json}",
  );
  // No Trailer group anywhere, and the warning is the after-IDAT one (NOT the
  // trailer one).
  assert!(!json.contains("\"Trailer:"), "got {json}");
  assert!(!json.contains("Trailer data after PNG IEND"), "got {json}");
  assert!(
    json.contains("Text/EXIF chunk(s) found after PNG IDAT"),
    "got {json}",
  );
}

#[test]
fn engine_trailing_exif_typed_meta_records_trailer_boundary() {
  // Direct typed-layer check: the walker enters trailer mode and the eXIf event
  // is recorded as a TRAILER event, while the warning corpus carries the
  // `Trailer data after PNG IEND chunk` message FIRST.
  let exif = tiff_one_tag(0x010f, "TrailerMake");
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    &chunk(b"eXIf", &exif),
  );
  let meta = parse_borrowed(&bytes).expect("png");
  // One EXIF event captured (the trailing eXIf).
  assert_eq!(meta.exif_events().len(), 1);
  // The first warning is the trailer warning (drives ExifTool:Warning).
  assert_eq!(
    meta.warnings().first().map(String::as_str),
    Some("Trailer data after PNG IEND chunk"),
  );
}

#[test]
fn engine_trailing_exif_cycle_guard_diagnostic_is_trailer_scoped() {
  use exifast::diagnostics::Diagnose;
  // #180 (round 2) — the embedded-EXIF DIAGNOSTIC channel under SET_GROUP1.
  // Two TRAILING eXIf chunks whose IFD0 both live at offset 8: the FIRST claims
  // addr 8, the SECOND is BLOCKED by the offset-keyed cross-source cycle-guard
  // (`ExifTool.pm:9067-9070`) and raises `IFD0 pointer references previous IFD0
  // directory`. Because both eXIf chunks are post-`IEND`, that warning is raised
  // under `$$et{SET_GROUP1} = 'Trailer'` (`PNG.pm:1484`), so — like the tag-side
  // `apply_trailer_group` — it must be re-scoped to the `Trailer` family-1 group
  // (the EXIF arm of the diagnostic drain). We inspect the raw `Diagnose` stream
  // directly (rather than the JSON), because in the rendered document this
  // `Trailer:Warning` LOSES the priority-0 first-wins race to the earlier
  // `Text/EXIF chunk(s) found after IDAT` trailer walker warning and is
  // suppressed — so the typed channel is where the re-scoping is observable.
  let first = tiff_make_model("FirstMk", "FirstModel");
  let second = tiff_make_model("SecondMk", "SecondModel");
  let mut trailer = chunk(b"eXIf", &first);
  trailer.extend_from_slice(&chunk(b"eXIf", &second));
  let bytes = assemble_with_trailer(
    &[ihdr_gray_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))],
    &trailer,
  );
  let meta = parse_borrowed(&bytes).expect("png");
  let diags = Diagnose::diagnostics(&meta);
  // The cross-source cycle-guard diagnostic exists AND carries the `Trailer`
  // family-1 group (re-scoped from the would-be document-level `ExifTool:Warning`).
  let cg = diags
    .iter()
    .find(|d| d.message() == "IFD0 pointer references previous IFD0 directory")
    .unwrap_or_else(|| panic!("cycle-guard diagnostic missing, got {diags:?}"));
  assert_eq!(
    cg.group(),
    Some("Trailer"),
    "a trailing embedded-EXIF cycle-guard warning must be Trailer-scoped, got {cg:?}",
  );
  // Sanity: it is NOT a stray document-level diagnostic (group None).
  assert!(
    !diags.iter().any(
      |d| d.group().is_none() && d.message() == "IFD0 pointer references previous IFD0 directory"
    ),
    "the cycle-guard warning must not leak as a document-level diagnostic, got {diags:?}",
  );
}

// ===========================================================================
// Finding 1 — container-aware FileType finalize (signature-authoritative).
//
// The detector's candidate is `PNG` for ALL THREE NG signatures, so before the
// container-aware finalize an MNG/JNG-signature file whose extension did NOT
// promote it (named `.png`, or extension-less) finalized as `PNG`/`image/png`.
// Now the SIGNATURE-resolved container (`PngContainer`) drives File:FileType +
// MIME. Oracle-verified vs bundled 13.59 (see the per-test comments).
// ===========================================================================

/// An MHDR chunk body (MNG.pm MHDR, FORMAT int32u): FrameWidth, FrameHeight,
/// TicksPerSecond, NominalLayerCount, NominalFrameCount, NominalPlayTime,
/// SimplicityProfile.
fn mhdr_chunk(simplicity: u32) -> Vec<u8> {
  let mut d = Vec::new();
  for v in [100u32, 200, 30, 0, 0, 0, simplicity] {
    d.extend_from_slice(&v.to_be_bytes());
  }
  chunk(b"MHDR", &d)
}

/// A minimal MNG file: `\x8aMNG…` signature + MHDR + MEND (the MNG end chunk is
/// `MEND`, NOT `IEND`).
fn minimal_mng(simplicity: u32) -> Vec<u8> {
  let mut bytes = Vec::new();
  bytes.extend_from_slice(exifast::formats::png::MNG_SIGNATURE);
  bytes.extend_from_slice(&mhdr_chunk(simplicity));
  bytes.extend_from_slice(&chunk(b"MEND", &[]));
  bytes
}

/// A minimal JNG file: `\x8bJNG…` signature + JHDR + IEND (JNG's end is `IEND`).
fn minimal_jng() -> Vec<u8> {
  let mut jhdr = Vec::new();
  jhdr.extend_from_slice(&640u32.to_be_bytes()); // ImageWidth
  jhdr.extend_from_slice(&480u32.to_be_bytes()); // ImageHeight
  jhdr.extend_from_slice(&[8, 0, 0, 8, 0, 0]); // ColorType etc.
  let mut bytes = Vec::new();
  bytes.extend_from_slice(exifast::formats::png::JNG_SIGNATURE);
  bytes.extend_from_slice(&chunk(b"JHDR", &jhdr));
  bytes.extend_from_slice(&chunk(b"IEND", &[]));
  bytes
}

/// An MNG-signature file NAMED `.png` finalizes signature-first: File:FileType
/// `MNG`, MIME `video/mng`, extension `mng` — the extension does NOT win.
/// Oracle (bundled 13.59, `mng_as_png.png`): FileType=MNG, MIMEType=video/mng,
/// FileTypeExtension=mng, plus MNG:* tags.
#[test]
fn engine_mng_signature_named_png_finalizes_as_mng() {
  let bytes = minimal_mng(0x0000_000b);
  let json = extract_info("mislabeled.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"MNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"video/mng\""),
    "got {json}"
  );
  assert!(
    json.contains("\"File:FileTypeExtension\":\"mng\""),
    "got {json}"
  );
  // The signature-selected MNG container engaged the %MNG::Main fallback.
  assert!(json.contains("\"MNG:ImageWidth\":100"), "got {json}");
  assert!(
    json.contains("\"MNG:SimplicityProfile\":\"0x0000000b\""),
    "got {json}"
  );
}

/// An MNG-signature file with NO extension also finalizes as MNG (the
/// container, not the absent extension, is authoritative). Oracle (bundled
/// 13.59, `mng_noext`): FileType=MNG, MIMEType=video/mng.
#[test]
fn engine_mng_signature_no_extension_finalizes_as_mng() {
  let bytes = minimal_mng(0x0000_0001);
  let json = extract_info("mng_noext", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"MNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"video/mng\""),
    "got {json}"
  );
}

/// The SAME MNG bytes NAMED `.mng` still finalize as MNG (the container-aware
/// finalize is consistent with the extension-promoted path — no regression to
/// the `.mng`/`.jng` goldens). Oracle (bundled 13.59, `real.mng`): MNG.
#[test]
fn engine_mng_signature_named_mng_finalizes_as_mng() {
  let bytes = minimal_mng(0x0000_0001);
  let json = extract_info("real.mng", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"MNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"video/mng\""),
    "got {json}"
  );
}

/// A JNG-signature file NAMED `.png` finalizes as JNG, `image/jng`, ext `jng`.
/// Oracle (bundled 13.59, `jng_as_png.png`): FileType=JNG, MIMEType=image/jng,
/// FileTypeExtension=jng.
#[test]
fn engine_jng_signature_named_png_finalizes_as_jng() {
  let bytes = minimal_jng();
  let json = extract_info("mislabeled.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"JNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/jng\""),
    "got {json}"
  );
  assert!(
    json.contains("\"File:FileTypeExtension\":\"jng\""),
    "got {json}"
  );
}

/// Guard: a PLAIN PNG-signature file still finalizes as PNG/image/png — the
/// container-aware finalize is a byte-identical no-op for the PNG container
/// (`Explicit("PNG")` == the old `Detected`). Oracle (bundled 13.59): PNG.
#[test]
fn engine_plain_png_signature_still_finalizes_as_png() {
  let bytes = assemble(&[ihdr_rgb_1x1(), chunk(b"IDAT", &zlib_store(&[0, 0]))]);
  let json = extract_info("plain.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"PNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/png\""),
    "got {json}"
  );
}

/// Guard: a PNG-signature APNG (an `acTL` chunk) still overrides to
/// APNG/image/apng with extension `png` — the `is_apng()` arm is UNCHANGED by
/// the container-aware split. Oracle (bundled 13.59): FileType=APNG,
/// MIMEType=image/apng, FileTypeExtension=png.
#[test]
fn engine_apng_actl_still_overrides_to_apng() {
  let mut actl = 2u32.to_be_bytes().to_vec(); // num_frames
  actl.extend_from_slice(&0u32.to_be_bytes()); // num_plays
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"acTL", &actl),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
  ]);
  let json = extract_info("anim.png", &bytes, /* print_conv */ true);
  assert!(json.contains("\"File:FileType\":\"APNG\""), "got {json}");
  assert!(
    json.contains("\"File:MIMEType\":\"image/apng\""),
    "got {json}"
  );
  assert!(
    json.contains("\"File:FileTypeExtension\":\"png\""),
    "got {json}"
  );
}

// ===========================================================================
// #142 (JUMBF / C2PA, Codex [medium]) — the `caBX` walker's `Jpeg2000.pm`
// warnings surface at the `caBX` CHUNK-WALK POSITION (the `PngDiagStep::Jumbf`
// step in `diag_order`), not after the whole PNG walk. `Warning` is priority-0
// FIRST-WINS ([[exifast-warning-priority0-firstwins]]), so a malformed `caBX`
// BEFORE a later PNG walker warning must win the document-level
// `ExifTool:Warning` slot, and a `caBX` AFTER must lose to the earlier PNG one
// — matching ExifTool's walk-position emission. Oracle: bundled `perl exiftool
// -j -G1` 13.59 emits the FIRST `$et->Warn` raised in chunk-walk order.
// ===========================================================================

/// A JUMBF box: 4-byte BE length (INCLUDING the 8-byte header) + 4-byte type +
/// payload (mirrors `src/exif/jumbf/tests.rs::box_bytes`).
fn jumbf_box(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(8 + payload.len());
  v.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
  v.extend_from_slice(typ);
  v.extend_from_slice(payload);
  v
}

/// A `caBX` chunk whose JUMBF box stream is a `jumb` → `jumd` where the `jumd`
/// is shorter than the 17-byte minimum — the walker raises `Truncated JUMD
/// directory` (`Jpeg2000.pm:811`), a NON-minor document-level `$et->Warn`. This
/// gives a `caBX` chunk that contributes exactly one JUMBF warning (and no
/// content tags) so the ordering vs a later PNG warning is unambiguous.
fn cabx_truncated_jumd() -> Vec<u8> {
  let jumd = jumbf_box(b"jumd", &[0u8; 10]); // 10-byte jumd content < 17 ⇒ Truncated
  let jumb = jumbf_box(b"jumb", &jumd);
  chunk(b"caBX", &jumb)
}

#[test]
fn engine_cabx_warning_before_post_idat_text_wins_first_slot() {
  // caBX(malformed jumd) BEFORE IDAT + a post-IDAT tEXt: the JUMBF
  // `Truncated JUMD directory` warning is raised at the `caBX` walk position
  // (before IDAT), the `Text/EXIF chunk(s) found after PNG IDAT` warning later
  // — so the JUMBF warning WINS the priority-0 first-wins `ExifTool:Warning`.
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    cabx_truncated_jumd(),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"tEXt", b"Comment\0Hi"),
  ]);
  let json = extract_info("cabx_first.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"ExifTool:Warning\":\"Truncated JUMD directory\""),
    "the caBX warning precedes the post-IDAT text warning ⇒ it must win the \
     first-wins ExifTool:Warning slot, got {json}",
  );
  // The later PNG text warning must NOT have taken the slot.
  assert!(
    !json.contains("\"ExifTool:Warning\":\"[minor] Text/EXIF chunk(s) found after"),
    "the post-IDAT text warning must lose to the earlier caBX warning, got {json}",
  );
}

#[test]
fn engine_post_idat_text_before_cabx_warning_wins_first_slot() {
  // The reverse: a post-IDAT tEXt (the `Text/EXIF chunk(s) found after PNG
  // IDAT` warning) BEFORE the malformed caBX. `caBX` is not a text chunk, so it
  // raises no post-IDAT warning of its own; its `Truncated JUMD directory`
  // warning is raised LATER (at the caBX walk position) ⇒ the EARLIER PNG text
  // warning WINS the first-wins `ExifTool:Warning` slot, and the caBX warning
  // loses. Oracle-aligned with the walk-position emission.
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"tEXt", b"Comment\0Hi"),
    cabx_truncated_jumd(),
  ]);
  let json = extract_info("cabx_second.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains(
      "\"ExifTool:Warning\":\"[minor] Text/EXIF chunk(s) found after PNG IDAT \
       (may be ignored by some readers)\""
    ),
    "the post-IDAT text warning precedes the caBX warning ⇒ it must win the \
     first-wins ExifTool:Warning slot, got {json}",
  );
  // The later caBX warning must NOT have taken the slot.
  assert!(
    !json.contains("\"ExifTool:Warning\":\"Truncated JUMD directory\""),
    "the caBX warning must lose to the earlier post-IDAT text warning, got {json}",
  );
}

/// A `caBX` chunk whose JUMBF box stream is a WELL-FORMED `jumb` → `jumd`
/// (JSON type-UUID, toggles `0x02` = Label, NUL-terminated `label`) — ≥ the
/// 17-byte minimum, so the walker emits `JUMDType` + `JUMDToggles` + `JUMDLabel`
/// and raises NO warning. Used to give a VALID first `caBX` (tags, no warning)
/// preceding a later malformed one in the repeated-`caBX` ordering regression.
fn cabx_valid_label(label: &str) -> Vec<u8> {
  // 16-byte JSON type-UUID + 1-byte toggles (0x02 = Label) + NUL-terminated label.
  let mut jumd = Vec::new();
  jumd.extend_from_slice(b"json");
  jumd.extend_from_slice(&[
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
  ]);
  jumd.push(0x02); // toggles: Label only
  jumd.extend_from_slice(label.as_bytes());
  jumd.push(0); // label NUL terminator
  let jumb = jumbf_box(b"jumb", &jumbf_box(b"jumd", &jumd));
  chunk(b"caBX", &jumb)
}

#[test]
fn engine_repeated_cabx_diags_drain_per_occurrence_first_warning_wins() {
  // #142 (Codex [medium], R3 follow-up): the per-OCCURRENCE JUMBF diagnostic
  // axis. A PNG with [valid caBX A: tags, NO warning] [post-IDAT tEXt: the
  // `Text/EXIF chunk(s) found after PNG IDAT` PNG warning] [malformed caBX B:
  // `Truncated JUMD directory`]. `Warning` is priority-0 FIRST-wins
  // ([[exifast-warning-priority0-firstwins]]), so the EARLIER-walked tEXt
  // warning must win the document-level `ExifTool:Warning` slot and the LATER
  // malformed caBX B's warning must lose — at ITS walk position.
  //
  // The R3 bug stored a SINGLE `Jumbf` diag marker (at caBX A's position) but
  // last-wins-replaced `self.jumbf` with caBX B's meta, so B's `Truncated JUMD
  // directory` drained at A's EARLIER position and incorrectly STOLE the
  // first-wins slot from the intervening tEXt warning. Per-occurrence storage
  // drains each caBX's warnings at its OWN position, so B loses.
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    cabx_valid_label("c2pa.first"),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
    chunk(b"tEXt", b"Comment\0Hi"),
    cabx_truncated_jumd(),
  ]);
  let json = extract_info("cabx_repeat_order.png", &bytes, /* print_conv */ true);
  // The intervening post-IDAT tEXt warning (walked BEFORE caBX B) wins.
  assert!(
    json.contains(
      "\"ExifTool:Warning\":\"[minor] Text/EXIF chunk(s) found after PNG IDAT \
       (may be ignored by some readers)\""
    ),
    "the intervening post-IDAT text warning precedes the later malformed caBX \
     ⇒ it must win the first-wins ExifTool:Warning slot, got {json}",
  );
  // The LATER malformed caBX B's warning must NOT have taken the slot (the R3
  // bug: it drained at caBX A's earlier position and stole it).
  assert!(
    !json.contains("\"ExifTool:Warning\":\"Truncated JUMD directory\""),
    "the later malformed caBX warning must lose to the earlier text warning \
     (per-occurrence drain), got {json}",
  );
}

#[test]
fn engine_repeated_cabx_tags_are_last_wins() {
  // The TAG axis stays last-wins (`%PNG::Main` `caBX` singleton key), UNCHANGED
  // by the per-occurrence diagnostic decoupling: a 2nd non-empty `caBX`'s tags
  // overwrite the 1st's. Two valid `caBX` with DIFFERENT labels ⇒ the emitted
  // `JUMBF:JUMDLabel` is the SECOND-walked label.
  let bytes = assemble(&[
    ihdr_rgb_1x1(),
    cabx_valid_label("c2pa.first"),
    cabx_valid_label("c2pa.second"),
    chunk(b"IDAT", &zlib_store(&[0, 0])),
  ]);
  let json = extract_info("cabx_repeat_tags.png", &bytes, /* print_conv */ true);
  assert!(
    json.contains("\"JUMBF:JUMDLabel\":\"c2pa.second\""),
    "the 2nd caBX's tags must last-wins-replace the 1st's (unchanged tag \
     behavior), got {json}",
  );
  assert!(
    !json.contains("\"JUMBF:JUMDLabel\":\"c2pa.first\""),
    "the 1st caBX's label must have been overwritten by the 2nd (last-wins), \
     got {json}",
  );
}
