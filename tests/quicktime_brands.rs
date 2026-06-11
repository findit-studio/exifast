//! QuickTime SP4 brand-variant container dispatch — integration tests.
//!
//! Verifies the `ftyp`-driven brand routing layer (HEIC/AVIF/CR3/JP2/iso5/
//! hvc1) against both synthetic builds and real bundled fixtures.
//!
//! Real fixtures are read from the directory named by the `EXIFTOOL_T_IMAGES`
//! environment variable (the `t/images` dir of an ExifTool checkout); the tests
//! skip when it is unset so a checkout without the bundled tree still passes.
//! The synthetic builds provide the portable coverage.
#![cfg(feature = "quicktime")]

use exifast::parse_quicktime;

/// Read a bundled ExifTool test image by file name from the directory named by
/// the `EXIFTOOL_T_IMAGES` environment variable. Returns `None` — and the
/// caller skips — when the var is unset or the file is absent, so the suite
/// stays portable across machines (no hardcoded paths).
fn exiftool_fixture(name: &str) -> Option<Vec<u8>> {
  let dir = std::env::var_os("EXIFTOOL_T_IMAGES")?;
  std::fs::read(std::path::Path::new(&dir).join(name)).ok()
}

/// Build a top-level ISO-BMFF box.
fn box_bytes(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
  let size = 8u32 + body.len() as u32;
  let mut out = Vec::with_capacity(size as usize);
  out.extend_from_slice(&size.to_be_bytes());
  out.extend_from_slice(tag);
  out.extend_from_slice(body);
  out
}

/// Build a minimal HEIC: ftyp(major=heic, compat=[mif1,heic]) + meta(pitm v0 = 1)
fn synthetic_heic() -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic"); // major
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]); // minor
  ftyp_body.extend_from_slice(b"mif1"); // compat 1
  ftyp_body.extend_from_slice(b"heic"); // compat 2
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]); // version 0 + flags
  pitm_body.extend_from_slice(&1u16.to_be_bytes()); // id = 1
  let pitm = box_bytes(b"pitm", &pitm_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]); // FullBox version+flags
  meta_body.extend(pitm);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);
  data
}

/// Build a minimal AVIF: ftyp(major=avif, compat=[mif1,avif]) + meta.
fn synthetic_avif() -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"avif"); // major
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]); // minor
  ftyp_body.extend_from_slice(b"mif1"); // compat 1
  ftyp_body.extend_from_slice(b"avif"); // compat 2
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&7u16.to_be_bytes()); // id = 7
  let pitm = box_bytes(b"pitm", &pitm_body);
  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(pitm);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);
  data
}

/// Build a minimal CR3: ftyp(major=crx, compat=[crx ,isom]) + moov(uuid[Canon]{CNCV=CanonCR3 0.1.00, CMT1, CMT2, CMT3, CMT4})
fn synthetic_cr3() -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx "); // major
  ftyp_body.extend_from_slice(&[0, 0, 0, 1]); // minor 0.0.0.1
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(b"isom");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  // The Canon UUID = 85 c0 b6 87 82 0f 11 e0 81 11 f4 ce 46 2b 6a 48
  const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
  ];
  let mut uuid_body = Vec::new();
  uuid_body.extend_from_slice(&CANON_UUID);
  // CNCV — bundled ASCII string.
  uuid_body.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
  // CMT1-4 (TIFF/Exif bodies — content doesn't matter for this test).
  uuid_body.extend(box_bytes(b"CMT1", &[0xAB; 32]));
  uuid_body.extend(box_bytes(b"CMT2", &[0xCD; 24]));
  uuid_body.extend(box_bytes(b"CMT3", &[0xEF; 64]));
  uuid_body.extend(box_bytes(b"CMT4", &[0x12; 16]));
  let uuid = box_bytes(b"uuid", &uuid_body);
  let mut moov_body = Vec::new();
  moov_body.extend(uuid);
  let moov = box_bytes(b"moov", &moov_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(moov);
  data
}

// ============================================================================
// Synthetic-input conformance
// ============================================================================

#[test]
fn synthetic_heic_file_type_heic_with_mif1_only() {
  // Major brand `heic` → file_type=HEIC, mime=image/heic. The bundled
  // %ftypLookup{'heic'} = 'High Efficiency Image Format HEVC still image
  // (.HEIC)' has the `(.HEIC)` substring so the regex extracts HEIC.
  let data = synthetic_heic();
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.file_type(), "HEIC");
  assert_eq!(m.mime(), "image/heic");
  assert_eq!(m.quicktime().major_brand(), Some("heic"));
  assert_eq!(m.heif().primary_item(), Some(1));
  assert!(!m.heif().is_empty());
}

#[test]
fn synthetic_avif_file_type_avif() {
  let data = synthetic_avif();
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.file_type(), "AVIF");
  assert_eq!(m.mime(), "image/avif");
  assert_eq!(m.quicktime().major_brand(), Some("avif"));
  assert_eq!(m.heif().primary_item(), Some(7));
}

#[test]
fn synthetic_cr3_override_via_cncv() {
  let data = synthetic_cr3();
  let m = parse_quicktime(&data).expect("accepted");
  // The `crx ` brand alone resolves to CRX/video/x-canon-crx; the CNCV
  // `CanonCR3_001/...` then overrides to CR3/image/x-canon-cr3.
  assert_eq!(m.file_type(), "CR3");
  assert_eq!(m.mime(), "image/x-canon-cr3");
  assert_eq!(
    m.cr3().compressor_version(),
    Some("CanonCR3_001/00.09.00/00.00.00")
  );
  assert_eq!(m.cr3().override_file_type(), Some("CR3"));
  assert!(m.cr3().cmt1().is_some());
  assert!(m.cr3().cmt2().is_some());
  assert!(m.cr3().cmt3().is_some());
  assert!(m.cr3().cmt4().is_some());
  assert_eq!(m.cr3().cmt1().unwrap().length(), 32);
  assert_eq!(m.cr3().cmt4().unwrap().length(), 16);
}

#[test]
fn synthetic_cr3_media_metadata_camera_make_canon() {
  let data = synthetic_cr3();
  let m = parse_quicktime(&data).expect("accepted");
  let md = m.media_metadata();
  // Cr3Meta::project_into stamps CameraInfo.make = "Canon" when the
  // file carries any Canon UUID child.
  assert_eq!(
    md.camera().and_then(exifast::metadata::CameraInfo::make),
    Some("Canon")
  );
}

#[test]
fn synthetic_iso5_brand_resolves_to_mp4() {
  // `iso5` IS in %ftypLookup but its value has no (.EXT) — bundled
  // falls through to the compatible-brand scan which yields MP4 by
  // default (no mp41/mp42/avc1/f4v/qt brand in compat slots). The
  // resulting file_type must be MP4 (with image/mp4 wait — actually
  // video/mp4 — but the post-walk M4A override might apply when no
  // vide handler — but no handler at all means no M4A override since
  // the predicate requires `soun` handler to be present).
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"iso5");
  ftyp_body.extend_from_slice(&[0u8; 4]); // minor
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let m = parse_quicktime(&ftyp).expect("accepted");
  assert_eq!(m.file_type(), "MP4");
  assert_eq!(m.mime(), "video/mp4");
  assert!(m.heif().is_empty());
  assert!(m.cr3().is_empty());
}

#[test]
fn synthetic_msf1_brand_resolves_to_heifs() {
  // msf1 → HEIFS (sequence variant of HEIF). Bundled QuickTime.pm:230.
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"msf1");
  ftyp_body.extend_from_slice(&[0u8; 4]);
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let m = parse_quicktime(&ftyp).expect("accepted");
  assert_eq!(m.file_type(), "HEIFS");
  assert_eq!(m.mime(), "image/heif-sequence");
}

#[test]
fn synthetic_mqv_brand_resolves_to_mqv() {
  // Sony Mobile QuickTime (.MQV) — QuickTime.pm:204.
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"mqt ");
  ftyp_body.extend_from_slice(&[0u8; 4]);
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let m = parse_quicktime(&ftyp).expect("accepted");
  assert_eq!(m.file_type(), "MQV");
  assert_eq!(m.mime(), "video/quicktime");
}

#[test]
fn cr3_override_skips_when_no_canon_uuid() {
  // A vanilla MP4 with brand `crx ` but no Canon UUID stays at CRX
  // (no override fires because cr3.is_empty() is true and
  // cr3.override_file_type() is None).
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(&[0u8; 4]);
  ftyp_body.extend_from_slice(b"crx ");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let m = parse_quicktime(&ftyp).expect("accepted");
  assert_eq!(m.file_type(), "CRX");
  assert_eq!(m.mime(), "video/x-canon-crx");
}

#[test]
fn canon_uuid_in_trailer_region_does_not_override() {
  // FIX F5 — the Canon-UUID scanner must run over the BOUNDED `scan_data`
  // (the top-level box region, `..box_region_end`), NOT the full file. A
  // Canon-UUID-shaped run of bytes that lives in a file-end TRAILER (past
  // the box region) must be IGNORED, so it does NOT trigger the CR3
  // override. Pre-fix the scanner walked the whole file and would
  // misread the trailer bytes as a top-level `uuid` box → CR3.
  //
  // Layout: ftyp(crx ) + moov  ‖  [Canon uuid box]  +  [Insta360 trailer].
  // The Insta360 trailer's declared length covers everything from the end
  // of `moov` to EOF, so the box walk stops at end-of-moov and
  // `box_region_end` excludes the Canon uuid.
  const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
  ];
  // Insta360 trailer magic (insta360.rs:88) — 32 ASCII bytes.
  const INSTA360_MAGIC: &[u8; 32] = b"8db42d694ccc418790edff439fe026bf";

  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx "); // major brand → CRX by default
  ftyp_body.extend_from_slice(&[0, 0, 0, 1]);
  ftyp_body.extend_from_slice(b"crx ");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  // A small, well-formed moov so the box region ends cleanly after it.
  let moov = box_bytes(b"moov", &[0u8; 8]);

  // The Canon uuid box that lives AFTER the box region (in the trailer).
  let mut uuid_body = Vec::new();
  uuid_body.extend_from_slice(&CANON_UUID);
  uuid_body.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
  let canon_uuid = box_bytes(b"uuid", &uuid_body);

  // Assemble: ftyp + moov, then the trailing Canon uuid + a 40-byte
  // Insta360 trailer window `[len: LE u32][4 pad][MAGIC:32]`.
  let mut data = Vec::new();
  data.extend_from_slice(&ftyp);
  data.extend_from_slice(&moov);
  let box_region_end = data.len(); // = end of moov
  data.extend_from_slice(&canon_uuid);
  // Trailer length = bytes from end-of-moov to EOF = canon_uuid + 40.
  let trailer_len = (canon_uuid.len() + 40) as u32;
  data.extend_from_slice(&trailer_len.to_le_bytes()); // buff[0..4]
  data.extend_from_slice(&[0u8; 4]); // buff[4..8] (pad)
  data.extend_from_slice(INSTA360_MAGIC); // buff[8..40]
  // Sanity: the trailer start (file_size - trailer_len) is exactly the
  // end of moov, so the box walk stops there.
  assert_eq!(data.len() - trailer_len as usize, box_region_end);

  let m = parse_quicktime(&data).expect("accepted");
  // The Canon uuid is in the trailer region (past `box_region_end`), so
  // the bounded scanner never sees it: no CR3 override, stays CRX.
  assert_eq!(m.file_type(), "CRX");
  assert_eq!(m.mime(), "video/x-canon-crx");
  assert!(
    m.cr3().is_empty(),
    "Canon uuid in trailer must not populate Cr3Meta"
  );
  assert_eq!(m.cr3().override_file_type(), None);
}

// ============================================================================
// JP2 standalone entry point (FIX 3 — the independent JP2-signature route)
// ============================================================================

/// The 12-byte JP2 signature box (Jpeg2000.pm:1548).
const JP2_SIG: [u8; 12] = [
  0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];

/// Build a real-shaped `.jpx`: the JP2 signature box + an `ftyp`
/// (brand=`jpx `) + a `jp2h`{`ihdr`} + a `uuid` UUID-Exif box. This is
/// the on-disk shape ExifTool's `ProcessJP2` walks.
fn synthetic_jpx() -> Vec<u8> {
  // 16-byte `JpgTiffExif->JP2` UUID prefix (Jpeg2000.pm:283).
  const JP2_UUID_EXIF: [u8; 16] = [
    0x4a, 0x70, 0x67, 0x54, 0x69, 0x66, 0x66, 0x45, 0x78, 0x69, 0x66, 0x2d, 0x3e, 0x4a, 0x50, 0x32,
  ];
  let mut data = JP2_SIG.to_vec();

  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"jpx "); // major brand → JPX promotion
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]); // minor
  ftyp_body.extend_from_slice(b"jpx "); // compat
  data.extend(box_bytes(b"ftyp", &ftyp_body));

  // jp2h { ihdr } — Image Header (14-byte body: H, W, NC, bpc, C, UnkC, IPR).
  let mut ihdr_body = Vec::new();
  ihdr_body.extend_from_slice(&480u32.to_be_bytes()); // height
  ihdr_body.extend_from_slice(&640u32.to_be_bytes()); // width
  ihdr_body.extend_from_slice(&3u16.to_be_bytes()); // num components
  ihdr_body.extend_from_slice(&[7, 7, 0, 0]); // bpc, C, UnkC, IPR
  let ihdr = box_bytes(b"ihdr", &ihdr_body);
  data.extend(box_bytes(b"jp2h", &ihdr));

  // uuid UUID-Exif box: 16-byte prefix + a minimal big-endian TIFF.
  let mut uuid_body = Vec::new();
  uuid_body.extend_from_slice(&JP2_UUID_EXIF);
  uuid_body.extend_from_slice(b"MM\0*\0\0\0\x08\0\0"); // tiny fake TIFF
  data.extend(box_bytes(b"uuid", &uuid_body));

  data
}

#[test]
fn synthetic_jpx_parses_via_direct_entry() {
  // The dedicated `parse_jp2_borrowed` entry walks the JP2 signature box,
  // promotes the sub-type from the inner `jpx ` ftyp brand, and locates
  // the ihdr + UUID-Exif blocks.
  let data = synthetic_jpx();
  let m = exifast::formats::quicktime_brands::parse_jp2_borrowed(&data).expect("JP2 accepted");
  assert_eq!(m.sub_type(), Some("JPX"));
  assert!(m.ihdr().is_some(), "ihdr located");
  assert!(m.uuid_exif().is_some(), "UUID-Exif located");
}

#[test]
fn non_jp2_rejected_by_direct_entry() {
  // A non-JP2 input (no signature) returns None — `ProcessJP2`'s
  // `return 0 unless …` gate (Jpeg2000.pm:1547-1552).
  assert!(exifast::formats::quicktime_brands::parse_jp2_borrowed(b"not a jp2 file").is_none());
}

#[cfg(feature = "json")]
#[test]
fn jpx_full_entry_point_emits_file_type_jpx() {
  // FIX 3 — the FULL detect → dispatch → emit path. A `.jp2`-named
  // buffer beginning with the JP2 signature is detected as file type
  // `JP2` (filetype_data magic) and routed (via `any_parser_for("JP2")`
  // → `AnyParser::Jp2`) to `ProcessJp2`. The inner `jpx ` brand promotes
  // the emitted `File:FileType` to JPX with MIME `image/jpx`
  // (Jpeg2000.pm:1580-1587 + ExifTool.pm:708).
  let data = synthetic_jpx();
  let json = exifast::parser::extract_info("test.jp2", &data, false);
  assert!(
    json.contains(r#""File:FileType":"JPX""#),
    "expected File:FileType JPX, got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/jpx""#),
    "expected MIME image/jpx, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn plain_jp2_full_entry_point_emits_file_type_jp2() {
  // A bare JP2 (signature + no promoting ftyp) finalizes to the detected
  // `JP2` candidate with MIME `image/jp2` (SetFileType(undef) →
  // `%mimeType{JP2}`).
  let mut data = JP2_SIG.to_vec();
  // A `jp2h` box with NO ftyp ⇒ sub_type stays JP2.
  let mut ihdr_body = Vec::new();
  ihdr_body.extend_from_slice(&100u32.to_be_bytes());
  ihdr_body.extend_from_slice(&100u32.to_be_bytes());
  ihdr_body.extend_from_slice(&3u16.to_be_bytes());
  ihdr_body.extend_from_slice(&[7, 7, 0, 0]);
  data.extend(box_bytes(b"jp2h", &box_bytes(b"ihdr", &ihdr_body)));
  let json = exifast::parser::extract_info("test.jp2", &data, false);
  assert!(
    json.contains(r#""File:FileType":"JP2""#),
    "expected File:FileType JP2, got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/jp2""#),
    "expected MIME image/jp2, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn raw_j2c_codestream_full_entry_point_emits_file_type_j2c() {
  // R3-F2 — a bare JPEG 2000 codestream (NOT a boxed JP2 container) begins
  // with the SOC+SIZ marker `ff 4f ff 51 00` (Jpeg2000.pm:1552). It matches
  // the `%magicNumber{JP2}` regex (which folds in the J2C codestream
  // alternative), so detection yields file type `JP2` and routes (via
  // `parser_for_file_type("JP2")` → `AnyParser::Jp2`) to `ProcessJp2`. The
  // parser recognizes the codestream signature and `SetFileType('J2C')`
  // (Jpeg2000.pm:1561), finalizing `File:FileType=J2C` with MIME
  // `image/x-j2c` (ExifTool.pm:702) — NO box walk, NO error.
  let mut data = vec![0xff, 0x4f, 0xff, 0x51, 0x00];
  // A little plausible SIZ payload so the buffer is non-trivial; ignored by
  // the (box-walk-free) J2C path.
  data.extend_from_slice(&[0u8; 32]);
  let json = exifast::parser::extract_info("test.j2c", &data, false);
  assert!(
    json.contains(r#""File:FileType":"J2C""#),
    "expected File:FileType J2C, got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/x-j2c""#),
    "expected MIME image/x-j2c, got: {json}"
  );
  // No document-level error/warning was raised by the J2C acceptance.
  assert!(
    !json.contains(r#""ExifTool:Error""#),
    "J2C acceptance must not raise an Error, got: {json}"
  );
}

// ============================================================================
// JXL (JPEG XL) full entry point — ProcessJXL (Jpeg2000.pm:1603-1653)
// ============================================================================

/// The 12-byte boxed-JXL signature (Jpeg2000.pm:1611).
const JXL_SIG: [u8; 12] = [
  0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];

/// The bundled `t/images/JXL.jxl` raw codestream header (verified vs
/// `exiftool -ImageWidth -ImageHeight` ⇒ 200x130).
const JXL_REAL_CODESTREAM: [u8; 14] = [
  0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
];

#[cfg(feature = "json")]
#[test]
fn raw_jxl_codestream_full_entry_point() {
  // A raw `\xff\x0a` JXL codestream → file type detected as "JXL", routed
  // (via `any_parser_for("JXL")` → `AnyParser::Jxl`) to `ProcessJxl`, which
  // `SetFileType('JXL Codestream','image/jxl','jxl')` (Jpeg2000.pm:1628) and
  // decodes the dimensions. Verified vs bundled `exiftool` on the same
  // fixture bytes: FileType "JXL Codestream", MIME image/jxl, 200x130. The
  // PrintConv (default) path lowercases FileTypeExtension to "jxl" (the `-n`
  // path keeps the raw `uc $normExt` = "JXL"; both verified vs bundled).
  let json = exifast::parser::extract_info("test.jxl", &JXL_REAL_CODESTREAM, true);
  assert!(
    json.contains(r#""File:FileType":"JXL Codestream""#),
    "expected File:FileType 'JXL Codestream', got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/jxl""#),
    "expected MIME image/jxl, got: {json}"
  );
  assert!(
    json.contains(r#""File:FileTypeExtension":"jxl""#),
    "expected FileTypeExtension jxl (PrintConv lc), got: {json}"
  );
  // The `-n` path keeps the raw uppercased extension.
  let json_n = exifast::parser::extract_info("test.jxl", &JXL_REAL_CODESTREAM, false);
  assert!(
    json_n.contains(r#""File:FileTypeExtension":"JXL""#),
    "expected raw FileTypeExtension JXL under -n, got: {json_n}"
  );
  // ImageWidth/ImageHeight emitted in the File group (bare-number JSON).
  assert!(
    json.contains(r#""File:ImageWidth":200"#),
    "expected File:ImageWidth 200, got: {json}"
  );
  assert!(
    json.contains(r#""File:ImageHeight":130"#),
    "expected File:ImageHeight 130, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn boxed_jxl_full_entry_point() {
  // A boxed JXL (signature + ftyp jxl + jxlc codestream) → file type "JXL",
  // routed to `ProcessJxl` which walks the boxes (reusing the JP2 walker)
  // and decodes the `jxlc` dimensions. FileType "JXL", MIME image/jxl, the
  // codestream gives 200x130.
  let mut data = JXL_SIG.to_vec();
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"jxl ");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"jxl ");
  data.extend(box_bytes(b"ftyp", &ftyp_body));
  data.extend(box_bytes(b"jxlc", &JXL_REAL_CODESTREAM));
  let json = exifast::parser::extract_info("test.jxl", &data, false);
  assert!(
    json.contains(r#""File:FileType":"JXL""#),
    "expected File:FileType JXL, got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/jxl""#),
    "expected MIME image/jxl, got: {json}"
  );
  assert!(
    json.contains(r#""File:ImageWidth":200"#) && json.contains(r#""File:ImageHeight":130"#),
    "expected 200x130 from the jxlc codestream, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn boxed_jxl_two_jxlp_once_guard_uses_first() {
  // A boxed JXL with TWO `jxlp` partial-codestream boxes decodes the
  // dimensions from the FIRST only (Jpeg2000.pm:1475
  // `$$et{ProcessedJXLCodestream}`). The 2nd carries a small-form 80x40
  // header that must be ignored.
  let mut data = JXL_SIG.to_vec();
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"jxl ");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  data.extend(box_bytes(b"ftyp", &ftyp_body));
  // First jxlp: leading index word + the real 200x130 header.
  let mut first = Vec::new();
  first.extend_from_slice(&[0, 0, 0, 0]);
  first.extend_from_slice(&JXL_REAL_CODESTREAM);
  data.extend(box_bytes(b"jxlp", &first));
  // Second jxlp: small-form 80x40 (must be ignored).
  let mut window = [0u8; 12];
  window[0] = 0b0001_0011;
  window[1] = 0b0000_1000;
  let mut second = Vec::new();
  second.extend_from_slice(&[0, 0, 0, 1]);
  second.extend_from_slice(&[0xff, 0x0a]);
  second.extend_from_slice(&window);
  data.extend(box_bytes(b"jxlp", &second));

  let json = exifast::parser::extract_info("test.jxl", &data, false);
  assert!(
    json.contains(r#""File:ImageWidth":200"#) && json.contains(r#""File:ImageHeight":130"#),
    "once-guard: dimensions must come from the first jxlp (200x130), got: {json}"
  );
  // The 2nd-box 80x40 must NOT appear.
  assert!(
    !json.contains(r#""File:ImageWidth":40"#),
    "the 2nd jxlp (80x40) must be ignored, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_jxl_codestream() {
  // Real bundled raw-codestream JXL. Oracle (bundled `exiftool`):
  //   File Type: JXL Codestream, MIME: image/jxl, 200x130.
  let Some(data) = exiftool_fixture("JXL.jxl") else {
    return; // fixture absent — skip
  };
  let json = exifast::parser::extract_info("JXL.jxl", &data, false);
  assert!(
    json.contains(r#""File:FileType":"JXL Codestream""#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""File:MIMEType":"image/jxl""#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""File:ImageWidth":200"#) && json.contains(r#""File:ImageHeight":130"#),
    "got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_jxl_boxed() {
  // Real bundled boxed JXL. Oracle (bundled `exiftool`):
  //   File Type: JXL, MIME: image/jxl, 200x130 (from the codestream box).
  let Some(data) = exiftool_fixture("JXL2.jxl") else {
    return; // fixture absent — skip
  };
  let json = exifast::parser::extract_info("JXL2.jxl", &data, false);
  assert!(json.contains(r#""File:FileType":"JXL""#), "got: {json}");
  assert!(
    json.contains(r#""File:MIMEType":"image/jxl""#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""File:ImageWidth":200"#) && json.contains(r#""File:ImageHeight":130"#),
    "got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_jxl2_boxed_emits_majorbrand_and_no_ihdr() {
  // SP4 #159-audit. A boxed JXL emits the `ftyp` FileType tags (Jpeg2000
  // group) AND the codestream `File:ImageWidth/Height` — but NO `ihdr` tags
  // (a boxed JXL carries no `ihdr` box). The JSON keys are family-1 prefixed
  // (`Jpeg2000:`), matching the engine's default `-G1` rendering.
  // Oracle (bundled `exiftool -j JXL2.jxl`):
  //   MajorBrand "JPEG XL Image (.JXL)", MinorVersion "0.0.0",
  //   CompatibleBrands ["jxl "], File:ImageWidth 200, File:ImageHeight 130.
  let Some(data) = exiftool_fixture("JXL2.jxl") else {
    return;
  };
  let json = exifast::parser::extract_info("JXL2.jxl", &data, true);
  assert!(
    json.contains(r#""Jpeg2000:MajorBrand":"JPEG XL Image (.JXL)""#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""Jpeg2000:MinorVersion":"0.0.0""#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""Jpeg2000:CompatibleBrands":["jxl "]"#),
    "got: {json}"
  );
  assert!(
    json.contains(r#""File:ImageWidth":200"#) && json.contains(r#""File:ImageHeight":130"#),
    "got: {json}"
  );
  // A boxed JXL has no ihdr box ⇒ no `Jpeg2000:ImageWidth`/`ImageHeight`.
  assert!(
    !json.contains(r#""Jpeg2000:ImageWidth""#),
    "boxed JXL must NOT emit a Jpeg2000:ImageWidth (no ihdr), got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_jpeg2000_jp2_full_emission() {
  // SP4 #159-audit. The full JP2 emission surface (ftyp + ihdr + colr).
  // Oracle (bundled `exiftool -j Jpeg2000.jp2`, 16x16, 3 comp, 8-bit, sRGB):
  //   MajorBrand "JPEG 2000 Image (.JP2)", MinorVersion "0.0.0",
  //   CompatibleBrands ["jp2 "], ImageHeight 16, ImageWidth 16,
  //   NumberOfComponents 3, BitsPerComponent "8 Bits, Unsigned",
  //   Compression "JPEG 2000", ColorSpecMethod "Enumerated",
  //   ColorSpecPrecedence 0, ColorSpecApproximation "Not Specified",
  //   ColorSpace "sRGB".
  let Some(data) = exiftool_fixture("Jpeg2000.jp2") else {
    return;
  };
  let json = exifast::parser::extract_info("Jpeg2000.jp2", &data, true);
  for expect in [
    r#""Jpeg2000:MajorBrand":"JPEG 2000 Image (.JP2)""#,
    r#""Jpeg2000:MinorVersion":"0.0.0""#,
    r#""Jpeg2000:CompatibleBrands":["jp2 "]"#,
    r#""Jpeg2000:ImageHeight":16"#,
    r#""Jpeg2000:ImageWidth":16"#,
    r#""Jpeg2000:NumberOfComponents":3"#,
    r#""Jpeg2000:BitsPerComponent":"8 Bits, Unsigned""#,
    r#""Jpeg2000:Compression":"JPEG 2000""#,
    r#""Jpeg2000:ColorSpecMethod":"Enumerated""#,
    r#""Jpeg2000:ColorSpecPrecedence":0"#,
    r#""Jpeg2000:ColorSpecApproximation":"Not Specified""#,
    r#""Jpeg2000:ColorSpace":"sRGB""#,
  ] {
    assert!(json.contains(expect), "missing {expect} in: {json}");
  }
  // File:FileType stays JP2 (the engine finalizes it from the sub_type).
  assert!(json.contains(r#""File:FileType":"JP2""#), "got: {json}");
}

// ============================================================================
// Real-fixture conformance (bundled ExifTool tree)
// ============================================================================

#[test]
fn real_fixture_heic_parses() {
  let Some(data) = exiftool_fixture("QuickTime.heic") else {
    // Bundled fixture not present — skip rather than fail.
    return;
  };
  let m = parse_quicktime(&data).expect("accepted");
  // Oracle (perl exiftool):
  //   "File:FileType": "HEIF",  ← mif1 major (not heic)
  //   "File:MIMEType": "image/heif",
  //   "QuickTime:CompatibleBrands": ["mif1","heic","hevc"]
  //   "Meta:PrimaryItemReference": 20002
  assert_eq!(m.file_type(), "HEIF");
  assert_eq!(m.mime(), "image/heif");
  assert_eq!(m.quicktime().major_brand(), Some("mif1"));
  assert_eq!(m.heif().primary_item(), Some(20002));
  // Two HEVC items + primary references one of them.
  assert!(!m.heif().items().is_empty());
  assert!(m.cr3().is_empty());
}

#[test]
fn real_fixture_cr3_parses() {
  let Some(data) = exiftool_fixture("CanonRaw.cr3") else {
    return;
  };
  let m = parse_quicktime(&data).expect("accepted");
  // Oracle:
  //   "File:FileType": "CR3",
  //   "File:MIMEType": "image/x-canon-cr3",
  //   "Canon:CompressorVersion": "CanonCR3_001/00.09.00/00.00.00",
  //   "QuickTime:MajorBrand": "Canon Raw (.CRX)" (i.e. brand `crx `)
  assert_eq!(m.file_type(), "CR3");
  assert_eq!(m.mime(), "image/x-canon-cr3");
  assert_eq!(m.quicktime().major_brand(), Some("crx "));
  assert_eq!(
    m.cr3().compressor_version(),
    Some("CanonCR3_001/00.09.00/00.00.00")
  );
  assert_eq!(m.cr3().override_file_type(), Some("CR3"));
  // All 4 CMT blocks must be located.
  assert!(m.cr3().cmt1().is_some());
  assert!(m.cr3().cmt2().is_some());
  assert!(m.cr3().cmt3().is_some());
  assert!(m.cr3().cmt4().is_some());
  // The MediaMetadata projection should stamp Canon brand.
  let md = m.media_metadata();
  assert_eq!(
    md.camera().and_then(exifast::metadata::CameraInfo::make),
    Some("Canon")
  );
}

#[test]
fn real_fixture_cr3_compositionally_consistent() {
  // The CMT1-4 + THMB offsets ALL must point inside the file (no
  // out-of-bounds offsets even on hostile-input regressions).
  let Some(data) = exiftool_fixture("CanonRaw.cr3") else {
    return;
  };
  let m = parse_quicktime(&data).expect("accepted");
  let file_len = data.len() as u64;
  for (name, blk) in [
    ("cmt1", m.cr3().cmt1()),
    ("cmt2", m.cr3().cmt2()),
    ("cmt3", m.cr3().cmt3()),
    ("cmt4", m.cr3().cmt4()),
    ("cnth", m.cr3().cnth()),
    ("thmb", m.cr3().thmb()),
  ] {
    if let Some(b) = blk {
      let end = b.offset() + b.length();
      assert!(
        end <= file_len,
        "{name} end {} > file_len {}",
        end,
        file_len
      );
    }
  }
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_cr3_emits_compressor_version() {
  // SP4 #159-audit. The CR3 `Image::ExifTool::Canon::uuid` CNCV
  // CompressorVersion (Canon.pm:9666-9668) must reach the output stream under
  // the `Canon` family-1 group (the `%Canon::uuid` table `GROUPS => { 1 =>
  // 'Canon' }`). Oracle (bundled `exiftool -j CanonRaw.cr3`):
  //   CompressorVersion "CanonCR3_001/00.09.00/00.00.00".
  let Some(data) = exiftool_fixture("CanonRaw.cr3") else {
    return;
  };
  let json = exifast::parser::extract_info("CanonRaw.cr3", &data, true);
  assert!(
    json.contains(r#""Canon:CompressorVersion":"CanonCR3_001/00.09.00/00.00.00""#),
    "got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_heic_emits_primary_item_reference() {
  // SP4 #159-audit. The HEIF `meta` box `pitm` PrimaryItemReference
  // (QuickTime.pm:2883) must reach the output stream under the `Meta`
  // family-1 group (the `%QuickTime::Meta` table `GROUPS => { 1 => 'Meta' }`)
  // as a bare int. Oracle (bundled `exiftool -j QuickTime.heic`):
  //   PrimaryItemReference 20002.
  let Some(data) = exiftool_fixture("QuickTime.heic") else {
    return;
  };
  let json = exifast::parser::extract_info("QuickTime.heic", &data, true);
  assert!(
    json.contains(r#""Meta:PrimaryItemReference":20002"#),
    "got: {json}"
  );
}
