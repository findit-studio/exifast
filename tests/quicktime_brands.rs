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

/// Build a HEIC with an `iprp`(`ipco`[ispe,ispe], `ipma`) property store + two
/// items, the primary (id 2) pointing at the FIRST `ispe` (640x480) and a
/// thumbnail (id 3) at the SECOND `ispe` (80x60). Mirrors the bundled
/// QuickTime.heic shape so the primary-item `ispe` resolution (#146) is covered
/// portably (without EXIFTOOL_T_IMAGES).
fn synthetic_heic_with_ispe() -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  // pitm v0 → primary item id 2.
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let pitm = box_bytes(b"pitm", &pitm_body);

  // ispe box body: [version/flags 4][width u32][height u32].
  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };
  // ipco children: index 1 = ispe(640x480), index 2 = ispe(80x60).
  let mut ipco_body = Vec::new();
  ipco_body.extend(ispe(640, 480));
  ipco_body.extend(ispe(80, 60));
  let ipco = box_bytes(b"ipco", &ipco_body);

  // ipma v0 flags0: item 2 → [prop 1], item 3 → [prop 2] (1 byte per assoc).
  let mut ipma_body = Vec::new();
  ipma_body.extend_from_slice(&[0, 0, 0, 0]); // version/flags
  ipma_body.extend_from_slice(&2u32.to_be_bytes()); // entry count
  ipma_body.extend_from_slice(&2u16.to_be_bytes()); // item id 2
  ipma_body.push(1); // 1 association
  ipma_body.push(1); // prop index 1 (essential bit clear)
  ipma_body.extend_from_slice(&3u16.to_be_bytes()); // item id 3
  ipma_body.push(1);
  ipma_body.push(2); // prop index 2
  let ipma = box_bytes(b"ipma", &ipma_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(ipco);
  iprp_body.extend(ipma);
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]); // FullBox version+flags
  meta_body.extend(pitm);
  meta_body.extend(iprp);
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
fn synthetic_heic_primary_ispe_resolves_dimensions() {
  // #146 — the primary item (id 2) associates the FIRST `ispe` (640x480) so it
  // is main-document and emits; the SECOND `ispe` (80x60) is associated only by
  // the thumbnail item 3 → a sub-document `DOC_NUM` → gated out. Oracle (bundled
  // `exiftool -G1 -j` on this exact box layout): File:ImageWidth 640,
  // File:ImageHeight 480.
  let data = synthetic_heic_with_ispe();
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().primary_item(), Some(2));
  assert_eq!(m.heif().image_width(), Some(640));
  assert_eq!(m.heif().image_height(), Some(480));
}

#[cfg(feature = "json")]
#[test]
fn synthetic_heic_emits_file_image_dimensions() {
  // #146 — the resolved primary `ispe` reaches the output stream as
  // `File:ImageWidth`/`File:ImageHeight` (bare ints, `File,File` group).
  let data = synthetic_heic_with_ispe();
  let json = exifast::parser::extract_info("synthetic.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":640"#) && json.contains(r#""File:ImageHeight":480"#),
    "got: {json}"
  );
  // The thumbnail dimensions must NOT leak (they belong to the non-primary item).
  assert!(
    !json.contains(r#""File:ImageWidth":80"#),
    "thumbnail ispe leaked: {json}"
  );
}

/// Build a HEIC: ftyp(heic) + meta(pitm(primary) + iprp(ipco[ispe…], ipma rows)).
/// `ispes` is `&[(w, h)]` (declaration order = 1-based ipco index); `rows` is
/// `&[(item_id, &[prop_index])]` for the `ipma` (v0, flags0, 1-byte assoc).
fn heic_with_ispes_and_ipma(primary: u16, ispes: &[(u32, u32)], rows: &[(u16, &[u8])]) -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&primary.to_be_bytes());
  let pitm = box_bytes(b"pitm", &pitm_body);

  let mut ipco_body = Vec::new();
  for &(w, h) in ispes {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    ipco_body.extend(box_bytes(b"ispe", &b));
  }
  let ipco = box_bytes(b"ipco", &ipco_body);

  let mut ipma_body = Vec::new();
  ipma_body.extend_from_slice(&[0, 0, 0, 0]);
  ipma_body.extend_from_slice(&(rows.len() as u32).to_be_bytes());
  for &(id, props) in rows {
    ipma_body.extend_from_slice(&id.to_be_bytes());
    ipma_body.push(props.len() as u8);
    ipma_body.extend_from_slice(props);
  }
  let ipma = box_bytes(b"ipma", &ipma_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(ipco);
  iprp_body.extend(ipma);
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(pitm);
  meta_body.extend(iprp);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);
  data
}

#[test]
fn heif_unassociated_ispe_emits_dimensions() {
  // #146 — an `ispe` that NO `ipma` row references is still MAIN-DOCUMENT and
  // emits `File:ImageWidth`/`Height`. ExifTool's `ispe` `RawConv` FoundTags the
  // dims `unless ($$self{DOC_NUM})` (QuickTime.pm:3037-3045); the deferred `ipco`
  // walk only sets `DOC_NUM` for a property associated with a NON-primary item
  // (QuickTime.pm:10196-10238), so an unassociated property stays main-document.
  // Layout: primary item 2, ipco[ispe(640x480)], EMPTY ipma. Oracle (bundled
  // `exiftool -G1 -j` on this layout): File:ImageWidth 640, File:ImageHeight 480.
  let data = heic_with_ispes_and_ipma(2, &[(640, 480)], &[]);
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().primary_item(), Some(2));
  assert_eq!(
    m.heif().image_width(),
    Some(640),
    "an unassociated ispe must still emit its dims (main-document)"
  );
  assert_eq!(m.heif().image_height(), Some(480));
}

#[cfg(feature = "json")]
#[test]
fn heif_multiple_ispe_winner_matches_exiftool() {
  // #146 — with TWO unassociated `ispe` of different sizes (640x480 then
  // 1280x960), both are main-document and FoundTag `ImageWidth`; the non-list
  // `File:ImageWidth` is overwritten in `ipco` order, so the LAST one wins.
  // Oracle (bundled `exiftool -G1 -j` on ipco[ispe(640x480), ispe(1280x960)] +
  // EMPTY ipma): File:ImageWidth 1280, File:ImageHeight 960.
  let data = heic_with_ispes_and_ipma(2, &[(640, 480), (1280, 960)], &[]);
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(
    m.heif().image_width(),
    Some(1280),
    "last main-document ispe in ipco order must win"
  );
  assert_eq!(m.heif().image_height(), Some(960));

  let json = exifast::parser::extract_info("multi.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":1280"#) && json.contains(r#""File:ImageHeight":960"#),
    "expected 1280x960 (last ispe), got: {json}"
  );
  assert!(
    !json.contains(r#""File:ImageWidth":640"#),
    "the earlier 640 ispe must be overwritten, got: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_primary_associated_ispe_gates_out_nonprimary() {
  // #146 — when the primary associates the FIRST ispe and a thumbnail the
  // SECOND, the second is a SUB-document (`DOC_NUM` set) and is gated out even
  // though it is later in ipco order. Layout: ipco[ispe(640x480), ispe(1280x960)],
  // primary 2→[1], thumb 3→[2]. Oracle: File:ImageWidth 640 (NOT 1280).
  let data = heic_with_ispes_and_ipma(2, &[(640, 480), (1280, 960)], &[(2, &[1]), (3, &[2])]);
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().image_width(), Some(640));
  assert_eq!(m.heif().image_height(), Some(480));
  let json = exifast::parser::extract_info("gated.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":640"#) && !json.contains(r#""File:ImageWidth":1280"#),
    "the non-primary (sub-document) ispe must be gated out, got: {json}"
  );
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

#[cfg(feature = "json")]
#[test]
fn real_fixture_cr3_emits_exif_make_model_serial_lens() {
  // #148 — the Canon CR3 `Image::ExifTool::Canon::uuid` CMT1-4 boxes
  // (Canon.pm:9686-9726) re-dispatch through `ProcessTIFF` / `ProcessCMT3`:
  //   CMT1 → IFD0 (`Exif::Main`)        → EXIF:IFD0:*
  //   CMT2 → ExifIFD (`Exif::Main`)     → EXIF:ExifIFD:*
  //   CMT3 → MakerNoteCanon (`Canon::Main` via ProcessCMT3) → MakerNotes:Canon:*
  //   CMT4 → GPSInfo (`GPS::Main`)      → EXIF:GPS:*
  // Each box body is a self-contained TIFF (its own header + IFD); the IFD
  // offsets are relative to the box body start (base 0). Oracle
  // (bundled `exiftool -G1 -j CanonRaw.cr3`), each tag at its faithful group
  // (the `extract_info` JSON keys are `<family1>:<name>`):
  //   IFD0:Make=Canon, IFD0:Model=Canon EOS M50, IFD0:ImageWidth=6000,
  //   IFD0:ImageHeight=4000; ExifIFD:SerialNumber=613040000565,
  //   ExifIFD:FNumber=3.5, ExifIFD:ExposureTime=1/80, ExifIFD:ISO=12800,
  //   ExifIFD:FocalLength=15.0 mm, ExifIFD:DateTimeOriginal=2018:02:21 12:08:56;
  //   Canon:LensModel=EF-M15-45mm f/3.5-6.3 IS STM; GPS:GPSVersionID=2.3.0.0.
  let Some(data) = exiftool_fixture("CanonRaw.cr3") else {
    return;
  };
  let json = exifast::parser::extract_info("CanonRaw.cr3", &data, true);
  for needle in [
    // CMT1 → IFD0.
    r#""IFD0:Make":"Canon""#,
    r#""IFD0:Model":"Canon EOS M50""#,
    r#""IFD0:ImageWidth":6000"#,
    r#""IFD0:ImageHeight":4000"#,
    // CMT2 → ExifIFD.
    r#""ExifIFD:SerialNumber":613040000565"#,
    r#""ExifIFD:FNumber":3.5"#,
    r#""ExifIFD:ExposureTime":"1/80""#,
    r#""ExifIFD:ISO":12800"#,
    r#""ExifIFD:FocalLength":"15.0 mm""#,
    r#""ExifIFD:DateTimeOriginal":"2018:02:21 12:08:56""#,
    r#""ExifIFD:LensModel":"EF-M15-45mm f/3.5-6.3 IS STM""#,
    // CMT3 → Canon MakerNote.
    r#""Canon:LensModel":"EF-M15-45mm f/3.5-6.3 IS STM""#,
    r#""Canon:LensType":"Canon EF-M 15-45mm f/3.5-6.3 IS STM""#,
    // CMT4 → GPS.
    r#""GPS:GPSVersionID":"2.3.0.0""#,
    // The first DoProcessTIFF FoundTag's File:ExifByteOrder (deduped once).
    r#""File:ExifByteOrder":"Little-endian (Intel, II)""#,
    // The pre-existing CR3 CompressorVersion must NOT regress.
    r#""Canon:CompressorVersion":"CanonCR3_001/00.09.00/00.00.00""#,
  ] {
    assert!(
      json.contains(needle),
      "missing {needle}\n--- got ---\n{json}"
    );
  }
}

#[cfg(feature = "json")]
#[test]
fn real_fixture_heic_emits_image_dimensions() {
  // #146 — the HEIF primary item's `ispe` (ImageSpatialExtent) property in
  // `ipco` (QuickTime.pm:3034-3047) emits `File:ImageWidth`/`File:ImageHeight`.
  // The `ispe` body is `[version/flags 4][width u32 BE][height u32 BE]`; the
  // primary item (`pitm` = 20002) is associated (via `ipma`) with the `ispe` at
  // `ipco` index 2 → 1596x1064 (the 320x240 thumbnail `ispe` belongs to the
  // non-primary item 20003 and is gated out by `DOC_NUM`). Oracle (bundled
  // `exiftool -G1 -j QuickTime.heic`): File:ImageWidth=1596, File:ImageHeight=1064.
  let Some(data) = exiftool_fixture("QuickTime.heic") else {
    return;
  };
  let json = exifast::parser::extract_info("QuickTime.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":1596"#),
    "missing File:ImageWidth 1596\n--- got ---\n{json}"
  );
  assert!(
    json.contains(r#""File:ImageHeight":1064"#),
    "missing File:ImageHeight 1064\n--- got ---\n{json}"
  );
  // The primary-item reference must NOT regress.
  assert!(
    json.contains(r#""Meta:PrimaryItemReference":20002"#),
    "PrimaryItemReference regressed\n--- got ---\n{json}"
  );
}

// ============================================================================
// SP4 robustness — F1 / F2 / F3 (oversized ipco, stale primary dims, CMT clone)
// ============================================================================

#[cfg(feature = "json")]
#[test]
fn heif_oversized_ipco_property_count_no_panic_emits_unassociated_ispe() {
  // An `ipco` with MORE than `u16::MAX` property boxes must not overflow the
  // 1-based property-index counter (a `u16` would debug-panic / release-wrap and
  // alias one index onto another). The counter is a `u32` with a checked
  // increment, so the walk stays sound; memory stays bounded because each `ispe`
  // box is ≥20 bytes in the file.
  //
  // Layout: the primary item (id 2) associates `ipco` property index 1 — a
  // FILLER `free` box (NOT an `ispe`). A real `ispe` (9999x9999) is planted at
  // the 65537th `ipco` child. That `ispe` is UNassociated (no `ipma` row
  // references index 65537), so ExifTool treats it as main-document and FoundTags
  // its dims — index size is irrelevant to the `ispe` `RawConv`; only an `ipma`
  // association to a non-primary item gates an `ispe` out. Oracle (bundled
  // `exiftool -G1 -j` on this exact layout): File:ImageWidth 9999,
  // File:ImageHeight 9999.
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  // pitm v0 → primary item id 2.
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let pitm = box_bytes(b"pitm", &pitm_body);

  // ipco: a sequence of empty 8-byte `free` boxes with a single `ispe` planted
  // at child index 65537 (= u16::MAX + 2 ⇒ the wrap target of a buggy u16 counter).
  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };
  let planted_at = (u16::MAX as usize) + 2; // 65537
  let free_box = box_bytes(b"free", &[]); // 8-byte header, empty body
  let mut ipco_body = Vec::with_capacity(planted_at * free_box.len() + 20);
  for idx in 1..=planted_at {
    if idx == planted_at {
      ipco_body.extend_from_slice(&ispe(9999, 9999));
    } else {
      ipco_body.extend_from_slice(&free_box);
    }
  }
  let ipco = box_bytes(b"ipco", &ipco_body);

  // ipma v0 flags0: item 2 → [prop index 1] (the filler `free`, not an ispe).
  let mut ipma_body = Vec::new();
  ipma_body.extend_from_slice(&[0, 0, 0, 0]);
  ipma_body.extend_from_slice(&1u32.to_be_bytes());
  ipma_body.extend_from_slice(&2u16.to_be_bytes());
  ipma_body.push(1);
  ipma_body.push(1); // association → property index 1
  let ipma = box_bytes(b"ipma", &ipma_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(ipco);
  iprp_body.extend(ipma);
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(pitm);
  meta_body.extend(iprp);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);

  // Must not panic (debug) / wrap (release) on the 65537-child ipco.
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().primary_item(), Some(2));
  // The unassociated high-index `ispe` is main-document and emits (oracle: 9999).
  assert_eq!(
    m.heif().image_width(),
    Some(9999),
    "unassociated ispe at a high ipco index must still emit (main-document)"
  );
  assert_eq!(m.heif().image_height(), Some(9999));

  // And the emitted JSON carries the faithful File:ImageWidth/Height.
  let json = exifast::parser::extract_info("oversized.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":9999"#) && json.contains(r#""File:ImageHeight":9999"#),
    "expected faithful 9999x9999 dims, got: {json}"
  );
}

#[test]
fn heif_many_zero_association_ipma_rows_near_linear() {
  // CPU-DoS guard: the `ispe` main-document resolution must be near-linear in the
  // `ipma` row count. A zero-association `ipma` row is only ~3 bytes (2-byte id +
  // 1-byte count 0), so a tiny crafted HEIC can carry tens of thousands of rows
  // alongside several `ispe`; an O(N·M²) resolver (rescanning every row per
  // `ispe`) would do billions of comparisons and hang. The faithful precompute +
  // single pass stays O((N+M) log M), so this completes effectively instantly.
  //
  // The dims must STILL match the faithful rule, unchanged by the extra rows:
  // primary item 2 associates `ipco` index 1 (640x480); index 2 (1280x960) is
  // UNassociated ⇒ main-document, and it is LAST in `ipco` order ⇒ it wins. The
  // 50k extra rows are distinct non-primary items (ids 3.. ascending, so no
  // out-of-order warning) whose association list is EMPTY — they reference no
  // property index and so cannot gate either `ispe`. Oracle (the same faithful
  // determination as `heif_multiple_ispe_winner_matches_exiftool`): the last
  // unassociated `ispe` wins ⇒ File:ImageWidth 1280, File:ImageHeight 960.
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  // pitm v0 → primary item id 2.
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let pitm = box_bytes(b"pitm", &pitm_body);

  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };
  // ipco: index 1 = ispe(640x480), index 2 = ispe(1280x960).
  let mut ipco_body = Vec::new();
  ipco_body.extend(ispe(640, 480));
  ipco_body.extend(ispe(1280, 960));
  let ipco = box_bytes(b"ipco", &ipco_body);

  // ipma v0 flags0: the primary (item 2) associates property index 1, then a
  // flood of 50_000 zero-association rows for ascending non-primary ids.
  const ZERO_ROWS: u32 = 50_000;
  let mut ipma_body = Vec::new();
  ipma_body.extend_from_slice(&[0, 0, 0, 0]); // version/flags
  ipma_body.extend_from_slice(&(1 + ZERO_ROWS).to_be_bytes()); // entry count
  ipma_body.extend_from_slice(&2u16.to_be_bytes()); // item 2 (primary)
  ipma_body.push(1); // 1 association
  ipma_body.push(1); // → property index 1
  for id in 3u32..3 + ZERO_ROWS {
    ipma_body.extend_from_slice(&(id as u16).to_be_bytes()); // ascending id
    ipma_body.push(0); // 0 associations (the cheap-bytes attack)
  }
  let ipma = box_bytes(b"ipma", &ipma_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(ipco);
  iprp_body.extend(ipma);
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(pitm);
  meta_body.extend(iprp);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);

  // Completes near-instantly (no O(N·M²) hang) AND yields the faithful dims.
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().primary_item(), Some(2));
  assert_eq!(
    m.heif().image_width(),
    Some(1280),
    "the last unassociated ispe must win regardless of the ipma row flood"
  );
  assert_eq!(m.heif().image_height(), Some(960));
}

#[test]
fn heif_primary_change_across_meta_boxes_keeps_main_doc_dims() {
  // `walk_heif_meta` can be called more than once into the same `HeifMeta` (the
  // persistent `$$et{ItemInfo}`), and a later `meta` can change the primary item.
  // ExifTool's `ispe` FoundTag is cumulative over the WHOLE file (QuickTime.pm:
  // 3040): a later `meta` that produces no MAIN-DOCUMENT `ispe` does NOT erase
  // the dims an earlier `meta` already emitted. (A later main-document `ispe`
  // overrides — see `heif_two_meta_primary_ispe_overrides`.)
  //
  // Pass 1: primary = item 2, associating ispe(640x480) ⇒ main-document ⇒ 640x480.
  // Pass 2 (same HeifMeta): a new `pitm` changes the primary to item 9, AND the
  // meta supplies an `ipco`[ispe(11x22)] + `ipma` associating that ispe with a
  // DIFFERENT item (3), not the primary 9 ⇒ that ispe is a SUB-document ⇒ gated
  // out ⇒ the earlier 640x480 must REMAIN (not clear). Oracle (bundled
  // `exiftool -G1 -j` on the equivalent two-meta-box file): File:ImageWidth 640,
  // File:ImageHeight 480, Meta:PrimaryItemReference 9.
  use exifast::formats::quicktime_brands::walk_heif_meta;
  use exifast::metadata::HeifMeta;

  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };

  // Pass-1 meta BODY: pitm(2) + iprp(ipco[ispe(640x480)], ipma{2→1}).
  let mut pitm1 = Vec::new();
  pitm1.extend_from_slice(&[0, 0, 0, 0]);
  pitm1.extend_from_slice(&2u16.to_be_bytes());
  let ipco1 = box_bytes(b"ipco", &ispe(640, 480));
  let mut ipma1 = Vec::new();
  ipma1.extend_from_slice(&[0, 0, 0, 0]);
  ipma1.extend_from_slice(&1u32.to_be_bytes());
  ipma1.extend_from_slice(&2u16.to_be_bytes());
  ipma1.push(1);
  ipma1.push(1);
  let mut iprp1 = Vec::new();
  iprp1.extend(ipco1);
  iprp1.extend(box_bytes(b"ipma", &ipma1));
  let mut body1 = Vec::new();
  body1.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
  body1.extend(box_bytes(b"pitm", &pitm1));
  body1.extend(box_bytes(b"iprp", &iprp1));

  let mut m = HeifMeta::new();
  let mut iloc_budget = u64::MAX;
  walk_heif_meta(&body1, 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(m.primary_item(), Some(2));
  assert_eq!(m.image_width(), Some(640));
  assert_eq!(m.image_height(), Some(480));

  // Pass-2 meta BODY into the SAME HeifMeta: pitm changes the primary to 9, and
  // the meta DOES supply a property store (ipco[ispe(11x22)] + ipma{3→1}) — but
  // item 9 (the primary) is NOT associated with that ispe; only the non-primary
  // item 3 is ⇒ the ispe is a sub-document ⇒ gated out ⇒ the earlier 640x480
  // stays (cumulative FoundTag, never cleared).
  let mut pitm2 = Vec::new();
  pitm2.extend_from_slice(&[0, 0, 0, 0]);
  pitm2.extend_from_slice(&9u16.to_be_bytes());
  let ipco2 = box_bytes(b"ipco", &ispe(11, 22));
  let mut ipma2 = Vec::new();
  ipma2.extend_from_slice(&[0, 0, 0, 0]);
  ipma2.extend_from_slice(&1u32.to_be_bytes());
  ipma2.extend_from_slice(&3u16.to_be_bytes()); // associate ispe with item 3, not 9
  ipma2.push(1);
  ipma2.push(1);
  let mut iprp2 = Vec::new();
  iprp2.extend(ipco2);
  iprp2.extend(box_bytes(b"ipma", &ipma2));
  let mut body2 = Vec::new();
  body2.extend_from_slice(&[0, 0, 0, 0]);
  body2.extend(box_bytes(b"pitm", &pitm2));
  body2.extend(box_bytes(b"iprp", &iprp2));

  walk_heif_meta(&body2, 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(m.primary_item(), Some(9), "pitm overwrote the primary");
  assert_eq!(
    m.image_width(),
    Some(640),
    "pass-2 ispe is a sub-document (associated to non-primary item 3) — earlier \
     main-document 640 must remain, not clear"
  );
  assert_eq!(m.image_height(), Some(480));
}

#[test]
fn heif_two_meta_primary_ispe_overrides() {
  // The complement of `heif_primary_change_across_meta_boxes_keeps_main_doc_dims`:
  // a later `meta` whose `ispe` IS main-document (associated with that meta's
  // primary) overrides the earlier dims (last-FoundTag-wins over the whole file).
  //
  // Pass 1: primary 2, ispe(640x480) assoc{2→1} ⇒ 640x480. Pass 2: primary 9,
  // ispe(11x22) assoc{9→1} (the PRIMARY) ⇒ main-document ⇒ overrides to 11x22.
  // Oracle (bundled `exiftool -G1 -j` on the equivalent two-meta-box file):
  // File:ImageWidth 11, File:ImageHeight 22.
  use exifast::formats::quicktime_brands::walk_heif_meta;
  use exifast::metadata::HeifMeta;

  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };
  // Build a meta body: pitm(primary) + iprp(ipco[ispe(w,h)] , ipma{assoc_id→1}).
  let meta_body = |primary: u16, w: u32, h: u32, assoc_id: u16| -> Vec<u8> {
    let mut pitm = Vec::new();
    pitm.extend_from_slice(&[0, 0, 0, 0]);
    pitm.extend_from_slice(&primary.to_be_bytes());
    let ipco = box_bytes(b"ipco", &ispe(w, h));
    let mut ipma = Vec::new();
    ipma.extend_from_slice(&[0, 0, 0, 0]);
    ipma.extend_from_slice(&1u32.to_be_bytes());
    ipma.extend_from_slice(&assoc_id.to_be_bytes());
    ipma.push(1);
    ipma.push(1);
    let mut iprp = Vec::new();
    iprp.extend(ipco);
    iprp.extend(box_bytes(b"ipma", &ipma));
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend(box_bytes(b"pitm", &pitm));
    body.extend(box_bytes(b"iprp", &iprp));
    body
  };

  let mut m = HeifMeta::new();
  let mut iloc_budget = u64::MAX;
  walk_heif_meta(&meta_body(2, 640, 480, 2), 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(m.image_width(), Some(640));
  // Pass 2: ispe(11x22) associated with the NEW primary 9 ⇒ overrides.
  walk_heif_meta(&meta_body(9, 11, 22, 9), 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(m.primary_item(), Some(9));
  assert_eq!(
    m.image_width(),
    Some(11),
    "main-document later ispe must override"
  );
  assert_eq!(m.image_height(), Some(22));
}

#[cfg(feature = "json")]
#[test]
fn cr3_many_empty_cmt_boxes_bounded() {
  // R4 [high] — the CMT block COUNT must be bounded. Storing each CMT box's
  // decoded TAGS (eager parse at walk time), not its raw body, means an empty
  // (size-8) CMT box yields ZERO tags and only updates a FIXED per-kind
  // location slot — so a crafted CR3 with a huge N of empty CMT boxes can
  // neither grow an unbounded list nor spin the emit loop. There is no raw-body
  // Vec and no per-box list to amplify (that surface is gone structurally).
  //
  // This builds a Canon `uuid` payload with a large N of size-8 empty CMT1
  // boxes and asserts the walk completes promptly without OOM/hang, the CMT1
  // location slot holds the LAST box (last-wins), and NO CMT tags were produced
  // (an empty body has no parseable TIFF).
  use exifast::formats::quicktime_brands::walk_canon_uuid;
  use exifast::metadata::Cr3Meta;

  // 2,000,000 size-8 empty CMT1 boxes — the old per-box list would have grown
  // to millions of entries; the fixed-slot design stays O(1) in storage.
  const N: usize = 2_000_000;
  let mut payload = Vec::new();
  payload.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
  // A size-8 box is header-only (4-byte size + 4-byte tag), empty body.
  for _ in 0..N {
    payload.extend_from_slice(&8u32.to_be_bytes());
    payload.extend_from_slice(b"CMT1");
  }

  let mut m = Cr3Meta::new();
  walk_canon_uuid(&payload, 0, &mut m); // must complete without OOM/hang

  // The CNCV still decoded (the walk ran to completion past all the empties).
  assert_eq!(
    m.compressor_version(),
    Some("CanonCR3_001/00.09.00/00.00.00")
  );
  // A CMT1 location slot is present (last-wins): millions of boxes collapse to
  // ONE fixed slot, not a list.
  let blk = m.cmt1().expect("a CMT1 location slot is recorded");
  assert_eq!(blk.length(), 0, "an empty CMT1 box has a zero-length body");
  // No CMT tags were produced — an empty body has no parseable TIFF, so the
  // rendered-tag buffers stay empty regardless of box count (∝ parsed tags).
  assert!(
    m.cmt_tags(true).is_empty() && m.cmt_tags(false).is_empty(),
    "empty CMT boxes must yield no rendered tags"
  );
}

// ============================================================================
// SP4 R2 — reordered / duplicate-input fidelity (F1 dup ipma, F2 CMT file order)
// ============================================================================

/// Build a minimal little-endian TIFF block holding a single IFD0 entry. The
/// IFD lives at offset 8 (just past the `II*\0` + ifd0-offset header); the
/// value bytes go out-of-line just after the IFD. Used to synthesize the
/// self-contained CMT1 (IFD0) / CMT3 (Canon MakerNote) TIFF blocks a Canon
/// `uuid` re-dispatches.
fn tiff_le_one_entry(tag: u16, ifd_type: u16, value: &[u8]) -> Vec<u8> {
  let count = value.len() as u32;
  // header(8) + [count(2) + 1 entry(12) + next-ifd(4)] = 8 + 18 = 26; value at 26.
  let ool_off = 26u32;
  let mut out = Vec::new();
  out.extend_from_slice(b"II");
  out.extend_from_slice(&0x2au16.to_le_bytes());
  out.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset
  out.extend_from_slice(&1u16.to_le_bytes()); // entry count
  out.extend_from_slice(&tag.to_le_bytes());
  out.extend_from_slice(&ifd_type.to_le_bytes());
  out.extend_from_slice(&count.to_le_bytes());
  out.extend_from_slice(&ool_off.to_le_bytes()); // value offset (out-of-line)
  out.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
  out.extend_from_slice(value);
  out
}

/// Build a CR3 (`crx ` brand) whose Canon `uuid` carries CNCV + the given
/// CMT blocks IN THE GIVEN ORDER. Each `(tag, body)` is emitted as a child
/// box in sequence, so the caller controls the file order of CMT1/CMT3.
fn cr3_with_cmt_order(blocks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(&[0, 0, 0, 1]);
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(b"isom");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
  ];
  let mut uuid_body = Vec::new();
  uuid_body.extend_from_slice(&CANON_UUID);
  uuid_body.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
  for (tag, body) in blocks {
    uuid_body.extend(box_bytes(tag, body));
  }
  let uuid = box_bytes(b"uuid", &uuid_body);
  let moov = box_bytes(b"moov", &uuid);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(moov);
  data
}

#[cfg(feature = "json")]
#[test]
fn heif_duplicate_ipma_last_association_wins() {
  // ExifTool assigns `$$items{$id}{Association} = \@association` per `ipma` ROW
  // (QuickTime.pm:9331), a plain `=`: a DUPLICATE row for the primary id
  // OVERWRITES the earlier association (last-wins) while STILL warning ("Item
  // property association entries are out of order"). The deferred `ipco` walk
  // then gates each `ispe` by that effective association: ispe index 1 (640) is
  // referenced only by the FIRST (overwritten) primary row and by the thumbnail
  // item 3, so it ends up a SUB-document (associated to non-primary item 3) and
  // is gated out; ispe index 2 (1280) is the primary's effective association ⇒
  // main-document ⇒ wins.
  //
  // Ground-truthed against `exiftool -G1 -j` on this exact shape: it emits
  // File:ImageWidth=1280 / File:ImageHeight=960 (the LAST row's ispe, prop 2),
  // NOT 640x480 (the first row's prop 1), plus the out-of-order warning.
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  // pitm v0 → primary item id 2.
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let pitm = box_bytes(b"pitm", &pitm_body);

  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };
  // ipco: index 1 = ispe(640x480), index 2 = ispe(1280x960).
  let mut ipco_body = Vec::new();
  ipco_body.extend(ispe(640, 480));
  ipco_body.extend(ispe(1280, 960));
  let ipco = box_bytes(b"ipco", &ipco_body);

  // ipma v0 flags0 with THREE rows, TWO of them for the primary item 2:
  //   row A: item 2 → [prop 1]  (640x480)
  //   row B: item 2 → [prop 2]  (1280x960)  ← duplicate id, LAST wins
  //   row C: item 3 → [prop 1]
  let mut ipma_body = Vec::new();
  ipma_body.extend_from_slice(&[0, 0, 0, 0]);
  ipma_body.extend_from_slice(&3u32.to_be_bytes()); // entry count
  ipma_body.extend_from_slice(&2u16.to_be_bytes()); // item 2
  ipma_body.push(1);
  ipma_body.push(1); // prop 1
  ipma_body.extend_from_slice(&2u16.to_be_bytes()); // item 2 AGAIN
  ipma_body.push(1);
  ipma_body.push(2); // prop 2
  ipma_body.extend_from_slice(&3u16.to_be_bytes()); // item 3
  ipma_body.push(1);
  ipma_body.push(1);
  let ipma = box_bytes(b"ipma", &ipma_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(ipco);
  iprp_body.extend(ipma);
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(pitm);
  meta_body.extend(iprp);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);

  let m = parse_quicktime(&data).expect("accepted");
  // The LAST association (prop 2 → 1280x960) wins, NOT the first (640x480).
  assert_eq!(m.heif().primary_item(), Some(2));
  assert_eq!(
    m.heif().image_width(),
    Some(1280),
    "duplicate ipma rows: the LAST association must win (1280, not 640)"
  );
  assert_eq!(m.heif().image_height(), Some(960));

  // The duplicate/out-of-order warning is still raised (ExifTool warns per the
  // `unless $id > $lastID` check even though the row overwrites).
  assert_eq!(
    m.heif().warning(),
    Some("Item property association entries are out of order"),
    "the out-of-order warning must be preserved on the duplicate row"
  );

  // And the emitted JSON carries the LAST association's dims, not the first.
  let json = exifast::parser::extract_info("dup_ipma.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":1280"#) && json.contains(r#""File:ImageHeight":960"#),
    "got: {json}"
  );
  assert!(
    !json.contains(r#""File:ImageWidth":640"#),
    "the first (overwritten) association leaked: {json}"
  );
}

#[test]
fn heif_unrelated_later_meta_does_not_erase_dims() {
  // `scan_quicktime_brands` walks EVERY `meta` box into the SAME `HeifMeta`.
  // ExifTool's `ispe` FoundTag is cumulative over the whole file (QuickTime.pm:
  // 3040); a later meta that produces NO main-document `ispe` does NOT remove the
  // earlier dims. So an earlier HEIF meta that emits 640x480, followed by an
  // UNRELATED later meta (no `iprp`/`ispe` — e.g. an iTunes-style metadata meta),
  // must LEAVE the dims at 640x480.
  use exifast::formats::quicktime_brands::walk_heif_meta;
  use exifast::metadata::HeifMeta;

  let ispe = |w: u32, h: u32| -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    box_bytes(b"ispe", &b)
  };

  // Meta 1: pitm(2) + iprp(ipco[ispe(640x480)], ipma{2→1}) ⇒ resolves 640x480.
  let mut pitm1 = Vec::new();
  pitm1.extend_from_slice(&[0, 0, 0, 0]);
  pitm1.extend_from_slice(&2u16.to_be_bytes());
  let ipco1 = box_bytes(b"ipco", &ispe(640, 480));
  let mut ipma1 = Vec::new();
  ipma1.extend_from_slice(&[0, 0, 0, 0]);
  ipma1.extend_from_slice(&1u32.to_be_bytes());
  ipma1.extend_from_slice(&2u16.to_be_bytes());
  ipma1.push(1);
  ipma1.push(1);
  let mut iprp1 = Vec::new();
  iprp1.extend(ipco1);
  iprp1.extend(box_bytes(b"ipma", &ipma1));
  let mut body1 = Vec::new();
  body1.extend_from_slice(&[0, 0, 0, 0]);
  body1.extend(box_bytes(b"pitm", &pitm1));
  body1.extend(box_bytes(b"iprp", &iprp1));

  let mut m = HeifMeta::new();
  let mut iloc_budget = u64::MAX;
  walk_heif_meta(&body1, 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(m.image_width(), Some(640));
  assert_eq!(m.image_height(), Some(480));

  // Meta 2 into the SAME HeifMeta: an UNRELATED meta with NO iprp/ipma/pitm
  // (only an unrelated hdlr child). It establishes NO property-resolution state,
  // so the earlier 640x480 must STAY (not be erased).
  let mut body2 = Vec::new();
  body2.extend_from_slice(&[0, 0, 0, 0]);
  body2.extend(box_bytes(b"hdlr", &[0u8; 24]));

  walk_heif_meta(&body2, 0, 4, &mut m, &mut iloc_budget);
  assert_eq!(
    m.image_width(),
    Some(640),
    "an unrelated later meta (no iprp/ipma) erased the earlier HEIF dims"
  );
  assert_eq!(m.image_height(), Some(480));
}

#[cfg(feature = "json")]
#[test]
fn cr3_cmt3_before_cmt1_no_model_threaded() {
  // F2 — ExifTool processes the Canon `uuid` child atoms in FILE order, and
  // `$$self{Model}` (set by a CMT1 IFD0) is a stateful single-pass value. The
  // Canon MakerNote (CMT3 → `Canon::Main` via ProcessCMT3) is walked with the
  // Model of the most-recent PRECEDING CMT1. So a CMT3 BEFORE any CMT1 runs with
  // NO Model in state; a CMT1-before-CMT3 threads the Model.
  //
  // The clean model-gated observable is Canon Main tag `0x96` (Canon.pm:1834):
  //   - Model =~ /EOS 5D/  ⇒ FIRST arm `SerialInfo` SubDirectory (decoded into
  //     `%Canon::SerialInfo`, #175) ⇒ `Canon:InternalSerialNumber2` IS emitted
  //     and the bare `Canon:InternalSerialNumber` is ABSENT (offset-9 string is
  //     empty in this 9-byte blob).
  //   - no/other Model      ⇒ SECOND arm `InternalSerialNumber` (the trailing
  //     `0xff` strip applies) ⇒ the bare `Canon:InternalSerialNumber` IS emitted
  //     (and `InternalSerialNumber2` is ABSENT).
  // Ground-truthed against `exiftool -G1 -j`: the in-order file emits
  // `Canon:InternalSerialNumber2` (the SerialInfo arm); the reordered file emits
  // the bare `Canon:InternalSerialNumber":"ABC123"`.

  // CMT1 IFD0 with Model (0x0110) ASCII = "Canon EOS 5D\0".
  let cmt1 = tiff_le_one_entry(0x0110, 2, b"Canon EOS 5D\0");
  // CMT3 (Canon MakerNote) IFD0 with 0x96 ASCII = "ABC123\xff\xff\xff".
  let cmt3 = tiff_le_one_entry(0x0096, 2, b"ABC123\xff\xff\xff");

  // In-order [CMT1, CMT3]: the Model is in state at the CMT3 walk ⇒ 0x96 routes
  // to the SerialInfo arm ⇒ `InternalSerialNumber2` emitted, bare
  // `InternalSerialNumber` absent.
  let in_order = cr3_with_cmt_order(&[(b"CMT1", cmt1.clone()), (b"CMT3", cmt3.clone())]);
  let json_in = exifast::parser::extract_info("cr3_inorder.cr3", &in_order, true);
  assert!(
    json_in.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "in-order CMT1 Model missing: {json_in}"
  );
  assert!(
    json_in.contains(r#""Canon:InternalSerialNumber2""#)
      && !json_in.contains(r#""Canon:InternalSerialNumber":"#),
    "in-order: Model in state ⇒ 0x96 is SerialInfo ⇒ InternalSerialNumber2 \
     present and bare InternalSerialNumber absent: {json_in}"
  );

  // Reordered [CMT3, CMT1]: the Model is NOT yet in state at the CMT3 walk ⇒
  // 0x96 falls to the InternalSerialNumber arm (stripped of trailing 0xff). The
  // Model is still emitted (CMT1 is processed after, in file order).
  let reordered = cr3_with_cmt_order(&[(b"CMT3", cmt3), (b"CMT1", cmt1)]);
  let json_re = exifast::parser::extract_info("cr3_reorder.cr3", &reordered, true);
  assert!(
    json_re.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "reordered CMT1 Model missing: {json_re}"
  );
  assert!(
    json_re.contains(r#""Canon:InternalSerialNumber":"ABC123""#),
    "reordered: CMT3-before-CMT1 ⇒ no Model in state ⇒ 0x96 InternalSerialNumber (stripped): {json_re}"
  );
}

// ============================================================================
// SP4 R4 — CMT memory discipline (no raw-body storage; bounded ∝ parsed tags)
// + model-state on the degradation path
// ============================================================================

/// Build a CR3 (`crx ` brand) moov carrying MANY Canon `uuid` atoms, each with
/// the given CMT blocks. Mirrors a crafted file with repeated moov-level Canon
/// uuid boxes (ExifTool re-runs `Canon::uuid` per box in file order).
fn cr3_with_n_canon_uuids(n: usize, blocks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
  const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
  ];
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(&[0, 0, 0, 1]);
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(b"isom");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut moov_body = Vec::new();
  for _ in 0..n {
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
    for (tag, body) in blocks {
      uuid_body.extend(box_bytes(tag, body));
    }
    moov_body.extend(box_bytes(b"uuid", &uuid_body));
  }
  let moov = box_bytes(b"moov", &moov_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(moov);
  data
}

#[cfg(feature = "json")]
#[test]
fn cr3_multiple_canon_uuid_atoms_bounded() {
  // R4 [high] — the aggregate CMT allocation must NOT reset per Canon `uuid`
  // atom. ExifTool re-runs `Canon::uuid` for EVERY moov-level Canon uuid box in
  // file order; the old design carried a PER-ATOM byte budget, so each atom
  // could copy up to the cap (unbounded across atoms). The eager-parse design
  // stores decoded TAGS, not raw bodies, and threads ONE shared `Cr3Meta`
  // across every `walk_canon_uuid` call — there is no per-atom budget to reset,
  // and allocation is bounded by the total parsed tag count (∝ input).
  //
  // This builds a moov with many Canon uuid atoms, each carrying a small real
  // CMT2 (ExifIFD) TIFF, and asserts: the parse completes (no OOM/hang), and the
  // CMT2 ExifIFD tag surfaces (the per-atom walk accumulates into the shared
  // view — it is not silently dropped by a stale per-atom budget).
  const N: usize = 50_000;
  // CMT2 (ExifIFD) carrying a single ASCII LensModel (0xa434) — a plain
  // string passthrough that surfaces as `ExifIFD:LensModel` (the real-fixture
  // test proves this tag emits). ASCII (type 2) ⇒ count == byte length, which
  // is what `tiff_le_one_entry` writes.
  let cmt2 = tiff_le_one_entry(0xa434, 2, b"PROBE-LENS ");
  let data = cr3_with_n_canon_uuids(N, &[(b"CMT2", cmt2)]);

  // Must complete promptly without OOM/hang despite N atoms.
  let json = exifast::parser::extract_info("cr3_multi_uuid.cr3", &data, true);

  // The CMT2 ExifIFD tag surfaces — the per-atom walk accumulated into the
  // SHARED Cr3Meta (no per-atom budget reset silently dropped it). Last-wins on
  // the duplicate key collapses the N identical copies to one.
  assert!(
    json.contains(r#""ExifIFD:LensModel":"PROBE-LENS""#),
    "CMT2 ExifIFD tag must surface across multiple uuid atoms: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn cr3_overbudget_or_dropped_cmt1_no_stale_model_for_cmt3() {
  // R4 [medium] — the file-order `$$self{Model}` threading must be correct on
  // the degradation path. The old design stored each CMT1 BODY and re-parsed it
  // at emit; a dropped (over-budget) CMT1 became an EMPTY body that parsed to NO
  // model, leaving the EARLIER CMT1's Model STALE for the next CMT3 — flipping
  // the model-conditional `0x96` arm. The eager-parse design captures each
  // CMT1's Model AT WALK POSITION in file order (no drop, no re-parse), so a
  // later CMT1's Model correctly SUPERSEDES an earlier one and a model-less CMT1
  // never clears it. This test pins BOTH directions.
  //
  // Discriminating observable is Canon Main tag `0x96` (Canon.pm:1834):
  //   - Model =~ /EOS 5D/ ⇒ `SerialInfo` SubDirectory arm (decoded, #175) ⇒
  //     `InternalSerialNumber2` present, bare `InternalSerialNumber` ABSENT.
  //   - other / no Model  ⇒ `InternalSerialNumber` arm (trailing 0xff stripped)
  //     ⇒ bare `InternalSerialNumber` present.
  // Ground-truthed against `exiftool -G1 -j`.

  let cmt1_5d = || tiff_le_one_entry(0x0110, 2, b"Canon EOS 5D\0");
  let cmt1_r5 = || tiff_le_one_entry(0x0110, 2, b"Canon EOS R5\0");
  let cmt1_nomodel = || tiff_le_one_entry(0x0131, 2, b"exifast\0");
  let cmt3 = || tiff_le_one_entry(0x0096, 2, b"ABC123\xff\xff\xff");

  // (a) The spec scenario — CMT1(5D), then a model-LESS CMT1, then CMT3. The 5D
  // Model must STILL thread (the model-less CMT1 does not clear it) ⇒ 0x96 is
  // SerialInfo ⇒ InternalSerialNumber2 present, bare InternalSerialNumber ABSENT.
  let data_a = cr3_with_cmt_order(&[
    (b"CMT1", cmt1_5d()),
    (b"CMT1", cmt1_nomodel()),
    (b"CMT3", cmt3()),
  ]);
  let json_a = exifast::parser::extract_info("cr3_a.cr3", &data_a, true);
  assert!(
    json_a.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "the 5D Model is emitted (the model-less CMT1 carries no Model tag): {json_a}"
  );
  assert!(
    json_a.contains(r#""Canon:InternalSerialNumber2""#)
      && !json_a.contains(r#""Canon:InternalSerialNumber":"#),
    "model-less middle CMT1 must NOT clear the 5D Model: 0x96 stays SerialInfo \
     ⇒ InternalSerialNumber2 present, bare InternalSerialNumber absent: {json_a}"
  );

  // (b) The supersede direction (the exact R4 drop-bug inverse) — CMT1(5D),
  // then a DIFFERENT real CMT1(R5), then CMT3. The LATER R5 Model must
  // supersede the 5D (the drop-bug would have left a stale 5D) ⇒ R5 does NOT
  // match /EOS 5D/ ⇒ 0x96 is the InternalSerialNumber arm ⇒ present (stripped).
  let data_b = cr3_with_cmt_order(&[
    (b"CMT1", cmt1_5d()),
    (b"CMT1", cmt1_r5()),
    (b"CMT3", cmt3()),
  ]);
  let json_b = exifast::parser::extract_info("cr3_b.cr3", &data_b, true);
  assert!(
    json_b.contains(r#""IFD0:Model":"Canon EOS R5""#),
    "the LAST CMT1 Model wins (last-wins per kind): {json_b}"
  );
  assert!(
    json_b.contains(r#""Canon:InternalSerialNumber":"ABC123""#),
    "the later R5 Model must SUPERSEDE the 5D (no stale earlier model): R5 ≠ \
     /EOS 5D/ ⇒ 0x96 is InternalSerialNumber (stripped): {json_b}"
  );
}

#[cfg(feature = "json")]
#[test]
fn cr3_modelless_cmt1_does_not_clear_threaded_model() {
  // F2 — `$$self{Model}` (set by a CMT1 IFD0 Model) is a stateful single-pass
  // value that ExifTool only ASSIGNS when a Model (0x0110) tag is handled. A
  // CMT1 that parses but lacks a Model does NOT clear an earlier Model. So a
  // sequence CMT1(Model), CMT1(no-Model), CMT3 must walk the CMT3 with the FIRST
  // CMT1's Model still threaded — overwriting it with `None` on the model-less
  // CMT1 would be wrong.
  //
  // Discriminating observable is Canon Main tag `0x96` (Canon.pm:1834): with
  // Model =~ /EOS 5D/ ⇒ the `SerialInfo` SubDirectory arm (decoded, #175 ⇒
  // `InternalSerialNumber2` present, bare `InternalSerialNumber` ABSENT); with no
  // Model in state ⇒ the bare `InternalSerialNumber` arm (present, trailing 0xff
  // stripped). The threaded model is therefore "Canon EOS 5D" (the model the
  // `0x96` condition actually keys on), so the assertion is meaningful: if the
  // model-less CMT1 wrongly cleared the Model, the bare InternalSerialNumber
  // would appear. Ground-truthed against `exiftool -G1 -j`.

  // CMT1 #1: IFD0 with Model (0x0110) = "Canon EOS 5D\0".
  let cmt1_model = tiff_le_one_entry(0x0110, 2, b"Canon EOS 5D\0");
  // CMT1 #2: a model-LESS IFD0 (Software 0x0131 instead of Model) — parses, but
  // `dispatcher_model()` is None, so it must NOT overwrite the threaded Model.
  let cmt1_nomodel = tiff_le_one_entry(0x0131, 2, b"exifast\0");
  // CMT3 (Canon MakerNote) IFD0 with 0x96 = "ABC123\xff\xff\xff".
  let cmt3 = tiff_le_one_entry(0x0096, 2, b"ABC123\xff\xff\xff");

  let data = cr3_with_cmt_order(&[
    (b"CMT1", cmt1_model),
    (b"CMT1", cmt1_nomodel),
    (b"CMT3", cmt3),
  ]);
  let json = exifast::parser::extract_info("cr3_modelless.cr3", &data, true);

  // The CMT1 Model is still emitted (last-wins per kind on IFD0; the model-less
  // CMT1 carries no Model tag to overwrite it).
  assert!(
    json.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "CMT1 Model missing: {json}"
  );
  // The CMT3 walk saw the threaded Model (NOT cleared by the model-less CMT1) ⇒
  // 0x96 routes to SerialInfo ⇒ InternalSerialNumber2 present, bare
  // InternalSerialNumber ABSENT.
  assert!(
    json.contains(r#""Canon:InternalSerialNumber2""#)
      && !json.contains(r#""Canon:InternalSerialNumber":"#),
    "model-less CMT1 must NOT clear the threaded Model: with EOS 5D in state, \
     0x96 is SerialInfo ⇒ InternalSerialNumber2 present, bare \
     InternalSerialNumber absent: {json}"
  );
}

// ============================================================================
// SP4 R5 — file-walk `$$self{Model}` threads ACROSS Canon `uuid` atoms
// ============================================================================

/// Build a CR3 (`crx ` brand) moov carrying ONE Canon `uuid` atom PER inner
/// slice, each atom holding CNCV + that slice's CMT blocks (in order). Lets a
/// test place CMT1 in one Canon `uuid` and CMT3 in a LATER one — the layout
/// ExifTool walks as a single moov-level pass with persistent `$$self{Model}`.
fn cr3_with_canon_uuids(uuids: &[&[(&[u8; 4], Vec<u8>)]]) -> Vec<u8> {
  const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
  ];
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(&[0, 0, 0, 1]);
  ftyp_body.extend_from_slice(b"crx ");
  ftyp_body.extend_from_slice(b"isom");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut moov_body = Vec::new();
  for blocks in uuids {
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend(box_bytes(b"CNCV", b"CanonCR3_001/00.09.00/00.00.00"));
    for (tag, body) in *blocks {
      uuid_body.extend(box_bytes(tag, body));
    }
    moov_body.extend(box_bytes(b"uuid", &uuid_body));
  }
  let moov = box_bytes(b"moov", &moov_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(moov);
  data
}

#[cfg(feature = "json")]
#[test]
fn cr3_cmt1_in_earlier_uuid_threads_model_to_cmt3_in_later_uuid() {
  // R5 [high] — ExifTool's `$$self{Model}` is FILE-WALK object state, not
  // per-`uuid`-atom: it is set when ANY IFD0 / CMT1 `Model` (0x0110) is handled
  // and persists for the rest of the moov tree walk. So a CMT3 in a LATER Canon
  // `uuid` atom must see the `Model` of a CMT1 in an EARLIER Canon `uuid` atom.
  // The old per-uuid-local model reset this between atoms, silently flipping the
  // model-conditional `0x96` arm (Canon.pm:1834):
  //   - Model =~ /EOS 5D/ ⇒ `SerialInfo` SubDirectory arm (decoded, #175) ⇒
  //     `InternalSerialNumber2` present, bare `InternalSerialNumber` ABSENT.
  //   - no/other Model     ⇒ bare `InternalSerialNumber` arm (trailing 0xff
  //     stripped) ⇒ present.
  // Ground-truthed against `exiftool -G1 -j` on this multi-uuid layout.

  let cmt1_5d = || tiff_le_one_entry(0x0110, 2, b"Canon EOS 5D\0");
  let cmt3 = || tiff_le_one_entry(0x0096, 2, b"ABC123\xff\xff\xff");

  // uuid#1 { CMT1(Model="Canon EOS 5D") }, then uuid#2 { CMT3(0x96) }. The 5D
  // Model set while walking uuid#1 must STILL be in state at the uuid#2 CMT3 ⇒
  // 0x96 routes to SerialInfo ⇒ InternalSerialNumber2 present, bare
  // InternalSerialNumber ABSENT.
  let threaded = cr3_with_canon_uuids(&[&[(b"CMT1", cmt1_5d())], &[(b"CMT3", cmt3())]]);
  let json = exifast::parser::extract_info("cr3_cross_uuid.cr3", &threaded, true);
  assert!(
    json.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "the uuid#1 CMT1 Model is emitted: {json}"
  );
  assert!(
    json.contains(r#""Canon:InternalSerialNumber2""#)
      && !json.contains(r#""Canon:InternalSerialNumber":"#),
    "R5: a CMT1 Model in an EARLIER Canon uuid must thread to a CMT3 in a LATER \
     uuid ⇒ 0x96 is SerialInfo ⇒ InternalSerialNumber2 present, bare \
     InternalSerialNumber absent: {json}"
  );

  // Non-vacuousness: the SAME 0x96 bytes WITHOUT a preceding CMT1 Model take the
  // OTHER arm. Reversing the atom order — uuid#1 { CMT3(0x96) } BEFORE uuid#2
  // { CMT1(5D) } — leaves the CMT3 with NO model in state ⇒ 0x96 is
  // InternalSerialNumber (stripped). This proves the assertion above is
  // observable (it would FAIL if the model state were per-uuid-local: the
  // threaded case would also fall to InternalSerialNumber).
  let reversed = cr3_with_canon_uuids(&[&[(b"CMT3", cmt3())], &[(b"CMT1", cmt1_5d())]]);
  let json_rev = exifast::parser::extract_info("cr3_cross_uuid_rev.cr3", &reversed, true);
  assert!(
    json_rev.contains(r#""IFD0:Model":"Canon EOS 5D""#),
    "the uuid#2 CMT1 Model is still emitted (file order): {json_rev}"
  );
  assert!(
    json_rev.contains(r#""Canon:InternalSerialNumber":"ABC123""#),
    "CMT3 before any CMT1 (even cross-uuid) ⇒ no model in state ⇒ 0x96 is \
     InternalSerialNumber (stripped): {json_rev}"
  );
}

// ============================================================================
// HEIF item-property shape matrix (pitm / ipco / ipma / ispe)
//
// Every assertion below is ground-truthed against the bundled
// `perl exiftool 13.59 -fast -G1 -j -FileType -ImageWidth -ImageHeight` on the
// EXACT byte layout the builder produces (a synthetic HEIC: `ftyp(heic)` +
// `meta`). These pin the full association-shape class: the effective-primary-0
// fold (`$$et{PrimaryItem} || 0`), duplicate-`ipco` last-container-wins, the
// `ispe` version/flags `Condition` gate, the `@dim < 2` short-`ispe` guard, and
// the essential-bit index width.
// ============================================================================

/// Build a HEIC with an arbitrary `ipco` byte body + an explicit `ipma` body
/// (already serialized), an optional `pitm`. `pitm` is `Some(primary)` for a
/// `pitm` v0 box, or `None` to OMIT the box entirely (effective primary 0).
/// Lets the sweep tests craft `ispe` boxes with non-zero version/flags or a
/// truncated body that the typed `heic_with_ispes_and_ipma` builder cannot.
fn heic_with_raw_ipco_ipma(primary: Option<u16>, ipco_body: &[u8], ipma_body: &[u8]) -> Vec<u8> {
  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);

  let mut iprp_body = Vec::new();
  iprp_body.extend(box_bytes(b"ipco", ipco_body));
  iprp_body.extend(box_bytes(b"ipma", ipma_body));
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  if let Some(p) = primary {
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&p.to_be_bytes());
    meta_body.extend(box_bytes(b"pitm", &pitm_body));
  }
  meta_body.extend(iprp);
  let meta = box_bytes(b"meta", &meta_body);

  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(meta);
  data
}

/// Serialize an `ispe` box with an explicit 4-byte version/flags prefix and a
/// caller-controlled body length (`body_len` truncates the `[verflags][w][h]`
/// payload to exercise the `@dim < 2` short-box guard).
fn ispe_box_raw(verflags: [u8; 4], w: u32, h: u32, body_len: usize) -> Vec<u8> {
  let mut b = Vec::new();
  b.extend_from_slice(&verflags);
  b.extend_from_slice(&w.to_be_bytes());
  b.extend_from_slice(&h.to_be_bytes());
  b.truncate(body_len);
  box_bytes(b"ispe", &b)
}

/// Serialize a v0 `ipma` body: `[version=0|flags:3][num:u32]` then, per row,
/// `[id:u16][count:u8]` and `count` 1-byte (or 2-byte when `low_flag`)
/// association entries (the raw entry byte, INCLUDING any essential top bit).
fn ipma_v0_raw(low_flag: bool, rows: &[(u16, &[u16])]) -> Vec<u8> {
  let flags: u32 = u32::from(low_flag);
  let mut body = Vec::new();
  body.extend_from_slice(&flags.to_be_bytes());
  body.extend_from_slice(&(rows.len() as u32).to_be_bytes());
  for &(id, entries) in rows {
    body.extend_from_slice(&id.to_be_bytes());
    body.push(entries.len() as u8);
    for &e in entries {
      if low_flag {
        body.extend_from_slice(&e.to_be_bytes());
      } else {
        body.push(e as u8);
      }
    }
  }
  body
}

#[cfg(feature = "json")]
#[test]
fn heif_missing_pitm_item0_primary_emits() {
  // ExifTool's `my $primary = $$et{PrimaryItem} || 0`
  // (QuickTime.pm:10200) folds a MISSING `pitm` to the effective primary id 0,
  // so an `ipma` row for item id 0 matches the primary (`$id == $primary`) and
  // its `ispe` is MAIN-DOCUMENT. Layout: NO `pitm`, ipco[ispe(111×222)],
  // ipma{0 → prop 1}. Oracle (bundled `perl exiftool -fast -G1 -j` on this exact
  // layout): File:ImageWidth 111, File:ImageHeight 222.
  let ipco = ispe_box_raw([0, 0, 0, 0], 111, 222, 12);
  let ipma = ipma_v0_raw(false, &[(0, &[1])]);
  let data = heic_with_raw_ipco_ipma(None, &ipco, &ipma);
  let m = parse_quicktime(&data).expect("accepted");
  assert!(
    m.heif().primary_item().is_none(),
    "no pitm ⇒ primary_item None"
  );
  assert_eq!(
    m.heif().image_width(),
    Some(111),
    "missing pitm ⇒ effective primary 0; the item-0 ipma row makes its ispe main-document"
  );
  assert_eq!(m.heif().image_height(), Some(222));
  let json = exifast::parser::extract_info("nopitm0.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":111"#) && json.contains(r#""File:ImageHeight":222"#),
    "expected 111x222: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_missing_pitm_nonzero_item_gated_out() {
  // With NO `pitm` (effective primary 0) and the `ispe`
  // associated ONLY by a NON-zero item id (5), no item 0 row exists, so the
  // `ispe` is associated-but-not-by-primary ⇒ a SUB-document ⇒ gated out.
  // Layout: NO `pitm`, ipco[ispe(111×222)], ipma{5 → prop 1}. Oracle
  // (`perl exiftool -fast -G1 -j`): NO File:ImageWidth / File:ImageHeight.
  let ipco = ispe_box_raw([0, 0, 0, 0], 111, 222, 12);
  let ipma = ipma_v0_raw(false, &[(5, &[1])]);
  let data = heic_with_raw_ipco_ipma(None, &ipco, &ipma);
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(
    m.heif().image_width(),
    None,
    "no pitm + association only by a non-zero item ⇒ sub-document ⇒ no dims"
  );
  assert_eq!(m.heif().image_height(), None);
  let json = exifast::parser::extract_info("nopitm5.heic", &data, true);
  assert!(
    !json.contains(r#""File:ImageWidth""#),
    "no File:ImageWidth expected: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_duplicate_ipco_last_wins() {
  // ExifTool DEFERS the `ipco` directory by a plain ASSIGNMENT
  // `$$et{ItemPropertyContainer} = [ \%dirInfo, ... ]` (QuickTime.pm:10363) and
  // `%dupDirOK` whitelists `ipco` (QuickTime.pm:510), so a SECOND `ipco` in the
  // same `meta` OVERWRITES the first and only the LAST is processed once after
  // the walk (QuickTime.pm:9530-9534). The `ipma` index then refers into the
  // LAST `ipco`. Layout: iprp{ ipco#1[ispe(640×480)], ipco#2[ispe(1280×960)],
  // ipma{primary 2 → prop 1} }. Oracle (`perl exiftool -fast -G1 -j`):
  // File:ImageWidth 1280, File:ImageHeight 960 (NOT 640 — ipco#1 discarded).
  let ispe = |w: u32, h: u32| ispe_box_raw([0, 0, 0, 0], w, h, 12);
  let mut iprp_body = Vec::new();
  iprp_body.extend(box_bytes(b"ipco", &ispe(640, 480)));
  iprp_body.extend(box_bytes(b"ipco", &ispe(1280, 960)));
  iprp_body.extend(box_bytes(b"ipma", &ipma_v0_raw(false, &[(2, &[1])])));
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(box_bytes(b"pitm", &pitm_body));
  meta_body.extend(iprp);
  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(box_bytes(b"meta", &meta_body));

  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(
    m.heif().image_width(),
    Some(1280),
    "duplicate ipco: the LAST ipco's ispe must win (1280, not the discarded 640)"
  );
  assert_eq!(m.heif().image_height(), Some(960));
  let json = exifast::parser::extract_info("dupipco.heic", &data, true);
  assert!(
    json.contains(r#""File:ImageWidth":1280"#) && !json.contains(r#""File:ImageWidth":640"#),
    "the first ipco's ispe must NOT survive: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_duplicate_ipco_stale_unassociated_ispe_discarded() {
  // The shape that distinguishes last-`ipco`-wins from accumulation: the LAST
  // `ipco`'s `ispe` is GATED OUT while the FIRST `ipco` carries an UNassociated
  // (main-document) `ispe`. Under last-`ipco`-wins (ExifTool) ipco#1 is
  // discarded entirely, so the only surviving `ispe` (ipco#2 index 1) is
  // associated by a NON-primary item ⇒ sub-document ⇒ NOTHING emits.
  // Accumulating both containers would instead keep ipco#1's index-2
  // `ispe(7777×8888)` as a main-document property and wrongly emit it.
  //
  // Layout: NO `pitm` association for the primary; iprp{ ipco#1[ispe(1×1),
  // ispe(7777×8888)], ipco#2[ispe(640×480)], ipma{ item 3 → prop 1 } }. Oracle
  // (`perl exiftool -fast -G1 -j` on this exact layout): NO File:ImageWidth.
  let ispe = |w: u32, h: u32| ispe_box_raw([0, 0, 0, 0], w, h, 12);
  let mut ipco1 = Vec::new();
  ipco1.extend(ispe(1, 1));
  ipco1.extend(ispe(7777, 8888));
  let mut iprp_body = Vec::new();
  iprp_body.extend(box_bytes(b"ipco", &ipco1));
  iprp_body.extend(box_bytes(b"ipco", &ispe(640, 480)));
  iprp_body.extend(box_bytes(b"ipma", &ipma_v0_raw(false, &[(3, &[1])])));
  let iprp = box_bytes(b"iprp", &iprp_body);

  let mut ftyp_body = Vec::new();
  ftyp_body.extend_from_slice(b"heic");
  ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
  ftyp_body.extend_from_slice(b"mif1");
  ftyp_body.extend_from_slice(b"heic");
  let ftyp = box_bytes(b"ftyp", &ftyp_body);
  let mut pitm_body = Vec::new();
  pitm_body.extend_from_slice(&[0, 0, 0, 0]);
  pitm_body.extend_from_slice(&2u16.to_be_bytes());
  let mut meta_body = Vec::new();
  meta_body.extend_from_slice(&[0, 0, 0, 0]);
  meta_body.extend(box_bytes(b"pitm", &pitm_body));
  meta_body.extend(iprp);
  let mut data = Vec::new();
  data.extend(ftyp);
  data.extend(box_bytes(b"meta", &meta_body));

  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(
    m.heif().image_width(),
    None,
    "the stale ipco#1 ispe(7777x8888) must be discarded; ipco#2's ispe is a sub-document"
  );
  let json = exifast::parser::extract_info("dupipco_stale.heic", &data, true);
  assert!(
    !json.contains(r#""File:ImageWidth":7777"#) && !json.contains(r#""File:ImageWidth""#),
    "no dims expected (stale ipco#1 discarded, ipco#2 gated): {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_primary_without_ipma_row_only_nonprimary_gated_out() {
  // `pitm` present, but the PRIMARY item has NO `ipma` row; only a
  // NON-primary item associates the `ispe`. ExifTool's per-property loop
  // (QuickTime.pm:10203-10227) only iterates items that HAVE an Association, so
  // the primary never matches and the property is associated-by-non-primary ⇒ a
  // sub-document ⇒ gated out. Layout: pitm=2, ipco[ispe(640×480)],
  // ipma{ item 3 → prop 1 }. Oracle (`perl exiftool -fast -G1 -j`): NO dims.
  let data = heic_with_ispes_and_ipma(2, &[(640, 480)], &[(3, &[1])]);
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().primary_item(), Some(2));
  assert_eq!(
    m.heif().image_width(),
    None,
    "primary has no ipma row; the only association is non-primary ⇒ sub-document ⇒ no dims"
  );
  let json = exifast::parser::extract_info("prim_noassoc.heic", &data, true);
  assert!(
    !json.contains(r#""File:ImageWidth""#),
    "no dims expected: {json}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_ispe_nonzero_version_not_emitted() {
  // The `ispe` tag has `Condition => '$$valPt =~ /^\0{4}/'`
  // (QuickTime.pm:3036): a non-zero version/flags word means the box is NOT the
  // `ImageSpatialExtent` variant ExifTool decodes, so NO dims are produced. Both
  // a non-zero VERSION byte and a non-zero FLAGS low byte must suppress.
  let ipma = ipma_v0_raw(false, &[(2, &[1])]);

  // (a) version byte = 1.
  let data_v = heic_with_raw_ipco_ipma(Some(2), &ispe_box_raw([1, 0, 0, 0], 640, 480, 12), &ipma);
  let mv = parse_quicktime(&data_v).expect("accepted");
  assert_eq!(
    mv.heif().image_width(),
    None,
    "ispe with version byte 1 fails the Condition gate ⇒ no dims"
  );
  let json_v = exifast::parser::extract_info("ispe_ver.heic", &data_v, true);
  assert!(
    !json_v.contains(r#""File:ImageWidth""#),
    "no dims expected (version!=0): {json_v}"
  );

  // (b) flags low byte = 1.
  let data_f = heic_with_raw_ipco_ipma(Some(2), &ispe_box_raw([0, 0, 0, 1], 640, 480, 12), &ipma);
  let mf = parse_quicktime(&data_f).expect("accepted");
  assert_eq!(
    mf.heif().image_width(),
    None,
    "ispe with non-zero flags fails the Condition gate ⇒ no dims"
  );
  let json_f = exifast::parser::extract_info("ispe_flags.heic", &data_f, true);
  assert!(
    !json_f.contains(r#""File:ImageWidth""#),
    "no dims expected (flags!=0): {json_f}"
  );
}

#[cfg(feature = "json")]
#[test]
fn heif_ispe_too_short_no_dims() {
  // The `ispe` `RawConv` is `my @dim = unpack("x4N*", $val); return
  // undef if @dim < 2` (QuickTime.pm:3038-3039): a body shorter than 12 bytes
  // yields fewer than two `int32u` dims ⇒ no emit, no panic. Cover an 8-byte
  // (width only) and a 4-byte (verflags only) `ispe`.
  let ipma = ipma_v0_raw(false, &[(2, &[1])]);

  for body_len in [8usize, 4] {
    let data = heic_with_raw_ipco_ipma(
      Some(2),
      &ispe_box_raw([0, 0, 0, 0], 640, 480, body_len),
      &ipma,
    );
    let m = parse_quicktime(&data).expect("accepted");
    assert_eq!(
      m.heif().image_width(),
      None,
      "ispe body {body_len} bytes (@dim < 2) ⇒ no dims, no panic"
    );
    let json = exifast::parser::extract_info("ispe_short.heic", &data, true);
    assert!(
      !json.contains(r#""File:ImageWidth""#),
      "no dims expected (body {body_len}): {json}"
    );
  }
}

#[cfg(feature = "json")]
#[test]
fn heif_ispe_extra_dims_uses_first_two() {
  // `unpack("x4N*", ...)` reads ALL trailing `int32u`; only
  // `$dim[0]`/`$dim[1]` become ImageWidth/ImageHeight. An `ispe` carrying THREE
  // dims (an extra trailing u32) still emits the first two. Oracle
  // (`perl exiftool -fast -G1 -j`): File:ImageWidth 640, File:ImageHeight 480.
  let mut ispe_body = Vec::new();
  ispe_body.extend_from_slice(&[0, 0, 0, 0]);
  ispe_body.extend_from_slice(&640u32.to_be_bytes());
  ispe_body.extend_from_slice(&480u32.to_be_bytes());
  ispe_body.extend_from_slice(&7u32.to_be_bytes()); // extra trailing dim
  let ipco = box_bytes(b"ispe", &ispe_body);
  let data = heic_with_raw_ipco_ipma(Some(2), &ipco, &ipma_v0_raw(false, &[(2, &[1])]));
  let m = parse_quicktime(&data).expect("accepted");
  assert_eq!(m.heif().image_width(), Some(640));
  assert_eq!(m.heif().image_height(), Some(480));
}

#[cfg(feature = "json")]
#[test]
fn heif_ipma_essential_bit_masked_out_of_index() {
  // `ParseItemPropAssoc` masks the property index with the
  // essential-bit cleared: 1-byte entries `& 0x7f` (QuickTime.pm:9324), 2-byte
  // entries (`flags & 1`) `& 0x7fff` (QuickTime.pm:9317). So an association byte
  // with the top bit SET still resolves to the same `ipco` index. Both index
  // widths must point at the `ispe` regardless of the essential bit.
  let ispe = ispe_box_raw([0, 0, 0, 0], 640, 480, 12);

  // (a) 1-byte assoc, essential bit (0x80) + index 1 ⇒ masked to index 1.
  let ipma1 = ipma_v0_raw(false, &[(2, &[0x80 | 1])]);
  let data1 = heic_with_raw_ipco_ipma(Some(2), &ispe, &ipma1);
  let m1 = parse_quicktime(&data1).expect("accepted");
  assert_eq!(
    m1.heif().image_width(),
    Some(640),
    "1-byte essential bit must be masked out of the index ⇒ index 1 ⇒ emits"
  );
  assert_eq!(m1.heif().image_height(), Some(480));

  // (b) 2-byte assoc (flags&1), essential bit (0x8000) + 15-bit index 1.
  let ipma2 = ipma_v0_raw(true, &[(2, &[0x8000 | 1])]);
  let data2 = heic_with_raw_ipco_ipma(Some(2), &ispe, &ipma2);
  let m2 = parse_quicktime(&data2).expect("accepted");
  assert_eq!(
    m2.heif().image_width(),
    Some(640),
    "2-byte essential bit must be masked out of the 15-bit index ⇒ index 1 ⇒ emits"
  );
  assert_eq!(m2.heif().image_height(), Some(480));
}
