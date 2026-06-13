//! #181 — content/magic-based TIFF subtype detection → `File:FileType`.
//!
//! ExifTool's `DoProcessTIFF` refines a TIFF-structured file's `File:FileType`
//! from the file BODY, not the extension:
//!   - a `DNGVersion` (0xc612) tag in IFD0 → `OverrideFileType('DNG')`
//!     (`ExifTool.pm:8763-8765`), regardless of extension;
//!   - the `CR\x02\0` magic at byte 8 → `$fileType = 'CR2'`
//!     (`ExifTool.pm:8636-8641`), regardless of extension.
//! Both set `$$self{TIFF_TYPE}` away from `'TIFF'`, so neither emits the
//! multi-page `File:PageCount` tag (`ExifTool.pm:8767`).
//!
//! These use the REAL bundled fixtures (`DNG.dng`, `CanonRaw.cr2`,
//! `ExifTool.tif`, `GeoTiff.tif`) via the `EXIFTOOL_T_IMAGES` env var (ExifTool's
//! `t/images`); each test skips when it is unset / unreadable so a checkout
//! without the ExifTool sources still passes. Oracle values were captured with
//! `perl exiftool -G1 -FileType -FileTypeExtension -MIMEType -PageCount` on
//! ExifTool 13.59.
#![cfg(feature = "json")]

use exifast::parser::extract_info;
use serde_json::Value;

/// Read a real bundled fixture from `EXIFTOOL_T_IMAGES`, returning `None`
/// (with a skip note) when the env var is unset or the file is unreadable.
fn t_image(file: &str) -> Option<Vec<u8>> {
  let dir = match std::env::var("EXIFTOOL_T_IMAGES") {
    Ok(d) => d,
    Err(_) => {
      eprintln!("skipping: EXIFTOOL_T_IMAGES not set");
      return None;
    }
  };
  let path = format!("{dir}/{file}");
  match std::fs::read(&path) {
    Ok(d) => Some(d),
    Err(_) => {
      eprintln!("skipping: {path} not readable");
      None
    }
  }
}

/// Parse `data` under the presented `name` and return the single document
/// object (the `[{…}]` first element).
fn doc(name: &str, data: &[u8], print_on: bool) -> serde_json::Map<String, Value> {
  let json = extract_info(name, data, print_on);
  let v: Value =
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
  v.as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .cloned()
    .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"))
}

/// Assert the `File:*` type triplet matches `(file_type, ext, mime)` and that
/// NO `File:PageCount` is emitted, in BOTH `-j` and `-n` modes. `ext` is the
/// LOWERCASE extension as the `-j` PrintConv `lc` emits it (`ExifTool.pm:1433`);
/// `-n` emits the raw UPPERCASE form (`FoundTag('FileTypeExtension', uc …)`,
/// `ExifTool.pm:9714`), so the expected value is upper-cased for that mode.
fn assert_triplet_no_pagecount(name: &str, data: &[u8], file_type: &str, ext: &str, mime: &str) {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let o = doc(name, data, print_on);
    assert_eq!(
      o.get("File:FileType").and_then(Value::as_str),
      Some(file_type),
      "{name} ({mode}): File:FileType"
    );
    let want_ext = if print_on {
      ext.to_string()
    } else {
      ext.to_ascii_uppercase()
    };
    assert_eq!(
      o.get("File:FileTypeExtension").and_then(Value::as_str),
      Some(want_ext.as_str()),
      "{name} ({mode}): File:FileTypeExtension"
    );
    assert_eq!(
      o.get("File:MIMEType").and_then(Value::as_str),
      Some(mime),
      "{name} ({mode}): File:MIMEType"
    );
    assert!(
      !o.contains_key("File:PageCount"),
      "{name} ({mode}): a TIFF subtype must NOT emit File:PageCount: {o:?}"
    );
  }
}

/// DNG.dng → `File:FileType = DNG`, `dng`, `image/x-adobe-dng` (it carries
/// IFD0 `DNGVersion` 1.1.0.0). The CORE of #181: the SAME bytes presented under
/// a `.tif` extension OR a dotless name must STILL resolve to `DNG` — proving
/// the detection taps CONTENT (`DNGVersion`), not the filename. Pre-fix exifast
/// derived the subtype from the extension alone, so a misnamed DNG fell back to
/// plain `TIFF` (the bug this closes).
///
/// Oracle: `perl exiftool -G1 -FileType -FileTypeExtension -MIMEType -PageCount`
/// on `DNG.dng`, and on the same bytes copied to `foo.tif` / `foo` (no ext) →
/// `DNG` / `dng` / `image/x-adobe-dng` in every case, no `PageCount`.
#[test]
fn real_fixture_dng_filetype_via_dngversion() {
  let Some(data) = t_image("DNG.dng") else {
    return;
  };
  // Correctly-named: DNG via either the extension OR the content.
  assert_triplet_no_pagecount("DNG.dng", &data, "DNG", "dng", "image/x-adobe-dng");
  // Misnamed `.tif`: extension says TIFF, but IFD0 `DNGVersion` forces DNG.
  assert_triplet_no_pagecount("misnamed.tif", &data, "DNG", "dng", "image/x-adobe-dng");
  // Dotless name (no extension hint at all): still DNG, from `DNGVersion`.
  assert_triplet_no_pagecount("misnamed", &data, "DNG", "dng", "image/x-adobe-dng");
}

/// CanonRaw.cr2 → `File:FileType = CR2`, `cr2`, `image/x-canon-cr2`, detected
/// from the `CR\x02\0` magic at byte 8 of the TIFF header
/// (`ExifTool.pm:8636-8641`). The SAME bytes presented under a `.tif` extension
/// must STILL resolve to `CR2` — proving the detection taps the MAGIC, not the
/// filename (pre-fix the CR2 subtype came from the `.cr2` extension alone, so a
/// misnamed CR2 fell back to plain `TIFF`).
///
/// Oracle: `perl exiftool -G1 -FileType -FileTypeExtension -MIMEType -PageCount`
/// on `CanonRaw.cr2`, and on the same bytes copied to `foo.tif` → `CR2` / `cr2`
/// / `image/x-canon-cr2`, no `PageCount`.
#[test]
fn real_fixture_cr2_filetype_via_magic() {
  let Some(data) = t_image("CanonRaw.cr2") else {
    return;
  };
  assert_triplet_no_pagecount("CanonRaw.cr2", &data, "CR2", "cr2", "image/x-canon-cr2");
  // Misnamed `.tif`: extension says TIFF, but the `CR\x02\0` magic forces CR2.
  assert_triplet_no_pagecount("misnamed.tif", &data, "CR2", "cr2", "image/x-canon-cr2");
  // Dotless name: still CR2, from the byte-8 magic.
  assert_triplet_no_pagecount("misnamed", &data, "CR2", "cr2", "image/x-canon-cr2");
}

/// The CR2 `CR\x02\0` magic (`ExifTool.pm:8633-8641`) is computed for EVERY
/// standalone TIFF parse — ExifTool's `$raf` gate (`ExifTool.pm:8629`), NOT the
/// extension-derived `TIFF_TYPE eq 'TIFF'` PageCount gate — so a CR2 body
/// presented under ANOTHER RAW extension (`.dng`/`.nef`/`.arw`, whose extension
/// maps to a RAW SUBTYPE) STILL resolves to `CR2`: the magic is a strong early
/// signal that wins over the extension. This is the case the `.tif`/dotless
/// tests above could not catch — those extensions map to plain `TIFF`, where
/// the (buggy) `tiff_type_is_tiff` gate was already `true`; a RAW-subtype
/// extension makes it `false`, which is where a CR2 was mis-finalized to
/// `DNG`/`NEF`/`ARW` before this fix.
///
/// Oracle (ExifTool 13.59): `perl exiftool -G1 -FileType -FileTypeExtension
/// -MIMEType -PageCount` on `CanonRaw.cr2` copied to `foo.dng` / `foo.nef` /
/// `foo.arw` → `CR2` / `cr2` / `image/x-canon-cr2` in every case, no
/// `PageCount`.
#[test]
fn cr2_magic_overrides_other_raw_extension() {
  let Some(data) = t_image("CanonRaw.cr2") else {
    return;
  };
  for name in ["foo.dng", "foo.nef", "foo.arw"] {
    assert_triplet_no_pagecount(name, &data, "CR2", "cr2", "image/x-canon-cr2");
  }
}

/// A standalone classic TIFF whose IFD0 offset is ≥ 16 but which is shorter than
/// 16 bytes is REJECTED outright — no `File:FileType` at all — not recovered to a
/// plain `TIFF`. `DoProcessTIFF` does `$raf->Read($sig, 8) == 8 or return 0`
/// (`ExifTool.pm:8634`): for a `$raf`-backed (standalone) classic TIFF
/// (`$identifier == 0x2a`) whose IFD0 offset is already ≥ 16 (`ExifTool.pm:8633`),
/// it reads 8 bytes at byte 8 and `return 0`s — aborting the WHOLE TIFF (File
/// format error, no `File:FileType`) BEFORE any IFD walk or the `CR\x02\0` regex.
/// So the candidate must be rejected, not walked: a too-short header whose IFD0
/// offset already points past EOF carries no recoverable directory.
///
/// The crafted inputs are 12/13/15-byte little-endian headers: `II*\0`, IFD0
/// offset 16 (≥ 16, satisfying the offset gate), `CR\x02\0` at byte 8 — so bytes
/// 8..16 do NOT exist (the 8-byte read at byte 8 fails). They are presented under
/// a `.tif` AND a dotless name so the EXTENSION cannot itself imply a type. The
/// reject is gated on the standalone-TIFF path, `magic == 0x2a`, `ifd0_offset >=
/// 16`, and `data[8..16]` being absent — precise to this malformed shape; a valid
/// small TIFF (`ifd0_offset < 16`, or ≥ 16 bytes present) and every embedded
/// `APP1`/`eXIf` block are untouched.
///
/// Oracle (ExifTool 13.59, `perl exiftool -j -G1` on each crafted file): only
/// `SourceFile` + an `ExifTool:Error` — `File format error` under the recognized
/// `.tif` extension, `Unknown file type` under a dotless name — and NO
/// `File:FileType`/`FileTypeExtension`/`MIMEType`/`PageCount`. (ExifTool also
/// raises `Warning: Processing TIFF-like data after unknown 0-byte header`, which
/// it emits only after its seek-back loop re-tries the terminal TIFF scan; the
/// port's candidate-list model rejects the candidate without re-running it, so it
/// emits the same `Error` with no triplet but not that warning — a warning-only
/// trait of the engine, orthogonal to the load-bearing fact asserted here: the
/// file yields NO `File:FileType`.)
#[test]
fn cr2_magic_rejects_truncated_signature_window() {
  // II*\0 headers truncated at 12/13/15 bytes: IFD0 offset 16, CR\x02\0 at byte
  // 8. The bytes 8..16 are absent in every one, so the 8-byte read at byte 8
  // fails and `DoProcessTIFF` rejects the whole TIFF before any walk.
  let header: [u8; 12] = [
    0x49, 0x49, 0x2a, 0x00, // II*\0 (little-endian classic TIFF)
    0x10, 0x00, 0x00, 0x00, // IFD0 offset = 16 (>= 16, the offset gate)
    b'C', b'R', 0x02, 0x00, // the CR\x02\0 signature at byte 8 (bytes 8..12)
  ];
  for trunc_len in [12usize, 13, 15] {
    let mut data = header.to_vec();
    data.resize(trunc_len, 0); // pad 13/15 with NUL; bytes 8..16 still absent
    assert_eq!(data.len(), trunc_len, "truncated window length");
    assert!(
      data.get(8..16).is_none(),
      "bytes 8..16 must be absent (< 16 bytes)"
    );

    // `.tif` (recognized ⇒ `File format error`) AND dotless (`Unknown file
    // type`): in BOTH the truncated candidate is rejected, so NO `File:*`
    // triplet is emitted and the finalization `Error` matches the oracle.
    for (name, want_err) in [
      ("cr2trunc.tif", "File format error"),
      ("cr2trunc", "Unknown file type"),
    ] {
      for print_on in [true, false] {
        let mode = if print_on { "-j" } else { "-n" };
        let o = doc(name, &data, print_on);
        // The hard candidate-abort: NONE of the `File:*` type triplet is set.
        for key in ["File:FileType", "File:FileTypeExtension", "File:MIMEType"] {
          assert!(
            !o.contains_key(key),
            "{name} ({mode}, {trunc_len}B): a rejected truncated TIFF must emit no {key} \
             (oracle: File format error / Unknown file type, no File:FileType): {o:?}"
          );
        }
        assert!(
          !o.contains_key("File:PageCount"),
          "{name} ({mode}, {trunc_len}B): no File:PageCount on a rejected candidate: {o:?}"
        );
        // The engine surfaces the same finalization Error ExifTool does.
        assert_eq!(
          o.get("ExifTool:Error").and_then(Value::as_str),
          Some(want_err),
          "{name} ({mode}, {trunc_len}B): finalization Error: {o:?}"
        );
      }
    }
  }
}

/// A JPEG with an embedded `APP1` Exif/TIFF block must NEVER be misclassified
/// from the embedded TIFF's content — the CR2-magic / DNGVersion taps are gated
/// on the standalone-TIFF `$raf` path (`ExifTool.pm:8629`), which an embedded
/// block does not have. Two checks:
///  - real bundled JPEGs carrying EXIF (incl. a Canon MakerNote) stay `JPEG`
///    (`perl exiftool -G1 -FileType` on `Canon.jpg`/`ExifTool.jpg`/`GPS.jpg` →
///    `JPEG`);
///  - a CRAFTED JPEG whose embedded `APP1` TIFF carries the `CR\x02\0`
///    signature at byte 8 STAYS `JPEG` (the embedded path must not fire CR2
///    magic — bundled never detects CR2 from an `APP1` block).
#[test]
fn embedded_app1_tiff_never_triggers_cr2_magic() {
  for f in ["Canon.jpg", "ExifTool.jpg", "GPS.jpg"] {
    let Some(data) = t_image(f) else {
      continue;
    };
    let o = doc(f, &data, true);
    assert_eq!(
      o.get("File:FileType").and_then(Value::as_str),
      Some("JPEG"),
      "{f}: a JPEG with embedded EXIF must stay JPEG"
    );
  }

  // Crafted JPEG: SOI + APP1("Exif\0\0" + a TIFF header whose byte 8 is the
  // CR2 signature, IFD0 offset 16, empty IFD0) + EOI. The embedded TIFF carries
  // the CR2 magic, but the embedded path is gated OFF, so this stays JPEG.
  let mut tiff: Vec<u8> = vec![
    0x49, 0x49, 0x2a, 0x00, // II*\0 (little-endian classic TIFF)
    0x10, 0x00, 0x00, 0x00, // IFD0 offset = 16 (>= 16, the CR2 gate)
    b'C', b'R', 0x02, 0x00, // the CR\x02\0 signature at byte 8
    0x00, 0x00, 0x00, 0x00, // pad to offset 16
    0x00, 0x00, // IFD0 entry count = 0
    0x00, 0x00, 0x00, 0x00, // next-IFD pointer = 0
  ];
  let mut app1: Vec<u8> = b"Exif\0\0".to_vec();
  app1.append(&mut tiff);
  let seg_len = u16::try_from(app1.len() + 2).expect("APP1 fits in u16");
  let mut jpeg: Vec<u8> = vec![0xff, 0xd8, 0xff, 0xe1]; // SOI + APP1 marker
  jpeg.extend_from_slice(&seg_len.to_be_bytes());
  jpeg.extend_from_slice(&app1);
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  let o = doc("crafted.jpg", &jpeg, true);
  assert_eq!(
    o.get("File:FileType").and_then(Value::as_str),
    Some("JPEG"),
    "a JPEG whose embedded APP1 TIFF carries CR2 magic must stay JPEG (embedded gate off): {o:?}"
  );
}

/// Build an in-memory little-endian classic TIFF with two IFDs (a 2-page
/// image: each IFD carries `NewSubfileType` = 2, the `$val == 2` MultiPage
/// trigger of `Exif.pm:456`), optionally embedding a `DNGVersion` (0xc612,
/// `int8u`) tag in IFD0 with `dngversion`'s bytes as the COUNT and an inline
/// (≤4-byte) value field. With no `DNGVersion`, `OverrideFileType` never fires
/// and the multi-page `File:PageCount` is emitted; whether a present
/// `DNGVersion` promotes the file to DNG (and suppresses `PageCount`) is exactly
/// the Perl-truthiness question this exercises.
fn multipage_tiff_with_dngversion(dngversion: Option<&[u8]>) -> Vec<u8> {
  // A 12-byte IFD entry: tag(2) type(2) count(4) value/offset(4, inline).
  fn entry(tag: u16, typ: u16, count: u32, value: [u8; 4]) -> [u8; 12] {
    let mut e = [0u8; 12];
    e[0..2].copy_from_slice(&tag.to_le_bytes());
    e[2..4].copy_from_slice(&typ.to_le_bytes());
    e[4..8].copy_from_slice(&count.to_le_bytes());
    e[8..12].copy_from_slice(&value);
    e
  }
  // IFD0: NewSubfileType=2 (+ optional DNGVersion); IFD1: NewSubfileType=2.
  // NewSubfileType (0x00FE) < DNGVersion (0xc612) keeps tag ids ascending.
  let new_subfile = entry(0x00FE, 4, 1, 2u32.to_le_bytes()); // LONG = 2
  let mut ifd0: Vec<[u8; 12]> = vec![new_subfile];
  if let Some(bytes) = dngversion {
    assert!(
      bytes.len() <= 4,
      "inline DNGVersion value must be <= 4 bytes"
    );
    let count = u32::try_from(bytes.len()).expect("len fits u32");
    let mut value = [0u8; 4];
    value[..bytes.len()].copy_from_slice(bytes); // left-justified, zero-padded
    ifd0.push(entry(0xC612, 1, count, value)); // BYTE[count]
  }
  let ifd1: Vec<[u8; 12]> = vec![new_subfile];

  let ifd_size = |n: usize| 2 + 12 * n + 4; // count(2) + entries + next-ptr(4)
  let ifd0_off = 8u32; // right after the 8-byte header
  let ifd1_off = ifd0_off + u32::try_from(ifd_size(ifd0.len())).expect("fits u32");

  let mut out: Vec<u8> = Vec::new();
  out.extend_from_slice(b"II"); // little-endian
  out.extend_from_slice(&42u16.to_le_bytes()); // TIFF magic
  out.extend_from_slice(&ifd0_off.to_le_bytes()); // IFD0 offset
  // IFD0
  out.extend_from_slice(&u16::try_from(ifd0.len()).expect("fits u16").to_le_bytes());
  for e in &ifd0 {
    out.extend_from_slice(e);
  }
  out.extend_from_slice(&ifd1_off.to_le_bytes()); // next IFD = IFD1
  // IFD1
  out.extend_from_slice(&u16::try_from(ifd1.len()).expect("fits u16").to_le_bytes());
  for e in &ifd1 {
    out.extend_from_slice(e);
  }
  out.extend_from_slice(&0u32.to_le_bytes()); // no further IFD
  out
}

/// The `DNGVersion` (0xc612) `RawConv` DataMember drives `OverrideFileType('DNG')`
/// ONLY when its decoded value is PERL-TRUTHY — `ExifTool.pm:8763`'s gate is
/// `if ($$self{DNGVersion} and …)`, testing the truthiness of the RawConv'd
/// `$val` (`Exif.pm:3365` `$$self{DNGVersion} = $val`), NOT mere tag presence.
/// Perl treats a scalar as false only when it is `""` or `"0"`; an `int8u[4]`
/// renders as the space-joined `$val` (`ReadValue`'s `join(' ', @vals)`):
///
///   - count-0 (empty `$val == ''`)  → FALSY → `FileType TIFF` + `PageCount`;
///   - count-1 scalar `0` (`$val == '0'`) → FALSY → `FileType TIFF` + `PageCount`;
///   - `int8u[4]` `0 0 0 0` (`$val == '0 0 0 0'`, non-empty) → TRUTHY → `DNG`;
///   - `int8u[4]` `1 1 0 0` → TRUTHY → `DNG`.
///
/// Each crafted file is a 2-page TIFF (`NewSubfileType = 2` in both IFDs), so a
/// non-promotion leaves it a plain multi-page TIFF that DOES emit
/// `File:PageCount = 2` (`ExifTool.pm:8757`), while a promotion to DNG sets
/// `$$self{TIFF_TYPE} = 'DNG'` and SUPPRESSES `PageCount`.
///
/// Oracle (ExifTool 13.59, `perl exiftool -G1 -FileType -FileTypeExtension
/// -MIMEType -PageCount -DNGVersion` on each crafted file):
///   empty/`0` → `TIFF`/`tif`/`image/tiff` + `PageCount 2`;
///   `0 0 0 0`/`1 1 0 0` → `DNG`/`dng`/`image/x-adobe-dng`, no `PageCount`.
#[test]
fn empty_dngversion_stays_tiff() {
  // Asserts the crafted file resolves to `(file_type, ext, mime)` and that
  // `File:PageCount` is present iff `want_pagecount` (value 2), in both modes.
  let check =
    |label: &str, data: &[u8], file_type: &str, ext: &str, mime: &str, want_pagecount: bool| {
      for print_on in [true, false] {
        let mode = if print_on { "-j" } else { "-n" };
        let o = doc("crafted.tif", data, print_on);
        assert_eq!(
          o.get("File:FileType").and_then(Value::as_str),
          Some(file_type),
          "{label} ({mode}): File:FileType"
        );
        let want_ext = if print_on {
          ext.to_string()
        } else {
          ext.to_ascii_uppercase()
        };
        assert_eq!(
          o.get("File:FileTypeExtension").and_then(Value::as_str),
          Some(want_ext.as_str()),
          "{label} ({mode}): File:FileTypeExtension"
        );
        assert_eq!(
          o.get("File:MIMEType").and_then(Value::as_str),
          Some(mime),
          "{label} ({mode}): File:MIMEType"
        );
        assert_eq!(
          o.get("File:PageCount").and_then(Value::as_u64),
          want_pagecount.then_some(2),
          "{label} ({mode}): File:PageCount (want present={want_pagecount}): {o:?}"
        );
      }
    };

  // FALSY DNGVersion → stays a plain multi-page TIFF (PageCount emitted).
  let empty = multipage_tiff_with_dngversion(Some(&[]));
  check(
    "empty (count-0) DNGVersion",
    &empty,
    "TIFF",
    "tif",
    "image/tiff",
    true,
  );
  let scalar0 = multipage_tiff_with_dngversion(Some(&[0]));
  check(
    "scalar-0 DNGVersion",
    &scalar0,
    "TIFF",
    "tif",
    "image/tiff",
    true,
  );

  // TRUTHY DNGVersion → promoted to DNG (PageCount suppressed). `0 0 0 0` is the
  // subtle case: all bytes zero, but the joined `$val == '0 0 0 0'` is non-empty
  // and not `"0"`, so Perl-true (oracle: DNG).
  let all_zero = multipage_tiff_with_dngversion(Some(&[0, 0, 0, 0]));
  check(
    "all-zero (0 0 0 0) DNGVersion",
    &all_zero,
    "DNG",
    "dng",
    "image/x-adobe-dng",
    false,
  );
  let real = multipage_tiff_with_dngversion(Some(&[1, 1, 0, 0]));
  check(
    "nonzero (1 1 0 0) DNGVersion",
    &real,
    "DNG",
    "dng",
    "image/x-adobe-dng",
    false,
  );

  // Sanity: with NO DNGVersion at all, the same 2-page skeleton is a plain TIFF
  // with PageCount — proving the promotion is driven by the value, not the
  // surrounding structure.
  let none = multipage_tiff_with_dngversion(None);
  check("no DNGVersion", &none, "TIFF", "tif", "image/tiff", true);
}

/// A 12-byte little-endian IFD entry — `tag(2) type(2) count(4) value/offset(4,
/// inline)`. Shared by the duplicate-DNGVersion and GPS-IFD builders below.
fn ifd_entry(tag: u16, typ: u16, count: u32, value: [u8; 4]) -> [u8; 12] {
  let mut e = [0u8; 12];
  e[0..2].copy_from_slice(&tag.to_le_bytes());
  e[2..4].copy_from_slice(&typ.to_le_bytes());
  e[4..8].copy_from_slice(&count.to_le_bytes());
  e[8..12].copy_from_slice(&value);
  e
}

/// A `DNGVersion` (0xc612, `int8u`) IFD entry whose value is `bytes` (the COUNT
/// and the inline ≤4-byte value field). `bytes.len() == 0` is the falsy count-0
/// shape (`$val == ''`); `[1, 1, 0, 0]` is the truthy `1 1 0 0`.
fn dng_version_entry(bytes: &[u8]) -> [u8; 12] {
  assert!(
    bytes.len() <= 4,
    "inline DNGVersion value must be <= 4 bytes"
  );
  let count = u32::try_from(bytes.len()).expect("len fits u32");
  let mut value = [0u8; 4];
  value[..bytes.len()].copy_from_slice(bytes);
  ifd_entry(0xC612, 1, count, value)
}

/// Build a 2-page little-endian TIFF (`NewSubfileType = 2` in IFD0 and IFD1)
/// whose IFD0 carries `dngversions`'s entries IN ORDER after `NewSubfileType`
/// (`0x00FE < 0xc612`, so the ids stay ascending; duplicate 0xc612 ids are
/// processed in file order). Used to exercise the LAST-WINS assignment: a later
/// 0xc612 entry's truthiness OVERWRITES an earlier one's, so a truthy-then-falsy
/// pair stays a plain TIFF (`PageCount`) and a falsy-then-truthy pair promotes to
/// DNG — exactly as ExifTool's `$$self{DNGVersion} = $val` DataMember does.
fn multipage_tiff_with_dngversions(dngversions: &[&[u8]]) -> Vec<u8> {
  let new_subfile = ifd_entry(0x00FE, 4, 1, 2u32.to_le_bytes()); // LONG = 2
  let mut ifd0: Vec<[u8; 12]> = vec![new_subfile];
  for bytes in dngversions {
    ifd0.push(dng_version_entry(bytes));
  }
  let ifd1: Vec<[u8; 12]> = vec![new_subfile];

  let ifd_size = |n: usize| 2 + 12 * n + 4;
  let ifd0_off = 8u32;
  let ifd1_off = ifd0_off + u32::try_from(ifd_size(ifd0.len())).expect("fits u32");

  let mut out: Vec<u8> = Vec::new();
  out.extend_from_slice(b"II");
  out.extend_from_slice(&42u16.to_le_bytes());
  out.extend_from_slice(&ifd0_off.to_le_bytes());
  out.extend_from_slice(&u16::try_from(ifd0.len()).expect("fits u16").to_le_bytes());
  for e in &ifd0 {
    out.extend_from_slice(e);
  }
  out.extend_from_slice(&ifd1_off.to_le_bytes());
  out.extend_from_slice(&u16::try_from(ifd1.len()).expect("fits u16").to_le_bytes());
  for e in &ifd1 {
    out.extend_from_slice(e);
  }
  out.extend_from_slice(&0u32.to_le_bytes());
  out
}

/// The `DNGVersion` (0xc612) DataMember is `$$self{DNGVersion} = $val`
/// (`Exif.pm:3365`) — an ASSIGNMENT that runs EACH time the tag is handled, so
/// the value `DoProcessTIFF` (`ExifTool.pm:8763`) tests is the LAST-handled
/// 0xc612 in IFD0, NOT the first/any truthy one. Two duplicate IFD0 0xc612
/// entries, processed in file order:
///   - truthy `1 1 0 0` THEN falsy count-0 (`$val == ''`) → the falsy value
///     wins → `FileType TIFF` + `File:PageCount 2` (a sticky set-true-only latch
///     would WRONGLY keep the earlier truthy and finalize DNG);
///   - falsy count-0 THEN truthy `1 1 0 0` → the truthy value wins → `DNG`,
///     `PageCount` suppressed.
///
/// Oracle (ExifTool 13.59, `perl exiftool -G1 -FileType -FileTypeExtension
/// -MIMEType -PageCount -DNGVersion` on each crafted file):
///   `1 1 0 0` then count-0 → `TIFF`/`tif`/`image/tiff` + `PageCount 2`
///   (DNGVersion empty); count-0 then `1 1 0 0` → `DNG`/`dng`/`image/x-adobe-dng`
///   (DNGVersion `1.1.0.0`), no `PageCount`.
#[test]
fn duplicate_dngversion_last_wins_falsy_stays_tiff() {
  let check =
    |label: &str, data: &[u8], file_type: &str, ext: &str, mime: &str, want_pagecount: bool| {
      for print_on in [true, false] {
        let mode = if print_on { "-j" } else { "-n" };
        let o = doc("crafted.tif", data, print_on);
        assert_eq!(
          o.get("File:FileType").and_then(Value::as_str),
          Some(file_type),
          "{label} ({mode}): File:FileType"
        );
        let want_ext = if print_on {
          ext.to_string()
        } else {
          ext.to_ascii_uppercase()
        };
        assert_eq!(
          o.get("File:FileTypeExtension").and_then(Value::as_str),
          Some(want_ext.as_str()),
          "{label} ({mode}): File:FileTypeExtension"
        );
        assert_eq!(
          o.get("File:MIMEType").and_then(Value::as_str),
          Some(mime),
          "{label} ({mode}): File:MIMEType"
        );
        assert_eq!(
          o.get("File:PageCount").and_then(Value::as_u64),
          want_pagecount.then_some(2),
          "{label} ({mode}): File:PageCount (want present={want_pagecount}): {o:?}"
        );
      }
    };

  // Truthy THEN falsy: the LAST (falsy count-0) wins → plain multi-page TIFF.
  let truthy_then_falsy = multipage_tiff_with_dngversions(&[&[1, 1, 0, 0], &[]]);
  check(
    "DNGVersion 1 1 0 0 then count-0",
    &truthy_then_falsy,
    "TIFF",
    "tif",
    "image/tiff",
    true,
  );

  // Falsy THEN truthy: the LAST (truthy `1 1 0 0`) wins → DNG.
  let falsy_then_truthy = multipage_tiff_with_dngversions(&[&[], &[1, 1, 0, 0]]);
  check(
    "DNGVersion count-0 then 1 1 0 0",
    &falsy_then_truthy,
    "DNG",
    "dng",
    "image/x-adobe-dng",
    false,
  );
}

/// The `DNGVersion` RawConv lives ONLY in `%Exif::Main` (`Exif.pm:3353`), which
/// the walker applies in the Exif-main directories (IFD0 / ExifIFD / SubIFD /
/// trailing IFDs / InteropIFD). The GPS IFD is walked against `%GPS::Main`,
/// which has NO 0xc612 entry — so a tag id 0xc612 in the GPS IFD is just an
/// unknown GPS tag and must NOT set the `$$self{DNGVersion}` DataMember. A TIFF
/// whose GPS IFD carries a (truthy-bytes) 0xc612, with NO IFD0/Exif DNGVersion,
/// therefore stays a plain multi-page `TIFF` (+ `PageCount`).
///
/// Oracle (ExifTool 13.59, `perl exiftool -G1 -FileType -FileTypeExtension
/// -MIMEType -PageCount` on the crafted file): `TIFF`/`tif`/`image/tiff` +
/// `PageCount 2` (the GPS-IFD 0xc612 does not promote to DNG).
#[test]
fn gps_ifd_0xc612_does_not_promote_dng() {
  // IFD0: NewSubfileType=2 + a GPSInfo (0x8825) pointer to the GPS IFD; IFD1:
  // NewSubfileType=2 (the 2-page structure). The GPS IFD carries GPSVersionID
  // (0x0000) + tag 0xc612 with truthy `1 1 0 0` bytes.
  let new_subfile = ifd_entry(0x00FE, 4, 1, 2u32.to_le_bytes());

  let ifd_size = |n: usize| 2 + 12 * n + 4;
  let ifd0_off = 8u32;
  let ifd0_len = 2usize; // NewSubfileType + GPSInfo pointer
  let ifd1_off = ifd0_off + u32::try_from(ifd_size(ifd0_len)).expect("fits u32");
  let ifd1_len = 1usize;
  let gps_off = ifd1_off + u32::try_from(ifd_size(ifd1_len)).expect("fits u32");

  // GPSInfo pointer (0x8825, LONG, count 1) → gps_off. 0x00FE < 0x8825 keeps the
  // IFD0 tag ids ascending.
  let gps_pointer = ifd_entry(0x8825, 4, 1, gps_off.to_le_bytes());
  // GPS IFD leaves: GPSVersionID (0x0000, int8u[4]) then 0xc612 (truthy bytes).
  let gps_version = ifd_entry(0x0000, 1, 4, [2, 3, 0, 0]);
  let gps_c612 = ifd_entry(0xC612, 1, 4, [1, 1, 0, 0]);

  let mut out: Vec<u8> = Vec::new();
  out.extend_from_slice(b"II");
  out.extend_from_slice(&42u16.to_le_bytes());
  out.extend_from_slice(&ifd0_off.to_le_bytes());
  // IFD0
  out.extend_from_slice(&2u16.to_le_bytes());
  out.extend_from_slice(&new_subfile);
  out.extend_from_slice(&gps_pointer);
  out.extend_from_slice(&ifd1_off.to_le_bytes());
  // IFD1
  out.extend_from_slice(&1u16.to_le_bytes());
  out.extend_from_slice(&new_subfile);
  out.extend_from_slice(&0u32.to_le_bytes());
  // GPS IFD (terminal — next-IFD pointer 0)
  out.extend_from_slice(&2u16.to_le_bytes());
  out.extend_from_slice(&gps_version);
  out.extend_from_slice(&gps_c612);
  out.extend_from_slice(&0u32.to_le_bytes());

  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let o = doc("crafted.tif", &out, print_on);
    assert_eq!(
      o.get("File:FileType").and_then(Value::as_str),
      Some("TIFF"),
      "{mode}: a GPS-IFD 0xc612 must NOT promote to DNG: {o:?}"
    );
    assert_eq!(
      o.get("File:MIMEType").and_then(Value::as_str),
      Some("image/tiff"),
      "{mode}: GPS-IFD 0xc612 file MIME"
    );
    assert_eq!(
      o.get("File:PageCount").and_then(Value::as_u64),
      Some(2),
      "{mode}: a non-promoted multi-page TIFF emits PageCount 2: {o:?}"
    );
  }
}

/// A genuine plain TIFF (no `DNGVersion`, no RAW magic) stays `File:FileType =
/// TIFF` — the content taps must NOT mis-promote it. `ExifTool.tif` and
/// `GeoTiff.tif` are single-page plain TIFFs, so they also carry no
/// `File:PageCount` (oracle-confirmed). Guards against the content detection
/// firing on the wrong bytes.
#[test]
fn plain_tiff_stays_tiff() {
  for file in ["ExifTool.tif", "GeoTiff.tif"] {
    let Some(data) = t_image(file) else {
      continue;
    };
    for print_on in [true, false] {
      let mode = if print_on { "-j" } else { "-n" };
      let o = doc(file, &data, print_on);
      assert_eq!(
        o.get("File:FileType").and_then(Value::as_str),
        Some("TIFF"),
        "{file} ({mode}): plain TIFF must stay TIFF"
      );
      assert_eq!(
        o.get("File:MIMEType").and_then(Value::as_str),
        Some("image/tiff"),
        "{file} ({mode}): plain TIFF MIME"
      );
      assert!(
        !o.contains_key("File:PageCount"),
        "{file} ({mode}): single-page plain TIFF emits no PageCount: {o:?}"
      );
    }
  }
}
