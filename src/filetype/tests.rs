//! Tests for the faithful `GetFileType` port. Expectations were derived from
//! the bundled Perl ExifTool oracle:
//! `perl -I.../exiftool/lib -MImage::ExifTool=GetFileType -e '...'`
//! (see the module doc-comment and the commit message for the commands).

use super::*;

/// (input, scalar primary_type, ordered candidate list, description).
/// Verbatim from the Perl oracle.
const ORACLE: &[(&str, &str, &[&str], &str)] = &[
  ("x.mov", "MOV", &["MOV"], "Apple QuickTime movie"),
  ("x.mp4", "MOV", &["MOV"], "MPEG-4 video"),
  ("x.m4a", "MOV", &["MOV"], "MPEG-4 Audio"),
  ("x.m4v", "MOV", &["MOV"], "MPEG-4 Video"),
  (
    "x.3gp",
    "MOV",
    &["MOV"],
    "3rd Gen. Partnership Project audio/video",
  ),
  (
    "x.3gp2",
    "MOV",
    &["MOV"],
    "3rd Gen. Partnership Project 2 audio/video",
  ),
  (
    "x.3gpp",
    "MOV",
    &["MOV"],
    "3rd Gen. Partnership Project audio/video",
  ),
  ("x.avi", "RIFF", &["RIFF"], "Audio Video Interleaved"),
  (
    "x.wav",
    "RIFF",
    &["RIFF"],
    "WAVeform (Windows digital audio)",
  ),
  ("x.mkv", "MKV", &["MKV"], "Matroska Video"),
  ("x.flac", "FLAC", &["FLAC"], "Free Lossless Audio Codec"),
  ("x.ogg", "OGG", &["OGG"], "Ogg Vorbis audio file"),
  ("x.opus", "OGG", &["OGG"], "Ogg Opus audio file"),
  ("x.aac", "AAC", &["AAC"], "Advanced Audio Coding"),
  ("x.mp3", "MP3", &["MP3"], "MPEG-1 Layer 3 audio"),
  (
    "x.asf",
    "ASF",
    &["ASF"],
    "Microsoft Advanced Systems Format",
  ),
  ("x.wmv", "ASF", &["ASF"], "Windows Media Video"),
  ("x.flv", "FLV", &["FLV"], "Flash Video"),
  ("x.r3d", "R3D", &["R3D"], "Redcode RAW Video"),
  ("x.dv", "DV", &["DV"], "Digital Video"),
  ("x.mxf", "MXF", &["MXF"], "Material Exchange Format"),
  ("x.m2ts", "M2TS", &["M2TS"], "MPEG-2 Transport Stream"),
  ("x.mts", "M2TS", &["M2TS"], "MPEG-2 Transport Stream"),
  ("x.m2t", "M2TS", &["M2TS"], "MPEG-2 Transport Stream"),
  ("x.ts", "M2TS", &["M2TS"], "MPEG-2 Transport Stream"),
  ("x.aiff", "AIFF", &["AIFF"], "Audio Interchange File Format"),
  ("x.aif", "AIFF", &["AIFF"], "Audio Interchange File Format"),
  (
    "x.aifc",
    "AIFF",
    &["AIFF"],
    "Audio Interchange File Format Compressed",
  ),
  ("x.ape", "APE", &["APE"], "Monkey's Audio format"),
  (
    "x.docx",
    "DOCX",
    &["ZIP", "FPX"],
    "Office Open XML Document",
  ),
  (
    "x.docm",
    "DOCM",
    &["ZIP", "FPX"],
    "Office Open XML Document Macro-enabled",
  ),
  (
    "x.pptx",
    "PPTX",
    &["ZIP", "FPX"],
    "Office Open XML Presentation",
  ),
  (
    "x.xlsx",
    "XLSX",
    &["ZIP", "FPX"],
    "Office Open XML Spreadsheet",
  ),
  ("x.ai", "AI", &["PDF", "PS"], "Adobe Illustrator"),
  (
    "x.fff",
    "FFF",
    &["TIFF", "FLIR"],
    "Hasselblad Flexible File Format",
  ),
  (
    "x.raw",
    "RAW",
    &["RAW", "TIFF"],
    "Kyocera Contax N Digital RAW or Panasonic RAW",
  ),
  ("x.pfm", "PFM", &["Font", "PFM2"], "Printer Font Metrics"),
  (
    "x.vnt",
    "VNT",
    &["FPX", "VCard"],
    "Scene7 Vignette or V-Note text file",
  ),
  ("x.tif", "TIFF", &["TIFF"], "Tagged Image File Format"),
  ("x.qt", "MOV", &["MOV"], "Apple QuickTime movie"),
  (
    "x.heic",
    "MOV",
    &["MOV"],
    "High Efficiency Image Format still image",
  ),
  ("x.webm", "MKV", &["MKV"], "Google Web Movie"),
  ("x.webp", "RIFF", &["RIFF"], "Google Web Picture"),
  ("x.svg", "XMP", &["XMP"], "Scalable Vector Graphics"),
  (
    "x.jpg",
    "JPEG",
    &["JPEG"],
    "Joint Photographic Experts Group",
  ),
  (
    "x.jpeg",
    "JPEG",
    &["JPEG"],
    "Joint Photographic Experts Group",
  ),
  ("x.djvu", "AIFF", &["AIFF"], "DjVu image"),
  ("x.doc", "FPX", &["FPX"], "Microsoft Word Document"),
  ("foo.dll", "EXE", &["EXE"], "Windows Dynamic Link Library"),
  // whole-string fallback (no '.')
  ("MOV", "MOV", &["MOV"], "Apple QuickTime movie"),
  ("mp3", "MP3", &["MP3"], "MPEG-1 Layer 3 audio"),
  ("DOCX", "DOCX", &["ZIP", "FPX"], "Office Open XML Document"),
  // trailing " (SubType)" stripped only when no real extension
  (
    "image.heic",
    "MOV",
    &["MOV"],
    "High Efficiency Image Format still image",
  ),
  // D10 r7 fix: strip_subtype now uses leftmost " (" (Perl greedy .*).
  // "MOV (a) (b)" -> strip from first " (" to final ")" -> "MOV".
  // "DOCX (a) (b)" -> "DOCX" (multi-candidate -> scalar = ext "DOCX").
  // "AIT (a) (b)" -> "AIT" (alias AIT->AI, multi -> scalar = ext "AIT").
  ("MOV (a) (b)", "MOV", &["MOV"], "Apple QuickTime movie"),
  (
    "DOCX (a) (b)",
    "DOCX",
    &["ZIP", "FPX"],
    "Office Open XML Document",
  ),
  ("AIT (a) (b)", "AIT", &["PDF", "PS"], "Adobe Illustrator"),
];

/// Inputs the Perl oracle returns `<undef>` for (unrecognized OR unsupported).
const ORACLE_NONE: &[&str] = &[
  "x.avc",   // AVC -> %moduleName{AVC} == 0  (unsupported)
  "x.alias", // ALIAS -> 0 (unsupported)
  "x.bz2",   // BZ2 -> 0 (unsupported)
  "x.tar",   // TAR -> 0 (unsupported)
  "x.nope",  // unrecognized extension
  "AVC",     // whole-string, unsupported
  "unknownx",
  "x.filewithnodot",
  "photo.cr3 (Canon)", // has '.', ext "CR3 (CANON)" not in table
  "file (sub)",        // no '.', strip " (sub)" -> "file" -> FILE, unknown
  "foo.MOV (X Y)",     // ext "MOV (X Y)" not in table
  // D10 r7: Perl-oracle-verified None cases for strip_subtype fix.
  "weird)",        // ends with ')' but no " (" => no strip => uc "WEIRD)" unknown
  "x.flv (X) (Y)", // has '.', ext "FLV (X) (Y)" not in table => None
  "no parens",     // no '.' and no " (" => uc "NO PARENS" unknown
];

#[test]
fn get_file_type_matches_perl_oracle() {
  for &(input, scalar, list, desc) in ORACLE {
    let ft = get_file_type(input).unwrap_or_else(|| panic!("{input}: expected Some, got None"));
    assert_eq!(ft.primary_type(), scalar, "scalar primary_type for {input}");
    assert_eq!(ft.candidate_types(), list, "candidate list for {input}");
    assert_eq!(ft.description(), desc, "description for {input}");
  }
}

#[test]
fn get_file_type_none_matches_perl_oracle() {
  for &input in ORACLE_NONE {
    assert!(
      get_file_type(input).is_none(),
      "{input}: expected None (unrecognized or unsupported), got {:?}",
      get_file_type(input)
    );
  }
}

/// D10 r7: unit-test the fixed `strip_subtype` primitive in isolation.
///
/// Perl: `$file =~ s/ \((.*)\)$//` — greedy `.*` + `\)$` anchoring means the
/// substitution fires from the FIRST ` (` through the final `)`. Expectations
/// verified against the Perl oracle (see commit message).
#[test]
fn strip_subtype_leftmost_paren_matches_perl() {
  // Single subtype suffix — unchanged from before the fix.
  assert_eq!(strip_subtype("MOV (sub)"), Some("MOV"));
  assert_eq!(strip_subtype("file (sub)"), Some("file"));
  assert_eq!(strip_subtype("AIT (Illustrator)"), Some("AIT"));
  // Multiple subtype suffixes — the KEY fix: strip from the FIRST " (".
  assert_eq!(strip_subtype("MOV (a) (b)"), Some("MOV"));
  assert_eq!(strip_subtype("DOCX (a) (b)"), Some("DOCX"));
  assert_eq!(strip_subtype("AIT (a) (b)"), Some("AIT"));
  assert_eq!(strip_subtype("X (a) (b) (c)"), Some("X"));
  // No strip when string does not end with ')'.
  assert_eq!(strip_subtype("MOV"), None);
  assert_eq!(strip_subtype("weird)"), None); // no " (" before ")"
  assert_eq!(strip_subtype("no parens"), None);
  assert_eq!(strip_subtype(""), None);
  // No strip when ends with ')' but no " (" anywhere before it.
  assert_eq!(strip_subtype("(nodot)"), None); // no SPACE before "("
  assert_eq!(strip_subtype("a(b)"), None); // no space before "("
                                           // Edge: " (" immediately before the ")".
  assert_eq!(strip_subtype("stem ()"), Some("stem"));
  // Unicode in the stem is not a concern (" (" and ")" are ASCII so the
  // byte index from find is always a valid char boundary).
  assert_eq!(strip_subtype("caf\u{e9} (sub)"), Some("caf\u{e9}"));
}

#[test]
fn alias_recursion() {
  // TIF -> 'TIFF';  3GP2 -> '3G2' -> ['MOV',..];  MTS/M2T/TS -> 'M2TS';
  // QT -> 'MOV';  AZW -> 'MOBI' -> ['PDB',..];  ORI -> 'ORF'.
  assert_eq!(get_file_type("x.tif").unwrap().primary_type(), "TIFF");
  assert_eq!(get_file_type("x.3gp2").unwrap().candidate_types(), &["MOV"]);
  assert_eq!(get_file_type("x.qt").unwrap().primary_type(), "MOV");
  // AZW -> MOBI -> PDB (single type, supported).
  let azw = get_file_type("x.azw").unwrap();
  assert_eq!(azw.primary_type(), "PDB");
  assert_eq!(azw.description(), "Mobipocket electronic book");
  assert_eq!(get_file_type("x.ori").unwrap().primary_type(), "ORF");
}

#[test]
fn multi_candidate_order_is_preserved() {
  // DOCX scalar "DOCX", list ["ZIP","FPX"] (ZIP first — writable type first).
  let docx = get_file_type("x.docx").unwrap();
  assert_eq!(docx.primary_type(), "DOCX");
  assert_eq!(docx.candidate_types(), &["ZIP", "FPX"]);
  // AI list ["PDF","PS"]; FFF ["TIFF","FLIR"]; RAW ["RAW","TIFF"];
  // VNT ["FPX","VCard"]; PFM ["Font","PFM2"].
  assert_eq!(
    get_file_type("x.ai").unwrap().candidate_types(),
    &["PDF", "PS"]
  );
  assert_eq!(
    get_file_type("x.fff").unwrap().candidate_types(),
    &["TIFF", "FLIR"]
  );
  assert_eq!(
    get_file_type("x.raw").unwrap().candidate_types(),
    &["RAW", "TIFF"]
  );
  assert_eq!(
    get_file_type("x.vnt").unwrap().candidate_types(),
    &["FPX", "VCard"]
  );
  assert_eq!(
    get_file_type("x.pfm").unwrap().candidate_types(),
    &["Font", "PFM2"]
  );
  for ext in [
    "docm", "dotx", "pptm", "ppsx", "xlsm", "xltx", "potx", "ppam", "thmx", "xlam",
  ] {
    assert_eq!(
      get_file_type(&format!("x.{ext}"))
        .unwrap()
        .candidate_types(),
      &["ZIP", "FPX"],
      "{ext} candidate order"
    );
  }
}

/// FIX B (D10 r3): `%moduleName` is now faithful to Perl
/// `$module = $moduleName{$type}; $module = $type unless defined $module;`
/// — an ABSENT type yields `Module(Cow::Owned(<the type name>))`, NOT a
/// `(unknown)` sentinel and NOT via an interning table. Explicit `''` =>
/// `Core`, explicit `'0'` => `Unsupported`. Verified entry-by-entry against
/// bundled ExifTool.pm:853-918.
#[test]
fn module_for_type_semantics() {
  use std::borrow::Cow;
  let m = |s: &'static str| ModuleName::Module(Cow::Borrowed(s));
  // Explicit module-name entries (borrowed &'static).
  assert_eq!(module_for_type("MOV"), m("QuickTime"));
  assert_eq!(module_for_type("MP3"), m("ID3"));
  assert_eq!(module_for_type("MKV"), m("Matroska"));
  assert_eq!(module_for_type("R3D"), m("Red"));
  assert_eq!(module_for_type("OGG"), m("Ogg"));
  assert_eq!(module_for_type("CHM"), m("EXE"));
  assert_eq!(module_for_type("GZIP"), m("ZIP"));
  // Absent from %moduleName => Module(Cow::Owned(type)) (Perl $module=$type).
  // Spot-check the task's list: EXE, ZIP, AAC, FLV, RIFF.
  for t in ["EXE", "ZIP", "AAC", "RIFF"] {
    assert_eq!(
      module_for_type(t),
      ModuleName::Module(Cow::Owned(t.to_string())),
      "{t}: absent %moduleName => Module(type)"
    );
  }
  // FLV is PRESENT in %moduleName (=> 'Flash'); not an absent case.
  assert_eq!(module_for_type("FLV"), m("Flash"));
  // A never-listed free-form string => Module(Cow::Owned("THATSTRING")),
  // must not panic, must not be Unsupported (no (unknown) sentinel).
  assert_eq!(
    module_for_type("zzz-not-a-type"),
    ModuleName::Module(Cow::Owned("zzz-not-a-type".to_string()))
  );
  assert_eq!(
    module_for_type("THATSTRING"),
    ModuleName::Module(Cow::Owned("THATSTRING".to_string()))
  );
  assert!(!module_for_type("zzz-not-a-type").is_unsupported());
  // Core ('' in %moduleName)
  assert!(module_for_type("JPEG").is_core());
  assert!(module_for_type("TIFF").is_core());
  assert!(module_for_type("EXIF").is_core());
  assert!(module_for_type("EXV").is_core());
  // Unsupported (0 in %moduleName)
  assert!(module_for_type("AVC").is_unsupported());
  assert!(module_for_type("ALIAS").is_unsupported());
  assert!(module_for_type("BZ2").is_unsupported());
  assert!(module_for_type("TAR").is_unsupported());
  assert!(module_for_type("DEX").is_unsupported());
  assert!(module_for_type("WMF").is_unsupported());
  assert!(module_for_type("PHP").is_unsupported());
  // derive_more accessors still work with Cow.
  assert_eq!(module_for_type("MOV").unwrap_module(), "QuickTime");
  assert_eq!(module_for_type("EXE").unwrap_module(), "EXE"); // owned
  assert!(module_for_type("JPEG").try_unwrap_core().is_ok());
}

#[test]
fn magic_gate_no_signature_and_weak_and_no_magic() {
  // MP3 has NO %magicNumber entry -> NoSignature (NOT Match), and is weak.
  assert_eq!(magic("MP3", b"\xff\xfb\x90\x00"), Magic::NoSignature);
  assert!(magic("MP3", b"anything").is_no_signature());
  assert!(is_weak_magic("MP3"));
  assert!(!is_weak_magic("MOV"));
  // noMagic = { MXF, DV }.
  assert!(is_no_magic("MXF"));
  assert!(is_no_magic("DV"));
  assert!(!is_no_magic("MOV"));
  // A type with no entry at all.
  assert_eq!(magic("MOBI", b"whatever"), Magic::NoSignature);
}

#[test]
fn magic_gate_good_and_bad_bytes() {
  // FLV good 'FLV\x01' -> Match; wrong bytes -> NoMatch (the exact defect
  // being fixed: a known-signature type with wrong bytes is NOT accepted).
  assert_eq!(magic("FLV", b"FLV\x01\x05\x00\x00"), Magic::Match);
  assert_eq!(magic("FLV", b"NOTFLVDATA"), Magic::NoMatch);
  assert_eq!(magic("FLV", b"FLV\x00"), Magic::NoMatch); // \x00 != \x01

  // RIFF variants.
  assert_eq!(magic("RIFF", b"RIFF\0\0\0\0WAVE"), Magic::Match);
  assert_eq!(magic("RIFF", b"RF64\0\0\0\0"), Magic::Match);
  assert_eq!(magic("RIFF", b"NOPExxxx"), Magic::NoMatch);

  // MKV / EBML.
  assert_eq!(magic("MKV", &[0x1a, 0x45, 0xdf, 0xa3, 0x01]), Magic::Match);
  assert_eq!(magic("MKV", b"not-an-mkv"), Magic::NoMatch);

  // AAC '\xff[\xf0\xf1]'.
  assert_eq!(magic("AAC", &[0xff, 0xf1, 0x00]), Magic::Match);
  assert_eq!(magic("AAC", &[0xff, 0xf0]), Magic::Match);
  assert_eq!(magic("AAC", &[0xff, 0xe0]), Magic::NoMatch);

  // MOV: 4 any bytes then a known atom.
  assert_eq!(magic("MOV", b"\0\0\0\x14ftypqt  "), Magic::Match);
  assert_eq!(magic("MOV", b"\0\0\0\x14XXXXyyyy"), Magic::NoMatch);

  // FLAC / OGG ('...|ID3').
  assert_eq!(magic("FLAC", b"fLaC\0\0"), Magic::Match);
  assert_eq!(magic("FLAC", b"ID3\x04"), Magic::Match);
  assert_eq!(magic("FLAC", b"junk"), Magic::NoMatch);
  assert_eq!(magic("OGG", b"OggS\0\x02"), Magic::Match);
  assert_eq!(magic("OGG", b"nope"), Magic::NoMatch);

  // ASF 16-byte GUID.
  assert_eq!(
    magic(
      "ASF",
      &[
        0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce,
        0x6c, 0x00
      ]
    ),
    Magic::Match
  );
  assert_eq!(magic("ASF", &[0x00; 16]), Magic::NoMatch);

  // FPX / OLE2.
  assert_eq!(
    magic(
      "FPX",
      &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0x00]
    ),
    Magic::Match
  );
  assert_eq!(magic("FPX", b"\xd0\xcf\x11\xe0\x00"), Magic::NoMatch);

  // ZIP / DOCX 'PK\x03\x04'.
  assert_eq!(magic("ZIP", b"PK\x03\x04rest"), Magic::Match);
  assert_eq!(magic("DOCX", b"PK\x03\x04rest"), Magic::Match);
  assert_eq!(magic("ZIP", b"PK\x05\x06"), Magic::NoMatch);

  // JPEG / TIFF.
  assert_eq!(magic("JPEG", &[0xff, 0xd8, 0xff, 0xe0]), Magic::Match);
  assert_eq!(magic("JPEG", &[0xff, 0xd8, 0x00]), Magic::NoMatch);
  assert_eq!(magic("TIFF", b"II\x2a\x00"), Magic::Match);
  assert_eq!(magic("TIFF", b"MMxx"), Magic::Match); // (II|MM) only
  assert_eq!(magic("TIFF", b"XX"), Magic::NoMatch);
}

#[test]
fn magic_variable_width_patterns() {
  // M2TS: 0x47 sync every 188 bytes (g=187 between).
  let mut ts = vec![0u8; 1 + 188 + 188 + 1];
  ts[0] = 0x47;
  ts[1 + 187] = 0x47;
  ts[1 + 187 + 1 + 187] = 0x47;
  assert_eq!(magic("M2TS", &ts), Magic::Match);
  assert_eq!(magic("M2TS", &[0x00; 400]), Magic::NoMatch);

  // PDF: '\s*%PDF-\d+\.\d+'  (leading whitespace allowed).
  assert_eq!(magic("PDF", b"%PDF-1.4\n"), Magic::Match);
  assert_eq!(magic("PDF", b"   \r\n%PDF-1.7"), Magic::Match);
  assert_eq!(magic("PDF", b"%PDX-1.4"), Magic::NoMatch);

  // HTML: optional BOM, ws, then case-insensitive <HTML / <!DOCTYPE HTML / <?xml.
  assert_eq!(magic("HTML", b"<!DOCTYPE   html>"), Magic::Match);
  assert_eq!(magic("HTML", b"\xef\xbb\xbf  <html>"), Magic::Match);
  assert_eq!(magic("HTML", b"<?xml version"), Magic::Match);
  assert_eq!(magic("HTML", b"plain text"), Magic::NoMatch);

  // JSON: optional BOM/ws, optional '[', '{', ws, "key", ws, ':'.
  assert_eq!(magic("JSON", b"{\"a\":1}"), Magic::Match);
  assert_eq!(
    magic("JSON", b"\xef\xbb\xbf  [ { \"x\" : 2 ]"),
    Magic::Match
  );
  assert_eq!(magic("JSON", b"not json"), Magic::NoMatch);

  // Font: sfnt / OTTO / ttcf / wOFF / %!PS-AdobeFont- / StartFontMetrics.
  assert_eq!(magic("Font", &[0x00, 0x01, 0x00, 0x00, 0x00]), Magic::Match);
  assert_eq!(magic("Font", b"OTTO\x00rest"), Magic::Match);
  assert_eq!(magic("Font", b"wOFFxx"), Magic::Match);
  assert_eq!(magic("Font", b"StartFontMetrics 2.0"), Magic::Match);
  assert_eq!(magic("Font", b"random"), Magic::NoMatch);

  // TXT: all printable -> Match; a control byte -> NoMatch.
  assert_eq!(magic("TXT", b"hello world\n"), Magic::Match);
  assert_eq!(magic("TXT", b""), Magic::Match); // empty matches
  assert_eq!(magic("TXT", &[0xff, 0xfe]), Magic::Match); // UTF-16 LE BOM
  assert_eq!(magic("TXT", b"bad\x00byte"), Magic::NoMatch);

  // XMP: optional NULs/BOM then ws then '<'.
  assert_eq!(magic("XMP", b"<?xpacket"), Magic::Match);
  assert_eq!(magic("XMP", b"\xef\xbb\xbf  <x:xmpmeta"), Magic::Match);
  assert_eq!(magic("XMP", b"binary\x01"), Magic::NoMatch);

  // VCard: case-insensitive BEGIN:VCARD\r\n.
  assert_eq!(magic("VCard", b"BEGIN:VCARD\r\n"), Magic::Match);
  assert_eq!(magic("VCard", b"begin:vcalendar\r\n"), Magic::Match);
  assert_eq!(magic("VCard", b"BEGIN:VCARD\n"), Magic::NoMatch); // needs \r\n
}

#[test]
fn magic_optional_and_alternation_edges_vs_perl() {
  // Expectations verified against Perl /^regex/s (see commit message).
  // RAR 'Rar!\x1a\x07\x01?\0' — optional \x01 before \0.
  assert_eq!(magic("RAR", b"Rar!\x1a\x07\0"), Magic::Match); // no \x01
  assert_eq!(magic("RAR", b"Rar!\x1a\x07\x01\0"), Magic::Match); // \x01
  assert_eq!(magic("RAR", b"Rar!\x1a\x07XY"), Magic::NoMatch);

  // RSRC '(....)?\0\0\x01\0' — optional 4-byte prefix.
  assert_eq!(magic("RSRC", b"\0\0\x01\0rest"), Magic::Match); // absent
  assert_eq!(magic("RSRC", b"ABCD\0\0\x01\0"), Magic::Match); // present
  assert_eq!(magic("RSRC", b"\0\0\0\0"), Magic::NoMatch);

  // M2TS skip variant: 10-byte junk, then 192-, then 188-byte spacing.
  let mut m = vec![0u8; 10 + 1 + 191 + 1 + 187 + 1];
  m[10] = 0x47;
  m[10 + 1 + 191] = 0x47;
  m[10 + 1 + 191 + 1 + 187] = 0x47;
  assert_eq!(magic("M2TS", &m), Magic::Match);

  // PICT '(.{10}|.{522})(\x11\x01|\x00\x11)'.
  let mut p = vec![0u8; 10];
  p.extend_from_slice(&[0x11, 0x01]);
  assert_eq!(magic("PICT", &p), Magic::Match);
  let mut p2 = vec![0u8; 522];
  p2.extend_from_slice(&[0x00, 0x11]);
  assert_eq!(magic("PICT", &p2), Magic::Match);
  assert_eq!(magic("PICT", b"abc"), Magic::NoMatch);

  // ICO '\0\0[\x01\x02]\0[^0]\0' — 5th byte must NOT be '0' (0x30).
  assert_eq!(magic("ICO", &[0, 0, 1, 0, 0x41, 0]), Magic::Match);
  assert_eq!(magic("ICO", &[0, 0, 1, 0, b'0', 0]), Magic::NoMatch);

  // WMF two fixed alternatives.
  assert_eq!(magic("WMF", &[0xd7, 0xcd, 0xc6, 0x9a, 0, 0]), Magic::Match);
  assert_eq!(magic("WMF", &[0x01, 0, 0x09, 0, 0, 0x03]), Magic::Match);
  assert_eq!(magic("WMF", b"junk!!"), Magic::NoMatch);

  // SWF '[FC]WS[^\0]'.
  assert_eq!(magic("SWF", b"FWS\x01"), Magic::Match);
  assert_eq!(magic("SWF", b"CWS\x99"), Magic::Match);
  assert_eq!(magic("SWF", b"FWS\0"), Magic::NoMatch);

  // Real alternation.
  assert_eq!(magic("Real", b".RMF..."), Magic::Match);
  assert_eq!(magic("Real", b".ra\xfd"), Magic::Match);
  assert_eq!(magic("Real", b"http://x"), Magic::Match);
  assert_eq!(magic("Real", b"nope"), Magic::NoMatch);
}

#[test]
fn enum_variant_helpers() {
  assert!(Magic::Match.is_match());
  assert!(Magic::NoMatch.is_no_match());
  assert!(Magic::NoSignature.is_no_signature());
  assert!(ModuleName::Core.is_core());
  assert!(ModuleName::Unsupported.is_unsupported());
  assert!(ModuleName::Module(std::borrow::Cow::Borrowed("X")).is_module());
  assert_eq!(
    ModuleName::Module(std::borrow::Cow::Borrowed("X")).unwrap_module(),
    "X"
  );
}

/// FIX 1 (D10 r2): `%fileTypeLookup` string-aliases whose transitive
/// resolution is a multi-candidate `[[...],...]` row. In Perl `GetFileType`,
/// scalar context for any multi row is `$fileExt` — the *uppercased file
/// extension* — so for a string-alias-to-multi the scalar is the ALIAS KEY,
/// not any direct table entry. Enumerated from the bundled ExifTool.pm
/// (lines 230-586) via the Perl oracle; `AIT -> AI -> [['PDF','PS'],...]`
/// is the ONLY such alias. The pre-fix code paniced here (`ext_to_static`
/// `unreachable!`). Tuples verbatim from:
/// `perl -I.../exiftool/lib -MImage::ExifTool=GetFileType -e '...'`
/// (scalar, ordered list, description).
const ALIAS_MULTI: &[(&str, &str, &[&str], &str)] = &[
  ("x.ait", "AIT", &["PDF", "PS"], "Adobe Illustrator"),
  ("x.AIT", "AIT", &["PDF", "PS"], "Adobe Illustrator"),
  ("ait", "AIT", &["PDF", "PS"], "Adobe Illustrator"),
];

#[test]
fn alias_to_multi_scalar_is_extension_no_panic() {
  for &(input, scalar, list, desc) in ALIAS_MULTI {
    let ft = get_file_type(input).unwrap_or_else(|| panic!("{input}: expected Some, got None"));
    // scalar == the uppercased file extension (the alias key), like Perl.
    assert_eq!(ft.primary_type(), scalar, "alias->multi scalar for {input}");
    assert_eq!(ft.candidate_types(), list, "alias->multi list for {input}");
    assert_eq!(ft.description(), desc, "alias->multi desc for {input}");
  }
  // The direct multi row AI is unchanged: scalar "AI" (its own ext).
  let ai = get_file_type("x.ai").unwrap();
  assert_eq!(ai.primary_type(), "AI");
  assert_eq!(ai.candidate_types(), &["PDF", "PS"]);
  assert_eq!(ai.description(), "Adobe Illustrator");
}

/// FIX 2 (D10 r2): `%magicNumber{LNK}` (ExifTool.pm:988, verbatim, /s):
/// `(.{4}\x01\x14\x02\0{5}\xc0\0{6}\x46|\[[InternetShortcut\][\x0d\x0a])`.
/// alt2 is `[` then ONE byte from a single char-class (distinct bytes of
/// "InternetShortcut" plus `]` `[` CR LF), i.e. exactly 2 bytes — NOT
/// `[`,letter,`]`,CR/LF. Expected column is the bundled Perl regex result:
/// `perl -e 'print(($b =~ /^<regex>/s)?"M":"N")' "<bytes>"`.
#[test]
fn lnk_magic_matches_perl_regex() {
  // alt1: 4 any bytes, \x01\x14\x02, 5x\0, \xc0, 6x\0, \x46 (20 bytes).
  let alt1: &[u8] = b"ABCD\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46";
  let mut alt1_trailing = alt1.to_vec();
  alt1_trailing.extend_from_slice(b"rest-of-lnk");

  // (bytes, Perl regex result -> expected Magic).
  let cases: &[(&[u8], Magic)] = &[
    // alt2 positives (byte0 '[', byte1 in the class).
    (b"[InternetShortcut]\r\n", Magic::Match),
    (b"[I", Magic::Match),  // 'I' in set
    (b"[]", Magic::Match),  // ']' in set
    (b"[[", Magic::Match),  // '[' in set
    (b"[\r", Magic::Match), // CR in set
    (b"[\n", Magic::Match), // LF in set
    // alt1 positives.
    (alt1, Magic::Match),
    (&alt1_trailing, Magic::Match),
    // negatives.
    (b"[XZ", Magic::NoMatch),                // byte1 'Z' not in set
    (b"[Z", Magic::NoMatch),                 // 'Z' not in set
    (b"[a", Magic::NoMatch),                 // 'a' not in set
    (b"[s", Magic::NoMatch),                 // 's' not in set (case-sensitive)
    (b"xInternetShortcut]", Magic::NoMatch), // byte0 not '['
    (b"[", Magic::NoMatch),                  // only 1 byte
    (b"", Magic::NoMatch),                   // empty
    (
      b"ABCD\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x47",
      Magic::NoMatch, // alt1 wrong last byte (0x47 != 0x46)
    ),
    (
      b"ABCD\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00",
      Magic::NoMatch, // alt1 too short (19 bytes)
    ),
  ];
  for &(bytes, expected) in cases {
    assert_eq!(
      magic("LNK", bytes),
      expected,
      "LNK magic for {bytes:?} must equal Perl regex result"
    );
  }
}

// ===========================================================================
// D10 r4: `detection_candidates` — faithful ExtractInfo CANDIDATE ITERATOR.
// ===========================================================================
//
// SCOPE: `detection_candidates` is ExifTool's content-gated *candidate* loop
// (ExifTool.pm:2965-3045) under the default FastScan=0, transliterated
// EXACTLY. It does NOT finalize a type and does NOT dispatch a parser
// (`require .../$module.pm` / `Process$type`): ExifTool finalizes the FIRST
// candidate whose parser accepts the data and, on parser failure, seeks back
// and advances to the NEXT candidate (ExifTool.pm:3060-3077). That parser
// step is Phase 2. So this iterator faithfully yields EVERY gate-passing
// `$type` in loop order (== "every parser returned false"), then the `''`
// end-of-list terminal (recognizedExt, else the JPEG/TIFF unknown-header
// scan). The consumer drives it and stops at the first parser-accepted one.
//
// ORACLE: a faithful Perl transliteration of the SAME loop (`_ExifastSelectSeq`
// in /tmp/exifast_oracle/Image/ExifTool.pm — injected before `1;  # end` into
// a COPY of the bundled lib/Image/ExifTool.pm so it uses the real `my
// %magicNumber/%moduleName/%weakMagic` lexicals and the real
// @fileTypes/$testLen/GetFileType/GetFileExtension) but which, instead of
// stopping at the first selected type, collects the ORDERED LIST of every
// type the loop would select if each successive parser failed. The expected
// SEQ column below is that oracle's verbatim ordered output, run on
// byte-identical inputs (command + table in the commit message).
//
// KEY FAITHFUL FACTS (from the real source, confirmed by the oracle):
//   * The no-`%magicNumber` + truthy-`%moduleName` + not-`%weakMagic`
//     fall-through set, in @fileTypes order, is WV(21), 7Z(63), PFM2(95),
//     ISO(100), PCD(108) — none is ever gate-skipped, so every input whose
//     earlier candidates all fail their magic gate emits ALL of these in
//     order. `noMagic{MXF(36),DV(37)}` (gate bypassed when candidates are
//     non-empty) and weak `MP3(104)` (skipped only when recognizedExt is set)
//     interleave by their @fileTypes index.
//   * The OLD finalizing API returned only the FIRST of these (e.g.
//     `spoof.mp4 => WV`); that single-value assertion was wrong-by-design.
//     ExifTool's WavPack parser rejects non-WV data and the loop advances —
//     so the FULL faithful candidate sequence is what we assert now.
//   * `''` terminal: recognizedExt type if set (e.g. `x.dir => ... , DIR`),
//     else the JPEG/TIFF scan result with header_skip/after_unknown_header
//     (e.g. `x.jpg => ... , JPEG@skip0`, `junkjpeg.dat => ... , JPEG@skip16`).
//   * Container-module relabels (RIFF->AVI/WAV, inside the RIFF module) are
//     Phase 2; candidate granularity is the loop's `$type` (RIFF).

const PNG_HEAD: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
const JPEG_HEAD: &[u8] = b"\xff\xd8\xff\xe0\0\x10JFIF";

/// A terminal JPEG/TIFF candidate carrying its skip (Perl
/// `pos($buff) - length($1)`). All non-terminal candidates have skip 0 /
/// `after_unknown_header == false`.
#[derive(Debug, PartialEq, Eq)]
struct Term {
  ty: &'static str,
  skip: usize,
}

/// (filename, head bytes, expected ORDERED candidate type list, optional
/// JPEG/TIFF terminal). The list + terminal are VERBATIM from the injected
/// faithful Perl `_ExifastSelectSeq` oracle (see `/tmp/exifast_oracle/run.pl`).
struct SeqCase {
  name: &'static str,
  head: &'static [u8],
  seq: &'static [&'static str],
  /// `Some` iff the oracle's final element was a `TYPE\tskip\t1` JPEG/TIFF
  /// terminal; that element is NOT included in `seq`.
  term: Option<Term>,
}

const SEQ_ORACLE: &[SeqCase] = &[
  // -- real ext + matching magic: candidate first, then the full
  //    no-magic/noMagic/weak fall-through set (parser-failure emulation). --
  SeqCase {
    name: "x.flv",
    head: b"FLV\x01\x05\0\0\0\x09\0\0\0\0",
    seq: &["FLV", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "riffwave.wav",
    head: b"RIFF\x24\0\0\0WAVEf",
    seq: &["RIFF", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "x.mkv",
    head: &[0x1a, 0x45, 0xdf, 0xa3, 1, 0, 0, 0, 0, 0, 0, 0],
    seq: &["MKV", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "x.aac",
    head: &[0xff, 0xf1, 0x50, 0x80],
    seq: &["AAC", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "x.png",
    head: PNG_HEAD,
    seq: &["PNG", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // x.jpg: JPEG candidate, fall-through set, then '' terminal => the
  // JPEG/TIFF scan finds the JPEG marker at offset 0 (skip 0).
  SeqCase {
    name: "x.jpg",
    head: JPEG_HEAD,
    seq: &["JPEG", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: Some(Term {
      ty: "JPEG",
      skip: 0,
    }),
  },
  // -- SPOOFED / corrupt: the core fix. The wrong-magic candidate is gated
  //    out; the iterator continues. x.flv carrying PNG bytes: NO FLV; PNG
  //    (idx 10) appears, FLV does NOT. --
  SeqCase {
    name: "spoof.flv",
    head: PNG_HEAD,
    seq: &["PNG", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // x.mp4 carrying 'RIFF....AVI ': candidate MOV fails magic; @fileTypes
  // scan reaches WV(21) BEFORE RIFF(22). The OLD API returned just "WV";
  // the faithful sequence is WV, RIFF, ... (ExifTool's WavPack parser
  // fails, loop advances to RIFF; RIFF->AVI relabel is Phase 2).
  SeqCase {
    name: "spoof.mp4",
    head: b"RIFF\x24\0\0\0AVI ",
    seq: &["WV", "RIFF", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // x.flv zeros / random: FLV magic fails; fall-through set only.
  SeqCase {
    name: "zero.flv",
    head: &[0u8; 16],
    seq: &["WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "rand.flv",
    head: &[
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 1, 2, 3, 4, 5, 6, 7, 8,
    ],
    seq: &["WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // -- no/unknown ext + valid magic: empty candidate list => full
  //    @fileTypes scan. PNG(10) appears before WV(21); no MXF/DV (those are
  //    noMagic-bypassed ONLY in the non-empty-candidates branch). --
  SeqCase {
    name: "blob",
    head: PNG_HEAD,
    seq: &["PNG", "WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "unkext.zzz",
    head: PNG_HEAD,
    seq: &["PNG", "WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // -- JPEG/TIFF after a junk header: empty candidates => @fileTypes scan
  //    (no MXF/DV bypass), fall-through set, then the '' JPEG/TIFF terminal
  //    with the non-zero skip (Perl pos - len(marker)). --
  SeqCase {
    name: "junkjpeg.dat",
    head:
      b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xd8\xff\xe0\0\x10JFIF",
    seq: &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: Some(Term {
      ty: "JPEG",
      skip: 16,
    }),
  },
  SeqCase {
    name: "junktiff.bin",
    head: b"ABCDEFGHII\x2a\x00rest",
    seq: &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: Some(Term {
      ty: "TIFF",
      skip: 8,
    }),
  },
  // -- MXF/DV noMagic: GetFileType gives [MXF]/[DV]; non-empty-candidates
  //    branch sets noMagic{MXF,DV} => the magic gate is bypassed for them,
  //    so the named type appears even with arbitrary bytes. The OTHER of
  //    the pair also appears (still noMagic), at its @fileTypes index. --
  SeqCase {
    name: "x.mxf",
    head: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    seq: &["MXF", "WV", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "x.dv",
    head: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    seq: &["DV", "WV", "MXF", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // -- MP3 weak: ext "MP3" has no %magicNumber AND %moduleName{MP3}='ID3'
  //    (truthy, NOT falsey) => recognizedExt is NOT set; weakMagic{MP3} is
  //    skipped ONLY when recognizedExt is set, so MP3 (the candidate)
  //    appears first and is then deduped out of the @fileTypes tail (so MP3
  //    is ABSENT from the fall-through set here). --
  SeqCase {
    name: "x.mp3",
    head: &[1, 2, 3, 4, 5, 6, 7, 8],
    seq: &["MP3", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "PCD"],
    term: None,
  },
  SeqCase {
    name: "mp3weak.mp3",
    head: &[1, 2, 3, 4, 5, 6, 7, 8],
    seq: &["MP3", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "PCD"],
    term: None,
  },
  // -- misc edges (oracle-verified) --
  // plain.txt: TXT candidate (magic matches printable), fall-through set.
  SeqCase {
    name: "plain.txt",
    head: b"hello world\n",
    seq: &["TXT", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  SeqCase {
    name: "noext_junk",
    head: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    seq: &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // empty.flv: FLV magic fails on empty; fall-through set; TXT magic
  // matches the EMPTY buffer (TXT idx 111) => TXT appears as the last
  // gate-passing element; no '' terminal (no recognizedExt, no JPEG/TIFF).
  SeqCase {
    name: "empty.flv",
    head: b"",
    seq: &["WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD", "TXT"],
    term: None,
  },
  // x.dir: ext DIR -> %moduleName{DIR}='0' => get_file_type None => empty
  // candidates => @fileTypes scan; recognizedExt=DIR is SET so weak MP3 is
  // skipped, and the '' terminal yields recognizedExt DIR (NOT a JPEG/TIFF
  // scan: Perl reaches the JPEG/TIFF branch only as the `else` of
  // `elsif ($recognizedExt)`).
  SeqCase {
    name: "x.dir",
    head: &[1, 2, 3, 4],
    seq: &["WV", "7Z", "PFM2", "ISO", "PCD", "DIR"],
    term: None,
  },
  // dotless name, junk bytes: no ext => @fileTypes scan, fall-through set.
  SeqCase {
    name: "nodot",
    head: &[0u8; 32],
    seq: &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    term: None,
  },
  // empty name + empty head: no ext => @fileTypes scan; TXT matches empty.
  SeqCase {
    name: "",
    head: b"",
    seq: &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD", "TXT"],
    term: None,
  },
];

#[test]
fn detection_candidates_matches_injected_perl_extractinfo_sequence_oracle() {
  for c in SEQ_ORACLE {
    let got: Vec<DetectionCandidate> = detection_candidates(c.name, c.head).collect();
    // The non-terminal candidate type list, in order.
    let n = got.len();
    let term_count = usize::from(c.term.is_some());
    let body_types: Vec<&str> = got
      .iter()
      .take(n.saturating_sub(term_count))
      .map(DetectionCandidate::file_type)
      .collect();
    assert_eq!(
      body_types, c.seq,
      "ordered candidate sequence for {:?}",
      c.name
    );
    // Every non-terminal candidate has skip 0 / not after-unknown-header.
    for d in got.iter().take(n.saturating_sub(term_count)) {
      assert_eq!(d.header_skip(), 0, "non-terminal skip for {:?}", c.name);
      assert!(
        !d.after_unknown_header(),
        "non-terminal after_unknown_header for {:?}",
        c.name
      );
    }
    // The optional JPEG/TIFF terminal: type + skip + after_unknown_header.
    match (&c.term, got.last()) {
      (Some(t), Some(last)) => {
        assert_eq!(last.file_type(), t.ty, "terminal type {:?}", c.name);
        assert_eq!(
          last.header_skip(),
          t.skip,
          "terminal header_skip {:?}",
          c.name
        );
        assert!(
          last.after_unknown_header(),
          "terminal after_unknown_header {:?}",
          c.name
        );
      }
      (None, _) => {} // no JPEG/TIFF terminal expected
      (Some(_), None) => {
        panic!("{:?}: expected a JPEG/TIFF terminal, got empty", c.name)
      }
    }
  }
}

/// The exact defect being fixed: a spoofed `x.flv` whose bytes are NOT FLV
/// must NOT yield FLV as a candidate. Pre-fix the finalizing API returned the
/// first gate-passer; now it is a faithful ordered candidate sequence and a
/// gated-out type is simply absent.
#[test]
fn spoofed_extension_is_not_a_candidate() {
  // Real FLV bytes under x.flv => FLV is the FIRST candidate (gate passes).
  let real: Vec<&str> = detection_candidates("x.flv", b"FLV\x01\x05\0\0\0\x09\0\0\0\0")
    .map(|c| c.file_type())
    .collect();
  assert_eq!(real.first(), Some(&"FLV"), "real FLV is first candidate");

  // PNG bytes under x.flv: FLV magic gate fails => FLV is NEVER a
  // candidate; PNG appears (it is the GetFileType-less @fileTypes idx 10,
  // BEFORE the WV fall-through). The OLD finalizing API returned PNG; the
  // sequence simply must contain PNG and must NOT contain FLV.
  let spoof: Vec<&str> = detection_candidates("x.flv", PNG_HEAD)
    .map(|c| c.file_type())
    .collect();
  assert!(spoof.contains(&"PNG"), "PNG must be a candidate: {spoof:?}");
  assert!(
    !spoof.contains(&"FLV"),
    "FLV must NOT be a candidate: {spoof:?}"
  );
  // PNG must come before the WV fall-through (faithful @fileTypes order).
  let png_i = spoof.iter().position(|&t| t == "PNG").unwrap();
  let wv_i = spoof.iter().position(|&t| t == "WV").unwrap();
  assert!(png_i < wv_i, "PNG before WV in {spoof:?}");

  // get_file_type (name-only) STILL says FLV — proving the magic gate is
  // what removes FLV from the candidate sequence, not the lookup.
  assert_eq!(get_file_type("x.flv").unwrap().primary_type(), "FLV");
}

/// `detection_candidates` is panic-free for any name/head, including empty,
/// all-zero, 1-byte, dotless, and non-ASCII/unicode names; it always returns
/// a real, fully-consumable iterator.
#[test]
fn detection_candidates_is_panic_free_on_degenerate_input() {
  let inputs: &[(&str, &[u8])] = &[
    ("", b""),
    ("", &[0]),
    ("x", b""),
    (".", b""),
    ("..", b""),
    ("x.", b""),
    (".flv", b""),
    ("name.with.many.dots.png", PNG_HEAD),
    ("x.\u{1f600}", &[0xff, 0xd8, 0xff]),
    ("\u{1f600}.\u{1f600}", &[0xff, 0xd8, 0xff]),
    ("nodot", &[0u8; 4096]),
    ("x.unknownext", &[0xff; 1024]),
  ];
  for &(n, h) in inputs {
    // Must not panic; fully drain the iterator (exercises ExactSize/Fused).
    let it = detection_candidates(n, h);
    let (lo, hi) = it.size_hint();
    let v: Vec<_> = it.collect();
    assert_eq!(lo, v.len());
    assert_eq!(hi, Some(v.len()));
  }
}

/// Unit test of the JPEG/TIFF "scan past unknown header" tail in ISOLATION
/// (`scan_jpeg_tiff`), the Perl `/(\xff\xd8\xff|MM\0\x2a|II\x2a\0)/g` with
/// `skip = pos - length($1)`. This is the `''` end-of-list terminal's
/// `else`-branch; the public `detection_candidates` sequence oracle above
/// already exercises it end-to-end as the final candidate (e.g.
/// `junkjpeg.dat => ..., JPEG@skip16`), so this just pins the primitive.
#[test]
fn jpeg_tiff_tail_scan_logic() {
  // JPEG marker at offset 0 => ("JPEG", len 3, end 3) => skip 0.
  assert_eq!(scan_jpeg_tiff(b"\xff\xd8\xffrest"), Some(("JPEG", 3, 3)));
  // JPEG marker after a 16-byte header => skip 16 (Perl pos-len(marker)).
  let h = b"0123456789abcdef\xff\xd8\xffjpeg";
  let (t, ml, end) = scan_jpeg_tiff(h).unwrap();
  assert_eq!(t, "JPEG");
  assert_eq!(end - ml, 16, "skip = pos - length(marker)");
  // TIFF II at offset 8 => ("TIFF", 4, 12) => skip 8.
  assert_eq!(scan_jpeg_tiff(b"ABCDEFGHII\x2a\0xx"), Some(("TIFF", 4, 12)));
  // TIFF MM big-endian.
  assert_eq!(scan_jpeg_tiff(b"junkMM\0\x2a"), Some(("TIFF", 4, 8)));
  // Leftmost / earliest position wins (JPEG before a later TIFF).
  assert_eq!(
    scan_jpeg_tiff(b"..\xff\xd8\xff..MM\0\x2a"),
    Some(("JPEG", 3, 5))
  );
  // None when neither marker present, and on empty.
  assert_eq!(scan_jpeg_tiff(b"no markers here at all"), None);
  assert_eq!(scan_jpeg_tiff(b""), None);
  // This `skip = pos - len(marker)` value is exactly what
  // `detection_candidates` puts in the terminal `DetectionCandidate`'s
  // `header_skip` (with `after_unknown_header == true`); the public
  // sequence oracle above asserts that end-to-end (`junkjpeg.dat`/
  // `junktiff.bin` terminals carry skip 16 / 8).
}

/// `DetectionCandidate`'s public accessors are `const fn`, `#[must_use]`, and
/// report the candidate cleanly (D8/D9). The struct has only private fields
/// and is constructed solely inside `detection_candidates`; the iterator type
/// is a real `Iterator` (+ `ExactSizeIterator` + `FusedIterator`). Verify the
/// accessor + iterator contract through that single public entry point.
#[test]
fn detection_candidate_accessor_contract() {
  let mut it = detection_candidates("x.flv", b"FLV\x01\x05\0\0\0\x09\0\0\0\0");
  // It IS an Iterator (and ExactSize / Fused).
  let _: &dyn Iterator<Item = DetectionCandidate> = &it;
  let d = it.next().expect("at least one candidate (FLV)");
  let _: &'static str = d.file_type(); // &'static, not borrowed-from-d
  assert_eq!(d.file_type(), "FLV"); // real FLV bytes => FLV is first
  assert_eq!(d.header_skip(), 0);
  assert!(!d.after_unknown_header());
  // FIX 4 (D10 r10): non-`TIFF` candidate => Parent == the type itself
  // (ExifTool.pm:3038 `($type eq 'TIFF') ? $tiffType : $type`).
  assert_eq!(d.parent_type(), "FLV");
  assert_eq!(d, d.clone()); // Clone + PartialEq (derive_more-free struct)
                            // Remaining candidates are the faithful WV.. fall-through (non-empty,
                            // fully drainable — FusedIterator stays None after exhaustion).
  let rest: Vec<&str> = it.by_ref().map(|c| c.file_type()).collect();
  assert_eq!(
    rest,
    &["WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"]
  );
  assert!(it.next().is_none());
  assert!(it.next().is_none()); // fused
}

/// FIX 4 (D10 r10): `DetectionCandidate::parent_type` is ExifTool's
/// `$dirInfo{Parent}` (ExifTool.pm:3038): `($type eq 'TIFF') ? $tiffType :
/// $type`, where `$tiffType` is `$$self{FILE_EXT}` =
/// `GetFileExtension($realname)` on the non-empty-`@fileTypeList` branch
/// (ExifTool.pm:2965,2984) or the literal `'TIFF'` on the empty/full-scan
/// branch (ExifTool.pm:2992). Verified against the bundled Perl ExifTool:
///
///   perl -Ilib -MImage::ExifTool=GetFileType -e '... GetFileType($f) ...'
///   x.cr2/x.dng/x.nef  list=[TIFF]       FILE_EXT=CR2/DNG/NEF
///   x.fff              list=[TIFF FLIR]  FILE_EXT=FFF
///   x.raw              list=[RAW TIFF]   FILE_EXT=RAW
///   x.tif              list=[TIFF]       FILE_EXT=TIFF  (TIF->TIFF)
///   blob/junktiff.bin  list=[]           => $tiffType='TIFF' (L2992)
///   RAW (dotless)      list=[RAW TIFF]   FILE_EXT=undef => $tiffType=undef
///
/// so a `TIFF` candidate's Parent is the uppercased ext when candidates were
/// produced (`"CR2"`, `"FFF"`, `"RAW"`, `"TIFF"`), `"TIFF"` on the full-scan
/// branch, and `""` for a dotless name (Perl `$$self{FILE_EXT}` undef);
/// every non-`TIFF` candidate's Parent is its own `file_type()`.
#[test]
fn detection_candidate_parent_type_matches_exiftool_dirinfo_parent() {
  // TIFF little-endian header so the TIFF magic gate matches.
  let tiff_le: &[u8] = b"II\x2a\x00\x08\x00\x00\x00";

  // (a) Raw extensions whose ONLY candidate is TIFF: that TIFF candidate's
  //     Parent == the uppercased extension (ExifTool.pm:2984), NOT "TIFF".
  for (name, ext) in [("x.cr2", "CR2"), ("x.dng", "DNG"), ("x.nef", "NEF")] {
    let v: Vec<_> = detection_candidates(name, tiff_le).collect();
    let tiff = v
      .iter()
      .find(|c| c.file_type() == "TIFF")
      .unwrap_or_else(|| panic!("{name}: expected a TIFF candidate"));
    assert_eq!(
      tiff.parent_type(),
      ext,
      "{name}: TIFF candidate Parent == uppercased ext"
    );
    // Every non-TIFF candidate's Parent == its own file_type().
    for c in v.iter().filter(|c| c.file_type() != "TIFF") {
      assert_eq!(
        c.parent_type(),
        c.file_type(),
        "{name}: non-TIFF {} Parent == type",
        c.file_type()
      );
    }
  }

  // (b) x.fff => candidates [TIFF, FLIR]: the TIFF candidate's Parent is the
  //     ext "FFF"; the FLIR (non-TIFF) candidate's Parent is "FLIR".
  let fff: Vec<_> = detection_candidates("x.fff", tiff_le).collect();
  let fff_tiff = fff.iter().find(|c| c.file_type() == "TIFF").expect("TIFF");
  assert_eq!(fff_tiff.parent_type(), "FFF");
  if let Some(flir) = fff.iter().find(|c| c.file_type() == "FLIR") {
    assert_eq!(flir.parent_type(), "FLIR", "non-TIFF FLIR Parent == type");
  }

  // (c) x.raw => candidates [RAW, TIFF]: RAW Parent "RAW"; TIFF Parent the
  //     ext "RAW" (NOT "TIFF" — candidates were produced, L2984).
  let raw: Vec<_> = detection_candidates("x.raw", tiff_le).collect();
  let raw_raw = raw.iter().find(|c| c.file_type() == "RAW").expect("RAW");
  let raw_tiff = raw.iter().find(|c| c.file_type() == "TIFF").expect("TIFF");
  assert_eq!(raw_raw.parent_type(), "RAW");
  assert_eq!(
    raw_tiff.parent_type(),
    "RAW",
    "TIFF Parent == ext, not 'TIFF'"
  );

  // (d) x.tif => candidate [TIFF]; GetFileExtension TIF->TIFF so Parent
  //     happens to be "TIFF" (the ext), still the L2984 path not L2992.
  let tif: Vec<_> = detection_candidates("x.tif", tiff_le).collect();
  assert_eq!(
    tif
      .iter()
      .find(|c| c.file_type() == "TIFF")
      .unwrap()
      .parent_type(),
    "TIFF"
  );

  // (e) Full-scan (no recognized ext => empty candidate list): a TIFF
  //     candidate that arises gets Parent "TIFF" (ExifTool.pm:2992
  //     `$tiffType = 'TIFF'`). `blob` has no '.'; `junktiff.bin` has an
  //     unrecognized ext (BIN) => both take the empty-list branch.
  let blob: Vec<_> = detection_candidates("blob", tiff_le).collect();
  assert_eq!(
    blob
      .iter()
      .find(|c| c.file_type() == "TIFF")
      .unwrap()
      .parent_type(),
    "TIFF",
    "full-scan TIFF candidate Parent == 'TIFF'"
  );

  // (f) JPEG/TIFF unknown-header TERMINAL: ExifTool.pm:3038 applies to the
  //     terminal $type too. junktiff.bin's terminal is a TIFF@skip8 found by
  //     the scan; empty-list branch => $tiffType='TIFF' => Parent "TIFF".
  let jt: Vec<_> = detection_candidates("junktiff.bin", b"ABCDEFGHII\x2a\x00rest").collect();
  let term = jt.last().expect("a terminal candidate");
  assert_eq!(term.file_type(), "TIFF");
  assert!(
    term.after_unknown_header(),
    "terminal is the header-skip scan"
  );
  assert_eq!(
    term.header_skip(),
    8,
    "skip = pos - len(marker) (unchanged)"
  );
  assert_eq!(term.parent_type(), "TIFF", "TIFF terminal Parent == 'TIFF'");

  // A JPEG terminal (non-TIFF) => Parent "JPEG" (== file_type), unchanged.
  let jpg: Vec<_> = detection_candidates("x.jpg", b"\xff\xd8\xff\xe0\0\x10JFIF").collect();
  let jterm = jpg.last().expect("JPEG terminal");
  assert_eq!(jterm.file_type(), "JPEG");
  assert!(jterm.after_unknown_header());
  assert_eq!(jterm.parent_type(), "JPEG");

  // (g) Dotless name WITH candidates ([RAW, TIFF] for "RAW"): Perl
  //     `$$self{FILE_EXT}` = GetFileExtension("RAW") = undef => $tiffType
  //     undef => a TIFF candidate's Parent is "" (faithfully reproduced).
  let dotless: Vec<_> = detection_candidates("RAW", tiff_le).collect();
  assert_eq!(
    dotless
      .iter()
      .find(|c| c.file_type() == "RAW")
      .unwrap()
      .parent_type(),
    "RAW"
  );
  assert_eq!(
    dotless
      .iter()
      .find(|c| c.file_type() == "TIFF")
      .unwrap()
      .parent_type(),
    "",
    "dotless-name TIFF candidate Parent == \"\" (Perl FILE_EXT undef)"
  );
}

/// FIX 4 (D10 r10): adding `parent_type` must NOT change the candidate
/// ORDERING/algorithm. Re-assert every `SEQ_ORACLE` body sequence + terminal
/// (the prior independent injected-Perl ExtractInfo oracle) is byte-identical
/// — i.e. `file_type()`/`header_skip()`/`after_unknown_header()` are
/// unchanged; only the new `parent_type()` accessor was added. (The
/// authoritative oracle test
/// `detection_candidates_matches_injected_perl_extractinfo_sequence_oracle`
/// still runs unmodified; this is an explicit no-regression guard tied to
/// FIX 4.)
#[test]
fn parent_type_addition_does_not_change_candidate_ordering() {
  for c in SEQ_ORACLE {
    let got: Vec<DetectionCandidate> = detection_candidates(c.name, c.head).collect();
    let term_count = usize::from(c.term.is_some());
    let n = got.len();
    let body: Vec<&str> = got
      .iter()
      .take(n.saturating_sub(term_count))
      .map(DetectionCandidate::file_type)
      .collect();
    assert_eq!(body, c.seq, "ordering unchanged for {:?}", c.name);
    if let (Some(t), Some(last)) = (&c.term, got.last()) {
      assert_eq!(last.file_type(), t.ty, "terminal type {:?}", c.name);
      assert_eq!(last.header_skip(), t.skip, "terminal skip {:?}", c.name);
      assert!(last.after_unknown_header(), "terminal auh {:?}", c.name);
    }
    // And every candidate now also exposes a Parent consistent with the
    // L3038 rule (non-TIFF == its own type; only TIFF may differ).
    for d in &got {
      if d.file_type() != "TIFF" {
        assert_eq!(
          d.parent_type(),
          d.file_type(),
          "{:?}: non-TIFF Parent == type",
          c.name
        );
      }
    }
  }
}

/// FIX B (D10 r3): `file_types_static` resolves a runtime type/ext string to
/// its canonical interned `&'static`; only `@fileTypes` members + the single
/// `recognizedExt`-eligible non-@fileTypes type `DIR` resolve.
#[test]
fn file_types_static_coverage() {
  for t in [
    "JPEG", "PNG", "RIFF", "FLV", "MXF", "DV", "WV", "MP3", "TXT", "AAC",
  ] {
    assert_eq!(file_types_static(t), Some(t), "{t} must intern");
  }
  // DIR is the only %fileTypeLookup ''/0-moduleName + no-magic ext, and is
  // NOT in @fileTypes, but must still resolve (recognizedExt end-branch).
  assert_eq!(file_types_static("DIR"), Some("DIR"));
  // Non-types resolve to None.
  assert_eq!(file_types_static("zzz-not-a-type"), None);
  assert_eq!(file_types_static("THATSTRING"), None);
  assert_eq!(file_types_static(""), None);
}

// ===========================================================================
// D10 r5: TEST_LEN cap — detection_candidates must see only head[..1024]
// ===========================================================================
//
// ExifTool reads exactly $testLen = 1024 bytes into its magic-test buffer
// (ExifTool.pm:922,3003). All %magicNumber tests and the JPEG/TIFF end-marker
// scan operate on that ≤1024-byte window. Passing a longer slice to
// detection_candidates must not expose markers or bytes beyond offset 1023.
//
// Oracle: the capped Perl oracle (/tmp/exifast_oracle/run_capped.pl) applies
// substr($buff, 0, $testLen) before calling _ExifastSelectSeq, exactly
// mirroring ExifTool's $raf->Read($buff,$testLen). All expected sequences
// below are verbatim from that oracle.

/// JPEG marker placed AFTER offset 1024 (byte 1100): ExifTool's 1024-byte cap
/// means the JPEG marker is never seen → the terminal is NOT a JPEG candidate.
/// Uncapped behavior would yield a JPEG terminal at skip=1100.
/// Perl capped oracle output: [WV, 7Z, PFM2, ISO, MP3, PCD]  (no terminal)
/// Perl uncapped oracle output: [WV, 7Z, PFM2, ISO, MP3, PCD, JPEG\t1100\t1]
#[test]
fn cap_late_jpeg_marker_beyond_1024_not_seen() {
  // 1100 zero bytes, then JPEG SOI marker, then more zeros — total 1203 bytes.
  let mut head = vec![0x00u8; 1100];
  head.extend_from_slice(b"\xff\xd8\xff");
  head.extend(vec![0x00u8; 100]);
  assert!(head.len() > 1024);

  // With cap: the JPEG marker is beyond the 1024-byte window → not found.
  let capped: Vec<DetectionCandidate> = detection_candidates("late.dat", &head).collect();
  let capped_types: Vec<&str> = capped.iter().map(DetectionCandidate::file_type).collect();
  // Perl capped oracle: no JPEG terminal.
  assert_eq!(
    capped_types,
    &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    "capped: late JPEG marker must not appear in candidates"
  );
  assert!(
    !capped.iter().any(|c| c.after_unknown_header()),
    "capped: no after_unknown_header candidate expected"
  );

  // Prove the pre-cap (uncapped) behavior would have differed: the raw
  // scan_jpeg_tiff on the full buffer DOES find the JPEG marker.
  let full_scan = scan_jpeg_tiff(&head);
  assert!(
    full_scan.is_some(),
    "uncapped scan_jpeg_tiff finds the marker in the full buffer"
  );
  let (ty, _ml, end) = full_scan.unwrap();
  assert_eq!(ty, "JPEG");
  assert_eq!(end - 3, 1100, "marker at offset 1100 in full buffer");
}

/// Text content where the ONLY non-ASCII byte is at offset 1024 (the 1025th
/// byte). ExifTool's 1024-byte cap means the TXT magic test sees only 1024
/// clean ASCII bytes → TXT passes. Without the cap the null byte at offset
/// 1024 would fail TXT magic and TXT would be absent from the sequence.
/// Perl capped oracle output: [TXT, WV, MXF, DV, 7Z, PFM2, ISO, MP3, PCD]
/// Perl uncapped oracle output: [WV, MXF, DV, 7Z, PFM2, ISO, MP3, PCD]  (no TXT)
#[test]
fn cap_text_binary_past_1024_txt_candidate_present() {
  // Exactly 1024 ASCII 'A' bytes, then a NUL byte, then more ASCII — 1100 total.
  let mut head = vec![b'A'; 1024];
  head.push(0x00);
  head.extend(vec![b'A'; 75]);
  assert_eq!(head.len(), 1100);

  // With cap: only the 1024 'A' bytes are tested → TXT magic passes.
  let capped_types: Vec<&str> = detection_candidates("late.txt", &head)
    .map(|c| c.file_type())
    .collect();
  // Perl capped oracle: TXT is present (first gate-passer for .txt ext).
  assert_eq!(
    capped_types,
    &["TXT", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    "capped: TXT must be a candidate when null is beyond byte 1024"
  );

  // Prove pre-cap behavior would have differed: TXT magic on the full buffer
  // fails (the NUL at offset 1024 is a binary byte).
  assert_eq!(
    magic("TXT", &head),
    Magic::NoMatch,
    "uncapped: TXT magic fails on full buffer containing NUL"
  );
  // And the uncapped detection_candidates would omit TXT:
  // (We simulate "uncapped" by passing the raw full buffer to magic directly;
  //  the actual pre-fix code path used head directly without the cap.)
  assert!(
    magic("TXT", &head).is_no_match(),
    "uncapped full-buffer TXT check confirms the pre-fix divergence"
  );
}

/// Boundary: head is exactly TEST_LEN (1024) bytes — capped and uncapped are
/// identical (no bytes beyond the window). Assert same result either way.
/// Perl capped oracle output: [TXT, WV, MXF, DV, 7Z, PFM2, ISO, MP3, PCD]
#[test]
fn cap_boundary_exact_1024_unchanged() {
  let head = vec![b'A'; 1024];
  assert_eq!(head.len(), 1024);

  let seq: Vec<&str> = detection_candidates("boundary.txt", &head)
    .map(|c| c.file_type())
    .collect();
  // Perl capped oracle (same as uncapped at this length):
  assert_eq!(
    seq,
    &["TXT", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    "boundary at 1024: TXT is a candidate"
  );
}

/// Boundary: head is exactly 1025 bytes of all-printable ASCII. The 1025th
/// byte is also 'A' so both capped and uncapped TXT magic pass — the result
/// is identical. This confirms the cap does not corrupt the ≤1024 case.
/// Perl capped oracle output: [TXT, WV, MXF, DV, 7Z, PFM2, ISO, MP3, PCD]
#[test]
fn cap_boundary_1025_all_printable_unchanged() {
  let head = vec![b'A'; 1025];
  assert_eq!(head.len(), 1025);

  let seq: Vec<&str> = detection_candidates("just_over.txt", &head)
    .map(|c| c.file_type())
    .collect();
  // Perl capped oracle (same as uncapped: 1025th byte is also 'A'):
  assert_eq!(
    seq,
    &["TXT", "WV", "MXF", "DV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    "1025 all-printable: TXT still a candidate (cap doesn't corrupt)"
  );
}

/// FIX B: spot-check `module_for_type` for the absent-vs-explicit cases the
/// task calls out (mirrors Perl `$module = $type unless defined $module`).
#[test]
fn module_for_type_fix_b_spotcheck() {
  use std::borrow::Cow;
  // ABSENT from %moduleName (ExifTool.pm:853-918) => Module(Cow::Owned(type))
  // == Perl `$module = $type`. EXE/ZIP/AAC/RIFF appear only in
  // %fileTypeLookup/%magicNumber, never in %moduleName.
  for t in ["EXE", "ZIP", "AAC", "RIFF"] {
    assert_eq!(
      module_for_type(t),
      ModuleName::Module(Cow::Owned(t.to_string())),
      "{t}: absent => Module(type)"
    );
  }
  // PRESENT-and-truthy entries borrow their &'static module name:
  // FLV='Flash' (ExifTool.pm:878), WV='WavPack' (917).
  assert_eq!(
    module_for_type("FLV"),
    ModuleName::Module(Cow::Borrowed("Flash"))
  );
  assert_eq!(
    module_for_type("WV"),
    ModuleName::Module(Cow::Borrowed("WavPack"))
  );
  // Core / Unsupported explicit entries.
  assert!(module_for_type("JPEG").is_core());
  assert!(module_for_type("TIFF").is_core());
  assert!(module_for_type("EXIF").is_core());
  assert!(module_for_type("EXV").is_core());
  assert!(module_for_type("AVC").is_unsupported());
  assert!(module_for_type("ALIAS").is_unsupported());
  assert!(module_for_type("BZ2").is_unsupported());
  // Never-listed free-form string => Module(Cow::Owned("THATSTRING")).
  assert_eq!(
    module_for_type("THATSTRING"),
    ModuleName::Module(Cow::Owned("THATSTRING".to_string()))
  );
}

// ===========================================================================
// D10 r6: Unsupported (%moduleName == '0') magic match is terminal.
// ===========================================================================
//
// ExifTool ExtractInfo loop (ExifTool.pm:~3046-3058):
//   my $module = $moduleName{$type};
//   $module = $type unless defined $module;
//   if ($module) { ... require/dispatch ... }
//   elsif ($module eq '0') {
//       $self->SetFileType(); $self->Warn('Unsupported file type'); last;
//   }
// When a gate-passing type has %moduleName{type} eq '0' (Unsupported),
// ExifTool stops the ENTIRE candidate loop: no later @fileTypes candidates
// are tried and the '' end-of-list terminal (recognizedExt / JPEG-TIFF scan)
// is never reached.
//
// ORACLE: Perl simulation with the '0'=>last branch modelled.
// Unsupported types with %magicNumber entries (confirmed from ExifTool.pm:
// 853-920 + 928-1047): ALIAS, AVC, BZ2, DCX, DEX, DWF, DWG, DXF, LRI, PHP,
// TAR, WMF.  DIR is the ONLY '0' type with NO %magicNumber entry.
//
// KEY: DIR appears only via the recognizedExt terminal (post-loop, not
// affected by this fix). x.dir behavior is UNCHANGED by this fix.
//
// No-regression: every type in the pre-existing SEQ_ORACLE suite
// (WV, 7Z, PFM2, ISO, MP3, PCD, RIFF, PNG, TXT, MXF, DV, DIR, JPEG, TIFF,
// FLV, MKV, AAC) has module_for_type != Unsupported in the main loop;
// only DIR is Unsupported, and it enters only via the recognizedExt path
// (post-loop), so no prior case is affected.

/// Unsupported types (ExifTool `%moduleName eq '0'`) that have a
/// `%magicNumber` entry (confirmed against ExifTool.pm:928-1047).
/// A type NOT in this list (e.g. DIR) has NO magic entry — it can only
/// appear via the `recognizedExt` terminal, never the main loop.
#[test]
fn unsupported_types_with_magic_are_known() {
  let types_with_magic = [
    "ALIAS", "AVC", "BZ2", "DCX", "DEX", "DWF", "DWG", "DXF", "LRI", "PHP", "TAR", "WMF",
  ];
  for ty in types_with_magic {
    assert!(
      module_for_type(ty).is_unsupported(),
      "{ty} must be Unsupported"
    );
    assert!(has_magic_number(ty), "{ty} must have a %magicNumber entry");
  }
  // DIR is '0' but has NO magic entry.
  assert!(module_for_type("DIR").is_unsupported());
  assert!(!has_magic_number("DIR"), "DIR has no %magicNumber entry");
}

/// AVC magic (`\+A\+V\+C\+`) — gate passes, AVC is Unsupported.
/// Oracle (Perl, no ext): sequence [WV, 7Z, AVC], loop stops, NO terminal.
/// WV (idx 21) and 7Z (idx 63) are no-magic/truthy-module pass-throughs;
/// AVC (idx 73) passes its magic gate and is terminal.
#[test]
fn unsupported_avc_magic_is_terminal() {
  // +A+V+C+ with a NUL byte to prevent TXT magic matching (TXT matches
  // all-printable; the NUL makes it a binary buffer so TXT is gated out).
  let head: &[u8] = b"+A+V+C+\x00rest\x00\x00\x00\x00";

  // No extension: full @fileTypes scan, no recognized_ext.
  let seq: Vec<&str> = detection_candidates("avc_magic.dat", head)
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq,
    &["WV", "7Z", "AVC"],
    "AVC magic: oracle [WV,7Z,AVC], terminal=none (loop stopped)"
  );
  // No after_unknown_header candidate — the '' terminal was never reached.
  assert!(
    !detection_candidates("avc_magic.dat", head).any(|c| c.after_unknown_header()),
    "AVC magic: no JPEG/TIFF terminal (loop stopped before '' element)"
  );
  // x.avc gives None from get_file_type (AVC is Unsupported); empty
  // candidates => same full scan; recognized_ext NOT set (AVC has magic).
  let seq_ext: Vec<&str> = detection_candidates("x.avc", head)
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq_ext,
    &["WV", "7Z", "AVC"],
    "x.avc: same terminal sequence"
  );
}

/// ALIAS magic (`book\0\0\0\0mark\0\0\0\0`) — Unsupported, terminal.
/// Oracle (Perl, no ext): [WV, 7Z, PFM2, ISO, ALIAS].
/// PFM2 (idx 95) and ISO (idx 100) are no-magic pass-throughs that appear
/// between 7Z (63) and ALIAS (101); MP3 (104) / PCD (108) are AFTER ALIAS
/// and are never reached.
#[test]
fn unsupported_alias_magic_is_terminal() {
  let head: &[u8] = b"book\x00\x00\x00\x00mark\x00\x00\x00\x00more";

  let seq: Vec<&str> = detection_candidates("alias_magic.dat", head)
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq,
    &["WV", "7Z", "PFM2", "ISO", "ALIAS"],
    "ALIAS magic: oracle [WV,7Z,PFM2,ISO,ALIAS], terminal=none"
  );
  assert!(
    !detection_candidates("alias_magic.dat", head).any(|c| c.after_unknown_header()),
    "ALIAS magic: no JPEG/TIFF terminal"
  );
}

/// WMF magic (`\xd7\xcd\xc6\x9a\0\0`) — Unsupported, terminal.
/// Oracle (Perl, no ext): [WV, 7Z, WMF].
/// WMF is at @fileTypes index 72, just before AVC (73); WV and 7Z are the
/// only no-magic pass-throughs before it.
#[test]
fn unsupported_wmf_magic_is_terminal() {
  let head: &[u8] = b"\xd7\xcd\xc6\x9a\x00\x00more_data_here";

  let seq: Vec<&str> = detection_candidates("wmf_magic.dat", head)
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq,
    &["WV", "7Z", "WMF"],
    "WMF magic: oracle [WV,7Z,WMF], terminal=none"
  );
  assert!(
    !detection_candidates("wmf_magic.dat", head).any(|c| c.after_unknown_header()),
    "WMF magic: no JPEG/TIFF terminal"
  );
}

/// DCX magic (`\xb1\x68\xde\x3a`) — Unsupported, terminal.
/// Oracle (Perl, no ext): [WV, 7Z, DCX].
/// DCX is at @fileTypes index 84; no other magic-having types between 7Z and
/// DCX match these bytes.
#[test]
fn unsupported_dcx_magic_is_terminal() {
  let head: &[u8] = b"\xb1\x68\xde\x3a\x00\x01\x02\x03more";

  let seq: Vec<&str> = detection_candidates("dcx_magic.dat", head)
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq,
    &["WV", "7Z", "DCX"],
    "DCX magic: oracle [WV,7Z,DCX], terminal=none"
  );
  assert!(
    !detection_candidates("dcx_magic.dat", head).any(|c| c.after_unknown_header()),
    "DCX magic: no JPEG/TIFF terminal"
  );
}

/// Control: when an Unsupported type's magic does NOT match, the type is
/// NOT yielded and the loop continues normally.  A junk buffer `\x01\x02...`
/// does not match any Unsupported type's magic; the loop emits the full
/// no-magic fall-through set [WV, 7Z, PFM2, ISO, MP3, PCD] and then reaches
/// the '' terminal (no recognizedExt, JPEG/TIFF scan finds nothing → empty).
/// Oracle (Perl, no ext): [WV, 7Z, PFM2, ISO, MP3, PCD], no terminal.
#[test]
fn unsupported_magic_not_matching_loop_continues() {
  // All-junk buffer: no unsupported type's magic matches.
  let head: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  ];

  // No AVC magic in this buffer.
  assert_eq!(
    magic("AVC", head),
    Magic::NoMatch,
    "AVC magic must not match junk"
  );
  assert_eq!(
    magic("WMF", head),
    Magic::NoMatch,
    "WMF magic must not match junk"
  );

  let seq: Vec<&str> = detection_candidates("junk.dat", head)
    .map(|c| c.file_type())
    .collect();
  // Oracle: full fall-through set, no Unsupported type stops the loop.
  assert_eq!(
    seq,
    &["WV", "7Z", "PFM2", "ISO", "MP3", "PCD"],
    "junk: loop continues past all Unsupported types (none match)"
  );
  // No after_unknown_header either (no JPEG/TIFF marker in junk).
  assert!(
    !detection_candidates("junk.dat", head).any(|c| c.after_unknown_header()),
    "junk: no JPEG/TIFF terminal"
  );
}

/// No-regression: the x.dir case is UNCHANGED by the Unsupported-terminal
/// fix. DIR is `%moduleName eq '0'` (Unsupported) but has NO `%magicNumber`
/// entry — it is therefore SKIPPED in the main loop (else-branch: `defined
/// $moduleName{$type} and not $moduleName{$type}` => next). DIR appears only
/// as the `recognizedExt` terminal (the '' end-of-list element), which is
/// entirely outside the main loop and is NOT affected by the Unsupported-
/// terminal early-return. Oracle (unchanged): [WV,7Z,PFM2,ISO,PCD,DIR].
#[test]
fn x_dir_recognized_ext_terminal_unchanged() {
  // DIR has no magic entry: the main loop never reaches the module check.
  assert!(!has_magic_number("DIR"), "DIR has no %magicNumber entry");
  assert!(module_for_type("DIR").is_unsupported());

  // x.dir: get_file_type=None (DIR is Unsupported), ext="DIR",
  // !has_magic_number("DIR") && is_unsupported() => recognized_ext = "DIR".
  // Full @fileTypes scan; MP3 (weakMagic) skipped because recognized_ext set.
  // '' terminal => recognized_ext=DIR.
  let seq: Vec<&str> = detection_candidates("x.dir", &[1, 2, 3, 4])
    .map(|c| c.file_type())
    .collect();
  assert_eq!(
    seq,
    &["WV", "7Z", "PFM2", "ISO", "PCD", "DIR"],
    "x.dir: DIR is recognizedExt terminal, not a main-loop Unsupported stop"
  );
  // DIR terminal is NOT a JPEG/TIFF after-unknown-header candidate.
  let last = detection_candidates("x.dir", &[1, 2, 3, 4]).last().unwrap();
  assert_eq!(last.file_type(), "DIR");
  assert!(
    !last.after_unknown_header(),
    "DIR terminal is not after_unknown_header"
  );
  assert_eq!(last.header_skip(), 0);
}
