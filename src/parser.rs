//! The Phase-2 parser contract (spec D10(5)).
//!
//! Phase-1 `filetype::detection_candidates` only *selects* candidates
//! (spec D10(5)). ExifTool finalizes a type only when the candidate's
//! `Process<Type>` accepts the data (ExifTool.pm:3060-3077). A parser
//! therefore returns whether it accepted, exactly like Perl `ProcessAAC`
//! returning 0/1 (AAC.pm:99-139).
//!
//! ExifTool's `Process<Type>` calls `$et->SetFileType` itself (e.g.
//! `AAC.pm:107`) — the type-finalization is *parser-driven*, not done by
//! the caller. [`ParseContext`] gives the parser that capability faithfully:
//! it owns the `$et` value sink ([`ParseContext::metadata`]) and exposes
//! [`ParseContext::set_file_type`] (faithful `SetFileType`,
//! ExifTool.pm:9677-9706) and [`ParseContext::override_file_type`] (faithful
//! `OverrideFileType`, ExifTool.pm:9712-9730).

use crate::{
  convert::apply,
  filetype::detection_candidates,
  format_parser::any_parser_for,
  tagtable::{PrintConv, TagDef, ValueConv},
  value::TagValue,
};

/// ExifTool `$VERSION` (ExifTool.pm:32). The serializer's number gate
/// renders this string as the bare JSON number `13.58`.
const EXIFTOOL_VERSION: &str = "13.58";

/// `FileTypeExtension` has `PrintConv => 'lc $val'` (ExifTool.pm:1433):
/// lowercase with PrintConv on, raw (uppercase) under `-n`.
fn lc_print(v: &TagValue) -> TagValue {
  match v {
    TagValue::Str(s) => TagValue::Str(s.to_lowercase().into()),
    other => other.clone(),
  }
}
static FILE_TYPE_EXT: TagDef = TagDef::new(
  "FileTypeExtension",
  "File",
  ValueConv::None,
  PrintConv::Func(lc_print),
);

/// `%mimeType` (ExifTool.pm:616-847), the FULL 230-entry table. Ported
/// verbatim in [`crate::filetype::mime_type_lookup`] (mirrors the engine's
/// `%fileTypeLookup`/`%moduleName`/`%magicNumber` data-module precedent). A
/// TYPE absent yields `None` ⇒ Perl `$mimeType{$fileType}` is `undef`
/// (`SetFileType` then emits `'application/unknown'`, ExifTool.pm:9704).
/// Fan-out-ready: every ported format's `File:MIMEType` is now sourced from
/// the faithful full table, not a per-format private patch.
fn mime_type(file_type: &str) -> Option<&'static str> {
  crate::filetype::mime_type_lookup(file_type)
}

/// `%fileTypeExt` (ExifTool.pm:590-600), the FULL 9-entry table. Ported
/// verbatim in [`crate::filetype::file_type_ext_lookup`]. A TYPE absent
/// yields `None` ⇒ Perl `$normExt = $fileType` (ExifTool.pm:9698,9720).
fn file_type_ext(file_type: &str) -> Option<&'static str> {
  crate::filetype::file_type_ext_lookup(file_type)
}

/// Content-derived MIME override for an accepted typed Meta — the
/// post-finalize `$$self{VALUE}{MIMEType} = $mime` step that some
/// bundled-Perl parsers run AFTER `SetFileType` (Real.pm:653-657's
/// single-stream override; ExifTool.pm calls this an "in-place MIME
/// rewrite"). Returns `None` for Metas that have no such override.
///
/// Returning a fresh `String` (rather than borrowing from `meta`) lets
/// the engine drop the `AnyMeta` reference before the `obj.insert` call;
/// this keeps the function signature simple while paying one
/// allocation per override fire (only one or two formats use this).
#[cfg(feature = "json")]
fn meta_mime_override(meta: &crate::format_parser::AnyMeta<'_>) -> Option<String> {
  // Real (RM only): Real.pm:653-657 — overrides MIMEType to the lone
  // non-`logical-fileinfo` stream's MimeType. Other Metas do not
  // currently expose a MIME-override path.
  #[cfg(feature = "real")]
  if let crate::format_parser::AnyMeta::Real(m) = meta {
    return m.mime_override().map(str::to_string);
  }
  let _ = meta;
  None
}

/// The computed `File:*` triplet from a faithful `SetFileType` resolution —
/// the `(FileType, FileTypeExtension-shown, MIMEType)` values. `FileType` and
/// `MIMEType` are owned strings; `FileTypeExtension` is the post-`apply`
/// [`TagValue`] (uppercase stored, PrintConv `lc`, ExifTool.pm:1433).
struct FileTypeTriplet {
  file_type: String,
  file_type_extension: TagValue,
  mime_type: String,
}

/// The resolved `$fileType` NAME — the string ExifTool ultimately stores as
/// `File:FileType` (ExifTool.pm:9684-9692). It is the explicit `file_type` arg
/// (the `SetFileType($ft)` argument) or `base_type` when none, AFTER the
/// sub-type-by-ext promotion (ExifTool.pm:9686-9692). Borrows from its inputs
/// (no allocation, no `apply`), so it can be reused both by [`resolve_file_type`]
/// (which then resolves the MIME + extension triplet) and by
/// [`finalized_tiff_file_type`] (which needs ONLY the name to thread the
/// finalized `$$self{FILE_TYPE}` into the standalone-TIFF parse). This is the
/// computation that makes `File:FileType` and the threaded container type ONE
/// value — e.g. a `.crw`-named TIFF resolves to `"TIFF"` here (CRW's base module
/// is `CanonRaw`, not TIFF, and `"CRW"` has no `RAW` substring — see
/// [`finalized_tiff_file_type`]), never `"CRW"`.
fn resolved_file_type_name<'a>(
  base_type: &'a str,
  file_type: Option<&'a str>,
  ext: Option<&'a str>,
) -> &'a str {
  // ExifTool.pm:9684 `$fileType or $fileType = $baseType`.
  let mut ft: &str = file_type.unwrap_or(base_type);
  // ExifTool.pm:9686-9692 — handle sub-types identified by extension.
  if let Some(ext) = ext {
    if ext != ft {
      let f = crate::filetype::file_type_lookup_root(ft);
      let e = crate::filetype::file_type_lookup_root(ext);
      if let (Some(fr), Some(er)) = (f, e) {
        if fr == er && (fr == ft || !crate::filetype::file_type_lookup_defined(fr)) {
          ft = ext;
        }
      }
    }
  }
  ft
}

/// Pure `SetFileType` resolution (ExifTool.pm:9677-9706) — the COMPUTATION
/// half of [`ParseContext::set_file_type`], factored out so both the writer
/// path (legacy) and the typed serde path ([`extract_info`]) share ONE
/// faithful implementation. Given the detected `base_type` (`$$self{FILE_TYPE}`),
/// an optional explicit `file_type` (the `SetFileType($ft)` argument), the file
/// `ext` (`$$self{FILE_EXT}`), and `print_conv`, returns the resolved triplet.
///
/// Mirrors the body of `set_file_type` lines-for-line: the sub-type-by-ext
/// promotion (ExifTool.pm:9686-9692), the `$mimeType{$fileType}` lookup with
/// the base-type fallback excluding TIFF (ExifTool.pm:9693-9695), and the
/// `$fileTypeExt{$fileType}` / `$fileType` extension fallback
/// (ExifTool.pm:9696-9699).
fn resolve_file_type(
  base_type: &str,
  file_type: Option<&str>,
  ext: Option<&str>,
  print_conv: bool,
) -> FileTypeTriplet {
  // ExifTool.pm:9684-9692 — the resolved `$fileType` NAME (the explicit arg or
  // base, then the sub-type-by-ext promotion). Shared with the standalone-TIFF
  // dispatch so `File:FileType` and the threaded `$$self{FILE_TYPE}` agree.
  let ft: &str = resolved_file_type_name(base_type, file_type, ext);
  // ExifTool.pm:9693 `$mimeType or $mimeType = $mimeType{$fileType}`.
  let mut mime = mime_type(ft);
  // ExifTool.pm:9695 base-type MIME fallback (TIFF excluded).
  if mime.is_none() && base_type != "TIFF" {
    mime = mime_type(base_type);
  }
  // ExifTool.pm:9696-9699 extension fallback.
  let norm_ext = file_type_ext(ft).unwrap_or(ft);
  // ExifTool.pm:9703 FoundTag('FileTypeExtension', uc $normExt) + PrintConv lc.
  let file_type_extension = apply(
    &FILE_TYPE_EXT,
    &TagValue::Str(norm_ext.to_uppercase().into()),
    print_conv,
  );
  FileTypeTriplet {
    file_type: ft.to_string(),
    file_type_extension,
    mime_type: mime.unwrap_or("application/unknown").to_string(),
  }
}

/// Faithful `DoProcessTIFF` file-type finalization (ExifTool.pm:8685-8694) for
/// an accepted Exif/TIFF parse on the `Detected` path. `DoProcessTIFF` does
/// NOT call the bare `SetFileType()` — it computes a `$t` argument from the
/// directory's PARENT type and the TIFF/RAW base-type rule, then
/// `SetFileType($t)`:
/// ```text
/// my $fileType = $$dirInfo{Parent} || '';     # the candidate's Parent (8546)
/// ...
/// if ($fileType and not $$self{VALUE}{FileType}) {
///     my $lookup   = $fileTypeLookup{$fileType};                 # (alias-deref)
///     my $baseType = ...first module of $lookup, or '';
///     my $t = ($baseType eq 'TIFF' or $fileType =~ /RAW/) ? $fileType : undef;
///     $self->SetFileType($t);
/// }
/// ```
/// So a TIFF-backed SUBTYPE extension (`.fff`/`.3fr`/`.nef`/…) — whose
/// `Parent` is the uppercased extension and whose lookup root is `TIFF` (or
/// whose Parent matches `/RAW/`) — promotes `File:FileType` to that subtype,
/// NOT the literal `"TIFF"`. A plain `.tif` has `Parent == "TIFF"` (root
/// `TIFF`) ⇒ `$t = "TIFF"`; an embedded/dotless TIFF has `Parent == ""` ⇒ the
/// guard's `$fileType` is falsey ⇒ bundled never re-finalizes here, leaving
/// the detection-time `SetFileType()` (== bare detected `"TIFF"`).
///
/// `base_type` is `$$self{FILE_TYPE}` (the detection `$type`, always `"TIFF"`
/// for the standalone-TIFF dispatch); `parent_type` is the candidate's
/// `$dirInfo{Parent}` ([`crate::filetype::DetectionCandidate::parent_type`]).
#[cfg(feature = "exif")]
fn tiff_finalize_file_type(
  base_type: &str,
  parent_type: &str,
  ext: Option<&str>,
  print_conv: bool,
) -> FileTypeTriplet {
  // ExifTool.pm:8685-8690 `$t = ($baseType eq 'TIFF' or $fileType =~ /RAW/) ?
  // $fileType : undef` (the empty-Parent guard ⇒ `None`). ExifTool.pm:8693
  // `$self->SetFileType($t)` — `$$self{FILE_TYPE}` stays the detection `$type`
  // (`base_type`), the explicit arg is `$t`.
  let t = tiff_finalized_type_arg(parent_type);
  resolve_file_type(base_type, t, ext, print_conv)
}

/// The `$t` argument `DoProcessTIFF` feeds to `SetFileType` (ExifTool.pm:8685-
/// 8690) — the COMPUTATION shared by [`tiff_finalize_file_type`] (which then
/// resolves the full `File:*` triplet) and [`finalized_tiff_file_type`] (which
/// composes it with the ext promotion to get the finalized `$$self{FILE_TYPE}`
/// NAME). `None` for an empty `parent_type` (dotless / embedded TIFF — the
/// `if ($fileType ...)` guard at ExifTool.pm:8685 is false, so bundled never
/// re-finalizes, keeping the detection-time bare `"TIFF"`), or when the parent's
/// base module is not `TIFF` AND `parent_type` has no `RAW` substring; otherwise
/// `Some(parent_type)`. (Perl's `$baseType` here is the base MODULE of
/// `$fileType`==`parent_type`, computed below — NOT the outer detection
/// `$$self{FILE_TYPE}`.) Borrows `parent_type`.
#[cfg(feature = "exif")]
fn tiff_finalized_type_arg(parent_type: &str) -> Option<&str> {
  // ExifTool.pm:8685 `if ($fileType and ...)` — an empty Parent skips the
  // re-finalization (⇒ `$t` undef).
  if parent_type.is_empty() {
    return None;
  }
  // ExifTool.pm:8687-8689 `$baseType` = first module of `$fileType`'s row.
  let base_module = crate::filetype::file_type_base_module(parent_type);
  // ExifTool.pm:8690 `$t = ($baseType eq 'TIFF' or $fileType =~ /RAW/) ?
  // $fileType : undef`.
  if base_module == "TIFF" || parent_type.contains("RAW") {
    Some(parent_type)
  } else {
    None
  }
}

/// The FINALIZED `$$self{FILE_TYPE}` NAME for a standalone-TIFF parse — the
/// exact string [`extract_info`] emits as `File:FileType` (so the two never
/// diverge). It is [`resolved_file_type_name`] applied to the
/// [`tiff_finalized_type_arg`] `$t`: e.g. a plain `.tif` ⇒ `"TIFF"`, a TIFF-
/// rooted RAW subtype (`.nef`/`.cr2`/…) ⇒ that subtype (`"NEF"`/`"CR2"`/…), and
/// crucially a `.crw`-named TIFF ⇒ `"TIFF"` — because `CRW`'s base module is
/// `CanonRaw` (NOT `TIFF`) and `"CRW"` has no `RAW` substring, so
/// [`tiff_finalized_type_arg`] returns `None` ⇒ the name stays the detected
/// `base_type` (`"TIFF"`), never `"CRW"`.
///
/// This is the value the engine threads into the standalone-TIFF parse as the
/// container `$$self{FILE_TYPE}` (the `Canon::ShotInfo` pos-22 CRW-allows-0
/// RawConv, Canon.pm:2977/:2990, keys on it) — provably never `"CRW"` in the
/// port (there is no CIFF/CRW front-end, and `CRW` is never a TIFF-base/RAW
/// promotion), so the CRW branch stays correctly dead while the gate now checks
/// the RIGHT variable.
#[cfg(feature = "exif")]
pub(crate) fn finalized_tiff_file_type(
  base_type: &str,
  parent_type: &str,
  ext: Option<&str>,
) -> String {
  let t = tiff_finalized_type_arg(parent_type);
  resolved_file_type_name(base_type, t, ext).to_string()
}

/// Pure `OverrideFileType` resolution (ExifTool.pm:9712-9730) — the
/// COMPUTATION half of [`ParseContext::override_file_type`]. Returns the
/// `(FileType, FileTypeExtension-shown, Option<MIMEType>)` to overwrite in
/// place. `MIMEType` is `None` when no MIME is known for `file_type`
/// (ExifTool.pm:9724 `... if $mimeType` — leave the existing MIME unchanged).
fn resolve_override_file_type(
  file_type: &str,
  print_conv: bool,
) -> (String, TagValue, Option<String>) {
  // ExifTool.pm:9718-9720 extension fallback.
  let norm_ext = file_type_ext(file_type).unwrap_or(file_type);
  // ExifTool.pm:9723 `$mimeType or $mimeType = $mimeType{$fileType}`.
  let mime = mime_type(file_type).map(str::to_string);
  let file_type_extension = apply(
    &FILE_TYPE_EXT,
    &TagValue::Str(norm_ext.to_uppercase().into()),
    print_conv,
  );
  (file_type.to_string(), file_type_extension, mime)
}

/// Faithful `ConvertFileSize` (ExifTool.pm:6840-6860), default-units branch
/// only. The `ByteUnit eq 'Binary'` arm (ExifTool.pm:6843-6850) is gated on
/// the `ByteUnit` option, which the read path here does not expose (YAGNI;
/// consistent with the no-options deferrals) — so only the decimal `else`
/// (ExifTool.pm:6851-6859) is transliterated. Used solely for the
/// `'First <ConvertFileSize($num)> of file is …'` insight text
/// (ExifTool.pm:3109). Perl `sprintf("%.1f"/"%.0f", …)` rounds
/// half-to-even on the IEEE-754 quotients here, byte-identical to Rust's
/// `{:.1}`/`{:.0}` (verified against the bundled Perl across the kB/MB/GB
/// boundary inputs).
fn convert_file_size(val: u64) -> String {
  // ExifTool.pm:6852-6858 (the decimal `else` branch), exact thresholds.
  let v = val as f64;
  if val < 2000 {
    format!("{val} bytes") // ExifTool.pm:6852 "$val bytes"
  } else if val < 10000 {
    format!("{:.1} kB", v / 1000.0) // ExifTool.pm:6853
  } else if val < 2_000_000 {
    format!("{:.0} kB", v / 1000.0) // ExifTool.pm:6854
  } else if val < 10_000_000 {
    format!("{:.1} MB", v / 1_000_000.0) // ExifTool.pm:6855
  } else if val < 2_000_000_000 {
    format!("{:.0} MB", v / 1_000_000.0) // ExifTool.pm:6856
  } else if val < 10_000_000_000 {
    format!("{:.1} GB", v / 1_000_000_000.0) // ExifTool.pm:6857
  } else {
    format!("{:.0} GB", v / 1_000_000_000.0) // ExifTool.pm:6858
  }
}

/// Faithful post-loop error finalization (ExifTool.pm:3080-3128), the
/// "nothing was finalized" case. ExifTool computes `$err` only when
/// `not $err and not defined $type and not $$self{DOC_NUM}`
/// (ExifTool.pm:3080) — i.e. no parser accepted AND the unsupported
/// terminal (ExifTool.pm:3054-3057) did NOT fire AND no prior error (no
/// `DOC_NUM` on this read path). `data` is the file bytes (`$buff`/`$raf`).
///
/// `$buff` in the Perl block is the INITIAL `$raf->Read($buff, $testLen)`
/// (first ≤`TEST_LEN` bytes; the candidate loop seeks back to `$pos`=0 and
/// never re-reads `$buff`), so the `length $buff < 16` /
/// `$buff =~ /[^\Q$ch\E]/` tests are over `data[..min(len, TEST_LEN)]`.
/// The all-same-byte scan (ExifTool.pm:3102-3107, no FastScan ⇒ the scan
/// path) reads from file position 0 (RAF was reset after the testLen read)
/// in 64 KiB chunks; `$num` accumulates to the absolute 0-based offset of
/// the first byte ≠ `$ch`, or `undef` at EOF (whole file is `$ch`). Over
/// the full `data` slice that is exactly `data.iter().position(|b| b !=
/// ch)`. Returns the `$err` string, or `None` when `$err` stays unset.
fn finalization_error(name: &str, data: &[u8]) -> Option<String> {
  // ExifTool.pm:3084 `my $fileType = GetFileType($realname) || ''`.
  // `get_file_type` returns None for unrecognized OR unsupported types;
  // an unsupported type would have fired the terminal (we are only here
  // when it did not), so None ⇒ '' (falsy), Some ⇒ a known type (truthy).
  let known_type = crate::filetype::get_file_type(name);
  // ExifTool.pm:3085 `if (not length $buff)`.
  if data.is_empty() {
    return Some("File is empty".to_string()); // ExifTool.pm:3086
  }
  // PLIST.pm:494-499 — `$$et{FILE_EXT} eq 'PLIST'` and `^\xfe\xff\x00`: the
  // legacy UCS-2BE PLIST recognition arm of `ProcessPLIST`. Bundled emits
  // `$et->Error('Old PLIST format currently not supported')` with NO preceding
  // `SetFileType` (the branch never sets the file type, PLIST.pm:498-499 only
  // calls `Error` and `$result = 1`), so the resulting JSON carries
  // `ExifTool:Error` and NO `File:FileType` triplet (oracle-verified). In our
  // engine, `ProcessPlist::parse` returns `Ok(None)` for this input (XML and
  // binary gates both reject it), so the candidate loop exhausts without a
  // claim and lands here — short-circuit the `File format error` arm below
  // with bundled's exact wording. Routed at the finalization-error seam so the
  // engine's per-format dispatch needn't model a fourth `FileTypeFinalize` mode
  // (suppress-triplet), and faithful to PLIST.pm:494's `$$et{FILE_EXT} eq
  // 'PLIST'` guard (a non-`.plist` extension with the same magic would NOT
  // fire this branch in bundled).
  #[cfg(feature = "plist")]
  if crate::filetype::file_ext_for_name(name).as_deref() == Some("PLIST")
    && data.starts_with(&[0xfe, 0xff, 0x00])
  {
    return Some("Old PLIST format currently not supported".to_string());
  }
  // ExifTool.pm:3088 `my $ch = substr($buff, 0, 1)`.
  let ch = data[0];
  // ExifTool.pm:3003 `$raf->Read($buff, $testLen)` — `$buff` is the first
  // ≤ $testLen bytes; the < 16 / regex tests below are over THIS window.
  const TEST_LEN: usize = 1024; // ExifTool.pm:922 $testLen = 1024
  let buff = &data[..data.len().min(TEST_LEN)];
  // ExifTool.pm:3089 `if (length $buff < 16 or $buff =~ /[^\Q$ch\E]/)`.
  if buff.len() < 16 || buff.iter().any(|&b| b != ch) {
    // ExifTool.pm:3090-3096. `RAW` IS reachable (e.g. a `.raw` file resolves
    // via `%fileTypeLookup{RAW}` to the `RAW` type) and emits a distinct
    // string. Match Perl's ordered if/elsif/else so an unknown type still
    // falls to the final arm. Perl `$fileType eq 'RAW'` compares the
    // SCALAR-context `GetFileType($realname)` (ExifTool.pm:3084) — that is
    // `primary_type` (the un-promoted root type of a multi row, e.g. the
    // `.raw` lookup is a multi row whose primary is `"RAW"`).
    let is_raw = known_type
      .as_ref()
      .is_some_and(|f| f.primary_type() == "RAW");
    return Some(if is_raw {
      "Unsupported RAW file type".to_string() // ExifTool.pm:3091
    } else if known_type.is_some() {
      "File format error".to_string() // ExifTool.pm:3093
    } else {
      "Unknown file type".to_string() // ExifTool.pm:3095
    });
  }
  // ExifTool.pm:3097-3123: all-same-byte insight (buff ≥ 16 AND every
  // byte == $ch). No FastScan option on this path ⇒ the scan branch
  // (ExifTool.pm:3101-3113): `$num` = absolute offset of the first byte
  // ≠ $ch over the whole file, else undef (entire file is $ch).
  let mut err = match data.iter().position(|&b| b != ch) {
    // ExifTool.pm:3108-3109 `if ($num) { 'First '.ConvertFileSize($num).
    // ' of file is' }`. $num is this offset; it is ≥ TEST_LEN ≥ 16 here
    // (the prefix `data[..min(len,TEST_LEN)]` is all $ch), hence always
    // truthy — but the `else` still faithfully covers the `$num == 0`
    // case (a 0-offset diff is impossible: data[0] == ch by construction).
    Some(num) if num != 0 => format!("First {} of file is", convert_file_size(num as u64)),
    // ExifTool.pm:3110-3112 `else { 'Entire file is' }` (undef ⇒ EOF, the
    // whole file is $ch; or the vacuous $num == 0).
    _ => "Entire file is".to_string(),
  };
  // ExifTool.pm:3114-3122 the trailing insight suffix.
  if ch == b'\0' {
    err.push_str(" binary zeros"); // ExifTool.pm:3115
  } else if ch == b' ' {
    err.push_str(" ASCII spaces"); // ExifTool.pm:3117
  } else if ch.is_ascii_alphanumeric() {
    // ExifTool.pm:3118-3119 `$ch =~ /[a-zA-Z0-9]/ ⇒ " ASCII '${ch}'
    // characters"`. $ch is a single byte; ASCII-alnum is pure ASCII.
    err.push_str(&format!(" ASCII '{}' characters", ch as char));
  } else {
    // ExifTool.pm:3121 `sprintf(" binary 0x%.2x's", ord $ch)`.
    err.push_str(&format!(" binary 0x{ch:02x}'s"));
  }
  Some(err)
}

/// The `ExtractInfo` finalization consumer (spec D10(5);
/// ExifTool.pm:3060-3128): emit `ExifTool:ExifToolVersion`, then walk the
/// Phase-1 candidate iterator; the first candidate whose ported parser
/// accepts the data is finalized. The parser itself drives `SetFileType`
/// (ExifTool's `Process<Type>` calls `$et->SetFileType`, e.g. AAC.pm:107),
/// so the consumer only merges the accepted parser's tags/warnings.
///
/// If NOTHING was finalized — no parser accepted AND the unsupported
/// terminal (ExifTool.pm:3054-3057) did not fire — ExifTool's post-loop
/// block (ExifTool.pm:3080-3128) computes an `ExifTool:Error` (`File is
/// empty` / `File format error` / `Unknown file type` / an all-same-byte
/// insight). [`finalization_error`] is the faithful port; `$self->Error`
/// (ExifTool.pm:5648) ⇒ `m.push_error`.
/// `json`-gated: the rendered JSON output goes through `serde_json` (the `json`
/// feature). The serde-free engine tier still parses (`extract_info_to_writer`
/// collects the typed tag stream under `alloc`); only this terminal render
/// needs `json`.
#[cfg(feature = "json")]
#[must_use]
pub fn extract_info(name: &str, data: &[u8], print_conv_enabled: bool) -> String {
  // The unified typed path: detect → run the typed parse (complete `AnyMeta`
  // incl. chains) → emit the orchestration tags (`ExifTool:ExifToolVersion`,
  // `SourceFile`, the `File:*` triplet) → serde-render the whole document.
  // No `TagMap` collector; the typed `AnyMeta` IS the tag source.
  extract_info_typed(name, data, print_conv_enabled)
}

/// The typed-serde engine entry — `extract_info`'s implementation. Detects the
/// file type, runs the closed [`AnyParser::parse_any`] dispatch over the
/// `ExtractInfo` candidate loop (faithful to ExifTool.pm:3060-3128), finalizes
/// the accepted parser's `File:*` triplet via [`crate::format_parser::AnyMeta::finalize_file_type`],
/// and serde-renders the typed `AnyMeta`'s format tags + the orchestration
/// tags + the finalization `Warning`/`Error` into the `[{ … }]` document
/// (value-equivalent to bundled `perl exiftool -j -G1`).
///
/// `%noDups` first-wins (ExifTool.pm:2950-2951) is applied via insert-if-absent
/// into a `serde_json::Map`; `SourceFile` is first; `ExifTool:Warning` /
/// `ExifTool:Error` carry the FIRST of each (ExifTool.pm:1288-1297).
#[cfg(feature = "json")]
#[must_use]
fn extract_info_typed(name: &str, data: &[u8], print_conv_enabled: bool) -> String {
  use serde_json::{Map, Value};

  // The single per-file object. `%noDups` first-wins ⇒ insert-if-absent.
  let mut obj: Map<String, Value> = Map::new();
  let insert = |obj: &mut Map<String, Value>, key: String, value: Value| {
    obj.entry(key).or_insert(value);
  };
  // `SourceFile` first (ExifTool emits it before the per-tag loop; never deduped).
  obj.insert("SourceFile".into(), Value::String(name.to_string()));
  // Orchestration: `ExifTool:ExifToolVersion` (the number gate renders 13.58).
  insert(
    &mut obj,
    "ExifTool:ExifToolVersion".into(),
    serde_json::to_value(&TagValue::Str(EXIFTOOL_VERSION.into())).unwrap_or(Value::Null),
  );

  // ExifTool.pm:2966 `$$self{FILE_EXT} = GetFileExtension($realname)`.
  let file_ext = crate::filetype::file_ext_for_name(name);
  let ext_ref = file_ext.as_deref();

  // Diagnostics: the FIRST warning + FIRST error reach the document.
  let mut warning: Option<String> = None;
  let mut error: Option<String> = None;
  // `$$self{FILE_TYPE}` bookkeeping (ExifTool.pm:3080): set once finalized.
  let mut finalized = false;
  // Fresh per-candidate cross-format state (mirrors `parse_bytes`).
  let mut shared = crate::format_parser::SharedFlags::new();

  // ExifTool's `$$self{FILE_TYPE}` is whatever module FIRST claims the file —
  // the FIRST detection candidate (ExifTool.pm:3035-3045 `SetFileType` sets
  // FILE_TYPE on the first recognized type). The PLIST `XMLFileType=ModdXML`
  // override (PLIST.pm:136) is gated on `FILE_TYPE eq 'XMP'`: an XML plist
  // reached via an `.xml`-family extension (first candidate `XMP`), NOT via an
  // explicit `.plist`/`.modd` extension (first candidate `PLIST`).
  let file_type_is_xmp = detection_candidates(name, data)
    .next()
    .is_some_and(|c| c.file_type() == "XMP");

  for cand in detection_candidates(name, data) {
    let ft = cand.file_type();
    // ExifTool.pm:3035-3045 / XMP.pm:4369-4387 — the XMP module's content sniff
    // routes an XML `<plist>` (or `<!DOCTYPE plist>`) to `ProcessPLIST`. Bundled
    // reaches a UTF-8-BOM-prefixed XML plist ONLY this way: its XMP `%magicNumber`
    // (ExifTool.pm:1045 `…(\xef\xbb\xbf)?…\s*<`) accepts the BOM that the PLIST
    // `%magicNumber` (ExifTool.pm:1015 `(bplist0|\s*<|…)`) does not, so XMP is the
    // first/only candidate; `ProcessXMP` then `SetFileType('PLIST',
    // 'application/xml')` and hands the body to `PLIST::FoundTag`. This port has
    // no standalone XMP parser, so replicate that hop here: when the candidate is
    // `XMP` and the content is an XML `<plist>`, finalize as `PLIST` and dispatch
    // to `ProcessPlist`. `magic()` stays a faithful 1:1 of `%magicNumber` (the
    // PLIST gate is unchanged); the BOM tolerance lives only in this XMP→PLIST
    // route, exactly where bundled's lives. (A non-BOM XML plist is unaffected:
    // `ProcessPlist` accepts it here just as it did at the later PLIST candidate.)
    #[cfg(feature = "plist")]
    let ft = if ft == "XMP"
      && any_parser_for("XMP").is_none()
      && crate::formats::plist::xml_content_is_plist(data)
    {
      "PLIST"
    } else {
      ft
    };
    // ExifTool.pm:3046-3057 — recognized but UNSUPPORTED ⇒ SetFileType + Warn,
    // terminal (no parser runs, loop stops, post-loop Error suppressed).
    if crate::filetype::module_for_type(ft).is_unsupported() {
      let triplet = resolve_file_type(ft, None, ext_ref, print_conv_enabled);
      insert(
        &mut obj,
        "File:FileType".into(),
        Value::String(triplet.file_type),
      );
      insert(
        &mut obj,
        "File:FileTypeExtension".into(),
        serde_json::to_value(&triplet.file_type_extension).unwrap_or(Value::Null),
      );
      insert(
        &mut obj,
        "File:MIMEType".into(),
        Value::String(triplet.mime_type),
      );
      warning.get_or_insert_with(|| "Unsupported file type".to_string());
      finalized = true;
      break;
    }
    let Some(parser) = any_parser_for(ft) else {
      continue;
    };
    // Faithful closed-dispatch parse. The contract is `Option`: `Some(meta)`
    // is an accepted candidate, `None` is a rejection ("not this candidate").
    // `cand.header_skip()` is the unknown-leading-header byte count (Perl
    // `$skip`, `ExifTool.pm:3029`) for the terminal JPEG/TIFF candidate — `0`
    // for every ordinary candidate; the JPEG/TIFF arm slices `data` at it.
    let meta = match parser.parse_any(
      data,
      &mut shared,
      ext_ref,
      cand.header_skip(),
      Some(cand.parent_type()),
    ) {
      Some(meta) => meta,
      None => {
        // Rejected candidate: reset shared so partial side effects don't leak.
        shared = crate::format_parser::SharedFlags::new();
        continue;
      }
    };

    // ----- Unknown-leading-header reset (ExifTool.pm:3069-3073) -----------
    // The detector's terminal candidate scanned PAST an unknown `header_skip`-
    // byte header to find this JPEG/TIFF (`ExifTool.pm:3026-3034`). After the
    // parser succeeds, bundled `DeleteTag`s `FileType`, `FileTypeExtension`
    // AND `MIMEType` ("Reset file type due to unknown header") — so a
    // junk-prefixed JPEG/TIFF emits NO `File:*` triplet, only the recovered
    // tags and the detection-time `Warn`. The warning is raised at detection
    // (`ExifTool.pm:3033`), BEFORE the parser runs, so it precedes — and wins
    // over — any parser warning in the FIRST-warning `%noDups` slot.
    if cand.after_unknown_header() {
      warning.get_or_insert_with(|| {
        std::format!(
          "Processing {}-like data after unknown {}-byte header",
          ft,
          cand.header_skip()
        )
      });
    }

    // ----- Finalize File:* per the typed Meta's plan ---------------------
    // SKIPPED entirely after an unknown leading header — bundled deletes the
    // whole `File:*` triplet (above), so the engine simply never inserts it.
    use crate::format_parser::FileTypeFinalize;
    if !cand.after_unknown_header() {
      match meta.finalize_file_type() {
        FileTypeFinalize::Detected => {
          // The Exif/TIFF parser is `DoProcessTIFF`, which finalizes via
          // `SetFileType($t)` where `$t` is derived from the candidate's
          // PARENT type (ExifTool.pm:8685-8694) — so a TIFF-backed subtype
          // extension (`.fff`/`.3fr`/`.nef`/…) promotes to that subtype, not
          // the literal `"TIFF"`. Every OTHER `Detected` parser calls the bare
          // `SetFileType()` (no `$t`), and its candidate's `Parent` equals its
          // own type (`parent_of` differs from the type only for a `TIFF`
          // candidate), so the parent-aware path would be a faithful no-op for
          // them too — but routing it only through the Exif arm keeps the
          // TIFF/RAW-specific `$baseType` rule scoped to `DoProcessTIFF`.
          #[cfg(feature = "exif")]
          let t = if matches!(&meta, crate::format_parser::AnyMeta::Exif(_)) {
            tiff_finalize_file_type(ft, cand.parent_type(), ext_ref, print_conv_enabled)
          } else {
            resolve_file_type(ft, None, ext_ref, print_conv_enabled)
          };
          #[cfg(not(feature = "exif"))]
          let t = resolve_file_type(ft, None, ext_ref, print_conv_enabled);
          insert(&mut obj, "File:FileType".into(), Value::String(t.file_type));
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&t.file_type_extension).unwrap_or(Value::Null),
          );
          insert(&mut obj, "File:MIMEType".into(), Value::String(t.mime_type));
        }
        FileTypeFinalize::Explicit(set) => {
          let t = resolve_file_type(ft, Some(set), ext_ref, print_conv_enabled);
          insert(&mut obj, "File:FileType".into(), Value::String(t.file_type));
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&t.file_type_extension).unwrap_or(Value::Null),
          );
          insert(&mut obj, "File:MIMEType".into(), Value::String(t.mime_type));
        }
        FileTypeFinalize::DetectedThenOverride(target) => {
          // SetFileType() (detected) then OverrideFileType(target): the override
          // replaces FileType + FileTypeExtension in place, and MIMEType only
          // when known. Compose them: the override values win where present.
          let base = resolve_file_type(ft, None, ext_ref, print_conv_enabled);
          let (ov_ft, ov_ext, ov_mime) = resolve_override_file_type(target, print_conv_enabled);
          insert(&mut obj, "File:FileType".into(), Value::String(ov_ft));
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&ov_ext).unwrap_or(Value::Null),
          );
          insert(
            &mut obj,
            "File:MIMEType".into(),
            Value::String(ov_mime.unwrap_or(base.mime_type)),
          );
        }
        FileTypeFinalize::ExplicitThenLiteral(payload) => {
          // SetFileType(set) then raw-replace FileType value with `literal`; the
          // extension + MIME come from `set` (AIFF DjVu multi-page, AIFF.pm:206).
          let (set, literal) = (payload.set(), payload.literal());
          let t = resolve_file_type(ft, Some(set), ext_ref, print_conv_enabled);
          insert(
            &mut obj,
            "File:FileType".into(),
            Value::String(literal.to_string()),
          );
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&t.file_type_extension).unwrap_or(Value::Null),
          );
          insert(&mut obj, "File:MIMEType".into(), Value::String(t.mime_type));
        }
        FileTypeFinalize::ExplicitWithMime(payload) => {
          // SetFileType($set, $mime): FileType + FileTypeExtension come from the
          // explicit `set` (via resolve_file_type), but the MIMEType is the
          // parser-supplied `mime` — NOT the generic %mimeType lookup, which
          // lacks M4A/M4V/M4B (QuickTime.pm:10008, F2).
          let (set, mime) = (payload.set(), payload.mime());
          let t = resolve_file_type(ft, Some(set), ext_ref, print_conv_enabled);
          insert(&mut obj, "File:FileType".into(), Value::String(t.file_type));
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&t.file_type_extension).unwrap_or(Value::Null),
          );
          insert(
            &mut obj,
            "File:MIMEType".into(),
            Value::String(mime.to_string()),
          );
        }
        FileTypeFinalize::DetectedWithMime(mime) => {
          // SetFileType($baseType, $mimeType) — the FileType + FileTypeExtension
          // are the detected triplet's, but the MIME is the explicit 2nd arg
          // (binary PLIST: `SetFileType('PLIST', 'application/x-plist')`,
          // PLIST.pm:483). `resolve_file_type` with no explicit type yields the
          // detected FileType/Extension; we replace ONLY the MIME.
          let t = resolve_file_type(ft, None, ext_ref, print_conv_enabled);
          insert(&mut obj, "File:FileType".into(), Value::String(t.file_type));
          insert(
            &mut obj,
            "File:FileTypeExtension".into(),
            serde_json::to_value(&t.file_type_extension).unwrap_or(Value::Null),
          );
          insert(
            &mut obj,
            "File:MIMEType".into(),
            Value::String(mime.to_string()),
          );
        }
      }

      // ----- PLIST content file-type override (PLIST.pm:41-43, :133-141, :225) -
      // An XML plist may carry a content-derived `OverrideFileType` target: the
      // `%plistType` table (`adjustmentBaseVersion => 'AAE'`, PLIST.pm:42/:225) or
      // the `XMLFileType == ModdXML` RawConv (`MODD`, PLIST.pm:136). Both are
      // keyed on the EXACT raw tag ID (computed in the typed Meta) and fire ONLY
      // when `$$self{FILE_TYPE} eq 'XMP'` (PLIST.pm:136/:225) — i.e. the file was
      // reached via the `.xml`-family (XMP) extension, not an explicit
      // `.plist`/`.modd`/`.aae`. The override replaces FileType + FileTypeExtension
      // in place, plus MIMEType when the target has a `%mimeType` entry (`AAE` ⇒
      // `application/vnd.apple.photos`; `MODD` has none, so the XML plist's
      // `application/xml` is kept — ExifTool.pm:9724 `... if $mimeType`). Skipped
      // with the rest of the `File:*` triplet after an unknown leading header.
      #[cfg(feature = "plist")]
      if let crate::format_parser::AnyMeta::Plist(m) = &meta
        && file_type_is_xmp
        && let Some(ov) = m.content_override()
      {
        let (ov_ft, ov_ext, ov_mime) = resolve_override_file_type(ov.as_str(), print_conv_enabled);
        obj.insert("File:FileType".into(), Value::String(ov_ft));
        obj.insert(
          "File:FileTypeExtension".into(),
          serde_json::to_value(&ov_ext).unwrap_or(Value::Null),
        );
        if let Some(mime) = ov_mime {
          obj.insert("File:MIMEType".into(), Value::String(mime));
        }
      }

      // ----- MIME override (Real.pm:653-657 single-stream override) ----------
      // After `SetFileType` resolves the engine table-derived `File:MIMEType`,
      // certain typed Metas can supply a CONTENT-DERIVED MIME that overrides
      // the table value (`$$self{VALUE}{MIMEType} = $mime`). Real.pm's RM
      // path does this when exactly one stream has a non-`logical-fileinfo`
      // MIME. The override must run BEFORE the format-tag emission below so
      // `%noDups` first-wins doesn't lock the table value. Skipped with the
      // rest of the `File:*` triplet after an unknown leading header.
      if let Some(mime) = meta_mime_override(&meta) {
        // The base `insert` macro is `or_insert` (first-wins); we need to
        // REPLACE the just-inserted `File:MIMEType` entry. Use direct
        // `insert` to write over.
        obj.insert("File:MIMEType".into(), Value::String(mime));
      }
    } // end `if !cand.after_unknown_header()` — `File:*` finalization

    // ----- Format tags + diagnostics via the typed tag emission ----------
    // Drive the typed Meta's inherent `serialize_tags` into a `TagMap` (the
    // inline first-wins sink), then merge its entries into the document and
    // lift its FIRST warning/error.
    let mut tm = crate::tagmap::TagMap::new();
    let _ = meta.serialize_tags(print_conv_enabled, &mut tm);
    for (key, value) in tm.entries() {
      insert(
        &mut obj,
        key.to_string(),
        serde_json::to_value(value).unwrap_or(Value::Null),
      );
    }
    if let Some(w) = tm.first_warning() {
      warning.get_or_insert_with(|| w.to_string());
    }
    if let Some(e) = tm.first_error() {
      error.get_or_insert_with(|| e.to_string());
    }

    finalized = true;
    break;
  }

  // ExifTool.pm:3080-3128 — nothing finalized ⇒ compute the finalization Error.
  if !finalized {
    if let Some(err) = finalization_error(name, data) {
      error.get_or_insert(err);
    }
  }

  // Generated `ExifTool:Warning` / `ExifTool:Error` join the same dedup set
  // (ExifTool.pm:2951; only the FIRST of each under default `-j`).
  if let Some(w) = warning {
    insert(&mut obj, "ExifTool:Warning".into(), Value::String(w));
  }
  if let Some(e) = error {
    insert(&mut obj, "ExifTool:Error".into(), Value::String(e));
  }

  Value::Array(vec![Value::Object(obj)]).to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Run the engine over `data` and return the parsed file object. The engine
  /// path is now `extract_info` (detect → typed parse → serde-render).
  #[cfg(feature = "json")]
  fn engine_obj(
    name: &str,
    data: &[u8],
    print_on: bool,
  ) -> serde_json::Map<String, serde_json::Value> {
    let json = extract_info(name, data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  // The `SetFileType` / `OverrideFileType` File:* COMPUTATION is now the pure
  // `resolve_file_type` / `resolve_override_file_type` functions (the engine
  // builds the `File:*` triplet from them in `extract_info_typed`). These unit
  // tests pin that computation directly, replacing the retired
  // `ParseContext::set_file_type` / `override_file_type` writer tests. The
  // first-call-wins / override-in-place SEMANTICS (one File:* triplet, never
  // duplicated) are now structurally guaranteed by the serde `Map` (one key per
  // name) and covered end-to-end by `conformance.rs` (OGG override fixtures).

  #[test]
  fn set_file_type_pseudo_tags_print_on() {
    // -j: detected AAC ⇒ AAC / aac (PrintConv lc) / audio/aac.
    let t = resolve_file_type("AAC", None, Some("AAC"), true);
    assert_eq!(t.file_type, "AAC");
    assert_eq!(t.file_type_extension, TagValue::Str("aac".into()));
    assert_eq!(t.mime_type, "audio/aac");
  }

  #[test]
  fn file_type_extension_is_raw_uppercase_under_n() {
    // -n: FileTypeExtension is the raw uppercase (no PrintConv lc).
    let t = resolve_file_type("AAC", None, Some("AAC"), false);
    assert_eq!(t.file_type_extension, TagValue::Str("AAC".into()));
  }

  #[test]
  fn mime_fallback_is_application_unknown() {
    // Detected type "XYZ" has no %mimeType / %fileTypeExt key.
    let t = resolve_file_type("XYZ", None, None, true);
    assert_eq!(t.mime_type, "application/unknown");
  }

  #[test]
  fn override_file_type_keeps_mime_when_none_known() {
    // ExifTool.pm:9724 `... if $mimeType` — "XYZ" has no %mimeType ⇒ the
    // override returns `None` for MIME (the engine then leaves the existing
    // MIMEType untouched). FileType/FileTypeExtension still change.
    let (ft, _ext, mime) = resolve_override_file_type("XYZ", true);
    assert_eq!(ft, "XYZ");
    assert_eq!(mime, None);
    // A known type yields its MIME + FileTypeExtension.
    let (ft2, ext2, mime2) = resolve_override_file_type("MP4", true);
    assert_eq!(ft2, "MP4");
    assert_eq!(ext2, TagValue::Str("mp4".into()));
    assert_eq!(mime2.as_deref(), Some("video/mp4"));
  }

  /// `BZh91AY&SY` satisfies `%magicNumber{BZ2}` (ExifTool.pm:940); BZ2 is
  /// `%moduleName{BZ2}=0` (ExifTool.pm:858) ⇒ unsupported-terminal branch
  /// (ExifTool.pm:3054-3057): SetFileType + Warn + stop.
  #[cfg(feature = "json")]
  #[test]
  fn unsupported_type_sets_filetype_and_warning_then_stops() {
    // %magicNumber{BZ2} = `BZh[1-9]\x31\x41\x59\x26\x53\x59` (ExifTool.pm:940);
    // prefix-only — trailing bytes are inert padding.
    let bz2_magic: &[u8] = b"BZh91AY\x26SY\x00\x00";
    let obj = engine_obj("x.bz2", bz2_magic, true);
    // File:FileType == "BZ2" (SetFileType ran).
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("BZ2")
    );
    // ExifTool:Warning == "Unsupported file type".
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Unsupported file type")
    );
    // Terminal stop: only SourceFile + ExifTool:* + File:* — no format tags.
    let extra: Vec<&String> = obj
      .keys()
      .filter(|k| *k != "SourceFile" && !k.starts_with("ExifTool:") && !k.starts_with("File:"))
      .collect();
    assert!(extra.is_empty(), "no extra tags expected, got: {extra:?}");
  }

  #[cfg(feature = "json")]
  #[test]
  fn empty_input_emits_faithful_file_is_empty_error() {
    // ExifTool.pm:3080-3128: nothing finalized + `not length $buff` ⇒
    // `$self->Error('File is empty')` (ExifTool.pm:3086).
    let obj = engine_obj("Empty.dat", &[], true);
    assert_eq!(
      obj.get("ExifTool:Error").and_then(|v| v.as_str()),
      Some("File is empty")
    );
    assert!(!obj.contains_key("File:FileType"));
    assert!(!obj.contains_key("ExifTool:Warning"));
  }

  #[cfg(feature = "json")]
  #[test]
  fn all_zero_32_bytes_emits_faithful_all_same_byte_insight() {
    // ExifTool.pm:3097-3122: buff ≥ 16 AND every byte == $ch (\0) ⇒
    // 'Entire file is' + ' binary zeros'.
    let obj = engine_obj("allzero.dat", &[0u8; 32], true);
    assert_eq!(
      obj.get("ExifTool:Error").and_then(|v| v.as_str()),
      Some("Entire file is binary zeros")
    );
    assert!(!obj.contains_key("File:FileType"));
  }

  #[cfg(feature = "json")]
  #[test]
  fn unknown_type_emits_faithful_unknown_file_type_error() {
    // ExifTool.pm:3089-3095: buff < 16 (8 bytes), unrecognized ⇒ 'Unknown
    // file type'.
    let obj = engine_obj("mystery.xyz", b"\x51\x7a\x2b\x6d\x09\x44\x1e\x77", true);
    assert_eq!(
      obj.get("ExifTool:Error").and_then(|v| v.as_str()),
      Some("Unknown file type")
    );
  }

  #[cfg(feature = "json")]
  #[test]
  fn malformed_aac_emits_faithful_file_format_error() {
    // `\xff\xf1` passes the AAC %magicNumber gate so AAC is a candidate, but
    // SF index 0xf > 12 makes ProcessAAC reject. `.aac` is known ⇒ 'File
    // format error' (ExifTool.pm:3093).
    let obj = engine_obj("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00\x00\x00\x00", true);
    assert_eq!(
      obj.get("ExifTool:Error").and_then(|v| v.as_str()),
      Some("File format error")
    );
    assert!(!obj.contains_key("File:FileType"));
  }

  #[test]
  fn convert_file_size_matches_bundled_perl() {
    // Transliteration of ExifTool.pm:6852-6858 (decimal branch). Each
    // value cross-checked against bundled Perl `ConvertFileSize` and the
    // observed `perl exiftool` 'First …' Error text (oracle 2026-05-19):
    //   1999→"1999 bytes"  2000→"2.0 kB"  9999→"10.0 kB"  10000→"10 kB"
    //   70000→"70 kB"  1999999→"2000 kB"  2000000→"2.0 MB"
    //   9999999→"10.0 MB"  10000000→"10 MB"  100000→"100 kB"
    assert_eq!(convert_file_size(0), "0 bytes");
    assert_eq!(convert_file_size(1999), "1999 bytes");
    assert_eq!(convert_file_size(2000), "2.0 kB");
    assert_eq!(convert_file_size(2001), "2.0 kB");
    assert_eq!(convert_file_size(9999), "10.0 kB");
    assert_eq!(convert_file_size(10000), "10 kB");
    assert_eq!(convert_file_size(70000), "70 kB");
    assert_eq!(convert_file_size(100_000), "100 kB");
    assert_eq!(convert_file_size(1_999_999), "2000 kB");
    assert_eq!(convert_file_size(2_000_000), "2.0 MB");
    assert_eq!(convert_file_size(9_999_999), "10.0 MB");
    assert_eq!(convert_file_size(10_000_000), "10 MB");
    assert_eq!(convert_file_size(1_999_999_999), "2000 MB");
    assert_eq!(convert_file_size(2_000_000_000), "2.0 GB");
    assert_eq!(convert_file_size(9_999_999_999), "10.0 GB");
    assert_eq!(convert_file_size(10_000_000_000), "10 GB");
  }

  #[test]
  fn finalization_error_first_n_and_suffix_variants() {
    // 'First N of file is' fires when a differing byte follows an
    // all-same prefix that fills the ≥16-byte test window. Offsets and
    // suffixes verified against the bundled tool (oracle 2026-05-19):
    //   1999 \0 then \x01 ⇒ "First 1999 bytes of file is binary zeros"
    //   2000 \0 then \x01 ⇒ "First 2.0 kB of file is binary zeros"
    let mut d = vec![0u8; 1999];
    d.push(1);
    assert_eq!(
      finalization_error("x", &d).as_deref(),
      Some("First 1999 bytes of file is binary zeros")
    );
    let mut d = vec![0u8; 2000];
    d.push(1);
    assert_eq!(
      finalization_error("x", &d).as_deref(),
      Some("First 2.0 kB of file is binary zeros")
    );
    // Suffix variants on an all-same ≥16 file (whole file ⇒ 'Entire'):
    //   32 \xff ⇒ "Entire file is binary 0xff's" (bundled-verified)
    assert_eq!(
      finalization_error("x", &[0xffu8; 32]).as_deref(),
      Some("Entire file is binary 0xff's")
    );
    // A non-printable, non-NUL, non-space byte ⇒ sprintf 0x%.2x's.
    assert_eq!(
      finalization_error("x", &[0x01u8; 20]).as_deref(),
      Some("Entire file is binary 0x01's")
    );
    // < 16 bytes, unknown ⇒ the not-all-same arm ⇒ 'Unknown file type'.
    assert_eq!(
      finalization_error("x", &[0u8; 15]).as_deref(),
      Some("Unknown file type")
    );
    // A differing byte WITHIN the ≤1024 test window ⇒ regex matches ⇒
    // the not-all-same arm (bundled: 15 \0 + \x01 ⇒ "Unknown file type").
    let mut d = vec![0u8; 15];
    d.push(1);
    d.extend(std::iter::repeat(0u8).take(100));
    assert_eq!(
      finalization_error("mystery.xyz", &d).as_deref(),
      Some("Unknown file type")
    );
  }

  #[test]
  fn mime_type_full_table_matches_bundled_perl() {
    // The full %mimeType (ExifTool.pm:616-847) is now ported. Every value
    // below was captured from the BUNDLED `perl exiftool` /
    // `%Image::ExifTool::mimeType` (oracle 2026-05-19); if any ported
    // value ≠ this, the table is mis-transcribed — fix it, never fudge.
    // ≥10 entries incl. a spaces-in-key (`Canon 1D RAW`) and a hyphen
    // key (`DVR-MS`), plus the Phase-2-reachable audio types that the
    // ~28-format fan-out will source from this seam.
    for (ft, want) in [
      ("AAC", "audio/aac"),                     // ExifTool.pm:620 (unchanged)
      ("BZ2", "application/bzip2"),             // ExifTool.pm:632 (unchanged)
      ("FLAC", "audio/flac"),                   // ExifTool.pm:679
      ("MP3", "audio/mpeg"),                    // ExifTool.pm:734
      ("AIFF", "audio/x-aiff"),                 // ExifTool.pm:623
      ("APE", "audio/x-monkeys-audio"),         // ExifTool.pm:625
      ("MPC", "audio/x-musepack"),              // ExifTool.pm:736
      ("WV", "audio/x-wavpack"),                // ExifTool.pm:831
      ("FLV", "video/x-flv"),                   // ExifTool.pm:682
      ("SWF", "application/x-shockwave-flash"), // ExifTool.pm:811
      ("JPEG", "image/jpeg"),                   // ExifTool.pm:704
      ("TIFF", "image/tiff"),                   // ExifTool.pm:814
      ("PNG", "image/png"),                     // ExifTool.pm:773
      ("Canon 1D RAW", "image/x-raw"),          // ExifTool.pm:634 (spaces in key)
      ("DVR-MS", "video/x-ms-dvr"),             // ExifTool.pm:665 (hyphen in key)
      ("3FR", "image/x-hasselblad-3fr"),        // ExifTool.pm:617 (digit-leading)
      ("7Z", "application/x-7z-compressed"),    // ExifTool.pm:618
      ("XMP", "application/rdf+xml"),           // ExifTool.pm:845
      ("ZIP", "application/zip"),               // ExifTool.pm:846 (last entry)
    ] {
      assert_eq!(mime_type(ft), Some(want), "%mimeType[{ft}]");
    }
    // A TYPE absent from %mimeType ⇒ None (⇒ application/unknown).
    assert_eq!(mime_type("NoSuchType"), None);
  }

  #[test]
  fn file_type_ext_full_table_matches_bundled_perl() {
    // The full %fileTypeExt (ExifTool.pm:590-600) — all 9 keys, verbatim
    // (oracle: bundled `perl exiftool` `File:FileTypeExtension`, e.g. a
    // .jpg JPEG ⇒ "jpg"). Case round-trips via uc→PrintConv lc.
    for (ft, want) in [
      ("Canon 1D RAW", "tif"), // ExifTool.pm:591
      ("DICOM", "dcm"),        // ExifTool.pm:592
      ("FLIR", "fff"),         // ExifTool.pm:593
      ("GZIP", "gz"),          // ExifTool.pm:594
      ("JPEG", "jpg"),         // ExifTool.pm:595
      ("M2TS", "mts"),         // ExifTool.pm:596
      ("MPEG", "mpg"),         // ExifTool.pm:597
      ("TIFF", "tif"),         // ExifTool.pm:598
      ("VCard", "vcf"),        // ExifTool.pm:599
    ] {
      assert_eq!(file_type_ext(ft), Some(want), "%fileTypeExt[{ft}]");
    }
    // %fileTypeExt has NO AAC / Phase-2 audio key ⇒ None ⇒ Perl
    // `$normExt = $fileType` (ExifTool.pm:9698): unchanged AAC behavior.
    assert_eq!(file_type_ext("AAC"), None);
    assert_eq!(file_type_ext("MP3"), None);
    assert_eq!(file_type_ext("FLAC"), None);
  }

  #[test]
  fn set_file_type_cross_format_mime_and_normext_match_bundled_perl() {
    // No-arg SetFileType (file_type=None) ⇒ resolve from detected type. The
    // detected type == base type (no ext divergence) so the sub-type block is
    // inert; validates the %mimeType / %fileTypeExt seam. (type, normExt-lc,
    // MIME) per bundled `perl exiftool` (oracle 2026-05-19).
    for (ft, want_ext_lc, want_mime) in [
      ("FLAC", "flac", "audio/flac"),
      ("MP3", "mp3", "audio/mpeg"),
      ("JPEG", "jpg", "image/jpeg"),
      ("M2TS", "mts", "video/m2ts"),
      ("MPEG", "mpg", "video/mpeg"),
    ] {
      let t = resolve_file_type(ft, None, None, true);
      assert_eq!(t.file_type, ft, "{ft}");
      assert_eq!(
        t.file_type_extension,
        TagValue::Str(want_ext_lc.into()),
        "{ft} FileTypeExtension (PrintConv lc)"
      );
      assert_eq!(t.mime_type, want_mime, "{ft} MIMEType");
    }
  }

  #[test]
  fn set_file_type_subtype_by_ext_promotes_to_extension() {
    // ExifTool.pm:9686-9692: detected base TIFF, but a TIFF-rooted RAW
    // extension ⇒ $fileType is promoted to the extension and MIME comes from
    // the extension's own %mimeType (e.g. a TIFF-magic *.nef ⇒ NEF / nef /
    // image/x-nikon-nef).
    for (ext, want_type, want_ext_lc, want_mime) in [
      ("NEF", "NEF", "nef", "image/x-nikon-nef"),
      ("CR2", "CR2", "cr2", "image/x-canon-cr2"),
      ("DNG", "DNG", "dng", "image/x-adobe-dng"),
      ("ARW", "ARW", "arw", "image/x-sony-arw"),
      ("3FR", "3FR", "3fr", "image/x-hasselblad-3fr"),
    ] {
      let t = resolve_file_type("TIFF", None, Some(ext), true);
      assert_eq!(t.file_type, want_type, "{ext}: promoted FileType");
      assert_eq!(
        t.file_type_extension,
        TagValue::Str(want_ext_lc.into()),
        "{ext}: FileTypeExtension"
      );
      assert_eq!(t.mime_type, want_mime, "{ext}: MIMEType from promoted type");
    }
    // ext == fileType (TIFF/.tif) ⇒ NO promotion, plain TIFF.
    let t = resolve_file_type("TIFF", None, Some("TIFF"), true);
    assert_eq!(t.file_type, "TIFF");
    assert_eq!(t.mime_type, "image/tiff");
  }

  #[test]
  fn set_file_type_subtype_by_ext_no_promote_when_roots_differ() {
    // ExifTool.pm:9688 `$$f[0] eq $$e[0]` must hold. PNG root 'PNG' vs JPEG
    // root 'JPEG' differ ⇒ NO promotion: detected PNG with $ext=JPEG stays PNG.
    let t = resolve_file_type("PNG", None, Some("JPEG"), true);
    assert_eq!(t.file_type, "PNG", "roots differ ⇒ no sub-type promotion");
    // A multi-row extension can never promote (`$$e[0]` is an arrayref).
    // Detected PDF + $ext=AI ⇒ stays PDF.
    let t2 = resolve_file_type("PDF", None, Some("AI"), true);
    assert_eq!(t2.file_type, "PDF", "multi-row ext ⇒ no promotion");
  }

  #[cfg(feature = "exif")]
  #[test]
  fn tiff_subtype_finalizes_to_parent_not_tiff() {
    // Codex F3: `DoProcessTIFF` finalizes via `SetFileType($t)` where `$t` is
    // the candidate's PARENT type, not the bare detected `"TIFF"`
    // (ExifTool.pm:8685-8694). For a TIFF-backed subtype extension the
    // detection candidate is `file_type()=="TIFF"` with
    // `parent_type()==$$self{FILE_EXT}` (the uppercased ext), so the
    // finalization must promote to the subtype. Ground-truth from bundled
    // `perl exiftool`'s DoProcessTIFF `$t` + SetFileType (oracle 2026-05-29).
    for (parent_ext, want_type, want_ext_lc, want_mime) in [
      ("FFF", "FFF", "fff", "image/x-hasselblad-fff"),
      ("3FR", "3FR", "3fr", "image/x-hasselblad-3fr"),
      ("NEF", "NEF", "nef", "image/x-nikon-nef"),
      ("RAW", "RAW", "raw", "image/x-raw"),
    ] {
      // The engine passes `base_type = "TIFF"` (the detection `$type`),
      // `parent_type` and `ext` both == the file extension (`$tiffType ==
      // $$self{FILE_EXT}`).
      let t = tiff_finalize_file_type("TIFF", parent_ext, Some(parent_ext), true);
      assert_eq!(t.file_type, want_type, "{parent_ext}: promoted FileType");
      assert_eq!(
        t.file_type_extension,
        TagValue::Str(want_ext_lc.into()),
        "{parent_ext}: FileTypeExtension"
      );
      assert_eq!(t.mime_type, want_mime, "{parent_ext}: MIMEType");
    }

    // A plain `.tif` has `parent_type == "TIFF"` (root TIFF) ⇒ `$t = "TIFF"` ⇒
    // stays TIFF (no spurious promotion).
    let tif = tiff_finalize_file_type("TIFF", "TIFF", Some("TIFF"), true);
    assert_eq!(tif.file_type, "TIFF");
    assert_eq!(tif.mime_type, "image/tiff");

    // An embedded / dotless TIFF has `parent_type == ""` ⇒ the
    // `if ($fileType ...)` guard is FALSE ⇒ bundled never re-finalizes here,
    // leaving the detection-time bare `"TIFF"`.
    let embedded = tiff_finalize_file_type("TIFF", "", None, true);
    assert_eq!(embedded.file_type, "TIFF");
    assert_eq!(embedded.mime_type, "image/tiff");

    // A subtype whose lookup root is NOT TIFF and whose Parent doesn't match
    // /RAW/ would yield `$t = undef` ⇒ falls back to the detected base
    // `"TIFF"`. (`X3F`'s root is `X3F`, not TIFF.) Faithful even though no
    // real X3F file dispatches through DoProcessTIFF.
    let non_tiff_root = tiff_finalize_file_type("TIFF", "X3F", Some("X3F"), true);
    assert_eq!(
      non_tiff_root.file_type, "TIFF",
      "non-TIFF-root parent ⇒ $t=undef ⇒ stays detected TIFF"
    );
  }

  /// The finalized `$$self{FILE_TYPE}` NAME ([`finalized_tiff_file_type`]) —
  /// the value the standalone-TIFF dispatch threads as the container type for
  /// the `Canon::ShotInfo` pos-22 CRW-allows-0 RawConv — must EQUAL the
  /// `File:FileType` ([`tiff_finalize_file_type`]`.file_type`) for every
  /// candidate `Parent`, and is **provably never `"CRW"`**.
  ///
  /// The load-bearing case (Codex R6 bug): a `.crw`-named TIFF-magic file. Its
  /// candidate `Parent` is `"CRW"` (the uppercased extension), but its finalized
  /// `FILE_TYPE` is `"TIFF"` — `CRW`'s base module is `CanonRaw` (NOT `TIFF`)
  /// and `"CRW"` has no `RAW` substring, so `DoProcessTIFF`'s `$t` is undef ⇒ the
  /// name stays the detected `"TIFF"`. Threading the bare `Parent` (the bug) would
  /// wrongly fire the CRW branch (keep a raw-0 ExposureTime); threading this
  /// finalized type does NOT.
  #[cfg(feature = "exif")]
  #[test]
  fn finalized_tiff_file_type_never_crw_and_matches_filetype() {
    // (candidate Parent, ext) ⇒ finalized FILE_TYPE. Includes the .crw-named
    // TIFF (Parent "CRW" ⇒ "TIFF"), a plain .tif, TIFF-rooted RAW subtypes
    // (promote), a non-TIFF-root parent (X3F ⇒ stays TIFF), and the empty /
    // dotless Parent.
    for (parent, ext, want) in [
      ("CRW", Some("CRW"), "TIFF"), // the bug: Parent "CRW" but FILE_TYPE "TIFF".
      ("TIFF", Some("TIFF"), "TIFF"),
      ("NEF", Some("NEF"), "NEF"),
      ("CR2", Some("CR2"), "CR2"),
      ("3FR", Some("3FR"), "3FR"),
      ("RAW", Some("RAW"), "RAW"),
      ("X3F", Some("X3F"), "TIFF"), // non-TIFF-root, no RAW substring ⇒ $t undef.
      ("", None, "TIFF"),           // dotless / embedded ⇒ guard false ⇒ "TIFF".
    ] {
      let finalized = finalized_tiff_file_type("TIFF", parent, ext);
      assert_eq!(
        finalized, want,
        "finalized FILE_TYPE for Parent={parent:?} ext={ext:?}"
      );
      assert_ne!(finalized, "CRW", "the finalized FILE_TYPE is never CRW");
      // It MUST equal the `File:FileType` the engine emits (same computation).
      let emitted = tiff_finalize_file_type("TIFF", parent, ext, true).file_type;
      assert_eq!(
        finalized, emitted,
        "finalized FILE_TYPE must match File:FileType for Parent={parent:?}"
      );
    }
  }

  #[test]
  fn set_file_type_base_mime_fallback_and_tiff_exclusion() {
    // ExifTool.pm:9695 `$mimeType = $mimeType{$baseType} unless $mimeType or
    // $baseType eq 'TIFF'`. base = "AAC", explicit fileType "XYZ" (no
    // %mimeType) ⇒ fall back to $mimeType{AAC} = "audio/aac".
    let t = resolve_file_type("AAC", Some("XYZ"), None, true);
    assert_eq!(t.file_type, "XYZ");
    assert_eq!(t.mime_type, "audio/aac", "base-type MIME fallback (AAC)");
    // The `$baseType eq 'TIFF'` exclusion: base TIFF + explicit "XYZ" ⇒
    // fallback SUPPRESSED ⇒ application/unknown (NOT image/tiff).
    let t2 = resolve_file_type("TIFF", Some("XYZ"), None, true);
    assert_eq!(t2.file_type, "XYZ");
    assert_eq!(t2.mime_type, "application/unknown", "TIFF exclusion");
    // Sanity: base TIFF, no override ⇒ image/tiff directly.
    let t3 = resolve_file_type("TIFF", None, None, true);
    assert_eq!(t3.mime_type, "image/tiff");
  }

  /// END-TO-END regression for the Codex R6 bug: a `.crw`-named TIFF-magic
  /// file must finalize to `File:FileType == "TIFF"` (NOT "CRW"), so the
  /// container `$$self{FILE_TYPE}` threaded into `Canon::ShotInfo` position
  /// 22's RawConv (`Canon.pm:2977`/`:2990`) is "TIFF" ⇒ a raw-0 ExposureTime is
  /// DROPPED (the `FILE_TYPE eq "CRW"` clause is false), matching bundled.
  ///
  /// Before the fix, the engine threaded the candidate `Parent` ("CRW" for a
  /// `.crw` name) instead of the finalized `FILE_TYPE` ("TIFF"), so the CRW
  /// branch wrongly fired and KEPT the raw-0 ExposureTime — this test would
  /// fail (an `…:ExposureTime` key would be present).
  ///
  /// The fixture is a minimal little-endian TIFF: IFD0 = Make "Canon\0" +
  /// ExifIFD pointer; ExifIFD = a `0x927C` MakerNote; the MakerNote is a Canon
  /// IFD with one `ShotInfo` (tag `0x0004`, int16[23], all zero ⇒ pos-22 raw 0,
  /// stored out-of-line at an absolute file offset — Canon inherits base 0).
  #[cfg(all(feature = "json", feature = "exif"))]
  #[test]
  fn crw_named_tiff_finalizes_to_tiff_and_drops_shotinfo_exposuretime() {
    // Little-endian TIFF. Offsets (absolute, base 0):
    //   0   header: "II" 0x2a 0x00, IFD0 = 8
    //   8   IFD0 (2 entries): 8..38
    //   38  Make string "Canon\0": 38..44
    //   44  ExifIFD (1 entry): 44..62
    //   62  MakerNote = Canon IFD (1 entry): 62..80
    //   80  ShotInfo int16[23] = 46 bytes of zero: 80..126
    let mut t: Vec<u8> = Vec::new();
    t.extend_from_slice(&[b'I', b'I', 0x2a, 0x00]); // II, magic 42
    t.extend_from_slice(&8u32.to_le_bytes()); // IFD0 @ 8
    // --- IFD0 @ 8 (2 entries) ---
    t.extend_from_slice(&2u16.to_le_bytes());
    // Make (0x010f) ASCII(2) count=6 ⇒ out-of-line @ 38.
    t.extend_from_slice(&0x010fu16.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&6u32.to_le_bytes());
    t.extend_from_slice(&38u32.to_le_bytes());
    // ExifIFD (0x8769) LONG(4) count=1 ⇒ value = 44.
    t.extend_from_slice(&0x8769u16.to_le_bytes());
    t.extend_from_slice(&4u16.to_le_bytes());
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(&44u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // IFD0 next = 0
    debug_assert_eq!(t.len(), 38);
    // --- Make string @ 38 ---
    t.extend_from_slice(b"Canon\x00");
    debug_assert_eq!(t.len(), 44);
    // --- ExifIFD @ 44 (1 entry: MakerNote) ---
    t.extend_from_slice(&1u16.to_le_bytes());
    // MakerNote (0x927c) UNDEF(7) count=64 ⇒ value @ 62 (the Canon IFD: 62..126).
    t.extend_from_slice(&0x927cu16.to_le_bytes());
    t.extend_from_slice(&7u16.to_le_bytes());
    t.extend_from_slice(&64u32.to_le_bytes());
    t.extend_from_slice(&62u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // ExifIFD next = 0
    debug_assert_eq!(t.len(), 62);
    // --- MakerNote = Canon IFD @ 62 (1 entry: ShotInfo) ---
    t.extend_from_slice(&1u16.to_le_bytes());
    // ShotInfo (0x0004) int16(3) count=23 ⇒ out-of-line @ 80 (absolute).
    t.extend_from_slice(&0x0004u16.to_le_bytes());
    t.extend_from_slice(&3u16.to_le_bytes());
    t.extend_from_slice(&23u32.to_le_bytes());
    t.extend_from_slice(&80u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // Canon IFD next = 0
    debug_assert_eq!(t.len(), 80);
    // --- ShotInfo int16[23] all zero @ 80 (pos-22 raw = 0) ---
    t.extend_from_slice(&[0u8; 46]);
    debug_assert_eq!(t.len(), 126);

    let obj = engine_obj("x.crw", &t, true);
    // The `.crw`-named TIFF-magic file finalizes to FileType "TIFF" (NOT "CRW").
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("TIFF"),
      "a .crw-named TIFF-magic file must finalize to FileType TIFF"
    );
    // The Make round-tripped (proves the Canon MakerNote dispatch ran).
    assert_eq!(
      obj.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("Canon"),
      "IFD0:Make should be Canon (the Canon vendor dispatch keys on it)"
    );
    // The raw-0 ShotInfo ExposureTime is DROPPED (FILE_TYPE is "TIFF", not
    // "CRW") — NO key bears an ExposureTime name.
    let exposure_keys: Vec<&String> = obj.keys().filter(|k| k.contains("ExposureTime")).collect();
    assert!(
      exposure_keys.is_empty(),
      "raw-0 ShotInfo ExposureTime must be DROPPED for a TIFF (non-CRW) container, got: {exposure_keys:?}"
    );
  }

  #[cfg(feature = "json")]
  #[test]
  fn aac_fixture_matches_golden_print_on() {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/AAC.aac")).expect("fixture");
    let want =
      std::fs::read_to_string(format!("{root}/tests/golden/AAC.aac.json")).expect("golden");
    let got = extract_info("AAC.aac", &data, true);
    crate::jsondiff::json_equivalent(&got, &want)
      .unwrap_or_else(|e| panic!("AAC -j -G1 -struct conformance: {}", e.message()));
  }

  #[cfg(feature = "json")]
  #[test]
  fn aac_fixture_matches_golden_n() {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/AAC.aac")).expect("fixture");
    let want =
      std::fs::read_to_string(format!("{root}/tests/golden/AAC.aac.n.json")).expect("golden");
    let got = extract_info("AAC.aac", &data, false);
    crate::jsondiff::json_equivalent(&got, &want)
      .unwrap_or_else(|e| panic!("AAC -n conformance: {}", e.message()));
  }
}
