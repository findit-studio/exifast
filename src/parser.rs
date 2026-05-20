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
  formats::parser_for,
  tagtable::{PrintConv, TagDef, ValueConv},
  value::{Group, Metadata, TagValue},
};
use smol_str::SmolStr;

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

/// The per-parse `$et`-equivalent: the data, the detected file type, and the
/// value sink the parser fills, plus the faithful `SetFileType` /
/// `OverrideFileType` operations a `Process<Type>` invokes itself (e.g.
/// `AAC.pm:107`).
///
/// D8/D9: all fields are private; construct via [`ParseContext::new`] and
/// access via the accessors.
pub struct ParseContext<'a> {
  /// The file bytes (`$raf` content the parser reads).
  data: &'a [u8],
  /// The detected file TYPE for this candidate — ExifTool's `$$self{FILE_TYPE}`
  /// (the no-arg `SetFileType()` default, ExifTool.pm:9684).
  file_type: &'a str,
  /// JPEG/TIFF unknown-header skip (`pos($buff) - length($1)`); `0` otherwise.
  header_skip: usize,
  /// ExifTool's `$dirInfo{Parent}` (ExifTool.pm:3038).
  parent_type: &'a str,
  /// ExifTool's `$$self{FILE_EXT}` (ExifTool.pm:2966 = `GetFileExtension(
  /// $realname)`): the uppercased, `TIF`→`TIFF` file extension, or `None`
  /// for a dotless name. Read as `$ext` by `SetFileType` (ExifTool.pm:9683)
  /// for the sub-type-by-ext block (ExifTool.pm:9686-9692).
  ext: Option<SmolStr>,
  /// ExifTool `-n`: `false` ⇒ ValueConv-only (no PrintConv).
  print_conv_enabled: bool,
  /// The `$et` value sink: the parser pushes its FoundTag/HandleTag tags here.
  /// The first-call-wins gate (`$$self{FileType}`, ExifTool.pm:9681) is read
  /// off this `Metadata` via [`Metadata::has_file_type`] — FILE-scoped, not
  /// candidate-scoped (faithful to `$self` outliving any single
  /// `Process<Type>` invocation: a candidate-loop iteration that constructs
  /// a fresh `ParseContext` MUST still observe the marker any earlier
  /// candidate's `SetFileType` set on `m`).
  meta: &'a mut Metadata,
}

impl<'a> ParseContext<'a> {
  /// Construct a parse context. `file_type` is the detected candidate type
  /// (the no-arg `SetFileType()` default, ExifTool.pm:9684); `ext` is
  /// ExifTool's `$$self{FILE_EXT}` (ExifTool.pm:2966 =
  /// `GetFileExtension($realname)` — derive via
  /// [`crate::filetype::file_ext_for_name`], the same normalizer the
  /// detection path uses); `meta` is the `$et` value sink the parser fills.
  #[must_use]
  pub fn new(
    data: &'a [u8],
    file_type: &'a str,
    header_skip: usize,
    parent_type: &'a str,
    ext: Option<SmolStr>,
    print_conv_enabled: bool,
    meta: &'a mut Metadata,
  ) -> Self {
    Self {
      data,
      file_type,
      header_skip,
      parent_type,
      ext,
      print_conv_enabled,
      meta,
    }
  }

  /// The file bytes the parser reads (`$raf` content).
  ///
  /// Returns `&'a [u8]` (the original construction-time borrow), NOT
  /// `&[u8]` tied to `&self`. That lets a parser hold a slice borrowed
  /// from this method across calls to `&mut ctx` mutators
  /// (`ctx.metadata()`, `ctx.set_file_type(...)`) without a borrow-
  /// checker conflict — the slice's lifetime is independent of the
  /// `&self` receiver. Avoids the formats-side `.to_vec()` workaround
  /// (per Copilot PR #12 review #3271619078).
  #[must_use]
  pub fn data(&self) -> &'a [u8] {
    self.data
  }

  /// JPEG/TIFF unknown-header skip (`pos($buff) - length($1)`); `0` otherwise.
  #[must_use]
  pub fn header_skip(&self) -> usize {
    self.header_skip
  }

  /// ExifTool's `$dirInfo{Parent}` (ExifTool.pm:3038).
  #[must_use]
  pub fn parent_type(&self) -> &str {
    self.parent_type
  }

  /// ExifTool's `$$self{FILE_EXT}` (ExifTool.pm:2966): the uppercased,
  /// `TIF`→`TIFF` file extension (or `None` for a dotless name). Read as
  /// `$ext` by `SetFileType` (ExifTool.pm:9683).
  #[must_use]
  pub fn ext(&self) -> Option<&str> {
    self.ext.as_deref()
  }

  /// ExifTool `-n`: `false` ⇒ ValueConv-only (no PrintConv).
  #[must_use]
  pub fn print_conv_enabled(&self) -> bool {
    self.print_conv_enabled
  }

  /// The `$et` value sink: the parser pushes its FoundTag/HandleTag tags
  /// here (this is the `&mut Metadata` a `Process<Type>` fills, e.g. the
  /// AAC bit-stream + Encoder tags).
  #[must_use]
  pub fn metadata(&mut self) -> &mut Metadata {
    self.meta
  }

  /// Split-borrow accessor: returns `(&[u8], &mut Metadata)` simultaneously
  /// so a parser can slice into [`Self::data`] and call into a metadata-
  /// pushing sub-parser (e.g. `process_vorbis_comments`, `process_flac_picture`,
  /// `bitstream::process_bit_stream`) WITHOUT cloning the slice into a `Vec`.
  ///
  /// Required because [`Self::data`] reborrows `&self` while
  /// [`Self::metadata`] reborrows `&mut self` — calling both in sequence
  /// forces the caller to `.to_vec()` the slice. The split borrow is sound
  /// because `data` and `meta` are disjoint fields (the `&[u8]` does NOT
  /// alias `&mut Metadata`).
  #[must_use]
  pub fn data_and_metadata(&mut self) -> (&[u8], &mut Metadata) {
    (self.data, self.meta)
  }

  /// Faithful `SetFileType` (ExifTool.pm:9677-9706), read path. Pushes
  /// `File:FileType`, `File:FileTypeExtension` (`uc $normExt`; PrintConv
  /// `lc`), `File:MIMEType` (`$mimeType || 'application/unknown'`). Called
  /// by the parser itself (e.g. no-arg at `AAC.pm:107`):
  ///
  /// - `file_type = None` ⇒ `$$self{FILE_TYPE}`, here the detected
  ///   [`file_type`](Self::new) (ExifTool.pm:9684).
  /// - First-call-wins: a second call is ignored (`$$self{FileType}` guard,
  ///   ExifTool.pm:9681).
  pub fn set_file_type(
    &mut self,
    file_type: Option<&str>,
    mime: Option<&str>,
    norm_ext: Option<&str>,
  ) {
    // ExifTool.pm:9681 `unless ($$self{FileType} and not $$self{DOC_NUM})`:
    // use only the first FileType set (no DOC_NUM ⇒ always first-call-wins).
    // The marker is on the per-file `$self` (ExifTool.pm:9701
    // `$$self{FileType} = $fileType`), NOT on the per-`Process<Type>`
    // context — so it MUST be read off `self.meta` (file-scoped), not a
    // per-`ParseContext` bool (which would reset across candidates and
    // re-push duplicate File:FileType/FileTypeExtension/MIMEType when a
    // later candidate's parser also calls `SetFileType`).
    if self.meta.has_file_type() {
      return;
    }
    // ExifTool.pm:9682 `my $baseType = $$self{FILE_TYPE}` — the detected
    // candidate type carried by this context.
    let base_type = self.file_type;
    // ExifTool.pm:9683 `my $ext = $$self{FILE_EXT}` (= GetFileExtension(
    // $realname), ExifTool.pm:2966): the uppercased, TIF→TIFF extension.
    let ext = self.ext.as_deref();
    // ExifTool.pm:9684 `$fileType or $fileType = $baseType`.
    let mut ft: &str = file_type.unwrap_or(base_type);
    // ExifTool.pm:9686-9692 — handle sub-types identified by extension.
    // `not $$self{DOC_NUM}` is always true on this read path (DOC_NUM is
    // never set; consistent with the first-call-wins note above).
    if let Some(ext) = ext {
      // ExifTool.pm:9686 `if (defined $ext and $ext ne $fileType ...)`.
      if ext != ft {
        // ExifTool.pm:9687-9688 `my ($f,$e) = @fileTypeLookup{$fileType,
        // $ext}; if (ref $f eq 'ARRAY' and ref $e eq 'ARRAY' and $$f[0] eq
        // $$e[0])`. `file_type_lookup_root` is `Some($$X[0]-as-string)`
        // ONLY for a single-type row and `None` for a multi row (Perl
        // `$$X[0]` is then an arrayref, never string-`eq`) or a string
        // alias / absent key (Perl `ref` test fails) — so this `==` of two
        // `Some` values is exactly the Perl triple-condition.
        let f = crate::filetype::file_type_lookup_root(ft);
        let e = crate::filetype::file_type_lookup_root(ext);
        if let (Some(fr), Some(er)) = (f, e) {
          if fr == er {
            // ExifTool.pm:9690 `$fileType = $ext if $$f[0] eq $fileType or
            // not $fileTypeLookup{$$f[0]}` — make sure $fileType was a root
            // type and not another sub-type. ($$f[0] == `fr`.)
            if fr == ft || !crate::filetype::file_type_lookup_defined(fr) {
              ft = ext;
            }
          }
        }
      }
    }
    // ExifTool.pm:9693 `$mimeType or $mimeType = $mimeType{$fileType}`.
    let mut mime = mime.or_else(|| mime_type(ft));
    // ExifTool.pm:9695 `$mimeType = $mimeType{$baseType} unless $mimeType
    // or $baseType eq 'TIFF'` — base file type MIME fallback (TIFF is a
    // special case: many sub-types share base TIFF, so it is excluded).
    if mime.is_none() && base_type != "TIFF" {
      mime = mime_type(base_type);
    }
    // ExifTool.pm:9696-9699 `unless (defined $normExt) { $normExt =
    // $fileTypeExt{$fileType}; $normExt = $fileType unless defined }`.
    let norm_ext = norm_ext.or_else(|| file_type_ext(ft)).unwrap_or(ft);
    // ExifTool.pm:9702 FoundTag('FileType', $fileType).
    self.meta.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str(ft.into()),
    );
    // ExifTool.pm:9703 FoundTag('FileTypeExtension', uc $normExt) — stored
    // uppercased, then PrintConv `lc` (ExifTool.pm:1433): lc on, raw uc -n.
    let shown = apply(
      &FILE_TYPE_EXT,
      &TagValue::Str(norm_ext.to_uppercase().into()),
      self.print_conv_enabled,
    );
    self
      .meta
      .push(Group::new("File", "File"), "FileTypeExtension", shown);
    // ExifTool.pm:9704 FoundTag('MIMEType', $mimeType || 'application/unknown').
    self.meta.push(
      Group::new("File", "File"),
      "MIMEType",
      TagValue::Str(mime.unwrap_or("application/unknown").into()),
    );
    // ExifTool.pm:9701 `$$self{FileType} = $fileType` — engage first-call-
    // wins. Faithfully recorded by the File:FileType push above (read via
    // [`Metadata::has_file_type`] on the next call); no separate per-
    // context bool, so a fresh `ParseContext` for the NEXT candidate also
    // sees the marker (file-scoped, ExifTool.pm:9681 `$$self{FileType}`).
  }

  /// Faithful `OverrideFileType` (ExifTool.pm:9712-9730). Overwrites the
  /// `File:FileType` / `File:FileTypeExtension` / `File:MIMEType` *values in
  /// place* (`$$self{VALUE}{$tag} = ...`, ExifTool.pm:9717,9722,9724) — it
  /// does NOT append new tags, so there is never a duplicate `File:*`.
  ///
  /// No-op (ExifTool.pm:9715 `if defined $$self{VALUE}{FileType} and
  /// $fileType ne $$self{VALUE}{FileType}`) when `File:FileType` is absent
  /// (nothing to override) or already equals `file_type`.
  pub fn override_file_type(
    &mut self,
    file_type: &str,
    mime: Option<&str>,
    norm_ext: Option<&str>,
  ) {
    let file_grp = Group::new("File", "File");
    // ExifTool.pm:9715 guard: locate the existing File:FileType value; if
    // absent OR already == $fileType, do nothing.
    let current = self
      .meta
      .tags()
      .iter()
      .find(|t| t.group() == &file_grp && t.name() == "FileType")
      .map(|t| t.value().clone());
    match current {
      Some(TagValue::Str(ref cur)) if cur.as_str() == file_type => return,
      Some(_) => {}
      None => return,
    }
    // ExifTool.pm:9718-9720 `unless (defined $normExt) { $normExt =
    // $fileTypeExt{$fileType}; $normExt = $fileType unless defined }`.
    let norm_ext = norm_ext
      .or_else(|| file_type_ext(file_type))
      .unwrap_or(file_type);
    // ExifTool.pm:9723 `$mimeType or $mimeType = $mimeType{$fileType}`.
    let mime = mime.or_else(|| mime_type(file_type));
    // ExifTool.pm:9717 `$$self{VALUE}{FileType} = $fileType` (in place).
    self
      .meta
      .set_tag_value(&file_grp, "FileType", TagValue::Str(file_type.into()));
    // ExifTool.pm:9722 `$$self{VALUE}{FileTypeExtension} = uc $normExt`
    // (stored uc, then PrintConv `lc`, ExifTool.pm:1433).
    let shown = apply(
      &FILE_TYPE_EXT,
      &TagValue::Str(norm_ext.to_uppercase().into()),
      self.print_conv_enabled,
    );
    self
      .meta
      .set_tag_value(&file_grp, "FileTypeExtension", shown);
    // ExifTool.pm:9724 `$$self{VALUE}{MIMEType} = $mimeType if $mimeType`
    // — only overwrite MIMEType when a MIME type is known.
    if let Some(mime) = mime {
      self
        .meta
        .set_tag_value(&file_grp, "MIMEType", TagValue::Str(mime.into()));
    }
    // ExifTool.pm:9725-9729 Verbose [override] VPrint block not modelled
    // (no Verbose option; consistent with existing deferrals).
  }
}

/// One ported format parser. `process` reads `ctx.data()` and may push tags
/// / call `ctx.set_file_type(...)` / push warnings/errors via `ctx.metadata()`.
/// Returning `true` (Perl `return 1`) finalizes this file type; returning
/// `false` (Perl `return 0`) lets `extract_info` try the next detection
/// candidate. **Side effects already made on `ctx.metadata()` PERSIST
/// regardless of return value** — faithful to ExifTool's `$self` model.
// `Sync` is required so `&'static dyn FormatParser` can be returned/shared.
pub trait FormatParser: Sync {
  /// Returns `true` if this parser accepted the data (Perl `return 1`).
  /// Returns `false` (Perl `return 0`) so `extract_info` tries the next
  /// candidate.
  ///
  /// IMPORTANT: `false` means only **"keep scanning"** — any side effects
  /// already made on `ctx.metadata()` (tags, `set_file_type`, warnings,
  /// errors) PERSIST. Each parser MUST mirror its Perl module's exact
  /// ordering of `SetFileType`/`FoundTag`/`Warn`/`Error` calls and the
  /// `return 0` line; e.g. `MPEG.pm:675 $et->SetFileType()` then `:678
  /// $raf->Read(...) or return 0;` on a short read — bundled `perl
  /// exiftool` emits the `File:FileType=MPEG` triplet plus the post-loop
  /// `ExifTool:Error`, and exifast matches byte-exact because of this
  /// contract.
  ///
  /// On accept, call `ctx.set_file_type(...)` BEFORE pushing any format
  /// tags via `ctx.metadata()` — faithful to ExifTool, where
  /// `$et->SetFileType` precedes `ProcessDirectory` (e.g. `AAC.pm:107`
  /// before `:109`). Output tag order follows push order; `File:*` must
  /// precede format-specific tags.
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool;
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

// Test-only parser-lookup override seam. `parser_for` (formats/mod.rs) is a
// fixed `match` keyed on the real file-type string, and no real ported
// format errors-while-accepting or set-file-type-then-rejects, so these
// scenarios cannot be exercised end-to-end by any real input. This
// thread-local lets a test register one OR MORE injected parsers (one per
// file type); `lookup_parser` consults it FIRST, so `extract_info` runs its
// genuine candidate→process(&mut m)→finalize block with that parser,
// against the real outer `Metadata`. A `Vec` (not `Option`) because the
// file-scoped first-call-wins-across-candidates test needs to inject TWO
// distinct file types in one run (one for the early candidate, one for a
// later candidate from the same `detection_candidates` iterator).
//
// `#[cfg(test)]`-gated: it does not exist in, and adds zero surface to, the
// production/release build (`cargo build --release` is byte-identical to
// pre-seam). No `pub`.
#[cfg(test)]
thread_local! {
  static INJECTED_PARSERS: std::cell::RefCell<
    Vec<(&'static str, &'static dyn FormatParser)>,
  > = const { std::cell::RefCell::new(Vec::new()) };
}

/// Parser lookup for [`extract_info`]. Production: exactly [`parser_for`].
/// Under `#[cfg(test)]` the [`INJECTED_PARSERS`] table is consulted first —
/// see the seam comment above for why and how. First matching entry wins,
/// so a test can override a real ported file type if it needs to.
#[cfg(test)]
fn lookup_parser(file_type: &str) -> Option<&'static dyn FormatParser> {
  let injected = INJECTED_PARSERS.with(|c| {
    c.borrow()
      .iter()
      .find(|(ft, _)| *ft == file_type)
      .map(|(_, p)| *p)
  });
  if let Some(parser) = injected {
    return Some(parser);
  }
  parser_for(file_type)
}

#[cfg(not(test))]
fn lookup_parser(file_type: &str) -> Option<&'static dyn FormatParser> {
  parser_for(file_type)
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
#[must_use]
pub fn extract_info(name: &str, data: &[u8], print_conv_enabled: bool) -> Metadata {
  let mut m = Metadata::new(name);
  m.push(
    Group::new("ExifTool", "ExifTool"),
    "ExifToolVersion",
    TagValue::Str(EXIFTOOL_VERSION.into()),
  );
  // ExifTool.pm:2966 `$$self{FILE_EXT} = GetFileExtension($realname)` —
  // set ONCE per file (before the candidate loop), then read as `$ext` by
  // every `SetFileType` call (ExifTool.pm:9683). Derived via the SAME
  // normalizer the detection path uses (no second extension parser).
  let file_ext = crate::filetype::file_ext_for_name(name);
  // ExifTool's `$type` bookkeeping (ExifTool.pm:3080 `not defined $type`):
  // `true` once a candidate is finalized — either a parser accepted
  // (ExifTool.pm:3068 `if ($result) { ... last }`) or the unsupported
  // terminal ran (ExifTool.pm:3054-3057 SetFileType+Warn, `$type` is set).
  // While false at loop end, ExifTool runs the post-loop Error block.
  let mut finalized = false;
  // Unknown-header path (ExifTool.pm:3025-3076 "last ditch effort to scan
  // past unknown header for JPEG/TIFF") is hardcoded to JPEG/TIFF magic
  // only — `(\xff\xd8\xff|MM\0\x2a|II\x2a\0)`, with `$type` ∈ {JPEG,TIFF};
  // NO Phase-2 audio/video format reaches it. `cand.header_skip()`/
  // `after_unknown_header()` already carry the context to the parser; the
  // extract_info-side Warn (`Processing $type-like data after unknown
  // $skip-byte header`) + post-accept DeleteTag(FileType/FileTypeExtension/
  // MIMEType) cascade is faithfully deferred to the first JPEG/TIFF port
  // (Stage 2+) — derive from the real consumer + oracle golden, same
  // incremental-derivation discipline as D11 conversion context.
  for cand in detection_candidates(name, data) {
    let ft = cand.file_type();
    // ExifTool.pm:3046-3057: `%moduleName{$type} eq '0'` ⇒ recognized but
    // UNSUPPORTED. `$self->SetFileType(); $self->Warn('Unsupported file
    // type'); last;` — terminal: no parser runs, loop stops. `$type` is
    // set, so the post-loop Error block does NOT fire.
    if crate::filetype::module_for_type(ft).is_unsupported() {
      {
        // Scope ctx so the &mut m borrow is released before push_warning.
        let mut ctx = ParseContext::new(
          data,
          ft,
          cand.header_skip(),
          cand.parent_type(),
          file_ext.clone(),
          print_conv_enabled,
          &mut m,
        );
        ctx.set_file_type(None, None, None); // ExifTool.pm:3055 $self->SetFileType()
      }
      m.push_warning("Unsupported file type"); // ExifTool.pm:3056 $self->Warn(...)
      finalized = true; // ExifTool.pm:3037 $$self{FILE_TYPE}=$type (defined)
      break; // ExifTool.pm:3057 last
    }
    // `lookup_parser` ≡ `parser_for(ft)` in release (test seam compiled
    // out; see above) — kept identical so tests exercise THIS block.
    let Some(parser) = lookup_parser(ft) else {
      continue;
    };
    // Faithful to Perl `&$func($self, \%dirInfo)` (ExifTool.pm:3066):
    // the parser operates DIRECTLY on the per-file `$self` value sink, so
    // every side effect (SetFileType, FoundTag, Warn, Error) PERSISTS
    // regardless of the return value. The canonical example is MPEG.pm:
    // 675 `$et->SetFileType()` followed by MPEG.pm:678 `$raf->Read(...)
    // or return 0` — a too-short MPEG keeps its File:* tags even though
    // ProcessMPEG returned 0. Bundled `perl exiftool` on a 4-byte MPEG
    // emits `File:FileType=MPEG` + the post-loop `ExifTool:Error`
    // simultaneously. Rolling back via a throwaway `trial` Metadata
    // would silently drop those File:* tags — divergent. So borrow
    // `&mut m` directly; the lexical scope drops the borrow before the
    // next iteration.
    let accepted = {
      let mut ctx = ParseContext::new(
        data,
        ft,
        cand.header_skip(),
        cand.parent_type(),
        file_ext.clone(),
        print_conv_enabled,
        &mut m,
      );
      parser.process(&mut ctx)
    };
    if accepted {
      // Finalization is keyed on the parser returning truthy
      // (`$result` ⇒ `last`, ExifTool.pm:3066-3070) — exactly as the
      // post-loop finalization Error is gated by `not defined $type`
      // (ExifTool.pm:3080), NOT by `SetFileType`. A parser that returns
      // true WITHOUT `set_file_type` is faithful (its tags/errors emit;
      // no `File:*`, no finalization Error). Do NOT add a
      // `file_type_set` gate here: that would diverge from bundled
      // ExifTool (emit an `ExifTool:Error` it does not).
      finalized = true; // ExifTool.pm:3068 `if ($result) { ... last }`
      break;
    }
    // Rejection ⇒ side effects on `m` persist (faithful to Perl: no
    // rollback). The candidate loop tries the next candidate.
  }
  // ExifTool.pm:3080-3128: `if (not $err and not defined $type and not
  // $$self{DOC_NUM})` — nothing finalized ⇒ compute & emit the Error.
  // (No `$err` is possible above on this read path, and `$$self{DOC_NUM}`
  // is never set: the only condition is "nothing finalized".)
  if !finalized {
    if let Some(err) = finalization_error(name, data) {
      m.push_error(err); // ExifTool.pm:3127 `$self->Error($err)` (:5648)
    }
  }
  m
}

#[cfg(test)]
mod tests {
  use super::*;

  fn names(m: &Metadata) -> Vec<(String, String, TagValue)> {
    m.tags()
      .iter()
      .map(|t| {
        (
          t.group().family1().to_string(),
          t.name().to_string(),
          t.value().clone(),
        )
      })
      .collect()
  }

  /// A throwaway `ParseContext` over a fresh `Metadata` for the
  /// `set_file_type`/`override_file_type` unit tests (the parser-driven
  /// finalization in isolation). `$ext` is derived from the metadata's
  /// file name via the real `GetFileExtension` (faithful to ExifTool.pm:
  /// 2966) — e.g. `Metadata::new("x.aac")` ⇒ `$ext = "AAC"`,
  /// `Metadata::new("x")` ⇒ `$ext = None`.
  fn ctx_over<'a>(meta: &'a mut Metadata, ft: &'a str, print_on: bool) -> ParseContext<'a> {
    let ext = crate::filetype::file_ext_for_name(meta.source_file());
    ParseContext::new(&[], ft, 0, ft, ext, print_on, meta)
  }

  /// Like [`ctx_over`] but with an explicit `$ext` (`$$self{FILE_EXT}`),
  /// for the ExifTool.pm:9686-9692 sub-type-by-ext block tests.
  fn ctx_with_ext<'a>(
    meta: &'a mut Metadata,
    ft: &'a str,
    ext: Option<&str>,
    print_on: bool,
  ) -> ParseContext<'a> {
    ParseContext::new(&[], ft, 0, ft, ext.map(SmolStr::new), print_on, meta)
  }

  #[test]
  fn set_file_type_pseudo_tags_print_on() {
    let mut m = Metadata::new("x.aac");
    ctx_over(&mut m, "AAC", true).set_file_type(None, None, None);
    assert_eq!(
      names(&m),
      vec![
        (
          "File".into(),
          "FileType".into(),
          TagValue::Str("AAC".into())
        ),
        (
          "File".into(),
          "FileTypeExtension".into(),
          TagValue::Str("aac".into())
        ),
        (
          "File".into(),
          "MIMEType".into(),
          TagValue::Str("audio/aac".into())
        ),
      ]
    );
  }

  #[test]
  fn file_type_extension_is_raw_uppercase_under_n() {
    let mut m = Metadata::new("x.aac");
    ctx_over(&mut m, "AAC", false).set_file_type(None, None, None);
    let ext = m
      .tags()
      .iter()
      .find(|t| t.name() == "FileTypeExtension")
      .unwrap();
    assert_eq!(ext.value(), &TagValue::Str("AAC".into())); // -n: raw uc
  }

  #[test]
  fn mime_fallback_is_application_unknown() {
    let mut m = Metadata::new("x");
    // Detected type "XYZ" has no %mimeType / %fileTypeExt key.
    ctx_over(&mut m, "XYZ", true).set_file_type(None, None, None);
    let mime = m.tags().iter().find(|t| t.name() == "MIMEType").unwrap();
    assert_eq!(mime.value(), &TagValue::Str("application/unknown".into()));
  }

  #[test]
  fn set_file_type_first_call_wins() {
    // ExifTool.pm:9681 `unless ($$self{FileType} and not $$self{DOC_NUM})`:
    // a second SetFileType call for the main document is ignored.
    let mut m = Metadata::new("x");
    {
      let mut c = ctx_over(&mut m, "AAC", true);
      c.set_file_type(None, None, None);
      c.set_file_type(Some("PNG"), Some("image/png"), Some("png"));
    }
    // The 2nd call must have been a no-op: still AAC, no extra File:* tags.
    assert_eq!(
      names(&m),
      vec![
        (
          "File".into(),
          "FileType".into(),
          TagValue::Str("AAC".into())
        ),
        (
          "File".into(),
          "FileTypeExtension".into(),
          TagValue::Str("aac".into())
        ),
        (
          "File".into(),
          "MIMEType".into(),
          TagValue::Str("audio/aac".into())
        ),
      ]
    );
  }

  #[test]
  fn override_file_type_replaces_in_place() {
    // Faithful OverrideFileType (ExifTool.pm:9712-9730): the three File:*
    // VALUES are overwritten in place — NOT duplicated.
    let mut m = Metadata::new("x");
    {
      let mut c = ctx_over(&mut m, "AAC", true);
      c.set_file_type(None, None, None); // File:* = AAC / aac / audio/aac
      c.override_file_type("MP4", Some("video/mp4"), None);
    }
    assert_eq!(
      names(&m),
      vec![
        (
          "File".into(),
          "FileType".into(),
          TagValue::Str("MP4".into())
        ),
        (
          "File".into(),
          "FileTypeExtension".into(),
          TagValue::Str("mp4".into())
        ),
        (
          "File".into(),
          "MIMEType".into(),
          TagValue::Str("video/mp4".into())
        ),
      ]
    );
    // Exactly one of each File:* tag — values overwritten, not appended.
    assert_eq!(
      m.tags().iter().filter(|t| t.name() == "FileType").count(),
      1
    );
    assert_eq!(
      m.tags()
        .iter()
        .filter(|t| t.name() == "FileTypeExtension")
        .count(),
      1
    );
    assert_eq!(
      m.tags().iter().filter(|t| t.name() == "MIMEType").count(),
      1
    );
  }

  #[test]
  fn override_file_type_noop_when_filetype_absent() {
    // ExifTool.pm:9715 `if defined $$self{VALUE}{FileType}` — with no prior
    // SetFileType there is nothing to override.
    let mut m = Metadata::new("x");
    ctx_over(&mut m, "AAC", true).override_file_type("MP4", Some("video/mp4"), None);
    assert!(m.tags().is_empty());
  }

  #[test]
  fn override_file_type_noop_when_equal() {
    // ExifTool.pm:9715 `$fileType ne $$self{VALUE}{FileType}` — overriding
    // to the same type is a no-op (and must not duplicate File:*).
    let mut m = Metadata::new("x");
    {
      let mut c = ctx_over(&mut m, "AAC", true);
      c.set_file_type(None, None, None);
      c.override_file_type("AAC", Some("audio/aac"), None);
    }
    assert_eq!(
      names(&m),
      vec![
        (
          "File".into(),
          "FileType".into(),
          TagValue::Str("AAC".into())
        ),
        (
          "File".into(),
          "FileTypeExtension".into(),
          TagValue::Str("aac".into())
        ),
        (
          "File".into(),
          "MIMEType".into(),
          TagValue::Str("audio/aac".into())
        ),
      ]
    );
  }

  #[test]
  fn override_file_type_keeps_mime_when_none_known() {
    // ExifTool.pm:9724 `$$self{VALUE}{MIMEType} = $mimeType if $mimeType`
    // — when neither the argument nor %mimeType yields a MIME, the existing
    // MIMEType is left untouched (FileType/FileTypeExtension still change).
    let mut m = Metadata::new("x");
    {
      let mut c = ctx_over(&mut m, "AAC", true);
      c.set_file_type(None, None, None); // MIMEType = audio/aac
                                         // "XYZ" has no %mimeType key and we pass mime=None.
      c.override_file_type("XYZ", None, None);
    }
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("XYZ".into()));
    let mime = m.tags().iter().find(|t| t.name() == "MIMEType").unwrap();
    // unchanged — `if $mimeType` was false.
    assert_eq!(mime.value(), &TagValue::Str("audio/aac".into()));
  }

  /// `BZh91AY&SY` satisfies `%magicNumber{BZ2}` (ExifTool.pm:940); BZ2 is
  /// `%moduleName{BZ2}=0` (ExifTool.pm:858) ⇒ unsupported-terminal branch
  /// (ExifTool.pm:3054-3057): SetFileType + Warn + stop.
  #[test]
  fn unsupported_type_sets_filetype_and_warning_then_stops() {
    // %magicNumber{BZ2} = `BZh[1-9]\x31\x41\x59\x26\x53\x59` (ExifTool.pm:940);
    // prefix-only — trailing bytes are inert padding.
    let bz2_magic: &[u8] = b"BZh91AY\x26SY\x00\x00";
    let m = extract_info("x.bz2", bz2_magic, true);
    // Must have File:FileType == "BZ2" (SetFileType ran).
    let ft = m
      .tags()
      .iter()
      .find(|t| t.name() == "FileType")
      .expect("File:FileType must be set");
    assert_eq!(ft.value(), &TagValue::Str("BZ2".into()));
    // Must have ExifTool:Warning == "Unsupported file type".
    assert_eq!(
      m.warnings(),
      &[smol_str::SmolStr::new("Unsupported file type")],
      "must have exactly the Warn string from ExifTool.pm:3056"
    );
    // Terminal stop: only ExifToolVersion + File:{FileType,FileTypeExtension,
    // MIMEType} — no format-specific tags beyond those four.
    let extra: Vec<_> = m
      .tags()
      .iter()
      .filter(|t| {
        !(t.name() == "ExifToolVersion"
          || t.name() == "FileType"
          || t.name() == "FileTypeExtension"
          || t.name() == "MIMEType")
      })
      .collect();
    assert!(
      extra.is_empty(),
      "terminal stop: no extra tags beyond version + File:* expected, got: {:?}",
      extra
    );
  }

  #[test]
  fn empty_input_emits_faithful_file_is_empty_error() {
    // ExifTool.pm:3080-3128: nothing finalized + `not length $buff` ⇒
    // `$self->Error('File is empty')` (ExifTool.pm:3086). Bundled
    // `perl exiftool -j -G1 -struct Empty.dat` ⇒ ExifTool:Error
    // "File is empty" (oracle-captured 2026-05-19).
    let m = extract_info("Empty.dat", &[], true);
    assert_eq!(
      names(&m),
      vec![(
        "ExifTool".into(),
        "ExifToolVersion".into(),
        TagValue::Str("13.58".into())
      )]
    );
    assert_eq!(
      m.errors(),
      &[smol_str::SmolStr::new("File is empty")],
      "ExifTool.pm:3086"
    );
    assert!(m.warnings().is_empty(), "no Warning on the empty path");
  }

  #[test]
  fn all_zero_32_bytes_emits_faithful_all_same_byte_insight() {
    // ExifTool.pm:3097-3122: buff ≥ 16 AND every byte == $ch (\0); the
    // whole file is $ch ⇒ $num undef ⇒ 'Entire file is' + ' binary
    // zeros'. Bundled `perl exiftool` on a 32-\0 file ⇒ ExifTool:Error
    // "Entire file is binary zeros" (oracle-captured 2026-05-19).
    let m = extract_info("allzero.dat", &[0u8; 32], true);
    assert_eq!(
      m.errors(),
      &[smol_str::SmolStr::new("Entire file is binary zeros")],
      "ExifTool.pm:3111,3115"
    );
    // The post-loop Error path emits no FileType (nothing finalized).
    assert_eq!(
      names(&m),
      vec![(
        "ExifTool".into(),
        "ExifToolVersion".into(),
        TagValue::Str("13.58".into())
      )]
    );
  }

  #[test]
  fn unknown_type_emits_faithful_unknown_file_type_error() {
    // ExifTool.pm:3089-3095: buff < 16 (8 bytes) ⇒ the not-all-same arm;
    // `mystery.xyz` has no recognized type ⇒ 'Unknown file type'.
    // Bundled `perl exiftool` ⇒ ExifTool:Error "Unknown file type".
    let m = extract_info("mystery.xyz", b"\x51\x7a\x2b\x6d\x09\x44\x1e\x77", true);
    assert_eq!(
      m.errors(),
      &[smol_str::SmolStr::new("Unknown file type")],
      "ExifTool.pm:3095"
    );
  }

  #[test]
  fn malformed_aac_emits_faithful_file_format_error() {
    // `\xff\xf1` passes the AAC %magicNumber gate (filetype_data.rs:530)
    // so AAC is a candidate, but the sampling-frequency index 0xf > 12
    // makes `ProcessAAC` reject (aac.rs:111, AAC.pm:103). `.aac` is a
    // known type ⇒ 'File format error' (ExifTool.pm:3093). Bundled
    // `perl exiftool bad.aac` ⇒ ExifTool:Error "File format error".
    let m = extract_info("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00\x00\x00\x00", true);
    assert_eq!(
      m.errors(),
      &[smol_str::SmolStr::new("File format error")],
      "ExifTool.pm:3093 (.aac known, ProcessAAC rejected)"
    );
    // Reject ⇒ no File:* finalized; only version + the Error.
    assert_eq!(
      names(&m),
      vec![(
        "ExifTool".into(),
        "ExifToolVersion".into(),
        TagValue::Str("13.58".into())
      )]
    );
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
    // ≥3 OTHER types: no-arg SetFileType (file_type/mime/norm_ext all
    // None) ⇒ File:* exactly the bundled-`perl exiftool` values. The
    // detected type == base type (no ext divergence) so the sub-type
    // block is inert; this validates the %mimeType / %fileTypeExt seam
    // for the fan-out. (group, normExt-shown-lc, MIME) per the bundled
    // tool (oracle 2026-05-19):
    //   FLAC ⇒ flac / audio/flac     MP3  ⇒ mp3 / audio/mpeg
    //   JPEG ⇒ jpg  / image/jpeg     M2TS ⇒ mts / video/m2ts
    //   MPEG ⇒ mpg  / video/mpeg
    for (ft, want_ext_lc, want_mime) in [
      ("FLAC", "flac", "audio/flac"),
      ("MP3", "mp3", "audio/mpeg"),
      ("JPEG", "jpg", "image/jpeg"), // %fileTypeExt key ⇒ normExt=jpg
      ("M2TS", "mts", "video/m2ts"), // %fileTypeExt key ⇒ normExt=mts
      ("MPEG", "mpg", "video/mpeg"), // %fileTypeExt key ⇒ normExt=mpg
    ] {
      let mut m = Metadata::new("x");
      ctx_over(&mut m, ft, true).set_file_type(None, None, None);
      let pick = |n: &str| {
        m.tags()
          .iter()
          .find(|t| t.name() == n)
          .map(|t| t.value().clone())
      };
      assert_eq!(pick("FileType"), Some(TagValue::Str(ft.into())), "{ft}");
      assert_eq!(
        pick("FileTypeExtension"),
        Some(TagValue::Str(want_ext_lc.into())),
        "{ft} FileTypeExtension (PrintConv lc)"
      );
      assert_eq!(
        pick("MIMEType"),
        Some(TagValue::Str(want_mime.into())),
        "{ft} MIMEType"
      );
    }
  }

  #[test]
  fn set_file_type_subtype_by_ext_promotes_to_extension() {
    // ExifTool.pm:9686-9692: detected base TIFF, but a TIFF-rooted RAW
    // extension ⇒ $fileType is promoted to the extension and MIME comes
    // from the extension's own %mimeType. This is the canonical bundled
    // behavior: a TIFF-magic file named *.nef ⇒ File:FileType=NEF,
    // FileTypeExtension=nef, MIMEType=image/x-nikon-nef (oracle: bundled
    // `perl exiftool` on a II*\0 file with each extension, 2026-05-19).
    //   %fileTypeLookup{TIFF}=['TIFF',..], {NEF}=['TIFF',..] (Single,
    //   roots both 'TIFF' ⇒ eq); $$f[0]=='TIFF'==$fileType ⇒ promote.
    for (ext, want_type, want_ext_lc, want_mime) in [
      ("NEF", "NEF", "nef", "image/x-nikon-nef"), // ExifTool.pm:741
      ("CR2", "CR2", "cr2", "image/x-canon-cr2"), // ExifTool.pm:637
      ("DNG", "DNG", "dng", "image/x-adobe-dng"), // ExifTool.pm:652
      ("ARW", "ARW", "arw", "image/x-sony-arw"),  // ExifTool.pm:628
      ("3FR", "3FR", "3fr", "image/x-hasselblad-3fr"), // ExifTool.pm:617
    ] {
      let mut m = Metadata::new("x");
      // base/detected type = "TIFF"; $ext = the RAW extension.
      ctx_with_ext(&mut m, "TIFF", Some(ext), true).set_file_type(None, None, None);
      let pick = |n: &str| {
        m.tags()
          .iter()
          .find(|t| t.name() == n)
          .map(|t| t.value().clone())
      };
      assert_eq!(
        pick("FileType"),
        Some(TagValue::Str(want_type.into())),
        "{ext}: promoted FileType"
      );
      assert_eq!(
        pick("FileTypeExtension"),
        Some(TagValue::Str(want_ext_lc.into())),
        "{ext}: FileTypeExtension"
      );
      assert_eq!(
        pick("MIMEType"),
        Some(TagValue::Str(want_mime.into())),
        "{ext}: MIMEType from promoted type's %mimeType"
      );
    }
    // ext == fileType (TIFF/.tif) ⇒ NO promotion, plain TIFF (oracle:
    // II*\0 named .tif ⇒ TIFF / tif / image/tiff).
    let mut m = Metadata::new("x");
    ctx_with_ext(&mut m, "TIFF", Some("TIFF"), true).set_file_type(None, None, None);
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value().clone()),
      Some(TagValue::Str("TIFF".into()))
    );
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "MIMEType")
        .map(|t| t.value().clone()),
      Some(TagValue::Str("image/tiff".into()))
    );
  }

  #[test]
  fn set_file_type_subtype_by_ext_no_promote_when_roots_differ() {
    // ExifTool.pm:9688 `$$f[0] eq $$e[0]` must hold. PNG's lookup root is
    // 'PNG' and JPEG's is 'JPEG' (Single rows, different roots) ⇒ NO
    // promotion: detected PNG with $ext=JPEG stays PNG (faithful: the
    // condition is false, so $fileType is untouched).
    let mut m = Metadata::new("x");
    ctx_with_ext(&mut m, "PNG", Some("JPEG"), true).set_file_type(None, None, None);
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value().clone()),
      Some(TagValue::Str("PNG".into())),
      "roots differ ⇒ no sub-type promotion"
    );
    // A multi-row extension can never promote: %fileTypeLookup{AI} is
    // [['PDF','PS'],..] so Perl `$$e[0]` is an arrayref (never string-
    // `eq`). Detected PDF + $ext=AI ⇒ stays PDF.
    let mut m2 = Metadata::new("x");
    ctx_with_ext(&mut m2, "PDF", Some("AI"), true).set_file_type(None, None, None);
    assert_eq!(
      m2.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value().clone()),
      Some(TagValue::Str("PDF".into())),
      "multi-row ext ⇒ $$e[0] is arrayref ⇒ no promotion"
    );
  }

  #[test]
  fn set_file_type_base_mime_fallback_and_tiff_exclusion() {
    // ExifTool.pm:9695 `$mimeType = $mimeType{$baseType} unless $mimeType
    // or $baseType eq 'TIFF'`. Synthetic: detected base = "AAC" (has a
    // %mimeType: audio/aac) but caller passes an explicit fileType "XYZ"
    // that has NO %mimeType and no %fileTypeExt. The sub-type block does
    // not fire (no ext); $mimeType{XYZ} is None ⇒ fall back to
    // $mimeType{baseType=AAC} = "audio/aac".
    let mut m = Metadata::new("x");
    // base type = "AAC"; explicit fileType arg "XYZ" (no %mimeType).
    ctx_over(&mut m, "AAC", true).set_file_type(Some("XYZ"), None, None);
    let pick = |mm: &Metadata, n: &str| {
      mm.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    assert_eq!(pick(&m, "FileType"), Some(TagValue::Str("XYZ".into())));
    assert_eq!(
      pick(&m, "MIMEType"),
      Some(TagValue::Str("audio/aac".into())),
      "ExifTool.pm:9695 base-type MIME fallback (baseType AAC)"
    );
    // The `$baseType eq 'TIFF'` exclusion: base = "TIFF", explicit
    // fileType "XYZ" (no %mimeType, no %fileTypeExt). Fallback is
    // SUPPRESSED ⇒ MIMEType stays application/unknown (NOT image/tiff).
    let mut m2 = Metadata::new("x");
    ctx_over(&mut m2, "TIFF", true).set_file_type(Some("XYZ"), None, None);
    assert_eq!(pick(&m2, "FileType"), Some(TagValue::Str("XYZ".into())));
    assert_eq!(
      pick(&m2, "MIMEType"),
      Some(TagValue::Str("application/unknown".into())),
      "ExifTool.pm:9695 `unless ... $baseType eq 'TIFF'` exclusion"
    );
    // Sanity: with base "TIFF" and NO override (plain TIFF), $mimeType
    // {fileType=TIFF} is image/tiff directly (the exclusion only matters
    // when $mimeType{fileType} is undef).
    let mut m3 = Metadata::new("x");
    ctx_over(&mut m3, "TIFF", true).set_file_type(None, None, None);
    assert_eq!(
      pick(&m3, "MIMEType"),
      Some(TagValue::Str("image/tiff".into()))
    );
  }

  #[test]
  fn aac_fixture_matches_golden_print_on() {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/AAC.aac")).expect("fixture");
    let want =
      std::fs::read_to_string(format!("{root}/tests/golden/AAC.aac.json")).expect("golden");
    let got = crate::serialize::to_exiftool_json(&extract_info("AAC.aac", &data, true));
    crate::jsondiff::json_equivalent(&got, &want)
      .unwrap_or_else(|e| panic!("AAC -j -G1 -struct conformance: {}", e.message()));
  }

  #[test]
  fn aac_fixture_matches_golden_n() {
    let root = env!("CARGO_MANIFEST_DIR");
    let data = std::fs::read(format!("{root}/tests/fixtures/AAC.aac")).expect("fixture");
    let want =
      std::fs::read_to_string(format!("{root}/tests/golden/AAC.aac.n.json")).expect("golden");
    let got = crate::serialize::to_exiftool_json(&extract_info("AAC.aac", &data, false));
    crate::jsondiff::json_equivalent(&got, &want)
      .unwrap_or_else(|e| panic!("AAC -n conformance: {}", e.message()));
  }

  // ── An accepting parser's tags / warning / `ExifTool:Error` must
  // propagate through the REAL `extract_info` to the serialized JSON.
  //
  // ExifTool's `Process<Type>` may call `$et->Error('…')` (stored in
  // `$$self{VALUE}{Error}`) and still `return 1` — `Error` is emitted in
  // `-j` regardless of the module returning success. `parser_for`
  // (formats/mod.rs) is a fixed `match` keyed on the real file-type
  // string and no real ported format errors-while-accepting, so this test
  // uses the `#[cfg(test)]` [`INJECTED_PARSERS`] seam (consulted by
  // [`lookup_parser`], which `extract_info` calls in place of
  // `parser_for`): it registers an accepting-but-erroring parser for the
  // *real* `AAC` file type, then calls the genuine `extract_info`. An
  // `\xff\xf1` head passes the AAC `%magicNumber` gate (filetype_data.rs)
  // so `bad.aac` detects to `AAC`, the seam swaps in the injected parser,
  // and `extract_info` runs its real candidate→process(&mut m)→finalize
  // block against the outer Metadata directly (faithful to Perl
  // `&$func($self, \%dirInfo)`, ExifTool.pm:3066).
  struct AcceptingButErroring;
  impl FormatParser for AcceptingButErroring {
    fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
      // Faithful to every real accepting parser: `$et->SetFileType()`
      // BEFORE pushing format tags (e.g. AAC.pm:107). All-`None` = the
      // detected type (AAC.pm:107 no-arg style). Releases the &mut ctx
      // borrow before `ctx.metadata()` re-borrows below.
      ctx.set_file_type(None, None, None);
      // Push via the real `&mut Metadata` seam parsers reach through
      // `ctx.metadata()` (no public surface added for the test).
      let m = ctx.metadata();
      m.push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
      m.push_warning("a non-fatal warning");
      // ExifTool `$et->Error('File format error')` while still handling
      // the file (sets $$self{VALUE}{Error}), then `return 1`.
      m.push_error("File format error");
      true // Perl `return 1`
    }
  }

  /// RAII guard so the `#[cfg(test)]` injection table is always cleared —
  /// even on assertion panic — keeping this thread's seam state clean for
  /// any subsequent test (thread-locals are per-thread, but a panic must
  /// not leak overrides either way).
  struct InjectionGuard;
  impl Drop for InjectionGuard {
    fn drop(&mut self) {
      INJECTED_PARSERS.with(|c| c.borrow_mut().clear());
    }
  }

  /// Register one injected parser under `file_type` for the duration of the
  /// surrounding `InjectionGuard`. Multiple `inject` calls in one test stack
  /// (the file-scoped first-call-wins test uses TWO: an early file-type's
  /// parser AND a later file-type's parser — both from the same
  /// `detection_candidates` iterator on the same input).
  fn inject(file_type: &'static str, parser: &'static dyn FormatParser) {
    INJECTED_PARSERS.with(|c| c.borrow_mut().push((file_type, parser)));
  }

  static ACCEPTING_BUT_ERRORING: AcceptingButErroring = AcceptingButErroring;

  #[test]
  fn accepted_parser_error_reaches_serialized_json() {
    // Register the injected parser for the REAL detected file type.
    let _guard = InjectionGuard;
    inject("AAC", &ACCEPTING_BUT_ERRORING);

    // Drive the genuine `extract_info`: `\xff\xf1…` passes the AAC magic
    // gate ⇒ `bad.aac` detects to `AAC` ⇒ `lookup_parser("AAC")` returns
    // the injected parser ⇒ the REAL accepted-parser block runs against
    // the outer Metadata directly (no trial-merge).
    let meta = extract_info("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00", true);

    // The accepting parser's ExifTool:Error reached the outer Metadata
    // via direct `&mut Metadata` push (faithful Perl `$self->Error`).
    assert_eq!(
      meta.errors(),
      &[smol_str::SmolStr::new("File format error")],
      "accepting parser's ExifTool:Error must propagate through extract_info"
    );
    assert_eq!(
      meta.warnings(),
      &[smol_str::SmolStr::new("a non-fatal warning")],
      "accepting parser's warning must propagate through extract_info"
    );
    // And it survives serialization as the `ExifTool:Error` token,
    // alongside the parser-driven File:FileType (the parser called
    // SetFileType against the real outer Metadata), the pushed tag, and
    // the always-emitted version.
    let json = crate::serialize::to_exiftool_json(&meta);
    assert!(
      json.contains("\"ExifTool:Error\": \"File format error\""),
      "serialized JSON must carry ExifTool:Error, got: {json}"
    );
    assert!(
      json.contains("\"File:FileType\": \"AAC\""),
      "SetFileType against &mut m must emit File:FileType, got: {json}"
    );
    assert!(json.contains("\"AAC:Channels\": 2"), "got: {json}");
    assert!(
      json.contains("\"ExifTool:ExifToolVersion\": 13.58"),
      "got: {json}"
    );
  }

  // A parser that calls `SetFileType` and THEN rejects (returns false) —
  // faithful to MPEG.pm:675 `$et->SetFileType()` followed by MPEG.pm:678
  // `$raf->Read(...) or return 0`. Bundled Perl keeps the File:* tags
  // (the side effect is on `$self`, never rolled back). Same
  // [`INJECTED_PARSERS`] seam: registered for the real `AAC` file type so
  // an `\xff\xf1…` input detects to AAC, the seam swaps in this parser,
  // and `extract_info` runs its real candidate loop. Since the injected
  // parser is the ONLY candidate (no other real parser runs before it),
  // rejection exhausts the loop and the post-loop finalization Error
  // fires — yet `File:FileType=AAC` must remain (no rollback). This
  // FAILS the moment anyone re-introduces a trial-and-rollback model.
  struct RejectingAfterSetFileType;
  impl FormatParser for RejectingAfterSetFileType {
    fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
      // Faithful to MPEG.pm:675: `$et->SetFileType()` (no-arg ⇒ detected
      // type) BEFORE reading/rejecting.
      ctx.set_file_type(None, None, None);
      // Push one tag for assertion clarity — also a side effect that
      // must persist post-reject (faithful: `FoundTag` writes to
      // `$$self{VALUE}` directly).
      ctx
        .metadata()
        .push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
      // MPEG.pm:678 style `or return 0` — reject AFTER SetFileType.
      false
    }
  }

  static REJECTING_AFTER_SET_FILE_TYPE: RejectingAfterSetFileType = RejectingAfterSetFileType;

  #[test]
  fn rejecting_parser_set_file_type_side_effect_persists() {
    // Faithful Perl `$self` model: a rejecting `Process<Type>` that
    // already called `$et->SetFileType` leaves the File:* tags on
    // `$self`. Bundled `perl exiftool` on a too-short MPEG (`00 00 01
    // ba` named `.mpg`) emits BOTH:
    //   "ExifTool:Error":"File format error"
    //   "File:FileType":"MPEG"
    // simultaneously. The same pattern is exercised here via the
    // injected-parser seam against the real AAC file type, since
    // `parser_for` has no rejecting-after-SetFileType real parser yet.
    let _guard = InjectionGuard;
    inject("AAC", &REJECTING_AFTER_SET_FILE_TYPE);

    // `\xff\xf1…` passes the AAC magic gate ⇒ detects to AAC ⇒ the
    // injected parser runs ⇒ SetFileType pushes File:* THEN parser
    // returns false ⇒ post-loop finalization Error fires.
    let meta = extract_info("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00", true);
    let json = crate::serialize::to_exiftool_json(&meta);

    // The rejecting parser's SetFileType side effects PERSIST on the
    // outer Metadata (faithful Perl: no rollback).
    assert!(
      json.contains("\"File:FileType\": \"AAC\""),
      "rejecting parser's SetFileType side effect must persist (no rollback), got: {json}"
    );
    // And the pushed Channels tag persists too — every side effect of a
    // rejecting parser persists, not just SetFileType.
    assert!(
      json.contains("\"AAC:Channels\": 2"),
      "rejecting parser's pushed tag must persist (no rollback), got: {json}"
    );
    // Reject ⇒ post-loop finalization Error fires (ExifTool.pm:3080,
    // 3093 — `.aac` is a known type).
    assert!(
      json.contains("\"ExifTool:Error\": \"File format error\""),
      "post-loop finalization Error must fire on candidate-loop exhaustion, got: {json}"
    );
  }

  // An accepting parser that returns `true` but never calls
  // `set_file_type` (no real parser does this, but ExifTool's accept is
  // keyed ONLY on the truthy Process return). Same `INJECTED_PARSERS`
  // seam as Part B.
  struct AcceptingNoSetFileType;
  impl FormatParser for AcceptingNoSetFileType {
    fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
      // One tag, NO set_file_type, NO error — then `return 1`.
      ctx
        .metadata()
        .push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
      true // Perl `return 1`
    }
  }

  static ACCEPTING_NO_SET_FILE_TYPE: AcceptingNoSetFileType = AcceptingNoSetFileType;

  // Executable pin of the faithful finalization criterion: finalization
  // (and thus suppression of the post-loop Error) is keyed on the parser
  // returning truthy (`$result` ⇒ `last`, ExifTool.pm:3066-3070),
  // gated exactly like the post-loop Error's `not defined $type`
  // (ExifTool.pm:3080) — NOT on `SetFileType`. This FAILS if anyone
  // adopts the reviewer's unfaithful `file_type_set` gate.
  #[test]
  fn finalization_error_keyed_on_parser_accept_not_set_file_type() {
    // (a) Parser returns true WITHOUT set_file_type ⇒ its tag emits, and
    //     NO finalization ExifTool:Error and NO File:FileType (exifast's
    //     current faithful behavior; the regression guard vs the gate).
    let _guard = InjectionGuard;
    inject("AAC", &ACCEPTING_NO_SET_FILE_TYPE);
    // `\xff\xf1…` passes the AAC magic gate ⇒ `bad.aac` detects to
    // `AAC` ⇒ the injected parser runs and accepts (returns true).
    let meta = extract_info("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00", true);
    let json = crate::serialize::to_exiftool_json(&meta);
    // The parser's tag is present (it accepted and pushed it).
    assert!(json.contains("\"AAC:Channels\": 2"), "got: {json}");
    // Accept ⇒ post-loop finalization Error SUPPRESSED: no
    // ExifTool:Error and none of its `$err` strings (ExifTool.pm:3086-
    // 3122). Asserting on the JSON token AND each finalization phrase.
    assert!(
      !json.contains("\"ExifTool:Error\""),
      "parser-accept must suppress the finalization Error, got: {json}"
    );
    for phrase in [
      "File format error",
      "Unknown file type",
      "File is empty",
      "of file is",
      "Entire file is",
    ] {
      assert!(
        !json.contains(phrase),
        "no finalization-Error phrase ({phrase:?}) on parser-accept, got: {json}"
      );
    }
    // No SetFileType call ⇒ no `File:*` tags (faithful: SetFileType is
    // what emits them; accept does not imply it).
    assert!(
      !json.contains("\"File:FileType\""),
      "parser that skipped set_file_type emits no File:FileType, got: {json}"
    );

    // (b) The complementary case — a parser that REJECTS for a detected,
    //     otherwise-unhandled type ⇒ the post-loop finalization Error IS
    //     emitted (ExifTool.pm:3080 `not defined $type` ⇒ $err) — is
    //     already pinned through the REAL seam: the in-module
    //     `malformed_aac_emits_faithful_file_format_error` test and the
    //     `bad.aac` conformance golden (tests/conformance.rs:59-60 ⇒
    //     `"ExifTool:Error": "File format error"`). Not re-wired here:
    //     (a) is the decisive refutation of the `file_type_set` gate.
  }

  // The `SetFileType` first-call-wins guard is FILE-scoped
  // (`$$self{FileType}` on `$self`, ExifTool.pm:9681), NOT scoped to one
  // `Process<Type>` invocation. ExifTool's candidate loop reuses the same
  // `$self` across every candidate's `Process<Type>` call, so an early
  // candidate's `SetFileType` (e.g. `MPEG.pm:675` followed by a `return 0`
  // — see `RejectingAfterSetFileType` above) leaves `$$self{FileType}`
  // set; any LATER candidate's `SetFileType` is a no-op
  // (ExifTool.pm:9681).
  //
  // In exifast each candidate iteration constructs a fresh `ParseContext`,
  // and the first-call-wins gate MUST therefore be read off the shared
  // outer `Metadata` (via [`Metadata::has_file_type`]), not off a per-
  // `ParseContext` bool. A per-context bool resets each iteration ⇒
  // candidate 2's `set_file_type(...)` re-pushes a SECOND File:FileType /
  // FileTypeExtension / MIMEType into `m`. This test pins the file-scoped
  // invariant via the `INJECTED_PARSERS` seam: candidate 1 sets AAC then
  // rejects (its `File:*` side effect persists, per
  // `rejecting_parser_set_file_type_side_effect_persists`); candidate 2
  // attempts to set a DIFFERENT triplet (`FAKE2`/`application/fake`/
  // `fk2`) and accepts. Exactly one `File:FileType` (= `"AAC"`) must
  // remain on `m`, with the second parser's marker tag present and no
  // finalization Error (the second parser accepted).
  struct AacSetThenReject;
  impl FormatParser for AacSetThenReject {
    fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
      // Faithful to MPEG.pm:675 — `$et->SetFileType` BEFORE rejecting.
      ctx.set_file_type(Some("AAC"), None, None);
      false // MPEG.pm:678 style `or return 0`
    }
  }
  static AAC_SET_THEN_REJECT: AacSetThenReject = AacSetThenReject;

  struct WvOverwriteAndAccept;
  impl FormatParser for WvOverwriteAndAccept {
    fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
      // Try to set a DIFFERENT File:* triplet — must be a no-op because
      // candidate 1 already engaged first-call-wins on `m`. If exifast
      // ever drops the file-scoped guard, this call leaks a duplicate
      // File:FileType (= "FAKE2") into `m`, and the assertions below fire.
      ctx.set_file_type(Some("FAKE2"), Some("application/fake"), Some("fk2"));
      // Distinguishing marker so the test can confirm THIS parser ran.
      ctx
        .metadata()
        .push(Group::new("Audio", "WV"), "Marker", TagValue::I64(1));
      true // Perl `return 1` — accept ⇒ no post-loop Error
    }
  }
  static WV_OVERWRITE_AND_ACCEPT: WvOverwriteAndAccept = WvOverwriteAndAccept;

  #[test]
  fn set_file_type_is_file_scoped_first_call_wins_across_candidates() {
    // `bad.aac` with head `\xff\xf1\xf0…` yields candidates beginning
    // with `AAC` (extension+magic match) followed by `WV`, `MXF`, `DV`,
    // … (types whose magic gate the head passes via `noMagic`/weakMagic
    // / no-`%magicNumber`-entry pathways). Inject parsers for the FIRST
    // (`AAC`) and a LATER (`WV`) candidate; the loop must invoke `AAC`'s
    // parser then `WV`'s — both against the SAME outer Metadata.
    let _guard = InjectionGuard;
    inject("AAC", &AAC_SET_THEN_REJECT);
    inject("WV", &WV_OVERWRITE_AND_ACCEPT);

    let meta = extract_info("bad.aac", b"\xff\xf1\xf0\x00\x00\x00\x00", true);

    // Candidate 2 ran (its marker is on `m`) and accepted ⇒ no post-loop
    // finalization Error (ExifTool.pm:3080 `not defined $type` is false).
    assert!(
      meta
        .tags()
        .iter()
        .any(|t| t.name() == "Marker" && t.group().family1() == "WV"),
      "candidate 2's parser must have run and pushed its marker tag, got: {:?}",
      meta.tags()
    );
    assert!(
      meta.errors().is_empty(),
      "candidate 2 accepted ⇒ no finalization Error, got: {:?}",
      meta.errors()
    );

    // The file-scoped first-call-wins invariant: candidate 1 set
    // AAC/aac/audio/aac; candidate 2's `set_file_type(Some("FAKE2"), …)`
    // MUST be a no-op (it would re-push a SECOND File:* triplet if the
    // guard were per-context, leaking `FAKE2`/`application/fake`/`fk2`).
    let file_types: Vec<_> = meta
      .tags()
      .iter()
      .filter(|t| t.name() == "FileType" && t.group().family1() == "File")
      .map(|t| t.value().clone())
      .collect();
    assert_eq!(
      file_types,
      vec![TagValue::Str("AAC".into())],
      "exactly one File:FileType (first-call-wins ⇒ \"AAC\", not \"FAKE2\")"
    );
    let file_ext: Vec<_> = meta
      .tags()
      .iter()
      .filter(|t| t.name() == "FileTypeExtension" && t.group().family1() == "File")
      .collect();
    assert_eq!(file_ext.len(), 1, "exactly one File:FileTypeExtension");
    let mime: Vec<_> = meta
      .tags()
      .iter()
      .filter(|t| t.name() == "MIMEType" && t.group().family1() == "File")
      .collect();
    assert_eq!(mime.len(), 1, "exactly one File:MIMEType");

    // And the same invariant must survive serialization (the `%noDups`
    // first-wins serializer would mask a leak from `Metadata::tags()`-
    // level checks if we only asserted on JSON, but we already asserted
    // on `meta.tags()` directly above; this is the belt-and-braces).
    let json = crate::serialize::to_exiftool_json(&meta);
    assert!(
      json.contains("\"File:FileType\": \"AAC\""),
      "serialized File:FileType must be \"AAC\" (candidate 1's value), got: {json}"
    );
    assert!(
      !json.contains("\"FAKE2\""),
      "FAKE2 must not appear (candidate 2's SetFileType was a no-op), got: {json}"
    );
    assert!(
      !json.contains("\"application/fake\""),
      "application/fake must not appear, got: {json}"
    );
    assert!(
      !json.contains("\"ExifTool:Error\""),
      "no finalization Error (candidate 2 accepted), got: {json}"
    );
  }
}
