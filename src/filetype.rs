//! File-type detection: ExifTool's real `GetFileType` algorithm.
//!
//! Faithful transliteration of:
//! - `%fileTypeLookup` (ExifTool.pm:230-586) — EXT -> file TYPE(s) / alias.
//! - `%moduleName`     (ExifTool.pm:853-920) — TYPE -> module / Core / Unsupported.
//! - `%magicNumber`    (ExifTool.pm:928-1047) — TYPE -> start-anchored byte gate.
//! - `%weakMagic = ( MP3 => 1 )` (ExifTool.pm:~1050) and
//!   `noMagic{MXF}=1; noMagic{DV}=1` (ExifTool.pm:2987-2988).
//! - `GetFileType` (ExifTool.pm:4203-4275) and
//!   `GetFileExtension` (ExifTool.pm:9096+).
//!
//! `%fileTypeLookup` values are FILE TYPES (and aliases), NOT modules. Module
//! dispatch is a *separate* step (`%moduleName`), and the `%magicNumber` gate
//! is keyed by TYPE — a type with no entry is NOT auto-accepted (it has no
//! gate; `Magic::NoSignature`). This mirrors ExifTool exactly; the previous
//! collapsed ext->module model with a blanket magic accept was a defect.
//!
//! Deliberate, documented deferrals (none affect `GetFileType` Some/None,
//! candidate order, the scalar value, or the magic gate):
//! - `static_vars{OverrideFileDescription}` (a runtime override map) is not
//!   modelled; we always return the `%fileTypeLookup` entry description, which
//!   is what `GetFileType($file, 1)` returns absent that override.
//! - The `$desc .= ", $subType"` suffix appended for a trailing ` (SubType)`
//!   is not applied to the returned description (the SubType is still stripped
//!   for extension resolution, matching detection behaviour).
//! - `%fileDescription` / bare-`$file` description fallback only applies when
//!   there is *no* resolved file type; `get_file_type` returns `None` in that
//!   case, so the fallback is irrelevant to this API.

use smol_str::SmolStr;
use std::borrow::Cow;

/// A `%fileTypeLookup` entry shape (ExifTool.pm:230-586).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
  /// `EXT => 'OTHEREXT'` — alias; resolve transitively.
  Alias(&'static str),
  /// `EXT => ['TYPE', 'desc']` — a single file type (1-element slice).
  Single(&'static [&'static str], &'static str),
  /// `EXT => [['T1','T2',..], 'desc']` — ordered candidate file types.
  Multi(&'static [&'static str], &'static str),
}

/// Resolved, supported file-type info for an extension (mirrors `GetFileType`).
///
/// Construct via [`get_file_type`]. `candidate_types` is the list-context
/// `GetFileType` result (ordered, always at least one). `primary_type` is the
/// scalar-context result: the (uppercased) extension itself when the resolved
/// entry was a multi-candidate list, otherwise the single file type.
/// `description` is the description from the resolved `%fileTypeLookup` entry.
///
/// The scalar `primary` is a [`Cow<'static, str>`] because for a multi-candidate
/// row the value is Perl's `$fileExt` — the *runtime* uppercased extension,
/// which for a string-alias-to-multi (e.g. `AIT` -> `AI`) is the alias key
/// itself, not any direct table entry. Single rows borrow their `&'static`
/// type; multi rows own the computed extension string. This is faithful to
/// Perl `GetFileType` and removes any interning table / panic path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileType {
  candidate_types: &'static [&'static str],
  primary: Cow<'static, str>,
  description: &'static str,
}

impl FileType {
  /// Construct a `FileType` from its candidate types, scalar primary type
  /// and description. Internal to [`get_file_type`]; the `primary` is either
  /// a borrowed `&'static str` (single row: the file type) or an owned
  /// `String` (multi row: the uppercased runtime extension).
  #[must_use]
  fn new(
    candidate_types: &'static [&'static str],
    primary: impl Into<Cow<'static, str>>,
    description: &'static str,
  ) -> Self {
    Self {
      candidate_types,
      primary: primary.into(),
      description,
    }
  }

  /// List-context `GetFileType`: ordered candidate file types (1 or more).
  #[must_use]
  #[inline(always)]
  pub const fn candidate_types(&self) -> &'static [&'static str] {
    self.candidate_types
  }

  /// Scalar-context `GetFileType`: the uppercased extension if the resolved
  /// entry was a multi-candidate list, otherwise the single file type.
  #[must_use]
  #[inline(always)]
  pub fn primary_type(&self) -> &str {
    &self.primary
  }

  /// Description from the resolved `%fileTypeLookup` entry.
  #[must_use]
  #[inline(always)]
  pub const fn description(&self) -> &'static str {
    self.description
  }
}

/// `%moduleName` resolution for a file TYPE (ExifTool.pm:853-920).
///
/// `''` => [`ModuleName::Core`] (Image::ExifTool core handles it),
/// `0` => [`ModuleName::Unsupported`] (recognized but unsupported),
/// any other string => [`ModuleName::Module`], and a type ABSENT from the
/// table defaults to `Module(<the type name itself>)` — exactly Perl's
/// `$module = $moduleName{$type}; $module = $type unless defined $module;`.
///
/// The module name is a [`Cow<'static, str>`] because an absent entry yields
/// the *runtime* type name (Perl `$module = $type`); explicit table entries
/// borrow their `&'static` module name, absent entries own the type string.
/// This is faithful to Perl and removes any interning table / `(unknown)`
/// sentinel (a version-skew hazard).
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum ModuleName {
  /// Processed by `Image::ExifTool::<name>` (or the type name itself when
  /// the type is absent from `%moduleName`, per Perl `$module = $type`).
  Module(Cow<'static, str>),
  /// Processed by `Image::ExifTool` core (Perl module name `''`).
  Core,
  /// Recognized but unsupported (Perl module name `'0'`).
  Unsupported,
}

/// `%magicNumber` gate result for a file TYPE (ExifTool.pm:928-1047).
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum Magic {
  /// The type has a signature and `head` matches it (anchored at byte 0).
  Match,
  /// The type has a signature and `head` does NOT match it.
  NoMatch,
  /// The type has no `%magicNumber` entry, so there is no gate.
  NoSignature,
}

include!("filetype_data.rs");

/// `GetFileExtension` (ExifTool.pm:9096+): uppercased text after the last
/// `.`; `TIF` is normalized to `TIFF`. `None` when there is no `.`.
fn get_file_extension(name: &str) -> Option<SmolStr> {
  // Perl: /^.*\.([^.]+)$/s  — last '.', then 1+ non-'.' chars to end.
  let dot = name.rfind('.')?;
  let ext = &name[dot + 1..];
  if ext.is_empty() {
    return None;
  }
  let up = ext.to_ascii_uppercase();
  Some(if up == "TIF" {
    SmolStr::new_static("TIFF")
  } else {
    SmolStr::new(&up)
  })
}

/// `$$self{FILE_EXT}` (ExifTool.pm:2966 `$$self{FILE_EXT} =
/// GetFileExtension($realname)`): the uppercased, `TIF`→`TIFF`-normalized
/// file extension, or `None` for a dotless name. This is exactly the value
/// `SetFileType`/`OverrideFileType` read as `$ext` (ExifTool.pm:9683) — the
/// shared seam must derive `$ext` identically to the detection path, so it
/// reuses the same private [`get_file_extension`] (no second normalizer).
#[must_use]
pub fn file_ext_for_name(name: &str) -> Option<SmolStr> {
  get_file_extension(name)
}

/// Resolve string aliases transitively: `while value is a string: value =
/// lookup[value]`. Returns the terminal non-alias entry, or `None` if the
/// chain is broken (unrecognized).
fn resolve(mut ext: &str) -> Option<Lookup> {
  loop {
    match file_type_lookup(ext)? {
      Lookup::Alias(next) => ext = next,
      other => return Some(other),
    }
  }
}

/// `GetFileType` (ExifTool.pm:4203-4275), list + scalar contexts combined.
///
/// Returns `None` if the extension is unrecognized OR if the type is
/// unsupported (`%moduleName{firstCandidateType}` eq `'0'`). On `Some`, the
/// [`FileType`] carries both the ordered candidate list (list context) and the
/// scalar `primary_type`, plus the entry description.
#[must_use]
pub fn get_file_type(name_or_ext: &str) -> Option<FileType> {
  // GetFileExtension; else strip a trailing " (SubType)" and retry; else
  // the whole (uppercased) string is the extension.
  let ext: String = match get_file_extension(name_or_ext) {
    Some(e) => e.into(),
    None => match strip_subtype(name_or_ext) {
      Some(stripped) => {
        get_file_extension(stripped).map_or_else(|| stripped.to_ascii_uppercase(), Into::into)
      }
      None => name_or_ext.to_ascii_uppercase(),
    },
  };

  let entry = resolve(&ext)?;

  // Support filter: $mod = $moduleName{$$fileType[0]}; undef $fileType if
  // defined $mod and $mod eq '0'. When the first element is itself a list
  // ($$fileType[0] is a listref), $moduleName{listref} is undef in Perl, so
  // a Multi row is NOT support-filtered here.
  match entry {
    Lookup::Alias(_) => None, // unreachable: resolve() strips aliases
    Lookup::Single(types, desc) => {
      if module_for_type(types[0]).is_unsupported() {
        return None;
      }
      // scalar context: single type, so return the type itself
      // (a `&'static str`, borrowed into the Cow).
      Some(FileType::new(types, types[0], desc))
    }
    Lookup::Multi(types, desc) => {
      // scalar context: ref is an ARRAY-of-ARRAY, so Perl sets
      // $fileType = $fileExt (the uppercased file extension). For a
      // string-alias-to-multi row (e.g. AIT -> AI) this is the alias
      // key itself, so we own the already-computed `ext` string —
      // never an interning table, never a panic.
      Some(FileType::new(types, ext, desc))
    }
  }
}

/// Strip a trailing subtype annotation (the Perl `s/ \((.*)\)$//`).
///
/// Perl's `.*` is greedy and the pattern is end-anchored (`\)$`), so the
/// substitution matches from the **leftmost** ` (` through the final `)`.
/// Two invariants must both hold for the substitution to fire:
///
///   1. The string ends with `)`.
///   2. There is at least one ` (` (space + open-paren) somewhere before that
///      final `)`.
///
/// When they hold, the result is the slice before the first ` (`.
/// Returns `None` when either invariant fails — exactly like the Perl regex
/// not matching (ExifTool.pm:~4223).
///
/// `" ("` is ASCII so `str::find`'s byte index is safe to slice on directly.
fn strip_subtype(s: &str) -> Option<&str> {
  // ExifTool.pm:~4223  $file =~ s/ \((.*)\)$//
  // Greedy .* + \)$ => strip from the FIRST " (" to the final ")".
  if !s.ends_with(')') {
    return None;
  }
  let open = s.find(" (")?;
  Some(&s[..open])
}

/// One candidate file TYPE that ExifTool's `ExtractInfo` magic/candidate loop
/// (ExifTool.pm:2965-3045) would *try*, in order. Yielded by
/// [`detection_candidates`].
///
/// This is **selection only**: each candidate is a type whose `%magicNumber`
/// gate (and `%moduleName`/`%weakMagic`/`recognizedExt` rules) passed, i.e. a
/// type ExifTool would `$$self{FILE_TYPE} = $type` and then attempt to parse.
/// It does NOT dispatch a format parser (`require Image/ExifTool/$module.pm` /
/// `Process$type`); that — and the parser-failure retry that advances to the
/// next candidate (ExifTool.pm:3060-3077) — is Phase 2. The consumer drives
/// this iterator and stops at the first parser-accepted candidate.
///
/// `header_skip`/`after_unknown_header` are non-zero/true only for the
/// terminal "scan past an unknown header for JPEG/TIFF" candidate
/// (ExifTool.pm:3026-3032): ExifTool there also emits the warning
/// `Processing $type-like data after unknown $skip-byte header`. Emitting
/// that exact warning string is **deliberately deferred** to the parser
/// phase; the offset and flag are preserved here so it can be reconstructed.
///
/// `parent_type` is ExifTool's `$dirInfo{Parent}` (ExifTool.pm:3038):
/// `($type eq 'TIFF') ? $tiffType : $type`, where `$tiffType` is
/// `$$self{FILE_EXT}` = `GetFileExtension($realname)` (the uppercased,
/// TIF→TIFF-normalized extension) when `GetFileType` produced candidates
/// (ExifTool.pm:2965,2984), or the literal `'TIFF'` on the empty/full-scan
/// branch (ExifTool.pm:2992). So for a non-`TIFF` candidate it equals
/// `file_type()`; for a `TIFF` candidate it is the extension (e.g. `"CR2"`)
/// when candidates were produced, else `"TIFF"`. It is a
/// [`Cow<'static, str>`] mirroring [`FileType::primary`]: a borrowed
/// `&'static` for the common (type / `"TIFF"`) case, an owned `String` only
/// for the `TIFF`-candidate-with-runtime-extension case. (When candidates
/// were produced but the name has no extension — the whole-string
/// `GetFileType` fallback — Perl's `$tiffType` is `undef`, so a `TIFF`
/// candidate's `Parent` is the empty string; faithfully reproduced.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionCandidate {
  file_type: &'static str,
  header_skip: usize,
  after_unknown_header: bool,
  parent_type: Cow<'static, str>,
}

impl DetectionCandidate {
  /// The candidate file TYPE (an `@fileTypes`/`%fileTypeLookup` type name,
  /// e.g. `"FLV"`, `"PNG"`, `"JPEG"`, `"MXF"`). This is the loop's selected
  /// `$type`, not a container module relabel (e.g. RIFF is not yet
  /// relabelled to `AVI`/`WAV` — that happens in the RIFF module, a later
  /// phase).
  #[must_use]
  #[inline(always)]
  pub const fn file_type(&self) -> &'static str {
    self.file_type
  }

  /// Byte offset of the JPEG/TIFF marker when this candidate was produced
  /// only by scanning past an unknown header (Perl `pos($buff) -
  /// length($1)`); `0` for every other candidate.
  #[must_use]
  #[inline(always)]
  pub const fn header_skip(&self) -> usize {
    self.header_skip
  }

  /// `true` iff this candidate was produced via the terminal JPEG/TIFF
  /// header-skip scan (Perl `$unkHeader = 1`).
  #[must_use]
  #[inline(always)]
  pub const fn after_unknown_header(&self) -> bool {
    self.after_unknown_header
  }

  /// ExifTool's `$dirInfo{Parent}` for this candidate (ExifTool.pm:3038):
  /// `($type eq 'TIFF') ? $tiffType : $type`. Equals [`file_type`] for any
  /// non-`TIFF` candidate; for a `TIFF` candidate it is `$tiffType` —
  /// the (uppercased, TIF→TIFF) file extension when `GetFileType` produced
  /// candidates (ExifTool.pm:2984), the literal `"TIFF"` on the full-scan
  /// branch (ExifTool.pm:2992), or `""` when candidates were produced from
  /// a dotless name (Perl `$$self{FILE_EXT}` is then `undef`).
  ///
  /// [`file_type`]: DetectionCandidate::file_type
  #[must_use]
  #[inline(always)]
  pub fn parent_type(&self) -> &str {
    &self.parent_type
  }
}

/// Iterator over [`DetectionCandidate`]s in ExifTool `ExtractInfo` loop order.
/// Returned by [`detection_candidates`]; a real [`Iterator`] over a
/// precomputed candidate sequence (the selection logic itself is run eagerly,
/// faithfully reproducing the loop order; no parser is ever invoked).
#[derive(Debug, Clone)]
pub struct DetectionCandidates {
  items: std::vec::IntoIter<DetectionCandidate>,
}

impl Iterator for DetectionCandidates {
  type Item = DetectionCandidate;

  fn next(&mut self) -> Option<Self::Item> {
    self.items.next()
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    self.items.size_hint()
  }
}

impl ExactSizeIterator for DetectionCandidates {}

impl std::iter::FusedIterator for DetectionCandidates {}

/// Does `%magicNumber` have an entry for this key? Faithful to Perl
/// `defined $magicNumber{$key}`: [`magic`]'s `NoSignature` is returned iff
/// (and only iff) the key has no `%magicNumber` entry, independent of the
/// bytes — so an empty `head` is a safe probe for "is the entry defined".
fn has_magic_number(key: &str) -> bool {
  !magic(key, b"").is_no_signature()
}

/// Last-ditch scan (ExifTool.pm:3027): the Perl `/(\xff\xd8\xff|MM\0\x2a|`
/// `II\x2a\0)/g` — first occurrence at ANY offset. Returns `(type, marker
/// length, match-end position)` mirroring `($1, length($1), pos($buff))`.
fn scan_jpeg_tiff(head: &[u8]) -> Option<(&'static str, usize, usize)> {
  const JPEG: &[u8] = b"\xff\xd8\xff";
  const TIFF_MM: &[u8] = b"MM\0\x2a";
  const TIFF_II: &[u8] = b"II\x2a\0";
  // Perl's alternation tries the leftmost position first; at a given
  // position the branches are tried left-to-right (all length 3 or 4).
  for i in 0..head.len() {
    let rest = &head[i..];
    if rest.starts_with(JPEG) {
      return Some(("JPEG", JPEG.len(), i + JPEG.len()));
    }
    if rest.starts_with(TIFF_MM) || rest.starts_with(TIFF_II) {
      return Some(("TIFF", TIFF_MM.len(), i + TIFF_MM.len()));
    }
  }
  None
}

// ExifTool.pm:922 — number of bytes read into the magic-test buffer:
//   $testLen = 1024;
//   $raf->Read($buff, $testLen)  (ExifTool.pm:3003)
// ALL %magicNumber tests AND the JPEG/TIFF end-marker scan operate on this
// ≤1024-byte window, never on a longer slice.
const TEST_LEN: usize = 1024;

/// ExifTool's content-gated file-type **candidate sequence**: filename + the
/// first bytes of the file (ideally at least the first 1024 = `$testLen`) ->
/// every type ExifTool's `ExtractInfo` loop (ExifTool.pm:2965-3045) would
/// try, **in order**. Faithful transliteration of that candidate/magic loop
/// under the default `FastScan = 0` (full processing; the `fast > 2`/
/// `fast >= 4` early-exit branches are never taken and are out of scope).
///
/// Composes the faithful primitives: [`get_file_type`] (candidate list) +
/// the `@fileTypes` master-order fallback + the `%magicNumber` gate
/// ([`magic`]) + [`is_no_magic`]/[`is_weak_magic`] + `recognizedExt` + the
/// JPEG/TIFF tail. Yields, IN ORDER, every type that passes the gate; the
/// final yielded item is the `''` end-of-list terminal — the `recognizedExt`
/// type if set, else the JPEG/TIFF unknown-header scan result (carrying
/// `header_skip`/`after_unknown_header`), else nothing. An **empty** iterator
/// means ExifTool would reach "Unknown file type" with nothing to try.
///
/// This runs **NO parsers** and finalizes **NO type**. ExifTool finalizes the
/// FIRST candidate whose parser `Process$type` accepts the data; on parser
/// failure it seeks back and advances to the next candidate
/// (ExifTool.pm:3060-3077). That parser-validation is Phase 2 — the consumer
/// drives this iterator and stops at the first parser-accepted candidate.
///
/// Panic-free for any `name`/`head`, including empty/dotless/unicode.
#[must_use]
pub fn detection_candidates(name: &str, head: &[u8]) -> DetectionCandidates {
  // Cap to $testLen bytes exactly as ExifTool does: $raf->Read($buff,$testLen).
  // All subsequent buffer reads (magic gate + JPEG/TIFF scan) see only this
  // ≤1024-byte window — panic-free for any length including 0.
  let head = &head[..head.len().min(TEST_LEN)];

  // L2965: $ext = GetFileExtension($realname)  (DOES TIF->TIFF; faithful
  // to the real GetFileExtension, ExifTool.pm:9106).
  let ext = get_file_extension(name);

  // L2967-8: $recognizedExt = $ext if defined $ext and
  //   not defined $magicNumber{$ext} and
  //   defined $moduleName{$ext} and not $moduleName{$ext};
  // "$moduleName{$ext} defined and falsey" == module_for_type(ext) is an
  // EXPLICIT '' (Core) or '0' (Unsupported). With the faithful
  // module_for_type, Core/Unsupported are returned ONLY for explicit table
  // entries (absent => Module(..)), so this is exact.
  let recognized_ext: Option<String> = ext
    .as_deref()
    .filter(|e| {
      !has_magic_number(e) && {
        let m = module_for_type(e);
        m.is_core() || m.is_unsupported()
      }
    })
    .map(str::to_owned);

  // L2969: @fileTypeList = GetFileType($realname)  (list context).
  let resolved = get_file_type(name);
  let candidates: &[&str] = resolved.as_ref().map_or(&[], FileType::candidate_types);

  // L2979-2992 (fast >= 4 branch is out of scope; fast == 3 never true):
  //   if (@fileTypeList) { push remaining @fileTypes not already in list;
  //                        noMagic{MXF}=1; noMagic{DV}=1; }
  //   else               { @fileTypeList = @fileTypes; }   (no noMagic set)
  //   push @fileTypeList, '';   # end-of-list marker
  let mut list: Vec<&str> = Vec::new();
  let apply_no_magic = if candidates.is_empty() {
    list.extend_from_slice(FILE_TYPES);
    false
  } else {
    list.extend_from_slice(candidates);
    list.extend(
      FILE_TYPES
        .iter()
        .copied()
        .filter(|t| !candidates.contains(t)),
    );
    true
  };

  // L2984/L2992: $tiffType. Non-empty-candidates branch (== apply_no_magic):
  // `$tiffType = $$self{FILE_EXT}` = GetFileExtension($realname) (the
  // already-computed `ext`; `undef`/`""` for a dotless name). Empty/full-
  // scan branch: `$tiffType = 'TIFF'`. Used ONLY for a `TIFF` candidate's
  // Parent (L3038). Cow mirrors `FileType::primary`: owned runtime ext, or
  // borrowed `&'static "TIFF"`/`""`.
  let tiff_type: Cow<'static, str> = if apply_no_magic {
    ext
      .as_deref()
      .map_or(Cow::Borrowed(""), |e| Cow::Owned(e.to_owned()))
  } else {
    Cow::Borrowed("TIFF")
  };
  // L3038: $dirInfo{Parent} = ($type eq 'TIFF') ? $tiffType : $type.
  // Non-`TIFF` candidate => the type itself (a `&'static`, borrowed);
  // `TIFF` candidate => $tiffType (cloned Cow, owned only when an ext).
  let parent_of = |ty: &'static str| -> Cow<'static, str> {
    if ty == "TIFF" {
      tiff_type.clone()
    } else {
      Cow::Borrowed(ty)
    }
  };

  // L3009-3036: loop over the list, then the '' end-of-list marker. ExifTool
  // would `$$self{FILE_TYPE} = $type` for each non-skipped element and try
  // its parser; on parser failure it seeks back and `shift`s the next. We
  // run NO parser, so we faithfully emit EVERY non-skipped element in order
  // (== "every parser returned false"); the consumer stops at the first
  // parser-accepted one (Phase 2).
  let mut out: Vec<DetectionCandidate> = Vec::new();
  for &ty in &list {
    // L3013-3018:
    if has_magic_number(ty) {
      // next if $buff !~ /^$magicNumber{$type}/s and not $noMagic{$type}
      let gated_out = magic(ty, head).is_no_match() && !(apply_no_magic && is_no_magic(ty));
      if gated_out {
        continue;
      }
    } else {
      // next if defined $moduleName{$type} and not $moduleName{$type}
      // (ext-only types are skipped while scanning). The `next if
      // $fast > 2` line below it is out of scope (fast == 0).
      let m = module_for_type(ty);
      if m.is_core() || m.is_unsupported() {
        continue;
      }
    }
    // L3019: next if $weakMagic{$type} and defined $recognizedExt
    if is_weak_magic(ty) && recognized_ext.is_some() {
      continue;
    }
    // Not skipped => ExifTool sets $$self{FILE_TYPE} = $type here and
    // attempts Process$type. Faithful candidate — emit. L3038 sets
    // $dirInfo{Parent} for this same $type.
    out.push(DetectionCandidate {
      file_type: ty,
      header_skip: 0,
      after_unknown_header: false,
      parent_type: parent_of(ty),
    });
    // ExifTool.pm:~3052 (elsif $module eq '0' => SetFileType; Warn; last)
    // A gate-passing type whose %moduleName is '0' (Unsupported) causes
    // ExifTool to stop the entire candidate loop immediately: no later
    // @fileTypes candidates are tried, and the '' end-of-list terminal
    // (recognizedExt / JPEG-TIFF scan) is never reached.
    if module_for_type(ty).is_unsupported() {
      return DetectionCandidates {
        items: out.into_iter(),
      };
    }
  }

  // End-of-list marker reached (Perl: $type is the '' element). This is the
  // FINAL candidate ExifTool would try.
  // L3023-3024: } elsif ($recognizedExt) { $type = $recognizedExt; }
  if let Some(e) = recognized_ext {
    // `e` is an uppercased extension that resolved to an explicit
    // ''/'0' %moduleName entry, so it is itself a type-name key; emit
    // the matching &'static so `file_type()` stays `&'static str`.
    if let Some(interned) = file_types_static(&e) {
      out.push(DetectionCandidate {
        file_type: interned,
        header_skip: 0,
        after_unknown_header: false,
        parent_type: parent_of(interned),
      });
    }
    // Defensive: an ext whose %moduleName is explicit ''/'0' but which
    // is not in @fileTypes/%moduleName key set. None such exists today
    // (all are e.g. EXIF/EXV/JPEG/TIFF/AVC/ALIAS/...); we cannot mint a
    // &'static for it, so emit nothing rather than fabricate.
    // (Documented; unreachable in practice — every such ext is covered
    // by file_types_static.)
  } else if let Some((ty, marker_len, end)) = scan_jpeg_tiff(head) {
    // L3026-3032: last-ditch scan past unknown header for JPEG/TIFF.
    // (Perl reaches this branch only when $recognizedExt is false — it is
    // the `else` of the `elsif ($recognizedExt)`.)
    let skip = end - marker_len; // Perl: pos($buff) - length($1)
    // L3038 applies to this terminal $type too: a JPEG terminal's Parent
    // is "JPEG"; a TIFF terminal's Parent is $tiffType.
    out.push(DetectionCandidate {
      file_type: ty,
      header_skip: skip,
      after_unknown_header: true,
      parent_type: parent_of(ty),
    });
  }
  // Empty `out` <=> Perl reaches `$self->Error('Unknown file type')` with
  // nothing to try.
  DetectionCandidates {
    items: out.into_iter(),
  }
}

#[cfg(test)]
mod tests;
