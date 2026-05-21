// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "audible")]
//! Faithful port of `Image::ExifTool::Audible` (lib/Image/ExifTool/Audible.pm),
//! AA-side only: `ProcessAA` + the `%Audible::Main` tag table.
//!
//! **Phase F1 — lib-first migration.** Follows the MOI pilot (Phase E) +
//! AAC/DV pattern: a typed [`AaMeta<'a>`] is produced by the new
//! [`crate::parser_new::FormatParser`] trait; the engine entry
//! `process` drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! **M4B-side DEFERRED to FORMATS.md row 25 (QuickTime/MOV).** The bundled
//! Audible.pm also defines `%Audible::tags`, `%Audible::meta`, `%Audible::cvrx`,
//! `%Audible::tseg` and `ProcessAudible_meta` / `ProcessAudible_cvrx` for
//! M4B audiobooks (lines 51-188). Those tables are reached ONLY through
//! QuickTime.pm's atom-tree walker (`Audible::tags` is registered as a
//! sub-directory under the QuickTime `tags` atom). Without QuickTime ported
//! (FORMATS.md row 25, Phase 4) no caller can reach them, so half-building
//! them now would be dead-but-reachable code (anti-D5/D11/R7 incremental-
//! derivation pattern; see `[[exifast-phase2-forward-items]]`). They are
//! intentionally not ported here — derive their faithful Rust shape when
//! QuickTime.pm ships and the goldens for an `.m4b` Audible fixture become
//! the oracle.
//!
//! PROCESS_PROC is `ProcessAA` (Audible.pm:194), invoked from
//! [`crate::parser_new::any_parser_for`] via the `"AA"` arm. The flow is:
//! magic+size gate → `SetFileType` → walk TOC (12-byte triples) → for each
//! triple whose type ∈ {2, 6, 11}, dispatch chunk 6 (chapter count),
//! chunk 11 (cover art) or chunk 2 (UTF-8 dictionary).

use crate::{
  convert::{fix_utf8, pack_c0u},
  parser_new::{FormatParser, parser_sealed},
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
};
use smol_str::SmolStr;

// ---------- %Audible::Main static table (Audible.pm:24-48) -----------------

// Audible.pm:31 — pubdate => { Name => 'PublishDate', Groups => { 2 => 'Time' } }
static PUBLISH_DATE: TagDef =
  TagDef::new("PublishDate", "Audible", ValueConv::None, PrintConv::None);
// Audible.pm:32 — pub_date_start => { Name => 'PublishDateStart', Groups => { 2 => 'Time' } }
static PUBLISH_DATE_START: TagDef = TagDef::new(
  "PublishDateStart",
  "Audible",
  ValueConv::None,
  PrintConv::None,
);
// Audible.pm:33 — author => { Name => 'Author', Groups => { 2 => 'Author' } }
static AUTHOR: TagDef = TagDef::new("Author", "Audible", ValueConv::None, PrintConv::None);
// Audible.pm:34 — copyright => { Name => 'Copyright', Groups => { 2 => 'Author' } }
static COPYRIGHT: TagDef = TagDef::new("Copyright", "Audible", ValueConv::None, PrintConv::None);
// Audible.pm:42 — _chapter_count => { Name => 'ChapterCount' }
static CHAPTER_COUNT: TagDef =
  TagDef::new("ChapterCount", "Audible", ValueConv::None, PrintConv::None);
// Audible.pm:43-47 — _cover_art => { Name => 'CoverArt', ..., Binary => 1 }
// `Binary => 1` is faithfully rendered by the universal `TagValue::Bytes`
// serializer (`(Binary data N bytes, use -b option to extract)`).
static COVER_ART: TagDef = TagDef::new("CoverArt", "Audible", ValueConv::None, PrintConv::None);

fn audible_get(id: TagId) -> Option<&'static TagDef> {
  // Audible.pm:24-48 explicit keys. Anything else falls through to the
  // dynamic-name path (`AddTagToTable`, Audible.pm:258) — implemented
  // inline in `parse_inner` so the dispatch table only carries the
  // statically-listed entries.
  match id {
    TagId::Str("pubdate") => Some(&PUBLISH_DATE),
    TagId::Str("pub_date_start") => Some(&PUBLISH_DATE_START),
    TagId::Str("author") => Some(&AUTHOR),
    TagId::Str("copyright") => Some(&COPYRIGHT),
    TagId::Str("_chapter_count") => Some(&CHAPTER_COUNT),
    TagId::Str("_cover_art") => Some(&COVER_ART),
    _ => None,
  }
}

/// `%Audible::Main` (Audible.pm:24). Family-0 group "Audible"; family-1
/// "Audible" (default). The Perl `GROUPS => { 2 => 'Audio' }` (family-2)
/// is not emitted under `-G1`.
pub static AUDIBLE_MAIN: TagTable = TagTable::new("Audible", audible_get);

/// Faithful `Image::ExifTool::%specialTags` (ExifTool.pm:1229-1236).
/// Reserved keys that collide with internal table fields — when an AA
/// dictionary entry's tag id matches one of these, Perl `GetTagInfo`
/// (`ExifTool.pm:9119-9121`) emits a warning and returns empty, so
/// `HandleTag` drops the tag entirely (no `FoundTag` call). R7: the
/// previous dynamic-name path treated `GROUPS`/`FORMAT` etc. as plain
/// metadata, surfacing `Audible:GROUPS` where bundled Perl emits
/// nothing.
fn is_perl_special_tag(tag: &str) -> bool {
  matches!(
    tag,
    "TABLE_NAME"
      | "SHORT_NAME"
      | "PROCESS_PROC"
      | "WRITE_PROC"
      | "CHECK_PROC"
      | "GROUPS"
      | "FORMAT"
      | "FIRST_ENTRY"
      | "TAG_PREFIX"
      | "PRINT_CONV"
      | "WRITABLE"
      | "TABLE_DESC"
      | "NOTES"
      | "IS_OFFSET"
      | "IS_SUBDIR"
      | "EXTRACT_UNKNOWN"
      | "NAMESPACE"
      | "PREFERRED"
      | "SRC_TABLE"
      | "PRIORITY"
      | "AVOID"
      | "WRITE_GROUP"
      | "LANG_INFO"
      | "VARS"
      | "DATAMEMBER"
      | "SET_GROUP1"
      | "PERMANENT"
      | "INIT_TABLE"
  )
}

// ---------- Dynamic-tag name (Audible.pm:256-258, MakeTagName) -------------

/// Faithful `Image::ExifTool::MakeTagName` (ExifTool.pm:6440-6448).
///
/// 1. `tr/-_a-zA-Z0-9//dc` — keep only `[-_a-zA-Z0-9]`.
/// 2. `ucfirst` — uppercase first character.
/// 3. If length < 2 OR first char ∈ `[-0-9]`, prepend `Tag`.
fn make_tag_name(tag: &str) -> String {
  // (1) Filter to `[-_a-zA-Z0-9]`. The input is already UTF-8; non-ASCII
  // bytes are non-alnum so they are dropped — exactly what the Perl tr///
  // does over the byte string.
  let filtered: String = tag
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
    .collect();
  // (2) ucfirst — only the first character is uppercased, the rest are
  // left as-is (`uppercase` of a digit/`-`/`_` is itself).
  let mut chars = filtered.chars();
  let first = chars.next();
  let ucfirst: String = match first {
    Some(c) => {
      let mut buf = String::with_capacity(filtered.len());
      // Faithful Perl ucfirst: ASCII-only uppercase on first char (the
      // input is already filtered to ASCII alnum+`-_` so this is total).
      let up = if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
      } else {
        c
      };
      buf.push(up);
      buf.push_str(chars.as_str());
      buf
    }
    None => String::new(),
  };
  // (3) Prepend "Tag" if too short OR starts with `-` / `[0-9]`.
  let needs_prefix = ucfirst.len() < 2
    || ucfirst
      .as_bytes()
      .first()
      .is_some_and(|&b| b == b'-' || b.is_ascii_digit());
  if needs_prefix {
    format!("Tag{ucfirst}")
  } else {
    ucfirst
  }
}

/// Faithful Audible.pm:257 `s/_(.)/\U$1/g` — change underscore-separated
/// segments into mixed case. Applied AFTER `make_tag_name`. The pattern is
/// `_` followed by any single character; the replacement is that character
/// in upper case (the `_` itself is dropped). Operates left-to-right.
fn underscore_to_mixed_case(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  let mut it = s.chars();
  while let Some(c) = it.next() {
    if c == '_' {
      match it.next() {
        // Faithful `\U$1` — uppercase the captured char and drop the `_`.
        Some(next) => out.extend(next.to_uppercase()),
        // Trailing `_` (no captured char): the regex doesn't match, the
        // underscore stays in the output.
        None => out.push('_'),
      }
    } else {
      out.push(c);
    }
  }
  out
}

/// Faithful `Image::ExifTool::AddTagToTable` name-normalization tail
/// (`ExifTool.pm:9243-9254`). After Audible.pm:256-257's `MakeTagName`
/// then `s/_(.)/\U$1/g`, Perl calls AddTagToTable which re-applies
/// `tr/-_a-zA-Z0-9//dc` (redundant; input was already MakeTagName-
/// filtered), `ucfirst` (already done), and a final-prefix gate:
/// `$name = "Tag$name" if length($name) < 2 or $name !~ /^[A-Z]/i`.
///
/// `MakeTagName`'s own gate fires only on `[-0-9]` first chars; the
/// AddTagToTable gate ALSO fires on `_`-prefixed names (and any other
/// non-letter). For input `__foo`: `make_tag_name` ⇒ `__foo` (no
/// prefix, first char `_`); `underscore_to_mixed_case` ⇒ `_foo` (Perl
/// leftmost-greedy strips the outer `_`, capitalizes the inner);
/// AddTagToTable tail ⇒ `Tag_foo` (first char `_` ⇒ prefix). R6:
/// bundled Perl emits `Audible:Tag_foo`; previously we stopped after
/// `underscore_to_mixed_case` and emitted `Audible:_foo`.
fn add_tag_to_table_name_normalize(name: String) -> String {
  let needs_prefix = name.len() < 2
    || !name
      .as_bytes()
      .first()
      .is_some_and(|b| b.is_ascii_alphabetic());
  if needs_prefix {
    format!("Tag{name}")
  } else {
    name
  }
}

// ---------- HTML entity unescape (Audible.pm:261, `HTML::UnescapeHTML`) ----

/// Faithful port of `Image::ExifTool::HTML::UnescapeHTML` (HTML.pm:401-405),
/// the `UnescapeXML` it delegates to (XMP.pm:2875-2881), and the
/// `UnescapeChar` (XMP.pm:2919-2936) it iterates with.
///
/// **Operates on raw bytes**: Audible.pm:261 passes the dict-value byte
/// string (`$val = substr($buff, $valPos, $valLen)`) directly to
/// `HTML::UnescapeHTML`; Perl's string regex on a byte-flavored scalar walks
/// bytes, and `pack('C0U', $val)` at XMP.pm:2933 emits UTF-8 (or a
/// UTF-8-shaped byte sequence for surrogates / out-of-range codepoints).
/// The downstream `FixUTF8` pass at JSON serialization (`exiftool` script
/// :3822) turns each invalid byte into `'?'`. To match that pipeline
/// byte-for-byte, this helper preserves invalid input bytes verbatim and
/// emits Perl `pack('C0U', N)` bytes for entity expansions (via
/// [`crate::convert::pack_c0u`]). The caller must then run the result
/// through [`crate::convert::fix_utf8`] before storing as a UTF-8 `String`.
///
/// The Perl regex is `&(#?\w+);` (XMP.pm:2879) — exactly one `&...;` token,
/// with the hash-name body matching `#?\w+`. `UnescapeChar` does:
/// 1. Look up the name in the supplied table (here `%entityNum`, HTML.pm:
///    38-124, the full HTML 4 character entity table; we port it verbatim
///    below in [`ENTITY_NUM`]). Hit ⇒ that codepoint via `pack('C0U')`.
/// 2. Else if `^#x([0-9a-fA-F]+)$` — `chr(hex($1))` then `pack('C0U')`.
///    NOTE: the literal `x` here is LOWERCASE only; `&#X{hex};` is NOT a
///    valid hex entity.
/// 3. Else if `^#(\d+)$` — `chr($1)` then `pack('C0U')`.
/// 4. Else return the literal `&$ch;` (XMP.pm:2929 "should issue a
///    warning here? [no]" — leaves it untouched).
///
/// On every codepoint resolution Perl emits via `pack('C0U', $val)`
/// (XMP.pm:2933); we replicate via [`pack_c0u`]. The `Decode($_, 'UTF8')`
/// outer wrapper at Audible.pm:261 is a no-op when from==to==UTF8
/// (ExifTool.pm:6337-6340 `$from ne $to` gate), so it doesn't change the
/// byte stream.
fn unescape_html_bytes(bytes: &[u8]) -> Result<Vec<u8>, FatalEntityError> {
  // Fast-path: no `&` ⇒ clone the input verbatim.
  if !bytes.contains(&b'&') {
    return Ok(bytes.to_vec());
  }
  let mut out = Vec::with_capacity(bytes.len());
  let mut i = 0;
  while i < bytes.len() {
    if bytes[i] != b'&' {
      // Copy one byte verbatim — invalid UTF-8 lead/continuation bytes
      // survive untouched here and are later mapped to `?` by fix_utf8.
      out.push(bytes[i]);
      i += 1;
      continue;
    }
    // Perl `&(#?\w+);` — `\w` is `[A-Za-z0-9_]`. Find the terminating
    // `;`, but only if every byte between is a `\w` char (or the
    // optional leading `#`). Otherwise the regex doesn't match: emit
    // the literal `&` and resume.
    let body_start = i + 1;
    let mut j = body_start;
    let mut allow_hash = true;
    while j < bytes.len() {
      let b = bytes[j];
      if b == b';' {
        break;
      }
      let is_hash_lead = allow_hash && b == b'#';
      let is_word = b.is_ascii_alphanumeric() || b == b'_';
      if !is_hash_lead && !is_word {
        // Non-`\w` between `&` and `;`: the regex fails to match.
        break;
      }
      allow_hash = false;
      j += 1;
    }
    if j == bytes.len() || bytes[j] != b';' || j == body_start {
      // No `;`, OR the body is empty (`&;` doesn't match `\w+`) ⇒
      // literal `&`.
      out.push(b'&');
      i += 1;
      continue;
    }
    // `entity` body is guaranteed `\w+` ASCII (we just enforced that
    // every byte in `body_start..j` is `[A-Za-z0-9_#]`), so the slice
    // is valid UTF-8.
    let entity = std::str::from_utf8(&bytes[body_start..j])
      .expect("entity body is restricted to ASCII `\\w` chars");
    match resolve_html_entity_codepoint(entity) {
      EntityResolution::Resolved(code) => {
        // Perl `pack('C0U', $val)` (XMP.pm:2933) — variable-length
        // UTF-8 encoding without surrogate / out-of-range validity
        // checks. Invalid codepoints become malformed UTF-8 byte
        // sequences that fix_utf8 will later replace with `?` each.
        pack_c0u(code, &mut out);
        i = j + 1; // skip past `;`
      }
      EntityResolution::Unknown => {
        // XMP.pm:2929 — "return &$ch;" leaves the original token
        // unchanged. Emit the literal `&...;` verbatim and resume.
        out.push(b'&');
        i += 1;
      }
      EntityResolution::Fatal => {
        // R9: numeric entity above i64::MAX. Bundled Perl `pack('C0U')`
        // dies at XMP.pm:2933 with `Use of code point ... is not
        // allowed; the permissible max is 0x7FFFFFFFFFFFFFFF`, aborting
        // the entire process (exit 255, NO JSON stdout). Surface the
        // fatal up to the AA dictionary loop so it can emit the
        // engine's `ExifTool:Error` substitute.
        return Err(FatalEntityError);
      }
    }
  }
  Ok(out)
}

/// Marker for the AA dict loop: an HTML numeric entity exceeded Perl
/// `pack('C0U')`'s i64::MAX cap (XMP.pm:2933). Bundled Perl dies with
/// "Use of code point ... is not allowed", aborting the entire `exiftool`
/// process. The Rust library (panic-free per `#![forbid(unsafe_code)]`)
/// surfaces this upward instead; the caller pushes `ExifTool:Error` —
/// the engine's chosen ExifTool-fatal equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FatalEntityError;

/// Tri-state result of `resolve_html_entity_codepoint`. R9: the previous
/// `Option<u64>` collapsed "no match (leave literal)" with "value above
/// Perl's pack max (would die)" — both returned `None`. The fatal case
/// must propagate to the dict loop so it can emit `ExifTool:Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntityResolution {
  /// Successfully resolved to a codepoint in `0..=i64::MAX`.
  Resolved(u64),
  /// Body did not match any branch (no named entity, no `#x...`, no
  /// `#...`, OR malformed body). Caller leaves the original `&body;`
  /// token verbatim (XMP.pm:2929).
  Unknown,
  /// Numeric entity above `i64::MAX` — Perl would die in `pack('C0U')`.
  /// Caller surfaces this as the AA-fatal Error.
  Fatal,
}

/// `&str`-flavored wrapper for unit tests / call sites that already have
/// valid UTF-8 input AND DO NOT produce a [`FatalEntityError`]. Panics
/// on the fatal case — the dedicated [`unescape_html_try`] returns the
/// `Result` for tests that exercise the fatal arm.
#[cfg(test)]
fn unescape_html(s: &str) -> String {
  unescape_html_try(s).expect("test input must not produce FatalEntityError")
}

/// `Result`-flavored wrapper for tests that exercise the fatal arm
/// (R9: numeric entity above i64::MAX). Production callers go through
/// the byte-level [`unescape_html_bytes`] directly.
#[cfg(test)]
fn unescape_html_try(s: &str) -> Result<String, FatalEntityError> {
  unescape_html_bytes(s.as_bytes()).map(|b| fix_utf8(&b))
}

/// Resolve one HTML/XML entity body (the text between `&` and `;`) into
/// one of three states (R9-introduced tri-state, was `Option<u64>`):
///
/// - [`EntityResolution::Resolved`]`(u64)` — valid codepoint within
///   Perl `pack('C0U')`'s `0..=i64::MAX` range.
/// - [`EntityResolution::Unknown`] — body didn't match any branch
///   (no named entity, no `#x...`, no `#...`, OR malformed body).
///   Caller leaves the original `&body;` token verbatim (XMP.pm:2929
///   "should issue a warning here? [no]").
/// - [`EntityResolution::Fatal`] — numeric entity above `i64::MAX`.
///   Perl `pack('C0U')` (XMP.pm:2933) DIES in this case
///   (`Use of code point ... is not allowed; the permissible max is
///   0x7FFFFFFFFFFFFFFF`) and the whole `exiftool` process exits 255
///   with no JSON output. The Rust port (panic-free) surfaces this so
///   the AA dict loop can push `ExifTool:Error` — the engine's chosen
///   ExifTool-fatal substitute. R9 splits this from `Unknown` (where
///   we leave the entity literal): same `Option::None` would silently
///   accept malformed metadata that ExifTool refuses to expose.
///
/// The raw `u64` deliberately rides surrogates and codepoints above
/// U+10FFFF — `pack_c0u` encodes them as 7-byte/13-byte invalid UTF-8
/// sequences, and `fix_utf8` later replaces each bad byte with `?` —
/// matching the bundled Perl pipeline byte-for-byte.
fn resolve_html_entity_codepoint(entity: &str) -> EntityResolution {
  // Perl `pack('C0U', $n)` rejects values strictly greater than i64::MAX.
  const PERL_PACK_C0U_MAX: u64 = 0x7FFF_FFFF_FFFF_FFFF;
  // (1) HTML.pm:38-124 named-entity table lookup (verbatim). Named
  // entities top out at U+2666 (`diams`), trivially in range.
  if let Some(&n) = ENTITY_NUM
    .iter()
    .find(|(k, _)| *k == entity)
    .map(|(_, v)| v)
  {
    return EntityResolution::Resolved(u64::from(n));
  }
  // (2) Numeric `&#x...;` (lowercase `x` only — XMP.pm:2924). The body
  // must match `^x[0-9a-fA-F]+$` after the leading `#`.
  let Some(rest) = entity.strip_prefix('#') else {
    return EntityResolution::Unknown;
  };
  if let Some(hex) = rest.strip_prefix('x') {
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
      return EntityResolution::Unknown;
    }
    // R9: above i64::MAX we surface Fatal (Perl pack would die).
    // u64 parse failure (hex body of 17+ digits, > u64::MAX) ALSO
    // counts as fatal — Perl `hex()` saturates to u64::MAX which
    // pack would still reject as > i64::MAX.
    let n = match u64::from_str_radix(hex, 16) {
      Ok(n) => n,
      Err(_) => return EntityResolution::Fatal,
    };
    if n > PERL_PACK_C0U_MAX {
      return EntityResolution::Fatal;
    }
    return EntityResolution::Resolved(n);
  }
  // (3) Numeric decimal `&#NNN;` — XMP.pm:2926-2927.
  if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
    return EntityResolution::Unknown;
  }
  let n = match rest.parse::<u64>() {
    Ok(n) => n,
    Err(_) => return EntityResolution::Fatal,
  };
  if n > PERL_PACK_C0U_MAX {
    return EntityResolution::Fatal;
  }
  EntityResolution::Resolved(n)
}

/// `%entityNum` (HTML.pm:38-124), verbatim. HTML 4 character entity
/// references that `UnescapeHTML` resolves to Unicode codepoints. Keys are
/// case-sensitive (Perl hash lookup), so e.g. `&copy;` resolves but
/// `&COPY;` does not.
#[rustfmt::skip]
static ENTITY_NUM: &[(&str, u32)] = &[
    ("quot",    34), ("eth",     240), ("lsquo",   8216),
    ("amp",     38), ("ntilde",  241), ("rsquo",   8217),
    ("apos",    39), ("ograve",  242), ("sbquo",   8218),
    ("lt",      60), ("oacute",  243), ("ldquo",   8220),
    ("gt",      62), ("ocirc",   244), ("rdquo",   8221),
    ("nbsp",   160), ("otilde",  245), ("bdquo",   8222),
    ("iexcl",  161), ("ouml",    246), ("dagger",  8224),
    ("cent",   162), ("divide",  247), ("Dagger",  8225),
    ("pound",  163), ("oslash",  248), ("bull",    8226),
    ("curren", 164), ("ugrave",  249), ("hellip",  8230),
    ("yen",    165), ("uacute",  250), ("permil",  8240),
    ("brvbar", 166), ("ucirc",   251), ("prime",   8242),
    ("sect",   167), ("uuml",    252), ("Prime",   8243),
    ("uml",    168), ("yacute",  253), ("lsaquo",  8249),
    ("copy",   169), ("thorn",   254), ("rsaquo",  8250),
    ("ordf",   170), ("yuml",    255), ("oline",   8254),
    ("laquo",  171), ("OElig",   338), ("frasl",   8260),
    ("not",    172), ("oelig",   339), ("euro",    8364),
    ("shy",    173), ("Scaron",  352), ("image",   8465),
    ("reg",    174), ("scaron",  353), ("weierp",  8472),
    ("macr",   175), ("Yuml",    376), ("real",    8476),
    ("deg",    176), ("fnof",    402), ("trade",   8482),
    ("plusmn", 177), ("circ",    710), ("alefsym", 8501),
    ("sup2",   178), ("tilde",   732), ("larr",    8592),
    ("sup3",   179), ("Alpha",   913), ("uarr",    8593),
    ("acute",  180), ("Beta",    914), ("rarr",    8594),
    ("micro",  181), ("Gamma",   915), ("darr",    8595),
    ("para",   182), ("Delta",   916), ("harr",    8596),
    ("middot", 183), ("Epsilon", 917), ("crarr",   8629),
    ("cedil",  184), ("Zeta",    918), ("lArr",    8656),
    ("sup1",   185), ("Eta",     919), ("uArr",    8657),
    ("ordm",   186), ("Theta",   920), ("rArr",    8658),
    ("raquo",  187), ("Iota",    921), ("dArr",    8659),
    ("frac14", 188), ("Kappa",   922), ("hArr",    8660),
    ("frac12", 189), ("Lambda",  923), ("forall",  8704),
    ("frac34", 190), ("Mu",      924), ("part",    8706),
    ("iquest", 191), ("Nu",      925), ("exist",   8707),
    ("Agrave", 192), ("Xi",      926), ("empty",   8709),
    ("Aacute", 193), ("Omicron", 927), ("nabla",   8711),
    ("Acirc",  194), ("Pi",      928), ("isin",    8712),
    ("Atilde", 195), ("Rho",     929), ("notin",   8713),
    ("Auml",   196), ("Sigma",   931), ("ni",      8715),
    ("Aring",  197), ("Tau",     932), ("prod",    8719),
    ("AElig",  198), ("Upsilon", 933), ("sum",     8721),
    ("Ccedil", 199), ("Phi",     934), ("minus",   8722),
    ("Egrave", 200), ("Chi",     935), ("lowast",  8727),
    ("Eacute", 201), ("Psi",     936), ("radic",   8730),
    ("Ecirc",  202), ("Omega",   937), ("prop",    8733),
    ("Euml",   203), ("alpha",   945), ("infin",   8734),
    ("Igrave", 204), ("beta",    946), ("ang",     8736),
    ("Iacute", 205), ("gamma",   947), ("and",     8743),
    ("Icirc",  206), ("delta",   948), ("or",      8744),
    ("Iuml",   207), ("epsilon", 949), ("cap",     8745),
    ("ETH",    208), ("zeta",    950), ("cup",     8746),
    ("Ntilde", 209), ("eta",     951), ("int",     8747),
    ("Ograve", 210), ("theta",   952), ("there4",  8756),
    ("Oacute", 211), ("iota",    953), ("sim",     8764),
    ("Ocirc",  212), ("kappa",   954), ("cong",    8773),
    ("Otilde", 213), ("lambda",  955), ("asymp",   8776),
    ("Ouml",   214), ("mu",      956), ("ne",      8800),
    ("times",  215), ("nu",      957), ("equiv",   8801),
    ("Oslash", 216), ("xi",      958), ("le",      8804),
    ("Ugrave", 217), ("omicron", 959), ("ge",      8805),
    ("Uacute", 218), ("pi",      960), ("sub",     8834),
    ("Ucirc",  219), ("rho",     961), ("sup",     8835),
    ("Uuml",   220), ("sigmaf",  962), ("nsub",    8836),
    ("Yacute", 221), ("sigma",   963), ("sube",    8838),
    ("THORN",  222), ("tau",     964), ("supe",    8839),
    ("szlig",  223), ("upsilon", 965), ("oplus",   8853),
    ("agrave", 224), ("phi",     966), ("otimes",  8855),
    ("aacute", 225), ("chi",     967), ("perp",    8869),
    ("acirc",  226), ("psi",     968), ("sdot",    8901),
    ("atilde", 227), ("omega",   969), ("lceil",   8968),
    ("auml",   228), ("thetasym",977), ("rceil",   8969),
    ("aring",  229), ("upsih",   978), ("lfloor",  8970),
    ("aelig",  230), ("piv",     982), ("rfloor",  8971),
    ("ccedil", 231), ("ensp",    8194),("lang",    9001),
    ("egrave", 232), ("emsp",    8195),("rang",    9002),
    ("eacute", 233), ("thinsp",  8201),("loz",     9674),
    ("ecirc",  234), ("zwnj",    8204),("spades",  9824),
    ("euml",   235), ("zwj",     8205),("clubs",   9827),
    ("igrave", 236), ("lrm",     8206),("hearts",  9829),
    ("iacute", 237), ("rlm",     8207),("diams",   9830),
    ("icirc",  238), ("ndash",   8211),
    ("iuml",   239), ("mdash",   8212),
];

// ===========================================================================
// Typed Meta — `AaMeta<'a>` + `AaEntry<'a>` + `AaValue<'a>`
// ===========================================================================

/// One emitted tag in [`AaMeta::entries`]. Each entry carries the resolved
/// `name` (post-`MakeTagName`/`AddTagToTable` normalization) and a typed
/// value. The `group` is always family-0 = family-1 = `"Audible"` (the
/// only group the AA path emits under).
#[derive(Debug, Clone)]
pub struct AaEntry<'a> {
  /// Tag name (e.g. `"Author"`, `"Title"`, `"Tag7eb298ac1328"`, `"ChapterCount"`,
  /// `"CoverArt"`). Already normalized via `MakeTagName` + `s/_(.)/\U$1/g` +
  /// `AddTagToTable` for the dynamic-name path; matches the static `TagDef::
  /// name()` for the explicit entries (`PublishDate`, `Author`, etc.).
  name: SmolStr,
  /// Tag value. Strings are post-UnescapeHTML + post-fix_utf8 (synthesized);
  /// `I64` carries the chunk-6 ChapterCount; `Bytes` carries cover art
  /// (chunk-11 or dict `_cover_art` after UnescapeHTML).
  value: AaValue<'a>,
}

impl<'a> AaEntry<'a> {
  /// Tag name (e.g. `"Author"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Typed tag value (borrow of the non-`Copy` [`AaValue`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &AaValue<'a> {
    &self.value
  }
}

/// Typed value variants emitted by an AA dict / chunk parse. The choice
/// between `Str` and `Bytes` mirrors the bundled-Perl `Binary => 1` table
/// flag (Audible.pm:46): `_cover_art` ⇒ `Bytes`; every other dict entry ⇒
/// `Str`. `I64` is only used for `_chapter_count` (Audible.pm:42, the
/// `Get32u(\$buff, 0)` u32 stored as i64 to match the existing
/// `TagValue::I64` JSON path).
///
/// D8 newtype-style — variants are flat data carriers; consumers match
/// directly. `#[non_exhaustive]`: AA could grow a typed value kind without a
/// breaking change for downstream matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AaValue<'a> {
  /// UTF-8 text post-UnescapeHTML + post-fix_utf8 (synthesized — does not
  /// borrow from input because the pipeline materially transforms bytes).
  /// Stored as [`SmolStr`] so small values (most AA dict tags) inline.
  Str(SmolStr),
  /// Signed integer (used only for `ChapterCount`).
  I64(i64),
  /// Raw binary data (cover art). The chunk-11 path borrows from the input
  /// buffer (`&'a [u8]`); the dict-`_cover_art` path produces an owned
  /// `Vec<u8>` because UnescapeHTML reshapes bytes. We unify via
  /// [`alloc::borrow::Cow`] so the chunk-11 hot path stays zero-copy while
  /// the dict path can still hand off owned bytes.
  Bytes(std::borrow::Cow<'a, [u8]>),
}

impl AaValue<'_> {
  /// True iff this is an [`AaValue::Str`].
  #[must_use]
  #[inline(always)]
  pub const fn is_str(&self) -> bool {
    matches!(self, AaValue::Str(_))
  }
  /// True iff this is an [`AaValue::I64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_i64(&self) -> bool {
    matches!(self, AaValue::I64(_))
  }
  /// True iff this is an [`AaValue::Bytes`].
  #[must_use]
  #[inline(always)]
  pub const fn is_bytes(&self) -> bool {
    matches!(self, AaValue::Bytes(_))
  }

  /// The string payload of an [`AaValue::Str`], else `None`.
  #[must_use]
  #[inline(always)]
  pub fn try_unwrap_str(&self) -> Option<&str> {
    match self {
      AaValue::Str(s) => Some(s.as_str()),
      _ => None,
    }
  }
  /// The integer payload of an [`AaValue::I64`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_i64(&self) -> Option<i64> {
    match self {
      AaValue::I64(n) => Some(*n),
      _ => None,
    }
  }
  /// The byte payload of an [`AaValue::Bytes`], else `None`.
  #[must_use]
  #[inline(always)]
  pub fn try_unwrap_bytes(&self) -> Option<&[u8]> {
    match self {
      AaValue::Bytes(b) => Some(b.as_ref()),
      _ => None,
    }
  }
}

/// Typed AA metadata — the lib-first output of [`ProcessAa`].
///
/// **D8 — no public fields, accessors only.**
///
/// **Shape.** AA's tag set is **dynamic**: chunk-2 dictionaries can carry
/// any number of arbitrary `tag_string => value_string` pairs (Audible.pm:
/// 256-258), each normalized via `MakeTagName` + `s/_(.)/\U$1/g` +
/// `AddTagToTable`. Adding to that, two chunk types emit single
/// well-known tags: chunk-6 ⇒ `ChapterCount` (Audible.pm:223), chunk-11 ⇒
/// `CoverArt` (Audible.pm:234). The natural typed representation is an
/// **ordered list of [`AaEntry`]** mirroring the bundled-Perl `FoundTag`
/// call sequence. Last-wins (Perl `FoundTag` promote-then-overwrite +
/// `%noDups` first-token filter, ExifTool.pm:9504-9577, exiftool:2744-2752)
/// is applied at construction in [`parse_inner`].
///
/// `cover_art` and `chapter_count` are also exposed as direct accessors for
/// library callers that want typed access without scanning the entries
/// list; the entries list is the canonical emission order, while the
/// dedicated slots cache the last-wins resolved values.
///
/// **Lifetimes.** Most fields are synthesized (entity-decoded /
/// UTF-8-repaired) and stored as [`SmolStr`] (alloc-backed). The cover-art
/// chunk-11 path stays zero-copy by borrowing `&'a [u8]` from input via
/// [`AaValue::Bytes`]`(Cow::Borrowed)`. The dict-`_cover_art` path
/// materializes an owned `Vec<u8>` (UnescapeHTML reshapes bytes).
#[derive(Debug, Clone)]
pub struct AaMeta<'a> {
  /// Ordered list of emitted tags (faithful to the Perl `FoundTag` call
  /// sequence in `ProcessAA` after last-wins resolution).
  entries: std::vec::Vec<AaEntry<'a>>,
  /// Warnings accumulated during parse (faithful to `$et->Warn` —
  /// Audible.pm:210, 212, 227, 228, 238, 240, 246, 252). Mirrors
  /// [`crate::value::Metadata::warnings`].
  warnings: std::vec::Vec<SmolStr>,
  /// Errors accumulated during parse (R9: HTML numeric entity above
  /// Perl `pack('C0U')`'s i64::MAX cap, surfaced as the engine's
  /// canonical `ExifTool:Error` substitute).
  errors: std::vec::Vec<SmolStr>,
}

impl<'a> AaMeta<'a> {
  /// All emitted tag entries in bundled-Perl `FoundTag` call order
  /// (post-last-wins resolution).
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[AaEntry<'a>] {
    &self.entries
  }

  /// Accumulated warnings (Audible.pm:210 `Invalid TOC`, 212
  /// `Truncated TOC`, 227 `Chunk N too big`, 228 `Chunk N read error`,
  /// 238 `Bad dictionary`, 240 `Bad dictionary count`, 246
  /// `Truncated dictionary`, 252 `Bad dictionary entry`).
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[SmolStr] {
    &self.warnings
  }

  /// Accumulated errors (R9: numeric entity above Perl `pack('C0U')`'s
  /// i64::MAX cap surfaces as the engine's `ExifTool:Error` substitute).
  #[must_use]
  #[inline(always)]
  pub fn errors(&self) -> &[SmolStr] {
    &self.errors
  }

  /// `ChapterCount` extracted from chunk-6 (Audible.pm:223), if present.
  /// Convenience accessor; the same value also appears as an [`AaEntry`]
  /// in [`Self::entries`] named `"ChapterCount"`.
  #[must_use]
  pub fn chapter_count(&self) -> Option<i64> {
    self
      .entries
      .iter()
      .find_map(|e| match (e.name.as_str(), &e.value) {
        ("ChapterCount", AaValue::I64(n)) => Some(*n),
        _ => None,
      })
  }

  /// `CoverArt` raw bytes from chunk-11 (Audible.pm:234) OR from
  /// dict `_cover_art` (Audible.pm:43-47), if present. The chunk-11
  /// path borrows from the input buffer (zero-copy); the dict path
  /// holds owned bytes.
  #[must_use]
  pub fn cover_art(&self) -> Option<&[u8]> {
    self
      .entries
      .iter()
      .find_map(|e| match (e.name.as_str(), &e.value) {
        ("CoverArt", AaValue::Bytes(b)) => Some(b.as_ref()),
        _ => None,
      })
  }
}

// ===========================================================================
// `ProcessAa` — the lib-first parser
// ===========================================================================

/// Big-endian u32 from `bytes[off..off+4]`. Faithful to Perl `Get32u(\$buf,
/// $off)` under `SetByteOrder('MM')` (Audible.pm:208). The caller is
/// responsible for the `off + 4 <= bytes.len()` precondition (mirrors Perl,
/// which would otherwise read past the end of the substr — but every
/// caller below guards that explicitly).
fn get32u_be(bytes: &[u8], off: usize) -> u32 {
  debug_assert!(off + 4 <= bytes.len(), "Get32u out of range: off={off}");
  u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// AA parser (faithful `ProcessAA`, Audible.pm:194-273).
#[derive(Debug, Clone, Copy)]
pub struct ProcessAa;

impl parser_sealed::Sealed for ProcessAa {}

impl FormatParser for ProcessAa {
  /// AA's only borrowed lifetime is the cover-art chunk-11 path (`&'a
  /// [u8]`). GAT: the Meta borrows from the input `'a` directly (Codex
  /// AF2).
  type Meta<'a> = AaMeta<'a>;
  /// Spec §8: leaf format Context is `&'a [u8]` (no shared cross-format
  /// state — AA does not chain to ID3/APE etc.).
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; AA parsing has no I/O modes —
  /// every bad input either returns `Ok(None)` or accumulates warnings/
  /// errors into the typed Meta and returns `Ok(Some)`).
  type Error = AudibleError;

  /// Parse an AA file's bytes into a typed [`AaMeta`], or `None` if the
  /// buffer is not a valid AA (short read, wrong magic, or embedded
  /// filesize mismatch — Audible.pm:201-205). Returns `Err` only for
  /// Rust-level fatal modes; the current port has none.
  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, AudibleError> {
    Ok(parse_inner(data))
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`AaMeta`] that borrows the cover-art chunk-11 payload directly from
/// the input buffer (zero-copy).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<AaMeta<'_>>, AudibleError> {
  Ok(parse_inner(data))
}

/// Inner parser — produces a borrow-from-input [`AaMeta`] (chunk-11 cover
/// art borrows). The [`FormatParser::Meta`] GAT (`type Meta<'a> =
/// AaMeta<'a>`) returns this borrowed form directly into the closed
/// [`crate::parser_new::AnyMeta`] enum — no `'static` upgrade (Codex AF2).
///
/// Faithful to `ProcessAA` (Audible.pm:194-273):
/// 1. 16-byte magic + filesize gate (Audible.pm:201-205) — return `None`
///    on reject (Perl `return 0`).
/// 2. `SetFileType()` (Audible.pm:207) — the bridge runs this in the
///    legacy the engine entry `process` path, not here; the typed parser
///    doesn't push `File:*` tags.
/// 3. `SetByteOrder('MM')` (Audible.pm:208) — every u32 read is BE.
/// 4. TOC walk (Audible.pm:215-271) — dispatch chunk 6 (chapter count),
///    chunk 11 (cover art), chunk 2 (UTF-8 dictionary).
fn parse_inner(data: &[u8]) -> Option<AaMeta<'_>> {
  // Audible.pm:201 — `$raf->Read($buff, 16) == 16 and $buff =~
  // /^.{4}\x57\x90\x75\x36/s`. Magic at bytes[4..8]; first 4 bytes are
  // unconstrained at this step.
  let data_len = data.len();
  if data_len < 16 {
    return None; // short read ⇒ Perl `return 0`
  }
  if data[4..8] != [0x57, 0x90, 0x75, 0x36] {
    return None; // magic mismatch ⇒ Perl `return 0`
  }
  // Audible.pm:203-206 — `defined $$et{VALUE}{FileSize}` AND
  // `unpack('N', $buff) == $$et{VALUE}{FileSize}`. The engine
  // doesn't push File:FileSize on this read path (the CLI strips
  // it), but ExifTool *internally* still has `$$self{VALUE}{
  // FileSize}` set from the stat pre-pass — the cross-check fires.
  // Faithful oracle: the actual data length the engine sees.
  let claimed_size = get32u_be(data, 0);
  if data_len as u64 != u64::from(claimed_size) {
    // Mismatch ⇒ `return 0` (Audible.pm:205, before SetFileType).
    return None;
  }

  // Local accumulators (the typed Meta we build up). The Perl push-style
  // `$et->FoundTag` + `$et->Warn` calls become these in-memory pushes;
  // last-wins / first-wins resolution runs against this Vec, NOT against
  // engine state.
  let mut entries: std::vec::Vec<AaEntry<'_>> = std::vec::Vec::new();
  let mut warnings: std::vec::Vec<SmolStr> = std::vec::Vec::new();
  let mut errors: std::vec::Vec<SmolStr> = std::vec::Vec::new();

  // Audible.pm:208 — `SetByteOrder('MM')`. Every multi-byte read below
  // uses `u32::from_be_bytes`.

  // Audible.pm:209 — `my $bytes = 12 * Get32u(\$buff, 8)`. Saturating
  // multiply ensures no overflow (Perl scalars are 64-bit; we cap at
  // usize for the slice indexing below).
  let toc_count = get32u_be(data, 8) as usize;
  let toc_bytes = toc_count.saturating_mul(12);

  // Audible.pm:210 — `$bytes > 0xc00 and $et->Warn('Invalid TOC'),
  // return 1`. The comma-operator chain still returns 1 (the value of
  // the last expression). Faithful: warn + return TRUE (accept).
  if toc_bytes > 0xc00 {
    warnings.push(SmolStr::new_static("Invalid TOC"));
    return Some(AaMeta {
      entries,
      warnings,
      errors,
    });
  }

  // Audible.pm:212 — `$raf->Read($toc, $bytes) == $bytes or
  // $et->Warn('Truncated TOC'), return 1`. TOC starts at file offset 16
  // (right after the 16-byte read buffer).
  let toc_start = 16usize;
  let Some(toc_end) = toc_start.checked_add(toc_bytes) else {
    // Numerically impossible after the 0xc00 cap, but keep panic-free.
    warnings.push(SmolStr::new_static("Truncated TOC"));
    return Some(AaMeta {
      entries,
      warnings,
      errors,
    });
  };
  if toc_end > data_len {
    warnings.push(SmolStr::new_static("Truncated TOC"));
    return Some(AaMeta {
      entries,
      warnings,
      errors,
    });
  }
  // Borrow the TOC slice from input (≤ 0xc00 = 3072 bytes). The labels
  // below need both the TOC view and the chunk-payload view; both
  // ultimately borrow from `data`, lifetimes coincide.
  let toc: &[u8] = &data[toc_start..toc_end];

  // Audible.pm:215-271 — TOC walk. ExifTool processes chunks in TOC
  // order (entry index ascending); output tag order follows.
  //
  // R10: the dict-loop's fatal-entity arm (Perl `pack('C0U')` die
  // at XMP.pm:2933) needs to terminate ALL further AA processing,
  // not just the inner dict iteration. Labeled `'toc:` lets the
  // arm break out of BOTH loops at once; subsequent type-6
  // (ChapterCount) / type-11 (CoverArt) chunks are NOT emitted,
  // matching Perl's process-fatal abort.
  let mut entry = 0usize;
  'toc: while entry < toc_bytes {
    let chunk_type = get32u_be(toc, entry);
    // Audible.pm:217 — `next unless $type == 2 or $type == 6 or
    // $type == 11`.
    if chunk_type != 2 && chunk_type != 6 && chunk_type != 11 {
      entry += 12;
      continue;
    }
    let offset = get32u_be(toc, entry + 4) as usize;
    let length = get32u_be(toc, entry + 8) as usize;
    // Audible.pm:219 — `Get32u(\$toc, $entry + 8) or next` — falsy
    // length skips. After this point `length` is guaranteed > 0.
    if length == 0 {
      entry += 12;
      continue;
    }
    // Audible.pm:220 — `$raf->Seek($offset, 0) or $et->Warn("Chunk
    // $type seek error"), last`. NOTE: `File::RandomAccess::Seek`
    // succeeds even when the requested offset is past EOF
    // (RandomAccess.pm:141-143 explicit: "this doesn't quite behave
    // like seek() since it will return success even if you seek
    // outside the limits of the file. However if you do this, you
    // will get an error on your next Read()"). The unbuffered backing
    // delegates to Perl's `seek()`, which only fails on broken file
    // handles. Both non-failures mean the "Chunk $type seek error"
    // branch is effectively dead for in-memory / normal-file
    // backings — the actual EOF surfaces at the per-chunk Read below.
    // Faithful port: don't gate on offset alone; let each type's own
    // Read-length check decide between silent skip (type 6) and the
    // "read error" warning (types 2/11). Codex R1 finding #1.

    if chunk_type == 6 {
      // Audible.pm:221-225 — offset table; we only read the chapter
      // count (the first u32 of the chunk). The inline `next if
      // $length < 4 or $raf->Read($buff, 4) != 4` (:222) silently
      // skips a short or unreadable type-6 chunk — no Warn.
      if length < 4 {
        entry += 12;
        continue;
      }
      let read_end = match offset.checked_add(4) {
        Some(e) => e,
        None => {
          entry += 12;
          continue;
        }
      };
      if read_end > data_len {
        // Short read ⇒ `next` (Audible.pm:222), silent skip.
        entry += 12;
        continue;
      }
      let count = get32u_be(data, offset);
      // Last-wins replace: bundled Perl `FoundTag` (ExifTool.pm:9504-
      // 9577) promotes the earlier `ChapterCount` to `ChapterCount (1)`
      // and writes the new value at the base key; `%noDups` filter
      // (exiftool:2744-2752) then drops `(1)`, emitting only the
      // LATEST count. R6 fix: chunk-6 must go through the same
      // last-wins helper as the dict path.
      handle_static_entry(&mut entries, "ChapterCount", AaValue::I64(i64::from(count)));
      entry += 12;
      continue;
    }

    // Audible.pm:227 — `$length > 100000000 and $et->Warn("Chunk $type
    // too big"), next`. Checked BEFORE the Read so an oversized chunk
    // never triggers the "read error" branch even when EOF would have
    // bitten first.
    if length > 100_000_000 {
      warnings.push(SmolStr::from(format!("Chunk {chunk_type} too big")));
      entry += 12;
      continue;
    }
    // Audible.pm:228 — `$raf->Read($buff, $length) == $length or
    // $et->Warn("Chunk $type read error"), last`. Type 2/11 short
    // read ⇒ Warn + STOP the TOC walk (`last`).
    let chunk_end = match offset.checked_add(length) {
      Some(e) => e,
      None => {
        warnings.push(SmolStr::from(format!("Chunk {chunk_type} read error")));
        break;
      }
    };
    if chunk_end > data_len {
      warnings.push(SmolStr::from(format!("Chunk {chunk_type} read error")));
      break;
    }
    // Borrow the chunk bytes directly from `data`. The borrow outlives
    // every push below (the accumulators are local).
    let buf: &[u8] = &data[offset..chunk_end];

    if chunk_type == 11 {
      // Audible.pm:229-235 — cover art. `length < 8` is implicit (we
      // need to read two u32s); explicit guard mirrors Perl.
      if length < 8 {
        entry += 12;
        continue;
      }
      // Audible.pm:231-232 — `len = Get32u($buff, 0)`, `off = Get32u
      // ($buff, 4)`. Both u32. `off` is an ABSOLUTE file offset (Perl
      // semantics: matches the chunk's $offset arithmetic below).
      let cover_len = get32u_be(buf, 0) as usize;
      let cover_off = get32u_be(buf, 4) as usize;
      // Audible.pm:233 — `next if $off < $offset + 8 or $off - $offset
      // + $len > $length`. The first half guards that the cover
      // payload starts inside this chunk (past the 2-u32 header); the
      // second half guards that it ends within the chunk.
      let Some(min_off) = offset.checked_add(8) else {
        entry += 12;
        continue;
      };
      if cover_off < min_off {
        entry += 12;
        continue;
      }
      // After the first guard, `cover_off >= offset + 8`, so
      // `cover_off - offset >= 8 > 0` — no underflow. Faithful
      // signed-Perl → unsigned-Rust pattern (see
      // `[[exifast-phase2-forward-items]]` underflow item).
      debug_assert!(
        cover_off >= offset + 8,
        "cover_off >= offset+8 (Audible.pm:233 first guard)"
      );
      let cover_rel = cover_off - offset;
      let Some(cover_rel_end) = cover_rel.checked_add(cover_len) else {
        entry += 12;
        continue;
      };
      if cover_rel_end > length {
        entry += 12;
        continue;
      }
      // Audible.pm:234 — `HandleTag('_cover_art', substr($buff,
      // $off-$offset, $len))`. Borrow the cover bytes from input
      // (zero-copy via Cow::Borrowed).
      let cover_bytes: &[u8] = &buf[cover_rel..cover_rel_end];
      handle_static_entry(
        &mut entries,
        "CoverArt",
        AaValue::Bytes(std::borrow::Cow::Borrowed(cover_bytes)),
      );
      entry += 12;
      continue;
    }

    // chunk_type == 2 — metadata dictionary (Audible.pm:238-270).
    // Audible.pm:238 — `length < 4 and $et->Warn('Bad dictionary'), next`.
    if length < 4 {
      warnings.push(SmolStr::new_static("Bad dictionary"));
      entry += 12;
      continue;
    }
    let num = get32u_be(buf, 0) as usize;
    // Audible.pm:240 — `$num > 0x200 and $et->Warn('Bad dictionary
    // count'), next`.
    if num > 0x200 {
      warnings.push(SmolStr::new_static("Bad dictionary count"));
      entry += 12;
      continue;
    }
    // Audible.pm:241 — `my $pos = 4`. dictionary starts after the
    // count.
    let mut pos: usize = 4;
    // Audible.pm:244-269 — read each dictionary entry. `$i` itself is
    // unused for the tag emission (it goes to HandleTag as Index =>
    // $i, which the engine doesn't model).
    for _i in 0..num {
      // Audible.pm:245 — `my $tagPos = $pos + 9`.
      let Some(tag_pos) = pos.checked_add(9) else {
        warnings.push(SmolStr::new_static("Truncated dictionary"));
        break;
      };
      // Audible.pm:246 — `$tagPos > $length and $et->Warn('Truncated
      // dictionary'), last`.
      if tag_pos > length {
        warnings.push(SmolStr::new_static("Truncated dictionary"));
        break;
      }
      // Audible.pm:248 — `$tagLen = Get32u($buff, $pos + 1)`.
      let tag_len = get32u_be(buf, pos + 1) as usize;
      // Audible.pm:249 — `$valLen = Get32u($buff, $pos + 5)`.
      let val_len = get32u_be(buf, pos + 5) as usize;
      // Audible.pm:250-251 — `$valPos = $tagPos + $tagLen`, `$nxtPos
      // = $valPos + $valLen`. Checked addition keeps panic-free.
      let Some(val_pos) = tag_pos.checked_add(tag_len) else {
        warnings.push(SmolStr::new_static("Bad dictionary entry"));
        break;
      };
      let Some(nxt_pos) = val_pos.checked_add(val_len) else {
        warnings.push(SmolStr::new_static("Bad dictionary entry"));
        break;
      };
      // Audible.pm:252 — `$nxtPos > $length and $et->Warn('Bad
      // dictionary entry'), last`.
      if nxt_pos > length {
        warnings.push(SmolStr::new_static("Bad dictionary entry"));
        break;
      }
      // Audible.pm:253-254 — extract the two byte ranges.
      // Audible.pm:253 — `$tag = substr($buff, $tagPos, $tagLen)`.
      // The tag id is a byte string used as a hash key — Perl does
      // NOT decode it as UTF-8 (it's an opaque ASCII-ish identifier
      // like "product_id"). Treat as Latin-1 / ASCII (lossy_utf8 is
      // safe because every tag id encountered is ASCII).
      let tag = String::from_utf8_lossy(&buf[tag_pos..val_pos]).into_owned();
      // Audible.pm:261 — `$val = $et->Decode(UnescapeHTML($val),
      // 'UTF8')`. The Perl pipeline operates on raw bytes (see
      // unescape_html_bytes docs); R9: a numeric entity above Perl's
      // pack('C0U') i64::MAX cap is fatal.
      let unescaped_bytes = match unescape_html_bytes(&buf[val_pos..nxt_pos]) {
        Ok(b) => b,
        Err(FatalEntityError) => {
          errors.push(SmolStr::new_static(
            "Use of code point above 0x7FFFFFFFFFFFFFFF is not allowed",
          ));
          // R10: bundled Perl `pack('C0U')` die at XMP.pm:2933 aborts
          // the entire `exiftool` process. Faithful Rust mirror:
          // labeled break out of both loops.
          break 'toc;
        }
      };

      // Audible.pm:255-259 — dispatch by static-table presence.
      let table_get = (AUDIBLE_MAIN.get())(TagId::Str(known_static_key(&tag)));
      match table_get {
        Some(def) => {
          // R6: `_cover_art` static def carries `Binary => 1` (Audible.pm:
          // 43-47). Bundled Perl HandleTag stores raw post-UnescapeHTML
          // bytes; the JSON tier renders the universal binary
          // placeholder where N is the byte count. fix_utf8's per-`?`
          // expansion would change that count, so the binary path
          // skips it.
          let value = if def.name() == "CoverArt" {
            AaValue::Bytes(std::borrow::Cow::Owned(unescaped_bytes))
          } else {
            AaValue::Str(SmolStr::from(fix_utf8(&unescaped_bytes)))
          };
          // Last-wins: bundled Perl FoundTag promote-then-overwrite +
          // `%noDups` first-token filter ⇒ replace in-place at first
          // slot, preserving order.
          handle_static_entry(&mut entries, def.name(), value);
        }
        None => {
          // R7: Perl `%specialTags` (ExifTool.pm:1229-1236) keys collide
          // with table-internal fields. Their dict-loop path goes
          // through `unless ($$tagTablePtr{$tag})` — since the table has
          // GROUPS/FORMAT/etc. defined as hashrefs, the unless is FALSE
          // and AddTagToTable is skipped. Then HandleTag's `GetTagInfo`
          // warns and returns empty, so `FoundTag` is never reached.
          // The faithful equivalent here is: skip entirely.
          if is_perl_special_tag(&tag) {
            pos = nxt_pos;
            continue;
          }

          // Audible.pm:256-258 — dynamic-name path. Three-step
          // normalization (faithful Perl flow):
          // 1. MakeTagName       — ExifTool.pm:6440
          // 2. s/_(.)/\U$1/g     — Audible.pm:257
          // 3. AddTagToTable     — ExifTool.pm:9243-9254 prefix gate
          let dynamic_name =
            add_tag_to_table_name_normalize(underscore_to_mixed_case(&make_tag_name(&tag)));
          let value = AaValue::Str(SmolStr::from(fix_utf8(&unescaped_bytes)));

          // R7: dynamic-name collisions with engine pre-emitted
          // Priority-2 tags (only `FileType`) need first-wins. The
          // engine pushes `File:FileType=AA` UNCONDITIONALLY (via
          // `ctx.set_file_type` after this parser accepts), so we can
          // hardcode "any dict `FileType` triggers first-wins" without
          // peeking at engine state.
          handle_dynamic_entry(&mut entries, dynamic_name, value);
        }
      }
      // Audible.pm:269 — `$pos = $nxtPos`.
      pos = nxt_pos;
    }
    entry += 12;
  }

  Some(AaMeta {
    entries,
    warnings,
    errors,
  })
}

/// Helper: `AUDIBLE_MAIN.get()` needs a `&'static str` to dispatch on; the
/// caller has a runtime-owned `String`. Match against the SIX explicit
/// static keys and return the corresponding `&'static str` literal; any
/// other input returns `""` so `audible_get` falls through to the default
/// arm (`None`) and the caller takes the dynamic-name path. No allocation
/// or leakage — the runtime string is compared, the static literal is
/// returned.
fn known_static_key(tag: &str) -> &'static str {
  match tag {
    "pubdate" => "pubdate",
    "pub_date_start" => "pub_date_start",
    "author" => "author",
    "copyright" => "copyright",
    "_chapter_count" => "_chapter_count",
    "_cover_art" => "_cover_art",
    // Any other key resolves to a non-matching static literal so the
    // table-get falls through to `None`. The empty string is a safe
    // sentinel (no static entry matches it).
    _ => "",
  }
}

/// Push a static-table entry with Perl `FoundTag` last-wins semantics for
/// duplicates. ExifTool.pm:9504-9577 promotes the earlier entry to
/// `$tag (1)` and writes the new value at the base `$tag` key; the
/// `%noDups` serializer (exiftool:2744-2752) then suppresses `(1)`,
/// emitting only the LATEST value. We collapse that round-trip to a
/// direct in-place replace at the original slot (preserves insertion
/// order so `%noDups` keyed by `<family1>:<name>` remains first-token).
///
/// Pinned to the AA path only — the engine-wide HandleTag promotion is a
/// Phase-2 forward-item.
fn handle_static_entry<'a>(
  entries: &mut std::vec::Vec<AaEntry<'a>>,
  name: &str,
  value: AaValue<'a>,
) {
  if let Some(existing) = entries.iter_mut().find(|e| e.name == name) {
    existing.value = value;
  } else {
    entries.push(AaEntry {
      name: SmolStr::from(name),
      value,
    });
  }
}

/// Push a dynamic-name (post-MakeTagName) dict entry with last-wins
/// semantics. The R7 exception is the engine cross-group Priority-2
/// collision: when the resolved dynamic name is `FileType`, the engine's
/// `File:FileType=AA` (Priority 2; pushed by the bridge's
/// `ctx.set_file_type` BEFORE sink time) wins the promotion-gate, so the
/// FIRST AA push survives and subsequent dups are dropped.
///
/// R8 narrowed the cross-group first-wins from "any cross-group same-name"
/// to "exact match against the known Priority-2 engine tag name"
/// (`FileType` is the only one; `FileTypeExtension`/`MIMEType`/
/// `ExifToolVersion` use default Priority 1 and stay last-wins).
fn handle_dynamic_entry<'a>(
  entries: &mut std::vec::Vec<AaEntry<'a>>,
  name: String,
  value: AaValue<'a>,
) {
  if let Some(existing) = entries.iter_mut().find(|e| e.name == name.as_str()) {
    if collides_with_priority2_engine_tag(&name) {
      // R7/R8 first-wins exception: keep the existing (first) value.
      return;
    }
    existing.value = value;
  } else {
    entries.push(AaEntry {
      name: SmolStr::from(name),
      value,
    });
  }
}

/// True iff the dynamic-name resolves to a Priority-2 engine pre-emitted
/// bare name. Pre-AA emissions from the engine that declare `Priority => 2`
/// (ExifTool.pm:1437+): `FileType`. The other pre-emitted bare names
/// (`FileTypeExtension`, `MIMEType`, `ExifToolVersion`) use the default
/// Priority 1 and therefore do NOT trigger Perl FoundTag's no-promotion
/// arm; AA dict duplicates of those resolve to last-wins (the symmetric
/// promote case).
///
/// Hardcoded: because `ctx.set_file_type` runs UNCONDITIONALLY for an
/// accepted AA file (Audible.pm:207), the cross-group `File:FileType`
/// is ALWAYS present at sink time. The previous engine-state check
/// (`meta.tags().iter().any(...)`) is unnecessary in the typed path.
fn collides_with_priority2_engine_tag(name: &str) -> bool {
  name == "FileType"
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl AaMeta<'_> {
  /// Emit AA tags into the writer in `ProcessAA` extraction order
  /// (Audible.pm:215-271): TOC-walk order of (chunk_type ∈ {2, 6, 11})
  /// emissions, post-last-wins/first-wins resolution.
  ///
  /// AA has no PrintConv conversions — every static `TagDef` carries
  /// `ValueConv::None` + `PrintConv::None` (Audible.pm:24-48); dynamic
  /// dict entries are plain strings. So `-j` and `-n` emit identical
  /// tag values from this sink; the `print_conv` parameter is
  /// accepted for trait conformance but has no effect on AA emission.
  /// (The only -j vs -n difference for AA files is the engine's
  /// `File:FileTypeExtension` PrintConv `"aa"` vs `"AA"`, applied by
  /// `ctx.set_file_type` outside this sink.)
  pub(crate) fn serialize_tags(
    &self,
    _print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    const GROUP: &str = "Audible";
    // Tags first (TOC walk order, last-wins resolved at parse time).
    for entry in &self.entries {
      match &entry.value {
        AaValue::Str(s) => out.write_str(GROUP, entry.name.as_str(), s.as_str())?,
        AaValue::I64(n) => out.write_i64(GROUP, entry.name.as_str(), *n)?,
        AaValue::Bytes(b) => out.write_bytes(GROUP, entry.name.as_str(), b.as_ref())?,
      }
    }
    // Warnings (Audible.pm `$et->Warn` accumulator). The CLI serializer
    // emits only the FIRST warning (`%noDups` first-token filter +
    // copy-suffix dedup); pushing every warning here lets a future
    // engine grow `-a`/Duplicates without breaking the typed path.
    for w in &self.warnings {
      out.write_warning(w.as_str())?;
    }
    // Errors (R9 fatal-entity ExifTool:Error substitute).
    for e in &self.errors {
      out.write_error(e.as_str())?;
    }
    Ok(())
  }
}

// ===========================================================================
// `AudibleError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for AA parsing. Currently empty — every bad
/// input either produces `Ok(None)` (Perl `return 0`) or surfaces
/// warnings/errors inside the typed [`AaMeta`] (Perl `$et->Warn` /
/// `$et->Error`). Reserved for future I/O wrappers if streaming readers
/// are added.
///
/// §5: derived via `thiserror` (v2, `default-features = false` ⇒
/// `core::error::Error`), `#[non_exhaustive]` so variants can be added
/// without a breaking change. Variant names are kept stable for
/// [`crate::parser_new::AnyError`]'s `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AudibleError {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tagmap::TagMap;
  use crate::value::TagValue;

  // The engine path is now `crate::parser::extract_info`. `engine_obj` runs it
  // and returns the parsed file object (replacing the retired `ProcessAa::process`
  // + `TagMap` tests). `is_aa` checks finalization.
  fn engine_obj(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.aa", data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }
  fn is_aa(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("File:FileType").and_then(|v| v.as_str()) == Some("AA")
  }

  // ----- Static table -----

  #[test]
  fn table_carries_explicit_pm_entries() {
    let g = AUDIBLE_MAIN.get();
    assert_eq!(g(TagId::Str("pubdate")).unwrap().name(), "PublishDate");
    assert_eq!(
      g(TagId::Str("pub_date_start")).unwrap().name(),
      "PublishDateStart"
    );
    assert_eq!(g(TagId::Str("author")).unwrap().name(), "Author");
    assert_eq!(g(TagId::Str("copyright")).unwrap().name(), "Copyright");
    assert_eq!(
      g(TagId::Str("_chapter_count")).unwrap().name(),
      "ChapterCount"
    );
    assert_eq!(g(TagId::Str("_cover_art")).unwrap().name(), "CoverArt");
    // Family-1 group = "Audible".
    assert_eq!(g(TagId::Str("author")).unwrap().group1(), "Audible");
    assert_eq!(AUDIBLE_MAIN.group0(), "Audible");
    // Misses fall through.
    assert!(g(TagId::Str("nope")).is_none());
    assert!(g(TagId::Int(0)).is_none());
  }

  // ----- MakeTagName -----

  #[test]
  fn make_tag_name_short_or_digit_prefix_gets_tag_prefix() {
    // Audible.pm comment says "<12 hex digits>" can appear in the
    // dictionary — the fixture's `7eb298ac1328` exercises this.
    // ExifTool.pm:6446: prepend "Tag" if len<2 OR first ∈ [-0-9].
    assert_eq!(make_tag_name("7eb298ac1328"), "Tag7eb298ac1328");
    // Length < 2.
    assert_eq!(make_tag_name(""), "Tag");
    assert_eq!(make_tag_name("a"), "TagA"); // ucfirst then Tag-prefix
    // Leading hyphen.
    assert_eq!(make_tag_name("-foo"), "Tag-foo");
    // Normal name: ucfirst only.
    assert_eq!(make_tag_name("product_id"), "Product_id");
    assert_eq!(make_tag_name("ALBUMARTIST"), "ALBUMARTIST");
  }

  #[test]
  fn make_tag_name_drops_illegal_chars() {
    // tr/-_a-zA-Z0-9//dc deletes everything else.
    assert_eq!(make_tag_name("a.b"), "Ab");
    assert_eq!(make_tag_name("hello world"), "Helloworld");
    assert_eq!(make_tag_name("foo!@#bar"), "Foobar");
  }

  // ----- underscore_to_mixed_case -----

  #[test]
  fn underscore_to_mixed_case_capitalizes_after_underscore() {
    assert_eq!(underscore_to_mixed_case("Pub_date_start"), "PubDateStart");
    assert_eq!(underscore_to_mixed_case("ProductId"), "ProductId");
    assert_eq!(underscore_to_mixed_case("foo_"), "foo_");
    assert_eq!(underscore_to_mixed_case("a__b"), "a_b");
  }

  // ----- AddTagToTable post-normalization -----

  #[test]
  fn add_tag_to_table_name_normalize_perl_pin() {
    assert_eq!(
      add_tag_to_table_name_normalize("_foo".to_string()),
      "Tag_foo"
    );
    assert_eq!(add_tag_to_table_name_normalize("Foo".to_string()), "Foo");
    assert_eq!(add_tag_to_table_name_normalize("foo".to_string()), "foo");
    assert_eq!(add_tag_to_table_name_normalize("a".to_string()), "Taga");
    assert_eq!(add_tag_to_table_name_normalize("".to_string()), "Tag");
    assert_eq!(
      add_tag_to_table_name_normalize("Tag_foo".to_string()),
      "Tag_foo"
    );
    assert_eq!(
      add_tag_to_table_name_normalize("1foo".to_string()),
      "Tag1foo"
    );
  }

  #[test]
  fn full_dynamic_name_pipeline_perl_pin() {
    let pipeline = |tag: &str| -> String {
      add_tag_to_table_name_normalize(underscore_to_mixed_case(&make_tag_name(tag)))
    };
    assert_eq!(pipeline("__foo"), "Tag_foo");
    assert_eq!(pipeline("_foo"), "Foo");
    assert_eq!(pipeline("___foo"), "Tag_Foo");
    assert_eq!(pipeline("7eb298ac1328"), "Tag7eb298ac1328");
  }

  // ----- HTML unescape -----

  #[test]
  fn unescape_html_named_numeric_and_full_table() {
    // Plain pass-through.
    assert_eq!(unescape_html("plain"), "plain");
    // XML-5 (always present in %entityNum).
    assert_eq!(unescape_html("a&amp;b"), "a&b");
    assert_eq!(unescape_html("&lt;tag&gt;"), "<tag>");
    assert_eq!(unescape_html("&quot;x&quot;"), "\"x\"");
    assert_eq!(unescape_html("don&apos;t"), "don't");
    // Named non-XML entities.
    assert_eq!(unescape_html("&copy;"), "©");
    assert_eq!(unescape_html("&nbsp;"), "\u{00a0}");
    assert_eq!(unescape_html("&mdash;"), "—");
    assert_eq!(unescape_html("&eacute;"), "é");
    assert_eq!(unescape_html("&Alpha;"), "Α");
    // Numeric (decimal): `&#169;` = `©`.
    assert_eq!(unescape_html("&#169;"), "©");
    // Numeric (hex): lowercase `#x` only, per XMP.pm:2924.
    assert_eq!(unescape_html("&#xA9;"), "©");
    // Uppercase `#X` is NOT a valid hex entity.
    assert_eq!(unescape_html("&#XA9;"), "&#XA9;");
    // Unknown entity: literal pass-through (XMP.pm:2929).
    assert_eq!(unescape_html("&fubar;"), "&fubar;");
    // Bare `&` with no `;` ⇒ literal.
    assert_eq!(unescape_html("a & b"), "a & b");
    // `&;` (empty body): `\w+` requires at least one char ⇒ literal.
    assert_eq!(unescape_html("&;"), "&;");
    // Multiple consecutive entities.
    assert_eq!(unescape_html("&lt;&amp;&gt;"), "<&>");
    // Entity body interrupted by a non-`\w` character.
    assert_eq!(unescape_html("&amp ;"), "&amp ;");
  }

  #[test]
  fn unescape_html_numeric_entity_above_u32_matches_perl_pack_c0u() {
    assert_eq!(unescape_html("X&#x100000000;Y"), "X???????Y");
    assert_eq!(unescape_html("X&#x1000000000;Y"), "X?????????????Y");
    assert_eq!(unescape_html("X&#x7FFFFFFFFFFFFFFF;Y"), "X?????????????Y");
    assert_eq!(unescape_html("X&#4294967296;Y"), "X???????Y");
  }

  #[test]
  fn unescape_html_numeric_entity_above_i64_max_is_fatal() {
    assert_eq!(
      unescape_html_try("X&#x8000000000000000;Y"),
      Err(FatalEntityError),
    );
    assert_eq!(
      unescape_html_try("X&#9223372036854775808;Y"),
      Err(FatalEntityError),
    );
    assert_eq!(
      unescape_html_try("X&#xFFFFFFFFFFFFFFFFF;Y"),
      Err(FatalEntityError),
    );
    assert_eq!(
      unescape_html_try("X&#x7FFFFFFFFFFFFFFF;Y"),
      Ok("X?????????????Y".to_string()),
    );
  }

  // ----- Magic / file-size gate -----

  #[test]
  fn reject_short_data_does_not_set_filetype() {
    assert!(!is_aa(&engine_obj(&[0u8; 8]))); // < 16
  }

  #[test]
  fn reject_bad_magic_does_not_set_filetype() {
    let mut data = [0u8; 16];
    data[4..8].copy_from_slice(&[0, 0, 0, 0]);
    assert!(!is_aa(&engine_obj(&data)));
  }

  #[test]
  fn reject_file_size_mismatch_does_not_set_filetype() {
    let mut data = [0u8; 20];
    data[0..4].copy_from_slice(&[0, 0, 3, 0xe7]); // 999 BE
    data[4..8].copy_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    assert!(!is_aa(&engine_obj(&data)));
  }

  #[test]
  fn accept_empty_toc_emits_only_filetype_triplet() {
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&[0, 0, 0, 16]);
    data[4..8].copy_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    let obj = engine_obj(&data);
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AA")
    );
    // Only File:* + orchestration — no Audible:* body tags.
    assert!(!obj.keys().any(|k| k.starts_with("Audible:")));
  }

  #[test]
  fn invalid_toc_warns_and_accepts() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&[0, 0, 0, 16]);
    data[4..8].copy_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    data[8..12].copy_from_slice(&[0, 0, 0x01, 0x01]); // 257 ⇒ 3084 > 3072
    let obj = engine_obj(&data);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Invalid TOC")
    );
  }

  #[test]
  fn truncated_toc_warns_and_accepts() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&[0, 0, 0, 16]);
    data[4..8].copy_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    data[8..12].copy_from_slice(&[0, 0, 0, 5]);
    let obj = engine_obj(&data);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Truncated TOC")
    );
  }

  /// Build a minimal AA file with a single type-2 dictionary chunk.
  fn build_aa_with_dict(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut dict = Vec::new();
    dict.extend_from_slice(&(entries.len() as u32).to_be_bytes()); // count
    for (tag, val) in entries {
      dict.push(0x06); // 1 unknown byte
      dict.extend_from_slice(&(tag.len() as u32).to_be_bytes());
      dict.extend_from_slice(&(val.len() as u32).to_be_bytes());
      dict.extend_from_slice(tag.as_bytes());
      dict.extend_from_slice(val.as_bytes());
    }
    let dict_len = dict.len();
    let toc_size = 12u32;
    let dict_offset = 16 + toc_size;
    let mut toc = Vec::with_capacity(toc_size as usize);
    toc.extend_from_slice(&2u32.to_be_bytes());
    toc.extend_from_slice(&dict_offset.to_be_bytes());
    toc.extend_from_slice(&(dict_len as u32).to_be_bytes());
    let total = 16 + toc.len() + dict.len();
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&(total as u32).to_be_bytes());
    header.extend_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    header.extend_from_slice(&1u32.to_be_bytes()); // toc count
    header.extend_from_slice(&[0, 0, 0, 0]);
    let mut out = Vec::with_capacity(total);
    out.extend(header);
    out.extend(toc);
    out.extend(dict);
    debug_assert_eq!(out.len(), total);
    out
  }

  /// Typed parse + TagMap, returning the `Audible:*` entries in order
  /// (key without the prefix, value). Order is preserved by the typed sink.
  fn audible_entries(bytes: &[u8]) -> Vec<(String, TagValue)> {
    let meta = parse_borrowed(bytes).expect("ok").expect("parsed");
    let mut tm = TagMap::new();
    meta.serialize_tags(true, &mut tm).unwrap();
    tm.entries()
      .iter()
      .filter_map(|(k, v)| {
        k.strip_prefix("Audible:")
          .map(|n| (n.to_string(), v.clone()))
      })
      .collect()
  }

  #[test]
  fn duplicate_static_dict_tag_emits_last_value() {
    let bytes = build_aa_with_dict(&[("author", "FIRST"), ("author", "SECOND")]);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj.get("Audible:Author").and_then(|v| v.as_str()),
      Some("SECOND")
    );
  }

  #[test]
  fn duplicate_dynamic_dict_tag_emits_last_value() {
    let bytes = build_aa_with_dict(&[("title", "FIRST"), ("title", "SECOND")]);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj.get("Audible:Title").and_then(|v| v.as_str()),
      Some("SECOND")
    );
  }

  #[test]
  fn duplicate_dict_tag_preserves_first_position() {
    let bytes = build_aa_with_dict(&[("author", "A"), ("title", "T"), ("author", "B")]);
    let entries = audible_entries(&bytes);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, "Author");
    assert_eq!(entries[0].1, TagValue::Str("B".into()));
    assert_eq!(entries[1].0, "Title");
    assert_eq!(entries[1].1, TagValue::Str("T".into()));
  }

  fn build_aa_with_two_chap_chunks(c1: u32, c2: u32) -> Vec<u8> {
    let count1 = c1.to_be_bytes();
    let count2 = c2.to_be_bytes();
    let toc_count = 2u32;
    let offset1 = 16 + 12 * toc_count;
    let offset2 = offset1 + count1.len() as u32;
    let mut toc = Vec::with_capacity(24);
    toc.extend_from_slice(&6u32.to_be_bytes());
    toc.extend_from_slice(&offset1.to_be_bytes());
    toc.extend_from_slice(&(count1.len() as u32).to_be_bytes());
    toc.extend_from_slice(&6u32.to_be_bytes());
    toc.extend_from_slice(&offset2.to_be_bytes());
    toc.extend_from_slice(&(count2.len() as u32).to_be_bytes());
    let total = 16 + toc.len() + count1.len() + count2.len();
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&(total as u32).to_be_bytes());
    header.extend_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    header.extend_from_slice(&toc_count.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0]);
    let mut out = Vec::with_capacity(total);
    out.extend(header);
    out.extend(toc);
    out.extend_from_slice(&count1);
    out.extend_from_slice(&count2);
    out
  }

  #[test]
  fn duplicate_chapter_count_chunks_emit_last_value() {
    let bytes = build_aa_with_two_chap_chunks(1, 2);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj.get("Audible:ChapterCount").and_then(|v| v.as_i64()),
      Some(2)
    );
  }

  #[test]
  fn dict_cover_art_uses_binary_placeholder() {
    // Raw bytes preserved via the typed parse + TagMap.
    let bytes = build_aa_with_dict(&[("_cover_art", "ABCDE")]);
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    let mut tm = TagMap::new();
    meta.serialize_tags(true, &mut tm).unwrap();
    match tm.get("Audible", "CoverArt").expect("CoverArt") {
      TagValue::Bytes(b) => assert_eq!(b.as_slice(), b"ABCDE"),
      other => panic!("expected Bytes, got {other:?}"),
    }
  }

  #[test]
  fn reserved_special_dict_tags_are_dropped() {
    let bytes = build_aa_with_dict(&[("GROUPS", "g_val"), ("FORMAT", "f_val"), ("title", "T")]);
    let entries = audible_entries(&bytes);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "Title");
    assert_eq!(entries[0].1, TagValue::Str("T".into()));
  }

  #[test]
  fn dynamic_name_colliding_with_engine_filetype_is_first_wins() {
    // `file_type` mangles to Audible:FileType=FIRST; `FileType` (dynamic) →
    // also Audible:FileType, first-wins ⇒ FIRST. The File:FileType=AA
    // orchestration tag is separate (different group key).
    let bytes = build_aa_with_dict(&[("file_type", "FIRST"), ("FileType", "SECOND")]);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj.get("Audible:FileType").and_then(|v| v.as_str()),
      Some("FIRST")
    );
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AA")
    );
  }

  #[test]
  fn dynamic_name_colliding_with_engine_filetypeextension_is_last_wins() {
    let bytes = build_aa_with_dict(&[
      ("file_type_extension", "FIRST"),
      ("FileTypeExtension", "SECOND"),
    ]);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj
        .get("Audible:FileTypeExtension")
        .and_then(|v| v.as_str()),
      Some("SECOND")
    );
  }

  #[test]
  fn dynamic_name_colliding_with_engine_exiftoolversion_is_last_wins() {
    let bytes = build_aa_with_dict(&[
      ("exif_tool_version", "FIRST"),
      ("ExifToolVersion", "SECOND"),
    ]);
    let obj = engine_obj(&bytes);
    assert_eq!(
      obj.get("Audible:ExifToolVersion").and_then(|v| v.as_str()),
      Some("SECOND")
    );
  }

  #[test]
  fn dict_value_with_fatal_numeric_entity_emits_exiftool_error() {
    let bytes = build_aa_with_dict(&[("title", "X&#x8000000000000000;Y")]);
    let obj = engine_obj(&bytes);
    assert!(!obj.keys().any(|k| k.starts_with("Audible:")));
    assert!(
      obj
        .get("ExifTool:Error")
        .and_then(|v| v.as_str())
        .is_some_and(|e| e.contains("Use of code point"))
    );
  }

  #[test]
  fn dict_value_with_fatal_decimal_entity_emits_exiftool_error() {
    let bytes = build_aa_with_dict(&[("title", "X&#9223372036854775808;Y")]);
    let obj = engine_obj(&bytes);
    assert!(
      obj
        .get("ExifTool:Error")
        .and_then(|v| v.as_str())
        .is_some_and(|e| e.contains("Use of code point"))
    );
  }

  #[test]
  fn dict_value_with_fatal_entity_stops_dict_walk() {
    let bytes = build_aa_with_dict(&[
      ("author", "A"),
      ("title", "Y&#x8000000000000000;Z"),
      ("narrator", "should-not-appear"),
    ]);
    let entries = audible_entries(&bytes);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["Author"]);
    // The fatal entity surfaces as ExifTool:Error in the engine document.
    let obj = engine_obj(&bytes);
    assert!(obj.get("ExifTool:Error").and_then(|v| v.as_str()).is_some());
  }

  fn build_aa_dict_then_chap(dict_entries: &[(&str, &str)], chapter_count: u32) -> Vec<u8> {
    let mut dict = Vec::new();
    dict.extend_from_slice(&(dict_entries.len() as u32).to_be_bytes());
    for (tag, val) in dict_entries {
      dict.push(0x06);
      dict.extend_from_slice(&(tag.len() as u32).to_be_bytes());
      dict.extend_from_slice(&(val.len() as u32).to_be_bytes());
      dict.extend_from_slice(tag.as_bytes());
      dict.extend_from_slice(val.as_bytes());
    }
    let dict_len = dict.len();
    let cc_bytes = chapter_count.to_be_bytes();
    let cc_len = cc_bytes.len();
    let toc_count = 2u32;
    let offset1 = 16 + 12 * toc_count;
    let offset2 = offset1 + dict_len as u32;
    let mut toc = Vec::with_capacity(24);
    toc.extend_from_slice(&2u32.to_be_bytes());
    toc.extend_from_slice(&offset1.to_be_bytes());
    toc.extend_from_slice(&(dict_len as u32).to_be_bytes());
    toc.extend_from_slice(&6u32.to_be_bytes());
    toc.extend_from_slice(&offset2.to_be_bytes());
    toc.extend_from_slice(&(cc_len as u32).to_be_bytes());
    let total = 16 + toc.len() + dict.len() + cc_len;
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&(total as u32).to_be_bytes());
    header.extend_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    header.extend_from_slice(&toc_count.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0]);
    let mut out = Vec::with_capacity(total);
    out.extend(header);
    out.extend(toc);
    out.extend(dict);
    out.extend_from_slice(&cc_bytes);
    out
  }

  #[test]
  fn dict_fatal_entity_stops_later_toc_chunks() {
    let bytes = build_aa_dict_then_chap(&[("title", "X&#x8000000000000000;Y")], 7);
    let obj = engine_obj(&bytes);
    assert!(!obj.keys().any(|k| k.starts_with("Audible:")));
    assert!(
      obj
        .get("ExifTool:Error")
        .and_then(|v| v.as_str())
        .is_some_and(|e| e.contains("Use of code point"))
    );
  }

  // ----- Lib-first typed Meta surface -----

  #[test]
  fn parse_borrowed_returns_typed_meta() {
    let bytes = build_aa_with_dict(&[("author", "Alice"), ("title", "Book")]);
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    let names: Vec<&str> = meta.entries().iter().map(|e| e.name()).collect();
    assert_eq!(names, vec!["Author", "Title"]);
    match meta.entries()[0].value_ref() {
      AaValue::Str(s) => assert_eq!(s.as_str(), "Alice"),
      other => panic!("expected Str, got {other:?}"),
    }
  }

  #[test]
  fn parse_borrowed_returns_chapter_count_accessor() {
    let bytes = build_aa_with_two_chap_chunks(1, 42);
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    assert_eq!(meta.chapter_count(), Some(42));
  }

  #[test]
  fn aa_value_predicates_and_unwrap_accessors() {
    let s = AaValue::Str(SmolStr::from("hi"));
    assert!(s.is_str() && !s.is_i64() && !s.is_bytes());
    assert_eq!(s.try_unwrap_str(), Some("hi"));
    assert_eq!(s.try_unwrap_i64(), None);
    assert_eq!(s.try_unwrap_bytes(), None);

    let n = AaValue::I64(7);
    assert!(n.is_i64() && !n.is_str() && !n.is_bytes());
    assert_eq!(n.try_unwrap_i64(), Some(7));
    assert_eq!(n.try_unwrap_str(), None);

    let b = AaValue::Bytes(std::borrow::Cow::Borrowed(&[1u8, 2, 3]));
    assert!(b.is_bytes() && !b.is_str() && !b.is_i64());
    assert_eq!(b.try_unwrap_bytes(), Some(&[1u8, 2, 3][..]));
    assert_eq!(b.try_unwrap_i64(), None);
  }

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(&[0u8; 8]).unwrap().is_none());
  }

  #[test]
  fn format_parser_trait_returns_meta_static() {
    let bytes = build_aa_with_dict(&[("author", "Alice")]);
    let meta = <ProcessAa as FormatParser>::parse(&ProcessAa, &bytes)
      .expect("ok")
      .expect("parsed");
    assert_eq!(meta.entries().len(), 1);
    assert_eq!(meta.entries()[0].name(), "Author");
  }

  #[test]
  fn meta_sinker_emits_typed_tags() {
    use crate::tagmap::TagMap;
    let bytes = build_aa_with_dict(&[("author", "Alice"), ("title", "Book")]);
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("Audible", "Author"), Some("Alice".to_string()));
    assert_eq!(w.get_str("Audible", "Title"), Some("Book".to_string()));
  }

  #[test]
  fn meta_sinker_emits_chapter_count_as_i64() {
    use crate::tagmap::TagMap;
    let bytes = build_aa_with_two_chap_chunks(1, 7);
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("Audible", "ChapterCount"), Some("7".to_string()));
  }

  #[test]
  fn meta_sinker_emits_warnings() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&[0, 0, 0, 16]);
    data[4..8].copy_from_slice(&[0x57, 0x90, 0x75, 0x36]);
    data[8..12].copy_from_slice(&[0, 0, 0x01, 0x01]); // 257
    // The warning reaches the engine document as ExifTool:Warning.
    let obj = engine_obj(&data);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Invalid TOC")
    );

    // Also verify the typed path: parse_borrowed produces the same warning.
    let meta = parse_borrowed(&data).expect("ok").expect("parsed");
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert!(w.warnings().iter().any(|s| s == "Invalid TOC"));
  }
}
