// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The JUMBF box-type dispatch table + the `%Jpeg2000::JUMD` description-box tag
//! definitions + the JUMBFLabel sanitizer (`Jpeg2000.pm` 13.59).
//!
//! These are the read-only data the [`super`] box-tree walker consults: which
//! `%Jpeg2000::Main` arm a 4-char box id selects (`Jpeg2000.pm:397-446`) and how
//! a JUMD label is normalized into a tag-name prefix (`Jpeg2000.pm:824-831`).

/// One JUMBF box's dispatch kind — the subset of `%Jpeg2000::Main`
/// (`Jpeg2000.pm:397-446`) a Phase-1 JUMBF box stream can select. A `Copy`
/// token returned by value from [`lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoxKind {
  /// `jumb` (`Jpeg2000.pm:402`) — the JUMBF SUPERBOX, `ProcessProc =>
  /// ProcessJUMB`: opens a new sub-document level then recurses
  /// ([`super::JumbfWalker::process_jumb`]).
  Jumb,
  /// `jumd` (`Jpeg2000.pm:398`) — the JUMBF DESCRIPTION box, `ProcessJUMD`:
  /// the type-UUID + toggles + optional label/ID/signature
  /// ([`super::JumbfWalker::process_jumd`]).
  Jumd,
  /// `asoc` (`Jpeg2000.pm:231`) — a generic Association CONTAINER box that may
  /// hold any other sub-box; recurse structurally with no own value.
  Asoc,
  /// `bfdb` (`Jpeg2000.pm:425`) — `BinaryDataType`: the MIME type (+ optional
  /// file name) of the following `bidb`. A FORMAT (value) box, group
  /// `Jpeg2000`, `JUMBF_Suffix => 'Type'`.
  Bfdb,
  /// `bidb` (`Jpeg2000.pm:433`) — `BinaryData`: the embedded binary payload
  /// (a preview image). `Binary => 1`, `Groups => { 2 => 'Preview' }`,
  /// `JUMBF_Suffix => 'Data'` — emitted as the byte-count placeholder.
  Bidb,
  /// `c2sh` (`Jpeg2000.pm:441`) — `C2PASaltHash`: a hex salt. A FORMAT box,
  /// group `Jpeg2000`, `JUMBF_Suffix => 'Salt'`.
  C2sh,
  /// `json` (`Jpeg2000.pm:409`) — `JSONData`: a JSON content box decoded by
  /// `JSON::Main` / `ProcessJSON` ([`super::json`], Phase 2 #142) into flattened
  /// `JSON:*` tags.
  Json,
  /// `cbor` (`Jpeg2000.pm:420`) — `CBORData`: a CBOR content box whose decoder
  /// (`CBOR::Main`) is DEFERRED to Phase 3. Recursed-but-opaque: the box is
  /// traversed (its bounds validated) but emits no tags yet.
  Cbor,
}

/// Resolve a 4-byte JUMBF box id to its [`BoxKind`] (the `$$tagTablePtr{$boxID}`
/// lookup, `Jpeg2000.pm:1142`). `None` for a box this Phase-1 subset does not
/// recognize — the walker SKIPS it (advances past its length), faithful to
/// ExifTool's "no tagInfo and not verbose ⇒ next" (`Jpeg2000.pm:1143-1159`).
pub(crate) const fn lookup(box_id: &[u8; 4]) -> Option<BoxKind> {
  match box_id {
    b"jumb" => Some(BoxKind::Jumb),
    b"jumd" => Some(BoxKind::Jumd),
    b"asoc" => Some(BoxKind::Asoc),
    b"bfdb" => Some(BoxKind::Bfdb),
    b"bidb" => Some(BoxKind::Bidb),
    b"c2sh" => Some(BoxKind::C2sh),
    b"json" => Some(BoxKind::Json),
    b"cbor" => Some(BoxKind::Cbor),
    _ => None,
  }
}

/// Sanitize a raw JUMD label into the tag-name prefix bundled derives at
/// `Jpeg2000.pm:824-831` (the `JUMBFLabel` used to RENAME the following
/// `bfdb`/`bidb`/`c2sh` content tags, `Jpeg2000.pm:1205-1212`). The four
/// transforms, in order:
///
/// 1. `s/[^-_a-zA-Z0-9]([a-z])/\U$1/g` — capitalize a lowercase letter that
///    FOLLOWS an illegal character (drops the illegal char in the same pass,
///    since the whole 2-char match is replaced by the uppercased letter).
/// 2. `tr/-_a-zA-Z0-9//dc` — delete every remaining illegal character (anything
///    not `[-_a-zA-Z0-9]`).
/// 3. `s/__/_/` — collapse the FIRST `__` to a single `_` (Perl `s///` with no
///    `/g` replaces only the first occurrence).
/// 4. `ucfirst` — capitalize the first letter.
/// 5. `s/C2pa/C2PA/` — fix the `C2PA` acronym (first occurrence).
/// 6. `"Tag$name" if length < 2` — a sub-2-char result is prefixed `Tag`.
///
/// Returns `None` for an EMPTY input (`$len` is 0 ⇒ the `if ($len)` guard at
/// `Jpeg2000.pm:824` is false, so `$$et{JUMBFLabel}` is left unset and no
/// rename happens).
#[cfg(feature = "alloc")]
pub(crate) fn sanitize_label(raw: &str) -> Option<std::string::String> {
  use std::string::String;
  if raw.is_empty() {
    return None;
  }
  // Step 1: capitalize a lowercase letter after an illegal char, dropping the
  // illegal char. Walk byte-wise tracking whether the PREVIOUS retained char
  // would have been "illegal" in the Perl regex sense. The Perl regex consumes
  // the illegal char + the lowercase letter together, so an illegal char NOT
  // followed by a lowercase letter is left in place (to be deleted by step 2).
  let bytes = raw.as_bytes();
  let mut s1 = String::with_capacity(raw.len());
  let mut i = 0;
  while let Some(&c) = bytes.get(i) {
    if !is_label_legal(c) {
      // An illegal char: if the NEXT byte is an ASCII lowercase letter, the
      // regex replaces both with the uppercased letter (the illegal char is
      // consumed, the letter uppercased). Otherwise the illegal char passes
      // through here (step 2 will delete it).
      if let Some(&n) = bytes.get(i + 1)
        && n.is_ascii_lowercase()
      {
        s1.push((n - b'a' + b'A') as char);
        i += 2;
        continue;
      }
      s1.push(c as char);
      i += 1;
    } else {
      s1.push(c as char);
      i += 1;
    }
  }
  // Step 2: delete every remaining illegal character.
  let mut s2: String = s1.chars().filter(|&c| is_label_legal(c as u8)).collect();
  // Step 3: collapse the FIRST `__` (not global).
  if let Some(pos) = s2.find("__") {
    s2.replace_range(pos..pos + 2, "_");
  }
  // Step 4: ucfirst.
  let mut s3 = ucfirst(&s2);
  // Step 5: `C2pa` -> `C2PA` (first occurrence).
  if let Some(pos) = s3.find("C2pa") {
    s3.replace_range(pos..pos + 4, "C2PA");
  }
  // Step 6: prefix `Tag` if shorter than 2 characters.
  if s3.chars().count() < 2 {
    let mut prefixed = String::with_capacity(3 + s3.len());
    prefixed.push_str("Tag");
    prefixed.push_str(&s3);
    s3 = prefixed;
  }
  Some(s3)
}

/// `[-_a-zA-Z0-9]` — the JUMD-label "legal" character class (`Jpeg2000.pm:826`
/// `tr/-_a-zA-Z0-9//dc`).
const fn is_label_legal(c: u8) -> bool {
  c == b'-' || c == b'_' || c.is_ascii_alphanumeric()
}

/// Perl `ucfirst`: uppercase the first character, leave the rest. ASCII-only is
/// sufficient (step 2 already removed every non-`[-_a-zA-Z0-9]` byte, so the
/// first char is ASCII).
#[cfg(feature = "alloc")]
fn ucfirst(s: &str) -> std::string::String {
  let mut out = std::string::String::with_capacity(s.len());
  let mut chars = s.chars();
  if let Some(first) = chars.next() {
    out.extend(first.to_uppercase());
    out.push_str(chars.as_str());
  }
  out
}

/// The `JUMBF_Suffix` appended to a [`super::JumbfWalker`]-derived JUMBFLabel
/// when it renames a content tag (`Jpeg2000.pm:431`/`:439`/`:445`). Returned by
/// value (a `&'static str`) so the renamer can join `label + suffix`.
pub(crate) const fn jumbf_suffix(kind: BoxKind) -> Option<&'static str> {
  match kind {
    BoxKind::Bfdb => Some("Type"),
    BoxKind::Bidb => Some("Data"),
    BoxKind::C2sh => Some("Salt"),
    _ => None,
  }
}

/// Build the final RENAMED content-tag name from a (stage-1) JUMBFLabel and a
/// box's [`jumbf_suffix`] — `Name => $$et{JUMBFLabel} . $$tagInfo{JUMBF_Suffix}`
/// (`Jpeg2000.pm:1207`) — then apply `AddTagToTable`'s name-legalization
/// (`ExifTool.pm:6488`): `"Tag$name" if length($name) < 2 or $name !~ /^[A-Z]/i`
/// — prefix `Tag` when the joined name is under 2 chars OR does not START with an
/// ASCII letter (so a label like `_x` → `Tag_xType`; `c2pa.test` → `C2PATest` →
/// `C2PATestType`, kept). Stage-1 (`sanitize_label`) is the `Jpeg2000.pm:824-831`
/// pass; THIS is the second, independent legalization on the joined name.
#[cfg(feature = "alloc")]
pub(crate) fn make_renamed_tag_name(label: &str, suffix: &str) -> std::string::String {
  use std::string::String;
  let mut name = String::with_capacity(label.len() + suffix.len());
  name.push_str(label);
  name.push_str(suffix);
  let starts_with_letter = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
  if name.chars().count() < 2 || !starts_with_letter {
    let mut prefixed = String::with_capacity(3 + name.len());
    prefixed.push_str("Tag");
    prefixed.push_str(&name);
    return prefixed;
  }
  name
}
