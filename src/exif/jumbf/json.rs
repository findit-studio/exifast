// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::JSON` — the JUMBF `json` content-box decoder (the READ
//! subset of `JSON::Main` / `ProcessJSON` + `Import::ReadJSONObject`,
//! `JSON.pm` 1.11 + `Import.pm` 1.15, bundled 13.59). **Phase 2 of #142.**
//!
//! ## Where it enters
//!
//! A JUMBF `json` content box (`Jpeg2000.pm:409-418`: `json` → a `JSONData`
//! tagInfo with `Flags => ['Binary','Protected','BlockExtract']` +
//! `SubDirectory => { TagTable => 'Image::ExifTool::JSON::Main' }`) carries a
//! JSON document. Phase-1's [`super::JumbfWalker`] recognized the box but
//! emitted no tags; this module is the deferred decoder. The box's payload is
//! a JSON document; [`decode`] parses it and yields the FLATTENED `JSON:<key>`
//! tags (`JSON.pm`'s `ProcessJSON` → `ProcessTag` → `FoundTag`).
//!
//! ## Part A — the parser ([`Parser`], `Import.pm:138 ReadJSONObject`)
//!
//! ExifTool reads JSON with a small hand-written recursive descent
//! (`Import::ReadJSONObject`): it skips whitespace to the next non-`\S`
//! character and dispatches on it — `{` an object, `[` an array, `"` a quoted
//! string (with `\uHHHH` + `\t\n\r\b\f` un-escaping, `Import.pm:223-225`),
//! else a bare token (a number / `true` / `false` / `null`) scanned up to the
//! next `[\s:,\}\]]` delimiter (`Import.pm:235-238`). A number/literal is kept
//! as its RAW lexeme STRING — never coerced to a numeric type — and the
//! string-vs-number-vs-boolean decision is deferred to the OUTPUT gate
//! (`EscapeJSON`, `XMPStruct.pl:166`), exactly as ExifTool does. This port
//! mirrors that: every scalar is captured as its source text and rendered
//! through exifast's [`escape_json_is_number`](crate::value::escape_json_is_number)
//! gate at emit time (a [`TagValue::Str`] in-gate token emits BARE, an
//! out-of-gate token QUOTED; a `true`/`false` literal becomes a bare
//! [`TagValue::Bool`]). A JSON `null` becomes the literal STRING `"null"` —
//! ExifTool's default `MissingTagValue` (`JSON.pm:6`), which the number/boolean
//! gate then quotes.
//!
//! ## Part B — the flattening ([`flatten_object`], `JSON.pm:89-112 ProcessTag`)
//!
//! Under the exifast golden's `-struct` regime (`tools/gen_golden.sh` COMMON
//! flags carry `-struct`, so `Options('Struct')` is 1), `ProcessTag` on a HASH
//! calls `FoundTag(..., Struct => 1)` to emit the WHOLE object as ONE
//! struct-valued tag, then `return unless Struct > 1` (`JSON.pm:96-98`) — so
//! with `Struct == 1` it does NOT also flatten. Net effect: each TOP-LEVEL key
//! of the document becomes one `JSON:<key>` tag whose value is the object
//! (a nested JSON object), an array (a JSON array), or a scalar — with the
//! nested structure preserved VERBATIM (inner keys are NOT legalized, only the
//! top-level tag NAME is, oracle-verified vs bundled 13.59). An EMPTY top-level
//! array emits NO tag (`ProcessTag` iterates `@$val` = nothing, `JSON.pm:105-108`).
//!
//! The top-level tag NAME is derived by `FoundTag` (`JSON.pm:67-71`) +
//! `AddTagToTable` (`ExifTool.pm:9266`): `tr/:/_/` (colons → underscores),
//! `s/^c2pa/C2PA/i` (the C2PA-case hack), `MakeTagName` (delete illegal chars,
//! `ucfirst`, prefix `Tag` if < 2 chars or starts with `-`/digit), then
//! `AddTagToTable`'s prefix (`Tag` if < 2 chars or not starting with an ASCII
//! letter). See [`legalize_top_key`].
//!
//! ## Part C — group + axis
//!
//! `JSON::Main`'s `GROUPS => { 0 => 'JSON', 1 => 'JSON' }` (`JSON.pm:23`) — the
//! tags emit under family-0/1 group `JSON`. The `json` box rides the same
//! `Doc<N>` sub-document axis as the JUMD tags ([`super::JumbfWalker`] supplies
//! the box's `(doc, doc_subpath)`); a `-G3` render is `Doc<N>:JSON:<key>`.
//!
//! The JUMBFLabel rename (`Jpeg2000.pm:1205-1212`) does NOT change the emitted
//! `JSON:*` tag names: the rename condition `(not SubDirectory or BlockExtract)`
//! IS true for `json` (it has `BlockExtract`), so a renamed `JSONData` tagInfo
//! is created — but that only affects the BLOCK-EXTRACT tag name (the `-b`
//! whole-document path), NOT the `JSON::Main` SubDirectory's own flattened
//! tags, which keep group `JSON` (oracle-verified vs bundled 13.59).
//!
//! ## Robustness (beyond-faithful, the Phase-1 [`super::MAX_BOX_DEPTH`] pattern)
//!
//! * a **depth budget** ([`MAX_JSON_DEPTH`]) bounds object/array nesting so a
//!   crafted deeply-nested document cannot overflow the recursive-descent
//!   stack. `ReadJSONObject` recurses with no depth guard; real C2PA JSON is a
//!   handful of levels.
//! * **per-byte bounds** — every read is a checked `.get()` (the `exif`
//!   module's `#![deny(clippy::indexing_slicing)]` panic-safety contract), so a
//!   truncated or malformed document never reads out of range. A parse that
//!   fails or yields a non-object/array surfaces the bundled
//!   `Unrecognized <Name> box` warning (`Jpeg2000.pm:1332`) the JUMBF walker
//!   raises when `ProcessJSON` returns 0 — NOT a panic.

use crate::value::TagValue;
use smol_str::SmolStr;
use std::{string::String, vec::Vec};

/// Beyond-faithful recursion cap on JSON object/array nesting (the Phase-1
/// [`super::MAX_BOX_DEPTH`] pattern). `Import::ReadJSONObject` recurses with no
/// depth guard (`Import.pm:185`/`:193`/`:208`); a crafted document nesting
/// `{"a":{"a":{"a":…}}}` thousands deep would blow the stack. Real C2PA JSON is
/// a handful of levels, so this bound is far above any genuine document. A
/// container deeper than this is treated as a parse error at that point (the
/// whole document then fails to a non-object ⇒ the `Unrecognized box` warning).
const MAX_JSON_DEPTH: usize = 64;

/// Expose [`MAX_JSON_DEPTH`] to the sibling unit tests (the depth-budget
/// termination test builds a document just past the cap).
#[cfg(test)]
pub(super) fn tests_max_depth() -> usize {
  MAX_JSON_DEPTH
}

/// The outcome of decoding a `json` content box.
///
/// `JSON::Main`'s `ProcessJSON` either succeeds (emitting flattened `JSON:*`
/// tags) or returns 0 — the latter raised by the JUMBF walker as the bundled
/// `Unrecognized <Name> box` warning (`Jpeg2000.pm:1330-1332`). This mirrors
/// that boundary: [`super::JumbfWalker`] turns [`Self::Tags`] into emitted tags
/// and [`Self::Unrecognized`] into the warning.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JsonOutcome {
  /// The document parsed to an object (or an array of objects); these are the
  /// flattened top-level `(legalized-name, value)` tags in document-key order.
  /// An EMPTY object yields an empty list (no tags) — but is still a SUCCESS,
  /// so no warning is raised (`ReadJSON` accepts an empty hash).
  Tags(Vec<(SmolStr, TagValue)>),
  /// The document did not parse to a hash / array-of-hashes (a bare scalar, a
  /// syntax error, or an empty document) — `ProcessJSON` returns 0, so the
  /// JUMBF walker raises `Unrecognized <Name> box` (`Jpeg2000.pm:1332`).
  Unrecognized,
}

/// Decode a JUMBF `json` content box payload into a [`JsonOutcome`]
/// (`ProcessJSON` over the box's data, `JSON.pm:118-170`). The top-level
/// document is parsed (`Import::ReadJSONObject`), then run through the
/// `Import::ReadJSON` database step (`Import.pm:273-304`) and the `ProcessJSON`
/// flatten loop (`JSON.pm:161-168`):
///
/// * a top-level OBJECT is wrapped as a one-element array (`$obj = [ $obj ]`,
///   `Import.pm:283`);
/// * each array element that is a HASH is keyed by its `SourceFile`
///   (`Import.pm:286-303`): an explicit `SourceFile` value, else a
///   case-insensitive `sourcefile`-like key RENAMED to `SourceFile` (its
///   original key removed from the ordered set), else the literal `'*'`. A
///   later object with the SAME `SourceFile` key OVERWRITES the earlier one;
/// * the surviving objects are visited in `sort`ed `SourceFile`-key order, and
///   each object's ordered keys are flattened to `JSON:<key>` tags, SKIPPING a
///   `SourceFile` tag whose value is the auto-default `'*'` (`JSON.pm:165`).
///
/// A non-HASH element is skipped (`next unless ref $info eq 'HASH'`); an array
/// with NO surviving object — and any non-object/array top level (a scalar, a
/// parse failure) — is [`JsonOutcome::Unrecognized`] (`ReadJSON` returns an
/// error ⇒ `ProcessJSON` returns 0). Oracle-verified vs bundled 13.59.
pub(crate) fn decode(data: &[u8]) -> JsonOutcome {
  let mut parser = Parser { data, pos: 0 };
  // Skip a leading UTF-8 BOM (`Import.pm:167` `s/^\xef\xbb\xbf//`).
  if data.get(0..3) == Some(&[0xEF, 0xBB, 0xBF]) {
    parser.pos = 3;
  }
  let Some(top) = parser.parse_value(0) else {
    return JsonOutcome::Unrecognized;
  };
  // `ReadJSON` requires the top level to be an ARRAY or a HASH; a single HASH is
  // wrapped as `[ $hash ]` (`Import.pm:275-284`). A bare scalar ⇒ "Format
  // error" ⇒ `ProcessJSON` returns 0.
  let objects = match top {
    JsonNode::Object(pairs) => std::vec![pairs],
    // Keep only the HASH elements (`next unless ref $info eq 'HASH'`,
    // `Import.pm:287`); a scalar/array element is dropped.
    JsonNode::Array(items) => items
      .into_iter()
      .filter_map(|item| match item {
        JsonNode::Object(pairs) => Some(pairs),
        _ => None,
      })
      .collect(),
    JsonNode::Scalar(_) => return JsonOutcome::Unrecognized,
  };
  match read_json_database(objects) {
    Some(tags) => JsonOutcome::Tags(tags),
    // No surviving HASH ⇒ `$found` stays false ⇒ `ReadJSON` returns an error ⇒
    // `ProcessJSON` returns 0 (`Import.pm:287`/`:304`).
    None => JsonOutcome::Unrecognized,
  }
}

/// Model the `Import::ReadJSON` database step (`Import.pm:285-303`) and the
/// `ProcessJSON` extraction loop (`JSON.pm:161-168`) over the already-parsed
/// HASH elements.
///
/// `ReadJSON` keys every object by its `SourceFile` into `%database`: a later
/// object with the same key OVERWRITES the earlier (`$$database{$sf} = $info`),
/// so distinct keys survive independently while a repeated key keeps the LAST.
/// `SourceFile` resolution per object (`Import.pm:289-297`): an EXISTING exact
/// `SourceFile` key is used as-is; otherwise a case-insensitive `sourcefile`
/// key is renamed to `SourceFile` (and its ORIGINAL key removed from the
/// object, so it no longer flattens); otherwise the key defaults to `'*'`.
///
/// The database key is the RAW `SourceFile` scalar bytes — the value
/// `ReadJSONObject` returns (un-escaped + base64-decoded, PRE-`FixUTF8`,
/// `Import.pm:301`). Keying on the raw bytes (not the `FixUTF8` output) is what
/// keeps two distinct values that share a `FixUTF8` rendering — e.g. the
/// base64-decoded `FE FD` vs the literal `??` — as DISTINCT keys, so neither
/// object is lost. The sorted iteration + the same-key overwrite are likewise
/// on the raw bytes.
///
/// `ProcessJSON` then iterates `sort keys %database` and, for each object,
/// flattens its ordered keys ([`flatten_object`]) — SKIPPING a `SourceFile` tag
/// whose value equals the auto-default `'*'` (`JSON.pm:165`). Returns `None`
/// when no object survives (`$found` false).
fn read_json_database(objects: Vec<Vec<(SmolStr, JsonNode)>>) -> Option<Vec<(SmolStr, TagValue)>> {
  // The SourceFile-keyed database in first-insertion order, with an O(1) index
  // for the same-key overwrite. The key is the RAW SourceFile bytes (pre-FixUTF8);
  // iteration is by SORTED raw key, so insertion order only governs which entry a
  // duplicate key replaces in place.
  let mut keys: Vec<Vec<u8>> = Vec::new();
  let mut by_source: Vec<Vec<(SmolStr, JsonNode)>> = Vec::new();
  for object in objects {
    let (source, resolved) = resolve_source_file(object);
    match keys.iter().position(|k| *k == source) {
      // Same SourceFile: a later object OVERWRITES the earlier in place,
      // keeping the original key position (`$$database{$sf} = $info`).
      Some(idx) => {
        if let Some(slot) = by_source.get_mut(idx) {
          *slot = resolved;
        }
      }
      None => {
        keys.push(source);
        by_source.push(resolved);
      }
    }
  }
  if keys.is_empty() {
    return None;
  }
  // `sort keys %database` — visit the surviving objects in sorted SourceFile
  // order (`JSON.pm:161`). Sort an index permutation so the paired object Vec
  // follows its key without cloning the (heavy) object payloads.
  let mut order: Vec<usize> = (0..keys.len()).collect();
  order.sort_by(|&a, &b| keys.get(a).cmp(&keys.get(b)));
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for idx in order {
    if let Some(object) = by_source.get_mut(idx) {
      flatten_object(std::mem::take(object), &mut out);
    }
  }
  Some(out)
}

/// Resolve an object's `SourceFile` database key and return the object with its
/// ordered keys adjusted for the rename (`Import.pm:289-297`):
///
/// * an EXACT `SourceFile` key already present ⇒ that value is the key, the
///   object is unchanged (the `SourceFile` pair stays and flattens, unless its
///   value is `'*'`);
/// * else a case-insensitive `sourcefile`-like key ⇒ its value becomes the
///   `SourceFile` key, and that ORIGINAL key is REMOVED from the object (so it
///   no longer flattens — bundled deletes it, `Import.pm:293`, and the renamed
///   `SourceFile` is NOT re-added to the ordered keys, so it never flattens);
/// * else no SourceFile key ⇒ default `'*'`, the object unchanged.
///
/// The returned database key is the RAW `SourceFile` scalar bytes (pre-`FixUTF8`,
/// the value `ReadJSONObject` returns), so distinct raw values never collide. A
/// non-string `SourceFile`/`sourcefile` value (invalid JSON for this field) is
/// treated as absent — its `node` is not a scalar string, so it can't be a hash
/// key; this mirrors that the rename uses the scalar value directly.
fn resolve_source_file(
  mut object: Vec<(SmolStr, JsonNode)>,
) -> (Vec<u8>, Vec<(SmolStr, JsonNode)>) {
  // An EXACT `SourceFile` key (`defined $$info{SourceFile}`). The key is the RAW
  // scalar bytes (base64-decoded, PRE-`FixUTF8`).
  if let Some((_, node)) = object.iter().find(|(k, _)| k == "SourceFile")
    && let Some(value) = scalar_key_bytes(node)
  {
    return (value, object);
  }
  // A case-insensitive `sourcefile`-like key (`grep /^SourceFile$/i`). Bundled
  // takes the FIRST such key, copies its value to `SourceFile`, and DELETEs the
  // original key. The renamed key is not pushed onto `_ordered_keys_`, so it
  // does not flatten.
  if let Some(pos) = object
    .iter()
    .position(|(k, _)| k.eq_ignore_ascii_case("SourceFile"))
    && let Some((_, node)) = object.get(pos)
    && let Some(value) = scalar_key_bytes(node)
  {
    object.remove(pos);
    return (value, object);
  }
  // No SourceFile ⇒ the auto-default `'*'` (its raw ASCII bytes).
  (b"*".to_vec(), object)
}

/// The RAW bytes of a [`JsonNode::Scalar`] that is a string — the `SourceFile`
/// database key (`Import.pm:301`, the value `ReadJSONObject` returns, PRE-`FixUTF8`).
/// `None` for any other node shape (a boolean / object / array `SourceFile` is
/// not a hash-key string).
fn scalar_key_bytes(node: &JsonNode) -> Option<Vec<u8>> {
  match node {
    JsonNode::Scalar(scalar) => scalar.as_str_bytes().map(<[u8]>::to_vec),
    _ => None,
  }
}

/// A parsed JSON node — the in-memory shape `Import::ReadJSONObject` builds (a
/// Perl scalar / hash-with-ordered-keys / array). Object keys preserve
/// document order (the `_ordered_keys_` list, `Import.pm:181`/`:197`).
#[derive(Debug, Clone, PartialEq)]
enum JsonNode {
  /// A JSON object — ordered `(key, value)` pairs (document order).
  Object(Vec<(SmolStr, JsonNode)>),
  /// A JSON array — ordered elements.
  Array(Vec<JsonNode>),
  /// Any non-container value, carried as the RAW [`JsonScalar`] that
  /// `ReadJSONObject` returns (un-escaped + base64-decoded, but PRE-`FixUTF8`).
  /// The output-time `FixUTF8` + the final [`TagValue`] conversion happen only
  /// at [`flatten_object`] ([`scalar_to_value`]).
  Scalar(JsonScalar),
}

/// A parsed JSON scalar in its `Import::ReadJSONObject` form — the value EXACTLY
/// as `ReadJSONObject` returns it (`Import.pm:217-238`), which is the value
/// `ReadJSON` keys `%database` on (`Import.pm:301`) and the value
/// `ProcessJSON`/`FoundTag` later renders. Crucially this is the value BEFORE
/// `FixUTF8` — that repair is an OUTPUT concern (it is NOT in `JSON.pm` /
/// `Import.pm` at all; the generic ExifTool print path applies it), so it must
/// NOT be folded into the scalar. Folding it in early would corrupt the
/// `SourceFile` database key: two DISTINCT raw values whose `FixUTF8` outputs
/// happen to coincide (e.g. the base64-decoded bytes `FE FD` vs the literal
/// ASCII `??`, both `??` after `FixUTF8`) would collapse to one key and lose an
/// object (`Import.pm` keys `%database` on the RAW decoded scalar).
#[derive(Debug, Clone, PartialEq)]
enum JsonScalar {
  /// A quoted-string scalar's RAW bytes — after the `\uHHHH` + `\(.)` unescape
  /// passes AND the `base64:` decode (`Import.pm:224-229`), but BEFORE
  /// `FixUTF8`. Also carries a bare number / `null` lexeme (always ASCII, so
  /// `FixUTF8` is a no-op on it). These bytes are the `SourceFile` database key
  /// for equality + sorted iteration; at flatten they become a
  /// [`TagValue::Str`] via `FixUTF8`.
  Str(Vec<u8>),
  /// A bare `true`/`false` literal (`EscapeJSON`, `XMPStruct.pl:169-176`) — a
  /// [`TagValue::Bool`] at flatten. A QUOTED `"true"` is a [`Self::Str`], not
  /// this.
  Bool(bool),
}

impl JsonScalar {
  /// The raw bytes of a string scalar — the `SourceFile` database key
  /// (`Import.pm:301`, the raw decoded value). `None` for a boolean (a JSON
  /// `SourceFile` is a string; an object KEY is always a string).
  fn as_str_bytes(&self) -> Option<&[u8]> {
    match self {
      JsonScalar::Str(bytes) => Some(bytes),
      JsonScalar::Bool(_) => None,
    }
  }
}

/// Flatten one database object's ordered keys into `JSON:<legalized-key>` tags,
/// appending to `out` (the `ProcessJSON` per-object loop, `JSON.pm:162-167` →
/// `ProcessTag`, the `-struct` `Struct == 1` regime: ONE tag per top-level key,
/// the value kept as its nested structure, `JSON.pm:94-112`). The top-level key
/// is legalized ([`legalize_top_key`]); the value is converted to a
/// [`TagValue`] ([`node_to_value`]) preserving nested object/array structure
/// with RAW inner keys.
fn flatten_object(pairs: Vec<(SmolStr, JsonNode)>, out: &mut Vec<(SmolStr, TagValue)>) {
  out.reserve(pairs.len());
  for (key, node) in pairs {
    // Skip a `SourceFile` tag generated automatically by `ReadJSON` — the
    // default `'*'` value (`next if $tag eq 'SourceFile' and $val eq '*'`,
    // `JSON.pm:165`). An EXPLICIT `SourceFile` value (≠ `'*'`) is NOT skipped
    // (it flattens to `JSON:SourceFile`, oracle-verified vs bundled 13.59).
    if key == "SourceFile"
      && let JsonNode::Scalar(JsonScalar::Str(value)) = &node
      && value == b"*"
    {
      continue;
    }
    // An EMPTY top-level array emits no tag (`ProcessTag` iterates the empty
    // `@$val`, calling `FoundTag` zero times, `JSON.pm:105-108`). Every other
    // value — including an empty OBJECT (which `FoundTag(Struct=>1)` emits as
    // `{}`) — produces exactly one tag.
    if let JsonNode::Array(items) = &node
      && items.is_empty()
    {
      continue;
    }
    out.push((legalize_top_key(&key), node_to_value(node)));
  }
}

/// Convert a parsed [`JsonNode`] into its emitted [`TagValue`], preserving
/// nested structure (the `-struct` value: an object → [`TagValue::Map`] with
/// RAW inner keys, an array → [`TagValue::List`], a scalar → [`scalar_to_value`]).
/// Inner object keys are NOT legalized — they pass through as the struct's keys
/// verbatim (oracle-verified vs bundled 13.59). This is the FLATTEN stage where
/// the deferred `FixUTF8` + the final scalar→[`TagValue`] conversion happen
/// (a SURVIVING object's values only — a `SourceFile`-overwritten object never
/// reaches here, so its raw key never needed normalizing).
fn node_to_value(node: JsonNode) -> TagValue {
  match node {
    JsonNode::Object(pairs) => TagValue::Map(
      pairs
        .into_iter()
        .map(|(k, v)| (k, node_to_value(v)))
        .collect(),
    ),
    JsonNode::Array(items) => TagValue::List(items.into_iter().map(node_to_value).collect()),
    JsonNode::Scalar(scalar) => scalar_to_value(scalar),
  }
}

/// Convert a raw [`JsonScalar`] into its emitted [`TagValue`] at the FLATTEN
/// (output) stage — where the deferred `FixUTF8` is applied:
///
/// * [`JsonScalar::Str`] → [`TagValue::Str`] of the bytes repaired through
///   [`crate::convert::fix_utf8`] (`FixUTF8`, the ExifTool output stage): a
///   decoded text base64 renders directly (`Hi`), an invalid byte renders `?`
///   (`FE FD` → `??`), a `\uHHHH` surrogate's WTF-8 bytes render `?`, and an
///   ASCII number / `null` lexeme passes through unchanged (the
///   `escape_json_is_number` gate then renders an in-range number bare).
/// * [`JsonScalar::Bool`] → [`TagValue::Bool`].
fn scalar_to_value(scalar: JsonScalar) -> TagValue {
  match scalar {
    JsonScalar::Str(bytes) => TagValue::Str(SmolStr::from(crate::convert::fix_utf8(&bytes))),
    JsonScalar::Bool(b) => TagValue::Bool(b),
  }
}

/// Derive the emitted `JSON:<name>` tag name from a top-level JSON key
/// (`FoundTag`, `JSON.pm:67-71`, then `AddTagToTable`, `ExifTool.pm:9266`):
///
/// 1. `tr/:/_/` — colons become underscores (`JSON.pm:69`).
/// 2. `s/^c2pa/C2PA/i` — the C2PA-case hack (only at the START,
///    case-insensitive, `JSON.pm:70`).
/// 3. `MakeTagName` (`ExifTool.pm:6451-6459`): `tr/-_a-zA-Z0-9//dc` (delete
///    every char outside `[-_a-zA-Z0-9]`), `ucfirst`, then `"Tag$name"` if the
///    result is < 2 chars OR starts with `-`/`0`-`9`.
/// 4. `AddTagToTable`'s own legalization (`ExifTool.pm:9266`): `"Tag$name"` if
///    the result is < 2 chars OR does NOT start with an ASCII letter
///    (`/^[A-Z]/i`) — so a leading `_` (legal in step 3) still gets the
///    `Tag` prefix here (e.g. `_x` → `Tag_x`).
///
/// Shared with the sibling [`super::cbor`] decoder (`CBOR::Main`'s `ProcessCBOR`
/// flattens a top-level key through the SAME `JSON::ProcessTag` → `FoundTag`
/// path, `CBOR.pm:292`), so a CBOR key with no predefined tag is legalized
/// identically (oracle-verified vs bundled 13.59).
pub(super) fn legalize_top_key(key: &str) -> SmolStr {
  // Step 1: `tr/:/_/`.
  let step1: String = key
    .chars()
    .map(|c| if c == ':' { '_' } else { c })
    .collect();
  // Step 2: `s/^c2pa/C2PA/i` — replace a leading "c2pa" (any case) with "C2PA".
  let step2 = if step1.len() >= 4
    && step1
      .get(0..4)
      .is_some_and(|p| p.eq_ignore_ascii_case("c2pa"))
  {
    let mut s = String::with_capacity(step1.len());
    s.push_str("C2PA");
    s.push_str(step1.get(4..).unwrap_or(""));
    s
  } else {
    step1
  };
  // Step 3: MakeTagName.
  let mut name = make_tag_name(&step2);
  // Step 4: AddTagToTable prefix (`< 2` chars OR not starting with a letter).
  let starts_with_letter = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
  if name.chars().count() < 2 || !starts_with_letter {
    let mut prefixed = String::with_capacity(3 + name.len());
    prefixed.push_str("Tag");
    prefixed.push_str(&name);
    name = prefixed;
  }
  SmolStr::from(name)
}

/// `MakeTagName` (`ExifTool.pm:6451-6459`): `tr/-_a-zA-Z0-9//dc` (delete every
/// char outside `[-_a-zA-Z0-9]`), `ucfirst`, then `"Tag$name"` if the result is
/// shorter than 2 chars OR starts with `-`/`0`-`9`.
fn make_tag_name(name: &str) -> String {
  // `tr/-_a-zA-Z0-9//dc` — keep only legal characters.
  let kept: String = name.chars().filter(|&c| is_name_legal(c)).collect();
  // `ucfirst`.
  let mut out = ucfirst(&kept);
  // `"Tag$name" if length($name) < 2 or $name =~ /^[-0-9]/`.
  let first = out.chars().next();
  let starts_dash_or_digit = first.is_some_and(|c| c == '-' || c.is_ascii_digit());
  if out.chars().count() < 2 || starts_dash_or_digit {
    let mut prefixed = String::with_capacity(3 + out.len());
    prefixed.push_str("Tag");
    prefixed.push_str(&out);
    out = prefixed;
  }
  out
}

/// `[-_a-zA-Z0-9]` — the `MakeTagName` legal character class
/// (`ExifTool.pm:6454` `tr/-_a-zA-Z0-9//dc`).
fn is_name_legal(c: char) -> bool {
  c == '-' || c == '_' || c.is_ascii_alphanumeric()
}

/// Perl `ucfirst`: uppercase the first character, leave the rest unchanged.
fn ucfirst(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  let mut chars = s.chars();
  if let Some(first) = chars.next() {
    out.extend(first.to_uppercase());
    out.push_str(chars.as_str());
  }
  out
}

/// The recursive-descent JSON parser (the READ subset of
/// `Import::ReadJSONObject`, `Import.pm:138-243`), carrying the input bytes and
/// a cursor. Whole-file buffering replaces ExifTool's incremental RAF reads —
/// the JUMBF `json` box is already a single in-memory slice (the walker
/// validated its bounds), so the 64 kB top-up loop (`Import.pm:155-172`) is not
/// needed; the `$readMore` / `next Tok` re-read paths collapse to a plain
/// end-of-input check.
struct Parser<'a> {
  /// The box payload bytes.
  data: &'a [u8],
  /// The byte cursor (`pos $$buffPt`, `Import.pm:144`).
  pos: usize,
}

impl Parser<'_> {
  /// Parse one JSON value at `depth` (`ReadJSONObject`): skip whitespace to the
  /// next non-`\S` byte and dispatch (`{` object, `[` array, `"` string, else a
  /// bare number/literal token). Returns `None` on a parse error / EOF / a
  /// depth-budget breach (the caller bubbles it to [`JsonOutcome::Unrecognized`]).
  fn parse_value(&mut self, depth: usize) -> Option<JsonNode> {
    // Beyond-faithful: bound the recursion so a deeply nested document cannot
    // overflow the stack (`ReadJSONObject` has no depth guard).
    if depth > MAX_JSON_DEPTH {
      return None;
    }
    // Skip whitespace to the next significant byte (`$$buffPt =~ /(\S)/g`,
    // `Import.pm:175`). JSON whitespace is space/tab/LF/CR; ExifTool's `\S`
    // skips ALL Perl whitespace, so mirror `char::is_ascii_whitespace`
    // (which also covers form-feed/VT, a strict superset that never appears in
    // valid JSON between tokens).
    let tok = self.skip_ws_peek()?;
    match tok {
      b'{' => self.parse_object(depth),
      b'[' => self.parse_array(depth),
      b'"' => self.parse_string().map(JsonNode::Scalar),
      // A lone `]`/`}`/`,` here is the EMPTY-container / empty-item case
      // (`Import.pm:231-234`): ExifTool backs the cursor up one and returns
      // undef (the caller — an object/array loop — then sees the closing
      // bracket). We mirror by NOT consuming it (peek only) and returning None;
      // the object/array loop re-reads it as the terminator.
      b']' | b'}' | b',' => None,
      // A bare token: a number, `true`, `false`, or `null`
      // (`Import.pm:235-238`).
      _ => self.parse_bare_token(),
    }
  }

  /// Parse an object `{ "k": v, … }` (`Import.pm:180-204`). Reads `"KEY": VALUE`
  /// pairs until the closing `}`; a syntactically wrong delimiter (a missing
  /// `:` or `,`) returns `None` (`return undef`).
  fn parse_object(&mut self, depth: usize) -> Option<JsonNode> {
    // Consume the opening `{` (the peek in `parse_value` did not advance).
    self.pos += 1;
    let mut pairs: Vec<(SmolStr, JsonNode)> = Vec::new();
    loop {
      // Read the KEY (`$key = ReadJSONObject(...)`, `Import.pm:185`). A `}` here
      // (empty object or trailing) makes `parse_value` return None — then the
      // delimiter scan below sees the `}` and ends the object.
      let key_node = self.parse_value(depth + 1);
      if let Some(key) = key_node {
        // The key must be a scalar STRING; in valid JSON it always is.
        let key_str = scalar_string(&key)?;
        // Scan to the delimiting `:` (`$1 eq ':' or return undef`,
        // `Import.pm:191-192`).
        let colon = self.skip_ws_peek()?;
        if colon != b':' {
          return None;
        }
        self.pos += 1;
        // Read the VALUE (`Import.pm:193`); a missing value is an error.
        let val = self.parse_value(depth + 1)?;
        pairs.push((key_str, val));
      }
      // Scan to the delimiting `,` or bounding `}` (`Import.pm:201-203`).
      let delim = self.skip_ws_peek()?;
      self.pos += 1;
      match delim {
        b'}' => break,
        b',' => {}
        _ => return None,
      }
    }
    Some(JsonNode::Object(pairs))
  }

  /// Parse an array `[ v, … ]` (`Import.pm:205-216`). Reads elements until the
  /// closing `]`; an empty array yields an empty `Vec` (the first
  /// `parse_value` returns None on the `]`, the delimiter scan ends the array).
  fn parse_array(&mut self, depth: usize) -> Option<JsonNode> {
    // Consume the opening `[`.
    self.pos += 1;
    let mut items: Vec<JsonNode> = Vec::new();
    loop {
      // Read an ITEM (`push @$rtnVal, $item if defined $item`,
      // `Import.pm:208-211`). A `]` makes `parse_value` return None (an empty
      // or trailing slot); the item is simply not pushed.
      if let Some(item) = self.parse_value(depth + 1) {
        items.push(item);
      }
      // Scan to the delimiting `,` or bounding `]` (`Import.pm:213-215`).
      let delim = self.skip_ws_peek()?;
      self.pos += 1;
      match delim {
        b']' => break,
        b',' => {}
        _ => return None,
      }
    }
    Some(JsonNode::Array(items))
  }

  /// Parse a quoted string `"…"` (`Import.pm:217-230`): scan to the next
  /// unescaped `"` (an even count of preceding backslashes), then un-escape
  /// `\uHHHH` (→ the code point's UTF-8) and `\t\n\r\b\f` (→ the control char);
  /// any other `\x` → the literal `x` (`Import.pm:224-225`). Finally, a string
  /// matching the `base64:` data form is decoded to its raw bytes
  /// (`Import.pm:227-229`, see [`decode_base64_value`]). The opening `"` is at
  /// the cursor. Returns the RAW decoded bytes as a [`JsonScalar::Str`] — `FixUTF8`
  /// is deferred to flatten (it is the output stage, NOT part of `ReadJSONObject`),
  /// so the raw bytes can key the `SourceFile` database without collision.
  fn parse_string(&mut self) -> Option<JsonScalar> {
    // Consume the opening `"`.
    self.pos += 1;
    let start = self.pos;
    // Find the closing quote — a `"` preceded by an EVEN number of backslashes
    // (`$$buffPt =~ /(\\*)"/g; last unless length($1) & 1`, `Import.pm:219-220`).
    let mut i = start;
    let close = loop {
      let &b = self.data.get(i)?;
      if b == b'"' {
        // Count the run of backslashes immediately before this quote.
        let mut bs = 0usize;
        let mut j = i;
        while j > start {
          let &p = self.data.get(j - 1)?;
          if p == b'\\' {
            bs += 1;
            j -= 1;
          } else {
            break;
          }
        }
        if bs.is_multiple_of(2) {
          break i;
        }
      }
      i += 1;
    };
    // The raw (still-escaped) string bytes are `data[start..close]`.
    let raw = self.data.get(start..close)?;
    self.pos = close + 1; // past the closing quote
    // Un-escape, then base64-decode if it matches — yielding the RAW bytes
    // `ReadJSONObject` returns. `FixUTF8` is NOT applied here (it is output-time).
    let unescaped = unescape_json_string(raw);
    Some(JsonScalar::Str(decode_base64_value(unescaped)))
  }

  /// Parse a bare token — a number, `true`, `false`, or `null`
  /// (`Import.pm:235-238`): the token runs from the current byte up to (but not
  /// including) the next `[\s:,\}\]]` delimiter, or end of input. The captured
  /// lexeme is classified by the OUTPUT gate (`EscapeJSON`, `XMPStruct.pl:169-176`):
  /// `/^(true|false)$/i` → a bare [`TagValue::Bool`]; `null` → the literal
  /// STRING `"null"` (the `MissingTagValue` default, `JSON.pm:6`); anything else
  /// (a number, or junk) → a [`TagValue::Str`] of the raw lexeme, which the
  /// number gate renders BARE if in-range or QUOTED otherwise.
  fn parse_bare_token(&mut self) -> Option<JsonNode> {
    let start = self.pos;
    let mut i = start;
    while let Some(&b) = self.data.get(i) {
      // `[\s:,\}\]]` — the token-terminating delimiters (`Import.pm:236`).
      if b.is_ascii_whitespace() || b == b':' || b == b',' || b == b'}' || b == b']' {
        break;
      }
      i += 1;
    }
    // An empty token (the very next byte was already a delimiter) cannot start a
    // value — a parse error.
    if i == start {
      return None;
    }
    let lexeme_bytes = self.data.get(start..i)?;
    self.pos = i;
    Some(JsonNode::Scalar(scalar_from_lexeme(lexeme_bytes)))
  }

  /// Skip whitespace and PEEK the next significant byte WITHOUT consuming it
  /// (the cursor is left AT that byte). `None` at end of input. Mirrors
  /// `$$buffPt =~ /(\S)/g` (`Import.pm:175`) but, because every caller then
  /// decides whether to consume, this peeks (leaving the matched byte) rather
  /// than advancing past it.
  fn skip_ws_peek(&mut self) -> Option<u8> {
    while let Some(&b) = self.data.get(self.pos) {
      if b.is_ascii_whitespace() {
        self.pos += 1;
      } else {
        return Some(b);
      }
    }
    None
  }
}

/// Classify a bare JSON lexeme (its RAW bytes) into a [`JsonScalar`] via
/// ExifTool's `EscapeJSON` gate semantics (`XMPStruct.pl:169-176`):
/// `/^(true|false)$/i` → a bare boolean; the literal `null` → the STRING `"null"`
/// (`MissingTagValue` default, `JSON.pm:6`); anything else (a number, or junk) →
/// the RAW lexeme bytes as a [`JsonScalar::Str`] (the `escape_json_is_number`
/// gate at emit renders an in-range number BARE, an out-of-range token QUOTED).
/// A bare token is ASCII in valid JSON, so deferring `FixUTF8` to flatten is a
/// no-op on it — and a non-ASCII junk token keeps its raw bytes, `FixUTF8`'d at
/// flatten exactly as before.
fn scalar_from_lexeme(lexeme: &[u8]) -> JsonScalar {
  if lexeme.eq_ignore_ascii_case(b"true") {
    JsonScalar::Bool(true)
  } else if lexeme.eq_ignore_ascii_case(b"false") {
    JsonScalar::Bool(false)
  } else if lexeme == b"null" {
    // ExifTool's default `MissingTagValue` is the string "null" (`JSON.pm:6`):
    // `ReadJSON` leaves a JSON `null` as the literal scalar "null", which the
    // EscapeJSON number/boolean gate then renders as the QUOTED string "null".
    JsonScalar::Str(b"null".to_vec())
  } else {
    // A number (or junk): keep the raw lexeme bytes.
    JsonScalar::Str(lexeme.to_vec())
  }
}

/// The string content of a [`JsonNode::Scalar`] that is a [`JsonScalar::Str`],
/// repaired through `FixUTF8` — used to recover an OBJECT KEY (always a JSON
/// string), which is rendered for output (a tag name). `None` for any other
/// node shape (a non-string key is invalid JSON). Keys are ASCII in practice,
/// so `FixUTF8` is normally a no-op; it matches the bundled output stage for a
/// malformed key.
fn scalar_string(node: &JsonNode) -> Option<SmolStr> {
  match node {
    JsonNode::Scalar(JsonScalar::Str(bytes)) => {
      Some(SmolStr::from(crate::convert::fix_utf8(bytes)))
    }
    _ => None,
  }
}

/// Un-escape a JSON string's RAW bytes, faithfully reproducing ExifTool's TWO
/// ordered global substitutions (`Import.pm:224-225`):
///
/// 1. `s/\\u([0-9a-f]{4})/ToUTF8(hex $1)/ige` — every `\uHHHH` (4 hex digits,
///    case-insensitive) is replaced by the code point's UTF-8 ([`push_to_utf8`],
///    matching `ToUTF8` with `Charset = 'UTF8'`: the standard 1–3-byte encoding
///    for any value ≤ U+FFFF, INCLUDING the surrogate range D800–DFFF, which
///    encodes as a 3-byte WTF-8 sequence — ExifTool does NOT combine surrogate
///    PAIRS; each half is encoded independently). U+0000 emits no byte.
/// 2. `s/\\(.)/$unescapeJSON{$1}||$1/sge` — over the RESULT of pass 1, every
///    `\` + next byte collapses to the control char for `t`/`n`/`r`/`b`/`f`
///    (`%unescapeJSON`, `Import.pm:21`) else the literal byte. Because this runs
///    AFTER pass 1, a `\` (which pass 1 turns into a literal `\`) is itself
///    consumed here — so `\n` becomes a newline (oracle-verified).
///
/// The result of both passes is the RAW (pre-`FixUTF8`) bytes that
/// `ReadJSONObject` returns — `FixUTF8` is the OUTPUT stage (it is not in
/// `Import.pm`), deferred to flatten ([`scalar_to_value`]), where the WTF-8
/// surrogate bytes / any other invalid sequence render as `?` exactly as
/// bundled does. Keeping these bytes raw lets them key the `SourceFile` database
/// without an early-normalization collision.
fn unescape_json_string(raw: &[u8]) -> Vec<u8> {
  // ── Pass 1: `\uHHHH` → ToUTF8 bytes; everything else copied verbatim. ──
  let mut pass1: Vec<u8> = Vec::with_capacity(raw.len());
  let mut i = 0usize;
  while let Some(&b) = raw.get(i) {
    if b == b'\\'
      && raw.get(i + 1) == Some(&b'u')
      && let Some(hex) = raw.get(i + 2..i + 6)
      && hex.iter().all(u8::is_ascii_hexdigit)
    {
      let mut cp: u32 = 0;
      for &h in hex {
        cp = cp * 16 + (h as char).to_digit(16).unwrap_or(0);
      }
      push_to_utf8(&mut pass1, cp);
      i += 6;
      continue;
    }
    pass1.push(b);
    i += 1;
  }
  // ── Pass 2: `\(.)` → the unescape mapping (else the literal byte). ──
  let mut pass2: Vec<u8> = Vec::with_capacity(pass1.len());
  let mut j = 0usize;
  while let Some(&b) = pass1.get(j) {
    if b == b'\\'
      && let Some(&e) = pass1.get(j + 1)
    {
      let replacement = match e {
        b't' => b'\t',
        b'n' => b'\n',
        b'r' => b'\r',
        b'b' => 0x08,
        b'f' => 0x0C,
        // Any other escaped byte → the literal byte (`|| $1`); `\"`, `\\`, `\/`
        // in practice. A non-ASCII escaped byte is kept and repaired by fix_utf8.
        other => other,
      };
      pass2.push(replacement);
      j += 2;
      continue;
    }
    // A trailing lone `\` (no following byte) is kept literally (`s/\\(.)/.../`
    // does not match it).
    pass2.push(b);
    j += 1;
  }
  // Return the RAW bytes — `FixUTF8` is deferred to flatten (the output stage).
  pass2
}

/// Encode a Unicode code point as ExifTool's `ToUTF8` does with
/// `Charset = 'UTF8'` (`Charset::Recompose`): the standard UTF-8 byte sequence
/// for any scalar ≤ U+FFFF, with NO special-casing of the surrogate range
/// (D800–DFFF encode to a 3-byte WTF-8 sequence — the same as `Recompose`,
/// which lets `😀` become two independent 3-byte sequences rather than
/// a combined astral character). U+0000 emits NO byte (Recompose drops it). A
/// `\uHHHH` escape is always ≤ U+FFFF (4 hex digits), so the 4-byte form never
/// arises; it is omitted.
fn push_to_utf8(out: &mut Vec<u8>, cp: u32) {
  if cp == 0 {
    // `ToUTF8(0)` yields an empty string (`Recompose` drops the NUL).
    return;
  }
  if cp < 0x80 {
    out.push(cp as u8);
  } else if cp < 0x800 {
    out.push(0xC0 | (cp >> 6) as u8);
    out.push(0x80 | (cp & 0x3F) as u8);
  } else {
    // cp ≤ 0xFFFF (a `\uHHHH` is at most 4 hex digits), surrogates included.
    out.push(0xE0 | (cp >> 12) as u8);
    out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
    out.push(0x80 | (cp & 0x3F) as u8);
  }
}

/// Decode an `Import::ReadJSON` `base64:`-prefixed binary value
/// (`Import.pm:227-229`):
///
/// ```text
/// if ($rtnVal =~ /^base64:[A-Za-z0-9+\/]*={0,2}$/ and length($rtnVal) % 4 == 3) {
///     $rtnVal = ${Image::ExifTool::XMP::DecodeBase64(substr($rtnVal,7))};
/// }
/// ```
///
/// A value whose ENTIRE content is `base64:` + a base64 body (`[A-Za-z0-9+/]`
/// with up to two trailing `=`) AND whose total length (including the 7-char
/// `base64:` prefix) is `≡ 3 (mod 4)` is decoded to its RAW bytes (the body
/// passed to [`decode_base64`], the XMP `DecodeBase64` algorithm). This mirrors
/// `ReadJSONObject` (`Import.pm:227-229`), which returns the raw decoded bytes —
/// `FixUTF8` is NOT applied here (it is the output stage, deferred to flatten),
/// so these decoded bytes can key the `SourceFile` database WITHOUT a collision:
/// the base64-decoded `FE FD` and the literal ASCII `??` are DISTINCT keys even
/// though both render `??` at output. At flatten the surviving bytes become text
/// (`base64:SGk=` → `Hi`) or `?` per invalid byte (`base64:/v0=` → `FE FD` →
/// `??`) via `FixUTF8`. A value that does not match (the length rule fails, or a
/// non-base64 byte is present) is returned unchanged (still pre-`FixUTF8`).
/// The match operates on the unescaped bytes interpreted as ASCII — a real
/// `base64:` value is all-ASCII (the `base64:` prefix + base64 alphabet), so a
/// byte ≥ 0x80 simply fails [`is_base64_body`] and the value passes through.
fn decode_base64_value(value: Vec<u8>) -> Vec<u8> {
  const PREFIX: &[u8] = b"base64:";
  // `length($rtnVal) % 4 == 3` is on the WHOLE string (prefix included).
  if value.len() % 4 == 3
    && let Some(body) = value.strip_prefix(PREFIX)
    && is_base64_body(body)
  {
    return decode_base64(body);
  }
  value
}

/// Whether `body` matches the base64 data form `[A-Za-z0-9+/]*={0,2}` ANCHORED
/// to the whole string (`Import.pm:227`): zero or more base64 characters, then
/// zero to two `=` padding characters, and NOTHING else.
fn is_base64_body(body: &[u8]) -> bool {
  let bytes = body;
  let mut i = 0;
  while let Some(&b) = bytes.get(i) {
    if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' {
      i += 1;
    } else {
      break;
    }
  }
  // The remainder must be only `=` padding, at most two.
  let pad = bytes.get(i..).unwrap_or(&[]);
  pad.len() <= 2 && pad.iter().all(|&b| b == b'=')
}

/// Decode a base64 body to its raw bytes — the read direction of XMP
/// `DecodeBase64` (`XMP.pm:2981-3011`): standard base64 over `A-Za-z0-9+/` with
/// `=` padding and whitespace ignored. (The caller has already validated the
/// body against the strict `[A-Za-z0-9+/]*={0,2}` form, so this only needs the
/// straight 4-sextet → 3-byte decode; a stray non-base64 byte is skipped, as
/// `DecodeBase64`'s `tr/.../d` deletes anything outside the alphabet.)
fn decode_base64(body: &[u8]) -> Vec<u8> {
  let mut out: Vec<u8> = Vec::with_capacity(body.len() / 4 * 3 + 3);
  let mut acc: u32 = 0;
  let mut bits = 0u32;
  for &b in body {
    let v = match b {
      b'A'..=b'Z' => b - b'A',
      b'a'..=b'z' => b - b'a' + 26,
      b'0'..=b'9' => b - b'0' + 52,
      b'+' => 62,
      b'/' => 63,
      // `=` padding and anything else (whitespace) is skipped.
      _ => continue,
    };
    acc = (acc << 6) | u32::from(v);
    bits += 6;
    if bits >= 8 {
      bits -= 8;
      out.push((acc >> bits) as u8);
    }
  }
  out
}
