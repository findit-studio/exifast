// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::CBOR` — the JUMBF `cbor` content-box decoder (the READ
//! subset of `CBOR::Main` / `ProcessCBOR` + `ReadCBORValue`, `CBOR.pm` 1.04,
//! bundled 13.59). **Phase 3 of #142 — the final phase.**
//!
//! ## Where it enters
//!
//! A JUMBF `cbor` content box (`Jpeg2000.pm:420-424`: `cbor` → a `CBORData`
//! tagInfo with `Flags => ['Binary','Protected']` + `SubDirectory => { TagTable
//! => 'Image::ExifTool::CBOR::Main' }`) carries a CBOR document (RFC 8949 binary
//! — the native C2PA manifest-store format). Phase-1's [`super::JumbfWalker`]
//! recognized the box but emitted no tags; this module is the deferred decoder.
//! [`decode`] parses the document and yields the FLATTENED `CBOR:<key>` tags
//! (`ProcessCBOR` → `JSON::ProcessTag` → `FoundTag`).
//!
//! Unlike the `json` box (`Jpeg2000.pm:411`), `cbor` does NOT carry the
//! `BlockExtract` flag, so the JUMBFLabel rename condition (`Jpeg2000.pm:1206`,
//! `not SubDirectory or BlockExtract`) is FALSE — a `cbor` box is never renamed
//! by an active label (the `CBORData` tagInfo and its SubDirectory keep their
//! own names regardless), oracle-verified vs bundled 13.59.
//!
//! ## Part A — the recursive item reader ([`Reader::read_value`], `CBOR.pm:88`)
//!
//! `ReadCBORValue` reads one CBOR data item: a 1-byte initial that splits into a
//! 3-bit MAJOR type (`>>5`) and 5-bit ADDITIONAL info (`& 0x1f`). The additional
//! info is the argument: `0..=23` inline, `24`/`25`/`26`/`27` a 1/2/4/8-byte
//! big-endian follow-on integer, `31` the indefinite-length marker
//! (`CBOR.pm:99-111`). The eight major types (`CBOR.pm:117-259`):
//!
//! * **0 unsigned int** — `$val = $num` (the argument).
//! * **1 negative int** — `$val = -1 * $num` (`CBOR.pm:121`). This is a faithful
//!   ExifTool QUIRK: RFC 8949 negative integers encode `-1 - n`, but CBOR.pm
//!   computes `-1 * n`, so a wire `-7` (major-1 argument `6`) decodes to `-6`,
//!   and `-1`/`-2` (arguments `0`/`1`) decode to `0`/`-1`. The port reproduces
//!   `-1 * num` EXACTLY (oracle-verified) — and the quirk cascades into the
//!   tag-6 decimal-fraction / bigfloat exponents, which are themselves decoded
//!   negatives.
//! * **2 byte string / 3 text string** — `substr` of `$num` bytes
//!   (`CBOR.pm:124-148`). A byte string becomes a scalar reference (binary), a
//!   text string is `Decode`d as UTF-8. An INDEFINITE-length string
//!   (`$num < 0`) concatenates break-terminated chunks (`CBOR.pm:125-136`).
//! * **4 array / 5 map** — `$num` elements (a map is `2 * $num` items read as
//!   key/value pairs, `CBOR.pm:149-194`); an indefinite count
//!   (`$num == -1`) reads until a break (`CBOR.pm:175-177`). A map preserves its
//!   ordered keys (`_ordered_keys_`, `CBOR.pm:185-190`).
//! * **6 semantic tag** — read the next value, then apply an optional conversion
//!   keyed on the tag number (`CBOR.pm:195-230`): tag 0 a date-time string
//!   (`ConvertXMPDate`), tag 1 an epoch (`ConvertUnixTime`), tags 2/3 a
//!   positive/negative bignum (big-endian byte accumulation), tags 4/5 a decimal
//!   fraction / bigfloat (`mantissa * base ** exponent`). All OTHER tags
//!   (including the COSE `16`/`17`/`18`/`19`) are TRANSPARENT — the wrapped value
//!   passes through unchanged. COSE signature structures therefore stay OPAQUE:
//!   the wrapped byte string renders as the `(Binary data N bytes …)`
//!   placeholder — NO crypto verification (`CBOR.pm:32-35` only NAMES the COSE
//!   tags for verbose output).
//! * **7 simple / float** — `false`/`true`/`null`/`undef` for arguments
//!   `20`/`21`/`22`/`23` (`CBOR.pm:56-61`), `25`/`26`/`27` a half/single/double
//!   float, `31` the break marker (`CBOR.pm:231-256`). The HALF-float decode is
//!   another faithful ExifTool quirk — `($mant + 1024) ** ($exp - 25)` with a
//!   `0 ** -24` subnormal and a DEAD inf/nan branch (the `elsif (exp != 31)` in
//!   `CBOR.pm:243` tests the Perl builtin `exp()`, always true, so `0x7c00`
//!   "infinity" decodes to `1024 ** 6`, NOT infinity); reproduced exactly in
//!   [`half_float`].
//!
//! ## Part B — the flattening ([`flatten_top`], `CBOR.pm:287-304`)
//!
//! `ProcessCBOR` reads top-level values in a LOOP until the box end. For each:
//! a HASH flattens its ordered keys via `JSON::ProcessTag(key, value)`; an ARRAY
//! flattens each element as `Item<i>` (`CBOR.pm:294-297`); a bare scalar `'0'`
//! STOPS the loop (treated as padding, `CBOR.pm:298-300`); any other top-level
//! scalar is ignored (`CBOR.pm:301-303`).
//!
//! `JSON::ProcessTag` (`JSON.pm:89-112`) under the golden `-struct` regime
//! (`Options('Struct') == 1`) emits ONE struct-valued tag per top-level key —
//! the SAME path the Phase-2 `json` decoder uses, so the value-tree → `TagValue`
//! flatten ([`node_to_value`]) and the top-level tag-NAME legalization
//! ([`super::json::legalize_top_key`], reused) are shared. The differences from
//! `json`: a top-level ARRAY emits `Item<i>` keys; CBOR leaves are NATIVE typed
//! values (a real integer / float / byte string / boolean / `null`), not raw
//! JSON lexemes; and the small `CBOR::Main` predefined-tag table
//! ([`predefined_name`], `CBOR.pm:72-82`) overrides a handful of top-level key
//! NAMES (`dc:title` → `Title`, `thumbnailUrl` → `ThumbnailURL`, …).
//!
//! ## Part C — group + axis
//!
//! `CBOR::Main`'s `GROUPS => { 0 => 'JUMBF', 1 => 'CBOR', 2 => 'Other' }`
//! (`CBOR.pm:64`) — the tags emit under family-0 group `JUMBF`, family-1 group
//! `CBOR` (so a `-G1` render is `CBOR:<key>`, distinct from `json`'s `JSON:*`).
//! The `cbor` box rides the same `Doc<N>` sub-document axis as the JUMD tags
//! ([`super::JumbfWalker`] supplies the box's `(doc, doc_subpath)`); a `-G3`
//! render is `Doc<N>:CBOR:<key>`.
//!
//! ## Robustness (beyond-faithful, the Phase-1/2 budget pattern)
//!
//! * a **depth budget** ([`MAX_CBOR_DEPTH`], the Phase-2 [`super::json`]
//!   `MAX_JSON_DEPTH` pattern) bounds array/map/tag nesting so a crafted
//!   deeply-nested document cannot overflow the recursive reader's stack
//!   (`ReadCBORValue` recurses with no depth guard). Real C2PA CBOR is a handful
//!   of levels.
//! * **per-byte bounds** — every read is a checked `.get()` (the `exif`
//!   module's `#![deny(clippy::indexing_slicing)]` panic-safety contract), so a
//!   truncated or malformed document never reads out of range; a truncation
//!   surfaces the bundled `Truncated CBOR …` `$et->Warn` (`CBOR.pm:91`/`:108`/
//!   `:124`) carried as a [`JumbfWarning::CborError`](super::JumbfWarning), NOT a
//!   panic. Mirroring ExifTool, a top-level value that fails mid-decode STOPS the
//!   loop and emits NO partial tag for that value (the whole item failed), while
//!   the values fully read BEFORE it are kept.

use super::json::legalize_top_key;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::{string::String, vec::Vec};

/// Beyond-faithful recursion cap on CBOR array/map/tag nesting (the Phase-2
/// [`super::json::MAX_JSON_DEPTH`] pattern). `ReadCBORValue` recurses with no
/// depth guard (`CBOR.pm:129`/`:173`/`:209`); a crafted document nesting
/// `[[[…]]]` thousands deep would blow the stack. Real C2PA CBOR is a handful of
/// levels, so this bound is far above any genuine document. A container deeper
/// than this fails at that point with the [`DEPTH_ERR`] message (the same
/// `$et->Warn` surface as a truncation), terminating the top-level loop.
const MAX_CBOR_DEPTH: usize = 64;

/// The `$et->Warn` message a [`MAX_CBOR_DEPTH`] breach raises (beyond-faithful —
/// ExifTool has no such guard). Phrased like the genuine `CBOR.pm` error strings
/// so it reads as one more `ExifTool:Warning`.
const DEPTH_ERR: &str = "CBOR nesting too deep";

/// Expose [`MAX_CBOR_DEPTH`] to the sibling unit tests (the depth-budget
/// termination test builds a document just past the cap).
#[cfg(test)]
pub(super) fn tests_max_depth() -> usize {
  MAX_CBOR_DEPTH
}

/// The outcome of decoding a `cbor` content box: the flattened tags in walk
/// order, plus an optional `$et->Warn` message if `ReadCBORValue` hit an error
/// (`CBOR.pm:289` `$err and $et->Warn($err), last`). Unlike the `json` decoder,
/// `ProcessCBOR` ALWAYS returns 1 (`CBOR.pm:305`) — it never raises the
/// `Unrecognized box` warning; a malformed item raises a SPECIFIC `Truncated …`
/// / `Invalid …` warning and stops the loop, keeping any tags already emitted.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct CborOutcome {
  /// The flattened top-level `(legalized-or-predefined-name, value)` tags in
  /// document order.
  tags: Vec<(SmolStr, TagValue)>,
  /// The `ReadCBORValue` error message, if the top-level loop stopped on one.
  warning: Option<SmolStr>,
}

impl CborOutcome {
  /// The flattened tags in walk order.
  pub(crate) fn tags(self) -> Vec<(SmolStr, TagValue)> {
    self.tags
  }

  /// The `$et->Warn` message raised by a mid-decode `ReadCBORValue` error, if
  /// any.
  pub(crate) fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }
}

/// Decode a JUMBF `cbor` content box payload into a [`CborOutcome`]
/// (`ProcessCBOR` over the box's data, `CBOR.pm:274-306`). Reads top-level CBOR
/// values in a loop until the box end (`while ($pos < $end)`): a HASH/ARRAY is
/// flattened ([`flatten_top`]); a bare `0` stops the loop (padding); any other
/// top-level scalar is ignored. A `ReadCBORValue` error stops the loop and is
/// returned as the outcome's warning, keeping the tags already emitted.
pub(crate) fn decode(data: &[u8]) -> CborOutcome {
  let mut reader = Reader { data, pos: 0 };
  let mut out = CborOutcome::default();
  // `SetByteOrder('MM')` (`CBOR.pm:283`) — CBOR's follow-on integers + floats
  // are big-endian; [`Reader`] reads them BE unconditionally.
  while reader.pos < data.len() {
    match reader.read_value(0) {
      // `$err and $et->Warn($err), last` (`CBOR.pm:289`).
      Err(msg) => {
        out.warning = Some(msg);
        break;
      }
      // A `break` (`undef $val`) at the top level — `ProcessCBOR` would loop
      // again; treat as end of meaningful data.
      Ok(None) => break,
      Ok(Some(node)) => match node {
        // `ref $val eq 'HASH'` — flatten the ordered keys (`CBOR.pm:290-293`).
        CborNode::Map(pairs) => flatten_top_map(pairs, &mut out.tags),
        // `ref $val eq 'ARRAY'` — flatten each element as `Item<i>`
        // (`CBOR.pm:294-297`).
        CborNode::Array(items) => flatten_top_array(items, &mut out.tags),
        // `$val eq '0'` — a bare zero (an unsigned `0`, or a negative whose
        // `-1 * num` is `0`) is treated as padding and STOPS the loop
        // (`CBOR.pm:298-300`).
        CborNode::Uint(0) | CborNode::Nint(0) => break,
        // Any other top-level scalar: `VPrint "Unknown value"` — ignored, no tag
        // (`CBOR.pm:301-303`). Continue the loop to the next value.
        _ => {}
      },
    }
  }
  out
}

/// Flatten one top-level HASH's ordered keys into `CBOR:<name>` tags
/// (`CBOR.pm:291-293` → `JSON::ProcessTag(key, value)`). Each key's NAME is the
/// `CBOR::Main` predefined override ([`predefined_name`]) when present, else the
/// `JSON`-shared legalization ([`legalize_top_key`]) of the STRINGIFIED key. An
/// EMPTY top-level array value emits no tag (`ProcessTag` iterates nothing,
/// `JSON.pm:105-108`); every other value (including an empty MAP, emitted as
/// `{}`) produces one tag. Nested structure is preserved verbatim
/// ([`node_to_value`]).
fn flatten_top_map(pairs: Vec<(String, CborNode)>, out: &mut Vec<(SmolStr, TagValue)>) {
  out.reserve(pairs.len());
  for (key, node) in pairs {
    // An EMPTY top-level array value emits no tag (the `ProcessTag` ARRAY branch
    // calls `FoundTag` zero times). This skip is TOP-LEVEL only — a nested empty
    // array inside a struct value is preserved as `[]` (`node_to_value`).
    if matches!(&node, CborNode::Array(items) if items.is_empty()) {
      continue;
    }
    let name = predefined_name(&key).unwrap_or_else(|| legalize_top_key(&key));
    out.push((name, node_to_value(node)));
  }
}

/// Flatten one top-level ARRAY into `CBOR:Item<i>` tags (`CBOR.pm:294-297` →
/// `JSON::ProcessTag("Item<i>", element)`). Each element index `i` keys a tag
/// `Item<i>` (legalized — always already legal). An empty array emits no tags
/// (the loop iterates nothing). A nested empty-array ELEMENT is preserved as
/// `[]` (it is a value, not a top-level array-value skip).
fn flatten_top_array(items: Vec<CborNode>, out: &mut Vec<(SmolStr, TagValue)>) {
  out.reserve(items.len());
  for (i, node) in items.into_iter().enumerate() {
    // `Item<i>` is always a legal tag name (a letter followed by digits), so the
    // shared legalizer leaves it unchanged; route it through anyway for a single
    // source of truth.
    let name = legalize_top_key(&std::format!("Item{i}"));
    out.push((name, node_to_value(node)));
  }
}

/// Convert a decoded [`CborNode`] into its emitted [`TagValue`], preserving
/// nested structure (the `-struct` value: a map → [`TagValue::Map`] with RAW
/// inner keys, an array → [`TagValue::List`], a scalar → its native value).
/// Inner map keys are NOT legalized — they pass through as the struct's keys
/// verbatim (the STRINGIFIED CBOR key), oracle-verified vs bundled 13.59.
fn node_to_value(node: CborNode) -> TagValue {
  match node {
    // `$val = $num` — a real unsigned integer (the `EscapeJSON` number gate
    // renders it bare, or quoted if `>= 16` digits, exactly as bundled
    // stringifies-then-gates a Perl integer).
    CborNode::Uint(n) => TagValue::U64(n),
    // `$val = -1 * $num` (the faithful negative-int quirk, already applied).
    CborNode::Nint(n) => TagValue::I64(n),
    // A byte string (`fmt == 2`) — a scalar reference (binary), rendered as the
    // `(Binary data N bytes …)` placeholder via [`TagValue::Bytes`] in BOTH
    // `-n` and `-j` modes (no PrintConv). COSE signature payloads land here.
    CborNode::Bytes(bytes) => TagValue::Bytes(bytes),
    // A text string (`fmt == 3`) — `Decode`d UTF-8, already repaired
    // ([`Reader::read_text`]).
    CborNode::Text(s) => TagValue::Str(SmolStr::from(s)),
    CborNode::Float(f) => TagValue::F64(f),
    // A type-7 simple value (`false`/`true`) — a bare boolean.
    CborNode::Bool(b) => TagValue::Bool(b),
    // `null`/`undef`/`Unknown (…)`, or a tag-0/1 converted date string — a plain
    // string (the `null` simple value is the literal text `"null"`, the
    // `MissingTagValue` default rendered by the gate as a quoted string).
    CborNode::SimpleStr(s) => TagValue::Str(s),
    CborNode::Array(items) => TagValue::List(items.into_iter().map(node_to_value).collect()),
    CborNode::Map(pairs) => TagValue::Map(
      pairs
        .into_iter()
        .map(|(k, v)| (SmolStr::from(k), node_to_value(v)))
        .collect(),
    ),
  }
}

/// The `CBOR::Main` predefined-tag NAME for a top-level key, if the key is one
/// of the table's pre-declared entries (`CBOR.pm:72-82`). `FoundTag`
/// (`JSON.pm:67`) only auto-creates a tag when the key is NOT already in the
/// table, so a predefined key keeps its declared `Name` instead of the
/// auto-legalized form. Only the entries whose Name DIFFERS from the
/// auto-derived `MakeTagName` form actually need overriding — but the whole
/// table is listed for fidelity:
///
/// * `dc:title` → `Title`, `dc:format` → `Format` (the colon would otherwise
///   become `Dc_title` / `Dc_format`);
/// * `thumbnailUrl` → `ThumbnailURL` (the `URL` acronym capitalization);
/// * `authorName` → `AuthorName`, `authorIdentifier` → `AuthorIdentifier`,
///   `documentID` → `DocumentID`, `instanceID` → `InstanceID`, `thumbnailHash`
///   → `ThumbnailHash`, `relationship` → `Relationship` — these coincide with
///   the auto-derived name, listed so the table is complete and unambiguous.
///
/// The `Groups => { 2 => 'Author' }` on the author tags + the `List => 1` on
/// `thumbnailHash` do NOT affect the `-G1`/`-G3` family-1 group (`CBOR`) or the
/// single-value rendering exercised here, so they are not modeled. `None` for a
/// key with no predefined entry (the caller legalizes it).
fn predefined_name(key: &str) -> Option<SmolStr> {
  let name = match key {
    "dc:title" => "Title",
    "dc:format" => "Format",
    "authorName" => "AuthorName",
    "authorIdentifier" => "AuthorIdentifier",
    "documentID" => "DocumentID",
    "instanceID" => "InstanceID",
    "thumbnailHash" => "ThumbnailHash",
    "thumbnailUrl" => "ThumbnailURL",
    "relationship" => "Relationship",
    _ => return None,
  };
  Some(SmolStr::new(name))
}

/// A decoded CBOR data item — the in-memory shape `ReadCBORValue` builds, after
/// the major-6 tag conversions have been applied. Map keys preserve document
/// order (the `_ordered_keys_` list, `CBOR.pm:186-189`).
#[derive(Debug, Clone, PartialEq)]
enum CborNode {
  /// A major-0 unsigned integer (`$val = $num`).
  Uint(u64),
  /// A major-1 negative integer AFTER the `-1 * num` quirk (`CBOR.pm:121`), or a
  /// tag-2/3 bignum. Stored as the (possibly-quirked) signed value.
  Nint(i64),
  /// A major-2 byte string (binary) — rendered as the `(Binary data N bytes …)`
  /// placeholder. The bytes are a copy of the (already in-memory, box-bounded)
  /// payload slice; only the LENGTH is rendered.
  Bytes(Vec<u8>),
  /// A major-3 text string, `Decode`d as UTF-8 ([`crate::convert::fix_utf8`]).
  Text(String),
  /// A major-7 / float value (half via [`half_float`], single, double, or a
  /// tag-4/5 decimal-fraction / bigfloat result).
  Float(f64),
  /// A major-7 `false`/`true` simple value (arguments 20/21) — a bare boolean.
  Bool(bool),
  /// A major-7 `null`/`undef`/`Unknown (…)` simple value (a plain STRING), or a
  /// tag-0/1 converted date-time string. `null` is the literal text `"null"`
  /// (`%cborType7{22}`, the `MissingTagValue` default).
  SimpleStr(SmolStr),
  /// A major-4 array — ordered elements (`CBOR.pm:192`).
  Array(Vec<CborNode>),
  /// A major-5 map — ordered `(stringified-key, value)` pairs in document order
  /// (`_ordered_keys_`, `CBOR.pm:185-191`).
  Map(Vec<(String, CborNode)>),
}

/// The recursive CBOR item reader (the READ subset of `ReadCBORValue`,
/// `CBOR.pm:88-268`), carrying the input bytes and a cursor. Whole-box buffering
/// replaces ExifTool's `$dataPt`/`$pos`/`$end` triple — the JUMBF `cbor` box is
/// a single in-memory slice (the walker validated its bounds).
struct Reader<'a> {
  /// The box payload bytes.
  data: &'a [u8],
  /// The byte cursor (`$pos`, `CBOR.pm:90`).
  pos: usize,
}

impl Reader<'_> {
  /// Read one CBOR data item at `depth` (`ReadCBORValue`). `Ok(Some(node))` is a
  /// value, `Ok(None)` is a `break` (an indefinite-length terminator), `Err(msg)`
  /// is the `$et->Warn` text of a truncation / invalid-type error. Beyond
  /// faithful: a recursion past [`MAX_CBOR_DEPTH`] is an `Err(DEPTH_ERR)`.
  fn read_value(&mut self, depth: usize) -> Result<Option<CborNode>, SmolStr> {
    // `return(undef, 'Truncated CBOR data', $pos) if $pos >= $end` (`CBOR.pm:91`).
    let Some(&initial) = self.data.get(self.pos) else {
      return Err(SmolStr::new_static("Truncated CBOR data"));
    };
    self.pos += 1;
    // `$dat = $fmt & 0x1f; $fmt >>= 5` (`CBOR.pm:95-98`).
    let dat = initial & 0x1f;
    let fmt = initial >> 5;

    // Decode the argument `$num` (and, for `24`-`27`, advance past the follow-on
    // bytes). `num` is `None` for the indefinite marker (`$dat == 31`).
    let (num, is_indefinite) = self.read_argument(dat)?;

    match fmt {
      // Major 0: unsigned integer (`$val = $num`, `CBOR.pm:117-119`).
      0 => Ok(Some(CborNode::Uint(num.unwrap_or(0)))),
      // Major 1: negative integer — the `-1 * $num` quirk (`CBOR.pm:120-122`).
      1 => Ok(Some(CborNode::Nint(neg_quirk(num.unwrap_or(0))))),
      // Major 2/3: byte / text string (`CBOR.pm:123-148`).
      2 | 3 => self.read_string(fmt, num, is_indefinite, depth),
      // Major 4/5: array / map (`CBOR.pm:149-194`).
      4 | 5 => self.read_collection(fmt, num, is_indefinite, depth),
      // Major 6: semantic tag (`CBOR.pm:195-230`).
      6 => self.read_tag(num.unwrap_or(0), depth),
      // Major 7: simple value / float / break (`CBOR.pm:231-256`).
      7 => Ok(read_simple(dat, num.unwrap_or(0))?),
      // `Unknown CBOR format $fmt` (`CBOR.pm:258`). Unreachable for a 3-bit
      // value (0..=7), but kept faithful.
      other => Err(SmolStr::from(std::format!("Unknown CBOR format {other}"))),
    }
  }

  /// Decode the additional-info ARGUMENT (`CBOR.pm:99-111`). Returns
  /// `(num, is_indefinite)`:
  /// * `dat < 24` ⇒ `num = dat` inline;
  /// * `dat == 31` ⇒ indefinite (`num = None`, `is_indefinite = true`);
  /// * `dat ∈ {24,25,26,27}` ⇒ a 1/2/4/8-byte big-endian follow-on integer
  ///   (`num = Some(value)`); for a major-7 `25`/`26`/`27` this same `num`
  ///   carries the half/single/double-float BITS (`GetFloat`/`GetDouble` read
  ///   the same bytes, `CBOR.pm:250`/`:252`);
  /// * any other `dat` (`28`/`29`/`30`) ⇒ `Invalid CBOR integer type $dat`
  ///   (`CBOR.pm:106`).
  fn read_argument(&mut self, dat: u8) -> Result<(Option<u64>, bool), SmolStr> {
    if dat < 24 {
      Ok((Some(u64::from(dat)), false))
    } else if dat == 31 {
      Ok((None, true))
    } else {
      let size = match dat {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        // `Invalid CBOR integer type $dat` (`CBOR.pm:106`).
        _ => {
          return Err(SmolStr::from(std::format!(
            "Invalid CBOR integer type {dat}"
          )));
        }
      };
      // `return ..., 'Truncated CBOR integer value' if $pos + $size > $end`
      // (`CBOR.pm:108`).
      let Some(slice) = self.data.get(self.pos..self.pos + size) else {
        return Err(SmolStr::new_static("Truncated CBOR integer value"));
      };
      let mut value: u64 = 0;
      for &b in slice {
        value = (value << 8) | u64::from(b);
      }
      self.pos += size;
      Ok((Some(value), false))
    }
  }

  /// Read a major-2 byte / major-3 text string (`CBOR.pm:123-148`). For a
  /// definite length, `$num` bytes are taken; a byte string becomes
  /// [`CborNode::Bytes`], a text string is `Decode`d UTF-8 ([`Reader::read_text`]).
  /// An INDEFINITE-length string (`is_indefinite`) concatenates break-terminated
  /// sub-chunks (`CBOR.pm:125-136`).
  fn read_string(
    &mut self,
    fmt: u8,
    num: Option<u64>,
    is_indefinite: bool,
    depth: usize,
  ) -> Result<Option<CborNode>, SmolStr> {
    if is_indefinite {
      // `$num < 0` indefinite-length string: read break-terminated sub-chunks,
      // appending each chunk's value to the accumulator until the break
      // (`CBOR.pm:127-136`, the `for(;;){ … last if not defined $val; $string .=
      // $val }` loop). The loop exits ONLY on the break (`undef $val`), so the
      // byte AFTER the indefinite string is always the next top-level item — a
      // non-string chunk MUST NOT abort the loop early (that would truncate the
      // string AND leave the remaining chunks + the break byte to be misread as
      // top-level data, silently dropping a following top-level map). For a
      // string chunk we accumulate its RAW bytes (a text chunk is already
      // `Decode`d; a byte chunk's bytes); ExifTool's `$string .= $val` for a
      // NON-string chunk appends that value's STRINGIFICATION (the comment at
      // `CBOR.pm:132` notes it does not verify the chunk was a string), which we
      // append as its ASCII bytes ([`stringify_indefinite_chunk`]) and keep
      // reading. ExifTool reads each chunk via a GENERIC `ReadCBORValue`
      // recursion (`CBOR.pm:129`) with NO budget — so a crafted payload of nested
      // indefinite strings (`0x7f`/`0x5f` …) recurses one frame per level. Bound
      // the recursion by the SAME beyond-faithful [`MAX_CBOR_DEPTH`] guard the
      // array/map (`read_collection`) and tag (`read_tag`) branches apply, so the
      // nested-string bomb fails at the cap with [`DEPTH_ERR`] instead of
      // overflowing the stack. A genuine indefinite string of definite chunks is
      // one level deep and unaffected. A MISSING break runs `read_value` off the
      // box end → `Err("Truncated CBOR data")` (bounded; no infinite loop — the
      // `?` propagates and the top-level loop resyncs / warns).
      if depth + 1 > MAX_CBOR_DEPTH {
        return Err(SmolStr::new_static(DEPTH_ERR));
      }
      let mut acc: Vec<u8> = Vec::new();
      loop {
        match self.read_value(depth + 1)? {
          // A break terminates the indefinite string (`last if not defined $val`).
          None => break,
          Some(CborNode::Bytes(chunk)) => acc.extend_from_slice(&chunk),
          Some(CborNode::Text(chunk)) => acc.extend_from_slice(chunk.as_bytes()),
          // A non-string chunk (`should not happen` in valid C2PA). ExifTool does
          // `$string .= $val` — appending the value's stringification, NOT
          // breaking — then loops on to the break. Append its faithful
          // stringification and continue so the top-level reader does not desync.
          Some(other) => acc.extend_from_slice(stringify_indefinite_chunk(&other).as_bytes()),
        }
      }
      return Ok(Some(if fmt == 2 {
        CborNode::Bytes(acc)
      } else {
        CborNode::Text(crate::convert::fix_utf8(&acc))
      }));
    }
    // Definite length: `$num` bytes. `return ..., 'Truncated CBOR string value'
    // if $pos + $num > $end` (`CBOR.pm:124`).
    let n = usize::try_from(num.unwrap_or(0)).unwrap_or(usize::MAX);
    let Some(slice) = self.data.get(self.pos..self.pos.saturating_add(n)) else {
      return Err(SmolStr::new_static("Truncated CBOR string value"));
    };
    self.pos += n;
    Ok(Some(if fmt == 2 {
      // `$val = \$dat` — a scalar reference (binary), the `(Binary data …)`
      // placeholder. Copy the (box-bounded) bytes; only the length renders.
      CborNode::Bytes(slice.to_vec())
    } else {
      // `$val = $et->Decode($val, 'UTF8')` (`CBOR.pm:146`).
      CborNode::Text(crate::convert::fix_utf8(slice))
    }))
  }

  /// Read a major-4 array / major-5 map (`CBOR.pm:149-194`). A map reads
  /// `2 * $num` items as ordered key/value pairs; an array reads `$num` items.
  /// An indefinite count (`is_indefinite`) reads until a break
  /// (`CBOR.pm:175-177`).
  fn read_collection(
    &mut self,
    fmt: u8,
    num: Option<u64>,
    is_indefinite: bool,
    depth: usize,
  ) -> Result<Option<CborNode>, SmolStr> {
    if depth + 1 > MAX_CBOR_DEPTH {
      return Err(SmolStr::new_static(DEPTH_ERR));
    }
    let is_map = fmt == 5;
    // `$num *= 2` for a hash (key + value per pair, `CBOR.pm:154`).
    let mut remaining: Option<u64> = num.map(|n| if is_map { n.saturating_mul(2) } else { n });
    let mut list: Vec<CborNode> = Vec::new();
    loop {
      // Definite count exhausted (`while ($num)` reaches 0).
      if let Some(0) = remaining {
        break;
      }
      let item = self.read_value(depth + 1)?;
      match item {
        // A break (`undef $val`): allowed only for an indefinite count
        // (`return ... 'Unexpected list terminator' unless $num < 0`,
        // `CBOR.pm:175-178`).
        None => {
          if is_indefinite {
            break;
          }
          return Err(SmolStr::new_static("Unexpected list terminator"));
        }
        Some(node) => list.push(node),
      }
      // `--$num` (only for a definite count; an indefinite one loops to the break).
      if let Some(r) = remaining.as_mut() {
        *r -= 1;
      }
    }
    if is_map {
      // Pair up `[k0, v0, k1, v1, …]` into ordered `(key, value)` entries
      // (`CBOR.pm:185-190`); a trailing unpaired key (odd item count, only via a
      // malformed indefinite map) is dropped, matching `for ($i=0; $i<@list-1;
      // $i+=2)`.
      let mut pairs: Vec<(String, CborNode)> = Vec::with_capacity(list.len() / 2);
      let mut iter = list.into_iter();
      while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
        pairs.push((stringify_key(&key), value));
      }
      Ok(Some(CborNode::Map(pairs)))
    } else {
      Ok(Some(CborNode::Array(list)))
    }
  }

  /// Read a major-6 semantic tag (`CBOR.pm:195-230`): read the next value, then
  /// apply an optional conversion keyed on the tag number `tag`. Tags with no
  /// conversion (all COSE tags, and any unrecognized) pass the wrapped value
  /// through UNCHANGED — so COSE signature structures stay OPAQUE.
  fn read_tag(&mut self, tag: u64, depth: usize) -> Result<Option<CborNode>, SmolStr> {
    if depth + 1 > MAX_CBOR_DEPTH {
      return Err(SmolStr::new_static(DEPTH_ERR));
    }
    // `($val, $err, $pos) = ReadCBORValue(...)` — read the tagged value
    // (`CBOR.pm:209`). A break under a tag is unusual; pass it through.
    let Some(node) = self.read_value(depth + 1)? else {
      return Ok(None);
    };
    Ok(Some(apply_tag(tag, node)))
  }
}

/// Apply a major-6 tag conversion to the wrapped value (`CBOR.pm:212-230`). Only
/// the tags ExifTool converts are handled; every other tag (including the COSE
/// `16`/`17`/`18`/`19`) returns the value UNCHANGED — COSE stays opaque.
fn apply_tag(tag: u64, node: CborNode) -> CborNode {
  match tag {
    // Tag 0: a date/time string (`ConvertXMPDate`, `CBOR.pm:213-215`). Only a
    // non-reference scalar (a text string) is converted.
    0 => match node {
      CborNode::Text(s) => CborNode::SimpleStr(SmolStr::from(convert_xmp_date(&s))),
      other => other,
    },
    // Tag 1: an epoch-based date/time (`ConvertUnixTime($val, 1, $dec)`,
    // `CBOR.pm:216-220`). The `1` is `$toLocal`, so this rendering is in the
    // machine's LOCAL timezone (`+HH:MM` suffix) and is INHERENTLY machine-locale
    // dependent — by design NO golden fixture exercises tag 1 (it would not be
    // byte-stable across machines/CI; the unit tests pin `TZ=UTC`). Only a numeric
    // (`IsFloat`) value is converted (`CBOR.pm:217`); both an integer epoch and a
    // wire `Float` node ARE numeric (Perl `IsFloat` matches an integer string).
    //
    // `CBOR.pm:218` `my $dec = ($val == int($val)) ? undef : 6` — a WHOLE epoch
    // gets the no-fractional render; a FRACTIONAL epoch is `ConvertUnixTime($val,
    // 1, 6)` = six FIXED fractional digits (e.g. `…:30.500000+00:00`), the
    // `$toLocal` fixed-`$dec` form ([`convert_unix_time_local_frac_f64`]). An
    // integer-typed node is always whole, so it never carries a fraction.
    1 => match node {
      CborNode::Uint(n) => CborNode::SimpleStr(SmolStr::from(
        crate::datetime::convert_unix_time_local(n as i64),
      )),
      CborNode::Nint(n) => {
        CborNode::SimpleStr(SmolStr::from(crate::datetime::convert_unix_time_local(n)))
      }
      // `CBOR.pm:217` gates the date conversion on `IsFloat($val)` — a regex on
      // the STRINGIFIED scalar (`ExifTool.pm:5947`), which a non-finite double
      // FAILS: Perl stringifies them as `Inf`/`-Inf`/`NaN`, none of which match
      // (oracle-verified vs bundled 13.59). So a non-finite tag-1 float is LEFT
      // UNCONVERTED — it passes through as the bare major-7 float, rendered by
      // [`node_to_value`] as `TagValue::F64` (the canonical `Inf`/`-Inf`/`NaN`
      // strings, byte-identical to Perl's stringification). Without this guard
      // `NaN` would reach [`convert_unix_time_local_frac_f64`] and fabricate a
      // bogus `aN`-suffixed date; `±Inf` would saturate through the helper.
      CborNode::Float(f) if !f.is_finite() => CborNode::Float(f),
      // `($val == int($val)) ? undef : 6` — a whole-valued (finite) float takes
      // the no-`$dec` (whole-second) render; a fractional one the fixed `$dec = 6`.
      CborNode::Float(f) if f == f.trunc() => CborNode::SimpleStr(SmolStr::from(
        crate::datetime::convert_unix_time_local_f64(f),
      )),
      CborNode::Float(f) => CborNode::SimpleStr(SmolStr::from(
        crate::datetime::convert_unix_time_local_frac_f64(f, 6),
      )),
      other => other,
    },
    // Tags 2/3: positive / negative bignum (`CBOR.pm:221-224`). A byte string is
    // accumulated big-endian into an integer; tag 3 negates. The accumulation is
    // a faithful port of Perl's `$big = 256 * $big + Get8u(...)`: an integer
    // (UV) while it fits, promoting to a double (NV) on overflow (see
    // [`bignum_node`]).
    2 | 3 => match node {
      CborNode::Bytes(bytes) => bignum_node(accumulate_bignum(&bytes), tag == 3),
      other => other,
    },
    // Tags 4/5: decimal fraction / bigfloat (`CBOR.pm:225-230`). An ARRAY of two
    // INTEGERS `[exponent, mantissa]` becomes `mantissa * base ** exponent`
    // (base 10 for tag 4, base 2 for tag 5). The exponent has ALREADY been
    // `-1 * num`-quirked at decode if it was a wire negative.
    4 | 5 => match &node {
      CborNode::Array(items) if items.len() == 2 => {
        match (
          items.first().and_then(int_of),
          items.get(1).and_then(int_of),
        ) {
          (Some(exp), Some(mant)) => {
            let base: f64 = if tag == 4 { 10.0 } else { 2.0 };
            let value = mant as f64 * base.powi(clamp_exp(exp));
            // ExifTool keeps Perl's numeric scalar; the `%.15g`/number gate
            // renders an integral result identically to a bare integer.
            CborNode::Float(value)
          }
          _ => node,
        }
      }
      _ => node,
    },
    // Every other tag (COSE 16/17/18/19, and any unrecognized) — transparent.
    _ => node,
  }
}

/// Decode a single major-7 simple / float value (`CBOR.pm:231-256`). `dat` is
/// the 5-bit additional info, `num` the decoded argument (which, for a `25`/`26`/
/// `27` float, carries the IEEE bits read by [`Reader::read_argument`]). Returns
/// `Ok(None)` for a `break` (`$dat == 31`).
fn read_simple(dat: u8, num: u64) -> Result<Option<CborNode>, SmolStr> {
  if dat == 31 {
    // `undef $val` — break (`CBOR.pm:232-233`).
    return Ok(None);
  }
  if dat < 24 {
    // `$val = $cborType7{$num}` (`CBOR.pm:234-236`): 20 False, 21 True, 22 null,
    // 23 undef; anything else `"Unknown ($val)"` where `$val` was undef ⇒ the
    // literal `Unknown ()` (ExifTool interpolates the undef as empty).
    return Ok(Some(match num {
      20 => CborNode::Bool(false),
      21 => CborNode::Bool(true),
      // `%cborType7{22}` = the literal text `null` (`CBOR.pm:59`), the
      // `MissingTagValue` default rendered as the quoted string `"null"`.
      22 => CborNode::SimpleStr(SmolStr::new_static("null")),
      23 => CborNode::SimpleStr(SmolStr::new_static("undef")),
      _ => CborNode::SimpleStr(SmolStr::new_static("Unknown ()")),
    }));
  }
  match dat {
    // Half-precision float (`CBOR.pm:237-248`) — the faithful buggy formula.
    25 => Ok(Some(CborNode::Float(half_float(num)))),
    // Single-precision float (`GetFloat`, `CBOR.pm:249-250`): `$num` holds the
    // 4 big-endian bytes read by [`Reader::read_argument`].
    26 => Ok(Some(CborNode::Float(f64::from(f32::from_bits(num as u32))))),
    // Double-precision float (`GetDouble`, `CBOR.pm:251-252`).
    27 => Ok(Some(CborNode::Float(f64::from_bits(num)))),
    // `Invalid CBOR type 7 variant $num` (`CBOR.pm:253-254`). (`24` is a
    // "simple value, one byte" the C2PA profile never uses.)
    _ => Err(SmolStr::from(std::format!(
      "Invalid CBOR type 7 variant {num}"
    ))),
  }
}

/// The faithful ExifTool half-precision-float decode (`CBOR.pm:237-248`),
/// reproducing its quirks EXACTLY (oracle-verified vs bundled 13.59):
///
/// ```text
/// my $exp = ($num >> 10) & 0x1f;
/// my $mant = $num & 0x3ff;
/// if ($exp == 0) {
///     $val = $mant ** -24;             # 0**-24 = +Inf; 1**-24 = 1; …
///     $val *= -1 if $num & 0x8000;
/// } elsif (exp != 31) {                # NOTE: `exp` is the Perl builtin → always true
///     $val = ($mant + 1024) ** ($exp - 25);
///     $val *= -1 if $num & 0x8000;
/// } else { … }                         # DEAD — never reached
/// ```
///
/// So a wire half `0x3c00` (true IEEE 1.0) decodes to `1024 ** -10` ≈
/// 7.8886e-31, and `0x7c00` (true +Inf) decodes to `1024 ** 6` ≈ 1.1529e18 (the
/// inf/nan branch is dead because `exp` is Perl's `exp()` function, not the
/// `$exp` variable). The subnormal `$mant ** -24` gives `+Inf` for `$mant == 0`
/// (Perl `0 ** -24`), which renders as the `"Inf"` string.
fn half_float(num: u64) -> f64 {
  let exp = (num >> 10) & 0x1f;
  let mant = (num & 0x3ff) as f64;
  let negative = num & 0x8000 != 0;
  let val = if exp == 0 {
    // `$mant ** -24` — `0f64.powi(-24)` is `+Inf`, `1f64.powi(-24)` is `1.0`.
    mant.powi(-24)
  } else {
    // `($mant + 1024) ** ($exp - 25)` — the always-taken branch (the inf/nan
    // `else` is dead in `CBOR.pm` because `exp != 31` is the builtin `exp(1)`).
    (mant + 1024.0).powi(exp as i32 - 25)
  };
  if negative { -val } else { val }
}

/// `$val = -1 * $num` — the faithful major-1 negative-integer quirk
/// (`CBOR.pm:121`). RFC 8949 encodes a negative as `-1 - n`, but ExifTool
/// computes `-1 * n`, so a wire argument `num` decodes to `-(num)`. A `num`
/// above `i64::MAX` saturates (it cannot arise from a genuine small-int C2PA
/// value; the saturation keeps the conversion total).
fn neg_quirk(num: u64) -> i64 {
  match i64::try_from(num) {
    Ok(n) => n.saturating_neg(),
    Err(_) => i64::MIN,
  }
}

/// `$big = 256 * $big + Get8u($val, $_)` over the bignum byte string
/// (`CBOR.pm:222-223`), reproducing Perl's integer→double promotion EXACTLY.
/// `$big` starts as an integer (UV) and accumulates exactly while every step
/// fits a 64-bit unsigned; the FIRST step that would overflow `u64::MAX`
/// promotes the running total to a double (NV) — `256.0 * big + byte` (Perl
/// computes `256 * $big` as an NV when it overflows, then adds `$byte`) — and
/// all subsequent bytes accumulate as `f64`. So a magnitude `<= u64::MAX` is
/// exact (`Ok`); anything larger is the promoted double (`Err`).
fn accumulate_bignum(bytes: &[u8]) -> Result<u64, f64> {
  let mut int_acc: u64 = 0;
  let mut float_acc: Option<f64> = None;
  for &b in bytes {
    if let Some(f) = float_acc {
      // Already an NV (double) — stay in double arithmetic (`CBOR.pm:223`).
      float_acc = Some(256.0 * f + f64::from(b));
      continue;
    }
    match int_acc
      .checked_mul(256)
      .and_then(|v| v.checked_add(u64::from(b)))
    {
      Some(v) => int_acc = v,
      // UV overflow: Perl promotes `256 * $big` (still the last integer) to an
      // NV, then adds `$byte` — `256.0 * (last int) + byte`.
      None => float_acc = Some(256.0 * (int_acc as f64) + f64::from(b)),
    }
  }
  match float_acc {
    Some(f) => Err(f),
    None => Ok(int_acc),
  }
}

/// Build the [`CborNode`] for a tag-2/3 bignum value (`CBOR.pm:222-224`): the
/// big-endian accumulation (an exact `u64` magnitude, or a promoted `f64`),
/// negated for tag 3 (`$val = $num==2 ? $big : -$big`).
///
/// Faithful to Perl's IV/UV/NV scalar semantics (oracle-verified vs bundled
/// 13.59): a positive bignum that fits a `u64` is the exact integer
/// ([`CborNode::Uint`], which the number gate quotes when `>= 16` digits); a
/// negative bignum whose `-$big` fits an `i64` is the exact [`CborNode::Nint`].
/// ANY larger magnitude — for tag 2 a value above `u64::MAX`, for tag 3 a `-$big`
/// below `i64::MIN` (i.e. a magnitude above `2^63`), or a magnitude already
/// promoted to a double during accumulation — renders as the double-precision
/// `%.15g` float ([`CborNode::Float`]), NOT a decimal string: Perl's `$big` /
/// `-$big` is an NV there, which `EscapeJSON` stringifies as a `%.15g` number.
fn bignum_node(big: Result<u64, f64>, negative: bool) -> CborNode {
  match big {
    // Exact integer magnitude (fit a `u64`).
    Ok(m) => {
      if negative {
        // `-$big`: exact `i64` iff the magnitude is `<= 2^63` (so `-$big >=
        // i64::MIN`); otherwise Perl's `-$big` is an NV (double).
        if m <= (i64::MAX as u64) + 1 {
          // `-(2^63)` is `i64::MIN`; `m <= i64::MAX` negates directly, and the
          // `m == 2^63` boundary maps to `i64::MIN`.
          CborNode::Nint(m.wrapping_neg() as i64)
        } else {
          CborNode::Float(-(m as f64))
        }
      } else {
        CborNode::Uint(m)
      }
    }
    // Promoted double magnitude — render the `%.15g` float (negated for tag 3).
    Err(f) => CborNode::Float(if negative { -f } else { f }),
  }
}

/// The integer value of a [`CborNode`] for the tag-4/5 decimal-fraction /
/// bigfloat `IsInt` check (`CBOR.pm:226-227`). `Some` for an unsigned / negative
/// integer node, `None` otherwise (the conversion then does NOT fire).
fn int_of(node: &CborNode) -> Option<i64> {
  match node {
    CborNode::Uint(n) => i64::try_from(*n).ok(),
    CborNode::Nint(n) => Some(*n),
    _ => None,
  }
}

/// Clamp a tag-4/5 exponent to the `powi` exponent range so the `mantissa *
/// base ** exponent` computation is total (a genuine C2PA decimal fraction has a
/// small exponent; an absurd crafted one saturates to `±i32::MAX`, yielding
/// `0.0`/`Inf` exactly as Perl's `**` would overflow/underflow).
fn clamp_exp(exp: i64) -> i32 {
  if exp > i64::from(i32::MAX) {
    i32::MAX
  } else if exp < i64::from(i32::MIN) {
    i32::MIN
  } else {
    exp as i32
  }
}

/// `ConvertXMPDate($val)` (`XMP.pm:3383-3393`) — reformat an ISO-8601 date-time
/// string into ExifTool's `YYYY:MM:DD HH:MM[:SS][tz]` form. A pure string
/// transform (locale-INDEPENDENT, so a tag-0 fixture is byte-stable):
///
/// 1. `^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$` ⇒
///    `"$1:$2:$3 $4$5$6"` (the dashes between Y/M/D become colons, the `T`/space
///    becomes a space, optional seconds + timezone preserved).
/// 2. else, a bare `^(\d{4})(-\d{2}){0,2}` date ⇒ `tr/-/:/` (all dashes → colons).
/// 3. else unchanged.
fn convert_xmp_date(val: &str) -> String {
  // Full date-time form: `YYYY-MM-DD[T ]HH:MM[:SS][ ]<tz>`.
  if let Some(parsed) = parse_xmp_datetime(val) {
    return parsed;
  }
  // Bare date `YYYY`, `YYYY-MM`, or `YYYY-MM-DD` (optionally with trailing junk):
  // translate every `-` to `:`.
  if is_bare_xmp_date(val) {
    return val
      .chars()
      .map(|c| if c == '-' { ':' } else { c })
      .collect();
  }
  String::from(val)
}

/// Match the `ConvertXMPDate` full date-time regex
/// (`^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$`) and rebuild as
/// `"$1:$2:$3 $4$5$6"`. `None` if the whole string does not match (the caller
/// falls back to the bare-date / identity branches).
fn parse_xmp_datetime(val: &str) -> Option<String> {
  let b = val.as_bytes();
  // `(\d{4})-(\d{2})-(\d{2})` then `[T ]`.
  let year = take_digits(b, 0, 4)?;
  let m1 = if b.get(4) == Some(&b'-') {
    5
  } else {
    return None;
  };
  let month = take_digits(b, m1, 2)?;
  let m2 = if b.get(m1 + 2) == Some(&b'-') {
    m1 + 3
  } else {
    return None;
  };
  let day = take_digits(b, m2, 2)?;
  let mut i = m2 + 2;
  match b.get(i) {
    Some(&c) if c == b'T' || c == b' ' => i += 1,
    _ => return None,
  }
  // `(\d{2}:\d{2})`.
  let hh = take_digits(b, i, 2)?;
  if b.get(i + 2) != Some(&b':') {
    return None;
  }
  let mm = take_digits(b, i + 3, 2)?;
  i += 5;
  // `(:\d{2})?` — optional `:SS`.
  let mut secs = String::new();
  if b.get(i) == Some(&b':')
    && let Some(ss) = take_digits(b, i + 1, 2)
  {
    secs = std::format!(":{ss}");
    i += 3;
  }
  // `\s*` — skip whitespace before the timezone.
  while matches!(b.get(i), Some(c) if c.is_ascii_whitespace()) {
    i += 1;
  }
  // `(\S*)$` — the rest is the timezone (no internal whitespace allowed by `\S*`,
  // and it must reach the end). A space inside the remainder fails the `$` anchor.
  let tz = val.get(i..)?;
  if tz.bytes().any(|c| c.is_ascii_whitespace()) {
    return None;
  }
  Some(std::format!("{year}:{month}:{day} {hh}:{mm}{secs}{tz}"))
}

/// Whether `val` starts with the bare-date shape `^(\d{4})(-\d{2}){0,2}`
/// (4 digits, then up to two `-\d\d` groups) — the second `ConvertXMPDate`
/// branch's `tr/-/:/` trigger (`XMP.pm:3389`). The Perl regex is UNANCHORED at
/// the end, so trailing characters after the optional groups are allowed.
fn is_bare_xmp_date(val: &str) -> bool {
  let b = val.as_bytes();
  if take_digits(b, 0, 4).is_none() {
    return false;
  }
  // Up to two further `-\d\d` groups; the match is greedy but `{0,2}` so it
  // simply needs the 4-digit lead — the `tr` then converts whatever dashes exist.
  true
}

/// Read exactly `n` ASCII digits of `b` starting at `start`, returning them as a
/// `&str` slice, or `None` if fewer than `n` digits are present.
fn take_digits(b: &[u8], start: usize, n: usize) -> Option<&str> {
  let slice = b.get(start..start + n)?;
  if slice.iter().all(u8::is_ascii_digit) {
    core::str::from_utf8(slice).ok()
  } else {
    None
  }
}

/// Stringify a CBOR map key for use as a tag name (top level) or struct key
/// (nested). CBOR keys are usually text; ExifTool stringifies whatever scalar
/// the key decoded to (`$$val{$tag}` keying, `CBOR.pm:188`). A text key is its
/// text; an integer key its decimal (so a COSE integer header key `1` →
/// `"1"`); a float its `%.15g`; a boolean `true`/`false`; a `null`/`undef`/date
/// its string. A byte-string or container key (not a hash-key scalar in valid
/// C2PA) renders its placeholder / a structural marker — these never arise in a
/// genuine document.
fn stringify_key(node: &CborNode) -> String {
  match node {
    CborNode::Text(s) => s.clone(),
    CborNode::Uint(n) => n.to_string(),
    CborNode::Nint(n) => n.to_string(),
    CborNode::Float(f) => crate::value::format_g(*f, 15),
    CborNode::Bool(b) => String::from(if *b { "true" } else { "false" }),
    CborNode::SimpleStr(s) => String::from(s.as_str()),
    CborNode::Bytes(bytes) => String::from(crate::value::binary_placeholder(bytes.len() as u64)),
    // A container key (never in valid C2PA) — a stable structural marker.
    CborNode::Array(_) | CborNode::Map(_) => String::from("[structure]"),
  }
}

/// Stringify a NON-string chunk encountered inside an indefinite-length
/// byte/text string (`$string .= $val`, `CBOR.pm:133`). ExifTool's
/// indefinite-string loop does not verify a chunk was a string (the `CBOR.pm:132`
/// comment) and concatenates the chunk's value, so a crafted indefinite string
/// can carry e.g. a `uint`/`nint` chunk. Faithful for the DETERMINISTIC scalar
/// cases, which is what a crafted payload realistically holds: a `uint`/`nint`
/// is its decimal (`uint(1)` → `"1"`, the `-1*num` `nint` → `"-6"`); a boolean
/// `true`/`false`; a `null`/`undef`/converted-date its string; a float its
/// `%.15g`. ExifTool's value for a BYTE-string or CONTAINER chunk is a Perl
/// reference whose default stringification (`SCALAR(0x…)` / `ARRAY(0x…)` /
/// `HASH(0x…)`) is a NON-deterministic pointer address — un-reproducible and
/// never present in a genuine C2PA document — so we render the same stable
/// placeholder [`stringify_key`] uses for those (the value, not its address).
/// The point of porting the loop faithfully is that it CONSUMES THROUGH THE
/// BREAK (no top-level desync), not that a malformed non-string chunk matches
/// bundled's pointer text byte-for-byte.
fn stringify_indefinite_chunk(node: &CborNode) -> String {
  stringify_key(node)
}
