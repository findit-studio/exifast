//! VALUE-semantic JSON equality, ignoring object key order, for comparing
//! `exifast` output to ExifTool golden (spec §4: object key order is *not*
//! significant, but the key *multiset* must match and every scalar must be
//! equal **by value**; array element order *is* significant).
//!
//! ## Why value-semantic, not byte-exact
//!
//! We do NOT reproduce ExifTool's exact scalar *tokens*. `0.0` and
//! `0.00000000` are the same JSON number; `3.4e+38` and `3.4e38` are the same
//! value; a bare `123` and a quoted numeric string `"123"` carry the same
//! value. Both spellings are valid JSON for the same value, so the token
//! *style* is irrelevant — exactly the same principle as "JSON key order
//! doesn't matter". The serializer therefore uses STANDARD `serde_json`
//! scalar formatting (it does not chase ExifTool's `sprintf` tokens), and this
//! comparator compares by VALUE, not by lexeme.
//!
//! ## The numeric-equality rules
//!
//! - **Numbers.** Two scalars are numeric-equal if both parse as the same
//!   numeric value. Integer literals that fit `i128`/`u128` compare exactly as
//!   integers (so a huge `18446744073709551615` u64 stays exact); a value that
//!   is not an integer literal on either side falls back to `f64` (so
//!   `0.0 == 0.00000000` and `3.40282366920938e+38 == 3.40282366920938e38`).
//! - **String ↔ number coercion.** A JSON *string* whose entire content parses
//!   as a number is numeric-comparable to a JSON *number* of the same value
//!   (ExifTool's `EscapeJSON` number-gate blurs these — a PrintConv-`sprintf`'d
//!   `"3.4e+38"` string equals a bare `3.4e38`). So `"123"` value-equals `123`
//!   and `"0.00000000"` value-equals `0.0`.
//! - **Non-numeric strings.** Compared exactly (escape/lexeme-exact). `"NaN"`,
//!   `"Inf"`, `"-Inf"` are non-numeric strings ⇒ exact compare (both sides emit
//!   the same titlecase via `value::perl_nonfinite_str`, so they match).
//!
//! ## Structure rules (unchanged)
//!
//! The comparison is done over `serde_json::value::RawValue`: objects are
//! parsed into an ORDERED `Vec<(String, &RawValue)>` (a serde visitor over
//! `MapAccess`) that PRESERVES duplicate keys, then compared as a *multiset*
//! of `(key, value)` pairs — key ORDER is insensitive but a repeated key is
//! significant, so `{"A":1,"A":2}` ≠ `{"A":1}` (this is what catches the
//! ExifTool `%noDups` regression class; a `serde_json::Map` / `BTreeMap` would
//! silently collapse the duplicate and mask it). Arrays are recursed
//! element-wise, order-significant.

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

/// A human-readable description of the first place two JSON documents differ.
#[derive(Debug, PartialEq, Eq)]
pub struct Mismatch(String);

impl Mismatch {
  /// Construct a `Mismatch` from a message string.
  #[must_use]
  #[inline(always)]
  pub fn new(message: impl Into<String>) -> Self {
    Self(message.into())
  }

  /// The mismatch description message (`&str` view of the owned `String`
  /// field — never expose `&String`, §3).
  #[must_use]
  #[inline(always)]
  pub fn message(&self) -> &str {
    &self.0
  }
}

/// Compare two JSON texts as the 1:1 bar requires: object key order is NOT
/// significant (but the key *multiset* must match), array element order IS
/// significant, and every scalar is compared by VALUE (so `1 == 1.0`,
/// `0.50 == 0.5`, `"123" == 123`, `3.4e+38 == 3.4e38`; non-numeric strings are
/// still escape-exact, so the literal `"A"` ≠ the escaped `"A"`). Returns
/// the first `Mismatch`.
pub fn json_equivalent(actual: &str, golden: &str) -> Result<(), Mismatch> {
  json_equivalent_with(actual, golden, false)
}

/// TOKEN-EXACT (strict) variant of [`json_equivalent`]: identical structure
/// rules (object key order insensitive but multiset-significant, array order
/// significant), and numeric VALUE-style insensitivity is still kept *within
/// one JSON type* (`2 == 2.0`, `0.50 == 0.5`, `3.4e+38 == 3.4e38`), BUT a
/// quoted numeric string and the bare number of the same value are NO LONGER
/// equal — the JSON *type* must match (Contract B / #197). So `"2"` ≠ `2` and
/// `"0.0"` ≠ `0.0`, reproducing ExifTool's exact `EscapeJSON` number-vs-string
/// typing. Non-numeric strings stay escape-exact exactly as in value mode.
///
/// Opt-in: callers that want the documented value-semantic behaviour keep using
/// [`json_equivalent`]; this is the comparator the token-exact conformance pass
/// uses. Returns the first [`Mismatch`].
pub fn json_equivalent_strict(actual: &str, golden: &str) -> Result<(), Mismatch> {
  json_equivalent_with(actual, golden, true)
}

/// Shared entry point for [`json_equivalent`] (value-semantic, `strict=false`)
/// and [`json_equivalent_strict`] (token-exact, `strict=true`). The only
/// behavioural difference is in the scalar arm: `strict` rejects a quoted-vs-
/// bare type mismatch even when the numeric values coincide.
fn json_equivalent_with(actual: &str, golden: &str, strict: bool) -> Result<(), Mismatch> {
  let a: &RawValue = serde_json::from_str(actual)
    .map_err(|e| Mismatch::new(format!("actual is invalid JSON: {e}")))?;
  let g: &RawValue = serde_json::from_str(golden)
    .map_err(|e| Mismatch::new(format!("golden is invalid JSON: {e}")))?;
  cmp(a, g, "$", strict)
}

/// An object parsed as ORDERED `(key, value)` pairs, preserving duplicate
/// keys (a `serde_json::Map`/`BTreeMap` would silently collapse them, masking
/// the ExifTool `%noDups` regression class). Keys are decoded to `String`
/// (escape-correct); values borrow the source text as `&'de RawValue` so
/// recursion stays zero-copy and lexeme-exact.
struct OrderedObject<'de>(Vec<(String, &'de RawValue)>);

impl<'de> serde::Deserialize<'de> for OrderedObject<'de> {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    struct ObjVisitor<'de> {
      marker: std::marker::PhantomData<&'de ()>,
    }
    impl<'de> Visitor<'de> for ObjVisitor<'de> {
      type Value = OrderedObject<'de>;
      fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
      }
      fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
      where
        M: MapAccess<'de>,
      {
        let mut pairs: Vec<(String, &'de RawValue)> = Vec::new();
        // `next_entry` over (String key, borrowed RawValue value)
        // yields EVERY entry in source order, duplicates included
        // (serde_json's map deserializer does not dedup the stream).
        while let Some((k, v)) = map.next_entry::<String, &'de RawValue>()? {
          pairs.push((k, v));
        }
        Ok(OrderedObject(pairs))
      }
    }
    deserializer.deserialize_map(ObjVisitor {
      marker: std::marker::PhantomData,
    })
  }
}

/// Render the key list of an ordered object, annotating any key that occurs
/// more than once as `"k"×N` so a duplicate-key mismatch is self-describing
/// in the `Mismatch` message (the ExifTool `%noDups` regression surfaces as
/// a repeated key on exactly one side).
fn keys_with_dups(pairs: &[(String, &RawValue)]) -> Vec<String> {
  let mut out: Vec<String> = Vec::new();
  for (k, _) in pairs {
    let n = pairs.iter().filter(|(o, _)| o == k).count();
    let label = if n > 1 {
      format!("{k:?}×{n}")
    } else {
      format!("{k:?}")
    };
    if !out.contains(&label) {
      out.push(label);
    }
  }
  out
}

/// JSON value shape, used only to decide how to recurse on a `RawValue`.
enum Kind {
  Object,
  Array,
  Scalar,
}

/// Classify a `RawValue` by its first non-whitespace byte. serde trims the
/// framing whitespace around a nested `RawValue`, but a leading `{`/`[` is
/// preserved, so this is sufficient to dispatch.
fn kind_of(r: &RawValue) -> Kind {
  match r.get().trim_start().as_bytes().first() {
    Some(b'{') => Kind::Object,
    Some(b'[') => Kind::Array,
    _ => Kind::Scalar,
  }
}

/// A scalar `RawValue`'s payload, with any surrounding JSON string quoting
/// removed: `("123", true)` for the JSON string `"123"`, `("123", false)` for
/// the bare number `123`. Returns `None` if the lexeme is not a plain JSON
/// string (the un-decoded inner text is returned for strings — escape-exact
/// comparison of NON-numeric strings relies on the raw inner bytes).
fn scalar_payload(r: &RawValue) -> (&str, bool) {
  let s = r.get().trim();
  match (s.strip_prefix('"'), s.strip_suffix('"')) {
    // A genuine JSON string is `"…"` with at least the two quotes. (`len >= 2`
    // guards the single `"` lexeme, which serde_json would never hand us as a
    // valid scalar anyway.)
    (Some(_), Some(_)) if s.len() >= 2 => (&s[1..s.len() - 1], true),
    _ => (s, false),
  }
}

/// Parse a scalar's *text* (already unquoted by [`scalar_payload`]) as a number
/// for value comparison. Returns `None` for any text that is not a complete
/// numeric literal (so non-numeric strings, `true`/`false`/`null`, `"NaN"`,
/// `"Inf"`, empty, etc. fall through to exact textual comparison).
///
/// Integer literals (no `.`, `e`, or `E`) that fit `i128`/`u128` are kept as
/// EXACT integers so a huge `18446744073709551615` u64 never loses precision;
/// everything else parses as `f64`.
fn parse_number(text: &str) -> Option<NumVal> {
  if text.is_empty() {
    return None;
  }
  let is_integer_literal = !text.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
  if is_integer_literal {
    if let Ok(i) = text.parse::<i128>() {
      return Some(NumVal::Int(i));
    }
    if let Ok(u) = text.parse::<u128>() {
      return Some(NumVal::Uint(u));
    }
    // Out of even u128 range (>39 digits): fall through to f64 below.
  }
  // `f64::from_str` accepts `inf`/`nan`; ExifTool never emits those bare and
  // our serializer quotes non-finite as the titlecase `Inf`/`NaN` *string*
  // (handled by exact text compare), so reject non-finite here to keep
  // `parse_number` strictly "a finite numeric value".
  match text.parse::<f64>() {
    Ok(f) if f.is_finite() => Some(NumVal::Float(f)),
    _ => None,
  }
}

/// A parsed numeric value used for value-equality of scalars. Integers keep
/// full `i128`/`u128` precision; non-integers (or out-of-integer-range values)
/// are `f64`.
#[derive(Clone, Copy)]
enum NumVal {
  Int(i128),
  Uint(u128),
  Float(f64),
}

impl NumVal {
  /// Value-equality across representations: same-kind integers compare
  /// exactly; an `Int`/`Uint` pair compares exactly via `i128`↔`u128`.
  ///
  /// An `Int`/`Float` (or `Uint`/`Float`) pair is the subtle case. The naive
  /// `as_f64() == as_f64()` fallback silently collapses any two integers that
  /// round to the same `f64` — e.g. `9007194254740993` and `…992.0` both become
  /// the same `f64` above 2^53, so a real off-by-one mismatch reads EQUAL. So
  /// the float must be integer-valued AND exactly representable as the integer
  /// type ([`f_as_exact_i128`] / [`f_as_exact_u128`] applies a range-check
  /// BEFORE the cast — see R2-F3 — to keep `2^127.0` from saturating to
  /// `i128::MAX` and falsely matching `i128::MAX (Int)`). Any out-of-range or
  /// fractional float returns FALSE: a NumVal::Int (which is by definition an
  /// exact integer literal) cannot value-equal a non-integer or out-of-i128
  /// f64; falling back to `as f64` would just re-introduce the precision-loss
  /// false-positive R1-F3 fixed at 2^53 and R2-F3 fixed at 2^127.
  ///
  /// `(Float, Float)` keeps `f64` comparison: both sides are `f64`-derived, so
  /// this is formatting-insensitive (`0.0`==`0.00000000`, `3.4e+38`==`3.4e38`).
  fn value_eq(self, other: NumVal) -> bool {
    match (self, other) {
      (NumVal::Int(a), NumVal::Int(b)) => a == b,
      (NumVal::Uint(a), NumVal::Uint(b)) => a == b,
      // `i128` spans all of `u128`'s representable-as-i128 range; a negative
      // i128 can never equal a u128, and a non-negative i128 maps losslessly.
      (NumVal::Int(i), NumVal::Uint(u)) | (NumVal::Uint(u), NumVal::Int(i)) => {
        u128::try_from(i).is_ok_and(|i| i == u)
      }
      (NumVal::Int(i), NumVal::Float(f)) | (NumVal::Float(f), NumVal::Int(i)) => {
        // R2-F3: integer-valued → range-check → cast → exact integer compare.
        // If the float is out of i128 range (or fractional), it cannot
        // represent the same integer value, so report UNEQUAL — do NOT fall
        // back to `as f64`, that was the saturation hole Codex caught.
        f_as_exact_i128(f).is_some_and(|fi| i == fi)
      }
      (NumVal::Uint(u), NumVal::Float(f)) | (NumVal::Float(f), NumVal::Uint(u)) => {
        // Symmetric to the Int/Float arm — see comment above.
        f_as_exact_u128(f).is_some_and(|fu| u == fu)
      }
      (NumVal::Float(a), NumVal::Float(b)) => a == b,
    }
  }
}

/// If `f` is integer-valued AND inside the `i128` range, return that exact
/// `i128`. Otherwise `None` — the caller then reports the values UNEQUAL (do
/// NOT fall back to `as f64`; that is the mask Codex caught in R2-F3).
///
/// **Why the range-check must precede the cast.** Rust's `f64 as i128` cast
/// is SATURATING (`-inf`/below-MIN → `i128::MIN`; `inf`/above-MAX →
/// `i128::MAX`; NaN → 0). And `i128::MAX as f64` rounds UP to `2^127` —
/// which is exactly the f64 literal `170141183460469231731687303715884105728.0`.
/// A naïve "round-trip" `(f as i128 as f64) == f` therefore looks valid for
/// `f = 2^127`: cast saturates to `i128::MAX`, the back-cast rounds UP to
/// the same `2^127`, the check passes, and we hand back `i128::MAX` for a
/// float that does not represent any i128. The integer comparator then reads
/// `i128::MAX (Int) == 2^127.0 (Float)` as TRUE — a false-positive.
///
/// The half-open range `[-2^127, 2^127)` is exact in f64 (both endpoints are
/// powers of two), so a literal-bound compare is exact and saturation-free.
/// `f.fract() == 0.0` is checked FIRST so a fractional in-range float
/// (e.g. `1.5`) also exits `None` cleanly.
fn f_as_exact_i128(f: f64) -> Option<i128> {
  if f.fract() != 0.0 {
    return None;
  }
  // Half-open: `f >= -2^127` AND `f < 2^127`. Reject the upper bound — that
  // f64 value cannot represent any i128 (i128::MAX = 2^127 - 1). Both
  // literals are exact f64 (powers of two), so no rounding hides here.
  if !(f >= -170_141_183_460_469_231_731_687_303_715_884_105_728.0_f64
    && f < 170_141_183_460_469_231_731_687_303_715_884_105_728.0_f64)
  {
    return None;
  }
  // Now safe: `f` is integer-valued AND inside [-2^127, 2^127). The cast is
  // exact (any in-range integer-valued f64 round-trips losslessly through
  // i128); the assert-style check guards future-proofs.
  let i = f as i128;
  debug_assert_eq!(i as f64, f, "in-range integer-valued f64 must round-trip");
  Some(i)
}

/// `u128` analogue of [`f_as_exact_i128`]. Same range-before-cast discipline
/// (the saturation hole is symmetric: `u128::MAX as f64` rounds UP to
/// `2^128`, masking a `2^128.0` float as equal to `u128::MAX`). Rejects
/// fractional `f`, negative `f`, and `f >= 2^128`. The half-open bounds
/// `[0, 2^128)` are exact in f64 (both powers of two).
fn f_as_exact_u128(f: f64) -> Option<u128> {
  if f.fract() != 0.0 {
    return None;
  }
  if !(f >= 0.0_f64 && f < 340_282_366_920_938_463_463_374_607_431_768_211_456.0_f64) {
    return None;
  }
  let u = f as u128;
  debug_assert_eq!(u as f64, f, "in-range integer-valued f64 must round-trip");
  Some(u)
}

/// VALUE-equality of two scalar `RawValue`s (numbers, strings, `true`/`false`/
/// `null`). The rule the module doc describes:
///
/// 1. If BOTH sides parse as a finite number (a bare number, OR a quoted string
///    whose entire content is numeric), compare by numeric value.
/// 2. Otherwise compare the scalars' raw lexeme text byte-for-byte — so
///    non-numeric strings stay escape-exact, and `true`/`null`/`"NaN"` match
///    only their identical spelling.
fn scalar_value_eq(a: &RawValue, g: &RawValue, strict: bool) -> bool {
  let (at, a_quoted) = scalar_payload(a);
  let (gt, g_quoted) = scalar_payload(g);
  // TOKEN-EXACT (strict): numeric VALUE-style insensitivity (`2.0` == `2`,
  // `0.50` == `0.5`) is allowed ONLY between two BARE numbers. When EITHER side
  // is QUOTED, the comparison falls through to the exact-lexeme path below:
  //  - quoted vs bare ⇒ a JSON *type* mismatch (`"2"` ≠ `2`, Contract B);
  //  - quoted vs quoted ⇒ compared as EXACT STRINGS, so a value ExifTool
  //    intentionally quotes (a leading-zero string `"01"`, an over-cap integer)
  //    is NOT normalized to a differently-spelled quoted numeric of the same
  //    value (`"01"` ≠ `"1"`). Only the strict path is affected — value mode
  //    keeps full numeric coercion regardless of quoting.
  let allow_numeric = !strict || (!a_quoted && !g_quoted);
  if allow_numeric && let (Some(an), Some(gn)) = (parse_number(at), parse_number(gt)) {
    return an.value_eq(gn);
  }
  // Non-numeric (or, under strict, any quoted side): exact lexeme compare.
  // Using the raw `get()` keeps a bare `123` distinct from the string `"abc"`,
  // a quoted `"NaN"` matching only another quoted `"NaN"`, and (under strict)
  // `"01"` distinct from `"1"`.
  a.get().trim() == g.get().trim()
}

/// A normal form of a SCALAR under our value-equivalence, used only as a sort
/// key when pairing duplicate object keys (`canonical`). The invariant the
/// dup-pairing sort relies on: `scalar_value_eq(a, g, strict)` ⟺
/// `canonical_scalar(a, strict) == canonical_scalar(g, strict)` — two scalars
/// that are value-equal MUST map to the same string, else the sort could
/// mis-rank value-equal-but-differently-spelled duplicates against a neighbor
/// and report a false mismatch. The numeric key therefore derives from the
/// SAME exact-value notion `scalar_value_eq` uses (every integer-valued number
/// folds to one `#i<decimal>` key); non-numbers keep their raw text.
///
/// `strict` mirrors [`scalar_value_eq`]'s typing: under strict, a QUOTED scalar
/// is canonicalized by its EXACT quoted lexeme (the `q:`-prefixed `None` arm),
/// never collapsed to a bare numeric form — otherwise the dup-pairing sort
/// could not separate a quoted `"1"` from a bare `1` (they are NOT strict-equal
/// yet would share a numeric key), mispairing a reordered quoted/bare duplicate
/// into a false mismatch. Only two BARE numbers share a numeric key under
/// strict; in value mode the quoting is irrelevant (full numeric collapse).
fn canonical_scalar(r: &RawValue, strict: bool) -> String {
  let (text, quoted) = scalar_payload(r);
  // Under strict a quoted scalar must NOT take the numeric key — its EXACT
  // quoted lexeme is the key, tagged `q:` so it can never alias a bare number's
  // `#…` key (or a bare non-number's plain text).
  if strict && quoted {
    return format!("q:{}", r.get().trim());
  }
  // The numeric key must derive from the SAME exact-value notion
  // `scalar_value_eq`/`NumVal::value_eq` uses, so canonicalization ⇔ equality
  // holds for ALL numeric pairs: `scalar_value_eq(a,b)` ⟺
  // `canonical_scalar(a) == canonical_scalar(b)` for numbers, in both modes.
  // `value_eq` treats a bare integer EQUAL to an integer-valued float that
  // recovers to the same integer via `f_as_exact_i128`/`f_as_exact_u128`, so the
  // canonical key folds EVERY integer-valued number (`Int`/`Uint`, OR a `Float`
  // that recovers exactly) onto one `#i<exact-integer-decimal>` key. A keying by
  // the float's `{}` text would diverge from the int's decimal — `1e23` displays
  // `100000000000000000000000` but recovers to the integer `99999999999999991611392`
  // (R3), and `-0.0`/`0.0` both recover to `0` (R2, now subsumed: the `±0.0`
  // case falls out of the exact-integer path). A genuinely non-integer (or
  // out-of-u128-range) float keys by its f64 `{}` form, tagged `#f`: equal-value
  // spellings (`1.5`==`1.50`==`1.5e0`) share one f64 ⇒ one key, matching
  // `value_eq`'s raw `f64 ==`. The `#i`/`#f` tags can never alias each other, a
  // bare non-number's raw text (`true`/`null`, never `#`-prefixed), or — under
  // strict — a quoted scalar's `q:` key. This is a SORT KEY only;
  // `scalar_value_eq` remains the verdict.
  match parse_number(text) {
    Some(NumVal::Int(i)) => format!("#i{i}"),
    Some(NumVal::Uint(u)) => format!("#i{u}"),
    Some(NumVal::Float(f)) => {
      if let Some(i) = f_as_exact_i128(f) {
        format!("#i{i}")
      } else if let Some(u) = f_as_exact_u128(f) {
        // Positive integer-valued floats above i128 but within u128 (mirrors the
        // `Uint`/`Float` `value_eq` arm), e.g. a `3.4e38`-magnitude whole number.
        format!("#i{u}")
      } else {
        // Genuinely fractional, or out of u128 range (then a bare integer literal
        // of the same magnitude is itself parsed as a `Float`, so both sides key
        // here identically). `{}` is deterministic per f64 value.
        format!("#f{f}")
      }
    }
    None => r.get().trim().to_string(),
  }
}

/// A normal form of a value under our equivalence (object key order is
/// insensitive, array order is significant, scalars are byte-exact). Two
/// values have equal canonical text **iff** they are `cmp`-equivalent, so
/// it is a correct sort key for pairing duplicate object keys whose values
/// are equivalent but textually reordered: a raw-byte sort can otherwise
/// mispair them and report a false mismatch. The recursive `cmp` remains
/// the source of truth — this only fixes the *pairing order*, never the
/// verdict, so byte-exact scalars / array order / dup cardinality stand.
fn canonical(r: &RawValue, strict: bool) -> String {
  match kind_of(r) {
    Kind::Object => {
      // Recurse, then sort entries by (key, canonical value),
      // KEEPING duplicates so cardinality stays significant (the
      // ExifTool `%noDups` regression class).
      let mut entries: Vec<(String, String)> = match serde_json::from_str(r.get()) {
        Ok(OrderedObject(p)) => p
          .into_iter()
          .map(|(k, v)| (k, canonical(v, strict)))
          .collect(),
        Err(_) => return r.get().to_string(),
      };
      entries.sort();
      let mut s = String::from("{");
      for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
          s.push(',');
        }
        // `{k:?}` is the JSON-escaped key; `key:val` is unambiguous.
        s.push_str(&format!("{k:?}:{v}"));
      }
      s.push('}');
      s
    }
    Kind::Array => {
      // Array order IS significant: canonicalize elements in place.
      let items: Vec<Box<RawValue>> = match serde_json::from_str(r.get()) {
        Ok(v) => v,
        Err(_) => return r.get().to_string(),
      };
      let mut s = String::from("[");
      for (i, it) in items.iter().enumerate() {
        if i > 0 {
          s.push(',');
        }
        s.push_str(&canonical(it, strict));
      }
      s.push(']');
      s
    }
    // Scalar: a VALUE-normalized form so value-equal-but-differently-spelled
    // scalars (`1` vs `1.0`, and — value mode only — `"123"` vs `123`) sort to
    // the same rank for dup-pairing. Under `strict` a quoted scalar keeps its
    // exact lexeme so it never aliases a bare number. `scalar_value_eq` remains
    // the actual verdict.
    Kind::Scalar => canonical_scalar(r, strict),
  }
}

fn cmp(a: &RawValue, g: &RawValue, path: &str, strict: bool) -> Result<(), Mismatch> {
  match (kind_of(a), kind_of(g)) {
    (Kind::Object, Kind::Object) => {
      // Parse as ORDERED (key, value) pairs preserving duplicate keys.
      let OrderedObject(mut ap) = serde_json::from_str(a.get())
        .map_err(|e| Mismatch::new(format!("{path}: actual object invalid: {e}")))?;
      let OrderedObject(mut gp) = serde_json::from_str(g.get())
        .map_err(|e| Mismatch::new(format!("{path}: golden object invalid: {e}")))?;
      // Object key ORDER is insensitive but DUPLICATES are significant:
      // compare as a MULTISET of (key, raw-value-lexeme) pairs. Sort
      // both sides by (key, raw value bytes) and compare element-wise;
      // a dup-free side vs a dup-bearing side always differs in
      // cardinality, so `{"A":1,"A":2}` ≠ `{"A":1}` (and ≠ `{"A":2}`).
      if ap.len() != gp.len() {
        return Err(Mismatch::new(format!(
          "{path}: object key multiset differs (count {} != {})\
                     \n  actual: {:?}\n  golden: {:?}",
          ap.len(),
          gp.len(),
          keys_with_dups(&ap),
          keys_with_dups(&gp),
        )));
      }
      // Pair entries for the multiset compare by (key, CANONICAL
      // value). A raw-byte value sort can mispair duplicate keys
      // whose values are equivalent-but-reordered objects (a false
      // mismatch); the canonical form is invariant under our
      // equivalence, so equivalent values sort to the same rank.
      ap.sort_by_cached_key(|e| (e.0.clone(), canonical(e.1, strict)));
      gp.sort_by_cached_key(|e| (e.0.clone(), canonical(e.1, strict)));
      for ((ak, av), (gk, gv)) in ap.iter().zip(&gp) {
        if ak != gk {
          return Err(Mismatch::new(format!(
            "{path}: object key multiset differs\n  actual: {:?}\n  golden: {:?}",
            keys_with_dups(&ap),
            keys_with_dups(&gp),
          )));
        }
        // Same key (and same rank after the (key,value) sort): recurse
        // so the precise first scalar-mismatch path is still reported.
        cmp(av, gv, &format!("{path}.{ak}"), strict)?;
      }
      Ok(())
    }
    (Kind::Array, Kind::Array) => {
      let aa: Vec<Box<RawValue>> = serde_json::from_str(a.get())
        .map_err(|e| Mismatch::new(format!("{path}: actual array invalid: {e}")))?;
      let ga: Vec<Box<RawValue>> = serde_json::from_str(g.get())
        .map_err(|e| Mismatch::new(format!("{path}: golden array invalid: {e}")))?;
      if aa.len() != ga.len() {
        return Err(Mismatch::new(format!(
          "{path}: array length {} != {}",
          aa.len(),
          ga.len()
        )));
      }
      for (i, (x, y)) in aa.iter().zip(&ga).enumerate() {
        cmp(x, y, &format!("{path}[{i}]"), strict)?;
      }
      Ok(())
    }
    // Scalars (and shape-mismatched pairs): compare by VALUE
    // ([`scalar_value_eq`]) — numbers (and numeric strings) numeric-equal,
    // non-numeric strings escape-exact, `true`/`null`/`"NaN"` spelling-exact.
    // For a shape mismatch (e.g. object vs array) neither side parses as a
    // number and the raw texts differ, so this still reports correctly.
    _ => {
      if scalar_value_eq(a, g, strict) {
        Ok(())
      } else {
        Err(Mismatch::new(format!(
          "{path}: value differs\n  actual: {}\n  golden: {}",
          a.get(),
          g.get()
        )))
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn identical_is_ok() {
    assert!(json_equivalent(r#"[{"a":1,"b":2}]"#, r#"[{"a":1,"b":2}]"#).is_ok());
  }

  #[test]
  fn strict_mode_distinguishes_number_from_string() {
    // TOKEN-EXACT (strict) mode: a quoted numeric string is NOT the bare number
    // of the same value — the JSON *type* differs (Contract B).
    assert!(json_equivalent_strict(r#"{"X":"2"}"#, r#"{"X":2}"#).is_err());
    // Same type (both bare numbers) still matches — and numeric VALUE-style
    // insensitivity inside one type is preserved (`2` == `2.0`).
    assert!(json_equivalent_strict(r#"{"X":2}"#, r#"{"X":2}"#).is_ok());
    // value-semantic mode still coerces (unchanged):
    assert!(json_equivalent(r#"{"X":"2"}"#, r#"{"X":2}"#).is_ok());
  }

  #[test]
  fn strict_mode_compares_two_quoted_strings_exactly() {
    // FINDING 1 (Codex): in STRICT mode two QUOTED strings must compare as
    // EXACT strings, NOT numerically — so a leading-zero / out-of-gate value
    // ExifTool intentionally quotes (`"01"`, an over-cap integer) is NOT equal
    // to a differently-spelled quoted numeric of the same value (`"1"`). Only
    // two BARE numbers keep style-insensitivity.
    assert!(json_equivalent_strict(r#"{"X":"01"}"#, r#"{"X":"1"}"#).is_err());
    // Two quoted strings that ARE byte-identical still match.
    assert!(json_equivalent_strict(r#"{"X":"1"}"#, r#"{"X":"1"}"#).is_ok());
    // A leading-zero pair that differs textually is caught even though their
    // numeric values coincide.
    assert!(json_equivalent_strict(r#"{"X":"007"}"#, r#"{"X":"7"}"#).is_err());
    // Two BARE numbers keep numeric style-insensitivity (`1` == `1.0`).
    assert!(json_equivalent_strict(r#"{"X":1}"#, r#"{"X":1.0}"#).is_ok());
    // VALUE-semantic mode is UNCHANGED: two quoted numerics still coerce.
    assert!(json_equivalent(r#"{"X":"01"}"#, r#"{"X":"1"}"#).is_ok());
    assert!(json_equivalent(r#"{"X":"1"}"#, r#"{"X":1.0}"#).is_ok());
  }

  #[test]
  fn strict_mode_dup_keys_are_type_aware_when_reordered() {
    // FINDING 3 (Codex): the duplicate-key multiset pairing sorts by the
    // canonical value, but `canonical_scalar` collapses a quoted numeric string
    // and the bare number to the SAME key — so the type-blind sort cannot
    // separate `"1"` from `1`. With both sides holding the SAME multiset
    // {quoted "1", bare 1} but in opposite ORDER, the stable sort keeps each
    // side's input order, mispairs `"1"`↔`1`, and reports a FALSE MISMATCH.
    // The canonical key must be strict-type-aware so each side sorts its quoted
    // and bare entries to matching ranks ⇒ the equal multiset compares EQUAL.
    assert!(json_equivalent_strict(r#"[{"A":"1","A":1}]"#, r#"[{"A":1,"A":"1"}]"#).is_ok());
    // A genuinely DIFFERENT multiset (two bare vs one-bare-one-quoted) must
    // still mismatch under strict (the quoted "1" has no bare partner).
    assert!(json_equivalent_strict(r#"[{"A":1,"A":1}]"#, r#"[{"A":1,"A":"1"}]"#).is_err());
    // value-semantic mode is unchanged: quoted/bare coerce, so BOTH the
    // reordered pair and the bare-vs-quoted pair match.
    assert!(json_equivalent(r#"[{"A":"1","A":1}]"#, r#"[{"A":1,"A":"1"}]"#).is_ok());
    assert!(json_equivalent(r#"[{"A":1,"A":1}]"#, r#"[{"A":1,"A":"1"}]"#).is_ok());
  }

  #[test]
  fn dup_keys_negative_zero_pairs_with_positive_zero() {
    // FINDING 2 (Codex): the dup-key multiset sort key (`canonical_scalar`)
    // formatted floats directly, so `-0.0` → `#-0` and `0.0` → `#0` — DIFFERENT
    // keys — even though `scalar_value_eq` treats `-0.0 == 0.0`. With both sides
    // holding the SAME multiset {a zero, a -0.5} but the zeros spelled with
    // opposite sign AND reordered, the type-blind sort ranked them differently
    // and mispaired the zero against `-0.5` ⇒ a FALSE MISMATCH. The numeric
    // canonical key for zero must be sign-agnostic (`#0` for both ±0.0) so the
    // equal multiset sorts into matching ranks and compares EQUAL — in BOTH
    // modes (consistent with `scalar_value_eq`).
    // Strict mode (both sides bare numbers ⇒ the numeric canonical key applies).
    assert!(json_equivalent_strict(r#"[{"A":-0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":0.0}]"#).is_ok());
    assert!(json_equivalent_strict(r#"[{"A":0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":-0.0}]"#).is_ok());
    // Value mode: same sign-agnostic zero pairing.
    assert!(json_equivalent(r#"[{"A":-0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":0.0}]"#).is_ok());
    assert!(json_equivalent(r#"[{"A":0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":-0.0}]"#).is_ok());
    // A genuinely different multiset still mismatches (the zero has no partner
    // when the other side holds two non-zero values).
    assert!(json_equivalent_strict(r#"[{"A":0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":-0.5}]"#).is_err());
    assert!(json_equivalent(r#"[{"A":0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":-0.5}]"#).is_err());
  }

  #[test]
  fn dup_keys_integer_valued_float_pairs_with_exact_integer() {
    // FINDING (Codex R3): the dup-key multiset sort key (`canonical_scalar`)
    // keyed a bare integer by its EXACT decimal but a non-zero integer-valued
    // FLOAT by `format!("#{}", f)` — DIFFERENT keys for value-EQUAL scalars,
    // because `scalar_value_eq` treats a bare int equal to an integer-valued
    // float via `f_as_exact_i128`/`f_as_exact_u128`. The R2 `#0`-for-zero guard
    // patched ONLY zero; non-zero stayed broken. e.g. `1e23` recovers to the
    // exact integer `99999999999999991611392` (so they value-equal), yet the
    // float `{}`-formatted to `100000000000000000000000` ⇒ key `#100…000` while
    // the int keyed `#99…392`. With both sides holding the SAME multiset
    // {that value, a neighbor `2`} but the value spelled as the float on one
    // side and the exact int on the other, the neighbor's `#2` key sorts
    // BETWEEN the two divergent keys, so the value-equal item landed at opposite
    // ranks and mispaired against `2` ⇒ a FALSE MISMATCH. The numeric canonical
    // key must derive from the same exact-value notion `scalar_value_eq` uses,
    // so an integer-valued float and the bare integer share one `#i…` key.
    // Both sides bare numbers ⇒ the strict numeric canonical key applies.
    assert!(
      json_equivalent_strict(
        r#"[{"A":1e23,"A":2}]"#,
        r#"[{"A":99999999999999991611392,"A":2}]"#
      )
      .is_ok()
    );
    // Same value spelled with an explicit `.0`, plus the same neighbor straddle.
    assert!(
      json_equivalent_strict(
        r#"[{"A":99999999999999991611392.0,"A":2}]"#,
        r#"[{"A":99999999999999991611392,"A":2}]"#
      )
      .is_ok()
    );
    // u128-range integer-valued float: `1.8446744073709552e19` recovers to the
    // exact integer `18446744073709551616` (= 2^64), keyed `#18446744073709552000`
    // by `{}` but `#18446744073709551616` as an int — must now share one key.
    assert!(
      json_equivalent_strict(
        r#"[{"A":1.8446744073709552e19,"A":2}]"#,
        r#"[{"A":18446744073709551616,"A":2}]"#
      )
      .is_ok()
    );
    // value-semantic mode pairs identically (it also coerces quoted/bare).
    assert!(
      json_equivalent(
        r#"[{"A":1e23,"A":2}]"#,
        r#"[{"A":99999999999999991611392,"A":2}]"#
      )
      .is_ok()
    );
    // (b) The R2 ±0.0 / 0.0 case still pairs sign-agnostically (now subsumed by
    // the exact-integer path: both ±0.0 recover to the exact integer 0 ⇒ `#i0`).
    assert!(json_equivalent_strict(r#"[{"A":-0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":0.0}]"#).is_ok());
    assert!(json_equivalent(r#"[{"A":0.0,"A":-0.5}]"#, r#"[{"A":-0.5,"A":-0.0}]"#).is_ok());
    // (c) A genuinely DIFFERENT multiset must still mismatch: the big value has
    // no partner when the other side holds a different non-neighbor value.
    assert!(json_equivalent_strict(r#"[{"A":1e23,"A":2}]"#, r#"[{"A":3,"A":2}]"#).is_err());
    assert!(json_equivalent(r#"[{"A":1e23,"A":2}]"#, r#"[{"A":3,"A":2}]"#).is_err());
    // (d) A genuinely-NON-integer float pairs across value-equal spellings:
    // `1.5` == `1.50` == `1.5e0` share one f64 ⇒ one `#f…` key. Reorder against
    // a neighbor and they must still pair (not mispair on a spelling difference).
    assert!(json_equivalent_strict(r#"[{"A":1.5,"A":9}]"#, r#"[{"A":9,"A":1.50}]"#).is_ok());
    assert!(json_equivalent_strict(r#"[{"A":1.5e0,"A":9}]"#, r#"[{"A":9,"A":1.5}]"#).is_ok());
    // ...but a different non-integer float still mismatches.
    assert!(json_equivalent_strict(r#"[{"A":1.5,"A":9}]"#, r#"[{"A":9,"A":1.25}]"#).is_err());
  }

  #[test]
  fn object_key_order_is_ignored() {
    assert!(json_equivalent(r#"[{"b":2,"a":1}]"#, r#"[{"a":1,"b":2}]"#).is_ok());
  }

  #[test]
  fn missing_key_is_reported() {
    let m = json_equivalent(r#"[{"a":1}]"#, r#"[{"a":1,"b":2}]"#).unwrap_err();
    assert!(
      m.message().contains("object key multiset differs"),
      "got: {}",
      m.message()
    );
  }

  #[test]
  fn duplicate_object_keys_are_significant_not_collapsed() {
    // FIX 2 (D10 r10): a dup-bearing object must NOT compare equal to a
    // dup-free one (this is the ExifTool `%noDups` regression class; a
    // `serde_json::Map`/`BTreeMap` would silently collapse `"A":1,"A":2`
    // to a single `"A"` and mask it). Cardinality differs => Err.
    assert!(json_equivalent(r#"[{"A":1,"A":2}]"#, r#"[{"A":1}]"#).is_err());
    assert!(json_equivalent(r#"[{"A":1,"A":2}]"#, r#"[{"A":2}]"#).is_err());
    // Same multiset but the values differ by position-after-sort => Err.
    // (`{"A":1,"A":2}` sorts to [(A,1),(A,2)]; `{"A":2,"A":1}` also sorts
    // to [(A,1),(A,2)] — so a pure REORDER of identical dup pairs is Ok,
    // but differing dup VALUES are caught.)
    assert!(json_equivalent(r#"[{"A":1,"A":2}]"#, r#"[{"A":2,"A":3}]"#).is_err());
    assert!(json_equivalent(r#"[{"A":1,"A":2}]"#, r#"[{"A":2,"A":1}]"#).is_ok());
    // The message names the repeated key (self-describing dup report).
    let m = json_equivalent(r#"[{"A":1,"A":2}]"#, r#"[{"A":1}]"#).unwrap_err();
    assert!(
      m.message().contains("multiset differs") && m.message().contains("×2"),
      "dup must be surfaced: {}",
      m.message()
    );
  }

  #[test]
  fn duplicate_keys_with_reordered_object_values_match() {
    // Copilot #8 regression: with DUPLICATE keys whose values are
    // non-scalars that are equivalent but textually reordered, the old
    // (key, raw-bytes) sort mispaired them and reported a FALSE
    // mismatch. Canonical-form pairing fixes it: {x:1,y:2} ≡ {y:2,x:1}
    // and {x:9} ≡ {x:9}, so the two documents are equivalent.
    assert!(
      json_equivalent(
        r#"[{"A":{"x":1,"y":2},"A":{"x":9}}]"#,
        r#"[{"A":{"x":9},"A":{"y":2,"x":1}}]"#,
      )
      .is_ok()
    );
    // Nested arrays inside dup values stay ORDER-significant.
    assert!(
      json_equivalent(
        r#"[{"A":[1,2],"A":{"q":0}}]"#,
        r#"[{"A":{"q":0},"A":[2,1]}]"#,
      )
      .is_err()
    );
    // The fix must NOT loosen the verdict: genuinely different dup
    // values (and different value multisets) still mismatch.
    assert!(
      json_equivalent(
        r#"[{"A":{"x":1},"A":{"x":2}}]"#,
        r#"[{"A":{"x":1},"A":{"x":3}}]"#,
      )
      .is_err()
    );
    assert!(
      json_equivalent(
        r#"[{"A":{"x":1},"A":{"y":1}}]"#,
        r#"[{"A":{"x":1},"A":{"x":1}}]"#,
      )
      .is_err()
    );
  }

  #[test]
  fn distinct_keys_reordered_remain_equal() {
    // Key ORDER stays insensitive for the (common) dup-free case.
    assert!(json_equivalent(r#"[{"a":1,"b":2}]"#, r#"[{"b":2,"a":1}]"#).is_ok());
  }

  #[test]
  fn number_formatting_is_value_semantic() {
    // VALUE-semantic: `1 == 1.0` and `0.50 == 0.5` (same numeric value,
    // different spelling — both valid JSON for the same number).
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"[{"a":1.0}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":0.50}]"#, r#"[{"a":0.5}]"#).is_ok());
    // But genuinely different numeric values still mismatch.
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"[{"a":2}]"#).is_err());
    assert!(json_equivalent(r#"[{"a":0.5}]"#, r#"[{"a":0.6}]"#).is_err());
  }

  #[test]
  fn trailing_zeros_are_value_equal() {
    // `0.0` == `0.00000000`; `1.5` == `1.50`; `-0.0` == `0`.
    assert!(json_equivalent(r#"[{"a":0.0}]"#, r#"[{"a":0.00000000}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":1.5}]"#, r#"[{"a":1.50}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":-0.0}]"#, r#"[{"a":0}]"#).is_ok());
  }

  #[test]
  fn scientific_notation_spelling_is_value_equal() {
    // `3.4e+38` == `3.4e38` (the `+` is style); `1E3` == `1000`.
    assert!(json_equivalent(r#"[{"a":3.4e+38}]"#, r#"[{"a":3.4e38}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":1E3}]"#, r#"[{"a":1000}]"#).is_ok());
    assert!(
      json_equivalent(
        r#"[{"a":3.40282366920938e+38}]"#,
        r#"[{"a":3.40282366920938e38}]"#
      )
      .is_ok()
    );
  }

  #[test]
  fn string_vs_bare_number_is_value_equal() {
    // A quoted numeric string equals the bare number of the same value
    // (ExifTool's `EscapeJSON` number-gate blurs these): `"123"` == `123`,
    // `"0.00000000"` == `0.0`, `"3.4e+38"` == `3.4e38`.
    assert!(json_equivalent(r#"[{"a":"123"}]"#, r#"[{"a":123}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":"0.00000000"}]"#, r#"[{"a":0.0}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":"3.4e+38"}]"#, r#"[{"a":3.4e38}]"#).is_ok());
    // Both quoted, value-equal.
    assert!(json_equivalent(r#"[{"a":"1.0"}]"#, r#"[{"a":"1"}]"#).is_ok());
    // A numeric string vs a DIFFERENT number still mismatches.
    assert!(json_equivalent(r#"[{"a":"123"}]"#, r#"[{"a":124}]"#).is_err());
  }

  #[test]
  fn huge_u64_compares_exact_as_integer() {
    // `18446744073709551615` (u64::MAX, 20 digits) exceeds f64's 53-bit
    // mantissa; it must compare as an EXACT integer, so the true value
    // matches itself and DIFFERS from its f64-rounded neighbour.
    assert!(
      json_equivalent(
        r#"[{"a":18446744073709551615}]"#,
        r#"[{"a":18446744073709551615}]"#
      )
      .is_ok()
    );
    // Quoted vs bare, both the exact huge integer ⇒ value-equal.
    assert!(
      json_equivalent(
        r#"[{"a":"18446744073709551615"}]"#,
        r#"[{"a":18446744073709551615}]"#
      )
      .is_ok()
    );
    // Off by one ⇒ mismatch (precision preserved, NOT collapsed via f64).
    assert!(
      json_equivalent(
        r#"[{"a":18446744073709551615}]"#,
        r#"[{"a":18446744073709551614}]"#
      )
      .is_err()
    );
  }

  #[test]
  fn int_vs_float_above_2pow53_compares_exact() {
    // Codex F3: the OLD `as_f64() == as_f64()` cross-arm fallback collapsed an
    // `Int` and a `Float` that round to the same `f64`. Above 2^53 that masks a
    // real off-by-one: `9007199254740993` (odd, Int) and `9007199254740992.0`
    // (the nearest even f64, Float) both become the same f64 ⇒ FALSE EQUAL.
    // The exact-integer comparison must report these UNEQUAL.
    assert!(
      json_equivalent(
        r#"[{"a":9007199254740993}]"#,
        r#"[{"a":9007199254740992.0}]"#
      )
      .is_err(),
      "9007199254740993 (Int) must NOT equal 9007199254740992.0 (Float)"
    );
    // But an Int that IS exactly the float's value stays EQUAL (2^53 is exactly
    // representable, so `…992` Int == `…992.0` Float).
    assert!(
      json_equivalent(
        r#"[{"a":9007199254740992}]"#,
        r#"[{"a":9007199254740992.0}]"#
      )
      .is_ok(),
      "9007199254740992 (Int) must equal 9007199254740992.0 (Float)"
    );
    // Order-independent (Float on the actual side).
    assert!(
      json_equivalent(
        r#"[{"a":9007199254740992.0}]"#,
        r#"[{"a":9007199254740993}]"#
      )
      .is_err()
    );
    // A genuinely fractional float vs a near integer still mismatches via the
    // f64 fallback (the float is fractional ⇒ never integer-valued).
    assert!(json_equivalent(r#"[{"a":3}]"#, r#"[{"a":3.5}]"#).is_err());
    // Within-mantissa Int-vs-Float value equality is unaffected.
    assert!(json_equivalent(r#"[{"a":42}]"#, r#"[{"a":42.0}]"#).is_ok());
  }

  #[test]
  fn float_float_spelling_stays_value_equal_after_hardening() {
    // The `(Float, Float)` arm keeps f64 comparison, so the value-style
    // insensitivity Codex wanted preserved still holds AFTER the F3 fix:
    // trailing zeros and exponent spelling of the same f64 stay EQUAL.
    assert!(json_equivalent(r#"[{"a":0.0}]"#, r#"[{"a":0.00000000}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":3.4e+38}]"#, r#"[{"a":3.4e38}]"#).is_ok());
  }

  #[test]
  fn huge_u64_vs_float_compares_exact() {
    // Uint cross-arm: `18446744073709551615` (u64::MAX) vs its own value as a
    // float spelling, and vs the f64-rounded neighbour `…614`.
    assert!(
      json_equivalent(
        r#"[{"a":18446744073709551615}]"#,
        r#"[{"a":18446744073709551615}]"#
      )
      .is_ok()
    );
    // u64::MAX rounds to 2^64 as f64; `18446744073709551614` is NOT that f64
    // value, so a bare-vs-bare integer pair stays exact and UNEQUAL.
    assert!(
      json_equivalent(
        r#"[{"a":18446744073709551615}]"#,
        r#"[{"a":18446744073709551614}]"#
      )
      .is_err()
    );
  }

  #[test]
  fn i128_max_vs_2pow127_float_is_unequal() {
    // R2-F3 (Codex round-2 [high]): the R1 fix used `f as i128` round-tripped
    // via `as f64` to decide "is this float an exact i128", but
    // `f64 as i128` SATURATES (`>= 2^127` → `i128::MAX`) and `i128::MAX as f64`
    // rounds UP to `2^127` — so the round-trip `(f as i128) as f64 == f` is
    // TRUE for `f = 2^127.0`, giving a false-positive equality between the
    // integer `i128::MAX` and the float `2^127.0` (which is one past i128's
    // representable range).
    //
    // i128::MAX = 170141183460469231731687303715884105727 (2^127 - 1).
    // The float 170141183460469231731687303715884105728.0 IS 2^127 in f64
    // (an exact power-of-two literal).
    let int_max = "[{\"a\":170141183460469231731687303715884105727}]";
    let f_2pow127 = "[{\"a\":170141183460469231731687303715884105728.0}]";
    assert!(
      json_equivalent(int_max, f_2pow127).is_err(),
      "i128::MAX (Int) must NOT equal 2^127.0 (Float)"
    );
    // Symmetric (Float on the actual side).
    assert!(json_equivalent(f_2pow127, int_max).is_err());
  }

  #[test]
  fn i128_min_vs_neg_2pow127_float_is_equal() {
    // i128::MIN = -2^127 = -170141183460469231731687303715884105728, which IS
    // exactly representable as the f64 literal of the same magnitude (it is a
    // power of two). The half-open range `[-2^127, +2^127)` INCLUDES this
    // value, so this pair stays EQUAL (and the equal-by-value verdict is the
    // correct one — they ARE the same mathematical value).
    let int_min = "[{\"a\":-170141183460469231731687303715884105728}]";
    let f_min = "[{\"a\":-170141183460469231731687303715884105728.0}]";
    assert!(
      json_equivalent(int_min, f_min).is_ok(),
      "i128::MIN (Int) must equal -2^127.0 (Float, exact)"
    );
    assert!(json_equivalent(f_min, int_min).is_ok());
  }

  #[test]
  fn u128_max_vs_2pow128_float_is_unequal() {
    // Symmetric Uint hole: `u128::MAX as f64` rounds UP to `2^128`, so the
    // OLD round-trip masked the float `2^128.0` as equal to `u128::MAX`
    // (which is one below `2^128`). u128::MAX = 2^128 - 1.
    let uint_max = "[{\"a\":340282366920938463463374607431768211455}]";
    let f_2pow128 = "[{\"a\":340282366920938463463374607431768211456.0}]";
    assert!(
      json_equivalent(uint_max, f_2pow128).is_err(),
      "u128::MAX (Uint) must NOT equal 2^128.0 (Float)"
    );
    assert!(json_equivalent(f_2pow128, uint_max).is_err());
  }

  #[test]
  fn float_beyond_i128_range_stays_unequal_to_any_int() {
    // Floats far outside the i128 / u128 ranges must NOT be coerced to the
    // saturated integer. Negative side: `-2^200.0` cannot equal any signed
    // 128-bit integer. Positive side: `2^200.0` cannot equal any 128-bit
    // integer either. Use exact power-of-two f64 literals.
    let f_neg_big = "[{\"a\":-1.6069380442589903e+60}]"; // ~-2^200
    let f_pos_big = "[{\"a\":1.6069380442589903e+60}]"; // ~2^200
    assert!(
      json_equivalent(f_neg_big, "[{\"a\":-1}]").is_err(),
      "huge negative float must NOT equal a small Int"
    );
    assert!(
      json_equivalent(f_pos_big, "[{\"a\":1}]").is_err(),
      "huge positive float must NOT equal a small Int"
    );
    // And no Int comparison saturates into a match for the boundary itself.
    let int_one = "[{\"a\":1}]";
    assert!(json_equivalent(f_pos_big, int_one).is_err());
  }

  #[test]
  fn float_in_int_range_just_below_2pow127_stays_equal() {
    // Sanity: a clearly-in-range integer-valued float (well below 2^127)
    // still round-trips equal to its Int spelling. `2^120` is exact in f64
    // (power of two) and clearly inside `[-2^127, +2^127)`.
    //
    // 2^120 = 1329227995784915872903807060280344576.
    let int_form = "[{\"a\":1329227995784915872903807060280344576}]";
    let float_form = "[{\"a\":1329227995784915872903807060280344576.0}]";
    assert!(
      json_equivalent(int_form, float_form).is_ok(),
      "2^120 (Int) must equal 2^120.0 (Float, well inside i128 range)"
    );
    // Below-range floats: -2^120 is exact and well inside the i128 range.
    let int_neg = "[{\"a\":-1329227995784915872903807060280344576}]";
    let float_neg = "[{\"a\":-1329227995784915872903807060280344576.0}]";
    assert!(json_equivalent(int_neg, float_neg).is_ok());
  }

  #[test]
  fn nonfinite_strings_compare_exact() {
    // `"NaN"`/`"Inf"`/`"-Inf"` are non-numeric strings ⇒ exact compare. They
    // match their identical spelling (both sides emit the same titlecase via
    // `perl_nonfinite_str`) and do NOT coerce to any number.
    assert!(json_equivalent(r#"[{"a":"NaN"}]"#, r#"[{"a":"NaN"}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":"Inf"}]"#, r#"[{"a":"Inf"}]"#).is_ok());
    assert!(json_equivalent(r#"[{"a":"-Inf"}]"#, r#"[{"a":"-Inf"}]"#).is_ok());
    // Different titlecase / a number does NOT match a non-finite string.
    assert!(json_equivalent(r#"[{"a":"NaN"}]"#, r#"[{"a":"nan"}]"#).is_err());
    assert!(json_equivalent(r#"[{"a":"Inf"}]"#, r#"[{"a":"-Inf"}]"#).is_err());
  }

  #[test]
  fn non_numeric_string_mismatch_still_fails() {
    // Non-numeric strings stay escape/lexeme-exact: an escaped form is NOT
    // equal to the literal even though both decode to the letter A.
    let lit = "[\"A\"]";
    let esc = "[\"\\u0041\"]";
    assert_ne!(
      lit.as_bytes(),
      esc.as_bytes(),
      "fixtures must differ in bytes"
    );
    assert!(json_equivalent(lit, esc).is_err());
    // Identical bytes ARE equal (literal vs literal, escaped vs escaped).
    assert!(json_equivalent(lit, lit).is_ok());
    assert!(json_equivalent(esc, esc).is_ok());
    // Forward-slash escape vs plain also differ byte-wise (non-numeric).
    assert!(json_equivalent(r#"["a/b"]"#, r#"["a\/b"]"#).is_err());
    // Two genuinely different non-numeric strings mismatch.
    assert!(json_equivalent(r#"["foo"]"#, r#"["bar"]"#).is_err());
    // A numeric string vs a non-numeric string mismatches (one side not a
    // number ⇒ exact text compare, and `"123"` ≠ `"abc"`).
    assert!(json_equivalent(r#"[{"a":"123"}]"#, r#"[{"a":"abc"}]"#).is_err());
  }

  #[test]
  fn array_order_is_significant() {
    assert!(json_equivalent(r#"[1,2]"#, r#"[2,1]"#).is_err());
    assert!(json_equivalent(r#"[1,2]"#, r#"[1,2]"#).is_ok());
  }

  #[test]
  fn nested_structures_compare_recursively() {
    assert!(
      json_equivalent(
        r#"[{"a":[1,{"x":"v"}],"b":2}]"#,
        r#"[{"b":2,"a":[1,{"x":"v"}]}]"#
      )
      .is_ok()
    );
    let m = json_equivalent(r#"[{"a":[1,{"x":"v"}]}]"#, r#"[{"a":[1,{"x":"w"}]}]"#).unwrap_err();
    assert_eq!(
      m,
      Mismatch::new("$[0].a[1].x: value differs\n  actual: \"v\"\n  golden: \"w\"")
    );
  }

  #[test]
  fn reports_first_scalar_mismatch_with_path() {
    let m = json_equivalent(r#"[{"a":1}]"#, r#"[{"a":2}]"#).unwrap_err();
    assert_eq!(
      m,
      Mismatch::new("$[0].a: value differs\n  actual: 1\n  golden: 2")
    );
  }

  #[test]
  fn invalid_json_is_reported() {
    assert!(
      json_equivalent("[1,]", "[1]")
        .unwrap_err()
        .message()
        .contains("actual is invalid")
    );
    assert!(
      json_equivalent("[1]", "nope")
        .unwrap_err()
        .message()
        .contains("golden is invalid")
    );
  }

  #[test]
  fn whitespace_insignificant_for_containers() {
    // Internal container whitespace must not cause a mismatch (only scalar
    // lexemes are byte-compared; structure is compared recursively).
    assert!(
      json_equivalent(
        "[ { \"a\" : 1 , \"b\" : [ 2 , 3 ] } ]",
        r#"[{"a":1,"b":[2,3]}]"#
      )
      .is_ok()
    );
  }

  #[test]
  fn shape_mismatch_is_reported() {
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"[[1]]"#).is_err());
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"["x"]"#).is_err());
  }
}
