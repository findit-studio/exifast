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
  let a: &RawValue = serde_json::from_str(actual)
    .map_err(|e| Mismatch::new(format!("actual is invalid JSON: {e}")))?;
  let g: &RawValue = serde_json::from_str(golden)
    .map_err(|e| Mismatch::new(format!("golden is invalid JSON: {e}")))?;
  cmp(a, g, "$")
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
  /// when the float side is INTEGER-VALUED and exactly representable as the
  /// integer type, we compare the integer values EXACTLY. Only a genuinely
  /// fractional or out-of-integer-range float falls back to `f64` comparison
  /// (where the float is the authoritative value anyway).
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
        match f_as_exact_i128(f) {
          Some(fi) => i == fi,
          None => i as f64 == f,
        }
      }
      (NumVal::Uint(u), NumVal::Float(f)) | (NumVal::Float(f), NumVal::Uint(u)) => {
        match f_as_exact_u128(f) {
          Some(fu) => u == fu,
          None => u as f64 == f,
        }
      }
      (NumVal::Float(a), NumVal::Float(b)) => a == b,
    }
  }
}

/// If `f` is integer-valued AND exactly representable as an `i128` (i.e. the
/// round-trip `f as i128 as f64 == f` holds, which also rejects `f` outside
/// `i128` range and any fractional `f`), return that exact `i128`. Otherwise
/// `None` — the caller then treats `f` as a genuine float.
fn f_as_exact_i128(f: f64) -> Option<i128> {
  if f.fract() != 0.0 {
    return None;
  }
  let i = f as i128;
  (i as f64 == f).then_some(i)
}

/// `u128` analogue of [`f_as_exact_i128`]. Also rejects negative `f`.
fn f_as_exact_u128(f: f64) -> Option<u128> {
  if f.fract() != 0.0 || f < 0.0 {
    return None;
  }
  let u = f as u128;
  (u as f64 == f).then_some(u)
}

/// VALUE-equality of two scalar `RawValue`s (numbers, strings, `true`/`false`/
/// `null`). The rule the module doc describes:
///
/// 1. If BOTH sides parse as a finite number (a bare number, OR a quoted string
///    whose entire content is numeric), compare by numeric value.
/// 2. Otherwise compare the scalars' raw lexeme text byte-for-byte — so
///    non-numeric strings stay escape-exact, and `true`/`null`/`"NaN"` match
///    only their identical spelling.
fn scalar_value_eq(a: &RawValue, g: &RawValue) -> bool {
  let (at, _) = scalar_payload(a);
  let (gt, _) = scalar_payload(g);
  if let (Some(an), Some(gn)) = (parse_number(at), parse_number(gt)) {
    return an.value_eq(gn);
  }
  // Non-numeric (or only-one-side-numeric): exact lexeme compare. Using the
  // raw `get()` keeps a bare `123` distinct from the string `"abc"` and a
  // quoted `"NaN"` matching only another quoted `"NaN"`.
  a.get().trim() == g.get().trim()
}

/// A normal form of a SCALAR under our value-equivalence, used only as a sort
/// key when pairing duplicate object keys (`canonical`). Two scalars that are
/// `scalar_value_eq` MUST map to the same string here, else the dup-pairing
/// sort could mis-rank value-equal-but-differently-spelled duplicates. Numbers
/// canonicalize to a single normalized form; non-numbers keep their raw text.
fn canonical_scalar(r: &RawValue) -> String {
  let (text, _) = scalar_payload(r);
  match parse_number(text) {
    // Integers print exactly; floats via `{}` (a single deterministic form,
    // e.g. `0.0` and `0.00000000` both canonicalize to `0`). This is a SORT
    // KEY only — `scalar_value_eq` remains the verdict (so f64 round-trip
    // imprecision in the key can never change equality, only pairing order).
    Some(NumVal::Int(i)) => format!("#{i}"),
    Some(NumVal::Uint(u)) => format!("#{u}"),
    Some(NumVal::Float(f)) => format!("#{}", f),
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
fn canonical(r: &RawValue) -> String {
  match kind_of(r) {
    Kind::Object => {
      // Recurse, then sort entries by (key, canonical value),
      // KEEPING duplicates so cardinality stays significant (the
      // ExifTool `%noDups` regression class).
      let mut entries: Vec<(String, String)> = match serde_json::from_str(r.get()) {
        Ok(OrderedObject(p)) => p.into_iter().map(|(k, v)| (k, canonical(v))).collect(),
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
        s.push_str(&canonical(it));
      }
      s.push(']');
      s
    }
    // Scalar: a VALUE-normalized form so value-equal-but-differently-spelled
    // scalars (`1` vs `1.0`, `"123"` vs `123`) sort to the same rank for
    // dup-pairing. `scalar_value_eq` remains the actual verdict.
    Kind::Scalar => canonical_scalar(r),
  }
}

fn cmp(a: &RawValue, g: &RawValue, path: &str) -> Result<(), Mismatch> {
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
      ap.sort_by_cached_key(|e| (e.0.clone(), canonical(e.1)));
      gp.sort_by_cached_key(|e| (e.0.clone(), canonical(e.1)));
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
        cmp(av, gv, &format!("{path}.{ak}"))?;
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
        cmp(x, y, &format!("{path}[{i}]"))?;
      }
      Ok(())
    }
    // Scalars (and shape-mismatched pairs): compare by VALUE
    // ([`scalar_value_eq`]) — numbers (and numeric strings) numeric-equal,
    // non-numeric strings escape-exact, `true`/`null`/`"NaN"` spelling-exact.
    // For a shape mismatch (e.g. object vs array) neither side parses as a
    // number and the raw texts differ, so this still reports correctly.
    _ => {
      if scalar_value_eq(a, g) {
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
