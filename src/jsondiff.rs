//! Byte-exact JSON value equality, ignoring object key order, for comparing
//! `exifast` output to ExifTool golden (spec §4: object key order is *not*
//! significant, but the key *multiset* must match and every scalar must equal
//! ExifTool **byte-for-byte** — number literals compared as text so `1` ≠
//! `1.0`, and strings compared by their exact lexeme so the literal `"A"`
//! ≠ its escaped form `"A"` (both decode to A); array element order
//! *is* significant).
//!
//! The comparison is done over `serde_json::value::RawValue`: objects are
//! parsed into an ORDERED `Vec<(String, &RawValue)>` (a serde visitor over
//! `MapAccess`) that PRESERVES duplicate keys, then compared as a *multiset*
//! of `(key, raw-value-lexeme)` pairs — key ORDER is insensitive but a
//! repeated key is significant, so `{"A":1,"A":2}` ≠ `{"A":1}` (this is what
//! catches the ExifTool `%noDups` regression class; a `serde_json::Map` /
//! `BTreeMap` would silently collapse the duplicate and mask it). Arrays are
//! recursed element-wise, order-significant; every scalar leaf is compared by
//! its raw lexeme text byte-for-byte (strings escape-exact, numbers
//! token-exact, subsuming the old `arbitrary_precision` number path).

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

/// A human-readable description of the first place two JSON documents differ.
#[derive(Debug, PartialEq, Eq)]
pub struct Mismatch(String);

impl Mismatch {
  /// Construct a `Mismatch` from a message string.
  #[must_use]
  pub fn new(message: impl Into<String>) -> Self {
    Self(message.into())
  }

  /// The mismatch description message.
  #[must_use]
  pub fn message(&self) -> &str {
    &self.0
  }
}

/// Compare two JSON texts as the 1:1 bar requires: object key order is NOT
/// significant (but the key *set* must match), array element order IS
/// significant, and every scalar is compared by its raw lexeme byte-for-byte
/// (so `1` ≠ `1.0`, `0.50` ≠ `0.5`, and the literal `"A"` ≠ the escaped
/// `"A"`). Returns the first
/// `Mismatch`.
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
    // Scalar: the raw lexeme IS the canonical form — byte-exact, so
    // `1` ≠ `1.0`, `0.50` ≠ `0.5`, `"A"` ≠ `"A"` all stand.
    Kind::Scalar => r.get().to_string(),
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
    // Scalars (and shape-mismatched pairs): compare the raw lexeme text
    // byte-for-byte. For a scalar this is escape-exact (strings) and
    // token-exact (numbers). For a shape mismatch (e.g. object vs array)
    // the raw texts differ, so this still reports correctly.
    _ => {
      if a.get() == g.get() {
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
    assert!(json_equivalent(
      r#"[{"A":{"x":1,"y":2},"A":{"x":9}}]"#,
      r#"[{"A":{"x":9},"A":{"y":2,"x":1}}]"#,
    )
    .is_ok());
    // Nested arrays inside dup values stay ORDER-significant.
    assert!(json_equivalent(
      r#"[{"A":[1,2],"A":{"q":0}}]"#,
      r#"[{"A":{"q":0},"A":[2,1]}]"#,
    )
    .is_err());
    // The fix must NOT loosen the verdict: genuinely different dup
    // values (and different value multisets) still mismatch.
    assert!(json_equivalent(
      r#"[{"A":{"x":1},"A":{"x":2}}]"#,
      r#"[{"A":{"x":1},"A":{"x":3}}]"#,
    )
    .is_err());
    assert!(json_equivalent(
      r#"[{"A":{"x":1},"A":{"y":1}}]"#,
      r#"[{"A":{"x":1},"A":{"x":1}}]"#,
    )
    .is_err());
  }

  #[test]
  fn distinct_keys_reordered_remain_equal() {
    // Key ORDER stays insensitive for the (common) dup-free case.
    assert!(json_equivalent(r#"[{"a":1,"b":2}]"#, r#"[{"b":2,"a":1}]"#).is_ok());
  }

  #[test]
  fn number_formatting_is_byte_exact() {
    // 1 vs 1.0 and 0.50 vs 0.5 must NOT be considered equal.
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"[{"a":1.0}]"#).is_err());
    assert!(json_equivalent(r#"[{"a":0.50}]"#, r#"[{"a":0.5}]"#).is_err());
  }

  #[test]
  fn string_lexeme_is_byte_exact_not_escape_normalized() {
    // The bar is byte-exact string lexemes: an escaped form is NOT equal
    // to the literal even though both decode to the letter A. Build the
    // escaped form from explicit bytes so there is zero ambiguity:
    // `lit` = `["A"]`, `esc` = `["A"]` (the 6-char JSON escape).
    let lit = "[\"A\"]";
    let esc = "[\"\\u0041\"]";
    assert_ne!(
      lit.as_bytes(),
      esc.as_bytes(),
      "fixtures must differ in bytes"
    );
    // Both decode to "A", but the bar is byte-exact ⇒ not equivalent.
    assert!(json_equivalent(lit, esc).is_err());
    // Identical bytes ARE equal (literal vs literal, escaped vs escaped).
    assert!(json_equivalent(lit, lit).is_ok());
    assert!(json_equivalent(esc, esc).is_ok());
    // Forward-slash escape vs plain also differ byte-wise.
    assert!(json_equivalent(r#"["a/b"]"#, r#"["a\/b"]"#).is_err());
  }

  #[test]
  fn array_order_is_significant() {
    assert!(json_equivalent(r#"[1,2]"#, r#"[2,1]"#).is_err());
    assert!(json_equivalent(r#"[1,2]"#, r#"[1,2]"#).is_ok());
  }

  #[test]
  fn nested_structures_compare_recursively() {
    assert!(json_equivalent(
      r#"[{"a":[1,{"x":"v"}],"b":2}]"#,
      r#"[{"b":2,"a":[1,{"x":"v"}]}]"#
    )
    .is_ok());
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
    assert!(json_equivalent("[1,]", "[1]")
      .unwrap_err()
      .message()
      .contains("actual is invalid"));
    assert!(json_equivalent("[1]", "nope")
      .unwrap_err()
      .message()
      .contains("golden is invalid"));
  }

  #[test]
  fn whitespace_insignificant_for_containers() {
    // Internal container whitespace must not cause a mismatch (only scalar
    // lexemes are byte-compared; structure is compared recursively).
    assert!(json_equivalent(
      "[ { \"a\" : 1 , \"b\" : [ 2 , 3 ] } ]",
      r#"[{"a":1,"b":[2,3]}]"#
    )
    .is_ok());
  }

  #[test]
  fn shape_mismatch_is_reported() {
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"[[1]]"#).is_err());
    assert!(json_equivalent(r#"[{"a":1}]"#, r#"["x"]"#).is_err());
  }
}
