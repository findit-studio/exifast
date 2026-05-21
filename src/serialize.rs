//! Serialize a tag stream to the `exiftool -j -G1` JSON document via
//! **standard `serde_json`**.
//!
//! We do NOT reproduce ExifTool's exact scalar tokens or its Group1 key order:
//! the value-semantic [`crate::jsondiff`] comparator treats a different valid
//! spelling of the same value (and a reordered object key) as equal, so chasing
//! `sprintf` token style or the Group1 stable-clustering sort would be wasted
//! effort. The per-scalar VALUE rules live in the [`crate::value::TagValue`]
//! `Serialize` impl (standard scalars; binary placeholder; titlecase non-finite
//! string; ExifTool-rounded rational value). This module owns only the document
//! shape: the single-element array `[{ … }]`, `SourceFile` first, the
//! `"<Group1>:<Name>"` keys, the generated `ExifTool:Warning`/`ExifTool:Error`
//! tags, and the `%noDups` first-wins token dedup.

use crate::value::Metadata;
use crate::value::Tag;
use std::string::String;

/// Serialize a [`Metadata`] to the `exiftool -j -G1` JSON string. Convenience
/// wrapper over [`render_document`] for the `Metadata` push-bag (the typed-Meta
/// staging / test oracle). Infallible — every `TagValue` has a faithful
/// representation, and `serde_json` cannot fail on an in-memory map of finite
/// scalars (non-finite floats are emitted as strings, never as a number).
#[must_use]
pub fn to_exiftool_json(m: &Metadata) -> String {
  render_document(m.source_file(), m.tags(), m.warnings(), m.errors())
}

/// Render the `exiftool -j -G1` JSON document from the `SourceFile` path, the
/// found tags (in FoundTag order), and the generated `Warning`/`Error` strings.
/// Output is VALUE-equivalent (not token- or order-exact) to bundled
/// `perl exiftool -j -G1`, which the value-semantic conformance gate verifies.
///
/// Reproduces, citing the bundled rules:
///
/// 1. **Framing** — the single-element array of one object (`exiftool:1649,
///    1650,2678`), `SourceFile` first.
/// 2. **Keys** — `"<Group1>:<Name>"` under `-G1` (`exiftool:2947`).
/// 3. **Generated `ExifTool:Warning` / `ExifTool:Error`** — real `ExifTool`-
///    group FoundTags (`ExifTool.pm:1225,1288-1297`). Default `-j -G1` emits
///    only the FIRST of each (`exiftool:2744`).
/// 4. **`%noDups` first-wins** — `next if $noDups{$tok}` (`exiftool:2950-2951`):
///    the FIRST occurrence of a `"<Group1>:<Name>"` token wins; later
///    same-token tags are dropped. (Object KEY ORDER and scalar TOKEN STYLE are
///    NOT preserved — the value-semantic comparator makes them irrelevant.)
#[must_use]
pub fn render_document<S: AsRef<str>>(
  source_file: &str,
  tags: &[Tag],
  warnings: &[S],
  errors: &[S],
) -> String {
  // `serde_json::to_string` on a `Document` wrapper. The wrapper's `Serialize`
  // owns the array-of-one-object shape + `SourceFile`-first + `%noDups`
  // first-wins; the per-scalar values come from `TagValue`'s `Serialize`.
  let warnings: std::vec::Vec<&str> = warnings.iter().map(AsRef::as_ref).collect();
  let errors: std::vec::Vec<&str> = errors.iter().map(AsRef::as_ref).collect();
  let doc = serde_doc::Document {
    source_file,
    tags,
    warning: warnings.first().copied(),
    error: errors.first().copied(),
  };
  // Infallible in practice: the only `serde_json` error mode for a value tree
  // is a non-finite float emitted as a NUMBER, but `TagValue` emits every
  // non-finite float as a STRING. A map key collision cannot error. Fall back
  // to an empty array on the unreachable error rather than panic in a library.
  serde_json::to_string(&doc).unwrap_or_else(|_| String::from("[]"))
}

/// The serde wrapper types for [`render_document`]. Private to this module
/// (the public surface is the two functions above). Gated identically to the
/// `serde`/`json`-only `serde_json` dependency.
mod serde_doc {
  use crate::value::Tag;
  use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
  use std::collections::BTreeSet;

  /// The whole `-j -G1` document: an array of exactly one object.
  pub struct Document<'a> {
    pub source_file: &'a str,
    pub tags: &'a [Tag],
    /// The FIRST warning (ExifTool emits only the first under default `-j`).
    pub warning: Option<&'a str>,
    /// The FIRST error.
    pub error: Option<&'a str>,
  }

  impl Serialize for Document<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      let mut seq = s.serialize_seq(Some(1))?;
      seq.serialize_element(&FileObject(self))?;
      seq.end()
    }
  }

  /// The single per-file object inside the array.
  struct FileObject<'a>(&'a Document<'a>);

  impl Serialize for FileObject<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      let doc = self.0;
      let mut map = s.serialize_map(None)?;
      // `SourceFile` is printed before the per-tag loop and never enters
      // `%noDups` (ExifTool emits it first).
      map.serialize_entry("SourceFile", doc.source_file)?;
      // `%noDups` first-wins on the `"<Group1>:<Name>"` token
      // (`exiftool:2950-2951`): the FIRST occurrence wins, later same-token
      // tags are skipped. The generated `ExifTool:Warning`/`ExifTool:Error`
      // join the SAME dedup set (`exiftool:2951`).
      let mut seen: BTreeSet<String> = BTreeSet::new();
      for t in doc.tags {
        let token = std::format!("{}:{}", t.group().family1(), t.name());
        if seen.insert(token.clone()) {
          map.serialize_entry(&token, t.value())?;
        }
      }
      if let Some(w) = doc.warning {
        if seen.insert(String::from("ExifTool:Warning")) {
          map.serialize_entry("ExifTool:Warning", w)?;
        }
      }
      if let Some(e) = doc.error {
        if seen.insert(String::from("ExifTool:Error")) {
          map.serialize_entry("ExifTool:Error", e)?;
        }
      }
      map.end()
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jsondiff::json_equivalent;
  use crate::value::{Group, Metadata, Rational, TagValue};

  /// Helper: assert the rendered JSON is value-equivalent to `want`.
  fn assert_value_eq(m: &Metadata, want: &str) {
    let got = to_exiftool_json(m);
    json_equivalent(&got, want)
      .unwrap_or_else(|e| panic!("value mismatch: {}\n got: {got}\nwant: {want}", e.message()));
  }

  #[test]
  fn shape_matches_exiftool_j_g1() {
    let mut m = Metadata::new("a.aac");
    m.push(
      Group::new("Audio", "AAC"),
      "SampleRate",
      TagValue::I64(44100),
    );
    m.push(
      Group::new("Audio", "AAC"),
      "AudioBitrate",
      TagValue::Str("128 kbps".into()),
    );
    // Value-equivalent to the bundled `-j -G1` framing.
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.aac","AAC:SampleRate":44100,"AAC:AudioBitrate":"128 kbps"}]"#,
    );
  }

  #[test]
  fn bytes_value_is_exiftool_binary_placeholder() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "ThumbnailImage",
      TagValue::Bytes(vec![1, 2, 3]),
    );
    let s = to_exiftool_json(&m);
    assert!(
      s.contains("(Binary data 3 bytes, use -b option to extract)"),
      "got: {s}"
    );
  }

  #[test]
  fn rational_value_is_numeric() {
    let mut m = Metadata::new("a.jpg");
    // 86/10 = 8.6 (a rational64).
    m.push(
      Group::new("EXIF", "IFD0"),
      "FocalLength",
      TagValue::Rational(Rational::rational64(86, 10)),
    );
    assert_value_eq(&m, r#"[{"SourceFile":"a.jpg","IFD0:FocalLength":8.6}]"#);
    // It is a bare number, not a quoted string.
    let s = to_exiftool_json(&m);
    assert!(
      !s.contains("\"8.6\""),
      "rational must be a bare number: {s}"
    );
  }

  #[test]
  fn rational_matches_exiftool_roundfloat_value() {
    // 10/2134 rational64 -> RoundFloat(_,10) = 0.004686035614. The rendered
    // number must be VALUE-equal to that rounded golden token (NOT the raw
    // f64 0.00468603561387067, which is a different value).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "ExposureTime",
      TagValue::Rational(Rational::rational64(10, 2134)),
    );
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","ExifIFD:ExposureTime":0.004686035614}]"#,
    );
  }

  #[test]
  fn rational_zero_denominator_is_undef_or_inf_string() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "DigitalZoomRatio",
      TagValue::Rational(Rational::rational64(0, 0)),
    );
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "Bad",
      TagValue::Rational(Rational::rational64(1, 0)),
    );
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","ExifIFD:DigitalZoomRatio":"undef","ExifIFD:Bad":"inf"}]"#,
    );
  }

  #[test]
  fn list_containing_bytes_and_rational_serializes() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "MixedList",
      TagValue::List(vec![
        TagValue::I64(1),
        TagValue::Bytes(vec![0_u8; 5]),
        TagValue::Rational(Rational::rational64(1, 2)),
      ]),
    );
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","IFD0:MixedList":[1,"(Binary data 5 bytes, use -b option to extract)",0.5]}]"#,
    );
  }

  #[test]
  fn numeric_looking_string_value_equals_bare_number() {
    // A numeric-looking string serializes as a JSON STRING; the value-semantic
    // comparator coerces it to the bare number the golden carries.
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "ExifIFD"),
      "Aperture",
      TagValue::Str("3.5".into()),
    );
    m.push(
      Group::new("EXIF", "ExifIFD"),
      "ISO",
      TagValue::Str("100".into()),
    );
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","ExifIFD:Aperture":3.5,"ExifIFD:ISO":100}]"#,
    );
  }

  #[test]
  fn boolean_value() {
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "A", TagValue::Bool(true));
    m.push(Group::new("X", "X"), "B", TagValue::Str("true".into()));
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"X:A\":true"), "got: {s}");
  }

  #[test]
  fn string_escaping_is_valid_json() {
    let mut m = Metadata::new("a.jpg");
    let raw = "tab\there\"q\\b\nnl";
    m.push(Group::new("X", "X"), "S", TagValue::Str(raw.into()));
    // serde_json escapes per the JSON spec; round-trips back to the same value.
    assert_value_eq(
      &m,
      &serde_json::to_string(&serde_json::json!([{
        "SourceFile": "a.jpg",
        "X:S": raw,
      }]))
      .unwrap(),
    );
  }

  #[test]
  fn u64_above_i64_max_renders_exact() {
    // A u64 above i64::MAX renders its EXACT value (no saturation); the
    // comparator keeps it exact.
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "Max", TagValue::U64(u64::MAX));
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","X:Max":18446744073709551615}]"#,
    );
    let s = to_exiftool_json(&m);
    assert!(
      !s.contains("9223372036854775807"),
      "must not saturate to i64::MAX: {s}"
    );
  }

  #[test]
  fn nonfinite_float_is_titlecase_string() {
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "Inf", TagValue::F64(f64::INFINITY));
    m.push(
      Group::new("X", "X"),
      "NegInf",
      TagValue::F64(f64::NEG_INFINITY),
    );
    m.push(Group::new("X", "X"), "Nan", TagValue::F64(f64::NAN));
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"X:Inf\":\"Inf\""), "got: {s}");
    assert!(s.contains("\"X:NegInf\":\"-Inf\""), "got: {s}");
    assert!(s.contains("\"X:Nan\":\"NaN\""), "got: {s}");
  }

  #[test]
  fn duplicate_group1_name_token_is_suppressed_first_wins() {
    // `%noDups` first-wins (exiftool:2950-2951). Two tags both resolving to
    // `AAC:Channels` => the FIRST is emitted, the second dropped entirely.
    let mut m = Metadata::new("a.aac");
    // Different family0, same family1:name => distinct at push (push dedups on
    // the FULL Group identity, so both survive), then deduped at render on the
    // family1:name token.
    m.push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
    m.push(Group::new("QuickTime", "AAC"), "Channels", TagValue::I64(6));
    let s = to_exiftool_json(&m);
    assert_eq!(
      s.matches("\"AAC:Channels\"").count(),
      1,
      "duplicate token must appear once: {s}"
    );
    // First wins (value 2), value-equivalent.
    assert_value_eq(&m, r#"[{"SourceFile":"a.aac","AAC:Channels":2}]"#);
  }

  #[test]
  fn warnings_emitted_as_single_exiftool_warning_tag() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    m.push_warning("w1");
    m.push_warning("w2");
    let s = to_exiftool_json(&m);
    assert_eq!(
      s.matches("\"ExifTool:Warning\"").count(),
      1,
      "only the first warning is emitted: {s}"
    );
    assert!(
      s.contains("\"ExifTool:Warning\":\"w1\""),
      "first warning: {s}"
    );
    assert!(!s.contains("w2"), "later warning dropped: {s}");
  }

  #[test]
  fn no_warnings_emits_no_warning_key() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    let s = to_exiftool_json(&m);
    assert!(!s.contains("Warning"), "no Warning key when none: {s}");
    assert_value_eq(&m, r#"[{"SourceFile":"a.jpg","IFD0:Make":"Canon"}]"#);
  }

  #[test]
  fn distinct_tokens_are_all_kept() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    m.push(
      Group::new("EXIF", "IFD1"),
      "Make",
      TagValue::Str("Nikon".into()),
    );
    m.push(
      Group::new("EXIF", "IFD0"),
      "Model",
      TagValue::Str("R5".into()),
    );
    assert_value_eq(
      &m,
      r#"[{"SourceFile":"a.jpg","IFD0:Make":"Canon","IFD1:Make":"Nikon","IFD0:Model":"R5"}]"#,
    );
  }
}
