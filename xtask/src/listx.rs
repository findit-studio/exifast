// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Parse `exiftool -listx` XML into a [`TableModel`] / [`TagModel`].
//!
//! ## Real `-listx` shape (ExifTool 13.59)
//!
//! `exiftool -listx` ALWAYS dumps every table (~18 MB) and ignores any tag /
//! group filter on the command line, so [`parse_listx`] takes the wanted
//! `<table name=…>` and walks only that one. A tag header looks like:
//!
//! ```xml
//! <table name='XMP::tiff' g0='XMP' g1='XMP-tiff' g2='Image'>
//!  <tag id='Compression' name='Compression' type='integer' writable='true'>
//!   <values>
//!    <key id='1'><val lang='en'>Uncompressed</val><val lang='de'>…</val></key>
//!   </values>
//!  </tag>
//! </table>
//! ```
//!
//! Note the attribute split that the design doc glossed over: **`type`** holds
//! the writable KIND (`integer` / `string` / `rational` / `lang-alt` / `date`
//! / `boolean` / `real`), while **`writable`** is just the boolean `true` /
//! `false`. Each `<key>` carries one `<val>` PER LANGUAGE; only `lang='en'`
//! (the canonical label ExifTool prints) is kept.

use anyhow::{Context, Result};

/// One ExifTool tag table (`<table>`), filtered to its English metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableModel {
  /// `<table name=…>` — e.g. `"XMP::tiff"`.
  pub name: String,
  /// `(g0, g1)` — e.g. `("XMP", "XMP-tiff")`.
  pub groups: (String, String),
  /// The table's tags in document order.
  pub tags: Vec<TagModel>,
}

/// One tag row (`<tag>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagModel {
  /// `<tag id=…>` — the raw property key (e.g. `"ImageLength"`).
  pub id: String,
  /// `<tag name=…>` — the emitted tag name (an ExifTool `Name` remap; e.g.
  /// the `ImageLength` key emits as `ImageHeight`).
  pub name: String,
  /// `<tag type=…>` — the writable KIND (`integer` / `string` / `rational`
  /// / `lang-alt` / `date` / `boolean` / `real`), NOT a boolean.
  pub ty: Option<String>,
  /// `<tag writable=…>` — the boolean `true` / `false` flag.
  pub writable: Option<String>,
  /// The `<values>` PrintConv map, `(key-id, en-label)` in document order, or
  /// `None` when the tag has no `<values>` block.
  pub values: Option<Vec<(String, String)>>,
}

/// Parse `-listx` XML and return the model for the `<table>` named `table_name`.
pub fn parse_listx(xml: &str, table_name: &str) -> Result<TableModel> {
  let doc = roxmltree::Document::parse(xml).context("parse -listx xml")?;
  let table = doc
    .descendants()
    .find(|n| n.has_tag_name("table") && n.attribute("name") == Some(table_name))
    .with_context(|| format!("no <table name='{table_name}'>"))?;
  let groups = (
    table.attribute("g0").unwrap_or_default().to_string(),
    table.attribute("g1").unwrap_or_default().to_string(),
  );
  let mut tags = Vec::new();
  for tag in table.children().filter(|n| n.has_tag_name("tag")) {
    tags.push(TagModel {
      id: tag.attribute("id").unwrap_or_default().to_string(),
      name: tag.attribute("name").unwrap_or_default().to_string(),
      ty: tag.attribute("type").map(str::to_string),
      writable: tag.attribute("writable").map(str::to_string),
      values: parse_values(tag),
    });
  }
  Ok(TableModel {
    name: table.attribute("name").unwrap_or_default().to_string(),
    groups,
    tags,
  })
}

/// Parse `-listx` XML and return EVERY `<table>` whose group-0 is `XMP`, in
/// document order. This is the all-namespaces mode used by the full XMP table
/// generation (Task 7): one `-listx` run dumps all ~78 XMP namespace tables
/// (`XMP::dc`, `XMP::crs`, `Google::GImage`, `DJI::XMP`, …), each routed by the
/// `XMP-<ns>` family-1 group. Tables are returned even when they carry no tags
/// (none do today, but the filter is structural, not tag-count based).
pub fn parse_all_xmp_listx(xml: &str) -> Result<Vec<TableModel>> {
  let doc = roxmltree::Document::parse(xml).context("parse -listx xml")?;
  let mut tables = Vec::new();
  for table in doc
    .descendants()
    .filter(|n| n.has_tag_name("table") && n.attribute("g0") == Some("XMP"))
  {
    let groups = (
      table.attribute("g0").unwrap_or_default().to_string(),
      table.attribute("g1").unwrap_or_default().to_string(),
    );
    let mut tags = Vec::new();
    for tag in table.children().filter(|n| n.has_tag_name("tag")) {
      tags.push(TagModel {
        id: tag.attribute("id").unwrap_or_default().to_string(),
        name: tag.attribute("name").unwrap_or_default().to_string(),
        ty: tag.attribute("type").map(str::to_string),
        writable: tag.attribute("writable").map(str::to_string),
        values: parse_values(tag),
      });
    }
    tables.push(TableModel {
      name: table.attribute("name").unwrap_or_default().to_string(),
      groups,
      tags,
    });
  }
  Ok(tables)
}

/// Collect a tag's `<values>` PrintConv map as `(key-id, en-label)` pairs,
/// keeping only the `lang='en'` `<val>` of each `<key>`. Returns `None` when
/// there is no `<values>` block (a tag with no PrintConv map).
fn parse_values(tag: roxmltree::Node) -> Option<Vec<(String, String)>> {
  let values = tag.children().find(|n| n.has_tag_name("values"))?;
  let pairs: Vec<(String, String)> = values
    .children()
    .filter(|n| n.has_tag_name("key"))
    .filter_map(|key| {
      let id = key.attribute("id")?.to_string();
      let label = en_val(key)?;
      Some((id, label))
    })
    .collect();
  // A `<values>` element with no English-labelled keys is treated as no map.
  (!pairs.is_empty()).then_some(pairs)
}

/// The text of a `<key>`'s `lang='en'` `<val>` (the label ExifTool prints).
/// Falls back to the first `<val>` if none is explicitly `lang='en'`.
fn en_val(key: roxmltree::Node) -> Option<String> {
  let mut first = None;
  for val in key.children().filter(|n| n.has_tag_name("val")) {
    if first.is_none() {
      first = Some(val);
    }
    if val.attribute("lang") == Some("en") {
      return Some(val.text().unwrap_or_default().to_string());
    }
  }
  first.map(|v| v.text().unwrap_or_default().to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_tag_with_values_map() {
    let xml = include_str!("../tests/fixtures/xmp_listx_sample.xml");
    let model = parse_listx(xml, "XMP::tiff").unwrap();
    assert_eq!(model.name, "XMP::tiff");
    assert_eq!(model.groups, ("XMP".to_string(), "XMP-tiff".to_string()));

    let comp = model.tags.iter().find(|t| t.name == "Compression").unwrap();
    // `type` carries the writable KIND; `writable` is the boolean true/false.
    assert_eq!(comp.ty.as_deref(), Some("integer"));
    assert_eq!(comp.writable.as_deref(), Some("true"));
    let values = comp.values.as_ref().unwrap();
    // Only the lang='en' <val> is kept (one entry per key, not one per language).
    assert!(values.iter().any(|(k, v)| k == "1" && v == "Uncompressed"));
    assert!(values
      .iter()
      .any(|(k, v)| k == "6" && v == "JPEG (old-style)"));
    // Entity-decoded by the XML reader.
    assert!(values
      .iter()
      .any(|(k, v)| k == "9" && v == "JBIG B&W or VC-5"));
    assert_eq!(values.len(), 3);

    // A plain integer tag has no values map.
    let width = model.tags.iter().find(|t| t.name == "ImageWidth").unwrap();
    assert_eq!(width.ty.as_deref(), Some("integer"));
    assert!(width.values.is_none());

    // A plain string tag.
    let make = model.tags.iter().find(|t| t.name == "Make").unwrap();
    assert_eq!(make.ty.as_deref(), Some("string"));
    assert!(make.values.is_none());
  }
}
