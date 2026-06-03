// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Decide a tag's `PrintConv` representation from its `-listx` data: a
//! `<values>` map becomes an `IntMap` / `StrMap`; everything else is `Identity`
//! unless the curated [`HANDPORTED`] override pins it to a hand-written conv or
//! to [`Conv::Unported`] (a faithful raw passthrough for a code-valued conv we
//! have not ported yet).

/// The `PrintConv` representation the emitter should render for a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conv {
  /// No conversion — the print form equals the raw form (`P::Identity`).
  Identity,
  /// An integer-keyed lookup map (`P::IntMap`); the keys are emitted as `i64`.
  IntMap,
  /// A string-keyed lookup map (`P::StrMap`).
  StrMap,
  /// A code-valued ExifTool conv with no `-listx` map and no hand-written Rust
  /// counterpart yet (`P::Unported`); carries the source module (e.g. `"XMP"`)
  /// for the provenance string. Renders the raw value faithfully.
  Unported(&'static str),
}

/// Decide the `PrintConv` representation for a tag from its `-listx` data.
///
/// - a numeric-keyed `<values>` map → [`Conv::IntMap`]
/// - a string-keyed `<values>` map → [`Conv::StrMap`]
/// - no map → [`Conv::Identity`] (the declarative default — a code-valued
///   PrintConv/ValueConv is NOT present in `-listx`), UNLESS the curated
///   [`HANDPORTED`] list overrides it.
///
/// A tag whose ExifTool PrintConv is a CODE expression but whose `-listx`
/// shows no map will default to `Identity` here; the [`HANDPORTED`] set is the
/// only hand-maintained escape hatch — it pins such a tag to a hand-written
/// conv (still surfaced via `Identity` once ported) or to [`Conv::Unported`]
/// so an un-ported code conv is faithfully passed through, never guessed.
pub fn resolve_printconv(
  name: &str,
  values: &Option<Vec<(String, String)>>,
  _writable: Option<&str>,
) -> Conv {
  if let Some(v) = values {
    // `-listx` may legitimately emit a map with no rows; treat empty as no map.
    if v.is_empty() {
      // fall through to the override / Identity path
    } else if v.iter().all(|(k, _)| k.parse::<i64>().is_ok()) {
      return Conv::IntMap;
    } else {
      return Conv::StrMap;
    }
  }
  if let Some((_, conv)) = HANDPORTED.iter().find(|(n, _)| *n == name) {
    return conv.clone();
  }
  Conv::Identity
}

/// Curated overrides for the code-valued ~10% (faithful to ExifTool). Each
/// entry pins a map-less tag whose `-listx` type would otherwise default to
/// [`Conv::Identity`]:
/// - to [`Conv::Identity`] when the faithful rendering really IS the raw value
///   (e.g. `aux:NeutralDensityFactor` keeps its `"1/2"` verbatim — but that is
///   already the `Identity` default, so it needs NO entry here), or
/// - to [`Conv::Unported`] for a code-valued conv not yet hand-ported, so the
///   generated table flags it (compile-visible + oracle-checked) instead of
///   silently mis-converting (cf. the R5 `NeutralDensityFactor` bug class).
///
/// Hand-maintained; the generator emits exactly what this says. The leading
/// `__xtask_unported_probe__` row is a test fixture (no such ExifTool tag).
static HANDPORTED: &[(&str, Conv)] = &[("__xtask_unported_probe__", Conv::Unported("XMP"))];

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn maps_known_value_map_and_marks_unknown_unported() {
    // A tag with a numeric-keyed -listx <values> map → IntMap.
    let comp_map = Some(vec![
      ("1".to_string(), "Uncompressed".to_string()),
      ("6".to_string(), "JPEG (old-style)".to_string()),
    ]);
    assert_eq!(
      resolve_printconv("Compression", &comp_map, Some("integer")),
      Conv::IntMap
    );

    // A string-keyed map (e.g. a GPS ref-letter lookup) → StrMap.
    let gps_status = Some(vec![
      ("A".to_string(), "Measurement Active".to_string()),
      ("V".to_string(), "Measurement Void".to_string()),
    ]);
    assert_eq!(
      resolve_printconv("GPSStatus", &gps_status, Some("string")),
      Conv::StrMap
    );

    // A plain string tag, no map, no override → Identity.
    assert_eq!(
      resolve_printconv("Lens", &None, Some("string")),
      Conv::Identity
    );

    // A HANDPORTED override pins a code-valued, map-less tag to Unported so it
    // is never silently mis-converted (it is not present in -listx).
    assert_eq!(
      resolve_printconv("__xtask_unported_probe__", &None, None),
      Conv::Unported("XMP")
    );
  }
}
