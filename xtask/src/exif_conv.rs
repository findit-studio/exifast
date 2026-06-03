// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Resolve an `Exif::Main` / `GPS::Main` `-listx` tag to the EXIF module's OWN
//! conversion vocabulary (`src/exif/tables.rs` [`Conv`] /
//! `src/exif/gps.rs` [`GpsConv`]), for the `--kind exif` emit target.
//!
//! Unlike the generic `tagtable::TagDef` vocabulary (`conv_registry.rs`), the
//! EXIF tables carry ~21 bespoke `Conv` variants — the code-valued
//! `sprintf`/`RawConv` formatters (`ExposureTime`, `FNumber`, `Version`, …) AND
//! a set of `IntLabel` PrintConv slices that are deliberately CURATED
//! camera-relevant SUBSETS of the full ExifTool maps (the hand `COMPRESSION`
//! slice has 13 entries vs `-listx`'s 53). `-listx` carries neither the
//! code-valued ValueConv/PrintConv NOR the `PrintHex` flag NOR the curated
//! subset, so those ids resolve through a hand-maintained [`ExifHandported`] /
//! [`GpsHandported`] override; everything else (plain tags → `Conv::None`;
//! label maps whose `<values>` already MATCH the hand slice, set-for-set →
//! `Conv::IntLabel`/`StrLabel` from `-listx`) derives declaratively.
//!
//! Step A is a BYTE-IDENTICAL shadow restricted to the current hand id set, so
//! the resolver's only job is to reproduce the hand `Conv`/`GpsConv` for each
//! shared id; the per-id differential parity test in the lib is the gate.

use crate::listx::TagModel;

/// One resolved EXIF/GPS tag row to emit: the tag NAME and the rendered
/// `Conv` / `GpsConv` Rust expression (verbatim source the emitter writes into
/// the `conv:` field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
  /// The emitted tag NAME.
  pub name: String,
  /// The `conv` field expression, e.g. `Conv::ExposureTime`,
  /// `Conv::IntLabel(&[(1, "Uncompressed")])`, `super::COMPRESSION` references.
  pub conv_expr: String,
}

// ===========================================================================
// EXIF (`Exif::Main`) HANDPORTED overrides
// ===========================================================================

/// A hand-maintained override for one `Exif::Main` id whose hand `Conv` cannot
/// be derived from `-listx` declaratively. Five shapes are pinned:
///
/// 1. **code-valued** convs — the `sprintf`/`RawConv` formatters ExifTool
///    expresses as Perl code (no `<values>` map in `-listx`):
///    `ExposureTime`/`FNumber`/`Version`/`DateTime`/`ApertureApex`/… ;
/// 2. **subset / variant label maps** — the curated camera-relevant
///    `IntLabel` slices that are a strict SUBSET of (or carry different labels
///    than) the full `-listx` map (`Compression`, `LightSource`,
///    `SensingMethod`, `Sharpness`→`CONTRAST`, …) and the two `PrintHex`
///    (`IntLabelHex`) maps (`Flash`, `ColorSpace`) — `-listx` omits the
///    `PrintHex` flag; these pin the conv to the existing hand const so the
///    shadow reuses the SAME curated slice;
/// 3. **order-bearing string map** — `InteropIndex` (0x0001): the hand
///    `INTEROP_INDEX` `StrLabel` slice is curated in a DIFFERENT key order than
///    `-listx` emits, so it is pinned to the hand const for a byte-identical
///    (and order-stable) shadow;
/// 4. **map suppression** — `SensitivityType` (0x8830): `-listx` carries a
///    `<values>` enumeration the hand subset deliberately does NOT apply, so it
///    is pinned to `Conv::None` rather than the derived `IntLabel`;
/// 5. **name-only** overrides — the four conditional ids whose `-listx` name is
///    a DIFFERENT `Condition` branch than the hand table's default name
///    (`0x0111` `JpgFromRawStart`→`StripOffsets`, `0x0117`
///    `JpgFromRawLength`→`StripByteCounts`, `0x0201`
///    `OtherImageStart`→`ThumbnailOffset`, `0x0202`
///    `OtherImageLength`→`ThumbnailLength`); their `Conv` is the auto-derived
///    `Conv::None`, so `conv` is `None` here and only the name is overridden.
struct ExifHandported {
  /// The on-disk tag id.
  id: u16,
  /// Override the emitted name (the `-listx` name is a different `Condition`
  /// branch); `None` keeps the `-listx` name.
  name: Option<&'static str>,
  /// The `conv` expression, or `None` to keep the auto-derived conv (used by
  /// the name-only overrides whose conv is the declarative `Conv::None`).
  conv_expr: Option<&'static str>,
}

/// The curated `Exif::Main` overrides (Step-A faithful shadow). Hand-maintained;
/// the generator emits exactly what this says. The const references (e.g.
/// `super::COMPRESSION`) resolve in the generated child module of
/// `src/exif/tables.rs`, so the shadow reuses the hand table's curated slices
/// byte-for-byte rather than re-deriving the (larger) full `-listx` map.
static EXIF_HANDPORTED: &[ExifHandported] = &[
  // ---- string-keyed PrintConv slice whose hand order differs from `-listx` --
  // `InteropIndex` (0x0001): the hand `INTEROP_INDEX` slice is curated in the
  // order R98/R03/THM, but `-listx` emits the `<values>` keys in a DIFFERENT
  // order (R03/R98/THM). The `Conv::StrLabel` slice is order-bearing source, so
  // pin it to the hand const to reuse its exact byte order (a hit is a linear
  // first-match either way, but byte-identical emit requires the hand order).
  hp(0x0001, "Conv::StrLabel(super::INTEROP_INDEX)"),
  // ---- `-listx`-has-a-map-but-hand-is-`None` (SensitivityType) -------------
  // `SensitivityType` (0x8830): `-listx` carries the full `%sensitivityType`
  // enumeration, but the hand `%Exif::Main` subset deliberately leaves this tag
  // as a plain numeric `Conv::None` (no PrintConv). Pin it to `Conv::None` so
  // the shadow does NOT pick up the (unported) `-listx` map.
  hp(0x8830, "Conv::None"),
  // ---- subset / variant `IntLabel` PrintConv slices (Exif.pm) -------------
  hp(0x00fe, "Conv::IntLabel(super::SUBFILE_TYPE)"),
  hp(0x0103, "Conv::IntLabel(super::COMPRESSION)"),
  hp(0x0106, "Conv::IntLabel(super::PHOTOMETRIC)"),
  hp(0x013d, "Conv::IntLabel(super::PREDICTOR)"),
  hp(0x9208, "Conv::IntLabel(super::LIGHT_SOURCE)"),
  hp(0xa210, "Conv::IntLabel(super::RESOLUTION_UNIT)"),
  hp(0xa217, "Conv::IntLabel(super::SENSING_METHOD)"),
  hp(0xa300, "Conv::IntLabel(super::FILE_SOURCE)"),
  hp(0xa40a, "Conv::IntLabel(super::CONTRAST)"),
  // ---- `PrintHex` (IntLabelHex) maps — `-listx` omits the PrintHex flag ----
  hp(0x9209, "Conv::IntLabelHex(super::FLASH)"),
  hp(0xa001, "Conv::IntLabelHex(super::COLOR_SPACE)"),
  // ---- code-valued sprintf / RawConv / ValueConv formatters ---------------
  hp(0x010f, "Conv::TrimTrailingWhitespace"), // Make
  hp(0x0110, "Conv::TrimTrailingWhitespace"), // Model
  hp(0x0131, "Conv::TrimTrailingWhitespace"), // Software
  hp(0x013b, "Conv::TrimTrailingWhitespace"), // Artist
  hp(0x0132, "Conv::DateTime"),               // ModifyDate
  hp(0x829a, "Conv::ExposureTime"),
  hp(0x829d, "Conv::FNumber"),
  hp(0x9000, "Conv::Version"),  // ExifVersion
  hp(0x9003, "Conv::DateTime"), // DateTimeOriginal
  hp(0x9004, "Conv::DateTime"), // CreateDate
  hp(0x9101, "Conv::ComponentsConfiguration"),
  hp(0x9201, "Conv::ShutterSpeedApex"),
  hp(0x9202, "Conv::ApertureApex"),
  hp(0x9204, "Conv::ExposureCompensation"),
  hp(0x9205, "Conv::ApertureApex"), // MaxApertureValue
  hp(0x9206, "Conv::MetersSuffix"), // SubjectDistance
  hp(0x920a, "Conv::FocalLengthMm"),
  hp(0x9286, "Conv::ExifText"),           // UserComment
  hp(0x9290, "Conv::TrimTrailingSpaces"), // SubSecTime
  hp(0x9291, "Conv::TrimTrailingSpaces"), // SubSecTimeOriginal
  hp(0x9292, "Conv::TrimTrailingSpaces"), // SubSecTimeDigitized
  hp(0xa000, "Conv::Version"),            // FlashpixVersion
  hp(0xa405, "Conv::FocalLength35mm"),
  hp(0xa432, "Conv::LensInfo"),
  hp(0x0002, "Conv::Version"), // InteropVersion
  // ---- name-only overrides (conditional ids; conv auto-derives `None`) -----
  hp_name(0x0111, "StripOffsets"),
  hp_name(0x0117, "StripByteCounts"),
  hp_name(0x0201, "ThumbnailOffset"),
  hp_name(0x0202, "ThumbnailLength"),
];

/// A conv-override entry (keep the `-listx` name).
const fn hp(id: u16, conv_expr: &'static str) -> ExifHandported {
  ExifHandported {
    id,
    name: None,
    conv_expr: Some(conv_expr),
  }
}

/// A name-only override entry (conv auto-derives to `Conv::None`).
const fn hp_name(id: u16, name: &'static str) -> ExifHandported {
  ExifHandported {
    id,
    name: Some(name),
    conv_expr: None,
  }
}

/// Resolve one `Exif::Main` tag to its emitted name + `Conv` expression.
///
/// Precedence (faithful to the hand `EXIF_TAGS`):
/// 1. an [`EXIF_HANDPORTED`] entry pins the name and/or the conv;
/// 2. otherwise an int-keyed `<values>` map → `Conv::IntLabel(&[…])`, a
///    string-keyed `<values>` map → `Conv::StrLabel(&[…])` (the maps that
///    already MATCH the hand slice set-for-set), emitted inline from `-listx`;
/// 3. otherwise `Conv::None` (a plain tag).
pub fn resolve_exif(id: u16, t: &TagModel) -> Resolved {
  let over = EXIF_HANDPORTED.iter().find(|h| h.id == id);
  let name = over
    .and_then(|h| h.name)
    .map(str::to_string)
    .unwrap_or_else(|| t.name.clone());
  if let Some(expr) = over.and_then(|h| h.conv_expr) {
    return Resolved {
      name,
      conv_expr: expr.to_string(),
    };
  }
  let conv_expr = match label_values(t) {
    Some(LabelKind::Int(rows)) => format!("Conv::IntLabel(&[{}])", int_rows(&rows)),
    Some(LabelKind::Str(rows)) => format!("Conv::StrLabel(&[{}])", str_rows(&rows)),
    None => "Conv::None".to_string(),
  };
  Resolved { name, conv_expr }
}

// ===========================================================================
// GPS (`GPS::Main`) HANDPORTED overrides
// ===========================================================================

/// A hand-maintained `GPS::Main` override. `GPS::Main` is ~⅓ code-valued — the
/// coordinate / timestamp / datestamp / version / text formatters ExifTool
/// expresses as Perl (`%coordConv`, `ConvertTimeStamp`, `ExifDate`,
/// `tr/ /./`, `ConvertExifText`) plus the two `GPSAltitude`-style
/// `Conv::MetersSuffix` wrappers; `-listx` carries no map for any of these.
/// The remaining GPS tags derive declaratively: a string-keyed `<values>` map
/// → `GpsConv::StrLabel(&[…])`, an int-keyed map → `GpsConv::Plain(Conv::
/// IntLabel(&[…]))`, no map → `GpsConv::Plain(Conv::None)`. (All GPS names
/// match `-listx`, so there are no name-only overrides here.) One extra pin:
/// `GPSMeasureMode` (0x000a), whose on-disk value is an ASCII string so the
/// hand table keys it by the STRING tokens `"2"`/`"3"` — `-listx` reports those
/// keys bare (looking int-keyed), so it is pinned to the hand `StrLabel` const.
struct GpsHandported {
  /// The on-disk tag id.
  id: u16,
  /// The `GpsConv` expression.
  conv_expr: &'static str,
}

/// The curated `GPS::Main` code-valued overrides (Step-A faithful shadow).
static GPS_HANDPORTED: &[GpsHandported] = &[
  // `GPSMeasureMode` (0x000a): the on-disk value is an ASCII string, so the
  // hand table keys the map by the STRING tokens `"2"`/`"3"`
  // (`GpsConv::StrLabel`, `GPS.pm:179-182`). `-listx` reports the keys bare
  // (`2`/`3`), which the declarative classifier would read as INT keys →
  // `Plain(Conv::IntLabel(…))`. Pin it to the hand string-keyed const so the
  // shadow keeps the faithful string-keyed lookup byte-for-byte.
  gp(0x000a, "GpsConv::StrLabel(super::GPS_MEASURE_MODE)"),
  gp(0x0000, "GpsConv::VersionId"),  // GPSVersionID — tr/ /./
  gp(0x0002, "GpsConv::Coordinate"), // GPSLatitude
  gp(0x0004, "GpsConv::Coordinate"), // GPSLongitude
  gp(0x0006, "GpsConv::Plain(Conv::MetersSuffix)"), // GPSAltitude
  gp(0x0007, "GpsConv::TimeStamp"),  // GPSTimeStamp
  gp(0x0014, "GpsConv::Coordinate"), // GPSDestLatitude
  gp(0x0016, "GpsConv::Coordinate"), // GPSDestLongitude
  gp(0x001b, "GpsConv::ExifText"),   // GPSProcessingMethod
  gp(0x001c, "GpsConv::ExifText"),   // GPSAreaInformation
  gp(0x001d, "GpsConv::DateStamp"),  // GPSDateStamp
  gp(0x001f, "GpsConv::Plain(Conv::MetersSuffix)"), // GPSHPositioningError
];

/// A GPS conv-override entry.
const fn gp(id: u16, conv_expr: &'static str) -> GpsHandported {
  GpsHandported { id, conv_expr }
}

/// Resolve one `GPS::Main` tag to its emitted name + `GpsConv` expression.
///
/// Precedence (faithful to the hand `GPS_TAGS`):
/// 1. a [`GPS_HANDPORTED`] entry pins the (code-valued) conv;
/// 2. otherwise a string-keyed `<values>` map → `GpsConv::StrLabel(&[…])`;
/// 3. otherwise an int-keyed `<values>` map →
///    `GpsConv::Plain(Conv::IntLabel(&[…]))`;
/// 4. otherwise `GpsConv::Plain(Conv::None)`.
pub fn resolve_gps(id: u16, t: &TagModel) -> Resolved {
  let name = t.name.clone();
  if let Some(h) = GPS_HANDPORTED.iter().find(|h| h.id == id) {
    return Resolved {
      name,
      conv_expr: h.conv_expr.to_string(),
    };
  }
  let conv_expr = match label_values(t) {
    Some(LabelKind::Str(rows)) => format!("GpsConv::StrLabel(&[{}])", str_rows(&rows)),
    Some(LabelKind::Int(rows)) => {
      format!("GpsConv::Plain(Conv::IntLabel(&[{}]))", int_rows(&rows))
    }
    None => "GpsConv::Plain(Conv::None)".to_string(),
  };
  Resolved { name, conv_expr }
}

// ===========================================================================
// `<values>` classification + slice rendering
// ===========================================================================

/// A classified `<values>` map: an all-int-keyed map or a string-keyed map.
enum LabelKind {
  Int(Vec<(i64, String)>),
  Str(Vec<(String, String)>),
}

/// Classify a tag's `<values>` block: every key parses as `i64` → [`LabelKind::Int`]
/// (the int enumeration PrintConv); otherwise [`LabelKind::Str`] (the string-keyed
/// `InteropIndex` / GPS ref-letter shape). An absent or empty map → `None` (a plain
/// tag). A key that does NOT round-trip to a clean decimal `i64` (e.g. the Sigma
/// `FileSource` binary key `"\x03\x00\x00\x00"`) is treated as a string key — but
/// every such id is pinned in HANDPORTED, so this path only ever sees clean keys.
fn label_values(t: &TagModel) -> Option<LabelKind> {
  let rows = t.values.as_ref()?;
  if rows.is_empty() {
    return None;
  }
  let parsed: Option<Vec<(i64, String)>> = rows
    .iter()
    .map(|(k, v)| k.parse::<i64>().ok().map(|n| (n, v.clone())))
    .collect();
  match parsed {
    Some(ints) => Some(LabelKind::Int(ints)),
    None => Some(LabelKind::Str(rows.clone())),
  }
}

/// Render int-keyed `(code, "label")` rows as the body of an `&[(i64, &str)]`
/// slice literal (the hand `IntLabel` representation). `{v:?}` is the Rust
/// string-escape, matching the hand table's source form.
fn int_rows(rows: &[(i64, String)]) -> String {
  rows
    .iter()
    .map(|(k, v)| format!("({k}, {v:?})"))
    .collect::<Vec<_>>()
    .join(", ")
}

/// Render string-keyed `("key", "label")` rows as the body of an
/// `&[(&str, &str)]` slice literal (the hand `StrLabel` representation).
fn str_rows(rows: &[(String, String)]) -> String {
  rows
    .iter()
    .map(|(k, v)| format!("({k:?}, {v:?})"))
    .collect::<Vec<_>>()
    .join(", ")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::listx::TagModel;

  fn tag(id: &str, name: &str, values: Option<Vec<(&str, &str)>>) -> TagModel {
    TagModel {
      id: id.to_string(),
      name: name.to_string(),
      ty: Some("int16u".to_string()),
      writable: Some("true".to_string()),
      values: values.map(|v| {
        v.into_iter()
          .map(|(k, val)| (k.to_string(), val.to_string()))
          .collect()
      }),
    }
  }

  #[test]
  fn exif_plain_tag_is_none() {
    let r = resolve_exif(0x0100, &tag("256", "ImageWidth", None));
    assert_eq!(r.name, "ImageWidth");
    assert_eq!(r.conv_expr, "Conv::None");
  }

  #[test]
  fn exif_matching_int_map_emits_inline_slice() {
    // Orientation (0x0112): the `<values>` already match the hand slice, so the
    // map is emitted inline from `-listx` (NOT via HANDPORTED).
    let r = resolve_exif(
      0x0112,
      &tag(
        "274",
        "Orientation",
        Some(vec![
          ("1", "Horizontal (normal)"),
          ("2", "Mirror horizontal"),
        ]),
      ),
    );
    assert_eq!(
      r.conv_expr,
      r#"Conv::IntLabel(&[(1, "Horizontal (normal)"), (2, "Mirror horizontal")])"#
    );
  }

  #[test]
  fn exif_subset_map_pins_to_hand_const() {
    // Compression (0x0103): the `<values>` have 53 rows but the hand slice is a
    // curated 13-row subset → HANDPORTED pins it to `super::COMPRESSION`, and
    // the inline `-listx` map is IGNORED.
    let r = resolve_exif(
      0x0103,
      &tag("259", "Compression", Some(vec![("1", "Uncompressed")])),
    );
    assert_eq!(r.conv_expr, "Conv::IntLabel(super::COMPRESSION)");
  }

  #[test]
  fn exif_print_hex_map_pins_to_hand_const() {
    // Flash (0x9209) carries `PrintHex => 1`, which `-listx` omits → HANDPORTED
    // pins `Conv::IntLabelHex(super::FLASH)`.
    let r = resolve_exif(
      0x9209,
      &tag("37385", "Flash", Some(vec![("0", "No Flash")])),
    );
    assert_eq!(r.conv_expr, "Conv::IntLabelHex(super::FLASH)");
  }

  #[test]
  fn exif_code_valued_pins_conv() {
    assert_eq!(
      resolve_exif(0x829a, &tag("33434", "ExposureTime", None)).conv_expr,
      "Conv::ExposureTime"
    );
    assert_eq!(
      resolve_exif(0x9000, &tag("36864", "ExifVersion", None)).conv_expr,
      "Conv::Version"
    );
  }

  #[test]
  fn exif_interop_index_pins_to_hand_const_for_stable_order() {
    // InteropIndex (0x0001): `-listx` emits the keys in a different order than
    // the curated hand `INTEROP_INDEX` slice → pin to `super::INTEROP_INDEX`
    // (the inline `-listx` map is IGNORED) for a byte-identical, order-stable
    // shadow.
    let r = resolve_exif(
      0x0001,
      &tag("1", "InteropIndex", Some(vec![("R03", "…"), ("R98", "…")])),
    );
    assert_eq!(r.name, "InteropIndex");
    assert_eq!(r.conv_expr, "Conv::StrLabel(super::INTEROP_INDEX)");
  }

  #[test]
  fn exif_sensitivity_type_suppresses_listx_map() {
    // SensitivityType (0x8830): `-listx` carries the full enumeration, but the
    // hand subset leaves it `Conv::None` → the HANDPORTED pin wins over the
    // derived `IntLabel`.
    let r = resolve_exif(
      0x8830,
      &tag("33866", "SensitivityType", Some(vec![("0", "Unknown")])),
    );
    assert_eq!(r.conv_expr, "Conv::None");
  }

  #[test]
  fn gps_measure_mode_pins_string_keyed_const() {
    // GPSMeasureMode (0x000a): the on-disk value is an ASCII string, so the
    // hand table keys it by `"2"`/`"3"` (`GpsConv::StrLabel`); `-listx` reports
    // the keys bare (int-looking) → pin to the hand string-keyed const.
    let r = resolve_gps(
      0x000a,
      &tag(
        "10",
        "GPSMeasureMode",
        Some(vec![("2", "2-Dimensional Measurement")]),
      ),
    );
    assert_eq!(r.conv_expr, "GpsConv::StrLabel(super::GPS_MEASURE_MODE)");
  }

  #[test]
  fn exif_name_only_override_keeps_none_conv() {
    // 0x0111: `-listx` says `JpgFromRawStart`; the hand default is `StripOffsets`
    // and the conv is the auto-derived `Conv::None`.
    let r = resolve_exif(0x0111, &tag("273", "JpgFromRawStart", None));
    assert_eq!(r.name, "StripOffsets");
    assert_eq!(r.conv_expr, "Conv::None");
  }

  #[test]
  fn gps_string_ref_map_emits_strlabel() {
    // GPSStatus (0x0009): string-keyed `<values>` → `GpsConv::StrLabel(&[…])`.
    let r = resolve_gps(
      0x0009,
      &tag(
        "9",
        "GPSStatus",
        Some(vec![("A", "Measurement Active"), ("V", "Measurement Void")]),
      ),
    );
    assert_eq!(
      r.conv_expr,
      r#"GpsConv::StrLabel(&[("A", "Measurement Active"), ("V", "Measurement Void")])"#
    );
  }

  #[test]
  fn gps_int_map_emits_plain_intlabel() {
    // GPSAltitudeRef (0x0005): int-keyed `<values>` → `Plain(Conv::IntLabel)`.
    let r = resolve_gps(
      0x0005,
      &tag(
        "5",
        "GPSAltitudeRef",
        Some(vec![("0", "Above Sea Level"), ("1", "Below Sea Level")]),
      ),
    );
    assert_eq!(
      r.conv_expr,
      r#"GpsConv::Plain(Conv::IntLabel(&[(0, "Above Sea Level"), (1, "Below Sea Level")]))"#
    );
  }

  #[test]
  fn gps_code_valued_pins_conv() {
    assert_eq!(
      resolve_gps(0x0002, &tag("2", "GPSLatitude", None)).conv_expr,
      "GpsConv::Coordinate"
    );
    assert_eq!(
      resolve_gps(0x0000, &tag("0", "GPSVersionID", None)).conv_expr,
      "GpsConv::VersionId"
    );
    assert_eq!(
      resolve_gps(0x0006, &tag("6", "GPSAltitude", None)).conv_expr,
      "GpsConv::Plain(Conv::MetersSuffix)"
    );
  }

  #[test]
  fn gps_plain_tag_is_plain_none() {
    assert_eq!(
      resolve_gps(0x0008, &tag("8", "GPSSatellites", None)).conv_expr,
      "GpsConv::Plain(Conv::None)"
    );
  }
}
