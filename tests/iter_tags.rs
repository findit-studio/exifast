//! Public `AnyMeta::iter_tags` API (golden-pattern L4): the no-JSON generic
//! tag-extraction surface. Parses real fixtures through the public
//! `parse_bytes` entry, then asserts the yielded `value::Tag`s carry BOTH
//! family-0 and family-1 groups (the `-G1` JSON key drops family-0), that the
//! `File:ExifByteOrder` orchestration-vs-extracted tag is present for EXIF,
//! and that the de-duped set matches expectation.
#![cfg(all(feature = "exif", feature = "quicktime", feature = "std"))]

use exifast::{AnyMeta, ConvMode};

/// A standalone TIFF, parsed via the public API, yields its EXIF tag stream
/// through `iter_tags` with full `Group` (family-0 + family-1) populated:
/// `File:ExifByteOrder` (family-0 `File`, family-1 `File`) FIRST, then the
/// IFD0 camera tags (family-0 `EXIF`, family-1 `IFD0`).
#[test]
fn exif_iter_tags_carries_both_group_families() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Exif.tif"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data).expect("TIFF recognized");
  assert!(matches!(meta, AnyMeta::Exif(_)), "got {meta:?}");

  let tags: Vec<exifast::Tag> = meta.iter_tags(ConvMode::PrintConv).collect();
  assert!(!tags.is_empty(), "EXIF must yield tags");

  // EVERY tag carries non-empty family-0 AND family-1.
  for t in &tags {
    assert!(
      !t.group_ref().family0().is_empty(),
      "family-0 must be populated for {}: {:?}",
      t.name(),
      t.group_ref()
    );
    assert!(
      !t.group_ref().family1().is_empty(),
      "family-1 must be populated for {}: {:?}",
      t.name(),
      t.group_ref()
    );
  }

  // `File:ExifByteOrder` is the FIRST yielded tag (ExifTool.pm:8691), under
  // family-0 `File`, family-1 `File`, with the PrintConv string value. It is a
  // REAL extracted tag (carried by `iter_tags`), unlike the engine
  // orchestration triplet (`File:FileType`/version) added only by the JSON path.
  let first = &tags[0];
  assert_eq!(first.name(), "ExifByteOrder");
  assert_eq!(first.group_ref().family0(), "File");
  assert_eq!(first.group_ref().family1(), "File");
  assert_eq!(
    first.value_ref(),
    &exifast::TagValue::Str("Big-endian (Motorola, MM)".into()),
    "Exif.tif is big-endian (MM); PrintConv renders the long form"
  );

  // The camera identity tags sit under family-0 `EXIF`, family-1 `IFD0`.
  let make = tags
    .iter()
    .find(|t| t.name() == "Make")
    .expect("IFD0:Make present");
  assert_eq!(make.group_ref().family0(), "EXIF");
  assert_eq!(make.group_ref().family1(), "IFD0");

  // De-dup invariant: each (family1, name) key appears at most once (the same
  // identity the TagMap JSON sink dedups on).
  let mut keys: Vec<(String, String)> = tags
    .iter()
    .map(|t| (t.group_ref().family1().to_string(), t.name().to_string()))
    .collect();
  let total = keys.len();
  keys.sort();
  keys.dedup();
  assert_eq!(keys.len(), total, "no duplicate (family1, name) keys");

  // The orchestration tags the engine adds (NOT part of iter_tags): no
  // SourceFile, no File:FileType, no ExifTool:* diagnostics in the stream.
  assert!(
    !tags.iter().any(|t| t.name() == "SourceFile"
      || t.name() == "FileType"
      || t.group_ref().family1() == "ExifTool"),
    "iter_tags must exclude engine-orchestration + diagnostic tags"
  );

  // ValueConv mode renders the bare `II`/`MM` marker (ExifTool.pm:8691 `-n`).
  let raw: Vec<exifast::Tag> = meta.iter_tags(ConvMode::ValueConv).collect();
  let raw_first = &raw[0];
  assert_eq!(raw_first.name(), "ExifByteOrder");
  assert_eq!(
    raw_first.value_ref(),
    &exifast::TagValue::Str("MM".into()),
    "ValueConv (-n) is the bare marker"
  );
}

/// A QuickTime `.mov`, parsed via the public API, yields its tag stream with
/// the QuickTime family-0 group and the `QuickTime`/`Track<N>` family-1 groups.
#[test]
fn quicktime_iter_tags_carries_quicktime_groups() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/QuickTime_m4a.mov"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data).expect("QuickTime recognized");
  assert!(matches!(meta, AnyMeta::QuickTime(_)), "got {meta:?}");

  let tags: Vec<exifast::Tag> = meta.iter_tags(ConvMode::PrintConv).collect();
  assert!(!tags.is_empty(), "QuickTime must yield tags");

  // Every tag carries family-0 `QuickTime` and a non-empty family-1; the
  // family-1 is either the main `QuickTime` group or a per-track `Track<N>`.
  for t in &tags {
    assert_eq!(
      t.group_ref().family0(),
      "QuickTime",
      "family-0 must be QuickTime for {}",
      t.name()
    );
    assert!(
      !t.group_ref().family1().is_empty(),
      "family-1 must be populated for {}",
      t.name()
    );
  }

  // At least the main QuickTime group is present.
  assert!(
    tags.iter().any(|t| t.group_ref().family1() == "QuickTime"),
    "expected a family-1 `QuickTime` tag"
  );

  // De-dup invariant holds here too.
  let mut keys: Vec<(String, String)> = tags
    .iter()
    .map(|t| (t.group_ref().family1().to_string(), t.name().to_string()))
    .collect();
  let total = keys.len();
  keys.sort();
  keys.dedup();
  assert_eq!(keys.len(), total, "no duplicate (family1, name) keys");
}

/// ID3 frame tags expose family-0 `ID3` (the module group), NOT the family-1
/// frame group — matching bundled `exiftool -G0:1` (`ID3:ID3v2_3:Title`),
/// while `File:ID3Size` stays family-0 `File`. `-G1` JSON conformance keys only
/// on family-1, so this full-`Group` correctness is pinned here via
/// `iter_tags`. Regression guard for the round-1 Codex finding (the ID3
/// `Group::new(family1, family1)` mirror bug).
#[cfg(feature = "mp3")]
#[test]
fn id3_iter_tags_family0_is_id3_not_frame_group() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ID3v2_3.mp3"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data).expect("MP3 recognized");
  let tags: Vec<exifast::Tag> = meta.iter_tags(ConvMode::PrintConv).collect();

  // The ID3v2.3 frames carry family-0 `ID3`, family-1 `ID3v2_3`.
  let title = tags
    .iter()
    .find(|t| t.name() == "Title")
    .expect("ID3v2_3:Title present");
  assert_eq!(
    title.group_ref().family0(),
    "ID3",
    "ID3 frame family-0 is the module group, not the frame group"
  );
  assert_eq!(title.group_ref().family1(), "ID3v2_3");

  // EVERY ID3v* frame tag has family-0 `ID3` (never the family1==family0 mirror).
  for t in &tags {
    if t.group_ref().family1().starts_with("ID3v") {
      assert_eq!(
        t.group_ref().family0(),
        "ID3",
        "frame {} ({}) must be family-0 ID3",
        t.name(),
        t.group_ref().family1()
      );
    }
  }

  // `File:ID3Size` keeps family-0 `File` (exiftool `File:ID3Size`).
  if let Some(sz) = tags.iter().find(|t| t.name() == "ID3Size") {
    assert_eq!(sz.group_ref().family0(), "File");
    assert_eq!(sz.group_ref().family1(), "File");
  }
}

/// A chained ID3v1 trailer (Real RM) surfaces through the wrapper's `iter_tags`
/// with family-0 `ID3`, family-1 `ID3v1` (exiftool `ID3:ID3v1:*`) — proving the
/// family-0 fix propagates through `Id3v1Meta::tags()` chained by `real`, while
/// the Real container tags stay family-0 `Real`.
#[cfg(feature = "real")]
#[test]
fn chained_id3v1_iter_tags_family0_is_id3() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Real.rm"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data).expect("Real recognized");
  let tags: Vec<exifast::Tag> = meta.iter_tags(ConvMode::PrintConv).collect();

  // Container tags stay family-0 `Real`.
  assert!(
    tags.iter().any(|t| t.group_ref().family0() == "Real"),
    "expected Real container tags"
  );
  // The chained ID3v1 trailer: family-0 `ID3`, family-1 `ID3v1`.
  let id3v1: Vec<&exifast::Tag> = tags
    .iter()
    .filter(|t| t.group_ref().family1() == "ID3v1")
    .collect();
  assert!(!id3v1.is_empty(), "Real.rm carries a chained ID3v1 trailer");
  for t in id3v1 {
    assert_eq!(
      t.group_ref().family0(),
      "ID3",
      "chained ID3v1 {} must be family-0 ID3",
      t.name()
    );
  }
}

/// `iter_tags` (the public generic-extraction L4 API) yields the engine-built
/// `Composite:Duration` too — the same `Composite:*` set the JSON path produces.
/// FLAC_duration.flac: family-0/1 `Composite`, value `"0:00:30"` under `-j`, and
/// (as the post-pass append) the LAST tag in the stream.
#[cfg(feature = "flac")]
#[test]
fn flac_iter_tags_carries_engine_composite_duration() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/FLAC_duration.flac"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data).expect("FLAC recognized");

  let tags: Vec<exifast::Tag> = meta.iter_tags(ConvMode::PrintConv).collect();
  let dur = tags
    .iter()
    .find(|t| t.group_ref().family1() == "Composite" && t.name() == "Duration")
    .expect("iter_tags must yield the engine-built Composite:Duration");
  assert_eq!(dur.group_ref().family0(), "Composite");
  assert!(
    matches!(dur.value_ref(), exifast::TagValue::Str(s) if s == "0:00:30"),
    "got {:?}",
    dur.value_ref()
  );
  // The composite is appended last (positional last-ness).
  let last = tags.last().expect("non-empty");
  assert_eq!(last.name(), "Duration");
  assert_eq!(last.group_ref().family1(), "Composite");

  // -n: the raw f64 (30.0).
  let raw: Vec<exifast::Tag> = meta.iter_tags(ConvMode::ValueConv).collect();
  let dur_n = raw
    .iter()
    .find(|t| t.group_ref().family1() == "Composite" && t.name() == "Duration")
    .expect("Composite:Duration under -n");
  assert!(
    matches!(dur_n.value_ref(), exifast::TagValue::F64(x) if (*x - 30.0).abs() < 1e-9),
    "got {:?}",
    dur_n.value_ref()
  );
}
