// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Apple iOS MakerNotes tag table — `%Image::ExifTool::Apple::Main`
//! (`Apple.pm:24-320`). Phase-2 port.
//!
//! Faithful subset:
//!
//! - Every named tag in `%Image::ExifTool::Apple::Main` with a clearly
//!   typed Format is ported (the commented-out long-tail tags 0x0009,
//!   0x000d, 0x000e, 0x0010, 0x0012-0x0013, 0x0016, 0x0018, 0x001b,
//!   0x001c-0x001e, 0x0022, 0x0024, 0x0028-0x002A, 0x002C, 0x0031-0x0037,
//!   0x0039-0x003C, 0x0043-0x004B are STILL all commented out in
//!   bundled Apple.pm and are not extracted by ExifTool either — they
//!   stay deferred here too).
//! - The `ConvertPLIST` ValueConv tags (0x0002, 0x003E, 0x0040, 0x0041,
//!   0x0042, 0x004E, 0x004F, 0x0054, 0x005A) emit RAW BYTES — the PLIST
//!   sub-parser is a separate port (file follow-up issue from Phase 2).
//! - The `0x0003 → RunTime` sub-table (`Apple.pm:42`) emits raw bytes —
//!   the PLIST CMTime sub-parser is deferred (file follow-up issue).

#![deny(clippy::indexing_slicing)]

use super::printconv::ApplePrintConv;

/// Apple MakerNote leaf tag — `(id, name, print_conv, unknown)`.
///
/// D8: no public fields — accessors only.
#[derive(Debug, Clone, Copy)]
pub struct AppleTag {
  /// Apple IFD tag ID (`Apple.pm`'s top-level hash key).
  id: u16,
  /// `Name => '…'` from bundled.
  name: &'static str,
  /// PrintConv table (or `None` for raw value).
  conv: ApplePrintConv,
  /// `Unknown => 1` in bundled. ExifTool (`ExifTool.pm:9179-9185`)
  /// suppresses such tags in default output (no `-u`/Verbose/HTML/Validate),
  /// so the `-j -G1` golden OMITS them; the emission builder skips them.
  unknown: bool,
}

impl AppleTag {
  /// Apple IFD tag ID.
  #[must_use]
  #[inline(always)]
  pub const fn id(&self) -> u16 {
    self.id
  }

  /// Tag `Name` (`Apple.pm` `Name => '…'`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// PrintConv strategy.
  #[must_use]
  #[inline(always)]
  pub const fn conv(&self) -> ApplePrintConv {
    self.conv
  }

  /// `true` when bundled marks this tag `Unknown => 1` — suppressed in
  /// the default (`-j`, no `-u`) output (`ExifTool.pm:9179-9185`).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// `%Image::ExifTool::Apple::Main` (`Apple.pm:24-320`). Sorted by tag ID
/// for binary-search lookup. Entries cite the bundled line.
pub const APPLE_TAGS: &[AppleTag] = &[
  // 0x0001 — MakerNoteVersion (Apple.pm:30-33)
  AppleTag {
    id: 0x0001,
    name: "MakerNoteVersion",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0002 — AEMatrix (Apple.pm:34-39) — binary PLIST.
  AppleTag {
    id: 0x0002,
    name: "AEMatrix",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:36 `Unknown => 1`
  },
  // 0x0003 — RunTime (Apple.pm:40-43) — PLIST CMTime sub-directory.
  AppleTag {
    id: 0x0003,
    name: "RunTime",
    conv: ApplePrintConv::PlistDeferred,
    unknown: false,
  },
  // 0x0004 — AEStable (Apple.pm:44-48). PrintConv {0=>'No',1=>'Yes'}.
  AppleTag {
    id: 0x0004,
    name: "AEStable",
    conv: ApplePrintConv::NoYes,
    unknown: false,
  },
  // 0x0005 — AETarget (Apple.pm:49-52).
  AppleTag {
    id: 0x0005,
    name: "AETarget",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0006 — AEAverage (Apple.pm:53-56).
  AppleTag {
    id: 0x0006,
    name: "AEAverage",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0007 — AFStable (Apple.pm:57-61). PrintConv {0=>'No',1=>'Yes'}.
  AppleTag {
    id: 0x0007,
    name: "AFStable",
    conv: ApplePrintConv::NoYes,
    unknown: false,
  },
  // 0x0008 — AccelerationVector (Apple.pm:62-78). 3 rational64s.
  AppleTag {
    id: 0x0008,
    name: "AccelerationVector",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x000a — HDRImageType (Apple.pm:80-88).
  AppleTag {
    id: 0x000a,
    name: "HDRImageType",
    conv: ApplePrintConv::HdrImageType,
    unknown: false,
  },
  // 0x000b — BurstUUID (Apple.pm:89-93).
  AppleTag {
    id: 0x000b,
    name: "BurstUUID",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x000c — FocusDistanceRange (Apple.pm:94-103) — 2-element rational64s.
  AppleTag {
    id: 0x000c,
    name: "FocusDistanceRange",
    conv: ApplePrintConv::FocusDistanceRange,
    unknown: false,
  },
  // 0x000f — OISMode (Apple.pm:106-110).
  AppleTag {
    id: 0x000f,
    name: "OISMode",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0011 — ContentIdentifier (Apple.pm:112-119).
  AppleTag {
    id: 0x0011,
    name: "ContentIdentifier",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0014 — ImageCaptureType (Apple.pm:122-133).
  AppleTag {
    id: 0x0014,
    name: "ImageCaptureType",
    conv: ApplePrintConv::ImageCaptureType,
    unknown: false,
  },
  // 0x0015 — ImageUniqueID (Apple.pm:134-137).
  AppleTag {
    id: 0x0015,
    name: "ImageUniqueID",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0017 — LivePhotoVideoIndex (Apple.pm:139-142).
  AppleTag {
    id: 0x0017,
    name: "LivePhotoVideoIndex",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0019 — ImageProcessingFlags (Apple.pm:144-149) — `Unknown => 1`, so
  // SUPPRESSED in default output; conv is the default (`None`) since the
  // empty-BITMASK PrintConv (`{ BITMASK => {} }`) is never reached.
  AppleTag {
    id: 0x0019,
    name: "ImageProcessingFlags",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:147 `Unknown => 1`
  },
  // 0x001a — QualityHint (Apple.pm:150-155).
  AppleTag {
    id: 0x001a,
    name: "QualityHint",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:153 `Unknown => 1`
  },
  // 0x001d — LuminanceNoiseAmplitude (Apple.pm:159-162).
  AppleTag {
    id: 0x001d,
    name: "LuminanceNoiseAmplitude",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x001f — PhotosAppFeatureFlags (Apple.pm:164-168).
  AppleTag {
    id: 0x001f,
    name: "PhotosAppFeatureFlags",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0020 — ImageCaptureRequestID (Apple.pm:169-173).
  AppleTag {
    id: 0x0020,
    name: "ImageCaptureRequestID",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:172 `Unknown => 1`
  },
  // 0x0021 — HDRHeadroom (Apple.pm:174-177).
  AppleTag {
    id: 0x0021,
    name: "HDRHeadroom",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0023 — AFPerformance (Apple.pm:179-189) — sprintf "%d %d %d".
  AppleTag {
    id: 0x0023,
    name: "AFPerformance",
    conv: ApplePrintConv::AfPerformance,
    unknown: false,
  },
  // 0x0025 — SceneFlags (Apple.pm:192-197) — `Unknown => 1`, so SUPPRESSED
  // in default output; conv is the default (`None`) since the empty-BITMASK
  // PrintConv (`{ BITMASK => {} }`) is never reached.
  AppleTag {
    id: 0x0025,
    name: "SceneFlags",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:195 `Unknown => 1`
  },
  // 0x0026 — SignalToNoiseRatioType (Apple.pm:198-202).
  AppleTag {
    id: 0x0026,
    name: "SignalToNoiseRatioType",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:201 `Unknown => 1`
  },
  // 0x0027 — SignalToNoiseRatio (Apple.pm:203-206).
  AppleTag {
    id: 0x0027,
    name: "SignalToNoiseRatio",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x002b — PhotoIdentifier (Apple.pm:210-213).
  AppleTag {
    id: 0x002b,
    name: "PhotoIdentifier",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x002d — ColorTemperature (Apple.pm:216-219). NOTE: Apple.pm has a
  // hex/upper-case duplicate of 0x002D as 0x002d in the PLIST-ValueConv form.
  // Bundled's hash uses the LOWER-CASE 0x002d (int32s), the upper-case
  // entry is commented out. The port keeps the int32s decoding.
  AppleTag {
    id: 0x002d,
    name: "ColorTemperature",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x002e — CameraType (Apple.pm:221-229).
  AppleTag {
    id: 0x002e,
    name: "CameraType",
    conv: ApplePrintConv::CameraType,
    unknown: false,
  },
  // 0x002F — FocusPosition (Apple.pm:231-234).
  AppleTag {
    id: 0x002F,
    name: "FocusPosition",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0030 — HDRGain (Apple.pm:235-238).
  AppleTag {
    id: 0x0030,
    name: "HDRGain",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x0038 — AFMeasuredDepth (Apple.pm:248-252).
  AppleTag {
    id: 0x0038,
    name: "AFMeasuredDepth",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x003D — AFConfidence (Apple.pm:259-262).
  AppleTag {
    id: 0x003D,
    name: "AFConfidence",
    conv: ApplePrintConv::None,
    unknown: false,
  },
  // 0x003E — ColorCorrectionMatrix (Apple.pm:263-267) — PLIST.
  AppleTag {
    id: 0x003E,
    name: "ColorCorrectionMatrix",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:265 `Unknown => 1`
  },
  // 0x003F — GreenGhostMitigationStatus (Apple.pm:268-272).
  AppleTag {
    id: 0x003F,
    name: "GreenGhostMitigationStatus",
    conv: ApplePrintConv::None,
    unknown: true, // Apple.pm:271 `Unknown => 1`
  },
  // 0x0040 — SemanticStyle (Apple.pm:273-277) — PLIST; raw.
  AppleTag {
    id: 0x0040,
    name: "SemanticStyle",
    conv: ApplePrintConv::PlistDeferred,
    unknown: false,
  },
  // 0x0041 — SemanticStyleRenderingVer (Apple.pm:278-281) — PLIST; raw.
  AppleTag {
    id: 0x0041,
    name: "SemanticStyleRenderingVer",
    conv: ApplePrintConv::PlistDeferred,
    unknown: false,
  },
  // 0x0042 — SemanticStylePreset (Apple.pm:282-285) — PLIST; raw.
  AppleTag {
    id: 0x0042,
    name: "SemanticStylePreset",
    conv: ApplePrintConv::PlistDeferred,
    unknown: false,
  },
  // 0x004e — Apple_0x004e (Apple.pm:299-304) — PLIST.
  AppleTag {
    id: 0x004e,
    name: "Apple_0x004e",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:301 `Unknown => 1`
  },
  // 0x004f — Apple_0x004f (Apple.pm:305-309) — PLIST.
  AppleTag {
    id: 0x004f,
    name: "Apple_0x004f",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:307 `Unknown => 1`
  },
  // 0x0054 — Apple_0x0054 (Apple.pm:310-314) — PLIST.
  AppleTag {
    id: 0x0054,
    name: "Apple_0x0054",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:312 `Unknown => 1`
  },
  // 0x005a — Apple_0x005a (Apple.pm:315-319) — PLIST.
  AppleTag {
    id: 0x005a,
    name: "Apple_0x005a",
    conv: ApplePrintConv::PlistDeferred,
    unknown: true, // Apple.pm:317 `Unknown => 1`
  },
];

/// Resolve a tag ID against the ID-sorted [`APPLE_TAGS`] table via binary
/// search (`apple_tags_sorted_by_id` guards the sorted invariant).
#[must_use]
pub fn lookup(id: u16) -> Option<&'static AppleTag> {
  match APPLE_TAGS.binary_search_by_key(&id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => APPLE_TAGS.get(i),
    Err(_) => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// `APPLE_TAGS` is sorted by tag ID — required for a future
  /// `binary_search` swap and useful for diagnostics.
  #[test]
  fn apple_tags_sorted_by_id() {
    let mut prev = 0u16;
    for t in APPLE_TAGS {
      assert!(
        t.id > prev,
        "Apple tag table out of order: 0x{:04x} after 0x{:04x}",
        t.id,
        prev
      );
      prev = t.id;
    }
  }

  /// Camera-identity tags are present.
  #[test]
  fn lookup_finds_camera_identity_tags() {
    assert_eq!(lookup(0x0001).unwrap().name, "MakerNoteVersion");
    assert_eq!(lookup(0x0008).unwrap().name, "AccelerationVector");
    assert_eq!(lookup(0x0011).unwrap().name, "ContentIdentifier");
    assert_eq!(lookup(0x0015).unwrap().name, "ImageUniqueID");
    assert_eq!(lookup(0x002e).unwrap().name, "CameraType");
  }

  /// An unknown ID returns `None`.
  #[test]
  fn lookup_unknown_is_none() {
    assert!(lookup(0xFFFF).is_none());
    assert!(lookup(0x9999).is_none());
  }

  /// Coverage check: the Phase-2 port covers AT LEAST the camera-
  /// indexing-critical Apple tags (Make/Model/SerialNumber-equivalents,
  /// HDR-flag, content-ID/burst-UUID for grouping).
  #[test]
  fn coverage_meets_phase2_bar() {
    // Camera identity hints
    assert!(lookup(0x0001).is_some()); // MakerNoteVersion
    assert!(lookup(0x002e).is_some()); // CameraType (back/front)
    // HDR identification
    assert!(lookup(0x000a).is_some()); // HDRImageType
    assert!(lookup(0x0014).is_some()); // ImageCaptureType
    assert!(lookup(0x0021).is_some()); // HDRHeadroom
    // Cross-image grouping
    assert!(lookup(0x000b).is_some()); // BurstUUID
    assert!(lookup(0x0011).is_some()); // ContentIdentifier
    assert!(lookup(0x0015).is_some()); // ImageUniqueID
    // Capture metadata
    assert!(lookup(0x0008).is_some()); // AccelerationVector
    assert!(lookup(0x000c).is_some()); // FocusDistanceRange
    assert!(lookup(0x002d).is_some()); // ColorTemperature
  }
}
