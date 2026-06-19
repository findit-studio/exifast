// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the Samsung Type2 tag table.

use super::*;
use crate::exif::makernotes::vendors::samsung::printconv::SamsungPrintConv;

#[test]
fn table_sorted_by_id() {
  let mut prev: Option<u16> = None;
  for t in SAMSUNG_TAGS {
    if let Some(p) = prev {
      assert!(
        t.id > p,
        "SAMSUNG_TAGS not strictly sorted at 0x{:04x}",
        t.id
      );
    }
    prev = Some(t.id);
  }
}

#[test]
fn lookup_resolves_key_leaves() {
  assert_eq!(lookup(0x0002).map(|t| t.name()), Some("DeviceType"));
  assert_eq!(lookup(0x0003).map(|t| t.name()), Some("SamsungModelID"));
  assert_eq!(lookup(0xa003).map(|t| t.name()), Some("LensType"));
  assert_eq!(lookup(0xa001).map(|t| t.name()), Some("FirmwareName"));
  // 0x0030 LocalLocationName is a PLAIN leaf (Phase 1, #210) — not deferred.
  assert_eq!(lookup(0x0030).map(|t| t.name()), Some("LocalLocationName"));
  // 0xa020 EncryptionKey is a PLAIN leaf: its RawConv returns `$val` unchanged
  // (raw int32u[11] passthrough), so ExifTool emits it — it is NOT a Crypt tag.
  assert_eq!(lookup(0xa020).map(|t| t.name()), Some("EncryptionKey"));
  assert!(matches!(
    lookup(0xa020).map(|t| t.conv),
    Some(SamsungPrintConv::None)
  ));
  // 0xa025 HighlightLinearityLimit — the LAST-WINS plain row of the table's only
  // duplicate id (the earlier 0xa025 DigitalGain Crypt row is overwritten). Plain
  // int32u, no conv ⇒ raw value emitted.
  assert_eq!(
    lookup(0xa025).map(|t| t.name()),
    Some("HighlightLinearityLimit")
  );
  assert!(matches!(
    lookup(0xa025).map(|t| t.conv),
    Some(SamsungPrintConv::None)
  ));
  assert_eq!(lookup(0xa025).and_then(|t| t.sub_table()), None);
  // The 16 emitted Crypt rows (RawConv => Samsung::Crypt, #242) ARE ported and
  // carry a `crypt` directive; the deferred SubDirectory rows are NOT ported.
  assert_eq!(
    lookup(0xa021).map(|t| t.name()),
    Some("WB_RGGBLevelsUncorrected")
  );
  assert!(
    lookup(0xa021).and_then(|t| t.crypt()).is_some(),
    "WB_RGGBLevelsUncorrected (Crypt) must carry a crypt directive"
  );
  assert_eq!(lookup(0xa030).map(|t| t.name()), Some("ColorMatrix"));
  assert!(
    lookup(0xa030).and_then(|t| t.crypt()).is_some(),
    "ColorMatrix (Crypt) must carry a crypt directive"
  );
  // A plain leaf carries NO crypt directive.
  assert!(lookup(0xa020).and_then(|t| t.crypt()).is_none());
  // The Unknown=>1 Crypt rows (0xa048/0xa05x) stay DEFERRED (suppressed from
  // default -j output) — not part of the 16.
  assert!(lookup(0xa048).is_none(), "RawData (Unknown Crypt) deferred");
  assert!(
    lookup(0xa050).is_none(),
    "Distortion (Unknown Crypt) deferred"
  );
  assert!(lookup(0x0011).is_none(), "OrientationInfo must be deferred");
  assert!(lookup(0x0035).is_none(), "PreviewIFD must be deferred");
  // 0xa002 SerialNumber is a PLAIN leaf (Phase 1, #210) — in the table; its
  // `$$valPt =~ /^\w{5}/` value-Condition is an emit-time gate
  // (`SamsungPrintConv::condition_holds`), NOT a lookup-time absence.
  assert_eq!(lookup(0xa002).map(|t| t.name()), Some("SerialNumber"));
}

#[test]
fn picture_wizard_is_a_subdirectory() {
  assert_eq!(
    lookup(0x0021).and_then(|t| t.sub_table()),
    Some(SubTable::PictureWizard)
  );
  // A plain leaf has no SubDirectory.
  assert_eq!(lookup(0x0002).and_then(|t| t.sub_table()), None);
}

#[test]
fn focal_length_35_carries_int32u_format_override() {
  assert_eq!(format_override(0xa01a), Some(Format::Int32u));
  // 0x0030 LocalLocationName carries `Format => 'undef'` (Samsung.pm:294).
  assert_eq!(format_override(0x0030), Some(Format::Undef));
  // A plain leaf has no override.
  assert_eq!(format_override(0x0002), None);
}

/// The two walked `%Samsung::Main` `Priority => 0` rows (`0xa019 FNumber`
/// `Samsung.pm:465`, `0xa01a FocalLengthIn35mmFormat` `Samsung.pm:475`) report
/// priority 0; a non-marked sibling reports the default 1 (#284).
#[test]
fn tag_priority_marks_priority0_rows() {
  assert_eq!(lookup(0xa019).unwrap().tag_priority(), 0, "FNumber");
  assert_eq!(
    lookup(0xa01a).unwrap().tag_priority(),
    0,
    "FocalLengthIn35mmFormat"
  );
  // A non-`Priority => 0` Main leaf keeps the default priority 1.
  assert_eq!(lookup(0xa018).unwrap().tag_priority(), 1, "ExposureTime");
  assert_eq!(lookup(0x0002).unwrap().tag_priority(), 1, "DeviceType");
}
