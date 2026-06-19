// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

#[test]
fn pentax_tags_sorted_and_unique() {
  let mut prev: Option<u16> = None;
  for t in PENTAX_TAGS {
    if let Some(p) = prev {
      assert!(t.id > p, "PENTAX_TAGS not strictly sorted at {:#06x}", t.id);
    }
    prev = Some(t.id);
  }
}

#[test]
fn lookup_resolves_known_and_rejects_unknown() {
  // Pentax.jpg (K10D) ported leaves.
  assert_eq!(lookup(0x0005).map(PentaxTag::name), Some("PentaxModelID"));
  assert_eq!(lookup(0x0008).map(PentaxTag::name), Some("Quality"));
  assert_eq!(lookup(0x0013).map(PentaxTag::name), Some("FNumber"));
  // 0x003f LensRec — the only Phase-1 SubDirectory.
  let lens_rec = lookup(0x003f).expect("LensRec row");
  assert_eq!(lens_rec.name(), "LensRec");
  assert_eq!(lens_rec.sub_table(), Some(SubTable::LensRec));
  // An unported / unknown id.
  assert!(lookup(0x9999).is_none());
}

#[test]
fn lens_rec_format_override_is_implicit_undef() {
  // The SubDirectory row carries NO explicit `Format`, so `Exif.pm:6733` forces
  // it to read as `undef` — without this the LensRec block (and `LensType`)
  // never materializes.
  use crate::exif::ifd::Format;
  assert_eq!(format_override(0x003f), Some(Format::Undef));
  // A plain leaf has no override.
  assert_eq!(format_override(0x0008), None);
  // An unknown id has no override.
  assert_eq!(format_override(0x9999), None);
}

#[test]
fn quality_hash_k10d_better() {
  // Pentax.jpg: Quality 1 => "Better".
  assert_eq!(
    PENTAX_TAGS
      .iter()
      .find(|t| t.id == 0x0008)
      .and_then(|t| match t.conv {
        PentaxPrintConv::Hash(h) => h.iter().find(|&&(k, _)| k == 1).map(|&(_, v)| v),
        _ => None,
      }),
    Some("Better")
  );
}

/// The two walked `%Pentax::Main` `Priority => 0` rows (`0x0012 ExposureTime`
/// `Pentax.pm:1474`, `0x0013 FNumber` `Pentax.pm:1484`) report priority 0; a
/// non-marked sibling reports the default 1 (#284). The walked sub-table
/// `Priority => 0` rows (`LensRec` LensType, `LensData` LensFocalLength) are
/// pinned at their own emit sites, not on `PentaxTag`.
#[test]
fn tag_priority_marks_priority0_main_rows() {
  assert_eq!(lookup(0x0012).unwrap().tag_priority(), 0, "ExposureTime");
  assert_eq!(lookup(0x0013).unwrap().tag_priority(), 0, "FNumber");
  // A non-`Priority => 0` Main leaf keeps the default priority 1.
  assert_eq!(lookup(0x0005).unwrap().tag_priority(), 1, "PentaxModelID");
}
