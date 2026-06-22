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

#[test]
fn new_main_leaves_173_present() {
  // The #173 Main-leaf ports resolve by id with the right name.
  assert_eq!(lookup(0x000c).map(PentaxTag::name), Some("FlashMode"));
  assert_eq!(lookup(0x000d).map(PentaxTag::name), Some("FocusMode"));
  assert_eq!(lookup(0x000e).map(PentaxTag::name), Some("AFPointSelected"));
  assert_eq!(
    lookup(0x0016).map(PentaxTag::name),
    Some("ExposureCompensation")
  );
  assert_eq!(lookup(0x0018).map(PentaxTag::name), Some("AutoBracketing"));
  assert_eq!(lookup(0x001d).map(PentaxTag::name), Some("FocalLength"));
  assert_eq!(lookup(0x002d).map(PentaxTag::name), Some("EffectiveLV"));
  assert_eq!(lookup(0x0032).map(PentaxTag::name), Some("ImageEditing"));
  assert_eq!(lookup(0x0033).map(PentaxTag::name), Some("PictureMode"));
  assert_eq!(lookup(0x0034).map(PentaxTag::name), Some("DriveMode"));
  assert_eq!(
    lookup(0x004d).map(PentaxTag::name),
    Some("FlashExposureComp")
  );
  assert_eq!(lookup(0x005d).map(PentaxTag::name), Some("ShutterCount"));
  assert_eq!(
    lookup(0x0062).map(PentaxTag::name),
    Some("RawDevelopmentProcess")
  );
}

#[test]
fn new_subdirectory_rows_173() {
  // The four #173 SubDirectory rows resolve with their SubTable marker and read
  // as implicit-`undef` (so the whole block reaches the child).
  use crate::exif::ifd::Format;
  for (id, sub) in [
    (0x005cu16, SubTable::SrInfo),
    (0x0216, SubTable::BatteryInfo),
    (0x021f, SubTable::AfInfo),
    (0x0222, SubTable::ColorInfo),
  ] {
    let row = lookup(id).unwrap_or_else(|| panic!("row {id:#06x} missing"));
    assert_eq!(row.sub_table(), Some(sub));
    assert_eq!(format_override(id), Some(Format::Undef));
    assert!(is_implicit_undef_subdir(id));
  }
}

#[test]
fn effective_lv_and_image_editing_format_overrides() {
  // EffectiveLV (0x002d) re-reads the int16u bytes as int16s; ImageEditing
  // (0x0032) re-reads the undef bytes as int8u[4].
  use crate::exif::ifd::Format;
  assert_eq!(format_override(0x002d), Some(Format::Int16s));
  assert_eq!(format_override(0x0032), Some(Format::Int8u));
  // A plain leaf (FocalLength 0x001d, int32u on disk) has no override.
  assert_eq!(format_override(0x001d), None);
}

/// Every `%Pentax::Main` leaf that carries an explicit `Format => 'int8u'`
/// directive must re-read as `int8u` regardless of the on-disk TIFF type: the
/// `0x0071 HighISONoiseReduction` row (`Pentax.pm:2445`, no `Count`) and the
/// three metering-segment arrays `0x0209 AEMeteringSegments` / `0x020a`
/// FlashMeteringSegments / `0x020b` SlaveFlashMeteringSegments (`Format =>
/// 'int8u', Count => -1` — variable-length, so NO bundled count). Without the
/// override the walker would trust the on-disk format and decode the wrong
/// element width/count (the regression this test pins).
#[test]
fn high_iso_nr_and_metering_segments_int8u_format_overrides() {
  use crate::exif::ifd::Format;
  for id in [0x0071u16, 0x0209, 0x020a, 0x020b] {
    assert_eq!(
      format_override(id),
      Some(Format::Int8u),
      "{id:#06x} must re-read as int8u",
    );
    // `Count => -1` (the metering arrays) and the count-less 0x0071 both carry
    // NO bundled count — the walker recomputes `int(size/1)` per Exif.pm:6743.
    let row = lookup(id).unwrap_or_else(|| panic!("row {id:#06x} missing"));
    let ovr = row
      .format_override()
      .unwrap_or_else(|| panic!("row {id:#06x} has no FormatOverride"));
    assert_eq!(ovr.format(), Format::Int8u, "{id:#06x} override format");
    assert_eq!(
      ovr.count(),
      None,
      "{id:#06x} variable-length: no bundled count"
    );
  }
}

/// Prove the `Format => 'int8u'` override actually RE-READS a non-byte-sized
/// on-disk entry. A crafted file may write `0x0209 AEMeteringSegments` with an
/// on-disk type that is not `int8u` (e.g. `int16u[8]`); ExifTool re-interprets
/// the SAME value bytes as `int8u`, recomputing the count from the byte size —
/// `int(16 / 1) == 16` (`Exif.pm:6743`). [`resolve_read_format`] (the shared
/// walker helper) must return `(Int8u, 16)`, not the on-disk `(Int16u, 8)`.
#[test]
fn format_override_rereads_non_byte_sized_metering_entry() {
  use crate::exif::ifd::Format;
  use crate::exif::makernotes::vendors::resolve_read_format;
  let ovr = lookup(0x0209).unwrap().format_override();
  assert!(
    ovr.is_some(),
    "0x0209 must carry a FormatOverride to re-read"
  );
  // On-disk int16u[8] = 16 bytes ⇒ re-read as int8u[16].
  let (fmt, count) = resolve_read_format(Format::Int16u, 8, ovr);
  assert_eq!(fmt, Format::Int8u, "re-read format");
  assert_eq!(count, 16, "recomputed int(16/1) element count");
  // Sanity: when the on-disk type already IS int8u, the count is the on-disk
  // count untouched (the override is a no-op for an equal format).
  let (fmt2, count2) = resolve_read_format(Format::Int8u, 77, ovr);
  assert_eq!(fmt2, Format::Int8u);
  assert_eq!(count2, 77, "equal-format override leaves the on-disk count");
}

/// #173 branch selection — the count-/`Make`-/`Model`-/on-disk-`$format`-
/// CONDITIONED `%Pentax::Main` leaves emit ONLY their ported variant; every
/// other context returns [`ConditionalLeaf::Suppress`] so no foreign-variant
/// value is ever emitted. The K10D `Pentax.jpg` exercises the ported branch of
/// `0x000d`/`0x000e`/`0x0016`/`0x001d`/`0x002d`/`0x004d`/`0x0062` (verified
/// byte-exact in the conformance golden).
use crate::exif::ifd::Format;

/// The K10D fixture context: Make `"PENTAX Corporation"`, Model `"PENTAX K10D"`,
/// 0x002d on disk `int16u`.
const K10D_MAKE: Option<&str> = Some("PENTAX Corporation");
const K10D_MODEL: Option<&str> = Some("PENTAX K10D");

#[test]
fn conditional_leaf_count_gated_leaves() {
  // 0x0016 ExposureCompensation: `$count == 1` emits; the count-2 variant is
  // deferred ⇒ Suppress.
  assert_eq!(
    conditional_leaf(0x0016, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Emit,
    "0x0016 count==1 must emit"
  );
  assert_eq!(
    conditional_leaf(0x0016, 2, K10D_MODEL, K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Suppress,
    "0x0016 count==2 must suppress (deferred variant)"
  );
  assert!(conditional_leaf(0x0016, 0, K10D_MODEL, K10D_MAKE, Format::Int16u).is_suppressed());
  // 0x004d FlashExposureComp: BOTH variants are now ported (the count==1 int32s
  // and the count==2 int8s array), so the leaf emits for either count (#311).
  for count in [1usize, 2] {
    assert_eq!(
      conditional_leaf(0x004d, count, K10D_MODEL, K10D_MAKE, Format::Int16u),
      ConditionalLeaf::Emit,
      "0x004d count=={count} must emit (both variants ported)"
    );
  }
}

#[test]
fn conditional_leaf_af_point_selected_model_gated() {
  // 0x000e AFPointSelected: the "other models" variant emits for a non-K-1/645Z,
  // non-K-3/KP model, for EITHER count (the array conv now renders both the
  // single-element K10D form `'Center'` and the two-element K-S2 form
  // `'Center; Single Point'`, #311).
  for count in [1usize, 2] {
    assert_eq!(
      conditional_leaf(0x000e, count, K10D_MODEL, K10D_MAKE, Format::Int16u),
      ConditionalLeaf::Emit,
      "0x000e count=={count} (other-models body) must emit"
    );
  }
  // The K-1/645Z and K-3/KP model variants are deferred (their own point hashes)
  // ⇒ Suppress, never the "other models" hash flattened onto them.
  for m in [
    "PENTAX K-1",
    "PENTAX 645Z",
    "PENTAX K-3",
    "PENTAX K-3 Mark III",
    "PENTAX KP",
  ] {
    assert_eq!(
      conditional_leaf(0x000e, 1, Some(m), K10D_MAKE, Format::Int16u),
      ConditionalLeaf::Suppress,
      "{m} AFPointSelected must suppress (model-specific variant deferred)"
    );
  }
  // The `K-3` token must not false-match a non-K-3 model containing the bytes
  // out of word-boundary (faithful `\b`); a plain Optio is the "other models"
  // arm.
  assert_eq!(
    conditional_leaf(0x000e, 1, Some("PENTAX Optio S"), K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Emit
  );
}

/// `0x000f AFPointsInFocus` (#311) — the ported variant 1 is the int32u 27-bit
/// BITMASK, `Condition => '$$self{Model} =~ /K-(3|S1|S2)\b/'`. ONLY a K-3 / K-S1
/// / K-S2 body emits; every other model — and a `None` model — suppresses
/// (variant 2, the int16u `'other models'` enum, is DEFERRED, so its layout is
/// never flattened onto the bitmask). The `format`/`count`/`make` axes are
/// irrelevant to this leaf, so the gate keys purely on the model.
#[test]
fn conditional_leaf_af_points_in_focus_model_gated() {
  // The three matching bodies (the `Notes => 'K-3, K-S1 and K-S2 only'` set) emit
  // the bitmask. `K-3` matches with a trailing space ("K-3 Mark III" too); the
  // K-S1/K-S2 models are spelled out in full.
  for m in [
    "PENTAX K-3",
    "PENTAX K-3 Mark III",
    "PENTAX K-S1",
    "PENTAX K-S2",
  ] {
    assert_eq!(
      conditional_leaf(0x000f, 1, Some(m), None, Format::Int32u),
      ConditionalLeaf::Emit,
      "{m} AFPointsInFocus must emit (the /K-(3|S1|S2)\\b/ bitmask variant)"
    );
  }
  // Every NON-matching model suppresses: the K10D / K-x / K-5 II carry no Main
  // 0x000f at all, the K-1 / KP / K-70 0x000f is the unrelated CAFPointInfo
  // sub-block — but were any of them to present a Main 0x000f it would be the
  // DEFERRED int16u enum, NOT the bitmask. `K-30` must NOT match `K-3\b` (the `3`
  // is followed by the word char `0`); `K-S10`/`K-S20` must NOT match `K-S1\b`/
  // `K-S2\b`; `645Z` and a bare `KP` are other Pentax bodies outside the set.
  for m in [
    "PENTAX K10D",
    "PENTAX K-x",
    "PENTAX K-5 II",
    "PENTAX K-1",
    "PENTAX KP",
    "PENTAX K-70",
    "PENTAX K-30",
    "PENTAX K-S10",
    "PENTAX K-S20",
    "PENTAX 645Z",
    "PENTAX Optio S",
  ] {
    assert_eq!(
      conditional_leaf(0x000f, 1, Some(m), None, Format::Int32u),
      ConditionalLeaf::Suppress,
      "{m} AFPointsInFocus must suppress (not /K-(3|S1|S2)\\b/; variant-2 deferred)"
    );
  }
  // A `None` model (videos carry no Model) cannot match the regex (Perl undef
  // `=~` is false) ⇒ suppress.
  assert_eq!(
    conditional_leaf(0x000f, 1, None, None, Format::Int32u),
    ConditionalLeaf::Suppress,
    "None-model AFPointsInFocus must suppress (undef =~ // is false)"
  );
}

/// `0x000d FocusMode` — `$$self{Make} !~ /^Asahi/`. The Pentax/Ricoh body (and a
/// `None`-Make video) emit the ported "Pentax models" hash; an Asahi body is the
/// deferred "Asahi models" variant ⇒ Suppress.
#[test]
fn conditional_leaf_focus_mode_make_gated() {
  // K10D (Make "PENTAX Corporation") ⇒ ported variant.
  assert_eq!(
    conditional_leaf(0x000d, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Emit,
    "PENTAX FocusMode must emit (Pentax-models variant)"
  );
  // A `None` Make (MOV/AVI video) is `!~ /^Asahi/` ⇒ ported variant.
  assert_eq!(
    conditional_leaf(0x000d, 1, Some("PENTAX K-x"), None, Format::Int16u),
    ConditionalLeaf::Emit,
    "None-Make video FocusMode must emit (undef !~ /^Asahi/)"
  );
  // An Asahi body selects the deferred "Asahi models" hash ⇒ Suppress (never the
  // Pentax-models labels flattened onto it).
  for m in ["Asahi", "Asahi Optical Co.,Ltd", "AsahiPentax"] {
    assert_eq!(
      conditional_leaf(0x000d, 1, Some("PENTAX *ist D"), Some(m), Format::Int16u),
      ConditionalLeaf::Suppress,
      "Asahi-make ({m}) FocusMode must suppress (Asahi variant deferred)"
    );
  }
  // RICOH is not Asahi ⇒ ported variant (GR III is a Ricoh-make Pentax body).
  assert_eq!(
    conditional_leaf(
      0x000d,
      1,
      Some("RICOH GR III"),
      Some("RICOH IMAGING COMPANY, LTD."),
      Format::Int16u
    ),
    ConditionalLeaf::Emit
  );
}

/// `0x001d FocalLength` — the ÷100 variant emits for the K10D / most bodies; an
/// Optio in `/^PENTAX Optio (30|33WR|43WR|450|550|555|750Z|X)\b/` uses the ÷10
/// variant (10× different) ⇒ Suppress.
#[test]
fn conditional_leaf_focal_length_optio_div10_gated() {
  // K10D (and a non-listed Optio) ⇒ the ported ÷100 variant.
  assert_eq!(
    conditional_leaf(0x001d, 1, K10D_MODEL, K10D_MAKE, Format::Int32u),
    ConditionalLeaf::Emit
  );
  // The ÷10 Optio bodies ⇒ Suppress (not 10× too small).
  for m in [
    "PENTAX Optio 30",
    "PENTAX Optio 33WR",
    "PENTAX Optio 43WR",
    "PENTAX Optio 450",
    "PENTAX Optio 550",
    "PENTAX Optio 555",
    "PENTAX Optio 750Z",
    "PENTAX Optio X",
  ] {
    assert_eq!(
      conditional_leaf(0x001d, 1, Some(m), K10D_MAKE, Format::Int32u),
      ConditionalLeaf::Suppress,
      "{m} FocalLength must suppress (÷10 Optio variant deferred)"
    );
  }
  // `\b` faithfulness: "Optio 300" / "Optio 33L" / "Optio S30" must NOT match the
  // ÷10 list (300 != 30 token; 33L != 33WR; S30 is the ÷100 list) ⇒ Emit.
  for m in [
    "PENTAX Optio 300",
    "PENTAX Optio 33L",
    "PENTAX Optio S30",
    "PENTAX Optio S",
  ] {
    assert_eq!(
      conditional_leaf(0x001d, 1, Some(m), K10D_MAKE, Format::Int32u),
      ConditionalLeaf::Emit,
      "{m} FocalLength must emit (÷100 variant; not in the ÷10 list)"
    );
  }
}

/// `0x002d EffectiveLV` — variant 1 `$format eq "int16u"` (ported, int16s
/// re-read). An int32u-on-disk record is the deferred int32s variant; any other
/// on-disk format matches NEITHER variant ⇒ Suppress.
#[test]
fn conditional_leaf_effective_lv_format_gated() {
  // K10D writes int16u ⇒ the ported variant emits.
  assert_eq!(
    conditional_leaf(0x002d, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Emit,
    "int16u EffectiveLV must emit (ported variant)"
  );
  // An int32u record is the deferred variant ⇒ Suppress (never misread as int16s).
  assert_eq!(
    conditional_leaf(0x002d, 2, K10D_MODEL, K10D_MAKE, Format::Int32u),
    ConditionalLeaf::Suppress,
    "int32u EffectiveLV must suppress (int32s variant deferred)"
  );
  // Any other on-disk format matches neither ExifTool Condition ⇒ Suppress.
  for f in [Format::Int16s, Format::Int8u, Format::Int32s, Format::Float] {
    assert_eq!(
      conditional_leaf(0x002d, 1, K10D_MODEL, K10D_MAKE, f),
      ConditionalLeaf::Suppress,
      "{f:?} EffectiveLV must suppress (no matching ExifTool variant)"
    );
  }
}

/// `0x0062 RawDevelopmentProcess` — `$$self{Make} =~ /^(PENTAX|RICOH)/` (rules
/// out Kodak). A non-PENTAX/RICOH Make (including `None`) ⇒ Suppress.
#[test]
fn conditional_leaf_raw_development_process_make_gated() {
  // PENTAX / RICOH ⇒ emit.
  assert_eq!(
    conditional_leaf(0x0062, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    ConditionalLeaf::Emit,
    "PENTAX RawDevelopmentProcess must emit"
  );
  assert_eq!(
    conditional_leaf(
      0x0062,
      1,
      Some("RICOH GR III"),
      Some("RICOH IMAGING COMPANY, LTD."),
      Format::Int16u
    ),
    ConditionalLeaf::Emit,
    "RICOH RawDevelopmentProcess must emit"
  );
  // Kodak (and any other / None Make) ⇒ Suppress (never decode a foreign value).
  for mk in [Some("EASTMAN KODAK COMPANY"), Some("Kodak"), None] {
    assert_eq!(
      conditional_leaf(0x0062, 1, None, mk, Format::Int16u),
      ConditionalLeaf::Suppress,
      "{mk:?} RawDevelopmentProcess must suppress (not PENTAX/RICOH)"
    );
  }
}

#[test]
fn conditional_leaf_non_conditional_leaves_always_emit() {
  // Every #173 leaf WITHOUT a `Pentax.pm` Condition is unconditional regardless
  // of count/make/model/format (a `Count => N` is an element count, not a gate):
  // FlashMode 0x000c, AutoBracketing 0x0018, ImageEditing 0x0032, PictureMode
  // 0x0033, DriveMode 0x0034. These have EXPLICIT `Emit` arms ⇒ always `Emit`.
  for id in [0x000cu16, 0x0018, 0x0032, 0x0033, 0x0034] {
    assert_eq!(
      conditional_leaf(id, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
      ConditionalLeaf::Emit
    );
    assert_eq!(
      conditional_leaf(id, 4, Some("PENTAX K-x"), None, Format::Undef),
      ConditionalLeaf::Emit
    );
    assert_eq!(
      conditional_leaf(id, 2, None, Some("Asahi"), Format::Int32u),
      ConditionalLeaf::Emit
    );
  }
  // A pre-#173 leaf (Quality 0x0008, PentaxModelID 0x0005) is NOT a #173 leaf, so
  // it reaches the catch-all and returns `EmitUnported` (byte-equivalent to
  // `Emit` for the caller — both are non-suppressed — so emission is unchanged).
  for id in [0x0008u16, 0x0005] {
    assert_eq!(
      conditional_leaf(id, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
      ConditionalLeaf::EmitUnported
    );
    assert!(!conditional_leaf(id, 1, K10D_MODEL, K10D_MAKE, Format::Int16u).is_suppressed());
  }
}

/// The COMPLETE set of `%Pentax::Main` LEAF ids the #173 commit ported (7 gated +
/// 5 confirmed-unconditional + `0x005d ShutterCount`). The structural test below
/// asserts EVERY one is handled by an explicit `conditional_leaf` arm, never the
/// catch-all.
const MAIN_173_LEAF_IDS: [u16; 13] = [
  // 7 gated leaves.
  0x000d, // FocusMode            (`Make !~ /^Asahi/`)
  0x000e, // AFPointSelected      (Model + count)
  0x0016, // ExposureCompensation (`$count == 1`)
  0x001d, // FocalLength          (Optio ÷10 list ⇒ suppress)
  0x002d, // EffectiveLV          (on-disk `$format eq "int16u"`)
  0x004d, // FlashExposureComp    (`$count == 1`)
  0x0062, // RawDevelopmentProcess(`Make =~ /^(PENTAX|RICOH)/`)
  // 5 confirmed-unconditional leaves.
  0x000c, // FlashMode
  0x0018, // AutoBracketing
  0x0032, // ImageEditing
  0x0033, // PictureMode
  0x0034, // DriveMode
  // ShutterCount — gated at its own emit site, but explicitly enumerated here.
  0x005d, // ShutterCount
];

/// STRUCTURAL no-flattening invariant (Codex #173 R3): every #173 Main leaf id
/// is covered by an EXPLICIT `conditional_leaf` arm, NEVER the `_` fallback. The
/// fallback returns the distinct [`ConditionalLeaf::EmitUnported`] variant, so an
/// id that fell through would yield `EmitUnported` for EVERY context (the
/// catch-all ignores count/make/model/format); an explicitly-handled id yields
/// only `Emit` or `Suppress`. The test probes each #173 id across a matrix of
/// contexts and asserts NONE ever returns `EmitUnported` — so removing any
/// explicit arm (e.g. one of the 5 confirmed-unconditional `Emit` arms) makes
/// that id fall through and FAILS this test. The discriminator guard confirms the
/// fallback is genuinely reachable (a non-#173 id DOES return `EmitUnported`), so
/// the assertion is not vacuous.
#[test]
fn conditional_leaf_173_leaves_are_structurally_handled() {
  // A matrix of contexts wide enough that a gated leaf takes BOTH its emit and
  // its suppress branch somewhere — yet an explicitly-handled leaf never returns
  // `EmitUnported` in any of them, while a fall-through leaf returns it in ALL.
  let contexts: &[(usize, Option<&str>, Option<&str>, Format)] = &[
    (1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    (1, K10D_MODEL, K10D_MAKE, Format::Int32u),
    (2, K10D_MODEL, K10D_MAKE, Format::Int16u),
    (0, None, None, Format::Undef),
    (4, Some("PENTAX K-x"), None, Format::Int8u),
    (
      1,
      Some("PENTAX K-1"),
      Some("Asahi Optical Co.,Ltd"),
      Format::Int32s,
    ),
    (
      3,
      Some("PENTAX Optio 30"),
      Some("EASTMAN KODAK COMPANY"),
      Format::Float,
    ),
  ];
  for id in MAIN_173_LEAF_IDS {
    for &(count, model, make, fmt) in contexts {
      assert_ne!(
        conditional_leaf(id, count, model, make, fmt),
        ConditionalLeaf::EmitUnported,
        "#173 Main leaf {id:#06x} reached the catch-all (count={count}, \
         model={model:?}, make={make:?}, format={fmt:?}); it MUST have an \
         explicit conditional_leaf arm so the no-flattening invariant is \
         structural, not comment-dependent"
      );
    }
  }
  // Discriminator: an id that is NOT a #173 leaf (no explicit arm) MUST hit the
  // fallback and return `EmitUnported`. This proves the variant is actually
  // produced, so the loop above is a real structural check rather than vacuously
  // true. `0x9999` is unported; `0x0008 Quality` is a pre-#173 Phase-1 leaf.
  for unported in [0x9999u16, 0x0008] {
    assert_eq!(
      conditional_leaf(unported, 1, K10D_MODEL, K10D_MAKE, Format::Int16u),
      ConditionalLeaf::EmitUnported,
      "{unported:#06x} is not a #173 leaf and must reach the catch-all"
    );
  }
  // `EmitUnported` is byte-equivalent to `Emit` for the caller (NOT suppressed),
  // so routing pre-#173 / unported ids through it does not change any output.
  assert!(!ConditionalLeaf::EmitUnported.is_suppressed());
}

/// The `%Pentax::Main` LEAF ids the #311 commit added that carry a `Pentax.pm`
/// `Condition` selected at the LEAF level (so they MUST gate through
/// [`conditional_leaf`], not the subdirectory dispatch). The audit of every
/// #311-added Main row found exactly ONE: `0x000f AFPointsInFocus`
/// (`/K-(3|S1|S2)\b/`). The other two #311 conditioned rows are SubDirectory
/// pointers whose `Condition` selects an axis at the subdir-dispatch site, NOT a
/// leaf PrintConv — see [`pentax_311_subdir_conditions_handled_at_dispatch`].
const MAIN_311_CONDITIONED_LEAF_IDS: [u16; 1] = [
  0x000f, // AFPointsInFocus (`$$self{Model} =~ /K-(3|S1|S2)\b/`)
];

/// STRUCTURAL no-flattening invariant for the #311 conditioned Main LEAVES
/// (mirrors [`conditional_leaf_173_leaves_are_structurally_handled`]). The #311
/// port added 25 Main rows; the comprehensive `Pentax.pm` audit found three with
/// a `Condition` — `0x000f` (a leaf, gated here), `0x022a` and `0x022b` (subdir
/// pointers, gated at dispatch). This test pins that the LEAF one
/// (`MAIN_311_CONDITIONED_LEAF_IDS`) has an EXPLICIT `conditional_leaf` arm and
/// NEVER reaches the `EmitUnported` catch-all in any context — so removing the
/// `0x000f` arm (regressing it to a global row that emits the K-3/S1/S2 bitmask
/// for EVERY model) FAILS this test. The K-S2 golden alone cannot catch that
/// regression (it matches the condition), which is exactly why the gate is
/// pinned structurally.
#[test]
fn conditional_leaf_311_leaves_are_structurally_handled() {
  // A context matrix wide enough that `0x000f` takes BOTH its emit branch (a
  // K-3/S1/S2 model) and its suppress branch (every other model / `None`), yet
  // never returns `EmitUnported` in any of them.
  let contexts: &[(usize, Option<&str>, Option<&str>, Format)] = &[
    (1, Some("PENTAX K-3"), None, Format::Int32u),
    (1, Some("PENTAX K-S1"), None, Format::Int32u),
    (
      1,
      Some("PENTAX K-S2"),
      Some("RICOH IMAGING COMPANY, LTD."),
      Format::Int32u,
    ),
    (1, K10D_MODEL, K10D_MAKE, Format::Int16u),
    (1, Some("PENTAX K-1"), None, Format::Int32u),
    (2, Some("PENTAX KP"), None, Format::Int32u),
    (0, None, None, Format::Undef),
    (1, Some("PENTAX K-30"), None, Format::Int32u),
  ];
  for id in MAIN_311_CONDITIONED_LEAF_IDS {
    for &(count, model, make, fmt) in contexts {
      assert_ne!(
        conditional_leaf(id, count, model, make, fmt),
        ConditionalLeaf::EmitUnported,
        "#311 conditioned Main leaf {id:#06x} reached the catch-all (count={count}, \
         model={model:?}, make={make:?}, format={fmt:?}); it MUST have an explicit \
         conditional_leaf arm so the model gate is structural, not a global row \
         that the K-S2 golden masks"
      );
    }
  }
}

/// The two #311 `%Pentax::Main` SubDirectory rows that carry a `Pentax.pm`
/// `Condition` (`Pentax.pm:3030-3051`) are CORRECTLY NOT gated through
/// [`conditional_leaf`] — their `Condition` picks a per-subdirectory axis that is
/// resolved at the dispatch site in `exif/mod.rs`, faithfully, so each routes
/// through the catch-all (`EmitUnported`) as a subdir pointer with no leaf
/// PrintConv to gate. This test pins that classification (so a future edit that
/// wrongly adds a leaf gate, or drops the dispatch-site handling, is visible):
///
/// * `0x022a FilterInfo` — `[{ Condition => '$$self{Make} =~ /^RICOH/' …
///   LittleEndian }, { … BigEndian }]`. BOTH variants are the SAME `%FilterInfo`
///   table; the `Condition` only flips the byte order, which
///   `pentax::subtables::emit_filter_info(block, make, …)` decides from the
///   threaded `Make` (RICOH ⇒ LE, else ⇒ BE).
/// * `0x022b LevelInfo` — `[{ Name => 'LevelInfoK3III', Condition =>
///   '$$self{Model} =~ /K-3 Mark III/' … }, { Name => 'LevelInfo' … }]`. The
///   `SubTable::LevelInfo` arm picks `%LevelInfoK3III` vs `%LevelInfo` from
///   `is_k3_mark_iii(model)`.
#[test]
fn pentax_311_subdir_conditions_handled_at_dispatch() {
  use crate::exif::ifd::Format;
  // Both rows resolve as SubDirectory pointers (a `sub_table`, no leaf gate).
  for (id, name, sub) in [
    (0x022au16, "FilterInfo", SubTable::FilterInfo),
    (0x022b, "LevelInfo", SubTable::LevelInfo),
  ] {
    let tag = lookup(id).unwrap_or_else(|| panic!("{id:#06x} row missing"));
    assert_eq!(tag.name(), name, "{id:#06x} name");
    assert_eq!(tag.sub_table(), Some(sub), "{id:#06x} is a SubDirectory");
    // No LEAF-level `conditional_leaf` gate (the byte-order / model axis lives at
    // the subdir-dispatch site), so the catch-all classifies it `EmitUnported`
    // for both the matching and non-matching context.
    for (model, make) in [
      (
        Some("PENTAX K-3 Mark III"),
        Some("RICOH IMAGING COMPANY, LTD."),
      ),
      (Some("PENTAX K-5 II"), Some("PENTAX")),
      (None, None),
    ] {
      assert_eq!(
        conditional_leaf(id, 1, model, make, Format::Undef),
        ConditionalLeaf::EmitUnported,
        "{id:#06x} subdir condition is resolved at dispatch, not via conditional_leaf"
      );
    }
  }
}

/// #311 P1 — the nine UNCONDITIONAL `%Pentax::Main` scalar leaves the K-x
/// `Pentax.avi` fixture exercises resolve via [`lookup`] with the right name,
/// are plain leaves (no SubDirectory), and — having NO `Pentax.pm` `Condition`
/// — route through the `conditional_leaf` catch-all as `EmitUnported` (which is
/// NOT suppressed, so they emit unconditionally). The `pentax_tags_sorted_and_
/// unique` test above proves their ids keep the table strictly sorted (the
/// `lookup` binary-search precondition).
#[test]
fn pentax_p1_main_scalar_leaves() {
  use crate::exif::ifd::Format;
  let expected: &[(u16, &str)] = &[
    (0x0067, "Hue"),
    (0x006c, "HighLowKeyAdj"),
    (0x0073, "MonochromeFilterEffect"),
    (0x0074, "MonochromeToning"),
    (0x007b, "CrossProcess"),
    (0x0229, "SerialNumber"),
    (0x022e, "Artist"),
    (0x022f, "Copyright"),
    (0x0230, "FirmwareVersion"),
  ];
  for &(id, name) in expected {
    let tag = lookup(id).unwrap_or_else(|| panic!("{id:#06x} {name} row missing"));
    assert_eq!(tag.name(), name, "{id:#06x} name");
    assert_eq!(tag.sub_table(), None, "{id:#06x} is a plain leaf");
    assert!(!tag.is_unknown(), "{id:#06x} not Unknown");
    // No `Pentax.pm` Condition ⇒ the catch-all (`EmitUnported`), never suppressed.
    assert_eq!(
      conditional_leaf(id, 1, Some("PENTAX K-x"), None, Format::Int16u),
      ConditionalLeaf::EmitUnported,
      "{id:#06x} is unconditional"
    );
  }
  // The five enum-hash leaves carry an int-keyed `Hash`; `HighLowKeyAdj` is the
  // one space-joined `StringKeyedHash`; the four `string` leaves are `None`.
  assert!(matches!(
    lookup(0x0067).unwrap().conv,
    PentaxPrintConv::Hash(_)
  ));
  assert!(matches!(
    lookup(0x006c).unwrap().conv,
    PentaxPrintConv::StringKeyedHash(_)
  ));
  assert!(matches!(
    lookup(0x007b).unwrap().conv,
    PentaxPrintConv::Hash(_)
  ));
  assert!(matches!(
    lookup(0x0229).unwrap().conv,
    PentaxPrintConv::None
  ));
  assert!(matches!(
    lookup(0x0230).unwrap().conv,
    PentaxPrintConv::None
  ));
}
