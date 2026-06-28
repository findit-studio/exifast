// Unit tests for the `PrintLensID` Sony/Minolta disambiguation. The A200 /
// A33 conformance fixtures cover the A-mount FocalLength/MaxAperture and the
// LensSpec exact-suffix branches end-to-end (byte-exact vs bundled); these
// guard the branches conformance does NOT exercise — the E-mount LensSpec
// keep-path, the teleconverter scaling, `MatchLensModel`, the 65535 manual-lens
// `%sonyEtype` path, and the 0-/multi-survivor fall-throughs — ground-truthed
// against the bundled `%sonyLensTypes*` tables and the `Exif.pm:5881` logic.

use super::*;

/// A base [`PrintLensIdInputs`] (a Sony body, no decoded ingredients) to
/// override per test.
fn base(table: SonyLensTable, lens_type: i64, lens_type_prt: &str) -> PrintLensIdInputs<'_> {
  PrintLensIdInputs {
    is_sony: true,
    model: None,
    lens_type_prt,
    lens_spec_prt: None,
    lens_type,
    focal_length: None,
    max_aperture: None,
    max_aperture_value: None,
    short_focal: None,
    long_focal: None,
    lens_model: None,
    lens_focal_range: None,
    table,
  }
}

// ---- end-to-end `print_lens_id` ----

#[test]
fn a200_focal_aperture_branch_picks_tamron_70_300() {
  // A200: LensType 129 (= "Tamron Lens (129)"), LensSpec all-zero ⇒ the
  // FocalLength (80) + MaxApertureValue (4.5002…) branch picks the 129.2 variant.
  let mut inp = base(SonyLensTable::AMount, 129, "Tamron Lens (129)");
  inp.lens_spec_prt = Some("Unknown (00 0 0 0 0 00)");
  inp.focal_length = Some(80.0);
  inp.max_aperture_value = Some(4.500_233_938_755_24);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Tamron 70-300mm F4-5.6 LD")
  );
}

#[test]
fn a33_lensspec_exact_suffix_wins_over_variant() {
  // A33: LensType 55, LensSpec "DT 18-55mm F3.5-5.6 SAM" — the PRIMARY 55
  // (SAL1855) wins via the exact LensSpec-suffix match over the 55.1 (SAM II).
  let mut inp = base(
    SonyLensTable::AMount,
    55,
    "Sony DT 18-55mm F3.5-5.6 SAM (SAL1855) or SAM II",
  );
  inp.lens_spec_prt = Some("DT 18-55mm F3.5-5.6 SAM");
  inp.lens_model = Some("DT 18-55mm F3.5-5.6 SAM");
  inp.focal_length = Some(24.0);
  inp.max_aperture_value = Some(4.0);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Sony DT 18-55mm F3.5-5.6 SAM (SAL1855)")
  );
}

#[test]
fn emount_lensspec_keeps_nonsony_match() {
  // E-mount id 0 (multi-candidate): LensSpec "30mm F2.8" keeps only the
  // in-tolerance non-Sony "Sigma 30mm F2.8 [EX] DN" (no exact-suffix win — the
  // `(SAL…)`/`[EX]` tail differs — so the `push @best unless /^Sony /` path).
  let mut inp = base(
    SonyLensTable::EMount,
    0,
    "Unknown E-mount lens or other lens",
  );
  inp.lens_spec_prt = Some("30mm F2.8");
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Sigma 30mm F2.8 [EX] DN")
  );
}

#[test]
fn teleconverter_scaling_rescues_200mm_at_280() {
  // A-mount 25901 ("… + Minolta AF 1.4x APO"): the 1.4x converter scales the
  // 200mm primary to 280mm, so FocalLength 280 SURVIVES (without the scaling it
  // would be ruled out as > 200.5mm); the 600mm variant scales to 840mm and is
  // ruled out.
  let mut inp = base(
    SonyLensTable::AMount,
    25901,
    "Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO or Other Lens + 1.4x",
  );
  inp.focal_length = Some(280.0);
  inp.max_aperture = Some(4.0);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO")
  );
}

#[test]
fn multi_survivor_joins_with_or() {
  // No FocalLength / MaxAperture / LensSpec to disqualify either candidate ⇒
  // both reach @matches and join with " or " (Exif.pm:6055).
  let inp = base(
    SonyLensTable::AMount,
    25901,
    "Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO or Other Lens + 1.4x",
  );
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some(
      "Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO or \
       Minolta AF 600mm F4 HS-APO G + Minolta AF 1.4x APO"
    )
  );
}

#[test]
fn zero_survivor_returns_lens_model_when_primary_has_or() {
  // FocalLength 2000 rules out every id-0 candidate ⇒ no @best/@matches; the
  // primary has " or " and LensModel is present ⇒ `return $lensModel`
  // (Exif.pm:6058).
  let mut inp = base(
    SonyLensTable::EMount,
    0,
    "Unknown E-mount lens or other lens",
  );
  inp.focal_length = Some(2000.0);
  inp.lens_model = Some("My Manual 2000mm");
  assert_eq!(print_lens_id(&inp).as_deref(), Some("My Manual 2000mm"));
}

#[test]
fn zero_survivor_returns_primary_without_lens_model() {
  // Same, but no LensModel ⇒ `return $lens` (the full primary, Exif.pm:6059).
  let mut inp = base(
    SonyLensTable::EMount,
    0,
    "Unknown E-mount lens or other lens",
  );
  inp.focal_length = Some(2000.0);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Unknown E-mount lens or other lens")
  );
}

#[test]
fn unambiguous_no_variant_returns_name_verbatim() {
  // A LensType with no float variants is unambiguous — `return $lens unless
  // $$printConv{"$lensType.1"}` (Exif.pm:5964). id 32821 = "Sony FE 24-70mm
  // F2.8 GM" has no `.1`.
  let inp = base(SonyLensTable::EMount, 32821, "Sony FE 24-70mm F2.8 GM");
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Sony FE 24-70mm F2.8 GM")
  );
}

#[test]
fn manual_lens_65535_early_return() {
  // The forum17379 patch (Exif.pm:5917): LensType 65535, no FocalLength,
  // MaxAperture == 1 ⇒ the A-mount table's 65535 name verbatim.
  let mut inp = base(
    SonyLensTable::AMount,
    65535,
    "E-Mount, T-Mount, Other Lens or no lens",
  );
  inp.max_aperture = Some(1.0);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("E-Mount, T-Mount, Other Lens or no lens")
  );
}

#[test]
fn manual_lens_65535_amount_variants_for_non_nex() {
  // 65535 on a NON-NEX/ILCE body keeps the A-mount %sonyLensTypes 65535
  // manual-lens variants; LensSpec "135mm F2.8" picks "Pentacon Auto 135mm F2.8".
  let mut inp = base(
    SonyLensTable::AMount,
    65535,
    "E-Mount, T-Mount, Other Lens or no lens",
  );
  inp.model = Some("DSLR-A900");
  inp.lens_spec_prt = Some("135mm F2.8");
  inp.focal_length = Some(135.0);
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Pentacon Auto 135mm F2.8")
  );
}

#[test]
fn manual_lens_65535_nex_ilce_uses_sony_etype() {
  // 65535 on a NEX/ILCE body rebuilds the printConv as %sonyEtype (the de-duped
  // E-mount names); LensSpec "FE 24-70mm F2.8 GM" exact-matches the GM (not the
  // " GM II"), proving the E-mount candidate set is used.
  let mut inp = base(
    SonyLensTable::AMount,
    65535,
    "E-Mount, T-Mount, Other Lens or no lens",
  );
  inp.model = Some("NEX-7");
  inp.lens_spec_prt = Some("FE 24-70mm F2.8 GM");
  inp.focal_length = Some(50.0); // truthy ⇒ skip the manual-lens early return
  assert_eq!(
    print_lens_id(&inp).as_deref(),
    Some("Sony FE 24-70mm F2.8 GM")
  );
}

#[test]
fn metabones_adapter_defers() {
  // A Metabones EF-adapter offset (high byte 0xef00) substitutes the unported
  // Canon lens DB ⇒ DEFER.
  let inp = base(SonyLensTable::EMount, 0xef12, "Unknown");
  assert_eq!(print_lens_id(&inp), None);
}

#[test]
fn non_sony_canon_branch_defers() {
  // A non-Sony body with Min/MaxFocalLength would call `Canon::PrintLensID`
  // (not ported) ⇒ DEFER.
  let mut inp = base(SonyLensTable::AMount, 200, "Some Canon Lens");
  inp.is_sony = false;
  inp.short_focal = Some(70.0);
  inp.long_focal = Some(200.0);
  assert_eq!(print_lens_id(&inp), None);
}

// ---- `MatchLensModel` (Exif.pm:5847) ----

#[test]
fn match_lens_model_filters_by_focal() {
  let mut list = std::vec![
    "Sony FE 24mm F1.4 GM".to_string(),
    "Sony FE 50mm F1.4 GM".to_string(),
  ];
  match_lens_model(&mut list, Some("FE 24mm F1.4 GM"));
  assert_eq!(list, ["Sony FE 24mm F1.4 GM"]);
}

#[test]
fn match_lens_model_filters_by_version_two() {
  // The `I+` version filter narrows to the "II" body (focal + aperture tie).
  let mut list = std::vec![
    "Canon EF 70-200mm F2.8L IS II USM".to_string(),
    "Canon EF 70-200mm F2.8L IS USM".to_string(),
  ];
  match_lens_model(&mut list, Some("EF 70-200mm F2.8L IS II USM"));
  assert_eq!(list, ["Canon EF 70-200mm F2.8L IS II USM"]);
}

#[test]
fn match_lens_model_filters_by_usm() {
  let mut list = std::vec![
    "Canon EF 50mm F1.8 USM".to_string(),
    "Canon EF 50mm F1.8".to_string(),
  ];
  match_lens_model(&mut list, Some("EF 50mm F1.8 USM"));
  assert_eq!(list, ["Canon EF 50mm F1.8 USM"]);
}

#[test]
fn match_lens_model_never_empties() {
  // A filter that would leave NO entry is not applied (Exif.pm:5856).
  let mut list = std::vec!["A 50mm".to_string(), "B 50mm".to_string()];
  match_lens_model(&mut list, Some("999mm"));
  assert_eq!(list, ["A 50mm", "B 50mm"]);
}

// ---- helper regex ports ----

#[test]
fn teleconverter_factor_cases() {
  assert_eq!(
    teleconverter_factor("Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO"),
    Some(1.4)
  );
  assert_eq!(
    teleconverter_factor("Minolta AF 600mm F4 HS-APO G + Minolta AF 2x APO"),
    Some(2.0)
  );
  assert_eq!(teleconverter_factor("Sony FE 24-70mm F2.8 GM"), None);
  // " + " present but no ` Nx` ⇒ no match.
  assert_eq!(teleconverter_factor("Lens + Hood"), None);
}

#[test]
fn lens_spec_suffix_match_cases() {
  // ` (` after the spec.
  assert!(lens_spec_suffix_match(
    "Sony DT 18-55mm F3.5-5.6 SAM (SAL1855)",
    "DT 18-55mm F3.5-5.6 SAM"
  ));
  // end-of-string after the spec.
  assert!(lens_spec_suffix_match(
    "Sony FE 24-70mm F2.8 GM",
    "FE 24-70mm F2.8 GM"
  ));
  // ` GM` at the end.
  assert!(lens_spec_suffix_match(
    "Some FE 21mm F2.8 GM",
    "FE 21mm F2.8"
  ));
  // a " II" tail is NOT a boundary ⇒ no match.
  assert!(!lens_spec_suffix_match(
    "Sony FE 24-70mm F2.8 GM II",
    "FE 24-70mm F2.8 GM"
  ));
  // spec absent from the name.
  assert!(!lens_spec_suffix_match(
    "Sony FE 50mm F1.8",
    "FE 24-70mm F2.8"
  ));
}

#[test]
fn strip_or_cases() {
  assert_eq!(
    strip_or("Sony DT 18-55mm F3.5-5.6 SAM (SAL1855) or SAM II"),
    "Sony DT 18-55mm F3.5-5.6 SAM (SAL1855)"
  );
  assert_eq!(strip_or("Tamron Lens (129)"), "Tamron Lens (129)");
  // "Motor" contains "or" but not " or " — not stripped.
  assert_eq!(strip_or("Motor Lens"), "Motor Lens");
}

#[test]
fn match_token_helpers() {
  assert_eq!(
    match_focal_token("FE 70-300mm F4.5-5.6").as_deref(),
    Some("70-300mm")
  );
  assert_eq!(match_focal_token("FE 50mm F1.4").as_deref(), Some("50mm"));
  assert_eq!(match_focal_token("no focal here"), None);
  assert_eq!(
    match_aperture_token("FE 24mm F1.4 GM").as_deref(),
    Some("1.4")
  );
  assert_eq!(match_aperture_token("Lens 1:2.8").as_deref(), Some("2.8"));
  assert!(aperture_matches("Sony FE 24mm F1.4 GM", "1.4"));
  assert!(!aperture_matches("Sony FE 24mm F2.8 GM", "1.4"));
}

#[test]
fn word_pattern_helpers() {
  assert_eq!(find_i_run("Some Lens III").as_deref(), Some("III"));
  assert_eq!(find_i_run("EF 70-200mm IS II USM").as_deref(), Some("II"));
  assert_eq!(find_i_run("Minolta AF Lens"), None);
  assert!(has_word("Canon EF 50mm USM", "USM"));
  assert!(!has_word("Canon EF 50mm USMx", "USM"));
}

#[test]
fn parse_lens_focal_range_cases() {
  assert_eq!(parse_lens_focal_range("50"), Some((50.0, 50.0)));
  assert_eq!(parse_lens_focal_range("18 55"), Some((18.0, 55.0)));
  assert_eq!(parse_lens_focal_range("18 to 200"), Some((18.0, 200.0)));
  assert_eq!(parse_lens_focal_range("18-55"), None);
  assert_eq!(parse_lens_focal_range(""), None);
}

#[test]
fn metabones_and_sigma_ranges() {
  assert!(is_metabones_or_sigma_adapter(0xef12)); // high byte 0xef00
  assert!(is_metabones_or_sigma_adapter(0xbc34)); // high byte 0xbc00
  assert!(is_metabones_or_sigma_adapter(0x4900)); // Sigma MC-11 low bound
  assert!(is_metabones_or_sigma_adapter(0x590a)); // Sigma MC-11 high bound
  assert!(!is_metabones_or_sigma_adapter(129)); // A200 lens — not an adapter
  assert!(!is_metabones_or_sigma_adapter(55)); // A33 lens — not an adapter
}

#[test]
fn tamron_zoom_model() {
  assert!(is_tamron_zoom("TAMRON SP 70-300mm F4-5.6"));
  assert!(!is_tamron_zoom("TAMRON 90mm F2.8 Macro")); // a prime — no `-NNmm`
  assert!(!is_tamron_zoom("Sigma 70-300mm")); // not TAMRON
}

#[test]
fn build_sony_etype_dedups_and_strips() {
  let etype = build_sony_etype();
  assert!(!etype.is_empty());
  // Every entry is de-`or`'d.
  assert!(etype.iter().all(|n| !n.contains(" or ")));
  // No duplicate names.
  let mut sorted: std::vec::Vec<&str> = etype.clone();
  sorted.sort_unstable();
  sorted.dedup();
  assert_eq!(
    sorted.len(),
    etype.len(),
    "%sonyEtype must be de-duplicated"
  );
  // The lowest string-sorted key is the integer "0".
  assert_eq!(etype.first().copied(), Some("Unknown E-mount lens"));
  // A known E-mount lens is present.
  assert!(etype.contains(&"Sony FE 24-70mm F2.8 GM"));
}
