//! Byte-exact tests for the `ScaleFactor35efl` lens-chain helpers against the
//! bundled-ExifTool 13.59 Perl originals (`CalcScaleFactor35efl`,
//! `CalculateLV`, `ToFloat`, and the optics PrintConv formatters), pinned to the
//! values the regenerated stills (NikonD2Hs / Pentax / DJI_Matrice30T /
//! DJIPhantom4) carry (2026-06-20).

use super::*;
use crate::composite::table::CompositeValue;
use crate::value::TagValue;

fn present(v: TagValue) -> CompositeValue {
  CompositeValue::Present(v)
}

#[test]
fn to_float_numeric_and_string_prefix() {
  // Numeric scalars pass through.
  assert_eq!(to_float(&present(TagValue::I64(50))), Some(50.0));
  assert_eq!(to_float(&present(TagValue::U64(75))), Some(75.0));
  assert_eq!(to_float(&present(TagValue::F64(9.1))), Some(9.1));
  // A float-shaped string ⇒ its leading prefix.
  assert_eq!(to_float(&present(TagValue::Str("1.5".into()))), Some(1.5));
  assert_eq!(to_float(&present(TagValue::Str("50mm".into()))), Some(50.0));
  assert_eq!(to_float(&present(TagValue::Str(".5".into()))), Some(0.5));
  assert_eq!(to_float(&present(TagValue::Str("+3".into()))), Some(3.0));
  // A non-float string ⇒ None (Perl undef), NOT a non-finite coercion.
  assert_eq!(to_float(&present(TagValue::Str("inf".into()))), None);
  assert_eq!(to_float(&present(TagValue::Str("nan".into()))), None);
  assert_eq!(to_float(&present(TagValue::Str("undef".into()))), None);
  assert_eq!(to_float(&present(TagValue::Str("".into()))), None);
  assert_eq!(to_float(&present(TagValue::Str("+".into()))), None);
  assert_eq!(to_float(&present(TagValue::Str("abc".into()))), None);
  // A Missing input ⇒ None.
  assert_eq!(to_float(&CompositeValue::Missing), None);
}

#[test]
fn to_float_scans_first_numeric_run_unanchored() {
  // ExifTool's `ToFloat` regex is UNANCHORED: a labelled / prefixed value still
  // contributes its FIRST numeric run anywhere in the string — it is NOT just a
  // leading-prefix or first-byte check. These all FAILED the old first-byte test.
  let s = |t: &str| to_float(&present(TagValue::Str(t.into())));
  assert_eq!(s("f/2.8"), Some(2.8)); // the `2.8` after the `f/`
  assert_eq!(s("Auto ISO 100"), Some(100.0)); // the trailing `100`
  assert_eq!(s("foo50mm"), Some(50.0)); // the embedded `50`
  assert_eq!(s(" 50mm"), Some(50.0)); // leading whitespace, then `50`
  assert_eq!(s("1.5 m"), Some(1.5)); // `1.5`, the ` m` ends the run
  assert_eq!(s("   .5x"), Some(0.5)); // leading whitespace then a `.digit` run
  // Sign + exponent forms anywhere in the string.
  assert_eq!(s("val=-3"), Some(-3.0)); // a `-`-signed run mid-string
  assert_eq!(s("x+3"), Some(3.0)); // a `+`-signed run mid-string
  assert_eq!(s("E=1.2e3J"), Some(1200.0)); // the exponent run `1.2e3`
  assert_eq!(s("t-2.5E-2s"), Some(-0.025)); // signed mantissa + signed exponent
  assert_eq!(s("++3"), Some(3.0)); // the lone `+` is skipped; `+3` matches at offset 1
  // The first run wins (left-to-right scan).
  assert_eq!(s("12 and 34"), Some(12.0));
  // No numeric run anywhere ⇒ None (Perl undef) — incl. a leading inf/nan word.
  assert_eq!(s("no digits"), None);
  assert_eq!(s("inf"), None);
  assert_eq!(s("nan tail"), None);
  assert_eq!(s("+-"), None);
  assert_eq!(s(". "), None); // a lone dot (no following digit) is not a run
}

#[test]
fn to_float_exact_capture_closes_msvcrt_over_read_class() {
  // ExifTool's `ToFloat` captures ONLY `$1` = the regex span
  // `[+-]?(?=\d|\.\d)\d*(\.\d*)?([eE][+-]?\d+)?`, then numifies it (`$1 + 0`).
  // A trailing MSVCRT non-finite spelling is therefore NEVER over-read — the `#`
  // stops the capture. Oracle (real Perl `ToFloat`): `1.#INF`→1, `1#INF`→1,
  // `-1.#INF`→-1, `foo1.#NAN`→1, `1.#QNAN`→1, `1.#IND`→1.
  let s = |t: &str| to_float(&present(TagValue::Str(t.into())));
  assert_eq!(s("1.#INF"), Some(1.0)); // captures "1." → 1 (NOT +Inf)
  assert_eq!(s("1#INF"), Some(1.0)); // captures "1" → 1
  assert_eq!(s("-1.#INF"), Some(-1.0)); // captures "-1." → -1 (NOT -Inf)
  assert_eq!(s("foo1.#NAN"), Some(1.0)); // scans to "1.", captures it → 1 (NOT NaN)
  assert_eq!(s("1.#QNAN"), Some(1.0)); // captures "1." → 1
  assert_eq!(s("1.#IND"), Some(1.0)); // captures "1." → 1
  assert_eq!(s("2.#INF"), Some(2.0)); // captures "2." → 2
  // Exponent then junk: the exponent IS captured (it has a full power), the
  // trailing letters are not. `1.5e3xyz`→1500, `1.5E10tail`→15000000000.
  assert_eq!(s("1.5e3xyz"), Some(1500.0));
  assert_eq!(s("1.5E10tail"), Some(15_000_000_000.0));
  // A bare `[Ee]` with no power is NOT consumed (the exponent group is optional
  // and requires ≥1 power digit): `1.5e`→1.5, `1.5e+`→1.5, `1.5ex`→1.5.
  assert_eq!(s("1.5e"), Some(1.5));
  assert_eq!(s("1.5e+"), Some(1.5));
  assert_eq!(s("1.5ex"), Some(1.5));
  // Re-confirm the R2 happy-path cases still parse with the exact-capture scan.
  assert_eq!(s("f/2.8"), Some(2.8)); // captures "2.8"
  assert_eq!(s("Auto ISO 100"), Some(100.0)); // captures "100"
  assert_eq!(s("50mm"), Some(50.0)); // captures "50"
  assert_eq!(s("50"), Some(50.0)); // a plain "50" still parses to 50.0
  assert_eq!(s("1.2e3"), Some(1200.0)); // a normal exponent is unaffected
}

#[test]
fn calculate_lv_exact_capture_closes_msvcrt_over_read_class() {
  // `CalculateLV` uses the SAME `ToFloat` regex per arg (`$_ = $1`), so an arg
  // with a trailing MSVCRT spelling captures ONLY the finite mantissa — never the
  // over-read non-finite that would poison the log2 formula. A `1.#INF` aperture
  // captures "1." → 1; LV(1, 0.008, 800) = log(1*1*100/(0.008*800))/log(2).
  let want = (1.0_f64 * 1.0 * 100.0 / (0.008 * 800.0)).ln() / 2.0_f64.ln();
  let got = calculate_lv("1.#INF", "0.008", "800").unwrap();
  assert_eq!(
    crate::value::format_g(got, 15),
    crate::value::format_g(want, 15)
  );
  // Each arg position closes the class identically (the captured finite mantissa
  // drives the formula, no `Inf`/`NaN` leaks in):
  // shutter "1.#INF"→1, iso "1.#INF"→1 both yield finite, positive LV inputs.
  assert!(calculate_lv("4", "1.#INF", "800").is_some());
  assert!(calculate_lv("4", "0.008", "1.#INF").is_some());
  // An exponent-then-junk arg captures the full exponent: "1.5e3xyz"→1500 (a
  // positive, finite LV input).
  assert!(calculate_lv("1.5e3xyz", "0.008", "800").is_some());
  // Re-confirm the R2 happy-path LV (bare numbers) is unchanged by exact-capture.
  let bare = calculate_lv("4", "0.008", "800").unwrap();
  assert_eq!(crate::value::format_g(bare, 15), "7.96578428466209");
}

#[test]
fn scale_factor_simple_foc35_over_focal() {
  // The simplest path: `$foc35 / $focal` when both present + truthy. NikonD2Hs
  // 75/50 = 1.5; DJI_Matrice30T 40/9.1 = 4.3956043956044.
  let nikon = ScaleFactorInputs {
    focal: Some(&present(TagValue::F64(50.0))),
    foc35: Some(&present(TagValue::F64(75.0))),
    digital_zoom: None,
    focal_plane_diagonal: None,
    sensor_size: None,
    focal_plane_x_size: None,
    focal_plane_y_size: None,
    resolution_unit: None,
    x_resolution: None,
    y_resolution: None,
    size_pairs: [(None, None), (None, None), (None, None)],
  };
  assert_eq!(
    calc_scale_factor_35efl(false, &nikon),
    ScaleFactorOutcome::Factor(1.5)
  );
  let dji = ScaleFactorInputs {
    focal: Some(&present(TagValue::F64(9.1))),
    foc35: Some(&present(TagValue::F64(40.0))),
    digital_zoom: None,
    focal_plane_diagonal: None,
    sensor_size: None,
    focal_plane_x_size: None,
    focal_plane_y_size: None,
    resolution_unit: None,
    x_resolution: None,
    y_resolution: None,
    size_pairs: [(None, None), (None, None), (None, None)],
  };
  let ScaleFactorOutcome::Factor(f) = calc_scale_factor_35efl(false, &dji) else {
    panic!("expected a factor");
  };
  assert_eq!(crate::value::format_g(f, 15), "4.3956043956044");
}

#[test]
fn scale_factor_canon_branch_deferred() {
  // A Canon body whose simple `$foc35 / $focal` path does NOT fire (no foc35)
  // signals the deferred Canon branch — NOT a generic value. (Exif.tif: Make=
  // Canon, FocalLength=50, no FocalLengthIn35mmFormat ⇒ bundled emits no
  // ScaleFactor35efl.)
  let canon = ScaleFactorInputs {
    focal: Some(&present(TagValue::F64(50.0))),
    foc35: None,
    digital_zoom: None,
    focal_plane_diagonal: None,
    sensor_size: None,
    focal_plane_x_size: None,
    focal_plane_y_size: None,
    resolution_unit: None,
    x_resolution: None,
    y_resolution: None,
    size_pairs: [(None, None), (None, None), (None, None)],
  };
  assert_eq!(
    calc_scale_factor_35efl(true, &canon),
    ScaleFactorOutcome::CanonBranch
  );
  // But a Canon body WITH foc35 still takes the simple path (the Canon branch is
  // only reached when `$foc35 / $focal` does not fire).
  let canon_foc35 = ScaleFactorInputs {
    focal: Some(&present(TagValue::F64(50.0))),
    foc35: Some(&present(TagValue::F64(75.0))),
    ..no_inputs()
  };
  assert_eq!(
    calc_scale_factor_35efl(true, &canon_foc35),
    ScaleFactorOutcome::Factor(1.5)
  );
}

#[test]
fn scale_factor_undef_when_no_data() {
  // No focal/foc35 and no sensor data ⇒ undef.
  assert_eq!(
    calc_scale_factor_35efl(false, &no_inputs()),
    ScaleFactorOutcome::Undef
  );
}

fn no_inputs<'a>() -> ScaleFactorInputs<'a> {
  ScaleFactorInputs {
    focal: None,
    foc35: None,
    digital_zoom: None,
    focal_plane_diagonal: None,
    sensor_size: None,
    focal_plane_x_size: None,
    focal_plane_y_size: None,
    resolution_unit: None,
    x_resolution: None,
    y_resolution: None,
    size_pairs: [(None, None), (None, None), (None, None)],
  }
}

#[test]
fn calculate_lv_log2_formula() {
  // NikonD2Hs: Aperture=4, ShutterSpeed=0.008, ISO=800 ⇒ 7.96578428466209.
  let lv = calculate_lv("4", "0.008", "800").unwrap();
  assert_eq!(crate::value::format_g(lv, 15), "7.96578428466209");
  // Pentax: Aperture=13, ShutterSpeed=0.01, ISO=100 ⇒ 14.0447356260569.
  let lv = calculate_lv("13", "0.01", "100").unwrap();
  assert_eq!(crate::value::format_g(lv, 15), "14.0447356260569");
  // DJIPhantom4: Aperture=2.8, ShutterSpeed=0.002546, ISO=100 ⇒ 11.5884055197633.
  let lv = calculate_lv("2.8", "0.002546", "100").unwrap();
  assert_eq!(crate::value::format_g(lv, 15), "11.5884055197633");
  // Any non-positive / non-float arg ⇒ None (the `$1 > 0` guard).
  assert_eq!(calculate_lv("0", "0.008", "800"), None);
  assert_eq!(calculate_lv("4", "undef", "800"), None);
  assert_eq!(calculate_lv("4", "0.008", "-100"), None);
  // `CalculateLV` uses the SAME unanchored first-float scan: a labelled arg still
  // contributes its first positive numeric run, identical to feeding the bare
  // numbers. `"f/4"`→4, `"ISO 800"`→800; both match the bare-number LV.
  let bare = calculate_lv("4", "0.008", "800").unwrap();
  let labelled = calculate_lv("f/4", "0.008", "ISO 800").unwrap();
  assert_eq!(
    crate::value::format_g(labelled, 15),
    crate::value::format_g(bare, 15)
  );
  // A labelled non-positive / no-run arg still fails the `$1 > 0` / regex guard.
  assert_eq!(calculate_lv("ISO 0", "0.008", "800"), None);
  assert_eq!(calculate_lv("4", "shutter", "800"), None);
}

#[test]
fn circle_of_confusion_value_and_print() {
  // NikonD2Hs SF=1.5 ⇒ sqrt(24*24+36*36)/(1.5*1440) = 0.0200308404192444.
  let coc = frame_diag_35mm() / (1.5 * 1440.0);
  assert_eq!(crate::value::format_g(coc, 15), "0.0200308404192444");
  assert_eq!(print_circle_of_confusion(coc), "0.020 mm");
  // DJI_Matrice30T SF=40/9.1 ⇒ 0.00683552429306715 (a 17-fraction-digit value
  // the EscapeJSON gate quotes — but the helper renders the print form).
  let coc = frame_diag_35mm() / ((40.0 / 9.1) * 1440.0);
  assert_eq!(crate::value::format_g(coc, 15), "0.00683552429306715");
  assert_eq!(print_circle_of_confusion(coc), "0.007 mm");
}

#[test]
fn focal_length_35efl_print_branches() {
  // With a truthy scale factor: the two-number form. NikonD2Hs focal=50, SF=1.5,
  // equiv=75 ⇒ "50.0 mm (35 mm equivalent: 75.0 mm)".
  assert_eq!(
    print_focal_length_35efl(50.0, Some(1.5), 75.0),
    "50.0 mm (35 mm equivalent: 75.0 mm)"
  );
  // DJI_Matrice30T focal=9.1, SF=4.3956, equiv=40 ⇒ "9.1 mm (35 mm equivalent:
  // 40.0 mm)".
  assert_eq!(
    print_focal_length_35efl(9.1, Some(40.0 / 9.1), 40.0),
    "9.1 mm (35 mm equivalent: 40.0 mm)"
  );
  // No scale factor (or a falsy 0): the single-number form. Exif.tif focal=50,
  // equiv=50 ⇒ "50.0 mm"; ExifGPS.jpg focal=0 ⇒ "0.0 mm".
  assert_eq!(print_focal_length_35efl(50.0, None, 50.0), "50.0 mm");
  assert_eq!(print_focal_length_35efl(0.0, None, 0.0), "0.0 mm");
  assert_eq!(print_focal_length_35efl(50.0, Some(0.0), 50.0), "50.0 mm");
}

#[test]
fn hyperfocal_print_finite_and_inf() {
  // NikonD2Hs 31.2018860376691 ⇒ "31.20 m"; Pentax 0.384023 ⇒ "0.38 m".
  assert_eq!(print_hyperfocal(31.2018860376691), "31.20 m");
  assert_eq!(print_hyperfocal(0.384023212771312), "0.38 m");
  // The `'inf'` ValueConv sentinel (INFINITY) ⇒ "Inf m" (Perl `sprintf("%.2f",
  // "inf")` uppercases).
  assert_eq!(print_hyperfocal(f64::INFINITY), "Inf m");
}

#[test]
fn dof_print_split_and_format() {
  // NikonD2Hs: near=0.693325809394639, far=0.723195615956146, dof=0.0299 (>0.02)
  // ⇒ "%.2f" ⇒ "0.03 m (0.69 - 0.72 m)".
  assert_eq!(
    print_dof("0.693325809394639 0.723195615956146"),
    "0.03 m (0.69 - 0.72 m)"
  );
  // DJI_Matrice30T: 3.54114619724571 8.50299940251809, dof=4.96 ⇒ "4.96 m (3.54
  // - 8.50 m)".
  assert_eq!(
    print_dof("3.54114619724571 8.50299940251809"),
    "4.96 m (3.54 - 8.50 m)"
  );
  // far == 0 ⇒ the "inf" form.
  assert_eq!(print_dof("2.5 0"), "inf (2.50 m - inf)");
  // A thin DOF (0 < dof < 0.02) ⇒ the "%.3f" precision.
  assert_eq!(print_dof("1.0 1.01"), "0.010 m (1.000 - 1.010 m)");
}

#[test]
fn fov_print_angle_and_optional_distance() {
  // NikonD2Hs: "25.1479641359127 0.315813976504386" ⇒ "25.1 deg (0.32 m)".
  assert_eq!(
    print_fov("25.1479641359127 0.315813976504386"),
    "25.1 deg (0.32 m)"
  );
  // Pentax: a lone angle ⇒ "100.4 deg".
  assert_eq!(print_fov("100.388942610382"), "100.4 deg");
  // DJI_Matrice30T: 48.4555315645449 ⇒ "48.5 deg".
  assert_eq!(print_fov("48.4555315645449"), "48.5 deg");
  // A zero distance is NOT appended (Perl-truthy `$v[1]`).
  assert_eq!(print_fov("30.0 0"), "30.0 deg");
}
