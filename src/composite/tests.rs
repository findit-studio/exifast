//! Oracle tests for the Composite fixpoint engine ([`build_into`]) — hand-built
//! input maps proving the `Require`/`Desire`/`Inhibit` resolution, the
//! Composite-requires-Composite multi-pass deferral, the circular-dependency
//! guard, and the prefixed-id sort tiebreak. These exercise the GENERIC engine
//! with synthetic defs (the real Duration migration is pinned by the
//! conformance goldens + the differential tests in the format modules).

#![cfg(feature = "alloc")]

use super::table::{
  CompositeDef, CompositeInput, CompositePrintConv, CompositeRaw, CompositeValue, InputKind,
};
use super::*;
use crate::emit::ConvMode;
use crate::tagmap::TagMap;
use crate::value::TagValue;

// `&'static` group slices the synthetic inputs reference (a runtime `&["X"]`
// would be a dropped temporary; these `const` items give the slices `'static`).
const GX: &[&str] = &["X"];
const GP_Q: &[&str] = &["P", "Q"];
const GCOMPOSITE: &[&str] = &["Composite"];

/// A synthetic `Require`d input on `group`.
const fn req(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: group,
    name,
  }
}

/// A synthetic `Desire`d input.
const fn des(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Desire,
    groups: group,
    name,
  }
}

/// A synthetic `Inhibit` input.
const fn inh(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Inhibit,
    groups: group,
    name,
  }
}

/// Sum the present inputs (a stand-in derivation; `Missing`/non-numeric ⇒ 0).
fn sum_inputs(v: &[CompositeValue]) -> Option<CompositeRaw> {
  Some(CompositeRaw::Num(
    v.iter().map(|x| x.coerce_numeric().unwrap_or(0.0)).sum(),
  ))
}

/// Build a TagMap with the given `(group, name, value)` entries in order.
fn map_with(entries: &[(&str, &str, TagValue)]) -> TagMap {
  let mut m = TagMap::new();
  for (g, n, v) in entries {
    let _ = m.write_value_doc(0, 0, g, n, 1, v.clone());
  }
  m
}

/// The stored `Composite:<name>` value, if present.
fn composite(m: &TagMap, name: &str) -> Option<TagValue> {
  m.get("Composite", name).cloned()
}

const SUM_AB: CompositeDef = CompositeDef {
  name: "Sum",
  inputs: &[req(GX, "A"), req(GX, "B")],
  derive: sum_inputs,
  print_conv: CompositePrintConv::ConvertDuration,
  priority: 1,
  sort_key: "X-Sum",
};

#[test]
fn require_present_builds() {
  let mut m = map_with(&[("X", "A", TagValue::I64(40)), ("X", "B", TagValue::I64(20))]);
  build_into(&[SUM_AB], &mut m, None, ConvMode::ValueConv);
  // 40 + 20 = 60 seconds, ValueConv ⇒ bare f64.
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(60.0)));
}

#[test]
fn require_missing_aborts() {
  // B is absent ⇒ Require miss ⇒ no composite.
  let mut m = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[SUM_AB], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), None);
}

#[test]
fn desire_absent_still_builds_with_undef_element() {
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GX, "A"), des(GX, "B")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Sum",
  };
  // B (Desire) absent ⇒ element None (counted as 0) but the composite builds.
  let mut m = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(40.0)));
}

#[test]
fn inhibit_present_suppresses() {
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GX, "A"), inh(GX, "Block")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Sum",
  };
  // The Inhibit tag `X:Block` is present ⇒ the composite is suppressed.
  let mut m = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::I64(1)),
  ]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), None);

  // Without the Inhibit tag, it builds.
  let mut m2 = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[DEF], &mut m2, None, ConvMode::ValueConv);
  assert_eq!(composite(&m2, "Sum"), Some(TagValue::F64(40.0)));
}

#[test]
fn inhibit_present_nonnumeric_string_suppresses() {
  // Finding-1 regression: a PRESENT inhibitor of a NON-NUMERIC value (a string)
  // must suppress. ExifTool keys `Inhibit` on `defined $val[i]`, not on numeric
  // coercibility — the pre-coerced-`Option<f64>` model wrongly saw a string as
  // absent and let the composite build. The presence model fixes it.
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GX, "A"), inh(GX, "Block")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Sum",
  };
  // `X:Block = "present"` is a non-numeric string ⇒ still suppresses.
  let mut m = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::Str("present".into())),
  ]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), None);

  // Even an empty string is PRESENT (ExifTool: `defined ""` is true) ⇒ suppresses.
  let mut m2 = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::Str("".into())),
  ]);
  build_into(&[DEF], &mut m2, None, ConvMode::ValueConv);
  assert_eq!(composite(&m2, "Sum"), None);
}

#[test]
fn desire_present_nonnumeric_string_reaches_derive() {
  // Finding-1: a present-but-non-numeric (string) Desire reaches `derive` as a
  // `Present(Str)` element (so future GPS/EXIF/datetime defs can read strings),
  // NOT as a `Missing`. The derive here asserts the raw value it was handed.
  fn assert_first_is_str(v: &[CompositeValue]) -> Option<CompositeRaw> {
    assert_eq!(
      v.first().and_then(CompositeValue::value),
      Some(&TagValue::Str("N".into())),
      "a present string Desire must arrive as Present(Str), not Missing"
    );
    assert!(v.first().is_some_and(CompositeValue::is_present));
    Some(CompositeRaw::Num(1.0))
  }
  const DEF: CompositeDef = CompositeDef {
    name: "Dur",
    inputs: &[des(GX, "Ref")],
    derive: assert_first_is_str,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Dur",
  };
  let mut m = map_with(&[("X", "Ref", TagValue::Str("N".into()))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv);
  // 1.0 s ⇒ ValueConv bare f64; proves the derive ran (the asserts inside fired).
  assert_eq!(composite(&m, "Dur"), Some(TagValue::F64(1.0)));
}

#[test]
fn composite_requires_composite_deferred_then_built() {
  // `Outer` requires `Composite:Inner`; `Inner` requires `X:A`. The engine must
  // build `Inner` first (pass 1) then `Outer` (sees the just-built Inner).
  const INNER: CompositeDef = CompositeDef {
    name: "Inner",
    inputs: &[req(GX, "A")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Inner",
  };
  const OUTER: CompositeDef = CompositeDef {
    name: "Outer",
    inputs: &[req(GCOMPOSITE, "Inner"), req(GX, "B")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Outer",
  };
  let mut m = map_with(&[("X", "A", TagValue::I64(10)), ("X", "B", TagValue::I64(5))]);
  build_into(&[OUTER, INNER], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Inner"), Some(TagValue::F64(10.0)));
  // Outer = Composite:Inner (10) + X:B (5) = 15.
  assert_eq!(composite(&m, "Outer"), Some(TagValue::F64(15.0)));
}

#[test]
fn composite_requires_composite_in_reverse_sort_order() {
  // Same as above but Outer sorts BEFORE Inner — Outer is attempted first,
  // must defer (Inner not built), then built in the second pass.
  const INNER: CompositeDef = CompositeDef {
    name: "Inner",
    inputs: &[req(GX, "A")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "Z-Inner", // sorts AFTER Outer
  };
  const OUTER: CompositeDef = CompositeDef {
    name: "Outer",
    inputs: &[req(GCOMPOSITE, "Inner")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "A-Outer", // sorts BEFORE Inner ⇒ attempted first ⇒ defers
  };
  let mut m = map_with(&[("X", "A", TagValue::I64(7))]);
  build_into(&[INNER, OUTER], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Inner"), Some(TagValue::F64(7.0)));
  assert_eq!(composite(&m, "Outer"), Some(TagValue::F64(7.0)));
}

#[test]
fn circular_dependency_does_not_loop() {
  // A requires Composite:B, B requires Composite:A — neither can build. The
  // fixpoint must terminate (the `$allBuilt` last-ditch pass then stop) and
  // emit neither.
  const A: CompositeDef = CompositeDef {
    name: "A",
    inputs: &[req(GCOMPOSITE, "B")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "M-A",
  };
  const B: CompositeDef = CompositeDef {
    name: "B",
    inputs: &[req(GCOMPOSITE, "A")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "M-B",
  };
  let mut m = TagMap::new();
  build_into(&[A, B], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "A"), None);
  assert_eq!(composite(&m, "B"), None);
}

#[test]
fn last_emitted_duplicate_wins_across_group_set() {
  // The APE_dup_override shape: a multi-group input set `{P, Q}`; the LAST
  // emitted match wins. `Q:A` is emitted after `P:A`, so 99 wins over 1.
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GP_Q, "A")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    priority: 1,
    sort_key: "X-Sum",
  };
  let mut m = map_with(&[("P", "A", TagValue::I64(1)), ("Q", "A", TagValue::I64(99))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(99.0)));
}

/// A derivation that always aborts (the `… ? … : undef` guard).
fn always_none(_v: &[CompositeValue]) -> Option<CompositeRaw> {
  None
}

const NONE_DEF: CompositeDef = CompositeDef {
  name: "Sum",
  inputs: &[req(GX, "A")],
  derive: always_none,
  print_conv: CompositePrintConv::ConvertDuration,
  priority: 1,
  sort_key: "X-Sum",
};

#[test]
fn derive_returning_none_emits_nothing() {
  // The `… ? … : undef` guard: a derivation returning None settles the def
  // without emitting (no panic, no spurious tag).
  let mut m = map_with(&[("X", "A", TagValue::I64(5))]);
  build_into(&[NONE_DEF], &mut m, None, ConvMode::ValueConv);
  assert_eq!(composite(&m, "Sum"), None);
}

/// A derivation yielding input 0's numeric coercion verbatim.
fn first_input(v: &[CompositeValue]) -> Option<CompositeRaw> {
  Some(CompositeRaw::Num(v.first()?.coerce_numeric()?))
}

const DUR_DEF: CompositeDef = CompositeDef {
  name: "Dur",
  inputs: &[req(GX, "A")],
  derive: first_input,
  print_conv: CompositePrintConv::ConvertDuration,
  priority: 1,
  sort_key: "X-Dur",
};

#[test]
fn composite_appended_after_format_tags_keeps_last_position() {
  // The positional last-ness the Duration goldens require: the composite is the
  // LAST entry in the map after the build pass.
  let mut m = map_with(&[
    ("X", "A", TagValue::I64(30)),
    ("X", "Z", TagValue::Str("tail".into())),
  ]);
  build_into(&[DUR_DEF], &mut m, None, ConvMode::PrintConv);
  let last = m.entries().last().expect("non-empty");
  assert_eq!(last.2.as_str(), "Composite");
  assert_eq!(last.3.as_str(), "Dur");
  // 30 s ⇒ ConvertDuration "0:00:30" under PrintConv.
  assert_eq!(last.5, TagValue::Str("0:00:30".into()));
}

// A def over one `Require`d input `X:A` whose derivation simply Perl-coerces
// that input numerically (`coerce_numeric` ⇒ `convert::perl_str_to_f64`). The
// appended `Composite:Probe` value is the f64 the engine resolved + coerced —
// so the stored value reveals WHICH form (raw vs printed) the input resolved to.
const PROBE_DEF: CompositeDef = CompositeDef {
  name: "Probe",
  inputs: &[req(GX, "A")],
  derive: first_input,
  // ValueConv output ⇒ a bare f64, so the resolved-then-coerced value is read
  // back directly (no ConvertDuration formatting to decode).
  print_conv: CompositePrintConv::ConvertDuration,
  priority: 1,
  sort_key: "X-Probe",
};

#[test]
fn input_resolves_from_raw_value_not_printconv_in_both_modes() {
  // Finding 2 (input model): a composite's inputs must resolve from each
  // ingredient's RAW / post-ValueConv value REGARDLESS of the `-j`/`-n` output
  // mode (ExifTool `GetValue($tag, 'ValueConv')` for `$val[i]`, ExifTool.pm:
  // 4112) — NOT the printed (PrintConv) form. Here `X:A`'s RAW value is
  // `I64(42)` (coerces to 42.0) while its hypothetical PRINTED form is
  // `Str("North")` (coerces to 0.0), so the resolved-and-coerced composite
  // value distinguishes the two: 42.0 ⇒ raw was read, 0.0 ⇒ the printed sink
  // leaked in.

  // `-n` (ValueConv): the single `out` sink holds the raw value (its own
  // resolution view). The composite must read 42.0.
  let mut out_n = map_with(&[("X", "A", TagValue::I64(42))]);
  build_into(&[PROBE_DEF], &mut out_n, None, ConvMode::ValueConv);
  assert_eq!(
    composite(&out_n, "Probe"),
    Some(TagValue::F64(42.0)),
    "-n: composite must resolve its input from the raw ValueConv value (42), not 0"
  );

  // `-j` (PrintConv): the OUTPUT sink holds the PRINTED form `Str("North")`
  // (which would coerce to 0.0), while a SEPARATE raw view holds the raw
  // `I64(42)`. The engine must resolve the input from the raw view ⇒ 42.0, even
  // though the output is rendered in `-j`. This is the case Duration could not
  // exercise (its ingredients have no PrintConv, so raw == printed).
  let mut out_j = map_with(&[("X", "A", TagValue::Str("North".into()))]);
  let mut raw_view = map_with(&[("X", "A", TagValue::I64(42))]);
  build_into(
    &[PROBE_DEF],
    &mut out_j,
    Some(&mut raw_view),
    ConvMode::PrintConv,
  );
  // 42 s ⇒ ConvertDuration "0:00:42" under `-j` — proving the input was the raw
  // 42 (a leaked `Str("North")` ⇒ 0.0 ⇒ ConvertDuration "0 s").
  assert_eq!(
    composite(&out_j, "Probe"),
    Some(TagValue::Str("0:00:42".into())),
    "-j: composite must resolve its input from the raw ValueConv value (42 ⇒ \"0:00:42\"), not the printed \"North\" (⇒ 0 ⇒ \"0 s\")"
  );
  // And the composite's RENDERED value lands in `out`, NOT in the raw view's
  // rendered slot — the raw view carries the composite's RAW form (F64) for any
  // dependent composite's `$val[i]`.
  assert_eq!(composite(&raw_view, "Probe"), Some(TagValue::F64(42.0)));
}

const SIGNED_SUM: CompositeDef = CompositeDef {
  name: "Sum",
  inputs: &[req(GX, "A"), req(GX, "B")],
  derive: sum_inputs,
  print_conv: CompositePrintConv::ConvertDuration,
  priority: 1,
  sort_key: "X-Sum",
};

#[test]
fn signed_and_whitespace_string_ingredients_coerce_via_shared_perl_rule() {
  // Finding 1: a Composite ingredient supplied as a Perl-numeric STRING with a
  // leading sign / whitespace / dual sign must coerce through the SHARED
  // `convert::perl_str_to_f64` (now carrying APE's dual-sign + inter-sign
  // whitespace rule). APE main tags hand `SampleRate`/`TotalFrames` as MakeTag
  // strings, so the engine's `coerce_numeric` is the path under test.

  // `" +44100"` (leading ws + sign) → 44100; `"++1000"` (dual `+`) → 1000.
  let mut m = map_with(&[
    ("X", "A", TagValue::Str(" +44100".into())),
    ("X", "B", TagValue::Str("++1000".into())),
  ]);
  build_into(&[SIGNED_SUM], &mut m, None, ConvMode::ValueConv);
  assert_eq!(
    composite(&m, "Sum"),
    Some(TagValue::F64(45100.0)),
    "signed/dual-sign/whitespace string ingredients must Perl-coerce (44100 + 1000)"
  );

  // Dual-sign that resolves NEGATIVE (`"+-20"` → -20) and the inter-sign
  // whitespace form (`"- +5"` → -5): sum = -25.
  let mut m2 = map_with(&[
    ("X", "A", TagValue::Str("+-20".into())),
    ("X", "B", TagValue::Str("- +5".into())),
  ]);
  build_into(&[SIGNED_SUM], &mut m2, None, ConvMode::ValueConv);
  assert_eq!(composite(&m2, "Sum"), Some(TagValue::F64(-25.0)));

  // A REJECTED dual-sign form (ws after sign 2: `"+- 20"` → 0) coerces to 0,
  // matching Perl — so the shared reject rule is live in the engine path too.
  let mut m3 = map_with(&[
    ("X", "A", TagValue::Str("+- 20".into())),
    ("X", "B", TagValue::Str("100".into())),
  ]);
  build_into(&[SIGNED_SUM], &mut m3, None, ConvMode::ValueConv);
  assert_eq!(composite(&m3, "Sum"), Some(TagValue::F64(100.0)));
}

// ===========================================================================
// The registered GPS Composites (GPS.pm / Exif.pm) — end-to-end through the
// real `REGISTRY` over a two-view (ValueConv + PrintConv) GPS TagMap pair. These
// mirror the bundled-ExifTool `ExifGPS.tif` truth and exercise the `$prt[i]`
// wiring + the `GPSPosition`-requires-two-Composites fixpoint deferral.
// ===========================================================================

#[cfg(feature = "exif")]
mod gps {
  use super::*;

  /// The ExifGPS.tif GPS inputs as the (ValueConv view, PrintConv view) pair the
  /// engine reads `$val[i]` / `$prt[i]` from. ValueConv: decimal coords + `"N"`/
  /// `"E"` refs + altitude `35`/ref `0` + the date/time strings. PrintConv: the
  /// GPS-main DMS strings + `"North"`/`"East"` + `"Above Sea Level"`.
  fn exifgps_views() -> (TagMap, TagMap) {
    let val = map_with(&[
      ("GPS", "GPSLatitude", TagValue::F64(48.85815)),
      ("GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
      ("GPS", "GPSLongitude", TagValue::F64(2.34893333333333)),
      ("GPS", "GPSLongitudeRef", TagValue::Str("E".into())),
      ("GPS", "GPSAltitude", TagValue::F64(35.0)),
      ("GPS", "GPSAltitudeRef", TagValue::U64(0)),
      ("GPS", "GPSDateStamp", TagValue::Str("2021:08:14".into())),
      ("GPS", "GPSTimeStamp", TagValue::Str("16:45:09".into())),
    ]);
    let prt = map_with(&[
      (
        "GPS",
        "GPSLatitude",
        TagValue::Str("48 deg 51' 29.34\"".into()),
      ),
      ("GPS", "GPSLatitudeRef", TagValue::Str("North".into())),
      (
        "GPS",
        "GPSLongitude",
        TagValue::Str("2 deg 20' 56.16\"".into()),
      ),
      ("GPS", "GPSLongitudeRef", TagValue::Str("East".into())),
      ("GPS", "GPSAltitude", TagValue::Str("35 m".into())),
      (
        "GPS",
        "GPSAltitudeRef",
        TagValue::Str("Above Sea Level".into()),
      ),
      ("GPS", "GPSDateStamp", TagValue::Str("2021:08:14".into())),
      ("GPS", "GPSTimeStamp", TagValue::Str("16:45:09".into())),
    ]);
    (val, prt)
  }

  #[test]
  fn printconv_builds_all_gps_composites_byte_exact() {
    // `-j`: `out` = the PrintConv view, `other` = the ValueConv view. Byte-exact
    // against bundled `ExifGPS.tif` `Composite:*`.
    let (mut val, mut prt) = exifgps_views();
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "GPSLatitude"),
      Some(TagValue::Str("48 deg 51' 29.34\" N".into()))
    );
    assert_eq!(
      composite(&prt, "GPSLongitude"),
      Some(TagValue::Str("2 deg 20' 56.16\" E".into()))
    );
    assert_eq!(
      composite(&prt, "GPSAltitude"),
      Some(TagValue::Str("35 m Above Sea Level".into()))
    );
    assert_eq!(
      composite(&prt, "GPSDateTime"),
      Some(TagValue::Str("2021:08:14 16:45:09Z".into()))
    );
    // `GPSPosition`'s PrintConv is the literal `"$prt[0], $prt[1]"` — the two
    // ingredient Composites' DMS strings (the `$prt[i]` wiring under test).
    assert_eq!(
      composite(&prt, "GPSPosition"),
      Some(TagValue::Str(
        "48 deg 51' 29.34\" N, 2 deg 20' 56.16\" E".into()
      ))
    );
  }

  #[test]
  fn valueconv_builds_all_gps_composites_byte_exact() {
    // `-n`: `out` = the ValueConv view, `other` = the PrintConv view. Byte-exact
    // against bundled `ExifGPS.tif` `-n` `Composite:*`.
    let (mut val, mut prt) = exifgps_views();
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "GPSLatitude"),
      Some(TagValue::F64(48.85815))
    );
    assert_eq!(
      composite(&val, "GPSLongitude"),
      Some(TagValue::F64(2.34893333333333))
    );
    assert_eq!(composite(&val, "GPSAltitude"), Some(TagValue::F64(35.0)));
    assert_eq!(
      composite(&val, "GPSDateTime"),
      Some(TagValue::Str("2021:08:14 16:45:09Z".into()))
    );
    // `GPSPosition`'s ValueConv is `"$val[0] $val[1]"` — the decimal coords.
    assert_eq!(
      composite(&val, "GPSPosition"),
      Some(TagValue::Str("48.85815 2.34893333333333".into()))
    );
  }

  #[test]
  fn ref_sign_negates_south_and_west() {
    // ValueConv `$val[1] =~ /^S/i ? -$val[0]` (lat) / `/^W/i ? -$val[0]` (lon).
    let entries: &[(&str, &str, TagValue)] = &[
      ("GPS", "GPSLatitude", TagValue::F64(48.85815)),
      ("GPS", "GPSLatitudeRef", TagValue::Str("S".into())),
      ("GPS", "GPSLongitude", TagValue::F64(2.34893333333333)),
      ("GPS", "GPSLongitudeRef", TagValue::Str("W".into())),
    ];
    let mut out = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut out, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&out, "GPSLatitude"),
      Some(TagValue::F64(-48.85815)),
      "ref S ⇒ negative latitude"
    );
    assert_eq!(
      composite(&out, "GPSLongitude"),
      Some(TagValue::F64(-2.34893333333333)),
      "ref W ⇒ negative longitude"
    );
  }

  #[test]
  fn gps_position_requires_both_composites_fixpoint_defers() {
    // `GPSPosition` `Require`s `Composite:GPSLatitude` + `Composite:GPSLongitude`
    // (sort_key `Composite-GPSPosition`, AFTER `GPS-…`), so it is attempted, the
    // two ingredient Composites are not yet built ⇒ it DEFERS, then builds in a
    // later pass once they exist (the composite-on-composite fixpoint).
    let (mut val, mut prt) = exifgps_views();
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    // Built only because the deferral resolved Composite:GPSLatitude/Longitude.
    assert_eq!(
      composite(&val, "GPSPosition"),
      Some(TagValue::Str("48.85815 2.34893333333333".into()))
    );
  }

  #[test]
  fn gps_position_not_built_when_a_coordinate_is_missing() {
    // No `GPSLongitude` ⇒ `Composite:GPSLongitude` never builds ⇒ `GPSPosition`'s
    // `Require` of it fails (after the fixpoint settles), so neither builds.
    let entries: &[(&str, &str, TagValue)] = &[
      ("GPS", "GPSLatitude", TagValue::F64(48.85815)),
      ("GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
    ];
    let mut out = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut out, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&out, "GPSLatitude"),
      Some(TagValue::F64(48.85815))
    );
    assert_eq!(composite(&out, "GPSLongitude"), None);
    assert_eq!(composite(&out, "GPSPosition"), None);
  }

  #[test]
  fn gps_datetime_requires_both_date_and_time() {
    // `GPSDateTime` `Require`s GPSDateStamp + GPSTimeStamp; a TimeStamp-only
    // input (the `ExifGPS.jpg` shape) must NOT build it.
    let entries: &[(&str, &str, TagValue)] =
      &[("GPS", "GPSTimeStamp", TagValue::Str("16:45:09".into()))];
    let mut out = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut out, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&out, "GPSDateTime"), None);
  }

  #[test]
  fn gps_altitude_requires_a_ref() {
    // The RawConv `(defined $val[1] or defined $val[3]) ? $val : undef` — an
    // altitude with NO ref builds nothing.
    let entries: &[(&str, &str, TagValue)] = &[("GPS", "GPSAltitude", TagValue::F64(35.0))];
    let mut out = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut out, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&out, "GPSAltitude"), None);
  }

  #[test]
  fn gps_altitude_comma_decimal_is_isfloat_normalized_both_modes() {
    // ExifTool `IsFloat($val[$_])` translates `,`→`.` IN PLACE (ExifTool.pm:5951),
    // so the altitude `"12,5"` (the wire string XMP preserves) is coerced AS
    // `12.5`, NOT `12` (a raw `$val+0` would treat the comma as a numeric-prefix
    // terminator). Bundled-ExifTool 13.59 on an `XMP-exif:GPSAltitude=12,5` +
    // above-sea ref emits `Composite:GPSAltitude` = `12.5` (-n) / `12.5 m Above
    // Sea Level` (-j). The input arrives at the GPS pair (index 0/1) as a string.
    let val_entries: &[(&str, &str, TagValue)] = &[
      ("GPS", "GPSAltitude", TagValue::Str("12,5".into())),
      ("GPS", "GPSAltitudeRef", TagValue::U64(0)),
    ];
    let prt_entries: &[(&str, &str, TagValue)] = &[
      ("GPS", "GPSAltitude", TagValue::Str("12,5 m".into())),
      (
        "GPS",
        "GPSAltitudeRef",
        TagValue::Str("Above Sea Level".into()),
      ),
    ];

    // `-n` (ValueConv): the normalized `12.5`, not `12`.
    let mut val = map_with(val_entries);
    let mut prt = map_with(prt_entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "GPSAltitude"), Some(TagValue::F64(12.5)));

    // `-j` (PrintConv): `(int($val[0]*10)/10) m $prt[1]` over the normalized
    // value ⇒ `12.5 m Above Sea Level`, not `12 m …`.
    let mut val = map_with(val_entries);
    let mut prt = map_with(prt_entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "GPSAltitude"),
      Some(TagValue::Str("12.5 m Above Sea Level".into()))
    );
  }
}
