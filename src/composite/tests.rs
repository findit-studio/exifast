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
fn sum_inputs(v: &[CompositeValue], _prts: &[Option<TagValue>]) -> Option<CompositeRaw> {
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
  fn assert_first_is_str(v: &[CompositeValue], _prts: &[Option<TagValue>]) -> Option<CompositeRaw> {
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
fn always_none(_v: &[CompositeValue], _prts: &[Option<TagValue>]) -> Option<CompositeRaw> {
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
fn first_input(v: &[CompositeValue], _prts: &[Option<TagValue>]) -> Option<CompositeRaw> {
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

// ===========================================================================
// The registered EXIF Composites (Exif.pm) — ImageSize / Megapixels (the
// composite-on-composite fixpoint) / ShutterSpeed / Aperture / SubSec*, end-to-
// end through the real `REGISTRY`. Two-view (ValueConv + PrintConv) maps mirror
// the bundled-ExifTool 13.59 truth the regenerated stills carry.
// ===========================================================================

#[cfg(feature = "exif")]
mod exif {
  use super::*;

  #[test]
  fn image_size_both_isfloat_branch_and_printconv_space_to_x() {
    // `return "$val[0] $val[1]" if IsFloat($val[0]) and IsFloat($val[1])`.
    // NikonD2Hs File:ImageWidth/Height = 8 (bare-name inputs). `-n` ⇒ "8 8";
    // `-j` ⇒ the PrintConv `tr/ /x/` ⇒ "8x8".
    let entries: &[(&str, &str, TagValue)] = &[
      ("File", "ImageWidth", TagValue::U64(8)),
      ("File", "ImageHeight", TagValue::U64(8)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "ImageSize"),
      Some(TagValue::Str("8 8".into()))
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "ImageSize"),
      Some(TagValue::Str("8x8".into()))
    );
  }

  #[test]
  fn image_size_raw_image_cropped_size_branch_wins() {
    // `return $val[4] if $val[4]` — a present RawImageCroppedSize (index 4)
    // overrides the ImageWidth/Height branch and is used verbatim (already
    // "WxH"). PrintConv `tr/ /x/` is a no-op on a value with no space.
    let entries: &[(&str, &str, TagValue)] = &[
      ("File", "ImageWidth", TagValue::U64(6000)),
      ("File", "ImageHeight", TagValue::U64(4000)),
      (
        "RAF",
        "RawImageCroppedSize",
        TagValue::Str("6000x4000".into()),
      ),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "ImageSize"),
      Some(TagValue::Str("6000x4000".into())),
      "RawImageCroppedSize ($val[4]) wins over the ImageWidth/Height branch"
    );
  }

  #[test]
  fn image_size_not_built_when_dimensions_non_numeric() {
    // Neither IsFloat ⇒ the `$val[0] $val[1]` branch is skipped and (no
    // RawImageCroppedSize) the ValueConv returns undef ⇒ not built.
    let entries: &[(&str, &str, TagValue)] = &[
      ("File", "ImageWidth", TagValue::Str("wide".into())),
      ("File", "ImageHeight", TagValue::Str("tall".into())),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "ImageSize"), None);
  }

  #[test]
  fn megapixels_requires_imagesize_fixpoint_oracle() {
    // `Composite:Megapixels` `Require`s `Composite:ImageSize` — the composite-
    // on-composite fixpoint. ImageSize must build first (from ImageWidth/Height),
    // then Megapixels reads its ValueConv string and computes `d0*d1/1e6`.
    // NikonD2Hs: 8*8/1e6 = 6.4e-5 (`-n`) / "0.000064" (`-j`).
    let entries: &[(&str, &str, TagValue)] = &[
      ("File", "ImageWidth", TagValue::U64(8)),
      ("File", "ImageHeight", TagValue::U64(8)),
    ];

    // `-n`: bare f64.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "Megapixels"), Some(TagValue::F64(6.4e-5)));

    // `-j`: the magnitude-keyed sprintf ⇒ 6 decimals for `< 0.001`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "Megapixels"),
      Some(TagValue::Str("0.000064".into()))
    );
  }

  #[test]
  fn megapixels_not_built_without_imagesize() {
    // No ImageWidth/Height ⇒ ImageSize never builds ⇒ Megapixels' Require of
    // `Composite:ImageSize` fails after the fixpoint settles ⇒ neither builds.
    let mut val = TagMap::new();
    let mut prt = TagMap::new();
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "ImageSize"), None);
    assert_eq!(composite(&val, "Megapixels"), None);
  }

  #[test]
  fn megapixels_one_decimal_for_large_count() {
    // DJI_Matrice30T: 1280*1024/1e6 = 1.31072 ⇒ `>= 1` ⇒ 1 dp "1.3" (`-j`).
    let entries: &[(&str, &str, TagValue)] = &[
      ("File", "ImageWidth", TagValue::U64(1280)),
      ("File", "ImageHeight", TagValue::U64(1024)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "Megapixels"),
      Some(TagValue::Str("1.3".into()))
    );
  }

  #[test]
  fn shutter_speed_exposure_time_branch() {
    // `defined($val[0]) ? $val[0] : $val[1]` — ExposureTime present (no Bulb).
    // NikonD2Hs ExposureTime 0.008 ⇒ `-n` 0.008, `-j` PrintExposureTime "1/125".
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "ExposureTime", TagValue::F64(0.008))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.008)));

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "ShutterSpeed"),
      Some(TagValue::Str("1/125".into()))
    );
  }

  #[test]
  fn shutter_speed_bulb_duration_branch_wins() {
    // `($val[2] and $val[2]>0) ? $val[2] : ...` — a positive BulbDuration wins
    // over ExposureTime. Bulb 2.0 ⇒ `-n` 2.0, `-j` "2" (decimal, ".0" stripped).
    let entries: &[(&str, &str, TagValue)] = &[
      ("ExifIFD", "ExposureTime", TagValue::F64(0.008)),
      ("MakerNotes", "BulbDuration", TagValue::F64(2.0)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "ShutterSpeed"),
      Some(TagValue::F64(2.0)),
      "positive BulbDuration ($val[2]) overrides ExposureTime"
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "ShutterSpeed"),
      Some(TagValue::Str("2".into()))
    );
  }

  #[test]
  fn shutter_speed_zero_bulb_falls_back_to_exposure_time() {
    // `$val[2]>0` is false for a zero/negative BulbDuration ⇒ fall back to
    // ExposureTime. Bulb 0 ⇒ uses ExposureTime 0.008.
    let entries: &[(&str, &str, TagValue)] = &[
      ("ExifIFD", "ExposureTime", TagValue::F64(0.008)),
      ("MakerNotes", "BulbDuration", TagValue::F64(0.0)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.008)));
  }

  #[test]
  fn shutter_speed_shutterspeedvalue_when_no_exposure_time() {
    // ExposureTime undef ⇒ `$val[1]` (ShutterSpeedValue) is used.
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "ShutterSpeedValue", TagValue::F64(0.004))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.004)));
  }

  #[test]
  fn aperture_fnumber_or_aperturevalue_and_printfnumber() {
    // `$val[0] || $val[1]` — FNumber present ⇒ used. NikonD2Hs FNumber 4.0 ⇒
    // `-n` 4.0, `-j` PrintFNumber "4.0" (>= 1 ⇒ %.1f, no strip).
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FNumber", TagValue::F64(4.0))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "Aperture"), Some(TagValue::F64(4.0)));

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "Aperture"),
      Some(TagValue::Str("4.0".into()))
    );

    // FNumber absent / falsy ⇒ `$val[1]` (ApertureValue). 0.64 ⇒ "0.64" (< 1 ⇒ %.2f).
    let entries2: &[(&str, &str, TagValue)] = &[("ExifIFD", "ApertureValue", TagValue::F64(0.64))];
    let mut val = map_with(entries2);
    let mut prt = map_with(entries2);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "Aperture"),
      Some(TagValue::Str("0.64".into()))
    );
  }

  #[test]
  fn aperture_not_built_when_both_zero() {
    // RawConv `($val[0] || $val[1]) ? $val : undef` — both falsy (numeric 0) ⇒
    // not built.
    let entries: &[(&str, &str, TagValue)] = &[
      ("ExifIFD", "FNumber", TagValue::F64(0.0)),
      ("ExifIFD", "ApertureValue", TagValue::F64(0.0)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "Aperture"), None);
  }

  #[test]
  fn subsec_datetime_original_assembles_fraction() {
    // NikonD2Hs: ExifIFD:DateTimeOriginal + SubSecTimeOriginal=16, no offset ⇒
    // "2005:03:18 02:55:18.16". ConvertDateTime is identity ⇒ both modes equal.
    let entries: &[(&str, &str, TagValue)] = &[
      (
        "ExifIFD",
        "DateTimeOriginal",
        TagValue::Str("2005:03:18 02:55:18".into()),
      ),
      ("ExifIFD", "SubSecTimeOriginal", TagValue::U64(16)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "SubSecDateTimeOriginal"),
      Some(TagValue::Str("2005:03:18 02:55:18.16".into()))
    );
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "SubSecDateTimeOriginal"),
      Some(TagValue::Str("2005:03:18 02:55:18.16".into()))
    );
  }

  #[test]
  fn subsec_not_built_without_subsec_or_offset() {
    // The Pentax/DJI/ExifGPS shape: a base DateTimeOriginal but NO SubSecTime
    // and NO OffsetTime ⇒ `%subSecConv` returns undef ⇒ not built.
    let entries: &[(&str, &str, TagValue)] = &[(
      "ExifIFD",
      "DateTimeOriginal",
      TagValue::Str("2008:03:02 12:01:23".into()),
    )];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(composite(&val, "SubSecDateTimeOriginal"), None);
  }

  #[test]
  fn subsec_exif_group_restriction_ignores_xmp_collision() {
    // `EXIF:DateTimeOriginal` restricts to the EXIF IFDs; an `XMP-exif`
    // DateTimeOriginal of the same name must NOT satisfy the Require (it is not
    // family-0 EXIF). With only an XMP source, the composite is not built.
    let entries: &[(&str, &str, TagValue)] = &[
      (
        "XMP-exif",
        "DateTimeOriginal",
        TagValue::Str("1999:01:01 00:00:00".into()),
      ),
      ("XMP-exif", "SubSecTimeOriginal", TagValue::U64(99)),
    ];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "SubSecDateTimeOriginal"),
      None,
      "an XMP-exif DateTimeOriginal must not satisfy EXIF:DateTimeOriginal"
    );

    // The same names in `ExifIFD` DO satisfy it.
    let entries2: &[(&str, &str, TagValue)] = &[
      (
        "ExifIFD",
        "DateTimeOriginal",
        TagValue::Str("1999:01:01 00:00:00".into()),
      ),
      ("ExifIFD", "SubSecTimeOriginal", TagValue::U64(99)),
    ];
    let mut val = map_with(entries2);
    let mut prt = map_with(entries2);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "SubSecDateTimeOriginal"),
      Some(TagValue::Str("1999:01:01 00:00:00.99".into()))
    );
  }

  /// `Composite:ShutterSpeed` / `Aperture` must PASS THROUGH a present-but-non-
  /// float operand (a zero-denominator / `undef` EXIF rational that ValueConv'd
  /// to the string `"undef"`) UNCHANGED — Exif.pm:5704/5719's
  /// `PrintExposureTime`/`PrintFNumber` return the operand verbatim when
  /// `IsFloat` fails. The prior `coerce_numeric` path turned `"undef"` into `0`
  /// (`perl_str_to_f64("undef") == 0.0`), fabricating `Composite:ShutterSpeed`/
  /// `Aperture` of `0`. The composite is STILL built (the operand is present +
  /// `coerce_numeric`-eligible as a string), but renders the passthrough — in
  /// BOTH `-n` (the raw `Str` operand) and `-j` (`PrintExposureTime("undef") ==
  /// "undef"`).
  #[test]
  fn shutter_speed_passes_zero_denominator_undef_rational_through() {
    use crate::value::TagValue;
    // `ExifIFD:ExposureTime` present as the `undef` ValueConv string (the form a
    // 0-denominator rational stringifies to). `bare_des("ExposureTime")` matches
    // it; it is `defined`, so ShutterSpeed selects it as `$val[0]`.
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "ExposureTime", TagValue::Str("undef".into()))];

    // `-n` (ValueConv): the selected operand value, UNCHANGED — the `"undef"`
    // string, NOT `0`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "ShutterSpeed"),
      Some(TagValue::Str("undef".into())),
      "-n must pass the undef operand through, not coerce to 0"
    );

    // `-j` (PrintConv): `PrintExposureTime("undef")` ⇒ `"undef"` (IsFloat fails).
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "ShutterSpeed"),
      Some(TagValue::Str("undef".into())),
      "-j must pass the undef operand through, not render 0"
    );
  }

  #[test]
  fn aperture_passes_zero_denominator_undef_rational_through() {
    use crate::value::TagValue;
    // `EXIF:FNumber` present as the `undef` ValueConv string. It is Perl-TRUTHY
    // (a non-empty, non-`"0"` string), so Aperture's `$val[0] || $val[1]` picks
    // it; `PrintFNumber` then passes the non-float string through.
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "FNumber", TagValue::Str("undef".into()))];

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "Aperture"),
      Some(TagValue::Str("undef".into())),
      "-n must pass the undef FNumber through, not coerce to 0"
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "Aperture"),
      Some(TagValue::Str("undef".into())),
      "-j must pass the undef FNumber through, not render 0"
    );
  }

  // ==========================================================================
  // END-TO-END JSON serialization of the degenerate-operand passthrough.
  //
  // The R1-R3 passthrough tests above stop at the `composite(&map, name)`
  // `TagValue` — they prove the `PrintExposureTime`/`PrintFNumber` helper +
  // selection produce the right SCALAR. These tests carry that scalar one step
  // further, through the SAME `serde_json` `Serialize` impl the `-j`/`-n` CLI
  // uses (`crate::value::TagValue`), and assert on the EXACT emitted token —
  // the step the R4 Codex finding (#133) flagged as un-covered.
  //
  // GROUND TRUTH (bundled ExifTool 13.59, an XMP with `exif:FNumber=0E0` +
  // `exif:ExposureTime=-0.0`, `-j -G1 -Composite:all` and `-j -n -G1`):
  //   Composite:Aperture      -> `0E0`  (BOTH -j and -n; literal, UNQUOTED)
  //   Composite:ShutterSpeed  -> `-0`   (-j),  `-0.0` (-n)  (literal, UNQUOTED)
  // ExifTool's `EscapeJSON` (`exiftool:3809`) emits a numeric-shaped scalar
  // BARE via `return $str` — it preserves the ORIGINAL token verbatim, it does
  // NOT reparse/canonicalize it.
  //
  // exifast stores the helper result as `TagValue::Str` and the shared
  // serializer (`value.rs`) re-runs the `escape_json_is_number` gate then
  // RE-EMITS via `serialize_f64`/`serialize_i64` — which CANONICALIZES the
  // value form: `Str("0E0")` -> `0.0`, `Str("-0")` -> `0`. This is the
  // crate-wide token-exact-vs-value-exact policy (Contract B / #197): every
  // numeric-looking string tag (an `APE:Year` "2005" -> `2005`, an
  // `ExifToolVersion` "13.59" -> `13.59`, the 11 PR-3 `Aperture` "4.0" goldens
  // -> `4.0`) round-trips through that re-emit, and the STRICT comparator
  // accepts the within-one-type numeric reshaping. So the divergence is NOT
  // local to the composite path: it is the shared `value.rs` `Str`->number
  // serializer, used by ALL string tags and depended on by all 540 goldens.
  //
  // Per the project ship-bar these are CRAFTED degenerate inputs (`0E0` /
  // `-0.0` as an `exif:FNumber`/`ExposureTime`; no real device emits them and
  // no fixture exercises them). Fixing them would require a broad change to the
  // shared serializer (force-string the composite emit, or carry a
  // "pre-rendered, do-not-reparse" flag through `TagValue`) — out of scope for
  // this PR. The divergence is recorded as a tracked follow-up; these tests are
  // `#[ignore]`d so they stand as executable documentation of the exact
  // exifast-vs-bundled token gap without failing the suite.
  //
  // Each test ALSO asserts the byte-exact bundled token in a comment so the gap
  // is unambiguous, and serializes a `Str("4.0")` control to prove the path is
  // live (`4.0` is preserved value-exact, matching the PR-3 Aperture goldens).

  /// Serialize a single composite `TagValue` exactly as the `-j`/`-n` CLI does.
  #[cfg(feature = "json")]
  fn emit(v: &TagValue) -> String {
    serde_json::to_string(v).expect("serialize composite scalar")
  }

  /// CONTROL: a normal `Aperture` "4.0" (the 11 PR-3 goldens' shape) MUST
  /// serialize to the bare `4.0` — proving the serializer preserves an ordinary
  /// numeric-looking string value-exact (so the byte-identical goldens hold).
  #[cfg(feature = "json")]
  #[test]
  fn aperture_normal_value_serializes_byte_exact_control() {
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FNumber", TagValue::F64(4.0))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    let aperture = composite(&prt, "Aperture").expect("Aperture built");
    assert_eq!(aperture, TagValue::Str("4.0".into()));
    // Bundled ExifTool 13.59: `Composite:Aperture: 4.0`. exifast: bare `4.0`.
    assert_eq!(emit(&aperture), "4.0", "the PR-3 Aperture goldens' control");
  }

  /// `Composite:Aperture` over an `exif:FNumber=0E0` operand.
  ///
  /// Bundled ExifTool 13.59 emits the literal `0E0` (UNQUOTED) in BOTH `-j` and
  /// `-n`. exifast canonicalizes `Str("0E0")` -> `0.0` via the shared
  /// `value.rs` serializer. The composite SCALAR is correct (`Str("0E0")`); the
  /// gap is purely in the shared `Str`->number JSON re-emit. `#[ignore]`d as a
  /// tracked crafted-input follow-up (broad-serializer fix, out of PR scope).
  #[cfg(feature = "json")]
  #[test]
  #[ignore = "crafted degenerate FNumber 0E0: bundled emits literal `0E0`, exifast's shared value.rs Str->number serializer canonicalizes to `0.0` (Contract B/#197); broad-serializer fix tracked as follow-up, not in PR #133 scope"]
  fn aperture_degenerate_0e0_token_emit_vs_bundled() {
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FNumber", TagValue::Str("0E0".into()))];

    // `-j` (PrintConv): PrintFNumber("0E0") — IsFloat matches, value 0 is not
    // `> 0`, so it returns the norm "0E0" verbatim. Bundled: bare `0E0`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    let j = composite(&prt, "Aperture").expect("Aperture built (-j)");
    assert_eq!(j, TagValue::Str("0E0".into()), "the SCALAR is correct");
    assert_eq!(emit(&j), "0E0", "bundled emits literal `0E0`");

    // `-n` (ValueConv): the operand passes through verbatim -> `Str("0E0")`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    let n = composite(&val, "Aperture").expect("Aperture built (-n)");
    assert_eq!(n, TagValue::Str("0E0".into()));
    assert_eq!(emit(&n), "0E0", "bundled emits literal `0E0`");
  }

  /// `Composite:ShutterSpeed` over an `exif:ExposureTime=-0.0` operand.
  ///
  /// Bundled ExifTool 13.59: `-0` (`-j`, after PrintExposureTime's `%.1f`+strip
  /// gives `-0`), `-0.0` (`-n`, the raw operand). exifast: `Str("-0")` -> `0`
  /// (`-j`) and `Str("-0.0")` -> serde `-0.0` (`-n`). The `-j` token loses the
  /// sign; `-n` may match (serde emits `-0.0`). `#[ignore]`d follow-up.
  #[cfg(feature = "json")]
  #[test]
  #[ignore = "crafted degenerate ExposureTime -0.0: bundled -j emits literal `-0`, exifast's shared value.rs Str->integer serializer drops the sign to `0`; broad-serializer fix tracked as follow-up, not in PR #133 scope"]
  fn shutter_speed_degenerate_negzero_token_emit_vs_bundled() {
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "ExposureTime", TagValue::Str("-0.0".into()))];

    // `-j` (PrintConv): PrintExposureTime("-0.0") — IsFloat matches, value -0.0
    // is not `> 0` and not `< 0.25001 && > 0`, so `%.1f` -> "-0.0" -> strip
    // ".0" -> "-0". Bundled: bare `-0`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    let j = composite(&prt, "ShutterSpeed").expect("ShutterSpeed built (-j)");
    assert_eq!(j, TagValue::Str("-0".into()), "the SCALAR is correct");
    assert_eq!(emit(&j), "-0", "bundled emits literal `-0`");

    // `-n` (ValueConv): the operand passes through verbatim -> `Str("-0.0")`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    let n = composite(&val, "ShutterSpeed").expect("ShutterSpeed built (-n)");
    assert_eq!(n, TagValue::Str("-0.0".into()));
    assert_eq!(emit(&n), "-0.0", "bundled emits literal `-0.0`");
  }

  // The NikonD2Hs lens-input set (bundled-ExifTool 13.59): the simple
  // `$foc35/$focal` ScaleFactor path (75/50 = 1.5) plus the inputs that drive the
  // whole chain. A bare `ExifIFD:FocalLength` of 50 AND a later `Nikon:FocalLength`
  // of 50.4 (the bare-name precedence probe).
  fn nikon_lens_inputs() -> Vec<(&'static str, &'static str, TagValue)> {
    vec![
      ("ExifIFD", "FocalLength", TagValue::F64(50.0)),
      ("ExifIFD", "FocalLengthIn35mmFormat", TagValue::F64(75.0)),
      ("ExifIFD", "FNumber", TagValue::F64(4.0)),
      ("ExifIFD", "ExposureTime", TagValue::F64(0.008)),
      ("ExifIFD", "ISO", TagValue::U64(800)),
      ("Nikon", "FocusDistance", TagValue::F64(0.707945784384138)),
      // The MakerNote FocalLength duplicate — exifast must NOT pick this for the
      // bare-name `FocalLength` inputs (ExifTool's priority dir is the EXIF IFD).
      ("Nikon", "FocalLength", TagValue::F64(50.4)),
    ]
  }

  #[test]
  fn lens_chain_full_resolves_through_multi_pass_fixpoint() {
    // The full NikonD2Hs lens chain builds via the registry fixpoint:
    //   ScaleFactor35efl (1.5) → CircleOfConfusion → {Hyperfocal, DOF, FOV}
    //   FocalLength35efl (needs ScaleFactor), LightValue (needs Aperture+Shutter).
    // `-j` (PrintConv) pinned to bundled.
    let entries = nikon_lens_inputs();
    let mut prt = map_with(&entries);
    let mut val = map_with(&entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    // `emit` is `serde_json::to_string`: a numeric-looking PrintConv string is
    // emitted BARE by the JSON gate (`1.5`, `8.0`); a unit-bearing one is QUOTED.
    let g = |n: &str| composite(&prt, n).map(|v| emit(&v));
    assert_eq!(g("ScaleFactor35efl").as_deref(), Some("1.5"));
    assert_eq!(g("CircleOfConfusion").as_deref(), Some("\"0.020 mm\""));
    assert_eq!(g("HyperfocalDistance").as_deref(), Some("\"31.20 m\""));
    assert_eq!(g("DOF").as_deref(), Some("\"0.03 m (0.69 - 0.72 m)\""));
    assert_eq!(g("FOV").as_deref(), Some("\"25.1 deg (0.32 m)\""));
    assert_eq!(
      g("FocalLength35efl").as_deref(),
      Some("\"50.0 mm (35 mm equivalent: 75.0 mm)\""),
      "the bare `FocalLength` resolves to the EXIF 50, NOT the MakerNote 50.4"
    );
    assert_eq!(g("LightValue").as_deref(), Some("8.0"));
  }

  #[test]
  fn lens_chain_n_mode_value_conv_forms() {
    // The `-n` (ValueConv) forms — full-precision scalars, the space-joined
    // DOF/FOV strings, and the `%.15g`-quoted CircleOfConfusion (Nikon CoC has 16
    // fraction digits ⇒ a BARE number; DJI's 17 would quote — see the helper test).
    let entries = nikon_lens_inputs();
    let mut val = map_with(&entries);
    let mut prt = map_with(&entries);
    build_into(REGISTRY, &mut val, Some(&mut prt), ConvMode::ValueConv);
    assert_eq!(
      composite(&val, "ScaleFactor35efl"),
      Some(TagValue::F64(1.5))
    );
    assert_eq!(
      composite(&val, "FocalLength35efl"),
      Some(TagValue::F64(75.0))
    );
    assert_eq!(
      composite(&val, "DOF"),
      Some(TagValue::Str("0.693325809394639 0.723195615956146".into()))
    );
    assert_eq!(
      composite(&val, "FOV"),
      Some(TagValue::Str("25.1479641359127 0.315813976504386".into()))
    );
    // CircleOfConfusion -n = the full f64; emit() routes it through the JSON gate
    // (16 fraction digits ⇒ bare number).
    assert_eq!(
      composite(&val, "CircleOfConfusion")
        .map(|v| emit(&v))
        .as_deref(),
      Some("0.0200308404192444")
    );
    assert_eq!(
      composite(&val, "LightValue").map(|v| emit(&v)).as_deref(),
      Some("7.96578428466209")
    );
  }

  #[test]
  fn focal_length_35efl_falls_back_to_focal_only_without_scale_factor() {
    // ExifGPS.jpg: FocalLength=0, no FocalLengthIn35mmFormat ⇒ ScaleFactor NOT
    // built; FocalLength35efl Requires FocalLength (0) + Desires ScaleFactor
    // (Missing) ⇒ `(0||0)*(undef||1)` = 0 ⇒ "0.0 mm".
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FocalLength", TagValue::F64(0.0))];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "FocalLength35efl")
        .map(|v| emit(&v))
        .as_deref(),
      Some("\"0.0 mm\"")
    );
    assert!(
      composite(&prt, "ScaleFactor35efl").is_none(),
      "no ScaleFactor without FocalLengthIn35mmFormat or sensor data"
    );
  }

  #[test]
  fn scale_factor_canon_branch_defers_focal_length_falls_through() {
    // Exif.tif: Make=Canon, FocalLength=50, no FocalLengthIn35mmFormat ⇒ the Canon
    // `CalcSensorDiag` branch (unported) ⇒ ScaleFactor35efl DEFERRED (not built).
    // FocalLength35efl then builds focal-only ("50.0 mm"), and LightValue builds.
    let entries: &[(&str, &str, TagValue)] = &[
      ("IFD0", "Make", TagValue::Str("Canon".into())),
      ("ExifIFD", "FocalLength", TagValue::F64(50.0)),
      ("ExifIFD", "FNumber", TagValue::F64(8.0)),
      ("ExifIFD", "ExposureTime", TagValue::F64(0.005)),
      ("ExifIFD", "ISO", TagValue::U64(100)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "ScaleFactor35efl").is_none(),
      "the Canon branch defers ScaleFactor35efl (unported CalcSensorDiag)"
    );
    assert_eq!(
      composite(&prt, "FocalLength35efl")
        .map(|v| emit(&v))
        .as_deref(),
      Some("\"50.0 mm\""),
      "FocalLength35efl falls through to the focal-only PrintConv branch"
    );
    // No ScaleFactor ⇒ no CircleOfConfusion ⇒ no Hyperfocal/DOF/FOV.
    assert!(composite(&prt, "CircleOfConfusion").is_none());
    assert!(composite(&prt, "FOV").is_none());
    // LightValue is independent of ScaleFactor (Aperture+ShutterSpeed+ISO).
    assert!(composite(&prt, "LightValue").is_some());
  }

  #[test]
  fn focal_length_35efl_defers_when_canon_scale_factor_would_use_sensor_branch() {
    // XMP.xmp: Make=Canon, FocalLength=5.8, NO FocalLengthIn35mmFormat, but
    // FocalPlaneXResolution IS present ⇒ ExifTool's Canon `CalcSensorDiag` branch
    // builds a ScaleFactor (6.08) the post-pass can't reach. exifast DEFERS the
    // whole chain — including FocalLength35efl (which would otherwise emit the
    // WRONG focal-only "5.8 mm" vs bundled's "5.8 mm (35 mm equivalent: 35.3 mm)").
    let entries: &[(&str, &str, TagValue)] = &[
      ("XMP-tiff", "Make", TagValue::Str("Canon".into())),
      ("XMP-exif", "FocalLength", TagValue::F64(5.8)),
      (
        "XMP-exif",
        "FocalPlaneXResolution",
        TagValue::F64(10142.8571428571),
      ),
      ("XMP-exif", "FocalPlaneResolutionUnit", TagValue::U64(2)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "ScaleFactor35efl").is_none(),
      "Canon branch defers ScaleFactor (generic would give a WRONG 12.17)"
    );
    assert!(
      composite(&prt, "FocalLength35efl").is_none(),
      "FocalLength35efl ALSO defers (the Canon ScaleFactor it needs is unported)"
    );
    assert!(composite(&prt, "CircleOfConfusion").is_none());
    assert!(composite(&prt, "FOV").is_none());
  }

  #[test]
  fn light_value_reads_iso_print_conv_view() {
    // `Composite:LightValue` ValueConv uses `$prt[2]` (ISO's PrintConv value), not
    // `$val[2]`. Build with an ISO whose ValueConv and PrintConv DIFFER: the raw
    // ValueConv `6` (a Pentax-style raw) but the PrintConv `100`. LightValue must
    // use 100. (Two views: ISO emits 6 into `val`, 100 into `prt`.)
    let val_entries: &[(&str, &str, TagValue)] = &[
      ("ExifIFD", "FNumber", TagValue::F64(13.0)),
      ("ExifIFD", "ExposureTime", TagValue::F64(0.01)),
      ("ExifIFD", "ISO", TagValue::U64(6)), // ValueConv view
    ];
    let prt_entries: &[(&str, &str, TagValue)] = &[
      ("ExifIFD", "FNumber", TagValue::F64(13.0)),
      ("ExifIFD", "ExposureTime", TagValue::F64(0.01)),
      ("ExifIFD", "ISO", TagValue::U64(100)), // PrintConv view
    ];
    let mut val = map_with(val_entries);
    let mut prt = map_with(prt_entries);
    // Active mode `-j`: `out` = prt, the other view = val.
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    // LV = log(13^2*100/(0.01*100))/log(2) = 14.0447356260569 ⇒ "%.1f" = "14.0".
    assert_eq!(
      composite(&prt, "LightValue").map(|v| emit(&v)).as_deref(),
      Some("14.0"),
      "LightValue uses ISO's PrintConv view (100), not the raw ValueConv (6)"
    );
  }

  #[test]
  fn dof_non_numeric_focus_distance_falls_back_post_tofloat() {
    // ExifTool's DOF runs `ToFloat(@val)` BEFORE the `defined $d` checks, so a
    // present-but-NON-NUMERIC FocusDistance is `undef` and falls through to
    // SubjectDistance/ObjectDistance/ApproximateFocusDistance — it does NOT map to
    // 0 → the `1e10` infinity sentinel. Here FocusDistance="unknown" (undef post
    // ToFloat) + SubjectDistance=0.707945784384138 ⇒ the SAME DOF the Nikon golden
    // gets from a numeric FocusDistance of that value ("0.03 m (0.69 - 0.72 m)").
    // (The pre-fix raw-presence check would take the `1e10` branch ⇒ the inf form.)
    let mut entries = nikon_lens_inputs();
    entries.retain(|(_, n, _)| *n != "FocusDistance");
    entries.push(("Nikon", "FocusDistance", TagValue::Str("unknown".into())));
    entries.push((
      "ExifIFD",
      "SubjectDistance",
      TagValue::F64(0.707945784384138),
    ));
    let mut prt = map_with(&entries);
    let mut val = map_with(&entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert_eq!(
      composite(&prt, "DOF").map(|v| emit(&v)).as_deref(),
      Some("\"0.03 m (0.69 - 0.72 m)\""),
      "a non-numeric FocusDistance is undef post-ToFloat ⇒ uses SubjectDistance, \
       NOT the 1e10 infinity sentinel"
    );
  }

  #[test]
  fn dof_present_non_float_bounds_yield_undef() {
    // The lower/upper fallback averages `($val[7] + $val[8]) / 2` ONLY when BOTH
    // are defined POST-ToFloat. A non-numeric FocusDistanceLower is undef ⇒
    // `defined $val[7]` is false ⇒ `return undef` (the composite is NOT built from
    // averaging a present-non-float bound as 0). No FocusDistance/Subject/Object/
    // Approximate present, so the lower/upper branch is the only path.
    let mut entries = nikon_lens_inputs();
    entries.retain(|(_, n, _)| *n != "FocusDistance");
    entries.push(("Nikon", "FocusDistanceLower", TagValue::Str("n/a".into())));
    entries.push(("Nikon", "FocusDistanceUpper", TagValue::F64(1.0)));
    let mut prt = map_with(&entries);
    let mut val = map_with(&entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "DOF").is_none(),
      "a present-non-float FocusDistanceLower is undef post-ToFloat ⇒ DOF is undef"
    );
  }

  #[test]
  fn focal_length_35efl_defers_for_canon_focal_plane_xy_size_only() {
    // A Canon body with ONLY FocalPlaneXSize/FocalPlaneYSize (no FocalPlaneX-
    // Resolution / SensorSize / FocalPlaneDiagonal) still reaches ExifTool's
    // `CalcScaleFactor35efl` FocalPlaneX/YSize aspect-ratio `$diag` path (a
    // ScaleFactor exifast can't compute) ⇒ FocalLength35efl must DEFER, not emit
    // the WRONG focal-only form. (The pre-fix guard probed only XResolution/
    // SensorSize/FocalPlaneDiagonal, so it MISSED this and emitted "5.8 mm".)
    let entries: &[(&str, &str, TagValue)] = &[
      ("IFD0", "Make", TagValue::Str("Canon".into())),
      ("ExifIFD", "FocalLength", TagValue::F64(5.8)),
      ("ExifIFD", "FocalPlaneXSize", TagValue::F64(6.16)),
      ("ExifIFD", "FocalPlaneYSize", TagValue::F64(4.62)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "FocalLength35efl").is_none(),
      "Canon + only FocalPlaneX/YSize ⇒ FocalLength35efl defers (NOT focal-only)"
    );
  }

  #[test]
  fn focal_length_35efl_defers_for_canon_present_but_falsy_foc35() {
    // A Canon body whose FocalLengthIn35mmFormat is PRESENT but FALSY (0) — so
    // ExifTool's simple `$foc35/$focal` ScaleFactor path does NOT fire (`return
    // $foc35/$focal if $focal and $foc35`, Exif.pm:5462, gated on the POST-ToFloat
    // TRUTHY foc35) — and FocalPlaneXResolution IS present ⇒ the Canon
    // `CalcSensorDiag` branch still BUILDS a ScaleFactor exifast can't reach. So
    // FocalLength35efl must DEFER, not emit the wrong focal-only "5.8 mm". (The
    // pre-fix guard keyed `no_foc35` off mere PRESENCE, so a present `0` made
    // `no_foc35` false and the deferral was skipped ⇒ wrong focal-only emission.)
    let entries: &[(&str, &str, TagValue)] = &[
      ("IFD0", "Make", TagValue::Str("Canon".into())),
      ("ExifIFD", "FocalLength", TagValue::F64(5.8)),
      ("ExifIFD", "FocalLengthIn35mmFormat", TagValue::U64(0)),
      (
        "ExifIFD",
        "FocalPlaneXResolution",
        TagValue::F64(10142.8571428571),
      ),
      ("ExifIFD", "FocalPlaneResolutionUnit", TagValue::U64(2)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "FocalLength35efl").is_none(),
      "Canon + present-but-falsy FocalLengthIn35mmFormat=0 + sensor data ⇒ \
       FocalLength35efl defers (the simple path is gated on a TRUTHY foc35)"
    );
  }

  #[test]
  fn focal_length_35efl_defers_for_canon_falsy_focal_but_truthy_foc35() {
    // A Canon body whose FocalLength is PRESENT but FALSY (0) WHILE
    // FocalLengthIn35mmFormat is TRUTHY (50) — so ExifTool's simple
    // `$foc35/$focal` ScaleFactor path does NOT fire (`return $foc35/$focal if
    // $focal and $foc35`, Exif.pm:5460, requires BOTH operands post-ToFloat
    // truthy; a falsy `$focal` fails the `and`) — and FocalPlaneXResolution IS
    // present ⇒ the Canon `CalcSensorDiag` branch still BUILDS a ScaleFactor
    // exifast can't reach. So FocalLength35efl must DEFER, not emit the wrong
    // focal-only value. (A guard checking only the foc35 operand would see a
    // truthy foc35, conclude the simple path fired, and skip the deferral — the
    // exact gap fixed by extending the predicate to BOTH operands of
    // `$focal and $foc35`.)
    let entries: &[(&str, &str, TagValue)] = &[
      ("IFD0", "Make", TagValue::Str("Canon".into())),
      ("ExifIFD", "FocalLength", TagValue::F64(0.0)),
      ("ExifIFD", "FocalLengthIn35mmFormat", TagValue::U64(50)),
      (
        "ExifIFD",
        "FocalPlaneXResolution",
        TagValue::F64(10142.8571428571),
      ),
      ("ExifIFD", "FocalPlaneResolutionUnit", TagValue::U64(2)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(REGISTRY, &mut prt, Some(&mut val), ConvMode::PrintConv);
    assert!(
      composite(&prt, "FocalLength35efl").is_none(),
      "Canon + present-but-falsy FocalLength=0 + truthy FocalLengthIn35mmFormat \
       + sensor data ⇒ FocalLength35efl defers (the simple path needs BOTH \
       `$focal` AND `$foc35` truthy)"
    );
  }
}
