//! Oracle tests for the Composite fixpoint engine ([`build_into`]) — hand-built
//! input maps proving the `Require`/`Desire`/`Inhibit` resolution, the
//! Composite-requires-Composite multi-pass deferral, the circular-dependency
//! guard, and the prefixed-id sort tiebreak. These exercise the GENERIC engine
//! with synthetic defs (the real Duration migration is pinned by the
//! conformance goldens + the differential tests in the format modules).

#![cfg(feature = "alloc")]

use super::table::{
  CompositeContext, CompositeDef, CompositeInput, CompositePrintConv, CompositeRaw, CompositeValue,
  InputKind, SubDoc,
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

/// The default (empty) context for the synthetic oracle tests — no format-state
/// reads (`AvgBitrate`/`Rotation` are not exercised by the synthetic defs).
fn ctx0() -> CompositeContext {
  CompositeContext::new(None, None)
}

/// A synthetic `Require`d input on `group`.
const fn req(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: group,
    group0: None,
    name,
  }
}

/// A synthetic `Desire`d input.
const fn des(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Desire,
    groups: group,
    group0: None,
    name,
  }
}

/// A synthetic `Inhibit` input.
const fn inh(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Inhibit,
    groups: group,
    group0: None,
    name,
  }
}

/// Sum the present inputs (a stand-in derivation; `Missing`/non-numeric ⇒ 0).
fn sum_inputs(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  Some(CompositeRaw::Num(
    v.iter().map(|x| x.coerce_numeric().unwrap_or(0.0)).sum(),
  ))
}

/// Build a TagMap with the given `(group, name, value)` entries in order.
fn map_with(entries: &[(&str, &str, TagValue)]) -> TagMap {
  let mut m = TagMap::new();
  for (g, n, v) in entries {
    let _ = m.write_value_doc(0, "", g, n, 1, v.clone(), g);
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
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "X-Sum",
};

#[test]
fn require_present_builds() {
  let mut m = map_with(&[("X", "A", TagValue::I64(40)), ("X", "B", TagValue::I64(20))]);
  build_into(&[SUM_AB], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  // 40 + 20 = 60 seconds, ValueConv ⇒ bare f64.
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(60.0)));
}

#[test]
fn require_missing_aborts() {
  // B is absent ⇒ Require miss ⇒ no composite.
  let mut m = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[SUM_AB], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), None);
}

#[test]
fn desire_absent_still_builds_with_undef_element() {
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GX, "A"), des(GX, "B")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Sum",
  };
  // B (Desire) absent ⇒ element None (counted as 0) but the composite builds.
  let mut m = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(40.0)));
}

#[test]
fn inhibit_present_suppresses() {
  const DEF: CompositeDef = CompositeDef {
    name: "Sum",
    inputs: &[req(GX, "A"), inh(GX, "Block")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Sum",
  };
  // The Inhibit tag `X:Block` is present ⇒ the composite is suppressed.
  let mut m = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::I64(1)),
  ]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), None);

  // Without the Inhibit tag, it builds.
  let mut m2 = map_with(&[("X", "A", TagValue::I64(40))]);
  build_into(&[DEF], &mut m2, None, ConvMode::ValueConv, 0, &ctx0());
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Sum",
  };
  // `X:Block = "present"` is a non-numeric string ⇒ still suppresses.
  let mut m = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::Str("present".into())),
  ]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), None);

  // Even an empty string is PRESENT (ExifTool: `defined ""` is true) ⇒ suppresses.
  let mut m2 = map_with(&[
    ("X", "A", TagValue::I64(40)),
    ("X", "Block", TagValue::Str("".into())),
  ]);
  build_into(&[DEF], &mut m2, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m2, "Sum"), None);
}

#[test]
fn desire_present_nonnumeric_string_reaches_derive() {
  // Finding-1: a present-but-non-numeric (string) Desire reaches `derive` as a
  // `Present(Str)` element (so future GPS/EXIF/datetime defs can read strings),
  // NOT as a `Missing`. The derive here asserts the raw value it was handed.
  fn assert_first_is_str(
    v: &[CompositeValue],
    _prts: &[Option<TagValue>],
    _ctx: &CompositeContext,
  ) -> Option<CompositeRaw> {
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Dur",
  };
  let mut m = map_with(&[("X", "Ref", TagValue::Str("N".into()))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Inner",
  };
  const OUTER: CompositeDef = CompositeDef {
    name: "Outer",
    inputs: &[req(GCOMPOSITE, "Inner"), req(GX, "B")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Outer",
  };
  let mut m = map_with(&[("X", "A", TagValue::I64(10)), ("X", "B", TagValue::I64(5))]);
  build_into(
    &[OUTER, INNER],
    &mut m,
    None,
    ConvMode::ValueConv,
    0,
    &ctx0(),
  );
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "Z-Inner", // sorts AFTER Outer
  };
  const OUTER: CompositeDef = CompositeDef {
    name: "Outer",
    inputs: &[req(GCOMPOSITE, "Inner")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "A-Outer", // sorts BEFORE Inner ⇒ attempted first ⇒ defers
  };
  let mut m = map_with(&[("X", "A", TagValue::I64(7))]);
  build_into(
    &[INNER, OUTER],
    &mut m,
    None,
    ConvMode::ValueConv,
    0,
    &ctx0(),
  );
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "M-A",
  };
  const B: CompositeDef = CompositeDef {
    name: "B",
    inputs: &[req(GCOMPOSITE, "A")],
    derive: sum_inputs,
    print_conv: CompositePrintConv::ConvertDuration,
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "M-B",
  };
  let mut m = TagMap::new();
  build_into(&[A, B], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
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
    sub_doc: SubDoc::No,
    priority: 1,
    sort_key: "X-Sum",
  };
  let mut m = map_with(&[("P", "A", TagValue::I64(1)), ("Q", "A", TagValue::I64(99))]);
  build_into(&[DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), Some(TagValue::F64(99.0)));
}

/// A derivation that always aborts (the `… ? … : undef` guard).
fn always_none(
  _v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  None
}

const NONE_DEF: CompositeDef = CompositeDef {
  name: "Sum",
  inputs: &[req(GX, "A")],
  derive: always_none,
  print_conv: CompositePrintConv::ConvertDuration,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "X-Sum",
};

#[test]
fn derive_returning_none_emits_nothing() {
  // The `… ? … : undef` guard: a derivation returning None settles the def
  // without emitting (no panic, no spurious tag).
  let mut m = map_with(&[("X", "A", TagValue::I64(5))]);
  build_into(&[NONE_DEF], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
  assert_eq!(composite(&m, "Sum"), None);
}

/// A derivation yielding input 0's numeric coercion verbatim.
fn first_input(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  Some(CompositeRaw::Num(v.first()?.coerce_numeric()?))
}

const DUR_DEF: CompositeDef = CompositeDef {
  name: "Dur",
  inputs: &[req(GX, "A")],
  derive: first_input,
  print_conv: CompositePrintConv::ConvertDuration,
  sub_doc: SubDoc::No,
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
  build_into(&[DUR_DEF], &mut m, None, ConvMode::PrintConv, 0, &ctx0());
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
  sub_doc: SubDoc::No,
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
  build_into(
    &[PROBE_DEF],
    &mut out_n,
    None,
    ConvMode::ValueConv,
    0,
    &ctx0(),
  );
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
    0,
    &ctx0(),
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
  sub_doc: SubDoc::No,
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
  build_into(&[SIGNED_SUM], &mut m, None, ConvMode::ValueConv, 0, &ctx0());
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
  build_into(
    &[SIGNED_SUM],
    &mut m2,
    None,
    ConvMode::ValueConv,
    0,
    &ctx0(),
  );
  assert_eq!(composite(&m2, "Sum"), Some(TagValue::F64(-25.0)));

  // A REJECTED dual-sign form (ws after sign 2: `"+- 20"` → 0) coerces to 0,
  // matching Perl — so the shared reject rule is live in the engine path too.
  let mut m3 = map_with(&[
    ("X", "A", TagValue::Str("+- 20".into())),
    ("X", "B", TagValue::Str("100".into())),
  ]);
  build_into(
    &[SIGNED_SUM],
    &mut m3,
    None,
    ConvMode::ValueConv,
    0,
    &ctx0(),
  );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut out,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut out,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut out,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&out, "GPSDateTime"), None);
  }

  #[test]
  fn gps_altitude_requires_a_ref() {
    // The RawConv `(defined $val[1] or defined $val[3]) ? $val : undef` — an
    // altitude with NO ref builds nothing.
    let entries: &[(&str, &str, TagValue)] = &[("GPS", "GPSAltitude", TagValue::F64(35.0))];
    let mut out = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut out,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "GPSAltitude"), Some(TagValue::F64(12.5)));

    // `-j` (PrintConv): `(int($val[0]*10)/10) m $prt[1]` over the normalized
    // value ⇒ `12.5 m Above Sea Level`, not `12 m …`.
    let mut val = map_with(val_entries);
    let mut prt = map_with(prt_entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "ImageSize"),
      Some(TagValue::Str("8 8".into()))
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "Megapixels"), Some(TagValue::F64(6.4e-5)));

    // `-j`: the magnitude-keyed sprintf ⇒ 6 decimals for `< 0.001`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.008)));

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "ShutterSpeed"),
      Some(TagValue::F64(2.0)),
      "positive BulbDuration ($val[2]) overrides ExposureTime"
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.008)));
  }

  #[test]
  fn shutter_speed_shutterspeedvalue_when_no_exposure_time() {
    // ExposureTime undef ⇒ `$val[1]` (ShutterSpeedValue) is used.
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "ShutterSpeedValue", TagValue::F64(0.004))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "ShutterSpeed"), Some(TagValue::F64(0.004)));
  }

  #[test]
  fn aperture_fnumber_or_aperturevalue_and_printfnumber() {
    // `$val[0] || $val[1]` — FNumber present ⇒ used. NikonD2Hs FNumber 4.0 ⇒
    // `-n` 4.0, `-j` PrintFNumber "4.0" (>= 1 ⇒ %.1f, no strip).
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FNumber", TagValue::F64(4.0))];
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(composite(&val, "Aperture"), Some(TagValue::F64(4.0)));

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&prt, "Aperture"),
      Some(TagValue::Str("4.0".into()))
    );

    // FNumber absent / falsy ⇒ `$val[1]` (ApertureValue). 0.64 ⇒ "0.64" (< 1 ⇒ %.2f).
    let entries2: &[(&str, &str, TagValue)] = &[("ExifIFD", "ApertureValue", TagValue::F64(0.64))];
    let mut val = map_with(entries2);
    let mut prt = map_with(entries2);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "SubSecDateTimeOriginal"),
      Some(TagValue::Str("2005:03:18 02:55:18.16".into()))
    );
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "ShutterSpeed"),
      Some(TagValue::Str("undef".into())),
      "-n must pass the undef operand through, not coerce to 0"
    );

    // `-j` (PrintConv): `PrintExposureTime("undef")` ⇒ `"undef"` (IsFloat fails).
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "Aperture"),
      Some(TagValue::Str("undef".into())),
      "-n must pass the undef FNumber through, not coerce to 0"
    );

    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
  // exifast stores the helper result as `TagValue::Str`, and the shared
  // serializer (`value.rs`) re-runs the `escape_json_is_number` gate then emits
  // the in-gate token VERBATIM (#321) — the EXACT source bytes, mirroring
  // `EscapeJSON`'s `return $str`: `Str("0E0")` -> `0E0`, `Str("-0")` -> `-0`.
  // (Before #321 it RE-EMITTED via `serialize_f64`/`serialize_i64`, which
  // CANONICALIZED the value form: `0E0` -> `0.0`, `-0` -> `0`.) This is a
  // crate-wide property (Contract B / #197 + #321): every numeric-looking string
  // tag (an `APE:Year` "2005" -> `2005`, an `ExifToolVersion` "13.59" -> `13.59`,
  // the 11 PR-3 `Aperture` "4.0" goldens -> `4.0`) flows through the SAME shared
  // `value.rs` `Str`->number serializer. The fix is a NO-OP for every existing
  // golden — their numeric-string tokens are all canonical-form already, so the
  // verbatim form IS the byte they had — and the STRICT comparator additionally
  // accepts any within-one-type numeric reshaping; ONLY a degenerate token (which
  // no current golden carries) changes, to its bundled-faithful verbatim form.
  //
  // Each test ALSO asserts the byte-exact bundled token, and serializes a
  // `Str("4.0")` control to prove the path is live (`4.0` is preserved
  // byte-exact, matching the PR-3 Aperture goldens).

  /// Serialize a single composite `TagValue` exactly as the `-j`/`-n` CLI does —
  /// through the renderer wrapper [`crate::value::JsonTagValue`], the SAME path
  /// the `Document` / `Rendered` serializers use, so the in-gate numeric string
  /// token is emitted VERBATIM (`EscapeJSON` `return $str`, #321). A bare
  /// `serde_json::to_string(v)` would hit the generic serializer-agnostic
  /// `TagValue::Serialize` (which canonicalizes `0E0` -> `0.0`), NOT the CLI path.
  #[cfg(feature = "json")]
  fn emit(v: &TagValue) -> String {
    serde_json::to_string(&crate::value::JsonTagValue(v)).expect("serialize composite scalar")
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    let aperture = composite(&prt, "Aperture").expect("Aperture built");
    assert_eq!(aperture, TagValue::Str("4.0".into()));
    // Bundled ExifTool 13.59: `Composite:Aperture: 4.0`. exifast: bare `4.0`.
    assert_eq!(emit(&aperture), "4.0", "the PR-3 Aperture goldens' control");
  }

  /// `Composite:Aperture` over an `exif:FNumber=0E0` operand.
  ///
  /// Bundled ExifTool 13.59 emits the literal `0E0` (UNQUOTED) in BOTH `-j` and
  /// `-n` (`EscapeJSON`'s `return $str`, `XMPStruct.pl:176`). The shared
  /// `value.rs` serializer now emits an in-gate numeric STRING token VERBATIM
  /// (#321), so `Str("0E0")` -> `0E0` byte-identically (it no longer reparses to
  /// the canonical `0.0`). The composite SCALAR was always correct (`Str("0E0")`);
  /// this pins the now-faithful JSON re-emit.
  #[cfg(feature = "json")]
  #[test]
  fn aperture_degenerate_0e0_token_emit_vs_bundled() {
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FNumber", TagValue::Str("0E0".into()))];

    // `-j` (PrintConv): PrintFNumber("0E0") — IsFloat matches, value 0 is not
    // `> 0`, so it returns the norm "0E0" verbatim. Bundled: bare `0E0`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    let j = composite(&prt, "Aperture").expect("Aperture built (-j)");
    assert_eq!(j, TagValue::Str("0E0".into()), "the SCALAR is correct");
    assert_eq!(emit(&j), "0E0", "bundled emits literal `0E0`");

    // `-n` (ValueConv): the operand passes through verbatim -> `Str("0E0")`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    let n = composite(&val, "Aperture").expect("Aperture built (-n)");
    assert_eq!(n, TagValue::Str("0E0".into()));
    assert_eq!(emit(&n), "0E0", "bundled emits literal `0E0`");
  }

  /// `Composite:ShutterSpeed` over an `exif:ExposureTime=-0.0` operand.
  ///
  /// Bundled ExifTool 13.59: `-0` (`-j`, after PrintExposureTime's `%.1f`+strip
  /// gives `-0`), `-0.0` (`-n`, the raw operand) — both emitted VERBATIM by
  /// `EscapeJSON`'s `return $str` (`XMPStruct.pl:176`). The shared `value.rs`
  /// serializer now emits an in-gate numeric STRING token VERBATIM (#321), so
  /// `Str("-0")` -> `-0` (it no longer reparses through `serialize_i64`, which
  /// dropped the sign to `0`) and `Str("-0.0")` -> `-0.0`, both byte-identical.
  #[cfg(feature = "json")]
  #[test]
  fn shutter_speed_degenerate_negzero_token_emit_vs_bundled() {
    let entries: &[(&str, &str, TagValue)] =
      &[("ExifIFD", "ExposureTime", TagValue::Str("-0.0".into()))];

    // `-j` (PrintConv): PrintExposureTime("-0.0") — IsFloat matches, value -0.0
    // is not `> 0` and not `< 0.25001 && > 0`, so `%.1f` -> "-0.0" -> strip
    // ".0" -> "-0". Bundled: bare `-0`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    let j = composite(&prt, "ShutterSpeed").expect("ShutterSpeed built (-j)");
    assert_eq!(j, TagValue::Str("-0".into()), "the SCALAR is correct");
    assert_eq!(emit(&j), "-0", "bundled emits literal `-0`");

    // `-n` (ValueConv): the operand passes through verbatim -> `Str("-0.0")`.
    let mut val = map_with(entries);
    let mut prt = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    let n = composite(&val, "ShutterSpeed").expect("ShutterSpeed built (-n)");
    assert_eq!(n, TagValue::Str("-0.0".into()));
    assert_eq!(emit(&n), "-0.0", "bundled emits literal `-0.0`");
  }

  /// `Composite:FocusDistance` `-n` (ValueConv) numeric branch: a WHOLE metres
  /// distance (`FocusPosition * FocalLength / 1000` over integer operands, e.g.
  /// `100 * 50 / 1000 = 5`) stringifies as the BARE token `5` — Perl renders a
  /// whole number bare, NOT serde's `5.0`; a fractional distance keeps the
  /// full-precision float. (The A200's real FocusDistance is `"inf"` —
  /// FocusPosition 128 — so this whole-value path is reachable only for a body
  /// with FocusPosition < 128 whose `pos * FocalLength` is a multiple of 1000.)
  #[cfg(feature = "json")]
  #[test]
  fn focus_distance_n_whole_renders_bare_token() {
    // pos=100, FocalLength=50 → 100*50/1000 = 5.0 (whole) → bare `5`.
    let whole = CompositePrintConv::FocusDistance.render(
      &CompositeRaw::Num(5.0),
      &[],
      &[],
      ConvMode::ValueConv,
    );
    assert_eq!(
      whole,
      TagValue::I64(5),
      "a whole distance is a bare integer scalar"
    );
    assert_eq!(
      emit(&whole),
      "5",
      "a whole FocusDistance is the bare token `5`, not `5.0`"
    );

    // A fractional distance keeps the full-precision float.
    let frac = CompositePrintConv::FocusDistance.render(
      &CompositeRaw::Num(5.5),
      &[],
      &[],
      ConvMode::ValueConv,
    );
    assert_eq!(frac, TagValue::F64(5.5));
    assert_eq!(
      emit(&frac),
      "5.5",
      "a fractional FocusDistance keeps the float token"
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    assert_eq!(
      composite(&val, "ScaleFactor35efl"),
      Some(TagValue::F64(1.5))
    );
    // `FocalLength35efl` ValueConv is the bare 35mm-equiv focal; an exactly-whole
    // value is an `I64` (`75`), not `F64(75.0)`, so the `-n` token is bare `75`.
    assert_eq!(composite(&val, "FocalLength35efl"), Some(TagValue::I64(75)));
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

  /// Drive `Composite:LensID` through the registry fixpoint from a `(val, prt)`
  /// pair of input triples — `val` carries the raw `$val[i]` (LensType + the
  /// disambiguator ingredients), `prt` the PrintConv `$prt[i]` (the resolved
  /// lens name). Returns the `-j` (PrintConv) LensID, or `None` when deferred.
  fn lens_id_pj(
    val_entries: &[(&str, &str, TagValue)],
    prt_entries: &[(&str, &str, TagValue)],
  ) -> Option<String> {
    let mut prt = map_with(prt_entries);
    let mut val = map_with(val_entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    composite(&prt, "LensID").map(|v| emit(&v))
  }

  #[test]
  fn lens_id_unambiguous_lenstype_emits() {
    // The Samsung NX1 case (`SamsungNX1.srw`): LensType raw 13, PrintConv the
    // resolved name; NO LensType2 / RFLensType / converter ingredient ⇒ the
    // plain-LensType path emits the name (ValueConv `$val` = 13, PrintConv the
    // name). The byte-exact in-tree fixture goldens depend on this still firing.
    let name = "Samsung NX 16-50mm F2-2.8 S ED OIS";
    let got = lens_id_pj(
      &[("Samsung", "LensType", TagValue::U64(13))],
      &[("Samsung", "LensType", TagValue::Str(name.into()))],
    );
    assert_eq!(got.as_deref(), Some(&*std::format!("\"{name}\"")));
  }

  #[test]
  fn lens_id_inactive_rf_lens_type_still_emits() {
    // The `CanonRaw_ctmd.cr3` case: a Canon RFLensType IS present but its RAW
    // `$val[12]` is `0` (PrintConv "n/a"). ExifTool's `if ($val[12])` is FALSE
    // (0 is falsy) ⇒ the Canon RF branch does NOT fire ⇒ the plain-LensType
    // LensID emits (byte-exact with the fixture's "Canon EF-M …" golden).
    let name = "Canon EF-M 15-45mm f/3.5-6.3 IS STM";
    let got = lens_id_pj(
      &[
        ("Track1", "LensType", TagValue::U64(4153)),
        ("Track1", "RFLensType", TagValue::U64(0)),
      ],
      &[
        ("Track1", "LensType", TagValue::Str(name.into())),
        ("Track1", "RFLensType", TagValue::Str("n/a".into())),
      ],
    );
    assert_eq!(got.as_deref(), Some(&*std::format!("\"{name}\"")));
  }

  #[test]
  fn lens_id_active_rf_lens_type_defers() {
    // A Canon RFLensType with a TRUTHY raw `$val[12]` (e.g. 61182) makes
    // ExifTool substitute the RFLensType base + Canon RF PrintConv — a different
    // lens DB exifast can't reproduce. The plain LensType name would be STALE,
    // so the derive defers (returns `None`), emitting no Composite:LensID.
    let got = lens_id_pj(
      &[
        ("Exif", "LensType", TagValue::U64(4153)),
        ("Exif", "RFLensType", TagValue::U64(61182)),
      ],
      &[
        (
          "Exif",
          "LensType",
          TagValue::Str("Canon EF-M 15-45mm f/3.5-6.3 IS STM".into()),
        ),
        (
          "Exif",
          "RFLensType",
          TagValue::Str("Canon RF 24-105mm F4 L IS USM".into()),
        ),
      ],
    );
    assert_eq!(got, None, "an active RFLensType defers LensID");
  }

  #[test]
  fn lens_id_active_lens_type2_emits_lens_type2_name() {
    // A Sony LensType2 whose raw `$val[9]` has bit 0x8000 set (an E-mount lens
    // ID) fires `if (defined $val[9] and ($val[9] & 0x8000 or $val[9] == 0))`:
    // ExifTool swaps in the LensType2 base + Sony PrintConv, so `Composite:LensID`
    // renders the LensType2 PrintConv name (`$prt[9]`). exifast ports this
    // substitution — the LensID PrintConv is the LensType2 name (the ValueConv
    // stays the PLAIN LensType raw, but `lens_id_pj` checks PrintConv).
    let got = lens_id_pj(
      &[
        ("Exif", "LensType", TagValue::U64(0)),
        ("Exif", "LensType2", TagValue::U64(32790)), // 0x8016 — 0x8000 set
      ],
      &[
        (
          "Exif",
          "LensType",
          TagValue::Str("Sony E 18-55mm F3.5-5.6 OSS".into()),
        ),
        (
          "Exif",
          "LensType2",
          TagValue::Str("Sony FE 24-70mm F2.8 GM".into()),
        ),
      ],
    );
    assert_eq!(
      got.as_deref(),
      Some("\"Sony FE 24-70mm F2.8 GM\""),
      "an active LensType2 (0x8000 set) renders the LensType2 PrintConv name"
    );
  }

  #[test]
  fn lens_id_lens_type2_zero_uses_lens_type3() {
    // The GM-lens sub-case (Exif.pm:5341): LensType2 == 0 AND LensType3 has bit
    // 0x8000 ⇒ ExifTool uses LensType3 (`$val[10]`/`$prt[10]`). The LensID
    // PrintConv is then the LensType3 name.
    let got = lens_id_pj(
      &[
        ("Exif", "LensType", TagValue::U64(0)),
        ("Exif", "LensType2", TagValue::U64(0)), // 0 ⇒ fires the branch
        ("Exif", "LensType3", TagValue::U64(40989)), // 0xA01D — 0x8000 set
      ],
      &[
        ("Exif", "LensType", TagValue::Str("Unknown".into())),
        ("Exif", "LensType2", TagValue::Str("n/a".into())),
        (
          "Exif",
          "LensType3",
          TagValue::Str("Sony FE 20mm F1.8 G".into()),
        ),
      ],
    );
    assert_eq!(
      got.as_deref(),
      Some("\"Sony FE 20mm F1.8 G\""),
      "LensType2==0 + LensType3 0x8000 renders the LensType3 PrintConv name"
    );
  }

  #[test]
  fn lens_id_pentax_converter_defers() {
    // The Pentax converter branch appends a `+ Nx converter` suffix only when
    // `$conv = $val[1] / $val[11] > 1.1` (FocalLength / LensFocalLength). Here
    // 300 / 200 = 1.5 > 1.1 ⇒ a real teleconverter; ExifTool appends the suffix
    // exifast can't compute, so the derive defers (no bare name emitted).
    let got = lens_id_pj(
      &[
        ("Exif", "LensType", TagValue::Str("8 61".into())),
        ("Exif", "FocalLength", TagValue::F64(300.0)),
        ("Exif", "LensFocalLength", TagValue::F64(200.0)),
      ],
      &[(
        "Exif",
        "LensType",
        TagValue::Str("smc PENTAX-DA* 200mm F2.8 ED [IF] SDM".into()),
      )],
    );
    assert_eq!(got, None, "a >1.1 converter ratio defers LensID");
  }

  #[test]
  fn lens_id_pentax_no_converter_ratio_still_emits() {
    // The `JPEG_pentax_k70` case: BOTH LensFocalLength and FocalLength present
    // but their ratio is ≈ 1 (28 / 27.5 = 1.018, NOT > 1.1) ⇒ ExifTool appends
    // NOTHING ⇒ the plain LensType name emits, byte-exact with the fixture's
    // golden. A present-but-inactive converter must NOT defer.
    let name = "smc PENTAX-DA 18-135mm F3.5-5.6 ED AL [IF] DC WR";
    let got = lens_id_pj(
      &[
        ("Pentax", "LensType", TagValue::Str("8 215".into())),
        ("Pentax", "FocalLength", TagValue::F64(28.0)),
        ("Pentax", "LensFocalLength", TagValue::F64(27.5)),
      ],
      &[("Pentax", "LensType", TagValue::Str(name.into()))],
    );
    assert_eq!(got.as_deref(), Some(&*std::format!("\"{name}\"")));
  }

  #[test]
  fn focal_length_35efl_falls_back_to_focal_only_without_scale_factor() {
    // ExifGPS.jpg: FocalLength=0, no FocalLengthIn35mmFormat ⇒ ScaleFactor NOT
    // built; FocalLength35efl Requires FocalLength (0) + Desires ScaleFactor
    // (Missing) ⇒ `(0||0)*(undef||1)` = 0 ⇒ "0.0 mm".
    let entries: &[(&str, &str, TagValue)] = &[("ExifIFD", "FocalLength", TagValue::F64(0.0))];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
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
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    assert!(
      composite(&prt, "FocalLength35efl").is_none(),
      "Canon + present-but-falsy FocalLength=0 + truthy FocalLengthIn35mmFormat \
       + sensor data ⇒ FocalLength35efl defers (the simple path needs BOTH \
       `$focal` AND `$foc35` truthy)"
    );
  }
}

// ===========================================================================
// #133 PR 5 — the SubDoc per-`Doc<N>` fixpoint, the cross-document (`DocScope::
// Main` fallback) resolution, and the QuickTime video defs (AvgBitrate /
// Rotation / RIFF Duration). The video allow-list flip is gated on the Sony
// SubDoc architecture decision, so these exercise the ENGINE directly over
// hand-built multi-document TagMaps (the M2TS/HEIF/rove conformance goldens pin
// the end-to-end byte-exactness once the flip lands).
// ===========================================================================

#[cfg(feature = "exif")]
mod subdoc {
  use super::*;

  /// Build a TagMap with `(doc, group, name, value)` entries (the family-3
  /// sub-document axis the SubDoc resolution keys on).
  fn map_with_docs(entries: &[(u32, &str, &str, TagValue)]) -> TagMap {
    let mut m = TagMap::new();
    for (doc, g, n, v) in entries {
      let _ = m.write_value_doc(*doc, "", g, n, 1, v.clone(), g);
    }
    m
  }

  /// The composite value at a specific family-3 `doc`.
  fn composite_at(m: &TagMap, doc: u32, name: &str) -> Option<TagValue> {
    m.entries()
      .iter()
      .find(|(d, _s, g, n, _p, _v, _)| *d == doc && g.as_str() == "Composite" && n.as_str() == name)
      .map(|(_d, _s, _g, _n, _p, v, _)| v.clone())
  }

  #[test]
  fn subdoc_gps_builds_per_document_m2ts_shape() {
    // The M2TS_h264_mdpm shape: Main `GPS:` coords (48/11) AND a `Doc1:GPS:`
    // sample (49/12). `Composite:GPSLatitude`/`GPSLongitude` (SubDoc) must build
    // at BOTH Main AND Doc1; `Composite:GPSPosition` (NOT SubDoc) builds at Main
    // only (from the Main composites). Byte-exact vs bundled (the earlier oracle
    // run: Main 48 N / 11 E + Position, Doc1 49 N / 12 E, NO Doc1 Position).
    let entries: &[(u32, &str, &str, TagValue)] = &[
      (0, "GPS", "GPSLatitude", TagValue::F64(48.0)),
      (0, "GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
      (0, "GPS", "GPSLongitude", TagValue::F64(11.0)),
      (0, "GPS", "GPSLongitudeRef", TagValue::Str("E".into())),
      (1, "GPS", "GPSLatitude", TagValue::F64(49.0)),
      (1, "GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
      (1, "GPS", "GPSLongitude", TagValue::F64(12.0)),
      (1, "GPS", "GPSLongitudeRef", TagValue::Str("E".into())),
    ];
    let mut prt = map_with_docs(entries);
    let mut valv = map_with_docs(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1, // doc_count = 1
      &ctx0(),
    );
    // Main composites (the DMS PrintConv strings).
    assert_eq!(
      composite_at(&prt, 0, "GPSLatitude"),
      Some(TagValue::Str("48 deg 0' 0.00\" N".into()))
    );
    assert_eq!(
      composite_at(&prt, 0, "GPSLongitude"),
      Some(TagValue::Str("11 deg 0' 0.00\" E".into()))
    );
    assert_eq!(
      composite_at(&prt, 0, "GPSPosition"),
      Some(TagValue::Str(
        "48 deg 0' 0.00\" N, 11 deg 0' 0.00\" E".into()
      ))
    );
    // Per-document Doc1 composites (built from the Doc1 GPS sample).
    assert_eq!(
      composite_at(&prt, 1, "GPSLatitude"),
      Some(TagValue::Str("49 deg 0' 0.00\" N".into()))
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSLongitude"),
      Some(TagValue::Str("12 deg 0' 0.00\" E".into()))
    );
    // `GPSPosition` is NOT SubDoc ⇒ no Doc1 Position (matches bundled).
    assert_eq!(composite_at(&prt, 1, "GPSPosition"), None);
  }

  #[test]
  fn subdoc_only_builds_for_documents_with_the_ingredient() {
    // A Doc1 GPS sample but NO Doc2 GPS ⇒ Doc1 builds, Doc2 does not (the
    // per-document `sub_doc_has_chance` gate skips a doc with no Require'd tag).
    let entries: &[(u32, &str, &str, TagValue)] = &[
      (1, "GPS", "GPSLatitude", TagValue::F64(49.0)),
      (1, "GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
      (1, "GPS", "GPSLongitude", TagValue::F64(12.0)),
      (1, "GPS", "GPSLongitudeRef", TagValue::Str("E".into())),
    ];
    let mut prt = map_with_docs(entries);
    let mut valv = map_with_docs(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      2,
      &ctx0(),
    );
    assert!(composite_at(&prt, 1, "GPSLatitude").is_some());
    assert_eq!(composite_at(&prt, 2, "GPSLatitude"), None);
    // No Main GPS ⇒ no Main composite (and GPSPosition needs the Main ones).
    assert_eq!(composite_at(&prt, 0, "GPSLatitude"), None);
  }

  #[test]
  fn gps_position_cross_doc_fallback_uses_doc1_when_no_main() {
    // The Main-`GPSPosition` cross-document `DocScope::Main` fallback: NO Main
    // `Composite:GPSLatitude`/`Longitude`, but Doc1 has them (built by the SubDoc
    // pass). `Composite:GPSPosition` (Main, non-SubDoc) resolves
    // `Composite:GPSLatitude` across docs ⇒ finds the Doc1 ones ⇒ builds a MAIN
    // `Composite:GPSPosition`. (The Sony rtmd source-tag family-0 `Sony` path is
    // exercised separately in `sony_subdoc_gps_*`; here a `GPS`-group Doc1 sample
    // drives the same cross-doc fixpoint.)
    let entries: &[(u32, &str, &str, TagValue)] = &[
      (1, "GPS", "GPSLatitude", TagValue::F64(47.628418)),
      (1, "GPS", "GPSLatitudeRef", TagValue::Str("N".into())),
      (1, "GPS", "GPSLongitude", TagValue::F64(122.165)),
      (1, "GPS", "GPSLongitudeRef", TagValue::Str("W".into())),
    ];
    let mut prt = map_with_docs(entries);
    let mut valv = map_with_docs(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1,
      &ctx0(),
    );
    // The Doc1 composites built.
    assert!(composite_at(&prt, 1, "GPSLatitude").is_some());
    // The MAIN GPSPosition built via the cross-doc fallback (reads the Doc1
    // Composite:GPSLatitude/Longitude).
    let pos = composite_at(&prt, 0, "GPSPosition");
    assert!(
      pos.is_some(),
      "Main GPSPosition must build from the Doc1 composites (cross-doc fallback)"
    );
  }

  /// Build a TagMap with `(doc, family0, family1, name, value)` entries — the
  /// family-0-qualified axis the Sony SubDoc GPS defs (`Sony:GPSLatitude`,
  /// Sony.pm:10929) resolve on. A Sony rtmd GPS tag is family-0 `Sony`,
  /// family-1 the per-sample `Track<N>`. Every entry takes ExifTool's default
  /// `Priority => 1`; use [`map_with_docs_g0_p`] for the priority-aware
  /// duplicate-override parity tests.
  #[cfg(feature = "quicktime")]
  fn map_with_docs_g0(entries: &[(u32, &str, &str, &str, TagValue)]) -> TagMap {
    let mut m = TagMap::new();
    for (doc, g0, g1, n, v) in entries {
      let _ = m.write_value_doc(*doc, "", g1, n, 1, v.clone(), g0);
    }
    m
  }

  /// Build a TagMap with `(doc, family0, family1, name, priority, value)`
  /// entries — the priority-aware variant of [`map_with_docs_g0`] for the
  /// two-sink duplicate-override parity tests. The explicit `priority` exercises
  /// ExifTool's general duplicate rule (`ExifTool.pm:9544-9560`) through the real
  /// [`crate::tagmap::TagMap::insert`] path: ordinary tags pass `1`, a
  /// `Priority => 0` duplicate (which never overrides) passes `0`, a
  /// higher-priority survivor passes `2`.
  #[cfg(feature = "quicktime")]
  fn map_with_docs_g0_p(entries: &[(u32, &str, &str, &str, u8, TagValue)]) -> TagMap {
    let mut m = TagMap::new();
    for (doc, g0, g1, n, p, v) in entries {
      let _ = m.write_value_doc(*doc, "", g1, n, *p, v.clone(), g0);
    }
    m
  }

  /// PART A + B: the family-0-qualified Sony SubDoc GPS defs build a
  /// `Doc<N>:Composite:GPS*` from Sony rtmd's family-0 `Sony` GPS source tags
  /// (family-1 `Track1`) — the family-0 carry on the TagMap entry is what lets
  /// `Sony:GPSLatitude` match. Ground-truth (bundled `-ee -G3:1`
  /// `QuickTime_sony_rtmd.mov`): Doc1 Composite GPSDateTime/GPSLatitude/
  /// GPSLongitude at 47°37'42.30"N / 122°9'54.00"W.
  #[cfg(feature = "quicktime")]
  #[test]
  fn sony_subdoc_gps_builds_from_family0_sony_inputs() {
    // Sony rtmd Doc1 GPS sample: family-0 `Sony`, family-1 `Track1`.
    let entries: &[(u32, &str, &str, &str, TagValue)] = &[
      (1, "Sony", "Track1", "GPSLatitude", TagValue::F64(47.628418)),
      (
        1,
        "Sony",
        "Track1",
        "GPSLatitudeRef",
        TagValue::Str("North".into()),
      ),
      (1, "Sony", "Track1", "GPSLongitude", TagValue::F64(122.165)),
      (
        1,
        "Sony",
        "Track1",
        "GPSLongitudeRef",
        TagValue::Str("West".into()),
      ),
      (
        1,
        "Sony",
        "Track1",
        "GPSDateStamp",
        TagValue::Str("2024:01:07".into()),
      ),
      (
        1,
        "Sony",
        "Track1",
        "GPSTimeStamp",
        TagValue::Str("11:19:15".into()),
      ),
    ];
    let mut prt = map_with_docs_g0(entries);
    let mut valv = map_with_docs_g0(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1,
      &ctx0(),
    );
    // Doc1 Composite GPS* built (the `^S`/`^W` negate via "North"/"West").
    assert_eq!(
      composite_at(&prt, 1, "GPSLatitude"),
      Some(TagValue::Str("47 deg 37' 42.30\" N".into()))
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSLongitude"),
      Some(TagValue::Str("122 deg 9' 54.00\" W".into()))
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSDateTime"),
      Some(TagValue::Str("2024:01:07 11:19:15Z".into()))
    );
  }

  /// PART B negative: a GoPro Doc1 GPS sample (family-0 `GoPro`, family-1
  /// `Track4`) does NOT match the `Sony:`-qualified defs ⇒ NO
  /// `Doc<N>:Composite:GPS*` from them. Ground-truth (bundled `-ee -G3:1`
  /// `QuickTime_gopro_hero8_gpmf.mp4`): no `Doc1:Composite:GPS*` — its per-doc
  /// GPS is the gpmf `Doc1:Track4:GPSLatitude` only. (The Main cross-doc
  /// `GPSPosition` from the gpmf GPS-group tags is a separate path.)
  #[cfg(feature = "quicktime")]
  #[test]
  fn gopro_subdoc_gps_does_not_match_sony_defs() {
    // GoPro gpmf Doc1 GPS sample: family-0 `GoPro` (NOT `Sony`).
    let entries: &[(u32, &str, &str, &str, TagValue)] = &[
      (1, "GoPro", "Track4", "GPSLatitude", TagValue::F64(42.02662)),
      (
        1,
        "GoPro",
        "Track4",
        "GPSLatitudeRef",
        TagValue::Str("North".into()),
      ),
      (
        1,
        "GoPro",
        "Track4",
        "GPSLongitude",
        TagValue::F64(-129.294),
      ),
      (
        1,
        "GoPro",
        "Track4",
        "GPSLongitudeRef",
        TagValue::Str("West".into()),
      ),
      (
        1,
        "GoPro",
        "Track4",
        "GPSDateStamp",
        TagValue::Str("2019:01:01".into()),
      ),
      (
        1,
        "GoPro",
        "Track4",
        "GPSTimeStamp",
        TagValue::Str("00:00:00".into()),
      ),
    ];
    let mut prt = map_with_docs_g0(entries);
    let mut valv = map_with_docs_g0(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1,
      &ctx0(),
    );
    // The Sony SubDoc defs require family-0 `Sony`; GoPro's family-0 is `GoPro`,
    // so NO Doc1 Composite GPS* is built from them.
    assert_eq!(composite_at(&prt, 1, "GPSLatitude"), None);
    assert_eq!(composite_at(&prt, 1, "GPSLongitude"), None);
    assert_eq!(composite_at(&prt, 1, "GPSDateTime"), None);
  }

  /// Build the deduped [`Tag`](crate::value::Tag) `Vec` from a raw
  /// `(doc, family0, family1, name, priority, value)` stream with the EXACT rule
  /// [`collect_deduped_tags`](crate::format_parser::AnyMeta) applies: the
  /// SHARED [`crate::tagmap::dedup_override`] +
  /// [`crate::tagmap::effective_priority`] predicate (so a duplicate REPLACES
  /// the surviving slot — the winner's whole tag, family-0 included, AND its
  /// stored effective priority — IFF its effective priority is non-zero AND
  /// `>=` the stored one; a `Priority => 0` duplicate never overrides). This is
  /// the SAME predicate the `TagMap` sink uses, so feeding the SAME stream into
  /// both lets us assert the two sinks agree across every priority case. The
  /// post-dedup `Vec` is what the `CompositeSink for Vec<Tag>` impl resolves
  /// over.
  #[cfg(feature = "quicktime")]
  fn vec_deduped_g0(
    entries: &[(u32, &str, &str, &str, u8, TagValue)],
  ) -> std::vec::Vec<crate::value::Tag> {
    let mut out: std::vec::Vec<(crate::value::Tag, u8)> = std::vec::Vec::new();
    for (doc, g0, g1, n, p, v) in entries {
      let tag =
        crate::value::Tag::new(crate::value::Group::with_doc(*g0, *g1, *doc), *n, v.clone());
      let effective = crate::tagmap::effective_priority(n, *p);
      if let Some(slot) = out.iter_mut().find(|(t, _p)| {
        t.group_ref().family1() == tag.group_ref().family1() && t.name() == tag.name()
      }) {
        if crate::tagmap::dedup_override(effective, slot.1) {
          // The winner's whole tag (with its family-0) replaces the slot, and
          // its effective priority becomes the new stored one — the Vec-sink
          // semantics `collect_deduped_tags` (and the `TagMap` fix) apply.
          *slot = (tag, effective);
        }
      } else {
        out.push((tag, effective));
      }
    }
    out.into_iter().map(|(t, _p)| t).collect()
  }

  /// TWO-SINK PARITY (the #133 finding): a MIXED-family-0 duplicate — same
  /// `(doc, family1, name)` but family-0 `GoPro` FIRST then family-0 `Sony`
  /// SECOND (Sony wins the priority-1 last-wins) — must resolve IDENTICALLY
  /// through the `TagMap` sink and the `Tag`-`Vec` sink. The surviving entry's
  /// family-0 is the WINNER's (`Sony`), so a `Sony:`-qualified Composite input
  /// MATCHES and a `GoPro:`-qualified one does NOT — from BOTH sinks. Before the
  /// fix the `TagMap` override kept the FIRST (`GoPro`) family-0 while the `Vec`
  /// sink (`*slot = tag`) kept the winner's (`Sony`), so the two sinks DISAGREED
  /// on this group-0-qualified resolution under the same input order. This is
  /// reachable on the video path: track-scoped timed emitters distinguish
  /// Sony/QuickTime/GoPro family-0 while SHARING a `Track<N>` family-1 name.
  #[cfg(feature = "quicktime")]
  #[test]
  fn mixed_family0_duplicate_resolves_identically_in_both_sinks() {
    // Doc1, family-1 `Track1`: a GoPro-family-0 sample is OVERRIDDEN by a later
    // Sony-family-0 sample of the same `(doc, family1, name)`. Sony's values are
    // the survivors (last-wins). Both lat + ref carry the mixed-family-0 dup so
    // the Sony `GPSLatitude` composite has its two Sony-qualified ingredients.
    let stream: &[(u32, &str, &str, &str, u8, TagValue)] = &[
      (1, "GoPro", "Track1", "GPSLatitude", 1, TagValue::F64(11.0)),
      (
        1,
        "GoPro",
        "Track1",
        "GPSLatitudeRef",
        1,
        TagValue::Str("South".into()),
      ),
      // Sony duplicates WIN (priority 1 >= 1, last-wins) — value AND family-0.
      (
        1,
        "Sony",
        "Track1",
        "GPSLatitude",
        1,
        TagValue::F64(47.628418),
      ),
      (
        1,
        "Sony",
        "Track1",
        "GPSLatitudeRef",
        1,
        TagValue::Str("North".into()),
      ),
    ];

    // ---- Sink A: TagMap (real `write_value_doc` -> `insert` dedup path). ----
    let map = map_with_docs_g0_p(stream);
    // The duplicate collapsed to ONE entry per `(doc, family1, name)`.
    assert_eq!(
      map
        .entries()
        .iter()
        .filter(|(d, _s, _g1, n, _p, _v, _f0)| *d == 1 && n.as_str() == "GPSLatitude")
        .count(),
      1,
      "mixed-family-0 duplicate must collapse to one entry"
    );

    // ---- Sink B: the deduped `Tag` `Vec` (same stream, `*slot = tag`). ----
    let vec = vec_deduped_g0(stream);

    // PARITY at the resolve level (DocScope::Exact(1), the SubDoc per-doc axis):
    // the surviving family-0 is the WINNER's (`Sony`), so a `Sony:`-qualified
    // input matches and a `GoPro:`-qualified one does NOT — from BOTH sinks.
    for (label, present, missing) in [
      (
        "Sony matches the winner / GoPro (the loser) does not — TagMap",
        map.resolve(&[], Some("Sony"), "GPSLatitude", DocScope::Exact(1)),
        map.resolve(&[], Some("GoPro"), "GPSLatitude", DocScope::Exact(1)),
      ),
      (
        "Sony matches the winner / GoPro (the loser) does not — Vec<Tag>",
        vec.resolve(&[], Some("Sony"), "GPSLatitude", DocScope::Exact(1)),
        vec.resolve(&[], Some("GoPro"), "GPSLatitude", DocScope::Exact(1)),
      ),
    ] {
      assert!(present.is_present(), "{label}: winner Sony must match");
      assert!(
        !missing.is_present(),
        "{label}: loser GoPro must NOT match the survivor"
      );
      // The matched value is the Sony survivor (47.628418), not the GoPro 11.0.
      assert_eq!(
        present.value(),
        Some(&TagValue::F64(47.628418)),
        "{label}: the survivor's VALUE is the winner's too"
      );
    }
    // The ref resolves to the Sony survivor ("North") in both sinks as well.
    assert_eq!(
      map
        .resolve(&[], Some("Sony"), "GPSLatitudeRef", DocScope::Exact(1))
        .value(),
      Some(&TagValue::Str("North".into()))
    );
    assert_eq!(
      vec
        .resolve(&[], Some("Sony"), "GPSLatitudeRef", DocScope::Exact(1))
        .value(),
      Some(&TagValue::Str("North".into()))
    );

    // END-TO-END: the Sony SubDoc `Composite:GPSLatitude` (family-0-qualified)
    // BUILDS at Doc1 from the SURVIVING Sony-family-0 ingredients (lat 47.628418
    // + ref "North" ⇒ +lat ⇒ 47°37'42.30" N). This only happens because the fix
    // carried the winner's family-0 through the TagMap override — with the stale
    // (`GoPro`) family-0 the `sony_req("GPSLatitude")` input would NOT match and
    // no composite would build. Ground-truth matches the Sony rtmd Doc1 GPS.
    let mut prt = map_with_docs_g0_p(stream);
    let mut valv = map_with_docs_g0_p(stream);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1,
      &ctx0(),
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSLatitude"),
      Some(TagValue::Str("47 deg 37' 42.30\" N".into())),
      "Sony Doc1 Composite:GPSLatitude must build from the surviving Sony family-0 ingredients"
    );
  }

  /// TWO-SINK PARITY — the LOWER / priority-0 duplicate that LOSES (the #133
  /// terminal-parity close). The R1 test above covers priority-1 last-wins; this
  /// covers the OTHER two branches of [`crate::tagmap::dedup_override`]:
  ///
  /// 1. A `Priority => 0` duplicate (`new_effective == 0`) — the VP8/VP8L
  ///    `ImageWidth`-behind-a-`VP8X`-canvas shape (RIFF.pm:1301/1312/1329/1340)
  ///    AND the `Warning`/`Error` pseudo-tags: it NEVER overrides ⇒ first-wins.
  /// 2. A strictly-LOWER non-zero priority (`new_effective < stored`, here `1`
  ///    after a `2`) — `1 >= 2` is false ⇒ the higher-priority FIRST entry wins.
  ///
  /// In BOTH the SURVIVOR is the FIRST (higher-priority) entry, whose VALUE and
  /// family-0 must be what BOTH sinks resolve — the `TagMap` (JSON / golden) sink
  /// and the `Tag`-`Vec` (`iter_tags` / Composite) sink. Before this fix the `Vec`
  /// sink did an UNCONDITIONAL `*slot = tag` on every non-`Warning`/`Error`
  /// duplicate, so a priority-0 / lower-priority loser would LAST-win in the `Vec`
  /// path while FIRST-winning in `TagMap` — diverging value AND family-0. Both
  /// shapes are reachable on the video path (track-scoped Sony/QuickTime/GoPro
  /// family-0 sharing a `Track<N>` family-1; the RIFF WEBP priority-0 dims).
  /// Combined with the R1 priority-1 test, parity now holds across ALL three
  /// cases: higher-wins, equal-last-wins, lower/zero-loses.
  #[cfg(feature = "quicktime")]
  #[test]
  fn lower_and_zero_priority_loser_resolves_identically_in_both_sinks() {
    // Doc1, family-1 `Track1`. The WINNER is family-0 `Sony` (so the Sony SubDoc
    // GPS composite defs, which `Require` `Sony:`-qualified inputs, fire); the
    // LOSER is family-0 `GoPro`:
    //  - `GPSLatitude`: a HIGHER-priority (2) Sony entry FIRST, then a LOWER (1)
    //    GoPro duplicate that LOSES (`1 >= 2` false) — Sony survives.
    //  - `GPSLongitude`: a default-priority (1) Sony entry FIRST, then a
    //    `Priority => 0` GoPro duplicate that LOSES (never overrides) — Sony
    //    survives. This is the VP8/VP8L-`ImageWidth`-behind-`VP8X` shape.
    // Both source tags carry their `*Ref` so the Sony-family-0 composite builds
    // from the SURVIVING Sony ingredients (and a GoPro-qualified one cannot).
    let stream: &[(u32, &str, &str, &str, u8, TagValue)] = &[
      // GPSLatitude: Sony priority-2 FIRST (survives the lower GoPro dup).
      (
        1,
        "Sony",
        "Track1",
        "GPSLatitude",
        2,
        TagValue::F64(47.628418),
      ),
      (
        1,
        "Sony",
        "Track1",
        "GPSLatitudeRef",
        2,
        TagValue::Str("North".into()),
      ),
      // GPSLongitude: Sony priority-1 FIRST (survives the priority-0 GoPro dup).
      (
        1,
        "Sony",
        "Track1",
        "GPSLongitude",
        1,
        TagValue::F64(122.165),
      ),
      (
        1,
        "Sony",
        "Track1",
        "GPSLongitudeRef",
        1,
        TagValue::Str("West".into()),
      ),
      // LOSERS — same `(doc, family1, name)`, mixed family-0 `GoPro`:
      //  lower-priority (1 < 2) ⇒ never wins; priority-0 ⇒ never wins.
      (1, "GoPro", "Track1", "GPSLatitude", 1, TagValue::F64(11.0)),
      (
        1,
        "GoPro",
        "Track1",
        "GPSLatitudeRef",
        1,
        TagValue::Str("South".into()),
      ),
      (1, "GoPro", "Track1", "GPSLongitude", 0, TagValue::F64(22.0)),
      (
        1,
        "GoPro",
        "Track1",
        "GPSLongitudeRef",
        0,
        TagValue::Str("East".into()),
      ),
    ];

    // ---- Sink A: TagMap; Sink B: the deduped `Tag` `Vec` (SAME stream). ----
    let map = map_with_docs_g0_p(stream);
    let vec = vec_deduped_g0(stream);

    // Each `(doc, family1, name)` collapsed to ONE entry in the TagMap sink.
    for name in ["GPSLatitude", "GPSLongitude"] {
      assert_eq!(
        map
          .entries()
          .iter()
          .filter(|(d, _s, _g1, n, _p, _v, _f0)| *d == 1 && n.as_str() == name)
          .count(),
        1,
        "the {name} loser duplicate must collapse to one entry"
      );
    }

    // PARITY at the resolve level (DocScope::Exact(1)): the surviving family-0 is
    // the WINNER's (`Sony`, the higher / non-zero-priority FIRST entry), so a
    // `Sony:`-qualified input matches and the `GoPro:` loser does NOT — from BOTH
    // sinks, for BOTH the lower-priority (GPSLatitude) and priority-0
    // (GPSLongitude) loss. The matched VALUE is the Sony survivor's, never the
    // GoPro loser's.
    for (name, winner_val) in [
      ("GPSLatitude", TagValue::F64(47.628418)),
      ("GPSLongitude", TagValue::F64(122.165)),
    ] {
      for (label, sink_present, sink_missing) in [
        (
          "TagMap",
          map.resolve(&[], Some("Sony"), name, DocScope::Exact(1)),
          map.resolve(&[], Some("GoPro"), name, DocScope::Exact(1)),
        ),
        (
          "Vec<Tag>",
          vec.resolve(&[], Some("Sony"), name, DocScope::Exact(1)),
          vec.resolve(&[], Some("GoPro"), name, DocScope::Exact(1)),
        ),
      ] {
        assert!(
          sink_present.is_present(),
          "{label}: winner Sony must match {name}"
        );
        assert!(
          !sink_missing.is_present(),
          "{label}: loser GoPro must NOT match the {name} survivor"
        );
        assert_eq!(
          sink_present.value(),
          Some(&winner_val),
          "{label}: the surviving {name} VALUE is the winner's (Sony), not the GoPro loser's"
        );
      }
    }

    // END-TO-END: the Sony SubDoc `Composite:GPSLatitude`/`GPSLongitude`
    // (family-0-qualified) BUILD at Doc1 from the SURVIVING Sony family-0
    // ingredients — proving the `Vec` and `TagMap` sinks present an IDENTICAL
    // family-0-qualified ingredient set after a lower/zero-priority loss. (With
    // the old unconditional `*slot = tag` the `Vec` path would have surfaced the
    // GoPro loser's value+family-0 here.)
    let mut prt = map_with_docs_g0_p(stream);
    let mut valv = map_with_docs_g0_p(stream);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut valv),
      ConvMode::PrintConv,
      1,
      &ctx0(),
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSLatitude"),
      Some(TagValue::Str("47 deg 37' 42.30\" N".into())),
      "Doc1 Composite:GPSLatitude must build from the surviving Sony (priority-2) ingredients"
    );
    assert_eq!(
      composite_at(&prt, 1, "GPSLongitude"),
      Some(TagValue::Str("122 deg 9' 54.00\" W".into())),
      "Doc1 Composite:GPSLongitude must build from the surviving Sony (priority-1) ingredients, \
       not the priority-0 GoPro loser"
    );
  }
}

#[cfg(feature = "quicktime")]
mod video_defs {
  use super::super::table::CompositeContext;
  use super::*;

  fn map_with(entries: &[(&str, &str, TagValue)]) -> TagMap {
    let mut m = TagMap::new();
    for (g, n, v) in entries {
      let _ = m.write_value_doc(0, "", g, n, 1, v.clone(), g);
    }
    m
  }
  fn composite(m: &TagMap, name: &str) -> Option<TagValue> {
    m.get("Composite", name).cloned()
  }

  #[test]
  fn avg_bitrate_sums_all_mdat_via_context() {
    // The HEIF shape: a single VISIBLE `MediaDataSize` (8) but the threaded
    // `media_data_total` is the SUM of all three `mdat` (1 004 715). Duration
    // 0.16 s ⇒ int(1004715*8 / 0.16 + 0.5) = 50 235 750 bps ⇒ "50.2 Mbps".
    let entries: &[(&str, &str, TagValue)] = &[
      ("QuickTime", "MediaDataSize", TagValue::U64(8)),
      ("QuickTime", "Duration", TagValue::F64(0.16)),
    ];
    let ctx = CompositeContext::new(Some(1_004_715), None);

    // `-j`: ConvertBitrate ⇒ "50.2 Mbps".
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx,
    );
    assert_eq!(
      composite(&prt, "AvgBitrate"),
      Some(TagValue::Str("50.2 Mbps".into()))
    );
    // `-n`: the bare integer bps.
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx,
    );
    assert_eq!(
      composite(&val, "AvgBitrate"),
      Some(TagValue::F64(50_235_750.0))
    );
  }

  #[test]
  fn avg_bitrate_no_timescale_divide_camm_shape() {
    // camm: MediaDataSize 116, Duration 3 s ⇒ int(116*8/3 + 0.5) = 309 ⇒
    // "309 bps". NO TimeScale divide (the ground-truthed behavior).
    let entries: &[(&str, &str, TagValue)] = &[
      ("QuickTime", "MediaDataSize", TagValue::U64(116)),
      ("QuickTime", "Duration", TagValue::F64(3.0)),
    ];
    let ctx = CompositeContext::new(Some(116), None);
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx,
    );
    assert_eq!(
      composite(&prt, "AvgBitrate"),
      Some(TagValue::Str("309 bps".into()))
    );
  }

  #[test]
  fn avg_bitrate_not_built_without_duration() {
    // `return undef unless $val[1]` — a zero/absent Duration ⇒ no AvgBitrate.
    let entries: &[(&str, &str, TagValue)] = &[
      ("QuickTime", "MediaDataSize", TagValue::U64(100)),
      ("QuickTime", "Duration", TagValue::F64(0.0)),
    ];
    let ctx = CompositeContext::new(Some(100), None);
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx,
    );
    assert_eq!(composite(&prt, "AvgBitrate"), None);
  }

  #[test]
  fn rotation_reads_precomputed_context_angle() {
    // `Composite:Rotation` requires `QuickTime:MatrixStructure` + `HandlerType`
    // (the build gate); the value is the pre-computed `ctx.rotation`. Identity
    // matrix ⇒ 0 (both modes emit the bare angle).
    let entries: &[(&str, &str, TagValue)] = &[
      (
        "QuickTime",
        "MatrixStructure",
        TagValue::Str("1 0 0 0 1 0 0 0 1".into()),
      ),
      ("QuickTime", "HandlerType", TagValue::Str("vide".into())),
    ];
    let ctx = CompositeContext::new(None, Some(0.0));
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx,
    );
    assert_eq!(composite(&prt, "Rotation"), Some(TagValue::F64(0.0)));
  }

  #[test]
  fn rotation_not_built_when_inputs_missing_or_angle_none() {
    // No MatrixStructure ⇒ the Require fails ⇒ no Rotation, even with a ctx angle.
    let entries: &[(&str, &str, TagValue)] =
      &[("QuickTime", "HandlerType", TagValue::Str("vide".into()))];
    let ctx = CompositeContext::new(None, Some(90.0));
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx,
    );
    assert_eq!(composite(&prt, "Rotation"), None);

    // Inputs present but `ctx.rotation` None (no video track) ⇒ the ValueConv is
    // `undef` ⇒ no Rotation.
    let entries2: &[(&str, &str, TagValue)] = &[
      (
        "QuickTime",
        "MatrixStructure",
        TagValue::Str("0 0 0 0 0 0 0 0 0".into()),
      ),
      ("QuickTime", "HandlerType", TagValue::Str("soun".into())),
    ];
    let ctx2 = CompositeContext::new(None, None);
    let mut prt = map_with(entries2);
    let mut val = map_with(entries2);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx2,
    );
    assert_eq!(composite(&prt, "Rotation"), None);
  }
}

#[cfg(feature = "riff")]
mod riff_duration {
  use super::*;

  fn map_with(entries: &[(&str, &str, TagValue)]) -> TagMap {
    let mut m = TagMap::new();
    for (g, n, v) in entries {
      let _ = m.write_value_doc(0, "", g, n, 1, v.clone(), g);
    }
    m
  }
  fn composite(m: &TagMap, name: &str) -> Option<TagValue> {
    m.get("Composite", name).cloned()
  }

  #[test]
  fn riff_duration_frame_count_over_rate() {
    // Pentax.avi: FrameRate 24, FrameCount 600 ⇒ 25 s. VideoFrameRate/Count are
    // equal (ratio 1.0, not in 1.9..3.1) ⇒ dur1 kept. `-j` ConvertDuration.
    let entries: &[(&str, &str, TagValue)] = &[
      ("RIFF", "FrameRate", TagValue::U64(24)),
      ("RIFF", "FrameCount", TagValue::U64(600)),
      ("RIFF", "VideoFrameRate", TagValue::U64(24)),
      ("RIFF", "VideoFrameCount", TagValue::U64(600)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut prt,
      Some(&mut val),
      ConvMode::PrintConv,
      0,
      &ctx0(),
    );
    // 25 s ⇒ ">= 30"? no, < 30 ⇒ "25.00 s".
    assert_eq!(
      composite(&prt, "Duration"),
      Some(TagValue::Str("25.00 s".into()))
    );
  }

  #[test]
  fn riff_duration_video_stream_override_when_2_to_3x() {
    // The header-FrameCount-too-long case: FrameRate 15, FrameCount 700 ⇒ dur1
    // 46.67 s; VideoFrameRate 15, VideoFrameCount 233 ⇒ dur2 15.53 s; ratio
    // 46.67/15.53 = 3.0 (in 1.9..3.1) ⇒ dur2 wins (15.53 s).
    let entries: &[(&str, &str, TagValue)] = &[
      ("RIFF", "FrameRate", TagValue::U64(15)),
      ("RIFF", "FrameCount", TagValue::U64(700)),
      ("RIFF", "VideoFrameRate", TagValue::U64(15)),
      ("RIFF", "VideoFrameCount", TagValue::U64(233)),
    ];
    let mut prt = map_with(entries);
    let mut val = map_with(entries);
    build_into(
      REGISTRY,
      &mut val,
      Some(&mut prt),
      ConvMode::ValueConv,
      0,
      &ctx0(),
    );
    // `-n` bare seconds = 233/15 = 15.5333...
    let d = composite(&val, "Duration").unwrap();
    if let TagValue::F64(x) = d {
      assert!((x - 233.0 / 15.0).abs() < 1e-9, "got {x}");
    } else {
      panic!("expected F64, got {d:?}");
    }
  }
}
