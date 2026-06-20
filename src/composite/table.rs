//! The [`CompositeDef`] model and the registry of ported Composite tags.
//!
//! A [`CompositeDef`] is exifast's transliteration of one `%…::Composite`
//! entry: the `Require` / `Desire` / `Inhibit` index→input map (ExifTool's
//! `AddCompositeTags` form, ExifTool.pm:5763-5840), the derivation that
//! computes the raw value from the resolved inputs (the def's
//! `RawConv`/`ValueConv`), and how that raw value is rendered for the active
//! conversion mode (the def's `PrintConv`).
//!
//! This PR registers ONLY the three `Duration` composites that the APE / FLAC /
//! AIFF formats used to emit inline (APE.pm:83-92, FLAC.pm:137-149,
//! AIFF.pm:136-145). No new composites are introduced; the cross-format sweep
//! (#133) adds the rest in later PRs.
//!
//! ## Input-group matching (the `APE:` ≡ `MAC:` subtlety)
//!
//! ExifTool's `Require => 'APE:SampleRate'` resolves via `GroupMatches('APE',
//! …)`, which matches a stored tag whose group in ANY family equals `APE`. The
//! APE MAC header table is `GROUPS => { 0 => 'APE', 1 => 'MAC' }`, so its
//! `MAC:SampleRate` (family-1 `MAC`) still satisfies `APE:SampleRate` through
//! its family-0 `APE`. exifast's [`TagMap`](crate::tagmap::TagMap) keys only on
//! family-1, so a [`CompositeInput`] carries the SET of family-1 groups that
//! map to the requested ExifTool group — `{APE, MAC}` for the APE inputs — and
//! the resolver takes the LAST-emitted match across that set (faithful to
//! ExifTool walking the duplicate keys in reverse precedence; the
//! `APE_dup_override` golden has `MAC:SampleRate=44100` then `APE:SampleRate=
//! 48000` and `Duration` must use `48000`).

use crate::value::TagValue;

/// One resolved Composite input, as the engine hands it to a
/// [`CompositeDef::derive`]. The model carries PRESENCE separately from any
/// numeric coercion: ExifTool's `Require`/`Desire`/`Inhibit` resolution keys on
/// whether the ingredient tag was extracted at all (`defined $val[i]`), while
/// each def's RawConv then coerces the RAW value on its own terms (the Duration
/// defs read a number; the GPS / EXIF / datetime defs added by later #133 PRs
/// read strings — GPS refs `N`/`S`/`E`/`W`, `DateStamp`, `TimeStamp`). So the
/// engine never pre-coerces; it delivers the actual RAW (post-`ValueConv`)
/// [`TagValue`] — the faithful `$val[i]`, independent of the `-j`/`-n` output
/// mode (ExifTool.pm:4112) — and lets the derivation interpret it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CompositeValue {
  /// The ingredient tag was not extracted (`!defined $val[i]`) — an absent
  /// `Desire`/`Inhibit` leaves this `undef` element; an absent `Require` aborts.
  Missing,
  /// The ingredient tag IS present, carrying its RAW (post-`ValueConv`) value
  /// (numeric OR string) — the same `$val[i]` ExifTool reads regardless of the
  /// output mode. A present `Inhibit` of ANY value suppresses the composite.
  Present(TagValue),
}

impl CompositeValue {
  /// `defined $val[i]` — the ingredient was extracted (ExifTool keys
  /// `Require`/`Desire`/`Inhibit` resolution on this, NOT on coercibility).
  pub(crate) const fn is_present(&self) -> bool {
    matches!(self, CompositeValue::Present(_))
  }
  /// The raw [`TagValue`] when present (for the def's own RawConv coercion).
  pub(crate) const fn value(&self) -> Option<&TagValue> {
    match self {
      CompositeValue::Present(v) => Some(v),
      CompositeValue::Missing => None,
    }
  }
  /// Perl numeric coercion (`0 + $val`) of a PRESENT value: integers and
  /// finite/non-finite floats pass through; a numeric STRING (incl.
  /// `"Inf"`/`"NaN"`) is parsed with the faithful leading-prefix scan; a
  /// present-but-otherwise-nonnumeric value or [`Missing`](Self::Missing) ⇒
  /// `None` (the def's `... ? ... : undef` guard then fires).
  pub(crate) fn coerce_numeric(&self) -> Option<f64> {
    match self.value()? {
      TagValue::I64(n) => Some(*n as f64),
      TagValue::U64(n) => Some(*n as f64),
      TagValue::F64(x) => Some(*x),
      TagValue::Str(s) => Some(crate::convert::perl_str_to_f64(s)),
      _ => None,
    }
  }
  /// Perl boolean context (`if ($val[i]`) on the RAW present value — the
  /// `($val[0] && $val[1])`-style RawConv guard. A wire-format string `"0.0"`
  /// is TRUTHY here (unlike its numeric coercion `0.0`); a [`Missing`](Self::
  /// Missing) element is falsy (`!defined` ⇒ false).
  pub(crate) fn is_truthy(&self) -> bool {
    self
      .value()
      .is_some_and(crate::convert::perl_boolean_truthy)
  }
}

/// How a [`CompositeDef`] turns its resolved raw value into the stored
/// [`TagValue`](crate::value::TagValue) for the active conversion mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositePrintConv {
  /// `PrintConv => 'ConvertDuration($val)'` — the duration format under `-j`,
  /// the bare raw scalar under `-n`, the quoted Perl string for a non-finite
  /// value in both modes ([`crate::composite::convs::duration_value`]).
  ConvertDuration,
}

/// One `Require` / `Desire` / `Inhibit` input of a [`CompositeDef`], at a fixed
/// index (ExifTool's `{ 0 => …, 1 => … }` hash position).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CompositeInput {
  /// Whether this input is required (missing ⇒ the whole composite is skipped),
  /// desired (missing ⇒ an `undef` element, the composite may still build), or
  /// an inhibitor (present ⇒ the composite is suppressed).
  pub(crate) kind: InputKind,
  /// The family-1 group(s) a stored tag may carry to satisfy this input. A
  /// single ExifTool `Group:Name` requirement expands to every exifast family-1
  /// group that shares the ExifTool family-0 group (see the module note); a
  /// bare-name requirement uses an empty slice (matches any group).
  pub(crate) groups: &'static [&'static str],
  /// The tag name to resolve (e.g. `"SampleRate"`).
  pub(crate) name: &'static str,
}

/// The role of a [`CompositeInput`] (ExifTool `Require` / `Desire` / `Inhibit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputKind {
  /// `Require` — the composite is NOT built if this input is missing
  /// (ExifTool.pm:4084-4087 `$found = 0; last`).
  Require,
  /// `Desire` — the composite may still build if this input is missing (the
  /// element is left `undef`).
  #[allow(dead_code)] // No Desire-only Duration input yet; used by the engine + oracle tests.
  Desire,
  /// `Inhibit` — the composite is SUPPRESSED if this input is present
  /// (ExifTool.pm:4078-4081 `$found = 0; last`).
  #[allow(dead_code)] // No Inhibit Duration input yet; used by the engine + oracle tests.
  Inhibit,
}

impl InputKind {
  /// `true` for [`Require`](Self::Require).
  pub(crate) const fn is_require(self) -> bool {
    matches!(self, InputKind::Require)
  }
  /// `true` for [`Inhibit`](Self::Inhibit).
  pub(crate) const fn is_inhibit(self) -> bool {
    matches!(self, InputKind::Inhibit)
  }
}

/// A ported Composite tag: the inputs (index = slice position), the derivation
/// that computes the raw value, and the print-conversion.
///
/// `derive` receives the resolved inputs by index as [`CompositeValue`]s
/// (`Present(value)` carrying the raw [`TagValue`] when the ingredient was
/// extracted, `Missing` when an absent `Desire`/`Inhibit`) and performs ITS OWN
/// Perl coercion — the Duration defs coerce numeric + apply the Perl-truthy
/// `&&` guard; future GPS / EXIF defs read string ingredients. It returns the
/// raw composite value, or `None` to abort the build (ExifTool's
/// `… ? … : undef` guard, e.g. APE.pm:90 `($val[0] && $val[1]) ? … : undef`).
#[derive(Clone, Copy)]
pub(crate) struct CompositeDef {
  /// The composite tag name (the `-G1` key is `Composite:<name>`).
  pub(crate) name: &'static str,
  /// The inputs in index order (ExifTool `{ 0 => …, 1 => … }`).
  pub(crate) inputs: &'static [CompositeInput],
  /// The def's `RawConv`/`ValueConv` arithmetic over the resolved inputs.
  pub(crate) derive: fn(&[CompositeValue]) -> Option<f64>,
  /// The def's `PrintConv`.
  pub(crate) print_conv: CompositePrintConv,
  /// The prefixed-id sort key (ExifTool's `Module-Name`, AddCompositeTags
  /// `$prefix . $tagID`). The build order sorts by this so the registry is
  /// position-independent and the fixpoint is deterministic.
  pub(crate) sort_key: &'static str,
}

/// `Require`d input on the `{APE, MAC}` family-1 group set (the APE MAC header
/// carries family-1 `MAC` but family-0 `APE`, so it satisfies `APE:`).
const fn ape_req(name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: &["APE", "MAC"],
    name,
  }
}

/// `Require`d input on a single family-1 group `group` (a `&'static` one-element
/// slice supplied by the caller, e.g. `&["FLAC"]`).
const fn req(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: group,
    name,
  }
}

/// APE.pm:90 `($val[0] && $val[1]) ? (($val[1] - 1) * $val[2] + $val[3]) / $val[0] : undef`.
/// `$val[0]`=SampleRate, `[1]`=TotalFrames, `[2]`=BlocksPerFrame, `[3]`=FinalFrameBlocks.
///
/// The `&&` guard is Perl-truthy on the RAW ingredient (APE main tags can supply
/// `SampleRate`/`TotalFrames` as MakeTag STRINGS — a string `"0.0"`/`"0E0"` is
/// Perl-TRUTHY, so it passes the guard and computes; only `""`, `"0"`, undef and
/// a numeric/`Bytes` zero are falsy). The arithmetic itself then coerces every
/// ingredient via Perl numeric coercion.
fn ape_duration(v: &[CompositeValue]) -> Option<f64> {
  let sr_raw = v.first()?;
  let tf_raw = v.get(1)?;
  // `$val[0] && $val[1]` — Perl-boolean on the RAW values (string-truthy).
  if !sr_raw.is_truthy() || !tf_raw.is_truthy() {
    return None;
  }
  let sr = sr_raw.coerce_numeric()?;
  let tf = tf_raw.coerce_numeric()?;
  let bpf = v.get(2)?.coerce_numeric()?;
  let ffb = v.get(3)?.coerce_numeric()?;
  Some(((tf - 1.0) * bpf + ffb) / sr)
}

/// FLAC.pm:147 `($val[0] and $val[1]) ? $val[1] / $val[0] : undef`.
/// `$val[0]`=SampleRate, `[1]`=TotalSamples. The `and` guard is Perl-truthy on
/// the RAW ingredients (string-truthy), then the arithmetic coerces numeric.
fn flac_duration(v: &[CompositeValue]) -> Option<f64> {
  let sr_raw = v.first()?;
  let total_raw = v.get(1)?;
  if !sr_raw.is_truthy() || !total_raw.is_truthy() {
    return None;
  }
  Some(total_raw.coerce_numeric()? / sr_raw.coerce_numeric()?)
}

/// AIFF.pm:143 `($val[0] and $val[1]) ? $val[1] / $val[0] : undef`.
/// `$val[0]`=SampleRate, `[1]`=NumSampleFrames. The `and` guard is Perl-truthy
/// on the RAW ingredients (string-truthy), then the arithmetic coerces numeric.
fn aiff_duration(v: &[CompositeValue]) -> Option<f64> {
  let sr_raw = v.first()?;
  let frames_raw = v.get(1)?;
  if !sr_raw.is_truthy() || !frames_raw.is_truthy() {
    return None;
  }
  Some(frames_raw.coerce_numeric()? / sr_raw.coerce_numeric()?)
}

/// APE `Duration` (APE.pm:83-92). Registered only when the `ape` feature is on.
#[cfg(feature = "ape")]
const APE_DURATION: CompositeDef = CompositeDef {
  name: "Duration",
  inputs: &[
    ape_req("SampleRate"),
    ape_req("TotalFrames"),
    ape_req("BlocksPerFrame"),
    ape_req("FinalFrameBlocks"),
  ],
  derive: ape_duration,
  print_conv: CompositePrintConv::ConvertDuration,
  sort_key: "APE-Duration",
};

/// FLAC `Duration` (FLAC.pm:137-149). Registered only when the `flac` feature
/// is on.
#[cfg(feature = "flac")]
const FLAC_DURATION: CompositeDef = CompositeDef {
  name: "Duration",
  inputs: &[req(&["FLAC"], "SampleRate"), req(&["FLAC"], "TotalSamples")],
  derive: flac_duration,
  print_conv: CompositePrintConv::ConvertDuration,
  sort_key: "FLAC-Duration",
};

/// AIFF `Duration` (AIFF.pm:136-145). Registered only when the `aiff` feature
/// is on.
#[cfg(feature = "aiff")]
const AIFF_DURATION: CompositeDef = CompositeDef {
  name: "Duration",
  inputs: &[
    req(&["AIFF"], "SampleRate"),
    req(&["AIFF"], "NumSampleFrames"),
  ],
  derive: aiff_duration,
  print_conv: CompositePrintConv::ConvertDuration,
  sort_key: "AIFF-Duration",
};

/// The full registry of ported Composite defs, cfg-gated per input format. The
/// engine sorts a working copy by [`CompositeDef::sort_key`] (ExifTool's
/// prefixed-id order) before the fixpoint, so this declaration order is
/// irrelevant.
pub(crate) const REGISTRY: &[CompositeDef] = &[
  #[cfg(feature = "ape")]
  APE_DURATION,
  #[cfg(feature = "flac")]
  FLAC_DURATION,
  #[cfg(feature = "aiff")]
  AIFF_DURATION,
];
