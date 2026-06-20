//! The [`CompositeDef`] model and the registry of ported Composite tags.
//!
//! A [`CompositeDef`] is exifast's transliteration of one `%…::Composite`
//! entry: the `Require` / `Desire` / `Inhibit` index→input map (ExifTool's
//! `AddCompositeTags` form, ExifTool.pm:5763-5840), the derivation that
//! computes the raw value from the resolved inputs (the def's
//! `RawConv`/`ValueConv`), and how that raw value is rendered for the active
//! conversion mode (the def's `PrintConv`).
//!
//! This module registers the three `Duration` composites that the APE / FLAC /
//! AIFF formats used to emit inline (APE.pm:83-92, FLAC.pm:137-149,
//! AIFF.pm:136-145) AND — added by #133 PR 2 — the five stills GPS composites
//! `GPSLatitude` / `GPSLongitude` / `GPSAltitude` / `GPSDateTime` (GPS.pm:355-
//! 432) and `GPSPosition` (Exif.pm:5271). The later #133 PRs add the rest.
//!
//! ## The composite value `$val` — numeric OR string
//!
//! A Composite's `ValueConv`/`RawConv` yields a Perl scalar that may be
//! numeric (the Duration seconds, a GPS decimal degree) OR a string (the
//! `GPSDateTime` `"$datestamp $timestampZ"`, the `GPSPosition` `"$val[0]
//! $val[1]"`). [`CompositeRaw`] models that scalar: [`Num`](CompositeRaw::Num)
//! for a numeric `$val` (rendered to its ValueConv `F64` and fed to a numeric
//! PrintConv such as `ConvertDuration` / `ToDMS`), [`Text`](CompositeRaw::Text)
//! for a string `$val` (rendered to its ValueConv `Str`).
//!
//! ## `$val[i]` (ValueConv) and `$prt[i]` (PrintConv) inputs
//!
//! A Composite's `RawConv`/`ValueConv` reads each input's ValueConv value
//! `$val[i]` (`GetValue($tag, 'ValueConv')`, ExifTool.pm:4112); a Composite's
//! `PrintConv` may ALSO read each input's PrintConv value `$prt[i]`
//! (ExifTool.pm:4116 builds the `@prt` array). `GPSPosition`'s PrintConv is the
//! literal `"$prt[0], $prt[1]"` — the two ingredient Composites' DMS strings —
//! and `GPSAltitude`'s PrintConv reads `$prt[1]` (the `GPSAltitudeRef` PrintConv
//! string). So the engine resolves BOTH a ValueConv view (`$val[i]`) and a
//! PrintConv view (`$prt[i]`) per input and hands BOTH arrays to
//! [`CompositePrintConv::render`].
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

/// A Composite tag's `ValueConv`/`RawConv` result — the Perl scalar `$val` the
/// def derives, which may be NUMERIC (Duration seconds, a GPS decimal degree)
/// or a STRING (`GPSDateTime`'s `"$datestamp $timestampZ"`, `GPSPosition`'s
/// `"$val[0] $val[1]"`). The engine renders it to the sink's ValueConv form
/// (`Num` → `F64`, `Text` → `Str`) and passes it to the def's PrintConv.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CompositeRaw {
  /// A numeric `$val` (e.g. Duration seconds, a signed GPS decimal degree).
  Num(f64),
  /// A string `$val` (e.g. `"2021:08:14 16:45:09Z"`, `"48.85815 2.3489"`).
  Text(std::string::String),
}

impl CompositeRaw {
  /// The numeric `$val` if [`Num`](Self::Num) (for a numeric PrintConv such as
  /// `ConvertDuration` / `ToDMS`); `None` for a [`Text`](Self::Text) raw.
  pub(crate) fn as_num(&self) -> Option<f64> {
    match self {
      CompositeRaw::Num(x) => Some(*x),
      CompositeRaw::Text(_) => None,
    }
  }
}

/// One resolved Composite input, as the engine hands it to a
/// [`CompositeDef::derive`]. The model carries PRESENCE separately from any
/// numeric coercion: ExifTool's `Require`/`Desire`/`Inhibit` resolution keys on
/// whether the ingredient tag was extracted at all (`defined $val[i]`), while
/// each def's RawConv then coerces the RAW value on its own terms (the Duration
/// defs read a number; the GPS / datetime defs read strings — GPS refs
/// `N`/`S`/`E`/`W`, `DateStamp`, `TimeStamp`). So the engine never pre-coerces;
/// it delivers the actual RAW (post-`ValueConv`) [`TagValue`] — the faithful
/// `$val[i]`, independent of the `-j`/`-n` output mode (ExifTool.pm:4112) — and
/// lets the derivation interpret it.
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
  /// The present value as text (`$val[i]` in string context) — a `Str` borrowed
  /// directly, any other present scalar via its textual rendering. `None` when
  /// [`Missing`](Self::Missing). Used by the string-valued GPS defs
  /// (`GPSDateTime`/`GPSPosition`) whose `ValueConv` concatenates `$val[i]`.
  pub(crate) fn as_text(&self) -> Option<std::borrow::Cow<'_, str>> {
    self.value().map(crate::composite::value_text)
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
/// [`TagValue`](crate::value::TagValue) for the active conversion mode. Each
/// variant is given the composite's own `$val` ([`CompositeRaw`]), the resolved
/// input `$val[]` ([`CompositeValue`]) and the input `$prt[]`
/// (`Option<TagValue>`, the PrintConv form, `None` for an absent/`Missing`
/// input) so a PrintConv that reads `$val[i]`/`$prt[i]` (e.g. `GPSPosition`,
/// `GPSAltitude`) renders faithfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositePrintConv {
  /// `PrintConv => 'ConvertDuration($val)'` — the duration format under `-j`,
  /// the bare raw scalar under `-n`, the quoted Perl string for a non-finite
  /// value in both modes ([`crate::composite::convs::duration_value`]).
  ConvertDuration,
  /// `PrintConv => 'Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)'` — the
  /// `Composite:GPSLatitude`/`GPSLongitude` PrintConv. Under `-j` the DMS string
  /// (`48 deg 51' 29.34" N`); under `-n` the bare signed decimal `$val`. The
  /// `char` is the positive-hemisphere letter (`'N'` lat, `'E'` lon).
  GpsCoordinate(char),
  /// `Composite:GPSAltitude` PrintConv (GPS.pm:419-431) — under `-j`
  /// `(int($val[0]*10)/10) . ' m ' . $prt[1]` (e.g. `35 m Above Sea Level`);
  /// under `-n` the bare signed altitude `$val`.
  GpsAltitude,
  /// `Composite:GPSDateTime` PrintConv (`$self->ConvertDateTime($val)`,
  /// GPS.pm:362) — the identity at exifast's option set, in BOTH modes (the
  /// ValueConv string `"$datestamp $timestampZ"`).
  GpsDateTime,
  /// `Composite:GPSPosition` PrintConv (Exif.pm:5314 `"$prt[0], $prt[1]"`) —
  /// under `-j` the two ingredient DMS strings joined by `", "`; under `-n` the
  /// ValueConv string `$val` (`"$val[0] $val[1]"`).
  GpsPosition,
}

impl CompositePrintConv {
  /// Render the composite's value for the active `mode`. `raw` is the def's
  /// `ValueConv` result (`$val`); `vals`/`prts` are the resolved input `$val[]`
  /// / `$prt[]` arrays (for a PrintConv that reads them). The ValueConv (`-n`)
  /// form is `raw` itself (`Num` → `F64`, `Text` → `Str`) EXCEPT where a
  /// non-finite `Num` stringifies (Duration); the PrintConv (`-j`) form runs the
  /// def's PrintConv expression.
  #[cfg(feature = "alloc")]
  pub(crate) fn render(
    self,
    raw: &CompositeRaw,
    vals: &[CompositeValue],
    prts: &[Option<TagValue>],
    mode: crate::emit::ConvMode,
  ) -> TagValue {
    use crate::emit::ConvMode;
    match self {
      CompositePrintConv::ConvertDuration => {
        // Duration's `$val` is always numeric; delegate to the shared
        // finite/non-finite-aware renderer.
        let n = raw.as_num().unwrap_or(f64::NAN);
        crate::composite::convs::duration_value(n, mode)
      }
      CompositePrintConv::GpsCoordinate(ref_pos) => {
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::gps::to_dms(n, ref_pos).into())
          }
        }
      }
      CompositePrintConv::GpsAltitude => {
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => {
            // ExifTool's `foreach (0,2)` PrintConv reads the INPUT altitude
            // `$val[$_]` + ref-print `$prt[$_+1]` (index 0 = GPS pair, 2 = XMP
            // pair). Build both candidates; the composite's own `$val` (`n`)
            // drives the fall-through.
            let alt_text = |i: usize| -> Option<std::borrow::Cow<'_, str>> {
              vals.get(i).and_then(CompositeValue::as_text)
            };
            let ref_text = |i: usize| -> Option<std::borrow::Cow<'_, str>> {
              prts
                .get(i)
                .and_then(Option::as_ref)
                .map(crate::composite::value_text)
            };
            let a0 = alt_text(0);
            let r1 = ref_text(1);
            let a2 = alt_text(2);
            let r3 = ref_text(3);
            let candidates = [
              crate::composite::convs::gps::AltCandidate {
                alt_text: a0.as_deref(),
                ref_print: r1.as_deref(),
              },
              crate::composite::convs::gps::AltCandidate {
                alt_text: a2.as_deref(),
                ref_print: r3.as_deref(),
              },
            ];
            TagValue::Str(crate::composite::convs::gps::gps_altitude_print(n, &candidates).into())
          }
        }
      }
      CompositePrintConv::GpsDateTime => {
        // ValueConv == PrintConv (ConvertDateTime is the identity here).
        let CompositeRaw::Text(s) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => TagValue::Str(s.as_str().into()),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::datetime::convert_date_time(s).into())
          }
        }
      }
      CompositePrintConv::GpsPosition => match mode {
        ConvMode::ValueConv => {
          // `$val` is the ValueConv string `"$val[0] $val[1]"`.
          let CompositeRaw::Text(s) = raw else {
            return TagValue::Str(Default::default());
          };
          TagValue::Str(s.as_str().into())
        }
        ConvMode::PrintConv => {
          // `"$prt[0], $prt[1]"` — the two ingredient Composites' PrintConv
          // (DMS) strings. An undefined `$prt[i]` stringifies as empty.
          let p0 = prts
            .first()
            .and_then(Option::as_ref)
            .map(crate::composite::value_text)
            .unwrap_or(std::borrow::Cow::Borrowed(""));
          let p1 = prts
            .get(1)
            .and_then(Option::as_ref)
            .map(crate::composite::value_text)
            .unwrap_or(std::borrow::Cow::Borrowed(""));
          TagValue::Str(std::format!("{p0}, {p1}").into())
        }
      },
    }
  }
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
  Desire,
  /// `Inhibit` — the composite is SUPPRESSED if this input is present
  /// (ExifTool.pm:4078-4081 `$found = 0; last`).
  #[allow(dead_code)]
  // No Inhibit input among the ported defs yet; used by the engine + oracle tests.
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
/// `&&` guard; the GPS defs read string/decimal ingredients. It returns the
/// composite's raw value [`CompositeRaw`] (`$val`), or `None` to abort the build
/// (ExifTool's `… ? … : undef` guard, e.g. APE.pm:90, the GPSAltitude RawConv).
#[derive(Clone, Copy)]
pub(crate) struct CompositeDef {
  /// The composite tag name (the `-G1` key is `Composite:<name>`).
  pub(crate) name: &'static str,
  /// The inputs in index order (ExifTool `{ 0 => …, 1 => … }`).
  pub(crate) inputs: &'static [CompositeInput],
  /// The def's `RawConv`/`ValueConv` arithmetic over the resolved inputs.
  pub(crate) derive: fn(&[CompositeValue]) -> Option<CompositeRaw>,
  /// The def's `PrintConv`.
  pub(crate) print_conv: CompositePrintConv,
  /// ExifTool `Priority => N` (default `1`). `GPSPosition` is `Priority => 0`
  /// (never overrides a duplicate); the others use the default `1`. Threaded
  /// into [`crate::tagmap::TagMap`]'s duplicate-override rule on append.
  pub(crate) priority: u8,
  /// The prefixed-id sort key (ExifTool's `Module-Name`, AddCompositeTags
  /// `$prefix . $tagID`). The build order sorts by this so the registry is
  /// position-independent and the fixpoint is deterministic.
  pub(crate) sort_key: &'static str,
}

/// `Require`d input on the `{APE, MAC}` family-1 group set (the APE MAC header
/// carries family-1 `MAC` but family-0 `APE`, so it satisfies `APE:`).
#[cfg(feature = "ape")]
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

/// `Desire`d input on a single family-1 group `group`.
const fn des(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Desire,
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
#[cfg(feature = "ape")]
fn ape_duration(v: &[CompositeValue]) -> Option<CompositeRaw> {
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
  Some(CompositeRaw::Num(((tf - 1.0) * bpf + ffb) / sr))
}

/// FLAC.pm:147 `($val[0] and $val[1]) ? $val[1] / $val[0] : undef`.
/// `$val[0]`=SampleRate, `[1]`=TotalSamples. The `and` guard is Perl-truthy on
/// the RAW ingredients (string-truthy), then the arithmetic coerces numeric.
#[cfg(feature = "flac")]
fn flac_duration(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let sr_raw = v.first()?;
  let total_raw = v.get(1)?;
  if !sr_raw.is_truthy() || !total_raw.is_truthy() {
    return None;
  }
  Some(CompositeRaw::Num(
    total_raw.coerce_numeric()? / sr_raw.coerce_numeric()?,
  ))
}

/// AIFF.pm:143 `($val[0] and $val[1]) ? $val[1] / $val[0] : undef`.
/// `$val[0]`=SampleRate, `[1]`=NumSampleFrames. The `and` guard is Perl-truthy
/// on the RAW ingredients (string-truthy), then the arithmetic coerces numeric.
#[cfg(feature = "aiff")]
fn aiff_duration(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let sr_raw = v.first()?;
  let frames_raw = v.get(1)?;
  if !sr_raw.is_truthy() || !frames_raw.is_truthy() {
    return None;
  }
  Some(CompositeRaw::Num(
    frames_raw.coerce_numeric()? / sr_raw.coerce_numeric()?,
  ))
}

/// `Composite:GPSLatitude` ValueConv (GPS.pm:367) `$val[1] =~ /^S/i ? -$val[0] :
/// $val[0]`. `$val[0]`=GPS:GPSLatitude (decimal degrees), `[1]`=GPSLatitudeRef
/// (`"N"`/`"S"`). The ref is case-insensitively `^S` ⇒ negate.
#[cfg(feature = "exif")]
fn gps_latitude(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let lat = v.first()?.coerce_numeric()?;
  let ref_s = v.get(1)?.as_text()?;
  Some(CompositeRaw::Num(if ref_starts_with(&ref_s, b'S') {
    -lat
  } else {
    lat
  }))
}

/// `Composite:GPSLongitude` ValueConv (GPS.pm:399) `$val[1] =~ /^W/i ? -$val[0]
/// : $val[0]`.
#[cfg(feature = "exif")]
fn gps_longitude(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let lon = v.first()?.coerce_numeric()?;
  let ref_s = v.get(1)?.as_text()?;
  Some(CompositeRaw::Num(if ref_starts_with(&ref_s, b'W') {
    -lon
  } else {
    lon
  }))
}

/// `Composite:GPSAltitude` RawConv + ValueConv (GPS.pm:412-418). The RawConv
/// `(defined $val[1] or defined $val[3]) ? $val : undef` requires an altitude
/// ref; the ValueConv `foreach (0,2) { next unless defined $val[$_] and
/// IsFloat($val[$_]) and defined $val[$_+1]; return $val[$_+1] ? -abs($val[$_])
/// : $val[$_] } return undef`. Inputs: 0=GPS:GPSAltitude, 1=GPS:GPSAltitudeRef,
/// 2=XMP:GPSAltitude, 3=XMP:GPSAltitudeRef.
#[cfg(feature = "exif")]
fn gps_altitude(v: &[CompositeValue]) -> Option<CompositeRaw> {
  // RawConv: require a ref (`$val[1]` OR `$val[3]` defined).
  let have_ref = v.get(1).is_some_and(CompositeValue::is_present)
    || v.get(3).is_some_and(CompositeValue::is_present);
  if !have_ref {
    return None;
  }
  // ValueConv `foreach (0, 2)`: the first index whose altitude is present + a
  // float AND whose ref is present yields `$ref ? -abs($alt) : $alt`.
  for base in [0usize, 2usize] {
    let Some(alt_cv) = v.get(base) else { continue };
    let Some(alt_text) = alt_cv.as_text() else {
      continue;
    };
    // `IsFloat($val[$_])` both guards AND translates `,`→`.` in place; the
    // subsequent `-abs($val[$_])` / `$val[$_]` coerces the NORMALIZED scalar
    // (e.g. `12,5` → `12.5`), so coerce the normalized string, not the raw.
    let Some(alt_norm) = crate::convert::is_float_norm(&alt_text) else {
      continue;
    };
    let Some(ref_cv) = v.get(base + 1) else {
      continue;
    };
    if !ref_cv.is_present() {
      continue;
    }
    let alt = crate::convert::perl_str_to_f64(&alt_norm);
    // `$val[$_+1] ? -abs(...) : ...` — Perl-boolean on the raw ref value.
    return Some(CompositeRaw::Num(if ref_cv.is_truthy() {
      -alt.abs()
    } else {
      alt
    }));
  }
  None
}

/// `Composite:GPSDateTime` ValueConv (GPS.pm:361) `"$val[0] $val[1]Z"`.
/// `$val[0]`=GPS:GPSDateStamp, `[1]`=GPS:GPSTimeStamp (both ValueConv strings).
#[cfg(feature = "exif")]
fn gps_datetime(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let date = v.first()?.as_text()?;
  let time = v.get(1)?.as_text()?;
  Some(CompositeRaw::Text(std::format!("{date} {time}Z")))
}

/// `Composite:GPSPosition` ValueConv (Exif.pm:5313) `(length($val[0]) or
/// length($val[1])) ? "$val[0] $val[1]" : undef`. `$val[0]`=Composite:GPSLatitude
/// (decimal), `[1]`=Composite:GPSLongitude (decimal) — both string-context.
#[cfg(feature = "exif")]
fn gps_position(v: &[CompositeValue]) -> Option<CompositeRaw> {
  let lat = v
    .first()
    .and_then(CompositeValue::as_text)
    .unwrap_or(std::borrow::Cow::Borrowed(""));
  let lon = v
    .get(1)
    .and_then(CompositeValue::as_text)
    .unwrap_or(std::borrow::Cow::Borrowed(""));
  // `(length($val[0]) or length($val[1]))` — at least one non-empty.
  if lat.is_empty() && lon.is_empty() {
    return None;
  }
  Some(CompositeRaw::Text(std::format!("{lat} {lon}")))
}

/// `$ref =~ /^<C>/i` — does the ref string start (case-insensitively) with the
/// ASCII letter `c` (`b'S'` for latitude, `b'W'` for longitude)? The GPS refs
/// are `"N"`/`"S"`/`"E"`/`"W"` (ValueConv form), so only the first byte matters.
#[cfg(feature = "exif")]
fn ref_starts_with(s: &str, c: u8) -> bool {
  s.as_bytes()
    .first()
    .is_some_and(|b| b.eq_ignore_ascii_case(&c))
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
  priority: 1,
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
  priority: 1,
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
  priority: 1,
  sort_key: "AIFF-Duration",
};

/// `Composite:GPSLatitude` (GPS.pm:368). Group2 `Location`. The composite name
/// matches the GPS-main `GPSLatitude`, but resolves from `GPS:GPSLatitude` (the
/// decimal-degrees ValueConv) — the family-1 `GPS` group keeps them distinct.
#[cfg(feature = "exif")]
const GPS_LATITUDE: CompositeDef = CompositeDef {
  name: "GPSLatitude",
  inputs: &[
    req(&["GPS"], "GPSLatitude"),
    req(&["GPS"], "GPSLatitudeRef"),
  ],
  derive: gps_latitude,
  print_conv: CompositePrintConv::GpsCoordinate('N'),
  priority: 1, // GPS.pm: Avoid sets Priority 0, then `Priority => 1` restores it.
  sort_key: "GPS-GPSLatitude",
};

/// `Composite:GPSLongitude` (GPS.pm:385). Group2 `Location`.
#[cfg(feature = "exif")]
const GPS_LONGITUDE: CompositeDef = CompositeDef {
  name: "GPSLongitude",
  inputs: &[
    req(&["GPS"], "GPSLongitude"),
    req(&["GPS"], "GPSLongitudeRef"),
  ],
  derive: gps_longitude,
  print_conv: CompositePrintConv::GpsCoordinate('E'),
  priority: 1,
  sort_key: "GPS-GPSLongitude",
};

/// `Composite:GPSAltitude` (GPS.pm:406). Group2 `Location`. `Desire`s the GPS +
/// XMP altitude/ref pairs; the RawConv requires an altitude ref.
#[cfg(feature = "exif")]
const GPS_ALTITUDE: CompositeDef = CompositeDef {
  name: "GPSAltitude",
  inputs: &[
    des(&["GPS"], "GPSAltitude"),
    des(&["GPS"], "GPSAltitudeRef"),
    des(&["XMP-exif"], "GPSAltitude"),
    des(&["XMP-exif"], "GPSAltitudeRef"),
  ],
  derive: gps_altitude,
  print_conv: CompositePrintConv::GpsAltitude,
  priority: 1,
  sort_key: "GPS-GPSAltitude",
};

/// `Composite:GPSDateTime` (GPS.pm:355). Group2 `Time`.
#[cfg(feature = "exif")]
const GPS_DATETIME: CompositeDef = CompositeDef {
  name: "GPSDateTime",
  inputs: &[req(&["GPS"], "GPSDateStamp"), req(&["GPS"], "GPSTimeStamp")],
  derive: gps_datetime,
  print_conv: CompositePrintConv::GpsDateTime,
  priority: 1,
  sort_key: "GPS-GPSDateTime",
};

/// `Composite:GPSPosition` (Exif.pm:5271). Group2 `Location`. Composite-on-
/// composite: `Require`s `Composite:GPSLatitude` + `Composite:GPSLongitude`
/// (exercises the fixpoint deferral). `Priority => 0` (never overrides).
#[cfg(feature = "exif")]
const GPS_POSITION: CompositeDef = CompositeDef {
  name: "GPSPosition",
  inputs: &[
    req(&["Composite"], "GPSLatitude"),
    req(&["Composite"], "GPSLongitude"),
  ],
  derive: gps_position,
  print_conv: CompositePrintConv::GpsPosition,
  priority: 0,
  // Exif.pm's prefix is `Composite` (Exif::Composite uses the default `Image-
  // ExifTool` prefix → `Composite-GPSPosition`). The cross-module GPS defs sort
  // before it (`GPS-…`), so `Composite-GPSLatitude/Longitude` are built first.
  sort_key: "Composite-GPSPosition",
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
  #[cfg(feature = "exif")]
  GPS_LATITUDE,
  #[cfg(feature = "exif")]
  GPS_LONGITUDE,
  #[cfg(feature = "exif")]
  GPS_ALTITUDE,
  #[cfg(feature = "exif")]
  GPS_DATETIME,
  #[cfg(feature = "exif")]
  GPS_POSITION,
];
