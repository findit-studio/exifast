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

/// Format-state scalars the post-pass threads into the derivations that read
/// ExifTool object state instead of (only) their declared `Require`/`Desire`
/// inputs — the `$$self{…}` reads inside a Composite's RawConv/ValueConv.
///
/// `Composite:AvgBitrate` (QuickTime.pm:8649) divides its `Duration` input by
/// `$$self{TimeScale}` and reads the SUM of every `MediaDataSize` (the
/// `NextTagKey` loop) — neither is a plain resolved input (the dedup-collapsing
/// `TagMap` keeps only one `MediaDataSize`, and `TimeScale` is the movie scalar,
/// not the per-input value). `Composite:Rotation` (QuickTime.pm:8646) calls
/// `CalcRotation($self)`, which scans the WHOLE emitted tag set for the `vide`
/// HandlerType track's MatrixStructure — a pure function of the final tags,
/// pre-computed once by the caller. exifast threads all three as context rather
/// than reaching back into the (being-mutated) sink from inside a derive.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CompositeContext {
  /// The SUM of every `mdat` payload size (`AvgBitrate`'s `$val[0]` after the
  /// `NextTagKey` loop, QuickTime.pm:8654-8660). `None` ⇒ no `mdat`.
  pub(crate) media_data_total: Option<u64>,
  /// The pre-computed `CalcRotation($self)` result (QuickTime.pm:8797) — the
  /// `vide`-track rotation angle in degrees, or `None` when there is no video
  /// track / matrix (then `Composite:Rotation`'s ValueConv is `undef`).
  pub(crate) rotation: Option<f64>,
}

impl CompositeContext {
  /// A context from the two pre-extracted scalars (the summed `MediaDataSize`
  /// total for `AvgBitrate`, and the pre-computed `CalcRotation` angle). The
  /// non-QuickTime / no-`mdat` / no-video cases pass `None`s. (`AvgBitrate` does
  /// NOT divide by `$$self{TimeScale}` — see [`avg_bitrate`] — so the TimeScale
  /// is not threaded.)
  #[cfg(feature = "alloc")]
  pub(crate) const fn new(media_data_total: Option<u64>, rotation: Option<f64>) -> Self {
    Self {
      media_data_total,
      rotation,
    }
  }
}

/// A Composite def's `SubDoc` flag (ExifTool `SubDoc => 1` / `SubDoc => [1,3]`,
/// GPS.pm:357 / 408). A SubDoc def is built once at Main (`DOC_NUM` 0) AND once
/// per sub-document `Doc<N>` (ExifTool.pm:4001-4147), each resolving its inputs
/// within that document's family-3 group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubDoc {
  /// Not a SubDoc def — built at the Main document only (every non-GPS def, plus
  /// `GPSPosition`, which is `Main`-only — Exif.pm:5271 has no `SubDoc`).
  No,
  /// `SubDoc => 1` — built for ALL sub-documents (`GPSLatitude`/`GPSLongitude`/
  /// `GPSDateTime`). The per-document `for (;;)` loop attempts every `Doc<N>`
  /// once at least one `Require`d input exists in that document.
  All,
  /// `SubDoc => [1,3]` (`GPSAltitude`, GPS.pm:408) — built per sub-document only
  /// when one of the listed (1-based) `Desire` indices has a chance to exist.
  /// The probe set; the indices select which `Desire`s gate the per-doc attempt.
  Indices(&'static [usize]),
}

impl SubDoc {
  /// Does this def build per sub-document at all?
  pub(crate) const fn is_sub_doc(self) -> bool {
    !matches!(self, SubDoc::No)
  }
}

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
  /// A `$val` that is a SELECTED ingredient scalar passed through UNCHANGED —
  /// `Composite:ShutterSpeed`/`Aperture` (Exif.pm:4778/4789) whose ValueConv
  /// merely PICKS one of its operands (`($val[2] and $val[2]>0) ? $val[2] :
  /// (defined($val[0]) ? $val[0] : $val[1])`, `$val[0] || $val[1]`) and hands
  /// it to `PrintExposureTime`/`PrintFNumber`. Those helpers return the operand
  /// VERBATIM when `IsFloat` fails (Exif.pm:5704/5719), so a present-but-non-
  /// float ingredient (a zero-denominator rational that ValueConv'd to
  /// `"undef"`, or any non-`IsFloat` text) must reach the PrintConv as its
  /// ORIGINAL [`TagValue`] — NOT numerically coerced to `0`. Carrying the raw
  /// scalar (rather than an `f64`) preserves the genuinely-numeric path
  /// byte-identically (a numeric ingredient is an `F64`/`I64`/`U64` ⇒ same
  /// `-n` number, same `IsFloat`-formatted `-j`) while making the non-float
  /// edge a faithful passthrough.
  Scalar(TagValue),
}

impl CompositeRaw {
  /// The numeric `$val` if [`Num`](Self::Num) (for a numeric PrintConv such as
  /// `ConvertDuration` / `ToDMS`); `None` otherwise.
  pub(crate) fn as_num(&self) -> Option<f64> {
    match self {
      CompositeRaw::Num(x) => Some(*x),
      CompositeRaw::Text(_) | CompositeRaw::Scalar(_) => None,
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
      // A `Rational` ingredient's ValueConv value IS its ExifTool ValueConv
      // STRING — the `%g`-rounded quotient for a finite rational, or the literal
      // `"inf"`/`"undef"` for a zero denominator (`Rational::exiftool_val_str`,
      // ExifTool's `GetRational`). Coercing THAT (not the raw `num/den`) keeps a
      // Sony rtmd `ExposureTime` kept as `Rational(1/60)` reading `0.01666…`
      // while a zero-denominator `ExposureTime` reads the faithful `"undef"`/
      // `"inf"` Perl-numeric coercion (NOT a raw `NaN`/`inf` divide).
      TagValue::Rational(r) => Some(crate::convert::perl_str_to_f64(&r.exiftool_val_str())),
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
  /// The SELECTED operand as a passthrough scalar for `Composite:ShutterSpeed`/
  /// `Aperture` — the raw [`TagValue`] cloned, but ONLY for an operand the prior
  /// `coerce_numeric` path would have BUILT from (a numeric scalar OR a
  /// [`Str`](TagValue::Str)). A non-coercible operand (a [`Rational`](TagValue::
  /// Rational) / [`Bytes`](TagValue::Bytes) / [`Bool`](TagValue::Bool)) yields
  /// `None`, so the def returns `None` and the composite is NOT built — exactly
  /// the build-vs-suppress decision the pre-passthrough `coerce_numeric()?`
  /// produced (`coerce_numeric` returns `None` only for those non-scalar
  /// shapes). This keeps every current golden byte-identical: a numeric operand
  /// renders the same number, and the ONLY behavior change is that a present
  /// non-`IsFloat` STRING operand (a zero-denominator rational that ValueConv'd
  /// to `"undef"`) is now carried through (the passthrough fix) instead of being
  /// coerced to `0`. Restricting to `coerce_numeric`-eligible operands (rather
  /// than every present value) deliberately leaves a raw [`Rational`](TagValue::
  /// Rational)-shaped operand suppressed (no current golden exercises a
  /// `Rational`-valued `FNumber`/`ExposureTime` reaching the selection; the EXIF
  /// rational tags ValueConv to a numeric scalar before the post-pass reads
  /// them). The bare-name group precedence (ExifTool picks the priority-directory
  /// `EXIF:FNumber` over a later `Samsung:FNumber`) IS honoured — the engine's
  /// bare-name resolver takes the FIRST-emitted match (see
  /// [`crate::composite::CompositeSink::resolve`]), so `SamsungNX500.srw`'s
  /// `Composite:Aperture`/`ShutterSpeed` resolve to the EXIF operands and build
  /// byte-identically.
  pub(crate) fn selected_scalar(&self) -> Option<TagValue> {
    let v = self.value()?;
    // The selected operand is handed on as its VALUECONV value. For an
    // already-ValueConv'd scalar (numeric / `Str`) that IS the stored value, so
    // it passes through verbatim. A raw `Rational` (a Sony rtmd `ExposureTime`
    // kept as `Rational(1/60)` at `-n`) is handed on as its ExifTool ValueConv:
    // a FINITE rational becomes its `num/den` FLOAT (so the `-n`
    // `Composite:ShutterSpeed` is the seconds number matching bundled
    // `0.01666…`, AND a dependent `LightValue` reads the seconds float, not the
    // `"1/60"` rational text); a ZERO-DENOMINATOR rational becomes its
    // `"undef"`/`"inf"` ValueConv STRING (`Rational::exiftool_val_str`), which
    // `PrintExposureTime`/`PrintFNumber` pass through verbatim (matching bundled
    // `Composite:ShutterSpeed "undef"`, not a raw `NaN`).
    match v {
      TagValue::Rational(r) => Some(if r.denominator() == 0 {
        TagValue::Str(r.exiftool_val_str().into())
      } else {
        TagValue::F64(r.numerator() as f64 / r.denominator() as f64)
      }),
      _ => self.coerce_numeric().map(|_| v.clone()),
    }
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
  /// `Composite:ImageSize` PrintConv (Exif.pm:4766 `$val =~ tr/ /x/; $val`) —
  /// the ValueConv string `$val` (a `Text` raw `"W H"`) with its single space
  /// replaced by `x` under `-j` (`"8x8"`); the bare space-joined `$val` under
  /// `-n` (`"8 8"`).
  ImageSize,
  /// `Composite:Megapixels` PrintConv (Exif.pm:4769 `sprintf("%.*f",
  /// ($val >= 1 ? 1 : ($val >= 0.001 ? 3 : 6)), $val)`) — a magnitude-dependent
  /// fixed-decimal string under `-j` (`>= 1` ⇒ 1 dp, `>= 0.001` ⇒ 3 dp, else
  /// 6 dp); the bare numeric `$val` under `-n`.
  Megapixels,
  /// `Composite:ShutterSpeed` PrintConv (`Image::ExifTool::Exif::
  /// PrintExposureTime($val)`, Exif.pm:4779) — the `1/N` fraction / decimal
  /// string under `-j`; the bare numeric `$val` (seconds) under `-n`.
  ShutterSpeed,
  /// `Composite:Aperture` PrintConv (`Image::ExifTool::Exif::PrintFNumber($val)`,
  /// Exif.pm:4790) — the 1-or-2-decimal f-number string under `-j`; the bare
  /// numeric `$val` under `-n`.
  Aperture,
  /// The shared `%subSecConv` PrintConv (`$self->ConvertDateTime($val)`,
  /// Exif.pm:4740) for `Composite:SubSecDateTimeOriginal`/`SubSecCreateDate`/
  /// `SubSecModifyDate` — the identity at exifast's option set, in BOTH modes
  /// (the RawConv-assembled `Text` string).
  SubSecDateTime,
  /// `Composite:ScaleFactor35efl` PrintConv (`sprintf("%.1f", $val)`,
  /// Exif.pm:4843) — the 1-decimal string under `-j` (emitted as a BARE JSON
  /// number by the `EscapeJSON` gate, e.g. `4.4`); the bare numeric `$val`
  /// (full precision, e.g. `4.3956043956044`) under `-n`.
  ScaleFactor35efl,
  /// `Composite:FocalLength35efl` PrintConv (Exif.pm:4815) — `$val[1] ?
  /// sprintf("%.1f mm (35 mm equivalent: %.1f mm)", $val[0], $val) :
  /// sprintf("%.1f mm", $val)`. Reads `$val[0]` (FocalLength) and `$val[1]`
  /// (`Composite:ScaleFactor35efl`); the `-n` form is the bare numeric `$val`
  /// (the 35mm-equiv, e.g. `75`).
  FocalLength35efl,
  /// `Composite:CircleOfConfusion` PrintConv (`sprintf("%.3f mm", $val)`,
  /// Exif.pm:4853) — the 3-decimal `"… mm"` string under `-j`; the bare numeric
  /// `$val` under `-n` (which the `EscapeJSON` gate quotes when its `%.15g`
  /// rendering exceeds the 16-fraction-digit cap, e.g. `"0.00683552429306715"`).
  CircleOfConfusion,
  /// `Composite:HyperfocalDistance` PrintConv (`sprintf("%.2f m", $val)`,
  /// Exif.pm:4868) — the 2-decimal `"… m"` string under `-j`; the bare numeric
  /// `$val` under `-n`. When the ValueConv returned the literal `'inf'` (a
  /// `Text` raw), `-n` emits the string `"inf"` and `-j` emits `"Inf m"`.
  HyperfocalDistance,
  /// `Composite:DOF` PrintConv (Exif.pm:4894) — the split-and-formatted
  /// `"<dof> m (<near> - <far> m)"` (or `"inf (… m - inf)"`) string under `-j`;
  /// the ValueConv space-joined `"<near> <far>"` string under `-n`.
  Dof,
  /// `Composite:FOV` PrintConv (Exif.pm:4936) — `"<angle> deg"` plus an optional
  /// ` (<dist> m)` under `-j`; the ValueConv `"<angle>"` (or `"<angle> <dist>"`)
  /// string under `-n` (a lone angle is emitted BARE by the `EscapeJSON` gate).
  Fov,
  /// `Composite:LightValue` PrintConv (`sprintf("%.1f", $val)`, Exif.pm:4802) —
  /// the 1-decimal string under `-j` (emitted as a BARE number by the gate, e.g.
  /// `8.0`); the bare numeric `$val` under `-n` (e.g. `7.96578428466209`).
  LightValue,
  /// `Composite:AvgBitrate` PrintConv (`ConvertBitrate($val)`, QuickTime.pm:8649)
  /// — the unit-scaled `"<n> <unit>"` string under `-j` (e.g. `25.2 Mbps`); the
  /// bare numeric bps `$val` (the RawConv's `int(...)`) under `-n`.
  AvgBitrate,
  /// `Composite:Rotation` (QuickTime.pm:8646) — the ValueConv `CalcRotation`
  /// degrees, identity PrintConv (no PrintConv on the def), so BOTH modes emit
  /// the bare numeric angle (`0`/`90`/`180`/`270`).
  Rotation,
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
      CompositePrintConv::ImageSize => {
        // `$val` is the ValueConv `Text` (`"W H"`). Under `-n` the bare string;
        // under `-j` the `tr/ /x/` (every space → `x`).
        let CompositeRaw::Text(s) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => TagValue::Str(s.as_str().into()),
          ConvMode::PrintConv => TagValue::Str(s.replace(' ', "x").into()),
        }
      }
      CompositePrintConv::Megapixels => {
        // `$val` is the megapixel count (`Num`). Under `-n` the bare f64; under
        // `-j` the magnitude-keyed `sprintf("%.*f", prec, $val)`.
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::exif::print_megapixels(n).into())
          }
        }
      }
      CompositePrintConv::ShutterSpeed => {
        // `$val` is the SELECTED operand (its ValueConv value), passed through
        // verbatim ([`CompositeRaw::Scalar`]). Under `-n` ExifTool emits that
        // operand value unchanged; under `-j` it runs `PrintExposureTime($val)`,
        // which IsFloat-gates (a non-float operand passes through, NOT coerced
        // to 0). The operand value is the operand's stored `-n` `TagValue`.
        let CompositeRaw::Scalar(operand) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => operand.clone(),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::exif::print_exposure_time_scalar(operand).into())
          }
        }
      }
      CompositePrintConv::Aperture => {
        // `$val` is the SELECTED f-number operand, passed through verbatim. Under
        // `-n` the operand value unchanged; under `-j` `PrintFNumber($val)` with
        // its IsFloat-gate (non-float / non-positive ⇒ passthrough).
        let CompositeRaw::Scalar(operand) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => operand.clone(),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::exif::print_fnumber_scalar(operand).into())
          }
        }
      }
      CompositePrintConv::SubSecDateTime => {
        // `$val` is the RawConv-assembled `Text`; ConvertDateTime is the identity
        // at exifast's option set, so both modes emit it unchanged.
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
      CompositePrintConv::ScaleFactor35efl => {
        // `$val` is the numeric scale factor. `-n` the bare f64; `-j`
        // `sprintf("%.1f", $val)` — a `Str` the `EscapeJSON` gate emits bare.
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => TagValue::Str(std::format!("{n:.1}").into()),
        }
      }
      CompositePrintConv::FocalLength35efl => {
        // `$val` is the 35mm-equiv focal (`Num`). `-n` the bare f64; `-j` the
        // two-branch PrintConv reading `$val[0]` (FocalLength) + `$val[1]`
        // (`Composite:ScaleFactor35efl`).
        let equiv = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(equiv),
          ConvMode::PrintConv => {
            // `$val[0]` is the lens FocalLength; `$val[1]` the (optional) scale
            // factor — both `ToFloat`-coerced as in the ValueConv.
            let focal = vals
              .first()
              .and_then(crate::composite::convs::lens::to_float)
              .unwrap_or(0.0);
            let sf = vals
              .get(1)
              .and_then(crate::composite::convs::lens::to_float);
            TagValue::Str(
              crate::composite::convs::lens::print_focal_length_35efl(focal, sf, equiv).into(),
            )
          }
        }
      }
      CompositePrintConv::CircleOfConfusion => {
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::lens::print_circle_of_confusion(n).into())
          }
        }
      }
      CompositePrintConv::HyperfocalDistance => match raw {
        // A finite numeric distance: `-n` the bare f64; `-j` `sprintf("%.2f m")`.
        CompositeRaw::Num(n) => match mode {
          ConvMode::ValueConv => TagValue::F64(*n),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::lens::print_hyperfocal(*n).into())
          }
        },
        // The `'inf'` ValueConv literal: `-n` the string `"inf"`; `-j` `"Inf m"`.
        CompositeRaw::Text(s) => match mode {
          ConvMode::ValueConv => TagValue::Str(s.as_str().into()),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::lens::print_hyperfocal(f64::INFINITY).into())
          }
        },
        CompositeRaw::Scalar(_) => TagValue::Str(Default::default()),
      },
      CompositePrintConv::Dof => {
        // `$val` is the space-joined `"<near> <far>"` ValueConv string. `-n` the
        // bare string; `-j` the split-and-format PrintConv.
        let CompositeRaw::Text(s) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => TagValue::Str(s.as_str().into()),
          ConvMode::PrintConv => TagValue::Str(crate::composite::convs::lens::print_dof(s).into()),
        }
      }
      CompositePrintConv::Fov => {
        // `$val` is the `"<angle>"` / `"<angle> <dist>"` ValueConv string. `-n`
        // the bare string (a lone angle is emitted bare by the gate); `-j` the
        // split-and-format PrintConv.
        let CompositeRaw::Text(s) = raw else {
          return TagValue::Str(Default::default());
        };
        match mode {
          ConvMode::ValueConv => TagValue::Str(s.as_str().into()),
          ConvMode::PrintConv => TagValue::Str(crate::composite::convs::lens::print_fov(s).into()),
        }
      }
      CompositePrintConv::LightValue => {
        // `$val` is the numeric light value. `-n` the bare f64; `-j`
        // `sprintf("%.1f", $val)` — a `Str` the gate emits bare.
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => TagValue::Str(std::format!("{n:.1}").into()),
        }
      }
      CompositePrintConv::AvgBitrate => {
        // `$val` is the integer bps (`Num`). `-n` the bare f64; `-j`
        // `ConvertBitrate($val)` — the unit-scaled string.
        let n = raw.as_num().unwrap_or(f64::NAN);
        match mode {
          ConvMode::ValueConv => TagValue::F64(n),
          ConvMode::PrintConv => {
            TagValue::Str(crate::composite::convs::video::convert_bitrate(n).into())
          }
        }
      }
      CompositePrintConv::Rotation => {
        // No PrintConv on the def (identity), so BOTH modes emit the bare angle.
        let n = raw.as_num().unwrap_or(f64::NAN);
        TagValue::F64(n)
      }
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
  /// A family-0 qualifier (ExifTool's `GroupMatches` over family-0). `Some(g0)`
  /// requires the resolved entry's family-0 to be `g0` — `Sony:GPSLatitude`
  /// (Sony.pm:10929) is `group0 = Some("Sony")`, so it matches a Sony rtmd GPS
  /// tag (family-0 `Sony`) but not a GoPro one (family-0 `GoPro`). `None` is the
  /// ordinary family-1-only match (every pre-existing input). Family-1 and
  /// family-0 constraints AND together when both are set.
  pub(crate) group0: Option<&'static str>,
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

/// A [`CompositeDef`]'s `RawConv`/`ValueConv` derivation: the resolved input
/// `$val[]` ([`CompositeValue`]) + `$prt[]` (`Option<TagValue>`, the PrintConv
/// view) + the format-state [`CompositeContext`], to the composite's raw value
/// [`CompositeRaw`] (`None` ⇒ the `… ? … : undef` guard, no composite).
pub(crate) type DeriveFn =
  fn(&[CompositeValue], &[Option<TagValue>], &CompositeContext) -> Option<CompositeRaw>;

/// A ported Composite tag: the inputs (index = slice position), the derivation
/// that computes the raw value, and the print-conversion.
///
/// `derive` receives the resolved inputs by index as [`CompositeValue`]s
/// (`Present(value)` carrying the raw [`TagValue`] when the ingredient was
/// extracted, `Missing` when an absent `Desire`/`Inhibit`) — the `$val[]` array
/// — AND the parallel `$prt[]` array (each input's PrintConv-view value,
/// `None` for a `Missing` input), for the few defs whose ValueConv reads a
/// PrintConv input (`Composite:LightValue`'s `CalculateLV($val[0],$val[1],
/// $prt[2])`, Exif.pm:4801). It performs ITS OWN Perl coercion — the Duration
/// defs coerce numeric + apply the Perl-truthy `&&` guard; the GPS defs read
/// string/decimal ingredients; the lens defs `ToFloat` their inputs. It returns
/// the composite's raw value [`CompositeRaw`] (`$val`), or `None` to abort the
/// build (ExifTool's `… ? … : undef` guard, e.g. APE.pm:90, the GPSAltitude
/// RawConv).
#[derive(Clone, Copy)]
pub(crate) struct CompositeDef {
  /// The composite tag name (the `-G1` key is `Composite:<name>`).
  pub(crate) name: &'static str,
  /// The inputs in index order (ExifTool `{ 0 => …, 1 => … }`).
  pub(crate) inputs: &'static [CompositeInput],
  /// The def's `RawConv`/`ValueConv` arithmetic over the resolved inputs
  /// (`$val[]`) and their PrintConv-view counterparts (`$prt[]`, read only by
  /// the defs whose ValueConv interpolates a `$prt[i]`), plus the format-state
  /// [`CompositeContext`] (the `$$self{…}` reads — `AvgBitrate`'s MediaDataSize
  /// sum, `Rotation`'s pre-computed angle).
  pub(crate) derive: DeriveFn,
  /// The def's `PrintConv`.
  pub(crate) print_conv: CompositePrintConv,
  /// The def's `SubDoc` flag (built per `Doc<N>` when set, ExifTool.pm:4001).
  pub(crate) sub_doc: SubDoc,
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
    group0: None,
    name,
  }
}

/// `Require`d input on a single family-1 group `group` (a `&'static` one-element
/// slice supplied by the caller, e.g. `&["FLAC"]`).
const fn req(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: group,
    group0: None,
    name,
  }
}

/// `Desire`d input on a single family-1 group `group`.
const fn des(group: &'static [&'static str], name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Desire,
    groups: group,
    group0: None,
    name,
  }
}

/// `Require`d input qualified by family-0 `"Sony"` (ExifTool's `Require =>
/// 'Sony:GPSLatitude'`, Sony.pm:10929) — matches a Sony rtmd timed-GPS tag
/// (family-0 `Sony`, family-1 the per-sample `Track<N>`) in ANY family-1 group,
/// but NOT a GoPro / camm / mebx tag of the same name (different family-0). The
/// family-1 set is empty (any), the family-0 qualifier does the discrimination.
#[cfg(feature = "quicktime")]
const fn sony_req(name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: &[],
    group0: Some("Sony"),
    name,
  }
}

/// `Require`d input qualified by family-0 `"QuickTime"` (ExifTool's `Require =>
/// 'QuickTime:HandlerType'`, QuickTime.pm:8639) — matches a TRACK-level
/// QuickTime tag (`HandlerType`/`MatrixStructure` carry family-0 `QuickTime`,
/// family-1 `Track<N>`) as well as a movie-level one. The plain family-1 `req`
/// would only match a movie-level `QuickTime:`-family-1 tag, missing the
/// per-track `Track<N>:HandlerType` the `Composite:Rotation` build gate needs.
#[cfg(feature = "quicktime")]
const fn qt_req(name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: &[],
    group0: Some("QuickTime"),
    name,
  }
}

/// The family-1 groups an ExifTool `EXIF:<Name>` requirement expands to. ExifTool
/// matches `EXIF:` via family-0 `EXIF` (every EXIF IFD); the SubSec composites'
/// date inputs (`DateTimeOriginal`/`CreateDate`/`SubSecTime…`/`OffsetTime…` in
/// `ExifIFD`, `ModifyDate` in `IFD0`/`IFD1`) live in these IFDs. Restricting to
/// the EXIF IFD set keeps `EXIF:CreateDate` from matching an `XMP-xmp:CreateDate`
/// / `QuickTime:CreateDate` / `RIFF:…` of the same name (a real collision —
/// those groups carry the same tag names but are NOT family-0 `EXIF`).
#[cfg(feature = "exif")]
const EXIF_IFDS: &[&str] = &["ExifIFD", "IFD0", "IFD1"];

/// A bare-name (group-less) `Require`d input — ExifTool's `Require => 'ImageWidth'`
/// with no `Group:` prefix, matching the tag in ANY group (the empty slice).
#[cfg(feature = "exif")]
const fn bare_req(name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Require,
    groups: &[],
    group0: None,
    name,
  }
}

/// A bare-name (group-less) `Desire`d input (ExifTool `Desire => 'ExifImageWidth'`).
#[cfg(feature = "exif")]
const fn bare_des(name: &'static str) -> CompositeInput {
  CompositeInput {
    kind: InputKind::Desire,
    groups: &[],
    group0: None,
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
fn ape_duration(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn flac_duration(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn aiff_duration(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn gps_latitude(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn gps_longitude(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn gps_altitude(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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
fn gps_datetime(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  let date = v.first()?.as_text()?;
  let time = v.get(1)?.as_text()?;
  Some(CompositeRaw::Text(std::format!("{date} {time}Z")))
}

/// `Composite:GPSPosition` ValueConv (Exif.pm:5313) `(length($val[0]) or
/// length($val[1])) ? "$val[0] $val[1]" : undef`. `$val[0]`=Composite:GPSLatitude
/// (decimal), `[1]`=Composite:GPSLongitude (decimal) — both string-context.
#[cfg(feature = "exif")]
fn gps_position(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
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

/// `Composite:ImageSize` ValueConv (Exif.pm:4757-4762):
///
/// ```perl
/// return $val[4] if $val[4];                            # RawImageCroppedSize
/// return "$val[2] $val[3]" if $val[2] and $val[3] and
///         $$self{TIFF_TYPE} =~ /^(CR2|Canon 1D RAW|IIQ|EIP)$/;
/// return "$val[0] $val[1]" if IsFloat($val[0]) and IsFloat($val[1]);
/// return undef;
/// ```
///
/// `$val[0]`=ImageWidth, `[1]`=ImageHeight, `[2]`=ExifImageWidth,
/// `[3]`=ExifImageHeight, `[4]`=RawImageCroppedSize. The result is a `Text`
/// `"W H"` (the PrintConv `tr/ /x/` later makes it `"WxH"`).
///
/// The `$val[2] $val[3]` branch is gated on `$$self{TIFF_TYPE}` being one of the
/// Canon/Phase-One TIFF-base RAW types. The Composite engine reads the FINAL
/// emitted tag set and has no `TIFF_TYPE` handle, so that branch is NOT taken
/// here — which is exact for every format the allow-list runs composites for
/// (EXIF JPEG/TIFF + still QuickTime + the audio Durations are never
/// CR2/Canon 1D RAW/IIQ/EIP). A future port that threads `TIFF_TYPE` into the
/// post-pass can add it.
#[cfg(feature = "exif")]
fn image_size(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  // `return $val[4] if $val[4]` — a present + Perl-truthy RawImageCroppedSize is
  // already a `"WxH"` string; use it verbatim.
  if let Some(cropped) = v.get(4)
    && cropped.is_truthy()
  {
    return Some(CompositeRaw::Text(cropped.as_text()?.into_owned()));
  }
  // The `$val[2] $val[3]` Canon/Phase-One RAW branch needs `$$self{TIFF_TYPE}`,
  // which the post-pass does not carry (see the doc note); skipped.
  //
  // `return "$val[0] $val[1]" if IsFloat($val[0]) and IsFloat($val[1])`. The
  // `$val[i]` interpolated is the ValueConv value (IsFloat-normalized in place,
  // so a comma decimal would be the translated form).
  let w_text = v.first()?.as_text()?;
  let h_text = v.get(1)?.as_text()?;
  let w_norm = crate::convert::is_float_norm(&w_text)?;
  let h_norm = crate::convert::is_float_norm(&h_text)?;
  Some(CompositeRaw::Text(std::format!("{w_norm} {h_norm}")))
}

/// `Composite:Megapixels` ValueConv (Exif.pm:4768):
/// `my @d = ($val =~ /\d+/g); $d[0] * $d[1] / 1000000`. `$val` is the
/// `Composite:ImageSize` ValueConv string (`"W H"`); the two `\d+` runs are the
/// dimensions, their product over a million is the megapixel count (`Num`).
#[cfg(feature = "exif")]
fn megapixels(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  let size = v.first()?.as_text()?;
  // `($val =~ /\d+/g)` — every maximal ASCII-digit run, in order.
  let mut digits = size
    .as_bytes()
    .split(|b| !b.is_ascii_digit())
    .filter(|run| !run.is_empty())
    .map(|run| {
      // Each run is ASCII digits; parse as f64 (a very wide dimension still
      // fits f64 exactly up to 2^53, far beyond any pixel count).
      std::str::from_utf8(run)
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
    });
  // `$d[0] * $d[1]` — a missing element is Perl `undef` ⇒ `0` in the product.
  let d0 = digits.next().unwrap_or(0.0);
  let d1 = digits.next().unwrap_or(0.0);
  Some(CompositeRaw::Num(d0 * d1 / 1_000_000.0))
}

/// `Composite:ShutterSpeed` ValueConv (Exif.pm:4778):
/// `($val[2] and $val[2]>0) ? $val[2] : (defined($val[0]) ? $val[0] : $val[1])`.
/// `$val[0]`=ExposureTime, `[1]`=ShutterSpeedValue, `[2]`=BulbDuration. A
/// positive BulbDuration wins; else ExposureTime if defined; else
/// ShutterSpeedValue.
///
/// The ValueConv merely SELECTS one operand — it does NOT coerce it. The chosen
/// value is the operand's ORIGINAL scalar, handed verbatim to
/// `PrintExposureTime` (the PrintConv), which passes a non-`IsFloat` operand
/// through unchanged (Exif.pm:5704). So a present-but-non-float ExposureTime /
/// ShutterSpeedValue (a zero-denominator rational that ValueConv'd to `"undef"`)
/// must be carried as its raw [`TagValue`] ([`CompositeRaw::Scalar`]), NOT
/// numerically coerced to `0`. The BulbDuration GUARD (`$val[2]>0`) still
/// coerces numerically (a non-numeric BulbDuration is not `> 0`), but the
/// SELECTED value remains `$val[2]`'s raw scalar.
#[cfg(feature = "exif")]
fn shutter_speed(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  // `($val[2] and $val[2]>0)` — BulbDuration present + Perl-truthy AND
  // numerically positive ⇒ it wins (selected VERBATIM, not the coerced number).
  if let Some(b) = v.get(2)
    && b.is_truthy()
    && b.coerce_numeric().is_some_and(|bn| bn > 0.0)
  {
    return Some(CompositeRaw::Scalar(b.selected_scalar()?));
  }
  // `defined($val[0]) ? $val[0] : $val[1]` — select the operand, pass through.
  let chosen = match v.first() {
    Some(cv) if cv.is_present() => cv,
    _ => v.get(1)?,
  };
  Some(CompositeRaw::Scalar(chosen.selected_scalar()?))
}

/// `Composite:Aperture` RawConv + ValueConv (Exif.pm:4788-4789):
/// RawConv `($val[0] || $val[1]) ? $val : undef`, ValueConv `$val[0] || $val[1]`.
/// `$val[0]`=FNumber, `[1]`=ApertureValue. The first Perl-truthy of the two is
/// the f-number; if NEITHER is truthy the composite is not built.
///
/// Like `ShutterSpeed`, the ValueConv only SELECTS an operand (the `||` picks
/// the first truthy one); `PrintFNumber` (the PrintConv) passes a non-`IsFloat`
/// operand through unchanged (Exif.pm:5719). So the chosen operand is carried as
/// its raw [`TagValue`] ([`CompositeRaw::Scalar`]) — a present-but-non-float
/// FNumber / ApertureValue (a zero-denominator rational ⇒ `"undef"`) is NOT
/// coerced to `0`. Truthiness is the RAW Perl-boolean (a wire `"0.0"` is
/// truthy, picked, then `PrintFNumber` passes it through since it is non-float).
#[cfg(feature = "exif")]
fn aperture(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  // `$val[0] || $val[1]` — first Perl-truthy operand, selected VERBATIM.
  if let Some(f) = v.first()
    && f.is_truthy()
  {
    return Some(CompositeRaw::Scalar(f.selected_scalar()?));
  }
  let av = v.get(1)?;
  if av.is_truthy() {
    return Some(CompositeRaw::Scalar(av.selected_scalar()?));
  }
  // `($val[0] || $val[1]) ? $val : undef` — neither truthy ⇒ undef.
  None
}

/// The shared `%subSecConv` derivation (Exif.pm:4726) for the three SubSec
/// composites. `$val[0]`=base DateTime (Require), `[1]`=SubSecTime (Desire),
/// `[2]`=OffsetTime (Desire). Delegates to
/// [`crate::composite::convs::datetime::sub_sec_assemble`] (the regex-faithful
/// assembly); `None` ⇒ neither a usable sub-second nor an offset ⇒ not built.
#[cfg(feature = "exif")]
fn sub_sec_datetime(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  let date = v.first()?.as_text()?;
  let sub_sec = v.get(1).and_then(CompositeValue::as_text);
  let offset = v.get(2).and_then(CompositeValue::as_text);
  crate::composite::convs::datetime::sub_sec_assemble(&date, sub_sec.as_deref(), offset.as_deref())
    .map(CompositeRaw::Text)
}

/// `Composite:ScaleFactor35efl` ValueConv (Exif.pm:4843):
/// `Image::ExifTool::Exif::CalcScaleFactor35efl($self, @val)`. The 16 documented
/// `Desire` inputs are `$val[0..15]`; exifast appends `Make` at index 16 (an
/// extra `Desire`) to supply the `$$et{Make}` the Canon-branch check reads — the
/// post-pass has no ExifTool object. Delegates to
/// [`crate::composite::convs::lens::calc_scale_factor_35efl`] (the generic path);
/// the Canon branch is DEFERRED (returns `None`, no `ScaleFactor35efl` emitted).
#[cfg(feature = "exif")]
fn scale_factor_35efl(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::{
    ScaleFactorInputs, ScaleFactorOutcome, calc_scale_factor_35efl,
  };
  // `$$et{Make} eq 'Canon'` — the IFD0 Make supplied at the appended index 16.
  let is_canon = v
    .get(16)
    .and_then(CompositeValue::as_text)
    .is_some_and(|m| m == "Canon");
  let inputs = ScaleFactorInputs {
    focal: v.first(),
    foc35: v.get(1),
    digital_zoom: v.get(2),
    focal_plane_diagonal: v.get(3),
    sensor_size: v.get(4),
    focal_plane_x_size: v.get(5),
    focal_plane_y_size: v.get(6),
    resolution_unit: v.get(7),
    x_resolution: v.get(8),
    y_resolution: v.get(9),
    size_pairs: [
      (v.get(10), v.get(11)), // ExifImageWidth/Height
      (v.get(12), v.get(13)), // CanonImageWidth/Height
      (v.get(14), v.get(15)), // ImageWidth/Height
    ],
  };
  match calc_scale_factor_35efl(is_canon, &inputs) {
    ScaleFactorOutcome::Factor(f) => Some(CompositeRaw::Num(f)),
    // The Canon-branch refinement is unported (DEFER) and a `undef` result both
    // emit NO `ScaleFactor35efl` — exactly ExifTool's `undef` ValueConv.
    ScaleFactorOutcome::CanonBranch | ScaleFactorOutcome::Undef => None,
  }
}

/// `Composite:FocalLength35efl` ValueConv (Exif.pm:4814):
/// `ToFloat(@val); ($val[0] || 0) * ($val[1] || 1)`. `$val[0]`=FocalLength
/// (Require), `[1]`=`Composite:ScaleFactor35efl` (Desire). The 35mm-equiv focal
/// is the lens focal times the scale factor (defaulting the missing factor to
/// `1`, the missing focal to `0`).
///
/// ## The Canon-deferred-ScaleFactor guard (an unported-`CalcSensorDiag` gap)
///
/// FocalLength35efl only DESIRES ScaleFactor, so absent a ScaleFactor it falls
/// through to the focal-only `$val[0] * 1`. That is FAITHFUL when ExifTool ALSO
/// built no ScaleFactor (e.g. `Exif.tif` — `Make=Canon`, no
/// `FocalLengthIn35mmFormat`, NO sensor data ⇒ both ExifTool and exifast emit
/// `"50.0 mm"`). But for a `Make=Canon` body WITH FocalPlane sensor data
/// (`XMP.xmp`: `FocalPlaneXResolution` present), ExifTool's `CalcScaleFactor35efl`
/// Canon `CalcSensorDiag` branch (Exif.pm:5464) BUILDS a ScaleFactor (6.08) the
/// exifast post-pass cannot reach (no `TAG_EXTRA{Rational}` handle) — so
/// ExifTool's FocalLength35efl is the SCALE-FACTOR form (`"5.8 mm (35 mm
/// equivalent: 35.3 mm)"`) while exifast's focal-only fall-through (`"5.8 mm"`)
/// DIVERGES. So when the ScaleFactor is absent BECAUSE the Canon branch would
/// have produced it (`Make=Canon` ∧ no `FocalLengthIn35mmFormat` ∧ FocalPlane
/// sensor data present), exifast DEFERS FocalLength35efl (emits nothing) rather
/// than the wrong focal-only value — the same deferral its
/// `Require`-ScaleFactor siblings (`CircleOfConfusion`/`FOV`/`HyperfocalDistance`)
/// take automatically. The extra inputs: `2`=Make, `3`=FocalLengthIn35mmFormat,
/// `4`=FocalPlaneXResolution, `5`=SensorSize, `6`=FocalPlaneDiagonal,
/// `7`=FocalPlaneXSize, `8`=FocalPlaneYSize (the full `CalcScaleFactor35efl`
/// generic-`$diag` sensor set, so the Canon-deferral guard matches every source
/// ExifTool could compute a ScaleFactor from).
#[cfg(feature = "exif")]
fn focal_length_35efl(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::to_float;
  // The Canon-deferred-ScaleFactor guard: ScaleFactor absent (`$val[1]` Missing)
  // BUT ExifTool's Canon branch would have built one ⇒ defer (the focal-only
  // fall-through would be the WRONG value).
  let scale_factor_missing = !v.get(1).is_some_and(CompositeValue::is_present);
  if scale_factor_missing {
    let is_canon = v
      .get(2)
      .and_then(CompositeValue::as_text)
      .is_some_and(|m| m == "Canon");
    // The simple `$foc35/$focal` ScaleFactor path did NOT fire — so ExifTool
    // would reach the Canon/sensor branch. That path is `return $foc35 / $focal
    // if $focal and $foc35` (Exif.pm:5460): it fires ONLY when BOTH operands —
    // `$focal` (FocalLength, v[0]) AND `$foc35` (FocalLengthIn35mmFormat, v[3])
    // — are POST-ToFloat Perl-truthy. Perl `and` on a number is true iff
    // non-zero, so a present-but-falsy `0`/`0.0`/`-0.0`, or a non-numeric string
    // (`"abc"`/`""`/`"Inf"`) whose `ToFloat` is `undef`, makes that operand
    // FALSY. If EITHER operand is falsy the simple path does NOT fire and the
    // Canon branch can still build a ScaleFactor from sensor data — so the guard
    // keys off the FULL predicate, not just `foc35` (a present-but-falsy
    // FocalLength with a truthy foc35 also fails `$focal and $foc35`, so it too
    // must not suppress the Canon deferral, else FocalLength35efl would emit the
    // wrong focal-only value).
    let focal_truthy = v.first().and_then(to_float).is_some_and(|f| f != 0.0);
    let foc35_truthy = v.get(3).and_then(to_float).is_some_and(|f| f != 0.0);
    let simple_path_fires = focal_truthy && foc35_truthy;
    // Any FocalPlane sensor input `CalcScaleFactor35efl` can derive `$diag` from
    // (Exif.pm:5470-5505) — the FULL generic-path set the deferred Canon branch
    // can fall through to: SensorSize, FocalPlaneDiagonal, FocalPlaneX/YSize, and
    // the FocalPlaneXResolution + image-size route. If ANY is present ExifTool
    // could compute a ScaleFactor exifast can't, so the focal-only fall-through
    // would diverge ⇒ defer. (The FocalPlaneX/YSize aspect-ratio path was the gap.)
    let has_sensor_data = v.get(4).is_some_and(CompositeValue::is_present) // FocalPlaneXResolution
      || v.get(5).is_some_and(CompositeValue::is_present) // SensorSize
      || v.get(6).is_some_and(CompositeValue::is_present) // FocalPlaneDiagonal
      || v.get(7).is_some_and(CompositeValue::is_present) // FocalPlaneXSize
      || v.get(8).is_some_and(CompositeValue::is_present); // FocalPlaneYSize
    if is_canon && !simple_path_fires && has_sensor_data {
      return None;
    }
  }
  // `ToFloat(@val)` then `($val[0] || 0) * ($val[1] || 1)` — Perl-truthy
  // defaults: a falsy/undef focal ⇒ 0, a falsy/undef scale factor ⇒ 1.
  let focal = match v.first().and_then(to_float) {
    Some(f) if f != 0.0 => f,
    _ => 0.0,
  };
  let sf = match v.get(1).and_then(to_float) {
    Some(s) if s != 0.0 => s,
    _ => 1.0,
  };
  Some(CompositeRaw::Num(focal * sf))
}

/// `Composite:CircleOfConfusion` ValueConv (Exif.pm:4851):
/// `sqrt(24*24+36*36) / ($val * 1440)`. `$val`=`Composite:ScaleFactor35efl`
/// (Require). The circle of confusion in mm.
///
/// This ValueConv reads `$val` (the single required ScaleFactor) DIRECTLY — it
/// does NOT call `ToFloat`, so the FULL-precision ScaleFactor f64 is used, NOT
/// the `%.15g`-reparsed form [`to_float`](crate::composite::convs::lens::to_float)
/// applies. (At 15 sig figs the CoC bytes are identical either way, but the
/// raw read is faithful to the ValueConv.)
#[cfg(feature = "exif")]
fn circle_of_confusion(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::frame_diag_35mm;
  let sf = v.first()?.coerce_numeric()?;
  Some(CompositeRaw::Num(frame_diag_35mm() / (sf * 1440.0)))
}

/// `Composite:HyperfocalDistance` ValueConv (Exif.pm:4859):
///
/// ```perl
/// ToFloat(@val);
/// return 'inf' unless $val[1] and $val[2];
/// return $val[0] * $val[0] / ($val[1] * $val[2] * 1000);
/// ```
///
/// `$val[0]`=FocalLength, `[1]`=`Composite:Aperture`, `[2]`=`Composite:
/// CircleOfConfusion` (all Require). When aperture or CoC is falsy the literal
/// `'inf'` is returned (a `Text` raw, rendered as `"inf"`/`"Inf m"`); otherwise
/// `focal^2 / (aperture * CoC * 1000)`.
#[cfg(feature = "exif")]
fn hyperfocal_distance(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::to_float;
  // `ToFloat(@val)` — a non-`ToFloat` input becomes undef; the formula then sees
  // `0`-or-undef as falsy. (`$val[i] || 0` is implicit in the `unless`/product.)
  let focal = v.first().and_then(to_float).unwrap_or(0.0);
  let aperture = v.get(1).and_then(to_float).unwrap_or(0.0);
  let coc = v.get(2).and_then(to_float).unwrap_or(0.0);
  // `return 'inf' unless $val[1] and $val[2]` (Perl-truthy: nonzero).
  if aperture == 0.0 || coc == 0.0 {
    return Some(CompositeRaw::Text("inf".to_string()));
  }
  // `return $val[0] * $val[0] / ($val[1] * $val[2] * 1000)`.
  Some(CompositeRaw::Num(focal * focal / (aperture * coc * 1000.0)))
}

/// `Composite:DOF` ValueConv (Exif.pm:4876):
///
/// ```perl
/// ToFloat(@val);
/// my ($d, $f) = ($val[3], $val[0]);
/// if (defined $d) { $d or $d = 1e10; }
/// else {
///     $d = $val[4] || $val[5] || $val[6];
///     unless (defined $d) {
///         return undef unless defined $val[7] and defined $val[8];
///         $d = ($val[7] + $val[8]) / 2;
///     }
/// }
/// return 0 unless $f and $val[2];
/// my $t = $val[1] * $val[2] * ($d * 1000 - $f) / ($f * $f);
/// my @v = ($d / (1 + $t), $d / (1 - $t));
/// $v[1] < 0 and $v[1] = 0;
/// return join(' ', @v);
/// ```
///
/// `$val[0]`=FocalLength, `[1]`=`Composite:Aperture`, `[2]`=`Composite:
/// CircleOfConfusion` (Require); `[3]`=FocusDistance, `[4]`=SubjectDistance,
/// `[5]`=ObjectDistance, `[6]`=ApproximateFocusDistance, `[7]`=FocusDistanceLower,
/// `[8]`=FocusDistanceUpper (Desire). The result is the space-joined `"<near>
/// <far>"` (each Perl-NV-stringified), or `"0"` when focal/CoC is falsy.
#[cfg(feature = "exif")]
fn dof(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::to_float;
  use crate::composite::convs::perl_nv_str;
  // `ToFloat(@val)` runs FIRST, mutating EVERY `$val[i]` to its float (or undef)
  // BEFORE any `defined`/`||` test. So every `defined $d` / `$d or` / `defined
  // $val[7]` decision below keys on the POST-ToFloat value, NOT raw tag presence:
  // a present-but-non-numeric ingredient is `undef` and falls through exactly as
  // Perl's `ToFloat`-coerced array does. Precompute each Option<f64> once.
  let f = v.first().and_then(to_float).unwrap_or(0.0);
  let aperture = v.get(1).and_then(to_float).unwrap_or(0.0);
  let coc = v.get(2).and_then(to_float).unwrap_or(0.0);
  let d3 = v.get(3).and_then(to_float); // FocusDistance
  let d4 = v.get(4).and_then(to_float); // SubjectDistance
  let d5 = v.get(5).and_then(to_float); // ObjectDistance
  let d6 = v.get(6).and_then(to_float); // ApproximateFocusDistance
  let d7 = v.get(7).and_then(to_float); // FocusDistanceLower
  let d8 = v.get(8).and_then(to_float); // FocusDistanceUpper

  // `my ($d, $f) = ($val[3], $val[0]); if (defined $d) { $d or $d = 1e10; }`.
  // `defined $d` is the POST-ToFloat definedness of FocusDistance — a non-numeric
  // FocusDistance is `undef` here and DOES fall to the alternatives below (it does
  // NOT short-circuit to the `1e10` sentinel). A defined falsy `0` ⇒ `1e10`.
  let d = if let Some(dv) = d3 {
    if dv == 0.0 { 1e10 } else { dv }
  } else {
    // `$d = $val[4] || $val[5] || $val[6]` — Perl `||` returns the first truthy
    // operand, else the LAST operand. So the result is truthy(d4)→d4,
    // else truthy(d5)→d5, else d6 (its value — defined `0` included). `defined $d`
    // afterwards is therefore truthy(d4) || truthy(d5) || d6.is_some().
    let alt = if d4.is_some_and(|x| x != 0.0) {
      d4
    } else if d5.is_some_and(|x| x != 0.0) {
      d5
    } else {
      d6 // first-truthy fell through ⇒ the last operand `$val[6]` (Some(0)/value/None)
    };
    match alt {
      Some(dv) => dv,
      None => {
        // `unless (defined $d) { return undef unless defined $val[7] and
        // defined $val[8]; $d = ($val[7] + $val[8]) / 2; }`. Reached only when the
        // `||` chain is `undef` (4/5 not truthy AND 6 undef). The lower/upper
        // average needs BOTH POST-ToFloat values defined (a present-non-numeric
        // bound is undef ⇒ the composite is undef, not averaged-as-0).
        let (Some(lo), Some(hi)) = (d7, d8) else {
          return None;
        };
        (lo + hi) / 2.0
      }
    }
  };

  // `return 0 unless $f and $val[2]` (Perl-truthy focal AND CoC).
  if f == 0.0 || coc == 0.0 {
    return Some(CompositeRaw::Text(perl_nv_str(0.0)));
  }
  // `$t = $val[1] * $val[2] * ($d*1000 - $f) / ($f*$f)`.
  let t = aperture * coc * (d * 1000.0 - f) / (f * f);
  // `@v = ($d/(1+$t), $d/(1-$t)); $v[1] < 0 and $v[1] = 0`.
  let near = d / (1.0 + t);
  let mut far = d / (1.0 - t);
  if far < 0.0 {
    far = 0.0;
  }
  // `join(' ', @v)` — each f64 via Perl's default NV stringification.
  Some(CompositeRaw::Text(std::format!(
    "{} {}",
    perl_nv_str(near),
    perl_nv_str(far)
  )))
}

/// `Composite:FOV` ValueConv (Exif.pm:4924):
///
/// ```perl
/// ToFloat(@val);
/// return undef unless $val[0] and $val[1];
/// my $corr = 1;
/// if ($val[2]) { my $d = 1000 * $val[2] - $val[0]; $corr += $val[0]/$d if $d > 0; }
/// my $fd2 = atan2(36, 2*$val[0]*$val[1]*$corr);
/// my @fov = ( $fd2 * 360 / 3.14159 );
/// if ($val[2] and $val[2] > 0 and $val[2] < 10000) {
///     push @fov, 2 * $val[2] * sin($fd2) / cos($fd2);
/// }
/// return join(' ', @fov);
/// ```
///
/// `$val[0]`=FocalLength, `[1]`=`Composite:ScaleFactor35efl` (Require);
/// `[2]`=FocusDistance (Desire). The angle uses the literal `3.14159`
/// (Exif.pm:4932 — a TRUNCATED pi, ported byte-exact); a present in-range focus
/// distance appends the subject-field width.
// The literal `3.14159` is REQUIRED for byte-exact parity with ExifTool's FOV
// ValueConv (Exif.pm:4932); `std::f64::consts::PI` (3.141592653589793) would
// change the angle in the 6th significant figure.
#[allow(clippy::approx_constant)]
#[cfg(feature = "exif")]
fn fov(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::to_float;
  use crate::composite::convs::perl_nv_str;
  let focal = v.first().and_then(to_float).unwrap_or(0.0);
  let scale = v.get(1).and_then(to_float).unwrap_or(0.0);
  // `return undef unless $val[0] and $val[1]` (Perl-truthy focal AND scale).
  if focal == 0.0 || scale == 0.0 {
    return None;
  }
  let focus_dist = v.get(2).and_then(to_float).unwrap_or(0.0);
  // `my $corr = 1; if ($val[2]) { my $d = 1000*$val[2] - $val[0]; $corr +=
  // $val[0]/$d if $d > 0; }`.
  let mut corr = 1.0;
  if focus_dist != 0.0 {
    let d = 1000.0 * focus_dist - focal;
    if d > 0.0 {
      corr += focal / d;
    }
  }
  // `my $fd2 = atan2(36, 2*$val[0]*$val[1]*$corr)`.
  let fd2 = 36.0_f64.atan2(2.0 * focal * scale * corr);
  // `@fov = ($fd2 * 360 / 3.14159)` — the TRUNCATED-pi literal (Exif.pm:4932).
  let angle = fd2 * 360.0 / 3.14159;
  let mut out = perl_nv_str(angle);
  // `if ($val[2] and $val[2] > 0 and $val[2] < 10000) { push @fov, 2*$val[2]*
  // sin($fd2)/cos($fd2); }`.
  if focus_dist != 0.0 && focus_dist > 0.0 && focus_dist < 10000.0 {
    let width = 2.0 * focus_dist * fd2.sin() / fd2.cos();
    out.push(' ');
    out.push_str(&perl_nv_str(width));
  }
  Some(CompositeRaw::Text(out))
}

/// `Composite:LightValue` ValueConv (Exif.pm:4801):
/// `Image::ExifTool::Exif::CalculateLV($val[0],$val[1],$prt[2])`. `$val[0]`=
/// `Composite:Aperture`, `[1]`=`Composite:ShutterSpeed`, `$prt[2]`=ISO's
/// PrintConv value (all Require). Delegates to
/// [`crate::composite::convs::lens::calculate_lv`] (the log2 LV formula); `None`
/// ⇒ a non-positive/non-float input ⇒ not built.
#[cfg(feature = "exif")]
fn light_value(
  v: &[CompositeValue],
  prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  use crate::composite::convs::lens::calculate_lv;
  // `$val[0]` Aperture, `$val[1]` ShutterSpeed (ValueConv views), `$prt[2]` the
  // ISO PRINTCONV value (Exif.pm:4801 uses `$prt[2]`, not `$val[2]`).
  let aperture = v.first()?.as_text()?;
  let shutter = v.get(1)?.as_text()?;
  let iso_prt = prts.get(2)?.as_ref()?;
  let iso_text = crate::composite::value_text(iso_prt);
  calculate_lv(&aperture, &shutter, &iso_text).map(CompositeRaw::Num)
}

/// `Composite:AvgBitrate` RawConv (QuickTime.pm:8649-8662):
///
/// ```perl
/// return undef unless $val[1];
/// $val[1] /= $$self{TimeScale} if $$self{TimeScale};
/// my $key = 'MediaDataSize';
/// my $size = $val[0];
/// for (;;) {
///     $key = $self->NextTagKey($key) or last;
///     $size += $self->GetValue($key, 'ValueConv');
/// }
/// return int($size * 8 / $val[1] + 0.5);
/// ```
///
/// `$val[0]` = `QuickTime:MediaDataSize` (Require), `$val[1]` = `QuickTime:
/// Duration` (Require) — the EMITTED Duration value (`-n`).
///
/// **The `MediaDataSize` sum** the post-pass threads via [`CompositeContext`]:
/// the `NextTagKey('MediaDataSize')`-summed total (`ctx.media_data_total`),
/// since the dedup-collapsing `TagMap` keeps only ONE `MediaDataSize` (the
/// visible last-wins tag) — so the summed total is pre-computed by the QuickTime
/// parser and threaded. (HEIF has 3 `mdat` boxes summing to 1 004 715 bytes.)
///
/// **No TimeScale divide.** ExifTool's RawConv has `$val[1] /= $$self{TimeScale}
/// if $$self{TimeScale}` — but `$val[1]` is the `QuickTime::Duration` ValueConv
/// value (`%durationInfo` `$$self{TimeScale} ? $val/$$self{TimeScale} : $val`),
/// which is ALREADY the seconds form, and ground-truthing the bundled output
/// shows the net result is `int($size*8 / Duration_emitted + 0.5)` with NO
/// further divide: camm `116*8/3 = 309`, blackvue `188848920*8/60 = 25.2 Mbps`,
/// zerotimescale `16*8/1200 = 0` (TimeScale 0 ⇒ Duration is the raw count 1200,
/// used directly). exifast's emitted `QuickTime:Duration` (`-n`) IS that same
/// `$val[1]` value, so the faithful port reads it directly.
#[cfg(feature = "quicktime")]
fn avg_bitrate(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  // `return undef unless $val[1]` — Duration present + Perl-truthy.
  let dur = v.get(1)?;
  if !dur.is_truthy() {
    return None;
  }
  let duration = dur.coerce_numeric()?;
  if duration == 0.0 {
    // `return undef unless $val[1]` already guarded a Perl-falsy Duration; a
    // non-zero-but-numerically-zero edge would divide-by-zero, so guard it too.
    return None;
  }
  // `my $size = $val[0]; for (;;) { ... $size += GetValue($key,'ValueConv'); }`
  // — the SUM of every MediaDataSize. The parser pre-summed all `mdat` sizes
  // into `ctx.media_data_total`; prefer it (it IS the `$val[0] + Σ rest`). Fall
  // back to the single resolved `$val[0]` if the total is somehow absent.
  let size = match ctx.media_data_total {
    Some(total) => total as f64,
    None => v.first()?.coerce_numeric()?,
  };
  // `return int($size * 8 / $val[1] + 0.5)` — Perl `int` truncates toward zero;
  // the `+ 0.5` rounds the non-negative bitrate to nearest.
  Some(CompositeRaw::Num((size * 8.0 / duration + 0.5).trunc()))
}

/// `Composite:Rotation` ValueConv `CalcRotation($self)` (QuickTime.pm:8646). The
/// angle is a PURE function of the final emitted tag set (the `vide` Handler
/// track's MatrixStructure), so the post-pass pre-computes it into
/// [`CompositeContext::rotation`] (see [`crate::composite::calc_rotation`]) and
/// this derive merely surfaces it. The `Require`d `MatrixStructure` +
/// `HandlerType` inputs gate the BUILD (ExifTool only attempts the composite
/// when both exist); `ctx.rotation` then supplies the value (or `None` ⇒ the
/// ValueConv returned `undef`, no composite).
#[cfg(feature = "quicktime")]
fn rotation(
  _v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  ctx.rotation.map(CompositeRaw::Num)
}

/// `Composite:Duration` (RIFF) RawConv `CalcDuration($self, @val)`
/// (RIFF.pm:1645-1693), single-document path (the AVI fixtures are not
/// multi-stream, so `DOC_COUNT` is 0 and the SubDoc loop runs once):
///
/// ```perl
/// my $dur1;
/// $dur1 = $val[1] / $val[0] if $val[0];
/// if ($val[2] and $val[3]) {
///     my $dur2 = $val[3] / $val[2];
///     my $rat = $dur1 / $dur2;
///     $dur1 = $dur2 if $rat > 1.9 and $rat < 3.1;
/// }
/// $totalDuration += $dur1 if defined $dur1;
/// ```
///
/// `$val[0]` = RIFF:FrameRate, `[1]` = RIFF:FrameCount (Require); `[2]` =
/// VideoFrameRate, `[3]` = VideoFrameCount (Desire). `dur1 = FrameCount /
/// FrameRate`; if BOTH video-stream values are truthy and their `dur2` ratio is
/// 1.9–3.1× `dur1`, the (multi-track-corrected) `dur2` replaces it.
#[cfg(feature = "riff")]
fn riff_duration(
  v: &[CompositeValue],
  _prts: &[Option<TagValue>],
  _ctx: &CompositeContext,
) -> Option<CompositeRaw> {
  // `$dur1 = $val[1] / $val[0] if $val[0]` — FrameCount / FrameRate, only when
  // FrameRate is Perl-truthy. A falsy/absent FrameRate ⇒ `$dur1` undef ⇒ the
  // `$totalDuration += $dur1 if defined` adds nothing ⇒ Duration 0 (built).
  let frame_rate = v.first()?.coerce_numeric()?;
  let mut dur1 = if frame_rate != 0.0 {
    Some(v.get(1)?.coerce_numeric()? / frame_rate)
  } else {
    None
  };
  // `if ($val[2] and $val[3]) { my $dur2 = $val[3]/$val[2]; ... }` — the
  // video-stream override (Perl-truthy VideoFrameRate AND VideoFrameCount).
  let vfr = v.get(2).and_then(CompositeValue::coerce_numeric);
  let vfc = v.get(3).and_then(CompositeValue::coerce_numeric);
  if let (Some(vfr), Some(vfc)) = (vfr, vfc)
    && vfr != 0.0
    && vfc != 0.0
    && let Some(d1) = dur1
  {
    let dur2 = vfc / vfr;
    // `my $rat = $dur1 / $dur2; $dur1 = $dur2 if $rat > 1.9 and $rat < 3.1`.
    if dur2 != 0.0 {
      let rat = d1 / dur2;
      if rat > 1.9 && rat < 3.1 {
        dur1 = Some(dur2);
      }
    }
  }
  // `$totalDuration += $dur1 if defined $dur1` (single doc) — undef ⇒ 0.
  Some(CompositeRaw::Num(dur1.unwrap_or(0.0)))
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
  sub_doc: SubDoc::No,
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
  sub_doc: SubDoc::No,
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
  sub_doc: SubDoc::No,
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
  sub_doc: SubDoc::All, // GPS.pm:369 `SubDoc => 1` — built per Doc<N>.
  priority: 1,          // GPS.pm: Avoid sets Priority 0, then `Priority => 1` restores it.
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
  sub_doc: SubDoc::All, // GPS.pm:386 `SubDoc => 1`.
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
  // GPS.pm:408 `SubDoc => [1,3]` — build per Doc<N> only when Desire index 1
  // (GPS:GPSAltitudeRef) or 3 (XMP:GPSAltitudeRef) has a chance to exist.
  sub_doc: SubDoc::Indices(&[1, 3]),
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
  sub_doc: SubDoc::All, // GPS.pm:357 `SubDoc => 1`.
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
  sub_doc: SubDoc::No,
  priority: 0,
  // Exif.pm's prefix is `Composite` (Exif::Composite uses the default `Image-
  // ExifTool` prefix → `Composite-GPSPosition`). The cross-module GPS defs sort
  // before it (`GPS-…`), so `Composite-GPSLatitude/Longitude` are built first.
  sort_key: "Composite-GPSPosition",
};

/// `Composite:ImageSize` (Exif.pm:4747). `Require`s ImageWidth + ImageHeight
/// (bare names, any group — ExifTool resolves the group-less tags), `Desire`s
/// ExifImageWidth/Height + RawImageCroppedSize.
#[cfg(feature = "exif")]
const IMAGE_SIZE: CompositeDef = CompositeDef {
  name: "ImageSize",
  inputs: &[
    bare_req("ImageWidth"),
    bare_req("ImageHeight"),
    bare_des("ExifImageWidth"),
    bare_des("ExifImageHeight"),
    bare_des("RawImageCroppedSize"),
  ],
  derive: image_size,
  print_conv: CompositePrintConv::ImageSize,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-ImageSize",
};

/// `Composite:Megapixels` (Exif.pm:4767). `Require`s `Composite:ImageSize` — the
/// composite-on-composite fixpoint (it defers until ImageSize is built).
#[cfg(feature = "exif")]
const MEGAPIXELS: CompositeDef = CompositeDef {
  name: "Megapixels",
  inputs: &[req(&["Composite"], "ImageSize")],
  derive: megapixels,
  print_conv: CompositePrintConv::Megapixels,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-Megapixels",
};

/// `Composite:ShutterSpeed` (Exif.pm:4773). `Desire`s ExposureTime /
/// ShutterSpeedValue / BulbDuration (bare names — these EXIF tags resolve
/// group-lessly in ExifTool).
#[cfg(feature = "exif")]
const SHUTTER_SPEED: CompositeDef = CompositeDef {
  name: "ShutterSpeed",
  inputs: &[
    bare_des("ExposureTime"),
    bare_des("ShutterSpeedValue"),
    bare_des("BulbDuration"),
  ],
  derive: shutter_speed,
  print_conv: CompositePrintConv::ShutterSpeed,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-ShutterSpeed",
};

/// `Composite:Aperture` (Exif.pm:4782). `Desire`s FNumber / ApertureValue. The
/// RawConv `($val[0]||$val[1]) ? $val : undef` is folded into [`aperture`].
#[cfg(feature = "exif")]
const APERTURE: CompositeDef = CompositeDef {
  name: "Aperture",
  inputs: &[bare_des("FNumber"), bare_des("ApertureValue")],
  derive: aperture,
  print_conv: CompositePrintConv::Aperture,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-Aperture",
};

/// `Composite:SubSecDateTimeOriginal` (Exif.pm:5164). `Require`s
/// `EXIF:DateTimeOriginal`, `Desire`s `EXIF:SubSecTimeOriginal` +
/// `EXIF:OffsetTimeOriginal`; the shared `%subSecConv` assembles the result.
#[cfg(feature = "exif")]
const SUBSEC_DATETIME_ORIGINAL: CompositeDef = CompositeDef {
  name: "SubSecDateTimeOriginal",
  inputs: &[
    req(EXIF_IFDS, "DateTimeOriginal"),
    des(EXIF_IFDS, "SubSecTimeOriginal"),
    des(EXIF_IFDS, "OffsetTimeOriginal"),
  ],
  derive: sub_sec_datetime,
  print_conv: CompositePrintConv::SubSecDateTime,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-SubSecDateTimeOriginal",
};

/// `Composite:SubSecCreateDate` (Exif.pm:5183). `Require`s `EXIF:CreateDate`,
/// `Desire`s `EXIF:SubSecTimeDigitized` + `EXIF:OffsetTimeDigitized`.
#[cfg(feature = "exif")]
const SUBSEC_CREATE_DATE: CompositeDef = CompositeDef {
  name: "SubSecCreateDate",
  inputs: &[
    req(EXIF_IFDS, "CreateDate"),
    des(EXIF_IFDS, "SubSecTimeDigitized"),
    des(EXIF_IFDS, "OffsetTimeDigitized"),
  ],
  derive: sub_sec_datetime,
  print_conv: CompositePrintConv::SubSecDateTime,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-SubSecCreateDate",
};

/// `Composite:SubSecModifyDate` (Exif.pm:5202). `Require`s `EXIF:ModifyDate`,
/// `Desire`s `EXIF:SubSecTime` + `EXIF:OffsetTime`.
#[cfg(feature = "exif")]
const SUBSEC_MODIFY_DATE: CompositeDef = CompositeDef {
  name: "SubSecModifyDate",
  inputs: &[
    req(EXIF_IFDS, "ModifyDate"),
    des(EXIF_IFDS, "SubSecTime"),
    des(EXIF_IFDS, "OffsetTime"),
  ],
  derive: sub_sec_datetime,
  print_conv: CompositePrintConv::SubSecDateTime,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-SubSecModifyDate",
};

/// `Composite:ScaleFactor35efl` (Exif.pm:4817). All 16 documented inputs are
/// `Desire` — bare names (any group) except `2 => 'Composite:DigitalZoom'`
/// (group-prefixed; unported ⇒ always `Missing`). exifast appends `16 => 'Make'`
/// (an extra bare `Desire`) to supply `$$et{Make}` for the Canon-branch check.
#[cfg(feature = "exif")]
const SCALE_FACTOR_35EFL: CompositeDef = CompositeDef {
  name: "ScaleFactor35efl",
  inputs: &[
    bare_des("FocalLength"),              // 0
    bare_des("FocalLengthIn35mmFormat"),  // 1
    des(&["Composite"], "DigitalZoom"),   // 2
    bare_des("FocalPlaneDiagonal"),       // 3
    bare_des("SensorSize"),               // 4
    bare_des("FocalPlaneXSize"),          // 5
    bare_des("FocalPlaneYSize"),          // 6
    bare_des("FocalPlaneResolutionUnit"), // 7
    bare_des("FocalPlaneXResolution"),    // 8
    bare_des("FocalPlaneYResolution"),    // 9
    bare_des("ExifImageWidth"),           // 10
    bare_des("ExifImageHeight"),          // 11
    bare_des("CanonImageWidth"),          // 12
    bare_des("CanonImageHeight"),         // 13
    bare_des("ImageWidth"),               // 14
    bare_des("ImageHeight"),              // 15
    bare_des("Make"),                     // 16 (exifast extra: $$et{Make})
  ],
  derive: scale_factor_35efl,
  print_conv: CompositePrintConv::ScaleFactor35efl,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-ScaleFactor35efl",
};

/// `Composite:FocalLength35efl` (Exif.pm:4804). `Require`s FocalLength (bare),
/// `Desire`s `Composite:ScaleFactor35efl` (so it DEFERS until the scale factor
/// is built — `Composite`-group input drives the fixpoint). Indices `2..=8` are
/// exifast extras (`Make`/`FocalLengthIn35mmFormat`/`FocalPlaneXResolution`/
/// `SensorSize`/`FocalPlaneDiagonal`/`FocalPlaneXSize`/`FocalPlaneYSize` — the
/// full `CalcScaleFactor35efl` sensor set) for the Canon-deferred-ScaleFactor
/// guard (see [`focal_length_35efl`]).
#[cfg(feature = "exif")]
const FOCAL_LENGTH_35EFL: CompositeDef = CompositeDef {
  name: "FocalLength35efl",
  inputs: &[
    bare_req("FocalLength"),                 // 0
    des(&["Composite"], "ScaleFactor35efl"), // 1
    bare_des("Make"),                        // 2 (extra: $$et{Make})
    bare_des("FocalLengthIn35mmFormat"),     // 3 (extra: the simple-path probe)
    bare_des("FocalPlaneXResolution"),       // 4 (extra: sensor-data probe)
    bare_des("SensorSize"),                  // 5 (extra: sensor-data probe)
    bare_des("FocalPlaneDiagonal"),          // 6 (extra: sensor-data probe)
    bare_des("FocalPlaneXSize"),             // 7 (extra: sensor-data probe)
    bare_des("FocalPlaneYSize"),             // 8 (extra: sensor-data probe)
  ],
  derive: focal_length_35efl,
  print_conv: CompositePrintConv::FocalLength35efl,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-FocalLength35efl",
};

/// `Composite:CircleOfConfusion` (Exif.pm:4845). `Require`s
/// `Composite:ScaleFactor35efl` (defers until built).
#[cfg(feature = "exif")]
const CIRCLE_OF_CONFUSION: CompositeDef = CompositeDef {
  name: "CircleOfConfusion",
  inputs: &[req(&["Composite"], "ScaleFactor35efl")],
  derive: circle_of_confusion,
  print_conv: CompositePrintConv::CircleOfConfusion,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-CircleOfConfusion",
};

/// `Composite:HyperfocalDistance` (Exif.pm:4855). `Require`s FocalLength (bare),
/// `Composite:Aperture`, `Composite:CircleOfConfusion` (the two composites defer
/// it until they are built).
#[cfg(feature = "exif")]
const HYPERFOCAL_DISTANCE: CompositeDef = CompositeDef {
  name: "HyperfocalDistance",
  inputs: &[
    bare_req("FocalLength"),
    req(&["Composite"], "Aperture"),
    req(&["Composite"], "CircleOfConfusion"),
  ],
  derive: hyperfocal_distance,
  print_conv: CompositePrintConv::HyperfocalDistance,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-HyperfocalDistance",
};

/// `Composite:DOF` (Exif.pm:4870). `Require`s FocalLength (bare),
/// `Composite:Aperture`, `Composite:CircleOfConfusion`; `Desire`s the focus-
/// distance family (bare names).
#[cfg(feature = "exif")]
const DOF: CompositeDef = CompositeDef {
  name: "DOF",
  inputs: &[
    bare_req("FocalLength"),
    req(&["Composite"], "Aperture"),
    req(&["Composite"], "CircleOfConfusion"),
    bare_des("FocusDistance"),
    bare_des("SubjectDistance"),
    bare_des("ObjectDistance"),
    bare_des("ApproximateFocusDistance"),
    bare_des("FocusDistanceLower"),
    bare_des("FocusDistanceUpper"),
  ],
  derive: dof,
  print_conv: CompositePrintConv::Dof,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-DOF",
};

/// `Composite:FOV` (Exif.pm:4913). `Require`s FocalLength (bare),
/// `Composite:ScaleFactor35efl`; `Desire`s FocusDistance (bare).
#[cfg(feature = "exif")]
const FOV: CompositeDef = CompositeDef {
  name: "FOV",
  inputs: &[
    bare_req("FocalLength"),
    req(&["Composite"], "ScaleFactor35efl"),
    bare_des("FocusDistance"),
  ],
  derive: fov,
  print_conv: CompositePrintConv::Fov,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-FOV",
};

/// `Composite:LightValue` (Exif.pm:4791). `Require`s `Composite:Aperture`,
/// `Composite:ShutterSpeed`, ISO (bare). The ValueConv reads `$prt[2]` (ISO's
/// PrintConv value), supplied to [`light_value`] via the `prts` array.
#[cfg(feature = "exif")]
const LIGHT_VALUE: CompositeDef = CompositeDef {
  name: "LightValue",
  inputs: &[
    req(&["Composite"], "Aperture"),
    req(&["Composite"], "ShutterSpeed"),
    bare_req("ISO"),
  ],
  derive: light_value,
  print_conv: CompositePrintConv::LightValue,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "Composite-LightValue",
};

/// `Composite:AvgBitrate` (QuickTime.pm:8649). `Require`s `QuickTime:
/// MediaDataSize` + `QuickTime:Duration`. `Priority => 0` (lets the
/// `QuickTime::AvgBitrate` track tag take precedence when both exist). The
/// RawConv's `$$self{TimeScale}` + `NextTagKey('MediaDataSize')`-sum are
/// threaded via [`CompositeContext`].
#[cfg(feature = "quicktime")]
const AVG_BITRATE: CompositeDef = CompositeDef {
  name: "AvgBitrate",
  inputs: &[
    req(&["QuickTime"], "MediaDataSize"),
    req(&["QuickTime"], "Duration"),
  ],
  derive: avg_bitrate,
  print_conv: CompositePrintConv::AvgBitrate,
  sub_doc: SubDoc::No,
  // QuickTime.pm:8650 `Priority => 0` — never overrides a duplicate.
  priority: 0,
  sort_key: "QuickTime-AvgBitrate",
};

/// `Composite:Rotation` (QuickTime.pm:8646). `Require`s `QuickTime:
/// MatrixStructure` + `QuickTime:HandlerType` (the BUILD gate — both must
/// exist); the value is `CalcRotation($self)`, the `vide`-track matrix angle,
/// pre-computed into [`CompositeContext::rotation`].
#[cfg(feature = "quicktime")]
const ROTATION: CompositeDef = CompositeDef {
  name: "Rotation",
  inputs: &[
    // `QuickTime:MatrixStructure`/`HandlerType` are TRACK-level (family-0
    // `QuickTime`, family-1 `Track<N>`) — a family-0-qualified match, not the
    // movie-level family-1 `QuickTime` one (which `HandlerType` never carries).
    qt_req("MatrixStructure"),
    qt_req("HandlerType"),
  ],
  derive: rotation,
  print_conv: CompositePrintConv::Rotation,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "QuickTime-Rotation",
};

/// `Sony:Composite:GPSDateTime` (Sony.pm:10929). Group2 `Time`. The Sony rtmd
/// timed-GPS analogue of `GPS:Composite:GPSDateTime`: `Require`s the family-0-
/// qualified `Sony:GPSDateStamp` + `Sony:GPSTimeStamp` (the per-sample rtmd GPS
/// tags), so it builds a `Doc<N>:Composite:GPSDateTime` ONLY for a Sony rtmd
/// (family-0 `Sony`), NOT GoPro/camm/mebx. `SubDoc => 1` ⇒ per `Doc<N>`.
#[cfg(feature = "quicktime")]
const SONY_GPS_DATETIME: CompositeDef = CompositeDef {
  name: "GPSDateTime",
  inputs: &[sony_req("GPSDateStamp"), sony_req("GPSTimeStamp")],
  derive: gps_datetime,
  print_conv: CompositePrintConv::GpsDateTime,
  sub_doc: SubDoc::All, // Sony.pm:10931 `SubDoc => 1`.
  priority: 1,
  // Sony's prefix is `Image::ExifTool::Sony`, so the Composite id sorts as
  // `Sony-GPSDateTime` — AFTER the cross-module `GPS-…` defs.
  sort_key: "Sony-GPSDateTime",
};

/// `Sony:Composite:GPSLatitude` (Sony.pm:10940). Group2 `Location`. `Require`s
/// `Sony:GPSLatitude` + `Sony:GPSLatitudeRef` (family-0 `Sony`); the ValueConv
/// is the same `^S`-negates rule as the GPS def. Builds per `Doc<N>` for Sony.
#[cfg(feature = "quicktime")]
const SONY_GPS_LATITUDE: CompositeDef = CompositeDef {
  name: "GPSLatitude",
  inputs: &[sony_req("GPSLatitude"), sony_req("GPSLatitudeRef")],
  derive: gps_latitude,
  print_conv: CompositePrintConv::GpsCoordinate('N'),
  sub_doc: SubDoc::All, // Sony.pm:10941 `SubDoc => 1`.
  priority: 1,
  sort_key: "Sony-GPSLatitude",
};

/// `Sony:Composite:GPSLongitude` (Sony.pm:10950). Group2 `Location`. `Require`s
/// `Sony:GPSLongitude` + `Sony:GPSLongitudeRef` (family-0 `Sony`); `^W` negates.
#[cfg(feature = "quicktime")]
const SONY_GPS_LONGITUDE: CompositeDef = CompositeDef {
  name: "GPSLongitude",
  inputs: &[sony_req("GPSLongitude"), sony_req("GPSLongitudeRef")],
  derive: gps_longitude,
  print_conv: CompositePrintConv::GpsCoordinate('E'),
  sub_doc: SubDoc::All, // Sony.pm:10951 `SubDoc => 1`.
  priority: 1,
  sort_key: "Sony-GPSLongitude",
};

/// `Composite:Duration` (RIFF/AVI, RIFF.pm:1549). `Require`s `RIFF:FrameRate` +
/// `RIFF:FrameCount`, `Desire`s `VideoFrameRate` + `VideoFrameCount` (bare).
/// `CalcDuration` single-document path (the AVI fixtures are not multi-stream).
#[cfg(feature = "riff")]
const RIFF_DURATION: CompositeDef = CompositeDef {
  name: "Duration",
  inputs: &[
    req(&["RIFF"], "FrameRate"),
    req(&["RIFF"], "FrameCount"),
    des(&[], "VideoFrameRate"),
    des(&[], "VideoFrameCount"),
  ],
  derive: riff_duration,
  print_conv: CompositePrintConv::ConvertDuration,
  sub_doc: SubDoc::No,
  priority: 1,
  sort_key: "RIFF-Duration",
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
  #[cfg(feature = "exif")]
  IMAGE_SIZE,
  #[cfg(feature = "exif")]
  MEGAPIXELS,
  #[cfg(feature = "exif")]
  SHUTTER_SPEED,
  #[cfg(feature = "exif")]
  APERTURE,
  #[cfg(feature = "exif")]
  SUBSEC_DATETIME_ORIGINAL,
  #[cfg(feature = "exif")]
  SUBSEC_CREATE_DATE,
  #[cfg(feature = "exif")]
  SUBSEC_MODIFY_DATE,
  #[cfg(feature = "exif")]
  SCALE_FACTOR_35EFL,
  #[cfg(feature = "exif")]
  FOCAL_LENGTH_35EFL,
  #[cfg(feature = "exif")]
  CIRCLE_OF_CONFUSION,
  #[cfg(feature = "exif")]
  HYPERFOCAL_DISTANCE,
  #[cfg(feature = "exif")]
  DOF,
  #[cfg(feature = "exif")]
  FOV,
  #[cfg(feature = "exif")]
  LIGHT_VALUE,
  #[cfg(feature = "quicktime")]
  AVG_BITRATE,
  #[cfg(feature = "quicktime")]
  ROTATION,
  #[cfg(feature = "quicktime")]
  SONY_GPS_DATETIME,
  #[cfg(feature = "quicktime")]
  SONY_GPS_LATITUDE,
  #[cfg(feature = "quicktime")]
  SONY_GPS_LONGITUDE,
  #[cfg(feature = "riff")]
  RIFF_DURATION,
];
