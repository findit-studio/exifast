//! The `ScaleFactor35efl` lens-chain helpers — faithful transliterations of
//! `CalcScaleFactor35efl` (Exif.pm:5451), `CalculateLV` (Exif.pm:5425), the
//! `Image::ExifTool::ToFloat` numeric coercion (ExifTool.pm:5969), and the
//! PrintConv formatters for the seven `Composite:*` lens tags
//! (`ScaleFactor35efl`/`FocalLength35efl`/`CircleOfConfusion`/
//! `HyperfocalDistance`/`DOF`/`FOV`/`LightValue`, Exif.pm:4791-4940).
//!
//! ## The `ToFloat` coercion (ExifTool.pm:5969)
//!
//! Every lens ValueConv opens with `ToFloat(@val)`, which mutates each input
//! `$val[i]` IN PLACE to the leading float it matches (`$1 + 0`) or to `undef`
//! if it matches no float. exifast models the resolved input as a
//! [`CompositeValue`](crate::composite::table::CompositeValue) and coerces it
//! through [`to_float`] — `Some(prefix_value)` when the value yields a leading
//! float (a numeric scalar passes through; a string matches the `ToFloat`
//! regex), `None` (Perl `undef`) otherwise. The subsequent `$val[i] || default`
//! / `unless $val[i]` / `defined $val[i]` guards then read the coerced
//! `Option<f64>`, faithful to the mutated Perl array.
//!
//! ## The constants — byte-exact
//!
//! The 35mm-frame diagonal `sqrt(36*36+24*24)` (the `ScaleFactor35efl`
//! numerator, Exif.pm:5510) and `sqrt(24*24+36*36)` (the `CircleOfConfusion`
//! numerator, Exif.pm:4849) are the SAME value (`43.2666153055679`) computed
//! at runtime so the bytes match Perl's evaluation exactly; the `FOV` literal
//! `3.14159` (Exif.pm:4932 — a TRUNCATED pi, NOT `std::f64::consts::PI`) is
//! carried verbatim.
//!
//! ## The deferred Canon branch
//!
//! `CalcScaleFactor35efl` (Exif.pm:5464) has a `Make eq 'Canon'` branch that
//! refines the sensor diagonal via `Canon::CalcSensorDiag`. [`calc_scale_factor_35efl`]
//! ports the GENERIC path only and signals the Canon case via
//! [`ScaleFactorOutcome::CanonBranch`] so the engine can DEFER a Canon fixture's
//! `ScaleFactor35efl` rather than emit a wrong value. The allow-listed lens
//! fixtures all take the simplest `$foc35 / $focal` path (they carry BOTH
//! `FocalLength` and `FocalLengthIn35mmFormat`), so the Canon branch is reached
//! by no built golden — the only `Make eq 'Canon'` still (`Exif.tif`) has no
//! `FocalLengthIn35mmFormat`, so bundled ExifTool itself emits NO
//! `ScaleFactor35efl` for it (its `FocalLength35efl` comes from `FocalLength`
//! alone).

#[cfg(feature = "alloc")]
use crate::composite::table::CompositeValue;

/// `Image::ExifTool::ToFloat($val)` (ExifTool.pm:5969) on a resolved Composite
/// input: the leading float the value matches (`$1 + 0`), or `None` (Perl
/// `undef`) if it matches no float.
///
/// ```perl
/// $_ = /((?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee](?:[+-]?\d+))?)/ ? $1 + 0 : undef;
/// ```
///
/// ## The `%.15g` stringify-reparse (load-bearing)
///
/// `ToFloat`'s `$1 + 0` matches the regex against `$_` in STRING context, so a
/// numeric NV input is FIRST stringified with Perl's default `%.15g` and the
/// captured 15-significant-figure decimal is reparsed (`$1 + 0`). A NV carrying
/// more than 15 significant figures (a COMPOSITE ingredient — `Composite:
/// CircleOfConfusion` is `0.005423350043510417`, `Composite:ScaleFactor35efl`
/// is `5.5401662049861494…`) therefore enters the lens arithmetic ROUNDED to
/// `%.15g`, NOT at full f64 precision. Skipping this round-trip diverges by 1
/// ULP in the 15th figure (`Composite:HyperfocalDistance` `…604` vs `…605`,
/// `Composite:DOF` far-limit `…809` vs `…808`). So this helper applies
/// [`crate::value::format_g`]`(_, 15)` then reparses every numeric input —
/// faithful to `ToFloat`'s string-context match. (A 15-or-fewer-sig-fig value —
/// the EXIF `FocalLength`/`FNumber` — round-trips unchanged.)
///
/// A genuinely-numeric scalar ([`I64`](crate::value::TagValue::I64) /
/// [`U64`](crate::value::TagValue::U64) / [`F64`](crate::value::TagValue::F64))
/// is `%.15g`-round-tripped (a non-finite `F64` is kept — its Perl spelling
/// fails the float regex, mirroring `ToFloat` mapping it to `undef`, so it is
/// `None`). A [`Str`](crate::value::TagValue::Str) is matched by ExifTool's
/// `ToFloat` regex — a LEADING float prefix (`"50mm"` → `50`, `"9.1"` → `9.1`)
/// coerces via [`crate::convert::perl_str_to_f64`] on the matched prefix; a
/// non-matching string (`"undef"`, `"inf"`, `""`) is `None`. Any other present
/// shape, or a [`Missing`](CompositeValue::Missing) input, is `None`.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn to_float(v: &CompositeValue) -> Option<f64> {
  use crate::value::TagValue;
  match v.value()? {
    // `$1 + 0` on the stringified NV: `%.15g` then reparse (the round-trip).
    TagValue::I64(n) => Some(reparse_15g(*n as f64)),
    TagValue::U64(n) => Some(reparse_15g(*n as f64)),
    // A non-finite f64 fails `ToFloat`'s float regex (its `Inf`/`NaN` spelling) ⇒
    // `undef`; a finite f64 is `%.15g`-reparsed.
    TagValue::F64(x) => x.is_finite().then(|| reparse_15g(*x)),
    // A raw `Rational` ingredient `ToFloat`s through its ExifTool ValueConv
    // STRING (`Rational::exiftool_val_str` — the `%g`-rounded quotient, or
    // `"inf"`/`"undef"` for a zero denominator): a Canon CTMD `Track1:FocalLength`
    // kept as `Rational(15/1)` `ToFloat`s to `15.0`, while a zero-denominator one
    // hits `ToFloat`'s `"inf"`/`"undef"`-is-non-float path ⇒ `None` — the same
    // as if the rational had ValueConv'd to a scalar/string first.
    TagValue::Rational(r) => to_float_str(&r.exiftool_val_str()),
    TagValue::Str(s) => to_float_str(s),
    _ => None,
  }
}

/// `$1 + 0` on a numeric NV's `%.15g` stringification — the round-trip that
/// `ToFloat`'s string-context regex match performs (see [`to_float`]). A finite
/// f64 with ≤15 significant figures round-trips unchanged; one with more is
/// rounded to its 15-sig-fig decimal.
#[cfg(feature = "alloc")]
#[must_use]
fn reparse_15g(x: f64) -> f64 {
  crate::convert::perl_str_to_f64(&crate::value::format_g(x, 15))
}

/// `ToFloat` on a STRING: the FIRST float `ToFloat`'s regex matches ANYWHERE in
/// the string as `$1 + 0`, or `None`.
///
/// ExifTool's regex `/((?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee](?:[+-]?\d+))?)/`
/// is UNANCHORED (no `^`/`\G`): `$_ =~ /.../` scans for the FIRST substring that
/// matches — an optional sign, then a digit-or-`.digit`-led mantissa with an
/// optional exponent — anywhere in the value, not just at the start. So a
/// labelled/prefixed value still contributes its first numeric run: `"f/2.8"` →
/// `2.8`, `"Auto ISO 100"` → `100`, `"foo50mm"` → `50`, `" 50mm"` → `50`,
/// `"1.5 m"` → `1.5`. [`to_float_capture`] returns the EXACT span of `$1` (start
/// AND end), and [`parse_captured_float`] parses ONLY that captured substring as
/// a plain `f64` — `$1 + 0`. A string with no numeric run (`""`, `"abc"`,
/// `"inf"`, a bare `"+"`) yields no match ⇒ `None`.
///
/// `$1` captures ONLY the digit-grammar run — never an `inf`/`nan`/MSVCRT
/// spelling. Parsing the exact capture (rather than the rest-of-string via
/// [`crate::convert::perl_str_to_f64`], whose Perl-numeric coercion ALSO
/// recognises `"inf"`/`"nan"`/MSVCRT `1.#INF`) is the structural guarantee that
/// nothing past the capture can ever be over-read: `"1.#INF"` captures `"1."` →
/// `1`, `"foo1.#NAN"` captures `"1."` → `1`, `"1.5e3xyz"` captures `"1.5e3"` →
/// `1500`. A leading `inf`/`nan` (which the regex never matches) is `undef`,
/// exactly like Perl.
#[cfg(feature = "alloc")]
#[must_use]
fn to_float_str(s: &str) -> Option<f64> {
  to_float_capture(s).map(|(start, end)| parse_captured_float(&s[start..end]))
}

/// The EXACT byte span `(start, end)` of the FIRST substring of `s` that
/// ExifTool's `ToFloat` regex
/// `/((?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee](?:[+-]?\d+))?)/` matches — i.e.
/// `$1`, the captured float — or `None` if the value carries no float at all.
/// The shared numeric scanner behind BOTH [`to_float_str`] and [`lv_arg`]
/// (`CalculateLV` uses the SAME regex, Exif.pm:5431).
///
/// Returning the END offset (not just the start) is the load-bearing structural
/// guarantee: `s[start..end]` is EXACTLY the regex capture `$1`, so a caller can
/// parse it with a plain float parse and NEVER over-read the trailing bytes
/// (which Perl's `$1` excludes). Without the end bound a caller that parses the
/// whole rest-of-string can over-read a trailing MSVCRT non-finite spelling
/// (`"1.#INF"`, `"foo1.#NAN"`) — the regex captures only `"1."` there, which
/// Perl numifies to a FINITE `1`.
///
/// The regex is UNANCHORED, so Perl tries each position left-to-right until one
/// matches. At a position the regex matches iff (mirroring `[+-]?` then the
/// `(?=\d|\.\d)` lookahead): the byte is a digit, or a `.` directly followed by a
/// digit (the no-sign alternative); or a `+`/`-` whose NEXT byte begins such a
/// mantissa (the signed alternative, whose match — and thus `$1` — INCLUDES the
/// sign). A `+`/`-` not directly followed by a digit/`.digit` does not start a
/// match (the optional sign cannot stand alone, and the lookahead rejects a sign
/// byte), so the scan advances past it — `"++3"` matches `"+3"` at offset 1.
///
/// Once a match position is found, the capture extends GREEDILY through the
/// mantissa `\d*(?:\.\d*)?` then an OPTIONAL exponent `(?:[Ee](?:[+-]?\d+))?`,
/// stopping at the first non-matching byte: the `#` in `"1.#INF"` stops the
/// capture at `"1."`, and a bare `[Ee]` with no following power digit is NOT
/// consumed (`"1.5e"` captures `"1.5"`, `"1.5ex"` captures `"1.5"`).
///
/// Distinct from [`crate::convert::is_float_norm`] (a WHOLE-string anchored
/// match with a comma-locale branch): `ToFloat` is a first-run scan with NO
/// comma branch, so `"12,5"` matches the run `12` (the comma ends it).
#[must_use]
fn to_float_capture(s: &str) -> Option<(usize, usize)> {
  let bytes = s.as_bytes();
  // A mantissa begins at `j` iff `(?=\d|\.\d)` holds there: a digit, or a `.`
  // immediately followed by a digit.
  let mantissa_at = |j: usize| match bytes.get(j) {
    Some(b) if b.is_ascii_digit() => true,
    Some(&b'.') => matches!(bytes.get(j + 1), Some(d) if d.is_ascii_digit()),
    _ => false,
  };
  let start = (0..bytes.len()).find(|&i| {
    // No-sign alternative: the mantissa starts right at `i`.
    if mantissa_at(i) {
      return true;
    }
    // Signed alternative: a `+`/`-` directly followed by a mantissa. `$1` (and
    // hence the start) includes the sign, so the start stays at `i`.
    matches!(bytes.get(i), Some(b'+' | b'-')) && mantissa_at(i + 1)
  })?;
  Some((start, to_float_capture_end(bytes, start)))
}

/// Given the matched START of `$1` (from [`to_float_capture`]), the END offset
/// the regex `((?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee](?:[+-]?\d+))?)` consumes:
/// the optional sign, then `\d*(?:\.\d*)?` (integer digits, an optional dot, more
/// digits), then an OPTIONAL `[Ee][+-]?\d+` exponent (consumed only with ≥1 power
/// digit). Mirrors [`crate::convert::matches_float_shape`]'s consumption, minus
/// the `$` anchor (the capture stops at the first non-matching byte rather than
/// requiring the whole string).
#[must_use]
fn to_float_capture_end(bytes: &[u8], start: usize) -> usize {
  let mut i = start;
  // The optional sign `[+-]?` (the lookahead guaranteed a mantissa follows it).
  if matches!(bytes.get(i), Some(b'+' | b'-')) {
    i += 1;
  }
  // `\d*` integer digits.
  while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
    i += 1;
  }
  // `(?:\.\d*)?` — an optional dot then zero-or-more fraction digits.
  if bytes.get(i) == Some(&b'.') {
    i += 1;
    while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
      i += 1;
    }
  }
  // `(?:[Ee](?:[+-]?\d+))?` — optional exponent with a MANDATORY ≥1-digit power.
  // Consume it only if a full power follows; otherwise the `[Ee]` is excluded
  // from `$1` (`"1.5e"`/`"1.5ex"` capture `"1.5"`).
  if matches!(bytes.get(i), Some(b'e' | b'E')) {
    let mut j = i + 1;
    if matches!(bytes.get(j), Some(b'+' | b'-')) {
      j += 1;
    }
    let power_start = j;
    while matches!(bytes.get(j), Some(b) if b.is_ascii_digit()) {
      j += 1;
    }
    if j > power_start {
      i = j; // a full exponent — include it in the capture.
    }
  }
  i
}

/// `$1 + 0` on the EXACT regex capture from [`to_float_capture`]: a PLAIN float
/// parse of the captured substring, with NO `inf`/`nan`/MSVCRT recognition.
///
/// This is the structural close of the `ToFloat` over-read class: the captured
/// span is, by construction, the digit-grammar run `[+-]?\d*(\.\d*)?([eE]…)?`, so
/// it can NEVER be `"inf"`/`"nan"`/`"1.#INF"` — and parsing ONLY it (not the
/// rest of the string) means no MSVCRT/non-finite spelling past the capture can
/// be over-read. Every capture this routine sees is a valid Rust float literal
/// (`"1."`, `".5"`, `"-1."`, `"+3"`, `"1.5e3"` all parse), so the parse cannot
/// fail; the `unwrap_or(0.0)` is a defensive floor matching Perl's `$1 + 0` (a
/// numeric capture is always finite).
#[must_use]
fn parse_captured_float(captured: &str) -> f64 {
  captured.parse::<f64>().unwrap_or(0.0)
}

/// The 35mm-frame diagonal `sqrt(36*36+24*24)` (`ScaleFactor35efl` numerator,
/// Exif.pm:5510) — identical to `CircleOfConfusion`'s `sqrt(24*24+36*36)`
/// (Exif.pm:4849). Evaluated at runtime so the bytes match Perl's `sqrt`.
#[must_use]
pub(crate) fn frame_diag_35mm() -> f64 {
  (36.0 * 36.0 + 24.0 * 24.0_f64).sqrt()
}

/// The outcome of [`calc_scale_factor_35efl`]: a computed factor, the deferred
/// Canon branch, or `undef`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ScaleFactorOutcome {
  /// A computed 35mm scale factor (the generic path produced a value).
  Factor(f64),
  /// The input is `Make eq 'Canon'` AND the simple `$foc35 / $focal` path did
  /// NOT fire (the Canon `CalcSensorDiag` refinement, Exif.pm:5464, would be
  /// needed). The engine DEFERS — emits NO `ScaleFactor35efl` — rather than the
  /// generic value (which would diverge from bundled). See the module note.
  CanonBranch,
  /// `CalcScaleFactor35efl` returned `undef` (no usable sensor data).
  Undef,
}

/// The resolved `ScaleFactor35efl` inputs (Exif.pm:4825-4842), as the engine
/// hands them — index-aligned to ExifTool's `@val` (post the `$self` shift). All
/// `Desire`, so each is `Option`.
#[cfg(feature = "alloc")]
pub(crate) struct ScaleFactorInputs<'a> {
  /// `0` FocalLength, `1` FocalLengthIn35mmFormat, `2` Composite:DigitalZoom.
  pub(crate) focal: Option<&'a CompositeValue>,
  pub(crate) foc35: Option<&'a CompositeValue>,
  pub(crate) digital_zoom: Option<&'a CompositeValue>,
  /// `3` FocalPlaneDiagonal, `4` SensorSize, `5` FocalPlaneXSize, `6` FocalPlaneYSize.
  pub(crate) focal_plane_diagonal: Option<&'a CompositeValue>,
  pub(crate) sensor_size: Option<&'a CompositeValue>,
  pub(crate) focal_plane_x_size: Option<&'a CompositeValue>,
  pub(crate) focal_plane_y_size: Option<&'a CompositeValue>,
  /// `7` FocalPlaneResolutionUnit, `8` FocalPlaneXResolution, `9` FocalPlaneYResolution.
  pub(crate) resolution_unit: Option<&'a CompositeValue>,
  pub(crate) x_resolution: Option<&'a CompositeValue>,
  pub(crate) y_resolution: Option<&'a CompositeValue>,
  /// `10..=15` the image width/height pairs in precedence order: ExifImage,
  /// CanonImage, Image.
  pub(crate) size_pairs: [(Option<&'a CompositeValue>, Option<&'a CompositeValue>); 3],
}

/// `Image::ExifTool::Exif::CalcScaleFactor35efl($self, @val)` (Exif.pm:5451) —
/// the GENERIC path. Returns the 35mm conversion factor, the deferred
/// [`CanonBranch`](ScaleFactorOutcome::CanonBranch), or
/// [`Undef`](ScaleFactorOutcome::Undef).
///
/// ```perl
/// my $res = $_[7];               # save resolution units (raw, pre-ToFloat)
/// my $sensXY = $_[4];            # SensorSize string (raw, for the / (\d+...)$/ tail)
/// ToFloat(@_);
/// my $focal = shift; my $foc35 = shift;
/// return $foc35 / $focal if $focal and $foc35;
/// my $digz = shift || 1; my $diag = shift; my $sens = shift;
/// if ($$et{Make} eq 'Canon') { ... CalcSensorDiag ... }     # DEFERRED
/// unless ($diag and IsFloat($diag)) {
///     if ($sens and $sensXY =~ / (\d+(\.?\d*)?)$/) {
///         $diag = sqrt($sens * $sens + $1 * $1);
///     } else {
///         undef $diag; my $xsize = shift; my $ysize = shift;
///         if ($xsize and $ysize) {
///             my $a = $xsize / $ysize;
///             if (abs($a-1.3333) < .1 or abs($a-1.5) < .1) {
///                 $diag = sqrt($xsize * $xsize + $ysize * $ysize);
///             }
///         }
///         unless ($diag) {
///             my %lkup = ( 3=>10, 4=>1, 5=>0.001, cm=>10, mm=>1, um=>0.001 );
///             my $units = $lkup{ shift() || $res || '' } || 25.4;
///             my $x_res = shift || return undef;
///             my $y_res = shift || $x_res;
///             IsFloat($x_res) and $x_res != 0 or return undef;
///             IsFloat($y_res) and $y_res != 0 or return undef;
///             my ($w, $h);
///             for (;;) {
///                 @_ < 2 and return undef;
///                 $w = shift; $h = shift;
///                 next unless $w and $h;
///                 my $a = $w / $h;
///                 last if $a > 0.5 and $a < 2;
///             }
///             $w *= $units / $x_res; $h *= $units / $y_res;
///             $diag = sqrt($w*$w+$h*$h);
///             return undef unless $diag > 1 and $diag < 100;
///         }
///     }
/// }
/// return sqrt(36*36+24*24) * $digz / $diag;
/// ```
///
/// `is_canon` is `$$et{Make} eq 'Canon'` (resolved by the caller from the FINAL
/// `Make` tag, since the post-pass has no ExifTool object). When `is_canon` is
/// true AND the simple `$foc35 / $focal` path does not fire, the routine
/// returns [`CanonBranch`](ScaleFactorOutcome::CanonBranch) WITHOUT attempting
/// the generic sensor math (the Canon branch would override `$diag`, so the
/// generic result would be wrong) — the engine then defers.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn calc_scale_factor_35efl(
  is_canon: bool,
  inputs: &ScaleFactorInputs<'_>,
) -> ScaleFactorOutcome {
  // `$res = $_[7]` — the raw FocalPlaneResolutionUnit BEFORE ToFloat (it may be
  // a unit STRING `"cm"`/`"mm"`/`"um"`, used as a %lkup key).
  let res_raw_key = inputs
    .resolution_unit
    .and_then(CompositeValue::value)
    .map(crate::composite::value_text);
  // `$sensXY = $_[4]` — the raw SensorSize string (for the ` (\d+...)$/` Y tail).
  let sens_xy_raw = inputs
    .sensor_size
    .and_then(CompositeValue::value)
    .map(crate::composite::value_text);

  // `ToFloat(@_)` then `$focal = shift; $foc35 = shift`.
  let focal = inputs.focal.and_then(to_float);
  let foc35 = inputs.foc35.and_then(to_float);

  // `return $foc35 / $focal if $focal and $foc35` (Perl-truthy: nonzero).
  if let (Some(fo), Some(f35)) = (focal, foc35)
    && perl_truthy_f64(fo)
    && perl_truthy_f64(f35)
  {
    return ScaleFactorOutcome::Factor(f35 / fo);
  }

  // The Canon branch refines `$diag` via Canon::CalcSensorDiag; DEFER (the
  // generic math below would produce a wrong factor for a Canon body).
  if is_canon {
    return ScaleFactorOutcome::CanonBranch;
  }

  // `$digz = shift || 1` — DigitalZoom (Perl-truthy default 1).
  let digz = match inputs.digital_zoom.and_then(to_float) {
    Some(z) if perl_truthy_f64(z) => z,
    _ => 1.0,
  };
  // `$diag = shift` — FocalPlaneDiagonal; `$sens = shift` — SensorSize (numeric).
  let mut diag = inputs.focal_plane_diagonal.and_then(to_float);
  let sens = inputs.sensor_size.and_then(to_float);

  // `unless ($diag and IsFloat($diag))` — a present, finite, Perl-truthy diagonal
  // is used directly; otherwise compute it. (`ToFloat` already yields a float or
  // `None`; the `IsFloat($diag)` re-check fails only for a non-finite value,
  // which `ToFloat` of a numeric scalar could carry.)
  let diag_ok = diag.is_some_and(|d| perl_truthy_f64(d) && d.is_finite());
  if !diag_ok {
    // `if ($sens and $sensXY =~ / (\d+(\.?\d*)?)$/)` — SensorSize numeric + the
    // raw string has a trailing ` <number>` (the Y dimension). (Perl's `undef
    // $diag` lives in the `else` arm below; the `if` arm overwrites `$diag`.)
    if let (Some(s), Some(xy)) = (sens, sens_xy_raw.as_deref())
      && perl_truthy_f64(s)
      && let Some(y) = sensor_xy_trailing(xy)
    {
      diag = Some((s * s + y * y).sqrt());
    } else {
      // `undef $diag; $xsize = shift; $ysize = shift`.
      diag = None;
      let xsize = inputs.focal_plane_x_size.and_then(to_float);
      let ysize = inputs.focal_plane_y_size.and_then(to_float);
      // `if ($xsize and $ysize)` — validate aspect ratio (4:3 or 3:2 ± .1).
      if let (Some(xs), Some(ys)) = (xsize, ysize)
        && perl_truthy_f64(xs)
        && perl_truthy_f64(ys)
      {
        let a = xs / ys;
        if (a - 1.3333).abs() < 0.1 || (a - 1.5).abs() < 0.1 {
          diag = Some((xs * xs + ys * ys).sqrt());
        }
      }
      // `unless ($diag)` — derive the diagonal from resolution + image size.
      if diag.is_none_or(|d| !perl_truthy_f64(d)) {
        match diag_from_resolution(inputs, res_raw_key.as_deref()) {
          DiagOutcome::Diag(d) => diag = Some(d),
          DiagOutcome::Undef => return ScaleFactorOutcome::Undef,
        }
      }
    }
  }

  // `return sqrt(36*36+24*24) * $digz / $diag`.
  match diag {
    Some(d) => ScaleFactorOutcome::Factor(frame_diag_35mm() * digz / d),
    None => ScaleFactorOutcome::Undef,
  }
}

/// The `unless ($diag)` resolution-derived-diagonal branch outcome.
#[cfg(feature = "alloc")]
enum DiagOutcome {
  Diag(f64),
  Undef,
}

/// The `unless ($diag) { ... }` block of `CalcScaleFactor35efl` (Exif.pm:5488):
/// derive the focal-plane diagonal from FocalPlaneResolutionUnit + X/Y
/// resolution + the first reasonable-aspect image-size pair.
///
/// ```perl
/// my %lkup = ( 3=>10, 4=>1, 5=>0.001, cm=>10, mm=>1, um=>0.001 );
/// my $units = $lkup{ shift() || $res || '' } || 25.4;   # default inches
/// my $x_res = shift || return undef;
/// my $y_res = shift || $x_res;
/// IsFloat($x_res) and $x_res != 0 or return undef;
/// IsFloat($y_res) and $y_res != 0 or return undef;
/// for (;;) { @_ < 2 and return undef; $w = shift; $h = shift; next unless $w and $h;
///            last if $w/$h > 0.5 and $w/$h < 2; }
/// $w *= $units / $x_res; $h *= $units / $y_res;
/// $diag = sqrt($w*$w+$h*$h);
/// return undef unless $diag > 1 and $diag < 100;
/// ```
///
/// `res_raw_key` is `$res` (the raw FocalPlaneResolutionUnit, possibly a unit
/// string). The `shift()` at the front of `$lkup{...}` is the post-ToFloat
/// resolution unit (a number `3`/`4`/`5`, or `undef` ⇒ falls back to `$res`).
#[cfg(feature = "alloc")]
fn diag_from_resolution(inputs: &ScaleFactorInputs<'_>, res_raw_key: Option<&str>) -> DiagOutcome {
  // `$units = $lkup{ shift() || $res || '' } || 25.4`. The `shift()` is the
  // post-ToFloat ResolutionUnit; a Perl-truthy float renders as its integer key
  // ("3"/"4"/"5"); else fall back to `$res` (the raw string), else `''`.
  let unit_float = inputs.resolution_unit.and_then(to_float);
  let units = lookup_units(unit_float, res_raw_key);

  // `$x_res = shift || return undef` — X resolution, Perl-truthy else undef.
  let x_res = match inputs.x_resolution.and_then(to_float) {
    Some(x) if perl_truthy_f64(x) => x,
    _ => return DiagOutcome::Undef,
  };
  // `$y_res = shift || $x_res` — Y resolution, Perl-truthy else X.
  let y_res = match inputs.y_resolution.and_then(to_float) {
    Some(y) if perl_truthy_f64(y) => y,
    _ => x_res,
  };
  // `IsFloat($x_res) and $x_res != 0 or return undef` — both must be finite,
  // non-zero floats. `to_float` already produced a float; reject non-finite/0.
  if !x_res.is_finite() || x_res == 0.0 {
    return DiagOutcome::Undef;
  }
  if !y_res.is_finite() || y_res == 0.0 {
    return DiagOutcome::Undef;
  }

  // `for (;;) { ... }` over the (width,height) pairs in precedence order: take
  // the FIRST pair whose ratio is reasonable (0.5 < w/h < 2). A pair with a
  // falsy member is skipped; running out of pairs ⇒ undef.
  let mut wh: Option<(f64, f64)> = None;
  for (w_in, h_in) in inputs.size_pairs {
    let w = w_in.and_then(to_float);
    let h = h_in.and_then(to_float);
    // `next unless $w and $h` (Perl-truthy).
    let (Some(w), Some(h)) = (w, h) else { continue };
    if !perl_truthy_f64(w) || !perl_truthy_f64(h) {
      continue;
    }
    let a = w / h;
    if a > 0.5 && a < 2.0 {
      wh = Some((w, h));
      break;
    }
  }
  let Some((mut w, mut h)) = wh else {
    // `@_ < 2 and return undef` — exhausted the pairs without a reasonable one.
    return DiagOutcome::Undef;
  };

  // `$w *= $units / $x_res; $h *= $units / $y_res; $diag = sqrt($w*$w+$h*$h)`.
  w *= units / x_res;
  h *= units / y_res;
  let diag = (w * w + h * h).sqrt();
  // `return undef unless $diag > 1 and $diag < 100`.
  if diag > 1.0 && diag < 100.0 {
    DiagOutcome::Diag(diag)
  } else {
    DiagOutcome::Undef
  }
}

/// `$lkup{ shift() || $res || '' } || 25.4` (Exif.pm:5489): the mm-per-unit for
/// the focal-plane resolution unit.
///
/// `%lkup = ( 3=>10, 4=>1, 5=>0.001, cm=>10, mm=>1, um=>0.001 )`. The key is the
/// FIRST Perl-truthy of: the post-ToFloat unit number (`3`/`4`/`5`, rendered as
/// its integer string), the raw `$res` string (`"cm"`/`"mm"`/`"um"` — or a
/// numeric `"3"` if the unit was extracted as a string), or `''`. A key absent
/// from `%lkup` (incl. `1`/`2`/`''`) yields `25.4` (inches — the default).
#[cfg(feature = "alloc")]
#[must_use]
fn lookup_units(unit_float: Option<f64>, res_raw_key: Option<&str>) -> f64 {
  // `shift() || $res || ''` — the first Perl-truthy. The post-ToFloat unit is a
  // float; Perl stringifies it to form the hash key, and a truthy integer-valued
  // unit (3/4/5) becomes "3"/"4"/"5". A falsy/absent unit falls back to $res.
  let key: std::borrow::Cow<'_, str> = match unit_float {
    Some(u) if perl_truthy_f64(u) => std::borrow::Cow::Owned(crate::value::format_g(u, 15)),
    _ => match res_raw_key {
      Some(r) if !r.is_empty() => std::borrow::Cow::Borrowed(r),
      _ => std::borrow::Cow::Borrowed(""),
    },
  };
  match key.as_ref() {
    "3" | "cm" => 10.0,
    "4" | "mm" => 1.0,
    "5" | "um" => 0.001,
    _ => 25.4,
  }
}

/// `$sensXY =~ / (\d+(\.?\d*)?)$/` (Exif.pm:5466): the trailing ` <number>` of a
/// `SensorSize` string (its Y dimension), as a float — or `None` if no match.
///
/// ExifTool's `SensorSize` ValueConv is `"$x $y"` (space-separated mm). The
/// regex captures the LAST whitespace-prefixed number to the end of string.
#[cfg(feature = "alloc")]
#[must_use]
fn sensor_xy_trailing(s: &str) -> Option<f64> {
  // ` (\d+(\.?\d*)?)$` — a space, then `\d+` (mandatory leading digits), an
  // optional `.` and optional fraction digits, anchored to the END.
  let bytes = s.as_bytes();
  // Find the last space; the tail after it must match `\d+(\.?\d*)?`.
  let sp = bytes.iter().rposition(|&b| b == b' ')?;
  let tail = &s[sp + 1..];
  let tb = tail.as_bytes();
  if tb.is_empty() {
    return None;
  }
  let mut i = 0;
  // `\d+` — at least one digit.
  while matches!(tb.get(i), Some(b) if b.is_ascii_digit()) {
    i += 1;
  }
  if i == 0 {
    return None; // no leading digit
  }
  // `(\.?\d*)?` — an optional dot then optional digits.
  if tb.get(i) == Some(&b'.') {
    i += 1;
    while matches!(tb.get(i), Some(b) if b.is_ascii_digit()) {
      i += 1;
    }
  }
  // Anchored to `$`: the whole tail must be consumed.
  if i != tb.len() {
    return None;
  }
  tail.parse::<f64>().ok()
}

/// `Image::ExifTool::Exif::CalculateLV($aperture, $shutter, $iso)`
/// (Exif.pm:5425): the light value, normalized to ISO 100.
///
/// ```perl
/// return undef unless @_ >= 3;
/// foreach (@_) {
///     return undef unless $_ and /([+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?)/ and $1 > 0;
///     $_ = $1;    # extract float from any other garbage
/// }
/// return log($_[0] * $_[0] * 100 / ($_[1] * $_[2])) / log(2);
/// ```
///
/// Each of the three args (`Composite:Aperture`'s `$val[0]`,
/// `Composite:ShutterSpeed`'s `$val[1]`, ISO's `$prt[2]`) is re-validated:
/// present, matches the float regex, AND the captured prefix is `> 0`. Any
/// failure ⇒ `None`. On success the captured prefix replaces the arg (`$_ =
/// $1`) and the formula runs.
///
/// `lv_arg` extracts each arg's leading float prefix and verifies `> 0`; the
/// formula then uses `log(a*a*100/(s*iso))/log(2)` — natural-log base change to
/// log2, byte-exact to Perl.
#[must_use]
pub(crate) fn calculate_lv(aperture: &str, shutter: &str, iso: &str) -> Option<f64> {
  let a = lv_arg(aperture)?;
  let s = lv_arg(shutter)?;
  let i = lv_arg(iso)?;
  // `log($_[0]*$_[0]*100 / ($_[1]*$_[2])) / log(2)`.
  Some((a * a * 100.0 / (s * i)).ln() / 2.0_f64.ln())
}

/// One `CalculateLV` arg (Exif.pm:5431): the captured float prefix, REQUIRED to
/// be present, float-shaped, AND `> 0`.
///
/// `return undef unless $_ and /([+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?)/ and $1 > 0`.
/// The regex is the SAME UNANCHORED first-float scan as `ToFloat` — so a labelled
/// arg still contributes its first numeric run (`"f/2.8"` → `2.8`) — via the
/// shared [`to_float_capture`]; the captured `$1` is parsed by
/// [`parse_captured_float`] (the exact capture, NO non-finite over-read), then
/// `$1 > 0` rejects a non-positive run (`"0"`, `"-1"`, `"ISO 0"`). The `$_`
/// truthiness guard is subsumed by the regex (an empty/zero string fails the
/// `$1 > 0` test).
#[must_use]
fn lv_arg(s: &str) -> Option<f64> {
  let (start, end) = to_float_capture(s)?;
  let v = parse_captured_float(&s[start..end]);
  // `$1 > 0` — the captured first float run must be strictly positive.
  (v > 0.0).then_some(v)
}

/// Perl boolean context on a coerced float: `0.0` (and `-0.0`) is FALSE, every
/// other finite/non-finite value is TRUE. (A `ToFloat` result is a number, so
/// the string-`"0"`-truthy nuance does not apply — `ToFloat` already mapped the
/// scalar to a float; a zero float is the falsy case the `||`/`unless` guards
/// test.)
#[must_use]
fn perl_truthy_f64(v: f64) -> bool {
  v != 0.0
}

/// `Composite:FocalLength35efl` PrintConv (Exif.pm:4815):
/// `$val[1] ? sprintf("%.1f mm (35 mm equivalent: %.1f mm)", $val[0], $val)
///          : sprintf("%.1f mm", $val)`.
///
/// `focal` is `$val[0]` (the lens FocalLength), `scale_factor` is `$val[1]`
/// (`Composite:ScaleFactor35efl`, `None` when not built), `equiv` is the
/// composite's own `$val` (`focal * (scale_factor || 1)`). A present + truthy
/// scale factor takes the two-number form (`"50.0 mm (35 mm equivalent: 75.0
/// mm)"`); otherwise the single-number form (`"50.0 mm"`).
#[must_use]
pub(crate) fn print_focal_length_35efl(
  focal: f64,
  scale_factor: Option<f64>,
  equiv: f64,
) -> String {
  // `$val[1] ?` — Perl-truthy on the (possibly undef) ScaleFactor.
  if scale_factor.is_some_and(perl_truthy_f64) {
    format!("{focal:.1} mm (35 mm equivalent: {equiv:.1} mm)")
  } else {
    format!("{equiv:.1} mm")
  }
}

/// `Composite:CircleOfConfusion` PrintConv (Exif.pm:4853):
/// `sprintf("%.3f mm", $val)`.
#[must_use]
pub(crate) fn print_circle_of_confusion(val: f64) -> String {
  format!("{val:.3} mm")
}

/// `Composite:HyperfocalDistance` PrintConv (Exif.pm:4868):
/// `sprintf("%.2f m", $val)`. When the ValueConv returned the literal `'inf'`
/// (aperture or CoC was 0), `sprintf("%.2f", "inf")` yields Perl's `"Inf"` (its
/// `%f` of a non-numeric `"inf"` string), so the result is `"Inf m"`.
#[must_use]
pub(crate) fn print_hyperfocal(val: f64) -> String {
  // A finite value formats to 2 decimals; the `'inf'` ValueConv sentinel (an
  // f64 INFINITY here) renders as Perl's `sprintf("%.2f", "inf")` = `"Inf"`.
  if val.is_finite() {
    format!("{val:.2} m")
  } else {
    // The `else` arm is reached ONLY for a non-finite `val`, so
    // `perl_nonfinite_str` returns `Some` by construction (it is `None` ONLY
    // for finite inputs). `expect` the invariant rather than silently degrade
    // to a wrong "NaN" token — a `None` here would be a programming-logic bug,
    // never a data edge (#53/FU-12).
    let non_finite = crate::value::perl_nonfinite_str(val)
      .expect("perl_nonfinite_str is Some for every non-finite f64 (is_finite-guarded)");
    format!("{non_finite} m")
  }
}

/// `Composite:DOF` PrintConv (Exif.pm:4894):
///
/// ```perl
/// $val =~ tr/,/./;    # in case locale is whacky
/// my @v = split ' ', $val;
/// $v[1] or return sprintf("inf (%.2f m - inf)", $v[0]);
/// my $dof = $v[1] - $v[0];
/// my $fmt = ($dof>0 and $dof<0.02) ? "%.3f" : "%.2f";
/// return sprintf("$fmt m ($fmt - $fmt m)",$dof,$v[0],$v[1]);
/// ```
///
/// `val` is the DOF ValueConv string `"$near $far"` (`$far` may be `0` ⇒ "inf").
/// The format string switches to `%.3f` only when the depth-of-field is a thin
/// `0 < dof < 0.02`.
#[must_use]
pub(crate) fn print_dof(val: &str) -> String {
  // `$val =~ tr/,/./` then `split ' '` (Perl split-on-whitespace).
  let normalized = val.replace(',', ".");
  let parts: std::vec::Vec<f64> = normalized
    .split_whitespace()
    .map(|t| t.parse::<f64>().unwrap_or(0.0))
    .collect();
  let v0 = parts.first().copied().unwrap_or(0.0);
  let v1 = parts.get(1).copied().unwrap_or(0.0);
  // `$v[1] or return sprintf("inf (%.2f m - inf)", $v[0])`.
  if !perl_truthy_f64(v1) {
    return format!("inf ({v0:.2} m - inf)");
  }
  let dof = v1 - v0;
  // `$fmt = ($dof>0 and $dof<0.02) ? "%.3f" : "%.2f"`.
  if dof > 0.0 && dof < 0.02 {
    format!("{dof:.3} m ({v0:.3} - {v1:.3} m)")
  } else {
    format!("{dof:.2} m ({v0:.2} - {v1:.2} m)")
  }
}

/// `Composite:FOV` PrintConv (Exif.pm:4936):
///
/// ```perl
/// my @v = split(' ',$val);
/// my $str = sprintf("%.1f deg", $v[0]);
/// $str .= sprintf(" (%.2f m)", $v[1]) if $v[1];
/// return $str;
/// ```
///
/// `val` is the FOV ValueConv string `"$angle"` or `"$angle $dist"` (the focus
/// distance is appended only when present). The angle prints to 1 decimal; the
/// optional distance (when Perl-truthy) to 2 with the ` (… m)` suffix.
#[must_use]
pub(crate) fn print_fov(val: &str) -> String {
  let parts: std::vec::Vec<f64> = val
    .split_whitespace()
    .map(|t| t.parse::<f64>().unwrap_or(0.0))
    .collect();
  let v0 = parts.first().copied().unwrap_or(0.0);
  let mut s = format!("{v0:.1} deg");
  if let Some(&v1) = parts.get(1)
    && perl_truthy_f64(v1)
  {
    s.push_str(&format!(" ({v1:.2} m)"));
  }
  s
}

#[cfg(test)]
mod tests;
