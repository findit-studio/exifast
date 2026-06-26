//! The EXIF Composite PrintConv helpers — `PrintExposureTime` (Exif.pm:5701)
//! and `PrintFNumber` (Exif.pm:5715) — that the `Composite:ShutterSpeed` /
//! `Composite:Aperture` defs render through.
//!
//! Both take the composite's own ValueConv result `$val` (a Perl numeric
//! scalar) and gate on `Image::ExifTool::IsFloat($val)`: a NON-FINITE `$val`
//! (its stringified `Inf`/`-Inf`/`NaN` fails the IsFloat regex) is returned
//! UNCHANGED, so it renders as the Perl non-finite spelling. A finite `$val`
//! takes the formatting branch. exifast's `CompositeRaw::Num` is always a
//! plain finite/non-finite `f64`, so the IsFloat split collapses to
//! `f64::is_finite`.

/// `Image::ExifTool::Exif::PrintExposureTime($secs)` (Exif.pm:5701):
///
/// ```perl
/// my $secs = shift;
/// return $secs unless Image::ExifTool::IsFloat($secs);
/// if ($secs < 0.25001 and $secs > 0) {
///     return sprintf("1/%d", int(0.5 + 1/$secs));
/// }
/// $_ = sprintf("%.1f", $secs);
/// s/\.0$//;
/// return $_;
/// ```
///
/// A short exposure (`0 < secs < 0.25001`) prints as a `1/N` fraction with `N`
/// the rounded reciprocal (`int(0.5 + 1/secs)` — Perl `int` truncates toward
/// zero, and the argument is positive here so it is a round-to-nearest); any
/// other finite value prints to one decimal with a trailing `.0` stripped
/// (`2.0` → `2`, `0.5` → `0.5`). A non-finite `secs` is returned as its Perl
/// spelling unchanged.
#[must_use]
pub(crate) fn print_exposure_time(secs: f64) -> String {
  // `return $secs unless IsFloat($secs)` — a non-finite scalar fails IsFloat.
  if !secs.is_finite() {
    return crate::value::perl_nonfinite_str(secs)
      .unwrap_or("NaN")
      .to_string();
  }
  // `if ($secs < 0.25001 and $secs > 0)`.
  if secs < 0.25001 && secs > 0.0 {
    // `sprintf("1/%d", int(0.5 + 1/$secs))`. `int()` truncates toward zero;
    // the argument is positive, so this is round-half-up of the reciprocal.
    let n = (0.5 + 1.0 / secs).trunc() as i64;
    return format!("1/{n}");
  }
  // `$_ = sprintf("%.1f", $secs); s/\.0$//`.
  let s = format!("{secs:.1}");
  match s.strip_suffix(".0") {
    Some(stripped) => stripped.to_string(),
    None => s,
  }
}

/// `Image::ExifTool::Exif::PrintFNumber($val)` (Exif.pm:5715):
///
/// ```perl
/// my $val = shift;
/// if (Image::ExifTool::IsFloat($val) and $val > 0) {
///     # round to 1 decimal place, or 2 for values < 1.0
///     $val = sprintf(($val < 1 ? "%.2f" : "%.1f"), $val);
/// }
/// return $val;
/// ```
///
/// A positive finite `val` prints to two decimals when `< 1.0` (`0.64` →
/// `0.64`) else one decimal (`4.0` → `4.0`, `13.0` → `13.0`) — NO trailing-`.0`
/// strip (unlike `PrintExposureTime`). A non-positive or non-finite `val` is
/// returned as its Perl numeric spelling unchanged.
#[must_use]
pub(crate) fn print_fnumber(val: f64) -> String {
  // `if (IsFloat($val) and $val > 0)` — finite AND positive takes the format.
  if val.is_finite() && val > 0.0 {
    return if val < 1.0 {
      format!("{val:.2}")
    } else {
      format!("{val:.1}")
    };
  }
  // Otherwise `$val` passes through: a finite non-positive value stringifies
  // with Perl's default NV rule, a non-finite value as `Inf`/`-Inf`/`NaN`.
  if val.is_finite() {
    crate::value::format_g(val, 15)
  } else {
    crate::value::perl_nonfinite_str(val)
      .unwrap_or("NaN")
      .to_string()
  }
}

/// `Composite:ShutterSpeed`'s `PrintExposureTime($val)` (Exif.pm:4779) where
/// `$val` is the composite's SELECTED operand passed through VERBATIM — the
/// operand's ValueConv value, which may be a number OR a non-float string.
///
/// Mirrors `PrintExposureTime` (Exif.pm:5704) on the actual Perl scalar `$val`
/// (see [`classify_operand`]). The gate is `return $secs unless IsFloat($secs)`
/// followed by ALWAYS formatting an `IsFloat` value (the `1/N` fraction for
/// `0 < secs < 0.25001`, else `%.1f` with a trailing `.0` stripped) — so unlike
/// `PrintFNumber` there is NO positivity passthrough: a non-positive `IsFloat`
/// `$val` is FORMATTED, not returned verbatim (`"0.0"`/`"+0"`/`"0,0"` → `"0"`,
/// `"-1.5"` → `"-1.5"`; bundled Perl `Image::ExifTool::Exif::PrintExposureTime`):
///
/// * a NUMBER operand (`I64`/`U64`/`F64`, finite OR not) ⇒ [`print_exposure_time`]
///   on its value — a finite value yields `1/N`/decimal, a non-finite `F64`
///   returns its Perl spelling (`Inf`/`NaN`), consistent with the `-n` rendering
///   of the SAME `F64` operand;
/// * a float-SHAPED string ⇒ [`print_exposure_time`] on its parsed value (the
///   `,`→`.`-translated `ExifGPS ShutterSpeedValue` path; `IsFloat`'s in-place
///   `tr/,/./` is applied before the numeric use);
/// * a NON-`IsFloat` string (a zero-denominator rational's `"undef"`, `"inf"`,
///   any other text) is returned UNCHANGED — NOT coerced to `0`.
///
/// This is the passthrough the prior `coerce_numeric` path violated (it turned
/// a non-float `$val` into `0.0` ⇒ a fabricated `Composite:ShutterSpeed` of 0).
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn print_exposure_time_scalar(val: &crate::value::TagValue) -> String {
  match classify_operand(val) {
    // `PrintExposureTime` formats EVERY `IsFloat` value, so a numeric operand
    // and an `IsFloat` string both run the formatter on the numeric value; only
    // the non-`IsFloat` `Passthrough` short-circuits (`return $secs unless …`).
    OperandValue::Number(secs) | OperandValue::Float { value: secs, .. } => {
      print_exposure_time(secs)
    }
    OperandValue::Passthrough(s) => s,
  }
}

/// `Composite:Aperture`'s `PrintFNumber($val)` (Exif.pm:4790) where `$val` is
/// the selected operand passed through VERBATIM.
///
/// `PrintFNumber` (Exif.pm:5719) formats ONLY when `IsFloat($val) and $val > 0`,
/// and otherwise returns `$val` — so unlike `PrintExposureTime` a non-positive
/// `IsFloat` `$val` is returned VERBATIM (after `IsFloat`'s in-place `tr/,/./`):
///
/// * a NUMBER operand formats via [`print_fnumber`] (`%.1f`/`%.2f` when `> 0`,
///   else the Perl NV spelling — `0` → `"0"`, `-1` → `"-1"`);
/// * a float-SHAPED string with a POSITIVE value formats via [`print_fnumber`];
///   a float-shaped string with a NON-positive value (`"0.0"`/`"+0"`/`"0E0"`/
///   `"-0.0"`/`"-1.5"`) is returned in its `,`→`.`-NORMALIZED form VERBATIM
///   (`"0,0"` → `"0.0"`; bundled Perl `Image::ExifTool::Exif::PrintFNumber`);
/// * a non-`IsFloat` string passes through unchanged.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn print_fnumber_scalar(val: &crate::value::TagValue) -> String {
  match classify_operand(val) {
    OperandValue::Number(v) => print_fnumber(v),
    // `if (IsFloat($val) and $val > 0)` — an `IsFloat` string formats only when
    // positive; a non-positive value takes the `else` arm `return $val`, which
    // is the `tr/,/./`-mutated scalar (`norm`), NOT a numeric canonicalization.
    OperandValue::Float { value, norm } => {
      if value > 0.0 {
        print_fnumber(value)
      } else {
        norm
      }
    }
    OperandValue::Passthrough(s) => s,
  }
}

/// How a selected operand [`TagValue`] feeds `PrintExposureTime`/`PrintFNumber`.
#[cfg(feature = "alloc")]
enum OperandValue {
  /// A genuinely-numeric `$val` (`I64`/`U64`/`F64`) to run the formatter on (the
  /// formatter itself handles a non-finite `f64` via its Perl-spelling
  /// passthrough). It has no string form to fall back to.
  Number(f64),
  /// An `IsFloat`-matching `Str` `$val`. Carries BOTH the parsed numeric `value`
  /// AND `norm` — the `,`→`.`-translated string `IsFloat` would have left in the
  /// scalar — because `PrintFNumber`'s `else` arm returns that verbatim string
  /// (the positivity gate failed) rather than a numeric form. The two helpers
  /// gate differently (`PrintExposureTime` always formats `value`; `PrintFNumber`
  /// formats `value` iff `> 0`, else returns `norm`).
  Float {
    value: f64,
    norm: std::string::String,
  },
  /// A `$val` that `IsFloat` rejects ⇒ returned VERBATIM (the operand's own
  /// string form — a non-float `Str` unchanged, or a non-scalar's text).
  Passthrough(std::string::String),
}

/// Classify a Perl scalar [`TagValue`] operand for ExifTool's
/// `IsFloat($val)`-gated `PrintExposureTime`/`PrintFNumber` (Exif.pm:5704/5719).
///
/// The classification stops at `IsFloat`; it does NOT apply either helper's
/// positivity gate — that differs between the two (`PrintFNumber` is `>0`,
/// `PrintExposureTime` has none) and is left to each scalar helper so the
/// original/normalized string survives for `PrintFNumber`'s `else` return:
///
/// * `I64`/`U64`/`F64` — a `Number`; the formatter runs on it (and a non-finite
///   `F64` returns its Perl spelling, so it need not be special-cased here —
///   keeping `-j` consistent with the `-n` `F64` rendering).
/// * `Str` — ExifTool's `IsFloat` regex
///   ([`is_float_norm`](crate::convert::is_float_norm)): a match is a `Float`
///   carrying the `,`→`.`-translated string AND its `perl_str_to_f64` value; a
///   non-match is a `Passthrough` of the ORIGINAL string (NOT coerced to `0`).
/// * anything else (`Bytes`/`Bool`/`Rational` — operands are build-gated to the
///   numeric/`Str` shapes, so this is defensive) ⇒ `Passthrough` of its text.
#[cfg(feature = "alloc")]
fn classify_operand(val: &crate::value::TagValue) -> OperandValue {
  use crate::value::TagValue;
  match val {
    TagValue::I64(n) => OperandValue::Number(*n as f64),
    TagValue::U64(n) => OperandValue::Number(*n as f64),
    TagValue::F64(x) => OperandValue::Number(*x),
    // A `Rational` operand is classified by its ExifTool ValueConv STRING
    // (`Rational::exiftool_val_str`) exactly as a `Str` operand: a finite
    // rational's `%g` quotient `IsFloat`-formats (a Sony rtmd `ExposureTime`
    // `Rational(1/60)` → `"1/60"`), a zero-denominator `"inf"`/`"undef"` is the
    // non-`IsFloat` `Passthrough` (`PrintExposureTime`/`PrintFNumber` return it
    // verbatim). (`selected_scalar` usually pre-resolves a `Rational` to its
    // float/`"undef"` form, so this arm is the direct-classify safety net.)
    TagValue::Rational(r) => classify_str(&r.exiftool_val_str()),
    TagValue::Str(s) => classify_str(s),
    other => OperandValue::Passthrough(crate::composite::value_text(other).into_owned()),
  }
}

/// Classify a string operand by `IsFloat` (the shared `Str`/`Rational` path):
/// an `IsFloat` string is a [`Float`](OperandValue::Float) carrying its
/// normalized value, a non-`IsFloat` one is a verbatim
/// [`Passthrough`](OperandValue::Passthrough).
fn classify_str(s: &str) -> OperandValue {
  match crate::convert::is_float_norm(s) {
    Some(norm) => OperandValue::Float {
      value: crate::convert::perl_str_to_f64(&norm),
      norm: norm.into_owned(),
    },
    None => OperandValue::Passthrough(s.to_string()),
  }
}

/// `Composite:Megapixels` PrintConv (Exif.pm:4769):
/// `sprintf("%.*f", ($val >= 1 ? 1 : ($val >= 0.001 ? 3 : 6)), $val)`.
///
/// The decimal precision is chosen by magnitude: `>= 1` ⇒ 1 place (`1.3`),
/// `>= 0.001` ⇒ 3 places (`0.922`), else 6 places (`0.000064`). A non-finite
/// `val` (impossible for a real megapixel count) renders via Perl's spelling.
#[must_use]
pub(crate) fn print_megapixels(val: f64) -> String {
  if !val.is_finite() {
    return crate::value::perl_nonfinite_str(val)
      .unwrap_or("NaN")
      .to_string();
  }
  let prec: usize = if val >= 1.0 {
    1
  } else if val >= 0.001 {
    3
  } else {
    6
  };
  format!("{val:.prec$}")
}

/// The complete `%Image::ExifTool::Exif::flash` enumerated hash (Exif.pm:175-
/// 209), ported key-for-key — the table `Composite:Flash`'s PrintConv references
/// (`PrintConv => \%Image::ExifTool::Exif::flash`, XMP.pm:2834). A faithful copy
/// is kept here (the same value the EXIF `Flash` leaf and `h264::flash_print_conv`
/// render) to avoid cross-feature table plumbing — `crate::exif::tables::FLASH`
/// is `exif`-private and the `xmp`/`exif` features are independent.
#[cfg(feature = "alloc")]
const FLASH: &[(i64, &str)] = &[
  (0x00, "No Flash"),
  (0x01, "Fired"),
  (0x05, "Fired, Return not detected"),
  (0x07, "Fired, Return detected"),
  (0x08, "On, Did not fire"),
  (0x09, "On, Fired"),
  (0x0d, "On, Return not detected"),
  (0x0f, "On, Return detected"),
  (0x10, "Off, Did not fire"),
  (0x14, "Off, Did not fire, Return not detected"),
  (0x18, "Auto, Did not fire"),
  (0x19, "Auto, Fired"),
  (0x1d, "Auto, Fired, Return not detected"),
  (0x1f, "Auto, Fired, Return detected"),
  (0x20, "No flash function"),
  (0x30, "Off, No flash function"),
  (0x41, "Fired, Red-eye reduction"),
  (0x45, "Fired, Red-eye reduction, Return not detected"),
  (0x47, "Fired, Red-eye reduction, Return detected"),
  (0x49, "On, Red-eye reduction"),
  (0x4d, "On, Red-eye reduction, Return not detected"),
  (0x4f, "On, Red-eye reduction, Return detected"),
  (0x50, "Off, Red-eye reduction"),
  (0x58, "Auto, Did not fire, Red-eye reduction"),
  (0x59, "Auto, Fired, Red-eye reduction"),
  (0x5d, "Auto, Fired, Red-eye reduction, Return not detected"),
  (0x5f, "Auto, Fired, Red-eye reduction, Return detected"),
];

/// `Composite:Flash`'s PrintConv (`PrintConv => \%Image::ExifTool::Exif::flash`,
/// XMP.pm:2834) on the composite's numeric `$val` (the assembled bitmask).
///
/// The XMP Flash composite carries `PrintHex => 1` (XMP.pm:2820), so a value
/// absent from `%flash` renders `sprintf('Unknown (0x%x)', $val)` (ExifTool.pm:
/// 3623-3627) — the same `Conv::IntLabelHex` fallback the EXIF `Flash` leaf uses.
/// `$val` is the non-negative bitmask the ValueConv built (`0..=0x7f`), so the
/// lowercase-hex `{:x}` matches Perl's unsigned `%x`.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn flash_print_conv(code: i64) -> std::string::String {
  match FLASH.iter().find(|(k, _)| *k == code) {
    Some((_, label)) => (*label).to_string(),
    None => std::format!("Unknown (0x{code:x})"),
  }
}

/// The CFA color names (`@cfaColor = qw(Red Green Blue Cyan Magenta Yellow
/// White)`, Exif.pm:5611). An out-of-range index renders `'Unknown'`.
#[cfg(feature = "alloc")]
const CFA_COLOR: [&str; 7] = ["Red", "Green", "Blue", "Cyan", "Magenta", "Yellow", "White"];

/// `Image::ExifTool::Exif::PrintCFAPattern($val)` (Exif.pm:5604):
///
/// ```perl
/// my @a = split ' ', $val;
/// return '<truncated data>' unless @a >= 2;
/// return '<zero pattern size>' unless $a[0] and $a[1];
/// my $end = 2 + $a[0] * $a[1];
/// return '<invalid pattern size>' if $end > @a;
/// my @cfaColor = qw(Red Green Blue Cyan Magenta Yellow White);
/// my ($pos, $rtnVal) = (2, '[');
/// for (;;) {
///     $rtnVal .= $cfaColor[$a[$pos]] || 'Unknown';
///     last if ++$pos >= $end;
///     ($pos - 2) % $a[1] and $rtnVal .= ',', next;
///     $rtnVal .= '][';
/// }
/// return $rtnVal . ']';
/// ```
///
/// `val` is the composite's ValueConv result (the space-joined
/// `"$cols $rows @bytes"` the [`Composite:CFAPattern`] ValueConv built). The
/// pattern is `cols × rows` color indices; the renderer walks them row-major,
/// joining a row's colors with `,` and bracketing each row.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn print_cfa_pattern(val: &str) -> std::string::String {
  let a: std::vec::Vec<i64> = val
    .split_ascii_whitespace()
    .map(|t| crate::convert::perl_str_to_f64(t) as i64)
    .collect();
  if a.len() < 2 {
    return "<truncated data>".to_string();
  }
  // `$a[0]`/`$a[1]` — cols/rows. `unless $a[0] and $a[1]` (Perl-truthy).
  let cols = *a.first().unwrap_or(&0);
  let rows = *a.get(1).unwrap_or(&0);
  if cols == 0 || rows == 0 {
    return "<zero pattern size>".to_string();
  }
  // `$end = 2 + $a[0]*$a[1]` — uses checked math; an overflow can only exceed
  // `@a`, which is the `<invalid pattern size>` guard.
  let Some(area) = cols.checked_mul(rows) else {
    return "<invalid pattern size>".to_string();
  };
  let Some(end) = area.checked_add(2) else {
    return "<invalid pattern size>".to_string();
  };
  if end > a.len() as i64 {
    return "<invalid pattern size>".to_string();
  }
  let mut out = std::string::String::from("[");
  let mut pos: i64 = 2;
  loop {
    // `$cfaColor[$a[$pos]] || 'Unknown'`.
    let color = usize::try_from(*a.get(pos as usize).unwrap_or(&-1))
      .ok()
      .and_then(|i| CFA_COLOR.get(i).copied())
      .unwrap_or("Unknown");
    out.push_str(color);
    pos += 1;
    if pos >= end {
      break;
    }
    // `($pos - 2) % $a[1]` truthy ⇒ same row, append ',' and continue; else a
    // new row ⇒ `][`.
    if (pos - 2) % rows != 0 {
      out.push(',');
    } else {
      out.push_str("][");
    }
  }
  out.push(']');
  out
}

/// `@rggbLookup` (Exif.pm:5664) — for each `WB_*Levels` Desire index, the input
/// component positions `[R, G, G, B]` (a green index `< 4` means "average the
/// two greens at these positions"; `256` is the literal "green level is 256").
#[cfg(feature = "alloc")]
const RGGB_LOOKUP: [[i64; 4]; 9] = [
  [0, 1, 2, 3],     // 0 RGGB
  [0, 1, 3, 2],     // 1 RGBG
  [0, 2, 3, 1],     // 2 RBGG
  [1, 0, 3, 2],     // 3 GRBG
  [1, 0, 2, 3],     // 4 GRGB
  [2, 3, 0, 1],     // 5 GBRG
  [0, 1, 1, 2],     // 6 RGB
  [1, 0, 0, 2],     // 7 GRB
  [0, 256, 256, 1], // 8 RB (green level is 256)
];

/// `Image::ExifTool::Exif::RedBlueBalance($blue, @val)` (Exif.pm:5676):
///
/// ```perl
/// my $blue = shift;
/// for ($i=0; $i<@rggbLookup; ++$i) {
///     $levels = shift or next;
///     my @levels = split ' ', $levels;
///     next if @levels < 2;
///     my $lookup = $rggbLookup[$i];
///     my $g = $$lookup[1];
///     if ($g < 4) {
///         next if @levels < 3;
///         $g = ($levels[$g] + $levels[$$lookup[2]]) / 2 or next;
///     } elsif ($levels[$$lookup[$blue * 3]] < 4) {
///         $g = 1;
///     }
///     $val = $levels[$$lookup[$blue * 3]] / $g;
///     last;
/// }
/// $val = $_[0] / $_[1] if not defined $val and ($_[0] and $_[1]);
/// return $val;
/// ```
///
/// `blue` selects Blue (`true`) vs Red (`false`). `levels[i]` is the
/// (already-resolved) `WB_*Levels` string for Desire index `i` (`None` ⇒ the
/// Perl `shift or next` skip). The final fallback divides the LAST two operands
/// (`WBBlueLevel`/`WBRedLevel` ÷ `WBGreenLevel`, the index 9/10 Desires) when no
/// earlier lookup matched. Returns the `$val` (or `None` ⇒ the def aborts).
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn red_blue_balance(blue: bool, levels: &[Option<std::string::String>]) -> Option<f64> {
  let blue3 = if blue { 3usize } else { 0 };
  for (i, lookup) in RGGB_LOOKUP.iter().enumerate() {
    let Some(Some(level_str)) = levels.get(i) else {
      continue; // `shift or next`
    };
    let parsed: std::vec::Vec<f64> = level_str
      .split_ascii_whitespace()
      .map(crate::convert::perl_str_to_f64)
      .collect();
    if parsed.len() < 2 {
      continue;
    }
    // `$$lookup[$blue*3]` — the R-or-B component position.
    let Some(&rb_pos) = lookup.get(blue3) else {
      continue;
    };
    let Some(&rb_val) = rb_pos.try_into().ok().and_then(|p: usize| parsed.get(p)) else {
      continue;
    };
    // `$g = $$lookup[1]` (the green index/level).
    let g_idx = lookup[1];
    let g: f64 = if g_idx < 4 {
      if parsed.len() < 3 {
        continue;
      }
      let Some(&g0) = (g_idx).try_into().ok().and_then(|p: usize| parsed.get(p)) else {
        continue;
      };
      let Some(&g1) = lookup[2].try_into().ok().and_then(|p: usize| parsed.get(p)) else {
        continue;
      };
      let avg = (g0 + g1) / 2.0;
      if avg == 0.0 {
        continue; // `… or next`
      }
      avg
    } else if rb_val < 4.0 {
      1.0 // Some Nikon cameras use a scaling factor of 1 (E5700)
    } else {
      // `$g` stays the literal `$$lookup[1]` (256 for the RB lookup).
      g_idx as f64
    };
    return Some(rb_val / g);
  }
  // Fallback: `$val = $_[0] / $_[1]` when no lookup matched AND both are truthy.
  // The loop `shift`s the first 9 operands (`@rggbLookup` has 9 entries) before
  // reaching here, so `$_[0]`/`$_[1]` are the 10th/11th Desires — `WBRedLevel`/
  // `WBBlueLevel` (index 9) and `WBGreenLevel` (index 10). (The FX3 matches at
  // lookup 0 via `WB_RGGBLevels` and `last`s, so this is exercised only by a
  // body that supplies ONLY the explicit WB*Level pair.)
  let num = levels.get(RGGB_LOOKUP.len()).and_then(Option::as_deref);
  let den = levels.get(RGGB_LOOKUP.len() + 1).and_then(Option::as_deref);
  if let (Some(num), Some(den)) = (num, den)
    // Perl string truthiness (`$_[0] and $_[1]`): false only for "" / "0".
    && perl_str_truthy(num)
    && perl_str_truthy(den)
  {
    return Some(crate::convert::perl_str_to_f64(num) / crate::convert::perl_str_to_f64(den));
  }
  None
}

/// Perl string boolean context: a string is FALSE only when empty or exactly
/// `"0"` (Exif.pm:5697 `$_[0] and $_[1]`).
#[cfg(feature = "alloc")]
#[must_use]
fn perl_str_truthy(s: &str) -> bool {
  !s.is_empty() && s != "0"
}

#[cfg(test)]
mod tests;
