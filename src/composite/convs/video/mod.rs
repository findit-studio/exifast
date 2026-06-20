//! The QuickTime video Composite conversions — `ConvertBitrate`
//! (`Composite:AvgBitrate`'s PrintConv) and `CalcRotation` / `GetRotationAngle`
//! (`Composite:Rotation`'s ValueConv), faithful transliterations of the
//! ExifTool Perl (ExifTool.pm:6902 + QuickTime.pm:8782-8829).

/// `ConvertBitrate($bitrate)` (ExifTool.pm:6902-6913):
///
/// ```perl
/// IsFloat($bitrate) or return $bitrate;
/// my @units = ('bps', 'kbps', 'Mbps', 'Gbps');
/// for (;;) {
///     my $units = shift @units;
///     $bitrate >= 1000 and @units and $bitrate /= 1000, next;
///     my $fmt = $bitrate < 100 ? '%.3g' : '%.0f';
///     return sprintf("$fmt $units", $bitrate);
/// }
/// ```
///
/// The AvgBitrate RawConv already produced an integer bps via `int(... + 0.5)`,
/// so `$bitrate` is always a finite number here (the non-`IsFloat` early-return
/// only fires for a genuinely non-numeric input, which `AvgBitrate` never
/// yields). The loop divides by 1000 while `>= 1000` AND a larger unit remains,
/// then formats `%.3g` below 100 / `%.0f` at-or-above 100.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn convert_bitrate(bitrate: f64) -> std::string::String {
  // `IsFloat($bitrate) or return $bitrate` — a non-finite value is not IsFloat;
  // Perl returns it unchanged (it would stringify titlecase). AvgBitrate's
  // `int(... + 0.5)` never produces one, but stay faithful.
  if !bitrate.is_finite() {
    return crate::value::perl_nonfinite_str(bitrate)
      .unwrap_or("NaN")
      .into();
  }
  let units = ["bps", "kbps", "Mbps", "Gbps"];
  let mut value = bitrate;
  let mut idx = 0usize;
  loop {
    // `$bitrate >= 1000 and @units and $bitrate /= 1000, next` — divide while
    // `>= 1000` AND a LARGER unit remains (`@units` non-empty after the shift).
    if value >= 1000.0 && idx + 1 < units.len() {
      value /= 1000.0;
      idx += 1;
      continue;
    }
    let unit = units[idx];
    // `$fmt = $bitrate < 100 ? '%.3g' : '%.0f'`.
    if value < 100.0 {
      return std::format!("{} {unit}", crate::value::format_g(value, 3));
    }
    return std::format!("{value:.0} {unit}");
  }
}

/// `GetRotationAngle($rotMatrix)` (QuickTime.pm:8782-8792):
///
/// ```perl
/// my @a = split ' ', $rotMatrix;
/// return undef if $a[0]==0 and $a[1]==0;
/// my $angle = atan2($a[1], $a[0]) * 180 / 3.14159;
/// $angle += 360 if $angle < 0;
/// return int($angle * 1000 + 0.5) / 1000;
/// ```
///
/// `$rotMatrix` is the `MatrixStructure` ValueConv string (nine space-separated
/// 16.16-fixed values rendered by `GetFixed32s`). The angle uses the TRUNCATED
/// literal `3.14159` (ported byte-exact) and is rounded to 3 decimals. `None`
/// when the top-left 2×2 is degenerate (`a[0]==0 and a[1]==0`) or the string has
/// fewer than two fields.
// The literal `3.14159` is REQUIRED for byte-exact parity with ExifTool's
// `GetRotationAngle` (QuickTime.pm:8789); `std::f64::consts::PI` would change
// the angle in the 6th significant figure.
#[allow(clippy::approx_constant)]
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn get_rotation_angle(rot_matrix: &str) -> Option<f64> {
  // `my @a = split ' ', $rotMatrix` — Perl's `split ' '` collapses runs of
  // whitespace and ignores leading blanks; the fields are floats.
  let mut fields = rot_matrix.split_ascii_whitespace();
  let a0: f64 = fields.next()?.parse().ok()?;
  let a1: f64 = fields.next()?.parse().ok()?;
  // `return undef if $a[0]==0 and $a[1]==0`.
  if a0 == 0.0 && a1 == 0.0 {
    return None;
  }
  // `atan2($a[1], $a[0]) * 180 / 3.14159` — the truncated-pi literal.
  let mut angle = a1.atan2(a0) * 180.0 / 3.14159;
  // `$angle += 360 if $angle < 0`.
  if angle < 0.0 {
    angle += 360.0;
  }
  // `int($angle * 1000 + 0.5) / 1000` — round to 3 decimals (Perl `int` ⇒
  // truncate toward zero; the `+ 0.5` makes it nearest for the non-negative
  // `$angle`).
  Some((angle * 1000.0 + 0.5).trunc() / 1000.0)
}

#[cfg(test)]
mod tests;
