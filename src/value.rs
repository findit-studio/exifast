//! The tag/value model. Mirrors ExifTool's notion of a tag with family-0 and
//! family-1 groups (the `-G1` grouping used for `-j` output keys).

use smol_str::SmolStr;

/// An ExifTool rational number (numerator / denominator) plus the
/// significant-digit width ExifTool rounds it to.
///
/// ExifTool stringifies a rational at the read layer via
/// `RoundFloat($numer/$denom, $sig)` = `sprintf("%.${sig}g", …)`
/// (`ExifTool.pm` `RoundFloat`, line 5949). The `$sig` value is fixed by the
/// on-disk width of the rational and is the ONLY thing that differs between
/// the two reader entry points:
///
/// - **rational32** (`GetRational32s`/`GetRational32u`, `ExifTool.pm`
///   lines 6087/6094) rounds to **7** significant figures.
/// - **rational64** (`GetRational64s`/`GetRational64u`, `ExifTool.pm`
///   lines 6101/6108) rounds to **10** significant figures.
///
/// Carrying `sig` here is what makes the serializer byte-exact: e.g.
/// `1/3` as a rational32 is `0.3333333` (7 sig) but as a rational64 is
/// `0.3333333333` (10 sig). The only `sig` values ExifTool ever uses are 7
/// and 10; the named constructors [`Rational::rational32`] /
/// [`Rational::rational64`] mirror those two reader widths exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rational {
  numerator: i64,
  denominator: i64,
  sig: u8,
}

impl Rational {
  /// Construct a `Rational` from numerator, denominator and the
  /// significant-digit width ExifTool's `RoundFloat` uses (`%.{sig}g`).
  /// ExifTool only ever uses `sig == 7` (rational32) or `sig == 10`
  /// (rational64); prefer [`Rational::rational32`] / [`Rational::rational64`].
  #[must_use]
  pub const fn new(numerator: i64, denominator: i64, sig: u8) -> Self {
    Self {
      numerator,
      denominator,
      sig,
    }
  }

  /// A 32-bit (16/16) rational: ExifTool `GetRational32s`/`GetRational32u`
  /// round the quotient to **7** significant figures
  /// (`ExifTool.pm:6087,6094` → `RoundFloat(n/d, 7)`).
  #[must_use]
  pub const fn rational32(numerator: i64, denominator: i64) -> Self {
    Self {
      numerator,
      denominator,
      sig: 7,
    }
  }

  /// A 64-bit (32/32) rational: ExifTool `GetRational64s`/`GetRational64u`
  /// round the quotient to **10** significant figures
  /// (`ExifTool.pm:6101,6108` → `RoundFloat(n/d, 10)`). This is the
  /// dominant EXIF width (`XResolution`, `ExposureTime`, `FNumber`, GPS, …).
  #[must_use]
  pub const fn rational64(numerator: i64, denominator: i64) -> Self {
    Self {
      numerator,
      denominator,
      sig: 10,
    }
  }

  /// The numerator of the rational number.
  #[must_use]
  pub const fn numerator(&self) -> i64 {
    self.numerator
  }

  /// The denominator of the rational number.
  #[must_use]
  pub const fn denominator(&self) -> i64 {
    self.denominator
  }

  /// The significant-digit width ExifTool's `RoundFloat` applies
  /// (`%.{sig}g`): `7` for a rational32, `10` for a rational64.
  #[must_use]
  pub const fn sig(&self) -> u8 {
    self.sig
  }

  /// ExifTool's `$val` text for this rational (the value `$$conv{$val}`
  /// would be keyed by, and what the JSON writer prints): `num/denom`
  /// rounded via `RoundFloat(n/d, sig)` = `sprintf("%.${sig}g", …)`
  /// (`ExifTool.pm` `GetRational*` 6081-6109, `RoundFloat` 5949). A zero
  /// denominator yields the bare word `inf` (numerator ≠ 0) or `undef`
  /// (numerator == 0) — `ExifTool.pm`: `... or return $ratNumer ? 'inf'
  /// : 'undef';`.
  ///
  /// This is the single source of truth for a rational's stringified
  /// scalar form, shared by the PrintConv-hash lookup ([`crate::convert`])
  /// and the JSON serializer ([`crate::serialize`]) so a hash key matches
  /// what ExifTool's `$val` would be.
  #[must_use]
  pub fn exiftool_val_str(&self) -> String {
    if self.denominator == 0 {
      return if self.numerator != 0 { "inf" } else { "undef" }.to_string();
    }
    let v = self.numerator as f64 / self.denominator as f64;
    format_g(v, self.sig as usize)
  }
}

/// Faithful C/Perl `sprintf("%.*g", precision, val)` for `f64`.
///
/// ExifTool stringifies floats/rationals with `%.{N}g` (e.g. `RoundFloat`
/// `ExifTool.pm:5949`, the JSON writer prints that text verbatim). This is
/// the single shared implementation: the serializer and the PrintConv-hash
/// lookup both call it so a hash key (`$$conv{$val}`) is keyed by exactly
/// the same `$val` text ExifTool would produce.
#[must_use]
pub fn format_g(val: f64, precision: usize) -> String {
  let p = precision.max(1);
  if val == 0.0 {
    // Perl `%g`: "0" for +0.0, "-0" for -0.0.
    return if val.is_sign_negative() {
      "-0".to_string()
    } else {
      "0".to_string()
    };
  }
  // Decompose via `%e` (Rust gives `p-1` fraction digits + decimal exponent)
  // to obtain the C `%g` exponent X.
  let e_str = format!("{:.*e}", p - 1, val);
  let Some((mantissa, exp_s)) = e_str.split_once('e') else {
    // `{:e}` always contains 'e'; if not, fall back to the raw text.
    return e_str;
  };
  let Ok(x) = exp_s.parse::<i32>() else {
    return e_str;
  };
  if x >= -4 && x < p as i32 {
    // Fixed notation: (p - 1 - x) fraction digits, then strip per `%g`.
    let frac = (p as i32 - 1 - x).max(0) as usize;
    strip_g_trailing_zeros(&format!("{val:.frac$}"))
  } else {
    // Scientific notation; C/Perl exponent: explicit sign, >= 2 digits.
    let m = strip_g_trailing_zeros(mantissa);
    let sign = if x < 0 { '-' } else { '+' };
    format!("{m}e{sign}{:02}", x.abs())
  }
}

/// `%g` (without `#`) strips trailing zeros in the fraction and a bare
/// trailing `.`.
fn strip_g_trailing_zeros(s: &str) -> String {
  if !s.contains('.') {
    return s.to_string();
  }
  s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// A metadata value. The variants cover what Stage-1 video/audio tags need;
/// `Bytes`/`Rational` JSON encoding is wired in the first format plan (AAC).
#[derive(
  Debug, Clone, PartialEq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum TagValue {
  /// Signed integer.
  I64(i64),
  /// Floating point.
  F64(f64),
  /// UTF-8 text.
  Str(SmolStr),
  /// Boolean.
  Bool(bool),
  /// Raw bytes (binary tag).
  Bytes(Vec<u8>),
  /// An ExifTool rational (numerator, denominator).
  Rational(Rational),
  /// An ordered list of values.
  List(Vec<TagValue>),
}

/// ExifTool group identity. `family0` is the broad category (e.g. `"QuickTime"`,
/// `"Audio"`, `"File"`); `family1` is the specific group used as the `Group1:`
/// prefix in `-G1 -j` output (e.g. `"QuickTime"`, `"ID3v2_3"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
  family0: SmolStr,
  family1: SmolStr,
}

impl Group {
  /// Construct a group from two string-ish values.
  #[must_use]
  pub fn new(family0: impl Into<SmolStr>, family1: impl Into<SmolStr>) -> Self {
    Self {
      family0: family0.into(),
      family1: family1.into(),
    }
  }

  /// The broad category (ExifTool family 0).
  #[must_use]
  pub fn family0(&self) -> &str {
    self.family0.as_str()
  }

  /// The specific group used as the JSON key prefix (ExifTool family 1).
  #[must_use]
  pub fn family1(&self) -> &str {
    self.family1.as_str()
  }
}

/// One extracted tag.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
  group: Group,
  name: SmolStr,
  value: TagValue,
}

impl Tag {
  /// Construct a tag from its group, name, and value.
  #[must_use]
  pub fn new(group: Group, name: impl Into<SmolStr>, value: TagValue) -> Self {
    Self {
      group,
      name: name.into(),
      value,
    }
  }

  /// The tag's group.
  #[must_use]
  pub fn group(&self) -> &Group {
    &self.group
  }

  /// The tag's name (e.g. `"Duration"`).
  #[must_use]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The value as it should appear in `-j` output (post-conversion).
  #[must_use]
  pub fn value(&self) -> &TagValue {
    &self.value
  }
}

/// The full result of reading a file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Metadata {
  source_file: SmolStr,
  tags: Vec<Tag>,
  warnings: Vec<SmolStr>,
}

impl Metadata {
  /// Construct a `Metadata` for the given source file path (tags and warnings empty).
  #[must_use]
  pub fn new(source_file: impl Into<SmolStr>) -> Self {
    Self {
      source_file: source_file.into(),
      tags: Vec::new(),
      warnings: Vec::new(),
    }
  }

  /// The path as ExifTool would echo it in the `SourceFile` key.
  #[must_use]
  pub fn source_file(&self) -> &str {
    self.source_file.as_str()
  }

  /// Extracted tags, in extraction order (order is significant).
  #[must_use]
  pub fn tags(&self) -> &[Tag] {
    &self.tags
  }

  /// Non-fatal warnings (ExifTool emits these as `Warning` tags).
  #[must_use]
  pub fn warnings(&self) -> &[SmolStr] {
    &self.warnings
  }

  /// Append a tag in extraction order.
  pub fn push(&mut self, group: Group, name: impl Into<SmolStr>, value: TagValue) {
    self.tags.push(Tag::new(group, name, value));
  }

  /// Record a non-fatal warning, in occurrence order. ExifTool accumulates
  /// these via `$self->Warn(...)` and surfaces them as its generated
  /// `Warning` tag (`ExifTool.pm:1297`); the serializer emits the first as
  /// `ExifTool:Warning` under `-j -G1` (`ExifTool.pm:1225`).
  pub fn push_warning(&mut self, warning: impl Into<SmolStr>) {
    self.warnings.push(warning.into());
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn push_preserves_order() {
    let mut m = Metadata::default();
    m.push(
      Group::new("File", "System"),
      "FileType",
      TagValue::Str("AAC".into()),
    );
    m.push(
      Group::new("Audio", "AAC"),
      "SampleRate",
      TagValue::I64(44100),
    );
    let names: Vec<&str> = m.tags().iter().map(Tag::name).collect();
    assert_eq!(names, ["FileType", "SampleRate"]);
    assert_eq!(m.tags()[1].group().family1(), "AAC");
  }
}
