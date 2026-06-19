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
  #[inline(always)]
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
  #[inline(always)]
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
  #[inline(always)]
  pub const fn rational64(numerator: i64, denominator: i64) -> Self {
    Self {
      numerator,
      denominator,
      sig: 10,
    }
  }

  /// The numerator of the rational number.
  #[must_use]
  #[inline(always)]
  pub const fn numerator(&self) -> i64 {
    self.numerator
  }

  /// The denominator of the rational number.
  #[must_use]
  #[inline(always)]
  pub const fn denominator(&self) -> i64 {
    self.denominator
  }

  /// The significant-digit width ExifTool's `RoundFloat` applies
  /// (`%.{sig}g`): `7` for a rational32, `10` for a rational64.
  #[must_use]
  #[inline(always)]
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

  /// The raw IEEE quotient `numerator / denominator` as an `f64` — the value
  /// BEFORE `RoundFloat`/`%g` stringification. Mirrors Perl's float coercion
  /// of a rational scalar: `n/0` (n≠0) is `±inf`, `0/0` is `NaN`. Callers
  /// that want the ExifTool-rounded *string* use [`Self::exiftool_val_str`];
  /// this is for downstream arithmetic (e.g. the cross-format domain layer).
  #[must_use]
  #[inline(always)]
  pub fn to_f64(&self) -> f64 {
    self.numerator as f64 / self.denominator as f64
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

/// ExifTool's universal no-`-b` placeholder for a binary value — the string
/// `(Binary data N bytes, use -b option to extract)` the `exiftool` script
/// substitutes for a scalar-ref tag value in default (non-`-b`) JSON output
/// (`exiftool:3982-3986` — `'(Binary data ' . length($$obj) . " bytes$bOpt)"`,
/// `$bOpt = ', use -b option to extract'`).
///
/// `len` is the REAL byte count to report. A caller that retains the bytes
/// (`TagValue::Bytes`) passes `bytes.len()`; a caller that deliberately did
/// NOT read the payload (e.g. an oversized binary plist `data` object — see
/// `formats::plist`, PLIST.pm:300-303) passes the known size directly, so the
/// placeholder still reports the true `N` without the bytes ever being copied.
///
/// Gated on `alloc` (needs `String`); reachable only via the value
/// `Serialize` impl (`serde`) and the plist serde-render path, so a plain
/// `alloc`-only build that links neither compiles it dead — same as
/// `formats::plist::apply_print_conv`.
#[cfg(feature = "alloc")]
#[allow(dead_code)]
#[must_use]
pub(crate) fn binary_data_placeholder(len: usize) -> String {
  std::format!("(Binary data {len} bytes, use -b option to extract)")
}

/// Perl-style stringification of a non-finite `f64` (Codex R8 fix).
///
/// Rust's `f64::to_string` emits lowercase `inf`/`-inf` and `NaN`; Perl's
/// default NV stringification on the same scalars emits titlecase `Inf`/
/// `-Inf` and `NaN`. ExifTool's `EscapeJSON` quotes any non-numeric-shape
/// scalar, so the casing surfaces unchanged in JSON output (a malformed
/// AIFF SampleRate that decodes to infinity would print as quoted
/// `"Inf"` in bundled Perl, `"inf"` in pre-fix Rust). This helper
/// produces Perl's casing so both the serializer's non-finite branch
/// and `convert_duration`'s `unless IsFloat` fallback agree.
///
/// Returns `None` for finite inputs (callers route those to `format_g`
/// or `to_string`); `Some(text)` for the three non-finite categories.
#[must_use]
pub fn perl_nonfinite_str(val: f64) -> Option<&'static str> {
  if val.is_nan() {
    Some("NaN")
  } else if val.is_infinite() {
    if val.is_sign_negative() {
      Some("-Inf")
    } else {
      Some("Inf")
    }
  } else {
    None
  }
}

/// Faithful port of ExifTool's `EscapeJSON` number-detection regex
/// (`exiftool:3809`):
/// `^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$` (the `e` is
/// case-insensitive). When the JSON writer's `$quote` flag is false (every
/// non-`StructFormat=JSONQ` `-j`/`-n` run), a value whose ENTIRE stringified
/// form matches this regex is printed as a BARE JSON NUMBER; anything else is
/// quoted as a JSON string.
///
/// This is the SINGLE crate-wide source of truth for the gate — the
/// [`TagValue::Str`] serializer (token-exact JSON typing, Contract B / #197),
/// the Exif/GPS scalar emitter (`exif::mod`), and the H264 `-n` classifier
/// (`formats::h264`) all delegate here so the regex is never duplicated.
///
/// A hand-rolled byte scan: dependency-free (no `regex`) and allocation-free,
/// so it is available in every feature tier (it gates nothing). The conservative
/// 15-digit integer cap (`int_len > 15` ⇒ not a number) is what keeps a large
/// integer — e.g. a `u64` above `i64::MAX` such as `9223372036854775808` — a
/// QUOTED string, byte-identical to bundled (which quotes those "big numbers
/// that caused problems for some JSON parsers", `exiftool:3808`).
#[must_use]
pub(crate) fn escape_json_is_number(s: &str) -> bool {
  // Every `b.get(i)` read is bound-folded (`b.get(i) == Some(&c)` ⟺ `i < len &&
  // b[i] == c`; `b.get(i).is_some_and(pred)` ⟺ `i < len && pred(b[i])`), so this
  // is panic-safe by construction and byte-identical to an indexed scan.
  let b = s.as_bytes();
  let mut i = 0usize;
  // optional leading `-`
  if b.first() == Some(&b'-') {
    i += 1;
  }
  // integer part: `\d` (one digit) OR `[1-9]\d{1,14}` (2..=15 digits, no
  // leading zero).
  let int_start = i;
  while b.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
  }
  let int_len = i - int_start;
  if int_len == 0 {
    return false;
  }
  if int_len > 1 && (int_len > 15 || b.get(int_start) == Some(&b'0')) {
    // 2..=15 digits, first must be 1..=9 (`[1-9]\d{1,14}`).
    return false;
  }
  // optional fraction `\.\d{1,16}`.
  if b.get(i) == Some(&b'.') {
    i += 1;
    let frac_start = i;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
    let frac_len = i - frac_start;
    if frac_len == 0 || frac_len > 16 {
      return false;
    }
  }
  // optional exponent `e[-+]?\d{1,3}` (case-insensitive `e`).
  if matches!(b.get(i), Some(&b'e' | &b'E')) {
    i += 1;
    if matches!(b.get(i), Some(&b'+' | &b'-')) {
      i += 1;
    }
    let exp_start = i;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
    let exp_len = i - exp_start;
    if exp_len == 0 || exp_len > 3 {
      return false;
    }
  }
  i == b.len()
}

/// Whether a [`escape_json_is_number`] token's SIGNIFICAND represents a nonzero
/// value — i.e. it contains a digit `1..=9` before the exponent marker.
///
/// The significand half of the [`f64_token_is_faithful`] predicate (Contract B
/// / #197), which the four f64-emitting paths share to complete the
/// f64-representation gate. The gate admits an exponent up to `e[-+]?\d{1,3}`
/// (faithful to `exiftool:3810`), so it accepts tokens OUTSIDE finite-f64 range
/// on BOTH sides: `1e999` OVERFLOWS to `INFINITY` (caught by `!is_finite()`),
/// and `1e-999` UNDERFLOWS to a FINITE `0.0` — which the finite-only guard would
/// silently rewrite the nonzero token to. A token whose significand is nonzero
/// but which `parse::<f64>()`'d to `0.0` therefore underflowed and must be
/// preserved as a string, NOT emitted as a bare `0.0`. A token whose significand
/// is genuinely zero (`0`, `0.0`, `0.`, `.0`, `-0`, `0e-5`, …) legitimately
/// denotes the value zero and stays a bare number.
///
/// Scans the significand only: bytes before `e`/`E`. The sign (`-`/`+`) and the
/// decimal point are non-digits, so they are naturally skipped; any remaining
/// byte in `1..=9` makes the significand nonzero. Allocation-free byte scan.
#[must_use]
pub(crate) fn lexeme_is_nonzero(token: &str) -> bool {
  token
    .bytes()
    .take_while(|&b| b != b'e' && b != b'E')
    .any(|b| b.is_ascii_digit() && b != b'0')
}

/// The COMPLETE f64-representation predicate (Contract B / #197): whether a
/// `parsed` f64 faithfully denotes its source `token`, so the value may be
/// emitted as a BARE JSON number rather than a quoted string.
///
/// The `EscapeJSON` gate ([`escape_json_is_number`]) admits an exponent up to
/// `e[-+]?\d{1,3}` (faithful to `exiftool:3810`), so it accepts a token whose
/// magnitude is OUTSIDE finite-f64 range on BOTH sides — and the same overflow
/// arises when a FINITE f64 near `f64::MAX` is `format_g`-rounded to a token
/// that exceeds `f64::MAX` (e.g. `f64::MAX` → `"1.79769313486232e+308"`). The
/// predicate is faithful ⟺ BOTH:
///   (a) `parsed.is_finite()` — an OVERFLOW (`1e999`, or a near-`f64::MAX` value
///       whose rounded token over-ranges) reparses to `±INFINITY`, which
///       `serialize_f64` would corrupt to `null` (or, via `TagValue::F64`, the
///       titlecase `"Inf"`); and
///   (b) `!(parsed == 0.0 && lexeme_is_nonzero(token))` — a nonzero significand
///       that UNDERFLOWED to a finite `0.0` (`1e-999`) must stay a string, not a
///       bare `0` that rewrites the value to zero.
/// A genuine-zero token (`0`, `0.0`, `0e-5`) stays a bare `0`; finite-nonzero
/// precision loss (`1.50` ≈ `1.5`) is value-preserving under the comparator.
///
/// The SINGLE crate-wide source of truth for this predicate — the four
/// f64-emitting paths delegate here so they can never diverge: the string-origin
/// consumers [`serialize_in_gate_number_str`] (this module),
/// `emit_gated_number` (`exif::mod`), `classify_json_scalar` (`formats::h264`),
/// AND the numeric-origin `TagValue::F64` serializer arm (this module). When
/// false, the caller emits the source token as a SOUND quoted string.
#[must_use]
pub(crate) fn f64_token_is_faithful(parsed: f64, token: &str) -> bool {
  parsed.is_finite() && !(parsed == 0.0 && lexeme_is_nonzero(token))
}

/// ExifTool's universal no-`-b` binary placeholder string for a value of `len`
/// bytes: `"(Binary data <len> bytes, use -b option to extract)"`
/// (`ExifTool.pm` `ConvertBinary` / the writer's `Binary data` rendering, and
/// `CanonRaw.pm:717` `"Binary data $size bytes"` for the over-512 leaf). The
/// SINGLE source of truth for this text — used both by the [`TagValue::Bytes`]
/// serializer (which derives `len` from the buffer it holds) and by callers
/// that know only the byte LENGTH of a binary leaf (e.g. the CRW
/// `RawData`/`JpgFromRaw`/`ThumbnailImage`/`FreeBytes` records, whose
/// multi-megabyte payload is never materialized). Renders from the length
/// alone — it allocates only the (~50-byte) result string, never the payload.
#[must_use]
pub fn binary_placeholder(len: u64) -> SmolStr {
  SmolStr::from(std::format!(
    "(Binary data {len} bytes, use -b option to extract)"
  ))
}

/// A metadata value. The variants cover what Stage-1 video/audio tags need;
/// `Bytes`/`Rational` JSON encoding is wired in the first format plan (AAC).
///
/// `#[non_exhaustive]`: the value vocabulary is open (a future format may need
/// a new scalar shape); downstream crates must keep a wildcard arm. In-crate
/// matches stay exhaustive (the attribute only constrains other crates).
#[non_exhaustive]
#[derive(
  Debug, Clone, PartialEq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum TagValue {
  /// Signed integer.
  I64(i64),
  /// Unsigned 64-bit integer. Distinct from [`TagValue::I64`] so a value
  /// above `i64::MAX` (e.g. an APE u64 day-count or a large file size) is
  /// preserved EXACTLY rather than saturating to `i64::MAX`. Perl is
  /// untyped — it stringifies any integer and runs the one `EscapeJSON`
  /// number gate (`exiftool:3809`), so this variant renders its full decimal
  /// text through that gate, byte-identical to bundled (a >15-digit value is
  /// quoted, matching `i64::MAX`/`i64::MIN`, but with the TRUE value).
  U64(u64),
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
  /// An ordered key/value object. Used for ExifTool's structured-value
  /// (`-struct`) output — e.g. an XMP `rdf:parseType="Resource"` structure
  /// or a flattened struct rebuilt by `RestoreStruct` (XMPStruct.pl:708).
  /// Keys preserve first-occurrence order; the value-semantic JSON
  /// comparator (`jsondiff`) makes that order non-load-bearing.
  Map(Vec<(SmolStr, TagValue)>),
}

/// ExifTool group identity. `family0` is the broad category (e.g. `"QuickTime"`,
/// `"Audio"`, `"File"`); `family1` is the specific group used as the `Group1:`
/// prefix in `-G1 -j` output (e.g. `"QuickTime"`, `"ID3v2_3"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
  family0: SmolStr,
  family1: SmolStr,
  /// ExifTool family-3 sub-document: `0` = Main, `N` = `Doc<N>` (the per-sample
  /// document index for `-ee` timed metadata). Almost every group is `0`.
  doc: u32,
  /// The SECOND-level sub-document index for the GoPro GPMF `ProcessString`
  /// shape only (`0` = none → render `Doc<N>`; `M > 0` → render `Doc<N>-<M>`,
  /// GoPro.pm:759-774). ExifTool's `ProcessString` keeps the parent `DOC_NUM`
  /// and splits each subsequent row of a multi-row `GPS5`/`GPS9` record into
  /// `"$docNum-$subDoc"`; this is the only source in the port that emits the
  /// two-level form. Every other group is `0` here (rendered as the ordinary
  /// `Doc<N>`), so this is purely additive — no existing golden carries it.
  doc_sub: u32,
}

impl Group {
  /// A Main (doc 0) group from two string-ish values.
  #[must_use]
  #[inline(always)]
  pub fn new(family0: impl Into<SmolStr>, family1: impl Into<SmolStr>) -> Self {
    Self {
      family0: family0.into(),
      family1: family1.into(),
      doc: 0,
      doc_sub: 0,
    }
  }

  /// A sub-document (`Doc<N>`) group; `doc==0` is Main (identical to `new`).
  #[must_use]
  #[inline(always)]
  pub fn with_doc(family0: impl Into<SmolStr>, family1: impl Into<SmolStr>, doc: u32) -> Self {
    Self {
      family0: family0.into(),
      family1: family1.into(),
      doc,
      doc_sub: 0,
    }
  }

  /// A two-level sub-document (`Doc<N>-<M>`) group — the GoPro GPMF
  /// `ProcessString` per-row split (GoPro.pm:759-774). `sub == 0` is the parent
  /// `Doc<N>` (identical to [`Self::with_doc`]); `sub > 0` renders `Doc<N>-<M>`.
  /// Used ONLY by the GoPro `gpmd` timed-metadata emitter for the subsequent
  /// rows of a multi-row `GPS5`/`GPS9` record.
  #[must_use]
  #[inline(always)]
  pub fn with_subdoc(
    family0: impl Into<SmolStr>,
    family1: impl Into<SmolStr>,
    doc: u32,
    sub: u32,
  ) -> Self {
    Self {
      family0: family0.into(),
      family1: family1.into(),
      doc,
      doc_sub: sub,
    }
  }

  /// The broad category (ExifTool family 0).
  #[must_use]
  #[inline(always)]
  pub fn family0(&self) -> &str {
    self.family0.as_str()
  }

  /// The specific group used as the JSON key prefix (ExifTool family 1).
  #[must_use]
  #[inline(always)]
  pub fn family1(&self) -> &str {
    self.family1.as_str()
  }

  /// The family-3 sub-document index (`0` = Main).
  #[must_use]
  #[inline(always)]
  pub const fn doc(&self) -> u32 {
    self.doc
  }

  /// The SECOND-level sub-document index (`0` = none → `Doc<N>`; `M > 0` →
  /// `Doc<N>-<M>`). Non-zero only for the GoPro GPMF `ProcessString` per-row
  /// split (GoPro.pm:759-774).
  #[must_use]
  #[inline(always)]
  pub const fn doc_sub(&self) -> u32 {
    self.doc_sub
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
  #[inline(always)]
  pub fn new(group: Group, name: impl Into<SmolStr>, value: TagValue) -> Self {
    Self {
      group,
      name: name.into(),
      value,
    }
  }

  /// The tag's group (non-`Copy` `&T` borrow → `_ref` per the accessor naming
  /// convention; pairs with no mutator since group is set at construction).
  #[must_use]
  #[inline(always)]
  pub const fn group_ref(&self) -> &Group {
    &self.group
  }

  /// Consume `self`, yielding its `(group, name, value)` parts — lets a consumer
  /// MOVE the owned [`TagValue`] (and group/name) out instead of cloning
  /// `value_ref()`. Used by [`crate::emit::run_emission`] to hand the value to
  /// the sink without a clone (Golden-v2 P3). Crate-internal: the public read
  /// path is the borrowing accessors.
  #[must_use]
  #[inline(always)]
  pub(crate) fn into_parts(self) -> (Group, SmolStr, TagValue) {
    (self.group, self.name, self.value)
  }

  /// The tag's name (e.g. `"Duration"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The value as it should appear in `-j` output (post-conversion). Non-`Copy`
  /// `&T` borrow → `_ref` (pairs with [`Self::value_mut`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &TagValue {
    &self.value
  }

  /// Replace this tag's value in place — the per-tag analogue of ExifTool
  /// overwriting `$$self{VALUE}{$tag}` (`ExifTool.pm:9717,9722,9724`).
  /// Crate-internal: the only faithful caller is [`Metadata::set_tag_value`]
  /// (the `OverrideFileType` path); regular extraction still appends via
  /// [`Metadata::push`]. Returns `&mut Self` to chain (§3 setter convention).
  /// Not `const`: assigning the field drops the previous (non-`Copy`)
  /// `TagValue`, which a `const fn` cannot run.
  #[inline(always)]
  pub(crate) fn set_value(&mut self, value: TagValue) -> &mut Self {
    self.value = value;
    self
  }

  /// Mutable access to the tag's value (`_mut` pairs with [`Self::value_ref`]) —
  /// only used by [`Metadata::push_listable`] to `mem::replace` the existing
  /// value out (avoiding an O(n) clone of the inner `Vec` per appended repeat).
  /// Crate-internal: regular write paths still go through [`Self::set_value`].
  #[inline(always)]
  pub(crate) const fn value_mut(&mut self) -> &mut TagValue {
    &mut self.value
  }
}

/// The full result of reading a file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Metadata {
  source_file: SmolStr,
  tags: Vec<Tag>,
  warnings: Vec<SmolStr>,
  /// Per-warning `sub Warn` ignorable level, index-aligned with
  /// [`warnings`](Self::warnings) (Phase C, Contract 2). `0` = normal,
  /// `1` = `[minor]`, `2` = `[Minor]` (`ExifTool.pm:5616-5630`). The message
  /// in `warnings` stays BARE — the `[minor]`/`[Minor]` prefix is applied
  /// centrally by [`run_diagnostics`](crate::diagnostics::run_diagnostics).
  /// A parallel `Vec<u8>` (rather than widening `warnings`) keeps every
  /// existing `warnings_slice() -> &[SmolStr]` consumer (OGG, the
  /// `Metadata`-staging serializer) untouched; the single push funnel keeps
  /// the two vectors lock-step.
  warnings_ignorable: Vec<u8>,
  errors: Vec<SmolStr>,
  /// Faithful `$$et{DoneID3}` flag (ID3.pm:1435-1436, APE.pm:124, etc.).
  /// `None` ⇒ ProcessID3 has not run on this `$self`; `Some(n)` ⇒ run, with
  /// `n` being the ID3v1-trailer size (ID3.pm:1527 `$$et{DoneID3} =
  /// $trailSize`) used by APE.pm:169 `$footPos -= $$et{DoneID3} if
  /// $$et{DoneID3} > 1` to walk PAST the ID3v1 trailer when looking for
  /// the APE footer. Per `$self`-scoped state (file-level), NOT per-
  /// `ParseContext` — guards cross-parser dispatch (`unless ($$et{DoneID3})`
  /// at APE.pm:124, MPC.pm:84, OGG/FLAC/DSF chained ID3 paths).
  done_id3: Option<usize>,
  /// Faithful `$$et{DoneAPE}` flag (APE.pm:131, ID3.pm:1723). Set by
  /// `ProcessAPE` immediately after the ID3 check (APE.pm:131); read by
  /// ID3.pm:1723 `if ($rtnVal and not $$et{DoneAPE}) { ... ProcessAPE ... }`
  /// to gate the MP3→APE trailer fallback (`return $rtnVal` from
  /// ProcessMP3 at ID3.pm:1727). Per `$self`-scoped — must NOT be reset
  /// across candidate parsers in the same file.
  done_ape: bool,
}

impl Metadata {
  /// Construct a `Metadata` for the given source file path (tags, warnings
  /// and errors empty).
  #[must_use]
  #[inline(always)]
  pub fn new(source_file: impl Into<SmolStr>) -> Self {
    Self {
      source_file: source_file.into(),
      tags: Vec::new(),
      warnings: Vec::new(),
      warnings_ignorable: Vec::new(),
      errors: Vec::new(),
      done_id3: None,
      done_ape: false,
    }
  }

  /// The path as ExifTool would echo it in the `SourceFile` key.
  #[must_use]
  #[inline(always)]
  pub fn source_file(&self) -> &str {
    self.source_file.as_str()
  }

  /// Extracted tags, in extraction order (order is significant). `_slice`
  /// projection of the `Vec<Tag>` field (§3: never expose `&Vec<T>`).
  #[must_use]
  #[inline(always)]
  pub const fn tags_slice(&self) -> &[Tag] {
    self.tags.as_slice()
  }

  /// Non-fatal warnings (ExifTool emits these as `Warning` tags). `_slice`
  /// projection of the `Vec<SmolStr>` field.
  #[must_use]
  #[inline(always)]
  pub const fn warnings_slice(&self) -> &[SmolStr] {
    self.warnings.as_slice()
  }

  /// Errors (ExifTool emits these as its generated `Error` tag). Mirrors
  /// [`warnings_slice`](Self::warnings_slice): `Error` is defined in
  /// `Image::ExifTool::Extra` (`ExifTool.pm:1288-1296`) with `Groups =>
  /// \%allGroupsExifTool` (group1 `ExifTool`, `ExifTool.pm:1225`) — exactly
  /// like `Warning` (`ExifTool.pm:1297`). `sub Error` (`ExifTool.pm:5648`) is
  /// the plain `$self->FoundTag('Error', $str)`, so the serializer emits the
  /// first as `ExifTool:Error` under `-j -G1`. `_slice` projection of the
  /// `Vec<SmolStr>` field.
  #[must_use]
  #[inline(always)]
  pub const fn errors_slice(&self) -> &[SmolStr] {
    self.errors.as_slice()
  }

  /// Append a tag in extraction order, OR overwrite an existing same-key
  /// tag's value in place (faithful to Perl `FoundTag`, ExifTool.pm:9437-
  /// 9519). When a tag with the SAME `group` (both family-0 AND family-1)
  /// AND SAME `name` already exists, FoundTag's "higher-or-equal priority"
  /// branch (line 9554-9573) moves the OLD entry to a `"$tag ($n)"` slot
  /// and stores the NEW value under the canonical name. Net effect after
  /// the JSON serializer suppresses the `\(\d+\)` copy-keys: the LATEST
  /// `push` call's value wins.
  ///
  /// Faithful implementation here: replace-in-place (no copy-key tracking
  /// — those keys are NEVER serialized under default `-j -G1` because the
  /// `next if $tag =~ /^(.*?) ?\(/ and defined $$info{$1}` gate at
  /// exiftool:2744 unconditionally drops them, and exifast doesn't yet
  /// support `-a` / `Duplicates`-mode output where they'd surface).
  ///
  /// Codex R11 fix: the prior unconditional `self.tags.push(...)` left
  /// the first-occurrence wins via the serializer's `%noDups` (which
  /// matches Perl's @foundTags iteration), but it kept the FIRST value
  /// instead of the LAST — diverging from Perl for any format that emits
  /// duplicate chunks (e.g. AIFF NAME, AUTH, ANNO, APPL chunks). Oracle
  /// verified 2026-05-20 on a synthesized two-NAME-chunk AIFF: bundled
  /// `perl exiftool` emits `"AIFF:Name": "<second value>"`, NOT the first.
  pub fn push(&mut self, group: Group, name: impl Into<SmolStr>, value: TagValue) {
    let name = name.into();
    if let Some(tag) = self
      .tags
      .iter_mut()
      .find(|t| t.group_ref() == &group && t.name() == name.as_str())
    {
      tag.set_value(value);
    } else {
      self.tags.push(Tag::new(group, name, value));
    }
  }

  /// Push `value` under `(group, name)`, faithfully accumulating a repeat as
  /// ExifTool's `FoundTag` does for a `List => 1` tagInfo
  /// (`ExifTool.pm:9505-9520`):
  ///
  /// - First occurrence: identical to [`Self::push`] — appends a new
  ///   [`Tag`] with the given scalar value.
  /// - Same-`(group, name)` repeat: the existing tag's value is widened to
  ///   `TagValue::List([...])` and the new value is appended (Perl
  ///   `push @{$$valueHash{$tag}}, $value` after promoting a scalar
  ///   `$$valueHash{$tag}` via `[ $$valueHash{$tag} ]`,
  ///   `ExifTool.pm:9514-9518`). NO new tag entry is created — exactly
  ///   `return $tag` at `ExifTool.pm:9520`.
  /// - If the existing tag's value is *already* a `TagValue::List`,
  ///   `value` is appended to it (the recursive accumulation case for
  ///   3+ repeats).
  ///
  /// Callers should reach this entry point only when the source `TagDef`
  /// has `list() == true`; for plain (non-List) tags use [`Self::push`]
  /// (the serializer's `%noDups` first-wins then applies as before, so
  /// repeats are silently dropped — `exiftool:2950-2951`). The flag-vs-call
  /// split keeps the seam tiny: only Vorbis/ID3-like accumulators that
  /// faithfully need `List` semantics opt in; every existing push site is
  /// untouched.
  pub fn push_listable(&mut self, group: Group, name: impl Into<SmolStr>, value: TagValue) {
    let name: SmolStr = name.into();
    // Find an existing same-(group, name) tag (faithful to FoundTag's
    // `$$valueHash{$tag}` lookup at ExifTool.pm:9505 `defined
    // $$valueHash{$tag}`). Group equality is family-0 AND family-1 — same
    // identity used by `set_tag_value` and the serializer's `%noDups` token.
    if let Some(tag) = self
      .tags
      .iter_mut()
      .find(|t| t.group_ref() == &group && t.name() == name.as_str())
    {
      // ExifTool.pm:9514-9518 promote-and-push: a scalar becomes a 1-elem
      // list, then `push` appends. We model that with one `TagValue::List`
      // step containing both the old scalar and the new value. `mem::replace`
      // moves the existing `Vec` out (no clone) so 3+ repeats are amortized
      // O(1) per append, not O(n²).
      let placeholder = TagValue::List(Vec::new());
      let new_val = match std::mem::replace(tag.value_mut(), placeholder) {
        TagValue::List(mut items) => {
          items.push(value);
          TagValue::List(items)
        }
        scalar => TagValue::List(vec![scalar, value]),
      };
      tag.set_value(new_val);
      return;
    }
    // First occurrence: identical to push().
    self.tags.push(Tag::new(group, name, value));
  }

  /// Record a non-fatal NORMAL warning (`$et->Warn(msg)`, ignorable `0`), in
  /// occurrence order. ExifTool accumulates these via `$self->Warn(...)` and
  /// surfaces them as its generated `Warning` tag (`ExifTool.pm:1297`); the
  /// serializer emits the first as `ExifTool:Warning` under `-j -G1`
  /// (`ExifTool.pm:1225`).
  pub fn push_warning(&mut self, warning: impl Into<SmolStr>) {
    self.push_warning_with_level(warning, 0);
  }

  /// Record a MINOR warning (`$et->Warn(msg, ignorable)`, `ExifTool.pm:5616`)
  /// — the BARE message plus its ignorable level (`1` ⇒ `[minor]`, `2` ⇒
  /// `[Minor]`). The prefix is NOT baked in here: it is applied centrally by
  /// [`run_diagnostics`](crate::diagnostics::run_diagnostics) (the port's
  /// `sub Warn` analogue), so the literal lives in exactly one place. Pair the
  /// level with [`warning_ignorable`](Self::warning_ignorable).
  pub fn push_warning_with_level(&mut self, warning: impl Into<SmolStr>, ignorable: u8) {
    self.warnings.push(warning.into());
    self.warnings_ignorable.push(ignorable);
  }

  /// The `sub Warn` ignorable level for the warning at `index` (index-aligned
  /// with [`warnings_slice`](Self::warnings_slice)); `0` for an out-of-range
  /// index or a normal warning.
  #[must_use]
  #[inline(always)]
  pub fn warning_ignorable(&self, index: usize) -> u8 {
    self.warnings_ignorable.get(index).copied().unwrap_or(0)
  }

  /// Record an error, in occurrence order — the faithful analogue of
  /// `sub Error` (`ExifTool.pm:5648` `$self->FoundTag('Error', $str)`; the
  /// plain read path has no `DemoteErrors`/`IgnoreMinorErrors`, so it is
  /// exactly `FoundTag`, like `Warn`). ExifTool surfaces these as its
  /// generated `Error` tag (`ExifTool.pm:1288-1296`); the serializer emits
  /// the first as `ExifTool:Error` under `-j -G1` (`ExifTool.pm:1225`).
  /// Mirrors [`push_warning`](Self::push_warning) exactly.
  pub fn push_error(&mut self, error: impl Into<SmolStr>) {
    self.errors.push(error.into());
  }

  /// Is `File:FileType` (family-1 `File`) already on this metadata? Faithful
  /// to ExifTool's per-file `$$self{FileType}` marker: every `SetFileType`
  /// call pushes `File:FileType` as its first FoundTag (`ExifTool.pm:9702`),
  /// AND `$$self{FileType} = $fileType` engages first-call-wins
  /// (`ExifTool.pm:9701`). Since `$self` outlives the per-`Process<Type>`
  /// invocation, this marker is FILE-scoped, not candidate-scoped — a second
  /// candidate's `SetFileType` is faithfully a no-op (`ExifTool.pm:9681`
  /// `unless ($$self{FileType} and not $$self{DOC_NUM})`).
  #[must_use]
  pub fn has_file_type(&self) -> bool {
    self
      .tags
      .iter()
      .any(|t| t.group_ref().family1() == "File" && t.name() == "FileType")
  }

  /// Replace the value of the existing tag identified by `group` (family-0
  /// AND family-1) + `name`, in place — the faithful analogue of ExifTool
  /// overwriting `$$self{VALUE}{$tag}` (`ExifTool.pm:9717,9722,9724`).
  /// Returns `true` if such a tag existed and was replaced; `false` (no-op)
  /// if absent (mirrors `OverrideFileType`'s `if defined
  /// $$self{VALUE}{FileType}` guard, `ExifTool.pm:9715`). Append-style
  /// [`push`](Self::push) would be non-faithful here: the serializer's
  /// `%noDups` first-wins would keep the pre-override value.
  pub fn set_tag_value(&mut self, group: &Group, name: &str, value: TagValue) -> bool {
    match self
      .tags
      .iter_mut()
      .find(|t| t.group_ref() == group && t.name() == name)
    {
      Some(tag) => {
        tag.set_value(value);
        true
      }
      None => false,
    }
  }

  /// Existence query for `(group, name)`. The companion to
  /// [`set_tag_value`](Self::set_tag_value) used by format-specific
  /// duplicate-handling paths (e.g. the Audible AA dictionary loop,
  /// which mirrors Perl `FoundTag` last-wins via "if exists ⇒ replace
  /// in place, else ⇒ push"). Keeps callers allocation-free on the
  /// common no-duplicate path.
  #[must_use]
  pub fn has_tag(&self, group: &Group, name: &str) -> bool {
    self
      .tags
      .iter()
      .any(|t| t.group_ref() == group && t.name() == name)
  }

  /// Faithful `$$et{DoneID3}` getter. `None` ⇒ ProcessID3 has not run;
  /// `Some(n)` ⇒ run, with `n` being the ID3v1-trailer size in bytes
  /// (ID3.pm:1527 `$$et{DoneID3} = $trailSize`; 0 when no trailer). Used
  /// by `unless ($$et{DoneID3})` guards (APE.pm:124, MPC.pm:84, etc.) and
  /// by APE.pm:169 `$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1`.
  #[must_use]
  #[inline(always)]
  pub const fn done_id3(&self) -> Option<usize> {
    self.done_id3
  }

  /// Faithful `$$et{DoneID3} = $n` setter. Pass `0` for the "ID3v2 found,
  /// no v1 trailer" case (ID3.pm:1436 `$$et{DoneID3} = 1` — Perl-truthy,
  /// not used in arithmetic; the trailer-aware path at ID3.pm:1527
  /// overwrites with `$trailSize`). Returns `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn set_done_id3(&mut self, trailer_size: usize) -> &mut Self {
    self.done_id3 = Some(trailer_size);
    self
  }

  /// Faithful `$$et{DoneAPE}` getter. `true` ⇒ ProcessAPE has run on this
  /// `$self`. Used by ID3.pm:1723 `if ($rtnVal and not $$et{DoneAPE})` to
  /// gate the MP3→APE trailer fallback at ID3.pm:1722-1727.
  #[must_use]
  #[inline(always)]
  pub const fn done_ape(&self) -> bool {
    self.done_ape
  }

  /// Faithful `$$et{DoneAPE} = 1` setter (APE.pm:131, immediately after
  /// the embedded-ID3 check and BEFORE the magic/header block). Must be
  /// called by every entry point that runs APE's tag-extraction work
  /// (full `ProcessApe::process` AND the chained `process_trailer_only`),
  /// so a subsequent MP3 `ProcessMp3::process` skips the APE.pm:1722-1727
  /// trailer fallback faithfully. Returns `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn set_done_ape(&mut self) -> &mut Self {
    self.done_ape = true;
    self
  }
}

// ===========================================================================
// Optional serde `Serialize` impls (skill §8: one anonymous gated const block;
// single `#[cfg]` + `doc(cfg)`; private helpers scoped inside; nothing `pub`).
//
// DESIGN (Contract B / #197): the serializer reproduces ExifTool's TOKEN-EXACT
// JSON typing — the bare-number-vs-quoted-string distinction the real `exiftool`
// JSON writer produces. ExifTool stringifies EVERY scalar then runs ONE
// `EscapeJSON` number gate (`exiftool:3809`,
// [`escape_json_is_number`](crate::value::escape_json_is_number)): a value whose
// stringified form is a clean JSON number is printed BARE, everything else is
// QUOTED. Each numeric/string arm below mirrors that exactly:
//   * `Str`  -> a numeric-looking string lands as a BARE number (e.g. an
//               `APE:Year` "2005" -> `2005`, `ExifTool:ExifToolVersion` "13.59"
//               -> `13.59`); a non-numeric string (PrintConv label,
//               `:`/`/`/space-bearing value) stays quoted; a `"true"`/`"false"`
//               string stays a bare JSON boolean (`exiftool:3804-3805`).
//   * `I64`/`U64` -> a bare integer token, EXCEPT a `>= 16`-digit integer (the
//               gate's 15-digit cap; e.g. a `u64` above `i64::MAX` such as
//               `PLIST:Big`) which FAILS the gate and is QUOTED with its true
//               value.
//   * `F64`  -> `%.15g` (ExifTool's default NV stringification) then gated: a
//               finite in-gate rendering is a bare number; an out-of-gate
//               rendering (a `>16`-fraction-digit float such as a `DV:Duration`
//               `0.00122222222222222`) is QUOTED; a non-finite f64 is the
//               titlecase `Inf`/`-Inf`/`NaN` quoted word.
//   * `Bytes` -> the binary placeholder string; `Rational` -> its
//               ExifTool-rounded numeric value (gated) or the `inf`/`undef` word.
// The companion [`crate::jsondiff`] comparator is STRICT (token-exact) by
// default ([`json_equivalent_strict`](crate::jsondiff::json_equivalent_strict)):
// it distinguishes `"2"` from `2`, so the conformance suite pins this typing.
// (The value-semantic [`json_equivalent`](crate::jsondiff::json_equivalent) is
// retained for the few call sites that compare two exifast renderings.)
// ===========================================================================

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
const _: () = {
  use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

  /// Emit an in-gate fractional/exponent numeric STRING (`escape_json_is_number`
  /// already verified its grammar) as a BARE JSON number.
  ///
  /// **Common path (the value parses to a FINITE f64).** Emit via the
  /// allocation-free `serialize_f64`. serde renders a value-equal bare number
  /// (`"13.59"` → `13.59`), which the token-exact (strict) comparator accepts
  /// under its within-one-type numeric insensitivity (`1.50` ≈ `1.5`,
  /// `1.4e2` ≈ `140.0`). This keeps every existing golden byte-output unchanged
  /// AND adds NO allocation on the hot path (the alloc-budget regression guard).
  ///
  /// **Soundness path (the f64 does not FAITHFULLY represent the token).** The
  /// gate admits an exponent up to `e[-+]?\d{1,3}` (faithful to `exiftool:3810`),
  /// so it accepts a token OUTSIDE finite-f64 range on BOTH sides. An OVERFLOW
  /// token such as `1e999` parses to `INFINITY`; `serialize_f64(INFINITY)` would
  /// emit `null` (silent corruption). An UNDERFLOW token such as `1e-999` parses
  /// to a FINITE `0.0`, so `is_finite()` alone would let it through and emit a
  /// bare `0.0`, silently rewriting the nonzero source token to zero. In EITHER
  /// case emit the ORIGINAL token as a QUOTED JSON STRING instead.
  ///
  /// **Completeness (the f64-representation class is CLOSED).** A gate-matching
  /// token falls into exactly one of three cases: (a) it overflows finite-f64
  /// range ⇒ `!is_finite()` ⇒ string; (b) it is a nonzero value that underflows
  /// to zero ⇒ `f == 0.0 && lexeme_is_nonzero(token)` ⇒ string; or (c) it parses
  /// to a finite f64 that faithfully denotes its value ⇒ bare number. There is no
  /// fourth corrupting case: a genuine-zero lexeme (`0`/`0.0`/`0e-5`/`-0`) is
  /// `f == 0.0` with a zero significand, so it stays a bare `0`; and precision
  /// loss strictly within finite-nonzero range is value-preserving under the
  /// token-exact comparator (`1.50` ≈ `1.5`). Hence [`f64_token_is_faithful`]
  /// (`is_finite() && !(f == 0.0 && lexeme_is_nonzero)`) is the complete,
  /// crate-wide predicate for "the f64 may be emitted bare".
  ///
  /// NOTE — this is a deliberate CRAFTED-input divergence from ExifTool's
  /// `EscapeJSON`, which `return $str`s an over-range exponent BARE. Emitting a
  /// bare number here (e.g. via `serde_json::value::RawValue`) is NOT sound on
  /// every serde path: the same `Serialize` impl is driven by
  /// `serde_json::to_value` (`Rendered` / the typed-serde+parity harness), and
  /// with this crate's serde_json features (`raw_value`+`alloc`, NO
  /// `arbitrary_precision`) materializing a `RawValue("1e999")` into a
  /// `serde_json::Value` REPARSES the token → `NumberOutOfRange` → `to_value`
  /// returns `Err`/panics. A quoted string is sound on EVERY path
  /// (`to_string` AND `to_value`), never panics, never emits `null`. Per the
  /// project ship-bar, `1e999` never appears in real metadata, so byte-for-byte
  /// crafted-faithfulness is optional here while soundness is required. (We do
  /// NOT enable `arbitrary_precision` — a broad dependency-feature change that
  /// could perturb the comparator.)
  fn serialize_in_gate_number_str<S: Serializer>(text: &str, s: S) -> Result<S::Ok, S::Error> {
    if let Ok(f) = text.parse::<f64>()
      && crate::value::f64_token_is_faithful(f, text)
    {
      return s.serialize_f64(f);
    }
    // The f64 does NOT faithfully represent the token: an over-range exponent
    // either OVERFLOWED to non-finite (`1e999`) or UNDERFLOWED a nonzero
    // significand to `0.0` (`1e-999`). Emit the source token as a QUOTED string.
    // Sound on every serde path (never `null`/`0.0` corruption, never a
    // `to_value` `NumberOutOfRange` error/panic).
    s.serialize_str(text)
  }

  impl Serialize for Rational {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      if self.denominator == 0 {
        // ExifTool: n/0 (n!=0) -> "inf", 0/0 -> "undef" (non-numeric words,
        // emitted as JSON strings by `EscapeJSON`). Value-faithful: a string.
        return s.serialize_str(if self.numerator != 0 { "inf" } else { "undef" });
      }
      // ExifTool stringifies a rational via `RoundFloat(n/d, sig)`
      // (`%.{sig}g`). Emit that ROUNDED value as a number — re-parsing the
      // rounded text yields the same f64 the golden's rounded token denotes,
      // so the value-semantic comparator matches it. (Serializing the RAW
      // `n/d` f64 would emit more digits, a DIFFERENT value than the golden's
      // rounded one.)
      let rounded = self.exiftool_val_str();
      match rounded.parse::<f64>() {
        Ok(f) if f.is_finite() => s.serialize_f64(f),
        // Defensive: a rounded form that does not re-parse as finite (not
        // reachable for a non-zero denominator) falls back to its text.
        _ => s.serialize_str(&rounded),
      }
    }
  }

  impl Serialize for TagValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      match self {
        // ExifTool stringifies every integer and runs the one `EscapeJSON`
        // number gate (`exiftool:3809`). A value within the gate's 15-digit
        // integer cap is a bare JSON number; a `>= 16`-digit integer FAILS the
        // gate and is emitted as a QUOTED string, byte-identical to bundled
        // (Contract B / #197). `serialize_i64` emits an exact integer token for
        // the common in-gate case; the out-of-gate quoted form renders the same
        // decimal text.
        TagValue::I64(n) => {
          let text = n.to_string();
          if escape_json_is_number(&text) {
            s.serialize_i64(*n)
          } else {
            s.serialize_str(&text)
          }
        }
        // Full unsigned value (no saturation to i64::MAX); the gate keeps a
        // `>= 16`-digit `u64` (e.g. a `PLIST:Big` above `i64::MAX`, or a large
        // file size) a QUOTED string exactly as bundled stringifies-then-gates
        // it, while an in-gate value stays a bare number.
        TagValue::U64(n) => {
          let text = n.to_string();
          if escape_json_is_number(&text) {
            s.serialize_u64(*n)
          } else {
            s.serialize_str(&text)
          }
        }
        TagValue::F64(n) => {
          if n.is_finite() {
            // ExifTool stringifies a float with `%.15g` (its default NV
            // stringification, `ExifTool.pm` RoundFloat / the JSON writer), then
            // runs the `EscapeJSON` number gate on that text. The 15-sig-fig
            // rounding is a VALUE step (e.g. 2.639229024943311 ->
            // 2.63922902494331); the gate is a TOKEN step — a rendering whose
            // fraction exceeds the gate's 16-digit cap (e.g. a `DV:Duration` of
            // `0.00122222222222222`, 17 fraction digits because the leading
            // zeros do not count toward `%.15g`'s significant figures) FAILS the
            // gate and is emitted as a QUOTED string, byte-identical to bundled
            // (Contract B / #197). An in-gate rendering is re-parsed so serde's
            // number equals the golden's rounded number.
            let rounded = format_g(*n, 15);
            if escape_json_is_number(&rounded) {
              // Re-parse the ROUNDED token and emit a bare number ONLY when it
              // is FAITHFUL ([`f64_token_is_faithful`], Contract B / #197) — this
              // makes the f64-representation predicate UNIVERSAL across the
              // string-origin paths (the R5 consumers) AND this numeric-origin
              // arm. `n` is finite, but `format_g(_, 15)` of a value near
              // `f64::MAX` can round UP past `f64::MAX` (e.g. `f64::MAX` →
              // `"1.79769313486232e+308"`), which the gate admits yet which
              // reparses to `INFINITY` → `serialize_f64(INFINITY)` would emit
              // `null`, silently corrupting a valid finite value. The faithful
              // predicate routes that extreme rounded form to a SOUND quoted
              // string instead (never `null`). Every normal finite metadata
              // double round-trips finite → bare number, UNCHANGED. (The residual
              // crafted-input faithful-bare-emission gap for such an extreme value
              // is tracked in the followup issue.)
              match rounded.parse::<f64>() {
                Ok(f) if f64_token_is_faithful(f, &rounded) => s.serialize_f64(f),
                // Over-range rounded token (overflow to non-finite) or an
                // unreachable non-parse: the faithful quoted source string.
                _ => s.serialize_str(&rounded),
              }
            } else {
              // Out of gate (a `>16`-fraction-digit or `>15`-integer-digit
              // rendering) ⇒ the quoted string ExifTool's `EscapeJSON` emits.
              s.serialize_str(&rounded)
            }
          } else {
            // serde_json errors on a non-finite number; ExifTool emits the
            // titlecase `Inf`/`-Inf`/`NaN` string. `perl_nonfinite_str`
            // covers every non-finite f64; the `None` arm is unreachable
            // under the `!is_finite` guard but falls back defensively.
            match perl_nonfinite_str(*n) {
              Some(text) => s.serialize_str(text),
              None => s.serialize_str(&n.to_string()),
            }
          }
        }
        // ExifTool `EscapeJSON` boolean coercion (`exiftool:3804-3805`:
        // `return lc($str) if $str =~ /^(true|false)$/i and $json < 2`): a
        // string that case-insensitively matches `true`/`false` is emitted as
        // a bare JSON BOOLEAN (e.g. an MPEG `CopyrightFlag` PrintConv of
        // `"True"` -> `true`). The value-semantic comparator does NOT coerce a
        // string to a bool (different JSON types), so this coercion must happen
        // here to match the golden's bare `true`/`false`.
        TagValue::Str(text) if text.eq_ignore_ascii_case("true") => s.serialize_bool(true),
        TagValue::Str(text) if text.eq_ignore_ascii_case("false") => s.serialize_bool(false),
        // ExifTool's terminal `EscapeJSON` NUMBER gate (`exiftool:3809`,
        // Contract B / #197): a string whose ENTIRE text is an
        // [`escape_json_is_number`] is emitted as a BARE JSON number — exactly
        // the token ExifTool's JSON writer produces for that value (e.g.
        // `ExifTool:ExifToolVersion` "13.59" -> `13.59`, an `APE:Year` "2005"
        // -> `2005`). A pure integer (no `.`/`e`) routes through the integer
        // writer so serde emits an exact integer token (`2005`, not `2005.0`);
        // a fractional/exponent value routes through `serialize_f64`. The gate's
        // 15-digit integer cap keeps a `>= 16`-digit integer (e.g. a `u64` above
        // `i64::MAX`) a QUOTED string, byte-identical to bundled. Anything not a
        // clean JSON number (a PrintConv label, a `:`/`/`/space-bearing value,
        // `inf`/`undef`/`Inf`/`NaN`) stays a quoted string.
        TagValue::Str(text) if escape_json_is_number(text) => {
          // A pure integer ⇒ an exact integer token; the gate caps the integer
          // part at 15 digits, so it always fits `i64`/`u64`.
          let is_integer = !text.bytes().any(|b| b == b'.' || b == b'e' || b == b'E');
          if is_integer {
            if let Some(rest) = text.strip_prefix('-') {
              if let Ok(n) = rest.parse::<i64>() {
                return s.serialize_i64(-n);
              }
            } else if let Ok(n) = text.parse::<u64>() {
              return s.serialize_u64(n);
            }
          }
          // Fractional / exponent in-gate string (Contract B / #197). A FINITE
          // value emits a value-equal bare number via the allocation-free
          // `serialize_f64` (unchanged golden bytes); a value OUTSIDE finite-f64
          // range that the gate still admits (`e[-+]?\d{1,3}`, e.g. `1e999`)
          // emits the ORIGINAL token as a QUOTED string — sound on every serde
          // path (`to_string` AND `to_value`) instead of the `null` that
          // `serialize_f64(INFINITY)` would corrupt it to, or the `to_value`
          // `NumberOutOfRange` a bare raw token would trigger. See the helper.
          serialize_in_gate_number_str(text, s)
        }
        // Otherwise STANDARD string emission: a non-numeric value (a PrintConv
        // label, a `:`/`/`/space-bearing value, `inf`/`undef`/`Inf`/`NaN`)
        // stays a quoted JSON string.
        //
        // ExifTool's JSON writer runs `$str =~ tr/\0//d` (`exiftool:3819`) —
        // it removes EVERY NUL from a string value (NOT just trailing) before
        // the `\u`-escape of the other control characters. `serde_json`
        // instead escapes a NUL as `\0`, so a value carrying embedded NULs
        // (e.g. a RIFF `ltxt` LabeledText whose `substr($val,18)` text region
        // begins with the unconsumed `int16u` Codepage bytes) would diverge.
        // Strip the NULs here to match — only allocates when a NUL is present,
        // which no non-RIFF-cue value carries, so existing output is unchanged.
        TagValue::Str(text) => {
          if text.as_bytes().contains(&0) {
            let stripped: String = text.chars().filter(|&c| c != '\0').collect();
            s.serialize_str(&stripped)
          } else {
            s.serialize_str(text)
          }
        }
        TagValue::Bool(b) => s.serialize_bool(*b),
        // ExifTool universal no-`-b` placeholder (a plain string, never
        // numeric). N = byte length. Shares `binary_placeholder` with the
        // length-only callers (CRW binary leaves) so the text stays identical.
        TagValue::Bytes(b) => s.serialize_str(&binary_placeholder(b.len() as u64)),
        TagValue::Rational(r) => r.serialize(s),
        TagValue::List(items) => {
          let mut seq = s.serialize_seq(Some(items.len()))?;
          for item in items {
            seq.serialize_element(item)?;
          }
          seq.end()
        }
        // Structured ExifTool `-struct` value: an ordered JSON object.
        TagValue::Map(pairs) => {
          let mut map = s.serialize_map(Some(pairs.len()))?;
          for (k, v) in pairs {
            map.serialize_entry(k.as_str(), v)?;
          }
          map.end()
        }
      }
    }
  }
};

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
    let names: Vec<&str> = m.tags_slice().iter().map(Tag::name).collect();
    assert_eq!(names, ["FileType", "SampleRate"]);
    assert_eq!(m.tags_slice()[1].group_ref().family1(), "AAC");
  }

  #[test]
  fn push_listable_coalesces_repeats_into_list() {
    // R1-F2 regression pin. ExifTool's FoundTag accumulates `List => 1`
    // tagInfos via `$$self{LIST_TAGS}{$tagInfo} = $tag` (ExifTool.pm:9606)
    // and `push @{$$valueHash{$tag}}, $value` (ExifTool.pm:9520). Two
    // `push_listable` calls under the same `(group, name)` → one tag, with
    // value `List([scalar1, scalar2])` (NOT two separate tags).
    let mut m = Metadata::new("x");
    let g = Group::new("Vorbis", "Vorbis");
    m.push_listable(g.clone(), "Artist", TagValue::Str("Alice".into()));
    m.push_listable(g.clone(), "Artist", TagValue::Str("Bob".into()));
    assert_eq!(m.tags_slice().len(), 1, "two pushes coalesce to one tag");
    assert_eq!(m.tags_slice()[0].name(), "Artist");
    assert_eq!(
      m.tags_slice()[0].value_ref(),
      &TagValue::List(vec![
        TagValue::Str("Alice".into()),
        TagValue::Str("Bob".into()),
      ])
    );

    // Third push extends the list (ExifTool.pm:9518 `push @{...}`).
    m.push_listable(g.clone(), "Artist", TagValue::Str("Carol".into()));
    assert_eq!(m.tags_slice().len(), 1);
    assert_eq!(
      m.tags_slice()[0].value_ref(),
      &TagValue::List(vec![
        TagValue::Str("Alice".into()),
        TagValue::Str("Bob".into()),
        TagValue::Str("Carol".into()),
      ])
    );

    // First-call for a fresh (group, name) is identical to push(): a new
    // scalar tag — NOT a 1-element list.
    m.push_listable(g.clone(), "Performer", TagValue::Str("X".into()));
    let p = m
      .tags_slice()
      .iter()
      .find(|t| t.name() == "Performer")
      .unwrap();
    assert_eq!(p.value_ref(), &TagValue::Str("X".into())); // scalar, not List

    // Different group (family-1) ⇒ NOT the same tag identity (ExifTool's
    // `$$valueHash{$tag}` keyed implicitly by group too).
    m.push_listable(
      Group::new("Vorbis", "Other"),
      "Artist",
      TagValue::Str("Z".into()),
    );
    let artists: Vec<_> = m
      .tags_slice()
      .iter()
      .filter(|t| t.name() == "Artist")
      .collect();
    assert_eq!(artists.len(), 2, "different family1 ⇒ separate tag");
  }

  #[test]
  fn push_listable_preserves_order_of_unrelated_tags() {
    // The accumulation site is the EXISTING tag; later unrelated pushes
    // append after the accumulated tag in extraction order.
    let mut m = Metadata::new("x");
    let g = Group::new("Vorbis", "Vorbis");
    m.push_listable(g.clone(), "Artist", TagValue::Str("Alice".into()));
    m.push(g.clone(), "Title", TagValue::Str("T".into())); // plain push
    m.push_listable(g.clone(), "Artist", TagValue::Str("Bob".into()));
    let names: Vec<_> = m.tags_slice().iter().map(Tag::name).collect();
    // Order: Artist (coalesced), Title. NO second Artist tag.
    assert_eq!(names, vec!["Artist", "Title"]);
    assert_eq!(
      m.tags_slice()[0].value_ref(),
      &TagValue::List(vec![
        TagValue::Str("Alice".into()),
        TagValue::Str("Bob".into()),
      ])
    );
  }

  #[test]
  fn push_duplicate_group_and_name_overwrites_last_wins() {
    // Codex R11 regression: faithful Perl `FoundTag` (`ExifTool.pm:9437-
    // 9519`) — when a tag with the SAME group AND name is FoundTag'd a
    // second time, the OLD value is moved to a `"Name (1)"` copy-slot
    // and the NEW value is stored under the canonical name; the JSON
    // serializer suppresses the copy-key, so the LATEST `push` wins.
    // Pinned here as a unit-level invariant; the conformance fixture
    // `AIFF_dup_name.aif` pins the JSON-output side.
    let mut m = Metadata::new("dup.aif");
    let aiff = Group::new("AIFF", "AIFF");
    m.push(aiff.clone(), "Name", TagValue::Str("First Name".into()));
    m.push(aiff.clone(), "Name", TagValue::Str("Second Name".into()));
    // No new tag appended — overwritten in place.
    assert_eq!(m.tags_slice().len(), 1);
    assert_eq!(m.tags_slice()[0].name(), "Name");
    assert_eq!(
      m.tags_slice()[0].value_ref(),
      &TagValue::Str("Second Name".into()),
      "LAST `push` value must win for duplicate group+name"
    );
  }

  #[test]
  fn push_different_group_or_name_appends_distinct_tags() {
    // The replace-in-place semantics are gated on EXACT group + name
    // match. A different family-1 OR a different name appends a NEW
    // tag (both are distinct JSON keys under `-G1`).
    let mut m = Metadata::new("x.dat");
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("AAC".into()),
    );
    // Same name, different group ⇒ distinct tag.
    m.push(
      Group::new("File", "System"),
      "FileType",
      TagValue::Str("OTHER".into()),
    );
    // Same group, different name ⇒ distinct tag.
    m.push(
      Group::new("File", "File"),
      "MIMEType",
      TagValue::Str("audio/aac".into()),
    );
    assert_eq!(m.tags_slice().len(), 3);
  }

  #[test]
  fn set_tag_value_replaces_existing_in_place() {
    // Faithful `$$self{VALUE}{FileType}=x` overwrite (ExifTool.pm:9717):
    // an existing tag's value is replaced in place — NOT appended.
    let mut m = Metadata::new("x");
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("M4A".into()),
    );
    m.push(Group::new("AAC", "AAC"), "SampleRate", TagValue::I64(44100));
    let before = m.tags_slice().len();
    let replaced = m.set_tag_value(
      &Group::new("File", "File"),
      "FileType",
      TagValue::Str("AAC".into()),
    );
    assert!(replaced); // existed ⇒ true
    assert_eq!(m.tags_slice().len(), before); // no new tag appended
    let ft = m
      .tags_slice()
      .iter()
      .find(|t| t.name() == "FileType")
      .unwrap();
    assert_eq!(ft.value_ref(), &TagValue::Str("AAC".into())); // value changed
    // exactly one FileType tag — the value was overwritten, not duplicated.
    assert_eq!(
      m.tags_slice()
        .iter()
        .filter(|t| t.name() == "FileType")
        .count(),
      1
    );
  }

  #[test]
  fn set_tag_value_absent_is_noop() {
    // Mirrors `OverrideFileType`'s `if defined $$self{VALUE}{FileType}`
    // guard (ExifTool.pm:9715): absent ⇒ false, nothing changes.
    let mut m = Metadata::new("x");
    m.push(Group::new("AAC", "AAC"), "SampleRate", TagValue::I64(44100));
    let before = m.tags_slice().len();
    let replaced = m.set_tag_value(
      &Group::new("File", "File"),
      "FileType",
      TagValue::Str("AAC".into()),
    );
    assert!(!replaced); // absent ⇒ false
    assert_eq!(m.tags_slice().len(), before); // len unchanged
  }

  #[test]
  fn set_tag_value_requires_both_group_families() {
    // ExifTool's `%VALUE` is keyed by tag within a group identity; our
    // `Group` carries family-0 AND family-1 and both must match (a tag with
    // the right name but a different group is NOT the target).
    let mut m = Metadata::new("x");
    m.push(
      Group::new("AAC", "AAC"),
      "FileType",
      TagValue::Str("nope".into()),
    );
    let replaced = m.set_tag_value(
      &Group::new("File", "File"),
      "FileType",
      TagValue::Str("AAC".into()),
    );
    assert!(!replaced);
    assert_eq!(m.tags_slice()[0].value_ref(), &TagValue::Str("nope".into()));
  }

  /// Contract B / #197 — the `TagValue::Str` serializer applies ExifTool's
  /// terminal `EscapeJSON` number gate (`exiftool:3809`): a numeric-looking
  /// string lands as a BARE JSON number (token-exact with bundled), a
  /// non-numeric string stays quoted, and an integer of `>= 16` digits stays
  /// quoted (the gate's 15-digit integer cap — this is what keeps `PLIST:Big`
  /// = `9223372036854775808` a quoted string, exactly as bundled emits it).
  #[cfg(feature = "serde")]
  #[test]
  fn str_serializes_through_escape_json_number_gate() {
    let j = |v: &TagValue| serde_json::to_string(v).unwrap();
    // A plain integer string ⇒ a bare JSON number.
    assert_eq!(j(&TagValue::Str("2".into())), "2");
    assert_eq!(j(&TagValue::Str("44100".into())), "44100");
    assert_eq!(j(&TagValue::Str("-3".into())), "-3");
    // A fractional/exponent numeric string ⇒ a bare JSON number.
    assert_eq!(j(&TagValue::Str("13.59".into())), "13.59");
    // A non-numeric string ⇒ stays a quoted JSON string.
    assert_eq!(j(&TagValue::Str("abc".into())), "\"abc\"");
    assert_eq!(j(&TagValue::Str("2.64 s".into())), "\"2.64 s\"");
    assert_eq!(j(&TagValue::Str("11.1.102".into())), "\"11.1.102\"");
    // The gate's 15-digit integer cap: a 16+-digit integer is OUT of gate and
    // stays a quoted string (the `PLIST:Big` u64-above-i64::MAX case).
    assert_eq!(
      j(&TagValue::Str("9223372036854775808".into())),
      "\"9223372036854775808\""
    );
    // A 19-digit integer (u64::MAX-ish) likewise stays quoted.
    assert_eq!(
      j(&TagValue::Str("1234567890123456789".into())),
      "\"1234567890123456789\""
    );
    // A 15-digit integer is IN gate ⇒ bare number (boundary just below the cap).
    assert_eq!(
      j(&TagValue::Str("123456789012345".into())),
      "123456789012345"
    );
    // The `true`/`false` boolean coercion still precedes the number gate.
    assert_eq!(j(&TagValue::Str("True".into())), "true");
    assert_eq!(j(&TagValue::Str("false".into())), "false");
  }

  /// FINDING 2 (Codex) — `escape_json_is_number` admits an exponent of up to
  /// `e[-+]?\d{1,3}` (faithful to ExifTool `exiftool:3810`), so it accepts
  /// `1e999`, which is OUTSIDE finite-f64 range. Routing such a string through
  /// `f64` (the old path) produced `INFINITY` → `serialize_f64` → `null` (silent
  /// corruption). The fix: a FINITE in-gate value keeps the hot,
  /// allocation-free `serialize_f64` path (a value-equal bare number the strict
  /// comparator accepts, no golden/budget change); a NON-FINITE one (the rare
  /// over-range crafted case) emits the ORIGINAL token as a QUOTED string —
  /// SOUND on every serde path (a bare raw token would `NumberOutOfRange` under
  /// `serde_json::to_value`; see `str_over_f64_range_exponent_to_value_is_ok_…`).
  /// This must (a) NOT panic, (b) emit VALID JSON, and (c) NEVER emit `null`.
  #[cfg(feature = "serde")]
  #[test]
  fn str_over_f64_range_exponent_emits_quoted_token_not_null() {
    let j = |v: &TagValue| serde_json::to_string(v).unwrap();
    // SOUNDNESS — out-of-f64-range exponents must NOT become `null`. They are
    // emitted as a QUOTED string carrying the EXACT source token (sound on
    // every serde path).
    assert_eq!(j(&TagValue::Str("1e999".into())), r#""1e999""#);
    assert_eq!(j(&TagValue::Str("-1e999".into())), r#""-1e999""#);
    assert_eq!(j(&TagValue::Str("1e309".into())), r#""1e309""#); // just above f64 max
    // The emitted text is syntactically VALID JSON (a string), it round-trips
    // as a `RawValue`, and it is never the `null` the old
    // `serialize_f64(INFINITY)` produced.
    for tok in ["1e999", "-1e999", "1e309"] {
      let out = j(&TagValue::Str(tok.into()));
      assert_ne!(out, "null", "over-range token must not corrupt to null");
      let rv: Result<Box<serde_json::value::RawValue>, _> = serde_json::from_str(&out);
      assert!(
        rv.is_ok(),
        "emitted token {out:?} must re-parse as a RawValue"
      );
      // The string's decoded payload is the exact original token.
      assert_eq!(
        serde_json::from_str::<String>(&out).unwrap(),
        tok,
        "over-range token must round-trip byte-identically as the string payload"
      );
    }
    // In-RANGE fractional/exponent strings keep the value-equal bare number from
    // the allocation-free f64 path (serde's canonical rendering). The strict
    // comparator's within-type numeric insensitivity treats these as equal to
    // any same-valued golden token (`3.4e38` == `3.4e+38`, `1e3` == `1000.0`).
    assert_eq!(j(&TagValue::Str("3.4e38".into())), "3.4e+38");
    assert_eq!(j(&TagValue::Str("1e3".into())), "1000.0");
    assert_eq!(j(&TagValue::Str("13.59".into())), "13.59");
    // A pure in-gate integer still routes through the exact integer writer.
    assert_eq!(j(&TagValue::Str("2005".into())), "2005");
  }

  /// FINDING 1 (Codex, R-B follow-up) — the over-f64-range raw-token path must be
  /// SOUND on EVERY serde path, not just `serde_json::to_string`. The `Serialize`
  /// impl is also driven by `serde_json::to_value` (used by `Rendered` and the
  /// typed-serde / parity harness). With THIS crate's serde_json features
  /// (`raw_value`+`alloc`, NO `arbitrary_precision`), serializing a
  /// `RawValue("1e999")` INTO a `serde_json::Value` REPARSES the token and
  /// `1e999` → `NumberOutOfRange` → `to_value` returns `Err` (or panics at an
  /// `expect` site). The fix emits a QUOTED STRING for the non-finite over-range
  /// case (sound on `to_string` AND `to_value`; never `Err`, never panic, never
  /// `null`). This test exercises `to_value` specifically and asserts `Ok(String)`.
  #[cfg(feature = "json")]
  #[test]
  fn str_over_f64_range_exponent_to_value_is_ok_string_not_err() {
    for tok in ["1e999", "-1e999", "1e309"] {
      // `to_value` must NOT error/panic for an over-range numeric token.
      let v = serde_json::to_value(TagValue::Str(tok.into()))
        .expect("to_value must not error on an over-f64-range numeric string");
      // The sound fallback is a JSON STRING carrying the original token (never a
      // number, never null) — value-faithful and round-trippable on every path.
      assert_eq!(
        v,
        serde_json::Value::String(tok.to_string()),
        "over-range token must serialize to a quoted JSON string under to_value"
      );
      assert!(!v.is_null(), "over-range token must never become null");
    }
    // The FINITE in-gate fractional/exponent path is unchanged: a value-equal
    // BARE number on `to_value` too (no quoting, no allocation regression).
    assert_eq!(
      serde_json::to_value(TagValue::Str("1e3".into())).unwrap(),
      serde_json::json!(1000.0)
    );
    assert_eq!(
      serde_json::to_value(TagValue::Str("13.59".into())).unwrap(),
      serde_json::json!(13.59)
    );
  }

  /// Contract B / #197 — the SYMMETRIC (under) side of the f64-representation
  /// class. The gate admits an exponent `e[-+]?\d{1,3}`, so it also accepts a
  /// token that UNDERFLOWS to a finite `0.0`: `1e-999` `parse::<f64>()`'s to
  /// `Ok(0.0)` (finite), which the finite-only guard would emit as a bare `0.0`,
  /// silently rewriting the nonzero source token to zero. The completed predicate
  /// `is_finite() && !(f == 0.0 && lexeme_is_nonzero)` routes a nonzero-underflow
  /// token to the QUOTED-string (preserve) path while keeping a GENUINE zero
  /// token a bare `0`/`0.0` and a finite-nonzero in-range value a bare number.
  #[cfg(feature = "serde")]
  #[test]
  fn str_underflow_exponent_preserves_nonzero_token_not_zero() {
    let j = |v: &TagValue| serde_json::to_string(v).unwrap();
    // A NONZERO significand that underflows to `0.0` ⇒ preserved as a QUOTED
    // string carrying the exact token, NEVER rewritten to a bare `0`/`0.0`.
    assert_eq!(j(&TagValue::Str("1e-999".into())), r#""1e-999""#);
    assert_eq!(j(&TagValue::Str("-1e-999".into())), r#""-1e-999""#);
    assert_eq!(j(&TagValue::Str("9e-400".into())), r#""9e-400""#);
    for tok in ["1e-999", "-1e-999", "9e-400"] {
      let out = j(&TagValue::Str(tok.into()));
      assert_ne!(out, "0", "nonzero-underflow token must not corrupt to 0");
      assert_ne!(
        out, "0.0",
        "nonzero-underflow token must not corrupt to 0.0"
      );
      assert_eq!(
        serde_json::from_str::<String>(&out).unwrap(),
        tok,
        "nonzero-underflow token must round-trip byte-identically as the string payload"
      );
    }
    // A GENUINE zero token (significand is zero) legitimately denotes the value
    // zero ⇒ stays a BARE number, not quoted.
    assert_eq!(j(&TagValue::Str("0e-5".into())), "0.0");
    assert_eq!(j(&TagValue::Str("0.0".into())), "0.0");
    // A FINITE tiny IN-RANGE value (nonzero, does NOT underflow) ⇒ a bare number,
    // NOT a quoted string — the predicate must not over-trigger on small magnitudes.
    assert_eq!(j(&TagValue::Str("1e-300".into())), "1e-300");
  }

  /// Contract B / #197 — the `lexeme_is_nonzero` significand predicate that
  /// completes the f64-representation gate. True iff a digit `1..=9` precedes the
  /// exponent marker (sign and decimal point are non-digits, skipped).
  #[test]
  fn lexeme_is_nonzero_classifies_significand() {
    // Nonzero significands (a `1..=9` digit before any `e`/`E`).
    for tok in ["1e-999", "-1e-999", "9e-400", "1.5", "0.0001", "1e3", "100"] {
      assert!(lexeme_is_nonzero(tok), "{tok} has a nonzero significand");
    }
    // Genuine-zero significands (every significand digit is `0`).
    for tok in [
      "0", "0.0", "0.", ".0", "-0", "+0.0", "0e-5", "0e10", "00.000",
    ] {
      assert!(
        !lexeme_is_nonzero(tok),
        "{tok} legitimately denotes the value zero"
      );
    }
    // A nonzero EXPONENT must NOT count toward the significand: `0e9` is zero.
    assert!(!lexeme_is_nonzero("0e9"));
  }

  /// Contract B / #197 — the consolidated [`f64_token_is_faithful`] predicate
  /// that the four f64-emitting paths share. Faithful ⟺ the reparsed f64 is
  /// finite AND not a nonzero-significand value that underflowed to `0.0`.
  #[test]
  fn f64_token_is_faithful_predicate() {
    // FAITHFUL: an in-range finite value round-trips bare (its token is irrelevant
    // beyond the underflow check, but pass the matching token).
    for (tok, n) in [("13.59", 13.59f64), ("1e-300", 1e-300f64), ("0", 0.0f64)] {
      assert!(f64_token_is_faithful(n, tok), "{tok} is faithful");
    }
    // A GENUINE-zero token parsing to `0.0` is faithful (stays a bare `0`).
    assert!(f64_token_is_faithful(0.0, "0e-5"));
    // NOT faithful — OVERFLOW: a token (or near-`f64::MAX` rounded form) that
    // reparses to ±INFINITY (would corrupt to `null`/`Inf`).
    assert!(!f64_token_is_faithful(f64::INFINITY, "1e999"));
    assert!(!f64_token_is_faithful(f64::NEG_INFINITY, "-1e999"));
    assert!(!f64_token_is_faithful(
      "1.79769313486232e+308".parse::<f64>().unwrap(),
      "1.79769313486232e+308"
    ));
    // NOT faithful — nonzero-UNDERFLOW: a nonzero significand that parsed to
    // `0.0` (would rewrite the token to a bare `0`).
    assert!(!f64_token_is_faithful(0.0, "1e-999"));
    assert!(!f64_token_is_faithful(0.0, "9e-400"));
    // NaN is never faithful.
    assert!(!f64_token_is_faithful(f64::NAN, "NaN"));
  }

  /// Contract B / #197 — the integer and float serializers run the SAME
  /// terminal `EscapeJSON` number gate (the value is stringified, then gated):
  /// an in-gate value is a bare JSON number; an out-of-gate value (a `>= 16`-
  /// digit integer such as a `u64` above `i64::MAX`, or a float whose `%.15g`
  /// rendering exceeds the 16-fraction-digit cap such as a `DV:Duration`) is a
  /// QUOTED string, byte-identical to bundled.
  #[cfg(feature = "serde")]
  #[test]
  fn numeric_scalars_serialize_through_escape_json_gate() {
    let j = |v: &TagValue| serde_json::to_string(v).unwrap();
    // In-gate integers ⇒ bare numbers.
    assert_eq!(j(&TagValue::U64(44100)), "44100");
    assert_eq!(j(&TagValue::I64(-3)), "-3");
    assert_eq!(j(&TagValue::U64(123456789012345)), "123456789012345"); // 15 digits
    // The `PLIST:Big` case: a `u64` above `i64::MAX` (19 digits) is OUT of the
    // gate's 15-digit integer cap ⇒ a QUOTED string, exactly as bundled emits.
    assert_eq!(
      j(&TagValue::U64(9223372036854775808)),
      "\"9223372036854775808\""
    );
    // u64::MAX (20 digits) likewise stays a quoted string with its TRUE value.
    assert_eq!(j(&TagValue::U64(u64::MAX)), "\"18446744073709551615\"");
    // i64::MIN (19 digits + sign) is out of gate ⇒ quoted with the true value.
    assert_eq!(j(&TagValue::I64(i64::MIN)), "\"-9223372036854775808\"");
    // The `DV:Duration` case: a float whose `%.15g` rendering has 17 fraction
    // digits (leading zeros do not count toward the 15 significant figures) is
    // OUT of the gate's 16-fraction-digit cap ⇒ a QUOTED string.
    assert_eq!(
      j(&TagValue::F64(0.001_222_222_222_222_22)),
      "\"0.00122222222222222\""
    );
    // An ordinary finite float stays a bare number (rounded to %.15g).
    assert_eq!(j(&TagValue::F64(0.5)), "0.5");
    assert_eq!(j(&TagValue::F64(2.4)), "2.4");
    // Non-finite floats stay the titlecase quoted word (unchanged).
    assert_eq!(j(&TagValue::F64(f64::INFINITY)), "\"Inf\"");
    assert_eq!(j(&TagValue::F64(f64::NAN)), "\"NaN\"");
  }

  /// Contract B / #197 — the NUMERIC-ORIGIN counterpart of the
  /// f64-representation predicate (the final structural piece of the class). A
  /// FINITE `TagValue::F64` near `f64::MAX` is `format_g(_, 15)`-rounded to a
  /// token that OVERFLOWS `f64::MAX` (`f64::MAX` → `"1.79769313486232e+308"`),
  /// which the `EscapeJSON` gate ADMITS (a 3-digit exponent) yet which reparses
  /// to `INFINITY`. The pre-fix `TagValue::F64` arm passed that reparse to
  /// `serialize_f64` WITHOUT re-checking `is_finite()`, so serde emitted `null`
  /// — silent corruption of a VALID finite value. The fix gates the reparse
  /// through the shared [`f64_token_is_faithful`] predicate (now universal across
  /// the string-origin R5 consumers AND this numeric-origin arm): the extreme
  /// rounded form falls to a SOUND quoted string (never `null`, never a panic) on
  /// `to_string` AND `to_value`, while every normal finite double is UNCHANGED.
  #[cfg(feature = "serde")]
  #[test]
  fn f64_near_max_rounds_to_quoted_string_not_null() {
    let js = |v: &TagValue| serde_json::to_string(v).unwrap();
    // The exact rounded form `format_g(f64::MAX, 15)` produces, which over-ranges
    // `f64::MAX` on reparse → would be the corrupting `null` without the recheck.
    let max_tok = r#""1.79769313486232e+308""#;
    let min_tok = r#""-1.79769313486232e+308""#;
    assert_eq!(js(&TagValue::F64(f64::MAX)), max_tok);
    assert_eq!(js(&TagValue::F64(f64::MIN)), min_tok);
    // SOUNDNESS on `to_string`: a VALID JSON string, NEVER `null`, round-trips as
    // a `RawValue`, and its decoded payload is the exact rounded token.
    for n in [f64::MAX, f64::MIN] {
      let out = js(&TagValue::F64(n));
      assert_ne!(out, "null", "near-f64::MAX value must not corrupt to null");
      let rv: Result<Box<serde_json::value::RawValue>, _> = serde_json::from_str(&out);
      assert!(
        rv.is_ok(),
        "emitted token {out:?} must re-parse as a RawValue"
      );
      assert_eq!(
        serde_json::from_str::<String>(&out).unwrap(),
        format_g(n, 15),
        "near-f64::MAX value must serialize to its rounded %.15g token as a string"
      );
    }
    // A NORMAL finite double still emits a BARE number, byte-identical to before
    // the fix (the common case is UNCHANGED — it round-trips finite → bare).
    assert_eq!(js(&TagValue::F64(2.6)), "2.6");
    assert_eq!(js(&TagValue::F64(0.5)), "0.5");
    // A large-but-in-range double still round-trips finite ⇒ a bare number.
    assert_eq!(js(&TagValue::F64(1.5e308)), "1.5e+308");
  }

  /// Contract B / #197 — the numeric-origin near-`f64::MAX` soundness must hold on
  /// `to_value` too (the `Serialize` impl is also driven by `serde_json::to_value`
  /// via `Rendered`/the typed-serde+parity harness). A reparse to `INFINITY` would
  /// make `serialize_f64(INFINITY)` corrupt the value to `Value::Null`; the
  /// faithful predicate emits a quoted JSON STRING instead — `Ok`, never `Err`,
  /// never `null`, never a panic — exactly like the string-origin `to_value` test.
  #[cfg(feature = "json")]
  #[test]
  fn f64_near_max_to_value_is_ok_string_not_null() {
    for n in [f64::MAX, f64::MIN] {
      let v = serde_json::to_value(TagValue::F64(n))
        .expect("to_value must not error on a near-f64::MAX double");
      assert_eq!(
        v,
        serde_json::Value::String(format_g(n, 15)),
        "near-f64::MAX value must serialize to its rounded token as a quoted string"
      );
      assert!(!v.is_null(), "near-f64::MAX value must never become null");
    }
    // A normal finite double is a BARE number on `to_value` too (unchanged).
    assert_eq!(
      serde_json::to_value(TagValue::F64(2.6)).unwrap(),
      serde_json::json!(2.6)
    );
  }

  #[test]
  fn group_doc_defaults_to_zero_and_with_doc_sets_it() {
    let g = Group::new("QuickTime", "QuickTime");
    assert_eq!(g.doc(), 0, "new() => Main/doc 0");
    let d = Group::with_doc("QuickTime", "QuickTime", 2);
    assert_eq!(d.doc(), 2);
    assert_eq!(d.family1(), "QuickTime");
    assert_ne!(Group::with_doc("QuickTime", "QuickTime", 1), g);
  }
}
