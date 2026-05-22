//! Runs a raw value through a `TagDef`'s ValueConv then PrintConv, producing
//! the value that appears in `-j` output (PrintConv on) — ExifTool's pipeline.
//!
//! # D11 conversion-context API (spec §11.2)
//!
//! ExifTool ValueConv/PrintConv code refs frequently dereference `$self`
//! (the per-file `Image::ExifTool` instance) for reader state/options —
//! e.g. `ConvertID3v1Text` (ID3.pm:897-901) reads
//! `$self->Options('CharsetID3')`. The D11 API exposes that state via
//! [`ConvContext`]: a small struct carrying ONLY the option/state fields
//! some real ported tag actually consumes.
//!
//! **Derivation rule (frozen in this PR — ID3 pathfinder, FORMATS.md row 2).**
//! Fields are added ADDITIVELY when a real ported tag's faithful conversion
//! needs them — NEVER speculatively. The initial field set is derived from
//! the FIRST context-dependent ValueConv in our port: ID3v1::Title
//! (ID3.pm:339-343 → :897-901 `ConvertID3v1Text`) reads
//! `$self->Options('CharsetID3')` (default `"Latin"`, ExifTool.pm:1118).
//! Future format ports CONSUME this shape (no re-design); they may add
//! fields, but every addition must cite the first real consumer.
//!
//! **Plumbing.** Two parallel APIs:
//! - [`apply`] — the legacy entry point (default `ConvContext`); existing
//!   `ValueConv::Func` / `PrintConv::Func` callers continue to work
//!   unchanged (AAC, FLAC StreamInfo, etc.).
//! - [`apply_ctx`] — the context-threaded entry point; routes to
//!   [`ValueConv::FuncCtx`] / [`PrintConv::FuncCtx`] when present.
//!
//! Both variants accept any [`ValueConv`]/[`PrintConv`] enum value; the
//! `FuncCtx` variants are simply the additive extension. `apply` is a thin
//! wrapper that builds a default context and delegates to `apply_ctx` —
//! no behavior change for AAC and friends.

use crate::{
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, ValueConv},
  value::{TagValue, format_g},
};
use smol_str::SmolStr;

/// Faithful model of the subset of `$$self{OPTIONS}` / `$self`-derived state
/// that ported ValueConv/PrintConv code refs actually consume. Per D11
/// derivation rule (spec §11.2): fields are added additively for each new
/// real consumer; do NOT speculate. The currently-carried fields:
///
/// - **`charset_id3`** — ExifTool `$$self{OPTIONS}{CharsetID3}` (default
///   `"Latin"`, ExifTool.pm:1118). First consumer: ID3v1::Title
///   (ID3.pm:339-343 calls :897-901 `ConvertID3v1Text` which does
///   `$et->Decode($val, $et->Options('CharsetID3'))`).
///
/// D8 (no public fields): all fields are private; access via accessors;
/// `const fn new` enables `static` use. Extension contract: add a field +
/// a `const fn with_<field>` builder + a `<field>()` accessor + an
/// in-code citation of the FIRST real-tag consumer.
#[derive(Clone, Copy)]
pub struct ConvContext {
  /// ExifTool `$$self{OPTIONS}{CharsetID3}`: drives `ConvertID3v1Text`
  /// (ID3.pm:897-901). Default `"Latin"` (ExifTool.pm:1118).
  charset_id3: &'static str,
}

impl ConvContext {
  /// Construct a `ConvContext` from explicit field values. Required for
  /// `static` use (e.g. test fixtures); production callers usually want
  /// [`ConvContext::default`].
  #[must_use]
  #[inline(always)]
  pub const fn new(charset_id3: &'static str) -> Self {
    Self { charset_id3 }
  }

  /// `$$self{OPTIONS}{CharsetID3}` — drives `ConvertID3v1Text`
  /// (ID3.pm:897-901). Default `"Latin"` (ExifTool.pm:1118).
  #[must_use]
  #[inline(always)]
  pub const fn charset_id3(&self) -> &'static str {
    self.charset_id3
  }

  /// Builder: override `charset_id3` (D8 `with_*` shape). The read path
  /// does not yet expose `CharsetID3` as a user-controllable option, so
  /// production callers stay on the default; this builder exists for
  /// tests + the documented extension contract.
  #[must_use]
  #[inline(always)]
  pub const fn with_charset_id3(mut self, value: &'static str) -> Self {
    self.charset_id3 = value;
    self
  }
}

impl Default for ConvContext {
  /// `CharsetID3 => 'Latin'` (ExifTool.pm:1118): bundled ExifTool's default.
  fn default() -> Self {
    Self::new("Latin")
  }
}

/// The conversion stage, faithful to ExifTool's `$convType` (`ExifTool.pm`
/// `GetValue`/`ConvertValue`). The `PrintHex → 'Unknown (0x%x)'` sub-case is
/// gated on `$convType eq 'PrintConv'` (`ExifTool.pm:3618`), so the runtime
/// must know which stage a hash conv is being applied for. (No conversion
/// *context/options* object — that is the tracked Phase-2 item; this is just
/// the stage discriminator ExifTool already threads as `$convType`.)
#[derive(Clone, Copy, derive_more::IsVariant)]
enum ConvType {
  /// ExifTool `$convType eq 'ValueConv'` — now also constructed for hash ValueConvs (AAC SampleRate).
  /// Faithfully part of the discriminator (a hash conv applied as ValueConv
  /// must take the generic `Unknown ($val)` branch, not the PrintHex hex
  /// form, `ExifTool.pm:3618`).
  ValueConv,
  /// ExifTool `$convType eq 'PrintConv'`.
  PrintConv,
}

/// Hot-path default — `apply` runs per tag, so the default `ConvContext`
/// is lifted to a `static` and passed by `&` instead of constructed (and
/// then immediately borrowed) on every call.
static DEFAULT_CONV_CONTEXT: ConvContext = ConvContext::new("Latin");

/// Apply ValueConv then PrintConv with the **default** [`ConvContext`].
/// `print_conv_enabled` mirrors ExifTool's `-n` switch: when `false`, the
/// post-ValueConv value is returned (the `-n` golden), matching spec §4's
/// two snapshots.
///
/// Thin wrapper over [`apply_ctx`]: zero behavioral difference for tags
/// that use only `ValueConv::None`/`Func`/`Hash` + `PrintConv::None`/`Func`/
/// `Hash` (AAC, FLAC StreamInfo). The `FuncCtx` variants observe whatever
/// `ConvContext` is in scope; `apply` provides the default.
pub fn apply(def: &TagDef, raw: &TagValue, print_conv_enabled: bool) -> TagValue {
  apply_ctx(def, raw, print_conv_enabled, &DEFAULT_CONV_CONTEXT)
}

/// Apply ValueConv then PrintConv, threading a [`ConvContext`] for any
/// `FuncCtx` variants. See module-level docs for the D11 derivation rule.
/// Element-wise over lists (ExifTool.pm:3578-3582), identical to [`apply`].
pub fn apply_ctx(
  def: &TagDef,
  raw: &TagValue,
  print_conv_enabled: bool,
  ctx: &ConvContext,
) -> TagValue {
  // ExifTool.pm:3578-3582 — the conversion loop iterates list elements for
  // the active stage, applying the current conv per scalar `$val`. Recurse
  // once at the top so BOTH ValueConv and PrintConv run element-wise; nested
  // lists terminate because each recursion drops one level of nesting.
  if let TagValue::List(items) = raw {
    return TagValue::List(
      items
        .iter()
        .map(|it| apply_ctx(def, it, print_conv_enabled, ctx))
        .collect(),
    );
  }
  let valued = match def.value_conv() {
    ValueConv::None => raw.clone(),
    ValueConv::Func(f) => f(raw),
    ValueConv::FuncCtx(f) => f(raw, ctx),
    ValueConv::Hash(h) => apply_hash_conv(def, &h, raw, ConvType::ValueConv),
  };
  if !print_conv_enabled {
    return valued;
  }
  apply_print_conv(def, def.print_conv(), &valued, ConvType::PrintConv, ctx)
}

/// The PrintConv stage. ExifTool runs the conversion over every element of a
/// list value (`ExifTool.pm:3578-3582` seeds `$val = $$vals[0]` then loops
/// `for(;;)` advancing through `@$value`, applying `$conv` each pass), so for
/// a [`TagValue::List`] we recurse element-wise and rebuild the list — for
/// every `PrintConv` variant, not just the hash. `apply` now pre-recurses on
/// `List` at the top, so this arm is defense-in-depth: it only fires if a
/// caller invokes `apply_print_conv` directly on a list (vanishingly rare).
fn apply_print_conv(
  def: &TagDef,
  conv: PrintConv,
  valued: &TagValue,
  conv_type: ConvType,
  ctx: &ConvContext,
) -> TagValue {
  if let TagValue::List(items) = valued {
    return TagValue::List(
      items
        .iter()
        .map(|it| apply_print_conv(def, conv, it, conv_type, ctx))
        .collect(),
    );
  }
  match conv {
    PrintConv::None => valued.clone(),
    PrintConv::Func(f) => f(valued),
    PrintConv::FuncCtx(f) => f(valued, ctx),
    PrintConv::Hash(h) => apply_hash_conv(def, &h, valued, conv_type),
  }
}

/// The Perl *hash* PrintConv branch, a faithful transliteration of
/// `ExifTool.pm:3603-3624`:
///
/// ```text
/// if (not defined($value = $$conv{$val})) {        # 1. direct key
///     if ($$conv{BITMASK}) {                       # 2. BITMASK -> DecodeBits, STOP
///         $value = DecodeBits($val, $$conv{BITMASK}, $$tagInfo{BitsPerWord});
///     } else {
///         if ($$conv{OTHER}) {                     # 3. OTHER callback
///             $value = &{$$conv{OTHER}}($val, undef, $conv);
///         }
///         if (not defined $value) {                # 4. fallback
///             if ($$tagInfo{PrintHex} and defined $val and IsInt($val)
///                 and $convType eq 'PrintConv') {
///                 $value = sprintf('Unknown (0x%x)', $val);
///             } else {
///                 $value = "Unknown ($val)";
///             }
///         }
///     }
/// }
/// ```
///
/// The `else` after the BITMASK branch is authoritative: when `BITMASK` is
/// present, `OTHER`/`Unknown` are **not** tried even on a `DecodeBits` miss.
fn apply_hash_conv(
  def: &TagDef,
  h: &PrintConvHash,
  valued: &TagValue,
  conv_type: ConvType,
) -> TagValue {
  // `$val` stringified the way Perl keys `$$conv{$val}` (hash keys are
  // strings) and the way the JSON serializer prints it.
  let key = match exiftool_val_string(valued) {
    Some(k) => k,
    // `Bytes` has no faithful Perl hash-key stringification ⇒ treat as a
    // miss (no key can match); `Unknown ($val)` is itself ill-defined for
    // bytes, so the value passes through unchanged — ExifTool never feeds
    // a binary scalar into a hash PrintConv lookup.
    None => return valued.clone(),
  };
  // 1. Direct key — `$$conv{$val}`. Faithful to ExifTool: a hash PrintConv
  //    value keeps its Perl scalar type, so numeric values stay numeric and
  //    serialize as JSON numbers (e.g. AAC Channels `2 => 2`).
  if let Some((_, pv)) = h.direct_entries().iter().find(|(k, _)| *k == key.as_str()) {
    return match pv {
      PrintValue::Str(s) => TagValue::Str(SmolStr::new(*s)),
      PrintValue::I64(n) => TagValue::I64(*n),
      PrintValue::F64(x) => TagValue::F64(*x),
    };
  }
  // 2. `$$conv{BITMASK}` ⇒ `DecodeBits($val, …, $$tagInfo{BitsPerWord})`,
  //    then STOP (Perl's `else` skips OTHER/Unknown entirely).
  if let Some(bitmask) = h.bitmask() {
    return TagValue::Str(
      decode_bits(&key, Some(bitmask), def.bits_per_word().unwrap_or(32)).into(),
    );
  }
  // 3. `$$conv{OTHER}` callback — `&{$$conv{OTHER}}($val, undef, $conv)`.
  //    Returning `None` ≡ Perl `undef`, falling through to the fallback.
  if let Some(other) = h.other() {
    if let Some(v) = other(valued) {
      return v;
    }
  }
  // 4. Fallback. PrintHex hex form only when the Perl conditions all hold:
  //    `$$tagInfo{PrintHex} and defined $val and IsInt($val) and
  //    $convType eq 'PrintConv'` (`ExifTool.pm:3617-3620`); otherwise the
  //    generic `"Unknown ($val)"` (`ExifTool.pm:3622`). `$val` is the same
  //    stringified scalar used for the lookup.
  if def.print_hex() && conv_type.is_print_conv() && is_int(&key) {
    // `sprintf('Unknown (0x%x)', $val)`: Perl's `%x` formats the value as
    // an unsigned 64-bit integer (UV). Faithful mapping:
    //   • negative values: two's-complement low 64 bits (`i64 as u64`,
    //     e.g. `-1` ⇒ `0xffffffffffffffff`).
    //   • values in [0, u64::MAX]: identity.
    //   • values > u64::MAX (e.g. 26-digit string): Perl UV saturates to
    //     `u64::MAX` (`0xffffffffffffffff`), as confirmed by:
    //       perl -e 'printf "0x%x\n", "99999999999999999999999999"+0'
    //       => 0xffffffffffffffff
    // Parse via i128 to handle the full range of `is_int`-validated strings
    // (pure-digit strings up to any length that would overflow i64).
    let uv: u64 = match key.parse::<i128>() {
      Ok(n) if n < 0 => {
        // Negative: two's-complement low 64 bits (e.g. -1 ⇒ all 1s).
        (n as i64) as u64
      }
      Ok(n) => {
        // Non-negative: clamp to u64::MAX if it overflows u64.
        u64::try_from(n).unwrap_or(u64::MAX)
      }
      Err(_) => {
        // Overflows even i128 (≥ ~1.7×10^38): Perl UV saturates.
        // `is_int` guarantees the string has no non-digit chars, so
        // this branch only fires for astronomically large positives.
        u64::MAX
      }
    };
    return TagValue::Str(format!("Unknown (0x{uv:x})").into());
  }
  TagValue::Str(format!("Unknown ({key})").into())
}

/// Faithful transliteration of ExifTool `sub IsInt($)`
/// (`ExifTool.pm:5943`): `return scalar($_[0] =~ /^[+-]?\d+$/);` — an
/// optional leading `+`/`-` then one-or-more ASCII digits, whole string.
fn is_int(s: &str) -> bool {
  let bytes = s.as_bytes();
  let digits = match bytes.first() {
    Some(b'+' | b'-') => &bytes[1..],
    _ => bytes,
  };
  !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

/// Faithful transliteration of ExifTool `sub IsFloat($)`
/// (`ExifTool.pm:5936-5942`):
///
/// ```perl
/// return 1 if $_[0] =~ /^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?$/;
/// # allow comma separators (for other locales)
/// return 0 unless $_[0] =~ /^[+-]?(?=\d|,\d)\d*(,\d*)?([Ee]([+-]?\d+))?$/;
/// $_[0] =~ tr/,/./;   # but translate ',' to '.'
/// return 1;
/// ```
///
/// Two anchored, whole-string forms (NO leading/trailing whitespace, NO hex):
/// an optional sign, then either a dot-decimal float (`12.5`, `.5`, `3.`,
/// `+3`, `1e3`) OR a single comma-decimal float (`12,5`, `,5` — at most one
/// comma per the `(,\d*)?` group). On the comma branch the caller's value is
/// rewritten `,`→`.` (the Perl `tr` mutates `$_[0]`), so we return the
/// already-translated owned string alongside the boolean. The caller uses the
/// returned string for the subsequent numeric coercion.
///
/// Returns `(matched, value_to_coerce)`:
/// - `matched == false` ⇒ NOT a float; `value_to_coerce` is the input
///   unchanged (the caller's `return $val unless IsFloat($val)`).
/// - `matched == true` ⇒ a float; `value_to_coerce` is the input with a sole
///   comma (if any) translated to a dot — a clean dot-decimal numeric string.
///
/// Bundled-Perl oracle (verified 2026-05-22 via `Image::ExifTool::IsFloat`):
/// `"12.5"`/`".5"`/`"3."`/`"+3"`/`"1e3"`/`"-2.5"` → matched; `"12,5"`/`",5"`
/// → matched + translated to `"12.5"`/`".5"`; `"  12.5"`/`"12.5 "`/`"0x10"`/
/// `"12abc"`/`""`/`"1e"`/`"1,5,6"`/`"inf"`/`"nan"` → NOT matched.
fn is_float(s: &str) -> (bool, std::borrow::Cow<'_, str>) {
  use std::borrow::Cow;
  // Dot-decimal branch (ExifTool.pm:5937) — `(?=\d|\.\d)` requires the
  // mantissa to start with a digit OR a `.` immediately followed by a digit.
  if matches_float_shape(s, b'.') {
    return (true, Cow::Borrowed(s));
  }
  // Comma-decimal branch (ExifTool.pm:5939) — same shape with `,` as the
  // single decimal separator; on a match the Perl `tr/,/./` rewrites the
  // value. At most one comma is permitted by the `(,\d*)?` group.
  if matches_float_shape(s, b',') {
    return (true, Cow::Owned(s.replace(',', ".")));
  }
  (false, Cow::Borrowed(s))
}

/// Whole-string match of ExifTool's `IsFloat` mantissa shape with `sep` as the
/// decimal separator: `^[+-]?(?=\d|<sep>\d)\d*(<sep>\d*)?([Ee]([+-]?\d+))?$`.
/// `sep` is `b'.'` for the primary branch (ExifTool.pm:5937) or `b','` for the
/// locale branch (ExifTool.pm:5939).
fn matches_float_shape(s: &str, sep: u8) -> bool {
  let bytes = s.as_bytes();
  let mut i = 0;
  // Optional leading sign.
  if matches!(bytes.first(), Some(b'+' | b'-')) {
    i += 1;
  }
  // Lookahead `(?=\d|<sep>\d)`: next char is a digit, OR `<sep>` followed by a
  // digit. Anything else (including end-of-string, a bare `<sep>`, or a
  // trailing separator like `<sep>` with no digit) fails the anchor.
  let look_ok = match bytes.get(i) {
    Some(b) if b.is_ascii_digit() => true,
    Some(&b) if b == sep => matches!(bytes.get(i + 1), Some(d) if d.is_ascii_digit()),
    _ => false,
  };
  if !look_ok {
    return false;
  }
  // `\d*` integer part.
  while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
    i += 1;
  }
  // `(<sep>\d*)?` — at most one separator, then zero-or-more digits.
  if bytes.get(i) == Some(&sep) {
    i += 1;
    while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
      i += 1;
    }
  }
  // `([Ee]([+-]?\d+))?` — optional exponent with a MANDATORY ≥1-digit power.
  if matches!(bytes.get(i), Some(b'e' | b'E')) {
    i += 1;
    if matches!(bytes.get(i), Some(b'+' | b'-')) {
      i += 1;
    }
    let exp_start = i;
    while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
      i += 1;
    }
    if i == exp_start {
      return false; // `[Ee]` with no power (e.g. `"1e"`) ⇒ no match.
    }
  }
  // `$` — the whole string must be consumed.
  i == bytes.len()
}

/// Perl numeric-context coercion of a string to an `f64`, matching Perl's
/// `$val + 0` / `$val * N` on a non-numeric or partially-numeric scalar.
///
/// Perl skips leading ASCII whitespace, then takes the longest leading prefix
/// matching `[+-]? ( \d* (\. \d*)? | \. \d+ ) ( [eE] [+-]? \d+ )?` and parses
/// that prefix as a double; the remainder of the string is ignored. A `,`
/// is NOT a decimal separator in raw arithmetic (it terminates the prefix),
/// matching Perl (`"1,5" + 0 == 1`). No leading numeric prefix ⇒ `0.0`; no
/// hex parsing (`"0x10" + 0 == 0`).
///
/// In addition to the finite numeric grammar, Perl's `Perl_my_atof` recognises
/// the IEEE non-finite spellings (oracle 2026-05-22 via `no warnings "numeric";
/// $s+0`), AFTER the same leading-whitespace skip and optional sign:
///   * `inf` (case-insensitive) → `±Inf`. The match is PREFIX-only: any tail
///     is ignored, so `inf`, `Inf`, `INFINITY`, `infinity`, `infinit`, `infX`
///     all coerce to `Inf` (`-inf` → `-Inf`). A leading sign carries.
///   * `nan` (case-insensitive) → `NaN`. Prefix-only likewise (`nan`, `NaN`,
///     `nan(123)`, `nanX` → `NaN`); any sign is dropped (`-nan` → `NaN`).
///   * The legacy MSVCRT spellings `1.#INF` / `1.#IND` / `1.#NAN` / `1.#QNAN`
///     / `1.#SNAN` (and the `1#INF` variant): a mantissa of EXACTLY `1`
///     (`1` or `1.`, not `1.0` / `01.`) followed by `#` then a case-insensitive
///     `INF` / `IND` / `NAN` / `QNAN` / `SNAN` prefix → `Inf` / `NaN`
///     (sign carries for `INF`: `-1.#INF` → `-Inf`). `1.#IN` / `1.#I` (no full
///     keyword) fall back to the finite mantissa `1`.
///
/// Leading junk before `inf`/`nan` is NOT a numeric prefix (`xinf`/`12inf` →
/// `0` / `12`, matching the finite rule), and a partial keyword (`in`, `na`,
/// `i`, `n`) yields `0`.
///
/// This is the `f64` analogue of [`perl_numeric_coerce`] (which truncates to a
/// `u64` for bitwise contexts). It is used by the Flash AMF-string ValueConv
/// `$val * 1000` (Flash.pm:168/230/237) and the `framerate` PrintConv
/// `int($val * 1000 + 0.5) / 1000` (Flash.pm:197), where Perl coerces an
/// AMF-string-typed value through arithmetic. A non-finite ValueConv result
/// (e.g. `"inf" * 1000 == Inf`) then flows into `ConvertBitrate` /
/// `ConvertDuration` (both `IsFloat`-reject it → pass through) or the bare
/// numeric emit, all of which render it via [`crate::value::perl_nonfinite_str`]
/// to Perl's `Inf` / `-Inf` / `NaN` casing.
///
/// Bundled-Perl oracle (verified 2026-05-22 via `no warnings "numeric"; $s+0`):
/// `"65.8"`/`"  65.8  "`/`"65.8 kbps"` → `65.8`; `"12abc"` → `12.0`;
/// `"1e3"` → `1000.0`; `"1,5"`/`"12,5"` → `1.0`/`12.0` (comma terminates);
/// `".5"` → `0.5`; `"3."` → `3.0`; `"+3.5"` → `3.5`; `"-2"` → `-2.0`;
/// `"abc"`/`""`/`"  "`/`"0x10"` → `0.0`; `"inf"`/`"Infinity"`/`"+inf"` → `Inf`;
/// `"-inf"`/`"-1.#INF"` → `-Inf`; `"nan"`/`"NaN"`/`"1.#IND"`/`"-nan"` → `NaN`.
#[allow(dead_code)] // Used by `feature = "flash"`; unused under feature-pruned builds without it.
pub fn perl_str_to_f64(s: &str) -> f64 {
  let bytes = s.as_bytes();
  let mut i = 0;
  // Perl skips leading whitespace (space, tab, NL, CR, FF, VT — exactly
  // `is_ascii_whitespace`) before numeric coercion (oracle 2026-05-22).
  while matches!(bytes.get(i), Some(b) if b.is_ascii_whitespace()) {
    i += 1;
  }
  let prefix_start = i;
  // Optional sign (captured for the non-finite spellings — `-inf` carries the
  // sign onto `Inf`; `nan`/`-nan` are unsigned `NaN`).
  let negative = bytes.get(i) == Some(&b'-');
  if matches!(bytes.get(i), Some(b'+' | b'-')) {
    i += 1;
  }
  // IEEE non-finite spellings — checked AFTER the sign, BEFORE the digit grammar
  // (a leading digit means a finite mantissa, so `inf`/`nan` can only begin the
  // post-sign run; `12inf` falls through to the digit path and stops at `12`).
  if ascii_prefix_eq_ci(&bytes[i..], b"inf") {
    return if negative {
      f64::NEG_INFINITY
    } else {
      f64::INFINITY
    };
  }
  if ascii_prefix_eq_ci(&bytes[i..], b"nan") {
    return f64::NAN; // Perl drops the sign on NaN (`-nan` + 0 == NaN).
  }
  let mantissa_start = i;
  // Integer digits.
  while matches!(bytes.get(i), Some(b) if b.is_ascii_digit()) {
    i += 1;
  }
  // Optional fraction `. \d*` (a `.` joins the prefix only if a digit precedes
  // it OR follows it — `"."`/`"+."` alone is not numeric).
  if bytes.get(i) == Some(&b'.') {
    let had_int_digits = i > mantissa_start;
    let frac_start = i + 1;
    let mut j = frac_start;
    while matches!(bytes.get(j), Some(b) if b.is_ascii_digit()) {
      j += 1;
    }
    if had_int_digits || j > frac_start {
      // `"3."`, `".5"`, or `"3.5"` — consume the dot + fraction digits.
      i = j;
    }
    // else: a lone `.` with no surrounding digit — leave `i` before the dot.
  }
  // Legacy MSVCRT `1.#INF` / `1.#IND` / `1.#NAN` / `1.#QNAN` / `1.#SNAN` forms
  // (and `1#INF`): the consumed mantissa must be EXACTLY `1` — i.e. the bytes
  // `[mantissa_start..i]` are `"1"` or `"1."` (so `1.0` / `01.` / `2.` do NOT
  // qualify; oracle: `1.0#INF` → 1, `2.#INF` → 2). The `#` then a keyword
  // prefix selects Inf/NaN; `INF` honours the sign, the NaN keywords drop it.
  if bytes.get(i) == Some(&b'#') {
    let mantissa = &bytes[mantissa_start..i];
    if mantissa == b"1" || mantissa == b"1." {
      let kw = &bytes[i + 1..];
      if ascii_prefix_eq_ci(kw, b"inf") {
        return if negative {
          f64::NEG_INFINITY
        } else {
          f64::INFINITY
        };
      }
      // `IND`, `NAN`, `QNAN`, `SNAN` all coerce to NaN (oracle 2026-05-22).
      if ascii_prefix_eq_ci(kw, b"ind")
        || ascii_prefix_eq_ci(kw, b"nan")
        || ascii_prefix_eq_ci(kw, b"qnan")
        || ascii_prefix_eq_ci(kw, b"snan")
      {
        return f64::NAN;
      }
    }
    // Not a recognised `1.#…` form (e.g. `1.#IN`, `1.0#INF`): fall through to the
    // finite mantissa parse below (`#` terminates the prefix).
  }
  // Optional exponent `[eE][+-]?\d+` (only consumed when ≥1 power digit).
  if matches!(bytes.get(i), Some(b'e' | b'E')) {
    let mut j = i + 1;
    if matches!(bytes.get(j), Some(b'+' | b'-')) {
      j += 1;
    }
    let exp_start = j;
    while matches!(bytes.get(j), Some(b) if b.is_ascii_digit()) {
      j += 1;
    }
    if j > exp_start {
      i = j;
    }
  }
  // No numeric prefix (only whitespace, a lone sign, or junk) ⇒ Perl yields 0.
  if i == prefix_start || i == mantissa_start {
    return 0.0;
  }
  // The prefix is a clean numeric form Rust's `f64` parser accepts (it handles
  // `"3."`, `".5"`, `"+3"`, `"1e3"`). On the rare overflow-to-inf parse, Perl
  // would likewise carry ±Inf, so the parsed value is faithful; the unreachable
  // `Err` arm (the prefix is always well-formed) falls back to 0.
  s[prefix_start..i].parse::<f64>().unwrap_or(0.0)
}

/// Case-insensitive ASCII prefix test: does `hay` begin with `needle` (which
/// MUST be lowercase ASCII)? Used by [`perl_str_to_f64`] for the prefix-only
/// `inf` / `nan` / `1.#…` keyword recognition (Perl's `Perl_my_atof` ignores
/// any tail after the keyword, so a prefix match suffices).
fn ascii_prefix_eq_ci(hay: &[u8], needle: &[u8]) -> bool {
  hay.len() >= needle.len()
    && hay[..needle.len()]
      .iter()
      .zip(needle)
      .all(|(h, n)| h.to_ascii_lowercase() == *n)
}

/// Perl string-to-integer coercion for bitwise operations, matching Perl's
/// `$val & (1 << $i)` where `$val` is a string in numeric context.
///
/// Perl string→number coercion: takes the longest leading prefix matching
/// `[+-]? ( \d+ \.? \d* | \. \d+ ) ( [eE] [+-]? \d+ )?`. The matched prefix
/// is then classified:
///
/// - **Pure integer** (sign + digits, no `.` and no `[eE]` consumed): mapped
///   to the exact 64-bit value Perl's bitwise `&` uses. On 64-bit Perl an
///   integer-valued scalar `0..2^64-1` is a UV (unsigned 64-bit) and `&`
///   forces operands to UV, so `0..=u64::MAX` map verbatim (bit 63 and any
///   `|n| > 2^53` survive — no f64 rounding). Negative integers are
///   two's-complement 64-bit (Perl `-1 & X == 0xFFFF…FFFF & X`). Magnitudes
///   that exceed the 64-bit window (real BITMASK tables never carry these)
///   saturate: `> u64::MAX ⇒ u64::MAX`, `< i64::MIN ⇒ i64::MIN`.
/// - **Float/exponent** (a `.` or `[eE]` was consumed): Perl keeps an NV
///   (double) operand for `&`, but `&` then converts it with the SAME
///   64-bit rule as the integer path — non-negative NV → UV (truncated
///   toward zero, exact in `[0, 2^64)`, saturating to `u64::MAX` at/above
///   `2^64`); negative NV → IV then UV reinterpret (two's-complement,
///   saturating at `i64::MIN`). f64's rounding is faithful because Perl's
///   NV is the same IEEE double (e.g. `"18446744073709551615.0"` rounds to
///   `2^64` in both).
///
/// No leading prefix ⇒ 0; no hex parsing of `"0x…"` strings
/// (Perl: `"0x05"+0 == 0`). Negative semantics are covered per-path above
/// (integer and float alike: two's-complement 64-bit).
fn perl_numeric_coerce(word: &str) -> u64 {
  // Parse the longest leading numeric prefix matching Perl's rules.
  // We handle sign, then integer digits, optional dot+fraction, optional exponent.
  let bytes = word.as_bytes();
  let mut i = 0;
  // Optional leading sign.
  if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
    i += 1;
  }
  // Must have at least one digit (or a dot followed by a digit).
  let start_after_sign = i;
  // Pure integer until we actually consume a `.` (with a fraction context)
  // or an exponent — then Perl carries an NV (double) into `&`.
  let mut is_integer = true;
  // Integer digits.
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  // Optional decimal fraction.
  if i < bytes.len() && bytes[i] == b'.' {
    let dot_pos = i;
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    // If we only consumed the dot but no digits before or after, it's not numeric.
    if i == dot_pos + 1 && start_after_sign == dot_pos {
      return 0;
    }
    // A `.` is part of the prefix ⇒ Perl float (NV) ⇒ f64 path.
    is_integer = false;
  }
  // Optional exponent.
  if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
    let exp_pos = i;
    i += 1;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
      i += 1;
    }
    let exp_digits_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    // No digits after [eE] => do not consume exponent.
    if i == exp_digits_start {
      i = exp_pos;
    } else {
      // A consumed exponent ⇒ Perl float (NV) ⇒ f64 path.
      is_integer = false;
    }
  }
  // No numeric prefix found (only a sign, or nothing at all) ⇒ 0.
  if i == 0 || i == start_after_sign {
    return 0;
  }
  let prefix = &word[..i];
  if is_integer {
    // Pure integer prefix: exact 64-bit (Perl UV/IV) — `$val & (1<<$i)`
    // forces a UV, so non-negative integers up to u64::MAX map verbatim
    // (bit 63 / >2^53 survive), negatives fold two's-complement.
    return match prefix.parse::<i128>() {
      Ok(v) if (0..=(u64::MAX as i128)).contains(&v) => v as u64,
      Ok(v) if ((i64::MIN as i128)..0).contains(&v) => (v as i64) as u64,
      // |v| beyond the 64-bit window (real BITMASK tables never reach
      // here): saturate, preserving the historical clamp intent.
      Ok(v) if v > u64::MAX as i128 => u64::MAX,
      Ok(_) => i64::MIN as u64,
      // Prefix overflows i128 itself: saturate by sign (never panic).
      Err(_) => {
        if prefix.as_bytes().first() == Some(&b'-') {
          i64::MIN as u64
        } else {
          u64::MAX
        }
      }
    };
  }
  // Float/exponent prefix: Perl carries an NV (incl. ±Inf/NaN) into
  // bitwise `&` → UV (non-negative) / IV→UV two's-complement (negative).
  // Rust's saturating `f64 as u64`/`as i64` reproduce Perl `(UV)nv`
  // exactly (oracle: "1e309"⇒all 64, "-1e309"⇒bit 63, "1e308"⇒all 64,
  // "-1e308"⇒bit 63). Same 64-bit rule as the integer path above
  // (DecodeBits ExifTool.pm:6374-6396).
  match prefix.parse::<f64>() {
    Ok(f) if f.is_nan() => 0, // (UV)NaN ⇒ 0 (also unreachable here)
    Ok(f) if f < 0.0 => {
      let t = f.trunc();
      let as_i64 = if t <= i64::MIN as f64 {
        i64::MIN
      } else {
        t as i64
      };
      as_i64 as u64
    }
    Ok(f) => f.trunc() as u64,
    Err(_) => 0,
  }
}

/// Faithful transliteration of ExifTool `sub DecodeBits($$;$)`
/// (`ExifTool.pm:6374-6396`):
///
/// ```text
/// $bits or $bits = 32;
/// $num = 0;
/// foreach $val (split ' ', $vals) {
///     for ($i=0; $i<$bits; ++$i) {
///         next unless $val & (1 << $i);
///         $n = $i + $num;
///         if    (not $lookup)  { push @bitList, $n }
///         elsif ($$lookup{$n}) { push @bitList, $$lookup{$n} }
///         else                 { push @bitList, "[$n]" }
///     }
///     $num += $bits;
/// }
/// return '(none)' unless @bitList;
/// return join($lookup ? ', ' : ',', @bitList);
/// ```
///
/// `split ' ', $vals` is Perl's special whitespace split: leading whitespace
/// trimmed, fields separated by runs of whitespace (`str::split_whitespace`).
/// Each word is taken in Perl numeric context for `$val & (1 << $i)` via
/// [`perl_numeric_coerce`]: an integer leading prefix uses exact 64-bit
/// (Perl UV/IV) semantics — `&` forces a UV, so bit 63 and any `|n| > 2^53`
/// survive; a float/exponent prefix goes through f64 (truncated toward
/// zero) and is mapped with the SAME 64-bit rule (non-negative → UV,
/// negative → two's-complement). No leading numeric prefix ⇒ 0; no hex
/// parsing of `"0x…"`.
/// `1 << $i` over `$i` up to `$bits-1`: ExifTool only ever passes
/// `BitsPerWord` ≤ 64 here, so a `u64` accumulator is exact for every real
/// table; shifts of ≥ 64 are treated as 0 (Perl's bit beyond the value is
/// unset anyway), matching "no such bit".
fn decode_bits(vals: &str, lookup: Option<&[(u8, &str)]>, bits: u8) -> String {
  // `$bits or $bits = 32;` — 0 ⇒ 32 (the `;$` default).
  let bits: u32 = if bits == 0 { 32 } else { u32::from(bits) };
  let mut bit_list: Vec<String> = Vec::new();
  let mut num: u64 = 0;
  for word in vals.split_whitespace() {
    // Perl numeric context: full leading-prefix coercion (float truncated
    // toward zero, two's-complement for negatives). See `perl_numeric_coerce`.
    let val: u64 = perl_numeric_coerce(word);
    for i in 0..bits {
      // `next unless $val & (1 << $i)` — shift ≥ 64 ⇒ bit unset.
      let set = i < 64 && (val & (1u64 << i)) != 0;
      if !set {
        continue;
      }
      let n = u64::from(i) + num;
      match lookup {
        None => bit_list.push(n.to_string()),
        Some(lk) => match lk.iter().find(|(k, _)| u64::from(*k) == n) {
          Some((_, name)) => bit_list.push((*name).to_string()),
          None => bit_list.push(format!("[{n}]")),
        },
      }
    }
    num += u64::from(bits);
  }
  if bit_list.is_empty() {
    return "(none)".to_string();
  }
  bit_list.join(if lookup.is_some() { ", " } else { "," })
}

/// Format-into-writer port of `Image::ExifTool::ConvertBitrate`
/// (ExifTool.pm:6891-6902). Writes the formatted bitrate string directly
/// into a [`core::fmt::Write`] sink — no intermediate `String` allocation.
///
/// Perl reference:
/// ```perl
/// my $bitrate = shift;
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
/// Bundled-Perl oracle (verified 2026-05-20 / 2026-05-22):
/// - `224_000` → `"224 kbps"`
/// - `8_500_000` → `"8.5 Mbps"`
/// - `50` → `"50 bps"`
/// - `999` → `"999 bps"`
/// - `1000` → `"1 kbps"`
/// - `1_500_000_000` → `"1.5 Gbps"`
/// - `32_000` (Vorbis NominalBitrate fixture) → `"32 kbps"`
/// - `128_000` (Vorbis NominalBitrate fixture) → `"128 kbps"`
///
/// R2 F-OGG-TRIM: this helper had been deferred to dedicated Vorbis/Theora
/// codec PRs (R1 F2 scope tightening). Round-2 review flagged the
/// identification-header tables as in-scope after all — the tables are
/// small, the deferral was creating new conformance hand-trims, and the
/// trims violated the "no hand-trims" 1:1 bar. Helper re-landed here (was
/// in `formats/moi.rs`) so both `formats/moi.rs` (`write_convert_bitrate`
/// re-export) and `formats/ogg.rs` (Vorbis::Identification +
/// Opus::Header PrintConv path) can share the single faithful
/// implementation.
#[allow(dead_code)] // Used under `feature = "moi"` and `feature = "ogg"`; unused under feature-pruned builds without either.
pub fn write_convert_bitrate<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  bitrate: f64,
) -> core::fmt::Result {
  // ExifTool.pm:6894 `IsFloat($bitrate) or return $bitrate`. `IsFloat`'s regex
  // rejects the stringified `Inf`/`-Inf`/`NaN` (it requires a leading digit or
  // `.digit`), so a non-finite bitrate is returned VERBATIM and stringifies via
  // Perl's NV default — titlecase `Inf`/`-Inf`/`NaN` (NOT Rust's lowercase
  // `inf`/`-inf` from `{}`). `perl_nonfinite_str` produces Perl's casing.
  if !bitrate.is_finite() {
    return w.write_str(crate::value::perl_nonfinite_str(bitrate).unwrap_or("NaN"));
  }
  const UNITS: &[&str] = &["bps", "kbps", "Mbps", "Gbps"];
  let mut b = bitrate;
  for (i, &unit) in UNITS.iter().enumerate() {
    let is_last = i + 1 == UNITS.len();
    if b >= 1000.0 && !is_last {
      b /= 1000.0;
      continue;
    }
    return if b < 100.0 {
      // `%.3g` — Perl `%g` strips trailing zeros. Share the engine's
      // existing helper so byte-exact matching against the bundled oracle
      // is centralized.
      let formatted = crate::value::format_g(b, 3);
      write!(w, "{formatted} {unit}")
    } else {
      // `%.0f` — Perl `%.0f` is half-to-even; for bitrate ranges here the
      // post-division values are never exactly `.5`, so Rust's
      // half-away-from-zero `{:.0}` produces byte-identical output.
      write!(w, "{b:.0} {unit}")
    };
  }
  // Unreachable: the loop always returns on the last UNITS entry.
  unreachable!("write_convert_bitrate loop must exit on the last unit");
}

/// Format-into-writer port of `Image::ExifTool::ConvertDuration`
/// (ExifTool.pm:6866-6884). Writes the formatted duration string directly
/// into a [`core::fmt::Write`] sink — no intermediate `String` allocation.
///
/// Perl reference (verbatim from MOI.pm port comments):
/// ```perl
/// my $time = shift;
/// return $time unless IsFloat($time);
/// return '0 s' if $time == 0;
/// my $sign = ($time > 0 ? '' : (($time = -$time), '-'));
/// return sprintf("$sign%.2f s", $time) if $time < 30;
/// $time += 0.5;
/// my $h = int($time / 3600);
/// $time -= $h * 3600;
/// my $m = int($time / 60);
/// $time -= $m * 60;
/// if ($h > 24) {
///     my $d = int($h / 24);
///     $h -= $d * 24;
///     $sign = "$sign$d days ";
/// }
/// return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time));
/// ```
///
/// Bundled-Perl oracle (verified 2026-05-20 / 2026-05-22):
/// - `8.16` → `"8.16 s"` (the MOI fixture)
/// - `3.089` → `"3.09 s"` (the FLV fixture)
/// - `0` → `"0 s"`
/// - `30` → `"0:00:30"`
/// - `86461` → `"24:01:01"`
/// - `90000` → `"1 days 1:00:00"`
/// - `-30` → `"-0:00:30"`
///
/// R2 wave-a-flash: this helper had lived in `formats/moi.rs` for the MOI
/// pilot. With FLV (Flash.pm:192/221/226 `ConvertDuration`) landing here it
/// moved to `crate::convert` so a feature-pruned `--features std,flash` build
/// without `moi` still resolves the symbol. The MOI module re-exports it for
/// backward compatibility with its own port site.
#[allow(dead_code)] // Used under `feature = "moi"` and `feature = "flash"`; unused under feature-pruned builds without either.
pub fn write_convert_duration<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  time: f64,
) -> core::fmt::Result {
  // ExifTool.pm:6869 `return $time unless IsFloat($time)`. As in
  // `write_convert_bitrate`, `IsFloat` rejects a stringified non-finite, so the
  // value passes through verbatim and stringifies to Perl's titlecase
  // `Inf`/`-Inf`/`NaN` (via `perl_nonfinite_str`), not Rust's lowercase `{}`.
  if !time.is_finite() {
    return w.write_str(crate::value::perl_nonfinite_str(time).unwrap_or("NaN"));
  }
  if time == 0.0 {
    return w.write_str("0 s"); // ExifTool.pm:6870
  }
  let (sign, mut t) = if time > 0.0 { ("", time) } else { ("-", -time) }; // ExifTool.pm:6871
  if t < 30.0 {
    return write!(w, "{sign}{t:.2} s"); // ExifTool.pm:6872
  }
  t += 0.5; // ExifTool.pm:6873 round to nearest second
  let mut h: i64 = (t / 3600.0) as i64;
  t -= (h as f64) * 3600.0;
  let m: i64 = (t / 60.0) as i64;
  t -= (m as f64) * 60.0;
  let s_int: i64 = t as i64;
  if h > 24 {
    let d = h / 24;
    h -= d * 24;
    return write!(w, "{sign}{d} days {h}:{m:02}:{s_int:02}");
  }
  write!(w, "{sign}{h}:{m:02}:{s_int:02}")
}

/// `ConvertDuration($val)` applied to a STRING-typed value, honouring the
/// `IsFloat($time) or return $time` guard (ExifTool.pm:6869). When the AMF
/// value carried a `duration`/`starttime` (Flash.pm:192/221) as a string,
/// bundled `GetValue` runs `ConvertDuration` on that string: a float-shaped
/// string (incl. a single comma-decimal, which `IsFloat` translates `,`→`.`)
/// is coerced and formatted; anything else is returned VERBATIM (e.g.
/// `"65.8 kbps"` → `"65.8 kbps"`, `"notnum"` → `"notnum"`). Coercion of the
/// (comma-translated) float string uses Perl arithmetic semantics
/// ([`perl_str_to_f64`]); since `IsFloat` already guaranteed the whole string
/// is numeric, the prefix parse consumes all of it.
///
/// Bundled-Perl oracle (verified 2026-05-22 on synthetic FLVs):
/// `"1.5"` → `"1.50 s"`; `"12,5"` → `"12.50 s"`; `"2.25"` → `"2.25 s"`;
/// `"notnum"`/`"65.8 kbps"` → returned verbatim.
#[allow(dead_code)] // Used under `feature = "flash"`; unused under feature-pruned builds without it.
pub fn write_convert_duration_str<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  val: &str,
) -> core::fmt::Result {
  // ExifTool.pm:6869 `return $time unless IsFloat($time)`.
  let (matched, coerce_src) = is_float(val);
  if !matched {
    return w.write_str(val);
  }
  write_convert_duration(w, perl_str_to_f64(&coerce_src))
}

/// `ConvertBitrate($val)` applied to a STRING-typed value, honouring the
/// `IsFloat($bitrate) or return $bitrate` guard (ExifTool.pm:6894).
///
/// In `%Flash::Meta` the `ConvertBitrate` PrintConv is only ever paired with a
/// `$val * 1000` ValueConv (Flash.pm:168-169/237-238), so by the time bundled
/// reaches the PrintConv the value is ALWAYS the numeric ValueConv result —
/// this string entry point is therefore unreachable on real Flash data and
/// exists only for defensive symmetry with [`write_convert_duration_str`]. It
/// mirrors the same IsFloat guard: a float-shaped string formats, anything
/// else is returned verbatim.
#[allow(dead_code)] // Defensive symmetry; the Flash *bitrate ValueConv always pre-numifies.
pub fn write_convert_bitrate_str<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  val: &str,
) -> core::fmt::Result {
  let (matched, coerce_src) = is_float(val);
  if !matched {
    return w.write_str(val);
  }
  write_convert_bitrate(w, perl_str_to_f64(&coerce_src))
}

/// Faithful transliteration of `Image::ExifTool::XMP::DecodeBase64` (an
/// RFC 4648 decode used by `Vorbis.pm:101-104` for `COVERART` and
/// `Vorbis.pm:122-134` for `METADATA_BLOCK_PICTURE`). The standard alphabet
/// `A-Za-z0-9+/`, with `=` padding; ignores whitespace; on the first
/// invalid input byte the function returns the *partial* decode collected
/// up to that point (mirroring Perl's `MIME::Base64::decode` permissive-
/// but-bounded behavior — real ExifTool COVERART payloads are clean base64,
/// so this fallback is mostly defensive and never panics). Output is the
/// decoded raw bytes.
///
/// `#[allow(dead_code)]`: only the `ogg` format uses this helper today; under
/// feature-pruned builds without OGG the dead-code lint fires. The helper
/// stays in `convert.rs` (not in `formats/ogg.rs`) because it's logically
/// a `ConvertBase64` helper akin to ExifTool's `MIME::Base64::decode` and
/// will be reused by future XMP/EXIF ports.
#[allow(dead_code)]
pub(crate) fn base64_decode(s: &str) -> Vec<u8> {
  // Map an ASCII byte to its 6-bit value, or `None` for ignored/invalid.
  fn val(b: u8) -> Option<u8> {
    match b {
      b'A'..=b'Z' => Some(b - b'A'),
      b'a'..=b'z' => Some(b - b'a' + 26),
      b'0'..=b'9' => Some(b - b'0' + 52),
      b'+' => Some(62),
      b'/' => Some(63),
      _ => None,
    }
  }
  let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4);
  let mut buf: u32 = 0;
  let mut have: u32 = 0; // number of valid 6-bit chunks accumulated (0..=4)
  for &b in s.as_bytes() {
    if b == b'=' {
      // Padding — stops decoding (the trailing 1/2 byte was emitted as the
      // chunks accumulated; padding is purely positional).
      break;
    }
    if b.is_ascii_whitespace() {
      continue;
    }
    let Some(v) = val(b) else {
      // Invalid byte ⇒ abort (mirror Perl's permissive-but-bounded decode:
      // anything outside the alphabet + padding + whitespace → no further
      // bytes, return what we have so far). Real ExifTool COVERART payloads
      // are clean base64, so this branch only fires on a truly malformed
      // input; returning the partial decode (Vec accumulated so far) keeps
      // the parser panic-free.
      return out;
    };
    buf = (buf << 6) | u32::from(v);
    have += 1;
    if have == 4 {
      out.push((buf >> 16) as u8);
      out.push((buf >> 8) as u8);
      out.push(buf as u8);
      buf = 0;
      have = 0;
    }
  }
  // Emit any leftover bytes (when input length % 4 ∈ {2, 3}). Perl's
  // `MIME::Base64::decode` does the same: a final partial group of 2 valid
  // base64 chars decodes to 1 byte, 3 chars to 2 bytes.
  match have {
    2 => out.push((buf >> 4) as u8),
    3 => {
      out.push((buf >> 10) as u8);
      out.push((buf >> 2) as u8);
    }
    _ => {}
  }
  out
}

/// crate's single shared `%g`/rational formatter ([`crate::value::format_g`]
/// / [`Rational::exiftool_val_str`]) so a hash key matches the serialized
/// `$val` text exactly. `Bytes` is keyed via [`fix_utf8`] (`XMP::FixUTF8`,
/// XMP.pm:2943-2974) — the same byte-walker `EscapeJSON` runs on every
/// string before serialization at exiftool:3822, so the hash-key lookup
/// matches the JSON-printed `$val` text byte-for-byte. ASCII is identity
/// (so AIFF `CompressionType` `"NONE"`/`"sowt"`/… hit the Perl hash
/// entries exactly); high bytes that do NOT form a valid UTF-8 sequence
/// are replaced with `?` (Perl default `$bad`). Codex R3 fix: an earlier
/// **byte-identical Latin-1** keying diverged from Perl for
/// `CompressionType b"\x80ABC"` (Perl ⇒ `"?ABC"`; Latin-1 ⇒ `"\u{0080}ABC"`).
/// This `Bytes` arm subsumes the prior `None` (which made every
/// `Bytes`-backed string[N] PrintConv hash lookup miss — flagged by Codex
/// R1 on the AIFF `CompressionType` path once string/pstring formats
/// started emitting `TagValue::Bytes` faithfully).
fn exiftool_val_string(v: &TagValue) -> Option<String> {
  match v {
    // Perl stringifies an integer as its decimal text (`"$n"`).
    TagValue::I64(n) => Some(n.to_string()),
    // An unsigned 64-bit integer stringifies the same way (`"$n"`).
    TagValue::U64(n) => Some(n.to_string()),
    // Same `%.15g`-ish text the serializer feeds through `EscapeJSON`
    // (non-finite never reaches a hash PrintConv; mirror Perl's `"$n"`).
    TagValue::F64(n) => Some(if n.is_finite() {
      format_g(*n, 15)
    } else {
      n.to_string()
    }),
    // A string value is its own Perl scalar (e.g. AIFF `CompressionType`
    // `"sowt"`/`"NONE"`).
    TagValue::Str(s) => Some(s.to_string()),
    // Rare for a hash PrintConv; Perl's boolean-ish scalars are not
    // `"true"`/`"false"`, but this port models a real `Bool`. The
    // documented, acceptable form: Rust `b.to_string()` ("true"/"false").
    TagValue::Bool(b) => Some(b.to_string()),
    // `num/denom` rounded via the shared formatter (or `inf`/`undef`):
    // exactly what the serializer prints, so the key matches `$val`.
    TagValue::Rational(r) => Some(r.exiftool_val_str()),
    // Byte strings: Perl-faithful FixUTF8 mapping (XMP.pm:2943-2974,
    // called by `EscapeJSON` at exiftool:3822). Valid UTF-8 sequences in
    // the byte buffer are preserved as their decoded chars; bytes that
    // do NOT form a valid UTF-8 sequence are replaced by `?`. ASCII is
    // identity (so AIFF `CompressionType` "NONE"/"sowt"/… still hits the
    // Perl hash entries exactly). For high bytes: a MacRoman-decoded
    // tag's ValueConv emits a `TagValue::Str` BEFORE this lookup runs
    // (the `Bytes → Str` MacRoman conversion happens in
    // `decode_macroman`), so `Bytes` arrives at this lookup ONLY for
    // tags WITHOUT a ValueConv (e.g. AIFF `CompressionType`). Codex R3:
    // a previous Latin-1 1:1 mapping diverged from Perl for
    // CompressionType `\x80ABC` (Perl: "?ABC"; Latin-1: "\u{0080}ABC").
    TagValue::Bytes(b) => Some(fix_utf8(b)),
    // Lists are stripped element-wise by `apply` before any hash-conv path
    // (and `apply_print_conv`'s list-arm defends the same on direct calls).
    TagValue::List(_) => None,
  }
}

/// Byte order for [`read_value`], faithful to ExifTool's `SetByteOrder('MM'|'II')`
/// (`ExifTool.pm:9669-9722`, the `Get<N>(u|s)` family + `RoundUp` pair).
///
/// ExifTool keeps the current byte order as global state (`$currentByteOrder`),
/// but exifast threads it as an explicit argument so every read is local and
/// the engine stays panic-/global-state-free.
#[derive(Clone, Copy, derive_more::IsVariant)]
pub enum ByteOrder {
  /// `MM` — big-endian (Motorola). ExifTool's default for TIFF/EXIF and
  /// `Image::ExifTool::Red::ProcessR3D` (Red.pm:231 `SetByteOrder('MM')`).
  Mm,
  /// `II` — little-endian (Intel).
  Ii,
}

/// Faithful transliteration of `Image::ExifTool::XMP::FixUTF8(\$str)`
/// (`XMP.pm:2943-2975`): replaces each byte sequence that is NOT a valid
/// UTF-8 codepoint with the literal ASCII `?` (Perl default `$bad`).
/// The bundled `exiftool` script invokes this in its JSON emitter at
/// `exiftool:3822` (`Image::ExifTool::XMP::FixUTF8(\$str) unless $altEnc`).
///
/// **Why a custom impl, not `String::from_utf8_lossy`:** `from_utf8_lossy`
/// substitutes the Unicode REPLACEMENT CHARACTER U+FFFD (3-byte UTF-8
/// `\xEF\xBF\xBD`), not the single ASCII byte `0x3F`. ExifTool's golden
/// JSON for any format whose raw bytes include a malformed UTF-8 byte
/// (e.g. an R3D `OriginalFileName` containing `A\xFF.R3D`) will emit
/// `A?.R3D`; `from_utf8_lossy` produces `A\u{FFFD}.R3D`, a 5-character
/// byte-mismatch at the conformance `jsondiff` gate. (Codex round-9 F1:
/// flagged precisely for the Red string-extraction path.)
///
/// **Faithful semantics from XMP.pm:2949-2972:**
/// 1. Scan byte-by-byte for high-bit bytes (`0x80..=0xFF`).
/// 2. If the byte is in `0xC2..0xF8`, it could be a valid UTF-8 leader
///    (1, 2, or 3 continuation bytes expected). Validate the continuation
///    bytes match `[0x80..=0xBF]{n}` for the expected length.
/// 3. For each leader/continuation length, apply the additional
///    overlong/surrogate/non-character checks (the `unless ... == 0x80` /
///    `... == 0xa0` / `... == 0xbf` chain at XMP.pm:2958-2964).
/// 4. Any byte that fails the chain is replaced with `?`.
///
/// **Re-use:** designed to be the engine-tier seam for every future
/// format whose Perl path passes raw bytes through to JSON serialization
/// (Phase-2 forward item #51 — engine-wide `FixUTF8` at JSON serialization).
/// The current consumer is `read_value`'s `string` arm; later formats
/// (Audible AA already has its own copy; we will dedupe when the
/// dependency-tree allows) can invoke this same helper at their parser
/// boundary instead of duplicating the byte-walker.
#[must_use]
pub fn fix_utf8(bytes: &[u8]) -> String {
  // **Codex round-10 F1:** no `std::str::from_utf8` fast path — Rust's
  // strict UTF-8 validator and ExifTool's `IsUTF8`/`FixUTF8` agree on
  // overlongs and surrogates, BUT Rust ACCEPTS the BMP "non-characters"
  // U+FFFE (`EF BF BE`) and U+FFFF (`EF BF BF`), while ExifTool's
  // `FixUTF8` explicitly REJECTS them (XMP.pm:2960-2961:
  // `ord($1) == 0xbf and (ord(substr $1, 1) & 0xfe) == 0xbe`). A
  // fast-path early-exit would silently preserve these non-characters
  // where Perl writes `?`.
  //
  // Bundled-Perl oracle for the divergent cases:
  //   perl -Ilib -MImage::ExifTool::XMP -e 'my $s="A\xEF\xBF\xBEB";
  //         Image::ExifTool::XMP::FixUTF8(\$s); print "$s\n"' ⇒ "A???B"
  //   (same for `\xEF\xBF\xBF`); U+FFFD (`EF BF BD`) and U+FFEC
  //   (`EF BF AC`) pass through unchanged.
  //
  // Always go through the byte-walker below — its valid-sequence
  // copy-as-slice path is fast enough for any realistic metadata
  // payload (single linear scan, no allocation churn on the happy
  // path).
  //
  // Faithful byte-by-byte transliteration of XMP.pm:2948-2972.
  let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
  let mut i = 0;
  while i < bytes.len() {
    let ch = bytes[i];
    if ch < 0x80 {
      out.push(ch);
      i += 1;
      continue;
    }
    // High-bit byte: validate as a UTF-8 leader. XMP.pm:2953 — leaders
    // are in `0xC2..=0xF7` (`< 0xf8`).
    if (0xC2..0xF8).contains(&ch) {
      // Expected continuation count (`$n` at XMP.pm:2954):
      // 0xC2..=0xDF ⇒ 1 continuation
      // 0xE0..=0xEF ⇒ 2 continuations
      // 0xF0..=0xF7 ⇒ 3 continuations
      let n: usize = if ch < 0xE0 {
        1
      } else if ch < 0xF0 {
        2
      } else {
        3
      };
      // Slurp `n` continuation bytes (`/\G([\x80-\xbf]{n})/g` at
      // XMP.pm:2955): they must all be in 0x80..=0xBF.
      if i + 1 + n <= bytes.len()
        && bytes[i + 1..i + 1 + n]
          .iter()
          .all(|&c| (0x80..=0xBF).contains(&c))
      {
        // Apply the overlong/surrogate/non-character chain.
        let cont1 = bytes[i + 1];
        let ok = if n == 1 {
          // 0xC2..=0xDF leader with one continuation is unconditionally
          // valid (XMP.pm:2956 `next if $n == 1`).
          true
        } else if n == 2 {
          // XMP.pm:2958-2961: reject overlongs (`0xe0` + cont1 < 0xA0),
          // surrogates (`0xed` + cont1 >= 0xA0), and the specific
          // non-character `0xef 0xbf 0xbe/0xbf` family.
          let is_overlong = ch == 0xE0 && (cont1 & 0xE0) == 0x80;
          let is_surrogate = ch == 0xED && (cont1 & 0xE0) == 0xA0;
          let is_non_char_efbf =
            ch == 0xEF && cont1 == 0xBF && i + 2 < bytes.len() && (bytes[i + 2] & 0xFE) == 0xBE;
          !(is_overlong || is_surrogate || is_non_char_efbf)
        } else {
          // n == 3, XMP.pm:2962-2964: reject overlongs (`0xf0` with cont1
          // < 0x90), out-of-range (`0xf4` with cont1 > 0x8f, or any
          // leader > 0xf4).
          let is_overlong_4byte = ch == 0xF0 && (cont1 & 0xF0) == 0x80;
          let is_out_of_range = (ch == 0xF4 && cont1 > 0x8F) || ch > 0xF4;
          !(is_overlong_4byte || is_out_of_range)
        };
        if ok {
          // Copy the leader + its `n` continuations verbatim.
          out.extend_from_slice(&bytes[i..i + 1 + n]);
          i += 1 + n;
          continue;
        }
      }
    }
    // Either not a valid leader, or the continuation chain failed.
    // Replace the *single bad byte* with `?` (XMP.pm:2970
    // `substr($$strPt, $pos-1, 1) = $bad`) and advance.
    out.push(b'?');
    i += 1;
  }
  // The result is now byte-for-byte valid UTF-8 (`?` is ASCII and every
  // accepted multi-byte sequence was already validated above), so the
  // `from_utf8` call cannot fail; use unchecked construction via
  // `String::from_utf8` (no unsafe) — falling back to lossy *just* in
  // case (panic-free contract, `#![forbid(unsafe_code)]`).
  String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Emit one codepoint as Perl's `pack('C0U', $n)` would (variable-length
/// UTF-8 encoding WITHOUT validity checks — surrogates and out-of-range
/// values get the same algorithmic encoding, deliberately producing
/// byte sequences that [`fix_utf8`] will later flag as bad).
///
/// XMP.pm:2933 (`UnescapeChar`) is the only call site this port targets —
/// see [[exifast-phase2-forward-items]] FixUTF8 entry for the broader
/// engine-level concern.
///
/// Perl's `pack('C0U', n)` follows the original UTF-8 spec (RFC 2279,
/// allowing up to 6 bytes) and then Perl's own RFC-2279-extended forms
/// (7-byte lead `0xFE`, 13-byte lead `0xFF`) for codepoints up to
/// `0x7FFF_FFFF_FFFF_FFFF` (i64::MAX, Perl's hard `pack` limit; values
/// above that die inside Perl — we treat them as "leave entity literal"
/// in [`resolve_html_entity_codepoint`]).
///
/// Bytes generated for `n >= 0x110000` are deliberately invalid UTF-8 —
/// [`fix_utf8`] will turn each into one `?` downstream.
pub fn pack_c0u(n: u64, out: &mut Vec<u8>) {
  if n < 0x80 {
    out.push(n as u8);
  } else if n < 0x800 {
    out.push(0xC0 | ((n >> 6) & 0x1F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else if n < 0x10000 {
    out.push(0xE0 | ((n >> 12) & 0x0F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else if n < 0x20_0000 {
    out.push(0xF0 | ((n >> 18) & 0x07) as u8);
    out.push(0x80 | ((n >> 12) & 0x3F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else if n < 0x400_0000 {
    out.push(0xF8 | ((n >> 24) & 0x03) as u8);
    out.push(0x80 | ((n >> 18) & 0x3F) as u8);
    out.push(0x80 | ((n >> 12) & 0x3F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else if n < 0x8000_0000 {
    // 6-byte form (Perl `pack('C0U')` for `0x0400_0000..=0x7FFF_FFFF`).
    // FixUTF8 lead-byte gate is `< 0xF8`, so 0xFC/0xFD are NEVER accepted —
    // each byte becomes `?` downstream. Empirical: `n=0x7fffffff` ⇒ 6
    // bytes `fd bf bf bf bf bf` ⇒ FixUTF8 ⇒ "??????" (6 `?`s).
    out.push(0xFC | ((n >> 30) & 0x01) as u8);
    out.push(0x80 | ((n >> 24) & 0x3F) as u8);
    out.push(0x80 | ((n >> 18) & 0x3F) as u8);
    out.push(0x80 | ((n >> 12) & 0x3F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else if n < 0x10_0000_0000 {
    // 7-byte form (Perl `pack('C0U')` for `0x8000_0000..=0xF_FFFF_FFFF`,
    // i.e. 31..36 payload bits). Lead byte is always `0xFE`. Empirical
    // bundled-Perl reference (R5 investigation):
    //   n=0x80000000   ⇒ fe 82 80 80 80 80 80
    //   n=0xFFFFFFFF   ⇒ fe 83 bf bf bf bf bf
    //   n=0x100000000  ⇒ fe 84 80 80 80 80 80
    //   n=0xFFFFFFFFF  ⇒ fe bf bf bf bf bf bf
    // Each invalid byte becomes one `?` via FixUTF8 (7 `?`s). Byte 1
    // carries six payload bits (`(n >> 30) & 0x3F`), not two — fixed
    // from the earlier u32-only `& 0x03` cap so 32..36-bit values
    // round-trip byte-exact against Perl.
    out.push(0xFE);
    out.push(0x80 | ((n >> 30) & 0x3F) as u8);
    out.push(0x80 | ((n >> 24) & 0x3F) as u8);
    out.push(0x80 | ((n >> 18) & 0x3F) as u8);
    out.push(0x80 | ((n >> 12) & 0x3F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  } else {
    // 13-byte form (Perl `pack('C0U')` for
    // `0x10_0000_0000..=0x7FFF_FFFF_FFFF_FFFF`, i.e. 37..63 payload bits).
    // Lead byte is `0xFF`; 12 continuation bytes follow, each carrying
    // 6 bits of payload starting from the most significant 6-bit group.
    // Empirical (R5):
    //   n=0x1000000000        ⇒ ff 80 80 80 80 80 81 80 80 80 80 80 80
    //   n=0x7FFFFFFFFFFFFFFF  ⇒ ff 80 87 bf bf bf bf bf bf bf bf bf bf
    // Lead `0xFF` is `>= 0xF8`, so FixUTF8 rejects it and every
    // continuation byte (orphans) — output is 13 `?` chars.
    //
    // The first two continuation bytes (i=1,2) cover bit positions
    // 66..71 and 60..65 respectively. A `u64` can only set bits 0..63,
    // so those slots are always `0x80`. We hard-code that to avoid an
    // illegal shift (`n >> 66` is undefined behavior for u64); the
    // remaining ten payload bytes use shifts in `[0, 60]` which are
    // safe.
    out.push(0xFF);
    out.push(0x80); // bits 71..66 — always zero for u64-bounded n
    out.push(0x80 | ((n >> 60) & 0x3F) as u8); // bits 65..60
    out.push(0x80 | ((n >> 54) & 0x3F) as u8);
    out.push(0x80 | ((n >> 48) & 0x3F) as u8);
    out.push(0x80 | ((n >> 42) & 0x3F) as u8);
    out.push(0x80 | ((n >> 36) & 0x3F) as u8);
    out.push(0x80 | ((n >> 30) & 0x3F) as u8);
    out.push(0x80 | ((n >> 24) & 0x3F) as u8);
    out.push(0x80 | ((n >> 18) & 0x3F) as u8);
    out.push(0x80 | ((n >> 12) & 0x3F) as u8);
    out.push(0x80 | ((n >> 6) & 0x3F) as u8);
    out.push(0x80 | (n & 0x3F) as u8);
  }
}

/// Faithful transliteration of `Image::ExifTool::ReadValue($dataPt, $offset,
/// $format, $count, $size, $ratPt)` (`ExifTool.pm:6275-6321`), restricted to
/// the format set `Image::ExifTool::Red` uses (Red.pm:22-33 `%redFormat` plus
/// the rational32u + string fields in RED1/RED2):
///
/// - integer types: `int8u`, `int8s`, `int16u`, `int32u`, `int32s`
///   (`ExifTool.pm:6068-6077` `Get8u`/`Get8s`/`Get16u`/`Get32u`/`Get32s`)
/// - `float` (`ExifTool.pm:6074` `GetFloat` ⇒ `unpack 'f'`, IEEE single)
/// - `rational32u` (`ExifTool.pm:6089-6095` `GetRational32u` ⇒
///   `Rational::rational32(num, denom)`; the zero-denominator `inf`/`undef`
///   semantics are carried by [`Rational::exiftool_val_str`])
/// - `string` (truncated at first NUL, `ExifTool.pm:6300`)
/// - `undef` (raw byte slice — `ExifTool.pm:6298`)
///
/// Returns the **value** ExifTool would pass to `HandleTag`: a scalar for
/// `count == 1` and a *space-joined* `TagValue::Str` for `count > 1`
/// (Perl `wantarray ? @vals : join(' ', @vals)`, `ExifTool.pm:6318-6320`).
/// For `string`/`undef` the byte slice itself is a single scalar; for the
/// fixed-width numeric formats with `size == count * len` >1 element each
/// element is read individually and the textual results joined with `' '`.
///
/// **Short buffers:** faithful to `ExifTool.pm:6290-6292` — when
/// `len * count > $size` (with `$size = length($$dataPt) - $offset`), `count`
/// is shortened to `int($size / len)` and the read continues; `None` is
/// returned only when the shortened count is `< 1`. So a `RED2` `int16u[3]`
/// against a 4-byte tail yields a 2-element `"a b"` value, not a dropped tag.
///
/// `byte_order` mirrors ExifTool's global `$currentByteOrder` but threaded
/// as an explicit argument (the engine is global-state-free). Red.pm uses
/// only `ByteOrder::Mm`; the `Ii` arm is faithful but unexercised here and
/// must be unit-tested at the first little-endian consumer (same discipline
/// as `bitstream::BitOrder::Ii`, see the Phase-2 forward items).
///
/// **Coverage:** intentionally sized to Red.pm's needs (per the
/// incremental-derivation discipline). Other ExifTool formats — `int16s`,
/// `int64u`/`int64s`, `rational32s`, `rational64u`/`rational64s`,
/// `fixed16(s|u)`/`fixed32(s|u)`, `double`, `extended`, `binary`,
/// `unicode`/`utf8`/`ue7`, `ifd`/`ifd64` — are deferred to the first format
/// that genuinely needs each one. Adding an arm is faithfully-additive: the
/// caller picks the format string, this function dispatches.
#[must_use]
pub fn read_value(
  data: &[u8],
  offset: usize,
  format: &str,
  count: usize,
  byte_order: ByteOrder,
) -> Option<TagValue> {
  // ExifTool.pm:6279 `my $len = $formatSize{$format}` — the per-element width.
  let elem_size = format_size(format)?;
  // ExifTool.pm:6284 `$size = length($$dataPt) - $offset unless defined $size`
  // — Perl defaults `$size` to "all of the buffer past `$offset`". Mirror that
  // here (Red.pm always omits `$size` at the ReadValue call sites).
  let size = data.len().checked_sub(offset)?;
  // ExifTool.pm:6290-6292 — when `$len * $count > $size`, shorten `$count` to
  // `int($size / $len)`; if the shortened count is < 1, return undef. This is
  // the faithful ReadValue semantic for short/truncated inputs (Codex round-1
  // F2: a RED2 file with header-declared `$size` short by one or two bytes at
  // offset 0x56 yields `int16u[3]` partial values `"1001 0"` or `"1001"` in
  // Perl, not a dropped tag).
  let total = elem_size.checked_mul(count)?;
  let count = if total > size {
    let shortened = size / elem_size;
    if shortened == 0 {
      return None;
    }
    shortened
  } else {
    count
  };
  // After shortening, `elem_size * count <= size` is guaranteed by `int`.
  let end = offset
    .checked_add(elem_size.checked_mul(count)?)
    .filter(|&e| e <= data.len())?;
  match format {
    // ExifTool.pm:6298-6300 — string is a single scalar of `count * len`
    // bytes (`length len` == 1), TRUNCATED at the first NUL.
    "string" => {
      let bytes = &data[offset..end];
      let trunc_end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
      // **Codex round-9 F1:** `from_utf8_lossy` substitutes U+FFFD
      // (3-byte `\xEF\xBF\xBD`) for malformed bytes, but bundled
      // `exiftool` runs `Image::ExifTool::XMP::FixUTF8(\$str)` at JSON
      // serialization (`exiftool:3822`), which substitutes the single
      // ASCII byte `?` per `XMP.pm:2949-2972`. Route through
      // [`fix_utf8`] to mirror that behaviour byte-exact (e.g. an R3D
      // `OriginalFileName` of `A\xff.R3D` emits `A?.R3D`, matching
      // ExifTool, not `A�.R3D`). Phase-2 forward-item #51 seam: the
      // engine-tier helper lives in this module for re-use by any
      // future format whose Perl path passes raw bytes to `HandleTag`.
      Some(TagValue::Str(fix_utf8(&bytes[..trunc_end]).into()))
    }
    // ExifTool.pm:6298 (`%readValueProc` has no `undef` entry) — raw bytes.
    "undef" => Some(TagValue::Bytes(data[offset..end].to_vec())),
    // Fixed-width numerics: read element by element, join multi-element
    // results with `' '` (Perl `join(' ', @vals)`, ExifTool.pm:6319).
    _ => {
      if count == 0 {
        // ExifTool.pm:6286 `return '' if defined $count or $size < $len`:
        // a literal `0` count yields the empty string — faithful but the
        // `HandleTag` callers in Red.pm always derive `count = size/len ≥ 1`.
        return Some(TagValue::Str(SmolStr::new("")));
      }
      // count == 1 ⇒ return a typed scalar; count > 1 ⇒ join textual forms.
      if count == 1 {
        return read_one(data, offset, format, byte_order);
      }
      let mut parts: Vec<String> = Vec::with_capacity(count);
      for i in 0..count {
        let v = read_one(data, offset + i * elem_size, format, byte_order)?;
        parts.push(scalar_text(&v));
      }
      Some(TagValue::Str(parts.join(" ").into()))
    }
  }
}

/// ExifTool `%formatSize` (`ExifTool.pm:6199-6231`), Red.pm subset.
fn format_size(format: &str) -> Option<usize> {
  Some(match format {
    "int8u" | "int8s" | "string" | "undef" => 1, // ExifTool.pm:6200-6201,6224,6226
    "int16u" => 2,                               // ExifTool.pm:6203
    "int32u" | "int32s" | "rational32u" | "float" => 4, // ExifTool.pm:6205-6211,6219
    _ => return None,
  })
}

/// Read a SINGLE element of `format` at `offset`. `count > 1` callers in
/// [`read_value`] invoke this per index and join textual forms.
fn read_one(data: &[u8], offset: usize, format: &str, byte_order: ByteOrder) -> Option<TagValue> {
  match format {
    // ExifTool.pm:6068-6069 `Get8u`/`Get8s` — no byte-order dependence.
    "int8u" => Some(TagValue::I64(i64::from(data[offset]))),
    "int8s" => Some(TagValue::I64(i64::from(data[offset] as i8))),
    "int16u" => {
      // ExifTool.pm:6071 `Get16u` ⇒ unpack `S`/`v` depending on byte order.
      let b: [u8; 2] = [data[offset], data[offset + 1]];
      Some(TagValue::I64(i64::from(match byte_order {
        ByteOrder::Mm => u16::from_be_bytes(b),
        ByteOrder::Ii => u16::from_le_bytes(b),
      })))
    }
    "int32u" => {
      // ExifTool.pm:6073 `Get32u`.
      let b: [u8; 4] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
      ];
      Some(TagValue::I64(i64::from(match byte_order {
        ByteOrder::Mm => u32::from_be_bytes(b),
        ByteOrder::Ii => u32::from_le_bytes(b),
      })))
    }
    "int32s" => {
      // ExifTool.pm:6072 `Get32s` (signed).
      let b: [u8; 4] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
      ];
      Some(TagValue::I64(i64::from(match byte_order {
        ByteOrder::Mm => i32::from_be_bytes(b),
        ByteOrder::Ii => i32::from_le_bytes(b),
      })))
    }
    "float" => {
      // ExifTool.pm:6074 `GetFloat` ⇒ unpack `f` (IEEE-754 single precision).
      let b: [u8; 4] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
      ];
      Some(TagValue::F64(f64::from(match byte_order {
        ByteOrder::Mm => f32::from_be_bytes(b),
        ByteOrder::Ii => f32::from_le_bytes(b),
      })))
    }
    "rational32u" => {
      // ExifTool.pm:6089-6095 `GetRational32u`: numerator = Get16u, denominator
      // = Get16u (offset+2), wrapped in `Rational::rational32` (7-sig
      // RoundFloat). Zero-denominator handling lives in `Rational::
      // exiftool_val_str` so a hash key matches what the serializer prints.
      let n_b: [u8; 2] = [data[offset], data[offset + 1]];
      let d_b: [u8; 2] = [data[offset + 2], data[offset + 3]];
      let (num, den) = match byte_order {
        ByteOrder::Mm => (u16::from_be_bytes(n_b), u16::from_be_bytes(d_b)),
        ByteOrder::Ii => (u16::from_le_bytes(n_b), u16::from_le_bytes(d_b)),
      };
      Some(TagValue::Rational(crate::value::Rational::rational32(
        i64::from(num),
        i64::from(den),
      )))
    }
    _ => None,
  }
}

/// Stringified form of a [`read_one`] scalar for the multi-element
/// `join(' ', @vals)` (`ExifTool.pm:6319`). Matches Perl scalar
/// stringification (the same text `%g`/integer form `ReadValue` would
/// pass to `HandleTag`).
fn scalar_text(v: &TagValue) -> String {
  match v {
    TagValue::I64(n) => n.to_string(),
    TagValue::U64(n) => n.to_string(),
    // Perl stringifies a float via `%g`-ish (default `$DIG = 15`). The
    // serializer uses `format_g(_, 15)` for floats; same here so the joined
    // text matches what ExifTool's joined `@vals` would print.
    TagValue::F64(n) => {
      if n.is_finite() {
        format_g(*n, 15)
      } else {
        n.to_string()
      }
    }
    TagValue::Rational(r) => r.exiftool_val_str(),
    TagValue::Str(s) => s.to_string(),
    TagValue::Bool(b) => b.to_string(),
    TagValue::Bytes(_) | TagValue::List(_) => String::new(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn tenths(v: &TagValue) -> TagValue {
    match v {
      TagValue::I64(n) => TagValue::F64(*n as f64 / 10.0),
      x => x.clone(),
    }
  }

  // Two separate statics — `TagDef` holds fn-pointers and is intentionally
  // not `Clone`; real ported tables are statics too, so this mirrors usage.
  static DEF_VC: TagDef = TagDef::new(
    "Demo",
    "Demo",
    ValueConv::Func(tenths),
    PrintConv::Hash(PrintConvHash::direct(&[("5", PrintValue::Str("five-ish"))])),
  );
  static DEF_NOVC: TagDef = TagDef::new(
    "Demo",
    "Demo",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::direct(&[("5", PrintValue::Str("five-ish"))])),
  );

  #[test]
  fn n_mode_stops_after_value_conv() {
    assert_eq!(
      apply(&DEF_VC, &TagValue::I64(50), false),
      TagValue::F64(5.0)
    );
  }

  #[test]
  fn print_mode_runs_both_stages_and_falls_back() {
    // ValueConv 50 -> 5.0. ExifTool keys the hash by the *stringified*
    // `$val` (`$$conv{$val}`, ExifTool.pm:3603): bundled Perl
    //   perl -e 'my $v=50/10; my %c=("5"=>"five-ish");
    //            print defined($c{$v})?$c{$v}:"Unknown ($v)"'  => five-ish
    // i.e. `5.0` stringifies to `"5"` and HITS the `"5"` key. (The old
    // i64-only Map could not represent this and wrongly passed the float
    // through — that was a fidelity bug; the string-keyed lookup matches
    // Perl exactly.)
    assert_eq!(
      apply(&DEF_VC, &TagValue::I64(50), true),
      TagValue::Str("five-ish".into())
    );
    // Map hit, then ExifTool-style "Unknown ($val)" fallback for a miss.
    assert_eq!(
      apply(&DEF_NOVC, &TagValue::I64(5), true),
      TagValue::Str("five-ish".into())
    );
    assert_eq!(
      apply(&DEF_NOVC, &TagValue::I64(9), true),
      TagValue::Str("Unknown (9)".into())
    );
    // A non-integral float misses (Perl: `5.5` ⇒ `Unknown (5.5)`).
    assert_eq!(
      apply(&DEF_NOVC, &TagValue::F64(5.5), true),
      TagValue::Str("Unknown (5.5)".into())
    );
  }

  // AAC.pm `Channels` maps integer keys to bare numbers; `exiftool -j`
  // emits the JSON number `2`, never the string `"2"`. Pin that shape:
  // the Map hit must yield a numeric `TagValue`, and serializing it must
  // produce a bare JSON number.
  #[cfg(feature = "json")]
  #[test]
  fn numeric_map_value_yields_number_not_string() {
    static CHANNELS: TagDef = TagDef::new(
      "Channels",
      "AAC",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[
        ("1", PrintValue::I64(1)),
        ("2", PrintValue::I64(2)),
      ])),
    );
    // `I64(2)` stringifies to `"2"` (Perl `$$conv{$val}`), hits the `"2"`
    // key, yields the numeric `PrintValue::I64(2)`.
    let v = apply(&CHANNELS, &TagValue::I64(2), true);
    assert_eq!(v, TagValue::I64(2));

    use crate::{Group, Metadata, serialize::to_exiftool_json};
    let mut m = Metadata::new("a.aac");
    m.push(Group::new("Audio", "AAC"), "Channels", v);
    let json = to_exiftool_json(&m);
    // serde emits the I64 as a bare JSON number `2`, NOT a quoted string `"2"`.
    crate::jsondiff::json_equivalent(&json, r#"[{"SourceFile":"a.aac","AAC:Channels":2}]"#)
      .expect("Channels=2 numeric value");
    assert!(!json.contains("\"AAC:Channels\":\"2\""), "got: {json}");
  }

  // Faithful to `Image::ExifTool::AIFF` `CompressionType` (AIFF.pm:88-101),
  // whose PrintConv hash is keyed by 4-char STRINGS: `NONE=>'None'`,
  // `sowt=>'Little-endian, no compression'`, `ULAW=>'Mu-law'`, … The old
  // i64-only Map could not represent these at all (raw value would leak).
  // Conversion text verified against bundled Perl (see body).
  static AIFF_COMPRESSION: TagDef = TagDef::new(
    "CompressionType",
    "AIFF",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::direct(&[
      ("NONE", PrintValue::Str("None")),
      ("sowt", PrintValue::Str("Little-endian, no compression")),
      ("ULAW", PrintValue::Str("Mu-law")),
      // A numeric-looking string key, to prove a numeric value whose
      // stringified form equals a key HITS (Perl: `$$conv{2}` keyed
      // `"2"`), exactly like ExifTool's stringified hash lookup.
      ("2", PrintValue::Str("Two")),
    ])),
  );

  #[test]
  fn aiff_string_keyed_print_conv_hits_and_misses() {
    // String value hits the string key (`$$conv{"sowt"}`), byte-exact
    // text. Cross-checked against the bundled Perl ExifTool source
    // `lib/Image/ExifTool/AIFF.pm:93` `sowt => 'Little-endian, no
    // compression'` and `:88` `NONE => 'None'` via:
    //   perl -e 'my %c=(NONE=>"None",
    //            sowt=>"Little-endian, no compression",ULAW=>"Mu-law");
    //            for (qw/sowt NONE ULAW zzzz/){print
    //            defined($c{$_})?$c{$_}:"Unknown ($_)","\n"}'
    //   => Little-endian, no compression / None / Mu-law / Unknown (zzzz)
    assert_eq!(
      apply(&AIFF_COMPRESSION, &TagValue::Str("sowt".into()), true),
      TagValue::Str("Little-endian, no compression".into())
    );
    assert_eq!(
      apply(&AIFF_COMPRESSION, &TagValue::Str("NONE".into()), true),
      TagValue::Str("None".into())
    );
    // Miss ⇒ ExifTool `"Unknown ($val)"` (ExifTool.pm:3622), `$val` =
    // the stringified scalar used for the lookup.
    assert_eq!(
      apply(&AIFF_COMPRESSION, &TagValue::Str("zzzz".into()), true),
      TagValue::Str("Unknown (zzzz)".into())
    );
    // A numeric value whose stringified form (`"2"`) equals a key HITS,
    // exactly as Perl's `$$conv{$val}` (scalar stringified to a hash key).
    assert_eq!(
      apply(&AIFF_COMPRESSION, &TagValue::I64(2), true),
      TagValue::Str("Two".into())
    );
  }

  #[test]
  fn print_conv_hash_is_applied_element_wise_over_lists() {
    // ExifTool runs the conversion over every list element
    // (ExifTool.pm:3578-3582, `for(;;)` over `@$value`). A
    // `List([Str("NONE"), Str("sowt")])` ⇒ element-wise converted list.
    let v = apply(
      &AIFF_COMPRESSION,
      &TagValue::List(vec![
        TagValue::Str("NONE".into()),
        TagValue::Str("sowt".into()),
      ]),
      true,
    );
    assert_eq!(
      v,
      TagValue::List(vec![
        TagValue::Str("None".into()),
        TagValue::Str("Little-endian, no compression".into()),
      ])
    );
    // A list with a miss converts that element to `Unknown ($val)` and
    // leaves the others converted (still a list, same arity).
    let v2 = apply(
      &AIFF_COMPRESSION,
      &TagValue::List(vec![
        TagValue::Str("sowt".into()),
        TagValue::Str("zzzz".into()),
      ]),
      true,
    );
    assert_eq!(
      v2,
      TagValue::List(vec![
        TagValue::Str("Little-endian, no compression".into()),
        TagValue::Str("Unknown (zzzz)".into()),
      ])
    );
  }

  #[test]
  fn print_conv_none_and_func_recurse_over_lists() {
    // ExifTool applies the PrintConv element-wise for *every* conv kind,
    // not just the hash (ExifTool.pm:3578-3582). `None` ⇒ each element
    // unchanged; `Func` ⇒ each element transformed.
    fn shout(v: &TagValue) -> TagValue {
      match v {
        TagValue::Str(s) => TagValue::Str(s.to_uppercase().into()),
        x => x.clone(),
      }
    }
    static NONE_DEF: TagDef = TagDef::new("N", "X", ValueConv::None, PrintConv::None);
    static FUNC_DEF: TagDef = TagDef::new("F", "X", ValueConv::None, PrintConv::Func(shout));
    let list = TagValue::List(vec![TagValue::Str("a".into()), TagValue::Str("b".into())]);
    assert_eq!(apply(&NONE_DEF, &list, true), list);
    assert_eq!(
      apply(&FUNC_DEF, &list, true),
      TagValue::List(vec![TagValue::Str("A".into()), TagValue::Str("B".into()),])
    );
  }

  #[test]
  fn rational_and_float_keys_use_shared_serializer_text() {
    // The PrintConv-hash key must be the SAME `$val` text the serializer
    // prints, so a rational/float value can be looked up by its rounded
    // form. `Rational::rational64(86,10)` ⇒ "8.6" (RoundFloat 10g);
    // `F64(8.6)` ⇒ "8.6" (%.15g). Both must hit a `"8.6"` key.
    static R: TagDef = TagDef::new(
      "R",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[(
        "8.6",
        PrintValue::Str("eight-six"),
      )])),
    );
    assert_eq!(
      apply(
        &R,
        &TagValue::Rational(crate::value::Rational::rational64(86, 10)),
        true
      ),
      TagValue::Str("eight-six".into())
    );
    assert_eq!(
      apply(&R, &TagValue::F64(8.6), true),
      TagValue::Str("eight-six".into())
    );
    // A zero-denominator rational stringifies to `undef`/`inf` (the same
    // word the serializer emits) and can be a key too.
    static Z: TagDef = TagDef::new(
      "Z",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[(
        "undef",
        PrintValue::Str("no-zoom"),
      )])),
    );
    assert_eq!(
      apply(
        &Z,
        &TagValue::Rational(crate::value::Rational::rational64(0, 0)),
        true
      ),
      TagValue::Str("no-zoom".into())
    );
  }

  // ── DecodeBits: faithful transliteration of `ExifTool.pm:6374-6396`.
  // Each case is the bundled Perl `Image::ExifTool::DecodeBits` oracle,
  // run via:
  //   perl -I/Users/user/Develop/findit-studio/exiftool/lib \
  //        -MImage::ExifTool -e 'print Image::ExifTool::DecodeBits(...)'
  // (outputs reproduced inline). `WEBP_FLAGS` mirrors the real
  // `lib/Image/ExifTool/RIFF.pm:1361` `PrintConv => { BITMASK => {
  // 1=>'Animation',2=>'XMP',3=>'EXIF',4=>'Alpha',5=>'ICC Profile' }}`.
  const WEBP_FLAGS: &[(u8, &str)] = &[
    (1, "Animation"),
    (2, "XMP"),
    (3, "EXIF"),
    (4, "Alpha"),
    (5, "ICC Profile"),
  ];

  #[test]
  fn decode_bits_matches_perl_oracle() {
    // DecodeBits(30, WEBP_FLAGS)            => "Animation, XMP, EXIF, Alpha"
    assert_eq!(
      decode_bits("30", Some(WEBP_FLAGS), 32),
      "Animation, XMP, EXIF, Alpha"
    );
    // DecodeBits(31, WEBP_FLAGS) (bit0 unmapped) =>
    //   "[0], Animation, XMP, EXIF, Alpha"
    assert_eq!(
      decode_bits("31", Some(WEBP_FLAGS), 32),
      "[0], Animation, XMP, EXIF, Alpha"
    );
    // DecodeBits(0, {1=>Animation,2=>XMP})  => "(none)"
    assert_eq!(
      decode_bits("0", Some(&[(1, "Animation"), (2, "XMP")]), 32),
      "(none)"
    );
    // DecodeBits(5, {2=>XMP}) (bit0 miss)   => "[0], XMP"
    assert_eq!(decode_bits("5", Some(&[(2, "XMP")]), 32), "[0], XMP");
    // Multi-word "3 1", default 32-bit words, {0=>a,1=>b,32=>c} => "a, b, c"
    // (word0 sets bits 0,1 -> n 0,1; word1 sets bit0 -> n 0+32=32).
    assert_eq!(
      decode_bits("3 1", Some(&[(0, "a"), (1, "b"), (32, "c")]), 32),
      "a, b, c"
    );
    // Same words but bits=4: word1 bit0 -> n 0+4=4, {0=>a,1=>b,4=>c} =>
    // "a, b, c" (non-default BitsPerWord).
    assert_eq!(
      decode_bits("3 1", Some(&[(0, "a"), (1, "b"), (4, "c")]), 4),
      "a, b, c"
    );
    // No lookup (undef): raw bit numbers joined by "," (not ", ").
    // DecodeBits(5, undef)        => "0,2"
    assert_eq!(decode_bits("5", None, 32), "0,2");
    // DecodeBits(0, undef)        => "(none)"
    assert_eq!(decode_bits("0", None, 32), "(none)");
    // DecodeBits("5 1", undef, 4) => "0,2,4"
    assert_eq!(decode_bits("5 1", None, 4), "0,2,4");
    // Non-numeric word: Perl `$val & (1<<$i)` treats "foo" as 0 ⇒ no bits.
    // DecodeBits("foo", {0=>a})   => "(none)"
    assert_eq!(decode_bits("foo", Some(&[(0, "a")]), 32), "(none)");
    // `bits == 0` ⇒ DecodeBits default of 32 (`ExifTool.pm:6377`,
    // `$bits or $bits = 32`): bit 5 still in range.
    assert_eq!(decode_bits("32", Some(WEBP_FLAGS), 0), "ICC Profile");
    // Signed / leading-zero words take Perl numeric context for `&`:
    //   perl -e 'print Image::ExifTool::DecodeBits("+5",{0=>"a",2=>"c"})'
    //     => a, c
    assert_eq!(decode_bits("+5", Some(&[(0, "a"), (2, "c")]), 32), "a, c");
    //   perl -e 'print Image::ExifTool::DecodeBits("007",
    //            {0=>"a",1=>"b",2=>"c"})'  => a, b, c
    assert_eq!(
      decode_bits("007", Some(&[(0, "a"), (1, "b"), (2, "c")]), 32),
      "a, b, c"
    );
    // A negative value: Perl `-1 & (1<<$i)` ⇒ every bit in [0,bits) set.
    //   perl -e 'print Image::ExifTool::DecodeBits(-1,{0=>"z",3=>"w"})'
    //     => z, [1], [2], w  (bits 0..3, 32-bit default)
    assert_eq!(
      decode_bits("-1", Some(&[(0, "z"), (3, "w")]), 4),
      "z, [1], [2], w"
    );
  }

  // QuickTime.pm:2627 `TrackProperty`: a single conv hash with BOTH a
  // direct key (`0 => 'No presentation'`) AND `BITMASK => { 0 => 'Main
  // track' }`. Direct key present ⇒ direct wins; direct miss ⇒ BITMASK.
  //   perl -e 'print Image::ExifTool::DecodeBits(1,{0=>"Main track"})'
  //     => Main track
  static QT_TRACKPROP: TagDef = TagDef::new(
    "TrackProperty",
    "QuickTime",
    ValueConv::None,
    PrintConv::Hash(PrintConvHash::new(
      &[("0", PrintValue::Str("No presentation"))],
      Some(&[(0, "Main track")]),
      None,
    )),
  );

  #[test]
  fn branch_order_direct_key_wins_over_bitmask() {
    // `$val` = 0 ⇒ `$$conv{0}` defined ⇒ direct value, BITMASK NOT run
    // (Perl: `if (not defined($value = $$conv{$val}))`).
    assert_eq!(
      apply(&QT_TRACKPROP, &TagValue::I64(0), true),
      TagValue::Str("No presentation".into())
    );
  }

  #[test]
  fn branch_order_direct_miss_then_bitmask_decodebits() {
    // `$val` = 1 ⇒ no `$$conv{1}` ⇒ `$$conv{BITMASK}` ⇒ DecodeBits(1,
    // {0=>'Main track'}) => "Main track".
    assert_eq!(
      apply(&QT_TRACKPROP, &TagValue::I64(1), true),
      TagValue::Str("Main track".into())
    );
    // bit set with no mapping ⇒ `[n]` (DecodeBits miss form). `$val`=2
    // ⇒ bit1 set, BITMASK has only bit0 ⇒ "[1]".
    assert_eq!(
      apply(&QT_TRACKPROP, &TagValue::I64(2), true),
      TagValue::Str("[1]".into())
    );
  }

  #[test]
  fn branch_order_bitmask_stops_other_and_unknown() {
    // Faithful to the Perl `else`: with BITMASK present, OTHER is NEVER
    // consulted and the Unknown fallback is NEVER reached — even when
    // DecodeBits yields "(none)" (`$val` = 0 but here NO direct `0` key).
    fn other_should_not_run(_v: &TagValue) -> Option<TagValue> {
      Some(TagValue::Str("OTHER-RAN".into()))
    }
    static BM_AND_OTHER: TagDef = TagDef::new(
      "BMOther",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::new(
        &[],
        Some(&[(1, "One")]),
        Some(other_should_not_run),
      )),
    );
    // `$val`=0: no direct key, BITMASK present ⇒ DecodeBits(0,…)=
    // "(none)"; OTHER NOT run, no "Unknown" (`else` skips both).
    //   perl -e 'print Image::ExifTool::DecodeBits(0,{1=>"One"})'
    //     => (none)
    assert_eq!(
      apply(&BM_AND_OTHER, &TagValue::I64(0), true),
      TagValue::Str("(none)".into())
    );
    // `$val`=2 ⇒ bit1 set ⇒ DecodeBits(2,{1=>One}) => "One"; no OTHER.
    //   perl -e 'print Image::ExifTool::DecodeBits(2,{1=>"One"})'
    //     => One
    assert_eq!(
      apply(&BM_AND_OTHER, &TagValue::I64(2), true),
      TagValue::Str("One".into())
    );
    // `$val`=1 ⇒ bit0 set, BITMASK maps only bit1 ⇒ "[0]" (DecodeBits
    // miss form) — still NOT OTHER and NOT "Unknown" (`else` skips them).
    //   perl -e 'print Image::ExifTool::DecodeBits(1,{1=>"One"})'
    //     => [0]
    assert_eq!(
      apply(&BM_AND_OTHER, &TagValue::I64(1), true),
      TagValue::Str("[0]".into())
    );
  }

  #[test]
  fn branch_order_other_used_when_no_bitmask_and_direct_miss() {
    // No BITMASK, direct miss ⇒ `$$conv{OTHER}` consulted; Some ⇒ used.
    fn other_cb(v: &TagValue) -> Option<TagValue> {
      match v {
        TagValue::I64(n) => Some(TagValue::Str(format!("via-OTHER:{n}").into())),
        _ => None,
      }
    }
    static OTHER_DEF: TagDef = TagDef::new(
      "O",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::new(
        &[("9", PrintValue::Str("nine"))],
        None,
        Some(other_cb),
      )),
    );
    // Direct key still wins when present.
    assert_eq!(
      apply(&OTHER_DEF, &TagValue::I64(9), true),
      TagValue::Str("nine".into())
    );
    // Direct miss + no BITMASK ⇒ OTHER returns Some ⇒ that value.
    assert_eq!(
      apply(&OTHER_DEF, &TagValue::I64(7), true),
      TagValue::Str("via-OTHER:7".into())
    );
  }

  #[test]
  fn branch_order_other_returning_none_falls_through_to_unknown() {
    // Perl: `if (not defined $value) { ... "Unknown ($val)" }` — an
    // OTHER returning undef/None falls through exactly like no OTHER.
    fn other_none(_v: &TagValue) -> Option<TagValue> {
      None
    }
    static OTHER_NONE_DEF: TagDef = TagDef::new(
      "ON",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::new(&[], None, Some(other_none))),
    );
    assert_eq!(
      apply(&OTHER_NONE_DEF, &TagValue::I64(42), true),
      TagValue::Str("Unknown (42)".into())
    );
  }

  #[test]
  fn branch_order_printhex_hex_vs_generic_unknown() {
    // `$$tagInfo{PrintHex} and defined $val and IsInt($val) and
    // $convType eq 'PrintConv'` ⇒ `sprintf('Unknown (0x%x)',$val)`,
    // else `"Unknown ($val)"` (`ExifTool.pm:3617-3622`).
    //   perl -e 'printf "Unknown (0x%x)\n", 31'  => Unknown (0x1f)
    static HEX_DEF: TagDef = TagDef::new(
      "H",
      "RIFF",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[("1", PrintValue::Str("one"))])),
    )
    .with_print_hex(true);
    static PLAIN_DEF: TagDef = TagDef::new(
      "P",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[("1", PrintValue::Str("one"))])),
    );
    // PrintHex + integer miss ⇒ lowercase hex, no leading zeros.
    assert_eq!(
      apply(&HEX_DEF, &TagValue::I64(31), true),
      TagValue::Str("Unknown (0x1f)".into())
    );
    // Non-PrintHex tag, same miss ⇒ generic decimal Unknown.
    assert_eq!(
      apply(&PLAIN_DEF, &TagValue::I64(31), true),
      TagValue::Str("Unknown (31)".into())
    );
    // PrintHex but `$val` not an integer (IsInt fails on "x") ⇒ generic.
    assert_eq!(
      apply(&HEX_DEF, &TagValue::Str("x".into()), true),
      TagValue::Str("Unknown (x)".into())
    );
    // PrintHex but a non-integral float ⇒ IsInt("2.5") false ⇒ generic.
    assert_eq!(
      apply(&HEX_DEF, &TagValue::F64(2.5), true),
      TagValue::Str("Unknown (2.5)".into())
    );
    // `sprintf '0x%x'` of 0 ⇒ "0x0"; negative ⇒ Perl unsigned wrap
    //   perl -e 'printf "0x%x\n", -1'  => 0xffffffffffffffff
    assert_eq!(
      apply(&HEX_DEF, &TagValue::I64(0), true),
      TagValue::Str("Unknown (0x0)".into())
    );
    assert_eq!(
      apply(&HEX_DEF, &TagValue::I64(-1), true),
      TagValue::Str("Unknown (0xffffffffffffffff)".into())
    );
  }

  #[test]
  fn printhex_hex_form_not_applied_in_value_conv_stage() {
    // The hex form is gated on `$convType eq 'PrintConv'`
    // (`ExifTool.pm:3618`). A hash conv applied as ValueConv must use the
    // generic `Unknown ($val)` even when the tag has PrintHex. The public
    // `apply` only ever runs PrintConv with ConvType::PrintConv, so we
    // exercise the gate at the hash-conv layer directly.
    static HEX_DEF: TagDef = TagDef::new(
      "H",
      "RIFF",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[])),
    )
    .with_print_hex(true);
    let h = match HEX_DEF.print_conv() {
      PrintConv::Hash(h) => h,
      _ => panic!("expected Hash"),
    };
    // ValueConv stage ⇒ generic, even though PrintHex is set + IsInt.
    assert_eq!(
      apply_hash_conv(&HEX_DEF, &h, &TagValue::I64(31), ConvType::ValueConv),
      TagValue::Str("Unknown (31)".into())
    );
    // PrintConv stage ⇒ hex form (the only difference is $convType).
    assert_eq!(
      apply_hash_conv(&HEX_DEF, &h, &TagValue::I64(31), ConvType::PrintConv),
      TagValue::Str("Unknown (0x1f)".into())
    );
  }

  #[test]
  fn is_int_matches_perl_regex() {
    // ExifTool `sub IsInt($) { return scalar($_[0] =~ /^[+-]?\d+$/); }`
    // (ExifTool.pm:5943). Verified shape-by-shape:
    //   perl -e 'for(qw/5 +5 -5 0 007/){print /^[+-]?\d+$/?1:0}'  => 11111
    //   perl -e 'for("5.0","","+","x","5x","x5"," 5"){print /^[+-]?\d+$/?1:0}'
    //     => 0000000
    for s in ["5", "+5", "-5", "0", "007", "123456789"] {
      assert!(is_int(s), "{s} should be IsInt");
    }
    for s in [
      "5.0", "", "+", "-", "x", "5x", "x5", " 5", "5 ", "0x1f", "+-5",
    ] {
      assert!(!is_int(s), "{s} should NOT be IsInt");
    }
  }

  // ── ISSUE A: Perl numeric context in decode_bits word coercion ────────────
  // Fixed in D10 r13b: words now use `perl_numeric_coerce` instead of
  // integer-only parse. Oracle: bundled Perl ExifTool via
  //   perl -I/Users/user/Develop/findit-studio/exiftool/lib -MImage::ExifTool \
  //        -e 'print Image::ExifTool::DecodeBits($ARGV[0], \
  //            {1=>"One",0=>"a",2=>"b",3=>"c"}, $ARGV[1]||32)' "<word>" [bits]
  // Lookup used in all cases below: {0=>"a", 1=>"One", 2=>"b", 3=>"c"}.
  const BITS_LOOKUP: &[(u8, &str)] = &[(0, "a"), (1, "One"), (2, "b"), (3, "c")];

  #[test]
  fn decode_bits_perl_numeric_coercion_float_truncation() {
    // "2.9": Perl int("2.9") = 2 ⇒ bit1 set ⇒ "One"
    //   oracle: perl ... "2.9"  => One
    assert_eq!(decode_bits("2.9", Some(BITS_LOOKUP), 32), "One");

    // "3.9": Perl int("3.9") = 3 ⇒ bits 0,1 ⇒ "a, One"
    //   oracle: perl ... "3.9"  => a, One
    assert_eq!(decode_bits("3.9", Some(BITS_LOOKUP), 32), "a, One");

    // "1e1": Perl "1e1"+0 = 10.0, int(10.0) = 10 ⇒ bits 1,3 ⇒ "One, c"
    //   oracle: perl ... "1e1"  => One, c
    assert_eq!(decode_bits("1e1", Some(BITS_LOOKUP), 32), "One, c");

    // "2.9abc": leading prefix "2.9" ⇒ int(2.9) = 2 ⇒ bit1 ⇒ "One"
    //   oracle: perl ... "2.9abc"  => One
    assert_eq!(decode_bits("2.9abc", Some(BITS_LOOKUP), 32), "One");
  }

  #[test]
  fn decode_bits_perl_numeric_coercion_no_hex_no_alpha() {
    // "0x05": Perl "0x05"+0 = 0 (no hex string parsing) ⇒ "(none)"
    //   oracle: perl ... "0x05"  => (none)
    assert_eq!(decode_bits("0x05", Some(BITS_LOOKUP), 32), "(none)");

    // "foo": no leading numeric prefix ⇒ 0 ⇒ "(none)"
    //   oracle: perl ... "foo"  => (none)
    assert_eq!(decode_bits("foo", Some(BITS_LOOKUP), 32), "(none)");
  }

  #[test]
  fn decode_bits_perl_numeric_coercion_leading_zero_and_sign() {
    // "007": Perl int("007") = 7 ⇒ bits 0,1,2 ⇒ "a, One, b"
    //   oracle: perl ... "007"  => a, One, b
    assert_eq!(decode_bits("007", Some(BITS_LOOKUP), 32), "a, One, b");

    // "+5": Perl int("+5") = 5 ⇒ bits 0,2 ⇒ "a, b"
    //   oracle: perl ... "+5"  => a, b
    assert_eq!(decode_bits("+5", Some(BITS_LOOKUP), 32), "a, b");
  }

  #[test]
  fn decode_bits_perl_numeric_coercion_negative() {
    // "-2.9": Perl int("-2.9") = -2; -2 as u64 two's-complement (4-bit
    // window) = 0b1110 = 14 ⇒ bits 1,2,3 ⇒ "One, b, c"
    //   oracle: perl -e 'my $v="-2.9"; print
    //     Image::ExifTool::DecodeBits($v,{0=>"a",1=>"One",2=>"b",3=>"c"},4)'
    //     => One, b, c
    assert_eq!(decode_bits("-2.9", Some(BITS_LOOKUP), 4), "One, b, c");
  }

  #[test]
  fn decode_bits_perl_numeric_coercion_multi_word() {
    // "2.9 1" with 32-bit BitsPerWord, lookup {0=>"a",1=>"One",2=>"b",3=>"c"}:
    //   word0 "2.9" ⇒ 2 ⇒ bit1 ⇒ n=1 ⇒ "One"
    //   word1 "1"   ⇒ 1 ⇒ bit0 ⇒ n=32 ⇒ no mapping ⇒ "[32]"
    //   oracle: perl ... "2.9 1"  => One, [32]
    assert_eq!(decode_bits("2.9 1", Some(BITS_LOOKUP), 32), "One, [32]");
  }

  #[test]
  fn decode_bits_perl_numeric_coercion_via_apply() {
    // Exercise the full `apply` pipeline with a BITMASK conv and
    // non-integer words to confirm `perl_numeric_coerce` is live.
    static BM_DEF: TagDef = TagDef::new(
      "BM",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::new(&[], Some(BITS_LOOKUP), None)),
    );
    // "2.9" as a Str TagValue ⇒ DecodeBits with word coercion ⇒ "One"
    assert_eq!(
      apply(&BM_DEF, &TagValue::Str("2.9".into()), true),
      TagValue::Str("One".into())
    );
    // "0x05" ⇒ 0 ⇒ "(none)"
    assert_eq!(
      apply(&BM_DEF, &TagValue::Str("0x05".into()), true),
      TagValue::Str("(none)".into())
    );
  }

  // ── ISSUE B: PrintHex `Unknown (0x%x)` with i64-overflowing integers ─────
  // Fixed in D10 r13b: parse via i128; values > u64::MAX saturate to
  // u64::MAX, matching Perl sprintf's UV semantics.
  // Oracle commands:
  //   perl -e 'printf "0x%x\n", "99999999999999999999999999"+0'
  //     => 0xffffffffffffffff
  //   perl -e 'printf "0x%x\n", 18446744073709551615'
  //     => 0xffffffffffffffff
  //   perl -e 'printf "0x%x\n", 31'
  //     => 0x1f
  //   perl -e 'printf "0x%x\n", -1'
  //     => 0xffffffffffffffff

  #[test]
  fn printhex_large_integer_saturates_to_uv_max() {
    static HEX_DEF: TagDef = TagDef::new(
      "H",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[])),
    )
    .with_print_hex(true);

    // 26-digit string: overflows i64 and u64 ⇒ Perl UV saturates to
    // u64::MAX = 0xffffffffffffffff
    //   oracle: perl -e 'printf "0x%x\n", "99999999999999999999999999"+0'
    //     => 0xffffffffffffffff
    assert_eq!(
      apply(
        &HEX_DEF,
        &TagValue::Str("99999999999999999999999999".into()),
        true
      ),
      TagValue::Str("Unknown (0xffffffffffffffff)".into())
    );

    // u64::MAX itself ⇒ 0xffffffffffffffff (no overflow)
    //   oracle: perl -e 'printf "0x%x\n", 18446744073709551615'
    //     => 0xffffffffffffffff
    assert_eq!(
      apply(
        &HEX_DEF,
        &TagValue::Str("18446744073709551615".into()),
        true
      ),
      TagValue::Str("Unknown (0xffffffffffffffff)".into())
    );

    // Normal case: 31 ⇒ 0x1f (unchanged behavior)
    //   oracle: perl -e 'printf "0x%x\n", 31'  => 0x1f
    assert_eq!(
      apply(&HEX_DEF, &TagValue::I64(31), true),
      TagValue::Str("Unknown (0x1f)".into())
    );

    // Negative: -1 ⇒ two's-complement u64 ⇒ 0xffffffffffffffff (unchanged)
    //   oracle: perl -e 'printf "0x%x\n", -1'  => 0xffffffffffffffff
    assert_eq!(
      apply(&HEX_DEF, &TagValue::I64(-1), true),
      TagValue::Str("Unknown (0xffffffffffffffff)".into())
    );
  }

  #[test]
  fn printhex_large_integer_non_printhex_or_valueconv_unaffected() {
    // Non-PrintHex tag: is_int but no print_hex ⇒ generic Unknown.
    static PLAIN_DEF: TagDef = TagDef::new(
      "P",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[])),
    );
    assert_eq!(
      apply(
        &PLAIN_DEF,
        &TagValue::Str("99999999999999999999999999".into()),
        true
      ),
      TagValue::Str("Unknown (99999999999999999999999999)".into())
    );

    // ValueConv stage ⇒ generic, even with PrintHex + is_int (gate unchanged).
    static HEX_DEF: TagDef = TagDef::new(
      "H",
      "X",
      ValueConv::None,
      PrintConv::Hash(PrintConvHash::direct(&[])),
    )
    .with_print_hex(true);
    let h = match HEX_DEF.print_conv() {
      PrintConv::Hash(h) => h,
      _ => panic!("expected Hash"),
    };
    assert_eq!(
      apply_hash_conv(
        &HEX_DEF,
        &h,
        &TagValue::Str("99999999999999999999999999".into()),
        ConvType::ValueConv
      ),
      TagValue::Str("Unknown (99999999999999999999999999)".into())
    );
  }

  #[test]
  fn hash_value_conv_maps_then_printconv_passthrough() {
    // Faithful to AAC.pm:18-26,46 — %convSampleRate as a ValueConv hash.
    static SR: TagDef = TagDef::new(
      "SampleRate",
      "AAC",
      ValueConv::Hash(PrintConvHash::direct(&[
        ("4", PrintValue::I64(44100)),
        ("11", PrintValue::I64(8000)),
      ])),
      PrintConv::None,
    );
    // -n (print_conv off): ValueConv still applies → 44100 (number).
    assert_eq!(apply(&SR, &TagValue::I64(4), false), TagValue::I64(44100));
    // print_conv on: ValueConv 4→44100 then PrintConv::None passthrough.
    assert_eq!(apply(&SR, &TagValue::I64(4), true), TagValue::I64(44100));
  }

  #[test]
  fn bitmask_decodebits_applied_element_wise_over_lists() {
    // PrintConv runs over every list element (ExifTool.pm:3578-3582) for
    // the hash conv too — including the BITMASK path.
    let v = apply(
      &QT_TRACKPROP,
      &TagValue::List(vec![TagValue::I64(0), TagValue::I64(1), TagValue::I64(2)]),
      true,
    );
    assert_eq!(
      v,
      TagValue::List(vec![
        TagValue::Str("No presentation".into()), // direct key 0
        TagValue::Str("Main track".into()),      // BITMASK bit0
        TagValue::Str("[1]".into()),             // BITMASK miss bit1
      ])
    );
  }

  // ── ISSUE C: exact 64-bit (Perl UV/IV) coercion for integer prefixes ──────
  // Fixed in D10 r13c: `perl_numeric_coerce` classifies the matched leading
  // prefix. A pure-integer prefix (sign + digits, no `.`/exponent consumed)
  // parses via i128 and maps to the exact 64-bit UV/IV Perl's bitwise `&`
  // uses — so bit 63 and any |n| > 2^53 survive. Only float/exponent
  // prefixes still go through f64 (ExifTool.pm:6374-6396 `$val & (1<<$i)`:
  // Perl forces a UV; an NV operand stays a double). Oracle: bundled Perl
  //   perl -I/Users/user/Develop/findit-studio/exiftool/lib -MImage::ExifTool \
  //        -e 'print Image::ExifTool::DecodeBits($ARGV[0],undef,$ARGV[1]||32)'

  #[test]
  fn decode_bits_bitsperword64_high_bit_exact() {
    // Perl: "9223372036854775808" (2^63) is a UV; $val & (1<<63) != 0
    // ⇒ ONLY bit 63. f64 coercion would have lost it (clamped to i64::MAX).
    // BitsPerWord=64 (bits arg = 64). One-entry lookup mapping bit 63.
    assert_eq!(
      decode_bits("9223372036854775808", Some(&[(63, "Bit63")]), 64),
      "Bit63"
    );
    // No lookup ⇒ raw bit number "63".
    assert_eq!(decode_bits("9223372036854775808", None, 64), "63");
  }

  #[test]
  fn decode_bits_integer_above_2pow53_is_exact() {
    // 2^53 + 1 = 9007199254740993: f64 rounds to 2^53 (bit 0 lost).
    // Faithful Perl UV keeps bit 0 set.  bits=64, map bit 0.
    assert_eq!(
      decode_bits("9007199254740993", Some(&[(0, "B0"), (53, "B53")]), 64),
      "B0, B53"
    );
  }

  #[test]
  fn decode_bits_u64_max_all_low_bits_set() {
    // 18446744073709551615 = u64::MAX (Perl UV): bits 0..=63 all set.
    // Spot-check a few via a 64-wide call with no lookup. No-lookup
    // separator is ',' (no space) — `join($lookup ? ', ' : ',', …)`,
    // ExifTool.pm:6396; oracle: DecodeBits("18446744073709551615",
    // undef, 64) => "0,1,2,3,…,63".
    let out = decode_bits("18446744073709551615", None, 64);
    assert!(out.starts_with("0,1,2,"));
    assert!(out.ends_with(",63"));
  }

  #[test]
  fn perl_numeric_coerce_integer_path_no_regression_small() {
    // |n| <= 2^53: integer path must equal the historical f64 result.
    assert_eq!(perl_numeric_coerce("0"), 0);
    assert_eq!(perl_numeric_coerce("30"), 30);
    assert_eq!(perl_numeric_coerce("-1"), u64::MAX); // two's-complement, unchanged
    assert_eq!(perl_numeric_coerce("+12abc"), 12); // leading prefix only
  }

  #[test]
  fn perl_numeric_coerce_float_path_unchanged() {
    // Float/exponent prefixes still go through f64 trunc-toward-zero.
    assert_eq!(perl_numeric_coerce("2.9"), 2);
    assert_eq!(perl_numeric_coerce("1e3"), 1000);
    assert_eq!(perl_numeric_coerce("-2.9"), (-2i64) as u64);
  }

  // ── Codex PR #32 R19/F1 — Perl string→f64 numeric coercion + ExifTool
  // IsFloat + the string-typed ConvertDuration guard. Oracle pinned against
  // bundled Perl 2026-05-22:
  //   perl -e 'no warnings "numeric"; print $ARGV[0]+0' -- '<s>'   (coercion)
  //   perl -I.../exiftool/lib -MImage::ExifTool -e '...IsFloat...'  (IsFloat)
  //   perl .../exiftool on synthetic FLVs                            (ConvertDuration)

  #[test]
  fn perl_str_to_f64_matches_bundled_arithmetic_coercion() {
    let cases: &[(&str, f64)] = &[
      ("65.8", 65.8),      // plain float
      ("  65.8  ", 65.8),  // leading/trailing ws skipped (trailing ignored)
      ("65.8 kbps", 65.8), // leading numeric prefix, rest ignored
      ("12abc", 12.0),     // integer prefix
      ("1e3", 1000.0),     // exponent
      ("1,5", 1.0),        // comma TERMINATES the prefix (raw arithmetic)
      ("12,5", 12.0),      // ditto
      (".5", 0.5),         // leading-dot fraction
      ("3.", 3.0),         // trailing-dot integer
      ("+3.5", 3.5),       // leading plus
      ("-2", -2.0),        // negative integer
      ("abc", 0.0),        // no numeric prefix ⇒ 0
      ("", 0.0),           // empty ⇒ 0
      ("  ", 0.0),         // all whitespace ⇒ 0
      ("0x10", 0.0),       // NO hex parsing ⇒ 0 (Perl "0x10"+0 == 0)
      (".", 0.0),          // lone dot ⇒ 0
      ("+", 0.0),          // lone sign ⇒ 0
      ("1e", 1.0),         // dangling exponent ⇒ mantissa only (Perl "1e"+0==1)
    ];
    for &(s, want) in cases {
      let got = perl_str_to_f64(s);
      assert!(
        (got - want).abs() < 1e-12 || (got == 0.0 && want == 0.0),
        "perl_str_to_f64({s:?}) = {got}, want {want}"
      );
    }
  }

  // ── Codex PR #32 R20/F1 — Perl `Perl_my_atof` non-finite string coercion.
  // Oracle pinned against bundled Perl 2026-05-22 via:
  //   perl -e 'no warnings "numeric"; printf("%s\n", $ARGV[0]+0)' -- '<s>'
  // Categorise the expected f64 by sign/class so Inf/NaN compare correctly
  // (NaN != NaN, so a value-equality table is insufficient).
  #[derive(Clone, Copy)]
  enum NonFinite {
    PosInf,
    NegInf,
    Nan,
    Finite(f64),
  }

  #[test]
  fn perl_str_to_f64_recognises_perl_nonfinite_spellings() {
    use NonFinite::{Finite, Nan, NegInf, PosInf};
    let cases: &[(&str, NonFinite)] = &[
      // Plain `inf`/`nan`, any case → Inf/NaN.
      ("inf", PosInf),
      ("Inf", PosInf),
      ("INF", PosInf),
      ("iNf", PosInf),
      ("nan", Nan),
      ("NaN", Nan),
      ("NAN", Nan),
      // Signs: `-inf` carries; NaN drops the sign.
      ("+inf", PosInf),
      ("-inf", NegInf),
      ("+nan", Nan),
      ("-nan", Nan),
      // Leading whitespace skipped, sign honoured.
      (" +inf", PosInf),
      (" -inf ", NegInf),
      (" nan ", Nan),
      // `infinity` word + any trailing tail (prefix match only).
      ("infinity", PosInf),
      ("Infinity", PosInf),
      ("INFINITY", PosInf),
      ("infinit", PosInf),
      ("infi", PosInf),
      ("infX", PosInf),
      ("infZZZ", PosInf),
      ("infinityandbeyond", PosInf),
      // `nan` + trailing tail (incl. the MSVCRT `nan(...)` payload).
      ("nanX", Nan),
      ("nan(123)", Nan),
      ("nanZZZ", Nan),
      // Leading junk is NOT a numeric prefix → 0 / digit-prefix.
      ("xinf", Finite(0.0)),
      ("Xnan", Finite(0.0)),
      ("12inf", Finite(12.0)),
      ("12nan", Finite(12.0)),
      ("1e3inf", Finite(1000.0)),
      // Partial keywords → 0.
      ("in", Finite(0.0)),
      ("i", Finite(0.0)),
      ("na", Finite(0.0)),
      ("n", Finite(0.0)),
      // Legacy MSVCRT `1.#…` forms.
      ("1.#INF", PosInf),
      ("1#INF", PosInf),
      ("1.#inf", PosInf),
      ("1.#INFINITY", PosInf),
      ("1.#INFX", PosInf),
      ("-1.#INF", NegInf),
      ("+1.#INF", PosInf),
      ("1.#IND", Nan),
      ("1.#NAN", Nan),
      ("1.#QNAN", Nan),
      ("1.#SNAN", Nan),
      ("1.#qnan", Nan),
      ("1.#INDX", Nan),
      // Non-qualifying `1.#…`: mantissa not exactly `1`, or incomplete keyword.
      ("1.0#INF", Finite(1.0)),
      ("01.#INF", Finite(1.0)),
      ("2.#INF", Finite(2.0)),
      ("0.#INF", Finite(0.0)),
      ("1.#IN", Finite(1.0)),
      ("1.#I", Finite(1.0)),
      ("#INF", Finite(0.0)),
    ];
    for &(s, want) in cases {
      let got = perl_str_to_f64(s);
      match want {
        PosInf => assert!(
          got.is_infinite() && got.is_sign_positive(),
          "perl_str_to_f64({s:?}) = {got}, want +Inf"
        ),
        NegInf => assert!(
          got.is_infinite() && got.is_sign_negative(),
          "perl_str_to_f64({s:?}) = {got}, want -Inf"
        ),
        Nan => assert!(got.is_nan(), "perl_str_to_f64({s:?}) = {got}, want NaN"),
        Finite(w) => assert!(
          (got - w).abs() < 1e-12 || (got == 0.0 && w == 0.0),
          "perl_str_to_f64({s:?}) = {got}, want {w}"
        ),
      }
    }
  }

  // ── Codex PR #32 R20/F1 — non-finite ConvertBitrate / ConvertDuration emit
  // Perl's titlecase `Inf`/`-Inf`/`NaN` (the `IsFloat or return` verbatim path
  // stringifies the NV with Perl's casing, NOT Rust's lowercase `{}`).
  // Oracle 2026-05-22: synthetic FLVs `audiodatarate="inf"` → "Inf",
  // `videodatarate="NaN"` → "NaN"; `ConvertBitrate(Inf*1000)` == "Inf".
  #[test]
  fn convert_bitrate_duration_nonfinite_use_perl_casing() {
    for (v, want) in [
      (f64::INFINITY, "Inf"),
      (f64::NEG_INFINITY, "-Inf"),
      (f64::NAN, "NaN"),
    ] {
      let mut br = std::string::String::new();
      write_convert_bitrate(&mut br, v).unwrap();
      assert_eq!(br, want, "write_convert_bitrate({v})");
      let mut du = std::string::String::new();
      write_convert_duration(&mut du, v).unwrap();
      assert_eq!(du, want, "write_convert_duration({v})");
    }
  }

  #[test]
  fn is_float_matches_exiftool_regex_and_comma_translation() {
    use std::borrow::Cow;
    // Matched, no translation (dot branch).
    for s in ["12.5", ".5", "3.", "+3", "1e3", "1E3", "-2.5"] {
      let (m, v) = is_float(s);
      assert!(m, "IsFloat({s:?}) should match");
      assert_eq!(v, Cow::Borrowed(s), "no translation for {s:?}");
    }
    // Matched, comma translated to dot (comma branch, Perl tr/,/./).
    assert_eq!(is_float("12,5"), (true, Cow::Owned("12.5".to_string())));
    assert_eq!(is_float(",5"), (true, Cow::Owned(".5".to_string())));
    // NOT matched (whitespace, hex, junk, multi-comma, dangling exponent).
    for s in [
      "  12.5", "12.5 ", "0x10", "12abc", "", "  ", "1e", "1,5,6", "inf", "nan",
    ] {
      let (m, _) = is_float(s);
      assert!(!m, "IsFloat({s:?}) should NOT match");
    }
  }

  #[test]
  fn write_convert_duration_str_honours_isfloat_guard() {
    fn dur(s: &str) -> String {
      let mut out = String::new();
      write_convert_duration_str(&mut out, s).unwrap();
      out
    }
    // Float-shaped strings coerce + format.
    assert_eq!(dur("1.5"), "1.50 s");
    assert_eq!(dur("2.25"), "2.25 s");
    assert_eq!(dur("12,5"), "12.50 s"); // comma-decimal via IsFloat translation
    assert_eq!(dur("1e3"), "0:16:40"); // 1000 s
    // Non-float strings returned VERBATIM (the IsFloat guard).
    assert_eq!(dur("notnum"), "notnum");
    assert_eq!(dur("65.8 kbps"), "65.8 kbps");
    assert_eq!(dur("  1.5"), "  1.5"); // leading ws ⇒ not IsFloat ⇒ verbatim
  }

  // ── PART A: float-path NV→UV unification (fixes residual 64-bit
  // corruption). Oracle: bundled Perl `Image::ExifTool::DecodeBits` via
  //   perl -I/Users/user/Develop/findit-studio/exiftool/lib -MImage::ExifTool \
  //        -e 'print Image::ExifTool::DecodeBits($ARGV[0],undef,64)' -- '<val>'
  // (outputs reproduced inline; re-verified 2026-05-19).

  #[test]
  fn decode_bits_float_path_high_uv_bits_exact() {
    // Perl NV→UV: "9223372036854775808.0" (2^63) ⇒ only bit 63.
    assert_eq!(
      decode_bits("9223372036854775808.0", Some(&[(63, "B63")]), 64),
      "B63"
    );
    assert_eq!(decode_bits("9223372036854775808.0", None, 64), "63");
    // "1e19" = 10000000000000000000 = 0x8AC7230489E80000.
    assert_eq!(
      decode_bits("1e19", None, 64),
      "19,21,22,23,24,27,31,34,40,41,45,48,49,50,54,55,57,59,63"
    );
    // "18446744073709551615.0" rounds (NV and f64 alike) to 2^64 ⇒
    // Perl (UV) ⇒ all 64 bits.
    let all = (0..64).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(decode_bits("18446744073709551615.0", None, 64), all);
  }

  #[test]
  fn decode_bits_float_path_no_regression() {
    // Negative + small non-negative floats already matched Perl — unchanged.
    // "-2.9" ⇒ -2 ⇒ 0xFFFF…FFFE ⇒ bits 1..63 (bit 0 unset).
    let one_to_63 = (1..64).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(decode_bits("-2.9", None, 64), one_to_63);
    assert_eq!(decode_bits("2.9", None, 64), "1"); // 2 ⇒ bit 1
    assert_eq!(decode_bits("1e3", None, 64), "3,5,6,7,8,9"); // 1000
    assert_eq!(perl_numeric_coerce("2.9"), 2);
    assert_eq!(perl_numeric_coerce("-2.9"), (-2i64) as u64);
  }

  #[test]
  fn decode_bits_non_finite_exponent_overflow_faithful() {
    // Perl (UV)+Inf = u64::MAX ⇒ all 64 bits; (UV)-Inf = i64::MIN as u64
    // ⇒ bit 63 only. Oracle-verified vs bundled ExifTool DecodeBits.
    let all = (0..64).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(decode_bits("1e309", None, 64), all); // +inf
    assert_eq!(decode_bits("9e999", None, 64), all); // +inf
    assert_eq!(decode_bits("1e400", None, 64), all); // +inf
    assert_eq!(decode_bits("-1e309", None, 64), "63"); // -inf
    assert_eq!(decode_bits("-9e999", None, 64), "63"); // -inf
  }

  #[test]
  fn decode_bits_finite_huge_unchanged_regression() {
    // Already faithful before the fix — pin so the change is zero-regression.
    // "1e308": finite, (UV) saturates u64::MAX. "-1e308": saturates i64::MIN.
    let all = (0..64).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    assert_eq!(decode_bits("1e308", None, 64), all);
    assert_eq!(decode_bits("-1e308", None, 64), "63");
    // Pre-existing small/float vectors must still hold.
    assert_eq!(decode_bits("2.9", None, 64), "1");
    assert_eq!(decode_bits("1e3", None, 64), "3,5,6,7,8,9");
  }

  // ExifTool.pm:3578-3582 — the conversion loop iterates list elements for
  // the ACTIVE stage (ValueConv as well as PrintConv). `apply` must recurse
  // element-wise so a scalar ValueConv::Func / ValueConv::Hash never sees
  // a `TagValue::List` as its raw scalar input.

  fn plus_one(v: &TagValue) -> TagValue {
    match v {
      TagValue::I64(n) => TagValue::I64(n + 1),
      x => x.clone(),
    }
  }

  static VC_FUNC_NO_PC: TagDef =
    TagDef::new("VCFunc", "X", ValueConv::Func(plus_one), PrintConv::None);

  #[test]
  fn apply_value_conv_func_is_element_wise_over_list() {
    // -n mode (PrintConv off): scalar ValueConv must be applied to each
    // element of a `List`, not to the list as a whole. Pre-fix the scalar
    // `plus_one` would see `TagValue::List(...)` (its `_` arm clones) and
    // return the list unchanged — a silent shape bug.
    let list = TagValue::List(vec![TagValue::I64(1), TagValue::I64(2), TagValue::I64(3)]);
    let out = apply(&VC_FUNC_NO_PC, &list, false);
    assert_eq!(
      out,
      TagValue::List(vec![TagValue::I64(2), TagValue::I64(3), TagValue::I64(4)])
    );
  }

  static VC_HASH_THEN_PC_HASH: TagDef = TagDef::new(
    "VCThenPC",
    "X",
    ValueConv::Hash(PrintConvHash::direct(&[
      ("1", PrintValue::I64(10)),
      ("2", PrintValue::I64(20)),
      ("3", PrintValue::I64(30)),
    ])),
    PrintConv::Hash(PrintConvHash::direct(&[
      ("10", PrintValue::Str("A")),
      ("20", PrintValue::Str("B")),
      ("30", PrintValue::Str("C")),
    ])),
  );

  #[test]
  fn apply_value_conv_hash_then_print_conv_is_element_wise_over_list() {
    // Both stages per element: ValueConv::Hash maps 1→10/2→20/3→30, then
    // PrintConv::Hash maps 10→"A"/20→"B"/30→"C". Mirrors ExifTool's
    // GetValue+ConvertValue running once per scalar element of `@$value`.
    let list = TagValue::List(vec![TagValue::I64(1), TagValue::I64(2), TagValue::I64(3)]);
    let out = apply(&VC_HASH_THEN_PC_HASH, &list, true);
    assert_eq!(
      out,
      TagValue::List(vec![
        TagValue::Str("A".into()),
        TagValue::Str("B".into()),
        TagValue::Str("C".into()),
      ])
    );
  }

  // ── read_value: faithful `ReadValue` (ExifTool.pm:6275-6321) over the
  // Red.pm format-coverage subset.

  #[test]
  fn read_value_int8u_scalar_and_array() {
    // count == 1 ⇒ typed `I64` scalar (`Get8u`, ExifTool.pm:6069).
    let buf = [0x05u8, 0x00, 0xff, 0x10];
    assert_eq!(
      read_value(&buf, 0, "int8u", 1, ByteOrder::Mm),
      Some(TagValue::I64(5))
    );
    // count > 1 ⇒ Perl `join(' ', @vals)` (ExifTool.pm:6319) — a single
    // space-joined `TagValue::Str`, NOT a `List`. Faithful to Red.pm tags
    // like CropArea (int16u[4]) which appear as "0 0 5120 2560".
    assert_eq!(
      read_value(&buf, 0, "int8u", 4, ByteOrder::Mm),
      Some(TagValue::Str("5 0 255 16".into()))
    );
  }

  // ---- D11 conversion-context API (spec §11.2) ----

  #[test]
  fn conv_context_default_is_latin() {
    // Default `CharsetID3 => 'Latin'` (ExifTool.pm:1118).
    let ctx = ConvContext::default();
    assert_eq!(ctx.charset_id3(), "Latin");
  }

  #[test]
  fn conv_context_with_charset_id3_override() {
    // `with_charset_id3` is the D8 builder shape — `const fn` so it
    // composes into a `static` if a port ever needs it.
    let ctx = ConvContext::default().with_charset_id3("UTF8");
    assert_eq!(ctx.charset_id3(), "UTF8");
  }

  /// First-consumer-shaped: an ID3v1::Title-style ValueConv that reads
  /// `ctx.charset_id3()` and returns a value derived from it. Proves the
  /// `FuncCtx` plumbing routes the context through `apply_ctx` correctly.
  fn fake_id3v1_text_conv(raw: &TagValue, ctx: &ConvContext) -> TagValue {
    let bytes = match raw {
      TagValue::Str(s) => s.as_bytes(),
      _ => return raw.clone(),
    };
    // Stand-in: emit the charset tag so the test sees which ctx was used.
    let s = format!("[{}]{}", ctx.charset_id3(), String::from_utf8_lossy(bytes));
    TagValue::Str(s.into())
  }

  static D11_VC_FUNCCTX: TagDef = TagDef::new(
    "Title",
    "ID3v1",
    ValueConv::FuncCtx(fake_id3v1_text_conv),
    PrintConv::None,
  );

  #[test]
  fn apply_ctx_routes_value_conv_funcctx() {
    // Default ctx (Latin), then an override; both reach the FuncCtx fn.
    assert_eq!(
      apply_ctx(
        &D11_VC_FUNCCTX,
        &TagValue::Str("hi".into()),
        true,
        &ConvContext::default()
      ),
      TagValue::Str("[Latin]hi".into())
    );
    assert_eq!(
      apply_ctx(
        &D11_VC_FUNCCTX,
        &TagValue::Str("hi".into()),
        true,
        &ConvContext::new("UTF8")
      ),
      TagValue::Str("[UTF8]hi".into())
    );
  }

  #[test]
  fn read_value_int8s_signed() {
    // `Get8s` (ExifTool.pm:6068) ⇒ `0xff` reads as `-1`.
    let buf = [0xffu8, 0x7f, 0x80];
    assert_eq!(
      read_value(&buf, 0, "int8s", 1, ByteOrder::Mm),
      Some(TagValue::I64(-1))
    );
    assert_eq!(
      read_value(&buf, 1, "int8s", 1, ByteOrder::Mm),
      Some(TagValue::I64(127))
    );
    assert_eq!(
      read_value(&buf, 2, "int8s", 1, ByteOrder::Mm),
      Some(TagValue::I64(-128))
    );
  }

  #[test]
  fn read_value_int16u_be_le() {
    // `Get16u`/`SetByteOrder` (ExifTool.pm:6071,6149-6190) ⇒ MM=big, II=little.
    let buf = [0x14u8, 0x00];
    assert_eq!(
      read_value(&buf, 0, "int16u", 1, ByteOrder::Mm),
      Some(TagValue::I64(0x1400))
    );
    assert_eq!(
      read_value(&buf, 0, "int16u", 1, ByteOrder::Ii),
      Some(TagValue::I64(0x0014))
    );
  }

  #[test]
  fn read_value_int32u_int32s() {
    // 0x12345678 BE ⇒ 305419896u32 ; 0xfffffffe BE as int32s ⇒ -2.
    let buf = [0x12u8, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xfe];
    assert_eq!(
      read_value(&buf, 0, "int32u", 1, ByteOrder::Mm),
      Some(TagValue::I64(0x12345678))
    );
    assert_eq!(
      read_value(&buf, 4, "int32s", 1, ByteOrder::Mm),
      Some(TagValue::I64(-2))
    );
  }

  #[test]
  fn read_value_string_truncates_at_nul() {
    // ExifTool.pm:6300 `$vals[0] =~ s/\0.*//s if $format eq 'string'`.
    let buf = b"hello\0extra";
    assert_eq!(
      read_value(buf, 0, "string", buf.len(), ByteOrder::Mm),
      Some(TagValue::Str("hello".into()))
    );
    // No NUL ⇒ keep full slice.
    let buf2 = b"abc";
    assert_eq!(
      read_value(buf2, 0, "string", 3, ByteOrder::Mm),
      Some(TagValue::Str("abc".into()))
    );
  }

  #[test]
  fn fix_utf8_passes_valid_strings_through_verbatim() {
    // Pure ASCII.
    assert_eq!(fix_utf8(b"hello"), "hello");
    // Valid multi-byte UTF-8 (é = \xC3\xA9, 日本 = \xE6\x97\xA5\xE6\x9C\xAC,
    // 🦀 = \xF0\x9F\xA6\x80).
    assert_eq!(fix_utf8("héllo".as_bytes()), "héllo");
    assert_eq!(fix_utf8("日本".as_bytes()), "日本");
    assert_eq!(fix_utf8("🦀".as_bytes()), "🦀");
    // Mixed.
    assert_eq!(fix_utf8("a日b🦀c".as_bytes()), "a日b🦀c");
    // Empty.
    assert_eq!(fix_utf8(b""), "");
  }

  #[test]
  fn fix_utf8_replaces_invalid_bytes_with_question_mark() {
    // **Codex round-9 F1 oracle:** `Image::ExifTool::XMP::FixUTF8` runs
    // at JSON serialize-time and replaces each invalid UTF-8 byte with
    // the literal ASCII byte `?` (XMP.pm:2949-2972 default `$bad='?'`).
    //
    //   perl -e 'use Image::ExifTool::XMP;
    //            my $s = "A\xff.R3D";
    //            Image::ExifTool::XMP::FixUTF8(\$s);
    //            print "$s\n"'   ⇒ "A?.R3D"
    let mut buf = b"A\xff.R3D".to_vec();
    let r = fix_utf8(&buf);
    assert_eq!(r, "A?.R3D");
    // Lone continuation byte (0x80-0xBF without a leader) — invalid.
    buf = b"A\x80B".to_vec();
    assert_eq!(fix_utf8(&buf), "A?B");
    // Overlong 2-byte sequence: 0xC0 0x80 (would encode NUL).
    // `0xC0` is < 0xC2 ⇒ not a valid leader ⇒ replaced with `?`,
    // then `0x80` is a lone continuation ⇒ also replaced.
    buf = b"A\xC0\x80B".to_vec();
    assert_eq!(fix_utf8(&buf), "A??B");
    // 4-byte sequence beyond U+10FFFF: 0xF5 0x80 0x80 0x80.
    // Leader 0xF5 is > 0xF4 ⇒ out-of-range ⇒ replaced with `?`, then
    // three lone continuations each replaced.
    buf = b"A\xF5\x80\x80\x80B".to_vec();
    assert_eq!(fix_utf8(&buf), "A????B");
    // Truncated 3-byte sequence: leader 0xE6 (Japanese leader) +
    // single continuation, missing the second continuation.
    buf = b"A\xE6\x97B".to_vec();
    // Both bytes (leader + one continuation) are invalid as standalone
    // sequence: leader needs 2 continuations, only 1 follows.
    // XMP.pm's regex `[\x80-\xbf]{2}` would fail ⇒ leader replaced with
    // `?`, then `0x97` is a lone continuation ⇒ also replaced.
    assert_eq!(fix_utf8(&buf), "A??B");
  }

  #[test]
  fn fix_utf8_rejects_bmp_non_characters_u_fffe_and_u_ffff() {
    // **Codex round-10 F1:** Rust's `std::str::from_utf8` ACCEPTS U+FFFE
    // and U+FFFF (they are valid in the Unicode codespace but flagged
    // as "non-characters" by Unicode). ExifTool's `FixUTF8` REJECTS
    // them via the explicit chain at XMP.pm:2960-2961
    // (`ord($1) == 0xbf and (ord(substr $1, 1) & 0xfe) == 0xbe`).
    // The fix_utf8 fast path was removed so the byte-walker can apply
    // these rules.
    //
    // Bundled-Perl oracle:
    //   "A\xEF\xBF\xBEB" (U+FFFE) ⇒ "A???B" (3 bytes each ⇒ `?`)
    //   "A\xEF\xBF\xBFB" (U+FFFF) ⇒ "A???B"
    //   "A\xEF\xBF\xBDB" (U+FFFD replacement char) ⇒ unchanged (BD ≠ BE/BF)
    //   "A\xEF\xBF\xACB" (U+FFEC random kanji punctuation) ⇒ unchanged
    assert_eq!(fix_utf8(b"A\xEF\xBF\xBEB"), "A???B");
    assert_eq!(fix_utf8(b"A\xEF\xBF\xBFB"), "A???B");
    // The replacement character U+FFFD is NOT a non-character and
    // passes through verbatim.
    let fffd_bytes = b"A\xEF\xBF\xBDB";
    assert_eq!(fix_utf8(fffd_bytes).as_bytes(), fffd_bytes);
    // U+FFEC (random valid BMP char) — passes through.
    let ffec_bytes = b"A\xEF\xBF\xACB";
    assert_eq!(fix_utf8(ffec_bytes).as_bytes(), ffec_bytes);
  }

  #[test]
  fn read_value_string_non_character_emits_fixutf8_question_mark() {
    // Codex round-10 F1: integration through `read_value` — a Red
    // `string` payload containing U+FFFE/U+FFFF must emit the
    // ExifTool-matching `?` substitution, not preserve the
    // non-character.
    let buf = b"A\xEF\xBF\xBEB";
    assert_eq!(
      read_value(buf, 0, "string", buf.len(), ByteOrder::Mm),
      Some(TagValue::Str("A???B".into()))
    );
    let buf2 = b"A\xEF\xBF\xBFB";
    assert_eq!(
      read_value(buf2, 0, "string", buf2.len(), ByteOrder::Mm),
      Some(TagValue::Str("A???B".into()))
    );
  }

  #[test]
  fn read_value_string_invalid_utf8_emits_fixutf8_question_mark() {
    // Codex round-9 F1: `read_value` routes through `fix_utf8` so a
    // bad-byte payload produces ExifTool-matching `A?.R3D`, not the
    // `from_utf8_lossy` `A\u{FFFD}.R3D`.
    let buf = b"A\xff.R3D";
    assert_eq!(
      read_value(buf, 0, "string", buf.len(), ByteOrder::Mm),
      Some(TagValue::Str("A?.R3D".into()))
    );
    // Truncate at NUL still applies before FixUTF8.
    let buf2 = b"A\xff\0extra";
    assert_eq!(
      read_value(buf2, 0, "string", buf2.len(), ByteOrder::Mm),
      Some(TagValue::Str("A?".into()))
    );
  }

  #[test]
  fn read_value_undef_returns_raw_bytes() {
    // ExifTool.pm:6298 (no `undef` entry in `%readValueProc` ⇒ raw substr).
    let buf = [0x00u8, 0xff, 0x10];
    assert_eq!(
      read_value(&buf, 0, "undef", 3, ByteOrder::Mm),
      Some(TagValue::Bytes(vec![0x00, 0xff, 0x10]))
    );
  }

  #[test]
  fn read_value_float_be_le() {
    // 1.0 (IEEE-754 single) = 0x3F800000.
    let be = [0x3fu8, 0x80, 0x00, 0x00];
    assert_eq!(
      read_value(&be, 0, "float", 1, ByteOrder::Mm),
      Some(TagValue::F64(1.0))
    );
    let le = [0x00u8, 0x00, 0x80, 0x3f];
    assert_eq!(
      read_value(&le, 0, "float", 1, ByteOrder::Ii),
      Some(TagValue::F64(1.0))
    );
  }

  #[test]
  fn read_value_float_array_joins_with_space() {
    // Two BE float32s: 0.25 (0x3e800000) and 0.5 (0x3f000000) ⇒ "0.25 0.5".
    let buf = [0x3eu8, 0x80, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00];
    assert_eq!(
      read_value(&buf, 0, "float", 2, ByteOrder::Mm),
      Some(TagValue::Str("0.25 0.5".into()))
    );
  }

  #[test]
  fn read_value_rational32u_be() {
    // num=1, denom=3 (BE int16u pairs) ⇒ `Rational::rational32(1,3)`,
    // which `exiftool_val_str` renders as `0.3333333` (%.7g, ExifTool.pm:6087).
    let buf = [0x00u8, 0x01, 0x00, 0x03];
    let v = read_value(&buf, 0, "rational32u", 1, ByteOrder::Mm).expect("rational32u should parse");
    match v {
      TagValue::Rational(r) => {
        assert_eq!(r.numerator(), 1);
        assert_eq!(r.denominator(), 3);
        assert_eq!(r.sig(), 7);
        assert_eq!(r.exiftool_val_str(), "0.3333333");
      }
      other => panic!("expected Rational, got {other:?}"),
    }
  }

  #[test]
  fn read_value_rational32u_zero_denom_inf_undef() {
    // ExifTool.pm:6094 `$ratDenom = Get16u(...) or return $ratNumer ? 'inf'
    // : 'undef'` — `Rational::exiftool_val_str` is the SHARED source of
    // truth: `inf` for numerator ≠ 0, `undef` for numerator == 0.
    let inf = [0x00u8, 0x05, 0x00, 0x00]; // num=5, denom=0
    let v_inf = read_value(&inf, 0, "rational32u", 1, ByteOrder::Mm).unwrap();
    assert_eq!(v_inf.unwrap_rational().exiftool_val_str(), "inf");
    let undef = [0x00u8, 0x00, 0x00, 0x00]; // num=0, denom=0
    let v_undef = read_value(&undef, 0, "rational32u", 1, ByteOrder::Mm).unwrap();
    assert_eq!(v_undef.unwrap_rational().exiftool_val_str(), "undef");
  }

  #[test]
  fn read_value_out_of_bounds_returns_none() {
    // ExifTool.pm:6290-6292 — when `$len * $count > $size`, count is shortened
    // to `int($size / $len)`; if the shortened count is < 1, return undef.
    // A 2-byte buffer asked for a single int32u shortens to count=0 ⇒ None.
    let buf = [0x01u8, 0x02];
    assert_eq!(read_value(&buf, 0, "int32u", 1, ByteOrder::Mm), None);
    // Offset past end ⇒ size underflows ⇒ None (no panic, faithful to
    // ExifTool.pm:6284 `length($$dataPt) - $offset`).
    assert_eq!(read_value(&buf, 99, "int8u", 1, ByteOrder::Mm), None);
  }

  #[test]
  fn read_value_shortens_count_when_buffer_truncates_array() {
    // Codex round-1 F2 (Red.pm RED2 FrameRate `int16u[3]` at 0x56): a header
    // that ends with only 4 bytes at the field offset should yield a 2-element
    // scalar "1001 0", and with only 2 bytes a single scalar "1001"; not
    // dropped. Cross-checked against bundled Perl:
    //   perl -MImage::ExifTool=:DataAccess -e '
    //     my $b = pack("nn", 1001, 0);
    //     print Image::ExifTool::ReadValue(\$b, 0, "int16u", 3, length($b))'
    //   => "1001 0"
    //   perl -MImage::ExifTool=:DataAccess -e '
    //     my $b = pack("n", 1001);
    //     print Image::ExifTool::ReadValue(\$b, 0, "int16u", 3, length($b))'
    //   => "1001"
    let four_bytes = [0x03u8, 0xe9, 0x00, 0x00]; // 1001, 0
    let v = read_value(&four_bytes, 0, "int16u", 3, ByteOrder::Mm)
      .expect("shortened to count=2, must emit");
    assert_eq!(v, TagValue::Str("1001 0".into()));
    let two_bytes = [0x03u8, 0xe9]; // 1001
    let v2 = read_value(&two_bytes, 0, "int16u", 3, ByteOrder::Mm)
      .expect("shortened to count=1, must emit");
    // count==1 ⇒ typed scalar (mirroring Perl's `wantarray ? @vals : @vals==1
    // ? $vals[0] : join ' ', @vals`, ExifTool.pm:6318-6320).
    assert_eq!(v2, TagValue::I64(1001));
    // 1 byte for int16u[3] ⇒ shortened to 0 elements ⇒ undef (None).
    let one_byte = [0xaau8];
    assert_eq!(read_value(&one_byte, 0, "int16u", 3, ByteOrder::Mm), None);
  }

  #[test]
  fn read_value_string_clamps_count_to_available_bytes() {
    // ExifTool.pm:6298 `substr($$dataPt, $offset, $count * $len)`: with the
    // count-shortening rule, asking for a 32-char string against a 10-byte
    // buffer yields the 10 bytes (truncated at NUL if present). Bundled Perl:
    //   perl -MImage::ExifTool=:DataAccess -e '
    //     my $b = "HELLO\0BYE"; print Image::ExifTool::ReadValue(
    //       \$b, 0, "string", 32, length($b))' => "HELLO"
    let buf = b"HELLO\0BYE";
    let v =
      read_value(buf, 0, "string", 32, ByteOrder::Mm).expect("string clamped to buffer, must emit");
    assert_eq!(v, TagValue::Str("HELLO".into()));
    // No NUL ⇒ entire (shortened) slice is the value.
    let raw = b"ABCD";
    let v2 = read_value(raw, 0, "string", 16, ByteOrder::Mm).expect("string clamped, must emit");
    assert_eq!(v2, TagValue::Str("ABCD".into()));
  }

  #[test]
  fn read_value_unknown_format_returns_none() {
    // ExifTool warns "Unknown format" (ExifTool.pm:6281) then proceeds with
    // $len=1. We return None instead — the caller (Red.pm:282 unknown
    // format-code path) emits its own Warning and aborts the directory walk,
    // so the engine never reaches a fake $len=1 read. Same incremental-
    // derivation discipline: future formats add their own arms as needed.
    let buf = [0u8; 16];
    assert_eq!(read_value(&buf, 0, "double", 1, ByteOrder::Mm), None);
    assert_eq!(read_value(&buf, 0, "binary", 1, ByteOrder::Mm), None);
    assert_eq!(read_value(&buf, 0, "garbage", 1, ByteOrder::Mm), None);
  }

  #[test]
  fn apply_thin_wraps_apply_ctx_with_default() {
    // `apply` must be a behavior-identical thin wrapper for default ctx —
    // any FuncCtx invoked via `apply` sees the Latin default.
    assert_eq!(
      apply(&D11_VC_FUNCCTX, &TagValue::Str("hi".into()), true),
      TagValue::Str("[Latin]hi".into())
    );
  }

  fn fake_printctx(v: &TagValue, ctx: &ConvContext) -> TagValue {
    match v {
      TagValue::Str(s) => TagValue::Str(format!("{}::{}", ctx.charset_id3(), s).into()),
      x => x.clone(),
    }
  }
  static D11_PC_FUNCCTX: TagDef = TagDef::new(
    "T",
    "ID3v1",
    ValueConv::None,
    PrintConv::FuncCtx(fake_printctx),
  );

  #[test]
  fn apply_ctx_routes_print_conv_funcctx() {
    assert_eq!(
      apply_ctx(
        &D11_PC_FUNCCTX,
        &TagValue::Str("x".into()),
        true,
        &ConvContext::new("ZZ")
      ),
      TagValue::Str("ZZ::x".into())
    );
    // -n mode (PrintConv off): the FuncCtx must NOT run; raw passes through.
    assert_eq!(
      apply_ctx(
        &D11_PC_FUNCCTX,
        &TagValue::Str("x".into()),
        false,
        &ConvContext::new("ZZ")
      ),
      TagValue::Str("x".into())
    );
  }

  #[test]
  fn apply_ctx_funcctx_is_element_wise_over_list() {
    // ExifTool.pm:3578-3582 — every element runs through the conv. The list
    // arm recursion in `apply_ctx` must thread `ctx` through every element.
    let list = TagValue::List(vec![TagValue::Str("a".into()), TagValue::Str("b".into())]);
    let out = apply_ctx(&D11_VC_FUNCCTX, &list, true, &ConvContext::new("Latin"));
    assert_eq!(
      out,
      TagValue::List(vec![
        TagValue::Str("[Latin]a".into()),
        TagValue::Str("[Latin]b".into()),
      ])
    );
  }

  // ---------- Audible-port FixUTF8 / pack_c0u tests --------------------------
  // Empirical reference column ("Perl" below) generated by running
  //   perl -I.../exiftool/lib -e 'use Image::ExifTool::XMP;
  //     my $s = ...; Image::ExifTool::XMP::FixUTF8(\$s); print $s;'
  // against the bundled ExifTool oracle (Audible PR #12 R4 investigation).

  #[test]
  fn fix_utf8_rejects_overlong_3byte_and_surrogates() {
    // Overlong 3-byte: 0xE0 + cont < 0xA0 (e.g. e0 80 80 encodes U+0000).
    // Perl rejects (XMP.pm:2958).
    assert_eq!(fix_utf8(b"\xe0\x80\x80"), "???");
    // Surrogate U+D800 = ed a0 80 — Perl rejects (XMP.pm:2959).
    assert_eq!(fix_utf8(b"X\xed\xa0\x80Y"), "X???Y");
    // Surrogate U+DFFF = ed bf bf — rejected.
    assert_eq!(fix_utf8(b"\xed\xbf\xbf"), "???");
    // Adjacent BMP noncharacter U+FDD0..U+FDEF — NOT rejected (FixUTF8
    // only catches U+FFFE/U+FFFF in the noncharacter range; faithful).
    assert_eq!(fix_utf8(b"\xef\xb7\x90"), "\u{fdd0}");
  }

  #[test]
  fn fix_utf8_rejects_overlong_4byte_and_above_u10ffff() {
    // Overlong 4-byte: 0xF0 + cont < 0x90 (encodes < U+10000). Rejected
    // (XMP.pm:2963).
    assert_eq!(fix_utf8(b"\xf0\x80\x80\x80"), "????");
    // > U+10FFFF: 0xF4 + cont > 0x8F. Rejected (XMP.pm:2964).
    assert_eq!(fix_utf8(b"\xf4\x90\x80\x80"), "????");
    // $ch > 0xF4 (0xF5..=0xF7) — always rejected.
    assert_eq!(fix_utf8(b"\xf5\x80\x80\x80"), "????");
    // Boundary: U+10FFFF = f4 8f bf bf — KEPT.
    assert_eq!(fix_utf8(b"\xf4\x8f\xbf\xbf"), "\u{10ffff}");
  }

  #[test]
  fn fix_utf8_truncated_continuation_each_byte_replaced() {
    // 0xC2 (2-byte lead) but no continuation: one `?`.
    assert_eq!(fix_utf8(b"\xc2"), "?");
    // 0xE0 + 0xA0 but missing third byte: each invalid byte ⇒ `?`.
    // Perl: scans byte by byte after the failed match.
    assert_eq!(fix_utf8(b"\xe0\xa0"), "??");
    // Multi-byte lead followed by ASCII (continuation pattern fails).
    assert_eq!(fix_utf8(b"\xe2A"), "?A");
  }

  #[test]
  fn pack_c0u_perl_pack_c0u_byte_exact() {
    // Empirical reference (Perl `pack('C0U', $n)`):
    //   n=0x7f                -> [7f]                       (1 byte)
    //   n=0x80                -> [c2 80]                    (2 bytes)
    //   n=0xa0                -> [c2 a0]
    //   n=0xff                -> [c3 bf]
    //   n=0xd800              -> [ed a0 80]                 (surrogate, 3 bytes invalid)
    //   n=0xfffe              -> [ef bf be]                 (noncharacter)
    //   n=0xffff              -> [ef bf bf]
    //   n=0x10000             -> [f0 90 80 80]              (4 bytes)
    //   n=0x10ffff            -> [f4 8f bf bf]              (max valid)
    //   n=0x110000            -> [f4 90 80 80]              (above max, FixUTF8 will reject)
    //   n=0x7fffffff          -> [fd bf bf bf bf bf]        (6 bytes)
    //   n=0x80000000          -> [fe 82 80 80 80 80 80]     (7 bytes)
    //   n=0xffffffff          -> [fe 83 bf bf bf bf bf]
    //   n=0x100000000         -> [fe 84 80 80 80 80 80]     (R5: 7-byte form extends past u32)
    //   n=0xfffffffff         -> [fe bf bf bf bf bf bf]     (R5: top of 7-byte range)
    //   n=0x1000000000        -> [ff 80 80 80 80 80 81 80 80 80 80 80 80] (R5: 13-byte form begins)
    //   n=0x7fffffffffffffff  -> [ff 80 87 bf bf bf bf bf bf bf bf bf bf] (Perl pack max)
    let mut out = Vec::new();
    let cases: &[(u64, &[u8])] = &[
      (0x7F, &[0x7F]),
      (0x80, &[0xC2, 0x80]),
      (0xA0, &[0xC2, 0xA0]),
      (0xFF, &[0xC3, 0xBF]),
      (0xD800, &[0xED, 0xA0, 0x80]),
      (0xFFFE, &[0xEF, 0xBF, 0xBE]),
      (0xFFFF, &[0xEF, 0xBF, 0xBF]),
      (0x10000, &[0xF0, 0x90, 0x80, 0x80]),
      (0x10FFFF, &[0xF4, 0x8F, 0xBF, 0xBF]),
      (0x110000, &[0xF4, 0x90, 0x80, 0x80]),
      (0x7FFFFFFF, &[0xFD, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF]),
      (0x80000000, &[0xFE, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80]),
      (0xFFFFFFFF, &[0xFE, 0x83, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF]),
      // R5 additions — empirically verified vs bundled Perl `pack('C0U', $n)`.
      (0x1_0000_0000, &[0xFE, 0x84, 0x80, 0x80, 0x80, 0x80, 0x80]),
      (0xF_FFFF_FFFF, &[0xFE, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF]),
      (
        0x10_0000_0000,
        &[
          0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ],
      ),
      (
        0x7FFF_FFFF_FFFF_FFFF,
        &[
          0xFF, 0x80, 0x87, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF,
        ],
      ),
    ];
    for (n, expected) in cases {
      out.clear();
      pack_c0u(*n, &mut out);
      assert_eq!(&out[..], *expected, "pack_c0u(0x{n:x}) mismatch");
    }
  }

  #[test]
  fn fix_utf8_after_pack_c0u_matches_perl_pipeline() {
    // End-to-end: simulate UnescapeChar(numeric entity) → pack_c0u → FixUTF8,
    // i.e. the byte path Audible.pm:243-261 takes for `&#xN;` entities.
    // Empirically verified vs bundled Perl ExifTool (R4 + R5 investigation).
    let pipeline = |n: u64| -> String {
      let mut buf = Vec::new();
      pack_c0u(n, &mut buf);
      fix_utf8(&buf)
    };
    assert_eq!(pipeline(0x7F), "\u{7f}"); // DEL is valid ASCII
    assert_eq!(pipeline(0x80), "\u{80}"); // Latin-1 PAD via valid 2-byte
    assert_eq!(pipeline(0xD800), "???"); // surrogate ⇒ 3 `?`s
    assert_eq!(pipeline(0xFFFE), "???"); // noncharacter ⇒ 3 `?`s
    assert_eq!(pipeline(0x10FFFF), "\u{10ffff}"); // max valid kept
    assert_eq!(pipeline(0x110000), "????"); // > U+10FFFF ⇒ 4 `?`s
    // R5 additions — Perl-empirical (`pack('C0U', n)` → `FixUTF8`):
    assert_eq!(pipeline(0x1_0000_0000), "???????"); // 7 `?`s (above-u32 7-byte)
    assert_eq!(pipeline(0xF_FFFF_FFFF), "???????"); // 7 `?`s (top of 7-byte range)
    assert_eq!(pipeline(0x10_0000_0000), "?????????????"); // 13 `?`s (13-byte form)
    assert_eq!(pipeline(0x7FFF_FFFF_FFFF_FFFF), "?????????????"); // 13 `?`s (Perl max)
  }
}
