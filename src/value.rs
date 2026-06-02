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
}

impl Group {
  /// Construct a group from two string-ish values.
  #[must_use]
  #[inline(always)]
  pub fn new(family0: impl Into<SmolStr>, family1: impl Into<SmolStr>) -> Self {
    Self {
      family0: family0.into(),
      family1: family1.into(),
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
// DESIGN: we emit STANDARD `serde_json` scalars and do NOT reproduce ExifTool's
// `sprintf` token style — the value-semantic [`crate::jsondiff`] comparator
// treats a different valid spelling of the same value as equal (`"123"==123`,
// `0.0==0.00000000`). So a numeric-looking `Str` is serialized as a plain JSON
// string (the comparator coerces it), a finite `f64` via `serialize_f64`
// (ryu shortest round-trip), and a large `u64` via `serialize_u64` (full
// value). The only value-shaping needed is for the variants whose JSON VALUE
// (not token) is special: `Bytes` -> the binary placeholder string; non-finite
// `f64` -> the titlecase `Inf`/`-Inf`/`NaN` string (serde_json errors on a
// non-finite number) AND `%.15g`-rounded for a finite float (ExifTool's default
// NV stringification — a VALUE difference, not token style); `Rational` -> its
// ExifTool-rounded numeric value (or the `inf`/`undef` word); a `"true"`/
// `"false"` string -> a bare JSON boolean (`exiftool:3804-3805`). These mirror
// the rules the retired hand-rolled encoder applied, VALUE-faithfully.
// ===========================================================================

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
const _: () = {
  use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

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
        TagValue::I64(n) => s.serialize_i64(*n),
        // Full unsigned value (no saturation to i64::MAX); the comparator
        // keeps huge integers exact.
        TagValue::U64(n) => s.serialize_u64(*n),
        TagValue::F64(n) => {
          if n.is_finite() {
            // ExifTool stringifies a float with `%.15g` (its default NV
            // stringification, `ExifTool.pm` RoundFloat / the JSON writer), so
            // the GOLDEN value is the 15-sig-fig rounding of the true f64 —
            // e.g. 2.639229024943311 -> 2.63922902494331. This is a VALUE
            // difference, not token style: emit the rounded value (round via
            // `format_g(_,15)` then re-parse, so serde's number equals the
            // golden's rounded number). The raw f64 would be a DIFFERENT value
            // and fail the value-semantic gate.
            let rounded = format_g(*n, 15);
            match rounded.parse::<f64>() {
              Ok(f) => s.serialize_f64(f),
              // `format_g` always yields a parseable decimal for a finite f64;
              // fall back to the raw value defensively.
              Err(_) => s.serialize_f64(*n),
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
        // Otherwise STANDARD string emission: a numeric-looking value (e.g. a
        // `"3.5"` PrintConv) stays a JSON string; the value-semantic comparator
        // coerces it to the bare number the golden carries.
        TagValue::Str(text) => s.serialize_str(text),
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
}
