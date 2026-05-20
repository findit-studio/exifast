//! Runs a raw value through a `TagDef`'s ValueConv then PrintConv, producing
//! the value that appears in `-j` output (PrintConv on) — ExifTool's pipeline.

use crate::{
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, ValueConv},
  value::{format_g, TagValue},
};
use smol_str::SmolStr;

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

/// Apply ValueConv then PrintConv. `print_conv_enabled` mirrors ExifTool's
/// `-n` switch: when `false`, the post-ValueConv value is returned (the `-n`
/// golden), matching spec §4's two snapshots.
pub fn apply(def: &TagDef, raw: &TagValue, print_conv_enabled: bool) -> TagValue {
  // ExifTool.pm:3578-3582 — the conversion loop iterates list elements for
  // the active stage, applying the current conv per scalar `$val`. Recurse
  // once at the top so BOTH ValueConv and PrintConv run element-wise; nested
  // lists terminate because each recursion drops one level of nesting.
  if let TagValue::List(items) = raw {
    return TagValue::List(
      items
        .iter()
        .map(|it| apply(def, it, print_conv_enabled))
        .collect(),
    );
  }
  let valued = match def.value_conv() {
    ValueConv::None => raw.clone(),
    ValueConv::Func(f) => f(raw),
    ValueConv::Hash(h) => apply_hash_conv(def, &h, raw, ConvType::ValueConv),
  };
  if !print_conv_enabled {
    return valued;
  }
  apply_print_conv(def, def.print_conv(), &valued, ConvType::PrintConv)
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
) -> TagValue {
  if let TagValue::List(items) = valued {
    return TagValue::List(
      items
        .iter()
        .map(|it| apply_print_conv(def, conv, it, conv_type))
        .collect(),
    );
  }
  match conv {
    PrintConv::None => valued.clone(),
    PrintConv::Func(f) => f(valued),
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

/// The stringified scalar ExifTool would key `$$conv{$val}` by (Perl hash
/// keys are strings), and which the JSON serializer prints. Numbers use the
/// crate's single shared `%g`/rational formatter ([`crate::value::format_g`]
/// / [`Rational::exiftool_val_str`]) so a hash key matches the serialized
/// `$val` text exactly. `Bytes` has no faithful Perl scalar key ⇒ `None`
/// (caller treats it as a miss).
fn exiftool_val_string(v: &TagValue) -> Option<String> {
  match v {
    // Perl stringifies an integer as its decimal text (`"$n"`).
    TagValue::I64(n) => Some(n.to_string()),
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
    // No faithful Perl hash key for raw bytes ⇒ miss.
    TagValue::Bytes(_) => None,
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

    use crate::{serialize::to_exiftool_json, Group, Metadata};
    let mut m = Metadata::new("a.aac");
    m.push(Group::new("Audio", "AAC"), "Channels", v);
    let json = to_exiftool_json(&m);
    // JSON number `2`, NOT the quoted string `"2"`.
    assert!(json.contains("\"AAC:Channels\": 2"), "got: {json}");
    assert!(!json.contains("\"AAC:Channels\": \"2\""), "got: {json}");
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
}
