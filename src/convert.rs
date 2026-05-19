//! Runs a raw value through a `TagDef`'s ValueConv then PrintConv, producing
//! the value that appears in `-j` output (PrintConv on) — ExifTool's pipeline.

use crate::tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, ValueConv};
use crate::value::{format_g, TagValue};
use smol_str::SmolStr;

/// The conversion stage, faithful to ExifTool's `$convType` (`ExifTool.pm`
/// `GetValue`/`ConvertValue`). The `PrintHex → 'Unknown (0x%x)'` sub-case is
/// gated on `$convType eq 'PrintConv'` (`ExifTool.pm:3618`), so the runtime
/// must know which stage a hash conv is being applied for. (No conversion
/// *context/options* object — that is the tracked Phase-2 item; this is just
/// the stage discriminator ExifTool already threads as `$convType`.)
#[derive(Clone, Copy, derive_more::IsVariant)]
enum ConvType {
  /// ExifTool `$convType eq 'ValueConv'`. Faithfully part of the
  /// discriminator (a hash conv applied as ValueConv must take the generic
  /// `Unknown ($val)` branch, not the PrintHex hex form,
  /// `ExifTool.pm:3618`). Stage-1 ValueConvs are all `Func`, never a hash,
  /// so the public pipeline never constructs this arm yet; the conv-type
  /// gate is exercised by `printhex_hex_form_not_applied_in_value_conv_stage`.
  #[allow(dead_code)]
  ValueConv,
  /// ExifTool `$convType eq 'PrintConv'`.
  PrintConv,
}

/// Apply ValueConv then PrintConv. `print_conv_enabled` mirrors ExifTool's
/// `-n` switch: when `false`, the post-ValueConv value is returned (the `-n`
/// golden), matching spec §4's two snapshots.
pub fn apply(def: &TagDef, raw: &TagValue, print_conv_enabled: bool) -> TagValue {
  let valued = match def.value_conv() {
    ValueConv::None => raw.clone(),
    ValueConv::Func(f) => f(raw),
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
/// every `PrintConv` variant, not just the hash.
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
/// `[+-]? ( \d+ \.? \d* | \. \d+ ) ( [eE] [+-]? \d+ )?`, evaluates as
/// `f64`, then truncates toward zero (`int()`) for the integer value used in
/// bitwise `&`. No leading prefix ⇒ 0; no hex parsing of `"0x…"` strings
/// (Perl: `"0x05"+0 == 0`). Negatives fold via `as u64` (two's-complement
/// low 64 bits), identical to Perl `$val & (1<<$i)` for negative values.
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
    }
  }
  // No numeric prefix found (only a sign, or nothing at all) ⇒ 0.
  if i == 0 || i == start_after_sign {
    return 0;
  }
  let prefix = &word[..i];
  // Parse as f64, then truncate toward zero to i64 (Perl `int()`), then
  // reinterpret as u64 (two's-complement) for bitwise operations.
  match prefix.parse::<f64>() {
    Ok(f) if f.is_finite() => {
      // Truncate toward zero: Perl's numeric context for `&`.
      let truncated = f.trunc();
      // Map to i64 range, then cast to u64 for two's-complement bitwise.
      // Values outside i64 range: clamp to i64::MIN/MAX before cast —
      // Perl uses its native integer width; ExifTool only passes values
      // fitting in 64 bits through real BITMASK tables.
      let as_i64 = if truncated >= i64::MAX as f64 {
        i64::MAX
      } else if truncated <= i64::MIN as f64 {
        i64::MIN
      } else {
        truncated as i64
      };
      as_i64 as u64
    }
    _ => 0,
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
/// [`perl_numeric_coerce`]: leading numeric prefix evaluated as f64, truncated
/// toward zero to i64, then reinterpreted as u64 for two's-complement bitwise
/// operations. No leading numeric prefix ⇒ 0; no hex parsing of `"0x…"`.
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
    // Lists are handled element-wise by `apply_print_conv` before this.
    TagValue::List(_) => None,
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

    use crate::serialize::to_exiftool_json;
    use crate::{Group, Metadata};
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
}
