//! Faithful port of `Image::ExifTool::ProcessBinaryData` (`ExifTool.pm:9866`),
//! the subset AIFF.pm exercises. Larger ProcessBinaryData features
//! (Hook/Mask/Condition/DataMember/IsOffset/MixedTags/Unknown/varSize
//! beyond the AIFF use, …) are faithfully deferred per spec §5 incremental
//! discipline — the FIRST consumer that needs each derives it against
//! that format's golden.
//!
//! AIFF tables exercised:
//! - `%AIFF::Common` (AIFF.pm:84-117) — `PROCESS_PROC = ProcessBinaryData`,
//!   `FORMAT = 'int16u'`. Tags 0/1/3/4/9/11 with per-tag `Format` overrides
//!   (`int32u`, `extended`, `string[4]`, `pstring`).
//! - `%AIFF::FormatVers` (AIFF.pm:119-123) — `PROCESS_PROC =
//!   ProcessBinaryData`, `FORMAT = 'int32u'`. Single tag 0 (no overrides).

use crate::{
  convert::apply,
  tagtable::{TagId, TagTable},
  value::{Group, Metadata, TagValue},
};

/// One of ExifTool's `%formatSize` Format strings, mapped to the value-type
/// the AIFF subset emits. Faithful to `ExifTool.pm:6199-6231 %formatSize` +
/// `:6232-6257 %readValueProc`, narrowed to the strings AIFF.pm uses.
/// Tag-table consumers carry the Perl `Format => '…'` string verbatim (e.g.
/// `Format => 'int32u'`, `'extended'`, `'string[4]'`, `'pstring'`); the
/// engine matches it here. Any other Format string passes through as
/// `BinaryFormat::Unsupported(s)` so the engine can faithfully no-op the
/// tag rather than panic — adding a new arm is how a future format extends
/// support.
#[derive(Clone, Copy, Debug, PartialEq)]
enum BinaryFormat<'a> {
  /// `int8u` (ExifTool.pm:6201) — 1-byte unsigned. ExifTool's
  /// `ProcessBinaryData` defaults to this when a table has no `FORMAT` key
  /// (`ExifTool.pm:9881 $defaultFormat = $$tagTablePtr{FORMAT} || 'int8u'`).
  Int8u,
  /// `int16u` (ExifTool.pm:6203) — 2-byte big-endian unsigned (AIFF uses MM).
  Int16u,
  /// `int32u` (ExifTool.pm:6206) — 4-byte big-endian unsigned.
  Int32u,
  /// `string[N]` (ExifTool.pm:6224 `string=1`, `:9966-9974` count from `[N]`).
  /// Fixed-length string; null-terminator stripping happens AFTER the read.
  StringFixed(usize),
  /// `pstring` (ExifTool.pm:6224, `:9961-9964`) — 1-byte length prefix, then
  /// that many bytes of `string`.
  Pstring,
  /// `extended` (ExifTool.pm:6221) — 10-byte 80-bit float (Apple SANE / Intel
  /// 8087). Decoded via [`get_extended`] (faithful `Writer.pl:4498`).
  Extended,
  /// Any Format string the AIFF subset does not implement. The tag is
  /// silently skipped (faithful: ExifTool would also produce no value for
  /// an unknown Format here without warnings on the default read path).
  Unsupported(&'a str),
}

impl BinaryFormat<'_> {
  /// Byte size of one element of this Format. `None` for variable-length
  /// (`Pstring`) or `Unsupported`.
  const fn size(self) -> Option<usize> {
    match self {
      BinaryFormat::Int8u => Some(1),
      BinaryFormat::Int16u => Some(2),
      BinaryFormat::Int32u => Some(4),
      BinaryFormat::StringFixed(n) => Some(n),
      BinaryFormat::Pstring | BinaryFormat::Unsupported(_) => None,
      BinaryFormat::Extended => Some(10),
    }
  }
}

/// Parse one of the Format strings AIFF.pm uses. `None` ⇒ no `Format` was
/// set (Perl `not $$tagInfo{Format}` ⇒ default-FORMAT path,
/// ExifTool.pm:9956-9957). `Some` of [`BinaryFormat::Unsupported`] for any
/// string outside the AIFF subset.
fn parse_format(s: &str) -> BinaryFormat<'_> {
  match s {
    "int8u" => BinaryFormat::Int8u,
    "int16u" => BinaryFormat::Int16u,
    "int32u" => BinaryFormat::Int32u,
    "pstring" => BinaryFormat::Pstring,
    "extended" => BinaryFormat::Extended,
    other => {
      if let Some(inner) = other
        .strip_prefix("string[")
        .and_then(|t| t.strip_suffix(']'))
      {
        if let Ok(n) = inner.parse::<usize>() {
          return BinaryFormat::StringFixed(n);
        }
      }
      BinaryFormat::Unsupported(other)
    }
  }
}

/// Faithful `GetExtended` (`Image::ExifTool::Writer.pl:4498`). Decode an
/// Apple SANE / Intel-8087 80-bit extended float at `data[pos..pos+10]`,
/// big-endian (AIFF's `SetByteOrder('MM')`, AIFF.pm:215). The value is
/// `sign * sig * 2^(exp - 16383 - 63)`; with `exp == 0 && sig == 0` it is
/// exactly `0.0` (and the I64 return path takes that to `0`, avoiding any
/// NaN-in-serialize concern).
///
/// Returns the decoded value as a [`TagValue`], faithful to Perl's IV/UV/NV
/// scalar typing of `$sign * $sig * (2 ** $exp)`:
/// - `I64(0)` for the all-zero significand+exponent.
/// - `I64(n)` for integer values in `i64::MIN..=i64::MAX`, detected via
///   INTEGER arithmetic on the bit pattern (NOT via f64 round-trip —
///   Codex R7 fix: `(sig as f64) as i64` lost precision for significands
///   above `2^53`, e.g. `403e0020000000000001` ⇒ Perl emits
///   `"9007199254740993"` while the prior path stored `9007199254740992`).
/// - `Str("<exact-integer>")` for POSITIVE integers in `(i64::MAX, u64::MAX]`
///   — Perl's UV path preserves the exact magnitude; the EscapeJSON gate
///   quotes any > 15-digit integer text (so JSON emits
///   `"9223372036854775809"`, not the saturated numeric
///   `9223372036854775807`).
/// - `F64(_)` for non-integer extendeds AND for integer magnitudes outside
///   the IV/UV ranges above. Codex R7 fix: Perl forces NV when (a) a
///   positive magnitude exceeds `u64::MAX` (e.g. `2^65` ⇒
///   `3.68934881474191e+19`) or (b) a negative magnitude exceeds
///   `2^63` (e.g. `-(2^63+1)` ⇒ `-9.22337203685478e+18`, because
///   `-1 * UV` degrades to NV when UV > i64::MAX). See [`int_or_str`].
///   Non-finite f64 (NaN/Inf) flows through to the serializer which
///   quotes it (Phase-2 forward-item; bundled Perl on NaN-extended inputs
///   is itself implementation-defined and we follow the EscapeJSON
///   quoting path).
fn get_extended(data: &[u8]) -> TagValue {
  // Writer.pl:4501-4506. AIFF is MM, so $pt=0 (exponent at +0), sig at +2.
  if data.len() < 10 {
    return TagValue::I64(0); // out-of-bounds ⇒ Perl would short-read; defensive 0.
  }
  let exp_raw = u16::from_be_bytes([data[0], data[1]]);
  let sig = u64::from_be_bytes([
    data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
  ]);
  // Writer.pl:4504-4505 `$sign = ($exp & 0x8000) ? -1 : 1; $exp = ($exp &
  // 0x7fff) - 16383 - 63`. The all-zero case (0x0000 exp, 0 sig) ⇒
  // value = 0.0, faithful to Perl's `1 * 0 * 2^(-16446) == 0`.
  let sign_neg = (exp_raw & 0x8000) != 0;
  let biased = (exp_raw & 0x7fff) as i32;
  let exp = biased - 16383 - 63;
  if sig == 0 {
    // Codex R8 + R9 fix: `sig == 0` short-circuit gated on whether the
    // Perl expression `0 * (2 ** $exp)` evaluates to 0 (finite power) or
    // NaN (infinite power). Model the BOUNDARY at the f64 expression
    // level, NOT just the biased == 0x7FFF special case: any `exp`
    // where `2f64.powi(exp)` overflows to Inf produces `0 * Inf = NaN`.
    // Oracle (2026-05-20) on `0x443e0000000000000000` (exp=1024, sig=0)
    // confirms `"NaN"` — even though biased=0x443E != 0x7FFF, the f64
    // power overflows at exp=1024 (= f64::MAX_EXP). Conversely
    // `0x80010000000000000000` (biased=1, sig=0) ⇒ bare `0` because
    // `2^-16445` is a finite subnormal.
    if 2f64.powi(exp).is_finite() {
      return TagValue::I64(0);
    }
    // exp produces non-finite power of 2 ⇒ fall through to the f64 path
    // where `0.0 * 2^exp = 0.0 * Inf = NaN` is computed IEEE-754 and
    // emitted via perl_nonfinite_str.
  }
  // Codex R7 + R8 + R9 + R10 fix: integer detection uses INTEGER
  // arithmetic on the bit pattern, BUT ONLY when `exp == 0`. Perl's
  // `$sig * (2 ** $exp)`:
  // - `2 ** 0 = NV(1)`; Perl optimizes `UV * NV(1) = UV` (the
  //   multiplication is a no-op and the UV scalar type is preserved).
  //   This is the ONLY exp case where Perl keeps IV/UV typing.
  // - `2 ** $exp` for any `$exp != 0` is NV with magnitude != 1; the
  //   multiplication `IV/UV * NV(!=1) = NV` propagates the NV type
  //   regardless of whether the mathematical result fits an integer.
  //   Codex R10 verified this empirically: `0x4073 0x8000000000000000`
  //   ⇒ `1 * 2^53 = 9007199254740992` (exact integer, fits i64), but
  //   Perl emits `9.00719925474099e+15` (NV scientific) because
  //   `2 ** 53` is NV. The prior R7-R9 code routed this through
  //   `int_or_str` and emitted `Str("9007199254740992")` (quoted 16-
  //   digit) — diverging from oracle's bare scientific form.
  //
  // For `exp == 0`, the integer path uses Perl IV/UV typing (oracle
  // `0x403e8000000000000001` ⇒ quoted `"9223372036854775809"`). The
  // u128 overflow gate is unnecessary here because `sig` fits u64
  // (≤ u128::MAX), but kept as a defensive guard.
  //
  // For `exp != 0` (positive OR negative), ALWAYS route through the
  // f64/NV path; the IEEE-754 multiplication `(sig as f64) * 2^exp` is
  // byte-exact to Perl's `$sig * (2 ** $exp)` NV arithmetic.
  if exp == 0 {
    // Pure UV-preserving path: value = sign * sig. No shift needed.
    return int_or_str(sign_neg, sig as u128);
  }
  // `exp != 0` ⇒ ALWAYS route through the f64/NV path below.
  // Non-integer path: reconstruct as f64. Significand fits in u64; 2^exp
  // via f64 powi. Result may be subnormal, very large, or (for adversarial
  // exponents) non-finite — the serializer quotes any non-finite TagValue
  // ::F64 via the `is_finite()` branch in `serialize.rs`.
  let sig_f = sig as f64;
  let val = sig_f * 2f64.powi(exp);
  let signed = if sign_neg { -val } else { val };
  TagValue::F64(signed)
}

/// Pack an exact unsigned integer + sign into a [`TagValue`], faithful to
/// Perl's IV/UV/NV scalar typing of `$sign * $sig * (2 ** $exp)`:
///
/// - Positive `[0, i64::MAX]` ⇒ `I64`. Perl IV path: bare numeric JSON.
/// - Positive `(i64::MAX, u64::MAX]` ⇒ `Str("<decimal>")`. Perl UV path:
///   exact decimal preserved; EscapeJSON's number-vs-string gate quotes
///   any > 15-digit integer text (e.g. `"9223372036854775809"`).
/// - Positive `> u64::MAX` ⇒ `F64`. Perl falls back to NV (cannot store
///   the exact magnitude as UV ≤ 2^64-1), producing `%.15g` stringification
///   (e.g. `2^65` ⇒ `3.68934881474191e+19`). Codex R7 fix.
/// - Negative `[-i64::MIN, 0]` ⇒ `I64`. Perl IV path: bare numeric JSON.
/// - Negative `< -i64::MIN` (magnitude `> 2^63`) ⇒ `F64`. Perl forces NV
///   here because IV cannot hold the negation of UV > i64::MAX (the
///   `-1 * UV` multiplication degrades to NV). Oracle verified
///   (2026-05-20) on `0xC03E 0x8000000000000001` ⇒ Perl emits
///   `-9.22337203685478e+18`, NOT exact `-9223372036854775809`.
///   Codex R7 fix.
fn int_or_str(sign_neg: bool, mag: u128) -> TagValue {
  if !sign_neg {
    if mag <= i64::MAX as u128 {
      return TagValue::I64(mag as i64);
    }
    if mag <= u64::MAX as u128 {
      // Perl UV path: exact decimal, EscapeJSON quotes it because > 15
      // digits. The serializer's `is_json_number_literal` gate emits it
      // as a JSON string (matching `"9223372036854775809"` oracle).
      return TagValue::Str(mag.to_string().into());
    }
    // Perl NV fallback for `> u64::MAX`: cast to f64 and emit. The
    // serializer's format_g(_,15) prints exactly Perl's `%.15g` form
    // (e.g. `3.68934881474191e+19`).
    return TagValue::F64(mag as f64);
  }
  // Negative branch: |i64::MIN| == 2^63, so an unsigned magnitude up to
  // 2^63 fits in i64 (negated).
  if mag <= (i64::MAX as u128) + 1 {
    // -(mag as i128) is safe up to 2^63 because i128 trivially fits it.
    return TagValue::I64(-(mag as i128) as i64);
  }
  // Magnitude > 2^63: Perl forces NV. Negate the f64 of `mag` (the same
  // f64 Perl would produce from `0 + $sig`). Oracle verified.
  TagValue::F64(-(mag as f64))
}

/// Strip trailing nulls from a byte slice, faithful to Perl's `$val =~ s/\0.*//s`
/// (ExifTool.pm:10027) — truncate at the first NUL, then anything before is
/// the value. (For `Format => 'undef'` Perl skips the truncate; the AIFF
/// subset does not exercise that path.)
fn strip_at_first_null(bytes: &[u8]) -> &[u8] {
  match bytes.iter().position(|&b| b == 0) {
    Some(i) => &bytes[..i],
    None => bytes,
  }
}

/// Faithful subset of `ProcessBinaryData` (`ExifTool.pm:9866-10141`). Walks
/// the tag table's integer keys in ascending numerical order
/// (`ExifTool.pm:9907`), computes each tag's `entry = index * increment`
/// offset (:9946 with `varSize == 0` — the AIFF subset uses no `var_*`
/// formats, so `$varSize` stays 0 throughout, audited against AIFF.pm), reads
/// the value per the tag's `Format` (or the table's default FORMAT,
/// :9956-9957), runs the convert pipeline, and pushes the result into `into`.
///
/// `default_format` is the Perl `$$tagTablePtr{FORMAT}` (e.g. `"int16u"` for
/// `%AIFF::Common`). `keys` is the module's static, sorted ascending list of
/// integer tag IDs (Rust statics aren't enumerable; the format module
/// supplies the sorted slice exactly as `sort { $a <=> $b } TagTableKeys`).
///
/// `var_size` (ExifTool.pm:9914): faithfully kept at 0 here — the AIFF tag
/// tables don't use any `var_*`-prefixed Format (the only updates to
/// `$varSize` happen in those branches, ExifTool.pm:9979 / :10023). The
/// AIFF plain-`pstring` branch (:9961-9964) is special-cased per Perl: it
/// post-increments the local `$entry` by 1 (the length byte) but leaves
/// `$varSize` alone, so subsequent tags still compute their offsets from
/// the same `$varSize` value (0). The first format port that needs `var_*`
/// must derive that path against its real ExifTool golden.
pub fn process_binary_data(
  data: &[u8],
  default_format: &str,
  table: &TagTable,
  keys: &[i64],
  into: &mut Metadata,
  print_conv_enabled: bool,
) {
  let default = parse_format(default_format);
  // Faithful to ExifTool.pm:9882 `$increment = $formatSize{$defaultFormat}`.
  // If the default Format has no fixed size (e.g. `pstring`), the engine
  // would short-circuit — AIFF only uses `int16u`/`int32u` as defaults here,
  // both fixed-size — but defensively fall back to 1 if unsupported.
  let increment = default.size().unwrap_or(1);
  let size = data.len(); // DirLen = length($$dataPt) (AIFF ProcessDirectory)

  for &key in keys {
    let Some(def) = (table.get())(TagId::Int(key)) else {
      continue;
    };
    // ExifTool.pm:9946 `$entry = int($index) * $increment + $varSize`,
    // with `$varSize == 0` for the AIFF subset (no var_* Formats).
    if key < 0 {
      continue;
    }
    let base = (key as usize).saturating_mul(increment);
    // ExifTool.pm:9952-9953 `$more = $size - $entry; last if $more <= 0`.
    if base >= size {
      break;
    }
    let more = size - base;

    // ExifTool.pm:9955-9963 — choose Format for this tag.
    let fmt = match def.format() {
      None => default, // :9956-9957 `if (not $format) { $format = $defaultFormat }`.
      Some(s) => parse_format(s),
    };
    // Decode per Format. `pstring` post-increments `entry` by the length
    // byte (:9963) but does NOT touch `$varSize` (no `var_` prefix); see
    // the function doc.
    let value: Option<TagValue> = match fmt {
      BinaryFormat::Int8u => {
        if more < 1 {
          None
        } else {
          Some(TagValue::I64(i64::from(data[base])))
        }
      }
      BinaryFormat::Int16u => {
        if more < 2 {
          None
        } else {
          Some(TagValue::I64(i64::from(u16::from_be_bytes([
            data[base],
            data[base + 1],
          ]))))
        }
      }
      BinaryFormat::Int32u => {
        if more < 4 {
          None
        } else {
          Some(TagValue::I64(i64::from(u32::from_be_bytes([
            data[base],
            data[base + 1],
            data[base + 2],
            data[base + 3],
          ]))))
        }
      }
      BinaryFormat::StringFixed(n) => {
        // ExifTool.pm:6290-6293 ReadValue: if requested count*len > size,
        // shorten count to int(size/len). Only return undef when count < 1
        // (zero bytes available). Faithfully clamp here: a truncated COMM
        // chunk's CompressionType (e.g. 2 of 4 bytes) MUST still emit, not
        // be silently dropped. Codex R3 fix.
        let avail = more.min(n);
        if avail == 0 {
          None
        } else {
          let bytes = &data[base..base + avail];
          let stripped = strip_at_first_null(bytes); // :10027
          // Emit raw bytes (faithful to Perl `$val = substr(...)`, which is
          // a BYTE STRING — no UTF-8 reinterpretation, no `from_utf8_lossy`).
          // The convert layer is responsible for any MacRoman/UTF-16
          // ValueConv; hash PrintConv lookups key the bytes via
          // [`crate::convert::exiftool_val_string`] (FixUTF8 — valid UTF-8
          // preserved, invalid high bytes replaced with `?`, matching Perl
          // EscapeJSON's behavior). Codex R3 verified the divergence on
          // CompressionType `\x80ABC` (Perl: "?ABC"; pre-fix: "U+0080ABC").
          Some(TagValue::Bytes(stripped.to_vec()))
        }
      }
      BinaryFormat::Pstring => {
        // :9961-9964 `$count = Get8u($dataPt, ($entry++)+$dirStart); --$more`
        // — read length, advance past it, then read `count` bytes. ExifTool
        // ReadValue (ExifTool.pm:6290-6293) shortens count when requested
        // bytes exceed remaining data. Faithful clamp: emit a truncated
        // pstring rather than silently drop. Codex R3 fix.
        if more < 1 {
          None
        } else {
          let declared = data[base] as usize;
          let body_start = base + 1; // post-increment of $entry
          let body_remaining = size.saturating_sub(body_start);
          let count = declared.min(body_remaining);
          if count == 0 && declared > 0 {
            // Declared length non-zero but no bytes available — only zero
            // bytes follow. Perl ReadValue's count==0 branch returns undef
            // (no value); mirror that as a silent skip.
            None
          } else {
            let bytes = &data[body_start..body_start + count];
            let stripped = strip_at_first_null(bytes); // :10027
            // Emit raw bytes — see the StringFixed branch above. ValueConv
            // (e.g. AIFC `CompressorName`'s MacRoman decode) reads the raw
            // bytes; Codex R1 fix.
            Some(TagValue::Bytes(stripped.to_vec()))
          }
        }
      }
      BinaryFormat::Extended => {
        if more < 10 {
          None
        } else {
          Some(get_extended(&data[base..base + 10]))
        }
      }
      BinaryFormat::Unsupported(_) => None,
    };

    let Some(raw_value) = value else {
      continue;
    };
    // Run convert (ValueConv → PrintConv) and push.
    let out = apply(def, &raw_value, print_conv_enabled);
    // String-format outputs that were not consumed by ValueConv/PrintConv
    // (e.g. AIFF `CompressionType` under `-n`, where ValueConv=None and
    // PrintConv runs only when print_conv_enabled is true) come back as
    // raw `TagValue::Bytes`. Perl scalar context on a byte string flows
    // through `EscapeJSON`, which runs `FixUTF8` (XMP.pm:2943): valid
    // UTF-8 is preserved; invalid high bytes are replaced with `?`.
    // Codex R3 verified that bundled ExifTool emits CompressionType
    // `\x80ABC` as `"?ABC"` under `-n`; the prior Latin-1 1:1 mapping
    // would have emitted `"\u{0080}ABC"`. Routing through
    // [`crate::convert::fix_utf8`] keeps the byte-exact output.
    // Bytes from a `ValueConv::Func` (e.g. MacRoman decode) have already
    // been converted to `Str`, so this arm only fires for tags that
    // intentionally stay byte-typed (which never have an associated
    // `Bytes` ValueConv).
    let out = match out {
      TagValue::Bytes(b) => TagValue::Str(crate::convert::fix_utf8(&b).into()),
      other => other,
    };
    into.push(Group::new(table.group0(), def.group1()), def.name(), out);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tagtable::{PrintConv, TagDef, ValueConv};

  #[test]
  fn parse_format_handles_aiff_subset() {
    assert_eq!(parse_format("int16u"), BinaryFormat::Int16u);
    assert_eq!(parse_format("int32u"), BinaryFormat::Int32u);
    assert_eq!(parse_format("pstring"), BinaryFormat::Pstring);
    assert_eq!(parse_format("extended"), BinaryFormat::Extended);
    assert_eq!(parse_format("string[4]"), BinaryFormat::StringFixed(4));
    assert_eq!(parse_format("string[18]"), BinaryFormat::StringFixed(18));
    // Anything else is Unsupported (no panic, no warn).
    assert_eq!(parse_format("int64u"), BinaryFormat::Unsupported("int64u"));
    assert_eq!(
      parse_format("string[]"),
      BinaryFormat::Unsupported("string[]")
    );
    assert_eq!(
      parse_format("string[X]"),
      BinaryFormat::Unsupported("string[X]")
    );
  }

  #[test]
  fn get_extended_zero_yields_i64_zero() {
    // SampleRate=0 in our AIFF fixture: all 10 bytes zero ⇒ TagValue::I64(0),
    // never F64(NaN) (the Phase-2 non-finite-f64-in-serialize forward-item).
    let raw = [0u8; 10];
    match get_extended(&raw) {
      TagValue::I64(0) => {} // ok
      other => panic!("expected I64(0), got {other:?}"),
    }
  }

  #[test]
  fn get_extended_known_integers_match_perl_oracle() {
    // 22050 Hz: 0x400D AC44000000000000 (validated against AIFF.aif fixture).
    // exp=0x400d=16397, biased=16397-16383-63=-49, sig=0xAC44000000000000.
    // 0xAC44000000000000 * 2^-49 = 22050 exactly.
    //
    // Codex R8 fix: `exp < 0` ALWAYS routes through the f64/NV path
    // (Perl's `$sig * (2 ** $exp)` is NV arithmetic even when the
    // result is mathematically integral). For SampleRate=22050 the
    // f64 is exactly 22050.0 (well below the 2^53 mantissa limit), so
    // the serializer emits bare `22050` via format_g(_,15) — byte-exact
    // to Perl's NV stringification of 22050.0 (the AIFF.aif golden
    // shows `"AIFF:SampleRate": 22050` matching either I64 or F64
    // representation through the serializer).
    let mut raw = [0u8; 10];
    raw[0..2].copy_from_slice(&0x400d_u16.to_be_bytes());
    raw[2..10].copy_from_slice(&0xAC44_0000_0000_0000_u64.to_be_bytes());
    assert_eq!(get_extended(&raw), TagValue::F64(22050.0));
    // 44100 Hz: exp 0x400e (16398), sig same top bit → 44100.
    let mut raw2 = [0u8; 10];
    raw2[0..2].copy_from_slice(&0x400e_u16.to_be_bytes());
    raw2[2..10].copy_from_slice(&0xAC44_0000_0000_0000_u64.to_be_bytes());
    assert_eq!(get_extended(&raw2), TagValue::F64(44100.0));
  }

  #[test]
  fn int_or_str_matches_perl_iv_uv_nv_thresholds() {
    // Codex R7 follow-up: pin the IV/UV/NV thresholds against Perl's
    // `$sign * $sig * (2 ** $exp)` scalar typing rules.

    // Positive IV range: [0, i64::MAX] ⇒ I64.
    assert_eq!(int_or_str(false, 0), TagValue::I64(0));
    assert_eq!(int_or_str(false, 1), TagValue::I64(1));
    assert_eq!(int_or_str(false, i64::MAX as u128), TagValue::I64(i64::MAX));

    // Positive UV range: (i64::MAX, u64::MAX] ⇒ Str (exact decimal). The
    // serializer's EscapeJSON gate quotes any > 15-digit integer text,
    // so JSON emits e.g. `"9223372036854775808"`.
    assert_eq!(
      int_or_str(false, (i64::MAX as u128) + 1),
      TagValue::Str("9223372036854775808".into())
    );
    // Existing AIFF_ext_int_overflow fixture's sig = 2^63 + 1.
    assert_eq!(
      int_or_str(false, (i64::MAX as u128) + 2),
      TagValue::Str("9223372036854775809".into())
    );
    assert_eq!(
      int_or_str(false, u64::MAX as u128),
      TagValue::Str("18446744073709551615".into())
    );

    // Positive NV fallback: > u64::MAX ⇒ F64. Perl converts to NV; the
    // serializer's format_g(_, 15) prints `3.68934881474191e+19` for 2^65.
    // Use exact 2^65 = 2 * (u64::MAX as u128 + 1) = 36893488147419103232.
    match int_or_str(false, 1u128 << 65) {
      TagValue::F64(x) => {
        // Cast through f64 ⇒ the round-trippable NV that Perl also stored.
        assert!((x - (1u128 << 65) as f64).abs() < 1.0);
        assert!(x.is_finite() && x > 0.0);
      }
      other => panic!("expected F64 for > u64::MAX, got {other:?}"),
    }

    // Negative IV range: [-(2^63), 0] ⇒ I64.
    assert_eq!(int_or_str(true, 0), TagValue::I64(0));
    assert_eq!(int_or_str(true, 1), TagValue::I64(-1));
    assert_eq!(
      int_or_str(true, (i64::MAX as u128) + 1),
      TagValue::I64(i64::MIN)
    );

    // Negative NV fallback: magnitude > 2^63 ⇒ F64 (Perl `-1 * UV` ⇒ NV).
    // Oracle (2026-05-20) on `0xC03E 0x8000000000000001`: Perl emits
    // `-9.22337203685478e+18`, NOT exact `-9223372036854775809`.
    match int_or_str(true, (i64::MAX as u128) + 2) {
      TagValue::F64(x) => {
        assert!(x.is_finite() && x < 0.0);
        assert!((x - (-((1u128 << 63) as f64) - 1.0)).abs() < 4096.0);
      }
      other => panic!("expected F64 for negative > 2^63 magnitude, got {other:?}"),
    }
  }

  #[test]
  fn strip_at_first_null_handles_all_cases() {
    assert_eq!(strip_at_first_null(b""), b"");
    assert_eq!(strip_at_first_null(b"abc"), b"abc");
    assert_eq!(strip_at_first_null(b"abc\0def"), b"abc");
    assert_eq!(strip_at_first_null(b"\0abc"), b"");
  }

  // Lightweight tag table for engine-level testing.
  static T0: TagDef = TagDef::new("A", "T", ValueConv::None, PrintConv::None);
  static T1: TagDef = TagDef::new("B", "T", ValueConv::None, PrintConv::None).with_format("int32u");
  fn lookup(id: TagId) -> Option<&'static TagDef> {
    match id {
      TagId::Int(0) => Some(&T0),
      TagId::Int(1) => Some(&T1),
      _ => None,
    }
  }
  static TABLE: TagTable = TagTable::new("T", lookup);

  #[test]
  fn process_binary_data_reads_int16u_default_and_int32u_override() {
    // FORMAT='int16u' (increment=2). Key 0 reads int16u at byte 0. Key 1
    // overrides Format='int32u' and reads u32 at byte 2 (1 * 2 + 0).
    let data = [0x00, 0x01, 0x00, 0x00, 0x2d, 0x22];
    let mut m = Metadata::new("x");
    process_binary_data(&data, "int16u", &TABLE, &[0, 1], &mut m, false);
    assert_eq!(m.tags()[0].name(), "A");
    assert_eq!(m.tags()[0].value(), &TagValue::I64(1));
    assert_eq!(m.tags()[1].name(), "B");
    assert_eq!(m.tags()[1].value(), &TagValue::I64(11554));
  }

  #[test]
  fn process_binary_data_stops_at_end_of_data() {
    // Two keys but only enough bytes for the first ⇒ second silently skipped.
    let data = [0x00, 0x07];
    let mut m = Metadata::new("x");
    process_binary_data(&data, "int16u", &TABLE, &[0, 1], &mut m, false);
    assert_eq!(m.tags().len(), 1);
    assert_eq!(m.tags()[0].value(), &TagValue::I64(7));
  }

  // Codex R1 regression: string[N] / pstring used to `from_utf8(...).unwrap_or_default()`
  // which CORRUPTED valid MacRoman high bytes (e.g. 0x80 → "") and reinterpreted
  // valid UTF-8 byte sequences as MacRoman bytes. Fixed by emitting raw Bytes
  // straight from the engine; downstream ValueConv decodes faithfully.
  static MAC_NAME: TagDef = {
    use crate::value::TagValue as TV;
    fn decode(v: &TV) -> TV {
      match v {
        TV::Bytes(b) => TV::Str(crate::charset::decode_macroman(b).into()),
        other => other.clone(),
      }
    }
    TagDef::new("MacName", "T", ValueConv::Func(decode), PrintConv::None).with_format("pstring")
  };
  fn mac_lookup(id: TagId) -> Option<&'static TagDef> {
    if id == TagId::Int(0) {
      Some(&MAC_NAME)
    } else {
      None
    }
  }
  static MAC_TABLE: TagTable = TagTable::new("T", mac_lookup);

  #[test]
  fn pstring_macroman_high_byte_decodes_faithfully_codex_r1_regression() {
    // pstring: 1-byte length=2, then bytes [0x80, 0x81]. Faithful MacRoman:
    //   0x80 → U+00C4 (Ä), 0x81 → U+00C5 (Å).
    // Prior `from_utf8(...).unwrap_or_default()` would have yielded "" for
    // these bytes (0x80 is invalid UTF-8 start). Now: raw Bytes flow through
    // the ValueConv which decodes MacRoman exactly.
    let data = [0x02, 0x80, 0x81];
    let mut m = Metadata::new("x");
    process_binary_data(&data, "int8u", &MAC_TABLE, &[0], &mut m, false);
    assert_eq!(m.tags().len(), 1);
    assert_eq!(m.tags()[0].name(), "MacName");
    assert_eq!(
      m.tags()[0].value(),
      &TagValue::Str("\u{00c4}\u{00c5}".into())
    );
  }

  #[test]
  fn string_no_valueconv_emits_latin1_decoded_ascii_string() {
    // string[4] WITHOUT a ValueConv: the engine pushes Bytes through `apply`
    // (no-op), then the trailing Bytes→Str shim converts via Latin-1 1:1.
    // For ASCII "NONE" this is identity — the oracle expectation for AIFF
    // `CompressionType` under `-n` (no PrintConv applied) is exactly "NONE".
    static T_NOVC: TagDef =
      TagDef::new("CT", "T", ValueConv::None, PrintConv::None).with_format("string[4]");
    fn novc_lookup(id: TagId) -> Option<&'static TagDef> {
      if id == TagId::Int(0) {
        Some(&T_NOVC)
      } else {
        None
      }
    }
    static NOVC_TABLE: TagTable = TagTable::new("T", novc_lookup);

    let data = b"NONE";
    let mut m = Metadata::new("x");
    process_binary_data(data, "int8u", &NOVC_TABLE, &[0], &mut m, false);
    assert_eq!(m.tags().len(), 1);
    assert_eq!(m.tags()[0].value(), &TagValue::Str("NONE".into()));
  }
}
