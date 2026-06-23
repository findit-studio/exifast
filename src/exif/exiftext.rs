// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "exif")]
//! Faithful port of `Image::ExifTool::Exif::ConvertExifText`
//! (`Exif.pm:5554-5601`) plus the UTF-16 `Unknown`-order decoder it relies on
//! (`Image::ExifTool::Charset::Decompose`, `Charset.pm:150-258`).
//!
//! `ConvertExifText` is the `RawConv` for the `undef`-format EXIF text tags:
//!
//! - `UserComment` (`0x9286`, `Exif.pm:2497-2507`) — ExifIFD,
//! - `GPSProcessingMethod` (`GPS.pm:299`) / `GPSAreaInformation` (`GPS.pm:305`)
//!   — the GPS sub-IFD,
//!
//! all of which call it with `$asciiFlex == 1`. The function lives in `Exif.pm`
//! (not `GPS.pm`), and `UserComment` needs it WITHOUT the GPS table, so this
//! module is gated on `feature = "exif"` (NOT `gps`) and the GPS table
//! (`feature = "gps"`) re-uses it.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length guard (the
// 8-byte charset-ID prefix split) and converted to a checked `.get()` form.
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use std::string::String;

/// `ConvertExifText($self, $val, 1, $tag)` (`Exif.pm:5554-5601`) — the
/// `RawConv` for the `undef`-format EXIF text tags (`UserComment`
/// `Exif.pm:2502`, `GPSProcessingMethod` `GPS.pm:299`, `GPSAreaInformation`
/// `GPS.pm:305`), all of which pass `$asciiFlex == 1`.
///
/// The `undef`-format value carries an 8-byte character-set ID prefix
/// followed by the payload (Exif §4.6.6 — `UserComment` / `GPSProcessingMethod`
/// etc.):
/// ```text
/// return $val if length($val) < 8;          # too short — no prefix
/// $id  = substr($val, 0, 8);
/// $str = substr($val, 8);
/// if ($id =~ /^(ASCII)?(\0|[\0 ]+$)/) { $str =~ s/\0.*//s; ... }
/// elsif ($id =~ /^(UNICODE)[\0 ]$/)  { Decode UTF16 Unknown }
/// elsif ($id =~ /^(JIS)[\0 ]{5}$/)   { Decode JIS Unknown }
/// else { Warn 'Invalid EXIF text encoding'; $str = $id . $str }
/// $str =~ s/ +$//;                          # trim trailing blanks
/// ```
///
/// ExifTool tolerates spaces in place of NULs in the ID code (camera-vendor
/// bug). With `$asciiFlex eq '1'` ASCII text MAY itself be re-decoded under
/// `CharsetEXIF` — but only `if $enc` (`Exif.pm:5575-5576`
/// `$str = $et->Decode($str, $enc) if $enc`). The default `CharsetEXIF` is
/// UNSET (`undef`, `ExifTool.pm:1117`), and exifast does not expose the
/// option, so `$enc` is always false and the re-decode is simply SKIPPED — an
/// identity pass on the already-NUL-trimmed ASCII payload.
///
/// JIS decoding needs the full `Image::ExifTool::Charset::JIS` multi-byte
/// table (a large standalone port — out of camera-metadata scope); a
/// `JIS\0\0\0\0\0`-prefixed value is rendered with the prefix DROPPED and
/// the payload kept as a string (`docs/tracking.md`). The bundled fixtures
/// use the ASCII / UNICODE prefixes.
///
/// **Invalid UTF-8 → `?` (`FixUTF8`, #200).** Every byte-payload branch
/// (ASCII, JIS, the undefined-prefix `else`, and the `< 8` passthrough)
/// renders its decoded payload through [`crate::convert::fix_utf8`] rather
/// than `String::from_utf8_lossy`: ExifTool applies its `FixUTF8` (default
/// `$bad = '?'`, `XMP.pm:2969`) at the JSON serialization boundary
/// (`exiftool:3823` `EscapeJSON`) to whatever string `ConvertExifText`
/// returns, so an invalid byte must emit one ASCII `?` (not the Unicode
/// REPLACEMENT CHARACTER U+FFFD). The UNICODE (UTF-16) branch keeps its own
/// faithful `decode_utf16_unknown` codec — its lone-surrogate handling is a
/// separate, `docs/tracking.md`-tracked divergence (`from_utf16_lossy` →
/// U+FFFD vs ExifTool's `pack 'U*'` → three `?`), out of #200 scope.
///
/// `order` is the TIFF byte order in effect when `ConvertExifText` runs —
/// ExifTool's `Decode($str, 'UTF16', 'Unknown')` seeds the byte-order guess
/// from `GetByteOrder()` (`Charset.pm:191-195`), so the UNICODE branch must
/// be threaded the EXIF block's order rather than hard-coding big-endian.
#[must_use]
pub fn convert_exif_text(val: &[u8], order: ByteOrder) -> String {
  // `return $val if length($val) < 8` — no prefix; treat the whole blob as
  // the value (FixUTF8'd at return). `split_at_checked(8)` fuses the
  // `length < 8` guard
  // with the `$id = substr($val,0,8); $str = substr($val,8)` split: it returns
  // `None` for a < 8-byte value (the `return $val` arm) and otherwise the two
  // sub-slices — the checked, byte-identical form of `(&val[0..8], &val[8..])`.
  let Some((id, payload)) = val.split_at_checked(8) else {
    return crate::convert::fix_utf8(val);
  };

  // `/^(ASCII)?(\0|[\0 ]+$)/` — an "ASCII" prefix (NUL- or space-padded),
  // or an all-NUL/space prefix with no name (the "undefined → ASCII"
  // default). The regex's first alternative matches a leading `\0`, the
  // second an all-`[\0 ]` 8-byte field.
  let is_ascii = {
    // `id.starts_with(b"ASCII")` guarantees `id.len() >= 5`, so `id.get(5..)`
    // is `Some` — the checked, byte-identical form of `&id[5..]` (the
    // `.unwrap_or(id)` fallback is unreachable on this branch).
    let after_name: &[u8] = if id.starts_with(b"ASCII") {
      id.get(5..).unwrap_or(id)
    } else {
      id
    };
    // First branch `(\0|...)`: a leading NUL right after the optional name.
    // Second branch `[\0 ]+$`: the remainder is all NUL/space.
    after_name.first() == Some(&0)
      || (!after_name.is_empty() && after_name.iter().all(|&b| b == 0 || b == b' '))
  };
  if is_ascii {
    // `$str =~ s/\0.*//s` — truncate at the first NUL terminator. `end` is
    // either a NUL position (`< len`) or `payload.len()`, so `payload.get(..end)`
    // is always `Some` — the checked form of `&payload[..end]`.
    let end = payload
      .iter()
      .position(|&b| b == 0)
      .unwrap_or(payload.len());
    let mut s = crate::convert::fix_utf8(payload.get(..end).unwrap_or(payload));
    trim_trailing_spaces(&mut s);
    return s;
  }

  // `/^(UNICODE)[\0 ]$/` — the 7-letter name plus one NUL/space byte. `id` is
  // exactly 8 bytes (`split_at_checked(8)`), so `id.get(7)` is the checked,
  // byte-identical form of `id[7]`.
  if id.starts_with(b"UNICODE") && matches!(id.get(7), Some(0 | b' ')) {
    // `Decode($str, 'UTF16', 'Unknown')` — byte order is guessed starting
    // from `GetByteOrder()` (the EXIF block's order), overridden by a BOM,
    // then flipped if the byte-distribution heuristic shows the guess was
    // wrong (`Charset.pm:191-235`). MicrosoftPhoto writes little-endian even
    // in big-endian EXIF, hence the guess.
    return decode_utf16_unknown(payload, order);
  }

  // `/^(JIS)[\0 ]{5}$/` — "JIS" plus five NUL/space bytes. `id` is exactly 8
  // bytes, so `id.get(3..8)` is `Some` — the checked form of `id[3..8]`.
  if id.starts_with(b"JIS")
    && id
      .get(3..8)
      .is_some_and(|tail| tail.iter().all(|&b| b == 0 || b == b' '))
  {
    // JIS codec not ported (see doc comment). Drop the prefix, keep the
    // payload as a string so the value is at least not a binary blob. Invalid
    // bytes render as `?` via `FixUTF8` (the same JSON-boundary pass ExifTool
    // would apply to whatever JIS-decoded string it produced).
    let mut s = crate::convert::fix_utf8(payload);
    trim_trailing_spaces(&mut s);
    return s;
  }

  // `else` — invalid encoding: ExifTool warns and returns `$id . $str`
  // (the prefix is NOT stripped). Reproduce the concatenation.
  let mut s = crate::convert::fix_utf8(val);
  trim_trailing_spaces(&mut s);
  s
}

/// `$str =~ s/ +$//` — drop a trailing run of ASCII spaces.
fn trim_trailing_spaces(s: &mut String) {
  let trimmed = s.trim_end_matches(' ').len();
  s.truncate(trimmed);
}

/// `Decode($str, 'UTF16', 'Unknown')` → `Charset::Decompose($self, $val,
/// 'UTF16', 'Unknown')` (`Charset.pm:150-258`) for the `0x200` (UTF16) 2-byte
/// fixed-width type.
///
/// Faithful port of the byte-order resolution:
/// 1. `$byteOrder = GetByteOrder()` then mark `$unknown = 1` because the order
///    arg is `'Unknown'` (`Charset.pm:190-196`). `$fmt` is `n*` (BE) for `MM`,
///    `v*` (LE) for `II`.
/// 2. A leading BOM overrides the order and CLEARS `$unknown`
///    (`Charset.pm:203-206`): `\xfe\xff` → BE, `\xff\xfe` → LE.
/// 3. Unpack to code units (`Charset.pm:209`).
/// 4. If still `$unknown` (no BOM), run the distribution heuristic
///    (`Charset.pm:213-234`): count unique hi/lo byte values (`bh`/`bl`) and
///    zero-byte counts (`zh`/`zl`); the byte with MORE unique values should be
///    the low byte, so when `bh > bl` (or tie with `zl > zh`) the guess was
///    wrong → flip the order and re-unpack.
/// 5. Collapse UTF-16 surrogate pairs to scalar values (`Charset.pm:235-244`).
///
/// `String::from_utf16_lossy` then maps any lone surrogate to U+FFFD (Perl's
/// `pack 'U*'` keeps it; the divergence is confined to malformed input — see
/// `docs/tracking.md`). NUL-truncated by the caller's display path: ExifTool
/// keeps interior NULs in `@uni` but `ConvertExifText` callers only ever feed
/// NUL-terminated payloads; the `take_while(!= 0)` matches the observed output.
fn decode_utf16_unknown(bytes: &[u8], order: ByteOrder) -> String {
  // Step 1: seed from GetByteOrder(); 'Unknown' arg ⇒ heuristic enabled.
  let mut big_endian = order.is_big();
  let mut unknown = true;

  // Step 2: a leading BOM overrides the order and disables the heuristic.
  let body = match bytes {
    [0xFE, 0xFF, rest @ ..] => {
      big_endian = true;
      unknown = false;
      rest
    }
    [0xFF, 0xFE, rest @ ..] => {
      big_endian = false;
      unknown = false;
      rest
    }
    _ => bytes,
  };

  // Step 3: unpack to u16 code units in the current order. `chunks_exact(2)`
  // yields only full 2-byte chunks, so the `[a, b]` slice pattern is total here
  // (it skips the trailing odd byte exactly as `c[0]`/`c[1]` did); a non-2 chunk
  // is impossible and falls to `0` (unreachable).
  let unpack = |be: bool| -> std::vec::Vec<u16> {
    body
      .chunks_exact(2)
      .map(|c| match *c {
        [a, b] if be => u16::from_be_bytes([a, b]),
        [a, b] => u16::from_le_bytes([a, b]),
        _ => 0,
      })
      .collect()
  };
  let mut units = unpack(big_endian);

  // Step 4: the `Unknown` byte-distribution heuristic (Charset.pm:213-234).
  if unknown {
    let (mut bh, mut bl) = (
      std::collections::BTreeSet::new(),
      std::collections::BTreeSet::new(),
    );
    let (mut zh, mut zl) = (0usize, 0usize);
    for &u in &units {
      bh.insert(u >> 8);
      bl.insert(u & 0xff);
      if u & 0xff00 == 0 {
        zh += 1;
      }
      if u & 0x00ff == 0 {
        zl += 1;
      }
    }
    // The byte with the GREATER number of unique values should be the low
    // byte; otherwise the byte more often zero is likely the high byte.
    if bh.len() > bl.len() || (bh.len() == bl.len() && zl > zh) {
      big_endian = !big_endian;
      units = unpack(big_endian);
    }
  }

  // Step 5: NUL-terminate (caller payloads are NUL-terminated) then collapse
  // UTF-16 surrogate pairs. `String::from_utf16_lossy` handles the pairing and
  // maps any unpaired surrogate to U+FFFD. `end` is a NUL position (`< len`) or
  // `units.len()`, so `units.get(..end)` is always `Some` — the checked form of
  // `&units[..end]`.
  let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
  let mut s = String::from_utf16_lossy(units.get(..end).unwrap_or(&units));
  trim_trailing_spaces(&mut s);
  s
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); relaxed for the test module (test indexing is an
// assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn exif_text_strips_ascii_prefix() {
    // ASCII\0\0\0 + payload → payload (NUL-truncated, trailing blanks
    // trimmed). GPSProcessingMethod = "GPS" / GPSAreaInformation = "Tokyo".
    // The ASCII branch ignores byte order, so either order is fine.
    let mm = ByteOrder::Big;
    assert_eq!(convert_exif_text(b"ASCII\x00\x00\x00GPS", mm), "GPS");
    assert_eq!(convert_exif_text(b"ASCII\x00\x00\x00Tokyo", mm), "Tokyo");
    // Trailing NUL ⇒ truncate at it; trailing space ⇒ trimmed.
    assert_eq!(
      convert_exif_text(b"ASCII\x00\x00\x00GPS\x00junk", mm),
      "GPS"
    );
    assert_eq!(convert_exif_text(b"ASCII\x00\x00\x00GPS  ", mm), "GPS");
    // An all-NUL 8-byte prefix (the "undefined → ASCII" default).
    assert_eq!(
      convert_exif_text(b"\x00\x00\x00\x00\x00\x00\x00\x00GPS", mm),
      "GPS"
    );
  }

  #[test]
  fn exif_text_decodes_unicode() {
    // UNICODE\0 + UTF-16BE "Hi" under MM (big-endian) order — the guess
    // starts from GetByteOrder() == MM and stays.
    let mut v = b"UNICODE\x00".to_vec();
    v.extend_from_slice(&[0x00, b'H', 0x00, b'i']);
    assert_eq!(convert_exif_text(&v, ByteOrder::Big), "Hi");
  }

  #[test]
  fn exif_text_unicode_le_no_bom_under_le_order() {
    // UNICODE\0 + UTF-16LE "MANUAL\0" with NO BOM, decoded under II
    // (little-endian) TIFF order. ConvertExifText seeds the guess from
    // GetByteOrder() == II → reads LE directly → "MANUAL"
    // (Charset.pm:191-195). Bundled oracle:
    //   SetByteOrder("II"); ConvertExifText(...) → "MANUAL".
    let mut v = b"UNICODE\x00".to_vec();
    for c in b"MANUAL" {
      v.extend_from_slice(&[*c, 0x00]); // little-endian code units
    }
    v.extend_from_slice(&[0x00, 0x00]); // NUL terminator
    assert_eq!(convert_exif_text(&v, ByteOrder::Little), "MANUAL");
  }

  #[test]
  fn exif_text_unicode_wrong_order_heuristic_flips() {
    // UNICODE\0 + UTF-16LE "MANUAL\0" but the TIFF order is MM (big-endian),
    // as MicrosoftPhoto writes (little-endian UTF-16 even in big-endian
    // EXIF). The initial MM guess reads garbage high-byte values; the
    // distribution heuristic (Charset.pm:213-234) detects the swap and
    // flips to LE → "MANUAL". Bundled oracle returns "MANUAL" with
    // WrongByteOrder set.
    let mut v = b"UNICODE\x00".to_vec();
    for c in b"MANUAL" {
      v.extend_from_slice(&[*c, 0x00]); // little-endian code units
    }
    v.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(convert_exif_text(&v, ByteOrder::Big), "MANUAL");
  }

  #[test]
  fn exif_text_unicode_bom_overrides_order() {
    // A leading BOM overrides the seeded order and DISABLES the heuristic
    // (Charset.pm:203-206). UTF-16LE BOM + "Hi" decoded even under MM order.
    let mut v = b"UNICODE\x00".to_vec();
    v.extend_from_slice(&[0xFF, 0xFE]); // LE BOM
    v.extend_from_slice(&[b'H', 0x00, b'i', 0x00]);
    assert_eq!(convert_exif_text(&v, ByteOrder::Big), "Hi");
    // BE BOM + "Hi" decoded even under II order.
    let mut v = b"UNICODE\x00".to_vec();
    v.extend_from_slice(&[0xFE, 0xFF]); // BE BOM
    v.extend_from_slice(&[0x00, b'H', 0x00, b'i']);
    assert_eq!(convert_exif_text(&v, ByteOrder::Little), "Hi");
  }

  #[test]
  fn exif_text_too_short_is_passthrough() {
    // `length($val) < 8` ⇒ return the value unchanged (lossy UTF-8).
    assert_eq!(convert_exif_text(b"abc", ByteOrder::Big), "abc");
  }

  #[test]
  fn exif_text_invalid_encoding_keeps_prefix() {
    // An unrecognized 8-byte ID ⇒ ExifTool returns `$id . $str`.
    assert_eq!(
      convert_exif_text(b"BOGUS\x00\x00\x00xy", ByteOrder::Big),
      "BOGUS\x00\x00\x00xy"
    );
  }

  #[test]
  fn exif_text_ascii_invalid_utf8_becomes_question_mark() {
    // #200 — the ASCII-prefix payload renders invalid UTF-8 as one `?` per
    // bad byte (ExifTool `FixUTF8`, default `$bad = '?'`), NOT the Unicode
    // REPLACEMENT CHARACTER U+FFFD `from_utf8_lossy` would emit. Bundled
    // 13.59 on `UserComment = ASCII\0\0\0A\xffB` → "A?B"; the valid `é`
    // (C3 A9) passes through and each invalid byte → one `?`:
    //   ASCII\0\0\0 + A é B \xff C \xfe D → "AéB?C?D".
    let mm = ByteOrder::Big;
    assert_eq!(convert_exif_text(b"ASCII\x00\x00\x00A\xffB", mm), "A?B");
    assert_eq!(
      convert_exif_text(b"ASCII\x00\x00\x00A\xc3\xa9B\xffC\xfeD", mm),
      "AéB?C?D"
    );
    // Truncation at the first NUL still happens BEFORE FixUTF8, so an invalid
    // byte after the NUL is dropped, not turned into `?`.
    assert_eq!(
      convert_exif_text(b"ASCII\x00\x00\x00A\xffB\x00\xfe", mm),
      "A?B"
    );
  }

  #[test]
  fn exif_text_too_short_invalid_utf8_becomes_question_mark() {
    // The `< 8` passthrough arm also routes through `FixUTF8` (ExifTool fixes
    // every emitted string at the JSON boundary regardless of how it was
    // produced), so a short invalid-UTF-8 blob renders `?`, not U+FFFD.
    assert_eq!(convert_exif_text(b"A\xffB", ByteOrder::Big), "A?B");
  }

  #[test]
  fn exif_text_invalid_encoding_invalid_utf8_becomes_question_mark() {
    // The undefined-prefix `else` branch returns `$id . $str`; its invalid
    // bytes also render `?` via `FixUTF8`.
    assert_eq!(
      convert_exif_text(b"BOGUS\x00\x00\x00x\xffy", ByteOrder::Big),
      "BOGUS\x00\x00\x00x?y"
    );
  }
}
