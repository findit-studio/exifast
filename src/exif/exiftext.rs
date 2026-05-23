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
/// the payload kept as a lossy-UTF-8 string (`docs/tracking.md`). The
/// bundled fixtures use the ASCII / UNICODE prefixes.
///
/// `order` is the TIFF byte order in effect when `ConvertExifText` runs —
/// ExifTool's `Decode($str, 'UTF16', 'Unknown')` seeds the byte-order guess
/// from `GetByteOrder()` (`Charset.pm:191-195`), so the UNICODE branch must
/// be threaded the EXIF block's order rather than hard-coding big-endian.
#[must_use]
pub fn convert_exif_text(val: &[u8], order: ByteOrder) -> String {
  // `return $val if length($val) < 8` — no prefix; treat the whole blob as
  // the (lossy-UTF-8) value.
  if val.len() < 8 {
    return String::from_utf8_lossy(val).into_owned();
  }
  let id = &val[0..8];
  let payload = &val[8..];

  // `/^(ASCII)?(\0|[\0 ]+$)/` — an "ASCII" prefix (NUL- or space-padded),
  // or an all-NUL/space prefix with no name (the "undefined → ASCII"
  // default). The regex's first alternative matches a leading `\0`, the
  // second an all-`[\0 ]` 8-byte field.
  let is_ascii = {
    let after_name: &[u8] = if id.starts_with(b"ASCII") {
      &id[5..]
    } else {
      id
    };
    // First branch `(\0|...)`: a leading NUL right after the optional name.
    // Second branch `[\0 ]+$`: the remainder is all NUL/space.
    after_name.first() == Some(&0)
      || (!after_name.is_empty() && after_name.iter().all(|&b| b == 0 || b == b' '))
  };
  if is_ascii {
    // `$str =~ s/\0.*//s` — truncate at the first NUL terminator.
    let end = payload
      .iter()
      .position(|&b| b == 0)
      .unwrap_or(payload.len());
    let mut s = String::from_utf8_lossy(&payload[..end]).into_owned();
    trim_trailing_spaces(&mut s);
    return s;
  }

  // `/^(UNICODE)[\0 ]$/` — the 7-letter name plus one NUL/space byte.
  if id.starts_with(b"UNICODE") && matches!(id[7], 0 | b' ') {
    // `Decode($str, 'UTF16', 'Unknown')` — byte order is guessed starting
    // from `GetByteOrder()` (the EXIF block's order), overridden by a BOM,
    // then flipped if the byte-distribution heuristic shows the guess was
    // wrong (`Charset.pm:191-235`). MicrosoftPhoto writes little-endian even
    // in big-endian EXIF, hence the guess.
    return decode_utf16_unknown(payload, order);
  }

  // `/^(JIS)[\0 ]{5}$/` — "JIS" plus five NUL/space bytes.
  if id.starts_with(b"JIS") && id[3..8].iter().all(|&b| b == 0 || b == b' ') {
    // JIS codec not ported (see doc comment). Drop the prefix, keep the
    // payload as a lossy string so the value is at least not a binary blob.
    let mut s = String::from_utf8_lossy(payload).into_owned();
    trim_trailing_spaces(&mut s);
    return s;
  }

  // `else` — invalid encoding: ExifTool warns and returns `$id . $str`
  // (the prefix is NOT stripped). Reproduce the concatenation.
  let mut s = String::from_utf8_lossy(val).into_owned();
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

  // Step 3: unpack to u16 code units in the current order.
  let unpack = |be: bool| -> std::vec::Vec<u16> {
    body
      .chunks_exact(2)
      .map(|c| {
        if be {
          u16::from_be_bytes([c[0], c[1]])
        } else {
          u16::from_le_bytes([c[0], c[1]])
        }
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
  // maps any unpaired surrogate to U+FFFD.
  let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
  let mut s = String::from_utf16_lossy(&units[..end]);
  trim_trailing_spaces(&mut s);
  s
}

#[cfg(test)]
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
}
