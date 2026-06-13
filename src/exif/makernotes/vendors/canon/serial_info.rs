// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::SerialInfo` (`Canon.pm:7145-7161`).
//!
//! Binary-data sub-table — `%binaryDataAttrs` (default `FORMAT => 'int8u'`),
//! `FIRST_ENTRY => 0`, `GROUPS => { 0 => 'MakerNotes', 2 => 'Camera' }`.
//! Reached via the `Canon::Main` tag `0x96` model-conditional LIST: the FIRST
//! arm `SerialInfo` SubDirectory is selected when `$$self{Model} =~ /EOS 5D/`
//! (`Canon.pm:1835-1838`); the SECOND arm `InternalSerialNumber` is the
//! model-agnostic leaf (handled by the dispatcher, not this table).
//!
//! Two named positions (`Canon.pm:7150-7160`):
//!
//! - offset 0 `InternalSerialNumber2`, `Format => 'string[9]'` — nine bytes
//!   read as a NUL-truncated string (`ReadValue`'s `s/\0.*//s`,
//!   `ExifTool.pm:6311`), then `RawConv => '$val =~ /^\w{6}/ ? $val : undef'`
//!   (emit only when the first six characters are word characters
//!   `[A-Za-z0-9_]`; else drop the tag). Seen on 5DmkII/5DmkIII/5DmkIV/5DS/5DSR
//!   (github398) — "could be the number on a barcode sticker of the main
//!   circuit board".
//! - offset 9 `InternalSerialNumber`, `Format => 'string'` — a `string` with no
//!   `[count]` runs to the END of the binary block (`$count = $more`,
//!   `ExifTool.pm:9970`), then NUL-truncated, then the SAME `/^\w{6}/` RawConv.
//!
//! Neither position has a `PrintConv`, so the `-j` and `-n` views are identical
//! (the bare ASCII string).
//!
//! D8: this is a pure decoder (no public struct fields); it returns the
//! `(Name, TagValue)` emission pairs the dispatch site wraps in the `Canon`
//! family-1 group.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length guard and
// converted to a checked `.get()` form (re-asserts the parent `exif` deny over
// the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Canon::SerialInfo` binary block (`Canon.pm:7145-7161`) into the
/// `(Name, TagValue)` emission pairs. `print_conv` is accepted for a uniform
/// sub-table signature; there is NO `PrintConv` here, so the result is
/// identical in `-j` and `-n` (the bare ASCII string per surviving position).
///
/// `data` is the raw SerialInfo blob (`$$valPt`) — the on-disk bytes captured
/// verbatim by the body walker for the 5D `0x96` arm (no NUL-trim, no `0xff`
/// strip applied upstream). A position whose bytes are absent / fail the
/// `/^\w{6}/` RawConv is simply omitted (bundled's `RawConv => … : undef`).
#[must_use]
pub fn parse(data: &[u8], print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv; // no PrintConv in this table
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // offset 0 `InternalSerialNumber2` — `Format => 'string[9]'`: read nine
  // bytes, NUL-truncate, then `/^\w{6}/`.
  if let Some(v) = read_word_string(data.get(0..9).unwrap_or(data)) {
    out.push((SmolStr::new_static("InternalSerialNumber2"), v));
  }
  // offset 9 `InternalSerialNumber` — `Format => 'string'` with no count runs
  // to the end of the block (`$count = $more`), NUL-truncate, then `/^\w{6}/`.
  if let Some(v) = read_word_string(data.get(9..).unwrap_or(&[])) {
    out.push((SmolStr::new_static("InternalSerialNumber"), v));
  }
  out
}

/// `ReadValue` `string` decode (`ExifTool.pm:6311`: `s/\0.*//s` — truncate at
/// the first NUL) followed by the SerialInfo `RawConv` (`Canon.pm:7154`/`:7159`:
/// `$val =~ /^\w{6}/ ? $val : undef` — keep the value only when its first SIX
/// bytes are ASCII word characters `[A-Za-z0-9_]`; otherwise drop it).
///
/// The `/^\w{6}/` RawConv gate is applied to the RAW (NUL-truncated) Perl byte
/// string, matching ExifTool's evaluation order (`RawConv` runs on the byte
/// value, BEFORE JSON serialization). `\w` (no `/u` flag) matches the ASCII word
/// class, so a non-ASCII byte in the first six positions correctly fails the
/// test the same way it does in Perl's byte-string regex.
///
/// The surviving byte string is then converted to the emitted `String` via
/// [`crate::convert::fix_utf8`] — the faithful transliteration of
/// `Image::ExifTool::XMP::FixUTF8`, which the `exiftool` JSON emitter runs on
/// every extracted string (`exiftool:3822`). Each MALFORMED UTF-8 byte becomes a
/// single ASCII `?` (`0x3F`), NOT the Unicode REPLACEMENT CHARACTER U+FFFD that
/// `String::from_utf8_lossy` would emit. A value such as `b"ABC123\xff\xff\xff"`
/// (six word chars then three invalid bytes, no NUL in the first nine) PASSES the
/// `/^\w{6}/` gate on its raw bytes and serializes as `"ABC123???"` (perl oracle:
/// `Image::ExifTool::XMP::FixUTF8(\$s)` on `"ABC123\xff\xff\xff"` ⇒ `ABC123???`,
/// bytes `41 42 43 31 32 33 3f 3f 3f`); `from_utf8_lossy` would wrongly emit
/// `ABC123` + three U+FFFD, a byte-mismatch at the conformance `jsondiff` gate.
fn read_word_string(window: &[u8]) -> Option<TagValue> {
  // `s/\0.*//s` — truncate at the first NUL byte.
  let trimmed = match window.iter().position(|&b| b == 0) {
    // `nul < window.len()`, so `window.get(..nul)` is `Some` — the checked,
    // byte-identical form of `&window[..nul]`.
    Some(nul) => window.get(..nul).unwrap_or(window),
    None => window,
  };
  // `/^\w{6}/` on the RAW (NUL-truncated) bytes — require at least six leading
  // bytes, each an ASCII word char. The gate stays on the byte string (ExifTool
  // RawConv order); only the OUTPUT conversion goes through FixUTF8.
  let head = trimmed.get(..6)?;
  if head.iter().all(|&b| is_word_byte(b)) {
    Some(TagValue::Str(SmolStr::from(crate::convert::fix_utf8(
      trimmed,
    ))))
  } else {
    None
  }
}

/// Perl `\w` (ASCII, no `/u`): `[A-Za-z0-9_]`.
const fn is_word_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// Both positions valid. Oracle (`perl exiftool -G1 -j` on a crafted EOS 5D
  /// Mark III): blob `"ABC123XYZ" + "DEF456\0"` ⇒
  /// `Canon:InternalSerialNumber2 = "ABC123XYZ"`,
  /// `Canon:InternalSerialNumber = "DEF456"`.
  #[test]
  fn decodes_both_positions() {
    let blob = b"ABC123XYZDEF456\x00";
    let em = parse(blob, true);
    assert_eq!(
      find(&em, "InternalSerialNumber2"),
      Some(TagValue::Str("ABC123XYZ".into()))
    );
    assert_eq!(
      find(&em, "InternalSerialNumber"),
      Some(TagValue::Str("DEF456".into()))
    );
    assert_eq!(em.len(), 2);
    // No PrintConv ⇒ `-n` is identical.
    assert_eq!(parse(blob, false), em);
  }

  /// `string[9]` reads exactly nine bytes from offset 0, even when no NUL
  /// terminates them inside the field — bytes 9.. are the offset-9 string.
  #[test]
  fn internal_serial_number2_is_fixed_nine_bytes() {
    // Nine-byte field, then offset-9 string `"WORD12\0"`.
    let blob = b"ABCDEFGHIWORD12\x00";
    let em = parse(blob, true);
    assert_eq!(
      find(&em, "InternalSerialNumber2"),
      Some(TagValue::Str("ABCDEFGHI".into()))
    );
    assert_eq!(
      find(&em, "InternalSerialNumber"),
      Some(TagValue::Str("WORD12".into()))
    );
  }

  /// `RawConv => '$val =~ /^\w{6}/ ? $val : undef'` drops a value whose first
  /// six bytes are NOT all word characters. Oracle: a leading-`!!` offset-0
  /// blob drops `InternalSerialNumber2` but keeps the valid offset-9
  /// `InternalSerialNumber`.
  #[test]
  fn rawconv_drops_non_word_leading() {
    let blob = b"!!ABC123ZDEF456\x00";
    let em = parse(blob, true);
    assert_eq!(find(&em, "InternalSerialNumber2"), None);
    assert_eq!(
      find(&em, "InternalSerialNumber"),
      Some(TagValue::Str("DEF456".into()))
    );
    assert_eq!(em.len(), 1);
  }

  /// The `string` decode NUL-truncates BEFORE `/^\w{6}/`: exactly six word
  /// chars then a NUL passes (oracle nul6); five word chars then a NUL fails
  /// (oracle nul5).
  #[test]
  fn nul_truncation_precedes_word_test() {
    // Six word chars then NUL in the offset-0 field.
    let pass = b"ABCDEF\x00YZWORD12\x00";
    assert_eq!(
      find(&parse(pass, true), "InternalSerialNumber2"),
      Some(TagValue::Str("ABCDEF".into()))
    );
    // Five word chars then NUL ⇒ `"ABCDE"` (5 chars) fails `/^\w{6}/`.
    let fail = b"ABCDE\x00XYZWORD12\x00";
    assert_eq!(find(&parse(fail, true), "InternalSerialNumber2"), None);
  }

  /// A value whose first six bytes are word chars but whose tail holds INVALID
  /// UTF-8 bytes (no NUL in the first nine) PASSES the `/^\w{6}/` RawConv on its
  /// raw byte string and must serialize through ExifTool's `FixUTF8` — each bad
  /// byte → a single ASCII `?` (`0x3F`), NOT the U+FFFD that `from_utf8_lossy`
  /// emits. Oracle (bundled perl, the exact function `exiftool:3822` runs):
  ///   perl -Ilib -MImage::ExifTool::XMP -e 'my $s="ABC123\xff\xff\xff";
  ///         Image::ExifTool::XMP::FixUTF8(\$s); print $s' ⇒ "ABC123???"
  ///         (bytes 41 42 43 31 32 33 3f 3f 3f).
  /// This is a genuine guard: `String::from_utf8_lossy(b"ABC123\xff\xff\xff")`
  /// returns `"ABC123\u{FFFD}\u{FFFD}\u{FFFD}"`, so the assertion below FAILS
  /// under the pre-fix conversion and only passes via `fix_utf8`.
  #[test]
  fn non_utf8_survivor_uses_fix_utf8_not_lossy() {
    // Offset-0 `string[9]` field = "ABC123" + three 0xff bytes (no NUL): the
    // raw bytes pass `/^\w{6}/`, then FixUTF8 maps each 0xff to '?'.
    let blob = b"ABC123\xff\xff\xffWORD12\x00";
    let v = find(&parse(blob, true), "InternalSerialNumber2");
    assert_eq!(v, Some(TagValue::Str("ABC123???".into())));
    // Sanity: confirm the expected string is plain ASCII '?' (0x3f), not U+FFFD.
    if let Some(TagValue::Str(s)) = v {
      assert_eq!(s.as_bytes(), b"ABC123\x3f\x3f\x3f");
      assert!(!s.contains('\u{FFFD}'));
    }
    // No PrintConv ⇒ `-n` is identical.
    assert_eq!(
      find(&parse(blob, false), "InternalSerialNumber2"),
      Some(TagValue::Str("ABC123???".into()))
    );
    // Independent regression anchor: the pre-fix `from_utf8_lossy` path would
    // have produced U+FFFD, which is what we are guarding against.
    assert_eq!(
      String::from_utf8_lossy(b"ABC123\xff\xff\xff"),
      "ABC123\u{FFFD}\u{FFFD}\u{FFFD}"
    );
  }

  /// The underscore is a `\w` character; six leading underscores pass.
  #[test]
  fn underscore_is_a_word_char() {
    let blob = b"______XYZWORD12\x00";
    assert_eq!(
      find(&parse(blob, true), "InternalSerialNumber2"),
      Some(TagValue::Str("______XYZ".into()))
    );
  }

  /// A blob too short to hold a six-char offset-0 string drops
  /// `InternalSerialNumber2`; a blob with no offset-9 bytes (≤ 9 bytes) drops
  /// `InternalSerialNumber` (the empty `string` cannot match `/^\w{6}/`).
  #[test]
  fn short_blob_drops_absent_positions() {
    // Five bytes: offset-0 field is `"ABCDE"` (< 6 word chars) → dropped;
    // offset 9.. is empty → dropped.
    let em = parse(b"ABCDE", true);
    assert!(em.is_empty());
    // Exactly nine valid bytes: offset-0 passes, offset 9.. empty → dropped.
    let em = parse(b"ABCDEF123", true);
    assert_eq!(
      find(&em, "InternalSerialNumber2"),
      Some(TagValue::Str("ABCDEF123".into()))
    );
    assert_eq!(find(&em, "InternalSerialNumber"), None);
    assert_eq!(em.len(), 1);
  }
}
