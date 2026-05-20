//! Faithful character-set decoders (`Image::ExifTool::Charset::*`).
//!
//! AIFF (AIFF.pm:53,58,63,67,115,132) uses `Decode($val, "MacRoman")` on its
//! text tags; this module ports the MacRoman → Unicode table verbatim from
//! `Image/ExifTool/Charset/MacRoman.pm` (lines 14-40). The full Charset/Recode
//! engine (multi-byte encodings, `Recode` dispatcher) is faithfully deferred
//! per spec §5 incremental discipline — the FIRST consumer (AIFF) only needs
//! the single-byte MacRoman table, so that is what this module ports.

/// MacRoman → Unicode high-byte mapping (`%Image::ExifTool::Charset::MacRoman`,
/// `lib/Image/ExifTool/Charset/MacRoman.pm:14-40`). The Perl table is sparse —
/// "The table omits 1-byte characters with the same values as Unicode" (MacRoman.pm:10)
/// — so absent entries pass through unchanged (i.e. high bytes 0xa2, 0xa3,
/// 0xa9, 0xb1, 0xb5, 0xc1 keep their MacRoman = Unicode codepoint identity).
/// Indexed 0..=0x7f are intentionally `0` here (low ASCII is identity, handled
/// by the [`decode_macroman`] fast path).
const MACROMAN_HIGH: [u32; 256] = {
  let mut t: [u32; 256] = [0; 256];
  // Low-ASCII identity (0..=0x7f) — the decoder fast-paths these without
  // consulting the table, but populate the slots for completeness.
  let mut i = 0u32;
  while i < 0x80 {
    t[i as usize] = i;
    i += 1;
  }
  // Identity high bytes (Perl table omits them: MacRoman.pm:10 "The table
  // omits 1-byte characters with the same values as Unicode"). Empirical
  // audit of MacRoman.pm:14-40 — the explicit `%Image::ExifTool::Charset::
  // MacRoman` hash has 123 entries in the 0x80..=0xff range, leaving these
  // FIVE high bytes UNLISTED and therefore identity-mapped per MacRoman.pm:
  // 10's "1-byte characters with the same values as Unicode" rule:
  //   0xa2 (¢ CENT SIGN), 0xa3 (£ POUND SIGN), 0xa9 (© COPYRIGHT SIGN),
  //   0xb1 (± PLUS-MINUS SIGN), 0xb5 (µ MICRO SIGN).
  // All other high bytes in 0x80..=0xff appear as explicit MacRoman.pm
  // entries below (e.g. 0xc1 is listed as `0xc1 => 0xa1`, NOT identity).
  t[0xa2] = 0xa2;
  t[0xa3] = 0xa3;
  t[0xa9] = 0xa9;
  t[0xb1] = 0xb1;
  t[0xb5] = 0xb5;
  // Explicit mappings — verbatim from MacRoman.pm:15-39.
  t[0x80] = 0xc4;
  t[0x81] = 0xc5;
  t[0x82] = 0xc7;
  t[0x83] = 0xc9;
  t[0x84] = 0xd1;
  t[0x85] = 0xd6;
  t[0x86] = 0xdc;
  t[0x87] = 0xe1;
  t[0x88] = 0xe0;
  t[0x89] = 0xe2;
  t[0x8a] = 0xe4;
  t[0x8b] = 0xe3;
  t[0x8c] = 0xe5;
  t[0x8d] = 0xe7;
  t[0x8e] = 0xe9;
  t[0x8f] = 0xe8;
  t[0x90] = 0xea;
  t[0x91] = 0xeb;
  t[0x92] = 0xed;
  t[0x93] = 0xec;
  t[0x94] = 0xee;
  t[0x95] = 0xef;
  t[0x96] = 0xf1;
  t[0x97] = 0xf3;
  t[0x98] = 0xf2;
  t[0x99] = 0xf4;
  t[0x9a] = 0xf6;
  t[0x9b] = 0xf5;
  t[0x9c] = 0xfa;
  t[0x9d] = 0xf9;
  t[0x9e] = 0xfb;
  t[0x9f] = 0xfc;
  t[0xa0] = 0x2020;
  t[0xa1] = 0xb0;
  t[0xa4] = 0xa7;
  t[0xa5] = 0x2022;
  t[0xa6] = 0xb6;
  t[0xa7] = 0xdf;
  t[0xa8] = 0xae;
  t[0xaa] = 0x2122;
  t[0xab] = 0xb4;
  t[0xac] = 0xa8;
  t[0xad] = 0x2260;
  t[0xae] = 0xc6;
  t[0xaf] = 0xd8;
  t[0xb0] = 0x221e;
  t[0xb2] = 0x2264;
  t[0xb3] = 0x2265;
  t[0xb4] = 0xa5;
  t[0xb6] = 0x2202;
  t[0xb7] = 0x2211;
  t[0xb8] = 0x220f;
  t[0xb9] = 0x03c0;
  t[0xba] = 0x222b;
  t[0xbb] = 0xaa;
  t[0xbc] = 0xba;
  t[0xbd] = 0x03a9;
  t[0xbe] = 0xe6;
  t[0xbf] = 0xf8;
  t[0xc0] = 0xbf;
  t[0xc1] = 0xa1;
  t[0xc2] = 0xac;
  t[0xc3] = 0x221a;
  t[0xc4] = 0x0192;
  t[0xc5] = 0x2248;
  t[0xc6] = 0x2206;
  t[0xc7] = 0xab;
  t[0xc8] = 0xbb;
  t[0xc9] = 0x2026;
  t[0xca] = 0xa0;
  t[0xcb] = 0xc0;
  t[0xcc] = 0xc3;
  t[0xcd] = 0xd5;
  t[0xce] = 0x0152;
  t[0xcf] = 0x0153;
  t[0xd0] = 0x2013;
  t[0xd1] = 0x2014;
  t[0xd2] = 0x201c;
  t[0xd3] = 0x201d;
  t[0xd4] = 0x2018;
  t[0xd5] = 0x2019;
  t[0xd6] = 0xf7;
  t[0xd7] = 0x25ca;
  t[0xd8] = 0xff;
  t[0xd9] = 0x0178;
  t[0xda] = 0x2044;
  t[0xdb] = 0x20ac;
  t[0xdc] = 0x2039;
  t[0xdd] = 0x203a;
  t[0xde] = 0xfb01;
  t[0xdf] = 0xfb02;
  t[0xe0] = 0x2021;
  t[0xe1] = 0xb7;
  t[0xe2] = 0x201a;
  t[0xe3] = 0x201e;
  t[0xe4] = 0x2030;
  t[0xe5] = 0xc2;
  t[0xe6] = 0xca;
  t[0xe7] = 0xc1;
  t[0xe8] = 0xcb;
  t[0xe9] = 0xc8;
  t[0xea] = 0xcd;
  t[0xeb] = 0xce;
  t[0xec] = 0xcf;
  t[0xed] = 0xcc;
  t[0xee] = 0xd3;
  t[0xef] = 0xd4;
  t[0xf0] = 0xf8ff;
  t[0xf1] = 0xd2;
  t[0xf2] = 0xda;
  t[0xf3] = 0xdb;
  t[0xf4] = 0xd9;
  t[0xf5] = 0x0131;
  t[0xf6] = 0x02c6;
  t[0xf7] = 0x02dc;
  t[0xf8] = 0xaf;
  t[0xf9] = 0x02d8;
  t[0xfa] = 0x02d9;
  t[0xfb] = 0x02da;
  t[0xfc] = 0xb8;
  t[0xfd] = 0x02dd;
  t[0xfe] = 0x02db;
  t[0xff] = 0x02c7;
  t
};

/// Faithful `Decode($val, "MacRoman")` (`ExifTool.pm:6333 sub Decode` →
/// `Charset::Decompose`/`Recode` with the MacRoman table). The Perl path
/// converts each input byte to its Unicode codepoint via
/// [`MACROMAN_HIGH`] (low ASCII identity, high bytes mapped), then encodes
/// the codepoints as UTF-8 (Perl: `pack 'U*', @cp` → utf8 string). Any
/// invalid 32-bit codepoint (impossible from the static table) is skipped.
#[must_use]
pub fn decode_macroman(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len());
  for &b in bytes {
    let cp = if b < 0x80 {
      u32::from(b) // low ASCII identity (table also has this, but skip the lookup)
    } else {
      MACROMAN_HIGH[b as usize]
    };
    // Every codepoint in MACROMAN_HIGH is valid Unicode (verified against
    // the source table), so `char::from_u32` always succeeds here. Defensive
    // fall-through: an unreachable mismatch maps to U+FFFD (REPLACEMENT
    // CHARACTER), preserving the panic-free guarantee.
    let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
    out.push(ch);
  }
  out
}

// `fix_utf8` is shared in `crate::convert::fix_utf8` (the canonical port of
// `Image::ExifTool::XMP::FixUTF8`, faithful to XMP.pm:2943-2974). Callers
// inside this crate use `crate::convert::fix_utf8` directly so the AIFF and
// Red ports share a single byte-walker.

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ascii_passes_through_identity() {
    assert_eq!(decode_macroman(b""), "");
    assert_eq!(decode_macroman(b"Hello"), "Hello");
    assert_eq!(decode_macroman(b"Phil Harvey"), "Phil Harvey");
    assert_eq!(decode_macroman(b"ExifTool test AIFF"), "ExifTool test AIFF");
  }

  #[test]
  fn high_bytes_map_per_macroman_pm() {
    // MacRoman.pm:15 `0x80 => 0xc4` (Ä), :39 `0xff => 0x02c7` (ˇ caron).
    assert_eq!(decode_macroman(&[0x80]), "\u{00c4}");
    assert_eq!(decode_macroman(&[0xff]), "\u{02c7}");
    // :22 `0xa5 => 0x2022` (• bullet) — multi-byte UTF-8.
    assert_eq!(decode_macroman(&[0xa5]), "\u{2022}");
    // :29 `0xc9 => 0x2026` (… ellipsis).
    assert_eq!(decode_macroman(&[0xc9]), "\u{2026}");
    // :36 `0xee => 0xd3` (Ó capital O acute).
    assert_eq!(decode_macroman(&[0xee]), "\u{00d3}");
  }

  #[test]
  fn omitted_high_bytes_are_identity_per_macroman_pm_note() {
    // MacRoman.pm:10 — bytes whose MacRoman value equals their Unicode value
    // are omitted from the table. Spot-check the five identity-only high
    // bytes; they MUST map to themselves (not to 0).
    assert_eq!(decode_macroman(&[0xa2]), "\u{00a2}"); // ¢
    assert_eq!(decode_macroman(&[0xa3]), "\u{00a3}"); // £
    assert_eq!(decode_macroman(&[0xa9]), "\u{00a9}"); // ©
    assert_eq!(decode_macroman(&[0xb1]), "\u{00b1}"); // ±
    assert_eq!(decode_macroman(&[0xb5]), "\u{00b5}"); // µ
  }

  #[test]
  fn mixed_ascii_and_high_bytes() {
    // "Copyright \xa9 2026" → "Copyright © 2026" (0xa9 is identity, U+00A9).
    let v = b"Copyright \xa9 2026";
    assert_eq!(decode_macroman(v), "Copyright \u{00a9} 2026");
  }

  // `fix_utf8` tests live in `crate::convert::tests` (the canonical port).
}
