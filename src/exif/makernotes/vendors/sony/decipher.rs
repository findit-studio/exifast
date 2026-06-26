// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The Sony 0x94xx substitution cipher — `sub Decipher` (`Sony.pm:11517-11529`)
//! and its caller `sub ProcessEnciphered` (`Sony.pm:11539-11567`).
//!
//! The encrypted Sony MakerNote sub-blocks (`Tag9050x`, `Tag9400x`, `Tag9401`,
//! `Tag9402`, `Tag9403`, `Tag9404x`, `Tag9405x`, `Tag9406x`, `Tag940x`, …) are
//! scrambled with a simple BYTE substitution cipher before being parsed as a
//! `ProcessBinaryData` block. The forward (encipher) map is
//! `c = (b·b·b) mod 249` for plaintext byte `b ∈ 0..=248` (bytes `249..=255`
//! pass through unchanged); ExifTool ships the inverse as a hardcoded `tr///`
//! translation "for speed" (`Sony.pm:11520`). Because `b ↦ b³ mod 249` is a
//! BIJECTION on `0..=248` (249 is `3·83`, and the cubing map has no collisions
//! over that residue range — verified against the bundled `tr` literal), the
//! decipher map is the exact inverse: every enciphered value `2..=247` maps back
//! to a unique plaintext byte, and `0`, `1`, `248..=255` are identity.
//!
//! [`SONY_DECIPHER`] is that 256-entry inverse table, transcribed byte-for-byte
//! from the bundled `tr/<encipher-set>/\x02-\xf7/` decipher branch
//! (`Sony.pm:11527`) using Perl `tr` FIRST-occurrence semantics (there are no
//! duplicate source bytes, so the table is unambiguous). [`decipher`] applies it
//! in place, mirroring `Decipher(\$data)` — a pure per-byte substitution that
//! NEVER reads or writes out of bounds.
//!
//! Scope: the DoubleCipher path (`Sony.pm:11553-11556`, a write-bug recovery for
//! ExifTool 9.04-9.10 that applies the cipher twice) is NOT handled here — it is
//! triggered only for the `Tag9400a`/`Tag9402`/`Tag9404`/`Tag9405` variants whose
//! enciphered first byte is `\x5e`/`\xe7`/`\x04` (`Sony.pm:1847`), none of which
//! are the single-ciphered `Tag9050c`/`Tag9400c` blocks this module's callers
//! decode. A double-ciphered block would simply decode to garbage leaves (as it
//! does in ExifTool without the `DoubleCipher` flag set), never a panic.

/// `sub Decipher` (`Sony.pm:11517-11529`) — the inverse substitution table.
///
/// Index by an ENCIPHERED on-disk byte; the entry is the deciphered plaintext
/// byte. Derived from `c = (b·b·b) mod 249` (`Sony.pm:11521`): index `enc[b]`
/// holds `b` for every `b ∈ 2..=247`, and `0`, `1`, `248..=255` are identity
/// (those bytes are not translated — `Sony.pm:11522-11523`). Cross-checked
/// against the bundled `tr` decipher literal (`Sony.pm:11527`) AND against the
/// real ILME-FX3 `Tag9050c` block (the enciphered Shutter bytes
/// `97 04 24 20 54 bb` decipher to `b2 0a 30 14 54 19` = `2738 5168 6484`).
pub const SONY_DECIPHER: [u8; 256] = [
  0x00, 0x01, 0x32, 0xb1, 0x0a, 0x0e, 0x87, 0x28, 0x02, 0xcc, 0xca, 0xad, 0x1b, 0xdc, 0x08, 0xed,
  0x64, 0x86, 0xf0, 0x4f, 0x8c, 0x6c, 0xb8, 0xcb, 0x69, 0xc4, 0x2c, 0x03, 0x97, 0xb6, 0x93, 0x7c,
  0x14, 0xf3, 0xe2, 0x3e, 0x30, 0x8e, 0xd7, 0x60, 0x1c, 0xa1, 0xab, 0x37, 0xec, 0x75, 0xbe, 0x23,
  0x15, 0x6a, 0x59, 0x3f, 0xd0, 0xb9, 0x96, 0xb5, 0x50, 0x27, 0x88, 0xe3, 0x81, 0x94, 0xe0, 0xc0,
  0x04, 0x5c, 0xc6, 0xe8, 0x5f, 0x4b, 0x70, 0x38, 0x9f, 0x82, 0x80, 0x51, 0x2b, 0xc5, 0x45, 0x49,
  0x9b, 0x21, 0x52, 0x53, 0x54, 0x85, 0x0b, 0x5d, 0x61, 0xda, 0x7b, 0x55, 0x26, 0x24, 0x07, 0x6e,
  0x36, 0x5b, 0x47, 0xb7, 0xd9, 0x4a, 0xa2, 0xdf, 0xbf, 0x12, 0x25, 0xbc, 0x1e, 0x7f, 0x56, 0xea,
  0x10, 0xe6, 0xcf, 0x67, 0x4d, 0x3c, 0x91, 0x83, 0xe1, 0x31, 0xb3, 0x6f, 0xf4, 0x05, 0x8a, 0x46,
  0xc8, 0x18, 0x76, 0x68, 0xbd, 0xac, 0x92, 0x2a, 0x13, 0xe9, 0x0f, 0xa3, 0x7a, 0xdb, 0x3d, 0xd4,
  0xe7, 0x3a, 0x1a, 0x57, 0xaf, 0x20, 0x42, 0xb2, 0x9e, 0xc3, 0x8b, 0xf2, 0xd5, 0xd3, 0xa4, 0x7e,
  0x1f, 0x98, 0x9c, 0xee, 0x74, 0xa5, 0xa6, 0xa7, 0xd8, 0x5e, 0xb0, 0xb4, 0x34, 0xce, 0xa8, 0x79,
  0x77, 0x5a, 0xc1, 0x89, 0xae, 0x9a, 0x11, 0x33, 0x9d, 0xf5, 0x39, 0x19, 0x65, 0x78, 0x16, 0x71,
  0xd2, 0xa9, 0x44, 0x63, 0x40, 0x29, 0xba, 0xa0, 0x8f, 0xe4, 0xd6, 0x3b, 0x84, 0x0d, 0xc2, 0x4e,
  0x58, 0xdd, 0x99, 0x22, 0x6b, 0xc9, 0xbb, 0x17, 0x06, 0xe5, 0x7d, 0x66, 0x43, 0x62, 0xf6, 0xcd,
  0x35, 0x90, 0x2e, 0x41, 0x8d, 0x6d, 0xaa, 0x09, 0x73, 0x95, 0x0c, 0xf1, 0x1d, 0xde, 0x4c, 0x2f,
  0x2d, 0xf7, 0xd1, 0x72, 0xeb, 0xef, 0x48, 0xc7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// `Decipher(\$data)` (`Sony.pm:11552`) — apply the inverse substitution table
/// to `data` IN PLACE.
///
/// A pure per-byte map (`$$dataPt =~ tr/.../.../`): each byte is replaced by
/// [`SONY_DECIPHER`]`[byte]`. MEMORY-SAFE — the index is always a valid `u8`, so
/// the `[u8; 256]` lookup can never go out of range, and no buffer byte is read
/// or written outside `data`.
//
// The file-level `#![deny(clippy::indexing_slicing)]` (panic-safety contract) is
// relaxed for the one table lookup: `SONY_DECIPHER` is a fixed `[u8; 256]` and
// the index is a `u8 as usize` (always `0..=255`), so the access is provably in
// range — not a parsed-input panic vector.
#[allow(clippy::indexing_slicing)]
pub fn decipher(data: &mut [u8]) {
  for b in data.iter_mut() {
    *b = SONY_DECIPHER[*b as usize];
  }
}

/// `ProcessEnciphered` (`Sony.pm:11539-11567`) — take a COPY of the `len`-byte
/// cipher block at `start` in `src`, [`decipher`] it, and return the plaintext
/// for a `ProcessBinaryData` walk.
///
/// Mirrors `my $data = substr($$dataPt, $dirStart, $dirLen); Decipher(\$data);`
/// — the deciphered bytes are a fresh buffer, leaving the on-disk source
/// untouched (so the parent walk never sees scrambled-then-unscrambled bytes).
/// `start`/`len` are clamped to `src` (a hostile `DirLen` simply yields the
/// bytes that fit, the Perl `substr` truncation), so this never panics.
#[must_use]
pub fn deciphered_block(src: &[u8], start: usize, len: usize) -> std::vec::Vec<u8> {
  let end = start.saturating_add(len).min(src.len());
  let mut block = match src.get(start..end) {
    Some(s) => s.to_vec(),
    None => std::vec::Vec::new(),
  };
  decipher(&mut block);
  block
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "decipher_tests.rs"]
mod tests;
