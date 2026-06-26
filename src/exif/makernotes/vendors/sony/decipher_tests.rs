// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

/// The decipher table is the exact inverse of the bundled forward formula
/// `c = (b·b·b) mod 249` (`Sony.pm:11521`): `SONY_DECIPHER[enc(b)] == b` for
/// every plaintext byte `b`, with `0`, `1` and `248..=255` mapping to
/// themselves. This both pins the table to the documented formula and proves it
/// is a clean round-trip (no collisions).
#[test]
fn decipher_is_the_inverse_of_the_cube_formula() {
  for b in 0u16..=255 {
    let enc = if b <= 248 {
      ((b * b % 249) * b % 249) as u8
    } else {
      b as u8
    };
    assert_eq!(
      SONY_DECIPHER[enc as usize], b as u8,
      "decipher(encipher({b})) must round-trip"
    );
  }
}

/// Bytes 0, 1 and 248..=255 are NOT translated (`Sony.pm:11522-11523`).
#[test]
fn decipher_identity_bytes() {
  assert_eq!(SONY_DECIPHER[0], 0);
  assert_eq!(SONY_DECIPHER[1], 1);
  for b in 248u8..=255 {
    assert_eq!(SONY_DECIPHER[b as usize], b, "byte {b} is identity");
  }
}

/// Real ILME-FX3 ground truth: the enciphered `Tag9050c` Shutter bytes
/// (on-disk `97 04 24 20 54 bb` at directory offset 0x26) decipher to
/// `b2 0a 30 14 54 19` = `int16u[3]` `2738 5168 6484`. Captured from the
/// bundled `exiftool -v4` deciphered-directory dump of the activation fixture.
#[test]
fn decipher_real_fx3_shutter_bytes() {
  let mut buf = [0x97u8, 0x04, 0x24, 0x20, 0x54, 0xbb];
  decipher(&mut buf);
  assert_eq!(buf, [0xb2, 0x0a, 0x30, 0x14, 0x54, 0x19]);
  // The three little-endian int16u shutter components.
  assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2738);
  assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 5168);
  assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 6484);
}

/// `deciphered_block` copies + deciphers a window, leaving the source untouched
/// and clamping a `len` that runs past the buffer (the Perl `substr`
/// truncation), so a hostile `DirLen` never panics.
#[test]
fn deciphered_block_clamps_and_preserves_source() {
  let src = [0x00u8, 0x97, 0x04, 0x24, 0x20, 0x54, 0xbb];
  let block = deciphered_block(&src, 1, 999);
  assert_eq!(block, vec![0xb2, 0x0a, 0x30, 0x14, 0x54, 0x19]);
  // Source is unchanged.
  assert_eq!(src, [0x00, 0x97, 0x04, 0x24, 0x20, 0x54, 0xbb]);
  // A start past the end yields an empty block (no panic).
  assert!(deciphered_block(&src, 100, 4).is_empty());
}
