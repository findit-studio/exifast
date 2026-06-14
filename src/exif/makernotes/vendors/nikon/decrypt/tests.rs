use super::*;

/// The exact NikonD2Hs.jpg `LensData0201` block: the 31 raw encrypted bytes and
/// the 31 decrypted bytes ExifTool's `-v3` dump shows after
/// `Decrypt(start=4, serial=3001006, count=2)`. Validates the cipher byte-exact
/// against the reference implementation, including the `DecryptStart => 4`
/// (the 4-byte `"0201"` version prefix stays in the clear).
#[test]
fn d2hs_lensdata0201_decrypts_byte_exact() {
  let mut block = [
    0x30, 0x32, 0x30, 0x31, 0xcb, 0xca, 0xb0, 0x32, 0xb6, 0xac, 0xa8, 0xab, 0xcd, 0x70, 0x2e, 0xbb,
    0xa7, 0xf0, 0x20, 0xa7, 0x42, 0x0a, 0x5d, 0xed, 0x7f, 0xee, 0x30, 0x45, 0x2d, 0xe8, 0x76,
  ];
  let expected = [
    0x30, 0x32, 0x30, 0x31, 0x22, 0x16, 0x12, 0x09, 0x11, 0x4a, 0x50, 0x76, 0x58, 0x50, 0x50, 0x14,
    0x14, 0x7a, 0x14, 0x16, 0x43, 0x2e, 0x47, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = block.len() - 4;
  decrypt(&mut block, 4, len, 3001006, 2);
  assert_eq!(
    block, expected,
    "D2Hs LensData0201 decrypt must be byte-exact"
  );
  // The decoded LensIDNumber lives at offset 0x0b → 0x76 == 118; MCUVersion at
  // 0x11 → 0x7a == 122 (the oracle values).
  assert_eq!(block[0x0b], 118);
  assert_eq!(block[0x11], 122);
}

/// The cipher is symmetric: decrypting twice with the same keys restores the
/// ciphertext (`Decrypt` re-encrypts on write the same way it decrypts).
#[test]
fn cipher_is_symmetric() {
  let original = [
    0x30u8, 0x32, 0x30, 0x31, 0xcb, 0xca, 0xb0, 0x32, 0xb6, 0xac, 0xa8, 0xab,
  ];
  let mut buf = original;
  let len = buf.len() - 4;
  decrypt(&mut buf, 4, len, 3001006, 2);
  decrypt(&mut buf, 4, len, 3001006, 2);
  assert_eq!(buf, original, "decrypt∘decrypt restores the input");
}

/// `start` at or past the buffer end decrypts nothing (the `$start >= length`
/// clamp) — bounds-safe on a short/empty block.
#[test]
fn start_past_end_is_noop() {
  let mut buf = [0x01u8, 0x02, 0x03];
  let before = buf;
  decrypt(&mut buf, 3, 10, 100, 5); // start == len
  assert_eq!(buf, before);
  decrypt(&mut buf, 99, 10, 100, 5); // start ≫ len
  assert_eq!(buf, before);
  let mut empty: [u8; 0] = [];
  decrypt(&mut empty, 0, 0, 100, 5); // empty block
  assert!(empty.is_empty());
}

/// `len` is clamped to `length - start`, so a `len` longer than the remaining
/// buffer never reads out of bounds — it decrypts only to the end.
#[test]
fn len_clamped_to_buffer() {
  let mut a = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60];
  let mut b = a;
  let alen = a.len();
  decrypt(&mut a, 2, alen - 2, 12345, 7); // exact remaining length
  decrypt(&mut b, 2, 1000, 12345, 7); // over-long len, same clamp
  assert_eq!(
    a, b,
    "an over-long len decrypts the same bytes as the clamped len"
  );
  // The bytes before `start` are untouched.
  assert_eq!(&a[..2], &[0x10, 0x20]);
}

/// The `count` key is the XOR fold of its four bytes: a `count` whose bytes XOR
/// to the same value produces the same `cj0` seed, so the same plaintext.
#[test]
fn count_key_is_xor_fold_of_bytes() {
  // 0x00000002 folds to 0x02; 0x00020000 also folds to 0x02.
  let plain = [0xaau8; 8];
  let mut x = plain;
  let mut y = plain;
  let n = plain.len();
  decrypt(&mut x, 0, n, 555, 0x0000_0002);
  decrypt(&mut y, 0, n, 555, 0x0002_0000);
  assert_eq!(x, y, "counts with equal XOR folds decrypt identically");
}

/// [`serial_key`] for the D2Hs numeric serial `"3001006"` is the integer
/// `3_001_006` (used verbatim).
#[test]
fn serial_key_numeric_is_verbatim() {
  assert_eq!(serial_key("3001006", Some("NIKON D2Hs")), Some(3_001_006));
  assert_eq!(serial_key("12345678", Some("NIKON D70")), Some(12_345_678));
}

/// A numeric serial is coerced via the shared 64-bit-saturating helper: exact
/// across the whole `u64` range, and a digit string EXCEEDING `u64` SATURATES
/// (Perl's 64-bit numeric model) rather than wrapping with arbitrary precision
/// (R10). Only `serial & 0xff` is consumed by the cipher; the low 32 bits are
/// returned. A `> u64` numeric serial is crafted (no real Nikon serial is 20+
/// digits) and has no portable Perl oracle.
#[test]
fn serial_key_numeric_saturates_over_u64() {
  // u64::MAX ⇒ low 32 bits 0xffff_ffff.
  assert_eq!(serial_key("18446744073709551615", None), Some(0xffff_ffff));
  // u64::MAX + 1 / + 2 saturate to u64::MAX ⇒ the same low bits.
  assert_eq!(serial_key("18446744073709551616", None), Some(0xffff_ffff));
  assert_eq!(serial_key("18446744073709551617", None), Some(0xffff_ffff));
}

/// [`serial_key`] for the D70 STRING serial `"No= 20025585"` is `0x60` (it is
/// not `/^\d+$/`, and the model is not a D50) — `Nikon.pm:13650`.
#[test]
fn serial_key_string_d70_is_0x60() {
  assert_eq!(serial_key("No= 20025585", Some("NIKON D70")), Some(0x60));
  // A non-numeric serial with no model still falls through to 0x60.
  assert_eq!(serial_key("No= 20025585", None), Some(0x60));
}

/// [`serial_key`] for a D50's string serial is `0x22` (`Nikon.pm:13649`,
/// `/\bD50$/`).
#[test]
fn serial_key_string_d50_is_0x22() {
  assert_eq!(serial_key("anything", Some("NIKON D50")), Some(0x22));
  assert_eq!(serial_key("No= 5", Some("D50")), Some(0x22));
  // `\b` boundary: a model merely ending in `...D50` glued to a word char is
  // still a boundary because `D` follows a non-word region only at the start;
  // here the char before `D50` is a space → boundary → 0x22.
  assert_eq!(serial_key("x", Some("NIKON FOO D50")), Some(0x22));
  // No `\bD50$` boundary when `D50` is glued to a preceding alphanumeric.
  assert_eq!(serial_key("x", Some("NIKOND50")), Some(0x60));
  // A numeric-looking serial wins over the D50 model branch (the `/^\d+$/`
  // test comes first).
  assert_eq!(serial_key("42", Some("NIKON D50")), Some(42));
}
