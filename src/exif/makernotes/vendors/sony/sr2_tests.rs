// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;
use crate::exif::tables::ExifTag;

/// The pad-generation is deterministic in `key`; the keystream's first word for
/// the fixed `SR2SubIFDKey = 0x44332211` (every ARW/SR2 body the activation set
/// uses carries this key) is a stable regression anchor. Decrypting four
/// all-zero bytes yields the first keystream word directly (`0 ^ ks == ks`).
/// The expected value was captured from the Perl `Decrypt` (`Sony.pm:11491`).
#[test]
fn decrypt_first_keystream_word_is_stable() {
  let mut buf = [0u8; 4];
  decrypt(&mut buf, 0, 4, 0x4433_2211);
  let ks = u32::from_be_bytes(buf);
  assert_eq!(
    ks, 0x54c2_c4d6,
    "first SR2 keystream word for key 0x44332211"
  );
}

/// `decrypt` transforms only whole 32-bit words (`int(len/4)`); a trailing
/// partial word and any bytes past `len` are untouched (parity with Perl's
/// `unpack`/`pack` round-trip over `$words` words). The transformed first word
/// + untouched tail are both captured from the Perl `Decrypt`.
#[test]
fn decrypt_leaves_trailing_partial_word_and_tail_untouched() {
  let mut buf = [0x11u8, 0x22, 0x33, 0x44, 0xAA, 0xBB];
  decrypt(&mut buf, 0, 6, 0x4433_2211);
  assert_eq!(
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
    0x45e0_f792,
    "first word transformed"
  );
  assert_eq!(
    &buf[4..],
    &[0xAA, 0xBB],
    "trailing partial word must be untouched"
  );
}

/// A `len` longer than the buffer must not panic — only the words that fit are
/// transformed (memory-safety guard for a hostile SR2SubIFDLength).
#[test]
fn decrypt_oversized_len_is_bounded() {
  let mut buf = [0u8; 8];
  decrypt(&mut buf, 0, 4096, 0x4433_2211);
  assert_ne!(buf, [0u8; 8]);
}

#[test]
fn sr2_lookups_resolve_known_ids() {
  assert_eq!(
    sr2_private_lookup(0x7200).map(ExifTag::name),
    Some("SR2SubIFDOffset")
  );
  assert_eq!(
    sr2_subifd_lookup(0x7313).map(ExifTag::name),
    Some("WB_RGGBLevels")
  );
  assert_eq!(
    sr2_data_ifd_lookup(0x7770).map(ExifTag::name),
    Some("ColorMode")
  );
  // The `0x74c0 SR2DataIFD` SubIFD pointer is descended structurally, not a leaf.
  assert!(sr2_subifd_lookup(0x74c0).is_none());
  assert!(sr2_subifd_lookup(0x0001).is_none());
}
