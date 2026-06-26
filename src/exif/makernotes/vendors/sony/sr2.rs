// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony SR2 private-IFD decryption + the `%Sony::SR2Private` / `%Sony::SR2SubIFD`
//! / `%Sony::SR2DataIFD` tag tables (`Sony.pm:10448-10586`, `sub Decrypt`
//! `Sony.pm:11491-11512`, `sub ProcessSR2` `Sony.pm:11808-11864`).
//!
//! ARW/SR2 raws reference an ENCRYPTED private IFD through the IFD0
//! `DNGPrivateData` tag (0xc634, `Exif.pm:3607-3624`, condition
//! `$$self{TIFF_TYPE} =~ /^(ARW|SR2)$/`). That `SR2Private` directory is a plain
//! TIFF IFD carrying three data-member leaves — `SR2SubIFDOffset` (0x7200),
//! `SR2SubIFDLength` (0x7201) and `SR2SubIFDKey` (0x7221). After it is walked,
//! `ProcessSR2` reads `Length` bytes at `Offset` (file-relative), DECRYPTS the
//! block with [`decrypt`] keyed by `Key`, and walks the decrypted bytes as a
//! `%Sony::SR2SubIFD` TIFF IFD (which itself contains the `0x74c0 SR2DataIFD`
//! SubIFD pointer, walked under `%Sony::SR2DataIFD`).
//!
//! The decrypt is a deterministic 127-word LFSR keystream XORed over the block's
//! 32-bit words — there are NO per-model branches, so the whole subsystem is a
//! faithful, self-contained port shared by every ARW/SR2 body.
//!
//! The three tables are expressed as [`crate::exif::tables::ExifTag`] arrays so
//! their leaves ride the SHARED `ResolvedConv::Exif` render path (the conv set
//! they need — bare value + the `"$val mm"` focal suffix — is a subset of
//! [`crate::exif::tables::Conv`]); the family-1 group (`SR2`/`SR2SubIFD`/
//! `SR2DataIFD`) comes from the directory's [`crate::exif::IfdKind`], not the
//! table.

use crate::exif::tables::{Conv, ExifTag};

/// `%Image::ExifTool::Sony::SR2Private` (`Sony.pm:10448-10513`) — the leaf data
/// members. The two SubIFD pointers (`IDC_IFD` 0x7240 / `IDC2_IFD` 0x7241,
/// `MRWInfo` 0x7250) and `0x7240`'s SonyIDC table are deferred (`SonyIDC` is a
/// distinct converter module; the activation fixtures' verbose dumps show those
/// pointers carry no camera-metadata leaves bundled surfaces under the default
/// `-j`). The three data members drive [`crate::exif::Walker`]'s SR2
/// orchestration; their RawConv DataMember capture is performed by the walker.
/// `SR2SubIFDKey` (0x7221) carries `PrintConv => 'sprintf("0x%.8x", $val)'`
/// ([`Conv::SonyHex8`]).
pub const SR2_PRIVATE_TAGS: &[ExifTag] = &[
  ExifTag::new(0x7200, "SR2SubIFDOffset", Conv::None),
  ExifTag::new(0x7201, "SR2SubIFDLength", Conv::None),
  ExifTag::new(0x7221, "SR2SubIFDKey", Conv::SonyHex8),
];

/// `%Image::ExifTool::Sony::SR2SubIFD` (`Sony.pm:10515-10574`) — the tags in the
/// DECRYPTED SR2SubIFD. `WB_*`/`BlackLevel`/`WhiteLevel`/`ColorMatrix`/the
/// correction-param arrays are bare values (space-joined); `MaxFocalLength`/
/// `MinFocalLength` carry the `"$val mm"` suffix. `0x74c0 SR2DataIFD` is the
/// nested SubIFD pointer, handled structurally by the walker (NOT a leaf here).
pub const SR2_SUBIFD_TAGS: &[ExifTag] = &[
  ExifTag::new(0x7300, "BlackLevel", Conv::None),
  ExifTag::new(0x7302, "WB_GRBGLevelsAuto", Conv::None),
  ExifTag::new(0x7303, "WB_GRBGLevels", Conv::None),
  ExifTag::new(0x7310, "BlackLevel", Conv::None),
  ExifTag::new(0x7312, "WB_RGGBLevelsAuto", Conv::None),
  ExifTag::new(0x7313, "WB_RGGBLevels", Conv::None),
  ExifTag::new(0x7480, "WB_RGBLevelsDaylight", Conv::None),
  ExifTag::new(0x7481, "WB_RGBLevelsCloudy", Conv::None),
  ExifTag::new(0x7482, "WB_RGBLevelsTungsten", Conv::None),
  ExifTag::new(0x7483, "WB_RGBLevelsFlash", Conv::None),
  ExifTag::new(0x7484, "WB_RGBLevels4500K", Conv::None),
  ExifTag::new(0x7486, "WB_RGBLevelsFluorescent", Conv::None),
  ExifTag::new(0x74a0, "MaxApertureAtMaxFocal", Conv::None),
  ExifTag::new(0x74a1, "MaxApertureAtMinFocal", Conv::None),
  ExifTag::new(0x74a2, "MaxFocalLength", Conv::FocalLength35mm),
  ExifTag::new(0x74a3, "MinFocalLength", Conv::FocalLength35mm),
  ExifTag::new(0x7800, "ColorMatrix", Conv::None),
  ExifTag::new(0x7820, "WB_RGBLevelsDaylight", Conv::None),
  ExifTag::new(0x7821, "WB_RGBLevelsCloudy", Conv::None),
  ExifTag::new(0x7822, "WB_RGBLevelsTungsten", Conv::None),
  ExifTag::new(0x7823, "WB_RGBLevelsFlash", Conv::None),
  ExifTag::new(0x7824, "WB_RGBLevels4500K", Conv::None),
  ExifTag::new(0x7825, "WB_RGBLevelsShade", Conv::None),
  ExifTag::new(0x7826, "WB_RGBLevelsFluorescent", Conv::None),
  ExifTag::new(0x7827, "WB_RGBLevelsFluorescentP1", Conv::None),
  ExifTag::new(0x7828, "WB_RGBLevelsFluorescentP2", Conv::None),
  ExifTag::new(0x7829, "WB_RGBLevelsFluorescentM1", Conv::None),
  ExifTag::new(0x782a, "WB_RGBLevels8500K", Conv::None),
  ExifTag::new(0x782b, "WB_RGBLevels6000K", Conv::None),
  ExifTag::new(0x782c, "WB_RGBLevels3200K", Conv::None),
  ExifTag::new(0x782d, "WB_RGBLevels2500K", Conv::None),
  ExifTag::new(0x787f, "WhiteLevel", Conv::None),
  ExifTag::new(0x797d, "VignettingCorrParams", Conv::None),
  ExifTag::new(0x7980, "ChromaticAberrationCorrParams", Conv::None),
  ExifTag::new(0x7982, "DistortionCorrParams", Conv::None),
];

/// `%Image::ExifTool::Sony::SR2DataIFD` (`Sony.pm:10576-10586`) — only
/// `ColorMode` (0x7770), an ASCII string emitted verbatim (`Priority => 0`, no
/// PrintConv, so identical in `-j`/`-n`).
pub const SR2_DATA_IFD_TAGS: &[ExifTag] = &[ExifTag::new(0x7770, "ColorMode", Conv::None)];

/// The `0x74c0 SR2DataIFD` SubIFD pointer id inside `%Sony::SR2SubIFD`
/// (`Sony.pm:10545-10554`, `Flags => 'SubIFD'`, `MaxSubdirs => 20`).
pub const SR2_DATA_IFD_POINTER: u16 = 0x74c0;

/// `MaxSubdirs => 20` for the `0x74c0 SR2DataIFD` pointer (`Sony.pm:10552`, "an
/// A700 ARW has 14 of these!").
pub const SR2_DATA_IFD_MAX_SUBDIRS: usize = 20;

/// The READ-side `Format` override for an `%Sony::SR2Private` tag (`$$tagInfo
/// {Format}`, `Exif.pm:6729`). `SR2SubIFDKey` (0x7221) carries `Format =>
/// 'int32u'` (`Sony.pm:10475`): its on-disk `undef[4]` value is re-read as one
/// int32u so the key is the integer `1144201745` (the verbose "undef[4] read as
/// int32u[1]"). Without it the key stays a 4-byte `undef` block — `first_uint`
/// fails and the SR2 decrypt never runs.
#[must_use]
pub fn sr2_private_format_override(id: u16) -> Option<crate::exif::ifd::Format> {
  match id {
    0x7221 => Some(crate::exif::ifd::Format::Int32u),
    _ => None,
  }
}

/// Resolve an `%Sony::SR2Private` tag by id.
#[must_use]
pub fn sr2_private_lookup(id: u16) -> Option<&'static ExifTag> {
  SR2_PRIVATE_TAGS.iter().find(|t| t.id() == id)
}

/// Resolve an `%Sony::SR2SubIFD` tag by id. The `0x74c0` SubIFD pointer is NOT a
/// leaf here (it is descended structurally), so it returns `None`.
#[must_use]
pub fn sr2_subifd_lookup(id: u16) -> Option<&'static ExifTag> {
  SR2_SUBIFD_TAGS.iter().find(|t| t.id() == id)
}

/// Resolve an `%Sony::SR2DataIFD` tag by id.
#[must_use]
pub fn sr2_data_ifd_lookup(id: u16) -> Option<&'static ExifTag> {
  SR2_DATA_IFD_TAGS.iter().find(|t| t.id() == id)
}

/// `sub Decrypt($$$$)` (`Sony.pm:11491-11512`) — decrypt `len` bytes of `buf`
/// starting at `start`, keyed by `key`, IN PLACE.
///
/// The cipher generates a 127-entry 32-bit LFSR keystream from `key`, then XORs
/// it over the block's big-endian 32-bit words (only the first `int(len/4)`
/// whole words are transformed; trailing < 4 bytes are left untouched, exactly
/// as Perl's `unpack("x$start N$words")` / `pack('N*')` round-trip does). All
/// arithmetic is 32-bit wrapping to match Perl's `& 0xffffffff` masking.
///
/// MEMORY-SAFE: `start`/`len` are validated by the caller before this runs; the
/// per-word slice writes use checked indexing (`get_mut`) and stop at the buffer
/// end, so a `len` longer than `buf` transforms only the words that fit.
//
// The file-level `#![deny(clippy::indexing_slicing)]` (panic-safety contract) is
// relaxed for the LFSR pad math: EVERY `pad[..]` index is provably in `0..128` —
// the build loop runs `i ∈ 4..0x7f` (so `i` and `i-1..=i-4` are all `< 0x7f`),
// and the keystream loop masks every index with `& 0x7f` (≤ 0x7f) — into a fixed
// `[u32; 128]`, so no index can be out of range (an out-of-range `pad[..]` here
// is impossible, not a parsed-input panic vector). The BUFFER bytes are read
// through the checked `get_mut(off..off+4)` slice, not raw indexing.
#[allow(clippy::indexing_slicing)]
pub fn decrypt(buf: &mut [u8], start: usize, len: usize, key: u32) {
  let words = len / 4;
  // Build the pad. `pad[0..4]` from the key's LCG, then the LFSR fills 4..0x7f
  // (indices 4..=126). The XOR loop's `$pad[$i & 0x7f]` write reaches index
  // 0x7f (127) — Perl auto-extends the array there — so the pad is 128 entries
  // (index 127 is written on the loop's first iteration, never read before).
  let mut pad = [0u32; 128];
  let mut k = key;
  for slot in pad.iter_mut().take(4) {
    // `$lo = ($key & 0xffff) * 0x0edd + 1`
    let lo = (k & 0xffff).wrapping_mul(0x0edd).wrapping_add(1);
    // `$hi = ($key >> 16) * 0x0edd + ($key & 0xffff) * 0x02e9 + ($lo >> 16)`
    let hi = (k >> 16)
      .wrapping_mul(0x0edd)
      .wrapping_add((k & 0xffff).wrapping_mul(0x02e9))
      .wrapping_add(lo >> 16);
    // `$pad[$i] = $key = (($hi & 0xffff) << 16) + ($lo & 0xffff)`
    k = ((hi & 0xffff) << 16).wrapping_add(lo & 0xffff);
    *slot = k;
  }
  // `$pad[3] = ($pad[3] << 1 | ($pad[0]^$pad[2]) >> 31) & 0xffffffff`
  pad[3] = (pad[3] << 1) | ((pad[0] ^ pad[2]) >> 31);
  // `for ($i=4; $i<0x7f; ++$i) { $pad[$i] = (($pad[$i-4]^$pad[$i-2]) << 1 |
  //  ($pad[$i-3]^$pad[$i-1]) >> 31) & 0xffffffff }`
  for i in 4..0x7f {
    pad[i] = ((pad[i - 4] ^ pad[i - 2]) << 1) | ((pad[i - 3] ^ pad[i - 1]) >> 31);
  }
  // `for ($i=0x7f,$j=0; $j<$words; ++$i,++$j) {
  //   $data[$j] ^= $pad[$i & 0x7f] = $pad[($i+1) & 0x7f] ^ $pad[($i+65) & 0x7f]; }`
  // The pad is updated in place at index `$i & 0x7f` from two later taps, then
  // XORed into word `$j`. `i` runs from 0x7f upward (so `i & 0x7f` cycles
  // 0x7f,0,1,…). The two read taps (`+1`, `+65` mod 128) never alias the write
  // index (`+0`), so reading both before writing is byte-identical to Perl.
  let mut i: usize = 0x7f;
  for j in 0..words {
    let updated = pad[(i + 1) & 0x7f] ^ pad[(i + 65) & 0x7f];
    pad[i & 0x7f] = updated;
    // Word `j` lives at byte `start + j*4` as big-endian.
    let off = start.wrapping_add(j.wrapping_mul(4));
    if let Some(slot) = buf.get_mut(off..off.wrapping_add(4)) {
      let word = u32::from_be_bytes([slot[0], slot[1], slot[2], slot[3]]) ^ updated;
      slot.copy_from_slice(&word.to_be_bytes());
    } else {
      // The block is shorter than `len` words — stop (parity with Perl, where a
      // short `$$dataPt` simply has fewer words to `unpack`).
      break;
    }
    i = i.wrapping_add(1);
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` (panic-safety contract) is
// relaxed for the tests, which index fixed-layout byte buffers directly (an
// out-of-range index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "sr2_tests.rs"]
mod tests;
