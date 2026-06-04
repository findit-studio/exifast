// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "h264")]
//! Faithful port of `Image::ExifTool::H264` (lib/Image/ExifTool/H264.pm).
//!
//! H.264 video is a stream of **NAL units** (Network Abstraction Layer),
//! each introduced by a start code (`00 00 01` or `00 00 00 01`). The first
//! byte after the start code is the NAL header; its low 5 bits are the
//! `nal_unit_type`. `ProcessH264Video` (H264.pm:1032-1105) scans the stream
//! for two NAL types:
//!
//! - **`0x07` — sequence parameter set (SPS)**: an Exp-Golomb-coded bitstream
//!   whose fields yield `ImageWidth` / `ImageHeight` (H264.pm:730-847
//!   `ParseSeqParamSet`).
//! - **`0x06` — supplemental enhancement information (SEI)**: a series of
//!   `(type, size, payload)` messages. Payload type 5 ("user data
//!   unregistered") carries a 16-byte UUID; the UUID
//!   `17ee8c60f84d11d98cd60800200c9a66` followed by `"MDPM"` is the
//!   *Modified Digital Video Pack Metadata* block written by AVCHD
//!   camcorders (H264.pm:930-1026 `ProcessSEI`).
//!
//! ## RBSP de-escaping (H264.pm:1063-1070)
//!
//! Within a NAL unit, the encoder inserts an *emulation-prevention* byte
//! `0x03` after any `00 00` pair that would otherwise be followed by a byte
//! `≤ 0x03` (so the payload can never accidentally contain a start code).
//! The reader strips every `00 00 03` back to `00 00` before interpreting
//! the NAL body.
//!
//! ## MDPM records (H264.pm:986-1023)
//!
//! The MDPM payload is a count byte followed by that many 5-byte records:
//! a 1-byte tag id + 4 data bytes. Records MUST appear in ascending tag-id
//! order (H264.pm:988-991 — out-of-order ⇒ `Warn` + stop). Some tags set
//! `Combine => N`, meaning the next `N` consecutive-id records' data bytes
//! are concatenated onto this tag's value (H264.pm:1002-1014) — used for
//! multi-word values like `GPSLatitude` (deg/min/sec across `0xb2`/`0xb3`/
//! `0xb4`).
//!
//! ## Engine-only — no standalone file type
//!
//! ExifTool exposes H264 ONLY as an engine module: `M2TS::ProcessM2TS`
//! de-packetizes the transport-stream PES payload and calls
//! `H264::ParseH264Video` on the assembled byte stream (M2TS.pm:343-346).
//! A raw `.h264` NAL file has no `%magicNumber` / `%fileTypeLookup` entry,
//! so bundled `exiftool` reports `Unknown file type` for one. This port
//! therefore ships the typed [`H264Meta`] + [`parse_borrowed`] for a future
//! M2TS / MPEG port to consume, and is conformance-tested directly against
//! the bundled `ParseH264Video` output (see `tests/conformance.rs`
//! `h264_conformance` + the unit tests below) rather than through the
//! file-type-dispatched `extract_info` path.

// Golden-v2 Contract 3c (Phase C, slice w2a): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;
use std::{borrow::Cow, vec::Vec};

use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// MDPM UUID (H264.pm:971-972)
// ===========================================================================

/// The 16-byte UUID + 4-byte `"MDPM"` tag that introduces a *Modified
/// Digital Video Pack Metadata* block inside an SEI type-5 ("user data
/// unregistered") payload (H264.pm:971-972).
pub const MDPM_UUID_TAG: [u8; 20] = [
  0x17, 0xee, 0x8c, 0x60, 0xf8, 0x4d, 0x11, 0xd9, 0x8c, 0xd6, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66,
  b'M', b'D', b'P', b'M',
];

// ===========================================================================
// Camera-manufacturer lookup (H264.pm:35-40 `%convMake`)
// ===========================================================================

/// `%convMake` (H264.pm:35-40) — the MakeModel `Make` word → manufacturer
/// name table. Returns `None` for an unmapped id (Perl `|| 'Unknown'` —
/// handled by the caller).
#[must_use]
pub const fn conv_make(id: u16) -> Option<&'static str> {
  match id {
    0x0103 => Some("Panasonic"),
    0x0108 => Some("Sony"),
    0x1011 => Some("Canon"),
    0x1104 => Some("JVC"),
    _ => None,
  }
}

// ===========================================================================
// Exp-Golomb bitstream (H264.pm:583-703)
// ===========================================================================

/// Big-endian bit reader over a NAL RBSP, faithful to the bitstream helpers
/// in H264.pm:583-703 (`NewBitStream` / `ReadNextWord` / `GetIntN` /
/// `GetGolomb` / `GetGolombS`). The Perl object tracks `Mask`/`Pos`/`Word`;
/// here a single monotonically-increasing bit cursor over `data` is
/// equivalent and simpler.
struct BitStream<'a> {
  data: &'a [u8],
  /// Absolute bit position (0 = MSB of byte 0).
  bit_pos: usize,
}

impl<'a> BitStream<'a> {
  /// `NewBitStream` (H264.pm:627-638) — `None` when `data` is empty (Perl
  /// `ReadNextWord` fails ⇒ `undef $bstr`).
  const fn new(data: &'a [u8]) -> Option<Self> {
    if data.is_empty() {
      return None;
    }
    Some(Self { data, bit_pos: 0 })
  }

  /// Bits remaining (`BitsLeft`, H264.pm:644-654).
  const fn bits_left(&self) -> usize {
    let total = self.data.len() * 8;
    if self.bit_pos >= total {
      0
    } else {
      total - self.bit_pos
    }
  }

  /// `GetIntN` (H264.pm:660-671) — read `bits` bits as an unsigned integer,
  /// MSB first.
  ///
  /// Faithful EOF semantics: Perl's loop is `while ($bits--) { $val <<= 1;
  /// ... ReadNextWord($bstr) or last; }`. Once the bitstream is exhausted
  /// the `or last` exits the **entire** loop, so the remaining `$val <<= 1`
  /// shifts never happen — a past-EOF `GetIntN` returns the value of the
  /// bits actually read, NOT that value left-shifted by the missing count
  /// (verified against bundled `GetIntN`: 8 real bits `0xff` then
  /// `GetIntN(20)` over 8 zero bits ⇒ `0`, and `GetIntN(70)` on one `0xff`
  /// byte ⇒ `255`). The earlier port kept iterating and shifting, which both
  /// diverged from Perl and could `<<` a `u64` past 63 (UB in an overflow-
  /// checking build); breaking at EOF removes both problems.
  ///
  /// Perl's accumulator `$val <<= 1` is a native `UV` whose left-shift
  /// wraps (truncates) at 64 bits — `1 << 64 == 0`, and a 64-bit-plus run of
  /// real bits saturates to the low 64 (bundled-verified: 70 one-bits ⇒
  /// `0xffff_ffff_ffff_ffff`). The `u64` `<<= 1` here reproduces that wrap
  /// exactly (one bit at a time never trips the `<< 64` UB). `bits` is
  /// `usize` because `GetGolomb` can request `count + 1` bits with `count`
  /// as large as the whole bitstream (≤ `8 * data.len()`), which can exceed
  /// `u32::MAX` for a multi-hundred-MB NAL; the EOF `break` stops the loop
  /// long before that many iterations actually run.
  fn get_int_n(&mut self, bits: usize) -> u64 {
    let mut val: u64 = 0;
    let total = self.data.len() * 8;
    for _ in 0..bits {
      // Perl `ReadNextWord ... or last` — exhausted ⇒ stop the whole loop.
      if self.bit_pos >= total {
        break;
      }
      val <<= 1;
      // The `bit_pos >= total` guard above (`total == data.len()*8`) proves
      // `bit_pos >> 3 < data.len()`, so `.get()` always hits; the `0` fallback
      // is unreachable (byte-identical to the raw index).
      let byte = self.data.get(self.bit_pos >> 3).copied().unwrap_or(0);
      let bit = (byte >> (7 - (self.bit_pos & 7))) & 1;
      val |= u64::from(bit);
      self.bit_pos += 1;
    }
    val
  }

  /// `GetGolomb` (H264.pm:677-689) — unsigned Exp-Golomb:
  ///
  /// ```text
  /// my $count = 0;
  /// until ($$bstr{Mask} & $$bstr{Word}) {           # peek, don't consume
  ///     ++$count;
  ///     $$bstr{Mask} >>= 1 and next;
  ///     ReadNextWord($bstr) or last;                # EOF
  /// }
  /// return GetIntN($bstr, $count + 1) - 1;
  /// ```
  ///
  /// The `until` loop **peeks** the next bit and stops on the first 1-bit
  /// *without consuming it* (bundled-verified: after the loop the cursor is
  /// still on the 1-bit, so a following `GetIntN(1)` reads `1`). The value is
  /// then `GetIntN(count + 1) - 1`, where the `count + 1` bits start AT that
  /// 1-bit (its MSB). We mirror that exactly: count zeros without consuming
  /// the 1-bit, then `get_int_n(count + 1)` reads the 1-bit plus the `count`
  /// suffix bits as one `u64`.
  ///
  /// The return type is **`i128`** to carry Perl's full result domain
  /// faithfully. `GetIntN` is a native `UV` (`0..=u64::MAX`), so its result
  /// is genuinely **unsigned**, and Perl's `... - 1` keeps a large `UV`
  /// large (`13835058055282163711 - 1`, not a negative). The only way the
  /// result goes negative is `GetIntN == 0` ⇒ `0 - 1 = -1`, which happens
  /// (a) at EOF before any 1-bit (`count + 1` past-EOF zero bits ⇒ `0`) and
  /// (b) when a 1-bit IS found but `count >= 64` with a zero suffix, because
  /// the implicit leading 1 shifts clean out of the 64-bit `UV`
  /// (bundled-verified: 64 zeros + 1 + 64-bit zero suffix ⇒ `GetGolomb = -1`,
  /// 100 zeros + zero suffix ⇒ `-1`). `i128::from(value) - 1` reproduces both
  /// the negative `-1` cases AND every large positive `UV` exactly, with no
  /// sign flip.
  ///
  /// The earlier port (a) cast the `u64` to `i64`, turning Perl's huge
  /// **unsigned** Golomb into a **signed negative** (which `ParseSeqParamSet`
  /// then wrapped back into the 160..=4096 validity window — fabricating a
  /// bogus `ImageWidth`/`ImageHeight`), and (b) synthesised the leading 1
  /// as `1u64 << count.min(63)`, which is wrong for any non-EOF `count >= 64`
  /// (Perl's leading 1 has already shifted out). Reading `count + 1` bits
  /// directly through `get_int_n` fixes both. `count` is `usize` so a
  /// multi-hundred-MB all-zero NAL cannot overflow it (the old `u32`
  /// `count += 1` could).
  fn get_golomb(&mut self) -> i128 {
    let total = self.data.len() * 8;
    // Peek-count leading zeros: stop on the first 1-bit WITHOUT consuming
    // it, or when the bitstream is exhausted (Perl `ReadNextWord ... or
    // last`). `count` is `usize` (bounded by `total`); it cannot overflow.
    let mut count: usize = 0;
    while self.bit_pos < total {
      // `bit_pos < total` (`total == data.len()*8`) ⇒ `bit_pos >> 3 <
      // data.len()`, so `.get()` always hits; `0` fallback is unreachable.
      let byte = self.data.get(self.bit_pos >> 3).copied().unwrap_or(0);
      let bit = (byte >> (7 - (self.bit_pos & 7))) & 1;
      if bit == 1 {
        break; // 1-bit found — leave the cursor ON it (Perl peeks).
      }
      count += 1;
      self.bit_pos += 1;
    }
    // `GetIntN(count + 1)` reads the (still-unconsumed) 1-bit as the MSB plus
    // the `count` suffix bits, `u64`-wrapping and EOF-safe. At full EOF it
    // returns 0; for `count >= 64` with a zero suffix the leading 1 wraps
    // out ⇒ 0. Either way `value - 1 == -1`, matching Perl.
    let value = self.get_int_n(count + 1);
    i128::from(value) - 1
  }

  /// `GetGolombS` (H264.pm:695-700) — signed Exp-Golomb. `my $val =
  /// GetGolomb($bstr) + 1; ($val & 1) ? -($val >> 1) : ($val >> 1)`. At EOF
  /// `GetGolomb` is `-1` ⇒ `$val = 0` ⇒ result `0` (bundled-verified). The
  /// `i128` domain holds `GetGolomb + 1` for every `u64` Golomb (the largest,
  /// `u64::MAX`, becomes `2^64` — well within `i128`) so the `& 1` / `>> 1`
  /// split is exact. (Perl promotes that single `2^64` boundary to a float
  /// and loses one ULP, but `GetGolombS` is only used by
  /// `DecodeScalingMatrices` to advance — and then discard — the SPS cursor
  /// via a `& 0xff` mask, so the i128-exact value is the right faithful
  /// choice for the bits that actually matter.)
  fn get_golomb_s(&mut self) -> i128 {
    let val = self.get_golomb() + 1;
    if val & 1 != 0 { -(val >> 1) } else { val >> 1 }
  }
}

/// `DecodeScalingMatrices` (H264.pm:709-724) — consumes the scaling-list
/// bits so the SPS cursor stays aligned. The decoded values are discarded
/// (ExifTool only wants the image size).
fn decode_scaling_matrices(bs: &mut BitStream<'_>) {
  if bs.get_int_n(1) != 0 {
    for i in 0..8u32 {
      let size = if i < 6 { 16 } else { 64 };
      if bs.get_int_n(1) == 0 {
        continue;
      }
      // H264.pm:717 — `my ($last, $next) = (8, 8)`. `$last` is never
      // reassigned in the bundled loop (a faithful quirk), so it stays 8.
      // `i128` to match `get_golomb_s`; `& 0xff` takes the two's-complement
      // low byte exactly as Perl does for a negative sum (bundled-verified).
      let last: i128 = 8;
      let mut next: i128 = 8;
      for j in 0..size {
        if next != 0 {
          next = (last + bs.get_golomb_s()) & 0xff;
        }
        // H264.pm:720 — `last unless $j or $next`.
        if j != 0 && next == 0 {
          break;
        }
      }
    }
  }
}

/// Result of [`parse_seq_param_set`]: the decoded picture size, when it
/// passes ExifTool's sanity bounds (H264.pm:788).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PictureSize {
  width: u32,
  height: u32,
}

/// `ParseSeqParamSet` (H264.pm:730-792, image-size portion only). The VUI /
/// picture-timing tail (H264.pm:794-847) is gated behind the test-only
/// `$parsePictureTiming` flag in Perl (`my $parsePictureTiming;` —
/// H264.pm:32, never set in production), so it is intentionally not ported.
///
/// Returns `Some(PictureSize)` only when the decoded `width`/`height` fall
/// inside ExifTool's validity window (`160..=4096` × `120..=3072`,
/// H264.pm:788); otherwise `None` (Perl emits nothing).
fn parse_seq_param_set(rbsp: &[u8]) -> Option<PictureSize> {
  let mut bs = BitStream::new(rbsp)?;

  let profile_idc = bs.get_int_n(8); // profile_idc
  let _ = bs.get_int_n(16); // constraint flags + level_idc
  let _ = bs.get_golomb(); // seq_parameter_set_id
  if profile_idc >= 100 {
    let chroma_format_idc = bs.get_golomb(); // chroma_format_idc
    if chroma_format_idc == 3 {
      let _ = bs.get_int_n(1); // separate_colour_plane_flag
    }
    let _ = bs.get_golomb(); // bit_depth_luma_minus8
    let _ = bs.get_golomb(); // bit_depth_chroma_minus8
    let _ = bs.get_int_n(1); // qpprime_y_zero_transform_bypass_flag
    decode_scaling_matrices(&mut bs);
  }
  let _ = bs.get_golomb(); // log2_max_frame_num_minus4
  let pic_order_cnt_type = bs.get_golomb(); // pic_order_cnt_type
  if pic_order_cnt_type == 0 {
    let _ = bs.get_golomb(); // log2_max_pic_order_cnt_lsb_minus4
  } else if pic_order_cnt_type == 1 {
    let _ = bs.get_int_n(1); // delta_pic_order_always_zero_flag
    let _ = bs.get_golomb(); // offset_for_non_ref_pic
    let _ = bs.get_golomb(); // offset_for_top_to_bottom_field
    let n = bs.get_golomb(); // num_ref_frames_in_pic_order_cnt_cycle
    // H264.pm:763 — `for ($i=0; $i<$n; ++$i)`. `$n` is a Golomb value; a
    // negative `-1` (EOF) makes the loop run zero times, exactly like
    // `0..n` over a non-positive `i128`.
    let mut i: i128 = 0;
    while i < n {
      let _ = bs.get_golomb(); // offset_for_ref_frame[i]
      i += 1;
    }
  }
  let _ = bs.get_golomb(); // num_ref_frames
  let _ = bs.get_int_n(1); // gaps_in_frame_num_value_allowed_flag
  // H264.pm:769-784 — all the size arithmetic uses native Perl numbers. A
  // Golomb value can be `-1` (EOF) OR a huge unsigned (`0..=u64::MAX`); Perl
  // does the `(w + 1) * 16` etc. as ordinary integer math that **promotes to
  // a float when it overflows `UV`** (bundled-verified: a 63-leading-zero
  // Golomb gives `w ≈ 9.2e18`, `(w + 1) * 16 ≈ 1.5e20` as a float). The
  // float never wraps, so an over-`UV` product stays monotonically huge and
  // fails the `<= 4096` window check. `i128` reproduces that faithfully: it
  // holds every `(u64 + 1) * 16` (and the crop subtractions) without
  // overflow, so checked arithmetic here keeps the huge values huge instead
  // of `wrapping_mul`-ing them back into the validity window (the bug that
  // let a crafted SPS fabricate a 160×128 `ImageWidth`/`ImageHeight`).
  let w_mbs: i128 = bs.get_golomb(); // pic_width_in_mbs_minus1
  let h_map: i128 = bs.get_golomb(); // pic_height_in_map_units_minus1
  let frame_mbs_only: i128 = i128::from(bs.get_int_n(1)); // frame_mbs_only_flag
  if frame_mbs_only == 0 {
    let _ = bs.get_int_n(1); // mb_adaptive_frame_field_flag
  }
  let _ = bs.get_int_n(1); // direct_8x8_inference_flag

  // H264.pm:775-776 — convert to pixels.
  let mut width: i128 = (w_mbs + 1) * 16;
  let mut height: i128 = (2 - frame_mbs_only) * (h_map + 1) * 16;

  // H264.pm:778-785 — account for cropping.
  if bs.get_int_n(1) != 0 {
    let m: i128 = 4 - frame_mbs_only * 2;
    width -= 4 * bs.get_golomb();
    width -= 4 * bs.get_golomb();
    height -= m * bs.get_golomb();
    height -= m * bs.get_golomb();
  }

  // H264.pm:787 — `return unless $$bstr{Mask}`. The Perl `Mask` word is 0
  // exactly when `ReadNextWord` has exhausted the bitstream — i.e. every bit
  // has been consumed. A truncated SPS (or one with a 64-bit-plus leading-
  // zero Exp-Golomb run, which drains the reader) therefore drops the size
  // here, BEFORE the validity-window check, just as Perl does.
  if bs.bits_left() == 0 {
    return None;
  }
  // H264.pm:788 — `if ($w>=160 and $w<=4096 and $h>=120 and $h<=3072)`.
  if (160..=4096).contains(&width) && (120..=3072).contains(&height) {
    Some(PictureSize {
      width: width as u32,
      height: height as u32,
    })
  } else {
    None
  }
}

// ===========================================================================
// MDPM tag table (H264.pm:56-422 `%Image::ExifTool::H264::MDPM`)
// ===========================================================================

/// The post-decode conversion applied to an MDPM `rational32u`/`rational32s`
/// tag — one variant per distinct `ValueConv`/`PrintConv` pairing in the
/// bundled MDPM table (H264.pm:153-369).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RationalConv {
  /// No `ValueConv`; `-j` = `-n` = the bare `RoundFloat(n/d, 7)` quotient.
  /// `0xa1 FNumber`, `0xa3 BrightnessValue`, `0xba GPSAltitude`,
  /// `0xc0 GPSDOP`, `0xc2 GPSSpeed`, `0xc4 GPSTrack`, `0xc6 GPSImgDirection`
  /// (H264.pm:159-163/179-183/290-370).
  Plain,
  /// `0xa0 ExposureTime` — `PrintConv => PrintExposureTime` (H264.pm:153-158).
  ExposureTime,
  /// `0xa4 ExposureCompensation` — `PrintConv => PrintFraction`
  /// (H264.pm:184-189).
  ExposureCompensation,
  /// `0xa5 MaxApertureValue` — `ValueConv => '2 ** ($val / 2)'`,
  /// `PrintConv => 'sprintf("%.1f",$val)'` (H264.pm:190-195).
  MaxApertureValue,
  /// `0xa9 FocalLengthIn35mmFormat` — `PrintConv => '"$val mm"'`
  /// (H264.pm:221-225).
  FocalLength35,
  /// `0xb2 GPSLatitude` / `0xb6 GPSLongitude` — `Combine => 2`,
  /// `ValueConv => GPS::ToDegrees`, `PrintConv => GPS::ToDMS`
  /// (H264.pm:253-279).
  GpsCoordinate,
  /// `0xbb GPSTimeStamp` — `Combine => 2`, `ValueConv => ConvertTimeStamp`,
  /// `PrintConv => PrintTimeStamp` (H264.pm:295-303).
  GpsTimeStamp,
}

/// The post-decode conversion applied to an MDPM `string`-format tag
/// (H264.pm:244-387).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringConv {
  /// Plain string passthrough — `0xc7 GPSMapDatum` (H264.pm:371-377). Same
  /// spelling for `-j`/`-n`. GPSMapDatum has **no** `RawConv`, so an empty
  /// (all-NUL) buffer is still emitted as an empty string (`""`) — bundled
  /// `ParseH264Video`/`HandleTag` produce a present-but-empty `GPS:GPSMapDatum`
  /// in both `-j` and `-n`.
  Plain,
  /// Plain string with the Sony `0xe4 Model` drop-empty `RawConv`
  /// (`'$val eq "" ? undef : $val'`, H264.pm:410): a non-empty value passes
  /// through unchanged, an empty string yields **no tag**. This is the ONLY
  /// MDPM string tag that drops the empty case — it must stay distinct from
  /// the GPS string tags ([`StringConv::Plain`] / [`StringConv::ExifDate`]),
  /// which have no `RawConv` and emit `""`.
  PlainDropEmpty,
  /// `0xca GPSDateStamp` — `ValueConv => Exif::ExifDate` (H264.pm:380-387).
  /// Like [`StringConv::Plain`] there is no `RawConv`, so an empty buffer is
  /// emitted as `""` (`ExifDate("")` returns `""`, Exif.pm:6068-6076).
  ExifDate,
  /// A single-character → label PrintConv map (H264.pm:244-364 — the GPS
  /// `*Ref` / `GPSStatus` / `GPSMeasureMode` tags). `-n` keeps the raw
  /// string, `-j` maps it (off-map ⇒ raw).
  Enum(&'static [(&'static str, &'static str)]),
}

/// What kind of value an MDPM tag carries — drives both decode and the
/// `-j`/`-n` rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MdpmKind {
  /// `0x13 TimeCode` (H264.pm:87-91) — `ValueConv` reverses the 4 data bytes
  /// and prints them as `%.2x:%.2x:%.2x:%.2x`. Same string for `-j`/`-n`.
  TimeCode,
  /// `0x18 DateTimeOriginal` (H264.pm:96-116) — `Combine => 1`; 8 bytes
  /// (this tag's 4 + the next tag's 4). First byte = timezone packing, the
  /// remaining 7 are BCD date/time. `-j` further runs `ConvertDateTime`.
  DateTimeOriginal,
  /// An `int32u`-format tag with a numeric → label PrintConv map
  /// (H264.pm:164-235 — ExposureProgram / CustomRendered / WhiteBalance /
  /// SceneCaptureType / GPSAltitudeRef). `-n` emits the raw integer; `-j`
  /// emits the mapped label (or the bare integer when off-map).
  Int32uEnum(&'static [(u32, &'static str)]),
  /// `0xa6 Flash` — `int32u`, `Flags => 'PrintHex'`, `PrintConv` = the
  /// shared `%Exif::flash` map (H264.pm:196-202). `-n` emits the decimal
  /// integer; `-j` emits the mapped label (or `0x%x` when off-map).
  Flash,
  /// `0xb9 GPSAltitudeRef` — `int32u`, `ValueConv => '$val ? 1 : 0'`,
  /// `PrintConv => {0 => 'Above Sea Level', 1 => 'Below Sea Level'}`
  /// (H264.pm:280-289). The ValueConv collapses the raw `int32u` to `0`/`1`
  /// FIRST, so `-n` emits the collapsed `0`/`1` (not the raw word).
  GpsAltitudeRef,
  /// `0xb0 GPSVersionID` — `Format => 'int8u', Count => 4`,
  /// `PrintConv => '$val =~ tr/ /./; $val'` (H264.pm:237-243). `-n` = the
  /// four bytes space-joined (`"2 3 0 0"`), `-j` = dot-joined (`"2.3.0.0"`).
  GpsVersionId,
  /// A `rational32u`/`rational32s` tag — the 4 data bytes are a big-endian
  /// 16/16 rational (`GetRational32*`, `ExifTool.pm:6081-6095`); `signed`
  /// selects `rational32s`. `Combine => 2` tags (GPS lat/long/time) widen
  /// the buffer to 3 rationals (H264.pm:153-370).
  Rational { signed: bool, conv: RationalConv },
  /// A `string`-format tag (H264.pm:244-411).
  Str(StringConv),
  /// A subdirectory: the 4 data bytes are themselves a `ProcessBinaryData`
  /// block (H264.pm:129-152/388-419 — Camera1 / Camera2 / Shutter /
  /// MakeModel / RecInfo / FrameInfo).
  SubDir(SubDirKind),
}

/// Which binary subdirectory an MDPM `SubDir` tag dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubDirKind {
  /// `0x70` Camera1 (H264.pm:425-479) — big-endian byte table.
  Camera1,
  /// `0x71` Camera2 (H264.pm:481-502) — big-endian byte table.
  Camera2,
  /// `0x7f` Shutter (H264.pm:504-519) — **little-endian** `int16u` table
  /// (H264.pm:150 `ByteOrder => 'LittleEndian'`).
  Shutter,
  /// `0xe0` MakeModel (H264.pm:521-550) — big-endian `int16u` table; word 0
  /// is `Make` (and records `$$self{Make}` for later `Condition`s).
  MakeModel,
  /// `0xe1` RecInfo (H264.pm:553-569) — `int8u` table, Canon-only.
  RecInfo,
  /// `0xee` FrameInfo (H264.pm:572-581) — `int8u` table, Canon-only.
  FrameInfo,
}

/// A bundled `Condition => '$$self{Make} eq "…"'` gate (H264.pm:396/405/417).
/// The MDPM block carries `Make` only when a `0xe0` MakeModel record has
/// already been walked (records are id-ordered, so `0xe0` always precedes
/// `0xe1`/`0xe4`/`0xee`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MakeCondition {
  /// No `Condition` — always extracted.
  Any,
  /// `Condition => '$$self{Make} eq "Canon"'` (H264.pm:396/417).
  Canon,
  /// `Condition => '$$self{Make} eq "Sony"'` (H264.pm:405).
  Sony,
}

/// One MDPM tag descriptor (H264.pm:56-422 entries).
#[derive(Debug, Clone, Copy)]
struct MdpmTag {
  /// MDPM tag id (the record's first byte).
  id: u8,
  /// `Name => '…'`.
  name: &'static str,
  /// Decode/render semantics.
  kind: MdpmKind,
  /// `Combine => N` (H264.pm:101/258/275/…): absorb the next `N`
  /// consecutive-id records' 4 data bytes. `0` for a plain single-word tag.
  combine: u8,
  /// `Condition => '$$self{Make} eq "…"'` (H264.pm:396/405/417).
  condition: MakeCondition,
  /// The family-1 group (`Groups => { 1 => '…' }`). `H264` for everything
  /// except the GPS block (H264.pm:241-387), which sets `GPS` (Codex R5 F1).
  group: H264Group,
  /// The `FoundTag` priority (`Priority => N`, ExifTool.pm:9458). `Normal` for
  /// every MDPM tag except the top-level `0xa8 WhiteBalance` (`Priority => 0`,
  /// H264.pm:215), which is `Low` so it does not overwrite the higher-priority
  /// Camera1 `WhiteBalance` (H264.pm:460-470).
  priority: H264Priority,
}

/// Build an [`MdpmTag`] in the family-1 `H264` group with no `Combine` and no
/// `Condition` — the common case. Keeps [`MDPM_TABLE`] readable without full
/// field literals everywhere.
const fn tag(id: u8, name: &'static str, kind: MdpmKind) -> MdpmTag {
  MdpmTag {
    id,
    name,
    kind,
    combine: 0,
    condition: MakeCondition::Any,
    group: H264Group::H264,
    priority: H264Priority::Normal,
  }
}

/// Build a family-1 `GPS`-group MDPM tag with no `Combine` (the simple GPS
/// scalar/string tags, H264.pm:241-387 — `Groups => { 1 => 'GPS' }`).
const fn gps_tag(id: u8, name: &'static str, kind: MdpmKind) -> MdpmTag {
  MdpmTag {
    id,
    name,
    kind,
    combine: 0,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  }
}

/// MDPM tag table — the COMPLETE port of `%Image::ExifTool::H264::MDPM`
/// (H264.pm:56-422). Every entry with a concrete `Name` is present; the many
/// commented-out `# 0xNN - …` lines in the Perl source are unnamed
/// (ExifTool's `GetTagInfo` returns nothing for them, so no tag is emitted)
/// and are intentionally absent.
const MDPM_TABLE: &[MdpmTag] = &[
  tag(0x13, "TimeCode", MdpmKind::TimeCode),
  // 0x18 DateTimeOriginal — Combine => 1 (H264.pm:96-116).
  MdpmTag {
    id: 0x18,
    name: "DateTimeOriginal",
    kind: MdpmKind::DateTimeOriginal,
    combine: 1,
    condition: MakeCondition::Any,
    group: H264Group::H264,
    priority: H264Priority::Normal,
  },
  tag(0x70, "Camera1", MdpmKind::SubDir(SubDirKind::Camera1)),
  tag(0x71, "Camera2", MdpmKind::SubDir(SubDirKind::Camera2)),
  tag(0x7f, "Shutter", MdpmKind::SubDir(SubDirKind::Shutter)),
  // 0xa0-0xaa — the Exif-image tags (H264.pm:153-235).
  tag(
    0xa0,
    "ExposureTime",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::ExposureTime,
    },
  ),
  tag(
    0xa1,
    "FNumber",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  tag(
    0xa2,
    "ExposureProgram",
    MdpmKind::Int32uEnum(&[
      (0, "Not Defined"),
      (1, "Manual"),
      (2, "Program AE"),
      (3, "Aperture-priority AE"),
      (4, "Shutter speed priority AE"),
      (5, "Creative (Slow speed)"),
      (6, "Action (High speed)"),
      (7, "Portrait"),
      (8, "Landscape"),
    ]),
  ),
  tag(
    0xa3,
    "BrightnessValue",
    MdpmKind::Rational {
      signed: true,
      conv: RationalConv::Plain,
    },
  ),
  tag(
    0xa4,
    "ExposureCompensation",
    MdpmKind::Rational {
      signed: true,
      conv: RationalConv::ExposureCompensation,
    },
  ),
  tag(
    0xa5,
    "MaxApertureValue",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::MaxApertureValue,
    },
  ),
  tag(0xa6, "Flash", MdpmKind::Flash),
  tag(
    0xa7,
    "CustomRendered",
    MdpmKind::Int32uEnum(&[(0, "Normal"), (1, "Custom")]),
  ),
  // 0xa8 WhiteBalance — `Priority => 0` (H264.pm:212-220). The ONLY H264 tag
  // with a non-default `FoundTag` priority, so it lands as `H264Priority::Low`
  // and never overwrites the higher-priority Camera1 `WhiteBalance`
  // (H264.pm:460-470) on a valid AVCHD stream that carries both (Codex R15 F1).
  MdpmTag {
    id: 0xa8,
    name: "WhiteBalance",
    kind: MdpmKind::Int32uEnum(&[(0, "Auto"), (1, "Manual")]),
    combine: 0,
    condition: MakeCondition::Any,
    group: H264Group::H264,
    priority: H264Priority::Low,
  },
  tag(
    0xa9,
    "FocalLengthIn35mmFormat",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::FocalLength35,
    },
  ),
  tag(
    0xaa,
    "SceneCaptureType",
    MdpmKind::Int32uEnum(&[
      (0, "Standard"),
      (1, "Landscape"),
      (2, "Portrait"),
      (3, "Night"),
    ]),
  ),
  // 0xb0-0xca — the GPS block (H264.pm:237-387). Every tag carries
  // `Groups => { 1 => 'GPS' }`, so bundled `ParseH264Video` reports them
  // under the family-1 `GPS` group (Codex R5 F1).
  gps_tag(0xb0, "GPSVersionID", MdpmKind::GpsVersionId),
  gps_tag(
    0xb1,
    "GPSLatitudeRef",
    MdpmKind::Str(StringConv::Enum(&[("N", "North"), ("S", "South")])),
  ),
  // 0xb2 GPSLatitude — Combine => 2 (deg/min/sec across 0xb2/0xb3/0xb4).
  MdpmTag {
    id: 0xb2,
    name: "GPSLatitude",
    kind: MdpmKind::Rational {
      signed: false,
      conv: RationalConv::GpsCoordinate,
    },
    combine: 2,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  },
  gps_tag(
    0xb5,
    "GPSLongitudeRef",
    MdpmKind::Str(StringConv::Enum(&[("E", "East"), ("W", "West")])),
  ),
  // 0xb6 GPSLongitude — Combine => 2 (deg/min/sec across 0xb6/0xb7/0xb8).
  MdpmTag {
    id: 0xb6,
    name: "GPSLongitude",
    kind: MdpmKind::Rational {
      signed: false,
      conv: RationalConv::GpsCoordinate,
    },
    combine: 2,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  },
  gps_tag(0xb9, "GPSAltitudeRef", MdpmKind::GpsAltitudeRef),
  gps_tag(
    0xba,
    "GPSAltitude",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  // 0xbb GPSTimeStamp — Combine => 2 (hour/min/sec across 0xbb/0xbc/0xbd).
  MdpmTag {
    id: 0xbb,
    name: "GPSTimeStamp",
    kind: MdpmKind::Rational {
      signed: false,
      conv: RationalConv::GpsTimeStamp,
    },
    combine: 2,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  },
  gps_tag(
    0xbe,
    "GPSStatus",
    MdpmKind::Str(StringConv::Enum(&[
      ("A", "Measurement Active"),
      ("V", "Measurement Void"),
    ])),
  ),
  gps_tag(
    0xbf,
    "GPSMeasureMode",
    MdpmKind::Str(StringConv::Enum(&[
      ("2", "2-Dimensional Measurement"),
      ("3", "3-Dimensional Measurement"),
    ])),
  ),
  gps_tag(
    0xc0,
    "GPSDOP",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  gps_tag(
    0xc1,
    "GPSSpeedRef",
    MdpmKind::Str(StringConv::Enum(&[
      ("K", "km/h"),
      ("M", "mph"),
      ("N", "knots"),
    ])),
  ),
  gps_tag(
    0xc2,
    "GPSSpeed",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  gps_tag(
    0xc3,
    "GPSTrackRef",
    MdpmKind::Str(StringConv::Enum(&[
      ("M", "Magnetic North"),
      ("T", "True North"),
    ])),
  ),
  gps_tag(
    0xc4,
    "GPSTrack",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  gps_tag(
    0xc5,
    "GPSImgDirectionRef",
    MdpmKind::Str(StringConv::Enum(&[
      ("M", "Magnetic North"),
      ("T", "True North"),
    ])),
  ),
  gps_tag(
    0xc6,
    "GPSImgDirection",
    MdpmKind::Rational {
      signed: false,
      conv: RationalConv::Plain,
    },
  ),
  // 0xc7 GPSMapDatum — string, Combine => 1 (H264.pm:371-377).
  MdpmTag {
    id: 0xc7,
    name: "GPSMapDatum",
    kind: MdpmKind::Str(StringConv::Plain),
    combine: 1,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  },
  // 0xca GPSDateStamp — string, Combine => 2, ValueConv ExifDate
  // (H264.pm:380-387).
  MdpmTag {
    id: 0xca,
    name: "GPSDateStamp",
    kind: MdpmKind::Str(StringConv::ExifDate),
    combine: 2,
    condition: MakeCondition::Any,
    group: H264Group::Gps,
    priority: H264Priority::Normal,
  },
  tag(0xe0, "MakeModel", MdpmKind::SubDir(SubDirKind::MakeModel)),
  // 0xe1 RecInfo — SubDir, Canon-only (H264.pm:394-399).
  MdpmTag {
    id: 0xe1,
    name: "RecInfo",
    kind: MdpmKind::SubDir(SubDirKind::RecInfo),
    combine: 0,
    condition: MakeCondition::Canon,
    group: H264Group::H264,
    priority: H264Priority::Normal,
  },
  // 0xe4 Model — string, Combine => 2, Sony-only, RawConv drops "" (H264.pm:
  // 403-411).
  MdpmTag {
    id: 0xe4,
    name: "Model",
    kind: MdpmKind::Str(StringConv::PlainDropEmpty),
    combine: 2,
    condition: MakeCondition::Sony,
    group: H264Group::H264,
    priority: H264Priority::Normal,
  },
  // 0xee FrameInfo — SubDir, Canon-only (H264.pm:415-420).
  MdpmTag {
    id: 0xee,
    name: "FrameInfo",
    kind: MdpmKind::SubDir(SubDirKind::FrameInfo),
    combine: 0,
    condition: MakeCondition::Canon,
    group: H264Group::H264,
    priority: H264Priority::Normal,
  },
];

/// Look up an MDPM tag id in [`MDPM_TABLE`].
fn mdpm_tag(id: u8) -> Option<&'static MdpmTag> {
  MDPM_TABLE.iter().find(|t| t.id == id)
}

/// Evaluate a tag's `Condition => '$$self{Make} eq "…"'` (H264.pm:396/405/
/// 417). `$$self{Make}` is the *string* the `0xe0` MakeModel `RawConv` stored
/// (`convMake{$val} || "Unknown"`, H264.pm:530); records are id-ordered so a
/// `0xe0` record always precedes the conditional `0xe1`/`0xe4`/`0xee`.
fn condition_holds(cond: MakeCondition, make: &Option<SmolStr>) -> bool {
  match cond {
    MakeCondition::Any => true,
    MakeCondition::Canon => make.as_deref() == Some("Canon"),
    MakeCondition::Sony => make.as_deref() == Some("Sony"),
  }
}

// ===========================================================================
// Typed value + entry
// ===========================================================================

/// One decoded H.264 value, kept post-byte-decode but pre-PrintConv (the
/// `-j`/`-n` split happens in the [`Taggable`](crate::emit::Taggable) impl).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum H264Value {
  /// An unsigned integer leaf (`ImageWidth`, `int32u` MDPM tags, binary
  /// subdirectory bytes). Carries the raw value; the PrintConv (if any) is
  /// resolved by name at emit time.
  U64(u64),
  /// An already-rendered string leaf — TimeCode, DateTimeOriginal, and the
  /// binary subdirectory tags whose own PrintConv produced a fixed string.
  /// `j` is the `-j` rendering, `n` the `-n` rendering (often equal).
  Text(TextValue),
}

impl H264Value {
  /// `true` when this is the [`H264Value::U64`] arm.
  #[must_use]
  #[inline(always)]
  pub const fn is_u64(&self) -> bool {
    matches!(self, H264Value::U64(_))
  }
  /// `true` when this is the [`H264Value::Text`] arm.
  #[must_use]
  #[inline(always)]
  pub const fn is_text(&self) -> bool {
    matches!(self, H264Value::Text(_))
  }
  /// The wrapped integer, when this is a [`H264Value::U64`].
  #[must_use]
  #[inline(always)]
  pub const fn as_u64(&self) -> Option<u64> {
    match self {
      H264Value::U64(n) => Some(*n),
      H264Value::Text(_) => None,
    }
  }
}

/// A pre-rendered string value carrying BOTH mode spellings (`-j` PrintConv
/// vs `-n` post-ValueConv). Extracted into a named struct so [`H264Value`]'s
/// `Text` arm stays a single-field newtype (§2 — no multi-field variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextValue {
  print_conv: SmolStr,
  numeric: SmolStr,
}

impl TextValue {
  /// Build a [`TextValue`] from its `-j` and `-n` spellings.
  #[must_use]
  #[inline(always)]
  pub fn new(print_conv: impl Into<SmolStr>, numeric: impl Into<SmolStr>) -> Self {
    Self {
      print_conv: print_conv.into(),
      numeric: numeric.into(),
    }
  }
  /// Both modes share one spelling (most ValueConv-only tags).
  #[must_use]
  #[inline(always)]
  pub fn uniform(s: impl Into<SmolStr> + Clone) -> Self {
    Self {
      print_conv: s.clone().into(),
      numeric: s.into(),
    }
  }
  /// The `-j` (PrintConv) rendering.
  #[must_use]
  #[inline(always)]
  pub fn print_conv(&self) -> &str {
    self.print_conv.as_str()
  }
  /// The `-n` (post-ValueConv) rendering.
  #[must_use]
  #[inline(always)]
  pub fn numeric(&self) -> &str {
    self.numeric.as_str()
  }
}

/// The family-1 group an emitted H.264 tag resolves to. Almost everything is
/// `H264` (group 0/1 both `H264`, H264.pm:43-53); the MDPM GPS block
/// (0xb0-0xca) carries `Groups => { 1 => 'GPS' }` (H264.pm:241-387), so
/// bundled `ParseH264Video` reports e.g. `GPS:GPSLatitude` under `-G1`
/// (Codex R5 F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264Group {
  /// Family-1 group `H264` — the default for SPS image-size, the MDPM
  /// non-GPS tags, and every binary subdirectory tag.
  H264,
  /// Family-1 group `GPS` — the MDPM GPS block (0xb0-0xca, H264.pm:241-387).
  Gps,
}

impl H264Group {
  /// The `-G1` family-1 group string ExifTool uses for the JSON key prefix.
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      H264Group::H264 => "H264",
      H264Group::Gps => "GPS",
    }
  }
  /// `true` when this is [`H264Group::H264`].
  #[must_use]
  #[inline(always)]
  pub const fn is_h264(self) -> bool {
    matches!(self, H264Group::H264)
  }
  /// `true` when this is [`H264Group::Gps`].
  #[must_use]
  #[inline(always)]
  pub const fn is_gps(self) -> bool {
    matches!(self, H264Group::Gps)
  }
}

/// A tag's `FoundTag` priority (ExifTool.pm:9458-9580). H264.pm gives exactly
/// ONE tag a non-default priority — the top-level MDPM `0xa8 WhiteBalance`
/// carries `Priority => 0` (H264.pm:215) so a higher-priority same-name tag
/// (e.g. the `0x70` Camera1 `WhiteBalance` subdirectory value, H264.pm:460-470)
/// is NOT overwritten by it. Every other H264 tag has no `Priority`/`PRIORITY`/
/// `Avoid`, so it takes the engine's normal default. ExifTool compares
/// priorities numerically (`$priority >= $oldPriority`, ExifTool.pm:9553) with
/// an undefined/default priority acting as `1` and `Priority => 0` as `0`; the
/// `Ord` derive (variants ordered `Low < Normal`) reproduces that comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum H264Priority {
  /// `Priority => 0` — a low-priority tag (H264.pm:215, only `0xa8`
  /// WhiteBalance). It never displaces a same-name `Normal` tag, and (ties
  /// aside) is itself displaced by one. Maps to ExifTool's `0`.
  Low,
  /// The engine default (undefined `Priority` ⇒ `1`, ExifTool.pm:9551). Every
  /// H264 tag except `0xa8` WhiteBalance.
  Normal,
}

/// One emitted H.264 tag: a family-1 group, a tag name, a `FoundTag` priority,
/// and the decoded value.
#[derive(Debug, Clone)]
pub struct H264Entry {
  group: H264Group,
  name: SmolStr,
  priority: H264Priority,
  value: H264Value,
}

impl H264Entry {
  /// Build a family-1 `H264`-group entry at the engine-default (`Normal`)
  /// priority — the default for SPS image-size and every binary subdirectory
  /// tag. The MDPM tags route through [`H264Entry::with_group_priority`] so the
  /// GPS block (Codex R5 F1) lands in `GPS` and `0xa8 WhiteBalance` keeps its
  /// `Priority => 0`.
  #[must_use]
  #[inline(always)]
  fn h264(name: SmolStr, value: H264Value) -> Self {
    Self {
      group: H264Group::H264,
      name,
      priority: H264Priority::Normal,
      value,
    }
  }
  /// Build an entry in an explicit family-1 group AND priority — the path every
  /// MDPM tag takes (threading `def.group` + `def.priority`), so the top-level
  /// `0xa8 WhiteBalance` (`Priority => 0`, H264.pm:215) lands as
  /// [`H264Priority::Low`] and does not overwrite a higher-priority same-name
  /// tag (the Camera1 `WhiteBalance`, H264.pm:460-470).
  #[must_use]
  #[inline(always)]
  fn with_group_priority(
    group: H264Group,
    priority: H264Priority,
    name: SmolStr,
    value: H264Value,
  ) -> Self {
    Self {
      group,
      name,
      priority,
      value,
    }
  }
  /// The family-1 group this tag resolves to (`H264`, or `GPS` for the MDPM
  /// GPS block — Codex R5 F1).
  #[must_use]
  #[inline(always)]
  pub const fn group(&self) -> H264Group {
    self.group
  }
  /// This tag's `FoundTag` priority (ExifTool.pm:9458). `Normal` for every
  /// H264 tag except the top-level MDPM `0xa8 WhiteBalance` (`Priority => 0`,
  /// H264.pm:215), which is `Low`.
  #[must_use]
  #[inline(always)]
  const fn priority(&self) -> H264Priority {
    self.priority
  }
  /// Tag name (e.g. `"TimeCode"`, `"ImageWidth"`, `"Make"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// The decoded value (borrow of the non-`Copy` [`H264Value`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &H264Value {
    &self.value
  }
}

// ===========================================================================
// Typed Meta — `H264Meta<'a>`
// ===========================================================================

/// Typed H.264 stream metadata — the lib-first output of [`ProcessH264`].
///
/// D8 convention: no public fields; accessors only. The lifetime `'a` is a
/// phantom today (every value is owned/decoded — H.264 decoding de-escapes
/// the RBSP into a fresh buffer, so nothing borrows the input), but it is
/// kept on the type so the [`FormatParser::Meta`] GAT threads the input
/// borrow uniformly with the other format ports.
///
/// `H264Meta` carries the emitted tags in extraction order (faithful to
/// Perl's `HandleTag` call sequence: SPS `ImageWidth`/`ImageHeight` first
/// when an SPS NAL precedes the SEI, then the MDPM records in id order).
#[derive(Debug, Clone)]
pub struct H264Meta<'a> {
  entries: Vec<H264Entry>,
  /// Cached `Make` (H264.pm:530 `$$self{Make} = …`), used by Perl
  /// `Condition`s on later tags; also a common library probe target.
  make: Option<SmolStr>,
  /// Warnings accumulated during parse (faithful to `$et->Warn` — the only
  /// `Warn` reachable inside `ParseH264Video`/`ProcessSEI` is the MDPM
  /// out-of-sequence one at H264.pm:989). Surfaced as `ExifTool:Warning`.
  warnings: Vec<SmolStr>,
  /// `$foundUserData` (H264.pm:1039/1084/1102) — set once an SEI message
  /// carrying user data (the MDPM block) was decoded by `ProcessSEI`. The
  /// M2TS demuxer reads this to honour `ParseH264Video`'s extra-frame
  /// contract (H264.pm:1100-1104): when no SEI/MDPM was found in the first
  /// frame, the demuxer parses one MORE frame (Panasonic cameras don't put
  /// the SEI in the first frame). NOT emitted as a tag.
  found_user_data: bool,
  _marker: core::marker::PhantomData<&'a ()>,
}

impl H264Meta<'_> {
  /// Every emitted tag in walk order. (`Vec` slice — never expose `&Vec`.)
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[H264Entry] {
    &self.entries
  }
  /// The decoded camera `Make` (`"Canon"` / `"Sony"` / …), when a
  /// MakeModel MDPM record (`0xe0`) was present. `None` otherwise.
  #[must_use]
  #[inline(always)]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }
  /// Warnings emitted during parse, in occurrence order. The only `Warn`
  /// reachable from `ParseH264Video`/`ProcessSEI` is the MDPM
  /// out-of-sequence message (`'Entries in MDPM directory are out of
  /// sequence'`, H264.pm:989). (`&[]` slice — never expose `&Vec`.)
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[SmolStr] {
    &self.warnings
  }
  /// `true` when the stream yielded no `H264:*` tags at all (no SPS image
  /// size and no MDPM block) — the typical case for a generic H.264 stream
  /// with no AVCHD camcorder metadata.
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
  /// `$foundUserData` (H264.pm:1039/1102) — `true` once an SEI message
  /// carrying the AVCHD MDPM user-data block was decoded. The M2TS demuxer
  /// uses this to implement `ParseH264Video`'s return contract
  /// (H264.pm:1100-1104): a stream whose first frame carried NO SEI/MDPM
  /// signals the caller to parse one more frame (Panasonic cameras don't put
  /// the SEI in the first frame). A non-empty stream with only an SPS size
  /// (no MDPM) therefore still reports `false` here.
  #[must_use]
  #[inline(always)]
  pub const fn found_user_data(&self) -> bool {
    self.found_user_data
  }
  /// Re-stamp the phantom lifetime to any lifetime `'b`. `H264Meta` is
  /// FULLY OWNED — every field (`entries: Vec<H264Entry>`, `make:
  /// Option<SmolStr>`, `warnings: Vec<SmolStr>`) carries no reference into
  /// the original input buffer, and the only lifetime-bearing field is a
  /// `PhantomData<&'a ()>` marker that exists solely for the
  /// `FormatParser::Meta<'a>` GAT shape.
  ///
  /// This helper exists for the M2TS / future MPEG-2 demuxers, which
  /// accumulate PES payload bytes into an owned `Vec<u8>` whose lifetime
  /// does NOT match the M2TS input buffer's `'a`. After parsing the H.264
  /// payload (which transforms every byte through the SPS / MDPM decoders),
  /// the demuxer needs to store the result on the M2TS [`Meta<'a>`]; the
  /// rebind is sound because no field actually borrows from `'a` ⇒ `'b`.
  #[must_use]
  #[inline(always)]
  pub fn into_rebound<'b>(self) -> H264Meta<'b> {
    H264Meta {
      entries: self.entries,
      make: self.make,
      warnings: self.warnings,
      found_user_data: self.found_user_data,
      _marker: core::marker::PhantomData,
    }
  }

  /// Fold a LATER frame's parse (`self`) into an EARLIER frame's (`earlier`),
  /// for the M2TS multi-frame H.264 accumulation (H264.pm:1100-1104).
  ///
  /// Bundled `ParseH264Video` runs against a single ExifTool object whose
  /// state persists across the (up to two) frames it parses: an SPS is
  /// processed once (`$$et{GotNAL07}`, H264.pm:1093) and every frame's MDPM
  /// user data is appended via `HandleTag`. exifast's parser is per-call
  /// (each `parse_borrowed` resets that state), so this combines the two
  /// results the way the shared `$$et` would have: the EARLIER frame's
  /// entries come first (so its SPS `ImageWidth`/`ImageHeight` survive even
  /// when the later frame carries only the MDPM block — the Panasonic case),
  /// then the later frame's entries (the downstream last-wins `TagMap` dedup
  /// then resolves any same-name collision exactly as `HandleTag` overwrite
  /// would). `Make` is sticky to the first frame that decoded it
  /// (H264.pm:530 sets `$$self{Make}` once); `found_user_data` is the union.
  #[must_use]
  pub fn merge_frame<'b>(mut self, mut earlier: H264Meta<'b>) -> H264Meta<'b> {
    earlier.entries.append(&mut self.entries);
    earlier.warnings.extend(self.warnings);
    H264Meta {
      entries: earlier.entries,
      make: earlier.make.or(self.make),
      warnings: earlier.warnings,
      found_user_data: earlier.found_user_data || self.found_user_data,
      _marker: core::marker::PhantomData,
    }
  }
}

// ===========================================================================
// `ProcessH264` — the lib-first parser
// ===========================================================================

/// H.264 video-stream parser — faithful port of
/// `Image::ExifTool::H264::ParseH264Video` (H264.pm:1032-1105).
///
/// Engine-only: ExifTool has no `H264` file type (see the module docs); this
/// parser is consumed by a future M2TS / MPEG port via [`parse_borrowed`].
#[derive(Debug, Clone, Copy)]
pub struct ProcessH264;

impl parser_sealed::Sealed for ProcessH264 {}

impl FormatParser for ProcessH264 {
  type Meta<'a> = H264Meta<'a>;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data, &mut H264FrameState::new())
  }
}

/// Lib-first direct entry. Parses an H.264 NAL byte stream (the assembled
/// PES payload an M2TS demuxer would hand us) and returns a typed
/// [`H264Meta`].
///
/// Returns `None` when the buffer contains no NAL start code at all
/// (not an H.264 stream); `Some(meta)` otherwise — `meta` may be
/// [`H264Meta::is_empty`] when the stream had no SPS size and no MDPM block.
///
/// This is the SINGLE-FRAME entry (a fresh [`H264FrameState`] each call) used
/// by the standalone H.264 conformance path. The M2TS demuxer, which calls
/// `ParseH264Video` repeatedly on ONE ExifTool object whose `GotNAL06`/
/// `GotNAL07` latches persist (H264.pm:1079/1093), uses
/// [`parse_borrowed_stateful`] instead.
#[must_use]
pub fn parse_borrowed(data: &[u8]) -> Option<H264Meta<'_>> {
  parse_inner(data, &mut H264FrameState::new())
}

/// `$$et`-resident H.264 NAL latches that persist across the (up to two)
/// `ParseH264Video` calls a single MPEG-2 demuxer makes on one ExifTool
/// object (H264.pm:1079/1093). The per-call `%parseNalUnit = (0x06,0x07)` is
/// LOCAL (reset every call), but `GotNAL06`/`GotNAL07` are stored on `$$et`,
/// so a later H.264 frame/PID does NOT re-emit an SPS already parsed, and (no
/// `ExtractEmbedded`) does NOT re-process an SEI once one carried user data.
///
/// The M2TS walker owns one of these for the whole file and threads it through
/// every [`parse_borrowed_stateful`] call, so the extra-frame scan
/// (H264.pm:1100-1104) faithfully suppresses the second frame's duplicate SPS
/// (Codex M2TS finding #6) instead of letting a stateless re-parse overwrite
/// the first frame's `ImageWidth`/`ImageHeight`.
#[derive(Debug, Clone, Copy, Default)]
pub struct H264FrameState {
  /// `$$et{GotNAL07}` (H264.pm:1093) — an SPS (0x07) has been parsed once;
  /// every later SPS NAL is skipped (`next if $$et{GotNAL07}`).
  got_nal07: bool,
  /// `$$et{GotNAL06}` (H264.pm:1079/1088) — an SEI (0x06) carrying user data
  /// has been processed; without `ExtractEmbedded` every later SEI is skipped
  /// (`next unless $et->Options('ExtractEmbedded')`).
  got_nal06: bool,
}

impl H264FrameState {
  /// A pristine `$$et` (no NAL seen yet) — the start-of-file latch state.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      got_nal07: false,
      got_nal06: false,
    }
  }
}

/// Stateful entry for the MPEG-2 demuxers: parse ONE H.264 frame while
/// carrying the `$$et`-resident `GotNAL06`/`GotNAL07` latches in `state`
/// across calls (H264.pm:1032-1104). Returns `None` on a buffer with no NAL
/// start code (reject), else `Some(meta)` for that frame. See
/// [`H264FrameState`].
#[must_use]
pub fn parse_borrowed_stateful<'a>(
  data: &'a [u8],
  state: &mut H264FrameState,
) -> Option<H264Meta<'a>> {
  parse_inner(data, state)
}

/// Inner parser body. `None` ⇒ no NAL start code anywhere (reject); else
/// `Some(meta)` (possibly with zero entries). `state` carries the
/// `GotNAL06`/`GotNAL07` latches (H264.pm:1079/1093) IN and OUT so a caller
/// parsing successive frames on one `$$et` (the M2TS demuxer) suppresses a
/// duplicate SPS / already-consumed SEI exactly as bundled does.
fn parse_inner<'a>(data: &'a [u8], state: &mut H264FrameState) -> Option<H264Meta<'a>> {
  // Reject buffers with no NAL start code at all — they are not an H.264
  // stream. (`ParseH264Video` would just walk off the end producing
  // nothing; we surface that as `Ok(None)` so a dispatcher can move on.)
  if find_start_code(data, 0).is_none() {
    return None;
  }

  let mut entries: Vec<H264Entry> = Vec::new();
  let mut make: Option<SmolStr> = None;
  let mut warnings: Vec<SmolStr> = Vec::new();
  // `got_sps`/`got_nal06` are seeded from the persistent `$$et` latches and
  // written back at the end, so a second frame on the same `$$et` skips an SPS
  // already parsed (H264.pm:1093) / an SEI already consumed (H264.pm:1079).
  // `found_user_data` is the PER-CALL `my $foundUserData` (H264.pm:1039) — the
  // value `ParseH264Video` returns and the M2TS extra-frame contract reads — so
  // it is a fresh local, distinct from the persistent `GotNAL06` skip gate.
  let mut got_sps = state.got_nal07; // H264.pm:1093 `$$et{GotNAL07}`
  let mut got_nal06 = state.got_nal06; // H264.pm:1079/1088 `$$et{GotNAL06}`
  let mut found_user_data = false; // H264.pm:1039 `my $foundUserData`

  // H264.pm:1042-1099 — walk NAL units. `cursor` is the offset of the byte
  // just past the start code (i.e. the NAL header byte).
  let mut search_from = 0usize;
  while let Some(sc) = find_start_code(data, search_from) {
    let nal_start = sc.payload_start; // first byte = NAL header
    if nal_start >= data.len() {
      break;
    }
    // The NAL body runs until the next start code (or end of buffer).
    let body_end = match find_start_code(data, nal_start) {
      Some(next) => next.code_start,
      None => data.len(),
    };
    search_from = body_end;

    // `nal_start >= data.len()` guard above ≡ `.get(nal_start)` returning
    // `None` (byte-identical; same `break` recovery).
    let Some(&header) = data.get(nal_start) else {
      break;
    };
    // H264.pm:1058 — forbidden_zero_bit must be clear. Perl:
    // `$nal_unit_type & 0x80 and $et->Warn('H264 forbidden bit error'), last`
    // — emit the warning (surfaced as `ExifTool:Warning`) BEFORE stopping the
    // scan (Codex R8 F2).
    if header & 0x80 != 0 {
      warnings.push(SmolStr::new_static("H264 forbidden bit error"));
      break;
    }
    let nal_type = header & 0x1f; // H264.pm:1059

    // Only SPS (0x07) and SEI (0x06) are of interest (H264.pm:1038/1061).
    if nal_type != 0x06 && nal_type != 0x07 {
      continue;
    }

    // H264.pm:1063-1070 — de-escape the RBSP (strip `00 00 03` → `00 00`).
    // The NAL body is `data[nal_start + 1 .. body_end]` (past the header).
    // Here `nal_start < data.len()` (guard above) and `body_end > nal_start`
    // (the NAL header is a non-`00` SPS/SEI byte, so the next start code cannot
    // sit AT `nal_start`), so `nal_start+1 <= body_end` and `.get()` always hits
    // (byte-identical; the `continue` skips this NAL on the unreachable miss).
    let Some(nal_body) = data.get(nal_start.saturating_add(1)..body_end) else {
      continue;
    };
    let rbsp = unescape_rbsp(nal_body);

    match nal_type {
      0x06 => {
        // H264.pm:1077-1088 — SEI. Without `ExtractEmbedded`, once an SEI has
        // carried user data (`$$et{GotNAL06}`, persistent) every later SEI is
        // skipped (`if ($$et{GotNAL06}) { next unless ExtractEmbedded }`) — this
        // gate is per-FILE, so a second frame on the same `$$et` whose first
        // frame already found the MDPM never re-processes its SEI.
        if got_nal06 {
          continue;
        }
        // `$foundUserData = ProcessSEI(...)`; `next unless $foundUserData`; then
        // `$$et{GotNAL06} = ($$et{GotNAL06}||0)+1` (H264.pm:1084-1088).
        if process_sei(&rbsp, &mut entries, &mut make, &mut warnings) {
          found_user_data = true;
          got_nal06 = true;
        }
      }
      0x07 => {
        // H264.pm:1090-1095 — SPS, processed at most once.
        if got_sps {
          continue;
        }
        got_sps = true;
        if let Some(size) = parse_seq_param_set(&rbsp) {
          entries.push(H264Entry::h264(
            SmolStr::new_static("ImageWidth"),
            H264Value::U64(u64::from(size.width)),
          ));
          entries.push(H264Entry::h264(
            SmolStr::new_static("ImageHeight"),
            H264Value::U64(u64::from(size.height)),
          ));
        }
      }
      _ => unreachable!("nal_type filtered to 0x06/0x07 above"),
    }
  }

  // Write the persistent latches back to `$$et` (H264.pm:1088/1094) so the
  // NEXT frame on this object suppresses a duplicate SPS / consumed SEI.
  state.got_nal07 = got_sps;
  state.got_nal06 = got_nal06;

  Some(H264Meta {
    entries,
    make,
    warnings,
    found_user_data,
    _marker: core::marker::PhantomData,
  })
}

/// A located NAL start code.
#[derive(Debug, Clone, Copy)]
struct StartCode {
  /// Offset of the first byte of the `00 00 [00] 01` start code.
  code_start: usize,
  /// Offset of the first byte AFTER the start code (the NAL header byte).
  payload_start: usize,
}

/// Find the next NAL start code at or after `from` — `00 00 01` or
/// `00 00 00 01` (H264.pm:1045 `/(\0{2,3}\x01)/`). The Perl regex `\0{2,3}`
/// is greedy, so a 4-byte `00 00 00 01` is matched as the 4-byte form.
fn find_start_code(data: &[u8], from: usize) -> Option<StartCode> {
  let mut i = from;
  // The `i + 3 <= data.len()` loop bound proves the 3-byte window exists, and
  // the `i > 0` guard proves `i - 1` exists, so every `.get()` here hits
  // (byte-identical to the raw indices).
  while i + 3 <= data.len() {
    if let Some(&[b0, b1, b2]) = data.get(i..i + 3)
      && b0 == 0
      && b1 == 0
      && b2 == 1
    {
      // 3-byte form. If preceded by another 0 within range, the Perl
      // greedy `\0{2,3}` would have consumed it — treat the leading 0 as
      // part of the code (code_start points one byte earlier).
      let code_start = if i > from && i > 0 && data.get(i - 1) == Some(&0) {
        i - 1
      } else {
        i
      };
      return Some(StartCode {
        code_start,
        payload_start: i + 3,
      });
    }
    i += 1;
  }
  None
}

/// De-escape a NAL RBSP: every `00 00 03` triple becomes `00 00` (the `03`
/// is the emulation-prevention byte). Faithful to H264.pm:1063-1070.
///
/// H264.pm:1064 seeds the de-escape regex at `pos($$dataPt) = $pos + 1`,
/// where `$pos` is the NAL body start (the byte after the 1-byte NAL
/// header). The `\0\0\x03` search therefore cannot match a triple whose
/// FIRST byte sits at body index 0 — its earliest match start is body
/// index 1. A leading `00 00 03 …` SEI body keeps that `03` (e.g. an SEI
/// starting `00 00 03 00 05 …` still reaches the MDPM payload). We mirror
/// that window: a `0x03` only counts as emulation-prevention when its
/// `00 00 03` triple starts at body index >= 1.
fn unescape_rbsp(body: &[u8]) -> Cow<'_, [u8]> {
  // Fast path: no strippable `00 00 03` triple ⇒ borrow the body unchanged.
  // Index 2 is the earliest a `03` can be dropped — its triple then starts
  // at index 1 (H264.pm:1064 `$pos + 1`).
  let mut needs = false;
  {
    let mut zeros = 0u32;
    for (i, &b) in body.iter().enumerate() {
      if i >= 3 && zeros >= 2 && b == 0x03 {
        needs = true;
        break;
      }
      zeros = if b == 0 { zeros + 1 } else { 0 };
    }
  }
  if !needs {
    return Cow::Borrowed(body);
  }
  let mut out: Vec<u8> = Vec::with_capacity(body.len());
  let mut zeros = 0u32;
  let mut i = 0usize;
  while i < body.len() {
    // `i < body.len()` (loop bound) ⇒ `.get(i)` always hits; `break` is the
    // unreachable recovery (byte-identical to the raw `body[i]`).
    let Some(&b) = body.get(i) else {
      break;
    };
    if i >= 3 && zeros >= 2 && b == 0x03 {
      // Drop this emulation-prevention byte. Per the H.264 spec the byte
      // AFTER an inserted 03 is always ≤ 0x03; Perl simply removes the 03
      // and continues, so the following byte resets the zero run.
      zeros = 0;
      i += 1;
      continue;
    }
    out.push(b);
    zeros = if b == 0 { zeros + 1 } else { 0 };
    i += 1;
  }
  Cow::Owned(out)
}

/// `ProcessSEI` (H264.pm:930-1026). Walks the SEI message list looking for
/// payload type 5 (user data unregistered); when found, checks for the MDPM
/// UUID and decodes the MDPM records. Returns `true` iff an MDPM block was
/// processed (Perl `return 1` after handling type 5).
fn process_sei(
  rbsp: &[u8],
  entries: &mut Vec<H264Entry>,
  make: &mut Option<SmolStr>,
  warnings: &mut Vec<SmolStr>,
) -> bool {
  let end = rbsp.len();
  let mut pos = 0usize;

  // H264.pm:939-966 — scan SEI messages until the type-5 payload. The loop
  // `break`s with the type-5 payload's byte size.
  let size: usize = loop {
    // Payload type (255-extended — H264.pm:941-946 `$type += $t`). Perl's
    // `$type` is a numeric scalar that silently promotes int→double, so a
    // long `0xff` run produces an arbitrarily large *exact* value that never
    // aliases 5 or 0x80. Accumulate in `u64` with `saturating_add`: a 64-bit
    // accumulator holds every value a non-pathological stream can reach (a
    // wrap would need ≈7.2e16 `0xff` bytes, far past any real `rbsp`), and
    // saturation guarantees a crafted overflow can never wrap *down* into
    // type 5 / 0x80 the way the former `u32 += ` did (0x01010101 `0xff`
    // bytes + `0x06` wrap to exactly 5 in `u32`, panicking debug builds and
    // fabricating MDPM tags in release builds).
    let mut payload_type: u64 = 0;
    loop {
      // The `pos >= end` guard ≡ `.get(pos)` returning `None` (byte-identical;
      // same `return false` recovery).
      let Some(&t) = rbsp.get(pos) else {
        return false;
      };
      pos += 1;
      payload_type = payload_type.saturating_add(u64::from(t));
      if t != 255 {
        break;
      }
    }
    // H264.pm:947 — `0x80` terminator (byte-alignment bits).
    if payload_type == 0x80 {
      return false;
    }
    // Payload size (255-extended — H264.pm:949-954 `$size += $t`). Same
    // 255-extended accumulation; `usize` already cannot wrap for any `rbsp`
    // a machine can hold (`pos >= end` stops the loop long before 2^64
    // bytes), but use `saturating_add` for parity with `payload_type` so no
    // narrow-type/overflow path can ever exist here.
    let mut payload_size = 0usize;
    loop {
      // The `pos >= end` guard ≡ `.get(pos)` returning `None` (byte-identical;
      // same `return false` recovery).
      let Some(&t) = rbsp.get(pos) else {
        return false;
      };
      pos += 1;
      payload_size = payload_size.saturating_add(usize::from(t));
      if t != 255 {
        break;
      }
    }
    if pos.saturating_add(payload_size) > end {
      return false; // H264.pm:955
    }
    if payload_type == 5 {
      break payload_size; // H264.pm:962-964 — exit loop to process user data.
    }
    // H264.pm:957-961 — picture timing (type 1) is test-only in Perl
    // (`$parsePictureTiming`, never set); every other type is skipped.
    pos += payload_size;
  };

  // H264.pm:971-972 — require the 16-byte UUID + "MDPM". The `pos + 20 > end`
  // short-circuit guards the slice, so `.get(pos..pos+20)` matches the raw
  // `rbsp[pos..pos+20]` comparison (byte-identical).
  if size <= 20 || pos + 20 > end || rbsp.get(pos..pos + 20) != Some(MDPM_UUID_TAG.as_slice()) {
    return false;
  }

  // H264.pm:977-1024 — walk the MDPM records.
  let payload_end = pos + size; // H264.pm:980
  pos += 20; // skip UUID + "MDPM" (H264.pm:981)
  // The `pos >= end` guard ≡ `.get(pos)` returning `None` (byte-identical;
  // same `return false` recovery).
  let Some(&num) = rbsp.get(pos) else {
    return false;
  };
  // entry count (H264.pm:982)
  pos += 1;

  let mut last_tag: i32 = 0; // H264.pm:983 `$lastTag = 0`
  // H264.pm:986/1011 — `$index` is `++`'d in the outer `for` AND the Combine
  // `while`. A `u8` cannot overflow here: the strictly-ascending-tag rule
  // (H264.pm:988) means every processed record consumes a distinct, larger
  // tag id, and the Combine `while` only fires for table tags whose ids cap
  // at 0xe4 (H264.pm:403) — so at most ~0xe4 records can precede a Combine
  // tag and `index` is structurally bounded well under 255 (Codex R13
  // class-sweep — audited, not overflowable).
  let mut index = 0u8;
  while index < num && pos < payload_end {
    // The `pos >= end` guard ≡ `.get(pos)` returning `None` (byte-identical;
    // same `break` recovery).
    let Some(&tag) = rbsp.get(pos) else {
      break;
    };
    // H264.pm:987
    // H264.pm:988-991 — records must be strictly ascending.
    if i32::from(tag) <= last_tag {
      // Perl `Warn('Entries in MDPM directory are out of sequence'); last`
      // (H264.pm:989-990). Record the warning, then stop the MDPM walk.
      warnings.push(SmolStr::new_static(
        "Entries in MDPM directory are out of sequence",
      ));
      break;
    }
    last_tag = i32::from(tag);

    // H264.pm:993 — `my $buff = substr($$dataPt, $pos + 1, 4)`. Perl's
    // `substr` SHORT-READS: when fewer than four data bytes remain after
    // the tag id, `$buff` simply holds whatever bytes are available (it is
    // never undef), and `HandleTag` still fires. String records can still
    // produce real metadata from a short read — e.g. a type-5 MDPM payload
    // with `count=1`, tag `0xb1`, and a single byte `N` after the tag id
    // yields `GPSLatitudeRef = North`. Take `min(4, remaining)` bytes here
    // instead of breaking (Codex R9 F2).
    let buff_start = pos + 1;
    let buff_end = (pos + 5).min(end);
    // `buff_end <= end == rbsp.len()`, so `.get(buff_start..buff_end)` is
    // `Some` on exactly the `buff_start <= buff_end` condition and `None`
    // otherwise — `map_or_else` reproduces the original if/else (byte-identical).
    // (Per Perl `substr`, `$pos+1` past the data ⇒ the empty string.)
    let mut buff: Vec<u8> = rbsp
      .get(buff_start..buff_end)
      .map_or_else(Vec::new, <[u8]>::to_vec);

    // H264.pm:995 — `GetTagInfo` evaluates the tag's `Condition`. A tag
    // whose `Condition => '$$self{Make} eq "…"'` fails yields `$tagInfo ==
    // undef`, so the whole `if ($tagInfo) { … }` block — INCLUDING the
    // Combine absorption (H264.pm:1003-1014) — is skipped and the record
    // simply advances by 5.
    let matched = mdpm_tag(tag).filter(|def| condition_holds(def.condition, make));
    if let Some(def) = matched {
      // H264.pm:1003-1014 — Combine: absorb consecutive-id records.
      let mut combine = def.combine;
      while combine > 0 {
        // H264.pm:1005 — `last if $pos + 5 >= $end`. `$end` here is the
        // MDPM *payload* end (H264.pm:980). The guard ONLY verifies that the
        // consecutive tag byte at `$pos + 5` lies before the payload end —
        // it does NOT require a full five-byte next record. A truncated
        // next record (tag byte present, fewer than four data bytes after
        // it) is still absorbed (Codex R10 F2).
        if pos + 5 >= payload_end {
          break;
        }
        // `pos + 5 < payload_end <= end == rbsp.len()`, so `.get()` always hits;
        // `break` is the unreachable recovery (byte-identical).
        let Some(&next_tag) = rbsp.get(pos + 5) else {
          break;
        };
        // H264.pm:1007 — must be the consecutive id.
        if i32::from(next_tag) != last_tag + 1 {
          break;
        }
        pos += 5;
        // H264.pm:1009 — `$buff .= substr($$dataPt, $pos + 1, 4)`. Perl's
        // `substr` SHORT-READS against the de-escaped NAL buffer length
        // (`rbsp.len()` == `end`): a truncated consecutive record appends
        // only the bytes that are actually present. E.g. `0xc7` data
        // `WGS8` followed by a truncated `0xc8` whose sole data byte is
        // `4` yields the combined string `WGS84` (Codex R10 F2).
        let append_end = (pos + 5).min(end);
        // `pos + 1 < append_end <= end == rbsp.len()` ⇒ `.get()` is `Some`
        // (byte-identical to the raw `&rbsp[pos+1..append_end]`).
        if let Some(append) = rbsp.get(pos + 1..append_end) {
          buff.extend_from_slice(append);
        }
        index += 1;
        last_tag += 1;
        combine -= 1;
      }
      emit_mdpm(def, &buff, entries, make);
    }
    // H264.pm:1022 — advance past this record.
    pos += 5;
    index += 1;
  }
  true
}

/// Render one matched MDPM tag's `buff` bytes into [`H264Entry`] values.
fn emit_mdpm(def: &MdpmTag, buff: &[u8], entries: &mut Vec<H264Entry>, make: &mut Option<SmolStr>) {
  match def.kind {
    MdpmKind::TimeCode => {
      // H264.pm:90 — `sprintf("%.2x:%.2x:%.2x:%.2x", reverse unpack("C*",$val))`.
      // `ProcessSEI` short-reads `$buff` (`substr($$dataPt, $pos+1, 4)` — never
      // padded), and `HandleTag` still fires for a tag with NO fixed-width
      // `Format` (`0x13` has only `ValueConv`), so the ValueConv runs on
      // whatever bytes are present. There is NO length gate in Perl. For a
      // short buffer `unpack("C*",$val)` yields fewer than four values;
      // `sprintf`'s missing `%.2x` arguments are Perl-undef ⇒ numify to `0`
      // ⇒ `00`. E.g. empty ⇒ `00:00:00:00`, one byte `01` ⇒ `01:00:00:00`
      // (Codex R12 F1; verified vs bundled ExifTool 13.58).
      let text = render_timecode(buff);
      entries.push(H264Entry::with_group_priority(
        def.group,
        def.priority,
        SmolStr::new_static(def.name),
        H264Value::Text(TextValue::uniform(text.as_str())),
      ));
    }
    MdpmKind::DateTimeOriginal => {
      // H264.pm:108-115 — byte 0 = timezone packing, the rest BCD date/time.
      // `ProcessSEI` short-reads `$buff` and `HandleTag` still fires (the tag
      // has only a `ValueConv`, no fixed-width `Format`), so the ValueConv
      // runs on an underlength buffer with NO length gate in Perl. Perl's
      // `sprintf` consumes the 11 conversion specs POSITIONALLY against
      // `(@a, tz_sign, tz_hours, tz_min, dst)`: when `@a` is short the
      // trailing computed args slide forward into the `%.2x`/`%.2d` slots and
      // numify there, and the missing tail args are Perl-undef. E.g. a 5-byte
      // `0x18` buffer ⇒ a malformed-but-PRESENT `DateTimeOriginal`, not a
      // dropped tag (Codex R12 F1; verified vs bundled ExifTool 13.58).
      let text = render_datetime_original(buff);
      entries.push(H264Entry::with_group_priority(
        def.group,
        def.priority,
        SmolStr::new_static(def.name),
        H264Value::Text(text),
      ));
    }
    MdpmKind::Int32uEnum(map) => {
      // H264.pm — `Format => 'int32u'`; the 4 data bytes are a BE u32. A
      // SHORT buffer (`< 4` bytes) is NOT dropped: ExifTool's `ReadValue`
      // for a `Count`-less `int32u` returns the empty string `''` when
      // `$size < $len` (`ExifTool.pm:6285` — `return '' if … $size < $len`),
      // and `HandleTag` still emits the tag. The empty value misses the
      // PrintConv hash, so `-j` renders `Unknown ()` and `-n` renders `""`
      // (Codex R10 F1).
      // `buff.get(0..4)` is `Some` on exactly the original `buff.len() >= 4`
      // condition, `None` otherwise — `match` reproduces the if/else (byte-identical).
      let value = match buff.get(0..4) {
        Some(&[b0, b1, b2, b3]) => int32u_enum_value(u32::from_be_bytes([b0, b1, b2, b3]), map),
        _ => int32u_enum_empty(),
      };
      entries.push(H264Entry::with_group_priority(
        def.group,
        def.priority,
        SmolStr::new_static(def.name),
        H264Value::Text(value),
      ));
    }
    MdpmKind::GpsAltitudeRef => {
      // H264.pm:280-289 — `int32u`, `ValueConv => '$val ? 1 : 0'`. The
      // ValueConv collapses the raw word to 0/1 before BOTH the `-n` scalar
      // and the PrintConv map. A SHORT buffer yields `ReadValue` `''`
      // (`ExifTool.pm:6285`); the ValueConv `'' ? 1 : 0` evaluates the empty
      // string as Perl-falsy, so `$val` collapses to `0` — bundled emits
      // `-n` `0` / `-j` `Above Sea Level`, NOT a dropped tag (Codex R10 F1).
      // `buff.get(0..4)` is `Some` iff `buff.len() >= 4` (byte-identical to the
      // original if/else; the `0` fallback matches the short-buffer branch).
      let raw = match buff.get(0..4) {
        Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]),
        _ => 0,
      };
      let vc: u32 = u32::from(raw != 0);
      entries.push(H264Entry::with_group_priority(
        def.group,
        def.priority,
        SmolStr::new_static(def.name),
        H264Value::Text(int32u_enum_value(
          vc,
          &[(0, "Above Sea Level"), (1, "Below Sea Level")],
        )),
      ));
    }
    MdpmKind::Flash => {
      // H264.pm:196-202 — `int32u`, `PrintHex`, PrintConv = `%Exif::flash`.
      // A SHORT buffer yields `ReadValue` `''` (`ExifTool.pm:6285`); the
      // empty value misses the Flash PrintConv hash. ExifTool's `Unknown`
      // fallback prints the value verbatim — an empty value renders
      // `Unknown ()` (NOT `Unknown (0x0)`), and `-n` renders `""` (Codex
      // R10 F1).
      // `buff.get(0..4)` is `Some` iff `buff.len() >= 4` (byte-identical to the
      // original if/else; the `Unknown ()` fallback matches the short branch).
      let value = match buff.get(0..4) {
        Some(&[b0, b1, b2, b3]) => flash_value(u32::from_be_bytes([b0, b1, b2, b3])),
        _ => TextValue::new(SmolStr::new_static("Unknown ()"), SmolStr::default()),
      };
      entries.push(H264Entry::with_group_priority(
        def.group,
        def.priority,
        SmolStr::new_static(def.name),
        H264Value::Text(value),
      ));
    }
    MdpmKind::GpsVersionId => {
      // H264.pm:237-243 — `int8u`, `Count => 4`. The data bytes are the
      // value; `-n` is the bytes space-joined, `-j` runs the `tr/ /./`
      // PrintConv (space → dot). With `Count` SET, ExifTool's `ReadValue`
      // SHORT-READS: it shortens the count to `int($size / $len)` and reads
      // only the bytes present (`ExifTool.pm:6289-6291`), so an underlength
      // buffer still emits a (shorter) value — e.g. one data byte `2`
      // yields `GPSVersionID = "2"`. An empty buffer shortens the count to
      // `0 < 1` ⇒ `ReadValue` returns `undef` and the tag is dropped.
      let n = buff.len().min(4);
      if n >= 1 {
        // `n = buff.len().min(4) <= buff.len()`, so `.get(..n)` always hits;
        // `unwrap_or(&[])` is the unreachable fallback (byte-identical).
        let head = buff.get(..n).unwrap_or(&[]);
        let numeric = head.iter().map(u8::to_string).collect::<Vec<_>>().join(" ");
        let print_conv = head.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
        entries.push(H264Entry::with_group_priority(
          def.group,
          def.priority,
          SmolStr::new_static(def.name),
          H264Value::Text(TextValue::new(print_conv.as_str(), numeric.as_str())),
        ));
      }
    }
    MdpmKind::Rational { signed, conv } => {
      if let Some(text) = render_rational(buff, signed, conv) {
        entries.push(H264Entry::with_group_priority(
          def.group,
          def.priority,
          SmolStr::new_static(def.name),
          H264Value::Text(text),
        ));
      }
    }
    MdpmKind::Str(conv) => {
      if let Some(text) = render_string(buff, conv) {
        entries.push(H264Entry::with_group_priority(
          def.group,
          def.priority,
          SmolStr::new_static(def.name),
          H264Value::Text(text),
        ));
      }
    }
    MdpmKind::SubDir(kind) => process_subdir(kind, buff, entries, make),
  }
}

/// `%Image::ExifTool::Exif::flash` (Exif.pm:175-209) — the shared Flash
/// PrintConv map, used by H264 `0xa6 Flash` (H264.pm:201). `None` ⇒ off-map.
fn flash_print_conv(n: u32) -> Option<&'static str> {
  Some(match n {
    0x00 => "No Flash",
    0x01 => "Fired",
    0x05 => "Fired, Return not detected",
    0x07 => "Fired, Return detected",
    0x08 => "On, Did not fire",
    0x09 => "On, Fired",
    0x0d => "On, Return not detected",
    0x0f => "On, Return detected",
    0x10 => "Off, Did not fire",
    0x14 => "Off, Did not fire, Return not detected",
    0x18 => "Auto, Did not fire",
    0x19 => "Auto, Fired",
    0x1d => "Auto, Fired, Return not detected",
    0x1f => "Auto, Fired, Return detected",
    0x20 => "No flash function",
    0x30 => "Off, No flash function",
    0x41 => "Fired, Red-eye reduction",
    0x45 => "Fired, Red-eye reduction, Return not detected",
    0x47 => "Fired, Red-eye reduction, Return detected",
    0x49 => "On, Red-eye reduction",
    0x4d => "On, Red-eye reduction, Return not detected",
    0x4f => "On, Red-eye reduction, Return detected",
    0x50 => "Off, Red-eye reduction",
    0x58 => "Auto, Did not fire, Red-eye reduction",
    0x59 => "Auto, Fired, Red-eye reduction",
    0x5d => "Auto, Fired, Red-eye reduction, Return not detected",
    0x5f => "Auto, Fired, Red-eye reduction, Return detected",
    _ => return None,
  })
}

/// Render `0xa6 Flash`. `-n` = the decimal `int32u` word; `-j` = the mapped
/// label, or `Unknown (0x%x)` on a hash miss — ExifTool's `Flags =>
/// 'PrintHex'` (H264.pm:199) makes a missed PrintConv-hash lookup render as
/// `Unknown (0x%x)` (`ExifTool.pm:3617-3620`), NOT the bare hex word.
fn flash_value(n: u32) -> TextValue {
  let numeric = smol_u64(u64::from(n));
  let print_conv = match flash_print_conv(n) {
    Some(label) => SmolStr::new_static(label),
    // PrintConv-hash miss with `PrintHex` ⇒ `Unknown (0x%x)`.
    None => print_conv_miss_int(u64::from(n), true),
  };
  TextValue::new(print_conv, numeric)
}

/// The numeric scalar a ValueConv/PrintConv expression sees for one rational32
/// component (Codex R3 F1).
///
/// `GetRational32u`/`GetRational32s` do NOT hand the exact `num/den` quotient
/// to downstream conversions — they `return RoundFloat($num/$den, 7)`
/// (`ExifTool.pm:6087,6094`), i.e. the quotient rendered as a `%.7g` STRING.
/// A subsequent `ValueConv`/`PrintConv` then numifies *that rounded string*.
/// For a non-terminating rational the rounded value differs from the exact
/// quotient — e.g. `1/3` ⇒ `RoundFloat` `"0.3333333"`, numified `0.3333333`,
/// not `0.333333333…`. MaxApertureValue `2 ** ($val/2)` on `1/3` therefore
/// yields bundled `1.12246203534218`, not the exact `1.12246204830937`.
///
/// This helper reproduces the round-then-numify chain: it stringifies via the
/// shared [`Rational::exiftool_val_str`] (`%.7g` for a rational32) and parses
/// the result back to `f64`. The caller must guarantee the rational is finite
/// (denominator ≠ 0) — every ValueConv branch below guards that first
/// (`inf`/`undef` would not `parse::<f64>()`), so a parse failure is
/// unreachable and falls back to the exact quotient.
fn rational_value_conv_scalar(r: crate::value::Rational) -> f64 {
  let rounded = r.exiftool_val_str();
  rounded
    .parse::<f64>()
    .unwrap_or_else(|_| r.numerator() as f64 / r.denominator() as f64)
}

/// The f64 a ValueConv/PrintConv expression sees after Perl *numifies* one
/// rational32 component — including the zero-denominator case (Codex R4 F1).
///
/// `GetRational32*` returns either a `RoundFloat(n/d, 7)` STRING (finite) or
/// the bare words `inf` / `undef` (`ExifTool.pm:6081-6095`). A downstream
/// ValueConv/PrintConv numifies that scalar: Perl's `'inf'+0` is
/// floating-point `Inf` (for ANY nonzero numerator — the word is unsigned, so
/// even `-1/0` numifies to `+∞`), and `'undef'+0` is `0`. A finite component
/// reuses [`rational_value_conv_scalar`]'s round-then-numify chain (R3 F1).
fn numify_rational_str(r: crate::value::Rational) -> f64 {
  if r.denominator() == 0 {
    // `exiftool_val_str` already encodes the sign-agnostic `inf`/`undef`
    // contract; `inf` numifies to `+∞`, `undef` to `0`.
    if r.numerator() != 0 {
      f64::INFINITY
    } else {
      0.0
    }
  } else {
    rational_value_conv_scalar(r)
  }
}

/// Decode an MDPM `rational32u`/`rational32s` value (H264.pm:153-370). The
/// 4-byte data field of each absorbed record is a **big-endian 16/16**
/// rational (`GetRational32*`, `ExifTool.pm:6081-6095` — `num = Get16*`,
/// `den = Get16*` two bytes later). A `Combine => 2` GPS tag arrives with 12
/// buffer bytes ⇒ three rationals.
fn render_rational(buff: &[u8], signed: bool, conv: RationalConv) -> Option<TextValue> {
  // Split the buffer into 4-byte rational chunks (1 for a plain tag,
  // 3 for a `Combine => 2` GPS tag).
  let mut rats: Vec<crate::value::Rational> = Vec::new();
  let mut i = 0usize;
  while i + 4 <= buff.len() {
    // The `i + 4 <= buff.len()` loop bound proves this 4-byte window exists,
    // so the destructure always binds (byte-identical; `break` ≡ the loop exit).
    let Some(&[b0, b1, b2, b3]) = buff.get(i..i + 4) else {
      break;
    };
    let num = i16::from_be_bytes([b0, b1]);
    let den = i16::from_be_bytes([b2, b3]);
    let r = if signed {
      // rational32s — `Get16s` num/den.
      crate::value::Rational::rational32(i64::from(num), i64::from(den))
    } else {
      // rational32u — `Get16u` num/den.
      crate::value::Rational::rational32(i64::from(num as u16), i64::from(den as u16))
    };
    rats.push(r);
    i += 4;
  }
  // ReadValue short-read (Codex R11 F1). A `Count`-less `rational32*` format
  // has `$len = 4`; when the MDPM buffer holds fewer than four bytes
  // `ReadValue` hits `return '' if … $size < $len` (`ExifTool.pm:6285`) and
  // returns the empty string `''` — it does NOT return `undef`, so `HandleTag`
  // still emits the tag. `rats.is_empty()` is exactly that `$size < 4`
  // condition (each chunk is 4 bytes). The empty `$val` then flows through the
  // SAME ValueConv/PrintConv as the integer kinds' R10 F1 fix: mirror Perl's
  // numification of `''` (`'' + 0 == 0`, `IsFloat('')` false) per `conv`.
  if rats.is_empty() {
    return Some(match conv {
      // No conv — `-j` = `-n` = the empty `ReadValue` result.
      RationalConv::Plain => TextValue::uniform(""),
      // `PrintExposureTime('')`: `IsFloat('')` is false ⇒ `return $secs`
      // verbatim (Exif.pm:5704), so both modes are `''`.
      RationalConv::ExposureTime => TextValue::uniform(""),
      // ValueConv = none; `-n` = `''`. `-j` runs `PrintFraction('')`:
      // `'' *= 1.00001` ⇒ `0`, `not $val` ⇒ `$str = '0'` (Exif.pm:5519-5523).
      RationalConv::ExposureCompensation => TextValue::new(print_fraction(0.0).as_str(), ""),
      // ValueConv `2 ** ($val / 2)` ALWAYS runs; `'' / 2` numifies to `0`,
      // `2 ** 0` = `1`. `-n` = the ValueConv'd `1`; `-j` = `sprintf("%.1f", 1)`
      // = `1.0`.
      RationalConv::MaxApertureValue => TextValue::new("1.0", "1"),
      // PrintConv `"$val mm"`; `-n` = the empty `$val`, `-j` = `" mm"`.
      RationalConv::FocalLength35 => TextValue::new(" mm", ""),
      // ValueConv `GPS::ToDegrees('')`: not `inf`/`undef`, but the
      // decimal-extraction regex finds no `$d` ⇒ `return '' unless defined $d`
      // (GPS.pm:594). `GPS::ToDMS('')` likewise returns `''`. Both modes `''`.
      RationalConv::GpsCoordinate => TextValue::uniform(""),
      // ValueConv `GPS::ConvertTimeStamp('')`: `split ' ', ''` yields no
      // fields, so `$h/$m/$s` are undef ⇒ `$f = 0` ⇒ `00:00:00` (GPS.pm:461-
      // 473). `PrintTimeStamp("00:00:00")` finds no fractional seconds and
      // returns it unchanged. Both modes `00:00:00`.
      RationalConv::GpsTimeStamp => {
        let numeric = gps_convert_time_stamp(0.0, 0.0, 0.0);
        let print_conv = gps_print_time_stamp(&numeric);
        TextValue::new(print_conv.as_str(), numeric.as_str())
      }
    });
  }
  let first = *rats.first()?;

  match conv {
    RationalConv::Plain => {
      // No ValueConv — `-j` = `-n` = `RoundFloat(n/d, 7)`.
      let s = first.exiftool_val_str();
      Some(TextValue::uniform(s.as_str()))
    }
    RationalConv::ExposureTime => {
      // H264.pm:153-158 — PrintConv = `PrintExposureTime`. `-n` = the bare
      // rational quotient. Codex R3 F1: `PrintExposureTime` receives `$val`
      // = the `RoundFloat(n/d, 7)` STRING numified, not the exact quotient.
      let numeric = first.exiftool_val_str();
      let print_conv = if first.denominator() == 0 {
        numeric.clone()
      } else {
        print_exposure_time(rational_value_conv_scalar(first))
      };
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
    RationalConv::ExposureCompensation => {
      // H264.pm:184-189 — ValueConv = none, PrintConv = `PrintFraction`.
      //
      // `-n` is the bare `GetRational32s` result. For a finite rational that
      // is the `RoundFloat(n/d, 7)` STRING (Codex R3 F1); for a
      // zero-denominator one (Codex R4 F1) it is the raw word `inf`
      // (numerator ≠ 0) or `undef` (numerator == 0) — emitted VERBATIM, NOT
      // numified, because no ValueConv runs (ExifTool.pm:6081-6087).
      let numeric = first.exiftool_val_str();
      // `-j` runs `PrintFraction($val)`, which numifies whatever `$val` is —
      // a number, or the words `inf`→+∞ / `undef`→0 (`'inf'+0` = Perl `Inf`,
      // `'undef'+0` = 0). `PrintFraction(+∞)` falls through its int/half/third
      // guards (each `int/$val` is `NaN`) to `sprintf("%+.3g", +∞)` = `+Inf`;
      // `PrintFraction(0)` short-circuits to `0` (Exif.pm:5522).
      let print_conv = print_fraction(numify_rational_str(first));
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
    RationalConv::MaxApertureValue => {
      // H264.pm:190-195 — ValueConv `2 ** ($val / 2)`, PrintConv `%.1f`.
      //
      // ValueConv ALWAYS runs (independent of `-n`/`-j`). For a finite
      // rational `$val` is the `RoundFloat(n/d, 7)` STRING from
      // `GetRational32u` numified, NOT the exact quotient (Codex R3 F1):
      // `1/3` ⇒ `$val` `0.3333333`, so `2 ** ($val/2)` = `1.12246203534218`
      // (bundled). For a zero-denominator rational (Codex R4 F1) `$val` is
      // the word `inf`→+∞ / `undef`→0: `2 ** (+∞/2)` = `+∞`, `2 ** (0/2)` = 1.
      let val = numify_rational_str(first);
      let vc = 2f64.powf(val / 2.0);
      // `-n` is the ValueConv'd value. Perl stringifies a finite NV via `%g`
      // (`RoundFloat`-free here — ExifTool prints the raw number) and a
      // non-finite NV with title-case `Inf`/`-Inf`/`NaN`.
      let numeric = crate::value::perl_nonfinite_str(vc)
        .map_or_else(|| crate::value::format_g(vc, 15), str::to_string);
      // `-j` runs `sprintf("%.1f", $val)`: a finite value formats normally;
      // Perl's `%.1f` of `±∞`/`NaN` is `Inf`/`-Inf`/`NaN` (no decimals).
      let print_conv = crate::value::perl_nonfinite_str(vc)
        .map_or_else(|| std::format!("{vc:.1}"), str::to_string);
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
    RationalConv::FocalLength35 => {
      // H264.pm:221-225 — PrintConv `"$val mm"`.
      let numeric = first.exiftool_val_str();
      let print_conv = std::format!("{numeric} mm");
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
    RationalConv::GpsCoordinate => {
      // H264.pm:253-279 — ValueConv `GPS::ToDegrees`, PrintConv `GPS::ToDMS`.
      //
      // ExifTool builds the combined `$val` by joining each component's
      // `GetRational32u` result (`ExifTool.pm:6089-6094`); a zero-denominator
      // component is the bare word `inf` (numerator ≠ 0) or `undef`
      // (numerator == 0), NOT a number. `GPS::ToDegrees` then bails with
      // `return '' if $val =~ /\b(inf|undef)\b/` (GPS.pm:584) — a single
      // invalid component voids the WHOLE coordinate. `GPS::ToDMS` likewise
      // returns the empty value unchanged for an empty input (GPS.pm:499-503).
      // We must NOT substitute `0.0`: that fabricates a real coordinate.
      if rats.iter().any(|r| r.denominator() == 0) {
        // Bundled emits the tag with an empty ValueConv AND PrintConv result.
        return Some(TextValue::uniform(""));
      }
      // Codex R3 F1: ExifTool joins each component's `GetRational32u`
      // result — `RoundFloat(n/d, 7)` STRINGS — into `$val`, and
      // `GPS::ToDegrees` numifies those rounded strings. A non-terminating
      // component (`1/3` ⇒ `0.3333333`) must be rounded BEFORE the
      // deg + min/60 + sec/3600 combination, not the exact quotient.
      let parts: Vec<f64> = rats
        .iter()
        .map(|r| rational_value_conv_scalar(*r))
        .collect();
      let degrees = gps_to_degrees(&parts);
      let numeric = crate::value::format_g(degrees, 15);
      let print_conv = gps_to_dms(degrees);
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
    RationalConv::GpsTimeStamp => {
      // H264.pm:295-303 — ValueConv `ConvertTimeStamp`, PrintConv
      // `PrintTimeStamp`. The 3 rationals are hour / minute / second.
      //
      // As above, a zero-denominator component reaches `GPS::ConvertTimeStamp`
      // (GPS.pm:459) as the word `inf`/`undef`, not a number. Perl numifies
      // `'undef'` to `0` but `'inf'` to floating-point infinity — so a
      // `1/0` component (numerator ≠ 0) poisons the total into `Inf`, and
      // `ConvertTimeStamp` then emits `Inf:NaN:000000000NaN`; a `0/0`
      // component (numerator == 0) is simply `0`. We mirror that by mapping
      // each zero-denominator component to `±INFINITY` (numerator ≠ 0) or
      // `0.0` (numerator == 0); `gps_convert_time_stamp` reproduces the
      // `Inf:NaN:…` string for a non-finite total.
      // Codex R3 F1: a finite component reaches `ConvertTimeStamp` as its
      // `GetRational32u` `RoundFloat(n/d, 7)` STRING numified — round
      // BEFORE the h*3600 + m*60 + s combination (`1/3` ⇒ `0.3333333`).
      let parts: Vec<f64> = rats
        .iter()
        .map(|r| {
          if r.denominator() == 0 {
            match r.numerator().cmp(&0) {
              std::cmp::Ordering::Greater => f64::INFINITY,
              std::cmp::Ordering::Less => f64::NEG_INFINITY,
              std::cmp::Ordering::Equal => 0.0,
            }
          } else {
            rational_value_conv_scalar(*r)
          }
        })
        .collect();
      let h = parts.first().copied().unwrap_or(0.0);
      let m = parts.get(1).copied().unwrap_or(0.0);
      let s = parts.get(2).copied().unwrap_or(0.0);
      let numeric = gps_convert_time_stamp(h, m, s);
      let print_conv = gps_print_time_stamp(&numeric);
      Some(TextValue::new(print_conv.as_str(), numeric.as_str()))
    }
  }
}

/// Decode an MDPM `string`-format value (H264.pm:244-411). ExifTool's
/// `string` reader truncates the buffer at the first NUL
/// (`ReadValue` → `s/\0.*//s`, `ExifTool.pm:6301`).
fn render_string(buff: &[u8], conv: StringConv) -> Option<TextValue> {
  // Truncate at the first NUL, then interpret as Latin-1/ASCII bytes.
  let end = buff.iter().position(|&b| b == 0).unwrap_or(buff.len());
  // `end <= buff.len()` (a `position` index or `buff.len()`), so `.get(..end)`
  // always hits; `unwrap_or(&[])` is the unreachable fallback (byte-identical).
  let raw: std::string::String = buff
    .get(..end)
    .unwrap_or(&[])
    .iter()
    .map(|&b| b as char)
    .collect();

  match conv {
    StringConv::Plain => {
      // H264.pm:371-377 — `0xc7 GPSMapDatum` has NO `RawConv`, so bundled
      // `ParseH264Video`/`HandleTag` emit it even when the MDPM bytes are
      // all-NUL: an empty buffer becomes a present-but-empty `GPS:GPSMapDatum`
      // (`""`) in both `-j` and `-n`. Do NOT drop the empty case here — that
      // would silently omit a faithful empty GPS field (Codex R6 F1).
      Some(TextValue::uniform(raw.as_str()))
    }
    StringConv::PlainDropEmpty => {
      // H264.pm:403-411 — `0xe4 Model` (Sony-only) carries
      // `RawConv => '$val eq "" ? undef : $val'` (H264.pm:410); an empty
      // string yields `undef`, so the tag is NOT emitted. This drop is
      // SPECIFIC to `0xe4` — the GPS string tags ([`StringConv::Plain`] /
      // [`StringConv::ExifDate`]) have no such `RawConv` and keep the empty
      // value.
      if raw.is_empty() {
        return None;
      }
      Some(TextValue::uniform(raw.as_str()))
    }
    StringConv::ExifDate => {
      // H264.pm:380-387 — `0xca GPSDateStamp`, ValueConv `Exif::ExifDate`.
      // The trailing NUL was already stripped above; `ExifDate` re-punctuates
      // `YYYY?MM?DD` (Exif.pm:6068-6076). There is NO `RawConv`, and
      // `ExifDate("")` returns `""` (the substitution does not match), so an
      // empty buffer is emitted as a present-but-empty `GPS:GPSDateStamp`
      // (`""`) in both `-j` and `-n` — do NOT drop it (Codex R6 F1).
      let v = exif_date(&raw);
      Some(TextValue::uniform(v.as_str()))
    }
    StringConv::Enum(map) => {
      // H264.pm:244-364 — single-character PrintConv map. `-n` = raw,
      // `-j` = mapped (off-map ⇒ `Unknown (<raw>)`, `ExifTool.pm:3622`).
      let print_conv = match map.iter().find(|(k, _)| *k == raw) {
        Some((_, label)) => SmolStr::new_static(label),
        None => print_conv_miss_str(&raw),
      };
      Some(TextValue::new(print_conv, SmolStr::new(&raw)))
    }
  }
}

/// `Image::ExifTool::Exif::PrintFraction` (Exif.pm:5516-5535) — the shared
/// fraction PrintConv used by H264 `0xa4 ExposureCompensation` (H264.pm:188).
fn print_fraction(val: f64) -> std::string::String {
  let val = val * 1.000_01; // Exif.pm:5521 — avoid round-off errors.
  if val == 0.0 {
    return "0".to_string();
  }
  // Exif.pm:5524-5529 — try integer, then halves, then thirds.
  let int_v = val.trunc();
  if int_v / val > 0.999 {
    return std::format!("{:+}", int_v as i64);
  }
  let v2 = (val * 2.0).trunc();
  if v2 / (val * 2.0) > 0.999 {
    return std::format!("{:+}/2", v2 as i64);
  }
  let v3 = (val * 3.0).trunc();
  if v3 / (val * 3.0) > 0.999 {
    return std::format!("{:+}/3", v3 as i64);
  }
  // Exif.pm:5531 — `sprintf("%+.3g", $val)`. A non-finite `$val` (Codex R4
  // F1: a `1/0` ExposureCompensation numifies to `+∞`) reaches here because
  // the int/half/third guards above all compare `int/$val` = `NaN` (not
  // `> 0.999`). Perl's `sprintf("%+.3g", +∞)` is `+Inf` (`%+.3g` of
  // `-∞`/`NaN` is `-Inf`/`NaN` — `NaN` carries no `+`).
  if let Some(nf) = crate::value::perl_nonfinite_str(val) {
    return if nf.starts_with('-') || nf == "NaN" {
      nf.to_string()
    } else {
      std::format!("+{nf}")
    };
  }
  let mut s = crate::value::format_g(val, 3);
  if !s.starts_with('-') {
    s.insert(0, '+');
  }
  s
}

/// `Image::ExifTool::Exif::ExifDate` (Exif.pm:6068-6076) — re-punctuate a
/// `YYYY?MM?DD` date with colon separators. The NUL terminator is already
/// stripped by [`render_string`]; this mirrors the `s/(\d{4})[^\d]*(\d{2})
/// [^\d]*(\d{2})$/$1:$2:$3/` rewrite (anchored at the END of the string).
fn exif_date(date: &str) -> std::string::String {
  let chars: Vec<char> = date.chars().collect();
  // The regex is end-anchored — find a `\d{4} <non-digit>* \d{2}
  // <non-digit>* \d{2}` suffix and replace it with `YYYY:MM:DD`.
  // Walk back from the end: last 2 digits = DD, then non-digits, then 2
  // digits = MM, then non-digits, then 4 digits = YYYY.
  let is_d = |c: char| c.is_ascii_digit();
  let mut i = chars.len();
  let take_digits = |i: &mut usize, n: usize| -> Option<std::string::String> {
    let mut got = std::string::String::new();
    for _ in 0..n {
      // The `*i == 0` guard prevents the `*i - 1` underflow; `.get(*i-1)` then
      // returns `Some` for a valid index (byte-identical to `chars[*i-1]`).
      let Some(&prev) = i.checked_sub(1).and_then(|p| chars.get(p)) else {
        return None;
      };
      if !is_d(prev) {
        return None;
      }
      *i -= 1;
      got.push(prev);
    }
    Some(got.chars().rev().collect())
  };
  let skip_nondigits = |i: &mut usize| {
    // The `*i > 0` guard prevents the `*i - 1` underflow; `.get()` then hits
    // for a valid index (byte-identical to `chars[*i-1]`).
    while *i > 0 && !chars.get(*i - 1).copied().is_some_and(is_d) {
      *i -= 1;
    }
  };
  let dd = take_digits(&mut i, 2);
  skip_nondigits(&mut i);
  let mm = take_digits(&mut i, 2);
  skip_nondigits(&mut i);
  let yyyy = take_digits(&mut i, 4);
  match (yyyy, mm, dd) {
    (Some(y), Some(m), Some(d)) => {
      // Keep any prefix before the matched `YYYY` (the regex only rewrites
      // the trailing run). `i <= chars.len()` (only ever decremented), so
      // `.get(..i)` always hits; `unwrap_or(&[])` is unreachable (byte-identical).
      let prefix: std::string::String = chars.get(..i).unwrap_or(&[]).iter().collect();
      std::format!("{prefix}{y}:{m}:{d}")
    }
    // No `YYYY..MM..DD` suffix ⇒ the regex does not match; return as-is.
    _ => date.to_string(),
  }
}

/// `Image::ExifTool::GPS::ToDegrees` (GPS.pm:582-596), specialised for the
/// already-numeric `[deg, min, sec]` input H264's `Combine => 2` GPS tags
/// produce: `deg + (min + sec/60) / 60`.
fn gps_to_degrees(parts: &[f64]) -> f64 {
  let d = parts.first().copied().unwrap_or(0.0);
  let m = parts.get(1).copied().unwrap_or(0.0);
  let s = parts.get(2).copied().unwrap_or(0.0);
  d + (m + s / 60.0) / 60.0
}

/// `Image::ExifTool::GPS::ToDMS` (GPS.pm:495-575) for the default
/// `CoordFormat` (`undef` ⇒ `q{%d deg %d' %.2f"}`), called WITHOUT a
/// reference direction (H264.pm:260/278 — `ToDMS($self, $val, 1)`). Produces
/// the `D deg M' S.SS"` string with the round-off carry to keep M/S < 60.
fn gps_to_dms(val: f64) -> std::string::String {
  // GPS.pm:530-535 — no `$ref` ⇒ `$fmt = q{%d deg %d' %.2f"}`. 3 specifiers.
  let mut c0 = val.trunc();
  let mut c1 = (val - c0) * 60.0;
  c1 = c1.trunc();
  let mut c2 = (val - c0 - c1 / 60.0) * 3600.0;
  // GPS.pm:558-563 — format the seconds, then handle the >= 60 carry.
  let mut c2_str = std::format!("{c2:.2}");
  if c2_str.parse::<f64>().unwrap_or(c2) >= 60.0 {
    c2 -= 60.0;
    c2_str = std::format!("{c2:.2}");
    c1 += 1.0;
    if c1 >= 60.0 {
      c1 -= 60.0;
      c0 += 1.0;
    }
  }
  // GPS.pm:566 — `sprintf('%d deg %d\' %.2f"', @c)`.
  std::format!("{} deg {}' {}\"", c0 as i64, c1 as i64, c2_str)
}

/// `Image::ExifTool::GPS::ConvertTimeStamp` (GPS.pm:459-474) — `[h, m, s]`
/// ⇒ a normalised `HH:MM:SS[.ffff]` string with trailing zeros trimmed.
fn gps_convert_time_stamp(h: f64, m: f64, s: f64) -> std::string::String {
  // GPS.pm:463 — total seconds.
  let f_total = (h * 60.0 + m) * 60.0 + s;
  // A non-finite total occurs only when a component was an `inf` rational
  // (zero denominator, non-zero numerator — `ExifTool.pm:6089`). Perl's
  // `int(Inf)` stays `Inf` and `$f -= $h*3600` becomes `NaN`, so
  // `sprintf("%012.9f", NaN)` ⇒ `000000000NaN` and the final string is
  // `Inf:NaN:000000000NaN` (capital `I`, as Perl stringifies infinity).
  if !f_total.is_finite() {
    let head = if f_total.is_sign_negative() {
      "-Inf"
    } else {
      "Inf"
    };
    return std::format!("{head}:NaN:000000000NaN");
  }
  let hh = (f_total / 3600.0).trunc();
  let mut f = f_total - hh * 3600.0;
  let mut mm = (f / 60.0).trunc();
  f -= mm * 60.0;
  let mut hh_i = hh as i64;
  // GPS.pm:466 — `sprintf('%012.9f', $f)`.
  let ss_str = std::format!("{f:012.9}");
  let (ss_final, mm_i) = if ss_str.parse::<f64>().unwrap_or(f) >= 60.0 {
    // GPS.pm:467-469 — carry.
    mm += 1.0;
    let mut mm2 = mm as i64;
    if mm2 >= 60 {
      mm2 -= 60;
      hh_i += 1;
    }
    ("00".to_string(), mm2)
  } else {
    // GPS.pm:471 — trim trailing zeros + the decimal point.
    let mut t = ss_str;
    if t.contains('.') {
      while t.ends_with('0') {
        t.pop();
      }
      if t.ends_with('.') {
        t.pop();
      }
    }
    (t, mm as i64)
  };
  // GPS.pm:473 — `sprintf("%.2d:%.2d:%s", $h, $m, $ss)`.
  std::format!("{hh_i:02}:{mm_i:02}:{ss_final}")
}

/// `Image::ExifTool::GPS::PrintTimeStamp` (GPS.pm:480-487) — round the
/// fractional-seconds tail of a `ConvertTimeStamp` string to microseconds.
fn gps_print_time_stamp(val: &str) -> std::string::String {
  // GPS.pm:483 — only fires when the value ends in `:DD.ffff`.
  let Some(dot) = val.rfind('.') else {
    return val.to_string();
  };
  let Some(colon) = val[..dot].rfind(':') else {
    return val.to_string();
  };
  let secs_part = &val[colon + 1..];
  // Must be exactly two integer digits then a fractional part. The
  // `secs_part.len() < 4` short-circuit guards the 2-byte prefix, so
  // `.get(..2)` matches the raw `as_bytes()[..2]` (byte-identical).
  if secs_part.len() < 4
    || !secs_part
      .as_bytes()
      .get(..2)
      .is_some_and(|b| b.iter().all(u8::is_ascii_digit))
  {
    return val.to_string();
  }
  let Ok(secs) = secs_part.parse::<f64>() else {
    return val.to_string();
  };
  // GPS.pm:484 — `int($1 * 1000000 + 0.5) / 1000000`.
  let rounded = (secs * 1_000_000.0 + 0.5).trunc() / 1_000_000.0;
  let mut s = crate::value::format_g(rounded, 15);
  // GPS.pm:485 — `$s = "0$s" if $s < 10`.
  if rounded < 10.0 {
    s.insert(0, '0');
  }
  std::format!("{}:{s}", &val[..colon])
}

/// Format an integer PrintConv-hash MISS the way ExifTool's `GetValue`
/// renders one (`ExifTool.pm:3616-3623`): with no `OTHER`/`BITMASK` sub, a
/// missed lookup becomes `Unknown (0x%x)` when the tag carries
/// `Flags => 'PrintHex'`, otherwise `Unknown (%d)`. This is a PrintConv-only
/// (`-j`) rendering — the `-n` path keeps the raw scalar.
fn print_conv_miss_int(n: u64, print_hex: bool) -> SmolStr {
  if print_hex {
    SmolStr::new(std::format!("Unknown (0x{n:x})"))
  } else {
    SmolStr::new(std::format!("Unknown ({n})"))
  }
}

/// Format a STRING PrintConv-hash miss — `Unknown (<raw>)` (`ExifTool.pm:3622`,
/// `$convType eq 'PrintConv'`, no `PrintHex` on a string tag). `-j` only.
fn print_conv_miss_str(raw: &str) -> SmolStr {
  SmolStr::new(std::format!("Unknown ({raw})"))
}

/// Render an `int32u` MDPM tag into a [`TextValue`] — `-j` = the mapped
/// label (or `Unknown (%d)` on a hash miss, per `ExifTool.pm:3622`), `-n` =
/// the bare integer.
fn int32u_enum_value(n: u32, map: &'static [(u32, &'static str)]) -> TextValue {
  let numeric = {
    let mut s = std::string::String::new();
    use core::fmt::Write;
    let _ = write!(s, "{n}");
    s
  };
  let print_conv = match map.iter().find(|(k, _)| *k == n) {
    Some((_, label)) => SmolStr::new(label),
    // PrintConv-hash miss ⇒ `Unknown (N)` (no `PrintHex` on these tags).
    None => print_conv_miss_int(u64::from(n), false),
  };
  TextValue::new(print_conv, SmolStr::new(&numeric))
}

/// Render a SHORT (`< 4`-byte) `int32u` MDPM record — ExifTool's `ReadValue`
/// returns the empty string `''` for an underlength `Count`-less fixed-width
/// format (`ExifTool.pm:6285`). The empty value misses every PrintConv hash,
/// so `-j` renders `Unknown ()` and `-n` renders the bare empty string
/// (Codex R10 F1).
fn int32u_enum_empty() -> TextValue {
  TextValue::new(print_conv_miss_str(""), SmolStr::default())
}

/// One argument in a Perl `sprintf` argument list — either a number or a
/// string. Mirrors Perl's loosely-typed scalars closely enough for the two
/// MDPM `ValueConv` format strings: `%.2x`/`%.2d` *numify* their argument,
/// `%s` *stringifies* it, and a MISSING argument is Perl-undef (numifies to
/// `0`, stringifies to `""`).
#[derive(Clone)]
enum PerlArg {
  Num(i64),
  Str(&'static str),
}

impl PerlArg {
  /// Perl numification of a scalar for `%x`/`%d`. A [`PerlArg::Num`] is the
  /// integer itself; a [`PerlArg::Str`] numifies its leading numeric prefix
  /// (`"30"` ⇒ `30`, `"+"`/`" DST"`/`""` ⇒ `0`) — faithful to Perl's
  /// `"string" + 0` for the strings these format strings actually pass
  /// (`"+"`, `"-"`, `"00"`, `"30"`, `" DST"`, `""`).
  fn numify(&self) -> i64 {
    match self {
      Self::Num(n) => *n,
      Self::Str(s) => {
        let t = s.trim_start();
        let digits: std::string::String = t.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap_or(0)
      }
    }
  }
}

/// Render one `sprintf` conversion spec from a positionally-consumed argument
/// list. `idx` is advanced past the consumed argument; a spec whose argument
/// is absent (`idx >= args.len()`) sees Perl-undef.
fn perl_sprintf_spec(
  out: &mut std::string::String,
  spec: PerlSpec,
  args: &[PerlArg],
  idx: &mut usize,
) {
  use core::fmt::Write;
  let arg = args.get(*idx).cloned();
  *idx += 1;
  match spec {
    // `%.2x` — minimum two hex digits of the numified argument (missing ⇒ 0).
    PerlSpec::Hex2 => {
      let n = arg.as_ref().map_or(0, PerlArg::numify);
      let _ = write!(out, "{:02x}", n as u64);
    }
    // `%.2d` — minimum two decimal digits of the numified argument.
    PerlSpec::Dec2 => {
      let n = arg.as_ref().map_or(0, PerlArg::numify);
      let _ = write!(out, "{n:02}");
    }
    // `%s` — the stringified argument (missing ⇒ empty string).
    PerlSpec::Str => match arg {
      Some(PerlArg::Str(s)) => out.push_str(s),
      Some(PerlArg::Num(n)) => {
        let _ = write!(out, "{n}");
      }
      None => {}
    },
  }
}

/// A single conversion spec used by the two MDPM `sprintf` format strings.
#[derive(Clone, Copy)]
enum PerlSpec {
  Hex2,
  Dec2,
  Str,
}

/// `0x13 TimeCode` `ValueConv` (H264.pm:90) —
/// `sprintf("%.2x:%.2x:%.2x:%.2x", reverse unpack("C*",$val))`.
///
/// `ProcessSEI` short-reads `$buff`, so `$val` may be shorter than four
/// bytes; `unpack("C*",$val)` yields exactly the bytes present, `reverse`
/// reverses *those*, and `sprintf`'s four `%.2x` specs consume the reversed
/// list positionally — any missing spec sees Perl-undef and prints `00`.
fn render_timecode(buff: &[u8]) -> std::string::String {
  // `reverse unpack("C*", $val)` — the present bytes, reversed.
  let args: Vec<PerlArg> = buff
    .iter()
    .rev()
    .map(|&b| PerlArg::Num(i64::from(b)))
    .collect();
  let mut out = std::string::String::new();
  let mut idx = 0usize;
  for (i, spec) in [PerlSpec::Hex2; 4].into_iter().enumerate() {
    if i != 0 {
      out.push(':');
    }
    perl_sprintf_spec(&mut out, spec, &args, &mut idx);
  }
  out
}

/// `0x18 DateTimeOriginal` `ValueConv` (H264.pm:108-115).
///
/// Perl: `my ($tz, @a) = unpack('C*',$val); sprintf('%.2x%.2x:%.2x:%.2x
/// %.2x:%.2x:%.2x%s%.2d:%s%s', @a, tz_sign, tz_hours, tz_min, dst)`.
///
/// `$tz` is the FIRST unpacked byte (Perl-undef when `$buff` is empty — its
/// bit tests then all see `0`); `@a` is every byte AFTER it. The 11
/// conversion specs consume `(@a..., tz_sign, tz_hours, tz_min, dst)`
/// POSITIONALLY: with a full 8-byte buffer `@a` has 7 entries and the four
/// trailing args land exactly in the `%s %.2d %s %s` slots; with a short
/// buffer `@a` is shorter, the trailing args slide forward into earlier
/// `%.2x`/`%.2d` slots (where they numify), and the unfilled tail specs see
/// Perl-undef.
fn render_datetime_original(buff: &[u8]) -> TextValue {
  // `($tz, @a) = unpack('C*', $val)` — `$tz` undef ⇒ bit tests see 0.
  let tz = buff.first().copied().unwrap_or(0);
  let tz_sign: &'static str = if tz & 0x20 != 0 { "-" } else { "+" };
  let tz_hours = i64::from((tz >> 1) & 0x0f);
  let tz_min: &'static str = if tz & 0x01 != 0 { "30" } else { "00" };
  let dst: &'static str = if tz & 0x40 != 0 { " DST" } else { "" };

  // Argument list: `@a` (every byte after `$tz`) then the four computed args.
  let mut args: Vec<PerlArg> = buff
    .iter()
    .skip(1)
    .map(|&b| PerlArg::Num(i64::from(b)))
    .collect();
  args.push(PerlArg::Str(tz_sign));
  args.push(PerlArg::Num(tz_hours));
  args.push(PerlArg::Str(tz_min));
  args.push(PerlArg::Str(dst));

  // Format `%.2x%.2x:%.2x:%.2x %.2x:%.2x:%.2x%s%.2d:%s%s` as an ordered
  // sequence of literals (`Ok`) and conversion specs (`Err`); specs consume
  // `args` positionally, literals are emitted verbatim.
  use PerlSpec::{Dec2, Hex2, Str};
  let template: [core::result::Result<char, PerlSpec>; 17] = [
    Err(Hex2),
    Err(Hex2),
    Ok(':'),
    Err(Hex2),
    Ok(':'),
    Err(Hex2),
    Ok(' '),
    Err(Hex2),
    Ok(':'),
    Err(Hex2),
    Ok(':'),
    Err(Hex2),
    Err(Str),
    Err(Dec2),
    Ok(':'),
    Err(Str),
    Err(Str),
  ];
  let mut value = std::string::String::new();
  let mut idx = 0usize;
  for item in template {
    match item {
      Ok(lit) => value.push(lit),
      Err(spec) => perl_sprintf_spec(&mut value, spec, &args, &mut idx),
    }
  }

  // H264.pm:115 — `-j` runs `ConvertDateTime`; `-n` keeps the ValueConv string.
  let print_conv = crate::datetime::convert_datetime(&value);
  TextValue::new(print_conv.as_str(), value.as_str())
}

// ===========================================================================
// Binary subdirectories (H264.pm:424-581)
// ===========================================================================

/// Dispatch a `SubDir` MDPM tag's 4 data bytes to its `ProcessBinaryData`
/// table. Each subdirectory emits zero or more entries.
fn process_subdir(
  kind: SubDirKind,
  buff: &[u8],
  entries: &mut Vec<H264Entry>,
  make: &mut Option<SmolStr>,
) {
  match kind {
    SubDirKind::MakeModel => {
      // H264.pm:521-550 — `FORMAT => 'int16u'`, big-endian. Word 0 = Make.
      // `buff.get(0..2)` is `Some` iff `buff.len() >= 2` (byte-identical guard).
      if let Some(&[b0, b1]) = buff.get(0..2) {
        let raw = u16::from_be_bytes([b0, b1]);
        // H264.pm:530 — `RawConv` sets `$$self{Make} = convMake{$val} ||
        // "Unknown"` (used for later `Condition`s), passing the raw `$val`
        // through unchanged.
        let make_label = conv_make(raw);
        *make = Some(SmolStr::new(make_label.unwrap_or("Unknown")));
        // H264.pm:529-531 — DISPLAY is the separate `PrintConv => \%convMake`
        // hash: a hit emits the manufacturer label; a MISS with `PrintHex =>
        // 1` (H264.pm:529) renders `Unknown (0x%x)` (`ExifTool.pm:3617-3620`),
        // NOT the `RawConv` "Unknown" string. `-n` = the raw `int16u` word.
        let print_conv = match make_label {
          Some(label) => SmolStr::new_static(label),
          None => print_conv_miss_int(u64::from(raw), true),
        };
        entries.push(H264Entry::h264(
          SmolStr::new_static("Make"),
          H264Value::Text(TextValue::new(print_conv, smol_u64(u64::from(raw)))),
        ));
      }
    }
    SubDirKind::Shutter => {
      // H264.pm:504-519 — `FORMAT => 'int16u'`, LITTLE-endian (H264.pm:150).
      // Tag `1.1 ExposureTime`: word 1 (byte offset 2), mask 0x7fff.
      // `buff.get(2..4)` is `Some` iff `buff.len() >= 4` (byte-identical guard).
      if let Some(&[b2, b3]) = buff.get(2..4) {
        let word1 = u16::from_le_bytes([b2, b3]);
        let masked = u32::from(word1) & 0x7fff;
        // H264.pm:516 — `RawConv => '$val == 0x7fff ? undef : $val'`.
        if masked != 0x7fff {
          // H264.pm:517 — `ValueConv => '$val / 28125'`.
          let secs = f64::from(masked) / 28125.0;
          // H264.pm:518 — `PrintConv => PrintExposureTime`.
          let print_conv = print_exposure_time(secs);
          let numeric = crate::value::format_g(secs, 15);
          entries.push(H264Entry::h264(
            SmolStr::new_static("ExposureTime"),
            H264Value::Text(TextValue::new(print_conv.as_str(), numeric.as_str())),
          ));
        }
      }
    }
    SubDirKind::Camera1 => process_camera1(buff, entries),
    SubDirKind::Camera2 => process_camera2(buff, entries),
    SubDirKind::RecInfo => {
      // H264.pm:553-569 — `int8u` table, `FIRST_ENTRY => 0`. Index 0 =
      // RecordingMode with a numeric → label PrintConv.
      if let Some(&b0) = buff.first() {
        let label = match b0 {
          0x02 => Some("XP+"),
          0x04 => Some("SP"),
          0x05 => Some("LP"),
          0x06 => Some("FXP"),
          0x07 => Some("MXP"),
          _ => None,
        };
        // Off-map ⇒ ExifTool's default PrintConv miss = `Unknown (N)`
        // (`ExifTool.pm:3622`; no `PrintHex` on RecordingMode).
        let print_conv = match label {
          Some(l) => SmolStr::new_static(l),
          None => print_conv_miss_int(u64::from(b0), false),
        };
        entries.push(H264Entry::h264(
          SmolStr::new_static("RecordingMode"),
          H264Value::Text(TextValue::new(print_conv, smol_u64(u64::from(b0)))),
        ));
      }
    }
    SubDirKind::FrameInfo => {
      // H264.pm:572-581 — `int8u` table, `FIRST_ENTRY => 0`. Index 0 =
      // CaptureFrameRate, index 1 = VideoFrameRate (both plain integers,
      // no PrintConv).
      if let Some(&b0) = buff.first() {
        entries.push(H264Entry::h264(
          SmolStr::new_static("CaptureFrameRate"),
          H264Value::U64(u64::from(b0)),
        ));
      }
      if let Some(&b1) = buff.get(1) {
        entries.push(H264Entry::h264(
          SmolStr::new_static("VideoFrameRate"),
          H264Value::U64(u64::from(b1)),
        ));
      }
    }
  }
}

/// `%Image::ExifTool::H264::Camera1` (H264.pm:425-479) — big-endian byte
/// table. Ports the named bit-masked entries.
fn process_camera1(buff: &[u8], entries: &mut Vec<H264Entry>) {
  // 0 — ApertureSetting (H264.pm:431-439).
  if let Some(&b0) = buff.first() {
    let pc = match b0 {
      0xff => SmolStr::new_static("Auto"),
      0xfe => SmolStr::new_static("Closed"),
      // OTHER => sprintf('%.1f', 2 ** (($_[0] & 0x3f) / 8)).
      other => {
        let v = 2f64.powf(f64::from(u32::from(other) & 0x3f) / 8.0);
        SmolStr::new(&std::format!("{v:.1}"))
      }
    };
    entries.push(H264Entry::h264(
      SmolStr::new_static("ApertureSetting"),
      H264Value::Text(TextValue::new(pc, smol_u64(u64::from(b0)))),
    ));
  }
  // 1 — Gain (mask 0x0f) + 1.1 ExposureProgram (mask 0xf0) (H264.pm:440-459).
  if let Some(&b1) = buff.get(1) {
    // Gain: ValueConv '($val - 1) * 3', PrintConv '$val==42?"Out of range":"$val dB"'.
    let gain_raw = i64::from(b1 & 0x0f);
    let gain_vc = (gain_raw - 1) * 3;
    let gain_pc = if gain_vc == 42 {
      SmolStr::new_static("Out of range")
    } else {
      SmolStr::new(&std::format!("{gain_vc} dB"))
    };
    entries.push(H264Entry::h264(
      SmolStr::new_static("Gain"),
      H264Value::Text(TextValue::new(gain_pc, smol_i64(gain_vc))),
    ));
    // ExposureProgram: Mask 0xf0, ValueConv '$val == 15 ? undef : $val'.
    let ep = (b1 & 0xf0) >> 4;
    if ep != 15 {
      let label = match ep {
        0 => Some("Program AE"),
        1 => Some("Gain"),
        2 => Some("Shutter speed priority AE"),
        3 => Some("Aperture-priority AE"),
        4 => Some("Manual"),
        _ => None,
      };
      // PrintConv-hash miss ⇒ `Unknown (N)` (`ExifTool.pm:3622`); `-n` raw.
      let pc = label.map_or_else(
        || print_conv_miss_int(u64::from(ep), false),
        SmolStr::new_static,
      );
      entries.push(H264Entry::h264(
        SmolStr::new_static("ExposureProgram"),
        H264Value::Text(TextValue::new(pc, smol_u64(u64::from(ep)))),
      ));
    }
  }
  // 2.1 — WhiteBalance (mask 0xe0) (H264.pm:460-470).
  if let Some(&b2) = buff.get(2) {
    let wb = (b2 & 0xe0) >> 5;
    if wb != 7 {
      let label = match wb {
        0 => Some("Auto"),
        1 => Some("Hold"),
        2 => Some("1-Push"),
        3 => Some("Daylight"),
        _ => None,
      };
      // PrintConv-hash miss ⇒ `Unknown (N)` (`ExifTool.pm:3622`); `-n` raw.
      let pc = label.map_or_else(
        || print_conv_miss_int(u64::from(wb), false),
        SmolStr::new_static,
      );
      entries.push(H264Entry::h264(
        SmolStr::new_static("WhiteBalance"),
        H264Value::Text(TextValue::new(pc, smol_u64(u64::from(wb)))),
      ));
    }
  }
  // 3 — Focus (H264.pm:471-478).
  if let Some(&b3) = buff.get(3) {
    if b3 != 0xff {
      // PrintConv: $foc = ($val & 0x7e) / (($val & 0x01) ? 40 : 400);
      //            ($val & 0x80 ? 'Manual' : 'Auto') . " ($foc)".
      let div = if b3 & 0x01 != 0 { 40.0 } else { 400.0 };
      let foc = f64::from(u32::from(b3) & 0x7e) / div;
      let mode = if b3 & 0x80 != 0 { "Manual" } else { "Auto" };
      let pc = std::format!("{mode} ({})", crate::value::format_g(foc, 15));
      entries.push(H264Entry::h264(
        SmolStr::new_static("Focus"),
        H264Value::Text(TextValue::new(pc.as_str(), smol_u64(u64::from(b3)))),
      ));
    }
  }
}

/// `%Image::ExifTool::H264::Camera2` (H264.pm:481-502) — big-endian byte
/// table. Only `1 ImageStabilization` is named.
fn process_camera2(buff: &[u8], entries: &mut Vec<H264Entry>) {
  if let Some(&b1) = buff.get(1) {
    // H264.pm:488-501 — ImageStabilization PrintConv.
    let pc = match b1 {
      0x00 => SmolStr::new_static("Off"),
      0x3f => SmolStr::new_static("On (0x3f)"),
      0xbf => SmolStr::new_static("Off (0xbf)"),
      0xff => SmolStr::new_static("n/a"),
      // OTHER => sprintf("%s (0x%.2x)", $val & 0x10 ? "On" : "Off", $val).
      other => {
        let on_off = if other & 0x10 != 0 { "On" } else { "Off" };
        SmolStr::new(&std::format!("{on_off} (0x{other:02x})"))
      }
    };
    entries.push(H264Entry::h264(
      SmolStr::new_static("ImageStabilization"),
      H264Value::Text(TextValue::new(pc, smol_u64(u64::from(b1)))),
    ));
  }
}

/// `Image::ExifTool::Exif::PrintExposureTime` (Exif.pm:5701-5711) — the
/// shared exposure-time PrintConv used by H264 `Shutter` (H264.pm:518).
fn print_exposure_time(secs: f64) -> std::string::String {
  use core::fmt::Write;
  if !secs.is_finite() {
    // Perl `return $secs unless IsFloat($secs)` — non-finite passes through.
    return crate::value::format_g(secs, 15);
  }
  if secs < 0.250_01 && secs > 0.0 {
    let denom = (0.5 + 1.0 / secs).floor() as i64;
    let mut s = std::string::String::new();
    let _ = write!(s, "1/{denom}");
    return s;
  }
  // sprintf("%.1f", $secs) then strip a trailing ".0".
  let mut s = std::format!("{secs:.1}");
  if let Some(stripped) = s.strip_suffix(".0") {
    s = stripped.to_string();
  }
  s
}

/// Small helper — a `u64` as a [`SmolStr`] (every H.264 integer fits the
/// 23-byte inline budget, so this never heap-allocates).
fn smol_u64(n: u64) -> SmolStr {
  use core::fmt::Write;
  let mut s = std::string::String::new();
  let _ = write!(s, "{n}");
  SmolStr::new(&s)
}

/// Small helper — an `i64` as a [`SmolStr`].
fn smol_i64(n: i64) -> SmolStr {
  use core::fmt::Write;
  let mut s = std::string::String::new();
  let _ = write!(s, "{n}");
  SmolStr::new(&s)
}

/// How ExifTool's JSON writer will emit a `-n` (post-ValueConv) scalar string —
/// the faithful port of `EscapeJSON`'s number gate (exiftool:3809). When the
/// `$quote` flag is false (every non-`StructFormat=JSONQ` `-j`/`-n` run,
/// exiftool:2676 + 2988), a value whose ENTIRE text matches
/// `^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$` is printed as a bare
/// JSON NUMBER; anything else is quoted as a string. This is what makes a
/// numeric MDPM tag (`WhiteBalance` raw `1`, `Make` raw `4113`,
/// `BrightnessValue` raw `2.5`) serialize as a JSON number under `-n`, while
/// the words `inf`/`undef`/`Inf`/`NaN` and `:`-bearing TimeCode/GPS values stay
/// strings (Codex R8 F1).
///
/// Gated with the [`Taggable`](crate::emit::Taggable) emission path
/// (`feature = "alloc"`) — it is only consumed by the typed-Meta → `TagMap`
/// lowering, which itself needs heap.
#[cfg(feature = "alloc")]
enum JsonScalar {
  /// Matched the number gate with no fractional/exponent part and fits `u64`.
  U64(u64),
  /// Matched the number gate, fits `i64` (a leading `-`), no fraction/exponent.
  I64(i64),
  /// Matched the number gate with a fraction/exponent (a floating value).
  F64(f64),
  /// Did NOT match the number gate ⇒ emitted as a quoted JSON string.
  Str,
}

/// Classify a `-n` scalar string exactly as ExifTool's `EscapeJSON` number gate
/// would (exiftool:3809). Returns the typed numeric arm so the caller routes
/// the value through the matching `write_u64`/`write_i64`/`write_f64` (a bare
/// JSON number), or [`JsonScalar::Str`] to keep it a quoted string.
#[cfg(feature = "alloc")]
fn classify_json_scalar(s: &str) -> JsonScalar {
  if !escape_json_is_number(s) {
    return JsonScalar::Str;
  }
  // The gate matched ⇒ ExifTool emits a bare number. A pure integer (no `.`,
  // no `e`/`E`) is an exact int token; route it through the integer writer so
  // serde emits e.g. `2`, not `2.0`. Otherwise it is a floating value.
  let is_integer = !s.bytes().any(|b| b == b'.' || b == b'e' || b == b'E');
  if is_integer {
    // The gate caps the magnitude at 15 digits, so the value always fits
    // `i64`/`u64`; the `parse` failures below are unreachable but fall back to
    // the float writer defensively (still a bare number, faithful to the gate).
    if let Some(rest) = s.strip_prefix('-') {
      if let Ok(n) = rest.parse::<i64>() {
        return JsonScalar::I64(-n);
      }
    } else if let Ok(n) = s.parse::<u64>() {
      return JsonScalar::U64(n);
    }
  }
  // A finite fractional/exponent value that FAITHFULLY represents its token
  // routes through the float writer as a bare JSON number. The gate admits an
  // exponent up to `e[-+]?\d{1,3}` (faithful to `exiftool:3810`), so it ALSO
  // accepts a token outside finite-f64 range on BOTH sides: `1e999` OVERFLOWS to
  // `INFINITY`, and `1e-999` UNDERFLOWS a nonzero significand to a FINITE `0.0`.
  // Neither may become `JsonScalar::F64(..)` — the caller lowers an overflow to
  // `TagValue::F64(INFINITY)` (serializer emits the titlecase `"Inf"`), and a
  // nonzero-underflow to `TagValue::F64(0.0)` (emits a bare `0`), both silently
  // corrupting the source token. Fall back to `Str` so the ORIGINAL token reaches
  // `TagValue::Str`, where the consolidated `value.rs` number gate emits it as a
  // sound quoted string (Contract B / #197). The predicate `is_finite() && !(f ==
  // 0.0 && lexeme_is_nonzero)` is COMPLETE for the f64-representation class:
  // overflow ⇒ !finite ⇒ `Str`; nonzero-underflow ⇒ `0.0`+nonzero-significand ⇒
  // `Str`; else the finite f64 faithfully denotes the value ⇒ `F64` (a
  // genuine-zero token stays a bare `0`; finite-nonzero precision loss is
  // value-preserving under the comparator). Real H264 MDPM metadata never carries
  // such a magnitude.
  match s.parse::<f64>() {
    Ok(f) if f.is_finite() && !(f == 0.0 && crate::value::lexeme_is_nonzero(s)) => {
      JsonScalar::F64(f)
    }
    _ => JsonScalar::Str,
  }
}

/// The `EscapeJSON` number gate (`exiftool:3809`) for the H264 `-n` scalar
/// classifier — a thin alias for the shared
/// [`crate::value::escape_json_is_number`] (Contract B / #197 consolidated the
/// regex crate-wide). `classify_json_scalar` calls this; keeping the local name
/// leaves that call site (and its tests) unchanged.
#[cfg(feature = "alloc")]
#[inline]
fn escape_json_is_number(s: &str) -> bool {
  crate::value::escape_json_is_number(s)
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for H264Meta<'_> {
  /// The H.264 `$et->Warn` corpus (MDPM out-of-sequence H264.pm:989 /
  /// forbidden-bit H264.pm:1058) as [`Diagnostic`](crate::diagnostics::Diagnostic)
  /// warnings, in occurrence order.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    self
      .warnings()
      .iter()
      .map(|w| crate::diagnostics::Diagnostic::warn(w.as_str()))
      .collect()
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for H264Meta<'_> {
  /// Yield the H.264 tags in extraction order (Perl `HandleTag` call
  /// sequence) — the golden-pattern parallel to the retired `serialize_tags`:
  /// the SINK changes (an [`EmittedTag`](crate::emit::EmittedTag) per value
  /// instead of `out.write_*`), the per-tag PrintConv/ValueConv branches AND
  /// the visibility filter are preserved verbatim. The `Warn` emission stays
  /// OUT of this stream — `run_emission` has no warning channel; the
  /// `format_parser::AnyMeta::H264` arm drains `self.warnings()` after the
  /// engine (H264.pm:989).
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars (routed through ExifTool's
  /// `EscapeJSON` number gate).
  ///
  /// Group: `family0` = `"H264"` (the `%H264::Main` table group — H264.pm
  /// `GROUPS` sets only family2 `Video`/`Camera`, so family0 defaults to the
  /// module name); `family1` = `entry.group().as_str()` (the per-entry `-G1`
  /// key — `"H264"` for SPS / MDPM non-GPS / binary subdir tags, `"GPS"` for
  /// the MDPM GPS block, H264.pm:241-387), byte-identical to the retired
  /// sink. No H264 table row is `Unknown => 1` ⇒ `unknown: false`.
  ///
  /// ## `FoundTag` priority (Codex R15 F1)
  ///
  /// A valid AVCHD MDPM stream can carry the SAME tag name twice — most
  /// notably an early `0x70` Camera1 subdirectory `WhiteBalance`
  /// (H264.pm:460-470) and a later top-level `0xa8` `WhiteBalance` whose table
  /// entry is marked `Priority => 0` (H264.pm:215). ExifTool's `FoundTag`
  /// (ExifTool.pm:9458-9580) keeps the HIGHER-priority value as the visible
  /// `WhiteBalance` and relegates the `Priority => 0` one to a duplicate-copy
  /// key (`WhiteBalance (1)`); the default `-j`/`-n` render then drops every
  /// `(N)` copy and shows only the priority winner (ExifTool.pm:5396-5404 and
  /// 5522-5538, `Duplicates` off — the supported output never sets `-a`). The
  /// [`crate::tagmap::TagMap`] models that DEFAULT one-per-`group:name` view, so
  /// here we yield only the visible winner for each `group:name`: the entry with
  /// the maximum [`H264Priority`], ties broken by LAST occurrence (the same
  /// last-wins `TagMap` already applies to equal-priority duplicates such as
  /// repeated AIFF `NAME` chunks). The relegated `(N)` copy is intentionally
  /// not yielded — it is invisible under the default render the goldens pin; see
  /// `docs/tracking.md` for the scoped `-a` duplicate-copy follow-up.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<EmittedTag> = Vec::with_capacity(self.entries.len());
    for (idx, entry) in self.entries.iter().enumerate() {
      // Skip an entry that a higher-priority — or equal-priority-but-later —
      // same-`group:name` entry outranks (the relegated duplicate copy, dropped
      // by the default render). `0xa8 WhiteBalance` (`Priority => 0`) loses to
      // an earlier Camera1 `WhiteBalance`; equal priorities keep last-wins.
      if !self.is_visible_winner(idx, entry) {
        continue;
      }
      // family0 "H264" (table group0); family1 = the per-entry group.
      let group = Group::new("H264", entry.group().as_str());
      let name = entry.name();
      let value = match entry.value_ref() {
        H264Value::U64(n) => TagValue::U64(*n),
        H264Value::Text(t) => {
          if print_conv {
            // `-j` ⇒ the PrintConv string. ExifTool's `EscapeJSON` number gate
            // still runs on PrintConv output (a `"3.5"`-style PrintConv prints
            // as a bare number), but the shared `TagValue::Str` serializer +
            // `json_equivalent` already model that string↔number coercion, so
            // emitting the raw string here is faithful for `-j`.
            TagValue::Str(t.print_conv().into())
          } else {
            // `-n` ⇒ the post-ValueConv scalar. Route it through ExifTool's
            // `EscapeJSON` number gate so a numeric value lands as a bare JSON
            // NUMBER (`U64`/`I64`/`F64`), exactly as bundled `ParseH264Video`
            // emits it; non-numeric words (`inf`, `undef`, `Inf`, `NaN`) and
            // `:`-bearing TimeCode/GPS values stay strings (Codex R8 F1).
            let n = t.numeric();
            match classify_json_scalar(n) {
              JsonScalar::U64(v) => TagValue::U64(v),
              JsonScalar::I64(v) => TagValue::I64(v),
              JsonScalar::F64(v) => TagValue::F64(v),
              JsonScalar::Str => TagValue::Str(n.into()),
            }
          }
        }
      };
      tags.push(EmittedTag::new(group, name.into(), value, false));
    }
    tags.into_iter()
  }
}

#[cfg(feature = "alloc")]
impl H264Meta<'_> {
  /// `true` when `entry` (at extraction index `idx`) is the value the default
  /// render shows for its `group:name` — i.e. no OTHER entry with the same
  /// `group:name` outranks it. An entry is outranked by a peer with strictly
  /// higher [`H264Priority`], or by an equal-priority peer at a LATER index
  /// (ties → last-wins). This mirrors `FoundTag`'s priority comparison
  /// (`$priority >= $oldPriority`, ExifTool.pm:9553) folded with the default
  /// `Duplicates`-off one-per-name dedup (ExifTool.pm:5396-5404 / 5522-5538):
  /// every loser becomes a `(N)` duplicate copy that the default `-j`/`-n`
  /// output omits (Codex R15 F1). The only stream that exercises a non-tie here
  /// is the `0xa8 WhiteBalance` (`Priority => 0`) vs an earlier Camera1
  /// `WhiteBalance`; every other H264 tag is `Normal`, so this reduces to the
  /// pre-existing last-wins for ordinary same-name duplicates.
  fn is_visible_winner(&self, idx: usize, entry: &H264Entry) -> bool {
    let group = entry.group();
    let name = entry.name();
    let prio = entry.priority();
    !self.entries.iter().enumerate().any(|(j, other)| {
      j != idx
        && other.group() == group
        && other.name() == name
        && match other.priority().cmp(&prio) {
          // A strictly higher-priority peer always wins.
          core::cmp::Ordering::Greater => true,
          // Equal priority → the LATER entry wins (last-wins tie-break).
          core::cmp::Ordering::Equal => j > idx,
          // A lower-priority peer never displaces this entry.
          core::cmp::Ordering::Less => false,
        }
    })
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for H264Meta<'_> {
  /// Project H.264 metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// H.264 is a video elementary stream (parsed only as the M2TS PES-payload
  /// callback), so the single faithful structural contribution is one video
  /// [`TrackKind`](crate::metadata::TrackKind). The SPS pixel dimensions are
  /// surfaced as the `H264:ImageWidth`/`ImageHeight` TAGS but are not mapped
  /// onto [`MediaInfo`](crate::metadata::MediaInfo) here (the typed `Meta`
  /// carries them only inside the tag stream, not as clean `u32` accessors);
  /// duration / created stay `None` (an elementary stream carries no
  /// container duration). Camera / lens / GPS / capture stay `None` — those
  /// MDPM facts surface as tags but have no normalized-domain slot yet.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Video);
    media
  }
}

// NOTE on serde (rust-type-conventions §8): the typed `H264Meta` does NOT
// implement `Serialize` directly — like every other format port in this
// crate, the `-j`/`-n` JSON view is produced by the shared
// `format_parser::Rendered` wrapper driving `serialize_tags` above. There is
// therefore no per-format gated `const _: () = { … };` serde block to add
// (one would be empty). The optional `serde` feature still flows through the
// crate-level `Rendered` impl.

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2a); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Drive the `H264Meta` through the production sink path that replaced the
  /// retired `serialize_tags`: the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for the tag stream, then —
  /// exactly like the `format_parser::AnyMeta::H264` arm — drain
  /// [`H264Meta::warnings`] into the [`TagMap`](crate::tagmap::TagMap) as
  /// `Warning`s (H264.pm:989/1058). Returns the populated map.
  #[cfg(feature = "alloc")]
  fn emit_into_tagmap(meta: &H264Meta<'_>, print_conv: bool) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(
      meta,
      crate::emit::ConvMode::from_print_conv(print_conv),
      &mut w,
    );
    for warn in meta.warnings() {
      let _ = w.write_warning(warn.as_str());
    }
    w
  }

  /// Emulation-prevention encoder — the inverse of [`unescape_rbsp`], used
  /// to build test NAL bodies the way a real H.264 encoder would.
  fn escape_rbsp(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut zeros = 0u32;
    for &b in input {
      if zeros >= 2 && b <= 3 {
        out.push(0x03);
        zeros = 0;
      }
      out.push(b);
      zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
  }

  /// Build the canonical synthetic AVCHD fixture: a single SEI NAL whose
  /// type-5 payload carries an MDPM block with TimeCode / Shutter /
  /// ExposureProgram / WhiteBalance / SceneCaptureType / MakeModel records.
  /// Mirrors `tests/golden/h264/H264_avchd.h264` byte-for-byte.
  fn avchd_fixture() -> Vec<u8> {
    let mut recs: Vec<u8> = Vec::new();
    // 0x13 TimeCode — bytes 01 02 03 04 ⇒ reversed ⇒ "04:03:02:01".
    recs.extend_from_slice(&[0x13, 0x01, 0x02, 0x03, 0x04]);
    // 0x7f Shutter (LE int16u) — word1 bytes 40 1f ⇒ 0x1f40 = 8000.
    recs.extend_from_slice(&[0x7f, 0x00, 0x00, 0x40, 0x1f]);
    // 0xa2 ExposureProgram int32u = 2 ⇒ "Program AE".
    recs.extend_from_slice(&[0xa2, 0x00, 0x00, 0x00, 0x02]);
    // 0xa8 WhiteBalance int32u = 1 ⇒ "Manual".
    recs.extend_from_slice(&[0xa8, 0x00, 0x00, 0x00, 0x01]);
    // 0xaa SceneCaptureType int32u = 3 ⇒ "Night".
    recs.extend_from_slice(&[0xaa, 0x00, 0x00, 0x00, 0x03]);
    // 0xe0 MakeModel int16u — word0 = 0x1011 ⇒ Canon.
    recs.extend_from_slice(&[0xe0, 0x10, 0x11, 0x31, 0x02]);

    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&MDPM_UUID_TAG);
    payload.push(6); // entry count
    payload.extend_from_slice(&recs);

    let mut sei: Vec<u8> = Vec::new();
    sei.push(5); // payload type 5
    sei.push(payload.len() as u8); // payload size (< 255)
    sei.extend_from_slice(&payload);
    sei.push(0x80); // terminator

    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    stream.extend_from_slice(&escape_rbsp(&sei));
    // Trailing NAL so the SEI body boundary is found.
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    stream
  }
  #[test]
  fn parse_borrowed_rejects_non_h264() {
    // No NAL start code anywhere ⇒ `Ok(None)`.
    assert!(parse_borrowed(b"not an h264 stream at all").is_none());
    assert!(parse_borrowed(&[]).is_none());
  }

  #[test]
  fn parse_borrowed_accepts_avchd_fixture() {
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).expect("has a NAL start code");
    assert!(!meta.is_empty(), "the MDPM block must yield tags");
    assert_eq!(meta.make(), Some("Canon"));
  }

  #[test]
  fn found_user_data_tracks_sei_mdpm_presence() {
    // H264.pm:1039/1102 — `$foundUserData` is set once `ProcessSEI`
    // decoded the MDPM user-data block. The AVCHD fixture carries it, so
    // `found_user_data()` is true (⇒ `ParseH264Video` would return 0 = no
    // more frames wanted).
    let with_mdpm = avchd_fixture();
    let meta = parse_borrowed(&with_mdpm).unwrap();
    assert!(
      meta.found_user_data(),
      "a frame carrying SEI/MDPM user data must report found_user_data"
    );

    // A stream with only an SPS NAL (image size) and NO SEI carries no user
    // data — `found_user_data()` is false even though the stream is non-empty
    // (H264.pm:1100-1104 ⇒ `ParseH264Video` returns 1 = parse one more frame,
    // matching Panasonic cameras that omit the SEI from the first frame).
    let mut sps_only: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x07];
    // Minimal SPS RBSP — `parse_seq_param_set` need not succeed for the
    // user-data flag (it only flips on an SEI). A trailing AUD NAL bounds it.
    sps_only.extend_from_slice(&[0x42, 0x00, 0x1f, 0x00]);
    sps_only.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    let meta = parse_borrowed(&sps_only).unwrap();
    assert!(
      !meta.found_user_data(),
      "an SPS-only frame carries no SEI/MDPM user data"
    );
  }

  #[test]
  fn avchd_fixture_print_conv_tags() {
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).unwrap();
    let tm = emit_into_tagmap(&meta, true);
    // -j mode — PrintConv labels.
    assert_eq!(
      tm.get_str("H264", "TimeCode").as_deref(),
      Some("04:03:02:01")
    );
    assert_eq!(
      tm.get_str("H264", "ExposureProgram").as_deref(),
      Some("Program AE")
    );
    assert_eq!(
      tm.get_str("H264", "WhiteBalance").as_deref(),
      Some("Manual")
    );
    assert_eq!(
      tm.get_str("H264", "SceneCaptureType").as_deref(),
      Some("Night")
    );
    assert_eq!(tm.get_str("H264", "Make").as_deref(), Some("Canon"));
    // Shutter ExposureTime — 8000/28125 ≈ 0.2844 ⇒ PrintExposureTime ⇒ "0.3".
    assert_eq!(tm.get_str("H264", "ExposureTime").as_deref(), Some("0.3"));
  }

  #[test]
  fn avchd_fixture_numeric_tags() {
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).unwrap();
    let tm = emit_into_tagmap(&meta, false);
    // -n mode — raw post-ValueConv scalars.
    assert_eq!(
      tm.get_str("H264", "TimeCode").as_deref(),
      Some("04:03:02:01") // ValueConv-only ⇒ same in both modes
    );
    assert_eq!(tm.get_str("H264", "ExposureProgram").as_deref(), Some("2"));
    assert_eq!(tm.get_str("H264", "WhiteBalance").as_deref(), Some("1"));
    assert_eq!(tm.get_str("H264", "SceneCaptureType").as_deref(), Some("3"));
    assert_eq!(tm.get_str("H264", "Make").as_deref(), Some("4113"));
    // ExposureTime -n — bare ValueConv float (8000/28125).
    let et = tm.get_str("H264", "ExposureTime").unwrap();
    assert!(
      et.starts_with("0.28444"),
      "ExposureTime -n should be ~0.2844…, got {et}"
    );
  }

  #[test]
  fn out_of_order_mdpm_records_stop_at_first_descending() {
    // Two records, second id <= first ⇒ Perl warns + stops; only the
    // first record is emitted.
    let mut recs: Vec<u8> = Vec::new();
    recs.extend_from_slice(&[0xa8, 0x00, 0x00, 0x00, 0x00]); // WhiteBalance=0
    recs.extend_from_slice(&[0xa2, 0x00, 0x00, 0x00, 0x02]); // 0xa2 < 0xa8 ⇒ stop
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&MDPM_UUID_TAG);
    payload.push(2);
    payload.extend_from_slice(&recs);
    let mut sei: Vec<u8> = vec![5, payload.len() as u8];
    sei.extend_from_slice(&payload);
    sei.push(0x80);
    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    stream.extend_from_slice(&escape_rbsp(&sei));
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);

    let meta = parse_borrowed(&stream).unwrap();
    let names: Vec<&str> = meta.entries().iter().map(super::H264Entry::name).collect();
    assert_eq!(names, ["WhiteBalance"], "must stop before the 0xa2 record");

    // Codex R7 F1 — H264.pm:989 emits the out-of-sequence Warn. The typed
    // meta must carry it and the production sink path (the
    // `format_parser::AnyMeta::H264` arm, replicated by `emit_into_tagmap`)
    // must surface it as a TagMap warning (the engine's `ExifTool:Warning`).
    assert_eq!(
      meta.warnings(),
      ["Entries in MDPM directory are out of sequence"],
      "out-of-order MDPM must record the H264.pm:989 warning"
    );
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(
      tm.first_warning(),
      Some("Entries in MDPM directory are out of sequence"),
      "the H264 arm must emit the warning into the TagMap after run_emission"
    );
  }

  /// Build a single-SEI MDPM stream from raw 5-byte records (id + 4 data).
  fn mdpm_stream(recs: &[u8]) -> Vec<u8> {
    assert_eq!(recs.len() % 5, 0);
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&MDPM_UUID_TAG);
    payload.push((recs.len() / 5) as u8);
    payload.extend_from_slice(recs);
    let mut sei: Vec<u8> = vec![5, payload.len() as u8];
    sei.extend_from_slice(&payload);
    sei.push(0x80);
    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    stream.extend_from_slice(&escape_rbsp(&sei));
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    stream
  }

  // === Codex R15 F1 — FoundTag Priority (0xa8 WhiteBalance) ===

  #[test]
  fn low_priority_a8_whitebalance_does_not_overwrite_camera1() {
    // An ascending MDPM stream: a `0x70` Camera1 subdirectory whose 4 bytes
    // `ff 00 20 00` decode WhiteBalance (mask 0xe0 of byte 2 = 0x20 ⇒ 1) =
    // "Hold" (H264.pm:460-470), FOLLOWED by a top-level `0xa8` WhiteBalance
    // `00 00 00 00` = 0 = "Auto" whose table entry is `Priority => 0`
    // (H264.pm:215). `FoundTag` keeps the higher-priority Camera1 value as the
    // visible `WhiteBalance`; the later `Priority => 0` value is relegated to a
    // duplicate copy the default render drops (ExifTool.pm:9458-9580 /
    // 5396-5404). Verified against bundled ExifTool 13.58 `ParseH264Video`:
    // visible `H264:WhiteBalance` = "Hold" (`-j`) / `1` (`-n`).
    let stream = mdpm_stream(&[
      0x70, 0xff, 0x00, 0x20, 0x00, // Camera1 ⇒ WhiteBalance "Hold"
      0xa8, 0x00, 0x00, 0x00, 0x00, // top-level WhiteBalance "Auto" (Priority=>0)
    ]);
    let meta = parse_borrowed(&stream).unwrap();

    // Both WhiteBalance entries are parsed (the Camera1 one and the 0xa8 one),
    // each carrying its `FoundTag` priority — the relegation happens at
    // serialize time, not parse time.
    let wbs: Vec<&H264Entry> = meta
      .entries()
      .iter()
      .filter(|e| e.name() == "WhiteBalance")
      .collect();
    assert_eq!(wbs.len(), 2, "both WhiteBalance entries are parsed");
    assert_eq!(
      wbs[0].priority(),
      H264Priority::Normal,
      "Camera1 WhiteBalance has the default priority"
    );
    assert_eq!(
      wbs[1].priority(),
      H264Priority::Low,
      "top-level 0xa8 WhiteBalance is Priority => 0 (H264.pm:215)"
    );

    // The VISIBLE WhiteBalance is the higher-priority Camera1 "Hold", NOT the
    // later Priority=>0 "Auto" — `-j` PrintConv.
    let j = emit_into_tagmap(&meta, true);
    assert_eq!(
      j.get_str("H264", "WhiteBalance").as_deref(),
      Some("Hold"),
      "visible WhiteBalance must be the higher-priority Camera1 value"
    );

    // `-n` post-ValueConv: the Camera1 raw `1`, not the 0xa8 raw `0`.
    let n = emit_into_tagmap(&meta, false);
    assert_eq!(
      n.get_str("H264", "WhiteBalance").as_deref(),
      Some("1"),
      "visible -n WhiteBalance must be the Camera1 raw value"
    );

    // The relegated `Priority => 0` copy is NOT emitted under the default
    // render (no `(N)`-suffixed key) — exactly one WhiteBalance survives.
    let wb_keys = j
      .entries()
      .iter()
      .filter(|(_, n, _)| n.contains("WhiteBalance"))
      .count();
    assert_eq!(wb_keys, 1, "only the priority winner is emitted");
  }

  /// The reverse ordering — a `Priority => 0` `0xa8` WhiteBalance FIRST then a
  /// higher-priority Camera1 WhiteBalance — must also resolve to the Camera1
  /// value (a strictly higher-priority later tag wins regardless of order),
  /// mirroring `FoundTag`'s promote-existing-0-priority-tag path
  /// (ExifTool.pm:9530-9575). NOTE: the MDPM walk requires ascending tag ids
  /// (H264.pm:988), so this ordering cannot occur in one in-sequence block; the
  /// case is exercised directly on a hand-built two-entry meta below.
  #[test]
  fn higher_priority_camera1_wins_even_when_emitted_after_low_a8() {
    // Build a meta with the 0xa8 (Low) entry FIRST, then a Camera1 (Normal)
    // WhiteBalance — the priority winner must still be the Normal one.
    // (`tests` is a child module of `h264`, so it can name `H264Meta`'s private
    // fields directly; this is a synthetic ordering, not a real stream.)
    let meta = H264Meta {
      entries: vec![
        H264Entry::with_group_priority(
          H264Group::H264,
          H264Priority::Low,
          SmolStr::new_static("WhiteBalance"),
          H264Value::Text(TextValue::new("Auto", "0")),
        ),
        H264Entry::h264(
          SmolStr::new_static("WhiteBalance"),
          H264Value::Text(TextValue::new("Hold", "1")),
        ),
      ],
      make: None,
      warnings: Vec::new(),
      found_user_data: false,
      _marker: core::marker::PhantomData,
    };
    let j = emit_into_tagmap(&meta, true);
    assert_eq!(
      j.get_str("H264", "WhiteBalance").as_deref(),
      Some("Hold"),
      "the higher-priority Normal WhiteBalance wins regardless of order"
    );
  }

  // === Codex R5 F1 — GPS family-1 group ===

  #[test]
  fn gps_block_tags_report_gps_family1_group() {
    // 0xb0-0xca carry `Groups => { 1 => 'GPS' }` (H264.pm:241-387) — bundled
    // `ParseH264Video` reports them under `GPS:`, not `H264:` (Codex R5 F1).
    // 0xb1 GPSLatitudeRef="N" is a simple single-record GPS tag.
    let s1 = mdpm_stream(&[0xb1, b'N', 0x00, 0x00, 0x00]);
    let meta = parse_borrowed(&s1).unwrap();
    let e = meta
      .entries()
      .iter()
      .find(|e| e.name() == "GPSLatitudeRef")
      .expect("GPSLatitudeRef emitted");
    assert!(e.group().is_gps(), "GPS block ⇒ family-1 GPS");
    // Non-GPS MDPM tag stays in H264 (0xa8 WhiteBalance).
    let s2 = mdpm_stream(&[0xa8, 0x00, 0x00, 0x00, 0x01]);
    let meta2 = parse_borrowed(&s2).unwrap();
    let wb = meta2
      .entries()
      .iter()
      .find(|e| e.name() == "WhiteBalance")
      .unwrap();
    assert!(wb.group().is_h264(), "non-GPS MDPM ⇒ family-1 H264");
    // serialize_tags must key the GPS tag under "GPS".
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(
      tm.get_str("GPS", "GPSLatitudeRef").as_deref(),
      Some("North")
    );
    assert!(tm.get_str("H264", "GPSLatitudeRef").is_none());
  }

  // === Codex R5 F2 — PrintConv-hash-miss formatting ===

  #[test]
  fn printconv_miss_renders_unknown() {
    // 0xa2 ExposureProgram=9 (off-map) ⇒ `Unknown (9)` in -j, raw `9` in -n
    // (ExifTool.pm:3622). 0xa6 Flash=0x99 (off-map, PrintHex) ⇒
    // `Unknown (0x99)` in -j, decimal `153` in -n (ExifTool.pm:3620).
    let stream = mdpm_stream(&[
      0xa2, 0x00, 0x00, 0x00, 0x09, // ExposureProgram=9
      0xa6, 0x00, 0x00, 0x00, 0x99, // Flash=0x99
      0xbe, b'Z', 0x00, 0x00, 0x00, // GPSStatus="Z" (string-enum miss)
    ]);
    let meta = parse_borrowed(&stream).unwrap();
    let j = emit_into_tagmap(&meta, true);
    assert_eq!(
      j.get_str("H264", "ExposureProgram").as_deref(),
      Some("Unknown (9)")
    );
    assert_eq!(
      j.get_str("H264", "Flash").as_deref(),
      Some("Unknown (0x99)")
    );
    assert_eq!(
      j.get_str("GPS", "GPSStatus").as_deref(),
      Some("Unknown (Z)")
    );
    let n = emit_into_tagmap(&meta, false);
    assert_eq!(n.get_str("H264", "ExposureProgram").as_deref(), Some("9"));
    assert_eq!(n.get_str("H264", "Flash").as_deref(), Some("153"));
    assert_eq!(n.get_str("GPS", "GPSStatus").as_deref(), Some("Z"));
  }

  #[test]
  fn make_convmake_miss_renders_unknown_hex() {
    // 0xe0 MakeModel word0=0x9999 (off-map): `PrintConv => \%convMake` miss
    // with `PrintHex => 1` (H264.pm:529) ⇒ `Unknown (0x9999)` in -j, raw
    // `39321` in -n — NOT the `RawConv` "Unknown" string (Codex R5 F2).
    let stream = mdpm_stream(&[0xe0, 0x99, 0x99, 0x00, 0x00]);
    let meta = parse_borrowed(&stream).unwrap();
    let j = emit_into_tagmap(&meta, true);
    assert_eq!(
      j.get_str("H264", "Make").as_deref(),
      Some("Unknown (0x9999)")
    );
    let n = emit_into_tagmap(&meta, false);
    assert_eq!(n.get_str("H264", "Make").as_deref(), Some("39321"));
  }

  #[test]
  fn camera1_subtable_enum_miss_renders_unknown() {
    // Camera1 (0x70): ExposureProgram (mask 0xf0 ⇒ 5, off-map) and
    // WhiteBalance (mask 0xe0 ⇒ 5, off-map) ⇒ `Unknown (5)` in -j, `5` in -n
    // (Codex R5 F2). b1=0x50 ⇒ ep=5; b2=0xa0 ⇒ wb=5; b3=0xff ⇒ no Focus.
    let stream = mdpm_stream(&[0x70, 0x00, 0x50, 0xa0, 0xff]);
    let meta = parse_borrowed(&stream).unwrap();
    let j = emit_into_tagmap(&meta, true);
    assert_eq!(
      j.get_str("H264", "ExposureProgram").as_deref(),
      Some("Unknown (5)")
    );
    assert_eq!(
      j.get_str("H264", "WhiteBalance").as_deref(),
      Some("Unknown (5)")
    );
    let n = emit_into_tagmap(&meta, false);
    assert_eq!(n.get_str("H264", "ExposureProgram").as_deref(), Some("5"));
    assert_eq!(n.get_str("H264", "WhiteBalance").as_deref(), Some("5"));
  }

  #[test]
  fn unescape_rbsp_strips_emulation_bytes() {
    // An interior `00 00 03 00` triple (start index >= 1) ⇒ `03` dropped.
    assert_eq!(
      &*unescape_rbsp(&[0xff, 0x00, 0x00, 0x03, 0x00]),
      &[0xff, 0x00, 0x00, 0x00]
    );
    // No triple ⇒ borrowed unchanged.
    assert!(matches!(
      unescape_rbsp(&[0x01, 0x02, 0x03]),
      Cow::Borrowed(_)
    ));
  }

  /// Codex R9 F1 — H264.pm:1064 seeds the de-escape regex at `pos = $pos +
  /// 1`, so a `00 00 03` triple whose FIRST byte sits at NAL-body index 0
  /// is never matched: its `0x03` is kept verbatim. A buggy de-escape that
  /// stripped it would desync SEI message parsing and skip the MDPM block.
  #[test]
  fn unescape_rbsp_keeps_leading_emulation_triple() {
    // `00 00 03` at body index 0 — the `03` must survive (borrowed).
    assert!(matches!(
      unescape_rbsp(&[0x00, 0x00, 0x03, 0x00, 0x05]),
      Cow::Borrowed(_)
    ));
    assert_eq!(
      &*unescape_rbsp(&[0x00, 0x00, 0x03, 0x00, 0x05]),
      &[0x00, 0x00, 0x03, 0x00, 0x05]
    );
    // A SECOND, interior triple is still stripped while the leading one
    // is kept.
    assert_eq!(
      &*unescape_rbsp(&[0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x01]),
      &[0x00, 0x00, 0x03, 0x00, 0x00, 0x01]
    );
  }

  #[test]
  fn conv_make_table() {
    assert_eq!(conv_make(0x1011), Some("Canon"));
    assert_eq!(conv_make(0x0108), Some("Sony"));
    assert_eq!(conv_make(0x0103), Some("Panasonic"));
    assert_eq!(conv_make(0x1104), Some("JVC"));
    assert_eq!(conv_make(0x9999), None);
  }

  #[test]
  fn sps_decodes_image_size() {
    // A real 1280x720 H.264 SPS (baseline profile) — RBSP bytes after the
    // 0x67 NAL header. Decoding must yield ImageWidth=1280, ImageHeight=720.
    let sps_rbsp: &[u8] = &[
      0x42, 0xc0, 0x1f, 0xd9, 0x00, 0x50, 0x05, 0xbb, 0x01, 0x6c, 0x80, 0x00, 0x00, 0x03, 0x00,
      0x80, 0x00, 0x00, 0x1e, 0x07, 0x8c, 0x18, 0xcb,
    ];
    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x67];
    stream.extend_from_slice(sps_rbsp);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    let meta = parse_borrowed(&stream).unwrap();
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(tm.get_str("H264", "ImageWidth").as_deref(), Some("1280"));
    assert_eq!(tm.get_str("H264", "ImageHeight").as_deref(), Some("720"));
  }

  #[test]
  fn format_parser_trait_matches_parse_borrowed() {
    let data = avchd_fixture();
    let via_trait = <ProcessH264 as FormatParser>::parse(&ProcessH264, &data).expect("some");
    let via_direct = parse_borrowed(&data).unwrap();
    assert_eq!(via_trait.entries().len(), via_direct.entries().len());
    assert_eq!(via_trait.make(), via_direct.make());
  }

  // === Codex R1 F2 — Exp-Golomb EOF semantics ===

  #[test]
  fn golomb_eof_returns_minus_one() {
    // Bundled `GetGolomb` on an all-zero buffer (no terminating 1-bit) hits
    // EOF in the leading-zero count loop ⇒ `GetIntN($count+1)` reads only
    // past-EOF zero bits ⇒ `0 - 1 = -1` (verified against bundled H264.pm:
    // an all-zero buffer of any length ⇒ `GetGolomb = -1`). The earlier port
    // synthesised an implicit leading 1 and returned a large bogus positive.
    for buf in [&[0x00u8][..], &[0x00, 0x00][..], &[0x00, 0x00, 0x00][..]] {
      let mut bs = BitStream::new(buf).expect("non-empty");
      assert_eq!(bs.get_golomb(), -1, "all-zero {buf:?} ⇒ GetGolomb = -1");
    }
  }

  #[test]
  fn golomb_eof_does_not_overflow_shift() {
    // A 64-bit-plus leading-zero run must not trip any shift UB. With no
    // 1-bit the value is `get_int_n(count + 1)` over only past-EOF zero bits
    // ⇒ 0 ⇒ -1; this 16-byte all-zero buffer (128 zero bits) exercises that
    // path. `count` is `usize`, so even a buffer with `> u32::MAX` zero bits
    // would only overflow `usize` (impossible — it is bounded by the slice
    // length); the old `u32` `count += 1` could wrap on a >512 MB NAL.
    let mut bs = BitStream::new(&[0u8; 16]).expect("non-empty");
    assert_eq!(bs.get_golomb(), -1);
  }

  // === Codex R14 F1 — Exp-Golomb 63/64-leading-zero boundary ===

  #[test]
  fn golomb_63_leading_zeros_stays_unsigned() {
    // Bundled `GetGolomb` is a native `UV`, so a 63-leading-zero code is a
    // huge POSITIVE value, NOT a negative `i64`. Construct `63 zeros · 1 ·
    // (1 << 62)` = `0xC000_0000_0000_0000` over 16 bytes; bundled returns
    // `13835058055282163711` (= `0xC000_0000_0000_0000 - 1`). The result
    // must be that exact positive `i128` — the pre-fix `(value as i64)` cast
    // turned it into `-4611686018427387905`, which `parse_seq_param_set`
    // then wrapped back into the validity window.
    let buf = [
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 63 zeros then the 1-bit
      0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // suffix MSB = 1 << 62
    ];
    let mut bs = BitStream::new(&buf).expect("non-empty");
    assert_eq!(bs.get_golomb(), 13_835_058_055_282_163_711_i128);
  }

  #[test]
  fn golomb_64_leading_zeros_wraps_to_minus_one_like_perl() {
    // count = 64 with a 64-bit ZERO suffix: bundled `GetIntN(65)` reads the
    // 1-bit then 64 zero bits, and the `UV` `<<` wraps the leading 1 clean
    // out ⇒ 0 ⇒ `GetGolomb = -1` (bundled-verified: `64 zeros · 1 · 64-bit
    // zero suffix ⇒ -1`, and `100 zeros · zero suffix ⇒ -1`). The pre-fix
    // synthesis `1u64 << count.min(63)` wrongly kept a `1 << 63` bit here.
    let mut buf = vec![0u8; 8]; // 64 leading zeros
    buf.push(0x80); // the 1-bit at bit 64
    buf.extend_from_slice(&[0u8; 8]); // 64-bit zero suffix
    let mut bs = BitStream::new(&buf).expect("non-empty");
    assert_eq!(bs.get_golomb(), -1);

    // A 64-zero code with a NON-zero suffix `1000…` gives `2^63 - 1`
    // (bundled-verified). The leading 1 (bit 64) wraps clean out of the
    // `UV`, then the suffix's leading 1 (bit 65) shifts to bit 63 over the
    // remaining reads. bit64 = bit65 = 1 ⇒ byte 8 = `0b1100_0000` = `0xc0`.
    let mut buf2 = vec![0u8; 8]; // 64 leading zeros
    buf2.push(0xc0); // 1-bit at bit 64 + suffix MSB at bit 65
    buf2.extend_from_slice(&[0u8; 8]);
    let mut bs2 = BitStream::new(&buf2).expect("non-empty");
    assert_eq!(bs2.get_golomb(), 9_223_372_036_854_775_807_i128); // 2^63 - 1
  }

  #[test]
  fn golomb_high_count_reads_count_plus_one_bits() {
    // A non-EOF code can have `count >= 64` (many leading zeros, THEN a
    // 1-bit, with trailing data). 70 zeros · 1 · 70 one-bits ⇒ bundled
    // `18446744073709551614` (= `u64::MAX - 1`, the `UV` saturated all-ones
    // minus 1). The fix reads `count + 1` bits straight through `get_int_n`
    // (u64-wrapping) instead of synthesising the leading 1, so it tracks the
    // wrap. 100 zeros · zero suffix ⇒ -1.
    let mut bits: Vec<u8> = vec![0; 70]; // 70 leading zeros
    bits.push(1); // the terminating 1-bit
    bits.resize(bits.len() + 70, 1); // 70 one-bits of suffix
    bits.resize(bits.len().next_multiple_of(8), 0); // byte-align
    let mut bytes: Vec<u8> = bits
      .chunks(8)
      .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b))
      .collect();
    bytes.extend_from_slice(&[0xff; 8]); // trailing data so the read does not EOF early
    let mut bs = BitStream::new(&bytes).expect("non-empty");
    assert_eq!(bs.get_golomb(), 18_446_744_073_709_551_614_i128);
  }

  #[test]
  fn golomb_leaves_cursor_after_count_plus_one_bits() {
    // Bundled `GetGolomb`'s `until` loop PEEKS the 1-bit without consuming
    // it; `GetIntN(count + 1)` then reads from that 1-bit. So `0x20`
    // (`0010_0000`: 2 zeros, 1-bit, suffix `00`) decodes to 3 and leaves the
    // cursor 5 bits in (after the 1-bit and 2 suffix bits). A following
    // `get_int_n(3)` reads the remaining `000` ⇒ 0.
    let mut bs = BitStream::new(&[0x20]).expect("non-empty");
    assert_eq!(bs.get_golomb(), 3);
    assert_eq!(bs.get_int_n(3), 0);
    // `0x80` (`1000_0000`: 0 zeros) ⇒ 0, cursor 1 bit in.
    let mut bs2 = BitStream::new(&[0x80]).expect("non-empty");
    assert_eq!(bs2.get_golomb(), 0);
    assert_eq!(bs2.get_int_n(1), 0);
  }

  #[test]
  fn sps_golomb63_fabricates_no_image_size() {
    // Codex R14 F1 end-to-end: an SPS whose width/height Golomb codes have
    // 63 leading zeros (the de-escaped RBSP from `tests/golden/h264/
    // h264_sps_golomb63.h264`). Bundled `ParseSeqParamSet` computes a FLOAT
    // size (`≈ 1.5e20`) outside `<= 4096` and emits nothing. The pre-fix
    // port wrapped a negative `i64` Golomb back to 160×128. `parse_seq_param
    // _set` must return `None`.
    let rbsp = b"\x42\x00\x00\xf8\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x89\x01\xfe";
    assert_eq!(
      parse_seq_param_set(rbsp),
      None,
      "63-leading-zero SPS must NOT fabricate a picture size",
    );
  }

  #[test]
  fn sps_golomb64_decodes_genuine_size() {
    // Codex R14 F1 boundary companion: the de-escaped RBSP from
    // `h264_sps_golomb64.h264` decodes to a GENUINELY valid 160×128 (bundled
    // `ParseH264Video` emits `ImageWidth=160`/`ImageHeight=128`). The
    // rewritten `get_golomb` must still reach that result — it pins the
    // 64-bit-`UV`-wrap boundary the old leading-1 synthesis got wrong.
    let rbsp = b"\x42\x00\x00\xf8\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x08\x90\x1f\xe0";
    assert_eq!(
      parse_seq_param_set(rbsp),
      Some(PictureSize {
        width: 160,
        height: 128
      }),
      "64-leading-zero SPS decodes to a genuine 160×128",
    );
  }

  #[test]
  fn get_int_n_stops_at_eof() {
    // Bundled `GetIntN`'s `ReadNextWord ... or last` exits the WHOLE loop at
    // EOF, so a past-end `GetIntN` returns only the bits actually read — NOT
    // that value left-shifted by the missing bit count. `0xff` then a
    // `GetIntN(20)` over the trailing zero bits ⇒ `255`, and `GetIntN(70)`
    // on one `0xff` byte ⇒ `255` (both bundled-verified).
    let mut bs = BitStream::new(&[0xff]).expect("non-empty");
    assert_eq!(bs.get_int_n(70), 255);
    let mut bs2 = BitStream::new(&[0xff, 0x00]).expect("non-empty");
    assert_eq!(bs2.get_int_n(8), 255);
    assert_eq!(bs2.get_int_n(20), 0); // 8 trailing zero bits, no spurious shift
  }

  #[test]
  fn truncated_sps_emits_no_image_size() {
    // A truncated / long-leading-zero SPS drains the bit reader; bundled
    // `ParseSeqParamSet`'s `return unless $$bstr{Mask}` (H264.pm:787) then
    // drops the size BEFORE the validity-window check. Verified against
    // bundled `ParseH264Video`: every short SPS RBSP ⇒ no ImageWidth /
    // ImageHeight. `parse_seq_param_set` must agree.
    for rbsp in [
      &[0x42u8, 0xc0, 0x1f][..],     // truncated baseline SPS prefix
      &[0x00, 0x00, 0x00, 0x00][..], // long leading-zero run
      &[0x42, 0x00][..],
    ] {
      assert!(
        parse_seq_param_set(rbsp).is_none(),
        "truncated SPS {rbsp:?} must yield no picture size",
      );
    }

    // End-to-end through a NAL stream: a `0x67` SPS NAL with a truncated
    // body must emit zero `ImageWidth`/`ImageHeight` entries.
    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x67];
    stream.extend_from_slice(&[0x42, 0xc0, 0x1f]);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    let meta = parse_borrowed(&stream).unwrap();
    assert!(
      meta
        .entries()
        .iter()
        .all(|e| e.name() != "ImageWidth" && e.name() != "ImageHeight"),
      "truncated SPS NAL must emit no image-size tags",
    );
  }

  #[test]
  fn forbidden_bit_pushes_warning() {
    // Codex R8 F2 — H264.pm:1058 `$nal_unit_type & 0x80 and
    // $et->Warn('H264 forbidden bit error'), last`. The NAL header `0x86`
    // (`0b1000_0110`) sets the forbidden_zero_bit; the warning must be pushed
    // into `H264Meta.warnings` BEFORE the scan stops.
    let stream: [u8; 5] = [0x00, 0x00, 0x00, 0x01, 0x86];
    let meta = parse_borrowed(&stream).expect("start code present");
    assert!(
      meta.entries().is_empty(),
      "a forbidden-bit NAL parses no tags",
    );
    assert_eq!(
      meta.warnings(),
      &[SmolStr::new_static("H264 forbidden bit error")],
      "forbidden_zero_bit must surface the static warning",
    );
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn escape_json_number_gate_matches_exiftool_regex() {
    // Faithful port of `EscapeJSON`'s number regex (exiftool:3809):
    // `^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$`.
    // Matches ⇒ bare JSON number.
    for s in [
      "0",
      "1",
      "-3",
      "4113",
      "39321",
      "2.5",
      "-0.3333333",
      "0.284444444444444",
      "1.12246203534218",
      "1e10",
      "1.5e+30",
      "9E-3",
      "123456789012345",    // 15-digit integer (max)
      "1.0123456789012345", // 16-digit fraction (max)
    ] {
      assert!(escape_json_is_number(s), "{s:?} must match the number gate");
    }
    // Does NOT match ⇒ stays a quoted string.
    for s in [
      "",
      "inf",
      "undef",
      "Inf",
      "-Inf",
      "NaN",
      "04:03:02:01",         // TimeCode (colons)
      "12:30:45",            // GPSTimeStamp
      "2021:05:22",          // GPSDateStamp
      "2 3 0 0",             // GPSVersionID (spaces)
      "00",                  // leading zero on a 2-digit int
      "01",                  // leading zero
      "1234567890123456",    // 16-digit integer (over the 15-digit cap)
      "1.",                  // empty fraction
      ".5",                  // missing integer part
      "1.12345678901234567", // 17-digit fraction (over the 16-digit cap)
      "1e",                  // empty exponent
      "1e1234",              // 4-digit exponent (over the 3-digit cap)
      "0x10",                // hex
      "5 mm",                // trailing text
    ] {
      assert!(
        !escape_json_is_number(s),
        "{s:?} must NOT match the number gate"
      );
    }
  }

  #[test]
  #[cfg(feature = "alloc")]
  fn classify_json_scalar_routes_to_typed_writer() {
    // Codex R8 F1 — integers route to the U64/I64 arms (clean int tokens),
    // floats to F64, non-numeric words stay strings.
    assert!(matches!(classify_json_scalar("1"), JsonScalar::U64(1)));
    assert!(matches!(
      classify_json_scalar("4113"),
      JsonScalar::U64(4113)
    ));
    assert!(matches!(classify_json_scalar("-3"), JsonScalar::I64(-3)));
    assert!(matches!(classify_json_scalar("2.5"), JsonScalar::F64(_)));
    assert!(matches!(
      classify_json_scalar("0.284444444444444"),
      JsonScalar::F64(_)
    ));
    assert!(matches!(classify_json_scalar("inf"), JsonScalar::Str));
    assert!(matches!(classify_json_scalar("undef"), JsonScalar::Str));
    assert!(matches!(
      classify_json_scalar("04:03:02:01"),
      JsonScalar::Str
    ));
  }

  /// Contract B / #197 over-f64-gate class (same defect class as
  /// `value.rs::str_over_f64_range_emits_quoted_token_not_null`, different
  /// consumer). `escape_json_is_number` admits an exponent up to
  /// `e[-+]?\d{1,3}` (faithful to `exiftool:3810`), so a crafted MDPM scalar
  /// such as `1e999` matches the gate yet is OUTSIDE finite-f64 range
  /// (`parse::<f64>()` ⇒ `INFINITY`). The classifier must NOT return
  /// `JsonScalar::F64(INFINITY)` — the lowering would build
  /// `TagValue::F64(INFINITY)`, whose serializer emits the titlecase `"Inf"`
  /// string (silently corrupting the source token). It must return
  /// `JsonScalar::Str` so the ORIGINAL token reaches `TagValue::Str`, where the
  /// consolidated `value.rs` gate emits it as a SOUND quoted string (never
  /// `Inf`/`null`, never a panic). Real H264 MDPM metadata never carries such a
  /// magnitude; the priority is consistency + no silent corruption.
  #[test]
  fn classify_json_scalar_over_f64_range_stays_string() {
    for tok in ["1e999", "-1e999", "1e309"] {
      assert!(
        matches!(classify_json_scalar(tok), JsonScalar::Str),
        "{tok:?} (over-f64 exponent) must classify as Str, not F64(INFINITY)"
      );
    }
    // A finite exponent value still routes to the float writer (no regression).
    assert!(matches!(classify_json_scalar("1e10"), JsonScalar::F64(_)));
    assert!(matches!(classify_json_scalar("-1e10"), JsonScalar::F64(_)));
  }

  /// Contract B / #197 SYMMETRIC (under) side of the f64-representation class. A
  /// gate-matching token whose nonzero significand UNDERFLOWS to a finite `0.0`
  /// (`1e-999`, `parse::<f64>()` ⇒ `Ok(0.0)`) must NOT classify as
  /// `JsonScalar::F64(0.0)` — the lowering would build `TagValue::F64(0.0)`, a
  /// bare `0` that rewrites the nonzero source token to zero. It must classify as
  /// `JsonScalar::Str` so the ORIGINAL token reaches `TagValue::Str` (a sound
  /// quoted string). A GENUINE zero token stays a bare `0`; a finite tiny IN-RANGE
  /// nonzero value still routes to the float writer (the predicate must not
  /// over-trigger on small magnitudes).
  #[test]
  #[cfg(feature = "alloc")]
  fn classify_json_scalar_underflow_nonzero_stays_string() {
    for tok in ["1e-999", "-1e-999", "9e-400"] {
      assert!(
        matches!(classify_json_scalar(tok), JsonScalar::Str),
        "{tok:?} (nonzero-underflow exponent) must classify as Str, not F64(0.0)"
      );
    }
    // A genuine zero token (zero significand) is a legitimate bare number.
    assert!(matches!(classify_json_scalar("0e-5"), JsonScalar::F64(_)));
    assert!(matches!(classify_json_scalar("0.0"), JsonScalar::F64(_)));
    // A finite tiny in-range nonzero value still routes to the float writer.
    assert!(matches!(classify_json_scalar("1e-300"), JsonScalar::F64(_)));
  }

  /// End-to-end (`-n` AND `-j`) for the over-f64 MDPM token: lowering the
  /// classifier's arm to a [`TagValue`] then serializing must preserve the
  /// EXACT source token as a quoted JSON string — never `Inf`, never `null`,
  /// never a panic — on both the post-ValueConv (`-n`) and PrintConv (`-j`)
  /// paths. Mirrors the production `H264Value::Text` lowering at
  /// `impl Taggable::tags` (`classify_json_scalar` → `TagValue`).
  #[cfg(feature = "serde")]
  #[test]
  fn over_f64_range_mdpm_token_serializes_quoted_both_modes() {
    use crate::value::TagValue;
    // `-n` (ValueConv scalar): the production lowering routes the numeric text
    // through `classify_json_scalar` → `TagValue`. Replicate that one block.
    let lower_n = |numeric: &str| -> TagValue {
      match classify_json_scalar(numeric) {
        JsonScalar::U64(v) => TagValue::U64(v),
        JsonScalar::I64(v) => TagValue::I64(v),
        JsonScalar::F64(v) => TagValue::F64(v),
        JsonScalar::Str => TagValue::Str(numeric.into()),
      }
    };
    // Both SIDES of the f64-representation class: OVERFLOW (`1e999` ⇒ INFINITY)
    // and nonzero-UNDERFLOW (`1e-999` ⇒ finite `0.0`) must each be preserved as
    // the EXACT quoted source token — never `Inf`, never `0`/`0.0`, never `null`.
    for tok in ["1e999", "-1e999", "1e309", "1e-999", "-1e-999", "9e-400"] {
      // `-n`: the raw token is preserved as a quoted string (the gate fix).
      let json_n = serde_json::to_string(&lower_n(tok)).unwrap();
      assert_eq!(
        json_n,
        std::format!("{tok:?}"),
        "`-n` out-of-range token must stay a quoted string, got {json_n}"
      );
      assert!(json_n != "null" && json_n != "0" && json_n != "0.0" && !json_n.contains("Inf"));
      // `-j` (PrintConv): the production lowering emits the PrintConv string as
      // `TagValue::Str`; the same `value.rs` gate keeps an out-of-range token a
      // sound quoted string.
      let json_j = serde_json::to_string(&TagValue::Str(tok.into())).unwrap();
      assert_eq!(json_j, std::format!("{tok:?}"));
      assert!(json_j != "null" && json_j != "0" && json_j != "0.0" && !json_j.contains("Inf"));
      // Valid JSON on every path (round-trips, never `null`).
      let v: serde_json::Value = serde_json::from_str(&json_n).unwrap();
      assert!(v.is_string());
    }
  }

  // === Codex R12 F1 — short MDPM TimeCode / DateTimeOriginal ===

  #[test]
  fn render_timecode_short_buffers_fill_missing_specs_with_zero() {
    // H264.pm:90 `sprintf("%.2x:%.2x:%.2x:%.2x", reverse unpack("C*",$val))`.
    // `ProcessSEI` short-reads `$buff`; `0x13` has only a `ValueConv` so it
    // runs with NO length gate. Verified vs bundled ExifTool 13.58.
    // Empty buffer ⇒ `unpack` yields nothing ⇒ all four specs Perl-undef.
    assert_eq!(render_timecode(&[]), "00:00:00:00");
    // One byte ⇒ reverse of `[01]` is `[01]`; three specs Perl-undef ⇒ `00`.
    assert_eq!(render_timecode(&[0x01]), "01:00:00:00");
    // Two bytes ⇒ `reverse [01,02]` = `[02,01]`; two trailing specs `00`.
    assert_eq!(render_timecode(&[0x01, 0x02]), "02:01:00:00");
    assert_eq!(render_timecode(&[0x01, 0x02, 0x03]), "03:02:01:00");
    // Full 4-byte buffer is unchanged from the pre-R12 behaviour.
    assert_eq!(render_timecode(&[0x01, 0x02, 0x03, 0x04]), "04:03:02:01");
  }

  #[test]
  fn render_datetime_original_short_buffers_slide_args_positionally() {
    // H264.pm:108-115 — Perl's `sprintf` consumes its 11 specs positionally
    // against `(@a, tz_sign, tz_hours, tz_min, dst)`; a short `@a` slides the
    // computed args into earlier `%.2x`/`%.2d` slots (numifying there) and
    // leaves the tail specs Perl-undef. Verified vs bundled ExifTool 13.58.
    // Empty buffer ⇒ `$tz` undef ⇒ all bit tests see 0; `@a` empty. `-j` and
    // `-n` share one spelling (`ConvertDateTime` is identity here).
    assert_eq!(
      render_datetime_original(&[]).numeric(),
      "0000:00:00 00:00:0000:"
    );
    // 4-byte buffer `80 20 13 05`: tz=0x80, @a=[0x20,0x13,0x05].
    assert_eq!(
      render_datetime_original(&[0x80, 0x20, 0x13, 0x05]).numeric(),
      "2013:05:00 00:00:0000:"
    );
    // 7-byte buffer (a full 0x18 + truncated combined 0x19): tz=0x80,
    // @a=[20,13,05,16,0a,1e].
    assert_eq!(
      render_datetime_original(&[0x80, 0x20, 0x13, 0x05, 0x16, 0x0a, 0x1e]).numeric(),
      "2013:05:16 0a:1e:00000:"
    );
    // Full 8-byte buffer: the four computed args land exactly in the
    // `%s %.2d %s %s` slots — the pre-R12 well-formed output.
    assert_eq!(
      render_datetime_original(&[0x80, 0x20, 0x13, 0x05, 0x16, 0x0a, 0x1e, 0x2d]).numeric(),
      "2013:05:16 0a:1e:2d+00:00"
    );
  }

  #[test]
  fn short_mdpm_timecode_and_datetime_records_are_not_dropped() {
    // End-to-end: a short `0x13` and a short `0x18` record must each still
    // emit their tag (Codex R12 F1). `mdpm_stream` pads to whole 5-byte
    // records, so the short read happens inside the 4-byte data field.
    // 0x13 with data `01 00 00 00` is full-width; to exercise the SHORT path
    // we drive `emit_mdpm` directly with an underlength buffer.
    let mut entries: Vec<H264Entry> = Vec::new();
    let mut make: Option<SmolStr> = None;
    let tc = mdpm_tag(0x13).unwrap();
    emit_mdpm(tc, &[0x01], &mut entries, &mut make);
    let dt = mdpm_tag(0x18).unwrap();
    emit_mdpm(dt, &[0x80, 0x20, 0x13, 0x05], &mut entries, &mut make);
    assert_eq!(entries.len(), 2, "both short records must emit a tag");
    let tc_entry = entries.iter().find(|e| e.name() == "TimeCode").unwrap();
    let dt_entry = entries
      .iter()
      .find(|e| e.name() == "DateTimeOriginal")
      .unwrap();
    if let H264Value::Text(t) = tc_entry.value_ref() {
      assert_eq!(t.numeric(), "01:00:00:00");
      assert_eq!(t.print_conv(), "01:00:00:00");
    } else {
      panic!("TimeCode must be a Text value");
    }
    if let H264Value::Text(t) = dt_entry.value_ref() {
      assert_eq!(t.numeric(), "2013:05:00 00:00:0000:");
    } else {
      panic!("DateTimeOriginal must be a Text value");
    }
  }

  /// Codex R13 F1 — SEI payload-type 255-extension must not overflow a
  /// narrow accumulator into type 5/0x80.
  ///
  /// H264.pm:941-946 accumulates `$type += $t` in a Perl numeric scalar
  /// (transparent int→double), so a long `0xff` run yields an *exact* huge
  /// value that is never 5 nor 0x80 — bundled `ProcessSEI` therefore skips
  /// the message. The former `payload_type: u32` accumulator instead wrapped
  /// modulo 2^32: 0x01010101 (16,843,009) `0xff` bytes contribute
  /// 16_843_009 * 255 = 0xffff_ffff, and a terminal `0x06` makes 2^32 + 5,
  /// which truncates to exactly `5` in `u32` — fabricating MDPM tags in
  /// release builds and panicking overflow-checked builds. Even though the
  /// crafted MDPM payload below is byte-perfect (`UUID + "MDPM"`, one valid
  /// `0xa8` WhiteBalance record), the real type is 4_294_967_301 ≠ 5, so the
  /// fixed parser must treat the message as a non-type-5 payload, skip it,
  /// and emit nothing.
  #[test]
  fn sei_payload_type_extension_does_not_overflow_into_type5() {
    // A genuine type-5 MDPM payload — UUID + "MDPM" + count=1 + one record.
    let mut mdpm: Vec<u8> = Vec::new();
    mdpm.extend_from_slice(&MDPM_UUID_TAG);
    mdpm.push(1); // entry count
    mdpm.extend_from_slice(&[0xa8, 0x00, 0x00, 0x00, 0x01]); // WhiteBalance=1

    // SEI message whose payload TYPE is 255-extended past 2^32: 0x01010101
    // bytes of 0xff (each contributes 255) then a terminal 0x06. Perl type =
    // 16_843_009*255 + 6 = 4_294_967_301; the old u32 port wrapped to 5.
    let mut sei: Vec<u8> = Vec::with_capacity(0x0101_0101 + 8 + mdpm.len());
    sei.resize(0x0101_0101, 0xff); // 16,843,009 type-extension bytes
    sei.push(0x06); // terminal type byte
    // Payload size: 255-extended encoding of mdpm.len() (< 255 here).
    debug_assert!(mdpm.len() < 255);
    sei.push(mdpm.len() as u8);
    sei.extend_from_slice(&mdpm);
    sei.push(0x80); // SEI terminator

    // Wrap in a NAL stream (type-6 SEI) the way `avchd_fixture` does. The
    // long 0xff run contains no `00 00 03`, so RBSP de-escaping is a no-op.
    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    stream.extend_from_slice(&escape_rbsp(&sei));
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);

    // Must not panic (overflow-checked builds) and must emit no tags: the
    // huge real type is not 5, so the MDPM payload is never decoded.
    let meta = parse_borrowed(&stream).expect("stream has a NAL start code");
    assert!(
      meta.is_empty(),
      "an overflowing SEI payload type must not fabricate MDPM tags, got {:?}",
      meta.entries()
    );
    assert!(meta.make().is_none(), "no Make from a skipped SEI message");

    // Sanity anchor: the SAME MDPM payload behind a real type-5 header DOES
    // decode — proving the assertion above is the overflow guard, not a
    // broken fixture.
    let mut ok_sei: Vec<u8> = vec![5, mdpm.len() as u8];
    ok_sei.extend_from_slice(&mdpm);
    ok_sei.push(0x80);
    let mut ok_stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    ok_stream.extend_from_slice(&escape_rbsp(&ok_sei));
    ok_stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);
    let ok = parse_borrowed(&ok_stream).unwrap();
    assert_eq!(
      ok.entries()
        .iter()
        .map(super::H264Entry::name)
        .collect::<Vec<_>>(),
      ["WhiteBalance"],
      "the crafted MDPM payload is itself valid behind a real type-5 header",
    );
  }

  /// Codex R13 class-sweep — a maximal 255-entry MDPM block parses without
  /// panic or divergence.
  ///
  /// H264.pm:986/1011 `++$index` runs in both the outer `for` and the
  /// Combine `while`. The MDPM walk's `index` counter is a `u8`; this anchors
  /// that a full count-255 ascending block (the largest the entry-count byte
  /// can express) walks to completion and emits every record. The
  /// strictly-ascending-tag rule (H264.pm:988) plus the low Combine-tag ids
  /// (≤ 0xe4) keep `index` structurally bounded well under 255, so no
  /// overflow is reachable — this is the regression anchor for that bound.
  /// The payload here exceeds 255 bytes, so it also exercises the
  /// `payload_size` 255-extension accumulator audited alongside F1.
  #[test]
  fn mdpm_walk_handles_maximal_255_entry_block() {
    // 255 distinct strictly-ascending ids (1..=255); most are not table
    // tags, so they parse-and-skip, but the walk must advance cleanly
    // across all 255 without panicking.
    let mut recs: Vec<u8> = Vec::with_capacity(255 * 5);
    for id in 1u16..=255 {
      recs.extend_from_slice(&[id as u8, 0x00, 0x00, 0x00, 0x01]);
    }

    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&MDPM_UUID_TAG);
    payload.push(255); // entry count
    payload.extend_from_slice(&recs);

    // SEI: type 5, then the payload SIZE 255-extended (payload > 255 bytes,
    // so this needs ⌊len/255⌋ `0xff` bytes + the remainder).
    let mut sei: Vec<u8> = vec![5];
    let mut remaining = payload.len();
    while remaining >= 255 {
      sei.push(0xff);
      remaining -= 255;
    }
    sei.push(remaining as u8);
    sei.extend_from_slice(&payload);
    sei.push(0x80);

    let mut stream: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x06];
    stream.extend_from_slice(&escape_rbsp(&sei));
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x09, 0x10]);

    // Must not panic on any build and must not emit the out-of-sequence
    // warning (the ids are strictly ascending).
    let meta = parse_borrowed(&stream).expect("has a NAL start code");
    assert!(
      meta.warnings().is_empty(),
      "strictly-ascending records ⇒ no out-of-sequence warning",
    );
    // 0xa8 WhiteBalance is one of the 255 ids and carries data `…01` ⇒ a
    // real record, proving the walk reached the high-id region.
    let wb = meta
      .entries()
      .iter()
      .find(|e| e.name() == "WhiteBalance")
      .expect("the 0xa8 record inside the 255-entry block must emit");
    assert!(wb.group().is_h264());
  }

  #[test]
  fn taggable_group_is_h264_family0_and_entry_family1() {
    use crate::emit::{ConvMode, Taggable};
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).unwrap();
    let tags: Vec<_> = meta.tags(ConvMode::PrintConv).collect();
    assert!(!tags.is_empty(), "the MDPM block must yield tags");
    // No H264 table row is `Unknown => 1`.
    assert!(tags.iter().all(|t| !t.unknown()));
    // family0 is the constant "H264" table group; the avchd fixture's tags
    // (TimeCode / ExposureProgram / WhiteBalance / Make …) are all in the
    // family-1 "H264" group (no GPS block in this fixture).
    assert!(tags.iter().all(|t| t.tag().group_ref().family0() == "H264"));
    let time_code = tags
      .iter()
      .find(|t| t.tag().name() == "TimeCode")
      .expect("TimeCode emitted");
    assert_eq!(time_code.tag().group_ref().family1(), "H264");
  }

  #[test]
  fn taggable_yields_only_visible_winner_for_duplicate_name() {
    use crate::emit::{ConvMode, Taggable};
    // The 255-entry maximal block ends with a real 0xa8 WhiteBalance; build a
    // meta whose tag stream the visibility filter governs. Here we reuse the
    // avchd fixture (single WhiteBalance) and assert the filter yields exactly
    // one WhiteBalance — the engine's one-per-`group:name` default render.
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).unwrap();
    let wb_count = meta
      .tags(ConvMode::PrintConv)
      .filter(|t| t.tag().name() == "WhiteBalance")
      .count();
    assert_eq!(wb_count, 1, "the visibility filter yields one winner");
  }

  #[test]
  fn project_populates_video_track() {
    use crate::metadata::{Project, TrackKind};
    let data = avchd_fixture();
    let meta = parse_borrowed(&data).unwrap();
    let projected = meta.project();
    // H.264 is a video elementary stream ⇒ a single video track kind.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Video]);
    assert!(projected.media().has_video());
    assert!(projected.media().duration().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().created().is_none());
    // The MDPM camera facts surface as tags but have no domain slot yet.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }
}
