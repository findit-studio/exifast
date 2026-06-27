// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag2010a`..`Tag2010f` (`Sony.pm:6464-6980`) — the
//! enciphered `0x2010` `ProcessBinaryData` shot-info blocks (release / self-timer
//! / flash mode, gain / brightness / exposure compensation, DRO / HDR /
//! PictureProfile / PictureEffect, metering / exposure program, white-balance
//! `WB_RGBLevels`, SonyISO, distortion-correction params, and — for the DSC
//! variants — focal-length / aspect-ratio).
//!
//! ## Variant dispatch
//!
//! The `0x2010` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:1100-1173`) selected by `$$self{Model}` — the `a`-`f` rows are
//! `$`-anchored EXACT matches, the `g`/`h`/`i` rows `\b`-anchored prefix sets:
//!
//! - `Tag2010a` — `/^NEX-5N$/` (`Sony.pm:1128`).
//! - `Tag2010b` — `/^(SLT-A(65|77)V?|NEX-(7|VG20E)|Lunar)$/` (`Sony.pm:1132`).
//! - `Tag2010c` — `/^(SLT-A(37|57)|NEX-F3)$/` (`Sony.pm:1136`).
//! - `Tag2010d` — `/^(DSC-(HX10V|HX20V|HX30V|HX200V|TX66|TX200V|TX300V|WX50|WX70|`
//!   `WX100|WX150))$/` AND `not $$self{Panorama}` (`Sony.pm:1140-1145`).
//! - `Tag2010e` — `/^(SLT-A99V?|HV|SLT-A58|ILCE-(3000|3500)|NEX-(3N|5R|5T|6|`
//!   `VG900|VG30E)|DSC-(RX100|RX1|RX1R)|Stellar)$/`, OR
//!   `/^(DSC-(HX300|HX50|HX50V|TX30|WX60|WX80|WX200|WX300))$/` AND
//!   `not $$self{Panorama}` (`Sony.pm:1147-1153`).
//! - `Tag2010f` — `/^(DSC-(RX100M2|QX10|QX100))$/` (`Sony.pm:1156`).
//! - `Tag2010g` — `/^(DSC-(QX30|RX10|RX100M3|HX60V|HX350|HX400V|WX220|WX350)|`
//!   `ILCE-(7(R|S|M2)?|[56]000|5100|QX1)|ILCA-(68|77M2))\b/` (`Sony.pm:1159-1161`).
//!   The `\b` (NOT `$`) means a bare `ILCE-7` does not swallow `ILCE-7RM2`.
//! - `Tag2010h` — `/^(DSC-(RX0|RX1RM2|RX10M2|RX10M3|RX100M4|RX100M5|HX80|HX90V?|`
//!   `WX500)|ILCE-(6300|6500|7RM2|7SM2)|ILCA-99M2)\b/` (`Sony.pm:1162-1164`).
//! - `Tag2010i` — `/^(ILCE-(6100A?|6400A?|6600|7C|7M3|7RM3A?|7RM4A?|9|9M2)|`
//!   `DSC-(RX10M4|RX100M6|RX100M5A|RX100M7A?|HX95|HX99|RX0M2)|`
//!   `ZV-(1[AF]?|1M2|E10))\b/` (`Sony.pm:1166-1169`).
//! - else `Tag_0x2010` (`%unknownCipherData`) — an unknown / newer body, emits
//!   nothing (faithful: ExifTool's `%unknownCipherData` extracts nothing either).
//!
//! The `a`-`f` model sets are pairwise disjoint and disjoint from the
//! `\b`-anchored `g`/`h`/`i` sets, so the dispatcher tests every variant
//! (`a`..`i`) independently; a body matching none falls to the unknown branch.
//!
//! ## Cipher + priority + availability
//!
//! Every `Tag2010x` table is `PROCESS_PROC => \&ProcessEnciphered`,
//! `FORMAT => 'int8u'`, `FIRST_ENTRY => 0`, `PRIORITY => 0` (`Sony.pm:6464-6473`
//! etc.). The dispatcher [`process_enciphered`](super::decipher::process_enciphered)s
//! the block (using `$$self{DoubleCipher}`, which `0x2010 < 0x9400` in IFD-tag
//! order leaves unset on a well-formed file) and hands the per-variant parser the
//! DECIPHERED bytes. Each emitted leaf rides `PRIORITY => 0`, so it never
//! overrides an earlier same-name duplicate.
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range is
//! in the deciphered block ([[exifast-processbinarydata-per-field]]). The
//! `MeterInfo` `IS_SUBDIR` row (`0x04b0`/`0x04b4`/`0x0490`/`0x050c`/`0x01e0`) is
//! `Unknown => 1` (`Sony.pm:7456-7458` — "Extracted only if the Unknown option is
//! used"), so it is NOT emitted in default output and is skipped here.
//!
//! The `a`/`b`/`c`/`d`/`f` tables have NO per-leaf model `Condition`s; their
//! model gate lives entirely in the dispatcher. `Tag2010e`/`g`/`h`/`i` (like
//! `Tag9405b`) DO carry per-leaf `Condition`s — for `e` the `\b`-anchored SonyISO
//! / FocalLength offset sets and the two mutually-exclusive `AspectRatio`
//! offsets; for all four, the `LensFormat`/`LensMount`/`DistortionCorr*`
//! DSC(-or-Stellar) exclusions and the `LensType2`/`LensType`
//! `LensMount`-DataMember gates — so `parse_tag2010e`/`g`/`h`/`i` take the
//! resolved `$$self{Model}`.

use super::{amount_lens_types, lens_types};
use crate::value::{TagValue, whole_f64_to_tag_value};
use smol_str::SmolStr;

/// One emitted `Tag2010a`..`Tag2010f` leaf — the resolved tag name and rendered
/// value.
pub struct Tag2010Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`/ValueConv).
  pub value: TagValue,
}

// --- byte readers ------------------------------------------------------------

/// Read a little-endian `int16u` at byte `off` of the deciphered block.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// Read a little-endian `int16s` at byte `off` of the deciphered block.
fn read_i16(buf: &[u8], off: usize) -> Option<i16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(i16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// Read a little-endian `int32u` at byte `off` of the deciphered block.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

// --- variant model gates (EXACT `$`-anchored `$$self{Model}` match) ----------

/// `true` when `model` equals any of `stems` exactly (the Perl `/^(…)$/`
/// whole-string alternation used by the `0x2010` dispatcher `Condition`s).
fn model_eq_any(model: Option<&str>, stems: &[&str]) -> bool {
  let Some(m) = model else { return false };
  stems.contains(&m)
}

/// `Sony.pm:1128` `/^NEX-5N$/` — selects `Tag2010a`.
#[must_use]
pub fn selects_tag2010a(model: Option<&str>) -> bool {
  model == Some("NEX-5N")
}

/// `Sony.pm:1132` `/^(SLT-A(65|77)V?|NEX-(7|VG20E)|Lunar)$/` — selects
/// `Tag2010b`. The `V?` makes the trailing `V` optional (SLT-A65/A65V/A77/A77V).
#[must_use]
pub fn selects_tag2010b(model: Option<&str>) -> bool {
  model_eq_any(
    model,
    &[
      "SLT-A65",
      "SLT-A65V",
      "SLT-A77",
      "SLT-A77V",
      "NEX-7",
      "NEX-VG20E",
      "Lunar",
    ],
  )
}

/// `Sony.pm:1136` `/^(SLT-A(37|57)|NEX-F3)$/` — selects `Tag2010c`.
#[must_use]
pub fn selects_tag2010c(model: Option<&str>) -> bool {
  model_eq_any(model, &["SLT-A37", "SLT-A57", "NEX-F3"])
}

/// `Sony.pm:1140-1145` `/^(DSC-(HX10V|HX20V|HX30V|HX200V|TX66|TX200V|TX300V|`
/// `WX50|WX70|WX100|WX150))$/` AND `not $$self{Panorama}` — selects `Tag2010d`.
/// The `panorama` flag is the file-global `$$self{Panorama}` DataMember
/// (`Sony.pm:902`), latched on the `0x1003` walk before `0x2010`.
#[must_use]
pub fn selects_tag2010d(model: Option<&str>, panorama: bool) -> bool {
  !panorama
    && model_eq_any(
      model,
      &[
        "DSC-HX10V",
        "DSC-HX20V",
        "DSC-HX30V",
        "DSC-HX200V",
        "DSC-TX66",
        "DSC-TX200V",
        "DSC-TX300V",
        "DSC-WX50",
        "DSC-WX70",
        "DSC-WX100",
        "DSC-WX150",
      ],
    )
}

/// `Sony.pm:1156` `/^(DSC-(RX100M2|QX10|QX100))$/` — selects `Tag2010f`.
#[must_use]
pub fn selects_tag2010f(model: Option<&str>) -> bool {
  model_eq_any(model, &["DSC-RX100M2", "DSC-QX10", "DSC-QX100"])
}

/// `Sony.pm:1148-1153` — selects `Tag2010e`. Two `$`-anchored alternations: the
/// first (`SLT-A99V?|HV|SLT-A58|ILCE-(3000|3500)|NEX-(3N|5R|5T|6|VG900|VG30E)|`
/// `DSC-(RX100|RX1|RX1R)|Stellar`) is unconditional; the second
/// (`DSC-(HX300|HX50|HX50V|TX30|WX60|WX80|WX200|WX300)`) additionally requires
/// `not $$self{Panorama}` (the `0x1003` DataMember latched earlier in the walk,
/// like `Tag2010d`). `SLT-A99V?` expands to `SLT-A99`/`SLT-A99V`.
#[must_use]
pub fn selects_tag2010e(model: Option<&str>, panorama: bool) -> bool {
  model_eq_any(
    model,
    &[
      "SLT-A99",
      "SLT-A99V",
      "HV",
      "SLT-A58",
      "ILCE-3000",
      "ILCE-3500",
      "NEX-3N",
      "NEX-5R",
      "NEX-5T",
      "NEX-6",
      "NEX-VG900",
      "NEX-VG30E",
      "DSC-RX100",
      "DSC-RX1",
      "DSC-RX1R",
      "Stellar",
    ],
  ) || (!panorama
    && model_eq_any(
      model,
      &[
        "DSC-HX300",
        "DSC-HX50",
        "DSC-HX50V",
        "DSC-TX30",
        "DSC-WX60",
        "DSC-WX80",
        "DSC-WX200",
        "DSC-WX300",
      ],
    ))
}

/// `Sony.pm:1160`
/// `/^(DSC-(QX30|RX10|RX100M3|HX60V|HX350|HX400V|WX220|WX350)|`
/// `ILCE-(7(R|S|M2)?|[56]000|5100|QX1)|ILCA-(68|77M2))\b/` — selects `Tag2010g`.
/// The `\b` word boundary means a bare `ILCE-7` does NOT swallow `ILCE-7RM2` /
/// `ILCE-7SM2` (`Tag2010h` models): `ILCE-(7(R|S|M2)?...)` expands to
/// `ILCE-7`/`-7R`/`-7S`/`-7M2`, then `\b`.
#[must_use]
pub fn selects_tag2010g(model: Option<&str>) -> bool {
  super::tag9405::starts_with_word_boundary(
    model,
    &[
      "DSC-QX30",
      "DSC-RX10",
      "DSC-RX100M3",
      "DSC-HX60V",
      "DSC-HX350",
      "DSC-HX400V",
      "DSC-WX220",
      "DSC-WX350",
      "ILCE-7",
      "ILCE-7R",
      "ILCE-7S",
      "ILCE-7M2",
      "ILCE-5000",
      "ILCE-6000",
      "ILCE-5100",
      "ILCE-QX1",
      "ILCA-68",
      "ILCA-77M2",
    ],
  )
}

/// `Sony.pm:1164`
/// `/^(DSC-(RX0|RX1RM2|RX10M2|RX10M3|RX100M4|RX100M5|HX80|HX90V?|WX500)|`
/// `ILCE-(6300|6500|7RM2|7SM2)|ILCA-99M2)\b/` — selects `Tag2010h`. The `\b`
/// keeps `DSC-RX0` from swallowing `DSC-RX0M2` and `DSC-RX100M5` from swallowing
/// `DSC-RX100M5A` (`Tag2010i` models); `HX90V?` expands to `DSC-HX90`/`-HX90V`.
#[must_use]
pub fn selects_tag2010h(model: Option<&str>) -> bool {
  super::tag9405::starts_with_word_boundary(
    model,
    &[
      "DSC-RX0",
      "DSC-RX1RM2",
      "DSC-RX10M2",
      "DSC-RX10M3",
      "DSC-RX100M4",
      "DSC-RX100M5",
      "DSC-HX80",
      "DSC-HX90",
      "DSC-HX90V",
      "DSC-WX500",
      "ILCE-6300",
      "ILCE-6500",
      "ILCE-7RM2",
      "ILCE-7SM2",
      "ILCA-99M2",
    ],
  )
}

/// `Sony.pm:1168`
/// `/^(ILCE-(6100A?|6400A?|6600|7C|7M3|7RM3A?|7RM4A?|9|9M2)|`
/// `DSC-(RX10M4|RX100M6|RX100M5A|RX100M7A?|HX95|HX99|RX0M2)|`
/// `ZV-(1[AF]?|1M2|E10))\b/` — selects `Tag2010i`. The `A?`/`[AF]?` optionals
/// expand to their base + suffixed stems (`ILCE-9`/`-9M2`, `ZV-1`/`-1A`/`-1F`);
/// the `\b` boundary distinguishes e.g. `ILCE-9` from `ILCE-9M2`.
#[must_use]
pub fn selects_tag2010i(model: Option<&str>) -> bool {
  super::tag9405::starts_with_word_boundary(
    model,
    &[
      "ILCE-6100",
      "ILCE-6100A",
      "ILCE-6400",
      "ILCE-6400A",
      "ILCE-6600",
      "ILCE-7C",
      "ILCE-7M3",
      "ILCE-7RM3",
      "ILCE-7RM3A",
      "ILCE-7RM4",
      "ILCE-7RM4A",
      "ILCE-9",
      "ILCE-9M2",
      "DSC-RX10M4",
      "DSC-RX100M6",
      "DSC-RX100M5A",
      "DSC-RX100M7",
      "DSC-RX100M7A",
      "DSC-HX95",
      "DSC-HX99",
      "DSC-RX0M2",
      "ZV-1",
      "ZV-1A",
      "ZV-1F",
      "ZV-1M2",
      "ZV-E10",
    ],
  )
}

/// `$$self{Panorama} = ($$valPt =~ /^(\0\0)?\x01\x01/)` (`Sony.pm:902`) — the
/// `0x1003` `Panorama` SubDirectory `Condition` DataMember side-effect: a raw
/// value that begins with `\x01\x01` (little-endian int32u 257) or
/// `\0\0\x01\x01` (big-endian) latches `$$self{Panorama}`. Tested against the
/// RAW on-disk `0x1003` value bytes.
#[must_use]
pub fn detects_panorama(raw: &[u8]) -> bool {
  raw.starts_with(&[0x01, 0x01]) || raw.starts_with(&[0x00, 0x00, 0x01, 0x01])
}

// --- PrintConv hashes (shared `%…2010` Tag2010 hashes) -----------------------

/// `%releaseMode2010` `ReleaseMode3` (`Sony.pm:6245-6256`).
fn release_mode3_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Continuous",
    2 => "Bracketing",
    4 => "Continuous - Burst",
    5 => "Continuous - Speed/Advance Priority",
    6 => "Normal - Self-timer",
    9 => "Single Burst Shooting",
    _ => return None,
  })
}

/// `%selfTimer2010` `SelfTimer` (`Sony.pm:6258-6265`).
fn self_timer_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Self-timer 10 s",
    2 => "Self-timer 2 s",
    _ => return None,
  })
}

/// `%flashMode2010` `FlashMode` (`Sony.pm:6365-6376`).
fn flash_mode_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Autoflash",
    1 => "Fill-flash",
    2 => "Flash Off",
    3 => "Slow Sync",
    4 => "Rear Sync",
    6 => "Wireless",
    _ => return None,
  })
}

/// `%dynamicRangeOptimizer2010` `DynamicRangeOptimizer` (`Sony.pm:6293-6305`).
fn dynamic_range_optimizer_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Auto",
    3 => "Lv1",
    4 => "Lv2",
    5 => "Lv3",
    6 => "Lv4",
    7 => "Lv5",
    8 => "n/a",
    _ => return None,
  })
}

/// `%hdr2010` `HDRSetting` (`Sony.pm:6306-6318`).
fn hdr_setting_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "HDR Auto",
    3 => "HDR 1 EV",
    5 => "HDR 2 EV",
    7 => "HDR 3 EV",
    9 => "HDR 4 EV",
    11 => "HDR 5 EV",
    13 => "HDR 6 EV",
    _ => return None,
  })
}

/// `%pictureEffect2010` `PictureEffect2` (`Sony.pm:6327-6346`).
fn picture_effect2_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Toy Camera",
    2 => "Pop Color",
    3 => "Posterization",
    4 => "Retro Photo",
    5 => "Soft High Key",
    6 => "Partial Color",
    7 => "High Contrast Monochrome",
    8 => "Soft Focus",
    9 => "HDR Painting",
    10 => "Rich-tone Monochrome",
    11 => "Miniature",
    12 => "Water Color",
    13 => "Illustration",
    _ => return None,
  })
}

/// `%quality2010` `Quality2` (`Sony.pm:6347-6354`).
fn quality2_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "JPEG",
    1 => "RAW",
    2 => "RAW + JPEG",
    _ => return None,
  })
}

/// `%meteringMode2010` `MeteringMode` (`Sony.pm:6355-6364`).
fn metering_mode_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Multi-segment",
    2 => "Center-weighted average",
    3 => "Spot",
    4 => "Average",
    5 => "Highlight",
    _ => return None,
  })
}

/// `%pictureProfile2010` `PictureProfile` (`Sony.pm:6382-6417`) — the FULL hash
/// (value `2` has no label → a miss). Distinct from `Tag9416`'s deliberately
/// truncated FX3-range copy.
fn picture_profile_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Gamma Still - Standard/Neutral (PP2)",
    1 => "Gamma Still - Portrait",
    3 => "Gamma Still - Night View/Portrait",
    4 => "Gamma Still - B&W/Sepia",
    5 => "Gamma Still - Clear",
    6 => "Gamma Still - Deep",
    7 => "Gamma Still - Light",
    8 => "Gamma Still - Vivid",
    9 => "Gamma Still - Real",
    10 => "Gamma Movie (PP1)",
    22 => "Gamma ITU709 (PP3 or PP4)",
    24 => "Gamma Cine1 (PP5)",
    25 => "Gamma Cine2 (PP6)",
    26 => "Gamma Cine3",
    27 => "Gamma Cine4",
    28 => "Gamma S-Log2 (PP7)",
    29 => "Gamma ITU709 (800%)",
    31 => "Gamma S-Log3 (PP8 or PP9)",
    33 => "Gamma HLG2 (PP10)",
    34 => "Gamma HLG3",
    36 => "Off",
    37 => "FL",
    38 => "VV2",
    39 => "IN",
    40 => "SH",
    48 => "FL2",
    49 => "FL3",
    _ => return None,
  })
}

/// `AspectRatio` PrintConv hash — `Tag2010f` `0x192c` (`Sony.pm:6970-6978`),
/// shared by the `Tag2010e`/`g`/`h`/`i` `AspectRatio` rows
/// (`Sony.pm:6870`/`7109`/`7256`/`7397`).
fn aspect_ratio_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "16:9",
    1 => "4:3",
    2 => "3:2",
    3 => "1:1",
    5 => "Panorama",
    _ => return None,
  })
}

/// `%selfTimerB2010` `SelfTimer` (`Sony.pm:6266-6273`) — the `Tag2010h`/`i`
/// variant where value `1` is "Self-timer 5 or 10 s" (the new 5 s mode), vs
/// `%selfTimer2010`'s "Self-timer 10 s".
fn self_timer_b_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Self-timer 5 or 10 s",
    2 => "Self-timer 2 s",
    _ => return None,
  })
}

/// `DistortionCorrParamsNumber` PrintConv `{ 11 => '11 (APS-C)', 16 => '16
/// (Full-frame)' }` (`Sony.pm:6863`/`7103`/`7252`/`7393`).
fn distortion_corr_params_number_print(v: u8) -> Option<&'static str> {
  Some(match v {
    11 => "11 (APS-C)",
    16 => "16 (Full-frame)",
    _ => return None,
  })
}

// --- value pushers -----------------------------------------------------------

/// An `int8u` row whose PrintConv is a lookup hash. A hash MISS renders
/// `"Unknown ($val)"` in `-j` / the raw `$val` in `-n` ([`super::hash_print_value`]).
fn push_u8_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  hash: impl Fn(u8) -> Option<&'static str>,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  out.push(Tag2010Emission {
    name,
    value: super::hash_print_value(raw, hash(raw), print_conv),
  });
}

/// `%releaseMode2, Format => 'int32u'` (`Sony.pm:6512` etc.) — the `ReleaseMode2`
/// hash applied to an `int32u`. A value `> 255` (or an unmapped one) is a hash
/// MISS → `"Unknown ($val)"` in `-j` (the FULL `int32u`) / the raw int in `-n`.
fn push_release_mode2_u32(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u32_le(buf, off) else {
    return;
  };
  let hit = u8::try_from(raw).ok().and_then(super::release_mode2_print);
  let value = match (print_conv, hit) {
    (true, Some(s)) => TagValue::Str(s.into()),
    (true, None) => TagValue::Str(std::format!("Unknown ({raw})").into()),
    (false, _) => TagValue::I64(i64::from(raw)),
  };
  out.push(Tag2010Emission { name, value });
}

/// `SonyISO` — int16u, `ValueConv => '100 * 2**(16 - $val/256)'`,
/// `PrintConv => 'sprintf("%.0f",$val)'` (`Sony.pm:6553-6559` etc.).
fn push_sony_iso(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let iso = 100.0 * 2f64.powf(16.0 - f64::from(raw) / 256.0);
  let value = if print_conv {
    TagValue::Str(std::format!("{iso:.0}").into())
  } else {
    whole_f64_to_tag_value(iso)
  };
  out.push(Tag2010Emission { name, value });
}

/// `%gain2010` `StopsAboveBaseISO` — int16u, `ValueConv => '16 - $val/256'`,
/// `PrintConv => '$val ? sprintf("%.1f",$val) : $val'` (`Sony.pm:6274-6286`).
fn push_gain2010(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let stops = 16.0 - f64::from(raw) / 256.0;
  // `$val ? sprintf("%.1f",$val) : $val` — a ValueConv of exactly 0 prints the
  // bare ValueConv result (integer `0`); otherwise "%.1f".
  let value = if print_conv && stops != 0.0 {
    TagValue::Str(std::format!("{stops:.1}").into())
  } else {
    whole_f64_to_tag_value(stops)
  };
  out.push(Tag2010Emission { name, value });
}

/// `%brightnessValue2010` `BrightnessValue` — int16u, `ValueConv =>
/// '$val/256 - 56.6'`, no PrintConv (`Sony.pm:6287-6292`). Same value in `-j`/`-n`.
fn push_brightness_value(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let v = f64::from(raw) / 256.0 - 56.6;
  out.push(Tag2010Emission {
    name,
    value: whole_f64_to_tag_value(v),
  });
}

/// `%exposureComp2010` `ExposureCompensation` — int16s, `ValueConv =>
/// '-$val/256'`, `PrintConv => '$val ? sprintf("%+.1f",$val) : 0'`
/// (`Sony.pm:6319-6326`). `-n` keeps the ValueConv; `-j` shows a signed `%.1f`
/// for a non-zero value, else the bare integer `0`.
fn push_exposure_comp(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_i16(buf, off) else {
    return;
  };
  let v = -f64::from(raw) / 256.0;
  let value = if print_conv {
    if raw != 0 {
      TagValue::Str(std::format!("{v:+.1}").into())
    } else {
      TagValue::I64(0)
    }
  } else {
    whole_f64_to_tag_value(v)
  };
  out.push(Tag2010Emission { name, value });
}

/// `%sequenceImageNumber`/`%sequenceFileNumber` — int32u, `ValueConv =>
/// '$val + 1'` (`Sony.pm:6180-6194`). Same value in `-j`/`-n`.
fn push_sequence_plus1(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  if let Some(raw) = read_u32_le(buf, off) {
    out.push(Tag2010Emission {
      name,
      value: TagValue::I64(i64::from(raw) + 1),
    });
  }
}

/// `%sonyDateTime2010` `SonyDateTime` — `undef[7]`, `ValueConv` unpacks
/// `('vC*')` → `"%.4d:%.2d:%.2d %.2d:%.2d:%.2d"`, `PrintConv => ConvertDateTime`
/// (identity under default options) (`Sony.pm:6229-6244`). Same value in `-j`/`-n`.
/// Emitted IFF all 7 bytes are in range.
fn push_sony_date_time(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(end) = off.checked_add(7) else {
    return;
  };
  // `unpack('vC*')`: the year is a little-endian int16u (2 bytes); month, day,
  // hour, minute, second are the next five int8u.
  let Some(&[y0, y1, mon, day, hour, min, sec]) = buf.get(off..end) else {
    return;
  };
  let year = u16::from_le_bytes([y0, y1]);
  let s = std::format!("{year:04}:{mon:02}:{day:02} {hour:02}:{min:02}:{sec:02}");
  out.push(Tag2010Emission {
    name,
    value: TagValue::Str(s.into()),
  });
}

/// `DigitalZoomRatio` — int8u, `ValueConv => '$val/16'`, no PrintConv
/// (`Sony.pm:6597`/`6724`). Same value in `-j`/`-n`.
fn push_digital_zoom_ratio(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  let v = f64::from(raw) / 16.0;
  out.push(Tag2010Emission {
    name,
    value: whole_f64_to_tag_value(v),
  });
}

/// `FocalLength`/`MinFocalLength`/`MaxFocalLength` — int16u, `ValueConv =>
/// '$val / 10'`, `PrintConv => 'sprintf("%.1f mm",$val)'` (`Sony.pm:6932-6958`).
fn push_focal_length(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let v = f64::from(raw) / 10.0;
  let value = if print_conv {
    TagValue::Str(std::format!("{v:.1} mm").into())
  } else {
    whole_f64_to_tag_value(v)
  };
  out.push(Tag2010Emission { name, value });
}

/// `MaxFocalLength` for the `e`/`g`/`h`/`i` variants — as [`push_focal_length`]
/// but with the `RawConv => '$val || undef'` (`Sony.pm:6795`/`7032` etc.): a RAW
/// int16u of `0` (a fixed-focal-length lens) yields `undef`, so the tag is NOT
/// emitted.
fn push_focal_length_nonzero(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  if raw == 0 {
    return;
  }
  let v = f64::from(raw) / 10.0;
  let value = if print_conv {
    TagValue::Str(std::format!("{v:.1} mm").into())
  } else {
    whole_f64_to_tag_value(v)
  };
  out.push(Tag2010Emission { name, value });
}

/// A `LensType2` (E-mount, `%sonyLensTypes2`) or `LensType` (A-mount,
/// `%sonyLensTypes`) row — int16u, `gated` by the caller on the `LensMount`
/// DataMember (`$$self{LensMount} == 2` / `== 1`). A hash MISS renders
/// `"Unknown ($val)"` (`-j`) / the raw int16u (`-n`); `PrintInt => 1` is a
/// `BuildTagLookup`-only doc flag, not a runtime directive. Mirrors the
/// `Tag9405` `push_lens_type` (`Sony.pm:6837-6854` etc.).
fn push_lens_type(
  buf: &[u8],
  off: usize,
  name: &'static str,
  gated: bool,
  lookup: impl Fn(u32) -> Option<SmolStr>,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  if !gated {
    return;
  }
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let value = if print_conv {
    match lookup(u32::from(raw)) {
      Some(label) => TagValue::Str(label),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({raw})"))),
    }
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(Tag2010Emission { name, value });
}

/// An `int16u[count]` array row (`WB_RGBLevels`) — space-joined for BOTH `-j`
/// and `-n` (no PrintConv). Emitted IFF the whole `count`-element span is in
/// range.
fn push_u16_array(
  buf: &[u8],
  off: usize,
  count: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(end) = count.checked_mul(2).and_then(|n| off.checked_add(n)) else {
    return;
  };
  let Some(span) = buf.get(off..end) else {
    return;
  };
  let mut joined = std::string::String::new();
  for (i, pair) in span.chunks_exact(2).enumerate() {
    use core::fmt::Write;
    if i > 0 {
      joined.push(' ');
    }
    let v = match pair {
      &[lo, hi] => u16::from_le_bytes([lo, hi]),
      _ => continue,
    };
    let _ = write!(joined, "{v}");
  }
  out.push(Tag2010Emission {
    name,
    value: TagValue::Str(joined.into()),
  });
}

/// An `int16s[count]` array row (`DistortionCorrParams`) — space-joined for BOTH
/// `-j` and `-n` (no PrintConv). Emitted IFF the whole `count`-element span is in
/// range.
fn push_i16_array(
  buf: &[u8],
  off: usize,
  count: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag2010Emission>,
) {
  let Some(end) = count.checked_mul(2).and_then(|n| off.checked_add(n)) else {
    return;
  };
  let Some(span) = buf.get(off..end) else {
    return;
  };
  let mut joined = std::string::String::new();
  for (i, pair) in span.chunks_exact(2).enumerate() {
    use core::fmt::Write;
    if i > 0 {
      joined.push(' ');
    }
    let v = match pair {
      &[lo, hi] => i16::from_le_bytes([lo, hi]),
      _ => continue,
    };
    let _ = write!(joined, "{v}");
  }
  out.push(Tag2010Emission {
    name,
    value: TagValue::Str(joined.into()),
  });
}

// --- parsers -----------------------------------------------------------------

/// Walk the DECIPHERED `Tag2010a` block (`Sony.pm:6464-6499`).
///
/// `buf` is the DECIPHERED `0x2010` block (the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered)); `print_conv`
/// selects `-j` (PrintConv) vs `-n` (raw `$val`/ValueConv).
#[must_use]
pub fn parse_tag2010a(buf: &[u8], print_conv: bool) -> Vec<Tag2010Emission> {
  let mut out = std::vec::Vec::new();
  // 0x04b0 MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x1128,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x112c,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1134,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1138,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x113e, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x1140, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x1144,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1148,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x114c, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x115e,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x115f,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1163,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1170,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1174,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1175,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x117c, 3, "WB_RGBLevels", &mut out);
  out
}

/// Walk the DECIPHERED `Tag2010b` block (`Sony.pm:6501-6567`).
#[must_use]
pub fn parse_tag2010b(buf: &[u8], print_conv: bool) -> Vec<Tag2010Emission> {
  let mut out = std::vec::Vec::new();
  push_sequence_plus1(buf, 0x0000, "SequenceImageNumber", &mut out);
  push_sequence_plus1(buf, 0x0004, "SequenceFileNumber", &mut out);
  push_release_mode2_u32(buf, 0x0008, "ReleaseMode2", print_conv, &mut out);
  push_sony_date_time(buf, 0x01b6, "SonyDateTime", &mut out);
  push_u8_hash(
    buf,
    0x0324,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  // 0x04b4 MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x1128,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x112c,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1134,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1138,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x113e, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x1140, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x1144,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1148,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x114c, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x1162,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1163,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1167,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1174,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1178,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1179,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x1180, 3, "WB_RGBLevels", &mut out);
  push_sony_iso(buf, 0x1218, "SonyISO", print_conv, &mut out);
  push_i16_array(buf, 0x1a23, 16, "DistortionCorrParams", &mut out);
  out
}

/// Walk the DECIPHERED `Tag2010c` block (`Sony.pm:6569-6633`).
#[must_use]
pub fn parse_tag2010c(buf: &[u8], print_conv: bool) -> Vec<Tag2010Emission> {
  let mut out = std::vec::Vec::new();
  push_sequence_plus1(buf, 0x0000, "SequenceImageNumber", &mut out);
  push_sequence_plus1(buf, 0x0004, "SequenceFileNumber", &mut out);
  push_release_mode2_u32(buf, 0x0008, "ReleaseMode2", print_conv, &mut out);
  push_digital_zoom_ratio(buf, 0x0200, "DigitalZoomRatio", &mut out);
  push_sony_date_time(buf, 0x0210, "SonyDateTime", &mut out);
  push_u8_hash(
    buf,
    0x0300,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  // 0x0490 MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x1104,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1108,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1110,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1114,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x111a, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x111c, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x1120,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1124,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x1128, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x113e,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x113f,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1143,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1150,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1154,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1155,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x115c, 3, "WB_RGBLevels", &mut out);
  push_sony_iso(buf, 0x11f4, "SonyISO", print_conv, &mut out);
  out
}

/// Walk the DECIPHERED `Tag2010d` block (`Sony.pm:6635-6695`).
#[must_use]
pub fn parse_tag2010d(buf: &[u8], print_conv: bool) -> Vec<Tag2010Emission> {
  let mut out = std::vec::Vec::new();
  push_sequence_plus1(buf, 0x0000, "SequenceImageNumber", &mut out);
  push_sequence_plus1(buf, 0x0004, "SequenceFileNumber", &mut out);
  push_release_mode2_u32(buf, 0x0008, "ReleaseMode2", print_conv, &mut out);
  push_sony_date_time(buf, 0x01fe, "SonyDateTime", &mut out);
  push_u8_hash(
    buf,
    0x037c,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  // 0x050c MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x1180,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1184,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x118c,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1190,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x1196, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x1198, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x119c,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11a0,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11ba,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11bb,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11bf,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11d0,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11d1,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x11d8, 3, "WB_RGBLevels", &mut out);
  push_sony_iso(buf, 0x1270, "SonyISO", print_conv, &mut out);
  out
}

/// Walk the DECIPHERED `Tag2010f` block (`Sony.pm:6893-6978`).
#[must_use]
pub fn parse_tag2010f(buf: &[u8], print_conv: bool) -> Vec<Tag2010Emission> {
  let mut out = std::vec::Vec::new();
  // 0x0004 ReleaseMode2 (int32u) — NOT at 0x0008 for this variant.
  push_release_mode2_u32(buf, 0x0004, "ReleaseMode2", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0050,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  // 0x01e0 MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x1014,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1018,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1020,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1024,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x102a, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x102c, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x1030,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1034,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x1038, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x104e,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x104f,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1053,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1060,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1064,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1065,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x106c, 3, "WB_RGBLevels", &mut out);
  push_focal_length(buf, 0x1134, "FocalLength", print_conv, &mut out);
  push_focal_length(buf, 0x1136, "MinFocalLength", print_conv, &mut out);
  push_focal_length(buf, 0x1138, "MaxFocalLength", print_conv, &mut out);
  push_sony_iso(buf, 0x113c, "SonyISO", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x192c,
    "AspectRatio",
    print_conv,
    aspect_ratio_print,
    &mut out,
  );
  out
}

/// Walk the DECIPHERED `Tag2010e` block (`Sony.pm:6697-6891`).
///
/// `buf` is the DECIPHERED `0x2010` block; `model` drives the per-leaf model
/// `Condition`s — the `\b`-anchored SonyISO / FocalLength sets, the
/// `LensFormat`/`LensMount`/`DistortionCorr*` DSC(-or-Stellar) exclusions, and
/// the two mutually-exclusive `AspectRatio` offsets. `print_conv` selects
/// `-j`/`-n`.
#[must_use]
pub fn parse_tag2010e(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag2010Emission> {
  use super::tag9405::{
    model_is_dsc, model_is_dsc_or_stellar, print_lens_format, print_lens_mount, print_no_yes,
    starts_with_word_boundary,
  };
  let mut out = std::vec::Vec::new();
  let not_dsc_or_stellar = !model_is_dsc_or_stellar(model);

  push_sequence_plus1(buf, 0x0000, "SequenceImageNumber", &mut out);
  push_sequence_plus1(buf, 0x0004, "SequenceFileNumber", &mut out);
  push_release_mode2_u32(buf, 0x0008, "ReleaseMode2", print_conv, &mut out);
  push_digital_zoom_ratio(buf, 0x021c, "DigitalZoomRatio", &mut out);
  push_sony_date_time(buf, 0x022c, "SonyDateTime", &mut out);
  push_u8_hash(
    buf,
    0x0328,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  // 0x04b8 MeterInfo (Unknown SubDirectory) — skipped.
  push_u8_hash(
    buf,
    0x115c,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1160,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1168,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x116c,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x1172, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x1174, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x1178,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x117c,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x1180, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x1196,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x1197,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x119b,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11a8,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11ac,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x11ad,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x11b4, 3, "WB_RGBLevels", &mut out);
  // 0x1254 SonyISO — Condition
  // /^(SLT-(A99|A99V)|NEX-(5R|5T|6|VG900|VG30E)|DSC-RX100|Stellar|HV)\b/.
  if starts_with_word_boundary(
    model,
    &[
      "SLT-A99",
      "SLT-A99V",
      "NEX-5R",
      "NEX-5T",
      "NEX-6",
      "NEX-VG900",
      "NEX-VG30E",
      "DSC-RX100",
      "Stellar",
      "HV",
    ],
  ) {
    push_sony_iso(buf, 0x1254, "SonyISO", print_conv, &mut out);
  }
  // 0x1258 SonyISO — Condition /^(DSC-(RX1|RX1R))\b/.
  if starts_with_word_boundary(model, &["DSC-RX1", "DSC-RX1R"]) {
    push_sony_iso(buf, 0x1258, "SonyISO", print_conv, &mut out);
  }
  // 0x1278-0x1280 FocalLength / MinFocalLength / MaxFocalLength / SonyISO —
  // Condition
  // /^(SLT-A58|ILCE-(3000|3500)|NEX-3N|DSC-(HX300|HX50V|WX60|WX80|WX200|WX300|TX30))\b/.
  if starts_with_word_boundary(
    model,
    &[
      "SLT-A58",
      "ILCE-3000",
      "ILCE-3500",
      "NEX-3N",
      "DSC-HX300",
      "DSC-HX50V",
      "DSC-WX60",
      "DSC-WX80",
      "DSC-WX200",
      "DSC-WX300",
      "DSC-TX30",
    ],
  ) {
    push_focal_length(buf, 0x1278, "FocalLength", print_conv, &mut out);
    push_focal_length(buf, 0x127a, "MinFocalLength", print_conv, &mut out);
    push_focal_length_nonzero(buf, 0x127c, "MaxFocalLength", print_conv, &mut out);
    push_sony_iso(buf, 0x1280, "SonyISO", print_conv, &mut out);
  }
  // 0x1870 DistortionCorrParams int16s[16] — Condition Model !~ /^(DSC-|Stellar)/.
  if not_dsc_or_stellar {
    push_i16_array(buf, 0x1870, 16, "DistortionCorrParams", &mut out);
  }
  // 0x1891 LensFormat — same Condition.
  if not_dsc_or_stellar {
    push_u8_hash(
      buf,
      0x1891,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x1892 LensMount — DataMember (raw always latched, drives LensType2/LensType);
  // the tag is emitted iff Model !~ /^(DSC-|Stellar)/.
  let lens_mount = buf.get(0x1892).copied();
  if not_dsc_or_stellar {
    push_u8_hash(
      buf,
      0x1892,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x1893 LensType2 — Condition LensMount == 2 (E-mount, %sonyLensTypes2).
  push_lens_type(
    buf,
    0x1893,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x1896 LensType — Condition LensMount == 1 (A-mount, %sonyLensTypes).
  push_lens_type(
    buf,
    0x1896,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x1898 DistortionCorrParamsPresent — Condition Model !~ /^(DSC-|Stellar)/.
  if not_dsc_or_stellar {
    push_u8_hash(
      buf,
      0x1898,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x1899 DistortionCorrParamsNumber — Condition Model !~ /^DSC-/ (NOT Stellar).
  if !model_is_dsc(model) {
    push_u8_hash(
      buf,
      0x1899,
      "DistortionCorrParamsNumber",
      print_conv,
      distortion_corr_params_number_print,
      &mut out,
    );
  }
  // 0x192c AspectRatio — Condition Model !~ /^(DSC-RX100|Stellar)\b/.
  // 0x1a88 AspectRatio — Condition Model =~ /^(DSC-RX100|Stellar)\b/.
  let aspect_rx100_stellar = starts_with_word_boundary(model, &["DSC-RX100", "Stellar"]);
  if !aspect_rx100_stellar {
    push_u8_hash(
      buf,
      0x192c,
      "AspectRatio",
      print_conv,
      aspect_ratio_print,
      &mut out,
    );
  }
  if aspect_rx100_stellar {
    push_u8_hash(
      buf,
      0x1a88,
      "AspectRatio",
      print_conv,
      aspect_ratio_print,
      &mut out,
    );
  }
  out
}

/// Walk the DECIPHERED `Tag2010g` block (`Sony.pm:6980-7119`).
///
/// `buf` is the DECIPHERED `0x2010` block; `model` drives the `Model !~ /^DSC-/`
/// lens / distortion-correction exclusions and the `LensMount` DataMember (which
/// gates `LensType2`/`LensType`). The FocalLength / SonyISO / AspectRatio rows
/// are unconditional here (unlike `Tag2010e`). `print_conv` selects `-j`/`-n`.
#[must_use]
pub fn parse_tag2010g(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag2010Emission> {
  use super::tag9405::{model_is_dsc, print_lens_format, print_lens_mount, print_no_yes};
  let mut out = std::vec::Vec::new();
  let not_dsc = !model_is_dsc(model);

  // 0x0004 ReleaseMode2 (int32u) — NOT at 0x0008 for this variant.
  push_release_mode2_u32(buf, 0x0004, "ReleaseMode2", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0050,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x020c,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0210,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0218,
    "SelfTimer",
    print_conv,
    self_timer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x021c,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x0222, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x0224, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x0228,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x022c,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x0230, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0246,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0247,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x024b,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0258,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x025c,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x025d,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x0264, 3, "WB_RGBLevels", &mut out);
  push_focal_length(buf, 0x032c, "FocalLength", print_conv, &mut out);
  push_focal_length(buf, 0x032e, "MinFocalLength", print_conv, &mut out);
  push_focal_length_nonzero(buf, 0x0330, "MaxFocalLength", print_conv, &mut out);
  push_sony_iso(buf, 0x0344, "SonyISO", print_conv, &mut out);
  // 0x0388 MeterInfo (Unknown SubDirectory) — skipped.
  // 0x189c DistortionCorrParams int16s[16] — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_i16_array(buf, 0x189c, 16, "DistortionCorrParams", &mut out);
  }
  // 0x18bd LensFormat — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18bd,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x18be LensMount — DataMember (raw always latched, drives LensType2/LensType);
  // the tag is emitted iff Model !~ /^DSC-/.
  let lens_mount = buf.get(0x18be).copied();
  if not_dsc {
    push_u8_hash(
      buf,
      0x18be,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x18bf LensType2 — Condition LensMount == 2 (E-mount, %sonyLensTypes2).
  push_lens_type(
    buf,
    0x18bf,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x18c2 LensType — Condition LensMount == 1 (A-mount, %sonyLensTypes).
  push_lens_type(
    buf,
    0x18c2,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x18c4 DistortionCorrParamsPresent — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18c4,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x18c5 DistortionCorrParamsNumber — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18c5,
      "DistortionCorrParamsNumber",
      print_conv,
      distortion_corr_params_number_print,
      &mut out,
    );
  }
  push_u8_hash(
    buf,
    0x1958,
    "AspectRatio",
    print_conv,
    aspect_ratio_print,
    &mut out,
  );
  out
}

/// Walk the DECIPHERED `Tag2010h` block (`Sony.pm:7121-7268`).
///
/// Structurally `Tag2010g` with: `SelfTimer` via `%selfTimerB2010` (value `1` =
/// "Self-timer 5 or 10 s"), `SonyISO` at 0x0346, the lens / distortion rows at
/// 0x18cc-0x18f5, and `AspectRatio` at 0x192c. `model` drives the
/// `Model !~ /^DSC-/` exclusions + the `LensMount` gate; `print_conv` selects
/// `-j`/`-n`.
#[must_use]
pub fn parse_tag2010h(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag2010Emission> {
  use super::tag9405::{model_is_dsc, print_lens_format, print_lens_mount, print_no_yes};
  let mut out = std::vec::Vec::new();
  let not_dsc = !model_is_dsc(model);

  push_release_mode2_u32(buf, 0x0004, "ReleaseMode2", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0050,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x020c,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0210,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0218,
    "SelfTimer",
    print_conv,
    self_timer_b_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x021c,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x0222, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x0224, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x0228,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x022c,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x0230, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0246,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0247,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x024b,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0258,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x025c,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x025d,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x0264, 3, "WB_RGBLevels", &mut out);
  push_focal_length(buf, 0x032c, "FocalLength", print_conv, &mut out);
  push_focal_length(buf, 0x032e, "MinFocalLength", print_conv, &mut out);
  push_focal_length_nonzero(buf, 0x0330, "MaxFocalLength", print_conv, &mut out);
  push_sony_iso(buf, 0x0346, "SonyISO", print_conv, &mut out);
  // 0x0388 / 0x0398 MeterInfo (Unknown SubDirectory, model-conditioned) — skipped.
  // 0x18cc DistortionCorrParams int16s[16] — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_i16_array(buf, 0x18cc, 16, "DistortionCorrParams", &mut out);
  }
  // 0x18ed LensFormat — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18ed,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x18ee LensMount — DataMember (raw always latched, drives LensType2/LensType);
  // the tag is emitted iff Model !~ /^DSC-/.
  let lens_mount = buf.get(0x18ee).copied();
  if not_dsc {
    push_u8_hash(
      buf,
      0x18ee,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x18ef LensType2 — Condition LensMount == 2 (E-mount, %sonyLensTypes2).
  push_lens_type(
    buf,
    0x18ef,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x18f2 LensType — Condition LensMount == 1 (A-mount, %sonyLensTypes).
  push_lens_type(
    buf,
    0x18f2,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x18f4 DistortionCorrParamsPresent — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18f4,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x18f5 DistortionCorrParamsNumber — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x18f5,
      "DistortionCorrParamsNumber",
      print_conv,
      distortion_corr_params_number_print,
      &mut out,
    );
  }
  push_u8_hash(
    buf,
    0x192c,
    "AspectRatio",
    print_conv,
    aspect_ratio_print,
    &mut out,
  );
  out
}

/// Walk the DECIPHERED `Tag2010i` block (`Sony.pm:7270-7405`).
///
/// `Tag2010h` repacked at lower offsets: the scalar block is at 0x004e-0x0252
/// (note `Quality2` is at 0x0247, where `g`/`h` had a second `PictureProfile`),
/// FocalLength / SonyISO at 0x030a-0x0320, the lens / distortion rows at
/// 0x17d0-0x17f9, and `AspectRatio` at 0x188c. `SelfTimer` is `%selfTimerB2010`.
/// `model` drives the `Model !~ /^DSC-/` exclusions + the `LensMount` gate;
/// `print_conv` selects `-j`/`-n`.
#[must_use]
pub fn parse_tag2010i(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag2010Emission> {
  use super::tag9405::{model_is_dsc, print_lens_format, print_lens_mount, print_no_yes};
  let mut out = std::vec::Vec::new();
  let not_dsc = !model_is_dsc(model);

  push_release_mode2_u32(buf, 0x0004, "ReleaseMode2", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x004e,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0204,
    "ReleaseMode3",
    print_conv,
    release_mode3_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0208,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0210,
    "SelfTimer",
    print_conv,
    self_timer_b_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0211,
    "FlashMode",
    print_conv,
    flash_mode_print,
    &mut out,
  );
  push_gain2010(buf, 0x0217, "StopsAboveBaseISO", print_conv, &mut out);
  push_brightness_value(buf, 0x0219, "BrightnessValue", &mut out);
  push_u8_hash(
    buf,
    0x021b,
    "DynamicRangeOptimizer",
    print_conv,
    dynamic_range_optimizer_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x021f,
    "HDRSetting",
    print_conv,
    hdr_setting_print,
    &mut out,
  );
  push_exposure_comp(buf, 0x0223, "ExposureCompensation", print_conv, &mut out);
  push_u8_hash(
    buf,
    0x0237,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0238,
    "PictureProfile",
    print_conv,
    picture_profile_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x023c,
    "PictureEffect2",
    print_conv,
    picture_effect2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0247,
    "Quality2",
    print_conv,
    quality2_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x024b,
    "MeteringMode",
    print_conv,
    metering_mode_print,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x024c,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  push_u16_array(buf, 0x0252, 3, "WB_RGBLevels", &mut out);
  push_focal_length(buf, 0x030a, "FocalLength", print_conv, &mut out);
  push_focal_length(buf, 0x030c, "MinFocalLength", print_conv, &mut out);
  push_focal_length_nonzero(buf, 0x030e, "MaxFocalLength", print_conv, &mut out);
  push_sony_iso(buf, 0x0320, "SonyISO", print_conv, &mut out);
  // 0x036d MeterInfo (Unknown SubDirectory, MeterInfo9) — skipped.
  // 0x17d0 DistortionCorrParams int16s[16] — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_i16_array(buf, 0x17d0, 16, "DistortionCorrParams", &mut out);
  }
  // 0x17f1 LensFormat — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x17f1,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x17f2 LensMount — DataMember (raw always latched, drives LensType2/LensType);
  // the tag is emitted iff Model !~ /^DSC-/.
  let lens_mount = buf.get(0x17f2).copied();
  if not_dsc {
    push_u8_hash(
      buf,
      0x17f2,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x17f3 LensType2 — Condition LensMount == 2 (E-mount, %sonyLensTypes2).
  push_lens_type(
    buf,
    0x17f3,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x17f6 LensType — Condition LensMount == 1 (A-mount, %sonyLensTypes).
  push_lens_type(
    buf,
    0x17f6,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x17f8 DistortionCorrParamsPresent — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x17f8,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x17f9 DistortionCorrParamsNumber — same Condition.
  if not_dsc {
    push_u8_hash(
      buf,
      0x17f9,
      "DistortionCorrParamsNumber",
      print_conv,
      distortion_corr_params_number_print,
      &mut out,
    );
  }
  push_u8_hash(
    buf,
    0x188c,
    "AspectRatio",
    print_conv,
    aspect_ratio_print,
    &mut out,
  );
  out
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag2010_tests.rs"]
mod tests;
