// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony A-mount lens-type lookup — the Minolta-backed `%sonyLensTypes`
//! (`Sony.pm:32,53`; runtime-filled at `Sony.pm:11000-11050` from
//! `%Image::ExifTool::Minolta::minoltaLensTypes`, `Minolta.pm:180-552`).
//!
//! `%Sony::Main` 0xb027 `LensType` uses `PrintConv => \%sonyLensTypes`
//! (`Sony.pm:2370`), the A-mount (Minolta-derived) table — NOT the E-mount
//! `%sonyLensTypes2` ([`super::lens_types`]). E-mount lenses (raw values
//! `0x80xx`) are written as `65535` here (`Sony.pm:2368`
//! `ValueConvInv => '($val & 0xff00) == 0x8000 ? 65535 : int($val)'`), which
//! maps to `"E-Mount, T-Mount, Other Lens or no lens"` (`Minolta.pm:545`).
//!
//! ## What is ported
//!
//! The 242 INTEGER keys of the runtime-filled `%sonyLensTypes` (the bundled
//! `%minoltaLensTypes` integer keys PLUS the 4-digit derivatives ExifTool
//! generates from 5-digit IDs at `Sony.pm:11010-11045`). Dumped from the
//! bundled module so the table matches what `PrintConv => \%sonyLensTypes`
//! resolves against at runtime, byte-for-byte.
//!
//! ## Deferred (faithful gaps, documented)
//!
//! - **Float-keyed disambiguation** (e.g. `7.1`, `65535.1`): the bundled
//!   secondary names shown when the primary doesn't match `LensSpec`. Same
//!   deferral as `%sonyLensTypes2` — only the primary (integer-key) name is
//!   ported; LensSpec disambiguation is a follow-up (#62).
//! - **The `OTHER => sub` adapter cross-reference** (`Minolta.pm:186-205`):
//!   for high-byte adapter IDs it combines Metabones (Canon `%canonLensTypes`)
//!   / Sigma MC-11 (`%sigmaLensTypes`) lens names. That requires the Canon +
//!   Sigma lens tables (deferred long-tail vendors); when the OTHER sub
//!   returns undef — the case for ordinary A-mount lenses — ExifTool falls
//!   through to the standard `"Unknown (N)"` PrintConv default, which the
//!   [`lookup_name`] miss-path reproduces.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of the A-mount `%sonyLensTypes` (Minolta-backed) table.
#[derive(Debug, Clone, Copy)]
pub struct SonyLensType {
  /// The integer lens-type ID (the key in the filled `%sonyLensTypes`).
  pub id: u32,
  /// The lens model name.
  pub name: &'static str,
}

/// `%sonyLensTypes` (A-mount, Minolta-backed) — sorted by ID
/// (binary-search-ready). 242 integer rows.
pub const SONY_LENS_TYPES_AMOUNT: &[SonyLensType] = &[
  SonyLensType {
    id: 0,
    name: "Minolta AF 28-85mm F3.5-4.5 New",
  },
  SonyLensType {
    id: 1,
    name: "Minolta AF 80-200mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 2,
    name: "Minolta AF 28-70mm F2.8 G",
  },
  SonyLensType {
    id: 3,
    name: "Minolta AF 28-80mm F4-5.6",
  },
  SonyLensType {
    id: 4,
    name: "Minolta AF 85mm F1.4G",
  },
  SonyLensType {
    id: 5,
    name: "Minolta AF 35-70mm F3.5-4.5 [II]",
  },
  SonyLensType {
    id: 6,
    name: "Minolta AF 24-85mm F3.5-4.5 [New]",
  },
  SonyLensType {
    id: 7,
    name: "Minolta AF 100-300mm F4.5-5.6 APO [New] or 100-400mm or Sigma Lens",
  },
  SonyLensType {
    id: 8,
    name: "Minolta AF 70-210mm F4.5-5.6 [II]",
  },
  SonyLensType {
    id: 9,
    name: "Minolta AF 50mm F3.5 Macro",
  },
  SonyLensType {
    id: 10,
    name: "Minolta AF 28-105mm F3.5-4.5 [New]",
  },
  SonyLensType {
    id: 11,
    name: "Minolta AF 300mm F4 HS-APO G",
  },
  SonyLensType {
    id: 12,
    name: "Minolta AF 100mm F2.8 Soft Focus",
  },
  SonyLensType {
    id: 13,
    name: "Minolta AF 75-300mm F4.5-5.6 (New or II)",
  },
  SonyLensType {
    id: 14,
    name: "Minolta AF 100-400mm F4.5-6.7 APO",
  },
  SonyLensType {
    id: 15,
    name: "Minolta AF 400mm F4.5 HS-APO G",
  },
  SonyLensType {
    id: 16,
    name: "Minolta AF 17-35mm F3.5 G",
  },
  SonyLensType {
    id: 17,
    name: "Minolta AF 20-35mm F3.5-4.5",
  },
  SonyLensType {
    id: 18,
    name: "Minolta AF 28-80mm F3.5-5.6 II",
  },
  SonyLensType {
    id: 19,
    name: "Minolta AF 35mm F1.4 G",
  },
  SonyLensType {
    id: 20,
    name: "Minolta/Sony 135mm F2.8 [T4.5] STF",
  },
  SonyLensType {
    id: 22,
    name: "Minolta AF 35-80mm F4-5.6 II",
  },
  SonyLensType {
    id: 23,
    name: "Minolta AF 200mm F4 Macro APO G",
  },
  SonyLensType {
    id: 24,
    name: "Minolta/Sony AF 24-105mm F3.5-4.5 (D) or Sigma or Tamron Lens",
  },
  SonyLensType {
    id: 25,
    name: "Minolta AF 100-300mm F4.5-5.6 APO (D) or Sigma Lens",
  },
  SonyLensType {
    id: 27,
    name: "Minolta AF 85mm F1.4 G (D)",
  },
  SonyLensType {
    id: 28,
    name: "Minolta/Sony AF 100mm F2.8 Macro (D) or Tamron Lens",
  },
  SonyLensType {
    id: 29,
    name: "Minolta/Sony AF 75-300mm F4.5-5.6 (D)",
  },
  SonyLensType {
    id: 30,
    name: "Minolta AF 28-80mm F3.5-5.6 (D) or Sigma Lens",
  },
  SonyLensType {
    id: 31,
    name: "Minolta/Sony AF 50mm F2.8 Macro (D) or F3.5",
  },
  SonyLensType {
    id: 32,
    name: "Minolta/Sony AF 300mm F2.8 G or 1.5x Teleconverter",
  },
  SonyLensType {
    id: 33,
    name: "Minolta/Sony AF 70-200mm F2.8 G",
  },
  SonyLensType {
    id: 35,
    name: "Minolta AF 85mm F1.4 G (D) Limited",
  },
  SonyLensType {
    id: 36,
    name: "Minolta AF 28-100mm F3.5-5.6 (D)",
  },
  SonyLensType {
    id: 38,
    name: "Minolta AF 17-35mm F2.8-4 (D)",
  },
  SonyLensType {
    id: 39,
    name: "Minolta AF 28-75mm F2.8 (D)",
  },
  SonyLensType {
    id: 40,
    name: "Minolta/Sony AF DT 18-70mm F3.5-5.6 (D)",
  },
  SonyLensType {
    id: 41,
    name: "Minolta/Sony AF DT 11-18mm F4.5-5.6 (D) or Tamron Lens",
  },
  SonyLensType {
    id: 42,
    name: "Minolta/Sony AF DT 18-200mm F3.5-6.3 (D)",
  },
  SonyLensType {
    id: 43,
    name: "Sony 35mm F1.4 G (SAL35F14G)",
  },
  SonyLensType {
    id: 44,
    name: "Sony 50mm F1.4 (SAL50F14)",
  },
  SonyLensType {
    id: 45,
    name: "Carl Zeiss Planar T* 85mm F1.4 ZA (SAL85F14Z)",
  },
  SonyLensType {
    id: 46,
    name: "Carl Zeiss Vario-Sonnar T* DT 16-80mm F3.5-4.5 ZA (SAL1680Z)",
  },
  SonyLensType {
    id: 47,
    name: "Carl Zeiss Sonnar T* 135mm F1.8 ZA (SAL135F18Z)",
  },
  SonyLensType {
    id: 48,
    name: "Carl Zeiss Vario-Sonnar T* 24-70mm F2.8 ZA SSM (SAL2470Z) or Other Lens",
  },
  SonyLensType {
    id: 49,
    name: "Sony DT 55-200mm F4-5.6 (SAL55200)",
  },
  SonyLensType {
    id: 50,
    name: "Sony DT 18-250mm F3.5-6.3 (SAL18250)",
  },
  SonyLensType {
    id: 51,
    name: "Sony DT 16-105mm F3.5-5.6 (SAL16105)",
  },
  SonyLensType {
    id: 52,
    name: "Sony 70-300mm F4.5-5.6 G SSM (SAL70300G) or G SSM II or Tamron Lens",
  },
  SonyLensType {
    id: 53,
    name: "Sony 70-400mm F4-5.6 G SSM (SAL70400G)",
  },
  SonyLensType {
    id: 54,
    name: "Carl Zeiss Vario-Sonnar T* 16-35mm F2.8 ZA SSM (SAL1635Z) or ZA SSM II",
  },
  SonyLensType {
    id: 55,
    name: "Sony DT 18-55mm F3.5-5.6 SAM (SAL1855) or SAM II",
  },
  SonyLensType {
    id: 56,
    name: "Sony DT 55-200mm F4-5.6 SAM (SAL55200-2)",
  },
  SonyLensType {
    id: 57,
    name: "Sony DT 50mm F1.8 SAM (SAL50F18) or Tamron Lens or Commlite CM-EF-NEX adapter",
  },
  SonyLensType {
    id: 58,
    name: "Sony DT 30mm F2.8 Macro SAM (SAL30M28)",
  },
  SonyLensType {
    id: 59,
    name: "Sony 28-75mm F2.8 SAM (SAL2875)",
  },
  SonyLensType {
    id: 60,
    name: "Carl Zeiss Distagon T* 24mm F2 ZA SSM (SAL24F20Z)",
  },
  SonyLensType {
    id: 61,
    name: "Sony 85mm F2.8 SAM (SAL85F28)",
  },
  SonyLensType {
    id: 62,
    name: "Sony DT 35mm F1.8 SAM (SAL35F18)",
  },
  SonyLensType {
    id: 63,
    name: "Sony DT 16-50mm F2.8 SSM (SAL1650)",
  },
  SonyLensType {
    id: 64,
    name: "Sony 500mm F4 G SSM (SAL500F40G)",
  },
  SonyLensType {
    id: 65,
    name: "Sony DT 18-135mm F3.5-5.6 SAM (SAL18135)",
  },
  SonyLensType {
    id: 66,
    name: "Sony 300mm F2.8 G SSM II (SAL300F28G2)",
  },
  SonyLensType {
    id: 67,
    name: "Sony 70-200mm F2.8 G SSM II (SAL70200G2)",
  },
  SonyLensType {
    id: 68,
    name: "Sony DT 55-300mm F4.5-5.6 SAM (SAL55300)",
  },
  SonyLensType {
    id: 69,
    name: "Sony 70-400mm F4-5.6 G SSM II (SAL70400G2)",
  },
  SonyLensType {
    id: 70,
    name: "Carl Zeiss Planar T* 50mm F1.4 ZA SSM (SAL50F14Z)",
  },
  SonyLensType {
    id: 128,
    name: "Tamron or Sigma Lens (128)",
  },
  SonyLensType {
    id: 129,
    name: "Tamron Lens (129)",
  },
  SonyLensType {
    id: 131,
    name: "Tamron 20-40mm F2.7-3.5 SP Aspherical IF",
  },
  SonyLensType {
    id: 135,
    name: "Vivitar 28-210mm F3.5-5.6",
  },
  SonyLensType {
    id: 136,
    name: "Tokina EMZ M100 AF 100mm F3.5",
  },
  SonyLensType {
    id: 137,
    name: "Cosina 70-210mm F2.8-4 AF",
  },
  SonyLensType {
    id: 138,
    name: "Soligor 19-35mm F3.5-4.5",
  },
  SonyLensType {
    id: 139,
    name: "Tokina AF 28-300mm F4-6.3",
  },
  SonyLensType {
    id: 142,
    name: "Cosina AF 70-300mm F4.5-5.6 MC",
  },
  SonyLensType {
    id: 146,
    name: "Voigtlander Macro APO-Lanthar 125mm F2.5 SL",
  },
  SonyLensType {
    id: 194,
    name: "Tamron SP AF 17-50mm F2.8 XR Di II LD Aspherical [IF]",
  },
  SonyLensType {
    id: 202,
    name: "Tamron SP AF 70-200mm F2.8 Di LD [IF] Macro",
  },
  SonyLensType {
    id: 203,
    name: "Tamron SP 70-200mm F2.8 Di USD",
  },
  SonyLensType {
    id: 204,
    name: "Tamron SP 24-70mm F2.8 Di USD",
  },
  SonyLensType {
    id: 212,
    name: "Tamron 28-300mm F3.5-6.3 Di PZD",
  },
  SonyLensType {
    id: 213,
    name: "Tamron 16-300mm F3.5-6.3 Di II PZD Macro",
  },
  SonyLensType {
    id: 214,
    name: "Tamron SP 150-600mm F5-6.3 Di USD",
  },
  SonyLensType {
    id: 215,
    name: "Tamron SP 15-30mm F2.8 Di USD",
  },
  SonyLensType {
    id: 216,
    name: "Tamron SP 45mm F1.8 Di USD",
  },
  SonyLensType {
    id: 217,
    name: "Tamron SP 35mm F1.8 Di USD",
  },
  SonyLensType {
    id: 218,
    name: "Tamron SP 90mm F2.8 Di Macro 1:1 USD (F017)",
  },
  SonyLensType {
    id: 220,
    name: "Tamron SP 150-600mm F5-6.3 Di USD G2",
  },
  SonyLensType {
    id: 224,
    name: "Tamron SP 90mm F2.8 Di Macro 1:1 USD (F004)",
  },
  SonyLensType {
    id: 255,
    name: "Tamron Lens (255)",
  },
  SonyLensType {
    id: 1868,
    name: "Sigma MC-11 SA-E Mount Converter with not-supported Sigma lens",
  },
  SonyLensType {
    id: 2550,
    name: "Minolta AF 50mm F1.7",
  },
  SonyLensType {
    id: 2551,
    name: "Minolta AF 35-70mm F4 or Other Lens",
  },
  SonyLensType {
    id: 2552,
    name: "Minolta AF 28-85mm F3.5-4.5 or Other Lens",
  },
  SonyLensType {
    id: 2553,
    name: "Minolta AF 28-135mm F4-4.5 or Other Lens",
  },
  SonyLensType {
    id: 2554,
    name: "Minolta AF 35-105mm F3.5-4.5",
  },
  SonyLensType {
    id: 2555,
    name: "Minolta AF 70-210mm F4 Macro or Sigma Lens",
  },
  SonyLensType {
    id: 2556,
    name: "Minolta AF 135mm F2.8",
  },
  SonyLensType {
    id: 2557,
    name: "Minolta/Sony AF 28mm F2.8",
  },
  SonyLensType {
    id: 2558,
    name: "Minolta AF 24-50mm F4",
  },
  SonyLensType {
    id: 2560,
    name: "Minolta AF 100-200mm F4.5",
  },
  SonyLensType {
    id: 2561,
    name: "Minolta AF 75-300mm F4.5-5.6 or Sigma Lens",
  },
  SonyLensType {
    id: 2562,
    name: "Minolta AF 50mm F1.4 [New]",
  },
  SonyLensType {
    id: 2563,
    name: "Minolta AF 300mm F2.8 APO or Sigma Lens",
  },
  SonyLensType {
    id: 2564,
    name: "Minolta AF 50mm F2.8 Macro or Sigma Lens",
  },
  SonyLensType {
    id: 2565,
    name: "Minolta AF 600mm F4 APO",
  },
  SonyLensType {
    id: 2566,
    name: "Minolta AF 24mm F2.8 or Sigma Lens",
  },
  SonyLensType {
    id: 2572,
    name: "Minolta/Sony AF 500mm F8 Reflex",
  },
  SonyLensType {
    id: 2578,
    name: "Minolta/Sony AF 16mm F2.8 Fisheye or Sigma Lens",
  },
  SonyLensType {
    id: 2579,
    name: "Minolta/Sony AF 20mm F2.8 or Tokina Lens",
  },
  SonyLensType {
    id: 2581,
    name: "Minolta AF 100mm F2.8 Macro [New] or Sigma or Tamron Lens",
  },
  SonyLensType {
    id: 2585,
    name: "Minolta AF 35-105mm F3.5-4.5 New or Tamron Lens",
  },
  SonyLensType {
    id: 2588,
    name: "Minolta AF 70-210mm F3.5-4.5",
  },
  SonyLensType {
    id: 2589,
    name: "Minolta AF 80-200mm F2.8 APO or Tokina Lens",
  },
  SonyLensType {
    id: 2590,
    name: "Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO or Other Lens + 1.4x",
  },
  SonyLensType {
    id: 2591,
    name: "Minolta AF 35mm F1.4",
  },
  SonyLensType {
    id: 2592,
    name: "Minolta AF 85mm F1.4 G (D)",
  },
  SonyLensType {
    id: 2593,
    name: "Minolta AF 200mm F2.8 APO",
  },
  SonyLensType {
    id: 2594,
    name: "Minolta AF 3x-1x F1.7-2.8 Macro",
  },
  SonyLensType {
    id: 2596,
    name: "Minolta AF 28mm F2",
  },
  SonyLensType {
    id: 2597,
    name: "Minolta AF 35mm F2 [New]",
  },
  SonyLensType {
    id: 2598,
    name: "Minolta AF 100mm F2",
  },
  SonyLensType {
    id: 2601,
    name: "Minolta AF 200mm F2.8 G APO + Minolta AF 2x APO or Other Lens + 2x",
  },
  SonyLensType {
    id: 2604,
    name: "Minolta AF 80-200mm F4.5-5.6",
  },
  SonyLensType {
    id: 2605,
    name: "Minolta AF 35-80mm F4-5.6",
  },
  SonyLensType {
    id: 2606,
    name: "Minolta AF 100-300mm F4.5-5.6",
  },
  SonyLensType {
    id: 2607,
    name: "Minolta AF 35-80mm F4-5.6",
  },
  SonyLensType {
    id: 2608,
    name: "Minolta AF 300mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 2609,
    name: "Minolta AF 600mm F4 HS-APO G",
  },
  SonyLensType {
    id: 2612,
    name: "Minolta AF 200mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 2613,
    name: "Minolta AF 50mm F1.7 New",
  },
  SonyLensType {
    id: 2615,
    name: "Minolta AF 28-105mm F3.5-4.5 xi",
  },
  SonyLensType {
    id: 2616,
    name: "Minolta AF 35-200mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 2618,
    name: "Minolta AF 28-80mm F4-5.6 xi",
  },
  SonyLensType {
    id: 2619,
    name: "Minolta AF 80-200mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 2620,
    name: "Minolta AF 28-70mm F2.8 G",
  },
  SonyLensType {
    id: 2621,
    name: "Minolta AF 100-300mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 2624,
    name: "Minolta AF 35-80mm F4-5.6 Power Zoom",
  },
  SonyLensType {
    id: 2628,
    name: "Minolta AF 80-200mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 2629,
    name: "Minolta AF 85mm F1.4 New",
  },
  SonyLensType {
    id: 2631,
    name: "Minolta AF 100-300mm F4.5-5.6 APO",
  },
  SonyLensType {
    id: 2632,
    name: "Minolta AF 24-50mm F4 New",
  },
  SonyLensType {
    id: 2638,
    name: "Minolta AF 50mm F2.8 Macro New",
  },
  SonyLensType {
    id: 2639,
    name: "Minolta AF 100mm F2.8 Macro",
  },
  SonyLensType {
    id: 2641,
    name: "Minolta/Sony AF 20mm F2.8 New",
  },
  SonyLensType {
    id: 2642,
    name: "Minolta AF 24mm F2.8 New",
  },
  SonyLensType {
    id: 2644,
    name: "Minolta AF 100-400mm F4.5-6.7 APO",
  },
  SonyLensType {
    id: 2662,
    name: "Minolta AF 50mm F1.4 New",
  },
  SonyLensType {
    id: 2667,
    name: "Minolta AF 35mm F2 New",
  },
  SonyLensType {
    id: 2668,
    name: "Minolta AF 28mm F2 New",
  },
  SonyLensType {
    id: 2672,
    name: "Minolta AF 24-105mm F3.5-4.5 (D)",
  },
  SonyLensType {
    id: 3046,
    name: "Metabones Canon EF Speed Booster",
  },
  SonyLensType {
    id: 4567,
    name: "Tokina 70-210mm F4-5.6",
  },
  SonyLensType {
    id: 4568,
    name: "Tokina AF 35-200mm F4-5.6 Zoom SD",
  },
  SonyLensType {
    id: 4570,
    name: "Tamron AF 35-135mm F3.5-4.5",
  },
  SonyLensType {
    id: 4571,
    name: "Vivitar 70-210mm F4.5-5.6",
  },
  SonyLensType {
    id: 4574,
    name: "2x Teleconverter or Tamron or Tokina Lens",
  },
  SonyLensType {
    id: 4575,
    name: "1.4x Teleconverter",
  },
  SonyLensType {
    id: 4585,
    name: "Tamron SP AF 300mm F2.8 LD IF",
  },
  SonyLensType {
    id: 4586,
    name: "Tamron SP AF 35-105mm F2.8 LD Aspherical IF",
  },
  SonyLensType {
    id: 4587,
    name: "Tamron AF 70-210mm F2.8 SP LD",
  },
  SonyLensType {
    id: 4812,
    name: "Metabones Canon EF Speed Booster Ultra",
  },
  SonyLensType {
    id: 6118,
    name: "Canon EF Adapter",
  },
  SonyLensType {
    id: 6528,
    name: "Sigma 16mm F2.8 Filtermatic Fisheye",
  },
  SonyLensType {
    id: 6553,
    name: "E-Mount, T-Mount, Other Lens or no lens",
  },
  SonyLensType {
    id: 18688,
    name: "Sigma MC-11 SA-E Mount Converter with not-supported Sigma lens",
  },
  SonyLensType {
    id: 25501,
    name: "Minolta AF 50mm F1.7",
  },
  SonyLensType {
    id: 25511,
    name: "Minolta AF 35-70mm F4 or Other Lens",
  },
  SonyLensType {
    id: 25521,
    name: "Minolta AF 28-85mm F3.5-4.5 or Other Lens",
  },
  SonyLensType {
    id: 25531,
    name: "Minolta AF 28-135mm F4-4.5 or Other Lens",
  },
  SonyLensType {
    id: 25541,
    name: "Minolta AF 35-105mm F3.5-4.5",
  },
  SonyLensType {
    id: 25551,
    name: "Minolta AF 70-210mm F4 Macro or Sigma Lens",
  },
  SonyLensType {
    id: 25561,
    name: "Minolta AF 135mm F2.8",
  },
  SonyLensType {
    id: 25571,
    name: "Minolta/Sony AF 28mm F2.8",
  },
  SonyLensType {
    id: 25581,
    name: "Minolta AF 24-50mm F4",
  },
  SonyLensType {
    id: 25601,
    name: "Minolta AF 100-200mm F4.5",
  },
  SonyLensType {
    id: 25611,
    name: "Minolta AF 75-300mm F4.5-5.6 or Sigma Lens",
  },
  SonyLensType {
    id: 25621,
    name: "Minolta AF 50mm F1.4 [New]",
  },
  SonyLensType {
    id: 25631,
    name: "Minolta AF 300mm F2.8 APO or Sigma Lens",
  },
  SonyLensType {
    id: 25641,
    name: "Minolta AF 50mm F2.8 Macro or Sigma Lens",
  },
  SonyLensType {
    id: 25651,
    name: "Minolta AF 600mm F4 APO",
  },
  SonyLensType {
    id: 25661,
    name: "Minolta AF 24mm F2.8 or Sigma Lens",
  },
  SonyLensType {
    id: 25721,
    name: "Minolta/Sony AF 500mm F8 Reflex",
  },
  SonyLensType {
    id: 25781,
    name: "Minolta/Sony AF 16mm F2.8 Fisheye or Sigma Lens",
  },
  SonyLensType {
    id: 25791,
    name: "Minolta/Sony AF 20mm F2.8 or Tokina Lens",
  },
  SonyLensType {
    id: 25811,
    name: "Minolta AF 100mm F2.8 Macro [New] or Sigma or Tamron Lens",
  },
  SonyLensType {
    id: 25851,
    name: "Beroflex 35-135mm F3.5-4.5",
  },
  SonyLensType {
    id: 25858,
    name: "Minolta AF 35-105mm F3.5-4.5 New or Tamron Lens",
  },
  SonyLensType {
    id: 25881,
    name: "Minolta AF 70-210mm F3.5-4.5",
  },
  SonyLensType {
    id: 25891,
    name: "Minolta AF 80-200mm F2.8 APO or Tokina Lens",
  },
  SonyLensType {
    id: 25901,
    name: "Minolta AF 200mm F2.8 G APO + Minolta AF 1.4x APO or Other Lens + 1.4x",
  },
  SonyLensType {
    id: 25911,
    name: "Minolta AF 35mm F1.4",
  },
  SonyLensType {
    id: 25921,
    name: "Minolta AF 85mm F1.4 G (D)",
  },
  SonyLensType {
    id: 25931,
    name: "Minolta AF 200mm F2.8 APO",
  },
  SonyLensType {
    id: 25941,
    name: "Minolta AF 3x-1x F1.7-2.8 Macro",
  },
  SonyLensType {
    id: 25961,
    name: "Minolta AF 28mm F2",
  },
  SonyLensType {
    id: 25971,
    name: "Minolta AF 35mm F2 [New]",
  },
  SonyLensType {
    id: 25981,
    name: "Minolta AF 100mm F2",
  },
  SonyLensType {
    id: 26011,
    name: "Minolta AF 200mm F2.8 G APO + Minolta AF 2x APO or Other Lens + 2x",
  },
  SonyLensType {
    id: 26041,
    name: "Minolta AF 80-200mm F4.5-5.6",
  },
  SonyLensType {
    id: 26051,
    name: "Minolta AF 35-80mm F4-5.6",
  },
  SonyLensType {
    id: 26061,
    name: "Minolta AF 100-300mm F4.5-5.6",
  },
  SonyLensType {
    id: 26071,
    name: "Minolta AF 35-80mm F4-5.6",
  },
  SonyLensType {
    id: 26081,
    name: "Minolta AF 300mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 26091,
    name: "Minolta AF 600mm F4 HS-APO G",
  },
  SonyLensType {
    id: 26121,
    name: "Minolta AF 200mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 26131,
    name: "Minolta AF 50mm F1.7 New",
  },
  SonyLensType {
    id: 26151,
    name: "Minolta AF 28-105mm F3.5-4.5 xi",
  },
  SonyLensType {
    id: 26161,
    name: "Minolta AF 35-200mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 26181,
    name: "Minolta AF 28-80mm F4-5.6 xi",
  },
  SonyLensType {
    id: 26191,
    name: "Minolta AF 80-200mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 26201,
    name: "Minolta AF 28-70mm F2.8 G",
  },
  SonyLensType {
    id: 26211,
    name: "Minolta AF 100-300mm F4.5-5.6 xi",
  },
  SonyLensType {
    id: 26241,
    name: "Minolta AF 35-80mm F4-5.6 Power Zoom",
  },
  SonyLensType {
    id: 26281,
    name: "Minolta AF 80-200mm F2.8 HS-APO G",
  },
  SonyLensType {
    id: 26291,
    name: "Minolta AF 85mm F1.4 New",
  },
  SonyLensType {
    id: 26311,
    name: "Minolta AF 100-300mm F4.5-5.6 APO",
  },
  SonyLensType {
    id: 26321,
    name: "Minolta AF 24-50mm F4 New",
  },
  SonyLensType {
    id: 26381,
    name: "Minolta AF 50mm F2.8 Macro New",
  },
  SonyLensType {
    id: 26391,
    name: "Minolta AF 100mm F2.8 Macro",
  },
  SonyLensType {
    id: 26411,
    name: "Minolta/Sony AF 20mm F2.8 New",
  },
  SonyLensType {
    id: 26421,
    name: "Minolta AF 24mm F2.8 New",
  },
  SonyLensType {
    id: 26441,
    name: "Minolta AF 100-400mm F4.5-6.7 APO",
  },
  SonyLensType {
    id: 26621,
    name: "Minolta AF 50mm F1.4 New",
  },
  SonyLensType {
    id: 26671,
    name: "Minolta AF 35mm F2 New",
  },
  SonyLensType {
    id: 26681,
    name: "Minolta AF 28mm F2 New",
  },
  SonyLensType {
    id: 26721,
    name: "Minolta AF 24-105mm F3.5-4.5 (D)",
  },
  SonyLensType {
    id: 30464,
    name: "Metabones Canon EF Speed Booster",
  },
  SonyLensType {
    id: 45671,
    name: "Tokina 70-210mm F4-5.6",
  },
  SonyLensType {
    id: 45681,
    name: "Tokina AF 35-200mm F4-5.6 Zoom SD",
  },
  SonyLensType {
    id: 45701,
    name: "Tamron AF 35-135mm F3.5-4.5",
  },
  SonyLensType {
    id: 45711,
    name: "Vivitar 70-210mm F4.5-5.6",
  },
  SonyLensType {
    id: 45741,
    name: "2x Teleconverter or Tamron or Tokina Lens",
  },
  SonyLensType {
    id: 45751,
    name: "1.4x Teleconverter",
  },
  SonyLensType {
    id: 45851,
    name: "Tamron SP AF 300mm F2.8 LD IF",
  },
  SonyLensType {
    id: 45861,
    name: "Tamron SP AF 35-105mm F2.8 LD Aspherical IF",
  },
  SonyLensType {
    id: 45871,
    name: "Tamron AF 70-210mm F2.8 SP LD",
  },
  SonyLensType {
    id: 48128,
    name: "Metabones Canon EF Speed Booster Ultra",
  },
  SonyLensType {
    id: 61184,
    name: "Canon EF Adapter",
  },
  SonyLensType {
    id: 65280,
    name: "Sigma 16mm F2.8 Filtermatic Fisheye",
  },
  SonyLensType {
    id: 65535,
    name: "E-Mount, T-Mount, Other Lens or no lens",
  },
];

/// Binary-search the A-mount table by lens-type ID, returning the bundled
/// lens name (`%sonyLensTypes` value) when present.
#[must_use]
pub fn lookup_name(id: u32) -> Option<SmolStr> {
  match SONY_LENS_TYPES_AMOUNT.binary_search_by_key(&id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => SONY_LENS_TYPES_AMOUNT.get(i).map(|t| SmolStr::from(t.name)),
    Err(_) => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn table_sorted_for_binary_search() {
    let mut prev: i64 = -1;
    for t in SONY_LENS_TYPES_AMOUNT {
      assert!(
        i64::from(t.id) > prev,
        "SONY_LENS_TYPES_AMOUNT not strictly sorted: {} after {prev}",
        t.id
      );
      prev = i64::from(t.id);
    }
  }

  #[test]
  fn has_242_rows() {
    assert_eq!(SONY_LENS_TYPES_AMOUNT.len(), 242);
  }

  /// 65535 is the E-mount sentinel (`Minolta.pm:545`) — NOT an E-mount lens
  /// name (which would come from `%sonyLensTypes2`).
  #[test]
  fn e_mount_sentinel_65535() {
    assert_eq!(
      lookup_name(65535).as_deref(),
      Some("E-Mount, T-Mount, Other Lens or no lens")
    );
  }

  /// A representative A-mount (Minolta-derived) ID resolves to the
  /// Minolta-backed name, distinct from the E-mount table's entry for the
  /// same ID.
  #[test]
  fn amount_id_zero_is_minolta_not_emount() {
    assert_eq!(
      lookup_name(0).as_deref(),
      Some("Minolta AF 28-85mm F3.5-4.5 New")
    );
  }

  #[test]
  fn unmatched_id_is_none() {
    // 60000 is not a key — caller renders the standard `Unknown (N)`.
    assert!(lookup_name(60000).is_none());
  }
}
