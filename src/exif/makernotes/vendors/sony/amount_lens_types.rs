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
//! The FLOAT-keyed disambiguation entries (e.g. `7.1`, `129.2`, `65535.1`):
//! secondary names appended after the primary when several lenses share an ID,
//! keyed by the integer ID plus the fractional suffix taken as an integer
//! "variant". They live in [`SONY_LENS_VARIANTS_AMOUNT`] / [`lens_variants`];
//! `PrintLensID` (`Exif.pm:5881`) consumes them via
//! [`super::lens_info::get_lens_info`] over `LensSpec`. That wiring lands in a
//! later chunk, so the variant table is inert here.
//!
//! ## Deferred (faithful gaps, documented)
//!
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

/// One FLOAT-keyed disambiguation entry of the A-mount `%sonyLensTypes` — a
/// secondary lens name `PrintLensID` considers after the primary
/// [`SonyLensType`] when several lenses share the integer `id`.
#[derive(Debug, Clone, Copy)]
pub struct SonyLensVariant {
  /// The integer part of the bundled float key (the shared lens-type ID).
  pub id: u32,
  /// The fractional suffix taken as an integer (`129.2` → 2, `128.27` → 27).
  /// `PrintLensID` scans `id.1`, `id.2`, … in ascending order.
  pub variant: u8,
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

/// FLOAT-keyed disambiguation entries of the A-mount `%sonyLensTypes`, sorted
/// by `(id, variant)`. Each shares its `id` with a primary
/// [`SONY_LENS_TYPES_AMOUNT`] row; `PrintLensID` appends [`lens_variants`]`(id)`
/// after that primary. Inert until the `PrintLensID` wiring lands.
pub const SONY_LENS_VARIANTS_AMOUNT: &[SonyLensVariant] = &[
  SonyLensVariant {
    id: 7,
    variant: 1,
    name: "Minolta AF 100-400mm F4.5-6.7 APO",
  },
  SonyLensVariant {
    id: 7,
    variant: 2,
    name: "Sigma AF 100-300mm F4 EX DG IF",
  },
  SonyLensVariant {
    id: 24,
    variant: 1,
    name: "Sigma 18-50mm F2.8",
  },
  SonyLensVariant {
    id: 24,
    variant: 2,
    name: "Sigma 17-70mm F2.8-4.5 DC Macro",
  },
  SonyLensVariant {
    id: 24,
    variant: 3,
    name: "Sigma 20-40mm F2.8 EX DG Aspherical IF",
  },
  SonyLensVariant {
    id: 24,
    variant: 4,
    name: "Sigma 18-200mm F3.5-6.3 DC",
  },
  SonyLensVariant {
    id: 24,
    variant: 5,
    name: "Sigma DC 18-125mm F4-5,6 D",
  },
  SonyLensVariant {
    id: 24,
    variant: 6,
    name: "Tamron SP AF 28-75mm F2.8 XR Di LD Aspherical [IF] Macro",
  },
  SonyLensVariant {
    id: 24,
    variant: 7,
    name: "Sigma 15-30mm F3.5-4.5 EX DG Aspherical",
  },
  SonyLensVariant {
    id: 25,
    variant: 1,
    name: "Sigma 100-300mm F4 EX (APO (D) or D IF)",
  },
  SonyLensVariant {
    id: 25,
    variant: 2,
    name: "Sigma 70mm F2.8 EX DG Macro",
  },
  SonyLensVariant {
    id: 25,
    variant: 3,
    name: "Sigma 20mm F1.8 EX DG Aspherical RF",
  },
  SonyLensVariant {
    id: 25,
    variant: 4,
    name: "Sigma 30mm F1.4 EX DC",
  },
  SonyLensVariant {
    id: 25,
    variant: 5,
    name: "Sigma 24mm F1.8 EX DG ASP Macro",
  },
  SonyLensVariant {
    id: 28,
    variant: 1,
    name: "Tamron SP AF 90mm F2.8 Di Macro",
  },
  SonyLensVariant {
    id: 28,
    variant: 2,
    name: "Tamron SP AF 180mm F3.5 Di LD [IF] Macro",
  },
  SonyLensVariant {
    id: 30,
    variant: 1,
    name: "Sigma AF 10-20mm F4-5.6 EX DC",
  },
  SonyLensVariant {
    id: 30,
    variant: 2,
    name: "Sigma AF 12-24mm F4.5-5.6 EX DG",
  },
  SonyLensVariant {
    id: 30,
    variant: 3,
    name: "Sigma 28-70mm EX DG F2.8",
  },
  SonyLensVariant {
    id: 30,
    variant: 4,
    name: "Sigma 55-200mm F4-5.6 DC",
  },
  SonyLensVariant {
    id: 31,
    variant: 1,
    name: "Minolta/Sony AF 50mm F3.5 Macro",
  },
  SonyLensVariant {
    id: 41,
    variant: 1,
    name: "Tamron SP AF 11-18mm F4.5-5.6 Di II LD Aspherical IF",
  },
  SonyLensVariant {
    id: 48,
    variant: 1,
    name: "Carl Zeiss Vario-Sonnar T* 24-70mm F2.8 ZA SSM II (SAL2470Z2)",
  },
  SonyLensVariant {
    id: 48,
    variant: 2,
    name: "Tamron SP 24-70mm F2.8 Di USD",
  },
  SonyLensVariant {
    id: 52,
    variant: 1,
    name: "Sony 70-300mm F4.5-5.6 G SSM II (SAL70300G2)",
  },
  SonyLensVariant {
    id: 52,
    variant: 2,
    name: "Tamron SP 70-300mm F4-5.6 Di USD",
  },
  SonyLensVariant {
    id: 54,
    variant: 1,
    name: "Carl Zeiss Vario-Sonnar T* 16-35mm F2.8 ZA SSM II (SAL1635Z2)",
  },
  SonyLensVariant {
    id: 55,
    variant: 1,
    name: "Sony DT 18-55mm F3.5-5.6 SAM II (SAL18552)",
  },
  SonyLensVariant {
    id: 57,
    variant: 1,
    name: "Tamron SP AF 60mm F2 Di II LD [IF] Macro 1:1",
  },
  SonyLensVariant {
    id: 57,
    variant: 2,
    name: "Tamron 18-270mm F3.5-6.3 Di II PZD",
  },
  SonyLensVariant {
    id: 128,
    variant: 1,
    name: "Tamron AF 18-200mm F3.5-6.3 XR Di II LD Aspherical [IF] Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 2,
    name: "Tamron AF 28-300mm F3.5-6.3 XR Di LD Aspherical [IF] Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 3,
    name: "Tamron AF 28-200mm F3.8-5.6 XR Di Aspherical [IF] Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 4,
    name: "Tamron SP AF 17-35mm F2.8-4 Di LD Aspherical IF",
  },
  SonyLensVariant {
    id: 128,
    variant: 5,
    name: "Sigma AF 50-150mm F2.8 EX DC APO HSM II",
  },
  SonyLensVariant {
    id: 128,
    variant: 6,
    name: "Sigma 10-20mm F3.5 EX DC HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 7,
    name: "Sigma 70-200mm F2.8 II EX DG APO MACRO HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 8,
    name: "Sigma 10mm F2.8 EX DC HSM Fisheye",
  },
  SonyLensVariant {
    id: 128,
    variant: 9,
    name: "Sigma 50mm F1.4 EX DG HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 10,
    name: "Sigma 85mm F1.4 EX DG HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 11,
    name: "Sigma 24-70mm F2.8 IF EX DG HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 12,
    name: "Sigma 18-250mm F3.5-6.3 DC OS HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 13,
    name: "Sigma 17-50mm F2.8 EX DC HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 14,
    name: "Sigma 17-70mm F2.8-4 DC Macro HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 15,
    name: "Sigma 150mm F2.8 EX DG OS HSM APO Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 16,
    name: "Sigma 150-500mm F5-6.3 APO DG OS HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 17,
    name: "Tamron AF 28-105mm F4-5.6 [IF]",
  },
  SonyLensVariant {
    id: 128,
    variant: 18,
    name: "Sigma 35mm F1.4 DG HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 19,
    name: "Sigma 18-35mm F1.8 DC HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 20,
    name: "Sigma 50-500mm F4.5-6.3 APO DG OS HSM",
  },
  SonyLensVariant {
    id: 128,
    variant: 21,
    name: "Sigma 24-105mm F4 DG HSM | A",
  },
  SonyLensVariant {
    id: 128,
    variant: 22,
    name: "Sigma 30mm F1.4",
  },
  SonyLensVariant {
    id: 128,
    variant: 23,
    name: "Sigma 35mm F1.4 DG HSM | A",
  },
  SonyLensVariant {
    id: 128,
    variant: 24,
    name: "Sigma 105mm F2.8 EX DG OS HSM Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 25,
    name: "Sigma 180mm F2.8 EX DG OS HSM APO Macro",
  },
  SonyLensVariant {
    id: 128,
    variant: 26,
    name: "Sigma 18-300mm F3.5-6.3 DC Macro HSM | C",
  },
  SonyLensVariant {
    id: 128,
    variant: 27,
    name: "Sigma 18-50mm F2.8-4.5 DC HSM",
  },
  SonyLensVariant {
    id: 129,
    variant: 1,
    name: "Tamron 200-400mm F5.6 LD",
  },
  SonyLensVariant {
    id: 129,
    variant: 2,
    name: "Tamron 70-300mm F4-5.6 LD",
  },
  SonyLensVariant {
    id: 255,
    variant: 1,
    name: "Tamron SP AF 17-50mm F2.8 XR Di II LD Aspherical",
  },
  SonyLensVariant {
    id: 255,
    variant: 2,
    name: "Tamron AF 18-250mm F3.5-6.3 XR Di II LD",
  },
  SonyLensVariant {
    id: 255,
    variant: 3,
    name: "Tamron AF 55-200mm F4-5.6 Di II LD Macro",
  },
  SonyLensVariant {
    id: 255,
    variant: 4,
    name: "Tamron AF 70-300mm F4-5.6 Di LD Macro 1:2",
  },
  SonyLensVariant {
    id: 255,
    variant: 5,
    name: "Tamron SP AF 200-500mm F5.0-6.3 Di LD IF",
  },
  SonyLensVariant {
    id: 255,
    variant: 6,
    name: "Tamron SP AF 10-24mm F3.5-4.5 Di II LD Aspherical IF",
  },
  SonyLensVariant {
    id: 255,
    variant: 7,
    name: "Tamron SP AF 70-200mm F2.8 Di LD IF Macro",
  },
  SonyLensVariant {
    id: 255,
    variant: 8,
    name: "Tamron SP AF 28-75mm F2.8 XR Di LD Aspherical IF",
  },
  SonyLensVariant {
    id: 255,
    variant: 9,
    name: "Tamron AF 90-300mm F4.5-5.6 Telemacro",
  },
  SonyLensVariant {
    id: 2551,
    variant: 1,
    name: "Sigma UC AF 28-70mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 2551,
    variant: 2,
    name: "Sigma AF 28-70mm F2.8",
  },
  SonyLensVariant {
    id: 2551,
    variant: 3,
    name: "Sigma M-AF 70-200mm F2.8 EX Aspherical",
  },
  SonyLensVariant {
    id: 2551,
    variant: 4,
    name: "Quantaray M-AF 35-80mm F4-5.6",
  },
  SonyLensVariant {
    id: 2551,
    variant: 5,
    name: "Tokina 28-70mm F2.8-4.5 AF",
  },
  SonyLensVariant {
    id: 2552,
    variant: 1,
    name: "Tokina 19-35mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 2552,
    variant: 2,
    name: "Tokina 28-70mm F2.8 AT-X",
  },
  SonyLensVariant {
    id: 2552,
    variant: 3,
    name: "Tokina 80-400mm F4.5-5.6 AT-X AF II 840",
  },
  SonyLensVariant {
    id: 2552,
    variant: 4,
    name: "Tokina AF PRO 28-80mm F2.8 AT-X 280",
  },
  SonyLensVariant {
    id: 2552,
    variant: 5,
    name: "Tokina AT-X PRO [II] AF 28-70mm F2.6-2.8 270",
  },
  SonyLensVariant {
    id: 2552,
    variant: 6,
    name: "Tamron AF 19-35mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 2552,
    variant: 7,
    name: "Angenieux AF 28-70mm F2.6",
  },
  SonyLensVariant {
    id: 2552,
    variant: 8,
    name: "Tokina AT-X 17 AF 17mm F3.5",
  },
  SonyLensVariant {
    id: 2552,
    variant: 9,
    name: "Tokina 20-35mm F3.5-4.5 II AF",
  },
  SonyLensVariant {
    id: 2553,
    variant: 1,
    name: "Sigma ZOOM-alpha 35-135mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 2553,
    variant: 2,
    name: "Sigma 28-105mm F2.8-4 Aspherical",
  },
  SonyLensVariant {
    id: 2553,
    variant: 3,
    name: "Sigma 28-105mm F4-5.6 UC",
  },
  SonyLensVariant {
    id: 2553,
    variant: 4,
    name: "Tokina AT-X 242 AF 24-200mm F3.5-5.6",
  },
  SonyLensVariant {
    id: 2555,
    variant: 1,
    name: "Sigma 70-210mm F4-5.6 APO",
  },
  SonyLensVariant {
    id: 2555,
    variant: 2,
    name: "Sigma M-AF 70-200mm F2.8 EX APO",
  },
  SonyLensVariant {
    id: 2555,
    variant: 3,
    name: "Sigma 75-200mm F2.8-3.5",
  },
  SonyLensVariant {
    id: 2561,
    variant: 1,
    name: "Sigma 70-300mm F4-5.6 DL Macro",
  },
  SonyLensVariant {
    id: 2561,
    variant: 2,
    name: "Sigma 300mm F4 APO Macro",
  },
  SonyLensVariant {
    id: 2561,
    variant: 3,
    name: "Sigma AF 500mm F4.5 APO",
  },
  SonyLensVariant {
    id: 2561,
    variant: 4,
    name: "Sigma AF 170-500mm F5-6.3 APO Aspherical",
  },
  SonyLensVariant {
    id: 2561,
    variant: 5,
    name: "Tokina AT-X AF 300mm F4",
  },
  SonyLensVariant {
    id: 2561,
    variant: 6,
    name: "Tokina AT-X AF 400mm F5.6 SD",
  },
  SonyLensVariant {
    id: 2561,
    variant: 7,
    name: "Tokina AF 730 II 75-300mm F4.5-5.6",
  },
  SonyLensVariant {
    id: 2561,
    variant: 8,
    name: "Sigma 800mm F5.6 APO",
  },
  SonyLensVariant {
    id: 2561,
    variant: 9,
    name: "Sigma AF 400mm F5.6 APO Macro",
  },
  SonyLensVariant {
    id: 2561,
    variant: 10,
    name: "Sigma 1000mm F8 APO",
  },
  SonyLensVariant {
    id: 2563,
    variant: 1,
    name: "Sigma AF 50-500mm F4-6.3 EX DG APO",
  },
  SonyLensVariant {
    id: 2563,
    variant: 2,
    name: "Sigma AF 170-500mm F5-6.3 APO Aspherical",
  },
  SonyLensVariant {
    id: 2563,
    variant: 3,
    name: "Sigma AF 500mm F4.5 EX DG APO",
  },
  SonyLensVariant {
    id: 2563,
    variant: 4,
    name: "Sigma 400mm F5.6 APO",
  },
  SonyLensVariant {
    id: 2564,
    variant: 1,
    name: "Sigma 50mm F2.8 EX Macro",
  },
  SonyLensVariant {
    id: 2566,
    variant: 1,
    name: "Sigma 17-35mm F2.8-4 EX Aspherical",
  },
  SonyLensVariant {
    id: 2578,
    variant: 1,
    name: "Sigma 8mm F4 EX [DG] Fisheye",
  },
  SonyLensVariant {
    id: 2578,
    variant: 2,
    name: "Sigma 14mm F3.5",
  },
  SonyLensVariant {
    id: 2578,
    variant: 3,
    name: "Sigma 15mm F2.8 Fisheye",
  },
  SonyLensVariant {
    id: 2579,
    variant: 1,
    name: "Tokina AT-X Pro DX 11-16mm F2.8",
  },
  SonyLensVariant {
    id: 2581,
    variant: 1,
    name: "Sigma AF 90mm F2.8 Macro",
  },
  SonyLensVariant {
    id: 2581,
    variant: 2,
    name: "Sigma AF 105mm F2.8 EX [DG] Macro",
  },
  SonyLensVariant {
    id: 2581,
    variant: 3,
    name: "Sigma 180mm F5.6 Macro",
  },
  SonyLensVariant {
    id: 2581,
    variant: 4,
    name: "Sigma 180mm F3.5 EX DG Macro",
  },
  SonyLensVariant {
    id: 2581,
    variant: 5,
    name: "Tamron 90mm F2.8 Macro",
  },
  SonyLensVariant {
    id: 2585,
    variant: 1,
    name: "Beroflex 35-135mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 2585,
    variant: 2,
    name: "Tamron 24-135mm F3.5-5.6",
  },
  SonyLensVariant {
    id: 2589,
    variant: 1,
    name: "Tokina 80-200mm F2.8",
  },
  SonyLensVariant {
    id: 2590,
    variant: 1,
    name: "Minolta AF 600mm F4 HS-APO G + Minolta AF 1.4x APO",
  },
  SonyLensVariant {
    id: 2601,
    variant: 1,
    name: "Minolta AF 600mm F4 HS-APO G + Minolta AF 2x APO",
  },
  SonyLensVariant {
    id: 4574,
    variant: 1,
    name: "Tamron SP AF 90mm F2.5",
  },
  SonyLensVariant {
    id: 4574,
    variant: 2,
    name: "Tokina RF 500mm F8.0 x2",
  },
  SonyLensVariant {
    id: 4574,
    variant: 3,
    name: "Tokina 300mm F2.8 x2",
  },
  SonyLensVariant {
    id: 6553,
    variant: 1,
    name: "Arax MC 35mm F2.8 Tilt+Shift",
  },
  SonyLensVariant {
    id: 6553,
    variant: 2,
    name: "Arax MC 80mm F2.8 Tilt+Shift",
  },
  SonyLensVariant {
    id: 6553,
    variant: 3,
    name: "Zenitar MF 16mm F2.8 Fisheye M42",
  },
  SonyLensVariant {
    id: 6553,
    variant: 4,
    name: "Samyang 500mm Mirror F8.0",
  },
  SonyLensVariant {
    id: 6553,
    variant: 5,
    name: "Pentacon Auto 135mm F2.8",
  },
  SonyLensVariant {
    id: 6553,
    variant: 6,
    name: "Pentacon Auto 29mm F2.8",
  },
  SonyLensVariant {
    id: 6553,
    variant: 7,
    name: "Helios 44-2 58mm F2.0",
  },
  SonyLensVariant {
    id: 25511,
    variant: 1,
    name: "Sigma UC AF 28-70mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 25511,
    variant: 2,
    name: "Sigma AF 28-70mm F2.8",
  },
  SonyLensVariant {
    id: 25511,
    variant: 3,
    name: "Sigma M-AF 70-200mm F2.8 EX Aspherical",
  },
  SonyLensVariant {
    id: 25511,
    variant: 4,
    name: "Quantaray M-AF 35-80mm F4-5.6",
  },
  SonyLensVariant {
    id: 25511,
    variant: 5,
    name: "Tokina 28-70mm F2.8-4.5 AF",
  },
  SonyLensVariant {
    id: 25521,
    variant: 1,
    name: "Tokina 19-35mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 25521,
    variant: 2,
    name: "Tokina 28-70mm F2.8 AT-X",
  },
  SonyLensVariant {
    id: 25521,
    variant: 3,
    name: "Tokina 80-400mm F4.5-5.6 AT-X AF II 840",
  },
  SonyLensVariant {
    id: 25521,
    variant: 4,
    name: "Tokina AF PRO 28-80mm F2.8 AT-X 280",
  },
  SonyLensVariant {
    id: 25521,
    variant: 5,
    name: "Tokina AT-X PRO [II] AF 28-70mm F2.6-2.8 270",
  },
  SonyLensVariant {
    id: 25521,
    variant: 6,
    name: "Tamron AF 19-35mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 25521,
    variant: 7,
    name: "Angenieux AF 28-70mm F2.6",
  },
  SonyLensVariant {
    id: 25521,
    variant: 8,
    name: "Tokina AT-X 17 AF 17mm F3.5",
  },
  SonyLensVariant {
    id: 25521,
    variant: 9,
    name: "Tokina 20-35mm F3.5-4.5 II AF",
  },
  SonyLensVariant {
    id: 25531,
    variant: 1,
    name: "Sigma ZOOM-alpha 35-135mm F3.5-4.5",
  },
  SonyLensVariant {
    id: 25531,
    variant: 2,
    name: "Sigma 28-105mm F2.8-4 Aspherical",
  },
  SonyLensVariant {
    id: 25531,
    variant: 3,
    name: "Sigma 28-105mm F4-5.6 UC",
  },
  SonyLensVariant {
    id: 25531,
    variant: 4,
    name: "Tokina AT-X 242 AF 24-200mm F3.5-5.6",
  },
  SonyLensVariant {
    id: 25551,
    variant: 1,
    name: "Sigma 70-210mm F4-5.6 APO",
  },
  SonyLensVariant {
    id: 25551,
    variant: 2,
    name: "Sigma M-AF 70-200mm F2.8 EX APO",
  },
  SonyLensVariant {
    id: 25551,
    variant: 3,
    name: "Sigma 75-200mm F2.8-3.5",
  },
  SonyLensVariant {
    id: 25611,
    variant: 1,
    name: "Sigma 70-300mm F4-5.6 DL Macro",
  },
  SonyLensVariant {
    id: 25611,
    variant: 2,
    name: "Sigma 300mm F4 APO Macro",
  },
  SonyLensVariant {
    id: 25611,
    variant: 3,
    name: "Sigma AF 500mm F4.5 APO",
  },
  SonyLensVariant {
    id: 25611,
    variant: 4,
    name: "Sigma AF 170-500mm F5-6.3 APO Aspherical",
  },
  SonyLensVariant {
    id: 25611,
    variant: 5,
    name: "Tokina AT-X AF 300mm F4",
  },
  SonyLensVariant {
    id: 25611,
    variant: 6,
    name: "Tokina AT-X AF 400mm F5.6 SD",
  },
  SonyLensVariant {
    id: 25611,
    variant: 7,
    name: "Tokina AF 730 II 75-300mm F4.5-5.6",
  },
  SonyLensVariant {
    id: 25611,
    variant: 8,
    name: "Sigma 800mm F5.6 APO",
  },
  SonyLensVariant {
    id: 25611,
    variant: 9,
    name: "Sigma AF 400mm F5.6 APO Macro",
  },
  SonyLensVariant {
    id: 25611,
    variant: 10,
    name: "Sigma 1000mm F8 APO",
  },
  SonyLensVariant {
    id: 25631,
    variant: 1,
    name: "Sigma AF 50-500mm F4-6.3 EX DG APO",
  },
  SonyLensVariant {
    id: 25631,
    variant: 2,
    name: "Sigma AF 170-500mm F5-6.3 APO Aspherical",
  },
  SonyLensVariant {
    id: 25631,
    variant: 3,
    name: "Sigma AF 500mm F4.5 EX DG APO",
  },
  SonyLensVariant {
    id: 25631,
    variant: 4,
    name: "Sigma 400mm F5.6 APO",
  },
  SonyLensVariant {
    id: 25641,
    variant: 1,
    name: "Sigma 50mm F2.8 EX Macro",
  },
  SonyLensVariant {
    id: 25661,
    variant: 1,
    name: "Sigma 17-35mm F2.8-4 EX Aspherical",
  },
  SonyLensVariant {
    id: 25781,
    variant: 1,
    name: "Sigma 8mm F4 EX [DG] Fisheye",
  },
  SonyLensVariant {
    id: 25781,
    variant: 2,
    name: "Sigma 14mm F3.5",
  },
  SonyLensVariant {
    id: 25781,
    variant: 3,
    name: "Sigma 15mm F2.8 Fisheye",
  },
  SonyLensVariant {
    id: 25791,
    variant: 1,
    name: "Tokina AT-X Pro DX 11-16mm F2.8",
  },
  SonyLensVariant {
    id: 25811,
    variant: 1,
    name: "Sigma AF 90mm F2.8 Macro",
  },
  SonyLensVariant {
    id: 25811,
    variant: 2,
    name: "Sigma AF 105mm F2.8 EX [DG] Macro",
  },
  SonyLensVariant {
    id: 25811,
    variant: 3,
    name: "Sigma 180mm F5.6 Macro",
  },
  SonyLensVariant {
    id: 25811,
    variant: 4,
    name: "Sigma 180mm F3.5 EX DG Macro",
  },
  SonyLensVariant {
    id: 25811,
    variant: 5,
    name: "Tamron 90mm F2.8 Macro",
  },
  SonyLensVariant {
    id: 25858,
    variant: 1,
    name: "Tamron 24-135mm F3.5-5.6",
  },
  SonyLensVariant {
    id: 25891,
    variant: 1,
    name: "Tokina 80-200mm F2.8",
  },
  SonyLensVariant {
    id: 25901,
    variant: 1,
    name: "Minolta AF 600mm F4 HS-APO G + Minolta AF 1.4x APO",
  },
  SonyLensVariant {
    id: 26011,
    variant: 1,
    name: "Minolta AF 600mm F4 HS-APO G + Minolta AF 2x APO",
  },
  SonyLensVariant {
    id: 45741,
    variant: 1,
    name: "Tamron SP AF 90mm F2.5",
  },
  SonyLensVariant {
    id: 45741,
    variant: 2,
    name: "Tokina RF 500mm F8.0 x2",
  },
  SonyLensVariant {
    id: 45741,
    variant: 3,
    name: "Tokina 300mm F2.8 x2",
  },
  SonyLensVariant {
    id: 65535,
    variant: 1,
    name: "Arax MC 35mm F2.8 Tilt+Shift",
  },
  SonyLensVariant {
    id: 65535,
    variant: 2,
    name: "Arax MC 80mm F2.8 Tilt+Shift",
  },
  SonyLensVariant {
    id: 65535,
    variant: 3,
    name: "Zenitar MF 16mm F2.8 Fisheye M42",
  },
  SonyLensVariant {
    id: 65535,
    variant: 4,
    name: "Samyang 500mm Mirror F8.0",
  },
  SonyLensVariant {
    id: 65535,
    variant: 5,
    name: "Pentacon Auto 135mm F2.8",
  },
  SonyLensVariant {
    id: 65535,
    variant: 6,
    name: "Pentacon Auto 29mm F2.8",
  },
  SonyLensVariant {
    id: 65535,
    variant: 7,
    name: "Helios 44-2 58mm F2.0",
  },
];

/// The `id.1`, `id.2`, … secondary names for `id`, in ascending `variant`
/// order — the order `PrintLensID` (`Exif.pm:5969`) scans them. Empty when
/// `id` has no float-keyed variants.
#[must_use]
pub fn lens_variants(id: u32) -> &'static [SonyLensVariant] {
  let lo = SONY_LENS_VARIANTS_AMOUNT.partition_point(|v| v.id < id);
  let hi = SONY_LENS_VARIANTS_AMOUNT.partition_point(|v| v.id <= id);
  // `partition_point` guarantees `lo <= hi <= len`, so the slice is in range.
  SONY_LENS_VARIANTS_AMOUNT.get(lo..hi).unwrap_or(&[])
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

  #[test]
  fn variants_sorted_and_contiguous_from_one() {
    // Sorted by `(id, variant)`; within an id the variants run `1..=N` with no
    // gap, because `PrintLensID` stops scanning at the first missing `id.i`.
    let mut prev_id: Option<u32> = None;
    let mut expect_var: u8 = 1;
    for v in SONY_LENS_VARIANTS_AMOUNT {
      if prev_id == Some(v.id) {
        assert_eq!(
          v.variant, expect_var,
          "non-contiguous variant for id {}",
          v.id
        );
        expect_var += 1;
      } else {
        if let Some(p) = prev_id {
          assert!(
            v.id > p,
            "SONY_LENS_VARIANTS_AMOUNT not sorted by id: {} after {p}",
            v.id
          );
        }
        assert_eq!(v.variant, 1, "first variant for id {} must be 1", v.id);
        expect_var = 2;
        prev_id = Some(v.id);
      }
    }
  }

  #[test]
  fn lens_variants_129_tamron_in_order() {
    let names: Vec<&str> = lens_variants(129).iter().map(|v| v.name).collect();
    assert_eq!(
      names,
      ["Tamron 200-400mm F5.6 LD", "Tamron 70-300mm F4-5.6 LD"]
    );
  }

  #[test]
  fn lens_variants_55_single() {
    let vs = lens_variants(55);
    assert_eq!(vs.len(), 1);
    assert_eq!(
      vs.first().map(|v| v.name),
      Some("Sony DT 18-55mm F3.5-5.6 SAM II (SAL18552)")
    );
  }

  #[test]
  fn lens_variants_128_has_twentyseven() {
    // The largest run in the table (Sigma/Tamron A-mount, `128.1`..`128.27`).
    assert_eq!(lens_variants(128).len(), 27);
  }

  #[test]
  fn lens_variants_absent_is_empty() {
    // 0 is a primary (Minolta AF 28-85mm) with no float entries; 999_999 unknown.
    assert!(lens_variants(0).is_empty());
    assert!(lens_variants(999_999).is_empty());
  }
}
