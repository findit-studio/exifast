// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony E-mount lens-type lookup table — `%sonyLensTypes2` (`Sony.pm:56-387`).
//!
//! [`SONY_LENS_TYPES`] holds the INTEGER keys — the primary lens name per ID.
//! These are the lens IDs used by `Sony::CameraSettings` and the AF-info
//! sub-tables, and back the `LensType` `PrintConv`.
//!
//! Bundled also carries FLOAT-keyed ambiguity entries (e.g. `0.1 => 'Sigma
//! 19mm F2.8 [EX] DN'`, `49473.1 => 'Tokina atx-m 85mm F1.8 FE'`): secondary
//! names appended after the primary when several lenses share an ID. They are
//! ported in [`SONY_LENS_VARIANTS`] / [`lens_variants`], keyed by the integer
//! ID plus the fractional suffix taken as an integer "variant" (`0.13` →
//! variant 13). `PrintLensID` (`Exif.pm:5881`) consumes them — together with
//! [`super::lens_info::get_lens_info`] over `LensSpec` — to pick the actual
//! lens. That wiring lands in a later chunk, so the variant table is inert
//! here.
//!
//! The A-mount (Minolta-backed) `%sonyLensTypes` is ported separately in
//! [`super::amount_lens_types`].

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of `%sonyLensTypes2`.
#[derive(Debug, Clone, Copy)]
pub struct SonyLensType {
  /// The integer lens-type ID (the key in bundled).
  pub id: u32,
  /// The lens model name.
  pub name: &'static str,
}

/// One FLOAT-keyed disambiguation entry of `%sonyLensTypes2` — a secondary
/// lens name `PrintLensID` considers after the primary [`SonyLensType`] when
/// several lenses share the integer `id`.
#[derive(Debug, Clone, Copy)]
pub struct SonyLensVariant {
  /// The integer part of the bundled float key (the shared lens-type ID).
  pub id: u32,
  /// The fractional suffix taken as an integer (`49473.1` → 1, `0.13` → 13).
  /// `PrintLensID` scans `id.1`, `id.2`, … in ascending order.
  pub variant: u8,
  /// The lens model name.
  pub name: &'static str,
}

/// `%sonyLensTypes2` — sorted by ID (binary-search-ready).
pub const SONY_LENS_TYPES: &[SonyLensType] = &[
  SonyLensType {
    id: 0,
    name: "Unknown E-mount lens or other lens",
  },
  SonyLensType {
    id: 1,
    name: "Sony LA-EA1 or Sigma MC-11 Adapter",
  },
  SonyLensType {
    id: 2,
    name: "Sony LA-EA2 Adapter",
  },
  SonyLensType {
    id: 3,
    name: "Sony LA-EA3 Adapter",
  },
  SonyLensType {
    id: 6,
    name: "Sony LA-EA4 Adapter",
  },
  SonyLensType {
    id: 7,
    name: "Sony LA-EA5 Adapter",
  },
  SonyLensType {
    id: 13,
    name: "Samyang AF 35-150mm F2-2.8",
  },
  SonyLensType {
    id: 17,
    name: "Samyang RS 21mm F3.5",
  },
  SonyLensType {
    id: 18,
    name: "Samyang RS 28mm F3.5",
  },
  SonyLensType {
    id: 19,
    name: "Samyang RS 32mm F2.8",
  },
  SonyLensType {
    id: 20,
    name: "Samyang AF 35mm F1.4 P FE",
  },
  SonyLensType {
    id: 21,
    name: "Samyang AF 14-24mm F2.8",
  },
  SonyLensType {
    id: 22,
    name: "Samyang AF 24-60mm F2.8",
  },
  SonyLensType {
    id: 24,
    name: "Samyang AF 85mm F1.8 P FE",
  },
  SonyLensType {
    id: 44,
    name: "Metabones Canon EF Smart Adapter",
  },
  SonyLensType {
    id: 78,
    name: "Metabones Canon EF Smart Adapter Mark III or Other Adapter",
  },
  SonyLensType {
    id: 184,
    name: "Metabones Canon EF Speed Booster Ultra",
  },
  SonyLensType {
    id: 234,
    name: "Metabones Canon EF Smart Adapter Mark IV",
  },
  SonyLensType {
    id: 239,
    name: "Metabones Canon EF Speed Booster",
  },
  SonyLensType {
    id: 24593,
    name: "LA-EA4r MonsterAdapter",
  },
  SonyLensType {
    id: 32784,
    name: "Sony E 16mm F2.8",
  },
  SonyLensType {
    id: 32785,
    name: "Sony E 18-55mm F3.5-5.6 OSS",
  },
  SonyLensType {
    id: 32786,
    name: "Sony E 55-210mm F4.5-6.3 OSS",
  },
  SonyLensType {
    id: 32787,
    name: "Sony E 18-200mm F3.5-6.3 OSS",
  },
  SonyLensType {
    id: 32788,
    name: "Sony E 30mm F3.5 Macro",
  },
  SonyLensType {
    id: 32789,
    name: "Sony E 24mm F1.8 ZA or Samyang AF 50mm F1.4",
  },
  SonyLensType {
    id: 32790,
    name: "Sony E 50mm F1.8 OSS or Samyang AF 14mm F2.8",
  },
  SonyLensType {
    id: 32791,
    name: "Sony E 16-70mm F4 ZA OSS",
  },
  SonyLensType {
    id: 32792,
    name: "Sony E 10-18mm F4 OSS",
  },
  SonyLensType {
    id: 32793,
    name: "Sony E PZ 16-50mm F3.5-5.6 OSS",
  },
  SonyLensType {
    id: 32794,
    name: "Sony FE 35mm F2.8 ZA or Samyang Lens",
  },
  SonyLensType {
    id: 32795,
    name: "Sony FE 24-70mm F4 ZA OSS",
  },
  SonyLensType {
    id: 32796,
    name: "Sony FE 85mm F1.8 or Viltrox PFU RBMH 85mm F1.8",
  },
  SonyLensType {
    id: 32797,
    name: "Sony E 18-200mm F3.5-6.3 OSS LE",
  },
  SonyLensType {
    id: 32798,
    name: "Sony E 20mm F2.8",
  },
  SonyLensType {
    id: 32799,
    name: "Sony E 35mm F1.8 OSS",
  },
  SonyLensType {
    id: 32800,
    name: "Sony E PZ 18-105mm F4 G OSS",
  },
  SonyLensType {
    id: 32801,
    name: "Sony FE 12-24mm F4 G",
  },
  SonyLensType {
    id: 32802,
    name: "Sony FE 90mm F2.8 Macro G OSS",
  },
  SonyLensType {
    id: 32803,
    name: "Sony E 18-50mm F4-5.6",
  },
  SonyLensType {
    id: 32804,
    name: "Sony FE 24mm F1.4 GM",
  },
  SonyLensType {
    id: 32805,
    name: "Sony FE 24-105mm F4 G OSS",
  },
  SonyLensType {
    id: 32807,
    name: "Sony E PZ 18-200mm F3.5-6.3 OSS",
  },
  SonyLensType {
    id: 32808,
    name: "Sony FE 55mm F1.8 ZA",
  },
  SonyLensType {
    id: 32810,
    name: "Sony FE 70-200mm F4 G OSS",
  },
  SonyLensType {
    id: 32811,
    name: "Sony FE 16-35mm F4 ZA OSS",
  },
  SonyLensType {
    id: 32812,
    name: "Sony FE 50mm F2.8 Macro",
  },
  SonyLensType {
    id: 32813,
    name: "Sony FE 28-70mm F3.5-5.6 OSS",
  },
  SonyLensType {
    id: 32814,
    name: "Sony FE 35mm F1.4 ZA",
  },
  SonyLensType {
    id: 32815,
    name: "Sony FE 24-240mm F3.5-6.3 OSS",
  },
  SonyLensType {
    id: 32816,
    name: "Sony FE 28mm F2",
  },
  SonyLensType {
    id: 32817,
    name: "Sony FE PZ 28-135mm F4 G OSS",
  },
  SonyLensType {
    id: 32819,
    name: "Sony FE 100mm F2.8 STF GM OSS",
  },
  SonyLensType {
    id: 32820,
    name: "Sony E PZ 18-110mm F4 G OSS",
  },
  SonyLensType {
    id: 32821,
    name: "Sony FE 24-70mm F2.8 GM",
  },
  SonyLensType {
    id: 32822,
    name: "Sony FE 50mm F1.4 ZA",
  },
  SonyLensType {
    id: 32823,
    name: "Sony FE 85mm F1.4 GM or Samyang AF 85mm F1.4",
  },
  SonyLensType {
    id: 32824,
    name: "Sony FE 50mm F1.8",
  },
  SonyLensType {
    id: 32826,
    name: "Sony FE 21mm F2.8 (SEL28F20 + SEL075UWC)",
  },
  SonyLensType {
    id: 32827,
    name: "Sony FE 16mm F3.5 Fisheye (SEL28F20 + SEL057FEC)",
  },
  SonyLensType {
    id: 32828,
    name: "Sony FE 70-300mm F4.5-5.6 G OSS",
  },
  SonyLensType {
    id: 32829,
    name: "Sony FE 100-400mm F4.5-5.6 GM OSS",
  },
  SonyLensType {
    id: 32830,
    name: "Sony FE 70-200mm F2.8 GM OSS",
  },
  SonyLensType {
    id: 32831,
    name: "Sony FE 16-35mm F2.8 GM",
  },
  SonyLensType {
    id: 32848,
    name: "Sony FE 400mm F2.8 GM OSS",
  },
  SonyLensType {
    id: 32849,
    name: "Sony E 18-135mm F3.5-5.6 OSS",
  },
  SonyLensType {
    id: 32850,
    name: "Sony FE 135mm F1.8 GM",
  },
  SonyLensType {
    id: 32851,
    name: "Sony FE 200-600mm F5.6-6.3 G OSS",
  },
  SonyLensType {
    id: 32852,
    name: "Sony FE 600mm F4 GM OSS",
  },
  SonyLensType {
    id: 32853,
    name: "Sony E 16-55mm F2.8 G",
  },
  SonyLensType {
    id: 32854,
    name: "Sony E 70-350mm F4.5-6.3 G OSS",
  },
  SonyLensType {
    id: 32855,
    name: "Sony FE C 16-35mm T3.1 G",
  },
  SonyLensType {
    id: 32858,
    name: "Sony FE 35mm F1.8",
  },
  SonyLensType {
    id: 32859,
    name: "Sony FE 20mm F1.8 G",
  },
  SonyLensType {
    id: 32860,
    name: "Sony FE 12-24mm F2.8 GM",
  },
  SonyLensType {
    id: 32862,
    name: "Sony FE 50mm F1.2 GM",
  },
  SonyLensType {
    id: 32863,
    name: "Sony FE 14mm F1.8 GM",
  },
  SonyLensType {
    id: 32864,
    name: "Sony FE 28-60mm F4-5.6",
  },
  SonyLensType {
    id: 32865,
    name: "Sony FE 35mm F1.4 GM",
  },
  SonyLensType {
    id: 32866,
    name: "Sony FE 24mm F2.8 G",
  },
  SonyLensType {
    id: 32867,
    name: "Sony FE 40mm F2.5 G",
  },
  SonyLensType {
    id: 32868,
    name: "Sony FE 50mm F2.5 G",
  },
  SonyLensType {
    id: 32871,
    name: "Sony FE PZ 16-35mm F4 G",
  },
  SonyLensType {
    id: 32873,
    name: "Sony E PZ 10-20mm F4 G",
  },
  SonyLensType {
    id: 32874,
    name: "Sony FE 70-200mm F2.8 GM OSS II",
  },
  SonyLensType {
    id: 32875,
    name: "Sony FE 24-70mm F2.8 GM II",
  },
  SonyLensType {
    id: 32876,
    name: "Sony E 11mm F1.8",
  },
  SonyLensType {
    id: 32877,
    name: "Sony E 15mm F1.4 G",
  },
  SonyLensType {
    id: 32878,
    name: "Sony FE 20-70mm F4 G",
  },
  SonyLensType {
    id: 32879,
    name: "Sony FE 50mm F1.4 GM",
  },
  SonyLensType {
    id: 32880,
    name: "Sony FE 16mm F1.8 G",
  },
  SonyLensType {
    id: 32881,
    name: "Sony FE 24-50mm F2.8 G",
  },
  SonyLensType {
    id: 32882,
    name: "Sony FE 16-25mm F2.8 G",
  },
  SonyLensType {
    id: 32884,
    name: "Sony FE 70-200mm F4 Macro G OSS II",
  },
  SonyLensType {
    id: 32885,
    name: "Sony FE 16-35mm F2.8 GM II",
  },
  SonyLensType {
    id: 32886,
    name: "Sony FE 300mm F2.8 GM OSS",
  },
  SonyLensType {
    id: 32887,
    name: "Sony E PZ 16-50mm F3.5-5.6 OSS II",
  },
  SonyLensType {
    id: 32888,
    name: "Sony FE 85mm F1.4 GM II",
  },
  SonyLensType {
    id: 32889,
    name: "Sony FE 28-70mm F2 GM",
  },
  SonyLensType {
    id: 32890,
    name: "Sony FE 400-800mm F6.3-8 G OSS",
  },
  SonyLensType {
    id: 32891,
    name: "Sony FE 50-150mm F2 GM",
  },
  SonyLensType {
    id: 32893,
    name: "Sony FE 100mm F2.8 Macro GM OSS",
  },
  SonyLensType {
    id: 32895,
    name: "Sony FE 100-400mm F4.5 GM OSS",
  },
  SonyLensType {
    id: 33072,
    name: "Sony FE 70-200mm F2.8 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33073,
    name: "Sony FE 70-200mm F2.8 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33076,
    name: "Sony FE 100mm F2.8 STF GM OSS (macro mode)",
  },
  SonyLensType {
    id: 33077,
    name: "Sony FE 100-400mm F4.5-5.6 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33078,
    name: "Sony FE 100-400mm F4.5-5.6 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33079,
    name: "Sony FE 400mm F2.8 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33080,
    name: "Sony FE 400mm F2.8 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33081,
    name: "Sony FE 200-600mm F5.6-6.3 G OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33082,
    name: "Sony FE 200-600mm F5.6-6.3 G OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33083,
    name: "Sony FE 600mm F4 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33084,
    name: "Sony FE 600mm F4 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33085,
    name: "Sony FE 70-200mm F2.8 GM OSS II + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33086,
    name: "Sony FE 70-200mm F2.8 GM OSS II + 2X Teleconverter",
  },
  SonyLensType {
    id: 33087,
    name: "Sony FE 70-200mm F4 Macro G OSS II + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33088,
    name: "Sony FE 70-200mm F4 Macro G OSS II + 2X Teleconverter",
  },
  SonyLensType {
    id: 33089,
    name: "Sony FE 300mm F2.8 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33090,
    name: "Sony FE 300mm F2.8 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33091,
    name: "Sony FE 400-800mm F6.3-8 G OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33092,
    name: "Sony FE 400-800mm F6.3-8 G OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33093,
    name: "Sony FE 100mm F2.8 Macro GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33094,
    name: "Sony FE 100mm F2.8 Macro GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 33095,
    name: "Sony FE 100-400mm F4.5 GM OSS + 1.4X Teleconverter",
  },
  SonyLensType {
    id: 33096,
    name: "Sony FE 100-400mm F4.5 GM OSS + 2X Teleconverter",
  },
  SonyLensType {
    id: 49201,
    name: "Zeiss Touit 12mm F2.8 or other Touit lens",
  },
  SonyLensType {
    id: 49202,
    name: "Zeiss Touit 32mm F1.8",
  },
  SonyLensType {
    id: 49203,
    name: "Zeiss Touit 50mm F2.8 Macro",
  },
  SonyLensType {
    id: 49216,
    name: "Zeiss Batis 25mm F2",
  },
  SonyLensType {
    id: 49217,
    name: "Zeiss Batis 85mm F1.8",
  },
  SonyLensType {
    id: 49218,
    name: "Zeiss Batis 18mm F2.8",
  },
  SonyLensType {
    id: 49219,
    name: "Zeiss Batis 135mm F2.8",
  },
  SonyLensType {
    id: 49220,
    name: "Zeiss Batis 40mm F2 CF",
  },
  SonyLensType {
    id: 49232,
    name: "Zeiss Loxia 50mm F2",
  },
  SonyLensType {
    id: 49233,
    name: "Zeiss Loxia 35mm F2",
  },
  SonyLensType {
    id: 49234,
    name: "Zeiss Loxia 21mm F2.8",
  },
  SonyLensType {
    id: 49235,
    name: "Zeiss Loxia 85mm F2.4",
  },
  SonyLensType {
    id: 49236,
    name: "Zeiss Loxia 25mm F2.4",
  },
  SonyLensType {
    id: 49456,
    name: "Tamron E 18-200mm F3.5-6.3 Di III VC",
  },
  SonyLensType {
    id: 49457,
    name: "Tamron 28-75mm F2.8 Di III RXD",
  },
  SonyLensType {
    id: 49458,
    name: "Tamron 17-28mm F2.8 Di III RXD",
  },
  SonyLensType {
    id: 49459,
    name: "Tamron 35mm F2.8 Di III OSD M1:2",
  },
  SonyLensType {
    id: 49460,
    name: "Tamron 24mm F2.8 Di III OSD M1:2",
  },
  SonyLensType {
    id: 49461,
    name: "Tamron 20mm F2.8 Di III OSD M1:2",
  },
  SonyLensType {
    id: 49462,
    name: "Tamron 70-180mm F2.8 Di III VXD",
  },
  SonyLensType {
    id: 49463,
    name: "Tamron 28-200mm F2.8-5.6 Di III RXD",
  },
  SonyLensType {
    id: 49464,
    name: "Tamron 70-300mm F4.5-6.3 Di III RXD",
  },
  SonyLensType {
    id: 49465,
    name: "Tamron 17-70mm F2.8 Di III-A VC RXD",
  },
  SonyLensType {
    id: 49466,
    name: "Tamron 150-500mm F5-6.7 Di III VC VXD",
  },
  SonyLensType {
    id: 49467,
    name: "Tamron 11-20mm F2.8 Di III-A RXD",
  },
  SonyLensType {
    id: 49468,
    name: "Tamron 18-300mm F3.5-6.3 Di III-A VC VXD",
  },
  SonyLensType {
    id: 49469,
    name: "Tamron 35-150mm F2-F2.8 Di III VXD",
  },
  SonyLensType {
    id: 49470,
    name: "Tamron 28-75mm F2.8 Di III VXD G2",
  },
  SonyLensType {
    id: 49471,
    name: "Tamron 50-400mm F4.5-6.3 Di III VC VXD",
  },
  SonyLensType {
    id: 49472,
    name: "Tamron 20-40mm F2.8 Di III VXD",
  },
  SonyLensType {
    id: 49473,
    name: "Tamron 17-50mm F4 Di III VXD or Tokina or Viltrox lens",
  },
  SonyLensType {
    id: 49474,
    name: "Tamron 70-180mm F2.8 Di III VXD G2 or Viltrox lens",
  },
  SonyLensType {
    id: 49475,
    name: "Tamron 50-300mm F4.5-6.3 Di III VC VXD",
  },
  SonyLensType {
    id: 49476,
    name: "Tamron 28-300mm F4-7.1 Di III VC VXD",
  },
  SonyLensType {
    id: 49477,
    name: "Tamron 90mm F2.8 Di III Macro VXD",
  },
  SonyLensType {
    id: 49478,
    name: "Tamron 16-30mm F2.8 Di III VXD G2",
  },
  SonyLensType {
    id: 49479,
    name: "Tamron 25-200mm F2.8-5.6 Di III VXD G2",
  },
  SonyLensType {
    id: 49480,
    name: "Tamron 35-100mm F2.8 Di III VXD",
  },
  SonyLensType {
    id: 49712,
    name: "Tokina FiRIN 20mm F2 FE AF",
  },
  SonyLensType {
    id: 49713,
    name: "Tokina FiRIN 100mm F2.8 FE MACRO",
  },
  SonyLensType {
    id: 49714,
    name: "Tokina atx-m 11-18mm F2.8 E",
  },
  SonyLensType {
    id: 50480,
    name: "Sigma 30mm F1.4 DC DN | C",
  },
  SonyLensType {
    id: 50481,
    name: "Sigma 50mm F1.4 DG HSM | A",
  },
  SonyLensType {
    id: 50482,
    name: "Sigma 18-300mm F3.5-6.3 DC MACRO OS HSM | C + MC-11",
  },
  SonyLensType {
    id: 50483,
    name: "Sigma 18-35mm F1.8 DC HSM | A + MC-11",
  },
  SonyLensType {
    id: 50484,
    name: "Sigma 24-35mm F2 DG HSM | A + MC-11",
  },
  SonyLensType {
    id: 50485,
    name: "Sigma 24mm F1.4 DG HSM | A + MC-11",
  },
  SonyLensType {
    id: 50486,
    name: "Sigma 150-600mm F5-6.3 DG OS HSM | C + MC-11",
  },
  SonyLensType {
    id: 50487,
    name: "Sigma 20mm F1.4 DG HSM | A + MC-11",
  },
  SonyLensType {
    id: 50488,
    name: "Sigma 35mm F1.4 DG HSM | A",
  },
  SonyLensType {
    id: 50489,
    name: "Sigma 150-600mm F5-6.3 DG OS HSM | S + MC-11",
  },
  SonyLensType {
    id: 50490,
    name: "Sigma 120-300mm F2.8 DG OS HSM | S + MC-11",
  },
  SonyLensType {
    id: 50492,
    name: "Sigma 24-105mm F4 DG OS HSM | A + MC-11",
  },
  SonyLensType {
    id: 50493,
    name: "Sigma 17-70mm F2.8-4 DC MACRO OS HSM | C + MC-11",
  },
  SonyLensType {
    id: 50495,
    name: "Sigma 50-100mm F1.8 DC HSM | A + MC-11",
  },
  SonyLensType {
    id: 50499,
    name: "Sigma 85mm F1.4 DG HSM | A",
  },
  SonyLensType {
    id: 50501,
    name: "Sigma 100-400mm F5-6.3 DG OS HSM | C + MC-11",
  },
  SonyLensType {
    id: 50503,
    name: "Sigma 16mm F1.4 DC DN | C",
  },
  SonyLensType {
    id: 50507,
    name: "Sigma 105mm F1.4 DG HSM | A",
  },
  SonyLensType {
    id: 50508,
    name: "Sigma 56mm F1.4 DC DN | C",
  },
  SonyLensType {
    id: 50512,
    name: "Sigma 70-200mm F2.8 DG OS HSM | S + MC-11",
  },
  SonyLensType {
    id: 50513,
    name: "Sigma 70mm F2.8 DG MACRO | A",
  },
  SonyLensType {
    id: 50514,
    name: "Sigma 45mm F2.8 DG DN | C",
  },
  SonyLensType {
    id: 50515,
    name: "Sigma 35mm F1.2 DG DN | A",
  },
  SonyLensType {
    id: 50516,
    name: "Sigma 14-24mm F2.8 DG DN | A",
  },
  SonyLensType {
    id: 50517,
    name: "Sigma 24-70mm F2.8 DG DN | A",
  },
  SonyLensType {
    id: 50518,
    name: "Sigma 100-400mm F5-6.3 DG DN OS | C",
  },
  SonyLensType {
    id: 50521,
    name: "Sigma 85mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50522,
    name: "Sigma 105mm F2.8 DG DN MACRO | A",
  },
  SonyLensType {
    id: 50523,
    name: "Sigma 65mm F2 DG DN | C",
  },
  SonyLensType {
    id: 50524,
    name: "Sigma 35mm F2 DG DN | C",
  },
  SonyLensType {
    id: 50525,
    name: "Sigma 24mm F3.5 DG DN | C",
  },
  SonyLensType {
    id: 50526,
    name: "Sigma 28-70mm F2.8 DG DN | C",
  },
  SonyLensType {
    id: 50527,
    name: "Sigma 150-600mm F5-6.3 DG DN OS | S",
  },
  SonyLensType {
    id: 50528,
    name: "Sigma 35mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50529,
    name: "Sigma 90mm F2.8 DG DN | C",
  },
  SonyLensType {
    id: 50530,
    name: "Sigma 24mm F2 DG DN | C",
  },
  SonyLensType {
    id: 50531,
    name: "Sigma 18-50mm F2.8 DC DN | C",
  },
  SonyLensType {
    id: 50532,
    name: "Sigma 20mm F2 DG DN | C",
  },
  SonyLensType {
    id: 50533,
    name: "Sigma 16-28mm F2.8 DG DN | C",
  },
  SonyLensType {
    id: 50534,
    name: "Sigma 20mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50535,
    name: "Sigma 24mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50536,
    name: "Sigma 60-600mm F4.5-6.3 DG DN OS | S",
  },
  SonyLensType {
    id: 50537,
    name: "Sigma 50mm F2 DG DN | C",
  },
  SonyLensType {
    id: 50538,
    name: "Sigma 17mm F4 DG DN | C",
  },
  SonyLensType {
    id: 50539,
    name: "Sigma 50mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50540,
    name: "Sigma 14mm F1.4 DG DN | A",
  },
  SonyLensType {
    id: 50543,
    name: "Sigma 70-200mm F2.8 DG DN OS | S",
  },
  SonyLensType {
    id: 50544,
    name: "Sigma 23mm F1.4 DC DN | C",
  },
  SonyLensType {
    id: 50545,
    name: "Sigma 24-70mm F2.8 DG DN II | A",
  },
  SonyLensType {
    id: 50546,
    name: "Sigma 500mm F5.6 DG DN OS | S",
  },
  SonyLensType {
    id: 50547,
    name: "Sigma 10-18mm F2.8 DC DN | C",
  },
  SonyLensType {
    id: 50548,
    name: "Sigma 15mm F1.4 DG DN DIAGONAL FISHEYE | A",
  },
  SonyLensType {
    id: 50549,
    name: "Sigma 50mm F1.2 DG DN | A",
  },
  SonyLensType {
    id: 50550,
    name: "Sigma 28-105mm F2.8 DG DN | A",
  },
  SonyLensType {
    id: 50551,
    name: "Sigma 28-45mm F1.8 DG DN | A",
  },
  SonyLensType {
    id: 50552,
    name: "Sigma 35mm F1.2 DG II | A",
  },
  SonyLensType {
    id: 50553,
    name: "Sigma 300-600mm F4 DG OS | S",
  },
  SonyLensType {
    id: 50554,
    name: "Sigma 16-300mm F3.5-6.7 DC OS | C",
  },
  SonyLensType {
    id: 50555,
    name: "Sigma 12mm F1.4 DC | C",
  },
  SonyLensType {
    id: 50556,
    name: "Sigma 17-40mm F1.8 DC | A",
  },
  SonyLensType {
    id: 50557,
    name: "Sigma 200mm F2 DG OS | S",
  },
  SonyLensType {
    id: 50558,
    name: "Sigma 20-200mm F3.5-6.3 DG | C",
  },
  SonyLensType {
    id: 50559,
    name: "Sigma 135mm F1.4 DG | A",
  },
  SonyLensType {
    id: 50563,
    name: "Sigma 35mm F1.4 DG II | A",
  },
  SonyLensType {
    id: 50564,
    name: "Sigma 15mm F1.4 DC | C",
  },
  SonyLensType {
    id: 50992,
    name: "Voigtlander SUPER WIDE-HELIAR 15mm F4.5 III",
  },
  SonyLensType {
    id: 50993,
    name: "Voigtlander HELIAR-HYPER WIDE 10mm F5.6",
  },
  SonyLensType {
    id: 50994,
    name: "Voigtlander ULTRA WIDE-HELIAR 12mm F5.6 III",
  },
  SonyLensType {
    id: 50995,
    name: "Voigtlander MACRO APO-LANTHAR 65mm F2 Aspherical",
  },
  SonyLensType {
    id: 50996,
    name: "Voigtlander NOKTON 40mm F1.2 Aspherical",
  },
  SonyLensType {
    id: 50997,
    name: "Voigtlander NOKTON classic 35mm F1.4",
  },
  SonyLensType {
    id: 50998,
    name: "Voigtlander MACRO APO-LANTHAR 110mm F2.5",
  },
  SonyLensType {
    id: 50999,
    name: "Voigtlander COLOR-SKOPAR 21mm F3.5 Aspherical",
  },
  SonyLensType {
    id: 51000,
    name: "Voigtlander NOKTON 50mm F1.2 Aspherical",
  },
  SonyLensType {
    id: 51001,
    name: "Voigtlander NOKTON 21mm F1.4 Aspherical",
  },
  SonyLensType {
    id: 51002,
    name: "Voigtlander APO-LANTHAR 50mm F2 Aspherical",
  },
  SonyLensType {
    id: 51003,
    name: "Voigtlander NOKTON 35mm F1.2 Aspherical SE",
  },
  SonyLensType {
    id: 51006,
    name: "Voigtlander APO-LANTHAR 35mm F2 Aspherical",
  },
  SonyLensType {
    id: 51007,
    name: "Voigtlander NOKTON 50mm F1 Aspherical",
  },
  SonyLensType {
    id: 51008,
    name: "Voigtlander NOKTON 75mm F1.5 Aspherical",
  },
  SonyLensType {
    id: 51009,
    name: "Voigtlander NOKTON 28mm F1.5 Aspherical",
  },
  SonyLensType {
    id: 51011,
    name: "Voigtlander APO-LANTHAR 28mm F2 Aspherical",
  },
  SonyLensType {
    id: 51072,
    name: "ZEISS Otus ML 50mm F1.4",
  },
  SonyLensType {
    id: 51073,
    name: "ZEISS Otus ML 85mm F1.4",
  },
  SonyLensType {
    id: 51504,
    name: "Samyang AF 50mm F1.4",
  },
  SonyLensType {
    id: 51505,
    name: "Samyang AF 14mm F2.8 or Samyang AF 35mm F2.8",
  },
  SonyLensType {
    id: 51507,
    name: "Samyang AF 35mm F1.4",
  },
  SonyLensType {
    id: 51508,
    name: "Samyang AF 45mm F1.8",
  },
  SonyLensType {
    id: 51510,
    name: "Samyang AF 18mm F2.8 or Samyang AF 35mm F1.8",
  },
  SonyLensType {
    id: 51512,
    name: "Samyang AF 75mm F1.8",
  },
  SonyLensType {
    id: 51513,
    name: "Samyang AF 35mm F1.8",
  },
  SonyLensType {
    id: 51514,
    name: "Samyang AF 24mm F1.8",
  },
  SonyLensType {
    id: 51515,
    name: "Samyang AF 12mm F2.0",
  },
  SonyLensType {
    id: 51516,
    name: "Samyang AF 24-70mm F2.8",
  },
  SonyLensType {
    id: 51517,
    name: "Samyang AF 50mm F1.4 II",
  },
  SonyLensType {
    id: 51518,
    name: "Samyang AF 135mm F1.8",
  },
  SonyLensType {
    id: 61569,
    name: "LAOWA FFII 10mm F2.8 C&D Dreamer",
  },
  SonyLensType {
    id: 61572,
    name: "LAOWA FFII 12mm F2.8 C&D Dreamer",
  },
  SonyLensType {
    id: 61600,
    name: "Thypoch AF 24-50mm F2.8 FE",
  },
  SonyLensType {
    id: 61760,
    name: "Viltrox 135mm F1.8 FE LAB",
  },
  SonyLensType {
    id: 61761,
    name: "Viltrox 28mm F4.5 FE",
  },
  SonyLensType {
    id: 61762,
    name: "Viltrox 35mm F1.2 FE LAB",
  },
  SonyLensType {
    id: 61763,
    name: "Viltrox 85mm F1.4 FE Pro",
  },
  SonyLensType {
    id: 61766,
    name: "Viltrox 40mm F2.5 FE Air",
  },
  SonyLensType {
    id: 61767,
    name: "Viltrox 50mm F2.0 FE Air",
  },
  SonyLensType {
    id: 61768,
    name: "Viltrox 25mm F1.7 E Air",
  },
  SonyLensType {
    id: 61776,
    name: "Viltrox 50mm F1.4 FE Pro",
  },
  SonyLensType {
    id: 61777,
    name: "Viltrox 9mm F2.8 E Air",
  },
  SonyLensType {
    id: 61778,
    name: "Viltrox 14mm F4.0 FE Air",
  },
  SonyLensType {
    id: 61779,
    name: "Viltrox 56mm F1.2 E Pro",
  },
  SonyLensType {
    id: 61780,
    name: "Viltrox 85mm F2.0 FE EVO",
  },
  SonyLensType {
    id: 61781,
    name: "Viltrox 55mm F1.8 FE EVO",
  },
  SonyLensType {
    id: 61783,
    name: "Viltrox 15mm F1.7 E Air",
  },
  SonyLensType {
    id: 61789,
    name: "Viltrox 35mm F1.8 II FE EVO",
  },
];

/// Look up a lens name by ID. Returns `None` if the ID is not in the
/// table; the caller (`SonyPrintConv::LensType`) renders `"Unknown (N)"`
/// in that case to match bundled.
#[must_use]
pub fn lookup_name(id: u32) -> Option<SmolStr> {
  match SONY_LENS_TYPES.binary_search_by_key(&id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => SONY_LENS_TYPES.get(i).map(|t| SmolStr::from(t.name)),
    Err(_) => None,
  }
}

/// FLOAT-keyed disambiguation entries of `%sonyLensTypes2`, sorted by
/// `(id, variant)`. Each shares its `id` with a primary [`SONY_LENS_TYPES`]
/// row; `PrintLensID` appends [`lens_variants`]`(id)` after that primary.
/// Inert until the `PrintLensID` wiring lands.
pub const SONY_LENS_VARIANTS: &[SonyLensVariant] = &[
  SonyLensVariant {
    id: 0,
    variant: 1,
    name: "Sigma 19mm F2.8 [EX] DN",
  },
  SonyLensVariant {
    id: 0,
    variant: 2,
    name: "Sigma 30mm F2.8 [EX] DN",
  },
  SonyLensVariant {
    id: 0,
    variant: 3,
    name: "Sigma 60mm F2.8 DN",
  },
  SonyLensVariant {
    id: 0,
    variant: 4,
    name: "Sony E 18-200mm F3.5-6.3 OSS LE",
  },
  SonyLensVariant {
    id: 0,
    variant: 5,
    name: "Tamron 18-200mm F3.5-6.3 Di III VC",
  },
  SonyLensVariant {
    id: 0,
    variant: 6,
    name: "Tokina FiRIN 20mm F2 FE AF",
  },
  SonyLensVariant {
    id: 0,
    variant: 7,
    name: "Tokina FiRIN 20mm F2 FE MF",
  },
  SonyLensVariant {
    id: 0,
    variant: 8,
    name: "Zeiss Touit 12mm F2.8",
  },
  SonyLensVariant {
    id: 0,
    variant: 9,
    name: "Zeiss Touit 32mm F1.8",
  },
  SonyLensVariant {
    id: 0,
    variant: 10,
    name: "Zeiss Touit 50mm F2.8 Macro",
  },
  SonyLensVariant {
    id: 0,
    variant: 11,
    name: "Zeiss Loxia 50mm F2",
  },
  SonyLensVariant {
    id: 0,
    variant: 12,
    name: "Zeiss Loxia 35mm F2",
  },
  SonyLensVariant {
    id: 0,
    variant: 13,
    name: "Viltrox 85mm F1.8",
  },
  SonyLensVariant {
    id: 32789,
    variant: 1,
    name: "Samyang AF 50mm F1.4",
  },
  SonyLensVariant {
    id: 32790,
    variant: 1,
    name: "Samyang AF 14mm F2.8",
  },
  SonyLensVariant {
    id: 32794,
    variant: 1,
    name: "Samyang AF 24mm F2.8",
  },
  SonyLensVariant {
    id: 32794,
    variant: 2,
    name: "Samyang AF 35mm F2.8",
  },
  SonyLensVariant {
    id: 32796,
    variant: 1,
    name: "Viltrox PFU RBMH 85mm F1.8",
  },
  SonyLensVariant {
    id: 32823,
    variant: 1,
    name: "Samyang AF 85mm F1.4",
  },
  SonyLensVariant {
    id: 49201,
    variant: 1,
    name: "Zeiss Touit 32mm F1.8",
  },
  SonyLensVariant {
    id: 49201,
    variant: 2,
    name: "Zeiss Touit 50mm F2.8",
  },
  SonyLensVariant {
    id: 49473,
    variant: 1,
    name: "Tokina atx-m 85mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49473,
    variant: 2,
    name: "Viltrox 23mm F1.4 E",
  },
  SonyLensVariant {
    id: 49473,
    variant: 3,
    name: "Viltrox 56mm F1.4 E",
  },
  SonyLensVariant {
    id: 49473,
    variant: 4,
    name: "Viltrox 85mm F1.8 II FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 1,
    name: "Viltrox 13mm F1.4 E",
  },
  SonyLensVariant {
    id: 49474,
    variant: 2,
    name: "Viltrox 16mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 3,
    name: "Viltrox 23mm F1.4 E",
  },
  SonyLensVariant {
    id: 49474,
    variant: 4,
    name: "Viltrox 24mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 5,
    name: "Viltrox 28mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 6,
    name: "Viltrox 33mm F1.4 E",
  },
  SonyLensVariant {
    id: 49474,
    variant: 7,
    name: "Viltrox 35mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 8,
    name: "Viltrox 50mm F1.8 FE",
  },
  SonyLensVariant {
    id: 49474,
    variant: 9,
    name: "Viltrox 75mm F1.2 E Pro",
  },
  SonyLensVariant {
    id: 49474,
    variant: 10,
    name: "Viltrox 20mm F2.8 FE Air",
  },
  SonyLensVariant {
    id: 49474,
    variant: 11,
    name: "Viltrox 135mm F1.8 FE LAB",
  },
  SonyLensVariant {
    id: 49474,
    variant: 12,
    name: "Viltrox 27mm F1.2 E Pro",
  },
  SonyLensVariant {
    id: 49474,
    variant: 13,
    name: "Viltrox 56mm F1.4 E",
  },
  SonyLensVariant {
    id: 51505,
    variant: 1,
    name: "Samyang AF 35mm F2.8",
  },
  SonyLensVariant {
    id: 51510,
    variant: 1,
    name: "Samyang AF 35mm F1.8",
  },
];

/// The `id.1`, `id.2`, … secondary names for `id`, in ascending `variant`
/// order — the order `PrintLensID` (`Exif.pm:5969`) scans them. Empty when
/// `id` has no float-keyed variants.
#[must_use]
pub fn lens_variants(id: u32) -> &'static [SonyLensVariant] {
  let lo = SONY_LENS_VARIANTS.partition_point(|v| v.id < id);
  let hi = SONY_LENS_VARIANTS.partition_point(|v| v.id <= id);
  // `partition_point` guarantees `lo <= hi <= len`, so the slice is in range.
  SONY_LENS_VARIANTS.get(lo..hi).unwrap_or(&[])
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
    for t in SONY_LENS_TYPES {
      assert!(
        t.id as i64 > prev,
        "SONY_LENS_TYPES not strictly sorted: {} after {}",
        t.id,
        prev
      );
      prev = t.id as i64;
    }
  }

  #[test]
  fn lookup_known_lens_id_zero() {
    // 0 => 'Unknown E-mount lens or other lens'
    let name = lookup_name(0).expect("ID 0 should be in the table");
    assert_eq!(name.as_str(), "Unknown E-mount lens or other lens");
  }

  #[test]
  fn lookup_la_ea2_adapter() {
    // 2 => 'Sony LA-EA2 Adapter'
    let name = lookup_name(2).expect("LA-EA2 should be present");
    assert_eq!(name.as_str(), "Sony LA-EA2 Adapter");
  }

  #[test]
  fn lookup_sony_fe_35mm_f1_4_zss() {
    // 32789 => 'Sony E 24mm F1.8 ZA or Samyang AF 50mm F1.4'
    let name = lookup_name(32789).expect("32789 should be present");
    assert!(name.contains("Sony E 24mm F1.8 ZA"));
  }

  #[test]
  fn lookup_voigtlander_color_skopar() {
    let name = lookup_name(50999).expect("50999 should be present");
    assert!(name.contains("Voigtlander COLOR-SKOPAR 21mm F3.5 Aspherical"));
  }

  #[test]
  fn lookup_zeiss_otus_ml_50mm() {
    let name = lookup_name(51072).expect("51072 should be present");
    assert!(name.contains("ZEISS Otus ML 50mm F1.4"));
  }

  #[test]
  fn lookup_viltrox_fe_pro_air_case_faithful() {
    // #472: ExifTool 13.59 %sonyLensTypes2 spells these "FE Pro"/"FE Air"
    // (not the all-caps "FE PRO"/"FE AIR" the table had drifted to).
    assert_eq!(
      lookup_name(61763).as_deref(),
      Some("Viltrox 85mm F1.4 FE Pro")
    );
    assert_eq!(
      lookup_name(61767).as_deref(),
      Some("Viltrox 50mm F2.0 FE Air")
    );
    assert_eq!(
      lookup_name(61776).as_deref(),
      Some("Viltrox 50mm F1.4 FE Pro")
    );
  }

  #[test]
  fn lookup_unknown_id_returns_none() {
    assert!(lookup_name(987654).is_none());
  }

  #[test]
  fn variants_sorted_and_contiguous_from_one() {
    // Sorted by `(id, variant)`; within an id the variants run `1..=N` with no
    // gap, because `PrintLensID` stops scanning at the first missing `id.i`.
    let mut prev_id: Option<u32> = None;
    let mut expect_var: u8 = 1;
    for v in SONY_LENS_VARIANTS {
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
            "SONY_LENS_VARIANTS not sorted by id: {} after {p}",
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
  fn lens_variants_49473_tamron_tokina_viltrox_in_order() {
    let names: Vec<&str> = lens_variants(49473).iter().map(|v| v.name).collect();
    assert_eq!(
      names,
      [
        "Tokina atx-m 85mm F1.8 FE",
        "Viltrox 23mm F1.4 E",
        "Viltrox 56mm F1.4 E",
        "Viltrox 85mm F1.8 II FE",
      ]
    );
  }

  #[test]
  fn lens_variants_zero_has_thirteen_in_order() {
    let vs = lens_variants(0);
    assert_eq!(vs.len(), 13);
    assert_eq!(vs.first().map(|v| v.name), Some("Sigma 19mm F2.8 [EX] DN"));
    assert_eq!(vs.last().map(|v| v.name), Some("Viltrox 85mm F1.8"));
  }

  #[test]
  fn lens_variants_absent_is_empty() {
    // 1 (LA-EA1) is a primary with no float entries; 999_999 is unknown.
    assert!(lens_variants(1).is_empty());
    assert!(lens_variants(999_999).is_empty());
  }

  #[test]
  fn refreshed_integer_ids_resolve_via_lookup() {
    // The 16 IDs added in this chunk all resolve through the unchanged lookup.
    for id in [
      24u32, 32895, 33095, 33096, 50563, 50564, 51011, 61600, 61766, 61768, 61777, 61778, 61779,
      61781, 61783, 61789,
    ] {
      assert!(lookup_name(id).is_some(), "missing refreshed id {id}");
    }
    assert_eq!(
      lookup_name(24).as_deref(),
      Some("Samyang AF 85mm F1.8 P FE")
    );
    assert_eq!(
      lookup_name(32895).as_deref(),
      Some("Sony FE 100-400mm F4.5 GM OSS")
    );
    assert_eq!(
      lookup_name(61789).as_deref(),
      Some("Viltrox 35mm F1.8 II FE EVO")
    );
  }
}
