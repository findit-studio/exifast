// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%canonLensTypes` — Canon lens-type ID → human-readable lens name
//! (`Canon.pm:97-651`). 534 entries. Canon stores the lens type as an
//! `int16u` value at index 22 of `CameraSettings` (`Canon.pm:2649-2653`),
//! BUT bundled treats integer-keyed entries as exact matches and
//! decimal-keyed entries (e.g. `2.1`, `8.2`) as third-party-lens
//! "siblings" that share the integer prefix (the dropdown selector when
//! ExifTool cannot uniquely identify the third-party lens).
//!
//! The port stores every entry — integer-keyed AND decimal-keyed — in a
//! single sorted const array. For an exact integer lookup, callers want
//! the integer-only entry (the FIRST one with that integer prefix); for
//! "tell me all candidates" the full set is iterable.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// this is the Canon LensType lookup table + helpers; any raw index/slice is
// dominated by a length/count guard and becomes a checked `.get()` form
// (re-asserts the parent `exif` deny over the makernotes `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One lens-type entry — the encoded key + the human-readable lens name.
///
/// `key_int` is the integer portion (matches the on-disk `LensType`
/// `int16u`); `key_decimal` is the fractional part times 100 (0 for
/// integer-keyed entries; `1` for `.1` siblings, `2` for `.2`, …). This
/// is what bundled stores after the `=>` symbol — Perl's hash key is a
/// string but the numeric value is what `Image::ExifTool::Canon::
/// PrintLensID` consults.
#[derive(Debug, Clone, Copy)]
pub struct CanonLensType {
  /// Integer portion of the lens key (the `int16u` from `CameraSettings[22]`).
  pub key_int: u16,
  /// Fractional portion ×100 — 0 for integer keys, `1` for `.1`, etc.
  pub key_frac: u16,
  /// Human-readable lens name (`Canon.pm:97-653` RHS).
  pub name: &'static str,
}

/// `%canonLensTypes` (`Canon.pm:97-653`), sorted by `(key_int, key_frac)`.
/// Binary-searchable on the composite key.
pub const CANON_LENS_TYPES: &[CanonLensType] = &[
  CanonLensType {
    key_int: 1,
    key_frac: 0,
    name: "Canon EF 50mm f/1.8",
  },
  CanonLensType {
    key_int: 2,
    key_frac: 0,
    name: "Canon EF 28mm f/2.8 or Sigma Lens",
  },
  CanonLensType {
    key_int: 2,
    key_frac: 1,
    name: "Sigma 24mm f/2.8 Super Wide II",
  },
  CanonLensType {
    key_int: 3,
    key_frac: 0,
    name: "Canon EF 135mm f/2.8 Soft",
  },
  CanonLensType {
    key_int: 4,
    key_frac: 0,
    name: "Canon EF 35-105mm f/3.5-4.5 or Sigma Lens",
  },
  CanonLensType {
    key_int: 4,
    key_frac: 1,
    name: "Sigma UC Zoom 35-135mm f/4-5.6",
  },
  CanonLensType {
    key_int: 5,
    key_frac: 0,
    name: "Canon EF 35-70mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 0,
    name: "Canon EF 28-70mm f/3.5-4.5 or Sigma or Tokina Lens",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 1,
    name: "Sigma 18-50mm f/3.5-5.6 DC",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 2,
    name: "Sigma 18-125mm f/3.5-5.6 DC IF ASP",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 3,
    name: "Tokina AF 193-2 19-35mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 4,
    name: "Sigma 28-80mm f/3.5-5.6 II Macro",
  },
  CanonLensType {
    key_int: 6,
    key_frac: 5,
    name: "Sigma 28-300mm f/3.5-6.3 DG Macro",
  },
  CanonLensType {
    key_int: 7,
    key_frac: 0,
    name: "Canon EF 100-300mm f/5.6L",
  },
  CanonLensType {
    key_int: 8,
    key_frac: 0,
    name: "Canon EF 100-300mm f/5.6 or Sigma or Tokina Lens",
  },
  CanonLensType {
    key_int: 8,
    key_frac: 1,
    name: "Sigma 70-300mm f/4-5.6 [APO] DG Macro",
  },
  CanonLensType {
    key_int: 8,
    key_frac: 2,
    name: "Tokina AT-X 242 AF 24-200mm f/3.5-5.6",
  },
  CanonLensType {
    key_int: 9,
    key_frac: 0,
    name: "Canon EF 70-210mm f/4",
  },
  CanonLensType {
    key_int: 9,
    key_frac: 1,
    name: "Sigma 55-200mm f/4-5.6 DC",
  },
  CanonLensType {
    key_int: 10,
    key_frac: 0,
    name: "Canon EF 50mm f/2.5 Macro or Sigma Lens",
  },
  CanonLensType {
    key_int: 10,
    key_frac: 1,
    name: "Sigma 50mm f/2.8 EX",
  },
  CanonLensType {
    key_int: 10,
    key_frac: 2,
    name: "Sigma 28mm f/1.8",
  },
  CanonLensType {
    key_int: 10,
    key_frac: 3,
    name: "Sigma 105mm f/2.8 Macro EX",
  },
  CanonLensType {
    key_int: 10,
    key_frac: 4,
    name: "Sigma 70mm f/2.8 EX DG Macro EF",
  },
  CanonLensType {
    key_int: 11,
    key_frac: 0,
    name: "Canon EF 35mm f/2",
  },
  CanonLensType {
    key_int: 13,
    key_frac: 0,
    name: "Canon EF 15mm f/2.8 Fisheye",
  },
  CanonLensType {
    key_int: 14,
    key_frac: 0,
    name: "Canon EF 50-200mm f/3.5-4.5L",
  },
  CanonLensType {
    key_int: 15,
    key_frac: 0,
    name: "Canon EF 50-200mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 16,
    key_frac: 0,
    name: "Canon EF 35-135mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 17,
    key_frac: 0,
    name: "Canon EF 35-70mm f/3.5-4.5A",
  },
  CanonLensType {
    key_int: 18,
    key_frac: 0,
    name: "Canon EF 28-70mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 20,
    key_frac: 0,
    name: "Canon EF 100-200mm f/4.5A",
  },
  CanonLensType {
    key_int: 21,
    key_frac: 0,
    name: "Canon EF 80-200mm f/2.8L",
  },
  CanonLensType {
    key_int: 22,
    key_frac: 0,
    name: "Canon EF 20-35mm f/2.8L or Tokina Lens",
  },
  CanonLensType {
    key_int: 22,
    key_frac: 1,
    name: "Tokina AT-X 280 AF Pro 28-80mm f/2.8 Aspherical",
  },
  CanonLensType {
    key_int: 23,
    key_frac: 0,
    name: "Canon EF 35-105mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 24,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6 Power Zoom",
  },
  CanonLensType {
    key_int: 25,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6 Power Zoom",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 0,
    name: "Canon EF 100mm f/2.8 Macro or Other Lens",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 1,
    name: "Cosina 100mm f/3.5 Macro AF",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 2,
    name: "Tamron SP AF 90mm f/2.8 Di Macro",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 3,
    name: "Tamron SP AF 180mm f/3.5 Di Macro",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 4,
    name: "Carl Zeiss Planar T* 50mm f/1.4",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 5,
    name: "Voigtlander APO Lanthar 125mm F2.5 SL Macro",
  },
  CanonLensType {
    key_int: 26,
    key_frac: 6,
    name: "Carl Zeiss Planar T 85mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 27,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6",
  },
  CanonLensType {
    key_int: 28,
    key_frac: 0,
    name: "Canon EF 80-200mm f/4.5-5.6 or Tamron Lens",
  },
  CanonLensType {
    key_int: 28,
    key_frac: 1,
    name: "Tamron SP AF 28-105mm f/2.8 LD Aspherical IF",
  },
  CanonLensType {
    key_int: 28,
    key_frac: 2,
    name: "Tamron SP AF 28-75mm f/2.8 XR Di LD Aspherical [IF] Macro",
  },
  CanonLensType {
    key_int: 28,
    key_frac: 3,
    name: "Tamron AF 70-300mm f/4-5.6 Di LD 1:2 Macro",
  },
  CanonLensType {
    key_int: 28,
    key_frac: 4,
    name: "Tamron AF Aspherical 28-200mm f/3.8-5.6",
  },
  CanonLensType {
    key_int: 29,
    key_frac: 0,
    name: "Canon EF 50mm f/1.8 II",
  },
  CanonLensType {
    key_int: 30,
    key_frac: 0,
    name: "Canon EF 35-105mm f/4.5-5.6",
  },
  CanonLensType {
    key_int: 31,
    key_frac: 0,
    name: "Canon EF 75-300mm f/4-5.6 or Tamron Lens",
  },
  CanonLensType {
    key_int: 31,
    key_frac: 1,
    name: "Tamron SP AF 300mm f/2.8 LD IF",
  },
  CanonLensType {
    key_int: 32,
    key_frac: 0,
    name: "Canon EF 24mm f/2.8 or Sigma Lens",
  },
  CanonLensType {
    key_int: 32,
    key_frac: 1,
    name: "Sigma 15mm f/2.8 EX Fisheye",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 0,
    name: "Voigtlander or Carl Zeiss Lens",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 1,
    name: "Voigtlander Ultron 40mm f/2 SLII Aspherical",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 2,
    name: "Voigtlander Color Skopar 20mm f/3.5 SLII Aspherical",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 3,
    name: "Voigtlander APO-Lanthar 90mm f/3.5 SLII Close Focus",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 4,
    name: "Carl Zeiss Distagon T* 15mm f/2.8 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 5,
    name: "Carl Zeiss Distagon T* 18mm f/3.5 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 6,
    name: "Carl Zeiss Distagon T* 21mm f/2.8 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 7,
    name: "Carl Zeiss Distagon T* 25mm f/2 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 8,
    name: "Carl Zeiss Distagon T* 28mm f/2 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 9,
    name: "Carl Zeiss Distagon T* 35mm f/2 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 10,
    name: "Carl Zeiss Distagon T* 35mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 11,
    name: "Carl Zeiss Planar T* 50mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 12,
    name: "Carl Zeiss Makro-Planar T* 50mm f/2 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 13,
    name: "Carl Zeiss Makro-Planar T* 100mm f/2 ZE",
  },
  CanonLensType {
    key_int: 33,
    key_frac: 14,
    name: "Carl Zeiss Apo-Sonnar T* 135mm f/2 ZE",
  },
  CanonLensType {
    key_int: 35,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6",
  },
  CanonLensType {
    key_int: 36,
    key_frac: 0,
    name: "Canon EF 38-76mm f/4.5-5.6",
  },
  CanonLensType {
    key_int: 37,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6 or Tamron Lens",
  },
  CanonLensType {
    key_int: 37,
    key_frac: 1,
    name: "Tamron 70-200mm f/2.8 Di LD IF Macro",
  },
  CanonLensType {
    key_int: 37,
    key_frac: 2,
    name: "Tamron AF 28-300mm f/3.5-6.3 XR Di VC LD Aspherical [IF] Macro (A20)",
  },
  CanonLensType {
    key_int: 37,
    key_frac: 3,
    name: "Tamron SP AF 17-50mm f/2.8 XR Di II VC LD Aspherical [IF]",
  },
  CanonLensType {
    key_int: 37,
    key_frac: 4,
    name: "Tamron AF 18-270mm f/3.5-6.3 Di II VC LD Aspherical [IF] Macro",
  },
  CanonLensType {
    key_int: 38,
    key_frac: 0,
    name: "Canon EF 80-200mm f/4.5-5.6 II",
  },
  CanonLensType {
    key_int: 39,
    key_frac: 0,
    name: "Canon EF 75-300mm f/4-5.6",
  },
  CanonLensType {
    key_int: 40,
    key_frac: 0,
    name: "Canon EF 28-80mm f/3.5-5.6",
  },
  CanonLensType {
    key_int: 41,
    key_frac: 0,
    name: "Canon EF 28-90mm f/4-5.6",
  },
  CanonLensType {
    key_int: 42,
    key_frac: 0,
    name: "Canon EF 28-200mm f/3.5-5.6 or Tamron Lens",
  },
  CanonLensType {
    key_int: 42,
    key_frac: 1,
    name: "Tamron AF 28-300mm f/3.5-6.3 XR Di VC LD Aspherical [IF] Macro (A20)",
  },
  CanonLensType {
    key_int: 43,
    key_frac: 0,
    name: "Canon EF 28-105mm f/4-5.6",
  },
  CanonLensType {
    key_int: 44,
    key_frac: 0,
    name: "Canon EF 90-300mm f/4.5-5.6",
  },
  CanonLensType {
    key_int: 45,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 [II]",
  },
  CanonLensType {
    key_int: 46,
    key_frac: 0,
    name: "Canon EF 28-90mm f/4-5.6",
  },
  CanonLensType {
    key_int: 47,
    key_frac: 0,
    name: "Zeiss Milvus 35mm f/2 or 50mm f/2",
  },
  CanonLensType {
    key_int: 47,
    key_frac: 1,
    name: "Zeiss Milvus 50mm f/2 Makro",
  },
  CanonLensType {
    key_int: 47,
    key_frac: 2,
    name: "Zeiss Milvus 135mm f/2 ZE",
  },
  CanonLensType {
    key_int: 48,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 IS",
  },
  CanonLensType {
    key_int: 49,
    key_frac: 0,
    name: "Canon EF-S 55-250mm f/4-5.6 IS",
  },
  CanonLensType {
    key_int: 50,
    key_frac: 0,
    name: "Canon EF-S 18-200mm f/3.5-5.6 IS",
  },
  CanonLensType {
    key_int: 51,
    key_frac: 0,
    name: "Canon EF-S 18-135mm f/3.5-5.6 IS",
  },
  CanonLensType {
    key_int: 52,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 IS II",
  },
  CanonLensType {
    key_int: 53,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 III",
  },
  CanonLensType {
    key_int: 54,
    key_frac: 0,
    name: "Canon EF-S 55-250mm f/4-5.6 IS II",
  },
  CanonLensType {
    key_int: 60,
    key_frac: 0,
    name: "Irix 11mm f/4 or 15mm f/2.4",
  },
  CanonLensType {
    key_int: 60,
    key_frac: 1,
    name: "Irix 15mm f/2.4",
  },
  CanonLensType {
    key_int: 63,
    key_frac: 0,
    name: "Irix 30mm F1.4 Dragonfly",
  },
  CanonLensType {
    key_int: 80,
    key_frac: 0,
    name: "Canon TS-E 50mm f/2.8L Macro",
  },
  CanonLensType {
    key_int: 81,
    key_frac: 0,
    name: "Canon TS-E 90mm f/2.8L Macro",
  },
  CanonLensType {
    key_int: 82,
    key_frac: 0,
    name: "Canon TS-E 135mm f/4L Macro",
  },
  CanonLensType {
    key_int: 94,
    key_frac: 0,
    name: "Canon TS-E 17mm f/4L",
  },
  CanonLensType {
    key_int: 95,
    key_frac: 0,
    name: "Canon TS-E 24mm f/3.5L II",
  },
  CanonLensType {
    key_int: 103,
    key_frac: 0,
    name: "Samyang AF 14mm f/2.8 EF or Rokinon Lens",
  },
  CanonLensType {
    key_int: 103,
    key_frac: 1,
    name: "Rokinon SP 14mm f/2.4",
  },
  CanonLensType {
    key_int: 103,
    key_frac: 2,
    name: "Rokinon AF 14mm f/2.8 EF",
  },
  CanonLensType {
    key_int: 106,
    key_frac: 0,
    name: "Rokinon SP / Samyang XP 35mm f/1.2",
  },
  CanonLensType {
    key_int: 112,
    key_frac: 0,
    name: "Sigma 28mm f/1.5 FF High-speed Prime or other Sigma Lens",
  },
  CanonLensType {
    key_int: 112,
    key_frac: 1,
    name: "Sigma 40mm f/1.5 FF High-speed Prime",
  },
  CanonLensType {
    key_int: 112,
    key_frac: 2,
    name: "Sigma 105mm f/1.5 FF High-speed Prime",
  },
  CanonLensType {
    key_int: 117,
    key_frac: 0,
    name: "Tamron 35-150mm f/2.8-4.0 Di VC OSD (A043) or other Tamron Lens",
  },
  CanonLensType {
    key_int: 117,
    key_frac: 1,
    name: "Tamron SP 35mm f/1.4 Di USD (F045)",
  },
  CanonLensType {
    key_int: 124,
    key_frac: 0,
    name: "Canon MP-E 65mm f/2.8 1-5x Macro Photo",
  },
  CanonLensType {
    key_int: 125,
    key_frac: 0,
    name: "Canon TS-E 24mm f/3.5L",
  },
  CanonLensType {
    key_int: 126,
    key_frac: 0,
    name: "Canon TS-E 45mm f/2.8",
  },
  CanonLensType {
    key_int: 127,
    key_frac: 0,
    name: "Canon TS-E 90mm f/2.8 or Tamron Lens",
  },
  CanonLensType {
    key_int: 127,
    key_frac: 1,
    name: "Tamron 18-200mm f/3.5-6.3 Di II VC (B018)",
  },
  CanonLensType {
    key_int: 129,
    key_frac: 0,
    name: "Canon EF 300mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 130,
    key_frac: 0,
    name: "Canon EF 50mm f/1.0L USM",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 0,
    name: "Canon EF 28-80mm f/2.8-4L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 1,
    name: "Sigma 8mm f/3.5 EX DG Circular Fisheye",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 2,
    name: "Sigma 17-35mm f/2.8-4 EX DG Aspherical HSM",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 3,
    name: "Sigma 17-70mm f/2.8-4.5 DC Macro",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 4,
    name: "Sigma APO 50-150mm f/2.8 [II] EX DC HSM",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 5,
    name: "Sigma APO 120-300mm f/2.8 EX DG HSM",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 6,
    name: "Sigma 4.5mm f/2.8 EX DC HSM Circular Fisheye",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 7,
    name: "Sigma 70-200mm f/2.8 APO EX HSM",
  },
  CanonLensType {
    key_int: 131,
    key_frac: 8,
    name: "Sigma 28-70mm f/2.8-4 DG",
  },
  CanonLensType {
    key_int: 132,
    key_frac: 0,
    name: "Canon EF 1200mm f/5.6L USM",
  },
  CanonLensType {
    key_int: 134,
    key_frac: 0,
    name: "Canon EF 600mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 135,
    key_frac: 0,
    name: "Canon EF 200mm f/1.8L USM",
  },
  CanonLensType {
    key_int: 136,
    key_frac: 0,
    name: "Canon EF 300mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 136,
    key_frac: 1,
    name: "Tamron SP 15-30mm f/2.8 Di VC USD (A012)",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 0,
    name: "Canon EF 85mm f/1.2L USM or Sigma or Tamron Lens",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 1,
    name: "Sigma 18-50mm f/2.8-4.5 DC OS HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 2,
    name: "Sigma 50-200mm f/4-5.6 DC OS HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 3,
    name: "Sigma 18-250mm f/3.5-6.3 DC OS HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 4,
    name: "Sigma 24-70mm f/2.8 IF EX DG HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 5,
    name: "Sigma 18-125mm f/3.8-5.6 DC OS HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 6,
    name: "Sigma 17-70mm f/2.8-4 DC Macro OS HSM | C",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 7,
    name: "Sigma 17-50mm f/2.8 OS HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 8,
    name: "Sigma 18-200mm f/3.5-6.3 DC OS HSM [II]",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 9,
    name: "Tamron AF 18-270mm f/3.5-6.3 Di II VC PZD (B008)",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 10,
    name: "Sigma 8-16mm f/4.5-5.6 DC HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 11,
    name: "Tamron SP 17-50mm f/2.8 XR Di II VC (B005)",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 12,
    name: "Tamron SP 60mm f/2 Macro Di II (G005)",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 13,
    name: "Sigma 10-20mm f/3.5 EX DC HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 14,
    name: "Tamron SP 24-70mm f/2.8 Di VC USD",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 15,
    name: "Sigma 18-35mm f/1.8 DC HSM",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 16,
    name: "Sigma 12-24mm f/4.5-5.6 DG HSM II",
  },
  CanonLensType {
    key_int: 137,
    key_frac: 17,
    name: "Sigma 70-300mm f/4-5.6 DG OS",
  },
  CanonLensType {
    key_int: 138,
    key_frac: 0,
    name: "Canon EF 28-80mm f/2.8-4L",
  },
  CanonLensType {
    key_int: 139,
    key_frac: 0,
    name: "Canon EF 400mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 140,
    key_frac: 0,
    name: "Canon EF 500mm f/4.5L USM",
  },
  CanonLensType {
    key_int: 141,
    key_frac: 0,
    name: "Canon EF 500mm f/4.5L USM",
  },
  CanonLensType {
    key_int: 142,
    key_frac: 0,
    name: "Canon EF 300mm f/2.8L IS USM",
  },
  CanonLensType {
    key_int: 143,
    key_frac: 0,
    name: "Canon EF 500mm f/4L IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 143,
    key_frac: 1,
    name: "Sigma 17-70mm f/2.8-4 DC Macro OS HSM",
  },
  CanonLensType {
    key_int: 144,
    key_frac: 0,
    name: "Canon EF 35-135mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 145,
    key_frac: 0,
    name: "Canon EF 100-300mm f/4.5-5.6 USM",
  },
  CanonLensType {
    key_int: 146,
    key_frac: 0,
    name: "Canon EF 70-210mm f/3.5-4.5 USM",
  },
  CanonLensType {
    key_int: 147,
    key_frac: 0,
    name: "Canon EF 35-135mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 148,
    key_frac: 0,
    name: "Canon EF 28-80mm f/3.5-5.6 USM",
  },
  CanonLensType {
    key_int: 149,
    key_frac: 0,
    name: "Canon EF 100mm f/2 USM",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 0,
    name: "Canon EF 14mm f/2.8L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 1,
    name: "Sigma 20mm EX f/1.8",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 2,
    name: "Sigma 30mm f/1.4 DC HSM",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 3,
    name: "Sigma 24mm f/1.8 DG Macro EX",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 4,
    name: "Sigma 28mm f/1.8 DG Macro EX",
  },
  CanonLensType {
    key_int: 150,
    key_frac: 5,
    name: "Sigma 18-35mm f/1.8 DC HSM | A",
  },
  CanonLensType {
    key_int: 151,
    key_frac: 0,
    name: "Canon EF 200mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 0,
    name: "Canon EF 300mm f/4L IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 1,
    name: "Sigma 12-24mm f/4.5-5.6 EX DG ASPHERICAL HSM",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 2,
    name: "Sigma 14mm f/2.8 EX Aspherical HSM",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 3,
    name: "Sigma 10-20mm f/4-5.6",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 4,
    name: "Sigma 100-300mm f/4",
  },
  CanonLensType {
    key_int: 152,
    key_frac: 5,
    name: "Sigma 300-800mm f/5.6 APO EX DG HSM",
  },
  CanonLensType {
    key_int: 153,
    key_frac: 0,
    name: "Canon EF 35-350mm f/3.5-5.6L USM or Sigma or Tamron Lens",
  },
  CanonLensType {
    key_int: 153,
    key_frac: 1,
    name: "Sigma 50-500mm f/4-6.3 APO HSM EX",
  },
  CanonLensType {
    key_int: 153,
    key_frac: 2,
    name: "Tamron AF 28-300mm f/3.5-6.3 XR LD Aspherical [IF] Macro",
  },
  CanonLensType {
    key_int: 153,
    key_frac: 3,
    name: "Tamron AF 18-200mm f/3.5-6.3 XR Di II LD Aspherical [IF] Macro (A14)",
  },
  CanonLensType {
    key_int: 153,
    key_frac: 4,
    name: "Tamron 18-250mm f/3.5-6.3 Di II LD Aspherical [IF] Macro",
  },
  CanonLensType {
    key_int: 154,
    key_frac: 0,
    name: "Canon EF 20mm f/2.8 USM or Zeiss Lens",
  },
  CanonLensType {
    key_int: 154,
    key_frac: 1,
    name: "Zeiss Milvus 21mm f/2.8",
  },
  CanonLensType {
    key_int: 154,
    key_frac: 2,
    name: "Zeiss Milvus 15mm f/2.8 ZE",
  },
  CanonLensType {
    key_int: 154,
    key_frac: 3,
    name: "Zeiss Milvus 18mm f/2.8 ZE",
  },
  CanonLensType {
    key_int: 155,
    key_frac: 0,
    name: "Canon EF 85mm f/1.8 USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 155,
    key_frac: 1,
    name: "Sigma 14mm f/1.8 DG HSM | A",
  },
  CanonLensType {
    key_int: 156,
    key_frac: 0,
    name: "Canon EF 28-105mm f/3.5-4.5 USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 156,
    key_frac: 1,
    name: "Tamron SP 70-300mm f/4-5.6 Di VC USD (A005)",
  },
  CanonLensType {
    key_int: 156,
    key_frac: 2,
    name: "Tamron SP AF 28-105mm f/2.8 LD Aspherical IF (176D)",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 0,
    name: "Canon EF 20-35mm f/3.5-4.5 USM or Tamron or Tokina Lens",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 1,
    name: "Tamron AF 19-35mm f/3.5-4.5",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 2,
    name: "Tokina AT-X 124 AF Pro DX 12-24mm f/4",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 3,
    name: "Tokina AT-X 107 AF DX 10-17mm f/3.5-4.5 Fisheye",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 4,
    name: "Tokina AT-X 116 AF Pro DX 11-16mm f/2.8",
  },
  CanonLensType {
    key_int: 160,
    key_frac: 5,
    name: "Tokina AT-X 11-20 F2.8 PRO DX Aspherical 11-20mm f/2.8",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 0,
    name: "Canon EF 28-70mm f/2.8L USM or Other Lens",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 1,
    name: "Sigma 24-70mm f/2.8 EX",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 2,
    name: "Sigma 28-70mm f/2.8 EX",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 3,
    name: "Sigma 24-60mm f/2.8 EX DG",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 4,
    name: "Tamron AF 17-50mm f/2.8 Di-II LD Aspherical",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 5,
    name: "Tamron 90mm f/2.8",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 6,
    name: "Tamron SP AF 17-35mm f/2.8-4 Di LD Aspherical IF (A05)",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 7,
    name: "Tamron SP AF 28-75mm f/2.8 XR Di LD Aspherical [IF] Macro",
  },
  CanonLensType {
    key_int: 161,
    key_frac: 8,
    name: "Tokina AT-X 24-70mm f/2.8 PRO FX (IF)",
  },
  CanonLensType {
    key_int: 162,
    key_frac: 0,
    name: "Canon EF 200mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 163,
    key_frac: 0,
    name: "Canon EF 300mm f/4L",
  },
  CanonLensType {
    key_int: 164,
    key_frac: 0,
    name: "Canon EF 400mm f/5.6L",
  },
  CanonLensType {
    key_int: 165,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 166,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L USM + 1.4x",
  },
  CanonLensType {
    key_int: 167,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L USM + 2x",
  },
  CanonLensType {
    key_int: 168,
    key_frac: 0,
    name: "Canon EF 28mm f/1.8 USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 168,
    key_frac: 1,
    name: "Sigma 50-100mm f/1.8 DC HSM | A",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 0,
    name: "Canon EF 17-35mm f/2.8L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 1,
    name: "Sigma 18-200mm f/3.5-6.3 DC OS",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 2,
    name: "Sigma 15-30mm f/3.5-4.5 EX DG Aspherical",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 3,
    name: "Sigma 18-50mm f/2.8 Macro",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 4,
    name: "Sigma 50mm f/1.4 EX DG HSM",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 5,
    name: "Sigma 85mm f/1.4 EX DG HSM",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 6,
    name: "Sigma 30mm f/1.4 EX DC HSM",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 7,
    name: "Sigma 35mm f/1.4 DG HSM",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 8,
    name: "Sigma 35mm f/1.5 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 169,
    key_frac: 9,
    name: "Sigma 70mm f/2.8 Macro EX DG",
  },
  CanonLensType {
    key_int: 170,
    key_frac: 0,
    name: "Canon EF 200mm f/2.8L II USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 170,
    key_frac: 1,
    name: "Sigma 300mm f/2.8 APO EX DG HSM",
  },
  CanonLensType {
    key_int: 170,
    key_frac: 2,
    name: "Sigma 800mm f/5.6 APO EX DG HSM",
  },
  CanonLensType {
    key_int: 171,
    key_frac: 0,
    name: "Canon EF 300mm f/4L USM",
  },
  CanonLensType {
    key_int: 172,
    key_frac: 0,
    name: "Canon EF 400mm f/5.6L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 172,
    key_frac: 1,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | S",
  },
  CanonLensType {
    key_int: 172,
    key_frac: 2,
    name: "Sigma 500mm f/4.5 APO EX DG HSM",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 0,
    name: "Canon EF 180mm Macro f/3.5L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 1,
    name: "Sigma 180mm EX HSM Macro f/3.5",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 2,
    name: "Sigma APO Macro 150mm f/2.8 EX DG HSM",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 3,
    name: "Sigma 10mm f/2.8 EX DC Fisheye",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 4,
    name: "Sigma 15mm f/2.8 EX DG Diagonal Fisheye",
  },
  CanonLensType {
    key_int: 173,
    key_frac: 5,
    name: "Venus Laowa 100mm F2.8 2X Ultra Macro APO",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 0,
    name: "Canon EF 135mm f/2L USM or Other Lens",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 1,
    name: "Sigma 70-200mm f/2.8 EX DG APO OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 2,
    name: "Sigma 50-500mm f/4.5-6.3 APO DG OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 3,
    name: "Sigma 150-500mm f/5-6.3 APO DG OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 4,
    name: "Zeiss Milvus 100mm f/2 Makro",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 5,
    name: "Sigma APO 50-150mm f/2.8 EX DC OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 6,
    name: "Sigma APO 120-300mm f/2.8 EX DG OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 7,
    name: "Sigma 120-300mm f/2.8 DG OS HSM S013",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 8,
    name: "Sigma 120-400mm f/4.5-5.6 APO DG OS HSM",
  },
  CanonLensType {
    key_int: 174,
    key_frac: 9,
    name: "Sigma 200-500mm f/2.8 APO EX DG",
  },
  CanonLensType {
    key_int: 175,
    key_frac: 0,
    name: "Canon EF 400mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 176,
    key_frac: 0,
    name: "Canon EF 24-85mm f/3.5-4.5 USM",
  },
  CanonLensType {
    key_int: 177,
    key_frac: 0,
    name: "Canon EF 300mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 178,
    key_frac: 0,
    name: "Canon EF 28-135mm f/3.5-5.6 IS",
  },
  CanonLensType {
    key_int: 179,
    key_frac: 0,
    name: "Canon EF 24mm f/1.4L USM",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 0,
    name: "Canon EF 35mm f/1.4L USM or Other Lens",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 1,
    name: "Sigma 50mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 2,
    name: "Sigma 24mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 3,
    name: "Zeiss Milvus 50mm f/1.4",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 4,
    name: "Zeiss Milvus 85mm f/1.4",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 5,
    name: "Zeiss Otus 28mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 6,
    name: "Sigma 24mm f/1.5 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 7,
    name: "Sigma 50mm f/1.5 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 8,
    name: "Sigma 85mm f/1.5 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 9,
    name: "Tokina Opera 50mm f/1.4 FF",
  },
  CanonLensType {
    key_int: 180,
    key_frac: 10,
    name: "Sigma 20mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 181,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS USM + 1.4x or Sigma Lens",
  },
  CanonLensType {
    key_int: 181,
    key_frac: 1,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | S + 1.4x",
  },
  CanonLensType {
    key_int: 182,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS USM + 2x or Sigma Lens",
  },
  CanonLensType {
    key_int: 182,
    key_frac: 1,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | S + 2x",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 1,
    name: "Sigma 150mm f/2.8 EX DG OS HSM APO Macro",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 2,
    name: "Sigma 105mm f/2.8 EX DG OS HSM Macro",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 3,
    name: "Sigma 180mm f/2.8 EX DG OS HSM APO Macro",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 4,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | C",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 5,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | S",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 6,
    name: "Sigma 100-400mm f/5-6.3 DG OS HSM",
  },
  CanonLensType {
    key_int: 183,
    key_frac: 7,
    name: "Sigma 180mm f/3.5 APO Macro EX DG IF HSM",
  },
  CanonLensType {
    key_int: 184,
    key_frac: 0,
    name: "Canon EF 400mm f/2.8L USM + 2x",
  },
  CanonLensType {
    key_int: 185,
    key_frac: 0,
    name: "Canon EF 600mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 186,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L USM",
  },
  CanonLensType {
    key_int: 187,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L USM + 1.4x",
  },
  CanonLensType {
    key_int: 188,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L USM + 2x",
  },
  CanonLensType {
    key_int: 189,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L USM + 2.8x",
  },
  CanonLensType {
    key_int: 190,
    key_frac: 0,
    name: "Canon EF 100mm f/2.8 Macro USM",
  },
  CanonLensType {
    key_int: 191,
    key_frac: 0,
    name: "Canon EF 400mm f/4 DO IS or Sigma Lens",
  },
  CanonLensType {
    key_int: 191,
    key_frac: 1,
    name: "Sigma 500mm f/4 DG OS HSM",
  },
  CanonLensType {
    key_int: 193,
    key_frac: 0,
    name: "Canon EF 35-80mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 194,
    key_frac: 0,
    name: "Canon EF 80-200mm f/4.5-5.6 USM",
  },
  CanonLensType {
    key_int: 195,
    key_frac: 0,
    name: "Canon EF 35-105mm f/4.5-5.6 USM",
  },
  CanonLensType {
    key_int: 196,
    key_frac: 0,
    name: "Canon EF 75-300mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 197,
    key_frac: 0,
    name: "Canon EF 75-300mm f/4-5.6 IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 197,
    key_frac: 1,
    name: "Sigma 18-300mm f/3.5-6.3 DC Macro OS HSM",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 0,
    name: "Canon EF 50mm f/1.4 USM or Other Lens",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 1,
    name: "Zeiss Otus 55mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 2,
    name: "Zeiss Otus 85mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 3,
    name: "Zeiss Milvus 25mm f/1.4",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 4,
    name: "Zeiss Otus 100mm f/1.4",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 5,
    name: "Zeiss Milvus 35mm f/1.4 ZE",
  },
  CanonLensType {
    key_int: 198,
    key_frac: 6,
    name: "Yongnuo YN 35mm f/2",
  },
  CanonLensType {
    key_int: 199,
    key_frac: 0,
    name: "Canon EF 28-80mm f/3.5-5.6 USM",
  },
  CanonLensType {
    key_int: 200,
    key_frac: 0,
    name: "Canon EF 75-300mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 201,
    key_frac: 0,
    name: "Canon EF 28-80mm f/3.5-5.6 USM",
  },
  CanonLensType {
    key_int: 202,
    key_frac: 0,
    name: "Canon EF 28-80mm f/3.5-5.6 USM IV",
  },
  CanonLensType {
    key_int: 208,
    key_frac: 0,
    name: "Canon EF 22-55mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 209,
    key_frac: 0,
    name: "Canon EF 55-200mm f/4.5-5.6",
  },
  CanonLensType {
    key_int: 210,
    key_frac: 0,
    name: "Canon EF 28-90mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 211,
    key_frac: 0,
    name: "Canon EF 28-200mm f/3.5-5.6 USM",
  },
  CanonLensType {
    key_int: 212,
    key_frac: 0,
    name: "Canon EF 28-105mm f/4-5.6 USM",
  },
  CanonLensType {
    key_int: 213,
    key_frac: 0,
    name: "Canon EF 90-300mm f/4.5-5.6 USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 213,
    key_frac: 1,
    name: "Tamron SP 150-600mm f/5-6.3 Di VC USD (A011)",
  },
  CanonLensType {
    key_int: 213,
    key_frac: 2,
    name: "Tamron 16-300mm f/3.5-6.3 Di II VC PZD Macro (B016)",
  },
  CanonLensType {
    key_int: 213,
    key_frac: 3,
    name: "Tamron SP 35mm f/1.8 Di VC USD (F012)",
  },
  CanonLensType {
    key_int: 213,
    key_frac: 4,
    name: "Tamron SP 45mm f/1.8 Di VC USD (F013)",
  },
  CanonLensType {
    key_int: 214,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 USM",
  },
  CanonLensType {
    key_int: 215,
    key_frac: 0,
    name: "Canon EF 55-200mm f/4.5-5.6 II USM",
  },
  CanonLensType {
    key_int: 217,
    key_frac: 0,
    name: "Tamron AF 18-270mm f/3.5-6.3 Di II VC PZD",
  },
  CanonLensType {
    key_int: 220,
    key_frac: 0,
    name: "Yongnuo YN 50mm f/1.8",
  },
  CanonLensType {
    key_int: 224,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS USM",
  },
  CanonLensType {
    key_int: 225,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS USM + 1.4x",
  },
  CanonLensType {
    key_int: 226,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS USM + 2x",
  },
  CanonLensType {
    key_int: 227,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS USM + 2.8x",
  },
  CanonLensType {
    key_int: 228,
    key_frac: 0,
    name: "Canon EF 28-105mm f/3.5-4.5 USM",
  },
  CanonLensType {
    key_int: 229,
    key_frac: 0,
    name: "Canon EF 16-35mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 230,
    key_frac: 0,
    name: "Canon EF 24-70mm f/2.8L USM",
  },
  CanonLensType {
    key_int: 231,
    key_frac: 0,
    name: "Canon EF 17-40mm f/4L USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 231,
    key_frac: 1,
    name: "Sigma 12-24mm f/4 DG HSM A016",
  },
  CanonLensType {
    key_int: 232,
    key_frac: 0,
    name: "Canon EF 70-300mm f/4.5-5.6 DO IS USM",
  },
  CanonLensType {
    key_int: 233,
    key_frac: 0,
    name: "Canon EF 28-300mm f/3.5-5.6L IS USM",
  },
  CanonLensType {
    key_int: 234,
    key_frac: 0,
    name: "Canon EF-S 17-85mm f/4-5.6 IS USM or Tokina Lens",
  },
  CanonLensType {
    key_int: 234,
    key_frac: 1,
    name: "Tokina AT-X 12-28 PRO DX 12-28mm f/4",
  },
  CanonLensType {
    key_int: 235,
    key_frac: 0,
    name: "Canon EF-S 10-22mm f/3.5-4.5 USM",
  },
  CanonLensType {
    key_int: 236,
    key_frac: 0,
    name: "Canon EF-S 60mm f/2.8 Macro USM",
  },
  CanonLensType {
    key_int: 237,
    key_frac: 0,
    name: "Canon EF 24-105mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 238,
    key_frac: 0,
    name: "Canon EF 70-300mm f/4-5.6 IS USM",
  },
  CanonLensType {
    key_int: 239,
    key_frac: 0,
    name: "Canon EF 85mm f/1.2L II USM or Rokinon Lens",
  },
  CanonLensType {
    key_int: 239,
    key_frac: 1,
    name: "Rokinon SP 85mm f/1.2",
  },
  CanonLensType {
    key_int: 240,
    key_frac: 0,
    name: "Canon EF-S 17-55mm f/2.8 IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 240,
    key_frac: 1,
    name: "Sigma 17-50mm f/2.8 EX DC OS HSM",
  },
  CanonLensType {
    key_int: 241,
    key_frac: 0,
    name: "Canon EF 50mm f/1.2L USM",
  },
  CanonLensType {
    key_int: 242,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 243,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L IS USM + 1.4x",
  },
  CanonLensType {
    key_int: 244,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L IS USM + 2x",
  },
  CanonLensType {
    key_int: 245,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L IS USM + 2.8x",
  },
  CanonLensType {
    key_int: 246,
    key_frac: 0,
    name: "Canon EF 16-35mm f/2.8L II USM",
  },
  CanonLensType {
    key_int: 247,
    key_frac: 0,
    name: "Canon EF 14mm f/2.8L II USM",
  },
  CanonLensType {
    key_int: 248,
    key_frac: 0,
    name: "Canon EF 200mm f/2L IS USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 248,
    key_frac: 1,
    name: "Sigma 24-35mm f/2 DG HSM | A",
  },
  CanonLensType {
    key_int: 248,
    key_frac: 2,
    name: "Sigma 135mm f/2 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 248,
    key_frac: 3,
    name: "Sigma 24-35mm f/2.2 FF Zoom | 017",
  },
  CanonLensType {
    key_int: 248,
    key_frac: 4,
    name: "Sigma 135mm f/1.8 DG HSM A017",
  },
  CanonLensType {
    key_int: 249,
    key_frac: 0,
    name: "Canon EF 800mm f/5.6L IS USM",
  },
  CanonLensType {
    key_int: 250,
    key_frac: 0,
    name: "Canon EF 24mm f/1.4L II USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 250,
    key_frac: 1,
    name: "Sigma 20mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 250,
    key_frac: 2,
    name: "Sigma 20mm f/1.5 FF High-Speed Prime | 017",
  },
  CanonLensType {
    key_int: 250,
    key_frac: 3,
    name: "Tokina Opera 16-28mm f/2.8 FF",
  },
  CanonLensType {
    key_int: 250,
    key_frac: 4,
    name: "Sigma 85mm f/1.4 DG HSM A016",
  },
  CanonLensType {
    key_int: 251,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS II USM",
  },
  CanonLensType {
    key_int: 251,
    key_frac: 1,
    name: "Canon EF 70-200mm f/2.8L IS III USM",
  },
  CanonLensType {
    key_int: 252,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS II USM + 1.4x",
  },
  CanonLensType {
    key_int: 252,
    key_frac: 1,
    name: "Canon EF 70-200mm f/2.8L IS III USM + 1.4x",
  },
  CanonLensType {
    key_int: 253,
    key_frac: 0,
    name: "Canon EF 70-200mm f/2.8L IS II USM + 2x",
  },
  CanonLensType {
    key_int: 253,
    key_frac: 1,
    name: "Canon EF 70-200mm f/2.8L IS III USM + 2x",
  },
  CanonLensType {
    key_int: 254,
    key_frac: 0,
    name: "Canon EF 100mm f/2.8L Macro IS USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 254,
    key_frac: 1,
    name: "Tamron SP 90mm f/2.8 Di VC USD 1:1 Macro (F017)",
  },
  CanonLensType {
    key_int: 255,
    key_frac: 0,
    name: "Sigma 24-105mm f/4 DG OS HSM | A or Other Lens",
  },
  CanonLensType {
    key_int: 255,
    key_frac: 1,
    name: "Sigma 180mm f/2.8 EX DG OS HSM APO Macro",
  },
  CanonLensType {
    key_int: 255,
    key_frac: 2,
    name: "Tamron SP 70-200mm f/2.8 Di VC USD",
  },
  CanonLensType {
    key_int: 255,
    key_frac: 3,
    name: "Yongnuo YN 50mm f/1.8",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 0,
    name: "Sigma 14-24mm f/2.8 DG HSM | A or other Sigma Lens",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 1,
    name: "Sigma 20mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 2,
    name: "Sigma 50mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 3,
    name: "Sigma 40mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 4,
    name: "Sigma 60-600mm f/4.5-6.3 DG OS HSM | S",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 5,
    name: "Sigma 28mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 6,
    name: "Sigma 150-600mm f/5-6.3 DG OS HSM | S",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 7,
    name: "Sigma 85mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 8,
    name: "Sigma 105mm f/1.4 DG HSM",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 9,
    name: "Sigma 14-24mm f/2.8 DG HSM",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 10,
    name: "Sigma 35mm f/1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 11,
    name: "Sigma 70mm f/2.8 DG Macro",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 12,
    name: "Sigma 18-35mm f/1.8 DC HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 13,
    name: "Sigma 24-105mm f/4 DG OS HSM | A",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 14,
    name: "Sigma 18-300mm f/3.5-6.3 DC Macro OS HSM | C",
  },
  CanonLensType {
    key_int: 368,
    key_frac: 15,
    name: "Sigma 24mm F1.4 DG HSM | A",
  },
  CanonLensType {
    key_int: 488,
    key_frac: 0,
    name: "Canon EF-S 15-85mm f/3.5-5.6 IS USM",
  },
  CanonLensType {
    key_int: 489,
    key_frac: 0,
    name: "Canon EF 70-300mm f/4-5.6L IS USM",
  },
  CanonLensType {
    key_int: 490,
    key_frac: 0,
    name: "Canon EF 8-15mm f/4L Fisheye USM",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 0,
    name: "Canon EF 300mm f/2.8L IS II USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 1,
    name: "Tamron SP 70-200mm f/2.8 Di VC USD G2 (A025)",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 2,
    name: "Tamron 18-400mm f/3.5-6.3 Di II VC HLD (B028)",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 3,
    name: "Tamron 100-400mm f/4.5-6.3 Di VC USD (A035)",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 4,
    name: "Tamron 70-210mm f/4 Di VC USD (A034)",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 5,
    name: "Tamron 70-210mm f/4 Di VC USD (A034) + 1.4x",
  },
  CanonLensType {
    key_int: 491,
    key_frac: 6,
    name: "Tamron SP 24-70mm f/2.8 Di VC USD G2 (A032)",
  },
  CanonLensType {
    key_int: 492,
    key_frac: 0,
    name: "Canon EF 400mm f/2.8L IS II USM",
  },
  CanonLensType {
    key_int: 493,
    key_frac: 0,
    name: "Canon EF 500mm f/4L IS II USM or EF 24-105mm f4L IS USM",
  },
  CanonLensType {
    key_int: 493,
    key_frac: 1,
    name: "Canon EF 24-105mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 494,
    key_frac: 0,
    name: "Canon EF 600mm f/4L IS II USM",
  },
  CanonLensType {
    key_int: 495,
    key_frac: 0,
    name: "Canon EF 24-70mm f/2.8L II USM or Sigma Lens",
  },
  CanonLensType {
    key_int: 495,
    key_frac: 1,
    name: "Sigma 24-70mm f/2.8 DG OS HSM | A",
  },
  CanonLensType {
    key_int: 496,
    key_frac: 0,
    name: "Canon EF 200-400mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 499,
    key_frac: 0,
    name: "Canon EF 200-400mm f/4L IS USM + 1.4x",
  },
  CanonLensType {
    key_int: 502,
    key_frac: 0,
    name: "Canon EF 28mm f/2.8 IS USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 502,
    key_frac: 1,
    name: "Tamron 35mm f/1.8 Di VC USD (F012)",
  },
  CanonLensType {
    key_int: 503,
    key_frac: 0,
    name: "Canon EF 24mm f/2.8 IS USM",
  },
  CanonLensType {
    key_int: 504,
    key_frac: 0,
    name: "Canon EF 24-70mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 505,
    key_frac: 0,
    name: "Canon EF 35mm f/2 IS USM",
  },
  CanonLensType {
    key_int: 506,
    key_frac: 0,
    name: "Canon EF 400mm f/4 DO IS II USM",
  },
  CanonLensType {
    key_int: 507,
    key_frac: 0,
    name: "Canon EF 16-35mm f/4L IS USM",
  },
  CanonLensType {
    key_int: 508,
    key_frac: 0,
    name: "Canon EF 11-24mm f/4L USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 508,
    key_frac: 1,
    name: "Tamron 10-24mm f/3.5-4.5 Di II VC HLD (B023)",
  },
  CanonLensType {
    key_int: 624,
    key_frac: 0,
    name: "Sigma 70-200mm f/2.8 DG OS HSM | S or other Sigma Lens",
  },
  CanonLensType {
    key_int: 624,
    key_frac: 1,
    name: "Sigma 150-600mm f/5-6.3 | C",
  },
  CanonLensType {
    key_int: 747,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS II USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 747,
    key_frac: 1,
    name: "Tamron SP 150-600mm f/5-6.3 Di VC USD G2",
  },
  CanonLensType {
    key_int: 748,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS II USM + 1.4x or Tamron Lens",
  },
  CanonLensType {
    key_int: 748,
    key_frac: 1,
    name: "Tamron 100-400mm f/4.5-6.3 Di VC USD A035E + 1.4x",
  },
  CanonLensType {
    key_int: 748,
    key_frac: 2,
    name: "Tamron 70-210mm f/4 Di VC USD (A034) + 2x",
  },
  CanonLensType {
    key_int: 749,
    key_frac: 0,
    name: "Canon EF 100-400mm f/4.5-5.6L IS II USM + 2x or Tamron Lens",
  },
  CanonLensType {
    key_int: 749,
    key_frac: 1,
    name: "Tamron 100-400mm f/4.5-6.3 Di VC USD A035E + 2x",
  },
  CanonLensType {
    key_int: 750,
    key_frac: 0,
    name: "Canon EF 35mm f/1.4L II USM or Tamron Lens",
  },
  CanonLensType {
    key_int: 750,
    key_frac: 1,
    name: "Tamron SP 85mm f/1.8 Di VC USD (F016)",
  },
  CanonLensType {
    key_int: 750,
    key_frac: 2,
    name: "Tamron SP 45mm f/1.8 Di VC USD (F013)",
  },
  CanonLensType {
    key_int: 751,
    key_frac: 0,
    name: "Canon EF 16-35mm f/2.8L III USM",
  },
  CanonLensType {
    key_int: 752,
    key_frac: 0,
    name: "Canon EF 24-105mm f/4L IS II USM",
  },
  CanonLensType {
    key_int: 753,
    key_frac: 0,
    name: "Canon EF 85mm f/1.4L IS USM",
  },
  CanonLensType {
    key_int: 754,
    key_frac: 0,
    name: "Canon EF 70-200mm f/4L IS II USM",
  },
  CanonLensType {
    key_int: 757,
    key_frac: 0,
    name: "Canon EF 400mm f/2.8L IS III USM",
  },
  CanonLensType {
    key_int: 758,
    key_frac: 0,
    name: "Canon EF 600mm f/4L IS III USM",
  },
  CanonLensType {
    key_int: 923,
    key_frac: 0,
    name: "Meike/SKY 85mm f/1.8 DCM",
  },
  CanonLensType {
    key_int: 1136,
    key_frac: 0,
    name: "Sigma 24-70mm f/2.8 DG OS HSM | A",
  },
  CanonLensType {
    key_int: 4142,
    key_frac: 0,
    name: "Canon EF-S 18-135mm f/3.5-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4143,
    key_frac: 0,
    name: "Canon EF-M 18-55mm f/3.5-5.6 IS STM or Tamron Lens",
  },
  CanonLensType {
    key_int: 4143,
    key_frac: 1,
    name: "Tamron 18-200mm f/3.5-6.3 Di III VC",
  },
  CanonLensType {
    key_int: 4144,
    key_frac: 0,
    name: "Canon EF 40mm f/2.8 STM",
  },
  CanonLensType {
    key_int: 4145,
    key_frac: 0,
    name: "Canon EF-M 22mm f/2 STM",
  },
  CanonLensType {
    key_int: 4146,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/3.5-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4147,
    key_frac: 0,
    name: "Canon EF-M 11-22mm f/4-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4148,
    key_frac: 0,
    name: "Canon EF-S 55-250mm f/4-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4149,
    key_frac: 0,
    name: "Canon EF-M 55-200mm f/4.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 4150,
    key_frac: 0,
    name: "Canon EF-S 10-18mm f/4.5-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4152,
    key_frac: 0,
    name: "Canon EF 24-105mm f/3.5-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4153,
    key_frac: 0,
    name: "Canon EF-M 15-45mm f/3.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 4154,
    key_frac: 0,
    name: "Canon EF-S 24mm f/2.8 STM",
  },
  CanonLensType {
    key_int: 4155,
    key_frac: 0,
    name: "Canon EF-M 28mm f/3.5 Macro IS STM",
  },
  CanonLensType {
    key_int: 4156,
    key_frac: 0,
    name: "Canon EF 50mm f/1.8 STM",
  },
  CanonLensType {
    key_int: 4157,
    key_frac: 0,
    name: "Canon EF-M 18-150mm f/3.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 4158,
    key_frac: 0,
    name: "Canon EF-S 18-55mm f/4-5.6 IS STM",
  },
  CanonLensType {
    key_int: 4159,
    key_frac: 0,
    name: "Canon EF-M 32mm f/1.4 STM",
  },
  CanonLensType {
    key_int: 4160,
    key_frac: 0,
    name: "Canon EF-S 35mm f/2.8 Macro IS STM",
  },
  CanonLensType {
    key_int: 4208,
    key_frac: 0,
    name: "Sigma 56mm f/1.4 DC DN | C or other Sigma Lens",
  },
  CanonLensType {
    key_int: 4208,
    key_frac: 1,
    name: "Sigma 30mm F1.4 DC DN | C",
  },
  CanonLensType {
    key_int: 4976,
    key_frac: 0,
    name: "Sigma 16-300mm F3.5-6.7 DC OS | C (025)",
  },
  CanonLensType {
    key_int: 6512,
    key_frac: 0,
    name: "Sigma 12mm F1.4 DC | C",
  },
  CanonLensType {
    key_int: 36910,
    key_frac: 0,
    name: "Canon EF 70-300mm f/4-5.6 IS II USM",
  },
  CanonLensType {
    key_int: 36912,
    key_frac: 0,
    name: "Canon EF-S 18-135mm f/3.5-5.6 IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 0,
    name: "Canon RF 50mm F1.2L USM or other Canon RF Lens",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 1,
    name: "Canon RF 24-105mm F4L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 2,
    name: "Canon RF 28-70mm F2L USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 3,
    name: "Canon RF 35mm F1.8 MACRO IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 4,
    name: "Canon RF 85mm F1.2L USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 5,
    name: "Canon RF 85mm F1.2L USM DS",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 6,
    name: "Canon RF 24-70mm F2.8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 7,
    name: "Canon RF 15-35mm F2.8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 8,
    name: "Canon RF 24-240mm F4-6.3 IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 9,
    name: "Canon RF 70-200mm F2.8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 10,
    name: "Canon RF 85mm F2 MACRO IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 11,
    name: "Canon RF 600mm F11 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 12,
    name: "Canon RF 600mm F11 IS STM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 13,
    name: "Canon RF 600mm F11 IS STM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 14,
    name: "Canon RF 800mm F11 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 15,
    name: "Canon RF 800mm F11 IS STM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 16,
    name: "Canon RF 800mm F11 IS STM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 17,
    name: "Canon RF 24-105mm F4-7.1 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 18,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 19,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 20,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 21,
    name: "Canon RF 70-200mm F4L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 22,
    name: "Canon RF 100mm F2.8L MACRO IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 23,
    name: "Canon RF 50mm F1.8 STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 24,
    name: "Canon RF 14-35mm F4L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 25,
    name: "Canon RF-S 18-45mm F4.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 26,
    name: "Canon RF 100-400mm F5.6-8 IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 27,
    name: "Canon RF 100-400mm F5.6-8 IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 28,
    name: "Canon RF 100-400mm F5.6-8 IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 29,
    name: "Canon RF-S 18-150mm F3.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 30,
    name: "Canon RF 24mm F1.8 MACRO IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 31,
    name: "Canon RF 16mm F2.8 STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 32,
    name: "Canon RF 400mm F2.8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 33,
    name: "Canon RF 400mm F2.8L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 34,
    name: "Canon RF 400mm F2.8L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 35,
    name: "Canon RF 600mm F4L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 36,
    name: "Canon RF 600mm F4L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 37,
    name: "Canon RF 600mm F4L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 38,
    name: "Canon RF 800mm F5.6L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 39,
    name: "Canon RF 800mm F5.6L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 40,
    name: "Canon RF 800mm F5.6L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 41,
    name: "Canon RF 1200mm F8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 42,
    name: "Canon RF 1200mm F8L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 43,
    name: "Canon RF 1200mm F8L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 44,
    name: "Canon RF 5.2mm F2.8L Dual Fisheye 3D VR",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 45,
    name: "Canon RF 15-30mm F4.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 46,
    name: "Canon RF 135mm F1.8 L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 47,
    name: "Canon RF 24-50mm F4.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 48,
    name: "Canon RF-S 55-210mm F5-7.1 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 49,
    name: "Canon RF 100-300mm F2.8L IS USM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 50,
    name: "Canon RF 100-300mm F2.8L IS USM + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 51,
    name: "Canon RF 100-300mm F2.8L IS USM + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 52,
    name: "Canon RF 10-20mm F4 L IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 53,
    name: "Canon RF 28mm F2.8 STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 54,
    name: "Canon RF 24-105mm F2.8 L IS USM Z",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 55,
    name: "Canon RF-S 10-18mm F4.5-6.3 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 56,
    name: "Canon RF 35mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 57,
    name: "Canon RF 70-200mm F2.8 L IS USM Z",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 58,
    name: "Canon RF 70-200mm F2.8 L IS USM Z + RF1.4x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 59,
    name: "Canon RF 70-200mm F2.8 L IS USM Z + RF2x",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 60,
    name: "Canon RF 16-28mm F2.8 IS STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 61,
    name: "Canon RF-S 14-30mm F4-6.3 IS STM PZ",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 62,
    name: "Canon RF 50mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 63,
    name: "Canon RF 24mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 64,
    name: "Canon RF 20mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 65,
    name: "Canon RF 85mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 66,
    name: "Canon RF 20-50mm F4 L IS USM PZ",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 67,
    name: "Canon RF 45mm F1.2 STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 68,
    name: "Canon RF 7-14mm F2.8-3.5 L FISHEYE STM",
  },
  CanonLensType {
    key_int: 61182,
    key_frac: 69,
    name: "Canon RF 14mm F1.4 L VCM",
  },
  CanonLensType {
    key_int: 61491,
    key_frac: 0,
    name: "Canon CN-E 14mm T3.1 L F",
  },
  CanonLensType {
    key_int: 61492,
    key_frac: 0,
    name: "Canon CN-E 24mm T1.5 L F",
  },
  CanonLensType {
    key_int: 61494,
    key_frac: 0,
    name: "Canon CN-E 85mm T1.3 L F",
  },
  CanonLensType {
    key_int: 61495,
    key_frac: 0,
    name: "Canon CN-E 135mm T2.2 L F",
  },
  CanonLensType {
    key_int: 61496,
    key_frac: 0,
    name: "Canon CN-E 35mm T1.5 L F",
  },
  // The bundled `-1 => 'n/a'` (Canon.pm:98) — encoded as 65534 (one less
  // than 65535) so it stays representable in u16 and orders before 65535.
  CanonLensType {
    key_int: 65534,
    key_frac: 0,
    name: "n/a",
  },
  // `65535 => 'n/a'` (Canon.pm:653) — sentinel for "no lens".
  CanonLensType {
    key_int: 65535,
    key_frac: 0,
    name: "n/a",
  },
];

/// Look up a Canon lens-type ID. Returns the FIRST entry matching
/// `(key_int, 0)` (the integer-only entry) — bundled `PrintLensID`
/// prefers the integer entry first, then walks decimal siblings.
#[must_use]
pub fn lookup(key_int: u16) -> Option<&'static CanonLensType> {
  // Binary search on key_int with key_frac == 0 (the integer-only entry).
  let idx = CANON_LENS_TYPES
    .binary_search_by(|t| (t.key_int, t.key_frac).cmp(&(key_int, 0)))
    .ok()?;
  // `binary_search` returns an in-bounds index on `Ok`, so `.get(idx)` is
  // `Some` — the checked, byte-identical form of `Some(&CANON_LENS_TYPES[idx])`.
  CANON_LENS_TYPES.get(idx)
}

/// Resolve a lens-type ID into a [`SmolStr`] for storage in
/// `MakerNotesCanon::lens_model` — the bundled human-readable name
/// from `%canonLensTypes`.
#[must_use]
pub fn lookup_name(key_int: u16) -> Option<SmolStr> {
  lookup(key_int).map(|t| SmolStr::from(t.name))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn lens_table_sorted() {
    let mut prev = (0u16, 0u16);
    for t in CANON_LENS_TYPES {
      assert!(
        (t.key_int, t.key_frac) >= prev,
        "lens table out of order at ({}, {})",
        t.key_int,
        t.key_frac
      );
      prev = (t.key_int, t.key_frac);
    }
  }

  #[test]
  fn lookup_canon_ef_50mm_f1_8() {
    let t = lookup(1).expect("lens 1");
    assert_eq!(t.name, "Canon EF 50mm f/1.8");
  }

  #[test]
  fn lookup_canon_ef_28mm_f2_8() {
    let t = lookup(2).expect("lens 2");
    assert_eq!(t.name, "Canon EF 28mm f/2.8 or Sigma Lens");
  }

  #[test]
  fn lookup_unknown_returns_none() {
    assert!(lookup(63333).is_none());
  }

  #[test]
  fn ten_representative_lenses_resolve() {
    // Verify ten well-known lens IDs round-trip.
    let cases = [
      (1, "Canon EF 50mm f/1.8"),
      (124, "Canon MP-E 65mm f/2.8 1-5x Macro Photo"),
      (129, "Canon EF 300mm f/2.8L USM"),
      (130, "Canon EF 50mm f/1.0L USM"),
      (132, "Canon EF 1200mm f/5.6L USM"),
      (134, "Canon EF 600mm f/4L IS USM"),
      (135, "Canon EF 200mm f/1.8L USM"),
      (45, "Canon EF-S 18-55mm f/3.5-5.6 [II]"),
      (48, "Canon EF-S 18-55mm f/3.5-5.6 IS"),
      (95, "Canon TS-E 24mm f/3.5L II"),
    ];
    for (id, expected_name) in cases {
      let t = lookup(id).expect("known lens");
      assert_eq!(t.name, expected_name, "lens id {id}");
    }
  }

  /// `%canonLensTypes` RF-sibling tail (`Canon.pm:646-652`). The `61182.66`
  /// `Canon RF 20-50mm F4 L IS USM PZ` entry was MISSING, shifting `.66`-`.68`
  /// by one and dropping `.69`. Assert the corrected `(61182, NN)` siblings.
  #[test]
  fn rf_sibling_tail_matches_canon_pm() {
    let expected: &[(u16, &str)] = &[
      (63, "Canon RF 24mm F1.4 L VCM"),               // Canon.pm:646
      (64, "Canon RF 20mm F1.4 L VCM"),               // Canon.pm:647
      (65, "Canon RF 85mm F1.4 L VCM"),               // Canon.pm:648
      (66, "Canon RF 20-50mm F4 L IS USM PZ"),        // Canon.pm:649
      (67, "Canon RF 45mm F1.2 STM"),                 // Canon.pm:650
      (68, "Canon RF 7-14mm F2.8-3.5 L FISHEYE STM"), // Canon.pm:651
      (69, "Canon RF 14mm F1.4 L VCM"),               // Canon.pm:652
    ];
    for &(frac, name) in expected {
      let found = CANON_LENS_TYPES
        .iter()
        .find(|t| t.key_int == 61182 && t.key_frac == frac)
        .unwrap_or_else(|| panic!("missing 61182.{frac}"));
      assert_eq!(found.name, name, "61182.{frac}");
    }
    // The shifted-out duplicates must NOT exist (only one .66 etc.).
    assert_eq!(
      CANON_LENS_TYPES
        .iter()
        .filter(|t| t.key_int == 61182 && t.key_frac == 66)
        .count(),
      1
    );
    // .70 must not exist (tail ends at .69).
    assert!(
      !CANON_LENS_TYPES
        .iter()
        .any(|t| t.key_int == 61182 && t.key_frac == 70)
    );
  }
}
