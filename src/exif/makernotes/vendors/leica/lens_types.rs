// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%leicaLensTypes` (`Panasonic.pm:46-133`) — the shared Leica M lens lookup,
//! referenced by the `LensType` PrintConv on Leica2 0x310, the M9 `Subdir`
//! 0x3405, and `Data1` 0x0016 (`Panasonic.pm:1644`/`1894`/`1980`).
//!
//! The key is a STRING — ExifTool splits the stored int32u value into
//! `"<id> <bits>"` (`($val>>2)." ".($val&0x3)`), and the PrintConv tries the
//! full `"id bits"` key first, then (the table's `OTHER` closure,
//! `Panasonic.pm:48-52`) the bare leading integer. So the table carries BOTH
//! integer-string keys (`"6"`) and `"id bits"` keys (`"6 0"`) verbatim.
//!
//! Faithful 1:1 port against bundled ExifTool 13.59. Sorted by key string
//! (binary-search-ready).

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of the `%leicaLensTypes` lookup.
#[derive(Debug, Clone, Copy)]
pub struct LeicaLensType {
  /// The lookup key — either a bare integer string (`"6"`) or an `"id bits"`
  /// string (`"6 0"`), kept exactly as the bundled hash key.
  pub key: &'static str,
  /// The lens name (verbatim from bundled).
  pub name: &'static str,
}

/// `%leicaLensTypes` rows — sorted by key string (binary-search-ready).
pub const LEICA_LENS_TYPES: &[LeicaLensType] = &[
  LeicaLensType {
    key: "0 0",
    name: "Uncoded lens",
  },
  LeicaLensType {
    key: "1",
    name: "Elmarit-M 21mm f/2.8",
  },
  LeicaLensType {
    key: "11",
    name: "Summaron-M 28mm f/5.6",
  },
  LeicaLensType {
    key: "12",
    name: "Thambar-M 90mm f/2.2",
  },
  LeicaLensType {
    key: "16",
    name: "Tri-Elmar-M 16-18-21mm f/4 ASPH.",
  },
  LeicaLensType {
    key: "16 1",
    name: "Tri-Elmar-M 16-18-21mm f/4 ASPH. (at 16mm)",
  },
  LeicaLensType {
    key: "16 2",
    name: "Tri-Elmar-M 16-18-21mm f/4 ASPH. (at 18mm)",
  },
  LeicaLensType {
    key: "16 3",
    name: "Tri-Elmar-M 16-18-21mm f/4 ASPH. (at 21mm)",
  },
  LeicaLensType {
    key: "23",
    name: "Summicron-M 50mm f/2 (III)",
  },
  LeicaLensType {
    key: "24",
    name: "Elmarit-M 21mm f/2.8 ASPH.",
  },
  LeicaLensType {
    key: "25",
    name: "Elmarit-M 24mm f/2.8 ASPH.",
  },
  LeicaLensType {
    key: "26",
    name: "Summicron-M 28mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "27",
    name: "Elmarit-M 28mm f/2.8 (IV)",
  },
  LeicaLensType {
    key: "28",
    name: "Elmarit-M 28mm f/2.8 ASPH.",
  },
  LeicaLensType {
    key: "29",
    name: "Summilux-M 35mm f/1.4 ASPH.",
  },
  LeicaLensType {
    key: "29 0",
    name: "Summilux-M 35mm f/1.4 ASPHERICAL",
  },
  LeicaLensType {
    key: "3",
    name: "Elmarit-M 28mm f/2.8 (III)",
  },
  LeicaLensType {
    key: "30",
    name: "Summicron-M 35mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "31",
    name: "Noctilux-M 50mm f/1",
  },
  LeicaLensType {
    key: "31 0",
    name: "Noctilux-M 50mm f/1.2",
  },
  LeicaLensType {
    key: "32",
    name: "Summilux-M 50mm f/1.4 ASPH.",
  },
  LeicaLensType {
    key: "33",
    name: "Summicron-M 50mm f/2 (IV, V)",
  },
  LeicaLensType {
    key: "34",
    name: "Elmar-M 50mm f/2.8",
  },
  LeicaLensType {
    key: "35",
    name: "Summilux-M 75mm f/1.4",
  },
  LeicaLensType {
    key: "36",
    name: "Apo-Summicron-M 75mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "37",
    name: "Apo-Summicron-M 90mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "38",
    name: "Elmarit-M 90mm f/2.8",
  },
  LeicaLensType {
    key: "39",
    name: "Macro-Elmar-M 90mm f/4",
  },
  LeicaLensType {
    key: "39 0",
    name: "Tele-Elmar-M 135mm f/4 (II)",
  },
  LeicaLensType {
    key: "4",
    name: "Tele-Elmarit-M 90mm f/2.8 (II)",
  },
  LeicaLensType {
    key: "40",
    name: "Macro-Adapter M",
  },
  LeicaLensType {
    key: "41",
    name: "Apo-Summicron-M 50mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "41 3",
    name: "Apo-Summicron-M 50mm f/2 ASPH.",
  },
  LeicaLensType {
    key: "42",
    name: "Tri-Elmar-M 28-35-50mm f/4 ASPH.",
  },
  LeicaLensType {
    key: "42 1",
    name: "Tri-Elmar-M 28-35-50mm f/4 ASPH. (at 28mm)",
  },
  LeicaLensType {
    key: "42 2",
    name: "Tri-Elmar-M 28-35-50mm f/4 ASPH. (at 35mm)",
  },
  LeicaLensType {
    key: "42 3",
    name: "Tri-Elmar-M 28-35-50mm f/4 ASPH. (at 50mm)",
  },
  LeicaLensType {
    key: "43",
    name: "Summarit-M 35mm f/2.5",
  },
  LeicaLensType {
    key: "44",
    name: "Summarit-M 50mm f/2.5",
  },
  LeicaLensType {
    key: "45",
    name: "Summarit-M 75mm f/2.5",
  },
  LeicaLensType {
    key: "46",
    name: "Summarit-M 90mm f/2.5",
  },
  LeicaLensType {
    key: "47",
    name: "Summilux-M 21mm f/1.4 ASPH.",
  },
  LeicaLensType {
    key: "48",
    name: "Summilux-M 24mm f/1.4 ASPH.",
  },
  LeicaLensType {
    key: "49",
    name: "Noctilux-M 50mm f/0.95 ASPH.",
  },
  LeicaLensType {
    key: "5",
    name: "Summilux-M 50mm f/1.4 (II)",
  },
  LeicaLensType {
    key: "50",
    name: "Elmar-M 24mm f/3.8 ASPH.",
  },
  LeicaLensType {
    key: "51",
    name: "Super-Elmar-M 21mm f/3.4 Asph",
  },
  LeicaLensType {
    key: "51 2",
    name: "Super-Elmar-M 14mm f/3.8 Asph",
  },
  LeicaLensType {
    key: "52",
    name: "Apo-Telyt-M 18mm f/3.8 ASPH.",
  },
  LeicaLensType {
    key: "53",
    name: "Apo-Telyt-M 135mm f/3.4",
  },
  LeicaLensType {
    key: "53 2",
    name: "Apo-Telyt-M 135mm f/3.4",
  },
  LeicaLensType {
    key: "53 3",
    name: "Apo-Summicron-M 50mm f/2 (VI)",
  },
  LeicaLensType {
    key: "58",
    name: "Noctilux-M 75mm f/1.25 ASPH.",
  },
  LeicaLensType {
    key: "6",
    name: "Summicron-M 35mm f/2 (IV)",
  },
  LeicaLensType {
    key: "6 0",
    name: "Summilux-M 35mm f/1.4",
  },
  LeicaLensType {
    key: "7",
    name: "Summicron-M 90mm f/2 (II)",
  },
  LeicaLensType {
    key: "9",
    name: "Elmarit-M 135mm f/2.8 (I/II)",
  },
  LeicaLensType {
    key: "9 0",
    name: "Apo-Telyt-M 135mm f/3.4",
  },
];

/// Resolve a `%leicaLensTypes` key (an `"id bits"` or bare-`"id"` string) to its
/// lens name. `None` ⇒ the key is not in the table (the caller then tries the
/// leading-integer fallback, and failing that keeps the ValueConv string).
#[must_use]
pub fn lookup_name(key: &str) -> Option<SmolStr> {
  match LEICA_LENS_TYPES.binary_search_by(|e| e.key.cmp(key)) {
    Ok(i) => LEICA_LENS_TYPES.get(i).map(|e| SmolStr::from(e.name)),
    Err(_) => None,
  }
}
