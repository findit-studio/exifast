// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Pentax world-time city lookup — `%pentaxCities` (`Pentax.pm:575-...`), the
//! `PrintConv` for `HometownCity` (`0x0023`) and `DestinationCity` (`0x0024`),
//! both `int16u`.
//!
//! 75 rows, sorted by ID for binary search.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// `%pentaxCities` rows — `(id, name)`, sorted by `id` (binary-search-ready).
pub const PENTAX_CITIES: &[(u16, &str)] = &[
  (0, "Pago Pago"),
  (1, "Honolulu"),
  (2, "Anchorage"),
  (3, "Vancouver"),
  (4, "San Francisco"),
  (5, "Los Angeles"),
  (6, "Calgary"),
  (7, "Denver"),
  (8, "Mexico City"),
  (9, "Chicago"),
  (10, "Miami"),
  (11, "Toronto"),
  (12, "New York"),
  (13, "Santiago"),
  (14, "Caracus"),
  (15, "Halifax"),
  (16, "Buenos Aires"),
  (17, "Sao Paulo"),
  (18, "Rio de Janeiro"),
  (19, "Madrid"),
  (20, "London"),
  (21, "Paris"),
  (22, "Milan"),
  (23, "Rome"),
  (24, "Berlin"),
  (25, "Johannesburg"),
  (26, "Istanbul"),
  (27, "Cairo"),
  (28, "Jerusalem"),
  (29, "Moscow"),
  (30, "Jeddah"),
  (31, "Tehran"),
  (32, "Dubai"),
  (33, "Karachi"),
  (34, "Kabul"),
  (35, "Male"),
  (36, "Delhi"),
  (37, "Colombo"),
  (38, "Kathmandu"),
  (39, "Dacca"),
  (40, "Yangon"),
  (41, "Bangkok"),
  (42, "Kuala Lumpur"),
  (43, "Vientiane"),
  (44, "Singapore"),
  (45, "Phnom Penh"),
  (46, "Ho Chi Minh"),
  (47, "Jakarta"),
  (48, "Hong Kong"),
  (49, "Perth"),
  (50, "Beijing"),
  (51, "Shanghai"),
  (52, "Manila"),
  (53, "Taipei"),
  (54, "Seoul"),
  (55, "Adelaide"),
  (56, "Tokyo"),
  (57, "Guam"),
  (58, "Sydney"),
  (59, "Noumea"),
  (60, "Wellington"),
  (61, "Auckland"),
  (62, "Lima"),
  (63, "Dakar"),
  (64, "Algiers"),
  (65, "Helsinki"),
  (66, "Athens"),
  (67, "Nairobi"),
  (68, "Amsterdam"),
  (69, "Stockholm"),
  (70, "Lisbon"),
  (71, "Copenhagen"),
  (72, "Warsaw"),
  (73, "Prague"),
  (74, "Budapest"),
];

/// Look up a Pentax world-time city ID against `%pentaxCities`. Returns the
/// city name, or `None` when the ID is absent.
#[must_use]
pub fn lookup_name(id: u16) -> Option<SmolStr> {
  match PENTAX_CITIES.binary_search_by_key(&id, |&(k, _)| k) {
    Ok(i) => PENTAX_CITIES.get(i).map(|&(_, name)| SmolStr::from(name)),
    Err(_) => None,
  }
}

#[cfg(test)]
mod tests;
