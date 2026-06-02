// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony body model-ID lookup — the inline PrintConv at
//! `Sony.pm:2131-2248` (the `0xb001 SonyModelID` tag).
//!
//! 112 model-ID rows ported as a binary-search-sorted const array.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of the Sony Model-ID lookup.
#[derive(Debug, Clone, Copy)]
pub struct SonyModelEntry {
  /// The Sony model ID (int16u value from `0xb001`).
  pub id: u16,
  /// The body name.
  pub name: &'static str,
}

/// Sony model-ID rows — sorted by ID (binary-search-ready).
pub const SONY_MODEL_IDS: &[SonyModelEntry] = &[
  SonyModelEntry {
    id: 2,
    name: "DSC-R1",
  },
  SonyModelEntry {
    id: 256,
    name: "DSLR-A100",
  },
  SonyModelEntry {
    id: 257,
    name: "DSLR-A900",
  },
  SonyModelEntry {
    id: 258,
    name: "DSLR-A700",
  },
  SonyModelEntry {
    id: 259,
    name: "DSLR-A200",
  },
  SonyModelEntry {
    id: 260,
    name: "DSLR-A350",
  },
  SonyModelEntry {
    id: 261,
    name: "DSLR-A300",
  },
  SonyModelEntry {
    id: 262,
    name: "DSLR-A900 (APS-C mode)",
  },
  SonyModelEntry {
    id: 263,
    name: "DSLR-A380/A390",
  },
  SonyModelEntry {
    id: 264,
    name: "DSLR-A330",
  },
  SonyModelEntry {
    id: 265,
    name: "DSLR-A230",
  },
  SonyModelEntry {
    id: 266,
    name: "DSLR-A290",
  },
  SonyModelEntry {
    id: 269,
    name: "DSLR-A850",
  },
  SonyModelEntry {
    id: 270,
    name: "DSLR-A850 (APS-C mode)",
  },
  SonyModelEntry {
    id: 273,
    name: "DSLR-A550",
  },
  SonyModelEntry {
    id: 274,
    name: "DSLR-A500",
  },
  SonyModelEntry {
    id: 275,
    name: "DSLR-A450",
  },
  SonyModelEntry {
    id: 278,
    name: "NEX-5",
  },
  SonyModelEntry {
    id: 279,
    name: "NEX-3",
  },
  SonyModelEntry {
    id: 280,
    name: "SLT-A33",
  },
  SonyModelEntry {
    id: 281,
    name: "SLT-A55 / SLT-A55V",
  },
  SonyModelEntry {
    id: 282,
    name: "DSLR-A560",
  },
  SonyModelEntry {
    id: 283,
    name: "DSLR-A580",
  },
  SonyModelEntry {
    id: 284,
    name: "NEX-C3",
  },
  SonyModelEntry {
    id: 285,
    name: "SLT-A35",
  },
  SonyModelEntry {
    id: 286,
    name: "SLT-A65 / SLT-A65V",
  },
  SonyModelEntry {
    id: 287,
    name: "SLT-A77 / SLT-A77V",
  },
  SonyModelEntry {
    id: 288,
    name: "NEX-5N",
  },
  SonyModelEntry {
    id: 289,
    name: "NEX-7",
  },
  SonyModelEntry {
    id: 290,
    name: "NEX-VG20E",
  },
  SonyModelEntry {
    id: 291,
    name: "SLT-A37",
  },
  SonyModelEntry {
    id: 292,
    name: "SLT-A57",
  },
  SonyModelEntry {
    id: 293,
    name: "NEX-F3",
  },
  SonyModelEntry {
    id: 294,
    name: "SLT-A99 / SLT-A99V",
  },
  SonyModelEntry {
    id: 295,
    name: "NEX-6",
  },
  SonyModelEntry {
    id: 296,
    name: "NEX-5R",
  },
  SonyModelEntry {
    id: 297,
    name: "DSC-RX100",
  },
  SonyModelEntry {
    id: 298,
    name: "DSC-RX1",
  },
  SonyModelEntry {
    id: 299,
    name: "NEX-VG900",
  },
  SonyModelEntry {
    id: 300,
    name: "NEX-VG30E",
  },
  SonyModelEntry {
    id: 302,
    name: "ILCE-3000 / ILCE-3500",
  },
  SonyModelEntry {
    id: 303,
    name: "SLT-A58",
  },
  SonyModelEntry {
    id: 305,
    name: "NEX-3N",
  },
  SonyModelEntry {
    id: 306,
    name: "ILCE-7",
  },
  SonyModelEntry {
    id: 307,
    name: "NEX-5T",
  },
  SonyModelEntry {
    id: 308,
    name: "DSC-RX100M2",
  },
  SonyModelEntry {
    id: 309,
    name: "DSC-RX10",
  },
  SonyModelEntry {
    id: 310,
    name: "DSC-RX1R",
  },
  SonyModelEntry {
    id: 311,
    name: "ILCE-7R",
  },
  SonyModelEntry {
    id: 312,
    name: "ILCE-6000",
  },
  SonyModelEntry {
    id: 313,
    name: "ILCE-5000",
  },
  SonyModelEntry {
    id: 317,
    name: "DSC-RX100M3",
  },
  SonyModelEntry {
    id: 318,
    name: "ILCE-7S",
  },
  SonyModelEntry {
    id: 319,
    name: "ILCA-77M2",
  },
  SonyModelEntry {
    id: 339,
    name: "ILCE-5100",
  },
  SonyModelEntry {
    id: 340,
    name: "ILCE-7M2",
  },
  SonyModelEntry {
    id: 341,
    name: "DSC-RX100M4",
  },
  SonyModelEntry {
    id: 342,
    name: "DSC-RX10M2",
  },
  SonyModelEntry {
    id: 344,
    name: "DSC-RX1RM2",
  },
  SonyModelEntry {
    id: 346,
    name: "ILCE-QX1",
  },
  SonyModelEntry {
    id: 347,
    name: "ILCE-7RM2",
  },
  SonyModelEntry {
    id: 350,
    name: "ILCE-7SM2",
  },
  SonyModelEntry {
    id: 353,
    name: "ILCA-68",
  },
  SonyModelEntry {
    id: 354,
    name: "ILCA-99M2",
  },
  SonyModelEntry {
    id: 355,
    name: "DSC-RX10M3",
  },
  SonyModelEntry {
    id: 356,
    name: "DSC-RX100M5",
  },
  SonyModelEntry {
    id: 357,
    name: "ILCE-6300",
  },
  SonyModelEntry {
    id: 358,
    name: "ILCE-9",
  },
  SonyModelEntry {
    id: 360,
    name: "ILCE-6500",
  },
  SonyModelEntry {
    id: 362,
    name: "ILCE-7RM3",
  },
  SonyModelEntry {
    id: 363,
    name: "ILCE-7M3",
  },
  SonyModelEntry {
    id: 364,
    name: "DSC-RX0",
  },
  SonyModelEntry {
    id: 365,
    name: "DSC-RX10M4",
  },
  SonyModelEntry {
    id: 366,
    name: "DSC-RX100M6",
  },
  SonyModelEntry {
    id: 367,
    name: "DSC-HX99",
  },
  SonyModelEntry {
    id: 369,
    name: "DSC-RX100M5A",
  },
  SonyModelEntry {
    id: 371,
    name: "ILCE-6400",
  },
  SonyModelEntry {
    id: 372,
    name: "DSC-RX0M2",
  },
  SonyModelEntry {
    id: 373,
    name: "DSC-HX95",
  },
  SonyModelEntry {
    id: 374,
    name: "DSC-RX100M7",
  },
  SonyModelEntry {
    id: 375,
    name: "ILCE-7RM4",
  },
  SonyModelEntry {
    id: 376,
    name: "ILCE-9M2",
  },
  SonyModelEntry {
    id: 378,
    name: "ILCE-6600",
  },
  SonyModelEntry {
    id: 379,
    name: "ILCE-6100",
  },
  SonyModelEntry {
    id: 380,
    name: "ZV-1",
  },
  SonyModelEntry {
    id: 381,
    name: "ILCE-7C",
  },
  SonyModelEntry {
    id: 382,
    name: "ZV-E10",
  },
  SonyModelEntry {
    id: 383,
    name: "ILCE-7SM3",
  },
  SonyModelEntry {
    id: 384,
    name: "ILCE-1",
  },
  SonyModelEntry {
    id: 385,
    name: "ILME-FX3",
  },
  SonyModelEntry {
    id: 386,
    name: "ILCE-7RM3A",
  },
  SonyModelEntry {
    id: 387,
    name: "ILCE-7RM4A",
  },
  SonyModelEntry {
    id: 388,
    name: "ILCE-7M4",
  },
  SonyModelEntry {
    id: 389,
    name: "ZV-1F",
  },
  SonyModelEntry {
    id: 390,
    name: "ILCE-7RM5",
  },
  SonyModelEntry {
    id: 391,
    name: "ILME-FX30",
  },
  SonyModelEntry {
    id: 392,
    name: "ILCE-9M3",
  },
  SonyModelEntry {
    id: 393,
    name: "ZV-E1",
  },
  SonyModelEntry {
    id: 394,
    name: "ILCE-6700",
  },
  SonyModelEntry {
    id: 395,
    name: "ZV-1M2",
  },
  SonyModelEntry {
    id: 396,
    name: "ILCE-7CR",
  },
  SonyModelEntry {
    id: 397,
    name: "ILCE-7CM2",
  },
  SonyModelEntry {
    id: 398,
    name: "ILX-LR1",
  },
  SonyModelEntry {
    id: 399,
    name: "ZV-E10M2",
  },
  SonyModelEntry {
    id: 400,
    name: "ILCE-1M2",
  },
  SonyModelEntry {
    id: 401,
    name: "DSC-RX1RM3",
  },
  SonyModelEntry {
    id: 402,
    name: "ILCE-6400A",
  },
  SonyModelEntry {
    id: 403,
    name: "ILCE-6100A",
  },
  SonyModelEntry {
    id: 404,
    name: "DSC-RX100M7A",
  },
  SonyModelEntry {
    id: 406,
    name: "ILME-FX2",
  },
  SonyModelEntry {
    id: 407,
    name: "ILCE-7M5",
  },
  SonyModelEntry {
    id: 408,
    name: "ZV-1A",
  },
  SonyModelEntry {
    id: 410,
    name: "ILCE-7RM6",
  },
];

/// Look up a model name by ID. Returns `None` if the ID is not in the
/// table; the caller renders `"Unknown (N)"` to match bundled.
#[must_use]
pub fn lookup_name(id: u16) -> Option<SmolStr> {
  match SONY_MODEL_IDS.binary_search_by_key(&id, |e| e.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => SONY_MODEL_IDS.get(i).map(|e| SmolStr::from(e.name)),
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
    for e in SONY_MODEL_IDS {
      assert!(
        e.id as i64 > prev,
        "SONY_MODEL_IDS not strictly sorted: {} after {}",
        e.id,
        prev
      );
      prev = e.id as i64;
    }
  }

  #[test]
  fn lookup_dsc_r1() {
    // 2 => 'DSC-R1'
    let name = lookup_name(2).expect("DSC-R1 should be present");
    assert_eq!(name.as_str(), "DSC-R1");
  }

  #[test]
  fn lookup_a100() {
    // 256 => 'DSLR-A100'
    let name = lookup_name(256).expect("A100 should be present");
    assert_eq!(name.as_str(), "DSLR-A100");
  }

  #[test]
  fn lookup_ilce_7m4() {
    // 388 => 'ILCE-7M4'
    let name = lookup_name(388).expect("ILCE-7M4 should be present");
    assert_eq!(name.as_str(), "ILCE-7M4");
  }

  #[test]
  fn lookup_unknown_id_returns_none() {
    assert!(lookup_name(0xFFFF).is_none());
  }
}
