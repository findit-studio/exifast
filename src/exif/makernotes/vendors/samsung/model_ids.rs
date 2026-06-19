// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Samsung body model-ID lookup — the inline PrintConv at
//! `Samsung.pm:158-244` (the `0x0003 SamsungModelID` tag, `PrintHex => 1`).
//!
//! 42 rows ported as a binary-search-sorted const array. The bundled
//! hash has several DUPLICATE keys (e.g. `0x1001226` appears twice); Perl keeps
//! the LAST assignment, so this table carries the last-wins name for each. The
//! commented-out `#0x…` aliases in the source are NOT hash entries (they
//! document which bodies share a "Various Models" ID) and are omitted.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of the Samsung model-ID lookup.
#[derive(Debug, Clone, Copy)]
pub struct SamsungModelEntry {
  /// The Samsung model ID (the `0x0003` int32u value).
  pub id: u32,
  /// The body name.
  pub name: &'static str,
}

/// Samsung model-ID rows — sorted by ID (binary-search-ready).
pub const SAMSUNG_MODEL_IDS: &[SamsungModelEntry] = &[
  SamsungModelEntry {
    id: 0x100101c,
    name: "NX10",
  },
  SamsungModelEntry {
    id: 0x1001226,
    name: "HMX-S15BP",
  },
  SamsungModelEntry {
    id: 0x1001233,
    name: "HMX-Q10",
  },
  SamsungModelEntry {
    id: 0x1001234,
    name: "HMX-H304",
  },
  SamsungModelEntry {
    id: 0x100130c,
    name: "NX100",
  },
  SamsungModelEntry {
    id: 0x1001327,
    name: "NX11",
  },
  SamsungModelEntry {
    id: 0x170104b,
    name: "ES65, ES67 / VLUU ES65, ES67 / SL50",
  },
  SamsungModelEntry {
    id: 0x170104e,
    name: "ES70, ES71 / VLUU ES70, ES71 / SL600",
  },
  SamsungModelEntry {
    id: 0x1701052,
    name: "ES73 / VLUU ES73 / SL605",
  },
  SamsungModelEntry {
    id: 0x1701055,
    name: "ES25, ES27 / VLUU ES25, ES27 / SL45",
  },
  SamsungModelEntry {
    id: 0x1701300,
    name: "ES28 / VLUU ES28",
  },
  SamsungModelEntry {
    id: 0x1701303,
    name: "ES74,ES75,ES78 / VLUU ES75,ES78",
  },
  SamsungModelEntry {
    id: 0x2001046,
    name: "PL150 / VLUU PL150 / TL210 / PL151",
  },
  SamsungModelEntry {
    id: 0x2001048,
    name: "PL100 / TL205 / VLUU PL100 / PL101",
  },
  SamsungModelEntry {
    id: 0x2001311,
    name: "PL120,PL121 / VLUU PL120,PL121",
  },
  SamsungModelEntry {
    id: 0x2001315,
    name: "PL170,PL171 / VLUUPL170,PL171",
  },
  SamsungModelEntry {
    id: 0x200131e,
    name: "PL210, PL211 / VLUU PL210, PL211",
  },
  SamsungModelEntry {
    id: 0x2701317,
    name: "PL20,PL21 / VLUU PL20,PL21",
  },
  SamsungModelEntry {
    id: 0x2a0001b,
    name: "WP10 / VLUU WP10 / AQ100",
  },
  SamsungModelEntry {
    id: 0x3000000,
    name: "Various Models (0x3000000)",
  },
  SamsungModelEntry {
    id: 0x3a00018,
    name: "Various Models (0x3a00018)",
  },
  SamsungModelEntry {
    id: 0x400101f,
    name: "ST1000 / ST1100 / VLUU ST1000 / CL65",
  },
  SamsungModelEntry {
    id: 0x4001022,
    name: "ST550 / VLUU ST550 / TL225",
  },
  SamsungModelEntry {
    id: 0x4001025,
    name: "Various Models (0x4001025)",
  },
  SamsungModelEntry {
    id: 0x400103e,
    name: "VLUU ST5500, ST5500, CL80",
  },
  SamsungModelEntry {
    id: 0x4001041,
    name: "VLUU ST5000, ST5000, TL240",
  },
  SamsungModelEntry {
    id: 0x4001043,
    name: "ST70 / VLUU ST70 / ST71",
  },
  SamsungModelEntry {
    id: 0x400130a,
    name: "Various Models (0x400130a)",
  },
  SamsungModelEntry {
    id: 0x400130e,
    name: "ST90,ST91 / VLUU ST90,ST91",
  },
  SamsungModelEntry {
    id: 0x4001313,
    name: "VLUU ST95, ST95",
  },
  SamsungModelEntry {
    id: 0x4a00015,
    name: "VLUU ST60",
  },
  SamsungModelEntry {
    id: 0x4a0135b,
    name: "ST30, ST65 / VLUU ST65 / ST67",
  },
  SamsungModelEntry {
    id: 0x5000000,
    name: "Various Models (0x5000000)",
  },
  SamsungModelEntry {
    id: 0x5001038,
    name: "Various Models (0x5001038)",
  },
  SamsungModelEntry {
    id: 0x500103a,
    name: "WB650 / VLUU WB650 / WB660",
  },
  SamsungModelEntry {
    id: 0x500103c,
    name: "WB600 / VLUU WB600 / WB610",
  },
  SamsungModelEntry {
    id: 0x500133e,
    name: "WB150 / WB150F / WB152 / WB152F / WB151",
  },
  SamsungModelEntry {
    id: 0x5a0000f,
    name: "WB5000 / HZ25W",
  },
  SamsungModelEntry {
    id: 0x5a0001e,
    name: "WB5500 / VLUU WB5500 / HZ50W",
  },
  SamsungModelEntry {
    id: 0x6001036,
    name: "EX1",
  },
  SamsungModelEntry {
    id: 0x700131c,
    name: "VLUU SH100, SH100",
  },
  SamsungModelEntry {
    id: 0x27127002,
    name: "SMX-C20N",
  },
];

/// Resolve a Samsung model ID to its name (`%Samsung::Type2` 0x0003 PrintConv).
/// `None` ⇒ the ID is not in the table (ExifTool then renders the raw value).
#[must_use]
pub fn lookup_name(id: u32) -> Option<SmolStr> {
  match SAMSUNG_MODEL_IDS.binary_search_by_key(&id, |e| e.id) {
    Ok(i) => SAMSUNG_MODEL_IDS.get(i).map(|e| SmolStr::from(e.name)),
    Err(_) => None,
  }
}
