// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Samsung NX lens-type lookup — `%samsungLensTypes` (`Samsung.pm:35-55`),
//! referenced by the `0xa003 LensType` PrintConv (`Samsung.pm:415`).
//!
//! 18 rows ported as a binary-search-sorted const array.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;

/// One row of the Samsung NX lens-type lookup.
#[derive(Debug, Clone, Copy)]
pub struct SamsungLensType {
  /// The lens-type ID (the `0xa003` int16u value).
  pub id: u32,
  /// The lens name (`"Samsung NX "` is already part of every bundled name).
  pub name: &'static str,
}

/// Samsung NX lens-type rows — sorted by ID (binary-search-ready).
pub const SAMSUNG_LENS_TYPES: &[SamsungLensType] = &[
  SamsungLensType {
    id: 0,
    name: "Built-in or Manual Lens",
  },
  SamsungLensType {
    id: 1,
    name: "Samsung NX 30mm F2 Pancake",
  },
  SamsungLensType {
    id: 2,
    name: "Samsung NX 18-55mm F3.5-5.6 OIS",
  },
  SamsungLensType {
    id: 3,
    name: "Samsung NX 50-200mm F4-5.6 ED OIS",
  },
  SamsungLensType {
    id: 4,
    name: "Samsung NX 20-50mm F3.5-5.6 ED",
  },
  SamsungLensType {
    id: 5,
    name: "Samsung NX 20mm F2.8 Pancake",
  },
  SamsungLensType {
    id: 6,
    name: "Samsung NX 18-200mm F3.5-6.3 ED OIS",
  },
  SamsungLensType {
    id: 7,
    name: "Samsung NX 60mm F2.8 Macro ED OIS SSA",
  },
  SamsungLensType {
    id: 8,
    name: "Samsung NX 16mm F2.4 Pancake",
  },
  SamsungLensType {
    id: 9,
    name: "Samsung NX 85mm F1.4 ED SSA",
  },
  SamsungLensType {
    id: 10,
    name: "Samsung NX 45mm F1.8",
  },
  SamsungLensType {
    id: 11,
    name: "Samsung NX 45mm F1.8 2D/3D",
  },
  SamsungLensType {
    id: 12,
    name: "Samsung NX 12-24mm F4-5.6 ED",
  },
  SamsungLensType {
    id: 13,
    name: "Samsung NX 16-50mm F2-2.8 S ED OIS",
  },
  SamsungLensType {
    id: 14,
    name: "Samsung NX 10mm F3.5 Fisheye",
  },
  SamsungLensType {
    id: 15,
    name: "Samsung NX 16-50mm F3.5-5.6 Power Zoom ED OIS",
  },
  SamsungLensType {
    id: 20,
    name: "Samsung NX 50-150mm F2.8 S ED OIS",
  },
  SamsungLensType {
    id: 21,
    name: "Samsung NX 300mm F2.8 ED OIS",
  },
];

/// Resolve a lens-type ID to its name (`%samsungLensTypes`). `None` ⇒ the ID
/// is not in the table (ExifTool then renders the raw `Unknown (N)`).
#[must_use]
pub fn lookup_name(id: u32) -> Option<SmolStr> {
  match SAMSUNG_LENS_TYPES.binary_search_by_key(&id, |e| e.id) {
    Ok(i) => SAMSUNG_LENS_TYPES.get(i).map(|e| SmolStr::from(e.name)),
    Err(_) => None,
  }
}
