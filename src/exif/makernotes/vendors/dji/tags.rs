// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::DJI::Main` IFD tag table (`DJI.pm:52-72`).
//!
//! Phase 4 scope:
//!
//! - Every named LEAF tag from the Main hash gets a row here. The bundled
//!   Main hash is small (10 named tags spanning IDs 0x01..0x0b) and has
//!   NO sub-table pointers — every tag is a scalar.
//! - The 0x02 tag is intentionally absent from bundled (`# 0x02 -
//!   int8u[4]: "1 0 0 0", "1 1 0 0"`) — Phil's notes say its meaning is
//!   undecoded; the port skips it (the body walker decodes it into raw
//!   bytes but no tag-table entry consumes it, which mirrors bundled).

#![deny(clippy::indexing_slicing)]

use super::printconv::DjiPrintConv;

/// One DJI Main IFD tag.
#[derive(Debug, Clone, Copy)]
pub struct DjiTag {
  /// Tag ID (`DJI.pm` Main hash key).
  pub id: u16,
  /// `Name => '…'` from bundled.
  pub name: &'static str,
  /// PrintConv strategy.
  pub conv: DjiPrintConv,
}

/// `%DJI::Main` (`DJI.pm:53-72`). Sorted by tag ID.
pub const DJI_TAGS: &[DjiTag] = &[
  // 0x01 — Make (`DJI.pm:61`)
  // `0x01 => { Name => 'Make', Writable => 'string' },`
  DjiTag {
    id: 0x01,
    name: "Make",
    conv: DjiPrintConv::None,
  },
  // 0x02 — UNDECODED (`DJI.pm:62`)
  // `# 0x02 - int8u[4]: "1 0 0 0", "1 1 0 0"` — bundled keeps as a comment;
  // no table entry. Phase 4 mirrors bundled (no row here).
  //
  // 0x03 — SpeedX (`DJI.pm:63`)
  // `0x03 => { Name => 'SpeedX', Writable => 'float', %convFloat2 },`
  DjiTag {
    id: 0x03,
    name: "SpeedX",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x04 — SpeedY (`DJI.pm:64`)
  DjiTag {
    id: 0x04,
    name: "SpeedY",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x05 — SpeedZ (`DJI.pm:65`)
  DjiTag {
    id: 0x05,
    name: "SpeedZ",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x06 — Pitch (`DJI.pm:66`)
  DjiTag {
    id: 0x06,
    name: "Pitch",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x07 — Yaw (`DJI.pm:67`)
  DjiTag {
    id: 0x07,
    name: "Yaw",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x08 — Roll (`DJI.pm:68`)
  DjiTag {
    id: 0x08,
    name: "Roll",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x09 — CameraPitch (`DJI.pm:69`)
  DjiTag {
    id: 0x09,
    name: "CameraPitch",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x0a — CameraYaw (`DJI.pm:70`)
  DjiTag {
    id: 0x0a,
    name: "CameraYaw",
    conv: DjiPrintConv::Float2Signed,
  },
  // 0x0b — CameraRoll (`DJI.pm:71`)
  DjiTag {
    id: 0x0b,
    name: "CameraRoll",
    conv: DjiPrintConv::Float2Signed,
  },
];

/// Resolve a tag ID to its [`DjiTag`] row, or `None` for unknown. Binary
/// search over the ID-sorted table (`table_is_sorted_by_id` guards it).
#[must_use]
#[inline]
pub fn lookup(id: u16) -> Option<&'static DjiTag> {
  match DJI_TAGS.binary_search_by_key(&id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => DJI_TAGS.get(i),
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
  fn known_tags_resolve_by_id() {
    assert_eq!(lookup(0x01).map(|t| t.name), Some("Make"));
    assert_eq!(lookup(0x03).map(|t| t.name), Some("SpeedX"));
    assert_eq!(lookup(0x06).map(|t| t.name), Some("Pitch"));
    assert_eq!(lookup(0x07).map(|t| t.name), Some("Yaw"));
    assert_eq!(lookup(0x08).map(|t| t.name), Some("Roll"));
    assert_eq!(lookup(0x09).map(|t| t.name), Some("CameraPitch"));
    assert_eq!(lookup(0x0a).map(|t| t.name), Some("CameraYaw"));
    assert_eq!(lookup(0x0b).map(|t| t.name), Some("CameraRoll"));
  }

  #[test]
  fn unknown_tag_returns_none() {
    assert!(lookup(0x02).is_none()); // bundled skips this; we skip too
    assert!(lookup(0x0c).is_none());
    assert!(lookup(0xffff).is_none());
  }

  #[test]
  fn table_is_sorted_by_id() {
    for w in DJI_TAGS.windows(2) {
      assert!(w[0].id < w[1].id, "tags must be sorted by id");
    }
  }

  #[test]
  fn float2_tags_use_signed_printconv() {
    for tag in DJI_TAGS {
      if tag.id != 0x01 {
        assert_eq!(tag.conv, DjiPrintConv::Float2Signed, "{} ", tag.name);
      }
    }
  }
}
