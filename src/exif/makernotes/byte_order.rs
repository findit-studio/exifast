// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Resolve the CHILD IFD walk's byte order from the dispatch
//! [`ChildByteOrder`](super::ChildByteOrder) directive.
//!
//! ## Bundled algorithm
//!
//! `MakerNotes.pm` `SubDirectory{ByteOrder}` is one of three string
//! values:
//!
//! - `LittleEndian` / `BigEndian`: hard-coded — the child walk MUST use
//!   this order regardless of the body's own TIFF magic
//!   (`Exif.pm:7078` `SetByteOrder($newByteOrder)`).
//! - `Unknown`: detect from the maker-note BODY at parse time. The
//!   bundled probe (`LocateIFD` / `ProcessUnknown` —
//!   `MakerNotes.pm:1622-1690`/`:1816-1837`) tries each byte order
//!   against a plausibility check (IFD entry count ≤ 256, entries' tag
//!   IDs / formats look sane). For a vendor whose body starts with a
//!   visible TIFF magic (`II\x2a\0` / `MM\0\x2a`) the probe is trivial —
//!   read the marker. For a headerless body the probe is iterative.
//!
//! ## Port surface
//!
//! Phase 1 surfaces ONLY the "marker probe" branch — the byte order is
//! determined by:
//!
//! 1. an explicit dispatcher directive (`Explicit(_)`) wins outright;
//! 2. for `Unknown`, the port checks the first 2 bytes of the maker-note
//!    BODY (after the vendor header) for `II` / `MM`;
//! 3. if no marker is present, the port falls back to the PARENT walk's
//!    byte order. This is a GUESS, NOT a faithful port of `LocateIFD`:
//!    bundled's `LocateIFD` (`MakerNotes.pm:1622-1690`) TOGGLES the byte
//!    order and re-tests the IFD entry-count plausibility for a
//!    headerless body, picking whichever order yields a sane IFD. That
//!    entry-count toggle is DEFERRED to the Phase-2+ walker; Phase 1 only
//!    seeds the parent's order as the opening assumption
//!    (`MakerNotes.pm:1622-1623` calls `GetByteOrder()` before probing).
//!
//! The function returns `(ByteOrder, ByteOrderSource)` — the source
//! enum lets diagnostics tell whether the resolution came from an
//! explicit directive, a body marker, or a (provisional) parent fallback.

use super::detected::ChildByteOrder;
use crate::exif::ifd::ByteOrder;

/// How the child IFD's byte order was resolved — for diagnostics and for
/// the Phase-2+ walker's plausibility probe.
///
/// D8: unit-variants + `const` predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteOrderSource {
  /// The dispatcher entry hard-coded `ByteOrder => 'LittleEndian'` /
  /// `'BigEndian'` (e.g. FujiFilm, Kodak1a/1b, Reconyx).
  Explicit,
  /// The maker-note BODY started with a TIFF magic (`II` / `MM`) and the
  /// port read it directly.
  BodyMarker,
  /// No body marker; the port fell back to the PARENT walk's byte order.
  /// This is a GUESS (the opening assumption) — NOT confirmed. The
  /// bundled `LocateIFD` would toggle the order and re-test IFD
  /// entry-count plausibility for a headerless body; that toggle is
  /// deferred to the Phase-2+ walker. Phase 1 surfaces only the initial
  /// guess.
  ParentFallback,
}

impl ByteOrderSource {
  /// `true` if the dispatcher hard-coded the order.
  #[must_use]
  #[inline(always)]
  pub const fn is_explicit(self) -> bool {
    matches!(self, ByteOrderSource::Explicit)
  }

  /// `true` if the order came from a TIFF magic at the start of the
  /// MakerNote body.
  #[must_use]
  #[inline(always)]
  pub const fn is_body_marker(self) -> bool {
    matches!(self, ByteOrderSource::BodyMarker)
  }

  /// `true` if the port fell back to the parent walk's order.
  #[must_use]
  #[inline(always)]
  pub const fn is_parent_fallback(self) -> bool {
    matches!(self, ByteOrderSource::ParentFallback)
  }
}

/// Resolve the byte order the child IFD walk should use.
///
/// - `directive`: the dispatcher's [`ChildByteOrder`].
/// - `body`: the MakerNote body (the bytes AFTER the vendor header —
///   i.e. `blob[body_offset..]`).
/// - `parent_order`: the parent IFD walk's `GetByteOrder()`.
#[must_use]
pub fn resolve_child_byte_order(
  directive: ChildByteOrder,
  body: &[u8],
  parent_order: ByteOrder,
) -> (ByteOrder, ByteOrderSource) {
  match directive {
    ChildByteOrder::Explicit(order) => (order, ByteOrderSource::Explicit),
    ChildByteOrder::Unknown => match ByteOrder::from_marker(body) {
      Some(order) => (order, ByteOrderSource::BodyMarker),
      None => (parent_order, ByteOrderSource::ParentFallback),
    },
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Explicit LE always wins.
  #[test]
  fn explicit_overrides_body_marker() {
    let body = b"MM\x00\x2arest"; // body magic says BE …
    let (order, src) = resolve_child_byte_order(
      ChildByteOrder::Explicit(ByteOrder::Little),
      body,
      ByteOrder::Big,
    );
    assert_eq!(order, ByteOrder::Little); // … but the directive wins.
    assert!(src.is_explicit());
  }

  /// Body marker is read when the directive is `Unknown`.
  #[test]
  fn unknown_reads_body_marker_le() {
    let body = b"II\x2a\x00rest";
    let (order, src) = resolve_child_byte_order(ChildByteOrder::Unknown, body, ByteOrder::Big);
    assert_eq!(order, ByteOrder::Little);
    assert!(src.is_body_marker());
  }

  #[test]
  fn unknown_reads_body_marker_be() {
    let body = b"MM\x00\x2arest";
    let (order, src) = resolve_child_byte_order(ChildByteOrder::Unknown, body, ByteOrder::Little);
    assert_eq!(order, ByteOrder::Big);
    assert!(src.is_body_marker());
  }

  /// No body marker → fall back to the parent's order.
  #[test]
  fn unknown_falls_back_to_parent() {
    let body = b"\x00\x05\x01\x00"; // not a TIFF marker
    let (order, src) = resolve_child_byte_order(ChildByteOrder::Unknown, body, ByteOrder::Big);
    assert_eq!(order, ByteOrder::Big);
    assert!(src.is_parent_fallback());
  }

  /// Empty body — fall back to parent.
  #[test]
  fn empty_body_falls_back_to_parent() {
    let (order, src) = resolve_child_byte_order(ChildByteOrder::Unknown, &[], ByteOrder::Little);
    assert_eq!(order, ByteOrder::Little);
    assert!(src.is_parent_fallback());
  }

  /// Source predicates round-trip.
  #[test]
  fn source_predicates() {
    assert!(ByteOrderSource::Explicit.is_explicit());
    assert!(!ByteOrderSource::Explicit.is_body_marker());
    assert!(ByteOrderSource::BodyMarker.is_body_marker());
    assert!(ByteOrderSource::ParentFallback.is_parent_fallback());
  }
}
