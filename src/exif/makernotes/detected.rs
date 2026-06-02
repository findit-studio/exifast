// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `DetectedMakerNote` — the parsed outcome of running the
//! [`MakerNotes.pm`](crate::exif::makernotes) dispatcher on a raw MakerNote
//! blob.
//!
//! ## `SubDirectory` directives MODELLED in Phase 1
//!
//! Phase 1 = faithful vendor IDENTIFICATION + faithful CAPTURE of the
//! `SubDirectory` directives that govern the child IFD walk. The fields:
//!
//! - **`body_offset`** — bundled `Start => '$valuePtr + N'`
//!   (`MakerNotes.pm:42`): the offset into the MakerNote BLOB at which the
//!   IFD / vendor-private data starts. `$valuePtr` in bundled is the
//!   absolute file offset of the blob's first byte; in the port the blob
//!   is `&[u8]` and `Start` becomes a relative header-length.
//! - **`offset_pt`** — bundled `OffsetPt => '$valuePtr+N'`
//!   (`MakerNotes.pm:128` FujiFilm): a small-endian 4-byte IFD POINTER
//!   read at in-blob offset `N` (NOT "skip N bytes" — that's `Start`).
//!   `None` when the entry has no `OffsetPt`.
//! - **`base_rule`** — bundled `Base => …` (`MakerNotes.pm:43`,
//!   `:131`, `:758`, …): the new `$$dirInfo{Base}` for the child IFD
//!   walk. See [`BaseRule`].
//! - **`byte_order`** — bundled
//!   `ByteOrder => 'Unknown'`/`'LittleEndian'`/`'BigEndian'`: the
//!   endianness of the child IFD. See [`ChildByteOrder`].
//! - **`not_ifd`** — bundled `NotIFD => 1`: the maker note is NOT an IFD;
//!   the vendor's `ProcessProc` parses its own binary structure.
//! - **`fix_base`** — bundled `FixBase => N` (`MakerNotes.pm:90` Casio2,
//!   `:141` GE, `:1124` Unknown, …): a FLAG that ExifTool's offset-fixup
//!   heuristic (`FixBase` in `MakerNotes.pm`) should run on the child
//!   walk. Phase 1 CAPTURES the flag only — the heuristic itself is
//!   deferred (Phase 2+).
//! - **`entry_based`** — bundled `EntryBased => 1` (`MakerNotes.pm:490`
//!   Kyocera): offsets inside the IFD are relative to the START OF EACH
//!   ENTRY, not the IFD base. Phase 1 captures the flag; Phase 2+ honors
//!   it.
//!
//! ## Directives DEFERRED (captured nowhere yet — Phase 2+ follow-ups)
//!
//! - The **`FixBase` heuristic** itself (the offset-correction algorithm
//!   `MakerNotes.pm` runs when `FixBase` is set) — Phase 1 captures only
//!   the [`DetectedMakerNote::fix_base`] flag.
//! - **`FixOffsets`** (`MakerNotes.pm:158` GE2, `:1003` SanyoC4): a
//!   per-tag offset patch expression — not modelled.
//! - **`Validate`** / **`ProcessProc`** / **`WriteProc`**: the bundled
//!   per-vendor parse/validate hooks — not modelled (vendor IFD walking
//!   is Phase 2-4).
//!
//! ## D8 — no public fields; accessors only
//!
//! Per `exifast-api-conventions`: every field is private; every accessor
//! is `const fn` where possible.

#![deny(clippy::indexing_slicing)]

use super::vendor::Vendor;
use crate::exif::ifd::ByteOrder;

/// Bundled `MakerNotes.pm` `SubDirectory` `ByteOrder` directive — the
/// endianness rule for the child IFD walk.
///
/// `Unknown` is bundled's `ByteOrder => 'Unknown'` (`MakerNotes.pm:44`,
/// `:57`, `:67`, …): the walker probes the child blob's TIFF magic
/// (`II`/`MM`) or, lacking one, the IFD-entry-count plausibility, to
/// pick an order at parse time. `Explicit(order)` is a hard-coded
/// `ByteOrder => 'LittleEndian'` / `'BigEndian'` (`MakerNotes.pm:132`
/// FujiFilm, `:260` Kodak1a, `:863` Reconyx, …).
///
/// D8: enum predicates + `as_str` for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildByteOrder {
  /// `ByteOrder => 'Unknown'` (`MakerNotes.pm`'s most common case —
  /// `Apple`, `Canon`, `Sony`, …). The Phase-2+ walker probes the
  /// MakerNote body's TIFF magic to pick the order.
  Unknown,
  /// `ByteOrder => 'LittleEndian'`/`'BigEndian'` — the bundled module
  /// hard-codes the endianness regardless of the body's magic. The
  /// child walk MUST honor this even if the body's TIFF marker
  /// disagrees (faithful: `Exif.pm:7078` `SetByteOrder($newByteOrder)`
  /// overrides the parent).
  Explicit(ByteOrder),
}

impl ChildByteOrder {
  /// A short label for the directive (`"Unknown"`, `"II"`, `"MM"`).
  #[must_use]
  #[inline]
  pub const fn as_str(self) -> &'static str {
    match self {
      ChildByteOrder::Unknown => "Unknown",
      ChildByteOrder::Explicit(b) => b.as_str(),
    }
  }

  /// `true` if the directive is `Unknown` (probe at parse time).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(self) -> bool {
    matches!(self, ChildByteOrder::Unknown)
  }

  /// `true` if the directive is an explicit endianness.
  #[must_use]
  #[inline(always)]
  pub const fn is_explicit(self) -> bool {
    matches!(self, ChildByteOrder::Explicit(_))
  }

  /// The explicit endianness, if any. `None` for [`Unknown`](Self::Unknown).
  #[must_use]
  #[inline(always)]
  pub const fn explicit(self) -> Option<ByteOrder> {
    match self {
      ChildByteOrder::Explicit(b) => Some(b),
      ChildByteOrder::Unknown => None,
    }
  }
}

/// `Base` directive in `MakerNotes.pm`'s `SubDirectory` — controls the
/// `$$dirInfo{Base}` of the child IFD walk (how absolute pointers inside
/// the MakerNote are interpreted).
///
/// ExifTool's `SubDirectory{Base}` is a Perl expression. The port
/// enumerates the four shapes bundled uses:
///
/// - `RelativeToStart(d)`: `Base => '$start - N'`. The bundled formula
///   `$start - N` rebases the child's `$$dirInfo{Base}` to the MakerNote
///   blob start MINUS N — used for vendors that prepend a header of N
///   bytes before the TIFF magic and want absolute IFD pointers to land
///   on the BLOB start (so the header is excluded from offset math).
///   Apple's `Base => '$start - 14'` (`MakerNotes.pm:43`) sets `d=-14`.
///   Stored as a SIGNED `i32`.
/// - `StartItself`: `Base => '$start'`. The child IFD's absolute
///   pointers are anchored to the blob's body start. FujiFilm
///   (`MakerNotes.pm:131`) is the canonical case.
/// - `NegativeOfBase`: `Base => '-$base'`. The child uses ABSOLUTE file
///   offsets (not relative to TIFF header) — only Leica7
///   (`MakerNotes.pm:699`) uses this for its JPEG-trailer maker note.
///   NOTE: Leica7 is a `LeicaTrailer` tag (`MakerNotes.pm:694`); the
///   bundled `-$base` is a PLACEHOLDER that `ProcessLeicaTrailer`
///   (LeicaTrailer code in `Exif.pm`) overrides with the trailer's
///   ABSOLUTE file offset. Phase 1 surfaces it; Phase 2+ will route it
///   (deferred long-tail).
/// - `Literal(n)`: `Base => 12` — a bundled LITERAL absolute base (not a
///   `$start`/`$base` expression). Panasonic3 (`MakerNotes.pm:758`,
///   `Base => 12`) and Hasselblad (`MakerNotes.pm:176`, `Base => 0`) are
///   the only two. The child's `$$dirInfo{Base}` is set to the literal
///   `n` directly, independent of `$start`/`$base`.
/// - `Inherit`: no `Base` directive — the child reuses the parent
///   walk's base. Canon (`MakerNotes.pm:67`) is the canonical case
///   (Canon writes its IFD with offsets relative to the SAME base as
///   the parent Exif IFD).
///
/// D8: variant predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BaseRule {
  /// `Base => '$start + N'` for any signed `N`. The child IFD's
  /// `$$dirInfo{Base}` is `body_offset + delta` from the blob start.
  /// `delta` is signed (Apple's `-14`, etc.).
  RelativeToStart(i32),
  /// `Base => '$start'` — the child IFD walks with `$$dirInfo{Base}`
  /// = the blob's body start (so absolute IFD pointers are
  /// blob-body-relative).
  StartItself,
  /// `Base => '-$base'` — the child uses absolute FILE offsets;
  /// only Leica7's JPEG-trailer case (`MakerNotes.pm:699`).
  NegativeOfBase,
  /// `Base => n` — a bundled LITERAL absolute base. Panasonic3
  /// (`MakerNotes.pm:758` `Base => 12`) and Hasselblad
  /// (`MakerNotes.pm:176` `Base => 0`) are the only two. The child's
  /// `$$dirInfo{Base}` is the literal `n`, NOT `$start + n`. Stored as
  /// a signed `i64` (bundled writes a non-negative integer; the signed
  /// type leaves room for a future negative literal and matches the
  /// resolver's internal arithmetic).
  Literal(i64),
  /// No `Base` directive — the child inherits the parent walk's
  /// `$$dirInfo{Base}` (Canon and several other vendors).
  Inherit,
}

impl BaseRule {
  /// `true` if the rule is [`RelativeToStart`](Self::RelativeToStart).
  #[must_use]
  #[inline(always)]
  pub const fn is_relative_to_start(self) -> bool {
    matches!(self, BaseRule::RelativeToStart(_))
  }

  /// `true` if the rule is [`StartItself`](Self::StartItself).
  #[must_use]
  #[inline(always)]
  pub const fn is_start_itself(self) -> bool {
    matches!(self, BaseRule::StartItself)
  }

  /// `true` if the rule is [`NegativeOfBase`](Self::NegativeOfBase).
  #[must_use]
  #[inline(always)]
  pub const fn is_negative_of_base(self) -> bool {
    matches!(self, BaseRule::NegativeOfBase)
  }

  /// `true` if the rule is [`Literal`](Self::Literal) (a bundled `Base => n`).
  #[must_use]
  #[inline(always)]
  pub const fn is_literal(self) -> bool {
    matches!(self, BaseRule::Literal(_))
  }

  /// `true` if the rule is [`Inherit`](Self::Inherit) (no `Base` line).
  #[must_use]
  #[inline(always)]
  pub const fn is_inherit(self) -> bool {
    matches!(self, BaseRule::Inherit)
  }

  /// The signed delta, if the rule is [`RelativeToStart`](Self::RelativeToStart).
  /// `None` for the other variants.
  #[must_use]
  #[inline(always)]
  pub const fn relative_delta(self) -> Option<i32> {
    match self {
      BaseRule::RelativeToStart(d) => Some(d),
      _ => None,
    }
  }

  /// The literal absolute base, if the rule is [`Literal`](Self::Literal).
  /// `None` for the other variants.
  #[must_use]
  #[inline(always)]
  pub const fn literal(self) -> Option<i64> {
    match self {
      BaseRule::Literal(n) => Some(n),
      _ => None,
    }
  }
}

/// The parsed outcome of dispatching a MakerNote blob — the four bundled
/// `SubDirectory` fields plus the matched [`Vendor`].
///
/// Returned by [`dispatch`](super::dispatcher::dispatch) for every blob
/// (the dispatcher is total — `Vendor::Unknown` is the catch-all).
///
/// D8: no public fields; accessors only; `const fn` where possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedMakerNote {
  /// The matched vendor.
  vendor: Vendor,
  /// Offset from the start of the MakerNote BLOB to the start of the
  /// child IFD / vendor body — bundled's `Start => '$valuePtr + N'`
  /// (`MakerNotes.pm:42` Apple = 14, `:55` Nikon = 18, …). For an
  /// unsigned vendor (Canon — `Start` defaults to `$valuePtr`) this is 0.
  body_offset: u16,
  /// `OffsetPt => '$valuePtr+N'` (`MakerNotes.pm:128` FujiFilm) — the
  /// in-blob offset at which a small-endian 4-byte IFD POINTER is read.
  /// Distinct from [`body_offset`](Self::body_offset): `OffsetPt` reads a
  /// 4-byte pointer at offset `N`, it does NOT skip `N` bytes. `None`
  /// when the bundled entry has no `OffsetPt` (every vendor but FujiFilm).
  offset_pt: Option<u16>,
  /// The `Base` directive — how absolute IFD pointers INSIDE the
  /// MakerNote body are interpreted relative to the parent walk's base.
  /// See [`BaseRule`].
  base_rule: BaseRule,
  /// The `ByteOrder` directive — `Unknown` (probe at parse time) or
  /// `Explicit(LittleEndian|BigEndian)`. See [`ChildByteOrder`].
  byte_order: ChildByteOrder,
  /// `NotIFD => 1` (`MakerNotes.pm:96` DJIInfo, `:164` Google,
  /// `:198` HP2, …) — the MakerNote is NOT in IFD format. Phase 1
  /// surfaces the flag for diagnostics; Phase 2+ routes through a
  /// per-vendor binary parser.
  not_ifd: bool,
  /// `FixBase => N` (`MakerNotes.pm:90` Casio2, `:141` GE, `:773` Pentax,
  /// `:1124` Unknown, …) — a FLAG that ExifTool's offset-correction
  /// heuristic should run on the child IFD walk. Phase 1 CAPTURES the
  /// flag; the heuristic itself is a deferred Phase-2+ follow-up.
  fix_base: bool,
  /// `EntryBased => 1` (`MakerNotes.pm:490` Kyocera) — offsets inside the
  /// IFD are relative to the start of EACH ENTRY rather than the IFD
  /// base. Phase 1 captures the flag; Phase 2+ honors it.
  entry_based: bool,
}

impl DetectedMakerNote {
  /// Construct a `DetectedMakerNote` for the common case. `const`-friendly
  /// so the dispatch table can build values inline. `offset_pt`,
  /// `fix_base`, and `entry_based` default to `None`/`false`; the few
  /// vendors that set them use the [`with_offset_pt`](Self::with_offset_pt)
  /// / [`with_fix_base`](Self::with_fix_base) /
  /// [`with_entry_based`](Self::with_entry_based) builders.
  #[must_use]
  #[inline]
  pub const fn new(
    vendor: Vendor,
    body_offset: u16,
    base_rule: BaseRule,
    byte_order: ChildByteOrder,
    not_ifd: bool,
  ) -> Self {
    Self {
      vendor,
      body_offset,
      offset_pt: None,
      base_rule,
      byte_order,
      not_ifd,
      fix_base: false,
      entry_based: false,
    }
  }

  /// Set the `OffsetPt` directive — bundled `OffsetPt => '$valuePtr+N'`
  /// (`MakerNotes.pm:128` FujiFilm). Builder form (consuming `self`).
  #[must_use]
  #[inline(always)]
  pub const fn with_offset_pt(mut self, offset_pt: u16) -> Self {
    self.offset_pt = Some(offset_pt);
    self
  }

  /// Set the `FixBase` flag — bundled `FixBase => N` (`MakerNotes.pm:90`
  /// Casio2, `:141` GE, `:773` Pentax, …). Captures the directive only;
  /// the offset-correction heuristic is a deferred Phase-2+ follow-up.
  #[must_use]
  #[inline(always)]
  pub const fn with_fix_base(mut self) -> Self {
    self.fix_base = true;
    self
  }

  /// Set the `EntryBased` flag — bundled `EntryBased => 1`
  /// (`MakerNotes.pm:490` Kyocera).
  #[must_use]
  #[inline(always)]
  pub const fn with_entry_based(mut self) -> Self {
    self.entry_based = true;
    self
  }

  /// The matched [`Vendor`].
  #[must_use]
  #[inline(always)]
  pub const fn vendor(&self) -> Vendor {
    self.vendor
  }

  /// Offset from the start of the MakerNote blob to the start of the
  /// child IFD / vendor body. The vendor header is `blob[..body_offset]`;
  /// the IFD / payload is `blob[body_offset..]`.
  #[must_use]
  #[inline(always)]
  pub const fn body_offset(&self) -> u16 {
    self.body_offset
  }

  /// `true` if the dispatcher stripped no header (`body_offset == 0`).
  /// Canon is the canonical case.
  #[must_use]
  #[inline(always)]
  pub const fn has_header(&self) -> bool {
    self.body_offset != 0
  }

  /// The `Base` directive — how the child IFD's absolute pointers
  /// rebase.
  #[must_use]
  #[inline(always)]
  pub const fn base_rule(&self) -> BaseRule {
    self.base_rule
  }

  /// The `ByteOrder` directive — `Unknown` (probe) or `Explicit(_)`.
  #[must_use]
  #[inline(always)]
  pub const fn byte_order(&self) -> ChildByteOrder {
    self.byte_order
  }

  /// `true` if `NotIFD => 1` was set on the bundled entry (the
  /// MakerNote is a binary blob, not an IFD).
  #[must_use]
  #[inline(always)]
  pub const fn is_not_ifd(&self) -> bool {
    self.not_ifd
  }

  /// The `OffsetPt` directive — the in-blob offset of a small-endian
  /// 4-byte IFD pointer (`MakerNotes.pm:128` FujiFilm). `None` for every
  /// vendor without an `OffsetPt`.
  #[must_use]
  #[inline(always)]
  pub const fn offset_pt(&self) -> Option<u16> {
    self.offset_pt
  }

  /// `true` if the bundled entry set `FixBase` (`MakerNotes.pm:90` Casio2,
  /// `:141` GE, `:773` Pentax, …). Phase 1 captures the flag; the
  /// offset-correction heuristic is deferred (Phase 2+).
  #[must_use]
  #[inline(always)]
  pub const fn fix_base(&self) -> bool {
    self.fix_base
  }

  /// `true` if the bundled entry set `EntryBased => 1` (`MakerNotes.pm:490`
  /// Kyocera) — IFD offsets are relative to each entry's start.
  #[must_use]
  #[inline(always)]
  pub const fn entry_based(&self) -> bool {
    self.entry_based
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

  /// `new` defaults the optional directives off.
  #[test]
  fn new_defaults_optional_directives_off() {
    let d = DetectedMakerNote::new(
      Vendor::Canon,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
    assert_eq!(d.offset_pt(), None);
    assert!(!d.fix_base());
    assert!(!d.entry_based());
  }

  /// The `with_*` builders set exactly their directive and chain.
  #[test]
  fn builders_set_directives() {
    let d = DetectedMakerNote::new(
      Vendor::Fuji,
      0,
      BaseRule::StartItself,
      ChildByteOrder::Explicit(ByteOrder::Little),
      false,
    )
    .with_offset_pt(8);
    assert_eq!(d.offset_pt(), Some(8));
    assert_eq!(d.body_offset(), 0);
    assert!(!d.fix_base());

    let d = DetectedMakerNote::new(
      Vendor::Pentax,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    )
    .with_fix_base();
    assert!(d.fix_base());
    assert!(!d.entry_based());

    let d = DetectedMakerNote::new(
      Vendor::Kyocera,
      22,
      BaseRule::RelativeToStart(2),
      ChildByteOrder::Unknown,
      false,
    )
    .with_entry_based();
    assert!(d.entry_based());
    assert!(!d.fix_base());
  }

  /// `BaseRule::Literal` predicates / accessor.
  #[test]
  fn base_rule_literal_predicate_and_accessor() {
    let r = BaseRule::Literal(12);
    assert!(r.is_literal());
    assert!(!r.is_relative_to_start());
    assert!(!r.is_inherit());
    assert_eq!(r.literal(), Some(12));
    assert_eq!(r.relative_delta(), None);
    // Non-literal rules return None.
    assert_eq!(BaseRule::Inherit.literal(), None);
    assert_eq!(BaseRule::RelativeToStart(-8).literal(), None);
  }
}
