// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The two `SubDirectory` directives the unified maker-note engine needs on top
//! of the ones [`DetectedMakerNote`](super::detected::DetectedMakerNote) already
//! models — `TableRef` (which tag table) and [`ProcessProc`] (which processor).
//!
//! ExifTool processes every maker note through the ONE shared engine
//! (`ProcessExif`, `Exif.pm:6278`); a vendor is not a walker but a **tag table
//! plus a set of `SubDirectory` directives** (`Start`/`Base`/`ByteOrder`/
//! `FixBase`/`ProcessProc`, `MakerNotes.pm:37-1127`). The directive *data* lives
//! in [`DetectedMakerNote`](super::detected::DetectedMakerNote) (the dispatcher's
//! per-blob result — `body_offset`=Start, `base_rule`=Base, `byte_order`,
//! `fix_base`, `not_ifd`, `entry_based`, `offset_pt`); this module adds only the
//! two pieces that the pre-unification code derived implicitly inside the
//! per-vendor walkers:
//!
//! - [`TableRef`] — which tag table the shared `Walker` resolves
//!   names/formats/conversions against (replaces the `IfdKind`-keyed lookup so
//!   the one walker serves Exif/GPS/Interop AND every vendor table).
//! - [`ProcessProc`] — the directory processor (`ProcessExif`/`ProcessCanon`/
//!   `ProcessUnknown`/`ProcessBinaryData`).
//!
//! `Walker::process_subdir` consumes a `&DetectedMakerNote` together with these.
//! It is THE only way a maker note is processed — there is no per-vendor IFD
//! walker (enforced by `tests/makernote_engine_invariant.rs`).
//!
//! See `docs/superpowers/specs/2026-06-15-makernote-engine-unification-design.md`.

use crate::exif::ifd::ByteOrder;
use crate::exif::makernotes::vendors::leica::tags::LeicaVariant;

/// Which tag table the shared walker resolves names/formats/conversions against
/// while walking a (sub-)directory. Replaces the `IfdKind`-keyed lookup so the
/// one `Walker` can process Exif/GPS/Interop IFDs AND every vendor maker note
/// with identical machinery.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TableRef {
  /// `%Exif::Main` — IFD0, ExifIFD, trailing IFDs, SubIFDs.
  Exif,
  /// `%GPS::Main`.
  Gps,
  /// `%Exif::Main` reused for the Interop IFD (faithful — InteropOffset has no
  /// own table, `Exif.pm:6939`).
  Interop,
  /// `%Canon::Main`.
  Canon,
  /// `%Sony::Main`.
  Sony,
  /// `%Panasonic::Main`.
  Panasonic,
  /// `%Nikon::Main`.
  Nikon,
  /// `%Nikon::Type2` — the `"Nikon\0\x01"` headerless layout (`Nikon.pm`
  /// `%Image::ExifTool::Nikon::Type2`). A SIBLING table of [`Nikon`](Self::Nikon)
  /// because the same maker-note dispatch produces either depending on the
  /// header; the two tables REUSE tag IDs 0x0003..0x000b for DIFFERENT tags
  /// (0x0003 is `ColorMode` in `%Nikon::Main` but `Quality` in `%Nikon::Type2`),
  /// so the resolved table must distinguish them (#243 phase 3-bis).
  NikonType2,
  /// `%Apple::Main`.
  Apple,
  /// `%Pentax::Main`.
  Pentax,
  /// `%Samsung::Type2`.
  Samsung,
  /// `%Image::ExifTool::Nikon::PreviewIFD` (`Nikon.pm:5386-5438`) — the small
  /// preview-image sub-IFD an SRW raw's Samsung `0x0035` SubDirectory descends
  /// into (#242). The rows REUSE the `%Exif::Main` leaf type
  /// ([`crate::exif::tables::ExifTag`] — they reference the standard EXIF
  /// PrintConvs), so a resolved leaf rides in
  /// [`ResolvedConv::Exif`](crate::exif::ResolvedConv::Exif) and renders through
  /// the core Exif machinery; the table supplies only the renamed
  /// `PreviewImageStart`/`Length` pair and its `DataTag => 'PreviewImage'`.
  /// Walked under `ByteOrder => Unknown` with the family-1 group `PreviewIFD`
  /// (applied by the Samsung capture, not the walker).
  NikonPreviewIfd,
  /// `%Sony::SR2Private` (`Sony.pm:10448`) — the encrypted private IFD's
  /// data-member leaves (`SR2SubIFDOffset`/`Length`/`Key`), reached via the IFD0
  /// `DNGPrivateData` 0xc634 pointer on an ARW/SR2. A SIBLING of [`Sony`](Self::Sony)
  /// because its tag IDs (0x72xx) are disjoint from `%Sony::Main` and resolve
  /// against [`crate::exif::makernotes::vendors::sony::sr2`].
  SonySr2Private,
  /// `%Sony::SR2SubIFD` (`Sony.pm:10515`) — the tags in the DECRYPTED SR2SubIFD
  /// block (WB levels, BlackLevel, ColorMatrix, the correction-param arrays).
  SonySr2SubIfd,
  /// `%Sony::SR2DataIFD` (`Sony.pm:10576`) — `ColorMode` (the 0x74c0 SubIFD).
  SonySr2DataIfd,
  /// One of `%Panasonic::Leica2`..`Leica9` — the Leica MakerNote variant
  /// tables (`Panasonic.pm:1604-2256`). The payload selects which of the SIX
  /// distinct tables (Leica7 reuses `%Leica6`, Leica8 reuses `%Leica5`); the
  /// dispatcher resolves the signature to the table-bearing [`LeicaVariant`].
  /// A SIBLING-payload `TableRef` (rather than six bare variants) keeps the
  /// shared-`Walker` dispatch matches to ONE `TableRef::Leica(v)` arm each, and
  /// equality is variant-sensitive (`TableRef::Leica(a) == TableRef::Leica(b)`
  /// iff `a == b`) — every existing `active_table == TableRef::X` check is for a
  /// non-Leica table, so the payload does not affect them.
  Leica(LeicaVariant),
}

/// `ProcessProc` (`MakerNotes.pm`) — the directory processor. The four real
/// processors maker notes use; all but [`ProcessProc::BinaryData`] ultimately
/// run the shared `ProcessExif` IFD walk (the difference is the pre-walk step).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessProc {
  /// Default — `ProcessExif` directly (Sony/Panasonic/Nikon/Apple).
  Exif,
  /// `ProcessCanon` — `ProcessExif` plus Canon footer/CNDC hooks (`Canon.pm`).
  Canon,
  /// `ProcessUnknown` — `LocateIFD` then `ProcessExif` (`MakerNotes.pm:1816`;
  /// Samsung2/Pentax/Casio2, whose offsets are inconsistent).
  Unknown,
  /// `ProcessBinaryData` — a fixed-layout sub-table (ShotInfo/AFInfo/…).
  BinaryData,
}

/// `ByteOrder => 'BigEndian' | 'LittleEndian' | 'Unknown'` — the endianness
/// rule for a (sub-)directory walk (`MakerNotes.pm` SubDirectory key,
/// `Exif.pm:6982-6996`).
///
/// [`Fixed`](Self::Fixed) is a hard-coded order (also the rule the core
/// Exif/GPS/Interop sub-IFDs use — they always inherit the parent TIFF order,
/// `Exif.pm:7064-7077`). [`Unknown`](Self::Unknown) defers the order to the
/// entry-count heuristic
/// ([`fixbase::detect_unknown_byte_order`](super::fixbase::detect_unknown_byte_order),
/// `Exif.pm:6982-6993`); it fires only for vendor maker notes, never a core
/// IFD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ByteOrderRule {
  /// A fixed endianness — `ByteOrder => 'LittleEndian'`/`'BigEndian'`, or (for
  /// a core sub-IFD) the inherited parent order.
  Fixed(ByteOrder),
  /// `ByteOrder => 'Unknown'` — probe the body's entry-count word to pick the
  /// order at walk time (`Exif.pm:6982-6993`).
  Unknown,
}

/// `FixBase => 0 | 1 | 2` (`MakerNotes.pm` SubDirectory key) — the
/// offset-correction heuristic mode for a (sub-)directory walk.
///
/// [`No`](Self::No) is the absence of a `FixBase` directive (every core
/// Exif/GPS/Interop sub-IFD — their offsets are already TIFF-correct).
/// [`Heuristic`](Self::Heuristic) (`FixBase => 1`) and
/// [`Aggressive`](Self::Aggressive) (`FixBase => 2`, "allow a range" for
/// genuinely Unknown maker notes) run [`fixbase::fix_base`](super::fixbase::fix_base).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FixBaseMode {
  /// No `FixBase` directive — do not run the heuristic.
  No,
  /// `FixBase => 1` — run the standard offset-correction heuristic.
  Heuristic,
  /// `FixBase => 2` — run the heuristic in "allow a range" mode (Unknown
  /// maker notes, `MakerNotes.pm:1124`).
  Aggressive,
}

impl ByteOrderRule {
  /// `true` if the rule is [`Unknown`](Self::Unknown) (probe at walk time).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(self) -> bool {
    matches!(self, ByteOrderRule::Unknown)
  }

  /// The fixed endianness, if any. `None` for [`Unknown`](Self::Unknown).
  #[must_use]
  #[inline(always)]
  pub const fn fixed(self) -> Option<ByteOrder> {
    match self {
      ByteOrderRule::Fixed(b) => Some(b),
      ByteOrderRule::Unknown => None,
    }
  }
}

impl FixBaseMode {
  /// `true` if the mode is [`No`](Self::No) (no `FixBase` directive).
  #[must_use]
  #[inline(always)]
  pub const fn is_no(self) -> bool {
    matches!(self, FixBaseMode::No)
  }

  /// The `$$dirInfo{FixBase}` value (`1`/`2`) the heuristic reads, or `None`
  /// for [`No`](Self::No).
  #[must_use]
  #[inline(always)]
  pub const fn dir_fix_base(self) -> Option<u8> {
    match self {
      FixBaseMode::No => None,
      FixBaseMode::Heuristic => Some(1),
      FixBaseMode::Aggressive => Some(2),
    }
  }
}

impl TableRef {
  /// `true` for the three core IFD tables (the pre-existing `IfdKind` set);
  /// `false` for a vendor maker-note table.
  #[must_use]
  pub const fn is_core_ifd(self) -> bool {
    matches!(self, TableRef::Exif | TableRef::Gps | TableRef::Interop)
  }
}
