// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic MakerNote IFD body constants — Phase-3 port.
//!
//! Single-walker invariant (#243 phase 5 / #255): the `%Panasonic::Main` route —
//! the automatic Panasonic dispatch AND the two cross-table Leica routes
//! (`MakerNoteLeica` / `MakerNoteLeica10`) — walks through the shared `Walker`
//! (`crate::exif::panasonic_makernote_isolated` / `…_with_offset`). The
//! per-vendor body walker (`walk_panasonic_in_tiff` + the `PanasonicEntry`
//! entry-list it produced) and the `parse` / `parse_main_gated` / `parse_in_tiff`
//! oracle entry points have ALL been deleted — there is no second per-vendor Main
//! walker, so the `-j`/`-n` byte-identity contract is enforced by construction.
//! Only [`HEADER_LEN`] (the body-offset constant the dispatcher + the shared
//! Walker share) survives here.
//!
//! Panasonic's MakerNote (`MakerNotePanasonic`, `MakerNotes.pm:732-740`)
//! starts with the 12-byte header `Panasonic\0\0\0` and is followed by a
//! standard IFD body (`count`, `entries[]`). `Start => '$valuePtr + 12'`,
//! `ByteOrder => 'Unknown'` (the byte order falls back to the parent IFD's
//! order since the body has no MM/II marker).
//!
//! ## Out-of-line value offsets and the `Base` directive
//!
//! There are TWO variants of `%Panasonic::Main`, distinguished only by
//! `Base` (`MakerNotes.pm:732-761`):
//!
//! - `MakerNotePanasonic` (`:733`) — NO `Base =>` line, so the child IFD
//!   INHERITS the parent walk's base. Out-of-line offsets are
//!   TIFF-relative (i.e. straight indices into the parent buffer).
//! - `MakerNotePanasonic3` (`:752`, the DC-FT7) — `Base => 12` (`:758`,
//!   the bundled comment literally reads `# crazy!`). The child IFD's
//!   `$$dirInfo{Base}` becomes `eval(12) + $base` (`Exif.pm:7003`); the
//!   value-offset resolver then reads `$valuePtr -= $dataPos`
//!   (`Exif.pm:6546`) where `$subdirDataPos += $base - $subdirBase`
//!   (`Exif.pm:7040`) has shifted `$dataPos` DOWN by 12. Net effect in
//!   the port's buffer coordinates (parent `base == 0`, `dataPos == 0`):
//!   a child out-of-line offset `off` resolves to buffer position
//!   `off + 12`. Reading it at `off` (base 0) lands 12 bytes EARLY ⇒ the
//!   value is corrupted/dropped.
//!
//! The shared `Walker` takes the resolved `base_offset` (the buffer addend, =
//! the literal `Base` integer; 0 for the inherit variant) from the
//! [dispatcher](crate::exif::makernotes::dispatcher) via its
//! `value_offset_base` and applies it to every OUT-OF-LINE offset. Inline
//! values (≤ 4 bytes, stored in the entry) carry no offset and are unaffected
//! (`Exif.pm:6504` only the `$size > 4` branch reads/rebases a pointer).

#![deny(clippy::indexing_slicing)]

/// Header byte length for `MakerNotePanasonic` and `MakerNotePanasonic3`
/// (the 12-byte `Panasonic\0\0\0` prefix) — bundled `Start => '$valuePtr +
/// 12'` (`MakerNotes.pm:738`/`:757`). It is the DEFAULT `body_offset`; the
/// cross-table `MakerNoteLeica` (`:599-608`) / `MakerNoteLeica10` (`:724-730`)
/// instead route `LEICA\0\0\0` / `LEICA CAMERA AG\0` blobs to `%Panasonic::Main`
/// with `Start => '$valuePtr + 8'` (`:606`) / `'+ 18'` (`:728`), so the shared
/// `Walker`'s `panasonic_makernote_isolated_with_offset` takes the body offset
/// as a PARAMETER rather than hard-coding 12.
pub const HEADER_LEN: usize = 12;
