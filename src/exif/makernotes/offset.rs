// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Compute the child IFD walk's `$$dirInfo{Base}` from the dispatch
//! [`BaseRule`](super::BaseRule).
//!
//! ## Bundled formulas
//!
//! `MakerNotes.pm` `SubDirectory` `Base` is a Perl expression evaluated
//! with these variables in scope (`Exif.pm:6920-7050`):
//!
//! - `$valuePtr`: absolute file offset of the maker-note blob's first byte
//!   (parent walk's `$base + $$dirInfo{DataPos} + $valuePtr` — the offset
//!   the parent IFD entry referenced).
//! - `$start`: absolute file offset of the CHILD walk's first IFD byte
//!   (`$valuePtr + Start` where `Start` was just evaluated for this
//!   subdir).
//! - `$base`: the parent walk's `$$dirInfo{Base}`.
//!
//! The new `$$dirInfo{Base}` for the child = `Base`'s value.
//!
//! ## Port surface
//!
//! In the port, the maker-note blob is a borrowed `&[u8]`; offsets INSIDE
//! the blob are blob-relative. The CHILD walk needs to know how to
//! interpret an absolute pointer found inside the blob (e.g. an IFD's
//! value-or-offset field that exceeds 4 bytes).
//!
//! [`resolve_child_base`] takes:
//!
//! - the parent walk's `$base` (the standalone-TIFF / JPEG-APP1 base),
//! - the blob's file offset (`$valuePtr`),
//! - the body offset within the blob (`Start - $valuePtr`),
//! - the [`BaseRule`](super::BaseRule),
//!
//! and returns the child's `$$dirInfo{Base}`. The Phase-2+ MakerNote
//! walker will pass this to a recursive call into the Exif walker.
//!
//! Phase 1 surfaces the value; nobody calls it from the production code
//! path yet (the Phase-1 walker only IDENTIFIES the vendor — it does
//! not recurse), but the function is the surface a Phase 2+ caller
//! consumes. The unit tests assert each formula matches the bundled
//! expression exactly.

use super::detected::BaseRule;

/// Compute the child IFD walk's `$$dirInfo{Base}` per the bundled
/// `SubDirectory{Base}` directive.
///
/// - `parent_base`: the PARENT walk's `$$dirInfo{Base}` (i.e. `$base`
///   in the Perl expression). For a standalone TIFF this is 0; for a
///   JPEG APP1 Exif block it is the file offset of the TIFF header.
/// - `value_ptr`: the file offset of the MakerNote blob's first byte
///   (`$valuePtr`).
/// - `body_offset`: the in-blob offset to the child IFD start (the
///   bundled `Start`'s addend — e.g. 14 for Apple). The `$start`
///   variable in Perl is `value_ptr + body_offset`.
/// - `rule`: the dispatch [`BaseRule`].
///
/// Returns the absolute file offset to use as the child's
/// `$$dirInfo{Base}`. Saturating arithmetic on the i64 carries —
/// degenerate dispatch (e.g. `RelativeToStart(-99999)` against a
/// `value_ptr` of 0) is clamped at 0; the port never panics on
/// over/underflow.
#[must_use]
pub fn resolve_child_base(
  parent_base: u32,
  value_ptr: u32,
  body_offset: u16,
  rule: BaseRule,
) -> u32 {
  // The parent's `$start` in the Perl expression — absolute file offset of
  // the child IFD start.
  let start = i64::from(value_ptr) + i64::from(body_offset);
  let resolved: i64 = match rule {
    // `Base => '$start + delta'` (delta is signed — Apple's -14, etc.)
    BaseRule::RelativeToStart(delta) => start + i64::from(delta),
    // `Base => '$start'` — FujiFilm (`MakerNotes.pm:131`).
    BaseRule::StartItself => start,
    // `Base => '-$base'` — Leica7 (`MakerNotes.pm:699`). NOTE: this is a
    // PLACEHOLDER. Leica7 is a `LeicaTrailer` tag (`MakerNotes.pm:694`)
    // and `ProcessLeicaTrailer` overrides the base with the trailer's
    // ABSOLUTE file offset; the bundled `-$base` is never the final
    // value for a real file. The port computes `-parent_base` (the
    // literal expression) and the clamp-at-0 below is NOT faithful — it
    // is a Phase-1 placeholder pending the Phase-2+ trailer handler.
    BaseRule::NegativeOfBase => -i64::from(parent_base),
    // `Base => n` — a LITERAL absolute base (Panasonic3 `Base => 12`,
    // `MakerNotes.pm:758`; Hasselblad `Base => 0`, `:176`). The child's
    // base is the literal `n` itself, independent of `$start`/`$base`.
    BaseRule::Literal(n) => n,
    // No `Base` line — child reuses the parent walk's base verbatim.
    BaseRule::Inherit => i64::from(parent_base),
  };
  // Clamp at u32 range — bundled would `Warn` and skip the directory on
  // an out-of-bounds base; the Phase-2+ walker will inherit that warning
  // path. Saturate so a degenerate dispatch never panics here.
  if resolved < 0 {
    0
  } else if resolved > i64::from(u32::MAX) {
    u32::MAX
  } else {
    resolved as u32
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Apple — `Base => '$start - 14'`. With `value_ptr=1000`,
  /// `body_offset=14`, the child base is `$start - 14 = 1000 + 14 - 14
  /// = 1000` — back to the blob start. (`MakerNotes.pm:43`.)
  #[test]
  fn apple_base_resolves_to_blob_start() {
    let base = resolve_child_base(0, 1000, 14, BaseRule::RelativeToStart(-14));
    assert_eq!(base, 1000);
  }

  /// Nikon — `Base => '$start - 8'` (`MakerNotes.pm:56`).
  /// `value_ptr=1000`, `body_offset=18` ⇒ `$start = 1018`, child base
  /// = `1018 - 8 = 1010`.
  #[test]
  fn nikon_base_resolves_relative() {
    let base = resolve_child_base(0, 1000, 18, BaseRule::RelativeToStart(-8));
    assert_eq!(base, 1010);
  }

  /// FujiFilm — `Base => '$start'` (`MakerNotes.pm:131`).
  /// `value_ptr=1000`, `body_offset=8` ⇒ child base = `1008`.
  #[test]
  fn fujifilm_base_resolves_to_start() {
    let base = resolve_child_base(0, 1000, 8, BaseRule::StartItself);
    assert_eq!(base, 1008);
  }

  /// Canon — `Inherit`: child base equals parent base
  /// (`MakerNotes.pm:60-68` has no `Base` line).
  #[test]
  fn canon_base_inherits_parent() {
    let base = resolve_child_base(42, 1000, 0, BaseRule::Inherit);
    assert_eq!(base, 42);
  }

  /// Panasonic3 (DC-FT7) — `Base => 12` is a LITERAL absolute 12
  /// (`MakerNotes.pm:758`), NOT `$start + 12`. The child base is exactly
  /// 12 regardless of `value_ptr` / `body_offset`.
  #[test]
  fn panasonic3_base_is_literal_12() {
    let base = resolve_child_base(0, 1000, 12, BaseRule::Literal(12));
    assert_eq!(base, 12);
    // Independent of value_ptr / body_offset (it's a literal).
    assert_eq!(resolve_child_base(500, 9999, 12, BaseRule::Literal(12)), 12);
  }

  /// Hasselblad — `Base => 0` is a LITERAL absolute 0 (`MakerNotes.pm:176`).
  #[test]
  fn hasselblad_base_is_literal_zero() {
    let base = resolve_child_base(42, 1000, 0, BaseRule::Literal(0));
    assert_eq!(base, 0);
  }

  /// `NegativeOfBase` clamps to 0 when `parent_base > 0` would underflow
  /// (the port never goes negative; bundled would warn and skip).
  #[test]
  fn negative_of_base_clamps_at_zero() {
    // Parent base 100 → child base = -100 → clamp to 0.
    let base = resolve_child_base(100, 1000, 8, BaseRule::NegativeOfBase);
    assert_eq!(base, 0);
  }

  /// `NegativeOfBase` with parent base 0 is 0 (no shift).
  #[test]
  fn negative_of_base_at_zero_parent_is_zero() {
    let base = resolve_child_base(0, 1000, 8, BaseRule::NegativeOfBase);
    assert_eq!(base, 0);
  }
}
