// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The unified error-recovery vocabulary (golden pattern, **Contract 1**).
//!
//! ExifTool expresses "what to do at this malformed-input point" with bare Perl
//! control words inside its parse loops — `next` (skip this record), `last` /
//! `return 0` mid-walk (stop this directory), `return 0` at the detect/file
//! level ("not this candidate"). A faithful 1:1 port has, until now, mirrored
//! each of those with a bare `break` / `continue` / `return None` plus a
//! `// .pm:LINE` comment. That is faithful in INTENT, but the abort-vs-skip
//! decision is enforced only by per-site review (the "F1" defect class): a
//! reviewer must read the cited Perl line to confirm a `break` should not have
//! been a `continue`, and nothing in the type system records the mapping.
//!
//! [`Step`] gives that decision a TYPED, reviewable name. A parse-loop body
//! returns a [`Step`] saying what ExifTool does at the point it reached; the
//! **loop driver is the single recovery boundary** that interprets it
//! ([`Step::Keep`] / [`Step::Skip`] continue the loop, [`Step::AbortDir`] stops
//! THIS loop/directory keeping everything gathered so far, [`Step::Reject`]
//! unwinds a detect/probe to "not this candidate"). The recovery decision then
//! lives in ONE place per loop instead of being scattered across every `break`
//! / `continue` site, and each site's variant can be checked 1:1 against the
//! Perl control word it cites.
//!
//! # The EXIF reference (and the rest of the tower)
//!
//! The EXIF IFD walker ([`crate::exif`]) is the reference implementation:
//! `walk_entry` returns a [`Step`] and `walk_entries` is the loop driver that
//! interprets it. This is the prototype the remaining tower ports (m2ts position
//! recovery, …) and any NEW port adopt instead of a bare `break` / `continue`:
//! e.g. M2TS.pm's `last` on a lost packet boundary becomes [`Step::AbortDir`].
//! Existing faithful walkers whose bare `break` / `continue` is already correct
//! and `.pm`-cited do not NEED retrofitting — establishing this typed vocabulary
//! plus the documented rule below IS Contract 1; adopting [`Step`] is how new
//! and resumed ports stay on the contract.
//!
//! # Faithfulness rule (faithful by default, opt-in salvage)
//!
//! **Each site's [`Step`] variant MUST equal the ExifTool control word at the
//! cited `.pm` line.** A `next` is [`Step::Skip`]; a `last` / mid-walk
//! `return 0` is [`Step::AbortDir`]; a detect/file-level `return 0` is
//! [`Step::Reject`]; a normally-processed record is [`Step::Keep`]. Deviating to
//! salvage MORE than bundled does — e.g. returning [`Step::Skip`] (drop one
//! record, keep walking) where ExifTool `last`s (abandons the rest) — is a
//! behavior change and is forbidden by default. If a deviation is ever
//! justified it MUST carry an explicit, greppable annotation at the site:
//!
//! ```text
//! // SALVAGE: deviates from .pm last @LINE — <reason>
//! ```
//!
//! so the non-faithful points are enumerable (`rg 'SALVAGE:'`) and reviewable as
//! a closed set, rather than hiding among the faithful `break`s.
//!
//! Not `alloc`-gated (unlike [`emit`](crate::emit) / [`diagnostics`](crate::diagnostics)):
//! [`Step`] is a 1-byte control-flow value with no heap, usable from every
//! build — including the `no_std` EXIF walker that is not behind `alloc`.

/// What bundled ExifTool does at one point in a parse loop — the typed
/// recovery vocabulary (golden pattern **Contract 1**). The loop driver is the
/// single boundary that interprets it; see the [module docs](self) for the
/// faithfulness rule and the EXIF reference.
///
/// The variants are keyed 1:1 to the Perl control words ExifTool uses at these
/// points:
///
/// | [`Step`]   | ExifTool                          | Loop driver does            |
/// |------------|-----------------------------------|-----------------------------|
/// | [`Keep`]   | record processed normally; fall through | advance to the next record |
/// | [`Skip`]   | `next`                            | drop THIS record, continue  |
/// | [`AbortDir`] | `last` / mid-walk `return 0`    | stop THIS loop/dir, keep what was gathered |
/// | [`Reject`] | detect/file-level `return 0`      | unwind to "not this candidate" |
///
/// [`Keep`]: Step::Keep
/// [`Skip`]: Step::Skip
/// [`AbortDir`]: Step::AbortDir
/// [`Reject`]: Step::Reject
///
/// Unit-only enum: `is_keep` / `is_skip` / `is_abort_dir` / `is_reject`
/// predicates (via [`derive_more::IsVariant`]) plus the mandatory [`as_str`],
/// with [`Display`](derive_more::Display) routed through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Display, derive_more::IsVariant)]
#[display("{}", self.as_str())]
pub enum Step {
  /// The record was processed normally — fall through to the next one. The
  /// loop driver advances. (ExifTool: the loop body ran to its end with no
  /// `next` / `last`.)
  Keep,
  /// Perl `next` — drop THIS record and continue the loop. A non-fatal,
  /// single-record skip (a bad/odd entry the surrounding loop steps over): the
  /// loop driver moves to the next record, having gathered nothing for this
  /// one.
  Skip,
  /// Perl `last` / a mid-walk `return 0` — stop THIS loop/directory but KEEP
  /// the tags and diagnostics gathered so far. The loop driver breaks out of
  /// the current directory; it does NOT discard prior results, and (for a
  /// chained walk) it does NOT follow the directory's trailing continuation
  /// (e.g. a next-IFD pointer), because the Perl `return 0` exits before that
  /// point. Faithful to ExifTool abandoning the rest of one directory while
  /// retaining what it already found.
  AbortDir,
  /// Perl `return 0` at the detect / file level — "not this candidate". The
  /// caller unwinds the probe (typically to a `None` / `false`), as ExifTool
  /// does when a format's `ProcessXxx` / detection decides the input is not
  /// its format. Distinct from [`AbortDir`](Step::AbortDir): that abandons one
  /// directory MID-parse keeping partial results, whereas `Reject` declines
  /// the whole candidate.
  Reject,
}

impl Step {
  /// The stable string name (single source of truth for
  /// [`Display`](derive_more::Display)). Matches the variant identifier.
  #[must_use]
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Keep => "Keep",
      Self::Skip => "Skip",
      Self::AbortDir => "AbortDir",
      Self::Reject => "Reject",
    }
  }

  /// `true` if the loop driver should ADVANCE to the next record — i.e. the
  /// loop continues. Both [`Keep`](Step::Keep) (record processed) and
  /// [`Skip`](Step::Skip) (record dropped) continue the loop; the predicate
  /// folds the two "keep walking" outcomes so a driver can branch on
  /// "continue vs stop" in one test.
  #[must_use]
  #[inline(always)]
  pub const fn continues(&self) -> bool {
    matches!(self, Self::Keep | Self::Skip)
  }
}

#[cfg(test)]
mod tests {
  use super::Step;

  /// `continues()` is true for exactly the two loop-advancing variants and
  /// false for the two stop variants — the loop driver's branch contract.
  #[test]
  fn continues_partitions_advance_vs_stop() {
    assert!(Step::Keep.continues());
    assert!(Step::Skip.continues());
    assert!(!Step::AbortDir.continues());
    assert!(!Step::Reject.continues());
  }

  /// `as_str` matches the variant name and round-trips through `Display`.
  #[test]
  fn as_str_matches_display() {
    for (step, name) in [
      (Step::Keep, "Keep"),
      (Step::Skip, "Skip"),
      (Step::AbortDir, "AbortDir"),
      (Step::Reject, "Reject"),
    ] {
      assert_eq!(step.as_str(), name);
      assert_eq!(std::format!("{step}"), name);
    }
  }

  /// The `IsVariant` predicates partition the four variants exactly.
  #[test]
  fn is_variant_predicates() {
    assert!(Step::Keep.is_keep());
    assert!(Step::Skip.is_skip());
    assert!(Step::AbortDir.is_abort_dir());
    assert!(Step::Reject.is_reject());
    assert!(!Step::Keep.is_skip());
    assert!(!Step::AbortDir.is_reject());
  }
}
