// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Format-agnostic DIAGNOSTIC framework (golden pattern L3, Contract 2). The
//! parallel of [`emit`](crate::emit) for the `$et->Warn` / `$et->Error`
//! channel: a typed `Meta` implements [`Diagnose`] to yield its ExifTool-parity
//! diagnostics IN EMISSION ORDER, and [`run_diagnostics`] drains any
//! [`Diagnose`] into the [`TagMap`](crate::tagmap::TagMap) sink's warning/error
//! accumulators.
//!
//! This replaces the ~465-line hand-written per-format `match` (the retired
//! `AnyMeta::drain_diagnostics`) that drained **13 incompatible accessor
//! shapes** (`warnings() -> &[String]`, `warning() -> Option<&str>`,
//! `warn_bad_trailer() -> bool`, `has_format_error() -> bool`,
//! `is_corrupted() -> bool`, …). Every `Meta` now exposes ONE shape —
//! [`Diagnose::diagnostics`] — yielding owned [`Diagnostic`]s, and a
//! bool-predicate format yields the (formerly hardcoded-in-drain) warning
//! STRING as a [`Diagnostic`] from its own `diagnostics()`.
//!
//! `run_emission` (the [`Taggable`](crate::emit::Taggable) tag stream) has no
//! warning/error channel; this is the diagnostics-only second half of the
//! typed-Meta serialization path
//! (`AnyMeta::serialize_tags` = `run_emission` + `run_diagnostics`).
//!
//! Gated on `feature = "alloc"` to match [`emit`](crate::emit) /
//! [`tagmap`](crate::tagmap): a [`Diagnostic`] owns a [`SmolStr`] message and
//! [`Diagnose::diagnostics`] returns an `alloc`-gated `Vec`, and the engine
//! drains into the `alloc`-gated [`TagMap`](crate::tagmap::TagMap).

#![cfg(feature = "alloc")]

use smol_str::SmolStr;
use std::vec::Vec;

/// The severity of a [`Diagnostic`] — whether it lands in the
/// [`TagMap`](crate::tagmap::TagMap)'s `warnings` accumulator (`$et->Warn`,
/// `ExifTool.pm:1297`, surfaced as `ExifTool:Warning`) or its `errors`
/// accumulator (`$et->Error`, `ExifTool.pm:5648`, surfaced as `ExifTool:Error`).
///
/// Unit-only enum: `is_warn`/`is_error` predicates + the mandatory `as_str`,
/// with [`Display`](derive_more::Display) routed through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Display, derive_more::IsVariant)]
#[display("{}", self.as_str())]
pub enum Severity {
  /// A non-fatal `$et->Warn` — surfaces as `ExifTool:Warning`.
  Warn,
  /// A fatal `$et->Error` — surfaces as `ExifTool:Error`.
  Error,
}

impl Severity {
  /// The stable string name (single source of truth for
  /// [`Display`](derive_more::Display)).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Warn => "Warn",
      Self::Error => "Error",
    }
  }
}

/// One typed diagnostic from a format `Meta` — the unified replacement for the
/// 13 bespoke per-format warning/error accessor shapes. Carries the rendered
/// `$et->Warn` / `$et->Error` message, its [`Severity`], and two
/// forward-compat flags (`ignorable` / `no_count`) that Phase C's faithful
/// multi-warning / `[minor]` / `[x$n]` accounting will read
/// (`ExifTool.pm` `Warn`/`WarnOnce` `$ignore` + `$$et{WARNED}` count). This
/// sub-phase sets them to the inert default (`ignorable == 0`,
/// `no_count == false`) and surfaces only the FIRST warning/error (unchanged
/// document output) — see the module docs.
///
/// Encapsulated per the crate accessor convention (no public fields): build
/// with [`Diagnostic::warn`] / [`Diagnostic::error`] (the common case) or the
/// full [`Diagnostic::new`], read via the accessors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Diagnostic {
  message: SmolStr,
  severity: Severity,
  ignorable: u8,
  no_count: bool,
}

impl Diagnostic {
  /// Compose a [`Diagnostic`] from its message, [`Severity`], and the
  /// forward-compat `ignorable` / `no_count` flags (Phase C).
  #[must_use]
  #[inline(always)]
  pub const fn new(message: SmolStr, severity: Severity, ignorable: u8, no_count: bool) -> Self {
    Self {
      message,
      severity,
      ignorable,
      no_count,
    }
  }

  /// A plain `$et->Warn(msg)` — [`Severity::Warn`], `ignorable == 0`,
  /// `no_count == false` (the common case).
  #[must_use]
  #[inline(always)]
  pub fn warn(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Warn, 0, false)
  }

  /// A plain `$et->Error(msg)` — [`Severity::Error`], `ignorable == 0`,
  /// `no_count == false`.
  #[must_use]
  #[inline(always)]
  pub fn error(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Error, 0, false)
  }

  /// The diagnostic message (`$et->Warn`/`$et->Error` argument).
  #[must_use]
  #[inline(always)]
  pub fn message(&self) -> &str {
    self.message.as_str()
  }

  /// This diagnostic's [`Severity`].
  #[must_use]
  #[inline(always)]
  pub const fn severity(&self) -> Severity {
    self.severity
  }

  /// The `$ignore` level (`ExifTool.pm` `Warn`/`WarnOnce`) — forward-compat
  /// for Phase C's `[minor]` accounting. `0` in this sub-phase.
  #[must_use]
  #[inline(always)]
  pub const fn ignorable(&self) -> u8 {
    self.ignorable
  }

  /// Whether this diagnostic is excluded from the `WarnOnce` count
  /// (`ExifTool.pm` `$noCount`) — forward-compat for Phase C's `[x$n]`
  /// accounting. `false` in this sub-phase.
  #[must_use]
  #[inline(always)]
  pub const fn no_count(&self) -> bool {
    self.no_count
  }
}

/// A typed `Meta` that yields its ExifTool-parity DIAGNOSTIC stream — the
/// `$et->Warn` / `$et->Error` channel parallel of
/// [`Taggable`](crate::emit::Taggable). Each format `Meta` implements it,
/// yielding its diagnostics (INCLUDING any chained sub-Meta's, in the
/// documented order — e.g. `Mp3` yields its ID3 / MPEG / APE sub-Metas'
/// diagnostics before its own) so [`run_diagnostics`] can drain the whole
/// `AnyMeta` in one pass.
pub trait Diagnose {
  /// Yield this `Meta`'s [`Diagnostic`]s in emission order (the order the
  /// retired per-format `serialize_tags` raised the `$et->Warn`/`$et->Error`
  /// calls; for a chained format, the sub-Metas' diagnostics precede /
  /// interleave per the documented `ProcessMP3`-style order). The default is
  /// "no diagnostics" — formats that never `Warn`/`Error` need not override.
  #[must_use]
  fn diagnostics(&self) -> Vec<Diagnostic> {
    Vec::new()
  }
}

/// Drive any [`Diagnose`] into the [`TagMap`](crate::tagmap::TagMap) sink's
/// warning/error accumulators, in emission order. The sibling of
/// [`run_emission`](crate::emit::run_emission): `run_emission` writes the tag
/// stream, `run_diagnostics` writes the `$et->Warn`/`$et->Error` stream. The
/// document path surfaces only the FIRST of each
/// ([`TagMap::first_warning`](crate::tagmap::TagMap::first_warning) /
/// [`first_error`](crate::tagmap::TagMap::first_error)) under default `-j`,
/// so this sub-phase stays output-preserving (the first [`Diagnostic`] ==
/// the old `first_warning`). Faithful multi-warning accumulation / `[x$n]` /
/// `[minor]` prefixing is DEFERRED to Phase C (the `ignorable`/`no_count`
/// flags are carried for it).
pub(crate) fn run_diagnostics<D: Diagnose + ?Sized>(meta: &D, out: &mut crate::tagmap::TagMap) {
  for d in meta.diagnostics() {
    // `write_warning`/`write_error` are infallible (`Result<(), Infallible>`);
    // the sink keeps occurrence order, the serializer takes only the first.
    match d.severity() {
      Severity::Warn => {
        let _ = out.write_warning(d.message());
      }
      Severity::Error => {
        let _ = out.write_error(d.message());
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A [`Severity`] round-trips through `as_str`, and `Display` routes through
  /// it (single source of truth).
  #[test]
  fn severity_as_str_and_display() {
    assert_eq!(Severity::Warn.as_str(), "Warn");
    assert_eq!(Severity::Error.as_str(), "Error");
    assert_eq!(std::format!("{}", Severity::Warn), "Warn");
    assert!(Severity::Warn.is_warn());
    assert!(Severity::Error.is_error());
  }

  /// [`Diagnostic::warn`] / [`Diagnostic::error`] set the severity + inert
  /// forward-compat flags; accessors read them back.
  #[test]
  fn diagnostic_constructors_and_accessors() {
    let w = Diagnostic::warn("Bad APE trailer");
    assert_eq!(w.message(), "Bad APE trailer");
    assert_eq!(w.severity(), Severity::Warn);
    assert_eq!(w.ignorable(), 0);
    assert!(!w.no_count());

    let e = Diagnostic::error("File format error");
    assert_eq!(e.message(), "File format error");
    assert_eq!(e.severity(), Severity::Error);
  }

  /// [`run_diagnostics`] drains a [`Diagnose`] into the sink's warning/error
  /// accumulators in emission order; the document surfaces the FIRST of each.
  #[test]
  fn run_diagnostics_drains_in_order() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn("first warning"),
          Diagnostic::error("an error"),
          Diagnostic::warn("second warning"),
        ]
      }
    }

    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    assert_eq!(tm.first_warning(), Some("first warning"));
    assert_eq!(tm.first_error(), Some("an error"));
    // both warnings reached the accumulator in order
    assert_eq!(tm.warnings(), ["first warning", "second warning"]);
  }
}
