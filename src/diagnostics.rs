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
/// `$et->Warn` / `$et->Error` message, its [`Severity`], an optional
/// family-1 `group` (the active `$$et{SET_GROUP1}` at `Warn`/`Error` time —
/// `ExifTool.pm:9475` `$grps[1] or $grps[1] = $$self{SET_GROUP1}`), and two
/// forward-compat flags (`ignorable` / `no_count`) that Phase C's faithful
/// multi-warning / `[minor]` / `[x$n]` accounting will read
/// (`ExifTool.pm` `Warn`/`WarnOnce` `$ignore` + `$$et{WARNED}` count). This
/// sub-phase sets the flags to the inert default (`ignorable == 0`,
/// `no_count == false`) and surfaces only the FIRST DOCUMENT-level
/// warning/error (unchanged document output) — see the module docs.
///
/// **Group scoping (Phase B.1.5).** Every `$et->Warn(msg)` is the FoundTag
/// `Warning` (`ExifTool.pm:5638`); its family-1 group is whatever
/// `$$self{SET_GROUP1}` was active (`ExifTool.pm:9475`), defaulting to the
/// `ExifTool` group (the document-level `ExifTool:Warning`) when none is set.
/// So a diagnostic with `group == None` is the document-level warning/error
/// (drained into the [`TagMap`](crate::tagmap::TagMap)'s warning/error
/// accumulator); a diagnostic with `group == Some("Info")` /
/// `Some("MXF")` / `Some("Track1")` is the group-scoped `<group>:Warning` /
/// `<group>:Error` TAG (emitted into the same `TagMap` via the normal tag
/// path, exactly as QuickTime's `Track<N>:Warning` rides its `Taggable`
/// stream). See [`run_diagnostics`].
///
/// Encapsulated per the crate accessor convention (no public fields): build
/// with [`Diagnostic::warn`] / [`Diagnostic::error`] (the document-level
/// common case), [`Diagnostic::warn_in_group`] / [`Diagnostic::error_in_group`]
/// (group-scoped), or the full [`Diagnostic::new`]; read via the accessors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Diagnostic {
  message: SmolStr,
  severity: Severity,
  /// The family-1 group the warning/error tag is scoped to (the active
  /// `$$et{SET_GROUP1}`), or `None` for the document-level
  /// `ExifTool:Warning` / `ExifTool:Error`.
  group: Option<SmolStr>,
  ignorable: u8,
  no_count: bool,
}

impl Diagnostic {
  /// Compose a [`Diagnostic`] from its message, [`Severity`], optional family-1
  /// `group` (the active `$$et{SET_GROUP1}`; `None` ⇒ document-level), and the
  /// forward-compat `ignorable` / `no_count` flags (Phase C).
  #[must_use]
  #[inline(always)]
  pub const fn new(
    message: SmolStr,
    severity: Severity,
    group: Option<SmolStr>,
    ignorable: u8,
    no_count: bool,
  ) -> Self {
    Self {
      message,
      severity,
      group,
      ignorable,
      no_count,
    }
  }

  /// A plain DOCUMENT-level `$et->Warn(msg)` (no `SET_GROUP1` active) —
  /// [`Severity::Warn`], `group == None` (→ `ExifTool:Warning`),
  /// `ignorable == 0`, `no_count == false` (the common case).
  #[must_use]
  #[inline(always)]
  pub fn warn(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Warn, None, 0, false)
  }

  /// A plain DOCUMENT-level `$et->Error(msg)` — [`Severity::Error`],
  /// `group == None` (→ `ExifTool:Error`), `ignorable == 0`,
  /// `no_count == false`.
  #[must_use]
  #[inline(always)]
  pub fn error(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Error, None, 0, false)
  }

  /// A GROUP-SCOPED `$et->Warn(msg)` raised while `$$et{SET_GROUP1} == group`
  /// — surfaces as the `<group>:Warning` TAG (`ExifTool.pm:5638`/`:9475`),
  /// NOT the document-level `ExifTool:Warning`. E.g. `group = "Info"`
  /// (Matroska's `Illegal float size`, Matroska.pm:1121/1179) or
  /// `group = "MXF"` (MXF's `Bad array or batch size`, MXF.pm:2528/2838).
  #[must_use]
  #[inline(always)]
  pub fn warn_in_group(group: impl Into<SmolStr>, message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Warn, Some(group.into()), 0, false)
  }

  /// A GROUP-SCOPED `$et->Error(msg)` — surfaces as the `<group>:Error` TAG
  /// (`ExifTool.pm:5659`/`:9475`), NOT the document-level `ExifTool:Error`.
  #[must_use]
  #[inline(always)]
  pub fn error_in_group(group: impl Into<SmolStr>, message: impl Into<SmolStr>) -> Self {
    Self::new(
      message.into(),
      Severity::Error,
      Some(group.into()),
      0,
      false,
    )
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

  /// The family-1 group this diagnostic is scoped to (the active
  /// `$$et{SET_GROUP1}`), or `None` for the document-level
  /// `ExifTool:Warning` / `ExifTool:Error`.
  #[must_use]
  #[inline(always)]
  pub fn group(&self) -> Option<&str> {
    self.group.as_deref()
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

/// Drive any [`Diagnose`] into the [`TagMap`](crate::tagmap::TagMap) sink, in
/// emission order. The sibling of [`run_emission`](crate::emit::run_emission):
/// `run_emission` writes the format tag stream, `run_diagnostics` writes the
/// `$et->Warn`/`$et->Error` stream.
///
/// Each diagnostic is dispatched on its family-1 `group` — the faithful
/// `ExifTool.pm:9475` `$grps[1] or $grps[1] = $$self{SET_GROUP1}` rule:
///
/// - **`group == None` ⇒ document-level** (`$$et{SET_GROUP1}` was unset, so the
///   `Warning`/`Error` FoundTag lands in the `ExifTool` group). Drained into
///   the sink's warning/error accumulator
///   ([`TagMap::write_warning`](crate::tagmap::TagMap::write_warning) /
///   [`write_error`](crate::tagmap::TagMap::write_error)); the document
///   surfaces only the FIRST of each
///   ([`TagMap::first_warning`](crate::tagmap::TagMap::first_warning) /
///   [`first_error`](crate::tagmap::TagMap::first_error)) as
///   `ExifTool:Warning` / `ExifTool:Error`. UNCHANGED from B.1.
/// - **`group == Some(g)` ⇒ group-scoped** (a `SET_GROUP1` was active). Emitted
///   as a `Warning` / `Error` TAG in family-1 group `g` via the normal tag path
///   ([`TagMap::write_value`](crate::tagmap::TagMap::write_value)), so it
///   surfaces as `<g>:Warning` / `<g>:Error` in the `-G1` document — byte-for-
///   byte how QuickTime's `Track<N>:Warning` rides its `Taggable` stream
///   (`formats/quicktime.rs`), and how the bundled `FoundTag('Warning', $str)`
///   (`ExifTool.pm:5638`) places it. Because the group-scoped key is unique
///   (`Info:Warning`, `MXF:Warning`, …), running AFTER `run_emission` is
///   value-equivalent (the `%noDups`/last-wins key set is unchanged).
///
/// Faithful multi-warning accumulation / `[x$n]` / `[minor]` prefixing is
/// DEFERRED to Phase C (the `ignorable`/`no_count` flags are carried for it).
pub(crate) fn run_diagnostics<D: Diagnose + ?Sized>(meta: &D, out: &mut crate::tagmap::TagMap) {
  for d in meta.diagnostics() {
    // `write_*` are infallible (`Result<(), Infallible>`); the sink keeps
    // occurrence order, the document serializer takes only the first of the
    // document-level accumulators.
    match (d.group(), d.severity()) {
      // Document-level (`SET_GROUP1` unset ⇒ `ExifTool:Warning`/`:Error`).
      (None, Severity::Warn) => {
        let _ = out.write_warning(d.message());
      }
      (None, Severity::Error) => {
        let _ = out.write_error(d.message());
      }
      // Group-scoped `<group>:Warning`/`<group>:Error` TAG — the active
      // `SET_GROUP1` is the family-1 group; the name is the FoundTag tag name
      // (`Warning`/`Error`, ExifTool.pm:5638/5659), the value is the message.
      (Some(group), Severity::Warn) => {
        let _ = out.write_value(
          group,
          "Warning",
          crate::value::TagValue::Str(d.message().into()),
        );
      }
      (Some(group), Severity::Error) => {
        let _ = out.write_value(
          group,
          "Error",
          crate::value::TagValue::Str(d.message().into()),
        );
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
  /// forward-compat flags + document-level group (`None`); the group-scoped
  /// constructors set the family-1 group. Accessors read them back.
  #[test]
  fn diagnostic_constructors_and_accessors() {
    let w = Diagnostic::warn("Bad APE trailer");
    assert_eq!(w.message(), "Bad APE trailer");
    assert_eq!(w.severity(), Severity::Warn);
    assert_eq!(w.group(), None);
    assert_eq!(w.ignorable(), 0);
    assert!(!w.no_count());

    let e = Diagnostic::error("File format error");
    assert_eq!(e.message(), "File format error");
    assert_eq!(e.severity(), Severity::Error);
    assert_eq!(e.group(), None);

    let g = Diagnostic::warn_in_group("Info", "Illegal float size (3)");
    assert_eq!(g.message(), "Illegal float size (3)");
    assert_eq!(g.severity(), Severity::Warn);
    assert_eq!(g.group(), Some("Info"));

    let ge = Diagnostic::error_in_group("MXF", "boom");
    assert_eq!(ge.group(), Some("MXF"));
    assert_eq!(ge.severity(), Severity::Error);
  }

  /// [`run_diagnostics`] drains DOCUMENT-level [`Diagnostic`]s into the sink's
  /// warning/error accumulators in emission order; the document surfaces the
  /// FIRST of each.
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

  /// A GROUP-SCOPED [`Diagnostic`] is routed to the TAG path
  /// (`<group>:Warning` / `<group>:Error`) via `write_value`, NOT the
  /// document-level warning/error accumulator. The document accumulators stay
  /// empty (no `ExifTool:Warning`/`:Error`).
  #[test]
  fn run_diagnostics_routes_group_scoped_to_tag() {
    use crate::value::TagValue;
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn_in_group("Info", "Illegal float size (3)"),
          Diagnostic::error_in_group("MXF", "boom"),
        ]
      }
    }

    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    // No document-level diagnostics.
    assert_eq!(tm.first_warning(), None);
    assert_eq!(tm.first_error(), None);
    // The group-scoped warning/error landed as TAGS.
    assert_eq!(
      tm.get("Info", "Warning"),
      Some(&TagValue::Str("Illegal float size (3)".into()))
    );
    assert_eq!(tm.get("MXF", "Error"), Some(&TagValue::Str("boom".into())));
  }

  /// Document-level and group-scoped diagnostics coexist: the document warning
  /// reaches the accumulator (→ `ExifTool:Warning`), the group-scoped warning
  /// reaches the tag store (→ `<group>:Warning`).
  #[test]
  fn run_diagnostics_mixes_document_and_group_scoped() {
    use crate::value::TagValue;
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn("Truncated Matroska header"),
          Diagnostic::warn_in_group("Info", "Illegal float size (3)"),
        ]
      }
    }

    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    assert_eq!(tm.first_warning(), Some("Truncated Matroska header"));
    assert_eq!(
      tm.get("Info", "Warning"),
      Some(&TagValue::Str("Illegal float size (3)".into()))
    );
  }
}
