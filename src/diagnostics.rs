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
use std::string::String;
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
/// 13 bespoke per-format warning/error accessor shapes. Carries the BARE
/// `$et->Warn` / `$et->Error` message (NO `[minor]`/`[x$n]` baked in — those
/// are applied centrally by [`run_diagnostics`], the port's `sub Warn`
/// analogue), its [`Severity`], an optional family-1 `group` (the active
/// `$$et{SET_GROUP1}` at `Warn`/`Error` time — `ExifTool.pm:9475`
/// `$grps[1] or $grps[1] = $$self{SET_GROUP1}`), and two flags
/// (`ignorable` / `no_count`) that drive that accounting:
///
/// - **`ignorable`** is `sub Warn`'s 3rd argument (`ExifTool.pm:5616-5618`):
///   `0` = normal, `1` = minor (→ `[minor] ` prefix), `2` = minor with a
///   behavioural change when ignored (→ `[Minor] ` prefix), `3` = a warning
///   suppressed only under the `Validate` option (still `[minor] `-prefixed in
///   normal mode — the `'3' ne '2'` else-branch at `ExifTool.pm:5630`).
///   `ignorable >= 1` is also what the `IgnoreMinorErrors` (`-m`) option would
///   suppress (`ExifTool.pm:5627`) — see [`run_diagnostics`] for why that gate
///   is a documented-deferred reading option, not present here.
/// - **`no_count`** is `sub Warn`'s `0x04` bit (`ExifTool.pm:5621-5623`): when
///   set, a REPEAT of an identical message does NOT increment the occurrence
///   count, so it never grows a ` [x$n]` suffix.
///
/// Construct the common cases with [`Diagnostic::warn`] / [`Diagnostic::error`]
/// (`ignorable == 0`), the minor cases with [`Diagnostic::warn_minor`]
/// (`ignorable == 1`) / [`Diagnostic::warn_minor_behavioral`]
/// (`ignorable == 2`), or the full [`Diagnostic::new`].
///
/// **Group scoping (Phase B.1.5).** Every `$et->Warn(msg)` is the FoundTag
/// `Warning` (`ExifTool.pm:5638`); its family-1 group is whatever
/// `$$self{SET_GROUP1}` was active (`ExifTool.pm:9475`), defaulting to the
/// `ExifTool` group (the document-level `ExifTool:Warning`) when none is set.
/// So a diagnostic with `group == None` is the document-level warning/error
/// (drained into the [`TagMap`](crate::tagmap::TagMap)'s warning/error
/// accumulator). A diagnostic with `group == Some(...)` is GROUP-SCOPED —
/// the `<group>:Warning`/`<group>:Error` TAG. NOTE (Phase B R1): the ported
/// formats do NOT raise group-scoped diagnostics through this channel; a
/// `<group>:Warning`/`<group>:Error` is emitted IN-STREAM as an ordinary tag
/// in the format's [`Taggable`](crate::emit::Taggable) `tags()` at the walk
/// position (like QuickTime's `Track<N>:Warning`), so a collision with a real
/// same-group `Warning`/`Error` is resolved by faithful FoundTag order
/// (priority-0 first-wins, [`crate::tagmap::TagMap`]). The group-scoped
/// constructors + the `run_diagnostics` group arm are retained for the general
/// API surface — see [`run_diagnostics`] for why production routes in-stream.
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

  /// A DOCUMENT-level MINOR `$et->Warn(msg, 1)` — `ignorable == 1`, so
  /// [`run_diagnostics`] renders it `"[minor] <msg>"` (`ExifTool.pm:5630`).
  /// The message stored here is BARE; the prefix is mechanism-applied (single
  /// source of truth). E.g. ID3's `Missing ID3 terminating frame`
  /// (ID3.pm:1148 `$et->Warn(..., 1)`) and `Frame '...' is not valid for this
  /// ID3 version` (ID3.pm:1172).
  #[must_use]
  #[inline(always)]
  pub fn warn_minor(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Warn, None, 1, false)
  }

  /// A DOCUMENT-level MINOR-WITH-BEHAVIOURAL-CHANGE `$et->Warn(msg, 2)` —
  /// `ignorable == 2`, so [`run_diagnostics`] renders it `"[Minor] <msg>"`
  /// (the `'2'` arm of `ExifTool.pm:5630`). The message stored is BARE. E.g.
  /// EXIF's `Ignoring <dir> <tag> with excessive count` when the count is in
  /// `(100000, 2000000]` (`$minor = $count > 2000000 ? 0 : 2`, Exif.pm:6767).
  #[must_use]
  #[inline(always)]
  pub fn warn_minor_behavioral(message: impl Into<SmolStr>) -> Self {
    Self::new(message.into(), Severity::Warn, None, 2, false)
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

  /// The `$ignorable` level (`sub Warn`'s 3rd arg, `ExifTool.pm:5616-5630`):
  /// `0` = normal, `1` = `[minor] `, `2` = `[Minor] `, `3` = Validate-only
  /// (still `[minor] ` in normal mode). [`run_diagnostics`] reads it to apply
  /// the prefix.
  #[must_use]
  #[inline(always)]
  pub const fn ignorable(&self) -> u8 {
    self.ignorable
  }

  /// Whether a REPEAT of this exact message is excluded from the occurrence
  /// count (`sub Warn`'s `0x04` bit → `$noCount`, `ExifTool.pm:5621-5623`); a
  /// `no_count` message never grows a ` [x$n]` suffix.
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

  /// Yield this `Meta`'s [`Diagnostic`]s when the `ExtractEmbedded` (`-ee`) mode
  /// is `extract_embedded`. The default IGNORES the flag and delegates to
  /// [`Self::diagnostics`] — only a format whose DOCUMENT-level diagnostic
  /// stream differs by `-ee` overrides it. The lone such producer is QuickTime,
  /// whose Pittasoft `3gf ` `EEWarn` ("the `-ee` option may find more tags") is
  /// raised ONLY at no-`ee` (`!extract_embedded`) — under `-ee` ExifTool
  /// processes every record and the warning is absent (QuickTimeStream.pl:2693).
  /// This is the single seam the serializer's mode reaches the offset-ordered
  /// `Warning` first-wins drain through, so the `EEWarn` participates in the
  /// established priority-0 / file-position ordering rather than a side hook.
  #[must_use]
  fn diagnostics_with_options(&self, extract_embedded: bool) -> Vec<Diagnostic> {
    let _ = extract_embedded;
    self.diagnostics()
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
///   `ExifTool:Warning` / `ExifTool:Error`. This is the path EVERY ported
///   format uses for its document-level diagnostics.
/// - **`group == Some(g)` ⇒ group-scoped** (a `SET_GROUP1` was active). Emitted
///   as a `Warning` / `Error` TAG in family-1 group `g` via the normal tag path
///   ([`TagMap::write_value`](crate::tagmap::TagMap::write_value)), surfacing as
///   `<g>:Warning` / `<g>:Error`.
///
///   **IMPORTANT — production formats do NOT use this arm.** A group-scoped
///   `<g>:Warning`/`<g>:Error` can COLLIDE on its `-G1` token with a real
///   same-family-1 `Warning`/`Error` TAG (e.g. a Matroska SimpleTag
///   `TagName=Warning`). Both are priority-0 (`Extra`/`StdTag`
///   `Priority => 0`), so ExifTool keeps whichever the WALK reached FIRST
///   (ExifTool.pm:9544-9560 / 5404-5417). `run_diagnostics` runs AFTER
///   `run_emission` (the whole tag stream), so draining a group-scoped warning
///   HERE would place it after every real tag in FoundTag order — inverting the
///   walk order vs a real same-group `Warning` and (pre-fix) clobbering it under
///   last-wins. The fix: group-scoped `<g>:Warning`/`<g>:Error` are emitted
///   IN-STREAM as ordinary tags by the format's [`Taggable`](crate::emit::Taggable)
///   `tags()` AT THE WALK POSITION — exactly how QuickTime rides
///   `Track<N>:Warning`, and how Matroska / MXF now emit their group-scoped
///   warnings — so the [`TagMap`](crate::tagmap::TagMap)'s priority-0 first-wins
///   (`Warning`/`Error`) resolves the collision by faithful FoundTag order. This
///   arm is therefore retained ONLY for the general API surface (and the unit
///   tests); the [`Diagnose`] impls of the ported formats yield only
///   `group == None` diagnostics.
///
/// **`[minor]`/`[Minor]` prefixing + `[x$n]` count (Phase C, live).** This is
/// the port's faithful analogue of `sub Warn` (`ExifTool.pm:5616-5643`) plus
/// the end-of-extraction count pass (`ExifTool.pm:3196-3204`), applied to the
/// DOCUMENT-level (`group == None`) warning/error stream:
///
/// 1. **Prefix** (`ExifTool.pm:5630`): the stored message is BARE; this applies
///    `[minor] ` for `ignorable == 1` (and `== 3`, the Validate-only level
///    which is still `[minor] ` in normal mode) and `[Minor] ` for
///    `ignorable == 2`. Errors get the same prefix (`ExifTool.pm:5658`).
/// 2. **Dedup + count** (`ExifTool.pm:5632-5639`, `WAS_WARNED`): identical
///    PREFIXED messages are emitted as the `Warning` tag ONCE (first
///    occurrence); a repeat increments an occurrence count (unless the
///    diagnostic carries `no_count`, the `0x04` bit). At the end the surviving
///    distinct message gains a ` [x$n]` suffix when `n > 1`
///    (`ExifTool.pm:3199-3201`). This is warnings-only — `sub Error` is a plain
///    `FoundTag` with no `WAS_WARNED` (`ExifTool.pm:5648-5660`), so errors are
///    written in occurrence order with NO dedup/count (only the prefix).
///
/// `run_diagnostics` is the SOLE writer of the [`TagMap`](crate::tagmap::TagMap)
/// document warning/error accumulators (`run_emission` has no warning channel
/// and runs first), so the dedup/count is computed wholly here over this single
/// pass — exactly the per-file `$$self{WAS_WARNED}` scope. Group-scoped
/// `<g>:Warning`/`<g>:Error` (the `Some(group)` arm) ride the TAG path and are
/// NOT part of this `Warning`-tag count loop (`ExifTool.pm:3197` iterates only
/// the `ExifTool`-group `Warning`/`Warning (n)` tags) — and production formats
/// emit those in-stream anyway (see above), so the arm is API-surface-only.
///
/// **`IgnoreMinorErrors` (`-m`) is NOT gated here.** It is a READING option
/// (`$$self{OPTIONS}{IgnoreMinorErrors}`, `ExifTool.pm:5627`) that would SUPPRESS
/// every `ignorable >= 1` warning. The port has no options/flags channel to
/// thread such a reading option through, and the spec scoped it as "possible,
/// not present"; building a net-new options API is out of scope for this
/// cosmetic-completeness phase. The `ignorable` bit is carried + prefixed
/// faithfully, so the gate is a localized follow-up: a single
/// `if ignore_minor && d.ignorable() >= 1 { continue }` here once an options
/// surface exists. Default behaviour (option off) is unchanged + faithful.
///
/// The 2-arg convenience (no-`ee`, the faithful base mode) is a TEST-only
/// shorthand: production always knows its `-ee` mode and drives
/// [`run_diagnostics_with_options`] directly (the serializer's single
/// mode-carrying entry), so the `-ee`-sensitive QuickTime `EEWarn` participates
/// in the established priority-0 / file-position first-wins ordering.
#[cfg(test)]
pub(crate) fn run_diagnostics<D: Diagnose + ?Sized>(meta: &D, out: &mut crate::tagmap::TagMap) {
  run_diagnostics_with_options(meta, false, out);
}

/// [`run_diagnostics`] threaded with the `ExtractEmbedded` (`-ee`) mode — the
/// serializer's single mode-carrying entry to the document-level diagnostics
/// drain. Routes through [`Diagnose::diagnostics_with_options`] so a format whose
/// doc-level `Warning` stream depends on `-ee` (QuickTime's Pittasoft `3gf `
/// `EEWarn`, raised only at no-`ee`) participates in the SAME priority-0 /
/// file-position first-wins ordering as every other doc warning.
pub(crate) fn run_diagnostics_with_options<D: Diagnose + ?Sized>(
  meta: &D,
  extract_embedded: bool,
  out: &mut crate::tagmap::TagMap,
) {
  // Document-level `WAS_WARNED` (`ExifTool.pm:5632`): the PREFIXED message in
  // first-occurrence order + its occurrence count. A `Vec` keeps the order
  // (the document surfaces the FIRST distinct message); the count drives the
  // ` [x$n]` suffix. Warning corpora are tiny (≤ a handful per file), so the
  // linear find is cheaper than a map + a side order list.
  let mut warned: Vec<WasWarned> = Vec::new();
  for d in meta.diagnostics_with_options(extract_embedded) {
    match (d.group(), d.severity()) {
      // Document-level (`SET_GROUP1` unset ⇒ `ExifTool:Warning`/`:Error`).
      (None, Severity::Warn) => {
        let msg = apply_minor_prefix(d.ignorable(), d.message());
        // `WAS_WARNED` dedup: bump an existing identical message's count
        // (unless `no_count`), else record it as a new first occurrence.
        if let Some(w) = warned.iter_mut().find(|w| w.message == msg) {
          if !d.no_count() {
            w.count += 1;
          }
        } else {
          warned.push(WasWarned {
            message: msg,
            count: 1,
          });
        }
      }
      (None, Severity::Error) => {
        // `sub Error` (`ExifTool.pm:5648`): plain `FoundTag('Error', $str)` —
        // no `WAS_WARNED`, so each error is written in order (the prefix still
        // applies to an ignorable error, `ExifTool.pm:5658`).
        let _ = out.write_error(&apply_minor_prefix(d.ignorable(), d.message()));
      }
      // Group-scoped `<group>:Warning`/`<group>:Error` TAG — the active
      // `SET_GROUP1` is the family-1 group; the name is the FoundTag tag name
      // (`Warning`/`Error`, ExifTool.pm:5638/5659), the value is the message.
      // (Production formats route these in-stream; this arm is API-surface +
      // unit tests. The `[x$n]` count loop is `ExifTool`-group only, so a
      // group-scoped warning carries only the `[minor]`/`[Minor]` prefix.)
      (Some(group), Severity::Warn) => {
        let _ = out.write_value(
          group,
          "Warning",
          crate::value::TagValue::Str(apply_minor_prefix(d.ignorable(), d.message()).into()),
        );
      }
      (Some(group), Severity::Error) => {
        let _ = out.write_value(
          group,
          "Error",
          crate::value::TagValue::Str(apply_minor_prefix(d.ignorable(), d.message()).into()),
        );
      }
    }
  }
  // End-of-extraction `[x$n]` pass (`ExifTool.pm:3196-3204`): append ` [x$n]`
  // to each distinct document-level warning that fired more than once, then
  // write the survivors into the sink in first-occurrence order.
  for mut w in warned {
    if w.count > 1 {
      let _ = core::fmt::write(&mut w.message, core::format_args!(" [x{}]", w.count));
    }
    let _ = out.write_warning(&w.message);
  }
}

/// One distinct document-level warning message (already `[minor]`/`[Minor]`-
/// prefixed) + its `WAS_WARNED` occurrence count, for the `[x$n]` pass.
struct WasWarned {
  message: String,
  count: u32,
}

/// Apply `sub Warn`'s `[minor]`/`[Minor]` prefix (`ExifTool.pm:5630`) to a bare
/// message, keyed on `ignorable`: `2` ⇒ `"[Minor] …"`; `1` or `3` ⇒
/// `"[minor] …"` (the `'3' ne '2'` else-branch — a Validate-only warning is
/// still `[minor] `-prefixed in normal mode); `0` ⇒ unchanged.
fn apply_minor_prefix(ignorable: u8, message: &str) -> String {
  match ignorable {
    0 => String::from(message),
    2 => {
      let mut s = String::with_capacity(8 + message.len());
      s.push_str("[Minor] ");
      s.push_str(message);
      s
    }
    _ => {
      let mut s = String::with_capacity(8 + message.len());
      s.push_str("[minor] ");
      s.push_str(message);
      s
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

    // The minor constructors set `ignorable` (1 / 2) but store the BARE
    // message — the prefix is applied by `run_diagnostics`, not baked in.
    let m1 = Diagnostic::warn_minor("Missing ID3 terminating frame");
    assert_eq!(m1.message(), "Missing ID3 terminating frame");
    assert_eq!(m1.ignorable(), 1);
    assert!(!m1.no_count());
    let m2 = Diagnostic::warn_minor_behavioral("Ignoring IFD0 tag 0x0001 with excessive count");
    assert_eq!(m2.ignorable(), 2);
    assert_eq!(
      m2.message(),
      "Ignoring IFD0 tag 0x0001 with excessive count"
    );
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

  /// [`apply_minor_prefix`] reproduces `sub Warn`'s `[minor]`/`[Minor]` rule
  /// (`ExifTool.pm:5630`): `2` ⇒ `[Minor] `; `1` and `3` ⇒ `[minor] `; `0` ⇒
  /// unchanged.
  #[test]
  fn minor_prefix_matches_warn() {
    assert_eq!(apply_minor_prefix(0, "msg"), "msg");
    assert_eq!(apply_minor_prefix(1, "msg"), "[minor] msg");
    assert_eq!(apply_minor_prefix(2, "msg"), "[Minor] msg");
    // Validate-only (level 3) is still `[minor] `-prefixed in normal mode
    // (the `'3' ne '2'` else-branch).
    assert_eq!(apply_minor_prefix(3, "msg"), "[minor] msg");
  }

  /// A MINOR `$et->Warn(msg, 1)` surfaces the `[minor] ` prefix from the
  /// mechanism (the stored message stays bare).
  #[test]
  fn run_diagnostics_applies_minor_prefix() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn_minor("Missing ID3 terminating frame"),
          Diagnostic::warn_minor_behavioral("Ignoring IFD0 tag 0x0001 with excessive count"),
        ]
      }
    }
    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    assert_eq!(
      tm.first_warning(),
      Some("[minor] Missing ID3 terminating frame")
    );
    assert_eq!(
      tm.warnings(),
      [
        "[minor] Missing ID3 terminating frame",
        "[Minor] Ignoring IFD0 tag 0x0001 with excessive count",
      ]
    );
  }

  /// `WAS_WARNED` dedup + the end-of-extraction `[x$n]` pass
  /// (`ExifTool.pm:3199-3201`, `:5632-5639`): identical messages collapse to a
  /// single `Warning` tag whose value gains ` [x$n]` (n = occurrences).
  #[test]
  fn run_diagnostics_counts_duplicate_warnings() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn("Short TIT2 frame"),
          Diagnostic::warn("Short TIT2 frame"),
          Diagnostic::warn("Short TIT2 frame"),
          Diagnostic::warn("Unique warning"),
        ]
      }
    }
    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    // The dup collapses to ONE tag with ` [x3]`; first-occurrence order kept.
    assert_eq!(tm.warnings(), ["Short TIT2 frame [x3]", "Unique warning"]);
    assert_eq!(tm.first_warning(), Some("Short TIT2 frame [x3]"));
  }

  /// The count keys on the PREFIXED message: a minor + a non-minor copy of the
  /// same bare text are DISTINCT warnings (ExifTool keys `WAS_WARNED` on the
  /// post-prefix `$str`), and each minor repeat still counts.
  #[test]
  fn run_diagnostics_counts_keyed_on_prefixed_message() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::warn_minor("dup"),
          Diagnostic::warn_minor("dup"),
          Diagnostic::warn("dup"),
        ]
      }
    }
    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    // `[minor] dup` fired twice (→ ` [x2]`); bare `dup` once (distinct key).
    assert_eq!(tm.warnings(), ["[minor] dup [x2]", "dup"]);
  }

  /// A `no_count` diagnostic (`sub Warn` `0x04`) never grows a ` [x$n]` suffix
  /// even when its identical message repeats.
  #[test]
  fn run_diagnostics_no_count_suppresses_suffix() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::new("noisy".into(), Severity::Warn, None, 0, true),
          Diagnostic::new("noisy".into(), Severity::Warn, None, 0, true),
        ]
      }
    }
    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    assert_eq!(tm.warnings(), ["noisy"]);
  }

  /// Errors are NOT deduped/counted (`sub Error` is a plain `FoundTag`), but an
  /// ignorable error still gets the `[minor]`/`[Minor]` prefix
  /// (`ExifTool.pm:5658`). The document surfaces the FIRST.
  #[test]
  fn run_diagnostics_errors_prefixed_not_counted() {
    struct Src;
    impl Diagnose for Src {
      fn diagnostics(&self) -> Vec<Diagnostic> {
        std::vec![
          Diagnostic::new("boom".into(), Severity::Error, None, 1, false),
          Diagnostic::new("boom".into(), Severity::Error, None, 0, false),
        ]
      }
    }
    let mut tm = crate::tagmap::TagMap::new();
    run_diagnostics(&Src, &mut tm);
    // First error prefixed `[minor]`; the second (bare) is kept too — no dedup.
    assert_eq!(tm.first_error(), Some("[minor] boom"));
  }
}
