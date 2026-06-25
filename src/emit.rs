// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Format-agnostic emission framework (golden pattern L3). A typed `Meta`
//! implements [`Taggable`] to yield its ExifTool-parity tags; [`run_emission`]
//! drives any [`Taggable`] into the [`TagMap`](crate::tagmap::TagMap) sink,
//! applying the cross-cutting rules ONCE (Unknown-suppression, then the
//! sink's `family1:name` dedup).
//!
//! This centralizes what each format's hand-rolled `serialize_tags` used to
//! repeat: a value's already been rendered for the requested [`ConvMode`]
//! (via the shared `render_value` for tag-table formats, or built directly for
//! domain-struct formats), so the engine only has to (1) drop `Unknown=>1`
//! tags — ExifTool's default output omits them (`ExifTool.pm:9179`) — and
//! (2) hand the survivor to the sink, which owns the dedup.
//!
//! Gated on `feature = "alloc"` to match [`tagmap`](crate::tagmap): the engine
//! writes into the `alloc`-gated [`TagMap`](crate::tagmap::TagMap), and an
//! [`EmittedTag`] carries an owned [`Tag`].

#![cfg(feature = "alloc")]

use crate::value::{Group, Tag, TagValue};
use smol_str::SmolStr;

/// ExifTool conversion mode — `-j` (PrintConv, human-readable) vs `-n`
/// (ValueConv, the post-ValueConv raw value). A [`Taggable`] renders its
/// values for the requested mode before yielding them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvMode {
  /// `-j`: PrintConv applied — the human-readable string ExifTool prints by
  /// default (e.g. ID3v1 Genre `"Hip-Hop"`).
  PrintConv,
  /// `-n`: ValueConv only — the machine value (e.g. Genre `7`).
  ValueConv,
}

impl ConvMode {
  /// Map the engine's `print_conv` boolean (the `-j`/`-n` toggle threaded
  /// through the typed `serialize_tags` path) to a [`ConvMode`]: `true` ⇒
  /// [`PrintConv`](Self::PrintConv) (`-j`), `false` ⇒
  /// [`ValueConv`](Self::ValueConv) (`-n`).
  #[must_use]
  #[inline(always)]
  pub const fn from_print_conv(print_conv: bool) -> Self {
    if print_conv {
      ConvMode::PrintConv
    } else {
      ConvMode::ValueConv
    }
  }

  /// The OPPOSITE conversion mode. Used by the Composite engine, which needs
  /// both a ValueConv view (`$val[i]`) and a PrintConv view (`$prt[i]`): the
  /// active-output mode's view is the emitted set, and the opposite-mode
  /// re-emission supplies the other view (see [`crate::composite`]).
  #[must_use]
  #[inline(always)]
  pub const fn flipped(self) -> Self {
    match self {
      ConvMode::PrintConv => ConvMode::ValueConv,
      ConvMode::ValueConv => ConvMode::PrintConv,
    }
  }
}

/// Options that shape a [`Taggable::tags`] emission: the conv mode (`-j`/`-n`),
/// ExifTool `-ee` (gates per-sample timed-metadata emission), and the
/// `-G1`/`-G3` group rendering. Non-timed formats read only
/// [`mode`](Self::mode); the timed-metadata emitter
/// ([`emit_timed_samples`](crate::formats::quicktime)) consults all three.
///
/// Built by external callers via [`EmitOptions::g1`] and handed to
/// [`Taggable::tags`]; the fields are crate-internal (the D8 no-public-fields
/// convention — and `group_mode`'s `GroupMode` is itself crate-private), read
/// by the in-crate emitters.
#[derive(Debug, Clone, Copy)]
pub struct EmitOptions {
  /// The `-j`/`-n` conversion mode every [`Taggable`] renders its values for.
  pub(crate) mode: ConvMode,
  /// ExifTool `-ee`: gates per-sample timed-metadata emission.
  pub(crate) extract_embedded: bool,
  /// `-G1` (doc axis collapsed) vs `-G3` (`Doc<N>:` prefixed) group rendering.
  pub(crate) group_mode: crate::serialize_key::GroupMode,
}

impl EmitOptions {
  /// The default `-G1` emission for a given conv mode + `-ee` flag.
  #[must_use]
  pub const fn g1(mode: ConvMode, extract_embedded: bool) -> Self {
    Self {
      mode,
      extract_embedded,
      group_mode: crate::serialize_key::GroupMode::G1,
    }
  }

  /// An emission for a given conv mode + `-ee` flag + explicit group rendering
  /// (`-G1` vs `-G3`). The `-G3` form is what the timed-metadata emitter needs
  /// to open a `Doc<N>` per sample; `-G1` collapses the doc axis (first-fix
  /// wins).
  #[must_use]
  pub(crate) const fn with_group_mode(
    mode: ConvMode,
    extract_embedded: bool,
    group_mode: crate::serialize_key::GroupMode,
  ) -> Self {
    Self {
      mode,
      extract_embedded,
      group_mode,
    }
  }
}

/// A rendered, ready-to-emit tag: the existing [`Tag`] (group + name + value,
/// already converted for the active [`ConvMode`]) plus the `Unknown=>1` flag
/// the engine uses to suppress it from default output (`ExifTool.pm:9179`).
///
/// Encapsulated per the crate accessor convention (no public fields): build
/// with [`EmittedTag::new`] (priority `1`, the ExifTool default) or
/// [`EmittedTag::new_with_priority`], read via [`tag`](Self::tag) /
/// [`unknown`](Self::unknown) / [`priority`](Self::priority), or take ownership
/// of the inner [`Tag`] with [`into_tag`](Self::into_tag).
///
/// `priority` is the tag's ExifTool `Priority => N` for duplicate handling
/// (`ExifTool.pm:9544-9560`): a NEW duplicate of an already-present
/// `(doc, family1, name)` overrides the existing value IFF its priority is
/// non-zero AND `>=` the stored one — a `Priority => 0` tag (e.g. `Warning` /
/// `Error`) therefore NEVER overrides. The default `1` reproduces ExifTool's
/// "no explicit Priority ⇒ forced to 1" rule (`ExifTool.pm:9553`), so an
/// ordinary tag keeps the faithful last-wins behavior. See
/// [`TagMap::insert`](crate::tagmap::TagMap).
#[derive(Debug, Clone)]
pub struct EmittedTag {
  tag: Tag,
  unknown: bool,
  /// ExifTool `Priority => N` (default `1`): a duplicate overrides only when
  /// `(priority != 0) && (priority >= stored_priority)`.
  priority: u8,
}

impl EmittedTag {
  /// Compose an [`EmittedTag`] from its group, name, already-rendered value,
  /// and the `Unknown=>1` flag (`true` ⇒ suppressed from default output). The
  /// tag takes ExifTool's default duplicate `Priority => 1`
  /// (`ExifTool.pm:9553`) — use [`new_with_priority`](Self::new_with_priority)
  /// to mark a `Priority => 0` tag (one that never overrides a duplicate).
  #[must_use]
  #[inline(always)]
  pub fn new(group: Group, name: SmolStr, value: TagValue, unknown: bool) -> Self {
    Self::new_with_priority(group, name, value, unknown, 1)
  }

  /// Compose an [`EmittedTag`] carrying an explicit ExifTool `Priority => N`
  /// for duplicate handling — `0` marks a tag that NEVER overrides an existing
  /// duplicate (`ExifTool.pm:9544-9560`); `1` is the default
  /// [`new`](Self::new) uses.
  #[must_use]
  #[inline(always)]
  pub fn new_with_priority(
    group: Group,
    name: SmolStr,
    value: TagValue,
    unknown: bool,
    priority: u8,
  ) -> Self {
    Self {
      tag: Tag::new(group, name, value),
      unknown,
      priority,
    }
  }

  /// The underlying [`Tag`] (group + name + value).
  #[must_use]
  #[inline(always)]
  pub const fn tag(&self) -> &Tag {
    &self.tag
  }

  /// Whether this tag carries ExifTool's `Unknown=>1` flag — the engine
  /// drops such tags from default output (`ExifTool.pm:9179`).
  #[must_use]
  #[inline(always)]
  pub const fn unknown(&self) -> bool {
    self.unknown
  }

  /// This tag's ExifTool `Priority => N` for duplicate handling (default `1`).
  /// A duplicate of an already-present `(doc, family1, name)` overrides the
  /// stored value only when `(priority != 0) && (priority >= stored_priority)`
  /// (`ExifTool.pm:9544-9560`), so a `Priority => 0` tag never overrides.
  #[must_use]
  #[inline(always)]
  pub const fn priority(&self) -> u8 {
    self.priority
  }

  /// Consume `self`, yielding the inner [`Tag`] (the engine moves it into the
  /// sink, avoiding a clone).
  #[must_use]
  #[inline(always)]
  pub fn into_tag(self) -> Tag {
    self.tag
  }
}

/// A typed `Meta` that yields its ExifTool-parity tag stream. Each yielded
/// [`EmittedTag`]'s value is ALREADY rendered for `mode` (via the shared
/// `render_value` for the tag-table archetype, or built directly for the
/// domain-struct archetype); the [`run_emission`] engine then applies the
/// cross-cutting rules.
pub trait Taggable {
  /// Yield this `Meta`'s [`EmittedTag`]s for the given [`EmitOptions`], in
  /// emission order (the sink keeps first-occurrence position on dedup). Most
  /// formats read only [`EmitOptions::mode`]; the timed-metadata path also
  /// consults `extract_embedded` / `group_mode`.
  fn tags(&self, opts: EmitOptions) -> impl Iterator<Item = EmittedTag> + '_;
}

/// Drive any [`Taggable`] into the [`TagMap`](crate::tagmap::TagMap) sink,
/// applying the cross-cutting rules ONCE:
///
/// 1. **Unknown-suppression** — a tag flagged `Unknown=>1` is skipped, because
///    ExifTool's default output omits unknown tags (`ExifTool.pm:9179`). Moving
///    this here lets every format drop its per-emitter `if unknown { continue }`.
/// 2. **`write_value_doc`** — the survivor's value, its `Priority => N`, and
///    its sub-document index are handed to the sink under the `family1:name`
///    key; [`TagMap`](crate::tagmap::TagMap) owns the priority-aware dedup
///    (ExifTool's general rule — a repeated key overrides the stored value IFF
///    the duplicate's priority is non-zero AND `>=` the stored one, keeping
///    first-occurrence position, `ExifTool.pm:9544-9560`; for an ordinary
///    `Priority => 1` tag this is the faithful last-wins-in-place).
pub(crate) fn run_emission<T: Taggable>(
  meta: &T,
  opts: EmitOptions,
  out: &mut crate::tagmap::TagMap,
) {
  for e in meta.tags(opts) {
    if e.unknown() {
      continue;
    }
    // MOVE the value out of the owned `Tag` (P3 — no `value_ref().clone()`); the
    // group + name are borrowed from the moved-out parts for the `write_value`
    // call. `write_value` is infallible (`Result<(), Infallible>`); the sink
    // keys on the family-1 group (`exiftool:2948` — only family-1 reaches the
    // `-G1` key) and owns the dedup.
    // Read the tag's `Priority => N` BEFORE moving the inner `Tag` out, then
    // hand it to the sink so the dedup applies the general ExifTool override
    // rule (`ExifTool.pm:9544-9560`).
    let priority = e.priority();
    let (group, name, value) = e.into_tag().into_parts();
    // The sink keys + serializes on the family-1 group; family-0 is carried as
    // METADATA (NOT part of the dedup key) so the Composite engine can resolve a
    // family-0-qualified ingredient (`Sony:GPSLatitude`). Behavior-preserving.
    let _ = out.write_value_doc(
      group.doc(),
      group.doc_subpath(),
      group.family1(),
      name.as_str(),
      priority,
      value,
      group.family0(),
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::{Group, TagValue};

  /// An [`EmittedTag`] composes the underlying [`Tag`] (group + name + value)
  /// with the `Unknown` flag, and exposes them via its accessors.
  #[test]
  fn emitted_tag_composes_value_tag_and_unknown() {
    let t = EmittedTag::new(
      Group::new("MakerNotes", "Apple"),
      "RunTime".into(),
      TagValue::I64(5),
      false,
    );
    assert_eq!(t.tag().group_ref().family1(), "Apple");
    assert_eq!(t.tag().name(), "RunTime");
    assert_eq!(t.tag().value_ref(), &TagValue::I64(5));
    assert!(!t.unknown());
  }

  /// The engine drops `Unknown=>1` tags, and the sink dedups a repeated
  /// `family1:name` key in place.
  ///
  /// NOTE on dedup direction: the plan snippet's prose called this "first-wins"
  /// and asserted `Some("Canon")`, but the REAL [`TagMap`](crate::tagmap::TagMap)
  /// sink is faithfully **last-wins-in-place** (`tagmap::TagMap::insert`,
  /// `ExifTool.pm:9437-9519` — a repeated `family1:name` is the same-identity
  /// `FoundTag` duplicate, whose LATEST value wins while keeping
  /// first-occurrence POSITION; pinned by the `AIFF_dup_name.aif` golden).
  /// The engine is a faithful pass-through to that golden-gated sink, so the
  /// duplicate `IFD0:Make` collapses to the LAST value (`"AGAIN"`). Asserting
  /// the real behavior here (not the plan's mis-stated direction) keeps the
  /// emission framework consistent with the existing conformance goldens.
  #[test]
  fn engine_suppresses_unknown_and_dedups() {
    struct Src;
    impl Taggable for Src {
      fn tags(&self, _opts: EmitOptions) -> impl Iterator<Item = EmittedTag> + '_ {
        [
          EmittedTag::new(
            Group::new("EXIF", "IFD0"),
            "Make".into(),
            TagValue::Str("Canon".into()),
            false,
          ),
          // `Unknown=>1` ⇒ the engine suppresses this one entirely.
          EmittedTag::new(
            Group::new("MakerNotes", "Apple"),
            "Hidden".into(),
            TagValue::I64(1),
            true,
          ),
          // Duplicate `IFD0:Make` ⇒ the sink replaces in place (last-wins).
          EmittedTag::new(
            Group::new("EXIF", "IFD0"),
            "Make".into(),
            TagValue::Str("AGAIN".into()),
            false,
          ),
        ]
        .into_iter()
      }
    }

    let mut tm = crate::tagmap::TagMap::new();
    run_emission(&Src, EmitOptions::g1(ConvMode::PrintConv, false), &mut tm);

    // The single surviving `IFD0:Make` carries the LAST value (faithful
    // last-wins-in-place; the first `"Canon"` was overwritten by `"AGAIN"`).
    assert_eq!(tm.get_str("IFD0", "Make").as_deref(), Some("AGAIN"));
    // The Unknown tag never reached the sink.
    assert!(tm.get("MakerNotes", "Hidden").is_none());
  }

  /// [`EmitOptions::g1`] carries the requested conv mode + `-ee` flag and the
  /// `-G1` (doc-collapsed) group rendering — the documented default the typed
  /// `serialize_tags` path builds; the public `-ee`/`-G3` toggle that feeds this
  /// is [`crate::ParseOptions`] (via `Rendered::new_with_options`).
  #[test]
  fn emit_options_g1_defaults() {
    let opts = EmitOptions::g1(ConvMode::ValueConv, false);
    assert_eq!(opts.mode, ConvMode::ValueConv);
    assert!(!opts.extract_embedded);
    assert!(matches!(
      opts.group_mode,
      crate::serialize_key::GroupMode::G1
    ));

    let ee = EmitOptions::g1(ConvMode::PrintConv, true);
    assert_eq!(ee.mode, ConvMode::PrintConv);
    assert!(ee.extract_embedded);
  }
}
