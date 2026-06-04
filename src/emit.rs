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
}

/// A rendered, ready-to-emit tag: the existing [`Tag`] (group + name + value,
/// already converted for the active [`ConvMode`]) plus the `Unknown=>1` flag
/// the engine uses to suppress it from default output (`ExifTool.pm:9179`).
///
/// Encapsulated per the crate accessor convention (no public fields): build
/// with [`EmittedTag::new`], read via [`tag`](Self::tag) /
/// [`unknown`](Self::unknown), or take ownership of the inner [`Tag`] with
/// [`into_tag`](Self::into_tag).
#[derive(Debug, Clone)]
pub struct EmittedTag {
  tag: Tag,
  unknown: bool,
}

impl EmittedTag {
  /// Compose an [`EmittedTag`] from its group, name, already-rendered value,
  /// and the `Unknown=>1` flag (`true` ⇒ suppressed from default output).
  #[must_use]
  #[inline(always)]
  pub fn new(group: Group, name: SmolStr, value: TagValue, unknown: bool) -> Self {
    Self {
      tag: Tag::new(group, name, value),
      unknown,
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
  /// Yield this `Meta`'s [`EmittedTag`]s for the given conversion `mode`, in
  /// emission order (the sink keeps first-occurrence position on dedup).
  fn tags(&self, mode: ConvMode) -> impl Iterator<Item = EmittedTag> + '_;
}

/// Drive any [`Taggable`] into the [`TagMap`](crate::tagmap::TagMap) sink,
/// applying the cross-cutting rules ONCE:
///
/// 1. **Unknown-suppression** — a tag flagged `Unknown=>1` is skipped, because
///    ExifTool's default output omits unknown tags (`ExifTool.pm:9179`). Moving
///    this here lets every format drop its per-emitter `if unknown { continue }`.
/// 2. **`write_value`** — the survivor's value is handed to the sink under its
///    `family1:name` key; [`TagMap`](crate::tagmap::TagMap) owns the dedup
///    (faithful `FoundTag` last-wins-in-place — a repeated key replaces the
///    earlier value while keeping its first-occurrence position,
///    `ExifTool.pm:9437-9519`).
pub(crate) fn run_emission<T: Taggable>(meta: &T, mode: ConvMode, out: &mut crate::tagmap::TagMap) {
  for e in meta.tags(mode) {
    if e.unknown() {
      continue;
    }
    // MOVE the value out of the owned `Tag` (P3 — no `value_ref().clone()`); the
    // group + name are borrowed from the moved-out parts for the `write_value`
    // call. `write_value` is infallible (`Result<(), Infallible>`); the sink
    // keys on the family-1 group (`exiftool:2948` — only family-1 reaches the
    // `-G1` key) and owns the dedup.
    let (group, name, value) = e.into_tag().into_parts();
    let _ = out.write_value_doc(group.doc(), group.family1(), name.as_str(), value);
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
      fn tags(&self, _m: ConvMode) -> impl Iterator<Item = EmittedTag> + '_ {
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
    run_emission(&Src, ConvMode::PrintConv, &mut tm);

    // The single surviving `IFD0:Make` carries the LAST value (faithful
    // last-wins-in-place; the first `"Canon"` was overwritten by `"AGAIN"`).
    assert_eq!(tm.get_str("IFD0", "Make").as_deref(), Some("AGAIN"));
    // The Unknown tag never reached the sink.
    assert!(tm.get("MakerNotes", "Hidden").is_none());
  }
}
