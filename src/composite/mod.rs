//! The generic ExifTool Composite-tag engine (a faithful transliteration of
//! `Image::ExifTool::BuildCompositeTags`, ExifTool.pm:3976-4162).
//!
//! ExifTool builds Composite tags AFTER all format extraction completes
//! (`ExifTool.pm:4577`, inside `ExtractInfo` once `$$opts{Composite}` is on —
//! default ON, `ExifTool.pm:1125`). exifast mirrors that ordering: the format
//! tag stream is driven into the [`TagMap`](crate::tagmap::TagMap) by
//! [`run_emission`](crate::emit::run_emission), and then — as a STANDALONE
//! post-pass — [`build_composites`] reads the FINAL emitted tag set, resolves
//! each registered [`CompositeDef`]'s `Require`/`Desire`/`Inhibit` inputs
//! against it, runs the derivation, and APPENDS the surviving composites. Being
//! appended after every format tag preserves their positional last-ness (the
//! `Composite:Duration` goldens have it as the final key).
//!
//! ## The fixpoint
//!
//! ExifTool loops until no def is deferred. A def that references another
//! `Composite:Name` not yet built is pushed onto `@deferredTags` and retried in
//! the next pass; if a whole pass defers everything, ExifTool tries ONE more
//! pass ignoring `Inhibit`-on-Composite (the `$allBuilt` flag) and then warns
//! `Circular dependency in Composite tags`. The defs are walked in
//! prefixed-id sort order (`Module-Name`) so the build is deterministic
//! regardless of registry order. `GPSPosition` (`Composite-GPSPosition`)
//! `Require`s `Composite:GPSLatitude`/`Composite:GPSLongitude` (`GPS-…`), so it
//! defers to a later pass — exercising the fixpoint on a real def.
//!
//! ## Input model — presence vs value
//!
//! ExifTool resolves each `Require`/`Desire`/`Inhibit` input by PRESENCE
//! (`defined $val[i]`, ExifTool.pm:4044-4087): a present `Inhibit` of ANY value
//! suppresses; a missing `Require` aborts; a missing `Desire` is an `undef`
//! element. Only AFTER an input survives does the def's `RawConv`/`ValueConv`
//! coerce the actual value. exifast mirrors that split: [`CompositeSink::
//! resolve`] returns a [`CompositeValue`](table::CompositeValue) — `Present`
//! carrying the ingredient's RAW (post-`ValueConv`) [`TagValue`], or `Missing`
//! — and the build loop keys Inhibit/Require/Desire on `is_present()`, NOT on
//! numeric coercibility. So a present-but-non-numeric ingredient (a STRING —
//! GPS refs `N`/`S`/`E`/`W`, `DateStamp`, `TimeStamp`) is correctly seen as
//! PRESENT, and a string `Inhibitor` correctly suppresses. Each
//! [`CompositeDef::derive`](table::CompositeDef) then does its OWN coercion: the
//! Duration defs coerce numeric and apply the Perl-truthy `&&` guard; the GPS
//! defs read the string/decimal ingredients directly.
//!
//! ## Two resolution views — `$val[i]` (ValueConv) and `$prt[i]` (PrintConv)
//!
//! ExifTool's `BuildCompositeTags` builds BOTH a `@val` array (each input's
//! ValueConv value, `GetValue($tag, 'ValueConv')`, ExifTool.pm:4112) AND a
//! `@prt` array (each input's PrintConv value, ExifTool.pm:4116). A Composite's
//! `RawConv`/`ValueConv` reads `$val[i]`; its `PrintConv` may read `$prt[i]`
//! (`GPSPosition`'s PrintConv is the literal `"$prt[0], $prt[1]"`;
//! `GPSAltitude`'s reads `$prt[1]`). exifast carries BOTH per input, in both
//! modes, by resolving from TWO views:
//!
//! * the **ValueConv view** — the emitted tag set in `-n` mode (raw ValueConv
//!   values) — supplies `$val[i]`;
//! * the **PrintConv view** — the emitted tag set in `-j` mode (PrintConv
//!   strings) — supplies `$prt[i]`.
//!
//! Under `-n` the active `out` sink already holds the ValueConv values, so it
//! IS the ValueConv view, and the caller re-emits a throwaway PrintConv view for
//! `$prt[i]`. Under `-j` the active `out` sink holds the PrintConv strings, so
//! it IS the PrintConv view, and the caller re-emits a throwaway ValueConv view
//! for `$val[i]`. Either way the engine populates BOTH views with each built
//! composite (its ValueConv form into the ValueConv view, its PrintConv form
//! into the PrintConv view) so a composite-on-composite (`GPSPosition`) reads a
//! faithful `$val[i]` AND `$prt[i]` of its ingredient composites — and because
//! `out` is one of the two views, the composite's output value for the active
//! mode lands in `out` automatically.

pub mod convs;
mod table;

#[cfg(feature = "alloc")]
use crate::value::TagValue;
#[cfg(feature = "alloc")]
pub(crate) use table::CompositeContext;
#[cfg(feature = "alloc")]
use table::{CompositeDef, CompositeValue, REGISTRY};

/// The family-3 sub-document axis a [`CompositeSink::resolve`] resolves on
/// (ExifTool.pm:4001-4147 `$docNum` / `$cacheTag[$doc]`).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocScope {
  /// Non-SubDoc resolution: Main (family-3 `0`) with the established within-doc
  /// precedence, then a cross-document fallback when Main has no match.
  Main,
  /// SubDoc per-document resolution: match family-3 `== d` EXACTLY.
  Exact(u32),
}

/// A dedup sink the Composite engine reads inputs from and appends results to.
/// Implemented by [`TagMap`](crate::tagmap::TagMap) (the JSON / golden path) and
/// by the [`Tag`](crate::value::Tag) `Vec` ([`iter_tags`](crate::format_parser
/// ::AnyMeta::iter_tags) path) so ONE fixpoint engine serves both.
#[cfg(feature = "alloc")]
trait CompositeSink {
  /// The matching value whose family-1 group is in `groups` (or ANY group when
  /// `groups` is empty) and whose name is `name`, as a [`CompositeValue`]
  /// carrying the RAW stored [`TagValue`] ([`Present`](CompositeValue::Present)).
  /// Invoked on whichever view supplies the requested form (the ValueConv view
  /// for `$val[i]`, the PrintConv view for `$prt[i]`). A `Missing` result means
  /// no such tag was extracted (`!defined`); a present value of ANY shape is
  /// [`Present`](CompositeValue::Present), so `Inhibit`/`Require`/`Desire`
  /// resolve on presence and each def performs its own coercion.
  ///
  /// `doc` selects the family-3 sub-document axis (ExifTool.pm:4001-4147):
  ///
  /// * [`DocScope::Main`] — the NON-SubDoc resolution: resolve at the Main
  ///   document (family-3 `0`) with the established within-doc precedence
  ///   (bare-name ⇒ FIRST match, group-scoped ⇒ LAST match), and ONLY when the
  ///   Main document has no match, FALL BACK to the first cross-document match
  ///   (emission order). This keeps every single-document (stills / audio)
  ///   resolution byte-identical (only `doc 0` exists there) while reproducing
  ///   ExifTool's cross-document base-key resolution for a video whose
  ///   ingredient lives only on a `Doc<N>` (e.g. `Composite:Aperture` built from
  ///   a Sony `Doc1` `FNumber`, or Main `Composite:GPSPosition` reading the Main
  ///   `Composite:GPSLatitude` ahead of any `Doc<N>` one).
  /// * [`DocScope::Exact`]`(d)` — the SubDoc per-document resolution: match
  ///   family-3 `== d` EXACTLY (the `$cacheTag[$doc]` lookup), used by a SubDoc
  ///   def's per-`Doc<N>` build pass.
  ///
  /// `group0` qualifies the match by family-0 (ExifTool's `GroupMatches` over
  /// family-0): `Some("Sony")` matches ONLY an entry whose family-0 is `Sony`
  /// (Sony.pm:10929 `Require => 'Sony:GPSLatitude'`), so the Sony SubDoc GPS
  /// defs build for a Sony rtmd (family-0 `Sony`) but NOT for a GoPro
  /// (family-0 `GoPro`). `None` is the ordinary family-1-only match every
  /// pre-existing def uses.
  fn resolve(
    &self,
    groups: &[&str],
    group0: Option<&str>,
    name: &str,
    doc: DocScope,
  ) -> CompositeValue;
  /// Is a `Composite:<name>` already present in family-3 document `doc`? (The
  /// Composite-dependency deferral checks the document the dependent is being
  /// built in — a SubDoc def at `Doc<N>` defers on the `Doc<N>` ingredient
  /// composite, not the Main one.)
  fn has_composite(&self, name: &str, doc: u32) -> bool;
  /// Append a built `Composite:<name>` at family-3 document `doc` (`0` = Main),
  /// with ExifTool `Priority`.
  fn append(&mut self, name: &'static str, priority: u8, value: TagValue, doc: u32);
}

#[cfg(feature = "alloc")]
impl CompositeSink for crate::tagmap::TagMap {
  fn resolve(
    &self,
    groups: &[&str],
    group0: Option<&str>,
    name: &str,
    doc: DocScope,
  ) -> CompositeValue {
    // A TagMap entry is `(doc, doc_subpath, family1, name, priority, value, family0)`.
    // An input matches when its family-1 group set contains the entry's family-1
    // (or the set is empty ⇒ any), AND — for a family-0-qualified input
    // (`Sony:GPSLatitude`, Sony.pm:10929) — the entry's family-0 (index 6)
    // equals `group0`. `group0 == None` is the ordinary family-1-only match
    // (every pre-existing input), so this is behavior-preserving.
    let group_ok = |entry: &(
      u32,
      smol_str::SmolStr,
      smol_str::SmolStr,
      smol_str::SmolStr,
      u8,
      TagValue,
      smol_str::SmolStr,
      u32,
    )| {
      (groups.is_empty() || groups.contains(&entry.2.as_str()))
        && group0.is_none_or(|g0| entry.6.as_str() == g0)
    };
    // Match a candidate entry IN a specific family-3 document `d`.
    let pred_in = |d: u32| {
      move |entry: &&(
        u32,
        smol_str::SmolStr,
        smol_str::SmolStr,
        smol_str::SmolStr,
        u8,
        TagValue,
        smol_str::SmolStr,
        u32,
      )| { entry.0 == d && entry.3.as_str() == name && group_ok(entry) }
    };
    // Within a single document, a GROUP-SCOPED input (`groups` non-empty) takes
    // the LAST match within that group set — the duplicate-override precedence
    // (`APE_dup_override`: a later `APE:SampleRate=48000` overrides an earlier
    // `MAC:SampleRate=44100`). A BARE-NAME input (empty `groups`) resolves the
    // un-suffixed key the way ExifTool's `FoundTag` settles it (ExifTool.pm:9544-
    // 9560): the HIGHEST effective priority wins. So `Composite:FocalLength35efl`'s
    // bare `FocalLength` resolves to `ExifIFD:FocalLength` (`Priority => 1`, 50.0)
    // over a MakerNote `Nikon:FocalLength` (its table `PRIORITY => 0`, 50.4); the
    // A200's bare `ImageWidth` resolves to `MinoltaRaw:ImageWidth` (`Priority => 1`,
    // 3872) over the earlier-emitted `SubIFD:ImageWidth` (the `%Exif::Main`
    // `Priority => 0` tag, 3880); a Pentax `File:ImageWidth` (`Priority => 1`)
    // beats an `XMP-tiff:ImageWidth` (`%XMP::tiff PRIORITY => 0`). Among EQUAL max
    // priority the tiebreak is the MIN walk-`seq` (entry.7) — the earliest-inserted
    // = first-emitted entry (#474 PR 1). Because `seq` == first-occurrence order
    // (never re-stamped, see `TagMap::insert`), this is BYTE-IDENTICAL to the prior
    // first-among-equals tiebreak; reading `seq` makes the walk-order axis explicit.
    // #474 PR 2 flips MIN→MAX `seq` for ExifTool's true `$priority >= $oldPriority`
    // last-walked `FoundTag` tiebreak (ExifTool.pm:9564), together with a PngMeta
    // chunk-walk-order emission override — a flip today (without that override, and
    // given exifast's emission order is NOT file order) would regress the 6 Pentax
    // composites, so it is intentionally split into PR 2.
    let find_in = |d: u32| {
      if groups.is_empty() {
        // MAX effective priority; among EQUAL priority, MIN walk-`seq` (entry.7,
        // the earliest-inserted = first-emitted). PR 2 flips `<` to `>` for the
        // last-walked tiebreak.
        self
          .entries()
          .iter()
          .filter(pred_in(d))
          .map(|e| (e, crate::tagmap::effective_priority(e.3.as_str(), e.4), e.7))
          .reduce(|best, cur| {
            if cur.1 > best.1 || (cur.1 == best.1 && cur.2 < best.2) {
              cur
            } else {
              best
            }
          })
          .map(|(e, _, _)| e)
      } else {
        self.entries().iter().rev().find(pred_in(d))
      }
    };
    let found = match doc {
      // SubDoc per-document: ONLY family-3 == d.
      DocScope::Exact(d) => find_in(d),
      // Non-SubDoc: Main (doc 0) first; only if Main has NOTHING, fall back to
      // the first cross-document match (emission order) — ExifTool's base-key
      // resolution for an ingredient that lives only on a `Doc<N>`.
      DocScope::Main => find_in(0).or_else(|| {
        let cross = |entry: &&(
          u32,
          smol_str::SmolStr,
          smol_str::SmolStr,
          smol_str::SmolStr,
          u8,
          TagValue,
          smol_str::SmolStr,
          u32,
        )| { entry.0 != 0 && entry.3.as_str() == name && group_ok(entry) };
        // First cross-doc match by emission order (the lowest `Doc<N>` first,
        // i.e. ExifTool's earliest-extracted base key).
        self.entries().iter().find(cross)
      }),
    };
    match found {
      Some(entry) => CompositeValue::Present(entry.5.clone()),
      None => CompositeValue::Missing,
    }
  }
  fn has_composite(&self, name: &str, doc: u32) -> bool {
    self
      .entries()
      .iter()
      .any(|(d, _sub, fam1, n, _pri, _val, _f0, _seq)| {
        *d == doc && fam1.as_str() == "Composite" && n.as_str() == name
      })
  }
  fn append(&mut self, name: &'static str, priority: u8, value: TagValue, doc: u32) {
    // A composite carries family-0 == family-1 == "Composite" (matching the
    // `iter_tags` path's `Group::with_doc("Composite", "Composite", doc)`), so a
    // composite-on-composite input (`Composite:GPSLatitude`) resolves it.
    let _ = self.write_value_doc(doc, "", "Composite", name, priority, value, "Composite");
  }
}

/// The [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) sink — the
/// deduped [`Tag`](crate::value::Tag) `Vec`, each tag PAIRED with its surviving
/// entry's EFFECTIVE priority so the bare-name resolver can prefer the
/// highest-priority ingredient (exactly as the `TagMap` sink reads entry.4). The
/// priority is stripped at the [`iter_tags`](crate::format_parser::AnyMeta::iter_tags)
/// boundary, so the public tag iterator is unchanged. Appended composites carry
/// the full `Composite`/`Composite` group (family-0 = family-1) and ExifTool's
/// `Priority`, matching the JSON path.
#[cfg(feature = "alloc")]
impl CompositeSink for std::vec::Vec<(crate::value::Tag, u8)> {
  fn resolve(
    &self,
    groups: &[&str],
    group0: Option<&str>,
    name: &str,
    doc: DocScope,
  ) -> CompositeValue {
    // The full `Group` carries family-0 here, so the family-0-qualified match
    // (`Sony:GPSLatitude`) reads `t.group_ref().family0()` directly — the JSON
    // path mirrors this via the TagMap entry's carried family-0.
    let group_ok = |t: &crate::value::Tag| {
      (groups.is_empty() || groups.contains(&t.group_ref().family1()))
        && group0.is_none_or(|g0| t.group_ref().family0() == g0)
    };
    let pred_in = |d: u32| {
      move |item: &&(crate::value::Tag, u8)| {
        item.0.group_ref().doc() == d && item.0.name() == name && group_ok(&item.0)
      }
    };
    // Bare-name (empty `groups`) ⇒ the HIGHEST effective priority wins; among
    // EQUAL priority, the MIN positional index — this `Vec`'s position IS its
    // walk-`seq` (it is built in emission order and a winning duplicate replaces
    // IN PLACE, keeping position), so min-index = first-emitted, byte-identical to
    // the prior first-among-equals AND consistent with the `TagMap` sink's MIN
    // `seq`. Group-scoped ⇒ LAST match (the duplicate-override). #474 PR 2 flips
    // this to MAX for the last-walked tiebreak (see the `TagMap` impl's note).
    let find_in = |d: u32| {
      if groups.is_empty() {
        self
          .iter()
          .enumerate()
          .filter(|(_i, item)| pred_in(d)(item))
          .map(|(i, item)| {
            (
              item,
              crate::tagmap::effective_priority(item.0.name(), item.1),
              i,
            )
          })
          .reduce(|best, cur| {
            if cur.1 > best.1 || (cur.1 == best.1 && cur.2 < best.2) {
              cur
            } else {
              best
            }
          })
          .map(|(item, _, _)| item)
      } else {
        self.iter().rev().find(pred_in(d))
      }
    };
    let found = match doc {
      DocScope::Exact(d) => find_in(d),
      DocScope::Main => find_in(0).or_else(|| {
        let cross = |item: &&(crate::value::Tag, u8)| {
          item.0.group_ref().doc() != 0 && item.0.name() == name && group_ok(&item.0)
        };
        self.iter().find(cross)
      }),
    };
    match found {
      Some(item) => CompositeValue::Present(t_value(&item.0).clone()),
      None => CompositeValue::Missing,
    }
  }
  fn has_composite(&self, name: &str, doc: u32) -> bool {
    self.iter().any(|(t, _p)| {
      t.group_ref().doc() == doc && t.group_ref().family1() == "Composite" && t.name() == name
    })
  }
  fn append(&mut self, name: &'static str, priority: u8, value: TagValue, doc: u32) {
    self.push((
      crate::value::Tag::new(
        crate::value::Group::with_doc("Composite", "Composite", doc),
        name,
        value,
      ),
      priority,
    ));
  }
}

/// Borrow a [`Tag`](crate::value::Tag)'s value (the `Vec` sink's accessor).
#[cfg(feature = "alloc")]
fn t_value(t: &crate::value::Tag) -> &TagValue {
  t.value_ref()
}

/// A [`TagValue`] in Perl string context — what `$val[i]` / `$prt[i]` becomes
/// when a Composite's ValueConv/PrintConv interpolates it. A `Str` is borrowed;
/// the numeric scalars stringify with Perl's default NV / integer rule (so a
/// GPS decimal `$val` interpolates as `48.85815`, matching ExifTool's
/// `"$val[0] $val[1]"`); other shapes render via their textual form.
#[cfg(feature = "alloc")]
pub(crate) fn value_text(v: &TagValue) -> std::borrow::Cow<'_, str> {
  use std::borrow::Cow;
  match v {
    TagValue::Str(s) => Cow::Borrowed(s.as_str()),
    TagValue::I64(n) => Cow::Owned(n.to_string()),
    TagValue::U64(n) => Cow::Owned(n.to_string()),
    // Perl's default NV stringification (`%.15g`) — the form a decimal GPS
    // coordinate interpolates as inside `"$val[0] $val[1]"`.
    TagValue::F64(x) => Cow::Owned(crate::value::format_g(*x, 15)),
    TagValue::Bool(b) => Cow::Borrowed(if *b { "1" } else { "" }),
    other => Cow::Owned(std::format!("{other:?}")),
  }
}

/// `CalcRotation($self)` (QuickTime.pm:8797) over a ValueConv-view tag set —
/// the pre-computed [`CompositeContext::rotation`]. Finds the FIRST `HandlerType`
/// tag whose RAW (ValueConv) value is `"vide"`, takes ITS family-1 group (the
/// video `Track<N>`), then finds the `MatrixStructure` in that SAME family-1
/// group and returns its [`get_rotation_angle`](convs::video::get_rotation_angle).
/// `None` when there is no video track or no matrix for it.
///
/// `entries` is the ValueConv view as `(family1, name, value)` triples in
/// emission order (so the FIRST `vide` HandlerType is ExifTool's lowest-instance
/// `HandlerType` key). The caller passes the `-n` (ValueConv) view because
/// ExifTool's `$$value{$tag} eq 'vide'` tests the raw 4cc, not the PrintConv
/// string.
#[cfg(feature = "alloc")]
pub(crate) fn calc_rotation_from<'a>(
  entries: impl Iterator<Item = (&'a str, &'a str, &'a TagValue)> + Clone,
) -> Option<f64> {
  // First HandlerType whose ValueConv value is the raw 4cc `"vide"`; its
  // family-1 group is the video track group.
  let video_group = entries.clone().find_map(|(group, name, value)| {
    if name == "HandlerType" && matches!(value, TagValue::Str(s) if s.as_str() == "vide") {
      Some(group)
    } else {
      None
    }
  })?;
  // The MatrixStructure in that SAME family-1 group.
  let matrix = entries.clone().find_map(|(group, name, value)| {
    if name == "MatrixStructure" && group == video_group {
      match value {
        TagValue::Str(s) => Some(s.as_str()),
        _ => None,
      }
    } else {
      None
    }
  })?;
  convs::video::get_rotation_angle(matrix)
}

/// Build a [`CompositeContext`] for the post-pass: the QuickTime summed
/// `MediaDataSize` total (`AvgBitrate`) plus the pre-computed `CalcRotation`
/// angle scanned from `value_view` (the ValueConv view, which holds the raw
/// `vide` HandlerType + the MatrixStructure string).
#[cfg(feature = "alloc")]
pub(crate) fn make_context(
  media_data_total: Option<u64>,
  value_view: &crate::tagmap::TagMap,
) -> CompositeContext {
  let rotation = calc_rotation_from(
    value_view
      .entries()
      .iter()
      .map(|(_d, _s, g, n, _p, v, _f0, _seq)| (g.as_str(), n.as_str(), v)),
  );
  CompositeContext::new(media_data_total, rotation)
}

/// Build every registered Composite tag into `out` (the post-`run_emission`
/// pass). `mode` is the active OUTPUT conversion mode (`-j` ⇒ PrintConv, `-n`
/// ⇒ ValueConv); `other_view` is the SAME Meta re-emitted in the OPPOSITE mode,
/// supplied so the engine has BOTH a ValueConv view (`$val[i]`) and a PrintConv
/// view (`$prt[i]`) regardless of `mode` — under `-n`, `out` is the ValueConv
/// view and `other_view` is the PrintConv re-emission; under `-j`, `out` is the
/// PrintConv view and `other_view` is the ValueConv re-emission. `None` is
/// permitted ONLY when the defs read neither the opposite-mode view NOR a
/// composite dependency (the legacy single-sink Duration path); the registered
/// GPS defs always require `other_view`. `doc_count` is the highest family-3
/// sub-document index present — the SubDoc defs (`GPSLatitude`/`GPSLongitude`/
/// `GPSAltitude`/`GPSDateTime`) build once at Main AND once per `Doc<N>` up to
/// it (ExifTool.pm:4001). `ctx` threads the format-state `$$self{…}` reads
/// (`AvgBitrate`'s TimeScale + MediaDataSize sum, `Rotation`'s pre-computed
/// angle).
#[cfg(feature = "alloc")]
pub(crate) fn build_composites(
  out: &mut crate::tagmap::TagMap,
  other_view: Option<&mut crate::tagmap::TagMap>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
  ctx: &table::CompositeContext,
) {
  build_into(REGISTRY, out, other_view, mode, doc_count, ctx);
}

/// Build every registered Composite tag into the
/// [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) `Tag` `Vec` (the
/// public generic-extraction path), so it yields the same `Composite:*` set the
/// JSON path does. `other_view` is the SAME tag stream re-collected in the
/// OPPOSITE mode (the `$prt[i]`/`$val[i]` source; see [`build_composites`]).
/// `doc_count` / `ctx` drive the SubDoc per-`Doc<N>` builds + the format-state
/// derivations exactly as for the JSON path.
#[cfg(feature = "alloc")]
pub(crate) fn build_composites_into_tags(
  tags: &mut std::vec::Vec<(crate::value::Tag, u8)>,
  other_view: Option<&mut std::vec::Vec<(crate::value::Tag, u8)>>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
  ctx: &table::CompositeContext,
) {
  build_into(REGISTRY, tags, other_view, mode, doc_count, ctx);
}

/// Drive the ExifTool `BuildCompositeTags` fixpoint over `defs`.
///
/// `out` is the view for the active output `mode`; `other_view` is the opposite-
/// mode re-emission. The engine binds them to a `(val_view, prt_view)` pair (in
/// `-n`, `out` is the ValueConv view and `other_view` the PrintConv view; in
/// `-j`, vice versa), resolves each input's `$val[i]` from `val_view` and
/// `$prt[i]` from `prt_view`, runs the def's derivation over `$val[]`, and
/// appends each built composite's ValueConv form to `val_view` and PrintConv
/// form to `prt_view` — so a composite-on-composite (`GPSPosition`) reads a
/// faithful `$val[i]`/`$prt[i]` of its ingredients, and the composite's output
/// for `mode` lands in `out` (which is one of the two views).
///
/// When `other_view` is `None` (the legacy single-sink Duration path, used by
/// the oracle tests and the `-n` build when no def reads `$prt`), `out` is BOTH
/// views: the engine resolves and appends through it alone, rendering the
/// composite once for `mode`. Byte-identical to the pre-`$prt` engine for any
/// def whose PrintConv ignores `$prt`.
#[cfg(feature = "alloc")]
fn build_into<S: CompositeSink>(
  defs: &[CompositeDef],
  out: &mut S,
  other_view: Option<&mut S>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
  ctx: &table::CompositeContext,
) {
  use crate::emit::ConvMode;
  match other_view {
    Some(other) => {
      // Bind (val_view, prt_view) by mode. `out` is whichever view holds the
      // active mode's form; `other` is the opposite-mode re-emission.
      let (val_view, prt_view): (&mut S, &mut S) = match mode {
        ConvMode::ValueConv => (out, other), // out = ValueConv view
        ConvMode::PrintConv => (other, out), // out = PrintConv view
      };
      run_fixpoint(defs, val_view, Some(prt_view), mode, doc_count, ctx);
    }
    // No `$prt` source: `out` is its own sole view (the ValueConv values in `-n`,
    // the synthetic oracle maps). A `$prt`-reading PrintConv sees `None` prt
    // elements; the Duration defs (the only `None`-path callers) ignore `$prt`.
    None => run_fixpoint(defs, out, None, mode, doc_count, ctx),
  }
}

/// The ExifTool `BuildCompositeTags` fixpoint over `defs`, resolving `$val[i]`
/// from `val_view` and `$prt[i]` from `prt_view` (the SAME sink as `val_view`
/// when `prt_view` is `None`). The Composite-dependency deferral (`not_built` /
/// `has_composite`) keys on `val_view` (a dependency's `$val[i]` is what gates
/// the build). For each built composite, both forms are appended: the ValueConv
/// form to `val_view`, the PrintConv form to `prt_view` (or, when they coincide,
/// the active-mode form once).
///
/// The OUTER loop is the def-fixpoint (deferral by composite NAME, Main-driven —
/// ExifTool clears `%notBuilt` only at `docNum == 0`). For each def the Main
/// (`docNum 0`) build runs with the deferral; a SubDoc def THEN also builds per
/// `Doc<N>` (1..=`doc_count`), resolving its inputs WITHIN that document
/// (`DocScope::Exact`). The ported SubDoc defs (GPS lat/lon/alt/datetime) depend
/// only on GPS-group ingredient tags, not on other composites, so their per-doc
/// builds carry no composite-on-composite deferral.
#[cfg(feature = "alloc")]
fn run_fixpoint<S: CompositeSink>(
  defs: &[CompositeDef],
  val_view: &mut S,
  mut prt_view: Option<&mut S>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
  ctx: &table::CompositeContext,
) {
  // Working order: a faithful prefixed-id sort (`Module-Name`). Stable sort so
  // equal keys keep registry order (ExifTool's keys are unique, so ties don't
  // occur in practice).
  let mut order: std::vec::Vec<&CompositeDef> = defs.iter().collect();
  order.sort_by(|a, b| a.sort_key.cmp(b.sort_key));

  // `not_built`: composite NAMES not yet built (drives the Composite-dependency
  // deferral). A name leaves the set when it is built OR proven unbuildable.
  let mut not_built: std::collections::HashSet<&'static str> =
    order.iter().map(|d| d.name).collect();

  // The defs still to attempt this pass (starts as the whole sorted list).
  let mut pending: std::vec::Vec<&CompositeDef> = order;
  let mut all_built = false; // ExifTool's `$allBuilt` (the last-ditch Inhibit-ignore pass)

  loop {
    let mut deferred: std::vec::Vec<&CompositeDef> = std::vec::Vec::new();
    let pending_len = pending.len();

    'def: for def in pending.iter().copied() {
      // The Main (docNum 0) build, with the composite-dependency deferral. A
      // `Composite:`-group input referencing an unbuilt composite defers the
      // WHOLE def (ExifTool `next COMPOSITE_TAG`); an Inhibit defers only until
      // the final `$allBuilt` pass.
      for input in def.inputs {
        if references_unbuilt_composite(input, &not_built, val_view, 0) {
          let defer = !(input.kind.is_inhibit() && all_built);
          if defer {
            deferred.push(def);
            continue 'def;
          }
        }
      }

      // Resolve + build at Main (docNum 0). The scope differs by def kind: a
      // NON-SubDoc def uses `DocScope::Main` (the standard ExifTool `GroupMatches`
      // over ALL keys — Main first, then a cross-document fallback for an
      // ingredient that lives only on a `Doc<N>`, e.g. `GPSPosition`/`Aperture`
      // from a `Doc1` tag). A SubDoc def's docNum-0 pass resolves ONLY the doc-0
      // (Main) ingredient (ExifTool's `$cacheTag[0]`, the G3-0 keys) — NO
      // cross-doc fallback, so a file with ONLY `Doc<N>` GPS builds NO Main
      // `Composite:GPSLatitude` (the per-Doc<N> pass below builds those). The def
      // is now settled (built or proven unbuildable), so it leaves `not_built`.
      not_built.remove(def.name);
      let main_scope = if def.sub_doc.is_sub_doc() {
        DocScope::Exact(0)
      } else {
        DocScope::Main
      };
      build_at_doc(
        def,
        val_view,
        prt_view.as_deref_mut(),
        mode,
        ctx,
        0,
        main_scope,
      );

      // SubDoc per-document builds (ExifTool.pm:4001-4147). For a SubDoc def,
      // ALSO attempt each `Doc<N>` (1..=doc_count), gated by the SubDoc probe,
      // resolving inputs WITHIN that document. These do NOT touch `not_built`
      // (only Main does) and the ported SubDoc defs have no composite ingredient.
      if def.sub_doc.is_sub_doc() {
        for d in 1..=doc_count {
          if sub_doc_has_chance(def, val_view, d) {
            build_at_doc(
              def,
              val_view,
              prt_view.as_deref_mut(),
              mode,
              ctx,
              d,
              DocScope::Exact(d),
            );
          }
        }
      }
    }

    if deferred.is_empty() {
      break; // fixpoint reached
    }
    if deferred.len() == pending_len {
      // Nothing built this pass.
      if all_built {
        // ExifTool warns `Circular dependency in Composite tags` and stops.
        // exifast has no doc-level warning channel for this synthetic case
        // (the registered defs never cycle); drop the unbuildable deferred defs
        // and stop.
        break;
      }
      all_built = true; // one more pass, ignoring Inhibit-on-Composite
    }
    pending = deferred;
  }
}

/// Resolve `def`'s inputs at family-3 `scope` and, if they survive
/// `Require`/`Inhibit`, run the derivation + append the built composite at
/// family-3 document `doc`. Shared by the Main (`doc 0`, `DocScope::Main`) and
/// the SubDoc per-document (`DocScope::Exact(d)`) builds. The deferral check is
/// the caller's responsibility (Main only); this resolves the NON-composite-
/// dependency inputs and builds.
#[cfg(feature = "alloc")]
fn build_at_doc<S: CompositeSink>(
  def: &CompositeDef,
  val_view: &mut S,
  prt_view: Option<&mut S>,
  mode: crate::emit::ConvMode,
  ctx: &table::CompositeContext,
  doc: u32,
  scope: DocScope,
) {
  use crate::emit::ConvMode;
  // Resolve each input index to its `$val[i]` ([`CompositeValue`], presence +
  // raw value) AND its `$prt[i]` (the PrintConv-view value, `None` for an
  // absent/`Missing` input). `Require`/`Desire`/`Inhibit` key on `$val[i]`
  // presence; the def's `derive` reads `$val[]`; the PrintConv reads both.
  let mut vals: std::vec::Vec<CompositeValue> = std::vec::Vec::with_capacity(def.inputs.len());
  let mut prts: std::vec::Vec<Option<TagValue>> = std::vec::Vec::with_capacity(def.inputs.len());
  let mut suppress = false; // an Inhibit input was present
  let mut require_missing = false;

  for input in def.inputs {
    let resolved = val_view.resolve(input.groups, input.group0, input.name, scope);
    if resolved.is_present() {
      if input.kind.is_inhibit() {
        // ExifTool.pm:4078-4081 `$found = 0; last` — a PRESENT inhibitor of ANY
        // value (numeric or string) suppresses the composite.
        suppress = true;
        break;
      }
      // The matching `$prt[i]` from the PrintConv view (the SAME sink as
      // `val_view` when `prt_view` is `None`).
      let prt = match prt_view.as_deref() {
        Some(pv) => pv.resolve(input.groups, input.group0, input.name, scope),
        None => val_view.resolve(input.groups, input.group0, input.name, scope),
      };
      prts.push(prt.value().cloned());
      vals.push(resolved);
    } else {
      if input.kind.is_require() {
        // ExifTool.pm:4084-4087 `$found = 0; last` — required & missing.
        require_missing = true;
        break;
      }
      // Desire / Inhibit absent ⇒ undef element, keep going.
      prts.push(None);
      vals.push(CompositeValue::Missing);
    }
  }

  if suppress || require_missing {
    return; // can't / shouldn't build
  }

  // All inputs resolved: run the derivation (`$val` from `$val[]`, `$prt[]` for
  // the few defs whose ValueConv reads a PrintConv input — `LightValue`'s
  // `CalculateLV(...,$prt[2])`; the format-state `ctx` for `AvgBitrate` /
  // `Rotation`).
  if let Some(raw) = (def.derive)(&vals, &prts, ctx) {
    // Append the ValueConv form to `val_view` and the PrintConv form to
    // `prt_view`, so a dependent composite reads both. When the two views
    // coincide (`None` prt_view), append the active-mode form once.
    match prt_view {
      Some(prt) => {
        val_view.append(
          def.name,
          def.priority,
          def
            .print_conv
            .render(&raw, &vals, &prts, ConvMode::ValueConv),
          doc,
        );
        prt.append(
          def.name,
          def.priority,
          def
            .print_conv
            .render(&raw, &vals, &prts, ConvMode::PrintConv),
          doc,
        );
      }
      None => {
        val_view.append(
          def.name,
          def.priority,
          def.print_conv.render(&raw, &vals, &prts, mode),
          doc,
        );
      }
    }
  }
  // `None` ⇒ the `… ? … : undef` guard fired; nothing emitted.
}

/// The SubDoc per-document attempt gate (ExifTool.pm:4137-4147). ExifTool only
/// attempts a `Doc<N>` build when the def has a chance to build there — for a
/// `Require`-bearing def, EVERY `Require`d (base-name) tag must exist somewhere;
/// for a `Desire`-only def (`GPSAltitude`, `SubDoc => [1,3]`), at least one of
/// the probed `Desire` tags must exist. exifast applies the per-document form:
/// the def's inputs must have a chance WITHIN document `d` (so a `Doc<N>` with no
/// relevant tag is skipped, matching ExifTool's per-doc `GroupMatches`).
#[cfg(feature = "alloc")]
fn sub_doc_has_chance<S: CompositeSink>(def: &CompositeDef, val_view: &S, d: u32) -> bool {
  use table::{InputKind, SubDoc};
  match def.sub_doc {
    SubDoc::No => false,
    // `SubDoc => 1` with `Require`d tags (GPSLatitude/Longitude/DateTime): every
    // `Require`d input must resolve within doc `d` (ExifTool.pm:4138-4142 checks
    // each `Require`d tag is defined for the sub-document).
    SubDoc::All => def.inputs.iter().all(|input| {
      input.kind != InputKind::Require
        || val_view
          .resolve(input.groups, input.group0, input.name, DocScope::Exact(d))
          .is_present()
    }),
    // `SubDoc => [1,3]` (GPSAltitude, Desire-only): at least one of the probed
    // (1-based) `Desire` indices must exist in doc `d` (ExifTool.pm:4144-4147).
    SubDoc::Indices(idxs) => idxs.iter().any(|&i| {
      def.inputs.get(i).is_some_and(|input| {
        val_view
          .resolve(input.groups, input.group0, input.name, DocScope::Exact(d))
          .is_present()
      })
    }),
  }
}

/// Does `input` reference a `Composite:Name` that is neither already built (in
/// `not_built`) nor present in `sink` at document `doc`? Such an input must defer
/// (ExifTool.pm:4044-4052). An input targets the Composite group when its group
/// set contains `"Composite"`.
#[cfg(feature = "alloc")]
fn references_unbuilt_composite<S: CompositeSink>(
  input: &table::CompositeInput,
  not_built: &std::collections::HashSet<&'static str>,
  sink: &S,
  doc: u32,
) -> bool {
  if !input.groups.contains(&"Composite") {
    return false;
  }
  // Already produced into the sink (this document) ⇒ not pending.
  if sink.has_composite(input.name, doc) {
    return false;
  }
  not_built.contains(input.name)
}

#[cfg(test)]
mod tests;
