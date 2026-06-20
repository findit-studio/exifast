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
use table::{CompositeDef, CompositeValue, REGISTRY};

/// A dedup sink the Composite engine reads inputs from and appends results to.
/// Implemented by [`TagMap`](crate::tagmap::TagMap) (the JSON / golden path) and
/// by the [`Tag`](crate::value::Tag) `Vec` ([`iter_tags`](crate::format_parser
/// ::AnyMeta::iter_tags) path) so ONE fixpoint engine serves both.
#[cfg(feature = "alloc")]
trait CompositeSink {
  /// The LAST-emitted Main-document value whose family-1 group is in `groups`
  /// (or ANY group when `groups` is empty) and whose name is `name`, as a
  /// [`CompositeValue`] carrying the RAW stored [`TagValue`]
  /// ([`Present`](CompositeValue::Present)). Invoked on whichever view supplies
  /// the requested form (the ValueConv view for `$val[i]`, the PrintConv view
  /// for `$prt[i]`). A `Missing` result means no such tag was extracted
  /// (`!defined`); a present value of ANY shape is
  /// [`Present`](CompositeValue::Present), so `Inhibit`/`Require`/`Desire`
  /// resolve on presence and each def performs its own coercion.
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue;
  /// Is a `Composite:<name>` already present?
  fn has_composite(&self, name: &str) -> bool;
  /// Append a built `Composite:<name>` (at Main, with ExifTool `Priority`).
  fn append(&mut self, name: &'static str, priority: u8, value: TagValue);
}

#[cfg(feature = "alloc")]
impl CompositeSink for crate::tagmap::TagMap {
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue {
    let group_ok = |g: &str| groups.is_empty() || groups.contains(&g);
    let pred = |entry: &&(u32, u32, smol_str::SmolStr, smol_str::SmolStr, u8, TagValue)| {
      entry.0 == 0 && entry.3.as_str() == name && group_ok(entry.2.as_str())
    };
    // A GROUP-SCOPED input (`groups` non-empty) takes the LAST match within that
    // group set — the duplicate-override precedence (`APE_dup_override`: a later
    // `APE:SampleRate=48000` overrides an earlier `MAC:SampleRate=44100`). A
    // BARE-NAME input (empty `groups`) takes the FIRST match across ALL groups —
    // ExifTool's bare-name lookup returns the PRIORITY-directory value (the main
    // EXIF IFD), which exifast emits BEFORE the lower-priority MakerNote
    // duplicate; so `Composite:FocalLength35efl`'s bare `FocalLength` resolves to
    // `ExifIFD:FocalLength` (50.0), NOT a later `Nikon:FocalLength` (50.4). (The
    // entries are in first-occurrence emission order: EXIF IFDs precede MakerNote
    // sub-tables, mirroring ExifTool's `$$self{PRIORITY}` directory.)
    let found = if groups.is_empty() {
      self.entries().iter().find(pred)
    } else {
      self.entries().iter().rev().find(pred)
    };
    match found {
      Some(entry) => CompositeValue::Present(entry.5.clone()),
      None => CompositeValue::Missing,
    }
  }
  fn has_composite(&self, name: &str) -> bool {
    self
      .entries()
      .iter()
      .any(|(_doc, _sub, fam1, n, _pri, _val)| fam1.as_str() == "Composite" && n.as_str() == name)
  }
  fn append(&mut self, name: &'static str, priority: u8, value: TagValue) {
    let _ = self.write_value_doc(0, 0, "Composite", name, priority, value);
  }
}

/// The [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) sink — the
/// deduped [`Tag`](crate::value::Tag) `Vec`. Appended composites carry the full
/// `Composite`/`Composite` group (family-0 = family-1), matching the JSON path.
#[cfg(feature = "alloc")]
impl CompositeSink for std::vec::Vec<crate::value::Tag> {
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue {
    let group_ok = |g: &str| groups.is_empty() || groups.contains(&g);
    let pred = |t: &&crate::value::Tag| {
      t.group_ref().doc() == 0 && t.name() == name && group_ok(t.group_ref().family1())
    };
    // Bare-name (empty `groups`) ⇒ FIRST match (the priority-directory EXIF tag,
    // emitted before its MakerNote duplicate); group-scoped ⇒ LAST match (the
    // duplicate-override). See the `TagMap` impl's note.
    let found = if groups.is_empty() {
      self.iter().find(pred)
    } else {
      self.iter().rev().find(pred)
    };
    match found {
      Some(tag) => CompositeValue::Present(t_value(tag).clone()),
      None => CompositeValue::Missing,
    }
  }
  fn has_composite(&self, name: &str) -> bool {
    self
      .iter()
      .any(|t| t.group_ref().family1() == "Composite" && t.name() == name)
  }
  fn append(&mut self, name: &'static str, _priority: u8, value: TagValue) {
    self.push(crate::value::Tag::new(
      crate::value::Group::new("Composite", "Composite"),
      name,
      value,
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

/// Build every registered Composite tag into `out` (the post-`run_emission`
/// pass). `mode` is the active OUTPUT conversion mode (`-j` ⇒ PrintConv, `-n`
/// ⇒ ValueConv); `other_view` is the SAME Meta re-emitted in the OPPOSITE mode,
/// supplied so the engine has BOTH a ValueConv view (`$val[i]`) and a PrintConv
/// view (`$prt[i]`) regardless of `mode` — under `-n`, `out` is the ValueConv
/// view and `other_view` is the PrintConv re-emission; under `-j`, `out` is the
/// PrintConv view and `other_view` is the ValueConv re-emission. `None` is
/// permitted ONLY when the defs read neither the opposite-mode view NOR a
/// composite dependency (the legacy single-sink Duration path); the registered
/// GPS defs always require `other_view`. `doc_count` is reserved for `SubDoc`
/// composites (the stills GPS defs build at Main only, `doc_count == 0`).
#[cfg(feature = "alloc")]
pub(crate) fn build_composites(
  out: &mut crate::tagmap::TagMap,
  other_view: Option<&mut crate::tagmap::TagMap>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
) {
  let _ = doc_count; // reserved for SubDoc composites (later #133 PRs)
  build_into(REGISTRY, out, other_view, mode);
}

/// Build every registered Composite tag into the
/// [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) `Tag` `Vec` (the
/// public generic-extraction path), so it yields the same `Composite:*` set the
/// JSON path does. `other_view` is the SAME tag stream re-collected in the
/// OPPOSITE mode (the `$prt[i]`/`$val[i]` source; see [`build_composites`]).
#[cfg(feature = "alloc")]
pub(crate) fn build_composites_into_tags(
  tags: &mut std::vec::Vec<crate::value::Tag>,
  other_view: Option<&mut std::vec::Vec<crate::value::Tag>>,
  mode: crate::emit::ConvMode,
) {
  build_into(REGISTRY, tags, other_view, mode);
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
      run_fixpoint(defs, val_view, Some(prt_view), mode);
    }
    // No `$prt` source: `out` is its own sole view (the ValueConv values in `-n`,
    // the synthetic oracle maps). A `$prt`-reading PrintConv sees `None` prt
    // elements; the Duration defs (the only `None`-path callers) ignore `$prt`.
    None => run_fixpoint(defs, out, None, mode),
  }
}

/// The ExifTool `BuildCompositeTags` fixpoint over `defs`, resolving `$val[i]`
/// from `val_view` and `$prt[i]` from `prt_view` (the SAME sink as `val_view`
/// when `prt_view` is `None`). The Composite-dependency deferral (`not_built` /
/// `has_composite`) keys on `val_view` (a dependency's `$val[i]` is what gates
/// the build). For each built composite, both forms are appended: the ValueConv
/// form to `val_view`, the PrintConv form to `prt_view` (or, when they coincide,
/// the active-mode form once).
#[cfg(feature = "alloc")]
fn run_fixpoint<S: CompositeSink>(
  defs: &[CompositeDef],
  val_view: &mut S,
  mut prt_view: Option<&mut S>,
  mode: crate::emit::ConvMode,
) {
  use crate::emit::ConvMode;
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
      // Resolve each input index to its `$val[i]` ([`CompositeValue`], presence
      // + raw value) AND its `$prt[i]` (the PrintConv-view value, `None` for an
      // absent/`Missing` input). `Require`/`Desire`/`Inhibit` key on `$val[i]`
      // presence; the def's `derive` reads `$val[]`; the PrintConv reads both.
      let mut vals: std::vec::Vec<CompositeValue> = std::vec::Vec::with_capacity(def.inputs.len());
      let mut prts: std::vec::Vec<Option<TagValue>> =
        std::vec::Vec::with_capacity(def.inputs.len());
      let mut suppress = false; // an Inhibit input was present
      let mut require_missing = false;

      for input in def.inputs {
        // Composite-dependency deferral (ExifTool.pm:4044-4052): an input that
        // references a `Composite:Name` not yet built defers this def — UNLESS
        // it is an Inhibit and we are in the final `$allBuilt` pass.
        if references_unbuilt_composite(input, &not_built, val_view) {
          let defer = !(input.kind.is_inhibit() && all_built);
          if defer {
            deferred.push(def);
            continue 'def;
          }
        }

        let resolved = val_view.resolve(input.groups, input.name);
        if resolved.is_present() {
          if input.kind.is_inhibit() {
            // ExifTool.pm:4078-4081 `$found = 0; last` — a PRESENT inhibitor of
            // ANY value (numeric or string) suppresses the composite.
            suppress = true;
            break;
          }
          // The matching `$prt[i]` from the PrintConv view (the SAME sink as
          // `val_view` when `prt_view` is `None`).
          let prt = match prt_view.as_deref() {
            Some(pv) => pv.resolve(input.groups, input.name),
            None => val_view.resolve(input.groups, input.name),
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
        // Can't / shouldn't build — proven settled this pass.
        not_built.remove(def.name);
        continue;
      }

      // All inputs resolved: run the derivation (`$val` from `$val[]`, and
      // `$prt[]` for the few defs whose ValueConv reads a PrintConv input —
      // `Composite:LightValue`'s `CalculateLV(...,$prt[2])`, Exif.pm:4801).
      not_built.remove(def.name);
      if let Some(raw) = (def.derive)(&vals, &prts) {
        // Append the ValueConv form to `val_view` and the PrintConv form to
        // `prt_view`, so a dependent composite reads both. When the two views
        // coincide (`None` prt_view), append the active-mode form once.
        match prt_view.as_deref_mut() {
          Some(prt) => {
            val_view.append(
              def.name,
              def.priority,
              def
                .print_conv
                .render(&raw, &vals, &prts, ConvMode::ValueConv),
            );
            prt.append(
              def.name,
              def.priority,
              def
                .print_conv
                .render(&raw, &vals, &prts, ConvMode::PrintConv),
            );
          }
          None => {
            val_view.append(
              def.name,
              def.priority,
              def.print_conv.render(&raw, &vals, &prts, mode),
            );
          }
        }
      }
      // `None` ⇒ the `… ? … : undef` guard fired; nothing emitted, but the
      // composite is settled (already removed from `not_built`).
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

/// Does `input` reference a `Composite:Name` that is neither already built (in
/// `not_built`) nor present in `sink`? Such an input must defer (ExifTool.pm:
/// 4044-4052). An input targets the Composite group when its group set contains
/// `"Composite"`.
#[cfg(feature = "alloc")]
fn references_unbuilt_composite<S: CompositeSink>(
  input: &table::CompositeInput,
  not_built: &std::collections::HashSet<&'static str>,
  sink: &S,
) -> bool {
  if !input.groups.contains(&"Composite") {
    return false;
  }
  // Already produced into the sink ⇒ not pending.
  if sink.has_composite(input.name) {
    return false;
  }
  not_built.contains(input.name)
}

#[cfg(test)]
mod tests;
