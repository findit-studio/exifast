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
//! regardless of registry order.
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
//! GPS refs `N`/`S`/`E`/`W`, `DateStamp`, `TimeStamp`, the ingredients the GPS /
//! EXIF / datetime defs added by later #133 PRs read) is correctly seen as
//! PRESENT, and a string `Inhibitor` correctly suppresses. Each
//! [`CompositeDef::derive`](table::CompositeDef) then does its OWN coercion: the
//! Duration defs coerce numeric and apply the Perl-truthy `&&` guard on the raw
//! value; future string defs read the string directly. This keeps ONE input
//! model general for PRs 2-5.
//!
//! ## Inputs resolve from the RAW value, independent of `-j`/`-n`
//!
//! ExifTool's `BuildCompositeTags` reads each input's ValueConv value for
//! `$val[i]` (`GetValue($tag, 'ValueConv')`, ExifTool.pm:4112) REGARDLESS of the
//! requested output conversion — the composite's own `RawConv`/`ValueConv` runs
//! on the machine value, never the printed form. exifast mirrors this: under
//! `-n` the emitted sink already holds the raw ValueConv values, so it is its
//! own resolution view; under `-j` the sink holds PrintConv strings, so the
//! caller re-emits the Meta in ValueConv mode into a separate `raw_view` and the
//! engine resolves inputs (and Composite-dependencies) from THAT, while each
//! composite's RENDERED (`-j`) value still lands in the output sink. (A
//! composite's PrintConv form `$prt[i]`, needed by e.g. `GPSPosition`'s
//! PrintConv in a later #133 PR, is not wired yet — no PR-1 composite reads it;
//! it slots in as a parallel per-input lookup.)

pub mod convs;
mod table;

#[cfg(feature = "alloc")]
use crate::tagmap::TagMap;
#[cfg(feature = "alloc")]
use crate::value::TagValue;
#[cfg(feature = "alloc")]
use table::{CompositeDef, CompositePrintConv, CompositeValue, REGISTRY};

/// A dedup sink the Composite engine reads inputs from and appends results to.
/// Implemented by [`TagMap`](crate::tagmap::TagMap) (the JSON / golden path) and
/// by the [`Tag`](crate::value::Tag) `Vec` ([`iter_tags`](crate::format_parser
/// ::AnyMeta::iter_tags) path) so ONE fixpoint engine serves both.
#[cfg(feature = "alloc")]
trait CompositeSink {
  /// The LAST-emitted Main-document value whose family-1 group is in `groups`
  /// (or ANY group when `groups` is empty) and whose name is `name`, as a
  /// [`CompositeValue`] carrying the RAW stored [`TagValue`]
  /// ([`Present`](CompositeValue::Present)) — NOT pre-coerced. The engine
  /// invokes this on the ValueConv RESOLUTION view (under `-n` the emitted sink
  /// itself; under `-j` a separate ValueConv re-emission), so the returned value
  /// is the faithful `$val[i]` regardless of the output mode. A `Missing` result
  /// means no such tag was extracted (`!defined $val[i]`); a present value of
  /// ANY shape (numeric or string) is [`Present`](CompositeValue::Present), so
  /// `Inhibit`/`Require`/`Desire` resolve on presence and each def performs its
  /// own coercion.
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue;
  /// Is a `Composite:<name>` already present?
  fn has_composite(&self, name: &str) -> bool;
  /// Append a built `Composite:<name>` (at Main, ExifTool default `Priority`).
  fn append(&mut self, name: &'static str, value: TagValue);
}

#[cfg(feature = "alloc")]
impl CompositeSink for TagMap {
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue {
    let group_ok = |g: &str| groups.is_empty() || groups.contains(&g);
    // Reverse scan for the LAST match (entries are in first-occurrence order;
    // the last duplicate is the highest-precedence — `APE_dup_override`).
    match self
      .entries()
      .iter()
      .rev()
      .find(|(doc, _sub, fam1, n, _pri, _val)| {
        *doc == 0 && n.as_str() == name && group_ok(fam1.as_str())
      }) {
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
  fn append(&mut self, name: &'static str, value: TagValue) {
    let _ = self.write_value_doc(0, 0, "Composite", name, 1, value);
  }
}

/// The [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) sink — the
/// deduped [`Tag`](crate::value::Tag) `Vec`. Appended composites carry the full
/// `Composite`/`Composite` group (family-0 = family-1), matching the JSON path.
#[cfg(feature = "alloc")]
impl CompositeSink for std::vec::Vec<crate::value::Tag> {
  fn resolve(&self, groups: &[&str], name: &str) -> CompositeValue {
    let group_ok = |g: &str| groups.is_empty() || groups.contains(&g);
    match self
      .iter()
      .rev()
      .find(|t| t.group_ref().doc() == 0 && t.name() == name && group_ok(t.group_ref().family1()))
    {
      Some(tag) => CompositeValue::Present(t_value(tag).clone()),
      None => CompositeValue::Missing,
    }
  }
  fn has_composite(&self, name: &str) -> bool {
    self
      .iter()
      .any(|t| t.group_ref().family1() == "Composite" && t.name() == name)
  }
  fn append(&mut self, name: &'static str, value: TagValue) {
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

/// Build every registered Composite tag into `out` (the post-`run_emission`
/// pass). `mode` is the active OUTPUT conversion mode (`-j` ⇒ PrintConv, `-n`
/// ⇒ ValueConv); `raw` is the SAME Meta re-emitted in ValueConv mode (`-n`),
/// supplied so the engine resolves each input from its post-ValueConv (raw)
/// value REGARDLESS of `mode` — ExifTool's `BuildCompositeTags`/`GetValue`
/// reads `$val[i]` as the input's ValueConv value, not the printed form
/// (ExifTool.pm:4044-4112). `None` ⇒ resolve from `out` itself (the `-n` path,
/// where the emitted values already ARE the raw ValueConv values, so a separate
/// pass is redundant). `doc_count` is the highest family-3 sub-document index
/// present (reserved for `SubDoc` composites — none of the registered Duration
/// defs is `SubDoc`, so they build at Main only regardless, ExifTool.pm:3999).
#[cfg(feature = "alloc")]
pub(crate) fn build_composites(
  out: &mut TagMap,
  raw: Option<&mut TagMap>,
  mode: crate::emit::ConvMode,
  doc_count: u32,
) {
  let _ = doc_count; // reserved for SubDoc composites (later #133 PRs)
  build_into(REGISTRY, out, raw, mode);
}

/// Build every registered Composite tag into the
/// [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) `Tag` `Vec` (the
/// public generic-extraction path), so it yields the same `Composite:*` set the
/// JSON path does. `raw` is the SAME tag stream re-collected in ValueConv mode
/// (the input-resolution source; see [`build_composites`]); `None` on the `-n`
/// path where `tags` already holds the raw values.
#[cfg(feature = "alloc")]
pub(crate) fn build_composites_into_tags(
  tags: &mut std::vec::Vec<crate::value::Tag>,
  raw: Option<&mut std::vec::Vec<crate::value::Tag>>,
  mode: crate::emit::ConvMode,
) {
  build_into(REGISTRY, tags, raw, mode);
}

/// Drive the ExifTool `BuildCompositeTags` fixpoint over `defs`.
///
/// Inputs are resolved from the RAW (post-ValueConv) value of each ingredient,
/// independent of the active output `mode`: this is ExifTool's `$val[i]`
/// (`GetValue($tag, 'ValueConv')`, ExifTool.pm:4112), so a composite's own
/// `RawConv`/`ValueConv` always runs on the faithful machine value (a GPS ref
/// `"N"`/`"S"`, a decimal coordinate, a `DateStamp`) — never the printed form.
/// (A composite's PrintConv form `$prt[i]`, needed by e.g. `GPSPosition`'s
/// PrintConv in a LATER #133 PR, is not wired yet because no PR-1 composite —
/// `Duration` — reads it; it slots in as a second per-input lookup.)
///
/// `resolve_src` is the raw view to read inputs + composite-dependencies from
/// AND to append each built composite's RAW value to (so a composite that
/// `Require`s another `Composite:*` sees its raw value in the fixpoint). When
/// `None`, the active `out` sink IS the raw view (the `-n` path), so the engine
/// reads + appends there directly. The RENDERED composite (for `mode`) is
/// always appended to `out`. Split out so the oracle tests can pass synthetic
/// def lists, and generic over the sink so the TagMap and `Vec<Tag>` paths
/// share ONE engine.
#[cfg(feature = "alloc")]
fn build_into<S: CompositeSink>(
  defs: &[CompositeDef],
  out: &mut S,
  resolve_src: Option<&mut S>,
  mode: crate::emit::ConvMode,
) {
  match resolve_src {
    // `-j` (PrintConv): inputs + composite-dependencies resolve from the SEPARATE
    // raw ValueConv view. Each built composite's RAW value is appended back into
    // that view (so a Composite-requires-Composite chain reads faithful `$val[i]`
    // in the fixpoint), while its RENDERED (`-j`) value is mirrored into `out`.
    Some(raw_view) => run_fixpoint(defs, raw_view, |view, name, raw, pc| {
      view.append(
        name,
        render_value(pc, raw, crate::emit::ConvMode::ValueConv),
      );
      out.append(name, render_value(pc, raw, mode));
    }),
    // `-n` (ValueConv) and the synthetic-map oracle/differential tests: `out` is
    // itself the resolution view (its values are already the raw ValueConv form
    // in `-n`; in the test maps they ARE the ingredients), so resolution reads
    // `out` directly and the composite is appended there ONCE, rendered for the
    // active `mode`. Under `-n` that rendered value is the raw value, so a
    // dependent composite still resolves a faithful `$val[i]`. Byte-identical to
    // the pre-#133-round-3 single-sink engine.
    None => run_fixpoint(defs, out, |view, name, raw, pc| {
      view.append(name, render_value(pc, raw, mode));
    }),
  }
}

/// The ExifTool `BuildCompositeTags` fixpoint over `defs`, reading inputs (and
/// Composite-dependencies) from `resolve_view`. For each built composite,
/// `place_built(resolve_view, name, raw, print_conv)` is invoked to (1) make the
/// composite visible in `resolve_view` for any dependent composite's `$val[i]`
/// and (2) emit its output value — the `-j` arm appends the RAW value to the
/// raw view AND mirrors the rendered value to the output sink; the `-n`/test arm
/// appends the mode-rendered value once to the single sink.
#[cfg(feature = "alloc")]
fn run_fixpoint<S: CompositeSink>(
  defs: &[CompositeDef],
  resolve_view: &mut S,
  mut place_built: impl FnMut(&mut S, &'static str, f64, CompositePrintConv),
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
      // Resolve each input index to a `CompositeValue` (PRESENCE + raw value),
      // never pre-coercing. `Require`/`Desire`/`Inhibit` key on presence; the
      // def's `derive` does its own coercion of the `Present` raw values.
      let mut values: std::vec::Vec<CompositeValue> =
        std::vec::Vec::with_capacity(def.inputs.len());
      let mut suppress = false; // an Inhibit input was present
      let mut require_missing = false;

      for input in def.inputs {
        // Composite-dependency deferral (ExifTool.pm:4044-4052): an input that
        // references a `Composite:Name` not yet built defers this def — UNLESS
        // it is an Inhibit and we are in the final `$allBuilt` pass.
        if references_unbuilt_composite(input, &not_built, resolve_view) {
          let defer = !(input.kind.is_inhibit() && all_built);
          if defer {
            deferred.push(def);
            continue 'def;
          }
        }

        let resolved = resolve_view.resolve(input.groups, input.name);
        if resolved.is_present() {
          if input.kind.is_inhibit() {
            // ExifTool.pm:4078-4081 `$found = 0; last` — a PRESENT inhibitor of
            // ANY value (numeric or string) suppresses the composite.
            suppress = true;
            break;
          }
          values.push(resolved);
        } else {
          if input.kind.is_require() {
            // ExifTool.pm:4084-4087 `$found = 0; last` — required & missing.
            require_missing = true;
            break;
          }
          // Desire / Inhibit absent ⇒ undef element, keep going.
          values.push(CompositeValue::Missing);
        }
      }

      if suppress || require_missing {
        // Can't / shouldn't build — proven settled this pass.
        not_built.remove(def.name);
        continue;
      }

      // All inputs resolved: run the derivation. The arm-specific `place_built`
      // makes the composite visible in `resolve_view` (for a dependent
      // composite's `$val[i]`) AND emits its output value (see `build_into`).
      not_built.remove(def.name);
      if let Some(raw) = (def.derive)(&values) {
        place_built(resolve_view, def.name, raw, def.print_conv);
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
        // (the registered Duration defs never cycle); drop the unbuildable
        // deferred defs and stop.
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

/// Render the derived raw value for the def's PrintConv + the active mode.
#[cfg(feature = "alloc")]
fn render_value(pc: CompositePrintConv, raw: f64, mode: crate::emit::ConvMode) -> TagValue {
  match pc {
    CompositePrintConv::ConvertDuration => convs::duration_value(raw, mode),
  }
}

#[cfg(test)]
mod tests;
