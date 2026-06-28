// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::Exif::PrintLensID` (Exif.pm:5881) — the Sony / Minolta
//! lens disambiguation that turns a multi-candidate `LensType` (a
//! `%sonyLensTypes` / `%sonyLensTypes2` row carrying `id.1`, `id.2`, … float
//! variants) into a single lens name, driven by `Composite:LensID`'s decoded
//! `LensSpec` / `FocalLength` / `MaxAperture` / `LensModel` ingredients
//! (Exif.pm:5303-5360).
//!
//! [`print_lens_id`] is the faithful transliteration of the Sony/Minolta paths
//! of `PrintLensID`: the candidate list (Exif.pm:5962-5971), the **LensSpec
//! branch** (Exif.pm:5983-5995 — keep candidates within ±0.5 focal / ±0.15
//! aperture of the parsed `LensSpec`, an exact LensSpec-suffix match winning
//! outright), the **FocalLength / MaxAperture branch** (Exif.pm:6001-6036 —
//! rule out by range, then pick the closest via the log-log aperture
//! interpolation), the Minolta teleconverter scaling (Exif.pm:5997-6000),
//! `MatchLensModel` (Exif.pm:5847-5872), the 65535 manual-lens `%sonyEtype`
//! path (Exif.pm:5915-5931) and the final fall-through join (Exif.pm:6052-6059).
//!
//! The caller ([`crate::composite::table`]) maps the `Composite:LensID`
//! ingredients into [`PrintLensIdInputs`] and selects the backing
//! [`SonyLensTable`] (the A-mount `%sonyLensTypes` for the plain `LensType`,
//! the E-mount `%sonyLensTypes2` for a substituted `LensType2`/`LensType3`).
//! The cross-vendor PrintLensID branches exifast does not back with a ported
//! lens DB (Canon `Canon::PrintLensID`, the Metabones/Sigma adapter
//! substitutions) return `None` so the composite DEFERS rather than mis-emit.

#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;
use std::collections::BTreeSet;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::exif::makernotes::vendors::sony::{amount_lens_types, lens_info, lens_types};

/// Which `%sonyLensTypes*` PrintConv table the effective `LensType` resolves
/// against — selected by the caller from the `Composite:LensID` substitution
/// index (the plain `LensType` is A-mount; a substituted `LensType2`/
/// `LensType3` is E-mount `%sonyLensTypes2`).
pub(crate) enum SonyLensTable {
  /// The A-mount (Minolta-backed) `%sonyLensTypes`.
  AMount,
  /// The E-mount `%sonyLensTypes2`.
  EMount,
}

impl SonyLensTable {
  /// `$$printConv{$lensType}` — the primary lens name for `id` (with any
  /// `" or …"` tail intact), or `None` when `id` is not a table key.
  pub(crate) fn lookup_name(&self, id: u32) -> Option<SmolStr> {
    match self {
      SonyLensTable::AMount => amount_lens_types::lookup_name(id),
      SonyLensTable::EMount => lens_types::lookup_name(id),
    }
  }

  /// `$$printConv{"$lensType.1"}`, `"$lensType.2"`, … — the float-keyed
  /// variant names for `id`, in ascending variant order (empty when none).
  fn variant_names(&self, id: u32) -> Vec<&'static str> {
    match self {
      SonyLensTable::AMount => amount_lens_types::lens_variants(id)
        .iter()
        .map(|v| v.name)
        .collect(),
      SonyLensTable::EMount => lens_types::lens_variants(id)
        .iter()
        .map(|v| v.name)
        .collect(),
    }
  }
}

/// The decoded `Composite:LensID` ingredients `PrintLensID` reads (Exif.pm:5883
/// argument list), post the `Composite:LensID` PrintConv's `LensType2`/
/// `LensType3` substitution. Every field but `lens_type` / `lens_type_prt` /
/// `table` is a `Desire` and may be absent.
pub(crate) struct PrintLensIdInputs<'a> {
  /// `$$et{Make} eq 'SONY'` — selects the Sony branch (65535 / adapter) over
  /// the non-Sony Canon branch.
  pub(crate) is_sony: bool,
  /// `$$et{Model}` — matched against `/NEX|ILCE/` for the 65535 manual-lens
  /// `%sonyEtype` path.
  pub(crate) model: Option<&'a str>,
  /// `$prt[idx]` — the LensType PrintConv name (the `$lensTypePrt` fallback).
  pub(crate) lens_type_prt: &'a str,
  /// `$prt[8]` — the printed `LensSpec` (GetLensInfo source + the exact-suffix
  /// match).
  pub(crate) lens_spec_prt: Option<&'a str>,
  /// `$lensType` — the effective (post-substitution) integer LensType.
  pub(crate) lens_type: i64,
  /// `$val[1]` FocalLength.
  pub(crate) focal_length: Option<f64>,
  /// `$val[2]` MaxAperture.
  pub(crate) max_aperture: Option<f64>,
  /// `$val[3]` MaxApertureValue (used when MaxAperture is absent/zero).
  pub(crate) max_aperture_value: Option<f64>,
  /// `$val[4]` MinFocalLength.
  pub(crate) short_focal: Option<f64>,
  /// `$val[5]` MaxFocalLength.
  pub(crate) long_focal: Option<f64>,
  /// `$val[6]` LensModel (the `MatchLensModel` filter).
  pub(crate) lens_model: Option<&'a str>,
  /// `$val[7]` LensFocalRange (overrides Min/MaxFocalLength when it parses).
  pub(crate) lens_focal_range: Option<&'a str>,
  /// The `%sonyLensTypes*` table backing `lens_type`.
  pub(crate) table: SonyLensTable,
}

/// `Image::ExifTool::Exif::PrintLensID` (Exif.pm:5881) — the Sony/Minolta
/// paths. Returns the resolved lens name (`Some`), or `None` to DEFER when a
/// cross-vendor branch (Canon `Canon::PrintLensID`, the Metabones/Sigma adapter
/// substitution) would be needed but exifast has not ported that lens DB.
#[must_use]
pub(crate) fn print_lens_id(inp: &PrintLensIdInputs<'_>) -> Option<String> {
  // `($sf0,$lf0,$sa0,$la0) = GetLensInfo($lensSpecPrt) if $lensSpecPrt; undef
  // $sf0 unless $sa0` (Exif.pm:5904-5908) — the LensSpec range, dropped when
  // the aperture parsed to zero.
  let lens_spec_info = inp
    .lens_spec_prt
    .and_then(lens_info::get_lens_info)
    .filter(|&(_sf0, _lf0, sa0, _la0)| sa0 != 0.0);

  // `$maxAperture = $maxApertureValue unless $maxAperture` (Exif.pm:5910).
  let max_aperture = if inp.max_aperture.is_some_and(|a| a != 0.0) {
    inp.max_aperture
  } else {
    inp.max_aperture_value
  };

  // `if ($lensFocalRange =~ /^(\d+)(?: (?:to )?(\d+))?$/) { ($shortFocal,
  // $longFocal) = ($1, $2 || $1) }` (Exif.pm:5911-5913). (Dead for the Sony
  // generic loop; only feeds the non-Sony Canon-branch defer test below.)
  let (mut short_focal, mut long_focal) = (inp.short_focal, inp.long_focal);
  if let Some(lfr) = inp.lens_focal_range.filter(|s| perl_truthy_str(s))
    && let Some((s, l)) = parse_lens_focal_range(lfr)
  {
    short_focal = Some(s);
    long_focal = Some(l);
  }

  let lens_type = inp.lens_type;
  // Make-specific branches (Exif.pm:5914-5961).
  if inp.is_sony {
    if lens_type == 65535 {
      // `return $$printConv{65535} if $$printConv{65535} and not $focalLength
      // and $maxAperture == 1` — the manual-lens patch (Exif.pm:5917).
      if !perl_truthy_opt(inp.focal_length)
        && max_aperture == Some(1.0)
        && let Some(name) = inp.table.lookup_name(65535)
      {
        return Some(name.to_string());
      }
      // The `%sonyEtype` switch for NEX/ILCE bodies is applied below.
    } else if lens_type != 0xff00 && is_metabones_or_sigma_adapter(lens_type) {
      // Metabones/Sigma adapter (Exif.pm:5932-5952): the substituted Canon /
      // Sigma lens DB is not ported — DEFER.
      return None;
    }
  } else if perl_truthy_opt(short_focal)
    && perl_truthy_opt(long_focal)
    && !inp.lens_model.is_some_and(is_tamron_zoom)
  {
    // Canon branch (Exif.pm:5955-5960): `Canon::PrintLensID` is not ported —
    // DEFER.
    return None;
  }

  // The effective printConv: normally the table, but a Sony NEX/ILCE body with
  // an unrecognised E-type lens (`LensType == 65535`) is matched against the
  // de-duped `%sonyEtype` built from `%sonyLensTypes2` (Exif.pm:5918-5931).
  let etype = (inp.is_sony
    && lens_type == 65535
    && inp
      .model
      .is_some_and(|m| m.contains("NEX") || m.contains("ILCE")))
  .then(build_sony_etype);

  // `$lens = $$printConv{$lensType}` (Exif.pm:5962) — the full primary name,
  // plus its float-keyed variants.
  let (lens_full, variant_names): (String, Vec<String>) = match &etype {
    Some(et) => match et.split_first() {
      // `%sonyEtype{65535}` is already de-`or`'d; `65535.1`, `65535.2`, … are
      // the remaining de-duped E-mount names.
      Some((first, rest)) => (
        (*first).to_string(),
        rest.iter().map(|s| (*s).to_string()).collect(),
      ),
      None => return Some(or_str(inp.lens_model, inp.lens_type_prt).to_string()),
    },
    None => {
      let Some(id) = u32::try_from(lens_type).ok() else {
        return Some(or_str(inp.lens_model, inp.lens_type_prt).to_string());
      };
      let Some(name) = inp.table.lookup_name(id) else {
        // `return ($lensModel || $lensTypePrt) unless $lens` (Exif.pm:5963).
        return Some(or_str(inp.lens_model, inp.lens_type_prt).to_string());
      };
      let vars = inp
        .table
        .variant_names(id)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
      (name.to_string(), vars)
    }
  };

  // `return $lens unless $$printConv{"$lensType.1"}` (Exif.pm:5964) — no float
  // variants ⇒ the lens is unambiguous, return the primary verbatim.
  if variant_names.is_empty() {
    return Some(lens_full);
  }

  // `$lens =~ s/ or .*//s` then `@lenses = ($lens, variant1, …)`
  // (Exif.pm:5965-5971) — the candidate list (the primary's first name plus
  // every variant).
  let mut candidates: Vec<String> = Vec::with_capacity(variant_names.len() + 1);
  candidates.push(strip_or(&lens_full).to_string());
  candidates.extend(variant_names);

  // The disambiguation loop (Exif.pm:5973-6038). (`@user`, the user-defined
  // lens set, is always empty in exifast, so its branch is omitted.)
  let mut matches: Vec<String> = Vec::new();
  let mut best: Vec<String> = Vec::new();
  let mut diff: Option<f64> = None;

  for lens in &candidates {
    // `my ($sf,$lf,$sa,$la) = GetLensInfo($lens); next unless $sf;`
    // (Exif.pm:5980-5981).
    let Some((mut sf, mut lf, mut sa, mut la)) = lens_info::get_lens_info(lens) else {
      continue;
    };
    if sf == 0.0 {
      continue;
    }

    // The LensSpec branch (Exif.pm:5983-5995).
    if let Some((sf0, lf0, sa0, la0)) = lens_spec_info {
      // `next if abs($sf-$sf0)>0.5 or abs($sa-$sa0)>0.15 or abs($lf-$lf0)>0.5
      // or abs($la-$la0)>0.15`.
      if (sf - sf0).abs() > 0.5
        || (sa - sa0).abs() > 0.15
        || (lf - lf0).abs() > 0.5
        || (la - la0).abs() > 0.15
      {
        continue;
      }
      // `$lensSpecPrt and $lens =~ / \Q$lensSpecPrt\E( \(| GM$|$)/ and @best =
      // ($lens), last` — an exact LensSpec-suffix match wins outright.
      if let Some(spec) = inp.lens_spec_prt
        && lens_spec_suffix_match(lens, spec)
      {
        best = std::vec![lens.clone()];
        break;
      }
      // `push @best, $lens unless $lens =~ /^Sony /` — keep only non-Sony
      // (the exact Sony match would have been taken above).
      if !lens.starts_with("Sony ") {
        best.push(lens.clone());
      }
      continue;
    }

    // `if ($lens =~ / \+ .*? (\d+(\.\d+)?)x( |$)/) { $sf*=$1; $lf*=$1; $sa*=$1;
    // $la*=$1 }` — the Minolta teleconverter scaling (Exif.pm:5997-6000).
    if let Some(factor) = teleconverter_factor(lens) {
      sf *= factor;
      lf *= factor;
      sa *= factor;
      la *= factor;
    }

    // `if ($focalLength) { next if $focalLength < $sf-0.5; next if $focalLength
    // > $lf+0.5 }` (Exif.pm:6002-6005).
    if let Some(fl) = inp.focal_length.filter(|&f| f != 0.0)
      && (fl < sf - 0.5 || fl > lf + 0.5)
    {
      continue;
    }

    // `if ($maxAperture) { … }` (Exif.pm:6006-6036).
    if let Some(ma) = max_aperture.filter(|&a| a != 0.0) {
      // `next if $maxAperture < $sa-0.15; next if $maxAperture > $la+0.15`.
      if ma < sa - 0.15 || ma > la + 0.15 {
        continue;
      }
      // The approximate max aperture at this focal length (Exif.pm:6015-6028).
      let fl = inp.focal_length.unwrap_or(0.0);
      let aa = if sf == lf || sa == la || fl <= sf {
        // 1) prime, 2) fixed-aperture zoom, or 3) zoom at/below min focal.
        sa
      } else if fl >= lf {
        la
      } else {
        // `exp(log($sa) + (log($la)-log($sa)) / (log($lf)-log($sf)) *
        // (log($focalLength)-log($sf)))` — the log-log variation (Exif.pm:6024).
        (sa.ln() + (la.ln() - sa.ln()) / (lf.ln() - sf.ln()) * (fl.ln() - sf.ln())).exp()
      };
      let d = (ma - aa).abs();
      // `if (defined $diff) { $d > $diff+0.15 and next; $d < $diff-0.15 and
      // undef @best } $diff = $d; push @best, $lens` (Exif.pm:6030-6035).
      if let Some(prev) = diff {
        if d > prev + 0.15 {
          continue;
        }
        if d < prev - 0.15 {
          best.clear();
        }
      }
      diff = Some(d);
      best.push(lens.clone());
    }

    // `push @matches, $lens` (Exif.pm:6037).
    matches.push(lens.clone());
  }

  // `@best = @matches unless @best` (Exif.pm:6052).
  if best.is_empty() {
    best = matches;
  }
  // `if (@best) { MatchLensModel(\@best, $lensModel); return join(' or ',
  // @best) }` (Exif.pm:6053-6056).
  if !best.is_empty() {
    match_lens_model(&mut best, inp.lens_model);
    return Some(best.join(" or "));
  }

  // The final fall-through (Exif.pm:6057-6059): `$lens = $$printConv{$lensType};
  // return $lensModel if $lensModel and $lens =~ / or /; return $lens`.
  if let Some(lm) = inp.lens_model.filter(|m| !m.is_empty())
    && lens_full.contains(" or ")
  {
    return Some(lm.to_string());
  }
  Some(lens_full)
}

/// `$lensModel || $lensTypePrt` — the LensModel when Perl-truthy (present,
/// non-empty), else the LensType print value.
fn or_str<'a>(lens_model: Option<&'a str>, lens_type_prt: &'a str) -> &'a str {
  match lens_model {
    Some(m) if !m.is_empty() => m,
    _ => lens_type_prt,
  }
}

/// `$lens =~ s/ or .*//s` (Exif.pm:5965) — the name up to (but excluding) its
/// first `" or "`.
fn strip_or(s: &str) -> &str {
  match s.find(" or ") {
    Some(i) => s.get(..i).unwrap_or(s),
    None => s,
  }
}

/// Perl boolean context on an optional coerced float: `0.0` (and absent) is
/// FALSE, every other value TRUE.
fn perl_truthy_opt(o: Option<f64>) -> bool {
  o.is_some_and(|v| v != 0.0)
}

/// Perl boolean context on a string: empty and the lone `"0"` are FALSE.
fn perl_truthy_str(s: &str) -> bool {
  !s.is_empty() && s != "0"
}

/// `/^(\d+)(?: (?:to )?(\d+))?$/` (Exif.pm:5911) on `LensFocalRange`: a leading
/// integer, then an optional ` <int>` / ` to <int>` tail. Returns
/// `(short, long || short)`, or `None` when the whole string does not match.
fn parse_lens_focal_range(s: &str) -> Option<(f64, f64)> {
  let b = s.as_bytes();
  // `^(\d+)`.
  let (n1, mut p) = uint_at(b, 0)?;
  if p == b.len() {
    return Some((n1, n1)); // bare integer ⇒ long defaults to short.
  }
  // `(?: (?:to )?(\d+))$` — a space, optional "to ", then a closing integer.
  if b.get(p) != Some(&b' ') {
    return None;
  }
  p += 1;
  if b.get(p..p + 3) == Some(b"to ") {
    p += 3;
  }
  let (n2, end) = uint_at(b, p)?;
  if end != b.len() {
    return None;
  }
  Some((n1, n2))
}

/// `\d+` at `i` → the integer value and the index past it (`None` when no digit).
fn uint_at(b: &[u8], i: usize) -> Option<(f64, usize)> {
  let mut j = i;
  while matches!(b.get(j), Some(c) if c.is_ascii_digit()) {
    j += 1;
  }
  let s = b.get(i..j)?;
  if s.is_empty() {
    return None;
  }
  let v: f64 = core::str::from_utf8(s).ok()?.parse().ok()?;
  Some((v, j))
}

/// `/ \+ .*? (\d+(\.\d+)?)x( |$)/` (Exif.pm:5997) — the teleconverter factor
/// (`1.4`/`2`) for a Minolta `… + … Nx …` lens name, or `None`.
fn teleconverter_factor(lens: &str) -> Option<f64> {
  let b = lens.as_bytes();
  // ` \+ ` (leftmost) then the lazy `.*?` gap then ` (\d+(\.\d+)?)x( |$)`.
  for (plus, _) in lens.match_indices(" + ") {
    let gap_start = plus + 3;
    let mut k = gap_start;
    loop {
      // The space that opens ` (\d+…)x`, then the number, then `x`, then ` `
      // or end-of-string.
      if b.get(k) == Some(&b' ')
        && let Some((num, end)) = number_at(b, k + 1)
        && b.get(end) == Some(&b'x')
        && matches!(b.get(end + 1), None | Some(&b' '))
      {
        return Some(num);
      }
      // `.` (= `[^\n]`) extends the lazy gap; it cannot cross a newline / end.
      match b.get(k) {
        Some(&c) if c != b'\n' => k += 1,
        _ => break,
      }
    }
  }
  None
}

/// `/ \Q$spec\E( \(| GM$|$)/` (Exif.pm:5991) — does ` <spec>` appear in `lens`
/// followed by ` (`, ` GM` at the end, or the end of string?
fn lens_spec_suffix_match(lens: &str, spec: &str) -> bool {
  if spec.is_empty() {
    return false;
  }
  let mut needle = String::with_capacity(spec.len() + 1);
  needle.push(' ');
  needle.push_str(spec);
  for (i, _) in lens.match_indices(&needle) {
    let rest = lens.get(i + needle.len()..).unwrap_or("");
    if rest.is_empty() || rest == " GM" || rest.starts_with(" (") {
      return true;
    }
  }
  false
}

/// `\d+(\.\d+)?` at `i` → the value and the end index, or `None`.
fn number_at(b: &[u8], i: usize) -> Option<(f64, usize)> {
  let mut j = i;
  while matches!(b.get(j), Some(c) if c.is_ascii_digit()) {
    j += 1;
  }
  if j == i {
    return None;
  }
  // `(?:\.\d+)?` — consume the dot only when at least one digit follows.
  if b.get(j) == Some(&b'.') {
    let frac = j + 1;
    let mut k = frac;
    while matches!(b.get(k), Some(c) if c.is_ascii_digit()) {
      k += 1;
    }
    if k > frac {
      j = k;
    }
  }
  let v: f64 = core::str::from_utf8(b.get(i..j)?).ok()?.parse().ok()?;
  Some((v, j))
}

/// The metabones/Sigma E-mount adapter test (Exif.pm:5939/5947): `LensType &
/// 0xff00` keys `%Image::ExifTool::Minolta::metabonesID` (Canon EF adapters),
/// OR `0x4900 <= LensType <= 0x590a` (the Sigma MC-11 SA-E offset). exifast has
/// not ported the substituted Canon / Sigma lens DBs, so the composite DEFERS.
fn is_metabones_or_sigma_adapter(lens_type: i64) -> bool {
  // `%metabonesID` keys (Minolta.pm:162-176) — the EF-adapter high bytes.
  const METABONES_HIGH: [i64; 12] = [
    0xef00, 0xf000, 0xf100, 0xff00, 0x7700, 0x7800, 0x7900, 0x8700, 0xbc00, 0xbd00, 0xbe00, 0xcc00,
  ];
  if METABONES_HIGH.contains(&(lens_type & 0xff00)) {
    return true;
  }
  (0x4900..=0x590a).contains(&lens_type)
}

/// `/^TAMRON.*-\d+mm/` (Exif.pm:5955) — a TAMRON zoom whose `LensModel`
/// reports a `-NNmm` focal RANGE (these report the CURRENT focal, so they are
/// excluded from the Canon-branch shortcut).
fn is_tamron_zoom(model: &str) -> bool {
  let Some(rest) = model.strip_prefix("TAMRON") else {
    return false;
  };
  // `.*-\d+mm` — a `-`, then `\d+`, then `mm`, anywhere in the remainder.
  let b = rest.as_bytes();
  for i in 0..b.len() {
    if b.get(i) != Some(&b'-') {
      continue;
    }
    let mut j = i + 1;
    while matches!(b.get(j), Some(c) if c.is_ascii_digit()) {
      j += 1;
    }
    if j > i + 1 && b.get(j) == Some(&b'm') && b.get(j + 1) == Some(&b'm') {
      return true;
    }
  }
  false
}

/// `%sonyEtype` (Exif.pm:5920-5928) — the de-duped E-mount lens names from
/// `%sonyLensTypes2`, in Perl's default string-`sort`-by-key order, each with
/// its `" or …"` tail removed. The first survivor is `%sonyEtype{65535}`, the
/// rest `65535.1`, `65535.2`, ….
fn build_sony_etype() -> Vec<&'static str> {
  // `sort keys %sonyLensTypes2` — collect the integer + float keys as the
  // strings Perl sorts (a byte-wise lexicographic order).
  let mut entries: Vec<(String, &'static str)> = Vec::new();
  for t in lens_types::SONY_LENS_TYPES {
    entries.push((t.id.to_string(), t.name));
  }
  for v in lens_types::SONY_LENS_VARIANTS {
    let mut key = v.id.to_string();
    key.push('.');
    key.push_str(&v.variant.to_string());
    entries.push((key, v.name));
  }
  entries.sort_by(|a, b| a.0.cmp(&b.0));
  // `($lens = $sonyLensTypes2{$_}) =~ s/ or .*//; next if $did{$lens}` — strip
  // and de-dup, keeping the first (sorted-key order) occurrence of each name.
  let mut seen: BTreeSet<&'static str> = BTreeSet::new();
  let mut out: Vec<&'static str> = Vec::new();
  for (_key, name) in entries {
    let lens = strip_or(name);
    if seen.insert(lens) {
      out.push(lens);
    }
  }
  out
}

/// `MatchLensModel($try, $lensModel)` (Exif.pm:5847) — narrow `try_list` (in
/// place) by the focal / aperture / version tokens of `lens_model`, never
/// emptying it. Each filter applies only when it leaves ≥1 and fewer entries.
fn match_lens_model(try_list: &mut Vec<String>, lens_model: Option<&str>) {
  // `if (@$try > 1 and $lensModel)`.
  let Some(model) = lens_model.filter(|m| !m.is_empty()) else {
    return;
  };
  if try_list.len() <= 1 {
    return;
  }
  // filter by focal length (`$lensModel =~ /((\d+-)?\d+mm)/`, Exif.pm:5853).
  if let Some(focal) = match_focal_token(model) {
    apply_filter(try_list, |t| t.contains(&focal));
  }
  // filter by aperture (`(?:F/?|1:)(\d+(\.\d+)?)`, Exif.pm:5859).
  if try_list.len() > 1
    && let Some(fnum) = match_aperture_token(model)
  {
    apply_filter(try_list, |t| aperture_matches(t, &fnum));
  }
  // filter by version / other lens parameters (`I+`, `USM`, Exif.pm:5865).
  for pat in ["I+", "USM"] {
    if try_list.len() <= 1 {
      break;
    }
    if let Some(val) = match_word_pattern(model, pat) {
      apply_filter(try_list, |t| has_word(t, &val));
    }
  }
}

/// `@filt = grep …; @$try = @filt if @filt and @filt < @$try` — apply one
/// `MatchLensModel` filter only when it keeps ≥1 and strictly fewer entries.
fn apply_filter(try_list: &mut Vec<String>, pred: impl Fn(&str) -> bool) {
  let filt: Vec<String> = try_list.iter().filter(|t| pred(t)).cloned().collect();
  if !filt.is_empty() && filt.len() < try_list.len() {
    *try_list = filt;
  }
}

/// `/((\d+-)?\d+mm)/` — the leftmost focal token of `model` (`"70-300mm"` /
/// `"55mm"`), or `None`.
fn match_focal_token(model: &str) -> Option<String> {
  let b = model.as_bytes();
  for start in 0..b.len() {
    if let Some(end) = focal_token_end(b, start) {
      return model.get(start..end).map(ToString::to_string);
    }
  }
  None
}

/// `((\d+-)?\d+mm)` anchored at `start` → the end index, mirroring the greedy
/// optional `\d+-` prefix (backtracking to absent).
fn focal_token_end(b: &[u8], start: usize) -> Option<usize> {
  // The greedy `(\d+-)?` prefix: `\d+` then `-`.
  let with_prefix = {
    let mut j = start;
    while matches!(b.get(j), Some(c) if c.is_ascii_digit()) {
      j += 1;
    }
    (j > start && b.get(j) == Some(&b'-')).then_some(j + 1)
  };
  for begin in [with_prefix, Some(start)] {
    let Some(p) = begin else { continue };
    // `\d+mm`.
    let mut k = p;
    while matches!(b.get(k), Some(c) if c.is_ascii_digit()) {
      k += 1;
    }
    if k > p && b.get(k) == Some(&b'm') && b.get(k + 1) == Some(&b'm') {
      return Some(k + 2);
    }
  }
  None
}

/// `m{(?:F/?|1:)(\d+(\.\d+)?)}i` — the leftmost f-number token of `model`
/// (`"F3.5"` → `"3.5"`), or `None`.
fn match_aperture_token(model: &str) -> Option<String> {
  let b = model.as_bytes();
  for i in 0..b.len() {
    let Some(p) = aperture_head(b, i) else {
      continue;
    };
    if let Some((_, end)) = number_at(b, p) {
      return model.get(p..end).map(ToString::to_string);
    }
  }
  None
}

/// `(?:F/?|1:)` (case-insensitive) at `i` → the index just past the head.
fn aperture_head(b: &[u8], i: usize) -> Option<usize> {
  match b.get(i) {
    Some(b'F' | b'f') => {
      let p = i + 1;
      Some(if b.get(p) == Some(&b'/') { p + 1 } else { p })
    }
    Some(b'1') if b.get(i + 1) == Some(&b':') => Some(i + 2),
    _ => None,
  }
}

/// `m{(F/?|1:)$fnum(\b|[A-Z])}i` — does `candidate` carry the f-number `fnum`
/// (an `F`/`F/`/`1:` head, then `fnum` with `.` as a regex wildcard, then a
/// word boundary or an uppercase letter)?
fn aperture_matches(candidate: &str, fnum: &str) -> bool {
  let b = candidate.as_bytes();
  let fb = fnum.as_bytes();
  for i in 0..b.len() {
    let Some(p) = aperture_head(b, i) else {
      continue;
    };
    if !fnum_match_at(b, p, fb) {
      continue;
    }
    if word_boundary_or_upper(b, p + fb.len()) {
      return true;
    }
  }
  false
}

/// `$fnum` interpolated into a regex: each byte matches literally except `.`,
/// which (a regex metacharacter) matches any single byte.
fn fnum_match_at(b: &[u8], p: usize, fnum: &[u8]) -> bool {
  for (k, &fc) in fnum.iter().enumerate() {
    match b.get(p + k) {
      Some(&c) if fc == b'.' || c == fc => {}
      _ => return false,
    }
  }
  true
}

/// `(\b|[A-Z])` after a `\w` (the f-number's last digit): a word boundary
/// (the next byte is non-word, or end-of-string) OR an uppercase ASCII letter.
fn word_boundary_or_upper(b: &[u8], q: usize) -> bool {
  match b.get(q) {
    None => true,
    Some(&c) => !is_word_byte(c) || c.is_ascii_uppercase(),
  }
}

/// `\b($pat)\b` for the two `MatchLensModel` version patterns: `"I+"` (a
/// word-bounded run of `I`s) or the literal `"USM"`. Returns the matched run.
fn match_word_pattern(model: &str, pat: &str) -> Option<String> {
  match pat {
    "I+" => find_i_run(model),
    literal => has_word(model, literal).then(|| literal.to_string()),
  }
}

/// `\b(I+)\b` — a maximal, word-bounded run of `I` in `model` (`"II"`,
/// `"III"`), or `None`.
fn find_i_run(model: &str) -> Option<String> {
  let b = model.as_bytes();
  let mut i = 0;
  while i < b.len() {
    if b.get(i) != Some(&b'I') {
      i += 1;
      continue;
    }
    let s = i;
    while b.get(i) == Some(&b'I') {
      i += 1;
    }
    let e = i;
    let before_ok = s == 0 || b.get(s - 1).is_none_or(|&c| !is_word_byte(c));
    let after_ok = b.get(e).is_none_or(|&c| !is_word_byte(c));
    if before_ok && after_ok {
      return model.get(s..e).map(ToString::to_string);
    }
  }
  None
}

/// `/\b$val\b/` — does `val` (`"II"`/`"III"`/`"USM"`, all word characters)
/// appear in `candidate` bounded by word boundaries?
fn has_word(candidate: &str, val: &str) -> bool {
  let b = candidate.as_bytes();
  let vb = val.as_bytes();
  if vb.is_empty() {
    return false;
  }
  let mut i = 0;
  while i + vb.len() <= b.len() {
    if b.get(i..i + vb.len()) == Some(vb) {
      let before_ok = i == 0 || b.get(i - 1).is_none_or(|&c| !is_word_byte(c));
      let after_ok = b.get(i + vb.len()).is_none_or(|&c| !is_word_byte(c));
      if before_ok && after_ok {
        return true;
      }
    }
    i += 1;
  }
  false
}

/// Perl `\w` byte: ASCII alphanumeric or `_`.
fn is_word_byte(c: u8) -> bool {
  c.is_ascii_alphanumeric() || c == b'_'
}

#[cfg(test)]
mod tests;
