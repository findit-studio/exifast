// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Condition-COMPLETENESS oracle for the Panasonic MakerNote Main tag table.
//!
//! Companion to `tests/panasonic_main_table.rs` (structure) and
//! `tests/panasonic_main_conv.rs` (conversions). This oracle pins
//! **Condition-gated tag suppression** — see the module doc of
//! `tests/sony_main_condition.rs` for the full rationale; the rule is
//! identical here.
//!
//! A bundled Conditioned row can SUPPRESS the tag on a non-matching body iff
//! it is a LEAF (first branch is not a `SubDirectory`) AND has no
//! unconditional catch-all branch. Every such **suppressible LEAF** row MUST
//! be in the parse path's condition-aware set
//! ([`CONDITION_GATED_IDS`](exifast::exif::makernotes::vendors::panasonic::CONDITION_GATED_IDS)),
//! UNLESS it is in [`CONDITION_DEFERRALS`].
//!
//! `%Panasonic::Main`'s Conditioned rows are: the two model-conditional ARRAY
//! rows 0x0f `AFAreaMode` / 0x2c `ContrastMode` (each with an unconditional
//! catch-all branch ⇒ never suppress, handled by the per-model branch
//! selection) and the three `$format`/`$$valPt`-gated single-HASH LensType
//! rows 0xc4/0xc5/0xe4 (suppressible — gated). So `CONDITION_DEFERRALS` is
//! currently empty; the oracle keeps it honest as bundled evolves.

#![cfg(all(unix, feature = "exif", feature = "std"))]

use std::{
  collections::{BTreeMap, BTreeSet},
  path::{Path, PathBuf},
  process::Command,
};

/// The bundled ExifTool `lib` directory containing `Image/ExifTool/*.pm`.
fn exiftool_lib_dir(root: &str) -> Option<PathBuf> {
  let script = if let Ok(p) = std::env::var("EXIFTOOL") {
    PathBuf::from(p)
  } else {
    Path::new(root).join("../exiftool/exiftool")
  };
  let lib = script.parent()?.join("lib");
  let pm = lib.join("Image/ExifTool/Panasonic.pm");
  pm.is_file().then_some(lib)
}

/// Whether a usable `perl` is on `PATH`.
fn have_perl() -> bool {
  Command::new("perl")
    .args(["-e", "1"])
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
}

/// One bundled Conditioned Main row's classification (see `BundledCond` in
/// `tests/sony_main_condition.rs`).
#[derive(Debug, Clone)]
struct BundledCond {
  name: String,
  is_array: bool,
  has_catchall: bool,
  first_is_subdir: bool,
  cond: String,
}

impl BundledCond {
  fn is_suppressible_leaf(&self) -> bool {
    !self.first_is_subdir && !self.has_catchall
  }
}

/// Dump every `%Panasonic::Main` numeric key that carries a `Condition`.
fn dump_bundled_conditions(lib: &Path) -> BTreeMap<u16, BundledCond> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my $is_array = (ref $info eq 'ARRAY') ? 1 : 0;
    my @branches = $is_array ? @$info : ($info);
    my @conds;
    my $has_uncond = 0;
    for my $b (@branches) {
        next unless ref $b eq 'HASH';
        if (exists $b->{Condition}) { push @conds, $b->{Condition}; }
        else { $has_uncond = 1; }
    }
    next unless @conds;
    my $first = $branches[0];
    next unless ref $first eq 'HASH';
    my $first_subdir = exists $first->{SubDirectory} ? 1 : 0;
    my $name = defined $first->{Name} ? $first->{Name} : '?';
    my $c = $conds[0];
    $c =~ s/[\r\n]+/ /g;
    $c =~ s/\|/!/g;
    $c =~ s/\s+/ /g;
    printf("0x%x|%s|%d|%d|%d|%s\n", $n, $name, $is_array, $has_uncond, $first_subdir, $c);
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main conditions");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main conditions failed:\nstdout={}\nstderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr),
  );
  let text = String::from_utf8(out.stdout).expect("perl output is UTF-8");
  let mut map = BTreeMap::new();
  for line in text.lines() {
    let line = line.trim();
    if line.is_empty() {
      continue;
    }
    let parts: Vec<&str> = line.splitn(6, '|').collect();
    assert_eq!(parts.len(), 6, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[0]));
    map.insert(
      id,
      BundledCond {
        name: parts[1].to_string(),
        is_array: parts[2] == "1",
        has_catchall: parts[3] == "1",
        first_is_subdir: parts[4] == "1",
        cond: parts[5].to_string(),
      },
    );
  }
  map
}

/// Bundled-Conditioned suppressible-LEAF Panasonic rows whose gate is
/// deliberately NOT ported — each with a reason. Currently EMPTY: every
/// suppressible Panasonic Main leaf row is gated.
const CONDITION_DEFERRALS: &[(u16, &str)] = &[];

#[test]
fn panasonic_main_suppressible_conditions_modelled() {
  use exifast::exif::makernotes::vendors::panasonic::CONDITION_GATED_IDS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); Condition-completeness oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; Condition-completeness oracle skipped");
    return;
  }

  let bundled = dump_bundled_conditions(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Panasonic::Main Conditioned rows"
  );

  let gated: BTreeSet<u16> = CONDITION_GATED_IDS.iter().copied().collect();
  let deferrals: BTreeMap<u16, &str> = CONDITION_DEFERRALS.iter().copied().collect();

  // (1) Every suppressible LEAF row must be gated or explicitly deferred.
  let mut ungated: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    if !b.is_suppressible_leaf() {
      continue;
    }
    if gated.contains(id) || deferrals.contains_key(id) {
      continue;
    }
    ungated.push(format!(
      "0x{id:x} {} ({}) — bundled can SUPPRESS this leaf on a non-matching \
       entry (Condition: {}) but it is neither in CONDITION_GATED_IDS nor \
       CONDITION_DEFERRALS",
      b.name,
      if b.is_array { "ARRAY" } else { "HASH" },
      b.cond,
    ));
  }
  assert!(
    ungated.is_empty(),
    "{} bundled-Conditioned Panasonic Main leaf row(s) can suppress but are \
     not modelled (gate them or add to CONDITION_DEFERRALS):\n{}",
    ungated.len(),
    ungated.join("\n"),
  );

  // (2) Every CONDITION_GATED_IDS id must be a bundled suppressible LEAF row.
  let mut stale_gated: Vec<String> = Vec::new();
  for id in CONDITION_GATED_IDS {
    match bundled.get(id) {
      None => stale_gated.push(format!(
        "0x{id:x}: in CONDITION_GATED_IDS but bundled has no Conditioned row there"
      )),
      Some(b) if !b.is_suppressible_leaf() => stale_gated.push(format!(
        "0x{id:x} {}: in CONDITION_GATED_IDS but bundled row is not a \
         suppressible leaf (subdir={}, catchall={})",
        b.name, b.first_is_subdir, b.has_catchall
      )),
      Some(_) => {}
    }
  }
  assert!(
    stale_gated.is_empty(),
    "stale CONDITION_GATED_IDS entries:\n{}",
    stale_gated.join("\n"),
  );

  // (3) Every CONDITION_DEFERRALS id must still be a bundled suppressible LEAF
  // that is NOT gated.
  let mut stale_def: Vec<String> = Vec::new();
  for (id, reason) in CONDITION_DEFERRALS {
    match bundled.get(id) {
      None => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no Conditioned row there"
      )),
      Some(b) if !b.is_suppressible_leaf() => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled row is not a suppressible leaf"
      )),
      Some(_) if gated.contains(id) => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but the id is now gated — drop it"
      )),
      Some(_) => {}
    }
  }
  assert!(
    stale_def.is_empty(),
    "stale CONDITION_DEFERRALS entries:\n{}",
    stale_def.join("\n"),
  );
}
