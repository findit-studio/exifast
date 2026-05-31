// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Condition-COMPLETENESS oracle for the Sony MakerNote Main tag table.
//!
//! `tests/sony_main_table.rs` pins the table STRUCTURE and
//! `tests/sony_main_conv.rs` pins the CONVERSIONS. This complementary oracle
//! pins **Condition-gated tag suppression**: in ExifTool a Main-table tag can
//! carry a `Condition` (a Perl expr, usually on `$$self{Model}`, sometimes on
//! `$format`/`$$valPt`/a DataMember). `GetTagInfo` evaluates it; if it does
//! NOT match, the tag is not extracted and is ABSENT from default output.
//!
//! A bundled Conditioned row can SUPPRESS the tag on a non-matching body iff
//!
//!   * it is a LEAF (the first branch is NOT a `SubDirectory` — SubDirectory
//!     dispatchers are surfaced/deferred separately, never emitted as a leaf
//!     value), AND
//!   * NONE of its branches is unconditional (a single-HASH `{Condition=>…}`
//!     is always "all-conditional"; a conditional `[…]` ARRAY is
//!     all-conditional only when no branch lacks a `Condition`). A branch
//!     with no `Condition` is an unconditional catch-all that ALWAYS matches,
//!     so such a row never suppresses.
//!
//! Every such **suppressible LEAF** row MUST be modelled by the parse path's
//! condition-aware set
//! ([`CONDITION_GATED_IDS`](exifast::exif::makernotes::vendors::sony::CONDITION_GATED_IDS)),
//! UNLESS the id is in the explicit [`CONDITION_DEFERRALS`] allow-list (each
//! with a one-line reason). Without this the parse path would emit a raw /
//! converted value that bundled suppresses (the R5→R6 "missed a sub-kind"
//! recurrence — single-HASH `Condition` rows were missed after the four
//! conditional-ARRAY AF tags were handled).
//!
//! Like the sibling oracles we shell out to `perl` and let ExifTool's own
//! interpreter load the module (the Main hash embeds braces inside quoted
//! `Condition` strings, which would defeat a naive Rust scanner). Path
//! resolution + SKIP-if-absent mirror `tests/sony_main_table.rs`.

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
  let pm = lib.join("Image/ExifTool/Sony.pm");
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

/// One bundled Conditioned Main row's classification.
#[derive(Debug, Clone)]
struct BundledCond {
  name: String,
  /// `ARRAY` vs `HASH`.
  is_array: bool,
  /// Any branch lacks a `Condition` (an unconditional catch-all) ⇒ the row
  /// always resolves and never suppresses.
  has_catchall: bool,
  /// The FIRST branch is a `SubDirectory` (a deferred dispatcher, surfaced —
  /// never emitted as a leaf value).
  first_is_subdir: bool,
  /// The first branch's `Condition` (for the report).
  cond: String,
}

impl BundledCond {
  /// A suppressible LEAF row: not a SubDirectory dispatcher, and with no
  /// unconditional catch-all branch (so a non-matching body ⇒ ABSENT).
  fn is_suppressible_leaf(&self) -> bool {
    !self.first_is_subdir && !self.has_catchall
  }
}

/// Dump every `%Sony::Main` numeric key that carries a `Condition` (on the
/// single HASH, or on ANY branch of a conditional ARRAY). Emits
/// `0xID|Name|ARRAY?|CATCHALL?|SUBDIR1?|firstCond` (the `?` fields ∈ {0,1};
/// `firstCond` is base64-free — newlines/pipes in the Condition are squashed).
fn dump_bundled_conditions(lib: &Path) -> BTreeMap<u16, BundledCond> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Sony;
no strict 'refs';
my %main = %Image::ExifTool::Sony::Main;
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
    next unless @conds;  # only Conditioned rows
    my $first = $branches[0];
    next unless ref $first eq 'HASH';
    my $first_subdir = exists $first->{SubDirectory} ? 1 : 0;
    my $name = defined $first->{Name} ? $first->{Name} : '?';
    my $c = $conds[0];
    $c =~ s/[\r\n]+/ /g;
    $c =~ s/\|/!/g;       # protect the field separator
    $c =~ s/\s+/ /g;
    printf("0x%x|%s|%d|%d|%d|%s\n", $n, $name, $is_array, $has_uncond, $first_subdir, $c);
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Sony::Main conditions");
  assert!(
    out.status.success(),
    "perl dump of Sony::Main conditions failed:\nstdout={}\nstderr={}",
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

/// Bundled-Conditioned suppressible-LEAF rows whose model/DataMember gate is
/// deliberately NOT ported in Phase 3 — each with a one-line reason. The
/// completeness test accepts an un-gated id ONLY for these.
///
/// Anything NOT listed here that bundled can suppress MUST be in the parse
/// path's [`CONDITION_GATED_IDS`] (the test fails otherwise), so a future
/// faithful bump can't silently emit a value bundled would suppress.
const CONDITION_DEFERRALS: &[(u16, &str)] = &[
  // 0xb042 FocusMode (Sony.pm:2481-2483): Condition is
  //   `($$self{TagB042} = Get16u($valPt,0)) and (not $$self{MetaVersion} or
  //    $$self{MetaVersion} ne 'DC7303320222000')`.
  // Gates on the `MetaVersion` DataMember, which is set ONLY by the DEFERRED
  // `%Sony::ShotInfo` sub-table (0x3000, Sony.pm:6154-6157 `RawConv =>
  // '$$self{MetaVersion} = $val'`). exifast does not walk ShotInfo, so
  // MetaVersion is never set — faithful gating needs that walker first.
  (
    0xb042,
    "Condition gates on MetaVersion (set by the deferred ShotInfo sub-table)",
  ),
  // 0xb043 AFAreaMode (Sony.pm:2501,2520): a 2-branch all-conditional ARRAY —
  // branch 0 `not $$self{MetaVersion} or $$self{MetaVersion} ne 'DC73…'`,
  // branch 1 `$$self{TagB042} and $$self{TagB042} != 0`. Both DataMembers
  // (MetaVersion via ShotInfo, TagB042 via the deferred 0xb042 RawConv above)
  // are unset in a Main-only walk; defer with 0xb042.
  (
    0xb043,
    "Condition gates on MetaVersion/TagB042 (deferred ShotInfo + 0xb042 RawConv)",
  ),
  // 0xb04e FocusMode (Sony.pm:2636): Condition
  //   `$$self{MetaVersion} and $$self{MetaVersion} eq 'DC7303320222000'`.
  // Same MetaVersion DataMember dependency as 0xb042; defer together.
  (
    0xb04e,
    "Condition gates on MetaVersion (set by the deferred ShotInfo sub-table)",
  ),
];

#[test]
fn sony_main_suppressible_conditions_modelled() {
  use exifast::exif::makernotes::vendors::sony::CONDITION_GATED_IDS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Sony.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); Condition-completeness oracle skipped"
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
    "perl produced no Sony::Main Conditioned rows"
  );

  let gated: BTreeSet<u16> = CONDITION_GATED_IDS.iter().copied().collect();
  let deferrals: BTreeMap<u16, &str> = CONDITION_DEFERRALS.iter().copied().collect();

  // (1) Every suppressible LEAF row must be gated or explicitly deferred.
  let mut ungated: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    if !b.is_suppressible_leaf() {
      continue; // SubDirectory dispatcher or catch-all ARRAY ⇒ never suppresses.
    }
    if gated.contains(id) || deferrals.contains_key(id) {
      continue;
    }
    ungated.push(format!(
      "0x{id:x} {} ({}) — bundled can SUPPRESS this leaf on a non-matching \
       body (Condition: {}) but it is neither in CONDITION_GATED_IDS nor \
       CONDITION_DEFERRALS",
      b.name,
      if b.is_array { "ARRAY" } else { "HASH" },
      b.cond,
    ));
  }
  assert!(
    ungated.is_empty(),
    "{} bundled-Conditioned Sony Main leaf row(s) can suppress but are not \
     modelled (gate them in the parse path or add to CONDITION_DEFERRALS \
     with a reason):\n{}",
    ungated.len(),
    ungated.join("\n"),
  );

  // (2) Every CONDITION_GATED_IDS id must actually be a bundled suppressible
  // LEAF row — otherwise the gated list has gone stale.
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
  // row that is NOT gated — otherwise the allow-list has gone stale.
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
        "0x{id:x}: deferral {reason:?} but the id is now gated — drop it from \
         CONDITION_DEFERRALS"
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
