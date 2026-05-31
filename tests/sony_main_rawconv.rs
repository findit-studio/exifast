// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! RawConv-undef-drop COMPLETENESS oracle for the Sony MakerNote Main tag
//! table.
//!
//! `tests/sony_main_table.rs` pins the table STRUCTURE, `tests/sony_main_conv.rs`
//! the CONVERSIONS, and `tests/sony_main_condition.rs` the Condition-gated
//! suppression. This complementary oracle pins **RawConv-driven tag
//! suppression**: in ExifTool a tag's `RawConv` runs during value extraction
//! (after `GetTagInfo`/Condition has selected the tag); if it returns `undef`
//! the value is NOT stored ⇒ the tag is ABSENT from default output. Several
//! `%Sony::Main` rows use this to DROP a sentinel raw value — almost all are
//! `$val == 65535 ? undef : $val` (`Sony.pm`), plus 0xb048's model-conditional
//! `($val == -1 and $$self{Model} =~ /DSLR-A100\b/) ? undef : $val`.
//!
//! A bundled LEAF row's RawConv is a **sentinel drop** (it can suppress the
//! tag) iff
//!
//!   * it is a LEAF (no `SubDirectory`), AND
//!   * its `RawConv` is a plain-string Perl expr (not a CODE ref), AND
//!   * the source mentions `undef` (a `… ? undef : …` or `return undef …`
//!     drop), AND
//!   * it is NOT a binary-passthrough RawConv — one that `return \$val`s a
//!     scalar ref to a binary blob (0x2001 PreviewImage), where the `undef` is
//!     the malformed-image branch, not a sentinel-scalar drop. These are
//!     excluded (the value the tag carries is the binary ref, never a scalar
//!     we convert).
//!
//! The DataMember-capture RawConvs (`$$self{AFAreaILCx} = $val`, 0x201c) and
//! the always-return ones (0x202f sprintf, 0xb000 `return $val`) carry no
//! `undef`, so the `undef`-mention test already excludes them.
//!
//! Every such **sentinel-drop LEAF** row MUST be modelled by the parse path's
//! [`RAWCONV_DROP_IDS`](exifast::exif::makernotes::vendors::sony::RAWCONV_DROP_IDS)
//! set (the drop is applied in `parse_in_tiff` via
//! [`rawconv_drops`](exifast::exif::makernotes::vendors::sony::rawconv_drops)),
//! UNLESS the id is in [`RAWCONV_DEFERRALS`] (each with a reason). Without this
//! the parse path would emit a bogus converted value where bundled drops the
//! tag (e.g. `65535 → "n/a"` instead of absent).
//!
//! Path resolution + SKIP-if-absent + staleness checks mirror
//! `tests/sony_main_condition.rs`.

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

/// One bundled LEAF RawConv-drop row's classification.
#[derive(Debug, Clone)]
struct BundledDrop {
  name: String,
  /// The squashed RawConv source (for the report).
  raw_conv: String,
}

/// Dump every `%Sony::Main` LEAF numeric key whose FIRST branch carries a
/// plain-string `RawConv` that can return `undef` (a sentinel drop), EXCLUDING
/// binary-passthrough RawConvs (those containing `\$val`). Emits
/// `0xID|Name|rawConvSquashed`.
fn dump_bundled_drops(lib: &Path) -> BTreeMap<u16, BundledDrop> {
  // NOTE: the per-branch scan covers ARRAY rows too (e.g. a future
  // conditional-ARRAY row could carry a drop on a branch), matching ExifTool's
  // per-branch RawConv. Today every Sony drop is on a single-HASH row.
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Sony;
no strict 'refs';
my %main = %Image::ExifTool::Sony::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my @branches = (ref $info eq 'ARRAY') ? @$info : ($info);
    for my $b (@branches) {
        next unless ref $b eq 'HASH';
        next if exists $b->{SubDirectory};
        my $rc = $b->{RawConv};
        next unless defined $rc;
        next if ref $rc;                 # CODE-ref RawConv — not a scalar drop
        next unless $rc =~ /undef/;       # must be able to return undef
        next if $rc =~ /\\\$val/;         # binary-passthrough (return \$val)
        my $name = defined $b->{Name} ? $b->{Name} : '?';
        (my $rc1 = $rc) =~ s/[\r\n]+/ /g;
        $rc1 =~ s/\|/!/g;                 # protect the field separator
        $rc1 =~ s/\s+/ /g;
        $rc1 =~ s/^\s+|\s+$//g;
        printf("0x%x|%s|%s\n", $n, $name, $rc1);
        last;                             # one row per id (first matching branch)
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Sony::Main RawConv drops");
  assert!(
    out.status.success(),
    "perl dump of Sony::Main RawConv drops failed:\nstdout={}\nstderr={}",
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
    let parts: Vec<&str> = line.splitn(3, '|').collect();
    assert_eq!(parts.len(), 3, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[0]));
    map.insert(
      id,
      BundledDrop {
        name: parts[1].to_string(),
        raw_conv: parts[2].to_string(),
      },
    );
  }
  map
}

/// Bundled sentinel-drop LEAF rows whose RawConv drop is deliberately NOT
/// ported — each with a one-line reason. Currently EMPTY: every Sony Main
/// sentinel-drop row is gated by the parse path. The oracle keeps it honest as
/// bundled evolves.
const RAWCONV_DEFERRALS: &[(u16, &str)] = &[];

#[test]
fn sony_main_rawconv_drops_modelled() {
  use exifast::exif::makernotes::vendors::sony::RAWCONV_DROP_IDS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Sony.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); RawConv-drop oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; RawConv-drop oracle skipped");
    return;
  }

  let bundled = dump_bundled_drops(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Sony::Main RawConv-drop rows"
  );

  let gated: BTreeSet<u16> = RAWCONV_DROP_IDS.iter().copied().collect();
  let deferrals: BTreeMap<u16, &str> = RAWCONV_DEFERRALS.iter().copied().collect();

  // (1) Every bundled sentinel-drop LEAF row must be gated or deferred.
  let mut ungated: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    if gated.contains(id) || deferrals.contains_key(id) {
      continue;
    }
    ungated.push(format!(
      "0x{id:x} {} — bundled RawConv can DROP a sentinel (RawConv: {}) but it \
       is neither in RAWCONV_DROP_IDS nor RAWCONV_DEFERRALS",
      b.name, b.raw_conv,
    ));
  }
  assert!(
    ungated.is_empty(),
    "{} bundled Sony Main RawConv-drop row(s) can suppress but are not \
     modelled (gate them in the parse path or add to RAWCONV_DEFERRALS with a \
     reason):\n{}",
    ungated.len(),
    ungated.join("\n"),
  );

  // (2) Every RAWCONV_DROP_IDS id must actually be a bundled sentinel-drop
  // LEAF row — otherwise the gated list has gone stale.
  let mut stale_gated: Vec<String> = Vec::new();
  for id in RAWCONV_DROP_IDS {
    if !bundled.contains_key(id) {
      stale_gated.push(format!(
        "0x{id:x}: in RAWCONV_DROP_IDS but bundled has no sentinel-drop RawConv there"
      ));
    }
  }
  assert!(
    stale_gated.is_empty(),
    "stale RAWCONV_DROP_IDS entries:\n{}",
    stale_gated.join("\n"),
  );

  // (3) Every RAWCONV_DEFERRALS id must still be a bundled sentinel-drop LEAF
  // that is NOT gated — otherwise the allow-list has gone stale.
  let mut stale_def: Vec<String> = Vec::new();
  for (id, reason) in RAWCONV_DEFERRALS {
    match bundled.get(id) {
      None => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no sentinel-drop RawConv there"
      )),
      Some(_) if gated.contains(id) => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but the id is now gated — drop it from \
         RAWCONV_DEFERRALS"
      )),
      Some(_) => {}
    }
  }
  assert!(
    stale_def.is_empty(),
    "stale RAWCONV_DEFERRALS entries:\n{}",
    stale_def.join("\n"),
  );
}
