// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! RawConv-undef-drop COMPLETENESS oracle for the Panasonic MakerNote Main
//! tag table (the counterpart of `tests/sony_main_rawconv.rs`).
//!
//! Companion to `tests/panasonic_main_table.rs` (structure),
//! `tests/panasonic_main_conv.rs` (conversions) and
//! `tests/panasonic_main_condition.rs` (Condition suppression). This oracle
//! pins **RawConv-driven tag suppression** — see the module doc of
//! `tests/sony_main_rawconv.rs` for the full rationale; the rule is identical.
//!
//! `%Panasonic::Main`'s sentinel-drop rows are: 0x86 ManometerPressure
//! (`$val==65535 ? undef : $val`), 0xd1 ISO (`$val > 0xfffffff0 ? undef :
//! $val`), and 0xc5/0xe4 LensTypeModel (`return undef unless $val; …`). All
//! four are gated by the parse path — 0x86/0xd1 via
//! [`PanasonicPrintConv::rawconv_drops`](exifast::exif::makernotes::vendors::panasonic::PanasonicPrintConv)
//! and 0xc5/0xe4 via the byte-swap conv's `apply_lens_type_model` (which
//! returns `None` on a zero raw) — so [`RAWCONV_DEFERRALS`] is currently
//! empty; the oracle keeps it honest as bundled evolves. There are no
//! DataMember-capture or binary-passthrough RawConvs in this table.

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

/// One bundled LEAF RawConv-drop row's classification.
#[derive(Debug, Clone)]
struct BundledDrop {
  name: String,
  raw_conv: String,
}

/// Dump every `%Panasonic::Main` LEAF numeric key whose FIRST branch carries a
/// plain-string `RawConv` that can return `undef` (a sentinel drop), EXCLUDING
/// binary-passthrough RawConvs (those containing `\$val`). Emits
/// `0xID|Name|rawConvSquashed`.
fn dump_bundled_drops(lib: &Path) -> BTreeMap<u16, BundledDrop> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my @branches = (ref $info eq 'ARRAY') ? @$info : ($info);
    for my $b (@branches) {
        next unless ref $b eq 'HASH';
        next if exists $b->{SubDirectory};
        my $rc = $b->{RawConv};
        next unless defined $rc;
        next if ref $rc;
        next unless $rc =~ /undef/;
        next if $rc =~ /\\\$val/;
        my $name = defined $b->{Name} ? $b->{Name} : '?';
        (my $rc1 = $rc) =~ s/[\r\n]+/ /g;
        $rc1 =~ s/\|/!/g;
        $rc1 =~ s/\s+/ /g;
        $rc1 =~ s/^\s+|\s+$//g;
        printf("0x%x|%s|%s\n", $n, $name, $rc1);
        last;
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main RawConv drops");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main RawConv drops failed:\nstdout={}\nstderr={}",
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
/// ported — each with a reason. Currently EMPTY: every Panasonic Main
/// sentinel-drop row is gated.
const RAWCONV_DEFERRALS: &[(u16, &str)] = &[];

#[test]
fn panasonic_main_rawconv_drops_modelled() {
  use exifast::exif::makernotes::vendors::panasonic::RAWCONV_DROP_IDS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); RawConv-drop oracle skipped"
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
    "perl produced no Panasonic::Main RawConv-drop rows"
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
    "{} bundled Panasonic Main RawConv-drop row(s) can suppress but are not \
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
  // that is NOT gated.
  let mut stale_def: Vec<String> = Vec::new();
  for (id, reason) in RAWCONV_DEFERRALS {
    match bundled.get(id) {
      None => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no sentinel-drop RawConv there"
      )),
      Some(_) if gated.contains(id) => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but the id is now gated — drop it"
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
