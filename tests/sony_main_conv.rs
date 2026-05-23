// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Conversion-COMPLETENESS oracle for the Sony MakerNote Main tag table.
//!
//! `tests/sony_main_table.rs` already pins the table STRUCTURE (id → Name →
//! Unknown). This complementary oracle pins the CONVERSIONS: every bundled
//! `%Image::ExifTool::Sony::Main` row that
//!
//!   (a) is a LEAF — its representative (first) branch is NOT a
//!       `SubDirectory` (matching the table-diff collapse, which records
//!       `$info->[0]{Name}` for conditional ARRAYs), AND
//!   (b) has a `PrintConv` OR `ValueConv` OR `RawConv` on that first branch
//!
//! MUST be wired to a non-[`SonyPrintConv::None`] `conv` in
//! [`SONY_TAGS`](exifast::exif::makernotes::vendors::sony::SONY_TAGS) —
//! UNLESS the id is in the explicit [`ACCEPTED_DEFERRALS`] allow-list (each
//! with a one-line reason). Without this, a leaf row that bundled converts
//! to a label silently emits the raw scalar in `-j`/`-n`.
//!
//! Like the table-diff oracle we shell out to `perl` and let ExifTool's own
//! interpreter load the module (the Main hash embeds braces inside quoted
//! `Condition` strings and pulls in shared fragments, which would defeat a
//! naive Rust scanner). Path resolution + SKIP-if-absent mirror
//! `tests/sony_main_table.rs` exactly: the bundled tree is `$EXIFTOOL`'s
//! parent (or the sibling `../exiftool` checkout); when `perl` or the
//! bundled `Sony.pm` is missing the test SKIPS gracefully.

#![cfg(all(unix, feature = "exif", feature = "std"))]

use std::{
  collections::BTreeMap,
  path::{Path, PathBuf},
  process::Command,
};

/// The bundled ExifTool `lib` directory containing `Image/ExifTool/*.pm`.
/// `$EXIFTOOL` points at the `exiftool` script; its sibling `lib/` holds the
/// modules. Falls back to the sibling `../exiftool` checkout. `None` ⇒ skip.
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

/// One bundled leaf-with-conv row: the set of conversion kinds present on
/// the FIRST branch (the table-diff representative).
#[derive(Debug, Default)]
struct BundledConv {
  name: String,
  print_conv: bool,
  value_conv: bool,
  raw_conv: bool,
}

/// Run `perl` to dump every Sony::Main numeric key whose FIRST branch is a
/// LEAF (no SubDirectory) and carries a PrintConv/ValueConv/RawConv. Emits
/// `0xID|Name|P|V|R` (P/V/R ∈ {0,1}).
fn dump_bundled_leaf_convs(lib: &Path) -> BTreeMap<u16, BundledConv> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Sony;
no strict 'refs';
my %main = %Image::ExifTool::Sony::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    # The representative is the FIRST branch (matches the table-diff oracle).
    my $first = (ref $info eq 'ARRAY') ? $info->[0] : $info;
    next unless ref $first eq 'HASH';
    # (a) LEAF: first branch is NOT a SubDirectory.
    next if exists $first->{SubDirectory};
    # (b) has a conversion on the first branch.
    my $p = exists $first->{PrintConv} ? 1 : 0;
    my $v = exists $first->{ValueConv} ? 1 : 0;
    my $r = exists $first->{RawConv}   ? 1 : 0;
    next unless $p || $v || $r;
    my $name = defined $first->{Name} ? $first->{Name} : '?';
    printf("0x%x|%s|%d|%d|%d\n", $n, $name, $p, $v, $r);
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Sony::Main leaf convs");
  assert!(
    out.status.success(),
    "perl dump of Sony::Main leaf convs failed:\nstdout={}\nstderr={}",
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
    let parts: Vec<&str> = line.split('|').collect();
    assert_eq!(parts.len(), 5, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[0]));
    map.insert(
      id,
      BundledConv {
        name: parts[1].to_string(),
        print_conv: parts[2] == "1",
        value_conv: parts[3] == "1",
        raw_conv: parts[4] == "1",
      },
    );
  }
  map
}

/// Leaf rows whose bundled first-branch conv is deliberately NOT ported in
/// Phase 3 — each with a one-line reason. The completeness test accepts a
/// `SonyPrintConv::None` ONLY for these ids.
///
/// Anything NOT listed here that bundled converts MUST have a real conv (the
/// test fails otherwise), so a future faithful bump can't silently regress a
/// leaf back to raw.
const ACCEPTED_DEFERRALS: &[(u16, &str)] = &[
  // 0x2001 PreviewImage (Sony.pm:906-948): RawConv is a Binary-data
  // passthrough (`return \$val if $val =~ /^Binary/`), not a value label —
  // the embedded preview JPEG is surfaced raw, not converted.
  (
    0x2001,
    "PreviewImage RawConv = binary-data passthrough (raw blob)",
  ),
  // NOTE: 0x201c AFAreaModeSetting / 0x201e AFPointSelected / 0x2020
  // AFPointsUsed / 0x2022 FocalPlaneAFPointsUsed / 0xb02a LensSpec are now
  // IMPLEMENTED (model-conditional dispatch + DataMember threading + BITMASK
  // + ConvLensSpec/PrintLensSpec) — see the `SonyPrintConv` variants and the
  // oracle tests in `printconv.rs` / `mod.rs`. They were removed from this
  // allow-list; the completeness test now requires their real convs.
  //
  // %unknownCipherData rows (Sony.pm:675-681): Unknown => 1, RawConv runs
  // Decipher() then ValueConv = PrintHex; the deciphered per-model decode is
  // deferred (and the rows are suppressed from default output anyway).
  (
    0x9407,
    "Sony_0x9407 %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x9408,
    "Sony_0x9408 %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x9409,
    "Sony_0x9409 %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x940b,
    "Sony_0x940b %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x940d,
    "Sony_0x940d %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x940f,
    "Sony_0x940f %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
  (
    0x9411,
    "Sony_0x9411 %unknownCipherData (Decipher, Unknown=>1, deferred)",
  ),
];

#[test]
fn sony_main_leaf_conversions_complete() {
  use exifast::exif::makernotes::vendors::sony::{SONY_TAGS, SonyPrintConv};

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Sony.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); conv-completeness oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; conv-completeness oracle skipped");
    return;
  }

  let bundled = dump_bundled_leaf_convs(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Sony::Main leaf-with-conv rows"
  );

  // id -> conv for the Rust table.
  let rust: BTreeMap<u16, SonyPrintConv> = SONY_TAGS.iter().map(|t| (t.id, t.conv)).collect();
  let deferrals: BTreeMap<u16, &str> = ACCEPTED_DEFERRALS.iter().copied().collect();

  let mut missing: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    let conv = rust.get(id).copied().unwrap_or(SonyPrintConv::None);
    if conv != SonyPrintConv::None {
      continue; // implemented — good.
    }
    if deferrals.contains_key(id) {
      continue; // explicitly, documentedly deferred.
    }
    let mut kinds = Vec::new();
    if b.print_conv {
      kinds.push("PrintConv");
    }
    if b.value_conv {
      kinds.push("ValueConv");
    }
    if b.raw_conv {
      kinds.push("RawConv");
    }
    missing.push(format!(
      "0x{id:x} {} — bundled has {} but SONY_TAGS conv is None (not in \
       ACCEPTED_DEFERRALS)",
      b.name,
      kinds.join("+"),
    ));
  }

  assert!(
    missing.is_empty(),
    "{} Sony Main leaf row(s) have a bundled conv but are wired to \
     SonyPrintConv::None (implement the conv or add to ACCEPTED_DEFERRALS \
     with a reason):\n{}",
    missing.len(),
    missing.join("\n"),
  );

  // Every ACCEPTED_DEFERRALS id must actually BE a bundled leaf-with-conv row
  // that is still None — otherwise the allow-list has gone stale (e.g. the
  // conv was implemented, or the row changed shape). Keeps the list honest.
  let mut stale: Vec<String> = Vec::new();
  for (id, reason) in ACCEPTED_DEFERRALS {
    if !bundled.contains_key(id) {
      stale.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no leaf conv there"
      ));
      continue;
    }
    if rust.get(id).copied().unwrap_or(SonyPrintConv::None) != SonyPrintConv::None {
      stale.push(format!(
        "0x{id:x}: deferral {reason:?} but the conv is now implemented — \
         drop it from ACCEPTED_DEFERRALS"
      ));
    }
  }
  assert!(
    stale.is_empty(),
    "stale ACCEPTED_DEFERRALS entries:\n{}",
    stale.join("\n"),
  );
}
