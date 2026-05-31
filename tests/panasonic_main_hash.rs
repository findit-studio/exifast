// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Hash-CONTENTS oracle for the Panasonic MakerNote Main tag table.
//!
//! `tests/panasonic_main_conv.rs` checks conversion PRESENCE (every bundled
//! leaf row that converts is wired to a non-`None` conv). That oracle is blind
//! to a MIS-TRANSCRIBED hash: a `PrintConv` whose keys map to the WRONG labels
//! still passes presence. (This is exactly how the 0xa1 FilterEffect scramble
//! — `'0 4' => 'High Key'` rendered as `Soft Focus`, etc. — slipped past.)
//!
//! This oracle closes that class. For EVERY bundled
//! `%Image::ExifTool::Panasonic::Main` LEAF branch whose `PrintConv` is a plain
//! discrete-value HASH (perl-dumped key → label), it DRIVES the real Rust
//! conversion path over EVERY bundled key and asserts the rendered
//! [`TagValue`] equals the bundled label verbatim — proving full hash-CONTENTS
//! fidelity, not just presence.
//!
//! Coverage: Panasonic's Main hashes are entirely integer- or
//! space-joined-integer-keyed (no ValueConv-produced string/float keys), so
//! the oracle drives ALL of them end-to-end, including the multi-branch
//! Model-conditional tags 0xf AFAreaMode (2 branches) and 0x2c ContrastMode
//! (3 hash branches), each branch wired to its distinct
//! [`PanasonicPrintConv`] variant via [`MULTI_BRANCH`]. The only auto-skips are
//! `OTHER`/`Notes`/`BITMASK` pseudo-keys (not discrete labels) and branches
//! with no hash `PrintConv`.
//!
//! Path resolution + SKIP-if-absent mirror `tests/panasonic_main_conv.rs`.

#![cfg(all(unix, feature = "exif", feature = "std"))]

use std::{
  path::{Path, PathBuf},
  process::Command,
};

use exifast::exif::ifd::RawValue;
use exifast::exif::makernotes::vendors::panasonic::{PanasonicPrintConv, lookup};
use exifast::value::TagValue;

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

/// One bundled hash entry: `(tag id, branch index, key, label)`.
#[derive(Debug, Clone)]
struct HashEntry {
  id: u16,
  branch: usize,
  key: String,
  label: String,
}

/// Perl-dump every plain discrete-value-HASH `PrintConv` entry of every
/// `%Panasonic::Main` LEAF branch as TAB-separated `0xID<TAB>branch<TAB>key<TAB>label`.
///
/// A branch contributes when its `PrintConv` is a HASH ref and the key is a
/// plain integer or space-joined integer string (`-?\d+( -?\d+)*`); the
/// `OTHER`/`Notes`/`BITMASK` pseudo-keys and any nested-ref value are skipped.
/// Labels never contain a TAB in either bundled module (asserted by the
/// harness), so TAB is an unambiguous field delimiter.
fn dump_bundled_hash_labels(lib: &Path) -> Vec<HashEntry> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my @branches = (ref $info eq 'ARRAY') ? @$info : ($info);
    for my $i (0..$#branches) {
        my $b = $branches[$i];
        next unless ref $b eq 'HASH';
        next if exists $b->{SubDirectory};
        my $pc = $b->{PrintConv};
        next unless ref $pc eq 'HASH';
        for my $k (sort keys %$pc) {
            next if $k =~ /^(OTHER|Notes|BITMASK)$/;
            next unless $k =~ /^-?\d+( -?\d+)*$/;
            my $v = $pc->{$k};
            next if ref $v;
            printf("0x%x\t%d\t%s\t%s\n", $n, $i, $k, $v);
        }
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main hash labels");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main hash labels failed:\nstdout={}\nstderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr),
  );
  let text = String::from_utf8(out.stdout).expect("perl output is UTF-8");
  let mut entries = Vec::new();
  for line in text.lines() {
    if line.is_empty() {
      continue;
    }
    let parts: Vec<&str> = line.split('\t').collect();
    assert_eq!(parts.len(), 4, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[0]));
    let branch: usize = parts[1].parse().expect("branch index");
    entries.push(HashEntry {
      id,
      branch,
      key: parts[2].to_string(),
      label: parts[3].to_string(),
    });
  }
  entries
}

/// Construct the `RawValue` that the conv path receives for a hash key. Every
/// Panasonic key is a single integer or a space-joined integer tuple; the conv
/// helpers (`simple_label` via `first_i64`, `int_pair_label` via
/// `int_vec_joined`) accept a signed `I64` list for both shapes, so a single
/// `RawValue::I64` covers every key (signed keys round-trip; unsigned keys are
/// non-negative and fit `i64`).
fn raw_for_key(key: &str) -> RawValue {
  let ints: Vec<i64> = key
    .split(' ')
    .map(|s| s.parse::<i64>().expect("integer key component"))
    .collect();
  RawValue::I64(ints)
}

/// Multi-branch tags: `(id, branch index) -> the distinct PanasonicPrintConv
/// variant that implements that branch`. The single-branch tags use the tag
/// table's own `conv`; only these conditional-ARRAY tags collapse multiple
/// per-Model hashes onto separate variants, so the oracle must drive each
/// branch against the matching variant (the variant IS the branch — Panasonic
/// selects it by `$$self{Model}` at parse time via
/// `PanasonicPrintConv::contrast_mode_for_model` / the FZ10 AFAreaMode check).
const MULTI_BRANCH: &[(u16, usize, PanasonicPrintConv)] = &[
  // 0xf AFAreaMode (Panasonic.pm:338-376): branch 0 = DMC-FZ10 (spot), branch
  // 1 = all other models (the default `conv`).
  (0x0f, 0, PanasonicPrintConv::AfAreaModeFz10),
  (0x0f, 1, PanasonicPrintConv::AfAreaMode),
  // 0x2c ContrastMode (Panasonic.pm:557-606): branch 0 = default models
  // (PrintHex), branch 1 = DMC-(GF*|G2), branch 2 = DMC-(TZ10|ZS7). Branch 3
  // has no PrintConv (auto-skipped by the dumper).
  (0x2c, 0, PanasonicPrintConv::ContrastMode),
  (0x2c, 1, PanasonicPrintConv::ContrastModeGfG2),
  (0x2c, 2, PanasonicPrintConv::ContrastModeTz10Zs7),
];

/// Resolve the conv variant for `(id, branch)`. Returns `None` only when the id
/// is absent from `PANASONIC_TAGS` (a structural gap caught by the table
/// oracle, reported here too).
fn variant_for(id: u16, branch: usize) -> Option<PanasonicPrintConv> {
  if let Some((_, _, v)) = MULTI_BRANCH
    .iter()
    .find(|(i, b, _)| *i == id && *b == branch)
  {
    return Some(*v);
  }
  // Single-branch tag: the table's own conv. (A multi-branch tag whose extra
  // branch is not in MULTI_BRANCH would fall here and likely mismatch — that
  // is the intended failure, surfacing an unported branch.)
  lookup(id).map(|t| t.conv)
}

#[test]
fn panasonic_main_hash_contents_match_bundled() {
  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); hash-contents oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; hash-contents oracle skipped");
    return;
  }

  let entries = dump_bundled_hash_labels(&lib);
  assert!(
    !entries.is_empty(),
    "perl produced no Panasonic::Main hash-PrintConv entries"
  );

  // TAB delimiter is only valid if no label contains a TAB.
  for e in &entries {
    assert!(
      !e.label.contains('\t'),
      "label for 0x{:x}[{}] key {:?} contains a TAB",
      e.id,
      e.branch,
      e.key,
    );
  }

  let mut mismatches: Vec<String> = Vec::new();
  let mut missing_tag: Vec<String> = Vec::new();
  let mut driven = 0usize;
  for e in &entries {
    let Some(variant) = variant_for(e.id, e.branch) else {
      missing_tag.push(format!(
        "0x{:x}[{}] key {:?} => {:?}: id absent from PANASONIC_TAGS",
        e.id, e.branch, e.key, e.label,
      ));
      continue;
    };
    let raw = raw_for_key(&e.key);
    let got = variant.apply(&raw, true);
    let want = TagValue::Str(e.label.as_str().into());
    driven += 1;
    if got != want {
      mismatches.push(format!(
        "0x{:x}[{}] {:?} key {:?}: Rust rendered {:?} but bundled label is {:?}",
        e.id, e.branch, variant, e.key, got, e.label,
      ));
    }
  }

  assert!(
    missing_tag.is_empty(),
    "{} Panasonic hash entry/-ies reference a tag id absent from \
     PANASONIC_TAGS:\n{}",
    missing_tag.len(),
    missing_tag.join("\n"),
  );
  assert!(
    mismatches.is_empty(),
    "{} Panasonic Main hash key(s) render the WRONG label (fix the Rust \
     PrintConv hash to the bundled value):\n{}",
    mismatches.len(),
    mismatches.join("\n"),
  );

  // Guard against the oracle silently driving nothing.
  assert!(
    driven >= 480,
    "expected to drive >=480 Panasonic hash keys, only drove {driven} — the \
     dump or driver regressed"
  );
  eprintln!("panasonic_main_hash: drove {driven} hash keys, all match bundled");
}
