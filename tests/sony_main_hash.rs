// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Hash-CONTENTS oracle for the Sony MakerNote Main tag table — the
//! counterpart of `tests/panasonic_main_hash.rs`.
//!
//! `tests/sony_main_conv.rs` checks conversion PRESENCE (every bundled leaf
//! row that converts is wired to a non-`None` conv). It is blind to a
//! MIS-TRANSCRIBED hash: a `PrintConv` whose keys map to the WRONG labels still
//! passes presence (the same class as the Panasonic 0xa1 FilterEffect
//! scramble).
//!
//! This oracle closes that class for Sony. For EVERY bundled
//! `%Image::ExifTool::Sony::Main` LEAF branch whose `PrintConv` is a plain
//! discrete-INTEGER-keyed HASH (perl-dumped key → label, including the
//! space-joined-integer tuple keys), it DRIVES the real Rust conversion path
//! over EVERY bundled key and asserts the rendered [`TagValue`] equals the
//! bundled label verbatim — proving full hash-CONTENTS fidelity, not just
//! presence.
//!
//! ## Coverage and documented skips
//!
//! The Sony Main hashes are mostly integer- (and space-joined-integer-) keyed
//! and are driven END-TO-END, including the multi-branch Model/DataMember
//! conditional-ARRAY tags 0x201c AFAreaModeSetting (3 branches) and 0x201e
//! AFPointSelected (5 branches, one with a `$val-1` ValueConv), each branch
//! driven through [`SonyPrintConv::apply_with_context`] with a representative
//! `$$self{Model}` + `AFAreaILCx` DataMember that selects exactly that branch
//! (see [`MULTI_BRANCH`]). 0xb043 AFAreaMode's first branch is driven via the
//! table conv; its second branch (gated on the `TagB042` DataMember that only
//! the deferred 0x3000 ShotInfo sub-table sets — see
//! `tests/sony_main_condition.rs`) is a documented skip.
//!
//! The perl dumper emits, per (id, branch), the count and reason of keys it
//! could NOT drive from a bare raw value (so the test REPORTS them, never
//! hides them):
//!
//!   - **BITMASK** branches (0x2020 AFPointsUsed, 0x2022 FocalPlaneAFPointsUsed)
//!     — these render via DecodeBits, not a flat hash; their bit-table contents
//!     are covered by the dedicated `tests/sony_main_*` AF tests.
//!   - **non-integer keys** — string keys (0xb020 CreativeStyle's English
//!     codes) and the fractional lens-variant keys of 0xb027 LensType — which
//!     are produced by an upstream ValueConv / string raw value and cannot be
//!     hit from a bare integer raw value through `apply`. The INTEGER keys of
//!     those same tags ARE driven.
//!
//! 0x200a HDR's positional `PrintConv => [ {..}, {..} ]` is an ARRAY (not a
//! HASH) ref, so the dumper never emits it; its two position hashes are pinned
//! by the unit tests in the Sony printconv module.
//!
//! Path resolution + SKIP-if-absent mirror `tests/sony_main_conv.rs`.

#![cfg(all(unix, feature = "exif", feature = "std"))]

use std::{
  collections::BTreeMap,
  path::{Path, PathBuf},
  process::Command,
};

use exifast::exif::ifd::RawValue;
use exifast::exif::makernotes::vendors::sony::{SonyPrintConv, lookup};
use exifast::value::TagValue;

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

/// One drivable bundled hash entry: `(tag id, branch index, key, label)`.
#[derive(Debug, Clone)]
struct HashEntry {
  id: u16,
  branch: usize,
  key: String,
  label: String,
}

/// One reported skip: `(tag id, branch index, reason, count)`.
#[derive(Debug, Clone)]
struct SkipEntry {
  id: u16,
  branch: usize,
  reason: String,
  count: usize,
}

/// Perl-dump every `%Sony::Main` LEAF branch's hash `PrintConv`. TAB-separated
/// records, first field a tag:
///   `K<TAB>0xID<TAB>branch<TAB>key<TAB>label` — a drivable integer/space-int key.
///   `S<TAB>0xID<TAB>branch<TAB>reason<TAB>count` — keys skipped (BITMASK, or
///     non-integer ValueConv-produced keys), reported by the harness.
fn dump_bundled_hash(lib: &Path) -> (Vec<HashEntry>, Vec<SkipEntry>) {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Sony;
no strict 'refs';
my %main = %Image::ExifTool::Sony::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my @branches = (ref $info eq 'ARRAY') ? @$info : ($info);
    for my $i (0..$#branches) {
        my $b = $branches[$i];
        next unless ref $b eq 'HASH';
        next if exists $b->{SubDirectory};
        my $pc = $b->{PrintConv};
        next unless ref $pc eq 'HASH';
        if (exists $pc->{BITMASK}) {
            printf("S\t0x%x\t%d\tBITMASK (DecodeBits, not a flat hash)\t1\n", $n, $i);
            next;
        }
        my $nonint = 0;
        for my $k (sort keys %$pc) {
            next if $k =~ /^(OTHER|Notes|BITMASK)$/;
            my $v = $pc->{$k};
            next if ref $v;
            if ($k =~ /^-?\d+( -?\d+)*$/) {
                printf("K\t0x%x\t%d\t%s\t%s\n", $n, $i, $k, $v);
            } else {
                $nonint++;
            }
        }
        if ($nonint) {
            printf("S\t0x%x\t%d\tnon-integer key (ValueConv/string-keyed)\t%d\n", $n, $i, $nonint);
        }
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Sony::Main hash");
  assert!(
    out.status.success(),
    "perl dump of Sony::Main hash failed:\nstdout={}\nstderr={}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr),
  );
  let text = String::from_utf8(out.stdout).expect("perl output is UTF-8");
  let mut entries = Vec::new();
  let mut skips = Vec::new();
  for line in text.lines() {
    if line.is_empty() {
      continue;
    }
    let parts: Vec<&str> = line.split('\t').collect();
    assert_eq!(parts.len(), 5, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[1].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[1]));
    let branch: usize = parts[2].parse().expect("branch index");
    match parts[0] {
      "K" => entries.push(HashEntry {
        id,
        branch,
        key: parts[3].to_string(),
        label: parts[4].to_string(),
      }),
      "S" => skips.push(SkipEntry {
        id,
        branch,
        reason: parts[3].to_string(),
        count: parts[4].parse().expect("skip count"),
      }),
      other => panic!("bad record tag {other:?} in line {line:?}"),
    }
  }
  (entries, skips)
}

/// How to drive a multi-branch conditional-ARRAY tag's branch: the
/// representative `$$self{Model}` and `AFAreaILCx` DataMember that select
/// exactly this `Condition` branch, plus a `key_offset` added to the bundled
/// key to recover the raw value when the branch carries a `ValueConv`.
#[derive(Clone, Copy)]
struct BranchCtx {
  model: &'static str,
  af_area: Option<i64>,
  /// raw = bundled_key + key_offset (the inverse of the branch's ValueConv).
  key_offset: i64,
}

/// Multi-branch conditional-ARRAY tags driven through `apply_with_context`:
/// `(id, branch index) -> BranchCtx`. The representative Model/DataMember is
/// chosen to satisfy the bundled branch `Condition` (`Sony.pm` line ranges in
/// the [`SonyPrintConv`] variant docs):
///
/// - 0x201c AFAreaModeSetting: [0] SLT/HV, [1] NEX/ILCE/…, [2] ILCA.
/// - 0x201e AFPointSelected: [0] SLT/HV (or ILCE+AFAreaILCE==4), [1] ILCA-68/77M2
///   with AFAreaILCA!=8 (`ValueConv => '$val - 1'` ⇒ key_offset +1), [2]
///   ILCA-99M2 with AFAreaILCA!=8, [3] ILCA with AFAreaILCA==8 (Zone), [4]
///   NEX/ILCE/ZV/DSC-RX (Zone).
const MULTI_BRANCH: &[(u16, usize, BranchCtx)] = &[
  (
    0x201c,
    0,
    BranchCtx {
      model: "SLT-A99",
      af_area: None,
      key_offset: 0,
    },
  ),
  (
    0x201c,
    1,
    BranchCtx {
      model: "NEX-5",
      af_area: None,
      key_offset: 0,
    },
  ),
  (
    0x201c,
    2,
    BranchCtx {
      model: "ILCA-77M2",
      af_area: None,
      key_offset: 0,
    },
  ),
  (
    0x201e,
    0,
    BranchCtx {
      model: "SLT-A99",
      af_area: None,
      key_offset: 0,
    },
  ),
  (
    0x201e,
    1,
    BranchCtx {
      model: "ILCA-77M2",
      af_area: Some(0),
      key_offset: 1,
    },
  ),
  (
    0x201e,
    2,
    BranchCtx {
      model: "ILCA-99M2",
      af_area: Some(0),
      key_offset: 0,
    },
  ),
  (
    0x201e,
    3,
    BranchCtx {
      model: "ILCA-77M2",
      af_area: Some(8),
      key_offset: 0,
    },
  ),
  (
    0x201e,
    4,
    BranchCtx {
      model: "NEX-5",
      af_area: None,
      key_offset: 0,
    },
  ),
];

/// Branches the oracle intentionally does NOT drive end-to-end, with a reason.
/// Each `(id, branch)` here must be a bundled hash branch (kept honest by the
/// test) that is genuinely not reachable from a bare raw value through the
/// modelled conv path.
const SKIPPED_BRANCHES: &[(u16, usize, &str)] = &[
  // 0xb043 AFAreaMode branch 1 (Sony.pm:2518-2532) is gated by the `TagB042`
  // DataMember that only the DEFERRED 0x3000 ShotInfo sub-table sets; the
  // ported conv models only branch 0. Documented in tests/sony_main_condition.rs.
  (
    0xb043,
    1,
    "branch gated by TagB042 DataMember (deferred 0x3000 ShotInfo)",
  ),
];

fn parse_ints(key: &str, offset: i64) -> Vec<i64> {
  key
    .split(' ')
    .map(|s| s.parse::<i64>().expect("integer key component") + offset)
    .collect()
}

/// Drive one bundled key through the real conv path and return the rendered
/// value. `None` means the branch is in [`SKIPPED_BRANCHES`] (not driven).
fn drive(id: u16, branch: usize, key: &str, conv: SonyPrintConv) -> Option<TagValue> {
  if SKIPPED_BRANCHES
    .iter()
    .any(|(i, b, _)| *i == id && *b == branch)
  {
    return None;
  }
  if let Some((_, _, ctx)) = MULTI_BRANCH
    .iter()
    .find(|(i, b, _)| *i == id && *b == branch)
  {
    let raw = RawValue::I64(parse_ints(key, ctx.key_offset));
    // A matched branch always returns Some; the no-match `None` cannot occur
    // because BranchCtx is chosen to satisfy the branch Condition.
    return Some(
      conv
        .apply_with_context(&raw, true, Some(ctx.model), ctx.af_area)
        .expect("BranchCtx must select a matching branch"),
    );
  }
  let raw = RawValue::I64(parse_ints(key, 0));
  Some(conv.apply(&raw, true))
}

#[test]
fn sony_main_hash_contents_match_bundled() {
  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Sony.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); hash-contents oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; hash-contents oracle skipped");
    return;
  }

  let (entries, skips) = dump_bundled_hash(&lib);
  assert!(
    !entries.is_empty(),
    "perl produced no Sony::Main hash-PrintConv entries"
  );

  // TAB delimiter is only valid if no driven label contains a TAB.
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
    let Some(tag) = lookup(e.id) else {
      missing_tag.push(format!(
        "0x{:x}[{}] key {:?} => {:?}: id absent from SONY_TAGS",
        e.id, e.branch, e.key, e.label,
      ));
      continue;
    };
    let Some(got) = drive(e.id, e.branch, &e.key, tag.conv) else {
      continue; // documented SKIPPED_BRANCHES
    };
    driven += 1;
    let want = TagValue::Str(e.label.as_str().into());
    if got != want {
      mismatches.push(format!(
        "0x{:x}[{}] {:?} key {:?}: Rust rendered {:?} but bundled label is {:?}",
        e.id, e.branch, tag.conv, e.key, got, e.label,
      ));
    }
  }

  assert!(
    missing_tag.is_empty(),
    "{} Sony hash entry/-ies reference a tag id absent from SONY_TAGS:\n{}",
    missing_tag.len(),
    missing_tag.join("\n"),
  );
  assert!(
    mismatches.is_empty(),
    "{} Sony Main hash key(s) render the WRONG label (fix the Rust PrintConv \
     hash to the bundled value):\n{}",
    mismatches.len(),
    mismatches.join("\n"),
  );

  // SKIPPED_BRANCHES must stay honest: each must be a bundled hash branch.
  let branch_ids: BTreeMap<(u16, usize), ()> =
    entries.iter().map(|e| ((e.id, e.branch), ())).collect();
  let skip_branch_ids: BTreeMap<(u16, usize), ()> =
    skips.iter().map(|s| ((s.id, s.branch), ())).collect();
  let mut stale: Vec<String> = Vec::new();
  for (id, branch, reason) in SKIPPED_BRANCHES {
    if !branch_ids.contains_key(&(*id, *branch)) && !skip_branch_ids.contains_key(&(*id, *branch)) {
      stale.push(format!(
        "0x{id:x}[{branch}]: skip {reason:?} but bundled has no such hash branch"
      ));
    }
  }
  assert!(
    stale.is_empty(),
    "stale SKIPPED_BRANCHES:\n{}",
    stale.join("\n")
  );

  // Report coverage so the run is auditable.
  let skipped_keys: usize = skips.iter().map(|s| s.count).sum();
  eprintln!(
    "sony_main_hash: drove {driven} integer hash keys (all match bundled); \
     reported skips: {} branch(es), ~{skipped_keys} key(s):",
    skips.len(),
  );
  for s in &skips {
    eprintln!(
      "  - 0x{:x}[{}] {} ({} key(s))",
      s.id, s.branch, s.reason, s.count
    );
  }
  for (id, branch, reason) in SKIPPED_BRANCHES {
    eprintln!("  - 0x{id:x}[{branch}] {reason} (not driven)");
  }

  assert!(
    driven >= 700,
    "expected to drive >=700 Sony hash keys, only drove {driven} — the dump \
     or driver regressed"
  );
}
