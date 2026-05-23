// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Faithfulness oracle for the Panasonic MakerNote Main tag table.
//!
//! This test asserts that `PANASONIC_TAGS`
//! (`src/exif/makernotes/vendors/panasonic/tags.rs`) matches the BUNDLED
//! `%Image::ExifTool::Panasonic::Main` hash on EVERY tag ID → Name →
//! `Unknown` flag. The bundled hash is the single source of truth.
//!
//! Rather than hand-roll a brace/quote-aware Perl-hash parser in Rust (the
//! Main hash embeds `{` / `}` inside quoted `Condition` strings, which would
//! defeat a naive scanner), we shell out to `perl` and let ExifTool's own
//! interpreter load the module, then dump one `0xID|Name|Unknown` line per
//! numeric key. Conditional ARRAY entries (`0x0f`, `0x2c`) collapse to the
//! FIRST variant's `Name` (identical across all branches in both cases) with
//! `Unknown` OR-ed across the branches — exactly the collapse the port uses.
//!
//! Path resolution mirrors `tests/harness_golden.rs`: the bundled tree is
//! `$EXIFTOOL`'s parent (or the sibling `../exiftool` checkout). When `perl`
//! or the bundled `lib/Image/ExifTool/Panasonic.pm` is absent (e.g. a clean
//! checkout without the sibling tree, or the Windows CI leg), the test SKIPS
//! gracefully — it never fails merely because the optional Perl toolchain is
//! missing. The in-crate `tags::tests` still pin the row count (136), the
//! single `Unknown` tag (0x63), and the headline corrected mappings without
//! any external dependency.

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
  // Candidate exiftool-script paths, newest-preference first.
  let script = if let Ok(p) = std::env::var("EXIFTOOL") {
    PathBuf::from(p)
  } else {
    Path::new(root).join("../exiftool/exiftool")
  };
  // `<script-dir>/lib` is ExifTool's module root.
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

/// Run `perl` to dump the bundled Main hash as `0xID|Name|Unknown` lines.
fn dump_bundled_main(lib: &Path) -> BTreeMap<u16, (String, bool)> {
  // The Perl program: load the module from the bundled lib, then walk the
  // numeric keys of %Panasonic::Main emitting "0x%x|Name|U".
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my ($name, $unknown) = ('?', 0);
    if (ref $info eq 'ARRAY') {
        # conditional list: primary Name = first variant; Unknown = OR.
        $name = (defined $info->[0]{Name}) ? $info->[0]{Name} : '?';
        for my $v (@$info) { $unknown ||= ($v->{Unknown} ? 1 : 0); }
    } elsif (ref $info eq 'HASH') {
        $name = (defined $info->{Name}) ? $info->{Name} : '?';
        $unknown = $info->{Unknown} ? 1 : 0;
    } else {
        $name = $info;            # 0xNN => 'Name' shorthand
    }
    printf("0x%x|%s|%d\n", $n, $name, $unknown);
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main failed:\nstdout={}\nstderr={}",
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
    let mut parts = line.splitn(3, '|');
    let id_s = parts.next().expect("id field");
    let name = parts.next().expect("name field").to_string();
    let unk = parts.next().expect("unknown field");
    let id = u16::from_str_radix(id_s.trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {id_s:?}"));
    map.insert(id, (name, unk == "1"));
  }
  map
}

#[test]
fn panasonic_main_table_matches_bundled() {
  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); table-diff oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; table-diff oracle skipped");
    return;
  }

  let bundled = dump_bundled_main(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Panasonic::Main entries"
  );

  // Build the Rust-side view: id -> (name, unknown).
  use exifast::exif::makernotes::vendors::panasonic::PANASONIC_TAGS;
  let rust: BTreeMap<u16, (String, bool)> = PANASONIC_TAGS
    .iter()
    .map(|t| (t.id, (t.name.to_string(), t.unknown)))
    .collect();

  let mut errors: Vec<String> = Vec::new();

  // Every bundled ID must be present with the right Name + Unknown.
  for (id, (bname, bunk)) in &bundled {
    match rust.get(id) {
      None => errors.push(format!(
        "0x{id:x}: MISSING from PANASONIC_TAGS (bundled {bname:?})"
      )),
      Some((rname, runk)) => {
        if rname != bname {
          errors.push(format!(
            "0x{id:x}: Name mismatch — Rust {rname:?} vs bundled {bname:?}"
          ));
        }
        if runk != bunk {
          errors.push(format!(
            "0x{id:x}: Unknown mismatch — Rust {runk} vs bundled {bunk}"
          ));
        }
      }
    }
  }
  // No EXTRA Rust IDs that bundled does not have.
  for id in rust.keys() {
    if !bundled.contains_key(id) {
      errors.push(format!(
        "0x{id:x}: EXTRA in PANASONIC_TAGS (not in bundled Panasonic::Main)"
      ));
    }
  }

  assert_eq!(
    bundled.len(),
    rust.len(),
    "row-count mismatch: bundled has {} numeric Main IDs, PANASONIC_TAGS has {}",
    bundled.len(),
    rust.len(),
  );
  assert!(
    errors.is_empty(),
    "PANASONIC_TAGS diverges from bundled %Panasonic::Main ({} diffs):\n{}",
    errors.len(),
    errors.join("\n"),
  );

  // Sanity-pin the headline numbers so a future bundled bump is noticed.
  assert_eq!(
    bundled.len(),
    136,
    "bundled Panasonic::Main numeric-key count changed (was 136 @ 13.59)"
  );
  assert_eq!(
    bundled.values().filter(|(_, u)| *u).count(),
    1,
    "exactly one bundled Main tag is Unknown => 1 (0x63 RecognizedFaceFlags)"
  );
}
