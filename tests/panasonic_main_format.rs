// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Format-override COMPLETENESS oracle for the Panasonic MakerNote Main tag
//! table (the counterpart of `tests/sony_main_format.rs`).
//!
//! Companion to `tests/panasonic_main_{table,conv,condition,rawconv}.rs`. This
//! oracle pins **`Format`-directive value re-interpretation**: a tag's
//! `Format => '…'` directive in `%Panasonic::Main` OVERRIDES the entry's
//! on-disk TIFF format, so `ProcessExif` re-reads the SAME value bytes with the
//! directive's format and a count recomputed from the on-disk byte size
//! (`Exif.pm:6728-6745`). Many Panasonic rows are `Writable => 'int16u'` but
//! `Format => 'int16s'` — the on-disk UNSIGNED bytes are read SIGNED (e.g.
//! 0x23 WhiteBalanceBias `ff fd` ⇒ int16s -3 ⇒ ValueConv -1, not 65533). The
//! Panasonic body walker
//! ([`walk_panasonic_in_tiff`](exifast::exif::makernotes::vendors::panasonic::walk_panasonic_in_tiff))
//! applies this via the tag def's
//! [`PanasonicTag::format`](exifast::exif::makernotes::vendors::panasonic::PanasonicTag)
//! override; the on-disk format is preserved separately for the `$format`
//! `Condition` gate (0xc4/0xc5/0xe4 — which carry NO Format directive).
//!
//! Every bundled LEAF row that carries a `Format` directive MUST be modelled
//! by a matching [`FormatOverride`] on the Rust def (same format NAME + same
//! `Count`), UNLESS the id is in [`FORMAT_DEFERRALS`] (each with a reason).
//! Staleness is checked BOTH ways.

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

/// One bundled LEAF row carrying a `Format` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledFormat {
  name: String,
  format: String,
  count: Option<usize>,
}

/// Dump every `%Panasonic::Main` LEAF numeric key whose FIRST leaf branch
/// carries a `Format` directive. Emits `0xID|Name|Format|Count`.
fn dump_bundled_formats(lib: &Path) -> BTreeMap<u16, BundledFormat> {
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
        my $fmt = $b->{Format};
        next unless defined $fmt;
        next if ref $fmt;
        my $name  = defined $b->{Name}  ? $b->{Name}  : '?';
        my $count = defined $b->{Count} ? $b->{Count} : '-';
        $count =~ s/\s+//g;
        printf("0x%x|%s|%s|%s\n", $n, $name, $fmt, $count);
        last;
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main Format directives");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main Format directives failed:\nstdout={}\nstderr={}",
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
    let parts: Vec<&str> = line.splitn(4, '|').collect();
    assert_eq!(parts.len(), 4, "bad dump line {line:?}");
    let id = u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {:?}", parts[0]));
    let count = if parts[3] == "-" {
      None
    } else {
      Some(
        parts[3]
          .parse::<usize>()
          .unwrap_or_else(|_| panic!("bad Count {:?}", parts[3])),
      )
    };
    map.insert(
      id,
      BundledFormat {
        name: parts[1].to_string(),
        format: parts[2].to_string(),
        count,
      },
    );
  }
  map
}

/// Bundled Format-directive LEAF rows whose override is deliberately NOT
/// modelled — each with a reason. Currently EMPTY: every `%Panasonic::Main`
/// leaf Format directive is carried on the Rust def.
const FORMAT_DEFERRALS: &[(u16, &str)] = &[];

#[test]
fn panasonic_main_format_overrides_modelled() {
  use exifast::exif::makernotes::vendors::panasonic::PANASONIC_TAGS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); Format-override oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; Format-override oracle skipped");
    return;
  }

  let bundled = dump_bundled_formats(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Panasonic::Main Format-directive rows"
  );

  let rust: BTreeMap<u16, (String, Option<usize>)> = PANASONIC_TAGS
    .iter()
    .filter_map(|t| {
      t.format
        .map(|f| (t.id, (f.format().name().to_string(), f.count())))
    })
    .collect();
  let deferrals: BTreeMap<u16, &str> = FORMAT_DEFERRALS.iter().copied().collect();

  // (1) Every bundled Format-directive LEAF row must be modelled or deferred.
  let mut problems: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    if deferrals.contains_key(id) {
      continue;
    }
    match rust.get(id) {
      None => problems.push(format!(
        "0x{id:x} {} — bundled `Format => '{}'`{} but the Rust def carries NO \
         FormatOverride (add one to PANASONIC_TAGS or list it in \
         FORMAT_DEFERRALS with a reason)",
        b.name,
        b.format,
        b.count
          .map(|c| format!(", Count => {c}"))
          .unwrap_or_default(),
      )),
      Some((fmt, count)) => {
        if fmt != &b.format || count != &b.count {
          problems.push(format!(
            "0x{id:x} {} — bundled `Format => '{}', Count => {:?}` but Rust def \
             has `Format => '{}', Count => {:?}` (MISMATCH)",
            b.name, b.format, b.count, fmt, count,
          ));
        }
      }
    }
  }
  assert!(
    problems.is_empty(),
    "{} Panasonic Main Format-override row(s) not faithfully modelled:\n{}",
    problems.len(),
    problems.join("\n"),
  );

  // (2) Every Rust FormatOverride must correspond to a bundled Format row.
  let mut stale: Vec<String> = Vec::new();
  for id in rust.keys() {
    if !bundled.contains_key(id) {
      stale.push(format!(
        "0x{id:x}: Rust def carries a FormatOverride but bundled has no leaf \
         Format directive there"
      ));
    }
  }
  assert!(
    stale.is_empty(),
    "stale Rust FormatOverride entries:\n{}",
    stale.join("\n"),
  );

  // (3) Every FORMAT_DEFERRALS id must still be a bundled Format row not
  // modelled.
  let modelled: BTreeSet<u16> = rust.keys().copied().collect();
  let mut stale_def: Vec<String> = Vec::new();
  for (id, reason) in FORMAT_DEFERRALS {
    match bundled.get(id) {
      None => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no leaf Format directive there"
      )),
      Some(_) if modelled.contains(id) => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but the id is now modelled — drop it"
      )),
      Some(_) => {}
    }
  }
  assert!(
    stale_def.is_empty(),
    "stale FORMAT_DEFERRALS entries:\n{}",
    stale_def.join("\n"),
  );

  eprintln!(
    "Panasonic::Main Format-directive leaf rows surveyed: {} (all modelled; {} deferred)",
    bundled.len(),
    FORMAT_DEFERRALS.len(),
  );
}
