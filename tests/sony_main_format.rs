// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Format-override COMPLETENESS oracle for the Sony MakerNote Main tag table.
//!
//! Companion to `tests/sony_main_{table,conv,condition,rawconv}.rs`. This
//! oracle pins **`Format`-directive value re-interpretation**: in ExifTool a
//! MakerNote entry's value is read with the entry's ON-DISK TIFF format by
//! default, BUT a tag's `Format => '…'` directive in `%Sony::Main` OVERRIDES
//! that — `ProcessExif` re-reads the SAME value bytes with the directive's
//! format and a count recomputed from the on-disk byte size
//! (`Exif.pm:6728-6745`: `$formatStr = $$tagInfo{Format}` and, when the new
//! format number differs from the on-disk one, `$count = int($size /
//! $formatSize[$format])`). The Sony body walk (the shared `Walker`'s Sony
//! capture) applies this via the tag def's
//! [`SonyTag::format`](exifast::exif::makernotes::vendors::sony::SonyTag)
//! override; the on-disk format is preserved separately for the `$format`
//! `Condition` gate.
//!
//! Every bundled LEAF row that carries a `Format` directive MUST be modelled
//! by a matching [`FormatOverride`] on the Rust def (same format NAME + same
//! `Count`), UNLESS the id is in [`FORMAT_DEFERRALS`] (each with a reason).
//! Without this a Format-override row would be silently read with the on-disk
//! format (e.g. Sony `0x200a HDR` → `U64(65537)` instead of `[1,1]`).
//!
//! Staleness is checked BOTH ways. Path resolution + SKIP-if-absent mirror
//! `tests/sony_main_rawconv.rs`.

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

/// One bundled LEAF row carrying a `Format` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledFormat {
  name: String,
  /// The `Format => '…'` string (e.g. "int16u", "int32s", "undef", "string").
  format: String,
  /// The `Count => N` directive, if any (parsed to a number).
  count: Option<usize>,
}

/// Dump every `%Sony::Main` LEAF numeric key whose FIRST leaf branch carries a
/// `Format` directive. Emits `0xID|Name|Format|Count` (Count = "-" if absent).
fn dump_bundled_formats(lib: &Path) -> BTreeMap<u16, BundledFormat> {
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
        next if exists $b->{SubDirectory};   # SubDirectory Format handled elsewhere
        my $fmt = $b->{Format};
        next unless defined $fmt;
        next if ref $fmt;                    # a CODE-ref Format (none in Sony::Main)
        my $name  = defined $b->{Name}  ? $b->{Name}  : '?';
        my $count = defined $b->{Count} ? $b->{Count} : '-';
        $count =~ s/\s+//g;                  # Count may be the string '3'
        printf("0x%x|%s|%s|%s\n", $n, $name, $fmt, $count);
        last;                                # one row per id (first leaf branch)
    }
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Sony::Main Format directives");
  assert!(
    out.status.success(),
    "perl dump of Sony::Main Format directives failed:\nstdout={}\nstderr={}",
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
/// modelled — each with a one-line reason. Currently EMPTY: every
/// `%Sony::Main` leaf Format directive is carried on the Rust def. The oracle
/// keeps it honest as bundled evolves.
const FORMAT_DEFERRALS: &[(u16, &str)] = &[];

#[test]
fn sony_main_format_overrides_modelled() {
  use exifast::exif::makernotes::vendors::sony::SONY_TAGS;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Sony.pm not found (set $EXIFTOOL or add the \
       sibling ../exiftool checkout); Format-override oracle skipped"
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
    "perl produced no Sony::Main Format-directive rows"
  );

  // The Rust override per id (format NAME + Count) from the tag table.
  let rust: BTreeMap<u16, (String, Option<usize>)> = SONY_TAGS
    .iter()
    .filter_map(|t| {
      t.format
        .map(|f| (t.id, (f.format().name().to_string(), f.count())))
    })
    .collect();
  let deferrals: BTreeMap<u16, &str> = FORMAT_DEFERRALS.iter().copied().collect();

  // (1) Every bundled Format-directive LEAF row must be modelled (matching
  // format NAME + Count) or deferred.
  let mut problems: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    if deferrals.contains_key(id) {
      continue;
    }
    match rust.get(id) {
      None => problems.push(format!(
        "0x{id:x} {} — bundled `Format => '{}'`{} but the Rust def carries NO \
         FormatOverride (add one to SONY_TAGS or list it in FORMAT_DEFERRALS \
         with a reason)",
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
    "{} Sony Main Format-override row(s) not faithfully modelled:\n{}",
    problems.len(),
    problems.join("\n"),
  );

  // (2) Every Rust FormatOverride must correspond to a bundled Format-directive
  // LEAF row — otherwise the Rust table has gone stale.
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

  // (3) Every FORMAT_DEFERRALS id must still be a bundled Format-directive LEAF
  // that is NOT modelled — otherwise the allow-list has gone stale.
  let modelled: BTreeSet<u16> = rust.keys().copied().collect();
  let mut stale_def: Vec<String> = Vec::new();
  for (id, reason) in FORMAT_DEFERRALS {
    match bundled.get(id) {
      None => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no leaf Format directive there"
      )),
      Some(_) if modelled.contains(id) => stale_def.push(format!(
        "0x{id:x}: deferral {reason:?} but the id is now modelled — drop it from \
         FORMAT_DEFERRALS"
      )),
      Some(_) => {}
    }
  }
  assert!(
    stale_def.is_empty(),
    "stale FORMAT_DEFERRALS entries:\n{}",
    stale_def.join("\n"),
  );

  // Report the surveyed count (visible with `--nocapture`).
  eprintln!(
    "Sony::Main Format-directive leaf rows surveyed: {} (all modelled; {} deferred)",
    bundled.len(),
    FORMAT_DEFERRALS.len(),
  );
}
