// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Conversion-COMPLETENESS oracle for the Panasonic MakerNote Main tag
//! table (the counterpart of `tests/sony_main_conv.rs`).
//!
//! `tests/panasonic_main_table.rs` pins the table STRUCTURE (id → Name →
//! Unknown). This oracle pins the CONVERSIONS: every bundled
//! `%Image::ExifTool::Panasonic::Main` row that
//!
//!   (a) is a LEAF — its representative (first) branch is NOT a
//!       `SubDirectory`, AND
//!   (b) has a `PrintConv` OR `ValueConv` OR `RawConv` on that first branch
//!
//! MUST be wired to a non-[`PanasonicPrintConv::None`] `conv` in
//! [`PANASONIC_TAGS`](exifast::exif::makernotes::vendors::panasonic::PANASONIC_TAGS)
//! — UNLESS the id is in the explicit [`ACCEPTED_DEFERRALS`] allow-list.
//! Without this a leaf row that bundled converts silently emits the raw
//! scalar in `-j`/`-n`.
//!
//! Path resolution + SKIP-if-absent mirror `tests/panasonic_main_table.rs`.

#![cfg(all(unix, feature = "exif", feature = "std"))]

use std::{
  collections::BTreeMap,
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

/// One bundled leaf-with-conv row: the conversion kinds on the FIRST branch.
#[derive(Debug, Default)]
struct BundledConv {
  name: String,
  print_conv: bool,
  value_conv: bool,
  raw_conv: bool,
}

/// Run `perl` to dump every Panasonic::Main numeric key whose FIRST branch is
/// a LEAF (no SubDirectory) carrying a PrintConv/ValueConv/RawConv. Emits
/// `0xID|Name|P|V|R`.
fn dump_bundled_leaf_convs(lib: &Path) -> BTreeMap<u16, BundledConv> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my $first = (ref $info eq 'ARRAY') ? $info->[0] : $info;
    next unless ref $first eq 'HASH';
    next if exists $first->{SubDirectory};
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
    .expect("spawn perl to dump Panasonic::Main leaf convs");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main leaf convs failed:\nstdout={}\nstderr={}",
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
/// `PanasonicPrintConv::None` ONLY for these ids.
const ACCEPTED_DEFERRALS: &[(u16, &str)] = &[
  // 0x4d AFPointPosition and 0xde AFAreaSize are now IMPLEMENTED
  // (`PanasonicPrintConv::AfPointPosition` / `AfAreaSize`): the rational64u[2]
  // pair renders to a space-joined DECIMAL ValueConv string (the `-n` output)
  // and the PrintConv maps the `16777216 16777216`/`4194303.9…` sentinels +
  // `%.2g`-formats the pair. They were removed from this allow-list; the
  // completeness test now requires their real convs.
  //
  // 0xa1 FilterEffect / 0xbf PostFocusMerging are now IMPLEMENTED
  // (`PanasonicPrintConv::FilterEffect` / `PostFocusMerging`): both carry
  // `Format => 'int32u'`, which the body walker already applies (the modelled
  // `FormatOverride`), so the value IS the int32u[2] pair the plain-hash
  // PrintConv keys on (`"0 1" => 'Expressive'`, `"0 0" => 'Post Focus …'`).
  // The earlier "the body reads the ON-DISK rational64u" reason was wrong —
  // the Format reinterpret is modelled. Removed from this allow-list.
  //
  // 0xaf TimeStamp (Panasonic.pm:1335-1342) is now IMPLEMENTED
  // (`PanasonicPrintConv::TimeStamp`): `PrintConv =>
  // '$self->ConvertDateTime($val)'` routed through the shared
  // `crate::datetime::convert_datetime` port. Under ExifTool's DEFAULT options
  // (no `DateFormat`/`GlobalTimeShift`) ConvertDateTime returns the input
  // unchanged (`ExifTool.pm:6574`), so this is value-identical to bundled; the
  // `DateFormat` reformatting is deferred there per spec §5. Removed here.
  //
  // 0xc5/0xe4 LensTypeModel (Panasonic.pm:1417-1428, 1461-1472) are now
  // IMPLEMENTED — `PanasonicPrintConv::LensTypeModel` does the RawConv
  // undef-drop (zero ⇒ absent) + byte-swap ValueConv (0x1234 → "34 12"). Only
  // the separate Olympus-Composite-LensID tag (which combines this with
  // LensTypeMake) remains deferred. They were removed from this allow-list;
  // the completeness test now requires their real convs.
  //
  // 0xd1 ISO (Panasonic.pm:1429-1433): RawConv-ONLY (`$val > 0xfffffff0 ?
  // undef : $val`) — it does not transform any real ISO value (the output
  // equals the raw int, which `None` already produces); it only SUPPRESSES
  // the >0xfffffff0 sentinel (undef→tag dropped), which needs the engine's
  // undef-drop. Deferred rather than mis-implemented as a no-op conv.
  (
    0xd1,
    "ISO RawConv only suppresses >0xfffffff0 sentinel (undef-drop, deferred)",
  ),
];

#[test]
fn panasonic_main_leaf_conversions_complete() {
  use exifast::exif::makernotes::vendors::panasonic::{PANASONIC_TAGS, PanasonicPrintConv};

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); conv-completeness oracle skipped"
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
    "perl produced no Panasonic::Main leaf-with-conv rows"
  );

  let rust: BTreeMap<u16, PanasonicPrintConv> =
    PANASONIC_TAGS.iter().map(|t| (t.id, t.conv)).collect();
  let deferrals: BTreeMap<u16, &str> = ACCEPTED_DEFERRALS.iter().copied().collect();

  let mut missing: Vec<String> = Vec::new();
  for (id, b) in &bundled {
    let conv = rust.get(id).copied().unwrap_or(PanasonicPrintConv::None);
    if conv != PanasonicPrintConv::None {
      continue;
    }
    if deferrals.contains_key(id) {
      continue;
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
      "0x{id:x} {} — bundled has {} but PANASONIC_TAGS conv is None (not in \
       ACCEPTED_DEFERRALS)",
      b.name,
      kinds.join("+"),
    ));
  }

  assert!(
    missing.is_empty(),
    "{} Panasonic Main leaf row(s) have a bundled conv but are wired to \
     PanasonicPrintConv::None (implement the conv or add to \
     ACCEPTED_DEFERRALS with a reason):\n{}",
    missing.len(),
    missing.join("\n"),
  );

  // ACCEPTED_DEFERRALS must stay honest: each id is a bundled leaf-with-conv
  // row that is still None.
  let mut stale: Vec<String> = Vec::new();
  for (id, reason) in ACCEPTED_DEFERRALS {
    if !bundled.contains_key(id) {
      stale.push(format!(
        "0x{id:x}: deferral {reason:?} but bundled has no leaf conv there"
      ));
      continue;
    }
    if rust.get(id).copied().unwrap_or(PanasonicPrintConv::None) != PanasonicPrintConv::None {
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
