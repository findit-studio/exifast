// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! SubDirectory-SUPPRESSION oracle for the Panasonic MakerNote Main tag
//! table.
//!
//! `tests/panasonic_main_table.rs` pins the table STRUCTURE and
//! `tests/panasonic_main_conv.rs` pins the LEAF conversions. This
//! complementary oracle pins the SubDirectory EMISSION contract: every
//! bundled `%Image::ExifTool::Panasonic::Main` row that
//!
//!   (a) is a SubDirectory pointer — its representative (first) branch has a
//!       `SubDirectory` key, AND
//!   (b) does NOT emit its own value as a block — it is neither a
//!       `MakerNotes` block nor `Writable`-as-a-block (`Writable` truthy) nor
//!       `BlockExtract`,
//!
//! is DESCENDED-INTO by ExifTool, NOT emitted as a parent value. In
//! `Image::ExifTool::Exif::ProcessExif` the `if ($subdir)` block
//! (`Exif.pm:6919`) processes the child directory (`ProcessDirectory`,
//! `:7091`) and then hits `next unless $doMaker or $$et{REQ_TAG_LOOKUP}{…}
//! or $$tagInfo{BlockExtract}` (`:7103-7104`) — in default `-j` output that
//! `next` skips the parent's `FoundTag` (`:7180`). So the parent Name is
//! ABSENT from default output for every such row (the four are 0x4e
//! FaceDetInfo, 0x61 FaceRecInfo, 0x0e00 PrintIM, 0x2003 TimeInfo).
//!
//! Phase 3 DEFERS the Panasonic sub-table walkers (documented scope), so the
//! faithful behaviour is to emit NEITHER the parent NOR (for now) the
//! children. This oracle drives the public Panasonic parse path with a
//! synthetic body carrying ONE entry per bundled SubDirectory tag id and
//! asserts NONE of those parent Names leak into the emissions.
//!
//! Path resolution + SKIP-if-absent mirror `tests/panasonic_main_table.rs`
//! exactly.

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

/// Run `perl` to dump every Panasonic::Main numeric key whose FIRST branch is
/// a SubDirectory pointer that does NOT block-extract its own parent value.
/// Emits `0xID|Name` per such row. `block_extract` (⇒ EXCLUDED) is true iff
/// the first branch is a `MakerNotes` block, OR is `Writable` with a truthy
/// value (`Exif.pm:7151`), OR sets `BlockExtract` (`Exif.pm:7104`). A
/// `Writable => 0` SubDirectory (e.g. PrintIM) is NOT a block ⇒ suppressed.
fn dump_bundled_subdir_rows(lib: &Path) -> BTreeMap<u16, String> {
  let prog = r#"
use strict; use warnings;
require Image::ExifTool::Panasonic;
no strict 'refs';
my %main = %Image::ExifTool::Panasonic::Main;
for my $n (sort { $a <=> $b } grep { /^\d+$/ } keys %main) {
    my $info = $main{$n};
    my $first = (ref $info eq 'ARRAY') ? $info->[0] : $info;
    next unless ref $first eq 'HASH';
    next unless exists $first->{SubDirectory};
    my $block = ($first->{MakerNotes} ? 1 : 0)
             || ($first->{Writable}   ? 1 : 0)
             || ($first->{BlockExtract} ? 1 : 0);
    next if $block;
    my $name = defined $first->{Name} ? $first->{Name} : '?';
    printf("0x%x|%s\n", $n, $name);
}
"#;
  let out = Command::new("perl")
    .arg(format!("-I{}", lib.display()))
    .arg("-e")
    .arg(prog)
    .output()
    .expect("spawn perl to dump Panasonic::Main SubDirectory rows");
  assert!(
    out.status.success(),
    "perl dump of Panasonic::Main SubDirectory rows failed:\nstdout={}\nstderr={}",
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
    let mut parts = line.splitn(2, '|');
    let id_s = parts.next().expect("id field");
    let name = parts.next().expect("name field").to_string();
    let id = u16::from_str_radix(id_s.trim_start_matches("0x"), 16)
      .unwrap_or_else(|_| panic!("bad id field {id_s:?}"));
    map.insert(id, name);
  }
  map
}

/// Build a self-contained Panasonic body (`Panasonic\0\0\0` header + IFD)
/// carrying ONE `int32u` entry per `id`. The format/value are irrelevant to
/// the suppression decision (purely `sub_table.is_some()`). Entries MUST be
/// tag-id sorted (IFD requirement).
fn build_body_with_ids(ids: &[u16]) -> Vec<u8> {
  let mut sorted = ids.to_vec();
  sorted.sort_unstable();
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"Panasonic\x00\x00\x00"); // 12-byte header
  blob.extend_from_slice(&(sorted.len() as u16).to_le_bytes()); // entry count LE
  for id in sorted {
    blob.extend_from_slice(&id.to_le_bytes()); // tag id
    blob.extend_from_slice(&4u16.to_le_bytes()); // format 4 = int32u
    blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
    blob.extend_from_slice(&1u32.to_le_bytes()); // value 1 inline
  }
  blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD pointer
  blob
}

#[test]
fn panasonic_main_subdir_rows_are_suppressed() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::panasonic;

  let root = env!("CARGO_MANIFEST_DIR");
  let Some(lib) = exiftool_lib_dir(root) else {
    eprintln!(
      "SKIP: bundled ExifTool Panasonic.pm not found (set $EXIFTOOL or add \
       the sibling ../exiftool checkout); subdir-suppression oracle skipped"
    );
    return;
  };
  if !have_perl() {
    eprintln!("SKIP: perl not available; subdir-suppression oracle skipped");
    return;
  }

  let bundled = dump_bundled_subdir_rows(&lib);
  assert!(
    !bundled.is_empty(),
    "perl produced no Panasonic::Main SubDirectory rows"
  );

  // Cross-check the perl dump against the Rust table.
  use exifast::exif::makernotes::vendors::panasonic::PANASONIC_TAGS;
  let rust_subdir: BTreeMap<u16, &str> = PANASONIC_TAGS
    .iter()
    .filter(|t| t.sub_table.is_some())
    .map(|t| (t.id, t.name))
    .collect();
  let mut table_errs: Vec<String> = Vec::new();
  for (id, bname) in &bundled {
    match rust_subdir.get(id) {
      None => table_errs.push(format!(
        "0x{id:x} {bname:?}: bundled SubDirectory row but PANASONIC_TAGS row \
         has sub_table=None (would leak a bogus parent)"
      )),
      Some(rname) if rname != bname => table_errs.push(format!(
        "0x{id:x}: SubDirectory Name mismatch — Rust {rname:?} vs bundled {bname:?}"
      )),
      Some(_) => {}
    }
  }
  for (id, rname) in &rust_subdir {
    if !bundled.contains_key(id) {
      table_errs.push(format!(
        "0x{id:x} {rname:?}: PANASONIC_TAGS sub_table=Some but bundled is not \
         a descend-no-parent SubDirectory row (block-extract or leaf?)"
      ));
    }
  }
  assert!(
    table_errs.is_empty(),
    "PANASONIC_TAGS sub_table flags diverge from bundled SubDirectory rows \
     ({} diffs):\n{}",
    table_errs.len(),
    table_errs.join("\n"),
  );

  // Drive the public Panasonic parse path with a body carrying every bundled
  // SubDirectory tag id, then assert NONE of those parent Names is emitted.
  let ids: Vec<u16> = bundled.keys().copied().collect();
  let blob = build_body_with_ids(&ids);
  for print_conv in [true, false] {
    let (_typed, emissions) =
      panasonic::parse_with_print_conv(&blob, ByteOrder::Little, print_conv);
    let mut leaked: Vec<String> = Vec::new();
    for (id, name) in &bundled {
      if emissions.iter().any(|e| e.name() == name.as_str()) {
        leaked.push(format!("0x{id:x} {name:?} (print_conv={print_conv})"));
      }
    }
    assert!(
      leaked.is_empty(),
      "{} Panasonic SubDirectory parent(s) leaked into emissions (must be \
       suppressed — ExifTool descends, never emits the parent):\n{}",
      leaked.len(),
      leaked.join("\n"),
    );
  }

  // Sanity-pin the count (4 @ 13.59: 0x4e, 0x61, 0x0e00, 0x2003).
  assert_eq!(
    bundled.len(),
    4,
    "bundled Panasonic::Main descend-no-parent SubDirectory count changed \
     (was 4 @ 13.59)"
  );
}
