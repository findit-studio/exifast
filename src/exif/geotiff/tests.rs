// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for `ProcessGeoTiff` (`GeoTiff.pm:2133-2221`) — the GeoKey
//! directory decoder. The conformance suite (`tests/conformance.rs`) pins the
//! end-to-end byte-exact output against bundled ExifTool 13.59 for three TIFF
//! fixtures; these tests exercise the algorithm's branches in isolation (the
//! loc dispatch, the per-field bounds warnings, the `|` strip, the structural
//! guard, the raw-int PrintConv fallback, the table integrity).

use super::*;
use crate::emit::{ConvMode, EmitOptions, Taggable};
use crate::exif::ifd::ByteOrder;

/// Little-endian `int16u` array → bytes.
fn le16(words: &[u16]) -> Vec<u8> {
  let mut v = Vec::new();
  for &w in words {
    v.extend_from_slice(&w.to_le_bytes());
  }
  v
}

/// Little-endian `double` array → bytes.
fn le64(vals: &[f64]) -> Vec<u8> {
  let mut v = Vec::new();
  for &x in vals {
    v.extend_from_slice(&x.to_le_bytes());
  }
  v
}

/// Collect a [`GeoTiffMeta`]'s emitted `(name, value-string)` pairs for a mode.
fn emit_pairs(meta: &GeoTiffMeta, print_conv: bool) -> Vec<(String, String)> {
  let opts = EmitOptions::g1(
    if print_conv {
      ConvMode::PrintConv
    } else {
      ConvMode::ValueConv
    },
    false,
  );
  meta
    .tags(opts)
    .map(|t| {
      let tag = t.tag();
      let val = match tag.value_ref() {
        crate::value::TagValue::Str(s) => s.to_string(),
        crate::value::TagValue::U64(n) => n.to_string(),
        crate::value::TagValue::I64(n) => n.to_string(),
        crate::value::TagValue::F64(f) => f.to_string(),
        other => std::format!("{other:?}"),
      };
      (tag.name().to_string(), val)
    })
    .collect()
}

/// The `GEO_KEYS` table is sorted by id (a `binary_search` precondition) and
/// every key's PrintConv slice is sorted by key.
#[test]
fn tables_are_sorted() {
  let mut prev = 0u16;
  for (i, k) in tables::GEO_KEYS.iter().enumerate() {
    if i > 0 {
      assert!(k.id > prev, "GEO_KEYS not sorted at id {}", k.id);
    }
    prev = k.id;
    if let Some(slice) = k.print_conv {
      let mut pk = i64::MIN;
      for &(key, _) in slice {
        assert!(key > pk, "PrintConv for {} not sorted at {key}", k.name);
        pk = key;
      }
    }
  }
}

/// The shared `%epsg_units` / `%epsg_vertcs` slices resolve their referencing
/// keys, and the giant tables carry their proof values.
#[test]
fn table_lookups() {
  // ProjectedCSType 32617 → "WGS84 UTM zone 17N" (the giant ~993-row table).
  let pcs = lookup(3072).expect("ProjectedCSType");
  let slice = pcs.print_conv.expect("ProjectedCSType PrintConv");
  let idx = slice
    .binary_search_by_key(&32617i64, |&(k, _)| k)
    .expect("32617 present");
  assert_eq!(slice.get(idx).map(|&(_, l)| l), Some("WGS84 UTM zone 17N"));
  // Projection 16017 → "UTM zone 17N" (the 428-row table).
  let proj = lookup(3074).expect("Projection");
  let pslice = proj.print_conv.expect("Projection PrintConv");
  let pi = pslice
    .binary_search_by_key(&16017i64, |&(k, _)| k)
    .expect("16017 present");
  assert_eq!(pslice.get(pi).map(|&(_, l)| l), Some("UTM zone 17N"));
  // GeogLinearUnits (2052) references the shared epsg_units table.
  let glu = lookup(2052).expect("GeogLinearUnits");
  assert!(std::ptr::eq(
    glu.print_conv.expect("ref").as_ptr(),
    tables::EPSG_UNITS.as_ptr()
  ));
}

/// A directory with all three `loc` source kinds: an inline int16u GeoKey
/// (loc=0), an ASCII string key (loc=0x87b1), and a double key (loc=0x87b0).
/// The synthetic `GeoTiffVersion` leads; the `|` terminator is stripped.
#[test]
fn all_three_loc_paths() {
  // version 1.1.0, 3 entries.
  let dir = le16(&[
    1, 1, 0, 3, // header
    1024, 0, 1, 1, // GTModelType = Projected (inline)
    2049, 0x87b1, 6, 0, // GeogCitation from ascii @0, count 6
    2057, 0x87b0, 1, 0, // GeogSemiMajorAxis from double @0
  ]);
  let ascii = b"WGS 84|".to_vec();
  let double = le64(&[6378137.0]);
  let meta =
    process(&dir, Some(&double), Some(&ascii), ByteOrder::Little).expect("GeoTiff present");
  assert!(meta.warnings().is_empty());

  let pc = emit_pairs(&meta, true);
  assert_eq!(
    pc,
    vec![
      ("GeoTiffVersion".to_string(), "1.1.0".to_string()),
      ("GTModelType".to_string(), "Projected".to_string()),
      ("GeogCitation".to_string(), "WGS 84".to_string()), // '|' stripped
      ("GeogSemiMajorAxis".to_string(), "6378137".to_string()),
    ]
  );
  // `-n`: the PrintConv key emits the RAW int; the string + double unchanged.
  let n = emit_pairs(&meta, false);
  assert_eq!(n[1], ("GTModelType".to_string(), "1".to_string()));
}

/// `GeoAsciiParams` reaches the value via `ReadValue(.., 'string', ..)`, whose
/// no-readValueProc `string` branch truncates at the FIRST NUL (`$vals[0] =~
/// s/\0.*//s`, `ExifTool.pm:6301`) BEFORE `ProcessGeoTiff` strips the one
/// trailing terminator (`s/(\0|\|)$//`, `GeoTiff.pm:2196`). So an interior NUL
/// terminates the string (the bytes after it — incl. a trailing `|` — are gone),
/// while an interior `|` survives. Ground-truthed vs bundled ExifTool 13.59:
///   `"ABC\0JUNK|"` → `"ABC"`, `"ABC\0"` → `"ABC"`, `"AB|CD\0EF|"` → `"AB|CD"`.
#[test]
fn ascii_params_truncate_at_first_nul_then_strip() {
  // A single GeoKey (GeogCitation 2049) reading the WHOLE ascii blob.
  let cases: &[(&[u8], &str)] = &[
    // Interior NUL terminates; the embedded-NUL suffix (incl the trailing '|')
    // is dropped — NOT the OLD lossy-whole-slice + one-char strip.
    (b"ABC\0JUNK|", "ABC"),
    // Interior NUL with no later '|'.
    (b"ABC\0", "ABC"),
    // Plain trailing '|' strip (no NUL) — the common GeoTiff terminator.
    (b"WGS 84|", "WGS 84"),
    // An INTERIOR '|' survives; only the TRAILING terminator is stripped, and
    // the first NUL truncates before any trailing '|' is considered.
    (b"AB|CD\0EF|", "AB|CD"),
    // No NUL, no trailing terminator — verbatim.
    (b"ABC", "ABC"),
  ];
  for &(blob, want) in cases {
    let dir = le16(&[1, 0, 0, 1, 2049, 0x87b1, blob.len() as u16, 0]);
    let meta = process(&dir, None, Some(blob), ByteOrder::Little).expect("present");
    assert!(meta.warnings().is_empty(), "blob {blob:?}");
    let pc = emit_pairs(&meta, true);
    // [0] is the synthetic GeoTiffVersion; [1] is the GeogCitation string.
    assert_eq!(
      pc.get(1),
      Some(&("GeogCitation".to_string(), want.to_string())),
      "blob {blob:?}"
    );
  }
}

/// A PrintConv MISS renders the RAW int (the HASH-PrintConv miss with no
/// `OTHER`/`BITMASK`, `ExifTool.pm:3614-3634`) in BOTH modes.
#[test]
fn printconv_miss_is_raw_int() {
  // GTModelType (1024) with an out-of-table value 9999.
  let dir = le16(&[1, 0, 0, 1, 1024, 0, 1, 9999]);
  let meta = process(&dir, None, None, ByteOrder::Little).expect("present");
  let pc = emit_pairs(&meta, true);
  assert_eq!(pc[1], ("GTModelType".to_string(), "9999".to_string()));
}

/// `loc` not in `%geoTiffFormat` → 'Unknown GeoTiff location (N) for Name'
/// (`GeoTiff.pm:2174`) + the key is skipped.
#[test]
fn unknown_location_warns_and_skips() {
  let dir = le16(&[1, 0, 0, 1, 1024, 0x9999, 1, 0]);
  let meta = process(&dir, None, None, ByteOrder::Little).expect("present");
  assert_eq!(
    meta.warnings(),
    &[GeoTiffWarning::UnknownLocation {
      loc: 0x9999,
      name: "GTModelType",
    }]
  );
  // Only GeoTiffVersion was emitted (the unknown-loc key skipped).
  assert_eq!(emit_pairs(&meta, true).len(), 1);
}

/// An absent / too-short params blob → 'Missing FORMAT data for Name'
/// (`GeoTiff.pm:2189`) per-field (the per-field availability check), and the
/// rest of the directory still decodes.
#[test]
fn missing_data_warns_per_field() {
  // Two double keys; the double blob holds only ONE value, so the second
  // (offset 1) is out of range.
  let dir = le16(&[
    1, 0, 0, 2, // 2 entries
    2057, 0x87b0, 1, 0, // GeogSemiMajorAxis @0 — OK
    2058, 0x87b0, 1, 1, // GeogSemiMinorAxis @1 — out of range
  ]);
  let double = le64(&[6378137.0]); // only 1 double
  let meta = process(&dir, Some(&double), None, ByteOrder::Little).expect("present");
  assert_eq!(
    meta.warnings(),
    &[GeoTiffWarning::MissingData {
      format: "double",
      name: "GeogSemiMinorAxis",
    }]
  );
  // GeoTiffVersion + the first (in-range) double key decoded.
  let pc = emit_pairs(&meta, true);
  assert_eq!(pc.len(), 2);
  assert_eq!(pc[1].0, "GeogSemiMajorAxis");
}

/// An entirely absent double/ascii blob also warns 'Missing FORMAT data'.
#[test]
fn missing_blob_warns() {
  let dir = le16(&[1, 0, 0, 1, 2057, 0x87b0, 1, 0]); // double key, no blob
  let meta = process(&dir, None, None, ByteOrder::Little).expect("present");
  assert_eq!(
    meta.warnings(),
    &[GeoTiffWarning::MissingData {
      format: "double",
      name: "GeogSemiMajorAxis",
    }]
  );
}

/// `length < 8` or `length < 8*(numEntries+1)` → 'Bad GeoTIFF directory'
/// (`GeoTiff.pm:2213`) and NO keys.
#[test]
fn bad_directory_warns() {
  // Header claims 5 entries but the buffer holds only the header.
  let dir = le16(&[1, 0, 0, 5]);
  let meta = process(&dir, None, None, ByteOrder::Little).expect("present");
  assert_eq!(meta.warnings(), &[GeoTiffWarning::BadDirectory]);
  assert_eq!(emit_pairs(&meta, true).len(), 0);
}

/// An empty captured directory ⇒ `None` (the `GetValue(...) or return` guard,
/// `GeoTiff.pm:2136`) — no `GeoTiffMeta`, no warning.
#[test]
fn empty_directory_is_none() {
  assert!(process(&[], None, None, ByteOrder::Little).is_none());
}

/// An unknown GeoKey id is skipped (`GetTagInfo(...) or next`, `GeoTiff.pm:
/// 2167`) BEFORE its loc is examined — no warning, no emit.
#[test]
fn unknown_geokey_skipped() {
  // Key 5555 is not in %GeoTiff::Main.
  let dir = le16(&[1, 0, 0, 1, 5555, 0, 1, 7]);
  let meta = process(&dir, None, None, ByteOrder::Little).expect("present");
  assert!(meta.warnings().is_empty());
  assert_eq!(emit_pairs(&meta, true).len(), 1); // only GeoTiffVersion
}

/// Big-endian decoding: the same directory read with the MM order.
#[test]
fn big_endian() {
  let mut dir = Vec::new();
  for &w in &[1u16, 0, 0, 1, 1024, 0, 1, 2] {
    dir.extend_from_slice(&w.to_be_bytes());
  }
  let meta = process(&dir, None, None, ByteOrder::Big).expect("present");
  let pc = emit_pairs(&meta, true);
  assert_eq!(pc[1], ("GTModelType".to_string(), "Geographic".to_string()));
}

/// Heap-amplification DoS floor: a crafted directory of MANY `double` keys, each
/// with the maximum `count = 65535` re-reading ONE small `GeoTiffDoubleParams`
/// blob (`offset = 0`), would materialize a fresh 65535-element `Vec<f64>` PER
/// key (~34 GB if all 65535 entries decoded). The total-element budget
/// ([`MAX_GEOKEY_ELEMENTS`]) bounds the sum of decoded counts across the whole
/// directory: after ~`MAX_GEOKEY_ELEMENTS / 65535` keys it raises ONE
/// `DirectoryTooLarge` warning and STOPS materializing further keys — so the test
/// allocates only a handful of `Vec`s (megabytes, not gigabytes) and runs fast.
/// ExifTool has no such guard (it would OOM); exifast warns + truncates.
#[test]
fn oversized_directory_is_bounded_and_warns() {
  // `count = 65535`, `offset = 0` ⇒ the per-field guard needs the double blob to
  // hold `8 * 65535` bytes; ONE such blob (re-read by every entry) is ~512 KB.
  const COUNT: u16 = u16::MAX;
  let blob_doubles = COUNT as usize; // 65535 doubles ≈ 512 KB
  let double = vec![0u8; blob_doubles * 8];

  // Declare far more entries than the budget admits (the budget trips at
  // `MAX_GEOKEY_ELEMENTS / COUNT` ≈ 16 keys, so 64 proves the loop STOPS early).
  let num_entries: u16 = 64;
  let mut words: Vec<u16> = vec![1, 0, 0, num_entries];
  for _ in 0..num_entries {
    // GeogSemiMajorAxis (2057), a real double GeoKey, re-read from offset 0.
    words.extend_from_slice(&[2057, 0x87b0, COUNT, 0]);
  }
  let dir = le16(&words);

  let meta = process(&dir, Some(&double), None, ByteOrder::Little).expect("present");

  // Exactly ONE `DirectoryTooLarge` warning, and no other warning kind.
  assert_eq!(meta.warnings(), &[GeoTiffWarning::DirectoryTooLarge]);

  // The budget admits `floor(MAX_GEOKEY_ELEMENTS / COUNT)` keys before tripping;
  // the (k+1)-th would exceed it, so it (and every later key) is dropped. The
  // emitted set is the synthetic GeoTiffVersion + exactly those admitted keys —
  // far fewer than the 64 declared (proving the walk stopped early, not OOM'd).
  let admitted = (MAX_GEOKEY_ELEMENTS / COUNT as usize).min(num_entries as usize);
  let pc = emit_pairs(&meta, true);
  assert_eq!(pc.len(), admitted + 1, "version + admitted keys only");
  assert!(
    pc.len() < num_entries as usize,
    "the oversized tail must be dropped, not materialized"
  );
  assert_eq!(pc[0].0, "GeoTiffVersion");
  // Every admitted key is the in-range double (offset 0 ⇒ 0.0), so nothing
  // diverged structurally — only the count was bounded.
  assert_eq!(pc[1].0, "GeogSemiMajorAxis");
}

/// `GeoAsciiParams` decodes malformed UTF-8 ExifTool's way — each bad byte maps
/// to ASCII `?` via [`crate::convert::fix_utf8`] (`XMP.pm`'s `FixUTF8`, the SAME
/// path the rest of the EXIF string tags use), NOT to U+FFFD as
/// `from_utf8_lossy` would. The first-NUL truncation and the trailing-`|` strip
/// still apply, in that order. Ground-truthed vs bundled ExifTool 13.59:
///   `b"A\xff|"` → `"A?"`, `b"AB|\xff|"` → `"AB|?"`, `b"A\xff"` → `"A?"`,
///   `b"ABC\0J\xff|"` → `"ABC"` (the interior NUL truncates before the bad byte).
#[test]
fn ascii_params_malformed_utf8_is_question_mark_not_fffd() {
  let cases: &[(&[u8], &str)] = &[
    // The finding's case: a lone bad byte → '?', then the trailing '|' strips.
    (b"A\xff|", "A?"),
    // An interior '|' survives; the bad byte → '?'; the trailing '|' strips.
    (b"AB|\xff|", "AB|?"),
    // No terminator — the bad byte → '?'.
    (b"A\xff", "A?"),
    // The interior NUL truncates BEFORE the bad byte is ever seen.
    (b"ABC\0J\xff|", "ABC"),
  ];
  for &(blob, want) in cases {
    let dir = le16(&[1, 0, 0, 1, 2049, 0x87b1, blob.len() as u16, 0]);
    let meta = process(&dir, None, Some(blob), ByteOrder::Little).expect("present");
    assert!(meta.warnings().is_empty(), "blob {blob:?}");
    let pc = emit_pairs(&meta, true);
    assert_eq!(
      pc.get(1),
      Some(&("GeogCitation".to_string(), want.to_string())),
      "blob {blob:?} must FixUTF8 (?), not from_utf8_lossy (U+FFFD)"
    );
    // Belt-and-suspenders: the emitted string never contains U+FFFD.
    assert!(
      !pc[1].1.contains('\u{fffd}'),
      "blob {blob:?} leaked a U+FFFD replacement char"
    );
  }
}
