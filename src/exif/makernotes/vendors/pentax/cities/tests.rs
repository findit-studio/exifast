// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

#[test]
fn cities_sorted_and_unique() {
  let mut prev: Option<u16> = None;
  for &(k, _) in PENTAX_CITIES {
    if let Some(p) = prev {
      assert!(k > p, "PENTAX_CITIES not strictly sorted at {k}");
    }
    prev = Some(k);
  }
}

#[test]
fn toronto_new_york() {
  // Pentax.jpg: HometownCity 11 => 'Toronto', DestinationCity 12 => 'New York'.
  assert_eq!(lookup_name(11).as_deref(), Some("Toronto"));
  assert_eq!(lookup_name(12).as_deref(), Some("New York"));
}
