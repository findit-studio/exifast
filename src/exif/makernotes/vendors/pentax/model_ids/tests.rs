// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

#[test]
fn model_ids_sorted_and_unique() {
  let mut prev: Option<u32> = None;
  for &(k, _) in PENTAX_MODEL_IDS {
    if let Some(p) = prev {
      assert!(k > p, "PENTAX_MODEL_IDS not strictly sorted at {k}");
    }
    prev = Some(k);
  }
}

#[test]
fn k10d_resolves() {
  // 0x12c1e == 76830 => 'K10D' (Pentax.jpg body).
  assert_eq!(lookup_name(76830).as_deref(), Some("K10D"));
}

#[test]
fn unknown_id_returns_none() {
  assert!(lookup_name(0xFFFF_FFFF).is_none());
}
