// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

fn find<'a>(em: &'a [Tag202aEmission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// The real ILME-FX3 `Tag202a` value (un-enciphered, `exiftool -v4`): first
/// byte 0x01 (the SubDirectory gate), 0x01=0x00 (FocalPlaneAFPointsUsed = 0,
/// Locations=0 so no per-location leaves follow). 66 bytes.
fn fx3_block() -> Vec<u8> {
  let mut b = vec![0xffu8; 66];
  b[0x00] = 0x01;
  b[0x01] = 0x00;
  b
}

#[test]
fn fx3_variant_gate() {
  assert!(selects_tag202a(&fx3_block()));
  // First byte not 0x01 ⇒ not selected (e.g. DSC-RX10M3 writes 110/137).
  assert!(!selects_tag202a(&[110, 0x00]));
  assert!(!selects_tag202a(&[]));
}

#[test]
fn fx3_focal_plane_af_points_used_zero() {
  let blk = fx3_block();
  for print_on in [true, false] {
    let em = parse_tag202a(&blk, print_on);
    assert_eq!(
      find(&em, "FocalPlaneAFPointsUsed"),
      Some(&TagValue::I64(0)),
      "FocalPlaneAFPointsUsed must be 0 (print_on={print_on})"
    );
  }
}

#[test]
fn focal_plane_af_points_used_nonzero() {
  let mut b = vec![0u8; 66];
  b[0x00] = 0x01;
  b[0x01] = 7;
  let em = parse_tag202a(&b, true);
  assert_eq!(find(&em, "FocalPlaneAFPointsUsed"), Some(&TagValue::I64(7)));
}

/// Per-field availability: a block too short for byte 0x01 emits nothing.
#[test]
fn truncated_block_per_field() {
  // Only the gate byte present (len 1) — 0x01 is out of range.
  assert!(parse_tag202a(&[0x01], true).is_empty());
  assert!(parse_tag202a(&[], true).is_empty());
}
