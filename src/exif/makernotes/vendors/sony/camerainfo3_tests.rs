// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::CameraInfo3` model-anchor regression: 0x0e `FocalLength` / 0x10
//! `FocalLengthTeleZoom` carry `Condition => '$$self{Model} !~
//! /^DSLR-(A450|A500|A550)$/'` (`$`-anchored EXACT, Sony.pm:3006/3016) — a
//! DISTINCT anchor from the 9-point-AF block (0x14..0x31), which is the `\b`
//! `/^DSLR-A(450|500|550)\b/`. A single `\b` bool wrongly suppressed the
//! `FocalLength*` leaves for a hyphen/space-suffixed A4xx string.

use super::*;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn has(model: &str, buf: &[u8], name: &str) -> bool {
  parse_camera_info3(buf, Some(model), true)
    .iter()
    .any(|e| e.name == name)
}

#[test]
fn focallength_is_exact_not_word_boundary() {
  let mut buf = vec![0u8; 0x40];
  put_u16(&mut buf, 0x0e, 500); // FocalLength 50.0 mm
  put_u16(&mut buf, 0x10, 300); // FocalLengthTeleZoom

  // SLT-A33 (15-point body, not an A4xx): both emit.
  assert!(has("SLT-A33", &buf, "FocalLength"));
  assert!(has("SLT-A33", &buf, "FocalLengthTeleZoom"));

  // Suffixed A4xx strings are NOT a `$`-exact match, so the `$`-anchored
  // `FocalLength*` still emit (the `\b` port wrongly dropped `DSLR-A500-x`).
  for m in ["DSLR-A500-x", "DSLR-A500X"] {
    assert!(
      has(m, &buf, "FocalLength"),
      "{m} FocalLength must emit ($-exact)"
    );
    assert!(
      has(m, &buf, "FocalLengthTeleZoom"),
      "{m} FocalLengthTeleZoom must emit ($-exact)"
    );
  }

  // The real 9-point bodies (exact match) do NOT carry these leaves.
  for m in ["DSLR-A450", "DSLR-A500", "DSLR-A550"] {
    assert!(!has(m, &buf, "FocalLength"), "{m} FocalLength suppressed");
    assert!(
      !has(m, &buf, "FocalLengthTeleZoom"),
      "{m} FocalLengthTeleZoom suppressed"
    );
  }
}
