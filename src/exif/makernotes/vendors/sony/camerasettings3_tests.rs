// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::CameraSettings3` model-anchor regression. The A4xx conditions in this
//! table come in TWO anchor flavors (never `\b`): most leaves are `$`-anchored
//! EXACT (`!~ /^DSLR-(A450|A500|A550)$/`, e.g. 0x32 `SweepPanoramaSize`, 0x99
//! `LensMount`) while 0x87/0x88 `FlashStatus*` are the no-anchor PREFIX
//! (`!~ /^DSLR-(A450|A500|A550)/`). A single `\b` bool was wrong in OPPOSITE
//! directions for a suffixed A4xx string.

use super::*;

fn has(model: &str, buf: &[u8], name: &str) -> bool {
  parse_camera_settings3(buf, Some(model), true)
    .iter()
    .any(|e| e.name == name)
}

#[test]
fn a4xx_anchors_split_exact_vs_prefix() {
  let mut buf = vec![0u8; 0x210];
  buf[0x32] = 1; // SweepPanoramaSize = Standard  ($-exact)
  buf[0x87] = 1; // FlashStatusBuilt-in = Off      (prefix)
  buf[0x99] = 16; // LensMount = A-mount            ($-exact)

  // SLT-A33 (not an A4xx): every probed leaf present.
  assert!(has("SLT-A33", &buf, "SweepPanoramaSize"));
  assert!(has("SLT-A33", &buf, "FlashStatusBuilt-in"));
  assert!(has("SLT-A33", &buf, "LensMount"));

  // Real exact A4xx bodies: ALL anchors exclude them.
  for m in ["DSLR-A450", "DSLR-A500", "DSLR-A550"] {
    assert!(!has(m, &buf, "SweepPanoramaSize"), "{m} 0x32 ($-exact)");
    assert!(!has(m, &buf, "FlashStatusBuilt-in"), "{m} 0x87 (prefix)");
    assert!(!has(m, &buf, "LensMount"), "{m} 0x99 ($-exact)");
  }

  // Suffixed A4xx strings: the `$`-exact leaves EMIT (not an exact match — the
  // `\b` port wrongly dropped the hyphen form), but the PREFIX 0x87/0x88 are
  // EXCLUDED (a prefix match — the `\b` port wrongly emitted the alnum form).
  for m in ["DSLR-A500-x", "DSLR-A500X"] {
    assert!(
      has(m, &buf, "SweepPanoramaSize"),
      "{m} 0x32 must emit ($-exact)"
    );
    assert!(has(m, &buf, "LensMount"), "{m} 0x99 must emit ($-exact)");
    assert!(
      !has(m, &buf, "FlashStatusBuilt-in"),
      "{m} 0x87 must be excluded (prefix)"
    );
  }
}
