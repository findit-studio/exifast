// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::Tag900b` model-anchor regression: 0x00bd `FaceDetection` carries
//! `Condition => '$$self{Model} !~ /^DSLR-(A450|A500|A550)$/'` (`$`-anchored
//! EXACT, Sony.pm:7571), NOT the `\b` boundary. 0x0002 `FacesDetected` is
//! unconditional.

use super::*;

fn has(model: &str, buf: &[u8], name: &str) -> bool {
  parse_tag900b(buf, Some(model), true)
    .iter()
    .any(|e| e.name == name)
}

#[test]
fn facedetection_is_exact_not_word_boundary() {
  let mut buf = vec![0u8; 0xc0];
  buf[0x0002] = 98; // FacesDetected -> "1"
  buf[0x00bd] = 98; // FaceDetection -> "On"

  // SLT-A33 + suffixed A4xx strings: NOT a `$`-exact match, so FaceDetection
  // still emits (the `\b` port wrongly dropped `DSLR-A500-x`).
  for m in ["SLT-A33", "DSLR-A500-x", "DSLR-A500X"] {
    assert!(has(m, &buf, "FacesDetected"), "{m} FacesDetected");
    assert!(
      has(m, &buf, "FaceDetection"),
      "{m} FaceDetection must emit ($-exact)"
    );
  }

  // Real exact A4xx bodies: FaceDetection suppressed (always 98 there), but
  // FacesDetected still emits.
  for m in ["DSLR-A450", "DSLR-A500", "DSLR-A550"] {
    assert!(has(m, &buf, "FacesDetected"), "{m} FacesDetected");
    assert!(
      !has(m, &buf, "FaceDetection"),
      "{m} FaceDetection suppressed (exact)"
    );
  }
}
