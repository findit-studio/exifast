// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::FaceInfo` (`Sony.pm:4062-4122`) per-face rows: `FacesDetected`
//! (int16s, `-1 => 'n/a'`) plus `Face1..8Position` (`int16u[4]`, key×2 byte
//! offsets, ×15 re-ordered ValueConv, gated by `FacesDetected >= N`).

use super::*;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_i16(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn names(out: &[SubEmission]) -> Vec<&'static str> {
  out.iter().map(|e| e.name).collect()
}

/// A crafted FaceInfo block with `FacesDetected = 2` and two rectangles emits
/// `Face1Position`/`Face2Position` byte-exact (the ×15 re-ordered
/// top,left,height,width ValueConv) and leaves Face3..8 gated out. There is no
/// PrintConv, so `-j` and `-n` are identical.
#[test]
fn two_faces_emit_rectangles_identical_in_j_and_n() {
  // FORMAT int16u ⇒ byte = key×2: FacesDetected@0, Face1@2, Face2@12, Face3@22.
  let mut buf = vec![0u8; 100];
  put_i16(&mut buf, 0, 2); // FacesDetected = 2
  // Face1 int16u[4] = [v0,v1,v2,v3] = [2,3,8,12] at bytes 2,4,6,8.
  put_u16(&mut buf, 2, 2);
  put_u16(&mut buf, 4, 3);
  put_u16(&mut buf, 6, 8);
  put_u16(&mut buf, 8, 12);
  // Face2 int16u[4] = [4,5,10,6] at bytes 12,14,16,18.
  put_u16(&mut buf, 12, 4);
  put_u16(&mut buf, 14, 5);
  put_u16(&mut buf, 16, 10);
  put_u16(&mut buf, 18, 6);
  // A non-zero Face3 region (byte 22) that must stay gated out.
  put_u16(&mut buf, 22, 9);

  for print_conv in [true, false] {
    let mut out = Vec::new();
    parse_face_info(&buf, print_conv, &mut out);
    assert_eq!(
      names(&out),
      ["FacesDetected", "Face1Position", "Face2Position"],
      "print_conv={print_conv}"
    );
    assert_eq!(out[0].value, TagValue::I64(2));
    // "$v[1]*15 $v[0]*15 $v[3]*15 $v[2]*15": Face1 [2,3,8,12] → top 45, left 30,
    // height 180, width 120.
    assert_eq!(out[1].value, TagValue::Str("45 30 180 120".into()));
    // Face2 [4,5,10,6] → top 75, left 60, height 90, width 150.
    assert_eq!(out[2].value, TagValue::Str("75 60 90 150".into()));
  }
}

/// `FacesDetected = 0` (the A33 activation-golden path) emits only the count —
/// no Face rows even when rectangle bytes are present.
#[test]
fn zero_faces_emits_only_the_count() {
  let mut buf = vec![0u8; 100];
  put_i16(&mut buf, 0, 0);
  put_u16(&mut buf, 2, 99); // a rectangle that must NOT be emitted
  let mut out = Vec::new();
  parse_face_info(&buf, true, &mut out);
  assert_eq!(names(&out), ["FacesDetected"]);
  assert_eq!(out[0].value, TagValue::I64(0));
}

/// `FacesDetected = -1` folds to `'n/a'` (`-j`) / raw `-1` (`-n`); the DataMember
/// gate folds to 0, so no Face rows.
#[test]
fn minus_one_is_na_and_gates_out_faces() {
  let mut buf = vec![0u8; 100];
  put_i16(&mut buf, 0, -1);
  put_u16(&mut buf, 2, 7);
  let mut j = Vec::new();
  parse_face_info(&buf, true, &mut j);
  assert_eq!(names(&j), ["FacesDetected"]);
  assert_eq!(j[0].value, TagValue::Str("n/a".into()));
  let mut n = Vec::new();
  parse_face_info(&buf, false, &mut n);
  assert_eq!(n[0].value, TagValue::I64(-1));
}

/// Per-field availability: `FacesDetected = 8` but the block only fits Face1 →
/// only Face1Position emits (the higher faces fall out-of-range).
#[test]
fn per_field_availability_truncates_at_block_end() {
  // 10-byte block: FacesDetected@0..2, Face1@2..10; Face2@12 is past the end.
  let mut buf = vec![0u8; 10];
  put_i16(&mut buf, 0, 8);
  put_u16(&mut buf, 2, 1);
  put_u16(&mut buf, 4, 1);
  put_u16(&mut buf, 6, 1);
  put_u16(&mut buf, 8, 1);
  let mut out = Vec::new();
  parse_face_info(&buf, true, &mut out);
  assert_eq!(names(&out), ["FacesDetected", "Face1Position"]);
  // [1,1,1,1] → "15 15 15 15".
  assert_eq!(out[1].value, TagValue::Str("15 15 15 15".into()));
}

/// A minimal `MoreInfo` index directory (`[num=1][len][tag=0x0002][off=8]`) whose
/// single block is a FaceInfo block with `FacesDetected = 1` and one rectangle.
fn more_info_with_face_block() -> Vec<u8> {
  let mut buf = vec![0u8; 40];
  put_u16(&mut buf, 0, 1); // num = 1 index entry
  put_u16(&mut buf, 2, 40); // len = whole directory
  put_u16(&mut buf, 4, 0x0002); // tagID = FaceInfo block
  put_u16(&mut buf, 6, 8); // block offset
  // FaceInfo block at byte 8: FacesDetected@block-0, Face1@block-2 = [2,3,8,12].
  put_i16(&mut buf, 8, 1);
  put_u16(&mut buf, 10, 2);
  put_u16(&mut buf, 12, 3);
  put_u16(&mut buf, 14, 8);
  put_u16(&mut buf, 16, 12);
  buf
}

/// `MoreInfo` 0x0002 routes via the `$`-anchored EXACT `/^DSLR-(A450|A500|A550)$/`
/// (`Sony.pm:3398`/`3402`), NOT the `\b` `model_is_a4xx_9pt` (which is the
/// ExtraInfo3 0x0014 condition). A SUFFIXED A4xx body is not an exact match, so
/// it must still parse the non-A4xx `FaceInfo` — matching ExifTool's `$`.
#[test]
fn faceinfo_dispatch_is_exact_match_not_word_boundary() {
  let buf = more_info_with_face_block();

  // Suffixed A4xx strings (`\b` would wrongly suppress these) still parse the
  // non-A4xx FaceInfo: FacesDetected + the per-face row emit.
  for model in ["DSLR-A500-x", "DSLR-A500 (extra)", "DSLR-A500X"] {
    let out = parse_more_info(&buf, Some(model), true);
    assert_eq!(
      names(&out),
      ["FacesDetected", "Face1Position"],
      "suffixed {model} must parse the non-A4xx FaceInfo"
    );
    // [2,3,8,12] → top 45, left 30, height 180, width 120 (the ×15 ValueConv).
    assert_eq!(out[1].value, TagValue::Str("45 30 180 120".into()));
  }

  // The A33 (SLT, exact-mismatch) keeps the activation-golden path: FaceInfo runs.
  let a33 = parse_more_info(&buf, Some("SLT-A33"), true);
  assert_eq!(names(&a33), ["FacesDetected", "Face1Position"]);
  assert_eq!(a33[0].value, TagValue::I64(1));

  // EXACTLY one of the three → the deferred `FaceInfoA`; the non-A4xx FaceInfo
  // does NOT run, so the 0x0002 block emits nothing.
  for model in ["DSLR-A450", "DSLR-A500", "DSLR-A550"] {
    let out = parse_more_info(&buf, Some(model), true);
    assert!(
      out.is_empty(),
      "exact {model} routes to the deferred FaceInfoA, not FaceInfo"
    );
  }
}
