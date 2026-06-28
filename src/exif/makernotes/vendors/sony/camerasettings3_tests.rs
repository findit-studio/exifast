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

/// The PrintConv (`-j`) value of the FIRST `name` leaf the model emits.
fn value_of(model: &str, buf: &[u8], name: &str) -> Option<TagValue> {
  parse_camera_settings3(buf, Some(model), true)
    .into_iter()
    .find(|e| e.name == name)
    .map(|e| e.value)
}

/// How many leaves named `name` the model emits.
fn count(model: &str, buf: &[u8], name: &str) -> usize {
  parse_camera_settings3(buf, Some(model), true)
    .iter()
    .filter(|e| e.name == name)
    .count()
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

/// FAMILY 4 (A4xx-only, `=~ /^DSLR-(A450|A500|A550)$/`): the +0x200-shifted masked
/// layout (0x283.. / 0x30c.. / 0x400..) fires, and the lower-offset "other models"
/// leaves at 0x83 / 0x99 / 0x32 / the int32u 0x0114 path do NOT.
#[test]
fn a4xx_family_emits_shifted_layout_not_other_models() {
  let mut buf = vec![0u8; 0x600];
  buf[0x283] = 16; // AFButtonPressed = Yes (0x283, A4xx)
  buf[0x286] = 2; // AELock = Off
  buf[0x287] = 1; // FlashStatusBuilt-in = Off (the A4xx 0x287, not 0x87)
  buf[0x28b] = 16; // LiveViewFocusMode = Manual
  buf[0x30c] = 2; // SequenceNumber = 2 (OTHER passthrough)
  // 0x314 ImageNumber int16u LE 0xC539, Mask 0x3fff -> 0x0539 = 1337 -> "1337".
  buf[0x314] = 0x39;
  buf[0x315] = 0xC5;
  // 0x316 FolderNumber int16u LE 0xFC2A, Mask 0x03ff -> 0x002A = 42 -> "042".
  buf[0x316] = 0x2A;
  buf[0x317] = 0xFC;
  // 0x400 ImageNumber / 0x402 FolderNumber (the second A4xx source).
  buf[0x400] = 0x01; // -> 1 -> "0001"
  buf[0x402] = 0x05; // -> 5 -> "005"
  // The "other models" lower-offset leaves (present in the buffer, must stay
  // silent for an A4xx body):
  buf[0x83] = 1; // would be AFButtonPressed = No
  buf[0x99] = 16; // would be LensMount = A-mount
  buf[0x32] = 1; // would be SweepPanoramaSize = Standard

  // The +0x200 leaves emit with their A4xx values.
  assert_eq!(
    value_of("DSLR-A500", &buf, "AFButtonPressed"),
    Some(TagValue::Str("Yes".into())),
    "0x283 wins over the 0x83 No"
  );
  assert_eq!(
    value_of("DSLR-A500", &buf, "AELock"),
    Some(TagValue::Str("Off".into()))
  );
  assert_eq!(
    value_of("DSLR-A500", &buf, "FlashStatusBuilt-in"),
    Some(TagValue::Str("Off".into()))
  );
  assert_eq!(
    value_of("DSLR-A500", &buf, "LiveViewFocusMode"),
    Some(TagValue::Str("Manual".into()))
  );
  assert_eq!(
    value_of("DSLR-A500", &buf, "SequenceNumber"),
    Some(TagValue::I64(2))
  );
  // Mask + sprintf("%.4d") / sprintf("%.3d") — the FIRST ImageNumber/FolderNumber
  // are the 0x314/0x316 masked reads.
  assert_eq!(
    value_of("DSLR-A500", &buf, "ImageNumber"),
    Some(TagValue::Str("1337".into())),
    "0x314 masked int16u + %.4d"
  );
  assert_eq!(
    value_of("DSLR-A500", &buf, "FolderNumber"),
    Some(TagValue::Str("042".into())),
    "0x316 masked int16u + %.3d"
  );
  // BOTH the 0x314/0x316 and 0x400/0x402 sources fire (== 2), and the int32u
  // 0x0114 path is A4xx-excluded (would have made it 3).
  assert_eq!(count("DSLR-A500", &buf, "ImageNumber"), 2);
  assert_eq!(count("DSLR-A500", &buf, "FolderNumber"), 2);

  // The "other models"-only leaves are excluded for an A4xx body.
  assert!(!has("DSLR-A500", &buf, "LensMount"), "0x99 A4xx-excluded");
  assert!(
    !has("DSLR-A500", &buf, "SweepPanoramaSize"),
    "0x32 A4xx-excluded"
  );

  // A non-A4xx body reads the lower-offset 0x83 (= No) and 0x99 instead.
  assert_eq!(
    value_of("SLT-A33", &buf, "AFButtonPressed"),
    Some(TagValue::Str("No".into()))
  );
  assert!(has("SLT-A33", &buf, "LensMount"));
}

/// FAMILY 5 (NEX-only, `=~ /^NEX-/`): the 0x3f0/0x3f3/0x3f7 lens leaves fire,
/// 0x3f7 `LensType2` resolves via the E-mount table and honours the 0x99
/// `LensMount != 1` gate, and the STEP-3 fix lets 0x38 `PanoramaSize3D` emit.
#[test]
fn nex_family_lens_leaves_and_0x38_fix() {
  let mut buf = vec![0u8; 0x600];
  // 0x3f0 LensE-mountVersion int16u LE 0x0102 -> sprintf("%x.%.2x",1,2) = "1.02".
  buf[0x3f0] = 0x02;
  buf[0x3f1] = 0x01;
  // 0x3f3 LensFirmwareVersion int16u LE 0x010f -> "Ver.01.015".
  buf[0x3f3] = 0x0F;
  buf[0x3f4] = 0x01;
  buf[0x99] = 17; // LensMount = E-mount (!= 1) -> 0x3f7 fires
  // 0x3f7 LensType2 int16u LE 2 -> %sonyLensTypes2[2] = "Sony LA-EA2 Adapter".
  buf[0x3f7] = 0x02;
  buf[0x38] = 1; // PanoramaSize3D = Standard (the fix: NEX NOT excluded)

  assert_eq!(
    value_of("NEX-5", &buf, "LensE-mountVersion"),
    Some(TagValue::Str("1.02".into()))
  );
  assert_eq!(
    value_of("NEX-5", &buf, "LensFirmwareVersion"),
    Some(TagValue::Str("Ver.01.015".into()))
  );
  assert_eq!(
    value_of("NEX-5", &buf, "LensType2"),
    Some(TagValue::Str("Sony LA-EA2 Adapter".into())),
    "0x3f7 resolves via the E-mount %sonyLensTypes2 table"
  );
  // STEP 3 fix: 0x38 Condition excludes ONLY A4xx, not NEX (was over-gated `!nex`).
  assert_eq!(
    value_of("NEX-5", &buf, "PanoramaSize3D"),
    Some(TagValue::Str("Standard".into())),
    "0x38 must emit for a NEX body"
  );

  // The LensMount DataMember gate: LensMount == 1 suppresses 0x3f7.
  let mut mount1 = buf.clone();
  mount1[0x99] = 1;
  assert!(
    !has("NEX-5", &mount1, "LensType2"),
    "LensMount==1 excludes 0x3f7 LensType2"
  );
  // The NEX lens leaves never fire for an A4xx body.
  assert!(!has("DSLR-A500", &buf, "LensE-mountVersion"));
  assert!(!has("DSLR-A500", &buf, "LensType2"));
}

/// REGRESSION: a non-A4xx, non-NEX body (A560) still walks the unchanged "other
/// models" branch — the A4xx-shifted and NEX-only families never fire, and the
/// 0x38 fix leaves it emitting `PanoramaSize3D` exactly as before.
#[test]
fn a560_other_models_unchanged() {
  let mut buf = vec![0u8; 0x600];
  buf[0x83] = 1; // AFButtonPressed = No (other-models layout)
  buf[0x99] = 16; // LensMount = A-mount
  buf[0x38] = 2; // PanoramaSize3D = Wide
  buf[0x36] = 1; // LiveViewAFSetting = Phase-detect AF
  // A4xx-shifted + NEX leaves present in the buffer but must stay silent.
  buf[0x283] = 16; // would be the A4xx AFButtonPressed = Yes
  buf[0x3f0] = 0x02;
  buf[0x3f1] = 0x01;

  assert_eq!(
    value_of("DSLR-A560", &buf, "AFButtonPressed"),
    Some(TagValue::Str("No".into())),
    "A560 reads 0x83, never the A4xx 0x283"
  );
  assert_eq!(
    value_of("DSLR-A560", &buf, "LensMount"),
    Some(TagValue::Str("A-mount".into()))
  );
  assert_eq!(
    value_of("DSLR-A560", &buf, "PanoramaSize3D"),
    Some(TagValue::Str("Wide".into()))
  );
  assert_eq!(
    value_of("DSLR-A560", &buf, "LiveViewAFSetting"),
    Some(TagValue::Str("Phase-detect AF".into()))
  );
  assert!(!has("DSLR-A560", &buf, "LensE-mountVersion"));
  assert!(!has("DSLR-A560", &buf, "LensFirmwareVersion"));
}
