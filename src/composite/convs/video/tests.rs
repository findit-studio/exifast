//! Unit tests for the QuickTime video Composite conversions
//! ([`convert_bitrate`] + [`get_rotation_angle`]) — pinned to bundled-ExifTool
//! 13.59 values.

#![cfg(feature = "alloc")]

use super::{convert_bitrate, get_rotation_angle};

#[test]
fn convert_bitrate_units_and_formats() {
  // `$bitrate < 100 ? '%.3g' : '%.0f'`, divide by 1000 while `>= 1000`. The
  // values are the bundled `Composite:AvgBitrate` strings (the census):
  //   QuickTime_camm.mov           309 bps    (309 < 1000 ⇒ bps; 309 >= 100 ⇒ %.0f)
  //   QuickTime_camm0.mov          128 bps
  //   QuickTime_m4a.mov            4 bps      (4 < 100 ⇒ %.3g)
  //   MP4_blackvue_dr770x.mp4      25.2 Mbps  (25 200 000 → 25.2, %.3g)
  //   HEIF_C001_msf1.heic          50.2 Mbps
  //   QuickTime_canon_ctmd_dup.mov 1.02 kbps  (1024 → 1.024 → %.3g "1.02")
  assert_eq!(convert_bitrate(309.0), "309 bps");
  assert_eq!(convert_bitrate(128.0), "128 bps");
  assert_eq!(convert_bitrate(4.0), "4 bps");
  assert_eq!(convert_bitrate(0.0), "0 bps");
  // 25 200 000 bps ⇒ 25.2 Mbps (3 sig figs, `%.3g`).
  assert_eq!(convert_bitrate(25_200_000.0), "25.2 Mbps");
  // 1024 bps ⇒ 1.024 kbps ⇒ `%.3g` "1.02 kbps".
  assert_eq!(convert_bitrate(1024.0), "1.02 kbps");
  // A value >= 100 in its final unit uses `%.0f` (no decimals).
  assert_eq!(convert_bitrate(262_000.0), "262 kbps");
  // Gbps is the largest unit — a value >= 1000 Gbps stays Gbps (no larger unit).
  assert_eq!(convert_bitrate(5_000_000_000_000.0), "5000 Gbps");
}

#[test]
fn get_rotation_angle_identity_is_zero() {
  // The identity matrix (`MatrixStructure "1 0 0 0 1 0 0 0 1"`) → atan2(0,1) = 0.
  // (exifast renders the QuickTime fixed32s identity as `"1 0 0 0 1 0 0 0 1"`.)
  assert_eq!(get_rotation_angle("1 0 0 0 1 0 0 0 1"), Some(0.0));
}

#[test]
fn get_rotation_angle_degenerate_top_left_is_none() {
  // `return undef if $a[0]==0 and $a[1]==0` — the all-zero `MatrixStructure`
  // (`"0 0 0 0 0 0 0 0 0"`, the Sony rtmd / many-fixture value) yields no angle.
  assert_eq!(get_rotation_angle("0 0 0 0 0 0 0 0 0"), None);
  // Too few fields ⇒ None.
  assert_eq!(get_rotation_angle("1"), None);
  assert_eq!(get_rotation_angle(""), None);
}

#[test]
fn get_rotation_angle_90_180_270() {
  // The `int($angle * 1000 + 0.5) / 1000` rounding to 3 dp absorbs the
  // truncated-pi error, so 90/180/270 land EXACTLY (verified vs the bundled
  // `GetRotationAngle` Perl: identity→0, 90→90, 180→180, 270→270).
  // 90°: `[0 1; -1 0]` ⇒ atan2(1, 0).
  assert_eq!(get_rotation_angle("0 1 0 -1 0 0 0 0 1"), Some(90.0));
  // 180°: `[-1 0; 0 -1]` ⇒ atan2(0, -1) = pi.
  assert_eq!(get_rotation_angle("-1 0 0 0 -1 0 0 0 1"), Some(180.0));
  // 270°: `[0 -1; 1 0]` ⇒ atan2(-1, 0) = -pi/2 ⇒ +360.
  assert_eq!(get_rotation_angle("0 -1 0 1 0 0 0 0 1"), Some(270.0));
}
