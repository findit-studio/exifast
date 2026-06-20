//! Unit tests for the GPS Composite PrintConv helpers — `ToDMS` (the default
//! `CoordFormat` DMS render with the hemisphere suffix, sign flip, and `>= 60`
//! carry) and the `Composite:GPSAltitude` PrintConv. Byte-exact against the
//! bundled-ExifTool 13.59 `Composite:*` strings.

use super::*;

#[test]
fn to_dms_positive_latitude_matches_bundled() {
  // ExifGPS.tif: GPS:GPSLatitude 48.85815, ref N ⇒ `48 deg 51' 29.34" N`.
  assert_eq!(to_dms(48.85815, 'N'), "48 deg 51' 29.34\" N");
}

#[test]
fn to_dms_positive_longitude_matches_bundled() {
  // ExifGPS.tif: GPS:GPSLongitude 2.34893333333333, ref E ⇒ `2 deg 20' 56.16" E`.
  assert_eq!(to_dms(2.34893333333333, 'E'), "2 deg 20' 56.16\" E");
}

#[test]
fn to_dms_dji_coordinates_match_bundled() {
  // DJIPhantom4.jpg lat 32.4785966666667 ⇒ `32 deg 28' 42.95" N`. The
  // longitude's `Composite:GPSLongitude` ValueConv already negated the ref-W
  // value to -90.2600013888889, so ToDMS receives the NEGATIVE coordinate and
  // flips the positive-hemisphere `E` to `W` ⇒ `90 deg 15' 36.01" W`.
  assert_eq!(to_dms(32.4785966666667, 'N'), "32 deg 28' 42.95\" N");
  assert_eq!(to_dms(-90.2600013888889, 'E'), "90 deg 15' 36.01\" W");
}

#[test]
fn to_dms_negative_flips_hemisphere_and_takes_abs() {
  // A negative latitude (`val < 0`) ⇒ `N` flips to `S`, magnitude is `abs`.
  assert_eq!(to_dms(-48.85815, 'N'), "48 deg 51' 29.34\" S");
  // A negative longitude ⇒ `E` flips to `W`.
  assert_eq!(to_dms(-2.34893333333333, 'E'), "2 deg 20' 56.16\" W");
}

#[test]
fn to_dms_seconds_round_off_carry() {
  // A value whose seconds round UP to 60.00 must carry into the minutes (and on
  // into the degrees): ExifTool `convert "72 59 60.00" to "73 0 0.00"`. Pick a
  // value where (val - d)*60 = 59 exactly and the residual seconds round to
  // 60.00: 72 + 59/60 + 59.999/3600 ≈ 72.9999997. `%.2f` of 59.9964 → "60.00".
  // Construct: degrees 73 minus a hair so seconds round to 60.
  let v = 73.0 - (0.001 / 3600.0); // 72 deg 59' 59.999"
  assert_eq!(to_dms(v, 'N'), "73 deg 0' 0.00\" N");
}

#[test]
fn to_dms_minute_carry_only() {
  // Seconds carry into minutes WITHOUT a degree carry: 48 deg 50' 59.999" ⇒
  // 48 deg 51' 0.00".
  let v = 48.0 + 50.0 / 60.0 + 59.999 / 3600.0;
  assert_eq!(to_dms(v, 'N'), "48 deg 51' 0.00\" N");
}

/// The GPS-pair-only candidate set (index 0 = `$val[0]`/`$prt[1]`; the XMP pair
/// absent), the common EXIF still case.
fn gps_only(alt_text: &str, ref_print: &str) -> [AltCandidate<'static>; 2] {
  [
    AltCandidate {
      alt_text: Some(Box::leak(alt_text.to_string().into_boxed_str())),
      ref_print: Some(Box::leak(ref_print.to_string().into_boxed_str())),
    },
    AltCandidate {
      alt_text: None,
      ref_print: None,
    },
  ]
}

#[test]
fn altitude_above_sea_level_matches_bundled() {
  // ExifGPS.tif: alt 35, prt "Above Sea Level" ⇒ `35 m Above Sea Level`.
  let c = gps_only("35", "Above Sea Level");
  assert_eq!(gps_altitude_print(35.0, &c), "35 m Above Sea Level");
}

#[test]
fn altitude_truncates_to_one_decimal() {
  // DJIPhantom4.jpg: alt 109.786 ⇒ int(1097.86)/10 = 109.7.
  let c = gps_only("109.786", "Above Sea Level");
  assert_eq!(gps_altitude_print(109.786, &c), "109.7 m Above Sea Level");
}

#[test]
fn altitude_below_sea_level_uses_input_ref_print() {
  // A below-sea altitude: the ExifTool branch uses the (positive) input
  // `$val[0]` with `$prt[1]` "Below Sea Level".
  let c = gps_only("12.3", "Below Sea Level");
  assert_eq!(gps_altitude_print(-12.3, &c), "12.3 m Below Sea Level");
}

#[test]
fn altitude_comma_decimal_is_isfloat_normalized() {
  // ExifTool `IsFloat($val[$_])` translates `,`→`.` in place (ExifTool.pm:5951),
  // so `int($val[$_]*10)/10` coerces `12,5` AS `12.5`, NOT `12` (a raw coercion
  // would treat the comma as a numeric-prefix terminator). Bundled-ExifTool
  // 13.59 on a `GPSAltitude=12,5` + above-sea ref emits the `12.5 m …` PrintConv.
  let c = gps_only("12,5", "Above Sea Level");
  assert_eq!(gps_altitude_print(12.5, &c), "12.5 m Above Sea Level");
}

#[test]
fn altitude_xmp_branch_uses_second_candidate() {
  // The XMP fixtures (`XMP_gps_abovesea.xmp`): the GPS pair (index 0/1) is
  // absent, the XMP pair (index 2/3) supplies `$val[2]`/`$prt[3]`. The loop
  // matches the SECOND candidate.
  let c = [
    AltCandidate {
      alt_text: None,
      ref_print: None,
    },
    AltCandidate {
      alt_text: Some("35"),
      ref_print: Some("Above Sea Level"),
    },
  ];
  assert_eq!(gps_altitude_print(35.0, &c), "35 m Above Sea Level");
}

#[test]
fn altitude_falls_through_to_own_val_when_no_sea_ref() {
  // No candidate has a `/Sea/` ref-print ⇒ fall through to the composite's own
  // `$val`: a negative value ⇒ Below, positive ⇒ Above.
  let c = [
    AltCandidate {
      alt_text: Some("35"),
      ref_print: Some("Unknown"),
    },
    AltCandidate {
      alt_text: None,
      ref_print: None,
    },
  ];
  assert_eq!(gps_altitude_print(35.0, &c), "35 m Above Sea Level");
  assert_eq!(gps_altitude_print(-35.0, &c), "35 m Below Sea Level");
}
