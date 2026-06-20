//! Tests for the `%subSecConv` assembly (Exif.pm:4726) the SubSec composites
//! share, pinned to the bundled-ExifTool 13.59 truth (NikonD2Hs.jpg emits the
//! sub-second form; the other still cameras emit nothing).

use super::*;

#[test]
fn subsec_with_subsectime_only_inserts_fraction() {
  // NikonD2Hs: base "2005:03:18 02:55:18", SubSecTime "16", no OffsetTime ⇒
  // ".16" inserted after the time.
  assert_eq!(
    sub_sec_assemble("2005:03:18 02:55:18", Some("16"), None).as_deref(),
    Some("2005:03:18 02:55:18.16")
  );
}

#[test]
fn subsec_absent_subsec_and_offset_returns_none() {
  // Pentax / DJI_Matrice30T / ExifGPS / DJIPhantom4 shape: a base DateTime but
  // NO SubSecTime and NO OffsetTime ⇒ `$v` stays undef ⇒ NOT built.
  assert_eq!(sub_sec_assemble("2008:03:02 12:01:23", None, None), None);
}

#[test]
fn subsec_empty_or_nondigit_subsectime_does_not_build() {
  // `$val[1]=~/^(\d+)/` fails for a non-leading-digit SubSecTime ⇒ no fraction;
  // with no offset either, `$v` is undef.
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", Some(""), None),
    None
  );
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", Some("abc"), None),
    None
  );
  // Leading digits ARE taken even with a trailing tail ("16x" ⇒ "16").
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", Some("16x"), None).as_deref(),
    Some("2008:03:02 12:01:23.16")
  );
}

#[test]
fn subsec_negative_lookahead_skips_existing_subseconds() {
  // The base already carries sub-seconds (" 12:01:23.5"): the `(?!\.\d+)`
  // lookahead blocks the ONLY ` HH:MM:SS`, the substitution returns 0, so `$v`
  // is undef'd and (with no offset) the composite is not built.
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23.5", Some("16"), None),
    None
  );
}

#[test]
fn subsec_offset_only_appends_timezone() {
  // No SubSecTime but a valid OffsetTime ⇒ `($v || $val[0])` falls back to the
  // base and appends the `sprintf('%s%.2d:%.2d')` tz (hours re-padded to 2).
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", None, Some("+1:00")).as_deref(),
    Some("2008:03:02 12:01:23+01:00")
  );
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", None, Some("-05:30")).as_deref(),
    Some("2008:03:02 12:01:23-05:30")
  );
}

#[test]
fn subsec_combines_fraction_and_offset() {
  // Both present ⇒ fraction first, then offset appended to the fraction'd value.
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", Some("16"), Some("+02:00")).as_deref(),
    Some("2008:03:02 12:01:23.16+02:00")
  );
}

#[test]
fn subsec_offset_skipped_when_base_already_signed() {
  // `$val[0]!~/[-+]/` — a base that already contains a sign suppresses the
  // offset branch. With no usable SubSecTime, `$v` is undef ⇒ not built.
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23-04:00", None, Some("+02:00")),
    None
  );
}

#[test]
fn subsec_malformed_offset_does_not_apply() {
  // OffsetTime not matching `^[-+]\d{1,2}:\d{2}` ⇒ the offset branch is skipped.
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", None, Some("Z")),
    None
  );
  assert_eq!(
    sub_sec_assemble("2008:03:02 12:01:23", None, Some("+5")),
    None
  );
}
