//! `$self->ConvertDateTime($val)` (ExifTool.pm:6574) for the Composite
//! `GPSDateTime` PrintConv.
//!
//! ExifTool's `ConvertDateTime` reformats a date/time string per the
//! `DateFormat` option and applies the `GlobalTimeShift` option. exifast
//! exposes NEITHER option (`$$self{OPTIONS}{DateFormat}` and
//! `{GlobalTimeShift}` are both unset), so both the `if ($shift)` block and the
//! `if ($fmt)` reformat block are skipped and the routine returns `$date`
//! unchanged. So at the default `-j`, `ConvertDateTime` is the IDENTITY — the
//! `GPSDateTime` ValueConv string (`"$datestamp $timestampZ"`) is also its
//! PrintConv form. (This mirrors the bundled-ExifTool golden, where
//! `Composite:GPSDateTime` is byte-identical in the `-j` and `-n` snapshots,
//! e.g. `2021:08:14 16:45:09Z`.)

/// `$self->ConvertDateTime($val)` at exifast's option set (no `DateFormat`, no
/// `GlobalTimeShift`) — the identity. Kept as a named helper so the GPSDateTime
/// def documents its PrintConv faithfully and a future `DateFormat` port has a
/// single seam.
#[must_use]
pub(crate) fn convert_date_time(val: &str) -> &str {
  val
}
