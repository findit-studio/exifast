//! The `force_string` opt-out for the terminal `EscapeJSON` number-gate
//! (Contract B / #197).
//!
//! Contract B makes the EXIF JSON scalar typing TOKEN-EXACT: a string-origin
//! scalar whose entire text is an `EscapeJSON` number (`escape_json_is_number`)
//! is normally emitted as a BARE JSON number, reproducing ExifTool's
//! `EscapeJSON` quote-or-not gate (`exiftool:3809`). A small RESIDUAL set of
//! tags is the exception: ExifTool QUOTES them even though the value looks
//! numeric (e.g. a `PrintConv` that returns a deliberately-string value, an
//! ` exiftool` table that sets `Format`/`PrintConv` to keep a leading-zero or
//! identifier-shaped value a string). For those, [`is_forced_string`] returns
//! `true` and the serializer keeps the quoted-string form.
//!
//! The membership of that residual set is DISCOVERED against bundled ExifTool
//! 13.59 (the `force_string` direction of the cascade, Task B3/B4) and is
//! populated tag-by-tag. Until then this returns `false` for every tag, so the
//! gate applies uniformly (the discovery pass is what tells us which tags need
//! the opt-out).

/// Whether the `(group, tag)` pair is one ExifTool emits as a QUOTED JSON
/// string even when its value text is an `EscapeJSON` number — i.e. the
/// terminal number-gate must be SUPPRESSED for it (Contract B / #197).
///
/// `group` is the family-1 group the EXIF/GPS emitter passes (`IFD0`,
/// `ExifIFD`, `GPS`, …); `tag` is the tag NAME (`GPSLatitude`, `SubSecTime`,
/// …). Returns `false` for now — the residual set is populated from the
/// oracle-driven cascade discovery (Task B3/B4); an empty set means the gate
/// applies to every numeric-looking string scalar.
#[must_use]
#[inline]
pub fn is_forced_string(group: &str, tag: &str) -> bool {
  // Reference the params so this stays a `(group, tag) -> bool` predicate
  // (the residual set keys on both) without an `unused_variables` warning
  // while the set is empty.
  let _ = (group, tag);
  false
}
