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

/// `%subSecConv` RawConv (Exif.pm:4726) — the shared assembly the three
/// `SubSecDateTimeOriginal` / `SubSecCreateDate` / `SubSecModifyDate`
/// composites use to fold a base `DateTime`, its `SubSecTime` fractional, and
/// its `OffsetTime` time-zone into one string. `date` is `$val[0]` (the base
/// `EXIF:DateTimeOriginal` / `…CreateDate` / `…ModifyDate`, a `Require`); `sub_sec`
/// is `$val[1]` (`SubSecTime…`, a `Desire`, `None` when absent); `offset` is
/// `$val[2]` (`OffsetTime…`, a `Desire`, `None` when absent).
///
/// ```perl
/// my $v;
/// if (defined $val[1] and $val[1]=~/^(\d+)/) {
///     my $subSec = $1;
///     undef $v unless ($v = $val[0]) =~ s/( \d{2}:\d{2}:\d{2})(?!\.\d+)/$1\.$subSec/;
/// }
/// if (defined $val[2] and $val[0]!~/[-+]/ and $val[2]=~/^([-+])(\d{1,2}):(\d{2})/) {
///     $v = ($v || $val[0]) . sprintf('%s%.2d:%.2d', $1, $2, $3);
/// }
/// return $v;
/// ```
///
/// `$v` starts undef and is set ONLY by a successful sub-second substitution OR
/// an applicable offset — so when the base has NEITHER a usable `SubSecTime`
/// NOR an `OffsetTime` (the common still-camera case) the composite is NOT
/// built (`return undef`). `None` ⇒ that composite emits nothing.
#[must_use]
pub(crate) fn sub_sec_assemble(
  date: &str,
  sub_sec: Option<&str>,
  offset: Option<&str>,
) -> Option<std::string::String> {
  // `my $v;` — undef until a branch sets it.
  let mut v: Option<std::string::String> = None;

  // `if (defined $val[1] and $val[1]=~/^(\d+)/)` — leading-digit prefix of
  // SubSecTime is the fractional `$subSec`. Then `($v = $val[0]) =~ s/(
  // \d{2}:\d{2}:\d{2})(?!\.\d+)/$1\.$subSec/` — insert `.$subSec` after the first
  // ` HH:MM:SS` not already carrying sub-seconds; `undef $v unless` it matched.
  if let Some(ss) = sub_sec
    && let Some(frac) = leading_digits(ss)
  {
    v = insert_subsec(date, frac);
  }

  // `if (defined $val[2] and $val[0]!~/[-+]/ and $val[2]=~/^([-+])(\d{1,2}):(\d{2})/)`
  // then `$v = ($v || $val[0]) . sprintf('%s%.2d:%.2d', $1, $2, $3)`. `($v ||
  // $val[0])` falls back to the base when `$v` is undef/empty.
  if let Some(off) = offset
    && !date.bytes().any(|b| b == b'-' || b == b'+')
    && let Some((sign, hh, mm)) = parse_offset(off)
  {
    let base = match v.as_deref() {
      Some(s) if !s.is_empty() => s,
      _ => date,
    };
    v = Some(std::format!("{base}{sign}{hh:02}:{mm:02}"));
  }

  v
}

/// `$s =~ /^(\d+)/` — the leading ASCII-digit run of `s`, or `None` when `s`
/// does not start with a digit. (`SubSecTime` is a fractional-seconds field,
/// e.g. `"16"` / `"0700"`; only the leading digits are the `$subSec` capture.)
fn leading_digits(s: &str) -> Option<&str> {
  let n = s.bytes().take_while(u8::is_ascii_digit).count();
  (n > 0).then(|| &s[..n])
}

/// `($v = $date) =~ s/( \d{2}:\d{2}:\d{2})(?!\.\d+)/$1.$subSec/` — find the
/// FIRST ` HH:MM:SS` (a space then three 2-digit colon-separated fields) NOT
/// immediately followed by `.<digit>` (the `(?!\.\d+)` lookahead, guarding a
/// time that already carries sub-seconds), and return `date` with `.<subSec>`
/// inserted directly after that match. `None` when no such position exists (the
/// Perl `s///` returned 0 ⇒ `undef $v`).
fn insert_subsec(date: &str, subsec: &str) -> Option<std::string::String> {
  let b = date.as_bytes();
  // The leftmost match wins (Perl `s///` without `/g`).
  let mut i = 0usize;
  while i + 9 <= b.len() {
    if b[i] == b' ' && is_hhmmss(&b[i + 1..i + 9]) {
      // `(?!\.\d+)` — the byte after the SS must NOT be `.` followed by a digit.
      let after = i + 9;
      let already_subsec =
        b.get(after) == Some(&b'.') && b.get(after + 1).is_some_and(u8::is_ascii_digit);
      if !already_subsec {
        // Insert `.<subSec>` after the matched ` HH:MM:SS` (byte `after`).
        let mut out = std::string::String::with_capacity(date.len() + 1 + subsec.len());
        out.push_str(&date[..after]);
        out.push('.');
        out.push_str(subsec);
        out.push_str(&date[after..]);
        return Some(out);
      }
    }
    i += 1;
  }
  None
}

/// Is `w` exactly the 8 bytes `DD:DD:DD` (two digits, colon, two digits, colon,
/// two digits)? The `\d{2}:\d{2}:\d{2}` body of the substitution pattern.
fn is_hhmmss(w: &[u8]) -> bool {
  w.len() == 8
    && w[0].is_ascii_digit()
    && w[1].is_ascii_digit()
    && w[2] == b':'
    && w[3].is_ascii_digit()
    && w[4].is_ascii_digit()
    && w[5] == b':'
    && w[6].is_ascii_digit()
    && w[7].is_ascii_digit()
}

/// `$off =~ /^([-+])(\d{1,2}):(\d{2})/` — a leading sign, 1-or-2-digit hours, a
/// colon, and 2-digit minutes (a trailing tail is ignored, matching the
/// unanchored-tail Perl match). Returns `(sign, hours, minutes)`; `None` on no
/// match. The values feed `sprintf('%s%.2d:%.2d', ...)` (hours re-padded to 2).
fn parse_offset(off: &str) -> Option<(char, u32, u32)> {
  let b = off.as_bytes();
  let sign = match b.first() {
    Some(b'-') => '-',
    Some(b'+') => '+',
    _ => return None,
  };
  // `(\d{1,2})` — one or two hour digits (greedy: take 2 if both are digits).
  let mut i = 1;
  if !b.get(i).is_some_and(u8::is_ascii_digit) {
    return None;
  }
  let h_start = i;
  i += 1;
  if b.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
  }
  let hours: u32 = off[h_start..i].parse().ok()?;
  // `:` then `(\d{2})` — exactly two minute digits.
  if b.get(i) != Some(&b':') {
    return None;
  }
  i += 1;
  if !(b.get(i).is_some_and(u8::is_ascii_digit) && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
    return None;
  }
  let minutes: u32 = off[i..i + 2].parse().ok()?;
  Some((sign, hours, minutes))
}

#[cfg(test)]
mod tests;
