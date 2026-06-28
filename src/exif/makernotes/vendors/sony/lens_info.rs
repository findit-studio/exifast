// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `GetLensInfo` — recover a focal-length / aperture range from a lens model
//! string (`Exif.pm:5825-5841`).
//!
//! `PrintLensID` (`Exif.pm:5881`, wired in a later chunk) calls this on the
//! printed `LensSpec` to obtain `(focalMin, focalMax, apertureMin,
//! apertureMax)` and disambiguate the float-keyed candidates of
//! [`super::lens_types`] / [`super::amount_lens_types`].
//!
//! Faithful to the ExifTool regex (the `$unk` flag — which permits `?`
//! placeholders — is unused on the Sony `LensSpec` path and is omitted):
//!
//! ```text
//! (\d+(?:\.\d+)?)(?:-(\d+(?:\.\d+)?))?\s*mm.*?(?:[fF]\/?\s*)(\d+(?:\.\d+)?)(?:-(\d+(?:\.\d+)?))?
//! ```
//!
//! The crate carries no regex engine (it is `no_std`), so the fixed-shape
//! pattern is matched by hand: an unanchored leftmost scan, the greedy
//! optional focal-range max (with backtrack to "absent"), the lazy `.*?`
//! gap (`.` = `[^\n]`), and the deterministic `[fF]\/?\s*` aperture head.

#![deny(clippy::indexing_slicing)]

/// Parse min/max focal length and min/max aperture from a lens model string.
///
/// Returns `(focalMin, focalMax, apertureMin, apertureMax)`, or `None` when
/// the string contains no `…mm … f/…` pattern. An absent range max equals the
/// min (`Exif.pm:5834-5835`, `$a[1] or $a[1] = $a[0]`).
#[must_use]
pub fn get_lens_info(lens: &str) -> Option<(f64, f64, f64, f64)> {
  let b = lens.as_bytes();
  // The pattern is unanchored: the engine takes the leftmost match, so try
  // each start position in turn and return the first that matches.
  for start in 0..b.len() {
    if let Some(m) = match_at(b, start) {
      return Some(m);
    }
  }
  None
}

/// Match the whole pattern anchored at `start`, mirroring the greedy/lazy/
/// backtracking choices of the Perl engine for this fixed shape.
fn match_at(b: &[u8], start: usize) -> Option<(f64, f64, f64, f64)> {
  // ($1) short focal — required `\d+(?:\.\d+)?`.
  let (f_min, p1) = parse_number(b, start)?;
  // (?:-($2))? long focal — greedy optional; on failure of the remainder,
  // backtrack to the "absent" branch.
  for take_long in [true, false] {
    let (f_max_s, p2) = if take_long {
      match parse_dash_number(b, p1) {
        Some((s, p)) => (Some(s), p),
        None => continue,
      }
    } else {
      (None, p1)
    };
    // `\s*mm`
    let p3 = skip_space(b, p2);
    let Some(p4) = match_mm(b, p3) else { continue };
    // `.*?` (lazy, `.` = `[^\n]`) then `(?:[fF]\/?\s*)($3)(?:-($4))?`.
    let mut j = p4;
    loop {
      if let Some((a_min, a_max_s)) = match_aperture(b, j) {
        return Some((
          f_min,
          default_max(f_min, f_max_s),
          a_min,
          default_max(a_min, a_max_s),
        ));
      }
      // Extend the lazy gap by one char; `.` cannot cross a newline or the end.
      match b.get(j) {
        Some(&c) if c != b'\n' => j += 1,
        _ => break,
      }
    }
  }
  None
}

/// Match `[fF]\/?\s*(\d+(?:\.\d+)?)(?:-(\d+(?:\.\d+)?))?` at `i`. Returns the
/// required min aperture and the optional max-aperture digit slice.
fn match_aperture(b: &[u8], i: usize) -> Option<(f64, Option<&[u8]>)> {
  match b.get(i) {
    Some(b'f' | b'F') => {}
    _ => return None,
  }
  let mut p = i + 1;
  if matches!(b.get(p), Some(b'/')) {
    p += 1;
  }
  p = skip_space(b, p);
  let (a_min, p3) = parse_number(b, p)?;
  // Trailing optional `-($4)`; nothing follows, so no backtrack is needed.
  let a_max_s = parse_dash_number(b, p3).map(|(s, _)| s);
  Some((a_min, a_max_s))
}

/// `\d+(?:\.\d+)?` at `i` → the matched digit slice and the end index.
fn parse_number_str(b: &[u8], i: usize) -> Option<(&[u8], usize)> {
  let mut j = i;
  while matches!(b.get(j), Some(c) if c.is_ascii_digit()) {
    j += 1;
  }
  if j == i {
    return None; // `\d+` needs at least one digit
  }
  // `(?:\.\d+)?` — only consume the dot when at least one digit follows it.
  if matches!(b.get(j), Some(b'.')) {
    let frac = j + 1;
    let mut k = frac;
    while matches!(b.get(k), Some(c) if c.is_ascii_digit()) {
      k += 1;
    }
    if k > frac {
      j = k;
    }
  }
  b.get(i..j).map(|s| (s, j))
}

/// As [`parse_number_str`] but also parses the slice to `f64`.
fn parse_number(b: &[u8], i: usize) -> Option<(f64, usize)> {
  let (s, j) = parse_number_str(b, i)?;
  Some((parse_f64(s)?, j))
}

/// Match `-` then a number; returns the number's digit slice and end index.
fn parse_dash_number(b: &[u8], i: usize) -> Option<(&[u8], usize)> {
  if !matches!(b.get(i), Some(b'-')) {
    return None;
  }
  parse_number_str(b, i + 1)
}

/// `\s*` — Perl `\s` = `[ \t\n\r\x0c\x0b]`. Returns the index past the run.
fn skip_space(b: &[u8], mut i: usize) -> usize {
  while matches!(b.get(i), Some(c) if is_perl_space(*c)) {
    i += 1;
  }
  i
}

/// `mm` literal at `i` → the index past it.
fn match_mm(b: &[u8], i: usize) -> Option<usize> {
  if matches!(b.get(i), Some(b'm')) && matches!(b.get(i + 1), Some(b'm')) {
    Some(i + 2)
  } else {
    None
  }
}

const fn is_perl_space(c: u8) -> bool {
  matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
}

/// Apply `$a[i] or $a[i] = $a[i-1]`: the optional max defaults to `min` when
/// the capture is absent or the Perl-false string `"0"`. Any other captured
/// number — including `"0.0"`/`"00"`, which Perl treats as true — is parsed.
fn default_max(min: f64, max_s: Option<&[u8]>) -> f64 {
  match max_s {
    Some(s) if !is_perl_false_number(s) => parse_f64(s).unwrap_or(min),
    _ => min,
  }
}

/// The only digit string Perl's boolean context treats as false is `"0"`.
fn is_perl_false_number(s: &[u8]) -> bool {
  s.len() == 1 && s.first() == Some(&b'0')
}

fn parse_f64(s: &[u8]) -> Option<f64> {
  core::str::from_utf8(s).ok()?.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Compare against values captured from the bundled
  /// `Image::ExifTool::Exif::GetLensInfo`.
  fn check(lens: &str, want: Option<(f64, f64, f64, f64)>) {
    assert_eq!(get_lens_info(lens), want, "lens = {lens:?}");
  }

  #[test]
  fn zoom_with_focal_and_aperture_ranges() {
    check("Sony DT 18-55mm F3.5-5.6 SAM", Some((18.0, 55.0, 3.5, 5.6)));
    check("Tamron 70-300mm F4-5.6 LD", Some((70.0, 300.0, 4.0, 5.6)));
    check(
      "Sony E PZ 16-50mm F3.5-5.6 OSS",
      Some((16.0, 50.0, 3.5, 5.6)),
    );
  }

  #[test]
  fn prime_defaults_max_to_min() {
    // No focal range and no aperture range: both maxes equal their mins.
    check("50mm F1.4", Some((50.0, 50.0, 1.4, 1.4)));
    check("Sigma 30mm F1.4 DC DN | C", Some((30.0, 30.0, 1.4, 1.4)));
    check("Viltrox 27mm F1.2 E Pro", Some((27.0, 27.0, 1.2, 1.2)));
    check("Samyang 500mm Mirror F8.0", Some((500.0, 500.0, 8.0, 8.0)));
  }

  #[test]
  fn zoom_constant_aperture() {
    check("Sony FE 24-70mm F2.8 GM", Some((24.0, 70.0, 2.8, 2.8)));
    check(
      "Sony FE 100-400mm F4.5 GM OSS",
      Some((100.0, 400.0, 4.5, 4.5)),
    );
    check(
      "Tamron SP 24-70mm F2.8 Di USD",
      Some((24.0, 70.0, 2.8, 2.8)),
    );
    // Leading "T*" must not be mistaken for the focal; leftmost real match wins.
    check(
      "Carl Zeiss Vario-Sonnar T* 24-70mm F2.8 ZA SSM II (SAL2470Z2)",
      Some((24.0, 70.0, 2.8, 2.8)),
    );
  }

  #[test]
  fn lowercase_f_and_slash() {
    // `[fF]\/?` accepts a lowercase `f` and an optional `/`.
    check("Some 35mm f/2", Some((35.0, 35.0, 2.0, 2.0)));
  }

  #[test]
  fn no_mm_no_aperture_is_none() {
    // A bare adapter name has a digit ("EA4") but no `mm … f/…` shape.
    check("Sony LA-EA4 Adapter", None);
    check("", None);
    check("Metabones Canon EF Speed Booster", None);
  }
}
