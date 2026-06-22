//! `Image::ExifTool::PrintIM` — the Print Image Matching directory reader
//! (PrintIM.pm, a faithful transliteration of `ProcessPrintIM`).
//!
//! PrintIM is a small Epson-proprietary structure carried as the EXIF IFD0 tag
//! `0xc4a5` (`Exif.pm:3280`, a `SubDirectory => { TagTable => PrintIM::Main }`)
//! and, on some vendors, as a MakerNote sub-directory tag `0x0e00`
//! (Sony/Panasonic/Nikon). Its `%PrintIM::Main` table emits ONE camera-relevant
//! tag — `PrintIMVersion` (PrintIM.pm:24-27, `PrintConv => undef` so it stays
//! the raw 4-char string) — under `GROUPS => { 0 => 'PrintIM', 1 => 'PrintIM',
//! 2 => 'Printing' }`. The numbered records 9-13 (`PIMContrast`/… ) are
//! commented out in `%PrintIM::Main`, so bundled emits NONE of them; this port
//! emits the version alone.
//!
//! ## The `ProcessPrintIM` block (PrintIM.pm:43-93)
//!
//! ```text
//! return 0 unless $size;                        # Warn 'Empty PrintIM data', 1 (MINOR)
//! return 0 unless $size > 15;                   # Warn 'Bad PrintIM data'
//! return 0 unless substr($dataPt,$off,7) eq 'PrintIM';  # 'Invalid PrintIM header'
//! my $num = Get16u($dataPt, $off + 14);
//! if ($size < 16 + $num * 6) {                  # size too big ⇒ wrong byte order
//!     ToggleByteOrder();
//!     $num = Get16u($dataPt, $off + 14);
//!     return 0 if $size < 16 + $num * 6;        # 'Bad PrintIM size'
//! }
//! HandleTag(PrintIMVersion, substr($dataPt, $off + 8, 4));   # the 4 ASCII bytes
//! # ... the numbered records (commented out — not emitted)
//! ```
//!
//! The `PrintIMVersion` value is the four bytes at `$off + 8` read as text (the
//! `substr` is byte-order-independent — it is the ASCII version like `"0300"`).
//! The `$num`-validation `ToggleByteOrder` only affects how the (un-emitted)
//! numbered records would be read; it does not change the version bytes, so the
//! port keeps the size-validation guard for fidelity (a structurally-invalid
//! block emits nothing) without needing the toggled order for the version.

use crate::exif::ifd::{ByteOrder, get_u16};

/// A `ProcessPrintIM` guard failure, carrying the FAITHFUL `$et->Warn(...)` text
/// AND its `sub Warn` severity so the caller can surface it on the shared
/// warning channel at ExifTool's exact level (`ExifTool.pm:5616-5630`):
///
/// * [`Minor`](Self::Minor) — `$et->Warn(msg, 1)`, the `,1` ignorable flag (→ a
///   `[minor] ` prefix). The ONLY PrintIM minor guard is the empty-block case
///   (`PrintIM.pm:52`, `$et->Warn('Empty PrintIM data', 1)`).
/// * [`Normal`](Self::Normal) — a plain `$et->Warn(msg)` (level 0, no prefix):
///   `'Bad PrintIM data'` (`PrintIM.pm:56`), `'Invalid PrintIM header'`
///   (`PrintIM.pm:60`) and `'Bad PrintIM size'` (`PrintIM.pm:70`).
///
/// The message is always a `&'static str` (the literal `ProcessPrintIM` warns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrintImError {
  /// A normal `$et->Warn(msg)` — `ignorable == 0`, no `[minor]` prefix.
  Normal(&'static str),
  /// A minor `$et->Warn(msg, 1)` — `ignorable == 1`, surfaced as `[minor] msg`.
  Minor(&'static str),
}

impl PrintImError {
  /// The bare `$et->Warn` message text (no `[minor]` prefix baked in — the
  /// prefix is applied centrally by `run_diagnostics`).
  pub(crate) const fn message(self) -> &'static str {
    match self {
      Self::Normal(m) | Self::Minor(m) => m,
    }
  }

  /// Whether this is the minor (`$et->Warn(msg, 1)`) case — the caller routes a
  /// `true` to the `[minor] ` (ignorable-`1`) warning path.
  pub(crate) const fn is_minor(self) -> bool {
    matches!(self, Self::Minor(_))
  }
}

/// The byte order's opposite — ExifTool's `ToggleByteOrder()` (ExifTool.pm:6171)
/// applied to the PrintIM `$num`-count re-read.
const fn toggled(order: ByteOrder) -> ByteOrder {
  match order {
    ByteOrder::Little => ByteOrder::Big,
    ByteOrder::Big => ByteOrder::Little,
  }
}

/// The 4-character `PrintIMVersion` (`"0300"`/`"0250"`/…) parsed from a PrintIM
/// block.
///
/// `Ok(version)` on a structurally-valid block; `Err(PrintImError)` carrying the
/// FAITHFUL `ProcessPrintIM` `$et->Warn(...)` text AND its severity when a guard
/// fails, so the caller can surface it on the shared warning channel at exactly
/// ExifTool's level — a file-level Warning, `[minor] `-prefixed iff the Perl site
/// passes the `,1` ignorable flag:
///
/// * [`Minor`](PrintImError::Minor)`("Empty PrintIM data")` (PrintIM.pm:52,
///   `$et->Warn(..., 1)`) — a zero-length block.
/// * [`Normal`](PrintImError::Normal)`("Bad PrintIM data")` (PrintIM.pm:56) —
///   `1..=15` bytes (`unless $size > 15`).
/// * [`Normal`](PrintImError::Normal)`("Invalid PrintIM header")` (PrintIM.pm:60)
///   — a missing `"PrintIM"` header.
/// * [`Normal`](PrintImError::Normal)`("Bad PrintIM size")` (PrintIM.pm:70) — a
///   `$num`-count too large for the block even after the byte-order toggle.
///
/// `block` is the SubDirectory value (the `0xc4a5` / `0x0e00` tag bytes);
/// `order` is the inherited TIFF byte order (`Get16u` reads the record count
/// with it, then toggles on a size mismatch). The version itself is read from
/// the fixed `block[8..12]` ASCII bytes — byte-order-independent.
pub(crate) fn parse_version(
  block: &[u8],
  order: ByteOrder,
) -> Result<smol_str::SmolStr, PrintImError> {
  // `return 0 unless $size` (PrintIM.pm:51-52) — `$et->Warn('Empty PrintIM
  // data', 1)` (the trailing `1` ⇒ MINOR/`[minor]`); then `return 0 unless
  // $size > 15` (:55-56) — `$et->Warn('Bad PrintIM data')` (no flag ⇒ NORMAL).
  // A zero-length block warns "empty" (minor); a non-empty but too-short one
  // warns "bad data" (normal).
  if block.is_empty() {
    return Err(PrintImError::Minor("Empty PrintIM data"));
  }
  if block.len() <= 15 {
    return Err(PrintImError::Normal("Bad PrintIM data"));
  }
  // `unless substr($$dataPt, $offset, 7) eq 'PrintIM'` (PrintIM.pm:59-60) — the
  // 7-byte ASCII header; `$et->Warn('Invalid PrintIM header')` (NORMAL).
  if block.get(0..7) != Some(b"PrintIM".as_slice()) {
    return Err(PrintImError::Normal("Invalid PrintIM header"));
  }
  // `my $num = Get16u($dataPt, $offset + 14)` + the size-vs-`16 + $num*6` check,
  // with a single byte-order toggle on overflow (PrintIM.pm:63-71). This
  // validates the structure faithfully; the version bytes do not depend on the
  // resolved order, so the toggle only gates the build.
  let size = block.len();
  let valid = |ord: ByteOrder| -> bool {
    match get_u16(block, 14, ord) {
      // `16 + $num * 6` in `usize` (the count is a `u16`, so the product cannot
      // overflow `usize`); a block smaller than that is rejected.
      Some(num) => size >= 16usize.saturating_add((num as usize).saturating_mul(6)),
      None => false,
    }
  };
  if !valid(order) && !valid(toggled(order)) {
    // `return 0` — `$et->Warn('Bad PrintIM size')` (NORMAL; the structure is
    // unusable in EITHER order).
    return Err(PrintImError::Normal("Bad PrintIM size"));
  }
  // `HandleTag(PrintIMVersion, substr($$dataPt, $offset + 8, 4))` (PrintIM.pm:
  // 72) — the four ASCII version bytes (`PrintConv => undef`, so raw text).
  // ExifTool's `substr` yields whatever bytes are there; the version is ASCII
  // digits in practice, read lossily into a `SmolStr`. The header + size guards
  // above already proved the block carries `>= 16` bytes, so `block[8..12]` is
  // in bounds.
  let bytes = block.get(8..12).unwrap_or_default();
  Ok(smol_str::SmolStr::from(
    String::from_utf8_lossy(bytes).as_ref(),
  ))
}

#[cfg(test)]
mod tests;
