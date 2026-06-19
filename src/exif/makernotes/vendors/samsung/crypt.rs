// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Samsung Type2 encryption — `Image::ExifTool::Samsung::Crypt`
//! (`Samsung.pm:1579-1605`) and the `%formatMinMax` range table
//! (`Samsung.pm:60-65`).
//!
//! The `0xa021`..`0xa057` block stores raw-processing arrays (white-balance,
//! colour, tone-curve, …) encrypted with a per-file int32u[11] key carried in
//! `0xa020 EncryptionKey`. Each tag's winning `%Samsung::Type2` row has a
//! `RawConv => Image::ExifTool::Samsung::Crypt($self,$val,$tagInfo,SALT…)`; the
//! salt arguments select the key-index phase (and, for ARRAY tags, mark that
//! `$a[0]` is the array length to skip). A salt string beginning with `-`
//! REVERSES the cipher (the decrypt direction the extractor takes).
//!
//! This is a faithful 1:1 port: the loop structure, the
//! `($salt + $i - $start) % 11` key index, and the `min`/`max` integer
//! wrap-around all mirror the Perl verbatim. Proven byte-exact against bundled
//! ExifTool 13.59 on `tests/fixtures/SamsungNX500.srw` (all 16 decrypted Crypt
//! tags — see [`tests`]).

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::Format;
use std::string::String;
use std::vec::Vec;

/// One Crypt salt argument (`Samsung.pm` `Crypt(...,SALT…)`): a signed key-index
/// phase. The Perl salt is a string whose optional leading `-` sets the
/// direction (`$sign = ($salt =~ s/^-//) ? -1 : 1`) and whose remaining digits
/// give the phase (`"-0"` ⇒ sign −1, magnitude 0). The extractor (RawConv) salts
/// are all NEGATIVE-or-zero-sign (decrypt); the never-ported RawConvInv (write)
/// would use the positive complements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt {
  /// `-1` when the salt string began with `-` (reverse/decrypt), else `+1`.
  sign: i64,
  /// The magnitude (the digits after the optional `-`).
  magnitude: i64,
}

impl Salt {
  /// A decrypt salt `"-N"` (`$sign = -1`, magnitude `n`) — the leading-`-`
  /// form every `%Samsung::Type2` RawConv uses for a single-array tag's phase
  /// and for the second (Y-coordinate) array of the tone curves.
  #[must_use]
  #[inline(always)]
  pub const fn neg(magnitude: i64) -> Self {
    Self {
      sign: -1,
      magnitude,
    }
  }

  /// A `"N"` salt (`$sign = +1`, magnitude `n`) — the leading phase of the
  /// `int32s` colour matrices / `CbCrMatrix` and the X-coordinate array of the
  /// tone curves (`Crypt($self,$val,$tagInfo,0,"-0")`).
  #[must_use]
  #[inline(always)]
  pub const fn pos(magnitude: i64) -> Self {
    Self { sign: 1, magnitude }
  }
}

/// `%formatMinMax` (`Samsung.pm:60-65`) — the `[min, max]` value range for the
/// integer formats Crypt wraps within. `None` for a non-integer format (the
/// Perl `return undef unless $formatMinMax{$format}` guard — no Crypt row uses
/// a float/rational `Writable`, so this is never hit in practice).
#[must_use]
#[inline]
fn format_min_max(format: Format) -> Option<(i64, i64)> {
  match format {
    Format::Int16u => Some((0, 65535)),
    Format::Int32u => Some((0, 4_294_967_295)),
    Format::Int16s => Some((-32768, 32767)),
    Format::Int32s => Some((-2_147_483_648, 2_147_483_647)),
    _ => None,
  }
}

/// Decrypt (or encrypt) one Samsung Type2 value — the 1:1 port of
/// `Image::ExifTool::Samsung::Crypt` (`Samsung.pm:1579-1605`).
///
/// `vals` are the raw on-disk integers (`ReadValue`'s `@a = split ' ', $val`):
/// an int32u entry arrives via [`RawValue::U64`](crate::exif::ifd::RawValue) and
/// an int32s entry via `RawValue::I64`, both already widened to `i64` (an
/// int32u up to `4_294_967_295` is exact). `key` is the int32u[11]
/// `$$et{EncryptionKey}` captured at `0xa020`; `format` is the tag's `Writable`
/// (selecting `%formatMinMax`); `salts` are the row's `SALT…` arguments.
///
/// Returns the space-joined decrypted integers (ExifTool's `return "@a"`), or
/// `None` when the key is empty (`$key or return undef`) or the format has no
/// `%formatMinMax` entry (`return undef unless $formatMinMax{$format}`).
///
/// ## Algorithm (verbatim)
///
/// `$newSalt = (@salt > 1) ? 1 : 0` — skip the leading length entry `$a[0]` for
/// the two-array tone-curve tags. Then for each `$i` from `$newSalt`: at a
/// salt boundary (`$i == $newSalt`) record `$start = $i`, pop the next salt
/// (its sign + magnitude), and — if another salt remains — advance the next
/// boundary by the array length `$a[0]`. Each element is offset by
/// `$sign * $key[($salt + $i - $start) % 11]` and wrapped back into
/// `[min, max]` (subtract the span when a positive offset overflows `max`, add
/// it when a negative offset underflows `min`).
#[must_use]
pub fn crypt(vals: &[i64], key: &[i64], format: Format, salts: &[Salt]) -> Option<String> {
  if key.is_empty() {
    return None; // $key or return undef
  }
  let (min, max) = format_min_max(format)?;
  let span = (max - min) + 1;
  let key_len = key.len() as i64;

  let mut a: Vec<i64> = vals.to_vec();
  // $newSalt = (@salt > 1) ? 1 : 0 — skip the array-length entry for ARRAY tags.
  let mut new_salt: usize = usize::from(salts.len() > 1);
  let mut salt_iter = salts.iter();
  // The length entry $a[0] — read ONCE up front (the loop never mutates it,
  // since the boundary advance happens before $a[0] would be re-offset).
  let len_entry: i64 = a.first().copied().unwrap_or(0);

  let mut sign: i64 = 1;
  let mut salt: i64 = 0;
  let mut start: usize = 0;
  let mut i: usize = new_salt;
  while i < a.len() {
    if i == new_salt {
      start = i;
      // shift @salt — a missing salt leaves $salt/$sign undef in Perl, but the
      // ported tables always provide exactly enough salts, so a None here is a
      // table bug; fall back to the prior values rather than panic.
      if let Some(s) = salt_iter.next() {
        sign = s.sign;
        salt = s.magnitude;
      }
      // $newSalt += $a[0] if @salt — only when a further salt remains.
      if salt_iter.len() > 0 {
        new_salt = new_salt.saturating_add(usize::try_from(len_entry).unwrap_or(0));
      }
    }
    // $a[$i] += $sign * $$key[($salt + $i - $start) % scalar(@$key)]
    // ($i - $start) is non-negative (i >= start); ($salt + …) is non-negative
    // for these tables (salt >= 0), so the Perl `%` (which here acts on a
    // non-negative numerator) maps cleanly onto Rust's `rem_euclid`.
    let phase = salt + (i as i64 - start as i64);
    let k = key
      .get(phase.rem_euclid(key_len) as usize)
      .copied()
      .unwrap_or(0);
    if let Some(slot) = a.get_mut(i) {
      *slot += sign * k;
      // handle integer wrap-around
      if sign > 0 {
        if *slot > max {
          *slot -= span;
        }
      } else if *slot < min {
        *slot += span;
      }
    }
    i += 1;
  }

  // return "@a" — space-joined.
  let mut out = String::new();
  for (idx, v) in a.iter().enumerate() {
    if idx != 0 {
      out.push(' ');
    }
    use core::fmt::Write as _;
    let _ = write!(out, "{v}");
  }
  Some(out)
}

#[cfg(test)]
mod tests;
