// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag940e` (`Sony.pm:9750-9795`) — the enciphered
//! `Tag940e` `ProcessBinaryData` block (`TiffMeteringImage*`), the E-mount
//! variant of the `0x940e` dispatcher.
//!
//! The `0x940e` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:2094-2105`):
//!
//! - `AFInfo` — `$$self{Model} =~ /^(SLT-|HV|ILCA-)/` ⇒ the separate large
//!   `%Sony::AFInfo` AF-status table (`Sony.pm:9452+`), ported in [`super::afinfo`];
//!   for those bodies this module emits nothing.
//! - `Tag940e` — `$$self{Model} =~ /^(NEX-|ILCE-|Lunar)/` ⇒ this table.
//! - else `Sony_0x940e` (`%unknownCipherData`) — emits nothing.
//!
//! The block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`,
//! `Sony.pm:9751`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED
//! bytes; `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:9754,9755`).
//! NOTES: "E-mount models."
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]) AND its
//! per-leaf `Condition` holds. The ILME-FX3 matches neither the `AFInfo` nor the
//! `Tag940e` model gate (it is `ILME-`, not `ILCE-`), so ExifTool dispatches its
//! `0x940e` as `Sony_0x940e` and this table is never selected for it.

use crate::value::TagValue;

/// One emitted `Tag940e` leaf — the resolved tag name and rendered value.
pub struct Tag940eEmission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// `true` when `$$self{Model} =~ /^(NEX-|ILCE-|Lunar)/` selects the `Tag940e`
/// variant (`Sony.pm:2100`). Tested against the parent `$$self{Model}`. (The
/// `AFInfo` SLT/HV/ILCA variant is handled by the separate [`super::afinfo`]
/// table.)
#[must_use]
pub fn selects_tag940e(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("NEX-") || m.starts_with("ILCE-") || m.starts_with("Lunar"))
}

/// Walk the DECIPHERED `Tag940e` block and emit the `TiffMeteringImage*` leaves.
///
/// `buf` is the DECIPHERED `0x940e` block — the dispatcher already confirmed the
/// variant gate ([`selects_tag940e`]) and ran
/// [`process_enciphered`](super::decipher::process_enciphered). The three leaves
/// have NO PrintConv (raw `int8u`) / a fixed binary placeholder, so the render
/// is identical in `-j` and `-n` and the function takes no `print_conv` flag.
#[must_use]
pub fn parse_tag940e(
  buf: &[u8],
  model: Option<&str>,
  software: Option<&str>,
) -> Vec<Tag940eEmission> {
  let mut out = std::vec::Vec::new();

  // All three leaves share the same `Condition` (Sony.pm:9768-9772): an
  // ILCE-6300/6500/7M3/7RM2/7RM3(A)/7SM2/9 body (with a `\b` boundary) whose
  // Software is not an `ILCE-9 v5.0`/`v6.0` build.
  if !tiff_metering_condition(model, software) {
    return out;
  }

  // 0x1a06 TiffMeteringImageWidth — int8u, no PrintConv (Sony.pm:9768).
  if let Some(&raw) = buf.get(0x1a06) {
    out.push(Tag940eEmission {
      name: "TiffMeteringImageWidth",
      value: TagValue::I64(i64::from(raw)),
    });
  }

  // 0x1a07 TiffMeteringImageHeight — int8u, no PrintConv (Sony.pm:9769).
  if let Some(&raw) = buf.get(0x1a07) {
    out.push(Tag940eEmission {
      name: "TiffMeteringImageHeight",
      value: TagValue::I64(i64::from(raw)),
    });
  }

  // 0x1a08 TiffMeteringImage — undef[2640], ValueConv `return undef unless
  // length $val >= 2640; \ "Binary data 2640 bytes"` (Sony.pm:9770-9794). The
  // scalar-ref renders to the fixed placeholder in BOTH modes; emitted only when
  // the full 2640-byte field is in range.
  if buf.len() >= 0x1a08 + 2640 {
    out.push(Tag940eEmission {
      name: "TiffMeteringImage",
      value: TagValue::Str("(Binary data 2640 bytes, use -b option to extract)".into()),
    });
  }

  out
}

/// The shared `TiffMeteringImage*` `Condition` (`Sony.pm:9768`): the body model
/// matches `/^(ILCE-(6300|6500|7M3|7RM2|7RM3A?|7SM2|9))\b/` AND the Software
/// does NOT match `/^ILCE-9 (v5.0|v6.0)/`.
fn tiff_metering_condition(model: Option<&str>, software: Option<&str>) -> bool {
  tiff_metering_model(model) && !software_excluded(software)
}

/// `$$self{Model} =~ /^(ILCE-(6300|6500|7M3|7RM2|7RM3A?|7SM2|9))\b/`. Every
/// listed body ends in a word char (digit or `A`), so the Perl `\b` boundary
/// requires the char after the prefix to be a non-word char (or end-of-string)
/// — e.g. `ILCE-9` matches but `ILCE-9M2` does not.
fn tiff_metering_model(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  for prefix in [
    "ILCE-6300",
    "ILCE-6500",
    "ILCE-7M3",
    "ILCE-7RM2",
    "ILCE-7RM3A",
    "ILCE-7RM3",
    "ILCE-7SM2",
    "ILCE-9",
  ] {
    if let Some(rest) = m.strip_prefix(prefix)
      && rest
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    {
      return true;
    }
  }
  false
}

/// `$$self{Software} =~ /^ILCE-9 (v5.0|v6.0)/` — the excluded firmware builds
/// (the leaves are dropped for these). A `None`/non-matching Software is NOT
/// excluded (`undef !~ /…/` is true).
fn software_excluded(software: Option<&str>) -> bool {
  software.is_some_and(|s| s.starts_with("ILCE-9 v5.0") || s.starts_with("ILCE-9 v6.0"))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag940e_tests.rs"]
mod tests;
