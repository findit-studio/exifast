// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-tag PrintConv for the Apple iOS MakerNotes table — small enum
//! over the bundled `PrintConv => { … }` hashes and inline sprintf
//! expressions in `Apple.pm`. The IFD walker calls
//! [`ApplePrintConv::apply`] at emit time with the decoded raw value.

#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;

/// One Apple tag's PrintConv strategy. Enum-newtype/unit-only (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplePrintConv {
  /// No PrintConv — emit the raw value as-is.
  None,
  /// `PrintConv => { 0 => 'No', 1 => 'Yes' }` (`Apple.pm:46-48`, `:59-61`).
  NoYes,
  /// `HDRImageType` — `PrintConv => { 3 => 'HDR Image', 4 => 'Original Image' }`
  /// (`Apple.pm:82-87`). Missing keys render as `Unknown (N)`.
  HdrImageType,
  /// `ImageCaptureType` (`Apple.pm:122-133`) —
  /// `{1=>'ProRAW', 2=>'Portrait', 10=>'Photo', 11=>'Manual Focus',
  /// 12=>'Scene'}`. Missing keys render `Unknown (N)`.
  ImageCaptureType,
  /// `CameraType` (`Apple.pm:221-229`) — `{0=>'Back Wide Angle',
  /// 1=>'Back Normal', 6=>'Front'}`. Missing keys render `Unknown (N)`.
  CameraType,
  /// `FocusDistanceRange` (`Apple.pm:94-103`) — 2 rational64s rendered
  /// `'%.2f - %.2f m'` (sorted smallest-first).
  FocusDistanceRange,
  /// `AFPerformance` (`Apple.pm:179-189`) — 2 int32s rendered as
  /// `'%d %d %d'` where the 3rd word is `(a1 << 28) + a2` reversed:
  /// bundled prints `$a[0]` then `$a[1] >> 28` then `$a[1] & 0xfffffff`.
  AfPerformance,
  /// One of the `ValueConv => \&ConvertPLIST` tags — the binary-PLIST
  /// payload. Phase 2 emits raw bytes (the PLIST sub-parser is a
  /// follow-up). The tag is named and surfaced; bundled would render a
  /// JSON-ish structured value, but the bytes carry the same info.
  PlistDeferred,
}

impl ApplePrintConv {
  /// Apply this PrintConv to the raw decoded value, returning a
  /// [`TagValue`] for the MakerNotes group sink.
  ///
  /// `print_conv = false` (-n mode) emits the post-ValueConv raw scalar;
  /// `print_conv = true` (the `-j` default) renders the human string.
  ///
  /// `raw_i64` is the first integer from the decoded value (the dominant
  /// Apple shape — most tags are int32s scalars). `raw` is the full
  /// decoded value for the tags that read multiple components.
  #[must_use]
  pub fn apply(self, raw: &super::body::ParsedValue, print_conv: bool) -> TagValue {
    match self {
      ApplePrintConv::None => raw.to_default_tag_value(),
      ApplePrintConv::NoYes => {
        let Some(n) = raw.first_i64() else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          match n {
            0 => TagValue::Str("No".into()),
            1 => TagValue::Str("Yes".into()),
            other => TagValue::Str(unknown_label(other).into()),
          }
        } else {
          TagValue::I64(n)
        }
      }
      ApplePrintConv::HdrImageType => {
        let Some(n) = raw.first_i64() else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          match n {
            3 => TagValue::Str("HDR Image".into()),
            4 => TagValue::Str("Original Image".into()),
            other => TagValue::Str(unknown_label(other).into()),
          }
        } else {
          TagValue::I64(n)
        }
      }
      ApplePrintConv::ImageCaptureType => {
        let Some(n) = raw.first_i64() else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          match n {
            1 => TagValue::Str("ProRAW".into()),
            2 => TagValue::Str("Portrait".into()),
            10 => TagValue::Str("Photo".into()),
            11 => TagValue::Str("Manual Focus".into()),
            12 => TagValue::Str("Scene".into()),
            other => TagValue::Str(unknown_label(other).into()),
          }
        } else {
          TagValue::I64(n)
        }
      }
      ApplePrintConv::CameraType => {
        let Some(n) = raw.first_i64() else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          match n {
            0 => TagValue::Str("Back Wide Angle".into()),
            1 => TagValue::Str("Back Normal".into()),
            6 => TagValue::Str("Front".into()),
            other => TagValue::Str(unknown_label(other).into()),
          }
        } else {
          TagValue::I64(n)
        }
      }
      ApplePrintConv::FocusDistanceRange => {
        // 2 rational64s; PrintConv `sprintf('%.2f - %.2f m', sorted_min, sorted_max)`.
        let pair = raw.rational_pair();
        let Some((a, b)) = pair else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
          TagValue::Str(SmolStr::from(std::format!("{lo:.2} - {hi:.2} m")))
        } else {
          // -n: emit "a b" (space-joined rationals' values).
          TagValue::Str(SmolStr::from(std::format!("{a} {b}")))
        }
      }
      ApplePrintConv::AfPerformance => {
        // Bundled: `my @a=split " ",$val; sprintf("%d %d %d", $a[0], $a[1]>>28, $a[1]&0xfffffff)`.
        // The decoded raw is 2 int32s; PrintConv expands the second to 2.
        let two = raw.first_two_i64();
        let Some((a0, a1)) = two else {
          return raw.to_default_tag_value();
        };
        if print_conv {
          // Faithful: take the int32 value of $a[1] and shift/mask.
          // Bundled uses signed int32s but the shift is on the bit pattern;
          // we follow Perl's coercion (mask to u32 first).
          let bits = (a1 as i32 as u32) as u64;
          let hi = (bits >> 28) as i64;
          let lo = (bits & 0xfff_ffff) as i64;
          TagValue::Str(SmolStr::from(std::format!("{a0} {hi} {lo}")))
        } else {
          TagValue::Str(SmolStr::from(std::format!("{a0} {a1}")))
        }
      }
      ApplePrintConv::PlistDeferred => raw.to_default_tag_value(),
    }
  }
}

/// `Unknown (N)` label — bundled `PrintConv` hash miss with no `OTHER`
/// defaults to this (per ExifTool's `EscapeJSON` numeric gate).
fn unknown_label(n: i64) -> String {
  std::format!("Unknown ({n})")
}
