// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Parse- and render-time options mirroring the ExifTool flags that change what
//! is extracted / emitted, not the always-on typed domain extraction.
//!
//! For MOST formats the parse walkers ALWAYS extract the full typed per-sample
//! data (the domain layer needs it regardless) and only the rendered tag STREAM
//! is gated, so [`extract_embedded`](ParseOptions::extract_embedded) rides the
//! render path beside the `-j`/`-n` `print_conv` toggle — see
//! [`crate::parser::extract_info_with_options`] /
//! [`crate::format_parser::Rendered::new_with_options`].
//!
//! ONE format (M2TS, M2TS.pm:347) makes the `-ee` full-scan-to-EOF part of the
//! PARSE itself: the LIGOGPSINFO dashcam-GPS PES sits near EOF and is reached
//! only when the walk extent is `-ee`-driven, so `extract_embedded` is ALSO
//! threaded into the parse signature there (the same `ParseOptions` value drives
//! both). [`crate::parse_bytes_with_options`] /
//! [`crate::media_metadata_with_options`] take `&ParseOptions` so a typed caller
//! gets the parse-time `-ee` walk (and thus the M2TS LIGOGPS
//! [`GpsLocation`](crate::metadata::GpsLocation) in
//! [`MediaMetadata::gps`](crate::metadata::MediaMetadata::gps)); the default
//! [`ParseOptions`] keeps the faithful no-`ee` baseline.

/// Parse + render options. [`extract_embedded`](Self::extract_embedded) mirrors
/// ExifTool `-ee`: for most formats it gates only whether the per-sample
/// timed-metadata tags are EMITTED (the typed per-sample data is parsed
/// unconditionally), but for M2TS it ALSO drives the parse-time walk extent that
/// reaches the LIGOGPSINFO dashcam-GPS PES near EOF (M2TS.pm:347), so an `-ee`
/// [`crate::parse_bytes_with_options`] / [`crate::media_metadata_with_options`]
/// is what surfaces the M2TS LIGOGPS GPS into the domain layer.
/// [`group3`](Self::group3) mirrors `-G3:1`: it switches the JSON key from the
/// default `-G1` (`<family1>:<name>`, the family-3 sub-document axis collapsed)
/// to `Doc<N>:<family1>:<name>` (one row per timed sample).
///
/// Construct with [`ParseOptions::default`] (everything off, the faithful
/// `perl exiftool -j -G1` baseline) and chain the builder setters. D8
/// convention: no public fields — accessor + `const fn` builder only.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
  extract_embedded: bool,
  /// `-G3:1` vs the default `-G1`. Stored as the crate-private
  /// [`GroupMode`](crate::serialize_key::GroupMode) so the public surface stays
  /// a plain `bool` (the enum is itself crate-internal).
  group3: bool,
}

impl ParseOptions {
  /// Enable ExifTool `-ee` (extract embedded): emit the per-sample timed
  /// metadata. Default off ⇒ the document carries the `[minor] ExtractEmbedded`
  /// warning instead and the per-sample tags are suppressed. For most formats
  /// the typed per-sample data is parsed regardless (only the rendered stream is
  /// gated); for M2TS this flag ALSO extends the parse-time walk to the
  /// near-EOF LIGOGPSINFO dashcam-GPS PES, so an M2TS LIGOGPS
  /// [`GpsLocation`](crate::metadata::GpsLocation) surfaces only when this is set
  /// on a parse-time options value ([`crate::parse_bytes_with_options`]).
  #[must_use]
  #[inline(always)]
  pub const fn with_extract_embedded(mut self, on: bool) -> Self {
    self.extract_embedded = on;
    self
  }

  /// Whether ExifTool `-ee` (extract embedded) is enabled (default `false`).
  #[must_use]
  #[inline(always)]
  pub const fn extract_embedded(&self) -> bool {
    self.extract_embedded
  }

  /// Select the `-G3:1` group rendering (every timed sample as a
  /// `Doc<N>:<family1>:<name>` row) instead of the default `-G1` (the doc axis
  /// collapsed, first-fix-wins). Off ⇒ `-G1`.
  #[must_use]
  #[inline(always)]
  pub const fn with_group3(mut self, on: bool) -> Self {
    self.group3 = on;
    self
  }

  /// Whether `-G3:1` rendering is selected (default `false` ⇒ `-G1`).
  #[must_use]
  #[inline(always)]
  pub const fn group3(&self) -> bool {
    self.group3
  }

  /// The crate-internal [`GroupMode`](crate::serialize_key::GroupMode) this
  /// option selects — `G3` when [`group3`](Self::group3) is set, else `G1`.
  #[cfg(feature = "alloc")]
  #[inline(always)]
  pub(crate) const fn group_mode(&self) -> crate::serialize_key::GroupMode {
    if self.group3 {
      crate::serialize_key::GroupMode::G3
    } else {
      crate::serialize_key::GroupMode::G1
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The default is the faithful baseline: `-ee` off.
  #[test]
  fn default_is_extract_embedded_off() {
    assert!(!ParseOptions::default().extract_embedded());
  }

  /// The builder flips `-ee` on and the accessor reads it back.
  #[test]
  fn with_extract_embedded_sets_the_flag() {
    assert!(
      ParseOptions::default()
        .with_extract_embedded(true)
        .extract_embedded()
    );
    // Idempotent / re-settable.
    assert!(
      !ParseOptions::default()
        .with_extract_embedded(true)
        .with_extract_embedded(false)
        .extract_embedded()
    );
  }
}
