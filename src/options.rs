// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Render-time options mirroring the ExifTool flags that change EMISSION, not
//! the always-on typed domain extraction.
//!
//! The parse walkers ALWAYS extract the full typed per-sample data (the domain
//! layer needs it regardless); only the rendered tag STREAM is gated. So these
//! options ride the same render path as the `-j`/`-n` `print_conv` toggle, not
//! the parse signature — see [`crate::parser::extract_info_with_options`] /
//! [`crate::format_parser::Rendered::new_with_options`].

/// Render/emit options. [`extract_embedded`](Self::extract_embedded) mirrors
/// ExifTool `-ee`: it gates whether the per-sample timed-metadata tags are
/// emitted, NOT whether they are parsed (the typed per-sample data — and thus
/// the domain `GpsLocation` — is parsed unconditionally).
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
  /// warning instead and the per-sample tags are suppressed; the typed
  /// per-sample data is ALWAYS parsed regardless, so the domain `GpsLocation`
  /// is unaffected by this flag.
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
