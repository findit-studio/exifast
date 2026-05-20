//! Faithful port of `%pictureType` (ID3.pm:42-64). Shared `PrintConv` for
//! the ID3v2 PIC-2 / APIC-2 PictureType pseudo-field. (Note Perl ID3.pm:41:
//! "Duplicated in ID3, ASF and FLAC modules!" — when those format ports
//! land they re-cite this same table; we expose it here as the shared
//! source so the duplication stays in sync.)

use crate::tagtable::{PrintConvHash, PrintValue};

/// `%pictureType` (ID3.pm:42-64) as a hash PrintConv direct-entries slice.
pub const PICTURE_TYPE: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("Other")),
  ("1", PrintValue::Str("32x32 PNG Icon")),
  ("2", PrintValue::Str("Other Icon")),
  ("3", PrintValue::Str("Front Cover")),
  ("4", PrintValue::Str("Back Cover")),
  ("5", PrintValue::Str("Leaflet")),
  ("6", PrintValue::Str("Media")),
  ("7", PrintValue::Str("Lead Artist")),
  ("8", PrintValue::Str("Artist")),
  ("9", PrintValue::Str("Conductor")),
  ("10", PrintValue::Str("Band")),
  ("11", PrintValue::Str("Composer")),
  ("12", PrintValue::Str("Lyricist")),
  ("13", PrintValue::Str("Recording Studio or Location")),
  ("14", PrintValue::Str("Recording Session")),
  ("15", PrintValue::Str("Performance")),
  ("16", PrintValue::Str("Capture from Movie or Video")),
  ("17", PrintValue::Str("Bright(ly) Colored Fish")),
  ("18", PrintValue::Str("Illustration")),
  ("19", PrintValue::Str("Band Logo")),
  ("20", PrintValue::Str("Publisher Logo")),
];

/// The full `PrintConvHash` for the PIC-2/APIC-2 PictureType field.
pub const PICTURE_TYPE_HASH: PrintConvHash = PrintConvHash::direct(PICTURE_TYPE);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn picture_type_count_and_endpoints() {
    // ID3.pm:43-63 has exactly 21 entries (0..=20).
    assert_eq!(PICTURE_TYPE.len(), 21);
    assert_eq!(PICTURE_TYPE[0], ("0", PrintValue::Str("Other")));
    assert_eq!(PICTURE_TYPE[20], ("20", PrintValue::Str("Publisher Logo")));
    // ID3.pm:60 has the famous typo / Easter egg.
    assert_eq!(
      PICTURE_TYPE[17],
      ("17", PrintValue::Str("Bright(ly) Colored Fish"))
    );
  }
}
