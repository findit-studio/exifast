// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The single group-key join shared by every JSON serializer. `-G1` is the
//! default conformance form (`<family1>:<name>`, the doc axis collapsed); `-G3`
//! prefixes the sub-document (`Doc<N>:<family1>:<name>`, `Doc0`→Main→no prefix),
//! matching `exiftool -G3:1`.
#[cfg(feature = "alloc")]
use std::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupMode {
  /// `-G1`: collapse the doc axis (the conformance golden form).
  G1,
  /// `-G3`: `Doc<N>:` prefix for sub-documents — the render mode the
  /// timed-metadata emission path (`EmitOptions`/`emit_timed_samples`) selects
  /// to emit one row per `Doc<N>` sample (`-ee -G3:1`).
  G3,
}

/// Write the group key into a caller-owned buffer, CLEARING it first. This is
/// the hot-path form: a serializer reuses ONE `String` across its tag loop so
/// the join costs a single amortized allocation total (the Golden-v2 C4
/// allocation budget), not one per tag.
#[cfg(feature = "alloc")]
pub(crate) fn group_key_into(
  buf: &mut String,
  doc: u32,
  family1: &str,
  name: &str,
  mode: GroupMode,
) {
  use core::fmt::Write;
  buf.clear();
  if matches!(mode, GroupMode::G3) && doc != 0 {
    let _ = write!(buf, "Doc{doc}:");
  }
  buf.reserve(family1.len() + 1 + name.len());
  buf.push_str(family1);
  buf.push(':');
  buf.push_str(name);
}

/// Owned-`String` convenience for callers that need to keep the token (e.g. a
/// dedup `BTreeSet`). Allocates one `String`; prefer [`group_key_into`] in a loop.
#[cfg(feature = "alloc")]
pub(crate) fn group_key(doc: u32, family1: &str, name: &str, mode: GroupMode) -> String {
  let mut key = String::new();
  group_key_into(&mut key, doc, family1, name, mode);
  key
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
  use super::*;
  #[test]
  fn g1_collapses_doc_g3_prefixes_doc() {
    assert_eq!(
      group_key(0, "QuickTime", "GPSLatitude", GroupMode::G1),
      "QuickTime:GPSLatitude"
    );
    assert_eq!(
      group_key(2, "QuickTime", "GPSLatitude", GroupMode::G1),
      "QuickTime:GPSLatitude"
    );
    assert_eq!(
      group_key(0, "QuickTime", "TimeScale", GroupMode::G3),
      "QuickTime:TimeScale"
    );
    assert_eq!(
      group_key(1, "QuickTime", "GPSLatitude", GroupMode::G3),
      "Doc1:QuickTime:GPSLatitude"
    );
  }
}
