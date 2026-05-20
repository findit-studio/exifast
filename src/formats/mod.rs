//! Dispatch registry: ExifTool file-type string → its parser
//! (ExifTool `%moduleName` → `Process<Type>`). Add one `match` arm per
//! ported format.

pub mod aac;
pub mod aiff;
pub mod mpc;
pub mod red;
pub mod wavpack;

use crate::parser::FormatParser;

/// Returns the parser for a finalized ExifTool file type, or `None` if that
/// format has no ported parser yet.
#[must_use]
pub fn parser_for(file_type: &str) -> Option<&'static dyn FormatParser> {
  // `match` (not a static HashMap/phf): zero-alloc, branch-predicted; fine at ~28 formats.
  match file_type {
    "AAC" => Some(&aac::ProcessAac), // ExifTool %moduleName{AAC}='AAC'
    // ExifTool %fileTypeLookup maps AIFF/AIFC/AIF all to TYPE 'AIFF'; the
    // detection candidate for any of those extensions is "AIFF". The
    // parser itself differentiates AIFF vs AIFC via the magic body
    // (AIFF.pm:209-210 `$1` = "AIFF" or "AIFC") and drives the right
    // SetFileType.
    "AIFF" => Some(&aiff::ProcessAiff), // ExifTool %moduleName{AIFF}=undef ⇒ default to 'AIFF'
    "MPC" => Some(&mpc::ProcessMpc),    // ExifTool %moduleName{MPC}=undef ⇒ 'MPC'
    "R3D" => Some(&red::ProcessR3D),    // ExifTool %moduleName{R3D}='Red'
    "WV" => Some(&wavpack::ProcessWv),  // ExifTool %moduleName{WV}='WavPack'
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn registry_resolves_ported_formats() {
    // AAC, AIFF, MPC, R3D, and WV are the ported formats; their arms must
    // resolve. Unported types (and the empty string) must still cleanly
    // report "no parser" so the consumer falls through to the next detection
    // candidate (faithful to Perl: a Process<Type> not loaded is `next`
    // in the candidate loop, ExifTool.pm:3060-3077).
    assert!(parser_for("AAC").is_some());
    assert!(parser_for("AIFF").is_some());
    assert!(parser_for("MPC").is_some());
    assert!(parser_for("R3D").is_some());
    assert!(parser_for("WV").is_some());
    assert!(parser_for("MP3").is_none());
    assert!(parser_for("").is_none());
    // AIFC is NOT a candidate type (%fileTypeLookup{AIFC} resolves to
    // 'AIFF'); the parser differentiates AIFC at the magic level.
    assert!(parser_for("AIFC").is_none());
  }
}
