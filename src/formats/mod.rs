//! Dispatch registry: ExifTool file-type string → its parser
//! (ExifTool `%moduleName` → `Process<Type>`). Add one `match` arm per
//! ported format.

pub mod aac;
pub mod id3;
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
    "AAC" => Some(&aac::ProcessAac),   // ExifTool %moduleName{AAC}='AAC'
    "MP3" => Some(&id3::ProcessMp3),   // ExifTool %moduleName{MP3}='ID3' → ProcessMP3 (ID3.pm:1684)
    "MPC" => Some(&mpc::ProcessMpc),   // ExifTool %moduleName{MPC}=undef ⇒ 'MPC'
    "R3D" => Some(&red::ProcessR3D),   // ExifTool %moduleName{R3D}='Red'
    "WV" => Some(&wavpack::ProcessWv), // ExifTool %moduleName{WV}='WavPack'
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn registry_resolves_ported_formats() {
    // AAC, MP3 (ID3), MPC, R3D, and WV are the ported formats; their arms
    // must resolve. Unported types (and the empty string) must still cleanly
    // report "no parser" so the consumer falls through to the next detection
    // candidate (faithful to Perl: a Process<Type> not loaded is `next`
    // in the candidate loop, ExifTool.pm:3060-3077).
    assert!(parser_for("AAC").is_some());
    assert!(parser_for("MP3").is_some());
    assert!(parser_for("MPC").is_some());
    assert!(parser_for("R3D").is_some());
    assert!(parser_for("WV").is_some());
    assert!(parser_for("FLAC").is_none());
    assert!(parser_for("").is_none());
  }
}
