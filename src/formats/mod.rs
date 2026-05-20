//! Dispatch registry: ExifTool file-type string → its parser
//! (ExifTool `%moduleName` → `Process<Type>`). Add one `match` arm per
//! ported format.

pub mod aac;
pub mod mpc;
pub mod mpeg;
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
    "MPC" => Some(&mpc::ProcessMpc), // ExifTool %moduleName{MPC}=undef ⇒ 'MPC'
    // ExifTool.pm:893 maps `MP3 => 'ID3'` — the ID3 module's
    // `ProcessMP3` scans for ID3v1/v2 tags and then delegates the audio
    // side to `MPEG.pm::ParseMPEGAudio`. The ID3 port is a parallel
    // pathfinder PR; until it lands, our MPEG audio-frame parser
    // registers DIRECTLY at "MP3" so MP3 files reach the audio-frame
    // parser. When ID3 merges, this arm is replaced by ID3's wrapping
    // parser (which calls back into `mpeg::parse_mpeg_audio` for the
    // audio side — see the `pub(crate)` re-export there).
    "MP3" => Some(&mpeg::ProcessMp3),
    "R3D" => Some(&red::ProcessR3D), // ExifTool %moduleName{R3D}='Red'
    "WV" => Some(&wavpack::ProcessWv), // ExifTool %moduleName{WV}='WavPack'
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn registry_resolves_ported_formats() {
    // AAC, MPC, MP3, R3D, and WV are the ported formats; their arms must resolve.
    // Unported types (and the empty string) must still cleanly report
    // "no parser" so the consumer falls through to the next detection
    // candidate (faithful to Perl: a Process<Type> not loaded is `next`
    // in the candidate loop, ExifTool.pm:3060-3077).
    assert!(parser_for("AAC").is_some());
    assert!(parser_for("MPC").is_some());
    assert!(parser_for("MP3").is_some());
    assert!(parser_for("R3D").is_some());
    assert!(parser_for("WV").is_some());
    assert!(parser_for("MPEG").is_none()); // video side deferred (forward item)
    assert!(parser_for("").is_none());
  }
}
