//! Dispatch registry: ExifTool file-type string → its parser
//! (ExifTool `%moduleName` → `Process<Type>`). Add one `match` arm per
//! ported format.

pub mod aac;
pub mod aiff;
pub mod ape;
pub mod audible;
pub mod dsf;
pub mod dv;
pub mod flac;
pub mod id3;
pub mod mpc;
pub mod mpeg;
pub mod ogg;
pub mod red;
pub mod wavpack;

use crate::parser::FormatParser;

/// Returns the parser for a finalized ExifTool file type, or `None` if that
/// format has no ported parser yet.
#[must_use]
pub fn parser_for(file_type: &str) -> Option<&'static dyn FormatParser> {
  // `match` (not a static HashMap/phf): zero-alloc, branch-predicted; fine at ~28 formats.
  match file_type {
    "AA" => Some(&audible::ProcessAa), // ExifTool %moduleName{AA}='Audible'
    "AAC" => Some(&aac::ProcessAac),   // ExifTool %moduleName{AAC}='AAC'
    // ExifTool %fileTypeLookup maps AIFF/AIFC/AIF all to TYPE 'AIFF'; the
    // detection candidate for any of those extensions is "AIFF". The
    // parser itself differentiates AIFF vs AIFC via the magic body
    // (AIFF.pm:209-210 `$1` = "AIFF" or "AIFC") and drives the right
    // SetFileType.
    "AIFF" => Some(&aiff::ProcessAiff), // ExifTool %moduleName{AIFF}=undef ⇒ default to 'AIFF'
    "APE" => Some(&ape::ProcessApe), // ExifTool %moduleName{APE}=undef ⇒ Perl $module=$type ⇒ "APE"
    // DSF: %moduleName absent ⇒ Perl `$module = $type` = 'DSF'; faithful to
    // ExifTool.pm:4203-4275 dispatch (`module_for_type("DSF")` returns
    // `Module(Cow::Owned("DSF"))` via the default arm in
    // `filetype_data.rs::module_for_type`).
    "DSF" => Some(&dsf::ProcessDsf),
    "DV" => Some(&dv::ProcessDv), // ExifTool %moduleName{DV} default = 'DV'
    "FLAC" => Some(&flac::ProcessFlac), // ExifTool %moduleName{FLAC}='FLAC'
    // ExifTool.pm:893 maps `MP3 => 'ID3'` — ID3::ProcessMP3 (ID3.pm:1684-1729)
    // scans for ID3v1/v2 tags and then delegates the audio side to
    // `MPEG::ParseMPEGAudio` (ID3.pm:1716). Faithful: this arm is ID3's
    // wrapping parser; its no-ID3 branch calls back into
    // `mpeg::parse_mpeg_audio` (see `src/formats/id3/process.rs`).
    "MP3" => Some(&id3::ProcessMp3),
    "MPC" => Some(&mpc::ProcessMpc), // ExifTool %moduleName{MPC}=undef ⇒ 'MPC'
    // ExifTool %moduleName{OGG}='Ogg' (handles OGG, OGV, OPUS via container
    // dispatch + OverrideFileType — Ogg.pm:49-50).
    "OGG" => Some(&ogg::ProcessOgg),
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
    // AA, AAC, AIFF, APE, DSF, DV, FLAC, MP3 (ID3), MPC, OGG, R3D, and WV
    // are the ported formats; their arms must resolve. Unported types (and
    // the empty string) must still cleanly report "no parser" so the
    // consumer falls through to the next detection candidate (faithful
    // to Perl: a Process<Type> not loaded is `next` in the candidate
    // loop, ExifTool.pm:3060-3077).
    assert!(parser_for("AA").is_some());
    assert!(parser_for("AAC").is_some());
    assert!(parser_for("AIFF").is_some());
    assert!(parser_for("APE").is_some());
    assert!(parser_for("DSF").is_some());
    assert!(parser_for("DV").is_some());
    assert!(parser_for("FLAC").is_some());
    assert!(parser_for("MP3").is_some());
    assert!(parser_for("MPC").is_some());
    assert!(parser_for("OGG").is_some());
    assert!(parser_for("R3D").is_some());
    assert!(parser_for("WV").is_some());
    assert!(parser_for("MPEG").is_none()); // video side deferred (forward item)
    assert!(parser_for("").is_none());
    // AIFC is NOT a candidate type (%fileTypeLookup{AIFC} resolves to
    // 'AIFF'); the parser differentiates AIFC at the magic level.
    assert!(parser_for("AIFC").is_none());
  }
}
