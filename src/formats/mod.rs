//! Dispatch registry: ExifTool file-type string → its parser
//! (ExifTool `%moduleName` → `Process<Type>`). Add one `match` arm per
//! ported format.
//!
//! Each `pub mod <fmt>;` is gated on its Cargo feature (spec §4); the
//! corresponding `match` arm in [`parser_for`] is gated identically. When
//! a format feature is disabled, its file-type string returns `None`
//! (faithful to ExifTool's "Process<Type> not loaded → `next` in candidate
//! loop" behavior — ExifTool.pm:3060-3077).

#[cfg(feature = "aac")]
pub mod aac;
#[cfg(feature = "aiff")]
pub mod aiff;
#[cfg(feature = "ape")]
pub mod ape;
#[cfg(feature = "audible")]
pub mod audible;
#[cfg(feature = "dsf")]
pub mod dsf;
#[cfg(feature = "dv")]
pub mod dv;
#[cfg(feature = "flac")]
pub mod flac;
#[cfg(feature = "id3")]
pub mod id3;
#[cfg(feature = "mpc")]
pub mod mpc;
// MPEG audio frame parser is the internal `mpeg-audio` feature (gates
// `mp3` and is reused by other audio chained formats). Phase D may split
// `mpeg::audio` from a future `mpeg::video` submodule; today the file
// holds only the audio half (the video side is a Phase-2 forward item).
#[cfg(feature = "mpeg-audio")]
pub mod mpeg;
#[cfg(feature = "ogg")]
pub mod ogg;
#[cfg(feature = "red")]
pub mod red;
#[cfg(feature = "wavpack")]
pub mod wavpack;

use crate::parser::FormatParser;

/// Returns the parser for a finalized ExifTool file type, or `None` if that
/// format has no ported parser yet OR its Cargo feature is disabled.
///
/// When a format's feature is off, this returns `None` for the corresponding
/// file-type string — faithful to ExifTool's "module not loaded ⇒ `next` in
/// candidate loop" (ExifTool.pm:3060-3077). Callers see the same "no parser"
/// signal whether the format is unported or merely feature-pruned.
#[must_use]
pub fn parser_for(file_type: &str) -> Option<&'static dyn FormatParser> {
  // `match` (not a static HashMap/phf): zero-alloc, branch-predicted; fine at ~28 formats.
  match file_type {
    #[cfg(feature = "audible")]
    "AA" => Some(&audible::ProcessAa), // ExifTool %moduleName{AA}='Audible'
    #[cfg(feature = "aac")]
    "AAC" => Some(&aac::ProcessAac), // ExifTool %moduleName{AAC}='AAC'
    // ExifTool %fileTypeLookup maps AIFF/AIFC/AIF all to TYPE 'AIFF'; the
    // detection candidate for any of those extensions is "AIFF". The
    // parser itself differentiates AIFF vs AIFC via the magic body
    // (AIFF.pm:209-210 `$1` = "AIFF" or "AIFC") and drives the right
    // SetFileType.
    #[cfg(feature = "aiff")]
    "AIFF" => Some(&aiff::ProcessAiff), // ExifTool %moduleName{AIFF}=undef ⇒ default to 'AIFF'
    #[cfg(feature = "ape")]
    "APE" => Some(&ape::ProcessApe), // ExifTool %moduleName{APE}=undef ⇒ Perl $module=$type ⇒ "APE"
    // DSF: %moduleName absent ⇒ Perl `$module = $type` = 'DSF'; faithful to
    // ExifTool.pm:4203-4275 dispatch (`module_for_type("DSF")` returns
    // `Module(Cow::Owned("DSF"))` via the default arm in
    // `filetype_data.rs::module_for_type`).
    #[cfg(feature = "dsf")]
    "DSF" => Some(&dsf::ProcessDsf),
    #[cfg(feature = "dv")]
    "DV" => Some(&dv::ProcessDv), // ExifTool %moduleName{DV} default = 'DV'
    #[cfg(feature = "flac")]
    "FLAC" => Some(&flac::ProcessFlac), // ExifTool %moduleName{FLAC}='FLAC'
    // ExifTool.pm:893 maps `MP3 => 'ID3'` — ID3::ProcessMP3 (ID3.pm:1684-1729)
    // scans for ID3v1/v2 tags and then delegates the audio side to
    // `MPEG::ParseMPEGAudio` (ID3.pm:1716). Faithful: this arm is ID3's
    // wrapping parser; its no-ID3 branch calls back into
    // `mpeg::parse_mpeg_audio` (see `src/formats/id3/process.rs`). The
    // `mp3` feature implies both `id3` and `mpeg-audio` (Cargo.toml §
    // per-format gates), so `id3` is in scope whenever this arm compiles.
    #[cfg(feature = "mp3")]
    "MP3" => Some(&id3::ProcessMp3),
    #[cfg(feature = "mpc")]
    "MPC" => Some(&mpc::ProcessMpc), // ExifTool %moduleName{MPC}=undef ⇒ 'MPC'
    // ExifTool %moduleName{OGG}='Ogg' (handles OGG, OGV, OPUS via container
    // dispatch + OverrideFileType — Ogg.pm:49-50).
    #[cfg(feature = "ogg")]
    "OGG" => Some(&ogg::ProcessOgg),
    #[cfg(feature = "red")]
    "R3D" => Some(&red::ProcessR3D), // ExifTool %moduleName{R3D}='Red'
    #[cfg(feature = "wavpack")]
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
    // are the ported formats; their arms must resolve when their Cargo
    // features are enabled. Unported types (and the empty string) must
    // still cleanly report "no parser" so the consumer falls through to
    // the next detection candidate (faithful to Perl: a Process<Type>
    // not loaded is `next` in the candidate loop, ExifTool.pm:3060-3077).
    // Each assertion is feature-gated to match the corresponding `match`
    // arm in [`parser_for`].
    #[cfg(feature = "audible")]
    assert!(parser_for("AA").is_some());
    #[cfg(feature = "aac")]
    assert!(parser_for("AAC").is_some());
    #[cfg(feature = "aiff")]
    assert!(parser_for("AIFF").is_some());
    #[cfg(feature = "ape")]
    assert!(parser_for("APE").is_some());
    #[cfg(feature = "dsf")]
    assert!(parser_for("DSF").is_some());
    #[cfg(feature = "dv")]
    assert!(parser_for("DV").is_some());
    #[cfg(feature = "flac")]
    assert!(parser_for("FLAC").is_some());
    #[cfg(feature = "mp3")]
    assert!(parser_for("MP3").is_some());
    #[cfg(feature = "mpc")]
    assert!(parser_for("MPC").is_some());
    #[cfg(feature = "ogg")]
    assert!(parser_for("OGG").is_some());
    #[cfg(feature = "red")]
    assert!(parser_for("R3D").is_some());
    #[cfg(feature = "wavpack")]
    assert!(parser_for("WV").is_some());
    assert!(parser_for("MPEG").is_none()); // video side deferred (forward item)
    assert!(parser_for("").is_none());
    // AIFC is NOT a candidate type (%fileTypeLookup{AIFC} resolves to
    // 'AIFF'); the parser differentiates AIFC at the magic level.
    assert!(parser_for("AIFC").is_none());
  }
}
