// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Samsung::Type2` IFD tag table (`Samsung.pm:129-648`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59 (Samsung.pm `$VERSION`
//! 1.51). Phase 1 ports the PLAIN scalar/enum/string/lookup LEAVES plus the
//! `0x0021 PictureWizard` `ProcessBinaryData` SubDirectory (whose five members
//! are surfaced by the capture loop, [`super::emit_picture_wizard`]).
//!
//! A "plain" leaf is one whose WINNING `%Samsung::Type2` row has NO
//! `RawConv => Image::ExifTool::Samsung::Crypt(...)` (and no `SubDirectory`).
//! Two such leaves live INSIDE the otherwise-Crypt `0xa02x` range and ARE
//! ported — ExifTool emits both at `-j`:
//!
//! - **`0xa020 EncryptionKey`** (`Samsung.pm:484-493`) — int32u Count 11. Its
//!   `RawConv` stores a split key in a DataMember but RETURNS `$val` unchanged,
//!   so the value is the RAW int32u[11] (the cleartext key); it is NOT a Crypt
//!   tag. `Protected => 1` gates writing only, not extraction.
//! - **`0xa025 HighlightLinearityLimit`** (`Samsung.pm:529-532`) — int32u, no
//!   conv. `0xa025` is the table's ONLY duplicate id: the earlier `DigitalGain`
//!   (`Samsung.pm:523`, a Crypt row) is OVERWRITTEN by this later plain row
//!   (Perl hash LAST-WINS), so the winning leaf is the raw int32u.
//!
//! ## Deferred (Phase 1+ follow-ups)
//!
//! - **The Crypt-encrypted block** `0xa021`..`0xa057` EXCEPT `0xa025` (i.e.
//!   `WB_RGGBLevels*`, `ColorMatrix*`, `CbCr*`, `ToneCurve*`,
//!   `RawData`/`Distortion`/`ChromaticAberration`/`Vignetting*`) — every one has
//!   a `RawConv => Image::ExifTool::Samsung::Crypt(...)` winning row
//!   (raw-processing data, not camera-indexing). These tag IDs are simply ABSENT
//!   from the table, so the shared `Walker` drops them (unknown-tag skip),
//!   exactly as Phase 1 intends; the conformance golden `-x`es them.
//! - **The remaining SubDirectory rows** `0x0011 OrientationInfo` (Gear 360
//!   only) and `0x0035 PreviewIFD` (a Nikon-PreviewIFD sub-IFD that emits under
//!   its own `PreviewIFD:` group) — deferred.
//!
//! ## The `0xa002 SerialNumber` value-`Condition`
//!
//! `0xa002 SerialNumber` is a PLAIN `Writable => 'string'` leaf, but bundled
//! gates it with `Condition => '$$valPt =~ /^\w{5}/'` (`Samsung.pm:404-409`):
//! emit it ONLY when the first five RAW value bytes are ASCII word characters
//! `[A-Za-z0-9_]`; otherwise `GetTagInfo` returns no tag and nothing is emitted.
//! The row is in the table ([`SAMSUNG_TAGS`]) like any other plain leaf; the
//! emission gate lives in
//! [`SamsungPrintConv::condition_holds`](super::printconv::SamsungPrintConv::condition_holds),
//! evaluated by `emit_samsung_value` (the Panasonic `single_hash_condition_holds`
//! shape). The NX500 fixture's `0xa002` fails the `/^\w{5}/` Condition, so
//! bundled emits no `Samsung:SerialNumber` for it and the golden is unchanged.

#![deny(clippy::indexing_slicing)]

use super::printconv::SamsungPrintConv;
use crate::exif::ifd::Format;
use crate::exif::makernotes::vendors::FormatOverride;

/// One Samsung Type2 IFD tag (or a `%Samsung::PictureWizard` member surfaced
/// via [`SubTable`]).
#[derive(Debug, Clone, Copy)]
pub struct SamsungTag {
  /// Tag ID (`Samsung.pm` Type2 hash key).
  pub id: u16,
  /// `Name => '…'` from bundled.
  pub name: &'static str,
  /// Conversion strategy.
  pub conv: SamsungPrintConv,
  /// `Some(SubTable::…)` when the tag is a SubDirectory pointer.
  pub sub_table: Option<SubTable>,
  /// `Unknown => 1` in bundled (`ExifTool.pm:9179-9185` suppresses such tags
  /// from default `-j` output). No Phase-1 leaf is `Unknown`.
  pub unknown: bool,
  /// `Some(FormatOverride)` when bundled carries a `Format => '…'` directive
  /// that RE-INTERPRETS the entry's on-disk bytes (`Exif.pm:6728-6745`).
  pub format: Option<FormatOverride>,
}

impl SamsungTag {
  /// The resolved tag name (`Name => '…'`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// The tag's optional `Format =>` directive (`Exif.pm:6728-6745`).
  #[must_use]
  #[inline(always)]
  pub const fn format_override(&self) -> Option<FormatOverride> {
    self.format
  }

  /// The tag's SubDirectory target, if any.
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<SubTable> {
    self.sub_table
  }

  /// `true` when bundled marks this tag `Unknown => 1`.
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// Samsung Type2 SubDirectory targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Samsung::PictureWizard` at `0x0021` (`Samsung.pm:650-705`) — a fixed
  /// `ProcessBinaryData` record (`FORMAT => 'int16u'`, `FIRST_ENTRY => 0`)
  /// carrying PictureWizardMode/Color/Saturation/Sharpness/Contrast.
  PictureWizard,
}

/// `%Samsung::Type2` (`Samsung.pm:129-648`) — Phase-1 plain leaves +
/// PictureWizard SubDirectory. Sorted by tag ID (binary-search-ready).
pub const SAMSUNG_TAGS: &[SamsungTag] = &[
  // 0x0001 MakerNoteVersion (Samsung.pm:135-139) — undef[4] rendered as the ASCII version string (e.g. "0100").
  SamsungTag {
    id: 0x0001,
    name: "MakerNoteVersion",
    conv: SamsungPrintConv::Version,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0002 DeviceType (Samsung.pm:140-152) — int32u, PrintHex label hash.
  SamsungTag {
    id: 0x0002,
    name: "DeviceType",
    conv: SamsungPrintConv::DeviceType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0003 SamsungModelID (Samsung.pm:153-245) — int32u, PrintHex lookup.
  SamsungTag {
    id: 0x0003,
    name: "SamsungModelID",
    conv: SamsungPrintConv::SamsungModelId,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0020 SmartAlbumColor (Samsung.pm:256-278) — int16u[2]. Branch 1 (the \0{4} "0 0"=>n/a) ported; branch 2's per-element color array is deferred (raw passthrough).
  SamsungTag {
    id: 0x0020,
    name: "SmartAlbumColor",
    conv: SamsungPrintConv::SmartAlbumColor,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0021 PictureWizard (Samsung.pm:279-283) — int16u SubDirectory → %Samsung::PictureWizard ProcessBinaryData (descended in the capture loop).
  SamsungTag {
    id: 0x0021,
    name: "PictureWizard",
    conv: SamsungPrintConv::None,
    sub_table: Some(SubTable::PictureWizard),
    unknown: false,
    format: None,
  },
  // 0x0030 LocalLocationName (Samsung.pm:291-298) — Format 'undef', Writable 'string', no PrintConv; ValueConv truncates at the first double-NUL and turns each NUL+spaces separator into a newline.
  SamsungTag {
    id: 0x0030,
    name: "LocalLocationName",
    conv: SamsungPrintConv::LocalLocationName,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Undef, None)),
  },
  // 0x0031 LocationName (Samsung.pm:299-303) — string.
  SamsungTag {
    id: 0x0031,
    name: "LocationName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0040 RawDataByteOrder (Samsung.pm:334-340) — label hash.
  SamsungTag {
    id: 0x0040,
    name: "RawDataByteOrder",
    conv: SamsungPrintConv::RawDataByteOrder,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0041 WhiteBalanceSetup (Samsung.pm:341-348) — int32u, 0=>Auto 1=>Manual.
  SamsungTag {
    id: 0x0041,
    name: "WhiteBalanceSetup",
    conv: SamsungPrintConv::WhiteBalanceSetup,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0043 CameraTemperature (Samsung.pm:349-356) — rational64s, "$val C" when numeric.
  SamsungTag {
    id: 0x0043,
    name: "CameraTemperature",
    conv: SamsungPrintConv::CameraTemperature,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0050 RawDataCFAPattern (Samsung.pm:361-368) — label hash.
  SamsungTag {
    id: 0x0050,
    name: "RawDataCFAPattern",
    conv: SamsungPrintConv::RawDataCfaPattern,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0100 FaceDetect (Samsung.pm:381-385) — int16u, 0=>Off 1=>On.
  SamsungTag {
    id: 0x0100,
    name: "FaceDetect",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0120 FaceRecognition (Samsung.pm:388-392) — int32u, 0=>Off 1=>On.
  SamsungTag {
    id: 0x0120,
    name: "FaceRecognition",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0123 FaceName (Samsung.pm:393) — string.
  SamsungTag {
    id: 0x0123,
    name: "FaceName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa001 FirmwareName (Samsung.pm:399-403) — string.
  SamsungTag {
    id: 0xa001,
    name: "FirmwareName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa002 SerialNumber (Samsung.pm:404-409) — string, no PrintConv. Gated by a
  // `Condition => '$$valPt =~ /^\w{5}/'` value-Condition (emit only when the
  // first five RAW value bytes are ASCII word chars); the emission gate lives in
  // `SamsungPrintConv::condition_holds`, applied by `emit_samsung_value`.
  SamsungTag {
    id: 0xa002,
    name: "SerialNumber",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa003 LensType (Samsung.pm:410-416) — int16u Count -1, %samsungLensTypes lookup.
  SamsungTag {
    id: 0xa003,
    name: "LensType",
    conv: SamsungPrintConv::LensType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa004 LensFirmware (Samsung.pm:417-421) — string.
  SamsungTag {
    id: 0xa004,
    name: "LensFirmware",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa005 InternalLensSerialNumber (Samsung.pm:422-426) — string.
  SamsungTag {
    id: 0xa005,
    name: "InternalLensSerialNumber",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa010 SensorAreas (Samsung.pm:427-433) — int32u[8], raw space-joined.
  SamsungTag {
    id: 0xa010,
    name: "SensorAreas",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa011 ColorSpace (Samsung.pm:434-441) — int16u, 0=>sRGB 1=>Adobe RGB.
  SamsungTag {
    id: 0xa011,
    name: "ColorSpace",
    conv: SamsungPrintConv::ColorSpace,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa012 SmartRange (Samsung.pm:442-446) — int16u, 0=>Off 1=>On.
  SamsungTag {
    id: 0xa012,
    name: "SmartRange",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa013 ExposureCompensation (Samsung.pm:447-450) — rational64s, raw.
  SamsungTag {
    id: 0xa013,
    name: "ExposureCompensation",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa014 ISO (Samsung.pm:451-454) — int32u, raw.
  SamsungTag {
    id: 0xa014,
    name: "ISO",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa018 ExposureTime (Samsung.pm:455-462) — rational64u, first-value ValueConv + PrintExposureTime.
  SamsungTag {
    id: 0xa018,
    name: "ExposureTime",
    conv: SamsungPrintConv::ExposureTime,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa019 FNumber (Samsung.pm:463-471) — rational64u, Priority 0, first-value ValueConv + %.1f.
  SamsungTag {
    id: 0xa019,
    name: "FNumber",
    conv: SamsungPrintConv::FNumber,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa01a FocalLengthIn35mmFormat (Samsung.pm:472-481) — Format int32u, ValueConv /10, "$val mm".
  SamsungTag {
    id: 0xa01a,
    name: "FocalLengthIn35mmFormat",
    conv: SamsungPrintConv::FocalLength35,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32u, None)),
  },
  // 0xa020 EncryptionKey (Samsung.pm:484-493) — int32u Count 11. Its
  // `RawConv => '$$self{EncryptionKey} = [ split(" ",$val) ]; $val'` STORES the
  // split key in a DataMember but RETURNS `$val` UNCHANGED — so the emitted value
  // is the RAW int32u[11], space-joined (the cleartext key, NOT a Crypt tag).
  // `Protected => 1` gates writing only, not extraction, so ExifTool emits it at
  // `-j` (oracle: NX500 = "305 72 737 456 282 307 519 724 13 505 193"). Plain leaf.
  SamsungTag {
    id: 0xa020,
    name: "EncryptionKey",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa025 HighlightLinearityLimit (Samsung.pm:529-532) — int32u, NO RawConv =
  // PLAIN. 0xa025 has a DUPLICATE row: Samsung.pm:523 (DigitalGain, RawConv =>
  // Samsung::Crypt) is OVERWRITTEN by this later HighlightLinearityLimit row
  // (Perl hash LAST-WINS), which has no conv ⇒ the emitted value is the RAW
  // int32u (oracle: NX500 = 3791). Plain leaf — NOT the deferred Crypt block.
  SamsungTag {
    id: 0xa025,
    name: "HighlightLinearityLimit",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
];

/// Resolve a Samsung Type2 tag by ID. `None` ⇒ not a Phase-1 ported tag (the
/// shared `Walker` then drops it, the unknown-tag skip).
#[must_use]
pub fn lookup(tag_id: u16) -> Option<&'static SamsungTag> {
  match SAMSUNG_TAGS.binary_search_by_key(&tag_id, |t| t.id) {
    Ok(i) => SAMSUNG_TAGS.get(i),
    Err(_) => None,
  }
}

/// The `Format =>` directive's FORMAT for tag `id` under `%Samsung::Type2`, if
/// any — the per-table override the shared `Walker` resolves when
/// `active_table == Samsung` (`Exif.pm:6729`). `None` for an unknown tag or a
/// tag with no directive. Returns the bare [`Format`] (the Walker recomputes
/// the count per `int(size/elemsize)`), matching the Sony/Pentax shape.
#[must_use]
pub fn format_override(id: u16) -> Option<Format> {
  lookup(id)
    .and_then(SamsungTag::format_override)
    .map(FormatOverride::format)
}

#[cfg(test)]
mod tests;
