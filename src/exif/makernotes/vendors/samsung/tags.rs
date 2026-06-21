// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Samsung::Type2` IFD tag table (`Samsung.pm:129-648`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59 (Samsung.pm `$VERSION`
//! 1.51). Ports the PLAIN scalar/enum/string/lookup LEAVES, the
//! `0x0021 PictureWizard` `ProcessBinaryData` SubDirectory (whose five members
//! are surfaced by the capture loop, [`super::emit_picture_wizard`]), and the
//! 16 Crypt-encrypted leaves (#242, see below).
//!
//! A "plain" leaf is one whose WINNING `%Samsung::Type2` row has NO
//! `RawConv => Image::ExifTool::Samsung::Crypt(...)` (and no `SubDirectory`).
//! Two such leaves live INSIDE the otherwise-Crypt `0xa02x` range and ARE
//! ported — ExifTool emits both at `-j`:
//!
//! - **`0xa020 EncryptionKey`** (`Samsung.pm:484-493`) — int32u Count 11. Its
//!   `RawConv` stores a split key in a DataMember but RETURNS `$val` unchanged,
//!   so the value is the RAW int32u[11] (the cleartext key); it is NOT a Crypt
//!   tag. `Protected => 1` gates writing only, not extraction. The isolated
//!   Samsung walker ALSO captures this raw key as the [`super::crypt::crypt`]
//!   key for the rows below.
//! - **`0xa025 HighlightLinearityLimit`** (`Samsung.pm:529-532`) — int32u, no
//!   conv. `0xa025` is the table's ONLY duplicate id: the earlier `DigitalGain`
//!   (`Samsung.pm:523`, a Crypt row) is OVERWRITTEN by this later plain row
//!   (Perl hash LAST-WINS), so the winning leaf is the raw int32u.
//!
//! ## The Crypt-encrypted block (#242)
//!
//! The 16 EMITTED encrypted leaves carry a [`CryptTag`] directive (the row's
//! `Writable` format + `Crypt(...,SALT…)` salts): `WB_RGGBLevels*`
//! (`0xa021`-`0xa024`, `0xa028`), `ColorMatrix*` (`0xa030`-`0xa032`), `CbCr*`
//! (`0xa033`-`0xa036`), `ToneCurve*` (`0xa040`-`0xa043`). The isolated Samsung
//! walker decrypts each with the captured `EncryptionKey` ([`super::crypt`]),
//! emitting the plaintext space-joined integers byte-exactly to bundled
//! ExifTool (proven on `tests/fixtures/SamsungNX500.srw`).
//!
//! ## The `0x0035 PreviewIFD` SubDirectory (#242)
//!
//! `0x0035 PreviewIFD` (`Samsung.pm:307-327`) points (`Flags => 'SubIFD'`,
//! `ByteOrder => Unknown`, `Start => '$val'`, `GROUPS => { 1 => PreviewIFD }`)
//! at `%Image::ExifTool::Nikon::PreviewIFD`, gated `$$self{TIFF_TYPE} eq "SRW"`.
//! The row carries [`SubTable::PreviewIfd`]; the shared `Walker` descends it
//! IN-WALK (while the Type2 FixBase correction is live) under
//! [`crate::exif::tables::NIKON_PREVIEW_IFD_TAGS`], emitting the 8 PreviewIFD
//! tags (incl. the `0x201`/`0x202` → `PreviewIFD:PreviewImage` DataTag pair)
//! byte-exactly to bundled (proven on `tests/fixtures/SamsungNX500.srw`).
//!
//! ## Deferred
//!
//! - **The `Unknown => 1` Crypt rows** `0xa048 RawData`, `0xa050 Distortion`,
//!   `0xa051 ChromaticAberration`, `0xa052`-`0xa054 Vignetting*`, and the
//!   `Hidden` `0xa055`-`0xa057` — every one is `Unknown => 1`, which
//!   ExifTool suppresses from default `-j` output (`ExifTool.pm:9179-9185`), so
//!   they are NOT among the 16 emitted and are simply ABSENT from the table.
//! - **The remaining SubDirectory row** `0x0011 OrientationInfo` (Gear 360
//!   only) — deferred (not present in the NX500 fixture, so not
//!   camera-indexing-proven; crafted-input only). The `0x0035 PreviewIFD`
//!   EK-GN120 alternate arm (`Start => '$val - 36'`) is handled but unproven
//!   (no EK-GN120 fixture).
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

use super::crypt::Salt;
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
  /// `Some(CryptTag)` when the winning row has a
  /// `RawConv => Image::ExifTool::Samsung::Crypt($self,$val,$tagInfo,SALT…)`
  /// (`Samsung.pm:1579-1605`). The isolated Samsung walker decrypts the raw
  /// integers with the captured `0xa020 EncryptionKey` + these salts + the
  /// tag's `Writable` format, emitting the space-joined plaintext. `None` for a
  /// plain leaf.
  pub crypt: Option<CryptTag>,
}

/// The `Image::ExifTool::Samsung::Crypt` directive carried by an encrypted
/// `%Samsung::Type2` row (`0xa021`..`0xa057`): the `Writable` format (selecting
/// `%formatMinMax`) and the `SALT…` arguments. Decrypted by
/// [`super::crypt::crypt`] with the per-file `EncryptionKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptTag {
  /// The tag's `Writable => '…'` integer format — selects the `%formatMinMax`
  /// `[min, max]` wrap range.
  format: Format,
  /// The row's `Crypt(...,SALT…)` salt arguments (one per stored array; the
  /// tone curves carry two).
  salts: &'static [Salt],
}

impl CryptTag {
  /// The `Writable` format selecting the `%formatMinMax` wrap range.
  #[must_use]
  #[inline(always)]
  pub const fn format(&self) -> Format {
    self.format
  }

  /// The `Crypt(...,SALT…)` salt arguments.
  #[must_use]
  #[inline(always)]
  pub const fn salts(&self) -> &'static [Salt] {
    self.salts
  }
}

impl SamsungTag {
  /// The resolved tag name (`Name => '…'`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// The ExifTool `Priority => N` of this `%Samsung::Main` leaf — `0` for a
  /// `Priority => 0` row (never overrides an earlier same-`(doc, family1, name)`
  /// tag, `ExifTool.pm:9544-9560`), `1` (the default) otherwise. The two walked
  /// `Priority => 0` rows are `0xa019 FNumber` (`Samsung.pm:465`) and `0xa01a
  /// FocalLengthIn35mmFormat` (`Samsung.pm:475`).
  #[must_use]
  #[inline(always)]
  pub const fn tag_priority(&self) -> u8 {
    match self.id {
      0xa019 | 0xa01a => 0,
      _ => 1,
    }
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

  /// The tag's `Samsung::Crypt` directive, if its winning row carries one.
  #[must_use]
  #[inline(always)]
  pub const fn crypt(&self) -> Option<CryptTag> {
    self.crypt
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
  /// `%Image::ExifTool::Nikon::PreviewIFD` at `0x0035` (`Samsung.pm:307-327`) —
  /// a SUB-IFD (`Flags => 'SubIFD'`, `ByteOrder => Unknown`, `Start => '$val'`,
  /// `GROUPS => { 1 => PreviewIFD }`), gated `$$self{TIFF_TYPE} eq "SRW"` (the
  /// main arm also `&& Model ne "EK-GN120"`, whose alternate arm uses
  /// `Start => '$val - 36'`). The Samsung isolated walker descends it on its own
  /// walker so the child `0x201`/`0x202` offset pair flows through the post-IFD
  /// DataTag pass into `PreviewIFD:PreviewImage` (#242).
  PreviewIfd,
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
    crypt: None,
  },
  // 0x0002 DeviceType (Samsung.pm:140-152) — int32u, PrintHex label hash.
  SamsungTag {
    id: 0x0002,
    name: "DeviceType",
    conv: SamsungPrintConv::DeviceType,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0003 SamsungModelID (Samsung.pm:153-245) — int32u, PrintHex lookup.
  SamsungTag {
    id: 0x0003,
    name: "SamsungModelID",
    conv: SamsungPrintConv::SamsungModelId,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0020 SmartAlbumColor (Samsung.pm:256-278) — int16u[2]. Branch 1 (the \0{4} "0 0"=>n/a) ported; branch 2's per-element color array is deferred (raw passthrough).
  SamsungTag {
    id: 0x0020,
    name: "SmartAlbumColor",
    conv: SamsungPrintConv::SmartAlbumColor,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0021 PictureWizard (Samsung.pm:279-283) — int16u SubDirectory → %Samsung::PictureWizard ProcessBinaryData (descended in the capture loop).
  SamsungTag {
    id: 0x0021,
    name: "PictureWizard",
    conv: SamsungPrintConv::None,
    sub_table: Some(SubTable::PictureWizard),
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0030 LocalLocationName (Samsung.pm:291-298) — Format 'undef', Writable 'string', no PrintConv; ValueConv truncates at the first double-NUL and turns each NUL+spaces separator into a newline.
  SamsungTag {
    id: 0x0030,
    name: "LocalLocationName",
    conv: SamsungPrintConv::LocalLocationName,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Undef, None)),
    crypt: None,
  },
  // 0x0031 LocationName (Samsung.pm:299-303) — string.
  SamsungTag {
    id: 0x0031,
    name: "LocationName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0035 PreviewIFD (Samsung.pm:307-327) — a SubIFD pointer to
  // %Nikon::PreviewIFD (`Flags => 'SubIFD'`, `ByteOrder => Unknown`,
  // `Start => '$val'`, `{ 1 => PreviewIFD }`), gated `TIFF_TYPE eq "SRW"`. NO
  // `format` override: the on-disk int32u[1] value IS the `$val` start offset
  // the isolated walker reads to descend the child IFD (#242). The parent
  // pointer itself emits nothing (`emit_samsung_value` skips SubDirectory rows).
  SamsungTag {
    id: 0x0035,
    name: "PreviewIFD",
    conv: SamsungPrintConv::None,
    sub_table: Some(SubTable::PreviewIfd),
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0040 RawDataByteOrder (Samsung.pm:334-340) — label hash.
  SamsungTag {
    id: 0x0040,
    name: "RawDataByteOrder",
    conv: SamsungPrintConv::RawDataByteOrder,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0041 WhiteBalanceSetup (Samsung.pm:341-348) — int32u, 0=>Auto 1=>Manual.
  SamsungTag {
    id: 0x0041,
    name: "WhiteBalanceSetup",
    conv: SamsungPrintConv::WhiteBalanceSetup,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0043 CameraTemperature (Samsung.pm:349-356) — rational64s, "$val C" when numeric.
  SamsungTag {
    id: 0x0043,
    name: "CameraTemperature",
    conv: SamsungPrintConv::CameraTemperature,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0050 RawDataCFAPattern (Samsung.pm:361-368) — label hash.
  SamsungTag {
    id: 0x0050,
    name: "RawDataCFAPattern",
    conv: SamsungPrintConv::RawDataCfaPattern,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0100 FaceDetect (Samsung.pm:381-385) — int16u, 0=>Off 1=>On.
  SamsungTag {
    id: 0x0100,
    name: "FaceDetect",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0120 FaceRecognition (Samsung.pm:388-392) — int32u, 0=>Off 1=>On.
  SamsungTag {
    id: 0x0120,
    name: "FaceRecognition",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0x0123 FaceName (Samsung.pm:393) — string.
  SamsungTag {
    id: 0x0123,
    name: "FaceName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa001 FirmwareName (Samsung.pm:399-403) — string.
  SamsungTag {
    id: 0xa001,
    name: "FirmwareName",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
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
    crypt: None,
  },
  // 0xa003 LensType (Samsung.pm:410-416) — int16u Count -1, %samsungLensTypes lookup.
  SamsungTag {
    id: 0xa003,
    name: "LensType",
    conv: SamsungPrintConv::LensType,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa004 LensFirmware (Samsung.pm:417-421) — string.
  SamsungTag {
    id: 0xa004,
    name: "LensFirmware",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa005 InternalLensSerialNumber (Samsung.pm:422-426) — string.
  SamsungTag {
    id: 0xa005,
    name: "InternalLensSerialNumber",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa010 SensorAreas (Samsung.pm:427-433) — int32u[8], raw space-joined.
  SamsungTag {
    id: 0xa010,
    name: "SensorAreas",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa011 ColorSpace (Samsung.pm:434-441) — int16u, 0=>sRGB 1=>Adobe RGB.
  SamsungTag {
    id: 0xa011,
    name: "ColorSpace",
    conv: SamsungPrintConv::ColorSpace,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa012 SmartRange (Samsung.pm:442-446) — int16u, 0=>Off 1=>On.
  SamsungTag {
    id: 0xa012,
    name: "SmartRange",
    conv: SamsungPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa013 ExposureCompensation (Samsung.pm:447-450) — rational64s, raw.
  SamsungTag {
    id: 0xa013,
    name: "ExposureCompensation",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa014 ISO (Samsung.pm:451-454) — int32u, raw.
  SamsungTag {
    id: 0xa014,
    name: "ISO",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa018 ExposureTime (Samsung.pm:455-462) — rational64u, first-value ValueConv + PrintExposureTime.
  SamsungTag {
    id: 0xa018,
    name: "ExposureTime",
    conv: SamsungPrintConv::ExposureTime,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa019 FNumber (Samsung.pm:463-471) — rational64u, Priority 0, first-value ValueConv + %.1f.
  SamsungTag {
    id: 0xa019,
    name: "FNumber",
    conv: SamsungPrintConv::FNumber,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: None,
  },
  // 0xa01a FocalLengthIn35mmFormat (Samsung.pm:472-481) — Format int32u, ValueConv /10, "$val mm".
  SamsungTag {
    id: 0xa01a,
    name: "FocalLengthIn35mmFormat",
    conv: SamsungPrintConv::FocalLength35,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32u, None)),
    crypt: None,
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
    crypt: None,
  },
  // 0xa021 WB_RGGBLevelsUncorrected (Samsung.pm:494-500) — int32u, Crypt SALT [neg(0)].
  SamsungTag {
    id: 0xa021,
    name: "WB_RGGBLevelsUncorrected",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(0)],
    }),
  },
  // 0xa022 WB_RGGBLevelsAuto (Samsung.pm:501-507) — int32u, Crypt SALT [neg(4)].
  SamsungTag {
    id: 0xa022,
    name: "WB_RGGBLevelsAuto",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(4)],
    }),
  },
  // 0xa023 WB_RGGBLevelsIlluminator1 (Samsung.pm:508-514) — int32u, Crypt SALT [neg(8)].
  SamsungTag {
    id: 0xa023,
    name: "WB_RGGBLevelsIlluminator1",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(8)],
    }),
  },
  // 0xa024 WB_RGGBLevelsIlluminator2 (Samsung.pm:515-521) — int32u, Crypt SALT [neg(1)].
  SamsungTag {
    id: 0xa024,
    name: "WB_RGGBLevelsIlluminator2",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(1)],
    }),
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
    crypt: None,
  },
  // 0xa028 WB_RGGBLevelsBlack (Samsung.pm:533-539) — int32s, Crypt SALT [neg(0)].
  SamsungTag {
    id: 0xa028,
    name: "WB_RGGBLevelsBlack",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::neg(0)],
    }),
  },
  // 0xa030 ColorMatrix (Samsung.pm:540-546) — int32s, Crypt SALT [pos(0)].
  SamsungTag {
    id: 0xa030,
    name: "ColorMatrix",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::pos(0)],
    }),
  },
  // 0xa031 ColorMatrixSRGB (Samsung.pm:547-553) — int32s, Crypt SALT [pos(0)].
  SamsungTag {
    id: 0xa031,
    name: "ColorMatrixSRGB",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::pos(0)],
    }),
  },
  // 0xa032 ColorMatrixAdobeRGB (Samsung.pm:554-560) — int32s, Crypt SALT [pos(0)].
  SamsungTag {
    id: 0xa032,
    name: "ColorMatrixAdobeRGB",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::pos(0)],
    }),
  },
  // 0xa033 CbCrMatrixDefault (Samsung.pm:561-567) — int32s, Crypt SALT [pos(0)].
  SamsungTag {
    id: 0xa033,
    name: "CbCrMatrixDefault",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::pos(0)],
    }),
  },
  // 0xa034 CbCrMatrix (Samsung.pm:568-574) — int32s, Crypt SALT [pos(4)].
  SamsungTag {
    id: 0xa034,
    name: "CbCrMatrix",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32s,
      salts: &[Salt::pos(4)],
    }),
  },
  // 0xa035 CbCrGainDefault (Samsung.pm:575-581) — int32u, Crypt SALT [neg(0)].
  SamsungTag {
    id: 0xa035,
    name: "CbCrGainDefault",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(0)],
    }),
  },
  // 0xa036 CbCrGain (Samsung.pm:582-588) — int32u, Crypt SALT [neg(2)].
  SamsungTag {
    id: 0xa036,
    name: "CbCrGain",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::neg(2)],
    }),
  },
  // 0xa040 ToneCurveSRGBDefault (Samsung.pm:589-602) — int32u, Crypt SALT [pos(0), neg(0)].
  SamsungTag {
    id: 0xa040,
    name: "ToneCurveSRGBDefault",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::pos(0), Salt::neg(0)],
    }),
  },
  // 0xa041 ToneCurveAdobeRGBDefault (Samsung.pm:603-609) — int32u, Crypt SALT [pos(0), neg(0)].
  SamsungTag {
    id: 0xa041,
    name: "ToneCurveAdobeRGBDefault",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::pos(0), Salt::neg(0)],
    }),
  },
  // 0xa042 ToneCurveSRGB (Samsung.pm:610-616) — int32u, Crypt SALT [pos(0), neg(0)].
  SamsungTag {
    id: 0xa042,
    name: "ToneCurveSRGB",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::pos(0), Salt::neg(0)],
    }),
  },
  // 0xa043 ToneCurveAdobeRGB (Samsung.pm:617-623) — int32u, Crypt SALT [pos(0), neg(0)].
  SamsungTag {
    id: 0xa043,
    name: "ToneCurveAdobeRGB",
    conv: SamsungPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
    crypt: Some(CryptTag {
      format: Format::Int32u,
      salts: &[Salt::pos(0), Salt::neg(0)],
    }),
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
