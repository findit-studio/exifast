// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The Exif IFD tag table — the camera-relevant subset of
//! `%Image::ExifTool::Exif::Main` (`Exif.pm:411-3700`).
//!
//! Each [`ExifTag`] maps a TIFF/Exif tag ID to a tag NAME plus the
//! conversion ([`Conv`]) ExifTool applies. The IFD walker
//! ([`crate::exif::ifd`] feeds [`crate::exif::RawValue`]); this table
//! resolves the name + drives PrintConv/ValueConv at serialize time.
//!
//! ## Scope (per the port plan's SCOPE DISCIPLINE)
//!
//! The IFD MACHINERY is complete + faithful (the priority is correctness of
//! the walker + type decoders, not 100% tag coverage). This table covers:
//!
//! - every camera-relevant tag the plan names (Make, Model, Lens*, FNumber,
//!   ExposureTime, ISO, FocalLength, DateTimeOriginal, Orientation,
//!   Software, …),
//! - every tag the bundled TIFF conformance fixtures exercise,
//! - the four SubDirectory pointer tags (ExifIFD 0x8769, GPS 0x8825,
//!   InteropIFD 0xa005, MakerNote 0x927c).
//!
//! Obscure `%Exif::Main` tags not in the fixtures are a documented
//! incremental-completion item (`docs/tracking.md`) — an unknown tag ID is
//! handled gracefully (the walker emits `Tag 0xNNNN` like ExifTool's verbose
//! fallback, but the default `-j` output simply omits unknown tags, faithful
//! to `Exif.pm:6757` `next unless $verbose`).

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction.
// This module is tag tables + scalar `sprintf`-style formatters — it carries
// no raw slice/index sites; the deny-lint pins that property for the future.
#![deny(clippy::indexing_slicing)]

// The `--kind exif` generator's shadow of this table (`cargo xtask gen-tables
// --module Exif::Main --kind exif`): every [`EXIF_TAGS`] row re-rendered into
// the same `ExifTag` row, each resolved to the SAME [`Conv`] (a per-id
// differential parity test below is the gate), PLUS the binary-EXIF
// coverage-gap ids ([`crate::exif::EXIF_MAIN_GAP_IDS`]) — `%Exif::Main` leaf
// tags this hand subset does NOT carry. It is a CHILD module so its HANDPORTED
// `super::COMPRESSION` / `super::FLASH` / … const references resolve against
// this module's curated label slices, reusing them byte-for-byte. [`lookup`]
// consults the hand table FIRST and falls back here: a SHARED id always AGREES
// with the hand entry, and a gap id (absent from [`EXIF_TAGS`]) is the only one
// this fallback actually returns — i.e. the hand table is a strict SUBSET of
// the generated shadow.
#[path = "tables_generated.rs"]
mod generated;

// ===========================================================================
// SubDirectory pointer tags — the IFD-chain seam (Exif.pm:2006/2130/2496/2720)
// ===========================================================================

/// `ExifOffset` (0x8769, `Exif.pm:2006-2015`) — SubIFD pointer to the
/// ExifIFD. `SubDirectory => { DirName => 'ExifIFD', Start => '$val' }`.
pub const TAG_EXIF_IFD: u16 = 0x8769;

/// `GPSInfo` (0x8825, `Exif.pm:2130-2141`) — SubIFD pointer to the GPS IFD.
/// `SubDirectory => { DirName => 'GPS', TagTable => GPS::Main, Start => '$val' }`.
pub const TAG_GPS_IFD: u16 = 0x8825;

/// `InteropOffset` (0xa005, `Exif.pm:2720-2730`) — SubIFD pointer to the
/// InteropIFD.
pub const TAG_INTEROP_IFD: u16 = 0xa005;

/// `MakerNote` (0x927c, `Exif.pm:2496`) — the vendor MakerNotes blob.
/// `0x927c => \@Image::ExifTool::MakerNotes::Main` — a conditional list that
/// dispatches Apple/Canon/Sony/etc. parsers. **Vendor MakerNote parsing is
/// deferred to the MakerNotes wave** (see `docs/tracking.md`); the Exif
/// walker captures the raw bytes and the SubDirectory-dispatch seam is
/// designed so a MakerNote port can plug in (see
/// [`crate::exif::SubDirKind::MakerNote`]).
pub const TAG_MAKER_NOTE: u16 = 0x927c;

/// `SubfileType` (0x00fe, `Exif.pm:444-461`) — the TIFF spec's
/// `NewSubfileType` (bit field: 0x01 reduced-res, 0x02 single page of
/// multi-page, 0x04 transparency mask). Bundled's `RawConv` increments
/// `$$self{PageCount}` when `$val == ($val & 0x02)` (i.e. `$val` ∈ {0, 2})
/// and sets `$$self{MultiPage} = 1` when `$val == 2` OR `PageCount > 1`.
/// The standalone-TIFF entry [`crate::exif::parse_standalone_tiff`] consults
/// the walker's tracked state to emit `File:PageCount` faithful to
/// `ExifTool.pm:8756-8757`.
pub const TAG_SUBFILE_TYPE: u16 = 0x00fe;

/// `OldSubfileType` (0x00ff, `Exif.pm:462-482`) — the TIFF 5.0 era
/// `SubfileType` (values 1/2/3 for full-res / reduced-res / single page of
/// multi-page). Bundled's `RawConv` increments `$$self{PageCount}` when
/// `$val == 1` OR `$val == 3` and sets `$$self{MultiPage} = 1` when
/// `$val == 3` OR `PageCount > 1`. Tracked alongside [`TAG_SUBFILE_TYPE`]
/// for the same `File:PageCount` synthesis.
///
/// NOTE: this tag is NOT in the port's leaf table (a deferred Exif-table
/// item); it is intercepted by the walker for the PageCount RawConv side
/// effect, then the unknown-tag `next` (`Exif.pm:6757`) drops it from the
/// emitted entries. Bundled behaviour matches on this fixture set (none of
/// the camera-relevant fixtures carry tag 0xff).
pub const TAG_OLD_SUBFILE_TYPE: u16 = 0x00ff;

// ===========================================================================
// Conversion descriptor — `Conv`
// ===========================================================================

/// The PrintConv / ValueConv ExifTool applies to one tag's decoded value.
///
/// `print_conv = true` (the `-j` default) renders the human string;
/// `print_conv = false` (`-n`) renders the post-ValueConv raw scalar.
///
/// D8: unit-or-newtype variants only; `#[non_exhaustive]` so future Exif
/// tags can add a conversion kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Conv {
  /// No conversion — emit the raw decoded value as-is.
  None,
  /// Integer → label via a static `(code, label)` slice. A miss (no slice
  /// entry) renders `Unknown (N)` with print_conv ON — faithful to ExifTool's
  /// HASH-PrintConv miss, which ALWAYS produces `sprintf('Unknown ($val)')`
  /// when the hash has no entry, no `OTHER` and no `BITMASK`
  /// (`ExifTool.pm:3614-3634`). With print_conv OFF (`-n`) the bare decimal
  /// number is emitted (the `emit_raw` path). Used for every integer
  /// enumeration WITHOUT `PrintHex` (Compression, PhotometricInterpretation,
  /// ExposureProgram, …).
  IntLabel(&'static [(i64, &'static str)]),
  /// Integer → label, but the tag carries `PrintHex => 1`, so a miss renders
  /// `Unknown (0x%x)` (hex) instead of decimal (`sprintf('Unknown (0x%x)',
  /// $val)`, `ExifTool.pm:3623-3626`). Only `ColorSpace` (0xa001,
  /// `Exif.pm:2693`) and `Flash` (0x9209, `Exif.pm:2414`) take this in the
  /// ported subset. With print_conv OFF the bare DECIMAL number is emitted
  /// (the `emit_raw` path) — `PrintHex` affects only the print string, e.g.
  /// `ColorSpace 12` → `"Unknown (0xc)"` (`-j`) / `12` (`-n`).
  IntLabelHex(&'static [(i64, &'static str)]),
  /// `ExposureTime` / `ShutterSpeedValue` PrintConv —
  /// `PrintExposureTime` (`Exif.pm:5701-5711`).
  ExposureTime,
  /// `FNumber` PrintConv — `PrintFNumber` (`Exif.pm:5715-5723`).
  FNumber,
  /// `FocalLength` (0x920a) PrintConv — `sprintf("%.1f mm",$val)`
  /// (`Exif.pm:2425`). A `rational64u`; rendered with one decimal.
  FocalLengthMm,
  /// `FocalLengthIn35mmFormat` (0xa405) PrintConv — `"$val mm"`
  /// (`Exif.pm:2896`). Normally an `int16u`, so `$val` is an integer and the
  /// string interpolation emits NO decimal point (e.g. `"75 mm"`) — distinct
  /// from 0x920a's `sprintf("%.1f mm")`. The raw scalar is rendered with the
  /// same `%g`/rational stringification as the other scalar convs, so an
  /// off-spec fractional value (`37.5`) is preserved as `"37.5 mm"` rather
  /// than truncated.
  FocalLength35mm,
  /// `ExposureCompensation` PrintConv — `PrintFraction` (`Exif.pm:5516-5535`).
  ExposureCompensation,
  /// `ApertureValue` / `MaxApertureValue` — ValueConv `2 ** ($val / 2)`,
  /// PrintConv `sprintf("%.1f",$val)` (`Exif.pm:2352-2360`).
  ApertureApex,
  /// `ShutterSpeedValue` ValueConv `2 ** -$val` then `PrintExposureTime`
  /// (`Exif.pm:2342-2350`).
  ShutterSpeedApex,
  /// EXIF date/time string PrintConv — `$self->ConvertDateTime($val)`
  /// (`Exif.pm:917`). With default options ConvertDateTime is identity.
  DateTime,
  /// `LensInfo` / `LensSpecification` PrintConv — `PrintLensInfo`
  /// (`Exif.pm:5800-5817`).
  LensInfo,
  /// `ExifVersion` / `FlashpixVersion` — `undef` bytes rendered as the raw
  /// ASCII version string (`"0200"`), NUL-stripped (`Exif.pm:2241`).
  Version,
  /// `ComponentsConfiguration` — per-byte label join (`Exif.pm:2304-2317`).
  ComponentsConfiguration,
  /// `GPSAltitude`-style — PrintConv `"$val m"` unless the value is
  /// `inf`/`undef` (`Exif.pm:2388-2389`, `GPS.pm:119`).
  MetersSuffix,
  /// `AmbientTemperature` (0x9400) PrintConv — `'"$val C"'` (`Exif.pm:2590`).
  /// A `rational64s`; the post-ValueConv scalar (0x9400 has no ValueConv) is
  /// interpolated verbatim with a trailing ` C` (e.g. `23.5` → `"23.5 C"`,
  /// `-5.5` → `"-5.5 C"`). Unlike [`Conv::MetersSuffix`] there is NO
  /// `inf`/`undef` guard in `Exif.pm`, so the suffix is appended
  /// unconditionally. With print_conv OFF the bare raw scalar is emitted.
  CelsiusSuffix,
  /// `CompositeImageExposureTimes` (0xa462) — `Writable => 'undef'` with a
  /// bespoke `RawConv`/`PrintConv` pair (`Exif.pm:3068-3119`). The `undef`
  /// blob is decoded as a sequence of `rational64u` quotients EXCEPT at byte
  /// offsets 56 and 58 (the 8th and 9th values, indices 7 and 8) which are
  /// `int16u` counts — `RawConv` (`Exif.pm:3079-3098`) reads each in turn
  /// until the bytes run out and space-joins them (so `-n` shows the joined
  /// decimals). The `PrintConv` (`Exif.pm:3104-3115`) then applies
  /// [`print_exposure_time`] to every element EXCEPT indices 7 and 8 (the
  /// counts), space-joined (so `-j` shows e.g. `"1/160 1/200 … 3 2 …"`).
  CompositeImageExposureTimes,
  /// `UserComment` (0x9286) `RawConv` — `ConvertExifText($self,$val,1,$tag)`
  /// (`Exif.pm:2502`, impl `Exif.pm:5554-5601`). The `undef`-format value
  /// carries an 8-byte charset-ID prefix (`ASCII`/`UNICODE`/`JIS`/all-NUL)
  /// that is stripped before the payload is decoded; a `RawConv` applies in
  /// BOTH `-j` and `-n` modes and there is no further PrintConv. Shared with
  /// the GPS `GPSProcessingMethod`/`GPSAreaInformation` path (the impl lives
  /// in [`crate::exif::exiftext`], which is `feature = "exif"` — NOT `gps` —
  /// so `UserComment` works without the GPS feature).
  ExifText,
  /// Trailing-whitespace-trim `RawConv` — `$val =~ s/\s+$//`. Applied to
  /// `Make` (0x010f, `Exif.pm:585`), `Model` (0x0110, `Exif.pm:599`),
  /// `Software` (0x0131, `Exif.pm:906`) and `Artist` (0x013b, `Exif.pm:925`):
  /// space-padded EXIF `string` fields (an EXIF-spec "unknown" filled with
  /// blanks) are stripped of EVERY trailing whitespace char (`\s` = space,
  /// tab, NL, CR, FF). It is a `RawConv`, so the trim applies in BOTH `-j`
  /// and `-n` modes; there is no further PrintConv on these tags. (The
  /// `$$self{Make/Model/Software}` DataMember side effect is a writer-only
  /// concern with no read-extraction analogue, so it is not modeled.)
  TrimTrailingWhitespace,
  /// Trailing-space-trim `ValueConv` — `$val=~s/ +$//`. Applied to
  /// `SubSecTime` (0x9290, `Exif.pm:2543`), `SubSecTimeOriginal` (0x9291,
  /// `Exif.pm:2552`) and `SubSecTimeDigitized` (0x9292, `Exif.pm:2560`):
  /// trims trailing SPACES ONLY (`s/ +$//`, NOT `\s` — a trailing tab/NL is
  /// kept). It is a `ValueConv`, so the trimmed value is what `-n` shows and
  /// the (identity) PrintConv carries through unchanged in `-j`.
  TrimTrailingSpaces,
  /// STRING-keyed HASH PrintConv via a static `(key, label)` slice. The
  /// on-disk value is a `string`; with print_conv ON the (NUL/space-trimmed)
  /// token is looked up — a hit emits the label, a MISS emits `Unknown
  /// ($val)` (`ExifTool.pm:3614-3634`, no `OTHER`/`PrintHex` on these tags).
  /// With print_conv OFF the raw token is emitted. Used for `InteropIndex`
  /// (0x0001, `Exif.pm:417-427` — `R98`/`R03`/`THM`); distinct from the
  /// integer-keyed [`Conv::IntLabel`].
  StrLabel(&'static [(&'static str, &'static str)]),
}

// ===========================================================================
// Tag descriptor — `ExifTag`
// ===========================================================================

/// One Exif IFD tag descriptor — a row of `%Image::ExifTool::Exif::Main`.
#[derive(Debug, Clone, Copy)]
pub struct ExifTag {
  /// On-disk tag ID (`%Exif::Main` hash key).
  pub id: u16,
  /// Tag NAME (`Name => '…'`).
  pub name: &'static str,
  /// The conversion ExifTool applies.
  pub conv: Conv,
}

/// Static PrintConv slice — `%orientation` (`Exif.pm:291-299`).
const ORIENTATION: &[(i64, &str)] = &[
  (1, "Horizontal (normal)"),
  (2, "Mirror horizontal"),
  (3, "Rotate 180"),
  (4, "Mirror vertical"),
  (5, "Mirror horizontal and rotate 270 CW"),
  (6, "Rotate 90 CW"),
  (7, "Mirror horizontal and rotate 90 CW"),
  (8, "Rotate 270 CW"),
];

/// `%compression` PrintConv (`Exif.pm:213-269`) — the common subset; the
/// bundled fixtures exercise codes 1/5/6.
const COMPRESSION: &[(i64, &str)] = &[
  (1, "Uncompressed"),
  (2, "CCITT 1D"),
  (3, "T4/Group 3 Fax"),
  (4, "T6/Group 4 Fax"),
  (5, "LZW"),
  (6, "JPEG (old-style)"),
  (7, "JPEG"),
  (8, "Adobe Deflate"),
  (9, "JBIG B&W or VC-5"),
  (10, "JBIG Color"),
  (99, "JPEG"),
  (32773, "PackBits"),
  (34892, "Lossy JPEG"),
];

/// `%photometricInterpretation` PrintConv (`Exif.pm:271-289`).
const PHOTOMETRIC: &[(i64, &str)] = &[
  (0, "WhiteIsZero"),
  (1, "BlackIsZero"),
  (2, "RGB"),
  (3, "RGB Palette"),
  (4, "Transparency Mask"),
  (5, "CMYK"),
  (6, "YCbCr"),
  (8, "CIELab"),
  (9, "ICCLab"),
  (10, "ITULab"),
  (32803, "Color Filter Array"),
  (34892, "Linear Raw"),
];

/// `%subfileType` PrintConv (`Exif.pm:302-322`) — the scalar entries.
const SUBFILE_TYPE: &[(i64, &str)] = &[
  (0, "Full-resolution image"),
  (1, "Reduced-resolution image"),
  (2, "Single page of multi-page image"),
  (3, "Single page of multi-page reduced-resolution image"),
  (4, "Transparency mask"),
  (5, "Transparency mask of reduced-resolution image"),
  (6, "Transparency mask of multi-page image"),
  (16, "Enhanced image data"),
];

/// `ResolutionUnit` / `FocalPlaneResolutionUnit` PrintConv
/// (`Exif.pm:879-883`).
const RESOLUTION_UNIT: &[(i64, &str)] = &[(1, "None"), (2, "inches"), (3, "cm")];

/// `PlanarConfiguration` PrintConv (`Exif.pm:809-812`).
const PLANAR_CONFIG: &[(i64, &str)] = &[(1, "Chunky"), (2, "Planar")];

/// `Predictor` PrintConv (`Exif.pm:1264-1271`).
const PREDICTOR: &[(i64, &str)] = &[
  (1, "None"),
  (2, "Horizontal differencing"),
  (3, "Floating point"),
];

/// `YCbCrPositioning` PrintConv (`Exif.pm:1457-1460`).
const YCBCR_POSITIONING: &[(i64, &str)] = &[(1, "Centered"), (2, "Co-sited")];

/// `ExposureProgram` PrintConv (`Exif.pm:2112-2123`).
const EXPOSURE_PROGRAM: &[(i64, &str)] = &[
  (0, "Not Defined"),
  (1, "Manual"),
  (2, "Program AE"),
  (3, "Aperture-priority AE"),
  (4, "Shutter speed priority AE"),
  (5, "Creative (Slow speed)"),
  (6, "Action (High speed)"),
  (7, "Portrait"),
  (8, "Landscape"),
  (9, "Bulb"),
];

/// `MeteringMode` PrintConv (`Exif.pm:2395-2404`).
const METERING_MODE: &[(i64, &str)] = &[
  (0, "Unknown"),
  (1, "Average"),
  (2, "Center-weighted average"),
  (3, "Spot"),
  (4, "Multi-spot"),
  (5, "Multi-segment"),
  (6, "Partial"),
  (255, "Other"),
];

/// `LightSource` PrintConv (`Exif.pm:139-176` `%lightSource`) — common subset.
const LIGHT_SOURCE: &[(i64, &str)] = &[
  (0, "Unknown"),
  (1, "Daylight"),
  (2, "Fluorescent"),
  (3, "Tungsten (Incandescent)"),
  (4, "Flash"),
  (9, "Fine Weather"),
  (10, "Cloudy"),
  (11, "Shade"),
  (12, "Daylight Fluorescent"),
  (13, "Day White Fluorescent"),
  (14, "Cool White Fluorescent"),
  (15, "White Fluorescent"),
  (17, "Standard Light A"),
  (18, "Standard Light B"),
  (19, "Standard Light C"),
  (20, "D55"),
  (21, "D65"),
  (22, "D75"),
  (23, "D50"),
  (24, "ISO Studio Tungsten"),
  (255, "Other"),
];

/// `ColorSpace` PrintConv (`Exif.pm:2694-2702`).
const COLOR_SPACE: &[(i64, &str)] = &[
  (1, "sRGB"),
  (2, "Adobe RGB"),
  (0xfffd, "Wide Gamut RGB"),
  (0xfffe, "ICC Profile"),
  (0xffff, "Uncalibrated"),
];

/// `SensingMethod` PrintConv (`Exif.pm:2480-2489` / `2800-2809`).
const SENSING_METHOD: &[(i64, &str)] = &[
  (1, "Monochrome area"),
  (2, "One-chip color area"),
  (3, "Two-chip color area"),
  (4, "Three-chip color area"),
  (5, "Color sequential area"),
  (6, "Monochrome linear"),
  (7, "Trilinear"),
  (8, "Color sequential linear"),
];

/// `FileSource` PrintConv (`Exif.pm:2815-2822`) — scalar entries.
const FILE_SOURCE: &[(i64, &str)] = &[
  (1, "Film Scanner"),
  (2, "Reflection Print Scanner"),
  (3, "Digital Camera"),
];

/// `SceneType` PrintConv (`Exif.pm:2827-2829`).
const SCENE_TYPE: &[(i64, &str)] = &[(1, "Directly photographed")];

/// `CustomRendered` PrintConv (`Exif.pm:2848-2852`) — common values.
const CUSTOM_RENDERED: &[(i64, &str)] = &[
  (0, "Normal"),
  (1, "Custom"),
  (2, "HDR (no original saved)"),
  (3, "HDR (original saved)"),
  (4, "Original (for HDR)"),
  (6, "Panorama"),
  (7, "Portrait HDR"),
  (8, "Portrait"),
];

/// `ExposureMode` PrintConv (`Exif.pm:2866-2870`).
const EXPOSURE_MODE: &[(i64, &str)] = &[(0, "Auto"), (1, "Manual"), (2, "Auto bracket")];

/// `WhiteBalance` PrintConv (`Exif.pm:2877-2880`).
const WHITE_BALANCE: &[(i64, &str)] = &[(0, "Auto"), (1, "Manual")];

/// `SceneCaptureType` PrintConv (`Exif.pm:2924-2929`).
const SCENE_CAPTURE_TYPE: &[(i64, &str)] = &[
  (0, "Standard"),
  (1, "Landscape"),
  (2, "Portrait"),
  (3, "Night"),
  (4, "Other"),
];

/// `GainControl` PrintConv (`Exif.pm:2932-2938`).
const GAIN_CONTROL: &[(i64, &str)] = &[
  (0, "None"),
  (1, "Low gain up"),
  (2, "High gain up"),
  (3, "Low gain down"),
  (4, "High gain down"),
];

/// `Contrast` / `Sharpness` PrintConv (`Exif.pm:2941-2954`).
const CONTRAST: &[(i64, &str)] = &[(0, "Normal"), (1, "Low"), (2, "High")];

/// `Saturation` PrintConv (`Exif.pm:2956-2961`).
const SATURATION: &[(i64, &str)] = &[(0, "Normal"), (1, "Low"), (2, "High")];

/// `SubjectDistanceRange` PrintConv (`Exif.pm:2965-2969`).
const SUBJECT_DISTANCE_RANGE: &[(i64, &str)] =
  &[(0, "Unknown"), (1, "Macro"), (2, "Close"), (3, "Distant")];

// ===========================================================================
// The Exif::Main tag table — one row per ported tag
// ===========================================================================

/// The ported subset of `%Image::ExifTool::Exif::Main`. The SubDirectory
/// pointer tags (0x8769/0x8825/0xa005/0x927c) are NOT in this table — they
/// are handled structurally by the IFD walker; this table is the leaf-tag
/// name+conversion lookup.
pub const EXIF_TAGS: &[ExifTag] = &[
  // ---- TIFF/IFD0 image-structure tags (Exif.pm:435-1500) ------------------
  ExifTag {
    id: 0x00fe,
    name: "SubfileType",
    conv: Conv::IntLabel(SUBFILE_TYPE),
  },
  ExifTag {
    id: 0x0100,
    name: "ImageWidth",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0101,
    name: "ImageHeight",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0102,
    name: "BitsPerSample",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0103,
    name: "Compression",
    conv: Conv::IntLabel(COMPRESSION),
  },
  ExifTag {
    id: 0x0106,
    name: "PhotometricInterpretation",
    conv: Conv::IntLabel(PHOTOMETRIC),
  },
  ExifTag {
    id: 0x010d,
    name: "DocumentName",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x010e,
    name: "ImageDescription",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x010f,
    name: "Make",
    conv: Conv::TrimTrailingWhitespace,
  },
  ExifTag {
    id: 0x0110,
    name: "Model",
    conv: Conv::TrimTrailingWhitespace,
  },
  ExifTag {
    id: 0x0111,
    name: "StripOffsets",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0112,
    name: "Orientation",
    conv: Conv::IntLabel(ORIENTATION),
  },
  ExifTag {
    id: 0x0115,
    name: "SamplesPerPixel",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0116,
    name: "RowsPerStrip",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0117,
    name: "StripByteCounts",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x011a,
    name: "XResolution",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x011b,
    name: "YResolution",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x011c,
    name: "PlanarConfiguration",
    conv: Conv::IntLabel(PLANAR_CONFIG),
  },
  ExifTag {
    id: 0x0128,
    name: "ResolutionUnit",
    conv: Conv::IntLabel(RESOLUTION_UNIT),
  },
  ExifTag {
    id: 0x0131,
    name: "Software",
    conv: Conv::TrimTrailingWhitespace,
  },
  ExifTag {
    id: 0x0132,
    name: "ModifyDate",
    conv: Conv::DateTime,
  },
  ExifTag {
    id: 0x013b,
    name: "Artist",
    conv: Conv::TrimTrailingWhitespace,
  },
  ExifTag {
    id: 0x013d,
    name: "Predictor",
    conv: Conv::IntLabel(PREDICTOR),
  },
  ExifTag {
    id: 0x013e,
    name: "WhitePoint",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x013f,
    name: "PrimaryChromaticities",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0211,
    name: "YCbCrCoefficients",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0213,
    name: "YCbCrPositioning",
    conv: Conv::IntLabel(YCBCR_POSITIONING),
  },
  ExifTag {
    id: 0x0214,
    name: "ReferenceBlackWhite",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0201,
    name: "ThumbnailOffset",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0202,
    name: "ThumbnailLength",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x8298,
    name: "Copyright",
    conv: Conv::None,
  },
  // ---- ExifIFD tags (Exif.pm:1848-3050) -----------------------------------
  ExifTag {
    id: 0x829a,
    name: "ExposureTime",
    conv: Conv::ExposureTime,
  },
  ExifTag {
    id: 0x829d,
    name: "FNumber",
    conv: Conv::FNumber,
  },
  ExifTag {
    id: 0x8822,
    name: "ExposureProgram",
    conv: Conv::IntLabel(EXPOSURE_PROGRAM),
  },
  ExifTag {
    id: 0x8824,
    name: "SpectralSensitivity",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x8827,
    name: "ISO",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x8830,
    name: "SensitivityType",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x8832,
    name: "RecommendedExposureIndex",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9000,
    name: "ExifVersion",
    conv: Conv::Version,
  },
  ExifTag {
    id: 0x9003,
    name: "DateTimeOriginal",
    conv: Conv::DateTime,
  },
  ExifTag {
    id: 0x9004,
    name: "CreateDate",
    conv: Conv::DateTime,
  },
  ExifTag {
    id: 0x9010,
    name: "OffsetTime",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9011,
    name: "OffsetTimeOriginal",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9012,
    name: "OffsetTimeDigitized",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9101,
    name: "ComponentsConfiguration",
    conv: Conv::ComponentsConfiguration,
  },
  ExifTag {
    id: 0x9102,
    name: "CompressedBitsPerPixel",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9201,
    name: "ShutterSpeedValue",
    conv: Conv::ShutterSpeedApex,
  },
  ExifTag {
    id: 0x9202,
    name: "ApertureValue",
    conv: Conv::ApertureApex,
  },
  ExifTag {
    id: 0x9203,
    name: "BrightnessValue",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x9204,
    name: "ExposureCompensation",
    conv: Conv::ExposureCompensation,
  },
  ExifTag {
    id: 0x9205,
    name: "MaxApertureValue",
    conv: Conv::ApertureApex,
  },
  ExifTag {
    id: 0x9206,
    name: "SubjectDistance",
    conv: Conv::MetersSuffix,
  },
  ExifTag {
    id: 0x9207,
    name: "MeteringMode",
    conv: Conv::IntLabel(METERING_MODE),
  },
  ExifTag {
    id: 0x9208,
    name: "LightSource",
    conv: Conv::IntLabel(LIGHT_SOURCE),
  },
  // Flash (0x9209) — the complete `%flash` enumerated hash (Exif.pm:175-209)
  // is ported in `FLASH`. `PrintHex => 1` (Exif.pm:2417) ⇒ a miss renders
  // `Unknown (0x%x)`.
  ExifTag {
    id: 0x9209,
    name: "Flash",
    conv: Conv::IntLabelHex(FLASH),
  },
  ExifTag {
    id: 0x920a,
    name: "FocalLength",
    conv: Conv::FocalLengthMm,
  },
  ExifTag {
    id: 0x9286,
    name: "UserComment",
    // `Format => 'undef'` + `RawConv => ConvertExifText($self,$val,1,$tag)`
    // (Exif.pm:2500-2502): strip the 8-byte charset-ID prefix and decode the
    // payload (ASCII / UTF-16 'Unknown' / JIS), threading the EXIF block's
    // byte order to the UTF-16 order guess.
    conv: Conv::ExifText,
  },
  ExifTag {
    id: 0x9290,
    name: "SubSecTime",
    conv: Conv::TrimTrailingSpaces,
  },
  ExifTag {
    id: 0x9291,
    name: "SubSecTimeOriginal",
    conv: Conv::TrimTrailingSpaces,
  },
  ExifTag {
    id: 0x9292,
    name: "SubSecTimeDigitized",
    conv: Conv::TrimTrailingSpaces,
  },
  ExifTag {
    id: 0xa000,
    name: "FlashpixVersion",
    conv: Conv::Version,
  },
  ExifTag {
    id: 0xa001,
    name: "ColorSpace",
    // `PrintHex => 1` (Exif.pm:2693) ⇒ a miss renders `Unknown (0x%x)`.
    conv: Conv::IntLabelHex(COLOR_SPACE),
  },
  ExifTag {
    id: 0xa002,
    name: "ExifImageWidth",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa003,
    name: "ExifImageHeight",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa004,
    name: "RelatedSoundFile",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa20b,
    name: "FlashEnergy",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa20e,
    name: "FocalPlaneXResolution",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa20f,
    name: "FocalPlaneYResolution",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa210,
    name: "FocalPlaneResolutionUnit",
    conv: Conv::IntLabel(RESOLUTION_UNIT),
  },
  ExifTag {
    id: 0xa215,
    name: "ExposureIndex",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa217,
    name: "SensingMethod",
    conv: Conv::IntLabel(SENSING_METHOD),
  },
  ExifTag {
    id: 0xa300,
    name: "FileSource",
    conv: Conv::IntLabel(FILE_SOURCE),
  },
  ExifTag {
    id: 0xa301,
    name: "SceneType",
    conv: Conv::IntLabel(SCENE_TYPE),
  },
  ExifTag {
    id: 0xa401,
    name: "CustomRendered",
    conv: Conv::IntLabel(CUSTOM_RENDERED),
  },
  ExifTag {
    id: 0xa402,
    name: "ExposureMode",
    conv: Conv::IntLabel(EXPOSURE_MODE),
  },
  ExifTag {
    id: 0xa403,
    name: "WhiteBalance",
    conv: Conv::IntLabel(WHITE_BALANCE),
  },
  ExifTag {
    id: 0xa404,
    name: "DigitalZoomRatio",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa405,
    name: "FocalLengthIn35mmFormat",
    conv: Conv::FocalLength35mm,
  },
  ExifTag {
    id: 0xa406,
    name: "SceneCaptureType",
    conv: Conv::IntLabel(SCENE_CAPTURE_TYPE),
  },
  ExifTag {
    id: 0xa407,
    name: "GainControl",
    conv: Conv::IntLabel(GAIN_CONTROL),
  },
  ExifTag {
    id: 0xa408,
    name: "Contrast",
    conv: Conv::IntLabel(CONTRAST),
  },
  ExifTag {
    id: 0xa409,
    name: "Saturation",
    conv: Conv::IntLabel(SATURATION),
  },
  ExifTag {
    id: 0xa40a,
    name: "Sharpness",
    conv: Conv::IntLabel(CONTRAST),
  },
  ExifTag {
    id: 0xa40c,
    name: "SubjectDistanceRange",
    conv: Conv::IntLabel(SUBJECT_DISTANCE_RANGE),
  },
  ExifTag {
    id: 0xa420,
    name: "ImageUniqueID",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa430,
    name: "OwnerName",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa431,
    name: "SerialNumber",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa432,
    name: "LensInfo",
    conv: Conv::LensInfo,
  },
  ExifTag {
    id: 0xa433,
    name: "LensMake",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa434,
    name: "LensModel",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xa435,
    name: "LensSerialNumber",
    conv: Conv::None,
  },
  // ---- InteropIFD tags (Exif.pm:416-435) ----------------------------------
  ExifTag {
    id: 0x0001,
    name: "InteropIndex",
    conv: Conv::StrLabel(INTEROP_INDEX),
  },
  ExifTag {
    id: 0x0002,
    name: "InteropVersion",
    conv: Conv::Version,
  },
];

/// `Flash` (0x9209) PrintConv — the COMPLETE `%flash` enumerated hash
/// (`Exif.pm:175-209`), ported key-for-key. The `OTHER` write-side sub
/// (Exif.pm:176-181) translates "Off"/"On" when WRITING only; it has no
/// effect on the read/PrintConv path so it is not modelled. `PrintHex => 1`
/// (Exif.pm:2417) ⇒ a true miss renders `Unknown (0x%x)`, which
/// [`Conv::IntLabelHex`] already produces. This is the same enumerated set
/// as `formats::h264::flash_print_conv` (both port `%flash`); a faithful
/// copy is kept here to avoid cross-module table plumbing.
const FLASH: &[(i64, &str)] = &[
  (0x00, "No Flash"),
  (0x01, "Fired"),
  (0x05, "Fired, Return not detected"),
  (0x07, "Fired, Return detected"),
  (0x08, "On, Did not fire"),
  (0x09, "On, Fired"),
  (0x0d, "On, Return not detected"),
  (0x0f, "On, Return detected"),
  (0x10, "Off, Did not fire"),
  (0x14, "Off, Did not fire, Return not detected"),
  (0x18, "Auto, Did not fire"),
  (0x19, "Auto, Fired"),
  (0x1d, "Auto, Fired, Return not detected"),
  (0x1f, "Auto, Fired, Return detected"),
  (0x20, "No flash function"),
  (0x30, "Off, No flash function"),
  (0x41, "Fired, Red-eye reduction"),
  (0x45, "Fired, Red-eye reduction, Return not detected"),
  (0x47, "Fired, Red-eye reduction, Return detected"),
  (0x49, "On, Red-eye reduction"),
  (0x4d, "On, Red-eye reduction, Return not detected"),
  (0x4f, "On, Red-eye reduction, Return detected"),
  (0x50, "Off, Red-eye reduction"),
  (0x58, "Auto, Did not fire, Red-eye reduction"),
  (0x59, "Auto, Fired, Red-eye reduction"),
  (0x5d, "Auto, Fired, Red-eye reduction, Return not detected"),
  (0x5f, "Auto, Fired, Red-eye reduction, Return detected"),
];

/// `InteropIndex` STRING-keyed PrintConv (`Exif.pm:423-426`). A miss renders
/// `Unknown ($val)` (the standard HASH-PrintConv fallback); `-n` shows the raw
/// token.
const INTEROP_INDEX: &[(&str, &str)] = &[
  ("R98", "R98 - DCF basic file (sRGB)"),
  ("R03", "R03 - DCF option file (Adobe RGB)"),
  ("THM", "THM - DCF thumbnail file"),
];

/// Resolve a tag ID against [`EXIF_TAGS`]. `None` for an unknown tag.
///
/// The hand [`EXIF_TAGS`] is consulted FIRST; on a miss the `--kind exif`
/// generated shadow ([`generated::lookup`]) is the fallback. A SHARED id
/// resolves identically in both (the differential parity test pins that), so
/// the fallback only matters for the Step-B binary-EXIF coverage-gap ids
/// ([`crate::exif::EXIF_MAIN_GAP_IDS`]) — `%Exif::Main` leaf tags absent from
/// the hand subset, which the generator emits and this fallback returns so they
/// are no longer dropped on the binary IFD path.
#[must_use]
pub fn lookup(id: u16) -> Option<&'static ExifTag> {
  EXIF_TAGS
    .iter()
    .find(|t| t.id == id)
    .or_else(|| generated::lookup(id))
}

/// The tag-table READ-side `Format` override (`$$tagInfo{Format}`,
/// `Exif.pm:6729`), applied to `$formatStr`/`$format`/`$count` BEFORE
/// `ReadValue` (`Exif.pm:6735-6744`). When set, ExifTool re-reads the value
/// with this format regardless of the on-disk format code — the on-disk byte
/// `$size` is preserved and `$count = int($size / $formatSize[$format])`.
///
/// In the camera-relevant `%Exif::Main` subset ported here exactly ONE tag
/// carries such an override: `UserComment` (0x9286), `Format => 'undef'`
/// (`Exif.pm:2500`), with the explicit Phil-Harvey comment "I have seen other
/// applications write it incorrectly as 'string' or 'int8u'" (`Exif.pm:2499`).
/// Forcing `undef` BEFORE `ReadValue` is what stops a mis-written `string`
/// 0x9286 from being NUL-trimmed (`ASCII\0\0\0Hello World` → `ASCII`) so the
/// later `ConvertExifText` RawConv can strip the 8-byte charset prefix and
/// recover the payload.
///
/// This `%Exif::Main` override is resolved ONLY for non-GPS IFDs; the GPS IFD
/// has its own table-scoped sibling [`crate::exif::gps::format_override`] (for
/// `GPSDateStamp` 0x001d, `Format => 'undef'`, `GPS.pm:312`). NOTE the contrast
/// with the GPS text tags `GPSProcessingMethod`/`GPSAreaInformation`: those
/// carry `Writable => 'undef'` but NOT `Format => 'undef'` (`GPS.pm:296/304`),
/// so `$$tagInfo{Format}` is unset and a `string`-on-disk GPS text tag IS
/// NUL-trimmed by bundled ExifTool. Hence the override is keyed on `Format`,
/// not `Writable`, and applies to 0x9286 only here (and only outside the GPS
/// IFD, whose 0x9286 is unrelated).
#[must_use]
pub const fn format_override(id: u16) -> Option<crate::exif::ifd::Format> {
  match id {
    0x9286 => Some(crate::exif::ifd::Format::Undef),
    _ => None,
  }
}

// ===========================================================================
// Conversion helpers — the Print* / Convert* functions (Exif.pm/ExifTool.pm)
// ===========================================================================

/// Look up `code` in a `(code, label)` slice.
#[must_use]
pub fn label_for(slice: &[(i64, &'static str)], code: i64) -> Option<&'static str> {
  slice.iter().find_map(|&(k, v)| (k == code).then_some(v))
}

/// Look up `key` in a `(key, label)` slice (`Conv::StrLabel` PrintConv).
#[must_use]
pub fn str_label_for(slice: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
  slice.iter().find_map(|&(k, v)| (k == key).then_some(v))
}

/// `PrintExposureTime` (`Exif.pm:5701-5711`):
/// ```text
/// return $secs unless IsFloat($secs);
/// if ($secs < 0.25001 and $secs > 0) { return sprintf("1/%d",int(0.5 + 1/$secs)) }
/// $_ = sprintf("%.1f",$secs); s/\.0$//; return $_;
/// ```
#[must_use]
pub fn print_exposure_time(secs: f64) -> std::string::String {
  use std::string::ToString;
  if !secs.is_finite() {
    // Perl `IsFloat` is false for inf/NaN ⇒ return the input unchanged.
    return secs.to_string();
  }
  if secs < 0.250_01 && secs > 0.0 {
    // `sprintf("1/%d", int(0.5 + 1/$secs))` — Perl `int` truncates toward 0.
    let denom = (0.5 + 1.0 / secs).trunc() as i64;
    return std::format!("1/{denom}");
  }
  let s = std::format!("{secs:.1}");
  // `s/\.0$//` — drop a trailing ".0".
  match s.strip_suffix(".0") {
    Some(stripped) => stripped.to_string(),
    None => s,
  }
}

/// `PrintFNumber` (`Exif.pm:5715-5723`):
/// ```text
/// if (IsFloat($val) and $val > 0) {
///   $val = sprintf(($val<1 ? "%.2f" : "%.1f"), $val);
/// }
/// return $val;
/// ```
#[must_use]
pub fn print_fnumber(val: f64) -> std::string::String {
  use std::string::ToString;
  if val.is_finite() && val > 0.0 {
    if val < 1.0 {
      return std::format!("{val:.2}");
    }
    return std::format!("{val:.1}");
  }
  val.to_string()
}

/// `PrintFraction` (`Exif.pm:5516-5535`) — the `ExposureCompensation` /
/// `ConvertFraction` PrintConv:
/// ```text
/// $val *= 1.00001;            # avoid round-off errors
/// if (not $val)                       { $str = '0' }
/// elsif (int($val)/$val > 0.999)      { $str = sprintf("%+d", int($val)) }
/// elsif ((int($val*2))/($val*2)>0.999){ $str = sprintf("%+d/2", int($val*2)) }
/// elsif ((int($val*3))/($val*3)>0.999){ $str = sprintf("%+d/3", int($val*3)) }
/// else                                { $str = sprintf("%+.3g", $val) }
/// ```
#[must_use]
pub fn print_fraction(val: f64) -> std::string::String {
  let v = val * 1.000_01;
  if v == 0.0 {
    return "0".into();
  }
  // Perl `int` truncates toward zero.
  let i1 = v.trunc();
  if i1 / v > 0.999 {
    return std::format!("{:+}", i1 as i64);
  }
  let v2 = v * 2.0;
  let i2 = v2.trunc();
  if i2 / v2 > 0.999 {
    return std::format!("{:+}/2", i2 as i64);
  }
  let v3 = v * 3.0;
  let i3 = v3.trunc();
  if i3 / v3 > 0.999 {
    return std::format!("{:+}/3", i3 as i64);
  }
  // `sprintf("%+.3g", $val)` — 3 significant figures with an explicit sign.
  let body = crate::value::format_g(v.abs(), 3);
  let sign = if v < 0.0 { '-' } else { '+' };
  std::format!("{sign}{body}")
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); relaxed for the test module (test indexing is an
// assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn lookup_finds_camera_tags() {
    assert_eq!(lookup(0x010f).map(|t| t.name), Some("Make"));
    assert_eq!(lookup(0x0110).map(|t| t.name), Some("Model"));
    assert_eq!(lookup(0xa434).map(|t| t.name), Some("LensModel"));
    assert_eq!(lookup(0x9003).map(|t| t.name), Some("DateTimeOriginal"));
    assert_eq!(lookup(0x829d).map(|t| t.name), Some("FNumber"));
    // Unknown tag ⇒ None (incremental-completion / verbose-only fallback).
    assert!(lookup(0xdead).is_none());
  }

  #[test]
  fn print_exposure_time_faithful() {
    // 1/724 s — sub-quarter-second branch.
    assert_eq!(print_exposure_time(1.0 / 724.0), "1/724");
    // 0.5 s — the ".1f" branch.
    assert_eq!(print_exposure_time(0.5), "0.5");
    // 2.0 s — whole number ⇒ ".0" stripped.
    assert_eq!(print_exposure_time(2.0), "2");
  }

  #[test]
  fn print_fnumber_faithful() {
    // FNumber 16.0 → "16.0" (>= 1 ⇒ %.1f).
    assert_eq!(print_fnumber(16.0), "16.0");
    // FNumber 0.64 → "0.64" (< 1 ⇒ %.2f).
    assert_eq!(print_fnumber(0.640_234_375), "0.64");
  }

  #[test]
  fn print_fraction_faithful() {
    // ExposureCompensation -0.65 → "-0.65": the int/int branches all fail
    // (0/x, -1/-1.3, -1/-1.95 are all ≤ 0.999), so the `%+.3g` branch fires
    // ⇒ "-0.65" (bundled `perl exiftool` on GPS.jpg shows the bare -0.65).
    assert_eq!(print_fraction(-0.65), "-0.65");
    // 0 → "0".
    assert_eq!(print_fraction(0.0), "0");
    // +1 → "+1" (int(1.00001)/1.00001 = 1/1.00001 > 0.999 ⇒ "%+d" of int).
    assert_eq!(print_fraction(1.0), "+1");
    // +1/3 ≈ 0.3333 → "+1/3" (the int(val*3)/(val*3) branch).
    assert_eq!(print_fraction(1.0 / 3.0), "+1/3");
    // -0.5 → "-1/2" (the int(val*2)/(val*2) branch).
    assert_eq!(print_fraction(-0.5), "-1/2");
  }

  #[test]
  fn label_lookup() {
    assert_eq!(label_for(ORIENTATION, 1), Some("Horizontal (normal)"));
    assert_eq!(label_for(COMPRESSION, 5), Some("LZW"));
    assert_eq!(label_for(COMPRESSION, 99999), None);
  }

  /// THE PARITY PROOF (table-codegen Step A): the `--kind exif` generated shadow
  /// (`tables_generated.rs`) must reproduce EVERY hand [`EXIF_TAGS`] row
  /// byte-identically — same NAME and same [`Conv`] (slice contents and all).
  /// This is what de-risks the emitter: the generated table is a verified
  /// shadow of the hand table, so a future Step B can extend it with confidence.
  #[test]
  fn generated_shadow_matches_hand_table() {
    for hand in EXIF_TAGS {
      let shadow = generated::lookup(hand.id).unwrap_or_else(|| {
        panic!(
          "generated shadow is MISSING hand id {:#06x} ({})",
          hand.id, hand.name
        )
      });
      assert_eq!(
        shadow.name, hand.name,
        "name mismatch at id {:#06x}: generated={:?} hand={:?}",
        hand.id, shadow.name, hand.name
      );
      assert_eq!(
        shadow.conv, hand.conv,
        "conv mismatch at id {:#06x} ({}): generated={:?} hand={:?}",
        hand.id, hand.name, shadow.conv, hand.conv
      );
    }
  }
}
