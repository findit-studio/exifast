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

/// `SubIFD` (0x014a, `Exif.pm:1006-1027`) — the classic-TIFF preview/raw
/// sub-IFD pointer. `Flags => 'SubIFD'`, `SubDirectory => { Start => '$val',
/// MaxSubdirs => 10 }`, `Groups => { 1 => 'SubIFD' }`. UNLIKE the single-offset
/// ExifIFD/GPS/Interop pointers, the value carries MULTIPLE int32u offsets
/// (`@values = split ' ', $val`, `Exif.pm:6930`), each descended as
/// `SubIFD`/`SubIFD1`/`SubIFD2`/… The DNG raw tower's `JpgFromRaw` lives in
/// `SubIFD2` (#331-P2). (The conditional A100DataOffset arm, `Exif.pm:1028`,
/// fires only for a SONY DSLR-A100 ARW — out of scope; for DNG/TIFF the SubIFD
/// arm always wins.)
pub const TAG_SUB_IFD: u16 = 0x014a;

/// `Compression` (0x0103, `Exif.pm:512-528`) — the TIFF compression scheme.
/// Its `RawConv` sets the `$$self{Compression}` DataMember (`Exif.pm:517`,
/// `return $$self{Compression} = $val`), which the `0x111`/`0x117` conditional
/// tag lists consult: `$$self{Compression} eq '7'` (JPEG) gates the
/// `PreviewImage`/`JpgFromRaw` arms vs the plain `StripOffsets` arm
/// (`Exif.pm:635`/`:735`, #331-P2). `int16u` (SHORT).
pub const TAG_COMPRESSION: u16 = 0x0103;

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

/// `DNGVersion` (0xc612, `Exif.pm:3354-3365`) — the Digital Negative
/// specification version (`int8u[4]`). Its `RawConv` (`Exif.pm:3365`
/// `$$self{DNGVersion} = $val`) sets the `$$self{DNGVersion}` DataMember as a
/// side effect of the IFD walk — even though the tag is itself absent from the
/// port's leaf table (a deferred-table item, like [`TAG_OLD_SUBFILE_TYPE`]).
/// That DataMember is what `DoProcessTIFF` (`ExifTool.pm:8763`) tests — via the
/// Perl-truthiness gate `if ($$self{DNGVersion} and …)` — to override
/// `File:FileType` to `DNG` for a TIFF-structured file regardless of extension.
/// The walker taps it before the unknown-tag `next` (`Exif.pm:6757`) drops it
/// from the emitted entries; the value's truthiness is tracked (a count-0 /
/// scalar-`0` value is falsy → no override), but the value is never emitted
/// (the port emits no `IFD0:DNGVersion` tag).
pub const TAG_DNG_VERSION: u16 = 0xc612;

/// `GeoTiffDirectory` (0x87af, `Exif.pm:2059-2079`) — the GeoKey directory
/// (`int16u` array), `Format => 'undef'`, `Binary => 1`. ExifTool's `RawConv`
/// saves the raw block for `ProcessGeoTiff` (`GeoTiff.pm:2136`) and the tag is
/// deleted from default output. The walker captures the raw bytes
/// ([`crate::exif`] [`Walker`]) WITHOUT emitting the leaf.
pub const TAG_GEOTIFF_DIRECTORY: u16 = 0x87af;

/// `GeoTiffDoubleParams` (0x87b0, `Exif.pm:2081-2097`) — the `double` parameter
/// block a GeoKey with `loc == 0x87b0` indexes (`GeoTiff.pm:2177`). `Binary => 1`,
/// captured raw, never emitted.
pub const TAG_GEOTIFF_DOUBLE_PARAMS: u16 = 0x87b0;

/// `GeoTiffAsciiParams` (0x87b1, `Exif.pm:2099-2105`) — the `string` parameter
/// block a GeoKey with `loc == 0x87b1` slices (`GeoTiff.pm:2179`). `Binary => 1`,
/// captured raw, never emitted.
pub const TAG_GEOTIFF_ASCII_PARAMS: u16 = 0x87b1;

/// `ColorMap` (0x0140, `Exif.pm:961-965`) — the `int16u[3*2^BitsPerSample]` RGB
/// palette, `Format => 'binary'`, `Binary => 1`. Classic `ProcessExif` applies
/// the `'binary'` (= `undef`) [`format_override`] so it decodes as raw bytes (the
/// `(Binary data N bytes …)` placeholder reports the on-disk byte count). The
/// BigTIFF walker does NOT apply that override (`ProcessBigIFD` `ReadValue`s with
/// the on-disk `int16u`), so its placeholder reports `length(join(' ', @vals))`
/// instead — handled in the BigTIFF Binary-placeholder path, keyed by this id.
pub const TAG_COLOR_MAP: u16 = 0x0140;

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
  /// `SR2SubIFDKey` (0x7221) PrintConv — `sprintf("0x%.8x", $val)`
  /// (`Sony.pm:10479`). The int32u key value is rendered as a zero-padded
  /// 8-digit hex string `0x________`. With print_conv OFF the bare decimal value
  /// emits (the `emit_raw` path).
  SonyHex8,
  /// `%MinoltaRaw::RIF` `WBMode` (offset 4) PrintConv —
  /// `Image::ExifTool::MinoltaRaw::ConvertWBMode($val)` (`MinoltaRaw.pm:161`,
  /// `:348-371`). The low nibble selects the WB name; a high nibble in `6..=12`
  /// appends ` (hi-8)`. With print_conv OFF the bare `$val` integer emits.
  MinoltaWbMode,
  /// `%MinoltaRaw::RIF` `ISOSetting` (offset 6) PrintConv (`MinoltaRaw.pm:179-200`)
  /// — a HASH (`0 => 'Auto'`, `48 => 100`, …, `174 => '80 (Zone Matching Low)'`)
  /// with an `OTHER` fall-through `int(2 ** (($val-48)/8) * 100 + 0.5)`. The
  /// `RawConv => '$val == 255 ? undef'` drop is applied at decode (the leaf is not
  /// emitted for `255`). With print_conv OFF the bare `$val` integer emits.
  MinoltaIsoSetting,
  /// `%MinoltaRaw::RIF` `ColorTemperature` (offset 78, the A200/A700 arm,
  /// `MinoltaRaw.pm:325-333`) — `ValueConv => '$val * 100'` then
  /// `PrintConv => '$val ? $val : "Auto"'`. With print_conv OFF the post-ValueConv
  /// `$val * 100` integer emits (so a zero raw stays `0`, not `"Auto"`).
  MinoltaColorTemperature,
  /// `FileSource` (0xa300) PrintConv (`Exif.pm:2815-2821`). A HASH whose keys
  /// are the integer codes `1`/`2`/`3` PLUS the literal 4-byte STRING
  /// `"\x03\x00\x00\x00"` (`Exif.pm:2820`) — Sigma incorrectly gives this
  /// `Writable => 'undef'` tag a count of 4, so a single value `\x03` matches
  /// the integer key `3` (the `undef[1] → int8u` carve-out, `Exif.pm:6682`)
  /// while the 4-byte `\x03\x00\x00\x00` matches the string key →
  /// `'Sigma Digital Camera'`. The integer codes flow through [`Conv::IntLabel`]
  /// (the single-byte carve-out makes them a `RawValue::U64`); only the
  /// multi-byte `undef` value needs the literal-string key handled here, with a
  /// HASH-miss falling to `Unknown ($val)` over the raw byte string
  /// (`ExifTool.pm:3614-3634`) exactly as bundled.
  FileSource(&'static [(i64, &'static str)]),
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
  /// Windows XP `XP*` tags (`XPComment` 0x9c9c / `XPKeywords` 0x9c9e, also
  /// `XPTitle`/`XPAuthor`/`XPSubject`) — `Format => 'undef'`, `ValueConv =>
  /// '$self->Decode($val,"UCS2","II")'` (`Exif.pm:2643-2650`/`:2661-2668`).
  /// The value is a little-endian UCS-2 (UTF-16LE) string, NUL-terminated;
  /// `Decode` converts it to UTF-8. It is a ValueConv (no further PrintConv),
  /// so the decoded UTF-8 is emitted in BOTH `-j` and `-n`. The on-disk format
  /// is `int8u`, so the walker decodes a `U64` byte array; this conv
  /// reconstructs the byte string before the UCS-2 decode.
  WindowsXp,
  /// A `Binary => 1` tag (`DeviceSettingDescription` 0xa40b, `Exif.pm:2957-2961`)
  /// — the value is rendered as the universal `(Binary data N bytes, use -b
  /// option to extract)` placeholder in default (`-b`-less) output, in BOTH
  /// `-j` and `-n`. `N` is the on-disk value byte length.
  BinaryData,
}

// ===========================================================================
// Tag descriptor — `ExifTag`
// ===========================================================================

/// One Exif IFD tag descriptor — a row of `%Image::ExifTool::Exif::Main`.
#[derive(Debug, Clone, Copy)]
pub struct ExifTag {
  /// On-disk tag ID (`%Exif::Main` hash key).
  id: u16,
  /// Tag NAME (`Name => '…'`).
  name: &'static str,
  /// The conversion ExifTool applies.
  conv: Conv,
}

/// The `OffsetPair` + `DataTag` attribute pair on an `IsOffset` leaf
/// (`Exif.pm:1168-1171` for `ThumbnailOffset`). It binds an offset tag to its
/// paired LENGTH tag (`OffsetPair => 0x202`) and the SYNTHETIC binary-image
/// tag that the offset+length describe (`DataTag => 'ThumbnailImage'`).
///
/// ExifTool extracts the named image as a Composite that `Require`s the
/// offset+length and calls `ExtractImage($self, $offset, $length, $dataTag)`
/// (`Exif.pm:4977-4991`), emitting it under the offset tag's OWN family-0/1
/// groups (`@grps = $self->GetGroup($$val{0})`, `Exif.pm:4989`) — i.e.
/// `IFD1:ThumbnailImage` for an IFD1 `ThumbnailOffset`. The port reproduces
/// that with the [`crate::exif`] walker's post-IFD data-tag pass.
#[derive(Debug, Clone, Copy)]
pub struct DataTagSpec {
  /// The paired tag ID — the LENGTH tag for an `IsOffset` leaf
  /// (`OffsetPair => 0x202`, `Exif.pm:1170`).
  offset_pair: u16,
  /// The synthetic image tag NAME the offset+length describe
  /// (`DataTag => 'ThumbnailImage'`, `Exif.pm:1171`).
  data_tag: &'static str,
}

impl DataTagSpec {
  /// The paired LENGTH tag ID (`$$tagInfo{OffsetPair}`).
  #[must_use]
  #[inline]
  pub const fn offset_pair(self) -> u16 {
    self.offset_pair
  }

  /// The synthetic image tag NAME (`$$tagInfo{DataTag}`).
  #[must_use]
  #[inline]
  pub const fn data_tag(self) -> &'static str {
    self.data_tag
  }
}

impl ExifTag {
  /// Construct a tag descriptor — the const constructor the table literals
  /// (and the synthetic-image placeholder in [`crate::exif`]) use in place of
  /// a private-field struct literal.
  #[must_use]
  #[inline]
  pub const fn new(id: u16, name: &'static str, conv: Conv) -> Self {
    Self { id, name, conv }
  }

  /// On-disk tag ID (`%Exif::Main` hash key).
  #[must_use]
  #[inline]
  pub const fn id(&self) -> u16 {
    self.id
  }

  /// Tag NAME (`Name => '…'`).
  #[must_use]
  #[inline]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// The conversion ExifTool applies.
  #[must_use]
  #[inline]
  pub const fn conv(&self) -> Conv {
    self.conv
  }

  /// The `OffsetPair`/`DataTag` attribute pair for this leaf, if it is an
  /// `IsOffset` tag that names a binary `DataTag` image — `None` for every
  /// other leaf. Keyed by tag ID (the attribute lives on the `%Exif::Main`
  /// row), mirroring the existing id-keyed [`format_override`] /
  /// [`crate::exif::is_offset_tag`] modelling of the per-row `Format`/`IsOffset`
  /// attributes rather than threading a field through all ~215 table literals
  /// (incl. the generated shadow, which the xtask owns).
  ///
  /// The id-DEFAULT spec — `ThumbnailOffset` (0x0201) → the camera-relevant IFD1
  /// thumbnail (`Exif.pm:1168-1171`, `OffsetPair => 0x202`,
  /// `DataTag => 'ThumbnailImage'`). The CONDITIONAL `PreviewImage` arms — 0x111
  /// in IFD0/CR2 and 0x201 in IFD0/ARW (`Exif.pm:645-661`/`:1226-1237`, #331-P2)
  /// — depend on `$$self{TIFF_TYPE}` + `DIR_NAME`, so they live in the
  /// context-aware [`exif_main_data_tag_spec_in_context`]; this id-only method
  /// returns the default the walker uses when no context override applies. The
  /// remaining `%Exif::Main` `DataTag` offsets (`JpgFromRawStart`/`OtherImageStart`,
  /// `Exif.pm:674-679`) are P3 follow-ups (#331); when ported, extend both.
  #[must_use]
  #[inline]
  pub const fn data_tag_spec(&self) -> Option<DataTagSpec> {
    match self.id {
      0x0201 => Some(DataTagSpec {
        offset_pair: 0x0202,
        data_tag: "ThumbnailImage",
      }),
      _ => None,
    }
  }
}

/// The `$$self{TIFF_TYPE}` + `$$self{DIR_NAME}` + `$$self{Compression}` +
/// `$$self{SubfileType}` context the `0x111`/`0x117`/`0x201`/`0x202` CONDITIONAL
/// tag lists (`Exif.pm:601-779`/`:1148-1294`) resolve their `Name`/`OffsetPair`/
/// `DataTag` against — the `DataMember`s a `ProcessExif` directory threads into
/// `GetTagInfo`'s `Condition` eval. Bundled by [`Walker::emit`] at the resolution
/// site from the walk's `IfdKind` + `file_type` + the per-IFD
/// `captured_compression`/`captured_subfile_type` DataMembers.
#[derive(Debug, Clone, Copy)]
pub struct OffsetTagContext<'a> {
  /// `$$self{TIFF_TYPE}` — the detected subtype (`"CR2"`/`"ARW"`/`"SR2"`/
  /// `"DNG"`/`"TIFF"`/…), `ExifTool.pm:8715`.
  pub tiff_type: Option<&'a str>,
  /// `$$self{DIR_NAME} eq 'IFD0'`.
  pub in_ifd0: bool,
  /// `$$self{DIR_NAME} eq 'SubIFD2'` — the classic-TIFF SubIFD tower's THIRD
  /// directory ([`IfdKind::SubIfd(2)`]), where `0x111`/`0x117` name
  /// `JpgFromRawStart`/`JpgFromRawLength` (`Exif.pm:673-684`/`:769-778`).
  pub in_subifd2: bool,
  /// `$$self{DIR_NAME} eq 'IFD2'` — the SECOND trailing IFD
  /// ([`IfdKind::Trailing(2)`]), where `0x201`/`0x202` name `JpgFromRawStart`/
  /// `JpgFromRawLength` (`DataTag => 'JpgFromRaw'`, `Exif.pm:1251-1263`/
  /// `:1346-1357` — "JpgFromRaw is in IFD2 of PEF files", and a Sony ARW's IFD2
  /// JPEG preview).
  pub in_ifd2: bool,
  /// `$$self{Compression}` (the 0x103 DataMember) as the EXACT scalar `$val`
  /// STRING (`None` ≡ ExifTool's `''` sentinel). The DNG/TIFF `PreviewImage`/
  /// `JpgFromRaw` arms gate on `Compression eq '7'` (JPEG) with STRING equality;
  /// `''` (`None`), a count>1 `"7 8"`, and any other value fall to the plain
  /// `StripOffsets` arm.
  pub compression: Option<&'a str>,
  /// `$$self{SubfileType}` (the 0xfe DataMember) as the EXACT scalar `$val`
  /// STRING (`None` ≡ `''`). The DNG/TIFF preview arms' EXCLUSION of the plain
  /// `StripOffsets` arm requires `SubfileType ne '0'` (STRING) — `''` (`None`), a
  /// count>1 `"0 1"`, and any non-`"0"` value SATISFY it (`'' ne '0'` /
  /// `'0 1' ne '0'` are true in Perl); only an exact `"0"` fails.
  pub subfile_type: Option<&'a str>,
}

impl OffsetTagContext<'_> {
  /// `true` when the DNG/TIFF JPEG-preview gate holds — `$$self{TIFF_TYPE} =~
  /// /^(DNG|TIFF)$/ and $$self{Compression} eq '7' and $$self{SubfileType} ne
  /// '0'` (`Exif.pm:635`/`:735`). When this holds, the plain `StripOffsets` arm
  /// (`Exif.pm:631-643`) is EXCLUDED, so `0x111`/`0x117` resolve to the
  /// `PreviewImage` arm (`DIR_NAME ne 'SubIFD2'`, `Exif.pm:661-672`) or the
  /// `JpgFromRaw` arm (the `SubIFD2` fallthrough, `Exif.pm:673-684`).
  #[must_use]
  #[inline]
  fn dng_tiff_jpeg_preview(&self) -> bool {
    // `TIFF_TYPE =~ /^(DNG|TIFF)$/`.
    let dng_or_tiff = matches!(self.tiff_type, Some("DNG" | "TIFF"));
    // `Compression eq '7'` (STRING equality) — a `''`/`None`, a count>1 `"7 8"`,
    // or any other value is false.
    let comp7 = self.compression == Some("7");
    // `SubfileType ne '0'` (STRING inequality) — `''`/`None`, a count>1 `"0 1"`,
    // and any non-`"0"` value pass; only an exact `"0"` fails.
    let subfile_ne0 = self.subfile_type != Some("0");
    dng_or_tiff && comp7 && subfile_ne0
  }
}

/// The conditional `Name` override for a `%Exif::Main` offset/length leaf whose
/// id is a `Condition`-list entry — `Exif.pm`'s `0x111`/`0x117`/`0x201`/`0x202`
/// are CONDITIONAL TAG LISTS that resolve to a DIFFERENT name depending on
/// `$$self{TIFF_TYPE}` + `$$self{DIR_NAME}` (+ the `Compression`/`SubfileType`
/// DataMembers for the DNG/TIFF arms). The port's static table carries the
/// most-common name (`StripOffsets`/`StripByteCounts` for 0x111/0x117,
/// `ThumbnailOffset`/`ThumbnailLength` for 0x201/0x202); this reproduces the
/// camera-relevant `PreviewImage`/`JpgFromRaw` arms (#331-P2):
///
///  - 0x111 → `PreviewImageStart` / 0x117 → `PreviewImageLength` in **IFD0 of a
///    CR2** (`Exif.pm:645-661`/`:742-758`, `Condition => '$$self{TIFF_TYPE} eq
///    "CR2"'`). The DEFAULT `StripOffsets` arm explicitly EXCLUDES this case
///    (`not ($$self{TIFF_TYPE} eq 'CR2' and $$self{DIR_NAME} eq 'IFD0')`,
///    `Exif.pm:643`), so a CR2 IFD0 falls through to the `PreviewImageStart` arm.
///  - 0x201 → `PreviewImageStart` / 0x202 → `PreviewImageLength` in **IFD0 of an
///    ARW or SR2** (`Exif.pm:1226-1237`, `Condition => '$$self{DIR_NAME} eq
///    "IFD0" and $$self{TIFF_TYPE} =~ /^(ARW|SR2)$/'`). The FIRST (ThumbnailOffset)
///    arm matches only IFD1 / RIFF-MOV-IFD0, so an ARW IFD0 reaches this arm.
///  - 0x111 → `JpgFromRawStart` / 0x117 → `JpgFromRawLength` in a **DNG/TIFF
///    SubIFD2** carrying `Compression == 7` + `SubfileType != 0`
///    (`Exif.pm:673-684`/`:769-778` — the `SubIFD2` fallthrough arm). The plain
///    `StripOffsets` arm is excluded by the JPEG-preview gate, the CR2 arm
///    misses (not CR2), and the `PreviewImageStart` arm misses (`DIR_NAME eq
///    'SubIFD2'`), so the JpgFromRaw arm wins.
///  - 0x111 → `PreviewImageStart` / 0x117 → `PreviewImageLength` in a **DNG/TIFF
///    NON-SubIFD2** directory carrying `Compression == 7` + `SubfileType != 0`
///    (`Exif.pm:661-672`/`:758-768` — `DIR_NAME ne 'SubIFD2'`).
///
/// `None` ⇒ the table default name is correct (every IFD1 thumbnail keeps
/// `ThumbnailOffset`/`Length`; a DNG SubIFD strip with NO `Compression=7` keeps
/// `StripOffsets`/`StripByteCounts` — the plain `StripOffsets` arm wins,
/// `Exif.pm:631-643`).
#[must_use]
#[inline]
pub fn exif_main_offset_name_override(
  tag_id: u16,
  ctx: OffsetTagContext<'_>,
) -> Option<&'static str> {
  // IFD0-only `PreviewImageStart` arms (CR2 0x111, ARW/SR2 0x201).
  if ctx.in_ifd0 {
    match tag_id {
      0x0111 if ctx.tiff_type == Some("CR2") => return Some("PreviewImageStart"),
      0x0117 if ctx.tiff_type == Some("CR2") => return Some("PreviewImageLength"),
      0x0201 if matches!(ctx.tiff_type, Some("ARW" | "SR2")) => {
        return Some("PreviewImageStart");
      }
      0x0202 if matches!(ctx.tiff_type, Some("ARW" | "SR2")) => {
        return Some("PreviewImageLength");
      }
      _ => {}
    }
  }
  // `0x201`/`0x202` in IFD2 (any TIFF type) — `JpgFromRawStart`/`JpgFromRawLength`
  // (`Exif.pm:1251-1263`/`:1346-1357`, `DIR_NAME eq "IFD2"`). The Sony ARW IFD2
  // holds the full-res embedded JPEG.
  if ctx.in_ifd2 {
    match tag_id {
      0x0201 => return Some("JpgFromRawStart"),
      0x0202 => return Some("JpgFromRawLength"),
      _ => {}
    }
  }
  // The DNG/TIFF JPEG-preview arms (0x111/0x117): `JpgFromRawStart`/`Length` in
  // SubIFD2, `PreviewImageStart`/`Length` elsewhere — both gated on the
  // JPEG-preview DataMember test (`Compression == 7` + `SubfileType != 0`).
  if ctx.dng_tiff_jpeg_preview() {
    match (tag_id, ctx.in_subifd2) {
      (0x0111, true) => return Some("JpgFromRawStart"),
      (0x0117, true) => return Some("JpgFromRawLength"),
      (0x0111, false) => return Some("PreviewImageStart"),
      (0x0117, false) => return Some("PreviewImageLength"),
      _ => {}
    }
  }
  None
}

/// The `%Exif::Main` `OffsetPair`/`DataTag` spec for an offset leaf, RESOLVED in
/// the IFD's `$$self{TIFF_TYPE}` + `$$self{DIR_NAME}` + `Compression`/
/// `SubfileType` context — the conditional analogue of [`ExifTag::data_tag_spec`]
/// (which returns only the static `ThumbnailImage` default keyed by id). Mirrors
/// the [`exif_main_offset_name_override`] rename:
///
///  - IFD0 of a CR2: 0x111 → `OffsetPair => 0x117`, `DataTag => 'PreviewImage'`
///    (`Exif.pm:645-661`).
///  - IFD0 of an ARW/SR2: 0x201 → `OffsetPair => 0x202`, `DataTag => 'PreviewImage'`
///    (`Exif.pm:1226-1237`) — overriding the id-default `ThumbnailImage`.
///  - DNG/TIFF SubIFD2 (`Compression == 7` + `SubfileType != 0`): 0x111 →
///    `OffsetPair => 0x117`, `DataTag => 'JpgFromRaw'` (`Exif.pm:673-684`).
///  - DNG/TIFF non-SubIFD2 (`Compression == 7` + `SubfileType != 0`): 0x111 →
///    `OffsetPair => 0x117`, `DataTag => 'PreviewImage'` (`Exif.pm:661-672`).
///  - otherwise: the id-default (`ThumbnailOffset` 0x201 → `ThumbnailImage`).
///
/// So an IFD1 thumbnail still yields `ThumbnailImage`; only a CR2/ARW/SR2 IFD0
/// preview leaf yields `PreviewImage`, a DNG/TIFF SubIFD2 JPEG strip yields
/// `JpgFromRaw`, and a DNG/TIFF non-SubIFD2 JPEG strip yields `PreviewImage`.
/// `None` ⇒ no `DataTag` binary for this id.
#[must_use]
#[inline]
pub fn exif_main_data_tag_spec_in_context(
  tag: &ExifTag,
  ctx: OffsetTagContext<'_>,
) -> Option<DataTagSpec> {
  if ctx.in_ifd0 {
    match tag.id {
      0x0111 if ctx.tiff_type == Some("CR2") => {
        return Some(DataTagSpec {
          offset_pair: 0x0117,
          data_tag: "PreviewImage",
        });
      }
      0x0201 if matches!(ctx.tiff_type, Some("ARW" | "SR2")) => {
        return Some(DataTagSpec {
          offset_pair: 0x0202,
          data_tag: "PreviewImage",
        });
      }
      _ => {}
    }
  }
  // `0x201` in IFD2 — `JpgFromRawStart`, `OffsetPair => 0x202`, `DataTag =>
  // 'JpgFromRaw'` (`Exif.pm:1251-1263`). The ARW IFD2 embedded JPEG.
  if ctx.in_ifd2 && tag.id == 0x0201 {
    return Some(DataTagSpec {
      offset_pair: 0x0202,
      data_tag: "JpgFromRaw",
    });
  }
  // DNG/TIFF JPEG-preview 0x111 — `JpgFromRaw` in SubIFD2, `PreviewImage`
  // elsewhere. Only the OFFSET id (0x111) carries a `DataTag` (its `OffsetPair`
  // points at the 0x117 LENGTH); 0x117 is the length side (no `DataTag` on the
  // offset-pair OFFSET role), so it is not matched here.
  if tag.id == 0x0111 && ctx.dng_tiff_jpeg_preview() {
    return Some(DataTagSpec {
      offset_pair: 0x0117,
      data_tag: if ctx.in_subifd2 {
        "JpgFromRaw"
      } else {
        "PreviewImage"
      },
    });
  }
  tag.data_tag_spec()
}

/// `%Image::ExifTool::Nikon::PreviewIFD` (`Nikon.pm:5386-5438`) — the small
/// preview-image sub-IFD an SRW raw's Samsung `0x0035` SubDirectory dispatches
/// to (`Samsung.pm:307-327`, #242). The rows REUSE the standard `%Exif::Main`
/// PrintConvs verbatim (`PrintConv => \%Image::ExifTool::Exif::subfileType` /
/// `…::compression`, and inline `ResolutionUnit`/`YCbCrPositioning` maps equal
/// to `%Exif`'s), so each leaf resolves through the SAME [`Conv`] machinery a
/// core Exif IFD uses — what differs from `%Exif::Main` is only the renamed
/// offset/length pair (`PreviewImageStart`/`Length`, not `ThumbnailOffset`/
/// `Length`) and the `DataTag => 'PreviewImage'` it names. The table's
/// `GROUPS => { 1 => PreviewIFD }` family-1 group is applied by the caller (the
/// Samsung isolated walker's capture, [`crate::exif`]), not stored here. Sorted
/// by tag id (binary-search-ready).
pub const NIKON_PREVIEW_IFD_TAGS: &[ExifTag] = &[
  // 0xfe SubfileType — `PrintConv => \%Image::ExifTool::Exif::subfileType`.
  ExifTag {
    id: 0x00fe,
    name: "SubfileType",
    conv: Conv::IntLabel(SUBFILE_TYPE),
  },
  // 0x103 Compression — `PrintConv => \%Image::ExifTool::Exif::compression`
  // (absent from the NX500 body; ported for table completeness).
  ExifTag {
    id: 0x0103,
    name: "Compression",
    conv: Conv::IntLabel(COMPRESSION),
  },
  // 0x11a/0x11b XResolution/YResolution — bare `rational64u`, no PrintConv.
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
  // 0x128 ResolutionUnit — inline `{ 1=>None, 2=>inches, 3=>cm }` (== `%Exif`'s).
  ExifTag {
    id: 0x0128,
    name: "ResolutionUnit",
    conv: Conv::IntLabel(RESOLUTION_UNIT),
  },
  // 0x201 PreviewImageStart — `Flags => 'IsOffset'`, `OffsetPair => 0x202`,
  // `DataTag => 'PreviewImage'`; the offset is paired with the 0x202 length via
  // the post-IFD DataTag pass into the synthetic `PreviewIFD:PreviewImage`. The
  // emitted leaf value itself is the bare int32u start offset.
  ExifTag {
    id: 0x0201,
    name: "PreviewImageStart",
    conv: Conv::None,
  },
  // 0x202 PreviewImageLength — `OffsetPair => 0x201`, `DataTag => 'PreviewImage'`.
  ExifTag {
    id: 0x0202,
    name: "PreviewImageLength",
    conv: Conv::None,
  },
  // 0x213 YCbCrPositioning — inline `{ 1=>Centered, 2=>Co-sited }` (== `%Exif`'s).
  ExifTag {
    id: 0x0213,
    name: "YCbCrPositioning",
    conv: Conv::IntLabel(YCBCR_POSITIONING),
  },
];

/// Resolve a `%Nikon::PreviewIFD` tag by id (binary search over
/// [`NIKON_PREVIEW_IFD_TAGS`]). `None` ⇒ an id not in the table — the walker's
/// verbose-only omit (`Exif.pm:6757`).
#[must_use]
pub fn nikon_preview_ifd_lookup(id: u16) -> Option<&'static ExifTag> {
  match NIKON_PREVIEW_IFD_TAGS.binary_search_by_key(&id, |t| t.id) {
    Ok(i) => NIKON_PREVIEW_IFD_TAGS.get(i),
    Err(_) => None,
  }
}

/// The `%Nikon::PreviewIFD` `OffsetPair`/`DataTag` spec for `id`, if it is the
/// `0x201 PreviewImageStart` offset leaf — `OffsetPair => 0x202`,
/// `DataTag => 'PreviewImage'` (`Nikon.pm:5414-5421`). Distinct from
/// [`ExifTag::data_tag_spec`], whose `0x201` names `ThumbnailImage` for
/// `%Exif::Main`; the DataTag pass selects the spec by ACTIVE table (#242).
#[must_use]
#[inline]
pub const fn nikon_preview_ifd_data_tag_spec(id: u16) -> Option<DataTagSpec> {
  match id {
    0x0201 => Some(DataTagSpec {
      offset_pair: 0x0202,
      data_tag: "PreviewImage",
    }),
    _ => None,
  }
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
  (262, "Kodak 262"),
  (32766, "NeXt or Sony ARW Compressed 2"),
  (32767, "Sony ARW Compressed"),
  (32769, "Packed RAW"),
  (32770, "Samsung SRW Compressed"),
  (32771, "CCIRLEW"),
  (32772, "Samsung SRW Compressed 2"),
  (32773, "PackBits"),
  (32809, "Thunderscan"),
  (32867, "Kodak KDC Compressed"),
  (32895, "IT8CTPAD"),
  (32896, "IT8LW"),
  (32897, "IT8MP"),
  (32898, "IT8BL"),
  (32908, "PixarFilm"),
  (32909, "PixarLog"),
  (32946, "Deflate"),
  (32947, "DCS"),
  (33003, "Aperio JPEG 2000 YCbCr"),
  (33005, "Aperio JPEG 2000 RGB"),
  (34661, "JBIG"),
  (34676, "SGILog"),
  (34677, "SGILog24"),
  (34712, "JPEG 2000"),
  (34713, "Nikon NEF Compressed"),
  (34715, "JBIG2 TIFF FX"),
  (34718, "Microsoft Document Imaging (MDI) Binary Level Codec"),
  (
    34719,
    "Microsoft Document Imaging (MDI) Progressive Transform Codec",
  ),
  (34720, "Microsoft Document Imaging (MDI) Vector"),
  (34887, "ESRI Lerc"),
  (34892, "Lossy JPEG"),
  (34925, "LZMA2"),
  (34926, "Zstd (old)"),
  (34927, "WebP (old)"),
  (34933, "PNG"),
  (34934, "JPEG XR"),
  (50000, "Zstd"),
  (50001, "WebP"),
  (50002, "JPEG XL (old)"),
  (52546, "JPEG XL"),
  (65000, "Kodak DCR Compressed"),
  (65535, "Pentax PEF Compressed"),
];

/// `%JPEG::yCbCrSubSampling` PrintConv (`ExifTool.pm`) — keyed by the
/// space-joined int16u[2] value. Ordered by key string to match the `-listx`
/// generated shadow (the `generated_shadow_matches_hand_table` parity proof
/// compares the slice contents IN ORDER).
const YCBCR_SUBSAMPLING: &[(&str, &str)] = &[
  ("1 1", "YCbCr4:4:4 (1 1)"),
  ("1 2", "YCbCr4:4:0 (1 2)"),
  ("1 4", "YCbCr4:4:1 (1 4)"),
  ("2 1", "YCbCr4:2:2 (2 1)"),
  ("2 2", "YCbCr4:2:0 (2 2)"),
  ("2 4", "YCbCr4:2:1 (2 4)"),
  ("4 1", "YCbCr4:1:1 (4 1)"),
  ("4 2", "YCbCr4:1:0 (4 2)"),
];

/// `SonyRawFileType` (0x7000) PrintConv (`Exif.pm:1620-1627`) — found in Sony
/// ARW `SubIFD`.
const SONY_RAW_FILE_TYPE: &[(i64, &str)] = &[
  (0, "Sony Uncompressed 14-bit RAW"),
  (1, "Sony Uncompressed 12-bit RAW"),
  (2, "Sony Compressed RAW"),
  (3, "Sony Lossless Compressed RAW"),
  (4, "Sony Lossless Compressed RAW 2"),
  (6, "Sony Compressed RAW 2"),
];

/// `VignettingCorrection` (0x7031) PrintConv (`Exif.pm:1645-1650`) — found in
/// Sony ARW `SubIFD`.
const SONY_VIGNETTING_CORRECTION: &[(i64, &str)] = &[
  (256, "Off"),
  (257, "Auto"),
  (272, "Auto (ILCE-1)"),
  (511, "No correction params available"),
];

/// `ChromaticAberrationCorrection` (0x7034) PrintConv (`Exif.pm:1668-1672`) —
/// found in Sony ARW `SubIFD`.
const SONY_CHROMATIC_ABERRATION_CORRECTION: &[(i64, &str)] = &[
  (0, "Off"),
  (1, "Auto"),
  (255, "No correction params available"),
];

/// `DistortionCorrection` (0x7036) PrintConv (`Exif.pm:1690-1695`) — found in
/// Sony ARW `SubIFD`.
const SONY_DISTORTION_CORRECTION: &[(i64, &str)] = &[
  (0, "Off"),
  (1, "Auto"),
  (17, "Auto fixed by lens"),
  (255, "No correction params available"),
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

/// `0x8830 SensitivityType` PrintConv (`Exif.pm`, the `applies to EXIF:ISO tag`
/// row). Sorted by key for binary search.
const SENSITIVITY_TYPE: &[(i64, &str)] = &[
  (0, "Unknown"),
  (1, "Standard Output Sensitivity"),
  (2, "Recommended Exposure Index"),
  (3, "ISO Speed"),
  (
    4,
    "Standard Output Sensitivity and Recommended Exposure Index",
  ),
  (5, "Standard Output Sensitivity and ISO Speed"),
  (6, "Recommended Exposure Index and ISO Speed"),
  (
    7,
    "Standard Output Sensitivity, Recommended Exposure Index and ISO Speed",
  ),
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

/// `Contrast` PrintConv (`Exif.pm:2924-2932`).
const CONTRAST: &[(i64, &str)] = &[(0, "Normal"), (1, "Low"), (2, "High")];

/// `Saturation` PrintConv (`Exif.pm:2936-2944`).
const SATURATION: &[(i64, &str)] = &[(0, "Normal"), (1, "Low"), (2, "High")];

/// `Sharpness` PrintConv (`Exif.pm:2946-2954`) — DISTINCT from `Contrast`:
/// `1 => 'Soft'`, `2 => 'Hard'` (not `Low`/`High`).
const SHARPNESS: &[(i64, &str)] = &[(0, "Normal"), (1, "Soft"), (2, "Hard")];

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
  // 0x0140 `ColorMap` — `Format => 'binary'`, `Binary => 1` (`Exif.pm:961-965`).
  // The SHORT[3*2^BitsPerSample] palette: the `Format => 'binary'` override
  // (format code 7, "same as undef", `ExifTool.pm:104`) re-reads the on-disk
  // value as raw `undef` bytes — `int(size/1)` of them — and `Binary => 1`
  // renders it as the `(Binary data N bytes, …)` placeholder (`N` = the byte
  // length). See [`format_override`] for the `undef` reshape.
  ExifTag {
    id: 0x0140,
    name: "ColorMap",
    conv: Conv::BinaryData,
  },
  ExifTag {
    id: 0x0211,
    name: "YCbCrCoefficients",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x0212,
    name: "YCbCrSubSampling",
    // `%JPEG::yCbCrSubSampling` — a STRING-keyed HASH PrintConv keyed by the
    // space-joined int16u[2] `$val` (`"2 1"` → `"YCbCr4:2:2 (2 1)"`). Rides the
    // shared `Conv::StrLabel` (which space-joins a numeric value for the key),
    // matching the `-listx` generated shadow.
    conv: Conv::StrLabel(YCBCR_SUBSAMPLING),
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
  // ---- Sony ARW SubIFD raw tags (`%Exif::Main`, `Exif.pm:1616-1742`) -------
  // These live in `%Exif::Main` (so the shared Exif table) and surface in the
  // `SubIFD` of Sony ARW raws. Most are bare values (space-joined when count>1);
  // the three correction-mode tags carry a HASH PrintConv.
  ExifTag {
    id: 0x7000,
    name: "SonyRawFileType",
    // `{ 0 => 'Sony Uncompressed 14-bit RAW', 1 => 'Sony Uncompressed 12-bit
    // RAW', 2 => 'Sony Compressed RAW', 3 => 'Sony Lossless Compressed RAW',
    // 4 => 'Sony Lossless Compressed RAW 2', 6 => 'Sony Compressed RAW 2' }`
    // (`Exif.pm:1618-1627`).
    conv: Conv::IntLabel(SONY_RAW_FILE_TYPE),
  },
  ExifTag {
    id: 0x7010,
    name: "SonyToneCurve",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7031,
    name: "VignettingCorrection",
    conv: Conv::IntLabel(SONY_VIGNETTING_CORRECTION),
  },
  ExifTag {
    id: 0x7032,
    name: "VignettingCorrParams",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7034,
    name: "ChromaticAberrationCorrection",
    conv: Conv::IntLabel(SONY_CHROMATIC_ABERRATION_CORRECTION),
  },
  ExifTag {
    id: 0x7035,
    name: "ChromaticAberrationCorrParams",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7036,
    name: "DistortionCorrection",
    conv: Conv::IntLabel(SONY_DISTORTION_CORRECTION),
  },
  ExifTag {
    id: 0x7037,
    name: "DistortionCorrParams",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7038,
    name: "SonyRawImageSize",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7310,
    name: "BlackLevel",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x7313,
    name: "WB_RGGBLevels",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x74c7,
    name: "SonyCropTopLeft",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x74c8,
    name: "SonyCropSize",
    conv: Conv::None,
  },
  // `CFARepeatPatternDim` (0x828d, `Exif.pm:1775`) / `CFAPattern2` (0x828e,
  // `Exif.pm:1782`) — the SubIFD CFA descriptors. 0x828e carries
  // `Format => 'int8u'` (`Exif.pm:1784`), applied via [`format_override`].
  ExifTag {
    id: 0x828d,
    name: "CFARepeatPatternDim",
    conv: Conv::None,
  },
  ExifTag {
    id: 0x828e,
    name: "CFAPattern2",
    conv: Conv::None,
  },
  // ---- DNG SubIFD crop / level tags (`%Exif::Main`, `Exif.pm:3453-3480`) ----
  ExifTag {
    id: 0xc61d,
    name: "WhiteLevel",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xc61f,
    name: "DefaultCropOrigin",
    conv: Conv::None,
  },
  ExifTag {
    id: 0xc620,
    name: "DefaultCropSize",
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
  // ---- GeoTiff IFD0 leaf tags (Exif.pm:1870-1982) -------------------------
  // The four `double` GeoTiff geometry tags carried directly in IFD0 (the
  // GeoKey directory itself rides the three `Binary => 1` block tags 0x87af/
  // 0x87b0/0x87b1, which are captured + decoded by `crate::exif::geotiff`, not
  // emitted as leaves). Each is `Conv::None` — `-listx` shows no `<values>`
  // map, so the generated shadow resolves them to `P::Identity` too. The
  // family-2 `Location` group on ModelTiePoint/ModelTransform never reaches the
  // `-G1 -j` output, so the leaf table need not model it.
  ExifTag {
    // `PixelScale` (0x830e, `Exif.pm:1870-1875`) — `double[3]`.
    id: 0x830e,
    name: "PixelScale",
    conv: Conv::None,
  },
  ExifTag {
    // `IntergraphMatrix` (0x8480, `Exif.pm:1902-1907`) — `double[-1]`.
    id: 0x8480,
    name: "IntergraphMatrix",
    conv: Conv::None,
  },
  ExifTag {
    // `ModelTiePoint` (0x8482, `Exif.pm:1909-1915`) — `double[-1]`,
    // `Groups => { 2 => 'Location' }`.
    id: 0x8482,
    name: "ModelTiePoint",
    conv: Conv::None,
  },
  ExifTag {
    // `ModelTransform` (0x85d8, `Exif.pm:1977-1983`) — `double[16]`,
    // `Groups => { 2 => 'Location' }`.
    id: 0x85d8,
    name: "ModelTransform",
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
    conv: Conv::IntLabel(SENSITIVITY_TYPE),
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
  // 0x9c9c `XPComment` — Windows XP UCS-2(LE) string (`Exif.pm:2643-2650`).
  ExifTag {
    id: 0x9c9c,
    name: "XPComment",
    conv: Conv::WindowsXp,
  },
  // 0x9c9e `XPKeywords` — Windows XP UCS-2(LE) string (`Exif.pm:2661-2668`).
  ExifTag {
    id: 0x9c9e,
    name: "XPKeywords",
    conv: Conv::WindowsXp,
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
    conv: Conv::FileSource(FILE_SOURCE),
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
    conv: Conv::IntLabel(SHARPNESS),
  },
  // 0xa40b `DeviceSettingDescription` — `Binary => 1` (`Exif.pm:2957-2961`).
  ExifTag {
    id: 0xa40b,
    name: "DeviceSettingDescription",
    conv: Conv::BinaryData,
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
/// The camera-relevant `%Exif::Main` subset ported here carries four such
/// overrides:
/// - `UserComment` (0x9286), `Format => 'undef'` (`Exif.pm:2500`), with the
///   explicit Phil-Harvey comment "I have seen other applications write it
///   incorrectly as 'string' or 'int8u'" (`Exif.pm:2499`). Forcing `undef`
///   BEFORE `ReadValue` is what stops a mis-written `string` 0x9286 from being
///   NUL-trimmed (`ASCII\0\0\0Hello World` → `ASCII`) so the later
///   `ConvertExifText` RawConv can strip the 8-byte charset prefix and recover
///   the payload.
/// - `XPComment`/`XPKeywords` (0x9c9c/0x9c9e), `Format => 'undef'` (the UCS-2
///   `WindowsXp` ValueConv must see the exact bytes — see below).
/// - `ComponentsConfiguration` (0x9101), `Format => 'int8u'` (`Exif.pm:2298`).
///   The tag is `Writable => 'undef'` but its READ `Format` is `int8u`, so
///   ExifTool decodes the on-disk value as `int(size/1)` int8u ELEMENTS
///   REGARDLESS of the declared format code — a mis-written `string`/`int16u`/…
///   0x9101 is still read as the raw bytes one-per-element (verified against
///   bundled `exiftool 13.59`: an `int16u[2]` `01 02 03 00` → `1 2 3 0` →
///   "Y, Cb, Cr, -", NOT the int16u decode `258 768`). Without this override
///   a wrong-format 0x9101 decoded per its on-disk format and the
///   `Conv::ComponentsConfiguration` byte-walk diverged (#201). The
///   `Count => 4` is a WRITE hint only; the read count is `int(size/1)`.
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
    // `ColorMap` (0x0140) — `Format => 'binary'` (`Exif.pm:963`). `'binary'` is
    // format code 7, "(same as undef)" (`ExifTool.pm:104`), so the on-disk
    // SHORT[3*2^BitsPerSample] value is re-read as `int(size/1)` raw `undef`
    // bytes (verbose: "int16u[768] read as undef[1536]"); `length($val)` is then
    // the byte size the `Conv::BinaryData` `(Binary data N bytes, …)` placeholder
    // reports (GeoTiff.tif: 1536). Without this the value would decode per its
    // on-disk `int16u[768]` and the placeholder count would be wrong.
    0x0140 => Some(crate::exif::ifd::Format::Undef),
    0x9286 => Some(crate::exif::ifd::Format::Undef),
    // `ComponentsConfiguration` (0x9101) — `Format => 'int8u'` (`Exif.pm:2298`).
    // The on-disk value is re-read as `int(size/1)` int8u elements regardless of
    // the declared format code, so the `Conv::ComponentsConfiguration` per-byte
    // PrintConv sees the raw value bytes one-per-element even when the tag was
    // mis-written as `string`/`int16u`/etc. (#201).
    0x9101 => Some(crate::exif::ifd::Format::Int8u),
    // `CFAPattern2` (0x828e) — `Format => 'int8u'` (`Exif.pm:1784`, "written
    // incorrectly as 'undef' in Nikon NRW images"). The on-disk value is re-read
    // as `int(size/1)` int8u elements so a mis-written `undef`/`int16u` CFA
    // descriptor still decodes to the per-byte `0 1 1 2` (the Sony ARW SubIFD).
    0x828e => Some(crate::exif::ifd::Format::Int8u),
    // `XPComment` (0x9c9c) / `XPKeywords` (0x9c9e) carry `Format => 'undef'`
    // (`Exif.pm:2645`/`:2663`): the on-disk `int8u[N]` value is re-read as raw
    // `undef` bytes so the `WindowsXp` UCS-2(LE) `Decode` ValueConv sees the
    // exact byte string (not a NUL-trimmed/space-joined re-encode).
    0x9c9c | 0x9c9e => Some(crate::exif::ifd::Format::Undef),
    // `GeoTiffDirectory` (0x87af) / `GeoTiffDoubleParams` (0x87b0) /
    // `GeoTiffAsciiParams` (0x87b1) all carry `Format => 'undef'`
    // (`Exif.pm:2061`/`:2083`/`:2101`, `Binary => 1`). ExifTool applies this
    // READ override (`Exif.pm:6733`) so `$formatStr` becomes `'undef'` BEFORE the
    // excessive-count guard, whose `$formatStr !~ /^(undef|string|binary)$/`
    // exclusion (`Exif.pm:6760`) then EXEMPTS these blocks from the `count >
    // 100000` skip. Without the override a crafted GeoKey directory stored as
    // SHORT with `count > 100000` (a `~25k`-key `GeoTiffDirectory`) keeps its
    // on-disk `int16u` format, trips [`walk_entry`](crate::exif)'s generic
    // excessive-count guard, and is `Step::Skip`ped BEFORE that walker's GeoTiff
    // block-capture fast-path runs — so [`crate::exif::geotiff::process`] never
    // sees it and its `MAX_GEOKEY_ELEMENTS` `DirectoryTooLarge` budget isn't
    // reached (a crafted-only faithfulness gap, #429). With the `undef` override
    // the guard is skipped and `walk_entry`'s fast-path captures the raw block
    // ONCE (it returns BEFORE the generic `read_value`/`emit`, so the block is
    // never double-materialized), routing an oversized directory to GeoTiff's OWN
    // budget. The leaf itself stays UNEMITTED either way (these ids are absent
    // from the emittable leaf table), so a well-formed GeoTiff (`count < 500`) is
    // byte-identical — the captured bytes are the same value pointer + on-disk
    // byte length, which are resolved BEFORE this override, unchanged. (The three
    // ids are consecutive — `GeoTiffDirectory` 0x87af, `GeoTiffDoubleParams`
    // 0x87b0, `GeoTiffAsciiParams` 0x87b1 — so the range is exactly that trio.)
    0x87af..=0x87b1 => Some(crate::exif::ifd::Format::Undef),
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
