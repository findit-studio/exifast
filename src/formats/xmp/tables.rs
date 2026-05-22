// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! XMP namespace + tag tables — faithful port of the `%nsURI` / `%stdXlatNS`
//! tables (XMP.pm:82-213) and the per-namespace tag tables (XMP.pm /
//! XMP2.pl).
//!
//! ## Scope (camera-metadata priority)
//!
//! The `%nsURI` namespace table (XMP.pm:109-213) is ported COMPLETELY — it
//! drives the walker's prefix-taming and `tmpN` collision logic.
//!
//! The camera-critical per-namespace TAG tables — `dc`, `xmp`, `xmpRights`,
//! `photoshop`, `tiff`, `exif`, `aux` — are ported with their `Name`
//! remaps, `Writable` kinds, and `PrintConv` maps (inline-hash PrintConvs
//! ported verbatim; the EXIF shared formula converters
//! `PrintExposureTime` / `PrintFNumber` / `PrintFraction` ported in
//! `xmp.rs`). A handful of tags whose PrintConv references an EXIF-module
//! hash that exifast has not yet ported (`%Image::ExifTool::Exif::orientation`,
//! `compression`, `lightSource`, `PrintLensInfo`, …) keep
//! [`PrintConv::Identity`]; their tags still extract with the correct raw
//! value — only the rare PrintConv label is absent (bit-identical to
//! ExifTool for a tag whose `PrintConv` sub is unavailable). See
//! `docs/tracking.md`.
//!
//! Namespaces with no ported table route through `FoundXMP`'s faithful
//! "default tagInfo" path (`IsDefault = 1`) — the 4-surface accept-defer
//! recorded by the `#[ignore]`'d `xmp_unported_namespace_printconv_deferred`
//! test in `xmp.rs`.

/// `Writable` kind of an XMP field (XMP.pm `%xmpTableDefaults` / per-tag
/// `Writable`) — drives lang-alt detection + XMPAutoConv gating.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writable {
  /// No explicit `Writable` type — XMPAutoConv applies.
  None,
  /// `Writable => 'lang-alt'`.
  LangAlt,
  /// `Writable => 'date'`.
  Date,
  /// `Writable => 'integer'`.
  Integer,
  /// `Writable => 'rational'`.
  Rational,
  /// `Writable => 'real'`.
  Real,
  /// `Writable => 'boolean'`.
  Boolean,
  /// `Writable => 'string'` (or any plain-string Writable).
  Str,
}

/// A field's `PrintConv` — the print-mode (`-j`) value transform.
#[derive(Debug, Clone, Copy)]
pub enum PrintConv {
  /// No PrintConv — the print form equals the numeric form.
  Identity,
  /// A `key => label` lookup hash (integer keys). A value with no matching
  /// key prints as `Unknown ($val)` (ExifTool.pm:3622 — the default
  /// hash-miss behavior of a PrintConv hash with no `OTHER` sub).
  IntMap(&'static [(i64, &'static str)]),
  /// A `key => label` lookup hash (integer keys) whose bundled definition
  /// carries an `OTHER => sub` that, for the READ direction, returns the
  /// value UNCHANGED on a miss — so an unmapped value passes through as-is
  /// instead of becoming `Unknown ($val)`. Used by `aux:ApproximateFocusDistance`
  /// (XMP.pm:2634-2638: `OTHER => sub { … return $val eq 4294967295 ?
  /// 'infinity' : $val; }`).
  IntMapPassthrough(&'static [(i64, &'static str)]),
  /// A `key => label` lookup hash (string keys — e.g. GPS ref letters).
  StrMap(&'static [(&'static str, &'static str)]),
  /// `true`/`false` (case-insensitive) → `True`/`False` (`%boolConv`).
  Bool,
  /// `Image::ExifTool::Exif::PrintExposureTime`.
  ExposureTime,
  /// `Image::ExifTool::Exif::PrintFNumber`.
  FNumber,
  /// `Image::ExifTool::Exif::PrintFraction`.
  Fraction,
  /// `sprintf("%.1f", $val)` — one-decimal fixed.
  Fixed1,
  /// `sprintf("%.1f mm", $val)` — focal-length form.
  FocalMm,
  /// `"$val mm"` — append a ` mm` unit.
  Mm,
  /// `$val =~ /^(inf|undef)$/ ? $val : "$val m"` — metres unit.
  Metres,
  /// `"$val m"` — append a ` m` unit unconditionally.
  MetresPlain,
  /// `Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)` — the
  /// `%latConv`/`%longConv` PrintConv (XMP.pm:227/233): render signed decimal
  /// degrees as `D deg M' S.SS" <ref>` (`-j` output). The carried byte is the
  /// positive-hemisphere reference letter (`b'N'` for latitude, `b'E'` for
  /// longitude); a negative value flips it (N→S, E→W) and drops the sign.
  GpsToDms(u8),
  /// `\&Image::ExifTool::Exif::PrintLensInfo` (XMP.pm:2615 — `aux:LensInfo`):
  /// render 4 focal/aperture values (the `ConvertRationalList` output) as
  /// `12-20mm f/3.8-4.5` / `50mm f/1.4` (Exif.pm:5800). A non-4-element
  /// value, or an element that is neither a float nor `inf`/`undef`, is
  /// returned UNCHANGED.
  LensInfo,
}

/// A field's `ValueConv` — the numeric-mode (`-n`) value transform applied
/// BEFORE PrintConv (XMP.pm per-tag `ValueConv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueConv {
  /// No `ValueConv` — only XMPAutoConv (`ConvertRational`/`ConvertXMPDate`).
  None,
  /// `sqrt(2) ** $val` — the APEX aperture-value conversion
  /// (`exif:ApertureValue`, `MaxApertureValue`).
  ApexAperture,
  /// `abs($val) < 100 ? 1/(2**$val) : 0` — the APEX shutter-speed
  /// conversion (`exif:ShutterSpeedValue`).
  ApexShutter,
  /// `Image::ExifTool::GPS::ToDegrees($val, 1)` — the `%latConv`/`%longConv`
  /// ValueConv (XMP.pm:225/231): parse a DMS coordinate string to signed
  /// decimal degrees (`-n` output). Negative for an S/W cardinal suffix.
  GpsToDegrees,
  /// `$val == 0xffffffff ? 0xffff : $val` — the `exif:ColorSpace` ValueConv
  /// (XMP.pm:2003): some applications incorrectly write `-1` as a 32-bit
  /// unsigned long (`0xffffffff` = 4294967295); collapse it to the EXIF
  /// `0xffff` "Uncalibrated" sentinel. The `==` is a Perl NUMERIC compare.
  ColorSpace,
  /// `\&ConvertRationalList` (XMP.pm:2600 — `aux:LensInfo`) — convert a
  /// space-separated string of 4 `N/D` rationals to floating-point values
  /// (`ConvertRationalList`, XMP.pm:3418). A non-4-element string, or any
  /// element not matching `^(-?\d+)/(-?\d+)$`, is returned UNCHANGED.
  RationalList,
}

/// One per-namespace tag-table field (XMP.pm per-tag hash).
#[derive(Debug, Clone, Copy)]
pub struct Field {
  key: &'static str,
  name: Option<&'static str>,
  writable: Writable,
  value_conv: ValueConv,
  print_conv: PrintConv,
}

impl Field {
  /// `Name` remap (the emitted tag name), if different from the key.
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> Option<&'static str> {
    self.name
  }
  /// `Writable` kind.
  #[must_use]
  #[inline(always)]
  pub const fn writable(&self) -> Writable {
    self.writable
  }
  /// `PrintConv` transform.
  #[must_use]
  #[inline(always)]
  pub const fn print_conv(&self) -> PrintConv {
    self.print_conv
  }
  /// `ValueConv` transform.
  #[must_use]
  #[inline(always)]
  pub const fn value_conv(&self) -> ValueConv {
    self.value_conv
  }

  /// Construct (crate-local — the hot in-module table-build path). The
  /// `ValueConv` defaults to [`ValueConv::None`]; use [`Field::make_vc`] for
  /// the rare tags carrying an explicit `ValueConv`.
  pub(super) const fn make(
    key: &'static str,
    name: Option<&'static str>,
    writable: Writable,
    print_conv: PrintConv,
  ) -> Self {
    Self {
      key,
      name,
      writable,
      value_conv: ValueConv::None,
      print_conv,
    }
  }

  /// Construct with an explicit `ValueConv` (the APEX aperture/shutter tags).
  pub(super) const fn make_vc(
    key: &'static str,
    name: Option<&'static str>,
    writable: Writable,
    value_conv: ValueConv,
    print_conv: PrintConv,
  ) -> Self {
    Self {
      key,
      name,
      writable,
      value_conv,
      print_conv,
    }
  }
}

/// A per-namespace tag table.
#[derive(Debug, Clone, Copy)]
pub struct NsTable {
  fields: &'static [Field],
}

impl NsTable {
  /// The fields of this table.
  #[must_use]
  #[inline(always)]
  #[allow(dead_code)] // public table-introspection accessor (D8)
  pub const fn fields(&self) -> &'static [Field] {
    self.fields
  }
}

/// Look a field up in a namespace table by its XMP property key.
#[must_use]
pub fn lookup_field<'t>(table: &'t NsTable, key: &str) -> Option<&'t Field> {
  table.fields.iter().find(|f| f.key == key)
}

// ===========================================================================
// %nsURI — the complete namespace-prefix → URI table (XMP.pm:109-213)
// ===========================================================================

/// `(prefix, URI)` rows of the bundled `%nsURI` hash (XMP.pm:109-213) +
/// XMP2.pl additions. Ported COMPLETELY.
static NS_URI: &[(&str, &str)] = &[
  ("aux", "http://ns.adobe.com/exif/1.0/aux/"),
  ("album", "http://ns.adobe.com/album/1.0/"),
  ("cc", "http://creativecommons.org/ns#"),
  ("crd", "http://ns.adobe.com/camera-raw-defaults/1.0/"),
  ("crs", "http://ns.adobe.com/camera-raw-settings/1.0/"),
  ("crss", "http://ns.adobe.com/camera-raw-saved-settings/1.0/"),
  ("dc", "http://purl.org/dc/elements/1.1/"),
  ("exif", "http://ns.adobe.com/exif/1.0/"),
  ("exifEX", "http://cipa.jp/exif/1.0/"),
  ("iX", "http://ns.adobe.com/iX/1.0/"),
  ("pdf", "http://ns.adobe.com/pdf/1.3/"),
  ("pdfx", "http://ns.adobe.com/pdfx/1.3/"),
  ("photoshop", "http://ns.adobe.com/photoshop/1.0/"),
  ("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
  ("rdfs", "http://www.w3.org/2000/01/rdf-schema#"),
  ("stDim", "http://ns.adobe.com/xap/1.0/sType/Dimensions#"),
  ("stEvt", "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"),
  ("stFnt", "http://ns.adobe.com/xap/1.0/sType/Font#"),
  ("stJob", "http://ns.adobe.com/xap/1.0/sType/Job#"),
  ("stRef", "http://ns.adobe.com/xap/1.0/sType/ResourceRef#"),
  ("stVer", "http://ns.adobe.com/xap/1.0/sType/Version#"),
  ("stMfs", "http://ns.adobe.com/xap/1.0/sType/ManifestItem#"),
  (
    "stCamera",
    "http://ns.adobe.com/photoshop/1.0/camera-profile",
  ),
  (
    "crlcp",
    "http://ns.adobe.com/camera-raw-embedded-lens-profile/1.0/",
  ),
  ("tiff", "http://ns.adobe.com/tiff/1.0/"),
  ("x", "adobe:ns:meta/"),
  ("xmpG", "http://ns.adobe.com/xap/1.0/g/"),
  ("xmpGImg", "http://ns.adobe.com/xap/1.0/g/img/"),
  ("xmp", "http://ns.adobe.com/xap/1.0/"),
  ("xmpBJ", "http://ns.adobe.com/xap/1.0/bj/"),
  ("xmpDM", "http://ns.adobe.com/xmp/1.0/DynamicMedia/"),
  ("xmpMM", "http://ns.adobe.com/xap/1.0/mm/"),
  ("xmpRights", "http://ns.adobe.com/xap/1.0/rights/"),
  ("xmpNote", "http://ns.adobe.com/xmp/note/"),
  ("xmpTPg", "http://ns.adobe.com/xap/1.0/t/pg/"),
  ("xmpidq", "http://ns.adobe.com/xmp/Identifier/qual/1.0/"),
  ("xmpPLUS", "http://ns.adobe.com/xap/1.0/PLUS/"),
  (
    "panorama",
    "http://ns.adobe.com/photoshop/1.0/panorama-profile",
  ),
  ("dex", "http://ns.optimasc.com/dex/1.0/"),
  ("mediapro", "http://ns.iview-multimedia.com/mediapro/1.0/"),
  (
    "expressionmedia",
    "http://ns.microsoft.com/expressionmedia/1.0/",
  ),
  (
    "Iptc4xmpCore",
    "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/",
  ),
  ("Iptc4xmpExt", "http://iptc.org/std/Iptc4xmpExt/2008-02-29/"),
  ("MicrosoftPhoto", "http://ns.microsoft.com/photo/1.0"),
  ("MP1", "http://ns.microsoft.com/photo/1.1"),
  ("MP", "http://ns.microsoft.com/photo/1.2/"),
  ("MPRI", "http://ns.microsoft.com/photo/1.2/t/RegionInfo#"),
  ("MPReg", "http://ns.microsoft.com/photo/1.2/t/Region#"),
  ("lr", "http://ns.adobe.com/lightroom/1.0/"),
  ("DICOM", "http://ns.adobe.com/DICOM/"),
  ("drone-dji", "http://www.dji.com/drone-dji/1.0/"),
  ("svg", "http://www.w3.org/2000/svg"),
  ("et", "http://ns.exiftool.org/1.0/"),
  ("plus", "http://ns.useplus.org/ldf/xmp/1.0/"),
  ("prism", "http://prismstandard.org/namespaces/basic/2.0/"),
  ("prl", "http://prismstandard.org/namespaces/prl/2.1/"),
  (
    "pur",
    "http://prismstandard.org/namespaces/prismusagerights/2.1/",
  ),
  ("pmi", "http://prismstandard.org/namespaces/pmi/2.2/"),
  ("prm", "http://prismstandard.org/namespaces/prm/3.0/"),
  ("acdsee", "http://ns.acdsee.com/iptc/1.0/"),
  ("acdsee-rs", "http://ns.acdsee.com/regions/"),
  ("digiKam", "http://www.digikam.org/ns/1.0/"),
  ("swf", "http://ns.adobe.com/swf/1.0/"),
  ("cell", "http://developer.sonyericsson.com/cell/1.0/"),
  ("aas", "http://ns.apple.com/adjustment-settings/1.0/"),
  (
    "mwg-rs",
    "http://www.metadataworkinggroup.com/schemas/regions/",
  ),
  (
    "mwg-kw",
    "http://www.metadataworkinggroup.com/schemas/keywords/",
  ),
  (
    "mwg-coll",
    "http://www.metadataworkinggroup.com/schemas/collections/",
  ),
  ("stArea", "http://ns.adobe.com/xmp/sType/Area#"),
  ("extensis", "http://ns.extensis.com/extensis/1.0/"),
  ("ics", "http://ns.idimager.com/ics/1.0/"),
  ("fpv", "http://ns.fastpictureviewer.com/fpv/1.0/"),
  ("creatorAtom", "http://ns.adobe.com/creatorAtom/1.0/"),
  ("apple-fi", "http://ns.apple.com/faceinfo/1.0/"),
  ("GAudio", "http://ns.google.com/photos/1.0/audio/"),
  ("GImage", "http://ns.google.com/photos/1.0/image/"),
  ("GPano", "http://ns.google.com/photos/1.0/panorama/"),
  ("GSpherical", "http://ns.google.com/videos/1.0/spherical/"),
  ("GDepth", "http://ns.google.com/photos/1.0/depthmap/"),
  ("GFocus", "http://ns.google.com/photos/1.0/focus/"),
  ("GCamera", "http://ns.google.com/photos/1.0/camera/"),
  ("GCreations", "http://ns.google.com/photos/1.0/creations/"),
  ("dwc", "http://rs.tdwg.org/dwc/index.htm"),
  ("GettyImagesGIFT", "http://xmp.gettyimages.com/gift/1.0/"),
  ("LImage", "http://ns.leiainc.com/photos/1.0/image/"),
  ("Profile", "http://ns.google.com/photos/dd/1.0/profile/"),
  ("sdc", "http://ns.nikon.com/sdc/1.0/"),
  ("ast", "http://ns.nikon.com/asteroid/1.0/"),
  ("nine", "http://ns.nikon.com/nine/1.0/"),
  ("hdr_metadata", "http://ns.adobe.com/hdr-metadata/1.0/"),
  ("hdrgm", "http://ns.adobe.com/hdr-gain-map/1.0/"),
  (
    "xmpDSA",
    "http://leica-camera.com/digital-shift-assistant/1.0/",
  ),
  ("seal", "http://ns.seal/2024/1.0/"),
  ("GContainer", "http://ns.google.com/photos/1.0/container/"),
  ("HDRGainMap", "http://ns.apple.com/HDRGainMap/1.0/"),
  ("apdi", "http://ns.apple.com/pixeldatainfo/1.0/"),
];

/// `%stdXlatNS` (XMP.pm:82-91) — the "shorten ugly namespace prefix" map.
static STD_XLAT_NS: &[(&str, &str)] = &[
  ("Iptc4xmpCore", "iptcCore"),
  ("Iptc4xmpExt", "iptcExt"),
  ("photomechanic", "photomech"),
  ("MicrosoftPhoto", "microsoft"),
  ("prismusagerights", "pur"),
  ("GettyImagesGIFT", "getty"),
  ("hdr_metadata", "hdr"),
];

/// The URI registered for a known namespace prefix (`%nsURI{$ns}`).
#[must_use]
pub fn ns_uri(ns: &str) -> Option<&'static str> {
  NS_URI.iter().find_map(|&(p, u)| (p == ns).then_some(u))
}

/// All `(URI, prefix)` rows — used by the version-insensitive URI match.
pub fn all_ns_uris() -> impl Iterator<Item = (&'static str, &'static str)> {
  NS_URI.iter().map(|&(p, u)| (u, p))
}

/// Reverse lookup: URI → standard ExifTool prefix (the FIRST prefix
/// registered for a URI wins, matching `%uri2ns`, XMP.pm:215-219).
#[must_use]
pub fn uri_to_ns(uri: &str) -> Option<&'static str> {
  NS_URI.iter().find_map(|&(p, u)| (u == uri).then_some(p))
}

/// `%stdXlatNS` translation — shorten an ugly namespace prefix (XMP.pm:3444).
#[must_use]
pub fn std_xlat_ns(ns: &str) -> Option<&'static str> {
  STD_XLAT_NS
    .iter()
    .find_map(|&(k, v)| (k == ns).then_some(v))
}

/// The standard XMP prefix for a (possibly already-shortened) namespace —
/// the reverse of `%stdXlatNS` (`%xmpNS`, XMP.pm:94).
#[must_use]
#[allow(dead_code)]
pub fn xmp_ns(ns: &str) -> &str {
  STD_XLAT_NS
    .iter()
    .find_map(|&(k, v)| (v == ns).then_some(k))
    .unwrap_or(ns)
}

// ===========================================================================
// Per-namespace tag tables
// ===========================================================================

use PrintConv as P;
use Writable as W;

/// `%Image::ExifTool::XMP::dc` (XMP.pm:1017) — Dublin Core.
static DC: &[Field] = &[
  Field::make("contributor", None, W::Str, P::Identity),
  Field::make("coverage", None, W::Str, P::Identity),
  Field::make("creator", None, W::Str, P::Identity),
  Field::make("date", None, W::Date, P::Identity),
  Field::make("description", None, W::LangAlt, P::Identity),
  Field::make("format", None, W::Str, P::Identity),
  Field::make("identifier", None, W::Str, P::Identity),
  Field::make("language", None, W::Str, P::Identity),
  Field::make("publisher", None, W::Str, P::Identity),
  Field::make("relation", None, W::Str, P::Identity),
  Field::make("rights", None, W::LangAlt, P::Identity),
  Field::make("source", None, W::Str, P::Identity),
  Field::make("subject", None, W::Str, P::Identity),
  Field::make("title", None, W::LangAlt, P::Identity),
  Field::make("type", None, W::Str, P::Identity),
];

/// `%Image::ExifTool::XMP::xmp` (XMP.pm:1041) — the core XMP namespace.
static XMP: &[Field] = &[
  Field::make("Advisory", None, W::Str, P::Identity),
  Field::make("BaseURL", None, W::Str, P::Identity),
  Field::make("CreateDate", None, W::Date, P::Identity),
  Field::make("CreatorTool", None, W::Str, P::Identity),
  Field::make("Identifier", None, W::Str, P::Identity),
  Field::make("Label", None, W::Str, P::Identity),
  Field::make("MetadataDate", None, W::Date, P::Identity),
  Field::make("ModifyDate", None, W::Date, P::Identity),
  Field::make("Nickname", None, W::Str, P::Identity),
  Field::make("Rating", None, W::Real, P::Identity),
  Field::make("RatingPercent", None, W::Real, P::Identity),
  Field::make("PageInfoImage", Some("PageImage"), W::Str, P::Identity),
  Field::make("Title", None, W::LangAlt, P::Identity),
  Field::make("Author", None, W::Str, P::Identity),
  Field::make("Keywords", None, W::Str, P::Identity),
  Field::make("Description", None, W::LangAlt, P::Identity),
  Field::make("Format", None, W::Str, P::Identity),
];

/// `%Image::ExifTool::XMP::xmpRights` — XMP Rights Management.
static XMP_RIGHTS: &[Field] = &[
  Field::make("Certificate", None, W::Str, P::Identity),
  Field::make("Marked", None, W::Boolean, P::Bool),
  Field::make("Owner", None, W::Str, P::Identity),
  Field::make("UsageTerms", None, W::LangAlt, P::Identity),
  Field::make("WebStatement", None, W::Str, P::Identity),
];

/// Photoshop `ColorMode` PrintConv (XMP.pm `photoshop` table).
static PS_COLOR_MODE: &[(i64, &str)] = &[
  (0, "Bitmap"),
  (1, "Grayscale"),
  (2, "Indexed"),
  (3, "RGB"),
  (4, "CMYK"),
  (7, "Multichannel"),
  (8, "Duotone"),
  (9, "Lab"),
];
/// Photoshop `Urgency` PrintConv.
static PS_URGENCY: &[(i64, &str)] = &[
  (0, "0 (reserved)"),
  (1, "1 (most urgent)"),
  (2, "2"),
  (3, "3"),
  (4, "4"),
  (5, "5 (normal urgency)"),
  (6, "6"),
  (7, "7"),
  (8, "8 (least urgent)"),
  (9, "9 (user-defined priority)"),
];

/// `%Image::ExifTool::XMP::photoshop` — Adobe Photoshop namespace.
static PHOTOSHOP: &[Field] = &[
  Field::make("AuthorsPosition", None, W::Str, P::Identity),
  Field::make("CaptionWriter", None, W::Str, P::Identity),
  Field::make("Category", None, W::Str, P::Identity),
  Field::make("City", None, W::Str, P::Identity),
  Field::make("ColorMode", None, W::Integer, P::IntMap(PS_COLOR_MODE)),
  Field::make("Country", None, W::Str, P::Identity),
  Field::make("Credit", None, W::Str, P::Identity),
  Field::make("DateCreated", None, W::Date, P::Identity),
  Field::make("Headline", None, W::Str, P::Identity),
  Field::make("History", None, W::Str, P::Identity),
  Field::make("ICCProfile", Some("ICCProfileName"), W::Str, P::Identity),
  Field::make("Instructions", None, W::Str, P::Identity),
  Field::make("LegacyIPTCDigest", None, W::Str, P::Identity),
  Field::make("SidecarForExtension", None, W::Str, P::Identity),
  Field::make("Source", None, W::Str, P::Identity),
  Field::make("State", None, W::Str, P::Identity),
  Field::make("SupplementalCategories", None, W::Str, P::Identity),
  Field::make("TransmissionReference", None, W::Str, P::Identity),
  Field::make("Urgency", None, W::Integer, P::IntMap(PS_URGENCY)),
  Field::make("EmbeddedXMPDigest", None, W::Str, P::Identity),
];

/// `%Image::ExifTool::XMP::tiff` (XMP.pm:1896) — XMP TIFF namespace.
/// PrintConvs that reference an unported EXIF-module hash
/// (`Compression`, `PhotometricInterpretation`, `Orientation`,
/// `YCbCrSubSampling`) keep `Identity` — see the module docs.
/// `%Image::ExifTool::Exif::orientation` (Exif.pm) — ported inline (it is a
/// plain lookup hash, not a converter sub).
static TIFF_ORIENTATION: &[(i64, &str)] = &[
  (1, "Horizontal (normal)"),
  (2, "Mirror horizontal"),
  (3, "Rotate 180"),
  (4, "Mirror vertical"),
  (5, "Mirror horizontal and rotate 270 CW"),
  (6, "Rotate 90 CW"),
  (7, "Mirror horizontal and rotate 90 CW"),
  (8, "Rotate 270 CW"),
];
static TIFF_PLANAR: &[(i64, &str)] = &[(1, "Chunky"), (2, "Planar")];
static TIFF_YCBCR_POS: &[(i64, &str)] = &[(1, "Centered"), (2, "Co-sited")];
static TIFF_RES_UNIT: &[(i64, &str)] = &[(1, "None"), (2, "inches"), (3, "cm")];
static TIFF: &[Field] = &[
  Field::make("ImageWidth", None, W::Integer, P::Identity),
  Field::make("ImageLength", Some("ImageHeight"), W::Integer, P::Identity),
  Field::make("BitsPerSample", None, W::Integer, P::Identity),
  Field::make("Compression", None, W::Integer, P::Identity),
  Field::make("PhotometricInterpretation", None, W::Integer, P::Identity),
  Field::make("Orientation", None, W::Integer, P::IntMap(TIFF_ORIENTATION)),
  Field::make("SamplesPerPixel", None, W::Integer, P::Identity),
  Field::make(
    "PlanarConfiguration",
    None,
    W::Integer,
    P::IntMap(TIFF_PLANAR),
  ),
  Field::make("YCbCrSubSampling", None, W::Integer, P::Identity),
  Field::make(
    "YCbCrPositioning",
    None,
    W::Integer,
    P::IntMap(TIFF_YCBCR_POS),
  ),
  Field::make("XResolution", None, W::Rational, P::Identity),
  Field::make("YResolution", None, W::Rational, P::Identity),
  Field::make("ResolutionUnit", None, W::Integer, P::IntMap(TIFF_RES_UNIT)),
  Field::make("TransferFunction", None, W::Integer, P::Identity),
  Field::make("WhitePoint", None, W::Rational, P::Identity),
  Field::make("PrimaryChromaticities", None, W::Rational, P::Identity),
  Field::make("YCbCrCoefficients", None, W::Rational, P::Identity),
  Field::make("ReferenceBlackWhite", None, W::Rational, P::Identity),
  Field::make("DateTime", Some("ModifyDate"), W::Date, P::Identity),
  Field::make("ImageDescription", None, W::LangAlt, P::Identity),
  Field::make("Make", None, W::Str, P::Identity),
  // (`Description => 'Camera Model Name'` is a description, NOT a Name
  // remap — the emitted tag stays `Model`.)
  Field::make("Model", None, W::Str, P::Identity),
  Field::make("Software", None, W::Str, P::Identity),
  Field::make("Artist", None, W::Str, P::Identity),
  Field::make("Copyright", None, W::LangAlt, P::Identity),
  Field::make("NativeDigest", None, W::Str, P::Identity),
];

/// `%Image::ExifTool::XMP::aux` — EXIF auxiliary (camera/lens) namespace.
/// `ApproximateFocusDistance` PrintConv hash (XMP.pm:2630-2640) — its bundled
/// definition pairs the `4294967295 => 'infinity'` row (XMP.pm:2633) with an
/// `OTHER => sub` (XMP.pm:2634-2638) that returns the value unchanged on a
/// read-direction miss (hence [`PrintConv::IntMapPassthrough`], not
/// [`PrintConv::IntMap`]).
static AUX_FOCUS_DIST: &[(i64, &str)] = &[(4_294_967_295, "infinity")];
static AUX: &[Field] = &[
  Field::make("Firmware", None, W::Str, P::Identity),
  Field::make("FlashCompensation", None, W::Rational, P::Identity),
  Field::make("ImageNumber", None, W::Str, P::Identity),
  // `aux:LensInfo` (XMP.pm:2596): `ValueConv => \&ConvertRationalList`
  // (XMP.pm:2600) + `PrintConv => \&Image::ExifTool::Exif::PrintLensInfo`
  // (XMP.pm:2615). The bundled tag has NO explicit `Writable`, so the
  // `%xmpTableDefaults` plain-string default applies (the ValueConv operates
  // on the raw whitespace-joined string — there is no XMPAutoConv
  // `ConvertRational` step for a non-`rational` Writable).
  Field::make_vc(
    "LensInfo",
    None,
    W::Str,
    ValueConv::RationalList,
    P::LensInfo,
  ),
  Field::make("Lens", None, W::Str, P::Identity),
  Field::make("OwnerName", None, W::Str, P::Identity),
  Field::make("SerialNumber", None, W::Str, P::Identity),
  Field::make("LensSerialNumber", None, W::Str, P::Identity),
  Field::make("LensID", None, W::Str, P::Identity),
  Field::make(
    "ApproximateFocusDistance",
    None,
    W::Rational,
    P::IntMapPassthrough(AUX_FOCUS_DIST),
  ),
  Field::make("IsMergedPanorama", None, W::Boolean, P::Bool),
  Field::make("IsMergedHDR", None, W::Boolean, P::Bool),
  Field::make("LensDistortInfo", None, W::Str, P::Identity),
];

/// `%Image::ExifTool::XMP::exif` (XMP.pm) — XMP EXIF namespace.
static EXIF_COLOR_SPACE: &[(i64, &str)] =
  &[(1, "sRGB"), (2, "Adobe RGB"), (0xffff, "Uncalibrated")];
static EXIF_COMPONENTS: &[(i64, &str)] = &[
  (0, "-"),
  (1, "Y"),
  (2, "Cb"),
  (3, "Cr"),
  (4, "R"),
  (5, "G"),
  (6, "B"),
];
static EXIF_EXPOSURE_PROGRAM: &[(i64, &str)] = &[
  (0, "Not Defined"),
  (1, "Manual"),
  (2, "Program AE"),
  (3, "Aperture-priority AE"),
  (4, "Shutter speed priority AE"),
  (5, "Creative (Slow speed)"),
  (6, "Action (High speed)"),
  (7, "Portrait"),
  (8, "Landscape"),
];
static EXIF_METERING: &[(i64, &str)] = &[
  (1, "Average"),
  (2, "Center-weighted average"),
  (3, "Spot"),
  (4, "Multi-spot"),
  (5, "Multi-segment"),
  (6, "Partial"),
  (255, "Other"),
];
static EXIF_FOCAL_PLANE_UNIT: &[(i64, &str)] =
  &[(1, "None"), (2, "inches"), (3, "cm"), (4, "mm"), (5, "um")];
static EXIF_SENSING: &[(i64, &str)] = &[
  (1, "Monochrome area"),
  (2, "One-chip color area"),
  (3, "Two-chip color area"),
  (4, "Three-chip color area"),
  (5, "Color sequential area"),
  (6, "Monochrome linear"),
  (7, "Trilinear"),
  (8, "Color sequential linear"),
];
static EXIF_FILE_SOURCE: &[(i64, &str)] = &[
  (1, "Film Scanner"),
  (2, "Reflection Print Scanner"),
  (3, "Digital Camera"),
];
static EXIF_SCENE_TYPE: &[(i64, &str)] = &[(1, "Directly photographed")];
static EXIF_CUSTOM_RENDERED: &[(i64, &str)] = &[(0, "Normal"), (1, "Custom")];
static EXIF_EXPOSURE_MODE: &[(i64, &str)] = &[(0, "Auto"), (1, "Manual"), (2, "Auto bracket")];
static EXIF_WHITE_BALANCE: &[(i64, &str)] = &[(0, "Auto"), (1, "Manual")];
static EXIF_SCENE_CAPTURE: &[(i64, &str)] = &[
  (0, "Standard"),
  (1, "Landscape"),
  (2, "Portrait"),
  (3, "Night"),
];
static EXIF_GAIN_CONTROL: &[(i64, &str)] = &[
  (0, "None"),
  (1, "Low gain up"),
  (2, "High gain up"),
  (3, "Low gain down"),
  (4, "High gain down"),
];
static EXIF_CONTRAST: &[(i64, &str)] = &[(0, "Normal"), (1, "Low"), (2, "High")];
static EXIF_SHARPNESS: &[(i64, &str)] = &[(0, "Normal"), (1, "Soft"), (2, "Hard")];
static EXIF_SUBJECT_DIST_RANGE: &[(i64, &str)] =
  &[(0, "Unknown"), (1, "Macro"), (2, "Close"), (3, "Distant")];
static EXIF_GPS_ALTITUDE_REF: &[(i64, &str)] = &[(0, "Above Sea Level"), (1, "Below Sea Level")];
static EXIF_GPS_STATUS: &[(&str, &str)] = &[("A", "Measurement Active"), ("V", "Measurement Void")];
static EXIF_GPS_MEASURE_MODE: &[(i64, &str)] = &[
  (2, "2-Dimensional Measurement"),
  (3, "3-Dimensional Measurement"),
];
static EXIF_GPS_SPEED_REF: &[(&str, &str)] = &[("K", "km/h"), ("M", "mph"), ("N", "knots")];
static EXIF_GPS_DIRECTION_REF: &[(&str, &str)] = &[("M", "Magnetic North"), ("T", "True North")];
static EXIF_GPS_DEST_DIST_REF: &[(&str, &str)] =
  &[("K", "Kilometers"), ("M", "Miles"), ("N", "Nautical Miles")];
static EXIF_GPS_DIFFERENTIAL: &[(i64, &str)] =
  &[(0, "No Correction"), (1, "Differential Corrected")];
static EXIF: &[Field] = &[
  Field::make("ExifVersion", None, W::Str, P::Identity),
  Field::make("FlashpixVersion", None, W::Str, P::Identity),
  // `exif:ColorSpace` (XMP.pm:2000): `Writable => 'integer'` +
  // `ValueConv => '$val == 0xffffffff ? 0xffff : $val'` (XMP.pm:2003 — some
  // applications incorrectly write `-1` as a 32-bit unsigned long). The
  // ValueConv runs BEFORE the PrintConv hash, so a written `4294967295`
  // collapses to `65535` and then maps to `Uncalibrated`.
  Field::make_vc(
    "ColorSpace",
    None,
    W::Integer,
    ValueConv::ColorSpace,
    P::IntMap(EXIF_COLOR_SPACE),
  ),
  Field::make(
    "ComponentsConfiguration",
    None,
    W::Integer,
    P::IntMap(EXIF_COMPONENTS),
  ),
  Field::make("CompressedBitsPerPixel", None, W::Rational, P::Identity),
  Field::make(
    "PixelXDimension",
    Some("ExifImageWidth"),
    W::Integer,
    P::Identity,
  ),
  Field::make(
    "PixelYDimension",
    Some("ExifImageHeight"),
    W::Integer,
    P::Identity,
  ),
  Field::make("MakerNote", None, W::Str, P::Identity),
  Field::make("UserComment", None, W::LangAlt, P::Identity),
  Field::make("RelatedSoundFile", None, W::Str, P::Identity),
  Field::make("DateTimeOriginal", None, W::Date, P::Identity),
  Field::make("DateTimeDigitized", None, W::Date, P::Identity),
  Field::make("ExposureTime", None, W::Rational, P::ExposureTime),
  Field::make("FNumber", None, W::Rational, P::FNumber),
  Field::make(
    "ExposureProgram",
    None,
    W::Integer,
    P::IntMap(EXIF_EXPOSURE_PROGRAM),
  ),
  Field::make("SpectralSensitivity", None, W::Str, P::Identity),
  Field::make("ISOSpeedRatings", Some("ISO"), W::Integer, P::Identity),
  Field::make("OECF", Some("Opto-ElectricConvFactor"), W::Str, P::Identity),
  Field::make_vc(
    "ShutterSpeedValue",
    None,
    W::Rational,
    ValueConv::ApexShutter,
    P::ExposureTime,
  ),
  Field::make_vc(
    "ApertureValue",
    None,
    W::Rational,
    ValueConv::ApexAperture,
    P::Fixed1,
  ),
  Field::make("BrightnessValue", None, W::Rational, P::Identity),
  Field::make(
    "ExposureBiasValue",
    Some("ExposureCompensation"),
    W::Rational,
    P::Fraction,
  ),
  Field::make_vc(
    "MaxApertureValue",
    None,
    W::Rational,
    ValueConv::ApexAperture,
    P::Fixed1,
  ),
  Field::make("SubjectDistance", None, W::Rational, P::Metres),
  Field::make("MeteringMode", None, W::Integer, P::IntMap(EXIF_METERING)),
  Field::make("LightSource", None, W::Integer, P::Identity),
  Field::make("Flash", None, W::Str, P::Identity),
  Field::make("FocalLength", None, W::Rational, P::FocalMm),
  Field::make("SubjectArea", None, W::Integer, P::Identity),
  Field::make("FlashEnergy", None, W::Rational, P::Identity),
  Field::make("SpatialFrequencyResponse", None, W::Str, P::Identity),
  Field::make("FocalPlaneXResolution", None, W::Rational, P::Identity),
  Field::make("FocalPlaneYResolution", None, W::Rational, P::Identity),
  Field::make(
    "FocalPlaneResolutionUnit",
    None,
    W::Integer,
    P::IntMap(EXIF_FOCAL_PLANE_UNIT),
  ),
  Field::make("SubjectLocation", None, W::Integer, P::Identity),
  Field::make("ExposureIndex", None, W::Rational, P::Identity),
  Field::make("SensingMethod", None, W::Integer, P::IntMap(EXIF_SENSING)),
  Field::make("FileSource", None, W::Integer, P::IntMap(EXIF_FILE_SOURCE)),
  Field::make("SceneType", None, W::Integer, P::IntMap(EXIF_SCENE_TYPE)),
  Field::make("CFAPattern", None, W::Str, P::Identity),
  Field::make(
    "CustomRendered",
    None,
    W::Integer,
    P::IntMap(EXIF_CUSTOM_RENDERED),
  ),
  Field::make(
    "ExposureMode",
    None,
    W::Integer,
    P::IntMap(EXIF_EXPOSURE_MODE),
  ),
  Field::make(
    "WhiteBalance",
    None,
    W::Integer,
    P::IntMap(EXIF_WHITE_BALANCE),
  ),
  Field::make("DigitalZoomRatio", None, W::Rational, P::Identity),
  Field::make(
    "FocalLengthIn35mmFilm",
    Some("FocalLengthIn35mmFormat"),
    W::Integer,
    P::Mm,
  ),
  Field::make(
    "SceneCaptureType",
    None,
    W::Integer,
    P::IntMap(EXIF_SCENE_CAPTURE),
  ),
  Field::make(
    "GainControl",
    None,
    W::Integer,
    P::IntMap(EXIF_GAIN_CONTROL),
  ),
  Field::make("Contrast", None, W::Integer, P::IntMap(EXIF_CONTRAST)),
  Field::make("Saturation", None, W::Integer, P::IntMap(EXIF_CONTRAST)),
  Field::make("Sharpness", None, W::Integer, P::IntMap(EXIF_SHARPNESS)),
  Field::make("DeviceSettingDescription", None, W::Str, P::Identity),
  Field::make(
    "SubjectDistanceRange",
    None,
    W::Integer,
    P::IntMap(EXIF_SUBJECT_DIST_RANGE),
  ),
  Field::make("ImageUniqueID", None, W::Str, P::Identity),
  Field::make("GPSVersionID", None, W::Str, P::Identity),
  // `%latConv` / `%longConv` (XMP.pm:224-234): ToDegrees ValueConv (signed
  // decimal degrees, `-n`) + ToDMS PrintConv (`D deg M' S.SS" <ref>`, `-j`).
  Field::make_vc(
    "GPSLatitude",
    None,
    W::Str,
    ValueConv::GpsToDegrees,
    P::GpsToDms(b'N'),
  ),
  Field::make_vc(
    "GPSLongitude",
    None,
    W::Str,
    ValueConv::GpsToDegrees,
    P::GpsToDms(b'E'),
  ),
  Field::make(
    "GPSAltitudeRef",
    None,
    W::Integer,
    P::IntMap(EXIF_GPS_ALTITUDE_REF),
  ),
  Field::make("GPSAltitude", None, W::Rational, P::Metres),
  Field::make("GPSTimeStamp", Some("GPSDateTime"), W::Date, P::Identity),
  Field::make("GPSSatellites", None, W::Str, P::Identity),
  Field::make("GPSStatus", None, W::Str, P::StrMap(EXIF_GPS_STATUS)),
  Field::make(
    "GPSMeasureMode",
    None,
    W::Integer,
    P::IntMap(EXIF_GPS_MEASURE_MODE),
  ),
  Field::make("GPSDOP", None, W::Rational, P::Identity),
  Field::make("GPSSpeedRef", None, W::Str, P::StrMap(EXIF_GPS_SPEED_REF)),
  Field::make("GPSSpeed", None, W::Rational, P::Identity),
  Field::make(
    "GPSTrackRef",
    None,
    W::Str,
    P::StrMap(EXIF_GPS_DIRECTION_REF),
  ),
  Field::make("GPSTrack", None, W::Rational, P::Identity),
  Field::make(
    "GPSImgDirectionRef",
    None,
    W::Str,
    P::StrMap(EXIF_GPS_DIRECTION_REF),
  ),
  Field::make("GPSImgDirection", None, W::Rational, P::Identity),
  Field::make("GPSMapDatum", None, W::Str, P::Identity),
  Field::make_vc(
    "GPSDestLatitude",
    None,
    W::Str,
    ValueConv::GpsToDegrees,
    P::GpsToDms(b'N'),
  ),
  Field::make_vc(
    "GPSDestLongitude",
    None,
    W::Str,
    ValueConv::GpsToDegrees,
    P::GpsToDms(b'E'),
  ),
  Field::make(
    "GPSDestBearingRef",
    None,
    W::Str,
    P::StrMap(EXIF_GPS_DIRECTION_REF),
  ),
  Field::make("GPSDestBearing", None, W::Rational, P::Identity),
  Field::make(
    "GPSDestDistanceRef",
    None,
    W::Str,
    P::StrMap(EXIF_GPS_DEST_DIST_REF),
  ),
  Field::make("GPSDestDistance", None, W::Rational, P::Identity),
  Field::make("GPSProcessingMethod", None, W::Str, P::Identity),
  Field::make("GPSAreaInformation", None, W::Str, P::Identity),
  Field::make(
    "GPSDifferential",
    None,
    W::Integer,
    P::IntMap(EXIF_GPS_DIFFERENTIAL),
  ),
  Field::make(
    "GPSHPositioningError",
    Some("GPSHPositioningError"),
    W::Rational,
    P::MetresPlain,
  ),
  Field::make("NativeDigest", None, W::Str, P::Identity),
];

static NS_TABLES: &[(&str, NsTable)] = &[
  ("dc", NsTable { fields: DC }),
  ("xmp", NsTable { fields: XMP }),
  ("xmpRights", NsTable { fields: XMP_RIGHTS }),
  ("photoshop", NsTable { fields: PHOTOSHOP }),
  ("tiff", NsTable { fields: TIFF }),
  ("aux", NsTable { fields: AUX }),
  ("exif", NsTable { fields: EXIF }),
];

/// Resolve a (already `%stdXlatNS`-translated) namespace to its ported tag
/// table, or `None` if the namespace has no ported table (its tags route
/// through `FoundXMP`'s faithful default-tagInfo path).
#[must_use]
pub fn lookup_ns_table(ns: &str) -> Option<&'static NsTable> {
  NS_TABLES.iter().find_map(|(n, t)| (*n == ns).then_some(t))
}

// ---------------------------------------------------------------------------
// Struct sub-field tables (`Struct => { … }` of a parent tag)
// ---------------------------------------------------------------------------

/// `Struct => { STRUCT_NAME => 'Flash', … }` of `exif:Flash` (XMP.pm). The
/// boolean fields carry `%boolConv`; `Mode` / `Return` carry inline hashes.
static FLASH_RETURN: &[(i64, &str)] = &[
  (0, "No return detection"),
  (2, "Return not detected"),
  (3, "Return detected"),
];
static FLASH_MODE: &[(i64, &str)] = &[(0, "Unknown"), (1, "On"), (2, "Off"), (3, "Auto")];
static EXIF_FLASH_STRUCT: &[Field] = &[
  Field::make("Fired", None, W::Boolean, P::Bool),
  Field::make("Return", None, W::Integer, P::IntMap(FLASH_RETURN)),
  Field::make("Mode", None, W::Integer, P::IntMap(FLASH_MODE)),
  Field::make("Function", None, W::Boolean, P::Bool),
  Field::make("RedEyeMode", None, W::Boolean, P::Bool),
];

/// `(namespace, parent-struct-field, sub-table)` registry. Looked up by
/// [`lookup_struct_field`] when a nested-struct field misses the top-level
/// namespace table. Camera-critical struct: `exif:Flash`.
static STRUCT_TABLES: &[(&str, &str, &[Field])] = &[("exif", "Flash", EXIF_FLASH_STRUCT)];

/// Resolve a nested-struct sub-field — `(ns, parent_struct, child_key)` →
/// the child [`Field`]. Faithful to ExifTool's `Struct => { … }` flattened
/// sub-tag lookup (XMP.pm). Returns `None` when the parent struct has no
/// ported sub-table.
#[must_use]
pub fn lookup_struct_field(ns: &str, parent: &str, child: &str) -> Option<&'static Field> {
  STRUCT_TABLES
    .iter()
    .find(|(n, p, _)| *n == ns && *p == parent)
    .and_then(|(_, _, fields)| fields.iter().find(|f| f.key == child))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ns_uri_round_trips() {
    assert_eq!(ns_uri("exif"), Some("http://ns.adobe.com/exif/1.0/"));
    assert_eq!(uri_to_ns("http://ns.adobe.com/exif/1.0/"), Some("exif"));
    assert_eq!(ns_uri("nonexistent"), None);
  }

  #[test]
  fn std_xlat_shortens_ugly_prefixes() {
    assert_eq!(std_xlat_ns("Iptc4xmpExt"), Some("iptcExt"));
    assert_eq!(xmp_ns("iptcExt"), "Iptc4xmpExt");
    assert_eq!(xmp_ns("exif"), "exif");
  }

  #[test]
  fn camera_tables_resolve() {
    let exif = lookup_ns_table("exif").expect("exif table ported");
    let metering = lookup_field(exif, "MeteringMode").expect("MeteringMode");
    assert!(matches!(metering.print_conv(), PrintConv::IntMap(_)));
    let tiff = lookup_field(lookup_ns_table("tiff").expect("tiff table"), "ImageLength")
      .expect("tiff ImageLength");
    assert_eq!(tiff.name(), Some("ImageHeight"));
  }
}
