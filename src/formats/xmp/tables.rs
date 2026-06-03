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
//! `xmp.rs`).
//!
//! ### Cross-module `PrintConv => \%Image::ExifTool::<Mod>::<hash>` refs
//!
//! Several XMP tags carry a `PrintConv` that REFERENCES a hash in another
//! ExifTool module instead of an inline hash (XMP.pm `\%Image::ExifTool::…`):
//! `tiff:Compression` → `%Exif::compression` (XMP.pm:1913),
//! `tiff:PhotometricInterpretation` → `%Exif::photometricInterpretation`
//! (XMP.pm:1917), `tiff:Orientation` → `%Exif::orientation` (XMP.pm:1921),
//! `tiff:YCbCrSubSampling` → `%JPEG::yCbCrSubSampling` (XMP.pm:1941) and
//! `exif:LightSource` → `%Exif::lightSource` (XMP.pm:2132). The `exif` /
//! `gps` IFD ports already carry these enumerations in
//! [`crate::exif::tables`], but the `xmp` feature is INDEPENDENT of `exif`
//! (`xmp = []` in `Cargo.toml`), so a direct cross-module `use` would break a
//! `--features xmp`-only build. The faithful, feature-clean resolution — the
//! pattern already used by `TIFF_ORIENTATION` (matching `%orientation`),
//! `EXIF_METERING`, `FLASH_RETURN`, … — is a LOCAL const that ports the
//! referenced bundled hash. These now carry a real [`PrintConv::IntMap`]
//! (full bundled hashes, NOT a subset) so a sidecar with e.g.
//! `tiff:Compression=1` prints `Uncompressed` like bundled ExifTool.
//!
//! TWO entries deliberately stay [`PrintConv::Identity`]:
//!   * `exif:Flash` — its `\%Exif::flash` PrintConv (XMP.pm:2834) belongs to
//!     the `%Image::ExifTool::XMP::Composite` `Flash` COMPOSITE tag
//!     (XMP.pm:2808-2834), NOT the `exif:Flash` STRUCT (XMP.pm:2134). Bundled
//!     ExifTool emits the raw integer for `XMP-exif:Flash` (the PrintConv'd
//!     label appears only on the deferred `Composite:Flash`), so `Identity`
//!     IS the faithful rendering; the struct's sub-fields keep their inline
//!     hashes in [`EXIF_FLASH_STRUCT`].
//!   * `tiff:YCbCrSubSampling` — needs the `RawJoin => 1` (XMP.pm:1936)
//!     list-join (the Seq is joined to `"2 2"` BEFORE the STRING-keyed
//!     `%yCbCrSubSampling` lookup, while `-n` keeps the `[2,2]` list). No
//!     RawJoin mechanism exists in the port (it would be its sole user), and
//!     the `-n` output already matches bundled; only the niche print label
//!     differs. Deferred (a documented incremental-completion item, like the
//!     `exif`-port's own omission of this tag).
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
  /// A code-valued ExifTool PrintConv/ValueConv that the generator could not
  /// transcribe (it is not present in `-listx`) and that has no hand-written
  /// Rust counterpart yet. Carries the source ref (e.g. `"XMP.pm:2648"`).
  /// Renders FAITHFULLY (the raw post-extraction string — no guessed conv) so
  /// an un-ported tag is never MIS-converted (cf. the R5 `NeutralDensityFactor`
  /// bug class); it is compile-visible + oracle-flagged for follow-up.
  /// Constructed by the xtask-GENERATED table (`tables_generated.rs`), e.g.
  /// `HDRGainMap:HDRGainMapVersion` (XMP2.pl:1791 — an un-ported `IsInt`/`unpack`
  /// version-number `PrintConv`).
  Unported(&'static str),
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
  /// A LARGE `key => label` lookup hash backed by a `phf::Map` for O(1)
  /// lookup, keyed by the RAW scalar STRING (an integer key is stored as its
  /// decimal text). Used by the xtask-GENERATED tables for value-maps over the
  /// emitter's phf threshold (e.g. PLUS `MediaSummaryCode` = 2143 entries); the
  /// lookup is the same faithful `$$conv{$val}` exact-string match as
  /// [`PrintConv::IntMap`]/[`PrintConv::StrMap`] (a miss ⇒ `Unknown ($val)`),
  /// just resolved through the perfect hash instead of a linear scan. The two
  /// representations share one lookup behind [`value_map_get`].
  MapPhf(&'static phf::Map<&'static str, &'static str>),
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
  /// `Image::ExifTool::XMP::DecodeBase64($val)` (XMP.pm:370/383 — the
  /// `xmpGImg:image` field of the `%sThumbnail` / `%sPageInfo` structs).
  /// `DecodeBase64` returns a Perl scalar REF (XMP.pm:3010), so `ConvertValue`
  /// (ExifTool.pm:3534) stops all further conversion and the value is kept as
  /// BINARY — emitted as the `(Binary data N bytes, use -b option to extract)`
  /// placeholder REGARDLESS of length (unlike the `rdf:datatype="base64"`
  /// attribute path, which dereferences ≤100-byte control-free payloads back
  /// to text, XMP.pm:3647). The decode runs on the ALREADY-un-escaped value
  /// (the field `ValueConv` fires after `FoundXMP` un-escapes + UTF8-decodes,
  /// XMP.pm:3655-3672), so an entity like `aGVs&#x62;G8=` un-escapes to
  /// `aGVsbG8=` first and only then decodes (→ `hello`).
  DecodeBase64,
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
///
/// Two layers (the ADDITIVE table-codegen invariant, Task 7): `fields` is the
/// hand-written, Codex-tuned table (it WINS on every key it defines); `gen` is
/// the xtask-generated fallback from `exiftool -listx` (it only ever supplies a
/// key the hand table lacks, and is the SOLE source for the ~71 namespaces the
/// hand table does not list). `lookup_field` consults `fields` first, then
/// `gen` — so an existing golden can never change (the hand `Field` shadows its
/// generated twin), while the generator purely ADDS coverage.
#[derive(Debug, Clone, Copy)]
pub struct NsTable {
  fields: &'static [Field],
  generated: &'static [Field],
}

impl NsTable {
  /// A hand-written-only table (no generated fallback) — used by the struct
  /// sub-tables and any table built before the generated layer is consulted.
  #[allow(dead_code)]
  const fn hand(fields: &'static [Field]) -> Self {
    Self {
      fields,
      generated: &[],
    }
  }

  /// The hand-written fields of this table (the tuned layer; excludes the
  /// generated fallback).
  #[must_use]
  #[inline(always)]
  #[allow(dead_code)] // public table-introspection accessor (D8)
  pub const fn fields(&self) -> &'static [Field] {
    self.fields
  }
}

/// Look a field up in a namespace table by its XMP property key. The
/// hand-written `fields` are consulted FIRST (they win on any collision); only
/// if the key is absent there does the generated fallback (`gen`) supply it.
/// This is the additive guarantee — a hand-tuned `Field` always shadows its
/// `-listx`-generated twin, so no existing golden can shift.
#[must_use]
pub fn lookup_field(table: &NsTable, key: &str) -> Option<&'static Field> {
  // Both layers are `&'static [Field]`, so an element reference is `&'static`
  // regardless of the (possibly by-value, on-the-fly) `table` it came from —
  // which is what lets `lookup_ns_table` return an `NsTable` by value.
  table
    .fields
    .iter()
    .find(|f| f.key == key)
    .or_else(|| table.generated.iter().find(|f| f.key == key))
}

/// One value-map lookup API shared by the hand-written sorted slices and the
/// generated `phf::Map`s (the `value_map!`/`lookup_map!` helper of the codegen
/// plan). Every representation keys by the RAW scalar STRING — the faithful
/// `$$conv{$val}` exact-string match (ExifTool.pm:3604, NO integer coercion:
/// `"05"` misses the `5` key) — so an `i64`-keyed slice stringifies its key,
/// while the phf map (whose keys are already the decimal/string text) does an
/// O(1) `get`. A hit returns the mapped label; a miss returns `None` (the
/// caller decides between `Unknown ($val)` and a passthrough). This unifies the
/// two map shapes behind one call so the generated + hand-written tables look
/// up identically.
#[must_use]
pub fn value_map_get(map: &ValueMap, key: &str) -> Option<&'static str> {
  match map {
    ValueMap::IntSlice(s) => s
      .iter()
      .find_map(|&(k, v)| (k.to_string() == key).then_some(v)),
    ValueMap::StrSlice(s) => s.iter().find_map(|&(k, v)| (k == key).then_some(v)),
    ValueMap::Phf(m) => m.get(key).copied(),
  }
}

/// The three concrete value-map representations [`value_map_get`] unifies: a
/// small int-keyed slice (stringified lookup), a small string-keyed slice, and
/// a large `phf::Map` (string-keyed, O(1)). The hand-written tables carry the
/// slices directly on their `PrintConv` variants; the generator emits a `phf`
/// map only above its size threshold.
pub enum ValueMap {
  /// `&[(i64, &str)]` — the hand-written [`PrintConv::IntMap`] representation.
  IntSlice(&'static [(i64, &'static str)]),
  /// `&[(&str, &str)]` — the hand-written [`PrintConv::StrMap`] representation.
  StrSlice(&'static [(&'static str, &'static str)]),
  /// A generated `phf::Map<&str, &str>` ([`PrintConv::MapPhf`]).
  Phf(&'static phf::Map<&'static str, &'static str>),
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
/// The cross-module `PrintConv => \%Image::ExifTool::Exif::…` refs
/// (`Compression`, `PhotometricInterpretation`, `Orientation`) are wired to
/// LOCAL ports of the referenced bundled hashes (see the module docs);
/// `YCbCrSubSampling` stays `Identity` (it needs the unported `RawJoin`).
/// `%Image::ExifTool::Exif::orientation` (Exif.pm:291-299) — a plain lookup
/// hash, not a converter sub.
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
/// `tiff:Compression` PrintConv — `\%Image::ExifTool::Exif::compression`
/// (XMP.pm:1913). Ported in FULL from `%compression` (Exif.pm:213-269) so an
/// uncommon code (e.g. `34713 => 'Nikon NEF Compressed'`) renders like
/// bundled instead of `Unknown (N)`. No `PrintHex` on the XMP tiff tag, so a
/// genuine miss is decimal `Unknown (N)` — i.e. [`PrintConv::IntMap`].
static TIFF_COMPRESSION: &[(i64, &str)] = &[
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
/// `tiff:PhotometricInterpretation` PrintConv —
/// `\%Image::ExifTool::Exif::photometricInterpretation` (XMP.pm:1917). Ported
/// in FULL from `%photometricInterpretation` (Exif.pm:271-289).
static TIFF_PHOTOMETRIC: &[(i64, &str)] = &[
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
  (32844, "Pixar LogL"),
  (32845, "Pixar LogLuv"),
  (32892, "Sequential Color Filter"),
  (34892, "Linear Raw"),
  (51177, "Depth Map"),
  (52527, "Semantic Mask"),
];
static TIFF_PLANAR: &[(i64, &str)] = &[(1, "Chunky"), (2, "Planar")];
static TIFF_YCBCR_POS: &[(i64, &str)] = &[(1, "Centered"), (2, "Co-sited")];
static TIFF_RES_UNIT: &[(i64, &str)] = &[(1, "None"), (2, "inches"), (3, "cm")];
static TIFF: &[Field] = &[
  Field::make("ImageWidth", None, W::Integer, P::Identity),
  Field::make("ImageLength", Some("ImageHeight"), W::Integer, P::Identity),
  Field::make("BitsPerSample", None, W::Integer, P::Identity),
  Field::make("Compression", None, W::Integer, P::IntMap(TIFF_COMPRESSION)),
  Field::make(
    "PhotometricInterpretation",
    None,
    W::Integer,
    P::IntMap(TIFF_PHOTOMETRIC),
  ),
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
  // LR6+ / LR7+ / LR11+ Lightroom AUX tags (XMP.pm:2641-2658). The four
  // bundled `{}` rows (no `Writable`) — `LensDistortInfo`,
  // `NeutralDensityFactor`, `EnhanceDetailsVersion`,
  // `EnhanceSuperResolutionVersion`, `EnhanceDenoiseVersion`,
  // `EnhanceDenoiseLumaAmount` — are EXPLICIT table entries, so ExifTool's
  // `$$tagInfo{IsDefault}` is FALSE and `$$tagInfo{Writable}` is undef ⇒ the
  // XMPAutoConv `ConvertRational`/`ConvertXMPDate` block (XMP.pm:3676) is
  // SKIPPED. They are therefore plain strings ([`W::Str`], which disables the
  // port's auto-conv exactly like the established `{}`→`W::Str` mapping for
  // `Lens`/`OwnerName`/… above). The bug this fixes: `NeutralDensityFactor`
  // (XMP.pm:2648) holds a rational-looking `"1/2"` whose DENOMINATOR is
  // significant (per the bundled comment), so it must stay `"1/2"` verbatim —
  // NOT be `ConvertRational`'d to `0.5` (which the missing-from-table default
  // path did). `EnhanceSuperResolutionScale` (XMP.pm:2654) DOES carry
  // `Writable => 'rational'`, so its `2/1` IS converted to `2`.
  Field::make("IsMergedPanorama", None, W::Boolean, P::Bool),
  Field::make("IsMergedHDR", None, W::Boolean, P::Bool),
  Field::make(
    "DistortionCorrectionAlreadyApplied",
    None,
    W::Boolean,
    P::Bool,
  ),
  Field::make(
    "VignetteCorrectionAlreadyApplied",
    None,
    W::Boolean,
    P::Bool,
  ),
  Field::make(
    "LateralChromaticAberrationCorrectionAlreadyApplied",
    None,
    W::Boolean,
    P::Bool,
  ),
  Field::make("LensDistortInfo", None, W::Str, P::Identity),
  // `{}` (no Writable) — rational-looking value kept VERBATIM (denominator is
  // significant); the AutoConv block is skipped for a table-present no-Writable
  // tag (XMP.pm:2648).
  Field::make("NeutralDensityFactor", None, W::Str, P::Identity),
  Field::make("EnhanceDetailsAlreadyApplied", None, W::Boolean, P::Bool),
  // `{}` (XMP.pm:2651, "integer?") — plain string, no AutoConv.
  Field::make("EnhanceDetailsVersion", None, W::Str, P::Identity),
  Field::make(
    "EnhanceSuperResolutionAlreadyApplied",
    None,
    W::Boolean,
    P::Bool,
  ),
  // `{}` (XMP.pm:2653, "integer?") — plain string, no AutoConv.
  Field::make("EnhanceSuperResolutionVersion", None, W::Str, P::Identity),
  // `Writable => 'rational'` (XMP.pm:2654) — `2/1` → `2` via ConvertRational.
  Field::make(
    "EnhanceSuperResolutionScale",
    None,
    W::Rational,
    P::Identity,
  ),
  Field::make("EnhanceDenoiseAlreadyApplied", None, W::Boolean, P::Bool),
  // `{}` (XMP.pm:2656, "integer?") — plain string, no AutoConv.
  Field::make("EnhanceDenoiseVersion", None, W::Str, P::Identity),
  // `{}` (XMP.pm:2657, "integer?") — plain string, no AutoConv.
  Field::make("EnhanceDenoiseLumaAmount", None, W::Str, P::Identity),
  Field::make("FujiRatingAlreadyApplied", None, W::Boolean, P::Bool),
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
/// `exif:LightSource` PrintConv — `\%Image::ExifTool::Exif::lightSource`
/// (XMP.pm:2132). Ported in FULL from `%lightSource` (Exif.pm:139-172). A
/// hash miss is decimal `Unknown (N)` (no `PrintHex` on this XMP tag) —
/// i.e. [`PrintConv::IntMap`].
static EXIF_LIGHT_SOURCE: &[(i64, &str)] = &[
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
  (16, "Warm White Fluorescent"),
  (17, "Standard Light A"),
  (18, "Standard Light B"),
  (19, "Standard Light C"),
  (20, "D55"),
  (21, "D65"),
  (22, "D75"),
  (23, "D50"),
  (24, "ISO Studio Tungsten"),
  (25, "Daylight"),
  (26, "Day White"),
  (27, "Cool White"),
  (28, "White"),
  (29, "Warm White"),
  (30, "Daylight LED"),
  (31, "Day White LED"),
  (32, "Cool White LED"),
  (33, "White LED"),
  (34, "Warm White LED"),
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
  Field::make(
    "LightSource",
    None,
    W::Integer,
    P::IntMap(EXIF_LIGHT_SOURCE),
  ),
  // `exif:Flash` (XMP.pm:2134) is a STRUCT; the bare/flattened integer keeps
  // `Identity` — the `\%Exif::flash` PrintConv (XMP.pm:2834) is the deferred
  // `Composite:Flash` tag's, not this one (bundled emits raw for
  // `XMP-exif:Flash`). The struct sub-fields convert via `EXIF_FLASH_STRUCT`.
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

use super::tables_generated as g;

/// The hand-written camera-metadata namespace tables, each paired with its
/// xtask-generated `GEN_<NS>` fallback slice (the additive layer — hand `fields`
/// win, `gen` only ADDS tags the hand table lacks). Namespaces NOT listed here
/// (crs, lr, xmpMM, xmpDM, pdf, iptcExt, …) have no hand table and are resolved
/// generated-only via [`lookup_ns_table`]'s fallback into `g::GEN_NS_TABLES`.
static NS_TABLES: &[(&str, NsTable)] = &[
  (
    "dc",
    NsTable {
      fields: DC,
      generated: g::GEN_DC,
    },
  ),
  (
    "xmp",
    NsTable {
      fields: XMP,
      generated: g::GEN_XMP,
    },
  ),
  (
    "xmpRights",
    NsTable {
      fields: XMP_RIGHTS,
      generated: g::GEN_XMPRIGHTS,
    },
  ),
  (
    "photoshop",
    NsTable {
      fields: PHOTOSHOP,
      generated: g::GEN_PHOTOSHOP,
    },
  ),
  (
    "tiff",
    NsTable {
      fields: TIFF,
      generated: g::GEN_TIFF,
    },
  ),
  (
    "aux",
    NsTable {
      fields: AUX,
      generated: g::GEN_AUX,
    },
  ),
  (
    "exif",
    NsTable {
      fields: EXIF,
      generated: g::GEN_EXIF,
    },
  ),
];

/// Resolve a (already `%stdXlatNS`-translated) namespace to its tag table.
///
/// The hand-written `NS_TABLES` are checked FIRST (so the 7 tuned namespaces
/// keep their hand `fields` + generated fallback); if the namespace has no hand
/// table, the generated `g::GEN_NS_TABLES` index is consulted and the namespace
/// is surfaced as a generated-only [`NsTable`] (empty hand `fields`, the
/// generated slice as `gen`). Returns `None` only for a namespace neither layer
/// defines — its tags route through `FoundXMP`'s faithful default-tagInfo path.
///
/// Returns by VALUE ([`NsTable`] is `Copy` — two slice pointers): the
/// generated-only case constructs the table on the fly, so a `&'static`
/// signature is not possible. Every consumer immediately reads `.fields()` or
/// calls [`lookup_field`], so by-value is transparent.
#[must_use]
pub fn lookup_ns_table(ns: &str) -> Option<NsTable> {
  if let Some(t) = NS_TABLES.iter().find_map(|(n, t)| (*n == ns).then_some(*t)) {
    return Some(t);
  }
  g::GEN_NS_TABLES.iter().find_map(|&(n, generated)| {
    (n == ns).then_some(NsTable {
      fields: &[],
      generated,
    })
  })
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

/// `%sThumbnail` (XMP.pm:361-373) — the struct of `xmp:Thumbnails`
/// (XMP.pm:1062, `Struct => \%sThumbnail`). `NAMESPACE => 'xmpGImg'`, so in a
/// sidecar the sub-fields are `xmpGImg:height|width|format|image`. The `image`
/// field (XMP.pm:367-372) carries `ValueConv => DecodeBase64` — its base64
/// payload decodes to BINARY and renders as the `(Binary data N bytes, …)`
/// placeholder, not the literal base64 scalar. `height`/`width` are
/// `Writable => 'integer'`; `format` is a plain `{}` string.
static THUMBNAIL_STRUCT: &[Field] = &[
  Field::make("height", None, W::Integer, P::Identity),
  Field::make("width", None, W::Integer, P::Identity),
  Field::make("format", None, W::Str, P::Identity),
  Field::make_vc("image", None, W::Str, ValueConv::DecodeBase64, P::Identity),
];

/// `%sPageInfo` (XMP.pm:374-386) — the struct of `xmp:PageInfo` (XMP.pm:1068,
/// `Struct => \%sPageInfo`, written by Adobe InDesign). Like `%sThumbnail` but
/// with a leading `PageNumber` (`Writable => 'integer'`, `Namespace =>
/// 'xmpTPg'`); the `image` field again decodes base64 → binary (XMP.pm:381).
static PAGE_INFO_STRUCT: &[Field] = &[
  Field::make("PageNumber", None, W::Integer, P::Identity),
  Field::make("height", None, W::Integer, P::Identity),
  Field::make("width", None, W::Integer, P::Identity),
  Field::make("format", None, W::Str, P::Identity),
  Field::make_vc("image", None, W::Str, ValueConv::DecodeBase64, P::Identity),
];

/// `(namespace, parent-struct-field, sub-table)` registry. Looked up by
/// [`lookup_struct_field`] when a nested-struct field misses the top-level
/// namespace table. Camera-critical struct: `exif:Flash`; the `xmp:Thumbnails`
/// / `xmp:PageInfo` structs are registered so the `xmpGImg:image` base64 field
/// resolves to its `DecodeBase64` `ValueConv` (binary placeholder).
static STRUCT_TABLES: &[(&str, &str, &[Field])] = &[
  ("exif", "Flash", EXIF_FLASH_STRUCT),
  ("xmp", "Thumbnails", THUMBNAIL_STRUCT),
  ("xmp", "PageInfo", PAGE_INFO_STRUCT),
];

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
    let metering = lookup_field(&exif, "MeteringMode").expect("MeteringMode");
    assert!(matches!(metering.print_conv(), PrintConv::IntMap(_)));
    let tiff_tbl = lookup_ns_table("tiff").expect("tiff table");
    let tiff = lookup_field(&tiff_tbl, "ImageLength").expect("tiff ImageLength");
    assert_eq!(tiff.name(), Some("ImageHeight"));
  }

  /// The additive layer resolves a generated-only namespace (no hand table)
  /// AND the hand `Field` still wins on a collision in a shared namespace.
  #[test]
  fn generated_namespaces_resolve_additively() {
    // `crs` (Lightroom camera-raw-settings) has NO hand table — generated-only.
    let crs = lookup_ns_table("crs").expect("crs resolves via the generated layer");
    assert!(crs.fields().is_empty(), "crs has no hand fields");
    assert!(
      lookup_field(&crs, "RawFileName").is_some(),
      "a generated crs tag resolves"
    );
    // In a SHARED namespace the hand field shadows its generated twin: the hand
    // `exif:MeteringMode` carries an `IntMap`, never the generated default.
    let exif = lookup_ns_table("exif").expect("exif table");
    let metering = lookup_field(&exif, "MeteringMode").expect("MeteringMode");
    assert!(matches!(metering.print_conv(), PrintConv::IntMap(_)));
  }
}
