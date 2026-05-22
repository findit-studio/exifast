// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "xmp")]
//! Faithful port of `Image::ExifTool::XMP` (lib/Image/ExifTool/XMP.pm +
//! XMP2.pl), bundled ExifTool 13.58.
//!
//! XMP (Extensible Metadata Platform) is Adobe's RDF/XML metadata format. A
//! standalone `.xmp` sidecar file → FileType `XMP` → `ProcessXMP`
//! (XMP.pm:4262). ExifTool ships its own lightweight, non-validating XML
//! element walker (`ParseXMPElement`, XMP.pm:3768) — this port replicates
//! that walker bit-for-bit rather than using a real XML library:
//!
//! - `<([?/]?)([-\w:.]+|!--)([^>]*)>` element/comment/CDATA scanner;
//! - namespace-prefix resolution against the `%nsURI` / `%uri2ns` tables
//!   (XMP.pm:109-213), with the wild-prefix-taming logic that maps a file's
//!   prefix back to ExifTool's canonical one;
//! - `rdf:li` indexed list items, `rdf:Bag`/`Seq`/`Alt` arrays;
//! - `rdf:parseType="Resource"` and nested `rdf:Description` structures;
//! - `xml:lang` language-alternative (`lang-alt`) handling;
//! - `rdf:nodeID` blank-node resolution (`SaveBlankInfo` /
//!   `ProcessBlankInfo`, WriteXMP.pl:419/456);
//! - structured-property flattening + the `RestoreStruct` rebuild
//!   (XMPStruct.pl:708) that turns flattened tags back into nested
//!   objects for `-struct` output.
//!
//! `FoundXMP` (XMP.pm:3435) assembles the tag id from the property path
//! (`GetXMPTagID`, XMP.pm:3018), looks the namespace up in the per-namespace
//! tag table for the family-1 group + any PrintConv / ValueConv / Name
//! remap, applies `XMPAutoConv` (default-on: `ConvertXMPDate` +
//! `ConvertRational` on every tag without an explicit Writable type), and
//! emits the value.
//!
//! ## Tag-table scope
//!
//! The product extracts camera maker / lens / model / GPS. The
//! camera-critical namespace tables — `tiff`, `exif`, `photoshop`, `xmp`,
//! `xmpRights`, `dc`, `xmpMM` — are ported COMPLETELY (PrintConv maps,
//! ValueConv, Name remaps). Tags in a namespace WITHOUT a ported table fall
//! through to FoundXMP's faithful "default tagInfo" path (`IsDefault=1`, no
//! PrintConv) — bit-identical to ExifTool's own behavior for any tag absent
//! from a loaded table: the tag IS extracted with its raw
//! (XMPAutoConv-converted) value, only namespace-specific PrintConv labels
//! are absent. See `docs/tracking.md` and the `#[ignore]`'d
//! `xmp_unported_namespace_printconv_deferred` test for the 4-surface
//! accept-defer of namespace-table PrintConv on non-fixture namespaces.

use crate::format_parser::{FormatParser, parser_sealed};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;

mod tables;
use tables::{NsTable, Writable, lookup_field, lookup_ns_table, std_xlat_ns, uri_to_ns};

// ===========================================================================
// XmpValue — the structured value tree
// ===========================================================================

/// A decoded XMP value. Scalars are stored as their post-conversion text
/// (`Str`) or numeric form; structures and lists nest. This mirrors the
/// shape `RestoreStruct` (XMPStruct.pl:708) rebuilds for `-struct` output.
///
/// D8: no public fields; the enum has newtype variants only.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum XmpValue {
  /// A scalar value (already un-escaped + XMPAutoConv-converted).
  Scalar(XmpScalar),
  /// An ordered list (`rdf:Bag` / `rdf:Seq` / `rdf:Alt`).
  List(Vec<XmpValue>),
  /// A structure (`rdf:parseType="Resource"` or nested `rdf:Description`).
  Struct(XmpStruct),
  /// Decoded `base64` binary payload kept as bytes (NOT coerced to text).
  /// `FoundXMP` (XMP.pm:3646-3647) dereferences the decoded value to a string
  /// ONLY when it is `<= 100` bytes AND has no control bytes; otherwise it
  /// stays a value ref (binary), which `FoundTag` records as binary data and
  /// JSON renders as the `(Binary data N bytes, use -b option to extract)`
  /// placeholder.
  Binary(Vec<u8>),
}

impl XmpValue {
  /// `true` if this is a [`XmpValue::Scalar`].
  #[must_use]
  #[inline(always)]
  pub const fn is_scalar(&self) -> bool {
    matches!(self, XmpValue::Scalar(_))
  }
  /// `true` if this is a [`XmpValue::List`].
  #[must_use]
  #[inline(always)]
  pub const fn is_list(&self) -> bool {
    matches!(self, XmpValue::List(_))
  }
  /// `true` if this is a [`XmpValue::Struct`].
  #[must_use]
  #[inline(always)]
  pub const fn is_struct(&self) -> bool {
    matches!(self, XmpValue::Struct(_))
  }
  /// `true` if this is a [`XmpValue::Binary`].
  #[must_use]
  #[inline(always)]
  pub const fn is_binary(&self) -> bool {
    matches!(self, XmpValue::Binary(_))
  }
  /// The scalar payload, if this is a [`XmpValue::Scalar`].
  #[must_use]
  #[inline(always)]
  pub const fn scalar_ref(&self) -> Option<&XmpScalar> {
    match self {
      XmpValue::Scalar(s) => Some(s),
      _ => None,
    }
  }

  /// Convert to a [`TagValue`] for the typed-Meta tag sink, in the given
  /// output mode (`print_conv = true` ⇒ `-j`, `false` ⇒ `-n`). Drives the
  /// `serialize_tags` emission — reachable only through the `alloc` `TagMap`
  /// sink, and exercised by callers that enable `json`/`serde`; `allow`'d so
  /// an `alloc`-only-no-`json` build (where the whole emit chain is dead) is
  /// warning-clean.
  #[cfg(feature = "alloc")]
  #[allow(dead_code)]
  fn to_tag_value(&self, print_conv: bool) -> TagValue {
    match self {
      XmpValue::Scalar(s) => s.to_tag_value(print_conv),
      XmpValue::List(items) => {
        TagValue::List(items.iter().map(|v| v.to_tag_value(print_conv)).collect())
      }
      XmpValue::Struct(st) => TagValue::Map(
        st.fields_slice()
          .iter()
          .map(|(k, v)| (k.clone(), v.to_tag_value(print_conv)))
          .collect(),
      ),
      // Binary base64 payload — emitted as raw bytes so the serializer prints
      // the `(Binary data N bytes, …)` placeholder, faithful to FoundTag's
      // handling of the decoded value ref (XMP.pm:3646-3647).
      XmpValue::Binary(b) => TagValue::Bytes(b.clone()),
    }
  }
}

/// A scalar XMP value. ExifTool is untyped — every value is fundamentally a
/// string and the one JSON number gate (`exiftool:3809`) decides bare vs
/// quoted at output time. A scalar keeps BOTH the post-ValueConv numeric
/// text (the `-n` form) and the post-PrintConv display text (the `-j`
/// form); they are equal for a tag with no PrintConv. [`TagValue`]'s
/// serializer runs the same value-semantic gate, so a numeric-looking
/// value (`"180"`, `"2.8"`) emits as a bare JSON number while a true
/// string stays quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmpScalar {
  /// Post-ValueConv form — what `-n` (numeric) output uses.
  numeric: String,
  /// Post-PrintConv form — what default `-j` output uses.
  print: String,
}

impl XmpScalar {
  /// Construct from a value with no PrintConv (numeric == print).
  #[must_use]
  #[inline(always)]
  pub(crate) fn new(text: impl Into<String>) -> Self {
    let s = text.into();
    Self {
      numeric: s.clone(),
      print: s,
    }
  }
  /// Construct from distinct numeric (`-n`) and print (`-j`) forms.
  #[must_use]
  #[inline(always)]
  pub(crate) fn with_print(numeric: impl Into<String>, print: impl Into<String>) -> Self {
    Self {
      numeric: numeric.into(),
      print: print.into(),
    }
  }
  /// The post-PrintConv display text (the `-j` form).
  #[must_use]
  #[inline(always)]
  pub fn text(&self) -> &str {
    &self.print
  }
  /// The post-ValueConv numeric text (the `-n` form).
  #[must_use]
  #[inline(always)]
  pub fn numeric(&self) -> &str {
    &self.numeric
  }
  /// To a [`TagValue`] for the given output mode — always `Str`; the
  /// serializer's number gate renders numeric text as a bare number
  /// (faithful to `EscapeJSON`, `exiftool:3804-3812`).
  #[cfg(feature = "alloc")]
  #[allow(dead_code)] // see `XmpValue::to_tag_value`
  fn to_tag_value(&self, print_conv: bool) -> TagValue {
    let s = if print_conv {
      &self.print
    } else {
      &self.numeric
    };
    TagValue::Str(SmolStr::new(s))
  }
}

/// An ordered XMP structure: field-name → value, first-occurrence order.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct XmpStruct {
  fields: Vec<(SmolStr, XmpValue)>,
}

impl XmpStruct {
  /// An empty structure.
  #[must_use]
  #[inline(always)]
  pub fn new() -> Self {
    Self { fields: Vec::new() }
  }
  /// The ordered `(field-name, value)` pairs.
  #[must_use]
  #[inline(always)]
  pub fn fields_slice(&self) -> &[(SmolStr, XmpValue)] {
    &self.fields
  }
  /// `true` if this structure has no fields.
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.fields.is_empty()
  }
  /// Number of fields.
  #[must_use]
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.fields.len()
  }
  /// Append one `(field-name, value)` pair (struct-rebuild internal use).
  pub(crate) fn push_field(&mut self, name: SmolStr, value: XmpValue) {
    self.fields.push((name, value));
  }
}

// ===========================================================================
// XmpMeta — the typed output
// ===========================================================================

/// Typed XMP metadata — the lib-first output of [`ProcessXmp`].
///
/// `XmpMeta` carries an ordered list of [`XmpTag`]s in extraction order
/// (faithful to ExifTool's `FoundTag` call sequence after `RestoreStruct`),
/// plus the detected sub-file-type (`XMP` / `SVG` / `XML` / `PLIST` …).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, Default)]
pub struct XmpMeta<'a> {
  tags: Vec<XmpTag>,
  /// First recorded warning (`$self->Warn`, ExifTool.pm:1297).
  warning: Option<String>,
  /// `OverrideFileType('NXD','application/x-nikon-nxd')` latch (XMP.pm:3916):
  /// set when the document declares an `xmlns` URI beginning
  /// `http://ns.nikon.com/BASIC_PARAM` (a Nikon NX-D settings sidecar). The
  /// engine uses this to finalize `File:FileType=NXD` +
  /// `File:MIMEType=application/x-nikon-nxd` instead of generic `XMP`.
  nikon_nxd: bool,
  /// `core::marker` lifetime anchor — `XmpMeta` is `'a`-parameterized to
  /// satisfy the `FormatParser::Meta<'a>` GAT contract even though the
  /// decoded XMP owns its strings (the input is transcoded UTF-8/16/32 →
  /// owned `String`, so nothing borrows from the buffer).
  _input: core::marker::PhantomData<&'a [u8]>,
}

impl XmpMeta<'_> {
  /// Every emitted tag in extraction order.
  #[must_use]
  #[inline(always)]
  pub fn tags_slice(&self) -> &[XmpTag] {
    &self.tags
  }
  /// The first recorded `Warning`, if any.
  #[must_use]
  #[inline(always)]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// Whether `OverrideFileType('NXD','application/x-nikon-nxd')` fired
  /// (XMP.pm:3916) — `true` when the document declared an `xmlns` URI
  /// beginning `http://ns.nikon.com/BASIC_PARAM` (a Nikon NX-D settings
  /// sidecar). The engine finalizes `File:FileType=NXD` +
  /// `File:MIMEType=application/x-nikon-nxd` when this is set.
  #[must_use]
  #[inline(always)]
  pub const fn is_nikon_nxd(&self) -> bool {
    self.nikon_nxd
  }

  /// Record the decode-stage warning (`XMP is double UTF-encoded`,
  /// XMP.pm:4491), which ExifTool emits BEFORE the element walk and therefore
  /// keeps ahead of any walk/`RestoreStruct` warning (`FoundTag('Warning', …)`
  /// first-wins). Overwrites any walk warning to preserve that ordering.
  fn set_decode_warning(&mut self, msg: String) {
    self.warning = Some(msg);
  }
}

/// One emitted XMP tag: family-1 group (`XMP-exif`, `XMP-dc`, …), tag name,
/// and decoded value.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq)]
pub struct XmpTag {
  group: SmolStr,
  name: SmolStr,
  value: XmpValue,
}

impl XmpTag {
  /// Family-1 group (e.g. `"XMP-exif"`, `"XMP-dc"`, `"XMP-x"`).
  #[must_use]
  #[inline(always)]
  pub fn group(&self) -> &str {
    self.group.as_str()
  }
  /// Tag name (e.g. `"Make"`, `"DateTimeOriginal"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Decoded value.
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &XmpValue {
    &self.value
  }
}

// ===========================================================================
// `ProcessXmp` — the lib-first parser
// ===========================================================================

/// XMP / SVG / XML parser — faithful port of `Image::ExifTool::XMP::ProcessXMP`
/// (XMP.pm:4262).
#[derive(Debug, Clone, Copy)]
pub struct ProcessXmp;

impl parser_sealed::Sealed for ProcessXmp {}

impl FormatParser for ProcessXmp {
  type Meta<'a> = XmpMeta<'a>;
  type Context<'a> = &'a [u8];
  type Error = Error;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
    Ok(parse_inner(data))
  }
}

/// Lib-first direct entry.
///
/// # Errors
///
/// Returns `Err` only for Rust-level fatal modes (none today — every bad
/// input is `Ok(None)`, faithful to `ProcessXMP` `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<XmpMeta<'_>>, Error> {
  Ok(parse_inner(data))
}

/// Rust-level fatal error for the XMP parser. Uninhabited: every malformed
/// input is `Ok(None)` (faithful to ExifTool `return 0`); warnings are
/// recorded in [`XmpMeta`].
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {}

// ===========================================================================
// ProcessXMP — file recognition + encoding (XMP.pm:4262-4620)
// ===========================================================================

/// Inner parser. Returns `None` if the data is not recognized XMP/XML
/// (faithful to `ProcessXMP` `return 0`, XMP.pm:4340/4380).
fn parse_inner(data: &[u8]) -> Option<XmpMeta<'_>> {
  // ProcessXMP file-recognition (XMP.pm:4321-4395): read the head, strip
  // NULs for a cheap UTF-8 probe, peel leading comments, then classify.
  // `buf2` is the NUL-stripped view used for the recognition regexes.
  let buf2: Vec<u8> = data.iter().copied().filter(|&b| b != 0).collect();
  let buf2 = strip_leading_comments(&buf2);

  // Recognition (XMP.pm:4337-4427). `ProcessXMP` recognizes several XML
  // flavours and `SetFileType`s each to a DIFFERENT type:
  //   - `<?xpacket begin=` / `<x(mp)?:x[ma]pmeta`        → XMP
  //   - `<rdf:RDF`                                       → XMP (`$isRDF`)
  //   - `<?xml` + `<x(mp)?:x[ma]pmeta` inside            → XMP (`$hasXMP`)
  //   - `<?xml` + `<rdf:RDF` inside                      → XMP (`$isRDF`)
  //   - `<?xml` + `<svg` / `<!DOCTYPE svg`               → `SetFileType('SVG')`
  //   - `<?xml` + `<plist` / `<!DOCTYPE plist`           → PLIST module
  //   - `<svg`-rooted                                    → `SetFileType('SVG')`
  //   - other `<?xml` (no xmpmeta/rdf/svg/plist)         → `SetFileType('XML')`
  //
  // Codex R8/F2: this port targets XMP sidecars only. The SVG path is a
  // sizeable sub-port (a whole `SVG` tag table — `Xmlns`/`ImageWidth`/
  // `ImageHeight`/`Title`/`Desc` … — plus the SVG-specific prop-list
  // filtering at XMP.pm:4051-4062 and the `SVG:` group); PLIST is a
  // separate `Image::ExifTool::PLIST` module; the bare-`XML` flavour is a
  // FileType label with effectively no metadata. All three are DEFERRED
  // (see `docs/tracking.md`). So `parse_inner` accepts ONLY the inputs
  // ExifTool finalizes to FileType `XMP`, and REJECTS (`return None`,
  // faithful to `ProcessXMP` `return 0`) every `<svg`-rooted or
  // non-XMP-`<?xml`-rooted input rather than mis-finalizing it as XMP.
  //
  // ProcessXMP recognition is a TWO-TIER match, and the tiers differ in their
  // leading-whitespace tolerance — Codex R9/F1. Mirror the Perl anchoring
  // EXACTLY (verified vs bundled 13.58):
  //
  //   Tier 1 (XMP.pm:4341): `if ($buf2 =~ /^\s*(<\?xpacket begin=|
  //     <x(mp)?:x[ma]pmeta)/)` — anchored `^\s*`, so leading ASCII whitespace
  //     IS tolerated, but NO byte-order mark may precede the token.
  //
  //   Tier 2 (XMP.pm:4345-4354, the `else` block): the BOM / `<?xml` /
  //     `<rdf:RDF` / xmpmeta / `<svg` / double-encoded-xpacket branches are all
  //     anchored at byte 0 (`/^(\xfe\xff)…/`, `/^(\xef\xbb\xbf)?(<\?xml|…)/`)
  //     with an OPTIONAL byte-0 BOM but NO leading whitespace.
  //
  // So `   <rdf:RDF…` / `   <?xml…<x:xmpmeta…` finalize to TXT (Tier-2 byte-0
  // anchor fails on the leading space), while `   <?xpacket…` / `   <x:xmpmeta…`
  // finalize to XMP (Tier-1 `^\s*`). Whitespace BEFORE a BOM is rejected by
  // both tiers. The old code trimmed whitespace before ALL branches, wrongly
  // accepting the Tier-2 inputs ExifTool rejects.
  //
  // `buf2` already dropped interior NULs, so a UTF-16/32 BOM is the bare two
  // bytes `FE FF` / `FF FE` here (XMP.pm:4345/4347 capture exactly that on the
  // NUL-stripped probe).
  //
  // ---- Tier 1: `^\s*(<?xpacket begin=|<x(mp)?:x[ma]pmeta)` ----------------
  // Leading ASCII whitespace IS tolerated (the `^\s*`), but NO BOM may precede
  // the token. Both spellings finalize to FileType `XMP` (`$hasXMP`,
  // XMP.pm:4341-4342).
  let tier1 = {
    let after_ws = trim_ascii_start(buf2);
    after_ws.starts_with(b"<?xpacket begin=") || starts_with_xmpmeta(after_ws)
  };
  // The recognition tiers both classify whether the input finalizes to
  // FileType `XMP` AND, for the byte-0-BOM `<?xpacket begin=` arm, capture the
  // `$double` BOM that selects the double-encoded-UTF decode (XMP.pm:4351).
  let recognized: Option<DoubleBom> = if tier1 {
    // Tier 1 has no BOM (a BOM forces Tier 2), so it is never the `$double`
    // path — ordinary single-layer decode.
    Some(DoubleBom::None)
  } else {
    // ---- Tier 2: byte-0 anchored, optional byte-0 BOM --------------------
    // Strip an OPTIONAL leading BOM at byte 0 (NO preceding whitespace), then
    // classify the token that must sit at byte 0 (XMP.pm:4345-4354).
    let (after_bom, bom) = strip_recognition_bom(buf2);
    if bom != DoubleBom::None && after_bom.starts_with(b"<?xpacket begin=") {
      // A byte-0 BOM (`\xfe\xff` / `\xff\xfe` / `\xef\xbb\xbf` — buf2 already
      // dropped interior NULs, so a UTF-32 BOM presents as its 2-byte form
      // here) directly before `<?xpacket begin=` is the `$double` capture
      // (XMP.pm:4351 `/^(\xfe\xff|\xff\xfe|\xef\xbb\xbf)(<\?xpacket begin=)/`).
      // It finalizes to FileType `XMP` and routes the double-encoded-UTF decode
      // (XMP.pm:4467-4498).
      Some(bom)
    } else if after_bom.starts_with(b"<rdf:RDF") || starts_with_xmpmeta(after_bom) {
      // `<rdf:RDF` (`$isRDF`, XMP.pm:4391) and a byte-0-BOM `<x(mp)?:x[ma]pmeta`
      // (XMP.pm:4345-4349) finalize to FileType `XMP` via the ordinary decode
      // (NOT `$double` — that arm is `<?xpacket begin=`-only). A *bare*
      // `<?xpacket`/xmpmeta — no BOM — was already taken by Tier 1.
      Some(DoubleBom::None)
    } else if after_bom.starts_with(b"<?xpacket begin=") {
      // `<?xpacket begin=` reached here with NO BOM stripped (`bom ==
      // DoubleBom::None`) is impossible — Tier 1's `^\s*` would have matched a
      // BOM-less `<?xpacket`. This arm therefore only fires for a BOM-less
      // `<?xpacket` that Tier 1 somehow missed (defensive); decode ordinarily.
      Some(DoubleBom::None)
    } else if after_bom.starts_with(b"<?xml") {
      // `<?xml`-rooted: XMP ONLY when the document also carries an
      // `<x(mp)?:x[ma]pmeta` (`$hasXMP`, XMP.pm:4366) or an `<rdf:RDF`
      // (`$isRDF`, XMP.pm:4385). Otherwise it is SVG / PLIST / bare-XML —
      // all deferred — so reject. Mirror `ProcessXMP`'s 256-byte recognition
      // read (`$raf->Read($buff,256)`, XMP.pm:4321): scan only the head.
      let head_len = after_bom.len().min(RECOGNITION_HEAD);
      let head = &after_bom[..head_len];
      (contains_sub(head, b"<rdf:RDF") || head_contains_xmpmeta(head)).then_some(DoubleBom::None)
    } else {
      // `<svg`-rooted, double-encoded-xpacket-with-leading-ws, or anything
      // else: not a FileType-`XMP` input — reject (faithful to
      // `ProcessXMP` `return 0`).
      None
    }
  };
  // `None` ⇒ not a FileType-`XMP` input (faithful to `ProcessXMP` `return 0`).
  let double = recognized?;

  // Decode the raw bytes to UTF-8 text. ProcessXMP handles UTF-16/UTF-32
  // (with or without BOM), double-UTF8 encoding (XMP.pm:4467-4498), and the
  // `pack('C0U*', unpack(...))` UTF-16/32 → UTF-8 transcode (XMP.pm:4571-4587).
  // A non-empty `double` BOM routes the double-encoded-UTF decode; otherwise we
  // strip a UTF-8/16/32 BOM and transcode 16/32 like the main encoding path.
  let (text, decode_warning) = match double {
    DoubleBom::None => decode_xmp_text(data),
    bom => decode_double_utf(data, bom),
  };

  let mut meta = XmpMeta::default();
  let mut walker = Walker::new(&text);
  walker.parse_element(0, text.len(), &mut Vec::new(), None, &BTreeMap::new());
  // Resolve any blank-node (rdf:nodeID) information collected during the
  // walk (ProcessBlankInfo, WriteXMP.pl:456) — done once at top level.
  walker.process_blank_info_root();
  // Rebuild structures from the flattened tags (RestoreStruct,
  // XMPStruct.pl:708) and emit into `meta`.
  walker.finish(&mut meta);
  // The `XMP is double UTF-encoded` warning is emitted DURING ProcessXMP setup
  // (XMP.pm:4491), BEFORE the element walk (XMP.pm:4600+). ExifTool keeps the
  // FIRST `FoundTag('Warning', …)`, so a decode warning precedes (and wins over)
  // any walk/RestoreStruct warning `finish` already recorded.
  if let Some(w) = decode_warning {
    meta.set_decode_warning(w);
  }
  Some(meta)
}

/// Which `$double` byte-order mark the recognition probe captured directly
/// before `<?xpacket begin=` (XMP.pm:4351). `None` means "no `$double` —
/// decode ordinarily". The variants name the BOM Perl assigns to `$double`:
/// because the recognition probe (`buf2`) has already dropped interior NULs, a
/// UTF-32 BOM also presents as its 2-byte UTF-16 form here, so only these three
/// reach the capture (matching Perl, where `$double` is taken from `buf2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoubleBom {
  /// No `$double` BOM — single-layer decode (`decode_xmp_text`).
  None,
  /// `\xef\xbb\xbf` — the UTF-8-BOM double path (XMP.pm:4476-4480).
  Utf8,
  /// `\xfe\xff` — UTF-16 BE double path, `$fmt = 'n'` (XMP.pm:4482-4486).
  Utf16Be,
  /// `\xff\xfe` — UTF-16 LE double path, `$fmt = 'v'` (XMP.pm:4482-4486).
  Utf16Le,
}

/// Decode the first layer of double-encoded UTF text — faithful port of the
/// `if ($double)` block (XMP.pm:4467-4498). The recognition probe matched a
/// byte-0 BOM directly before `<?xpacket begin=`, so the character data was
/// re-encoded in UTF: strip the leading BOM from the ORIGINAL data, re-pack as
/// characters, and look for warnings indicating a false assumption.
///
/// Returns the decoded (still-undecoded-second-layer) text for the walker plus
/// the optional warning. Two outcomes (XMP.pm:4489-4496):
///   * the re-pack succeeded (no Perl warning) → use the decoded bytes and emit
///     `XMP is double UTF-encoded`;
///   * the re-pack warned (e.g. malformed UTF-8) → keep the BOM-stripped
///     ORIGINAL and emit NO warning (the `Superfluous BOM` warning is
///     `unless $$dirInfo{RAF}`, and file/buffer input always has a RAF).
///
/// The decoded byte buffer is collapsed to a valid-UTF-8 `String` via
/// [`crate::convert::fix_utf8`] (Perl's downstream `Decode`/`FixUTF8`,
/// XMP.pm:3669 + the JSON-emitter `FixUTF8`): a re-packed byte that is not
/// valid UTF-8 (e.g. `é` → `0xE9`) becomes one `?`, exactly as the oracle.
fn decode_double_utf(data: &[u8], bom: DoubleBom) -> (String, Option<String>) {
  const DOUBLE_WARN: &str = "XMP is double UTF-encoded";
  // `$buff = substr($$dataPt, $dirStart + length $double)` — strip
  // `length($double)` bytes off the FRONT of the ORIGINAL data (XMP.pm:4470).
  // `$double` is the buf2-captured BOM, so its length is 3 (UTF-8) or 2
  // (UTF-16/32 — buf2 dropped the interior NULs, so even a 4-byte UTF-32 BOM
  // presents as 2 bytes here). ExifTool strips a FIXED byte count, NOT a
  // matched prefix: for the ordinary UTF-8/UTF-16 case `data` opens with the
  // BOM, so this removes exactly the BOM; for the (NUL-collapsed) UTF-32 case
  // it removes only the 2 captured bytes, leaving the residual `00 00`, exactly
  // as Perl's `substr`.
  let bom_len = match bom {
    DoubleBom::Utf8 => 3,
    DoubleBom::Utf16Be | DoubleBom::Utf16Le => 2,
    // Unreachable: callers route `DoubleBom::None` to `decode_xmp_text`.
    DoubleBom::None => return decode_xmp_text(data),
  };
  let stripped: &[u8] = data.get(bom_len..).unwrap_or(&[]);
  // Re-pack as characters (XMP.pm:4476-4488). `warned` mirrors
  // `Image::ExifTool::GetWarning()` after the re-pack.
  let (repacked, warned): (Vec<u8>, bool) = match bom {
    DoubleBom::Utf8 => {
      // `my $uni = Charset::Decompose(undef,$buff,'UTF8'); pack('C*',@$uni)`
      // (XMP.pm:4478-4480). `Decompose(_,_,'UTF8')` is `unpack('C0U*', $buff)`
      // (Charset.pm:165-181) — decode the BOM-stripped buffer as UTF-8 to a
      // list of code points, warning on malformed UTF-8 — then `pack('C*')`
      // truncates each code point to its low byte.
      let (uni, bad) = unpack_c0u(stripped);
      (uni.iter().map(|&cp| (cp & 0xff) as u8).collect(), bad)
    }
    DoubleBom::Utf16Be | DoubleBom::Utf16Le => {
      // `$buf2 = pack('C*', unpack("$fmt*", $buff))` with `$fmt` `n`/`v`
      // (XMP.pm:4483-4488). `unpack('n*'/'v*')` reads 16-bit units (BE/LE),
      // each `pack('C*')`-truncated to a byte; an odd trailing byte makes
      // `unpack` warn (and Perl drops it), so keep the original on a warning.
      let be = bom == DoubleBom::Utf16Be;
      let odd = !stripped.len().is_multiple_of(2);
      let units: Vec<u8> = stripped
        .chunks_exact(2)
        .map(|c| {
          let u = if be {
            u16::from_be_bytes([c[0], c[1]])
          } else {
            u16::from_le_bytes([c[0], c[1]])
          };
          (u & 0xff) as u8
        })
        .collect();
      (units, odd)
    }
    DoubleBom::None => unreachable!(),
  };
  if warned {
    // False assumption: the data was NOT double-encoded. Keep the BOM-stripped
    // ORIGINAL, no warning (RAF present) — XMP.pm:4491-4493.
    (bytes_to_walker_text(stripped), None)
  } else {
    // Use the decoded XMP and warn (XMP.pm:4494-4496).
    (
      bytes_to_walker_text(&repacked),
      Some(DOUBLE_WARN.to_string()),
    )
  }
}

/// `unpack('C0U*', $bytes)` — decode a byte slice as UTF-8 into a list of code
/// points (`u64` to hold the 6/7-byte extended forms up to `0xFFFF_FFFF`),
/// faithful to `Charset::Decompose(_,_,'UTF8')` (Charset.pm:165-181). Returns
/// the code points plus whether the decode hit malformed UTF-8 (Perl's captured
/// `Malformed UTF-8` warning).
///
/// Perl's `unpack('U')` is the inverse of `pack('C0U')` ([`crate::convert::pack_c0u`]):
/// it accepts RFC-2279-extended leaders up to the 13-byte `0xFF` form but
/// applies the per-length OVERLONG check (the decoded value must need that many
/// bytes). All behaviours verified vs bundled Perl 5.34 (`unpack('C0U*', …)` + a
/// `$SIG{__WARN__}` probe + a 400-vector differential), 2026-05-22:
///   * 2-byte leaders `0xC0`/`0xC1` are overlong → warn (but their continuation
///     is still CONSUMED: `C0 80` → one `[0]`, not two); `0xC2..` valid.
///   * `0xE0`/`0xF0`/… below their length minimum (`E0 80-9F`, `F0 80-8F`, …)
///     → warn (overlong); at/above the minimum → accepted.
///   * 5/6/7/13-byte forms (`0xF8..=0xFF`) ARE leaders: a complete non-overlong
///     one is accepted (`F8 88 80 80 80` → `0x200000`, `FE 82 …` →
///     `0x80000000`, a valid `FF …` 13-byte → up to i64::MAX); each consumes its
///     well-formed continuation run before any 0-substitution.
///   * NO surrogate/range checks: `ED A0 BD` → `U+D83D`, `F4 90 80 80`
///     (`> U+10FFFF`) → `0x110000`, both accepted.
///
/// A short or overlong sequence substitutes ONE code point `0` (consuming the
/// leader + the valid continuations seen, re-scanning after them); a stray
/// continuation byte substitutes `0` and advances one (`A\xffB` → `[65, 0, 66]`,
/// warning set).
fn unpack_c0u(bytes: &[u8]) -> (Vec<u64>, bool) {
  // (continuation count, minimum code point) per leader byte. `None` marks a
  // stray continuation byte (`0x80..=0xBF`). The overlong leaders `0xC0`/`0xC1`
  // ARE leaders so they consume their continuation run before the overlong
  // check substitutes a single 0. Each `min_cp` is the smallest value `pack_c0u`
  // encodes with that byte length (Perl-verified boundaries 2026-05-22): the
  // 13-byte `0xFF` form begins at `0x10_0000_0000` (`0xF_FFFF_FFFF` still uses
  // the 7-byte `0xFE` form). The mask `0x7F >> n.min(7)` is 0 for the 5..13-byte
  // leaders, matching `pack_c0u` (no payload bits in those leaders).
  fn leader(b: u8) -> Option<(usize, u64)> {
    match b {
      0xC0..=0xDF => Some((1, 0x80)),
      0xE0..=0xEF => Some((2, 0x800)),
      0xF0..=0xF7 => Some((3, 0x1_0000)),
      0xF8..=0xFB => Some((4, 0x20_0000)),
      0xFC..=0xFD => Some((5, 0x400_0000)),
      0xFE => Some((6, 0x8000_0000)),
      0xFF => Some((12, 0x10_0000_0000)),
      _ => None, // 0x80..=0xBF stray continuation
    }
  }
  let mut out: Vec<u64> = Vec::with_capacity(bytes.len());
  let mut bad = false;
  let mut i = 0;
  while i < bytes.len() {
    let b = bytes[i];
    if b < 0x80 {
      out.push(u64::from(b));
      i += 1;
      continue;
    }
    if let Some((n, min_cp)) = leader(b) {
      // Greedily consume up to `n` VALID continuation bytes (Perl consumes the
      // leader + the run of well-formed continuations that belong to this
      // sequence, then re-scans after them — e.g. `E0 A0 28` consumes `E0 A0`,
      // emits 0, resumes at `28`). `wrapping_shl` keeps the 13-byte (72-bit)
      // form panic-free in debug; the value is only ever used truncated to a
      // byte downstream (and only when the sequence is accepted).
      let mut cp = u64::from(b & (0x7F >> n.min(7)));
      let mut got = 0usize;
      while got < n {
        let Some(&c) = bytes.get(i + 1 + got) else {
          break;
        };
        if !(0x80..=0xBF).contains(&c) {
          break;
        }
        cp = cp.wrapping_shl(6) | u64::from(c & 0x3F);
        got += 1;
      }
      if got == n && cp >= min_cp {
        // Complete and non-overlong → accept (no surrogate/range check).
        out.push(cp);
        i += n + 1;
        continue;
      }
      // Incomplete (short) or overlong → one 0, consume leader + the valid
      // continuations actually seen (Perl re-scans after them).
      out.push(0);
      bad = true;
      i += 1 + got;
      continue;
    }
    // Stray continuation / `0xFF`: Perl substitutes 0 and advances one byte.
    out.push(0);
    bad = true;
    i += 1;
  }
  (out, bad)
}

/// Strip a leading UTF-8/16/32 byte-order mark, then transcode UTF-16/32 to a
/// valid-UTF-8 `String` for the walker. Faithful to the `$fmt` branch of
/// `ProcessXMP` (XMP.pm:4399-4420 BOM-less probe / 4516-4587 `pack('C0U*',
/// unpack("$fmt*",…))` transcode). UTF-16 BE/LE and UTF-32 BE/LE are recognized
/// by an explicit BOM or by the NUL-interleaving pattern.
///
/// Returns the decoded text plus the optional warning (none on this path —
/// ExifTool's only warning here, `Invalid XMP encoding marker` at XMP.pm:4567,
/// fires for a corrupt `<?xpacket` U+FEFF marker that the BOM/NUL-probe
/// recognition has already excluded for the inputs this port accepts).
fn decode_xmp_text(data: &[u8]) -> (String, Option<String>) {
  // Explicit BOMs.
  if let Some(rest) = data.strip_prefix(&[0xef, 0xbb, 0xbf]) {
    // UTF-8 with BOM: no transcode (`$fmt` is 0). Run the raw bytes through
    // FixUTF8 (Perl applies it per value at JSON time) so a malformed byte
    // becomes `?`, not the U+FFFD `from_utf8_lossy` would substitute.
    return (bytes_to_walker_text(rest), None);
  }
  if let Some(rest) = data.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
    return (decode_utf32(rest, true), None);
  }
  if let Some(rest) = data.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
    return (decode_utf32(rest, false), None);
  }
  if let Some(rest) = data.strip_prefix(&[0xfe, 0xff]) {
    return (decode_utf16(rest, true), None);
  }
  if let Some(rest) = data.strip_prefix(&[0xff, 0xfe]) {
    return (decode_utf16(rest, false), None);
  }
  // No BOM: probe for UTF-16/32 by NUL interleaving (XMP.pm:4399-4408).
  if data.len() >= 4 {
    if data[0] == 0 && data[1] == 0 && data[2] == 0 {
      return (decode_utf32(data, true), None); // UTF-32 BE
    }
    if data[1] == 0 && data[2] == 0 && data[3] == 0 {
      return (decode_utf32(data, false), None); // UTF-32 LE
    }
    if data[0] == 0 {
      return (decode_utf16(data, true), None); // UTF-16 BE
    }
    if data[1] == 0 {
      return (decode_utf16(data, false), None); // UTF-16 LE
    }
  }
  // Plain UTF-8 (no transcode, `$fmt` is 0). FixUTF8 the raw bytes (Perl runs
  // it per value at JSON time) — a malformed byte → `?`, NOT U+FFFD.
  (bytes_to_walker_text(data), None)
}

/// Collapse a byte buffer to a valid-UTF-8 `String` for the `&str` walker via
/// `Image::ExifTool::XMP::FixUTF8` (XMP.pm:2943-2972) — each malformed byte
/// becomes one ASCII `?`. ExifTool applies `FixUTF8` per extracted value at
/// JSON serialization; doing it once at the decode boundary is byte-equivalent
/// because (a) the structural XML is ASCII (unchanged), (b) `?` is ASCII so the
/// re-application in the value pipeline (`unescape_value_with_cdata`) is
/// idempotent, and (c) numeric character references stay ASCII here and are
/// expanded + `FixUTF8`-ed downstream exactly as before.
fn bytes_to_walker_text(bytes: &[u8]) -> String {
  crate::convert::fix_utf8(bytes)
}

/// Transcode a UTF-16 byte stream to a valid-UTF-8 `String`. Faithful to
/// `pack('C0U*', unpack('n*'/'v*', $$dataPt))` (XMP.pm:4571-4587): each 16-bit
/// unit is decoded INDEPENDENTLY (surrogate pairs are NOT combined) and emitted
/// via `pack('C0U')` ([`crate::convert::pack_c0u`]). A surrogate unit therefore
/// becomes the loose-UTF-8 bytes `ED A0/B…` that [`bytes_to_walker_text`]'s
/// `FixUTF8` maps to one `?` each, so a surrogate pair (`A😀B` → 2 units) →
/// `??????` (6 `?`), exactly as the oracle. An odd trailing byte is dropped
/// (Perl `unpack` discards the partial unit).
fn decode_utf16(bytes: &[u8], big_endian: bool) -> String {
  let mut buf: Vec<u8> = Vec::with_capacity(bytes.len());
  for c in bytes.chunks_exact(2) {
    let unit = if big_endian {
      u16::from_be_bytes([c[0], c[1]])
    } else {
      u16::from_le_bytes([c[0], c[1]])
    };
    crate::convert::pack_c0u(u64::from(unit), &mut buf);
  }
  bytes_to_walker_text(&buf)
}

/// Transcode a UTF-32 byte stream to a valid-UTF-8 `String`. Faithful to
/// `pack('C0U*', unpack('N*'/'V*', $$dataPt))` (XMP.pm:4571-4587): each 32-bit
/// unit is emitted via `pack('C0U')` ([`crate::convert::pack_c0u`]) — including
/// surrogate / out-of-range values, which produce loose-UTF-8 bytes that
/// [`bytes_to_walker_text`]'s `FixUTF8` maps to `?`. An incomplete trailing
/// unit (< 4 bytes) is dropped (Perl `unpack` discards it).
fn decode_utf32(bytes: &[u8], big_endian: bool) -> String {
  let mut buf: Vec<u8> = Vec::with_capacity(bytes.len());
  for c in bytes.chunks_exact(4) {
    let cp = if big_endian {
      u32::from_be_bytes([c[0], c[1], c[2], c[3]])
    } else {
      u32::from_le_bytes([c[0], c[1], c[2], c[3]])
    };
    crate::convert::pack_c0u(u64::from(cp), &mut buf);
  }
  bytes_to_walker_text(&buf)
}

/// Strip a leading byte-order mark from the NUL-stripped recognition probe,
/// reporting which BOM was consumed. The recognition regexes accept an OPTIONAL
/// BOM before the markup token (XMP.pm:4341-4350): a UTF-8 BOM (`\xef\xbb\xbf`)
/// or — because `buf2` has already dropped interior NULs — the bare two-byte
/// UTF-16/32 BOM (`\xfe\xff` / `\xff\xfe`). The reported [`DoubleBom`] lets the
/// caller route a byte-0-BOM `<?xpacket begin=` into the double-encoded-UTF
/// decode (XMP.pm:4351), while every other token decodes ordinarily.
fn strip_recognition_bom(s: &[u8]) -> (&[u8], DoubleBom) {
  if let Some(rest) = s.strip_prefix(&[0xef, 0xbb, 0xbf]) {
    return (rest, DoubleBom::Utf8);
  }
  if let Some(rest) = s.strip_prefix(&[0xfe, 0xff]) {
    return (rest, DoubleBom::Utf16Be);
  }
  if let Some(rest) = s.strip_prefix(&[0xff, 0xfe]) {
    return (rest, DoubleBom::Utf16Le);
  }
  (s, DoubleBom::None)
}

/// Remove ASCII whitespace from the start of a byte slice.
fn trim_ascii_start(s: &[u8]) -> &[u8] {
  let mut i = 0;
  while i < s.len() && s[i].is_ascii_whitespace() {
    i += 1;
  }
  &s[i..]
}

/// Strip leading `<!-- … -->` comments (XMP.pm:4324-4338 — "remove leading
/// comments if they exist (eg. ImageIngester)"). Operates on the NUL-stripped
/// probe buffer.
///
/// Faithful to the Perl loop:
/// ```text
/// while ($buf2 =~ /^\s*<!--/) {
///     if ($buf2 =~ s/^\s*<!--.*?-->\s+//s) { ... } else { ... }
///     ...
/// }
/// ```
/// Two faithfulness points that matter for recognition (Codex R9/F1):
///   1. The leading whitespace is consumed ONLY as part of a *successfully*
///      stripped comment (`s/^\s*<!--.*?-->\s+//s`). When the buffer does NOT
///      begin with a leading comment, the `while` body never runs, so the
///      leading whitespace is PRESERVED — and the byte-0-anchored Tier-2
///      recognition (`<?xml`/`<rdf:RDF`/BOM, XMP.pm:4345-4354) then correctly
///      rejects `   <rdf:RDF`/`   <?xml` (→ TXT). The old code trimmed the
///      whitespace unconditionally here, hiding the divergence.
///   2. The substitution requires `\s+` AFTER `-->`. A complete comment with
///      NO trailing whitespace (`<!--c--><rdf:RDF`) fails the `s///`, so the
///      buffer is left UNCHANGED with the `<!--` still at the front and
///      recognition fails (→ TXT, verified vs bundled 13.58).
///
/// The Perl `next if length $buf2 > 128` / 256-byte streaming re-read is a
/// stream artifact: for a fully-buffered input it only governs whether a
/// SECOND adjacent leading comment is also peeled. We approximate it with the
/// same `> 128` gate — re-loop to peel another comment only while more than
/// 128 bytes remain (matching a complete small file, which would hit EOF and
/// `last` otherwise). No bundled fixture stacks leading comments, so this is
/// belt-and-suspenders faithfulness.
fn strip_leading_comments(buf: &[u8]) -> &[u8] {
  let mut s = buf;
  loop {
    // `while ($buf2 =~ /^\s*<!--/)` — enter only on a (possibly
    // whitespace-led) leading comment; otherwise return UNCHANGED.
    let after_ws = trim_ascii_start(s);
    if !after_ws.starts_with(b"<!--") {
      return s;
    }
    // `s/^\s*<!--.*?-->\s+//s`: find the comment terminator …
    let Some(end) = find_sub(&after_ws[4..], b"-->") else {
      // Incomplete comment: Perl reads more, hits EOF, `last`s with the
      // buffer unchanged. Preserve `s` (still carries the `<!--`).
      return s;
    };
    let after_comment = &after_ws[4 + end + 3..];
    // … then `\s+` (≥1 whitespace) is REQUIRED after `-->`.
    let after_trailing = trim_ascii_start(after_comment);
    if after_trailing.len() == after_comment.len() {
      // No trailing whitespace ⇒ `s///` fails ⇒ Perl reads more, EOF,
      // `last`s with the buffer unchanged. Preserve `s`.
      return s;
    }
    // Successful strip: leading-ws + comment + trailing-ws are gone.
    s = after_trailing;
    // `next if length $buf2 > 128` — only re-loop to peel another comment
    // while >128 bytes remain (a small fully-read file hits EOF and stops).
    if s.len() <= 128 {
      return s;
    }
  }
}

/// The four spellings the XMP.pm regex `<x(mp)?:x[ma]pmeta` matches:
/// `x`/`xmp` prefix × `xmp`/`xap` (legacy) root.
const XMPMETA_TOKENS: [&[u8]; 4] = [
  b"<x:xmpmeta",
  b"<xmp:xmpmeta",
  b"<x:xapmeta",
  b"<xmp:xapmeta",
];

/// Length of the recognition head window — `ProcessXMP` reads 256 bytes for
/// file recognition (`$raf->Read($buff, 256)`, XMP.pm:4321). The `<?xml`
/// `<x(mp)?:x[ma]pmeta`/`<rdf:RDF` re-probe (XMP.pm:4366/4385) only sees
/// that head; a standalone XMP sidecar opens its root element well inside
/// it.
const RECOGNITION_HEAD: usize = 256;

/// `true` if the slice begins with `<x:xmpmeta` or `<xmp:xmpmeta` (the
/// MicrosoftPhoto mutant) or the `xapmeta` legacy spelling — XMP.pm regex
/// `<x(mp)?:x[ma]pmeta`.
fn starts_with_xmpmeta(s: &[u8]) -> bool {
  XMPMETA_TOKENS.iter().any(|pfx| s.starts_with(pfx))
}

/// `true` if `<x(mp)?:x[ma]pmeta` occurs ANYWHERE in `head` — the XMP.pm
/// `$buf2 =~ /<x(mp)?:x[ma]pmeta/` re-probe inside a `<?xml`-rooted document
/// (XMP.pm:4366).
fn head_contains_xmpmeta(head: &[u8]) -> bool {
  XMPMETA_TOKENS
    .iter()
    .any(|tok| find_sub(head, tok).is_some())
}

/// `true` if `needle` occurs anywhere in `haystack`.
fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
  find_sub(haystack, needle).is_some()
}

/// Find the first occurrence of `needle` in `haystack`, returning its start
/// index.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

// ===========================================================================
// ParseXMPElement — the recursive walker (XMP.pm:3768)
// ===========================================================================

/// One flattened tag captured by `FoundXMP`. Carries the full property path
/// (used by `RestoreStruct`) and the structure-property descriptor.
struct FlatTag {
  /// Tag id (`"<ns>:<Tag>"` for variable-namespace tables, else `<Tag>`).
  /// Retained from `GetXMPTagID` for the variable-namespace-table lookup
  /// path (a Phase-2 forward item — the converter-free namespaces ported
  /// today key off `struct_props`); see `tables.rs` module docs.
  #[allow(dead_code)]
  tag_id: SmolStr,
  /// Family-1 group (`"XMP-<ns>"`).
  group1: SmolStr,
  /// The final emitted tag name (after Name remaps).
  name: SmolStr,
  /// Decoded scalar value (already un-escaped + XMPAutoConv-converted +
  /// PrintConv/ValueConv-applied where the namespace table supplies one).
  value: XmpValue,
  /// Structure-property descriptor from `GetXMPTagID` (XMP.pm:3018) — the
  /// per-level `[name, index?]` list driving `RestoreStruct`. Empty for a
  /// plain top-level tag.
  struct_props: Vec<StructProp>,
  /// `xml:lang` language code (already `StandardLangCase`-normalized, never
  /// `x-default`), if this is a non-default lang-alt entry. The code is also
  /// baked into `name` as the `<Name>-<lang>` suffix by `found_xmp_full`, so
  /// `RestoreStruct` keys off `name` alone; this field is retained for the
  /// lang-alt list-rebuild forward item (`tables.rs` module docs).
  #[allow(dead_code)]
  lang: Option<String>,
}

/// One level of a structure property path (`GetXMPTagID`'s `structProps`).
#[derive(Debug, Clone)]
struct StructProp {
  /// Field name at this level.
  name: SmolStr,
  /// `rdf:li` list index at this level (the zero-padded ExifTool index, see
  /// the `rdf:li` handling in `parse_element`), if this level is a list.
  index: Option<String>,
}

/// Blank-node (rdf:nodeID) resource information (`%blankInfo`, WriteXMP.pl).
#[derive(Default)]
struct BlankInfo {
  /// nodeID → (pre-paths, post-(path-suffix → (val, propPath))).
  prop: BTreeMap<String, BlankNode>,
}

#[derive(Default)]
struct BlankNode {
  /// Distinct path prefixes that reference this node as a subject.
  pre: BTreeMap<String, ()>,
  /// Distinct path suffixes → (value, full-prop-path).
  post: BTreeMap<String, (String, Vec<SmolStr>)>,
}

/// The XMP element walker state — the `$$et` fields `ParseXMPElement` reads.
struct Walker<'a> {
  /// Whole transcoded UTF-8 document.
  data: &'a str,
  /// Captured flattened tags, in `FoundXMP` call order.
  flat: Vec<FlatTag>,
  /// `$$et{curURI}` — namespace URI → prefix used in THIS file (the unique
  /// prefix assigned the first time the URI is seen). XMP.pm:3941-3956.
  cur_uri: BTreeMap<String, String>,
  /// `$$et{curNS}` — prefix → URI for the prefixes assigned above.
  cur_ns: BTreeMap<String, String>,
  /// `$$et{XmpAbout}` — first `rdf:about` value seen (XMP.pm:4087).
  xmp_about: Option<String>,
  /// Blank-node info collected during the walk; resolved at top level.
  blank_info: BlankInfo,
  /// First warning recorded DURING the element walk (`$et->Warn`,
  /// ExifTool.pm:1297) — currently the `rdf:li` 1000-item cap warning
  /// (XMP.pm:3997). A walk-time warning precedes any `RestoreStruct`
  /// warning in ExifTool's `FoundTag('Warning', …)` order, so `finish`
  /// gives it priority over the post-walk struct-rebuild warning.
  warning: Option<String>,
  /// `OverrideFileType('NXD','application/x-nikon-nxd')` latch (XMP.pm:3916).
  /// Set the first time an `xmlns` declaration's URI begins
  /// `http://ns.nikon.com/BASIC_PARAM` (a Nikon NX-D settings sidecar),
  /// carried to [`XmpMeta`] so the engine finalizes `File:FileType=NXD`
  /// + `File:MIMEType=application/x-nikon-nxd` instead of generic `XMP`.
  nikon_nxd: bool,
}

impl<'a> Walker<'a> {
  fn new(data: &'a str) -> Self {
    Self {
      data,
      flat: Vec::new(),
      cur_uri: BTreeMap::new(),
      cur_ns: BTreeMap::new(),
      xmp_about: None,
      blank_info: BlankInfo::default(),
      warning: None,
      nikon_nxd: false,
    }
  }

  /// Record a `Warning` raised during the walk, keeping only the FIRST
  /// (`$self->Warn` adds each warning once, ExifTool.pm:1297).
  fn warn(&mut self, msg: String) {
    if self.warning.is_none() {
      self.warning = Some(msg);
    }
  }

  /// Resolve blank-node info at the top level (`ProcessBlankInfo`,
  /// WriteXMP.pl:456) — called once after the whole document is walked.
  fn process_blank_info_root(&mut self) {
    let blank = core::mem::take(&mut self.blank_info);
    if blank.prop.is_empty() {
      return;
    }
    process_blank_info(self, &blank);
  }

  /// Rebuild structures and emit into `meta` (`RestoreStruct`,
  /// XMPStruct.pl:708 + the post-loop emission).
  fn finish(self, meta: &mut XmpMeta<'_>) {
    let (tags, struct_warning) = restore_struct(self.flat);
    meta.tags = tags;
    // ExifTool emits warnings in `FoundTag('Warning', …)` order and keeps
    // the first; a walk-time `Warn` (the `rdf:li` 1000-item cap) precedes
    // any `RestoreStruct` warning, so the walk warning wins.
    meta.warning = self.warning.or(struct_warning);
    // Carry the `OverrideFileType('NXD',…)` latch (XMP.pm:3916) to the Meta.
    meta.nikon_nxd = self.nikon_nxd;
  }
}

// ===========================================================================
// The element scanner — ParseXMPElement (XMP.pm:3768-4255)
// ===========================================================================

/// One scanned element header: tag name, raw attribute text, and the byte
/// range of its content (between the open and close tags).
struct ScannedElement {
  /// Element name (e.g. `"rdf:Description"`, `"dc:title"`).
  prop: String,
  /// Raw attribute text (everything after the name, before `>`), with a
  /// trailing `/` of an empty element already stripped.
  attrs: String,
  /// Content start byte offset.
  val_start: usize,
  /// Content end byte offset (== `val_start` for an empty element).
  val_end: usize,
  /// Byte offset just past this element's close tag — where the next
  /// sibling scan resumes.
  next: usize,
  /// `true` if a `<!-- … -->` comment was found inside the content (so
  /// `FoundXMP` strips comments from the literal value).
  was_comment: bool,
}

impl Walker<'_> {
  /// Faithful port of the `ParseXMPElement` element loop (XMP.pm:3800-4250):
  /// scan sibling elements in `[start, end)`, resolve namespaces, descend.
  /// `prop_list` is the enclosing property-name stack; `node_id` is the
  /// inherited `rdf:nodeID` (reset per element); `xlat_ns` is the inherited
  /// file-prefix → ExifTool-canonical-prefix map (XMP.pm:3796 `$xlatNS`),
  /// threaded down the recursion so an `xmlns:` declared on an ancestor
  /// element tames the prefix of every descendant.
  ///
  /// Returns the number of elements found at this level (the Perl `$count`).
  fn parse_element(
    &mut self,
    start: usize,
    end: usize,
    prop_list: &mut Vec<SmolStr>,
    node_id: Option<&str>,
    xlat_ns: &BTreeMap<String, String>,
  ) -> usize {
    let bytes = self.data.as_bytes();
    let mut pos = start;
    let mut count = 0usize;
    let mut n_items = 0usize; // rdf:li counter at this level

    loop {
      // "all done if there isn't enough data" (XMP.pm:3802).
      if pos + 4 > end {
        break;
      }
      // Find the next `<…>` token (XMP.pm:3806). We scan for `<`.
      let Some(rel_lt) = bytes[pos..end].iter().position(|&b| b == b'<') else {
        break;
      };
      let lt = pos + rel_lt;
      // Scan the token. A token is `<[?/]?name attrs>` or `<!--` or
      // `<![CDATA[`.
      let Some(tok) = scan_token(bytes, lt, end) else {
        break;
      };
      match tok {
        Token::Closing(close_end) => {
          // `<?…>` or `</…>` — stop scanning at this level (XMP.pm:3809
          // `next if $1` actually skips, but a stray closing token at this
          // level means the parent is done; we advance past it and keep
          // scanning so a `</rdf:Description>` between siblings doesn't
          // terminate the whole document — faithful to Perl which `next`s).
          pos = close_end;
          continue;
        }
        Token::Comment(comment_end) => {
          // Skip the comment (XMP.pm:3819-3823).
          pos = comment_end;
          continue;
        }
        Token::Cdata(cdata_end) => {
          // Stray top-level CDATA — skip (XMP.pm:3812-3816).
          pos = cdata_end;
          continue;
        }
        Token::Element {
          name_start,
          name_end,
          attrs_start,
          tag_end,
          empty,
        } => {
          let prop_raw = self.data[name_start..name_end].to_string();
          let attrs_raw = self.data[attrs_start..tag_end].to_string();
          let mut element = if empty {
            ScannedElement {
              prop: prop_raw,
              attrs: attrs_raw,
              val_start: tag_end + 2, // past `/>`
              val_end: tag_end + 2,
              next: tag_end + 2,
              was_comment: false,
            }
          } else {
            // Non-empty: find the matching close tag, honoring nesting.
            let content_start = tag_end + 1; // past `>`
            let Some((val_end, next, was_comment)) =
              find_close(bytes, &prop_raw, content_start, end)
            else {
              // "no closing tag" — XMP.pm:3838 warns and `last`s.
              break;
            };
            ScannedElement {
              prop: prop_raw,
              attrs: attrs_raw,
              val_start: content_start,
              val_end,
              next,
              was_comment,
            }
          };
          let outcome =
            self.handle_element(&mut element, prop_list, node_id, &mut n_items, xlat_ns);
          // The `rdf:li` 1000-item cap fires `last` (XMP.pm:3998) BEFORE the
          // element is processed and BEFORE `++$count` (XMP.pm:4222): the
          // 1001st item is neither extracted nor counted — stop here.
          if outcome == ElementOutcome::StopBeforeProcessing {
            break;
          }
          count += 1;
          pos = element.next;
          // Skip whitespace after the close token (XMP.pm:4243).
          while pos < end && bytes[pos].is_ascii_whitespace() {
            pos += 1;
          }
        }
      }
    }
    count
  }

  /// Process one scanned element — the body of the `ParseXMPElement` loop
  /// after the element header is read (XMP.pm:4030-4242). `inherited_xlat`
  /// is the ancestor-scope file-prefix → canonical-prefix map.
  ///
  /// Returns [`ElementOutcome::StopBeforeProcessing`] when the `rdf:li`
  /// 1000-item cap fires (XMP.pm:3992-3998 `last`): the element is neither
  /// extracted nor counted and the caller must stop scanning this level.
  fn handle_element(
    &mut self,
    element: &mut ScannedElement,
    prop_list: &mut Vec<SmolStr>,
    node_id: Option<&str>,
    n_items: &mut usize,
    inherited_xlat: &BTreeMap<String, String>,
  ) -> ElementOutcome {
    // ---- Parse attributes + resolve namespace prefixes ------------------
    // `xlat_ns` maps a file prefix → ExifTool canonical prefix (XMP.pm:3796
    // `$xlatNS`). It starts from the inherited ancestor-scope map and is
    // extended by the `xmlns:` declarations on THIS element (an inner
    // `xmlns:` shadowing an outer one wins — the `extend` below overwrites).
    let parsed = self.parse_attrs(&element.attrs, inherited_xlat);
    let mut xlat_ns = inherited_xlat.clone();
    xlat_ns.extend(parsed.xlat_ns);

    // Translate the element's own prefix (XMP.pm:3987-3991).
    let mut prop = element.prop.clone();
    if let Some((ns, rest)) = split_prefix(&prop)
      && let Some(new_ns) = xlat_ns.get(ns)
    {
      prop = std::format!("{new_ns}{rest}");
    }

    // ---- Special element handling (XMP.pm:3992-4024) --------------------
    let mut parse_resource = false;
    let mut this_node_id: Option<String> = node_id.map(ToString::to_string);

    if prop == "rdf:li" {
      // Impose a reasonable maximum on the number of items in a list
      // (XMP.pm:3991-3999). At the 1001st item (`$nItems == 1000`),
      // ExifTool's default read path — no `IgnoreMinorErrors` — raises a
      // minor warning and `last`s out of the element loop, so only the
      // first 1000 items are extracted. (`exifast` has no
      // `IgnoreMinorErrors` option — see `value.rs` — so it always runs
      // this default-stop branch; the `isWriting` "Processing may be slow"
      // branch is write-only and out of scope.) `GetXMPTagID(propList)`
      // names the list — `$ns:$tg`, the namespace and *raw* tag id of the
      // enclosing path BEFORE this `rdf:li` is pushed (XMP.pm:3992-3994).
      // `Warn(..., 2)` prepends the literal `[Minor] ` marker
      // (ExifTool.pm:5619 `$str = "[Minor] $str"`).
      if *n_items == 1000 {
        let id = get_xmp_tag_id(prop_list);
        self.warn(std::format!(
          "[Minor] Extracted only 1000 {}:{} items. Ignore minor errors to extract all",
          id.namespace,
          id.tag,
        ));
        return ElementOutcome::StopBeforeProcessing;
      }
      // Indexed list item (XMP.pm:4001-4015). Append the ExifTool index.
      // The index is the digit-count prefix + the number, so alphabetic
      // sort gives numeric order.
      let idx = std::format!("{}{}", num_digits(*n_items), *n_items);
      prop = std::format!("rdf:li {idx}");
      *n_items += 1;
    } else if prop == "rdf:Description" {
      // A nested rdf:Description == a structure (XMP.pm:4016-4023).
      if prop_list.iter().any(|p| p == "rdf:Description") {
        parse_resource = true;
      }
    } else if prop == "xmp:xmpmeta" {
      // MicrosoftPhoto mutant (XMP.pm:4024-4027).
      prop = "x:xmpmeta".to_string();
    }

    // ---- rdf:parseType="Resource" → structure (XMP.pm:4060) -------------
    let mut parse_type_resource = parsed
      .attrs
      .iter()
      .any(|(k, v)| k == "rdf:parseType" && v == "Resource");
    if parse_resource {
      // rdf:Description nested → set parseType=Resource implicitly.
      parse_type_resource = true;
    }

    // ---- rdf:nodeID (XMP.pm:4042-4048) ----------------------------------
    if let Some((_, nid)) = parsed.attrs.iter().find(|(k, _)| k == "rdf:nodeID") {
      this_node_id = Some(nid.clone());
      prop = std::format!("{prop} #{nid}");
      parse_resource = false; // "can't ignore if this is a node"
    }

    // ---- Push the property name (XMP.pm:4051) ---------------------------
    if !parse_resource {
      prop_list.push(SmolStr::new(&prop));
    }

    // ---- Shorthand attribute properties (XMP.pm:4072-4148) --------------
    // Attributes of the form `a:b='c'` are themselves XMP properties.
    //
    // Perl `delete $attrs{$shortName}` (XMP.pm:4133) removes a NON-ignored
    // shorthand attribute from `%attrs` once it has been extracted as its
    // own property, so the later `FoundXMP(..., \%attrs)` call (XMP.pm:4206)
    // no longer sees it. We mirror that by recording which attr indices were
    // consumed; `deleted[i]` ⇒ attr `i` is gone from Perl's surviving hash.
    let mut shorthand = false;
    let mut deleted = std::vec![false; parsed.attrs.len()];
    for (attr_idx, (attr_name, attr_val)) in parsed.attrs.iter().enumerate() {
      // Resolve the attribute's namespace.
      let (ns, name, full_name) = resolve_attr_name(attr_name, &prop, &xlat_ns);
      // rdf:about handling (XMP.pm:4083-4096).
      if full_name == "rdf:about" && self.xmp_about.is_none() {
        self.xmp_about = Some(attr_val.clone());
      }
      // Recognized attributes that become tags: x:xmptk → XMPToolkit
      // (XMP.pm:%recognizedAttrs). `rdf:about` is in `rdf` table.
      if let Some((rec_group, rec_name)) = recognized_attr(&full_name) {
        if !attr_val.is_empty() {
          let unescaped = unescape_xml(attr_val);
          self.found_recognized(rec_group, rec_name, &unescaped);
        }
        continue;
      }
      // Skip ignored namespaces / et-properties (XMP.pm:4126).
      if is_ignored_namespace(&ns) || is_ignore_et_prop(&full_name) {
        continue;
      }
      // xmlns: declarations are handled by the namespace logic, not tags.
      if ns == "xmlns" {
        continue;
      }
      // rdf:parseType / rdf:nodeID / rdf:datatype etc. are recognized
      // structural attrs, not tags (XMP.pm:%recognizedAttrs `=> 1`).
      if is_structural_attr(&full_name) {
        continue;
      }
      // This shorthand attribute is a property: delete (XMP.pm:4133 —
      // "don't re-use this attribute"), push, found, pop.
      deleted[attr_idx] = true;
      prop_list.push(SmolStr::new(&full_name));
      if this_node_id.is_some() {
        // Shorthand attr inside a blank node — save to blankInfo.
        save_blank_info(&mut self.blank_info, prop_list, attr_val, None);
      } else {
        self.found_xmp(prop_list, attr_val, None);
      }
      prop_list.pop();
      shorthand = true;
      let _ = (name, &mut xlat_ns); // (name unused beyond resolution)
    }

    // ---- Descend or capture the literal value (XMP.pm:4150-4218) --------
    let content = &self.data[element.val_start..element.val_end];
    let descended = if element.val_start == element.val_end {
      false
    } else {
      // Recurse for nested elements, threading the merged `xlat_ns` so
      // descendants inherit this element's `xmlns:` declarations.
      let found = self.parse_element(
        element.val_start,
        element.val_end,
        prop_list,
        this_node_id.as_deref(),
        &xlat_ns,
      );
      found > 0
    };

    if !descended {
      // No nested elements → this is a simple property value.
      let mut val = content.to_string();
      // rdf:Description: strip comments + trim (XMP.pm:4198-4200).
      if prop == "rdf:Description" {
        val = strip_comments_and_trim(&val);
      } else if element.was_comment {
        val = strip_comments(&val);
      }
      // Empty value → fall back to rdf:value/resource/about attr
      // (XMP.pm:4203-4208).
      let mut was_empty = false;
      if val.is_empty() {
        if let Some(v) = rdf_raw_attr(&element.attrs, &["value", "resource"]) {
          val = v;
          was_empty = true;
        } else if let Some(v) = rdf_raw_attr(&element.attrs, &["about"]) {
          val = v;
          was_empty = true;
        }
      }
      // Emit unless we already took shorthand values and the literal is
      // empty (XMP.pm:4211).
      if !val.is_empty() || !shorthand {
        let last_prop = prop_list.last().map(SmolStr::as_str).unwrap_or("");
        if this_node_id.is_some() {
          save_blank_info(&mut self.blank_info, prop_list, &val, None);
        } else if last_prop == "rdf:type" && was_empty {
          // "do not extract empty structure types" (XMP.pm:4214).
        } else {
          // rdf:datatype="…base64…" → decode (XMP.pm:3644), and xml:lang
          // (XMP.pm:3497). Both are read by `FoundXMP` from the `%attrs`
          // HASH, whose keys are namespace-NORMALIZED by the attribute loop
          // (XMP.pm:3976 `$attr = $$xlatNS{$1} . substr(...)`). So a
          // noncanonical RDF prefix — `xmlns:r="…22-rdf-syntax-ns#"` with
          // `r:datatype="base64"` — is still recognized. Drive these lookups
          // from `parsed.attrs` (already prefix-translated), NOT the raw
          // attribute text. (The `rdf:value`/`resource`/`about` fallback at
          // XMP.pm:4186 deliberately matches the RAW `$attrs` string with a
          // literal `\brdf:` — so it stays raw above.)
          //
          // CRUCIAL: only attrs that SURVIVED the shorthand loop's
          // `delete $attrs{$shortName}` (XMP.pm:4133) are still in Perl's
          // `%attrs` for the `FoundXMP` call. `rdf:datatype` is caught by
          // `$ignoreNamespace{rdf}` (XMP.pm:4123) and never deleted, but
          // `et:encoding` (ns `et`, not ignored, not recognized) IS deleted
          // and extracted as its own tag — so it must NOT drive the parent
          // decode here.
          let surviving: std::vec::Vec<(String, String)> = parsed
            .attrs
            .iter()
            .enumerate()
            .filter(|(i, _)| !deleted[*i])
            .map(|(_, kv)| kv.clone())
            .collect();
          let datatype = attr_value_pairs(&surviving, &["rdf:datatype", "et:encoding"]);
          let lang = attr_value_pairs(&surviving, &["xml:lang"]);
          self.found_xmp_full(prop_list, &val, lang.as_deref(), datatype.as_deref());
        }
      }
    }

    // ---- Pop the property name (XMP.pm:4221) ----------------------------
    if !parse_resource {
      prop_list.pop();
    }
    let _ = parse_type_resource; // captured for empty-struct detection below
    ElementOutcome::Processed
  }
}

/// Result of [`Walker::handle_element`] — whether the `ParseXMPElement`
/// sibling loop should keep scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElementOutcome {
  /// The element was processed normally; continue scanning siblings.
  Processed,
  /// The `rdf:li` 1000-item cap fired (XMP.pm:3992-3998 `last`): the element
  /// was neither extracted nor counted — stop scanning this level.
  StopBeforeProcessing,
}

// ===========================================================================
// Low-level token scanner — the `<…>` regex of XMP.pm:3806/3829
// ===========================================================================

/// A scanned `<…>` token.
enum Token {
  /// `<?…>` or `</…>` — a processing-instruction / closing token. Carries
  /// the byte offset just past `>`.
  Closing(usize),
  /// `<!-- … -->` — carries the byte offset just past `-->`.
  Comment(usize),
  /// `<![CDATA[ … ]]>` — carries the byte offset just past `]]>`.
  Cdata(usize),
  /// `<name attrs>` or `<name attrs/>`.
  Element {
    name_start: usize,
    name_end: usize,
    attrs_start: usize,
    /// Byte offset of the `>` (for empty elements the `/` is just before).
    tag_end: usize,
    empty: bool,
  },
}

/// Scan a `<…>` token starting at `lt` (which must be `<`). Returns `None`
/// on malformed input. Faithful to the XMP.pm:3806 regex
/// `<([?/]?)([-\w:.\x80-\xff]+|!--)([^>]*)>|(<!\[CDATA\[)`.
fn scan_token(bytes: &[u8], lt: usize, end: usize) -> Option<Token> {
  debug_assert_eq!(bytes[lt], b'<');
  let after = lt + 1;
  if after >= end {
    return None;
  }
  // CDATA.
  if bytes[after..end].starts_with(b"![CDATA[") {
    let body = after + 8;
    let close = find_sub(&bytes[body..end], b"]]>")?;
    return Some(Token::Cdata(body + close + 3));
  }
  // Comment.
  if bytes[after..end].starts_with(b"!--") {
    let body = after + 3;
    let close = find_sub(&bytes[body..end], b"-->")?;
    return Some(Token::Comment(body + close + 3));
  }
  // Processing instruction / closing tag.
  if bytes[after] == b'?' || bytes[after] == b'/' {
    let close = bytes[after..end].iter().position(|&b| b == b'>')?;
    return Some(Token::Closing(after + close + 1));
  }
  // A name char per XMP.pm: `[-\w:.\x80-\xff]`.
  let name_start = after;
  let mut i = after;
  while i < end && is_name_char(bytes[i]) {
    i += 1;
  }
  if i == name_start {
    return None; // not a real element token
  }
  let name_end = i;
  // Attributes run until `>` (XMP.pm `[^>]*`).
  let attrs_start = i;
  let gt = bytes[i..end].iter().position(|&b| b == b'>')?;
  let tag_end = i + gt;
  // Empty element if the char before `>` is `/`.
  let empty = tag_end > attrs_start && bytes[tag_end - 1] == b'/';
  Some(Token::Element {
    name_start,
    name_end,
    attrs_start,
    // For an empty element, the attrs text excludes the trailing `/`; the
    // caller slices `[attrs_start..tag_end]` and we strip the `/` there.
    tag_end: if empty { tag_end - 1 } else { tag_end },
    empty,
  })
}

/// `true` for the XMP element-name character class `[-\w:.\x80-\xff]`.
fn is_name_char(b: u8) -> bool {
  b == b'-' || b == b'_' || b == b':' || b == b'.' || b.is_ascii_alphanumeric() || b >= 0x80
}

/// Find the close tag of a non-empty element, honoring same-name nesting.
/// Faithful to the XMP.pm:3829-3863 nesting loop. Returns
/// `(content_end, next_pos, was_comment)`.
fn find_close(
  bytes: &[u8],
  prop: &str,
  content_start: usize,
  end: usize,
) -> Option<(usize, usize, bool)> {
  let prop_bytes = prop.as_bytes();
  let mut pos = content_start;
  let mut nesting = 1i32;
  let mut was_comment = false;
  loop {
    // Find the next `<` that begins a relevant token.
    let rel = bytes[pos..end].iter().position(|&b| b == b'<')?;
    let lt = pos + rel;
    let after = lt + 1;
    if after >= end {
      return None;
    }
    // CDATA / comment inside content — skip.
    if bytes[after..end].starts_with(b"![CDATA[") {
      let body = after + 8;
      let close = find_sub(&bytes[body..end], b"]]>")?;
      pos = body + close + 3;
      continue;
    }
    if bytes[after..end].starts_with(b"!--") {
      let body = after + 3;
      let close = find_sub(&bytes[body..end], b"-->")?;
      pos = body + close + 3;
      was_comment = true;
      continue;
    }
    // Closing tag `</prop…>`?
    if bytes[after] == b'/' && bytes[after + 1..end].starts_with(prop_bytes) {
      // The name must be followed by a name-extension char OR `>` —
      // XMP.pm matches `\Q$prop\E([-\w:.\x80-\xff]*)`.
      let name_after = after + 1 + prop_bytes.len();
      // Find `>`.
      let gt_rel = bytes[name_after..end].iter().position(|&b| b == b'>')?;
      let gt = name_after + gt_rel;
      // Verify the chars between name and `>` are name-ext chars / ws.
      nesting -= 1;
      if nesting == 0 {
        return Some((lt, gt + 1, was_comment));
      }
      pos = gt + 1;
      continue;
    }
    // Opening tag `<prop…>`?
    if is_name_char(bytes[after]) && bytes[after..end].starts_with(prop_bytes) {
      // Find `>` and check for an empty-element `/>`.
      let gt_rel = bytes[after..end].iter().position(|&b| b == b'>')?;
      let gt = after + gt_rel;
      let is_empty = gt > after && bytes[gt - 1] == b'/';
      if !is_empty {
        nesting += 1;
      }
      pos = gt + 1;
      continue;
    }
    // Some other tag — skip past its `>`.
    let gt_rel = bytes[lt..end].iter().position(|&b| b == b'>')?;
    pos = lt + gt_rel + 1;
  }
}

/// Number of decimal digits in `n` (the rdf:li index-length prefix,
/// XMP.pm:4006 `length($nItems)`).
fn num_digits(n: usize) -> usize {
  if n == 0 {
    return 1;
  }
  let mut d = 0;
  let mut v = n;
  while v > 0 {
    d += 1;
    v /= 10;
  }
  d
}

// ===========================================================================
// Attribute parsing + namespace resolution (XMP.pm:3877-3984)
// ===========================================================================

/// Result of parsing one element's attribute text.
struct ParsedAttrs {
  /// `(name, value)` pairs in document order, AFTER prefix translation
  /// (XMP.pm `@attrs` / `%attrs`). Namespace prefixes have been mapped to
  /// ExifTool canonical prefixes for this scope.
  attrs: Vec<(String, String)>,
  /// File-prefix → ExifTool-canonical-prefix map for THIS element's scope
  /// (the `$xlatNS` translation, XMP.pm:3962-3974).
  xlat_ns: BTreeMap<String, String>,
}

impl Walker<'_> {
  /// Parse + namespace-resolve an element's attribute text. Faithful port of
  /// the `for (;;)` attribute loop in `ParseXMPElement` (XMP.pm:3877-3984).
  ///
  /// `inherited_xlat` is the ancestor-scope `$xlatNS` map. The Perl loop
  /// translates non-`xmlns:` attribute prefixes with `$$xlatNS{$1}`
  /// (XMP.pm:3976) where `$xlatNS` is the RUNNING merged map — it already
  /// holds every inherited translation when the loop starts. So an attribute
  /// like `r:datatype` whose `xmlns:r` was declared on an ANCESTOR element is
  /// still translated to `rdf:datatype`. The returned `ParsedAttrs::xlat_ns`
  /// remains only THIS element's freshly declared translations (the caller
  /// merges it over the inherited map for descendants).
  fn parse_attrs(
    &mut self,
    attrs_text: &str,
    inherited_xlat: &BTreeMap<String, String>,
  ) -> ParsedAttrs {
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut xlat_ns: BTreeMap<String, String> = BTreeMap::new();
    // `merged` is the running `$xlatNS`: inherited translations plus the
    // `xmlns:` declarations encountered so far in this element's attr loop.
    let mut merged = inherited_xlat.clone();
    for (raw_attr, raw_val) in iter_attrs(attrs_text) {
      let mut attr = raw_attr;
      let mut val = raw_val;
      // Namespace handling (XMP.pm:3897-3982).
      if let Some((pfx, _)) = split_prefix(&attr) {
        if pfx == "xmlns" {
          // xmlns:NS='URI' — register / tame the prefix.
          let ns = attr["xmlns:".len()..].to_string();
          let new_ns = self.register_namespace(&ns, &mut val, &mut attrs);
          match new_ns {
            Some(new) if !new.is_empty() => {
              xlat_ns.insert(ns.clone(), new.clone());
              merged.insert(ns.clone(), new.clone());
              attr = std::format!("xmlns:{new}");
            }
            // `register_namespace` returned `None` (or an empty string):
            // this `xmlns:` re-declares `ns` to a URI for which `ns` IS the
            // canonical ExifTool prefix. An IDENTITY entry is recorded so
            // that — when this scope's `xlat_ns` is merged over an inherited
            // map — any inherited translation of `ns` (e.g. an outer
            // `xmlns:xmp='adobe:ns:meta/'` that mapped `xmp` → `x`) is
            // SHADOWED back to the un-translated prefix. Without the
            // identity entry the inherited translation would leak into a
            // descendant whose scope legitimately redefined the prefix
            // (XMP6 fixture: `xmp` reused for `adobe:ns:meta/` then
            // `http://ns.adobe.com/xap/1.0/`).
            _ => {
              xlat_ns.insert(ns.clone(), ns.clone());
              // Perl's `delete $$xlatNS{$ns}` (XMP.pm:3980): drop any
              // inherited translation from the running merged map so a later
              // attribute in this scope reverts to the un-translated prefix.
              merged.remove(&ns);
            }
          }
        } else if let Some(canon) = merged.get(pfx) {
          // Translate this attribute's namespace prefix against the running
          // merged map (XMP.pm:3976 `$attr = $$xlatNS{$1} . substr(...)`).
          // `merged` already carries every inherited translation, so a prefix
          // declared on an ANCESTOR element (e.g. a noncanonical `r:` for the
          // RDF namespace, used here as `r:datatype`) is resolved too.
          if canon != pfx {
            attr = std::format!("{canon}{}", &attr[pfx.len()..]);
          }
        }
      }
      attrs.push((attr, val));
    }
    ParsedAttrs { attrs, xlat_ns }
  }

  /// Register an `xmlns:NS='URI'` declaration. Faithful port of the
  /// namespace-taming block (XMP.pm:3902-3982). Returns `Some(new_prefix)`
  /// if the file's prefix `ns` must be translated (`""` = "redefined to
  /// the standard prefix"), or `None` if no translation is needed.
  fn register_namespace(
    &mut self,
    ns: &str,
    val: &mut String,
    attrs: &mut [(String, String)],
  ) -> Option<String> {
    // Look the URI up in the reverse map (XMP.pm:3905).
    let mut std_ns = uri_to_ns(val).map(ToString::to_string);
    if std_ns.is_none() {
      // Patch for a trailing-slash URI bug (XMP.pm:3909-3913).
      let try_uri = if val.ends_with('/') {
        val.trim_end_matches('/').to_string()
      } else {
        std::format!("{val}/")
      };
      if let Some(s) = uri_to_ns(&try_uri) {
        *val = try_uri;
        std_ns = Some(s.to_string());
      } else if val.starts_with("http://ns.nikon.com/BASIC_PARAM") {
        // Nikon NX-D settings sidecar (XMP.pm:3915-3916):
        // `} elsif ($val =~ m(^http://ns.nikon.com/BASIC_PARAM)) {
        //      $et->OverrideFileType('NXD','application/x-nikon-nxd'); }`
        // Latch the override; this `elsif` arm does NOT fall through to the
        // version-insensitive lookup, so `std_ns` stays `None` exactly as in
        // Perl (the URI keeps its first-seen prefix via the normal path).
        // (The Perl regex's `.`s are unescaped but match literal dots here;
        // `^` anchors at the URI start, so `starts_with` is faithful.)
        self.nikon_nxd = true;
      } else {
        // Same namespace with a different version number
        // (XMP.pm:3919-3925) — match `…/N.M/` ignoring the version.
        std_ns = uri_to_ns_version_insensitive(val).map(ToString::to_string);
      }
    }

    let mut new_ns: Option<String> = None;
    if let Some(std) = &std_ns {
      // Pre-defined standard namespace (XMP.pm:3930-3938).
      if std != ns {
        new_ns = Some(std.clone());
      }
      // (the `$$xlatNS{$ns}` re-define-to-standard branch is handled by the
      // caller's xlat_ns map for the scope)
    } else if let Some(existing) = self.cur_ns.get(val) {
      // Consistent prefix over the whole file for a given URI
      // (XMP.pm:3939-3941).
      if existing != ns {
        new_ns = Some(existing.clone());
      }
    } else {
      // First sight of this URI (XMP.pm:3942-3956). Assign a unique
      // prefix; if `ns` collides with a known prefix, mint `tmpN`.
      let mut used_ns = ns.to_string();
      if self.cur_uri.contains_key(ns) || xmp_ns_known(ns) {
        let mut i = 0;
        while self.cur_uri.contains_key(&std::format!("tmp{i}")) {
          i += 1;
        }
        used_ns = std::format!("tmp{i}");
        new_ns = Some(used_ns.clone());
      }
      self.cur_ns.insert(val.clone(), used_ns.clone());
      self.cur_uri.insert(used_ns.clone(), val.clone());
    }

    // If we are translating to a non-empty prefix, retro-fix prior attrs
    // in the same element that used the old prefix (XMP.pm:3966-3974).
    if let Some(new) = &new_ns
      && !new.is_empty()
    {
      let old_prefix = std::format!("{ns}:");
      for (a, _) in attrs.iter_mut() {
        if let Some(rest) = a.strip_prefix(&old_prefix) {
          *a = std::format!("{new}:{rest}");
        }
      }
    }
    new_ns
  }
}

/// Iterate `name='value'` / `name="value"` attributes in an attribute text
/// run. Faithful to the XMP.pm:3884-3896 attribute regex
/// `(\S+?)\s*=\s*(['"])`.
fn iter_attrs(text: &str) -> Vec<(String, String)> {
  let bytes = text.as_bytes();
  let mut out = Vec::new();
  let mut i = 0;
  while i < bytes.len() {
    // Skip whitespace.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
      i += 1;
    }
    if i >= bytes.len() {
      break;
    }
    // Attribute name: non-whitespace, non-`=`.
    let name_start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
      i += 1;
    }
    let name_end = i;
    if name_end == name_start {
      i += 1;
      continue;
    }
    // Skip ws + `=` + ws.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
      i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'=' {
      break; // malformed — stop
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
      i += 1;
    }
    if i >= bytes.len() || (bytes[i] != b'\'' && bytes[i] != b'"') {
      break;
    }
    let quote = bytes[i];
    i += 1;
    let val_start = i;
    while i < bytes.len() && bytes[i] != quote {
      i += 1;
    }
    if i >= bytes.len() {
      break;
    }
    let val_end = i;
    i += 1; // past closing quote
    out.push((
      text[name_start..name_end].to_string(),
      text[val_start..val_end].to_string(),
    ));
  }
  out
}

/// Split a `prefix:rest` name. Returns `(prefix, ":rest")` — i.e. `rest`
/// keeps the leading colon (so concatenation works like Perl's `substr`).
fn split_prefix(name: &str) -> Option<(&str, &str)> {
  // XMP.pm uses `/(.*?):/` — the FIRST colon.
  let idx = name.find(':')?;
  Some((&name[..idx], &name[idx..]))
}

/// `true` if `ns` is a known XMP namespace prefix (`%nsURI` keys) — used by
/// the `tmpN` collision logic.
fn xmp_ns_known(ns: &str) -> bool {
  tables::ns_uri(ns).is_some()
}

/// Look a URI up version-insensitively (XMP.pm:3919-3925 — match `…/N.M/`
/// or `…/N.M$` with any version).
fn uri_to_ns_version_insensitive(uri: &str) -> Option<&'static str> {
  // Replace a `/N.M/` or trailing `/N.M` segment with a wildcard and probe.
  // Faithful enough: try stripping a trailing `/digit.digit/` or
  // `/digit.digit`.
  for (known, ns) in tables::all_ns_uris() {
    if uri_versions_match(uri, known) {
      return Some(ns);
    }
  }
  None
}

/// `true` if two URIs are equal once any `/N.M` version segment is treated
/// as a wildcard.
fn uri_versions_match(a: &str, b: &str) -> bool {
  if a == b {
    return true;
  }
  // Find the first `/<digit>.<digit>` segment in `b` and see if `a`
  // matches with a different version there.
  let mask = |s: &str| -> String {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
      if bytes[i] == b'/'
        && i + 3 < bytes.len()
        && bytes[i + 1].is_ascii_digit()
        && bytes[i + 2] == b'.'
        && bytes[i + 3].is_ascii_digit()
      {
        // skip the version run
        out.push_str("/#");
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
          i += 1;
        }
        continue;
      }
      out.push(bytes[i] as char);
      i += 1;
    }
    out
  };
  mask(a) == mask(b)
}

// ===========================================================================
// Helper predicates from XMP.pm's `my %…` lookups
// ===========================================================================

/// `%ignoreNamespace` (XMP.pm:268) — namespaces that don't contribute to a
/// generated tag name.
fn is_ignored_namespace(ns: &str) -> bool {
  matches!(ns, "x" | "rdf" | "xmlns" | "xml" | "svg" | "office")
}

/// `%ignoreEtProp` (XMP.pm:271) — ExifTool properties that don't generate
/// tag names.
fn is_ignore_et_prop(full_name: &str) -> bool {
  matches!(
    full_name,
    "et:desc" | "et:prt" | "et:val" | "et:id" | "et:tagid" | "et:toolkit" | "et:table" | "et:index"
  )
}

/// Structural attributes that are recognized but never produce a tag
/// (the `=> 1` entries of `%recognizedAttrs`, XMP.pm:283-291).
fn is_structural_attr(full_name: &str) -> bool {
  matches!(
    full_name,
    "rdf:parseType" | "rdf:nodeID" | "et:toolkit" | "rdf:xmlns" | "rdf:datatype"
  )
}

/// Recognized attributes that DO produce a tag (the list-ref entries of
/// `%recognizedAttrs`, XMP.pm:277-292). Returns `(family1-group, tag-name)`.
fn recognized_attr(full_name: &str) -> Option<(&'static str, &'static str)> {
  match full_name {
    "rdf:about" => Some(("XMP-rdf", "About")),
    "x:xmptk" | "x:xaptk" => Some(("XMP-x", "XMPToolkit")),
    "lastUpdate" => Some(("XMP-XML", "LastUpdate")),
    _ => None,
  }
}

/// Resolve a shorthand-attribute name into `(ns, name, full_name)`
/// (XMP.pm:4076-4082). If the attr has no prefix, it inherits the
/// containing property's namespace.
fn resolve_attr_name(
  attr_name: &str,
  parent_prop: &str,
  xlat_ns: &BTreeMap<String, String>,
) -> (String, String, String) {
  if let Some((pfx, rest)) = split_prefix(attr_name) {
    // Translate the prefix if needed.
    let canon = xlat_ns.get(pfx).map(String::as_str).unwrap_or(pfx);
    let name = rest.trim_start_matches(':').to_string();
    let full = std::format!("{canon}:{name}");
    (canon.to_string(), name, full)
  } else if let Some((ppfx, _)) = split_prefix(parent_prop) {
    // Inherit the parent's namespace (XMP.pm:4077-4080).
    (
      ppfx.to_string(),
      attr_name.to_string(),
      std::format!("{ppfx}:{attr_name}"),
    )
  } else {
    // A property qualifier with no namespace.
    (String::new(), attr_name.to_string(), attr_name.to_string())
  }
}

/// Strip `<!-- … -->` comments and trim ASCII whitespace (XMP.pm:4199 for
/// rdf:Description literal values).
fn strip_comments_and_trim(s: &str) -> String {
  strip_comments(s).trim().to_string()
}

/// Strip `<!-- … -->` comments (XMP.pm:4202).
fn strip_comments(s: &str) -> String {
  let mut out = String::new();
  let bytes = s.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    if bytes[i..].starts_with(b"<!--")
      && let Some(end) = find_sub(&bytes[i + 4..], b"-->")
    {
      i += 4 + end + 3;
      continue;
    }
    out.push(bytes[i] as char);
    i += 1;
  }
  // The naive byte-push above breaks multi-byte UTF-8 — redo via char iter
  // when the string is non-ASCII.
  if s.is_ascii() {
    out
  } else {
    strip_comments_unicode(s)
  }
}

/// Unicode-correct comment stripper (slower path for non-ASCII input).
fn strip_comments_unicode(s: &str) -> String {
  let mut out = String::new();
  let mut rest = s;
  while let Some(idx) = rest.find("<!--") {
    out.push_str(&rest[..idx]);
    if let Some(close) = rest[idx + 4..].find("-->") {
      rest = &rest[idx + 4 + close + 3..];
    } else {
      // unterminated — keep the rest verbatim
      out.push_str(&rest[idx..]);
      return out;
    }
  }
  out.push_str(rest);
  out
}

/// Empty-value fallback matcher (XMP.pm:4185-4186). ExifTool deliberately
/// matches the RAW `$attrs` string with the literal Perl regexes
/// `\brdf:(?:value|resource)=(['"])(.*?)\1` and `\brdf:about=(['"])(.*?)\1`.
///
/// Crucially these regexes have NO `\s*` around the `=`, unlike the general
/// attribute scanner (XMP.pm:3886). So `rdf:resource = "…"` (spaces around
/// `=`) does NOT match and the value stays empty. This is an EXACT literal
/// scan, not a reparse via [`iter_attrs`]. `\b` is a word boundary, so the
/// `rdf` must be preceded by a non-word char (or start of string).
///
/// `names` are the bare suffixes of one Perl alternation group (e.g.
/// `["value", "resource"]` for `\brdf:(?:value|resource)=…`). The Perl
/// regex engine scans the string left-to-right and, at the first byte
/// offset where ANY alternative matches, returns that capture — so the
/// earliest-positioned `rdf:NAME="…"` in the raw text wins, not the first
/// name in the list. Returns the raw, still-escaped attribute value.
fn rdf_raw_attr(attrs_text: &str, names: &[&str]) -> Option<String> {
  let bytes = attrs_text.as_bytes();
  let mut best: Option<(usize, String)> = None;
  for name in names {
    let needle = std::format!("rdf:{name}=");
    let nlen = needle.len();
    let mut search = 0usize;
    while let Some(rel) = attrs_text[search..].find(&needle) {
      let pos = search + rel;
      search = pos + 1;
      // `\b` before `rdf`: prev byte must not be a word char [A-Za-z0-9_].
      if pos > 0 {
        let prev = bytes[pos - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
          continue;
        }
      }
      // The byte right after `=` must be a quote (no whitespace tolerated).
      let q = pos + nlen;
      if q >= bytes.len() {
        continue;
      }
      let quote = bytes[q];
      if quote != b'"' && quote != b'\'' {
        continue;
      }
      // Non-greedy capture up to the matching quote.
      if let Some(end_rel) = attrs_text[q + 1..].find(quote as char) {
        if best.as_ref().is_none_or(|(p, _)| pos < *p) {
          best = Some((pos, attrs_text[q + 1..q + 1 + end_rel].to_string()));
        }
        break; // earliest match for THIS name found; other names compared
      }
    }
  }
  best.map(|(_, v)| v)
}

/// Pull the first present attribute value out of the namespace-NORMALIZED
/// `(name, value)` pairs produced by `parse_attrs`, trying each name in
/// order. Used for `rdf:datatype`/`et:encoding` (XMP.pm:3644) and `xml:lang`
/// (XMP.pm:3497), which `FoundXMP` reads from the `%attrs` hash whose keys
/// have already been prefix-translated. Returns the UN-unescaped raw value.
fn attr_value_pairs(attrs: &[(String, String)], names: &[&str]) -> Option<String> {
  for name in names {
    if let Some((_, v)) = attrs.iter().find(|(k, _)| k == name) {
      return Some(v.clone());
    }
  }
  None
}

// ===========================================================================
// UnescapeXML (XMP.pm:2875) + the named-entity table (XMP.pm %charNum)
// ===========================================================================

/// Un-escape XML character references — faithful port of `UnescapeXML`
/// (XMP.pm:2875) + `UnescapeChar` (XMP.pm:2918). Handles the five named
/// entities plus `&#NNN;` / `&#xHH;` numeric references.
///
/// Perl `UnescapeChar` (XMP.pm:2932-2933) emits `chr($val)` via
/// `pack('C0U', $val)`, which produces variable-length UTF-8 bytes WITHOUT
/// validity checks — surrogates and code points above U+10FFFF become
/// malformed byte sequences that the later `Decode(...,'UTF8')` /
/// `EscapeJSON`+`FixUTF8` (XMP.pm:2943) replaces with one `?` per bad byte.
/// We therefore unescape into BYTES ([`unescape_xml_bytes`], which never bails
/// to literal on overflow) and fold that downstream `FixUTF8` in via
/// [`crate::convert::fix_utf8`] (XMP.pm:2943-2972) before returning a `String`.
/// For ordinary, in-range input `fix_utf8` is a verbatim pass-through.
fn unescape_xml(s: &str) -> String {
  if !s.contains('&') {
    return s.to_string();
  }
  crate::convert::fix_utf8(&unescape_xml_bytes(s.as_bytes()))
}

/// Tri-state result of [`resolve_xml_entity_codepoint`] — faithful to the three
/// outcomes of Perl `UnescapeChar` (XMP.pm:2919-2936).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlEntity {
  /// Resolved to a code point in `0..=i64::MAX` (Perl `pack('C0U')` range).
  /// The code point is emitted via [`crate::convert::pack_c0u`] — surrogates
  /// and values above U+10FFFF deliberately yield malformed UTF-8 that
  /// `fix_utf8` later maps to `?` (XMP.pm:2932-2933 + 2943).
  Resolved(u64),
  /// Body matched no branch (not one of the five named entities, not a
  /// `#x[0-9a-fA-F]+` hex ref, not a `#\d+` decimal ref). Caller leaves the
  /// original `&body;` token verbatim (XMP.pm:2929 — `return "&$ch;"`).
  Unknown,
}

/// Resolve one XML entity body (the text between `&` and `;`, already known to
/// match Perl's `#?\w+`) — faithful to `UnescapeChar` (XMP.pm:2919-2931) with
/// XMP's `%charNum` table (XMP.pm:2874 — ONLY the five XML entities, NOT the
/// HTML set).
///
/// R9/F2 + class-sweep: the previous helper (a) accepted `#X…` (uppercase X),
/// (b) accepted a leading `+` in the numeric body (Rust `from_str_radix`/`parse`
/// admit `+`), and (c) bailed to literal on overflow/surrogate. Perl
/// `UnescapeChar` (XMP.pm:2924-2927) anchors `^#x([0-9a-fA-F]+)$` (LOWERCASE x,
/// no sign) and `^#(\d+)$`, then `pack('C0U')`s ANY in-range value. Bundled
/// 13.58 evidence: `&#X41;` and `&#x+41;` stay literal; `&#x100000000;` →
/// `A` + 7 loose-UTF-8 bytes → `A???????B`; `&#xD800;` → 3 bytes → `S???E`.
fn resolve_xml_entity_codepoint(entity: &str) -> XmlEntity {
  // Perl `pack('C0U', $n)` rejects values strictly greater than i64::MAX
  // (it dies). XMP.pm:2933. Above that we leave the entity LITERAL: a
  // panic-free library cannot reproduce Perl's process-abort, and the
  // bundled XMP fixtures never exercise it (see report / [[exifast-phase2-
  // forward-items]]). Within `0..=i64::MAX` we are byte-faithful.
  const PERL_PACK_C0U_MAX: u64 = 0x7FFF_FFFF_FFFF_FFFF;
  // (1) The five XML named entities — `%charNum` (XMP.pm:2874).
  let named = match entity {
    "quot" => Some(34),
    "amp" => Some(38),
    "apos" => Some(39),
    "lt" => Some(60),
    "gt" => Some(62),
    _ => None,
  };
  if let Some(n) = named {
    return XmlEntity::Resolved(n);
  }
  // Numeric forms require a leading `#` (XMP.pm:2924/2926).
  let Some(rest) = entity.strip_prefix('#') else {
    return XmlEntity::Unknown;
  };
  // (2) Hex `#x[0-9a-fA-F]+` — LOWERCASE `x` only (XMP.pm:2924).
  if let Some(hex) = rest.strip_prefix('x') {
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
      return XmlEntity::Unknown;
    }
    // Perl `hex()` saturates beyond u64; a >u64 body still exceeds the
    // pack max, so a u64 parse failure ⇒ leave literal (out of faithful
    // range, see PERL_PACK_C0U_MAX note above).
    let Ok(n) = u64::from_str_radix(hex, 16) else {
      return XmlEntity::Unknown;
    };
    if n > PERL_PACK_C0U_MAX {
      return XmlEntity::Unknown;
    }
    return XmlEntity::Resolved(n);
  }
  // (3) Decimal `#\d+` (XMP.pm:2926).
  if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
    return XmlEntity::Unknown;
  }
  let Ok(n) = rest.parse::<u64>() else {
    return XmlEntity::Unknown;
  };
  if n > PERL_PACK_C0U_MAX {
    return XmlEntity::Unknown;
  }
  XmlEntity::Resolved(n)
}

// ===========================================================================
// CDATA-aware un-escape (FoundXMP, XMP.pm:3656-3672)
// ===========================================================================

/// Un-escape an XMP value, handling embedded `<![CDATA[ … ]]>` sections
/// (whose content is NOT un-escaped) — faithful to the CDATA branch of
/// `FoundXMP` (XMP.pm:3656-3672).
///
/// Delegates to the byte twin [`unescape_value_with_cdata_bytes`] (which emits
/// RAW `UnescapeChar` bytes, incl. malformed `pack('C0U')` sequences for
/// surrogate / out-of-range numeric refs) and folds in Perl's downstream
/// `Decode`/`FixUTF8` (XMP.pm:2943) via [`crate::convert::fix_utf8`] in a single
/// pass over the whole result. For in-range input `fix_utf8` is a verbatim
/// pass-through, so this matches the previous behaviour byte-for-byte.
fn unescape_value_with_cdata(val: &str) -> String {
  crate::convert::fix_utf8(&unescape_value_with_cdata_bytes(val.as_bytes()))
}

/// Byte-level twin of [`unescape_value_with_cdata`] for the base64 text path.
///
/// `DecodeBase64` (XMP.pm:2981) yields a raw byte-string that Perl un-escapes
/// (XMP.pm:3655-3669) BEFORE the UTF-8 decode, so the un-escape must run on the
/// decoded bytes — which need not be valid UTF-8 (the text-branch guard only
/// excludes control bytes, not high-bit ones). `UnescapeXML` only ever rewrites
/// ASCII entity runs (`&…;`) and leaves every other byte verbatim, exactly like
/// this walker; numeric entities (`&#xE9;`) emit UTF-8 bytes that the later
/// `fix_utf8`/`Decode('UTF8')` then validates (matching Perl, verified vs
/// 13.58: `a&#xE9;b` → `61 c3 a9 62`).
fn unescape_value_with_cdata_bytes(val: &[u8]) -> Vec<u8> {
  const CDATA_OPEN: &[u8] = b"<![CDATA[";
  const CDATA_CLOSE: &[u8] = b"]]>";
  if find_subslice(val, CDATA_OPEN).is_none() {
    return unescape_xml_bytes(val);
  }
  let mut out = Vec::with_capacity(val.len());
  let mut rest = val;
  while let Some(idx) = find_subslice(rest, CDATA_OPEN) {
    out.extend_from_slice(&unescape_xml_bytes(&rest[..idx]));
    let body_start = idx + CDATA_OPEN.len();
    if let Some(close) = find_subslice(&rest[body_start..], CDATA_CLOSE) {
      out.extend_from_slice(&rest[body_start..body_start + close]);
      rest = &rest[body_start + close + CDATA_CLOSE.len()..];
    } else {
      out.extend_from_slice(&rest[body_start..]);
      return out;
    }
  }
  out.extend_from_slice(&unescape_xml_bytes(rest));
  out
}

/// Byte-level twin of [`unescape_xml`]: rewrite ASCII `&…;` entity runs,
/// copying every non-entity byte verbatim (no UTF-8 assumptions). This is the
/// faithful `UnescapeXML` (XMP.pm:2879 `s/&(#?\w+);/UnescapeChar(...)/sge`)
/// stage — it produces RAW `UnescapeChar` output, INCLUDING the malformed
/// `pack('C0U')` bytes for surrogate / out-of-range numeric refs. The caller
/// applies `fix_utf8` (Perl's downstream `Decode`/`FixUTF8`) before storing as
/// a UTF-8 `String`.
///
/// "Find first `;`, validate body, else emit `&` and advance one byte" matches
/// Perl's leftmost-match-with-resume `s///g` — when the body up to the first
/// `;` is not `#?\w+`, `UnescapeChar` is never reached at this `&` (the regex
/// fails here and the engine retries at the next `&`), so the literal `&` is
/// preserved and scanning resumes one byte on (verified vs 13.58 for
/// `&#x+41;`, `&#X41;`, `&x&amp;` → leftmost behaviour).
fn unescape_xml_bytes(s: &[u8]) -> Vec<u8> {
  if !s.contains(&b'&') {
    return s.to_vec();
  }
  let mut out = Vec::with_capacity(s.len());
  let mut i = 0;
  while i < s.len() {
    if s[i] == b'&' {
      if let Some(semi_rel) = s[i + 1..].iter().position(|&b| b == b';')
        && let Ok(entity) = core::str::from_utf8(&s[i + 1..i + 1 + semi_rel])
        && let XmlEntity::Resolved(code) = resolve_xml_entity_codepoint(entity)
      {
        // Perl `pack('C0U', $val)` (XMP.pm:2933) — variable-length UTF-8
        // WITHOUT validity checks; surrogates / >U+10FFFF become malformed
        // bytes that `fix_utf8` later maps to one `?` each.
        crate::convert::pack_c0u(code, &mut out);
        i += 1 + semi_rel + 1;
        continue;
      }
      // Not a recognized entity — emit the `&` verbatim.
      out.push(b'&');
      i += 1;
    } else {
      out.push(s[i]);
      i += 1;
    }
  }
  out
}

/// Find the first index of `needle` in `haystack` (byte-level `str::find`).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() {
    return Some(0);
  }
  haystack
    .windows(needle.len())
    .position(|window| window == needle)
}

// ===========================================================================
// ConvertXMPDate (XMP.pm:3383) + ConvertRational (XMP.pm:3401)
// ===========================================================================

/// Faithful port of `ConvertXMPDate` (XMP.pm:3383). Converts an XMP/ISO-8601
/// date into ExifTool's `YYYY:MM:DD HH:MM:SS` form. Returns
/// `(converted, was_full_datetime)` — the second flag mirrors the Perl
/// `wantarray` `($val, 1)` return.
fn convert_xmp_date(val: &str, unsure: bool) -> (String, bool) {
  // Regex 1: `^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$`.
  if let Some(parts) = match_xmp_datetime(val) {
    let (y, mo, d, hm, sec, tz) = parts;
    let converted = std::format!("{y}:{mo}:{d} {hm}{sec}{tz}");
    return (converted, true);
  }
  // Regex 2 (only when not "unsure"): `^(\d{4})(-\d{2}){0,2}` → tr/-/:/.
  if !unsure && match_xmp_dateonly(val) {
    return (val.replace('-', ":"), false);
  }
  (val.to_string(), false)
}

/// Match the full-datetime regex of ConvertXMPDate. Returns
/// `(year, month, day, "HH:MM", ":SS" or "", timezone)`.
fn match_xmp_datetime(val: &str) -> Option<(&str, &str, &str, &str, &str, &str)> {
  let b = val.as_bytes();
  // YYYY
  if b.len() < 16 || !b[..4].iter().all(u8::is_ascii_digit) {
    return None;
  }
  if b[4] != b'-' || !b[5..7].iter().all(u8::is_ascii_digit) {
    return None;
  }
  if b[7] != b'-' || !b[8..10].iter().all(u8::is_ascii_digit) {
    return None;
  }
  if b[10] != b'T' && b[10] != b' ' {
    return None;
  }
  if !b[11..13].iter().all(u8::is_ascii_digit) || b[13] != b':' {
    return None;
  }
  if !b[14..16].iter().all(u8::is_ascii_digit) {
    return None;
  }
  let year = &val[0..4];
  let month = &val[5..7];
  let day = &val[8..10];
  let hm = &val[11..16]; // HH:MM
  // Optional `:SS`.
  let mut i = 16;
  let sec =
    if i + 3 <= b.len() && b[i] == b':' && b[i + 1].is_ascii_digit() && b[i + 2].is_ascii_digit() {
      let s = &val[i..i + 3];
      i += 3;
      s
    } else {
      ""
    };
  // Optional whitespace then a non-whitespace timezone run to end-of-string.
  let mut j = i;
  while j < b.len() && b[j].is_ascii_whitespace() {
    j += 1;
  }
  let tz = &val[j..];
  // The regex anchors `$` — tz must be the rest with no internal ws.
  if tz.bytes().any(|c| c.is_ascii_whitespace()) {
    return None;
  }
  Some((year, month, day, hm, sec, tz))
}

/// Match the date-only regex `^(\d{4})(-\d{2}){0,2}` of ConvertXMPDate.
fn match_xmp_dateonly(val: &str) -> bool {
  let b = val.as_bytes();
  if b.len() < 4 || !b[..4].iter().all(u8::is_ascii_digit) {
    return false;
  }
  // The regex is unanchored at the end, so 4 digits alone match.
  true
}

/// Faithful port of `ConvertRational` (XMP.pm:3400-3411). If `val` is `N/D`,
/// returns the converted numeric string (`N/D` quotient, or `inf`/`undef`);
/// otherwise `None`.
///
/// Codex R12/F1 + class-sweep: `ConvertRational` gates the value with the
/// Perl regex `^(-?\d+)/(-?\d+)$` (XMP.pm:3402) — EXACTLY one `/`, an
/// OPTIONAL `-` (never a `+`) then one-or-more digits on each side, anchored
/// whole-string. Rust `i64::parse` is more lenient: it ACCEPTS a leading
/// `+`. The previous `split_once('/')` + `i64::parse` therefore converted
/// `+1/3` (a plausible non-malicious `XMP-exif:ExposureBiasValue` sidecar
/// value) to a quotient, whereas the oracle leaves it untouched. Enforce the
/// Perl lexical shape with [`is_perl_signed_digits`] before parsing; convert
/// only on a match. (`IsRational`, ExifTool.pm:5945, uses the LOOSER
/// `^[-+]?\d+/\d+$` — but `ConvertRational`, the function ported here, is
/// strict, and it is `ConvertRational` that `FoundXMP` calls, XMP.pm:3686.)
fn convert_rational(val: &str) -> Option<String> {
  let (num_s, den_s) = val.split_once('/')?;
  // The `$` anchor forbids a second `/` — `split_once` keeps the first
  // slash, so a `1/2/3` input leaves `den_s == "2/3"`, which fails
  // `is_perl_signed_digits` and is correctly rejected.
  if !is_perl_signed_digits(num_s) || !is_perl_signed_digits(den_s) {
    return None;
  }
  let num: i64 = num_s.parse().ok()?;
  let den: i64 = den_s.parse().ok()?;
  if den != 0 {
    // `$1 / $2` — Perl float division.
    let q = num as f64 / den as f64;
    Some(format_perl_num(q))
  } else if num != 0 {
    Some("inf".to_string())
  } else {
    Some("undef".to_string())
  }
}

/// Faithful port of `ConvertRationalList` (XMP.pm:3418-3427) — the
/// `aux:LensInfo` `ValueConv` (XMP.pm:2600). Splits `val` on whitespace
/// (Perl `split ' '` — leading whitespace trimmed, runs collapsed); unless
/// the result is EXACTLY 4 fields, returns `val` unchanged (XMP.pm:3422).
/// Applies [`convert_rational`] to each field; if ANY field is not an `N/D`
/// rational (`ConvertRational` returns false, XMP.pm:3424), returns `val`
/// unchanged. Otherwise joins the 4 converted values with a single space.
fn convert_rational_list(val: &str) -> String {
  // `split ' ', $val` — Perl's "awk" split: skips leading whitespace,
  // splits on whitespace runs (`str::split_whitespace` is the exact match).
  let fields: Vec<&str> = val.split_whitespace().collect();
  if fields.len() != 4 {
    return val.to_string();
  }
  let mut out: Vec<String> = Vec::with_capacity(4);
  for f in fields {
    match convert_rational(f) {
      Some(converted) => out.push(converted),
      // `ConvertRational(...) or return $val` — a non-rational field aborts
      // the whole conversion; the original string is returned untouched.
      None => return val.to_string(),
    }
  }
  out.join(" ")
}

/// Faithful port of the `exif:ColorSpace` `ValueConv`
/// `'$val == 0xffffffff ? 0xffff : $val'` (XMP.pm:2003). The `==` is a Perl
/// NUMERIC comparison, so `val` is coerced via [`perl_num`]; on equality with
/// `0xffffffff` (4294967295) the value collapses to the EXIF `0xffff`
/// "Uncalibrated" sentinel (`65535`), otherwise `val` passes through
/// UNCHANGED (the `: $val` branch — the original string, not a re-rendered
/// number).
fn convert_color_space(val: &str) -> String {
  if perl_num(val) == 4_294_967_295.0 {
    "65535".to_string()
  } else {
    val.to_string()
  }
}

/// Stringify a number the way Perl does (compact — drops a trailing `.0`,
/// uses up to 15 significant digits). Used to render every numeric
/// `ValueConv` result (the `ConvertRational` quotient, the APEX
/// aperture/shutter formulas, `gps_to_degrees`).
///
/// Codex R12 class-sweep: a non-finite `ValueConv` result is faithfully
/// possible — e.g. `sqrt(2) ** $val` (XMP.pm:2090) with `$val` the literal
/// `'inf'` token `ConvertRational` emits for a zero-denominator rational
/// (`exif:ApertureValue` = `1/0` ⇒ oracle `"Inf"`, verified vs bundled
/// 13.58). Perl stringifies an NV infinity/NaN with TITLECASE `Inf`/`-Inf`/
/// `NaN`; Rust's `{}`/`{:e}` formatting emits lowercase `inf`/`nan`. Route
/// non-finite values through the shared `perl_nonfinite_str` for byte-exact
/// casing (the same fix `convert_duration` carries, datetime.rs:86).
fn format_perl_num(v: f64) -> String {
  if let Some(nonfinite) = crate::value::perl_nonfinite_str(v) {
    return nonfinite.to_string();
  }
  if v == v.trunc() && v.abs() < 1e15 {
    // Whole number — Perl prints it without a decimal point.
    return std::format!("{}", v as i64);
  }
  // Perl's default %.15g stringification.
  let mut s = std::format!("{v:.15e}");
  // Re-render via the shortest form that round-trips, capped at 15 sig.
  s = format_g15(v);
  s
}

/// `%.15g`-style formatting (15 significant digits, trailing zero trim).
fn format_g15(v: f64) -> String {
  if v == 0.0 {
    return "0".to_string();
  }
  let mut s = std::format!("{v:.*e}", 14);
  // Parse back the mantissa/exponent and render in %g style.
  if let Some((mant, exp)) = s.split_once('e') {
    let exp: i32 = exp.parse().unwrap_or(0);
    if (-4..15).contains(&exp) {
      // Fixed notation.
      let decimals = (14 - exp).max(0) as usize;
      s = std::format!("{v:.*}", decimals);
      if s.contains('.') {
        s = s.trim_end_matches('0').trim_end_matches('.').to_string();
      }
    } else {
      // Scientific.
      let mant = mant.trim_end_matches('0').trim_end_matches('.');
      s = std::format!("{mant}e{exp}");
    }
  }
  s
}

/// Match the Perl character class `(-?\d+)` exactly: an OPTIONAL leading `-`
/// (NOT `+`), then one-or-more ASCII digits, whole-string. Used by
/// [`convert_rational`] to gate each side of an `N/D` rational the way
/// `ConvertRational`'s regex `^(-?\d+)/(-?\d+)$` does (XMP.pm:3402). Rust's
/// `i64::parse` is looser — it accepts a leading `+`, surrounding nothing
/// else but no underscores either — so the explicit pre-check is required
/// to faithfully reject `+1/3` (Codex R12/F1).
fn is_perl_signed_digits(s: &str) -> bool {
  let bytes = s.as_bytes();
  let digits = match bytes.first() {
    Some(b'-') => &bytes[1..],
    _ => bytes,
  };
  !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

/// Perl numeric coercion (`$val + 0`) to an `f64` — the longest leading
/// numeric prefix, sign-aware, with trailing garbage ignored and a
/// non-numeric string yielding `0`.
///
/// Codex R12 class-sweep: ExifTool's XMP `PrintConv`/`ValueConv` expressions
/// that this port models — `sprintf("%.1f",$val)` (`Fixed1`),
/// `sprintf("%.1f mm",$val)` (`FocalMm`), `sqrt(2) ** $val` (`ApexAperture`),
/// `abs($val)<100 ? 1/(2**$val) : 0` (`ApexShutter`) and
/// `Exif::PrintFraction` (`Fraction`) — operate on `$val` in PURE numeric
/// context, with NO `IsFloat`/`IsInt` gate. Perl's numeric coercion is
/// PREFIX-based: it scans the leading `[+-]?(\d+(\.\d*)?|\.\d+)([Ee][+-]?\d+)?`
/// run and ignores the rest, so `"+1/3" + 0 == 1`, `"50/1" + 0 == 50`,
/// `"2.8x" + 0 == 2.8`, `" 1.5" + 0 == 1.5`, `"0x10" + 0 == 0` and
/// `"abc" + 0 == 0` (verified vs Perl 5). Rust `f64::parse` instead requires
/// the WHOLE string to be numeric — it rejects `+1/3`/`2.8x` (where Perl
/// yields `1`/`2.8`) and accepts `inf`/`nan` (where Perl's prefix scan would
/// not). Both directions of that mismatch corrupt the converter output, so
/// the affected sites must coerce via this helper, not `f64::parse`.
///
/// This mirrors `formats::ape::perl_numeric_coerce_f64` (the engine's
/// `convert::perl_numeric_coerce` returns `u64` BITMASK semantics, unusable
/// for signed/float `ValueConv`s); both stay format-local until a third
/// consumer justifies an engine-tier `convert` helper.
fn perl_num(s: &str) -> f64 {
  let bytes = s.as_bytes();
  let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
  let mut i = 0;
  // 1. Leading ASCII whitespace (`" 1.5" + 0 == 1.5`).
  while i < bytes.len() && is_ws(bytes[i]) {
    i += 1;
  }
  // 2. Optional sign. (XMP `ValueConv`/`PrintConv` inputs are a single
  // tag value — never the multi-sign `"+-20"` strings APE's DURATION
  // field admits — so a single optional sign is the faithful scope here;
  // `convert_rational` has already consumed any well-formed rational.)
  let neg = match bytes.get(i) {
    Some(b'+') => {
      i += 1;
      false
    }
    Some(b'-') => {
      i += 1;
      true
    }
    _ => false,
  };
  // 3. The `Inf`/`Infinity`/`NaN` tokens — Perl's numeric coercion of an
  // `inf`/`undef` token (e.g. `ConvertRational`'s zero-denominator output,
  // XMP.pm:3406-3409, feeding the APEX `ValueConv`) yields the non-finite
  // NV, NOT 0: `"inf" + 0 == Inf`, `"undef" + 0 == 0` (verified vs Perl 5).
  // Case-insensitive, prefix scan (`"InfX" + 0` is still `Inf`).
  let starts_ci = |rest: &[u8], lit: &[u8]| -> bool {
    rest.len() >= lit.len() && rest[..lit.len()].eq_ignore_ascii_case(lit)
  };
  if starts_ci(&bytes[i..], b"infinity") || starts_ci(&bytes[i..], b"inf") {
    return if neg {
      f64::NEG_INFINITY
    } else {
      f64::INFINITY
    };
  }
  if starts_ci(&bytes[i..], b"nan") {
    // Perl `NaN` stringifies without a sign — drop `neg`.
    return f64::NAN;
  }
  // 4. Finite numeric prefix: `\d+(\.\d*)?` or `\.\d+`, optional exponent.
  let num_start = i;
  let int_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  let had_int = i > int_start;
  if i < bytes.len() && bytes[i] == b'.' {
    i += 1;
    let frac_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if !had_int && i == frac_start {
      // A lone `.` with no digits ⇒ no numeric prefix ⇒ 0.
      return 0.0;
    }
  } else if !had_int {
    // No leading digits and no `.\d+` form ⇒ no numeric prefix ⇒ 0.
    return 0.0;
  }
  // Optional exponent — `[Ee][+-]?\d+`; an `E` with no trailing digits is
  // NOT part of the prefix (Perl's scan terminates before it).
  let pre_exp = i;
  if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
    i += 1;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
      i += 1;
    }
    let exp_digits = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if i == exp_digits {
      i = pre_exp;
    }
  }
  // Parse the matched magnitude; an overlong literal overflows to ±inf,
  // matching Perl's NV. The sign is applied manually.
  let mag = s[num_start..i].parse::<f64>().unwrap_or(0.0);
  if neg { -mag } else { mag }
}

/// Perl `sprintf("%.1f", $v)` — one fixed decimal. A non-finite NV renders
/// as titlecase `Inf`/`-Inf`/`NaN` (Perl `%f`), NOT Rust's lowercase
/// `inf`/`nan`; route those through `perl_nonfinite_str` (Codex R12
/// class-sweep — the APEX `ValueConv` can yield `Inf`, e.g. `ApertureValue`
/// = `1/0`). The `Fixed1`/`FocalMm` `PrintConv`s share this.
fn sprintf_f1(v: f64) -> String {
  match crate::value::perl_nonfinite_str(v) {
    Some(nonfinite) => nonfinite.to_string(),
    None => std::format!("{v:.1}"),
  }
}

/// Faithful port of `Image::ExifTool::Exif::PrintLensInfo` (Exif.pm:5800-5818)
/// — the `aux:LensInfo` `PrintConv` (XMP.pm:2615). Renders the 4 focal/aperture
/// values produced by [`convert_rational_list`] as `"12-20mm f/3.8-4.5"` or
/// `"50mm f/1.4"`.
///
/// `split ' '`; unless exactly 4 fields, returns `val` unchanged
/// (Exif.pm:5804). Each field must be `IsFloat`, or the literal `inf`/`undef`
/// token (rewritten to `?`); otherwise the count check fails and `val` is
/// returned unchanged (Exif.pm:5806-5811). The upper focal/aperture is
/// appended only when it is Perl-truthy AND differs from the lower value —
/// `if $vals[1] and $vals[1] ne $vals[0]` (Exif.pm:5814) — so a Pentax-Q-style
/// `"0"` upper focal (a fixed-focal-length lens) is dropped.
fn print_lens_info(val: &str) -> String {
  // `split ' ', $val` — Perl awk-split (== `split_whitespace`).
  let mut vals: Vec<String> = val.split_whitespace().map(str::to_string).collect();
  if vals.len() != 4 {
    return val.to_string();
  }
  // `IsFloat($_) and ++$c, next;` / `$_ eq 'inf' and $_ = '?', …` — count
  // the fields that are a float or an `inf`/`undef` token (the latter two
  // are rewritten to `?`). A field that is none of those is left as-is and
  // NOT counted, so `$c != 4` aborts the conversion.
  let mut count = 0;
  for v in &mut vals {
    if is_perl_float(v) {
      count += 1;
    } else if v == "inf" || v == "undef" {
      *v = "?".to_string();
      count += 1;
    }
  }
  if count != 4 {
    return val.to_string();
  }
  // `$val = $vals[0]; $val .= "-$vals[1]" if $vals[1] and $vals[1] ne $vals[0];`
  // — Perl string truthiness: false only for `""` / `"0"`.
  let perl_true = |s: &str| !s.is_empty() && s != "0";
  let mut out = vals[0].clone();
  if perl_true(&vals[1]) && vals[1] != vals[0] {
    out.push('-');
    out.push_str(&vals[1]);
  }
  out.push_str("mm f/");
  out.push_str(&vals[2]);
  if perl_true(&vals[3]) && vals[3] != vals[2] {
    out.push('-');
    out.push_str(&vals[3]);
  }
  out
}

/// Match Perl `IsFloat` (ExifTool.pm:5936-5941) for the ASCII case: the
/// WHOLE string is `[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?`. Used to
/// gate `Exif::PrintExposureTime`/`PrintFNumber` (Exif.pm:5704/5719), which
/// each begin `return $val unless IsFloat($val)`. (The locale comma-decimal
/// alternative is irrelevant — XMP tag values are not locale-formatted.)
fn is_perl_float(s: &str) -> bool {
  let bytes = s.as_bytes();
  let mut i = 0;
  if matches!(bytes.first(), Some(b'+' | b'-')) {
    i += 1;
  }
  // Lookahead `(?=\d|\.\d)`: the next char is a digit, or a `.` then a digit.
  let digit_next = bytes.get(i).is_some_and(u8::is_ascii_digit);
  let dot_digit_next =
    bytes.get(i) == Some(&b'.') && bytes.get(i + 1).is_some_and(u8::is_ascii_digit);
  if !digit_next && !dot_digit_next {
    return false;
  }
  // `\d*`.
  while bytes.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
  }
  // `(\.\d*)?`.
  if bytes.get(i) == Some(&b'.') {
    i += 1;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
  }
  // `([Ee]([+-]?\d+))?`.
  if matches!(bytes.get(i), Some(b'E' | b'e')) {
    i += 1;
    if matches!(bytes.get(i), Some(b'+' | b'-')) {
      i += 1;
    }
    let exp_start = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
    if i == exp_start {
      return false; // `\d+` after the exponent marker is required.
    }
  }
  // The `$` anchor — the regex must consume the whole string.
  i == bytes.len()
}

// ===========================================================================
// GetXMPTagID (XMP.pm:3018)
// ===========================================================================

/// Result of `GetXMPTagID` (XMP.pm:3018): the assembled tag id, the
/// outermost contributing namespace, and the structure-property descriptor.
struct TagId {
  /// The assembled tag name (e.g. `"ImageWidth"`, `"FlashMode"`).
  tag: String,
  /// The outermost namespace that contributed to the tag name.
  namespace: String,
  /// Per-level structure-property descriptor (only the levels that
  /// contribute to the tag-name path), as `[name, index?]`.
  struct_props: Vec<StructProp>,
  /// Per-level namespace list paralleling `struct_props`. Retained for the
  /// variable-namespace-table resolution forward item (`tables.rs` docs).
  #[allow(dead_code)]
  ns_list: Vec<String>,
}

/// Faithful port of `GetXMPTagID` (XMP.pm:3018). Walks the property path,
/// splits each `ns:name`, skips ignored namespaces (recording list indices
/// for structures), de-uglifies all-uppercase names, and concatenates the
/// per-level names into a CamelCase tag id.
fn get_xmp_tag_id(props: &[SmolStr]) -> TagId {
  let mut tag: Option<String> = None;
  let mut namespace: Option<String> = None;
  let mut struct_props: Vec<StructProp> = Vec::new();
  let mut ns_list: Vec<String> = Vec::new();

  for prop in props {
    let prop = prop.as_str();
    // Split into namespace + name (ns may be "" for qualifiers).
    let (ns, nm) = match prop.find(':') {
      Some(idx) => (&prop[..idx], &prop[idx + 1..]),
      None => ("", prop),
    };
    if is_ignored_namespace(ns) || is_ignore_et_prop(prop) {
      // Special case: rdf numbered items `rdf:_\d+` are NOT ignored.
      if let Some(num) = rdf_numbered(prop) {
        // `$tag .= $1 if defined $tag`
        if let Some(t) = &mut tag {
          t.push_str(num);
        }
      } else {
        // Save list index for structures if this is `rdf:li \d+`.
        if let Some(idx) = rdf_li_index(prop)
          && let Some(last) = struct_props.last_mut()
        {
          last.index = Some(idx.to_string());
        }
        // NOTE: the bundled `$namespace = $ns unless $namespace`
        // (XMP.pm:3066) runs for ignored props too — but every observed
        // oracle output groups a tag under its FIRST CONTRIBUTING
        // (non-ignored) namespace, never under an enclosing `x` / `rdf`
        // container. The ExifTool quirk is masked because the container
        // namespaces (`x`, `rdf`) are never themselves keys in
        // `%XMP::Main`, so `FoundXMP`'s `$ns`-keyed table lookup +
        // `SetGroup("XMP-$ns")` only ever fires for a real namespace.
        // We record the namespace ONLY from a contributing prop, which is
        // bit-equivalent for the family-1 group.
        continue;
      }
    } else {
      // Strip a nodeID suffix (`nm =~ s/ .*//`).
      let nm_clean: &str = match nm.find(' ') {
        Some(i) => &nm[..i],
        None => nm,
      };
      // All-uppercase de-uglify (XMP.pm:3039-3050).
      let nm_final = if !nm_clean.bytes().any(|b| b.is_ascii_lowercase()) {
        // ExifTool checks the namespace's structure table for an exact
        // key first; if absent, lowercases + underscore-CamelCases.
        let xlat = std_xlat_ns(ns).unwrap_or(ns);
        if struct_table_has_key(xlat, nm_clean) {
          nm_clean.to_string()
        } else {
          deuglify_uppercase(nm_clean)
        }
      } else {
        nm_clean.to_string()
      };
      // Append to the tag name.
      match &mut tag {
        Some(t) => t.push_str(&ucfirst(&nm_final)),
        None => tag = Some(nm_final.clone()),
      }
      // Record the structure level.
      struct_props.push(StructProp {
        name: SmolStr::new(&nm_final),
        index: None,
      });
      ns_list.push(ns.to_string());
      // Namespace of the first CONTRIBUTING property (see the note in the
      // ignored-namespace branch above — XMP.pm:3066 is masked to this).
      if namespace.is_none() {
        namespace = Some(ns.to_string());
      }
    }
  }

  TagId {
    tag: tag.unwrap_or_default(),
    namespace: namespace.unwrap_or_default(),
    struct_props,
    ns_list,
  }
}

/// Match `rdf:_\d+` (an RDF numbered item) — returns the `_\d+` part.
fn rdf_numbered(prop: &str) -> Option<&str> {
  let rest = prop.strip_prefix("rdf:")?;
  let body = rest.strip_prefix('_')?;
  if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
    Some(rest)
  } else {
    None
  }
}

/// Match `rdf:li \d+` — returns the (ExifTool zero-padded) index string.
fn rdf_li_index(prop: &str) -> Option<&str> {
  let rest = prop.strip_prefix("rdf:li ")?;
  if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
    Some(rest)
  } else {
    None
  }
}

/// De-uglify an all-uppercase name (XMP.pm:3048-3049): `lc` then
/// `s/_([a-z])/\u$1/g` (underscore-CamelCase).
fn deuglify_uppercase(s: &str) -> String {
  let lower = s.to_ascii_lowercase();
  let mut out = String::with_capacity(lower.len());
  let mut chars = lower.chars().peekable();
  while let Some(c) = chars.next() {
    if c == '_' {
      if let Some(&next) = chars.peek() {
        out.push(next.to_ascii_uppercase());
        chars.next();
      }
    } else {
      out.push(c);
    }
  }
  out
}

/// `ucfirst` — uppercase the first character.
fn ucfirst(s: &str) -> String {
  let mut chars = s.chars();
  match chars.next() {
    Some(c) => {
      let mut out = c.to_uppercase().to_string();
      out.push_str(chars.as_str());
      out
    }
    None => String::new(),
  }
}

/// `true` if the namespace's structure / tag table has an exact key — used
/// by the all-uppercase de-uglify guard (XMP.pm:3042-3047). Most names
/// pass through de-uglify; the exact-key case is rare.
fn struct_table_has_key(ns: &str, key: &str) -> bool {
  lookup_ns_table(ns).is_some_and(|t| lookup_field(t, key).is_some())
}

// ===========================================================================
// FoundXMP (XMP.pm:3435)
// ===========================================================================

impl Walker<'_> {
  /// `FoundXMP` short form — used for shorthand attribute properties.
  fn found_xmp(&mut self, props: &[SmolStr], val: &str, lang: Option<&str>) {
    self.found_xmp_full(props, val, lang, None);
  }

  /// Faithful port of `FoundXMP` (XMP.pm:3435). Assembles the tag id, looks
  /// up the namespace table, applies un-escape + XMPAutoConv + any
  /// PrintConv/ValueConv, and records a flattened tag.
  ///
  /// `datatype` is the `rdf:datatype`/`et:encoding` attribute (drives the
  /// base64-decode branch, XMP.pm:3645).
  fn found_xmp_full(
    &mut self,
    props: &[SmolStr],
    raw_val: &str,
    lang_attr: Option<&str>,
    datatype: Option<&str>,
  ) {
    let id = get_xmp_tag_id(props);
    if id.tag.is_empty() {
      return; // "ignore things that aren't valid tags" (XMP.pm:3441)
    }

    // Translate the namespace (XMP.pm:3444 — `$ns = $stdXlatNS{$ns}`).
    let ns = std_xlat_ns(&id.namespace)
      .map(ToString::to_string)
      .unwrap_or_else(|| id.namespace.clone());

    // Look up the per-namespace tag table.
    let table = lookup_ns_table(&ns);

    // The family-1 group is `XMP-<ns>` (XMP.pm:3717 SetGroup). The `xns`
    // value used for the group prefix is `xmpNS{ns}` (the standard XMP
    // prefix, restoring e.g. `iptcExt` → `Iptc4xmpExt`) — but the ExifTool
    // family-1 group uses the SHORT ExifTool ns (`XMP-iptcExt`).
    let group1 = if ns.is_empty() {
      SmolStr::new("XMP")
    } else {
      SmolStr::new(std::format!("XMP-{ns}"))
    };

    // ---- Tag-name + conversion via the namespace table ------------------
    // The tag id within a variable-namespace structure carries the XMP
    // namespace prefix; for a normal namespace table the id is the bare
    // tag. We resolve the FIELD (innermost) for conversion + Name remap.
    let field = resolve_field(table, &id, &ns);

    // ---- Lang-alt detection (XMP.pm:3617-3625) --------------------------
    // A tag is lang-alt if its definition says so OR (for unknown tags) if
    // the property path ends with `rdf:li N` inside an `rdf:Alt` AND an
    // `xml:lang` attr is present.
    let is_alt_list = props.len() >= 2
      && rdf_li_index(props[props.len() - 1].as_str()).is_some()
      && props[props.len() - 2].as_str() == "rdf:Alt";
    let is_bag_seq_list = props.len() >= 2
      && rdf_li_index(props[props.len() - 1].as_str()).is_some()
      && matches!(props[props.len() - 2].as_str(), "rdf:Bag" | "rdf:Seq");
    let writable = field.map(tables::Field::writable).unwrap_or(Writable::None);
    let lang_alt = matches!(writable, Writable::LangAlt) || (is_alt_list && lang_attr.is_some());

    // ---- Lang code (XMP.pm:3651-3655) -----------------------------------
    // A non-`x-default` lang on a lang-alt tag suffixes the tag name.
    let lang = match lang_attr {
      Some(l) if !l.eq_ignore_ascii_case("x-default") => Some(standard_lang_case(l)),
      _ => None,
    };

    // ---- Value decode: base64 (XMP.pm:3645), un-escape, XMPAutoConv -----
    // `DecodeBase64` returns a value REF; `FoundXMP` dereferences it to a
    // string ONLY when `length <= 100 AND no control bytes` (XMP.pm:3646-3647:
    // `$val = $$val unless length $$val > 100 or $$val =~ /[\0-\x08\x0b\0x0c\x0e-\x1f]/`),
    // otherwise the decoded bytes stay binary (see `base64_is_binary` — note the
    // `\0x0c` typo also makes the literal bytes `x`/`0`/`c` count as binary).
    let base64 = datatype.is_some_and(|dt| dt.contains("base64"));
    // `DecodeBase64` (XMP.pm:2981) never fails — it truncates malformed input
    // and decodes the surviving prefix — so a `base64` datatype ALWAYS yields
    // decoded bytes, never a fall-through to the undecoded XMP text.
    //
    // **Codex R5/F1:** decode the RAW XML text. Perl runs
    // `DecodeBase64($val)` (XMP.pm:3645) on the still-escaped value FIRST and
    // only THEN un-escapes (XMP.pm:3655-3669). Un-escaping before decode is
    // wrong: `aGVs&#x62;G8=` must truncate at `&` inside `DecodeBase64`
    // (→ `hel`), not turn into `aGVsbG8=` (→ `hello`); and `YSZhbXA7Yg==`
    // must decode to `a&amp;b` and only then un-escape to `a&b`.
    let decoded = base64.then(|| decode_base64(raw_val));
    let value = match decoded {
      // Binary branch: bytes stay binary, bypassing the un-escape /
      // XMPAutoConv / PrintConv pipeline (which in Perl runs on the ref,
      // leaving the bytes intact); `FoundTag` records it as binary data.
      Some(bytes) if base64_is_binary(&bytes) => XmpValue::Binary(bytes),
      // Text branch: the decoded bytes become a Perl string that then flows
      // through UnescapeXML (XMP.pm:3655-3669, CDATA-aware) + `Decode($val,
      // 'UTF8')` and, at JSON time, `EscapeJSON`'s `FixUTF8`. Perl order is
      // un-escape THEN UTF-8 decode (numeric entities like `&#xE9;` emit
      // UTF-8 bytes that `Decode`/`FixUTF8` then validate), so we un-escape
      // the decoded BYTES first and fold the lossy UTF-8 decode in via
      // `fix_utf8` (e.g. `FF D8 FF E0` → `????`).
      Some(bytes) => XmpValue::Scalar(scalar_from_text(
        crate::convert::fix_utf8(&unescape_value_with_cdata_bytes(&bytes)),
        field,
        writable,
      )),
      // No base64 datatype: the ordinary un-escaped value.
      None => XmpValue::Scalar(scalar_from_text(
        unescape_value_with_cdata(raw_val),
        field,
        writable,
      )),
    };

    // Resolve the final emitted tag name (Name remap).
    let name = field
      .and_then(tables::Field::name)
      .map(SmolStr::new)
      .unwrap_or_else(|| SmolStr::new(ucfirst(&id.tag)));

    // For lang-alt non-default-lang tags, the emitted tag name gets the
    // `-lang` suffix and is treated as its own (List) tag (XMP.pm:3651-3655
    // GetLangInfo).
    let final_name = match (&lang, lang_alt) {
      (Some(l), true) => SmolStr::new(std::format!("{name}-{l}")),
      _ => name.clone(),
    };

    // The `-lang` suffix must also brand the innermost structure-property
    // level: a lang-alt field NESTED inside a struct (`ArtworkOrObject` →
    // `AOTitle-de`) is a DISTINCT struct field per language, so
    // `RestoreStruct` must key it by the suffixed name (XMP.pm GetLangInfo
    // creates a separate flattened tag per language).
    let mut struct_props = apply_li_indices(id.struct_props, props, lang_alt);
    if let (Some(l), true) = (&lang, lang_alt)
      && let Some(last) = struct_props.last_mut()
    {
      last.name = SmolStr::new(std::format!("{}-{l}", last.name));
    }

    self.flat.push(FlatTag {
      tag_id: SmolStr::new(&id.tag),
      group1,
      name: final_name,
      value,
      struct_props,
      lang: if lang_alt { lang } else { None },
    });
    let _ = (is_bag_seq_list, &self.xmp_about);
  }

  /// Emit a recognized-attribute tag (`x:xmptk` → XMPToolkit etc.,
  /// XMP.pm:4128-4136). These bypass the namespace-table machinery.
  fn found_recognized(&mut self, group: &str, name: &str, value: &str) {
    self.flat.push(FlatTag {
      tag_id: SmolStr::new(name),
      group1: SmolStr::new(group),
      name: SmolStr::new(name),
      value: XmpValue::Scalar(XmpScalar::new(value)),
      struct_props: Vec::new(),
      lang: None,
    });
  }
}

/// Re-attach `rdf:li` indices to the structProps. `GetXMPTagID` already
/// records indices when it walks the path; this is a hook in case the
/// lang-alt list index must be dropped (lang-alt lists are NOT structures).
fn apply_li_indices(
  mut props: Vec<StructProp>,
  _full_props: &[SmolStr],
  lang_alt: bool,
) -> Vec<StructProp> {
  // A lang-alt tag's value lives in an `rdf:Alt`/`rdf:li` list, but the
  // lang-alt is FLATTENED to a single x-default scalar (or a `-<lang>`
  // suffixed tag) — it is NOT a structure list. `GetXMPTagID` records the
  // `rdf:li` index on the innermost contributing struct level regardless;
  // drop it here so `RestoreStruct` does not mistake the lang-alt entry for
  // a list item (XMP.pm:3651-3655 — lang-alt is handled before structs).
  if lang_alt && let Some(last) = props.last_mut() {
    last.index = None;
  }
  props
}

// ===========================================================================
// Namespace-table field resolution + conversions
// ===========================================================================

/// Resolve the per-namespace tag-table [`tables::Field`] for a tag id.
/// Faithful to the `$$tagTablePtr{$tag}` lookup in `FoundXMP` (XMP.pm:3460):
/// the innermost contributing key is looked up in the namespace's table.
fn resolve_field<'t>(
  table: Option<&'t NsTable>,
  id: &TagId,
  ns: &str,
) -> Option<&'t tables::Field> {
  // The innermost structure-prop name is the field key; for a plain tag the
  // whole id IS the key. ExifTool looks up the un-CamelCased property name.
  let key = id
    .struct_props
    .last()
    .map(|p| p.name.as_str())
    .unwrap_or(id.tag.as_str());

  // A nested-struct field — `[…, ParentStruct, ChildField]` — is resolved
  // against the parent's `Struct => { … }` sub-table (XMP.pm). This is tried
  // FIRST so a struct field shadowing a top-level tag of the same name
  // (e.g. `exif:Flash` struct's `Mode`) picks the struct's PrintConv.
  if id.struct_props.len() >= 2 {
    let parent = id.struct_props[id.struct_props.len() - 2].name.as_str();
    if let Some(f) = tables::lookup_struct_field(ns, parent, key) {
      return Some(f);
    }
  }

  lookup_field(table?, key)
}

/// Result of the XMPAutoConv + ValueConv pass — carries the post-ValueConv
/// numeric (`-n`) form (`FoundXMP`'s `$val` after `ConvertXMPDate` /
/// `ConvertRational`, XMP.pm:3673-3689).
struct ConvResult {
  /// Post-ValueConv numeric text — the `-n` output form.
  numeric: String,
}

/// Apply XMPAutoConv (`ConvertXMPDate` + `ConvertRational`) — faithful to
/// the auto-conversion block of `FoundXMP` (XMP.pm:3673-3689). With no
/// explicit `Writable` type (or with a `date`/`rational` Writable) the value
/// is run through the date + rational converters; an explicit non-date
/// non-rational Writable leaves the value untouched.
fn apply_value_conversions(
  val: &str,
  writable: Writable,
  value_conv: tables::ValueConv,
  is_default: bool,
) -> ConvResult {
  // XMPAutoConv is default-on; it applies to every tag WITHOUT an explicit
  // Writable type (the `IsDefault` case) and to `date`/`rational` Writables.
  let auto = is_default || matches!(writable, Writable::None);
  let want_date = auto || matches!(writable, Writable::Date);
  let want_rational = auto || matches!(writable, Writable::Rational);

  let mut out = val.to_string();
  if want_date {
    // `unsure` mirrors the Perl `$$tagInfo{Writable}` undef test — for an
    // explicit `date` Writable the converter is sure; for the auto path it
    // is "unsure" (does not coerce a bare YYYY-only value).
    let unsure = !matches!(writable, Writable::Date);
    let (converted, was_dt) = convert_xmp_date(&out, unsure);
    if was_dt || !unsure {
      out = converted;
    }
  }
  if want_rational && let Some(converted) = convert_rational(&out) {
    out = converted;
  }
  // The tag's explicit `ValueConv` runs AFTER XMPAutoConv's `ConvertRational`
  // (the rational string is already the decimal quotient here). XMP.pm
  // per-tag `ValueConv` — only the APEX aperture/shutter formulas are
  // modeled (`tables::ValueConv`).
  out = match value_conv {
    tables::ValueConv::None => out,
    // `sqrt(2) ** $val` (XMP.pm:2090) — Perl numeric context, no `IsFloat`
    // gate, so `$val` is coerced (e.g. a `ConvertRational`-rejected `+1/3`
    // coerces to `1`); use `perl_num`, not `f64::parse`.
    tables::ValueConv::ApexAperture => format_perl_num(2f64.sqrt().powf(perl_num(&out))),
    // `abs($val)<100 ? 1/(2**$val) : 0` (XMP.pm:2083) — same numeric-context
    // coercion of `$val`.
    tables::ValueConv::ApexShutter => {
      let v = perl_num(&out);
      if v.abs() < 100.0 {
        format_perl_num(1.0 / 2f64.powf(v))
      } else {
        "0".to_string()
      }
    }
    // `Image::ExifTool::GPS::ToDegrees($val, 1)` (GPS.pm:582): parse the
    // DMS coordinate string to signed decimal degrees (`-n` form). An
    // `inf`/`undef` token or an unparseable string yields `''` (GPS.pm:584),
    // matching ExifTool's empty-coordinate suppression.
    tables::ValueConv::GpsToDegrees => gps_to_degrees(&out),
    // `$val == 0xffffffff ? 0xffff : $val` (XMP.pm:2003 — `exif:ColorSpace`).
    // `Writable => 'integer'` means XMPAutoConv's `ConvertRational` did NOT
    // run, so `out` is still the raw integer string here.
    tables::ValueConv::ColorSpace => convert_color_space(&out),
    // `\&ConvertRationalList` (XMP.pm:2600 — `aux:LensInfo`). `aux:LensInfo`
    // has no explicit `Writable` (plain-string default), so XMPAutoConv's
    // `ConvertRational` did NOT pre-convert the value — `ConvertRationalList`
    // operates on the raw whitespace-joined `N/D N/D N/D N/D` string.
    tables::ValueConv::RationalList => convert_rational_list(&out),
  };
  ConvResult { numeric: out }
}

/// Apply a namespace-table `PrintConv` — faithful to `FoundXMP`'s PrintConv
/// dispatch (XMP.pm:3493). The `tables::PrintConv` enum carries either an
/// inline `key => label` hash (ported verbatim from the bundled tag table)
/// or one of the EXIF shared formula converters; an unmapped numeric value
/// passes through unchanged (ExifTool's `PrintConv` hash-miss behavior).
fn apply_print_conv(numeric: &str, field: &tables::Field) -> String {
  use tables::PrintConv;
  match field.print_conv() {
    PrintConv::Identity => numeric.to_string(),
    PrintConv::IntMap(map) => {
      // ExifTool's PrintConv hash lookup is `$$conv{$val}` — a Perl hash keyed
      // by the EXACT scalar STRING, with NO integer coercion (ExifTool.pm:3604).
      // A miss returns `Unknown ($val)` (ExifTool.pm:3622). So `"05"` keys the
      // string `05` (not the int 5 → it does NOT collapse to `Multi-segment`)
      // and `"99"` (no key) ⇒ `Unknown (99)` (Codex R1/F3). The integer keys
      // are stringified to compare against the raw scalar.
      map
        .iter()
        .find_map(|&(k, v)| (k.to_string() == numeric).then(|| v.to_string()))
        .unwrap_or_else(|| std::format!("Unknown ({numeric})"))
    }
    PrintConv::IntMapPassthrough(map) => {
      // Same `$$conv{$val}` exact-string lookup as `IntMap`, but the bundled
      // hash carries an `OTHER => sub` whose READ branch returns `$val`
      // unchanged (XMP.pm:2634-2638) — so a miss passes the value through
      // as-is, NOT `Unknown ($val)`. The `aux:ApproximateFocusDistance`
      // value has already been `ConvertRational`-converted (a `rational`
      // Writable), so e.g. `4294967295/1` arrives here as `4294967295` and
      // keys the `4294967295 => 'infinity'` row; `53/10` arrives as `5.3`
      // (a hash miss) and the OTHER sub returns it unchanged.
      map
        .iter()
        .find_map(|&(k, v)| (k.to_string() == numeric).then(|| v.to_string()))
        .unwrap_or_else(|| numeric.to_string())
    }
    PrintConv::StrMap(map) => map
      .iter()
      .find_map(|&(k, v)| (k == numeric).then(|| v.to_string()))
      .unwrap_or_else(|| std::format!("Unknown ({numeric})")),
    // `\&Image::ExifTool::Exif::PrintLensInfo` (XMP.pm:2615 — `aux:LensInfo`).
    PrintConv::LensInfo => print_lens_info(numeric),
    PrintConv::Bool => match numeric.to_ascii_lowercase().as_str() {
      // `%boolConv` (XMP.pm:246): case-insensitive `true`/`false` → titlecase.
      "true" => "True".to_string(),
      "false" => "False".to_string(),
      _ => numeric.to_string(),
    },
    PrintConv::ExposureTime => print_exposure_time(numeric),
    PrintConv::FNumber => print_f_number(numeric),
    PrintConv::Fraction => print_fraction(numeric),
    // `sprintf("%.1f",$val)` (XMP.pm:2091 — `ApertureValue`/`MaxApertureValue`)
    // and `sprintf("%.1f mm",$val)` (XMP.pm:2164 — `FocalLength`): raw Perl
    // `sprintf`, NO `IsFloat` gate, so `$val` is coerced (Codex R12
    // class-sweep — `f64::parse` rejects a `ConvertRational`-untouched
    // `+50/1` that Perl coerces to `50`).
    PrintConv::Fixed1 => sprintf_f1(perl_num(numeric)),
    PrintConv::FocalMm => std::format!("{} mm", sprintf_f1(perl_num(numeric))),
    PrintConv::Mm => std::format!("{numeric} mm"),
    PrintConv::Metres => {
      if numeric == "inf" || numeric == "undef" {
        numeric.to_string()
      } else {
        std::format!("{numeric} m")
      }
    }
    PrintConv::MetresPlain => std::format!("{numeric} m"),
    // `Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)` (GPS.pm:495): the
    // input is the signed decimal-degrees `ValueConv` output; render
    // `D deg M' S.SS" <ref>`. An empty value (ToDegrees suppressed it) is
    // passed through unchanged (GPS.pm:500-503 `$doPrintConv eq '1'`).
    PrintConv::GpsToDms(ref_byte) => gps_to_dms(numeric, ref_byte),
  }
}

/// `Image::ExifTool::GPS::ToDegrees($val, 1)` (GPS.pm:582) — parse a string
/// holding 1-3 decimal numbers (any surrounding garbage) into signed decimal
/// degrees. Returns `""` for an `inf`/`undef` token or a value with no
/// extractable number (GPS.pm:584/590), and negates for an S/W cardinal
/// suffix (`$doSign` is always true at the XMP `%latConv`/`%longConv` call).
fn gps_to_degrees(val: &str) -> String {
  // `return '' if $val =~ /\b(inf|undef)\b/` (GPS.pm:584).
  if has_word(val, "inf") || has_word(val, "undef") {
    return String::new();
  }
  // Extract up to 3 signed decimal/float numbers (GPS.pm:592 regex
  // `(?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee][+-]\d+)?`).
  let nums = extract_gps_numbers(val);
  let Some(&d) = nums.first() else {
    return String::new(); // `return '' unless defined $d` (GPS.pm:593)
  };
  let m = nums.get(1).copied().unwrap_or(0.0);
  let s = nums.get(2).copied().unwrap_or(0.0);
  // `$deg = $d + (($m||0) + ($s||0)/60) / 60` (GPS.pm:594).
  let mut deg = d + (m + s / 60.0) / 60.0;
  // `$deg = -$deg if $val =~ /[^A-Z](S(outh)?|W(est)?)\s*$/i` (GPS.pm:596,
  // `$doSign` branch). The `[^A-Z]` guard (case-insensitive) means the
  // S/W letter must be preceded by a non-letter (or be at string start).
  if ends_with_south_west(val) {
    deg = -deg;
  }
  format_perl_num(deg)
}

/// Extract the leading sign-and-decimal numbers from a GPS coordinate string
/// (GPS.pm:592 `/((?:[+-]?)(?=\d|\.\d)\d*(?:\.\d*)?(?:[Ee][+-]\d+)?)/g`), up
/// to the first three. A match requires a digit or `.<digit>` lookahead.
fn extract_gps_numbers(val: &str) -> Vec<f64> {
  let bytes = val.as_bytes();
  let mut out: Vec<f64> = Vec::new();
  let mut i = 0;
  while i < bytes.len() && out.len() < 3 {
    let start = i;
    let mut j = i;
    // optional sign
    if j < bytes.len() && (bytes[j] == b'+' || bytes[j] == b'-') {
      j += 1;
    }
    // lookahead: `\d` or `.\d`
    let has_digit = j < bytes.len() && bytes[j].is_ascii_digit();
    let has_dot_digit = j + 1 < bytes.len() && bytes[j] == b'.' && bytes[j + 1].is_ascii_digit();
    if !has_digit && !has_dot_digit {
      i += 1;
      continue;
    }
    // integer digits `\d*`
    while j < bytes.len() && bytes[j].is_ascii_digit() {
      j += 1;
    }
    // fraction `(?:\.\d*)?`
    if j < bytes.len() && bytes[j] == b'.' {
      j += 1;
      while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
      }
    }
    // exponent `(?:[Ee][+-]\d+)?`
    if j < bytes.len() && (bytes[j] == b'E' || bytes[j] == b'e') {
      let mut k = j + 1;
      if k < bytes.len() && (bytes[k] == b'+' || bytes[k] == b'-') {
        k += 1;
        if k < bytes.len() && bytes[k].is_ascii_digit() {
          while k < bytes.len() && bytes[k].is_ascii_digit() {
            k += 1;
          }
          j = k;
        }
      }
    }
    if let Ok(v) = val[start..j].parse::<f64>() {
      out.push(v);
    }
    i = j.max(start + 1);
  }
  out
}

/// `$val =~ /[^A-Z](S(outh)?|W(est)?)\s*$/i` (GPS.pm:596): the coordinate
/// ends in an `S`/`W` (or `South`/`West`) cardinal whose letter is preceded
/// by a non-`A-Z` character (case-insensitive).
fn ends_with_south_west(val: &str) -> bool {
  let trimmed = val.trim_end();
  let lower = trimmed.to_ascii_lowercase();
  for tail in ["south", "west", "s", "w"] {
    if let Some(prefix) = lower.strip_suffix(tail) {
      // `[^A-Z]` (case-insensitive ⇒ `[^A-Za-z]`) must precede the letter,
      // OR the letter is at the very start of the string.
      match prefix.chars().last() {
        None => return true,
        Some(c) if !c.is_ascii_alphabetic() => return true,
        _ => {}
      }
    }
  }
  false
}

/// `Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)` (GPS.pm:495) with
/// `$doPrintConv == 1` and a hemisphere `$ref` — the XMP `%latConv`/`%longConv`
/// PrintConv. The input is signed decimal degrees; emit
/// `%d deg %d' %.2f" <ref>` (the default `CoordFormat`). A negative value
/// flips the reference (N→S, E→W). An empty input passes through (GPS.pm:500).
fn gps_to_dms(numeric: &str, ref_byte: u8) -> String {
  if numeric.is_empty() {
    return String::new();
  }
  let Ok(mut val) = numeric.parse::<f64>() else {
    return numeric.to_string();
  };
  // `$ref` flip + abs (GPS.pm:505-514, with `$ref` always set here).
  let cardinal = if val < 0.0 {
    val = -val;
    match ref_byte {
      b'N' => 'S',
      b'E' => 'W',
      other => other as char,
    }
  } else {
    ref_byte as char
  };
  // Default `CoordFormat`: `%d deg %d' %.2f"` + ` <ref>` (GPS.pm:526-527).
  // num = 3 specifiers (GPS.pm:537-541).
  let mut d = val.trunc();
  let m_full = (val - d) * 60.0;
  let mut m = m_full.trunc();
  let s = (val - d - m / 60.0) * 3600.0;
  // Round-off handling (GPS.pm:557-563): the LAST coordinate (seconds) is
  // `$c[-1] = sprintf($fmt[-1], $c[-1])` FIRST (rounded to a string), then the
  // carry compares + subtracts on that ROUNDED string-as-number
  // (`$c[-1] -= 60`), and the final `sprintf($fmt, @c)` re-renders it. So the
  // subtraction operates on the rounded value (e.g. `"60.00" - 60 == 0`),
  // *not* the original unrounded `$c[-1]` — otherwise a value like
  // `59.999999996` would carry to `-0.00` instead of `0.00`. A minute overflow
  // carries into degrees (`$c[-2] -= 60, $c[-3] += 1`).
  let s_rounded = std::format!("{s:.2}").parse::<f64>().unwrap_or(0.0);
  let s_str = if s_rounded >= 60.0 {
    let carried = s_rounded - 60.0;
    m += 1.0;
    if m >= 60.0 {
      m -= 60.0;
      d += 1.0;
    }
    std::format!("{carried:.2}")
  } else {
    std::format!("{s_rounded:.2}")
  };
  std::format!("{} deg {}' {}\" {}", d as i64, m as i64, s_str, cardinal)
}

/// `$str =~ /\b<word>\b/` — a word-boundaried case-sensitive match used by
/// `gps_to_degrees` for the `inf`/`undef` suppression (GPS.pm:584). The Perl
/// pattern is case-sensitive (no `/i`).
fn has_word(s: &str, word: &str) -> bool {
  let bytes = s.as_bytes();
  let wbytes = word.as_bytes();
  let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
  let mut i = 0;
  while let Some(off) = find_sub(&bytes[i..], wbytes) {
    let start = i + off;
    let end = start + wbytes.len();
    let left_ok = start == 0 || !is_word(bytes[start - 1]);
    let right_ok = end >= bytes.len() || !is_word(bytes[end]);
    if left_ok && right_ok {
      return true;
    }
    i = start + 1;
  }
  false
}

/// `Image::ExifTool::Exif::PrintExposureTime` (Exif.pm:5701-5712). A float
/// `< 0.25` renders as `1/N`; otherwise one-decimal with a trailing `.0`
/// trimmed.
///
/// Codex R12 class-sweep: `PrintExposureTime` opens `return $secs unless
/// IsFloat($secs)` (Exif.pm:5704), so a non-`IsFloat` value passes through
/// VERBATIM. Rust `f64::parse` is not the same gate — it ACCEPTS `inf`/
/// `infinity`/`nan` (which `IsFloat`'s `^[+-]?(?=\d|\.\d)…$` regex rejects),
/// so a literal `nan` `exif:ShutterSpeedValue` would wrongly format as
/// `NaN` instead of staying `nan`. Gate with [`is_perl_float`]; once it
/// passes, the value is a clean numeric string that `f64::parse` reads
/// identically to Perl's coercion.
fn print_exposure_time(val: &str) -> String {
  if !is_perl_float(val) {
    return val.to_string();
  }
  let Ok(secs) = val.parse::<f64>() else {
    return val.to_string();
  };
  if secs > 0.0 && secs < 0.250_01 {
    return std::format!("1/{}", (0.5 + 1.0 / secs) as i64);
  }
  let s = std::format!("{secs:.1}");
  s.strip_suffix(".0").map_or(s.clone(), ToString::to_string)
}

/// `Image::ExifTool::Exif::PrintFNumber` (Exif.pm:5715-5725). Rounds to 1
/// decimal (2 for values `< 1.0`).
///
/// Codex R12 class-sweep: `PrintFNumber` gates with `IsFloat($val) and $val
/// > 0` (Exif.pm:5719) — anything else falls through to `return $val`. As
/// with `PrintExposureTime`, Rust `f64::parse` is a looser gate than
/// `IsFloat` (it accepts `inf`/`nan`), so gate with [`is_perl_float`] first.
fn print_f_number(val: &str) -> String {
  // `is_perl_float` ⇒ the string is a clean float `f64::parse` reads
  // identically; the `> 0` half of the Perl guard then selects the format.
  match val.parse::<f64>() {
    Ok(v) if is_perl_float(val) && v > 0.0 => {
      if v < 1.0 {
        std::format!("{v:.2}")
      } else {
        std::format!("{v:.1}")
      }
    }
    _ => val.to_string(),
  }
}

/// `Image::ExifTool::Exif::PrintFraction` (Exif.pm:5516-5535). Renders a
/// signed fraction (`+1`, `+1/2`, `+1/3`) or a `%+.3g` form.
///
/// Codex R12 class-sweep: `PrintFraction` runs `$val *= 1.00001` DIRECTLY,
/// with NO `IsFloat` gate (unlike `PrintExposureTime`/`PrintFNumber`) — so
/// `$val` undergoes plain Perl numeric coercion. After the F1 fix
/// `ConvertRational` correctly leaves a `+1/3` `exif:ExposureBiasValue`
/// untouched, so `PrintConv` here receives the literal `"+1/3"`; Perl
/// coerces it to `1` (oracle `-j` ⇒ `+1`, verified vs bundled 13.58),
/// whereas Rust `f64::parse` rejects the `/3` and would return `"+1/3"`
/// unchanged. Coerce with [`perl_num`].
fn print_fraction(val: &str) -> String {
  let mut v = perl_num(val);
  v *= 1.000_01; // avoid round-off errors (Exif.pm:5520)
  if v == 0.0 {
    return "0".to_string();
  }
  let int = v.trunc();
  if int != 0.0 && int / v > 0.999 {
    return std::format!("{:+}", int as i64);
  }
  let v2 = v * 2.0;
  if (v2.trunc()) / v2 > 0.999 {
    return std::format!("{:+}/2", v2.trunc() as i64);
  }
  let v3 = v * 3.0;
  if (v3.trunc()) / v3 > 0.999 {
    return std::format!("{:+}/3", v3.trunc() as i64);
  }
  // `sprintf("%+.3g", $val)` — 3 significant digits, signed. Perl's `%+g`
  // of a non-finite NV is `+Inf`/`-Inf`/`NaN` (NaN takes no sign — verified
  // vs Perl 5); a finite value gets the explicit `+`/`-`. (Reachable when
  // `ConvertRational` feeds the literal `inf` token of a `1/0`
  // `exif:ExposureBiasValue` — oracle `-j` ⇒ `+Inf`.)
  if let Some(nonfinite) = crate::value::perl_nonfinite_str(v) {
    // `perl_nonfinite_str` already prefixes `-Inf`; `+Inf` needs the sign.
    return if v.is_sign_positive() && v.is_infinite() {
      std::format!("+{nonfinite}")
    } else {
      nonfinite.to_string()
    };
  }
  let sign = if v < 0.0 { "" } else { "+" };
  std::format!("{sign}{}", format_g3(v))
}

/// `%.3g`-style formatting (3 significant digits). Callers gate non-finite
/// inputs (`print_fraction` handles `Inf`/`NaN` before this point), so `v`
/// is always finite here.
fn format_g3(v: f64) -> String {
  if v == 0.0 {
    return "0".to_string();
  }
  let exp = v.abs().log10().floor() as i32;
  if (-4..3).contains(&exp) {
    let decimals = (2 - exp).max(0) as usize;
    let mut s = std::format!("{v:.*}", decimals);
    if s.contains('.') {
      s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    s
  } else {
    let mant = v / 10f64.powi(exp);
    let mut m = std::format!("{mant:.2}");
    m = m.trim_end_matches('0').trim_end_matches('.').to_string();
    std::format!("{m}e{exp}")
  }
}

/// Normalize a language code to the `-<lang>` tag-name suffix form ExifTool
/// emits: `StandardLangCase` (XMP.pm:3239) followed by `GetLangInfo`'s
/// underscore→hyphen pass (XMP.pm:3230). The two run together at the
/// `FoundXMP` lang-alt call site (XMP.pm:3651-3652: `$lang =
/// StandardLangCase($lang); GetLangInfo($tagInfo, $lang)`), so this models
/// both — SLC FIRST, then `tr/_/-/` (Codex R1/F4).
///
/// `StandardLangCase` regex `^([a-z]{2,3}|[xi])(-[a-z]{2})\b(.*)/i` matches
/// ⇒ `lc(lang) . uc(2-letter-2nd-subtag) . lc(rest)`; no match ⇒ `lc(entire)`.
/// Only a 2-LETTER 2nd subtag (with a `\b` boundary after it) is uppercased;
/// a 3+-letter script subtag (`zh-Hant`), a digit region (`es-419`), or an
/// underscore separator falls through to all-lowercase. Examples:
/// `en-us-x-private` → `en-US-x-private`; `zh-Hant-CN` → `zh-hant-cn`;
/// `de_DE` → `de-de`.
fn standard_lang_case(lang: &str) -> String {
  let cased = standard_lang_case_inner(lang);
  // `GetLangInfo`: `$langCode =~ tr/_/-/` (XMP.pm:3230).
  cased.replace('_', "-")
}

/// `StandardLangCase($lang)` (XMP.pm:3239) — the case-folding pass, WITHOUT
/// the separate `GetLangInfo` underscore normalization.
fn standard_lang_case_inner(lang: &str) -> String {
  // `^([a-z]{2,3}|[xi])(-[a-z]{2})\b(.*)` (case-insensitive). The first
  // subtag is 2-3 ASCII letters or a single `x`/`i`; the 2nd subtag is
  // exactly `-<2 letters>` with a `\b` word boundary after it.
  let bytes = lang.as_bytes();
  let is_alpha = |b: u8| b.is_ascii_alphabetic();

  // Group 1: `[a-z]{2,3}` or `[xi]` (single char). Try the longest first so
  // a 3-letter primary subtag is not mis-split, but the alternation also
  // allows a lone `x`/`i`. Perl's regex is greedy with backtracking; the
  // `(-[a-z]{2})\b` that follows pins where group 1 ends.
  for g1_len in [3usize, 2, 1] {
    if g1_len == 1 {
      // `[xi]` single-letter alternative.
      let is_xi = bytes
        .first()
        .is_some_and(|&b| matches!(b, b'x' | b'X' | b'i' | b'I'));
      if !is_xi {
        continue;
      }
    } else if bytes.len() < g1_len || !bytes[..g1_len].iter().all(|&b| is_alpha(b)) {
      continue;
    }
    // Group 2: `-[a-z]{2}` immediately after group 1.
    let g2_start = g1_len;
    if bytes.len() < g2_start + 3
      || bytes[g2_start] != b'-'
      || !is_alpha(bytes[g2_start + 1])
      || !is_alpha(bytes[g2_start + 2])
    {
      continue;
    }
    // `\b` after the 2nd subtag: the char following the 2 letters must NOT be
    // a word char (alphanumeric/underscore), or be end-of-string. This is
    // what rejects `zh-Hant` (3rd letter `n` ⇒ no boundary).
    let after = g2_start + 3;
    let boundary = after >= bytes.len() || !is_word_byte(bytes[after]);
    if !boundary {
      continue;
    }
    let g1 = lang[..g1_len].to_ascii_lowercase();
    let g2 = lang[g2_start..after].to_ascii_uppercase();
    let g3 = lang[after..].to_ascii_lowercase();
    return std::format!("{g1}{g2}{g3}");
  }
  // No match ⇒ `lc($lang)`.
  lang.to_ascii_lowercase()
}

/// Perl `\w` byte test (ASCII): alphanumeric or underscore.
fn is_word_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether decoded base64 bytes are kept as BINARY rather than coerced to
/// text — faithful to the `unless` guard in `FoundXMP` (XMP.pm:3647):
/// `$val = $$val unless length $$val > 100 or $$val =~ /[\0-\x08\x0b\0x0c\x0e-\x1f]/`.
/// So bytes stay binary when their length is `> 100` OR any byte is in the
/// (literally-parsed) Perl character class.
///
/// `\0x0c` in the Perl class is a TYPO ExifTool 13.58 ships verbatim: it is NOT
/// `\x0c` (FF). Perl parses `\0x0c` as `\0` (NUL, already covered by `\0-\x08`)
/// FOLLOWED BY the three LITERAL characters `x`, `0`, `c`. So the full class is
/// `\0-\x08`, `\x0b` (VT), `\x0e-\x1f`, PLUS the literal bytes `x` (0x78), `0`
/// (0x30), `c` (0x63). `\x09` (tab), `\x0a` (LF), `\x0c` (FF) and `\x0d`
/// (CR) are NOT members of the class. Verified against bundled 13.58 via the
/// oracle (`rdf:datatype="base64"`): `cat`/`x`/`0`/`c` decode to a binary
/// placeholder (payload contains x/0/c), while `dog`/`9`/`hi`/`test`/single-FF/
/// single-tab/single-LF/single-CR stay text and single-VT (`\x0b`) /
/// single-`\x0e` are binary. A faithful 1:1 port MUST reproduce the typo,
/// hence the `b'x'`/`b'0'`/`b'c'` arms below.
fn base64_is_binary(bytes: &[u8]) -> bool {
  bytes.len() > 100
    || bytes
      .iter()
      .any(|&b| matches!(b, 0x00..=0x08 | 0x0b | 0x0e..=0x1f | b'x' | b'0' | b'c'))
}

/// Build a [`XmpScalar`] from already-unescaped text — the shared
/// XMPAutoConv (`ConvertXMPDate` + `ConvertRational`) + PrintConv tail of
/// `FoundXMP` (XMP.pm:3673-3689), producing BOTH the `-n` (numeric) and `-j`
/// (print) forms.
fn scalar_from_text(val: String, field: Option<&tables::Field>, writable: Writable) -> XmpScalar {
  let is_default = field.is_none();
  let value_conv = field
    .map(tables::Field::value_conv)
    .unwrap_or(tables::ValueConv::None);
  let converted = apply_value_conversions(&val, writable, value_conv, is_default);
  let print_value = field
    .map(|f| apply_print_conv(&converted.numeric, f))
    .unwrap_or_else(|| converted.numeric.clone());
  XmpScalar::with_print(converted.numeric, print_value)
}

/// `DecodeBase64` (XMP.pm:2981) — faithful port of the two-step Perl decode.
///
/// Step 1 (XMP.pm:2988, `s/[^A-Za-z0-9+\/= \t\n\r\f].*//s`): truncate at the
/// FIRST byte not in the allow-list `[A-Za-z0-9+/= \t\n\r\f]`, discarding it
/// and everything after (e.g. `aGVsbG8=#junk` → `aGVsbG8=`; a VT `\x0b` is NOT
/// in the list, so `aGVs\x0bbG8=` → `aGVs`).
///
/// Step 2 (XMP.pm:2990, `tr/A-Za-z0-9+\/= \t\n\r\f/ -_/d`): map the base64
/// alphabet to six-bit values, deleting padding/whitespace `= \t\n\r\f` and
/// space (the `tr` replacement list runs out before these, so `/d` drops
/// them), then decode the surviving prefix even if it is a partial group
/// (e.g. unpadded `aGVsbG8` → `hello`).
///
/// Like the Perl, this NEVER fails: malformed input yields the bytes decoded
/// from the surviving prefix (possibly empty), never a fall-back to raw text.
fn decode_base64(s: &str) -> Vec<u8> {
  fn sextet(c: u8) -> Option<u8> {
    match c {
      b'A'..=b'Z' => Some(c - b'A'),
      b'a'..=b'z' => Some(c - b'a' + 26),
      b'0'..=b'9' => Some(c - b'0' + 52),
      b'+' => Some(62),
      b'/' => Some(63),
      _ => None,
    }
  }
  let mut out = Vec::new();
  let mut buf = 0u32;
  let mut bits = 0u32;
  for &c in s.as_bytes() {
    // Step 1: stop at the first byte outside the allow-list. `= \t\n\r\f` and
    // space are inside the list but ignored by step 2; everything else not a
    // base64 digit (incl. VT `\x0b`) truncates the remainder.
    if c == b'=' || c.is_ascii_whitespace() {
      continue;
    }
    let Some(v) = sextet(c) else { break };
    buf = (buf << 6) | u32::from(v);
    bits += 6;
    if bits >= 8 {
      bits -= 8;
      out.push((buf >> bits) as u8);
    }
  }
  out
}

// ===========================================================================
// RestoreStruct (XMPStruct.pl:708) — rebuild nested structs from flat tags
// ===========================================================================

/// Rebuild structured (`-struct`) values from the flattened `FoundXMP`
/// captures — faithful port of `RestoreStruct` (XMPStruct.pl:708) plus the
/// post-walk `FoundTag` emission. Flat tags whose `struct_props` describe a
/// nested path are merged into one [`XmpTag`] carrying an
/// [`XmpValue::Struct`] / [`XmpValue::List`] tree; plain tags pass through.
///
/// Lang-alt list entries are NOT structures (XMP.pm:3651-3655) — each
/// non-default-language entry is emitted as its own `<Name>-<lang>` tag (the
/// `lang` suffix was already baked into `FlatTag::name` by `found_xmp_full`).
fn restore_struct(flat: Vec<FlatTag>) -> (Vec<XmpTag>, Option<String>) {
  // Group by `(group1, top-level-name)` in first-occurrence order.
  let mut order: Vec<(SmolStr, SmolStr)> = Vec::new();
  let mut groups: BTreeMap<(SmolStr, SmolStr), Vec<FlatTag>> = BTreeMap::new();
  for ft in flat {
    let key = (ft.group1.clone(), top_level_name(&ft));
    if !groups.contains_key(&key) {
      order.push(key.clone());
    }
    groups.entry(key).or_default().push(ft);
  }

  let mut out = Vec::new();
  let mut warning: Option<String> = None;
  for key in order {
    let members = groups.remove(&key).unwrap_or_default();
    let (group, name) = key;
    // "X is not a structure!" (XMPStruct.pl:731). `RestoreStruct` looks the
    // top-level `$tag` up in the tag table; when that entry already exists
    // as a plain (non-`Struct`) tag — i.e. the property carried its OWN
    // literal value (a `struct_props` length-≤1 member) — yet a child
    // shorthand attr added a deeper-path member (`struct_props` length > 1),
    // the rebuild aborts and every member is left flat. This is exactly the
    // `et:encoding`-on-a-value shape: `<foo:payload et:encoding="…">val<…>`
    // yields a `Payload` leaf AND a `Payload`→`Encoding` sub-field.
    let has_leaf_parent = members.iter().any(|m| m.struct_props.len() <= 1);
    let has_substruct = members.iter().any(|m| m.struct_props.len() > 1);
    if has_leaf_parent && has_substruct {
      if warning.is_none() {
        warning = Some(std::format!("{name} is not a structure!"));
      }
      // Keep every member flat under its own emitted flat name.
      for m in members {
        out.push(XmpTag {
          group: m.group1,
          name: m.name,
          value: m.value,
        });
      }
      continue;
    }
    let value = build_value(&members);
    out.push(XmpTag { group, name, value });
  }
  (out, warning)
}

/// The top-level emitted tag name for a flat tag — the first
/// structure-property level, or the flat `name` for a plain tag.
fn top_level_name(ft: &FlatTag) -> SmolStr {
  match ft.struct_props.first() {
    Some(p) if ft.struct_props.len() > 1 => SmolStr::new(ucfirst(p.name.as_str())),
    _ => ft.name.clone(),
  }
}

/// Build the (possibly nested) [`XmpValue`] for one `(group, name)` group of
/// flat tags. A single plain member yields its scalar/list directly; members
/// with deeper `struct_props` are merged into a nested struct/list tree.
fn build_value(members: &[FlatTag]) -> XmpValue {
  // Plain (non-structured) tag: a single member with ≤1 struct level AND no
  // list index on that level. A single struct-prop carrying a `rdf:li`
  // index is a one-element `rdf:Bag`/`Seq`/`Alt` — ExifTool keeps it as a
  // List even with one item (XMP.pm `List` Writable), so it must NOT
  // collapse to a scalar.
  if members.len() == 1
    && members[0].struct_props.len() <= 1
    && members[0]
      .struct_props
      .first()
      .is_none_or(|p| p.index.is_none())
  {
    return members[0].value.clone();
  }
  // Multiple members or nested levels — rebuild the tree from struct_props.
  // The root node IS the tag itself: `struct_props[0]`'s NAME is the tag
  // (already consumed by `top_level_name`) but its INDEX is load-bearing —
  // a `rdf:li` index on the top level means the tag is a list/array. So we
  // feed `struct_props[0..]` and let `StructNode::insert` consume the head
  // level's index (its name is dropped at the root — see `insert_root`).
  let mut root = StructNode::default();
  for ft in members {
    root.insert_root(&ft.struct_props, ft.value.clone());
  }
  root.into_value()
}

/// A transient node in the struct-rebuild tree.
#[derive(Default)]
struct StructNode {
  /// Ordered child fields (struct) — `(field-name, child)`.
  fields: Vec<(SmolStr, StructNode)>,
  /// Ordered list items (`rdf:Bag`/`Seq`/`Alt`) — `(index, child)`.
  items: Vec<(String, StructNode)>,
  /// Leaf scalar/list value, if this node is a terminal.
  leaf: Option<XmpValue>,
}

impl StructNode {
  /// Find-or-create a list item child keyed by `idx`.
  fn item_mut(&mut self, idx: &str) -> &mut StructNode {
    if let Some(pos) = self.items.iter().position(|(i, _)| i == idx) {
      return &mut self.items[pos].1;
    }
    self.items.push((idx.to_string(), StructNode::default()));
    &mut self.items.last_mut().expect("just pushed").1
  }

  /// Find-or-create a struct field child keyed by `name` (ucfirst'd).
  fn field_mut(&mut self, name: &str) -> &mut StructNode {
    let key = SmolStr::new(ucfirst(name));
    if let Some(pos) = self.fields.iter().position(|(n, _)| *n == key) {
      return &mut self.fields[pos].1;
    }
    self.fields.push((key, StructNode::default()));
    &mut self.fields.last_mut().expect("just pushed").1
  }

  /// Insert at the root: `path[0]` is the tag-name level. Its NAME is
  /// already consumed by `top_level_name`; only its `rdf:li` INDEX (if any)
  /// is load-bearing — it makes the root a list. `path[1..]` is the
  /// structure below the tag.
  fn insert_root(&mut self, path: &[StructProp], value: XmpValue) {
    let Some((head, rest)) = path.split_first() else {
      self.leaf = Some(value);
      return;
    };
    match &head.index {
      // The tag itself is a list — one item per `rdf:li` index.
      Some(idx) => self.item_mut(idx).insert(rest, value),
      // Plain top-level (struct or scalar).
      None => self.insert(rest, value),
    }
  }

  /// Insert a value at the given structure-property path. Each
  /// [`StructProp`] carries a field NAME and, when that field's value is a
  /// `rdf:Bag`/`Seq`/`Alt`, an `rdf:li` INDEX: `{name, Some(idx)}` means
  /// "field `name`, then list item `idx` within it".
  fn insert(&mut self, path: &[StructProp], value: XmpValue) {
    let Some((head, rest)) = path.split_first() else {
      self.leaf = Some(value);
      return;
    };
    let field = self.field_mut(head.name.as_str());
    match &head.index {
      // The field's value is a list — descend into the indexed item.
      Some(idx) => field.item_mut(idx).insert(rest, value),
      None => field.insert(rest, value),
    }
  }

  /// Collapse this node into an [`XmpValue`].
  fn into_value(self) -> XmpValue {
    if let Some(leaf) = self.leaf {
      return leaf;
    }
    if !self.items.is_empty() {
      // Items are keyed by ExifTool's zero-padded index — sort by it.
      let mut items = self.items;
      items.sort_by(|a, b| a.0.cmp(&b.0));
      return XmpValue::List(items.into_iter().map(|(_, n)| n.into_value()).collect());
    }
    let mut st = XmpStruct::new();
    for (name, node) in self.fields {
      st.push_field(name, node.into_value());
    }
    XmpValue::Struct(st)
  }
}

// ===========================================================================
// Blank-node info (SaveBlankInfo / ProcessBlankInfo, WriteXMP.pl:419/456)
// ===========================================================================

/// Record a value under a blank-node (`rdf:nodeID`) reference — faithful to
/// `SaveBlankInfo` (WriteXMP.pl:419). The `nodeID` is encoded in a
/// `prop_list` entry as a ` #<id>` suffix (see the `parse_element`
/// node-id handling). When no node id is present in the path this is a
/// no-op (the value was already emitted via the normal `FoundXMP` path).
fn save_blank_info(blank: &mut BlankInfo, prop_list: &[SmolStr], val: &str, _extra: Option<()>) {
  // Find the path segment carrying a ` #<id>` node-id suffix.
  let Some((split_at, node_id)) = prop_list.iter().enumerate().find_map(|(i, p)| {
    p.as_str()
      .rfind(" #")
      .map(|j| (i, p.as_str()[j + 2..].to_string()))
  }) else {
    return;
  };
  let pre: String = prop_list[..split_at]
    .iter()
    .map(SmolStr::as_str)
    .collect::<Vec<_>>()
    .join("/");
  let post: Vec<SmolStr> = prop_list[split_at + 1..].to_vec();
  let post_key = post
    .iter()
    .map(SmolStr::as_str)
    .collect::<Vec<_>>()
    .join("/");
  let node = blank.prop.entry(node_id).or_default();
  node.pre.insert(pre, ());
  node.post.insert(post_key, (val.to_string(), post.clone()));
}

/// Resolve blank-node references into emitted tags — faithful to
/// `ProcessBlankInfo` (WriteXMP.pl:456). For each blank node, every
/// recorded subject path-prefix is concatenated with every recorded
/// property suffix and the value is emitted through `FoundXMP`.
fn process_blank_info(walker: &mut Walker<'_>, blank: &BlankInfo) {
  for node in blank.prop.values() {
    for pre in node.pre.keys() {
      for (val, post_props) in node.post.values() {
        // Re-assemble the full property path: <pre-segments> + <post>.
        let mut props: Vec<SmolStr> = Vec::new();
        if !pre.is_empty() {
          props.extend(pre.split('/').map(SmolStr::new));
        }
        props.extend(post_props.iter().cloned());
        walker.found_xmp(&props, val, None);
      }
    }
  }
}

// ===========================================================================
// XmpMeta::serialize_tags — typed-path tag emission
// ===========================================================================

#[cfg(feature = "alloc")]
impl XmpMeta<'_> {
  /// Emit XMP tags into the inline tag sink in extraction order — the
  /// typed-path counterpart of bundled `FoundTag` (the post-`RestoreStruct`
  /// emission). `print_conv = true` selects the `-j` (PrintConv) value form;
  /// `false` selects the `-n` (post-ValueConv numeric) form. Infallible.
  ///
  /// `allow(dead_code)`: reachable through `AnyMeta::serialize_tags`, itself
  /// only invoked from the `json`/`serde` render path — an `alloc`-only
  /// build that pulls in neither leaves the whole emit chain dead.
  #[allow(dead_code)]
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    for tag in &self.tags {
      out.write_value(
        tag.group.as_str(),
        tag.name.as_str(),
        tag.value.to_tag_value(print_conv),
      )?;
    }
    if let Some(w) = &self.warning {
      out.write_warning(w)?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  /// Faithful-port checkpoint for the XMP namespaces NOT exercised by a
  /// conformance fixture (the 4-surface accept-defer contract). The
  /// camera-critical namespace TAG tables (`exif`, `tiff`, `photoshop`,
  /// `aux`, `dc`, `xmp`, `xmpRights`) ARE ported with PrintConv/ValueConv;
  /// the `plus` / `mwg-rs` / `mwg-kw` / `prism` / IPTC-Ext namespace tables
  /// and the full `rdf:nodeID` blank-node resolution + list-of-lang-alt
  /// rebuild are deferred — see `docs/tracking.md`. Their tags still extract
  /// via `FoundXMP`'s faithful default-tagInfo path (raw value, no
  /// namespace-table PrintConv label).
  #[test]
  #[ignore = "accept-defer: unported XMP namespace PrintConv tables — docs/tracking.md"]
  fn xmp_unported_namespace_printconv_deferred() {}

  // ----- Codex R1/F4: StandardLangCase + GetLangInfo underscore -----------
  #[test]
  fn standard_lang_case_matches_exiftool() {
    use super::standard_lang_case;
    // 2-letter 2nd subtag uppercased, rest lowercased (XMP.pm:3241).
    assert_eq!(standard_lang_case("en-us"), "en-US");
    assert_eq!(standard_lang_case("en-us-x-private"), "en-US-x-private");
    assert_eq!(standard_lang_case("EN-GB-oed"), "en-GB-oed");
    // 3+-letter script subtag ⇒ no `\b` after 2 letters ⇒ all-lowercase.
    assert_eq!(standard_lang_case("zh-Hant-CN"), "zh-hant-cn");
    // Digit region ⇒ `(-[a-z]{2})` fails ⇒ all-lowercase.
    assert_eq!(standard_lang_case("es-419"), "es-419");
    // Underscore separator ⇒ SLC no-match (lc) THEN tr/_/-/ (XMP.pm:3230).
    assert_eq!(standard_lang_case("de_DE"), "de-de");
    // Single-letter `x`/`i` primary subtag.
    assert_eq!(standard_lang_case("i-klingon"), "i-klingon");
    assert_eq!(standard_lang_case("x-foo-bar"), "x-foo-bar");
    // No subtag ⇒ lowercase whole.
    assert_eq!(standard_lang_case("DE"), "de");
  }

  // ----- Codex R3/F1: base64 decoded-payload binary/text split ------------
  #[test]
  fn base64_is_binary_matches_exiftool_unless_guard() {
    use super::base64_is_binary;
    // The control-byte ranges `\0-\x08`, `\x0b`, `\x0e-\x1f` ⇒ BINARY.
    for b in 0x00u8..=0x08 {
      assert!(base64_is_binary(&[b]), "0x{b:02x} must be binary");
    }
    assert!(base64_is_binary(&[0x0b]), "VT must be binary");
    for b in 0x0eu8..=0x1f {
      assert!(base64_is_binary(&[b]), "0x{b:02x} must be binary");
    }
    // Codex R11/F2: the Perl class is the TYPO `[\0-\x08\x0b\0x0c\x0e-\x1f]`,
    // where `\0x0c` parses as `\0` + the LITERAL bytes `x`/`0`/`c`. So those
    // three printable ASCII bytes are ALSO binary (verified vs bundled 13.58:
    // base64 decoding to `x`/`0`/`c`/`cat` ⇒ binary placeholder).
    for b in [b'x', b'0', b'c'] {
      assert!(base64_is_binary(&[b]), "literal 0x{b:02x} must be binary");
    }
    assert!(base64_is_binary(b"cat"), "`cat` (has `c`) must be binary");
    // Excluded controls (tab/LF/FF/CR) stay TEXT — `\x0c` (FF) is NOT in the
    // class (the typo is `\0x0c`, not `\x0c`), so 0x0c is text (vs 13.58).
    for b in [0x09u8, 0x0a, 0x0c, 0x0d, 0x20] {
      assert!(!base64_is_binary(&[b]), "0x{b:02x} must be text");
    }
    // Printable payloads WITHOUT control bytes and WITHOUT `x`/`0`/`c` stay
    // TEXT (verified vs 13.58: `dog`/`9`/`hi`/`test` decode to text). Note `9`
    // is text — only the digit `0` is special, not all digits.
    for s in [&b"dog"[..], b"9", b"hi", b"test", b"A"] {
      assert!(!base64_is_binary(s), "{s:?} must be text");
    }
    // A `<= 100`-byte non-UTF-8 image header has no control/`x`/`0`/`c` bytes
    // ⇒ TEXT (0xff 0xd8 0xff 0xe0: none of these is x/0/c).
    assert!(!base64_is_binary(&[0xff, 0xd8, 0xff, 0xe0]));
    // Length `> 100` ⇒ BINARY regardless of content (100 is the inclusive
    // text bound; 101 is the first binary length). `b'A'` (0x41) is not in the
    // class, isolating the length condition.
    assert!(!base64_is_binary(&[b'A'; 100]));
    assert!(base64_is_binary(&[b'A'; 101]));
  }

  // ----- Codex R11/F1: Nikon BASIC_PARAM → NXD override latch --------------
  #[test]
  fn parse_inner_latches_nikon_nxd_override() {
    use super::parse_inner;
    // An `xmlns` URI beginning `http://ns.nikon.com/BASIC_PARAM` latches the
    // `OverrideFileType('NXD',…)` flag (XMP.pm:3915-3916). The prefix match is
    // anchored at the URI start, so any version suffix (`/1.0/`, `/2.0/`, …)
    // and any prefix name trigger it.
    let nxd = parse_inner(
      b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
        <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
        <rdf:Description rdf:about=\"\" \
        xmlns:nbp=\"http://ns.nikon.com/BASIC_PARAM/1.0/\">\
        <nbp:Exposure>0</nbp:Exposure></rdf:Description></rdf:RDF></x:xmpmeta>",
    )
    .expect("NXD sidecar is accepted as XMP");
    assert!(
      nxd.is_nikon_nxd(),
      "BASIC_PARAM URI must latch the NXD override"
    );

    // The bare `http://ns.nikon.com/BASIC_PARAM` URI (no trailing version) also
    // matches (`^http://ns.nikon.com/BASIC_PARAM`, `starts_with`).
    let nxd_bare = parse_inner(
      b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
        <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
        <rdf:Description rdf:about=\"\" \
        xmlns:nbp=\"http://ns.nikon.com/BASIC_PARAM\">\
        <nbp:X>1</nbp:X></rdf:Description></rdf:RDF></x:xmpmeta>",
    )
    .expect("bare BASIC_PARAM sidecar is accepted as XMP");
    assert!(nxd_bare.is_nikon_nxd(), "bare BASIC_PARAM URI must latch");

    // A plain dc: XMP sidecar does NOT latch the override.
    let plain = parse_inner(
      b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
        <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
        <rdf:Description rdf:about=\"\" \
        xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
        <dc:title>x</dc:title></rdf:Description></rdf:RDF></x:xmpmeta>",
    )
    .expect("plain XMP is accepted");
    assert!(
      !plain.is_nikon_nxd(),
      "non-Nikon XMP must NOT latch the override"
    );

    // A DIFFERENT Nikon namespace (`sdc`, a registered std URI, not
    // BASIC_PARAM) does NOT latch — only `BASIC_PARAM` triggers NXD.
    let sdc = parse_inner(
      b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
        <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
        <rdf:Description rdf:about=\"\" \
        xmlns:sdc=\"http://ns.nikon.com/sdc/1.0/\">\
        <sdc:X>1</sdc:X></rdf:Description></rdf:RDF></x:xmpmeta>",
    )
    .expect("Nikon sdc XMP is accepted");
    assert!(
      !sdc.is_nikon_nxd(),
      "non-BASIC_PARAM Nikon URI must NOT latch"
    );
  }

  // ----- Codex R4/F1: DecodeBase64 truncate-and-decode semantics ----------
  #[test]
  fn decode_base64_matches_perl_decodebase64() {
    use super::decode_base64;
    // Padded and bare prefix both decode (XMP.pm:2990 partial-group decode).
    assert_eq!(decode_base64("aGVsbG8="), b"hello");
    assert_eq!(decode_base64("aGVsbG8"), b"hello");
    // Trailing invalid data truncates at the first non-allow-list byte
    // (XMP.pm:2988 `s/[^...].*//s`): `#` and the rest are dropped, NOT a
    // fall-back to the raw string. Verified vs bundled 13.58 → `hello`.
    assert_eq!(decode_base64("aGVsbG8=#junk"), b"hello");
    // VT (0x0b) is NOT in the allow-list, so it truncates: only `aGVs`
    // survives → `hel` (bundled 13.58: `aGVs\x0bbG8=` → `hel`).
    assert_eq!(decode_base64("aGVs\x0bbG8="), b"hel");
    // Allow-list whitespace `= \t\n\r\f` and space are ignored, not decoded.
    assert_eq!(decode_base64("aGVs bG8\t=\n"), b"hello");
    // Leading garbage truncates immediately ⇒ empty (never raw fall-back).
    assert_eq!(decode_base64("!aGVsbG8="), Vec::<u8>::new());
    assert_eq!(decode_base64(""), Vec::<u8>::new());
  }

  // ----- Codex R5/F1: decode-BEFORE-unescape order ------------------------
  #[test]
  fn base64_decodes_raw_then_unescapes() {
    use super::{decode_base64, unescape_value_with_cdata_bytes};
    // The `&` truncates DecodeBase64 (XMP.pm:3645 runs on the RAW value),
    // so only `aGVs` decodes ⇒ `hel`. The post-decode un-escape is a no-op.
    let raw = "aGVs&#x62;G8=";
    let decoded = decode_base64(raw);
    assert_eq!(decoded, b"hel");
    assert_eq!(unescape_value_with_cdata_bytes(&decoded), b"hel");
    // `YSZhbXA7Yg==` decodes to the bytes `a&amp;b`; un-escaping THEN
    // (XMP.pm:3655-3669) yields `a&b` (bundled 13.58).
    let raw = "YSZhbXA7Yg==";
    let decoded = decode_base64(raw);
    assert_eq!(decoded, b"a&amp;b");
    assert_eq!(unescape_value_with_cdata_bytes(&decoded), b"a&b");
  }

  #[test]
  fn unescape_value_with_cdata_bytes_matches_str_helper() {
    use super::{unescape_value_with_cdata, unescape_value_with_cdata_bytes};
    // Byte twin agrees with the `&str` helper on UTF-8 input, incl. CDATA
    // (whose body is NOT un-escaped) and numeric entities (UTF-8 bytes,
    // matching Perl `UnescapeXML` → `61 c3 a9 62` for `a&#xE9;b`).
    for s in [
      "plain",
      "a&amp;b &lt;x&gt; &quot;q&quot; &apos;a&apos;",
      "a&#xE9;b",
      "before<![CDATA[ raw &amp; <kept> ]]>after &amp; end",
      "unterminated<![CDATA[ tail",
      "&unknown; &amp;",
    ] {
      assert_eq!(
        unescape_value_with_cdata_bytes(s.as_bytes()),
        unescape_value_with_cdata(s).into_bytes(),
        "mismatch for {s:?}"
      );
    }
    // High-bit (non-UTF-8) bytes pass through verbatim — the text-branch
    // guard admits them, and `UnescapeXML` only rewrites ASCII entity runs.
    assert_eq!(
      unescape_value_with_cdata_bytes(&[0xff, b'&', b'a', b'm', b'p', b';', 0x80]),
      vec![0xff, b'&', 0x80]
    );
  }

  // ----- Codex R1/F2: GPS ToDegrees / ToDMS -------------------------------
  #[test]
  fn gps_to_degrees_matches_exiftool() {
    use super::gps_to_degrees;
    assert_eq!(gps_to_degrees("45,30.00N"), "45.5");
    assert_eq!(gps_to_degrees("122,30.50W"), "-122.508333333333");
    assert_eq!(gps_to_degrees("10,15.25S"), "-10.2541666666667");
    assert_eq!(gps_to_degrees("20,45.75E"), "20.7625");
    // `inf`/`undef` ⇒ '' (GPS.pm:584).
    assert_eq!(gps_to_degrees("inf"), "");
    assert_eq!(gps_to_degrees("undef"), "");
    // No extractable number ⇒ '' (GPS.pm:593).
    assert_eq!(gps_to_degrees("garbage"), "");
  }

  #[test]
  fn gps_to_dms_matches_exiftool() {
    use super::gps_to_dms;
    assert_eq!(gps_to_dms("45.5", b'N'), "45 deg 30' 0.00\" N");
    assert_eq!(
      gps_to_dms("-122.508333333333", b'E'),
      "122 deg 30' 30.00\" W"
    );
    assert_eq!(
      gps_to_dms("-10.2541666666667", b'N'),
      "10 deg 15' 15.00\" S"
    );
    assert_eq!(gps_to_dms("20.7625", b'E'), "20 deg 45' 45.00\" E");
    // Empty input passes through (GPS.pm:500-503).
    assert_eq!(gps_to_dms("", b'N'), "");
    // Codex R2/F1: the seconds round-off carry (GPS.pm:559-561) subtracts 60
    // from the ROUNDED `sprintf('%.2f', $c[-1])` value, never the original
    // unrounded seconds. `12.9999999999` rounds to `60.00"` → carries to
    // `13 deg 0' 0.00" N` — NOT the negative-zero `13 deg 0' -0.00" N` the
    // raw subtraction would emit.
    assert_eq!(gps_to_dms("12.9999999999", b'N'), "13 deg 0' 0.00\" N");
    // Negative longitude: `$ref` E flips to W (GPS.pm:507-514).
    assert_eq!(gps_to_dms("-122.9999999999", b'E'), "123 deg 0' 0.00\" W");
    // Signed-decimal Dest with the sign flipping N→S, still carrying cleanly.
    assert_eq!(gps_to_dms("-44.9999999999", b'N'), "45 deg 0' 0.00\" S");
    // Minute-only carry: seconds carry into minutes WITHOUT a degree increment
    // (`$c[-2] += 1` stays < 60). `0.0166666666` deg → `0 deg 1' 0.00" E`.
    assert_eq!(gps_to_dms("0.0166666666", b'E'), "0 deg 1' 0.00\" E");
  }

  // ----- Codex R1/F3: hash PrintConv miss ⇒ Unknown ($val) ----------------
  #[test]
  fn intmap_printconv_miss_is_unknown_no_coercion() {
    use super::apply_print_conv;
    use crate::formats::xmp::tables::{lookup_field, lookup_ns_table};
    // `exif:MeteringMode` IntMap: "5" ⇒ Multi-segment, "99"/"05" ⇒ Unknown.
    let table = lookup_ns_table("exif").expect("exif ns table");
    let f = lookup_field(table, "MeteringMode").expect("MeteringMode field");
    assert_eq!(apply_print_conv("5", f), "Multi-segment");
    assert_eq!(apply_print_conv("99", f), "Unknown (99)");
    // "05" must NOT collapse to int 5 ⇒ exact string miss.
    assert_eq!(apply_print_conv("05", f), "Unknown (05)");
  }

  // ----- Codex R8/F2: only FileType-`XMP` inputs are accepted -------------
  // `ProcessXMP` recognizes several XML flavours and `SetFileType`s each
  // separately (XMP.pm:4337-4427): `<?xpacket`/`<x(mp)?:x[ma]pmeta`/
  // `<rdf:RDF` ⇒ XMP; `<?xml` is XMP only when it ALSO carries an
  // `<x(mp)?:x[ma]pmeta` (`$hasXMP`) or `<rdf:RDF` (`$isRDF`); a `<svg`-rooted
  // or non-XMP-`<?xml`-rooted input is SVG / PLIST / bare-XML. The SVG /
  // PLIST / XML sub-ports are deferred (`docs/tracking.md`), so `parse_inner`
  // ACCEPTS only the FileType-`XMP` inputs and REJECTS the rest as `None`
  // (faithful to `ProcessXMP` `return 0`) rather than mis-finalizing them
  // as XMP.
  #[test]
  fn parse_inner_accepts_only_filetype_xmp_inputs() {
    use super::parse_inner;
    // --- ACCEPTED: every input ExifTool finalizes to FileType `XMP` ---
    // `<?xpacket`-rooted.
    assert!(
      parse_inner(
        b"<?xpacket begin=\"\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>\n<?xpacket end=\"w\"?>"
      )
      .is_some(),
      "<?xpacket-rooted XMP must be accepted"
    );
    // `<x:xmpmeta`-rooted (no xpacket — CS2 sidecar).
    assert!(
      parse_inner(b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>").is_some(),
      "<x:xmpmeta-rooted XMP must be accepted"
    );
    // `<xmp:xmpmeta`-rooted (MicrosoftPhoto mutant).
    assert!(
      parse_inner(b"<xmp:xmpmeta xmlns:xmp=\"adobe:ns:meta/\"/>").is_some(),
      "<xmp:xmpmeta-rooted XMP must be accepted"
    );
    // `<rdf:RDF`-rooted (XMP without an x:xmpmeta wrapper — `$isRDF`).
    assert!(
      parse_inner(b"<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>")
        .is_some(),
      "<rdf:RDF-rooted XMP must be accepted"
    );
    // `<?xml`-rooted WITH an x:xmpmeta inside (`$hasXMP`).
    assert!(
      parse_inner(b"<?xml version=\"1.0\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>").is_some(),
      "<?xml-rooted doc carrying <x:xmpmeta must be accepted"
    );
    // `<?xml`-rooted WITH an rdf:RDF inside (`$isRDF`).
    assert!(
      parse_inner(
        b"<?xml version=\"1.0\"?>\n<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_some(),
      "<?xml-rooted doc carrying <rdf:RDF must be accepted"
    );

    // --- REJECTED: SVG / PLIST / bare-XML (deferred sub-ports) ---
    // `<svg`-rooted (no XML declaration) ⇒ ExifTool `SetFileType('SVG')`.
    assert!(
      parse_inner(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><title>T</title></svg>").is_none(),
      "<svg-rooted SVG must be rejected (not mis-finalized as XMP)"
    );
    // `<?xml`-rooted SVG ⇒ ExifTool `SetFileType('SVG')`.
    assert!(
      parse_inner(
        b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"><title>T</title></svg>"
      )
      .is_none(),
      "<?xml-rooted SVG must be rejected"
    );
    // `<?xml`-rooted bare XML (no xmpmeta/rdf/svg) ⇒ `SetFileType('XML')`.
    assert!(
      parse_inner(b"<?xml version=\"1.0\"?>\n<root><item>x</item></root>").is_none(),
      "<?xml-rooted bare XML must be rejected"
    );
    // `<?xml`-rooted PLIST ⇒ `Image::ExifTool::PLIST` (deferred module).
    assert!(
      parse_inner(b"<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict/></plist>").is_none(),
      "<?xml-rooted PLIST must be rejected"
    );
    // Not XML at all.
    assert!(
      parse_inner(b"\x89PNG\r\n\x1a\n").is_none(),
      "binary non-XML must be rejected"
    );
  }

  // Codex R9/F1: `ProcessXMP` recognition is a TWO-TIER match whose tiers
  // differ in leading-whitespace tolerance. Tier 1 (XMP.pm:4341,
  // `^\s*(<\?xpacket begin=|<x(mp)?:x[ma]pmeta)`) tolerates leading ASCII
  // whitespace; Tier 2 (the `else` block, XMP.pm:4345-4354 — BOM / `<?xml` /
  // `<rdf:RDF` / `<svg`) is anchored at byte 0 with an OPTIONAL byte-0 BOM but
  // NO leading whitespace. The old port trimmed whitespace before EVERY
  // branch, wrongly accepting Tier-2 inputs ExifTool finalizes to TXT.
  #[test]
  fn parse_inner_leading_whitespace_anchoring_matches_perl_tiers() {
    use super::parse_inner;
    // --- Tier 2 byte-0 anchor: leading whitespace ⇒ REJECTED (ExifTool TXT) ---
    assert!(
      parse_inner(
        b"   <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_none(),
      "leading whitespace before <rdf:RDF must be rejected (Tier-2 byte-0 anchor)"
    );
    assert!(
      parse_inner(
        b"\t<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_none(),
      "leading tab before <rdf:RDF must be rejected"
    );
    assert!(
      parse_inner(b"   <?xml version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>").is_none(),
      "leading whitespace before <?xml (carrying xmpmeta) must be rejected (Tier-2 byte-0 anchor)"
    );
    assert!(
      parse_inner(
        b"\n<?xml version=\"1.0\"?><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_none(),
      "leading newline before <?xml (carrying rdf:RDF) must be rejected"
    );
    // --- Tier 1 `^\s*`: leading whitespace before xpacket/xmpmeta ⇒ ACCEPTED ---
    assert!(
      parse_inner(b"   <?xpacket begin=\"\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>").is_some(),
      "leading whitespace before <?xpacket must still be accepted (Tier-1 ^\\s*)"
    );
    assert!(
      parse_inner(b"  \n <x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>").is_some(),
      "leading whitespace before <x:xmpmeta must still be accepted (Tier-1 ^\\s*)"
    );
    // --- Tier 2 optional byte-0 BOM (NO preceding whitespace) ---
    // UTF-8 BOM + <rdf:RDF / <x:xmpmeta / <?xpacket(double-encoded) ⇒ XMP.
    assert!(
      parse_inner(b"\xef\xbb\xbf<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>")
        .is_some(),
      "byte-0 BOM + <rdf:RDF must be accepted (Tier-2 optional BOM)"
    );
    assert!(
      parse_inner(b"\xef\xbb\xbf<?xpacket begin=\"\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>")
        .is_some(),
      "byte-0 BOM + <?xpacket (double-encoded) must be accepted (XMP.pm:4351)"
    );
    // Whitespace BEFORE a BOM is rejected by BOTH tiers.
    assert!(
      parse_inner(b"  \xef\xbb\xbf<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>")
        .is_none(),
      "whitespace before a BOM must be rejected"
    );
  }

  // Codex R9/F1 (comment-strip faithfulness): `s/^\s*<!--.*?-->\s+//s`
  // (XMP.pm:4327) consumes a leading comment's surrounding whitespace ONLY on
  // a successful strip, and REQUIRES `\s+` after `-->`. When there is no
  // leading comment, the leading whitespace is preserved (so Tier-2 anchoring
  // still rejects `   <rdf:RDF`).
  #[test]
  fn strip_leading_comments_matches_perl_substitution() {
    use super::parse_inner;
    // Complete comment + trailing whitespace ⇒ stripped, byte-0 token follows
    // ⇒ ACCEPTED.
    assert!(
      parse_inner(
        b"<!-- c -->\n<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_some(),
      "comment + trailing whitespace + <rdf:RDF must be accepted"
    );
    // Complete comment but NO trailing whitespace ⇒ `s///` fails ⇒ buffer
    // keeps the `<!--` ⇒ REJECTED (verified vs bundled 13.58 → TXT).
    assert!(
      parse_inner(
        b"<!-- c --><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"></rdf:RDF>"
      )
      .is_none(),
      "comment with no trailing whitespace before <rdf:RDF must be rejected"
    );
    // Comment + trailing whitespace + <?xpacket (Tier-1) ⇒ ACCEPTED.
    assert!(
      parse_inner(b"<!-- c -->\n<?xpacket begin=\"\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>")
        .is_some(),
      "comment + <?xpacket must be accepted"
    );
  }

  /// Codex R10/F1+F2 class-sweep: every XMP text-encoding decode path must
  /// follow XMP.pm's `unpack` + `pack('C0U*')` + `FixUTF8` byte semantics
  /// (XMP.pm:2943-2972 / 4467-4498 / 4571-4587), NOT correct Unicode decoding.
  #[test]
  fn decode_paths_match_perl_pack_c0u_and_fixutf8_byte_semantics() {
    use super::{DoubleBom, decode_double_utf, decode_utf16, decode_utf32};

    // ---- UTF-16 transcode: 16-bit units decoded INDEPENDENTLY (R10/F2) ----
    // BMP units pass through; a surrogate PAIR is two units → `pack('C0U')`
    // gives 6 loose-UTF-8 bytes → FixUTF8 → 6 `?` (verified vs bundled 13.58:
    // UTF-16LE `A😀B` → `A??????B`).
    let a_emoji_b_le: Vec<u8> = vec![
      0x41, 0x00, // 'A'
      0x3d, 0xd8, // U+D83D (high surrogate, LE)
      0x00, 0xde, // U+DE00 (low surrogate, LE)
      0x42, 0x00, // 'B'
    ];
    assert_eq!(decode_utf16(&a_emoji_b_le, false), "A??????B");
    // BE byte order of the same string.
    let a_emoji_b_be: Vec<u8> = vec![0x00, 0x41, 0xd8, 0x3d, 0xde, 0x00, 0x00, 0x42];
    assert_eq!(decode_utf16(&a_emoji_b_be, true), "A??????B");
    // A valid BMP non-ASCII char (é, U+00E9) survives as real UTF-8.
    assert_eq!(decode_utf16(&[0xe9, 0x00], false), "é");
    // Odd trailing byte is dropped (Perl `unpack` discards the partial unit).
    assert_eq!(decode_utf16(&[0x41, 0x00, 0x42], false), "A");

    // ---- UTF-32 transcode: each 32-bit unit via `pack('C0U')` -------------
    // U+1F600 (😀) as a single UTF-32 unit IS a valid scalar → real UTF-8.
    assert_eq!(decode_utf32(&[0x00, 0xf6, 0x01, 0x00], false), "😀");
    // A lone surrogate scalar (U+D800) → `pack('C0U')` 3 loose bytes → 3 `?`.
    assert_eq!(decode_utf32(&[0x00, 0xd8, 0x00, 0x00], false), "???");
    // Above U+10FFFF (U+00110000) → 4 loose bytes → 4 `?`.
    assert_eq!(decode_utf32(&[0x00, 0x00, 0x11, 0x00], false), "????");

    // ---- $double decode, UTF-8 BOM (R10/F1) ------------------------------
    // BOM + `<?xpacket` + a valid-UTF-8 `é` body → decode-UTF8 then truncate
    // each code point to a byte: `é`(U+00E9) → 0xE9 → FixUTF8 → `?`, AND the
    // `XMP is double UTF-encoded` warning fires (XMP.pm:4494).
    let utf8_double = b"\xef\xbb\xbf<?xpacket begin=\"\"?><x:xmpmeta>\xc3\xa9</x:xmpmeta>";
    let (txt, warn) = decode_double_utf(utf8_double, DoubleBom::Utf8);
    assert_eq!(warn.as_deref(), Some("XMP is double UTF-encoded"));
    assert!(txt.contains("xmpmeta>?<"), "é → single ? : {txt:?}");
    // BOM + `<?xpacket` + INVALID UTF-8 (`0xFF`) body → the re-pack warns, so
    // ExifTool keeps the BOM-stripped ORIGINAL and emits NO warning; the lone
    // 0xFF then becomes `?` via the later value-stage FixUTF8 (XMP.pm:4491).
    let utf8_bad = b"\xef\xbb\xbf<?xpacket begin=\"\"?><x:xmpmeta>\xff</x:xmpmeta>";
    let (txt_bad, warn_bad) = decode_double_utf(utf8_bad, DoubleBom::Utf8);
    assert_eq!(warn_bad, None);
    assert!(
      txt_bad.contains("xmpmeta>?<"),
      "0xFF kept then ? : {txt_bad:?}"
    );

    // ---- $double decode, UTF-16 BOM --------------------------------------
    // `\xff\xfe` + UTF-16LE `<?xpacket…é…` → `pack('C*', unpack('v*'))`
    // truncates each 16-bit unit to a byte (é→0xE9→`?`); warning fires.
    let mut u16_double: Vec<u8> = vec![0xff, 0xfe];
    for ch in "<?xpacket begin=\"\"?><x:xmpmeta>".chars() {
      u16_double.extend_from_slice(&(ch as u16).to_le_bytes());
    }
    u16_double.extend_from_slice(&0x00e9u16.to_le_bytes()); // é
    for ch in "</x:xmpmeta>".chars() {
      u16_double.extend_from_slice(&(ch as u16).to_le_bytes());
    }
    let (txt16, warn16) = decode_double_utf(&u16_double, DoubleBom::Utf16Le);
    assert_eq!(warn16.as_deref(), Some("XMP is double UTF-encoded"));
    assert!(txt16.contains("xmpmeta>?<"), "u16 é → ? : {txt16:?}");
    // Odd trailing byte after the BOM ⇒ `unpack` warns ⇒ keep original, no warn.
    let (_t, warn_odd) = decode_double_utf(&[0xff, 0xfe, 0x41, 0x00, 0x42], DoubleBom::Utf16Le);
    assert_eq!(warn_odd, None);
  }

  /// `unpack_c0u` mirrors `Charset::Decompose(_,_,'UTF8')` (Charset.pm:165-181)
  /// = `unpack('C0U*', $bytes)`. All expectations verified vs bundled Perl 5.34
  /// (`unpack('C0U*', …)` + a `$SIG{__WARN__}` probe), 2026-05-22.
  #[test]
  fn unpack_c0u_decodes_utf8_codepoints_and_flags_malformed() {
    use super::unpack_c0u;
    // Pure ASCII: code points == bytes, no warning.
    assert_eq!(unpack_c0u(b"AB"), (vec![0x41_u64, 0x42], false));
    // 2-byte `é` → U+00E9, no warning.
    assert_eq!(unpack_c0u(b"\xc3\xa9"), (vec![0xe9_u64], false));
    // 4-byte 😀 → U+1F600, no warning.
    assert_eq!(unpack_c0u("😀".as_bytes()), (vec![0x1_f600_u64], false));
    // Surrogate ENCODING `ED A0 BD` is ACCEPTED (loose UTF-8) → U+D83D, NO
    // warning — `unpack` applies no surrogate/range checks (Perl: `[55357]`).
    assert_eq!(unpack_c0u(b"\xed\xa0\xbd"), (vec![0xd83d_u64], false));
    // Beyond U+10FFFF is ACCEPTED, no warning (Perl: `F4 90 80 80` → 0x110000).
    assert_eq!(
      unpack_c0u(b"\xf4\x90\x80\x80"),
      (vec![0x11_0000_u64], false)
    );
    // 5/6/7-byte RFC-2279 forms are accepted (Perl: `F8 88 80 80 80` →
    // 0x200000, `FE 82 80 80 80 80 80` → 0x80000000).
    assert_eq!(
      unpack_c0u(b"\xf8\x88\x80\x80\x80"),
      (vec![0x20_0000_u64], false)
    );
    assert_eq!(
      unpack_c0u(b"\xfe\x82\x80\x80\x80\x80\x80"),
      (vec![0x8000_0000_u64], false)
    );
    // Overlong forms WARN + substitute 0 (Perl: `C0 80`, `C1 BF`, `E0 9F BF`,
    // `F0 80 80 80` all → [0], warned).
    assert_eq!(unpack_c0u(b"\xc0\x80"), (vec![0x00_u64], true));
    assert_eq!(unpack_c0u(b"\xe0\x9f\xbf"), (vec![0x00_u64], true));
    assert_eq!(unpack_c0u(b"\xf0\x80\x80\x80"), (vec![0x00_u64], true));
    // Minimum non-overlong values ARE accepted (Perl: `C2 80`→0x80,
    // `E0 A0 80`→0x800, `F0 90 80 80`→0x10000).
    assert_eq!(unpack_c0u(b"\xc2\x80"), (vec![0x80_u64], false));
    assert_eq!(unpack_c0u(b"\xe0\xa0\x80"), (vec![0x800_u64], false));
    // The 13-byte `0xFF` lead is REJECTED (Perl: warned, [0]).
    assert_eq!(unpack_c0u(b"\xff"), (vec![0x00_u64], true));
    // Lone high byte → code point `0` substituted, malformed flagged
    // (Perl: `A\xffB` → `[65, 0, 66]`, warning set).
    assert_eq!(unpack_c0u(b"A\xffB"), (vec![0x41_u64, 0x00, 0x42], true));
    // Truncated 2-byte lead at EOF → `0`, malformed flagged (Perl: `[0]`, warn).
    assert_eq!(unpack_c0u(b"\xc3"), (vec![0x00_u64], true));
    // Bad continuation `c3 28` → lead substitutes `0`, then `(`=0x28 follows
    // (Perl: `[0, 40]`, warning set).
    assert_eq!(unpack_c0u(b"\xc3\x28"), (vec![0x00_u64, 0x28], true));
    // Greedy consumption of valid continuations before re-scan (Perl-verified):
    //   `E0 28 80` (cont1 bad) → consume `E0` only → `[0, 0x28, 0]`.
    assert_eq!(
      unpack_c0u(b"\xe0\x28\x80"),
      (vec![0x00_u64, 0x28, 0x00], true)
    );
    //   `E0 A0 28` (cont1 ok, cont2 bad) → consume `E0 A0` → `[0, 0x28]`.
    assert_eq!(unpack_c0u(b"\xe0\xa0\x28"), (vec![0x00_u64, 0x28], true));
    //   `E0 A0` at EOF (short) → consume both → `[0]`.
    assert_eq!(unpack_c0u(b"\xe0\xa0"), (vec![0x00_u64], true));
    // Valid 13-byte `0xFF` form round-trips a >32-bit value (Perl-verified:
    // `pack('C0U', 0x1000000000)` = `FF 80 80 80 80 80 81 80 80 80 80 80 80`).
    assert_eq!(
      unpack_c0u(b"\xff\x80\x80\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80"),
      (vec![0x10_0000_0000_u64], false)
    );
    // `0xFF` with a short continuation run → one 0, consumes the run (Perl:
    // `FF A4 33` → `[0, 0x33]`).
    assert_eq!(unpack_c0u(b"\xff\xa4\x33"), (vec![0x00_u64, 0x33], true));
  }

  /// Codex R10 class-sweep, end-to-end through `parse_inner`: the BOM+`<?xpacket`
  /// double path emits the warning + `?`, the plain-UTF-8 bad-byte path emits
  /// `?` (NOT U+FFFD), and a valid UTF-16LE BMP value round-trips intact.
  #[test]
  fn parse_inner_encoding_paths_end_to_end() {
    use super::{XmpValue, parse_inner};
    fn title(m: &super::XmpMeta<'_>) -> Option<String> {
      m.tags_slice()
        .iter()
        .find(|t| t.name() == "Title")
        .and_then(|t| match t.value_ref() {
          XmpValue::Scalar(s) => Some(s.text().to_string()),
          _ => None,
        })
    }
    let tmpl = |body: &[u8]| -> Vec<u8> {
      let head = b"<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">";
      let tail = b"</rdf:li></rdf:Alt></dc:title></rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>";
      let mut v = head.to_vec();
      v.extend_from_slice(body);
      v.extend_from_slice(tail);
      v
    };
    // Plain UTF-8 with a bad byte → `?` (NOT U+FFFD), no warning.
    let plain = tmpl(b"A\xffB");
    let m = parse_inner(&plain).expect("plain accepted");
    assert_eq!(title(&m).as_deref(), Some("A?B"));
    assert_eq!(m.warning(), None);
    // UTF-8 BOM + `<?xpacket` + `é` → double path: `?` + warning.
    let mut double = vec![0xef, 0xbb, 0xbf];
    double.extend_from_slice(&tmpl(b"\xc3\xa9"));
    let md = parse_inner(&double).expect("double accepted");
    assert_eq!(title(&md).as_deref(), Some("?"));
    assert_eq!(md.warning(), Some("XMP is double UTF-encoded"));
  }

  // Codex R9/F2: `UnescapeChar` (XMP.pm:2919-2936) emits `pack('C0U', $val)`
  // (loose UTF-8, no validity checks) for numeric refs, then `FixUTF8`
  // (XMP.pm:2943-2972) maps each malformed byte to one `?`. Surrogates and
  // values above U+10FFFF must NOT bail to the literal entity text.
  #[test]
  fn unescape_xml_numeric_entity_pack_c0u_then_fixutf8() {
    use super::unescape_xml;
    // In-range: `&#x100;` → U+0100 `Ā`, `&#65;` → `A`, named entities resolve.
    assert_eq!(unescape_xml("good&#x100;point"), "good\u{100}point");
    assert_eq!(unescape_xml("a&#65;b"), "aAb");
    assert_eq!(
      unescape_xml("a&amp;b&lt;c&gt;d&quot;e&apos;f"),
      "a&b<c>d\"e'f"
    );
    // 2-byte UTF-8 numeric ref stays valid: `&#xE9;` → `é`.
    assert_eq!(unescape_xml("a&#xE9;b"), "a\u{e9}b");
    // Out-of-range U+100000000 ⇒ 7 loose-UTF-8 bytes ⇒ 7 `?` (FixUTF8).
    assert_eq!(unescape_xml("A&#x100000000;B"), "A???????B");
    // Surrogate U+D800 ⇒ 3 loose-UTF-8 bytes (`ED A0 80`) ⇒ 3 `?`.
    assert_eq!(unescape_xml("S&#xD800;E"), "S???E");
    // Just above U+10FFFF ⇒ `&#x110000;` ⇒ 4 bytes (`F4 90 80 80`) ⇒ 4 `?`.
    assert_eq!(unescape_xml("over&#x110000;flow"), "over????flow");
    // --- class-sweep literals (UnescapeChar leaves these verbatim) ---
    // Uppercase `&#X41;` (Perl anchors lowercase `^#x…`).
    assert_eq!(unescape_xml("upperX&#X41;literal"), "upperX&#X41;literal");
    // `&#x+41;` — the `+` breaks `#?\w+`, so `UnescapeChar` is never reached.
    assert_eq!(unescape_xml("plus&#x+41;literal"), "plus&#x+41;literal");
    // Unknown named entity stays verbatim (XMP.pm:2929).
    assert_eq!(unescape_xml("x&unknownent;y"), "x&unknownent;y");
    // Empty / malformed bodies stay verbatim.
    assert_eq!(unescape_xml("a&;b"), "a&;b");
    assert_eq!(unescape_xml("a&#;b"), "a&#;b");
    assert_eq!(unescape_xml("a&#x;b"), "a&#x;b");
  }

  // Codex R12/F1: `ConvertRational`'s regex `^(-?\d+)/(-?\d+)$` (XMP.pm:3402)
  // permits an OPTIONAL `-` but NEVER a `+` on either side, exactly one `/`,
  // and digits on both sides. Rust `i64::parse` is looser (accepts `+`).
  #[test]
  fn convert_rational_matches_exiftool_regex_gate() {
    use super::convert_rational;
    // Valid `(-?\d+)/(-?\d+)` rationals convert (quotient / inf / undef).
    assert_eq!(
      convert_rational("1/3").as_deref(),
      Some("0.333333333333333")
    );
    assert_eq!(
      convert_rational("-1/3").as_deref(),
      Some("-0.333333333333333")
    );
    assert_eq!(convert_rational("6/2").as_deref(), Some("3"));
    assert_eq!(convert_rational("-6/-2").as_deref(), Some("3"));
    assert_eq!(convert_rational("1/0").as_deref(), Some("inf"));
    assert_eq!(convert_rational("0/0").as_deref(), Some("undef"));
    // Leading `+` on EITHER side breaks the regex ⇒ not converted (`None`).
    assert_eq!(convert_rational("+1/3"), None);
    assert_eq!(convert_rational("1/+3"), None);
    assert_eq!(convert_rational("+1/+3"), None);
    // A second `/`, surrounding whitespace, underscores, hex, an empty side,
    // or a non-rational string all fail the anchored regex.
    assert_eq!(convert_rational("1/2/3"), None);
    assert_eq!(convert_rational(" 1/3"), None);
    assert_eq!(convert_rational("1/3 "), None);
    assert_eq!(convert_rational("1_000/3"), None);
    assert_eq!(convert_rational("0x10/2"), None);
    assert_eq!(convert_rational("/3"), None);
    assert_eq!(convert_rational("1/"), None);
    assert_eq!(convert_rational("abc"), None);
  }

  // Codex R12 class-sweep: `perl_num` reproduces Perl's `$val + 0` prefix
  // coercion — the un-gated numeric `ValueConv`/`PrintConv` expressions
  // (`sqrt(2)**$val`, `sprintf("%.1f",$val)`, `PrintFraction`) feed it.
  #[test]
  fn perl_num_matches_perl_numeric_coercion() {
    use super::perl_num;
    // Whole-string numbers parse as-is.
    assert_eq!(perl_num("50"), 50.0);
    assert_eq!(perl_num("2.8"), 2.8);
    assert_eq!(perl_num("-1.5"), -1.5);
    assert_eq!(perl_num("+1.5"), 1.5);
    assert_eq!(perl_num("1e2"), 100.0);
    assert_eq!(perl_num(".5"), 0.5);
    assert_eq!(perl_num("1."), 1.0);
    // PREFIX coercion — trailing non-numeric is ignored (`"+1/3"+0 == 1`).
    assert_eq!(perl_num("+1/3"), 1.0);
    assert_eq!(perl_num("1/3"), 1.0);
    assert_eq!(perl_num("-1/3"), -1.0);
    assert_eq!(perl_num("+50/1"), 50.0);
    assert_eq!(perl_num("2.8xyz"), 2.8);
    // Leading ASCII whitespace is skipped.
    assert_eq!(perl_num("  1.5"), 1.5);
    assert_eq!(perl_num("\t-5"), -5.0);
    // No numeric prefix ⇒ 0 (`"abc"+0 == 0`, `"0x10"+0 == 0`, lone `.`).
    assert_eq!(perl_num("abc"), 0.0);
    assert_eq!(perl_num("0x10"), 0.0);
    assert_eq!(perl_num("."), 0.0);
    assert_eq!(perl_num(""), 0.0);
    // The `inf`/`undef` tokens `ConvertRational` emits: `"inf"+0 == Inf`
    // (case-insensitive, prefix), `"undef"+0 == 0` (no numeric prefix).
    assert!(perl_num("inf").is_infinite() && perl_num("inf") > 0.0);
    assert!(perl_num("Infinity").is_infinite());
    assert!(perl_num("-inf") == f64::NEG_INFINITY);
    assert!(perl_num("nan").is_nan());
    assert_eq!(perl_num("undef"), 0.0);
    // An `E` with no trailing digits is NOT part of the prefix.
    assert_eq!(perl_num("12e"), 12.0);
  }

  // Codex R12 class-sweep: `is_perl_float` mirrors `IsFloat` (ExifTool.pm:
  // 5936-5941) — the gate `PrintExposureTime`/`PrintFNumber` apply. It is
  // STRICTER than Rust `f64::parse` (rejects `inf`/`nan`) and whole-string.
  #[test]
  fn is_perl_float_matches_exiftool_isfloat() {
    use super::is_perl_float;
    for ok in ["1", "1.5", ".5", "1.", "+1.5", "-0.25", "1e3", "1.5E-2"] {
      assert!(is_perl_float(ok), "{ok} should be IsFloat");
    }
    for no in [
      "", " 1", "1 ", "+1/3", "0x10", "inf", "Inf", "nan", "abc", ".", "1e", "1e+",
    ] {
      assert!(!is_perl_float(no), "{no} should NOT be IsFloat");
    }
  }

  // Codex R12 class-sweep: the numeric converters must match the oracle on
  // a `ConvertRational`-rejected `+`-rational (Perl coerces) and on the
  // non-finite `inf` token (`PrintFraction`/`sprintf` titlecase `Inf`).
  #[test]
  fn numeric_print_convs_coerce_like_perl() {
    use super::{print_exposure_time, print_f_number, print_fraction};
    // `PrintFraction` coerces `+1/3` → 1 ⇒ `+1`; valid forms unchanged.
    assert_eq!(print_fraction("+1/3"), "+1");
    assert_eq!(print_fraction("0.333333333333333"), "+1/3");
    assert_eq!(print_fraction("-0.333333333333333"), "-1/3");
    assert_eq!(print_fraction("0"), "0");
    // `PrintFraction(inf)` → `+Inf`; `sprintf("%+.3g", -Inf)` → `-Inf`.
    assert_eq!(print_fraction("inf"), "+Inf");
    assert_eq!(print_fraction("-inf"), "-Inf");
    // `PrintExposureTime`/`PrintFNumber` are `IsFloat`-gated: a non-float
    // value (incl. `inf`/`nan`, which `f64::parse` would accept) passes
    // through verbatim.
    assert_eq!(print_exposure_time("inf"), "inf");
    assert_eq!(print_exposure_time("nan"), "nan");
    assert_eq!(print_exposure_time("0.5"), "0.5");
    assert_eq!(print_f_number("nan"), "nan");
    assert_eq!(print_f_number("2.8"), "2.8");
  }

  // Codex R12 class-sweep: `format_perl_num` titlecases a non-finite
  // `ValueConv` result (`sqrt(2)**'inf'` ⇒ `Inf`, oracle-verified).
  #[test]
  fn format_perl_num_titlecases_nonfinite() {
    use super::format_perl_num;
    assert_eq!(format_perl_num(f64::INFINITY), "Inf");
    assert_eq!(format_perl_num(f64::NEG_INFINITY), "-Inf");
    assert_eq!(format_perl_num(f64::NAN), "NaN");
    // Finite values are unchanged by the new guard.
    assert_eq!(format_perl_num(3.0), "3");
    assert_eq!(format_perl_num(0.5), "0.5");
  }

  // Codex R14/F1: `ConvertRationalList` (XMP.pm:3418-3427) — exactly-4-field
  // gate, `ConvertRational` per field, abort-to-unchanged on any miss.
  // All expected values cross-checked against bundled ExifTool 13.58.
  #[test]
  fn convert_rational_list_matches_exiftool() {
    use super::convert_rational_list;
    // 4 valid rationals — converted field-by-field, space-joined.
    assert_eq!(
      convert_rational_list("24/1 70/1 28/10 40/10"),
      "24 70 2.8 4"
    );
    assert_eq!(
      convert_rational_list("50/1 0/1 14/10 14/10"),
      "50 0 1.4 1.4"
    );
    // A zero-denominator field yields `ConvertRational`'s `inf`/`undef` token.
    assert_eq!(convert_rational_list("1/0 2/1 3/1 4/1"), "inf 2 3 4");
    assert_eq!(convert_rational_list("0/0 2/1 3/1 4/1"), "undef 2 3 4");
    // Not exactly 4 fields ⇒ returned UNCHANGED (3 fields / 1 field).
    assert_eq!(convert_rational_list("1/1 2/1 3/1"), "1/1 2/1 3/1");
    assert_eq!(convert_rational_list("5/10"), "5/10");
    // Any non-rational field aborts the whole conversion ⇒ UNCHANGED.
    assert_eq!(convert_rational_list("abc 2/1 3/1 4/1"), "abc 2/1 3/1 4/1");
    // The `+`-rational is not a `ConvertRational` match ⇒ abort ⇒ UNCHANGED.
    assert_eq!(
      convert_rational_list("+1/1 2/1 3/1 4/1"),
      "+1/1 2/1 3/1 4/1"
    );
  }

  // Codex R14/F1: `exif:ColorSpace` ValueConv `$val == 0xffffffff ? 0xffff
  // : $val` (XMP.pm:2003). All expected values cross-checked vs bundled 13.58.
  #[test]
  fn convert_color_space_matches_exiftool() {
    use super::convert_color_space;
    // The `0xffffffff` sentinel collapses to `0xffff` (65535).
    assert_eq!(convert_color_space("4294967295"), "65535");
    // The `==` is NUMERIC: a trailing `.0` / leading whitespace still match.
    assert_eq!(convert_color_space("4294967295.0"), "65535");
    assert_eq!(convert_color_space(" 4294967295"), "65535");
    // Every other value passes through UNCHANGED (the `: $val` branch — the
    // ORIGINAL string, never a re-rendered number).
    assert_eq!(convert_color_space("65535"), "65535");
    assert_eq!(convert_color_space("1"), "1");
    assert_eq!(convert_color_space("0"), "0");
    assert_eq!(convert_color_space("abc"), "abc");
  }

  // Codex R14/F1: `Exif::PrintLensInfo` (Exif.pm:5800-5818) — exactly-4-field
  // gate, `IsFloat`/`inf`/`undef` count gate, the Perl-truthy `if $vals[N]`
  // upper-value guards. All expected values cross-checked vs bundled 13.58.
  #[test]
  fn print_lens_info_matches_exiftool() {
    use super::print_lens_info;
    // Zoom lens — both ranges rendered.
    assert_eq!(print_lens_info("24 70 2.8 4"), "24-70mm f/2.8-4");
    // Prime lens — Pentax-Q-style `"0"` upper focal is Perl-falsy ⇒ dropped;
    // identical upper aperture ⇒ `ne` guard drops it too.
    assert_eq!(print_lens_info("50 0 1.4 1.4"), "50mm f/1.4");
    // `inf`/`undef` tokens are rewritten to `?` and DO count toward the gate.
    assert_eq!(print_lens_info("inf 70 2.8 4"), "?-70mm f/2.8-4");
    assert_eq!(print_lens_info("24 undef 2.8 4"), "24-?mm f/2.8-4");
    // Equal lower/upper focal ⇒ the `ne` guard drops the `-50`.
    assert_eq!(print_lens_info("50 50 1.4 1.4"), "50mm f/1.4");
    // Not exactly 4 fields ⇒ returned UNCHANGED.
    assert_eq!(print_lens_info("24 70 2.8"), "24 70 2.8");
    // A field that is neither a float nor `inf`/`undef` fails the count gate
    // ⇒ returned UNCHANGED.
    assert_eq!(print_lens_info("x 70 2.8 4"), "x 70 2.8 4");
  }
}
