// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "plist")]
//! Faithful port of `Image::ExifTool::PLIST` (lib/Image/ExifTool/PLIST.pm).
//!
//! Apple Property List files come in TWO on-disk encodings, both decoded by
//! the bundled `ProcessPLIST` (PLIST.pm:453-502):
//!
//! - **Binary plist** — magic `bplist0` (`bplist00` / `bplist01`). A tagged
//!   binary object graph: a top-level object index, an offset table at EOF,
//!   and a 32-byte trailer holding `intSize` / `refSize` / `numObj` /
//!   `topObj` / `tableOff` (PLIST.pm:398-447 `ProcessBinaryPLIST`). Objects
//!   are read by the type-tag dispatch in `ExtractObject` (PLIST.pm:260-392).
//! - **XML plist** — `<?xml …?>` + `<!DOCTYPE plist …>` + `<plist>` with
//!   `<dict>` / `<array>` / `<string>` / `<integer>` / `<real>` / `<date>` /
//!   `<true/>` / `<false/>` / `<data>` element nodes. Bundled dispatches XML
//!   plist through the XMP module's event parser with `FoundProc =>
//!   \&FoundTag` (PLIST.pm:155-244, 466-469). This port replays that exact
//!   EVENT STREAM ([`XmlEventWalker`]): a SAX-style scan over the `<plist>`
//!   subtree with a single persistent `@keys` stack, firing `FoundTag` key /
//!   value events in document order (Codex R6 — the prior value-tree walker
//!   could not reproduce the sticky cross-sibling key state of a heterogeneous
//!   `<array>` and dropped empty containers).
//!
//! The two encodings use DIFFERENT emit paths (faithful to bundled — the
//! binary path is a value-graph walk, the XML path an event stream):
//!
//! - Binary: [`ExtractObject`](extract_object) builds a `PlistValue` tree and
//!   [`walk_tree`] emits a tag ID `"$parent/$key"`; the dict walker emits leaf
//!   children directly with nested dict KEYS joined by a single `/`
//!   (PLIST.pm:343). The family-1 group is `"PLIST"` (PLIST.pm:484
//!   `$$et{SET_GROUP1} = 'PLIST'`).
//! - XML: [`XmlEventWalker`] keeps a persistent `@keys` stack of `<key>` names
//!   (mutated only by `<key>` events, read untouched by value events) and
//!   joins them with `/` (PLIST.pm:160-202). The family-1 group is `"XML"`
//!   (PLIST.pm:48 `GROUPS => { 1 => 'XML' }`, applied because XML plist runs
//!   through the XMP machinery).
//!
//! ## Tag-name generation (PLIST.pm:204-217 + 358-370)
//!
//! Bundled generates a tag NAME from the `/`-joined ID for any ID not in the
//! static `%Main` table (which the fixtures don't hit): strip a
//! `MetaDataList//` prefix, drop a trailing `//name`, capitalize the letter
//! after every non-alpha (`s/([^A-Za-z])([a-z])/$1\u$2/g`), strip illegal
//! characters (`tr/-_a-zA-Z0-9//dc`), and `ucfirst`. So `TestDict/Author`
//! becomes the tag name `TestDictAuthor` — the `/` is an illegal character
//! that is removed AFTER it triggers the capitalization of `Author`'s
//! already-uppercase `A` (a no-op) — net `TestDictAuthor`. See
//! `generate_xml_tag_name` / `generate_binary_tag_name` for the faithful
//! transliteration (the two encodings differ — see Codex R1 F3).
//!
//! ## Accepted deferrals (visible, per the port task)
//!
//! - **Composite engine** — bundled has no `%PLIST::Composite`; nothing to
//!   defer for the fixtures. Noted for completeness.
//! - **External DTD references** — the XML plist `<!DOCTYPE …>` line names an
//!   `http://www.apple.com/DTDs/PropertyList-1.0.dtd` external DTD. Bundled
//!   does NOT fetch or resolve it (the XMP parser ignores the DOCTYPE body);
//!   this port likewise skips the DOCTYPE declaration — faithful pass-through.
//! - **JSON-plist branch** (PLIST.pm:490-493) — a `{"`-prefixed file routes
//!   to `Image::ExifTool::JSON`. Out of scope (JSON is a separate format).
//!
//! ## Codex R20 — fixed real-input value-parity findings
//!
//! - **`adjustmentData` CompressedPLIST sub-directory** (PLIST.pm:142-146,
//!   228-241, 484) — FIXED. `adjustmentData` is now in [`PLIST_MAIN`]; the
//!   XML walker intercepts its `<data>` payload and routes through
//!   `process_compressed_plist`: PLIST.pm:228's `^bplist00` short-circuit
//!   skips inflate for already-uncompressed payloads (the AAE fixture's
//!   path), otherwise `miniz_oxide::inflate::decompress_to_vec` runs raw-
//!   DEFLATE inflation (the wire format `IO::Uncompress::RawInflate`
//!   consumes, PLIST.pm:231). The inflated/raw bytes re-enter the binary
//!   decoder and emit with `group_override = Some("PLIST")` faithful to
//!   PLIST.pm:484 `SET_GROUP1='PLIST'`. Inflate failure surfaces the bundled
//!   `Warn` text `COMPRESSED_PLIST_INFLATE_WARN` (PLIST.pm:234) on the meta's
//!   `warning` field.
//! - **Legacy UCS-2BE recognition arm** (PLIST.pm:494-499) — FIXED. A
//!   `.plist` whose body matches `\xfe\xff\x00` reaches
//!   `crate::parser::finalization_error`'s short-circuit and yields bundled's
//!   exact `ExifTool:Error: "Old PLIST format currently not supported"`. No
//!   `File:FileType` triplet (the UCS-2BE branch never calls `SetFileType` in
//!   bundled either).
//! - **Binary dict consecutive-duplicate-key list-fold** (PLIST.pm:362-378) —
//!   FIXED. `walk_tree`'s `Dict` branch now routes pair emissions through a
//!   scratch buffer + [`fold_consecutive_lists`] (was the case only for
//!   array-of-dict children, Codex R2 F4). A root binary dict `{a,a,b}`
//!   correctly emits `PLIST:TagA=[v1,v2], PLIST:TagB=v3`; class-sweep covers
//!   nested dicts under dicts (the fold is per-dict at every level) and the
//!   non-consecutive negative case (last-wins via TagMap last-wins-in-place
//!   insert).
//!
//! ## Recognized-but-unreadable inputs (Codex R14 F1 + class-sweep)
//!
//! Once a candidate's MAGIC matches, bundled COMMITS to the file type and never
//! drops it — a later body-decode failure becomes a reported error/warning, not
//! a rejection. This port now mirrors that for the binary path and the audit of
//! the analogous paths is recorded here (every claim verified against the stdin
//! oracle, `perl exiftool -j -G1 -struct`):
//!
//! - **Binary `bplist0` decode failure** (FIXED, the merge blocker): the magic
//!   matches (PLIST.pm:480) ⇒ `SetFileType('PLIST', 'application/x-plist')`
//!   (PLIST.pm:483) ⇒ `$result = 1` UNCONDITIONALLY (PLIST.pm:489); a falsy
//!   `ProcessBinaryPLIST` only adds `$et->Error('Error reading binary PLIST
//!   file')` (PLIST.pm:485-486). EVERY binary-decode failure mode lands at that
//!   one `unless (...)` chokepoint — missing/short trailer (PLIST.pm:419),
//!   `topObj >= numObj` (:426), an unsupported `intSize`/`refSize` (:427-428), a
//!   bad offset table (:432), a bad object ref / seek / malformed root object
//!   (`ExtractObject` :260-392) — so all yield the SAME `PLIST:Error` (oracle:
//!   identical output for the truncated, `topObj`, `intSize`, and `tableOff`
//!   cases). The port maps the whole class at the single [`decode_binary`]
//!   boundary (see [`parse_binary`]); the error is the family-1 `PLIST:Error`
//!   (PLIST.pm:484 `SET_GROUP1 = 'PLIST'`).
//! - **Malformed XML plist** (no recognized-PLIST `Error` path exists): the XML
//!   branch returns the XMP result directly (PLIST.pm:464-469 `return $result if
//!   $result`) — there is NO `$et->Error` in it. A truncated/unclosed `plist`
//!   element surfaces a family-0 `ExifTool:Warning` ("XMP format error …")
//!   emitted by the XMP TEXT parser, which this port does NOT model (the port
//!   runs its own tolerant SAX walk, not the XMP event parser); a
//!   well-formed-but-empty `plist` emits no diagnostic at all. So there is no
//!   XML "recognized-PLIST plus Error" class to add. An angle-bracket-leading
//!   file with NO recognizable `plist` structure correctly stays `Ok(None)`
//!   here — the oracle types it `TXT` (a `plist` element with no `xml` PI) or
//!   `XML` (an `xml` PI with a non-`plist` root), NOT PLIST, so the port must
//!   fall through to the next candidate.
//! - **Non-UTF-8 body inside a valid `<plist>`** (visible deferral): the oracle
//!   DOES recognize this as PLIST and extracts the tag with ExifTool's
//!   per-bad-unit `?` downgrade (e.g. `XML:TagK = "??"`, from
//!   `Decode($val, 'UTF8')`, PLIST.pm:186). The port's [`parse_xml`] currently
//!   returns `None` on a non-UTF-8 buffer (`from_utf8(...).ok()?`). Making this
//!   faithful is NOT a Rust `from_utf8_lossy` swap — lossy yields U+FFFD, but
//!   the golden is two ASCII `?` per bad unit (ExifTool's charset machinery), so
//!   a lossy decode would MISMATCH the golden. This is the same deferred
//!   charset/`Decode`-fidelity class as the binary type-5/6 string decode
//!   (decode_ascii / decode_ucs2_be already approximate it), is tangential to
//!   the R14 error-path fix, and produces no error/warning — only a
//!   tag-value-fidelity difference. Activate alongside a faithful ExifTool
//!   charset-downgrade helper.

// Golden-v2 Contract 3c (Phase C, slice S2): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use std::{string::String, vec::Vec};

use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// Magic
// ===========================================================================

/// Binary-plist magic prefix — bundled `PLIST.pm:480` `/\Gbplist0/`.
/// `bplist00` and `bplist01` are the two real-world variants; the gate keys
/// on the 7-byte `bplist0` prefix so both pass.
pub const BPLIST_MAGIC: &[u8] = b"bplist0";

/// The error a binary plist whose `bplist0` magic matched but whose body could
/// not be decoded carries — bundled `PLIST.pm:486`
/// `$et->Error('Error reading binary PLIST file')`. Faithful to the bundled
/// flow (PLIST.pm:480-489): once the magic matches, the file is recognized as
/// PLIST via `SetFileType('PLIST', 'application/x-plist')` (PLIST.pm:483) and
/// `$result = 1` is set UNCONDITIONALLY (PLIST.pm:489); a falsy
/// `ProcessBinaryPLIST` (PLIST.pm:485) only adds this `Error` tag — it never
/// un-recognizes the file. The `Error` lands in the family-1 `PLIST` group
/// because `$$et{SET_GROUP1} = 'PLIST'` (PLIST.pm:484) wraps the `Error` call
/// (verified via the `-G1` oracle ⇒ `"PLIST:Error"`).
const BINARY_PLIST_ERROR: &str = "Error reading binary PLIST file";

/// UTF-8 byte order mark (`EF BB BF`) — the optional leading BOM bundled's
/// XMP magic (ExifTool.pm:1045) and `ProcessXMP` (XMP.pm:4349) tolerate before
/// the `<?xml` of an XML plist. Used at the XML gate ([`parse_inner`]) and by the
/// content-sniff predicate ([`xml_content_is_plist`]); a binary plist never
/// carries it.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Size threshold above which a BINARY type-4 `data` object is NOT read into
/// memory. PLIST.pm:300 — `if ($size < 1000000 or $et->Options('Binary'))`:
/// the default (no-`-b`) path reads a binary `data` payload only when
/// `$size < 1000000`; at or above it PLIST.pm:302-303 stores a length-only
/// placeholder string. This port has no Binary/`-b` mode, so a binary `data`
/// object whose size is `>= BINARY_DATA_INLINE_LIMIT` always becomes a
/// length-only [`PlistValue::DataLen`] — never a multi-MB copy. The XML
/// `<data>` path has no equivalent threshold in bundled (PLIST.pm:171-179
/// decodes unconditionally) and is intentionally NOT gated on this.
const BINARY_DATA_INLINE_LIMIT: usize = 1_000_000;

// ===========================================================================
// Typed value tree
// ===========================================================================

/// One decoded plist value — the common tree both the binary and XML
/// decoders produce, and the single [`walk_tree`] consumer emits from.
///
/// Faithful to the value space bundled `ExtractObject` / `FoundTag` produce:
/// the scalar leaves carry their post-conversion form (a `<date>` is already
/// the formatted `"YYYY:MM:DD …"` string, a `<data>` carries the raw decoded
/// bytes), `Dict` / `Array` are the recursive containers.
///
/// D8: an enum with payload-carrying variants is the natural model here (a
/// value IS one of these shapes); the public surface is the accessor-only
/// [`PlistMeta`], so `PlistValue` stays crate-internal.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PlistValue {
  /// A `<string>` / binary ASCII or UCS-2 string. Owned (binary UCS-2 strings
  /// are transcoded; XML strings are entity-unescaped) — never borrows input.
  Str(String),
  /// An XML `<integer>` — decimal text, may be negative. Binary integers
  /// that fit `i64` also land here. (PLIST.pm:271-274.)
  Int(i64),
  /// A binary-plist integer whose `Get64u` value exceeds `i64::MAX` (Codex
  /// R3 F2). Binary plist type-1 integers are read by `Get64u` — an UNSIGNED
  /// read (PLIST.pm:35 `8 => \&Get64u`); Perl never sign-extends them, so a
  /// value like `0x8000000000000000` renders as the unsigned scalar
  /// `9223372036854775808`. Kept distinct from [`Self::Int`] so the value is
  /// not silently wrapped to a negative `i64`.
  UInt(u64),
  /// A `<real>` / binary float or double.
  Real(f64),
  /// A `<date>` — ALREADY the formatted date string (binary: faithful
  /// `ConvertUnixTime`, PLIST.pm:277; XML: `ConvertXMPDate`, PLIST.pm:180).
  Date(String),
  /// A `<true/>` / `<false/>` boolean.
  Bool(bool),
  /// A `<data>` element / SMALL binary data object — raw decoded bytes.
  Data(Vec<u8>),
  /// A LARGE binary type-4 data object — a length-only placeholder, NOT the
  /// bytes. PLIST.pm:300-303 reads a binary `data` object's payload only when
  /// `$size < 1000000` (or `-b`/Binary mode is set); otherwise it stores the
  /// literal scalar `"Binary data $size bytes"` and never touches the bytes
  /// (PLIST.pm:302-303 — note the `else` branch has no `$raf->Read`, so it is
  /// also NOT bounds-checked). The default JSON path only renders the
  /// `(Binary data N bytes...)` placeholder anyway (the `exiftool` script
  /// recognises the `^Binary data \d+ bytes$` scalar and just parenthesises
  /// it, exiftool:3983-3984), so a multi-MB data object never needs the
  /// bytes copied. `usize` is the real `$size` — the placeholder reports the
  /// TRUE byte count, not the length of the placeholder string. Only the
  /// binary decoder produces this; the XML `<data>` path has no bundled
  /// threshold (PLIST.pm:171-179 always decodes) and keeps [`Self::Data`].
  DataLen(usize),
  /// A `<dict>` — ordered `(key, value)` pairs (insertion order preserved,
  /// faithful to the on-disk order both decoders walk).
  Dict(Vec<(String, PlistValue)>),
  /// An `<array>` — ordered values.
  Array(Vec<PlistValue>),
}

// ===========================================================================
// PLIST::Main static tag table (PLIST.pm:46-147)
// ===========================================================================

/// One static-table conversion — the `ValueConv` / `PrintConv` a known
/// `%PLIST::Main` tag ID carries (Codex R3 F1).
///
/// PLIST.pm's `%Main` table assigns a fixed `Name` (handled separately via
/// [`StaticTag::name`]) and, for the MODD-metadata tags, a `ValueConv` and/or
/// `PrintConv`. ExifTool applies `ValueConv` regardless of the print mode and
/// `PrintConv` only in print (`-j`, default) mode — `-n` shows the
/// post-`ValueConv` value. So `ValueConv` is applied at WALK time (mode-
/// independent) and `PrintConv` at SERIALIZE time (mode-gated). Only the
/// conversions the three named fixture IDs hit are modelled — every other
/// `%Main` entry is a bare `Name` (no conv).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlistConv {
  /// No conversion — a `%Main` entry that is just a `Name` string.
  None,
  /// `MetaDataList//Duration` `PrintConv => 'ConvertDuration($val)'`
  /// (PLIST.pm:79). Print-mode only.
  Duration,
  /// `MetaDataList//Geolocation/Latitude` `PrintConv =>
  /// 'Image::ExifTool::GPS::ToDMS($self, $val, 1, "N")'` (PLIST.pm:84).
  /// Print-mode only.
  GpsLatitude,
  /// `MetaDataList//Geolocation/Longitude` `PrintConv =>
  /// '…ToDMS($self, $val, 1, "E")'` (PLIST.pm:89). Print-mode only.
  GpsLongitude,
  /// `MetaDataList//DateTimeOriginal` `ValueConv => 'IsFloat($val) ?
  /// ConvertUnixTime(($val - 25569) * 24 * 3600) : $val'` (PLIST.pm:73). A
  /// `ValueConv` — applied at walk time, mode-independent (its `PrintConv`,
  /// `$self->ConvertDateTime($val)`, is identity under the default options).
  DateTimeOriginalDays,
  /// The `slowMotion/.../timeRange/{start,duration}/flags` `PrintConv =>
  /// { BITMASK => { 0 => 'Valid', 1 => 'Has been rounded', 2 => 'Positive
  /// infinity', 3 => 'Negative infinity', 4 => 'Indefinite' } }`
  /// (PLIST.pm:98-104, 111-117). Print-mode only — `DecodeBits` joins the
  /// set-bit names with `, ` (unknown bits as `[n]`, no bits as `(none)`).
  SlowMotionFlags,
}

/// One `%PLIST::Main` static tag-table entry (PLIST.pm:46-147) — the `Name`
/// the known tag ID maps to plus its conversion.
///
/// The `%Main` `cast//name`-family entries also carry `List => 1`, but it is
/// NOT modelled as a field: under `exiftool -struct` (the canonical golden
/// mode) a repeated `List` tag collapses to last-value-wins exactly like a
/// non-list tag (verified — `"XML:Cast": "Bob"` for a two-element `cast`
/// array), and the binary list-accumulation is handled structurally by
/// [`fold_consecutive_lists`]. So `List` has no behavioral effect on the
/// emitted tag set here.
#[derive(Debug, Clone, Copy)]
struct StaticTag {
  /// The fixed `Name` (PLIST.pm `Name => …`).
  name: &'static str,
  /// The `ValueConv` / `PrintConv` this entry carries.
  conv: PlistConv,
}

/// The `%PLIST::Main` static tag table (PLIST.pm:46-147), keyed by the RAW
/// `/`-joined tag ID — `ExtractObject` / `FoundTag` consult `$$tagTablePtr{$tag}`
/// BEFORE generating a dynamic name (PLIST.pm:203 / :358, Codex R3 F1).
///
/// The binary dict path joins keys with a single `/` (PLIST.pm:343) and the
/// XML `FoundTag` path inserts an empty key-stack slot per nesting level
/// (PLIST.pm:191-194) — so the MODD `MetaDataList//…` double-slash IDs are
/// reached only by the XML path, while the single-slash IDs
/// (`SystemVersion/ProductName`, `FrameworkVersions/CoreMedia`, …) are reached
/// by both. The lookup is keyed by the exact ID either path produces, so each
/// entry applies to whichever encoding generates that ID.
///
/// `adjustmentData` (PLIST.pm:142-146) carries the `CompressedPLIST` raw-DEFLATE
/// sub-directory recursively dispatched through `Image::ExifTool::PLIST::Main`.
/// `StaticTag::is_compressed_plist` flags it so the XML walker routes the
/// `<data>` payload through [`process_compressed_plist`] (decompress via
/// `miniz_oxide` when not already `bplist00`-prefixed, then re-parse as binary
/// plist) rather than emitting the raw `<data>` bytes.
static PLIST_MAIN: &[(&str, StaticTag)] = &[
  // QuickTime iTunesInfo iTunMOVI atom tags (PLIST.pm:59-64) — `List => 1` in
  // bundled, but `List` has no effect on the emitted set here (see `StaticTag`).
  (
    "cast//name",
    StaticTag {
      name: "Cast",
      conv: PlistConv::None,
    },
  ),
  (
    "directors//name",
    StaticTag {
      name: "Directors",
      conv: PlistConv::None,
    },
  ),
  (
    "producers//name",
    StaticTag {
      name: "Producers",
      conv: PlistConv::None,
    },
  ),
  (
    "screenwriters//name",
    StaticTag {
      name: "Screenwriters",
      conv: PlistConv::None,
    },
  ),
  (
    "codirectors//name",
    StaticTag {
      name: "Codirectors",
      conv: PlistConv::None,
    },
  ),
  (
    "studio//name",
    StaticTag {
      name: "Studio",
      conv: PlistConv::None,
    },
  ),
  // MODD-file metadata tags (PLIST.pm:68-94).
  (
    "MetaDataList//DateTimeOriginal",
    StaticTag {
      name: "DateTimeOriginal",
      conv: PlistConv::DateTimeOriginalDays,
    },
  ),
  (
    "MetaDataList//Duration",
    StaticTag {
      name: "Duration",
      conv: PlistConv::Duration,
    },
  ),
  (
    "MetaDataList//Geolocation/Latitude",
    StaticTag {
      name: "GPSLatitude",
      conv: PlistConv::GpsLatitude,
    },
  ),
  (
    "MetaDataList//Geolocation/Longitude",
    StaticTag {
      name: "GPSLongitude",
      conv: PlistConv::GpsLongitude,
    },
  ),
  (
    "MetaDataList//Geolocation/MapDatum",
    StaticTag {
      name: "GPSMapDatum",
      conv: PlistConv::None,
    },
  ),
  // AAE slow-motion tags (PLIST.pm:96-123). The `*Flags` tags carry a
  // BITMASK `PrintConv` (PLIST.pm:98-104, 111-117 — `DecodeBits`).
  (
    "slowMotion/regions/timeRange/start/flags",
    StaticTag {
      name: "SlowMotionRegionsStartTimeFlags",
      conv: PlistConv::SlowMotionFlags,
    },
  ),
  (
    "slowMotion/regions/timeRange/start/value",
    StaticTag {
      name: "SlowMotionRegionsStartTimeValue",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions/timeRange/start/timescale",
    StaticTag {
      name: "SlowMotionRegionsStartTimeScale",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions/timeRange/start/epoch",
    StaticTag {
      name: "SlowMotionRegionsStartTimeEpoch",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions/timeRange/duration/flags",
    StaticTag {
      name: "SlowMotionRegionsDurationFlags",
      conv: PlistConv::SlowMotionFlags,
    },
  ),
  (
    "slowMotion/regions/timeRange/duration/value",
    StaticTag {
      name: "SlowMotionRegionsDurationValue",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions/timeRange/duration/timescale",
    StaticTag {
      name: "SlowMotionRegionsDurationTimeScale",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions/timeRange/duration/epoch",
    StaticTag {
      name: "SlowMotionRegionsDurationEpoch",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/regions",
    StaticTag {
      name: "SlowMotionRegions",
      conv: PlistConv::None,
    },
  ),
  (
    "slowMotion/rate",
    StaticTag {
      name: "SlowMotionRate",
      conv: PlistConv::None,
    },
  ),
  // Live-photo / system-version tags (PLIST.pm:125-132).
  (
    "SystemVersion/ProductBuildVersion",
    StaticTag {
      name: "ProductBuildVersion",
      conv: PlistConv::None,
    },
  ),
  (
    "SystemVersion/ProductName",
    StaticTag {
      name: "ProductName",
      conv: PlistConv::None,
    },
  ),
  (
    "SystemVersion/ProductVersion",
    StaticTag {
      name: "ProductVersion",
      conv: PlistConv::None,
    },
  ),
  (
    "FrameworkVersions/CoreMotion",
    StaticTag {
      name: "CoreMotionVersion",
      conv: PlistConv::None,
    },
  ),
  (
    "FrameworkVersions/CMCaptureCore",
    StaticTag {
      name: "CMCaptureCoreVersion",
      conv: PlistConv::None,
    },
  ),
  (
    "FrameworkVersions/H16ISPServices",
    StaticTag {
      name: "H16ISPServicesVersion",
      conv: PlistConv::None,
    },
  ),
  (
    "FrameworkVersions/CoreMedia",
    StaticTag {
      name: "CoreMediaVersion",
      conv: PlistConv::None,
    },
  ),
  // AAE `adjustmentData` (PLIST.pm:142-146) — `CompressedPLIST` raw-DEFLATE
  // sub-directory recursively dispatched through `Image::ExifTool::PLIST::Main`.
  // The `Name` here matches the static `%Main` entry (PLIST.pm:143
  // `Name => 'AdjustmentData'`); a real AAE file's `adjustmentData` value
  // never lands as a standalone tag because the XML walker intercepts it and
  // emits the inflated sub-walk's tags under the `PLIST` family-1 group
  // (PLIST.pm:484). When the inflate fails (`Error inflating PLIST::
  // AdjustmentData`, PLIST.pm:234), the name is still needed for the warning
  // string. `conv: None` because the static `Name` is the only field bundled
  // sets — the `CompressedPLIST => 1` + `SubDirectory => …` flags are handled
  // structurally by the XML walker (no engine-level `ValueConv` / `PrintConv`).
  (
    "adjustmentData",
    StaticTag {
      name: "AdjustmentData",
      conv: PlistConv::None,
    },
  ),
];

/// Look up a raw `/`-joined tag ID in the [`PLIST_MAIN`] static table —
/// `$$tagTablePtr{$tag}` (PLIST.pm:203 / :358, Codex R3 F1). Returns the
/// `%Main` entry when the ID is a known tag, `None` otherwise (the caller
/// then generates a dynamic name).
fn lookup_static(id: &str) -> Option<&'static StaticTag> {
  PLIST_MAIN
    .iter()
    .find(|(key, _)| *key == id)
    .map(|(_, info)| info)
}

// ===========================================================================
// Which encoding produced the tree (drives the family-1 group)
// ===========================================================================

/// The on-disk encoding the file used — selects the family-1 group at emit
/// time (`"PLIST"` for binary, `"XML"` for XML — see the module docs).
///
/// §2: a `Copy` unit-variant enum with a predicate + `as_str` (no `Display`
/// derive; `as_str` is the single rendering seam).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlistFormat {
  /// Binary plist (`bplist00` / `bplist01`). Family-1 group `"PLIST"`.
  Binary,
  /// XML plist (`<?xml …?>` + `<plist>`). Family-1 group `"XML"`.
  Xml,
}

impl PlistFormat {
  /// `true` for the binary (`bplist0…`) encoding.
  #[must_use]
  #[inline(always)]
  pub const fn is_binary(self) -> bool {
    matches!(self, Self::Binary)
  }

  /// `true` for the XML (`<?xml …?>`) encoding.
  #[must_use]
  #[inline(always)]
  pub const fn is_xml(self) -> bool {
    matches!(self, Self::Xml)
  }

  /// The family-1 group string this encoding emits its tags under
  /// (`"PLIST"` binary, `"XML"` XML — PLIST.pm:48 / 484).
  #[must_use]
  #[inline(always)]
  pub const fn group(self) -> &'static str {
    match self {
      Self::Binary => "PLIST",
      Self::Xml => "XML",
    }
  }
}

// ===========================================================================
// Content-derived file-type override target (PLIST.pm:41-43, :133-141, :225)
// ===========================================================================

/// A content-derived file-type override an XML plist requests — bundled's two
/// `OverrideFileType` mechanisms, both keyed on the EXACT raw `/`-joined tag ID
/// (NOT the generated tag name) and applied only when `$$self{FILE_TYPE} eq
/// 'XMP'` (the engine guard, PLIST.pm:136 / :225):
///
/// 1. `%plistType` (PLIST.pm:41-43) — a table mapping an exact raw tag ID to a
///    file type, applied at PLIST.pm:225 (`OverrideFileType($plistType{$tag})`
///    where `$tag = join '/', @keys`). The bundled table has ONE entry:
///    `adjustmentBaseVersion => 'AAE'`.
/// 2. The `XMLFileType` RawConv (PLIST.pm:133-141) — keyed on the `%Main` table
///    entry whose key is the exact raw tag ID `XMLFileType`; when its value is
///    `ModdXML` it calls `OverrideFileType('MODD')`. The table lookup uses the
///    raw `$tag` (PLIST.pm:203), so a NAME-colliding key such as `xMLFileType`
///    (which generates the SAME emitted name `XMLFileType`) does NOT carry the
///    RawConv and never overrides (Codex R11 F1).
///
/// Both fire per qualifying tag over the document-order `FoundTag` stream;
/// `OverrideFileType` is last-call-wins (it overwrites `VALUE{FileType}` each
/// time, ExifTool.pm:9714-9716), so the LAST qualifying tag in walk order
/// selects the target. A real MODD/AAE file carries only one of these keys.
///
/// §2: a `Copy` unit-variant enum with `is_*` predicates + an `as_str`
/// single-source rendering seam (the `OverrideFileType` target string). No
/// `Default` — "no override" is the absence of this value (modeled by the
/// `Option` the meta stores), not a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlistContentOverride {
  /// `OverrideFileType('MODD')` — raw tag ID `XMLFileType` == `ModdXML`
  /// (PLIST.pm:133-141).
  Modd,
  /// `OverrideFileType('AAE')` — `%plistType{adjustmentBaseVersion}`
  /// (PLIST.pm:42, applied at :225).
  Aae,
}

impl PlistContentOverride {
  /// `true` for the `XMLFileType == ModdXML` MODD override.
  #[must_use]
  #[inline(always)]
  pub const fn is_modd(self) -> bool {
    matches!(self, Self::Modd)
  }

  /// `true` for the `adjustmentBaseVersion` AAE override.
  #[must_use]
  #[inline(always)]
  pub const fn is_aae(self) -> bool {
    matches!(self, Self::Aae)
  }

  /// The `OverrideFileType($target)` file-type string this override applies
  /// (the single rendering seam — fed to `resolve_override_file_type`).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Modd => "MODD",
      Self::Aae => "AAE",
    }
  }

  /// The content-override an XML plist tag with raw ID `id` and string value
  /// `value` requests, if any — the exact-raw-ID predicate shared by the
  /// `%plistType` table (PLIST.pm:41-43, :225) and the `XMLFileType` RawConv
  /// (PLIST.pm:133-141). Keyed on the RAW `/`-joined tag ID, evaluated BEFORE
  /// the emitted-name generation discards it (Codex R11 F1/F2). `value` is the
  /// already-decoded (`UnescapeXML`/`Decode`) leaf string — only string-valued
  /// leaves can match (`adjustmentBaseVersion`'s `%plistType` entry has no
  /// value predicate; the `XMLFileType` RawConv requires `eq 'ModdXML'`).
  #[must_use]
  fn for_xml_tag(id: &str, value: &str) -> Option<Self> {
    match id {
      // PLIST.pm:42 — `%plistType` exact-ID entry (no value predicate).
      "adjustmentBaseVersion" => Some(Self::Aae),
      // PLIST.pm:136 — RawConv exact-ID `XMLFileType`, value `ModdXML`.
      "XMLFileType" if value == "ModdXML" => Some(Self::Modd),
      _ => None,
    }
  }
}

// ===========================================================================
// Typed Meta — `PlistMeta<'a>`
// ===========================================================================

/// One emitted plist tag — the `(name, value)` pair after the tag-tree walk.
///
/// The family-1 group is normally NOT stored per-entry (it is uniform for the
/// whole file — [`PlistMeta::format`]'s [`PlistFormat::group`]); the entry
/// carries only the generated tag name + the typed value. The exception is
/// the [`Self::group_override`] field, set for tags produced by a recursive
/// `CompressedPLIST` sub-directory dispatch (PLIST.pm:144-145, 228-241) —
/// bundled's `SET_GROUP1 = 'PLIST'` (PLIST.pm:484) inside `ProcessBinaryPLIST`
/// scopes the inflated child tags into the `PLIST` family-1 group even when
/// the outer XML plist's tags are emitted under `XML`. So an AAE
/// `adjustmentData` payload's `SlowMotionRegions*` children carry
/// `group_override = Some("PLIST")` while their sibling `adjustment*` keys
/// remain under the meta's XML group.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq)]
pub struct PlistTag {
  /// Generated tag name (e.g. `"TestDictAuthor"`, `"TestReal"`). A short tag
  /// identifier (stored, feeds the emitted tag name) ⇒ `SmolStr`; the static
  /// hit is a `&'static str` and the dynamic name is built in a transient
  /// `String` (a builder — String per the rule), both converted here.
  name: smol_str::SmolStr,
  /// The typed leaf value (already `ValueConv`-converted).
  value: PlistLeaf,
  /// The `%PLIST::Main` `PrintConv` to apply at serialize time, in print
  /// (`-j`) mode (Codex R3 F1). `PlistConv::None` for a dynamic-name tag or a
  /// static tag with no `PrintConv`; `Duration` / `GpsLatitude` /
  /// `GpsLongitude` for the MODD metadata tags whose `PrintConv` is
  /// print-mode-only. (`DateTimeOriginalDays` is a `ValueConv`, applied at
  /// walk time — it never appears here.)
  print_conv: PlistConv,
  /// Family-1 group override for tags emitted from a recursive
  /// `CompressedPLIST` sub-directory dispatch (PLIST.pm:144-145, 228-241).
  /// `None` ⇒ inherit the meta's [`PlistFormat::group`]. `Some("PLIST")` is
  /// used by the AAE `adjustmentData` sub-walk (PLIST.pm:484
  /// `$$et{SET_GROUP1} = 'PLIST'` inside `ProcessBinaryPLIST` applies to its
  /// children regardless of the outer caller's group).
  group_override: Option<&'static str>,
}

impl PlistTag {
  /// The generated tag name.
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The typed leaf value (borrow of the non-`Copy` [`PlistLeaf`]).
  #[must_use]
  #[inline(always)]
  pub const fn value(&self) -> &PlistLeaf {
    &self.value
  }

  /// Family-1 group override for this tag, if any — `Some("PLIST")` for tags
  /// emitted by a recursive `CompressedPLIST` sub-directory dispatch
  /// (PLIST.pm:484 `SET_GROUP1='PLIST'`); `None` means inherit the meta's
  /// [`PlistFormat::group`].
  #[must_use]
  #[inline(always)]
  pub const fn group_override(&self) -> Option<&'static str> {
    self.group_override
  }
}

/// The typed value an emitted [`PlistTag`] carries. A plist `<dict>` /
/// `<array>` is FLATTENED by the walker (dicts into `parent/key` tags,
/// scalar arrays into a list); only leaf-shaped values reach a `PlistTag`.
///
/// `#[non_exhaustive]` — additive within the crate.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PlistLeaf {
  /// A string value.
  Str(String),
  /// A signed integer value.
  Int(i64),
  /// A binary-plist integer above `i64::MAX` — kept unsigned, rendered as
  /// the unsigned scalar (Codex R3 F2; see [`PlistValue::UInt`]).
  UInt(u64),
  /// A real (floating-point) value.
  Real(f64),
  /// A date — already the formatted date string (binary: `ConvertUnixTime`;
  /// XML: `ConvertXMPDate`).
  Date(String),
  /// A boolean value.
  Bool(bool),
  /// Raw `<data>` bytes (rendered as the no-`-b` binary placeholder).
  Data(Vec<u8>),
  /// A LARGE binary type-4 data object — a length-only placeholder carrying
  /// the real byte count, NOT the bytes (see [`PlistValue::DataLen`]).
  /// PLIST.pm:300-303 stores `"Binary data $size bytes"` for a binary `data`
  /// object `>= 1000000` bytes instead of reading the payload; serialization
  /// renders the identical `(Binary data N bytes...)` placeholder a small
  /// [`Self::Data`] would, so the skipped bytes never need to be retained.
  DataLen(usize),
  /// A list of typed leaves — a BINARY plist `<array>` (a real Perl arrayref
  /// in bundled, unaffected by `-struct`). Faithful to PLIST.pm:379-388: the
  /// array branch keeps EVERY referenced object that is `defined` and not a
  /// `HASH` ref, so a binary `<array>` preserves its `int` / `real` /
  /// `string` / `bool` / `date` / `data` members AND nested `<array>`s
  /// (`ref ne 'HASH'` admits an arrayref) — only `<dict>` elements are
  /// dropped. (Codex R1 F2: the prior `StrList(Vec<String>)` flattened
  /// every member to a string and silently dropped Real / Data / nested
  /// arrays.) An XML `<array>` does NOT use this variant: under `-struct`
  /// its elements collapse to the last-value-wins scalar (see the walker).
  List(Vec<PlistLeaf>),
}

/// Typed Apple-Property-List metadata — the lib-first output of
/// [`ProcessPlist`].
///
/// Carries the on-disk [`PlistFormat`] (binary vs XML — selects the family-1
/// group) plus the ordered list of emitted [`PlistTag`]s (walk order,
/// faithful to bundled's `HandleTag` call sequence).
///
/// D8: no public fields; accessors only. Construct via [`ProcessPlist::parse`]
/// / [`parse_borrowed`].
///
/// The lifetime `'a` is a phantom: `PlistMeta` owns all its strings (binary
/// UCS-2 strings are transcoded, XML strings are entity-unescaped, tag names
/// are generated), so nothing borrows the input buffer. The parameter is kept
/// to satisfy the [`FormatParser::Meta`] GAT shape shared by every format.
#[derive(Debug, Clone)]
pub struct PlistMeta<'a> {
  format: PlistFormat,
  tags: Vec<PlistTag>,
  /// The content-derived file-type override this plist requests, if any — the
  /// LAST qualifying tag's target over the document-order walk (PLIST.pm:41-43
  /// `%plistType` + :133-141 `XMLFileType` RawConv, both keyed on the EXACT raw
  /// tag ID; last-call-wins per `OverrideFileType`). `None` for a binary plist
  /// (FILE_TYPE is `PLIST`, never `XMP`, so neither override can fire) or an
  /// XML plist with no override key. The engine applies it only when the file
  /// would otherwise have been typed `XMP` (`$$self{FILE_TYPE} eq 'XMP'`,
  /// PLIST.pm:136 / :225). See [`PlistContentOverride`].
  content_override: Option<PlistContentOverride>,
  /// A recoverable parse error this recognized plist carries, if any —
  /// bundled `$et->Error(...)` ([`BINARY_PLIST_ERROR`]). Set ONLY on the binary
  /// path: a `bplist0`-magic file whose body fails to decode is still
  /// recognized as PLIST (PLIST.pm:483/489) and emits `PLIST:Error`
  /// (PLIST.pm:485-486) instead of being dropped. `None` for a successfully
  /// decoded binary plist or any XML plist (the XML path has no `$et->Error`
  /// branch — a malformed XML plist surfaces an `ExifTool:Warning` from the XMP
  /// text parser, which this port does not model; see the module docs'
  /// class-sweep note). Carried as `&'static str` because the only message is
  /// the fixed bundled literal.
  error: Option<&'static str>,
  /// A recoverable `$et->Warn(...)` this plist carries, if any — bundled
  /// PLIST.pm:234 `$et->Warn("Error inflating PLIST::$$tagInfo{Name}")` when
  /// an AAE `adjustmentData` payload fails raw-DEFLATE inflate
  /// ([`COMPRESSED_PLIST_INFLATE_WARN`]). Surfaced under the engine `ExifTool:
  /// Warning` family-0 slot (NOT the family-1 group), matching bundled's
  /// `Warn` semantics. The XML path is the only one that can set this: a
  /// `bplist00`-prefixed `adjustmentData` payload bypasses inflate (PLIST.pm:
  /// 228) and never warns; the binary plist path has no compressed-sub-dir.
  warning: Option<&'static str>,
  _marker: core::marker::PhantomData<&'a [u8]>,
}

impl PlistMeta<'_> {
  /// The on-disk encoding (binary vs XML) — selects the family-1 group.
  #[must_use]
  #[inline(always)]
  pub const fn format(&self) -> PlistFormat {
    self.format
  }

  /// The recoverable parse error this recognized plist carries, if any —
  /// bundled `$et->Error('Error reading binary PLIST file')` (PLIST.pm:486).
  /// `Some` ONLY for a `bplist0`-magic binary plist whose body could not be
  /// decoded: bundled still recognizes such a file as PLIST (`SetFileType`,
  /// PLIST.pm:483; `$result = 1`, PLIST.pm:489) and reports the error tag
  /// rather than rejecting it. The error renders as the family-1 `PLIST:Error`
  /// tag (PLIST.pm:484 `SET_GROUP1 = 'PLIST'`), emitted by the golden
  /// [`Taggable`](crate::emit::Taggable) `tags` stream.
  #[must_use]
  #[inline(always)]
  pub const fn error(&self) -> Option<&'static str> {
    self.error
  }

  /// The recoverable `Warning` this plist carries, if any — bundled
  /// `$et->Warn(...)`. Currently the only sourced warning is the AAE
  /// `adjustmentData` raw-DEFLATE inflate failure (PLIST.pm:234,
  /// [`COMPRESSED_PLIST_INFLATE_WARN`]). The engine surfaces this under the
  /// family-0 `ExifTool:Warning` slot (the `$et->Warn` API does NOT honor
  /// `SET_GROUP1`, unlike `$et->Error`), so it is NOT scoped under the meta's
  /// [`PlistFormat::group`].
  #[must_use]
  #[inline(always)]
  pub const fn warning(&self) -> Option<&'static str> {
    self.warning
  }

  /// Every emitted tag in walk order. (`Vec` slice — never expose `&Vec`.)
  ///
  /// Named `tags_slice` (not `tags`) so it does not collide with the golden
  /// [`Taggable::tags`](crate::emit::Taggable::tags) trait method (the
  /// `(&self, mode)` rendered-`EmittedTag` stream the engine drives through
  /// [`run_emission`](crate::emit::run_emission)). This accessor exposes the
  /// raw typed [`PlistTag`] walk entries (pre-render).
  #[must_use]
  #[inline(always)]
  pub fn tags_slice(&self) -> &[PlistTag] {
    &self.tags
  }

  /// The content-derived file-type override this plist requests, if any
  /// (PLIST.pm:41-43 `%plistType` + :133-141 `XMLFileType` RawConv — both keyed
  /// on the EXACT raw tag ID). The bundled mechanisms then call
  /// `OverrideFileType($target)` — but ONLY when `$$self{FILE_TYPE} eq 'XMP'`,
  /// i.e. when the file was reached via the `.xml`-family (XMP) extension and
  /// not via an explicit `.plist`/`.modd`/`.aae` extension. The engine combines
  /// this with that FILE_TYPE check before applying the override. `None` for a
  /// binary plist (always FILE_TYPE `PLIST`) or an XML plist without an override
  /// key. See [`PlistContentOverride`].
  #[must_use]
  #[inline(always)]
  pub const fn content_override(&self) -> Option<PlistContentOverride> {
    self.content_override
  }
}

// ===========================================================================
// `ProcessPlist` — the lib-first parser
// ===========================================================================

/// Apple Property List parser — faithful port of
/// `Image::ExifTool::PLIST::ProcessPLIST` (PLIST.pm:453-502). Decodes both
/// the binary (`bplist0…`) and XML (`<?xml …?>`) encodings.
#[derive(Debug, Clone, Copy)]
pub struct ProcessPlist;

impl parser_sealed::Sealed for ProcessPlist {}

impl FormatParser for ProcessPlist {
  /// Leaf format: the Meta owns all its data (the `'a` GAT parameter is a
  /// phantom — see [`PlistMeta`]).
  type Meta<'a> = PlistMeta<'a>;
  /// Leaf format: reads a single byte slice.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error — none today (every bad input is `Ok(None)`).

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Returns a [`PlistMeta`]; the `'a` lifetime is a
/// phantom (the Meta owns all its strings — see [`PlistMeta`]).
///
/// # Errors
///
/// Returns `Err` only for Rust-level fatal modes (none today — every bad
/// input is `Ok(None)`, faithful to bundled `ProcessPLIST` `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Option<PlistMeta<'_>> {
  parse_inner(data)
}

/// Does this XML buffer's content identify it as a PLIST — bundled's
/// `ProcessXMP` content sniff (XMP.pm:4369-4387)? After an optional leading
/// UTF-8 BOM and the `<?xml …?>` PI, bundled recognizes a plist by either a
/// `<!DOCTYPE …>` whose root word is `plist` (XMP.pm:4370-4374 `<!DOCTYPE\s+(\w+)`
/// with `$1 eq 'plist'`) or a `<plist[\s>]` element (XMP.pm:4385).
///
/// This is the engine's gate for the XMP→PLIST dispatch route: a BOM-prefixed
/// XML plist matches the XMP `%magicNumber` (ExifTool.pm:1045 — BOM-tolerant)
/// but NOT the PLIST `%magicNumber` (ExifTool.pm:1015 — no BOM), so bundled
/// reaches `ProcessPLIST` only through `ProcessXMP`'s content relabel. This port
/// has no standalone XMP parser, so the engine consults this predicate to route
/// such a candidate to [`ProcessPlist`]. It is intentionally STRICT (requires
/// the `<?xml` PI and a `<plist>`/`<!DOCTYPE plist>` marker) so a BOM-prefixed
/// SVG/RDF/other XMP — which this port cannot parse anyway — is NOT mis-claimed.
///
/// Bundled reads 256 bytes into `$buf2` (XMP.pm:4322) before sniffing; this scans
/// the same leading window. A longer plist is still recognized because the
/// `<plist>` root immediately follows the short `<?xml`/`<!DOCTYPE>` preamble.
#[must_use]
pub fn xml_content_is_plist(data: &[u8]) -> bool {
  // `$buf2 = substr($buff, 0, 256)` with NUL bytes stripped (XMP.pm:4322-4323).
  // UTF-8 XML plists have no embedded NULs in this preamble, so a plain prefix
  // scan over the same window is faithful for the in-scope inputs.
  const SNIFF_WINDOW: usize = 256;
  // Checked `.get()`: `min(len, 256) <= len` ⇒ `Some`; `skip <= head.len()`
  // (a `take_while` count) ⇒ `Some` ⇒ byte-identical.
  let head = data.get(..data.len().min(SNIFF_WINDOW)).unwrap_or(data);
  // Skip a leading UTF-8 BOM (ExifTool.pm:1045 / XMP.pm:4349 accept it).
  let head = head.strip_prefix(UTF8_BOM).unwrap_or(head);
  // Must be XML (`<?xml`, after optional ASCII whitespace) — the branch under
  // which the plist sniff runs (the `$2 eq '<?xml'` arm, XMP.pm:4357/4385).
  let skip = head.iter().take_while(|b| b.is_ascii_whitespace()).count();
  let head = head.get(skip..).unwrap_or(head);
  if !head.starts_with(b"<?xml") {
    return false;
  }
  // `<!DOCTYPE\s+plist` (XMP.pm:4370-4374) OR `<plist[\s>]` (XMP.pm:4385).
  doctype_root_is_plist(head) || plist_element_present(head)
}

/// `<!DOCTYPE` + ASCII whitespace (`\s+`) + the root word `plist` — bundled's
/// `<!DOCTYPE\s+(\w+)` capture with `$1 eq 'plist'` (XMP.pm:4370-4374).
fn doctype_root_is_plist(head: &[u8]) -> bool {
  const DOCTYPE: &[u8] = b"<!DOCTYPE";
  const ROOT: &[u8] = b"plist";
  let mut i = 0;
  // Checked `.get()`: the `i + DOCTYPE.len() <= head.len()` guard makes
  // `head[i..i + DOCTYPE.len()]` in-range; `i + DOCTYPE.len() <= len` makes
  // `head[i + DOCTYPE.len()..]` in-range; `ws <= rest.len()` ⇒ byte-identical.
  while i + DOCTYPE.len() <= head.len() {
    if head.get(i..i + DOCTYPE.len()) == Some(DOCTYPE) {
      let rest = head.get(i + DOCTYPE.len()..).unwrap_or(&[]);
      let ws = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
      if ws > 0 && rest.get(ws..).is_some_and(|r| r.starts_with(ROOT)) {
        return true;
      }
    }
    i += 1;
  }
  false
}

/// `<plist` followed by ASCII whitespace or `>` — bundled's `<plist[\s>]`
/// element test (XMP.pm:4385).
fn plist_element_present(head: &[u8]) -> bool {
  const NEEDLE: &[u8] = b"<plist";
  let mut i = 0;
  // Checked `.get()`: the `i + NEEDLE.len() <= head.len()` guard makes the
  // window in-range ⇒ byte-identical.
  while i + NEEDLE.len() <= head.len() {
    if head.get(i..i + NEEDLE.len()) == Some(NEEDLE)
      && matches!(head.get(i + NEEDLE.len()), Some(&b) if b.is_ascii_whitespace() || b == b'>')
    {
      return true;
    }
    i += 1;
  }
  false
}

/// Detect the encoding and dispatch — faithful to `ProcessPLIST`
/// (PLIST.pm:453-502): an XML plist (leading `<`, after optional whitespace)
/// goes to the XML decoder; a `bplist0`-prefixed file to the binary decoder;
/// anything else is `None` (not a plist).
fn parse_inner(data: &[u8]) -> Option<PlistMeta<'_>> {
  // PLIST.pm:461-463 — `$$dataPt =~ /\G</` decides XML vs not. The `\G`
  // anchor is at `$start` (0 here); a plist XML file begins with `<?xml`
  // possibly after leading whitespace (the XMP entry tolerates leading
  // whitespace — filetype_data.rs's PLIST magic is `(bplist0|\s*<|…)`).
  //
  // A valid UTF-8 XML plist may carry a leading UTF-8 BOM (`EF BB BF`): some
  // XML-plist producers emit one. Bundled ExifTool reaches such a file through
  // its XMP path — the XMP `%magicNumber` (ExifTool.pm:1045
  // `…(\xef\xbb\xbf)?…\s*<`) and `ProcessXMP` (XMP.pm:4349 `^(\xef\xbb\xbf)?<\?xml`)
  // both accept the BOM, then `ProcessXMP` content-sniffs `<plist[\s>]`
  // (XMP.pm:4385) and routes the body to `PLIST::FoundTag`. The plain
  // (non-double-encoded) UTF-8 BOM is NOT stripped from the buffer there
  // (XMP.pm:4467 strips only the `<?xpacket` double-encode `$double`); the XMP
  // element scanner simply skips past it to the first `<`. This port folds the
  // XML-plist-via-XMP route into `ProcessPlist`, so mirror that BOM tolerance
  // at the XML gate: skip a leading UTF-8 BOM when deciding XML-vs-not, but —
  // faithful to bundled — feed the ORIGINAL buffer to `parse_xml` (its element
  // scan likewise skips the leading BOM to reach `<plist`). A binary plist
  // never carries a BOM (it starts with `bplist00`, ExifTool.pm:1015 /
  // PLIST.pm:480), so the binary gate below keys on the un-skipped buffer.
  let xml_view = data.strip_prefix(UTF8_BOM).unwrap_or(data);
  let first_non_ws = xml_view.iter().position(|b| !b.is_ascii_whitespace());
  // Checked `.get()`: `idx` is a `position()` result ⇒ in-range ⇒ byte-identical.
  if first_non_ws.is_some_and(|idx| xml_view.get(idx) == Some(&b'<')) {
    // XML plist (PLIST.pm:464-469 — the XMP-machinery branch).
    return parse_xml(data);
  }
  // PLIST.pm:480 — `$$dataPt =~ /\Gbplist0/` ⇒ binary PLIST. Once the magic
  // matches, the file is RECOGNIZED as PLIST (PLIST.pm:483 `SetFileType` +
  // :489 unconditional `$result = 1`); `parse_binary` always returns a meta —
  // a decode failure carries `PLIST:Error` rather than dropping the file
  // (Codex R14 F1). So this is `Ok(Some(...))`, never `Ok(None)`.
  if data.starts_with(BPLIST_MAGIC) {
    return Some(parse_binary(data));
  }
  // Not an XML plist, not a binary plist. PLIST.pm:490-493 covers JSON-plist
  // (`{"`-prefixed, out of scope per module docs). PLIST.pm:494-499 covers the
  // legacy UCS-2BE arm (`$$et{FILE_EXT} eq 'PLIST'` + `^\xfe\xff\x00`); the
  // port routes that at the [`crate::parser::finalization_error`] seam — `Ok(
  // None)` here lets the engine candidate loop exhaust, then the finalization
  // path returns bundled's exact `ExifTool:Error` text (Codex R20 F2).
  None
}

// ===========================================================================
// Binary plist decoder (PLIST.pm:260-447)
// ===========================================================================

/// Faithful `Get24u` (PLIST.pm:250-254) — big-endian 24-bit unsigned.
///
/// Checked-indexing (Phase C S2): the `.get(off..off + N)?` already bounds the
/// read; the slice-patterns below replace the `b[0..N]` indexing with the same
/// byte bindings ⇒ byte-identical.
#[inline]
fn get_u24(buf: &[u8], off: usize) -> Option<u32> {
  let &[b0, b1, b2, ..] = buf.get(off..off + 3)? else {
    return None;
  };
  Some(u32::from_be_bytes([0, b0, b1, b2]))
}

/// Read a big-endian unsigned integer of `size` bytes (1/2/3/4/8) starting at
/// `off` — faithful to the `%readProc` table (PLIST.pm:30-38) for the integer
/// sizes. Returns `None` on a short buffer or an unsupported size.
fn read_uint(buf: &[u8], off: usize, size: usize) -> Option<u64> {
  match size {
    1 => buf.get(off).map(|&b| u64::from(b)),
    2 => match buf.get(off..off + 2) {
      Some(&[b0, b1, ..]) => Some(u64::from(u16::from_be_bytes([b0, b1]))),
      _ => None,
    },
    3 => get_u24(buf, off).map(u64::from),
    4 => match buf.get(off..off + 4) {
      Some(&[b0, b1, b2, b3, ..]) => Some(u64::from(u32::from_be_bytes([b0, b1, b2, b3]))),
      _ => None,
    },
    8 => match buf.get(off..off + 8) {
      Some(&[b0, b1, b2, b3, b4, b5, b6, b7, ..]) => {
        Some(u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
      }
      _ => None,
    },
    _ => None,
  }
}

/// Lowercase hex digits — the `unpack 'H*'` alphabet (PLIST.pm:290).
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The lowercase-hex digit for a nibble — the checked-indexing form of
/// `HEX_LOWER[nib as usize]` (Phase C S2). Every caller masks to a single
/// nibble (`b >> 4` / `b & 0x0f`), so the index is always `0..16` and the
/// `b'0'` fallback is unreachable ⇒ byte-identical.
#[inline]
fn hex_lower_nibble(nib: u8) -> u8 {
  HEX_LOWER.get(nib as usize).copied().unwrap_or(b'0')
}

/// Format a 16-byte buffer as an ASF GUID — faithful `ASF::GetGUID`
/// (ASF.pm:525-534). The bundled code does `unpack('H*', pack('NnnNN',
/// unpack('VvvNN', $val)))` (a little-/big-endian byte swap of the first
/// three fields), inserts `-` after the 8/12/16/20 hex columns, and
/// uppercases the result — e.g. `33221100-5544-7766-8899-AABBCCDDEEFF`.
fn get_guid(buf: &[u8]) -> String {
  debug_assert_eq!(buf.len(), 16);
  // `unpack('VvvNN', $val)` then `pack('NnnNN', ...)`: field 1 is a 32-bit
  // LE→BE swap, fields 2 & 3 are 16-bit LE→BE swaps, fields 4 & 5 are 32-bit
  // BE read kept as BE — i.e. the last 8 bytes are emitted verbatim.
  // Checked-indexing (Phase C S2): the slice-pattern binds the 16 bytes the
  // raw `buf[0..16]` indexing did (the caller passes a 16-byte slice); a
  // shorter buffer yields the all-zero GUID (unreachable for real input) ⇒
  // byte-identical.
  let &[
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7,
    b8,
    b9,
    b10,
    b11,
    b12,
    b13,
    b14,
    b15,
  ] = buf
  else {
    return String::new();
  };
  let out: [u8; 16] = [
    b3, b2, b1, b0, // field 1 LE→BE
    b5, b4, // field 2 LE→BE
    b7, b6, // field 3 LE→BE
    b8, b9, b10, b11, b12, b13, b14, b15, // fields 4 & 5 verbatim
  ];
  let mut s = String::with_capacity(36);
  for (i, &b) in out.iter().enumerate() {
    if matches!(i, 4 | 6 | 8 | 10) {
      s.push('-');
    }
    s.push(hex_lower_nibble(b >> 4).to_ascii_uppercase() as char);
    s.push(hex_lower_nibble(b & 0x0f).to_ascii_uppercase() as char);
  }
  s
}

/// State threaded through the recursive binary-plist object reader — the
/// faithful `%plistInfo` hash (PLIST.pm:436-442).
struct BinaryDecoder<'d> {
  /// The whole file buffer (the binary plist `RAF`).
  data: &'d [u8],
  /// `$$plistInfo{Table}` — object index → file offset.
  table: Vec<usize>,
  /// `$$plistInfo{RefSize}` — bytes per object reference.
  ref_size: usize,
  /// Recursion-depth guard (PLIST.pm:328-331 caps the `$parent` ID length;
  /// we cap the recursion depth directly — simpler, equivalent intent).
  depth: u32,
}

/// Recursion-depth ceiling for the binary object graph (PLIST.pm:328-331
/// `length $parent > 1000` ⇒ `Warn` + bail). A plist nested 64 deep is
/// already pathological; the cap keeps the parser panic-/stack-safe.
const MAX_BINARY_DEPTH: u32 = 64;

/// Parse a `bplist0`-magic file — faithful to the bundled binary branch of
/// `ProcessPLIST` (PLIST.pm:480-489). The caller ([`parse_inner`]) reaches
/// here ONLY after the `bplist0` magic matched (PLIST.pm:480), which in bundled
/// is the point of `SetFileType('PLIST', 'application/x-plist')` (PLIST.pm:483)
/// — so this ALWAYS yields a recognized binary-PLIST meta (the file IS a
/// PLIST), mirroring the unconditional `$result = 1` (PLIST.pm:489); the return
/// is infallible (`PlistMeta`, not `Option`).
///
/// The actual decode is the fallible [`decode_binary`] (faithful
/// `ProcessBinaryPLIST`, PLIST.pm:398-447). When it fails — ANY of the bundled
/// `return 0` / `return undef` paths (missing/short trailer, `topObj>=numObj`,
/// an unsupported `intSize`/`refSize`, a bad offset table, a bad object ref,
/// a malformed root object, …) — bundled does NOT drop the file: PLIST.pm:485
/// `unless (ProcessBinaryPLIST(...))` adds `$et->Error('Error reading binary
/// PLIST file')` (PLIST.pm:486) and still returns success. This port mirrors
/// that exactly: a decode failure yields a recognized PLIST meta carrying
/// [`BINARY_PLIST_ERROR`] (rendered as `PLIST:Error`) with no tags, rather than
/// `None` (Codex R14 F1). Mapping the failure here, at the `decode_binary`
/// boundary, covers the WHOLE binary-failure class in one place — the same
/// chokepoint as the bundled `unless (...)`.
fn parse_binary(data: &[u8]) -> PlistMeta<'_> {
  match decode_binary(data) {
    // PLIST.pm:445-446 — `ProcessBinaryPLIST` succeeded (`$$dirInfo{Value}`
    // defined). Recognized PLIST, no error.
    Some(tags) => PlistMeta {
      format: PlistFormat::Binary,
      tags,
      // The binary path always `SetFileType('PLIST', …)` (PLIST.pm:483), so the
      // `$$self{FILE_TYPE} eq 'XMP'` guard on BOTH content overrides (the
      // `XMLFileType` RawConv, PLIST.pm:136, and the `%plistType` table at :225)
      // can never hold — a binary plist never content-overrides. Also `%plistType`
      // is applied only in `FoundTag` (the XML path), not the binary `HandleTag`
      // dict branch (PLIST.pm:362-377).
      content_override: None,
      error: None,
      warning: None,
      _marker: core::marker::PhantomData,
    },
    // PLIST.pm:485-486 — `ProcessBinaryPLIST` returned falsy ⇒ recognized
    // PLIST + `$et->Error('Error reading binary PLIST file')`. Still
    // `$result = 1` (PLIST.pm:489): the file is NOT dropped.
    None => PlistMeta {
      format: PlistFormat::Binary,
      tags: Vec::new(),
      content_override: None,
      error: Some(BINARY_PLIST_ERROR),
      warning: None,
      _marker: core::marker::PhantomData,
    },
  }
}

/// Decode the binary plist body — faithful `ProcessBinaryPLIST`
/// (PLIST.pm:398-447) plus `ExtractObject` (PLIST.pm:260-392). Returns the
/// flattened tag list on success, or `None` on any structural failure (every
/// bundled `return 0` / `return undef`). The `None` is mapped to the
/// recognized-PLIST `Error` meta by the caller [`parse_binary`] (PLIST.pm:485)
/// — a failure here NEVER means "not a plist".
fn decode_binary(data: &[u8]) -> Option<Vec<PlistTag>> {
  // PLIST.pm:419 — `$raf->Seek(-32,2) and $raf->Read($buff,32)==32`. The
  // 32-byte trailer must exist (an 8-byte magic + 32-byte trailer ⇒ ≥ 40).
  if data.len() < 40 {
    return None;
  }
  // Checked `.get()`: `data.len() >= 40 > 32` (guarded above) ⇒ the 32-byte
  // trailer window is `Some` ⇒ byte-identical; the empty fallback is
  // unreachable.
  let trailer = data.get(data.len() - 32..).unwrap_or(&[]);
  // PLIST.pm:420-424 — trailer fields (the leading 6 trailer bytes unused).
  let int_size = usize::from(trailer.get(6).copied().unwrap_or(0));
  let ref_size = usize::from(trailer.get(7).copied().unwrap_or(0));
  let num_obj = read_uint(trailer, 8, 8)? as usize;
  let top_obj = read_uint(trailer, 16, 8)? as usize;
  let table_off = read_uint(trailer, 24, 8)? as usize;
  // PLIST.pm:426 — `return 0 if $topObj >= $numObj`.
  if top_obj >= num_obj {
    return None;
  }
  // PLIST.pm:427-428 — `intSize` / `refSize` must be a supported `%readProc`
  // width (1/2/3/4/8). `read_uint` rejects others; pre-check here so a bad
  // width fails fast.
  if !matches!(int_size, 1 | 2 | 3 | 4 | 8) || !matches!(ref_size, 1 | 2 | 3 | 4 | 8) {
    return None;
  }
  // PLIST.pm:431-435 — read the offset table: `numObj` entries, each
  // `intSize` bytes, starting at `tableOff`.
  let table_size = int_size.checked_mul(num_obj)?;
  let table_end = table_off.checked_add(table_size)?;
  if table_end > data.len() {
    return None;
  }
  let mut table = Vec::with_capacity(num_obj);
  for i in 0..num_obj {
    let entry_off = table_off + i * int_size;
    table.push(read_uint(data, entry_off, int_size)? as usize);
  }
  let mut dec = BinaryDecoder {
    data,
    table,
    ref_size,
    depth: 0,
  };
  // PLIST.pm:444-445 — seek to the top object and extract it.
  let top_off = *dec.table.get(top_obj)?;
  let root = extract_object(&mut dec, top_off)?;
  // The top object is normally a `<dict>`; the walker flattens it into tags.
  let mut tags = Vec::new();
  walk_tree(&root, &mut Vec::new(), &mut tags);
  Some(tags)
}

/// Faithful `ExtractObject` (PLIST.pm:260-392) — read the binary object at
/// file offset `obj_off`. Returns `None` on a structural failure (every
/// bundled `return undef` / `return 0`).
fn extract_object(dec: &mut BinaryDecoder<'_>, obj_off: usize) -> Option<PlistValue> {
  // PLIST.pm:266 — `$raf->Read($buff,1)`. The first byte is `type<<4 | size`.
  let marker = *dec.data.get(obj_off)?;
  let obj_type = marker >> 4;
  let low = usize::from(marker & 0x0f);
  let mut cursor = obj_off + 1;

  match obj_type {
    // PLIST.pm:269-270 — type 0: null / bool / fill.
    0 => match low {
      0x08 => Some(PlistValue::Bool(true)),  // `True`
      0x09 => Some(PlistValue::Bool(false)), // `False`
      // 0x00 `<null>` / 0x0f `<fill>` — bundled stores the literal string;
      // neither is a real dict value in any plist. Return them as strings
      // faithfully (the dict walker `next`s on undef, not on these).
      0x00 => Some(PlistValue::Str("<null>".into())),
      0x0f => Some(PlistValue::Str("<fill>".into())),
      _ => None,
    },
    // PLIST.pm:271-279 — types 1/2/3: int / float / date. `1 << low` bytes.
    1..=3 => {
      let size = 1usize << low;
      if obj_type == 1 {
        // Integer — big-endian UNSIGNED of `size` bytes (PLIST.pm:30-35
        // `%readProc` maps every integer size to a `Get*u` proc; the 8-byte
        // case is `Get64u`). Codex R3 F2: Perl never sign-extends — a
        // `Get64u` value above `i64::MAX` (e.g. `0x8000000000000000`) must
        // render as the unsigned scalar, NOT a wrapped negative `i64`. Keep
        // it unsigned past the `i64` ceiling.
        let raw = read_uint(dec.data, cursor, size)?;
        Some(match i64::try_from(raw) {
          Ok(n) => PlistValue::Int(n),
          Err(_) => PlistValue::UInt(raw),
        })
      } else if obj_type == 2 {
        // Float — `%readProc{size + 0x100}` ⇒ 4-byte single / 8-byte double.
        let real = read_real(dec.data, cursor, size)?;
        Some(PlistValue::Real(real))
      } else {
        // Date — an 8-byte (rarely 4-byte) BE float, seconds since the
        // Apple epoch 2001-01-01. PLIST.pm:275-278.
        let secs = read_real(dec.data, cursor, size)?;
        Some(PlistValue::Date(convert_binary_date(secs)))
      }
    }
    // PLIST.pm:280-291 — type 8: UID. `++$size` ⇒ `low + 1` bytes.
    8 => {
      let size = low + 1;
      let bytes = dec.data.get(cursor..cursor.checked_add(size)?)?;
      // PLIST.pm:283-291 — `$readProc{$size}` handles sizes 1/2/3/4/8 as a
      // numeric `Get*u` read; size 16 ⇒ `ASF::GetGUID`; every other width
      // (5-7, 9-15) ⇒ `"0x" . unpack 'H*', $buff` — the full-byte hex.
      match size {
        1 | 2 | 3 | 4 | 8 => {
          // Numeric — an unsigned `Get*u` read. Keep it unsigned past
          // `i64::MAX` (Codex R3 F2).
          let raw = read_uint(dec.data, cursor, size)?;
          Some(match i64::try_from(raw) {
            Ok(n) => PlistValue::Int(n),
            Err(_) => PlistValue::UInt(raw),
          })
        }
        // PLIST.pm:286-288 — 16-byte UID ⇒ `ASF::GetGUID`.
        16 => Some(PlistValue::Str(get_guid(bytes))),
        // PLIST.pm:290 — every other width: `"0x" . unpack 'H*', $buff`.
        _ => {
          let mut hex = String::with_capacity(2 + size * 2);
          hex.push_str("0x");
          for &b in bytes {
            hex.push(hex_lower_nibble(b >> 4) as char);
            hex.push(hex_lower_nibble(b & 0x0f) as char);
          }
          Some(PlistValue::Str(hex))
        }
      }
    }
    // PLIST.pm:292-389 — types 4/5/6/10/12/13 — the size-prefixed objects.
    4 | 5 | 6 | 10 | 12 | 13 => {
      // PLIST.pm:294-298 — `$size == 0x0f` ⇒ the count is stored in an
      // extra integer object that immediately follows.
      let count = if low == 0x0f {
        let (n, consumed) = read_inline_int(dec, cursor)?;
        cursor += consumed;
        n
      } else {
        low
      };
      match obj_type {
        // PLIST.pm:299-305 — type 4: data.
        4 => {
          // PLIST.pm:300 — `if ($size < 1000000 or $et->Options('Binary'))`.
          // The default path (no `-b`) reads the payload only below the 1 MB
          // threshold; at or above it PLIST.pm:302-303 stores the literal
          // `"Binary data $size bytes"` placeholder WITHOUT a `$raf->Read`
          // (the `else` branch — so it is not even bounds-checked, matching
          // the truncated-but-oversized case the oracle confirms). A length-
          // only `DataLen` mirrors that: no multi-MB copy in a media indexer.
          if count >= BINARY_DATA_INLINE_LIMIT {
            Some(PlistValue::DataLen(count))
          } else {
            let end = cursor.checked_add(count)?;
            let bytes = dec.data.get(cursor..end)?;
            Some(PlistValue::Data(bytes.to_vec()))
          }
        }
        // PLIST.pm:306-307 — type 5: ASCII string.
        5 => {
          let end = cursor.checked_add(count)?;
          let bytes = dec.data.get(cursor..end)?;
          // ASCII bytes; faithful pass-through as UTF-8 (latin-1 high bytes
          // would be rare and bundled `Decode`s ASCII verbatim).
          Some(PlistValue::Str(decode_ascii(bytes)))
        }
        // PLIST.pm:308-311 — type 6: UCS-2BE string. `count` is the CHAR
        // count; the byte length is `count * 2`.
        6 => {
          let byte_len = count.checked_mul(2)?;
          let end = cursor.checked_add(byte_len)?;
          let bytes = dec.data.get(cursor..end)?;
          Some(PlistValue::Str(decode_ucs2_be(bytes)))
        }
        // PLIST.pm:312-388 — types 10/12/13: array / set / dict — lists of
        // object references.
        10 | 12 | 13 => {
          // PLIST.pm:316 — a dict stores `2 * size` refs (keys then values);
          // an array/set stores `size` refs.
          let ref_count = if obj_type == 13 {
            count.checked_mul(2)?
          } else {
            count
          };
          let refs = read_refs(dec, cursor, ref_count)?;
          if obj_type == 13 {
            extract_dict(dec, &refs, count)
          } else {
            // array / set — extract each referenced object in order.
            extract_array(dec, &refs)
          }
        }
        _ => None,
      }
    }
    // Any other top nibble is not a valid binary-plist object.
    _ => None,
  }
}

/// Read a list of `ref_count` object references starting at `cursor` — each
/// `dec.ref_size` bytes (PLIST.pm:318-325).
fn read_refs(dec: &BinaryDecoder<'_>, cursor: usize, ref_count: usize) -> Option<Vec<usize>> {
  let total = dec.ref_size.checked_mul(ref_count)?;
  let end = cursor.checked_add(total)?;
  if end > dec.data.len() {
    return None;
  }
  let mut refs = Vec::with_capacity(ref_count);
  for i in 0..ref_count {
    let r = read_uint(dec.data, cursor + i * dec.ref_size, dec.ref_size)? as usize;
    // PLIST.pm:323 — `return 0 if $ref >= @$table`.
    if r >= dec.table.len() {
      return None;
    }
    refs.push(r);
  }
  Some(refs)
}

/// Read an INLINE integer object at `off` (the `$size == 0x0f` extra-count
/// object, PLIST.pm:296). Returns `(value, bytes_consumed)`. The inline
/// object is itself a type-1 int marker + its bytes.
fn read_inline_int(dec: &BinaryDecoder<'_>, off: usize) -> Option<(usize, usize)> {
  let marker = *dec.data.get(off)?;
  // PLIST.pm:296-297 — the extra object MUST be an integer (`/^\d+$/`).
  if marker >> 4 != 1 {
    return None;
  }
  let size = 1usize << usize::from(marker & 0x0f);
  let raw = read_uint(dec.data, off + 1, size)?;
  Some((raw as usize, 1 + size))
}

/// Extract a binary dict from its key/value reference list (PLIST.pm:326-378).
/// `refs` holds `2 * num_pairs` entries: keys `[0..num_pairs)`, values
/// `[num_pairs..2*num_pairs)`.
fn extract_dict(
  dec: &mut BinaryDecoder<'_>,
  refs: &[usize],
  num_pairs: usize,
) -> Option<PlistValue> {
  // PLIST.pm:328-331 — recursion-depth guard.
  if dec.depth >= MAX_BINARY_DEPTH {
    return None;
  }
  dec.depth += 1;
  let mut pairs: Vec<(String, PlistValue)> = Vec::with_capacity(num_pairs);
  for i in 0..num_pairs {
    // PLIST.pm:337-339 — read the key object; skip the pair on a bad key.
    let key_ref = *refs.get(i)?;
    let key_off = *dec.table.get(key_ref)?;
    let Some(key_val) = extract_object(dec, key_off) else {
      continue; // PLIST.pm:339 `next unless defined $key`
    };
    let key = match plist_value_as_key(&key_val) {
      Some(k) if !k.is_empty() => k,
      // PLIST.pm:339 — `next unless … length $key`.
      _ => continue,
    };
    // PLIST.pm:341-345 — read the value object.
    let val_ref = *refs.get(num_pairs + i)?;
    let val_off = *dec.table.get(val_ref)?;
    let Some(val) = extract_object(dec, val_off) else {
      continue; // PLIST.pm:346 `next if not defined $obj`
    };
    pairs.push((key, val));
  }
  dec.depth -= 1;
  Some(PlistValue::Dict(pairs))
}

/// Extract a binary array/set from its reference list (PLIST.pm:379-388).
fn extract_array(dec: &mut BinaryDecoder<'_>, refs: &[usize]) -> Option<PlistValue> {
  if dec.depth >= MAX_BINARY_DEPTH {
    return None;
  }
  dec.depth += 1;
  let mut items = Vec::with_capacity(refs.len());
  for &r in refs {
    let off = *dec.table.get(r)?;
    // PLIST.pm:384 `next unless defined $val and ref $val ne 'HASH'` drops a
    // `<dict>` member from the arrayref ONLY — but `ExtractObject` still
    // routes the dict's own `key`/`value` pairs through `HandleTag` as
    // separate `parent/key` tags FIRST (PLIST.pm:347-377). So the decoded
    // TREE must KEEP the dict member: the [`walk_tree`] binary-array branch
    // (Codex R2 F4) recurses into it to emit those child tags and then
    // excludes the dict from the list VALUE. (The prior pass dropped the
    // dict here, so its child tags never reached the walker.) An `undef`
    // member is still dropped — only a `defined` object is pushed.
    if let Some(v) = extract_object(dec, off) {
      items.push(v);
    }
  }
  dec.depth -= 1;
  Some(PlistValue::Array(items))
}

/// Render a decoded key object as a dict key string. Binary plist keys are
/// normally type-5 ASCII strings; an integer / non-string key is stringified
/// faithfully so the `parent/key` tag ID is still well-formed.
fn plist_value_as_key(v: &PlistValue) -> Option<String> {
  match v {
    PlistValue::Str(s) => Some(s.clone()),
    PlistValue::Int(n) => Some(itoa(*n)),
    PlistValue::UInt(n) => {
      let mut s = String::new();
      let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{n}"));
      Some(s)
    }
    // A bool / real / container key is not something a real plist emits;
    // returning `None` makes the dict walker skip the pair (PLIST.pm:339).
    _ => None,
  }
}

/// Read a binary-plist real of `size` bytes — 4-byte IEEE single or 8-byte
/// double, big-endian (`%readProc{0x104}` / `{0x108}`, PLIST.pm:36-37).
fn read_real(buf: &[u8], off: usize, size: usize) -> Option<f64> {
  // Checked-indexing (Phase C S2): `.get()` + slice-patterns bind the same
  // bytes the raw `b[0..N]` did ⇒ byte-identical.
  match size {
    4 => match buf.get(off..off + 4) {
      Some(&[b0, b1, b2, b3, ..]) => Some(f64::from(f32::from_be_bytes([b0, b1, b2, b3]))),
      _ => None,
    },
    8 => match buf.get(off..off + 8) {
      Some(&[b0, b1, b2, b3, b4, b5, b6, b7, ..]) => {
        Some(f64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
      }
      _ => None,
    },
    _ => None,
  }
}

/// Decode an ASCII byte slice to an owned `String`. Bytes ≥ 0x80 (not valid
/// in a binary-plist type-5 string) are passed through as their Unicode
/// code-point so the parser never panics on malformed input.
fn decode_ascii(bytes: &[u8]) -> String {
  match core::str::from_utf8(bytes) {
    Ok(s) => s.to_string(),
    Err(_) => bytes.iter().map(|&b| b as char).collect(),
  }
}

/// Decode a UCS-2 big-endian byte slice (binary-plist type-6 string) to an
/// owned `String` — faithful to `Decode($buff, 'UTF16')` (PLIST.pm:311). An
/// unpaired surrogate becomes U+FFFD (Rust's `decode_utf16` lossy behavior);
/// a trailing odd byte is dropped.
fn decode_ucs2_be(bytes: &[u8]) -> String {
  let units = bytes.chunks_exact(2).map(|c| match c {
    // `chunks_exact(2)` yields exactly-2-byte chunks; the slice-pattern binds
    // the same `c[0..2]` (the `_` arm is unreachable) ⇒ byte-identical.
    &[hi, lo, ..] => u16::from_be_bytes([hi, lo]),
    _ => 0,
  });
  char::decode_utf16(units)
    .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect()
}

/// Faithful integer→string (used for stringified dict keys / list items).
fn itoa(n: i64) -> String {
  let mut s = String::new();
  let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{n}"));
  s
}

// ===========================================================================
// Binary-plist date conversion (PLIST.pm:275-278)
// ===========================================================================

/// Seconds from the Unix epoch (1970-01-01) to the Apple/CoreFoundation epoch
/// (2001-01-01) — PLIST.pm:277 `11323 * 24 * 3600`. (`11323` days = the day
/// count from 1970-01-01 to 2001-01-01.)
const APPLE_EPOCH_OFFSET_SECS: i64 = 11323 * 24 * 3600;

/// Faithful `ConvertUnixTime($val + 11323*24*3600, 1)` (PLIST.pm:277) — the
/// `$toLocal = 1` branch of `ConvertUnixTime` (ExifTool.pm:6773-6800).
///
/// Input: seconds since the Apple epoch (a binary-plist `<date>` value, an
/// 8-byte BE double). The bundled call passes `$toLocal = 1`, so the result
/// is the OS-LOCAL broken-down clock with a `TimeZoneString` numeric-offset
/// suffix (ExifTool.pm:6794-6795).
///
/// This delegates to [`crate::datetime::convert_unix_time_local`], which ports
/// the faithful `localtime` branch (the OS timezone via
/// `jiff::tz::TimeZone::system()` under `std`; a documented `+00:00` UTC
/// fallback under `no_std`, where no OS TZ database exists). The conformance
/// harness pins `TZ=UTC` (`tools/gen_golden.sh`) so the golden is
/// host-independent while still exercising the localtime code path.
fn convert_binary_date(apple_secs: f64) -> String {
  let unix_secs = apple_secs + APPLE_EPOCH_OFFSET_SECS as f64;
  // ExifTool.pm:6776-6795 — `ConvertUnixTime($time, 1)` on the FLOAT. The
  // shared helper ports the fractional reduction (`sprintf('%.0f', $frac)`
  // half-to-EVEN + carry, :6780-6785; Codex R4 F1 — Rust's `f64::round()`
  // was half-away-from-zero and mis-rounded an exact `…:00.5` to `…:01`)
  // and the `$toLocal = 1` localtime branch (:6794-6795).
  crate::datetime::convert_unix_time_local_f64(unix_secs)
}

// ===========================================================================
// `CompressedPLIST` recursive sub-directory (PLIST.pm:142-146, 228-241, 484)
// ===========================================================================

/// The bundled `Warn` string for a failed AAE `adjustmentData` raw-DEFLATE
/// inflate — `$et->Warn("Error inflating PLIST::$$tagInfo{Name}")`
/// (PLIST.pm:234). `$$tagInfo{Name}` is `AdjustmentData` for the only entry
/// carrying `CompressedPLIST => 1` (PLIST.pm:143), so the rendered text is
/// fixed: `"Error inflating PLIST::AdjustmentData"`. Used by
/// [`process_compressed_plist`] when [`miniz_oxide::inflate::decompress_to_vec`]
/// returns an error.
const COMPRESSED_PLIST_INFLATE_WARN: &str = "Error inflating PLIST::AdjustmentData";

/// Process the AAE `adjustmentData` `CompressedPLIST` sub-directory
/// (PLIST.pm:142-146, 228-241). `bytes` is the already-decoded `<data>`
/// payload (Base64- or ASCII-hex-decoded). Returns the inflated binary plist's
/// tags with `group_override = Some("PLIST")` (PLIST.pm:484 `SET_GROUP1 =
/// 'PLIST'` inside `ProcessBinaryPLIST` scopes the sub-walk into the family-1
/// `PLIST` group) plus an optional warning string — `Some(
/// COMPRESSED_PLIST_INFLATE_WARN)` when the non-`bplist00` payload failed to
/// inflate (PLIST.pm:234).
///
/// PLIST.pm:228 — `if (... and $$val !~ /^bplist00/) { rawinflate }`. So a
/// payload that is ALREADY a `bplist00`-magic binary plist (which the real
/// AAE fixture is) skips the inflate step and is parsed verbatim. The
/// short-circuit matches bundled byte-for-byte.
///
/// `miniz_oxide::inflate::decompress_to_vec` is RAW DEFLATE (no zlib header) —
/// the same wire format `IO::Uncompress::RawInflate::rawinflate` consumes
/// (PLIST.pm:231; `RawInflate` is the raw-DEFLATE entry point in the `IO::
/// Uncompress::Zlib::*` family).
fn process_compressed_plist(bytes: &[u8]) -> (Vec<PlistTag>, Option<&'static str>) {
  // PLIST.pm:228 — `$$val !~ /^bplist00/` short-circuit: an already-uncompressed
  // payload bypasses inflate. The bundled regex matches the literal 8-byte
  // `bplist00` prefix (NOT the 7-byte `bplist0` family used by the outer
  // magic): `bplist01` would attempt inflate, fail, and warn. Match exactly.
  let plist_bytes: std::borrow::Cow<'_, [u8]> = if bytes.starts_with(b"bplist00") {
    std::borrow::Cow::Borrowed(bytes)
  } else {
    // PLIST.pm:229-235 — `IO::Uncompress::RawInflate::rawinflate`. The
    // `decompress_to_vec` entry handles raw DEFLATE (no zlib/gzip framing).
    match miniz_oxide::inflate::decompress_to_vec(bytes) {
      Ok(v) => std::borrow::Cow::Owned(v),
      Err(_) => {
        // PLIST.pm:234 — `$et->Warn("Error inflating PLIST::AdjustmentData")`.
        // No tags emitted, just the family-0 Warning the engine surfaces.
        return (Vec::new(), Some(COMPRESSED_PLIST_INFLATE_WARN));
      }
    }
  };
  // PLIST.pm:241 — `$et->HandleTag(..., $val, ProcessProc => $proc)` with
  // SubDirectory `TagTable => 'Image::ExifTool::PLIST::Main'`. The inflated
  // body re-enters the binary-plist decoder; the resulting tags get
  // `group_override = Some("PLIST")`.
  let Some(mut tags) = decode_binary(&plist_bytes) else {
    return (Vec::new(), None);
  };
  for t in &mut tags {
    t.group_override = Some("PLIST");
  }
  (tags, None)
}

// ===========================================================================
// XML plist decoder (PLIST.pm:155-244, 464-469)
// ===========================================================================

/// Decode an XML plist — a small recursive-descent element scanner over the
/// `<plist>` body. Bundled routes XML plist through the XMP event parser
/// (PLIST.pm:464-469); real plist XML is well-formed and shallow, so a direct
/// element scan is faithful and far simpler.
///
/// Returns `None` if the buffer is not valid UTF-8 or has no `<plist>` /
/// top-level value element.
fn parse_xml(data: &[u8]) -> Option<PlistMeta<'static>> {
  // The XML plist is UTF-8 (the `<?xml … encoding="UTF-8"?>` declaration).
  let text = core::str::from_utf8(data).ok()?;
  // Skip the `<?xml …?>` PI and the `<!DOCTYPE …>` declaration (the external
  // DTD reference is NOT resolved — see the module docs' accepted deferrals).
  // The XMP machinery (PLIST.pm:464-469) runs the WHOLE `<plist>` subtree
  // through `ParseXMPElement` as ONE event stream — `FoundTag` is fired per
  // leaf with the full `@props` element path and a SINGLE persistent `@keys`
  // stack. This port replays that exact event semantics with
  // [`XmlEventWalker`] rather than re-deriving the key path from a value tree
  // (which the prior tree walker did — it could not reproduce the sticky
  // cross-sibling key state of a mixed scalar/dict XML `<array>`; Codex R6).
  let plist_body = slice_element_body(text, "plist")?;
  // `ParseXMPElement` starts with `@props = ('plist')` (the `<plist>` element
  // is the outermost), so child events fire at prop-depth ≥ 2 — which is what
  // `FoundTag`'s depth arithmetic (`@props - 3` etc., PLIST.pm:188-194)
  // expects. Seed `props` with the `plist` component and walk the body.
  let mut walker = XmlEventWalker {
    out: Vec::new(),
    content_override: None,
    warning: None,
  };
  walker.walk_children(
    plist_body,
    &mut std::vec![String::from("plist")],
    &mut Vec::new(),
  );
  // PLIST.pm:41-43 / :133-141 / :225 — the content-derived file-type override.
  // Both bundled mechanisms (the `%plistType` table and the `XMLFileType`
  // RawConv) key on the EXACT RAW `/`-joined tag ID (`$tag`, PLIST.pm:202-203),
  // NOT the generated tag NAME — so a NAME-colliding key like `xMLFileType`
  // (which generates the same emitted name `XMLFileType`) must NOT override
  // (Codex R11 F1). The walker tracks this from the raw ID at each value event,
  // last-call-wins over the document-order stream (matching `OverrideFileType`,
  // ExifTool.pm:9714-9716) and BEFORE the `-struct` last-wins NAME collapse.
  // The `$$self{FILE_TYPE} eq 'XMP'` guard is applied by the engine.
  let content_override = walker.content_override;
  let warning = walker.warning;
  // Under `exiftool -struct` (the canonical golden generator) the bundled
  // `List => 1` accumulation collapses to LAST-value-wins per tag ID: each
  // leaf is a separate `FoundTag`→`HandleTag` call on the same tag NAME, and
  // `-struct` suppresses the duplicate-into-list merge so the final emission
  // overwrites earlier ones. Dedup by name keeping the LAST occurrence, then
  // restore emission order (the engine `TagMap` is otherwise first-wins).
  // The compressed-PLIST sub-walk's `group_override = Some("PLIST")` tags
  // are EXCLUDED from the XML last-wins dedup — they live under the `PLIST`
  // family-1 group, not `XML`, so a (rare) name collision with an outer XML
  // tag must NOT silently swallow either side.
  let tags = last_wins_by_name_xml_only(walker.out);
  Some(PlistMeta {
    format: PlistFormat::Xml,
    tags,
    content_override,
    // The XML path has NO `$et->Error` branch (PLIST.pm:464-469 returns the
    // XMP result directly): a malformed XML plist surfaces an
    // `ExifTool:Warning` from the XMP text parser (NOT modeled in this port) or
    // nothing — never a `PLIST:Error`. So the XML meta never carries one.
    error: None,
    warning,
    _marker: core::marker::PhantomData,
  })
}

// ===========================================================================
// XML event-stream walker — faithful `FoundTag` replay (PLIST.pm:155-244)
// ===========================================================================

/// The faithful XML-plist EVENT-STREAM emitter — a 1:1 replay of bundled
/// `FoundTag` (PLIST.pm:155-244) driven by the XMP module's `ParseXMPElement`
/// event order (PLIST.pm:464-469).
///
/// Bundled processes XML plist as a single event stream over the WHOLE
/// `<plist>` subtree, with ONE persistent `@keys` stack
/// (`$$et{PListKeys}`, PLIST.pm:160) that is NEVER reset between siblings — it
/// is mutated only by `<key>` events and read (untouched) by value events.
/// The prior tree walker re-derived the key path structurally per node and so
/// lost the sticky cross-sibling state (Codex R6 F2): a scalar following a
/// `<dict>` in the same `<array>` must inherit the dict's last `<key>`. This
/// walker keeps the real stack and applies the exact `FoundTag` rules:
///
/// - **`<key>` event** (PLIST.pm:187-195): a `<key>` does NOT emit a tag and
///   does NOT recurse; it rewrites `@keys`. At prop-depth ≤ 3 (a top-level
///   `plist/dict/key`) `@keys = ($val)`; deeper, it pads `@keys` with `''` up
///   to `@props-3`, truncates to `@props-2`, and sets `$keys[@props-3] = $val`.
/// - **value event** (PLIST.pm:200-202): any non-`key` leaf (scalar, `<true/>`,
///   `<data>`, OR an EMPTY container — Codex R6 F3) emits ONE tag under the
///   CURRENT `join '/', @keys` WITHOUT touching `@keys`; nothing is emitted
///   when `@keys` is empty (`return 0 unless @$keys`).
/// - **non-empty container** (`<dict>`/`<array>`): fires NO value event of its
///   own; the walker recurses into its children (just like
///   `ParseXMPElement` recursing when the body has child elements).
///
/// `props` is the live element path (`@$props`); `keys` is the persistent
/// `@keys` stack. Emissions land in `out` in walk order (the bundled
/// `HandleTag` sequence); `parse_xml` then collapses same-name runs
/// last-value-wins (the `-struct` golden behavior).
struct XmlEventWalker {
  /// Emitted tags in walk order (pre last-wins collapse).
  out: Vec<PlistTag>,
  /// The content-derived file-type override the stream has selected so far —
  /// the LAST value event whose RAW tag ID matched the `%plistType` table or
  /// the `XMLFileType` RawConv (PLIST.pm:41-43 / :133-141), keyed on the exact
  /// raw `/`-joined ID (Codex R11 F1/F2). Tracked here, on the raw event
  /// stream, BEFORE the emitted-name generation discards the ID and before the
  /// `-struct` last-wins NAME collapse — last-call-wins per `OverrideFileType`.
  content_override: Option<PlistContentOverride>,
  /// A recoverable warning the walk surfaced, if any — PLIST.pm:234
  /// `$et->Warn("Error inflating PLIST::$$tagInfo{Name}")` when an AAE
  /// `adjustmentData` payload fails raw-DEFLATE inflate. Carried as a
  /// `&'static str` because the only message bundled emits here is the fixed
  /// literal [`COMPRESSED_PLIST_INFLATE_WARN`]. `None` for a successful walk
  /// (incl. a `bplist00`-prefixed `adjustmentData` payload that skips inflate
  /// per PLIST.pm:228).
  warning: Option<&'static str>,
}

impl XmlEventWalker {
  /// Walk every child element of an element body, firing events in document
  /// order. `props` is the path of the ENCLOSING element (so each child fires
  /// at `props.len() + 1`); `keys` is the persistent key stack.
  fn walk_children(&mut self, body: &str, props: &mut Vec<String>, keys: &mut Vec<String>) {
    let mut scanner = XmlScanner { s: body };
    while let Some(el) = scanner.next_element() {
      self.visit_element(&el, props, keys);
    }
  }

  /// Process one element `<name …>inner</name>` (or `<name/>`) — push its name
  /// onto `props`, dispatch the `FoundTag` event, and pop.
  fn visit_element(
    &mut self,
    el: &ScannedElement<'_>,
    props: &mut Vec<String>,
    keys: &mut Vec<String>,
  ) {
    let ScannedElement {
      ref name,
      inner,
      self_closing,
      was_comment,
    } = *el;
    let name = name.as_str();
    props.push(name.to_string());
    if name == "key" {
      // PLIST.pm:187-195 — a `<key>` rewrites `@keys` and returns 0 (no tag,
      // no recursion). Even an empty/self-closing `<key/>` is still a key
      // event (its value is the empty string). XMP.pm:4180-4181 — a leaf
      // value whose close-scan crossed an XML comment has its inline
      // `<!--…-->` runs stripped before `&$foundProc`.
      let key_val = if self_closing {
        String::new()
      } else {
        unescape_xml(&strip_xml_comments(inner, was_comment))
      };
      apply_key_event(keys, props.len(), key_val);
    } else if is_container(name) && !self_closing && body_has_element(inner) {
      // PLIST.pm — a NON-empty `<dict>`/`<array>` fires no value event; the
      // XMP parser recurses into its child elements. (Recursion via
      // `ParseXMPElement` returning truthy ⇒ no `&$foundProc` for the parent.)
      self.walk_children(inner, props, keys);
    } else {
      // A value event (PLIST.pm:200-202): a scalar, `<true/>`/`<false/>`,
      // `<data>`, an empty string element, OR an EMPTY container (Codex R6
      // F3 — `<dict/>` / `<array/>` / a whitespace-only container body emit
      // the raw body string under the current key). The leaf value is decoded
      // by the element name (PLIST.pm:171-186).
      self.value_event(name, inner, self_closing, was_comment, keys);
    }
    props.pop();
  }

  /// Fire a `FoundTag` value event (PLIST.pm:200-241): decode the leaf by its
  /// element name and, if `@keys` is non-empty, emit ONE tag under the current
  /// `join '/', @keys`. Nothing is emitted when `@keys` is empty.
  fn value_event(
    &mut self,
    name: &str,
    inner: &str,
    self_closing: bool,
    was_comment: bool,
    keys: &[String],
  ) {
    // PLIST.pm:200 — `return 0 unless @$keys` (no key ⇒ value is dropped).
    if keys.is_empty() {
      return;
    }
    // XMP.pm:4180-4181 — when the close-scan crossed an XML comment, strip
    // every inline `<!--…-->` run from the leaf body BEFORE decoding it (so
    // `<string>foo<!-- … -->bar</string>` decodes to `foobar`, not the
    // comment text). A leaf whose scan saw no comment passes through verbatim.
    let stripped = strip_xml_comments(inner, was_comment);
    let id = keys.join("/");
    // PLIST.pm:228-241 — `CompressedPLIST` recursive sub-directory dispatch.
    // `adjustmentData` (PLIST.pm:142-146) is the only `CompressedPLIST` entry
    // in `%PLIST::Main` (class-sweep verified `rg -n 'CompressedPLIST' PLIST.pm`
    // = 2 hits, both this single entry). A `<data>` element under this exact
    // raw key is decoded to bytes (Base64 or ASCII-hex), then routed through
    // [`process_compressed_plist`]: a `bplist00`-prefixed payload is parsed
    // directly (PLIST.pm:228 `$$val !~ /^bplist00/` short-circuits inflate),
    // otherwise inflated via `miniz_oxide` raw-DEFLATE (PLIST.pm:229-235
    // `IO::Uncompress::RawInflate::rawinflate`). The resulting binary-plist
    // tags carry `group_override = Some("PLIST")` (PLIST.pm:484 `SET_GROUP1 =
    // 'PLIST'` inside `ProcessBinaryPLIST`) so they emit under the family-1
    // `PLIST` group even when the outer XML plist uses `XML`.
    if name == "data" && id == "adjustmentData" {
      let bytes = decode_plist_data(&unescape_xml(&stripped));
      let (mut sub_tags, warn) = process_compressed_plist(&bytes);
      self.out.append(&mut sub_tags);
      // PLIST.pm:234 — first-call-wins on the engine `ExifTool:Warning`
      // (ExifTool.pm:1288-1297). The XML walker can only encounter one
      // `adjustmentData` per file in practice, but `or` enforces the same
      // first-wins discipline.
      if self.warning.is_none() {
        self.warning = warn;
      }
      return;
    }
    let value = decode_xml_leaf(name, &stripped, self_closing);
    let Some(leaf) = scalar_to_leaf(&value) else {
      // A non-empty container reaching here would have no scalar leaf — but
      // `visit_element` only routes leaves / empty containers here, and an
      // empty container is decoded to an empty `Str` by `decode_xml_leaf`.
      return;
    };
    // PLIST.pm:41-43 / :133-141 / :225 — the content-derived file-type override
    // is keyed on the EXACT RAW tag ID (`$tag`, not the generated name) and
    // evaluated HERE, on the live event stream, before `emit_tag` discards the
    // ID (Codex R11 F1/F2). `OverrideFileType` is last-call-wins, so a later
    // qualifying event replaces an earlier one. The `XMLFileType` RawConv's
    // value predicate (`eq 'ModdXML'`) only matches a string leaf — a non-`Str`
    // value (e.g. `<integer>`) supplies `""` and never triggers MODD; the
    // `%plistType` `adjustmentBaseVersion` entry has no value predicate.
    let value_str = match &leaf {
      PlistLeaf::Str(s) => s.as_str(),
      _ => "",
    };
    if let Some(ov) = PlistContentOverride::for_xml_tag(&id, value_str) {
      self.content_override = Some(ov);
    }
    self.out.push(emit_tag(&id, PlistFormat::Xml, leaf));
  }
}

/// Apply the `FoundTag` `<key>` event arithmetic (PLIST.pm:187-195) to the
/// persistent `@keys` stack. `props_len` is `@$props` (the element-path depth
/// of THIS `<key>`). A top-level key (depth ≤ 3, i.e. `plist/dict/key`) resets
/// the stack to a single component; a deeper key pads with empty slots up to
/// `props_len-3`, truncates to `props_len-2`, and writes the key at index
/// `props_len-3` (one empty slot per intervening `<array>`/`<dict>` level).
fn apply_key_event(keys: &mut Vec<String>, props_len: usize, key_val: String) {
  if props_len <= 3 {
    // PLIST.pm:188-189 — `@$keys = ( $val )`.
    keys.clear();
    keys.push(key_val);
    return;
  }
  // PLIST.pm:192 — `push @$keys, '' while @$keys < @$props - 3`.
  let pad_to = props_len - 3;
  while keys.len() < pad_to {
    keys.push(String::new());
  }
  // PLIST.pm:193 — `pop @$keys while @$keys > @$props - 2`.
  let trunc_to = props_len - 2;
  while keys.len() > trunc_to {
    keys.pop();
  }
  // PLIST.pm:194 — `$$keys[@$props - 3] = $val`. The index is `props_len-3`;
  // after the pad/truncate the stack has either that many or one-more
  // components, so a direct indexed write (extending by one if needed) matches
  // Perl's autovivifying `$$keys[$i] = $val`.
  let idx = props_len - 3;
  // Checked `.get_mut()`: matches the `idx < keys.len()` guard exactly ⇒
  // byte-identical.
  if let Some(slot) = keys.get_mut(idx) {
    *slot = key_val;
  } else {
    // `idx == keys.len()` (the truncate left exactly `idx` components) — push.
    keys.push(key_val);
  }
}

/// `true` for the plist container element names whose non-empty body is walked
/// as child events rather than emitted as a value (`<dict>` / `<array>`; a
/// `<set>` is the binary-only type-12 and never appears in XML, but is admitted
/// for symmetry).
#[inline]
fn is_container(name: &str) -> bool {
  matches!(name, "dict" | "array" | "set")
}

/// `true` if `body` contains at least one real element start-tag (so the
/// enclosing container is NON-empty and the XMP parser would recurse rather
/// than fire a value event). Comments (`<!-- … -->`), processing instructions
/// (`<? … ?>`), declarations (`<! … >`) and close tags (`</…>`) are NOT
/// elements — faithful to `ParseXMPElement`, which counts only real elements.
fn body_has_element(body: &str) -> bool {
  let mut scanner = XmlScanner { s: body };
  scanner.next_element().is_some()
}

/// Decode one XML-plist LEAF element into a [`PlistValue`] scalar — the
/// per-property value handling of `FoundTag` (PLIST.pm:171-186). Unlike
/// [`decode_xml_element`] this never recurses into containers: an EMPTY
/// container (`<dict/>` / `<array/>` / whitespace-only body) decodes to the
/// raw body string (Codex R6 F3 — bundled stores the un-trimmed inner text
/// `$val` for the container's value event).
fn decode_xml_leaf(name: &str, inner: &str, self_closing: bool) -> PlistValue {
  match name {
    // PLIST.pm:182-183 — `<true/>` / `<false/>`.
    "true" => PlistValue::Bool(true),
    "false" => PlistValue::Bool(false),
    // PLIST.pm:171-198 — `<string>`, `<integer>` and `<real>` (a `<key>` never
    // reaches here) all fall into `FoundTag`'s final `else` branch
    // (PLIST.pm:184-186): `$val = $et->Decode($val, 'UTF8')` — a CHARSET decode
    // only, with NO numeric type-parse. The XML path stores the UNESCAPED
    // scalar text of `<integer>` / `<real>` verbatim — `<integer>007</integer>`
    // stays `"007"`, `<real>1.50</real>` stays `"1.50"`, `<real>inf</real>`
    // stays `"inf"` (oracle-verified, Codex R17 F1). It is NOT typed to an
    // `i64` / `f64` here: that would (a) discard a leading zero or trailing
    // fraction digit and (b) round-trip a non-finite word like `inf` through
    // `f64` into the titlecase Perl-NV string `Inf` — changing the extracted
    // VALUE. Numeric parsing happens on demand ONLY where a `%PLIST::Main`
    // static `ValueConv` / `PrintConv` needs it (`leaf_numeric`,
    // `apply_value_conv`), faithful to Perl's `IsFloat($val)` test running on
    // the raw scalar. The binary decoder is unaffected — a binary plist
    // type-1/2 object IS genuinely typed (PLIST.pm:271-274, `Get*u`), so it
    // keeps [`PlistValue::Int`] / [`PlistValue::Real`].
    "string" | "integer" | "real" => PlistValue::Str(unescape_xml(inner)),
    // PLIST.pm:180-181 — `<date>`: `ConvertXMPDate($val)` on the RAW unescaped
    // scalar. PLIST.pm does NOT trim `$val` first, and neither does the XMP
    // read-path that feeds it: XMP.pm:4178-4181 only `s/^\s+//;s/\s+$//` for a
    // `rdf:Description` prop (or — `$wasComment` — only a comment-strip); a
    // plist `<date>` prop is never `rdf:Description`, so its body reaches
    // `FoundTag` whitespace-VERBATIM (Codex R17 F1 class-sweep). A trim here
    // would change the VALUE: `ConvertXMPDate`'s regex `^(\d{4})-…$` is
    // anchored, so a leading/trailing-whitespace body FAILS the match and
    // passes through UNCHANGED — oracle: `<date> 2013-02-22T12:49:10Z </date>`
    // → `" 2013-02-22T12:49:10Z "` (raw, separators NOT rewritten), whereas a
    // pre-trim would have matched and emitted `"2013:02:22 12:49:10Z"`.
    "date" => PlistValue::Date(convert_xmp_date(&unescape_xml(inner))),
    // PLIST.pm:171-179 — `<data>`: ASCII-hex or Base64. PLIST.pm:168 first
    // runs `UnescapeXML` on the value; the hex/Base64 branch is decided on
    // that unescaped string.
    "data" => PlistValue::Data(decode_plist_data(&unescape_xml(inner))),
    // An EMPTY container or any other leaf — bundled's value event stores the
    // raw inner text (un-trimmed), unescaped (PLIST.pm:185-186 `$val` for a
    // `dict`/`array` prop is just the UTF8-decoded body). A self-closing
    // `<dict/>` / unknown element has an empty body.
    _ => {
      if self_closing {
        PlistValue::Str(String::new())
      } else {
        PlistValue::Str(unescape_xml(inner))
      }
    }
  }
}

/// Collapse same-NAME tags to LAST-value-wins, preserving emission order — the
/// `exiftool -struct` behavior for repeated XML-plist tag IDs (the golden
/// generator). Each leaf is a separate `FoundTag`→`HandleTag` call on the same
/// tag NAME; `-struct` suppresses the `List => 1` merge so the LAST emission
/// is the value, while the engine `TagMap` is otherwise first-wins — so a
/// last-wins dedup is required.
///
/// The dedup applies ONLY to tags emitted under the meta's outer XML group
/// (`tag.group_override == None`); tags carrying an explicit family-1 override
/// (PLIST.pm:484 `SET_GROUP1='PLIST'` from a recursive `CompressedPLIST`
/// sub-walk) bypass the dedup so an outer XML name collision with a sub-walk's
/// PLIST-grouped tag does not silently swallow either side.
fn last_wins_by_name_xml_only(scratch: Vec<PlistTag>) -> Vec<PlistTag> {
  // Only XML-group tags actually engage the dedup. A PLIST-group sub-walk
  // tag (from `CompressedPLIST`) is always kept.
  let mut seen_xml: Vec<smol_str::SmolStr> = Vec::new();
  let mut keep: Vec<PlistTag> = Vec::new();
  for tag in scratch.iter().rev() {
    if tag.group_override.is_some() {
      keep.push(tag.clone());
      continue;
    }
    let key = tag.name.clone();
    if !seen_xml.iter().any(|k| k == &key) {
      seen_xml.push(key);
      keep.push(tag.clone());
    }
  }
  keep.reverse();
  keep
}

/// One markup token recognised by [`next_markup`] — the faithful counterpart
/// of XMP.pm's element regex `<([?/]?)([-\w:.\x80-\xff]+|!--)([^>]*)>|(<!\[CDATA\[)`
/// (XMP.pm:3806) plus the close-scan alternation `(!\[CDATA\[|!--)`
/// (XMP.pm:3835). `ParseXMPElement` skips comments/CDATA/PIs (the `!--` /
/// `![CDATA[` / `[?/]` branches) so they never count as plist structure.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Markup {
  /// `<!-- … -->` — skipped (XMP.pm:3818-3821).
  Comment,
  /// `<![CDATA[ … ]]>` — skipped (XMP.pm:3811-3815).
  CData,
  /// `<? … ?>` / `<! … >` (declaration / processing instruction) — the
  /// `[?/]?` leading group; skipped (XMP.pm:3808 `next if $1`).
  Pi,
  /// A start-tag `<name …>`. Carries `self_closing` for `<name/>`.
  Start { self_closing: bool },
  /// A close-tag `</name>`.
  Close,
}

/// One markup token plus its byte span — `tok` classifies it, `[start,end)`
/// is its byte range in the scanned text, and `name_span` (for `Start`/
/// `Close`) is the element-name sub-range.
#[derive(Debug, Clone, Copy)]
struct MarkupToken {
  tok: Markup,
  /// Byte index of the leading `<`.
  start: usize,
  /// Byte index just past the token's terminator (`>`, `-->`, `]]>`, `?>`).
  end: usize,
  /// Element-name byte range (only meaningful for `Start`/`Close`).
  name_span: (usize, usize),
}

impl MarkupToken {
  /// The element name, sliced from the source `text` the token came from.
  fn name<'t>(&self, text: &'t str) -> &'t str {
    &text[self.name_span.0..self.name_span.1]
  }
}

/// Find the next markup token in `text` at or after `from` — a token-aware
/// XML scan. Comments / CDATA / PIs / declarations are recognised so callers
/// can SKIP them rather than treat their bracketed content as real plist
/// structure (Codex R7 F2). Faithful to `ParseXMPElement`'s element regex
/// (XMP.pm:3806) and close-scan alternation (XMP.pm:3835). Returns `None`
/// when no further `<` exists, or on a missing comment/CDATA terminator
/// (the bundled `last`/`last Element` bailouts).
fn next_markup(text: &str, from: usize) -> Option<MarkupToken> {
  let bytes = text.as_bytes();
  let mut pos = from;
  loop {
    let rel = text[pos..].find('<')?;
    let lt = pos + rel;
    let rest = &text[lt..];
    // `<!-- … -->` — comment. XMP.pm:3818-3821 (`next if … /-->/`).
    if let Some(after) = rest.strip_prefix("<!--") {
      let term = after.find("-->")?;
      return Some(MarkupToken {
        tok: Markup::Comment,
        start: lt,
        end: lt + 4 + term + 3,
        name_span: (lt, lt),
      });
    }
    // `<![CDATA[ … ]]>` — CDATA section. XMP.pm:3811-3815.
    if let Some(after) = rest.strip_prefix("<![CDATA[") {
      let term = after.find("]]>")?;
      return Some(MarkupToken {
        tok: Markup::CData,
        start: lt,
        end: lt + 9 + term + 3,
        name_span: (lt, lt),
      });
    }
    // `<? … ?>` — processing instruction (e.g. `<?xml …?>`).
    if rest.starts_with("<?") {
      let term = rest.find("?>")?;
      return Some(MarkupToken {
        tok: Markup::Pi,
        start: lt,
        end: lt + term + 2,
        name_span: (lt, lt),
      });
    }
    // `<!DOCTYPE …>` and any other `<!…>` declaration.
    if rest.starts_with("<!") {
      let term = rest.find('>')?;
      return Some(MarkupToken {
        tok: Markup::Pi,
        start: lt,
        end: lt + term + 1,
        name_span: (lt, lt),
      });
    }
    // A start- or close-tag. Locate its `>`.
    let is_close = rest.as_bytes().get(1) == Some(&b'/');
    let name_start = lt + if is_close { 2 } else { 1 };
    // The element-name run ends at the first `>`, `/`, or whitespace.
    let name_end =
      match text[name_start..].find(|c: char| c == '>' || c == '/' || c.is_whitespace()) {
        Some(i) => name_start + i,
        None => return None, // no terminator — unbalanced
      };
    if name_end == name_start {
      // A bare `<` / `< ` / `</>` — not a real tag. Step past it.
      pos = lt + 1;
      continue;
    }
    let gt = lt + text[lt..].find('>')?;
    let self_closing = !is_close && bytes.get(gt - 1) == Some(&b'/');
    return Some(MarkupToken {
      tok: if is_close {
        Markup::Close
      } else {
        Markup::Start { self_closing }
      },
      start: lt,
      end: gt + 1,
      name_span: (name_start, name_end),
    });
  }
}

/// Return the inner body of the FIRST `<tag …>…</tag>` element in `text`
/// (between the start-tag's `>` and the matching `</tag>`). Handles a
/// self-closing `<tag/>` (returns an empty body). `None` if no such element.
/// Comments / CDATA / PIs are skipped (Codex R7 F2) — a commented fake
/// `<tag>` is never mistaken for the real element.
fn slice_element_body<'t>(text: &'t str, tag: &str) -> Option<&'t str> {
  let open = find_start_tag(text, tag)?;
  // `open.0` = byte index of `<`, `open.1` = byte index just past `>`,
  // `open.2` = whether the start-tag was self-closing (`<tag/>`).
  if open.2 {
    return Some(""); // self-closing — empty body
  }
  let scan = match_close_offset(text, open.1, tag)?;
  Some(&text[open.1..open.1 + scan.body_len])
}

/// Locate the FIRST real `<tag …>` (or `<tag/>`) start-tag for `tag` in
/// `text`, skipping any inside comments / CDATA / PIs (Codex R7 F2).
/// Returns `(start_idx, body_start_idx, self_closing)`:
/// - `start_idx` — byte index of the `<`,
/// - `body_start_idx` — byte index just past the start-tag's `>`,
/// - `self_closing` — `true` for `<tag/>`.
fn find_start_tag(text: &str, tag: &str) -> Option<(usize, usize, bool)> {
  let mut pos = 0usize;
  while let Some(t) = next_markup(text, pos) {
    match t.tok {
      // Comment / CDATA / PI — skip the whole bracketed run.
      Markup::Comment | Markup::CData | Markup::Pi | Markup::Close => {
        pos = t.end;
      }
      Markup::Start { self_closing } => {
        if t.name(text) == tag {
          return Some((t.start, t.end, self_closing));
        }
        pos = t.end;
      }
    }
  }
  None
}

/// A forward cursor over an XML plist element-body string — the tokenizer the
/// event-stream [`XmlEventWalker`] drives. `next_element` consumes the next
/// child element (`<dict>` / `<array>` / `<key>` / `<string>` / …), skipping
/// text/whitespace/comments, and advances the cursor past it.
struct XmlScanner<'t> {
  /// Remaining unparsed body text.
  s: &'t str,
}

/// One child element produced by [`XmlScanner::next_element`].
struct ScannedElement<'t> {
  /// Element name (`dict` / `string` / `key` / …).
  name: String,
  /// Inner body text (empty for a self-closing `<name/>`); may still contain
  /// `<!--…-->` runs (XMP.pm strips those from a scalar leaf — see
  /// [`was_comment`](ScannedElement::was_comment)).
  inner: &'t str,
  /// `true` for a self-closing `<name/>`.
  self_closing: bool,
  /// `true` iff the close-scan crossed an XML comment (XMP.pm:3847
  /// `$wasComment`) — a scalar leaf then strips its inline `<!--…-->` text.
  was_comment: bool,
}

impl<'t> XmlScanner<'t> {
  /// Consume the next element, returning a [`ScannedElement`] and advancing
  /// the cursor past it. Skips leading text/whitespace, XML comments, CDATA
  /// sections and PIs (Codex R7 F2 — a `<!-- <array> -->` comment never
  /// registers as a real child). `None` at end of body or on reaching the
  /// enclosing element's close-tag.
  fn next_element(&mut self) -> Option<ScannedElement<'t>> {
    loop {
      let t = next_markup(self.s, 0)?;
      match t.tok {
        // Comment / CDATA / PI — skip the bracketed run, keep scanning.
        Markup::Comment | Markup::CData | Markup::Pi => {
          self.s = &self.s[t.end..];
        }
        // A close-tag at this level ends the enclosing element.
        Markup::Close => return None,
        Markup::Start { self_closing: true } => {
          let name = t.name(self.s).to_string();
          self.s = &self.s[t.end..];
          return Some(ScannedElement {
            name,
            inner: "",
            self_closing: true,
            was_comment: false,
          });
        }
        Markup::Start {
          self_closing: false,
        } => {
          let name = t.name(self.s).to_string();
          // Find the matching close-tag, tracking nesting depth for
          // same-named children (`<dict>` in `<dict>`, `<array>` in
          // `<array>` — plist's only recursive elements). Comments / CDATA
          // / PIs inside the body are NOT counted.
          let scan = match_close_offset(self.s, t.end, &name)?;
          let inner = &self.s[t.end..t.end + scan.body_len];
          let close_len = name.len() + 3; // `</name>`
          self.s = &self.s[t.end + scan.body_len + close_len..];
          return Some(ScannedElement {
            name,
            inner,
            self_closing: false,
            was_comment: scan.was_comment,
          });
        }
      }
    }
  }
}

/// The result of [`match_close_offset`]: the body byte length plus the
/// `wasComment` close-scan signal (XMP.pm:3847 — set when an XML comment is
/// crossed while finding the matching close-tag).
#[derive(Debug, Clone, Copy)]
struct CloseScan {
  /// Byte length of the element body, RELATIVE to `body_start`.
  body_len: usize,
  /// `true` iff an XML comment was crossed during the close-scan
  /// (XMP.pm:3847 `… and $wasComment = 1`).
  was_comment: bool,
}

/// Find the body length of the element named `name` whose start-tag ended at
/// byte index `body_start` in `text` — i.e. the byte offset, RELATIVE to
/// `body_start`, of the matching `</name>`. Nesting depth is tracked so a
/// same-named child does not end the search early; comments / CDATA / PIs
/// are token-skipped so a `<!-- <name> -->` (or `</name>` in a comment)
/// never shifts the depth (Codex R7 F2). The returned [`CloseScan`] also
/// reports whether a comment was crossed (XMP.pm:3847 `$wasComment`), so a
/// scalar leaf value can later strip the inline `<!--…-->` text. `None` if
/// unbalanced.
fn match_close_offset(text: &str, body_start: usize, name: &str) -> Option<CloseScan> {
  let mut depth = 1usize;
  let mut pos = body_start;
  let mut was_comment = false;
  while let Some(t) = next_markup(text, pos) {
    pos = t.end;
    match t.tok {
      // An XML comment is opaque for nesting, but XMP.pm:3847 records that
      // the close-scan crossed one — the leaf value then strips it.
      Markup::Comment => was_comment = true,
      // CDATA / PI are opaque — skip without touching depth or the signal.
      Markup::CData | Markup::Pi => {}
      Markup::Start { self_closing } => {
        // A SELF-CLOSING same-named child (`<name/>`) opens AND closes in
        // one tag, so it must NOT deepen the nesting (Codex R6 F3).
        if !self_closing && t.name(text) == name {
          depth += 1;
        }
      }
      Markup::Close => {
        if t.name(text) == name {
          depth -= 1;
          if depth == 0 {
            return Some(CloseScan {
              body_len: t.start - body_start,
              was_comment,
            });
          }
        }
      }
    }
  }
  None
}

/// Faithful `<data>` decode (PLIST.pm:171-179): MODD files ASCII-hex-encode
/// `<data>` (`/^[0-9a-f]+$/` with an even length); the PLIST DTD otherwise
/// specifies Base64.
///
/// PLIST.pm:172 tests the UNESCAPED `<data>` value DIRECTLY with
/// `/^[0-9a-f]+$/` and `not length($val) & 0x01` — it does NOT strip
/// formatting whitespace first (Codex R8 F2). A whitespace-wrapped payload
/// such as `<data> 48656c6c6f </data>` therefore FAILS the lower-hex test
/// (the leading/trailing spaces are not hex digits) and falls through to the
/// Base64 branch. So the hex test runs on `body` verbatim; only the Base64
/// decoder tolerates whitespace (and ignores it internally).
fn decode_plist_data(body: &str) -> Vec<u8> {
  let all_hex = !body.is_empty()
    && body.len().is_multiple_of(2)
    && body
      .bytes()
      .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
  if all_hex {
    // PLIST.pm:173-174 — `pack('H*', $val)`.
    let mut out = Vec::with_capacity(body.len() / 2);
    let bytes = body.as_bytes();
    for pair in bytes.chunks_exact(2) {
      // `chunks_exact(2)` yields exactly-2-byte chunks; the slice-pattern binds
      // the same `pair[0..2]` (the `_` arm is unreachable) ⇒ byte-identical.
      if let &[p0, p1, ..] = pair {
        out.push((hex_val(p0) << 4) | hex_val(p1));
      }
    }
    out
  } else {
    // PLIST.pm:177-178 — `DecodeBase64`. `base64_decode` ignores ASCII
    // whitespace, faithful to Perl's `DecodeBase64` (`tr` strips non-Base64).
    crate::convert::base64_decode(body)
  }
}

/// Lower-hex digit → nibble (caller guarantees `b` is `0-9a-f`).
#[inline]
const fn hex_val(b: u8) -> u8 {
  match b {
    b'0'..=b'9' => b - b'0',
    _ => b - b'a' + 10, // 'a'..='f'
  }
}

/// Faithful `ConvertXMPDate($val)` (XMP.pm:3383-3394). For an ISO-8601-ish
/// `YYYY-MM-DDThh:mm[:ss][tz]` the function rewrites the date separators to
/// `:` and the `T` to a space, keeping the timezone suffix verbatim:
/// `2013-02-22T12:49:10Z` → `2013:02:22 12:49:10Z`.
fn convert_xmp_date(val: &str) -> String {
  // XMP.pm:3386 regex: `^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$`.
  // Transliterated as a direct field scan rather than a regex (no regex dep).
  let bytes = val.as_bytes();
  // Checked `.get()` (Phase C S2): `digits(a, b)` is `Some-and-all-digit` iff
  // the old `bytes[a..b].iter().all(..)` ran in-range and matched; `at(i, c)`
  // matches the old `bytes[i] == c`; the `val[a..b]` string slices below run
  // under the same satisfied predicate ⇒ byte-identical.
  let digits = |a: usize, b: usize| {
    bytes
      .get(a..b)
      .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
  };
  let at = |i: usize, c: u8| bytes.get(i) == Some(&c);
  // Need at least `YYYY-MM-DDThh:mm` (16 chars).
  if bytes.len() >= 16
    && digits(0, 4)
    && at(4, b'-')
    && digits(5, 7)
    && at(7, b'-')
    && digits(8, 10)
    && (at(10, b'T') || at(10, b' '))
    && digits(11, 13)
    && at(13, b':')
    && digits(14, 16)
  {
    let yyyy = val.get(0..4).unwrap_or("");
    let mm = val.get(5..7).unwrap_or("");
    let dd = val.get(8..10).unwrap_or("");
    let hh_mm = val.get(11..16).unwrap_or("");
    // Optional `:ss` (chars 16..19).
    let (ss, rest_idx) = if bytes.len() >= 19 && at(16, b':') && digits(17, 19) {
      (val.get(16..19).unwrap_or(""), 19)
    } else {
      ("", 16)
    };
    // Trailing timezone (`\s*(\S*)`) — strip leading whitespace, keep the rest.
    let tz = val.get(rest_idx..).unwrap_or("").trim_start();
    return std::format!("{yyyy}:{mm}:{dd} {hh_mm}{ss}{tz}");
  }
  // XMP.pm:3390-3392 — the `not $unsure` fallback (`^(\d{4})(-\d{2}){0,2}` ⇒
  // `tr/-/:/`). Real plist `<date>` values always hit the full form above;
  // this branch is a defensive faithful fallback for a date-only string.
  if bytes.len() >= 4 && digits(0, 4) {
    return val.replace('-', ":");
  }
  // Not date-shaped — pass through unchanged (XMP.pm:3393).
  val.to_string()
}

/// Strip inline `<!--…-->` runs from a leaf body — a BYTE-EXACT port of the
/// XMP.pm:4181 substitution `$val =~ s/<!--.*?-->//g`, applied to a scalar /
/// `<key>` value whose close-scan crossed a comment (`$wasComment`,
/// XMP.pm:3847). The substitution has NO `/s` modifier, so the regex `.`
/// does NOT match a newline (Perl `.` matches every char except `\n`):
/// a `<!--…-->` whose span between the literal `<!--` and `-->` contains a
/// `\n` is therefore NOT matched and is preserved VERBATIM — only a comment
/// run that lies entirely on one line is removed (Codex R9 F1; bundled
/// ExifTool 13.58 keeps `foo<!--\nx\n-->bar` intact). The `/g` flag re-scans
/// after every match or failed position, and `.*?` is non-greedy, so this
/// walks `<!--` candidates one byte at a time and matches the SHORTEST
/// newline-free `<!--…-->` — exactly Perl's engine. When `was_comment` is
/// false the body is returned unchanged (borrowed).
fn strip_xml_comments(body: &str, was_comment: bool) -> std::borrow::Cow<'_, str> {
  if !was_comment {
    return std::borrow::Cow::Borrowed(body);
  }
  let bytes = body.as_bytes();
  let mut out = String::with_capacity(body.len());
  // `i` is the byte the regex engine's `/g` scan is currently anchored at.
  let mut i = 0usize;
  while i < bytes.len() {
    // Try to match `<!--.*?-->` anchored at `i` (Perl tries the regex at
    // each position the `/g` scan reaches). The `<!--` / `-->` sentinels
    // are pure ASCII, so all scanning is done on the BYTE slice — `j` walks
    // one byte at a time and may land mid-UTF-8-char (e.g. inside an `é`
    // in `<!--é-->`); a `body[j..]` `str` slice there would panic. `body`
    // is only ever sub-sliced at the known char boundary `i` when copying
    // output below.
    // Checked `.get()` (Phase C S2): `bytes[i..]`/`bytes[j..]` had `i`/`j` < len
    // guards; `bytes[i]`/`bytes[j]` likewise; `&body[i..i + ch_len]` keeps `i` a
    // char boundary and `i + ch_len <= len` ⇒ byte-identical recovery + bytes.
    if bytes.get(i..).is_some_and(|s| s.starts_with(b"<!--")) {
      // `.*?` (non-greedy, no `/s`): scan from just past `<!--`, expanding
      // over non-`\n` bytes, and accept the FIRST `-->` reached. A `\n`
      // hit before any `-->` makes the `.` fail ⇒ this `<!--` does not
      // match here (the comment run is left verbatim).
      let mut j = i + 4;
      let mut matched_end: Option<usize> = None;
      while j < bytes.len() {
        if bytes.get(j..).is_some_and(|s| s.starts_with(b"-->")) {
          matched_end = Some(j + 3);
          break;
        }
        // `.` does not match `\n` — the non-greedy run cannot cross it.
        if bytes.get(j) == Some(&b'\n') {
          break;
        }
        j += 1;
      }
      if let Some(end) = matched_end {
        // Whole `<!--…-->` matched on one line — drop it; `/g` resumes
        // scanning immediately after the match.
        i = end;
        continue;
      }
      // No newline-free match at `i` — keep this byte, advance by one
      // (Perl's `/g` retries the regex at the next position).
    }
    // Non-matching byte — copy it verbatim and advance. Step by the full
    // UTF-8 char width so multi-byte text is not split.
    let ch_len = utf8_char_len(bytes.get(i).copied().unwrap_or(0));
    out.push_str(body.get(i..i + ch_len).unwrap_or(""));
    i += ch_len;
  }
  std::borrow::Cow::Owned(out)
}

/// Byte length of the UTF-8 code point whose leading byte is `b` (1–4).
/// A stray continuation / invalid byte is treated as width 1 — the body is
/// already a valid `&str` here, so a leading byte always starts a code point.
fn utf8_char_len(b: u8) -> usize {
  match b {
    0x00..=0x7F => 1,
    0xC0..=0xDF => 2,
    0xE0..=0xEF => 3,
    0xF0..=0xF7 => 4,
    _ => 1,
  }
}

/// Un-escape the five predefined XML character entities — faithful to
/// `Image::ExifTool::XMP::UnescapeXML` (PLIST.pm:168). Numeric character
/// references (`&#NN;` / `&#xNN;`) are also decoded (XMP's `UnescapeXML`
/// resolves them via `UnescapeChar`). An unrecognized `&…;` is left verbatim.
fn unescape_xml(s: &str) -> String {
  if !s.contains('&') {
    return s.to_string();
  }
  let mut out = String::with_capacity(s.len());
  let mut rest = s;
  while let Some(amp) = rest.find('&') {
    out.push_str(&rest[..amp]);
    let after = &rest[amp..];
    if let Some(semi) = after.find(';') {
      let entity = &after[1..semi]; // between `&` and `;`
      match entity {
        "amp" => out.push('&'),
        "lt" => out.push('<'),
        "gt" => out.push('>'),
        "quot" => out.push('"'),
        "apos" => out.push('\''),
        _ => {
          // Numeric character reference?
          if let Some(num) = entity.strip_prefix('#') {
            let cp = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
              u32::from_str_radix(hex, 16).ok()
            } else {
              num.parse::<u32>().ok()
            };
            match cp.and_then(char::from_u32) {
              Some(c) => out.push(c),
              None => out.push_str(&after[..=semi]), // bad ref — verbatim
            }
          } else {
            out.push_str(&after[..=semi]); // unknown entity — verbatim
          }
        }
      }
      rest = &after[semi + 1..];
    } else {
      // Stray `&` with no `;` — emit verbatim and stop.
      out.push_str(after);
      return out;
    }
  }
  out.push_str(rest);
  out
}

// ===========================================================================
// Binary tag-tree walker (PLIST.pm:326-388) — the binary encoding only
// ===========================================================================

/// Walk the decoded BINARY value tree, emitting flattened tags into `out`.
/// (The XML encoding uses the event-stream [`XmlEventWalker`] instead — its
/// sticky-`@keys` semantics cannot be re-derived from a value tree; Codex R6.)
///
/// `keys` is the current dict-key stack — joined with `/` to form the tag ID,
/// then run through [`generate_binary_tag_name`] (PLIST.pm:362-365). Faithful
/// to bundled `exiftool -struct` (the canonical golden generator):
///
/// - **Dict** — each `(key, value)` pushes `key`, recurses, pops. A nested
///   dict produces `parent/child` IDs (PLIST.pm:343).
/// - **Array** (PLIST.pm:379-388 type-10) — `ExtractObject` builds an actual
///   Perl `\@array` and `HandleTag` stores that ARRAY REF as ONE value.
///   PLIST.pm:381-386 `push @array` keeps every member that is `defined` and
///   `ref ne 'HASH'`, so the array emits ONE list-valued tag preserving its
///   int / real / string / bool / date / data members and any nested
///   arrayrefs; a `<dict>` member's `key`/`value` pairs are routed through
///   `HandleTag` as separate `parent/key` tags FIRST and then the dict (an
///   empty `{}` HASH) is dropped from the arrayref (Codex R1 F2 / R2 F4).
/// - **Scalar leaf** — emitted directly under the current key path.
fn walk_tree(value: &PlistValue, keys: &mut Vec<String>, out: &mut Vec<PlistTag>) {
  const FORMAT: PlistFormat = PlistFormat::Binary;
  match value {
    // PLIST.pm:326-378 — a `<dict>` walks its key/value pairs in order,
    // emitting each child through `HandleTag` (PLIST.pm:377). The dict-level
    // `LastPListTag` bookkeeping (PLIST.pm:373-376) treats CONSECUTIVE
    // same-tagInfo emissions as a `List => 1` accumulator: same tag ⇒ append,
    // different tag ⇒ drop the prior `LIST_TAGS` entry and start fresh. With
    // dynamic-name tag IDs each child gets its own tagInfo, so the run gate is
    // effectively per-name within the dict — folding consecutive same-name
    // emissions into one list-valued tag matches bundled's `List => 1`
    // behavior. Last-wins for NON-consecutive same-name duplicates is handled
    // by the engine `TagMap` (last-wins in place); fold operates only on
    // adjacent runs.
    //
    // Codex R20 F3 — pre-fix, the dict walker emitted children straight into
    // `out`, so a root binary dict with consecutive `[(a, v1), (a, v2)]` lost
    // the list-fold (TagMap last-wins kept only `v2`). The scratch+fold is
    // applied to EVERY dict level (root and nested-inside-dict alike); dicts
    // nested inside arrays already had this via the array branch's
    // `child_scratch` (Codex R2 F4). Triple-fold safety: a nested dict's
    // pre-folded output appears as one `PlistTag` per name in the outer
    // scratch, so the outer fold sees AT MOST one entry per name from that
    // child — equivalent to bundled's single-pass global `LastPListTag`.
    PlistValue::Dict(pairs) => {
      let mut scratch: Vec<PlistTag> = Vec::with_capacity(pairs.len());
      for (key, child) in pairs {
        keys.push(key.clone());
        walk_tree(child, keys, &mut scratch);
        keys.pop();
      }
      fold_consecutive_lists(scratch, out);
    }
    PlistValue::Array(items) => {
      if keys.is_empty() {
        // A top-level bare array with no key — bundled has no key to store
        // it under (`@$keys` empty ⇒ `FoundTag` returns 0). Drop it.
        return;
      }
      // Binary `<array>` — PLIST.pm:379-388 type-10 branch. `ExtractObject`
      // calls `ExtractObject($et, $plistInfo, $parent)` per member with the
      // ARRAY's own `$parent`:
      //
      // - a `<dict>` member recurses into PLIST.pm:347-377, which routes each
      //   of its `key`/`value` pairs through `HandleTag` as a SEPARATE
      //   `parent/key` tag — emitted BEFORE the array's own tag — and then
      //   `ExtractObject` returns the empty `{}` HASH, which PLIST.pm:384
      //   `next unless … ref $val ne 'HASH'` drops from the arrayref;
      // - every scalar / nested-array member is kept in the arrayref.
      let mut list: Vec<PlistLeaf> = Vec::with_capacity(items.len());
      // The dict members' child tags are collected into a scratch buffer so
      // consecutive same-ID emissions can be folded into one list-valued tag —
      // faithful to bundled's `List => 1` accumulation (`HandleTag`
      // ExifTool.pm:9504-9520).
      let mut child_scratch: Vec<PlistTag> = Vec::new();
      for it in items {
        match it {
          PlistValue::Dict(_) => {
            walk_tree(it, keys, &mut child_scratch);
          }
          PlistValue::Array(inner) => {
            list.push(binary_array_to_leaf(inner, keys, &mut child_scratch));
          }
          _ => {
            if let Some(leaf) = scalar_to_leaf(it) {
              list.push(leaf);
            }
          }
        }
      }
      fold_consecutive_lists(child_scratch, out);
      out.push(emit_tag(&keys.join("/"), FORMAT, PlistLeaf::List(list)));
    }
    // Scalar leaves — emit under the current key path. A scalar with NO key
    // (`keys` empty) cannot be stored (PLIST.pm:200 `return 0 unless @$keys`).
    scalar => {
      if keys.is_empty() {
        return;
      }
      let id = keys.join("/");
      if let Some(leaf) = scalar_to_leaf(scalar) {
        out.push(emit_tag(&id, FORMAT, leaf));
      }
    }
  }
}

/// Build a [`PlistTag`] for a raw `/`-joined tag ID — Codex R3 F1. Consults
/// the [`PLIST_MAIN`] static table FIRST (`$$tagTablePtr{$tag}`, PLIST.pm:203
/// / :358): a hit supplies the fixed `Name`, applies the entry's `ValueConv`
/// to the leaf, and records its `PrintConv` for serialize time; a miss falls
/// back to the encoding-specific dynamic name generator (PLIST.pm:206-217 /
/// :362-365).
fn emit_tag(id: &str, format: PlistFormat, leaf: PlistLeaf) -> PlistTag {
  if let Some(info) = lookup_static(id) {
    // PLIST.pm `Name => …` — the fixed static name.
    let value = apply_value_conv(info.conv, leaf);
    // The `*Days` `DateTimeOriginal` conv is a `ValueConv` (applied just
    // now); only the print-mode `PrintConv`s carry to serialize time.
    let print_conv = match info.conv {
      PlistConv::DateTimeOriginalDays => PlistConv::None,
      other => other,
    };
    PlistTag {
      name: info.name.into(),
      value,
      print_conv,
      group_override: None,
    }
  } else {
    let name: smol_str::SmolStr = match format {
      PlistFormat::Binary => generate_binary_tag_name(id),
      PlistFormat::Xml => generate_xml_tag_name(id),
    }
    .into();
    PlistTag {
      name,
      value: leaf,
      print_conv: PlistConv::None,
      group_override: None,
    }
  }
}

/// Apply a `%PLIST::Main` `ValueConv` to a leaf — mode-independent (ExifTool
/// applies `ValueConv` for both `-j` and `-n`). Only
/// [`PlistConv::DateTimeOriginalDays`] is a `ValueConv`; every other variant
/// is a `PrintConv` (deferred to serialize time) or `None`, returning the
/// leaf unchanged.
fn apply_value_conv(conv: PlistConv, leaf: PlistLeaf) -> PlistLeaf {
  match conv {
    // PLIST.pm:73 — `IsFloat($val) ? ConvertUnixTime(($val - 25569) * 24 *
    // 3600) : $val`. Sony stores a "real" = days since 1899-12-31; `IsFloat`
    // matches any numeric scalar (ExifTool.pm:5936 — integers included), so
    // both an `<integer>` and a `<real>` are converted. The non-numeric
    // branch (`: $val`) passes a string leaf through unchanged.
    PlistConv::DateTimeOriginalDays => {
      // PLIST.pm:73 — `IsFloat($val) ? ConvertUnixTime(...) : $val`. `$val` is
      // the raw scalar: a BINARY `<real>`/`<integer>` is pre-typed, an XML
      // `<real>`/`<integer>` is the raw text [`PlistLeaf::Str`] (Codex R17 F1).
      // `leaf_numeric` applies Perl's `IsFloat` grammar — a non-numeric word
      // (`inf`, a `<string>`, a hex value) yields `None` ⇒ the `: $val`
      // pass-through, leaving the verbatim scalar untouched.
      let days = leaf_numeric(&leaf);
      match days {
        Some(d) => {
          // `ConvertUnixTime(($val - 25569) * 24 * 3600)` — no `$toLocal`,
          // so the GMT branch (ExifTool.pm:6787-6789). Codex R4 F2: the float
          // `$time` is passed STRAIGHT into ConvertUnixTime (which performs
          // the fractional reduction + `$time == 0` sentinel itself,
          // :6776-6789); the prior port `trunc()`'d to an i64 first, which
          // (a) dropped the fractional-second rounding and (b) mis-fired the
          // `$itime == 0` sentinel for any sub-second value of `$time`
          // (e.g. 25569 + 0.6/86400 days ⇒ bundled `1970:01:01 00:00:01`,
          // port emitted the `0000:…` sentinel). `convert_unix_time_f64`
          // applies the sentinel against the ORIGINAL float, matching Perl.
          let unix_secs = (d - 25569.0) * 24.0 * 3600.0;
          PlistLeaf::Date(crate::datetime::convert_unix_time_f64(unix_secs))
        }
        None => leaf,
      }
    }
    // Every other variant is a `PrintConv` or `None` — leaf unchanged here.
    PlistConv::None
    | PlistConv::Duration
    | PlistConv::GpsLatitude
    | PlistConv::GpsLongitude
    | PlistConv::SlowMotionFlags => leaf,
  }
}

/// Convert a scalar [`PlistValue`] to a [`PlistLeaf`] for emission. Returns
/// `None` for a container (the walker handles those before calling this).
fn scalar_to_leaf(v: &PlistValue) -> Option<PlistLeaf> {
  Some(match v {
    PlistValue::Str(s) => PlistLeaf::Str(s.clone()),
    PlistValue::Int(n) => PlistLeaf::Int(*n),
    PlistValue::UInt(n) => PlistLeaf::UInt(*n),
    PlistValue::Real(x) => PlistLeaf::Real(*x),
    PlistValue::Date(d) => PlistLeaf::Date(d.clone()),
    PlistValue::Bool(b) => PlistLeaf::Bool(*b),
    PlistValue::Data(bytes) => PlistLeaf::Data(bytes.clone()),
    PlistValue::DataLen(n) => PlistLeaf::DataLen(*n),
    PlistValue::Dict(_) | PlistValue::Array(_) => return None,
  })
}

/// Recursively convert a binary `<array>` nested INSIDE another binary
/// `<array>` into a [`PlistLeaf::List`], emitting any dict members' child
/// tags into `child_scratch` (Codex R3 F3).
///
/// PLIST.pm:381-383 calls `ExtractObject($et, $plistInfo, $parent)` for EVERY
/// member at EVERY array level, passing the array's `$parent` unchanged. So a
/// `<dict>` buried at any nesting depth still routes its `key`/`value` pairs
/// through `HandleTag` as `$parent/$key` tags (PLIST.pm:347-377) BEFORE
/// `ExtractObject` returns the empty `{}` HASH that PLIST.pm:384 `ref ne
/// 'HASH'` drops from the inner arrayref.
///
/// The earlier `value_to_list_leaf` (Codex R2 F4) recursed into a nested
/// array purely structurally and `filter_map`-dropped its dict members — so
/// `cast=[[{name:"Ann"}]]` lost `CastName`. This function carries the parent
/// `keys` path through every array level: a dict member is walked (its child
/// tags emitted), a nested-array member recurses here, and a scalar member is
/// kept in the list. The returned list excludes dict members (the bundled
/// `ref ne 'HASH'` drop) — so `cast=[[{name:"Ann"}]]` yields BOTH the
/// `CastName` child tag AND the `Cast => [[]]` list value.
fn binary_array_to_leaf(
  items: &[PlistValue],
  keys: &mut Vec<String>,
  child_scratch: &mut Vec<PlistTag>,
) -> PlistLeaf {
  let mut list: Vec<PlistLeaf> = Vec::with_capacity(items.len());
  for it in items {
    match it {
      // A `<dict>` at this array level — emit its `parent/key` child tags
      // (the array's `keys` path is unchanged, like Perl's `$parent`); the
      // dict itself is dropped from the list (`ref ne 'HASH'`).
      PlistValue::Dict(_) => {
        walk_tree(it, keys, child_scratch);
      }
      // A deeper nested `<array>` — recurse, still under the same `keys`.
      PlistValue::Array(inner) => {
        list.push(binary_array_to_leaf(inner, keys, child_scratch));
      }
      // A scalar — kept with its type.
      scalar => {
        if let Some(leaf) = scalar_to_leaf(scalar) {
          list.push(leaf);
        }
      }
    }
  }
  PlistLeaf::List(list)
}

/// Fold consecutive same-NAME tags in `scratch` into single list-valued
/// tags — faithful to bundled's `List => 1` accumulation (`HandleTag`
/// ExifTool.pm:9504-9520: consecutive emissions of the SAME tagInfo
/// accumulate into one arrayref; a different tag breaks the run).
///
/// A run of length 1 is emitted as the scalar tag unchanged (a single
/// `List => 1` emission is still a bare scalar); a run of length ≥ 2 becomes
/// one [`PlistTag`] with a [`PlistLeaf::List`] of the members in order. Used
/// for binary array-of-dict child tags (Codex R2 F4): every dict member of a
/// binary `<array>` emits the SAME `parent/key` tag ID, so the run collapses
/// to one list-valued tag.
fn fold_consecutive_lists(scratch: Vec<PlistTag>, out: &mut Vec<PlistTag>) {
  let mut iter = scratch.into_iter().peekable();
  while let Some(first) = iter.next() {
    // Collect the run of immediately-following tags with the same name.
    let mut run: Vec<PlistLeaf> = Vec::new();
    while iter.peek().is_some_and(|t| t.name == first.name) {
      let next = iter.next().expect("peeked");
      if run.is_empty() {
        run.push(first.value.clone());
      }
      run.push(next.value);
    }
    if run.is_empty() {
      // A run of one — emit the scalar tag unchanged.
      out.push(first);
    } else {
      // Every tag in the run shares the name ⇒ the same static entry ⇒ the
      // same `print_conv` AND same `group_override`; carry the run-start tag's.
      out.push(PlistTag {
        name: first.name,
        value: PlistLeaf::List(run),
        print_conv: first.print_conv,
        group_override: first.group_override,
      });
    }
  }
}

/// Apply the two shared character-rewrite steps to a tag ID — used by BOTH
/// the XML and binary tag-name generators (Codex R1 F3 split the two paths;
/// only these steps are common):
///
/// - **Step 3** `s/([^A-Za-z])([a-z])/$1\u$2/g` — uppercase the lowercase
///   letter that follows any non-alpha character (PLIST.pm:210 / :362).
/// - **Step 4** `tr/-_a-zA-Z0-9//dc` — delete every character outside
///   `[-_A-Za-z0-9]` (PLIST.pm:211 / :363). The `/` separators vanish here.
///
/// Returns the post-step-4 ASCII-only string (NOT yet `ucfirst`ed).
fn name_rewrite_steps(s: &str) -> String {
  // Step 3 — uppercase a lowercase letter after a non-alpha. Scan char pairs.
  let chars: Vec<char> = s.chars().collect();
  let mut step3: Vec<char> = Vec::with_capacity(chars.len());
  for (i, &c) in chars.iter().enumerate() {
    // Checked `.get()`: `i > 0` with an enumerate index ⇒ `i - 1 < chars.len()`
    // ⇒ `Some` ⇒ byte-identical (the `i == 0` case keeps `prev` absent).
    if let Some(&prev) = i.checked_sub(1).and_then(|j| chars.get(j)) {
      // Perl `[^A-Za-z]` — a non-ASCII-alpha char; `[a-z]` — ASCII lowercase.
      if !prev.is_ascii_alphabetic() && c.is_ascii_lowercase() {
        step3.push(c.to_ascii_uppercase());
        continue;
      }
    }
    step3.push(c);
  }
  // Step 4 — `tr/-_a-zA-Z0-9//dc`: keep ONLY `[-_A-Za-z0-9]`.
  step3
    .into_iter()
    .filter(|c| *c == '-' || *c == '_' || c.is_ascii_alphanumeric())
    .collect()
}

/// `ucfirst` an ASCII-only string in place (PLIST.pm `ucfirst`).
fn ucfirst_ascii(s: &mut String) {
  if let Some(fc) = s.as_bytes().first().copied()
    && fc.is_ascii_lowercase()
  {
    // A 1-byte ASCII range edit on an ASCII-only string.
    s.replace_range(0..1, &(fc.to_ascii_uppercase() as char).to_string());
  }
}

/// Faithful XML-plist tag-NAME generation from a `/`-joined tag ID — the
/// not-in-`%Main`-table `FoundTag` path (PLIST.pm:206-217) followed by the
/// generic `AddTagToTable` name cleanup (ExifTool.pm:9243-9255).
///
/// Steps (line-for-line):
/// 1. `s{^MetaDataList//}{}` — strip the MODD prefix (PLIST.pm:208).
/// 2. `s{//name$}{}` — drop a trailing `//name` (PLIST.pm:209).
/// 3. + 4. — the shared [`name_rewrite_steps`] (PLIST.pm:210-211).
/// 5. `ucfirst` — uppercase the first character (PLIST.pm:212).
/// 6. `AddTagToTable` (ExifTool.pm:9254) `$name = "Tag$name" if length($name)
///    < 2 or $name !~ /^[A-Z]/i` — `FoundTag` passes its `{ Name => … }`
///    hash through `AddTagToTable`, whose generic cleanup ALSO prefixes the
///    literal `Tag` when the name is shorter than 2 characters OR does not
///    begin with an ASCII LETTER. (Codex R2 F3 — R1 F3 added the guard to
///    the binary path only; the XML path needs it too. NOTE the criterion
///    differs from the binary inline guard at PLIST.pm:364, which uses
///    `/^[-0-9]/`; `AddTagToTable` uses `/^[A-Z]/i` negated — any non-letter
///    lead triggers it. For the binary path the inline guard already makes
///    the name letter-leading, so `AddTagToTable`'s step 6 is then a no-op
///    there — only the XML path observes it.)
///
/// Worked examples (verified against bundled `exiftool -j -G1 -struct`):
/// `TestDict/Author` → (1,2 no-op) → steps 3/4 delete `/` ⇒ `TestDictAuthor`
/// → step 5/6 no-op ⇒ `TestDictAuthor`. `x` → `x` → `<2` chars ⇒ `Tag` +
/// `ucfirst("x")` ⇒ `TagX`. `9abc` → step 3 `9Abc` → not letter-leading ⇒
/// `Tag9Abc`. `-foo` → step 3 `-Foo` → not letter-leading ⇒ `Tag-Foo`.
///
/// NOTE the `MetaDataList//` / `//name` strips are XML-ONLY: PLIST.pm only
/// applies them in `FoundTag` (the XML branch). The binary dict path
/// (PLIST.pm:362-365) does NOT — see [`generate_binary_tag_name`].
fn generate_xml_tag_name(id: &str) -> String {
  // Step 1 + 2 — prefix / suffix strips (XML-only).
  let mut s: &str = id;
  if let Some(stripped) = s.strip_prefix("MetaDataList//") {
    s = stripped;
  }
  if let Some(stripped) = s.strip_suffix("//name") {
    s = stripped;
  }
  // Steps 3 + 4.
  let mut kept = name_rewrite_steps(s);
  // Step 5 — `ucfirst`.
  ucfirst_ascii(&mut kept);
  // Step 6 — `AddTagToTable` (ExifTool.pm:9254): `Tag` prefix when the name
  // is `< 2` chars OR does not begin with an ASCII letter.
  let needs_prefix = kept.len() < 2
    || !kept
      .as_bytes()
      .first()
      .copied()
      .is_some_and(|b| b.is_ascii_alphabetic());
  if needs_prefix {
    let mut prefixed = String::with_capacity(kept.len() + 3);
    prefixed.push_str("Tag");
    prefixed.push_str(&kept);
    prefixed
  } else {
    kept
  }
}

/// Faithful BINARY-plist tag-NAME generation from a `/`-joined tag ID — the
/// not-in-table path in the `ExtractObject` dict branch (PLIST.pm:361-365).
///
/// Unlike the XML path this does NOT strip `MetaDataList//` / `//name`
/// (those `s///` are XML-only, in `FoundTag`). Steps:
/// 1. + 2. — the shared [`name_rewrite_steps`] (PLIST.pm:362-363).
/// 3. PLIST.pm:364 — the binary-only Tag-prefix guard:
///    `$name = 'Tag'.ucfirst($name) if length($name) < 2 or $name =~ /^[-0-9]/`.
///    If the filtered name is shorter than 2 characters OR begins with `-`
///    or an ASCII digit, prefix the literal `Tag` (to the `ucfirst`ed name).
/// 4. PLIST.pm:365 — `Name => ucfirst($name)`.
///
/// Worked examples (verified against bundled `exiftool -j -G1 -struct`):
/// `x` → steps 1/2 `x` → `<2` chars → `Tag` + `ucfirst("x")` ⇒ `TagX`.
/// `9abc` → steps 1/2 `9Abc` → `^[0-9]` ⇒ `Tag` + `ucfirst("9Abc")` ⇒
/// `Tag9Abc`. `-foo` → steps 1/2 `-Foo` → `^[-]` ⇒ `Tag` + `-Foo` ⇒
/// `Tag-Foo`. `good` → steps 1/2 `good` → guard not hit ⇒ `ucfirst` ⇒ `Good`.
fn generate_binary_tag_name(id: &str) -> String {
  // Steps 1 + 2 — the shared rewrite (NO prefix / suffix strip).
  let filtered = name_rewrite_steps(id);
  // PLIST.pm:364 — the guard is tested on the POST-filter name.
  let needs_prefix =
    filtered.len() < 2 || matches!(filtered.as_bytes().first(), Some(b'-') | Some(b'0'..=b'9'));
  // PLIST.pm:364-365 — `ucfirst` always runs; the `Tag` prefix is prepended
  // to the already-`ucfirst`ed name when the guard fires.
  let mut name = filtered;
  ucfirst_ascii(&mut name);
  if needs_prefix {
    let mut prefixed = String::with_capacity(name.len() + 3);
    prefixed.push_str("Tag");
    prefixed.push_str(&name);
    prefixed
  } else {
    name
  }
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

/// Render one [`PlistLeaf`] as a [`crate::value::TagValue`] (the crate's value
/// type with the faithful scalar `Serialize`). A `<data>` becomes the binary
/// placeholder via `TagValue::Bytes`; a [`PlistLeaf::List`] becomes a
/// `TagValue::List` whose members keep their types (recursive — a nested
/// binary `<array>` nests a `TagValue::List`). A boolean is stored as the
/// string `"True"` / `"False"`: `TagValue`'s `Serialize` coerces a
/// case-insensitive `true`/`false` string to a bare JSON boolean
/// (`EscapeJSON`, value.rs:704-705), so a plist bool renders as `true` /
/// `false` exactly as bundled emits it.
#[cfg(feature = "alloc")]
fn leaf_to_tag_value(leaf: &PlistLeaf) -> crate::value::TagValue {
  use crate::value::TagValue;
  match leaf {
    PlistLeaf::Str(s) => TagValue::Str(s.as_str().into()),
    PlistLeaf::Int(n) => TagValue::I64(*n),
    PlistLeaf::UInt(n) => TagValue::U64(*n),
    PlistLeaf::Real(x) => TagValue::F64(*x),
    PlistLeaf::Date(d) => TagValue::Str(d.as_str().into()),
    PlistLeaf::Bool(b) => TagValue::Str(if *b { "True" } else { "False" }.into()),
    PlistLeaf::Data(bytes) => TagValue::Bytes(bytes.clone()),
    // An oversized binary `data` object — emit the SAME `(Binary data N
    // bytes...)` placeholder a small `Data` renders, but built directly from
    // the known size (PLIST.pm:300-303 — the bytes were never read). Bundled
    // produces this string identically: the `exiftool` script recognises the
    // PLIST.pm-stored `"Binary data $size bytes"` scalar and just wraps it in
    // parentheses + the `-b` hint (exiftool:3983-3984).
    PlistLeaf::DataLen(n) => TagValue::Str(crate::value::binary_data_placeholder(*n).into()),
    PlistLeaf::List(items) => TagValue::List(items.iter().map(leaf_to_tag_value).collect()),
  }
}

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for PlistMeta<'_> {
  /// The PLIST.pm:234 AAE `adjustmentData` raw-DEFLATE inflate-failure
  /// `$et->Warn(...)` as a [`Diagnostic`](crate::diagnostics::Diagnostic)
  /// warning. The bundled `Warn` API does NOT honor `SET_GROUP1 = 'PLIST'`, so
  /// it surfaces as the family-0 `ExifTool:Warning` (the recognized-PLIST
  /// binary `PLIST:Error` is a family-1 TAG emitted by `tags()`, NOT a
  /// diagnostic, so it is not here).
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    match self.warning() {
      Some(msg) => std::vec![crate::diagnostics::Diagnostic::warn(msg)],
      None => std::vec::Vec::new(),
    }
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for PlistMeta<'_> {
  /// The golden-pattern tag stream — the parallel to the retired inherent
  /// `serialize_tags`: the SINK changes (an [`EmittedTag`](crate::emit::EmittedTag)
  /// per value, the [`run_emission`](crate::emit::run_emission) engine then
  /// owns the `write_value` + dedup) but the EMITTED tags (names, groups,
  /// values, order) are byte-identical to the old writer-path output.
  ///
  /// The tags are emitted in walk order (faithful to bundled's `HandleTag`
  /// call sequence). The family-0 group is always `"PLIST"` (PLIST.pm:48
  /// `GROUPS => { 0 => 'PLIST', 1 => 'XML', … }`); the family-1 group — the
  /// one that reaches the `-G1` key — is `"PLIST"` for a binary plist
  /// (PLIST.pm:484 `SET_GROUP1 = 'PLIST'`) or `"XML"` for an XML plist
  /// (the `%Main` table's family-1 default), per [`PlistFormat::group`].
  ///
  /// `mode` is mode-invariant for EVERY dynamically-named plist tag
  /// (PLIST.pm:212 `{ Name => …, List => 1 }` carries no `PrintConv`; the
  /// `<date>` leaf is already the post-`ValueConv` string and its
  /// `ConvertDateTime` `PrintConv` is identity under the default options). The
  /// ONLY mode-sensitive tags are the `%PLIST::Main` static entries that carry
  /// a print-mode `PrintConv` (Codex R3 F1): `Duration` (`ConvertDuration`),
  /// `GPSLatitude` / `GPSLongitude` (`GPS::ToDMS`). Their conversion is applied
  /// here, gated on `PrintConv` mode (the `-n` snapshot shows the raw
  /// post-`ValueConv` value, the default `-j` snapshot the print form).
  ///
  /// NOTE: every PLIST tag is always-emitted (no `Unknown => 1` gate), so
  /// `unknown` is `false` throughout. The recoverable `$et->Warn` (AAE
  /// inflate) is NOT in this stream — it is a diagnostic, yielded by
  /// [`PlistMeta::diagnostics`](crate::diagnostics::Diagnose::diagnostics). The recognized-PLIST binary
  /// `PLIST:Error` IS a family-1 tag (PLIST.pm:484-486 inside the
  /// `SET_GROUP1 = 'PLIST'` scope) and IS emitted here.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    let group = self.format.group();
    // Family-0 is always "PLIST" (PLIST.pm:48); family-1 is the per-tag group.
    let make = |family1: &str, name: &str, value: TagValue| {
      EmittedTag::new(Group::new("PLIST", family1), name.into(), value, false)
    };
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: Vec<EmittedTag> = Vec::new();

    // PLIST.pm:484-486 — a `bplist0`-magic binary plist whose body failed to
    // decode carries `$et->Error('Error reading binary PLIST file')` INSIDE the
    // `SET_GROUP1 = 'PLIST'` scope, so the error tag is the family-1
    // `PLIST:Error` (verified via the `-G1` oracle), NOT the family-0
    // `ExifTool:Error` channel. An error meta has no extracted tags, so this is
    // the only emission. `group` is `"PLIST"` here — the binary path is the
    // only one that can set `error` (`PlistFormat::Binary`, see [`parse_binary`]).
    if let Some(msg) = self.error {
      tags.push(make(group, "Error", TagValue::Str(msg.into())));
    }
    for tag in &self.tags {
      // PLIST.pm:484 — a recursive `CompressedPLIST` sub-directory dispatched
      // through `ProcessBinaryPLIST` scopes its children under `SET_GROUP1 =
      // 'PLIST'` regardless of the outer caller's group. So an AAE
      // `adjustmentData` payload's inflated tags carry `group_override =
      // Some("PLIST")` even when the meta's outer XML plist uses `XML`.
      let tag_group = tag.group_override.unwrap_or(group);
      // Apply the static `PrintConv` (print mode only) — Codex R3 F1. A
      // matching tag's value is rewritten to its print form; otherwise the
      // raw leaf is emitted as its typed `TagValue`.
      if print_conv && let Some(s) = apply_print_conv(tag.print_conv, &tag.value) {
        tags.push(make(tag_group, tag.name(), TagValue::Str(s.into())));
        continue;
      }
      // The non-converted leaf renders to its typed `TagValue` exactly as the
      // retired writer path did (`leaf_to_tag_value` maps every leaf — incl.
      // the oversized-`data` placeholder and the typed-member binary list — to
      // the SAME value the old `out.write_*` calls produced).
      tags.push(make(tag_group, tag.name(), leaf_to_tag_value(&tag.value)));
    }
    tags.into_iter()
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for PlistMeta<'_> {
  /// Project an Apple Property List onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain — the empty
  /// aggregate.
  ///
  /// A plist is a generic key/value document (`%PLIST::Main` carries only a
  /// handful of fixed entries — `Duration`, `GPSLatitude`/`GPSLongitude`,
  /// `DateTimeOriginal`, the slowMotion flags — and the rest are dynamically
  /// named). It is not a media stream with a faithful camera / lens / GPS /
  /// capture projection the cross-format domain can consume here (the GPS
  /// entries are rendered DMS display strings, not the structured
  /// `GpsLocation` decimals the domain expects), so every domain stays `None`.
  /// Routed through the [`Project`](crate::metadata::Project) trait like every
  /// other arm for uniformity (matches MXF, which likewise projects no camera
  /// facts).
  fn project(&self) -> crate::metadata::MediaMetadata {
    crate::metadata::MediaMetadata::new()
  }
}

/// Apply a `%PLIST::Main` print-mode `PrintConv` (Codex R3 F1) to a leaf,
/// returning the rendered display string — or `None` when the entry has no
/// `PrintConv` (`PlistConv::None` / the `*Days` `ValueConv`) or the value is
/// not the numeric shape the conv expects (Perl `PrintConv` passes a
/// non-`IsFloat` value through, but the static-table tags only ever carry a
/// numeric leaf).
#[cfg(feature = "alloc")]
// Reachable only via the golden `Taggable::tags` render path (the `-j`
// PrintConv branch); a `--features std,plist` build with no consumer driving
// the emission compiles it but may never call it (same as `leaf_to_tag_value`).
// Suppress the dead-code lint in that combo.
#[allow(dead_code)]
fn apply_print_conv(conv: PlistConv, leaf: &PlistLeaf) -> Option<String> {
  match conv {
    // PLIST.pm:79 — `ConvertDuration($val)`.
    PlistConv::Duration => Some(crate::datetime::convert_duration(leaf_numeric(leaf)?)),
    // PLIST.pm:84 — `GPS::ToDMS($self, $val, 1, "N")`.
    PlistConv::GpsLatitude => Some(gps_to_dms(leaf_numeric(leaf)?, 'N')),
    // PLIST.pm:89 — `GPS::ToDMS($self, $val, 1, "E")`.
    PlistConv::GpsLongitude => Some(gps_to_dms(leaf_numeric(leaf)?, 'E')),
    // PLIST.pm:98-104 / :111-117 — `{ BITMASK => { … } }`. ExifTool.pm:3607
    // `DecodeBits($val, $$conv{BITMASK}, $$tagInfo{BitsPerWord})`; no
    // `BitsPerWord` ⇒ the 32-bit default. Perl's `DecodeBits` (ExifTool.pm:
    // 6374-6396) takes the scalar `$val` REGARDLESS of the XML plist leaf
    // type — a `<string>` flags value is split and numified just like an
    // `<integer>` (Codex R9 F2), so this is gated only on the conv.
    PlistConv::SlowMotionFlags => Some(decode_slow_motion_flags(leaf)),
    // `None` / the `DateTimeOriginalDays` `ValueConv` — no print conv here.
    PlistConv::None | PlistConv::DateTimeOriginalDays => None,
  }
}

/// Numify a `split ' '` word the way Perl numifies a string in a bitwise
/// context (ExifTool.pm:6379 `$val & (1 << $i)`), then return the 32-bit
/// unsigned word the `&` mask actually sees.
///
/// Perl's `&` first numifies each operand. A string is numified by scanning
/// a leading numeric prefix — `[ws]* [+-]? ( D+ (. D*)? | . D+ ) ([eE][+-]?D+)?`
/// (Perl's `grok_number`): an optional sign, a decimal mantissa (which may
/// start with `.` only when digits follow) and an optional exponent. So
/// `1e2` numifies to 100, `1.9e2` to 190 — NOT `1` as a digit-only scan
/// would give. Anything after the prefix (`12abc`, `1e2.5`) is ignored, and
/// a string with no numeric prefix (`abc`, `0x10`, `inf`) numifies to 0
/// (Perl does NOT honour `0x`/`inf`/`nan` spellings in this scan).
///
/// `&` then coerces the numified value to an integer. A pure-integer prefix
/// (no `.`/`e`) that fits Perl's IV/UV stays EXACT — `18446744073709551615`
/// masks to all-ones, not `0` as an `i64`-only parse would yield on
/// overflow. A prefix with a `.`/`e`, or one too large for the integer
/// types, is a double: `&` truncates it toward zero, saturating an
/// out-of-range magnitude (`1e30` ⇒ `u64::MAX`, `-1e30` ⇒ `0`) and a
/// non-finite value to `0` — exactly Perl's NV→UV/IV conversion.
#[cfg(feature = "alloc")]
fn perl_numify_word(word: &str) -> u32 {
  #[allow(clippy::cast_possible_truncation)]
  {
    perl_numify_word_u64(word) as u32
  }
}

/// Numify `word` to the full 64-bit value Perl's `&` would mask (see
/// `perl_numify_word`). Split out so it can be unit-tested at u64 width.
#[cfg(feature = "alloc")]
fn perl_numify_word_u64(word: &str) -> u64 {
  // ── Scan the numeric prefix (Perl skips leading whitespace first). ──
  let s = word.trim_start();
  let bytes = s.as_bytes();
  let mut p = 0usize;
  let neg = match bytes.first() {
    Some(b'-') => {
      p = 1;
      true
    }
    Some(b'+') => {
      p = 1;
      false
    }
    _ => false,
  };
  // Checked-indexing (Phase C S2): every `bytes[p]`/`bytes[q]` had a preceding
  // `< bytes.len()` guard, so `bytes.get(..)` reads the same byte and takes the
  // same branch ⇒ byte-identical.
  let int_start = p;
  while bytes.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  let int_len = p - int_start;
  // A fractional part: a `.` is part of the number only when the mantissa
  // already has an integer digit OR a fraction digit follows (`.5` is
  // numeric, a bare `.` is not).
  let mut frac_len = 0usize;
  if bytes.get(p) == Some(&b'.') {
    let frac_start = p + 1;
    let mut q = frac_start;
    while bytes.get(q).is_some_and(u8::is_ascii_digit) {
      q += 1;
    }
    if int_len > 0 || q > frac_start {
      frac_len = q - frac_start;
      p = q;
    }
  }
  // No mantissa digit at all ⇒ no numeric prefix ⇒ numifies to 0 (`abc`,
  // `0x10`, `inf`, a bare `.`).
  if int_len == 0 && frac_len == 0 {
    return 0;
  }
  // An optional exponent — `[eE] [+-]? digit+`; an `e` with no digits after
  // it (`1e`) is NOT consumed (Perl numifies `1e` as `1`).
  let mut has_exp = false;
  if matches!(bytes.get(p), Some(b'e' | b'E')) {
    let mut q = p + 1;
    if matches!(bytes.get(q), Some(b'+' | b'-')) {
      q += 1;
    }
    let exp_digits_start = q;
    while bytes.get(q).is_some_and(u8::is_ascii_digit) {
      q += 1;
    }
    if q > exp_digits_start {
      has_exp = true;
      p = q;
    }
  }
  let numeric = &s[..p];

  // ── Integer-exact fast path: a pure-integer prefix (no `.`, no `e`). ──
  // Perl keeps these as an exact IV/UV, so `&` sees every bit. Try the
  // unsigned then signed integer types before falling back to a double.
  if frac_len == 0 && !has_exp {
    if neg {
      if let Ok(v) = numeric.parse::<i64>() {
        #[allow(clippy::cast_sign_loss)]
        {
          return v as u64;
        }
      }
    } else {
      // `numeric` here still carries a leading `+` for a signed literal;
      // strip it for the unsigned parse (`u64::from_str` rejects `+`).
      let unsigned = numeric.strip_prefix('+').unwrap_or(numeric);
      if let Ok(v) = unsigned.parse::<u64>() {
        return v;
      }
    }
    // Falls through: the integer overflowed its type — Perl promotes it to
    // a double, which the float path below truncates / saturates.
  }

  // ── Double path: a `.`/`e` prefix, or an integer too big for u64/i64. ──
  // Parse the prefix as `f64` and apply Perl's NV→integer `&` conversion.
  let f: f64 = numeric.parse().unwrap_or(0.0);
  if !f.is_finite() {
    // A finite prefix can still parse to ±∞ on exponent overflow (`1e400`);
    // Perl's `&` of such a value is 0 / saturates — `as` casts below do the
    // same, so just fall through. (A NaN is impossible from this grammar.)
  }
  // Perl truncates toward zero, then takes the value mod 2^64. Rust's
  // `f64 as uN` saturates an out-of-range or non-finite value, matching
  // Perl's UV/IV saturation: a non-negative double clamps high to
  // `u64::MAX`; a negative double goes through `i64` (clamping low to
  // `i64::MIN`, whose low 32 bits are 0) and reinterprets as `u64`.
  #[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
  )]
  if f < 0.0 { f as i64 as u64 } else { f as u64 }
}

/// Render a leaf as the Perl scalar string `DecodeBits` would `split`. A
/// `<string>` keeps its text verbatim; a numeric leaf stringifies like Perl
/// (`<integer>`/`<real>`); a boolean / date / non-scalar leaf stringifies to
/// the same text the leaf would otherwise emit (faithful to Perl receiving
/// whatever scalar `FoundTag` stored).
#[cfg(feature = "alloc")]
fn leaf_scalar_text(leaf: &PlistLeaf) -> std::borrow::Cow<'_, str> {
  use std::borrow::Cow;
  match leaf {
    PlistLeaf::Str(s) => Cow::Borrowed(s.as_str()),
    PlistLeaf::Date(d) => Cow::Borrowed(d.as_str()),
    PlistLeaf::Int(n) => Cow::Owned(std::format!("{n}")),
    PlistLeaf::UInt(n) => Cow::Owned(std::format!("{n}")),
    PlistLeaf::Real(x) => Cow::Owned(std::format!("{x}")),
    PlistLeaf::Bool(b) => Cow::Borrowed(if *b { "True" } else { "False" }),
    // `<data>` / `<array>` are never a `flags` scalar in a real plist; treat
    // them as an empty (⇒ `(none)`) value rather than panicking. An oversized
    // `DataLen` placeholder string would likewise numify to 0 under Perl's
    // `DecodeBits` split, so `""` (⇒ `(none)`) is the same result.
    PlistLeaf::Data(_) | PlistLeaf::DataLen(_) | PlistLeaf::List(_) => Cow::Borrowed(""),
  }
}

/// Faithful `DecodeBits($val, $BITMASK, 32)` for the slowMotion `*Flags` tags
/// (ExifTool.pm:6374-6396, PLIST.pm:98-104 / :111-117). `$val` is the scalar
/// leaf text REGARDLESS of XML plist leaf type — `split ' ', $vals` breaks it
/// into whitespace-separated words, each numified independently; word `w`
/// contributes bits at offset `32 * w`. For each set bit `n`, emit the lookup
/// name (`0 Valid`, `1 Has been rounded`, `2 Positive infinity`,
/// `3 Negative infinity`, `4 Indefinite`) or `[n]` for an unmapped bit; join
/// with `, `. No bits set ⇒ `(none)`.
#[cfg(feature = "alloc")]
#[allow(dead_code)] // see `apply_print_conv` — json/serde-path-only helper.
fn decode_slow_motion_flags(leaf: &PlistLeaf) -> String {
  // PLIST.pm:99-103 — the BITMASK lookup (bit ⇒ name).
  const NAMES: [&str; 5] = [
    "Valid",
    "Has been rounded",
    "Positive infinity",
    "Negative infinity",
    "Indefinite",
  ];
  let text = leaf_scalar_text(leaf);
  let mut parts: Vec<String> = Vec::new();
  // ExifTool.pm:6378 — `foreach $val (split ' ', $vals)`; `$num` steps by 32
  // per word. `split ' '` collapses runs of whitespace and trims both ends.
  for (word_idx, word) in text.split_whitespace().enumerate() {
    // ExifTool.pm:6379 — `$val & (1 << $i)`; the 32-bit default word size.
    let bits = perl_numify_word(word);
    let num = (word_idx as u32) * 32;
    for i in 0..32u32 {
      if bits & (1u32 << i) == 0 {
        continue;
      }
      let n = i + num;
      match NAMES.get(n as usize) {
        // ExifTool.pm:6385 — `push @bitList, $$lookup{$n}`.
        Some(name) => parts.push((*name).to_string()),
        // ExifTool.pm:6387 — `push @bitList, "[$n]"` for an unmapped bit.
        None => parts.push(std::format!("[{n}]")),
      }
    }
  }
  if parts.is_empty() {
    // ExifTool.pm:6393 — `return '(none)' unless @bitList`.
    "(none)".to_string()
  } else {
    // ExifTool.pm:6394 — `join($lookup ? ', ' : ',', @bitList)`.
    parts.join(", ")
  }
}

/// Render a numeric leaf as `f64` for a `ValueConv` / `PrintConv` input — the
/// `%PLIST::Main` static conversions all take the raw scalar `$val` and apply
/// `IsFloat($val) ? convert(...) : $val`. Returns `None` for a non-numeric leaf
/// (Perl's `IsFloat` fails ⇒ the `: $val` pass-through branch).
///
/// A BINARY plist `<real>` / `<integer>` arrives pre-typed as
/// [`PlistLeaf::Real`] / [`PlistLeaf::Int`] / [`PlistLeaf::UInt`] (the binary
/// format is genuinely typed). An XML `<real>` / `<integer>` arrives as
/// [`PlistLeaf::Str`] carrying the RAW scalar text (Codex R17 F1 — PLIST.pm's
/// XML path never type-parses, PLIST.pm:184-186): parse it on demand here,
/// gated on Perl's exact `IsFloat` grammar so a non-numeric word (`inf`, a
/// hex `0x10`, `5.`) is NOT converted — matching Perl's `: $val` branch — and
/// the stored/emitted scalar stays the verbatim text. A binary `<string>`
/// flags value reaching here is likewise numified only when `IsFloat`.
#[cfg(feature = "alloc")]
#[allow(dead_code)] // see `apply_print_conv` — json/serde-path-only helper.
fn leaf_numeric(leaf: &PlistLeaf) -> Option<f64> {
  #[allow(clippy::cast_precision_loss)]
  match leaf {
    PlistLeaf::Real(x) => Some(*x),
    PlistLeaf::Int(n) => Some(*n as f64),
    PlistLeaf::UInt(n) => Some(*n as f64),
    // An XML `<real>` / `<integer>` (raw text) — apply Perl's `IsFloat` test
    // (ExifTool.pm:5936) before numifying; a non-`IsFloat` string is the
    // `: $val` pass-through ⇒ `None`.
    PlistLeaf::Str(s) if perl_is_float(s) => s.parse::<f64>().ok(),
    _ => None,
  }
}

/// Perl's `Image::ExifTool::IsFloat($_[0])` (ExifTool.pm:5936) — `true` when
/// the scalar is a numeric float literal: `^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]
/// ([+-]?\d+))?$`. An optional sign, then (look-ahead) at least one digit OR a
/// `.` immediately followed by a digit; an optional integer run; an optional
/// `.`-fractional part; an optional exponent. So `1.50`, `41327.5`, `3725.0`,
/// `1e10`, `.5`, `+5.0` and even `5.` all pass (`5.` matches `\d*` = `5`,
/// `\.\d*` = `.`); `inf`, `0x10`, `1.4e2 ` with surrounding whitespace, an
/// empty exponent `1e` all fail. (The bundled comma-locale fallback is
/// omitted: the port runs under the C locale and a plist `<real>` is always
/// `.`-decimal — `IsFloat`'s second regex only ever matches a `,`-form.)
///
/// This is the `ValueConv` GATE, distinct from `EscapeJSON`'s stricter
/// JSON-number regex (PLIST.pm has no bearing on that — the serializer's
/// value-semantic comparator handles JSON token shape). `5.` is `IsFloat`
/// (so a MODD `DateTimeOriginal` of `5.` IS date-converted) yet is a JSON
/// STRING — both faithful.
#[cfg(feature = "alloc")]
#[allow(dead_code)] // see `apply_print_conv` — json/serde-path-only helper.
fn perl_is_float(s: &str) -> bool {
  let b = s.as_bytes();
  let mut i = 0;
  // Checked-indexing (Phase C S2): every `b[i]` had a preceding `i < b.len()`
  // guard, so `b.get(i)` reads the same byte and takes the same branch ⇒
  // byte-identical; the `matches!`/`is_some_and` forms fold the guard in.
  // Optional leading sign.
  if matches!(b.get(i), Some(b'+' | b'-')) {
    i += 1;
  }
  // Look-ahead `(?=\d|\.\d)`: a digit here, OR a `.` followed by a digit.
  let la = match b.get(i) {
    Some(c) if c.is_ascii_digit() => true,
    Some(b'.') => matches!(b.get(i + 1), Some(d) if d.is_ascii_digit()),
    _ => false,
  };
  if !la {
    return false;
  }
  // `\d*` — integer digits.
  while b.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
  }
  // `(\.\d*)?` — optional fractional part.
  if b.get(i) == Some(&b'.') {
    i += 1;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
  }
  // `([Ee]([+-]?\d+))?` — optional exponent (sign optional, ≥1 digit).
  if matches!(b.get(i), Some(b'E' | b'e')) {
    i += 1;
    if matches!(b.get(i), Some(b'+' | b'-')) {
      i += 1;
    }
    let exp_start = i;
    while b.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
    if i == exp_start {
      return false; // `[Ee]` with no exponent digits.
    }
  }
  // Anchored `$` — the whole string must be consumed.
  i == b.len()
}

/// Faithful `Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)` (GPS.pm) for
/// `$doPrintConv == 1` with the DEFAULT `CoordFormat` (Codex R3 F1).
///
/// The bundled default format is `q{%d deg %d' %.2f"}` plus the reference
/// suffix; `$ref` flips `N`↔`S` / `E`↔`W` for a negative value
/// (GPS.pm:482-498). Steps (GPS.pm:524-553):
/// - `$c[0] = int($val)` (degrees),
/// - `$c[1] = int(($val - deg) * 60)` (minutes),
/// - `$c[2] = ($val - deg - min/60) * 3600` (seconds),
/// - round-off carry so a `%.2f`-rounded `60.00"` rolls into the next minute.
///
/// Output: e.g. `37.7749` / `'N'` ⇒ `37 deg 46' 29.64" N`.
#[cfg(feature = "alloc")]
#[allow(dead_code)] // see `apply_print_conv` — json/serde-path-only helper.
fn gps_to_dms(val: f64, pos_ref: char) -> String {
  // GPS.pm:483-491 — a negative value flips the hemisphere and uses |val|.
  let (val, refc) = if val < 0.0 {
    let flipped = match pos_ref {
      'N' => 'S',
      'E' => 'W',
      other => other,
    };
    (-val, flipped)
  } else {
    (val, pos_ref)
  };
  // GPS.pm:534-540 — degrees / minutes / seconds.
  #[allow(clippy::cast_possible_truncation)]
  let deg = val.trunc() as i64;
  let min_f = (val - deg as f64) * 60.0;
  #[allow(clippy::cast_possible_truncation)]
  let min = min_f.trunc() as i64;
  let sec = (val - deg as f64 - min as f64 / 60.0) * 3600.0;
  // GPS.pm:542-547 — render the seconds with `%.2f` and carry any `>= 60`
  // round-off up into minutes (and minutes into degrees).
  let mut deg = deg;
  let mut min = min;
  // `sprintf('%.2f', $c[-1])` then the `>= 60` check — do the rounding first.
  let sec_rounded = (sec * 100.0).round() / 100.0;
  let (min, deg, sec_str) = if sec_rounded >= 60.0 {
    let carry_sec = sec_rounded - 60.0;
    min += 1;
    if min >= 60 {
      min -= 60;
      deg += 1;
    }
    (min, deg, format!("{carry_sec:.2}"))
  } else {
    (min, deg, format!("{sec_rounded:.2}"))
  };
  // GPS.pm default `$fmt = q{%d deg %d' %.2f"} . " $ref"`.
  format!("{deg} deg {min}' {sec_str}\" {refc}")
}

// ===========================================================================
// serde §8 — optional `Serialize` for the typed value/Meta types
// ===========================================================================

// One anonymous gated `const _` block (skill §8). The crate's `-j`/`-n` JSON
// rendering goes through the `crate::Rendered` wrapper, which drives
// `serialize_tags` into a `TagMap` — so `PlistMeta`'s own `Serialize` is NOT
// on the rendering hot path. It is provided for library consumers that want
// to serialize a typed `PlistMeta` directly (e.g. `serde_json::to_value(&meta)`):
// a flat object of `"<name>": value` entries, value-equivalent to the tag set.
#[cfg(all(feature = "serde", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "alloc"))))]
const _: () = {
  use serde::ser::{Serialize, SerializeMap, Serializer};

  impl Serialize for PlistMeta<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      let len = self.tags.len() + usize::from(self.error.is_some());
      let mut map = s.serialize_map(Some(len))?;
      // A recognized binary plist that failed to decode (PLIST.pm:485-486)
      // carries the `Error` tag and no extracted tags; emit it under the bare
      // name `"Error"` (this direct serializer uses unprefixed tag names — the
      // family-1 `PLIST` group is applied by the engine's `serialize_tags`).
      if let Some(msg) = self.error {
        map.serialize_entry("Error", msg)?;
      }
      for tag in &self.tags {
        map.serialize_entry(tag.name(), &leaf_to_tag_value(&tag.value))?;
      }
      map.end()
    }
  }
};

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::tagmap::TagMap;

  /// Drive a [`PlistMeta`] through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for the print (`-j`) mode
  /// and return the resulting [`TagMap`](crate::tagmap::TagMap) — the
  /// production sink path that replaces the retired inherent `serialize_tags`.
  /// (The AAE inflate `$et->Warn` is a diagnostic drained at the `AnyMeta`
  /// layer, so it is NOT reflected here — these tests assert the TAG stream.)
  fn emit_into_tagmap(meta: &PlistMeta<'_>, mode: crate::emit::ConvMode) -> TagMap {
    let mut tm = TagMap::new();
    crate::emit::run_emission(meta, mode, &mut tm);
    tm
  }

  /// The bundled binary-plist fixture (`t/images/PLIST-bin.plist`, 351 bytes).
  const BIN_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/PLIST-bin.plist");
  /// The bundled XML-plist fixture (`t/images/PLIST-xml.plist`, 795 bytes).
  const XML_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/PLIST-xml.plist");

  /// `true` if `s` matches the faithful `ConvertUnixTime(_, 1)` localtime
  /// shape `"YYYY:MM:DD HH:MM:SS±HH:MM"` (Codex R2 F1). The binary-plist
  /// `<date>` path ports the OS-localtime branch, so the exact offset is
  /// host-dependent — these unit tests assert the STRUCTURE; the
  /// `TZ=UTC`-pinned conformance suite (`tests/conformance.rs`) asserts the
  /// exact `+00:00` golden values.
  fn is_localtime_shape(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 25
      && b[..4].iter().all(u8::is_ascii_digit)
      && b[4] == b':'
      && b[5..7].iter().all(u8::is_ascii_digit)
      && b[7] == b':'
      && b[8..10].iter().all(u8::is_ascii_digit)
      && b[10] == b' '
      && b[11..13].iter().all(u8::is_ascii_digit)
      && b[13] == b':'
      && b[14..16].iter().all(u8::is_ascii_digit)
      && b[16] == b':'
      && b[17..19].iter().all(u8::is_ascii_digit)
      && (b[19] == b'+' || b[19] == b'-')
      && b[20..22].iter().all(u8::is_ascii_digit)
      && b[22] == b':'
      && b[23..25].iter().all(u8::is_ascii_digit)
  }
  #[test]
  fn detects_binary_plist() {
    let meta = parse_borrowed(BIN_FIXTURE).expect("binary plist recognized");
    assert!(meta.format().is_binary());
    assert_eq!(meta.format().group(), "PLIST");
  }

  #[test]
  fn detects_xml_plist() {
    let meta = parse_borrowed(XML_FIXTURE).expect("xml plist recognized");
    assert!(meta.format().is_xml());
    assert_eq!(meta.format().group(), "XML");
  }

  #[test]
  fn rejects_non_plist() {
    // Neither a `bplist0` prefix nor a leading `<` ⇒ not a plist (`Ok(None)`).
    assert!(parse_borrowed(b"not a plist at all").is_none());
    // Empty buffer ⇒ not a plist.
    assert!(parse_borrowed(b"").is_none());
    // NOTE: a `bplist00` magic with no trailer is NOT rejected — once the magic
    // matches it is a RECOGNIZED PLIST carrying the error (PLIST.pm:483-489);
    // see `truncated_binary_is_recognized_with_error` (Codex R14 F1).
  }

  /// Codex R14 F1 — once the `bplist0` magic matches (PLIST.pm:480), a binary
  /// plist whose body cannot be decoded is RECOGNIZED as PLIST (PLIST.pm:483
  /// `SetFileType` + :489 unconditional `$result = 1`) and carries
  /// `$et->Error('Error reading binary PLIST file')` (PLIST.pm:485-486) — it is
  /// NOT dropped to `Ok(None)`. The error renders as the family-1 `PLIST:Error`
  /// (PLIST.pm:484 `SET_GROUP1 = 'PLIST'`).
  #[test]
  fn truncated_binary_is_recognized_with_error() {
    // The 8-byte magic only (no 32-byte trailer ⇒ PLIST.pm:419 `return 0`).
    let meta = parse_borrowed(b"bplist00").expect("truncated bplist00 is RECOGNIZED, not Ok(None)");
    assert!(meta.format().is_binary());
    assert_eq!(meta.error(), Some("Error reading binary PLIST file"));
    assert!(
      meta.tags_slice().is_empty(),
      "an error meta has no extracted tags"
    );
    // It surfaces as the family-1 `PLIST:Error` tag (NOT `ExifTool:Error`).
    let tm = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      tm.get_str("PLIST", "Error").as_deref(),
      Some("Error reading binary PLIST file")
    );
    // `write_error` (the family-0 `ExifTool:Error` channel) is NOT used.
    assert!(tm.first_error().is_none());
  }

  /// Codex R14 class-sweep — EVERY binary-decode failure mode (not just the
  /// missing trailer) lands at the same bundled chokepoint (PLIST.pm:485
  /// `unless (ProcessBinaryPLIST(...))`) ⇒ recognized PLIST + the SAME
  /// `PLIST:Error`. Verified against the stdin oracle for: `topObj >= numObj`
  /// (PLIST.pm:426), an unsupported `intSize` (PLIST.pm:427), and an
  /// out-of-range offset table (PLIST.pm:432). Each must be `Some` with the
  /// error — never `Ok(None)`.
  #[test]
  fn binary_decode_failures_all_recognized_with_error() {
    // Trailer layout (last 32 bytes): [0..6 unused][6 intSize][7 refSize]
    // [8..16 numObj BE][16..24 topObj BE][24..32 tableOff BE]. PLIST.pm:420-424.
    let mk = |int_size: u8, ref_size: u8, num_obj: u64, top_obj: u64, table_off: u64| {
      let mut v = Vec::from(*b"bplist00");
      v.extend_from_slice(&[0u8; 8]); // a minimal body
      v.extend_from_slice(&[0u8; 6]); // unused trailer head
      v.push(int_size);
      v.push(ref_size);
      v.extend_from_slice(&num_obj.to_be_bytes());
      v.extend_from_slice(&top_obj.to_be_bytes());
      v.extend_from_slice(&table_off.to_be_bytes());
      v
    };
    let cases = [
      ("topObj >= numObj", mk(1, 1, 1, 5, 8)),    // PLIST.pm:426
      ("unsupported intSize", mk(7, 1, 1, 0, 8)), // PLIST.pm:427
      ("offset table past EOF", mk(1, 1, 1, 0, 9999)), // PLIST.pm:432
    ];
    for (label, data) in cases {
      let meta = parse_borrowed(&data)
        .unwrap_or_else(|| panic!("{label}: must be RECOGNIZED, not Ok(None)"));
      assert!(meta.format().is_binary(), "{label}: binary");
      assert_eq!(
        meta.error(),
        Some("Error reading binary PLIST file"),
        "{label}: carries the bundled error"
      );
    }
  }

  /// The success path is unchanged by the R14 error-meta refactor: the bundled
  /// binary fixture still decodes to its tags with NO error.
  #[test]
  fn binary_success_has_no_error() {
    let meta = parse_borrowed(BIN_FIXTURE).unwrap();
    assert!(meta.format().is_binary());
    assert_eq!(meta.error(), None);
    assert!(!meta.tags_slice().is_empty());
  }

  /// The binary fixture decodes to the 10 expected `PLIST:*` tags with the
  /// bundled-oracle values.
  #[test]
  fn binary_fixture_tag_values() {
    let meta = parse_borrowed(BIN_FIXTURE).unwrap();
    let tm = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      tm.get_str("PLIST", "TestString").as_deref(),
      Some("ExifTool PLIST test")
    );
    assert_eq!(tm.get_str("PLIST", "TestInteger").as_deref(), Some("256"));
    assert_eq!(
      tm.get_str("PLIST", "TestUnicode").as_deref(),
      Some("ExîfTöøl PLIST tést")
    );
    assert_eq!(tm.get_str("PLIST", "TestBoolean").as_deref(), Some("False"));
    assert_eq!(
      tm.get_str("PLIST", "TestDictAuthor").as_deref(),
      Some("Phil")
    );
    // Binary `<date>` — the faithful localtime branch (Codex R2 F1). The
    // exact offset is OS-TZ dependent; assert the `"YYYY:MM:DD HH:MM:SS±HH:MM"`
    // shape here, and the exact `+00:00` golden value in the `TZ=UTC`-pinned
    // conformance suite.
    let test_date = tm.get_str("PLIST", "TestDate").expect("TestDate present");
    assert!(
      is_localtime_shape(&test_date),
      "TestDate not localtime-shaped: {test_date}"
    );
    let dict_when = tm
      .get_str("PLIST", "TestDictWhen")
      .expect("TestDictWhen present");
    assert!(
      is_localtime_shape(&dict_when),
      "TestDictWhen not localtime-shaped: {dict_when}"
    );
    // `<real>` 1.4.
    match tm.get("PLIST", "TestReal") {
      Some(TagValue::F64(x)) => assert!((x - 1.4).abs() < 1e-9),
      other => panic!("TestReal not a float: {other:?}"),
    }
    // `<array>` of three strings.
    match tm.get("PLIST", "TestArray") {
      Some(TagValue::List(items)) => assert_eq!(items.len(), 3),
      other => panic!("TestArray not a list: {other:?}"),
    }
    // `<data>` — 12-byte binary.
    match tm.get("PLIST", "TestData") {
      Some(TagValue::Bytes(b)) => assert_eq!(b.len(), 12),
      other => panic!("TestData not bytes: {other:?}"),
    }
  }
  use crate::value::TagValue;

  /// Build a minimal `bplist00` whose top object is a dict `{ "Blob": <data> }`,
  /// where the type-4 `data` object's header CLAIMS `data_size` bytes but the
  /// payload is omitted (truncated). PLIST.pm:302-303 stores the length-only
  /// `"Binary data $size bytes"` placeholder for a `data` object `>= 1000000`
  /// bytes WITHOUT a `$raf->Read` — so a truncated oversized object is still a
  /// faithful input. (For `< 1000000` PLIST.pm:301 *does* read, so a truncated
  /// small object would instead fail to extract.)
  fn truncated_data_bplist(data_size: u32) -> Vec<u8> {
    let mut out: Vec<u8> = b"bplist00".to_vec();
    let mut offsets: Vec<u8> = Vec::new();
    // obj 0 — dict, 1 entry: marker 0xD1, key ref 1, value ref 2 (refSize 1).
    offsets.push(out.len() as u8);
    out.extend_from_slice(&[0xD0 | 1, 1, 2]);
    // obj 1 — ASCII string "Blob" (type 5, len 4).
    offsets.push(out.len() as u8);
    out.push(0x50 | 4);
    out.extend_from_slice(b"Blob");
    // obj 2 — data object (type 4); size >= 15 ⇒ 0x0F escape + inline int.
    offsets.push(out.len() as u8);
    out.push(0x40 | 0x0F);
    out.push(0x10 | 2); // inline int marker, 4-byte width
    out.extend_from_slice(&data_size.to_be_bytes());
    // (no payload — truncated)
    let table_off = out.len() as u8;
    out.extend_from_slice(&offsets);
    // 32-byte trailer: intSize @6, refSize @7, numObj @8, topObj @16, tableOff @24.
    let mut trailer = [0u8; 32];
    trailer[6] = 1;
    trailer[7] = 1;
    trailer[15] = offsets.len() as u8; // numObj (low byte of the u64)
    trailer[31] = table_off; // tableOff (low byte of the u64)
    out.extend_from_slice(&trailer);
    out
  }

  /// Codex R15 F1 — a binary type-4 `data` object `>= 1000000` bytes becomes a
  /// length-only [`PlistLeaf::DataLen`] (PLIST.pm:300-303), NOT a byte copy.
  /// AT the 1 000 000 boundary and ABOVE it the placeholder reports the TRUE
  /// size; the bytes are never sliced (the fixture is truncated, which a
  /// `dec.data.get(..).to_vec()` would have failed to extract).
  #[test]
  fn binary_oversized_data_is_length_only_placeholder() {
    for size in [1_000_000_u32, 2_000_000, u32::MAX] {
      let bytes = truncated_data_bplist(size);
      let meta = parse_borrowed(&bytes).expect("recognized binary plist");
      let tag = meta
        .tags_slice()
        .iter()
        .find(|t| t.name() == "Blob")
        .expect("Blob tag emitted");
      // The leaf is a length-only placeholder carrying the REAL size — the
      // multi-MB payload was never copied.
      assert_eq!(
        tag.value(),
        &PlistLeaf::DataLen(size as usize),
        "size {size}: oversized data must be a length-only DataLen"
      );
      // It renders as the `(Binary data N bytes...)` placeholder with the
      // true N (matching `TagValue::Bytes` but built from the size alone).
      let tm = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
      assert_eq!(
        tm.get_str("PLIST", "Blob").as_deref(),
        Some(std::format!("(Binary data {size} bytes, use -b option to extract)").as_str()),
      );
    }
  }

  /// Codex R15 F1 — the threshold's lower side: a binary `data` object just
  /// BELOW 1 000 000 bytes still goes through the byte-copying [`PlistLeaf::Data`]
  /// path (PLIST.pm:300 `$size < 1000000` ⇒ `$raf->Read`). Built with a real
  /// (small, here 4-byte) payload so the bounds-checked read succeeds.
  #[test]
  fn binary_small_data_keeps_bytes() {
    // A complete `bplist00` with a 4-byte type-4 `data` object (well under the
    // 1 000 000 threshold) — the payload IS present and copied.
    let mut out: Vec<u8> = b"bplist00".to_vec();
    let mut offsets: Vec<u8> = Vec::new();
    offsets.push(out.len() as u8);
    out.extend_from_slice(&[0xD0 | 1, 1, 2]); // dict
    offsets.push(out.len() as u8);
    out.push(0x50 | 4);
    out.extend_from_slice(b"Blob"); // key string
    offsets.push(out.len() as u8);
    out.push(0x40 | 4); // data, inline size 4 (< 15 ⇒ no escape)
    out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let table_off = out.len() as u8;
    out.extend_from_slice(&offsets);
    let mut trailer = [0u8; 32];
    trailer[6] = 1;
    trailer[7] = 1;
    trailer[15] = offsets.len() as u8;
    trailer[31] = table_off;
    out.extend_from_slice(&trailer);

    let meta = parse_borrowed(&out).expect("recognized binary plist");
    let tag = meta
      .tags_slice()
      .iter()
      .find(|t| t.name() == "Blob")
      .expect("Blob tag emitted");
    assert_eq!(
      tag.value(),
      &PlistLeaf::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]),
      "a sub-threshold data object keeps its bytes"
    );
  }

  /// The XML fixture decodes to the same value set under the `"XML"` group.
  #[test]
  fn xml_fixture_tag_values() {
    let meta = parse_borrowed(XML_FIXTURE).unwrap();
    let tm = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      tm.get_str("XML", "TestString").as_deref(),
      Some("ExifTool PLIST test")
    );
    assert_eq!(tm.get_str("XML", "TestInteger").as_deref(), Some("256"));
    assert_eq!(
      tm.get_str("XML", "TestUnicode").as_deref(),
      Some("ExîfTöøl PLIST tést")
    );
    assert_eq!(tm.get_str("XML", "TestBoolean").as_deref(), Some("True"));
    assert_eq!(tm.get_str("XML", "TestDictAuthor").as_deref(), Some("Phil"));
    // XML `<date>` — `ConvertXMPDate` keeps the `Z` suffix verbatim.
    assert_eq!(
      tm.get_str("XML", "TestDate").as_deref(),
      Some("2013:02:22 12:49:10Z")
    );
    assert_eq!(
      tm.get_str("XML", "TestDictWhen").as_deref(),
      Some("2000:01:02 08:04:05Z")
    );
    // XML `<array>` — last-value-wins SCALAR under `exiftool -struct` (the
    // canonical golden mode): each `<string>` is a separate `FoundTag` call,
    // `-struct` suppresses list accumulation, so `three` wins. (Contrast the
    // binary fixture, where the array is a real Perl arrayref ⇒ a list.)
    assert_eq!(tm.get_str("XML", "TestArray").as_deref(), Some("three"));
    match tm.get("XML", "TestData") {
      Some(TagValue::Bytes(b)) => assert_eq!(b.len(), 12),
      other => panic!("TestData not bytes: {other:?}"),
    }
  }

  // -- tag-name generation -------------------------------------------------

  #[test]
  fn generate_tag_name_flattens_nested_keys() {
    // `TestDict/Author` ⇒ `TestDictAuthor` (the `/` is stripped by step 4).
    assert_eq!(generate_xml_tag_name("TestDict/Author"), "TestDictAuthor");
    assert_eq!(generate_xml_tag_name("TestDict/When"), "TestDictWhen");
    // A plain top-level key passes through unchanged.
    assert_eq!(generate_xml_tag_name("TestString"), "TestString");
    // The binary path flattens the same way (no prefix/suffix strip needed).
    assert_eq!(
      generate_binary_tag_name("TestDict/Author"),
      "TestDictAuthor"
    );
  }

  #[test]
  fn generate_tag_name_strips_modd_prefix_and_name_suffix() {
    // PLIST.pm:208-209 — XML-only strips.
    assert_eq!(
      generate_xml_tag_name("MetaDataList//DateTimeOriginal"),
      "DateTimeOriginal"
    );
    assert_eq!(generate_xml_tag_name("cast//name"), "Cast");
    // Codex R1 F3 — the binary path does NOT strip `MetaDataList//` / `//name`
    // (those `s///` live only in `FoundTag`). `cast//name` ⇒ steps 3/4 drop
    // the slashes ⇒ `castName` ⇒ `ucfirst` ⇒ `CastName`.
    assert_eq!(generate_binary_tag_name("cast//name"), "CastName");
    assert_eq!(
      generate_binary_tag_name("MetaDataList//DateTimeOriginal"),
      "MetaDataListDateTimeOriginal"
    );
  }

  #[test]
  fn generate_tag_name_capitalizes_after_non_alpha() {
    // PLIST.pm:210 — `s/([^A-Za-z])([a-z])/$1\u$2/g`. `a-b` ⇒ `-` is
    // non-alpha, `b` is lowercase ⇒ `B` (string becomes `a-B`). Step 4's
    // `tr/-_a-zA-Z0-9//dc` KEEPS `-` (it is in the `[-_A-Za-z0-9]` keep
    // set), so step 5 `ucfirst` yields `A-B` — verified against bundled
    // Perl. (Contrast `/`, which is NOT in the keep set and IS stripped.)
    assert_eq!(generate_xml_tag_name("a-b"), "A-B");
    // A `/` separator is stripped: `a/b` ⇒ step 3 `/b` ⇒ `/B` ⇒ step 4
    // drops `/` ⇒ `aB` ⇒ `ucfirst` ⇒ `AB`.
    assert_eq!(generate_xml_tag_name("a/b"), "AB");
  }

  /// Codex R1 F3 — the binary-only `Tag`-prefix guard (PLIST.pm:364):
  /// `$name = 'Tag'.ucfirst($name) if length($name) < 2 or $name =~ /^[-0-9]/`.
  /// Verified against bundled `exiftool -j -G1 -struct` on a synthetic
  /// binary plist with short / digit-leading / dash-leading dict keys.
  #[test]
  fn generate_binary_tag_name_applies_tag_prefix_guard() {
    // `< 2` characters after filtering ⇒ `Tag` prefix.
    assert_eq!(generate_binary_tag_name("x"), "TagX");
    // Starts with a digit ⇒ `Tag` prefix (step 3 also capitalizes `9abc`).
    assert_eq!(generate_binary_tag_name("9abc"), "Tag9Abc");
    // Starts with `-` ⇒ `Tag` prefix; the dash survives step 4.
    assert_eq!(generate_binary_tag_name("-foo"), "Tag-Foo");
    // A normal name is NOT prefixed — just `ucfirst`.
    assert_eq!(generate_binary_tag_name("good"), "Good");
    // Codex R2 F3 — the XML path ALSO prefixes via `AddTagToTable`
    // (ExifTool.pm:9254): `Tag` when `< 2` chars or not letter-leading.
    // Verified against bundled `exiftool -j -G1 -struct` (`/tmp/tx1.plist`):
    // bundled emits `XML:TagX` / `XML:Tag9Abc` / `XML:Tag-Foo`.
    assert_eq!(generate_xml_tag_name("9abc"), "Tag9Abc");
    assert_eq!(generate_xml_tag_name("x"), "TagX");
    assert_eq!(generate_xml_tag_name("-foo"), "Tag-Foo");
    // A normal letter-leading XML name is left bare (`ucfirst` only).
    assert_eq!(generate_xml_tag_name("good"), "Good");
  }

  // -- ConvertXMPDate ------------------------------------------------------

  #[test]
  fn convert_xmp_date_rewrites_separators() {
    assert_eq!(
      convert_xmp_date("2013-02-22T12:49:10Z"),
      "2013:02:22 12:49:10Z"
    );
    // No seconds component.
    assert_eq!(convert_xmp_date("2013-02-22T12:49Z"), "2013:02:22 12:49Z");
  }

  // -- unescape_xml --------------------------------------------------------

  #[test]
  fn unescape_xml_decodes_predefined_entities() {
    assert_eq!(unescape_xml("a &amp; b"), "a & b");
    assert_eq!(unescape_xml("&lt;tag&gt;"), "<tag>");
    assert_eq!(unescape_xml("&quot;q&quot; &apos;a&apos;"), "\"q\" 'a'");
    // No entity — fast path.
    assert_eq!(unescape_xml("plain"), "plain");
    // Numeric reference.
    assert_eq!(unescape_xml("&#65;&#x42;"), "AB");
  }

  // -- binary primitives ---------------------------------------------------

  #[test]
  fn read_uint_big_endian_widths() {
    let b = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    assert_eq!(read_uint(&b, 0, 1), Some(0x12));
    assert_eq!(read_uint(&b, 0, 2), Some(0x1234));
    assert_eq!(read_uint(&b, 0, 3), Some(0x123456));
    assert_eq!(read_uint(&b, 0, 4), Some(0x12345678));
    assert_eq!(read_uint(&b, 0, 8), Some(0x123456789abcdef0));
    // Unsupported width.
    assert_eq!(read_uint(&b, 0, 5), None);
    // Short buffer.
    assert_eq!(read_uint(&b, 6, 4), None);
  }

  #[test]
  fn decode_ucs2_be_transcodes_surrogate_safe() {
    // "AB" as UCS-2 big-endian.
    assert_eq!(decode_ucs2_be(&[0x00, 0x41, 0x00, 0x42]), "AB");
    // A non-ASCII BMP char: U+00EE (î).
    assert_eq!(decode_ucs2_be(&[0x00, 0xee]), "î");
  }

  #[test]
  fn decode_plist_data_picks_base64_then_hex() {
    // Base64 `PGR1bW15IGRhdGE+` ⇒ `<dummy data>` (12 bytes).
    let b64 = decode_plist_data("PGR1bW15IGRhdGE+");
    assert_eq!(b64, b"<dummy data>");
    // ASCII-hex `48656c6c6f` ⇒ `Hello`.
    let hex = decode_plist_data("48656c6c6f");
    assert_eq!(hex, b"Hello");
  }

  // -- Codex R17 F1: XML `<real>` / `<integer>` stored as RAW scalar text ---

  #[test]
  fn xml_real_integer_leaf_keeps_raw_scalar_text() {
    // PLIST.pm's XML path (`FoundTag`, PLIST.pm:184-186) never type-parses a
    // numeric leaf — it stores the UNESCAPED scalar text verbatim. A
    // non-finite word stays lowercase (NOT round-tripped through `f64` into
    // the titlecase Perl-NV string); a trailing zero / leading zero / hex /
    // exponent form is preserved exactly.
    for body in [
      "inf", "-inf", "nan", "Infinity", "1.50", "1.4e2", "+5.0", ".5", "5.",
    ] {
      assert_eq!(
        decode_xml_leaf("real", body, false),
        PlistValue::Str(body.to_string()),
        "<real>{body}</real> must store the raw scalar text"
      );
    }
    for body in ["007", "-007", "0x10", "42", "3000000000"] {
      assert_eq!(
        decode_xml_leaf("integer", body, false),
        PlistValue::Str(body.to_string()),
        "<integer>{body}</integer> must store the raw scalar text"
      );
    }
    // The XML entity-unescape (PLIST.pm:168) still runs on the body.
    assert_eq!(
      decode_xml_leaf("string", "a &amp; b", false),
      PlistValue::Str("a & b".to_string())
    );
  }

  #[test]
  fn perl_is_float_matches_exiftool_grammar() {
    // ExifTool.pm:5936 `IsFloat` — `^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?$`.
    for s in [
      "1.50", "41327.5", "3725.0", "1e10", "1.4e2", ".5", "+5.0", "-3", "5.", "0", "1E-3", "-.5",
    ] {
      assert!(perl_is_float(s), "IsFloat({s:?}) should be true");
    }
    for s in [
      "inf", "-inf", "nan", "Infinity", "0x10", " 8 ", "1.4e2 ", "1e", "e5", ".", "", "+", "1.2.3",
      "1,5",
    ] {
      assert!(!perl_is_float(s), "IsFloat({s:?}) should be false");
    }
  }

  #[test]
  fn leaf_numeric_parses_str_only_when_is_float() {
    // A binary numeric leaf is pre-typed — taken directly.
    assert_eq!(leaf_numeric(&PlistLeaf::Real(2.5)), Some(2.5));
    assert_eq!(leaf_numeric(&PlistLeaf::Int(7)), Some(7.0));
    assert_eq!(leaf_numeric(&PlistLeaf::UInt(9)), Some(9.0));
    // An XML numeric leaf is raw text — numified only when `IsFloat`.
    assert_eq!(leaf_numeric(&PlistLeaf::Str("3725.0".into())), Some(3725.0));
    assert_eq!(
      leaf_numeric(&PlistLeaf::Str("41327.5".into())),
      Some(41327.5)
    );
    // A non-`IsFloat` word ⇒ `None` (Perl's `: $val` pass-through).
    assert_eq!(leaf_numeric(&PlistLeaf::Str("inf".into())), None);
    assert_eq!(leaf_numeric(&PlistLeaf::Str("0x10".into())), None);
    assert_eq!(leaf_numeric(&PlistLeaf::Bool(true)), None);
  }

  #[test]
  fn value_conv_passes_through_non_finite_real_text() {
    // PLIST.pm:73 — the MODD `DateTimeOriginal` `ValueConv` is
    // `IsFloat($val) ? ConvertUnixTime(...) : $val`. An XML `<real>inf</real>`
    // is NOT `IsFloat` ⇒ the raw scalar passes through unchanged (no
    // titlecase Perl-NV `Inf`).
    let out = apply_value_conv(
      PlistConv::DateTimeOriginalDays,
      PlistLeaf::Str("inf".into()),
    );
    assert_eq!(out, PlistLeaf::Str("inf".into()));
    // A numeric XML `<real>` IS converted (same as a binary `Real`).
    let from_str = apply_value_conv(
      PlistConv::DateTimeOriginalDays,
      PlistLeaf::Str("41327.5".into()),
    );
    let from_real = apply_value_conv(PlistConv::DateTimeOriginalDays, PlistLeaf::Real(41327.5));
    assert_eq!(from_str, from_real);
    assert!(matches!(from_str, PlistLeaf::Date(_)));
  }

  #[test]
  fn xml_date_leaf_is_not_trimmed_before_convert() {
    // Codex R17 F1 class-sweep — `decode_xml_leaf("date", …)` feeds the RAW
    // unescaped body to `ConvertXMPDate` with NO trim (PLIST.pm:180-181 +
    // XMP.pm:4178-4181, which trims only an `rdf:Description` prop). A clean
    // body matches `ConvertXMPDate`'s anchored regex and is rewritten to EXIF
    // form; a leading/trailing-whitespace body FAILS the anchored match and
    // passes through VERBATIM (separators NOT rewritten) — oracle-verified.
    assert_eq!(
      decode_xml_leaf("date", "2013-02-22T12:49:10Z", false),
      PlistValue::Date("2013:02:22 12:49:10Z".to_string())
    );
    assert_eq!(
      decode_xml_leaf("date", " 2013-02-22T12:49:10Z ", false),
      PlistValue::Date(" 2013-02-22T12:49:10Z ".to_string())
    );
    assert_eq!(
      decode_xml_leaf("date", "\n2013-02-22T12:49:10Z\n", false),
      PlistValue::Date("\n2013-02-22T12:49:10Z\n".to_string())
    );
  }

  #[test]
  fn convert_binary_date_apple_epoch_is_2001() {
    // Apple epoch 0.0 ⇒ 2001-01-01 00:00:00 UTC ⇒ the faithful localtime
    // branch (Codex R2 F1). The exact offset is OS-TZ dependent; assert the
    // `"YYYY:MM:DD HH:MM:SS±HH:MM"` shape (the conformance suite, pinned
    // `TZ=UTC`, asserts the exact `2001:01:01 00:00:00+00:00`).
    let s = convert_binary_date(0.0);
    assert!(
      is_localtime_shape(&s),
      "epoch date not localtime-shaped: {s}"
    );
  }

  // -- Codex R3 F4: fractional binary-date rounding ------------------------

  #[test]
  fn convert_binary_date_rounds_fractional_seconds() {
    // 0.6 s past the Apple epoch ⇒ round UP to `…00:00:01` (ExifTool.pm
    // `sprintf('%.0f',$frac)` + the leading-`1` carry); 1.4 s ⇒ round DOWN
    // to `…00:00:01`; the prior `trunc()` gave `…00:00:00` for both. The
    // exact offset is OS-TZ dependent — assert the integral-second part the
    // rounding controls. (The conformance suite, pinned `TZ=UTC`, asserts
    // the exact `2001:01:01 00:00:01+00:00`.)
    assert!(
      convert_binary_date(0.6).starts_with("2001:01:01 00:00:01"),
      "0.6s should round up to 00:00:01: {}",
      convert_binary_date(0.6)
    );
    assert!(
      convert_binary_date(1.4).starts_with("2001:01:01 00:00:01"),
      "1.4s should round down to 00:00:01: {}",
      convert_binary_date(1.4)
    );
    // 0.4 s ⇒ round DOWN to `…00:00:00`.
    assert!(
      convert_binary_date(0.4).starts_with("2001:01:01 00:00:00"),
      "0.4s should round down to 00:00:00: {}",
      convert_binary_date(0.4)
    );
  }

  // -- Codex R4 F1: exact half-second binary-date rounds half-to-EVEN -------

  #[test]
  fn convert_binary_date_half_second_rounds_to_even() {
    // ExifTool.pm:6783 `sprintf('%.0f', $frac)` is round-half-to-EVEN, NOT
    // half-away-from-zero. An exact `.5` fraction therefore rounds DOWN
    // (the even neighbour `0`), so `apple=0.5` ⇒ `…00:00:00` — the prior
    // `f64::round()` (half-away) gave `…00:00:01`. Verified against bundled
    // ExifTool 13.58: `ConvertUnixTime(0.5 + 11323*24*3600, 1)` ⇒
    // `2001:01:01 00:00:00+00:00`.
    assert!(
      convert_binary_date(0.5).starts_with("2001:01:01 00:00:00"),
      "0.5s (half-to-even) should NOT carry: {}",
      convert_binary_date(0.5)
    );
    // Just past the tie ⇒ round UP to `…00:00:01`.
    assert!(
      convert_binary_date(0.500_000_1).starts_with("2001:01:01 00:00:01"),
      "0.5000001s should round up to 00:00:01: {}",
      convert_binary_date(0.500_000_1)
    );
    // `apple=1.5`: `$itime = 1`, `$frac = 0.5` ⇒ `"0"` (no carry) ⇒
    // `…00:00:01` (bundled: `2001:01:01 00:00:01+00:00`).
    assert!(
      convert_binary_date(1.5).starts_with("2001:01:01 00:00:01"),
      "1.5s half-to-even should stay 00:00:01: {}",
      convert_binary_date(1.5)
    );
    // Negative half-fraction: `apple=-0.5` ⇒ floor to `$itime = -1`,
    // `$frac = 0.5` ⇒ `"0"` (no carry) ⇒ one second before the epoch
    // (bundled: `2000:12:31 23:59:59+00:00`).
    assert!(
      convert_binary_date(-0.5).starts_with("2000:12:31 23:59:59"),
      "-0.5s should floor to 23:59:59: {}",
      convert_binary_date(-0.5)
    );
  }

  // -- Codex R4 F2: DateTimeOriginal ValueConv keeps the fractional float ---

  #[test]
  fn datetime_original_days_keeps_fractional_seconds() {
    // PLIST.pm:73 `ConvertUnixTime(($val - 25569) * 24 * 3600)` is applied to
    // the FLOAT, with the `$time == 0` sentinel checked on the ORIGINAL
    // float (ExifTool.pm:6776). The prior port truncated to an i64 first,
    // dropping the fraction AND mis-firing the sentinel for sub-second
    // values. Fixtures verified against bundled ExifTool 13.58.
    let conv =
      |days: f64| match apply_value_conv(PlistConv::DateTimeOriginalDays, PlistLeaf::Real(days)) {
        PlistLeaf::Date(s) => s,
        other => panic!("expected Date leaf, got {other:?}"),
      };
    // 25569 + 0.6/86400 days ⇒ 0.5999998888 s ⇒ `1970:01:01 00:00:01`
    // (was the `0000:…` sentinel under the old truncating path).
    assert_eq!(conv(25569.0 + 0.6 / 86400.0), "1970:01:01 00:00:01");
    // Exact half-second ⇒ 0.5000001169 s (the float isn't a true tie) ⇒
    // rounds up to `…00:00:01`.
    assert_eq!(conv(25569.0 + 0.5 / 86400.0), "1970:01:01 00:00:01");
    // Negative fractional day ⇒ -0.5999998888 s ⇒ floor ⇒
    // `1969:12:31 23:59:59`.
    assert_eq!(conv(25569.0 - 0.6 / 86400.0), "1969:12:31 23:59:59");
    // Exactly the 25569 epoch ⇒ `$time == 0` ⇒ the sentinel.
    assert_eq!(conv(25569.0), "0000:00:00 00:00:00");
  }

  // -- Codex R3 F2: unsigned binary integers above i64::MAX ----------------

  #[test]
  fn binary_integer_above_i64_max_stays_unsigned() {
    // A type-1 8-byte integer marker (`0x13`) + `0x8000000000000000`. Build
    // the minimal binary plist `{ big: <that int> }` and check the leaf is
    // `UInt`, not a wrapped negative `Int`.
    let mut body: Vec<u8> = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    offsets.push(body.len());
    body.extend_from_slice(&[0xD1, 0x01, 0x02]); // dict, 1 pair
    offsets.push(body.len());
    body.extend_from_slice(&[0x53]); // ASCII string len 3
    body.extend_from_slice(b"big");
    offsets.push(body.len());
    body.extend_from_slice(&[0x13]); // int, 8 bytes
    body.extend_from_slice(&0x8000_0000_0000_0000u64.to_be_bytes());
    let table_off = body.len() as u64;
    for o in &offsets {
      body.push(*o as u8);
    }
    body.extend_from_slice(&[0; 6]); // trailer pad
    body.push(1); // intSize
    body.push(1); // refSize
    body.extend_from_slice(&3u64.to_be_bytes()); // numObj
    body.extend_from_slice(&0u64.to_be_bytes()); // topObj
    body.extend_from_slice(&table_off.to_be_bytes());

    let meta = parse_borrowed(&body).unwrap();
    let tm = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    // Bundled emits the unsigned scalar `9223372036854775808`.
    assert_eq!(
      tm.get_str("PLIST", "Big").as_deref(),
      Some("9223372036854775808")
    );
  }

  // -- Codex R3 F1: static `%PLIST::Main` table lookup ---------------------

  #[test]
  fn static_table_lookup_maps_known_ids() {
    // The double-slash MODD IDs (XML path) and single-slash IDs (both paths)
    // resolve to their fixed `Name`.
    assert_eq!(
      lookup_static("MetaDataList//Duration").unwrap().name,
      "Duration"
    );
    assert_eq!(lookup_static("cast//name").unwrap().name, "Cast");
    assert_eq!(
      lookup_static("SystemVersion/ProductName").unwrap().name,
      "ProductName"
    );
    assert_eq!(
      lookup_static("MetaDataList//Geolocation/Latitude")
        .unwrap()
        .name,
      "GPSLatitude"
    );
    // An unknown ID — no static entry (caller generates a dynamic name).
    assert!(lookup_static("TestDict/Author").is_none());
    // Codex R20 F1: `adjustmentData` is now PRESENT (PLIST.pm:142-146) so the
    // XML walker can intercept its `<data>` payload for the `CompressedPLIST`
    // sub-walk; the entry's `Name` is `AdjustmentData` (PLIST.pm:143).
    assert_eq!(
      lookup_static("adjustmentData").unwrap().name,
      "AdjustmentData"
    );
  }

  #[test]
  fn static_datetime_original_value_conv_days_to_unixtime() {
    // PLIST.pm:73 — `ConvertUnixTime(($val - 25569) * 24 * 3600)`. 41327.5
    // days since 1899-12-31 ⇒ `2013:02:22 12:00:00` (GMT, no tz suffix).
    let leaf = apply_value_conv(PlistConv::DateTimeOriginalDays, PlistLeaf::Real(41327.5));
    assert_eq!(leaf, PlistLeaf::Date("2013:02:22 12:00:00".to_string()));
    // A non-numeric value passes through unchanged (`: $val`).
    let s = apply_value_conv(PlistConv::DateTimeOriginalDays, PlistLeaf::Str("x".into()));
    assert_eq!(s, PlistLeaf::Str("x".into()));
  }

  // -- Codex R3 F1: GPS ToDMS PrintConv ------------------------------------

  #[test]
  fn gps_to_dms_default_format() {
    // PLIST.pm:84/89 — `ToDMS($self, $val, 1, "N"/"E")` with the default
    // `q{%d deg %d' %.2f"}` format. Verified against bundled `exiftool`.
    assert_eq!(gps_to_dms(37.7749, 'N'), "37 deg 46' 29.64\" N");
    // A negative longitude flips `E`→`W` and uses |val|.
    assert_eq!(gps_to_dms(-122.4194, 'E'), "122 deg 25' 9.84\" W");
    // A negative latitude flips `N`→`S`.
    assert_eq!(gps_to_dms(-1.5, 'N'), "1 deg 30' 0.00\" S");
  }

  #[test]
  fn static_print_conv_duration_print_mode_only() {
    // `Duration` ⇒ `ConvertDuration` in print mode; raw value in `-n` (the
    // serialize path emits the raw leaf when `print_conv` is false).
    let s = apply_print_conv(PlistConv::Duration, &PlistLeaf::Real(3725.0));
    assert_eq!(s.as_deref(), Some("1:02:05"));
    // A `None`-conv tag yields no print string (raw leaf emitted instead).
    assert!(apply_print_conv(PlistConv::None, &PlistLeaf::Int(5)).is_none());
  }

  // -- Codex R5 F1 / R6 F1 / R11 F1+F2: content file-type override ----------

  /// PLIST.pm:133-141 — the MODD override is keyed on the EXACT RAW tag ID
  /// `XMLFileType` == `ModdXML` (NOT the generated name). The detection follows
  /// the event-stream emission (Codex R6 F1), so it covers the array-wrapped
  /// form too, and (Codex R11 F1) a NAME-colliding key that generates the same
  /// emitted name must NOT override.
  #[test]
  fn modd_xml_root_detected_only_for_exact_raw_id() {
    let ov = |body: &str| -> Option<PlistContentOverride> {
      let xml =
        std::format!("<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict>{body}</dict></plist>");
      parse_xml(xml.as_bytes())
        .expect("parse xml")
        .content_override()
    };
    // Direct top-level `XMLFileType` == `ModdXML`.
    assert_eq!(
      ov("<key>XMLFileType</key><string>ModdXML</string>"),
      Some(PlistContentOverride::Modd)
    );
    // Codex R6 F1 — an ARRAY-wrapped `ModdXML` still emits tag `XMLFileType`
    // (a scalar value event does not extend `@keys`) ⇒ the override fires.
    assert_eq!(
      ov("<key>XMLFileType</key><array><string>ModdXML</string></array>"),
      Some(PlistContentOverride::Modd)
    );
    // Wrong value ⇒ no override.
    assert_eq!(ov("<key>XMLFileType</key><string>Other</string>"), None);
    // A non-string value (`<integer>`) never matches `eq 'ModdXML'`.
    assert_eq!(ov("<key>XMLFileType</key><integer>42</integer>"), None);
    // Wrong key ⇒ no override.
    assert_eq!(ov("<key>FileType</key><string>ModdXML</string>"), None);
    // Codex R11 F1 — the NAME-colliding raw key `xMLFileType` generates the
    // SAME emitted name `XMLFileType` (ucfirst), but the RawConv is keyed on the
    // exact RAW ID, which differs ⇒ NO override. (Oracle: `FileType=PLIST`.)
    assert_eq!(ov("<key>xMLFileType</key><string>ModdXML</string>"), None);
  }

  /// Codex R11 F2 — `%plistType` (PLIST.pm:42, applied at :225) keys the AAE
  /// override on the EXACT RAW tag ID `adjustmentBaseVersion` (no value
  /// predicate). A NAME-colliding raw key must NOT override.
  #[test]
  fn aae_override_keyed_on_exact_raw_id() {
    let ov = |body: &str| -> Option<PlistContentOverride> {
      let xml =
        std::format!("<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict>{body}</dict></plist>");
      parse_xml(xml.as_bytes())
        .expect("parse xml")
        .content_override()
    };
    // Exact raw ID — any value type triggers AAE (`%plistType` has no value
    // predicate). Oracle: `<integer>0>` AND `<string>hello>` both ⇒ AAE.
    assert_eq!(
      ov("<key>adjustmentBaseVersion</key><integer>0</integer>"),
      Some(PlistContentOverride::Aae)
    );
    assert_eq!(
      ov("<key>adjustmentBaseVersion</key><string>hello</string>"),
      Some(PlistContentOverride::Aae)
    );
    // Codex R11 F2 — the NAME-colliding raw key `adjustmentbaseVersion`
    // (lowercase `b`) is a different raw ID ⇒ NO override. (Oracle:
    // `FileType=PLIST`.)
    assert_eq!(
      ov("<key>adjustmentbaseVersion</key><integer>0</integer>"),
      None
    );
  }

  /// Last-call-wins over the document-order stream (PLIST.pm `OverrideFileType`,
  /// ExifTool.pm:9714-9716). Verified against the oracle: MODD-key-first ⇒ AAE,
  /// AAE-key-first ⇒ MODD.
  #[test]
  fn content_override_is_last_qualifying_tag_wins() {
    let ov = |body: &str| -> Option<PlistContentOverride> {
      let xml =
        std::format!("<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict>{body}</dict></plist>");
      parse_xml(xml.as_bytes())
        .expect("parse xml")
        .content_override()
    };
    assert_eq!(
      ov(
        "<key>XMLFileType</key><string>ModdXML</string>\
          <key>adjustmentBaseVersion</key><integer>0</integer>"
      ),
      Some(PlistContentOverride::Aae),
      "MODD key first, AAE key second ⇒ AAE wins"
    );
    assert_eq!(
      ov(
        "<key>adjustmentBaseVersion</key><integer>0</integer>\
          <key>XMLFileType</key><string>ModdXML</string>"
      ),
      Some(PlistContentOverride::Modd),
      "AAE key first, MODD key second ⇒ MODD wins"
    );
  }

  #[test]
  fn parse_xml_sets_content_override() {
    // End-to-end: an XML plist with `XMLFileType=ModdXML` selects MODD, one with
    // `adjustmentBaseVersion` selects AAE, a plain plist selects none. The
    // binary path never sets it (PLIST.pm:483 SetFileType('PLIST') ⇒ the
    // `eq 'XMP'` guard can't hold).
    let modd = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>XMLFileType</key><string>ModdXML</string>
</dict></plist>"#;
    assert_eq!(
      parse_xml(modd).expect("parse modd xml").content_override(),
      Some(PlistContentOverride::Modd)
    );
    let aae = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>adjustmentBaseVersion</key><integer>0</integer>
</dict></plist>"#;
    assert_eq!(
      parse_xml(aae).expect("parse aae xml").content_override(),
      Some(PlistContentOverride::Aae)
    );
    let plain = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>Foo</key><string>Bar</string>
</dict></plist>"#;
    assert_eq!(
      parse_xml(plain)
        .expect("parse plain xml")
        .content_override(),
      None
    );
  }

  // -- Codex R5 F2: nested XML array recursion -----------------------------

  #[test]
  fn nested_xml_scalar_array_emits_under_bare_key() {
    // `<key>outer</key><array><array><string>Deep</string></array></array>` ⇒
    // `XML:Outer="Deep"`: a value event never extends `@keys`
    // (PLIST.pm:200-202), so the scalar lands under the bare `outer` ID.
    let xml = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>outer</key><array><array><string>Deep</string></array></array>
</dict></plist>"#;
    let m = parse_xml(xml).expect("parse nested scalar array");
    let outer = m
      .tags_slice()
      .iter()
      .find(|t| t.name() == "Outer")
      .expect("Outer tag present");
    assert_eq!(outer.value(), &PlistLeaf::Str("Deep".into()));
  }

  #[test]
  fn nested_xml_array_of_dict_accrues_empty_slots() {
    // `<key>top</key><array><array><dict><key>inner</key><string>Val</string>
    // </dict></array></array>` ⇒ tag ID `top///inner` (two array levels each
    // add an empty key-slot, PLIST.pm:191-194) ⇒ `XML:TopInner="Val"`.
    let xml = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>top</key><array><array><dict><key>inner</key><string>Val</string></dict></array></array>
</dict></plist>"#;
    let m = parse_xml(xml).expect("parse nested array of dict");
    let tag = m
      .tags_slice()
      .iter()
      .find(|t| t.name() == "TopInner")
      .expect("TopInner tag present");
    assert_eq!(tag.value(), &PlistLeaf::Str("Val".into()));
  }

  // -- Codex R10 F2: Perl-style bitwise numification of a flags word --------

  /// `perl_numify_word_u64` must numify a `split ' '` word the way Perl's
  /// `&` does (ExifTool.pm:6379) — a numeric prefix with sign / fraction /
  /// exponent, exact for an integer that fits Perl's IV/UV, truncating &
  /// saturating a double. Each expectation is pinned to the Perl oracle
  /// `perl -e 'printf "%d", "<word>" & 0xFFFF...FFFF'`.
  #[cfg(feature = "alloc")]
  #[test]
  fn perl_numify_word_matches_perl_bitwise_coercion() {
    // Exponent: `1e2` numifies to 100, NOT `1` (a digit-only scan's bug).
    assert_eq!(perl_numify_word_u64("1e2"), 100);
    // Signed exponent: `-1e2` ⇒ -100, two's-complement in u64 space.
    assert_eq!(perl_numify_word_u64("-1e2"), (-100i64) as u64);
    assert_eq!(perl_numify_word_u64("1e2") as u32, 100); // bits 2,5,6
    assert_eq!(perl_numify_word_u64("-1e2") as u32, 0xFFFF_FF9C);
    // `u64::MAX` as a decimal string stays EXACT (an `i64` parse would
    // overflow ⇒ the old code yielded 0); `&` sees every bit.
    assert_eq!(
      perl_numify_word_u64("18446744073709551615"),
      u64::MAX,
      "u64::MAX literal must numify exactly, not to 0"
    );
    // Just past `u64::MAX` ⇒ Perl promotes to a double ⇒ `&` saturates the
    // UV high to all-ones (oracle: `…616 & 0xFFFFFFFF == 0xFFFFFFFF`).
    assert_eq!(
      perl_numify_word_u64("18446744073709551616") as u32,
      0xFFFF_FFFF
    );
    // A mantissa fraction is truncated toward zero (`3.9` ⇒ 3, `-3.9` ⇒ -3).
    assert_eq!(perl_numify_word_u64("3.9"), 3);
    assert_eq!(perl_numify_word_u64("-3.9"), (-3i64) as u64);
    // `1.9e2` ⇒ 190 (mantissa + exponent), `1.` ⇒ 1, `.5` ⇒ 0 (0.5 trunc).
    assert_eq!(perl_numify_word_u64("1.9e2"), 190);
    assert_eq!(perl_numify_word_u64("1."), 1);
    assert_eq!(perl_numify_word_u64(".5"), 0);
    assert_eq!(perl_numify_word_u64(".5e1"), 5);
    // Trailing garbage after a valid prefix is ignored (`12abc` ⇒ 12).
    assert_eq!(perl_numify_word_u64("12abc"), 12);
    assert_eq!(perl_numify_word_u64("1e2.5"), 100);
    assert_eq!(perl_numify_word_u64("1e"), 1); // bare `e` not consumed
    // No numeric prefix ⇒ 0 — Perl does NOT honour `0x`/`inf`/`nan` here.
    assert_eq!(perl_numify_word_u64("abc"), 0);
    assert_eq!(perl_numify_word_u64("0x10"), 0);
    assert_eq!(perl_numify_word_u64("inf"), 0);
    assert_eq!(perl_numify_word_u64("nan"), 0);
    // Huge magnitudes saturate: a positive double clamps to `u64::MAX`; a
    // negative double clamps through `i64` to `i64::MIN` (oracle: `-1e30 &
    // 0xFFFF…FFFF == 9223372036854775808`), whose low 32 bits are 0.
    assert_eq!(perl_numify_word_u64("1e30"), u64::MAX);
    assert_eq!(perl_numify_word_u64("-1e30"), i64::MIN as u64);
    assert_eq!(perl_numify_word_u64("-1e30") as u32, 0);
    // Leading whitespace + sign are skipped like Perl's scan.
    assert_eq!(perl_numify_word_u64("  +5"), 5);
  }

  /// The slowMotion `*Flags` `PrintConv` (`DecodeBits`, PLIST.pm:98-104) over
  /// the R10 F2 oracle words — verifies the full bit-decode, not just the
  /// numification. Oracle: `exiftool` on a `<string>flags` plist.
  #[cfg(feature = "alloc")]
  #[test]
  fn slow_motion_flags_decode_matches_oracle() {
    let decode = |s: &str| decode_slow_motion_flags(&PlistLeaf::Str(s.into()));
    // `1e2` ⇒ 100 ⇒ bits 2,5,6 ⇒ `Positive infinity, [5], [6]`.
    assert_eq!(decode("1e2"), "Positive infinity, [5], [6]");
    // `-1e2` ⇒ 0xFFFFFF9C ⇒ bits 2,3,4 then 7..31.
    let neg = decode("-1e2");
    assert!(neg.starts_with("Positive infinity, Negative infinity, Indefinite, [7], "));
    assert!(neg.ends_with(", [31]"));
    // `18446744073709551615` ⇒ all 32 low bits ⇒ 0..4 named + [5]..[31].
    let allbits = decode("18446744073709551615");
    assert!(allbits.starts_with(
      "Valid, Has been rounded, Positive infinity, Negative infinity, Indefinite, [5], "
    ));
    assert!(allbits.ends_with(", [31]"));
    // A non-numeric word ⇒ 0 ⇒ `(none)` (regression-guard for `abc`).
    assert_eq!(decode("abc"), "(none)");
  }

  // -- Codex R10 F1: non-ASCII inline comment must not panic ----------------

  /// `strip_xml_comments` walks `<!--…-->` candidates one BYTE at a time;
  /// a non-ASCII char inside an inline comment (`<!--é-->`) used to make a
  /// `str` slice land mid-UTF-8-char and panic. The scan is now byte-only.
  /// Faithful to XMP.pm:4181 `s/<!--.*?-->//g` (Perl strips it regardless).
  #[test]
  fn strip_xml_comments_handles_non_ascii_comment_body() {
    // Compare the rendered `&str` — `was_comment=true` always returns owned.
    let strip = |s: &str| strip_xml_comments(s, true).into_owned();
    // Inline single-line comment with a multi-byte char ⇒ stripped.
    assert_eq!(strip("foo<!--é-->bar"), "foobar");
    // Multi-byte chars in the surrounding text are preserved verbatim
    // (`strip_xml_comments` ports only `s/<!--.*?-->//g`, not the leading-
    // whitespace trim — XMP.pm:4181 is a bare substitution).
    assert_eq!(strip("café<!--ñ-->shop"), "caféshop");
    // A non-ASCII char right before `-->` (the cursor would land mid-char).
    assert_eq!(strip("a<!--xé-->b"), "ab");
    // Emoji (4-byte) inside the comment — widest UTF-8 case.
    assert_eq!(strip("p<!--🎬-->q"), "pq");
    // A newline-crossing comment is still left verbatim (no `/s`) even with
    // a non-ASCII char present — the byte scan must not panic here either.
    assert_eq!(strip("x<!--é\n-->y"), "x<!--é\n-->y");
  }

  // -- Codex R12 F1: UTF-8-BOM XML-plist recognition + over-skip guard ------

  /// `xml_content_is_plist` is the engine's XMP→PLIST routing gate (bundled's
  /// `ProcessXMP` `<plist>`/`<!DOCTYPE plist>` content sniff, XMP.pm:4369-4387).
  /// It must recognize a BOM-prefixed XML plist (the merge-blocker), accept the
  /// non-BOM and DOCTYPE forms, and — the CLASS-SWEEP boundary — NOT over-claim
  /// a binary plist, a BOM-prefixed SVG/RDF, or non-XML/empty input.
  #[test]
  fn xml_content_is_plist_recognizes_bom_and_rejects_non_plist() {
    let xml = b"<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict/></plist>";
    let bom_xml = [&[0xEF, 0xBB, 0xBF][..], xml].concat();
    // BOM + `<?xml` + `<plist>` ⇒ recognized (the bug being fixed).
    assert!(xml_content_is_plist(&bom_xml));
    // Non-BOM `<?xml` + `<plist>` ⇒ recognized (unchanged path).
    assert!(xml_content_is_plist(xml));
    // `<!DOCTYPE plist …>` (no `<plist>` yet in the window) ⇒ recognized.
    let doctype = b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"x\" \"y\">";
    assert!(xml_content_is_plist(doctype));
    let bom_doctype = [&[0xEF, 0xBB, 0xBF][..], doctype].concat();
    assert!(xml_content_is_plist(&bom_doctype));

    // -- over-skip guard: must NOT be claimed --
    // A binary plist (`bplist00`, no BOM) is NOT an XML plist.
    assert!(!xml_content_is_plist(b"bplist00\x00\x01\x02\x03"));
    // A BOM-prefixed binary-plist prefix is still not XML (`bplist0` != `<?xml`).
    let bom_bin = [&[0xEF, 0xBB, 0xBF][..], &b"bplist00"[..]].concat();
    assert!(!xml_content_is_plist(&bom_bin));
    // A BOM-prefixed SVG / RDF (real bundled XMP, no `<plist>`) ⇒ NOT plist.
    let bom_svg = [
      &[0xEF, 0xBB, 0xBF][..],
      &b"<?xml version=\"1.0\"?>\n<svg xmlns=\"x\"></svg>"[..],
    ]
    .concat();
    assert!(!xml_content_is_plist(&bom_svg));
    let bom_rdf = [
      &[0xEF, 0xBB, 0xBF][..],
      &b"<?xml version=\"1.0\"?>\n<rdf:RDF></rdf:RDF>"[..],
    ]
    .concat();
    assert!(!xml_content_is_plist(&bom_rdf));
    // `<plistx` (not `<plist[\s>]`) ⇒ NOT a plist element.
    assert!(!xml_content_is_plist(
      b"<?xml version=\"1.0\"?>\n<plistx></plistx>"
    ));
    // Non-XML / empty / lone BOM ⇒ NOT plist (panic-free).
    assert!(!xml_content_is_plist(b""));
    assert!(!xml_content_is_plist(&[0xEF, 0xBB, 0xBF]));
    assert!(!xml_content_is_plist(b"random bytes"));
  }
}
