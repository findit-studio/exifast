// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "mxf")]
//! Faithful port of `Image::ExifTool::MXF` (`lib/Image/ExifTool/MXF.pm`):
//! reads Material Exchange Format files (FORMATS.md row 24, Engine-only).
//!
//! ## KLV (Key-Length-Value) encoding
//!
//! An MXF file is a flat stream of KLV triplets: a 16-byte universal label
//! ("UL") **Key**, a BER-encoded **Length**, then the **Value** bytes
//! (MXF.pm:2854-2868). The bundled `ProcessMXF` (MXF.pm:2807-2969) walks the
//! stream, converts each 16-byte key to dotted-hex UL notation via
//! [`ul_notation`] (MXF.pm:2452-2455 `sub UL`), looks it up in
//! `%Image::ExifTool::MXF::Main`, and dispatches.
//!
//! ### BER length (MXF.pm:2857-2868)
//!
//! The first length byte: if `< 0x80`, it IS the length (short form). If
//! `>= 0x80`, the low 7 bits give a count `n` of subsequent big-endian bytes
//! holding the actual length (long form).
//!
//! ## Three sub-structures
//!
//! - **Header partition pack** (`OpenHeader`/`ClosedCompleteHeader`/…) — a
//!   `ProcessBinaryData` subtable (`%MXF::Header`, MXF.pm:2419-2446) yielding
//!   `MXFVersion` (offset 0, `int16u[2]`) plus the `FooterPosition` /
//!   `HeaderSize` book-keeping fields (offsets 24/32).
//! - **Primer** (`060e2b34.0205.0101.0d010201.01050100`, MXF.pm:2569-2597) —
//!   a table of `(int16u local-id, 16-byte global UL)` entries that builds the
//!   `local-id → UL` lookup the header-metadata local sets need.
//! - **Local sets** (`Preface`, `Identification`, `Track`, …) — a stream of
//!   `(int16u local-tag, int16u length, value)` triplets (MXF.pm:2603-2723).
//!   Each local-tag is mapped to a global UL through the Primer, then the UL
//!   is looked up in the tag table.
//!
//! ## MXF-specific value types ([`read_mxf_value`], MXF.pm:2477-2563)
//!
//! `UTF-16` (UTF-16BE → UTF-8), `Timestamp` (2+6 byte broken-down time),
//! `VersionType` / `ProductVersion` (dotted version numbers), `UL` / `GUID` /
//! `AUID` / `UUID` / `Label` (16-byte identifiers), `PackageID` / `UMID`
//! (32-byte), `StrongReference*` / `WeakReference*` / `BatchOfUL` (reference
//! arrays/batches), `Position` / `Length` (64-bit), `Boolean`.
//!
//! ## Family-1 group naming
//!
//! Every emitted tag starts in family-1 group `"MXF"` (MXF.pm:2838
//! `$$et{SET_GROUP1} = 'MXF'`). After the object tree is walked, tags belonging
//! to a `Track`'s object sub-tree are re-grouped to `Track<N>` (MXF.pm:2681-2684
//! and `SetGroups`, MXF.pm:2731-2778). `<N>` is a 1-based counter assigned in
//! the order TrackID values are first seen.
//!
//! ## Duration handling
//!
//! `Duration` / `Origin` / `StartTimecode` / `EssenceLength` carry the
//! `%duration` flags (MXF.pm:96-100): a `RawConv` drops all-`0xff` values
//! (`$val > 1e18 ? undef : $val`), the value is divided by the owning track's
//! `EditRate` (MXF.pm:2783-2801 `ConvertDurations`), and the PrintConv runs
//! `ConvertDuration` (`H:MM:SS` / `N s`). The top-level `MXF:Duration` is
//! synthesized from the "best" `TimecodeComponent` (MXF.pm:2943-2962).
//!
//! ## Header / footer traversal
//!
//! Faithful to MXF.pm:2842-2891: a `ClosedCompleteHeader` ends the walk once
//! the header partition is consumed; any other header type skips DIRECTLY
//! from the end of the header to the footer partition (body partitions carry
//! no header metadata). The `FooterPosition` / `HeaderSize` book-keeping
//! fields drive this — see [`process_header`] + the walk loop.
//!
//! ## Accepted deferral — partial tag table (4-surface visible)
//!
//! `%Image::ExifTool::MXF::Main` has ~1650 UL→tag rows. [`TAG_TABLE`] here
//! lists the subset the bundled conformance fixture reaches; an unrecognized
//! UL is skipped (faithful to bundled's "no `-U` ⇒ unknown tags not
//! emitted", MXF.pm:2896). The STRUCTURAL UL classification
//! ([`classify_top_level`]) IS complete (every `%header` / `%localSet` /
//! structural `Unknown` row), so the KLV walk + local-set framing + object
//! tree are faithful for ANY MXF file — only LEAF-tag coverage is fixture-
//! scoped. A non-fixture MXF would lose leaf tags whose UL is outside
//! `TAG_TABLE` (NOT a framing or object-graph break). The 4 surfaces of
//! this deferral: (1) this doc, (2) the [`TAG_TABLE`] doc comment,
//! (3) `tests/conformance.rs::mxf_conformance` exercises the listed rows,
//! (4) `docs/tracking.md` (local). A follow-up PR can generate the full
//! table; the structural classification needs no further work.
//!
//! Other deferrals:
//!
//! - The `Composite:*` engine is not ported; the bundled MXF golden has no
//!   `Composite:*` rows so the goldens here need no trimming on that axis.
//! - The MXF-specific `Lat`/`Lon`/`Alt` GPS coordinate types (MXF.pm:
//!   2510-2524) and the alternate-language `GetLangInfo` UTF-16 suffix path
//!   (MXF.pm:2644-2647) have no [`TAG_TABLE`] rows here — they fall under the
//!   partial-table deferral above (the fixture exercises neither). The `Kind`
//!   set is `#[non_exhaustive]` so they can be added without a breaking
//!   change when a fixture needs them.

// Golden-v2 Contract 3c (Phase C, slice w2a): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use smol_str::SmolStr;
use std::{borrow::Cow, string::String, vec::Vec};

use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// §1. Magic
// ===========================================================================

/// MXF run-in detection pattern — MXF.pm:2817
/// `\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02`. The bundled `ProcessMXF`
/// scans the first 65547 bytes for this 11-byte prefix and starts the KLV
/// walk 11 bytes earlier (the partition-pack UL begins there). Every MXF
/// partition pack key shares this prefix.
const MXF_RUN_IN_MARKER: [u8; 11] = [
  0x06, 0x0e, 0x2b, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0d, 0x01, 0x02,
];

/// The bundled `ProcessMXF` reads at most this many bytes to locate the
/// run-in marker (MXF.pm:2816 `$raf->Read($buff, 65547)`).
const RUN_IN_SCAN_LIMIT: usize = 65547;

// ===========================================================================
// §2. UL notation + 16-byte key helpers
// ===========================================================================

/// MXF.pm:2452-2455 `sub UL` — `join('.', unpack('H8H4H4H8H8', $val))`: a
/// 16-byte universal label rendered as five dotted lowercase-hex groups of
/// 8/4/4/8/8 hex digits (`060e2b34.0205.0101.0d010201.01050100`).
#[must_use]
fn ul_notation(key: &[u8]) -> SmolStr {
  // A UL key is always 16 bytes by construction (the KLV walker only calls
  // this with `&buf[..16]`); guard defensively for short slices.
  if key.len() < 16 {
    return SmolStr::default();
  }
  // The `key.len() < 16` guard above proves every group below is in range, so
  // each `.get(..)` hits; `unwrap_or(&[])` is the unreachable fallback
  // (byte-identical to the raw `&key[a..b]`).
  let mut s = String::with_capacity(36);
  push_hex(&mut s, key.get(0..4).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, key.get(4..6).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, key.get(6..8).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, key.get(8..12).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, key.get(12..16).unwrap_or(&[]));
  SmolStr::new(&s)
}

/// Append the lowercase-hex rendering of `bytes` to `out`.
fn push_hex(out: &mut String, bytes: &[u8]) {
  use core::fmt::Write as _;
  for b in bytes {
    let _ = write!(out, "{b:02x}");
  }
}

/// Lowercase-hex of an arbitrary byte slice — `unpack('H*', $val)`.
#[must_use]
fn hex_all(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len() * 2);
  push_hex(&mut s, bytes);
  s
}

/// MXF.pm:2556 `join('-', unpack('H8H4H4H4H12', $val))` — the 16-byte
/// "compact GUID" rendering (`8-4-4-4-12` dashed hex groups).
#[must_use]
fn guid_notation(key: &[u8]) -> String {
  if key.len() < 16 {
    return hex_all(key);
  }
  // The `key.len() < 16` guard above proves every group below is in range, so
  // each `.get(..)` hits; `unwrap_or(&[])` is the unreachable fallback
  // (byte-identical to the raw `&key[a..b]`).
  let mut s = String::with_capacity(36);
  push_hex(&mut s, key.get(0..4).unwrap_or(&[]));
  s.push('-');
  push_hex(&mut s, key.get(4..6).unwrap_or(&[]));
  s.push('-');
  push_hex(&mut s, key.get(6..8).unwrap_or(&[]));
  s.push('-');
  push_hex(&mut s, key.get(8..10).unwrap_or(&[]));
  s.push('-');
  push_hex(&mut s, key.get(10..16).unwrap_or(&[]));
  s
}

// ===========================================================================
// §3. Tag table — `%Image::ExifTool::MXF::Main` (the subset MXF needs)
// ===========================================================================

/// Decode + post-decode semantics for one MXF tag. Mirrors the `Format` /
/// `Type` distinction in `%MXF::Main`: `Format` rows use ExifTool's generic
/// `ReadValue`; `Type` rows use the MXF-specific [`read_mxf_value`]
/// (MXF.pm:2633-2648 — only types in `%knownType` get decoded).
///
/// `#[non_exhaustive]` so future tag-table rows can grow new decode kinds
/// without breaking downstream matchers. Variants are unit only (D8 §2).
///
/// Four variants (`Int8u`, `AsciiString`, `Label`, `Binary`) are not
/// referenced from the current [`TAG_TABLE`] — the bundled MXF fixture's
/// tags all go through the other kinds. They remain as exhaustive
/// documentation of the `%MXF::Main` `Format`/`Type` set (every `.pm` row
/// uses one of these) so future tag-table additions need no new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(dead_code)]
enum Kind {
  /// `Format => 'int8u'` — 1-byte big-endian unsigned.
  Int8u,
  /// `Format => 'int16u'` — 2-byte big-endian unsigned.
  Int16u,
  /// `Format => 'int32u'` — 4-byte big-endian unsigned.
  Int32u,
  /// `Format => 'int64s'` — 8-byte big-endian signed.
  Int64s,
  /// `Format => 'rational64s'` — int32s/int32s rational.
  Rational64s,
  /// `Format => 'string'` — Latin-1 string, NUL-trimmed.
  AsciiString,
  /// `Type => 'UTF-16'` — UTF-16BE string (MXF.pm:2483-2484).
  Utf16,
  /// `Type => 'Boolean'` — `"\0"` ⇒ `False`, else `True` (MXF.pm:2508-2509).
  Boolean,
  /// `Type => 'Timestamp'` — 2-byte year + 6 single-byte fields
  /// (MXF.pm:2493-2505).
  Timestamp,
  /// `Type => 'VersionType'` — single bytes dot-joined (MXF.pm:2491-2492).
  VersionType,
  /// `Type => 'ProductVersion'` — five `int16u` (MXF.pm:2485-2490).
  ProductVersion,
  /// `Type => 'UL'` — 16-byte universal label, GUID-reversal aware
  /// (MXF.pm:2549-2556).
  Ul,
  /// `Type => 'GUID'`/`AUID`/`UUID` — 16-byte dashed-hex GUID
  /// (MXF.pm:2546-2556).
  Guid,
  /// `Type => 'Label'` — 16-byte label (same render as GUID for non-UL).
  Label,
  /// `Type => 'PackageID'`/`UMID` — 32-byte identifier (MXF.pm:2541-2545).
  PackageId,
  /// `Type => 'StrongReference'`/`WeakReference` — 16-byte object reference.
  StrongReference,
  /// `Type => 'WeakReference'` — 16-byte UL-style object reference.
  WeakReference,
  /// `Type => 'StrongReferenceArray'`/`Batch` — count/size + GUID entries.
  StrongReferenceArray,
  /// `Type => 'StrongReferenceBatch'` — count/size + GUID entries.
  StrongReferenceBatch,
  /// `Type => 'BatchOfUL'` — count/size + UL entries (MXF.pm:2537-2538).
  BatchOfUl,
  /// `Type => 'Position'`/`Length` — 64-bit (MXF.pm:2506-2507).
  Length,
  /// `Type => 'Node'` / `Unknown => 1` with no decoded format — emitted as
  /// the ExifTool binary-data placeholder (the `Binary` flag is auto-set,
  /// MXF.pm:2653-2655).
  Binary,
}

/// One entry in `%MXF::Main`: a global UL → `(Name, Kind, …)` descriptor.
#[derive(Debug, Clone, Copy)]
struct TagDef {
  /// The global UL in dotted notation (the `%MXF::Main` hash key).
  ul: &'static str,
  /// `Name => '…'`.
  name: &'static str,
  /// Decode + conversion semantics.
  kind: Kind,
  /// `Unknown => 1` (MXF.pm) — an EXPLICIT visibility flag (NOT inferred
  /// from `kind`). An `Unknown` row's value is decoded for object-tree
  /// book-keeping (InstanceUID, strong-reference children) but the tag is
  /// NOT emitted in the bundled default `-j`/`-n` output: MXF.pm:2653/2899
  /// auto-sets its `Binary` flag, and binary tags need `-b` to extract. See
  /// [`emit_tag_default`].
  unknown: bool,
  /// `IsDuration => 1` — divide by the owning track's `EditRate` and run
  /// `ConvertDuration` (MXF.pm:96-100).
  is_duration: bool,
  /// `Name =~ /TrackID$/` — drives the `Track<N>` group attribution
  /// (MXF.pm:2679-2684).
  is_track_id: bool,
}

impl TagDef {
  /// A visible `Format`-based scalar row (`Format => '…'`, no `Unknown`).
  const fn fmt(ul: &'static str, name: &'static str, kind: Kind) -> Self {
    Self {
      ul,
      name,
      kind,
      unknown: false,
      is_duration: false,
      is_track_id: false,
    }
  }
  /// A visible `%duration`-flagged row (`Format`/`Type` + `IsDuration => 1`).
  const fn duration(ul: &'static str, name: &'static str, kind: Kind) -> Self {
    Self {
      ul,
      name,
      kind,
      unknown: false,
      is_duration: true,
      is_track_id: false,
    }
  }
  /// An `Unknown => 1` row — decoded for object-tree book-keeping but NOT
  /// emitted as a visible tag (MXF.pm `Binary`-flag suppression).
  const fn unknown(ul: &'static str, name: &'static str, kind: Kind) -> Self {
    Self {
      ul,
      name,
      kind,
      unknown: true,
      is_duration: false,
      is_track_id: false,
    }
  }
}

/// The MXF tag table — a subset of `%Image::ExifTool::MXF::Main`
/// (MXF.pm:117-2416). The full `.pm` table has ~1650 rows. Two DISTINCT
/// coverage classes live here:
///
/// 1. VISIBLE leaf tags — a documented PARTIAL: every row the conformance
///    fixtures exercise (each annotated with its MXF.pm line). Any other
///    leaf UL is emitted as the auto-generated `MXF_<hex>` binary-data tag
///    (MXF.pm:2903-2911) only under `-U` — faithful to bundled, which does
///    NOT emit unknown-format tags in the default output.
///
/// 2. HIDDEN structural-reference edges — COMPLETE: EVERY `StrongReference*`
///    row in `%MXF::Main` is present (see the dedicated section below), so
///    the `@strongRef` object graph is walked exactly as Perl walks it
///    (MXF.pm:2638/2770). These rows are all `Unknown => 1` and emit NO
///    visible tag (`emit_tag_default`); they exist purely so `SetGroups`
///    visits every descriptor/track subtree and attributes its tags to the
///    correct `Track<N>` group. Omitting any one of them would silently
///    drop a subtree from the traversal (Codex R1/F1).
const TAG_TABLE: &[TagDef] = &[
  // -- Identifiers (MXF.pm:182-183) ---------------------------------------
  // InstanceUID/PackageID are `Unknown => 1` — decoded for object-tree
  // book-keeping (InstanceUID is the per-object key) but NOT emitted as
  // visible tags (the auto-`Binary` flag suppresses them in the bundled
  // default output).
  TagDef::unknown(
    "060e2b34.0101.0101.01011502.00000000",
    "InstanceUID",
    Kind::Guid,
  ),
  TagDef::unknown(
    "060e2b34.0101.0101.01011510.00000000",
    "PackageID",
    Kind::PackageId,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010106.01000000",
    "LinkedPackageID",
    Kind::PackageId,
  ),
  // -- Timecode / timebase (MXF.pm) ---------------------------------------
  TagDef::fmt(
    "060e2b34.0101.0101.04040101.05000000",
    "DropFrame",
    Kind::Boolean,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.04040101.02060000",
    "RoundedTimecodeTimebase",
    Kind::Int16u,
  ),
  // -- Sample / essence rates ---------------------------------------------
  TagDef::fmt(
    "060e2b34.0101.0101.04060101.00000000",
    "SampleRate",
    Kind::Rational64s,
  ),
  TagDef::duration(
    "060e2b34.0101.0101.04060102.00000000",
    "EssenceLength",
    Kind::Length,
  ),
  // -- Track structural ----------------------------------------------------
  TagDef::fmt(
    "060e2b34.0101.0102.01040103.00000000",
    "TrackNumber",
    Kind::Int32u,
  ),
  TagDef {
    ul: "060e2b34.0101.0102.01070101.00000000",
    name: "TrackID",
    kind: Kind::Int32u,
    unknown: false,
    is_duration: false,
    is_track_id: true,
  },
  TagDef::fmt(
    "060e2b34.0101.0102.01070102.01000000",
    "TrackName",
    Kind::Utf16,
  ),
  // `LinkedTrackID` ends in `TrackID`, so MXF.pm:2679's `/TrackID$/` regex
  // matches it — the WaveAudioDescriptor's `LinkedTrackID` therefore sets
  // the descriptor object's `TrackID`, which `SetGroups` propagates so the
  // descriptor's tags land in the linked `Track<N>` group.
  TagDef {
    ul: "060e2b34.0101.0105.06010103.05000000",
    name: "LinkedTrackID",
    kind: Kind::Int32u,
    unknown: false,
    is_duration: false,
    is_track_id: true,
  },
  TagDef::fmt(
    "060e2b34.0101.0102.05300405.00000000",
    "EditRate",
    Kind::Rational64s,
  ),
  TagDef::duration(
    "060e2b34.0101.0102.07020103.01030000",
    "Origin",
    Kind::Int64s,
  ),
  TagDef::duration(
    "060e2b34.0101.0102.07020103.01050000",
    "StartTimecode",
    Kind::Int64s,
  ),
  TagDef::duration(
    "060e2b34.0101.0102.07020201.01030000",
    "Duration",
    Kind::Length,
  ),
  // -- Component data definition (WeakReference + %componentDataDef) -------
  // NOT `Unknown => 1` (it has a real `%componentDataDef` PrintConv) ⇒ a
  // visible tag. `emit_one` applies the UL→label PrintConv by tag name.
  TagDef::fmt(
    "060e2b34.0101.0102.04070100.00000000",
    "ComponentDataDefinition",
    Kind::WeakReference,
  ),
  // -- Identification (Application*/Toolkit) (MXF.pm) ---------------------
  TagDef::fmt(
    "060e2b34.0101.0102.05200701.02010000",
    "ApplicationSupplierName",
    Kind::Utf16,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.05200701.03010000",
    "ApplicationName",
    Kind::Utf16,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.05200701.05010000",
    "ApplicationVersionString",
    Kind::Utf16,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.05200701.06010000",
    "ApplicationPlatform",
    Kind::Utf16,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.05200701.0a000000",
    "ToolkitVersion",
    Kind::ProductVersion,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.03010201.05000000",
    "SDKVersion",
    Kind::VersionType,
  ),
  // `GenerationID`/`LinkedGenerationID` are `Type => 'AUID', Unknown => 1`.
  TagDef::unknown(
    "060e2b34.0101.0102.05200701.01000000",
    "GenerationID",
    Kind::Guid,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.05200701.08000000",
    "LinkedGenerationID",
    Kind::Guid,
  ),
  // -- Timestamps (MXF.pm) -------------------------------------------------
  TagDef::fmt(
    "060e2b34.0101.0102.07020110.01030000",
    "CreateDate",
    Kind::Timestamp,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.07020110.02030000",
    "ModifyDate",
    Kind::Timestamp,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.07020110.02040000",
    "ContainerLastModifyDate",
    Kind::Timestamp,
  ),
  TagDef::fmt(
    "060e2b34.0101.0102.07020110.02050000",
    "PackageLastModifyDate",
    Kind::Timestamp,
  ),
  // -- Reference arrays / batches — every row is `Unknown => 1` in
  //    `%MXF::Main`: decoded for the object-tree strong-reference graph
  //    (drives `SetGroups`) but NOT emitted as visible tags. -------------
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.01020000",
    "EssenceContainerFormat",
    Kind::WeakReference,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02010000",
    "ContentStorage",
    Kind::StrongReference,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02030000",
    "EssenceDescription",
    Kind::StrongReference,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02040000",
    "Sequence",
    Kind::StrongReference,
  ),
  TagDef::unknown(
    "060e2b34.0101.0104.06010104.01080000",
    "PrimaryPackage",
    Kind::WeakReference,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05010000",
    "Packages",
    Kind::StrongReferenceBatch,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05020000",
    "EssenceData",
    Kind::StrongReferenceBatch,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06040000",
    "IdentificationList",
    Kind::StrongReferenceArray,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06050000",
    "Tracks",
    Kind::StrongReferenceArray,
  ),
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06090000",
    "ComponentsInSequence",
    Kind::StrongReferenceArray,
  ),
  TagDef::unknown(
    "060e2b34.0101.0105.01020203.00000000",
    "OperationalPatternUL",
    Kind::Ul,
  ),
  TagDef::unknown(
    "060e2b34.0101.0105.01020210.02010000",
    "EssenceContainers",
    Kind::BatchOfUl,
  ),
  TagDef::unknown(
    "060e2b34.0101.0105.01020210.02020000",
    "DescriptiveMetadataSchemes",
    Kind::BatchOfUl,
  ),
  // -- Essence / audio descriptor (MXF.pm) --------------------------------
  TagDef::fmt(
    "060e2b34.0101.0104.01030404.00000000",
    "EssenceStreamID",
    Kind::Int32u,
  ),
  TagDef::fmt(
    "060e2b34.0101.0104.04020301.04000000",
    "LockedIndicator",
    Kind::Boolean,
  ),
  TagDef::fmt(
    "060e2b34.0101.0104.04020303.04000000",
    "BitsPerAudioSample",
    Kind::Int32u,
  ),
  TagDef::fmt(
    "060e2b34.0101.0105.04020101.04000000",
    "ChannelCount",
    Kind::Int32u,
  ),
  TagDef::fmt(
    "060e2b34.0101.0105.04020301.01010000",
    "AudioSampleRate",
    Kind::Rational64s,
  ),
  TagDef::fmt(
    "060e2b34.0101.0105.04020302.01000000",
    "BlockAlign",
    Kind::Int16u,
  ),
  TagDef::fmt(
    "060e2b34.0101.0105.04020303.05000000",
    "AverageBytesPerSecond",
    Kind::Int32u,
  ),
  // -- Hidden structural-reference edges (Codex R1/F1) ---------------------
  //
  // EVERY remaining `Type => 'StrongReference'/'StrongReferenceArray'/
  // 'StrongReferenceBatch'` row in `%MXF::Main` that is NOT already listed
  // above. In MXF.pm, `ProcessLocalSet` collects a row's decoded value into
  // `@strongRef` whenever its `Type =~ /^StrongReference/` (MXF.pm:2638) —
  // and that happens INSIDE the `if ($tag and $$tagTablePtr{$tag})` branch
  // (MXF.pm:2625/2634), so the row MUST be present in the table for its
  // children to enter the `SetGroups` object-graph traversal (MXF.pm:2770).
  //
  // These are the HIDDEN edges of the graph: every row is `Unknown => 1`, so
  // ExifTool auto-sets its `Binary` flag (MXF.pm:2653-2655) and emits NO
  // visible tag without `-U`/`-b` — `emit_tag_default` keeps them suppressed.
  // We decode them ONLY to walk the tree faithfully. Without these rows a
  // normal multi-essence file (`MultipleDescriptor -> FileDescriptors`, or a
  // `MaterialPackage -> PackageTracks`) would never visit its descriptor /
  // track children during `set_groups`, leaving their tags under `MXF`
  // instead of the owning `Track<N>` and skewing duration/EditRate
  // propagation through that subtree.
  //
  // WeakReference rows are intentionally EXCLUDED: `/^StrongReference/` does
  // not match `WeakReference`, so the Perl never pushes them into `@strongRef`
  // (they resolve a class/definition by ID, not an owned child object).
  // MXF.pm:1023
  TagDef::unknown(
    "060e2b34.0101.0102.03010210.03000000",
    "PackageKLVData",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1024
  TagDef::unknown(
    "060e2b34.0101.0102.03010210.04000000",
    "ComponentKLVData",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1030
  TagDef::unknown(
    "060e2b34.0101.0102.03020102.0c000000",
    "PackageUserComments",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1153
  TagDef::unknown(
    "060e2b34.0101.0102.0520090d.00000000",
    "Plug-InLocatorSet",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1197
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02020000",
    "Dictionary",
    Kind::StrongReference,
  ),
  // MXF.pm:1200
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02050000",
    "TransitionEffect",
    Kind::StrongReference,
  ),
  // MXF.pm:1201
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02060000",
    "EffectRendering",
    Kind::StrongReference,
  ),
  // MXF.pm:1202
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02070000",
    "InputSegment",
    Kind::StrongReference,
  ),
  // MXF.pm:1203
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02080000",
    "StillFrame",
    Kind::StrongReference,
  ),
  // MXF.pm:1204
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.02090000",
    "Selected",
    Kind::StrongReference,
  ),
  // MXF.pm:1205
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.020a0000",
    "Annotation",
    Kind::StrongReference,
  ),
  // MXF.pm:1206
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.020b0000",
    "ManufacturerInformationObject",
    Kind::StrongReference,
  ),
  // MXF.pm:1215
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05030000",
    "OperationDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1216
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05040000",
    "ParameterDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1217
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05050000",
    "DataDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1218
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05060000",
    "Plug-InDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1219
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05070000",
    "CodecDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1220
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05080000",
    "ContainerDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1221
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.05090000",
    "InterpolationDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1223
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06010000",
    "AvailableRepresentations",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1224
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06020000",
    "InputSegments",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1225
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06030000",
    "EssenceLocators",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1228
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06060000",
    "ControlPointList",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1229
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06070000",
    "PackageTracks",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1230
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.06080000",
    "Alternates",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1232
  TagDef::unknown(
    "060e2b34.0101.0102.06010104.060a0000",
    "Parameters",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1237
  TagDef::unknown(
    "060e2b34.0101.0102.06010107.02000000",
    "Properties",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1242
  TagDef::unknown(
    "060e2b34.0101.0102.06010107.07000000",
    "ClassDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1243
  TagDef::unknown(
    "060e2b34.0101.0102.06010107.08000000",
    "TypeDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1649
  TagDef::unknown(
    "060e2b34.0101.0104.06010104.060b0000",
    "FileDescriptors",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1866
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.020c0000",
    "DescriptiveMetadataFramework",
    Kind::StrongReference,
  ),
  // MXF.pm:1867
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02400500",
    "GroupSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1868
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02401c00",
    "BankDetailsSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1869
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02401d00",
    "ImageFormatSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1870
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02402000",
    "ProcessingSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1871
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02402100",
    "ProjectSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1872
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02402200",
    "ContactsListSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1874
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02402301",
    "AnnotationCueWordsSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1875
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.02402302",
    "ShotCueWordsSet",
    Kind::StrongReference,
  ),
  // MXF.pm:1885
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400400",
    "TitlesSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1886
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400500",
    "GroupSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1887
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400600",
    "IdentificationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1888
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400700",
    "EpisodicItemSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1889
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400800",
    "BrandingSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1890
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400900",
    "EventSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1891
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400a00",
    "PublicationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1892
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400b00",
    "AwardSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1893
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400c00",
    "CaptionDescriptionSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1894
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400d00",
    "AnnotationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1896
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400e01",
    "ProductionSettingPeriodSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1897
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400e02",
    "SceneSettingPeriodSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1898
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05400f00",
    "ScriptingSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1899
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401000",
    "ClassificationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1901
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401101",
    "SceneShotSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1902
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401102",
    "ClipShotSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1903
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401200",
    "KeyPointSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1904
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401300",
    "ShotParticipantRoleSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1905
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401400",
    "ShotPersonSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1906
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401500",
    "OrganizationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1907
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401600",
    "ShotLocationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1908
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401700",
    "AddressSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1909
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401800",
    "CommunicationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1910
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401900",
    "ContractSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1911
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401a00",
    "RightsSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1912
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401b00",
    "PaymentsSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1913
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401e00",
    "DeviceParametersSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1915
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401f01",
    "ClassificationNameValueSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1916
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401f02",
    "ContactNameValueSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1917
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.05401f03",
    "DeviceParameterNameValueSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:1918
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.060c0000",
    "MetadataServerLocators",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1919
  TagDef::unknown(
    "060e2b34.0101.0105.06010104.060d0000",
    "RelatedMaterialLocators",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1959
  TagDef::unknown(
    "060e2b34.0101.0107.03010210.07000000",
    "PackageAttributes",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1960
  TagDef::unknown(
    "060e2b34.0101.0107.03010210.08000000",
    "ComponentAttributes",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:1980
  TagDef::unknown(
    "060e2b34.0101.0107.03020102.16000000",
    "ComponentUserComments",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2001
  TagDef::unknown(
    "060e2b34.0101.0107.06010104.050a0000",
    "KLVDataDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:2002
  TagDef::unknown(
    "060e2b34.0101.0107.06010104.050b0000",
    "TaggedValueDefinitions",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:2003
  TagDef::unknown(
    "060e2b34.0101.0107.06010104.05401f04",
    "AddressNameValueSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:2065
  TagDef::unknown(
    "060e2b34.0101.0108.06010104.05400d01",
    "EventAnnotationSets",
    Kind::StrongReferenceBatch,
  ),
  // MXF.pm:2066
  TagDef::unknown(
    "060e2b34.0101.0108.06010104.060e0000",
    "ScriptingLocators",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2067
  TagDef::unknown(
    "060e2b34.0101.0108.06010104.060f0000",
    "UnknownBWFChunks",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2112
  TagDef::unknown(
    "060e2b34.0101.0109.06010104.020d0000",
    "CryptographicContextObject",
    Kind::StrongReference,
  ),
  // MXF.pm:2113
  TagDef::unknown(
    "060e2b34.0101.0109.06010104.06100000",
    "Sub-descriptors",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2173
  TagDef::unknown(
    "060e2b34.0101.010a.06010107.16000000",
    "RootMetaDictionary",
    Kind::StrongReference,
  ),
  // MXF.pm:2174
  TagDef::unknown(
    "060e2b34.0101.010a.06010107.17000000",
    "RootPreface",
    Kind::StrongReference,
  ),
  // MXF.pm:2241
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.020e0000",
    "ApplicationPlug-InBatch",
    Kind::StrongReference,
  ),
  // MXF.pm:2242
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.020f0000",
    "PackageMarker",
    Kind::StrongReference,
  ),
  // MXF.pm:2243
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.02100000",
    "PackageTimelineMarkerRef",
    Kind::StrongReference,
  ),
  // MXF.pm:2244
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.02110000",
    "RegisterAdministrationObject",
    Kind::StrongReference,
  ),
  // MXF.pm:2245
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.02120000",
    "RegisterEntryAdministrationObject",
    Kind::StrongReference,
  ),
  // MXF.pm:2247
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.06110000",
    "RegisterEntryArray",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2248
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.06120000",
    "RegisterAdministrationArray",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2249
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.06130000",
    "ApplicationInformationArray",
    Kind::StrongReferenceArray,
  ),
  // MXF.pm:2250
  TagDef::unknown(
    "060e2b34.0101.010c.06010104.06140000",
    "RegisterChildEntryArray",
    Kind::StrongReferenceArray,
  ),
];

/// UL → [`TAG_TABLE`] index, sorted ascending by UL for `binary_search`.
///
/// [`TAG_TABLE`] itself stays in faithful Perl-source section order (its
/// per-section provenance comments — notably the "every `StrongReference*`
/// row is present" invariant — would be destroyed by sorting it), so this
/// companion index provides the O(log n) key order instead. The crate is
/// `no_std`, so a runtime-built `OnceLock` index is unavailable; this const
/// array is the `no_std`-compatible equivalent.
///
/// The second field is the row's position in [`TAG_TABLE`]. The
/// `tag_index_round_trips` test re-derives this mapping from [`TAG_TABLE`]
/// and fails if the array drifts (e.g. a row is inserted without updating
/// the index), so the indices can never silently go stale.
const TAG_INDEX: &[(&str, u16)] = &[
  ("060e2b34.0101.0101.01011502.00000000", 0),
  ("060e2b34.0101.0101.01011510.00000000", 1),
  ("060e2b34.0101.0101.04040101.05000000", 3),
  ("060e2b34.0101.0101.04060101.00000000", 5),
  ("060e2b34.0101.0101.04060102.00000000", 6),
  ("060e2b34.0101.0102.01040103.00000000", 7),
  ("060e2b34.0101.0102.01070101.00000000", 8),
  ("060e2b34.0101.0102.01070102.01000000", 9),
  ("060e2b34.0101.0102.03010201.05000000", 21),
  ("060e2b34.0101.0102.03010210.03000000", 48),
  ("060e2b34.0101.0102.03010210.04000000", 49),
  ("060e2b34.0101.0102.03020102.0c000000", 50),
  ("060e2b34.0101.0102.04040101.02060000", 4),
  ("060e2b34.0101.0102.04070100.00000000", 15),
  ("060e2b34.0101.0102.05200701.01000000", 22),
  ("060e2b34.0101.0102.05200701.02010000", 16),
  ("060e2b34.0101.0102.05200701.03010000", 17),
  ("060e2b34.0101.0102.05200701.05010000", 18),
  ("060e2b34.0101.0102.05200701.06010000", 19),
  ("060e2b34.0101.0102.05200701.08000000", 23),
  ("060e2b34.0101.0102.05200701.0a000000", 20),
  ("060e2b34.0101.0102.0520090d.00000000", 51),
  ("060e2b34.0101.0102.05300405.00000000", 11),
  ("060e2b34.0101.0102.06010104.01020000", 28),
  ("060e2b34.0101.0102.06010104.02010000", 29),
  ("060e2b34.0101.0102.06010104.02020000", 52),
  ("060e2b34.0101.0102.06010104.02030000", 30),
  ("060e2b34.0101.0102.06010104.02040000", 31),
  ("060e2b34.0101.0102.06010104.02050000", 53),
  ("060e2b34.0101.0102.06010104.02060000", 54),
  ("060e2b34.0101.0102.06010104.02070000", 55),
  ("060e2b34.0101.0102.06010104.02080000", 56),
  ("060e2b34.0101.0102.06010104.02090000", 57),
  ("060e2b34.0101.0102.06010104.020a0000", 58),
  ("060e2b34.0101.0102.06010104.020b0000", 59),
  ("060e2b34.0101.0102.06010104.05010000", 33),
  ("060e2b34.0101.0102.06010104.05020000", 34),
  ("060e2b34.0101.0102.06010104.05030000", 60),
  ("060e2b34.0101.0102.06010104.05040000", 61),
  ("060e2b34.0101.0102.06010104.05050000", 62),
  ("060e2b34.0101.0102.06010104.05060000", 63),
  ("060e2b34.0101.0102.06010104.05070000", 64),
  ("060e2b34.0101.0102.06010104.05080000", 65),
  ("060e2b34.0101.0102.06010104.05090000", 66),
  ("060e2b34.0101.0102.06010104.06010000", 67),
  ("060e2b34.0101.0102.06010104.06020000", 68),
  ("060e2b34.0101.0102.06010104.06030000", 69),
  ("060e2b34.0101.0102.06010104.06040000", 35),
  ("060e2b34.0101.0102.06010104.06050000", 36),
  ("060e2b34.0101.0102.06010104.06060000", 70),
  ("060e2b34.0101.0102.06010104.06070000", 71),
  ("060e2b34.0101.0102.06010104.06080000", 72),
  ("060e2b34.0101.0102.06010104.06090000", 37),
  ("060e2b34.0101.0102.06010104.060a0000", 73),
  ("060e2b34.0101.0102.06010106.01000000", 2),
  ("060e2b34.0101.0102.06010107.02000000", 74),
  ("060e2b34.0101.0102.06010107.07000000", 75),
  ("060e2b34.0101.0102.06010107.08000000", 76),
  ("060e2b34.0101.0102.07020103.01030000", 12),
  ("060e2b34.0101.0102.07020103.01050000", 13),
  ("060e2b34.0101.0102.07020110.01030000", 24),
  ("060e2b34.0101.0102.07020110.02030000", 25),
  ("060e2b34.0101.0102.07020110.02040000", 26),
  ("060e2b34.0101.0102.07020110.02050000", 27),
  ("060e2b34.0101.0102.07020201.01030000", 14),
  ("060e2b34.0101.0104.01030404.00000000", 41),
  ("060e2b34.0101.0104.04020301.04000000", 42),
  ("060e2b34.0101.0104.04020303.04000000", 43),
  ("060e2b34.0101.0104.06010104.01080000", 32),
  ("060e2b34.0101.0104.06010104.060b0000", 77),
  ("060e2b34.0101.0105.01020203.00000000", 38),
  ("060e2b34.0101.0105.01020210.02010000", 39),
  ("060e2b34.0101.0105.01020210.02020000", 40),
  ("060e2b34.0101.0105.04020101.04000000", 44),
  ("060e2b34.0101.0105.04020301.01010000", 45),
  ("060e2b34.0101.0105.04020302.01000000", 46),
  ("060e2b34.0101.0105.04020303.05000000", 47),
  ("060e2b34.0101.0105.06010103.05000000", 10),
  ("060e2b34.0101.0105.06010104.020c0000", 78),
  ("060e2b34.0101.0105.06010104.02400500", 79),
  ("060e2b34.0101.0105.06010104.02401c00", 80),
  ("060e2b34.0101.0105.06010104.02401d00", 81),
  ("060e2b34.0101.0105.06010104.02402000", 82),
  ("060e2b34.0101.0105.06010104.02402100", 83),
  ("060e2b34.0101.0105.06010104.02402200", 84),
  ("060e2b34.0101.0105.06010104.02402301", 85),
  ("060e2b34.0101.0105.06010104.02402302", 86),
  ("060e2b34.0101.0105.06010104.05400400", 87),
  ("060e2b34.0101.0105.06010104.05400500", 88),
  ("060e2b34.0101.0105.06010104.05400600", 89),
  ("060e2b34.0101.0105.06010104.05400700", 90),
  ("060e2b34.0101.0105.06010104.05400800", 91),
  ("060e2b34.0101.0105.06010104.05400900", 92),
  ("060e2b34.0101.0105.06010104.05400a00", 93),
  ("060e2b34.0101.0105.06010104.05400b00", 94),
  ("060e2b34.0101.0105.06010104.05400c00", 95),
  ("060e2b34.0101.0105.06010104.05400d00", 96),
  ("060e2b34.0101.0105.06010104.05400e01", 97),
  ("060e2b34.0101.0105.06010104.05400e02", 98),
  ("060e2b34.0101.0105.06010104.05400f00", 99),
  ("060e2b34.0101.0105.06010104.05401000", 100),
  ("060e2b34.0101.0105.06010104.05401101", 101),
  ("060e2b34.0101.0105.06010104.05401102", 102),
  ("060e2b34.0101.0105.06010104.05401200", 103),
  ("060e2b34.0101.0105.06010104.05401300", 104),
  ("060e2b34.0101.0105.06010104.05401400", 105),
  ("060e2b34.0101.0105.06010104.05401500", 106),
  ("060e2b34.0101.0105.06010104.05401600", 107),
  ("060e2b34.0101.0105.06010104.05401700", 108),
  ("060e2b34.0101.0105.06010104.05401800", 109),
  ("060e2b34.0101.0105.06010104.05401900", 110),
  ("060e2b34.0101.0105.06010104.05401a00", 111),
  ("060e2b34.0101.0105.06010104.05401b00", 112),
  ("060e2b34.0101.0105.06010104.05401e00", 113),
  ("060e2b34.0101.0105.06010104.05401f01", 114),
  ("060e2b34.0101.0105.06010104.05401f02", 115),
  ("060e2b34.0101.0105.06010104.05401f03", 116),
  ("060e2b34.0101.0105.06010104.060c0000", 117),
  ("060e2b34.0101.0105.06010104.060d0000", 118),
  ("060e2b34.0101.0107.03010210.07000000", 119),
  ("060e2b34.0101.0107.03010210.08000000", 120),
  ("060e2b34.0101.0107.03020102.16000000", 121),
  ("060e2b34.0101.0107.06010104.050a0000", 122),
  ("060e2b34.0101.0107.06010104.050b0000", 123),
  ("060e2b34.0101.0107.06010104.05401f04", 124),
  ("060e2b34.0101.0108.06010104.05400d01", 125),
  ("060e2b34.0101.0108.06010104.060e0000", 126),
  ("060e2b34.0101.0108.06010104.060f0000", 127),
  ("060e2b34.0101.0109.06010104.020d0000", 128),
  ("060e2b34.0101.0109.06010104.06100000", 129),
  ("060e2b34.0101.010a.06010107.16000000", 130),
  ("060e2b34.0101.010a.06010107.17000000", 131),
  ("060e2b34.0101.010c.06010104.020e0000", 132),
  ("060e2b34.0101.010c.06010104.020f0000", 133),
  ("060e2b34.0101.010c.06010104.02100000", 134),
  ("060e2b34.0101.010c.06010104.02110000", 135),
  ("060e2b34.0101.010c.06010104.02120000", 136),
  ("060e2b34.0101.010c.06010104.06110000", 137),
  ("060e2b34.0101.010c.06010104.06120000", 138),
  ("060e2b34.0101.010c.06010104.06130000", 139),
  ("060e2b34.0101.010c.06010104.06140000", 140),
];

/// Look up a global UL in [`TAG_TABLE`] via binary search over [`TAG_INDEX`].
fn tag_def(ul: &str) -> Option<&'static TagDef> {
  let i = TAG_INDEX.binary_search_by(|&(k, _)| k.cmp(ul)).ok()?;
  // `binary_search` yields an in-bounds `TAG_INDEX` slot on `Ok`; the row
  // index it stores is `< TAG_TABLE.len()` (guarded by `tag_index_round_trips`),
  // so both `.get`s are the checked, provably-`Some` form.
  let &(_, row) = TAG_INDEX.get(i)?;
  let def = TAG_TABLE.get(row as usize)?;
  // The index slot must point at the row that actually holds this UL — cheap
  // in debug, compiled out in release. Also keeps `TagDef::ul` a live read.
  debug_assert_eq!(def.ul, ul, "TAG_INDEX row {row} mismatched UL");
  Some(def)
}

/// `%componentDataDef` PrintConv (MXF.pm:103-113) — map a decoded UL string
/// to its essence-track label. Returns `None` for an unrecognized UL
/// (bundled's `PrintConv` hash leaves the raw value through).
fn component_data_def_label(ul: &str) -> Option<&'static str> {
  Some(match ul {
    "060e2b34.0401.0101.01030201.01000000" => "SMPTE 12M Timecode Track",
    "060e2b34.0401.0101.01030201.02000000" => "SMPTE 12M Timecode Track with active user bits",
    "060e2b34.0401.0101.01030201.03000000" => "SMPTE 309M Timecode Track",
    "060e2b34.0401.0101.01030201.10000000" => "Descriptive Metadata Track",
    "060e2b34.0401.0101.01030202.01000000" => "Picture Essence Track",
    "060e2b34.0401.0101.01030202.02000000" => "Sound Essence Track",
    "060e2b34.0401.0101.01030202.03000000" => "Data Essence Track",
    _ => return None,
  })
}

// ===========================================================================
// §4. Top-level partition-pack / structural UL classification
// ===========================================================================

/// What a top-level KLV key denotes (MXF.pm:2317-2371). Distinguishes the
/// header partition packs, the Primer, the header-metadata local sets, and
/// the index/random-index segments the bundled code skips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
enum TopLevel {
  /// One of the four header partition packs (`%header` SubDirectory,
  /// MXF.pm:2317-2320). The carried `&str` is the header type name (used to
  /// detect `ClosedCompleteHeader` for the early-stop, MXF.pm:2845).
  Header(&'static str),
  /// The Primer pack (MXF.pm:2328) — builds the local-id → UL lookup.
  Primer,
  /// A header-metadata local set (`%localSet` SubDirectory). The carried
  /// `&str` is the set's object-class name (`Preface`, `Track`, …) — it
  /// becomes the object's `DIR_NAME` (MXF.pm:2702 `$$objInfo{Name}`).
  LocalSet(&'static str),
  /// A body / index / footer partition the bundled code walks past without
  /// emitting visible tags (`Unknown => 1`, MXF.pm:2321-2332/2369-2370).
  SkipUnknown,
}

/// Classify a top-level KLV key. Returns `None` for a UL absent from the
/// FULL `%MXF::Main` structural table below — only then does the caller try
/// the `0d`/`0f` auto-generated-set heuristic (MXF.pm:2872-2879, gated on
/// `not $tagInfo`).
///
/// This is the COMPLETE structural-UL classification (every `%header`,
/// `%localSet`, and structural `Unknown => 1` row of `%MXF::Main`,
/// MXF.pm:2317-2415). It must be exhaustive so the auto-generated-set
/// heuristic fires ONLY for genuinely-unknown ULs — a `%localSet` row that
/// is intentionally `Unknown => 1` (e.g. `SourceClip`, MXF.pm:2336-2339, or
/// the index-table segments, MXF.pm:2368-2370) MUST be classified
/// [`TopLevel::SkipUnknown`] here, NOT parsed by the heuristic. (The bundled
/// fixture exercises this: it carries `SourceClip` records — see
/// MXF.pm:2336-2339, "isn't decoded because it has a Duration tag which
/// gets confused with the other Duration tags".)
fn classify_top_level(ul: &str) -> Option<TopLevel> {
  Some(match ul {
    // -- Header partition packs (%header) — MXF.pm:2317-2320 -------------
    "060e2b34.0205.0101.0d010201.01020100" => TopLevel::Header("OpenHeader"),
    "060e2b34.0205.0101.0d010201.01020200" => TopLevel::Header("ClosedHeader"),
    "060e2b34.0205.0101.0d010201.01020300" => TopLevel::Header("OpenCompleteHeader"),
    "060e2b34.0205.0101.0d010201.01020400" => TopLevel::Header("ClosedCompleteHeader"),
    // -- Primer — MXF.pm:2328 --------------------------------------------
    "060e2b34.0205.0101.0d010201.01050100" => TopLevel::Primer,
    // -- Body / index / footer partition packs (Unknown => 1) +
    //    RandomIndex / PartitionMetadata — MXF.pm:2321-2332 --------------
    "060e2b34.0205.0101.0d010201.01030100"
    | "060e2b34.0205.0101.0d010201.01030200"
    | "060e2b34.0205.0101.0d010201.01030300"
    | "060e2b34.0205.0101.0d010201.01030400"
    | "060e2b34.0205.0101.0d010201.01040200"
    | "060e2b34.0205.0101.0d010201.01040400"
    | "060e2b34.0205.0101.0d010201.01110000"
    | "060e2b34.0205.0101.0d010201.01110100"
    | "060e2b34.0206.0101.0d010200.00000000" => TopLevel::SkipUnknown,
    // -- Header-metadata local sets (%localSet) — MXF.pm:2334-2409 -------
    // Every `%localSet` row. Their bodies are decoded as local sets; tags
    // inside resolve through the Primer + the (fixture-scoped) tag table.
    "060e2b34.0253.0101.0d010101.01010200" => TopLevel::LocalSet("StructuralComponent"),
    "060e2b34.0253.0101.0d010101.01010f00" => TopLevel::LocalSet("SequenceSet"),
    "060e2b34.0253.0101.0d010101.01011400" => TopLevel::LocalSet("TimecodeComponent"),
    "060e2b34.0253.0101.0d010101.01011800" => TopLevel::LocalSet("ContentStorageSet"),
    "060e2b34.0253.0101.0d010101.01012300" => TopLevel::LocalSet("EssenceContainerDataSet"),
    "060e2b34.0253.0101.0d010101.01012500" => TopLevel::LocalSet("FileDescriptor"),
    "060e2b34.0253.0101.0d010101.01012700" => TopLevel::LocalSet("GenericPictureEssenceDescriptor"),
    "060e2b34.0253.0101.0d010101.01012800" => TopLevel::LocalSet("CDCIEssenceDescriptor"),
    "060e2b34.0253.0101.0d010101.01012900" => TopLevel::LocalSet("RGBAEssenceDescriptor"),
    "060e2b34.0253.0101.0d010101.01012f00" => TopLevel::LocalSet("Preface"),
    "060e2b34.0253.0101.0d010101.01013000" => TopLevel::LocalSet("Identification"),
    "060e2b34.0253.0101.0d010101.01013200" => TopLevel::LocalSet("NetworkLocator"),
    "060e2b34.0253.0101.0d010101.01013300" => TopLevel::LocalSet("TextLocator"),
    "060e2b34.0253.0101.0d010101.01013400" => TopLevel::LocalSet("GenericPackage"),
    "060e2b34.0253.0101.0d010101.01013600" => TopLevel::LocalSet("MaterialPackage"),
    "060e2b34.0253.0101.0d010101.01013700" => TopLevel::LocalSet("SourcePackage"),
    "060e2b34.0253.0101.0d010101.01013800" => TopLevel::LocalSet("GenericTrack"),
    "060e2b34.0253.0101.0d010101.01013900" => TopLevel::LocalSet("EventTrack"),
    "060e2b34.0253.0101.0d010101.01013a00" => TopLevel::LocalSet("StaticTrack"),
    "060e2b34.0253.0101.0d010101.01013b00" => TopLevel::LocalSet("Track"),
    "060e2b34.0253.0101.0d010101.01014100" => TopLevel::LocalSet("DMSegment"),
    "060e2b34.0253.0101.0d010101.01014200" => TopLevel::LocalSet("GenericSoundEssenceDescriptor"),
    "060e2b34.0253.0101.0d010101.01014300" => TopLevel::LocalSet("GenericDataEssenceDescriptor"),
    "060e2b34.0253.0101.0d010101.01014400" => TopLevel::LocalSet("MultipleDescriptor"),
    "060e2b34.0253.0101.0d010101.01014500" => TopLevel::LocalSet("DMSourceClip"),
    "060e2b34.0253.0101.0d010101.01014700" => TopLevel::LocalSet("AES3PCMDescriptor"),
    "060e2b34.0253.0101.0d010101.01014800" => TopLevel::LocalSet("WaveAudioDescriptor"),
    "060e2b34.0253.0101.0d010101.01015100" => TopLevel::LocalSet("MPEG2VideoDescriptor"),
    "060e2b34.0253.0101.0d010101.01015a00" => TopLevel::LocalSet("JPEG2000PictureSubDescriptor"),
    "060e2b34.0253.0101.0d010101.01015b00" => TopLevel::LocalSet("VBIDataDescriptor"),
    "060e2b34.0253.0101.0d010400.00000000" => TopLevel::LocalSet("DMSet"),
    "060e2b34.0253.0101.0d010401.00000000" => TopLevel::LocalSet("DMFramework"),
    // DMS1 local sets (MXF.pm:2374-2406).
    "060e2b34.0253.0101.0d010401.01010100" => TopLevel::LocalSet("ProductionFramework"),
    "060e2b34.0253.0101.0d010401.01010200" => TopLevel::LocalSet("ClipFramework"),
    "060e2b34.0253.0101.0d010401.01010300" => TopLevel::LocalSet("SceneFramework"),
    "060e2b34.0253.0101.0d010401.01100100" => TopLevel::LocalSet("Titles"),
    "060e2b34.0253.0101.0d010401.01110100" => TopLevel::LocalSet("Identification"),
    "060e2b34.0253.0101.0d010401.01120100" => TopLevel::LocalSet("GroupRelationship"),
    "060e2b34.0253.0101.0d010401.01130100" => TopLevel::LocalSet("Branding"),
    "060e2b34.0253.0101.0d010401.01140100" => TopLevel::LocalSet("Event"),
    "060e2b34.0253.0101.0d010401.01140200" => TopLevel::LocalSet("Publication"),
    "060e2b34.0253.0101.0d010401.01150100" => TopLevel::LocalSet("Award"),
    "060e2b34.0253.0101.0d010401.01160100" => TopLevel::LocalSet("CaptionDescription"),
    "060e2b34.0253.0101.0d010401.01170100" => TopLevel::LocalSet("Annotation"),
    "060e2b34.0253.0101.0d010401.01170200" => TopLevel::LocalSet("SettingPeriod"),
    "060e2b34.0253.0101.0d010401.01170300" => TopLevel::LocalSet("Scripting"),
    "060e2b34.0253.0101.0d010401.01170400" => TopLevel::LocalSet("Classification"),
    "060e2b34.0253.0101.0d010401.01170500" => TopLevel::LocalSet("Shot"),
    "060e2b34.0253.0101.0d010401.01170600" => TopLevel::LocalSet("KeyPoint"),
    "060e2b34.0253.0101.0d010401.01170800" => TopLevel::LocalSet("CueWords"),
    "060e2b34.0253.0101.0d010401.01180100" => TopLevel::LocalSet("Participant"),
    "060e2b34.0253.0101.0d010401.01190100" => TopLevel::LocalSet("ContactsList"),
    "060e2b34.0253.0101.0d010401.011a0200" => TopLevel::LocalSet("Person"),
    "060e2b34.0253.0101.0d010401.011a0300" => TopLevel::LocalSet("Organisation"),
    "060e2b34.0253.0101.0d010401.011a0400" => TopLevel::LocalSet("Location"),
    "060e2b34.0253.0101.0d010401.011b0100" => TopLevel::LocalSet("Address"),
    "060e2b34.0253.0101.0d010401.011b0200" => TopLevel::LocalSet("Communications"),
    "060e2b34.0253.0101.0d010401.011c0100" => TopLevel::LocalSet("Contract"),
    "060e2b34.0253.0101.0d010401.011c0200" => TopLevel::LocalSet("Rights"),
    "060e2b34.0253.0101.0d010401.011d0100" => TopLevel::LocalSet("PictureFormat"),
    "060e2b34.0253.0101.0d010401.011e0100" => TopLevel::LocalSet("DeviceParameters"),
    "060e2b34.0253.0101.0d010401.011f0100" => TopLevel::LocalSet("NameValue"),
    "060e2b34.0253.0101.0d010401.01200100" => TopLevel::LocalSet("Processing"),
    "060e2b34.0253.0101.0d010401.01200200" => TopLevel::LocalSet("Projects"),
    "060e2b34.0253.0101.0d010401.02010000" => TopLevel::LocalSet("CryptographicFramework"),
    "060e2b34.0253.0101.0d010401.02020000" => TopLevel::LocalSet("CryptographicContext"),
    // -- Structural rows that are `Unknown => 1` — bundled does NOT
    //    decode their bodies (MXF.pm:2336-2339, 2368-2371, 2411) --------
    // `SourceClip` (MXF.pm:2336-2339): "actually a local set, but it isn't
    // decoded because it has a Duration tag which gets confused with the
    // other Duration tags". Index-table segments carry no useful metadata
    // (MXF.pm:2368). `DefaultObject` (MXF.pm:2411). Treating these as
    // `SkipUnknown` is what stops the `0d` heuristic from wrongly parsing
    // them (the heuristic is `not $tagInfo`-gated, MXF.pm:2872).
    "060e2b34.0253.0101.0d010101.01011100" => TopLevel::SkipUnknown, // SourceClip
    "060e2b34.0253.0101.0d010201.01100000" => TopLevel::SkipUnknown, // V10IndexTableSegment
    "060e2b34.0253.0101.0d010201.01100100" => TopLevel::SkipUnknown, // IndexTableSegment
    "060e2b34.0253.0101.7f000000.00000000" => TopLevel::SkipUnknown, // DefaultObject
    _ => return None,
  })
}

/// MXF.pm:2872-2879 — the `0d`/`0f` auto-generated-set heuristic. A UL of
/// the form `060e2b34.0253.0101.(0d|0f)…` that is NOT already classified by
/// [`classify_top_level`] (i.e. Perl's `not $tagInfo`) is treated as a
/// `%localSet`-style container. The `0f` ("Experimental") arm only fires
/// under `-v`/`-U`; the bundled default path uses only the `0d`
/// ("UserOrganizationPublicUse") arm. Callers MUST consult
/// [`classify_top_level`] first so a known-but-`Unknown` set (`SourceClip`,
/// index segments) is never routed here.
fn is_auto_generated_set(ul: &str) -> bool {
  ul.starts_with("060e2b34.0253.0101.0d")
}

// ===========================================================================
// §5. BER length decoder (MXF.pm:2857-2868)
// ===========================================================================

/// Outcome of [`read_ber_length`]: the decoded length plus the number of
/// length bytes consumed (1 for the short form, `1 + n` for the long form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BerLength {
  /// The decoded value length.
  length: u64,
  /// Bytes consumed by the length field itself.
  consumed: usize,
}

/// Decode a BER length at `buf[pos]` (MXF.pm:2857-2868). The first byte: if
/// `< 0x80` it IS the length (short form); if `>= 0x80` its low 7 bits give
/// a count `n` of subsequent big-endian length bytes (long form). Returns
/// `None` on a truncated length field OR an impossible length.
///
/// CHECKED arithmetic: ExifTool accumulates the long-form bytes into a Perl
/// NV (`$len = $len * 256 + $b`, MXF.pm:2863-2865) and then fails the
/// subsequent `$raf->Read($buff, $len)` cleanly (MXF.pm:2892) when `$len`
/// exceeds the file. A naive `u64` (or `usize`) accumulator could WRAP for
/// a hostile 9+-byte BER length and misframe the KLV walk, or overflow the
/// `value_start + value_len` slice math. We instead reject — via `None` —
/// any long-form length that does not fit `u64` (the leading bytes are
/// non-zero past byte 8, or the running accumulator overflows). The caller
/// treats `None` as end-of-walk, matching ExifTool's failed-read `last`.
fn read_ber_length(buf: &[u8], pos: usize) -> Option<BerLength> {
  let first = *buf.get(pos)?;
  if first < 0x80 {
    return Some(BerLength {
      length: u64::from(first),
      consumed: 1,
    });
  }
  let n = usize::from(first & 0x7f);
  if pos + 1 + n > buf.len() {
    return None; // truncated length field — MXF.pm:2861 failed Read.
  }
  // MXF.pm:2863-2865 `$len = $len * 256 + $b`. Reject (None) any length
  // that overflows `u64` — a wrapped length would misalign the walker.
  // The `pos + 1 + n > buf.len()` guard above ≡ `.get()` returning `None`
  // (byte-identical; the `?` early-return matches the guard's `return None`).
  let mut len: u64 = 0;
  for &b in buf.get(pos + 1..pos + 1 + n)? {
    len = len.checked_mul(256)?.checked_add(u64::from(b))?;
  }
  Some(BerLength {
    length: len,
    consumed: 1 + n,
  })
}

// ===========================================================================
// §6. MXF-specific value decoders ([`read_mxf_value`], MXF.pm:2477-2563)
// ===========================================================================
//
// MXF.pm:2636 gates the MXF-specific decode on `$knownType{$type}` — every
// `Kind` in [`TAG_TABLE`] that maps to a `%knownType` entry. The Rust port
// dispatches on the `Kind` directly in `decode_tag_value` (every `Kind`
// variant has an explicit decode arm), so a separate membership check is
// unnecessary — the match is exhaustive by construction.

/// Decode `Type => 'UTF-16'` (MXF.pm:2483-2484 `$et->Decode($val, 'UTF16')`).
///
/// Byte order + BOM: `Decode` forwards to `Charset::Decompose` with
/// `$fromOrder` undef (MXF.pm:2484 passes no byte-order arg), so
/// `Decompose` falls back to `GetByteOrder()` — 'MM' here, since MXF is read
/// `SetByteOrder('MM')` (MXF.pm:2821) — making the default format big-endian
/// (`Charset.pm:191-197` `$fmt = 'n*'`). `Decompose` then strips a leading
/// BOM (`Charset.pm:203-206`): `$val =~ s/^(\xfe\xff|\xff\xfe)//` removes the
/// 2 BOM bytes and sets `$fmt = $1 eq "\xfe\xff" ? 'n*' : 'v*'`, i.e. a
/// `FE FF` (BE) BOM is stripped and the rest decoded big-endian, while a
/// `FF FE` (LE) BOM is stripped and the rest decoded little-endian. No BOM ⇒
/// the default big-endian order. We mirror that exactly before the loop.
///
/// NUL handling: ExifTool's `Decode` routes UTF-16 → UTF-8 through
/// `Charset::Decompose` then `Charset::Recompose`. `Recompose`'s UTF-8
/// branch (`Charset.pm:318-327`, `$csType == 0x100`) packs the code-point
/// array and then runs `$outVal =~ s/\0.*//s` — TRUNCATING the UTF-8 output
/// at the first NUL (the sub header even documents "truncated at null
/// character if it exists", `Charset.pm:308`). So we stop at the first
/// decoded `U+0000`: text AFTER an embedded NUL is dropped, exactly like
/// ExifTool. (A `tr/\0//d`-style skip would diverge — it would keep stale
/// padding/text that follows an in-band terminator.)
///
/// Lone surrogates are dropped (MXF.pm Notes §2 — "UTF-16 surrogate pairs
/// are not handled properly"; we decode well-formed pairs and drop unpaired
/// code units rather than panic).
fn decode_utf16(bytes: &[u8]) -> String {
  // `Charset.pm:203-206` BOM strip + byte-order select. Default is 'MM'
  // (big-endian) per the `GetByteOrder()` fallback above.
  let (bytes, little_endian) = match bytes {
    [0xfe, 0xff, rest @ ..] => (rest, false), // BE BOM: strip, decode 'n*'
    [0xff, 0xfe, rest @ ..] => (rest, true),  // LE BOM: strip, decode 'v*'
    _ => (bytes, false),                      // no BOM: GetByteOrder() = 'MM'
  };
  let mut out = String::with_capacity(bytes.len() / 2);
  let mut i = 0;
  while i + 1 < bytes.len() {
    // The `i + 1 < bytes.len()` loop bound proves this 2-byte window exists,
    // so the destructure always binds (byte-identical; `break` ≡ the loop exit).
    let Some(&[hi, lo]) = bytes.get(i..i + 2) else {
      break;
    };
    let pair = [hi, lo];
    let unit = if little_endian {
      u16::from_le_bytes(pair)
    } else {
      u16::from_be_bytes(pair)
    };
    i += 2;
    if unit == 0 {
      // `Charset.pm:326` `Recompose`: `$outVal =~ s/\0.*//s` truncates the
      // UTF-8 output at the first NUL — a terminator OR an embedded NUL
      // ends the string; any padding/stale text after it is discarded.
      break;
    }
    if (0xd800..0xdc00).contains(&unit) {
      // High surrogate — pair with the following low surrogate. `i + 1 <
      // bytes.len()` ⇒ `.get(i..i+2)` is `Some` (byte-identical to `bytes[i..]`).
      if let Some(&[lh, ll]) = bytes.get(i..i + 2) {
        let lo_pair = [lh, ll];
        let lo = if little_endian {
          u16::from_le_bytes(lo_pair)
        } else {
          u16::from_be_bytes(lo_pair)
        };
        if (0xdc00..0xe000).contains(&lo) {
          i += 2;
          let cp = 0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(lo) - 0xdc00);
          if let Some(c) = char::from_u32(cp) {
            out.push(c);
          }
          continue;
        }
      }
      // Unpaired high surrogate — skip.
      continue;
    }
    if (0xdc00..0xe000).contains(&unit) {
      // Unpaired low surrogate — skip.
      continue;
    }
    if let Some(c) = char::from_u32(u32::from(unit)) {
      out.push(c);
    }
  }
  out
}

/// Decode `Format => 'string'` — Latin-1, NUL-trimmed. ExifTool's `string`
/// format is byte-for-byte; non-ASCII bytes are Latin-1. The fixture's
/// `string` rows are pure ASCII; non-ASCII bytes are lossy-converted to keep
/// a `String` shape.
fn decode_ascii(bytes: &[u8]) -> String {
  let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
  // `end <= bytes.len()` (a `position` index or `bytes.len()`), so `.get(..end)`
  // always hits; `unwrap_or(&[])` is the unreachable fallback (byte-identical).
  let head = bytes.get(..end).unwrap_or(&[]);
  match core::str::from_utf8(head) {
    Ok(s) => s.to_owned(),
    Err(_) => head.iter().map(|&b| b as char).collect(),
  }
}

/// Decode a big-endian unsigned integer of `bytes.len()` bytes (capped at 8).
fn decode_uint(bytes: &[u8]) -> u64 {
  let mut v: u64 = 0;
  for &b in bytes.iter().take(8) {
    v = v.wrapping_mul(256).wrapping_add(u64::from(b));
  }
  v
}

/// Decode a big-endian signed integer of `bytes.len()` bytes (capped at 8),
/// sign-extended from the top bit.
fn decode_int(bytes: &[u8]) -> i64 {
  if bytes.is_empty() {
    return 0;
  }
  let mut v: i64 = 0;
  let mut over: i64 = 1;
  for &b in bytes.iter().take(8) {
    v = v.wrapping_mul(256).wrapping_add(i64::from(b));
    over = over.wrapping_mul(256);
  }
  // The `bytes.is_empty()` guard above proves byte 0 exists, so `.first()`
  // hits; the `0` fallback is unreachable (byte-identical to `bytes[0]`).
  if bytes.first().copied().unwrap_or(0) & 0x80 != 0 {
    v = v.wrapping_sub(over);
  }
  v
}

/// `Type => 'Timestamp'` decode (MXF.pm:2493-2505). The 8-byte value is a
/// 2-byte `int16u` year then six single bytes (month, day, hour, minute,
/// second, 1/250-second). Each field is range-checked against
/// `(3000,12,31,24,59,59,249)`; an out-of-range field yields the
/// `Invalid (0x…)` form. The 7th field is multiplied by 4 (centi-of-second
/// to milli-of-second) and the result is `%.4d:%.2d:%.2d %.2d:%.2d:%.2d.%.3d`.
fn decode_timestamp(bytes: &[u8]) -> String {
  // MXF.pm:2494 `unpack('nC*', $val)`: an `n` (u16) then `C*` (u8 each).
  if bytes.len() < 2 {
    return format!("Invalid (0x{})", hex_all(bytes));
  }
  // The `bytes.len() < 2` guard above proves bytes 0..2 exist; `.get(2..)` is
  // then also `Some` (byte-identical; the `unwrap_or` fallbacks are unreachable).
  let year = bytes.get(0..2).map_or(0, |b| {
    u32::from(u16::from_be_bytes(b.try_into().unwrap_or_default()))
  });
  let rest: Vec<u32> = bytes
    .get(2..)
    .unwrap_or(&[])
    .iter()
    .map(|&b| u32::from(b))
    .collect();
  // MXF.pm:2495-2499 — walk fields against `@max`, shifting on each valid
  // field; if `@max` is non-empty at the end (a field exceeded its max OR
  // a field was missing) the value is `Invalid`.
  let max = [3000u32, 12, 31, 24, 59, 59, 249];
  let mut fields = Vec::with_capacity(7);
  fields.push(year);
  fields.extend_from_slice(&rest);
  let mut max_idx = 0usize;
  for &f in &fields {
    // The `max_idx >= max.len()` short-circuit guards the index, so
    // `.get(max_idx)` matches the raw `max[max_idx]` (byte-identical).
    if max_idx >= max.len() || max.get(max_idx).is_some_and(|&m| f > m) {
      break;
    }
    max_idx += 1;
  }
  if max_idx < max.len() {
    return format!("Invalid (0x{})", hex_all(bytes));
  }
  // MXF.pm:2503-2504 — `$a[6] *= 4` then the sprintf. The loop above advanced
  // `max_idx` to `max.len()` (== 7) only by passing 7 in-range fields, so
  // `fields.len() >= 7` and `first_chunk` always hits; the `Invalid` fallback
  // mirrors the out-of-range recovery (byte-identical, unreachable here).
  let Some(&[y, mo, d, h, mi, s, ms_raw]) = fields.first_chunk::<7>() else {
    return format!("Invalid (0x{})", hex_all(bytes));
  };
  let ms = ms_raw * 4;
  format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}.{ms:03}")
}

/// `Type => 'VersionType'` (MXF.pm:2491-2492) — single bytes dot-joined.
fn decode_version_type(bytes: &[u8]) -> String {
  let mut s = String::new();
  for (i, &b) in bytes.iter().enumerate() {
    if i > 0 {
      s.push('.');
    }
    push_dec(&mut s, u32::from(b));
  }
  s
}

/// `Type => 'ProductVersion'` (MXF.pm:2485-2490) — five `int16u`; the 5th is
/// a release-type code mapped to a word; output `a.b.c.d <release>`.
fn decode_product_version(bytes: &[u8]) -> String {
  // MXF.pm:2486 `unpack('n*', $val)` then pad to 5 entries with 0.
  // `chunks_exact(2)` yields exactly-2-byte slices, so `try_into::<[u8;2]>`
  // never fails (byte-identical to the raw `[c[0], c[1]]`).
  let mut a: Vec<u32> = bytes
    .chunks_exact(2)
    .map(|c| u32::from(u16::from_be_bytes(c.try_into().unwrap_or_default())))
    .collect();
  while a.len() < 5 {
    a.push(0);
  }
  // The pad loop guarantees `a.len() >= 5`, so `.get(4)` / `.get(..4)` hit;
  // the fallbacks are unreachable (byte-identical to `a[4]` / `a[..4]`).
  let release = match a.get(4).copied().unwrap_or(0) {
    0 => Cow::Borrowed("unknown"),
    1 => Cow::Borrowed("released"),
    2 => Cow::Borrowed("debug"),
    3 => Cow::Borrowed("patched"),
    4 => Cow::Borrowed("beta"),
    5 => Cow::Borrowed("private build"),
    n => Cow::Owned(format!("unknown {n}")),
  };
  let mut s = String::new();
  for (i, v) in a.get(..4).unwrap_or(&[]).iter().enumerate() {
    if i > 0 {
      s.push('.');
    }
    push_dec(&mut s, *v);
  }
  s.push(' ');
  s.push_str(&release);
  s
}

/// Append a decimal `u32` to `out`.
fn push_dec(out: &mut String, v: u32) {
  use core::fmt::Write as _;
  let _ = write!(out, "{v}");
}

/// `Type => 'UL'` / `WeakReference` 16-byte decode (MXF.pm:2549-2556). A
/// reversed-GUID-in-UL slot (high bit of byte 0 set) is un-reversed and
/// rendered as a GUID; a true UL (high bit clear) is rendered in dotted UL
/// notation.
fn decode_ul_type(bytes: &[u8]) -> String {
  if bytes.len() != 16 {
    // Non-16-byte falls through to the generic hex render below (MXF.pm:
    // 2557-2561 `unpack('H*', $val)`).
    return hex_all(bytes);
  }
  // MXF.pm:2553 — `return UL($val) unless unpack('C',$val) & 0x80`. The
  // `bytes.len() != 16` guard above proves byte 0 and both halves exist, so
  // every `.get()` here hits; the fallbacks are unreachable (byte-identical).
  if bytes.first().copied().unwrap_or(0) & 0x80 == 0 {
    return ul_notation(bytes).to_string();
  }
  // MXF.pm:2554 — reversed: `substr($val,8) . substr($val,0,8)`.
  let mut reordered = Vec::with_capacity(16);
  reordered.extend_from_slice(bytes.get(8..16).unwrap_or(&[]));
  reordered.extend_from_slice(bytes.get(0..8).unwrap_or(&[]));
  guid_notation(&reordered)
}

/// `Type => 'PackageID'` / `UMID` 32-byte decode (MXF.pm:2541-2545):
/// `join('.', H8H4H4H8)` + space + `join(' ', x12 H2 H6)` + space +
/// `join('-', x16 H8H4H4H4H12)`.
fn decode_package_id(bytes: &[u8]) -> String {
  if bytes.len() != 32 {
    return hex_all(bytes);
  }
  // The `bytes.len() != 32` guard above proves every group below is in range,
  // so each `.get()` hits; `unwrap_or(&[])` is the unreachable fallback
  // (byte-identical to the raw `&bytes[a..b]`).
  let mut s = String::with_capacity(70);
  // First group: H8 H4 H4 H8 dotted (bytes 0..12).
  push_hex(&mut s, bytes.get(0..4).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, bytes.get(4..6).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, bytes.get(6..8).unwrap_or(&[]));
  s.push('.');
  push_hex(&mut s, bytes.get(8..12).unwrap_or(&[]));
  s.push(' ');
  // Second group: x12 H2 H6 (bytes 12, 13..16) space-joined.
  push_hex(&mut s, bytes.get(12..13).unwrap_or(&[]));
  s.push(' ');
  push_hex(&mut s, bytes.get(13..16).unwrap_or(&[]));
  s.push(' ');
  // Third group: x16 H8H4H4H4H12 dashed (bytes 16..32).
  s.push_str(&guid_notation(bytes.get(16..32).unwrap_or(&[])));
  s
}

/// A decoded reference array/batch entry — already rendered as a string.
type RefList = Vec<String>;

/// Decode a `(Array|Batch)` reference list (MXF.pm:2525-2540): an 8-byte
/// `(int32u count, int32u size)` header then `count` entries of `size`
/// bytes. `StrongReference*` entries render as GUIDs; `BatchOfUL` /
/// `WeakReference` entries render as ULs (recursive `read_mxf_value(_, 'UL')`).
///
/// Returns the rendered entries plus `bad_size`: the faithful
/// `$len == 8 + $count * $size or $et->Warn("Bad array or batch size")`
/// validation (MXF.pm:2528). `bad_size == true` ⇒ the caller raises the
/// group-scoped `MXF:Warning`. The entry loop is UNAFFECTED by `bad_size` —
/// it still reads `count` entries, `last`ing when one would overrun
/// (MXF.pm:2530-2533) — so a bad size changes ONLY the warning, never the
/// emitted list (faithful: the warning and the read loop are independent).
fn decode_ref_list(bytes: &[u8], guid_entries: bool) -> (RefList, bool) {
  let mut out = Vec::new();
  // MXF.pm:2525 — `$len > 16` is the precondition for the whole Array/Batch
  // branch; a `<= 16` byte value never reaches the count/size validation.
  if bytes.len() <= 16 {
    return (out, false);
  }
  // MXF.pm:2526 `unpack('NN', $val)`. The `bytes.len() <= 16` guard above
  // proves bytes 0..8 exist, so these `.get()`s hit; the `0` fallbacks are
  // unreachable and the 4-byte `try_into` never fails (byte-identical).
  let count = bytes
    .get(0..4)
    .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default())) as usize;
  let size = bytes
    .get(4..8)
    .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default())) as usize;
  // MXF.pm:2528 `$len == 8 + $count * $size or $et->Warn(...)`. Use
  // `checked_mul`/`checked_add` so a hostile count/size cannot overflow the
  // comparison (an overflowing product is `!= len`, i.e. ALSO bad).
  let expected = count.checked_mul(size).and_then(|p| p.checked_add(8));
  let bad_size = expected != Some(bytes.len());
  for i in 0..count {
    // `8 + i * size` with overflow-safe arithmetic (a hostile count/size must
    // not panic/wrap on a 32-bit `usize`); an overflow means the entry is
    // out of range ⇒ `last`, faithful to MXF.pm:2532.
    let Some(pos) = i.checked_mul(size).and_then(|o| o.checked_add(8)) else {
      break;
    };
    let Some(entry_end) = pos.checked_add(size) else {
      break;
    };
    if size == 0 || entry_end > bytes.len() {
      break; // MXF.pm:2532 `last if $pos + $size > $len`.
    }
    // `pos < entry_end <= bytes.len()` (the guard above + `size > 0`), so
    // `.get()` always hits (byte-identical; `break` ≡ the overrun recovery).
    let Some(entry) = bytes.get(pos..entry_end) else {
      break;
    };
    if guid_entries {
      out.push(guid_notation(entry));
    } else {
      out.push(decode_ul_type(entry));
    }
  }
  (out, bad_size)
}

// ===========================================================================
// §7. Typed value carrier — `MxfValue`
// ===========================================================================

/// One decoded MXF tag value, post-format-decode but pre-PrintConv. The
/// PrintConv (Boolean string, `ConvertDuration`, `%componentDataDef` label)
/// is applied at emit time by the [`Taggable`](crate::emit::Taggable) impl.
///
/// `#[non_exhaustive]`, single-field newtype variants only (D8 §2).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MxfValue {
  /// Decoded unsigned integer.
  U64(u64),
  /// Decoded signed integer.
  I64(i64),
  /// Decoded string (UTF-16/string text, version string, timestamp,
  /// UL/GUID notation, Boolean `"False"`/`"True"`, …).
  Str(SmolStr),
  /// A reference array/batch — a list of rendered GUID/UL strings.
  List(Vec<SmolStr>),
  /// Raw bytes — emitted as the ExifTool `(Binary data N bytes, …)`
  /// placeholder (`Unknown => 1` rows without a decoded format).
  Bytes(Vec<u8>),
  /// A `%duration`-flagged raw value (Length/Origin/StartTimecode/…),
  /// carrying the pre-`ConvertDuration` integer. `RawConv` already dropped
  /// all-`0xff` (`> 1e18`) values before this variant is constructed — a
  /// dropped value yields `None` from `decode_tag_value` and is never queued
  /// as a `WalkEntry` (MXF.pm:98, ExifTool.pm:9493), so this variant only
  /// ever carries a value that ExifTool actually stored.
  Duration(i64),
  /// A `%duration` value AFTER division by the owning track's `EditRate`
  /// (MXF.pm:2798) — a possibly-fractional `f64`.
  DurationF64(f64),
  /// A `rational64s` value — a `(numerator, denominator)` pair.
  Rational(i64, i64),
}

impl MxfValue {
  /// `true` for [`MxfValue::U64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_u64(&self) -> bool {
    matches!(self, MxfValue::U64(_))
  }
  /// `true` for [`MxfValue::I64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_i64(&self) -> bool {
    matches!(self, MxfValue::I64(_))
  }
  /// `true` for [`MxfValue::Str`].
  #[must_use]
  #[inline(always)]
  pub const fn is_str(&self) -> bool {
    matches!(self, MxfValue::Str(_))
  }
  /// `true` for [`MxfValue::List`].
  #[must_use]
  #[inline(always)]
  pub const fn is_list(&self) -> bool {
    matches!(self, MxfValue::List(_))
  }
  /// `true` for [`MxfValue::Bytes`].
  #[must_use]
  #[inline(always)]
  pub const fn is_bytes(&self) -> bool {
    matches!(self, MxfValue::Bytes(_))
  }
  /// `true` for [`MxfValue::Duration`].
  #[must_use]
  #[inline(always)]
  pub const fn is_duration(&self) -> bool {
    matches!(self, MxfValue::Duration(_))
  }
  /// `true` for [`MxfValue::DurationF64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_duration_f64(&self) -> bool {
    matches!(self, MxfValue::DurationF64(_))
  }
  /// `true` for [`MxfValue::Rational`].
  #[must_use]
  #[inline(always)]
  pub const fn is_rational(&self) -> bool {
    matches!(self, MxfValue::Rational(..))
  }
  /// The string payload of a [`MxfValue::Str`], else `None`.
  #[must_use]
  #[inline(always)]
  pub fn try_unwrap_str(&self) -> Option<&str> {
    match self {
      MxfValue::Str(s) => Some(s.as_str()),
      _ => None,
    }
  }
}

// ===========================================================================
// §8. Typed entry + Meta — `MxfEntry`, `MxfMeta`
// ===========================================================================

/// One emitted MXF tag: family-1 group, tag name, decoded value, plus the
/// ExifTool `Unknown => 1` visibility flag.
///
/// D8 convention: no public fields; accessors only. `group` and `name` are
/// [`SmolStr`] — `group` may be a synthesized `Track<N>` string, `name` is a
/// static-table `&'static str` that inlines heap-free.
///
/// `unknown` carries the ported `Unknown => 1` marker (MXF.pm — InstanceUID /
/// PackageID / reference-batch rows, auto-`Binary` so suppressed from the
/// default `-j`/`-n` view). The golden-pattern engine
/// ([`crate::emit::run_emission`]) performs that suppression centrally
/// (`ExifTool.pm:9179`), so [`MxfMeta`]'s [`Taggable`](crate::emit::Taggable)
/// yields EVERY entry with its `unknown` flag set faithfully rather than
/// pre-filtering. In the current parser the upstream KLV walk only queues
/// VISIBLE rows (`emit_tag_default` at the `WalkEntry` gate), so every
/// production [`MxfEntry`] is `unknown == false`; the flag exists so the
/// engine-suppression contract is expressible (and unit-tested) end-to-end.
#[derive(Debug, Clone, PartialEq)]
pub struct MxfEntry {
  group: SmolStr,
  name: SmolStr,
  value: MxfValue,
  unknown: bool,
}

impl MxfEntry {
  /// Family-1 group (`"MXF"`, `"Track1"`, `"Track2"`, …).
  #[must_use]
  #[inline(always)]
  pub fn group(&self) -> &str {
    self.group.as_str()
  }
  /// Tag name (`"MXFVersion"`, `"Duration"`, `"TrackName"`, …).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Decoded value (borrow of the non-`Copy` [`MxfValue`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &MxfValue {
    &self.value
  }
  /// The ExifTool `Unknown => 1` flag — `true` ⇒ suppressed from the default
  /// output by the emission engine (`ExifTool.pm:9179`). Always `false` for
  /// production entries (the walk pre-filters unknown rows); see the type
  /// docs.
  #[must_use]
  #[inline(always)]
  pub const fn unknown(&self) -> bool {
    self.unknown
  }
}

/// Typed MXF metadata — the lib-first output of [`ProcessMxf`].
///
/// D8 convention: no public fields; accessors only. Carries an ordered list
/// of [`MxfEntry`] tags (already deduplicated and group-fixed, in final
/// emit order) plus a cached `header_type` accessor.
///
/// `MxfMeta` owns its data — MXF values are heavily transformed during the
/// KLV/local-set walk (UTF-16 transcode, hex rendering, duration division),
/// so nothing borrows from the input buffer. The `'a` lifetime is a phantom
/// kept for `FormatParser::Meta<'a>` GAT uniformity with the borrowing
/// formats.
#[derive(Debug, Clone, Default)]
pub struct MxfMeta<'a> {
  entries: Vec<MxfEntry>,
  /// The header partition type (`"OpenHeader"` / `"ClosedCompleteHeader"` /
  /// …) if a header pack was seen — bundled `$$et{MXFInfo}{HeaderType}`
  /// (MXF.pm:2440).
  header_type: Option<SmolStr>,
  /// Phantom anchor for the `'a` GAT lifetime (the Meta is fully owned).
  _marker: core::marker::PhantomData<&'a ()>,
}

impl MxfMeta<'_> {
  /// Every emitted MXF tag, in final order (post dedup + group fixup).
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[MxfEntry] {
    &self.entries
  }
  /// The header partition type, if a header pack was parsed.
  #[must_use]
  #[inline(always)]
  pub fn header_type(&self) -> Option<&str> {
    self.header_type.as_deref()
  }
}

// ===========================================================================
// §9. `ProcessMxf` + parser
// ===========================================================================

/// MXF (Material Exchange Format) parser — faithful port of
/// `Image::ExifTool::MXF::ProcessMXF` (MXF.pm:2807-2969).
#[derive(Debug, Clone, Copy)]
pub struct ProcessMxf;

impl parser_sealed::Sealed for ProcessMxf {}

impl FormatParser for ProcessMxf {
  /// GAT: the Meta is fully owned; `'a` is a phantom (Codex AF2 uniformity).
  type Meta<'a> = MxfMeta<'a>;
  /// Leaf-format Context — `&'a [u8]` (Engine-only, no chained state).
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Returns an owned [`MxfMeta`] (the `'a` lifetime is
/// a phantom — MXF transforms every value, so nothing borrows from `data`).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today — every bad input is
/// `Ok(None)`, faithful to MXF.pm:2816-2817 `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Option<MxfMeta<'_>> {
  parse_inner(data)
}

// ===========================================================================
// §10. KLV walker
// ===========================================================================

/// Per-object book-keeping accumulated during the local-set walk — the
/// `$$mxfInfo{$instance}` hash (MXF.pm:2695-2721).
#[derive(Debug, Default)]
struct ObjInfo {
  /// The object's class name / `DIR_NAME` (`Preface`, `Track`, …).
  name: SmolStr,
  /// Strong-reference child instance UIDs (drives the `SetGroups` tree walk).
  strong_refs: Vec<SmolStr>,
  /// Indices into [`Walker::entries`] for tags emitted by this object's
  /// local set (so a later group fixup can re-stamp the family-1 group).
  entry_indices: Vec<usize>,
  /// The object's `TrackID` value, if it carried one.
  track_id: Option<i64>,
  /// The object's `EditRate` value (`numerator/denominator`), if present.
  edit_rate: Option<(i64, i64)>,
}

/// One in-flight emitted tag, with the file-order index needed by the
/// reverse-order dedup (MXF.pm:2948).
#[derive(Debug, Clone)]
struct WalkEntry {
  group: SmolStr,
  name: SmolStr,
  value: MxfValue,
  /// `IsDuration` flag — drives `ConvertDurations` (MXF.pm:2791-2800).
  is_duration: bool,
  /// The owning object's InstanceUID (used by the dedup to compute the
  /// instance-specific `"<name> <uid>"` key, MXF.pm:2949-2952).
  instance_uid: Option<SmolStr>,
}

/// KLV / local-set walker state — mirrors `%mxfInfo` (MXF.pm:2828-2834).
struct Walker {
  /// Emitted tags in file order.
  entries: Vec<WalkEntry>,
  /// `Primer` lookup: local 16-bit tag id → global UL.
  primer: std::collections::HashMap<u16, SmolStr>,
  /// `$$mxfInfo{$instance}` — per-InstanceUID object book-keeping.
  objects: std::collections::HashMap<SmolStr, ObjInfo>,
  /// InstanceUIDs of all `Preface` objects — `SetGroups` tree roots
  /// (MXF.pm:2720, 2933-2935).
  prefaces: Vec<SmolStr>,
  /// `Group1` lookup: `TrackID` value → `Track<N>` group name
  /// (MXF.pm:2681-2684).
  track_groups: std::collections::HashMap<i64, SmolStr>,
  /// `NumTracks` — 1-based `Track<N>` counter (MXF.pm:2683).
  num_tracks: u32,
  /// The header type from the first header pack (MXF.pm:2440).
  header_type: Option<SmolStr>,
  /// `BestDuration` — InstanceUID of the preferred `TimecodeComponent`
  /// (Source package preferred over Other, MXF.pm:2747-2749/2943-2945).
  best_duration_source: Option<SmolStr>,
  best_duration_other: Option<SmolStr>,
  /// `$$mxfInfo{EditRate}{$g1}` (MXF.pm:2744-2745) — the EditRate (as a
  /// `numerator/denominator` f64) keyed by family-1 group name. Populated
  /// DURING the `SetGroups` tree walk (NOT during the local-set walk), so
  /// the "last object in DFS order wins" semantic of MXF.pm:2744 is
  /// preserved when multiple objects in one track's sub-tree carry EditRate.
  edit_rate_by_group: std::collections::HashMap<SmolStr, f64>,
  /// `$$mxfInfo{FooterPos}` (MXF.pm:2433) — the header subtable's
  /// `FooterPosition` field (offset 24). `0` (the default) means "no
  /// footer pointer" — MXF.pm:2885's `if $mxfInfo{FooterPos}` is falsy.
  footer_position: u64,
  /// `$$mxfInfo{HeaderSize}` (MXF.pm:2441) — the header subtable's
  /// `HeaderSize` field (offset 32): header bytes counted from the start of
  /// the Primer. `None` until a header pack carrying the field is parsed.
  header_size: Option<u64>,
}

impl Walker {
  fn new() -> Self {
    Self {
      entries: Vec::new(),
      primer: std::collections::HashMap::new(),
      objects: std::collections::HashMap::new(),
      prefaces: Vec::new(),
      track_groups: std::collections::HashMap::new(),
      num_tracks: 0,
      header_type: None,
      best_duration_source: None,
      best_duration_other: None,
      edit_rate_by_group: std::collections::HashMap::new(),
      footer_position: 0,
      header_size: None,
    }
  }

  /// Raise a faithful group-scoped `$et->Warn(msg)` — MXF runs entirely under
  /// `$$et{SET_GROUP1} = 'MXF'` (MXF.pm:2838, cleared :2966), so EVERY warning
  /// is the `MXF:Warning` TAG (`ExifTool.pm:9475`), never the document-level
  /// `ExifTool:Warning`. It is pushed AS AN IN-STREAM [`WalkEntry`] at this walk
  /// position (mirroring QuickTime's `Track<N>:Warning` and Matroska's
  /// group-scoped warnings) rather than routed through the later-running
  /// diagnostics channel, so a same-key collision would be resolved by FoundTag
  /// order (priority-0 first-wins, `TagMap::insert`). The `Warning` entry
  /// carries `instance_uid = None` (so `finalize_entries`' reverse-order dedup
  /// `next`s past it — never deduplicated) and is NOT recorded in any object's
  /// `entry_indices`, so `set_groups` leaves its `MXF` family-1 group intact.
  fn push_mxf_warning(&mut self, message: impl Into<SmolStr>) {
    self.entries.push(WalkEntry {
      group: SmolStr::new_static(GROUP_MXF),
      name: SmolStr::new_static("Warning"),
      value: MxfValue::Str(message.into()),
      is_duration: false,
      instance_uid: None,
    });
  }
}

/// Parse the MXF buffer. Returns `Ok(None)`'s `None` if the run-in marker is
/// absent (MXF.pm:2816-2817), else a fully-walked [`MxfMeta`].
fn parse_inner(data: &[u8]) -> Option<MxfMeta<'_>> {
  // MXF.pm:2816-2818 — scan the first 65547 bytes for the run-in marker; the
  // KLV walk starts 11 bytes before the marker (the partition-pack UL).
  // `data.len().min(RUN_IN_SCAN_LIMIT) <= data.len()`, so `.get(..n)` always
  // hits (byte-identical to `&data[..n]`; the `?` reject is unreachable).
  let scan = data.get(..data.len().min(RUN_IN_SCAN_LIMIT))?;
  let marker_at = find_subslice(scan, &MXF_RUN_IN_MARKER)?;
  let start = marker_at; // marker IS bytes 0..11 of the partition-pack UL.

  let mut w = Walker::new();

  // MXF.pm:2840-2929 — the top-level KLV walk loop.
  //
  // `header_start` tracks the most recent header-pack offset (`$start`,
  // MXF.pm:2890) — the footer position is relative to it. `header_end` is
  // the end-of-header offset (`$headerEnd`, MXF.pm:2887) computed once the
  // Primer is reached; `footer_pos` is the absolute footer offset
  // (`$footerPos`, MXF.pm:2885).
  let mut pos = start;
  let mut header_start = start;
  let mut header_end: Option<usize> = None;
  let mut footer_pos: Option<usize> = None;
  loop {
    // MXF.pm:2842-2853 — header-end handling. Once the cursor reaches the
    // end of the header partition: a closed-complete header ends the walk
    // entirely (the file's metadata is all in the header); otherwise the
    // walk skips DIRECTLY to the footer partition (body partitions carry no
    // header metadata). `header_end` is cleared so this fires only once.
    if let Some(end) = header_end {
      if pos >= end {
        // MXF.pm:2845 `last if HeaderType eq 'ClosedCompleteHeader'`.
        if w.header_type.as_deref() == Some("ClosedCompleteHeader") {
          break;
        }
        header_end = None; // MXF.pm:2846 `undef $headerEnd`.
        // MXF.pm:2848-2852 — skip directly to the footer when one exists
        // ahead of the cursor.
        if let Some(fp) = footer_pos {
          if fp > pos {
            if fp >= data.len() {
              break; // MXF.pm:2850 `Seek($footerPos,0) or last`.
            }
            pos = fp;
          }
        }
      }
    }
    // MXF.pm:2855 `$raf->Read($buff, 17) == 17 or last` — need 16-byte key +
    // 1 length byte. (`pos + 17` cannot overflow: `pos` is a buffer offset.)
    if pos + 17 > data.len() {
      break;
    }
    // `klv_start` is the offset of THIS KLV triplet — `$pos = $raf->Tell()`
    // at MXF.pm:2841, captured BEFORE the 17-byte read.
    let klv_start = pos;
    // The `pos + 17 > data.len()` guard above proves bytes `pos..pos+16` exist,
    // so `.get()` always hits (byte-identical; `break` ≡ the failed-read `last`).
    let Some(key) = data.get(pos..pos + 16) else {
      break;
    };
    let ul = ul_notation(key);
    // BER length starts at pos+16; `read_ber_length` rejects (None) any
    // length too large to fit `u64`.
    let Some(ber) = read_ber_length(data, pos + 16) else {
      break;
    };
    let value_start = pos + 16 + ber.consumed;
    // CHECKED end-of-value math: a hostile BER length close to `u64::MAX`
    // must not overflow `value_start + value_len`. `usize::try_from` rejects
    // a length wider than the platform `usize`; `checked_add` rejects the
    // overflow. Either failure ends the walk — matching ExifTool's failed
    // `$raf->Read($buff, $len)` `last` (MXF.pm:2892/2914).
    let Ok(value_len) = usize::try_from(ber.length) else {
      break;
    };
    let Some(value_end) = value_start.checked_add(value_len) else {
      break;
    };
    if value_end > data.len() {
      // MXF.pm:2892/2914 — a truncated value ends the walk.
      break;
    }
    // `value_start <= value_end <= data.len()` (the `checked_add` + the guard
    // above), so `.get()` always hits (byte-identical; `break` ≡ truncated `last`).
    let Some(value) = data.get(value_start..value_end) else {
      break;
    };

    // Classify the top-level key (MXF.pm:2870-2879).
    let class = classify_top_level(&ul).or_else(|| {
      // MXF.pm:2872-2873 auto-generated-set heuristic — the `0d` arm runs in
      // the default path. The generated set's name is `UserOrganizationPublicUse`.
      if is_auto_generated_set(&ul) {
        Some(TopLevel::LocalSet("UserOrganizationPublicUse"))
      } else {
        None
      }
    });

    match class {
      Some(TopLevel::Header(htype)) => {
        // MXF.pm:2888-2891 — `elsif ($$tagInfo{IsHeader}) { $start = $pos }`:
        // a header pack resets the header-start anchor for the footer calc.
        header_start = klv_start;
        // `process_header` records `HeaderType` (MXF.pm:2440) — gated on the
        // `HeaderSize` field being present, exactly as the Perl RawConv is.
        process_header(&mut w, htype, value);
      }
      Some(TopLevel::Primer) => {
        process_primer(&mut w, value);
        // MXF.pm:2883-2887 — `if ($$tagInfo{Name} eq 'Primer' and
        // $mxfInfo{HeaderSize})`: compute the footer offset (relative to the
        // header start, only when `FooterPos` is non-zero) and the
        // header-end offset (relative to the Primer's start).
        if let Some(hsize) = w.header_size {
          if w.footer_position != 0 {
            footer_pos = usize::try_from(w.footer_position)
              .ok()
              .and_then(|fp| header_start.checked_add(fp));
          }
          header_end = usize::try_from(hsize)
            .ok()
            .and_then(|hs| klv_start.checked_add(hs));
        }
      }
      Some(TopLevel::LocalSet(name)) => {
        process_local_set(&mut w, name, value);
      }
      Some(TopLevel::SkipUnknown) | None => {
        // MXF.pm:2918-2921 — skip the value, emit nothing.
      }
    }

    // Advance past key + length + value (`value_end` is the checked
    // `value_start + value_len`, already proven `<= data.len()`).
    pos = value_end;
  }

  // MXF.pm:2930-2937 — walk the object tree to fix family-1 group names,
  // then convert durations.
  fix_groups(&mut w);
  convert_durations(&mut w);

  // MXF.pm:2942-2962 — synthesize the best `MXF:Duration` and dedup.
  let entries = finalize_entries(&mut w);

  Some(MxfMeta {
    entries,
    header_type: w.header_type,
    _marker: core::marker::PhantomData,
  })
}

/// Find the first occurrence of `needle` within `haystack` (the run-in
/// marker scan, MXF.pm:2817 `$buff =~ /…/g`).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || haystack.len() < needle.len() {
    return None;
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

// ===========================================================================
// §11. Header partition pack (`%MXF::Header`, MXF.pm:2419-2446)
// ===========================================================================

/// Decode the header partition pack binary subtable (MXF.pm:2419-2446).
/// `MXFVersion` (offset 0, `int16u[2]`) is the only VISIBLE tag;
/// `FooterPosition` (offset 24, `int64u`) and `HeaderSize` (offset 32,
/// `int64u`) are book-keeping — their `RawConv` returns `undef` so they are
/// NOT emitted (MXF.pm:2433/2439-2443), but they ARE recorded on the Walker
/// to drive the header-end / footer-skip control flow (MXF.pm:2843-2852).
///
/// `htype` is the classified header-pack name (`"OpenHeader"` etc.).
/// `HeaderType` is recorded only when the `HeaderSize` field (offset 32) is
/// PRESENT — faithful to MXF.pm:2439-2442 where `HeaderType` is set by the
/// same `HeaderSize` `RawConv`, which `ProcessBinaryData` runs only when the
/// offset-32 field fits the partition-pack value.
fn process_header(w: &mut Walker, htype: &'static str, buf: &[u8]) {
  // MXF.pm:2422-2426 — `MXFVersion`, `Format => 'int16u[2]'`,
  // `ValueConv => '$val =~ tr/ /./; $val'`. ProcessBinaryData renders an
  // `int16u[2]` as two space-joined integers; the ValueConv replaces the
  // space with a dot. The fixture's bytes are `00 01 00 02` ⇒ "1 2" ⇒ "1.2".
  // `buf.get(0..4)` is `Some` iff `buf.len() >= 4` (byte-identical guard).
  if let Some(&[b0, b1, b2, b3]) = buf.get(0..4) {
    let major = u16::from_be_bytes([b0, b1]);
    let minor = u16::from_be_bytes([b2, b3]);
    let mut s = String::new();
    push_dec(&mut s, u32::from(major));
    s.push('.');
    push_dec(&mut s, u32::from(minor));
    w.entries.push(WalkEntry {
      group: SmolStr::new_static(GROUP_MXF),
      name: SmolStr::new_static("MXFVersion"),
      value: MxfValue::Str(SmolStr::new(&s)),
      is_duration: false,
      instance_uid: None,
    });
  }
  // MXF.pm:2430-2434 — `FooterPosition`, offset 24, `int64u`,
  // `RawConv => '$$self{MXFInfo}{FooterPos} = $val; undef'`.
  // `buf.get(24..32)` is `Some` iff `buf.len() >= 32`; the 8-byte `try_into`
  // never fails (byte-identical to the raw `buf[24..32]` read).
  if let Some(fp) = buf.get(24..32) {
    w.footer_position = u64::from_be_bytes(fp.try_into().unwrap_or_default());
  }
  // MXF.pm:2435-2444 — `HeaderSize`, offset 32, `int64u`. The same `RawConv`
  // sets BOTH `$$self{MXFInfo}{HeaderType} = $$self{DIR_NAME}` (MXF.pm:2440)
  // AND `$$self{MXFInfo}{HeaderSize}` — so `HeaderType` is recorded ONLY
  // when the offset-32 field is present (the FIRST header pack wins, like
  // Perl's `$$self{DIR_NAME}` at the moment ProcessBinaryData runs).
  // `buf.get(32..40)` is `Some` iff `buf.len() >= 40`; the 8-byte `try_into`
  // never fails (byte-identical to the raw `buf[32..40]` read).
  if let Some(hs) = buf.get(32..40) {
    w.header_size = Some(u64::from_be_bytes(hs.try_into().unwrap_or_default()));
    if w.header_type.is_none() {
      w.header_type = Some(SmolStr::new_static(htype));
    }
  }
}

// ===========================================================================
// §12. Primer (MXF.pm:2569-2597)
// ===========================================================================

/// Build the `local-id → UL` lookup from a Primer pack (MXF.pm:2569-2597).
/// The pack is an 8-byte `(int32u count, int32u size)` header then `count`
/// entries of `size` bytes each: a 2-byte `int16u` local id then a 16-byte
/// global UL.
fn process_primer(w: &mut Walker, buf: &[u8]) {
  // MXF.pm:2574 `return 0 unless $end > 8`.
  if buf.len() <= 8 {
    return;
  }
  // The `buf.len() <= 8` guard above proves bytes 0..8 exist; `.get()` then
  // hits and the 4-byte `try_into` never fails (byte-identical).
  let count = buf
    .get(0..4)
    .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default())) as usize;
  let size = buf
    .get(4..8)
    .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default())) as usize;
  // MXF.pm:2577 `return 0 unless $size >= 18`.
  if size < 18 {
    return;
  }
  let mut pos = 8usize;
  for _ in 0..count {
    // MXF.pm:2584 `last if $pos + $size > $end`. The guard + `size >= 18` prove
    // `pos..pos+2` and `pos+2..pos+18` exist, so the `.get()`s hit (byte-identical;
    // `break` ≡ the overrun `last`).
    if pos + size > buf.len() {
      break;
    }
    let Some(&[l0, l1]) = buf.get(pos..pos + 2) else {
      break;
    };
    let local = u16::from_be_bytes([l0, l1]);
    let Some(global_bytes) = buf.get(pos + 2..pos + 18) else {
      break;
    };
    let global = ul_notation(global_bytes);
    w.primer.insert(local, global);
    pos += size;
  }
}

// ===========================================================================
// §13. Local set (MXF.pm:2603-2723)
// ===========================================================================

/// Walk a header-metadata local set (MXF.pm:2603-2723). `dir_name` is the
/// set's object-class name (becomes `ObjInfo::name`). The set is a stream of
/// `(int16u local-tag, int16u length, value)` triplets; each local-tag is
/// resolved to a global UL through the Primer, the UL looked up in
/// [`TAG_TABLE`], and the value decoded + emitted.
///
/// Golden-v2 3a — this walk is **structurally bounded, not recursive**: it is
/// a flat `while pos + 4 < end` loop over the triplets in one KLV value, with
/// no self-call. A nested object is NOT walked inline; it is referenced by an
/// InstanceUID (a `strong_refs` string) and resolved later by the SEPARATE
/// recursive [`set_groups`] tree walk, which carries the recursion budget.
/// So no depth cap is needed here.
fn process_local_set(w: &mut Walker, dir_name: &'static str, buf: &[u8]) {
  let end = buf.len();
  // Per-set book-keeping (MXF.pm:2612).
  let mut instance: Option<SmolStr> = None;
  let mut edit_rate: Option<(i64, i64)> = None;
  let mut track_id: Option<i64> = None;
  let mut strong_refs: Vec<SmolStr> = Vec::new();
  let mut entry_indices: Vec<usize> = Vec::new();

  // MXF.pm:2617-2618 — `while ($pos + 4 < $end)`.
  let mut pos = 0usize;
  while pos + 4 < end {
    // `pos + 4 < end == buf.len()` ⇒ bytes `pos..pos+4` exist, so the
    // destructure binds (byte-identical; `break` ≡ the loop exit).
    let Some(&[k0, k1, n0, n1]) = buf.get(pos..pos + 4) else {
      break;
    };
    let loc = u16::from_be_bytes([k0, k1]);
    let len = u16::from_be_bytes([n0, n1]) as usize;
    pos += 4;
    // MXF.pm:2622 `last if $pos + $len > $end` ≡ `.get(pos..pos+len)` returning
    // `None` (byte-identical; same `break` recovery).
    let Some(value_bytes) = buf.get(pos..pos + len) else {
      break;
    };
    pos += len;

    // MXF.pm:2623 — resolve the local id to a global UL via the Primer.
    let Some(global_ul) = w.primer.get(&loc).cloned() else {
      // MXF.pm:2627-2630 — "NOT IN PRIMER!": the tag is keyed by the raw
      // local id; without a tag-table match it is an unknown tag, which
      // bundled does not emit (binary, no `-U`). Skip.
      continue;
    };

    // MXF.pm:2632 — look up the global UL in the tag table.
    let Some(def) = tag_def(&global_ul) else {
      // Unknown UL — bundled emits the auto-generated `MXF_<hex>` tag only
      // under `-v`/`-U` (MXF.pm:2896 needs `$verbose`). Default path: skip.
      continue;
    };

    // Decode the value (MXF.pm:2634-2648). `None` ⇒ the row's `RawConv`
    // returned `undef` (the `%duration` `> 1e18` all-`0xff` drop, MXF.pm:98):
    // `HandleTag`/`FoundTag` stores no key (ExifTool.pm:9493), so `next unless
    // $key` (MXF.pm:2666) skips the `push @groups`. We model that by skipping
    // this tag entirely — no `WalkEntry` is queued, so the dropped value is
    // absent from `entry_indices`, the duplicate-removal pass, the
    // `FixDuration` set, and the best-`Duration` synthesis. (The only modeled
    // `RawConv => undef` row is `%duration`, which is a `Format` row with no
    // `Type`, so MXF.pm:2636's `ReadMXFValue`/InstanceUID/strong-ref/EditRate
    // book-keeping never runs for it either — `continue` is faithful.)
    let mut bad_array = false;
    let Some(decoded) = decode_tag_value(def, value_bytes, &mut bad_array) else {
      continue;
    };
    // MXF.pm:2528 — `$len == 8 + $count * $size or $et->Warn("Bad array or
    // batch size")`. Raised while `$$et{SET_GROUP1} = 'MXF'`, so it surfaces
    // as the `MXF:Warning` TAG. Raised in walk order (before the tag emit),
    // matching bundled (the `Warn` fires INSIDE `ReadMXFValue`, before
    // `HandleTag` stores the value).
    if bad_array {
      w.push_mxf_warning("Bad array or batch size");
    }

    // Per-object book-keeping (MXF.pm:2640-2685).
    match def.name {
      "InstanceUID" => {
        if let MxfValue::Str(s) = &decoded {
          instance = Some(s.clone());
        }
      }
      "EditRate" => {
        if let MxfValue::Rational(n, d) = &decoded {
          edit_rate = Some((*n, *d));
        }
      }
      _ => {}
    }
    if def.is_track_id {
      // MXF.pm:2679-2684 — record the TrackID + assign a `Track<N>` group.
      if let MxfValue::U64(n) = &decoded {
        let id = *n as i64;
        track_id = Some(id);
        if !w.track_groups.contains_key(&id) {
          w.num_tracks += 1;
          let mut g = String::with_capacity(8);
          g.push_str("Track");
          push_dec(&mut g, w.num_tracks);
          w.track_groups.insert(id, SmolStr::new(&g));
        }
      } else if let MxfValue::I64(n) = &decoded {
        let id = *n;
        track_id = Some(id);
        if !w.track_groups.contains_key(&id) {
          w.num_tracks += 1;
          let mut g = String::with_capacity(8);
          g.push_str("Track");
          push_dec(&mut g, w.num_tracks);
          w.track_groups.insert(id, SmolStr::new(&g));
        }
      }
    }

    // MXF.pm:2638 — collect StrongReference children for the tree walk.
    if matches!(
      def.kind,
      Kind::StrongReference | Kind::StrongReferenceArray | Kind::StrongReferenceBatch
    ) {
      match &decoded {
        MxfValue::Str(s) => strong_refs.push(s.clone()),
        MxfValue::List(items) => strong_refs.extend(items.iter().cloned()),
        _ => {}
      }
    }

    // Emit the tag, unless it is a non-visible identity-only row
    // (InstanceUID/PackageID/reference batches are `Unknown => 1` and the
    // bundled default output emits NONE of them — see `emit_tag_default`).
    if emit_tag_default(def) {
      let idx = w.entries.len();
      w.entries.push(WalkEntry {
        group: SmolStr::new_static(GROUP_MXF),
        name: SmolStr::new_static(def.name),
        value: decoded,
        is_duration: def.is_duration,
        instance_uid: None, // filled in below once `instance` is known
      });
      entry_indices.push(idx);
    }
  }

  // MXF.pm:2688-2721 — register the object now that the InstanceUID is known.
  if let Some(inst) = instance {
    // Stamp every entry this set emitted with the owning InstanceUID
    // (MXF.pm:2701 `$$_{UID} = $instance foreach @groups`).
    // Each `idx` was recorded from a just-pushed `w.entries` element, so it is
    // always in range; `.get_mut()` hits (byte-identical to `w.entries[idx]`).
    for &idx in &entry_indices {
      if let Some(e) = w.entries.get_mut(idx) {
        e.instance_uid = Some(inst.clone());
      }
    }
    let obj = w.objects.entry(inst.clone()).or_default();
    obj.name = SmolStr::new_static(dir_name);
    obj.strong_refs.extend(strong_refs);
    obj.entry_indices.extend(entry_indices);
    if let Some(tid) = track_id {
      obj.track_id = Some(tid);
    }
    if let Some(er) = edit_rate {
      obj.edit_rate = Some(er);
    }
    // MXF.pm:2720 — record Preface roots.
    if dir_name == "Preface" {
      w.prefaces.push(inst);
    }
  }
}

/// Whether a tag row produces a visible top-level tag in the bundled DEFAULT
/// output (no `-v`/`-U`).
///
/// Driven by the EXPLICIT `unknown` flag (the ported `Unknown => 1` marker),
/// NOT inferred from `Kind`: an `Unknown` row's value IS decoded — for the
/// object-tree book-keeping (InstanceUID identity, strong-reference children)
/// — but ExifTool auto-sets its `Binary` flag (MXF.pm:2653/2899-2902) so the
/// tag is suppressed from `-j`/`-n` output (binary tags need `-b`).
/// `ComponentDataDefinition` is `Type => 'WeakReference'` but NOT `Unknown`
/// (it has a real PrintConv), so it stays visible.
fn emit_tag_default(def: &TagDef) -> bool {
  !def.unknown
}

/// Decode one local-set tag's value bytes per its [`Kind`] (MXF.pm:2634-2648
/// for `Type` rows + ExifTool's generic `ReadValue` for `Format` rows).
///
/// Returns `None` when the row's `RawConv` would yield `undef` — for the
/// `%duration` family that is `$val > 1e18` (the all-`0xff` sentinel,
/// MXF.pm:98). A `None` decode mirrors `FoundTag` returning no key
/// (ExifTool.pm:9493 `return undef unless defined $value`): the caller then
/// runs `next unless $key` (MXF.pm:2666) so the value is NEVER pushed onto
/// `@groups` — i.e. it does not participate in the duplicate-removal pass,
/// the `FixDuration` set, or the best-`Duration` synthesis.
/// Decode one MXF tag value (MXF.pm:2634-2648 `ReadMXFValue`). `bad_array` is
/// set to `true` by the Array/Batch arms when the faithful
/// `$len == 8 + $count * $size` check fails (MXF.pm:2528) — the caller then
/// raises the group-scoped `MXF:Warning`. (Threaded as an out-param rather
/// than folded into the return so the `RawConv => undef` drop — `None` — and
/// the bad-array signal stay orthogonal.)
fn decode_tag_value(def: &TagDef, bytes: &[u8], bad_array: &mut bool) -> Option<MxfValue> {
  let value = match def.kind {
    Kind::Int8u | Kind::Int16u | Kind::Int32u => {
      let n = decode_uint(bytes);
      if def.is_duration {
        return duration_or_drop(n as i64);
      }
      MxfValue::U64(n)
    }
    Kind::Int64s => {
      let n = decode_int(bytes);
      if def.is_duration {
        return duration_or_drop(n);
      }
      MxfValue::I64(n)
    }
    Kind::Length => {
      // MXF.pm:2506-2507 — `Position`/`Length` decode as `Get64u`. The
      // `%duration` RawConv then drops `> 1e18` (all-`0xff`) values.
      let n = decode_uint(bytes);
      if def.is_duration {
        // The raw u64 may exceed i64::MAX (the `0xff…` sentinel) — compare
        // as u64 against the 1e18 threshold before the i64 cast. RawConv
        // `undef` ⇒ no tag (MXF.pm:98).
        if n > 1_000_000_000_000_000_000u64 {
          return None;
        }
        MxfValue::Duration(n as i64)
      } else {
        MxfValue::U64(n)
      }
    }
    Kind::Rational64s => {
      // `rational64s` = int32s numerator / int32s denominator. `bytes.get(0..8)`
      // is `Some` iff `bytes.len() >= 8` (byte-identical to the if/else).
      if let Some(&[n0, n1, n2, n3, d0, d1, d2, d3]) = bytes.get(0..8) {
        let num = i64::from(i32::from_be_bytes([n0, n1, n2, n3]));
        let den = i64::from(i32::from_be_bytes([d0, d1, d2, d3]));
        MxfValue::Rational(num, den)
      } else {
        MxfValue::Rational(0, 1)
      }
    }
    Kind::AsciiString => MxfValue::Str(SmolStr::new(decode_ascii(bytes))),
    Kind::Utf16 => MxfValue::Str(SmolStr::new(decode_utf16(bytes))),
    Kind::Boolean => {
      // MXF.pm:2508-2509 — `$val eq "\0" ? 'False' : 'True'`. A single NUL
      // byte ⇒ False; anything else ⇒ True.
      let is_false = bytes == [0u8];
      MxfValue::Str(SmolStr::new_static(if is_false { "False" } else { "True" }))
    }
    Kind::Timestamp => MxfValue::Str(SmolStr::new(decode_timestamp(bytes))),
    Kind::VersionType => MxfValue::Str(SmolStr::new(decode_version_type(bytes))),
    Kind::ProductVersion => MxfValue::Str(SmolStr::new(decode_product_version(bytes))),
    Kind::Ul | Kind::WeakReference => MxfValue::Str(SmolStr::new(decode_ul_type(bytes))),
    Kind::Guid | Kind::StrongReference => {
      // 16-byte GUID/StrongReference (MXF.pm:2546-2556). A non-16-byte
      // value falls through to the generic hex render.
      if bytes.len() == 16 {
        MxfValue::Str(SmolStr::new(guid_notation(bytes)))
      } else {
        MxfValue::Str(SmolStr::new(hex_all(bytes)))
      }
    }
    Kind::Label => {
      // `Type => 'Label'` is a 16-byte identifier rendered as a GUID
      // (MXF.pm:2546-2556 — Label is neither `UL` nor `WeakReference`, so it
      // takes the plain compact-GUID branch).
      if bytes.len() == 16 {
        MxfValue::Str(SmolStr::new(guid_notation(bytes)))
      } else {
        MxfValue::Str(SmolStr::new(hex_all(bytes)))
      }
    }
    Kind::PackageId => MxfValue::Str(SmolStr::new(decode_package_id(bytes))),
    Kind::StrongReferenceArray | Kind::StrongReferenceBatch => {
      let (list, bad) = decode_ref_list(bytes, /* guid_entries */ true);
      *bad_array = bad;
      MxfValue::List(list.iter().map(SmolStr::new).collect())
    }
    Kind::BatchOfUl => {
      let (list, bad) = decode_ref_list(bytes, /* guid_entries */ false);
      *bad_array = bad;
      MxfValue::List(list.iter().map(SmolStr::new).collect())
    }
    Kind::Binary => MxfValue::Bytes(bytes.to_vec()),
  };
  Some(value)
}

/// Apply the `%duration` `RawConv` (MXF.pm:98): drop `> 1e18` (the all-`0xff`
/// sentinel) by returning `None` — exactly as the RawConv returns `undef` so
/// no tag key is stored (ExifTool.pm:9493). Otherwise carry the raw integer
/// as a [`MxfValue::Duration`].
fn duration_or_drop(raw: i64) -> Option<MxfValue> {
  // `$val > 1e18` — a 64-bit Length of `0xff…` decodes (via `Get64u`) to
  // ~1.84e19; an `int64s` of all-`0xff` decodes to -1. Only the former
  // exceeds 1e18, so a negative raw value is NOT dropped.
  if raw > 1_000_000_000_000_000_000 {
    None
  } else {
    Some(MxfValue::Duration(raw))
  }
}

// ===========================================================================
// §14. SetGroups tree walk (MXF.pm:2731-2778)
// ===========================================================================

/// Max recursion depth for the `SetGroups` strong-reference object-tree walk
/// (Golden-v2 Contract 3a). Bundled `SetGroups` (MXF.pm:2731-2778) recurses
/// the file-declared strong-reference graph with only a `DidGroups` cycle
/// guard (mirrored by [`set_groups`]'s `visited` set). The cycle guard stops a
/// *cyclic* graph, but a hostile file can declare a long ACYCLIC chain of
/// distinct objects (`Preface`→A→B→C→…), one per top-level KLV local set, so
/// the recursion would grow to the chain length and overflow the stack — a
/// DoS reachable from a crafted (large) real file. Real MXF object trees are
/// shallow (`Preface`→`ContentStorage`→`Package`→`Track`→`Sequence`→
/// `Component`, ≈6-8 deep), so this cap is a large superset that never trips
/// on a real file (byte-identical output). Exceeding it stops descending that
/// branch (the deeper objects keep their default `MXF` family-1 group — they
/// are unreachable garbage in any real file).
const MAX_OBJECT_TREE_DEPTH: u32 = 1000;

/// Walk the MXF object tree from each `Preface` root to assign `Track<N>`
/// family-1 groups (MXF.pm:2731-2778 `SetGroups`). When an object carries a
/// `TrackID`, that ID's `Track<N>` group is propagated down its entire
/// strong-reference sub-tree, re-stamping every emitted entry.
///
/// Also records the "best duration" `TimecodeComponent` instance: the one in
/// a `SourcePackage` sub-tree is preferred over any other (MXF.pm:2747-2754).
fn fix_groups(w: &mut Walker) {
  let prefaces: Vec<SmolStr> = w.prefaces.clone();
  let mut visited: std::collections::HashSet<SmolStr> = std::collections::HashSet::new();
  for root in prefaces {
    // Each `Preface` root starts the tree walk at depth 0.
    set_groups(w, 0, &root, None, false, &mut visited);
  }
}

/// Recursive `SetGroups` (MXF.pm:2731-2778). `track_id` is the inherited
/// track id (set by the nearest ancestor that had one); `in_source` is true
/// inside a `SourcePackage` sub-tree.
fn set_groups(
  w: &mut Walker,
  depth: u32,
  instance: &SmolStr,
  inherited_track_id: Option<i64>,
  in_source: bool,
  visited: &mut std::collections::HashSet<SmolStr>,
) {
  // Golden-v2 3a — recursion-depth guard for the strong-reference tree. Real
  // object trees are ≈6-8 deep, far below `MAX_OBJECT_TREE_DEPTH`, so this
  // never trips on a real file (byte-identical); it bounds stack growth on a
  // maliciously long strong-ref chain.
  if depth >= MAX_OBJECT_TREE_DEPTH {
    return;
  }
  // MXF.pm:2735-2736 — `return unless $objInfo and not $$objInfo{DidGroups}`.
  if !visited.insert(instance.clone()) {
    return;
  }
  // Snapshot the object's fields (avoids holding a borrow across the
  // recursive call / the entry re-stamping).
  let Some(obj) = w.objects.get(instance) else {
    return;
  };
  let obj_name = obj.name.clone();
  let obj_track_id = obj.track_id;
  let obj_edit_rate = obj.edit_rate;
  let entry_indices = obj.entry_indices.clone();
  let strong_refs = obj.strong_refs.clone();

  // MXF.pm:2737 — `$trackID = $$objInfo{TrackID} if defined`.
  let track_id = obj_track_id.or(inherited_track_id);

  // MXF.pm:2740-2750 — the object's `Track<N>` group + best-duration record.
  let group1: Option<SmolStr> = track_id.and_then(|tid| w.track_groups.get(&tid).cloned());
  // MXF.pm:2743-2745 — `$$mxfInfo{EditRate}{$g1} = $$objInfo{EditRate}`.
  // Recorded HERE (not in the local-set walk) so it is keyed by the `$g1`
  // the tree walk computed AND the DFS-order "last wins" matches Perl.
  if let (Some(g1), Some((num, den))) = (&group1, obj_edit_rate) {
    if den != 0 {
      w.edit_rate_by_group
        .insert(g1.clone(), num as f64 / den as f64);
    }
  }
  if track_id.is_some() && obj_name == "TimecodeComponent" {
    // MXF.pm:2747-2749 — record this TimecodeComponent as the best
    // duration for its `Source`/`Other` bucket.
    if in_source {
      w.best_duration_source = Some(instance.clone());
    } else {
      w.best_duration_other = Some(instance.clone());
    }
  }

  // MXF.pm:2753-2754 — set the `InSource` flag for a `SourcePackage` subtree.
  let child_in_source = in_source || obj_name == "SourcePackage";

  // MXF.pm:2765-2768 — re-stamp every entry this object emitted with `g1`.
  if let Some(g1) = &group1 {
    for &idx in &entry_indices {
      if let Some(e) = w.entries.get_mut(idx) {
        e.group = g1.clone();
      }
    }
  }

  // MXF.pm:2770-2772 — recurse into the strong-reference children (one level
  // deeper, Golden-v2 3a).
  for child in &strong_refs {
    set_groups(w, depth + 1, child, track_id, child_in_source, visited);
  }
}

// ===========================================================================
// §15. ConvertDurations (MXF.pm:2783-2801)
// ===========================================================================

/// Divide every `%duration` tag by its owning track's `EditRate`
/// (MXF.pm:2783-2801 `ConvertDurations`). The per-group `EditRate` was
/// recorded into `Walker::edit_rate_by_group` during the `SetGroups` tree
/// walk (MXF.pm:2744-2745); each duration entry is divided by the rate
/// keyed on its (post-fixup) family-1 group.
fn convert_durations(w: &mut Walker) {
  // MXF.pm:2791-2800 — for each FixDuration tag, `my $g1 = $$tagExtra{$key}
  // {G1} or next; my $editRate = $$editHash{$g1}; $$valueHash{$key} /=
  // $editRate if $editRate`. A duration whose group has NO recorded
  // EditRate (the `$editHash{$g1}` is undef) is left unchanged.
  for e in &mut w.entries {
    if !e.is_duration {
      continue;
    }
    let MxfValue::Duration(raw) = e.value else {
      continue;
    };
    // MXF.pm:2796 `or next` — only durations whose family-1 group is a
    // `Track<N>` with a recorded EditRate are divided. Perl's `$editRate`
    // truthiness also skips a zero EditRate.
    if let Some(rate) = w.edit_rate_by_group.get(&e.group) {
      if *rate != 0.0 {
        e.value = MxfValue::DurationF64(raw as f64 / rate);
      }
    }
  }
}

// ===========================================================================
// §16. Finalize — best-duration synthesis + reverse-order dedup
// ===========================================================================

/// Synthesize `MXF:Duration` from the best `TimecodeComponent` and apply the
/// reverse-file-order duplicate removal (MXF.pm:2942-2962), then convert the
/// in-flight [`WalkEntry`] list to the public [`MxfEntry`] list.
fn finalize_entries(w: &mut Walker) -> Vec<MxfEntry> {
  // MXF.pm:2943-2945 — `$instance = BestDuration{Source} || BestDuration{Other}`.
  let best_instance = w
    .best_duration_source
    .clone()
    .or_else(|| w.best_duration_other.clone());

  // MXF.pm:2946-2962 — process tags in REVERSE file order; the first time an
  // instance-specific `"<name> <uid>"` key is seen it is KEPT, later (i.e.
  // earlier-in-file) duplicates are deleted. A tag with no InstanceUID is
  // never deduplicated (`next` at MXF.pm:2949). When the kept tag is the
  // best-duration `Duration`, ALSO synthesize the top-level `MXF:Duration`.
  let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
  // `kept[i]` == true ⇒ entry i survives the dedup.
  let mut kept = std::vec![true; w.entries.len()];
  // The synthesized best `MXF:Duration` value (inserted at the position of
  // the kept best-duration `Duration` tag, faithful to `HandleTag` running
  // inline at MXF.pm:2960).
  let mut best_duration_value: Option<(usize, MxfValue)> = None;

  for idx in (0..w.entries.len()).rev() {
    // `idx` ranges over `0..w.entries.len()`, so `.get(idx)` / `.get_mut(idx)`
    // (`kept.len() == w.entries.len()`) always hit; the `continue` recovery
    // matches the no-UID skip (byte-identical to `w.entries[idx]` / `kept[idx]`).
    let Some(e) = w.entries.get(idx) else {
      continue;
    };
    let Some(uid) = &e.instance_uid else {
      continue; // MXF.pm:2949 `next` — no UID ⇒ never deduplicated.
    };
    // MXF.pm:2951-2952 — instance-specific key `"<name> <uid>"`.
    let utag = format!("{} {}", e.name, uid);
    if seen.contains(&utag) {
      // MXF.pm:2954 — duplicate ⇒ delete.
      if let Some(k) = kept.get_mut(idx) {
        *k = false;
      }
    } else {
      seen.insert(utag);
      // MXF.pm:2957-2961 — best-duration synthesis.
      if let Some(best) = &best_instance {
        if e.name == "Duration" && uid == best {
          best_duration_value = Some((idx, e.value.clone()));
        }
      }
    }
  }

  // Assemble the surviving entries in file order.
  let mut out: Vec<MxfEntry> = Vec::new();
  for (idx, e) in w.entries.iter().enumerate() {
    // `idx < w.entries.len() == kept.len()`, so `.get(idx)` always hits; the
    // `true` fallback (keep) is unreachable (byte-identical to `!kept[idx]`).
    if !kept.get(idx).copied().unwrap_or(true) {
      continue;
    }
    out.push(MxfEntry {
      group: e.group.clone(),
      name: e.name.clone(),
      value: e.value.clone(),
      // The walk only queued visible (`emit_tag_default`) rows, so every
      // surviving entry is a default-visible tag.
      unknown: false,
    });
    // MXF.pm:2960 — `HandleTag($tagTablePtr, '…Duration…', $val)` runs
    // inline right after the kept best-duration `Duration` tag, so the
    // synthesized `MXF:Duration` lands immediately after it in file order.
    if let Some((best_idx, val)) = &best_duration_value {
      if *best_idx == idx {
        out.push(MxfEntry {
          group: SmolStr::new_static(GROUP_MXF),
          name: SmolStr::new_static("Duration"),
          value: val.clone(),
          unknown: false,
        });
      }
    }
  }
  out
}

// ===========================================================================
// §17. Group constant
// ===========================================================================

/// The default family-1 group for every MXF tag (MXF.pm:2838
/// `$$et{SET_GROUP1} = 'MXF'`).
const GROUP_MXF: &str = "MXF";

// ===========================================================================
// §18. `Diagnose` — the golden-pattern diagnostics path (Phase B.1.5)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for MxfMeta<'_> {
  // MXF has NO document-level diagnostics — it runs entirely under
  // `$$et{SET_GROUP1} = 'MXF'` (MXF.pm:2838, cleared :2966), so EVERY
  // `$et->Warn` raised during the walk is the group-scoped `MXF:Warning` TAG
  // (`ExifTool.pm:5638`/`:9475`), emitted IN-STREAM via the `Taggable` impl
  // (see [`Walker::push_mxf_warning`]), not the document `ExifTool:Warning`.
  // The lone reachable warning is `Bad array or batch size` (MXF.pm:2528);
  // `Seek error` (MXF.pm:2822) needs a fallible `RAF->Seek` this in-memory port
  // lacks, so it is unreachable. The trait default (no diagnostics) therefore
  // applies.
}

// ===========================================================================
// §18. `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for MxfMeta<'_> {
  /// Yield MXF tags in final order (post dedup + group fixup) — the
  /// golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead
  /// of `out.write_*`), the per-tag PrintConv branches are preserved
  /// verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings: `ConvertDuration` for
  /// `%duration` tags, `%componentDataDef` label for
  /// `ComponentDataDefinition`. `mode == ValueConv` (`-n`) ⇒ post-ValueConv
  /// raw scalars.
  ///
  /// Group: `family0` = `"MXF"` (the `%MXF::Main` table group — bundled
  /// `$$et{SET_GROUP1} = 'MXF'`, MXF.pm:2838 — and the default group0);
  /// `family1` = `entry.group()` (the per-entry `-G1` key — `"MXF"` or a
  /// synthesized `"Track<N>"`), byte-identical to the retired sink.
  ///
  /// `unknown` is carried PER ENTRY from [`MxfEntry::unknown`]; the engine
  /// ([`run_emission`](crate::emit::run_emission)) drops `Unknown => 1` tags
  /// centrally (`ExifTool.pm:9179`). The walk pre-filters unknown rows
  /// (`emit_tag_default`), so every production entry is visible
  /// (`unknown == false`) — but yielding the flag rather than re-filtering
  /// keeps the suppression contract in the engine (proven by the
  /// `taggable_yields_unknown_but_engine_suppresses` test).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<EmittedTag> = Vec::with_capacity(self.entries.len());
    for entry in &self.entries {
      push_one(&mut tags, entry, print_conv);
    }
    tags.into_iter()
  }
}

/// Push a single MXF entry as an [`EmittedTag`] (family0 `"MXF"`, family1 =
/// `entry.group()`, the entry's `unknown` flag). Preserves every per-value
/// PrintConv branch of the retired `emit_one` verbatim.
#[cfg(feature = "alloc")]
fn push_one(tags: &mut Vec<crate::emit::EmittedTag>, entry: &MxfEntry, print_conv: bool) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let name = entry.name();
  // family0 = "MXF" (table group0); family1 = the per-entry group (`-G1` key).
  let group = || Group::new(GROUP_MXF, entry.group());
  let unknown = entry.unknown();
  let mut push = |value: TagValue| tags.push(EmittedTag::new(group(), name.into(), value, unknown));
  match entry.value_ref() {
    MxfValue::U64(n) => push(TagValue::U64(*n)),
    MxfValue::I64(n) => push(TagValue::I64(*n)),
    MxfValue::Str(s) => {
      if name == "ComponentDataDefinition" && print_conv {
        // %componentDataDef PrintConv (MXF.pm:103-113) — map the decoded UL
        // to a human label; an unrecognized UL passes through unchanged.
        match component_data_def_label(s.as_str()) {
          Some(label) => push(TagValue::Str(label.into())),
          None => push(TagValue::Str(s.as_str().into())),
        }
      } else {
        push(TagValue::Str(s.as_str().into()));
      }
    }
    MxfValue::List(items) => {
      // A reference array/batch — ExifTool's struct rendering emits the
      // bracketed list. None of the fixture's emitted tags are List-typed
      // (the reference rows are `Unknown => 1`, suppressed), but a future
      // tag-table row could be: emit as a string list.
      let list: Vec<TagValue> = items
        .iter()
        .map(|s| TagValue::Str(s.as_str().into()))
        .collect();
      push(TagValue::List(list));
    }
    MxfValue::Bytes(b) => push(TagValue::Bytes(b.clone())),
    MxfValue::Duration(raw) => {
      // A `%duration` tag that was NOT divided by an EditRate (no track
      // EditRate found) — still apply the PrintConv. (RawConv-dropped values
      // never reach here: they yield `None` at decode time and are never
      // queued — MXF.pm:98.)
      if print_conv {
        // PrintConv `ConvertDuration($val)`.
        let s = crate::datetime::convert_duration(*raw as f64);
        push(TagValue::Str(s.into()));
      } else {
        // -n: the post-ValueConv raw integer.
        push(TagValue::I64(*raw));
      }
    }
    MxfValue::DurationF64(v) => {
      if print_conv {
        let s = crate::datetime::convert_duration(*v);
        push(TagValue::Str(s.into()));
      } else {
        push(TagValue::F64(*v));
      }
    }
    MxfValue::Rational(num, den) => {
      // `rational64s` — ExifTool's `ReadValue` yields the quotient
      // (`RoundFloat(n/d, 10)`). Both `-j` and `-n` render the numeric
      // quotient (no PrintConv on the bare `Format => 'rational64s'` rows).
      let r = crate::value::Rational::rational64(*num, *den);
      let text = r.exiftool_val_str();
      // Emit as a numeric value when the quotient is a finite number, else
      // the `inf`/`undef` word string.
      match text.parse::<f64>() {
        Ok(f) if f.is_finite() => push(TagValue::F64(f)),
        _ => push(TagValue::Str(text.into())),
      }
    }
  }
}

// ===========================================================================
// §18b. `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for MxfMeta<'_> {
  /// Project MXF metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// MXF is a professional video container: the single faithful structural
  /// contribution is one video [`TrackKind`](crate::metadata::TrackKind).
  /// Duration is left `None` — the decoded MXF `Duration` is a per-instance
  /// edit-unit count (divided by a track EditRate) carried as an
  /// [`MxfValue`] inside the tag stream, not a clean wall-clock seconds
  /// accessor the projection can faithfully consume. Camera / lens / GPS /
  /// capture stay `None` (MXF carries no such facts here).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Video);
    media
  }
}

// ===========================================================================
// §20. Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2a); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// [`TAG_INDEX`] must stay sorted by UL (the `binary_search` invariant)
  /// AND map every UL back to the [`TAG_TABLE`] row that actually holds it.
  /// Re-deriving the mapping here makes any drift in the hand-listed index
  /// (stale row number, missing/extra row, lost sort) a hard test failure.
  #[test]
  fn tag_index_round_trips() {
    assert_eq!(
      TAG_INDEX.len(),
      TAG_TABLE.len(),
      "TAG_INDEX must have one slot per TAG_TABLE row"
    );
    let mut prev: Option<&str> = None;
    for &(ul, row) in TAG_INDEX {
      if let Some(p) = prev {
        assert!(p < ul, "TAG_INDEX not sorted: {ul} after {p}");
      }
      prev = Some(ul);
      assert_eq!(
        TAG_TABLE[row as usize].ul, ul,
        "TAG_INDEX[{row}] points at the wrong TAG_TABLE row"
      );
    }
    // Every table row is reachable through the index (no row left unindexed).
    for (i, t) in TAG_TABLE.iter().enumerate() {
      assert_eq!(
        tag_def(t.ul).map(|d| d.ul),
        Some(t.ul),
        "row {i} ({}) is not reachable via tag_def",
        t.ul
      );
    }
  }

  #[test]
  fn ul_notation_renders_dotted_groups() {
    let key = [
      0x06, 0x0e, 0x2b, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01,
      0x00,
    ];
    assert_eq!(
      ul_notation(&key).as_str(),
      "060e2b34.0205.0101.0d010201.01020100"
    );
  }

  #[test]
  fn ber_length_short_form() {
    // 0x83 < 0x80? no — 0x83 has the high bit set ⇒ long form, n=3.
    // A short-form example: 0x68 ⇒ length 104.
    let b = read_ber_length(&[0x68], 0).unwrap();
    assert_eq!(b.length, 104);
    assert_eq!(b.consumed, 1);
  }

  #[test]
  fn ber_length_long_form() {
    // 0x83 ⇒ n=3 subsequent bytes: 0x00 0x00 0x68 ⇒ length 104.
    let b = read_ber_length(&[0x83, 0x00, 0x00, 0x68], 0).unwrap();
    assert_eq!(b.length, 104);
    assert_eq!(b.consumed, 4);
  }

  #[test]
  fn ber_length_long_form_truncated_returns_none() {
    // 0x82 ⇒ n=2 but only 1 byte follows.
    assert!(read_ber_length(&[0x82, 0x00], 0).is_none());
  }

  #[test]
  fn ber_length_overflow_rejected() {
    // A 9-byte long-form length (0x89 ⇒ n=9) with non-zero leading bytes
    // overflows u64 — must be rejected (None), not wrapped. Without the
    // `checked_mul` guard this would wrap and misframe the KLV walker.
    let buf = [0x89, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(read_ber_length(&buf, 0).is_none());
    // An 8-byte u64::MAX length decodes (fits u64) but the caller's
    // `usize::try_from` / `checked_add` then ends the walk cleanly.
    let max8 = [0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(read_ber_length(&max8, 0).unwrap().length, u64::MAX);
  }

  #[test]
  fn classify_top_level_sourceclip_is_skip_unknown() {
    // SourceClip is `Unknown => 1` in %MXF::Main (MXF.pm:2336-2339) — it
    // must classify as SkipUnknown, NOT be parsed by the `0d`
    // auto-generated-set heuristic (which would emit spurious Duration
    // tags from its body). It DOES share the `0253.0101.0d` prefix.
    assert_eq!(
      classify_top_level("060e2b34.0253.0101.0d010101.01011100"),
      Some(TopLevel::SkipUnknown)
    );
    assert!(is_auto_generated_set(
      "060e2b34.0253.0101.0d010101.01011100"
    ));
    // Index-table segments are also Unknown (MXF.pm:2368-2370).
    assert_eq!(
      classify_top_level("060e2b34.0253.0101.0d010201.01100100"),
      Some(TopLevel::SkipUnknown)
    );
    // A genuinely-unknown `0d` UL falls through to the heuristic.
    assert_eq!(
      classify_top_level("060e2b34.0253.0101.0d019999.01010100"),
      None
    );
    assert!(is_auto_generated_set(
      "060e2b34.0253.0101.0d019999.01010100"
    ));
  }

  #[test]
  fn decode_uint_be() {
    assert_eq!(decode_uint(&[]), 0);
    assert_eq!(decode_uint(&[0x16, 0x01, 0x02, 0x01]), 369_164_801);
    assert_eq!(decode_uint(&[0x00, 0x00, 0x1e, 0xc0]), 7872);
  }

  #[test]
  fn decode_int_sign_extends() {
    assert_eq!(
      decode_int(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      0
    );
    assert_eq!(
      decode_int(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
      -1
    );
  }

  #[test]
  fn decode_utf16_basic() {
    // "Hi" in UTF-16BE (no BOM ⇒ GetByteOrder() = 'MM' = big-endian).
    assert_eq!(decode_utf16(&[0x00, 0x48, 0x00, 0x69]), "Hi");
    // An embedded NUL TRUNCATES the value — `Charset.pm:326` `Recompose`
    // runs `s/\0.*//s` on the UTF-8 output, so text after the NUL (here
    // the `i`) is discarded. `H\0i` ⇒ `H`, NOT `Hi`.
    assert_eq!(decode_utf16(&[0x00, 0x48, 0x00, 0x00, 0x00, 0x69]), "H");
    // A trailing UTF-16 NUL terminator likewise ends the string.
    assert_eq!(decode_utf16(&[0x00, 0x48, 0x00, 0x00]), "H");
  }

  #[test]
  fn decode_utf16_strips_be_bom() {
    // `Charset.pm:203-206`: a leading `FE FF` (BE) BOM is stripped and the
    // remainder decoded big-endian — the BOM is NOT preserved as U+FEFF.
    assert_eq!(decode_utf16(&[0xfe, 0xff, 0x00, 0x48, 0x00, 0x69]), "Hi");
    // BOM-only value decodes to empty (BOM stripped, nothing left).
    assert_eq!(decode_utf16(&[0xfe, 0xff]), "");
  }

  #[test]
  fn decode_utf16_strips_le_bom_and_decodes_little_endian() {
    // `Charset.pm:203-204`: a leading `FF FE` (LE) BOM is stripped and the
    // remainder decoded little-endian (`$fmt = 'v*'`) — not garbled.
    assert_eq!(decode_utf16(&[0xff, 0xfe, 0x48, 0x00, 0x69, 0x00]), "Hi");
    // LE BOM with a trailing LE NUL terminator (00 00) — dropped.
    assert_eq!(decode_utf16(&[0xff, 0xfe, 0x48, 0x00, 0x00, 0x00]), "H");
  }

  #[test]
  fn decode_utf16_bom_surrogate_pairs_respect_byte_order() {
    // U+1F600 (😀) = surrogate pair D83D DE00. BE BOM ⇒ big-endian units.
    assert_eq!(
      decode_utf16(&[0xfe, 0xff, 0xd8, 0x3d, 0xde, 0x00]),
      "\u{1f600}"
    );
    // Same code point, LE BOM ⇒ little-endian units (bytes within each u16
    // swapped). A naive BE read here would mis-pair the surrogates.
    assert_eq!(
      decode_utf16(&[0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xde]),
      "\u{1f600}"
    );
  }

  #[test]
  fn decode_timestamp_fixture_value() {
    // Fixture ContainerLastModifyDate bytes: 07 da 0c 14 00 0e 28 38.
    // year = 0x07da = 2010, month=0x0c=12, day=0x14=20, h=0x00, m=0x0e=14,
    // s=0x28=40, frac=0x38=56 ⇒ *4 = 224.
    let bytes = [0x07, 0xda, 0x0c, 0x14, 0x00, 0x0e, 0x28, 0x38];
    assert_eq!(decode_timestamp(&bytes), "2010:12:20 00:14:40.224");
  }

  #[test]
  fn decode_timestamp_out_of_range_is_invalid() {
    // month 0xff (255 > 12) ⇒ Invalid.
    let bytes = [0x07, 0xda, 0xff, 0x14, 0x00, 0x0e, 0x28, 0x38];
    assert_eq!(decode_timestamp(&bytes), "Invalid (0x07daff14000e2838)");
  }

  #[test]
  fn decode_version_type_dot_joins_bytes() {
    // Fixture SDKVersion bytes: 01 02 ⇒ "1.2".
    assert_eq!(decode_version_type(&[0x01, 0x02]), "1.2");
  }

  #[test]
  fn decode_product_version_fixture_value() {
    // Fixture ToolkitVersion bytes: 00 01 00 00 00 01 00 10 00 01.
    // a = [1, 0, 1, 16, 1] ⇒ "1.0.1.16 released".
    let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01];
    assert_eq!(decode_product_version(&bytes), "1.0.1.16 released");
  }

  #[test]
  fn decode_ul_type_true_ul_dotted() {
    // High bit of byte 0 clear (0x06) ⇒ dotted UL notation.
    let bytes = [
      0x06, 0x0e, 0x2b, 0x34, 0x04, 0x01, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00,
      0x00,
    ];
    assert_eq!(
      decode_ul_type(&bytes),
      "060e2b34.0401.0101.01030201.01000000"
    );
  }

  #[test]
  fn decode_ul_type_reversed_guid() {
    // High bit of byte 0 set ⇒ reversed-GUID-in-UL: swap halves, render GUID.
    let bytes = [
      0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f,
    ];
    // reordered = bytes[8..16] ++ bytes[0..8].
    let reordered = [
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07,
    ];
    assert_eq!(decode_ul_type(&bytes), guid_notation(&reordered));
  }

  #[test]
  fn decode_package_id_32_byte_format() {
    // Fixture PackageID bytes (MaterialPackage):
    // 06 0a 2b 34 01 01 01 01 01 01 02 20 13 00 00 00
    // b0 c9 6b 18 dc 45 24 49 aa 52 cc 7b 79 20 28 f7
    let bytes = [
      0x06, 0x0a, 0x2b, 0x34, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x13, 0x00, 0x00,
      0x00, 0xb0, 0xc9, 0x6b, 0x18, 0xdc, 0x45, 0x24, 0x49, 0xaa, 0x52, 0xcc, 0x7b, 0x79, 0x20,
      0x28, 0xf7,
    ];
    assert_eq!(
      decode_package_id(&bytes),
      "060a2b34.0101.0101.01010220 13 000000 b0c96b18-dc45-2449-aa52-cc7b792028f7"
    );
  }

  #[test]
  fn guid_notation_dashed_groups() {
    let bytes = [
      0x70, 0x06, 0xe3, 0x4d, 0x4d, 0x15, 0xaf, 0x46, 0xa7, 0xbc, 0x63, 0xf9, 0x60, 0x79, 0x54,
      0x40,
    ];
    assert_eq!(
      guid_notation(&bytes),
      "7006e34d-4d15-af46-a7bc-63f960795440"
    );
  }

  #[test]
  fn classify_top_level_known_keys() {
    assert_eq!(
      classify_top_level("060e2b34.0205.0101.0d010201.01020100"),
      Some(TopLevel::Header("OpenHeader"))
    );
    assert_eq!(
      classify_top_level("060e2b34.0205.0101.0d010201.01050100"),
      Some(TopLevel::Primer)
    );
    assert_eq!(
      classify_top_level("060e2b34.0253.0101.0d010101.01013b00"),
      Some(TopLevel::LocalSet("Track"))
    );
    assert_eq!(
      classify_top_level("ffffffff.0000.0000.00000000.00000000"),
      None
    );
  }

  #[test]
  fn parse_borrowed_rejects_non_mxf() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(b"not an mxf file at all").is_none());
  }

  #[test]
  fn parse_borrowed_accepts_fixture() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MXF.mxf"
    ))
    .expect("read MXF.mxf fixture");
    let meta = parse_borrowed(&bytes).expect("MXF accepted");
    assert_eq!(meta.header_type(), Some("OpenHeader"));
    // MXFVersion is the first emitted tag (from the header subtable).
    let names: Vec<&str> = meta.entries().iter().map(MxfEntry::name).collect();
    assert!(names.contains(&"MXFVersion"));
    assert!(names.contains(&"TrackName"));
  }

  /// Drive the `MxfMeta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for `mode` and return the
  /// resulting [`TagMap`](crate::tagmap::TagMap) — the production sink path.
  #[cfg(feature = "alloc")]
  fn emit_into_tagmap(meta: &MxfMeta<'_>, mode: crate::emit::ConvMode) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(meta, crate::emit::EmitOptions::g1(mode, false), &mut w);
    w
  }

  #[test]
  fn fixture_emits_expected_tags() {
    use crate::emit::ConvMode;
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MXF.mxf"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(tm.get_str("MXF", "MXFVersion"), Some("1.2".into()));
    assert_eq!(
      tm.get_str("MXF", "ApplicationName"),
      Some("ExifTool".into())
    );
    assert_eq!(
      tm.get_str("MXF", "ContainerLastModifyDate"),
      Some("2010:12:20 00:14:40.228".into())
    );
    assert_eq!(
      tm.get_str("MXF", "ToolkitVersion"),
      Some("1.0.1.16 released".into())
    );
    // Track grouping.
    assert_eq!(
      tm.get_str("Track1", "TrackName"),
      Some("Timecode Track".into())
    );
    assert_eq!(
      tm.get_str("Track2", "TrackName"),
      Some("Sound Track".into())
    );
    assert_eq!(
      tm.get_str("Track1", "ComponentDataDefinition"),
      Some("SMPTE 12M Timecode Track".into())
    );
    assert_eq!(
      tm.get_str("Track2", "ComponentDataDefinition"),
      Some("Sound Essence Track".into())
    );
    // Boolean → "False" string (the serializer coerces to JSON `false`).
    assert_eq!(tm.get_str("Track1", "DropFrame"), Some("False".into()));
  }

  #[test]
  fn fixture_n_mode_raw_scalars() {
    use crate::emit::ConvMode;
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MXF.mxf"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, ConvMode::ValueConv);
    // -n: ComponentDataDefinition is the raw UL string.
    assert_eq!(
      tm.get_str("Track1", "ComponentDataDefinition"),
      Some("060e2b34.0401.0101.01030201.01000000".into())
    );
  }

  #[test]
  fn taggable_group_is_mxf_family0_and_entry_family1() {
    use crate::emit::{ConvMode, Taggable};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MXF.mxf"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tags: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    // Every production entry is visible (the walk pre-filters Unknown rows).
    assert!(tags.iter().all(|t| !t.unknown()));
    // family0 is the constant "MXF" table group; family1 is the per-entry
    // `-G1` key ("MXF" for top-level tags, "Track<N>" for per-track tags).
    assert!(tags.iter().all(|t| t.tag().group_ref().family0() == "MXF"));
    let mxf_version = tags
      .iter()
      .find(|t| t.tag().name() == "MXFVersion")
      .expect("MXFVersion emitted");
    assert_eq!(mxf_version.tag().group_ref().family1(), "MXF");
    let track_name = tags
      .iter()
      .find(|t| t.tag().name() == "TrackName")
      .expect("TrackName emitted");
    assert_eq!(track_name.tag().group_ref().family1(), "Track1");
  }

  /// The golden-pattern engine gate: an `Unknown => 1` entry is YIELDED by
  /// [`Taggable::tags`](crate::emit::Taggable::tags) with `unknown == true`,
  /// but [`run_emission`](crate::emit::run_emission) suppresses it from the
  /// [`TagMap`](crate::tagmap::TagMap) output (`ExifTool.pm:9179`). This
  /// proves the suppression lives in the ENGINE, not the format — production
  /// entries are all visible, so a synthetic `Unknown` entry is used to
  /// exercise the gate.
  #[test]
  fn taggable_yields_unknown_but_engine_suppresses() {
    use crate::emit::{ConvMode, Taggable};
    let meta = MxfMeta {
      entries: std::vec![
        MxfEntry {
          group: SmolStr::new_static(GROUP_MXF),
          name: SmolStr::new_static("MXFVersion"),
          value: MxfValue::Str("1.2".into()),
          unknown: false,
        },
        // An `Unknown => 1` row (e.g. InstanceUID) — decoded for the object
        // tree but suppressed from default output.
        MxfEntry {
          group: SmolStr::new_static(GROUP_MXF),
          name: SmolStr::new_static("InstanceUID"),
          value: MxfValue::Str("060e2b34.deadbeef".into()),
          unknown: true,
        },
      ],
      header_type: None,
      _marker: core::marker::PhantomData,
    };

    // `tags()` yields BOTH entries, the second flagged unknown.
    let tags: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert_eq!(tags.len(), 2);
    let hidden = tags
      .iter()
      .find(|t| t.tag().name() == "InstanceUID")
      .expect("Unknown entry is still yielded by tags()");
    assert!(hidden.unknown(), "the Unknown=>1 entry carries the flag");

    // The engine suppresses it: only the visible tag reaches the sink.
    let tm = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(tm.get_str("MXF", "MXFVersion"), Some("1.2".into()));
    assert!(
      tm.get("MXF", "InstanceUID").is_none(),
      "run_emission must drop the Unknown=>1 tag"
    );
  }

  #[test]
  fn project_populates_single_video_track() {
    use crate::metadata::{Project, TrackKind};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MXF.mxf"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let projected = meta.project();
    // MXF projects to a single video track; the rest of MediaInfo is empty.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Video]);
    assert!(projected.media().has_video());
    assert!(projected.media().duration().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().created().is_none());
    // MXF carries no camera / lens / GPS / capture facts.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  #[test]
  fn deeply_chained_strong_refs_do_not_overflow_the_stack() {
    // Golden-v2 Contract 3a — `set_groups` recurses the file-declared
    // strong-reference graph. The `visited` cycle guard stops a cyclic graph,
    // but a hostile MXF can declare a long ACYCLIC chain of distinct objects
    // (`Preface`→obj1→obj2→…), one per top-level KLV local set, which would
    // recurse to the chain length and overflow the stack (a DoS reachable
    // from a crafted large file: the KLV walk populates `objects`/`prefaces`
    // then `fix_groups` runs). With `MAX_OBJECT_TREE_DEPTH` the descent stops
    // at the cap. 200_000 is far past any real tree (≈6-8 deep), so the cap
    // never trips on a real file (byte-identical output).
    const N: usize = 200_000;
    let mut w = Walker::new();
    for i in 0..N {
      let inst = SmolStr::new(std::format!("obj{i}"));
      let mut obj = ObjInfo {
        name: SmolStr::new("Preface"),
        ..ObjInfo::default()
      };
      if i + 1 < N {
        obj
          .strong_refs
          .push(SmolStr::new(std::format!("obj{}", i + 1)));
      }
      w.objects.insert(inst, obj);
    }
    w.prefaces.push(SmolStr::new("obj0"));
    // The depth budget bounds the recursion; this returns without overflowing.
    fix_groups(&mut w);
  }
}
