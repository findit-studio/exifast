// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::Jpeg2000` — the JUMBF / C2PA box-structure reader (the
//! READ-only subset of `ProcessJpeg2000Box` + `ProcessJUMB` + `ProcessJUMD`,
//! `Jpeg2000.pm` 13.59), **Phase 1: structure + binary boxes only**.
//!
//! ## What JUMBF is, and where it enters
//!
//! A PNG `caBX` chunk (`PNG.pm:343-346`: `caBX` → `Jpeg2000::Main` SubDirectory)
//! carries a JUMBF box stream — ISO-BMFF boxes: a 4-byte big-endian length, a
//! 4-byte type, then the payload, recursively. C2PA (content provenance) rides
//! this: `jumb` superboxes nest `jumb`→`jumd`→content (`json`/`cbor`/`bfdb`+
//! `bidb`), ~3-4 deep. exifast's PNG [`dispatch_chunk`](crate::formats::png)
//! gains a `caBX` arm that hands the chunk payload to [`process`].
//!
//! ## Phase boundary
//!
//! Phase 1 ported the box TREE walk + the `jumd` description layer + the binary
//! content boxes (`bfdb`/`bidb`/`c2sh`). **Phase 2 (#142)** adds the JSON
//! content decoder ([`json`], `JSON::Main` / `ProcessJSON`): a `json` box now
//! decodes its document into flattened `JSON:*` tags. The CBOR (`cbor`) content
//! decoder (`CBOR::Main`) is the remaining Phase 3: a `cbor` box is recognized
//! and its bounds validated, but it still emits NO tags. So a fixture that must
//! stay byte-exact vs bundled without the CBOR decoder may carry structure +
//! binary + `json` content, but NOT `cbor` CONTENT (which bundled WOULD decode).
//!
//! ## Part A — the box-tree walker ([`JumbfWalker::walk`])
//!
//! The read subset of `ProcessJpeg2000Box` (`Jpeg2000.pm:1016-1359`): for each
//! box, read `boxLen` (4 BE, INCLUDES the 8-byte header) + `boxID` (4); a
//! `boxLen == 1` means an extended 64-bit size follows (`Jpeg2000.pm:1102-1116`);
//! `boxLen == 0` means the box runs to the END of the enclosing data
//! (`Jpeg2000.pm:1117`/`:1137`). The 8-byte header read MIRRORS the QuickTime
//! atom header ([`crate::formats::quicktime`] `read_atom_header` — byte-identical
//! BE-length + extended-`1` + to-end-`0` logic), written from scratch here
//! because the QuickTime reader is `QtTable`-coupled. A `Jumb`/`Asoc` box
//! RECURSES (a new walk over its payload); a `Jumd` box runs [`process_jumd`]; a
//! FORMAT box (`bfdb`/`c2sh`) emits a value; `bidb` emits the byte-count
//! placeholder. Two robustness bounds beyond ExifTool:
//! * a **depth budget** ([`MAX_BOX_DEPTH`], the QuickTime `MAX_ATOM_DEPTH`
//!   pattern) caps `jumb`/`asoc` recursion (real C2PA is ~3-4 deep).
//! * **per-field bounds** — every length/slice is a checked `.get()`, so a
//!   truncated or crafted box never reads out of range (`Jpeg2000.pm` trusts the
//!   declared `boxLen`; exifast clamps it to the available data).
//!
//! ## Part B — `ProcessJUMB` ([`JumbfWalker::process_jumb`], `Jpeg2000.pm:777`)
//!
//! The `jumb` superbox manages the sub-document axis: it pushes/increments the
//! `jumd_level` stack and sets `DOC_NUM = join '-', @jumd_level` (the
//! arbitrarily deep `Doc<N>` / `Doc<N>-<M>` / `Doc<N>-<M>-<P>` … axis,
//! `SET_GROUP0 = 'JUMBF'`), recurses, then pops. exifast's
//! [`crate::value::Group`] carries the `Doc<N>` axis as a first ordinal plus a
//! pre-rendered N-level sub-path tail ([`crate::value::Group::with_subpath`] —
//! the generalization of the GoPro two-level `with_subdoc`); the CAMM / timed-
//! sample producers drive the shallow form, JUMBF is the NEW N-level producer.
//! The first top-level `jumb` opens `Doc<DOC_COUNT+1>`; a nested `jumb`
//! increments the LAST level (`Doc1`, `Doc1-1`, `Doc1-1-1`, …). Real C2PA nests
//! `jumb`→`jumb`→`jumb`→content, so a leaf is `Doc1-1-1`; the FULL path is
//! carried in both the `-G3` render and the dedup key so two distinct nested
//! superbox contents never collide (oracle-verified vs bundled 13.59).
//!
//! ## Part C — `ProcessJUMD` ([`JumbfWalker::process_jumd`], `Jpeg2000.pm:803`)
//!
//! The `jumd` description box: a 16-byte type-UUID @ 0, a 1-byte `toggles`, then
//! optionally a NUL-terminated `label` (bit `0x02`), a 4-byte `id` (bit `0x04`),
//! a 32-byte `signature` (bit `0x08`), and trailing private data (a `c2sh` box).
//! Emits the `%Jpeg2000::JUMD` tags (`Jpeg2000.pm:739-771`, GROUPS `0/1 =>
//! JUMBF`): `JUMDType` (the UUID, see [`render_type`]), `JUMDToggles` (a
//! `Unknown=>1` BITMASK — suppressed from default output), `JUMDLabel`, `JUMDID`,
//! `JUMDSignature`. When a label is present its sanitized form
//! ([`tables::sanitize_label`]) becomes the active `JUMBFLabel`, which RENAMES
//! the following `bfdb`/`bidb`/`c2sh` content tags (`Jpeg2000.pm:1205-1212`).
//!
//! ## Part D — the binary / preview content boxes
//!
//! `bfdb` (`BinaryDataType`, group `Jpeg2000`): the MIME type + optional file
//! name (`Jpeg2000.pm:425-431`, ValueConv drops the toggle byte, trims trailing
//! NULs, joins a `type, name` pair). `bidb` (`BinaryData`, group `Jpeg2000`,
//! `Groups => { 2 => 'Preview' }`): the embedded preview payload — the byte-count
//! placeholder (`Binary => 1`, the bytes are never retained). `c2sh`
//! (`C2PASaltHash`, group `Jpeg2000`): the hex-encoded salt. All three live in
//! `%Jpeg2000::Main` (default group `Jpeg2000`, NOT `JUMBF`), so they emit under
//! `Jpeg2000:*` even inside a `jumb` — UNLESS a JUMBFLabel renames them
//! (`<Label>Type`/`<Label>Data`/`<Label>Salt`, keeping the `Jpeg2000` group).
//!
//! ## Part E — the golden architecture
//!
//! [`JumbfMeta`] is the typed L1 ([`GeoTiffMeta`](crate::exif::geotiff) /
//! [`MngMeta`](crate::exif::mng) precedent): a flat list of decoded entries each
//! carrying its `Doc<N>` ordinal + family-0/1 group, emitted via its
//! [`Taggable`](crate::emit::Taggable) impl. D8: no public fields (in-crate
//! accessors only); per-field availability (a tag is emitted iff its bytes are
//! in range).

mod json;
mod tables;
#[cfg(test)]
mod tests;

use crate::exif::ifd::{ByteOrder, get_u8, get_u32};
use smol_str::SmolStr;
use std::{string::String, vec::Vec};
use tables::BoxKind;

/// JUMBF boxes are big-endian (ISO-BMFF, like QuickTime / JPEG 2000).
const JUMBF_ORDER: ByteOrder = ByteOrder::Big;

/// Family-0 / family-1 group of the `%Jpeg2000::JUMD` description tags
/// (`Jpeg2000.pm:741`, `GROUPS => { 0 => 'JUMBF', 1 => 'JUMBF' }`).
const GROUP_JUMBF: &str = "JUMBF";

/// Family-0 / family-1 group of the `bfdb`/`bidb`/`c2sh` content tags — they
/// live in `%Jpeg2000::Main` whose default group is `Jpeg2000`, so they emit
/// under `Jpeg2000:*` even when nested in a `jumb` superbox (oracle-verified vs
/// bundled 13.59).
const GROUP_JPEG2000: &str = "Jpeg2000";

/// Family-0 / family-1 group of the flattened `json` content-box tags
/// (`JSON::Main`'s `GROUPS => { 0 => 'JSON', 1 => 'JSON' }`, `JSON.pm:23`). The
/// JSON tags emit under `JSON:*` (on the box's `Doc<N>` axis) regardless of any
/// active JUMBFLabel (oracle-verified vs bundled 13.59).
const GROUP_JSON: &str = "JSON";

/// Beyond-faithful recursion cap on `jumb`/`asoc` box nesting (the QuickTime
/// [`MAX_ATOM_DEPTH`](crate::formats::quicktime) pattern). `ProcessJpeg2000Box`
/// recurses a SubDirectory box with no depth guard (`Jpeg2000.pm:1327`); a
/// crafted file could nest `jumb` boxes thousands deep and blow the stack. Real
/// C2PA nests `caBX`→`jumb`→`jumb`→`jumb`→content ~3-4 deep, so this bound is far
/// above any genuine file. When the limit is hit the box (and its descendants)
/// are NOT recursed — a single [`JumbfWarning::TooDeep`] is raised.
const MAX_BOX_DEPTH: usize = 16;

/// The 8-byte JUMBF box header length (`hdrLen = 8`, `Jpeg2000.pm:1067`).
const BOX_HEADER_LEN: usize = 8;

/// A `$et->Warn(...)` raised by the JUMBF walker. Surfaced via the
/// [`Diagnose`](crate::diagnostics::Diagnose) channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JumbfWarning {
  /// The box tree nested past [`MAX_BOX_DEPTH`] (a beyond-faithful guard).
  TooDeep,
  /// `Truncated JPEG 2000 box` (`Jpeg2000.pm:1350`) — the GENERIC box-structure
  /// truncation `$et->Warn` raised once at the end of `ProcessJpeg2000Box` for
  /// every `$err = ''` break: a box header that does not fit the remaining data
  /// (a short tail < 8 bytes), an extended-length (`boxLen == 1`) header whose
  /// 8 extra size bytes do not fit, or a box whose claimed payload runs past the
  /// buffer (`$pos + $boxLen > $dirEnd`, `Jpeg2000.pm:1170`). Valid boxes parsed
  /// BEFORE the malformed one still emit (faithful partial progress, oracle-
  /// verified vs bundled 13.59).
  BoxTruncated,
  /// `Invalid JPEG 2000 box length` (`Jpeg2000.pm:1141`) — a declared `boxLen`
  /// in `1..hdrLen` (so `boxLen - hdrLen < 0`): a full 8-byte header is present
  /// but the length is smaller than the header itself (incl. the extended-size
  /// `lo < 16` case). Distinct from [`Self::BoxTruncated`]: a header too short
  /// to even READ a length is `BoxTruncated`; a readable-but-nonsensical length
  /// is `InvalidBoxLength` (oracle-verified vs bundled 13.59).
  InvalidBoxLength,
  /// `Can't currently handle JPEG 2000 boxes > 4 GB` (`Jpeg2000.pm:1114`) — an
  /// extended-length (`boxLen == 1`) box whose 64-bit size has a non-zero HIGH
  /// word (a >4 GB box ExifTool refuses; no such box fits a PNG chunk).
  Over4Gb,
  /// `Truncated JUMD directory` (`Jpeg2000.pm:811`) — a `jumd` box shorter than
  /// the 17-byte minimum (16-byte UUID + 1-byte toggles).
  TruncatedJumd,
  /// `Missing JUMD label terminator` (`Jpeg2000.pm:819`) — the label toggle was
  /// set but no NUL terminator was found.
  MissingLabelTerminator,
  /// `Missing JUMD ID` (`Jpeg2000.pm:835`) — the ID toggle was set but fewer
  /// than 4 bytes remain.
  MissingId,
  /// `Missing JUMD signature` (`Jpeg2000.pm:840`) — the signature toggle was set
  /// but fewer than 32 bytes remain.
  MissingSignature,
  /// `Unrecognized <Name> box` (`Jpeg2000.pm:1330-1332`) — a `json` content box
  /// whose `JSON::Main` SubDirectory processor (`ProcessJSON`) returned 0: the
  /// document did not parse to a hash / array-of-hashes (a bare scalar, an
  /// array with no object, or a syntax error). `<Name>` is the content tag's
  /// name — `JSONData` by default, or the active JUMBFLabel (the renamed
  /// `JSONData`, since `json` carries `BlockExtract`) — so the message is
  /// carried as an owned [`SmolStr`].
  UnrecognizedJsonBox(SmolStr),
}

impl JumbfWarning {
  /// The exact bundled warning text (`$et->Warn(...)`). Most are fixed
  /// `&'static str`; [`Self::UnrecognizedJsonBox`] interpolates the content
  /// tag's name (`Unrecognized <Name> box`), so the result is a [`SmolStr`].
  pub(crate) fn message(&self) -> SmolStr {
    match self {
      Self::TooDeep => SmolStr::new_static("JUMBF box nesting too deep"),
      Self::BoxTruncated => SmolStr::new_static("Truncated JPEG 2000 box"),
      Self::InvalidBoxLength => SmolStr::new_static("Invalid JPEG 2000 box length"),
      Self::Over4Gb => SmolStr::new_static("Can't currently handle JPEG 2000 boxes > 4 GB"),
      Self::TruncatedJumd => SmolStr::new_static("Truncated JUMD directory"),
      Self::MissingLabelTerminator => SmolStr::new_static("Missing JUMD label terminator"),
      Self::MissingId => SmolStr::new_static("Missing JUMD ID"),
      Self::MissingSignature => SmolStr::new_static("Missing JUMD signature"),
      // `$et->Warn("Unrecognized $$tagInfo{Name} box")` (`Jpeg2000.pm:1332`).
      Self::UnrecognizedJsonBox(name) => SmolStr::from(std::format!("Unrecognized {name} box")),
    }
  }
}

/// One decoded JUMBF tag, captured at walk position, ready to render.
///
/// The value is stored already in its `-n` (ValueConv) form where the two modes
/// AGREE; the only PrintConv-vs-ValueConv split is [`Self::JumdType`]'s UUID
/// formatting and [`Self::JumdToggles`]'s BITMASK, both rendered per-mode in
/// [`JumbfMeta::tags`].
#[derive(Debug, Clone, PartialEq)]
enum JumbfValue {
  /// `JUMDType` — the 16-byte type-UUID, stored as its lowercase hex (the
  /// `unpack "H*"` ValueConv, `Jpeg2000.pm:745`). `-n` renders the raw hex; `-j`
  /// applies the `Jpeg2000.pm:746-752` split + ASCII-detect (see [`render_type`]).
  JumdType(SmolStr),
  /// `JUMDToggles` — the raw toggle byte. `Unknown=>1`, so SUPPRESSED from
  /// default output; `-n` renders the raw int, `-j -u` the BITMASK.
  JumdToggles(u8),
  /// A plain string value, identical in both modes (`JUMDLabel`,
  /// `bfdb`/`C2PASaltHash`, the renamed `<Label>Type`/`<Label>Salt`).
  Text(SmolStr),
  /// `JUMDID` — the 4-byte int32u (no PrintConv).
  JumdId(u32),
  /// `JUMDSignature` — the 32-byte signature as hex (`unpack "H*"`,
  /// `Jpeg2000.pm:770`).
  Signature(SmolStr),
  /// `bidb`/`<Label>Data` — the binary payload LENGTH (the `(Binary data N
  /// bytes …)` placeholder; the bytes are never retained).
  BinaryLen(u64),
  /// A flattened `json` content-box value (`JSON::Main`, Phase 2,
  /// [`json::decode`]): a top-level JSON key's already-converted [`TagValue`]
  /// — a scalar, a [`TagValue::List`] (array), or a [`TagValue::Map`] (object),
  /// identical in both `-n` and `-j` modes (JSON values have no PrintConv).
  Json(crate::value::TagValue),
}

/// One decoded JUMBF tag: its family-0/1 group, name, value, the full `Doc<N>`
/// axis (`doc` + the N-level `doc_subpath`), and the `Unknown=>1` flag.
#[derive(Debug, Clone, PartialEq)]
struct JumbfTag {
  /// Family-0 group ([`GROUP_JUMBF`] for JUMD tags, [`GROUP_JPEG2000`] for
  /// content tags).
  family0: &'static str,
  /// Family-1 group (same string as `family0` for JUMBF; `Jpeg2000` for content).
  family1: &'static str,
  /// The tag name (possibly a renamed `<Label>Type`/…).
  name: SmolStr,
  /// The decoded value.
  value: JumbfValue,
  /// The `Doc<N>` ordinal — the FIRST component of `DOC_NUM = join '-',
  /// @{$$et{jumd_level}}` (`Jpeg2000.pm:786`). `0` = Main — never `0` in
  /// practice, a JUMBF tag is always inside a `jumb`.
  doc: u32,
  /// The pre-rendered dash-joined TAIL of `DOC_NUM` beyond the first `doc`
  /// component — `""` for a top-level `jumb` (`Doc<N>`), `"-<M>"` for one
  /// nesting level (`Doc<N>-<M>`), `"-<M>-<P>"` for two (`Doc<N>-<M>-<P>`), …
  /// Real C2PA nests `jumb`→`jumb`→`jumb`→content, so a leaf carries `"-1-1"`
  /// (`Doc1-1-1`). Carrying the WHOLE tail (not a single second ordinal) is what
  /// keeps a deep nest distinct from a shallow one in both the `-G3` render and
  /// the dedup key.
  doc_subpath: SmolStr,
  /// `Unknown=>1` (`JUMDToggles` only) — suppressed from default output.
  unknown: bool,
}

/// The typed JUMBF / C2PA metadata (golden-pattern L1) — the decoded tags in
/// walk order plus any walker warnings. Built by [`process`] from a PNG `caBX`
/// chunk payload; emitted via its [`Taggable`](crate::emit::Taggable) impl under
/// groups `JUMBF` (JUMD tags) and `Jpeg2000` (content tags) on the `Doc<N>`
/// axis, and its warnings via the [`Diagnose`](crate::diagnostics::Diagnose)
/// channel.
///
/// D8: no public fields — the tags/warnings are read by the in-crate emitter.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JumbfMeta {
  /// The decoded tags in walk order. The `TagMap` dedup applied by
  /// [`run_emission`](crate::emit::run_emission) keeps the LAST of any duplicate
  /// `(doc, doc_subpath, family1, name)` — faithful to ExifTool's last-wins;
  /// the full `doc_subpath` in the key keeps a deep nest (`Doc1-1-1`) distinct
  /// from a shallow one (`Doc1-1`).
  tags: Vec<JumbfTag>,
  /// `$et->Warn(...)` messages in emission order — surfaced via the
  /// [`Diagnose`](crate::diagnostics::Diagnose) channel.
  warnings: Vec<JumbfWarning>,
}

impl JumbfMeta {
  /// An empty `JumbfMeta`.
  #[must_use]
  pub(crate) const fn new() -> Self {
    Self {
      tags: Vec::new(),
      warnings: Vec::new(),
    }
  }

  /// `true` IFF nothing was decoded — no tags AND no warnings. The caller drops
  /// an empty `JumbfMeta` (a `caBX` whose box stream recognized nothing) so the
  /// PNG output stays byte-identical.
  #[must_use]
  pub(crate) fn is_empty(&self) -> bool {
    self.tags.is_empty() && self.warnings.is_empty()
  }

  /// The walker warnings, in emission order.
  pub(crate) fn warnings(&self) -> &[JumbfWarning] {
    &self.warnings
  }
}

/// Decode a PNG `caBX` chunk payload (a JUMBF box stream) into a [`JumbfMeta`]
/// (`PNG.pm:343-346` → `Jpeg2000::Main` → [`JumbfWalker::walk`] over the whole
/// payload at depth 0). Returns the decoded meta (possibly [`JumbfMeta::is_empty`]
/// for a payload that recognized nothing).
#[must_use]
pub(crate) fn process(cabx: &[u8]) -> JumbfMeta {
  let mut walker = JumbfWalker {
    meta: JumbfMeta::new(),
    jumd_level: Vec::new(),
    doc_count: 0,
    cur_label: None,
  };
  walker.walk(cabx, 0);
  walker.meta
}

/// The recursive JUMBF box-tree walker (the `ProcessJpeg2000Box` read subset),
/// carrying the accumulating [`JumbfMeta`] and the `jumd_level` sub-document
/// stack (`$$et{jumd_level}`, `Jpeg2000.pm:780-794`).
struct JumbfWalker {
  /// The accumulating decoded metadata.
  meta: JumbfMeta,
  /// The sub-document level stack — `ProcessJUMB` pushes a `0` before recursing
  /// and increments the LAST entry on entry. The first component is the `Doc<N>`
  /// ordinal; each FURTHER nesting level appends another component (`Doc<N>-<M>`,
  /// `Doc<N>-<M>-<P>`, …) — the depth is UNBOUNDED (real C2PA nests 3-4 deep).
  /// `DOC_NUM = join '-', @jumd_level` (`Jpeg2000.pm:786`), recovered by
  /// [`JumbfWalker::current_docpath`]. RESET between top-level superboxes
  /// (`delete $$et{jumd_level}`, `Jpeg2000.pm:793`).
  jumd_level: Vec<u32>,
  /// The PERSISTENT document counter (`$$et{DOC_COUNT}`, `Jpeg2000.pm:783`):
  /// `++DOC_COUNT` opens each NEW top-level sub-document, and — UNLIKE
  /// `jumd_level` — it is never reset, so two sibling top-level `jumb` superboxes
  /// become `Doc1`, `Doc2` (oracle-verified vs bundled 13.59). exifast is
  /// JUMBF-only on the PNG path, so this is a self-contained counter (a real
  /// ExifTool shares `DOC_COUNT` across all `-ee` producers; the PNG `caBX` path
  /// has no other producer).
  doc_count: u32,
  /// The active `JUMBFLabel` (`$$et{JUMBFLabel}`, `Jpeg2000.pm:831`): the
  /// sanitized label of the most recent `jumd` that carried one, used to RENAME
  /// the following `bfdb`/`bidb`/`c2sh` content tags (`Jpeg2000.pm:1205-1212`).
  /// Reset to `None` at each new `jumd` (`delete $$et{JUMBFLabel}`,
  /// `Jpeg2000.pm:810`) and cleared when a `jumb` superbox closes (`Jpeg2000.pm:790`).
  cur_label: Option<SmolStr>,
}

impl JumbfWalker {
  /// Walk a JUMBF box stream (`data`) at recursion `depth` (the
  /// `ProcessJpeg2000Box` box loop, `Jpeg2000.pm:1064-1348`), dispatching each
  /// box by [`tables::lookup`]. Faithful to ExifTool's `$err`/`$et->Warn`
  /// truncation handling: a box header / extended size / payload that does not
  /// fit STOPS the loop AND raises a single box-structure warning
  /// (`Jpeg2000.pm:1349-1356` warns ONCE at the end with whatever `$err` the
  /// break set). Valid boxes parsed before the malformed one still emit
  /// (partial progress). The warning kinds mirror the exact `$err` paths:
  /// * a short tail (< 8 bytes, not an exact end), an extended-size header whose
  ///   8 size bytes do not fit, or a payload that overruns the buffer ⇒
  ///   `$err = ''` ⇒ [`JumbfWarning::BoxTruncated`]
  ///   (`Jpeg2000.pm:1080`/`:1112`/`:1170`/`:1350`);
  /// * a declared `boxLen` in `1..hdrLen` (a readable header with a length below
  ///   the header itself, incl. extended-size `lo < 16`) ⇒
  ///   [`JumbfWarning::InvalidBoxLength`] (`Jpeg2000.pm:1141`);
  /// * an extended-size high word set ⇒ [`JumbfWarning::Over4Gb`]
  ///   (`Jpeg2000.pm:1114`).
  ///
  /// An EXACTLY-consumed buffer (`$pos == $dirEnd`) ends cleanly with NO warning
  /// (`Jpeg2000.pm:1080` `$err = '' unless $pos == $dirEnd`).
  fn walk(&mut self, data: &[u8], depth: usize) {
    let mut pos = 0usize;
    let end = data.len();
    loop {
      // `$pos >= $dirEnd - $hdrLen ⇒ last` (`Jpeg2000.pm:1079`), evaluated as
      // `$pos + $hdrLen > $dirEnd` to avoid the unsigned underflow when `$dirEnd
      // < $hdrLen`. An EXACT end (`$pos == $dirEnd`) is clean; any other short
      // tail (fewer than the 8-byte header remain) is a truncation — the header
      // is NOT even read (matching ExifTool, which breaks before `unpack`).
      if pos + BOX_HEADER_LEN > end {
        if pos != end {
          self.warn(JumbfWarning::BoxTruncated);
        }
        break;
      }
      // The full 8-byte header is in range. `boxLen` INCLUDES the header
      // (`Jpeg2000.pm:1083`).
      let Some(boxlen_raw) = get_u32(data, pos, JUMBF_ORDER) else {
        break;
      };
      let Some(box_id_slice) = data.get(pos + 4..pos + BOX_HEADER_LEN) else {
        break;
      };
      let box_id: [u8; 4] = match box_id_slice.try_into() {
        Ok(a) => a,
        Err(_) => break,
      };
      let mut content_start = pos + BOX_HEADER_LEN;
      let content_len: usize = match boxlen_raw {
        // Extended 64-bit size: an 8-byte int follows the header
        // (`Jpeg2000.pm:1102-1116`).
        1 => {
          // `$pos > $dirEnd - 8 ⇒ $err = '', last` (`Jpeg2000.pm:1112`): the 8
          // size bytes must fit the remaining data, else a truncation.
          let (Some(hi), Some(lo)) = (
            get_u32(data, content_start, JUMBF_ORDER),
            get_u32(data, content_start + 4, JUMBF_ORDER),
          ) else {
            self.warn(JumbfWarning::BoxTruncated);
            break;
          };
          // `$hi and $err = "Can't currently handle JPEG 2000 boxes > 4 GB"`
          // (`Jpeg2000.pm:1114`).
          if hi != 0 {
            self.warn(JumbfWarning::Over4Gb);
            break;
          }
          content_start += 8;
          // `boxLen = lo - hdrLen` (hdrLen now 16); `boxLen < 0` ⇒ an
          // `Invalid JPEG 2000 box length` (`Jpeg2000.pm:1141`).
          match (lo as usize).checked_sub(BOX_HEADER_LEN + 8) {
            Some(n) => n,
            None => {
              self.warn(JumbfWarning::InvalidBoxLength);
              break;
            }
          }
        }
        // To-end: the box runs to the end of `data` (`Jpeg2000.pm:1117`/`:1137`).
        0 => end.saturating_sub(content_start),
        // Ordinary: `boxLen - hdrLen` (`Jpeg2000.pm:1139`); a value below the
        // header length (`boxLen < 0` at `Jpeg2000.pm:1141`) is an
        // `Invalid JPEG 2000 box length`.
        n => match (n as usize).checked_sub(BOX_HEADER_LEN) {
          Some(c) => c,
          None => {
            self.warn(JumbfWarning::InvalidBoxLength);
            break;
          }
        },
      };
      // The payload must be in range (`$pos + $boxLen > $dirEnd ⇒ $err = '',
      // last`, `Jpeg2000.pm:1170`) — a claimed payload past the buffer is a
      // truncation.
      let Some(content) = data.get(content_start..content_start + content_len) else {
        self.warn(JumbfWarning::BoxTruncated);
        break;
      };
      // Advance to the next box BEFORE dispatching (the recursion borrows
      // `content`, a sub-slice — `pos` is independent).
      pos = content_start + content_len;
      self.dispatch_box(&box_id, content, depth);
    }
  }

  /// Push a `$et->Warn(...)` (de-noises the repeated `self.meta.warnings.push`
  /// call sites).
  fn warn(&mut self, w: JumbfWarning) {
    self.meta.warnings.push(w);
  }

  /// Dispatch one resolved box (`box_id` + its `content` payload) at `depth` —
  /// the `$tagInfo` switch in `ProcessJpeg2000Box` (`Jpeg2000.pm:1142-1347`). An
  /// unrecognized id is SKIPPED (the walker already advanced past it).
  fn dispatch_box(&mut self, box_id: &[u8; 4], content: &[u8], depth: usize) {
    let Some(kind) = tables::lookup(box_id) else {
      return;
    };
    match kind {
      // SubDirectory boxes — recurse (with the depth guard).
      BoxKind::Jumb => self.process_jumb(content, depth),
      BoxKind::Asoc => self.recurse(content, depth),
      // The description box (carries `depth` so its trailing-private box stream
      // recurses under the SAME depth budget, never resetting to 0).
      BoxKind::Jumd => self.process_jumd(content, depth),
      // Content boxes (group `Jpeg2000`, possibly renamed by a JUMBFLabel).
      BoxKind::Bfdb => self.process_bfdb(content),
      BoxKind::Bidb => self.process_bidb(content),
      BoxKind::C2sh => self.process_c2sh(content),
      // Phase 2 (#142): a `json` content box decodes through `JSON::Main`
      // ([`process_json`]) into flattened `JSON:*` tags.
      BoxKind::Json => self.process_json(content),
      // Phase 3: a `cbor` content box is RECOGNIZED and traversed (its bounds
      // were validated in `walk`) but its decoder (`CBOR::Main`) is deferred —
      // it emits NO tags here.
      BoxKind::Cbor => {}
    }
  }

  /// Recurse into a SubDirectory box's payload, honoring [`MAX_BOX_DEPTH`].
  fn recurse(&mut self, content: &[u8], depth: usize) {
    if depth + 1 > MAX_BOX_DEPTH {
      self.warn(JumbfWarning::TooDeep);
      return;
    }
    self.walk(content, depth + 1);
  }

  /// `ProcessJUMB` (`Jpeg2000.pm:777-797`) — the `jumb` superbox: manage the
  /// sub-document axis, then recurse. On the FIRST top-level `jumb` open a new
  /// `Doc<N>` (`jumd_level = [++DOC_COUNT]`); on a nested `jumb` increment the
  /// last level. Push a `0` (the placeholder the next nested `jumb` increments),
  /// recurse, then pop — so a sibling `jumb` re-uses the parent's level.
  fn process_jumb(&mut self, content: &[u8], depth: usize) {
    if let Some(last) = self.jumd_level.last_mut() {
      // `++$$et{jumd_level}[-1]` — bump the current sub-document number.
      *last += 1;
    } else {
      // `$$et{jumd_level} = [ ++$$et{DOC_COUNT} ]` — a new top-level
      // sub-document opened from the PERSISTENT counter. The first top-level
      // `jumb` is `Doc1`, the next SIBLING `Doc2`, … (the stack is reset between
      // siblings but `DOC_COUNT` is not).
      self.doc_count += 1;
      self.jumd_level.push(self.doc_count);
    }
    // `push @{$$et{jumd_level}}, 0` — the slot the next nested `jumb`
    // increments (so a nested `jumb` becomes `Doc<N>-1`, `Doc<N>-2`, …).
    self.jumd_level.push(0);
    self.recurse(content, depth);
    // `delete $$et{JUMBFLabel}` (`Jpeg2000.pm:790`) — the rename context does not
    // escape the superbox.
    self.cur_label = None;
    // `pop @{$$et{jumd_level}}` — drop the nested slot.
    self.jumd_level.pop();
    // `if (@{$$et{jumd_level}} < 2) { delete $$et{jumd_level} }` — once the stack
    // holds only the single top-level ordinal, clear it so the NEXT top-level
    // `jumb` opens a fresh `Doc<N>` (`Jpeg2000.pm:792-795`).
    if self.jumd_level.len() < 2 {
      self.jumd_level.clear();
    }
  }

  /// The FULL `DOC_NUM` of the CURRENT box (`join '-', @{$$et{jumd_level}}`,
  /// `Jpeg2000.pm:786`), split into `(doc, doc_subpath)`: the first level, and
  /// the pre-rendered dash-joined tail (`""`, `"-<M>"`, `"-<M>-<P>"`, …). A
  /// JUMBF tag is always emitted while inside a `jumb`, so the stack is `[doc]`
  /// (top-level) or `[doc, sub, …]` (nested) — the FULL depth is preserved
  /// (no collapse), so a 3+-level C2PA nest emits as a distinct `Doc1-1-1`.
  fn current_docpath(&self) -> (u32, SmolStr) {
    // While processing a `jumd`/content box inside a `jumb`, the trailing slot
    // (the placeholder `process_jumb` pushed for the NEXT nested `jumb`) is `0`
    // and not part of this box's `DOC_NUM` — ExifTool sets `DOC_NUM` from
    // `@jumd_level` BEFORE pushing that `0` (`Jpeg2000.pm:786-787`), so drop a
    // single trailing `0` to recover the value in force during this recursion.
    let levels: &[u32] = match self.jumd_level.as_slice() {
      [head @ .., 0] => head,
      all => all,
    };
    let Some((&doc, rest)) = levels.split_first() else {
      // Empty stack ⇒ Main (no JUMBF tag is emitted here in practice).
      return (0, SmolStr::default());
    };
    if rest.is_empty() {
      return (doc, SmolStr::default());
    }
    // `join '-'` the remaining levels, each prefixed by `-` (the dash-joined
    // TAIL after the first `doc` component).
    use core::fmt::Write;
    let mut subpath = String::new();
    for level in rest {
      let _ = write!(subpath, "-{level}");
    }
    (doc, SmolStr::from(subpath))
  }

  /// `ProcessJUMD` (`Jpeg2000.pm:803-861`) — the `jumd` description box. Emits
  /// `JUMDType`/`JUMDToggles`/`JUMDLabel`/`JUMDID`/`JUMDSignature` per the present
  /// toggle bits, sets the active `JUMBFLabel` when a label is present, then
  /// processes any trailing private data (a `c2sh` box). Per-field bounds: a
  /// truncated box raises the matching `Missing …` warning and STOPS (the
  /// `… , return 0` early-outs). `depth` is the box-tree depth at which this
  /// `jumd` was dispatched — threaded so the trailing-private box stream recurses
  /// under the SAME [`MAX_BOX_DEPTH`] budget.
  fn process_jumd(&mut self, content: &[u8], depth: usize) {
    let (doc, doc_subpath) = self.current_docpath();
    // Clear any stale JUMBFLabel from a previous `jumd` (`delete
    // $$et{JUMBFLabel}` at `Jpeg2000.pm:810`); a new `jumd` resets the rename
    // context.
    self.cur_label = None;
    // `$$dirInfo{DirLen} < 17 and Warn 'Truncated JUMD directory', return 0`.
    if content.len() < 17 {
      self.warn(JumbfWarning::TruncatedJumd);
      return;
    }
    // The 16-byte type-UUID @ 0 (`HandleTag 'type', substr($val,0,16)`,
    // `Jpeg2000.pm:813`). The `len() < 17` guard above already proves the slice
    // is in range; the checked `.get()` keeps the module panic-safe by
    // construction (`exif/mod.rs` `#![deny(clippy::indexing_slicing)]`).
    let Some(uuid) = content.get(0..16) else {
      return;
    };
    self.push_jumd_type(uuid, doc, doc_subpath.clone());
    // The toggle byte @ 16 (`Get8u`, `Jpeg2000.pm:815`).
    let flags = get_u8(content, 16).unwrap_or(0);
    self.push_tag(JumbfTag {
      family0: GROUP_JUMBF,
      family1: GROUP_JUMBF,
      name: SmolStr::new("JUMDToggles"),
      value: JumbfValue::JumdToggles(flags),
      doc,
      doc_subpath: doc_subpath.clone(),
      unknown: true,
    });
    let mut pos = 17usize;
    let end = content.len();
    // Label (bit 0x02, `Jpeg2000.pm:817-833`): NUL-terminated.
    if flags & 0x02 != 0 {
      let rest = content.get(pos..).unwrap_or(&[]);
      let Some(nul) = rest.iter().position(|&b| b == 0) else {
        self.warn(JumbfWarning::MissingLabelTerminator);
        return;
      };
      let label_bytes = rest.get(..nul).unwrap_or(rest);
      let label = crate::convert::fix_utf8(label_bytes);
      self.push_tag(JumbfTag {
        family0: GROUP_JUMBF,
        family1: GROUP_JUMBF,
        name: SmolStr::new("JUMDLabel"),
        value: JumbfValue::Text(SmolStr::from(label.as_str())),
        doc,
        doc_subpath: doc_subpath.clone(),
        unknown: false,
      });
      // The sanitized JUMBFLabel renames the following content tags
      // (`Jpeg2000.pm:824-831`); an EMPTY label leaves the rename context unset.
      if !label_bytes.is_empty() {
        self.cur_label = tables::sanitize_label(&label).map(SmolStr::from);
      }
      pos += nul + 1; // past the label + its NUL terminator
    }
    // ID (bit 0x04, `Jpeg2000.pm:834-838`): a 4-byte int32u.
    if flags & 0x04 != 0 {
      if pos + 4 > end {
        self.warn(JumbfWarning::MissingId);
        return;
      }
      let id = get_u32(content, pos, JUMBF_ORDER).unwrap_or(0);
      self.push_tag(JumbfTag {
        family0: GROUP_JUMBF,
        family1: GROUP_JUMBF,
        name: SmolStr::new("JUMDID"),
        value: JumbfValue::JumdId(id),
        doc,
        doc_subpath: doc_subpath.clone(),
        unknown: false,
      });
      pos += 4;
    }
    // Signature (bit 0x08, `Jpeg2000.pm:839-843`): 32 bytes, hex-encoded.
    if flags & 0x08 != 0 {
      let Some(sig) = content.get(pos..pos + 32) else {
        self.warn(JumbfWarning::MissingSignature);
        return;
      };
      self.push_tag(JumbfTag {
        family0: GROUP_JUMBF,
        family1: GROUP_JUMBF,
        name: SmolStr::new("JUMDSignature"),
        value: JumbfValue::Signature(SmolStr::from(hex_lower(sig))),
        doc,
        doc_subpath: doc_subpath.clone(),
        unknown: false,
      });
      pos += 32;
    }
    // Trailing private data (`Jpeg2000.pm:844-859`): if >= 8 bytes, a `c2sh` box
    // hides here — recurse the `Main` table over it (`$et->ProcessDirectory`
    // onto `Jpeg2000::Main`, whose `PROCESS_PROC` is `ProcessJpeg2000Box`,
    // `Jpeg2000.pm:127-130`/`:855`). Fewer than 8 bytes are ignored (the `Extra
    // data` minor warn, which exifast does not surface). The recursion is at the
    // SAME sub-document level (no new `jumb`), so the `c2sh` tag carries this
    // `jumd`'s `Doc<N>`.
    if end - pos >= 8
      && let Some(more) = content.get(pos..)
    {
      // The private region's boxes (in practice a single `c2sh`) sit at THIS
      // jumd's level — the `jumd_level` stack is unchanged, so
      // [`current_docpath`] returns the right path. ExifTool re-enters the FULL
      // recursive box walker here (`ProcessDirectory` → `ProcessJpeg2000Box`),
      // with NO depth guard of its own, so a crafted `jumd` whose private data is
      // ITSELF another `jumd` (whose private data is another `jumd`, …) would
      // recurse `process_jumd → walk → process_jumd` without bound and exhaust
      // the stack. Route the private box stream through the depth-budgeted
      // [`Self::recurse`] (walk at `depth + 1`, honoring [`MAX_BOX_DEPTH`])
      // rather than `walk(more, 0)`, so this private-data path is bounded by the
      // SAME budget as `jumb`/`asoc` nesting — a `c2sh` only ever sits one level
      // deep, so a genuine file is unaffected; a `jumb` nested in the private
      // region is still managed by `process_jumb`.
      self.recurse(more, depth);
    }
  }

  /// Emit `JUMDType` for a 16-byte type-UUID (`Jpeg2000.pm:743-757`): store the
  /// lowercase hex (the `unpack "H*"` ValueConv); the PrintConv split is applied
  /// per-mode at emission.
  fn push_jumd_type(&mut self, uuid: &[u8], doc: u32, doc_subpath: SmolStr) {
    self.push_tag(JumbfTag {
      family0: GROUP_JUMBF,
      family1: GROUP_JUMBF,
      name: SmolStr::new("JUMDType"),
      value: JumbfValue::JumdType(SmolStr::from(hex_lower(uuid))),
      doc,
      doc_subpath,
      unknown: false,
    });
  }

  /// `bfdb` → `BinaryDataType` (`Jpeg2000.pm:425-431`). ValueConv `$_ =
  /// substr($val,1); s/\0+$//; s/\0/, /;` — drop the leading toggle byte, strip
  /// TRAILING NULs, then replace the FIRST remaining NUL with `, ` (the MIME-type
  /// / file-name separator). Group `Jpeg2000`; renamed `<Label>Type` if a
  /// JUMBFLabel is active.
  fn process_bfdb(&mut self, content: &[u8]) {
    let (doc, doc_subpath) = self.current_docpath();
    // `substr($val, 1)` — drop the toggle byte. A 0-length payload yields "".
    let after = content.get(1..).unwrap_or(&[]);
    // `s/\0+$//` — strip trailing NULs.
    let trimmed_end = after
      .iter()
      .rposition(|&b| b != 0)
      .map_or(0, |last| last + 1);
    let trimmed = after.get(..trimmed_end).unwrap_or(after);
    // `s/\0/, /` — replace the FIRST remaining NUL with ", ".
    let text = match trimmed.iter().position(|&b| b == 0) {
      Some(nul) => {
        let mut s = String::with_capacity(trimmed.len() + 1);
        s.push_str(&crate::convert::fix_utf8(
          trimmed.get(..nul).unwrap_or(trimmed),
        ));
        s.push_str(", ");
        s.push_str(&crate::convert::fix_utf8(
          trimmed.get(nul + 1..).unwrap_or(&[]),
        ));
        s
      }
      None => crate::convert::fix_utf8(trimmed),
    };
    let name = self.content_tag_name(BoxKind::Bfdb, "BinaryDataType");
    self.push_tag(JumbfTag {
      family0: GROUP_JPEG2000,
      family1: GROUP_JPEG2000,
      name,
      value: JumbfValue::Text(SmolStr::from(text)),
      doc,
      doc_subpath,
      unknown: false,
    });
  }

  /// `bidb` → `BinaryData` (`Jpeg2000.pm:433-439`): `Binary => 1`, `Groups =>
  /// { 2 => 'Preview' }` — emit the `(Binary data N bytes …)` placeholder from
  /// the payload LENGTH (the bytes are never retained). Group `Jpeg2000`; renamed
  /// `<Label>Data` if a JUMBFLabel is active.
  fn process_bidb(&mut self, content: &[u8]) {
    let (doc, doc_subpath) = self.current_docpath();
    let name = self.content_tag_name(BoxKind::Bidb, "BinaryData");
    self.push_tag(JumbfTag {
      family0: GROUP_JPEG2000,
      family1: GROUP_JPEG2000,
      name,
      value: JumbfValue::BinaryLen(content.len() as u64),
      doc,
      doc_subpath,
      unknown: false,
    });
  }

  /// `c2sh` → `C2PASaltHash` (`Jpeg2000.pm:441-445`): ValueConv `unpack("H*",
  /// $val)` — the whole payload as lowercase hex. Group `Jpeg2000`; renamed
  /// `<Label>Salt` if a JUMBFLabel is active.
  fn process_c2sh(&mut self, content: &[u8]) {
    let (doc, doc_subpath) = self.current_docpath();
    let name = self.content_tag_name(BoxKind::C2sh, "C2PASaltHash");
    self.push_tag(JumbfTag {
      family0: GROUP_JPEG2000,
      family1: GROUP_JPEG2000,
      name,
      value: JumbfValue::Text(SmolStr::from(hex_lower(content))),
      doc,
      doc_subpath,
      unknown: false,
    });
  }

  /// `json` → `JSON::Main` (`Jpeg2000.pm:409-418`, Phase 2 #142): decode the
  /// JSON document ([`json::decode`]) and emit the flattened `JSON:<key>` tags
  /// (group `JSON`, `JSON.pm:23`) on THIS box's `Doc<N>` axis. A document that
  /// does not parse to an object / array-of-objects yields the bundled
  /// `Unrecognized <Name> box` warning (`Jpeg2000.pm:1330-1332`), where
  /// `<Name>` is the renamed JUMBFLabel (the `json` box carries `BlockExtract`,
  /// so the rename applies, with the empty `JUMBF_Suffix` — `JSONData` is
  /// renamed to just the label) or the default `JSONData`. The flattened tags
  /// keep group `JSON` regardless of the label (the rename only affects the
  /// block-extract name, oracle-verified vs bundled 13.59).
  fn process_json(&mut self, content: &[u8]) {
    let (doc, doc_subpath) = self.current_docpath();
    match json::decode(content) {
      json::JsonOutcome::Tags(pairs) => {
        for (name, value) in pairs {
          self.push_tag(JumbfTag {
            family0: GROUP_JSON,
            family1: GROUP_JSON,
            name,
            value: JumbfValue::Json(value),
            doc,
            doc_subpath: doc_subpath.clone(),
            unknown: false,
          });
        }
      }
      json::JsonOutcome::Unrecognized => {
        // `$$tagInfo{Name}` in the warning is the renamed JUMBFLabel when one is
        // active (`Jpeg2000.pm:1206-1212`; `json` has `BlockExtract`, so the
        // rename fires with the empty suffix → the bare label), else `JSONData`.
        let name = match self.cur_label.as_ref() {
          Some(label) => SmolStr::from(tables::make_renamed_tag_name(label, "")),
          None => SmolStr::new("JSONData"),
        };
        self.warn(JumbfWarning::UnrecognizedJsonBox(name));
      }
    }
  }

  /// The content tag's NAME: the renamed `<Label><Suffix>` when a JUMBFLabel is
  /// active (`Jpeg2000.pm:1205-1212`), else the default `default_name`. The
  /// rename joins the sanitized label + the box's [`tables::jumbf_suffix`] then
  /// applies `AddTagToTable`'s `Tag` prefix rule
  /// ([`tables::make_renamed_tag_name`]).
  fn content_tag_name(&self, kind: BoxKind, default_name: &'static str) -> SmolStr {
    match (self.cur_label.as_ref(), tables::jumbf_suffix(kind)) {
      (Some(label), Some(suffix)) => SmolStr::from(tables::make_renamed_tag_name(label, suffix)),
      _ => SmolStr::new(default_name),
    }
  }

  /// Append a decoded tag.
  fn push_tag(&mut self, tag: JumbfTag) {
    self.meta.tags.push(tag);
  }
}

/// `unpack "H*", $val` — lowercase hex of a byte slice (the `JUMDType` /
/// `JUMDSignature` / `C2PASaltHash` ValueConv).
fn hex_lower(bytes: &[u8]) -> String {
  use core::fmt::Write;
  let mut s = String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    let _ = write!(s, "{b:02x}");
  }
  s
}

/// Render `JUMDType` for the active conv mode (`Jpeg2000.pm:746-752`). `-n`
/// (ValueConv) is the raw lowercase hex; `-j` (PrintConv) splits the 32-hex-digit
/// UUID into `8-4-4-16` groups and, IFF the FIRST 4 bytes are all printable ASCII
/// alphanumerics, renders that group as `(text)` instead of its hex
/// (`6a736f6e…` → `(json)-0011-0010-800000aa00389b71`; a non-printable first
/// group stays raw `6579d6fb-dba2-446b-b2ac1b82feeb89d1`). A hex string that does
/// not match the `^(\w{8})(\w{4})(\w{4})(\w{16})$` shape renders verbatim.
fn render_type(hex: &str, print_conv: bool) -> SmolStr {
  if !print_conv {
    return SmolStr::new(hex);
  }
  // `^(\w{8})(\w{4})(\w{4})(\w{16})$` — exactly 32 hex digits in 8/4/4/16 groups.
  let bytes = hex.as_bytes();
  if bytes.len() != 32 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
    return SmolStr::new(hex);
  }
  // The `len() == 32` check above proves every slice is in range; the checked
  // `.get()` keeps the module panic-safe (`exif/mod.rs`
  // `#![deny(clippy::indexing_slicing)]`). A failed `.get()` cannot happen here.
  let (Some(g0), Some(g1), Some(g2), Some(g3)) = (
    hex.get(0..8),
    hex.get(8..12),
    hex.get(12..16),
    hex.get(16..32),
  ) else {
    return SmolStr::new(hex);
  };
  // `$ascii = pack 'H*', $a[0]; $a[0] = "($ascii)" if $ascii =~ /^[a-zA-Z0-9]{4}$/`.
  // Decode the first group's 8 hex digits into 4 bytes; if all four are ASCII
  // alphanumerics, substitute `(text)`.
  let first_group = decode_4_ascii_alnum(g0);
  let mut out = String::with_capacity(40);
  match first_group {
    Some(text) => {
      out.push('(');
      out.push_str(&text);
      out.push(')');
    }
    None => out.push_str(g0),
  }
  out.push('-');
  out.push_str(g1);
  out.push('-');
  out.push_str(g2);
  out.push('-');
  out.push_str(g3);
  SmolStr::from(out)
}

/// Decode 8 hex digits into a 4-char ASCII string IFF every decoded byte is an
/// ASCII alphanumeric (`/^[a-zA-Z0-9]{4}$/`); else `None`. Used by [`render_type`]
/// for the `(json)`/`(cbor)`-style human-readable UUID prefix.
fn decode_4_ascii_alnum(eight_hex: &str) -> Option<String> {
  let b = eight_hex.as_bytes();
  if b.len() != 8 {
    return None;
  }
  let mut out = String::with_capacity(4);
  // Each 2-byte hex pair → one decoded byte; a non-alphanumeric byte aborts.
  for pair in b.chunks_exact(2) {
    let &[hi, lo] = pair else {
      return None;
    };
    let hi = (hi as char).to_digit(16)?;
    let lo = (lo as char).to_digit(16)?;
    let byte = (hi * 16 + lo) as u8;
    if !byte.is_ascii_alphanumeric() {
      return None;
    }
    out.push(byte as char);
  }
  Some(out)
}

impl crate::emit::Taggable for JumbfMeta {
  /// Yield the decoded JUMBF tags as [`EmittedTag`](crate::emit::EmittedTag)s, in
  /// walk order, on the `Doc<N>` axis. JUMD tags emit under group `JUMBF`; the
  /// `bfdb`/`bidb`/`c2sh` content tags under `Jpeg2000` (possibly renamed by a
  /// JUMBFLabel). `JUMDType` renders per-mode ([`render_type`]); `JUMDToggles`
  /// carries `Unknown=>1` (the engine suppresses it from default output) and
  /// renders the BITMASK under `-j -u` / the raw int under `-n`.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let print_conv = matches!(opts.mode, crate::emit::ConvMode::PrintConv);
    let mut out: Vec<crate::emit::EmittedTag> = Vec::with_capacity(self.tags.len());
    for t in &self.tags {
      let value = match &t.value {
        JumbfValue::JumdType(hex) => crate::value::TagValue::Str(render_type(hex, print_conv)),
        JumbfValue::JumdToggles(flags) => {
          if print_conv {
            crate::value::TagValue::Str(render_toggles(*flags))
          } else {
            crate::value::TagValue::U64(u64::from(*flags))
          }
        }
        JumbfValue::Text(s) | JumbfValue::Signature(s) => crate::value::TagValue::Str(s.clone()),
        JumbfValue::JumdId(id) => crate::value::TagValue::U64(u64::from(*id)),
        JumbfValue::BinaryLen(len) => {
          crate::value::TagValue::Str(crate::value::binary_placeholder(*len))
        }
        // A flattened `json` value is already a fully-formed `TagValue`
        // (scalar / `List` / `Map`), identical in both modes — clone it through.
        JumbfValue::Json(v) => v.clone(),
      };
      let group =
        crate::value::Group::with_subpath(t.family0, t.family1, t.doc, t.doc_subpath.clone());
      out.push(crate::emit::EmittedTag::new(
        group,
        t.name.clone(),
        value,
        t.unknown,
      ));
    }
    out.into_iter()
  }
}

/// Render the `JUMDToggles` BITMASK (`Jpeg2000.pm:762-767`): bits 0/1/2/3 →
/// `Requestable`/`Label`/`ID`/`Signature`, set bits joined `", "` in bit order;
/// an unmapped set bit `n` renders `[n]`; zero renders `(none)` — the ExifTool
/// `DecodeBits` rendering ([[exifast-bitmask-decodebits]]).
fn render_toggles(flags: u8) -> SmolStr {
  const LABELS: [(u32, &str); 4] = [
    (0, "Requestable"),
    (1, "Label"),
    (2, "ID"),
    (3, "Signature"),
  ];
  if flags == 0 {
    return SmolStr::new("(none)");
  }
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..8u32 {
    if flags & (1 << bit) != 0 {
      match LABELS.iter().find(|&&(b, _)| b == bit) {
        Some(&(_, label)) => parts.push(String::from(label)),
        None => parts.push(std::format!("[{bit}]")),
      }
    }
  }
  SmolStr::from(parts.join(", "))
}
