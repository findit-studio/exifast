// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::MNG` — the MNG/JNG chunk sub-table reader (`MNG.pm`, a
//! faithful transliteration of the 17 `ProcessBinaryData` sub-tables + the
//! inline-`ValueConv` + `Binary => 1` chunks `%MNG::Main` dispatches).
//!
//! MNG (Multi-image Network Graphics) and JNG (JPEG Network Graphics) are
//! PNG-sibling containers: a PNG-style 8-byte signature (`\x8aMNG…` / `\x8bJNG…`,
//! `PNG.pm:63-64`) then the same `length + 4-char-type + data + CRC` chunk
//! stream. `PNG.pm`'s `ProcessPNG` walks BOTH containers, dispatching each chunk
//! first against `%PNG::Main` and then — when `fileType ne 'PNG'` — against
//! `%MNG::Main` as a FALLBACK (`PNG.pm:1444-1446`/`:1653-1657`). So a chunk
//! shared with PNG (`IHDR`, `pHYs`, `tEXt`, …) is decoded by the PNG handler
//! (under the `PNG`/`PNG-pHYs` group), and only an MNG-specific chunk reaches
//! this module (under the `MNG` family-1 group, `MNG.pm:21` `GROUPS => { 2 =>
//! 'Image' }`).
//!
//! ## The 17 sub-tables + the inline/binary chunks (`MNG.pm:28-643`)
//!
//! Each `SubDirectory` chunk (BACK/BASI/CLIP/CLON/DEFI/DHDR/eXPi/fPRI/JHDR/LOOP/
//! MAGN/MHDR/MOVE/PAST/PROM/SHOW/TERM) maps to a `ProcessBinaryData` table
//! ([`tables::MngSubTable`]): a table-level `FORMAT` (`int8u` default, `int32u`
//! for MHDR) sets the offset INCREMENT (`ExifTool.pm:9893`/`:9957` `$entry =
//! int($index) * $increment`), and each numeric offset key is a leaf with its own
//! `Format`/`Format[count]` (overriding the table FORMAT for the bytes READ) and
//! optional int->label PrintConv. Every leaf is emitted **per-field** — iff its
//! `byte_off + size` is within the chunk (`buf.get(off..off+size)`, the
//! [[exifast-processbinarydata-per-field]] discipline), so a truncated chunk
//! yields exactly the leaves that fit.
//!
//! Three chunks (DISC/DROP/SEEK) are INLINE `ValueConv` tags (not sub-tables):
//! the whole chunk value passes through a hand-ported transform
//! ([`MngConv::DiscardObjects`]/[`DropChunks`](MngConv::DropChunks)/
//! [`SeekPoint`](MngConv::SeekPoint)). Six chunks (DBYK/FRAM/nEED/ORDR/PPLT/SAVE)
//! are `Binary => 1` with NO SubDirectory: like PNG's `iDOT`/`gdAT` they emit the
//! universal `(Binary data N bytes, use -b option to extract)` placeholder from
//! the chunk LENGTH alone (oracle-verified vs bundled 13.59 — even a 0-byte SAVE
//! renders `(Binary data 0 bytes …)`). `pHYg` (`GlobalPixelSize`) is a
//! `SubDirectory` onto `PNG::PhysicalPixel`, so it routes to the shared PNG `pHYs`
//! decoder (emitting under `PNG-pHYs`, NOT `MNG`) and is handled by the caller.
//!
//! ## The 5 HAND-PORTED conv-bearing fields (the codegen-survey trap, #190)
//!
//! `-listx`/declarative extraction carries NO ValueConv/RawConv, so the
//! generator (`tools/gen_mng_tables.pl`) leaves these as `MngConv` overrides
//! ground-truthed vs bundled:
//! 1. MHDR `SimplicityProfile` — `sprintf("0x%.8x", $val)` (`MNG.pm:158`).
//! 2. DISC `DiscardObjects` — `join(" ", unpack("n*", $val))` (`MNG.pm:58`).
//! 3. DROP `DropChunks` — `join(" ", $val =~ /..../g)` (4-char split, `:62`).
//! 4. SEEK `SeekPoint` — `$val =~ s/\0.*//s` (NUL-strip, `:133`).
//! 5. BASI `ColorType` `RawConv => '$PNG::colorType = $val'` (`:177`) — an INERT
//!    global side-effect: exifast has no `PNG::colorType` to mutate, the VALUE
//!    passes through UNCHANGED, so it needs no override (the declarative
//!    int->label PrintConv carries it).
//!
//! A leaf whose decoded PrintConv value isn't in its slice renders the RAW INT
//! (ExifTool's HASH-PrintConv miss with no `OTHER`/`BITMASK`,
//! `ExifTool.pm:3614-3634`).

mod tables;
#[cfg(test)]
mod tests;

use crate::exif::ifd::{ByteOrder, get_u8, get_u16, get_u32};
use smol_str::SmolStr;
use std::{string::String, vec::Vec};

/// MNG/JNG chunks are big-endian (`SetByteOrder('MM')`, `PNG.pm:1441`).
const MNG_ORDER: ByteOrder = ByteOrder::Big;

/// One `%MNG::Main` chunk's dispatch kind (the generated [`tables`] map values).
/// A `Copy` token so the binary-search lookup can return it by value.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MngChunkKind {
  /// A `ProcessBinaryData` SubDirectory — decode each leaf per-field.
  Sub(&'static MngSubTable),
  /// An inline `ValueConv` chunk (DISC/DROP/SEEK): the whole chunk value passes
  /// through the named transform; the `&str` is the tag Name.
  Inline(&'static str, MngConv),
  /// A `Binary => 1` chunk (DBYK/FRAM/nEED/ORDR/PPLT/SAVE): emit the
  /// `(Binary data N bytes …)` placeholder under the `&str` tag Name.
  Binary(&'static str),
  /// `pHYg` (`GlobalPixelSize`) — a SubDirectory onto `PNG::PhysicalPixel`,
  /// routed by the CALLER to the shared PNG `pHYs` decoder (NOT decoded here).
  Phys,
}

/// A `ProcessBinaryData` sub-table descriptor: the offset INCREMENT (the
/// table-level FORMAT's element size — 1 for the int8u-default tables, 4 for
/// MHDR's `int32u`) plus the per-offset leaf descriptors (in table/offset order).
#[derive(Debug, Clone, Copy)]
pub(crate) struct MngSubTable {
  /// `$increment = formatSize{defaultFormat}` (`ExifTool.pm:9893`): a leaf's
  /// offset key is multiplied by this to get its BYTE offset.
  increment: usize,
  /// The leaf descriptors (offset key, name, element format/count, PrintConv,
  /// hand-port conv), in table order.
  leaves: &'static [MngLeafDef],
}

impl MngSubTable {
  /// Construct a sub-table descriptor (gen-time only).
  #[must_use]
  pub(crate) const fn new(increment: usize, leaves: &'static [MngLeafDef]) -> Self {
    Self { increment, leaves }
  }
}

/// One `ProcessBinaryData` leaf descriptor (a numeric offset entry of a
/// `%MNG::*` sub-table): the offset KEY (in table-FORMAT units), the tag Name,
/// the element format + array count (the per-leaf `Format`/`Format[count]`,
/// overriding the table FORMAT for the bytes read), the optional int->label
/// PrintConv slice, and the hand-ported conv ([`MngConv::SimplicityProfile`] for
/// MHDR, else [`MngConv::None`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct MngLeafDef {
  offset: usize,
  name: &'static str,
  format: MngFormat,
  count: usize,
  print_conv: Option<&'static [(i64, &'static str)]>,
  conv: MngConv,
}

impl MngLeafDef {
  /// Construct a leaf descriptor (gen-time only).
  #[must_use]
  pub(crate) const fn new(
    offset: usize,
    name: &'static str,
    format: MngFormat,
    count: usize,
    print_conv: Option<&'static [(i64, &'static str)]>,
    conv: MngConv,
  ) -> Self {
    Self {
      offset,
      name,
      format,
      count,
      print_conv,
      conv,
    }
  }

  /// The offset KEY (in table-FORMAT units; multiply by the table increment).
  #[must_use]
  const fn offset(&self) -> usize {
    self.offset
  }
  /// The tag Name.
  #[must_use]
  const fn name(&self) -> &'static str {
    self.name
  }
  /// The element format (per-leaf `Format`, or the inherited table FORMAT).
  #[must_use]
  const fn format(&self) -> MngFormat {
    self.format
  }
  /// The array element count (1 for a scalar, N for `Format[N]`).
  #[must_use]
  const fn count(&self) -> usize {
    self.count
  }
  /// The int->label PrintConv slice, or `None`.
  #[must_use]
  const fn print_conv(&self) -> Option<&'static [(i64, &'static str)]> {
    self.print_conv
  }
  /// The hand-ported conv ([`MngConv::SimplicityProfile`] / [`MngConv::None`]).
  #[must_use]
  const fn conv(&self) -> MngConv {
    self.conv
  }
}

/// A `ProcessBinaryData` element format (`MNG.pm` `FORMAT` / per-leaf `Format`).
/// Only the four MNG actually uses; the byte [`Self::size`] drives the per-field
/// availability check and the offset INCREMENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MngFormat {
  /// `int8u` — 1 byte.
  Int8u,
  /// `int16u` — 2 bytes (big-endian).
  Int16u,
  /// `int32u` — 4 bytes (big-endian).
  Int32u,
  /// `string` — a NUL-terminated ASCII string (size 1 per element, but a
  /// `string` leaf reads to the chunk end / first NUL, `ExifTool.pm:9962`).
  Strng,
}

impl MngFormat {
  /// `FormatSize` (`ExifTool.pm` `@formatSize`) — the bytes ONE element occupies.
  /// `string` is 1 (a per-byte unit; the leaf reads `count` bytes then truncates
  /// at the first NUL).
  pub(crate) const fn size(self) -> usize {
    match self {
      Self::Int8u | Self::Strng => 1,
      Self::Int16u => 2,
      Self::Int32u => 4,
    }
  }
}

/// A hand-ported conv-bearing transform (the 5 survey overrides) OR no transform.
/// Applies BOTH at leaf level ([`Self::SimplicityProfile`], MHDR) and at the
/// inline-chunk level ([`Self::DiscardObjects`]/[`DropChunks`](Self::DropChunks)/
/// [`SeekPoint`](Self::SeekPoint), the DISC/DROP/SEEK whole-chunk ValueConvs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MngConv {
  /// No hand-port — the declarative (int->label PrintConv or raw) rendering.
  None,
  /// MHDR `SimplicityProfile` (`MNG.pm:158`): `sprintf("0x%.8x", $val)` — render
  /// the int32u as a zero-padded 8-hex-digit `0x…` string (PrintConv, `-j`); the
  /// raw int in `-n`.
  SimplicityProfile,
  /// DISC `DiscardObjects` (`MNG.pm:58`): `join(" ", unpack("n*", $val))` — the
  /// whole chunk read as big-endian `int16u`s, space-joined (a ValueConv, so it
  /// applies in BOTH `-j` and `-n`).
  DiscardObjects,
  /// DROP `DropChunks` (`MNG.pm:62`): `join(" ", $val =~ /..../g)` — the chunk
  /// split into 4-byte (4-char) groups, space-joined (ValueConv, both modes).
  DropChunks,
  /// SEEK `SeekPoint` (`MNG.pm:133`): `$val =~ s/\0.*//s` — the chunk truncated at
  /// the first NUL (ValueConv, both modes).
  SeekPoint,
}

/// One decoded MNG leaf value, captured at parse time and rendered per conv mode
/// in [`MngMeta::tags`]. The shape follows the leaf's `MngFormat` + count:
/// scalar/array `int*u`, a `string`, the `Binary => 1` placeholder LENGTH, or a
/// pre-rendered inline-`ValueConv` string.
#[derive(Debug, Clone, PartialEq)]
enum MngValue {
  /// `int8u`/`int16u`/`int32u` value(s). A single value renders through the
  /// leaf's PrintConv (or raw); a multi-element array space-joins the raw
  /// decimals (`ReadValue` `join(' ', @vals)`) — no `%MNG` array leaf has a
  /// PrintConv, so the mode does not change an array.
  Ints(Vec<u64>),
  /// A `string` leaf (eXPi `SnapshotName`) — already NUL-truncated + decoded.
  Text(SmolStr),
  /// A `Binary => 1` chunk's payload LENGTH (DBYK/FRAM/nEED/ORDR/PPLT/SAVE) —
  /// renders as `(Binary data N bytes, use -b option to extract)` in BOTH modes
  /// (the raw bytes are never retained).
  BinaryLen(u64),
  /// A pre-rendered inline-`ValueConv` string (DISC/DROP/SEEK) — identical in
  /// `-j` and `-n` (these are ValueConvs, applied before PrintConv).
  InlineText(SmolStr),
}

/// One decoded MNG leaf: its tag name, value, and (for an int scalar) the
/// PrintConv slice + hand-port conv to render it.
#[derive(Debug, Clone, PartialEq)]
struct MngLeaf {
  /// The tag Name (e.g. `ImageWidth`, `SimplicityProfile`).
  name: SmolStr,
  /// The decoded value.
  value: MngValue,
  /// The int->label PrintConv slice for a single-`int*u` value, or `None`.
  print_conv: Option<&'static [(i64, &'static str)]>,
  /// The hand-ported conv for this leaf ([`MngConv::SimplicityProfile`] for
  /// MHDR, else [`MngConv::None`] — the inline-conv variants are pre-rendered
  /// into [`MngValue::InlineText`] at decode time, so a leaf only ever carries
  /// `None` or `SimplicityProfile`).
  conv: MngConv,
  /// Whether the producing chunk came AFTER the `MEND`/`IEND` end chunk — a
  /// post-end TRAILER chunk. Captured from the walker's trailer state when the
  /// chunk is dispatched (`PNG.pm:1484` `$$et{SET_GROUP1} = 'Trailer'`); drives
  /// the family-1 `MNG` → `Trailer` group shift in [`MngMeta::tags`].
  in_trailer: bool,
}

/// The typed MNG/JNG metadata (golden-pattern L1) — the decoded leaves (in
/// chunk-walk + offset order) plus any `$et->Warn(...)` the sub-tables raised.
/// Built incrementally by [`MngMeta::process_chunk`] as the PNG chunk walker
/// reaches each MNG-specific chunk; emitted via its
/// [`Taggable`](crate::emit::Taggable) impl under group `MNG` (family-2 `Image`,
/// which never reaches `-G1 -j`) and its warnings via the
/// [`Diagnose`](crate::diagnostics::Diagnose) channel.
///
/// (`MNG.pm`'s `ProcessBinaryData` sub-tables raise NO `$et->Warn` for a
/// well-formed-or-truncated chunk — per-field availability silently omits an
/// out-of-range leaf — so `warnings` is a defensive channel that stays empty in
/// practice; it is kept for parity with the GeoTiff precedent + future hostile
/// hardening.)
///
/// D8: no public fields — the leaves/warnings are read by the in-crate emitter.
#[derive(Debug, Clone, PartialEq)]
pub struct MngMeta {
  /// The decoded leaves in walk order (chunk order, then offset order within a
  /// chunk). The `TagMap` dedup applied by
  /// [`run_emission`](crate::emit::run_emission) keeps the LAST of any
  /// duplicate `MNG:<Name>` — faithful to ExifTool's last-wins
  /// (`ExifTool.pm:9544-9560`).
  leaves: Vec<MngLeaf>,
  /// `$et->Warn(...)` messages, in emission order — surfaced via the
  /// [`Diagnose`](crate::diagnostics::Diagnose) channel. Empty in practice (see
  /// the type docs).
  warnings: Vec<String>,
}

impl Default for MngMeta {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl MngMeta {
  /// An empty `MngMeta` — no leaves, no warnings. The starting point the chunk
  /// walker fills via [`Self::process_chunk`].
  #[must_use]
  pub(crate) const fn new() -> Self {
    Self {
      leaves: Vec::new(),
      warnings: Vec::new(),
    }
  }

  /// The `$et->Warn(...)` corpus the MNG sub-tables raised, in emission order.
  pub(crate) fn warnings(&self) -> &[String] {
    &self.warnings
  }

  /// Decode ONE MNG-specific chunk's payload, appending its leaves (`FoundPNG`
  /// → the matched `%MNG::Main` sub-table / inline / binary handler,
  /// `PNG.pm:1655`). Returns `true` IFF `chunk` was a recognized MNG chunk (so
  /// the caller knows the MNG fallback consumed it). `pHYg` is NOT handled here —
  /// it routes to the shared PNG `pHYs` decoder (the caller checks for it before
  /// calling this).
  ///
  /// `data` is the chunk payload (the bytes between the 4-byte type and the CRC).
  /// `in_trailer` is the walker's post-`MEND`/`IEND` trailer state at this chunk
  /// (`PNG.pm:1484` `SET_GROUP1 = 'Trailer'`): a `true` chunk's leaves emit under
  /// family-1 `Trailer` instead of `MNG`, so a crafted post-end MHDR/BACK does
  /// NOT overwrite the main `MNG:*` (they coexist as distinct `-G1` tags —
  /// oracle-verified vs bundled 13.59).
  pub(crate) fn process_chunk(&mut self, chunk: &[u8; 4], data: &[u8], in_trailer: bool) -> bool {
    let Some(kind) = tables::lookup(chunk) else {
      return false;
    };
    match kind {
      MngChunkKind::Sub(table) => self.decode_sub_table(table, data, in_trailer),
      MngChunkKind::Binary(name) => {
        // `Binary => 1`, no SubDirectory: emit the placeholder from the chunk
        // LENGTH (the bytes are never retained — `MNG.pm:44`/`:75`/etc).
        self.leaves.push(MngLeaf {
          name: SmolStr::new(name),
          value: MngValue::BinaryLen(data.len() as u64),
          print_conv: None,
          conv: MngConv::None,
          in_trailer,
        });
      }
      MngChunkKind::Inline(name, conv) => self.decode_inline(name, conv, data, in_trailer),
      // `pHYg` should have been routed to `decode_phys` by the caller; if it
      // reaches here it is a no-op (defensive — never happens in the walk).
      MngChunkKind::Phys => {}
    }
    true
  }

  /// Decode a `ProcessBinaryData` sub-table (`ExifTool.pm:9890-9990`). The table
  /// FORMAT sets the offset INCREMENT (the leaf offset key is in FORMAT units);
  /// each leaf reads `count * size` bytes at `off * increment` IFF in range
  /// (per-field availability). Leaves are appended in table (offset) order.
  fn decode_sub_table(&mut self, table: &'static MngSubTable, data: &[u8], in_trailer: bool) {
    // The table FORMAT's element size is the per-index INCREMENT. ExifTool keys
    // every sub-table by a numeric index multiplied by `$increment` — for MHDR
    // (`FORMAT int32u`) the increment is 4, so index N is byte N*4; for the
    // int8u-default tables it is 1, so index N is byte N. The increment is the
    // table-level FORMAT's element size, carried on the [`MngSubTable`].
    let increment = table.increment;
    for def in table.leaves {
      let byte_off = def.offset() * increment;
      let elem = def.format();
      let size = elem.size();
      let count = def.count();
      match elem {
        MngFormat::Strng => {
          // A `string` leaf reads `count` bytes at `byte_off` then truncates at
          // the first NUL (`ExifTool.pm:9962` `$val =~ s/\0.*//s`). A `count` of
          // 0 is the "unsized string" sentinel (`Format => 'string'` with no
          // `[N]`): ProcessBinaryData reads from the offset to the END of the
          // block (`$count = $size - $entry`, eXPi SnapshotName). Per-field
          // availability: the leaf is emitted only when its FIRST byte is in
          // range. For the unsized form that is `byte_off < data.len()` — a
          // STRICT bound, since `data.get(byte_off..)` succeeds even at
          // `byte_off == data.len()` (yielding an empty slice). ExifTool's
          // `ProcessBinaryData` `last if $entry >= $size` (`ExifTool.pm:9924`)
          // skips the leaf entirely at that boundary, so a 2-byte eXPi (the
          // int16u `SnapshotID` only) emits NO `SnapshotName` — NOT an empty
          // string (oracle-verified vs bundled 13.59).
          let Some(bytes) = (if count == 0 {
            (byte_off < data.len())
              .then(|| data.get(byte_off..))
              .flatten()
          } else {
            data.get(byte_off..byte_off + count)
          }) else {
            continue;
          };
          let truncated = match bytes.iter().position(|&b| b == 0) {
            Some(nul) => bytes.get(..nul).unwrap_or(bytes),
            None => bytes,
          };
          self.leaves.push(MngLeaf {
            name: SmolStr::new(def.name()),
            value: MngValue::Text(SmolStr::from(crate::convert::fix_utf8(truncated))),
            print_conv: None,
            conv: MngConv::None,
            in_trailer,
          });
        }
        _ => {
          // An int scalar/array: read `count` elements of `size` bytes each at
          // `byte_off`. Per-field availability: every element must be in range
          // (`not $dataPt or length < ...` — ProcessBinaryData skips an
          // out-of-range index). A partial read of one array element drops the
          // whole leaf (the window check is all-or-nothing per leaf).
          let needed = byte_off.saturating_add(size.saturating_mul(count));
          if data.len() < needed {
            continue;
          }
          let mut vals = Vec::with_capacity(count);
          for j in 0..count {
            let p = byte_off + j * size;
            let v = match elem {
              MngFormat::Int8u => get_u8(data, p).map(u64::from),
              MngFormat::Int16u => get_u16(data, p, MNG_ORDER).map(u64::from),
              MngFormat::Int32u => get_u32(data, p, MNG_ORDER).map(u64::from),
              MngFormat::Strng => None,
            };
            if let Some(v) = v {
              vals.push(v);
            }
          }
          self.leaves.push(MngLeaf {
            name: SmolStr::new(def.name()),
            value: MngValue::Ints(vals),
            print_conv: def.print_conv(),
            conv: def.conv(),
            in_trailer,
          });
        }
      }
    }
  }

  /// Decode an INLINE `ValueConv` chunk (DISC/DROP/SEEK) — the whole chunk value
  /// passes through the hand-ported transform (`MNG.pm:58`/`:62`/`:133`). The
  /// ValueConv applies in BOTH `-j` and `-n` (it precedes PrintConv), so the
  /// rendered string is stored once.
  fn decode_inline(&mut self, name: &'static str, conv: MngConv, data: &[u8], in_trailer: bool) {
    let text = match conv {
      MngConv::DiscardObjects => {
        // `join(" ", unpack("n*", $val))` — the chunk as big-endian int16u,
        // space-joined. `unpack("n*")` drops a trailing odd byte (the
        // `chunks_exact(2)` window count, then a checked `get_u16` per pair).
        let mut parts: Vec<String> = Vec::with_capacity(data.len() / 2);
        for j in 0..data.len() / 2 {
          if let Some(v) = get_u16(data, j * 2, MNG_ORDER) {
            parts.push(std::format!("{v}"));
          }
        }
        parts.join(" ")
      }
      MngConv::DropChunks => {
        // `join(" ", $val =~ /..../g)` — the chunk split into 4-BYTE groups
        // (the `.` in Perl matches a byte here; the data is 4-char chunk ids).
        // A trailing partial (<4-byte) group is dropped (the regex requires
        // exactly 4). Decode each 4-byte group as text (chunk ids are ASCII).
        let parts: Vec<String> = data.chunks_exact(4).map(crate::convert::fix_utf8).collect();
        parts.join(" ")
      }
      MngConv::SeekPoint => {
        // `$val =~ s/\0.*//s` — truncate at the first NUL.
        let truncated = match data.iter().position(|&b| b == 0) {
          Some(nul) => data.get(..nul).unwrap_or(data),
          None => data,
        };
        crate::convert::fix_utf8(truncated)
      }
      // The leaf-level conv (SimplicityProfile) + None never reach the inline
      // path (the dispatch table only assigns the three inline variants here).
      MngConv::SimplicityProfile | MngConv::None => String::new(),
    };
    self.leaves.push(MngLeaf {
      name: SmolStr::new(name),
      value: MngValue::InlineText(SmolStr::from(text)),
      print_conv: None,
      conv: MngConv::None,
      in_trailer,
    });
  }
}

/// Render one `int*u` PrintConv scalar through a leaf's static int->label slice
/// (`print_conv = true`) or as the raw int (`print_conv = false`). A hash MISS
/// renders the RAW INT — ExifTool's HASH-PrintConv miss with no `OTHER`/`BITMASK`
/// (`ExifTool.pm:3614-3634`); `%MNG` defines no `OTHER`, and the keys carry no
/// `PrintHex`, so the miss is the bare DECIMAL.
fn render_int_scalar(
  v: u64,
  print_conv: bool,
  slice: Option<&'static [(i64, &'static str)]>,
) -> crate::value::TagValue {
  if print_conv
    && let Some(s) = slice
    && let Ok(idx) = s.binary_search_by_key(&(v as i64), |&(k, _)| k)
    && let Some(&(_, label)) = s.get(idx)
  {
    return crate::value::TagValue::Str(SmolStr::new(label));
  }
  crate::value::TagValue::U64(v)
}

impl crate::emit::Taggable for MngMeta {
  /// Yield the decoded MNG leaves as [`EmittedTag`](crate::emit::EmittedTag)s
  /// under group `MNG` (family-0 and family-1 both `MNG`; family-2 `Image` does
  /// not reach `-G1 -j`), in walk order. Each leaf renders for the active conv
  /// mode: an `int*u` scalar through its int->label hash (`-j`) or raw (`-n`),
  /// the MHDR `SimplicityProfile` through `sprintf 0x%.8x` (`-j`) or raw (`-n`),
  /// an array space-joined, a `string` verbatim, the inline-`ValueConv` strings
  /// (DISC/DROP/SEEK) identically in both modes, and a `Binary => 1` chunk as the
  /// `(Binary data N bytes …)` placeholder.
  ///
  /// A leaf from a post-`MEND`/`IEND` TRAILER chunk ([`MngLeaf::in_trailer`])
  /// emits under family-1 `Trailer` instead of `MNG` (`PNG.pm:1484`
  /// `SET_GROUP1 = 'Trailer'`). MNG carries no explicit family-1 group that the
  /// `$grps[1] or …` rule (`ExifTool.pm:9475`) would preserve, so the override
  /// always applies — unlike the EXIF/XMP sub-IFDs that keep `IFD0`/`XMP-*` (the
  /// PNG-path `apply_trailer_group`/`has_explicit_family1_group` distinction).
  /// Because the `TagMap` dedup is keyed `(doc, family1, name)`, a `Trailer:*`
  /// leaf and a same-named main `MNG:*` leaf COEXIST — the trailer value does
  /// NOT overwrite the main (oracle-verified vs bundled 13.59).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let print_conv = matches!(opts.mode, crate::emit::ConvMode::PrintConv);
    let mut out: Vec<crate::emit::EmittedTag> = Vec::with_capacity(self.leaves.len());
    for leaf in &self.leaves {
      let value = match &leaf.value {
        MngValue::Ints(v) => match v.as_slice() {
          [scalar] => match leaf.conv {
            // MHDR `SimplicityProfile`: `sprintf("0x%.8x", $val)` (`-j`); raw
            // int (`-n`).
            MngConv::SimplicityProfile => {
              if print_conv {
                crate::value::TagValue::Str(SmolStr::from(std::format!("0x{scalar:08x}")))
              } else {
                crate::value::TagValue::U64(*scalar)
              }
            }
            _ => render_int_scalar(*scalar, print_conv, leaf.print_conv),
          },
          // An array (XYLocation/ClippingBoundary/BackgroundColor/…) space-joins
          // the raw decimals (`ReadValue` `join(' ', @vals)`), in BOTH modes (no
          // array leaf has a PrintConv).
          _ => {
            let parts: Vec<String> = v.iter().map(|x| std::format!("{x}")).collect();
            crate::value::TagValue::Str(SmolStr::from(parts.join(" ")))
          }
        },
        MngValue::Text(s) | MngValue::InlineText(s) => crate::value::TagValue::Str(s.clone()),
        MngValue::BinaryLen(len) => {
          crate::value::TagValue::Str(crate::value::binary_placeholder(*len))
        }
      };
      // `PNG.pm:1484` `SET_GROUP1 = 'Trailer'` for a post-end chunk; family-0
      // stays `MNG` (the override touches only group-1).
      let family1 = if leaf.in_trailer { "Trailer" } else { "MNG" };
      out.push(crate::emit::EmittedTag::new(
        crate::value::Group::new("MNG", family1),
        leaf.name.clone(),
        value,
        false,
      ));
    }
    out.into_iter()
  }
}
