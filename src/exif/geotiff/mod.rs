// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::GeoTiff` — the GeoTiff GeoKey directory reader
//! (`GeoTiff.pm`'s `ProcessGeoTiff`, a faithful transliteration).
//!
//! GeoTiff metadata rides three IFD0 TIFF tags (`Exif.pm:2059`/`:2081`/`:2099`):
//!
//! * `GeoTiffDirectory` (`0x87af`) — an `int16u` array: a 4-word header
//!   (`version`, `revision`, `minorRev`, `numEntries`) followed by `numEntries`
//!   8-byte GeoKey entries (`tag`, `loc`, `count`, `offset`).
//! * `GeoTiffDoubleParams` (`0x87b0`) — a `double` array the entries index into
//!   when `loc == 0x87b0`.
//! * `GeoTiffAsciiParams` (`0x87b1`) — a `string` blob the entries slice when
//!   `loc == 0x87b1`.
//!
//! ExifTool DELETES those three block tags from the default output (they are
//! `Binary => 1` and emitted only under `RequestAll`/an explicit request,
//! `GeoTiff.pm:2215-2220`); the port has no `RequestAll`, so it captures their
//! raw bytes during the IFD0 walk (the same way the `0x927c` MakerNote blob is
//! captured) WITHOUT emitting them, then runs [`process`] to decode the GeoKeys.
//!
//! ## The `ProcessGeoTiff` block (`GeoTiff.pm:2133-2221`)
//!
//! ```text
//! return unless GeoTiffDirectory captured.
//! Get16u(dir, 0/2/4/6) = version, revision, minorRev, numEntries.
//! length(dir) >= 8 and length(dir) >= 8*(numEntries+1) else Warn 'Bad GeoTIFF directory'.
//! FoundTag(GeoTiffVersion, "version.revision.minorRev").
//! for i in 0..numEntries:                       # entry at 8*(i+1)
//!     tag, loc, count, offset = Get16u(dir, pt + 0/2/4/6)
//!     format = geoTiffFormat{loc}               # 0/0x87af -> int16u, 0x87b0 -> double, 0x87b1 -> string
//!     not format         => Warn 'Unknown GeoTiff location (loc) for Name'; next
//!     loc == 0           => count=1, offset = (pt+6)/2 (the value is IN the offset field)
//!     size = FormatSize(format)                 # int16u 2, double 8, string 1
//!     not dataPt or length(dataPt) < size*(offset+count) => Warn 'Missing format data for Name'; next
//!     val = ReadValue(dataPt, offset*size, format, count)
//!     format eq 'string' => strip a trailing \0 or '|'.
//!     FoundTag(Name, val)                        # PrintConv applied at print time
//! ```
//!
//! The decoded GeoKeys emit under family-0/1 group `GeoTiff` (family-2
//! `Location`, which never reaches the `-G1 -j` output), in walk order, each
//! through its static int->label `PrintConv` (a miss renders the RAW INT — the
//! HASH-PrintConv miss with no `OTHER`/`BITMASK`, `ExifTool.pm:3614-3634`).

mod tables;
#[cfg(test)]
mod tests;

use crate::exif::ifd::{ByteOrder, get_f64, get_u16};
use smol_str::SmolStr;
use tables::GeoKeyDef;

/// `FormatSize('int16u')` (`ExifTool.pm` `@formatSize`).
const SIZE_INT16U: usize = 2;
/// `FormatSize('double')`.
const SIZE_DOUBLE: usize = 8;
/// `FormatSize('string')`.
const SIZE_STRING: usize = 1;

/// The `%geoTiffFormat` location code that means "the value is stored after the
/// directory, as `int16u`" (`GeoTiff.pm:27`) — also the `GeoTiffDirectory` tag
/// id (`Exif.pm:2059`).
const LOC_INT16U: u16 = 0x87af;
/// The `loc` selecting the `GeoTiffDoubleParams` blob (`double`, `GeoTiff.pm:28`).
const LOC_DOUBLE: u16 = 0x87b0;
/// The `loc` selecting the `GeoTiffAsciiParams` blob (`string`, `GeoTiff.pm:29`).
const LOC_STRING: u16 = 0x87b1;

/// FILE-WIDE cumulative cap on the TOTAL decoded scalar elements (`int16u` +
/// `double` + `string` bytes) materialized across the WHOLE GeoKey directory in
/// one [`process`] call — a beyond-faithful heap-amplification DoS floor.
///
/// `ProcessGeoTiff` (`GeoTiff.pm:2164-2207`) trusts `numEntries` and each entry's
/// `count`, materializing a fresh `Vec` per int/double GeoKey. Both `numEntries`
/// and `count` are `int16u` (≤ 65535), so a crafted ~1 MB directory can declare
/// 65535 entries each with `count = 65535` (all re-reading the same tiny
/// `GeoTiffDoubleParams`, `offset = 0`), forcing ~4.3 billion retained `f64`s
/// (tens of GB) from a small file — a heap AMPLIFICATION. ExifTool itself just
/// materializes these and OOMs; exifast instead bounds the SUM of all decoded
/// element counts to this single cap (mirroring the file-wide PNG
/// [`MAX_ZXIF_INFLATE_TOTAL`](crate::formats::png) decompressed-byte budget and
/// the HEIF [`MAX_ILOC_EXTENTS`](crate::formats::quicktime_brands) extent budget
/// — a running total threaded across the whole walk, NOT reset per key). When a
/// key's elements would push the running total past this cap, that key (and every
/// later one) is NOT materialized and a single [`GeoTiffWarning::DirectoryTooLarge`]
/// is raised — so exifast is MORE robust than ExifTool here, which would OOM.
///
/// A real GeoTiff carries tens of GeoKeys with tiny counts (scalars, a handful of
/// `double` model-transformation coefficients) — hundreds of elements TOTAL, four
/// orders of magnitude below this cap — so it NEVER fires on a well-formed file
/// (the conformance fixtures `GeoTiff.tif`/`mini`/`projcs`/`bigtiff` stay
/// byte-identical) yet bounds the ~4-billion-element crafted amplification.
const MAX_GEOKEY_ELEMENTS: usize = 1 << 20;

/// A decoded GeoKey's value, captured at parse time and rendered per conv mode
/// in [`GeoTiffMeta::tags`]. The shape follows the entry's `%geoTiffFormat`
/// source: an `int16u` array (inline or from the directory), a `double` array
/// (from `GeoTiffDoubleParams`), or a NUL/`|`-trimmed `string` (from
/// `GeoTiffAsciiParams`).
#[derive(Debug, Clone, PartialEq)]
enum GeoValue {
  /// `int16u` value(s) — the PrintConv keys are single `int16u` (the hash maps
  /// the scalar to a label; a multi-value `int16u` would space-join, but no
  /// `%GeoTiff::Main` PrintConv key has `count > 1`).
  Ints(Vec<u16>),
  /// `double` value(s) from `GeoTiffDoubleParams` — rendered `%.15g`, space-joined.
  Doubles(Vec<f64>),
  /// `string` from `GeoTiffAsciiParams` — already NUL/`|`-trimmed.
  Text(SmolStr),
}

/// One decoded GeoKey: its descriptor (id/name/PrintConv) plus its value.
#[derive(Debug, Clone, PartialEq)]
struct GeoKey {
  /// The GeoKey id (the `%GeoTiff::Main` hash key) — also the lookup into
  /// [`tables::GEO_KEYS`] for the name + PrintConv slice.
  id: u16,
  /// The decoded value (`int16u`/`double`/`string`).
  value: GeoValue,
}

/// A `ProcessGeoTiff` warning, carrying the faithful `$et->Warn(...)` text so the
/// caller can surface it on the shared diagnostics channel. Every GeoTiff warning
/// is a NORMAL (non-minor) `$et->Warn` (`GeoTiff.pm:2174`/`:2189`/`:2213`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GeoTiffWarning {
  /// `'Bad GeoTIFF directory'` (`GeoTiff.pm:2213`) — the directory failed the
  /// `length >= 8 and length >= 8*(numEntries+1)` structural check.
  BadDirectory,
  /// `"Unknown GeoTiff location (N) for Name"` (`GeoTiff.pm:2174`) — an entry's
  /// `loc` is not one of `0`/`0x87af`/`0x87b0`/`0x87b1`.
  UnknownLocation { loc: u16, name: &'static str },
  /// `"Missing FORMAT data for Name"` (`GeoTiff.pm:2189`) — the source blob is
  /// absent or too short for `size * (offset + count)` (per-field bounds check).
  MissingData {
    format: &'static str,
    name: &'static str,
  },
  /// `"Oversized GeoTIFF directory"` — a beyond-faithful DoS floor: the directory
  /// declared more total decoded elements than [`MAX_GEOKEY_ELEMENTS`], so the
  /// over-cap keys were dropped rather than materialized. ExifTool has no such
  /// guard (it would OOM); exifast warns + truncates instead.
  DirectoryTooLarge,
}

impl GeoTiffWarning {
  /// The bare `$et->Warn` message text (`GeoTiff.pm`).
  pub(crate) fn message(&self) -> String {
    match self {
      Self::BadDirectory => "Bad GeoTIFF directory".to_string(),
      Self::UnknownLocation { loc, name } => {
        std::format!("Unknown GeoTiff location ({loc}) for {name}")
      }
      Self::MissingData { format, name } => std::format!("Missing {format} data for {name}"),
      Self::DirectoryTooLarge => "Oversized GeoTIFF directory".to_string(),
    }
  }
}

/// The typed GeoTiff metadata (golden-pattern L1) — the decoded GeoKeys (in
/// walk order) plus the `$et->Warn(...)` corpus `ProcessGeoTiff` raised. Built
/// by [`process`] from the captured `GeoTiffDirectory`/`DoubleParams`/
/// `AsciiParams` blocks; emitted via its [`Taggable`](crate::emit::Taggable)
/// impl under group `GeoTiff` and its warnings via the
/// [`Diagnose`](crate::diagnostics::Diagnose) channel.
///
/// D8: no public fields — the keys/warnings are read by the in-crate emitter.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoTiffMeta {
  /// The decoded GeoKeys in walk order. The synthetic `GeoTiffVersion`
  /// (`GeoTiff.pm:2158-2161`) leads, then each `numEntries` key that decoded.
  keys: Vec<GeoKey>,
  /// `$et->Warn(...)` messages, in emission order — surfaced as
  /// `ExifTool:Warning` tags by the [`Diagnose`](crate::diagnostics::Diagnose)
  /// channel.
  warnings: Vec<GeoTiffWarning>,
}

impl GeoTiffMeta {
  /// The `$et->Warn(...)` corpus `ProcessGeoTiff` raised, in emission order.
  pub(crate) fn warnings(&self) -> &[GeoTiffWarning] {
    &self.warnings
  }
}

/// Look up a GeoKey descriptor by id in the sorted [`tables::GEO_KEYS`].
fn lookup(id: u16) -> Option<&'static GeoKeyDef> {
  tables::GEO_KEYS
    .binary_search_by_key(&id, |k| k.id)
    .ok()
    .and_then(|i| tables::GEO_KEYS.get(i))
}

/// `ProcessGeoTiff` (`GeoTiff.pm:2133-2221`) — decode the GeoKey directory into a
/// [`GeoTiffMeta`].
///
/// `dir` is the captured `GeoTiffDirectory` (`0x87af`) bytes; `double_params` /
/// `ascii_params` are the captured `GeoTiffDoubleParams` (`0x87b0`) /
/// `GeoTiffAsciiParams` (`0x87b1`) blocks (each `None`/empty when the IFD0 had
/// no such tag). `order` is the TIFF byte order (`Get16u`/`Get64u` read with it —
/// "byte order must be set before calling this routine", `GeoTiff.pm:2132`).
///
/// Returns `None` when there is no GeoKey directory to process (`$et->GetValue
/// ('GeoTiffDirectory') or return`, `GeoTiff.pm:2136`) — i.e. a plain TIFF with
/// no GeoTiff tags emits nothing. Otherwise `Some(meta)` even when the directory
/// is structurally bad (the meta then carries only the [`GeoTiffWarning`]).
pub(crate) fn process(
  dir: &[u8],
  double_params: Option<&[u8]>,
  ascii_params: Option<&[u8]>,
  order: ByteOrder,
) -> Option<GeoTiffMeta> {
  // `my $dirData = $et->GetValue('GeoTiffDirectory', 'ValueConv') or return;`
  // (`GeoTiff.pm:2136`) — no directory ⇒ nothing to do. An empty captured block
  // (a zero-length `0x87af`) is falsy in Perl too (`''`), so treat it as absent.
  if dir.is_empty() {
    return None;
  }

  let mut keys: Vec<GeoKey> = Vec::new();
  let mut warnings: Vec<GeoTiffWarning> = Vec::new();
  // Running total of decoded scalar elements across the WHOLE directory, bounded
  // by [`MAX_GEOKEY_ELEMENTS`] (the heap-amplification DoS floor). A crafted
  // directory of 65535 entries × `count = 65535` each (all re-reading one tiny
  // params blob) would otherwise materialize ~4 billion retained values.
  let mut total_elements: usize = 0;

  // `length($$dirData) >= 8 and length($$dirData) >= 8 * (Get16u($dirData,6) +
  // 1)` (`GeoTiff.pm:2146-2147`). The `numEntries` word lives at byte 6. The
  // product `8 * (numEntries + 1)` cannot overflow `usize` (numEntries is a
  // `u16`). A `dir` shorter than 8 bytes has no readable `numEntries` word, so
  // the first conjunct already rejects it (and `get_u16(.., 6, ..)` returns
  // `None`), matching the `>= 8` guard.
  let num_entries = match get_u16(dir, 6, order) {
    Some(n) if dir.len() >= 8 && dir.len() >= 8 * (n as usize + 1) => n,
    _ => {
      // `else { $et->Warn('Bad GeoTIFF directory') }` (`GeoTiff.pm:2212-2213`).
      warnings.push(GeoTiffWarning::BadDirectory);
      return Some(GeoTiffMeta { keys, warnings });
    }
  };

  // `my $version = Get16u($dirData,0); my $revision = Get16u($dirData,2); my
  // $minorRev = Get16u($dirData,4);` (`GeoTiff.pm:2149-2151`). The `>= 8` guard
  // proved bytes 0..8 are present, so these reads succeed.
  let version = get_u16(dir, 0, order).unwrap_or(0);
  let revision = get_u16(dir, 2, order).unwrap_or(0);
  let minor_rev = get_u16(dir, 4, order).unwrap_or(0);

  // `FoundTag(GeoTiffVersion, "$version.$revision.$minorRev")` (`GeoTiff.pm:
  // 2158-2161`) — the synthetic version key (id 1, not a real GeoKey entry),
  // emitted FIRST in walk order. Stored as a `Text` value (its `%GeoTiff::Main`
  // row has no PrintConv).
  keys.push(GeoKey {
    id: 1,
    value: GeoValue::Text(SmolStr::from(std::format!(
      "{version}.{revision}.{minor_rev}"
    ))),
  });

  // `for ($i=0; $i<$numEntries; ++$i)` (`GeoTiff.pm:2164`). Each entry is 8 bytes
  // at `8 * (i + 1)`; the structural guard above proved every entry's 8 bytes are
  // in range.
  for i in 0..num_entries as usize {
    let pt = 8 * (i + 1);
    // `my $tag = Get16u($dirData, $pt)` (`:2166`); `my $loc = Get16u($dirData,
    // $pt+2)` (`:2168`); `my $count = Get16u($dirData, $pt+4)` (`:2169`); `my
    // $offset = Get16u($dirData, $pt+6)` (`:2170`). The guard bounds these.
    let (tag, loc, mut count, mut offset) = match (
      get_u16(dir, pt, order),
      get_u16(dir, pt + 2, order),
      get_u16(dir, pt + 4, order),
      get_u16(dir, pt + 6, order),
    ) {
      (Some(t), Some(l), Some(c), Some(o)) => (t, l, c as usize, o as usize),
      // Unreachable given the structural guard, but `get_u16` is fallible —
      // skip an unreadable entry (ExifTool's reads would warn + yield 0).
      _ => continue,
    };

    // `$tagInfo = $et->GetTagInfo($tagTable, $tag) or next` (`GeoTiff.pm:2167`) —
    // an unknown GeoKey id is SKIPPED before its `loc` is even examined.
    let Some(def) = lookup(tag) else { continue };

    // `my $format = $geoTiffFormat{$loc}` (`:2171`). `loc` selects the source +
    // element format; an unrecognized `loc` warns + skips (`:2173-2175`).
    enum Source<'a> {
      /// `int16u` from the `GeoTiffDirectory` itself (`loc == 0` inline, or
      /// `loc == 0x87af`).
      Dir(&'a [u8]),
      /// `double` from `GeoTiffDoubleParams` (`loc == 0x87b0`).
      Double(Option<&'a [u8]>),
      /// `string` from `GeoTiffAsciiParams` (`loc == 0x87b1`).
      Ascii(Option<&'a [u8]>),
    }
    let (format, size, source) = match loc {
      LOC_DOUBLE => ("double", SIZE_DOUBLE, Source::Double(double_params)),
      LOC_STRING => ("string", SIZE_STRING, Source::Ascii(ascii_params)),
      0 | LOC_INT16U => {
        // `int16u` in the `GeoTiffDirectory` data. `unless ($loc)` (`:2182`): a
        // `loc == 0` entry stores the VALUE inline in the offset field — `$count
        // = 1` and `$offset = ($pt + 6) / 2` (the int16u INDEX of the offset
        // word, `:2183-2184`). `pt + 6` is even, so the division is exact.
        if loc == 0 {
          count = 1;
          offset = (pt + 6) / 2;
        }
        ("int16u", SIZE_INT16U, Source::Dir(dir))
      }
      _ => {
        // `$et->Warn("Unknown GeoTiff location ($loc) for $$tagInfo{Name}")`
        // (`:2174`) + `next` (`:2175`).
        warnings.push(GeoTiffWarning::UnknownLocation {
          loc,
          name: def.name,
        });
        continue;
      }
    };

    // `if (not $dataPt or length($$dataPt) < $size*($offset+$count))` (`:2188`):
    // the per-field availability check — the source blob must hold every element
    // at `offset..offset+count`. An absent blob (`not $dataPt`) or a short one
    // warns 'Missing FORMAT data' + skips (`:2189-2190`). `size*(offset+count)`
    // is computed in `usize` (offset/count are `u16`-derived; the product cannot
    // overflow).
    let data_pt: &[u8] = match &source {
      Source::Dir(d) => d,
      Source::Double(d) | Source::Ascii(d) => match d {
        Some(d) if !d.is_empty() => d,
        // `not $dataPt` — an absent/empty params blob.
        _ => {
          warnings.push(GeoTiffWarning::MissingData {
            format,
            name: def.name,
          });
          continue;
        }
      },
    };
    let needed = size.saturating_mul(offset.saturating_add(count));
    if data_pt.len() < needed {
      warnings.push(GeoTiffWarning::MissingData {
        format,
        name: def.name,
      });
      continue;
    }

    // Heap-amplification DoS floor (beyond-faithful): bound the TOTAL decoded
    // scalar elements across the whole directory BEFORE materializing this key's
    // `Vec`. `count` is `int16u`-derived (≤ 65535, under the per-field guard), but
    // the `count` field is re-read independently per entry, so 65535 entries each
    // re-reading the same tiny params blob would retain ~4 billion values. Charge
    // `count` (the elements this key would materialize — `int16u`/`double` words
    // or `string` bytes) and, once the running total would pass
    // [`MAX_GEOKEY_ELEMENTS`], STOP materializing further keys + warn ONCE. A
    // real GeoTiff's total is hundreds of elements, so this never fires on a
    // well-formed directory. ExifTool would OOM here; exifast truncates + warns.
    total_elements = total_elements.saturating_add(count);
    if total_elements > MAX_GEOKEY_ELEMENTS {
      warnings.push(GeoTiffWarning::DirectoryTooLarge);
      break;
    }

    // `$offset *= $size` (`:2192`) then `ReadValue($dataPt, $offset, $format,
    // $count, ...)` (`:2193`). The byte offset is `offset * size`; the bounds
    // check above proved `offset*size + count*size <= len`.
    let byte_off = offset.saturating_mul(size);
    let value = match &source {
      Source::Dir(_) => {
        // `int16u` array — `count` words at `byte_off`. Each `get_u16` is in
        // range (the bounds check proved it); collect the scalars.
        let mut v = Vec::with_capacity(count);
        for j in 0..count {
          if let Some(x) = get_u16(data_pt, byte_off + j * SIZE_INT16U, order) {
            v.push(x);
          }
        }
        GeoValue::Ints(v)
      }
      Source::Double(_) => {
        // `double` array — `count` doubles at `byte_off`.
        let mut v = Vec::with_capacity(count);
        for j in 0..count {
          if let Some(x) = get_f64(data_pt, byte_off + j * SIZE_DOUBLE, order) {
            v.push(x);
          }
        }
        GeoValue::Doubles(v)
      }
      Source::Ascii(_) => {
        // `string` — `count` bytes at `byte_off`. ExifTool reaches the value via
        // `ReadValue($dataPt, $offset, 'string', $count, ...)` (`GeoTiff.pm:2193`),
        // whose no-readValueProc `string` branch FIRST truncates at the FIRST NUL
        // (`$vals[0] =~ s/\0.*//s`, `ExifTool.pm:6301`) — dropping the NUL and
        // everything after it — and ONLY THEN does `ProcessGeoTiff` strip ONE
        // trailing terminator `$val =~ s/(\0|\|)$//` (`GeoTiff.pm:2196`). So the
        // ORDER is first-NUL-truncate, then trailing strip: `"ABC\0JUNK|"` → `"ABC"`
        // (the embedded NUL terminates the string; the `|` after it is gone),
        // `"ABC|"` → `"ABC"` (trailing `|`), `"ABC\0"`/`"ABC"` → `"ABC"`. An
        // INTERIOR `|` survives (only the trailing one is stripped): `"AB|CD\0EF|"`
        // → `"AB|CD"`.
        let bytes = data_pt.get(byte_off..byte_off + count).unwrap_or_default();
        // `s/\0.*//s` — slice the bytes at the first NUL (the canonical
        // `RawValue::Ascii` truncation, `ifd.rs:974`).
        let truncated = match bytes.iter().position(|&b| b == 0) {
          Some(nul) => bytes.get(..nul).unwrap_or(bytes),
          None => bytes,
        };
        // Decode malformed bytes ExifTool's way: its JSON writer maps each bad
        // UTF-8 byte to `?` via `FixUTF8` (`XMP.pm:2948-2972`), NOT to U+FFFD as
        // `from_utf8_lossy` would — so `b"A\xff|"` must read `A?`, not `A\u{fffd}`.
        // This is the SAME [`crate::convert::fix_utf8`] the rest of the EXIF string
        // path uses (`exiftext.rs:86`). Order vs the terminator strip: ExifTool
        // applies `FixUTF8` at print time on the ALREADY-stripped value, but
        // `fix_utf8` never produces, consumes, or alters a trailing ASCII `\0`/`|`
        // (those are `< 0x80`, copied verbatim), so decoding-then-stripping is
        // byte-identical to stripping-then-decoding. Ground-truthed vs bundled
        // ExifTool 13.59: `b"A\xff|"` → `"A?"`, `b"AB|\xff|"` → `"AB|?"`,
        // `b"WGS 84|"` → `"WGS 84"` (well-formed text unchanged).
        let mut text = crate::convert::fix_utf8(truncated);
        // `s/(\0|\|)$//` — strip the one trailing `%geoKey` terminator. After the
        // first-NUL truncation no NUL can remain, so this only ever strips a
        // trailing `|`; the `\0` arm is kept for a literal 1:1 with the Perl regex.
        if text.ends_with('\0') || text.ends_with('|') {
          text.pop();
        }
        GeoValue::Text(SmolStr::from(text))
      }
    };

    // `$et->FoundTag($tagInfo, $val)` (`:2207`) — emit the GeoKey (PrintConv
    // applied at print time, in `tags()`).
    keys.push(GeoKey { id: tag, value });
  }

  Some(GeoTiffMeta { keys, warnings })
}

/// Render one `int16u` PrintConv scalar through a GeoKey's static int->label
/// slice (`print_conv = true`) or as the raw int (`print_conv = false`). A hash
/// MISS renders the RAW INT — ExifTool's HASH-PrintConv miss with no `OTHER`/
/// `BITMASK` (`ExifTool.pm:3614-3634`); `%GeoTiff::Main` defines none, and the
/// keys carry no `PrintHex`, so the miss is the bare DECIMAL.
fn render_int_scalar(
  v: u16,
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
  // `-n`, or a PrintConv miss / a key with no PrintConv — the raw int.
  crate::value::TagValue::U64(u64::from(v))
}

impl crate::emit::Taggable for GeoTiffMeta {
  /// Yield the decoded GeoKeys as [`EmittedTag`](crate::emit::EmittedTag)s under
  /// group `GeoTiff` (family-0 and family-1 both `GeoTiff`; family-2 `Location`
  /// does not reach `-G1 -j`), in walk order. Each key resolves its name +
  /// PrintConv from [`tables::GEO_KEYS`] and renders for the active conv mode:
  /// an `int16u` scalar through its int->label hash (`-j`) or raw (`-n`), a
  /// `double` array `%.15g` space-joined, a `string` verbatim.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let print_conv = matches!(opts.mode, crate::emit::ConvMode::PrintConv);
    let mut out: Vec<crate::emit::EmittedTag> = Vec::with_capacity(self.keys.len());
    for key in &self.keys {
      // The descriptor supplies the Name + PrintConv slice. Every decoded
      // `key.id` came from [`lookup`] (or is the synthetic version id 1), so it
      // is always present here.
      let Some(def) = lookup(key.id) else { continue };
      let value = match &key.value {
        GeoValue::Ints(v) => match v.as_slice() {
          // The common case: a single `int16u` through its PrintConv (or raw).
          [scalar] => render_int_scalar(*scalar, print_conv, def.print_conv),
          // A multi-value `int16u` (no `%GeoTiff::Main` PrintConv key has
          // `count > 1`, but a non-PrintConv key could) space-joins the raw
          // decimals — ExifTool's `ReadValue` `join(' ', @vals)`. With a
          // PrintConv this would HASH on the joined string and miss → the same
          // joined raw text, so the mode does not change it.
          _ => {
            let parts: Vec<String> = v.iter().map(|x| std::format!("{x}")).collect();
            crate::value::TagValue::Str(SmolStr::from(parts.join(" ")))
          }
        },
        GeoValue::Doubles(v) => match v.as_slice() {
          [scalar] => {
            crate::value::TagValue::Str(SmolStr::from(crate::value::format_g(*scalar, 15)))
          }
          _ => {
            let parts: Vec<String> = v.iter().map(|x| crate::value::format_g(*x, 15)).collect();
            crate::value::TagValue::Str(SmolStr::from(parts.join(" ")))
          }
        },
        GeoValue::Text(s) => crate::value::TagValue::Str(s.clone()),
      };
      out.push(crate::emit::EmittedTag::new(
        crate::value::Group::new("GeoTiff", "GeoTiff"),
        SmolStr::new(def.name),
        value,
        false,
      ));
    }
    out.into_iter()
  }
}
