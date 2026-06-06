// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Sony::Process_rtmd`
//! (Sony.pm:11566-11602) — the Sony "Real-Time MetaData" walker shared by
//! the Alpha A7 / A9 / FX / RX / Cinema-line MP4 / MOV recorders. Backed by
//! the `Image::ExifTool::Sony::rtmd` tag table (Sony.pm:10686-10850).
//!
//! ## Container
//!
//! Each rtmd sample begins with a 2-byte big-endian header length
//! (`Get16u($dataPt, 0)`, Sony.pm:11581). Bundled hard-codes the assumption
//! that the value is `0x1c` (28); we honour the value as-stored so a future
//! firmware that emits a different header still parses.
//!
//! After the header, records follow the shape `[tag:int16u-BE][len:int16u-BE]
//! [value:len bytes]`. Two special cases (Sony.pm:11586-11591):
//!
//!  - **`tag == 0x060e`** — the length field is REPLACED with a fixed `0x10`
//!    (16 bytes), AND `$pos` is NOT advanced past the 4-byte header. The
//!    walker reads 16 bytes STARTING at `$pos` (so the tag + len bytes are
//!    INCLUDED in those 16). Bundled comments say `# 0x060e - 16 bytes
//!    starting with 0x060e2b340253 (fake tag ID - comes before 0x8300
//!    container)`. This is the SMPTE Universal Label that introduces the
//!    container.
//!  - **`tag == 0x8300`** — the 4-byte header IS skipped (`$pos += 4`),
//!    `len` is the body length, but the loop continues with `next` and the
//!    increment `$pos += $len` is SKIPPED. The next iteration thus reads
//!    the FIRST record inside the container as if it were a sibling — a
//!    flat-recursion (inline descend) into the container's children.
//!
//! ## Loop termination
//!
//! Bundled (Sony.pm:11582-11600):
//!  - `while ($pos + 4 < $end)` — strict-less, identical to camm / mebx
//!    bounds handling; a trailing 4-byte remainder is dropped without
//!    decode.
//!  - `last if $tag == 0` — a zero-tag stops the walk (padding / EOM).
//!  - `last if $pos + $len > $end` — a truncated value stops the walk.
//!
//! ## What this module emits
//!
//! For each decoded sample, [`process_rtmd`] builds one
//! [`crate::metadata::SonyRtmdSample`] holding that sample's
//! [`SonyRtmdCameraSnapshot`] + (when any `0x85xx` GPS tag is present) its
//! [`SonyRtmdGpsSample`], correlated on one element. The aggregation is
//! per-CALL — one call = one sample; the QuickTimeStream dispatcher loops
//! over samples and pushes each unified [`crate::metadata::SonyRtmdSample`]
//! onto [`SonyRtmdMeta`] in source order.
//!
//! ## Endianness
//!
//! `Image::ExifTool::Sony` sets `BIG_ENDIAN` as the default byte order
//! (Sony.pm:55 `SetByteOrder('MM')` is the bundled `%Image::ExifTool::Sony`
//! initializer behaviour for rtmd records; `Get16u`/`Get32u` in the walker
//! inherit it).
//!
//! ## GPS priority chain
//!
//! Sony rtmd feeds the **THIRD-HIGHEST tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. Sony rtmd GPS is phone-paired
//! (Imaging Edge Mobile pairs the body to a phone whose GNSS feeds the
//! samples) so it ranks below GoPro / CAMM on-device-hardware GPS but
//! above Insta360 / SP3 (both also phone-paired or scan-based).

extern crate alloc;

use smol_str::SmolStr;

use crate::metadata::{
  NumericRead, SonyRtmdCameraSnapshot, SonyRtmdCoord, SonyRtmdGpsSample, SonyRtmdMeta,
  SonyRtmdSample,
};
use crate::value::Rational;

// ===========================================================================
// Big-endian readers (Sony rtmd is big-endian)
// ===========================================================================

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .and_then(|s| <[u8; 2]>::try_from(s).ok())
    .map(u16::from_be_bytes)
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map(u32::from_be_bytes)
}

// ===========================================================================
// Tag IDs (Sony.pm:10686-10850)
// ===========================================================================

const TAG_SMPTE_LABEL: u16 = 0x060e; // 16-byte fixed Universal Label
const TAG_CONTAINER: u16 = 0x8300; // recurse into contents (no len skip)

// Camera / capture (Sony.pm:10700-10735)
const TAG_FNUMBER: u16 = 0x8000;
const TAG_FRAME_RATE: u16 = 0x8106;
const TAG_EXPOSURE_TIME: u16 = 0x8109;
const TAG_MASTER_GAIN: u16 = 0x810a;
const TAG_ISO: u16 = 0x810b;
const TAG_ELECTRICAL_EXTENDER_MAGNIFICATION: u16 = 0x810c;
const TAG_SERIAL_NUMBER: u16 = 0x8114;

// GPS (Sony.pm:10738-10811)
const TAG_GPS_VERSION_ID: u16 = 0x8500;
const TAG_GPS_LATITUDE_REF: u16 = 0x8501;
const TAG_GPS_LATITUDE: u16 = 0x8502;
const TAG_GPS_LONGITUDE_REF: u16 = 0x8503;
const TAG_GPS_LONGITUDE: u16 = 0x8504;
const TAG_GPS_TIME_STAMP: u16 = 0x8507;
const TAG_GPS_STATUS: u16 = 0x8509;
const TAG_GPS_MEASURE_MODE: u16 = 0x850a;
const TAG_GPS_MAP_DATUM: u16 = 0x8512;
const TAG_GPS_DATE_STAMP: u16 = 0x851d;

// Time / WB (Sony.pm:10817-10833)
const TAG_WHITE_BALANCE: u16 = 0xe303;
const TAG_DATE_TIME: u16 = 0xe304;

// Motion (Sony.pm:10877-10887) — both `int16s` with `RawConv substr($val,8)`.
const TAG_PITCH_ROLL_YAW: u16 = 0xe43b;
const TAG_ACCELEROMETER: u16 = 0xe44b;

// Alternate ISO seen on FX-line firmware (`0xe301`, int32u; Sony.pm:10814).
// Bundled marks it `%hidUnk` and notes "seen: 100, 1600, 12800 - ISO". We
// fold it into the typed `iso` slot when the canonical `0x810b` was absent.
const TAG_ISO_ALT: u16 = 0xe301;

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// The CONSTANT string `GPS::ConvertTimeStamp` (GPS.pm:459-474) emits when ANY
/// `0x8507 GPSTimeStamp` H/M/S component is `inf` (an `n/0` `rational64u`,
/// `n != 0`). With no inf/undef guard, `$f` goes infinite and the spelled-out
/// result is invariant across the three component positions: `int(inf)` →
/// `"Inf"` for the hour, the propagated NaN → `"NaN"` for the minute, and
/// `sprintf('%012.9f', NaN)` → `"000000000NaN"` for the second. Verified
/// byte-exact vs bundled ExifTool 13.59 at both `-j` and `-n`.
const GPS_TIME_STAMP_NON_FINITE: &str = "Inf:NaN:000000000NaN";

/// `Image::ExifTool::Exif::PrintFNumber` (Exif.pm:5715-5723) — the
/// PrintConv used by `0x8000 FNumber` (Sony.pm:10700-10705). Bundled rounds
/// `< 1.0` to 2 decimals, otherwise to 1. exifast keeps the unrounded
/// `f64` in the typed snapshot; the rounded form is a presentation concern
/// (and would lose precision relative to the bundled `Value` channel under
/// `-n`).
///
/// The `ValueConv = 2^(8-val/8192)` (Sony.pm:10703) IS applied here.
fn decode_fnumber(value: &[u8]) -> Option<f64> {
  // Bundled format is `int16u` (Sony.pm:10702) — read 2 BE bytes.
  let raw = be_u16(value, 0)? as f64;
  // `2 ** (8 - raw/8192)`.
  Some(f64::powf(2.0, 8.0 - raw / 8192.0))
}

/// Read a `rational64u` as the typed [`Rational`] (two BE `u32`: numerator,
/// denominator) WITHOUT pre-dividing. Used by `0x8106 FrameRate` /
/// `0x8109 ExposureTime`, whose `-n` emission must render ExifTool's rational
/// `%g` form (`29.97002997`, not the 15-digit f64) and preserve the
/// zero-denominator `undef` case (Sony.pm:10731/10737, `GetRational64u`
/// rounds to 10 sig-figs). `Rational::rational64` carries `sig = 10`.
fn decode_rational64u_typed(value: &[u8]) -> Option<Rational> {
  let num = be_u32(value, 0)?;
  let denom = be_u32(value, 4)?;
  Some(Rational::rational64(i64::from(num), i64::from(denom)))
}

/// `0x810b ISO` (Sony.pm:10728) — `int16u` raw.
fn decode_iso_u16(value: &[u8]) -> Option<u32> {
  be_u16(value, 0).map(u32::from)
}

/// `0xe301` alt-ISO (Sony.pm:10814) — `int32u` raw.
fn decode_iso_u32(value: &[u8]) -> Option<u32> {
  be_u32(value, 0)
}

/// `0x810a MasterGainAdjustment` (Sony.pm:10722-10727) — `int16u / 100` dB.
fn decode_master_gain_db(value: &[u8]) -> Option<f64> {
  let raw = be_u16(value, 0)? as f64;
  Some(raw / 100.0)
}

/// `0x8114 SerialNumber` (Sony.pm:10734) — `Format => 'string'`. Bundled
/// trims a trailing NUL via `ReadValue`; we mirror that.
fn decode_string(value: &[u8]) -> Option<SmolStr> {
  // Bundled `ReadValue('string')` truncates at the FIRST NUL
  // (`$vals[0] =~ s/\0.*//s`, ExifTool.pm:6311) and does NOT trim whitespace.
  // For the normal NUL-padded Sony strings this equals a trailing-NUL strip; it
  // diverges only for stale bytes AFTER an embedded NUL (e.g. `b"N\0S"` ⇒ `"N"`,
  // not `"N\0S"`, which ExifTool drops) and for space padding (KEPT, not
  // trimmed). Invalid pre-NUL bytes are FixUTF8-substituted, NOT dropped (see
  // below; normal Sony rtmd strings are ASCII).
  //
  // A record of length >= 1 whose value truncates to empty (a leading NUL, or a
  // record that is all NULs) yields a DEFINED EMPTY STRING — `ReadValue` returns
  // `""` and `FoundTag` stores it, so bundled emits the tag with an empty value.
  //
  // A ZERO-LENGTH record (`Size => 0`) is ALSO a DEFINED EMPTY STRING — for a
  // NON-FINAL zero-length TLV the `Process_rtmd` walker (`while $pos+4 < $end`)
  // still reaches `HandleTag(Size => 0)`, and `ReadValue` returns `''` (the
  // `unless ($count) { return '' if … $size < $len }` branch, ExifTool.pm:6297
  // — `$size 0 < $len`). So a present zero-length `string` record emits the tag
  // with `""`. (The ONLY case bundled OMITS the tag is a FINAL bare 4-byte
  // header, where `pos+4 == end` exits the walk BEFORE `HandleTag` — handled by
  // the walker bound, not here.) Verified vs bundled ExifTool 13.59: a NON-FINAL
  // zero-length `0x8114`/`0x8501`/`0x8509`/… record is PRESENT-but-empty (`""`).
  let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
  // Invalid pre-NUL bytes do NOT drop the tag: bundled stores the raw byte
  // string (`ReadValue` does not validate UTF-8) and `exiftool` runs
  // `XMP::FixUTF8` at JSON output (`exiftool:3822`), substituting one ASCII `?`
  // per malformed byte (`XMP.pm:2949-2972`) in BOTH -j and -n. Route through the
  // engine's faithful [`crate::convert::fix_utf8`] — the SAME path `read_value`'s
  // `string` arm uses (convert.rs) — so a hostile `b"A\xffB"` ⇒ `"A?B"`, never a
  // dropped tag (and a GPS-only malformed string still sets `saw_gps`).
  Some(SmolStr::new(crate::convert::fix_utf8(value.get(..end)?)))
}

/// `0xe304 DateTime` (Sony.pm:10828-10834) — `Format => 'undef'`, BCD-packed
/// record. `ValueConv => 'my @a=unpack("x1H4H2H2H2H2H2",$val); "$a[0]:$a[1]:$a[2]
/// $a[3]:$a[4]:$a[5]"'`:
///   - skip byte 0 (`x1`);
///   - 2-byte year as a 4-digit hex string (`H4`, e.g. `0x20 0x24 → "2024"`);
///   - 1-byte month, day, hour, minute, second each as 2-digit hex (`H2`).
///
/// Each byte is rendered as a HEX-DIGITS string, NOT decimal — so a
/// `month` byte `0x05` becomes `"05"`, `0x12` becomes `"12"` (which on a
/// BCD-packed source IS the decimal 12). Bundled then joins them with
/// the formatting `"$y:$mo:$d $h:$mi:$s"`. `PrintConv => ConvertDateTime`
/// passes a malformed (partial) value through unchanged, so `-j` == `-n`.
///
/// A PRESENT record of ANY length yields a DEFINED (possibly PARTIAL) value —
/// Perl's `unpack` fills each `H`-field from whatever bytes remain and renders
/// `""` for a field with no remaining bytes (`H4`/`H2` past the end of the
/// buffer ⇒ empty). So a record SHORTER than 8 bytes is NOT dropped: the joined
/// template still emits, with the empty fields collapsing to bare separators.
/// Verified byte-exact vs bundled ExifTool 13.59 for each length 0..8:
///   0/1 → `":: ::"`        2 → `"20:: ::"`    3 → `"2024:: ::"`
///   4 → `"2024:03: ::"`    5 → `"2024:03:05 ::"`
///   6 → `"2024:03:05 10::"`  7 → `"2024:03:05 10:20:"`  8 → full.
/// This decoder therefore NEVER returns `None` for a present record.
fn decode_date_time(value: &[u8]) -> SmolStr {
  use core::fmt::Write;
  // `unpack("x1H4H2H2H2H2H2", $val)`: `x1` skips byte 0, then each `H`-field
  // consumes its bytes from the remaining buffer (2 nibbles per byte, MSB-first)
  // and yields the EMPTY STRING when no bytes remain. `value.get(1..)` is the
  // post-`x1` tail; a record shorter than 1 byte yields an empty tail (every
  // field empty) — matching Perl `unpack` past end-of-string.
  let tail = value.get(1..).unwrap_or(&[]);
  // `H4` reads UP TO 2 bytes (the year); `H2` ×5 each read UP TO 1 byte. Perl's
  // `unpack` consumes whatever bytes REMAIN — a field requesting more bytes than
  // are left renders only what is present (e.g. `H4` on a 1-byte tail → 2
  // nibbles), and a field with no bytes left renders `""`. `clamped_slice` takes
  // up to `n` bytes from `start`, returning a (possibly shorter / empty) slice.
  let year = hex_nibbles(clamped_slice(tail, 0, 2));
  let month = hex_nibbles(clamped_slice(tail, 2, 1));
  let day = hex_nibbles(clamped_slice(tail, 3, 1));
  let hour = hex_nibbles(clamped_slice(tail, 4, 1));
  let minute = hex_nibbles(clamped_slice(tail, 5, 1));
  let second = hex_nibbles(clamped_slice(tail, 6, 1));
  let mut out = alloc::string::String::with_capacity(19);
  let _ = write!(out, "{year}:{month}:{day} {hour}:{minute}:{second}");
  SmolStr::new(out)
}

/// Take UP TO `n` bytes from `bytes` starting at `start`, clamping to the buffer
/// end — Perl `unpack`'s "consume what remains" semantics for a fixed-width `H`
/// field. `start >= bytes.len()` yields an empty slice (the field ran past the
/// end of the record); a partial range yields the available prefix.
fn clamped_slice(bytes: &[u8], start: usize, n: usize) -> &[u8] {
  let end = start.saturating_add(n).min(bytes.len());
  bytes.get(start..end).unwrap_or(&[])
}

/// Render a byte slice as Perl `unpack("H…")` lowercase hex nibbles, MSB-first
/// (high nibble then low nibble of each byte). An EMPTY slice renders `""` —
/// Perl's `unpack` of an `H` field with no remaining bytes yields the empty
/// string. A PARTIAL `H4` (only one byte present where two were requested)
/// renders just that byte's two nibbles, exactly as `unpack` does (verified vs
/// bundled 13.59: a 1-byte year buffer `0x20` → `"20"`).
fn hex_nibbles(bytes: &[u8]) -> alloc::string::String {
  use core::fmt::Write;
  let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
  for b in bytes {
    // `:02x` is lowercase hex (Perl `H` is lowercase); for BCD the result is
    // digits-only so the case is moot, but this matches `unpack` exactly.
    let _ = write!(out, "{b:02x}");
  }
  out
}

/// `0x810c ElectricalExtenderMagnification` (Sony.pm:10769-10772) —
/// `Format => 'int16u'`, no conv. Read 2 BE bytes.
fn decode_eem_u16(value: &[u8]) -> Option<u16> {
  be_u16(value, 0)
}

/// `0xe303 WhiteBalance` (Sony.pm:10816-10827) — `int8u` raw.
fn decode_u8(value: &[u8]) -> Option<u8> {
  value.first().copied()
}

/// `0xe43b PitchRollYaw` / `0xe44b Accelerometer` (Sony.pm:10877-10887) —
/// `Format => 'int16s'`, `RawConv => 'substr($val, 8)'`.
///
/// **This is a STRING substr, NOT a byte skip.** ExifTool's `HandleTag`
/// reads the WHOLE record value as an `int16s` array FIRST (`ReadValue`,
/// ExifTool.pm:9337 — count = `size / 2` big-endian signed shorts,
/// space-joined into a single scalar), and only THEN — in `FoundTag`
/// (ExifTool.pm:9484) — applies the non-SubDirectory `RawConv`
/// `substr($val, 8)` to that RENDERED STRING, dropping its first 8
/// CHARACTERS. (Verified empirically against bundled ExifTool 13.59: a
/// 14-byte record `aabbccdd11223344 0064 ff38 012c` decodes to the
/// 7-element string `"-21829 -13091 4386 13124 100 -200 300"`, whose
/// `substr(_, 8)` is `"13091 4386 13124 100 -200 300"`.)
///
/// When the rendered string is shorter than 8 characters Perl's `substr`
/// warns `substr outside of string` and returns `undef` ⇒ ExifTool raises a
/// `RawConv` Warning and DROPS the tag; we mirror that by returning `None`.
fn decode_int16s_substr8(value: &[u8]) -> Option<SmolStr> {
  use core::fmt::Write;
  // ReadValue('int16s', count = len/2): a trailing odd byte is ignored
  // (ExifTool reads only whole `int16s` units). Big-endian, space-joined.
  let mut rendered = alloc::string::String::with_capacity(value.len() * 4);
  for (i, pair) in value.chunks_exact(2).enumerate() {
    if i > 0 {
      rendered.push(' ');
    }
    // `chunks_exact(2)` yields 2-byte slices; `try_into` to a fixed array
    // avoids raw `pair[0]`/`pair[1]` indexing (the formats-tree
    // `#![deny(clippy::indexing_slicing)]` parser-panic-safety contract).
    let v = match <[u8; 2]>::try_from(pair) {
      Ok(bytes) => i16::from_be_bytes(bytes),
      Err(_) => break,
    };
    let _ = write!(rendered, "{v}");
  }
  // `substr($val, 8)` on the rendered string — drop the first 8 CHARS. A
  // string shorter than 8 chars ⇒ Perl `substr outside of string` ⇒ undef.
  if rendered.len() < 8 {
    return None;
  }
  // ASCII-only (digits / `-` / space), so byte-slicing at 8 is char-safe.
  let tail = rendered.get(8..)?;
  Some(SmolStr::new(tail))
}

/// `0x8500 GPSVersionID` (Sony.pm:10738-10743) — `int8u` value with
/// `PrintConv => '$val =~ tr/ /./; $val'`. Bundled `ReadValue` for `int8u`
/// with `Count != 1` joins the values with spaces; the PrintConv then
/// rewrites spaces to dots. We mirror the final form. A NON-FINAL zero-length
/// record is a present, DEFINED tag — `ReadValue` returns `''`, the `tr` leaves
/// it `''`, so bundled emits `GPSVersionID ""` (verified vs ExifTool 13.59); the
/// empty-`value` loop below yields the same `""` (so this never returns `None`).
fn decode_gps_version_id(value: &[u8]) -> Option<SmolStr> {
  let mut out = alloc::string::String::with_capacity(value.len() * 4);
  use core::fmt::Write;
  for (i, b) in value.iter().enumerate() {
    if i > 0 {
      out.push('.');
    }
    let _ = write!(out, "{b}");
  }
  Some(SmolStr::new(out))
}

/// `0x8502 GPSLatitude` / `0x8504 GPSLongitude` — up to three `rational64u`
/// components (degrees, minutes, seconds). `ValueConv` calls
/// `GPS::ToDegrees($val)` on the joined string, returning `D + M/60 + S/3600`
/// (GPS.pm:582-600). ExifTool reads each component as a `rational64u`
/// (`GetRational64u` ⇒ `RoundFloat` to 10 sig figs, or `"undef"`/`"inf"` for a
/// zero denominator) BEFORE `ToDegrees`, and `ToDegrees` line 585 `return ''
/// if $val =~ /\b(inf|undef)\b/` returns the EMPTY STRING (a DEFINED value)
/// when ANY component is inf/undef.
///
/// A PRESENT record (which — for a NON-FINAL TLV — INCLUDES a zero-length
/// `Size => 0` one; the walker still reaches `HandleTag` and `ReadValue` returns
/// `''`) therefore ALWAYS yields a defined tag — `GetTagInfo`/`FoundTag` store
/// either the decimal (all-finite) or `""`. So this NEVER returns `None`; it
/// returns:
///  - [`SonyRtmdCoord::Value`] — every present component finite (rounded to
///    match the bundled `-n` value for a non-decimal denominator);
///  - [`SonyRtmdCoord::Empty`] — ANY present component renders `inf`/`undef`,
///    the record is too short (1–7 bytes) to carry even the degrees component,
///    OR the record is ZERO-LENGTH (`ToDegrees('')` extracts no `$d` ⇒
///    `return ''`). Verified vs bundled ExifTool 13.59: a 4-byte AND a NON-FINAL
///    zero-length `0x8502` both render `""` (present-empty). (Record ABSENCE —
///    a FINAL bare 4-byte header — is handled by the walker bound, never here.)
///
/// The tag is `Format => 'rational64u'` with NO `Count`, so `ReadValue` derives
/// the component count from the RECORD SIZE (`int($size / 8)`): a 1-component
/// (8-byte) or 2-component (16-byte) record is valid. `GPS::ToDegrees` accepts
/// 1-3 components (`$deg + (($min || 0) + ($sec || 0)/60)/60`), so a missing
/// minute / second defaults to 0. Verified against bundled ExifTool 13.59: an
/// 8-byte `"12/1"` GPSLatitude → `12`; a 16-byte `"122/1 30/1"` GPSLongitude →
/// `122.5`; an inf/undef in ANY of D/M/S, or a 1–7 byte record → `""`.
fn decode_gps_coordinate(value: &[u8]) -> Option<SonyRtmdCoord> {
  // A NON-FINAL zero-length record (`Size => 0`) is STILL a present, defined tag:
  // the walker reaches `HandleTag(Size => 0)`, `ReadValue` returns `''`, and
  // `GPS::ToDegrees('')` (GPS.pm:582) extracts no `$d` ⇒ `return ''` — the EMPTY
  // STRING (a DEFINED value). So a zero-length coordinate is `Some(Empty)` (NOT
  // absent), exactly like a too-short (1–7-byte) record. Verified vs bundled
  // ExifTool 13.59: a NON-FINAL zero-length `0x8502` emits `GPSLatitude ""`.
  if value.is_empty() {
    return Some(SonyRtmdCoord::Empty);
  }
  // Up to 3 × rational64u; `ReadValue` reads whole 8-byte components only.
  let mut components = value.chunks_exact(8);
  // Degrees: required for a finite value. An absent degrees component (record
  // 1–7 bytes) means `ToDegrees` sees no `$d` ⇒ `return ''` (present-empty).
  let Some(d) = degrees_component(components.next()) else {
    return Some(SonyRtmdCoord::Empty);
  };
  // Minutes / seconds: a MISSING component defaults to 0 (`($min || 0)`); a
  // PRESENT inf/undef component renders `""` (the whole coordinate is Empty).
  let Some(m) = degrees_component_or_zero(components.next()) else {
    return Some(SonyRtmdCoord::Empty);
  };
  let Some(s) = degrees_component_or_zero(components.next()) else {
    return Some(SonyRtmdCoord::Empty);
  };
  Some(SonyRtmdCoord::Value(d + m / 60.0 + s / 3600.0))
}

/// The degrees / minutes / seconds component when one is PRESENT: `Some(f)` for
/// a finite `GetRational64u`-rounded value, or `None` when the component is
/// absent OR renders `"inf"`/`"undef"` (a zero denominator). Used for the
/// REQUIRED degrees component (absent ⇒ Empty) — see
/// [`degrees_component_or_zero`] for the optional minute/second.
fn degrees_component(component: Option<&[u8]>) -> Option<f64> {
  let value = component?;
  let num = be_u32(value, 0)?;
  let denom = be_u32(value, 4)?;
  let rendered = Rational::rational64(i64::from(num), i64::from(denom)).exiftool_val_str();
  if rendered == "inf" || rendered == "undef" {
    return None;
  }
  rendered.parse::<f64>().ok()
}

/// The optional minute / second component: an ABSENT component defaults to
/// `Some(0.0)` (`GPS::ToDegrees` `($min || 0)` / `($sec || 0)`), while a PRESENT
/// component routes through [`degrees_component`] — so a present inf/undef
/// yields `None` (⇒ the whole coordinate is Empty), distinct from an absent one.
fn degrees_component_or_zero(component: Option<&[u8]>) -> Option<f64> {
  match component {
    None => Some(0.0),
    Some(_) => degrees_component(component),
  }
}

/// `0x8507 GPSTimeStamp` (Sony.pm:10776-10781) — three rational64u in
/// `"H M S"` form, then `GPS::ConvertTimeStamp` reformats to
/// `"HH:MM:SS[.s+]"` (GPS.pm:459-474). A PRESENT record — which, for a NON-FINAL
/// TLV, INCLUDES a zero-length `Size => 0` one (`ConvertTimeStamp('')` defaults
/// every `($x||0)` component to 0 ⇒ `"00:00:00"`) — always yields a DEFINED
/// value (this never returns `None`): the typed layer stores the
/// post-`ConvertTimeStamp` string, or the CONSTANT `"Inf:NaN:000000000NaN"` for
/// an `inf` component (see [`GPS_TIME_STAMP_NON_FINITE`]). Record PRESENCE is
/// the caller's concern (a FINAL bare 4-byte header is excluded by the walker
/// bound, never reaching this decoder).
fn decode_gps_time_stamp(value: &[u8]) -> Option<SmolStr> {
  // ExifTool reads each H/M/S as a `rational64u` (`GetRational64u`), which
  // ROUNDS the quotient to 10 significant figures (`RoundFloat(n/d, 10)`)
  // BEFORE `ConvertTimeStamp` does its arithmetic. A non-decimal denominator
  // (e.g. `1496725904/123456789` = 12.1234799327…) must therefore be rounded
  // to `12.12347993` first, else the rebuilt seconds carry extra digits the
  // bundled `-n` value never shows. Route each component through
  // `Rational::exiftool_val_str()` (the `%.10g` form) parsed back to f64.
  //
  // The tag is `Format => 'rational64u'` with NO `Count`, so a 0/1/2/3-component
  // record is valid — `ConvertTimeStamp` splits on space and `($x || 0)` defaults
  // EVERY missing component (including the hour) to 0. A NON-FINAL ZERO-LENGTH
  // record (`Size => 0`) is STILL a present, defined tag: the walker reaches
  // `HandleTag(Size => 0)`, `ReadValue` returns `''`, and `ConvertTimeStamp('')`
  // splits to an empty list ⇒ every H/M/S `($x||0)` is 0 ⇒ `"00:00:00"`. So an
  // empty record is `Some("00:00:00")` (NOT absent), exactly like a too-short
  // (1–7-byte) record. Verified against bundled ExifTool 13.59: an 8-byte `"12/1"`
  // → `12:00:00`, a 1–7-byte record → `00:00:00`, and a NON-FINAL zero-length
  // `0x8507` → `00:00:00` (PRESENT, NOT a dropped tag).
  let mut components = value.chunks_exact(8);
  let h = rounded_rational64u_or_zero(components.next());
  let m = rounded_rational64u_or_zero(components.next());
  let s = rounded_rational64u_or_zero(components.next());
  // A non-finite component — an `inf` from an `n/0` rational (`"inf"` parses as
  // `f64::INFINITY`, unlike `"undef"` from `0/0` which fails to parse → numifies
  // to 0, matching ExifTool's `($x||0)`) — makes `ConvertTimeStamp`'s `$f`
  // infinite. ExifTool has NO inf/undef guard there: `int(inf)` interpolates as
  // `"Inf"`, the NaN arithmetic propagates, and `sprintf('%012.9f', NaN)` →
  // `"000000000NaN"`, so the result is the CONSTANT string
  // `"Inf:NaN:000000000NaN"` for an inf in ANY of the H/M/S positions (verified
  // byte-exact vs bundled ExifTool 13.59 for each position, both `-j` and `-n`).
  // Emit that constant verbatim — do NOT call `format_gps_time_stamp`, whose
  // `i64` casts would give a Rust-specific saturated value instead.
  if !h.is_finite() || !m.is_finite() || !s.is_finite() {
    return Some(SmolStr::new(GPS_TIME_STAMP_NON_FINITE));
  }
  Some(SmolStr::new(format_gps_time_stamp(h, m, s)))
}

/// Read a `rational64u` (two BE `u32`) and return its `GetRational64u`-rounded
/// `f64` — `RoundFloat(n/d, 10)` via [`Rational::exiftool_val_str`] parsed
/// back. This matches the value `GPS::ConvertTimeStamp` consumes (it operates
/// on the already-rounded `$val`, not the raw quotient). A zero denominator
/// yields `0.0` (the `"undef"`/`"inf"` string is not numeric; `ConvertTimeStamp`
/// `($x || 0)` treats a non-numeric component as 0 — Sony rtmd timestamps never
/// carry a zero denominator in practice).
fn rounded_rational64u(value: &[u8]) -> Option<f64> {
  let num = be_u32(value, 0)?;
  let denom = be_u32(value, 4)?;
  let rounded = Rational::rational64(i64::from(num), i64::from(denom)).exiftool_val_str();
  // `"undef"` (`0/0`) does not parse as f64 ⇒ fall back to 0.0, matching Perl
  // `($x || 0)` numification of a non-numeric scalar. `"inf"` (`n/0`, n≠0) DOES
  // parse to `f64::INFINITY` in Rust — preserved so the caller's `is_finite`
  // guard fires (bundled `ConvertTimeStamp` likewise lets the inf propagate).
  Some(rounded.parse::<f64>().unwrap_or(0.0))
}

/// The H / M / S timestamp component: an ABSENT component (a record shorter than
/// the next 8-byte boundary) defaults to `0.0` (`GPS::ConvertTimeStamp`
/// `($x || 0)`), while a PRESENT one routes through [`rounded_rational64u`]
/// (which yields `f64::INFINITY` for an `inf` `n/0` rational). So a present
/// record always produces a defined H/M/S triplet — record presence is the
/// caller's concern, never a dropped tag.
fn rounded_rational64u_or_zero(component: Option<&[u8]>) -> f64 {
  match component {
    None => 0.0,
    // A present 8-byte chunk always decodes (`be_u32` of 8 bytes never fails);
    // the `unwrap_or` is a total-function safety net, not a reachable default.
    Some(c) => rounded_rational64u(c).unwrap_or(0.0),
  }
}

/// `Image::ExifTool::GPS::ConvertTimeStamp` (GPS.pm:459-474). Inputs are
/// the H / M / S triplet AS NUMBERS (the rational quotients). Bundled
/// reconstructs the total seconds, splits into HH / MM / `sprintf("%012.9f",
/// $f)` then strips trailing zeros (after the decimal point); if the
/// rebuilt seconds float >= 60.0 rounds up the minute (and the hour).
fn format_gps_time_stamp(h_in: f64, m_in: f64, s_in: f64) -> alloc::string::String {
  use core::fmt::Write;
  // `my $f = (($h || 0) * 60 + ($m || 0)) * 60 + ($s || 0);`
  let f = (h_in * 60.0 + m_in) * 60.0 + s_in;
  let h_full = (f / 3600.0).floor();
  let mut f1 = f - h_full * 3600.0;
  let m_full = (f1 / 60.0).floor();
  f1 -= m_full * 60.0;

  // `sprintf('%012.9f', $f)` — 12 chars wide, 9 fractional digits,
  // zero-padded. The string IS what bundled tests against `>= 60`.
  let ss_str = alloc::format!("{f1:012.9}");
  let ss_num: f64 = ss_str.parse().unwrap_or(f1);
  let mut h_out = h_full as i64;
  let mut m_out = m_full as i64;
  let ss_final = if ss_num >= 60.0 {
    m_out += 1;
    if m_out >= 60 {
      m_out -= 60;
      h_out += 1;
    }
    alloc::string::String::from("00")
  } else {
    // `$ss =~ s/\.?0+$//` — strip trailing zeros, AND the trailing `.` if
    // it ends up bare.
    trim_trailing_zeros(&ss_str)
  };
  let mut out = alloc::string::String::with_capacity(16);
  let _ = write!(out, "{h_out:02}:{m_out:02}:{ss_final}");
  out
}

/// Perl `s/\.?0+$//` — strip trailing zeros, plus an optional trailing
/// `.` if the trim landed it bare. Operates on a `sprintf("%012.9f", $f)`
/// shape (always carries a `.`), so the regex is safe.
fn trim_trailing_zeros(s: &str) -> alloc::string::String {
  let trimmed = s.trim_end_matches('0');
  let trimmed = trimmed.trim_end_matches('.');
  alloc::string::String::from(trimmed)
}

/// `0x851d GPSDateStamp` (Sony.pm:10806-10811) — `Format => 'string'`,
/// `ValueConv => 'Image::ExifTool::Exif::ExifDate($val)'`. Bundled
/// `ExifDate` (Exif.pm:6068-6076):
///   - strips a trailing NUL;
///   - rewrites `YYYY?MM?DD` (any non-digit separator) to `YYYY:MM:DD`;
///   - already-colon-separated input passes through unchanged.
fn decode_gps_date_stamp(value: &[u8]) -> Option<SmolStr> {
  let s = decode_string(value)?;
  Some(SmolStr::new(exif_date(&s)))
}

/// `Image::ExifTool::Exif::ExifDate` (Exif.pm:6068-6076).
fn exif_date(input: &str) -> alloc::string::String {
  let s = input.trim_end_matches('\0');
  // Trailing 4-digit-year + 2-digit-month + 2-digit-day with any
  // non-digit separators ⇒ rewrite to colon-separated. We match only
  // when the input ends with `\d{4}\D*\d{2}\D*\d{2}`.
  let bytes = s.as_bytes();
  let n = bytes.len();
  if n >= 8 {
    // Try to find a (Y,Y,Y,Y, sep*, M,M, sep*, D,D) tail.
    if let Some(rebuilt) = try_rebuild_exif_date(s) {
      return rebuilt;
    }
  }
  alloc::string::String::from(s)
}

/// Walk backwards from the end of `s`: pop 2 digits (day), skip non-digits,
/// pop 2 digits (month), skip non-digits, pop 4 digits (year). If the
/// preceding text is empty OR we can identify a clean prefix split, rebuild
/// `${prefix}YYYY:MM:DD`. Returns `None` when the tail does NOT match the
/// trailing-date pattern (bundled then leaves the input untouched).
fn try_rebuild_exif_date(s: &str) -> Option<alloc::string::String> {
  // Operate on bytes (ASCII-only for an ExifDate stamp).
  let bytes = s.as_bytes();
  let mut i = bytes.len();

  // Take last 2 digits.
  let d_end = i;
  let d_start = take_n_digits_back(bytes, i, 2)?;
  i = d_start;
  // Skip non-digits.
  i = skip_nondigits_back(bytes, i);
  // Take 2 digits.
  let m_end = i;
  let m_start = take_n_digits_back(bytes, i, 2)?;
  i = m_start;
  // Skip non-digits.
  i = skip_nondigits_back(bytes, i);
  // Take 4 digits (year).
  let y_end = i;
  let y_start = take_n_digits_back(bytes, i, 4)?;
  // Anything before y_start is a prefix that bundled leaves verbatim.
  let prefix = core::str::from_utf8(bytes.get(..y_start)?).ok()?;
  let y = core::str::from_utf8(bytes.get(y_start..y_end)?).ok()?;
  let m = core::str::from_utf8(bytes.get(m_start..m_end)?).ok()?;
  let d = core::str::from_utf8(bytes.get(d_start..d_end)?).ok()?;
  Some(alloc::format!("{prefix}{y}:{m}:{d}"))
}

fn take_n_digits_back(bytes: &[u8], end: usize, n: usize) -> Option<usize> {
  if end < n {
    return None;
  }
  let start = end - n;
  if bytes.get(start..end)?.iter().all(u8::is_ascii_digit) {
    Some(start)
  } else {
    None
  }
}

fn skip_nondigits_back(bytes: &[u8], mut i: usize) -> usize {
  while i > 0 {
    match bytes.get(i - 1) {
      Some(b) if !b.is_ascii_digit() => i -= 1,
      _ => break,
    }
  }
  i
}

/// Wrap a NUMERIC decoder's `Option<T>` result into a [`NumericRead`] for a
/// record the walker has ALREADY dispatched (⇒ the record is PRESENT). The
/// numeric decoders (`decode_fnumber`, `decode_rational64u_typed`,
/// `decode_iso_u16`, `decode_master_gain_db`, `decode_eem_u16`) return `Some(t)`
/// when the value carries enough bytes and `None` ONLY when it is sub-width /
/// empty (`ReadValue` ⇒ `''`). Because the walker calls these solely for present
/// records (the `while $pos+4 < $end` bound excludes a FINAL bare header, the
/// only ABSENT case), a `None` here is exactly the PRESENT-but-sub-width state —
/// mapped to [`NumericRead::EmptyRead`], NOT a dropped tag. A `Some(t)` is
/// [`NumericRead::Valid`]. The result is always `Some(_)` (the record is
/// present), so the caller stores `Some(present_numeric_read(...))`.
#[inline]
fn present_numeric_read<T>(decoded: Option<T>) -> NumericRead<T> {
  match decoded {
    Some(t) => NumericRead::Valid(t),
    None => NumericRead::EmptyRead,
  }
}

// ===========================================================================
// process_rtmd — the bundled Process_rtmd port
// ===========================================================================

/// `Image::ExifTool::Sony::Process_rtmd` (Sony.pm:11566-11602) — walk one
/// rtmd metadata sample and accumulate every camera + GPS record into a
/// single [`SonyRtmdCameraSnapshot`] + (optional) [`SonyRtmdGpsSample`],
/// pushed onto `out` as one unified [`crate::metadata::SonyRtmdSample`]
/// per call.
///
/// Faithful behaviour notes:
///
/// - Sony.pm:11614 `return 0 if $end < 2`: a sample shorter than 2 bytes
///   yields no records and NO warning (bundled is silent). exifast still
///   pushes ONE empty sample so the `Doc<N>` timing row `ProcessSamples`
///   already opened (SampleTime/SampleDuration) survives.
/// - Sony.pm:11581: the 2-byte BE header length at offset 0 is honoured
///   as-is — `$pos` starts at `Get16u($dataPt, 0)`, NOT a hard-coded
///   `0x1c`. (Bundled never rewrites this; matching the file lets new
///   firmware variants parse.)
/// - Sony.pm:11582: `while ($pos + 4 < $end)` — strict-less; a trailing
///   4-byte remainder is dropped.
/// - Sony.pm:11583-11584: `last if $tag == 0` — a zero tag stops the walk.
/// - Sony.pm:11586-11591: the `0x060e` / `0x8300` special cases.
/// - Sony.pm:11592: a truncated value stops the walk.
///
/// Re-entrancy of the container path: the `0x8300` recurse is FLAT (no
/// stack); bundled simply rewrites `$pos += 4` then `next`s. Our port
/// mirrors that — a `0x8300` skips its 4-byte header and continues the
/// `while` loop. Nested containers therefore work for the same reason
/// they do in bundled: each `0x8300` site just advances `pos` by 4.
pub fn process_rtmd(data: &[u8], out: &mut SonyRtmdMeta) {
  let end = data.len();
  if end < 2 {
    // Sony.pm:11614 `return 0 if $end < 2` — bundled `Process_rtmd` is
    // SILENT on a short header (no warning, no tag). But `ProcessSamples`
    // already opened a `Doc<N>` and emitted this sample's SampleTime /
    // SampleDuration (`FoundSomething`, QuickTimeStream.pl) BEFORE the
    // dispatch, so the timing row must survive. Push ONE empty sample
    // (all-None camera, no GPS) so the dispatcher stamps the doc + timing
    // onto it and the emission surfaces a timing-only `Doc<N>` — consistent
    // with the `>= 2`-byte-but-no-records path below.
    out.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), None));
    return;
  }
  // Sony.pm:11581 `$pos = Get16u($dataPt, 0)`.
  let mut pos = match be_u16(data, 0) {
    Some(v) => v as usize,
    None => return,
  };

  // Per-sample accumulators.
  let mut snap = SonyRtmdCameraSnapshot::new();
  let mut gps = SonyRtmdGpsSample::new();
  let mut saw_gps = false;
  // Track whether the canonical 0x810b ISO has fired so we don't let the
  // alt 0xe301 overwrite it (per the fallback semantics in the typed
  // surface — bundled keeps both tags independently under their own
  // `Sony:ISO` / `Sony:Sony_rtmd_0xe301` keys; the typed `iso` slot picks
  // the canonical one when present).
  let mut canonical_iso_set = false;

  // Sony.pm:11582 `while ($pos + 4 < $end)`.
  while pos + 4 < end {
    // Sony.pm:11583 `my $tag = Get16u($dataPt, $pos)`.
    let Some(tag) = be_u16(data, pos) else { break };
    // Sony.pm:11584 `last if $tag == 0`.
    if tag == 0 {
      break;
    }
    // Sony.pm:11585 `my $len = Get16u($dataPt, $pos+2)`.
    let Some(len_raw) = be_u16(data, pos + 2) else {
      break;
    };

    // Sony.pm:11586-11591: `0x060e` / `0x8300` special-cases.
    //
    //   if ($tag == 0x060e) { $len = 0x10; }
    //   else                { $pos += 4; next if $tag == 0x8300; }
    //
    // The dispatch: for 0x060e, `$pos` is NOT advanced (the 16-byte read
    // starts at `$pos`, INCLUDING the 4-byte header). For 0x8300, we skip
    // the 4-byte header and `next` (no `$pos += $len`, so the next
    // iteration reads the FIRST child record). For every other tag we
    // skip the 4-byte header.
    let len: usize;
    let value_start: usize;
    let advance_after: bool;
    if tag == TAG_SMPTE_LABEL {
      len = 0x10;
      value_start = pos; // bundled: the 16 bytes start AT $pos
      advance_after = true;
    } else if tag == TAG_CONTAINER {
      // Skip the header and continue without consuming the body.
      pos += 4;
      continue;
    } else {
      pos += 4;
      len = len_raw as usize;
      value_start = pos;
      advance_after = true;
    }

    // Sony.pm:11592 `last if $pos + $len > $end`. After the `+= 4` shift
    // above, `$pos` == `value_start`.
    if value_start.checked_add(len).is_none_or(|e| e > end) {
      break;
    }
    // The bounds were just verified (`value_start + len <= end == data.len()`),
    // so this slice always succeeds; `get` keeps it panic-free and the `else`
    // mirrors the bundled truncation `last`.
    let Some(value) = data.get(value_start..value_start + len) else {
      break;
    };

    // Dispatch by tag (Sony.pm:10686-10850).
    match tag {
      // Camera / capture identity. The NUMERIC tags below are walker-dispatched
      // ⇒ PRESENT; a sub-width / empty value (decoder ⇒ `None`) becomes
      // `NumericRead::EmptyRead` (a DEFINED ValueConv-of-`''` rendered by the
      // emission), NOT a dropped tag — `present_numeric_read` does that mapping.
      TAG_FNUMBER => {
        snap.set_f_number(Some(present_numeric_read(decode_fnumber(value))));
      }
      TAG_FRAME_RATE => {
        snap.set_frame_rate(Some(present_numeric_read(decode_rational64u_typed(value))));
      }
      TAG_EXPOSURE_TIME => {
        snap.set_exposure_time(Some(present_numeric_read(decode_rational64u_typed(value))));
      }
      TAG_MASTER_GAIN => {
        snap.set_master_gain_db(Some(present_numeric_read(decode_master_gain_db(value))));
      }
      TAG_ISO => {
        // The CANONICAL `0x810b` ISO. A sub-width record is PRESENT-but-empty
        // (bundled emits `Sony:ISO ""`), so it sets the `EmptyRead` AND the
        // canonical marker (the emission gates `Sony:ISO` on the marker, and a
        // present-empty canonical record still surfaces the empty tag). A LATER
        // alt `0xe301` must not overwrite it — `canonical_iso_set` latches.
        snap.set_iso(Some(present_numeric_read(decode_iso_u16(value))));
        snap.set_iso_from_canonical(true);
        canonical_iso_set = true;
      }
      TAG_ISO_ALT => {
        // The alternate `0xe301` int32u channel (Sony.pm:10814, `%hidUnk`):
        // NEVER surfaced as `Sony:ISO`, only a domain fallback. A sub-width
        // `0xe301` carries no usable fallback AND no emitted tag, so leave the
        // slot untouched (no `EmptyRead` — that state only drives `Sony:ISO`
        // emission, which `0xe301` never feeds). Only a full `int32u` read,
        // when the canonical `0x810b` was absent, populates the fallback.
        if !canonical_iso_set && let Some(v) = decode_iso_u32(value) {
          snap.set_iso(Some(NumericRead::Valid(v)));
        }
      }
      TAG_ELECTRICAL_EXTENDER_MAGNIFICATION => {
        snap
          .set_electrical_extender_magnification(Some(present_numeric_read(decode_eem_u16(value))));
      }
      TAG_SERIAL_NUMBER => {
        if let Some(v) = decode_string(value) {
          snap.set_serial_number(Some(v));
        }
      }
      // White balance + DateTime. Both are walker-dispatched ⇒ PRESENT; a
      // sub-width / empty value renders the ValueConv/PrintConv-of-`''`, NOT a
      // dropped tag.
      TAG_WHITE_BALANCE => {
        // `int8u` + PrintConv hash. A sub-width (zero-length) record is
        // PRESENT-but-empty: `ReadValue` ⇒ `''`, which the hash misses (no `0`
        // key for an empty), so bundled emits `"Unknown ()"` at `-j` / `''` at
        // `-n`. Carry that as `NumericRead::EmptyRead` (the emission renders it);
        // a sufficient-width byte is `Valid`. (`present_numeric_read` maps the
        // decoder `None` ⇒ `EmptyRead`.)
        snap.set_white_balance_raw(Some(present_numeric_read(decode_u8(value))));
      }
      TAG_DATE_TIME => {
        // `Format => 'undef'` + `unpack("x1H4H2H2H2H2H2")` ValueConv. A PRESENT
        // record of ANY length (incl. zero) yields a DEFINED (possibly PARTIAL)
        // BCD string — `unpack` fills each `H`-field from whatever bytes remain
        // and renders `""` for a field with no bytes, so a 0-byte record →
        // `":: ::"`, a 4-byte → `"2024:03: ::"`, etc. `decode_date_time` never
        // returns `None`, so a dispatched record always emits its tag.
        snap.set_date_time(Some(decode_date_time(value)));
      }
      // Motion (int16s, RawConv substr($val,8) — a STRING substr, see decoder)
      TAG_PITCH_ROLL_YAW => {
        if let Some(v) = decode_int16s_substr8(value) {
          snap.set_pitch_roll_yaw(Some(v));
        }
      }
      TAG_ACCELEROMETER => {
        if let Some(v) = decode_int16s_substr8(value) {
          snap.set_accelerometer(Some(v));
        }
      }
      // GPS family
      TAG_GPS_VERSION_ID => {
        if let Some(v) = decode_gps_version_id(value) {
          gps.set_version_id(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LATITUDE_REF => {
        if let Some(v) = decode_string(value) {
          gps.set_latitude_ref(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LATITUDE => {
        // A PRESENT record always yields a DEFINED coordinate — a finite value OR
        // `GPS::ToDegrees`'s `""` for an inf/undef, a 1–7-byte, OR a (non-final)
        // ZERO-LENGTH record. `decode_gps_coordinate` never returns `None`, so the
        // tag + `saw_gps` fire whenever the walker dispatches this record (a FINAL
        // bare 4-byte header is excluded by the walker bound — GPS.pm:585).
        if let Some(v) = decode_gps_coordinate(value) {
          gps.set_latitude(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LONGITUDE_REF => {
        if let Some(v) = decode_string(value) {
          gps.set_longitude_ref(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LONGITUDE => {
        // A present record ⇒ a defined coordinate (see `TAG_GPS_LATITUDE`).
        if let Some(v) = decode_gps_coordinate(value) {
          gps.set_longitude(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_TIME_STAMP => {
        if let Some(v) = decode_gps_time_stamp(value) {
          gps.set_time_stamp(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_STATUS => {
        if let Some(v) = decode_string(value) {
          gps.set_status(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_MEASURE_MODE => {
        if let Some(v) = decode_string(value) {
          gps.set_measure_mode(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_MAP_DATUM => {
        if let Some(v) = decode_string(value) {
          gps.set_map_datum(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_DATE_STAMP => {
        if let Some(v) = decode_gps_date_stamp(value) {
          gps.set_date_stamp(Some(v));
          saw_gps = true;
        }
      }
      _ => {
        // Tags bundled marks `%hidUnk` (Sony.pm:10695-10843) AND tags
        // unrecognized by the table — bundled `HandleTag`s them under
        // their `Sony_rtmd_0xNNNN` name; exifast's typed layer does not
        // surface them (see SonyRtmdMeta module docs). Fall through.
      }
    }

    if advance_after {
      // Sony.pm:11599 `$pos += $len`.
      pos += len;
    }
  }

  // Apply the LatitudeRef / LongitudeRef signs (Sony.pm:10752-10775 — the
  // PrintConv on the *Ref tags is the display N/S/E/W; the ValueConv on
  // the coordinate is the unsigned positive number. The sign comes from
  // applying the ref under `GPS::ToDegrees($val, 1)` — but bundled
  // calls `ToDegrees($val)` here (no `$doSign`), so the bundled `Value`
  // channel is UNSIGNED.
  //
  // For the cross-format domain layer (which feeds `GpsLocation` in
  // decimal degrees), exifast applies the sign so the typed projection
  // is unambiguous. The FAITHFUL bundled-value rendering is the unsigned
  // form; the SIGNED form is exposed via the `signed_latitude` /
  // `signed_longitude` derived accessors on [`SonyRtmdGpsSample`] (which
  // are implicitly the `latitude` / `longitude` fields after we apply
  // the ref here in the walker).
  //
  // (This is a deliberate departure from bundled's per-Value rendering,
  // documented in the SonyRtmdGpsSample module docs.)
  apply_gps_ref_signs(&mut gps);

  let gps_opt = if saw_gps { Some(gps) } else { None };
  out.push_sample(SonyRtmdSample::new(snap, gps_opt));
}

/// Apply `GPSLatitudeRef='S'` / `GPSLongitudeRef='W'` as negative-sign
/// flips on the stored coordinate. Bundled `Value` keeps the unsigned
/// rational; the typed layer surfaces the signed decimal degrees so the
/// `GpsLocation` projection is unambiguous.
fn apply_gps_ref_signs(gps: &mut SonyRtmdGpsSample) {
  // Snapshot the refs BEFORE mutating; the setter takes the value by value so
  // the borrow checker would otherwise complain. The sign flip applies ONLY to
  // a finite `SonyRtmdCoord::Value` — a present-empty (`Empty`) coordinate
  // (`GPS::ToDegrees` `""`) carries no magnitude and is left untouched.
  let lat_ref = gps.latitude_ref().map(alloc::string::String::from);
  let lon_ref = gps.longitude_ref().map(alloc::string::String::from);
  if let (Some(r), Some(SonyRtmdCoord::Value(v))) = (lat_ref.as_deref(), gps.latitude()) {
    let signed = if matches_south_or_west(r, b'S') {
      -v.abs()
    } else {
      v.abs()
    };
    gps.set_latitude(Some(SonyRtmdCoord::Value(signed)));
  }
  if let (Some(r), Some(SonyRtmdCoord::Value(v))) = (lon_ref.as_deref(), gps.longitude()) {
    let signed = if matches_south_or_west(r, b'W') {
      -v.abs()
    } else {
      v.abs()
    };
    gps.set_longitude(Some(SonyRtmdCoord::Value(signed)));
  }
}

/// `true` only when `r` is EXACTLY the single-byte hemisphere sign (`b'S'` for
/// latitude, `b'W'` for longitude). The DOMAIN sign flip must agree with the
/// emission PrintConv (Sony.pm:10744-10767), which maps only the exact `N`/`S`/
/// `E`/`W` and renders any other ref `"Unknown (...)"`. A malformed ref — e.g.
/// `"Wrong"` (a former first-byte match) or `"South"` — must NOT flip the sign;
/// the coordinate is left as the unsigned magnitude rather than silently
/// projecting the wrong hemisphere into `GpsLocation`.
fn matches_south_or_west(r: &str, sign: u8) -> bool {
  r.len() == 1 && r.as_bytes().first().copied() == Some(sign)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Build a Sony rtmd byte stream: `[hdr_len:u16-BE = 0x1c][zeros to 0x1c]
  /// [records...]`.
  fn rtmd(records: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(0x1c + records.len());
    out.extend_from_slice(&0x001cu16.to_be_bytes());
    out.extend(core::iter::repeat_n(0u8, 0x1c - 2));
    out.extend_from_slice(records);
    out
  }

  /// Build one record `[tag:u16-BE][len:u16-BE][value]`.
  fn rec(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + value.len());
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
  }

  #[test]
  fn decode_string_truncates_at_first_nul_no_trim() {
    // ExifTool `ReadValue('string')` = `s/\0.*//s` (ExifTool.pm:6311): truncate
    // at the FIRST NUL, NO whitespace trim.
    // Stale bytes AFTER an embedded NUL are dropped (was `"N\0S"`).
    assert_eq!(decode_string(b"N\0S").as_deref(), Some("N"));
    // A normal NUL-padded string ⇒ its value (the trailing NULs are dropped).
    assert_eq!(decode_string(b"WGS-84\0\0\0").as_deref(), Some("WGS-84"));
    // No NUL ⇒ the whole value.
    assert_eq!(decode_string(b"2024:01:07").as_deref(), Some("2024:01:07"));
    // Internal AND trailing spaces are KEPT (no trim, unlike the old decoder).
    assert_eq!(
      decode_string(b"ILCE-7SM3 5072108").as_deref(),
      Some("ILCE-7SM3 5072108")
    );
    assert_eq!(decode_string(b"AB \0").as_deref(), Some("AB "));
    // A non-empty record that truncates to empty (leading NUL, or all-NUL) ⇒ a
    // DEFINED empty string (bundled emits the tag with `""`), NOT None.
    // Verified against bundled ExifTool 13.59.
    assert_eq!(decode_string(b"\0XYZ").as_deref(), Some(""));
    assert_eq!(decode_string(b"\0").as_deref(), Some(""));
    assert_eq!(decode_string(b"\0\0\0").as_deref(), Some(""));
    // A ZERO-LENGTH record is ALSO a DEFINED empty string: a NON-FINAL
    // zero-length `string` TLV reaches `HandleTag(Size => 0)` and `ReadValue`
    // returns `''` (was `None`). Verified vs bundled ExifTool 13.59
    // (a non-final zero-length `0x8114`/`0x8501`/… emits the tag with `""`).
    assert_eq!(decode_string(b"").as_deref(), Some(""));
  }

  #[test]
  fn decode_string_invalid_utf8_is_fixutf8_substituted_not_dropped() {
    // Invalid pre-NUL bytes must NOT drop the tag. Bundled stores the
    // raw byte string and FixUTF8's it at JSON output (`exiftool:3822`), one
    // ASCII `?` per malformed byte (`XMP.pm:2949-2972`) — the SAME engine path as
    // `read_value`'s `string` arm (an R3D `A\xff.R3D` ⇒ `A?.R3D`). The old
    // `from_utf8(...).ok()?` returned None and suppressed the tag entirely.
    assert_eq!(decode_string(b"A\xffB").as_deref(), Some("A?B"));
    // First-NUL truncation still runs BEFORE FixUTF8: post-NUL bytes drop, the
    // malformed pre-NUL byte becomes `?`.
    assert_eq!(decode_string(b"A\xffB\0junk").as_deref(), Some("A?B"));
    // A lone malformed byte is a PRESENT one-char `?`, never an absent tag.
    assert_eq!(decode_string(b"\xff").as_deref(), Some("?"));
  }

  /// Big-endian u16 helper for value bytes.
  fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
  }

  /// Big-endian u32 helper.
  fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
  }

  /// Build a rational64u value (num/denom, 8 bytes BE).
  fn rat64u(num: u32, denom: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&be32(num));
    out[4..8].copy_from_slice(&be32(denom));
    out
  }

  #[test]
  fn short_buffer_decodes_nothing_but_pushes_empty_sample() {
    let data = [0u8, 1u8]; // exactly 2 bytes — passes the `< 2` guard but
    // `pos = 0x0001` and `pos+4 < end (=2)` is false ⇒ no records.
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // A sample is still pushed (empty camera, no GPS).
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].camera().is_empty());
    assert!(out.samples()[0].gps().is_none());
  }

  #[test]
  fn short_header_under_two_bytes_pushes_empty_timing_sample() {
    // Bundled `Process_rtmd` `return 0 if $end < 2` is SILENT (no warning,
    // no tag), but `ProcessSamples` already opened the `Doc<N>` and emitted
    // the sample's SampleTime/SampleDuration. So a `< 2`-byte payload must
    // still push ONE empty sample (faithful to the `>= 2`-but-no-records
    // path), letting the dispatcher stamp a timing-only `Doc<N>`.
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&[0u8], &mut out);
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].camera().is_empty());
    assert!(out.samples()[0].gps().is_none());
  }

  #[test]
  fn empty_header_iterates_zero_records() {
    // 28-byte header, no records.
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&rtmd(&[]), &mut out);
    // One sample with an empty camera snapshot is pushed; no GPS.
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].camera().is_empty());
    assert!(out.samples()[0].gps().is_none());
  }

  #[test]
  fn fnumber_value_conv_applied() {
    // bundled raw `int16u` with ValueConv 2^(8 - val/8192). For raw
    // `4096`, `8 - 0.5 = 7.5`, `2^7.5 ≈ 181.019`. Choose a value that
    // matches a friendly f-number: raw `40960` ⇒ `8 - 5 = 3` ⇒ `2^3 = 8`
    // (an f/8 aperture).
    let mut data = rtmd(&rec(TAG_FNUMBER, &be16(40960)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert!(snap.f_number().is_some());
    assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
    // Lone-record exercises the `pos += len` advance after the dispatch.
    data.clear();
  }

  #[test]
  fn exposure_time_rational() {
    // 1/200 s — num=1, denom=200.
    let data = rtmd(&rec(TAG_EXPOSURE_TIME, &rat64u(1, 200)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert!((snap.exposure_time_s().unwrap() - 0.005).abs() < 1e-9);
  }

  #[test]
  fn iso_int16u() {
    let data = rtmd(&rec(TAG_ISO, &be16(800)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(800));
  }

  #[test]
  fn iso_alt_int32u_used_when_canonical_absent() {
    let data = rtmd(&rec(TAG_ISO_ALT, &be32(12800)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(12800));
  }

  #[test]
  fn iso_canonical_wins_over_alt() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(400)));
    records.extend_from_slice(&rec(TAG_ISO_ALT, &be32(12800)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(400));
  }

  #[test]
  fn iso_from_canonical_marker_only_for_0x810b() {
    // 0x810b ⇒ iso set AND iso_from_canonical true (emittable as Sony:ISO).
    let data = rtmd(&rec(TAG_ISO, &be16(640)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.iso(), Some(640));
    assert!(snap.iso_from_canonical());

    // 0xe301 alone ⇒ iso set (domain fallback) but NOT canonical — bundled
    // hides the 0xe301 channel from Sony:ISO.
    let data = rtmd(&rec(TAG_ISO_ALT, &be32(12800)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.iso(), Some(12800));
    assert!(!snap.iso_from_canonical());
  }

  #[test]
  fn master_gain_int16u_div_100_db() {
    // raw = 1234 ⇒ 12.34 dB.
    let data = rtmd(&rec(TAG_MASTER_GAIN, &be16(1234)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert!((snap.master_gain_db().unwrap() - 12.34).abs() < 1e-9);
  }

  #[test]
  fn frame_rate_rational() {
    // 24000/1001 ≈ 23.976.
    let data = rtmd(&rec(TAG_FRAME_RATE, &rat64u(24_000, 1001)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert!((snap.frame_rate().unwrap() - 24_000.0 / 1001.0).abs() < 1e-9);
  }

  #[test]
  fn serial_number_splits_model_and_serial() {
    let data = rtmd(&rec(TAG_SERIAL_NUMBER, b"ILCE-7SM3 5072108"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.serial_number(), Some("ILCE-7SM3 5072108"));
    assert_eq!(snap.model(), Some("ILCE-7SM3"));
    assert_eq!(snap.serial(), Some("5072108"));
  }

  #[test]
  fn serial_number_with_nul_padding_trims() {
    let data = rtmd(&rec(TAG_SERIAL_NUMBER, b"ILCE-7M4 99999999\0\0\0"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    // Trailing NULs stripped by decode_string.
    assert_eq!(snap.serial_number(), Some("ILCE-7M4 99999999"));
    assert_eq!(snap.model(), Some("ILCE-7M4"));
    assert_eq!(snap.serial(), Some("99999999"));
  }

  #[test]
  fn date_time_bcd_decodes() {
    // 8-byte BCD: skip 1, year 2024, month 03, day 05, hh 10, mm 20, ss 30.
    // BCD: 2024 = 0x20, 0x24; 03 = 0x03; 05 = 0x05; 10 = 0x10; 20 = 0x20;
    // 30 = 0x30. Byte 0 is skipped (any value).
    let payload = [0u8, 0x20, 0x24, 0x03, 0x05, 0x10, 0x20, 0x30];
    let data = rtmd(&rec(TAG_DATE_TIME, &payload));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.date_time(), Some("2024:03:05 10:20:30"));
  }

  #[test]
  fn date_time_partial_bcd_for_short_records() {
    // A PRESENT DateTime record SHORTER than 8 bytes yields
    // a DEFINED PARTIAL BCD string (Perl `unpack("x1H4H2H2H2H2H2")` fills each
    // field from whatever bytes remain, rendering `""` for an empty field) — NOT
    // a dropped tag. `decode_date_time` never returns `None`. Verified byte-exact
    // vs bundled ExifTool 13.59 for each length 0..8.
    let full = [0u8, 0x20, 0x24, 0x03, 0x05, 0x10, 0x20, 0x30];
    let cases: [(usize, &str); 9] = [
      (0, ":: ::"),               // zero-length: every field empty
      (1, ":: ::"),               // x1 pad consumes byte 0 → all empty
      (2, "20:: ::"),             // H4 reads 1 byte → "20"
      (3, "2024:: ::"),           // H4 reads 2 bytes → "2024"
      (4, "2024:03: ::"),         // + month
      (5, "2024:03:05 ::"),       // + day
      (6, "2024:03:05 10::"),     // + hour
      (7, "2024:03:05 10:20:"),   // + minute
      (8, "2024:03:05 10:20:30"), // full
    ];
    for (n, expected) in cases {
      assert_eq!(
        decode_date_time(&full[..n]).as_str(),
        expected,
        "DateTime of length {n} must render the partial BCD {expected:?}"
      );
    }
  }

  #[test]
  fn white_balance_raw_passes_through() {
    let data = rtmd(&rec(TAG_WHITE_BALANCE, &[4u8])); // Daylight
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.white_balance_raw(), Some(4));
    assert_eq!(snap.white_balance_read(), Some(NumericRead::Valid(4)));
  }

  #[test]
  fn white_balance_zero_length_is_empty_read() {
    // A PRESENT zero-length `0xe303` record is sub-width —
    // `ReadValue` ⇒ `''`, the PrintConv hash misses (no `0`/empty key) → bundled
    // emits `"Unknown ()"` at `-j` / `''` at `-n`. exifast carries that as
    // `NumericRead::EmptyRead` (a trailing valid ISO keeps it NON-FINAL). The
    // domain accessor is `None`; the `*_read` accessor is `Some(EmptyRead)`.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_WHITE_BALANCE, b"")); // zero-len → EmptyRead
    records.extend_from_slice(&rec(TAG_ISO, &be16(800))); // final keeper (non-final WB)
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.white_balance_read(), Some(NumericRead::EmptyRead));
    assert_eq!(
      snap.white_balance_raw(),
      None,
      "an EmptyRead WhiteBalance is hidden from the Valid-only accessor"
    );
    // The walker stepped past the zero-length WB record (ISO proves it).
    assert_eq!(snap.iso(), Some(800));
  }

  #[test]
  fn white_balance_valid_byte_is_valid_read() {
    // The contrapositive: a 1-byte `0xe303` decodes to `Valid` (the domain
    // accessor surfaces it), pinning `EmptyRead` to the zero-length case only.
    let data = rtmd(&rec(TAG_WHITE_BALANCE, &[6u8])); // Custom
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.white_balance_read(), Some(NumericRead::Valid(6)));
    assert_eq!(snap.white_balance_raw(), Some(6));
  }

  #[test]
  fn electrical_extender_magnification_int16u() {
    // 0x810c: int16u, no conv.
    let data = rtmd(&rec(TAG_ELECTRICAL_EXTENDER_MAGNIFICATION, &be16(200)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(
      out.samples()[0]
        .camera()
        .electrical_extender_magnification(),
      Some(200)
    );
  }

  #[test]
  fn pitch_roll_yaw_int16s_substr8_string_semantics() {
    // RawConv `substr($val, 8)` is a STRING substr on the WHOLE-record
    // int16s rendering, NOT an 8-byte skip. Header bytes
    // `aabbccdd 11223344` + payload int16s 100,-200,300 → the 7-element
    // rendering `"-21829 -13091 4386 13124 100 -200 300"`, whose first 8
    // CHARS dropped = `"13091 4386 13124 100 -200 300"` (verified vs bundled).
    let mut val = Vec::new();
    val.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
    val.extend_from_slice(&100i16.to_be_bytes());
    val.extend_from_slice(&(-200i16).to_be_bytes());
    val.extend_from_slice(&300i16.to_be_bytes());
    let data = rtmd(&rec(TAG_PITCH_ROLL_YAW, &val));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(
      out.samples()[0].camera().pitch_roll_yaw(),
      Some("13091 4386 13124 100 -200 300")
    );
  }

  #[test]
  fn accelerometer_int16s_substr8_string_semantics() {
    // Same RawConv shape as PitchRollYaw. Header + int16s -50,16384,-1 →
    // rendering `"-21829 -13091 4386 13124 -50 16384 -1"`, substr(8) =
    // `"13091 4386 13124 -50 16384 -1"` (verified vs bundled 13.59).
    let mut val = Vec::new();
    val.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
    val.extend_from_slice(&(-50i16).to_be_bytes());
    val.extend_from_slice(&16384i16.to_be_bytes());
    val.extend_from_slice(&(-1i16).to_be_bytes());
    let data = rtmd(&rec(TAG_ACCELEROMETER, &val));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(
      out.samples()[0].camera().accelerometer(),
      Some("13091 4386 13124 -50 16384 -1")
    );
  }

  #[test]
  fn int16s_substr8_short_rendering_drops_tag() {
    // A value rendering shorter than 8 chars ⇒ Perl `substr outside of
    // string` ⇒ undef ⇒ dropped tag. 4 int16s `1,2,3,4` → `"1 2 3 4"`
    // (7 chars < 8) ⇒ None.
    let mut val = Vec::new();
    for n in [1i16, 2, 3, 4] {
      val.extend_from_slice(&n.to_be_bytes());
    }
    let data = rtmd(&rec(TAG_PITCH_ROLL_YAW, &val));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert!(out.samples()[0].camera().pitch_roll_yaw().is_none());
  }

  #[test]
  fn int16s_substr8_exactly_eight_chars_emits_empty() {
    // A rendering exactly 8 chars long ⇒ Perl `substr(_, 8)` = `""` (NOT
    // undef, no warning) ⇒ ExifTool emits an empty value (verified vs
    // bundled). int16s 10,20,30 → `"10 20 30"` (8 chars) ⇒ Some("").
    let mut val = Vec::new();
    for n in [10i16, 20, 30] {
      val.extend_from_slice(&n.to_be_bytes());
    }
    let data = rtmd(&rec(TAG_PITCH_ROLL_YAW, &val));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().pitch_roll_yaw(), Some(""));
  }

  #[test]
  fn gps_time_stamp_rounds_rational64_before_convert() {
    // Each H/M/S `rational64u` is `GetRational64u`-rounded
    // (`%.10g`) BEFORE ConvertTimeStamp. Seconds = 1496725904/123456789 =
    // 12.1234799327… rounds to 12.12347993; H=12, M=0 → `"12:00:12.12347993"`
    // (the bundled `-ee -n` value — NOT the 11-digit raw quotient).
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(12, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(1_496_725_904, 123_456_789));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.time_stamp(), Some("12:00:12.12347993"));
  }

  #[test]
  fn gps_time_stamp_non_finite_emits_constant_inf_nan_string() {
    // A component with a ZERO denominator + non-zero numerator (423/0) renders
    // the WORD `"inf"` (= `f64::INFINITY`). `GPS::ConvertTimeStamp` has NO
    // inf/undef guard, so its arithmetic + string interpolation yield the
    // CONSTANT bogus string `"Inf:NaN:000000000NaN"` for an inf in ANY of the
    // H/M/S positions (verified byte-exact vs bundled ExifTool 13.59 for each
    // position, both `-j`/`-n`). The fix EMITS that constant verbatim (the
    // defined-but-bogus value bundled emits), NOT `None`.
    const BOGUS: &str = "Inf:NaN:000000000NaN";
    // S = 423/0 → "inf".
    let mut s_inf = Vec::new();
    s_inf.extend_from_slice(&rat64u(12, 1));
    s_inf.extend_from_slice(&rat64u(0, 1));
    s_inf.extend_from_slice(&rat64u(423, 0));
    assert_eq!(decode_gps_time_stamp(&s_inf).as_deref(), Some(BOGUS));
    // M = 423/0 → "inf".
    let mut m_inf = Vec::new();
    m_inf.extend_from_slice(&rat64u(12, 1));
    m_inf.extend_from_slice(&rat64u(423, 0));
    m_inf.extend_from_slice(&rat64u(15, 1));
    assert_eq!(decode_gps_time_stamp(&m_inf).as_deref(), Some(BOGUS));
    // H = 423/0 → "inf".
    let mut h_inf = Vec::new();
    h_inf.extend_from_slice(&rat64u(423, 0));
    h_inf.extend_from_slice(&rat64u(0, 1));
    h_inf.extend_from_slice(&rat64u(15, 1));
    assert_eq!(decode_gps_time_stamp(&h_inf).as_deref(), Some(BOGUS));
  }

  #[test]
  fn gps_time_stamp_all_finite_decodes() {
    // The all-finite counterpart of the n/0 case: H=12, M=0, S=42 → the
    // `ConvertTimeStamp` string "12:00:42" (no fractional part). Pins that the
    // drop is SPECIFIC to a non-finite component, not the whole decoder.
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(12, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(42, 1));
    assert_eq!(
      decode_gps_time_stamp(&ts).as_deref(),
      Some("12:00:42"),
      "an all-finite H/M/S decodes normally"
    );
  }

  #[test]
  fn gps_time_stamp_zero_over_zero_undef_numifies_to_zero() {
    // A `0/0` `undef` component is NOT non-finite — `"undef"` fails to parse as
    // f64 and `rounded_rational64u` falls back to `0.0` (matching ExifTool's
    // `($x||0)` numification of a non-numeric scalar). So a `0/0` seconds is
    // treated as 0 and the timestamp is NOT dropped: H=12, M=0, S=0/0 → 0 →
    // "12:00:00". (Contrast the n/0 `inf` case above, which IS dropped.)
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(12, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(0, 0)); // S = 0/0 → "undef" → 0.0
    assert_eq!(
      decode_gps_time_stamp(&ts).as_deref(),
      Some("12:00:00"),
      "a 0/0 undef component numifies to 0 ($x||0) and is NOT dropped"
    );
  }

  #[test]
  fn gps_full_record_decodes_with_signs_applied() {
    // Build a complete GPS record: VersionID + LatRef='S' + Lat 37 30' 0''
    // + LonRef='W' + Lon 122 0' 30'' + TimeStamp 10:20:30 + Status 'A' +
    // MeasureMode '3' + MapDatum 'WGS-84' + DateStamp '2024 03 05'.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_VERSION_ID, &[2u8, 2, 0, 0]));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"S"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(37, 1));
    lat.extend_from_slice(&rat64u(30, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE_REF, b"W"));
    let mut lon = Vec::new();
    lon.extend_from_slice(&rat64u(122, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    lon.extend_from_slice(&rat64u(30, 1));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE, &lon));
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(30, 1));
    records.extend_from_slice(&rec(TAG_GPS_TIME_STAMP, &ts));
    records.extend_from_slice(&rec(TAG_GPS_STATUS, b"A"));
    records.extend_from_slice(&rec(TAG_GPS_MEASURE_MODE, b"3"));
    records.extend_from_slice(&rec(TAG_GPS_MAP_DATUM, b"WGS-84"));
    records.extend_from_slice(&rec(TAG_GPS_DATE_STAMP, b"2024:03:05"));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].gps().is_some(), "one GPS sample");
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.version_id(), Some("2.2.0.0"));
    assert_eq!(g.latitude_ref(), Some("S"));
    let lat = g
      .latitude()
      .and_then(SonyRtmdCoord::value)
      .expect("finite lat");
    assert!((lat + 37.5).abs() < 1e-9); // South ⇒ negative
    assert_eq!(g.longitude_ref(), Some("W"));
    let lon = g
      .longitude()
      .and_then(SonyRtmdCoord::value)
      .expect("finite lon");
    assert!((lon + 122.00833333333333).abs() < 1e-9);
    assert_eq!(g.time_stamp(), Some("10:20:30"));
    assert_eq!(g.status(), Some("A"));
    assert_eq!(g.measure_mode(), Some("3"));
    assert_eq!(g.map_datum(), Some("WGS-84"));
    assert_eq!(g.date_stamp(), Some("2024:03:05"));
    assert!(g.has_coordinates());
  }

  #[test]
  fn gps_coordinate_partial_one_and_two_components() {
    // `Format => 'rational64u'` with NO Count: a 1-component (8-byte) or
    // 2-component (16-byte) record is valid; a missing minute/second defaults
    // to 0 (`GPS::ToDegrees` `($min||0)`/`($sec||0)`). Verified vs bundled 13.59.
    // 1-component "12/1" → 12.0.
    assert_eq!(
      decode_gps_coordinate(&rat64u(12, 1)),
      Some(SonyRtmdCoord::Value(12.0))
    );
    // 2-component "122/1 30/1" → 122 + 30/60 = 122.5.
    let mut two = Vec::new();
    two.extend_from_slice(&rat64u(122, 1));
    two.extend_from_slice(&rat64u(30, 1));
    assert_eq!(
      decode_gps_coordinate(&two),
      Some(SonyRtmdCoord::Value(122.5))
    );
    // 3-component "47/1 37/1 423/10" → 47 + 37/60 + 42.3/3600 (the full form).
    let mut three = Vec::new();
    three.extend_from_slice(&rat64u(47, 1));
    three.extend_from_slice(&rat64u(37, 1));
    three.extend_from_slice(&rat64u(423, 10));
    let v = decode_gps_coordinate(&three)
      .and_then(SonyRtmdCoord::value)
      .expect("3-component finite");
    assert!((v - (47.0 + 37.0 / 60.0 + 42.3 / 3600.0)).abs() < 1e-9);
  }

  #[test]
  fn gps_coordinate_present_empty_for_inf_undef_and_short() {
    // `GPS::ToDegrees` (GPS.pm:585) returns `""` (a DEFINED value) for ANY
    // inf/undef component, OR a record too short to carry the degrees component.
    // `decode_gps_coordinate` mirrors that with `SonyRtmdCoord::Empty` — NEVER
    // `None` for a present record. Verified vs bundled ExifTool 13.59 (inf/undef
    // in EACH of D/M/S, and a sub-component record, all render `""`).
    // inf (n/0) in the D / M / S positions.
    let inf_d = {
      let mut v = Vec::new();
      v.extend_from_slice(&rat64u(423, 0)); // D = inf
      v.extend_from_slice(&rat64u(37, 1));
      v.extend_from_slice(&rat64u(15, 1));
      v
    };
    assert_eq!(decode_gps_coordinate(&inf_d), Some(SonyRtmdCoord::Empty));
    let inf_m = {
      let mut v = Vec::new();
      v.extend_from_slice(&rat64u(47, 1));
      v.extend_from_slice(&rat64u(423, 0)); // M = inf
      v.extend_from_slice(&rat64u(15, 1));
      v
    };
    assert_eq!(decode_gps_coordinate(&inf_m), Some(SonyRtmdCoord::Empty));
    let inf_s = {
      let mut v = Vec::new();
      v.extend_from_slice(&rat64u(47, 1));
      v.extend_from_slice(&rat64u(37, 1));
      v.extend_from_slice(&rat64u(423, 0)); // S = inf
      v
    };
    assert_eq!(decode_gps_coordinate(&inf_s), Some(SonyRtmdCoord::Empty));
    // undef (0/0) in the D / M / S positions — `"undef"` also triggers the
    // ToDegrees `\b(inf|undef)\b` guard ⇒ `""` (distinct from the TIMESTAMP,
    // where a 0/0 undef numifies to 0).
    let undef_d = {
      let mut v = Vec::new();
      v.extend_from_slice(&rat64u(0, 0)); // D = undef
      v.extend_from_slice(&rat64u(37, 1));
      v.extend_from_slice(&rat64u(15, 1));
      v
    };
    assert_eq!(decode_gps_coordinate(&undef_d), Some(SonyRtmdCoord::Empty));
    let undef_s = {
      let mut v = Vec::new();
      v.extend_from_slice(&rat64u(47, 1));
      v.extend_from_slice(&rat64u(37, 1));
      v.extend_from_slice(&rat64u(0, 0)); // S = undef
      v
    };
    assert_eq!(decode_gps_coordinate(&undef_s), Some(SonyRtmdCoord::Empty));
    // A 1–7-byte record (present, too short for even one component) ⇒
    // Some(Empty) (NOT None — only a 0-byte record is absent).
    assert_eq!(decode_gps_coordinate(&[0u8; 7]), Some(SonyRtmdCoord::Empty));
    assert_eq!(decode_gps_coordinate(&[0u8; 4]), Some(SonyRtmdCoord::Empty));
    // A 1-component inf ⇒ Empty.
    assert_eq!(
      decode_gps_coordinate(&rat64u(423, 0)),
      Some(SonyRtmdCoord::Empty)
    );
    // A ZERO-LENGTH record is ALSO present-empty: a NON-FINAL zero-length
    // `0x8502` reaches `HandleTag(Size => 0)`, `ReadValue` returns `''`, and
    // `GPS::ToDegrees('')` extracts no `$d` ⇒ `""` (was `None`).
    // Verified vs bundled ExifTool 13.59 (emits `GPSLatitude ""`).
    assert_eq!(decode_gps_coordinate(&[]), Some(SonyRtmdCoord::Empty));
  }

  #[test]
  fn gps_present_empty_coordinate_emits_tag_and_sets_saw_gps() {
    // A present 0x8502 with an inf component ⇒ the GPS sample exists, the
    // latitude is `Some(Empty)` (a defined present-empty value, NOT absent), and
    // `has_coordinates` is false (the Empty value is not a fix).
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"N"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(47, 1));
    lat.extend_from_slice(&rat64u(37, 1));
    lat.extend_from_slice(&rat64u(423, 0)); // S = inf ⇒ Empty
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0]
      .gps()
      .expect("a present-empty coordinate still creates the GPS sample");
    assert_eq!(
      g.latitude(),
      Some(SonyRtmdCoord::Empty),
      "present-empty latitude is Some(Empty), not None"
    );
    assert!(!g.has_coordinates(), "an Empty coordinate is not a fix");
  }

  #[test]
  fn gps_time_stamp_partial_one_and_two_components() {
    // 1-component "12/1" → 12:00:00 (missing M/S default to 0). Vs bundled 13.59.
    assert_eq!(
      decode_gps_time_stamp(&rat64u(12, 1)).as_deref(),
      Some("12:00:00")
    );
    // 2-component "10/1 20/1" → 10:20:00.
    let mut two = Vec::new();
    two.extend_from_slice(&rat64u(10, 1));
    two.extend_from_slice(&rat64u(20, 1));
    assert_eq!(decode_gps_time_stamp(&two).as_deref(), Some("10:20:00"));
    // A record TOO SHORT for even one component (no hours) is PRESENT and
    // renders `00:00:00` — `ConvertTimeStamp` `($x||0)` defaults every absent
    // component to 0 (verified vs bundled 13.59: a 4-byte GPSTimeStamp →
    // `00:00:00`, NOT a dropped tag).
    assert_eq!(
      decode_gps_time_stamp(&[0u8; 7]).as_deref(),
      Some("00:00:00")
    );
    assert_eq!(
      decode_gps_time_stamp(&[0u8; 4]).as_deref(),
      Some("00:00:00")
    );
    // A ZERO-LENGTH record is ALSO present: a NON-FINAL zero-length `0x8507`
    // reaches `HandleTag(Size => 0)`, `ReadValue` returns `''`, and
    // `ConvertTimeStamp('')` defaults every `($x||0)` to 0 ⇒ `"00:00:00"` (was
    // `None`). Verified vs bundled ExifTool 13.59.
    assert_eq!(decode_gps_time_stamp(b"").as_deref(), Some("00:00:00"));
  }

  #[test]
  fn gps_empty_string_ref_present_and_sets_saw_gps() {
    // A leading-NUL GPSLatitudeRef (len >= 1) is a DEFINED EMPTY value: the tag
    // is present-but-empty AND `saw_gps` fires so the GPS sample is created.
    // (The empty ref applies no hemisphere sign — the coordinate stays positive,
    // matching bundled's out-of-table ref handling.) Verified vs bundled 13.59.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"\x00"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(37, 1));
    lat.extend_from_slice(&rat64u(30, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0]
      .gps()
      .expect("an empty ref still creates the GPS sample");
    assert_eq!(
      g.latitude_ref(),
      Some(""),
      "empty ref is present, not dropped"
    );
    let lat = g
      .latitude()
      .and_then(SonyRtmdCoord::value)
      .expect("finite lat");
    assert!((lat - 37.5).abs() < 1e-9, "empty ref ⇒ no sign flip");
  }

  #[test]
  fn gps_north_east_keep_positive() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"N"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(10, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE_REF, b"E"));
    let mut lon = Vec::new();
    lon.extend_from_slice(&rat64u(20, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE, &lon));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0].gps().expect("gps sample present");
    let lat = g
      .latitude()
      .and_then(SonyRtmdCoord::value)
      .expect("finite lat");
    let lon = g
      .longitude()
      .and_then(SonyRtmdCoord::value)
      .expect("finite lon");
    assert!((lat - 10.0).abs() < 1e-9);
    assert!((lon - 20.0).abs() < 1e-9);
  }

  #[test]
  fn gps_malformed_ref_applies_no_hemisphere_sign() {
    // A malformed ref (NOT exactly `N`/`S`/`E`/`W`) must
    // NOT flip the DOMAIN sign — the emission PrintConv renders any other ref
    // `"Unknown (...)"`, so the stored coordinate must agree and stay the
    // unsigned magnitude rather than silently projecting the wrong hemisphere.
    // A former FIRST-BYTE match wrongly treated `"South"`/`"Wrong"` (and the
    // lowercase `"s"`/`"w"`, which bundled also maps to `Unknown`) as negative.
    for (lat_ref, lon_ref) in [(&b"South"[..], &b"Wrong"[..]), (&b"s"[..], &b"w"[..])] {
      let mut records = Vec::new();
      records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, lat_ref));
      let mut lat = Vec::new();
      lat.extend_from_slice(&rat64u(10, 1));
      lat.extend_from_slice(&rat64u(0, 1));
      lat.extend_from_slice(&rat64u(0, 1));
      records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
      records.extend_from_slice(&rec(TAG_GPS_LONGITUDE_REF, lon_ref));
      let mut lon = Vec::new();
      lon.extend_from_slice(&rat64u(20, 1));
      lon.extend_from_slice(&rat64u(0, 1));
      lon.extend_from_slice(&rat64u(0, 1));
      records.extend_from_slice(&rec(TAG_GPS_LONGITUDE, &lon));
      let data = rtmd(&records);
      let mut out = SonyRtmdMeta::new();
      process_rtmd(&data, &mut out);
      let g = out.samples()[0].gps().expect("gps sample present");
      let lat_v = g
        .latitude()
        .and_then(SonyRtmdCoord::value)
        .expect("finite lat");
      let lon_v = g
        .longitude()
        .and_then(SonyRtmdCoord::value)
        .expect("finite lon");
      assert!(
        (lat_v - 10.0).abs() < 1e-9,
        "malformed lat ref {lat_ref:?} ⇒ no sign flip"
      );
      assert!(
        (lon_v - 20.0).abs() < 1e-9,
        "malformed lon ref {lon_ref:?} ⇒ no sign flip"
      );
    }
  }

  #[test]
  fn gps_date_stamp_rewrites_non_colon_separators() {
    // Bundled ExifDate accepts non-colon separators in the date — `2024
    // 03 05` ⇒ `2024:03:05`.
    let data = rtmd(&rec(TAG_GPS_DATE_STAMP, b"2024 03 05\0"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.date_stamp(), Some("2024:03:05"));
  }

  #[test]
  fn gps_time_stamp_fractional_seconds_trim_trailing_zeros() {
    // 10:20:30.50 — encoded as h=10/1, m=20/1, s=305/10. ConvertTimeStamp
    // builds `sprintf("%012.9f", 30.5) = "30.500000000"` (12 chars, no
    // leading zero needed because the integer part is 2 digits and the
    // total already meets the minimum width). The substitution
    // `\.?0+$` matches `.500000000`?? No — `0+` is anchored at `$` and
    // matches a run of `0`s. After the trailing 8 zeros come a `5`,
    // not a `0`. So the regex matches just the 8 trailing zeros (the
    // `\.?` matches NOTHING because the preceding char is `5`). Result:
    // `30.5`, joined `10:20:30.5`.
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(305, 10));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.time_stamp(), Some("10:20:30.5"));
  }

  #[test]
  fn zero_tag_stops_walk() {
    // Two records: first valid ISO, second a synthetic zero-tag pad that
    // must stop the walk before any subsequent record fires.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(100)));
    records.extend_from_slice(&[0u8, 0, 0, 4]); // tag=0, len=4
    records.extend_from_slice(&[0u8; 4]); // pad
    records.extend_from_slice(&rec(TAG_FNUMBER, &be16(40960))); // would set f/8 if reached
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.iso(), Some(100));
    assert!(snap.f_number().is_none(), "zero-tag must stop the walk");
  }

  #[test]
  fn truncated_value_stops_walk() {
    // ISO record claims 16 bytes but only 2 are provided.
    let mut records = Vec::new();
    records.extend_from_slice(&[0x81, 0x0b, 0x00, 0x10]); // ISO tag, len=16
    records.extend_from_slice(&[0u8; 2]); // only 2 bytes — truncated
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // The truncated value stops the walk; no fields set.
    assert!(out.samples()[0].camera().is_empty());
  }

  #[test]
  fn smpte_label_0x060e_skipped_then_walk_continues() {
    // The fixture: 0x060e fake-tag at the start (16 bytes from $pos),
    // followed by a regular ISO record. After 0x060e bundled does NOT
    // advance past the 4-byte header before reading 16 bytes — so the
    // 16-byte block CONSUMES the tag+len AND 12 payload bytes. The next
    // record begins exactly 16 bytes later.
    let mut records = Vec::new();
    // 16 bytes starting `06 0e 2b 34 02 53 ...` — bundled's SMPTE label.
    let mut label = Vec::with_capacity(16);
    label.extend_from_slice(&[0x06, 0x0e]); // tag bytes
    label.extend_from_slice(&[0x00, 0x00]); // dummy len (ignored)
    label.extend_from_slice(&[
      0x2b, 0x34, 0x02, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    records.extend_from_slice(&label);
    records.extend_from_slice(&rec(TAG_ISO, &be16(640)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(640));
  }

  #[test]
  fn container_0x8300_recurses_inline() {
    // 0x8300 container: bundled skips the 4-byte header and continues
    // (no len skip) — so the NEXT record is the first child.
    let mut records = Vec::new();
    // Container header — len value is IGNORED (bundled `next`s without
    // reading the body length).
    records.extend_from_slice(&[0x83, 0x00, 0x00, 0x00]); // tag=0x8300, len=0
    // Child record: ISO 1600.
    records.extend_from_slice(&rec(TAG_ISO, &be16(1600)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(1600));
  }

  #[test]
  fn multiple_records_one_sample_produces_one_snapshot() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_SERIAL_NUMBER, b"ILCE-7SM3 5072108"));
    records.extend_from_slice(&rec(TAG_FNUMBER, &be16(40960))); // f/8
    records.extend_from_slice(&rec(TAG_EXPOSURE_TIME, &rat64u(1, 100)));
    records.extend_from_slice(&rec(TAG_ISO, &be16(200)));
    records.extend_from_slice(&rec(TAG_FRAME_RATE, &rat64u(24_000, 1001)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples().len(), 1);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.model(), Some("ILCE-7SM3"));
    assert_eq!(snap.serial(), Some("5072108"));
    assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
    assert!((snap.exposure_time_s().unwrap() - 0.01).abs() < 1e-9);
    assert_eq!(snap.iso(), Some(200));
    assert!((snap.frame_rate().unwrap() - 24_000.0 / 1001.0).abs() < 1e-9);
  }

  #[test]
  fn exif_date_already_colon_separated_passes_through() {
    assert_eq!(exif_date("2024:03:05"), "2024:03:05");
  }

  #[test]
  fn exif_date_strips_trailing_nul() {
    assert_eq!(exif_date("2024:03:05\0"), "2024:03:05");
  }

  #[test]
  fn exif_date_rewrites_space_separated() {
    assert_eq!(exif_date("2024 03 05"), "2024:03:05");
  }

  #[test]
  fn exif_date_rewrites_slash_separated() {
    assert_eq!(exif_date("2024/03/05"), "2024:03:05");
  }

  #[test]
  fn gps_time_stamp_minute_carry() {
    // ConvertTimeStamp: ss >= 60 ⇒ ss reset to "00", ++mm. Build h=10/1,
    // m=20/1, s=60/1 → secs = 36060, h=10, m=21, ss="00".
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(60, 1));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // Note: f = (10*60 + 20)*60 + 60 = 36660; h=10, m=21, ss=0.
    // sprintf 0.0 ⇒ "000.000000000" ⇒ trim → "" ⇒ but our pre-test ss_num
    // = 0.0, which is NOT >= 60, so we take the else branch:
    // trimmed "000.000000000" → strip 0+ → "" → strip . → "".
    // Result: "10:20:" — undesirable. Test the OTHER branch: f=3660 ⇒
    // h=1, m=1, ss_str = "000.000000000" → "" again. Need a fractional
    // that rounds up under sprintf.
    //
    // Use h=10/1 m=20/1 s=59999/1000 ⇒ s = 59.999, sprintf gives
    // "059.999000000" → trim trailing zeros → "059.999". Not a carry test
    // either; need s that rounds to 60.0 under %012.9f. %.9f is fixed-
    // point precision; 59.9999999995 ⇒ "059.999999999" (no rounding to
    // 60). 60.0 ⇒ "060.000000000" → trims to "060". That's >= 60 ⇒ minute
    // carries. Use s=60.
    let _ = data;
    // Replace the expectation with the actual h=10, m=21 minute-carry.
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.time_stamp(), Some("10:21:00"));
  }

  #[test]
  fn gps_time_stamp_zero_components() {
    // h=0 m=0 s=0 ⇒ ConvertTimeStamp produces "00:00:00".
    //
    // `sprintf("%012.9f", 0.0)` = "00.000000000" (12 chars: 2-digit int
    // part already pads to 12 — Perl's `%012.f` is a MINIMUM width).
    // The substitution `\.?0+$` finds the leftmost match: starting at the
    // `.` (pos 2), `\.?` consumes `.`, `0+` consumes the 9 trailing
    // zeros to end-of-string. Substitution removes `.000000000`. Result:
    // "00". Joined: "00:00:00".
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = out.samples()[0].gps().expect("gps sample present");
    assert_eq!(g.time_stamp(), Some("00:00:00"));
  }

  #[test]
  fn gps_version_id_dotted() {
    let data = rtmd(&rec(TAG_GPS_VERSION_ID, &[2, 2, 0, 0]));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(
      out.samples()[0].gps().expect("gps present").version_id(),
      Some("2.2.0.0")
    );
  }

  #[test]
  fn gps_version_id_decoder_empty_is_present() {
    // A NON-FINAL zero-length `0x8500` is a present, DEFINED tag: `ReadValue`
    // returns `''`, the `tr/ /./` PrintConv leaves it `''` (was
    // `None`). Verified vs bundled ExifTool 13.59 (emits `GPSVersionID ""`).
    assert_eq!(decode_gps_version_id(b"").as_deref(), Some(""));
    // A single byte still renders its one component (no dot).
    assert_eq!(decode_gps_version_id(&[2u8]).as_deref(), Some("2"));
  }

  #[test]
  fn nonfinal_zero_length_records_emit_defined_values() {
    // A NON-FINAL zero-length TLV is walker-processed
    // (`while pos+4 < end` still reaches `HandleTag(Size => 0)`), and `ReadValue`
    // returns `''` → a DEFINED value. A trailing valid ISO keeps each zero-length
    // record NON-FINAL. Verified vs bundled ExifTool 13.59:
    //   SerialNumber(0x8114) → ""        GPSLatitudeRef(0x8501) → ""
    //   GPSTimeStamp(0x8507) → 00:00:00  GPSLatitude(0x8502)    → Empty ("")
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_VERSION_ID, &[2u8, 2, 0, 0])); // makes GPS group
    records.extend_from_slice(&rec(TAG_SERIAL_NUMBER, b"")); // zero-len SN
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"")); // zero-len ref
    records.extend_from_slice(&rec(TAG_GPS_TIME_STAMP, b"")); // zero-len timestamp
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, b"")); // zero-len coordinate
    records.extend_from_slice(&rec(TAG_ISO, &be16(800))); // final valid record
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    // The walker continued past every zero-length record (ISO is the proof).
    assert_eq!(snap.iso(), Some(800));
    // SerialNumber is PRESENT-but-empty (a defined `""`, not absent).
    assert_eq!(snap.serial_number(), Some(""));
    let g = out.samples()[0].gps().expect("GPS group present");
    assert_eq!(g.latitude_ref(), Some(""), "zero-len ref → present-empty");
    assert_eq!(
      g.time_stamp(),
      Some("00:00:00"),
      "zero-len timestamp → 00:00:00"
    );
    assert_eq!(
      g.latitude(),
      Some(SonyRtmdCoord::Empty),
      "zero-len coordinate → present-empty"
    );
    assert!(
      !g.has_coordinates(),
      "the present-empty coordinate is not a fix"
    );

    // Domain isolation: these defined-empty / 00:00:00 values must NOT populate
    // `md.gps()` (no finite coordinate pair; 00:00:00 is a valid time but there
    // is no fix to attach it to).
    let mut md = crate::metadata::MediaMetadata::new();
    out.project_into(&mut md);
    assert!(
      md.gps().is_none(),
      "present-empty coordinate + 00:00:00 timestamp must not populate the domain GPS"
    );
  }

  #[test]
  fn final_bare_four_byte_header_is_not_processed() {
    // A FINAL bare 4-byte record header (a 0-length record
    // at `pos+4 == end`) is NOT processed — the `while pos+4 < end` bound exits
    // BEFORE `HandleTag`. So a trailing zero-length SerialNumber header (with no
    // body, at the very end) is ABSENT. Verified vs bundled ExifTool 13.59 (ISO
    // emits; the trailing SerialNumber header does NOT). Contrast the NON-FINAL
    // case above where a following record makes the zero-length record present.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(555))); // valid
    records.extend_from_slice(&TAG_SERIAL_NUMBER.to_be_bytes()); // SN tag …
    records.extend_from_slice(&0u16.to_be_bytes()); // … len=0, NO body → final bare 4 bytes
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.iso(), Some(555));
    assert!(
      snap.serial_number().is_none(),
      "a FINAL bare 4-byte header must NOT be processed (walker bound exits)"
    );
  }

  #[test]
  fn unknown_tag_skipped_walk_continues() {
    // An unrecognized tag — bundled `HandleTag`s it under a `Sony_rtmd_*`
    // name; exifast's typed layer ignores it but the walk must continue
    // and pick up the next valid record.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(0xabcd, &[0u8, 0u8, 0u8, 0u8]));
    records.extend_from_slice(&rec(TAG_ISO, &be16(3200)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.samples()[0].camera().iso(), Some(3200));
  }

  #[test]
  fn present_numeric_read_maps_some_to_valid_none_to_empty_read() {
    // The walker-side wrapper: a decoder `Some(t)` → `Valid(t)` (sufficient
    // width), a decoder `None` → `EmptyRead` (the record was dispatched ⇒
    // PRESENT, so `None` is sub-width/empty, NOT absent).
    assert_eq!(present_numeric_read(Some(4.0_f64)), NumericRead::Valid(4.0));
    assert_eq!(present_numeric_read::<f64>(None), NumericRead::EmptyRead);
  }

  #[test]
  fn sub_width_numeric_records_yield_empty_read_not_none() {
    // A NON-FINAL sub-width numeric record is PRESENT —
    // the walker (`while pos+4 < end`) dispatches its decode, `ReadValue` returns
    // `''`, and exifast stores `Some(EmptyRead)` (a DEFINED value), NOT `None`
    // (absent). A trailing valid record (SerialNumber) keeps each one NON-FINAL.
    // int16u tags need a < 2-byte value; rational64u tags a < 8-byte value.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_FNUMBER, &[0x05])); // 1-byte → sub-width
    records.extend_from_slice(&rec(TAG_ISO, &[0x05])); // 1-byte → sub-width
    records.extend_from_slice(&rec(TAG_FRAME_RATE, &[0x05, 0x06, 0x07, 0x08])); // 4-byte → sub-width
    records.extend_from_slice(&rec(TAG_EXPOSURE_TIME, &[0x05, 0x06])); // 2-byte → sub-width
    records.extend_from_slice(&rec(TAG_MASTER_GAIN, &[0x05])); // 1-byte → sub-width
    records.extend_from_slice(&rec(TAG_ELECTRICAL_EXTENDER_MAGNIFICATION, &[0x05])); // 1-byte
    records.extend_from_slice(&rec(TAG_SERIAL_NUMBER, b"KEEP")); // final keeper
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    // Every numeric is PRESENT-but-empty (EmptyRead), so the full `*_read`
    // accessor is `Some(EmptyRead)` while the domain accessor is `None`.
    assert_eq!(snap.f_number_read(), Some(NumericRead::EmptyRead));
    assert_eq!(snap.f_number(), None);
    assert_eq!(snap.iso_read(), Some(NumericRead::EmptyRead));
    assert_eq!(snap.iso(), None);
    assert!(
      snap.iso_from_canonical(),
      "a sub-width canonical 0x810b still sets the marker (emits Sony:ISO \"\")"
    );
    assert_eq!(snap.frame_rate_read(), Some(NumericRead::EmptyRead));
    assert_eq!(snap.frame_rate_rational(), None);
    assert_eq!(snap.exposure_time_read(), Some(NumericRead::EmptyRead));
    assert_eq!(snap.exposure_time_rational(), None);
    assert_eq!(snap.master_gain_db_read(), Some(NumericRead::EmptyRead));
    assert_eq!(snap.master_gain_db(), None);
    assert_eq!(
      snap.electrical_extender_magnification_read(),
      Some(NumericRead::EmptyRead)
    );
    assert_eq!(snap.electrical_extender_magnification(), None);
    // The walker stepped past every sub-width record (the keeper proves it).
    assert_eq!(snap.serial_number(), Some("KEEP"));
  }

  #[test]
  fn valid_numeric_records_yield_valid_not_empty_read() {
    // The contrapositive: a SUFFICIENT-width numeric record decodes to
    // `Valid(t)` (the domain accessor surfaces it), pinning that `EmptyRead` is
    // SPECIFIC to a sub-width value, not the whole numeric path.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_FNUMBER, &be16(40960))); // f/8
    records.extend_from_slice(&rec(TAG_ISO, &be16(800)));
    records.extend_from_slice(&rec(TAG_FRAME_RATE, &rat64u(30_000, 1001)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert!(matches!(snap.f_number_read(), Some(NumericRead::Valid(_))));
    assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
    assert_eq!(snap.iso_read(), Some(NumericRead::Valid(800)));
    assert_eq!(snap.iso(), Some(800));
    assert!(matches!(
      snap.frame_rate_read(),
      Some(NumericRead::Valid(_))
    ));
    assert!((snap.frame_rate().unwrap() - 30_000.0 / 1001.0).abs() < 1e-9);
  }

  #[test]
  fn final_bare_numeric_header_is_absent_not_empty_read() {
    // A FINAL bare 4-byte numeric header (a 0-length record at `pos+4 == end`) is
    // NOT processed — the `while pos+4 < end` bound exits BEFORE the decode runs,
    // so the record is ABSENT (`None`), NOT `EmptyRead`. Contrast the NON-FINAL
    // sub-width case above. Verified vs bundled ExifTool 13.59 (a trailing bare
    // FNumber header emits nothing).
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(555))); // valid, non-final
    records.extend_from_slice(&TAG_FNUMBER.to_be_bytes()); // FNumber tag …
    records.extend_from_slice(&0u16.to_be_bytes()); // … len=0, NO body → final bare 4 bytes
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = out.samples()[0].camera();
    assert_eq!(snap.iso(), Some(555));
    assert_eq!(
      snap.f_number_read(),
      None,
      "a FINAL bare numeric header is ABSENT (walker bound exits), not EmptyRead"
    );
  }
}
