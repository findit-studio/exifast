// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Canon::ProcessCTMD`
//! (Canon.pm:10758-10804) — the Canon "Timed MetaData" walker shared by
//! the EOS R-line / EOS C-line (Cinema) bodies that write CTMD records into
//! CR3 / CRM / MP4 / MOV containers. Backed by the
//! `Image::ExifTool::Canon::CTMD` / `FocalInfo` / `ExposureInfo` tag tables
//! (Canon.pm:9790-9887).
//!
//! ## Record layout
//!
//! Each CTMD sample is a sequence of records of the shape
//!
//! ```text
//! [size:int32u-LE][type:int16u-LE][header:6 bytes][payload]
//! ```
//!
//! where `size` covers the whole record (including the 4-byte size field),
//! and `payload` is `size - 12` bytes long. ExifTool enters with
//! `SetByteOrder('II')` (Canon.pm:10765) — every multi-byte int is LE.
//!
//! Termination cases:
//!  - **`pos + 6 < dirLen`** is the loop guard (Canon.pm:10766); a record
//!    needs at least 6 readable bytes (size + type) before it can be
//!    classified.
//!  - **`size < 12`** ⇒ `Short CTMD record` warning, stop the walk
//!    (Canon.pm:10781).
//!  - **`pos + size > dirLen`** ⇒ `Truncated CTMD record` warning, stop
//!    the walk (Canon.pm:10782).
//!  - Trailing-byte residue (`pos != dirLen` after the loop) ⇒
//!    `Error parsing Canon CTMD data` warning, but the walker has already
//!    accumulated everything it could (Canon.pm:10802 — emitted at log
//!    level 1, AFTER `return 1`).
//!
//! ## Type dispatch
//!
//! Per `Canon.pm:9790-9830` the indexing-relevant record types are:
//!
//!  - **Type 1 — `TimeStamp`** (Canon.pm:9798-9806). The payload is
//!    `[skip:2][year:int16u-LE][month:u8][day:u8][hour:u8][min:u8][sec:u8]
//!    [centisec:u8]`. Bundled's `RawConv` (Canon.pm:9801-9804):
//!
//!    ```perl
//!    my $fmt = GetByteOrder() eq 'MM' ? 'x2nCCCCCC' : 'x2vCCCCCC';
//!    sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%.2d.%.2d', unpack($fmt, $val));
//!    ```
//!
//!    `ProcessCTMD` sets `'II'`, so the year is the LE variant.
//!  - **Type 4 — `FocalInfo`** (Canon.pm:9853-9864). A binary table of
//!    one `rational32u` entry: `FocalLength` (`Get16u(num) /
//!    Get16u(denom)`).
//!  - **Type 5 — `ExposureInfo`** (Canon.pm:9866-9887). Binary table:
//!    - `FNumber` rational32u @ offset 0 (4 bytes total);
//!    - `ExposureTime` rational32u @ offset 4 (parent stride is `int32u`
//!      = 4 bytes; rational32u itself is 4 bytes);
//!    - `ISO` int32u @ offset 8 with `ValueConv => '$val & 0x7fffffff'`.
//!
//!  - **Types 7 / 8 / 9 — `ExifInfo7/8/9`** (Canon.pm:9818-9829). Each routes
//!    into `%Canon::ExifInfo` (`PROCESS_PROC => ProcessExifInfo`,
//!    Canon.pm:9835-9853), which walks a sequence of
//!    `[len:int32u-LE][tag:int32u-LE][TIFF]` records and re-dispatches the
//!    `len - 8` TIFF bytes per `tag`: `0x8769` → `ExifIFD` (the standard Exif
//!    walker, `Exif::Main`) and `0x927c` → `MakerNoteCanon` (the Canon
//!    MakerNote walker, `Canon::Main`). [`process_exif_info`] ports this; the
//!    captured blocks ride on [`CanonCtmdSample::exif_info`] and are re-walked
//!    at emit time (the value conversion is mode-dependent).
//!
//! Other types (3 / 10 / 11) are declared in the table but carry no `Tag`
//! entry; bundled `HandleTag`s only when `$$tagTablePtr{$type}` exists
//! (Canon.pm:10790).
//!
//! ## Re-entrancy
//!
//! `ProcessCTMD` is per-sample, single-pass; no recursion is involved at
//! the walker level. Each call yields ONE [`CanonCtmdSample`].
//!
//! ## GPS priority chain
//!
//! Canon CTMD does NOT currently surface GPS — Canon writes GPS via the
//! embedded Exif TIFF blocks (`ExifInfo7/8/9` → `GPSInfoIFD`), not CTMD
//! records directly. That decode is deferred to the Exif chain (#82).
//! When it lands, the Canon-CTMD GPS would slot at the same tier as Sony
//! rtmd in the cross-port priority chain (Canon body, phone-paired GPS
//! similar to Sony's Imaging Edge Mobile model). Today's CTMD projection
//! only surfaces CameraInfo (Make=Canon), CaptureSettings (FNumber /
//! ExposureTime / ISO) and LensInfo (FocalLength).

extern crate alloc;

use smol_str::SmolStr;

use crate::metadata::{
  CanonCtmdExposure, CanonCtmdFocal, CanonCtmdMeta, CanonCtmdSample, CanonCtmdWarning,
  CtmdExifInfo, CtmdExifTag,
};
use crate::value::Rational;

// ===========================================================================
// Little-endian readers (Canon CTMD is `SetByteOrder('II')`, Canon.pm:10765)
// ===========================================================================

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)?.try_into().ok().map(u16::from_le_bytes)
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)?.try_into().ok().map(u32::from_le_bytes)
}

// ===========================================================================
// Record types (Canon.pm:9790-9830)
// ===========================================================================

const TYPE_TIMESTAMP: u16 = 1;
const TYPE_FOCAL_INFO: u16 = 4;
const TYPE_EXPOSURE_INFO: u16 = 5;
// 7 / 8 / 9 are ExifInfo* — `%Canon::ExifInfo` (ProcessExifInfo) re-dispatch.
const TYPE_EXIF_INFO_7: u16 = 7;
const TYPE_EXIF_INFO_8: u16 = 8;
const TYPE_EXIF_INFO_9: u16 = 9;
// 3, 10, 11 are declared placeholders without a Tag entry — bundled skips
// them via `if ($$tagTablePtr{$type})` (Canon.pm:10790).

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// The outcome of decoding a type-1 `TimeStamp` payload — the optional
/// rendered string plus the optional `RawConv` warning bundled raises.
///
/// `Image::ExifTool::Canon`'s `TimeStamp` `RawConv` (Canon.pm:9801-9805) ALWAYS
/// runs `unpack('x2vCCCCCC', $val)` then `sprintf('%.4d:%.2d:%.2d
/// %.2d:%.2d:%.2d.%.2d', @v)` on whatever the unpack yields — it does NOT guard
/// on a minimum length. So a SHORT payload still produces a (partial) string
/// AND may raise a `RawConv`-context warning, both surfaced here.
struct TimeStampDecode {
  /// The rendered `"YYYY:MM:DD HH:MM:SS.cc"` string, or `None` when the payload
  /// is too short for even the `x2` skip (len 0-1) — `unpack` croaks ⇒ the
  /// `RawConv` yields undef ⇒ the tag is dropped.
  text: Option<SmolStr>,
  /// The `RawConv`-context warning bundled raises (already `RawConv TimeStamp:
  /// `-prefixed), or `None` for a full (len ≥ 10) payload.
  warning: Option<&'static str>,
}

/// The `'x' outside of string in unpack` warning (RawConv-prefixed) — raised for
/// a payload shorter than the 2-byte `x2` skip (len 0-1), `unpack` croaks.
const TS_WARN_OUTSIDE: &str = "RawConv TimeStamp: 'x' outside of string in unpack";
/// The `Missing argument in sprintf` warning (RawConv-prefixed) — raised when a
/// partial (2 ≤ len < 10) payload leaves one or more `sprintf` `%` fields with
/// no `unpack` value. Bundled fires it once per missing field, but its
/// WAS_WARNED string-dedup collapses them to ONE `Warning` per sample.
const TS_WARN_MISSING: &str = "RawConv TimeStamp: Missing argument in sprintf";

/// Decode the type-1 `TimeStamp` payload (Canon.pm:9798-9806).
///
/// Payload is `[skip:2][year:int16u-LE][month:u8][day:u8][hour:u8]
/// [min:u8][sec:u8][centisec:u8]` — 10 bytes in a complete record. Mirrors the
/// Perl `RawConv` `unpack('x2vCCCCCC', $val)` + `sprintf(...)` partial
/// semantics EXACTLY (oracle-verified vs bundled 13.59 for every length 0..=12):
///
///  - **len 0-1** — the `x2` skip overruns the string; `unpack` croaks
///    (`'x' outside of string in unpack`), the `RawConv` yields undef ⇒ NO
///    `TimeStamp` tag, the warning is surfaced.
///  - **len 2-9** — `unpack` fills the fields it can and leaves the rest undef.
///    The 16-bit `year` (`v`) reads a present low byte with a zero-padded
///    missing high byte (`"\xe2"` ⇒ `0x00e2` = 226), or `0` when both year
///    bytes are absent; each missing trailing `C` byte renders `0`. `sprintf`
///    fires `Missing argument in sprintf` for each defaulted field (deduped to
///    one warning). The (partial) string IS produced.
///  - **len ≥ 10** — the full `"YYYY:MM:DD HH:MM:SS.cc"`, no warning.
///
/// Note: Perl `%.4d`/`%.2d` is "minimum width, integer" — for a non-negative
/// value identical to Rust's `{:04}`/`{:02}` zero-padding.
fn decode_time_stamp(value: &[u8]) -> TimeStampDecode {
  let len = value.len();
  // `x2` needs 2 bytes; a shorter payload croaks `unpack` ⇒ undef ⇒ no tag.
  if len < 2 {
    return TimeStampDecode {
      text: None,
      warning: Some(TS_WARN_OUTSIDE),
    };
  }
  // `v` (year, 16-bit LE) past the x2 skip: a present low byte (offset 2) with
  // the missing high byte (offset 3) zero-padded, or `0` when both are absent.
  let year = match (value.get(2), value.get(3)) {
    (Some(lo), Some(hi)) => u32::from(*lo) | (u32::from(*hi) << 8),
    (Some(lo), None) => u32::from(*lo),
    _ => 0,
  };
  // Each trailing `C` byte, or `0` (undef → sprintf renders `0`) when absent.
  let byte_or_zero = |off: usize| -> u32 { value.get(off).map_or(0, |b| u32::from(*b)) };
  let mo = byte_or_zero(4);
  let d = byte_or_zero(5);
  let h = byte_or_zero(6);
  let mi = byte_or_zero(7);
  let s = byte_or_zero(8);
  let cs = byte_or_zero(9);
  let mut out = alloc::string::String::with_capacity(22);
  use core::fmt::Write;
  let _ = write!(
    out,
    "{year:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}.{cs:02}"
  );
  // A `sprintf` `Missing argument` warning fires whenever ANY field was
  // defaulted — i.e. fewer than the 10 bytes a complete record carries.
  let warning = if len < 10 {
    Some(TS_WARN_MISSING)
  } else {
    None
  };
  TimeStampDecode {
    text: Some(SmolStr::new(out)),
    warning,
  }
}

/// Decode a `rational32u` as the typed [`Rational`] (Canon.pm:6089-6094) — the
/// format used inside the Canon CTMD binary subtables: two LE `u16` halves
/// (`Get16u(num)` / `Get16u(denom)`). Stored RAW (num/denom, NOT pre-divided)
/// so the `-n` emission renders ExifTool's `GetRational32u` `%.7g` form
/// (`ExifTool.pm:6094` `RoundFloat(n/d, 7)`) and a zero denominator keeps the
/// bare `inf` (numerator ≠ 0) / `undef` (`0/0`) word — both handled by the
/// [`Rational`] serializer. `Rational::rational32` carries `sig = 7`.
fn decode_rational32u(value: &[u8], off: usize) -> Option<Rational> {
  let num = le_u16(value, off)?;
  let denom = le_u16(value, off + 2)?;
  Some(Rational::rational32(i64::from(num), i64::from(denom)))
}

/// Decode the type-4 `FocalInfo` payload (Canon.pm:9853-9864).
///
/// Binary table with `FORMAT => 'int32u'` (4-byte stride) and one entry at
/// index 0: `FocalLength` `rational32u` (4 bytes total). Returns `None`
/// when the payload is too short to fit the rational.
fn decode_focal_info(value: &[u8]) -> Option<CanonCtmdFocal> {
  let focal_length = decode_rational32u(value, 0)?;
  let mut out = CanonCtmdFocal::new();
  out.set_focal_length(Some(focal_length));
  Some(out)
}

/// Decode the type-5 `ExposureInfo` payload (Canon.pm:9866-9887).
///
/// Binary table with `FORMAT => 'int32u'` (4-byte stride):
///  - index 0: `FNumber` rational32u at offset 0;
///  - index 1: `ExposureTime` rational32u at offset 4 (stride 4 × 1 = 4);
///  - index 2: `ISO` int32u at offset 8 with `ValueConv =>
///    '$val & 0x7fffffff'` (Canon.pm:9885).
///
/// Returns `None` when the payload is shorter than 4 bytes (no field fits) —
/// matching bundled's ProcessBinaryData early-out (`last if $more <= 0`,
/// ExifTool.pm:9953). A partial payload (4 ≤ len < 12) yields a
/// partially-populated record carrying ONLY the fields that fit (the early
/// fields decode `Some`, the later ones stay `None`), so a caller can merge it
/// PER FIELD over a fuller earlier record (see
/// [`CanonCtmdSample::merge_exposure`](crate::metadata::CanonCtmdSample::merge_exposure)).
fn decode_exposure_info(value: &[u8]) -> Option<CanonCtmdExposure> {
  let mut out = CanonCtmdExposure::new();
  let mut any = false;
  if value.len() >= 4
    && let Some(v) = decode_rational32u(value, 0)
  {
    out.set_f_number(Some(v));
    any = true;
  }
  if value.len() >= 8
    && let Some(v) = decode_rational32u(value, 4)
  {
    out.set_exposure_time(Some(v));
    any = true;
  }
  if value.len() >= 12
    && let Some(raw) = le_u32(value, 8)
  {
    // Canon.pm:9885 `ValueConv => '$val & 0x7fffffff'`.
    out.set_iso(Some(raw & 0x7fff_ffff));
    any = true;
  }
  if any { Some(out) } else { None }
}

// ===========================================================================
// process_exif_info — the bundled ProcessExifInfo port (Canon.pm:10730-10754)
// ===========================================================================

/// `Image::ExifTool::Canon::ProcessExifInfo` (Canon.pm:10730-10754) — walk the
/// `ExifInfo7/8/9` payload's `[len:int32u-LE][tag:int32u-LE][TIFF]` records,
/// capturing each declared (`0x8769` / `0x927c`) embedded TIFF block onto
/// `sample` for emit-time re-dispatch.
///
/// Bundled (the payload is the directory: `start = 0`, `dirEnd = payload.len()`,
/// the `'II'` byte order inherited from `ProcessCTMD`'s `SetByteOrder('II')`):
///
/// ```perl
/// for ($pos = $start; $pos + 8 < $dirEnd; $pos += $len) {
///     $len = Get32u($dataPt, $pos);
///     $tag = Get32u($dataPt, $pos + 4);
///     last if $len < 8 or $pos + $len > $dirEnd or not $$tagTablePtr{$tag};
///     $et->HandleTag($tagTablePtr, $tag, undef,
///         DataPt  => $dataPt,
///         Base    => $$dirInfo{Base} + $pos + 8, # base for TIFF pointers
///         DataPos => -($pos + 8),                # (relative to Base)
///         Start   => $pos + 8,
///         Size    => $len - 8);
/// }
/// ```
///
/// Each record is `[len:int32u-LE][tag:int32u-LE][TIFF: len-8 bytes]`; the TIFF
/// data is a complete TIFF (header + IFD) whose `Base` is `$pos + 8` and whose
/// `DataPos` is `-($pos + 8)` — i.e. its out-of-line value offsets are relative
/// to the TIFF's OWN start, so the captured `len - 8` slice is self-contained
/// and walks at base 0. The `tag` (`0x8769` / `0x927c`) selects the re-dispatch
/// table; an undeclared `tag` STOPS the walk (the `not $$tagTablePtr{$tag}`
/// guard — matching bundled's "valid ExifInfo (not EXIF in CRM files)" test).
///
/// **Diagnostics.** Bundled re-dispatches each block through
/// `ProcessTIFF` → `ProcessExif` (Canon.pm:10745-10751), so a MALFORMED embedded
/// TIFF (valid header + bad IFD0 offset) raises a normal EXIF `Bad $dir
/// directory` warning (Exif.pm:6383) UNDER the active Doc/Track scope — `Bad
/// ExifIFD directory` (0x8769, non-minor) / `[minor] Bad MakerNotes directory`
/// (0x927c, `$inMakerNotes` ⇒ minor). Diagnostics are PARSE-invariant, so they
/// are harvested HERE (once, at parse time) via [`drain_exif_ifd_diagnostics`] /
/// [`drain_maker_note_diagnostics`] and pushed onto `out` as [`CanonCtmdWarning`]
/// records — the walker then stamps them with this sample's doc/track/timing (the
/// `warning_count` watermark) and [`crate::metadata::CanonCtmdMeta::warnings`]
/// surfaces them through the SAME `emit_ctmd_warnings` channel (priority-0
/// first-wins + WAS_WARNED `[xN]` dedup) as the `ProcessCTMD` walk-abort
/// warnings. The same `0x8769` parse ALSO yields its IFD0 `Model`
/// (`$$self{Model}`), threaded across the in-order walk into the emit-time
/// `0x927c` re-dispatch for model-conditional tags. The tag VALUES keep
/// re-walking at emit time unchanged.
fn process_exif_info(payload: &[u8], sample: &mut CanonCtmdSample, out: &mut CanonCtmdMeta) {
  let dir_end = payload.len();
  let mut pos = 0usize;

  // `$$self{Model}` is threaded via the OBJECT-level cell on `out`
  // ([`CanonCtmdMeta::model_state`]): a `0x8769` `ExifIFD` re-dispatch overwrites
  // it from its IFD0 `Model` (`0x0110`, last-wins), and it stays STICKY across
  // every later record AND every later sample of the file (Canon.pm:10739-10751;
  // oracle: bundled 13.59 keeps `$$self{Model}` set across CTMD samples). A LATER
  // `0x927c` `MakerNoteCanon` entry's `Canon::Main` decode keys MODEL-CONDITIONAL
  // tags on the value in effect at its walk position (e.g. `Canon::ShotInfo`
  // `CameraTemperature`); that value is frozen onto the `0x927c` block here for
  // the emit-time re-dispatch. Mirrors bundled's stateful single-pass walk.

  // Canon.pm:10739 `for (...; $pos + 8 < $dirEnd; ...)` — strict-less: a record
  // needs at least the 4-byte len + 4-byte tag readable past `$pos`.
  while pos + 8 < dir_end {
    // Canon.pm:10740-10741 `$len = Get32u($dataPt,$pos); $tag = Get32u
    // ($dataPt,$pos+4);`.
    let Some(len) = le_u32(payload, pos) else {
      break;
    };
    let Some(tag) = le_u32(payload, pos + 4) else {
      break;
    };
    let len = len as usize;

    // Canon.pm:10743 `last if $len < 8 or $pos + $len > $dirEnd or not
    // $$tagTablePtr{$tag};`. The `len < 8` underflow guard, the bounds guard,
    // and the declared-tag guard (`0x8769` / `0x927c`) — any failure STOPS the
    // walk. `from_tag_id` returns `None` for an undeclared tag (the
    // `not $$tagTablePtr{$tag}` case).
    if len < 8 {
      break;
    }
    if pos.checked_add(len).is_none_or(|e| e > dir_end) {
      break;
    }
    let Some(redispatch) = CtmdExifTag::from_tag_id(tag) else {
      break;
    };

    // Canon.pm:10749-10750 `Start => $pos + 8, Size => $len - 8` — the TIFF
    // data spans `[pos + 8, pos + len)`. The `len >= 8` + `pos + len <= dir_end`
    // guards above prove `tiff_start <= tiff_end <= dir_end`; the checked
    // `.get()` satisfies the module's `deny(indexing_slicing)` (always `Some`).
    let tiff_start = pos + 8;
    let tiff_end = pos + len;
    let Some(tiff) = payload.get(tiff_start..tiff_end) else {
      break;
    };
    // Harvest the embedded TIFF's parse-time diagnostics (the `Bad $dir
    // directory` family) at the walk position, BEFORE capturing the block —
    // so a malformed block's `Warning` is raised at the same record offset
    // bundled raises it (ahead of the post-loop residue warning), matching the
    // priority-0 first-wins emit order. A `0x8769` `ExifIFD` block ALSO yields
    // its IFD0 `Model` (`$$self{Model}`), which updates the in-order state for a
    // later `0x927c` re-dispatch. The capture below keeps the RAW bytes for the
    // unchanged emit-time value re-walk.
    let block = match redispatch {
      CtmdExifTag::ExifIfd => {
        // A `0x8769` carrying an IFD0 `Model` OVERWRITES the object-level state
        // (`$$self{Model}`, last-wins); bundled stores `$$self{Model}` from the
        // top-level Exif walk (Exif.pm:567-575) and KEEPS it forward, so a block
        // WITHOUT a `Model` leaves the prior sticky state intact. The `ExifIFD`
        // block itself carries no threaded model (the `0x8769` re-dispatch
        // consumes none).
        if let Some(m) = drain_exif_ifd_diagnostics(tiff, out) {
          out.set_model_state(Some(m));
        }
        CtmdExifInfo::new(redispatch, tiff.to_vec())
      }
      CtmdExifTag::MakerNoteCanon => {
        // A `0x927c` re-dispatches through `Canon::Main`, whose model-conditional
        // sub-tables key on the `$$self{Model}` in effect HERE — freeze it onto
        // the block for the emit-time walk.
        drain_maker_note_diagnostics(tiff, out);
        let model = out.model_state().map(SmolStr::new);
        CtmdExifInfo::with_model(redispatch, tiff.to_vec(), model)
      }
    };
    sample.push_exif_info(block);

    // `$pos += $len`.
    pos += len;
  }
}

/// Push one embedded-block diagnostic onto `out` as a [`CanonCtmdWarning`],
/// re-mapping the EXIF walker's top-directory token (`IFD0`) to the bundled
/// re-dispatch `dir_name` and forcing the `minor` level when `force_minor`.
///
/// A nested-IFD message has no whole-token `IFD0` and is left verbatim (its name
/// already matches bundled); a `0x927c` block forces every warning minor
/// (`$inMakerNotes = 1`).
fn push_redispatch_diagnostic(
  d: &crate::diagnostics::Diagnostic,
  dir_name: &str,
  force_minor: bool,
  out: &mut CanonCtmdMeta,
) {
  let message = d.message().replace("IFD0", dir_name);
  let minor = force_minor || d.ignorable() >= 1;
  out.push_warning(CanonCtmdWarning::new(SmolStr::new(message), minor));
}

/// Harvest the parse-time diagnostics of ONE `0x8769` `ExifIFD` block AND return
/// its IFD0 `Model` (`$$self{Model}`) for the in-order `ProcessExifInfo` walk.
///
/// `0x8769` → `Image::ExifTool::Exif::Main` (`Name => 'ExifIFD'`, Canon.pm:9838).
/// The EMISSION path uses the generic EXIF walker
/// ([`parse_standalone_tiff_with_base`](crate::exif::parse_standalone_tiff_with_base)),
/// which IS the 1:1 `ProcessExif`-under-`Exif::Main` port — so its diagnostics
/// (incl. nested `Bad GPS directory` from following a real `0x8825` GPS pointer)
/// match bundled. `Exif::Main` has `GROUPS{0} eq 'EXIF'`, so `$inMakerNotes = 0`
/// ⇒ NON-minor; the top directory is named `IFD0` and RE-MAPPED to `ExifIFD` (a
/// nested sub-IFD keeps its own `GPS`/`InteropIFD`/`IFD1` name — none contain the
/// whole-token `IFD0`, so the swap is precise).
///
/// The SAME parse yields the TRIMMED IFD0 `Model` the dispatcher records as
/// `$$self{Model}` (Exif.pm:567-575) — returned so a LATER in-sample `0x927c`
/// re-dispatch can evaluate its model-conditional sub-tables against it. A block
/// whose header does not parse (`None`) yields no `ExifMeta` ⇒ no diagnostic and
/// no model (bundled's `ProcessTIFF` `return 0`); a block with no IFD0 `Model`
/// returns `None` (the caller leaves the prior sticky state intact).
fn drain_exif_ifd_diagnostics(tiff: &[u8], out: &mut CanonCtmdMeta) -> Option<SmolStr> {
  use crate::diagnostics::Diagnose;
  // The embedded TIFF is self-contained (base 0), re-dispatched FROM MEMORY with
  // NO RAF: an out-of-bounds out-of-line value warns `Bad offset for ExifIFD
  // <tag>` + CONTINUE (NON-minor, `$inMakerNotes = 0`), NOT the RAF path's
  // `Error reading value` + abort. The emission path
  // ([`crate::formats::quicktime`]) uses the same no-RAF entry point, so the
  // warning and the surfaced tags agree.
  let meta = crate::exif::parse_ctmd_exif_ifd_redispatch(tiff)?;
  for d in meta.diagnostics() {
    push_redispatch_diagnostic(&d, "ExifIFD", false, out);
  }
  meta.dispatcher_model().map(SmolStr::new)
}

/// Harvest the parse-time diagnostics of ONE `0x927c` `MakerNoteCanon` block.
///
/// `0x927c` → `Image::ExifTool::Canon::Main` (Canon.pm:9845). The EMISSION path
/// uses the Canon body walker
/// ([`redispatch_ctmd_makernote`](crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote)),
/// NOT the EXIF walker — so its diagnostics come from
/// [`redispatch_ctmd_makernote_diagnostics`](crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote_diagnostics),
/// which raises ONLY the top-level IFD0-readability diagnostic `Canon::Main`
/// would. Bundled runs `ProcessExif` with `$inMakerNotes = 1` ⇒ `$dir` →
/// `MakerNotes` AND every warning MINOR (`[minor] Bad MakerNotes directory`); the
/// `IFD0` token is RE-MAPPED to `MakerNotes` and the level forced minor.
/// CRITICALLY `Canon::Main` has NO `0x8769`/`0x8825`/`0xa005` Exif sub-dir
/// pointers, so a crafted `0x927c` IFD0 carrying e.g. a bad `0x8769` is NEVER
/// followed and raises NO spurious nested `Bad ExifIFD directory` — the bug using
/// the generic EXIF walker here would introduce.
///
/// Two diagnostic sources, in bundled's walk order: (1) the top-level IFD0
/// STRUCTURAL gate (`Bad … directory` for an unreadable directory) and (2) the
/// PER-ENTRY value-offset warnings (`Bad offset for MakerNotes <tag>` /
/// `Suspicious MakerNotes offset for <tag>`) a READABLE IFD0 with a bad
/// out-of-line value pointer raises under `$inMakerNotes`
/// (Exif.pm:6549/6660/6675). The two are mutually exclusive (an unreadable
/// directory aborts before the entry loop), so concatenating them is faithful;
/// the per-entry source is its OWN walk (the generic walker models a RAF-backed
/// non-MakerNotes directory and would raise the wrong `Error reading value` text).
/// Both route through [`push_redispatch_diagnostic`] (the `IFD0` token re-mapped
/// to `MakerNotes`, level forced minor — `$inMakerNotes`).
fn drain_maker_note_diagnostics(tiff: &[u8], out: &mut CanonCtmdMeta) {
  use crate::exif::makernotes::vendors::canon;
  // STRUCTURAL: only `Bad MakerNotes directory` (`Exif.pm:6383`,
  // `$et->Warn(..., $inMakerNotes)`) — FORCE minor. The generic 1:1 walker the
  // structural drain reuses models the `$inMakerNotes = 0` Exif frame and emits
  // it NON-minor, so the `$inMakerNotes = 1` Canon re-dispatch must flip it.
  for d in canon::redispatch_ctmd_makernote_diagnostics(tiff) {
    push_redispatch_diagnostic(&d, "MakerNotes", true, out);
  }
  // PER-ENTRY + the directory-tail `Illegal … directory size`: each carries its
  // OWN faithful level — `Bad offset` / `Suspicious offset` / `Bad format` /
  // `Invalid size` are MINOR (`$inMakerNotes`), but `Illegal MakerNotes
  // directory size` (`Exif.pm:6397`, no minor arg) is NON-minor. Do NOT force
  // minor here — respect the source level (the R8-class fix surfaced the level
  // split).
  for d in canon::redispatch_ctmd_makernote_value_offset_diagnostics(tiff) {
    push_redispatch_diagnostic(&d, "MakerNotes", false, out);
  }
}

// ===========================================================================
// process_ctmd — the bundled ProcessCTMD port
// ===========================================================================

/// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) — walk one
/// CTMD timed-metadata sample and accumulate every camera-indexing-relevant
/// record into a single [`CanonCtmdSample`], pushed onto `out` as one
/// sample per call.
///
/// Faithful behaviour notes:
///
/// - Canon.pm:10765 `SetByteOrder('II')` — every multi-byte int is LE.
/// - Canon.pm:10766 `while ($pos + 6 < $dirLen)` — strict-less; a record
///   needs at least the 4-byte size + 2-byte type readable past `$pos`.
/// - Canon.pm:10767 `$size = Get32u($dataPt, $pos)`.
/// - Canon.pm:10768 `$type = Get16u($dataPt, $pos + 4)`.
/// - Canon.pm:10781 `$size < 12` ⇒ `Short CTMD record` warning + stop.
/// - Canon.pm:10782 `$pos + $size > $dirLen` ⇒ `Truncated CTMD record`
///   warning + stop.
/// - Canon.pm:10790-10796 `HandleTag(..., Start => $pos + 12, Size => $size
///   - 12, ...)` — the value payload starts AFTER the 12-byte (size + type
///   + opaque 6-byte) prefix.
/// - Canon.pm:10800 `$pos += $size` — record-by-record advance.
/// - Canon.pm:10802 `$et->Warn('Error parsing Canon CTMD data', 1) if $pos
///   != $dirLen` — a trailing-byte residue is reported, but is non-fatal
///   (bundled returns 1 either way).
///
/// Re-entrancy: per-sample, single-pass; the walker yields exactly ONE
/// [`CanonCtmdSample`] (which itself may carry a TimeStamp + FocalInfo +
/// ExposureInfo all decoded from this call).
pub fn process_ctmd(data: &[u8], out: &mut CanonCtmdMeta) {
  let dir_len = data.len();
  let mut pos = 0usize;

  let mut sample = CanonCtmdSample::new();

  // Canon.pm:10766 `while ($pos + 6 < $dirLen)`.
  while pos + 6 < dir_len {
    // Canon.pm:10767-10768 `$size = Get32u($dataPt, $pos); $type = Get16u
    // ($dataPt, $pos + 4);`.
    let Some(size) = le_u32(data, pos) else { break };
    let Some(type_) = le_u16(data, pos + 4) else {
      break;
    };
    let size = size as usize;

    // Canon.pm:10781 `$size < 12 and $et->Warn('Short CTMD record'), last` —
    // a non-minor `$et->Warn` (no ignorable arg).
    if size < 12 {
      out.push_warning(CanonCtmdWarning::new(
        SmolStr::new("Short CTMD record"),
        false,
      ));
      break;
    }
    // Canon.pm:10782 `$pos + $size > $dirLen and $et->Warn('Truncated CTMD
    // record'), last` — also a non-minor `$et->Warn`.
    if pos.checked_add(size).is_none_or(|e| e > dir_len) {
      out.push_warning(CanonCtmdWarning::new(
        SmolStr::new("Truncated CTMD record"),
        false,
      ));
      break;
    }

    // Canon.pm:10790-10796 — value payload starts at `pos + 12`, size
    // `size - 12`. The `size >= 12` + `pos + size <= dir_len` guards above
    // prove `value_start <= value_end <= dir_len`; the checked `.get()`
    // satisfies the module's `deny(indexing_slicing)` (it is always `Some`).
    let value_start = pos + 12;
    let value_end = pos + size;
    let Some(value) = data.get(value_start..value_end) else {
      break;
    };

    // Canon.pm:10790 `if ($$tagTablePtr{$type})` — bundled only HandleTags
    // for types declared in the table. Types 3 / 10 / 11 carry comments
    // but NO `Tag` entry; they're skipped silently here.
    match type_ {
      TYPE_TIMESTAMP => {
        // The `TimeStamp` `RawConv` ALWAYS runs (Canon.pm:9801-9805); a SHORT
        // payload still yields a partial string and/or a `RawConv` warning
        // (`'x' outside of string` for len 0-1, `Missing argument in sprintf`
        // for len 2-9). The warning rides the SAME `Doc<N>:Track<N>:Warning`
        // channel as the ProcessCTMD walk-abort warnings — `$et->Warn` inside
        // a `RawConv` `FoundTag`s under the sample's open `DOC_NUM`.
        let decode = decode_time_stamp(value);
        if let Some(ts) = decode.text {
          sample.set_time_stamp(Some(ts));
        }
        if let Some(msg) = decode.warning {
          out.push_warning(CanonCtmdWarning::new(SmolStr::new(msg), false));
        }
      }
      TYPE_FOCAL_INFO => {
        if let Some(f) = decode_focal_info(value) {
          sample.set_focal(Some(f));
        }
      }
      TYPE_EXPOSURE_INFO => {
        // PER-FIELD merge, not whole-record replace: a partial duplicate (e.g. a
        // 4-byte type-5 carrying only `FNumber`) overwrites JUST that field and
        // preserves an earlier record's `ExposureTime` / `ISO` — bundled emits
        // only the fields that fit the payload and resolves duplicates per tag
        // name (Canon.pm:9874-9887; ExifTool.pm:9917-9918,9514-9565). A full
        // record still overwrites every field (full-record last-wins unchanged).
        if let Some(e) = decode_exposure_info(value) {
          sample.merge_exposure(e);
        }
      }
      // 7 / 8 / 9: ExifInfo* — `%Canon::ExifInfo` (ProcessExifInfo) re-dispatch
      // (Canon.pm:9818-9853). All three route into the SAME `%Canon::ExifInfo`
      // table, so they share one walker; the captured TIFF blocks are re-walked
      // at emit time (the value conversion is mode-dependent).
      TYPE_EXIF_INFO_7 | TYPE_EXIF_INFO_8 | TYPE_EXIF_INFO_9 => {
        process_exif_info(value, &mut sample, out);
      }
      // 3 / 10 / 11 / unknown: bundled has no Tag → no decode.
      _ => {}
    }

    // Canon.pm:10800 `$pos += $size`.
    pos += size;
  }

  // Canon.pm:10802 `$et->Warn('Error parsing Canon CTMD data', 1) if $pos
  // != $dirLen` — the `1` ignorable arg marks it MINOR ⇒ bundled prefixes
  // `[minor] `. Raised AFTER the walk (so a TimeStamp `RawConv` warning raised
  // mid-walk takes the priority-0 first-wins `Warning` slot ahead of it).
  if pos != dir_len {
    out.push_warning(CanonCtmdWarning::new(
      SmolStr::new("Error parsing Canon CTMD data"),
      true,
    ));
  }

  out.push_sample(sample);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ---------- record builders ----------

  /// Build one CTMD record `[size:u32-LE][type:u16-LE][6 opaque header
  /// bytes][payload]`.
  fn ctmd_record(type_: u16, header: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let size = 12 + payload.len();
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(&(size as u32).to_le_bytes());
    v.extend_from_slice(&type_.to_le_bytes());
    v.extend_from_slice(&header);
    v.extend_from_slice(payload);
    v
  }

  fn opaque_header() -> [u8; 6] {
    [0, 0, 0, 1, 0xff, 0xff]
  }

  // ---------- decoder unit tests ----------

  #[test]
  fn decode_time_stamp_matches_perl_fixture() {
    // From the CanonRaw.cr3 fixture (perl exiftool -v3 dump):
    //   payload bytes: `00 00 e2 07 02 15 0c 08 38 15 00 00`
    //   ⇒ skip 2, year=0x07e2 LE = 2018, month=2, day=21, hour=12 (0x0c),
    //     min=8, sec=56 (0x38), centisec=21 (0x15).
    //   ⇒ "2018:02:21 12:08:56.21".
    let payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let d = decode_time_stamp(&payload);
    assert_eq!(d.text.as_deref(), Some("2018:02:21 12:08:56.21"));
    assert_eq!(d.warning, None);
  }

  #[test]
  fn decode_time_stamp_partial_lengths_match_bundled() {
    // FIX #4 — `unpack('x2vCCCCCC')` + `sprintf` partial semantics, oracle'd
    // against bundled ExifTool 13.59 for EVERY payload length 0..=12. The full
    // 12-byte payload truncated at each length:
    //   00 00 | e2 07 | 02 15 0c 08 38 15 | 00 00
    let full = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    // (len, expected text, expected warning)
    let cases: &[(usize, Option<&str>, Option<&str>)] = &[
      (0, None, Some(TS_WARN_OUTSIDE)),
      (1, None, Some(TS_WARN_OUTSIDE)),
      (2, Some("0000:00:00 00:00:00.00"), Some(TS_WARN_MISSING)),
      (3, Some("0226:00:00 00:00:00.00"), Some(TS_WARN_MISSING)),
      (4, Some("2018:00:00 00:00:00.00"), Some(TS_WARN_MISSING)),
      (5, Some("2018:02:00 00:00:00.00"), Some(TS_WARN_MISSING)),
      (6, Some("2018:02:21 00:00:00.00"), Some(TS_WARN_MISSING)),
      (7, Some("2018:02:21 12:00:00.00"), Some(TS_WARN_MISSING)),
      (8, Some("2018:02:21 12:08:00.00"), Some(TS_WARN_MISSING)),
      (9, Some("2018:02:21 12:08:56.00"), Some(TS_WARN_MISSING)),
      (10, Some("2018:02:21 12:08:56.21"), None),
      (11, Some("2018:02:21 12:08:56.21"), None),
      (12, Some("2018:02:21 12:08:56.21"), None),
    ];
    for &(len, want_text, want_warn) in cases {
      let payload = full.get(..len).expect("len <= 12");
      let d = decode_time_stamp(payload);
      assert_eq!(d.text.as_deref(), want_text, "TimeStamp text at len={len}");
      assert_eq!(d.warning, want_warn, "TimeStamp warning at len={len}");
    }
  }

  #[test]
  fn decode_time_stamp_pads_year_and_centisec() {
    // year=99 (0x63 00), month=1, day=1, hour=0, min=0, sec=0, cs=1.
    let payload = [
      0x00, 0x00, 0x63, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    let d = decode_time_stamp(&payload);
    assert_eq!(d.text.as_deref(), Some("0099:01:01 00:00:00.01"));
    assert_eq!(d.warning, None);
  }

  #[test]
  fn decode_focal_info_matches_perl_fixture() {
    // Real CR3 bytes: `0f 00 01 00 ff ff ff ff ff ff ff ff` ⇒ FocalLength
    // rational32u = (15, 1) = 15.0mm.
    let payload = [
      0x0f, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let f = decode_focal_info(&payload).expect("decoded");
    assert!((f.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);
    assert_eq!(f.focal_length_rational(), Some(Rational::rational32(15, 1)));
  }

  #[test]
  fn decode_focal_info_too_short_returns_none() {
    let payload = [0x0fu8, 0x00];
    assert!(decode_focal_info(&payload).is_none());
  }

  #[test]
  fn decode_exposure_info_matches_perl_fixture() {
    // Real CR3 bytes (28 bytes payload):
    //   `23 00 0a 00 01 00 50 00 00 32 00 00 01 00 00 00 ff ff ff ff
    //    00 00 00 00 ff ff ff ff`
    //  - FNumber = rational32u(0x0023, 0x000a) = 35 / 10 = 3.5.
    //  - ExposureTime = rational32u(0x0001, 0x0050) = 1 / 80 = 0.0125.
    //  - ISO = int32u(0x00003200) & 0x7fffffff = 12800.
    let payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!((e.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
    assert_eq!(e.f_number_rational(), Some(Rational::rational32(35, 10)));
    assert_eq!(
      e.exposure_time_rational(),
      Some(Rational::rational32(1, 80))
    );
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn decode_exposure_info_iso_high_bit_masked() {
    // ISO = 0x80003200 ⇒ post-mask = 0x00003200 = 12800.
    let payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x80,
    ];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn decode_exposure_info_partial_payload_decodes_prefix_only() {
    // Only 4 bytes ⇒ FNumber only.
    let payload = [0x23, 0x00, 0x0a, 0x00];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!(e.exposure_time_s().is_none());
    assert!(e.iso().is_none());
  }

  #[test]
  fn decode_rational32u_keeps_num_denom_with_sig7() {
    // FIX #3 — the rational is stored RAW (num/denom) with sig=7, so its `-n`
    // string is the `GetRational32u` `%.7g` form, NOT a pre-divided 15-digit
    // f64. `10/3` ⇒ `3.333333` (the bundled oracle value).
    let bytes = [0x0a, 0x00, 0x03, 0x00]; // 10 / 3
    let r = decode_rational32u(&bytes, 0).unwrap();
    assert_eq!(r, Rational::rational32(10, 3));
    assert_eq!(r.exiftool_val_str(), "3.333333");
  }

  #[test]
  fn decode_rational32u_zero_denominator_renders_inf_undef() {
    // n/0 (n≠0) ⇒ the bare `inf` word; 0/0 ⇒ `undef` (the Rational serializer
    // handles both, matching bundled's `GetRational32u`).
    let inf = decode_rational32u(&[0x01, 0x00, 0x00, 0x00], 0).unwrap();
    assert_eq!(inf.exiftool_val_str(), "inf");
    assert!(inf.to_f64().is_infinite());
    let undef = decode_rational32u(&[0x00, 0x00, 0x00, 0x00], 0).unwrap();
    assert_eq!(undef.exiftool_val_str(), "undef");
    assert!(undef.to_f64().is_nan());
  }

  // ---------- ProcessExifInfo (type 7/8/9) walker tests ----------

  /// Build one `ProcessExifInfo` record: `[len:u32-LE][tag:u32-LE][tiff]` with
  /// `len = 8 + tiff.len()` (Canon.pm:10740-10750).
  fn exif_info_entry(tag: u32, tiff: &[u8]) -> Vec<u8> {
    let len = 8 + tiff.len();
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&(len as u32).to_le_bytes());
    v.extend_from_slice(&tag.to_le_bytes());
    v.extend_from_slice(tiff);
    v
  }

  #[test]
  fn process_exif_info_captures_exif_and_makernote_in_walk_order() {
    // Two entries: 0x8769 ExifIFD (4-byte TIFF stub) then 0x927c
    // MakerNoteCanon (3-byte TIFF stub). `process_exif_info` only WALKS the
    // `[len][tag]` records (the TIFF re-dispatch happens at emit time), so the
    // TIFF bytes are opaque here — just length-bearing.
    let exif_tiff = [0xaa, 0xbb, 0xcc, 0xdd];
    let mn_tiff = [0x11, 0x22, 0x33];
    let mut payload = exif_info_entry(0x8769, &exif_tiff);
    payload.extend_from_slice(&exif_info_entry(0x927c, &mn_tiff));
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    let blocks = sample.exif_info();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].tag(), CtmdExifTag::ExifIfd);
    assert_eq!(blocks[0].tiff(), &exif_tiff);
    assert_eq!(blocks[1].tag(), CtmdExifTag::MakerNoteCanon);
    assert_eq!(blocks[1].tiff(), &mn_tiff);
    // The opaque 4-/3-byte stubs are NOT valid TIFF (no II/MM header), so the
    // diagnostics harvest parses nothing and raises no warning.
    assert!(out.warnings().is_empty());
  }

  /// A minimal valid LE TIFF whose IFD0 carries `Model` (`0x0110`, ASCII
  /// out-of-line) — the `$$self{Model}` source a `0x8769` `ExifIFD` block hands
  /// off to a following `0x927c` re-dispatch.
  fn tiff_ifd0_model(model: &[u8]) -> Vec<u8> {
    let mut s = model.to_vec();
    if s.last() != Some(&0) {
      s.push(0);
    }
    let count: u16 = 1;
    let ifd0_off: u32 = 8;
    let ifd0_size = 2 + usize::from(count) * 12 + 4;
    let str_off = ifd0_off as usize + ifd0_size;
    let mut ifd0 = Vec::new();
    ifd0.extend_from_slice(&count.to_le_bytes());
    ifd0.extend_from_slice(&0x0110u16.to_le_bytes()); // Model
    ifd0.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    ifd0.extend_from_slice(&(s.len() as u32).to_le_bytes());
    ifd0.extend_from_slice(&(str_off as u32).to_le_bytes());
    ifd0.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    let mut v = Vec::new();
    v.extend_from_slice(b"II");
    v.extend_from_slice(&0x2Au16.to_le_bytes());
    v.extend_from_slice(&ifd0_off.to_le_bytes());
    v.extend_from_slice(&ifd0);
    v.extend_from_slice(&s);
    v
  }

  #[test]
  fn process_exif_info_threads_0x8769_model_to_following_0x927c() {
    // A `0x8769` `ExifIFD` block carrying IFD0 `Model` "Canon EOS R5", FOLLOWED by
    // a `0x927c` `MakerNoteCanon` block, in ONE record. The `0x8769` parse sets
    // `$$self{Model}`; the `0x927c` block freezes it for the emit-time
    // model-conditional re-dispatch (Canon.pm:10739-10751). The `0x8769` block
    // itself carries no threaded model.
    let mn_tiff = [0x11, 0x22, 0x33];
    let mut payload = exif_info_entry(0x8769, &tiff_ifd0_model(b"Canon EOS R5"));
    payload.extend_from_slice(&exif_info_entry(0x927c, &mn_tiff));
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    let blocks = sample.exif_info();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].tag(), CtmdExifTag::ExifIfd);
    assert_eq!(blocks[0].model(), None, "the 0x8769 block carries no model");
    assert_eq!(blocks[1].tag(), CtmdExifTag::MakerNoteCanon);
    assert_eq!(
      blocks[1].model(),
      Some("Canon EOS R5"),
      "the 0x927c block freezes the preceding 0x8769 IFD0 Model"
    );
    // The object-level cell stays set for any later record/sample.
    assert_eq!(out.model_state(), Some("Canon EOS R5"));
    assert!(out.warnings().is_empty());
  }

  #[test]
  fn process_ctmd_model_state_sticky_across_records_and_samples() {
    // `$$self{Model}` is OBJECT-level state, sticky across records AND samples
    // (oracle: bundled 13.59). Sample A's record sets it via a `0x8769`; a LATER
    // `0x927c`-only sample (no `0x8769`) still freezes the carried-over Model.
    // Build two `process_ctmd` calls sharing one `CanonCtmdMeta` (the per-file
    // accumulator), mirroring the per-sample driver.
    let mn = [0x11, 0x22, 0x33];
    let mut out = CanonCtmdMeta::new();

    // Sample A: a type-7 record with 0x8769(Model) then 0x927c.
    let mut a_payload = exif_info_entry(0x8769, &tiff_ifd0_model(b"Canon EOS R5"));
    a_payload.extend_from_slice(&exif_info_entry(0x927c, &mn));
    let sample_a = ctmd_record(7, opaque_header(), &a_payload);
    process_ctmd(&sample_a, &mut out);

    // Sample B: a SEPARATE call (new sample) with ONLY a 0x927c — no 0x8769.
    let b_payload = exif_info_entry(0x927c, &mn);
    let sample_b = ctmd_record(7, opaque_header(), &b_payload);
    process_ctmd(&sample_b, &mut out);

    // Sample A's 0x927c (sample 0, block 1) and sample B's 0x927c (sample 1,
    // block 0) both carry the EOS Model — the cell stayed set across the calls.
    let a_mn = &out.samples()[0].exif_info()[1];
    let b_mn = &out.samples()[1].exif_info()[0];
    assert_eq!(a_mn.tag(), CtmdExifTag::MakerNoteCanon);
    assert_eq!(a_mn.model(), Some("Canon EOS R5"));
    assert_eq!(b_mn.tag(), CtmdExifTag::MakerNoteCanon);
    assert_eq!(
      b_mn.model(),
      Some("Canon EOS R5"),
      "the cross-sample $$self{{Model}} is sticky"
    );
  }

  #[test]
  fn process_exif_info_later_0x8769_model_overrides_earlier() {
    // Last-wins: two `0x8769` blocks with different Models, then a `0x927c`. The
    // SECOND Model overwrites `$$self{Model}` (Exif.pm `$$self{Model} = ...`), so
    // the `0x927c` carries the LATER one (oracle-confirmed vs bundled 13.59).
    let mn = [0x11, 0x22, 0x33];
    let mut payload = exif_info_entry(0x8769, &tiff_ifd0_model(b"Canon EOS-1DS"));
    payload.extend_from_slice(&exif_info_entry(0x8769, &tiff_ifd0_model(b"Canon EOS R5")));
    payload.extend_from_slice(&exif_info_entry(0x927c, &mn));
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    let blocks = sample.exif_info();
    assert_eq!(blocks.len(), 3);
    assert_eq!(
      blocks[2].model(),
      Some("Canon EOS R5"),
      "the later 0x8769 Model overrides the earlier for the following 0x927c"
    );
  }

  #[test]
  fn process_exif_info_0x927c_without_preceding_model_carries_none() {
    // A `0x927c` with NO preceding in-sample (or prior-sample) `0x8769` Model
    // carries `None` — the model-conditional tags then evaluate against an unset
    // `$$self{Model}` exactly as bundled does for a model-less stream.
    let mn = [0x11, 0x22, 0x33];
    let payload = exif_info_entry(0x927c, &mn);
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    assert_eq!(sample.exif_info()[0].model(), None);
    assert_eq!(out.model_state(), None);
  }

  #[test]
  fn process_exif_info_stops_on_undeclared_tag() {
    // Canon.pm:10743 `not $$tagTablePtr{$tag}` — an undeclared tag STOPS the
    // walk (the "valid ExifInfo (not EXIF in CRM files)" test). A valid 0x8769
    // entry FOLLOWED by an undeclared 0x1234 entry: only the first is captured.
    let exif_tiff = [0xaa, 0xbb, 0xcc, 0xdd];
    let bogus_tiff = [0u8; 4];
    let mut payload = exif_info_entry(0x8769, &exif_tiff);
    payload.extend_from_slice(&exif_info_entry(0x1234, &bogus_tiff));
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    assert_eq!(sample.exif_info().len(), 1);
    assert_eq!(sample.exif_info()[0].tag(), CtmdExifTag::ExifIfd);
  }

  #[test]
  fn process_exif_info_stops_on_short_len() {
    // Canon.pm:10743 `last if $len < 8` — a `len < 8` record stops the walk
    // (and would underflow `len - 8`). Craft a raw entry with len = 4.
    let mut payload = Vec::new();
    payload.extend_from_slice(&4u32.to_le_bytes()); // len = 4 (< 8)
    payload.extend_from_slice(&0x8769u32.to_le_bytes()); // tag
    payload.extend_from_slice(&[0u8; 8]); // padding so `pos + 8 < dirEnd`
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    assert!(sample.exif_info().is_empty());
  }

  #[test]
  fn process_exif_info_stops_on_truncated_len() {
    // Canon.pm:10743 `$pos + $len > $dirEnd` — a `len` that overruns the
    // payload stops the walk. len = 100, but only ~16 bytes present.
    let mut payload = Vec::new();
    payload.extend_from_slice(&100u32.to_le_bytes()); // len = 100
    payload.extend_from_slice(&0x8769u32.to_le_bytes()); // tag
    payload.extend_from_slice(&[0u8; 8]); // 8 bytes only → pos+len overruns
    let mut sample = CanonCtmdSample::new();
    let mut out = CanonCtmdMeta::new();
    process_exif_info(&payload, &mut sample, &mut out);
    assert!(sample.exif_info().is_empty());
  }

  #[test]
  fn process_exif_info_empty_or_too_short_payload_captures_nothing() {
    // `$pos + 8 < $dirEnd` guard: a payload shorter than 9 bytes can't hold
    // even the 8-byte len+tag prefix readably, so the loop never runs.
    for payload in [&[][..], &[0u8; 8][..]] {
      let mut sample = CanonCtmdSample::new();
      let mut out = CanonCtmdMeta::new();
      process_exif_info(payload, &mut sample, &mut out);
      assert!(sample.exif_info().is_empty());
    }
  }

  #[test]
  fn process_ctmd_type7_record_captures_exif_info_block() {
    // End-to-end via the CTMD walker: a type-7 record whose payload is one
    // 0x8769 ExifInfo entry. `process_ctmd` dispatches types 7/8/9 to
    // `process_exif_info`; the sample carries the captured block.
    let exif_tiff = [0xde, 0xad, 0xbe, 0xef];
    let payload = exif_info_entry(0x8769, &exif_tiff);
    let data = ctmd_record(7, opaque_header(), &payload);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warnings().is_empty());
    let s = &out.samples()[0];
    assert_eq!(s.exif_info().len(), 1);
    assert_eq!(s.exif_info()[0].tag(), CtmdExifTag::ExifIfd);
    assert_eq!(s.exif_info()[0].tiff(), &exif_tiff);
    // A type-7-only sample is NOT empty (it carries the ExifInfo block).
    assert!(!s.is_empty());
  }

  // ---------- embedded-TIFF diagnostics ----------

  /// A VALID little-endian TIFF header (`II 0x2a`) whose IFD0 offset (64) clears
  /// the `>= 8` gate but OVERRUNS the 16-byte block — the `parse_standalone_tiff`
  /// header parses (so `ExifByteOrder` survives) but the IFD0 directory read
  /// aborts with `Bad <dir> directory`. Mirrors `tools/gen_canon_ctmd_fixture.py`
  /// `tiff_bad_ifd0`.
  fn tiff_bad_ifd0() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"II");
    v.extend_from_slice(&0x2Au16.to_le_bytes());
    v.extend_from_slice(&64u32.to_le_bytes()); // IFD0 offset overruns
    v.extend_from_slice(&[0u8; 8]); // 8 filler bytes (total 16)
    v
  }

  #[test]
  fn drain_diagnostics_0x8769_bad_ifd0_is_non_minor_exififd() {
    // The 0x8769 (ExifIFD) re-dispatch runs `Exif::Main` (non-MakerNotes), so
    // bundled raises the NON-minor `Bad ExifIFD directory` (Canon.pm:9838 names
    // the directory `ExifIFD`).
    let mut out = CanonCtmdMeta::new();
    let _ = drain_exif_ifd_diagnostics(&tiff_bad_ifd0(), &mut out);
    assert_eq!(
      out
        .warnings()
        .iter()
        .map(|w| (w.message(), w.minor()))
        .collect::<Vec<_>>(),
      [("Bad ExifIFD directory", false)],
    );
  }

  #[test]
  fn drain_diagnostics_0x927c_bad_ifd0_is_minor_makernotes() {
    // The 0x927c (MakerNoteCanon) re-dispatch runs `Canon::Main`, whose
    // `GROUPS{0} eq 'MakerNotes'` sets `$inMakerNotes = 1` in `ProcessExif`,
    // renaming the directory `MakerNotes` AND forcing the warning MINOR —
    // `[minor] Bad MakerNotes directory`. The `[minor] ` prefix is applied at
    // emit time from the `minor` flag, so the stored message is bare.
    let mut out = CanonCtmdMeta::new();
    drain_maker_note_diagnostics(&tiff_bad_ifd0(), &mut out);
    assert_eq!(
      out
        .warnings()
        .iter()
        .map(|w| (w.message(), w.minor()))
        .collect::<Vec<_>>(),
      [("Bad MakerNotes directory", true)],
    );
  }

  /// A VALID LE TIFF whose IFD0 is READABLE and holds (1) a `0x0007` firmware
  /// leaf and (2) a `0x8769` (ExifIFD-pointer) LONG entry whose value points far
  /// past EOF. Under `Canon::Main` (the `0x927c` re-dispatch) `0x8769` is NOT a
  /// table key, so it is never followed — no nested directory walk. Under
  /// `Exif::Main` it WOULD be followed (the bug). 16-byte block: header(8) +
  /// IFD0(2 + 2×12 + 4 = 30) + firmware string — but to keep IFD0 readable the
  /// string sits right after, so the block is self-sized below.
  fn tiff_makernote_with_bad_exif_pointer() -> Vec<u8> {
    let s = b"FW1.0.0\x00";
    let count: u16 = 2;
    let ifd0_off: u32 = 8;
    let ifd0_size = 2 + usize::from(count) * 12 + 4;
    let str_off = ifd0_off as usize + ifd0_size;
    let mut ifd0 = Vec::new();
    ifd0.extend_from_slice(&count.to_le_bytes());
    // 0x0007 CanonFirmwareVersion (ASCII), out-of-line at str_off.
    ifd0.extend_from_slice(&0x0007u16.to_le_bytes());
    ifd0.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    ifd0.extend_from_slice(&(s.len() as u32).to_le_bytes());
    ifd0.extend_from_slice(&(str_off as u32).to_le_bytes());
    // 0x8769 ExifIFD-style pointer (LONG) → way past EOF.
    ifd0.extend_from_slice(&0x8769u16.to_le_bytes());
    ifd0.extend_from_slice(&4u16.to_le_bytes()); // LONG
    ifd0.extend_from_slice(&1u32.to_le_bytes());
    ifd0.extend_from_slice(&0x7000_0000u32.to_le_bytes()); // bad offset
    ifd0.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    let mut v = Vec::new();
    v.extend_from_slice(b"II");
    v.extend_from_slice(&0x2Au16.to_le_bytes());
    v.extend_from_slice(&ifd0_off.to_le_bytes());
    v.extend_from_slice(&ifd0);
    v.extend_from_slice(s);
    v
  }

  #[test]
  fn drain_diagnostics_0x927c_bad_exif_pointer_raises_no_nested_warning() {
    // R3-1 (crafted): a `0x927c` block whose READABLE IFD0 carries a `0x8769`
    // pointer with a bad offset. `Canon::Main` has no `0x8769` SubDirectory, so
    // bundled NEVER follows it ⇒ NO `Bad ExifIFD directory` (oracle-verified vs
    // ExifTool 13.59: `-ee -warning` emits nothing; `CanonFirmwareVersion`
    // decodes). The generic EXIF walker (`Exif::Main`) WOULD follow it and emit
    // the spurious nested warning — routing through the Canon `Canon::Main`
    // diagnostics suppresses it.
    let mut out = CanonCtmdMeta::new();
    drain_maker_note_diagnostics(&tiff_makernote_with_bad_exif_pointer(), &mut out);
    assert!(
      out.warnings().is_empty(),
      "0x927c IFD0 with a bad 0x8769 pointer must raise NO nested warning (Canon::Main \
       does not follow it), got {:?}",
      out
        .warnings()
        .iter()
        .map(|w| w.message())
        .collect::<Vec<_>>(),
    );
  }

  #[test]
  fn drain_diagnostics_0x8769_bad_exif_pointer_via_exif_main_unaffected() {
    // Counterpart: the SAME bad-`0x8769`-pointer IFD0, but re-dispatched as a
    // `0x8769` (ExifIFD) block → the generic EXIF walker (`Exif::Main`) DOES
    // follow the `0x8769` SubDirectory and raises `Bad ExifIFD directory` (the
    // `0x8769` path is faithful — `Exif::Main` is the right table there).
    let mut out = CanonCtmdMeta::new();
    let _ = drain_exif_ifd_diagnostics(&tiff_makernote_with_bad_exif_pointer(), &mut out);
    assert_eq!(
      out
        .warnings()
        .iter()
        .map(|w| (w.message(), w.minor()))
        .collect::<Vec<_>>(),
      [("Bad ExifIFD directory", false)],
      "the 0x8769 (Exif::Main) path follows the nested pointer as bundled does",
    );
  }

  #[test]
  fn drain_diagnostics_valid_tiff_raises_nothing() {
    // A well-formed embedded TIFF (the real ExifIFD stub the exifinfo fixture
    // uses) decodes cleanly — no `Bad directory` warning.
    let tiff = tiff_exif_ifd_stub();
    let mut out = CanonCtmdMeta::new();
    let _ = drain_exif_ifd_diagnostics(&tiff, &mut out);
    assert!(out.warnings().is_empty());
  }

  #[test]
  fn drain_diagnostics_unparseable_header_raises_nothing() {
    // A block whose first bytes are not a TIFF byte-order marker yields no
    // `ExifMeta` (bundled's `ProcessTIFF` `return 0`) ⇒ no diagnostic.
    let mut out = CanonCtmdMeta::new();
    let _ = drain_exif_ifd_diagnostics(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0], &mut out);
    assert!(out.warnings().is_empty());
  }

  /// A minimal valid LE TIFF: IFD0 with one inline ISO (0x8827) tag. Used to
  /// prove the diagnostics harvest stays SILENT on a well-formed block.
  fn tiff_exif_ifd_stub() -> Vec<u8> {
    let mut ifd0 = Vec::new();
    ifd0.extend_from_slice(&1u16.to_le_bytes()); // count = 1
    ifd0.extend_from_slice(&0x8827u16.to_le_bytes()); // ISO
    ifd0.extend_from_slice(&3u16.to_le_bytes()); // int16u
    ifd0.extend_from_slice(&1u32.to_le_bytes()); // count
    ifd0.extend_from_slice(&100u16.to_le_bytes()); // value 100 (inline)
    ifd0.extend_from_slice(&0u16.to_le_bytes()); // value padding
    ifd0.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    let mut v = Vec::new();
    v.extend_from_slice(b"II");
    v.extend_from_slice(&0x2Au16.to_le_bytes());
    v.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8
    v.extend_from_slice(&ifd0);
    v
  }

  #[test]
  fn process_ctmd_type7_bad_exif_block_raises_exififd_warning() {
    // End-to-end: a type-7 record carrying ONE 0x8769 block whose embedded TIFF
    // has a valid header but a bad IFD0 offset. The block is STILL captured (its
    // header parses, so emit re-walks it for `ExifByteOrder`), AND a non-minor
    // `Bad ExifIFD directory` warning is raised under this sample.
    let payload = exif_info_entry(0x8769, &tiff_bad_ifd0());
    let data = ctmd_record(7, opaque_header(), &payload);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert_eq!(
      out
        .warnings()
        .iter()
        .map(|w| (w.message(), w.minor()))
        .collect::<Vec<_>>(),
      [("Bad ExifIFD directory", false)],
    );
    // The block is retained for the emit-time `ExifByteOrder` re-walk.
    assert_eq!(out.samples()[0].exif_info().len(), 1);
  }

  #[test]
  fn process_ctmd_type7_bad_makernote_block_raises_minor_warning() {
    // End-to-end: a type-7 record carrying ONE 0x927c block whose embedded TIFF
    // is bad ⇒ the MINOR `Bad MakerNotes directory` warning (no `ExifByteOrder`
    // surfaces for the MakerNote re-dispatch, handled at emit time).
    let payload = exif_info_entry(0x927c, &tiff_bad_ifd0());
    let data = ctmd_record(7, opaque_header(), &payload);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert_eq!(
      out
        .warnings()
        .iter()
        .map(|w| (w.message(), w.minor()))
        .collect::<Vec<_>>(),
      [("Bad MakerNotes directory", true)],
    );
  }

  // ---------- walker tests ----------

  #[test]
  fn process_ctmd_decodes_real_fixture_record_sequence() {
    // Mirror the real CR3 fixture (CanonRaw.cr3): TimeStamp + Focal +
    // Exposure (the type-3 / type-7 placeholders are walked but not
    // decoded).
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let focal_payload = [
      0x0f, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let exp_payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00,
    ];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    data.extend_from_slice(&ctmd_record(4, opaque_header(), &focal_payload));
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &exp_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warnings().is_empty(), "no warnings on clean fixture");
    assert_eq!(out.samples().len(), 1);
    let s = &out.samples()[0];
    assert_eq!(s.time_stamp(), Some("2018:02:21 12:08:56.21"));
    let f = s.focal().expect("focal");
    assert!((f.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);
    let e = s.exposure().expect("exposure");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!((e.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn process_ctmd_partial_duplicate_exposure_merges_per_field() {
    // R3-2 (crafted): a FULL type-5 (FNumber 3.5, ExposureTime 1/80, ISO 12800)
    // followed by an 8-byte type-5 (FNumber 8.0, ExposureTime 1/250, NO ISO)
    // then a 4-byte type-5 (FNumber 5.6 only). Bundled `HandleTag`s each record;
    // `ProcessBinaryData` emits only the fields that fit the payload and resolves
    // duplicates PER tag name (Canon.pm:9874-9887; ExifTool.pm:9514-9565). So the
    // merged sample carries the LAST FNumber (5.6), the 8-byte ExposureTime
    // (1/250 — the 4-byte record did not carry it), and the FULL record's ISO
    // (12800 — neither partial record carried it). Oracle-verified vs bundled
    // 13.59 at -ee -j AND -ee -j -n.
    let full = exposure_info_payload_full();
    let eight = {
      // FNumber 80/10, ExposureTime 1/250 — 8 bytes, no ISO field.
      let mut p = Vec::new();
      p.extend_from_slice(&80u16.to_le_bytes());
      p.extend_from_slice(&10u16.to_le_bytes());
      p.extend_from_slice(&1u16.to_le_bytes());
      p.extend_from_slice(&250u16.to_le_bytes());
      p
    };
    let four = {
      // FNumber 56/10 — 4 bytes, FNumber only.
      let mut p = Vec::new();
      p.extend_from_slice(&56u16.to_le_bytes());
      p.extend_from_slice(&10u16.to_le_bytes());
      p
    };
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &full));
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &eight));
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &four));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warnings().is_empty());
    let e = out.samples()[0].exposure().expect("exposure");
    assert_eq!(
      e.f_number_rational(),
      Some(Rational::rational32(56, 10)),
      "FNumber takes the LAST record's value (5.6)"
    );
    assert_eq!(
      e.exposure_time_rational(),
      Some(Rational::rational32(1, 250)),
      "ExposureTime is preserved from the 8-byte record (the 4-byte one omitted it)"
    );
    assert_eq!(
      e.iso(),
      Some(12800),
      "ISO is preserved from the FULL record (neither partial record carried it)"
    );
  }

  #[test]
  fn process_ctmd_full_duplicate_exposure_still_last_wins() {
    // The full-record last-wins behaviour is UNCHANGED: a full type-5 followed
    // by another FULL type-5 overwrites every field (each later field is present,
    // so the per-field merge replaces all three). Pins the `_dup` fixture's
    // byte-exact behaviour against the per-field merge.
    let first = exposure_info_payload_full(); // FN 3.5, ET 1/80, ISO 12800
    let second = {
      // FN 8.0, ET 1/250, ISO 6400 — a complete 12-byte payload.
      let mut p = Vec::new();
      p.extend_from_slice(&80u16.to_le_bytes());
      p.extend_from_slice(&10u16.to_le_bytes());
      p.extend_from_slice(&1u16.to_le_bytes());
      p.extend_from_slice(&250u16.to_le_bytes());
      p.extend_from_slice(&6400u32.to_le_bytes());
      p
    };
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &first));
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &second));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    let e = out.samples()[0].exposure().expect("exposure");
    assert_eq!(e.f_number_rational(), Some(Rational::rational32(80, 10)));
    assert_eq!(
      e.exposure_time_rational(),
      Some(Rational::rational32(1, 250))
    );
    assert_eq!(e.iso(), Some(6400));
  }

  /// A complete 12-byte type-5 `ExposureInfo` payload: FNumber 35/10,
  /// ExposureTime 1/80, ISO 12800 (the real-fixture full record).
  fn exposure_info_payload_full() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&35u16.to_le_bytes());
    p.extend_from_slice(&10u16.to_le_bytes());
    p.extend_from_slice(&1u16.to_le_bytes());
    p.extend_from_slice(&80u16.to_le_bytes());
    p.extend_from_slice(&12800u32.to_le_bytes());
    p
  }

  /// The `(message, minor)` of every warning the walker raised.
  fn warn_pairs(out: &CanonCtmdMeta) -> Vec<(&str, bool)> {
    out
      .warnings()
      .iter()
      .map(|w| (w.message(), w.minor()))
      .collect()
  }

  #[test]
  fn process_ctmd_short_record_warns_and_stops() {
    // size = 10 < 12 ⇒ `Short CTMD record` warning + stop. We need a
    // record where the size field claims < 12; the loop guard `pos + 6 <
    // dirLen` permits the read (4-byte size + 2-byte type are readable).
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&10u32.to_le_bytes()); // size = 10
    data.extend_from_slice(&1u16.to_le_bytes()); // type = 1
    // Pad so the `pos+6<dirLen` guard isn't the early-out.
    data.extend_from_slice(&[0u8; 4]);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    // The walk breaks on the short record, then the post-loop `pos != dirLen`
    // check ALSO raises the MINOR residue warning — BOTH are raised (verified
    // vs bundled `-warning`: `Short CTMD record` + `[minor] Error parsing Canon
    // CTMD data`). The emitter's priority-0 first-wins keeps only the FIRST.
    assert_eq!(
      warn_pairs(&out),
      [
        ("Short CTMD record", false),
        ("Error parsing Canon CTMD data", true),
      ]
    );
    // The sample is still pushed (empty).
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_truncated_record_warns_and_stops() {
    // size = 100, but only ~20 bytes available ⇒ truncated.
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(&100u32.to_le_bytes()); // size = 100
    data.extend_from_slice(&1u16.to_le_bytes()); // type = 1
    data.extend_from_slice(&[0u8; 14]); // 14 more bytes, total = 20
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    // As with the short case, the post-loop residue check ALSO fires (`pos`
    // never advanced past the truncated record) — both raised, the emitter
    // keeps the first (verified vs bundled `-warning`).
    assert_eq!(
      warn_pairs(&out),
      [
        ("Truncated CTMD record", false),
        ("Error parsing Canon CTMD data", true),
      ]
    );
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_unknown_type_skipped_walk_continues() {
    // Build a sequence: type=99 (no decoder) + type=1 (TimeStamp). The
    // walker must advance past type 99 and decode type 1.
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let unknown_payload = [0u8; 8];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(99, opaque_header(), &unknown_payload));
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warnings().is_empty());
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_type3_placeholder_walked_silently() {
    // Type 3 IS commented in bundled (Canon.pm:9807) but has NO Tag entry;
    // the walker advances past it without decoding anything and without
    // a warning. Pair with a type-1 to verify the walker survives.
    let placeholder_payload = [0xff, 0xff, 0xff, 0xff]; // 4 bytes, real-world shape
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(3, opaque_header(), &placeholder_payload));
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warnings().is_empty());
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_trailing_byte_residue_warns_after_decode() {
    // A full record + 5 trailing bytes (< 6, so the loop exits the
    // `pos + 6 < dirLen` guard without consuming them). Bundled emits the
    // MINOR `Error parsing Canon CTMD data` (Canon.pm:10802 `Warn(..., 1)`)
    // since `pos != dirLen` after the walk.
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let mut data = ctmd_record(1, opaque_header(), &ts_payload);
    data.extend_from_slice(&[0u8; 5]);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    // The decode happens first, then the trailing-residue warning fires.
    assert_eq!(warn_pairs(&out), [("Error parsing Canon CTMD data", true)]);
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_short_timestamp_raises_rawconv_warning_before_residue() {
    // A type-1 record carrying a len-4 TimeStamp payload (RawConv `Missing
    // argument in sprintf`) followed by 5 trailing bytes (residue → MINOR
    // `Error parsing Canon CTMD data`). The RawConv warning is raised
    // mid-walk, the residue one post-walk, in THAT order (the emitter's
    // priority-0 first-wins then keeps the RawConv one — verified vs bundled).
    let short_ts = [0x00, 0x00, 0xe2, 0x07]; // len 4 → "2018:00:00 00:00:00.00"
    let mut data = ctmd_record(1, opaque_header(), &short_ts);
    data.extend_from_slice(&[0u8; 5]);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert_eq!(
      warn_pairs(&out),
      [
        ("RawConv TimeStamp: Missing argument in sprintf", false),
        ("Error parsing Canon CTMD data", true),
      ]
    );
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:00:00 00:00:00.00")
    );
  }

  #[test]
  fn process_ctmd_empty_buffer_pushes_empty_sample_no_warning() {
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&[], &mut out);
    assert!(out.warnings().is_empty());
    // One (empty) sample is always pushed per call.
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_buffer_smaller_than_6_bytes_warns_trailing_residue() {
    // 5 bytes — the loop guard (`pos + 6 < dirLen`) fails on first iter
    // so no record is walked. After the loop, `pos (0) != dirLen (5)`
    // ⇒ Canon.pm:10802 MINOR `Error parsing Canon CTMD data` warning fires
    // (bundled has no separate guard for "dirLen too small for any
    // record"; the trailing-residue check is the only post-loop warning).
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&[0u8; 5], &mut out);
    assert_eq!(warn_pairs(&out), [("Error parsing Canon CTMD data", true)]);
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }
}
