// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
// Checked-indexing contract (golden pattern, Contract 3): this is an
// untrusted-byte parser, so every index into the GPMF input bytes is the
// checked `.get(..)` form — a hostile/truncated record must never panic. The
// few provably-bounded const-table / post-checked accesses take a narrow
// `#[allow(clippy::indexing_slicing)]` with a justifying comment at the site.
#![deny(clippy::indexing_slicing)]
//! Faithful port of `Image::ExifTool::GoPro` — the recursive Key-Length-Value
//! GoPro Metadata Format (GPMF) extracted from `gpmd` timed-metadata samples,
//! the unreferenced GoPro `GP\x06\0\0` records discovered by the
//! [`scan_media_data`](crate::formats::quicktime_freegps::scan_media_data)
//! brute-force scan, the moov-level `GPMF` atom, and the JPEG APP6
//! `GoPro` segment.
//!
//! ## What GPMF is
//!
//! Each KLV record carries an 8-byte header:
//!
//! ```text
//!   [tag: 4 ASCII] [fmt: u8] [sample_size: u8] [sample_count: u16 BE]
//! ```
//!
//! followed by `sample_size * sample_count` bytes, padded with 0..=3 NUL
//! bytes to a 4-byte boundary (GoPro.pm:831-844).
//!
//! `fmt = 0x00` is a CONTAINER — its payload is a sequence of child KLV
//! records that recurse through [`process_gopro`]. The top-level container
//! is `DEVC` (`DeviceContainer`, GoPro.pm:155-165); each `DEVC` typically
//! contains one or more nested `STRM` (`NestedSignalStream`,
//! GoPro.pm:381-384) streams. Inside `STRM` live the per-tag GPS / sensor
//! records.
//!
//! Three sibling records modify how a following tag is decoded:
//!
//!  - `TYPE` — a packed format string for a `?` (complex-struct) tag
//!    (GoPro.pm:848-863, 414);
//!  - `UNIT` / `SIUN` — per-element unit strings (informational, the
//!    PrintConv-only `%addUnits` glue, GoPro.pm:419-423, 369-373);
//!  - `SCAL` — per-sample scaling factors applied to the LAST tag in the
//!    container (GoPro.pm:337-340, 884).
//!
//! ## Format-code table (`%goProFmt`, GoPro.pm:29-48)
//!
//! ```text
//!   0x62 'b' int8s        0x42 'B' int8u        0x63 'c' string
//!   0x73 's' int16s       0x53 'S' int16u
//!   0x6c 'l' int32s       0x4c 'L' int32u
//!   0x66 'f' float        0x64 'd' double
//!   0x46 'F' undef[4]     0x47 'G' undef[16]    0x55 'U' undef[16]
//!   0x6a 'j' int64s       0x4a 'J' int64u
//!   0x71 'q' fixed32s     0x51 'Q' fixed64s     0x3f '?' complex
//! ```
//!
//! ## What this sub-port decodes
//!
//! The KLV walker visits EVERY record (containers recurse, scalars are
//! parsed by format) so the tree shape stays faithful. The typed
//! [`GoProMeta`] surface (`src/metadata/gopro.rs`) captures the GoPro-GPS
//! family this product targets:
//!
//!  - `GPS5` (Hero5+, GoPro.pm:487-514) — multi-row `int32s[5]` lat /
//!    lon / alt / 2D-speed / 3D-speed, scaled by `SCAL`;
//!  - `GPS9` (Hero13, GoPro.pm:516-563) — multi-row `?lllllllSS` lat /
//!    lon / alt / 2D-speed / 3D-speed / days / seconds / DOP / fix,
//!    scaled by `SCAL`;
//!  - `GPSU` (GoPro.pm:242-248) — UTC `YYMMDDhhmmss[.fff]` string,
//!    converted to `YYYY:MM:DD HH:MM:SS[.fff]` (no timezone suffix);
//!  - `GPSP` (GoPro.pm:237-241) — horizontal positioning error in cm,
//!    converted to metres (`$val / 100`);
//!  - `GPSF` (GoPro.pm:230-236) — numeric fix code;
//!  - `GPSA` (GoPro.pm:472) — altitude reference system;
//!  - camera identification — `DVNM` / `MINF` / `CASN` / `FMWR` / `MUID`
//!    (GoPro.pm:121, 169-172, 286-290, 195, 456-462);
//!  - the Karma-drone telemetry — `GLPI` (`GPSPos`, GoPro.pm:197-204,
//!    598-626), `KBAT` (`BatteryStatus`, GoPro.pm:264-270, 628-649), and the
//!    `SYST` (`SystemTime`, GoPro.pm:390-405) calibration the `GLPI`
//!    `GPSDateTime` column resolves against via `ConvertSystemTime`
//!    (GoPro.pm:677-702).
//!
//! `GPRI` (`GPSRaw`, GoPro.pm:205-213) is intentionally NOT decoded: its
//! `%GoPro::GPRI` SubDirectory tag carries `Unknown => 1` (GoPro.pm:210), so
//! bundled `exiftool -ee` does NOT emit it in default mode — the walker visits
//! the record (its container nesting is honoured) but drops the value, exactly
//! like ExifTool's `next unless $unknown` (GoPro.pm:876-877).
//!
//! Other tag families (ACCL/GYRO/MAGN/SHUT/ISO/Max calibrations) are walked by
//! the KLV traversal but their values are NOT emitted into the typed
//! surface in this sub-port — the parse layer's tag-dispatch is structured
//! to make adding them an additive change.
//!
//! ## Entry points
//!
//! - [`process_gopro`] — the recursive KLV walker (`ProcessGoPro`,
//!   GoPro.pm:810-900). Applied to a GPMF byte slice; visits records,
//!   tracks the `TYPE` / `SCAL` / `UNIT` sibling state, and emits into a
//!   `GoProMeta`.
//! - [`process_gp6`] — the brute-force-scan loop that walks unreferenced
//!   `GP\x06\0\0` records in `mdat` (GoPro.pm:783-803). Each contained
//!   record whose tag starts `DEVC` is dispatched into [`process_gopro`].
//!
//! ## GPS priority chain
//!
//! GoPro GPMF feeds the **HIGHEST tier** of the cross-port GPS priority
//! chain that [`crate::metadata::MediaMetadata`] projects from a QuickTime
//! file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360 trailer →
//! Parrot mett → SP3 stream. The order encodes on-device-GPS fidelity —
//! GoPro carries its own GNSS hardware and writes GPS9/GPS5 records
//! per-sample, so a GoPro file's `MediaMetadata.gps()` is always sourced
//! from these records when present.

extern crate alloc;
use alloc::{
  format,
  string::{String, ToString},
  vec::Vec,
};

use smol_str::SmolStr;

use crate::metadata::{
  GoProConv, GoProGlpiSample, GoProGpsSample, GoProIdentity, GoProKbat, GoProMeta, GoProScalar,
  GoProTag, GoProTagValue,
};

// ===========================================================================
// Byte readers — GPMF is BIG-ENDIAN (the GoPro Metadata Format byte order;
// GoPro.pm's `ReadValue` defaults to ExifTool's `MM` byte order since
// QuickTime.pm SetByteOrder('MM') is in effect at the call site).
// ===========================================================================

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  // `get(..)` yields an exactly-2-byte slice; `try_into` to a fixed array
  // keeps the read free of raw indexing (clippy::indexing_slicing).
  b.get(off..off + 2)?.try_into().ok().map(u16::from_be_bytes)
}

fn be_i16(b: &[u8], off: usize) -> Option<i16> {
  be_u16(b, off).map(|v| v as i16)
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)?.try_into().ok().map(u32::from_be_bytes)
}

fn be_i32(b: &[u8], off: usize) -> Option<i32> {
  be_u32(b, off).map(|v| v as i32)
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)?.try_into().ok().map(u64::from_be_bytes)
}

fn be_f32(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 4)?
    .try_into()
    .ok()
    .map(|a| f64::from(f32::from_be_bytes(a)))
}

fn be_f64(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 8)?.try_into().ok().map(f64::from_be_bytes)
}

// ===========================================================================
// Format codes (`%goProFmt` / `%goProSize`, GoPro.pm:29-55).
// The KLV header itself carries `sample_size` (the byte after `fmt`), so the
// walker never needs a per-fmt size table — record element sizes are read
// straight from each header. [`read_scalar_vec`] below honours the fmt code
// directly via a `match` that dispatches by code → reader, which is also
// faithful to ExifTool's `ReadValue($dataPt, $pos, $format, undef, $size)`
// dispatch (GoPro.pm:869).
// ===========================================================================

/// 4-byte-padded size of a record payload (GoPro.pm:831
/// `$pos += ($size+3) & 0xfffffffc`).
const fn padded_size(size: usize) -> usize {
  (size + 3) & !3
}

// ===========================================================================
// ProcessGP6 (GoPro.pm:783-803) — unreferenced `GP\x06\0\0` records in mdat
// ===========================================================================

/// `ProcessGP6` (GoPro.pm:783-803): walk a buffer containing one or more
/// `GP..\0[size:u32 BE]…` records. For each contained record whose payload
/// starts `DEVC`, dispatch into [`process_gopro`] (the GPMF KLV walker).
///
/// `data` is the buffer starting at the first `GP\x06\0\0` byte; the
/// scanner found this via the brute-force `\bGP\x06\0\0\b` search and
/// hands the rest of the chunk in. Records are 16-byte-header + payload,
/// repeated until the header magic stops matching or the buffer runs out.
///
/// Faithful: ExifTool's loop reads 16 bytes, parses `(tag:a4, size:N)`,
/// then if `tag =~ /^GP..\0/` and `size + 16 <= len` reads `size` more
/// bytes (the payload). Records whose payload starts `DEVC` go through
/// `ProcessGoPro`; others are silently skipped (still consume `size + 16`).
pub fn process_gp6(data: &[u8], out: &mut GoProMeta) -> usize {
  let mut pos = 0usize;
  while pos + 16 <= data.len() {
    // GoPro.pm:791 `(tag, size) = unpack('a4N', $buff)`. The 16-byte-header
    // bound (`pos + 16 <= len`) guarantees the 5-byte magic window + the size
    // u32 are present, but read them via the checked accessors anyway.
    let Some(magic) = data.get(pos..pos + 5) else {
      break;
    };
    let size = match be_u32(data, pos + 4) {
      Some(s) => s as usize,
      None => break,
    };
    // GoPro.pm:792 `last if $size + 16 > $len or $buff !~ /^GP..\0/`.
    if pos + 16 + size > data.len() {
      break;
    }
    // The header magic is `GP..\0` (5 bytes); since we passed only 4 of
    // the 16-byte unpack to the regex, the regex ALSO checks the 5th byte
    // — the first byte of the `size` u32 BE. So the FULL match window is
    // bytes 0..5 of the unpacked 16-byte header (`GP`, two arbitrary,
    // then NUL). `magic` is exactly that 5-byte slice.
    if magic.first() != Some(&b'G') || magic.get(1) != Some(&b'P') || magic.get(4) != Some(&0) {
      break;
    }
    let body_start = pos + 16;
    let body_end = body_start + size;
    let Some(body) = data.get(body_start..body_end) else {
      break;
    };
    // GoPro.pm:794 `if ($buff =~ /^DEVC/)`.
    if body.starts_with(b"DEVC") {
      // Faithful: the contained record IS itself a GPMF KLV record (its
      // first 4 bytes are the DEVC FourCC of the outermost KLV). Pass it
      // straight into the recursive walker. The byte count returned by
      // `process_gp6` (not the walker's recognized flag) is the scan-loop's
      // GP6 "found" signal (QuickTimeStream.pl:3739).
      let _ = process_gopro(body, out);
    }
    // GoPro.pm:799 `$len -= $size + 16` — advance past this record.
    pos = body_end;
  }
  pos
}

// ===========================================================================
// ProcessGoPro (GoPro.pm:810-900) — the recursive GPMF KLV walker
// ===========================================================================

/// `ProcessGoPro` (GoPro.pm:810-900): walk a GPMF byte slice as a sequence
/// of 8-byte-header KLV records; recurse on `fmt=0` containers; emit
/// recognised scalar tags into `out`.
///
/// `data` is the GPMF payload — the `DEVC` outermost KLV record, the body
/// of a `gpmd` sample, the `GPMF` atom payload, or the contents of a JPEG
/// APP6 segment. The walker is shape-faithful (it visits every record,
/// honours containers, tracks the per-container `TYPE` / `SCAL` / `UNIT`
/// state) even when the typed surface discards the value.
///
/// Returns `true` iff at least one valid GoPro GPMF record was recognized —
/// ExifTool's `$$et{FoundEmbedded}` side effect (GoPro.pm:822), which
/// QuickTimeStream.pl:3689 uses to suppress the brute-force `mdat` scan. A
/// non-GoPro `gpmd` sample misrouted here (Kingslim/Rove/FMAS/Wolfbox —
/// DEFERRED at the dispatch level) bails on the magic guard and returns
/// `false`, so the scan still runs (faithful, since the port hasn't ported
/// those dedicated processors).
#[must_use]
pub fn process_gopro(data: &[u8], out: &mut GoProMeta) -> bool {
  let mut walker = Walker {
    out,
    type_str: None,
    scal: None,
    unit: None,
  };
  walker.walk(data)
}

/// Container-walk state. ExifTool tracks `$type`, `$scal`, `$unit` per
/// recursion level (each `ProcessGoPro` invocation gets its own
/// state — the outer container's TYPE/SCAL doesn't leak into a child
/// container; GoPro.pm:819-820).
struct Walker<'a> {
  out: &'a mut GoProMeta,
  /// Last `TYPE` payload — a packed format-code string for the next `?`
  /// (complex-struct) record (GoPro.pm:848-862, 872).
  type_str: Option<Vec<u8>>,
  /// Last `SCAL` payload — the per-element scaling vector applied to the
  /// last preceding tag in this container, joined as one space-separated
  /// string (GoPro.pm:874, 884, 705-721).
  scal: Option<Vec<f64>>,
  /// Last `UNIT` / `SIUN` payload, parsed into the per-element unit strings
  /// (GoPro.pm:873) the `%addUnits` PrintConv consumes (GoPro.pm:727-743). A
  /// multi-element `c` record (count>1 && len>1) unpacks as a LIST of `len`-wide
  /// NUL-trimmed strings (GoPro.pm:864-867); a single record is one string.
  unit: Option<Vec<SmolStr>>,
}

impl Walker<'_> {
  /// Walk a GPMF byte slice. Returns `true` iff at least one valid GoPro KLV
  /// record was recognized (a header that parsed and passed the
  /// `[^-_a-zA-Z0-9 ]` tag-char guard, GoPro.pm:833) — the faithful signal for
  /// ExifTool's `$$et{FoundEmbedded} = 1` (set on `ProcessGoPro` entry,
  /// GoPro.pm:822, but only reached when the `gpmd_GoPro` SubDirectory is
  /// selected — i.e. the data really is a GoPro record, not a deferred
  /// Kingslim/Rove/FMAS/Wolfbox variant that the port misroutes here and that
  /// bails immediately on the magic guard).
  fn walk(&mut self, data: &[u8]) -> bool {
    let mut recognized = false;
    let mut pos = 0usize;
    // GoPro.pm:831 `for (; $pos+8<=$dirEnd; $pos+=($size+3)&0xfffffffc)`.
    while pos + 8 <= data.len() {
      // The 8-byte KLV header: 4-byte tag + fmt + sample_size + 2-byte BE
      // count. The `pos + 8 <= len` loop bound guarantees it is present;
      // fetch it via the checked accessor regardless.
      let Some(header) = data.get(pos..pos + 8) else {
        break;
      };
      // `header` is exactly 8 bytes, so these fixed-offset reads are in range.
      let (Some(tag), Some(&fmt), Some(&len_byte)) =
        (header.get(0..4), header.get(4), header.get(5))
      else {
        break;
      };
      let len = len_byte as usize;
      let count = match be_u16(header, 6) {
        Some(c) => c as usize,
        None => break,
      };
      // GoPro.pm:833-836 — bail on a tag with non-printable bytes (other
      // than a four-NUL terminator).
      if tag == [0, 0, 0, 0] {
        break;
      }
      if !tag.iter().all(is_tag_char) {
        // ExifTool: `$et->Warn('Unrecognized GoPro record')` and bail.
        break;
      }
      // A valid record header that passed the tag-char guard — this is a
      // genuine GoPro GPMF record (ExifTool's `FoundEmbedded`, GoPro.pm:822).
      recognized = true;
      let size = len.saturating_mul(count);
      // GoPro.pm:839-842 `if ($pos + $size > $dirEnd) { last; }`.
      if pos + 8 + size > data.len() {
        break;
      }
      let Some(payload) = data.get(pos + 8..pos + 8 + size) else {
        break;
      };
      // GoPro.pm:884 — "apply scaling … to last tag in this container":
      // `$pos + $size + 3 >= $dirEnd`. At line 884 Perl's `$pos` is the
      // record's VALUE position (it did `$pos += 8` at GoPro.pm:838), `$size`
      // is the value byte length, and `$dirEnd` is the container end. Here the
      // Rust `pos` is still the HEADER position (it is advanced only at the
      // bottom of this loop), and the container ends at `data.len()`, so the
      // value position is `pos + 8` and the predicate is `(pos + 8) + size + 3
      // >= data.len()`. The `+3` (NOT masked with `&0xfffffffc`, unlike the
      // loop-increment alignment) tests whether the NEXT record would start at
      // or past `dirEnd` — i.e. this is the last record in the container.
      let is_last_in_container = pos + 8 + size + 3 >= data.len();
      self.visit(tag, fmt, len, count, payload, is_last_in_container);
      // GoPro.pm:831 `$pos += ($size + 3) & 0xfffffffc` — 4-byte align.
      pos += 8 + padded_size(size);
    }
    recognized
  }

  fn visit(
    &mut self,
    tag: &[u8],
    fmt: u8,
    len: usize,
    count: usize,
    payload: &[u8],
    is_last_in_container: bool,
  ) {
    // GoPro.pm:845-846 — empty records (`size == 0`) are skipped unless
    // verbose, which exifast never sets.
    if payload.is_empty() {
      return;
    }
    // GoPro.pm:823-829 — a `fmt=0` is a container (subdirectory). Recurse
    // with FRESH state — `$type`/`$scal`/`$unit` are LOCAL to the
    // sub-call.
    //
    // FAITHFULNESS (GoPro.pm:876-882): a tag NOT in the `%GoPro::GPMF` table
    // is `next unless $unknown` — SKIPPED entirely in default `-ee` mode; an
    // unknown `fmt=0` record only becomes a recursable SubDirectory under the
    // `-u` (Unknown) option (`$$tagInfo{SubDirectory} = … if not $fmt`,
    // GoPro.pm:880). exifast has no `-u` channel, so default = skip unknown.
    // Therefore ONLY a KNOWN container tag is recursed; the only two tags in
    // the GoPro tables carrying `SubDirectory => GoPro::GPMF` with `fmt \0`
    // are `DEVC` (GoPro.pm:155-157) and `STRM` (GoPro.pm:381-383) — the
    // `is_known_container` set. A crafted/future unknown `fmt=0` container
    // (e.g. one wrapping GPS5/GPS9/DVNM) is NOT recursed, so exifast does not
    // emit highest-priority GoPro GPS/camera tags that bundled ExifTool would
    // not. (The GPS5/GPS9/GLPI/GPRI/KBAT SubDirectories are NOT `fmt \0`
    // containers — they carry a numeric `fmt` and are decoded as scalar
    // records in `emit_tag`, so they are unaffected by this gate.)
    if fmt == 0 {
      if !is_known_container(tag) {
        // Unknown `fmt=0` container — skipped in default mode
        // (`next unless $unknown`). The walk still advances past it (the
        // loop computes the next record from the header, not from
        // recursion), so siblings are unaffected.
        return;
      }
      // `DEVC` / `STRM` — a known recursable GPMF container.
      let mut child = Walker {
        out: self.out,
        type_str: None,
        scal: None,
        unit: None,
      };
      // The top-level record already counts as "recognized"; a child
      // container's own recognition flag is not separately threaded.
      let _ = child.walk(payload);
      return;
    }
    // Save TYPE / UNIT / SCAL for later tags in this container
    // (GoPro.pm:872-874).
    match tag {
      b"TYPE" => {
        self.type_str = Some(payload.to_vec());
      }
      b"UNIT" | b"SIUN" => {
        // Parse the unit record into per-element strings the way ExifTool reads
        // it (GoPro.pm:864-867): a `c` record with count>1 && len>1 unpacks as a
        // LIST of `len`-wide NUL-trimmed strings; otherwise it is one string
        // (which `%addUnits` later treats as a single-element unit list).
        self.unit = Some(read_unit_strings(fmt, len, count, payload));
      }
      b"SCAL" => {
        // SCAL values are scalar `int*` or `float` types — read each
        // element as f64. ExifTool reads them via ReadValue($fmt) and
        // joins with a space (GoPro.pm:869).
        self.scal = Some(read_scalar_vec(fmt, len, count, payload));
      }
      _ => {}
    }
    // Per-tag emission into the typed surface. Faithful: scaling is
    // applied via `ScaleValues` to the last container tag (GoPro.pm:884
    // `if $scal and $tag ne 'SCAL' and $pos + $size + 3 >= $dirEnd`).
    // `apply_scal` mirrors that full guard: a SCAL vector is present, the tag
    // is not SCAL itself, AND this record is the last in its container. Our
    // typed surface targets the GPS family; for those tags scaling is applied
    // at the dedicated decoder below only when `apply_scal` holds.
    let apply_scal = self.scal.is_some() && tag != b"SCAL" && is_last_in_container;
    self.emit_tag(tag, fmt, len, count, payload, apply_scal);
  }

  /// Dispatch a non-container scalar record into the typed `GoProMeta`.
  /// This is the data-extraction side of GoPro.pm:867-869 +
  /// 884-896 (ScaleValues + HandleTag). Only the tags the typed surface
  /// stores are decoded; the rest are visited (so containers recurse) but
  /// their values are dropped.
  ///
  /// `apply_scal` is the fully-evaluated GoPro.pm:884 guard (a SCAL vector is
  /// saved, this tag is not SCAL, and this record is the last in its
  /// container). The GPS5/GPS9 decoders divide by SCAL only when it holds —
  /// otherwise they emit the RAW int32s values, matching ExifTool, which
  /// scales only the last tag in a container.
  fn emit_tag(
    &mut self,
    tag: &[u8],
    fmt: u8,
    len: usize,
    count: usize,
    payload: &[u8],
    apply_scal: bool,
  ) {
    match tag {
      b"DVNM" => {
        // GoPro.pm:170-172 — `DeviceName` (`c` ASCII), trim trailing NULs. A
        // non-zero-size all-NUL payload NUL-trims to "" and is still
        // `HandleTag`-emitted (GoPro.pm:845 skips only `$size == 0`, which the
        // `payload.is_empty()` guard in `visit` already mirrors), so map an
        // empty `read_ascii` to `Some("")` rather than dropping the tag — and a
        // later duplicate DVNM whose value is "" wins last (typed setter
        // overwrites; the recorded device position is kept first).
        let s = read_ascii(payload).unwrap_or_default();
        self.out.set_device_name(Some(SmolStr::from(s)));
        self.out.record_identity(GoProIdentity::DeviceName);
      }
      b"MINF" => {
        // GoPro.pm:286-290 — `Model`, ASCII `c`. Empty-string-emitting +
        // last-wins like `DVNM` above.
        let s = read_ascii(payload).unwrap_or_default();
        self.out.set_model(Some(SmolStr::from(s)));
        self.out.record_identity(GoProIdentity::Model);
      }
      b"CASN" => {
        // GoPro.pm:121 — `CameraSerialNumber`, ASCII `c`. Empty-string-emitting
        // + last-wins like `DVNM` above.
        let s = read_ascii(payload).unwrap_or_default();
        self.out.set_camera_serial_number(Some(SmolStr::from(s)));
        self.out.record_identity(GoProIdentity::CameraSerialNumber);
      }
      b"FMWR" => {
        // GoPro.pm:195 — `FirmwareVersion`, ASCII `c`. Empty-string-emitting +
        // last-wins like `DVNM` above.
        let s = read_ascii(payload).unwrap_or_default();
        self.out.set_firmware_version(Some(SmolStr::from(s)));
        self.out.record_identity(GoProIdentity::FirmwareVersion);
      }
      b"MUID" => {
        // GoPro.pm:456-462 — `MediaUniqueID`. The "forum12825" entry defines
        // ONLY a PrintConv: the RAW (ValueConv) value is the space-joined
        // `count` × `u32` list that ExifTool's `ReadValue(..., 'L', ...)`
        // produces (GPMF reads big-endian — the QuickTime outer-call default,
        // GoPro.pm:869, no `SetByteOrder` override); the PrintConv then
        // hex-renders each element (`sprintf('%.8x',$_) foreach @a;
        // join('')`). Store the RAW space-joined decimal list here so `-n`
        // matches bundled ExifTool; the hex string is built at emission in
        // PrintConv mode ([`crate::formats::quicktime`]'s `media_uid_value`).
        //
        // FLAT list, not count×len stride: ExifTool reads the whole record via
        // `ReadValue($dataPt, $pos, 'L', undef, $size)` with `$size = len*count`
        // (GoPro.pm:837/869) → `size/4` u32s at stride 4, regardless of `len`.
        // This is byte-identical to the common `len=4` encoding and also handles
        // a single-structure `len=N*4, count=1` packing. The trailing `<4`-byte
        // run (if any) is not a u32 and is dropped by the checked `be_u32`.
        let _ = (len, count);
        let mut s = String::new();
        let mut off = 0usize;
        while let Some(v) = be_u32(payload, off) {
          if !s.is_empty() {
            s.push(' ');
          }
          s.push_str(&format!("{v}"));
          off += 4;
        }
        if !s.is_empty() {
          self.out.set_media_uid(Some(SmolStr::from(s)));
          self.out.record_identity(GoProIdentity::MediaUniqueID);
        }
      }
      b"GPSU" => {
        // GoPro.pm:242-248 — `GPSDateTime`. Hero5 wrote this as `c`
        // (ASCII), Hero6+ as `U` (16-byte date). Both decode the same
        // YYMMDDhhmmss[.fff] → `20YY:MM:DD HH:MM:` shape via the regex
        // substitution.
        let s = if fmt == 0x55 {
          read_utc_date(payload)
        } else {
          read_ascii(payload)
        };
        if let Some(raw) = s {
          self
            .out
            .set_gps_date_time(Some(SmolStr::from(convert_gpsu(&raw))));
          self.out.record_scalar(GoProScalar::GpsDateTime);
        }
      }
      b"GPSF" => {
        // GoPro.pm:230-236 — `GPSMeasureMode`, fmt `L` u32. The PrintConv
        // maps 2 → '2-Dimensional Measurement', 3 → '3-Dimensional
        // Measurement'; the typed surface stores the raw numeric.
        if let Some(v) = be_u32(payload, 0) {
          self.out.set_gps_measure_mode(Some(v));
          self.out.record_scalar(GoProScalar::GpsMeasureMode);
        }
      }
      b"GPSP" => {
        // GoPro.pm:237-241 — `GPSHPositioningError` — int16u in cm, the
        // `ValueConv` is `$val / 100` ⇒ metres.
        if let Some(v) = be_u16(payload, 0) {
          self
            .out
            .set_gps_h_positioning_error_m(Some(f64::from(v) / 100.0));
          self.out.record_scalar(GoProScalar::GpsHPositioningError);
        }
      }
      b"GPSA" => {
        // GoPro.pm:472 — `GPSAltitudeSystem` (4-char ID, e.g. 'MSLV').
        if let Some(s) = read_ascii(payload) {
          self.out.set_gps_altitude_system(Some(SmolStr::from(s)));
          self.out.record_scalar(GoProScalar::GpsAltitudeSystem);
        }
      }
      b"GPS5" => {
        // GoPro.pm:214-221 — `GPS5` SubDirectory dispatch into
        // `Image::ExifTool::GoPro::GPS5`. The dispatched table's
        // `PROCESS_PROC => &ProcessString` (GoPro.pm:488-489, 749-777)
        // splits the multi-row int32s[5] payload into one `Doc<N>` per
        // row — exifast emits one `GoProGpsSample` per row, with `SCAL`
        // already applied (faithful: ExifTool's `ScaleValues`
        // GoPro.pm:884 fires before HandleTag dispatches the
        // subdirectory; the dispatched table receives space-joined
        // strings of post-`SCAL` values) — but ONLY when GPS5 is the last
        // tag in its container (`apply_scal`); otherwise the values stay
        // RAW, matching ExifTool.
        self.emit_gps5(fmt, len, count, payload, apply_scal);
      }
      b"GPS9" => {
        // GoPro.pm:222-229 — `GPS9` SubDirectory dispatch. Same shape as
        // GPS5 plus the per-sample days/seconds/DOP/fix columns. SCAL is
        // applied only when GPS9 is the last tag in its container
        // (`apply_scal`), per GoPro.pm:884.
        self.emit_gps9(fmt, len, count, payload, apply_scal);
      }
      b"SYST" => {
        // GoPro.pm:390-405 — `SystemTime` (Karma). A complex `?` record with
        // `TYPE=JJ` (two int64u columns) and `SCAL=1000000 1000`. Its `RawConv`
        // pushes each two-element row `(systime_s, unix_s)` onto the file-global
        // `SystemTimeList`, later consumed by the `GLPI` `GPSDateTime`
        // `ConvertSystemTime` lookup. Decoded via the same complex-`?` path as
        // GPS9; SCAL applies only when SYST is the last tag in its container.
        self.accumulate_syst(fmt, len, count, payload, apply_scal);
      }
      b"GLPI" => {
        // GoPro.pm:197-204 — `GPSPos` (Karma). A complex `?` record decoded
        // per the preceding `TYPE` (`LllllsssS`); the resolved columns map by
        // position to `%GoPro::GLPI` (GoPro.pm:598-626). SCAL applies only when
        // GLPI is the last tag in its container, per GoPro.pm:884.
        self.emit_glpi(fmt, len, count, payload, apply_scal);
      }
      b"KBAT" => {
        // GoPro.pm:264-270 — `BatteryStatus` (Karma). A complex `?` record
        // decoded per the preceding `TYPE` (`lLlsSSSSSSSBBBb`); the resolved
        // columns map by position to `%GoPro::KBAT` (GoPro.pm:628-649). SCAL
        // applies only when KBAT is the last tag in its container.
        self.emit_kbat(fmt, len, count, payload, apply_scal);
      }
      _ => {
        // Every OTHER tag. ExifTool's `HandleTag` emits EVERY tag that resolves
        // to a default-visible `%GoPro::GPMF` entry (GoPro.pm:885); a tag NOT in
        // the table is `next unless $unknown` — SKIPPED in default `-ee` mode
        // (GoPro.pm:876-877). So: a default-visible non-typed tag is decoded
        // into the table-driven [`GoProTag`] surface; an unknown / `Unknown`=>1
        // / `Hidden`=>1 tag (and the sibling-state tags TYPE/SCAL/UNIT/SIUN) is
        // dropped exactly as ExifTool drops it.
        if let Some((name, conv)) = generic_tag_def(tag) {
          self.emit_generic(name, conv, fmt, len, count, payload, apply_scal);
        }
      }
    }
  }

  /// Decode a default-visible non-typed `%GoPro::GPMF` tag into a table-driven
  /// [`GoProTag`] — the faithful `ReadValue` + `ScaleValues` + per-tag conv path
  /// of GoPro.pm:846-896 for the ~95 tags the typed surface does not model.
  ///
  /// The DECODE is format-driven (the KLV `fmt`), exactly like ExifTool:
  ///  - `fmt == 0x3f` (complex `?`) with a preceding `TYPE` → one space-joined
  ///    post-`ScaleValues` string per row (GoPro.pm:848-863) ⇒
  ///    [`GoProTagValue::Rows`]; a single row is a scalar string, several rows a
  ///    JSON array (`$val = @v > 1 ? \@v : $v[0]`).
  ///  - a `string` (`c`) / `undef` (`F`/`G`/`U`) format → the NUL-trimmed ASCII
  ///    string (GoPro.pm:846/869, ReadValue 'string'/'undef') ⇒
  ///    [`GoProTagValue::Str`]. (A multi-element `undef`/`string` list,
  ///    GoPro.pm:864-867, is uncommon for these default tags and collapses to
  ///    the leading string here — the typed surface targets the scalar form.)
  ///  - a numeric format → a FLAT `ReadValue` list (GoPro.pm:869), `ScaleValues`
  ///    applied per COLUMN (`i % SCAL.len()`) when this is the last tag in its
  ///    container (`apply_scal`, GoPro.pm:884); one element ⇒
  ///    [`GoProTagValue::Num`], several ⇒ [`GoProTagValue::NumList`].
  ///
  /// The per-tag `ValueConv`/`RawConv` whose result is a scalar (STMP `$val/1e6`,
  /// CDAT `ConvertUnixTime`, RMRK Latin decode) is folded in HERE so the stored
  /// value is already the `-n` value; the `-j` PrintConv (carried by `conv`) is
  /// applied at emission.
  #[allow(clippy::too_many_arguments)]
  fn emit_generic(
    &mut self,
    name: &'static str,
    conv: GoProConv,
    fmt: u8,
    len: usize,
    count: usize,
    payload: &[u8],
    apply_scal: bool,
  ) {
    // ValueConv-only tags whose conversion yields a scalar string/number are
    // folded at decode (the table marks them `Plain`; their `-n` == `-j`).
    match name {
      "TimeStamp" => {
        // STMP `ValueConv => '$val / 1e6'` (GoPro.pm:377-380). fmt is `J`
        // (int64u) in practice; read the first scalar. `ScaleValues`
        // (GoPro.pm:884) divides by SCAL[0] FIRST when STMP is the last tag in
        // its container (the ValueConv runs on the scaled value); in real files
        // STMP carries no SCAL so this is the identity.
        if let Some(v) = read_one_f64(fmt, payload, 0) {
          let scaled = self.scale_scalar(v, apply_scal);
          self.out.push_generic_tag(GoProTag::new(
            name.into(),
            GoProTagValue::Num(scaled / 1e6),
            conv,
          ));
        }
        return;
      }
      "CreationDate" => {
        // CDAT `RawConv => 'ConvertUnixTime($val)'` (GoPro.pm:122-127). fmt is
        // `L` (int32u Unix epoch); render as the EXIF date string (no forced
        // millis), matching `ConvertUnixTime($val)` (2-arg form). `ScaleValues`
        // applies first when last-in-container (identity in real files).
        if let Some(v) = read_one_f64(fmt, payload, 0)
          && let Some(dt) = unix_to_iso_no_millis(self.scale_scalar(v, apply_scal))
        {
          self.out.push_generic_tag(GoProTag::new(
            name.into(),
            GoProTagValue::Str(SmolStr::from(dt)),
            conv,
          ));
        }
        return;
      }
      "Comments" => {
        // RMRK `ValueConv => '$self->Decode($val, "Latin")'` (GoPro.pm:333-336)
        // — decode the Latin-1 (ISO-8859-1) payload to UTF-8.
        if let Some(s) = read_latin1(payload) {
          self.out.push_generic_tag(GoProTag::new(
            name.into(),
            GoProTagValue::Str(SmolStr::from(s)),
            conv,
          ));
        }
        return;
      }
      _ => {}
    }

    let value = self.decode_generic_value(fmt, len, count, payload, apply_scal);
    let Some(value) = value else { return };
    // GoPro.pm:845 `next unless $size or $verbose` skips ONLY a zero-SIZE
    // record (the `payload.is_empty()` guard in `visit` already mirrors that);
    // a non-zero-size `c`/`undef` record whose bytes are all NUL decodes to an
    // EMPTY STRING that ExifTool still `HandleTag`s (e.g. GoPro.jpg's
    // 8-NUL-byte `EXPT` ⇒ `GoPro:ExposureType = ""`). So an empty
    // [`GoProTagValue::Str`] MUST emit. Only a numeric/complex decode that
    // resolved ZERO elements ([`GoProTagValue::NumList`]/[`Rows`] empty —
    // a too-short payload that produced no `ReadValue` element) carries nothing
    // to emit and is dropped.
    if value.is_empty() && !matches!(value, GoProTagValue::Str(_)) {
      return;
    }
    // `%addUnits` (SCPR/SIMU) carries the captured per-element units so the
    // emission can interleave them in PrintConv mode (GoPro.pm:727-743).
    let tag = if matches!(conv, GoProConv::AddUnits) {
      let units = self.unit.clone().unwrap_or_default();
      GoProTag::with_units(name.into(), value, units)
    } else {
      GoProTag::new(name.into(), value, conv)
    };
    self.out.push_generic_tag(tag);
  }

  /// The shared format-driven value decode for [`Self::emit_generic`] — see its
  /// doc for the cases. Returns `None` only for a format that yields nothing.
  fn decode_generic_value(
    &self,
    fmt: u8,
    len: usize,
    count: usize,
    payload: &[u8],
    apply_scal: bool,
  ) -> Option<GoProTagValue> {
    // Complex `?` (GoPro.pm:848-863) — one scaled space-joined string per row.
    if fmt == 0x3f {
      let type_bytes = self.type_str.as_deref()?;
      let columns = resolve_complex_columns(type_bytes, len);
      if columns.is_empty() {
        return None;
      }
      // SCAL applies (per column, modulo-folded) only when this is the last tag
      // in its container (GoPro.pm:884); otherwise identity.
      let identity = [1.0_f64];
      let scal: &[f64] = if apply_scal {
        self.scal.as_deref().unwrap_or(&identity)
      } else {
        &identity
      };
      let mut rows: Vec<SmolStr> = Vec::new();
      for row in 0..count {
        let cols = decode_complex_row_str(&columns, payload, row.saturating_mul(len), scal);
        // Perl `push @v, join ' ', @s if @s` — keep only the leading DEFINED run
        // of per-column strings (numeric → scaled `%g`, F/G/U → raw FourCC/uuid,
        // c → NUL-trimmed), joined with a single space. A row that decoded no
        // column (`@s` empty) is skipped.
        let defined: Vec<&str> = cols.iter().map_while(|c| c.as_deref()).collect();
        if !defined.is_empty() {
          rows.push(SmolStr::from(defined.join(" ")));
        }
      }
      return Some(GoProTagValue::Rows(rows));
    }
    // `string` (`c`) / `undef` (`F`/`G`/`U`) — the NUL-trimmed text. ExifTool's
    // `ReadValue($dataPt, $pos, 'string'/'undef', undef, $size)` (GoPro.pm:869)
    // returns the NUL-trimmed text, which is the EMPTY STRING for an all-NUL
    // (but non-zero-`$size`) record. `read_ascii` already returns `Some("")` for
    // that all-NUL case (the helper reserves `None` for the `$size == 0`
    // payload, which `visit` filters), so the empty `Str` emits — a non-zero
    // record MUST emit (GoPro.pm:845 only skips `$size == 0`), e.g. GoPro.jpg's
    // 8-NUL-byte `EXPT` ⇒ `GoPro:ExposureType = ""`.
    if matches!(fmt, 0x63 | 0x46 | 0x47 | 0x55) {
      let s = read_ascii(payload).unwrap_or_default();
      return Some(GoProTagValue::Str(SmolStr::from(s)));
    }
    // Numeric — a FLAT ReadValue list (GoPro.pm:869) with per-column SCAL.
    let flat = read_scalar_vec(fmt, len, count, payload);
    if flat.is_empty() {
      return None;
    }
    let identity = [1.0_f64];
    let scal: &[f64] = if apply_scal {
      self.scal.as_deref().unwrap_or(&identity)
    } else {
      &identity
    };
    // GoPro.pm:717 `$a[$_] /= $scl[$_ % @scl]` — divide each element by its
    // column-index SCAL factor.
    let scaled: Vec<f64> = flat
      .iter()
      .enumerate()
      .map(|(i, &v)| v / scal_at(scal, i))
      .collect();
    Some(if scaled.len() == 1 {
      // `.first()` keeps the access checked; the `len()==1` guard proves Some.
      GoProTagValue::Num(scaled.first().copied().unwrap_or(0.0))
    } else {
      GoProTagValue::NumList(scaled)
    })
  }

  /// Apply the column-0 `SCAL` factor to a single scalar (GoPro.pm:884
  /// `ScaleValues`) when this tag is the last in its container (`apply_scal`);
  /// otherwise the identity. Used by the single-scalar `ValueConv` tags
  /// (STMP / CDAT) whose conversion runs on the post-`ScaleValues` value.
  fn scale_scalar(&self, v: f64, apply_scal: bool) -> f64 {
    if apply_scal {
      match self.scal.as_deref() {
        Some(scal) => v / scal_at(scal, 0),
        None => v,
      }
    } else {
      v
    }
  }

  /// `GPS5` — a FLAT list of big-endian int32s chunked into rows of 5. SCAL is
  /// the 5-element scale vector `[10000000, 10000000, 1000, 1000, 100]`
  /// (GoPro.pm:218); each row is `(lat / SCAL[0], lon / SCAL[1], alt / SCAL[2],
  /// spd / SCAL[3], spd3d / SCAL[4])`.
  ///
  /// ENCODING-AGNOSTIC DECODE (GoPro.pm:214-221, 749-777, 865-871). GPS5 is the
  /// simple `l` (int32s) list format, NOT the complex `?` path. ExifTool reads
  /// the value via `ReadValue($dataPt, $pos, 'int32s', undef, $size)` where
  /// `$size = $len * $count` (GoPro.pm:837, 869); with `$count` undef ReadValue
  /// computes `int($size / 4)` int32s (ExifTool.pm:6296-6299) — a FLAT sequence
  /// of `len*count/4` values, AGNOSTIC to how the KLV header split `len` vs
  /// `count`. The dispatched `%GoPro::GPS5` SubDirectory's `ProcessString`
  /// (GoPro.pm:749-777) then cycles those flat values through the table's 5
  /// columns (indices 0..=4), starting a new sub-document every time the column
  /// index wraps — so every 5 consecutive int32s is one GPS row. A trailing
  /// partial group of `<5` int32s never completes a cycle, so it forms no Doc
  /// (GoPro.pm:763-768 bumps the sub-doc only on a full wrap) and is dropped.
  ///
  /// `ScaleValues` divides element `i` by `SCAL[i % len(SCAL)]` (GoPro.pm:717),
  /// i.e. by COLUMN index `i % 5` here. `apply_scal` is the GoPro.pm:884
  /// last-tag-in-container guard: when false (GPS5 is NOT the last tag in its
  /// container, or no SCAL was seen) the raw int32s pass through unscaled via an
  /// all-ones identity vector.
  ///
  /// `_len`/`_count`/`_fmt` are informational only — the decode reads purely
  /// from the payload bytes. The standard encoding (`len=20, count=N` → 5N
  /// int32s → N rows) is therefore byte-identical to the historical fixed-stride
  /// decode, AND a valid flat encoding (`len=4, count=5N`) yields the same N
  /// rows.
  fn emit_gps5(&mut self, _fmt: u8, _len: usize, _count: usize, payload: &[u8], apply_scal: bool) {
    // GoPro.pm:884 — divide by SCAL only when this is the last tag in the
    // container; otherwise the raw int32s pass through (identity vector).
    let scal: &[f64] = if apply_scal {
      self
        .scal
        .as_deref()
        .unwrap_or(&[10_000_000.0, 10_000_000.0, 1_000.0, 1_000.0, 100.0])
    } else {
      &[1.0, 1.0, 1.0, 1.0, 1.0]
    };
    // Read the WHOLE payload as a flat sequence of big-endian int32s; the count
    // of values is `payload.len() / 4` (equivalently `len*count/4` for the run
    // ProcessGoPro passes in), independent of any per-element stride. A trailing
    // run of `<4` bytes is not an int32 and is ignored.
    let mut flat = Vec::with_capacity(payload.len() / 4);
    let mut off = 0usize;
    while let Some(v) = be_i32(payload, off) {
      flat.push(v);
      off += 4;
    }
    // Chunk the flat int32 list into rows of 5 (lat, lon, alt, 2D-speed,
    // 3D-speed). `chunks_exact(5)` drops the trailing partial group of `<5`
    // values — ExifTool emits a Doc only for a complete 5-column cycle
    // (GoPro.pm:763-768).
    for chunk in flat.chunks_exact(5) {
      // `chunks_exact` yields exactly-5-element slices; map each by COLUMN index
      // `i % 5` through SCAL (GoPro.pm:717). The `.get()` reads keep the access
      // checked (the file-level indexing deny is active).
      let col = |i: usize| chunk.get(i).map(|&v| f64::from(v) / scal_at(scal, i));
      let mut s = GoProGpsSample::new();
      s.set_latitude(col(0))
        .set_longitude(col(1))
        .set_altitude_m(col(2))
        .set_speed_2d_mps(col(3))
        .set_speed_3d_mps(col(4));
      self.out.push_gps_sample(s);
    }
  }

  /// `GPS9` — multi-row complex `?` record (fmt `0x3f`) whose per-row column
  /// layout is described by the PRECEDING `TYPE` record (GoPro.pm:848-863),
  /// NOT a hardcoded shape. The standard Hero13 `TYPE` is `lllllllSS`
  /// (7 int32s + 2 int16u = 7*4 + 2*2 = 32 bytes per row, GoPro.pm:225); the
  /// resolved columns map by POSITION to the `%GoPro::GPS9` table indices
  /// (GoPro.pm:516-563): 0 lat, 1 lon, 2 alt, 3 2D-speed, 4 3D-speed,
  /// 5 days-since-2000, 6 seconds, 7 DOP, 8 measure-mode. SCAL is the
  /// 9-element scale vector `[1e7, 1e7, 1000, 1000, 100, 1, 1000, 100, 1]`
  /// (GoPro.pm:226).
  ///
  /// FAITHFULNESS (GoPro.pm:848-863): the columns are derived from `TYPE` via
  /// [`resolve_complex_columns`], which mirrors the Perl inner type-walk
  /// including its `last` fallback — an absent / short / format-incompatible
  /// `TYPE` yields FEWER columns (or none), so the corresponding GPS9 fields
  /// stay unset rather than being force-decoded from a fixed offset. A row
  /// that resolves zero columns produces no sample (Perl `push @v, … if @s`
  /// / `if ($i)`, GoPro.pm:861, 769). With the standard `lllllllSS` TYPE the
  /// resolved offsets are exactly `0,4,8,12,16,20,24,28,30`, so the decoded
  /// values are byte-identical to the previous fixed-layout decode.
  fn emit_gps9(&mut self, _fmt: u8, len: usize, count: usize, payload: &[u8], apply_scal: bool) {
    // GoPro.pm:848 `if ($fmt == 0x3f and defined $type)` — the complex decode
    // only runs when a TYPE record precedes GPS9. Without it (or when the
    // first TYPE byte is already an invalid code) no numeric column list is
    // produced, so no GPS9 sample is emitted (the typed surface targets the
    // structured columns; the raw-`undef` fallback carries no usable
    // lat/lon).
    let Some(type_bytes) = self.type_str.as_deref() else {
      return;
    };
    let columns = resolve_complex_columns(type_bytes, len);
    if columns.is_empty() {
      return;
    }
    // GoPro.pm:884 — divide by SCAL only when GPS9 is the last tag in the
    // container; otherwise the raw values pass through (identity vector).
    // See `emit_gps5` for the same last-tag-in-container guard.
    let scal: &[f64] = if apply_scal {
      self.scal.as_deref().unwrap_or(&[
        10_000_000.0,
        10_000_000.0,
        1_000.0,
        1_000.0,
        100.0,
        1.0,
        1_000.0,
        100.0,
        1.0,
      ])
    } else {
      &[1.0; 9]
    };
    for row in 0..count {
      let row_off = row * len;
      // Per-column scaled f64 in TYPE/table order. `read_one_f64` returns
      // `None` for a non-numeric column code or an out-of-range read — Perl's
      // `last unless defined $s` (GoPro.pm:858) stops the row there, so a
      // `None` column truncates the rest of the row.
      let mut decoded: [Option<f64>; 9] = [None; 9];
      let mut any = false;
      for (idx, col) in columns.iter().enumerate() {
        // Only the first 9 columns have a typed GPS9 slot; ExifTool's GPS9
        // table defines indices 0..=8, so a longer TYPE's extra columns are
        // visited (consume offset) but carry no typed field.
        let Some(raw) = read_one_f64(col.code, payload, row_off + col.offset) else {
          // Perl `last unless defined $s` — stop reading this row's columns.
          break;
        };
        any = true;
        if let Some(slot) = decoded.get_mut(idx) {
          // GoPro.pm:705-721 `ScaleValues` divides every column by
          // `$scl[$_ % @scl]` as an f64.
          *slot = Some(raw / scal_at(scal, idx));
        }
      }
      // A row with no decoded column produces no Doc (GoPro.pm:861, 769).
      if !any {
        continue;
      }
      let col = |i: usize| decoded.get(i).copied().flatten();
      // GPS9 columns 5+6 are per-sample DAYS (since 2000-01-01) + SECONDS of
      // date/time, post-`SCAL`. ExifTool synthesizes GPSDateTime via
      // `ConvertUnixTime(($days + 10957) * 86400 + $secs, undef, 3)`
      // (GoPro.pm:543-554); 10957 days from Jan 1 1970 to Jan 1 2000.
      let date_time = match (col(5), col(6)) {
        (Some(d), Some(s)) => unix_to_iso((d + 10957.0) * 86400.0 + s),
        _ => None,
      };
      // GPSMeasureMode (col 8). ExifTool's `ScaleValues` divides this column
      // too (as f64); the col-8 PrintConv then maps it to 2-D/3-D
      // (GoPro.pm:556-562). The default SCAL[8] is `1` so the real value is an
      // exact integer, but a file-controlled fractional SCAL must NOT cause an
      // integer divide-by-zero or truncation. Adopt the integer mode code only
      // when the (already-scaled) value is an exact, in-range, non-negative
      // integer; a fractional / out-of-range / `None` result is skipped.
      let mode = col(8).and_then(|scaled| {
        (scaled.is_finite()
          && scaled >= 0.0
          && scaled <= f64::from(u32::MAX)
          && scaled.fract() == 0.0)
          .then_some(scaled as u32)
      });
      let mut s = GoProGpsSample::new();
      s.set_latitude(col(0))
        .set_longitude(col(1))
        .set_altitude_m(col(2))
        .set_speed_2d_mps(col(3))
        .set_speed_3d_mps(col(4))
        .set_date_time(date_time.map(SmolStr::from))
        .set_dop(col(7))
        .set_measure_mode(mode);
      self.out.push_gps_sample(s);
    }
  }

  /// `SYST` (`SystemTime`, GoPro.pm:390-405) — emit the `SystemTime` default
  /// tag AND accumulate the file-global `(system_time_s, unix_time_s)`
  /// calibration list. SYST is a complex `?` record with `TYPE=JJ` (two int64u
  /// columns) and `SCAL=1000000 1000`.
  ///
  /// Faithful to ExifTool's two-step decode: ProcessGoPro builds one
  /// space-joined string per non-empty row, then `$val = @v > 1 ? \@v : $v[0]`
  /// (GoPro.pm:850-863) — a SINGLE non-empty row yields a SCALAR string,
  /// multiple rows yield an ARRAYREF. `ScaleValues` then scales each column in
  /// place (GoPro.pm:884, 705-721). HandleTag dispatches the scaled `$val`:
  ///
  ///  - `SystemTime` (R6-B) is the DISPLAY of that scaled `$val` — the scalar
  ///    string for one row, or the rows joined with `", "` for several. It is a
  ///    DEFAULT tag (no `Unknown`/`Hidden`), emitted by `exiftool -ee`.
  ///  - The `RawConv` (GoPro.pm:396-404) splits the scaled `$val` and pushes a
  ///    calibration pair ONLY when `@v == 2`. The arrayref of a multi-row record
  ///    stringifies as `ARRAY(0x…)` and does NOT split into two tokens, so a
  ///    `count > 1` record is NEVER calibration (R6-A). The gate is therefore:
  ///    exactly ONE non-empty row whose scaled column run is EXACTLY two values.
  ///
  /// SCAL applies only when SYST is the last tag in its container
  /// (`apply_scal`, GoPro.pm:884); otherwise the raw int64u pass through.
  fn accumulate_syst(
    &mut self,
    _fmt: u8,
    len: usize,
    count: usize,
    payload: &[u8],
    apply_scal: bool,
  ) {
    let Some(type_bytes) = self.type_str.as_deref() else {
      return;
    };
    let columns = resolve_complex_columns(type_bytes, len);
    if columns.is_empty() {
      return;
    }
    // SCAL fold: SYST's canonical SCAL is `[1000000, 1000]`. When SYST is not
    // the last tag in its container (or no SCAL was seen) the raw int64u pass
    // through (identity), mirroring GoPro.pm:884.
    let identity = [1.0_f64; 2];
    let default_scal = [1_000_000.0_f64, 1_000.0];
    let scal: &[f64] = if apply_scal {
      self.scal.as_deref().unwrap_or(&default_scal)
    } else {
      &identity
    };
    // GoPro.pm:850-862 — build the leading DEFINED column run of each row (Perl
    // `last unless defined $s` truncates `@s` at the first undef), keep it only
    // when non-empty (`push @v, … if @s`), and render it as the space-joined
    // scaled string ExifTool would store (`%.15g` per column, [`format_g`]).
    let mut rows: Vec<Vec<f64>> = Vec::new();
    for row in 0..count {
      let cols = decode_complex_row(&columns, payload, row.saturating_mul(len), scal);
      let defined: Vec<f64> = cols.iter().map_while(|c| *c).collect();
      if !defined.is_empty() {
        rows.push(defined);
      }
    }
    if rows.is_empty() {
      return;
    }
    // `$val` display string: each row's scaled `%.15g` space-join ([`join_g`]),
    // the rows themselves joined with `", "` (ExifTool's default array→scalar
    // rendering, oracle-confirmed).
    let display = rows
      .iter()
      .map(|r| join_g(r))
      .collect::<Vec<_>>()
      .join(", ");
    self.out.set_system_time(SmolStr::from(display));
    // Record the main-group walk position so `SystemTime` emits at its KLV
    // position interleaved with the device/settings/GPS-scalar tags. First-set
    // wins (idempotent), matching `set_system_time`'s first-record semantics.
    self.out.record_scalar(GoProScalar::SystemTime);
    // GoPro.pm:863 + 396-404: only `$val = $v[0]` (exactly one non-empty row)
    // that splits to EXACTLY two tokens is a calibration pair.
    if let [only] = rows.as_slice()
      && let [system_s, unix_s] = only.as_slice()
    {
      self.out.push_system_time(*system_s, *unix_s);
    }
  }

  /// `GLPI` (`GPSPos`, GoPro.pm:197-204) — multi-row complex `?` record whose
  /// per-row column layout is the preceding `TYPE` (`LllllsssS`). The resolved
  /// columns map by POSITION to `%GoPro::GLPI` (GoPro.pm:598-626): 0
  /// `GPSDateTime` (via `ConvertSystemTime`), 1 `GPSLatitude`, 2
  /// `GPSLongitude`, 3 `GPSAltitude`, 4 `GLPI_Unknown4` (dropped), 5
  /// `GPSSpeedX`, 6 `GPSSpeedY`, 7 `GPSSpeedZ`, 8 `GPSTrack`. SCAL =
  /// `[1000, 1e7, 1e7, 1000, 1000, 100, 100, 100, 100]` (GoPro.pm:201).
  fn emit_glpi(&mut self, _fmt: u8, len: usize, count: usize, payload: &[u8], apply_scal: bool) {
    let Some(type_bytes) = self.type_str.as_deref() else {
      return;
    };
    let columns = resolve_complex_columns(type_bytes, len);
    if columns.is_empty() {
      return;
    }
    let identity = [1.0_f64; 9];
    let default_scal = [
      1_000.0_f64,
      10_000_000.0,
      10_000_000.0,
      1_000.0,
      1_000.0,
      100.0,
      100.0,
      100.0,
      100.0,
    ];
    let scal: &[f64] = if apply_scal {
      self.scal.as_deref().unwrap_or(&default_scal)
    } else {
      &identity
    };
    for row in 0..count {
      let cols = decode_complex_row(&columns, payload, row.saturating_mul(len), scal);
      // A row with no decoded column produces no Doc (GoPro.pm:861, 769).
      if cols.iter().all(Option::is_none) {
        continue;
      }
      let col = |i: usize| cols.get(i).copied().flatten();
      // col 0 → GPSDateTime via ConvertSystemTime (GoPro.pm:605, 677-702),
      // resolved against the file-global SYST calibration list captured so far.
      let date_time =
        col(0).and_then(|systime| convert_system_time(self.out.system_time_list(), systime));
      let mut s = GoProGlpiSample::new();
      s.set_date_time(date_time.map(SmolStr::from))
        .set_latitude(col(1))
        .set_longitude(col(2))
        .set_altitude_m(col(3))
        // col 4 = GLPI_Unknown4 (Unknown/Hidden) — not stored.
        .set_speed_x_mps(col(5))
        .set_speed_y_mps(col(6))
        .set_speed_z_mps(col(7))
        .set_track_deg(col(8));
      self.out.push_glpi_sample(s);
    }
  }

  /// `KBAT` (`BatteryStatus`, GoPro.pm:264-270) — multi-row complex `?` record
  /// whose per-row column layout is the preceding `TYPE` (`lLlsSSSSSSSBBBb`).
  /// The resolved columns map by POSITION to `%GoPro::KBAT` (GoPro.pm:628-649):
  /// 0 `BatteryCurrent`, 1 `BatteryCapacity`, 2 `KBAT_Unknown2` (dropped), 3
  /// `BatteryTemperature`, 4-7 `BatteryVoltage1..4`, 8 `BatteryTime`, 9
  /// `KBAT_Unknown9` (dropped), 10-13 `KBAT_Unknown10..13` (dropped), 14
  /// `BatteryLevel`. SCAL =
  /// `[1000, 1000, 0.00999999977648258, 100, 1000, 1000, 1000, 1000,`
  /// `0.0166666675359011, 1, 1, 1, 1, 1, 1]` (GoPro.pm:268).
  fn emit_kbat(&mut self, _fmt: u8, len: usize, count: usize, payload: &[u8], apply_scal: bool) {
    let Some(type_bytes) = self.type_str.as_deref() else {
      return;
    };
    let columns = resolve_complex_columns(type_bytes, len);
    if columns.is_empty() {
      return;
    }
    let identity = [1.0_f64; 15];
    let default_scal = [
      1_000.0_f64,
      1_000.0,
      0.009_999_999_776_482_58,
      100.0,
      1_000.0,
      1_000.0,
      1_000.0,
      1_000.0,
      0.016_666_667_535_901_1,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
    ];
    let scal: &[f64] = if apply_scal {
      self.scal.as_deref().unwrap_or(&default_scal)
    } else {
      &identity
    };
    for row in 0..count {
      let cols = decode_complex_row(&columns, payload, row.saturating_mul(len), scal);
      if cols.iter().all(Option::is_none) {
        continue;
      }
      let col = |i: usize| cols.get(i).copied().flatten();
      let mut k = GoProKbat::new();
      k.set_current_a(col(0))
        .set_capacity_ah(col(1))
        // col 2 = KBAT_Unknown2 (J, Unknown/Hidden) — not stored.
        .set_temperature_c(col(3))
        .set_voltage1_v(col(4))
        .set_voltage2_v(col(5))
        .set_voltage3_v(col(6))
        .set_voltage4_v(col(7))
        .set_time_s(col(8))
        // cols 9-13 = KBAT_Unknown* (Unknown/Hidden) — not stored.
        .set_level_pct(col(14));
      self.out.push_kbat_record(k);
    }
  }
}

/// Read ONE scalar of GPMF format code `code` from `payload` at byte
/// offset `off`, as `f64`. Mirrors ExifTool's `ReadValue($dataPt, $off,
/// $format, undef, $size)` dispatch (GoPro.pm:869, 857) for the numeric
/// `%goProFmt` codes. Returns `None` when the code is not a numeric format
/// or the bytes are out of range (the checked-read short-circuit). The
/// `undef`-mapped codes (`F`/`G`/`U`/`?`) and `string` (`c`) have no f64
/// value and yield `None` here.
fn read_one_f64(code: u8, payload: &[u8], off: usize) -> Option<f64> {
  match code {
    0x62 => payload.get(off).map(|&b| f64::from(b as i8)), // 'b' int8s
    0x42 => payload.get(off).map(|&b| f64::from(b)),       // 'B' int8u
    0x73 => be_i16(payload, off).map(f64::from),           // 's' int16s
    0x53 => be_u16(payload, off).map(f64::from),           // 'S' int16u
    0x6c => be_i32(payload, off).map(f64::from),           // 'l' int32s
    0x4c => be_u32(payload, off).map(f64::from),           // 'L' int32u
    0x66 => be_f32(payload, off),                          // 'f' float
    0x64 => be_f64(payload, off),                          // 'd' double
    0x6a => be_u64(payload, off).map(|v| v as i64 as f64), // 'j' int64s
    0x4a => be_u64(payload, off).map(|v| v as f64),        // 'J' int64u
    0x71 => be_i32(payload, off).map(|v| f64::from(v) / 65_536.0), // 'q' fixed32s
    0x51 => be_u64(payload, off).map(|v| (v as i64 as f64) / 4_294_967_296.0), // 'Q' fixed64s
    _ => None,
  }
}

/// Byte size of GPMF format code `code` — ExifTool's `$goProSize{$b} ||
/// FormatSize($f)` (GoPro.pm:855, 51-55, 6210+). Returns `None` for a code
/// not in `%goProFmt` (mirroring `$f = $goProFmt{$b} or last`).
const fn go_pro_fmt_size(code: u8) -> Option<usize> {
  match code {
    0x62 | 0x42 | 0x63 | 0x3f => Some(1), // int8s/int8u/string/'?' undef (FormatSize 1)
    0x73 | 0x53 => Some(2),               // int16s/int16u
    0x6c | 0x4c | 0x66 | 0x71 => Some(4), // int32s/int32u/float/fixed32s
    0x64 | 0x6a | 0x4a | 0x51 => Some(8), // double/int64s/int64u/fixed64s
    0x46 => Some(4),                      // 'F' undef[4] (goProSize override)
    0x47 | 0x55 => Some(16),              // 'G'/'U' undef[16] (goProSize override)
    _ => None,
  }
}

/// Read a scalar record of `fmt`/`len`/`count` from `payload` as a FLAT list
/// of `f64`, faithfully mirroring `ReadValue($dataPt, $pos, $format, undef,
/// $size)` (GoPro.pm:869) where `$size = $len * $count` (GoPro.pm:837).
///
/// ExifTool's `ReadValue` reads `int($size / FormatSize($format))` elements at
/// a stride of one `FormatSize($format)` each — it does NOT step by the KLV
/// `len`. The element count is therefore `(len * count) / element_size(fmt)`,
/// read at `element_size(fmt)` stride from offset 0. This is byte-identical to
/// the common `len == element_size` encoding (e.g. SCAL `len=4, count=5` for a
/// `L`/`f` → 5 values) AND correctly handles a single-structure encoding (e.g.
/// SCAL `len=20, count=1` packing all five `L` factors into one 20-byte record
/// → still 5 values, not 1). All SCAL values in the bundled tables are `L`
/// (int32u) or `f` (float32); we still accept the full numeric set for forward
/// compatibility.
///
/// A code with no `%goProFmt` size (`go_pro_fmt_size` → `None`) yields an empty
/// list, matching ExifTool's `$format eq 'undef'` fall-through (a SCAL record
/// never carries a non-numeric format in practice). `read_one_f64`'s checked
/// `.get()` reads drop any element that would run past the payload end, so the
/// computed `n` is naturally clamped to the available bytes.
fn read_scalar_vec(fmt: u8, len: usize, count: usize, payload: &[u8]) -> Vec<f64> {
  let Some(elem) = go_pro_fmt_size(fmt) else {
    return Vec::new();
  };
  // `int($size / FormatSize($format))`, with `$size = len * count`. Clamp the
  // theoretical count to what the payload can actually supply so a truncated
  // record never inflates the element count.
  let n = (len.saturating_mul(count) / elem).min(payload.len() / elem);
  let mut out = Vec::with_capacity(n);
  for i in 0..n {
    if let Some(x) = read_one_f64(fmt, payload, i * elem) {
      out.push(x);
    }
  }
  out
}

/// One resolved column of a complex `?` (GoPro.pm:848-863) record's layout,
/// derived from the preceding `TYPE` payload: the format-code byte and its
/// byte offset WITHIN one row (`$p` in the Perl inner loop). The row stride
/// is the KLV header's `sample_size` (`$len`).
struct ComplexColumn {
  code: u8,
  offset: usize,
}

/// Resolve the per-row column layout of a complex `?` record from its
/// `TYPE` payload — a faithful port of the inner type-walk in
/// GoPro.pm:852-856:
///
/// ```text
/// for ($j=0, $p=0; $j<length($type); ++$j, $p+=$l) {
///     my $b = Get8u(\$type, $j);
///     my $f = $goProFmt{$b} or last;             # invalid code → stop
///     $l = $goProSize{$b} || FormatSize($f) or last;
///     last if $p + $l > $len;                    # column exceeds row → stop
///     …read column…
/// }
/// ```
///
/// Each TYPE byte is one column; the running offset `$p` accumulates each
/// column's size. The loop STOPS (Perl `last`) at the first byte that is
/// not a valid `%goProFmt` code, has zero size, or whose field would exceed
/// the row stride `len`. Columns resolved before that point are kept; this
/// is the GoPro.pm fallback for an absent / short / incompatible TYPE
/// (fewer columns ⇒ fewer decoded fields downstream). Returns the ordered
/// column list (possibly empty when `type` is empty or its first byte is
/// already invalid / overflows).
fn resolve_complex_columns(type_bytes: &[u8], len: usize) -> Vec<ComplexColumn> {
  let mut cols = Vec::new();
  let mut p = 0usize;
  for &code in type_bytes {
    // `$f = $goProFmt{$b} or last` + `$l = … or last`: an unknown code (or a
    // zero-size format) stops the walk.
    let Some(size) = go_pro_fmt_size(code) else {
      break;
    };
    // `last if $p + $l > $len`: a column that would spill past the per-row
    // stride stops the walk (the row is shorter than the TYPE describes).
    if p + size > len {
      break;
    }
    cols.push(ComplexColumn { code, offset: p });
    p += size;
  }
  cols
}

/// Decode ONE complex-`?` row into per-column scaled `f64` values, in `TYPE`
/// (and therefore table-index) order. `columns` is the resolved per-row layout
/// (from [`resolve_complex_columns`]); `row_off` is the byte offset of this
/// row within `payload`; `scal` is the per-column SCAL vector (modulo-folded
/// by [`scal_at`], GoPro.pm:717).
///
/// FAITHFUL TRUNCATION (GoPro.pm:857-861): a column whose format code is
/// non-numeric, or whose bytes are out of range, returns `None` from
/// [`read_one_f64`]; Perl's `last unless defined $s` stops reading the row at
/// that point, so every column from there on is left `None`. The returned
/// vector therefore has exactly `columns.len()` entries with a `Some` prefix
/// followed by a `None` tail once any column fails — letting the caller map
/// columns by index while honouring the early stop. (GPS9 inlines an
/// equivalent loop into a fixed `[Option<f64>; 9]`; this shared helper serves
/// the variable-width Karma records SYST / GLPI / KBAT.)
fn decode_complex_row(
  columns: &[ComplexColumn],
  payload: &[u8],
  row_off: usize,
  scal: &[f64],
) -> Vec<Option<f64>> {
  let mut out = Vec::with_capacity(columns.len());
  let mut stopped = false;
  for (idx, c) in columns.iter().enumerate() {
    if stopped {
      out.push(None);
      continue;
    }
    match read_one_f64(c.code, payload, row_off.saturating_add(c.offset)) {
      Some(raw) => out.push(Some(raw / scal_at(scal, idx))),
      None => {
        // Perl `last unless defined $s` — stop the row here; the rest stay None.
        stopped = true;
        out.push(None);
      }
    }
  }
  out
}

/// Decode ONE complex-`?` row into per-column FORMATTED-text values, in `TYPE`
/// (and therefore table-index) order — the GENERIC `?` path (GoPro.pm:848-863,
/// the `$fmt == 0x3f and defined $type` branch). Unlike [`decode_complex_row`]
/// (numeric-only, used by the typed Karma records) this honours EVERY
/// `%goProFmt` column type that `ReadValue` can return, so a mixed structure
/// like SCEN `TYPE=Ff` (a 4-byte FourCC + a float) or the GoPro.pm:414 example
/// `LLLllfFff` keeps its embedded string column instead of truncating the row.
///
/// Per ExifTool `ReadValue($dataPt, …, $f, undef, $l)` (GoPro.pm:857) where
/// `$l` is the column width from `%goProSize`/`FormatSize`:
/// - numeric code → the scaled value (`read_one_f64` ÷ [`scal_at`], GoPro.pm:717
///   `ScaleValues`), formatted with the SAME `%.15g` stringifier the all-numeric
///   rows use ([`format_g`]) so a scaled number renders byte-identically.
/// - `F`/`G`/`U` (0x46/0x47/0x55, `'undef'`) → the raw `$l` column bytes as a
///   string, NOT NUL-trimmed (ExifTool `undef` ReadValue = `substr`,
///   ExifTool.pm:6309). For the real default-visible case the `F` columns are
///   4-byte printable FourCCs (e.g. `SNOW`).
/// - `c` (0x63, `'string'`) → the `$l` (=1) column byte NUL-trimmed (ExifTool
///   `string` ReadValue applies `s/\0.*//s`, ExifTool.pm:6311).
///
/// FAITHFUL TRUNCATION (GoPro.pm:858 `last unless defined $s`): a column whose
/// bytes are genuinely out of range returns `None` and STOPS the row — every
/// later column is left `None`. (`resolve_complex_columns` already drops any
/// column that would spill past the row stride, so within a full-length row
/// every listed column has bytes; only a short payload trips the stop.) The
/// caller keeps the `Some` prefix and joins it with `' '` (`join ' ', @s`).
fn decode_complex_row_str(
  columns: &[ComplexColumn],
  payload: &[u8],
  row_off: usize,
  scal: &[f64],
) -> Vec<Option<SmolStr>> {
  let mut out = Vec::with_capacity(columns.len());
  let mut stopped = false;
  for (idx, c) in columns.iter().enumerate() {
    if stopped {
      out.push(None);
      continue;
    }
    let col_off = row_off.saturating_add(c.offset);
    let cell: Option<SmolStr> = match c.code {
      // `F`/`G`/`U` → `undef`: the raw column bytes verbatim (no NUL trim).
      0x46 | 0x47 | 0x55 => read_undef_column(c.code, payload, col_off),
      // `c` → `string`: the NUL-trimmed column byte(s).
      0x63 => read_string_column(c.code, payload, col_off),
      // numeric → scaled `%.15g`, mirroring the all-numeric row rendering.
      _ => read_one_f64(c.code, payload, col_off)
        .map(|raw| SmolStr::from(crate::value::format_g(raw / scal_at(scal, idx), 15))),
    };
    match cell {
      Some(s) => out.push(Some(s)),
      None => {
        // Perl `last unless defined $s` — stop the row; the rest stay None.
        stopped = true;
        out.push(None);
      }
    }
  }
  out
}

/// Read an `'undef'`-format complex column (`F`/`G`/`U`) of width
/// `go_pro_fmt_size(code)` at `off`, as a string of the raw bytes WITHOUT a NUL
/// trim — ExifTool `ReadValue` for `undef` is a bare `substr` (ExifTool.pm:6309).
/// Returns `None` when the column runs past the payload (Perl `last unless
/// defined $s`, i.e. ReadValue's `$count < 1 and return undef`). The raw bytes
/// are rendered UTF-8-lossy (real `F` FourCCs are ASCII).
fn read_undef_column(code: u8, payload: &[u8], off: usize) -> Option<SmolStr> {
  let width = go_pro_fmt_size(code)?;
  let slice = payload.get(off..off.checked_add(width)?)?;
  Some(SmolStr::from(String::from_utf8_lossy(slice)))
}

/// Read a `'string'`-format complex column (`c`) of width
/// `go_pro_fmt_size(code)` (=1) at `off`, NUL-trimmed — ExifTool `ReadValue` for
/// `string` applies `s/\0.*//s` after the `substr` (ExifTool.pm:6311). Returns
/// `None` only when the column is out of range (the read itself fails); a column
/// whose first byte is NUL yields an EMPTY string (a defined value Perl would
/// `push @s`), not `None`.
fn read_string_column(code: u8, payload: &[u8], off: usize) -> Option<SmolStr> {
  let width = go_pro_fmt_size(code)?;
  let slice = payload.get(off..off.checked_add(width)?)?;
  let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
  // `end <= slice.len()` by construction so the checked slice is always `Some`.
  let trimmed = slice.get(..end).unwrap_or(&[]);
  Some(SmolStr::from(String::from_utf8_lossy(trimmed)))
}

/// Pick a SCAL element with the modulo-fold ExifTool's `ScaleValues`
/// applies (GoPro.pm:717 `$a[$_] /= $scl[$_ % @scl]`). Defaults to `1.0`
/// when the SCAL vector is empty.
fn scal_at(scal: &[f64], i: usize) -> f64 {
  // `i % scal.len()` is provably in range for a non-empty `scal`; the checked
  // `.get(..)` form expresses that (and returns the empty-vector `1.0` default
  // in one shot).
  match scal.len() {
    0 => 1.0,
    n => scal.get(i % n).copied().unwrap_or(1.0),
  }
}

/// Read a NUL-terminated / NUL-padded ASCII string from a GPMF `c` (or
/// `F`/`G`/`U`) payload. Trims trailing NULs.
fn read_ascii(payload: &[u8]) -> Option<String> {
  // GoPro.pm:845 `next unless $size or $verbose` skips ONLY a zero-`$size`
  // record; `visit` already mirrors that (the `payload.is_empty()` guard). For
  // ANY non-zero-size payload ExifTool's `ReadValue('string')` returns the
  // NUL-trimmed bytes — which is the EMPTY STRING for an all-NUL (or
  // leading-NUL) payload, and ExifTool still `HandleTag`s it (oracle-confirmed:
  // an all-NUL RMRK/GPSU/GPSA emits `""`, and GoPro.jpg's 8-NUL `EXPT` emits
  // `ExposureType = ""`). So return `Some("")` for an all-NUL payload and
  // reserve `None` for a genuinely empty payload (the `$size == 0` case, never
  // reached through `visit`). This makes EVERY string tag — typed identity,
  // generic, RMRK→Comments, GPSU, GPSA — uniformly emit the empty string at the
  // helper, with no per-arm patching.
  if payload.is_empty() {
    return None;
  }
  let end = payload
    .iter()
    .position(|&b| b == 0)
    .unwrap_or(payload.len());
  // `end <= payload.len()` by construction (a found NUL index or the length),
  // so the checked slice is always `Some`.
  let slice = payload.get(..end)?;
  // Faithful: ExifTool's string ReadValue keeps non-ASCII as raw bytes;
  // the GoPro module then re-decodes via `Latin` for the RMRK/SIUN/UNIT
  // strings. The typed surface targets ASCII-only fields (model, serial,
  // firmware, GPSU, GPSA) — UTF-8-lossy is a safe rendering. An empty `slice`
  // (all-NUL payload) yields the empty string.
  Some(String::from_utf8_lossy(slice).into_owned())
}

/// `U` 16-byte UTC date payload (GoPro.pm:46, fmt `0x55`). Hero5+ writes
/// the literal ASCII string `YYMMDDhhmmss.fff` here; ExifTool's `undef`
/// ReadValue keeps the bytes verbatim. Returns the trimmed string.
fn read_utc_date(payload: &[u8]) -> Option<String> {
  // 16-byte slot — the trailing 0..N bytes may be NUL or '\0'-padded
  // sub-second fragments. Trim NULs and strip any trailing whitespace.
  read_ascii(payload)
}

/// `GPSU` PrintConv (GoPro.pm:246) —
/// `$val =~ s/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/20$1:$2:$3 $4:$5:/`.
/// I.e. the leading 10 digits `YYMMDDhhmm` become `20YY:MM:DD HH:MM:` and
/// the remaining tail (`ss[.fff]`) is preserved.
fn convert_gpsu(raw: &str) -> String {
  // Find the 10 leading digits. The `.get(..10)` (checked) replaces the
  // earlier `raw.len() < 10` guard + raw byte slice; a non-digit (or short)
  // prefix falls through to the verbatim value (faithful to the regex not
  // matching). Since the matched bytes are ASCII digits, every sub-slice below
  // lands on a char boundary, so the checked str slices are all `Some`.
  let digits_ok = raw
    .get(..10)
    .is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()));
  if !digits_ok {
    return raw.to_string();
  }
  let (Some(y), Some(m), Some(d), Some(h), Some(mn), Some(tail)) = (
    raw.get(0..2),
    raw.get(2..4),
    raw.get(4..6),
    raw.get(6..8),
    raw.get(8..10),
    raw.get(10..),
  ) else {
    return raw.to_string();
  };
  // Faithful: the regex replaces only the leading 10 digits with
  // `20YY:MM:DD HH:MM:` and preserves the tail (`ss[.fff]`) verbatim.
  // ExifTool's `PrintConv => '$self->ConvertDateTime($val)'` adds NO
  // timezone suffix by default (GoPro.pm:247) — do NOT append `Z`.
  format!("20{y}:{m}:{d} {h}:{mn}:{tail}")
}

/// `ConvertUnixTime($t, undef, 3)` — render a Unix epoch (with fractional
/// seconds) as `YYYY:MM:DD HH:MM:SS.sss` in UTC. The 3rd argument `3`
/// forces 3-digit milliseconds.
fn unix_to_iso(t: f64) -> Option<String> {
  // Reasonable range check — 1970..3000.
  if !t.is_finite() || !(0.0..=32_503_680_000.0).contains(&t) {
    return None;
  }
  let secs = t.trunc() as i64;
  let frac = t - t.trunc();
  let millis = (frac * 1000.0).round() as u32;
  // Civil date-time from epoch seconds.
  let dt = match jiff::Timestamp::from_second(secs) {
    Ok(ts) => ts.to_zoned(jiff::tz::TimeZone::UTC),
    Err(_) => return None,
  };
  let date = dt.date();
  let time = dt.time();
  // Faithful: `ConvertUnixTime($t, undef, 3)` returns `YYYY:MM:DD HH:MM:SS.sss`
  // with NO timezone suffix (the 2nd arg `undef` = no UTC-local conversion;
  // the 3rd arg `3` = 3-digit milliseconds). GoPro.pm:552. The `GPS9` col-6
  // `PrintConv => '$self->ConvertDateTime($val)'` (GoPro.pm:553) is a cosmetic
  // no-op on this already-formatted string and likewise adds no `Z`.
  Some(format!(
    "{:04}:{:02}:{:02} {:02}:{:02}:{:02}.{:03}",
    date.year(),
    date.month(),
    date.day(),
    time.hour(),
    time.minute(),
    time.second(),
    millis,
  ))
}

/// `ConvertSystemTime($val, $et)` (GoPro.pm:677-702) — resolve a Karma `GLPI`
/// column-0 "system time" (in seconds, post-`SCAL`) to a date/time string by
/// interpolating against the file's `SYST` calibration list.
///
/// `list` is the accumulated `(system_time_s, unix_time_s)` pairs (walk order;
/// this function sorts a copy by system time, mirroring ExifTool's lazy
/// `SystemTimeListSorted` sort, GoPro.pm:681-684). Algorithm (GoPro.pm:685-701):
///
///  1. EMPTY list ⇒ `<uncalibrated>` (GoPro.pm:680).
///  2. Binary-narrow to the bracketing pair `[i, j]` (GoPro.pm:685-690).
///  3. If the endpoints coincide use `list[i].unix`; else linearly interpolate
///     the unix time at `systime` (GoPro.pm:691-696).
///  4. THE QUIRK (GoPro.pm:700-701): stringify the interpolated unix value and
///     match `^(\d+)(\.\d+)`. A WHOLE-NUMBER epoch has no fractional part, so
///     the match FAILS, `$t`/`$f` are undef, and `ConvertUnixTime(undef)`
///     renders `0000:00:00 00:00:00`. A fractional epoch matches: the integer
///     part is converted via `ConvertUnixTime` (NO forced milliseconds — the
///     3-arg millis form is NOT used here) and the captured fraction string
///     (e.g. `.5`) is appended verbatim.
///
/// The result is then passed through `ConvertDateTime` (GoPro.pm:606), which is
/// a cosmetic no-op on this already-formatted string (adds no timezone). Like
/// the rest of this port's GoPro date handling the epoch is rendered in UTC for
/// reproducibility (matching the existing GPS9 [`unix_to_iso`] choice).
fn convert_system_time(list: &[(f64, f64)], systime: f64) -> Option<String> {
  // GoPro.pm:680 — no calibration ⇒ the literal `<uncalibrated>`.
  if list.is_empty() {
    return Some(String::from("<uncalibrated>"));
  }
  if !systime.is_finite() {
    return None;
  }
  // GoPro.pm:681-684 — sort a COPY by system time (the [0] column). ExifTool
  // sorts the stored list in place once and caches the flag; the typed layer
  // keeps the walk-order list immutable and sorts per lookup (correctness is
  // identical; GLPI lookups are rare).
  let mut s = list.to_vec();
  s.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
  // GoPro.pm:685-690 — binary search for the bracketing pair.
  let mut i = 0usize;
  let mut j = s.len() - 1; // non-empty checked above
  while j - i > 1 {
    let t = (i + j) / 2;
    // `($val < $$s[$t][0] ? $j : $i) = $t`.
    match s.get(t) {
      Some(&(st, _)) if systime < st => j = t,
      _ => i = t,
    }
  }
  let (Some(&(si, ui)), Some(&(sj, uj))) = (s.get(i), s.get(j)) else {
    return None;
  };
  // GoPro.pm:691-696 — coincident endpoints take `list[i].unix`; otherwise
  // linearly interpolate.
  let unix = if i == j || sj == si {
    ui
  } else {
    ui + (uj - ui) * (systime - si) / (sj - si)
  };
  Some(system_time_to_string(unix))
}

/// The GoPro.pm:700-701 stringify-and-render tail of `ConvertSystemTime`,
/// faithful to Perl's `("$val" =~ /^(\d+)(\.\d+)/)` capture + `ConvertUnixTime`.
/// Split out so it can be unit-tested against the exact ExifTool quirk.
fn system_time_to_string(unix: f64) -> String {
  // Perl stringifies `$val`; a whole-number float prints with NO decimal point,
  // so `^(\d+)(\.\d+)` fails to capture a fraction. Replicate: a finite,
  // in-range value with a zero fractional part has no `$f`, so the whole regex
  // fails and `ConvertUnixTime(undef)` → `0000:00:00 00:00:00`.
  if !unix.is_finite() {
    // Perl: a non-numeric value yields undef captures; `ConvertUnixTime(undef)`
    // is the all-zero string.
    return String::from("0000:00:00 00:00:00");
  }
  // FAITHFUL to `("$val" =~ /^(\d+)(\.\d+)/)` (GoPro.pm:700): Perl matches the
  // regex against the `%.15g` STRINGIFICATION of the interpolated value (its
  // default NV stringify width). The fraction MUST be taken from that decimal
  // string — NOT from f64 `unix - trunc`, which loses precision at a ~1.5e9
  // magnitude (e.g. it would render `.06` as `.059999942…`). Stringify with the
  // shared `%.15g` (`format_g`), then split on the decimal point.
  let s = crate::value::format_g(unix, 15);
  // `^(\d+)(\.\d+)`: the integer part must be all ASCII digits (no leading `-`,
  // no `e` scientific form). A negative or scientific `%.15g` string does not
  // match ⇒ undef captures ⇒ all-zero.
  let Some((int_str, frac_str)) = s.split_once('.') else {
    // No decimal point — a whole-number epoch. The regex's `(\.\d+)` group
    // fails to match ⇒ `$t`/`$f` undef ⇒ `ConvertUnixTime(undef)` all-zero.
    return String::from("0000:00:00 00:00:00");
  };
  if int_str.is_empty()
    || !int_str.bytes().all(|b| b.is_ascii_digit())
    || !frac_str.bytes().all(|b| b.is_ascii_digit())
  {
    // The `%g` string was scientific (`e`-form) or otherwise not `\d+\.\d+` —
    // the regex fails ⇒ all-zero (matches Perl on an out-of-`%g`-fixed value).
    return String::from("0000:00:00 00:00:00");
  }
  // `$t` = integer seconds; convert via `ConvertUnixTime($t, $utc)` (NO
  // forced-millis 3rd arg). UTC for reproducibility (matches GPS9 `unix_to_iso`).
  let Ok(secs) = int_str.parse::<i64>() else {
    return String::from("0000:00:00 00:00:00");
  };
  let dt = match jiff::Timestamp::from_second(secs) {
    Ok(ts) => ts.to_zoned(jiff::tz::TimeZone::UTC),
    Err(_) => return String::from("0000:00:00 00:00:00"),
  };
  let date = dt.date();
  let time = dt.time();
  // `. $f` appends the captured fraction (`.NN`) verbatim.
  format!(
    "{:04}:{:02}:{:02} {:02}:{:02}:{:02}.{}",
    date.year(),
    date.month(),
    date.day(),
    time.hour(),
    time.minute(),
    time.second(),
    frac_str,
  )
}

/// `[^-_a-zA-Z0-9 ]` — ExifTool's `Unrecognized GoPro record` bail check
/// (GoPro.pm:833). A tag passes if EVERY byte is alphanumeric / dash /
/// underscore / space.
const fn is_tag_char(b: &u8) -> bool {
  matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b' ')
}

/// The KNOWN recursable GPMF containers — the only two tags in the
/// `%GoPro::GPMF` family that pair `fmt \0` (container) with a
/// `SubDirectory => GoPro::GPMF` re-entry: `DEVC` (`DeviceContainer`,
/// GoPro.pm:155-157) and `STRM` (`NestedSignalStream`, GoPro.pm:381-383).
///
/// A `fmt=0` record whose tag is NOT in this set is an UNKNOWN container,
/// which ExifTool skips in default `-ee` mode (`next unless $unknown`,
/// GoPro.pm:877) and would recurse only under `-u` (GoPro.pm:880). The
/// non-container GoPro SubDirectories (`GPS5`/`GPS9`/`GLPI`/`GPRI`/`KBAT`)
/// are intentionally absent here — they carry a numeric `fmt`, never `\0`,
/// so they are dispatched as scalar records in [`Walker::emit_tag`], not
/// recursed.
const fn is_known_container(tag: &[u8]) -> bool {
  matches!(tag, b"DEVC" | b"STRM")
}

/// The DEFAULT-VISIBLE `%GoPro::GPMF` tags this port emits through the
/// table-driven [`GoProTag`] surface — every `TAG => …` entry in GoPro.pm:78-485
/// WITHOUT `Unknown => 1` / `Hidden => 1`, EXCLUDING the ones the typed surface
/// already models (the containers `DEVC`/`STRM`; the GPS/Karma subdirectories
/// `GPS5`/`GPS9`/`GLPI`/`KBAT`/`SYST`; and the camera-identity / block-level GPS
/// scalars `DVNM`/`MINF`/`CASN`/`FMWR`/`MUID`/`GPSU`/`GPSF`/`GPSP`/`GPSA`).
///
/// Returns `(Name, conv)`: the ExifTool tag `Name` and the `-j` PrintConv family
/// (the `-n` value is the verbatim decoded value for all but the value-affecting
/// `Binary`/`AddUnits`/hash conversions). A tag NOT in this table is dropped in
/// default `-ee` mode (`next unless $unknown`, GoPro.pm:876-877) — this is the
/// exact closed set ExifTool's `HandleTag` emits without `-u`.
///
/// The `Unknown`/`Hidden` siblings (`SCAL`/`TYPE`/`UNIT`/`SIUN`/`DVID`/`EMPT`/
/// `TSMP`/`STNM`/`BPOS`/`ESCS`/`GPRI`) are intentionally ABSENT — they are
/// consumed as walker state or dropped, never emitted.
fn generic_tag_def(tag: &[u8]) -> Option<(&'static str, GoProConv)> {
  use GoProConv as C;
  // The match arms transcribe GoPro.pm one-for-one; the conv column is the
  // tag's `PrintConv` family (`Plain` = none / `-n`==`-j`). The three
  // `ValueConv`-only tags (STMP/CDAT/RMRK) carry `Plain` here and fold their
  // conversion at decode (see `emit_generic`).
  let def = match tag {
    b"AALP" => ("AudioLevel", C::Plain),
    b"ABSC" => ("AutoBoostScore", C::Plain),
    b"ACCL" => ("Accelerometer", C::Binary),
    b"ALLD" => ("AutoLowLightDuration", C::Plain),
    b"APTO" => ("AudioProtuneOption", C::Plain),
    b"ARUW" => ("AspectRatioUnwarped", C::Plain),
    b"ARWA" => ("AspectRatioWarped", C::Plain),
    b"ATTD" => ("Attitude", C::Binary),
    b"ATTR" => ("AttitudeTarget", C::Binary),
    b"AUBT" => ("AudioBlueTooth", C::NoYes),
    b"AUDO" => ("AudioSetting", C::Plain),
    b"AUPT" => ("AutoProtune", C::NoYes),
    b"BITR" => ("BitrateSetting", C::Plain),
    b"CDAT" => ("CreationDate", C::Plain),
    b"CDTM" => ("CaptureDelayTimer", C::Plain),
    b"CLDP" => ("ClassificationDataPresent", C::NoYes),
    b"CORI" => ("CameraOrientation", C::Binary),
    b"CPIN" => ("ChapterNumber", C::Plain),
    b"CSEN" => ("CoyoteSense", C::Binary),
    b"CTRL" => ("ControlLevel", C::Plain),
    b"CYTS" => ("CoyoteStatus", C::Binary),
    b"DUST" => ("DurationSetting", C::Plain),
    b"DZMX" => ("DigitalZoomAmount", C::Plain),
    b"DZOM" => ("DigitalZoomOn", C::NoYes),
    b"DZST" => ("DigitalZoom", C::Plain),
    b"EISA" => ("ElectronicImageStabilization", C::Plain),
    b"EISE" => ("ElectronicStabilizationOn", C::NoYes),
    b"EXPT" => ("ExposureType", C::Plain),
    b"FACE" => ("FaceDetected", C::Plain),
    b"FCNM" => ("FaceNumbers", C::Plain),
    b"FWVS" => ("OtherFirmware", C::Plain),
    b"GRAV" => ("GravityVector", C::Binary),
    b"GYRO" => ("Gyroscope", C::Binary),
    b"HCTL" => ("HorizonControl", C::Plain),
    b"HDRV" => ("HDRVideo", C::NoYes),
    b"HSGT" => ("HindsightSettings", C::Plain),
    b"HUES" => ("PredominantHue", C::Plain),
    b"IORI" => ("ImageOrientation", C::Binary),
    b"ISOE" => ("ISOSpeeds", C::Plain),
    b"ISOG" => ("ImageSensorGain", C::Binary),
    b"LNED" => ("LocalPositionNED", C::Binary),
    b"LOGS" => ("HealthLogs", C::Plain),
    b"MAGN" => ("Magnetometer", C::Plain),
    b"MAPX" => ("MappingXCoefficients", C::Plain),
    b"MAPY" => ("MappingYCoefficients", C::Plain),
    b"MMOD" => ("MediaMode", C::Plain),
    b"MTRX" => ("AccelerometerMatrix", C::Plain),
    b"MWET" => ("MicrophoneWet", C::Plain),
    b"MXCF" => ("MappingXMode", C::Plain),
    b"MYCF" => ("MappingYMode", C::Plain),
    b"ORDP" => ("OrientationDataPresent", C::NoYes),
    b"OREN" => ("AutoRotation", C::AutoRotation),
    b"ORIN" => ("InputOrientation", C::Plain),
    b"ORIO" => ("OutputOrientation", C::Plain),
    b"PHDR" => ("HDRSetting", C::Plain),
    b"PIMD" => ("ProtuneISOMode", C::Plain),
    b"PIMN" => ("AutoISOMin", C::Plain),
    b"PIMX" => ("AutoISOMax", C::Plain),
    b"POLY" => ("PolynomialCoefficients", C::Plain),
    b"PRES" => ("PhotoResolution", C::Plain),
    b"PRJT" => ("LensProjection", C::Plain),
    b"PRTN" => ("Protune", C::Protune),
    b"PTCL" => ("ColorMode", C::Plain),
    b"PTEV" => ("ExposureCompensation", C::Plain),
    b"PTSH" => ("Sharpness", C::Plain),
    b"PTWB" => ("WhiteBalance", C::Plain),
    b"PWPR" => ("PowerProfile", C::Plain),
    b"PYCF" => ("PolynomialPower", C::Plain),
    b"RAMP" => ("SpeedRampSetting", C::Plain),
    b"RATE" => ("Rate", C::Plain),
    b"RMRK" => ("Comments", C::Plain),
    b"SCAP" => ("ScheduleCapture", C::NoYes),
    b"SCEN" => ("SceneClassification", C::Plain),
    b"SCPR" => ("ScaledPressure", C::AddUnits),
    b"SCTM" => ("ScheduleCaptureTime", C::Plain),
    b"SHUT" => ("ExposureTimes", C::ExposureTimes),
    b"SIMU" => ("ScaledIMU", C::AddUnits),
    b"SMTR" => ("SpotMeter", C::NoYes),
    b"SROT" => ("SensorReadoutTime", C::Plain),
    b"STMP" => ("TimeStamp", C::Plain),
    b"TIMO" => ("TimeOffset", C::Plain),
    b"TMPC" => ("CameraTemperature", C::TempC),
    b"TZON" => ("TimeZone", C::TimeZone),
    b"UNIF" => ("InputUniformity", C::Plain),
    b"VERS" => ("MetadataVersion", C::Version),
    b"VFOV" => ("FieldOfView", C::FieldOfView),
    b"VFPS" => ("VideoFrameRate", C::FrameRate),
    b"VFRH" => ("VisualFlightRulesHUD", C::Plain),
    b"VRES" => ("VideoFrameSize", C::FrameSize),
    b"WBAL" => ("ColorTemperatures", C::Plain),
    b"WNDM" => ("WindProcessing", C::Plain),
    b"WRGB" => ("WhiteBalanceRGB", C::Binary),
    b"YAVG" => ("LumaAverage", C::Plain),
    b"ZFOV" => ("DiagonalFieldOfView", C::Plain),
    b"ZMPL" => ("ZoomScaleNormalization", C::Plain),
    _ => return None,
  };
  Some(def)
}

/// Join scaled `f64`s with single spaces using Perl's default `%.15g` NV
/// stringification ([`crate::value::format_g`]) — the post-`ScaleValues` string
/// ExifTool's `HandleTag` stores for a numeric record.
fn join_g(vals: &[f64]) -> String {
  let mut s = String::new();
  for (i, &v) in vals.iter().enumerate() {
    if i > 0 {
      s.push(' ');
    }
    s.push_str(&crate::value::format_g(v, 15));
  }
  s
}

/// Parse a `UNIT`/`SIUN` record into per-element unit strings, mirroring
/// ExifTool's `ReadValue` of the unit record (GoPro.pm:864-867): a `c`-format
/// record with `count > 1` AND `len > 1` unpacks as a LIST of `len`-wide
/// NUL-trimmed strings; otherwise it is one NUL-trimmed string. The strings
/// feed the `%addUnits` PrintConv (GoPro.pm:727-743).
fn read_unit_strings(fmt: u8, len: usize, count: usize, payload: &[u8]) -> Vec<SmolStr> {
  // Only `c` (string) units carry per-element labels; a non-string UNIT is rare
  // and treated as a single whole-string element.
  if fmt == 0x63 && count > 1 && len > 1 {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
      let start = i * len;
      if let Some(chunk) = payload.get(start..start + len) {
        let end = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
        // `end <= chunk.len()` so the checked slice is always `Some`.
        if let Some(s) = chunk.get(..end) {
          out.push(SmolStr::from(String::from_utf8_lossy(s)));
        }
      }
    }
    out
  } else {
    // A single unit string (possibly space-separated, but `%addUnits` splits the
    // VALUE — the unit list itself is one element here).
    read_ascii(payload)
      .map(|s| alloc::vec![SmolStr::from(s)])
      .unwrap_or_default()
  }
}

/// Decode a Latin-1 (ISO-8859-1) payload to a UTF-8 [`String`], mirroring
/// ExifTool's `$self->Decode($val, "Latin")` (GoPro.pm:335) — each byte maps to
/// the Unicode code point of the same value. Trailing NULs are trimmed first
/// (the `c`-format records are NUL-padded). Returns `None` for an empty result.
fn read_latin1(payload: &[u8]) -> Option<String> {
  // Same faithfulness contract as [`read_ascii`]: a NON-zero-size payload
  // always decodes (the empty string for an all-NUL payload), and `None` is
  // reserved for the `$size == 0` case that `visit` already filters. This makes
  // an all-NUL `RMRK` emit `GoPro:Comments = ""` (oracle-confirmed) rather than
  // dropping the tag.
  if payload.is_empty() {
    return None;
  }
  let end = payload
    .iter()
    .position(|&b| b == 0)
    .unwrap_or(payload.len());
  let slice = payload.get(..end)?;
  // Latin-1 → UTF-8: each byte is its own code point (`char::from(byte)`). An
  // empty `slice` (all-NUL payload) yields the empty string.
  Some(slice.iter().map(|&b| char::from(b)).collect())
}

/// `ConvertUnixTime($val)` (the 2-arg form, no forced milliseconds) — render a
/// whole-second Unix epoch as `YYYY:MM:DD HH:MM:SS` in UTC, for `CDAT`
/// `CreationDate` (GoPro.pm:122-127). Distinct from [`unix_to_iso`] (the GPS9
/// 3-arg `..., undef, 3` form that forces `.sss`).
fn unix_to_iso_no_millis(t: f64) -> Option<String> {
  if !t.is_finite() || !(0.0..=32_503_680_000.0).contains(&t) {
    return None;
  }
  let secs = t.trunc() as i64;
  let dt = match jiff::Timestamp::from_second(secs) {
    Ok(ts) => ts.to_zoned(jiff::tz::TimeZone::UTC),
    Err(_) => return None,
  };
  let date = dt.date();
  let time = dt.time();
  Some(format!(
    "{:04}:{:02}:{:02} {:02}:{:02}:{:02}",
    date.year(),
    date.month(),
    date.day(),
    time.hour(),
    time.minute(),
    time.second(),
  ))
}

#[cfg(test)]
// Tests build hand-crafted fixtures and index the decoded sample vectors with
// known-good literals; raw indexing keeps the assertions terse and a panic is
// the desired failure mode, so the file-level deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  extern crate alloc;
  use alloc::vec;

  /// Build one KLV record header + payload, padded to a 4-byte boundary.
  fn klv(tag: &[u8; 4], fmt: u8, sample_size: u8, count: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag);
    out.push(fmt);
    out.push(sample_size);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
      out.push(0);
    }
    out
  }

  /// The standard Hero13 GPS9 `TYPE` record — `lllllllSS` (7×`l` int32s +
  /// 2×`S` int16u), GoPro.pm:225. A real GPS9 STRM always carries this TYPE
  /// ahead of the GPS9 record; the complex-`?` decoder (GoPro.pm:848-863)
  /// reads each column per this layout.
  fn gps9_standard_type() -> Vec<u8> {
    // 'l' = 0x6c, 'S' = 0x53.
    let type_payload = [0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x53, 0x53];
    klv(b"TYPE", 0x63, 9, 1, &type_payload)
  }

  #[test]
  fn klv_walker_decodes_dvnm_minf_casn_fmwr() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
    buf.extend_from_slice(&klv(b"MINF", 0x63, 11, 1, b"HERO6 Black"));
    buf.extend_from_slice(&klv(b"CASN", 0x63, 14, 1, b"C3221324657219"));
    buf.extend_from_slice(&klv(b"FMWR", 0x63, 15, 1, b"HD6.01.01.51.00"));
    let mut out = GoProMeta::new();
    // A valid GoPro record sets ExifTool's `FoundEmbedded` (GoPro.pm:822).
    assert!(process_gopro(&buf, &mut out));
    assert_eq!(out.device_name(), Some("Camera"));
    assert_eq!(out.model(), Some("HERO6 Black"));
    assert_eq!(out.camera_serial_number(), Some("C3221324657219"));
    assert_eq!(out.firmware_version(), Some("HD6.01.01.51.00"));
  }

  #[test]
  fn klv_walker_recurses_into_devc_container() {
    // Outer DEVC container holds one inner DVNM scalar.
    let inner = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    let outer = klv(b"DEVC", 0, 1, inner.len() as u16, &inner);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&outer, &mut out);
    assert_eq!(out.device_name(), Some("Hero"));
  }

  #[test]
  fn klv_walker_emits_one_sample_per_gps5_row() {
    // Two-row GPS5 with the canonical default SCAL vector. ExifTool scales
    // ONLY when a SCAL record was seen (GoPro.pm:884 `if $scal and …`), so a
    // real GoPro STRM always carries SCAL ahead of GPS5; emit it explicitly
    // here (and make GPS5 the last record in its container so the
    // last-in-container guard fires). lat=42_0000000 (raw int32) /
    // 10_000_000 = 4.2°, lon=-105_0000000 / 10_000_000 = -10.5°,
    // alt=1_500_000 / 1000 = 1500 m, spd=12_000 / 1000 = 12 m/s,
    // spd3d=1500 / 100 = 15 m/s. Second row doubles each value.
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut payload = Vec::new();
    for &factor in &[1i32, 2] {
      payload.extend_from_slice(&(factor * 42_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * -105_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 12_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500i32).to_be_bytes());
    }
    let gps5 = klv(b"GPS5", 0x6c, 20, 2, &payload);
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps5);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    let samples = out.gps_samples();
    assert_eq!(samples.len(), 2);
    let row0 = &samples[0];
    assert!((row0.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((row0.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((row0.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
    assert!((row0.speed_2d_mps().unwrap() - 12.0).abs() < 1e-6);
    assert!((row0.speed_3d_mps().unwrap() - 15.0).abs() < 1e-6);
    let row1 = &samples[1];
    assert!((row1.latitude().unwrap() - 8.4).abs() < 1e-6);
    assert!((row1.longitude().unwrap() + 21.0).abs() < 1e-6);
  }

  #[test]
  fn gps5_flat_int32_encoding_decodes_same_rows_as_standard() {
    // R10 fix: GPS5 is the simple `l` (int32s) list — ExifTool reads it as a
    // FLAT run of `len*count/4` int32s (GoPro.pm:837/869, ExifTool.pm:6296) and
    // chunks 5-per-row in ProcessString (GoPro.pm:749-777), AGNOSTIC to how the
    // KLV header split len vs count. A GoPro-producible flat layout encodes the
    // SAME 5N int32s as `fmt='l', len=4, count=5N` (a per-ELEMENT stride). It
    // must decode to the SAME N rows as the standard `len=20, count=N` framing.
    //
    // Identical SCAL container + identical 2 rows of int32 bytes as
    // `klv_walker_emits_one_sample_per_gps5_row`, only the GPS5 header's
    // len/count differ (4/10 instead of 20/2). The payload bytes are byte-for-
    // byte the same, so the decoded rows must be byte-identical.
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut payload = Vec::new();
    for &factor in &[1i32, 2] {
      payload.extend_from_slice(&(factor * 42_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * -105_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 12_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500i32).to_be_bytes());
    }
    // FLAT encoding: len=4 (one int32 per "element"), count=5*N=10 (10 elements).
    let gps5 = klv(b"GPS5", 0x6c, 4, 10, &payload);
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps5);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    let samples = out.gps_samples();
    // The flat (len=4, count=10) framing yields the SAME 2 rows as the standard
    // (len=20, count=2) framing — not dropped, not collapsed.
    assert_eq!(samples.len(), 2);
    let row0 = &samples[0];
    assert!((row0.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((row0.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((row0.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
    assert!((row0.speed_2d_mps().unwrap() - 12.0).abs() < 1e-6);
    assert!((row0.speed_3d_mps().unwrap() - 15.0).abs() < 1e-6);
    let row1 = &samples[1];
    assert!((row1.latitude().unwrap() - 8.4).abs() < 1e-6);
    assert!((row1.longitude().unwrap() + 21.0).abs() < 1e-6);
    assert!((row1.altitude_m().unwrap() - 3000.0).abs() < 1e-6);
    assert!((row1.speed_2d_mps().unwrap() - 24.0).abs() < 1e-6);
    assert!((row1.speed_3d_mps().unwrap() - 30.0).abs() < 1e-6);
  }

  #[test]
  fn gps5_trailing_partial_group_is_dropped() {
    // GoPro.pm:763-768 bumps the sub-document (= a typed GPS row) only on a
    // COMPLETE 5-column wrap. A flat run whose length is not a multiple of 5
    // therefore yields only the complete rows; the trailing `<5` int32s form no
    // Doc. Here: 7 int32s (1 full row + 2 leftover) ⇒ exactly 1 sample.
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut payload = Vec::new();
    payload.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat
    payload.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon
    payload.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt
    payload.extend_from_slice(&12_000i32.to_be_bytes()); // spd
    payload.extend_from_slice(&1_500i32.to_be_bytes()); // spd3d
    payload.extend_from_slice(&99i32.to_be_bytes()); // leftover col 0 of row 1
    payload.extend_from_slice(&88i32.to_be_bytes()); // leftover col 1 of row 1
    // 7 int32s flat (len=4, count=7).
    let gps5 = klv(b"GPS5", 0x6c, 4, 7, &payload);
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps5);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    let samples = out.gps_samples();
    assert_eq!(
      samples.len(),
      1,
      "trailing partial group must not form a row"
    );
    let s = &samples[0];
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
  }

  #[test]
  fn klv_walker_honours_explicit_scal_in_gps5_container() {
    // STRM { SCAL=[100, 100, 1, 1, 1], GPS5=[row] } —
    // a custom non-default SCAL should override the defaults.
    let scal_payload: Vec<u8> = [100u32, 100, 1, 1, 1]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut gps5_payload = Vec::new();
    gps5_payload.extend_from_slice(&42i32.to_be_bytes()); // lat: 0.42°
    gps5_payload.extend_from_slice(&105i32.to_be_bytes()); // lon: 1.05°
    gps5_payload.extend_from_slice(&1500i32.to_be_bytes()); // alt: 1500 m
    gps5_payload.extend_from_slice(&12i32.to_be_bytes()); // spd: 12 m/s
    gps5_payload.extend_from_slice(&15i32.to_be_bytes()); // spd3d
    let gps5 = klv(b"GPS5", 0x6c, 20, 1, &gps5_payload);
    let mut strm_body = Vec::new();
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps5);
    let strm = klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&strm, &mut out);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 0.42).abs() < 1e-6);
    assert!((s.longitude().unwrap() - 1.05).abs() < 1e-6);
    assert_eq!(s.altitude_m(), Some(1500.0));
    assert_eq!(s.speed_2d_mps(), Some(12.0));
  }

  #[test]
  fn gps5_not_last_in_container_is_not_scaled() {
    // FINDING B oracle (GoPro.pm:884 `… and $pos+$size+3>=$dirEnd`): a SCAL
    // vector is present, but GPS5 is NOT the last record in its container
    // (a sibling DVNM follows). ExifTool applies `ScaleValues` only to the
    // LAST tag, so GPS5 must come through RAW (unscaled) here, even though
    // SCAL was saved. Container = STRM { SCAL, GPS5, DVNM } — same SCAL/GPS5
    // bytes as the scaled test above, only the trailing DVNM differs.
    let scal_payload: Vec<u8> = [100u32, 100, 1, 1, 1]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut gps5_payload = Vec::new();
    gps5_payload.extend_from_slice(&42i32.to_be_bytes());
    gps5_payload.extend_from_slice(&105i32.to_be_bytes());
    gps5_payload.extend_from_slice(&1500i32.to_be_bytes());
    gps5_payload.extend_from_slice(&12i32.to_be_bytes());
    gps5_payload.extend_from_slice(&15i32.to_be_bytes());
    let gps5 = klv(b"GPS5", 0x6c, 20, 1, &gps5_payload);
    // A sibling AFTER GPS5 makes GPS5 no longer the last record.
    let dvnm = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    let mut strm_body = Vec::new();
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps5);
    strm_body.extend_from_slice(&dvnm);
    let strm = klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&strm, &mut out);
    // RAW int32s — NOT divided by the SCAL [100,100,1,1,1] vector.
    let s = &out.gps_samples()[0];
    assert_eq!(s.latitude(), Some(42.0));
    assert_eq!(s.longitude(), Some(105.0));
    assert_eq!(s.altitude_m(), Some(1500.0));
    assert_eq!(s.speed_2d_mps(), Some(12.0));
    assert_eq!(s.speed_3d_mps(), Some(15.0));
    // The trailing sibling was still decoded (the walk continued past GPS5).
    assert_eq!(out.device_name(), Some("Hero"));
  }

  #[test]
  fn gps9_not_last_in_container_is_not_scaled() {
    // FINDING B for GPS9 (GoPro.pm:884). SCAL present, but a sibling DVNM
    // follows GPS9 in the STRM, so GPS9 is NOT the last record ⇒ RAW values.
    let scal_payload: Vec<u8> = [
      10_000_000u32,
      10_000_000,
      1_000,
      1_000,
      100,
      1,
      1_000,
      100,
      1,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 9, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt
    row.extend_from_slice(&12_000i32.to_be_bytes()); // spd
    row.extend_from_slice(&1_500i32.to_be_bytes()); // spd3d
    row.extend_from_slice(&7000i32.to_be_bytes()); // days
    row.extend_from_slice(&12_345i32.to_be_bytes()); // secs
    row.extend_from_slice(&150u16.to_be_bytes()); // dop
    row.extend_from_slice(&3u16.to_be_bytes()); // fix mode
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let dvnm = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    let mut strm_body = Vec::new();
    // Real GPS9 STRMs carry the `lllllllSS` TYPE ahead of GPS9 (GoPro.pm:225);
    // the complex-`?` decoder reads each column per this layout.
    strm_body.extend_from_slice(&gps9_standard_type());
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps9);
    strm_body.extend_from_slice(&dvnm);
    let strm = klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&strm, &mut out);
    let s = &out.gps_samples()[0];
    // RAW (unscaled) lat/lon/alt/speed/dop and the raw integer mode code.
    assert_eq!(s.latitude(), Some(42_000_000.0));
    assert_eq!(s.longitude(), Some(-105_000_000.0));
    assert_eq!(s.altitude_m(), Some(1_500_000.0));
    assert_eq!(s.dop(), Some(150.0));
    assert_eq!(s.measure_mode(), Some(3));
    assert_eq!(out.device_name(), Some("Hero"));
  }

  #[test]
  fn gps5_with_no_scal_record_is_not_scaled() {
    // GoPro.pm:884 `if $scal and …`: with NO SCAL record at all, `$scal` is
    // undef so `ScaleValues` never fires — ExifTool emits the RAW int32s.
    // (Real GoPro STRMs always carry SCAL; this guards the bare/edge case.)
    let mut gps5_payload = Vec::new();
    gps5_payload.extend_from_slice(&42_000_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&(-105_000_000i32).to_be_bytes());
    gps5_payload.extend_from_slice(&1_500_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&12_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&1_500i32.to_be_bytes());
    let buf = klv(b"GPS5", 0x6c, 20, 1, &gps5_payload);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    let s = &out.gps_samples()[0];
    assert_eq!(s.latitude(), Some(42_000_000.0));
    assert_eq!(s.longitude(), Some(-105_000_000.0));
    assert_eq!(s.altitude_m(), Some(1_500_000.0));
    assert_eq!(s.speed_2d_mps(), Some(12_000.0));
    assert_eq!(s.speed_3d_mps(), Some(1_500.0));
  }

  #[test]
  fn klv_walker_decodes_gpsu_gpsf_gpsp_gpsa() {
    // GPSU is a Hero5-style 'c' ASCII "200731103245.500" → "2020:07:31 10:32:45.500"
    // (no `Z`: ConvertDateTime adds no timezone by default, GoPro.pm:247).
    let gpsu = klv(b"GPSU", 0x63, 16, 1, b"200731103245.500");
    let gpsf = klv(b"GPSF", 0x4c, 4, 1, &3u32.to_be_bytes());
    let gpsp = klv(b"GPSP", 0x53, 2, 1, &500u16.to_be_bytes()); // 500 cm
    let gpsa = klv(b"GPSA", 0x46, 4, 1, b"MSLV");
    let mut buf = Vec::new();
    buf.extend_from_slice(&gpsu);
    buf.extend_from_slice(&gpsf);
    buf.extend_from_slice(&gpsp);
    buf.extend_from_slice(&gpsa);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert_eq!(out.gps_date_time(), Some("2020:07:31 10:32:45.500"));
    assert_eq!(out.gps_measure_mode(), Some(3));
    assert_eq!(out.gps_h_positioning_error_m(), Some(5.0));
    assert_eq!(out.gps_altitude_system(), Some("MSLV"));
  }

  #[test]
  fn klv_walker_stops_on_null_tag() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&klv(b"DVNM", 0x63, 4, 1, b"Hero"));
    // 8 bytes of zero — a NULL tag, ExifTool last-stops.
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&klv(b"CASN", 0x63, 4, 1, b"FAKE"));
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert_eq!(out.device_name(), Some("Hero"));
    // CASN MUST NOT be reached (NULL tag terminated the walk).
    assert_eq!(out.camera_serial_number(), None);
  }

  #[test]
  fn klv_walker_skips_truncated_record() {
    // Header says size=200 but the buffer has 8 bytes of payload — bail.
    let mut buf = b"DVNM".to_vec();
    buf.push(0x63);
    buf.push(100); // sample_size
    buf.extend_from_slice(&2u16.to_be_bytes()); // count=2 → 200 bytes
    buf.extend_from_slice(&[b'A'; 8]);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert_eq!(out.device_name(), None);
  }

  #[test]
  fn process_gp6_dispatches_devc_record() {
    // Build a record whose payload is a DEVC container with one DVNM
    // child. The outer GP\x06\0\0 header is 16 bytes:
    // `GP\x06\0\0` (5 bytes magic, the `\x06` is arbitrary) + 3 reserved
    // bytes + 4-byte BE size + 4-byte payload-tag (the unpack template
    // takes only tag:a4, size:N so the actual layout is
    // [tag:4 = "GP\x06\0"][size:4]+[8 reserved bytes]+payload).
    //
    // GoPro.pm:791 `unpack('a4N', $buff)` of a 16-byte buffer reads 8
    // bytes (4 tag + 4 size); the remaining 8 bytes of header are unused
    // but consumed via `Read($buff, $size)`.
    let inner = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    let devc = klv(b"DEVC", 0, 1, inner.len() as u16, &inner);
    // size field measures the body length AFTER the 16-byte header.
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(b"GP\x06\0"); // tag: GP\x06\0
    header.extend_from_slice(&(devc.len() as u32).to_be_bytes()); // size BE
    header.extend_from_slice(&[0u8; 8]); // reserved
    let mut buf = header;
    buf.extend_from_slice(&devc);
    let mut out = GoProMeta::new();
    let consumed = process_gp6(&buf, &mut out);
    assert_eq!(consumed, buf.len());
    assert_eq!(out.device_name(), Some("Hero"));
  }

  #[test]
  fn process_gp6_stops_on_bad_magic() {
    // First record has tag "XX\x06\0…" — bail.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"XX\x06\0");
    buf.extend_from_slice(&8u32.to_be_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    let mut out = GoProMeta::new();
    let consumed = process_gp6(&buf, &mut out);
    assert_eq!(consumed, 0);
  }

  #[test]
  fn convert_gpsu_renders_hero5_style_ascii() {
    let s = convert_gpsu("171003105829.123");
    assert_eq!(s, "2017:10:03 10:58:29.123");
    // Without sub-seconds.
    let s = convert_gpsu("171003105829");
    assert_eq!(s, "2017:10:03 10:58:29");
  }

  #[test]
  fn convert_gpsu_passes_through_non_digit_prefix() {
    assert_eq!(convert_gpsu("not-a-date"), "not-a-date");
  }

  #[test]
  fn padded_size_rounds_up_to_four_byte_boundary() {
    assert_eq!(padded_size(0), 0);
    assert_eq!(padded_size(1), 4);
    assert_eq!(padded_size(3), 4);
    assert_eq!(padded_size(4), 4);
    assert_eq!(padded_size(5), 8);
    assert_eq!(padded_size(7), 8);
    assert_eq!(padded_size(8), 8);
  }

  #[test]
  fn klv_walker_decodes_muid_as_raw_u32_list() {
    // MUID is 4 BE u32s. ExifTool's RAW (ValueConv / `-n`) value is the
    // space-joined decimal list; the PrintConv (`-j`) hex-concatenates them.
    // The typed layer stores the RAW list (GoPro.pm:456-462).
    let muid_payload = vec![
      0x49u8, 0x1b, 0x31, 0x3c, 0xa8, 0x9d, 0x14, 0x16, 0xa5, 0x56, 0xfc, 0xe1, 0xd0, 0xcc, 0x7e,
      0x5a,
    ];
    let buf = klv(b"MUID", 0x4c, 4, 4, &muid_payload);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    // 0x491b313c 0xa89d1416 0xa556fce1 0xd0cc7e5a as decimals.
    assert_eq!(
      out.media_uid(),
      Some("1226518844 2828866582 2773941473 3503062618")
    );
  }

  #[test]
  fn klv_walker_decodes_gps9_per_sample_datetime() {
    // Pick a known date — days = 7000 (since 2000-01-01)
    // ⇒ Unix epoch (10957 + 7000) * 86400 = 1_551_484_800 ⇒
    // 2019-03-02 00:00:00 UTC; + 12_345 s ⇒ 03:25:45.
    let scal_payload: Vec<u8> = [
      10_000_000u32,
      10_000_000,
      1_000,
      1_000,
      100,
      1,
      1_000,
      100,
      1,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 9, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt
    row.extend_from_slice(&12_000i32.to_be_bytes()); // spd
    row.extend_from_slice(&1_500i32.to_be_bytes()); // spd3d
    row.extend_from_slice(&7000i32.to_be_bytes()); // days
    row.extend_from_slice(&(12_345i32 * 1000).to_be_bytes()); // secs * 1000 (scal=1000)
    row.extend_from_slice(&150u16.to_be_bytes()); // dop * 100 = 1.5
    row.extend_from_slice(&3u16.to_be_bytes()); // fix mode
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut buf = Vec::new();
    // GPS9 is a complex `?` record decoded per the preceding `lllllllSS` TYPE
    // (GoPro.pm:848-863, 225).
    buf.extend_from_slice(&gps9_standard_type());
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps9);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((s.dop().unwrap() - 1.5).abs() < 1e-6);
    assert_eq!(s.measure_mode(), Some(3));
    let dt = s.date_time().expect("GPS9 has per-sample datetime");
    // Faithful `ConvertUnixTime((7000+10957)*86400 + 12345, undef, 3)` —
    // `YYYY:MM:DD HH:MM:SS.sss` with NO `Z`/timezone suffix (GoPro.pm:552).
    assert_eq!(dt, "2019:03:02 03:25:45.000");
    assert!(
      !dt.contains('Z'),
      "GPS9 GPSDateTime must carry no timezone: {dt}"
    );
  }

  #[test]
  fn gps9_fractional_scal_measure_mode_does_not_panic() {
    // HOSTILE: a file-controlled fractional SCAL for the GPSMeasureMode
    // column (col 8). ExifTool's `ScaleValues` divides as f64 (GoPro.pm:717),
    // so a `0.5` scale is a value conversion — NOT a Rust panic. The pre-fix
    // code cast the denominator to `u32` (`0.5 as u32 == 0`) ⇒ integer
    // divide-by-zero panic. The fix scales as f64 and skips a non-exact
    // integer result. (Golden-v2 no-panic robustness contract.)
    //
    // SCAL as `float` (fmt 'f' = 0x66); col 8 = 0.5. The other columns use a
    // benign 1.0 so lat/lon/etc. stay finite.
    let scal_payload: Vec<u8> = [1.0f32, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.5]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x66, 4, 9, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&0i32.to_be_bytes()); // lat
    row.extend_from_slice(&0i32.to_be_bytes()); // lon
    row.extend_from_slice(&0i32.to_be_bytes()); // alt
    row.extend_from_slice(&0i32.to_be_bytes()); // spd
    row.extend_from_slice(&0i32.to_be_bytes()); // spd3d
    row.extend_from_slice(&7000i32.to_be_bytes()); // days
    row.extend_from_slice(&0i32.to_be_bytes()); // secs
    row.extend_from_slice(&0u16.to_be_bytes()); // dop
    row.extend_from_slice(&3u16.to_be_bytes()); // fix mode (raw 3)
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut buf = Vec::new();
    buf.extend_from_slice(&gps9_standard_type());
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps9);
    let mut out = GoProMeta::new();
    // Must not panic. 3 / 0.5 = 6.0 (an exact integer) ⇒ measure_mode = 6.
    assert!(process_gopro(&buf, &mut out));
    let s = &out.gps_samples()[0];
    assert_eq!(s.measure_mode(), Some(6));
  }

  #[test]
  fn gps9_non_integer_scal_measure_mode_is_skipped() {
    // A SCAL that makes the scaled mode NON-integer (3 / 2.0 = 1.5) — the
    // typed surface carries only the integer code, so a fractional result is
    // skipped (`None`) rather than truncated or panicking. ExifTool's
    // PrintConv would render `Unknown (1.5)`; the typed surface omits it.
    let scal_payload: Vec<u8> = [1.0f32, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 2.0]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x66, 4, 9, &scal_payload);
    let mut row = Vec::new();
    for _ in 0..5 {
      row.extend_from_slice(&0i32.to_be_bytes());
    }
    row.extend_from_slice(&7000i32.to_be_bytes()); // days
    row.extend_from_slice(&0i32.to_be_bytes()); // secs
    row.extend_from_slice(&0u16.to_be_bytes()); // dop
    row.extend_from_slice(&3u16.to_be_bytes()); // fix mode (raw 3) → 3/2 = 1.5
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut buf = Vec::new();
    buf.extend_from_slice(&gps9_standard_type());
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps9);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    let s = &out.gps_samples()[0];
    assert_eq!(s.measure_mode(), None);
  }

  // P3-C malformed-input tests — the parser must surface no panics / no
  // out-of-bounds reads on hostile inputs.

  #[test]
  fn klv_truncated_header_yields_empty_meta() {
    // 4-byte slice (no full 8-byte KLV header) — the walker stops at the
    // first short read and recognizes NO record (FoundEmbedded stays false).
    let mut out = GoProMeta::new();
    assert!(!process_gopro(b"DEVC", &mut out));
    assert!(out.is_empty());
  }

  #[test]
  fn process_gopro_reports_found_embedded() {
    // FoundEmbedded (GoPro.pm:822) — `true` iff a valid GoPro record is
    // recognized. A misrouted non-GoPro `gpmd` sample (a tag with
    // non-`[-_a-zA-Z0-9 ]` bytes) bails on the magic guard and reports
    // `false`, so the brute-force `mdat` scan is NOT suppressed.
    let mut out = GoProMeta::new();
    // A record whose tag has a non-printable byte (`\x01`) — bail, false.
    let bad = klv(b"D\x01VC", 0x63, 4, 1, b"junk");
    assert!(!process_gopro(&bad, &mut out));
    // A plain valid DVNM record — recognized, true.
    let good = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    assert!(process_gopro(&good, &mut out));
  }

  #[test]
  fn klv_header_size_zero_does_not_loop_forever() {
    // A KLV record with `sample_size=0`/`count=0` (zero-length payload) is
    // legal — the walker advances by the 8-byte header. A buffer holding
    // ONLY a zero-payload header parses cleanly and returns empty.
    let buf = klv(b"DVNM", 0x63, 0, 0, &[]);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn container_payload_overruns_buffer_silently_drops() {
    // A `DEVC` container claiming a 1024-byte payload but the buffer only
    // holds the header — the walker drops the partial container without
    // panicking.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"DEVC");
    buf.push(0x00); // fmt=container
    buf.push(0x01); // sample_size=1
    buf.extend_from_slice(&1024u16.to_be_bytes()); // count=1024 (payload >> buf)
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn unknown_fourcc_is_skipped() {
    // A KLV record with an unrecognised 4-byte tag is walked but produces
    // no typed-surface output (the fall-through case in `emit_tag`).
    let buf = klv(b"WXYZ", 0x4c, 4, 1, &[0u8; 4]);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn gps5_with_mismatched_scal_count_falls_back_to_one() {
    // SCAL with only 3 entries (lat, lon, alt) instead of the expected 5;
    // `scal_at` returns 1.0 for indices past the SCAL count, so speeds
    // come through as raw values. The walker still emits one sample per
    // row with no panic. Use GPS5's natural `sample_size=20` (5 * int32s).
    let scal_payload: Vec<u8> = [1u32, 1, 1].iter().flat_map(|v| v.to_be_bytes()).collect();
    let scal = klv(b"SCAL", 0x4c, 4, 3, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42i32.to_be_bytes()); // lat raw
    row.extend_from_slice(&(-105i32).to_be_bytes()); // lon raw
    row.extend_from_slice(&15i32.to_be_bytes()); // alt raw
    row.extend_from_slice(&5i32.to_be_bytes()); // spd raw (scal[3] out of bounds → 1.0)
    row.extend_from_slice(&6i32.to_be_bytes()); // spd3d raw (scal[4] out of bounds → 1.0)
    let gps5 = klv(b"GPS5", 0x6c, 20, 1, &row);
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps5);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    // SCAL only carried 3 entries — speed columns use the 1.0 fallback.
    assert_eq!(s.speed_2d_mps(), Some(5.0));
    assert_eq!(s.speed_3d_mps(), Some(6.0));
  }

  // ==========================================================================
  // FINDING R11 — `read_scalar_vec` (and the MUID list) must read a FLAT value
  // list (`ReadValue($dataPt,$pos,$format,undef,$size)` with `$size=len*count`,
  // GoPro.pm:837/869), NOT a `count × len` stride. The element count is
  // `(len*count)/element_size(fmt)` read at `element_size(fmt)` stride — so a
  // SCAL packed as a single 20-byte structure (`len=20, count=1`) yields all
  // FIVE factors, identical to the flat `len=4, count=5` encoding (which read
  // correctly before too). The pre-fix `count`-iteration at `i*len` stride read
  // only ONE factor for the `len=20, count=1` form, under-scaling GPS5/GPS9.
  // ==========================================================================

  #[test]
  fn read_scalar_vec_flat_list_independent_of_len_stride() {
    // Five int32u SCAL factors as one 20-byte big-endian blob.
    let factors = [10_000_000u32, 10_000_000, 1_000, 1_000, 100];
    let payload: Vec<u8> = factors.iter().flat_map(|v| v.to_be_bytes()).collect();
    let expected = [10_000_000.0, 10_000_000.0, 1_000.0, 1_000.0, 100.0];

    // Single-structure encoding: len = whole record (20), count = 1.
    let as_structure = read_scalar_vec(0x4c, 20, 1, &payload);
    // Flat encoding: len = element size (4), count = 5.
    let as_flat = read_scalar_vec(0x4c, 4, 5, &payload);

    assert_eq!(
      as_structure, expected,
      "len=20,count=1 must yield 5 factors"
    );
    assert_eq!(as_flat, expected, "len=4,count=5 must yield 5 factors");
    assert_eq!(as_structure, as_flat, "both encodings must agree");

    // 'f' float32 path (the other bundled SCAL format) — same flat behaviour.
    let fpay: Vec<u8> = [2.0f32, 4.0, 8.0]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    assert_eq!(read_scalar_vec(0x66, 12, 1, &fpay), [2.0, 4.0, 8.0]);
    assert_eq!(read_scalar_vec(0x66, 4, 3, &fpay), [2.0, 4.0, 8.0]);

    // A truncated record never inflates the count past the available bytes.
    assert_eq!(read_scalar_vec(0x4c, 20, 1, &payload[..6]), [10_000_000.0]);
    // A non-`%goProFmt` code yields an empty list (ExifTool 'undef' fall-through).
    assert!(read_scalar_vec(0x00, 4, 5, &payload).is_empty());
  }

  #[test]
  fn gps5_scales_with_single_structure_scal_len20_count1() {
    // The SAME standard GPS5 SCAL ([1e7,1e7,1000,1000,100]) and raw row as
    // `gps5_strm_body`, but the SCAL is encoded as ONE 20-byte structure
    // (`len=20, count=1`) instead of the flat `len=4, count=5`. Both MUST scale
    // the GPS5 sample identically; pre-fix the structure form read only the
    // first factor (1e7), leaving lon/alt/speeds wildly under-scaled.
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 20, 1, &scal_payload); // single 20-byte structure
    let mut gps5_payload = Vec::new();
    gps5_payload.extend_from_slice(&42_000_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&(-105_000_000i32).to_be_bytes());
    gps5_payload.extend_from_slice(&1_500_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&12_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&1_500i32.to_be_bytes());
    let gps5 = klv(b"GPS5", 0x6c, 20, 1, &gps5_payload);
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps5);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    let samples = out.gps_samples();
    assert_eq!(samples.len(), 1);
    let s = &samples[0];
    // Fully scaled values — identical to the flat-SCAL `gps5_strm_body` result.
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-9);
    assert!((s.longitude().unwrap() - (-10.5)).abs() < 1e-9);
    assert!((s.altitude_m().unwrap() - 1_500.0).abs() < 1e-9);
    assert!((s.speed_2d_mps().unwrap() - 12.0).abs() < 1e-9);
    assert!((s.speed_3d_mps().unwrap() - 15.0).abs() < 1e-9);
  }

  #[test]
  fn muid_reads_flat_list_independent_of_len_stride() {
    // MUID is `ReadValue($dataPt,$pos,'L',undef,$size)` ⇒ a FLAT u32 list. The
    // RAW (ValueConv) form the typed surface stores is the space-joined decimal
    // list. A `len=4, count=4` flat encoding and a `len=16, count=1` single
    // structure must yield the SAME four decimal values.
    let words = [0x1122_3344u32, 0x5566_7788, 0x99aa_bbcc, 0x0102_0304];
    let payload: Vec<u8> = words.iter().flat_map(|v| v.to_be_bytes()).collect();
    let want = SmolStr::from("287454020 1432778632 2578103244 16909060");

    let mut flat = GoProMeta::new();
    assert!(process_gopro(
      &klv(b"MUID", 0x4c, 4, 4, &payload),
      &mut flat
    ));
    assert_eq!(flat.media_uid(), Some(want.as_str()));

    let mut structure = GoProMeta::new();
    assert!(process_gopro(
      &klv(b"MUID", 0x4c, 16, 1, &payload),
      &mut structure
    ));
    assert_eq!(structure.media_uid(), Some(want.as_str()));
  }

  // ==========================================================================
  // FINDING R4-A — only KNOWN `fmt=0` containers (DEVC/STRM) are recursed.
  // GoPro.pm:876-882: a tag not in the table is `next unless $unknown`
  // (SKIPPED in default mode); an unknown `fmt=0` record becomes a recursable
  // SubDirectory only under `-u`. So a crafted/future unknown container that
  // wraps GPS5/GPS9 must NOT have its inner records extracted in default mode.
  // ==========================================================================

  /// A canonical one-row GPS5 STRM body — SCAL=[1e7,1e7,1000,1000,100] then a
  /// GPS5 row (raw int32s ⇒ 4.2° / -10.5° / 1500 m / 12 m/s / 15 m/s). GPS5
  /// is kept LAST so the GoPro.pm:884 last-in-container SCAL guard fires.
  fn gps5_strm_body() -> Vec<u8> {
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let mut gps5_payload = Vec::new();
    gps5_payload.extend_from_slice(&42_000_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&(-105_000_000i32).to_be_bytes());
    gps5_payload.extend_from_slice(&1_500_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&12_000i32.to_be_bytes());
    gps5_payload.extend_from_slice(&1_500i32.to_be_bytes());
    let gps5 = klv(b"GPS5", 0x6c, 20, 1, &gps5_payload);
    let mut body = Vec::new();
    body.extend_from_slice(&scal);
    body.extend_from_slice(&gps5);
    body
  }

  #[test]
  fn known_devc_container_recurses_and_emits_gps5() {
    // Control: a DEVC-wrapped GPS5 STRM body IS recursed and extracted (the
    // real GoPro path is unchanged by the R4-A gate).
    let body = gps5_strm_body();
    let devc = klv(b"DEVC", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&devc, &mut out));
    let samples = out.gps_samples();
    assert_eq!(samples.len(), 1, "DEVC container must be recursed");
    assert!((samples[0].latitude().unwrap() - 4.2).abs() < 1e-6);
  }

  #[test]
  fn known_strm_container_recurses_and_emits_gps5() {
    // Control: a STRM-wrapped GPS5 body IS recursed and extracted.
    let body = gps5_strm_body();
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    assert_eq!(
      out.gps_samples().len(),
      1,
      "STRM container must be recursed"
    );
  }

  #[test]
  fn unknown_fmt0_container_wrapping_gps5_is_not_recursed() {
    // R4-A: an UNKNOWN `fmt=0` container (`XXXX`, not DEVC/STRM) wrapping the
    // same GPS5 STRM body. In default mode ExifTool skips an unknown tag
    // (`next unless $unknown`) and never recurses, so GPS5 must NOT be
    // extracted — even though the inner bytes are a perfectly valid GPS5.
    let body = gps5_strm_body();
    let unknown = klv(b"XXXX", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    // The outer record header still passed the tag-char guard → recognized,
    // but the unknown container is NOT recursed, so nothing is extracted.
    assert!(process_gopro(&unknown, &mut out));
    assert!(
      out.gps_samples().is_empty(),
      "an unknown fmt=0 container must not be recursed in default mode"
    );
    assert!(out.is_empty());
  }

  #[test]
  fn unknown_fmt0_container_wrapping_gps9_is_not_recursed() {
    // R4-A for GPS9: an unknown `fmt=0` container wrapping a TYPE+SCAL+GPS9
    // body must not be recursed (no GPS9 sample) in default mode, while the
    // identical body under STRM (below) IS extracted.
    let scal_payload: Vec<u8> = [
      10_000_000u32,
      10_000_000,
      1_000,
      1_000,
      100,
      1,
      1_000,
      100,
      1,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 9, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt
    row.extend_from_slice(&12_000i32.to_be_bytes()); // spd
    row.extend_from_slice(&1_500i32.to_be_bytes()); // spd3d
    row.extend_from_slice(&7000i32.to_be_bytes()); // days
    row.extend_from_slice(&12_345i32.to_be_bytes()); // secs
    row.extend_from_slice(&150u16.to_be_bytes()); // dop
    row.extend_from_slice(&3u16.to_be_bytes()); // fix mode
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut body = Vec::new();
    body.extend_from_slice(&gps9_standard_type());
    body.extend_from_slice(&scal);
    body.extend_from_slice(&gps9);

    // Unknown container → NOT recursed.
    let unknown = klv(b"ZZZZ", 0, 1, body.len() as u16, &body);
    let mut out_unknown = GoProMeta::new();
    assert!(process_gopro(&unknown, &mut out_unknown));
    assert!(
      out_unknown.gps_samples().is_empty(),
      "unknown fmt=0 container wrapping GPS9 must not be recursed"
    );

    // Same body under a known STRM container → recursed and extracted.
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out_known = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out_known));
    assert_eq!(
      out_known.gps_samples().len(),
      1,
      "STRM-wrapped GPS9 must still be extracted"
    );
  }

  #[test]
  fn unknown_fmt0_container_sibling_does_not_block_following_records() {
    // The unknown-container skip must NOT halt the walk: a DVNM AFTER an
    // unknown `fmt=0` container is still decoded (the walk advances past the
    // skipped container by header size, mirroring Perl's `next`).
    let body = gps5_strm_body();
    let unknown = klv(b"XXXX", 0, 1, body.len() as u16, &body);
    let dvnm = klv(b"DVNM", 0x63, 4, 1, b"Hero");
    let mut buf = Vec::new();
    buf.extend_from_slice(&unknown);
    buf.extend_from_slice(&dvnm);
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert!(
      out.gps_samples().is_empty(),
      "unknown container still not recursed"
    );
    assert_eq!(
      out.device_name(),
      Some("Hero"),
      "the sibling after the skipped container is still decoded"
    );
  }

  // ==========================================================================
  // FINDING R4-B — GPS9 complex `?` decode is driven by the preceding TYPE
  // record (GoPro.pm:848-863), not a hardcoded layout.
  // ==========================================================================

  #[test]
  fn gps9_with_absent_type_emits_no_sample() {
    // R4-B fallback: GoPro.pm:848 `if ($fmt == 0x3f and defined $type)` — with
    // NO preceding TYPE record, the complex decode is skipped and no numeric
    // column list is produced ⇒ no GPS9 sample. (The pre-fix code force-decoded
    // a fixed `lllllllSS` layout regardless of TYPE.)
    let scal_payload: Vec<u8> = [
      10_000_000u32,
      10_000_000,
      1_000,
      1_000,
      100,
      1,
      1_000,
      100,
      1,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 9, &scal_payload);
    let mut row = Vec::new();
    for _ in 0..7 {
      row.extend_from_slice(&1i32.to_be_bytes());
    }
    row.extend_from_slice(&1u16.to_be_bytes());
    row.extend_from_slice(&3u16.to_be_bytes());
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    // SCAL + GPS9 but deliberately NO TYPE.
    let mut buf = Vec::new();
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps9);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    assert!(
      out.gps_samples().is_empty(),
      "GPS9 with no TYPE must emit no sample (GoPro.pm:848 `defined $type`)"
    );
  }

  #[test]
  fn gps9_with_short_type_decodes_only_resolved_columns() {
    // R4-B fallback: a SHORT TYPE describing only the first 3 columns (`lll` =
    // lat, lon, alt). GoPro.pm:852-856 walks only the TYPE bytes, so columns
    // 3..=8 are never read — lat/lon/alt are decoded, the rest stay unset.
    // (The `len`/sample_size is still 32 so the row bytes exist, but ExifTool
    // only reads what TYPE describes.)
    let type_payload = [0x6cu8, 0x6c, 0x6c]; // 'lll' — 3 int32s columns
    let type_rec = klv(b"TYPE", 0x63, 3, 1, &type_payload);
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 3, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat → 4.2
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon → -10.5
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt → 1500
    // Trailing bytes exist in the row (sample_size 32) but are NOT described
    // by TYPE, so they must be ignored.
    row.extend_from_slice(&999i32.to_be_bytes());
    row.extend_from_slice(&999i32.to_be_bytes());
    row.extend_from_slice(&7000i32.to_be_bytes());
    row.extend_from_slice(&12_345i32.to_be_bytes());
    row.extend_from_slice(&150u16.to_be_bytes());
    row.extend_from_slice(&3u16.to_be_bytes());
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut strm_body = Vec::new();
    strm_body.extend_from_slice(&type_rec);
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps9);
    let strm = klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let samples = out.gps_samples();
    assert_eq!(samples.len(), 1);
    let s = &samples[0];
    // Only the 3 TYPE-described columns are decoded.
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((s.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
    // Columns past the short TYPE were never read — no speed, no datetime, no
    // DOP, no measure-mode.
    assert_eq!(s.speed_2d_mps(), None);
    assert_eq!(s.speed_3d_mps(), None);
    assert_eq!(s.date_time(), None);
    assert_eq!(s.dop(), None);
    assert_eq!(s.measure_mode(), None);
  }

  #[test]
  fn gps9_with_invalid_type_byte_truncates_at_that_column() {
    // R4-B fallback: a TYPE whose 3rd byte is an INVALID format code (0x00 is
    // not in %goProFmt). GoPro.pm:854 `$f = $goProFmt{$b} or last` stops the
    // column walk there, so only the first two columns (lat, lon) decode.
    let type_payload = [0x6cu8, 0x6c, 0x00, 0x6c]; // 'l','l',<invalid>,'l'
    let type_rec = klv(b"TYPE", 0x63, 4, 1, &type_payload);
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x4c, 4, 2, &scal_payload);
    let mut row = Vec::new();
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat → 4.2
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon → -10.5
    for _ in 0..6 {
      row.extend_from_slice(&123i32.to_be_bytes());
    }
    let gps9 = klv(b"GPS9", 0x3f, 32, 1, &row);
    let mut strm_body = Vec::new();
    strm_body.extend_from_slice(&type_rec);
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps9);
    let strm = klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
    // The invalid 3rd TYPE byte stopped the walk — altitude and beyond unset.
    assert_eq!(s.altitude_m(), None);
    assert_eq!(s.measure_mode(), None);
  }

  #[test]
  fn resolve_complex_columns_standard_gps9_type_offsets() {
    // White-box: the standard `lllllllSS` TYPE resolves to the exact fixed
    // offsets the pre-fix code hardcoded — proving the standard path is
    // byte-identical. len=32 (the GPS9 row stride).
    let type_bytes = [0x6cu8, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x53, 0x53];
    let cols = resolve_complex_columns(&type_bytes, 32);
    let offsets: Vec<usize> = cols.iter().map(|c| c.offset).collect();
    assert_eq!(offsets, vec![0, 4, 8, 12, 16, 20, 24, 28, 30]);
    assert_eq!(cols.len(), 9);
  }

  #[test]
  fn resolve_complex_columns_stops_when_column_overflows_row() {
    // GoPro.pm:856 `last if $p + $l > $len`: with a row stride of only 10
    // bytes, the standard `lllllllSS` TYPE resolves just 2 `l` columns
    // (offset 0 and 4); a 3rd would reach offset 8..12 > 10.
    let type_bytes = [0x6cu8, 0x6c, 0x6c, 0x6c];
    let cols = resolve_complex_columns(&type_bytes, 10);
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0].offset, 0);
    assert_eq!(cols[1].offset, 4);
  }

  // ==========================================================================
  // R5 — Karma GLPI (`GPSPos`) + KBAT (`BatteryStatus`) + SYST `ConvertSystemTime`.
  // Byte fixtures + expected values pinned against `perl exiftool` 13.59's
  // `Image::ExifTool::GoPro::ProcessGoPro` (oracle in the PR notes): the
  // standard `TYPE`/`SCAL` from GoPro.pm:200-201 (GLPI) / 267-268 (KBAT).
  // ==========================================================================

  /// The standard Karma GLPI `TYPE` record — `LllllsssS` (GoPro.pm:200):
  /// 1×L + 4×l (int32) + 3×s (int16s) + 1×S (int16u) = 4+16+6+2 = 28 bytes/row.
  fn glpi_standard_type() -> Vec<u8> {
    // 'L'=0x4c 'l'=0x6c 's'=0x73 'S'=0x53.
    klv(
      b"TYPE",
      0x63,
      9,
      1,
      &[0x4c, 0x6c, 0x6c, 0x6c, 0x6c, 0x73, 0x73, 0x73, 0x53],
    )
  }

  /// The canonical GLPI SCAL (GoPro.pm:201): 9 int32u factors.
  fn glpi_scal() -> Vec<u8> {
    let p: Vec<u8> = [
      1000u32, 10_000_000, 10_000_000, 1000, 1000, 100, 100, 100, 100,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    klv(b"SCAL", 0x4c, 4, 9, &p)
  }

  /// One GLPI row: systime=5000(→5.0), lat=42e6(→4.2), lon=-105e6(→-10.5),
  /// alt=1_500_000(→1500), unk4=2000(→2.0), spdX=150(→1.5), spdY=250(→2.5),
  /// spdZ=-100(→-1.0), track=18000(→180.0). Mirrors the PR oracle row.
  fn glpi_row() -> Vec<u8> {
    let mut row = Vec::new();
    row.extend_from_slice(&5000u32.to_be_bytes()); // L systime
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // l lat
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // l lon
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // l alt
    row.extend_from_slice(&2000i32.to_be_bytes()); // l unk4
    row.extend_from_slice(&150i16.to_be_bytes()); // s spdX
    row.extend_from_slice(&250i16.to_be_bytes()); // s spdY
    row.extend_from_slice(&(-100i16).to_be_bytes()); // s spdZ
    row.extend_from_slice(&18000u16.to_be_bytes()); // S track
    row
  }

  #[test]
  fn glpi_karma_decodes_position_columns() {
    // STRM { TYPE, SCAL, GLPI } — GLPI last so the GoPro.pm:884 SCAL guard
    // fires. No SYST ⇒ GPSDateTime resolves to the `<uncalibrated>` literal.
    let mut body = Vec::new();
    body.extend_from_slice(&glpi_standard_type());
    body.extend_from_slice(&glpi_scal());
    body.extend_from_slice(&klv(b"GLPI", 0x3f, 28, 1, &glpi_row()));
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let g = &out.glpi_samples()[0];
    assert!((g.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((g.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((g.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
    assert!((g.speed_x_mps().unwrap() - 1.5).abs() < 1e-6);
    assert!((g.speed_y_mps().unwrap() - 2.5).abs() < 1e-6);
    assert!((g.speed_z_mps().unwrap() + 1.0).abs() < 1e-6);
    assert!((g.track_deg().unwrap() - 180.0).abs() < 1e-6);
    // No SYST calibration ⇒ ConvertSystemTime returns the `<uncalibrated>`
    // literal (oracle: GoPro.pm:680).
    assert_eq!(g.date_time(), Some("<uncalibrated>"));
  }

  #[test]
  fn glpi_karma_gpsdatetime_uses_syst_calibration() {
    // Two single-row SYST STRMs build the SystemTimeList = [(0,…800),(10,…810)]
    // (GoPro.pm:398 needs @v==2 per row ⇒ count=1). GLPI systime=5.0 then
    // interpolates to unix 1551484805 (a WHOLE number) ⇒ the GoPro.pm:700-701
    // `^(\d+)(\.\d+)` regex quirk yields the all-zero `0000:00:00 00:00:00`.
    let syst_type = klv(b"TYPE", 0x63, 2, 1, &[0x4a, 0x4a]); // 'JJ'
    let syst_scal_p: Vec<u8> = [1_000_000u32, 1000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let syst_scal = klv(b"SCAL", 0x4c, 4, 2, &syst_scal_p);
    let mk_syst = |sys: u64, unix_ms: u64| {
      let mut r = Vec::new();
      r.extend_from_slice(&sys.to_be_bytes());
      r.extend_from_slice(&unix_ms.to_be_bytes());
      klv(b"SYST", 0x3f, 16, 1, &r)
    };
    let mk_syst_strm = |sys: u64, unix_ms: u64| {
      let mut b = Vec::new();
      b.extend_from_slice(&syst_type);
      b.extend_from_slice(&syst_scal);
      b.extend_from_slice(&mk_syst(sys, unix_ms));
      klv(b"STRM", 0, 1, b.len() as u16, &b)
    };
    let mut glpi_body = Vec::new();
    glpi_body.extend_from_slice(&glpi_standard_type());
    glpi_body.extend_from_slice(&glpi_scal());
    glpi_body.extend_from_slice(&klv(b"GLPI", 0x3f, 28, 1, &glpi_row()));
    let glpi_strm = klv(b"STRM", 0, 1, glpi_body.len() as u16, &glpi_body);
    let mut devc_body = Vec::new();
    devc_body.extend_from_slice(&mk_syst_strm(0, 1_551_484_800_000));
    devc_body.extend_from_slice(&mk_syst_strm(10_000_000, 1_551_484_810_000));
    devc_body.extend_from_slice(&glpi_strm);
    let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&devc, &mut out));
    assert_eq!(
      out.system_time_list().len(),
      2,
      "two SYST calibration pairs"
    );
    let g = &out.glpi_samples()[0];
    // systime 5.0 → interpolated unix 1551484805.0 (whole) → quirk all-zero.
    assert_eq!(g.date_time(), Some("0000:00:00 00:00:00"));
  }

  /// Build a `STRM { TYPE=JJ, SCAL=1000000 1000, SYST }` STRM with `count` rows
  /// (each row `(systime_raw, unix_ms_raw)`), wrapped in a DEVC.
  fn syst_devc(rows: &[(u64, u64)]) -> Vec<u8> {
    let syst_type = klv(b"TYPE", 0x63, 1, 2, b"JJ"); // 'JJ'
    let syst_scal_p: Vec<u8> = [1_000_000u32, 1000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let syst_scal = klv(b"SCAL", 0x4c, 4, 2, &syst_scal_p);
    let mut payload = Vec::new();
    for (sys, unix_ms) in rows {
      payload.extend_from_slice(&sys.to_be_bytes());
      payload.extend_from_slice(&unix_ms.to_be_bytes());
    }
    let syst = klv(b"SYST", 0x3f, 16, rows.len() as u16, &payload);
    let mut body = Vec::new();
    body.extend_from_slice(&syst_type);
    body.extend_from_slice(&syst_scal);
    body.extend_from_slice(&syst);
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    klv(b"DEVC", 0, 1, strm.len() as u16, &strm)
  }

  #[test]
  fn syst_single_row_calibrates_and_emits_system_time() {
    // R6-A/R6-B. Oracle (`perl exiftool` 13.59 ProcessGoPro): a count==1 SYST
    // (`$val = $v[0]` scalar → RawConv `split` yields @v==2) pushes ONE
    // calibration pair AND emits `SystemTime = "5 1551484800"` (the post-SCAL
    // 2-column scaled join: 5000000/1000000=5, 1551484800000/1000=1551484800).
    let devc = syst_devc(&[(5_000_000, 1_551_484_800_000)]);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&devc, &mut out));
    assert_eq!(
      out.system_time_list(),
      &[(5.0, 1_551_484_800.0)],
      "single-row SYST is one calibration pair"
    );
    assert_eq!(
      out.system_time(),
      Some("5 1551484800"),
      "SystemTime display = post-SCAL 2-column join"
    );
  }

  #[test]
  fn syst_two_rows_not_calibrated_but_system_time_emitted() {
    // R6-A/R6-B. Oracle (`perl exiftool` 13.59 ProcessGoPro): a count==2 SYST
    // decodes to an ARRAYREF (`$val = \@v`); the RawConv `split ' ', $val` on
    // the stringified arrayref does NOT yield @v==2, so NO calibration pair is
    // pushed. `SystemTime` is still emitted as the rows joined with ", "
    // (`"5 1551484800, 10 1551484810"`).
    let devc = syst_devc(&[
      (5_000_000, 1_551_484_800_000),
      (10_000_000, 1_551_484_810_000),
    ]);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&devc, &mut out));
    assert!(
      out.system_time_list().is_empty(),
      "a count>1 SYST is NOT a calibration pair (arrayref does not split to 2)"
    );
    assert_eq!(
      out.system_time(),
      Some("5 1551484800, 10 1551484810"),
      "multi-row SystemTime joins rows with ', '"
    );
  }

  #[test]
  fn syst_count_two_does_not_calibrate_following_glpi() {
    // R6-A end-to-end: a count==2 SYST must NOT calibrate, so a FOLLOWING GLPI
    // resolves GPSDateTime to the `<uncalibrated>` literal (NOT an interpolated
    // datetime). Contrast `glpi_karma_gpsdatetime_uses_syst_calibration` (two
    // SEPARATE count==1 SYSTs DO calibrate).
    let syst_type = klv(b"TYPE", 0x63, 1, 2, b"JJ");
    let syst_scal_p: Vec<u8> = [1_000_000u32, 1000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let syst_scal = klv(b"SCAL", 0x4c, 4, 2, &syst_scal_p);
    // ONE SYST record carrying TWO rows (count=2).
    let mut syst_payload = Vec::new();
    syst_payload.extend_from_slice(&5_000_000u64.to_be_bytes());
    syst_payload.extend_from_slice(&1_551_484_800_000u64.to_be_bytes());
    syst_payload.extend_from_slice(&10_000_000u64.to_be_bytes());
    syst_payload.extend_from_slice(&1_551_484_810_000u64.to_be_bytes());
    let syst = klv(b"SYST", 0x3f, 16, 2, &syst_payload);
    let mut syst_body = Vec::new();
    syst_body.extend_from_slice(&syst_type);
    syst_body.extend_from_slice(&syst_scal);
    syst_body.extend_from_slice(&syst);
    let syst_strm = klv(b"STRM", 0, 1, syst_body.len() as u16, &syst_body);

    let mut glpi_body = Vec::new();
    glpi_body.extend_from_slice(&glpi_standard_type());
    glpi_body.extend_from_slice(&glpi_scal());
    glpi_body.extend_from_slice(&klv(b"GLPI", 0x3f, 28, 1, &glpi_row()));
    let glpi_strm = klv(b"STRM", 0, 1, glpi_body.len() as u16, &glpi_body);

    let mut devc_body = Vec::new();
    devc_body.extend_from_slice(&syst_strm);
    devc_body.extend_from_slice(&glpi_strm);
    let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);

    let mut out = GoProMeta::new();
    assert!(process_gopro(&devc, &mut out));
    assert!(
      out.system_time_list().is_empty(),
      "count==2 SYST must not calibrate"
    );
    let g = &out.glpi_samples()[0];
    assert_eq!(
      g.date_time(),
      Some("<uncalibrated>"),
      "uncalibrated GLPI GPSDateTime when the preceding SYST was count==2"
    );
  }

  #[test]
  fn glpi_gpsdatetime_fractional_epoch_renders_real_date() {
    // A SYST list whose interpolation lands on a FRACTIONAL epoch resolves to a
    // real date with the fraction appended (GoPro.pm:701). systime=2.5 between
    // (0,…800) and (10,…810) ⇒ 1551484802.5 → '2019:03:02 00:00:02.5'.
    let list = [(0.0_f64, 1_551_484_800.0_f64), (10.0, 1_551_484_810.0)];
    assert_eq!(
      convert_system_time(&list, 2.5).as_deref(),
      Some("2019:03:02 00:00:02.5")
    );
    // Exact-integer interpolation (systime 5.0 → 1551484805.0) → all-zero quirk.
    assert_eq!(
      convert_system_time(&list, 5.0).as_deref(),
      Some("0000:00:00 00:00:00")
    );
    // Empty list → `<uncalibrated>`.
    assert_eq!(
      convert_system_time(&[], 5.0).as_deref(),
      Some("<uncalibrated>")
    );
  }

  #[test]
  fn convert_system_time_matches_exiftool_edge_cases() {
    // Oracle: `Image::ExifTool::GoPro::ConvertSystemTime` 13.59. ExifTool does
    // NOT clamp out-of-range system times — the binary search picks the
    // bracketing endpoints and the linear formula EXTRAPOLATES beyond them.
    // Single-entry list ⇒ `i==j` ⇒ that entry's unix time verbatim.
    assert_eq!(
      convert_system_time(&[(0.0, 1_551_484_800.5)], 5.0).as_deref(),
      Some("2019:03:02 00:00:00.5"),
    );
    // Below the range (systime -3) — extrapolated, NOT clamped.
    assert_eq!(
      convert_system_time(&[(0.0, 1_551_484_800.5), (10.0, 1_551_484_810.5)], -3.0).as_deref(),
      Some("2019:03:01 23:59:57.5"),
    );
    // Above the range (systime 20) — extrapolated.
    assert_eq!(
      convert_system_time(&[(0.0, 1_551_484_800.5), (10.0, 1_551_484_810.5)], 20.0).as_deref(),
      Some("2019:03:02 00:00:20.5"),
    );
    // Three entries — the binary search selects the (5,10) bracket for
    // systime 6.0 ⇒ 1551484806.06 → '...:06.06'.
    assert_eq!(
      convert_system_time(
        &[
          (0.0, 1_551_484_800.0),
          (5.0, 1_551_484_805.0),
          (10.0, 1_551_484_810.3),
        ],
        6.0,
      )
      .as_deref(),
      Some("2019:03:02 00:00:06.06"),
    );
    // Unsorted input is sorted by system time before search (ExifTool's lazy
    // sort, GoPro.pm:681-684) — same result regardless of input order.
    assert_eq!(
      convert_system_time(
        &[
          (10.0, 1_551_484_810.3),
          (0.0, 1_551_484_800.0),
          (5.0, 1_551_484_805.0),
        ],
        6.0,
      )
      .as_deref(),
      Some("2019:03:02 00:00:06.06"),
    );
  }

  #[test]
  fn kbat_karma_decodes_battery_columns() {
    // STRM { TYPE, SCAL, KBAT } with the standard `lLlsSSSSSSSBBBb` TYPE
    // (GoPro.pm:267) and SCAL (GoPro.pm:268). Row pinned to the PR oracle:
    // current 1.5 A, capacity 2 Ah, temp 35 C, V1-4 4/4.1/4.2/4.3,
    // time 10 s, level 95 %.
    let kbat_type = klv(
      b"TYPE",
      0x63,
      15,
      1,
      // 'l'0x6c 'L'0x4c 'l'0x6c 's'0x73 'S'0x53×7 'B'0x42×3 'b'0x62
      &[
        0x6c, 0x4c, 0x6c, 0x73, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0x42, 0x42, 0x42, 0x62,
      ],
    );
    // SCAL as big-endian float32 (fmt 'f' = 0x66) so the fractional factors
    // (col 2 ≈ 0.01, col 8 ≈ 0.0167) survive.
    // 0.01f32 and 0.016_666_668f32 are the exact f32 round-trips of ExifTool's
    // stored SCAL factors 0.00999999977648258 / 0.0166666675359011
    // (GoPro.pm:268) — same 32-bit pattern, no excessive-precision lint.
    let ks = [
      1000.0f32,
      1000.0,
      0.01,
      100.0,
      1000.0,
      1000.0,
      1000.0,
      1000.0,
      0.016_666_668,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
    ];
    let scal_p: Vec<u8> = ks.iter().flat_map(|v| v.to_be_bytes()).collect();
    let kbat_scal = klv(b"SCAL", 0x66, 4, 15, &scal_p);
    // Row: offsets l@0 L@4 l@8 s@12 S@14 S@16 S@18 S@20 S@22 S@24 S@26 B@28 B@29 B@30 b@31.
    let mut row = Vec::new();
    row.extend_from_slice(&1500i32.to_be_bytes()); // col0 current →1.5
    row.extend_from_slice(&2000u32.to_be_bytes()); // col1 capacity →2
    row.extend_from_slice(&100i32.to_be_bytes()); // col2 unk2(J) dropped
    row.extend_from_slice(&3500i16.to_be_bytes()); // col3 temp →35
    row.extend_from_slice(&4000u16.to_be_bytes()); // col4 V1 →4
    row.extend_from_slice(&4100u16.to_be_bytes()); // col5 V2 →4.1
    row.extend_from_slice(&4200u16.to_be_bytes()); // col6 V3 →4.2
    row.extend_from_slice(&4300u16.to_be_bytes()); // col7 V4 →4.3
    row.extend_from_slice(&600u16.to_be_bytes()); // col8 time →10s
    row.extend_from_slice(&88u16.to_be_bytes()); // col9 unk9(%) dropped
    row.extend_from_slice(&7u16.to_be_bytes()); // col10 unk10 dropped
    row.push(11); // col11 B dropped
    row.push(12); // col12 B dropped
    row.push(13); // col13 B dropped
    row.extend_from_slice(&95i8.to_be_bytes()); // col14 level →95
    let kbat = klv(b"KBAT", 0x3f, 32, 1, &row);
    let mut body = Vec::new();
    body.extend_from_slice(&kbat_type);
    body.extend_from_slice(&kbat_scal);
    body.extend_from_slice(&kbat);
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let k = &out.kbat_records()[0];
    assert!((k.current_a().unwrap() - 1.5).abs() < 1e-4);
    assert!((k.capacity_ah().unwrap() - 2.0).abs() < 1e-4);
    assert!((k.temperature_c().unwrap() - 35.0).abs() < 1e-4);
    assert!((k.voltage1_v().unwrap() - 4.0).abs() < 1e-4);
    assert!((k.voltage2_v().unwrap() - 4.1).abs() < 1e-4);
    assert!((k.voltage3_v().unwrap() - 4.2).abs() < 1e-4);
    assert!((k.voltage4_v().unwrap() - 4.3).abs() < 1e-4);
    // BatteryTime is the raw scaled SECONDS (600 / 0.0166666… ≈ 36000 s);
    // the `ConvertDuration` PrintConv is deferred.
    assert!((k.time_s().unwrap() - 36000.0).abs() < 1.0);
    assert!((k.level_pct().unwrap() - 95.0).abs() < 1e-4);
  }

  #[test]
  fn gpri_karma_is_dropped_as_unknown() {
    // GPRI (`GPSRaw`, GoPro.pm:205-213) carries `Unknown => 1` (GoPro.pm:210),
    // so bundled `exiftool -ee` does NOT emit it in default mode — the walker
    // visits the record but the typed surface stays empty for it. (The walk
    // still advances; a trailing DVNM sibling is decoded.) GPRI uses
    // `TYPE=JlllSSSSBB` (GoPro.pm:208) — here we just confirm it is ignored.
    let gpri_type = klv(
      b"TYPE",
      0x63,
      10,
      1,
      &[0x4a, 0x6c, 0x6c, 0x6c, 0x53, 0x53, 0x53, 0x53, 0x42, 0x42],
    );
    // A plausible GPRI row (28 bytes: J8 l4 l4 l4 S2 S2 S2 S2 B1 B1 = 30? — the
    // exact bytes don't matter since GPRI must be dropped). Use a 30-byte row.
    let mut row = vec![0u8; 30];
    row[0] = 0x12; // arbitrary
    let gpri = klv(b"GPRI", 0x3f, 30, 1, &row);
    let dvnm = klv(b"DVNM", 0x63, 5, 1, b"Karma");
    let mut body = Vec::new();
    body.extend_from_slice(&gpri_type);
    body.extend_from_slice(&gpri);
    body.extend_from_slice(&dvnm);
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    // GPRI emits NO typed surface (it is not in the GLPI/KBAT/GPS dispatch).
    assert!(out.glpi_samples().is_empty(), "GPRI must not populate GLPI");
    assert!(out.gps_samples().is_empty(), "GPRI must not populate GPS");
    assert!(out.kbat_records().is_empty(), "GPRI must not populate KBAT");
    // The sibling after GPRI was still decoded (the walk continued).
    assert_eq!(out.device_name(), Some("Karma"));
  }

  #[test]
  fn glpi_with_absent_type_emits_no_sample() {
    // Like GPS9 (GoPro.pm:848 `defined $type`): without a preceding TYPE the
    // complex `?` decode is skipped ⇒ no GLPI sample.
    let mut body = Vec::new();
    body.extend_from_slice(&glpi_scal());
    body.extend_from_slice(&klv(b"GLPI", 0x3f, 28, 1, &glpi_row()));
    let mut out = GoProMeta::new();
    assert!(process_gopro(&body, &mut out));
    assert!(out.glpi_samples().is_empty());
  }

  // ==========================================================================
  // R12-A — the FULL default-visible %GoPro::GPMF tag set (table-driven). The
  // expected decoded values are oracle-pinned against `perl exiftool 13.59 -ee`
  // (see the conformance fixture QuickTime_gopro_gpmf.mov for the byte-exact
  // end-to-end check; these unit tests pin the parse-layer decode).
  // ==========================================================================

  /// Find a decoded generic tag by name.
  fn generic<'a>(out: &'a GoProMeta, name: &str) -> Option<&'a GoProTagValue> {
    out
      .generic_tags()
      .iter()
      .find(|t| t.name() == name)
      .map(GoProTag::value)
  }

  #[test]
  fn generic_scalar_string_and_numeric_tags_decode() {
    // Plain string config tags (`c`) and numeric tags decode to Str/Num.
    let mut buf = Vec::new();
    buf.extend_from_slice(&klv(b"PTWB", 0x63, 4, 1, b"AUTO")); // WhiteBalance
    buf.extend_from_slice(&klv(b"EXPT", 0x63, 6, 1, b"MANUAL")); // ExposureType
    buf.extend_from_slice(&klv(b"CPIN", 0x4c, 4, 1, &3u32.to_be_bytes())); // ChapterNumber
    buf.extend_from_slice(&klv(b"PIMX", 0x4c, 4, 1, &1600u32.to_be_bytes())); // AutoISOMax
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    assert_eq!(
      generic(&out, "WhiteBalance"),
      Some(&GoProTagValue::Str("AUTO".into()))
    );
    assert_eq!(
      generic(&out, "ExposureType"),
      Some(&GoProTagValue::Str("MANUAL".into()))
    );
    assert_eq!(
      generic(&out, "ChapterNumber"),
      Some(&GoProTagValue::Num(3.0))
    );
    assert_eq!(
      generic(&out, "AutoISOMax"),
      Some(&GoProTagValue::Num(1600.0))
    );
  }

  #[test]
  fn generic_stmp_value_conv_divides_by_1e6() {
    // STMP `ValueConv => '$val / 1e6'` (GoPro.pm:377-380), fmt `J` int64u.
    let buf = klv(b"STMP", 0x4a, 8, 1, &12_345_678u64.to_be_bytes());
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    assert_eq!(
      generic(&out, "TimeStamp"),
      Some(&GoProTagValue::Num(12.345678))
    );
  }

  #[test]
  fn generic_cdat_converts_unix_time() {
    // CDAT `RawConv => 'ConvertUnixTime($val)'` (GoPro.pm:122-127), fmt `L`.
    // 1551484800 ⇒ 2019:03:02 00:00:00 (no forced millis, 2-arg form).
    let buf = klv(b"CDAT", 0x4c, 4, 1, &1_551_484_800u32.to_be_bytes());
    let mut out = GoProMeta::new();
    assert!(process_gopro(&buf, &mut out));
    assert_eq!(
      generic(&out, "CreationDate"),
      Some(&GoProTagValue::Str("2019:03:02 00:00:00".into()))
    );
  }

  #[test]
  fn generic_binary_sensor_stream_decodes_scaled_value_for_placeholder_len() {
    // ACCL (`Binary => 1`) — the typed value is the post-SCAL flat list; the
    // emission renders the `(Binary data N bytes…)` placeholder where N is the
    // length of THIS list's string. Oracle (exiftool -ee -b): SCAL=418 (s),
    // rows (836,1254,-209),(418,836,1672) ⇒ "2 3 -0.5 1 2 4" (14 chars).
    let scal = klv(b"SCAL", 0x73, 2, 1, &418i16.to_be_bytes());
    let mut data = Vec::new();
    let rows: [(i16, i16, i16); 2] = [(836, 1254, -209), (418, 836, 1672)];
    for &(x, y, z) in &rows {
      data.extend_from_slice(&x.to_be_bytes());
      data.extend_from_slice(&y.to_be_bytes());
      data.extend_from_slice(&z.to_be_bytes());
    }
    let accl = klv(b"ACCL", 0x73, 6, 2, &data);
    let mut body = Vec::new();
    body.extend_from_slice(&scal);
    body.extend_from_slice(&accl);
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    // The decoded value is the flat scaled list (rendered to the placeholder at
    // emission). 836/418=2, 1254/418=3, -209/418=-0.5, 418/418=1, 836/418=2,
    // 1672/418=4.
    let GoProTagValue::NumList(vals) = generic(&out, "Accelerometer").expect("ACCL") else {
      panic!("ACCL must decode to a NumList");
    };
    let expect = [2.0, 3.0, -0.5, 1.0, 2.0, 4.0];
    assert_eq!(vals.len(), 6);
    for (g, e) in vals.iter().zip(expect) {
      assert!((g - e).abs() < 1e-9, "ACCL value {g} != {e}");
    }
    // The space-joined string is "2 3 -0.5 1 2 4" = 14 chars (the oracle's N).
    assert_eq!(join_g(vals).len(), 14);
  }

  #[test]
  fn generic_plain_multivalue_flat_list_across_rows() {
    // MAGN (plain, NOT Binary) with 2 rows ⇒ ONE flat space-joined list of all
    // values (GoPro.pm:869 ReadValue flat). SCAL=100 ⇒ /100.
    let scal = klv(b"SCAL", 0x73, 2, 1, &100i16.to_be_bytes());
    let mut data = Vec::new();
    for v in [10i16, 20, 30, 40, 50, 60] {
      data.extend_from_slice(&v.to_be_bytes());
    }
    let magn = klv(b"MAGN", 0x73, 6, 2, &data);
    let mut body = Vec::new();
    body.extend_from_slice(&scal);
    body.extend_from_slice(&magn);
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let GoProTagValue::NumList(vals) = generic(&out, "Magnetometer").expect("MAGN") else {
      panic!("MAGN must decode to a flat NumList");
    };
    assert_eq!(vals.len(), 6, "all 6 values in one flat list");
    assert!((vals[0] - 0.1).abs() < 1e-9 && (vals[5] - 0.6).abs() < 1e-9);
  }

  #[test]
  fn generic_complex_record_single_and_multi_row() {
    // VFRH (`BinaryData => 1` — NOT Binary => 1) is a complex `?` (TYPE=ffffsS).
    // Single row ⇒ Rows([one]); the emission renders a scalar string. No SCAL.
    let type_rec = klv(b"TYPE", 0x63, 6, 1, b"ffffsS");
    let row1 = {
      let mut r = Vec::new();
      for f in [1.0f32, 2.0, 3.0, 4.0] {
        r.extend_from_slice(&f.to_be_bytes());
      }
      r.extend_from_slice(&5i16.to_be_bytes());
      r.extend_from_slice(&6u16.to_be_bytes());
      r
    };
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&klv(b"VFRH", 0x3f, 20, 1, &row1));
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    assert_eq!(
      generic(&out, "VisualFlightRulesHUD"),
      Some(&GoProTagValue::Rows(alloc::vec![SmolStr::from(
        "1 2 3 4 5 6"
      )]))
    );
  }

  #[test]
  fn generic_complex_row_keeps_fourcc_and_string_columns() {
    // SCEN (`SceneClassification`, GoPro.pm:482) is a complex `?` whose TYPE
    // (GoPro.pm:414 example `…Ff…`) carries an `F` (4-char FourCC, `undef`)
    // column followed by an `f` float probability. The generic decoder must
    // KEEP the FourCC column and join it with the scaled float
    // (`ReadValue 'undef'` = raw bytes; GoPro.pm:857-861 `join ' ', @s`), NOT
    // truncate the row at the first non-numeric column. Two rows
    // ⇒ Rows(["SNOW 0.875", "URBA 0.125"]); no SCAL ⇒ the float passes through.
    // The probabilities are exactly-representable f32 values so `%.15g` renders
    // them cleanly (an inexact value like 0.85f32 would print 0.850000023841858,
    // which is equally faithful but noisy for a fixture).
    let type_rec = klv(b"TYPE", 0x63, 2, 1, b"Ff");
    let mut rows = Vec::new();
    for (id, p) in [(&b"SNOW"[..], 0.875f32), (b"URBA", 0.125)] {
      rows.extend_from_slice(id);
      rows.extend_from_slice(&p.to_be_bytes());
    }
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    // Row stride len = 8 (F=4 + f=4); count = 2.
    body.extend_from_slice(&klv(b"SCEN", 0x3f, 8, 2, &rows));
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    assert_eq!(
      generic(&out, "SceneClassification"),
      Some(&GoProTagValue::Rows(alloc::vec![
        SmolStr::from("SNOW 0.875"),
        SmolStr::from("URBA 0.125"),
      ])),
      "the F FourCC column must survive and join with the float, not be dropped"
    );
  }

  #[test]
  fn generic_complex_row_leading_fourcc_then_string_column() {
    // A column ordering with a `c` (string, 1 byte NUL-trimmed) AFTER the `F`
    // FourCC + a numeric, proving each `%goProFmt` column type round-trips and
    // a `c` column reads exactly ONE byte (FormatSize('string')==1). TYPE=`FBc`
    // ⇒ [4-byte FourCC][1-byte int8u][1-byte char]; row "WATR" + 7 + 'X'.
    let type_rec = klv(b"TYPE", 0x63, 3, 1, b"FBc");
    let mut row = Vec::new();
    row.extend_from_slice(b"WATR");
    row.push(7u8); // B int8u → "7"
    row.push(b'X'); // c → "X"
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&klv(b"SCEN", 0x3f, 6, 1, &row));
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    assert_eq!(
      generic(&out, "SceneClassification"),
      Some(&GoProTagValue::Rows(alloc::vec![SmolStr::from("WATR 7 X")]))
    );
  }

  #[test]
  fn generic_addunits_captures_unit_strings() {
    // SCPR (`%addUnits`, complex `?` TYPE=Lffs, UNIT=s,Pa,Pa,degC). The decoded
    // value is the scaled per-row string; the captured units ride on the tag.
    let unit_payload = {
      // 4 units, each 4-wide NUL-padded: 's','Pa','Pa','degC'.
      let mut p = Vec::new();
      for u in [&b"s\0\0\0"[..], b"Pa\0\0", b"Pa\0\0", b"degC"] {
        p.extend_from_slice(u);
      }
      p
    };
    let unit = klv(b"UNIT", 0x63, 4, 4, &unit_payload);
    let type_rec = klv(b"TYPE", 0x63, 4, 1, b"Lffs");
    let scal_p: Vec<u8> = [1000.0f32, 0.01, 0.01, 100.0]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = klv(b"SCAL", 0x66, 4, 4, &scal_p);
    // Row: L=5000(→5), f=50.0(→5000), f=70.0(→7000), s=3500(→35).
    let mut row = Vec::new();
    row.extend_from_slice(&5000u32.to_be_bytes());
    row.extend_from_slice(&50.0f32.to_be_bytes());
    row.extend_from_slice(&70.0f32.to_be_bytes());
    row.extend_from_slice(&3500i16.to_be_bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&unit);
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&scal);
    body.extend_from_slice(&klv(b"SCPR", 0x3f, 14, 1, &row));
    let strm = klv(b"STRM", 0, 1, body.len() as u16, &body);
    let mut out = GoProMeta::new();
    assert!(process_gopro(&strm, &mut out));
    let tag = out
      .generic_tags()
      .iter()
      .find(|t| t.name() == "ScaledPressure")
      .expect("SCPR");
    assert_eq!(tag.conv(), GoProConv::AddUnits);
    assert_eq!(tag.units(), &["s", "Pa", "Pa", "degC"]);
    // The value is the scaled single-row string.
    let GoProTagValue::Rows(rows) = tag.value() else {
      panic!("SCPR must decode to Rows");
    };
    assert_eq!(rows.len(), 1);
    assert!(
      rows[0].starts_with("5 5000") && rows[0].ends_with("35"),
      "SCPR scaled row: {}",
      rows[0]
    );
  }

  #[test]
  fn deferred_and_sibling_tags_are_not_emitted_as_generic() {
    // SCAL/TYPE/UNIT/SIUN (sibling state) and Unknown/Hidden tags (DVID/EMPT/
    // TSMP/STNM) must NOT appear in the generic surface — GoPro.pm:876-877
    // `next unless $unknown` + they are walker state, not emitted tags.
    let mut buf = Vec::new();
    buf.extend_from_slice(&klv(b"DVID", 0x4c, 4, 1, &1u32.to_be_bytes())); // Unknown
    buf.extend_from_slice(&klv(b"TSMP", 0x4c, 4, 1, &100u32.to_be_bytes())); // Unknown
    buf.extend_from_slice(&klv(b"STNM", 0x63, 4, 1, b"ACCL")); // Unknown
    buf.extend_from_slice(&klv(b"SCAL", 0x73, 2, 1, &100i16.to_be_bytes())); // sibling
    buf.extend_from_slice(&klv(b"WXYZ", 0x4c, 4, 1, &1u32.to_be_bytes())); // not in table
    let mut out = GoProMeta::new();
    let _ = process_gopro(&buf, &mut out);
    assert!(
      out.generic_tags().is_empty(),
      "no deferred / sibling / unknown tag is emitted as a generic tag"
    );
  }

  #[test]
  fn generic_tag_table_excludes_typed_and_deferred() {
    // The table must NOT claim the typed tags (they are handled by their own
    // arms) nor the deferred siblings.
    for typed in [
      b"DVNM", b"MINF", b"CASN", b"FMWR", b"MUID", b"GPSU", b"GPSF", b"GPSP", b"GPSA", b"GPS5",
      b"GPS9", b"GLPI", b"KBAT", b"SYST", b"DEVC", b"STRM",
    ] {
      assert!(
        generic_tag_def(typed).is_none(),
        "{} must not be in the generic table (typed/container)",
        core::str::from_utf8(typed).unwrap()
      );
    }
    for deferred in [
      &b"DVID"[..],
      b"EMPT",
      b"ESCS",
      b"GPRI",
      b"SCAL",
      b"SIUN",
      b"STNM",
      b"TSMP",
      b"TYPE",
      b"UNIT",
      b"BPOS",
    ] {
      assert!(
        generic_tag_def(deferred).is_none(),
        "{} must not be in the generic table (Unknown/Hidden)",
        core::str::from_utf8(deferred).unwrap()
      );
    }
    // A representative default-visible tag IS in the table.
    assert_eq!(
      generic_tag_def(b"ACCL"),
      Some(("Accelerometer", GoProConv::Binary))
    );
    assert_eq!(
      generic_tag_def(b"PRTN"),
      Some(("Protune", GoProConv::Protune))
    );
  }

  #[test]
  fn read_latin1_decodes_high_bytes() {
    // 0xE9 = é in Latin-1 ⇒ the Unicode code point U+00E9.
    assert_eq!(read_latin1(b"caf\xe9\0\0").as_deref(), Some("caf\u{e9}"));
    // A NON-zero-size all-NUL payload NUL-trims to the EMPTY STRING and still
    // decodes (GoPro.pm:845 skips only `$size == 0`); `None` is reserved for a
    // genuinely empty (`$size == 0`) payload, which `visit` filters upstream.
    assert_eq!(read_latin1(b"\0\0").as_deref(), Some(""));
    assert_eq!(read_latin1(b"").as_deref(), None);
  }

  #[test]
  fn read_ascii_all_nul_is_empty_string_not_none() {
    // Parallel faithfulness contract to `read_latin1`: a non-zero-size all-NUL
    // payload decodes to "" (so every `c`/string tag — typed identity, generic,
    // GPSU, GPSA — emits the empty string), and only a `$size == 0` payload is
    // `None`.
    assert_eq!(read_ascii(b"Camera\0\0").as_deref(), Some("Camera"));
    assert_eq!(read_ascii(&[0u8; 6]).as_deref(), Some(""));
    assert_eq!(read_ascii(b"").as_deref(), None);
  }
}
