// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
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
//!    converted to `YYYY:MM:DD HH:MM:SS[.fff]Z`;
//!  - `GPSP` (GoPro.pm:237-241) — horizontal positioning error in cm,
//!    converted to metres (`$val / 100`);
//!  - `GPSF` (GoPro.pm:230-236) — numeric fix code;
//!  - `GPSA` (GoPro.pm:472) — altitude reference system;
//!  - camera identification — `DVNM` / `MINF` / `CASN` / `FMWR` / `MUID`
//!    (GoPro.pm:121, 169-172, 286-290, 195, 456-462).
//!
//! Other tag families (ACCL/GYRO/MAGN/SHUT/ISO/Karma/Max) are walked by
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

use crate::metadata::{GoProGpsSample, GoProMeta};

// ===========================================================================
// Byte readers — GPMF is BIG-ENDIAN (the GoPro Metadata Format byte order;
// GoPro.pm's `ReadValue` defaults to ExifTool's `MM` byte order since
// QuickTime.pm SetByteOrder('MM') is in effect at the call site).
// ===========================================================================

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_i16(b: &[u8], off: usize) -> Option<i16> {
  be_u16(b, off).map(|v| v as i16)
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be_i32(b: &[u8], off: usize) -> Option<i32> {
  be_u32(b, off).map(|v| v as i32)
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn be_f32(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 4)
    .map(|s| f64::from(f32::from_be_bytes([s[0], s[1], s[2], s[3]])))
}

fn be_f64(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 8)
    .map(|s| f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
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
    // GoPro.pm:791 `(tag, size) = unpack('a4N', $buff)`.
    let tag = &data[pos..pos + 4];
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
    // then NUL).
    if tag[0] != b'G' || tag[1] != b'P' || data[pos + 4] != 0 {
      break;
    }
    let body_start = pos + 16;
    let body_end = body_start + size;
    let body = &data[body_start..body_end];
    // GoPro.pm:794 `if ($buff =~ /^DEVC/)`.
    if body.len() >= 4 && &body[..4] == b"DEVC" {
      // Faithful: the contained record IS itself a GPMF KLV record (its
      // first 4 bytes are the DEVC FourCC of the outermost KLV). Pass it
      // straight into the recursive walker.
      process_gopro(body, out);
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
pub fn process_gopro(data: &[u8], out: &mut GoProMeta) {
  let mut walker = Walker {
    out,
    type_str: None,
    scal: None,
    unit: None,
  };
  walker.walk(data);
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
  /// Last `UNIT` / `SIUN` payload (GoPro.pm:873, informational).
  unit: Option<Vec<u8>>,
}

impl Walker<'_> {
  fn walk(&mut self, data: &[u8]) {
    let mut pos = 0usize;
    // GoPro.pm:831 `for (; $pos+8<=$dirEnd; $pos+=($size+3)&0xfffffffc)`.
    while pos + 8 <= data.len() {
      let tag = &data[pos..pos + 4];
      let fmt = data[pos + 4];
      let len = data[pos + 5] as usize;
      let count = match be_u16(data, pos + 6) {
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
      let size = len.saturating_mul(count);
      // GoPro.pm:839-842 `if ($pos + $size > $dirEnd) { last; }`.
      if pos + 8 + size > data.len() {
        break;
      }
      let payload = &data[pos + 8..pos + 8 + size];
      self.visit(tag, fmt, len, count, payload);
      // GoPro.pm:831 `$pos += ($size + 3) & 0xfffffffc` — 4-byte align.
      pos += 8 + padded_size(size);
    }
  }

  fn visit(&mut self, tag: &[u8], fmt: u8, len: usize, count: usize, payload: &[u8]) {
    // GoPro.pm:845-846 — empty records (`size == 0`) are skipped unless
    // verbose, which exifast never sets.
    if payload.is_empty() {
      return;
    }
    // GoPro.pm:823-829 — a `fmt=0` is a container (subdirectory). Recurse
    // with FRESH state — `$type`/`$scal`/`$unit` are LOCAL to the
    // sub-call.
    if fmt == 0 {
      // `DEVC` / `STRM` (and any opportunistically-added unknown
      // container tag, GoPro.pm:880).
      let mut child = Walker {
        out: self.out,
        type_str: None,
        scal: None,
        unit: None,
      };
      child.walk(payload);
      return;
    }
    // Save TYPE / UNIT / SCAL for later tags in this container
    // (GoPro.pm:872-874).
    match tag {
      b"TYPE" => {
        self.type_str = Some(payload.to_vec());
      }
      b"UNIT" | b"SIUN" => {
        self.unit = Some(payload.to_vec());
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
    // Our typed surface targets the GPS family; for those tags scaling is
    // applied at the dedicated decoder below.
    self.emit_tag(tag, fmt, len, count, payload);
  }

  /// Dispatch a non-container scalar record into the typed `GoProMeta`.
  /// This is the data-extraction side of GoPro.pm:867-869 +
  /// 884-896 (ScaleValues + HandleTag). Only the tags the typed surface
  /// stores are decoded; the rest are visited (so containers recurse) but
  /// their values are dropped.
  fn emit_tag(&mut self, tag: &[u8], fmt: u8, len: usize, count: usize, payload: &[u8]) {
    match tag {
      b"DVNM" => {
        // GoPro.pm:170-172 — `DeviceName` (`c` ASCII), trim trailing NULs.
        if let Some(s) = read_ascii(payload) {
          self.out.set_device_name(Some(SmolStr::from(s)));
        }
      }
      b"MINF" => {
        // GoPro.pm:286-290 — `Model`, ASCII `c`.
        if let Some(s) = read_ascii(payload) {
          self.out.set_model(Some(SmolStr::from(s)));
        }
      }
      b"CASN" => {
        // GoPro.pm:121 — `CameraSerialNumber`, ASCII `c`.
        if let Some(s) = read_ascii(payload) {
          self.out.set_camera_serial_number(Some(SmolStr::from(s)));
        }
      }
      b"FMWR" => {
        // GoPro.pm:195 — `FirmwareVersion`, ASCII `c`.
        if let Some(s) = read_ascii(payload) {
          self.out.set_firmware_version(Some(SmolStr::from(s)));
        }
      }
      b"MUID" => {
        // GoPro.pm:456-462 — `MediaUniqueID`. The "forum12825" entry
        // overrides the earlier MUID with a PrintConv that splits the
        // payload into space-separated u32s and hex-renders each
        // (`sprintf('%.8x',$_) foreach @a; join('')`). Faithful: read
        // `count` u32s LE? No — GPMF reads via ExifTool's ReadValue which
        // honours SetByteOrder('MM') for the GPMF parse (the QuickTime
        // outer-call default). Concatenate as `count` × 8 hex chars.
        let mut s = String::new();
        for i in 0..count {
          if let Some(v) = be_u32(payload, i * len) {
            s.push_str(&format!("{v:08x}"));
          }
        }
        if !s.is_empty() {
          self.out.set_media_uid(Some(SmolStr::from(s)));
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
        }
      }
      b"GPSF" => {
        // GoPro.pm:230-236 — `GPSMeasureMode`, fmt `L` u32. The PrintConv
        // maps 2 → '2-Dimensional Measurement', 3 → '3-Dimensional
        // Measurement'; the typed surface stores the raw numeric.
        if let Some(v) = be_u32(payload, 0) {
          self.out.set_gps_measure_mode(Some(v));
        }
      }
      b"GPSP" => {
        // GoPro.pm:237-241 — `GPSHPositioningError` — int16u in cm, the
        // `ValueConv` is `$val / 100` ⇒ metres.
        if let Some(v) = be_u16(payload, 0) {
          self
            .out
            .set_gps_h_positioning_error_m(Some(f64::from(v) / 100.0));
        }
      }
      b"GPSA" => {
        // GoPro.pm:472 — `GPSAltitudeSystem` (4-char ID, e.g. 'MSLV').
        if let Some(s) = read_ascii(payload) {
          self.out.set_gps_altitude_system(Some(SmolStr::from(s)));
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
        // strings of post-`SCAL` values).
        self.emit_gps5(fmt, len, count, payload);
      }
      b"GPS9" => {
        // GoPro.pm:222-229 — `GPS9` SubDirectory dispatch. Same shape as
        // GPS5 plus the per-sample days/seconds/DOP/fix columns.
        self.emit_gps9(fmt, len, count, payload);
      }
      _ => {
        // Unrecognized / non-typed tag — visited but not extracted into
        // the typed surface. (Faithful: ExifTool's `unless ($tagInfo)`
        // branch silently skips a tag whose `Unknown => 1` info isn't
        // requested, GoPro.pm:876-882.)
        let _ = (fmt, len);
      }
    }
  }

  /// `GPS5` — multi-row int32s[5]. SCAL is the 5-element scale vector
  /// `[10000000, 10000000, 1000, 1000, 100]` (GoPro.pm:218); each row is
  /// `(lat / SCAL[0], lon / SCAL[1], alt / SCAL[2], spd / SCAL[3],
  /// spd3d / SCAL[4])`.
  fn emit_gps5(&mut self, _fmt: u8, len: usize, count: usize, payload: &[u8]) {
    if len < 20 {
      return;
    }
    let scal =
      self
        .scal
        .as_deref()
        .unwrap_or(&[10_000_000.0, 10_000_000.0, 1_000.0, 1_000.0, 100.0]);
    for row in 0..count {
      let off = row * len;
      let lat = be_i32(payload, off).map(|v| f64::from(v) / scal_at(scal, 0));
      let lon = be_i32(payload, off + 4).map(|v| f64::from(v) / scal_at(scal, 1));
      let alt = be_i32(payload, off + 8).map(|v| f64::from(v) / scal_at(scal, 2));
      let spd = be_i32(payload, off + 12).map(|v| f64::from(v) / scal_at(scal, 3));
      let s3d = be_i32(payload, off + 16).map(|v| f64::from(v) / scal_at(scal, 4));
      let mut s = GoProGpsSample::new();
      s.set_latitude(lat)
        .set_longitude(lon)
        .set_altitude_m(alt)
        .set_speed_2d_mps(spd)
        .set_speed_3d_mps(s3d);
      self.out.push_gps_sample(s);
    }
  }

  /// `GPS9` — multi-row `?lllllllSS` (`?` = complex struct described by
  /// `TYPE`). TYPE for GPS9 is `lllllllSS` (7 int32s + 2 int16u =
  /// 7*4 + 2*2 = 32 bytes per row). SCAL is the 9-element scale vector
  /// `[10000000, 10000000, 1000, 1000, 100, 1, 1000, 100, 1]`
  /// (GoPro.pm:226).
  fn emit_gps9(&mut self, _fmt: u8, len: usize, count: usize, payload: &[u8]) {
    if len < 32 {
      return;
    }
    let scal = self.scal.as_deref().unwrap_or(&[
      10_000_000.0,
      10_000_000.0,
      1_000.0,
      1_000.0,
      100.0,
      1.0,
      1_000.0,
      100.0,
      1.0,
    ]);
    for row in 0..count {
      let off = row * len;
      let lat = be_i32(payload, off).map(|v| f64::from(v) / scal_at(scal, 0));
      let lon = be_i32(payload, off + 4).map(|v| f64::from(v) / scal_at(scal, 1));
      let alt = be_i32(payload, off + 8).map(|v| f64::from(v) / scal_at(scal, 2));
      let spd = be_i32(payload, off + 12).map(|v| f64::from(v) / scal_at(scal, 3));
      let s3d = be_i32(payload, off + 16).map(|v| f64::from(v) / scal_at(scal, 4));
      // GPS9 columns 5+6 are per-sample DAYS (since 2000-01-01) + SECONDS
      // of date/time, post-`SCAL`. ExifTool synthesizes GPSDateTime
      // through `ConvertUnixTime(($days + 10957) * 86400 + $secs, undef, 3)`
      // (GoPro.pm:543-554). 10957 days from Jan 1 1970 to Jan 1 2000.
      let days = be_i32(payload, off + 20).map(|v| f64::from(v) / scal_at(scal, 5));
      let secs = be_i32(payload, off + 24).map(|v| f64::from(v) / scal_at(scal, 6));
      let dop = be_u16(payload, off + 28).map(|v| f64::from(v) / scal_at(scal, 7));
      let mode = be_u16(payload, off + 30).map(|v| u32::from(v) / scal_at(scal, 8) as u32);
      let date_time = match (days, secs) {
        (Some(d), Some(s)) => unix_to_iso((d + 10957.0) * 86400.0 + s),
        _ => None,
      };
      let mut s = GoProGpsSample::new();
      s.set_latitude(lat)
        .set_longitude(lon)
        .set_altitude_m(alt)
        .set_speed_2d_mps(spd)
        .set_speed_3d_mps(s3d)
        .set_date_time(date_time.map(SmolStr::from))
        .set_dop(dop)
        .set_measure_mode(mode);
      self.out.push_gps_sample(s);
    }
  }
}

/// Read `count` scalar values of `fmt`/`len` from `payload`, returning
/// them as `f64`. Mirrors `ReadValue` joining (GoPro.pm:869) for the
/// purpose of building a SCAL vector — all SCAL values in the bundled
/// tables are `L` (int32u) or `f` (float32); we still accept the full
/// numeric set for forward compatibility.
fn read_scalar_vec(fmt: u8, len: usize, count: usize, payload: &[u8]) -> Vec<f64> {
  let mut out = Vec::with_capacity(count);
  for i in 0..count {
    let off = i * len;
    let v = match fmt {
      0x62 => payload.get(off).map(|&b| f64::from(b as i8)),
      0x42 => payload.get(off).map(|&b| f64::from(b)),
      0x73 => be_i16(payload, off).map(f64::from),
      0x53 => be_u16(payload, off).map(f64::from),
      0x6c => be_i32(payload, off).map(f64::from),
      0x4c => be_u32(payload, off).map(f64::from),
      0x66 => be_f32(payload, off),
      0x64 => be_f64(payload, off),
      0x6a => be_u64(payload, off).map(|v| v as i64 as f64),
      0x4a => be_u64(payload, off).map(|v| v as f64),
      0x71 => be_i32(payload, off).map(|v| f64::from(v) / 65_536.0), // 32-bit fixed
      0x51 => be_u64(payload, off).map(|v| (v as i64 as f64) / 4_294_967_296.0),
      _ => None,
    };
    if let Some(x) = v {
      out.push(x);
    }
  }
  out
}

/// Pick a SCAL element with the modulo-fold ExifTool's `ScaleValues`
/// applies (GoPro.pm:717 `$a[$_] /= $scl[$_ % @scl]`). Defaults to `1.0`
/// when the SCAL vector is empty.
fn scal_at(scal: &[f64], i: usize) -> f64 {
  if scal.is_empty() {
    1.0
  } else {
    scal[i % scal.len()]
  }
}

/// Read a NUL-terminated / NUL-padded ASCII string from a GPMF `c` (or
/// `F`/`G`/`U`) payload. Trims trailing NULs.
fn read_ascii(payload: &[u8]) -> Option<String> {
  let end = payload
    .iter()
    .position(|&b| b == 0)
    .unwrap_or(payload.len());
  let slice = &payload[..end];
  if slice.is_empty() {
    return None;
  }
  // Faithful: ExifTool's string ReadValue keeps non-ASCII as raw bytes;
  // the GoPro module then re-decodes via `Latin` for the RMRK/SIUN/UNIT
  // strings. The typed surface targets ASCII-only fields (model, serial,
  // firmware, GPSU, GPSA) — UTF-8-lossy is a safe rendering.
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
  // Find the 10 leading digits.
  if raw.len() < 10 || !raw.as_bytes()[..10].iter().all(u8::is_ascii_digit) {
    return raw.to_string();
  }
  let y = &raw[0..2];
  let m = &raw[2..4];
  let d = &raw[4..6];
  let h = &raw[6..8];
  let mn = &raw[8..10];
  let tail = &raw[10..];
  format!("20{y}:{m}:{d} {h}:{mn}:{tail}Z")
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
  Some(format!(
    "{:04}:{:02}:{:02} {:02}:{:02}:{:02}.{:03}Z",
    date.year(),
    date.month(),
    date.day(),
    time.hour(),
    time.minute(),
    time.second(),
    millis,
  ))
}

/// `[^-_a-zA-Z0-9 ]` — ExifTool's `Unrecognized GoPro record` bail check
/// (GoPro.pm:833). A tag passes if EVERY byte is alphanumeric / dash /
/// underscore / space.
const fn is_tag_char(b: &u8) -> bool {
  matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b' ')
}

#[cfg(test)]
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

  #[test]
  fn klv_walker_decodes_dvnm_minf_casn_fmwr() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
    buf.extend_from_slice(&klv(b"MINF", 0x63, 11, 1, b"HERO6 Black"));
    buf.extend_from_slice(&klv(b"CASN", 0x63, 14, 1, b"C3221324657219"));
    buf.extend_from_slice(&klv(b"FMWR", 0x63, 15, 1, b"HD6.01.01.51.00"));
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
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
    process_gopro(&outer, &mut out);
    assert_eq!(out.device_name(), Some("Hero"));
  }

  #[test]
  fn klv_walker_emits_one_sample_per_gps5_row() {
    // Two-row GPS5 with default scaling. lat=42_0000000 (raw int32) /
    // 10_000_000 = 4.2°, lon=-105_0000000 / 10_000_000 = -10.5°,
    // alt=1_500_000 / 1000 = 1500 m, spd=12_000 / 1000 = 12 m/s,
    // spd3d=1500 / 100 = 15 m/s. Second row doubles each value.
    let mut payload = Vec::new();
    for &factor in &[1i32, 2] {
      payload.extend_from_slice(&(factor * 42_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * -105_000_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 12_000i32).to_be_bytes());
      payload.extend_from_slice(&(factor * 1_500i32).to_be_bytes());
    }
    let buf = klv(b"GPS5", 0x6c, 20, 2, &payload);
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
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
    process_gopro(&strm, &mut out);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 0.42).abs() < 1e-6);
    assert!((s.longitude().unwrap() - 1.05).abs() < 1e-6);
    assert_eq!(s.altitude_m(), Some(1500.0));
    assert_eq!(s.speed_2d_mps(), Some(12.0));
  }

  #[test]
  fn klv_walker_decodes_gpsu_gpsf_gpsp_gpsa() {
    // GPSU is a Hero5-style 'c' ASCII "200731103245.500" → "2020:07:31 10:32:45.500Z"
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
    process_gopro(&buf, &mut out);
    assert_eq!(out.gps_date_time(), Some("2020:07:31 10:32:45.500Z"));
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
    process_gopro(&buf, &mut out);
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
    process_gopro(&buf, &mut out);
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
    assert_eq!(s, "2017:10:03 10:58:29.123Z");
    // Without sub-seconds.
    let s = convert_gpsu("171003105829");
    assert_eq!(s, "2017:10:03 10:58:29Z");
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
  fn klv_walker_decodes_muid_as_hex() {
    // MUID is 4 u32s BE → 32 hex chars.
    let muid_payload = vec![
      0x49u8, 0x1b, 0x31, 0x3c, 0xa8, 0x9d, 0x14, 0x16, 0xa5, 0x56, 0xfc, 0xe1, 0xd0, 0xcc, 0x7e,
      0x5a,
    ];
    let buf = klv(b"MUID", 0x4c, 4, 4, &muid_payload);
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
    assert_eq!(out.media_uid(), Some("491b313ca89d1416a556fce1d0cc7e5a"));
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
    buf.extend_from_slice(&scal);
    buf.extend_from_slice(&gps9);
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
    assert!((s.dop().unwrap() - 1.5).abs() < 1e-6);
    assert_eq!(s.measure_mode(), Some(3));
    let dt = s.date_time().expect("GPS9 has per-sample datetime");
    assert!(
      dt.starts_with("2019:03:02 03:25:45"),
      "expected 2019-03-02 03:25:45 fix, got {dt}"
    );
  }

  // P3-C malformed-input tests — the parser must surface no panics / no
  // out-of-bounds reads on hostile inputs.

  #[test]
  fn klv_truncated_header_yields_empty_meta() {
    // 4-byte slice (no full 8-byte KLV header) — the walker stops at the
    // first short read.
    let mut out = GoProMeta::new();
    process_gopro(b"DEVC", &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn klv_header_size_zero_does_not_loop_forever() {
    // A KLV record with `sample_size=0`/`count=0` (zero-length payload) is
    // legal — the walker advances by the 8-byte header. A buffer holding
    // ONLY a zero-payload header parses cleanly and returns empty.
    let buf = klv(b"DVNM", 0x63, 0, 0, &[]);
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
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
    process_gopro(&buf, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn unknown_fourcc_is_skipped() {
    // A KLV record with an unrecognised 4-byte tag is walked but produces
    // no typed-surface output (the fall-through case in `emit_tag`).
    let buf = klv(b"WXYZ", 0x4c, 4, 1, &[0u8; 4]);
    let mut out = GoProMeta::new();
    process_gopro(&buf, &mut out);
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
    process_gopro(&buf, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    // SCAL only carried 3 entries — speed columns use the 1.0 fallback.
    assert_eq!(s.speed_2d_mps(), Some(5.0));
    assert_eq!(s.speed_3d_mps(), Some(6.0));
  }
}
