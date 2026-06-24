// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! DJI MakerNotes — Phase-4 port.
//!
//! Bundled source: `lib/Image/ExifTool/DJI.pm` —
//! `%Image::ExifTool::DJI::Main` (`DJI.pm:52-72`).
//!
//! ## Phase 4 scope
//!
//! - The DJI body walker ([`body::walk_dji_in_tiff`]) — headerless body
//!   (`Start => '$valuePtr'`; `MakerNotes.pm:104`), walks the IFD entries
//!   with the parent IFD's byte order (DJI body has no MM/II marker).
//! - The faithful tag table ([`tags::DJI_TAGS`]) — every named LEAF tag
//!   from `%DJI::Main` (10 tags: `Make`, plus the drone + camera angle
//!   triple `Pitch/Yaw/Roll` × 2 and the speed triple `Speed{X,Y,Z}`).
//! - Per-tag PrintConv ([`printconv::DjiPrintConv`]) — `%convFloat2`
//!   `sprintf("%+.2f", $val)` for every float tag, raw passthrough for
//!   `Make`.
//! - A typed [`MakerNotesDji`] struct with D8 accessors over the parsed
//!   fields — body identity (`Make`) plus the two pose triples
//!   ([`MakerNotesDji::flight_pose`] / [`MakerNotesDji::camera_pose`]
//!   = pitch/yaw/roll in degrees) plus the flight speed triple.
//!
//! ## Deferred (Phase 4+1 follow-up issues — see #62 umbrella)
//!
//! - **DJI Thermal sub-tables** — `%Image::ExifTool::DJI::ThermalParams`
//!   (`DJI.pm:97-121`), `%DJI::ThermalParams2` (`DJI.pm:123-134`),
//!   `%DJI::ThermalParams3` (`DJI.pm:137-146`). These live in the APP4
//!   JFIF segment of RJPEG thermal-camera files (Mavic 3T, M30T, ZH20T,
//!   H20N, M2EA) — NOT in the 0x927C MakerNote — so they're an APP4
//!   ingester problem, not a MakerNote table problem. Industrial /
//!   thermal-only; low consumer indexing value.
//! - **DJI XMP namespace** — `%DJI::XMP` (`DJI.pm:148-211`). The XMP
//!   drone-dji namespace (FlightYawDegree / FlightPitchDegree /
//!   FlightRollDegree / GimbalYawDegree / GimbalPitchDegree /
//!   GimbalRollDegree / AbsoluteAltitude / RelativeAltitude / Flight
//!   Speed{X,Y,Z}) is XMP-side data. The XMP namespace port lives under
//!   PR #37; out of scope for the MakerNote-IFD port.
//! - **DJI Glamour beauty-settings** — `%DJI::Glamour` (`DJI.pm:213-232`).
//!   Beauty-mode metadata from QuickTime UserData (`ProcessSettings`);
//!   QuickTime-chain, NOT 0x927C MakerNote. Out of scope.
//! - **DJI Protobuf telemetry** — `%DJI::Protobuf` (`DJI.pm:235-859`).
//!   This is a HUGE table (~700 lines) of protobuf-typed tags for the
//!   `djmd` + `dbgi` QuickTime timed-metadata stream (Osmo Action 4/5/6,
//!   Avata 2, Mavic 3/3 Pro/4, Mini 4 Pro/Mini 5 Pro, Air 3/3s, Pocket 3,
//!   Osmo 360, Matrice 30/4E). Requires a protobuf parser + the
//!   per-model dispatch table. QuickTime-chain (not 0x927C); the
//!   QuickTime port handles ingest, this MakerNote port handles only
//!   the 0x927C IFD.
//! - **DJI DroneInfo / GimbalInfo / FrameInfo / GPSInfo** sub-protobuf
//!   tables (`DJI.pm:868-921`) — protobuf nested messages decoded by the
//!   `%Protobuf` table above; deferred with it.
//! - **DJI Inspire / Matrice industrial deep tags** — bundled `%Protobuf`
//!   covers some Matrice 30 and 4E entries; the deeper Inspire / Matrice
//!   industrial-photogrammetry tags (LiDAR / multispectral) are NOT in
//!   bundled at all (per the standing rescope memory, these are
//!   industrial-photogrammetry features with low consumer indexing
//!   value).
//! - **DJIInfo / ae_dbg_info** — `%DJI::Info` (`DJI.pm:74-95`). Parsed by
//!   `ProcessDJIInfo` (`DJI.pm:943-966`); blob starts with
//!   `[ae_dbg_info:...]`. The dispatcher already routes the `NotIFD`
//!   signature to `Vendor::Dji`, but the bracketed-string body has its
//!   own parser. Defer the body parser as a Phase 4+1 follow-up — debug
//!   info, not camera-indexing.
//! - **Action-cam carve-out signatures** — `MakerNotes.pm:101`'s negative
//!   lookahead `$$valPt !~ /^(...\@AMBA|DJI)/s` excludes two action-cam
//!   shapes DJI shares with Ambarella SoC relatives. Phase 1 routes
//!   these to `Vendor::Unknown`; the dedicated Ambarella decoder is a
//!   long-tail deferral (out of camera-indexing rescope scope).
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future Phase 4-bis can add fields without a
//! breaking change. `PartialEq` only (NOT `Eq`) because the pose tuples
//! carry `f64` fields.

#![deny(clippy::indexing_slicing)]

pub mod body;
pub mod dji_info;
pub mod printconv;
pub mod tags;

use crate::exif::makernotes::vendors::VendorEmission;
use crate::value::{Group, Metadata, TagValue};
use smol_str::SmolStr;
use std::vec::Vec;

pub use body::{DjiEntry, walk_dji_body, walk_dji_in_tiff};
pub use dji_info::{is_dji_info, parse_dji_info};
pub use printconv::DjiPrintConv;
pub use tags::{DJI_TAGS, DjiTag, lookup};

use super::super::super::ifd::{ByteOrder, RawValue};

/// Decoded DJI MakerNotes data — populated by [`parse`] when the
/// dispatcher resolved [`Vendor::Dji`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `PartialEq` only (NOT `Eq`)
/// because the pose tuples carry `f64` fields.
///
/// "Flight" pose = drone-body angles (`Pitch`/`Yaw`/`Roll`, IDs
/// 0x06/0x07/0x08) — the drone's attitude.
/// "Camera" pose = gimbal angles (`CameraPitch`/`CameraYaw`/`CameraRoll`,
/// IDs 0x09/0x0a/0x0b) — the gimbal's orientation relative to the drone.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MakerNotesDji {
  // ---- camera-identity (Phase 4 ship-bar) ----
  /// DJI Main 0x01 (`Make`) — drone make string (typically just "DJI" —
  /// the actual model lives in IFD0's `Model` tag, not the MakerNote).
  make: Option<SmolStr>,
  // ---- flight (drone-body) pose ----
  /// DJI Main 0x06 (`Pitch`) — drone-body pitch in degrees.
  flight_pitch: Option<f64>,
  /// DJI Main 0x07 (`Yaw`) — drone-body yaw in degrees.
  flight_yaw: Option<f64>,
  /// DJI Main 0x08 (`Roll`) — drone-body roll in degrees.
  flight_roll: Option<f64>,
  // ---- camera (gimbal) pose ----
  /// DJI Main 0x09 (`CameraPitch`) — gimbal pitch in degrees.
  camera_pitch: Option<f64>,
  /// DJI Main 0x0a (`CameraYaw`) — gimbal yaw in degrees.
  camera_yaw: Option<f64>,
  /// DJI Main 0x0b (`CameraRoll`) — gimbal roll in degrees.
  camera_roll: Option<f64>,
  // ---- flight speed ----
  /// DJI Main 0x03 (`SpeedX`) — flight speed X in m/s (PH-guess per
  /// bundled `# (guess)`).
  speed_x: Option<f64>,
  /// DJI Main 0x04 (`SpeedY`) — flight speed Y in m/s.
  speed_y: Option<f64>,
  /// DJI Main 0x05 (`SpeedZ`) — flight speed Z in m/s.
  speed_z: Option<f64>,
}

impl MakerNotesDji {
  /// Build an empty DJI metadata bag. [`parse`] populates the per-tag
  /// fields.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      make: None,
      flight_pitch: None,
      flight_yaw: None,
      flight_roll: None,
      camera_pitch: None,
      camera_yaw: None,
      camera_roll: None,
      speed_x: None,
      speed_y: None,
      speed_z: None,
    }
  }

  /// `Make` (`DJI.pm:61`) — the drone-side make string (note this is
  /// distinct from IFD0's `Make` — DJI cameras emit both).
  #[must_use]
  #[inline]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }

  // ---- flight pose accessors ----

  /// `Pitch` (`DJI.pm:66`) — flight-body pitch in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn flight_pitch(&self) -> Option<f64> {
    self.flight_pitch
  }

  /// `Yaw` (`DJI.pm:67`) — flight-body yaw in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn flight_yaw(&self) -> Option<f64> {
    self.flight_yaw
  }

  /// `Roll` (`DJI.pm:68`) — flight-body roll in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn flight_roll(&self) -> Option<f64> {
    self.flight_roll
  }

  /// `(pitch, yaw, roll)` flight pose tuple — `Some` iff all three are
  /// present. Convenience accessor for the common "drone orientation"
  /// query.
  #[must_use]
  #[inline(always)]
  pub const fn flight_pose(&self) -> Option<(f64, f64, f64)> {
    match (self.flight_pitch, self.flight_yaw, self.flight_roll) {
      (Some(p), Some(y), Some(r)) => Some((p, y, r)),
      _ => None,
    }
  }

  // ---- camera (gimbal) pose accessors ----

  /// `CameraPitch` (`DJI.pm:69`) — gimbal pitch in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn camera_pitch(&self) -> Option<f64> {
    self.camera_pitch
  }

  /// `CameraYaw` (`DJI.pm:70`) — gimbal yaw in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn camera_yaw(&self) -> Option<f64> {
    self.camera_yaw
  }

  /// `CameraRoll` (`DJI.pm:71`) — gimbal roll in degrees.
  #[must_use]
  #[inline(always)]
  pub const fn camera_roll(&self) -> Option<f64> {
    self.camera_roll
  }

  /// `(pitch, yaw, roll)` camera/gimbal pose tuple — `Some` iff all
  /// three are present.
  #[must_use]
  #[inline(always)]
  pub const fn camera_pose(&self) -> Option<(f64, f64, f64)> {
    match (self.camera_pitch, self.camera_yaw, self.camera_roll) {
      (Some(p), Some(y), Some(r)) => Some((p, y, r)),
      _ => None,
    }
  }

  // ---- flight speed accessors ----

  /// `SpeedX` (`DJI.pm:63`) — flight-body X speed (m/s, PH-guess).
  #[must_use]
  #[inline(always)]
  pub const fn speed_x(&self) -> Option<f64> {
    self.speed_x
  }

  /// `SpeedY` (`DJI.pm:64`) — flight-body Y speed (m/s, PH-guess).
  #[must_use]
  #[inline(always)]
  pub const fn speed_y(&self) -> Option<f64> {
    self.speed_y
  }

  /// `SpeedZ` (`DJI.pm:65`) — flight-body Z speed (m/s, PH-guess).
  #[must_use]
  #[inline(always)]
  pub const fn speed_z(&self) -> Option<f64> {
    self.speed_z
  }

  /// `(x, y, z)` flight speed triple — `Some` iff all three present.
  #[must_use]
  #[inline(always)]
  pub const fn flight_speed(&self) -> Option<(f64, f64, f64)> {
    match (self.speed_x, self.speed_y, self.speed_z) {
      (Some(x), Some(y), Some(z)) => Some((x, y, z)),
      _ => None,
    }
  }
}

/// Parse the captured DJI MakerNote blob into a [`MakerNotesDji`] plus
/// the `(name, value)` emissions for the `MakerNotes:` JSON group.
///
/// `blob` is the raw 0x927C value (DJI's body has no header — `Start =>
/// '$valuePtr'`); `parent_order` is the parent IFD walk's byte order.
#[must_use]
pub fn parse(blob: &[u8], parent_order: ByteOrder) -> (MakerNotesDji, Vec<VendorEmission>) {
  parse_with_print_conv(blob, parent_order, true)
}

/// Like [`parse`] but lets the caller toggle PrintConv.
#[must_use]
pub fn parse_with_print_conv(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
) -> (MakerNotesDji, Vec<VendorEmission>) {
  parse_in_tiff(blob, 0, blob.len(), parent_order, print_conv)
}

/// Parse with the parent TIFF context — out-of-line offsets resolve
/// against `tiff_data` (DJI inherits the parent Base, so offsets are
/// TIFF-relative).
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the MakerNote
/// blob's start within `tiff_data`; `mn_len` is the blob length;
/// `parent_order` is the parent IFD's byte order.
///
/// `MakerNotes.pm:93-106` routes a 0x927C MakerNote two ways under
/// `Vendor::Dji`: a value matching `^\[ae_dbg_info:/` (`NotIFD => 1`) goes to
/// `%DJI::Info`/[`dji_info::parse_dji_info`] (a flat `[key:val]` bracket run),
/// everything else to the `%DJI::Main` headerless IFD walked here. This split
/// is reproduced by sniffing the blob's leading signature: a DJIInfo body has
/// no IFD, and the IFD walker would misread its leading `[a` (`0x615b`) as a
/// 24929-entry count and yield garbage. The DJIInfo path populates no typed
/// `MakerNotesDji` fields (it carries debug blobs, not the camera-pose / speed
/// data the struct models), so the typed slot stays empty there.
#[must_use]
pub fn parse_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  print_conv: bool,
) -> (MakerNotesDji, Vec<VendorEmission>) {
  let mut typed = MakerNotesDji::new();
  let mut emissions: Vec<VendorEmission> = Vec::new();
  // DJIInfo (`MakerNoteDJIInfo`, `NotIFD => 1`): the whole 0x927C value is the
  // bracketed-string body (`DirStart = 0`). `%DJI::Info` has no Conv, so the
  // emissions are `print_conv`-independent.
  let blob_end = mn_offset.saturating_add(mn_len);
  if let Some(blob) = tiff_data.get(mn_offset..blob_end) {
    if dji_info::is_dji_info(blob) {
      emissions.extend(dji_info::parse_dji_info(blob));
      return (typed, emissions);
    }
  }
  let entries = body::walk_dji_in_tiff(tiff_data, mn_offset, mn_len, parent_order);
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue;
    };
    let value = def.conv.apply(&entry.value, print_conv);
    populate_typed(&mut typed, entry, &value);
    emissions.push(VendorEmission::new(def.name.into(), value, false));
  }
  (typed, emissions)
}

/// Mirror of [`parse_with_print_conv`] that emits straight into a
/// [`Metadata`] sink under the `("MakerNotes","MakerNotes")` group.
pub fn parse_into_metadata(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  into: &mut Metadata,
) {
  // Family-1 group is the vendor name `DJI` (DJI.pm:56 family-0 =
  // `MakerNotes`); matches `Vendor::Dji.group1()` + the ProcessExif path.
  let group = Group::new("MakerNotes", "DJI");
  let (_typed, emissions) = parse_with_print_conv(blob, parent_order, print_conv);
  for e in emissions {
    // Unknown-suppression is the engine's job; this raw `Metadata`-sink
    // helper applies it inline so it matches the default-output contract
    // (`ExifTool.pm:9179-9185`), exactly like `run_emission`. Mirrors
    // Sony's `parse_into_metadata`.
    if e.unknown() {
      continue;
    }
    into.push(group.clone(), e.name(), e.value().clone());
  }
}

/// Populate the typed struct with the parsed value for `entry`.
fn populate_typed(typed: &mut MakerNotesDji, entry: &DjiEntry, val: &TagValue) {
  match entry.tag_id {
    0x01 => {
      // Make — string. Accept TagValue::Str from the post-PrintConv
      // emission (DjiPrintConv::None trims trailing NULs).
      if let TagValue::Str(s) = val {
        if !s.is_empty() {
          typed.make = Some(s.clone());
        }
      } else if let RawValue::Text { text: s, .. } = &entry.value {
        let trimmed = s.trim_end_matches(['\0', ' ']);
        if !trimmed.is_empty() {
          typed.make = Some(trimmed.into());
        }
      }
    }
    0x03 => typed.speed_x = first_f64(&entry.value),
    0x04 => typed.speed_y = first_f64(&entry.value),
    0x05 => typed.speed_z = first_f64(&entry.value),
    0x06 => typed.flight_pitch = first_f64(&entry.value),
    0x07 => typed.flight_yaw = first_f64(&entry.value),
    0x08 => typed.flight_roll = first_f64(&entry.value),
    0x09 => typed.camera_pitch = first_f64(&entry.value),
    0x0a => typed.camera_yaw = first_f64(&entry.value),
    0x0b => typed.camera_roll = first_f64(&entry.value),
    _ => {}
  }
}

fn first_f64(raw: &RawValue) -> Option<f64> {
  match raw {
    RawValue::F64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().map(|&n| n as f64),
    RawValue::U64(v) => v.first().map(|&n| n as f64),
    _ => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use std::vec::Vec;

  /// Build a synthetic DJI blob with `entries` (each `(tag, format, count, value_bytes)`).
  ///
  /// The body is little-endian, headerless (no 12-byte prefix — `Start =>
  /// '$valuePtr'`).
  fn build_blob(entries: &[(u16, u16, u32, Vec<u8>)]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let entries_start = blob.len();
    let dir_size = 12 * entries.len();
    let mut data_off = entries_start + dir_size;
    let mut pending_data: Vec<Vec<u8>> = Vec::new();
    // Element sizes by TIFF format code.
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    for (tag, format, count, value) in entries {
      let elem_size = elem_sizes[*format as usize];
      let total = elem_size * (*count as usize);
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if total <= 4 {
        let mut padded = [0u8; 4];
        padded[..value.len().min(4)].copy_from_slice(&value[..value.len().min(4)]);
        blob.extend_from_slice(&padded);
      } else {
        blob.extend_from_slice(&(data_off as u32).to_le_bytes());
        data_off += total;
        pending_data.push(value.clone());
      }
    }
    for v in pending_data {
      blob.extend_from_slice(&v);
    }
    blob
  }

  #[test]
  fn parse_flight_pitch_emits_printconv_string() {
    // Pitch (0x06) float count 1 value 12.5 ⇒ "+12.50"
    let blob = build_blob(&[(0x06, 0x0b, 1, 12.5f32.to_le_bytes().to_vec())]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(emissions.len(), 1);
    assert_eq!(emissions[0].name(), "Pitch");
    assert_eq!(emissions[0].value(), &TagValue::Str("+12.50".into()));
    assert!((typed.flight_pitch().unwrap() - 12.5).abs() < 1e-6);
  }

  #[test]
  fn parse_flight_pose_tuple_populated_when_all_three_present() {
    let pitch = 5.5f32;
    let yaw = -90.25f32;
    let roll = 0.0f32;
    let blob = build_blob(&[
      (0x06, 0x0b, 1, pitch.to_le_bytes().to_vec()),
      (0x07, 0x0b, 1, yaw.to_le_bytes().to_vec()),
      (0x08, 0x0b, 1, roll.to_le_bytes().to_vec()),
    ]);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    let pose = typed.flight_pose().expect("all three pose tags present");
    assert!((pose.0 - 5.5).abs() < 1e-6);
    assert!((pose.1 + 90.25).abs() < 1e-6);
    assert!((pose.2 - 0.0).abs() < 1e-6);
  }

  #[test]
  fn parse_partial_pose_does_not_yield_tuple() {
    // Only Pitch and Yaw — no Roll. flight_pose should be None.
    let pitch = 5.5f32;
    let yaw = 90.0f32;
    let blob = build_blob(&[
      (0x06, 0x0b, 1, pitch.to_le_bytes().to_vec()),
      (0x07, 0x0b, 1, yaw.to_le_bytes().to_vec()),
    ]);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert!(typed.flight_pitch().is_some());
    assert!(typed.flight_yaw().is_some());
    assert!(typed.flight_roll().is_none());
    assert!(typed.flight_pose().is_none());
  }

  #[test]
  fn parse_camera_pose_populated_separately_from_flight_pose() {
    let cpitch = -45.0f32;
    let cyaw = 0.0f32;
    let croll = 12.34f32;
    let blob = build_blob(&[
      (0x09, 0x0b, 1, cpitch.to_le_bytes().to_vec()),
      (0x0a, 0x0b, 1, cyaw.to_le_bytes().to_vec()),
      (0x0b, 0x0b, 1, croll.to_le_bytes().to_vec()),
    ]);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    let pose = typed.camera_pose().expect("all three camera pose tags");
    assert!((pose.0 + 45.0).abs() < 1e-6);
    assert!((pose.1 - 0.0).abs() < 1e-6);
    assert!((pose.2 - 12.34).abs() < 1e-4);
    assert!(typed.flight_pose().is_none()); // no flight tags
  }

  #[test]
  fn parse_make_emits_string() {
    // Make (0x01) string count 4 = "DJI\0"
    let blob = build_blob(&[(0x01, 0x02, 4, b"DJI\x00".to_vec())]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(emissions.len(), 1);
    assert_eq!(emissions[0].name(), "Make");
    assert_eq!(emissions[0].value(), &TagValue::Str("DJI".into()));
    assert_eq!(typed.make(), Some("DJI"));
  }

  #[test]
  fn parse_flight_speed_triple() {
    let sx = 1.25f32;
    let sy = -3.5f32;
    let sz = 0.0f32;
    let blob = build_blob(&[
      (0x03, 0x0b, 1, sx.to_le_bytes().to_vec()),
      (0x04, 0x0b, 1, sy.to_le_bytes().to_vec()),
      (0x05, 0x0b, 1, sz.to_le_bytes().to_vec()),
    ]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(emissions.len(), 3);
    assert_eq!(emissions[0].name(), "SpeedX");
    assert_eq!(emissions[0].value(), &TagValue::Str("+1.25".into()));
    assert_eq!(emissions[1].name(), "SpeedY");
    assert_eq!(emissions[1].value(), &TagValue::Str("-3.50".into()));
    assert_eq!(emissions[2].name(), "SpeedZ");
    assert_eq!(emissions[2].value(), &TagValue::Str("+0.00".into()));
    let triple = typed.flight_speed().expect("all three speed tags");
    assert!((triple.0 - 1.25).abs() < 1e-6);
    assert!((triple.1 + 3.5).abs() < 1e-6);
    assert!((triple.2 - 0.0).abs() < 1e-6);
  }

  #[test]
  fn parse_unknown_tag_0x02_is_skipped() {
    // 0x02 - bundled comment says int8u[4]: "1 0 0 0", "1 1 0 0" — no
    // tag definition. We synthesize and verify we skip it.
    let blob = build_blob(&[(0x02, 0x01, 4, std::vec![1, 0, 0, 0])]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert!(
      emissions.is_empty(),
      "0x02 must be skipped (no entry in DJI::Main)"
    );
    assert_eq!(typed, MakerNotesDji::new());
  }

  #[test]
  fn parse_into_metadata_emits_under_makernotes_group() {
    let blob = build_blob(&[(0x06, 0x0b, 1, 7.5f32.to_le_bytes().to_vec())]);
    let mut meta = Metadata::new("test.jpg");
    parse_into_metadata(&blob, ByteOrder::Little, true, &mut meta);
    let pitch = meta.tags_slice().iter().find(|t| t.name() == "Pitch");
    assert!(pitch.is_some(), "Pitch tag emitted");
    let pitch = pitch.unwrap();
    assert_eq!(pitch.group_ref().family0(), "MakerNotes");
    assert_eq!(pitch.value_ref(), &TagValue::Str("+7.50".into()));
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], ByteOrder::Little);
    assert_eq!(typed, MakerNotesDji::new());
    assert!(emissions.is_empty());
  }
}
