// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Typed mirror of `Image::ExifTool::Parrot::mett` (Parrot.pm:22-84) and the
//! per-record binary tables `Image::ExifTool::Parrot::V1` / `V2` / `V3` /
//! `TimeStamp` / `FollowMe` / `Automation` (Parrot.pm:86-660). Faithful port
//! of `Image::ExifTool::Parrot::Process_mett` (Parrot.pm:791-854) — the
//! Parrot drone `mett` walker shared by Anafi / Anafi USA / Anafi Ai /
//! Anafi Thermal / Bebop / Bebop 2 / Disco bodies that write a `mett`
//! timed-metadata track into MP4.
//!
//! ## What this sub-port surfaces (camera-indexing-relevant tags)
//!
//! Per Parrot.pm:86-660:
//!
//!  - **GPS fix (records `P1` / `P2` / `P3`)** — every "basic" record
//!    type carries `GPSLatitude` / `GPSLongitude` / `GPSAltitude` /
//!    `GPSSatellites` in a fixed-offset binary layout. The scaling
//!    differs by record version:
//!     - **V1 (60-byte record)** — Parrot.pm:144-167: lat/lon are
//!       `int32s / 0x100000` (i.e. ÷ 0x10_0000) at offsets 28 / 32;
//!       altitude is `(int32s & 0xffffff00) / 0x100` at offset 36
//!       (low byte holds the SV count).
//!     - **V2 (56-byte record)** — Parrot.pm:242-265: lat/lon are
//!       `int32s / 0x400000` at offsets 8 / 12; altitude is the same
//!       masked shape at offset 16; record CONCAT'd with the E*
//!       extension records (the bundled walker stretches the V2 size
//!       from `nwords*4 + 4` to 56 — see Parrot.pm:837-838).
//!     - **V3 (72-byte record)** — Parrot.pm:383-406: identical lat/
//!       lon/alt offsets to V2, but the record is 72 bytes including
//!       extensions (Parrot.pm:838-839).
//!  - **Flight telemetry (records `P1` / `P2` / `P3`)** — battery
//!    percent, WifiRSSI, AltitudeFromTakeOff (V1 only), DistanceFromHome
//!    (V1 only), drone speed (3-axis), camera pan/tilt, exposure time,
//!    ISO, flying state, piloting mode. Surfaced one [`ParrotFlightSample`]
//!    per record.
//!  - **Drone identity** — `mett` does NOT carry Make/Model/Serial/
//!    Firmware in the per-sample records. Bundled doesn't decode these
//!    in `Parrot::mett`; Parrot bodies surface their identity through
//!    the QuickTime `udta/©mod` + `udta/©mak` / Keys path (SP1+SP2).
//!    The `Make = "Parrot"` projection in [`crate::formats::quicktime`]
//!    fires whenever any `mett` record decoded — the drone-name string
//!    (Anafi / Bebop / …) MUST come from the container's udta.
//!  - **Timestamp extension (record `E1`)** — Parrot.pm:541-551: an
//!    `int64u` microsecond counter. Recorded as [`ParrotTimeStamp::raw_us`]
//!    on the host [`ParrotFlightSample`].
//!
//! ## What this sub-port deliberately does NOT decode
//!
//! Faithfully but as walked-only (the walker visits, the typed layer
//! discards):
//!  - **DroneQuaternion / FrameView / FrameBaseView** (4-element int16s
//!    quaternions) — telemetry-only, the camera-indexing product doesn't
//!    need pose vectors. Mirrors GoPro / Insta360 / Canon CTMD
//!    accelerometer rationale.
//!  - **FollowMe / Automation extensions (records `E2` / `E3`)** —
//!    Parrot.pm:553-660. These carry follow-me target GPS coordinates
//!    (`GPSTargetLatitude` etc.) which are PLANNED waypoints, not the
//!    drone's actual fix. Walked but not surfaced.
//!  - **ARCore phone-camera metadata** (`application/arcore-*` records,
//!    Parrot.pm:60-83) — Parrot drones also pass through ARCore
//!    accel/gyro on the controlling phone, but those records are phone-
//!    side AR data, not drone-side GPS. Walked but discarded (camera-
//!    indexing scope).
//!  - **CameraPan / CameraTilt** — these are gimbal angles, not body
//!    orientation. The bundled walker reads them as int16s scaled by
//!    `$val / 0x1000 * 180 / 3.14159` (rad → deg). Walked but discarded
//!    (gimbal pose is not camera identity).
//!
//! ## D8 compliance
//!
//! Every field is private; access through accessors. Setters return
//! `&mut Self` for chaining. `const fn` where types permit. Enums are
//! unit-only (Parrot's `FlyingState` and `PilotingMode` are closed lists
//! at the bundled level).

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata, MetaProjectInto};

// ===========================================================================
// ParrotFlyingState — Parrot.pm:203-211 (V1) + :329-339 (V2) + :510-520 (V3)
// ===========================================================================

/// `FlyingState` PrintConv (Parrot.pm:203-211 / :329-339 / :510-520).
/// V1's range is 0..=5 (`Landed` … `Emergency`); V2 / V3 extend the range
/// to 0..=8 with `User Takeoff` / `Motor Ramping` / `Emergency Landing`.
///
/// The typed layer surfaces the FULL range — a V1 walker can only emit
/// 0..=5; V2 / V3 walkers can emit any of 0..=8. Unknown numeric values
/// land in [`ParrotFlyingState::Unknown`] with the raw u8 preserved
/// (faithful: bundled's `PrintConv` hash returns the raw on miss).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotFlyingState {
  /// Bundled key `0`.
  Landed,
  /// Bundled key `1`.
  TakingOff,
  /// Bundled key `2`.
  Hovering,
  /// Bundled key `3`.
  Flying,
  /// Bundled key `4`.
  Landing,
  /// Bundled key `5`.
  Emergency,
  /// Bundled key `6` (V2 + V3 only).
  UserTakeoff,
  /// Bundled key `7` (V2 + V3 only).
  MotorRamping,
  /// Bundled key `8` (V2 + V3 only).
  EmergencyLanding,
  /// Bundled returned the raw numeric on PrintConv miss — keep the byte.
  Unknown(u8),
}

impl ParrotFlyingState {
  /// Build from the raw 7-bit value (`Mask => 0x7f`). Parrot.pm:202.
  #[inline]
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw {
      0 => Self::Landed,
      1 => Self::TakingOff,
      2 => Self::Hovering,
      3 => Self::Flying,
      4 => Self::Landing,
      5 => Self::Emergency,
      6 => Self::UserTakeoff,
      7 => Self::MotorRamping,
      8 => Self::EmergencyLanding,
      n => Self::Unknown(n),
    }
  }

  /// Raw 7-bit value (round-trip).
  #[inline]
  #[must_use]
  pub const fn as_u8(self) -> u8 {
    match self {
      Self::Landed => 0,
      Self::TakingOff => 1,
      Self::Hovering => 2,
      Self::Flying => 3,
      Self::Landing => 4,
      Self::Emergency => 5,
      Self::UserTakeoff => 6,
      Self::MotorRamping => 7,
      Self::EmergencyLanding => 8,
      Self::Unknown(n) => n,
    }
  }
}

// ===========================================================================
// ParrotPilotingMode — Parrot.pm:221-227 (V1) + :345-356 (V2) + :526-538 (V3)
// ===========================================================================

/// `PilotingMode` PrintConv (Parrot.pm:221-227 / :345-356 / :526-538).
/// V1 keys are 0..=3 (`Manual` … `Follow Me`); V2 / V3 extend to 0..=5 with
/// `Magic Carpet` / `Move To`. Note V1 calls key 3 "Follow Me" while V2 / V3
/// call it "Follow Me / Tracking" (same numeric value, just a wider
/// description — bundled keeps a single PrintConv entry per version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotPilotingMode {
  /// Bundled key `0`.
  Manual,
  /// Bundled key `1`.
  ReturnHome,
  /// Bundled key `2`.
  FlightPlan,
  /// Bundled key `3` (V1: "Follow Me"; V2 / V3: "Follow Me / Tracking").
  FollowMe,
  /// Bundled key `4` (V2 + V3 only).
  MagicCarpet,
  /// Bundled key `5` (V2 + V3 only).
  MoveTo,
  /// Bundled returned the raw on miss.
  Unknown(u8),
}

impl ParrotPilotingMode {
  /// Build from the raw 7-bit value (`Mask => 0x7f`). Parrot.pm:220.
  #[inline]
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw {
      0 => Self::Manual,
      1 => Self::ReturnHome,
      2 => Self::FlightPlan,
      3 => Self::FollowMe,
      4 => Self::MagicCarpet,
      5 => Self::MoveTo,
      n => Self::Unknown(n),
    }
  }

  /// Raw 7-bit value (round-trip).
  #[inline]
  #[must_use]
  pub const fn as_u8(self) -> u8 {
    match self {
      Self::Manual => 0,
      Self::ReturnHome => 1,
      Self::FlightPlan => 2,
      Self::FollowMe => 3,
      Self::MagicCarpet => 4,
      Self::MoveTo => 5,
      Self::Unknown(n) => n,
    }
  }
}

// ===========================================================================
// ParrotRecordVersion — which of V1 / V2 / V3 produced the sample
// ===========================================================================

/// Parrot `mett` record version (Parrot.pm:35-46). The walker only emits
/// the four-letter IDs `P1` / `P2` / `P3`; a V1 60-byte recording-record
/// without a leading ID falls through to V1 by the bundled
/// "no ID and dirEnd == 60" rule (Parrot.pm:827-833).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotRecordVersion {
  /// `P1` — Parrot V1 streaming metadata (Parrot.pm:87-228).
  V1,
  /// `P2` — Parrot V2 basic streaming metadata (Parrot.pm:230-369).
  V2,
  /// `P3` — Parrot V3 basic streaming metadata (Parrot.pm:371-539).
  V3,
}

impl ParrotRecordVersion {
  /// The id name in the bundled NOTES (`"P1"` / `"P2"` / `"P3"`).
  #[inline]
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::V1 => "P1",
      Self::V2 => "P2",
      Self::V3 => "P3",
    }
  }
}

// ===========================================================================
// ParrotGpsSample — one decoded GPS fix
// ===========================================================================

/// One GPS fix decoded from a Parrot `mett` `P1` / `P2` / `P3` record.
/// Bundled-derived field semantics:
///
///  - **V1** (Parrot.pm:144-167): latitude `int32s / 0x100000` at
///    record offset 28, longitude same scaling at offset 32, altitude
///    `(int32s & 0xffffff00) / 0x100` at offset 36 (low byte = SV count).
///  - **V2** (Parrot.pm:242-265): latitude `int32s / 0x400000` at
///    record offset 8, longitude same at offset 12, altitude
///    `(int32s & 0xffffff00) / 0x100` at offset 16 (low byte = SV count).
///  - **V3** (Parrot.pm:383-406): identical offsets / scaling to V2.
///
/// All three versions store coordinates in decimal degrees AFTER the
/// bundled `ValueConv` divisor (no DDDMM.MMMM intermediate). Altitude
/// is metres after `/ 0x100`. `satellites` is the SV count from the
/// low byte of the altitude word.
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotGpsSample {
  /// Which record version produced this fix (`P1` / `P2` / `P3`).
  version: ParrotRecordVersion,
  /// `GPSLatitude` decimal degrees (already-scaled by bundled ValueConv).
  latitude: Option<f64>,
  /// `GPSLongitude` decimal degrees.
  longitude: Option<f64>,
  /// `GPSAltitude` metres (already-scaled by bundled ValueConv).
  altitude_m: Option<f64>,
  /// `GPSSatellites` — SV count (low byte of altitude word).
  satellites: Option<u8>,
}

impl ParrotGpsSample {
  /// Build an empty sample tagged with the given record version.
  #[inline]
  #[must_use]
  pub const fn new(version: ParrotRecordVersion) -> Self {
    Self {
      version,
      latitude: None,
      longitude: None,
      altitude_m: None,
      satellites: None,
    }
  }

  /// Which record version produced this fix.
  #[inline(always)]
  #[must_use]
  pub const fn version(&self) -> ParrotRecordVersion {
    self.version
  }

  /// `GPSLatitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// `GPSLongitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// `GPSAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `GPSSatellites` — SV count (Parrot.pm:163-167 / :261-265 / :402-406).
  #[inline(always)]
  #[must_use]
  pub const fn satellites(&self) -> Option<u8> {
    self.satellites
  }

  /// `true` when no coordinate or telemetry field is populated.
  #[inline]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.satellites.is_none()
  }

  /// Assign `GPSLatitude`.
  #[inline(always)]
  pub const fn set_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign `GPSLongitude`.
  #[inline(always)]
  pub const fn set_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }

  /// Assign `GPSAltitude` metres.
  #[inline(always)]
  pub const fn set_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign `GPSSatellites`.
  #[inline(always)]
  pub const fn set_satellites(&mut self, v: Option<u8>) -> &mut Self {
    self.satellites = v;
    self
  }
}

// ===========================================================================
// ParrotFlightSample — telemetry from one P1 / P2 / P3 record
// ===========================================================================

/// Flight telemetry decoded from one Parrot `mett` `P1` / `P2` / `P3`
/// record. Mirrors `Image::ExifTool::Parrot::V1` / `V2` / `V3` row
/// (Parrot.pm:87-539). All fields are optional — a given drone may not
/// write every field (e.g. V1 has no `Elevation`; V3 adds `RedBalance`).
///
/// Bundled-derived field semantics:
///  - `battery_percent` (Parrot.pm:139-143 / :364-368 / :495-499) —
///    int8u at offset 27 / 55 / 69, unitless 0..=100.
///  - `wifi_rssi_dbm` (Parrot.pm:133-138 / :358-363 / :489-494) —
///    int8s at offset 26 / 54 / 68, dBm.
///  - `iso` (Parrot.pm:128-132 / :314-318 / :450-454) — int16s/int16u
///    at offset 24 / 50 / 54.
///  - `exposure_time_s` (Parrot.pm:121-127 / :307-313 / :443-449) —
///    int16s/int16u at offset 22 / 48 / 52, ValueConv `$val / 0x100 /
///    1000`.
///  - `flying_state` (Parrot.pm:199-211 / :324-339 / :505-520) —
///    int8u low 7 bits at offset 54 / 52 / 70.
///  - `piloting_mode` (Parrot.pm:217-227 / :340-356 / :521-538) —
///    int8u low 7 bits at offset 55 / 53 / 71.
///  - `altitude_from_takeoff_m` (Parrot.pm:168-173) — int32s scaled
///    `$val / 0x10000` at V1 offset 40; V2 / V3 don't carry this.
///  - `distance_from_home_m` (Parrot.pm:174-178) — int32u scaled
///    `$val / 0x10000` at V1 offset 44; V2 / V3 don't carry this.
///  - `air_speed_mps` (Parrot.pm:281-286 / :422-427) — int16s scaled
///    `$val / 0x100`, with bundled `RawConv => '$val < 0 ? undef : $val'`
///    (Parrot.pm:284 / :425). V1 doesn't carry this field.
///  - `elevation_m` (Parrot.pm:236-241 / :377-382) — int32s scaled
///    `$val / 0x10000` at V2 / V3 offset 4. V1 doesn't carry this.
///  - `time_stamp_us` — concat'd `E1 TimeStamp` extension when present
///    (Parrot.pm:541-551), int64u microseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotFlightSample {
  /// Which record version produced this sample.
  version: ParrotRecordVersion,
  /// `Battery` % (Parrot.pm:139-143 / :364-368 / :495-499).
  battery_percent: Option<u8>,
  /// `WifiRSSI` dBm (Parrot.pm:133-138 / :358-363 / :489-494).
  wifi_rssi_dbm: Option<i8>,
  /// `ISO` (Parrot.pm:128-132 / :314-318 / :450-454).
  iso: Option<i32>,
  /// `ExposureTime` seconds (Parrot.pm:121-127 / :307-313 / :443-449).
  exposure_time_s: Option<f64>,
  /// `FlyingState` (Parrot.pm:199-211 / :324-339 / :505-520).
  flying_state: Option<ParrotFlyingState>,
  /// `PilotingMode` (Parrot.pm:217-227 / :340-356 / :521-538).
  piloting_mode: Option<ParrotPilotingMode>,
  /// `AltitudeFromTakeOff` metres (V1 only — Parrot.pm:168-173).
  altitude_from_takeoff_m: Option<f64>,
  /// `DistanceFromHome` metres (V1 only — Parrot.pm:174-178).
  distance_from_home_m: Option<f64>,
  /// `AirSpeed` m/s (V2 / V3 — Parrot.pm:281-286 / :422-427).
  air_speed_mps: Option<f64>,
  /// `Elevation` metres above ground (V2 / V3 — Parrot.pm:236-241 / :377-382).
  elevation_m: Option<f64>,
  /// `E1 TimeStamp` microsecond counter (Parrot.pm:541-551).
  time_stamp_us: Option<u64>,
}

impl ParrotFlightSample {
  /// Build an empty sample tagged with the given record version.
  #[inline]
  #[must_use]
  pub const fn new(version: ParrotRecordVersion) -> Self {
    Self {
      version,
      battery_percent: None,
      wifi_rssi_dbm: None,
      iso: None,
      exposure_time_s: None,
      flying_state: None,
      piloting_mode: None,
      altitude_from_takeoff_m: None,
      distance_from_home_m: None,
      air_speed_mps: None,
      elevation_m: None,
      time_stamp_us: None,
    }
  }

  /// Which record version produced this sample.
  #[inline(always)]
  #[must_use]
  pub const fn version(&self) -> ParrotRecordVersion {
    self.version
  }

  /// `Battery` % (0..=100).
  #[inline(always)]
  #[must_use]
  pub const fn battery_percent(&self) -> Option<u8> {
    self.battery_percent
  }

  /// `WifiRSSI` dBm.
  #[inline(always)]
  #[must_use]
  pub const fn wifi_rssi_dbm(&self) -> Option<i8> {
    self.wifi_rssi_dbm
  }

  /// `ISO`.
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<i32> {
    self.iso
  }

  /// `ExposureTime` seconds.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time_s
  }

  /// `FlyingState`.
  #[inline(always)]
  #[must_use]
  pub const fn flying_state(&self) -> Option<ParrotFlyingState> {
    self.flying_state
  }

  /// `PilotingMode`.
  #[inline(always)]
  #[must_use]
  pub const fn piloting_mode(&self) -> Option<ParrotPilotingMode> {
    self.piloting_mode
  }

  /// `AltitudeFromTakeOff` metres (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn altitude_from_takeoff_m(&self) -> Option<f64> {
    self.altitude_from_takeoff_m
  }

  /// `DistanceFromHome` metres (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn distance_from_home_m(&self) -> Option<f64> {
    self.distance_from_home_m
  }

  /// `AirSpeed` m/s (V2 / V3).
  #[inline(always)]
  #[must_use]
  pub const fn air_speed_mps(&self) -> Option<f64> {
    self.air_speed_mps
  }

  /// `Elevation` metres above ground (V2 / V3).
  #[inline(always)]
  #[must_use]
  pub const fn elevation_m(&self) -> Option<f64> {
    self.elevation_m
  }

  /// `E1 TimeStamp` microsecond counter.
  #[inline(always)]
  #[must_use]
  pub const fn time_stamp_us(&self) -> Option<u64> {
    self.time_stamp_us
  }

  /// `true` when no telemetry field is populated.
  #[inline]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.battery_percent.is_none()
      && self.wifi_rssi_dbm.is_none()
      && self.iso.is_none()
      && self.exposure_time_s.is_none()
      && self.flying_state.is_none()
      && self.piloting_mode.is_none()
      && self.altitude_from_takeoff_m.is_none()
      && self.distance_from_home_m.is_none()
      && self.air_speed_mps.is_none()
      && self.elevation_m.is_none()
      && self.time_stamp_us.is_none()
  }

  /// Assign `Battery`.
  #[inline(always)]
  pub const fn set_battery_percent(&mut self, v: Option<u8>) -> &mut Self {
    self.battery_percent = v;
    self
  }

  /// Assign `WifiRSSI`.
  #[inline(always)]
  pub const fn set_wifi_rssi_dbm(&mut self, v: Option<i8>) -> &mut Self {
    self.wifi_rssi_dbm = v;
    self
  }

  /// Assign `ISO`.
  #[inline(always)]
  pub const fn set_iso(&mut self, v: Option<i32>) -> &mut Self {
    self.iso = v;
    self
  }

  /// Assign `ExposureTime`.
  #[inline(always)]
  pub const fn set_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }

  /// Assign `FlyingState`.
  #[inline(always)]
  pub const fn set_flying_state(&mut self, v: Option<ParrotFlyingState>) -> &mut Self {
    self.flying_state = v;
    self
  }

  /// Assign `PilotingMode`.
  #[inline(always)]
  pub const fn set_piloting_mode(&mut self, v: Option<ParrotPilotingMode>) -> &mut Self {
    self.piloting_mode = v;
    self
  }

  /// Assign `AltitudeFromTakeOff` metres.
  #[inline(always)]
  pub const fn set_altitude_from_takeoff_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_from_takeoff_m = v;
    self
  }

  /// Assign `DistanceFromHome` metres.
  #[inline(always)]
  pub const fn set_distance_from_home_m(&mut self, v: Option<f64>) -> &mut Self {
    self.distance_from_home_m = v;
    self
  }

  /// Assign `AirSpeed` m/s.
  #[inline(always)]
  pub const fn set_air_speed_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.air_speed_mps = v;
    self
  }

  /// Assign `Elevation` metres.
  #[inline(always)]
  pub const fn set_elevation_m(&mut self, v: Option<f64>) -> &mut Self {
    self.elevation_m = v;
    self
  }

  /// Assign `E1 TimeStamp` microsecond counter.
  #[inline(always)]
  pub const fn set_time_stamp_us(&mut self, v: Option<u64>) -> &mut Self {
    self.time_stamp_us = v;
    self
  }
}

// ===========================================================================
// ParrotMeta — the aggregate per-track result
// ===========================================================================

/// The typed result of Parrot `mett` track decoding — the per-format
/// mirror of what `Process_mett` (Parrot.pm:791-854) emits over every
/// `mett` sample the walker visits. One walker call yields ONE
/// [`ParrotMeta`]; multiple `mett` samples in a track accumulate.
///
/// Empty (`is_empty()`) when no `mett` track was present or every record
/// fork failed to decode.
///
/// **D8 compliance.** Every field is private; access through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotMeta {
  /// GPS fixes in source order (per-sample, one per `P1`/`P2`/`P3` record).
  gps_samples: Vec<ParrotGpsSample>,
  /// Flight telemetry samples in source order.
  flight_samples: Vec<ParrotFlightSample>,
  /// First-only walker warning ("Unexpected length for $metaType record",
  /// Parrot.pm:808).
  warning: Option<SmolStr>,
}

impl ParrotMeta {
  /// An empty result.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      gps_samples: Vec::new(),
      flight_samples: Vec::new(),
      warning: None,
    }
  }

  /// All GPS fixes in source order.
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[ParrotGpsSample] {
    self.gps_samples.as_slice()
  }

  /// All flight telemetry samples in source order.
  #[inline(always)]
  #[must_use]
  pub fn flight_samples(&self) -> &[ParrotFlightSample] {
    self.flight_samples.as_slice()
  }

  /// The first decoded walker warning.
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no record decoded successfully.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.gps_samples.is_empty() && self.flight_samples.is_empty()
  }

  /// The FIRST GPS sample whose `latitude` AND `longitude` are populated —
  /// feeds the [`crate::metadata::GpsLocation`] projection.
  #[inline]
  #[must_use]
  pub fn first_fix(&self) -> Option<&ParrotGpsSample> {
    self
      .gps_samples
      .iter()
      .find(|s| s.latitude.is_some() && s.longitude.is_some())
  }

  /// Append a GPS sample.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, v: ParrotGpsSample) -> &mut Self {
    self.gps_samples.push(v);
    self
  }

  /// Append a flight telemetry sample.
  #[inline(always)]
  pub fn push_flight_sample(&mut self, v: ParrotFlightSample) -> &mut Self {
    self.flight_samples.push(v);
    self
  }

  /// `&mut` to the LAST appended flight sample, or `None` when none
  /// has been pushed yet. Used by the `E1 TimeStamp` extension arm in
  /// [`crate::formats::parrot::process_mett`] to attach the timestamp
  /// to the host P2/P3 sample emitted immediately prior.
  ///
  /// Kept `pub(crate)` to constrain the mutation surface — external
  /// callers should round-trip through `push_flight_sample` for
  /// future flight samples.
  #[inline(always)]
  #[must_use]
  pub(crate) fn flight_samples_mut_last(&mut self) -> Option<&mut ParrotFlightSample> {
    self.flight_samples.last_mut()
  }

  /// Set the FIRST walker warning (subsequent calls are ignored, matching
  /// bundled's `-j` rendering).
  #[inline]
  pub fn set_warning(&mut self, msg: SmolStr) -> &mut Self {
    if self.warning.is_none() {
      self.warning = Some(msg);
    }
    self
  }
}

impl Default for ParrotMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — Parrot mett projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for ParrotMeta {
  /// Project Parrot mett metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** Make = `"Parrot"` (every body that writes a `mett`
  /// track with `[EP]\d` records is a Parrot drone — Anafi / Anafi USA /
  /// Anafi Ai / Anafi Thermal / Bebop / Bebop 2 / Disco). The `mett`
  /// table itself does NOT carry a Model / SerialNumber record — bundled
  /// routes Make/Model for Parrot bodies through the QuickTime
  /// `udta/©mod` + `udta/©mak` path (SP1/SP2 atoms parsed at the
  /// QuickTime SP1 layer, NOT the `mett` track). So today's projection
  /// sets only Make="Parrot" when any `mett` record decoded and leaves
  /// Model/Serial empty for a future SP1/SP2 udta+Keys layer to fill.
  /// Skipped when a higher-priority source already populated Camera.
  ///
  /// **CaptureSettings:** the FIRST P1/P2/P3 flight sample with
  /// ExposureTime OR ISO populates `md.capture()`. FNumber is not present
  /// in `mett` records (Parrot drones have a fixed aperture per body).
  /// Parrot ISO is `int16s`/`int16u`; the typed surface stores `i32` —
  /// the negative-ISO edge case (V1's `int16s` on a malformed buffer) is
  /// clamped to None before mapping into `CaptureSettings.iso: u32`.
  ///
  /// **GpsLocation:** Parrot mett is on-device-GNSS (drone hardware GPS)
  /// — same tier as GoPro / Android CAMM in the priority chain. The
  /// FIRST P1/P2/P3 row with a coordinate pair populates `md.gps()`;
  /// Parrot.pm's V1/V2/V3 tables don't emit a per-sample GPSDateTime
  /// (timestamps live on the E1 extension as a microsecond counter, not
  /// an Exif date+time pair), so `gps.timestamp()` stays `None` here.
  ///
  /// **Warnings:** the walker's `warning()` channel (`Unexpected length
  /// for ARCore mett record` etc.) propagates into `md.warnings()` with
  /// the `"[Parrot mett] "` prefix.
  fn project_into(&self, md: &mut MediaMetadata) {
    let is_empty = self.is_empty();
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none() && !is_empty {
      let mut cam = CameraInfo::new();
      cam.update_make(Some("Parrot".into()));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── CaptureSettings ────────────────────────────────────────────────
    if md.capture().is_none()
      && let Some(f) = self
        .flight_samples()
        .iter()
        .find(|s| s.exposure_time_s().is_some() || s.iso().is_some())
    {
      let mut cap = CaptureSettings::new();
      cap.update_exposure_time_s(f.exposure_time_s());
      // Parrot ISO is `int16s` / `int16u`; clamp the negative-ISO edge
      // case (V1 int16s on a malformed buffer) to None.
      cap.update_iso(f.iso().and_then(|v| u32::try_from(v).ok()));
      if !cap.is_empty() {
        md.set_capture(cap);
      }
    }
    // ── GpsLocation ────────────────────────────────────────────────────
    if md.gps().is_none()
      && let Some(p) = self.first_fix()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(p.latitude())
        .update_longitude(p.longitude())
        .update_altitude_m(p.altitude_m())
        .update_timestamp(None);
      md.set_gps(gps);
    }
    // ── Warnings ───────────────────────────────────────────────────────
    if let Some(w) = self.warning() {
      let mut msg = String::with_capacity(14 + w.len());
      msg.push_str("[Parrot mett] ");
      msg.push_str(w);
      md.push_warning(msg);
    }
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_meta_is_empty() {
    let m = ParrotMeta::new();
    assert!(m.is_empty());
    assert!(m.gps_samples().is_empty());
    assert!(m.flight_samples().is_empty());
    assert!(m.warning().is_none());
    assert!(m.first_fix().is_none());
  }

  #[test]
  fn gps_sample_get_set_roundtrip() {
    let mut g = ParrotGpsSample::new(ParrotRecordVersion::V2);
    assert!(g.is_empty());
    assert_eq!(g.version(), ParrotRecordVersion::V2);
    g.set_latitude(Some(47.6062));
    g.set_longitude(Some(-122.3321));
    g.set_altitude_m(Some(120.5));
    g.set_satellites(Some(9));
    assert_eq!(g.latitude(), Some(47.6062));
    assert_eq!(g.longitude(), Some(-122.3321));
    assert_eq!(g.altitude_m(), Some(120.5));
    assert_eq!(g.satellites(), Some(9));
    assert!(!g.is_empty());
  }

  #[test]
  fn flight_sample_get_set_roundtrip() {
    let mut f = ParrotFlightSample::new(ParrotRecordVersion::V3);
    assert!(f.is_empty());
    assert_eq!(f.version(), ParrotRecordVersion::V3);
    f.set_battery_percent(Some(72));
    f.set_wifi_rssi_dbm(Some(-60));
    f.set_iso(Some(400));
    f.set_exposure_time_s(Some(1.0 / 60.0));
    f.set_flying_state(Some(ParrotFlyingState::Flying));
    f.set_piloting_mode(Some(ParrotPilotingMode::Manual));
    f.set_air_speed_mps(Some(3.5));
    f.set_elevation_m(Some(50.0));
    f.set_time_stamp_us(Some(123_456_789));
    assert_eq!(f.battery_percent(), Some(72));
    assert_eq!(f.wifi_rssi_dbm(), Some(-60));
    assert_eq!(f.iso(), Some(400));
    assert_eq!(f.flying_state(), Some(ParrotFlyingState::Flying));
    assert_eq!(f.piloting_mode(), Some(ParrotPilotingMode::Manual));
    assert_eq!(f.air_speed_mps(), Some(3.5));
    assert_eq!(f.elevation_m(), Some(50.0));
    assert_eq!(f.time_stamp_us(), Some(123_456_789));
    assert!(!f.is_empty());
  }

  #[test]
  fn flying_state_round_trip() {
    for (raw, named) in [
      (0u8, ParrotFlyingState::Landed),
      (1, ParrotFlyingState::TakingOff),
      (2, ParrotFlyingState::Hovering),
      (3, ParrotFlyingState::Flying),
      (4, ParrotFlyingState::Landing),
      (5, ParrotFlyingState::Emergency),
      (6, ParrotFlyingState::UserTakeoff),
      (7, ParrotFlyingState::MotorRamping),
      (8, ParrotFlyingState::EmergencyLanding),
    ] {
      assert_eq!(ParrotFlyingState::from_raw(raw), named);
      assert_eq!(named.as_u8(), raw);
    }
    // Unknown values preserve the byte.
    assert_eq!(
      ParrotFlyingState::from_raw(99),
      ParrotFlyingState::Unknown(99)
    );
    assert_eq!(ParrotFlyingState::Unknown(99).as_u8(), 99);
  }

  #[test]
  fn piloting_mode_round_trip() {
    for (raw, named) in [
      (0u8, ParrotPilotingMode::Manual),
      (1, ParrotPilotingMode::ReturnHome),
      (2, ParrotPilotingMode::FlightPlan),
      (3, ParrotPilotingMode::FollowMe),
      (4, ParrotPilotingMode::MagicCarpet),
      (5, ParrotPilotingMode::MoveTo),
    ] {
      assert_eq!(ParrotPilotingMode::from_raw(raw), named);
      assert_eq!(named.as_u8(), raw);
    }
    assert_eq!(
      ParrotPilotingMode::from_raw(99),
      ParrotPilotingMode::Unknown(99)
    );
  }

  #[test]
  fn record_version_strings() {
    assert_eq!(ParrotRecordVersion::V1.as_str(), "P1");
    assert_eq!(ParrotRecordVersion::V2.as_str(), "P2");
    assert_eq!(ParrotRecordVersion::V3.as_str(), "P3");
  }

  #[test]
  fn first_fix_picks_first_with_lat_and_lon() {
    let mut m = ParrotMeta::new();
    // Sample 0: only altitude set (no lat/lon)
    let mut s0 = ParrotGpsSample::new(ParrotRecordVersion::V1);
    s0.set_altitude_m(Some(10.0));
    m.push_gps_sample(s0);
    // Sample 1: full fix
    let mut s1 = ParrotGpsSample::new(ParrotRecordVersion::V1);
    s1.set_latitude(Some(45.0));
    s1.set_longitude(Some(8.0));
    m.push_gps_sample(s1);
    // Sample 2: also full
    let mut s2 = ParrotGpsSample::new(ParrotRecordVersion::V1);
    s2.set_latitude(Some(46.0));
    s2.set_longitude(Some(9.0));
    m.push_gps_sample(s2);
    let f = m.first_fix().expect("fix");
    assert_eq!(f.latitude(), Some(45.0));
    assert_eq!(f.longitude(), Some(8.0));
  }

  #[test]
  fn set_warning_only_first_wins() {
    let mut m = ParrotMeta::new();
    m.set_warning(SmolStr::new("first"));
    m.set_warning(SmolStr::new("second"));
    assert_eq!(m.warning(), Some("first"));
  }

  // P3-D project_into round-trips.

  #[test]
  fn project_into_empty_meta_writes_nothing() {
    let m = ParrotMeta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
    assert!(md.warnings().is_empty());
  }

  #[test]
  fn project_into_populates_camera_make_parrot_when_any_record_decoded() {
    let mut m = ParrotMeta::new();
    let mut sample = ParrotGpsSample::new(ParrotRecordVersion::V1);
    sample.set_latitude(Some(48.85)).set_longitude(Some(2.35));
    m.push_gps_sample(sample);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.camera().expect("camera").make(), Some("Parrot"));
    let gps = md.gps().expect("gps populated");
    assert_eq!(gps.latitude(), Some(48.85));
    // Parrot mett doesn't carry per-sample GPSDateTime.
    assert_eq!(gps.timestamp(), None);
  }

  #[test]
  fn project_into_propagates_warning_with_parrot_mett_prefix() {
    let mut m = ParrotMeta::new();
    m.set_warning(SmolStr::new("Unexpected length for ARCore mett record"));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.warnings().len(), 1);
    assert_eq!(
      md.warnings()[0],
      "[Parrot mett] Unexpected length for ARCore mett record"
    );
  }
}
