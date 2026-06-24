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
//! ## What this sub-port surfaces (FULL mett parity)
//!
//! Per Parrot.pm:86-749, EVERY field of the per-version drone tables
//! (V1 / V2 / V3), the extension records (E1 / E2 / E3), and the ARCore
//! phone-camera subtables (the `application/arcore-*` MetaType branch) is
//! decoded and emitted:
//!
//!  - **GPS fix (records `P1` / `P2` / `P3`)** — `GPSLatitude` /
//!    `GPSLongitude` / `GPSAltitude` / `GPSSatellites` in a fixed-offset
//!    binary layout. The scaling differs by record version:
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
//!  - **GNSS velocity vector (V2 / V3)** — `GPSVelocityNorth` /
//!    `GPSVelocityEast` / `GPSVelocityDown`, `int16s / 0x100` m/s
//!    (Parrot.pm:266-280 / :407-421). Carried on [`ParrotGpsSample`].
//!  - **Flight + pose telemetry (records `P1` / `P2` / `P3`)** — battery
//!    percent, WifiRSSI, AltitudeFromTakeOff (V1), DistanceFromHome (V1),
//!    Elevation (V2/V3), AirSpeed (V2/V3), DroneYaw/Pitch/Roll (V1),
//!    CameraPan/CameraTilt (V1/V2), SpeedX/Y/Z (V1), FrameView (V1/V2/V3),
//!    DroneQuaternion (V2/V3), FrameBaseView (V3), RedBalance/BlueBalance
//!    (V3), FOV (V3), LinkGoodput/LinkQuality (V3), Binning/Animation,
//!    ExposureTime, ISO, FlyingState, PilotingMode. Surfaced one
//!    [`ParrotFlightSample`] per record.
//!  - **Timestamp extension (record `E1`)** — Parrot.pm:541-551: an
//!    `int64u` microsecond counter. Recorded as `time_stamp_us`
//!    on the host [`ParrotFlightSample`].
//!  - **FollowMe extension (record `E2`)** — Parrot.pm:553-593: the
//!    follow-me TARGET waypoint (`GPSTargetLatitude` / `Longitude` /
//!    `Altitude`) plus `Follow-meMode` (BITMASK) and `Follow-meAnimation`.
//!    Surfaced one [`ParrotFollowMeSample`] per record.
//!  - **Automation extension (record `E3`)** — Parrot.pm:595-660: the
//!    framing + destination waypoints (`GPSFramingLatitude` … /
//!    `GPSDestLatitude` …) plus `AutomationAnimation` and `AutomationFlags`
//!    (BITMASK). Surfaced one [`ParrotAutomationSample`] per record.
//!  - **Drone identity** — `mett` does NOT carry Make/Model/Serial/
//!    Firmware in the per-sample records. Bundled doesn't decode these
//!    in `Parrot::mett`; Parrot bodies surface their identity through
//!    the QuickTime `udta/©mod` + `udta/©mak` / Keys path (SP1+SP2).
//!    The `Make = "Parrot"` projection in [`crate::formats::quicktime`]
//!    fires whenever any `mett` record decoded — the drone-name string
//!    (Anafi / Bebop / …) MUST come from the container's udta.
//!
//!  - **ARCore phone-camera metadata** (`application/arcore-*` MetaType
//!    branch, Parrot.pm:60-83 → the `ARCoreAccel`/`ARCoreGyro`
//!    ProcessBinaryData subtables, Parrot.pm:663-739) — Parrot bodies
//!    pass ARCore accel/gyro through when recorded on an ARCore phone.
//!    The `Accelerometer` / `Gyroscope` three-component vector is decoded
//!    (the `RawConv` `%.15g`-joined float triple, per [`ParrotArCoreSample`]).
//!    `ARCoreVideo` / `ARCoreCustom` (Parrot.pm:741-749) have empty tables
//!    and surface nothing. These are phone-side AR telemetry (NOT the
//!    drone's GPS) so they are EMITTED at `-ee` but not projected into the
//!    camera-indexing domain.
//!
//! ## Projection scope note
//!
//! The CAMERA-INDEXING projection into [`MediaMetadata`] still uses only
//! the drone's own fix + capture settings (Make / GPS / ExposureTime /
//! ISO). The pose / gimbal / velocity / quaternion / colour-balance / FOV
//! columns and the E2 / E3 PLANNED-waypoint coordinates are decoded and
//! EMITTED (full `-ee` parity) but are not projected into the normalized
//! cross-format domain (they are not the camera's identity or its actual
//! fix). See [`ParrotMeta::project_into`].
//!
//! ## D8 compliance
//!
//! Every field is private; access through accessors. Setters return
//! `&mut Self` for chaining. `const fn` where types permit. Enums are
//! unit-only (Parrot's `FlyingState` and `PilotingMode` are closed lists
//! at the bundled level).

extern crate alloc;
use alloc::vec::Vec;

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata};

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
// ParrotFollowMeAnimation — Parrot.pm:585-591 (E2 FollowMe)
// ===========================================================================

/// `Follow-meAnimation` PrintConv (Parrot.pm:585-591). A miss returns the raw
/// numeric (bundled PrintConv hash with no `OTHER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotFollowMeAnimation {
  /// Bundled key `0`.
  None,
  /// Bundled key `1`.
  Orbit,
  /// Bundled key `2`.
  Boomerang,
  /// Bundled key `3`.
  Parabola,
  /// Bundled key `4`.
  Zenith,
  /// Bundled returned the raw numeric on PrintConv miss — keep the byte.
  Unknown(u8),
}

impl ParrotFollowMeAnimation {
  /// Build from the raw int8u value (Parrot.pm:582-592).
  #[inline]
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw {
      0 => Self::None,
      1 => Self::Orbit,
      2 => Self::Boomerang,
      3 => Self::Parabola,
      4 => Self::Zenith,
      n => Self::Unknown(n),
    }
  }

  /// Raw int8u value (round-trip).
  #[inline]
  #[must_use]
  pub const fn as_u8(self) -> u8 {
    match self {
      Self::None => 0,
      Self::Orbit => 1,
      Self::Boomerang => 2,
      Self::Parabola => 3,
      Self::Zenith => 4,
      Self::Unknown(n) => n,
    }
  }
}

// ===========================================================================
// ParrotAutomationAnimation — Parrot.pm:633-649 (E3 Automation)
// ===========================================================================

/// `AutomationAnimation` PrintConv (Parrot.pm:633-649). A miss returns the raw
/// numeric (bundled PrintConv hash with no `OTHER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotAutomationAnimation {
  /// Bundled key `0`.
  None,
  /// Bundled key `1`.
  Orbit,
  /// Bundled key `2`.
  Boomerang,
  /// Bundled key `3`.
  Parabola,
  /// Bundled key `4`.
  DollySlide,
  /// Bundled key `5`.
  DollyZoom,
  /// Bundled key `6`.
  RevealVertical,
  /// Bundled key `7`.
  RevealHorizontal,
  /// Bundled key `8`.
  Candle,
  /// Bundled key `9`.
  FlipFront,
  /// Bundled key `10`.
  FlipBack,
  /// Bundled key `11`.
  FlipLeft,
  /// Bundled key `12`.
  FlipRight,
  /// Bundled key `13`.
  TwistUp,
  /// Bundled key `14`.
  PositionTwistUp,
  /// Bundled returned the raw numeric on PrintConv miss — keep the byte.
  Unknown(u8),
}

impl ParrotAutomationAnimation {
  /// Build from the raw int8u value (Parrot.pm:630-650).
  #[inline]
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw {
      0 => Self::None,
      1 => Self::Orbit,
      2 => Self::Boomerang,
      3 => Self::Parabola,
      4 => Self::DollySlide,
      5 => Self::DollyZoom,
      6 => Self::RevealVertical,
      7 => Self::RevealHorizontal,
      8 => Self::Candle,
      9 => Self::FlipFront,
      10 => Self::FlipBack,
      11 => Self::FlipLeft,
      12 => Self::FlipRight,
      13 => Self::TwistUp,
      14 => Self::PositionTwistUp,
      n => Self::Unknown(n),
    }
  }

  /// Raw int8u value (round-trip).
  #[inline]
  #[must_use]
  pub const fn as_u8(self) -> u8 {
    match self {
      Self::None => 0,
      Self::Orbit => 1,
      Self::Boomerang => 2,
      Self::Parabola => 3,
      Self::DollySlide => 4,
      Self::DollyZoom => 5,
      Self::RevealVertical => 6,
      Self::RevealHorizontal => 7,
      Self::Candle => 8,
      Self::FlipFront => 9,
      Self::FlipBack => 10,
      Self::FlipLeft => 11,
      Self::FlipRight => 12,
      Self::TwistUp => 13,
      Self::PositionTwistUp => 14,
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
///
/// V2 / V3 additionally carry a 3-axis GNSS velocity vector
/// (`GPSVelocityNorth` / `GPSVelocityEast` / `GPSVelocityDown`,
/// Parrot.pm:266-280 / :407-421) scaled `int16s / 0x100` (m/s). V1 has no
/// velocity vector, so those accessors stay `None` for a V1 fix.
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
  /// `GPSVelocityNorth` m/s (V2 / V3 — Parrot.pm:266-270 / :407-411).
  velocity_north_mps: Option<f64>,
  /// `GPSVelocityEast` m/s (V2 / V3 — Parrot.pm:271-275 / :412-416).
  velocity_east_mps: Option<f64>,
  /// `GPSVelocityDown` m/s (V2 / V3 — Parrot.pm:276-280 / :417-421).
  velocity_down_mps: Option<f64>,
  /// The 1-based GLOBAL `Doc<N>` ordinal stamped at extraction (the typed
  /// mirror of `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`, opened once per `mett`
  /// SAMPLE by `ProcessSamples`). All records of one sample share it. `0` until
  /// the walker stamps it (and on unit-built samples).
  doc: u32,
  /// The 1-based moov `Track<N>` index (`SET_GROUP1 = "Track$num"`). `0` until
  /// stamped.
  track_index: u32,
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
      velocity_north_mps: None,
      velocity_east_mps: None,
      velocity_down_mps: None,
      doc: 0,
      track_index: 0,
    }
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
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

  /// `GPSVelocityNorth` m/s (V2 / V3 — Parrot.pm:266-270 / :407-411).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_north_mps(&self) -> Option<f64> {
    self.velocity_north_mps
  }

  /// `GPSVelocityEast` m/s (V2 / V3 — Parrot.pm:271-275 / :412-416).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_east_mps(&self) -> Option<f64> {
    self.velocity_east_mps
  }

  /// `GPSVelocityDown` m/s (V2 / V3 — Parrot.pm:276-280 / :417-421).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_down_mps(&self) -> Option<f64> {
    self.velocity_down_mps
  }

  /// `true` when no coordinate or telemetry field is populated.
  #[inline]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.satellites.is_none()
      && self.velocity_north_mps.is_none()
      && self.velocity_east_mps.is_none()
      && self.velocity_down_mps.is_none()
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

  /// Assign `GPSVelocityNorth` m/s.
  #[inline(always)]
  pub const fn set_velocity_north_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.velocity_north_mps = v;
    self
  }

  /// Assign `GPSVelocityEast` m/s.
  #[inline(always)]
  pub const fn set_velocity_east_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.velocity_east_mps = v;
    self
  }

  /// Assign `GPSVelocityDown` m/s.
  #[inline(always)]
  pub const fn set_velocity_down_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.velocity_down_mps = v;
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
  /// `DroneYaw` degrees (V1 only — Parrot.pm:91-95). `int16s / 0x1000 * 180 / π`.
  drone_yaw_deg: Option<f64>,
  /// `DronePitch` degrees (V1 only — Parrot.pm:96-100).
  drone_pitch_deg: Option<f64>,
  /// `DroneRoll` degrees (V1 only — Parrot.pm:101-105).
  drone_roll_deg: Option<f64>,
  /// `CameraPan` degrees (V1 @10 / V2 @44 — Parrot.pm:106-110 / :297-301).
  camera_pan_deg: Option<f64>,
  /// `CameraTilt` degrees (V1 @12 / V2 @46 — Parrot.pm:111-115 / :302-306).
  camera_tilt_deg: Option<f64>,
  /// `SpeedX` (V1 only — Parrot.pm:179-183). `int16s / 0x100`.
  speed_x: Option<f64>,
  /// `SpeedY` (V1 only — Parrot.pm:184-188).
  speed_y: Option<f64>,
  /// `SpeedZ` (V1 only — Parrot.pm:189-193).
  speed_z: Option<f64>,
  /// `FrameView` quaternion `(W,X,Y,Z)` (V1 @14 scaled `/0x1000`,
  /// V2 @36 / V3 @44 scaled `/0x4000` — Parrot.pm:116-120 / :292-296 / :438-442).
  frame_view: Option<[f64; 4]>,
  /// `DroneQuaternion` `(W,X,Y,Z)` (V2 @28 / V3 @28 scaled `/0x4000` —
  /// Parrot.pm:287-291 / :428-432).
  drone_quaternion: Option<[f64; 4]>,
  /// `FrameBaseView` quaternion `(W,X,Y,Z)` without pan/tilt (V3 @36 scaled
  /// `/0x4000` — Parrot.pm:433-437).
  frame_base_view: Option<[f64; 4]>,
  /// `RedBalance` (V3 only — Parrot.pm:455-460). `int16u / 0x4000`.
  red_balance: Option<f64>,
  /// `BlueBalance` (V3 only — Parrot.pm:461-466). `int16u / 0x4000`.
  blue_balance: Option<f64>,
  /// `FOV` horizontal + vertical field of view, degrees (V3 only —
  /// Parrot.pm:467-474). `int16u[2]`, each `/0x100`.
  fov_deg: Option<[f64; 2]>,
  /// `LinkGoodput` kbit/s (V3 only — Parrot.pm:475-481). `int32u` upper 24 bits.
  link_goodput_kbitps: Option<u32>,
  /// `LinkQuality` 0-5 (V3 only — Parrot.pm:482-488). `int32u` low byte.
  link_quality: Option<u8>,
  /// `Binning` flag (V1 @54 / V2 @52 / V3 @70, `Mask => 0x80` — high bit of the
  /// FlyingState byte; Parrot.pm:194-198 / :319-323 / :500-504).
  binning: Option<u8>,
  /// `Animation` flag (V1 @55 / V2 @53 / V3 @71, `Mask => 0x80` — high bit of the
  /// PilotingMode byte; Parrot.pm:212-216 / :340-344 / :521-525).
  animation: Option<u8>,
  /// `E1 TimeStamp` microsecond counter (Parrot.pm:541-551).
  time_stamp_us: Option<u64>,
  /// The 1-based GLOBAL `Doc<N>` ordinal stamped at extraction (one per `mett`
  /// SAMPLE — `ProcessSamples` opens it via `FoundSomething`). `0` until stamped.
  doc: u32,
  /// The 1-based moov `Track<N>` index. `0` until stamped.
  track_index: u32,
  /// The sample-table `SampleTime` (seconds) `ProcessSamples` emits ahead of the
  /// decoded payload (`ConvertDuration` PrintConv). `None` until stamped.
  sample_time: Option<f64>,
  /// The sample-table `SampleDuration` (seconds). `None` until stamped.
  sample_duration: Option<f64>,
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
      drone_yaw_deg: None,
      drone_pitch_deg: None,
      drone_roll_deg: None,
      camera_pan_deg: None,
      camera_tilt_deg: None,
      speed_x: None,
      speed_y: None,
      speed_z: None,
      frame_view: None,
      drone_quaternion: None,
      frame_base_view: None,
      red_balance: None,
      blue_balance: None,
      fov_deg: None,
      link_goodput_kbitps: None,
      link_quality: None,
      binning: None,
      animation: None,
      time_stamp_us: None,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// Which record version produced this sample.
  #[inline(always)]
  #[must_use]
  pub const fn version(&self) -> ParrotRecordVersion {
    self.version
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The sample-table `SampleTime` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// The sample-table `SampleDuration` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
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

  /// `DroneYaw` degrees (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn drone_yaw_deg(&self) -> Option<f64> {
    self.drone_yaw_deg
  }

  /// `DronePitch` degrees (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn drone_pitch_deg(&self) -> Option<f64> {
    self.drone_pitch_deg
  }

  /// `DroneRoll` degrees (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn drone_roll_deg(&self) -> Option<f64> {
    self.drone_roll_deg
  }

  /// `CameraPan` degrees (V1 / V2).
  #[inline(always)]
  #[must_use]
  pub const fn camera_pan_deg(&self) -> Option<f64> {
    self.camera_pan_deg
  }

  /// `CameraTilt` degrees (V1 / V2).
  #[inline(always)]
  #[must_use]
  pub const fn camera_tilt_deg(&self) -> Option<f64> {
    self.camera_tilt_deg
  }

  /// `SpeedX` (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn speed_x(&self) -> Option<f64> {
    self.speed_x
  }

  /// `SpeedY` (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn speed_y(&self) -> Option<f64> {
    self.speed_y
  }

  /// `SpeedZ` (V1 only).
  #[inline(always)]
  #[must_use]
  pub const fn speed_z(&self) -> Option<f64> {
    self.speed_z
  }

  /// `FrameView` quaternion `(W,X,Y,Z)` (V1 / V2 / V3).
  #[inline(always)]
  #[must_use]
  pub const fn frame_view(&self) -> Option<[f64; 4]> {
    self.frame_view
  }

  /// `DroneQuaternion` `(W,X,Y,Z)` (V2 / V3).
  #[inline(always)]
  #[must_use]
  pub const fn drone_quaternion(&self) -> Option<[f64; 4]> {
    self.drone_quaternion
  }

  /// `FrameBaseView` quaternion `(W,X,Y,Z)` without pan/tilt (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn frame_base_view(&self) -> Option<[f64; 4]> {
    self.frame_base_view
  }

  /// `RedBalance` (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn red_balance(&self) -> Option<f64> {
    self.red_balance
  }

  /// `BlueBalance` (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn blue_balance(&self) -> Option<f64> {
    self.blue_balance
  }

  /// `FOV` horizontal + vertical field of view, degrees (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn fov_deg(&self) -> Option<[f64; 2]> {
    self.fov_deg
  }

  /// `LinkGoodput` kbit/s (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn link_goodput_kbitps(&self) -> Option<u32> {
    self.link_goodput_kbitps
  }

  /// `LinkQuality` 0-5 (V3 only).
  #[inline(always)]
  #[must_use]
  pub const fn link_quality(&self) -> Option<u8> {
    self.link_quality
  }

  /// `Binning` flag (high bit of the FlyingState byte).
  #[inline(always)]
  #[must_use]
  pub const fn binning(&self) -> Option<u8> {
    self.binning
  }

  /// `Animation` flag (high bit of the PilotingMode byte).
  #[inline(always)]
  #[must_use]
  pub const fn animation(&self) -> Option<u8> {
    self.animation
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
      && self.drone_yaw_deg.is_none()
      && self.drone_pitch_deg.is_none()
      && self.drone_roll_deg.is_none()
      && self.camera_pan_deg.is_none()
      && self.camera_tilt_deg.is_none()
      && self.speed_x.is_none()
      && self.speed_y.is_none()
      && self.speed_z.is_none()
      && self.frame_view.is_none()
      && self.drone_quaternion.is_none()
      && self.frame_base_view.is_none()
      && self.red_balance.is_none()
      && self.blue_balance.is_none()
      && self.fov_deg.is_none()
      && self.link_goodput_kbitps.is_none()
      && self.link_quality.is_none()
      && self.binning.is_none()
      && self.animation.is_none()
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

  /// Assign `DroneYaw` degrees.
  #[inline(always)]
  pub const fn set_drone_yaw_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_yaw_deg = v;
    self
  }

  /// Assign `DronePitch` degrees.
  #[inline(always)]
  pub const fn set_drone_pitch_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_pitch_deg = v;
    self
  }

  /// Assign `DroneRoll` degrees.
  #[inline(always)]
  pub const fn set_drone_roll_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_roll_deg = v;
    self
  }

  /// Assign `CameraPan` degrees.
  #[inline(always)]
  pub const fn set_camera_pan_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.camera_pan_deg = v;
    self
  }

  /// Assign `CameraTilt` degrees.
  #[inline(always)]
  pub const fn set_camera_tilt_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.camera_tilt_deg = v;
    self
  }

  /// Assign `SpeedX`.
  #[inline(always)]
  pub const fn set_speed_x(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_x = v;
    self
  }

  /// Assign `SpeedY`.
  #[inline(always)]
  pub const fn set_speed_y(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_y = v;
    self
  }

  /// Assign `SpeedZ`.
  #[inline(always)]
  pub const fn set_speed_z(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_z = v;
    self
  }

  /// Assign `FrameView` quaternion `(W,X,Y,Z)`.
  #[inline(always)]
  pub const fn set_frame_view(&mut self, v: Option<[f64; 4]>) -> &mut Self {
    self.frame_view = v;
    self
  }

  /// Assign `DroneQuaternion` `(W,X,Y,Z)`.
  #[inline(always)]
  pub const fn set_drone_quaternion(&mut self, v: Option<[f64; 4]>) -> &mut Self {
    self.drone_quaternion = v;
    self
  }

  /// Assign `FrameBaseView` quaternion `(W,X,Y,Z)`.
  #[inline(always)]
  pub const fn set_frame_base_view(&mut self, v: Option<[f64; 4]>) -> &mut Self {
    self.frame_base_view = v;
    self
  }

  /// Assign `RedBalance`.
  #[inline(always)]
  pub const fn set_red_balance(&mut self, v: Option<f64>) -> &mut Self {
    self.red_balance = v;
    self
  }

  /// Assign `BlueBalance`.
  #[inline(always)]
  pub const fn set_blue_balance(&mut self, v: Option<f64>) -> &mut Self {
    self.blue_balance = v;
    self
  }

  /// Assign `FOV` `(horizontal, vertical)` degrees.
  #[inline(always)]
  pub const fn set_fov_deg(&mut self, v: Option<[f64; 2]>) -> &mut Self {
    self.fov_deg = v;
    self
  }

  /// Assign `LinkGoodput` kbit/s.
  #[inline(always)]
  pub const fn set_link_goodput_kbitps(&mut self, v: Option<u32>) -> &mut Self {
    self.link_goodput_kbitps = v;
    self
  }

  /// Assign `LinkQuality`.
  #[inline(always)]
  pub const fn set_link_quality(&mut self, v: Option<u8>) -> &mut Self {
    self.link_quality = v;
    self
  }

  /// Assign `Binning` flag.
  #[inline(always)]
  pub const fn set_binning(&mut self, v: Option<u8>) -> &mut Self {
    self.binning = v;
    self
  }

  /// Assign `Animation` flag.
  #[inline(always)]
  pub const fn set_animation(&mut self, v: Option<u8>) -> &mut Self {
    self.animation = v;
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
// ParrotFollowMeSample — E2 FollowMe extension (Parrot.pm:553-593)
// ===========================================================================

/// One `E2` FollowMe extension record (`Image::ExifTool::Parrot::FollowMe`,
/// Parrot.pm:553-593). Carries the follow-me TARGET waypoint coordinates plus
/// the mode bitmask and animation. The coordinates have ValueConv but NO
/// PrintConv (raw decimal degrees / metres in both `-n` and `-j`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotFollowMeSample {
  /// `GPSTargetLatitude` decimal degrees (Parrot.pm:558-562). `int32s / 0x400000`.
  target_latitude: Option<f64>,
  /// `GPSTargetLongitude` decimal degrees (Parrot.pm:563-567). `int32s / 0x400000`.
  target_longitude: Option<f64>,
  /// `GPSTargetAltitude` metres (Parrot.pm:568-572). `int32s / 0x10000`.
  target_altitude_m: Option<f64>,
  /// `Follow-meMode` raw int8u (Parrot.pm:573-581) — rendered via the
  /// `BITMASK` DecodeBits at emit time. `None` when the byte was absent.
  mode_flags: Option<u8>,
  /// `Follow-meAnimation` (Parrot.pm:582-592).
  animation: Option<ParrotFollowMeAnimation>,
  /// The 1-based GLOBAL `Doc<N>` ordinal. `0` until stamped.
  doc: u32,
  /// The 1-based moov `Track<N>` index. `0` until stamped.
  track_index: u32,
  /// The sample-table `SampleTime` (seconds). `None` until stamped.
  sample_time: Option<f64>,
  /// The sample-table `SampleDuration` (seconds). `None` until stamped.
  sample_duration: Option<f64>,
}

impl ParrotFollowMeSample {
  /// Build an empty FollowMe sample.
  #[inline]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      target_latitude: None,
      target_longitude: None,
      target_altitude_m: None,
      mode_flags: None,
      animation: None,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The sample-table `SampleTime` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// The sample-table `SampleDuration` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// `GPSTargetLatitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn target_latitude(&self) -> Option<f64> {
    self.target_latitude
  }

  /// `GPSTargetLongitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn target_longitude(&self) -> Option<f64> {
    self.target_longitude
  }

  /// `GPSTargetAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn target_altitude_m(&self) -> Option<f64> {
    self.target_altitude_m
  }

  /// `Follow-meMode` raw int8u (rendered via `BITMASK` DecodeBits at emit time).
  #[inline(always)]
  #[must_use]
  pub const fn mode_flags(&self) -> Option<u8> {
    self.mode_flags
  }

  /// `Follow-meAnimation`.
  #[inline(always)]
  #[must_use]
  pub const fn animation(&self) -> Option<ParrotFollowMeAnimation> {
    self.animation
  }

  /// `true` when no field is populated.
  #[inline]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.target_latitude.is_none()
      && self.target_longitude.is_none()
      && self.target_altitude_m.is_none()
      && self.mode_flags.is_none()
      && self.animation.is_none()
  }

  /// Assign `GPSTargetLatitude`.
  #[inline(always)]
  pub const fn set_target_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.target_latitude = v;
    self
  }

  /// Assign `GPSTargetLongitude`.
  #[inline(always)]
  pub const fn set_target_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.target_longitude = v;
    self
  }

  /// Assign `GPSTargetAltitude` metres.
  #[inline(always)]
  pub const fn set_target_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.target_altitude_m = v;
    self
  }

  /// Assign `Follow-meMode` raw int8u.
  #[inline(always)]
  pub const fn set_mode_flags(&mut self, v: Option<u8>) -> &mut Self {
    self.mode_flags = v;
    self
  }

  /// Assign `Follow-meAnimation`.
  #[inline(always)]
  pub const fn set_animation(&mut self, v: Option<ParrotFollowMeAnimation>) -> &mut Self {
    self.animation = v;
    self
  }
}

impl Default for ParrotFollowMeSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// ParrotAutomationSample — E3 Automation extension (Parrot.pm:595-660)
// ===========================================================================

/// One `E3` Automation extension record (`Image::ExifTool::Parrot::Automation`,
/// Parrot.pm:595-660). Carries the framing + destination waypoint coordinates
/// plus the automation animation and the flags bitmask. The coordinates have
/// ValueConv but NO PrintConv (raw decimal degrees / metres in both modes).
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotAutomationSample {
  /// `GPSFramingLatitude` decimal degrees (Parrot.pm:600-604). `int32s / 0x400000`.
  framing_latitude: Option<f64>,
  /// `GPSFramingLongitude` decimal degrees (Parrot.pm:605-609). `int32s / 0x400000`.
  framing_longitude: Option<f64>,
  /// `GPSFramingAltitude` metres (Parrot.pm:610-614). `int32s / 0x10000`.
  framing_altitude_m: Option<f64>,
  /// `GPSDestLatitude` decimal degrees (Parrot.pm:615-619). `int32s / 0x400000`.
  dest_latitude: Option<f64>,
  /// `GPSDestLongitude` decimal degrees (Parrot.pm:620-624). `int32s / 0x400000`.
  dest_longitude: Option<f64>,
  /// `GPSDestAltitude` metres (Parrot.pm:625-629). `int32s / 0x10000`.
  dest_altitude_m: Option<f64>,
  /// `AutomationAnimation` (Parrot.pm:630-650).
  animation: Option<ParrotAutomationAnimation>,
  /// `AutomationFlags` raw int8u (Parrot.pm:651-659) — rendered via the
  /// `BITMASK` DecodeBits at emit time. `None` when the byte was absent.
  flags: Option<u8>,
  /// The 1-based GLOBAL `Doc<N>` ordinal. `0` until stamped.
  doc: u32,
  /// The 1-based moov `Track<N>` index. `0` until stamped.
  track_index: u32,
  /// The sample-table `SampleTime` (seconds). `None` until stamped.
  sample_time: Option<f64>,
  /// The sample-table `SampleDuration` (seconds). `None` until stamped.
  sample_duration: Option<f64>,
}

impl ParrotAutomationSample {
  /// Build an empty Automation sample.
  #[inline]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      framing_latitude: None,
      framing_longitude: None,
      framing_altitude_m: None,
      dest_latitude: None,
      dest_longitude: None,
      dest_altitude_m: None,
      animation: None,
      flags: None,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The sample-table `SampleTime` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// The sample-table `SampleDuration` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// `GPSFramingLatitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn framing_latitude(&self) -> Option<f64> {
    self.framing_latitude
  }

  /// `GPSFramingLongitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn framing_longitude(&self) -> Option<f64> {
    self.framing_longitude
  }

  /// `GPSFramingAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn framing_altitude_m(&self) -> Option<f64> {
    self.framing_altitude_m
  }

  /// `GPSDestLatitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn dest_latitude(&self) -> Option<f64> {
    self.dest_latitude
  }

  /// `GPSDestLongitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn dest_longitude(&self) -> Option<f64> {
    self.dest_longitude
  }

  /// `GPSDestAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn dest_altitude_m(&self) -> Option<f64> {
    self.dest_altitude_m
  }

  /// `AutomationAnimation`.
  #[inline(always)]
  #[must_use]
  pub const fn animation(&self) -> Option<ParrotAutomationAnimation> {
    self.animation
  }

  /// `AutomationFlags` raw int8u (rendered via `BITMASK` DecodeBits at emit time).
  #[inline(always)]
  #[must_use]
  pub const fn flags(&self) -> Option<u8> {
    self.flags
  }

  /// `true` when no field is populated.
  #[inline]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.framing_latitude.is_none()
      && self.framing_longitude.is_none()
      && self.framing_altitude_m.is_none()
      && self.dest_latitude.is_none()
      && self.dest_longitude.is_none()
      && self.dest_altitude_m.is_none()
      && self.animation.is_none()
      && self.flags.is_none()
  }

  /// Assign `GPSFramingLatitude`.
  #[inline(always)]
  pub const fn set_framing_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.framing_latitude = v;
    self
  }

  /// Assign `GPSFramingLongitude`.
  #[inline(always)]
  pub const fn set_framing_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.framing_longitude = v;
    self
  }

  /// Assign `GPSFramingAltitude` metres.
  #[inline(always)]
  pub const fn set_framing_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.framing_altitude_m = v;
    self
  }

  /// Assign `GPSDestLatitude`.
  #[inline(always)]
  pub const fn set_dest_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.dest_latitude = v;
    self
  }

  /// Assign `GPSDestLongitude`.
  #[inline(always)]
  pub const fn set_dest_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.dest_longitude = v;
    self
  }

  /// Assign `GPSDestAltitude` metres.
  #[inline(always)]
  pub const fn set_dest_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.dest_altitude_m = v;
    self
  }

  /// Assign `AutomationAnimation`.
  #[inline(always)]
  pub const fn set_animation(&mut self, v: Option<ParrotAutomationAnimation>) -> &mut Self {
    self.animation = v;
    self
  }

  /// Assign `AutomationFlags` raw int8u.
  #[inline(always)]
  pub const fn set_flags(&mut self, v: Option<u8>) -> &mut Self {
    self.flags = v;
    self
  }
}

impl Default for ParrotAutomationSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// ParrotArCoreSample — the ARCore phone-camera mett subtables
// ===========================================================================

/// Which ARCore subtable produced a sample — selects the emitted tag NAME.
/// Parrot.pm:60-83 maps six `application/arcore-*` MetaType strings onto four
/// distinct `ProcessBinaryData` tables, but only two tag NAMES are ever
/// surfaced (the others are `Unknown`/empty): `Accelerometer`
/// (`ARCoreAccel`/`ARCoreAccel0`, Parrot.pm:663-706) and `Gyroscope`
/// (`ARCoreGyro`/`ARCoreGyro0`, Parrot.pm:709-739). `ARCoreVideo`/`ARCoreCustom`
/// (Parrot.pm:741-749) have empty tables and emit nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParrotArCoreTagKind {
  /// `Accelerometer` (Parrot.pm:676 / :702).
  Accelerometer,
  /// `Gyroscope` (Parrot.pm:722 / :735).
  Gyroscope,
}

impl ParrotArCoreTagKind {
  /// The ExifTool tag Name this kind emits.
  #[inline(always)]
  #[must_use]
  pub const fn tag_name(self) -> &'static str {
    match self {
      Self::Accelerometer => "Accelerometer",
      Self::Gyroscope => "Gyroscope",
    }
  }
}

/// One ARCore accel/gyro reading decoded from a Parrot `mett` sample whose
/// `MetaType` is an `application/arcore-*` string (Parrot.pm:60-83 dispatch).
///
/// The bundled tables decode a three-component vector via a Perl `RawConv`
/// (`GetFloat($val,0) . " " . GetFloat($val,5) . " " . GetFloat($val,10)`,
/// Parrot.pm:678 / :704 / :724 / :737) — three little-endian `float`s read at
/// `undef`-buffer offsets 0 / 5 / 10, space-joined. The value is a STRING (the
/// `RawConv` result) with NO ValueConv/PrintConv, so `-n` and `-j` render
/// identically. Each component is `Some` iff its 4 bytes are in range
/// (`GetFloat` returns `undef` on a short read, ExifTool.pm:6065-6066); a
/// missing component renders as an EMPTY slot in the join (e.g. `"0 0 "` when
/// the third float is past the record end), faithful to Perl's
/// uninitialized-value concatenation.
///
/// **D8 compliance.** Every field is private; access through the accessors.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParrotArCoreSample {
  /// Which subtable produced this reading (selects the tag NAME).
  kind: ParrotArCoreTagKind,
  /// The three space-joined float components (offsets 0 / 5 / 10 of the
  /// `undef` buffer). `None` when the component's 4 bytes were out of range
  /// (a truncated record) — rendered as an empty slot in the join.
  components: [Option<f32>; 3],
  /// The 1-based GLOBAL `Doc<N>` ordinal. `0` until stamped.
  doc: u32,
  /// The 1-based moov `Track<N>` index. `0` until stamped.
  track_index: u32,
  /// The sample-table `SampleTime` (seconds). `None` until stamped.
  sample_time: Option<f64>,
  /// The sample-table `SampleDuration` (seconds). `None` until stamped.
  sample_duration: Option<f64>,
  /// The TLV WALK-ORDER ordinal within the raising `mett` sample — a
  /// per-sample monotonic counter the walker assigns in `HandleTag`/`Warn`
  /// order (a RawConv warning of the decoded TLV gets a LOWER ordinal than the
  /// vector it precedes; a later overflow TLV's warning gets a HIGHER one).
  /// `emit_parrot` interleaves the per-doc vector + warning records by this
  /// ordinal so a valid-TLV vector emits AHEAD of a later overflow-TLV warning
  /// (walk order), not all-warnings-then-vector. `0` for unit-built samples
  /// (they share one doc + ordinal, keeping stable insertion order).
  seq: u32,
}

impl ParrotArCoreSample {
  /// Build an ARCore reading of the given kind from three optional float
  /// components.
  #[inline]
  #[must_use]
  pub const fn new(kind: ParrotArCoreTagKind, components: [Option<f32>; 3]) -> Self {
    Self {
      kind,
      components,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
      seq: 0,
    }
  }

  /// Set the TLV walk-order ordinal (see [`Self::seq`]) — the walker stamps it
  /// at `HandleTag` position so `emit_parrot` can interleave vectors + warnings
  /// in original walk order.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn with_seq(mut self, seq: u32) -> Self {
    self.seq = seq;
    self
  }

  /// Which subtable produced this reading.
  #[inline(always)]
  #[must_use]
  pub const fn kind(&self) -> ParrotArCoreTagKind {
    self.kind
  }

  /// The three float components (offsets 0 / 5 / 10; `None` = out-of-range).
  #[inline(always)]
  #[must_use]
  pub const fn components(&self) -> [Option<f32>; 3] {
    self.components
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The sample-table `SampleTime` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// The sample-table `SampleDuration` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// The TLV walk-order ordinal within the raising sample (see [`Self::seq`]).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn seq(&self) -> u32 {
    self.seq
  }
}

// ===========================================================================
// ParrotArCoreWarning — a `Process_mett` ARCore warning as a TIMED record
// ===========================================================================

/// One ARCore `Process_mett` warning raised while walking an `application/
/// arcore-*` `mett` sample (Parrot.pm:802-820), carried as a FIRST-CLASS TIMED
/// record (NOT a single unscoped string) so it can ride the in-stream
/// group-scoped `Doc<N>:Track<N>:Warning` axis exactly like the sibling
/// [`crate::metadata::CammWarning`] / [`crate::metadata::CanonCtmdWarning`] /
/// [`crate::metadata::DjiWarning`] producers.
///
/// Two `Process_mett` warnings exist on the ARCore branch:
///  - **`Unexpected length for $metaType record`** (Parrot.pm:808,
///    `$et->Warn(.., 1)` ⇒ MINOR ⇒ rendered `[minor] …`) — the TLV length
///    overflows the sample, so the loop `last`s BEFORE the `HandleTag`: the
///    sample emits ONLY this warning (no accel/gyro vector). `$metaType` is
///    interpolated (e.g. `application/arcore-accel`), NOT a fixed string.
///  - **`RawConv <Kind>: Use of uninitialized value in concatenation (.) or
///    string`** (Parrot.pm:678/704/724/737, a Perl runtime `Warn` from the
///    `GetFloat`-join `RawConv`; NON-minor) — a truncated record drops an
///    out-of-range float component to an empty slot, so the sample emits BOTH
///    the partial `Accelerometer`/`Gyroscope` value AND this warning (the
///    warning AHEAD of the value, the RawConv firing as the value is built).
///
/// ExifTool emits each as `Track<N>:Warning` (priority-0 first-wins, file-global
/// `WAS_WARNED` text dedup with a ` [x$n]` repeat count) at the raising sample's
/// walk position — verified vs bundled 13.59 (`-ee -G1`/`-G3`).
///
/// **D8 compliance.** Every field is private; access through the accessors.
#[derive(Debug, Clone, PartialEq)]
pub struct ParrotArCoreWarning {
  /// The warning string WITHOUT any `[minor]` prefix (applied at emit time from
  /// [`Self::minor`]).
  message: SmolStr,
  /// `true` for the `Warn(.., 1)` MINOR `Unexpected length for $metaType record`
  /// warning; `false` for the `RawConv … uninitialized value` warning.
  minor: bool,
  /// The 1-based GLOBAL `Doc<N>` ordinal of the ARCore sample that raised the
  /// warning (`0` until stamped). Surfaced as the `Doc<N>:` family-3 prefix at
  /// `-G3`; collapsed away at `-G1`.
  doc: u32,
  /// The 1-based moov `Track<N>` index the warning is scoped to (`0` until
  /// stamped; defaults to `Track1` at emit time).
  track_index: u32,
  /// `SampleTime` (seconds) of the sample that raised the warning — emitted
  /// ahead of the `Warning` under that sample's `Doc<N>`. `None` until stamped.
  sample_time: Option<f64>,
  /// `SampleDuration` (seconds) of the sample that raised the warning (paired
  /// with [`Self::sample_time`]). `None` until stamped.
  sample_duration: Option<f64>,
  /// The TLV WALK-ORDER ordinal within the raising `mett` sample — a per-sample
  /// monotonic counter the walker assigns in `HandleTag`/`Warn` order. A RawConv
  /// warning (raised while the decoded TLV's value is built) gets a LOWER
  /// ordinal than that TLV's vector; a later overflow TLV's warning gets a
  /// HIGHER ordinal than the vector. `emit_parrot` interleaves the per-doc
  /// vector + warning records by this ordinal so each lands at its walk
  /// position (the RawConv warning AHEAD of the partial vector, a later overflow
  /// warning AFTER it). `0` for unit-built warnings.
  seq: u32,
}

impl ParrotArCoreWarning {
  /// Build a warning carrying `message` and the `minor` flag (no track / doc /
  /// timing / seq yet — the dispatch arm stamps the doc/track/timing after the
  /// `process_mett` call; the walker stamps the seq in-place via
  /// [`Self::with_seq`]).
  #[inline(always)]
  #[must_use]
  pub fn new(message: SmolStr, minor: bool) -> Self {
    Self {
      message,
      minor,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
      seq: 0,
    }
  }

  /// Set the TLV walk-order ordinal (see [`Self::seq`]) — the walker stamps it
  /// at the `Warn` position so `emit_parrot` can interleave this warning with
  /// the sample's vector in original walk order.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn with_seq(mut self, seq: u32) -> Self {
    self.seq = seq;
    self
  }

  /// The warning string WITHOUT the `[minor]` prefix.
  #[inline(always)]
  #[must_use]
  pub fn message(&self) -> &str {
    self.message.as_str()
  }

  /// `true` for the MINOR `Unexpected length for $metaType record` warning
  /// (`Warn(.., 1)`) — the emission prepends `[minor] `.
  #[inline(always)]
  #[must_use]
  pub const fn minor(&self) -> bool {
    self.minor
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal of the sample that raised this warning
  /// (`0` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> u32 {
    self.doc
  }

  /// The 1-based moov `Track<N>` index this warning is scoped to (`0` when
  /// unstamped; defaults to `Track1` at emit time).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The sample-table `SampleTime` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// The sample-table `SampleDuration` in seconds (`None` when unstamped).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// The TLV walk-order ordinal within the raising sample (see [`Self::seq`]).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn seq(&self) -> u32 {
    self.seq
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
  /// `E2` FollowMe extension records in source order (Parrot.pm:553-593).
  follow_me_samples: Vec<ParrotFollowMeSample>,
  /// `E3` Automation extension records in source order (Parrot.pm:595-660).
  automation_samples: Vec<ParrotAutomationSample>,
  /// ARCore accel/gyro readings in source order — the `application/arcore-*`
  /// MetaType branch (Parrot.pm:60-83 + the `ARCoreAccel`/`ARCoreGyro` tables).
  arcore_samples: Vec<ParrotArCoreSample>,
  /// ARCore `Process_mett` walker warnings as TIMED records (the overflow
  /// `Unexpected length for $metaType record` + the truncated-float `RawConv …
  /// uninitialized value`, Parrot.pm:808/678) — each carrying its sample's
  /// `Doc<N>`/`Track<N>`/timing so it rides the in-stream group-scoped
  /// `Warning` axis (the camm/ctmd/dji pattern), in source order.
  arcore_warnings: Vec<ParrotArCoreWarning>,
}

impl ParrotMeta {
  /// An empty result.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      gps_samples: Vec::new(),
      flight_samples: Vec::new(),
      follow_me_samples: Vec::new(),
      automation_samples: Vec::new(),
      arcore_samples: Vec::new(),
      arcore_warnings: Vec::new(),
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

  /// All `E2` FollowMe extension records in source order.
  #[inline(always)]
  #[must_use]
  pub fn follow_me_samples(&self) -> &[ParrotFollowMeSample] {
    self.follow_me_samples.as_slice()
  }

  /// All `E3` Automation extension records in source order.
  #[inline(always)]
  #[must_use]
  pub fn automation_samples(&self) -> &[ParrotAutomationSample] {
    self.automation_samples.as_slice()
  }

  /// All ARCore accel/gyro readings in source order.
  #[inline(always)]
  #[must_use]
  pub fn arcore_samples(&self) -> &[ParrotArCoreSample] {
    self.arcore_samples.as_slice()
  }

  /// All ARCore `Process_mett` walker warnings (timed records) in source order.
  #[inline(always)]
  #[must_use]
  pub fn arcore_warnings(&self) -> &[ParrotArCoreWarning] {
    self.arcore_warnings.as_slice()
  }

  /// `true` when this `mett` track produced NO `-ee` emission — no decoded
  /// record AND no ARCore walker warning.
  ///
  /// Gates the EMISSION early-return in
  /// [`crate::formats::quicktime::emit_parrot`]: a warning-only ARCore sample
  /// (an overflow TLV that `last`s before any `HandleTag`) decodes NO vector
  /// but STILL emits its `Doc<N>:Track<N>:SampleTime`/`SampleDuration`/`Warning`
  /// at `-ee`, so the ARCore warnings count here. Distinct from
  /// [`Self::has_drone_records`], which gates the camera/GPS PROJECTION (drone
  /// records only — ARCore is phone telemetry, never projected).
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.gps_samples.is_empty()
      && self.flight_samples.is_empty()
      && self.follow_me_samples.is_empty()
      && self.automation_samples.is_empty()
      && self.arcore_samples.is_empty()
      && self.arcore_warnings.is_empty()
  }

  /// `true` when this track decoded at least one Parrot DRONE record — a `P`
  /// GPS / flight sample, an `E2` FollowMe, or an `E3` Automation record.
  ///
  /// Gates the camera-indexing PROJECTION (`Make = "Parrot"` + GPS + capture)
  /// in [`Self::project_into`]. ARCore (`application/arcore-*`) samples are
  /// PHONE telemetry, NOT a Parrot drone camera — an ARCore-only `mett` track
  /// emits at `-ee` (so it is NOT [`Self::is_empty`]) but must project NOTHING
  /// into the normalized camera domain. So this is the projection-eligibility
  /// predicate, deliberately SPLIT from the emission non-emptiness above:
  /// `arcore_samples` / `arcore_warnings` do NOT count here.
  #[inline(always)]
  #[must_use]
  pub fn has_drone_records(&self) -> bool {
    !self.gps_samples.is_empty()
      || !self.flight_samples.is_empty()
      || !self.follow_me_samples.is_empty()
      || !self.automation_samples.is_empty()
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

  /// Append an `E2` FollowMe extension record.
  #[inline(always)]
  pub fn push_follow_me_sample(&mut self, v: ParrotFollowMeSample) -> &mut Self {
    self.follow_me_samples.push(v);
    self
  }

  /// Append an `E3` Automation extension record.
  #[inline(always)]
  pub fn push_automation_sample(&mut self, v: ParrotAutomationSample) -> &mut Self {
    self.automation_samples.push(v);
    self
  }

  /// Append an ARCore accel/gyro reading.
  #[inline(always)]
  pub fn push_arcore_sample(&mut self, v: ParrotArCoreSample) -> &mut Self {
    self.arcore_samples.push(v);
    self
  }

  /// Append an ARCore `Process_mett` walker warning (timed record). The
  /// dispatch arm stamps its `Doc<N>`/`Track<N>`/timing after the
  /// `process_mett` call, alongside the sample vectors.
  #[inline(always)]
  pub fn push_arcore_warning(&mut self, v: ParrotArCoreWarning) -> &mut Self {
    self.arcore_warnings.push(v);
    self
  }

  /// The number of GPS samples decoded so far — a watermark the stream walker
  /// takes BEFORE one `process_mett` call so it can stamp the `Doc<N>` / track
  /// coordinates onto exactly the GPS samples that call appended (mirrors
  /// [`crate::metadata::SonyRtmdMeta::sample_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn gps_sample_count(&self) -> usize {
    self.gps_samples.len()
  }

  /// The number of flight samples decoded so far — the flight-vector watermark
  /// (the two vectors advance independently when a record yields only one).
  #[inline(always)]
  #[must_use]
  pub(crate) fn flight_sample_count(&self) -> usize {
    self.flight_samples.len()
  }

  /// The number of `E2` FollowMe samples decoded so far — the FollowMe
  /// watermark (the extension vectors advance independently of the P-records).
  #[inline(always)]
  #[must_use]
  pub(crate) fn follow_me_sample_count(&self) -> usize {
    self.follow_me_samples.len()
  }

  /// The number of `E3` Automation samples decoded so far — the Automation
  /// watermark.
  #[inline(always)]
  #[must_use]
  pub(crate) fn automation_sample_count(&self) -> usize {
    self.automation_samples.len()
  }

  /// The number of ARCore accel/gyro readings decoded so far — the ARCore
  /// watermark (the `application/arcore-*` MetaType branch advances independently
  /// of the drone P/E-records; a `mett` track is one or the other).
  #[inline(always)]
  #[must_use]
  pub(crate) fn arcore_sample_count(&self) -> usize {
    self.arcore_samples.len()
  }

  /// The number of ARCore walker warnings recorded so far — the warning
  /// watermark (an overflow TLV pushes a warning but NO sample, so the warning
  /// vector advances independently of `arcore_samples`).
  #[inline(always)]
  #[must_use]
  pub(crate) fn arcore_warning_count(&self) -> usize {
    self.arcore_warnings.len()
  }

  /// Stamp the GLOBAL `Doc<N>` ordinal, the `Track<N>` index, and the
  /// sample-table `SampleTime`/`SampleDuration` (seconds) onto every GPS and
  /// flight sample at or after the given watermarks — exactly the records ONE
  /// `process_mett` call appended (mirrors
  /// [`crate::metadata::SonyRtmdMeta::stamp_doc_from`] +
  /// `stamp_track_index_from`, fused since `ProcessSamples` opens ONE `Doc<N>`
  /// per `mett` SAMPLE and `Process_mett` `HandleTag`s every record under it).
  /// `SampleTime`/`SampleDuration` land on the flight samples (the per-sample
  /// timing `ProcessSamples` emits ahead of the payload).
  pub(crate) fn stamp_doc_from(
    &mut self,
    gps_start: usize,
    flight_start: usize,
    follow_me_start: usize,
    automation_start: usize,
    arcore_start: usize,
    warning_start: usize,
    doc: u32,
    track_index: u32,
    sample_time: Option<f64>,
    sample_duration: Option<f64>,
  ) {
    if let Some(slice) = self.gps_samples.get_mut(gps_start..) {
      for s in slice {
        s.doc = doc;
        s.track_index = track_index;
      }
    }
    if let Some(slice) = self.flight_samples.get_mut(flight_start..) {
      for s in slice {
        s.doc = doc;
        s.track_index = track_index;
        s.sample_time = sample_time;
        s.sample_duration = sample_duration;
      }
    }
    if let Some(slice) = self.follow_me_samples.get_mut(follow_me_start..) {
      for s in slice {
        s.doc = doc;
        s.track_index = track_index;
        s.sample_time = sample_time;
        s.sample_duration = sample_duration;
      }
    }
    if let Some(slice) = self.automation_samples.get_mut(automation_start..) {
      for s in slice {
        s.doc = doc;
        s.track_index = track_index;
        s.sample_time = sample_time;
        s.sample_duration = sample_duration;
      }
    }
    if let Some(slice) = self.arcore_samples.get_mut(arcore_start..) {
      for s in slice {
        s.doc = doc;
        s.track_index = track_index;
        s.sample_time = sample_time;
        s.sample_duration = sample_duration;
      }
    }
    if let Some(slice) = self.arcore_warnings.get_mut(warning_start..) {
      for w in slice {
        w.doc = doc;
        w.track_index = track_index;
        w.sample_time = sample_time;
        w.sample_duration = sample_duration;
      }
    }
  }

  /// `&mut` to the LAST appended flight sample, or `None` when none
  /// has been pushed yet. Used by the `E1 TimeStamp` extension arm in
  /// [`crate::formats::parrot::process_mett`] to attach the timestamp
  /// to the host P2/P3 sample emitted immediately prior — but ONLY when
  /// that prior sample was appended in the SAME `process_mett` call (the
  /// arm guards on a pre-call flight watermark; a standalone E1 in its
  /// own `mett` sample pushes a fresh sample instead, so the dispatch's
  /// `stamp_doc_from` assigns it the current `Doc<N>`).
  ///
  /// Kept `pub(crate)` to constrain the mutation surface — external
  /// callers should round-trip through `push_flight_sample` for
  /// future flight samples.
  #[inline(always)]
  #[must_use]
  pub(crate) fn flight_samples_mut_last(&mut self) -> Option<&mut ParrotFlightSample> {
    self.flight_samples.last_mut()
  }
}

impl Default for ParrotMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Parrot mett projection into MediaMetadata
// ===========================================================================

impl ParrotMeta {
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
  /// **Projection eligibility (DRONE records only):** the camera/GPS/capture
  /// projection is gated on [`Self::has_drone_records`], NOT [`Self::is_empty`].
  /// An ARCore (`application/arcore-*`) `mett` track is PHONE telemetry, not a
  /// Parrot drone camera — it emits at `-ee` (so it is NOT `is_empty`) but must
  /// project NOTHING into the normalized camera domain. So an ARCore-only file
  /// (no `[EP]\d` drone record) populates no `CameraInfo`/`GpsLocation`/
  /// `CaptureSettings`; only a real Parrot drone record stamps `Make = "Parrot"`.
  ///
  /// **Warnings:** the ARCore `Process_mett` walker warnings are FIRST-CLASS
  /// timed records ([`Self::arcore_warnings`]) emitted as in-stream
  /// group-scoped `Doc<N>:Track<N>:Warning` at `-ee` by
  /// [`crate::formats::quicktime::emit_parrot`] — NOT projected through
  /// [`MediaMetadata`] (which carries no warnings channel; mirrors the other
  /// timed-metadata ports).
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    // PROJECTION eligibility = DRONE records only (the camera identity); ARCore
    // phone telemetry is deliberately excluded (see `has_drone_records`).
    let has_drone = self.has_drone_records();
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none() && has_drone {
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
    // ARCore `Process_mett` warnings are NOT projected into `MediaMetadata`
    // (which has no warnings channel) — they ride the in-stream group-scoped
    // `Doc<N>:Track<N>:Warning` axis at `-ee` ([`Self::arcore_warnings`] →
    // [`crate::formats::quicktime::emit_parrot`]), like the sibling camm / ctmd
    // / dji producers.
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
    assert!(!m.has_drone_records());
    assert!(m.gps_samples().is_empty());
    assert!(m.flight_samples().is_empty());
    assert!(m.arcore_warnings().is_empty());
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
  fn arcore_warnings_accumulate_as_timed_records() {
    // ARCore warnings are now FIRST-CLASS timed records (the file-global
    // `WAS_WARNED` dedup + ` [x$n]` count are applied at emit time, NOT at push
    // time), so every raised warning is RETAINED in source order — distinct from
    // the prior single first-wins string field.
    let mut m = ParrotMeta::new();
    m.push_arcore_warning(ParrotArCoreWarning::new(SmolStr::new("first"), false));
    m.push_arcore_warning(ParrotArCoreWarning::new(SmolStr::new("second"), true));
    assert_eq!(m.arcore_warnings().len(), 2);
    assert_eq!(m.arcore_warnings()[0].message(), "first");
    assert!(!m.arcore_warnings()[0].minor());
    assert_eq!(m.arcore_warnings()[1].message(), "second");
    assert!(m.arcore_warnings()[1].minor());
    // A warning-only track is NOT empty (it still emits at `-ee`) but has NO
    // drone records (so it projects no camera identity).
    assert!(!m.is_empty());
    assert!(!m.has_drone_records());
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
  fn arcore_only_track_projects_no_camera_identity() {
    // FINDING 2: an ARCore-only `mett` track (PHONE telemetry — accel/gyro
    // samples and/or `Process_mett` warnings, NO `[EP]\d` drone record) emits at
    // `-ee` (so it is NOT `is_empty`) but must project NOTHING into the
    // normalized camera domain (`Make = "Parrot"` is a DRONE identity). The
    // projection is gated on `has_drone_records`, NOT `is_empty`.
    let mut m = ParrotMeta::new();
    m.push_arcore_sample(ParrotArCoreSample::new(
      ParrotArCoreTagKind::Accelerometer,
      [Some(0.1), Some(0.2), Some(0.3)],
    ));
    m.push_arcore_warning(ParrotArCoreWarning::new(
      SmolStr::new("Unexpected length for application/arcore-accel record"),
      true,
    ));
    // Emits at `-ee` (non-empty) but is NOT a drone camera.
    assert!(!m.is_empty());
    assert!(!m.has_drone_records());
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(
      md.camera().is_none(),
      "ARCore-only must not stamp Make=Parrot"
    );
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }

  #[test]
  fn drone_record_still_projects_make_parrot_alongside_arcore() {
    // A Parrot file with a DRONE record STILL projects `Make = "Parrot"` even
    // when ARCore phone samples are also present — `has_drone_records` is true.
    let mut m = ParrotMeta::new();
    let mut sample = ParrotGpsSample::new(ParrotRecordVersion::V1);
    sample.set_latitude(Some(48.85)).set_longitude(Some(2.35));
    m.push_gps_sample(sample);
    m.push_arcore_sample(ParrotArCoreSample::new(
      ParrotArCoreTagKind::Gyroscope,
      [Some(0.0), Some(0.0), Some(0.0)],
    ));
    assert!(m.has_drone_records());
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.camera().expect("camera").make(), Some("Parrot"));
    assert_eq!(md.gps().expect("gps").latitude(), Some(48.85));
  }
}
