// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Parrot::Process_mett`
//! (Parrot.pm:791-854) — the Parrot drone `mett` timed-metadata walker
//! shared by Anafi / Anafi USA / Anafi Ai / Anafi Thermal / Bebop /
//! Bebop 2 / Disco bodies. Backed by the per-record-version binary
//! tables `Image::ExifTool::Parrot::V1` / `V2` / `V3` (Parrot.pm:86-539)
//! and the extension records `TimeStamp` / `FollowMe` / `Automation`
//! (Parrot.pm:541-660).
//!
//! ## Record layout (Parrot.pm:823-852)
//!
//! Each `mett` sample is a sequence of records. The walker tries two
//! shapes in order:
//!
//!  1. **MetaType-keyed (ARCore)** — Parrot.pm:802-822. When the
//!     incoming `MetaType` (e.g. `"application/arcore-accel"`) is a
//!     key in the `%mett` table, each record is `[0x0a][len:u8][payload
//!     :len bytes]` (a TLV walk). The `MetaType` value selects the
//!     ARCore-specific subtable. ARCore data is phone-camera AR
//!     telemetry, NOT drone-side GPS, so this port WALKS the records
//!     faithfully but discards their values (camera-indexing scope).
//!  2. **ID-keyed (Parrot drones)** — Parrot.pm:823-852. Each record
//!     is `[id:2 bytes][nwords:u16-BE][payload]` where:
//!      - `id` is `"P1"` / `"P2"` / `"P3"` for a basic record, or
//!        `"E1"` / `"E2"` / `"E3"` for an extension record;
//!      - `nwords` is the record byte size minus the 4-byte prefix,
//!        in `u32`-sized units; total record size is `nwords*4 + 4`;
//!      - **size override** — `P2` records are forced to 56 bytes and
//!        `P3` to 72 bytes (Parrot.pm:836-841), since their nwords
//!        field reports only the basic-record size but the walker
//!        consumes the E* extension records concatenated after.
//!      - **V1 fallback** — Parrot.pm:827-833: if the first 2 bytes
//!        aren't a `[EP]\d` ID AND `dirEnd == 60`, treat the buffer as
//!        a fake `P1` V1 recording-record, skipping the first 4 bytes
//!        (the recording-frame timestamp goes undecoded as a bundled
//!        choice, "augh!").
//!
//! ## Endianness
//!
//! The walker (Parrot.pm:824 `unpack("x${pos}a2n", $$dataPt)`) reads
//! `nwords` as `n` = big-endian u16. The PER-RECORD binary tables don't
//! call `SetByteOrder`, so they inherit the QuickTime movie default of
//! big-endian (`MM`) — every `int16s` / `int32s` / `int16u` / `int32u`
//! field decoded from V1 / V2 / V3 / TimeStamp / FollowMe / Automation
//! payloads is BIG-ENDIAN.
//!
//! ## What this port surfaces (FULL mett parity)
//!
//! EVERY field of the per-version drone tables and extension records is
//! decoded:
//!  - **`P1` / `P2` / `P3` GPS** — lat/lon/alt/SV count, plus the V2/V3
//!    GNSS velocity vector (`GPSVelocity{North,East,Down}`) →
//!    [`ParrotGpsSample`];
//!  - **`P1` / `P2` / `P3` flight + pose** — Battery%, WifiRSSI, ISO,
//!    ExposureTime, FlyingState, PilotingMode, Binning, Animation,
//!    AltitudeFromTakeOff (V1), DistanceFromHome (V1), Elevation (V2/V3),
//!    AirSpeed (V2/V3), DroneYaw/Pitch/Roll (V1), CameraPan/CameraTilt
//!    (V1/V2), SpeedX/Y/Z (V1), FrameView (all), DroneQuaternion (V2/V3),
//!    FrameBaseView (V3), RedBalance/BlueBalance (V3), FOV (V3),
//!    LinkGoodput/LinkQuality (V3) → [`ParrotFlightSample`];
//!  - **`E1 TimeStamp`** (us counter) concatenated onto the host
//!    [`ParrotFlightSample`];
//!  - **`E2 FollowMe`** — follow-me target waypoint + mode/animation →
//!    [`ParrotFollowMeSample`];
//!  - **`E3 Automation`** — framing + destination waypoints +
//!    animation/flags → [`ParrotAutomationSample`].
//!
//! ## What this port walks but discards
//!
//! Faithful but unsurfaced (the walker visits, the typed layer discards):
//!  - **ARCore subtables** — phone-side AR telemetry, not drone-side
//!    GPS. The TLV walker still steps over the records; their values are
//!    discarded (flagged separately for the user).
//!
//! ## GPS priority chain
//!
//! Parrot mett GPS is the **THIRD tier** of the cross-port GPS priority
//! chain that [`crate::metadata::MediaMetadata`] projects from a QuickTime
//! file: GoPro GPMF → Android CAMM → **Parrot mett** → Sony rtmd →
//! Canon CTMD → Insta360 trailer → SP3 stream. Parrot mett is on-device
//! GNSS hardware (the drone's own GNSS) — same fidelity tier as GoPro /
//! CAMM; ordered after CAMM by implementation arrival (a single file is
//! produced by exactly one body so the tie-break is hypothetical).

use smol_str::SmolStr;

use crate::metadata::{
  ParrotAutomationAnimation, ParrotAutomationSample, ParrotFlightSample, ParrotFlyingState,
  ParrotFollowMeAnimation, ParrotFollowMeSample, ParrotGpsSample, ParrotMeta, ParrotPilotingMode,
  ParrotRecordVersion,
};

// ===========================================================================
// Big-endian readers (Parrot inherits the QuickTime movie default 'MM')
// ===========================================================================

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn be_i16(b: &[u8], off: usize) -> Option<i16> {
  be_u16(b, off).map(|v| v as i16)
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn be_i32(b: &[u8], off: usize) -> Option<i32> {
  be_u32(b, off).map(|v| v as i32)
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  Some(u64::from_be_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

// ===========================================================================
// Shared ValueConv helpers
// ===========================================================================

/// The radian→degree ValueConv used by `DroneYaw` / `DronePitch` / `DroneRoll`
/// (V1) and `CameraPan` / `CameraTilt` (V1 / V2): `$val / 0x1000 * 180 / 3.14159`
/// (Parrot.pm:94 etc.). ExifTool uses the literal `3.14159`, NOT a higher-
/// precision π — match it byte-for-byte.
#[inline]
// The literal `3.14159` is REQUIRED for byte-exact parity with ExifTool's
// ValueConv; `std::f64::consts::PI` (3.141592653589793) would change the result.
#[allow(clippy::approx_constant)]
fn rad_int16_to_deg(raw: i16) -> f64 {
  f64::from(raw) / f64::from(0x1000) * 180.0 / 3.14159
}

/// A 4-element `int16s[N]` quaternion / view vector, each component divided by
/// `divisor` (`0x1000` for V1 FrameView, `0x4000` for the V2/V3 quaternions).
/// Mirrors the bundled `my @a = split " ",$val; $_ /= D foreach @a; "@a"`
/// (Parrot.pm:119 / :290 / :295 / :431 / :436 / :441) — but the typed layer
/// stores the four scaled f64 components and the emitter does the `"@a"`
/// space-join. Returns `None` if fewer than 8 bytes are available.
#[inline]
fn be_i16x4(b: &[u8], off: usize, divisor: f64) -> Option<[f64; 4]> {
  let w0 = be_i16(b, off)?;
  let w1 = be_i16(b, off + 2)?;
  let w2 = be_i16(b, off + 4)?;
  let w3 = be_i16(b, off + 6)?;
  Some([
    f64::from(w0) / divisor,
    f64::from(w1) / divisor,
    f64::from(w2) / divisor,
    f64::from(w3) / divisor,
  ])
}

/// A 2-element `int16u[2]` vector, each component divided by `divisor`. The
/// `FOV` ValueConv `my @a = split " ",$val; $_ /= 0x100 foreach @a; "@a"`
/// (Parrot.pm:473) over `Format => 'int16u[2]'`. Returns `None` if fewer than
/// 4 bytes are available.
#[inline]
fn be_u16x2(b: &[u8], off: usize, divisor: f64) -> Option<[f64; 2]> {
  let w0 = be_u16(b, off)?;
  let w1 = be_u16(b, off + 2)?;
  Some([f64::from(w0) / divisor, f64::from(w1) / divisor])
}

// ===========================================================================
// V1 / V2 / V3 record sizes (Parrot.pm:836-841)
// ===========================================================================

/// V1 60-byte fallback record (Parrot.pm:828 `last unless $dirEnd == 60`).
const V1_FALLBACK_SIZE: usize = 60;

/// V2 fixed record size (Parrot.pm:836-837): the `nwords` field reports
/// only the BASIC record size but the walker consumes the E*
/// extensions concatenated after, so the record is forced to 56 bytes.
const V2_RECORD_SIZE: usize = 56;

/// V3 fixed record size (Parrot.pm:838-839).
const V3_RECORD_SIZE: usize = 72;

// ===========================================================================
// Per-version GPS decoders
// ===========================================================================

/// V1 GPS decode (Parrot.pm:144-167). The V1 walker `HandleTag`s the
/// 60-byte slot directly; lat/lon live at offsets 28 / 32 scaled by
/// `0x100000` (`1 << 20`); altitude is the upper 24 bits of the int32s
/// at offset 36 scaled by `0x100` (`1 << 8`); SV count is the low byte.
fn decode_v1_gps(payload: &[u8]) -> ParrotGpsSample {
  let mut g = ParrotGpsSample::new(ParrotRecordVersion::V1);
  // Parrot.pm:144-149 — lat int32s @28 / 0x100000.
  if let Some(raw) = be_i32(payload, 28) {
    g.set_latitude(Some(f64::from(raw) / f64::from(0x10_0000)));
  }
  // Parrot.pm:150-155 — lon int32s @32 / 0x100000.
  if let Some(raw) = be_i32(payload, 32) {
    g.set_longitude(Some(f64::from(raw) / f64::from(0x10_0000)));
  }
  // Parrot.pm:156-162 — alt int32s @36, `Mask => 0xffffff00`,
  // `ValueConv => '$val / 0x100'`. ExifTool applies the mask FIRST
  // (ExifTool.pm:10078-10079 `$val = ($val & $mask) >> $bitShift`, with the
  // BitShift derived from the mask = 8), THEN the ValueConv divides by 0x100.
  // Perl's bitwise `&` yields an UNSIGNED integer, so `(int32s & 0xffffff00)`
  // is never negative (the sign bits are part of the masked-out byte's high
  // bits but the result is a non-negative UV); read the word UNSIGNED so the
  // mask + shift + /256 match Perl exactly (the old signed `>> 8` both
  // sign-extended AND dropped the /256).
  if let Some(w) = be_u32(payload, 36) {
    let alt = f64::from((w & 0xffff_ff00) >> 8) / 256.0;
    g.set_altitude_m(Some(alt));
  }
  // Parrot.pm:163-167 — SV count is the low byte of the same word.
  if let Some(&b) = payload.get(39) {
    g.set_satellites(Some(b));
  }
  g
}

/// V2/V3 GPS decode (Parrot.pm:242-265 / :383-406). Identical offsets
/// and scaling between V2 and V3 — lat/lon `int32s / 0x400000` at 8/12,
/// altitude `(int32s & 0xffffff00) / 0x100` at 16 (low byte = SV count).
fn decode_v2_v3_gps(payload: &[u8], version: ParrotRecordVersion) -> ParrotGpsSample {
  let mut g = ParrotGpsSample::new(version);
  // Parrot.pm:242-247 / :383-388 — lat int32s @8 / 0x400000.
  if let Some(raw) = be_i32(payload, 8) {
    g.set_latitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:248-253 / :389-394 — lon int32s @12 / 0x400000.
  if let Some(raw) = be_i32(payload, 12) {
    g.set_longitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:254-260 / :395-401 — alt int32s @16, `Mask => 0xffffff00`,
  // `ValueConv => '$val / 0x100'`. Same two-stage compute as V1 @36: mask +
  // BitShift(8) (ExifTool.pm:10078-10079) THEN /0x100. Perl's `&` yields an
  // unsigned result, so read the word UNSIGNED and divide by 256 (the old
  // signed `>> 8` sign-extended AND dropped the /256).
  if let Some(w) = be_u32(payload, 16) {
    g.set_altitude_m(Some(f64::from((w & 0xffff_ff00) >> 8) / 256.0));
  }
  // Parrot.pm:261-265 / :402-406 — SV count = low byte of the alt word.
  if let Some(&b) = payload.get(19) {
    g.set_satellites(Some(b));
  }
  // Parrot.pm:266-280 / :407-421 — GPSVelocity{North,East,Down} int16s @20/22/24
  // each `/0x100` (m/s). No PrintConv → raw number both modes.
  if let Some(raw) = be_i16(payload, 20) {
    g.set_velocity_north_mps(Some(f64::from(raw) / f64::from(0x100)));
  }
  if let Some(raw) = be_i16(payload, 22) {
    g.set_velocity_east_mps(Some(f64::from(raw) / f64::from(0x100)));
  }
  if let Some(raw) = be_i16(payload, 24) {
    g.set_velocity_down_mps(Some(f64::from(raw) / f64::from(0x100)));
  }
  g
}

// ===========================================================================
// Per-version flight-telemetry decoders
// ===========================================================================

/// V1 flight-telemetry decode (Parrot.pm:91-228). Field offsets:
///  - `DroneYaw` / `DronePitch` / `DroneRoll` int16s @4/6/8, rad→deg.
///  - `CameraPan` / `CameraTilt` int16s @10/12, rad→deg.
///  - `FrameView` int16s[4] @14, each `/0x1000`.
///  - `ExposureTime` int16s @22, ValueConv `$val / 0x100 / 1000` (sec).
///  - `ISO` int16s @24.
///  - `WifiRSSI` int8s @26 (dBm).
///  - `Battery` int8u @27 (%).
///  - `AltitudeFromTakeOff` int32s @40, ValueConv `$val / 0x10000` (m).
///  - `DistanceFromHome` int32u @44, ValueConv `$val / 0x10000`.
///  - `SpeedX` / `SpeedY` / `SpeedZ` int16s @48/50/52, each `/0x100`.
///  - `Binning` byte @54, `Mask => 0x80` (high bit of the FlyingState byte).
///  - `FlyingState` int8u @54, low 7 bits.
///  - `Animation` byte @55, `Mask => 0x80` (high bit of the PilotingMode byte).
///  - `PilotingMode` int8u @55, low 7 bits.
fn decode_v1_flight(payload: &[u8]) -> ParrotFlightSample {
  let mut f = ParrotFlightSample::new(ParrotRecordVersion::V1);
  // Parrot.pm:91-105 — DroneYaw/Pitch/Roll int16s @4/6/8, rad→deg.
  if let Some(raw) = be_i16(payload, 4) {
    f.set_drone_yaw_deg(Some(rad_int16_to_deg(raw)));
  }
  if let Some(raw) = be_i16(payload, 6) {
    f.set_drone_pitch_deg(Some(rad_int16_to_deg(raw)));
  }
  if let Some(raw) = be_i16(payload, 8) {
    f.set_drone_roll_deg(Some(rad_int16_to_deg(raw)));
  }
  // Parrot.pm:106-115 — CameraPan/CameraTilt int16s @10/12, rad→deg.
  if let Some(raw) = be_i16(payload, 10) {
    f.set_camera_pan_deg(Some(rad_int16_to_deg(raw)));
  }
  if let Some(raw) = be_i16(payload, 12) {
    f.set_camera_tilt_deg(Some(rad_int16_to_deg(raw)));
  }
  // Parrot.pm:116-120 — FrameView int16s[4] @14, each /0x1000.
  if let Some(v) = be_i16x4(payload, 14, f64::from(0x1000)) {
    f.set_frame_view(Some(v));
  }
  // Parrot.pm:121-127 — ExposureTime int16s @22 / 0x100 / 1000.
  if let Some(raw) = be_i16(payload, 22) {
    f.set_exposure_time_s(Some(f64::from(raw) / f64::from(0x100) / 1000.0));
  }
  // Parrot.pm:128-132 — ISO int16s @24.
  if let Some(raw) = be_i16(payload, 24) {
    f.set_iso(Some(i32::from(raw)));
  }
  // Parrot.pm:133-138 — WifiRSSI int8s @26.
  if let Some(&b) = payload.get(26) {
    f.set_wifi_rssi_dbm(Some(b as i8));
  }
  // Parrot.pm:139-143 — Battery int8u @27 (no Format key ⇒ default int8u).
  if let Some(&b) = payload.get(27) {
    f.set_battery_percent(Some(b));
  }
  // Parrot.pm:168-173 — AltitudeFromTakeOff int32s @40 / 0x10000.
  if let Some(raw) = be_i32(payload, 40) {
    f.set_altitude_from_takeoff_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:174-178 — DistanceFromHome int32u @44 / 0x10000.
  if let Some(raw) = be_u32(payload, 44) {
    f.set_distance_from_home_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:179-193 — SpeedX/Y/Z int16s @48/50/52, each /0x100.
  if let Some(raw) = be_i16(payload, 48) {
    f.set_speed_x(Some(f64::from(raw) / f64::from(0x100)));
  }
  if let Some(raw) = be_i16(payload, 50) {
    f.set_speed_y(Some(f64::from(raw) / f64::from(0x100)));
  }
  if let Some(raw) = be_i16(payload, 52) {
    f.set_speed_z(Some(f64::from(raw) / f64::from(0x100)));
  }
  // Parrot.pm:194-211 — Binning (Mask 0x80) + FlyingState (Mask 0x7f), byte @54.
  if let Some(&b) = payload.get(54) {
    f.set_binning(Some((b & 0x80) >> 7));
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:212-227 — Animation (Mask 0x80) + PilotingMode (Mask 0x7f), @55.
  if let Some(&b) = payload.get(55) {
    f.set_animation(Some((b & 0x80) >> 7));
    f.set_piloting_mode(Some(ParrotPilotingMode::from_raw(b & 0x7f)));
  }
  f
}

/// V2 flight-telemetry decode (Parrot.pm:231-369). Field offsets:
///  - `Elevation` int32s @4, ValueConv `$val / 0x10000`.
///  - `AirSpeed` int16s @26 / 0x100, with `RawConv $val < 0 ? undef : $val`.
///  - `DroneQuaternion` int16s[4] @28, each `/0x4000`.
///  - `FrameView` int16s[4] @36, each `/0x4000`.
///  - `CameraPan` / `CameraTilt` int16s @44/46, rad→deg.
///  - `ExposureTime` int16u @48, ValueConv `$val / 0x100 / 1000`.
///  - `ISO` int16u @50.
///  - `Binning` byte @52, `Mask => 0x80`.
///  - `FlyingState` int8u @52, low 7 bits.
///  - `Animation` byte @53, `Mask => 0x80`.
///  - `PilotingMode` int8u @53, low 7 bits.
///  - `WifiRSSI` int8s @54.
///  - `Battery` int8u @55.
fn decode_v2_flight(payload: &[u8]) -> ParrotFlightSample {
  let mut f = ParrotFlightSample::new(ParrotRecordVersion::V2);
  // Parrot.pm:236-241 — Elevation int32s @4 / 0x10000.
  if let Some(raw) = be_i32(payload, 4) {
    f.set_elevation_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:281-286 — AirSpeed int16s @26 / 0x100 with RawConv guard.
  // Bundled `RawConv => '$val < 0 ? undef : $val'` (raw int16s value, not
  // the post-ValueConv). So we read the raw int16s, drop negatives, then
  // apply the /0x100 ValueConv. Negative AirSpeed is undef ⇒ None.
  if let Some(raw) = be_i16(payload, 26)
    && raw >= 0
  {
    f.set_air_speed_mps(Some(f64::from(raw) / f64::from(0x100)));
  }
  // Parrot.pm:287-291 — DroneQuaternion int16s[4] @28, each /0x4000.
  if let Some(v) = be_i16x4(payload, 28, f64::from(0x4000)) {
    f.set_drone_quaternion(Some(v));
  }
  // Parrot.pm:292-296 — FrameView int16s[4] @36, each /0x4000.
  if let Some(v) = be_i16x4(payload, 36, f64::from(0x4000)) {
    f.set_frame_view(Some(v));
  }
  // Parrot.pm:297-306 — CameraPan/CameraTilt int16s @44/46, rad→deg.
  if let Some(raw) = be_i16(payload, 44) {
    f.set_camera_pan_deg(Some(rad_int16_to_deg(raw)));
  }
  if let Some(raw) = be_i16(payload, 46) {
    f.set_camera_tilt_deg(Some(rad_int16_to_deg(raw)));
  }
  // Parrot.pm:307-313 — ExposureTime int16u @48 / 0x100 / 1000.
  if let Some(raw) = be_u16(payload, 48) {
    f.set_exposure_time_s(Some(f64::from(raw) / f64::from(0x100) / 1000.0));
  }
  // Parrot.pm:314-318 — ISO int16u @50.
  if let Some(raw) = be_u16(payload, 50) {
    f.set_iso(Some(i32::from(raw)));
  }
  // Parrot.pm:319-339 — Binning (Mask 0x80) + FlyingState (Mask 0x7f), byte @52.
  if let Some(&b) = payload.get(52) {
    f.set_binning(Some((b & 0x80) >> 7));
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:340-356 — Animation (Mask 0x80) + PilotingMode (Mask 0x7f), @53.
  if let Some(&b) = payload.get(53) {
    f.set_animation(Some((b & 0x80) >> 7));
    f.set_piloting_mode(Some(ParrotPilotingMode::from_raw(b & 0x7f)));
  }
  // Parrot.pm:358-363 — WifiRSSI int8s @54.
  if let Some(&b) = payload.get(54) {
    f.set_wifi_rssi_dbm(Some(b as i8));
  }
  // Parrot.pm:364-368 — Battery int8u @55.
  if let Some(&b) = payload.get(55) {
    f.set_battery_percent(Some(b));
  }
  f
}

/// V3 flight-telemetry decode (Parrot.pm:372-538). Field offsets:
///  - `Elevation` int32s @4, ValueConv `$val / 0x10000`.
///  - `AirSpeed` int16s @26 / 0x100, with `RawConv $val < 0 ? undef : $val`.
///  - `DroneQuaternion` int16s[4] @28, each `/0x4000`.
///  - `FrameBaseView` int16s[4] @36, each `/0x4000`.
///  - `FrameView` int16s[4] @44, each `/0x4000`.
///  - `ExposureTime` int16u @52, ValueConv `$val / 0x100 / 1000`.
///  - `ISO` int16u @54.
///  - `RedBalance` int16u @56, ValueConv `$val / 0x4000`.
///  - `BlueBalance` int16u @58, ValueConv `$val / 0x4000`.
///  - `FOV` int16u[2] @60, each `/0x100` (degrees).
///  - `LinkGoodput` int32u @64, `Mask => 0xffffff00` (upper 24 bits), kbit/s.
///  - `LinkQuality` int32u @64, `Mask => 0xff` (low byte), 0-5.
///  - `WifiRSSI` int8s @68.
///  - `Battery` int8u @69.
///  - `Binning` byte @70, `Mask => 0x80`.
///  - `FlyingState` int8u @70, low 7 bits.
///  - `Animation` byte @71, `Mask => 0x80`.
///  - `PilotingMode` int8u @71, low 7 bits.
fn decode_v3_flight(payload: &[u8]) -> ParrotFlightSample {
  let mut f = ParrotFlightSample::new(ParrotRecordVersion::V3);
  // Parrot.pm:377-382 — Elevation int32s @4 / 0x10000.
  if let Some(raw) = be_i32(payload, 4) {
    f.set_elevation_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:422-427 — AirSpeed int16s @26 / 0x100, RawConv guard.
  if let Some(raw) = be_i16(payload, 26)
    && raw >= 0
  {
    f.set_air_speed_mps(Some(f64::from(raw) / f64::from(0x100)));
  }
  // Parrot.pm:428-432 — DroneQuaternion int16s[4] @28, each /0x4000.
  if let Some(v) = be_i16x4(payload, 28, f64::from(0x4000)) {
    f.set_drone_quaternion(Some(v));
  }
  // Parrot.pm:433-437 — FrameBaseView int16s[4] @36, each /0x4000.
  if let Some(v) = be_i16x4(payload, 36, f64::from(0x4000)) {
    f.set_frame_base_view(Some(v));
  }
  // Parrot.pm:438-442 — FrameView int16s[4] @44, each /0x4000.
  if let Some(v) = be_i16x4(payload, 44, f64::from(0x4000)) {
    f.set_frame_view(Some(v));
  }
  // Parrot.pm:443-449 — ExposureTime int16u @52 / 0x100 / 1000.
  if let Some(raw) = be_u16(payload, 52) {
    f.set_exposure_time_s(Some(f64::from(raw) / f64::from(0x100) / 1000.0));
  }
  // Parrot.pm:450-454 — ISO int16u @54.
  if let Some(raw) = be_u16(payload, 54) {
    f.set_iso(Some(i32::from(raw)));
  }
  // Parrot.pm:455-460 — RedBalance int16u @56 / 0x4000.
  if let Some(raw) = be_u16(payload, 56) {
    f.set_red_balance(Some(f64::from(raw) / f64::from(0x4000)));
  }
  // Parrot.pm:461-466 — BlueBalance int16u @58 / 0x4000.
  if let Some(raw) = be_u16(payload, 58) {
    f.set_blue_balance(Some(f64::from(raw) / f64::from(0x4000)));
  }
  // Parrot.pm:467-474 — FOV int16u[2] @60, each /0x100 (degrees).
  if let Some(v) = be_u16x2(payload, 60, f64::from(0x100)) {
    f.set_fov_deg(Some(v));
  }
  // Parrot.pm:475-488 — LinkGoodput (Mask 0xffffff00) + LinkQuality (Mask 0xff),
  // int32u @64. The mask + BitShift(8) on the upper 24 bits gives kbit/s; the
  // low byte is the 0-5 quality. Perl `&` is unsigned, so read the word UNSIGNED.
  if let Some(w) = be_u32(payload, 64) {
    f.set_link_goodput_kbitps(Some((w & 0xffff_ff00) >> 8));
    // `Mask => 0xff` ⇒ low byte (BitShift 0).
    f.set_link_quality(Some((w & 0xff) as u8));
  }
  // Parrot.pm:489-494 — WifiRSSI int8s @68.
  if let Some(&b) = payload.get(68) {
    f.set_wifi_rssi_dbm(Some(b as i8));
  }
  // Parrot.pm:495-499 — Battery int8u @69.
  if let Some(&b) = payload.get(69) {
    f.set_battery_percent(Some(b));
  }
  // Parrot.pm:500-520 — Binning (Mask 0x80) + FlyingState (Mask 0x7f), byte @70.
  if let Some(&b) = payload.get(70) {
    f.set_binning(Some((b & 0x80) >> 7));
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:521-538 — Animation (Mask 0x80) + PilotingMode (Mask 0x7f), @71.
  if let Some(&b) = payload.get(71) {
    f.set_animation(Some((b & 0x80) >> 7));
    f.set_piloting_mode(Some(ParrotPilotingMode::from_raw(b & 0x7f)));
  }
  f
}

// ===========================================================================
// E1 TimeStamp extension decoder
// ===========================================================================

/// `Image::ExifTool::Parrot::TimeStamp` (Parrot.pm:541-551) — a 12-byte
/// extension record `[id:"E1"][nwords:u16-BE]` followed by an int64u
/// microsecond counter at offset 4 of the payload. ValueConv `$val / 1e6`
/// converts microseconds → seconds, but the typed layer surfaces the
/// raw microsecond integer (lossless) — the projection layer can divide
/// when needed.
fn decode_e1_timestamp(payload: &[u8]) -> Option<u64> {
  // The payload here is the WHOLE record bytes (incl. the 4-byte
  // id/nwords prefix); the timestamp lives at record offset 4.
  // Parrot.pm:546-550 `Format => 'int64u'` at table offset 4.
  be_u64(payload, 4)
}

// ===========================================================================
// E2 FollowMe / E3 Automation extension decoders
// ===========================================================================

/// `Image::ExifTool::Parrot::FollowMe` (Parrot.pm:553-593). The payload is the
/// WHOLE record bytes (incl. the 4-byte `[E2][nwords]` prefix), so the table
/// offsets are positions within it. Fields:
///  - `GPSTargetLatitude` int32s @4 / 0x400000.
///  - `GPSTargetLongitude` int32s @8 / 0x400000.
///  - `GPSTargetAltitude` int32s @12 / 0x10000.
///  - `Follow-meMode` int8u @16 (BITMASK — stored raw, rendered at emit time).
///  - `Follow-meAnimation` int8u @17.
fn decode_e2_followme(payload: &[u8]) -> ParrotFollowMeSample {
  let mut s = ParrotFollowMeSample::new();
  // Parrot.pm:558-562 — GPSTargetLatitude int32s @4 / 0x400000.
  if let Some(raw) = be_i32(payload, 4) {
    s.set_target_latitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:563-567 — GPSTargetLongitude int32s @8 / 0x400000.
  if let Some(raw) = be_i32(payload, 8) {
    s.set_target_longitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:568-572 — GPSTargetAltitude int32s @12 / 0x10000.
  if let Some(raw) = be_i32(payload, 12) {
    s.set_target_altitude_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:573-581 — Follow-meMode int8u @16 (BITMASK).
  if let Some(&b) = payload.get(16) {
    s.set_mode_flags(Some(b));
  }
  // Parrot.pm:582-592 — Follow-meAnimation int8u @17.
  if let Some(&b) = payload.get(17) {
    s.set_animation(Some(ParrotFollowMeAnimation::from_raw(b)));
  }
  s
}

/// `Image::ExifTool::Parrot::Automation` (Parrot.pm:595-660). The payload is the
/// WHOLE record bytes (incl. the 4-byte `[E3][nwords]` prefix). Fields:
///  - `GPSFramingLatitude` int32s @4 / 0x400000.
///  - `GPSFramingLongitude` int32s @8 / 0x400000.
///  - `GPSFramingAltitude` int32s @12 / 0x10000.
///  - `GPSDestLatitude` int32s @16 / 0x400000.
///  - `GPSDestLongitude` int32s @20 / 0x400000.
///  - `GPSDestAltitude` int32s @24 / 0x10000.
///  - `AutomationAnimation` int8u @28.
///  - `AutomationFlags` int8u @29 (BITMASK — stored raw, rendered at emit time).
fn decode_e3_automation(payload: &[u8]) -> ParrotAutomationSample {
  let mut s = ParrotAutomationSample::new();
  // Parrot.pm:600-604 — GPSFramingLatitude int32s @4 / 0x400000.
  if let Some(raw) = be_i32(payload, 4) {
    s.set_framing_latitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:605-609 — GPSFramingLongitude int32s @8 / 0x400000.
  if let Some(raw) = be_i32(payload, 8) {
    s.set_framing_longitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:610-614 — GPSFramingAltitude int32s @12 / 0x10000.
  if let Some(raw) = be_i32(payload, 12) {
    s.set_framing_altitude_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:615-619 — GPSDestLatitude int32s @16 / 0x400000.
  if let Some(raw) = be_i32(payload, 16) {
    s.set_dest_latitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:620-624 — GPSDestLongitude int32s @20 / 0x400000.
  if let Some(raw) = be_i32(payload, 20) {
    s.set_dest_longitude(Some(f64::from(raw) / f64::from(0x40_0000)));
  }
  // Parrot.pm:625-629 — GPSDestAltitude int32s @24 / 0x10000.
  if let Some(raw) = be_i32(payload, 24) {
    s.set_dest_altitude_m(Some(f64::from(raw) / f64::from(0x1_0000)));
  }
  // Parrot.pm:630-650 — AutomationAnimation int8u @28.
  if let Some(&b) = payload.get(28) {
    s.set_animation(Some(ParrotAutomationAnimation::from_raw(b)));
  }
  // Parrot.pm:651-659 — AutomationFlags int8u @29 (BITMASK).
  if let Some(&b) = payload.get(29) {
    s.set_flags(Some(b));
  }
  s
}

// ===========================================================================
// process_mett — the bundled Process_mett port
// ===========================================================================

/// Parrot.pm:791-854 — walk one `mett` timed-metadata sample.
///
/// Single sample per call (the QuickTime sample loop already iterates).
/// Each `[EP]\d` ID-keyed record yields one [`ParrotGpsSample`] AND/OR
/// [`ParrotFlightSample`] depending on which version produced it. The
/// V2 / V3 size override (Parrot.pm:836-841) folds the E* extensions
/// into the same record buffer; the E1 timestamp (when present at the
/// end of a V2 / V3 record) is attached to the host flight sample.
///
/// `meta_type` is the bundled `$$et{MetaType}` — the sample-description
/// MetaType string (`"application/arcore-accel"` and friends). When
/// non-empty AND the string is one of the ARCore subtable keys, the
/// walker switches to the TLV ARCore loop (Parrot.pm:802-822). For
/// plain Parrot-drone `mett` (MetaType empty), it walks the [EP]\d ID
/// loop (Parrot.pm:823-852).
///
/// Returns nothing — accumulates into `out` (one sample per `mett`
/// record decoded).
pub fn process_mett(data: &[u8], meta_type: Option<&str>, out: &mut ParrotMeta) {
  let dir_end = data.len();
  let mut pos = 0usize;
  // Pre-call flight watermark. ExifTool's `Process_mett` runs under the ONE
  // `DOC_NUM` that `ProcessSamples` opened for THIS `mett` sample
  // (QuickTimeStream.pl:1517-1523), and `HandleTag`s every record — the
  // P2/P3 GPS/flight fields and any E1 TimeStamp concatenated after them —
  // under it (Parrot.pm:844-850). The port's dispatch
  // ([`crate::formats::quicktime_stream::process_samples`]) mirrors that by
  // watermarking the sample vectors before the call and stamping the CURRENT
  // sample's `Doc<N>`/`Track<N>` onto exactly the records this call appended.
  // So an E1 may only fold into a flight sample CREATED IN THIS CALL; folding
  // into a flight sample left by a PRIOR `mett` sample would write the E1's
  // timestamp onto the wrong document (and lose the standalone E1's own
  // `Doc<N>`). Capture the count so the E1 arm can tell the two apart.
  let flight_watermark = out.flight_sample_count();

  // Parrot.pm:802 — `if ($$tagTbl{$metaType})`. The bundled `%mett`
  // table includes the ARCore string keys (`application/arcore-accel`
  // etc.). exifast does not decode the ARCore subtables (phone-side AR
  // telemetry, not camera-indexing). Faithful walker for the ARCore
  // case still needs to STEP over the records (so a future port can
  // hook in) — bundled `Process_mett` returns 1 after the loop in either
  // branch (Parrot.pm:821 / :853).
  let is_arcore = meta_type.is_some_and(is_arcore_meta_type);
  if is_arcore {
    // Parrot.pm:804-820 — TLV loop: `[0x0a][len:u8][payload:len bytes]`.
    // Oracle bound `while ($pos < $dirEnd - 2)` — a record needs the 0x0a tag
    // byte + the length byte + at least one payload byte, so `pos + 2 < dir_end`
    // (NOT `<=`; the trailing record must have a non-empty payload). Written
    // additively to avoid the `dir_end - 2` underflow when `dir_end < 2`.
    while pos + 2 < dir_end {
      // Parrot.pm:805 `last unless substr(.., $pos, 1) eq "\x0a"`.
      if data.get(pos) != Some(&0x0a) {
        break;
      }
      let Some(&len_raw) = data.get(pos + 1) else {
        break;
      };
      let len_byte = len_raw as usize;
      let total = pos.saturating_add(len_byte).saturating_add(2);
      // Parrot.pm:807-810 — overflow ⇒ first-only warning + stop.
      if total > dir_end {
        out.set_warning(SmolStr::new("Unexpected length for ARCore mett record"));
        break;
      }
      // Parrot.pm:811 `$len or $len = $dirEnd - $pos - 2` — len 0 means
      // "use the rest of the record".
      let effective_len = if len_byte == 0 {
        dir_end - pos - 2
      } else {
        len_byte
      };
      // FOLLOW-UP: decode the ARCore subtables (Parrot::ARCoreAccel /
      // ARCoreAccel0 / ARCoreGyro / ARCoreGyro0 / ARCoreVideo /
      // ARCoreCustom). Phone-side AR telemetry, not camera identity.
      let _ = effective_len;
      pos += len_byte + 2;
      if len_byte == 0 {
        // Defensive: a len-0 record means "consume the rest", so stop.
        break;
      }
    }
    return;
  }

  // Parrot.pm:823 `while ($pos + 4 < $dirLen)` — strict-less. A record
  // needs the 4-byte id+nwords prefix readable past `$pos`.
  while pos + 4 < dir_end {
    let Some(id_bytes) = data
      .get(pos..pos + 2)
      .and_then(|s| <[u8; 2]>::try_from(s).ok())
    else {
      break;
    };
    let nwords = match be_u16(data, pos + 2) {
      Some(v) => v,
      None => break,
    };

    // Parrot.pm:826 `if ($id !~ /^[EP]\d/)`.
    let id_is_ep = is_ep_id(&id_bytes);

    let size: usize;
    let mut effective_pos = pos;
    let effective_id: [u8; 2];
    if !id_is_ep {
      // Parrot.pm:827-833 — V1 60-byte fallback. Only fires when the
      // total dirEnd is exactly 60 bytes; otherwise stop.
      if dir_end != V1_FALLBACK_SIZE {
        break;
      }
      effective_id = *b"P1";
      // Parrot.pm:832 `$pos += 4` — skip the first 4 bytes so the V1
      // fields align with the rest of the V1 record (bundled "ignore
      // the first 4 of the record"). Then `$size = $dirEnd - $pos`.
      effective_pos = pos + 4;
      size = dir_end - effective_pos;
    } else if &id_bytes == b"P2" {
      // Parrot.pm:836-837 — force V2 size to 56.
      effective_id = id_bytes;
      size = V2_RECORD_SIZE;
    } else if &id_bytes == b"P3" {
      // Parrot.pm:838-839 — force V3 size to 72.
      effective_id = id_bytes;
      size = V3_RECORD_SIZE;
    } else {
      // Parrot.pm:840-842 — `$size = $nwords * 4 + 4` for any other
      // [EP]\d ID (P1 in a normal sample, E1/E2/E3 when freestanding).
      effective_id = id_bytes;
      size = usize::from(nwords) * 4 + 4;
    }

    // Parrot.pm:843 `last if $pos + $size > $dirEnd`.
    if effective_pos.checked_add(size).is_none_or(|e| e > dir_end) {
      break;
    }

    let Some(payload) = data.get(effective_pos..effective_pos + size) else {
      break;
    };

    // Parrot.pm:844-850 — HandleTag dispatch. Per-id decoders here.
    match &effective_id {
      b"P1" => {
        // V1: emit GPS + flight from the same 60-byte payload.
        let g = decode_v1_gps(payload);
        if !g.is_empty() {
          out.push_gps_sample(g);
        }
        let f = decode_v1_flight(payload);
        if !f.is_empty() {
          out.push_flight_sample(f);
        }
      }
      b"P2" => {
        // Per Parrot.pm:836-837 — the size override advances $pos by
        // exactly 56 bytes (the basic V2 record). Any E1/E2/E3
        // extensions concatenated after live PAST $pos+56 in the
        // sample buffer and are picked up as separate iterations of
        // the outer while-loop below (where they hit the `b"E1"` /
        // `b"E2"` / `b"E3"` arms).
        let g = decode_v2_v3_gps(payload, ParrotRecordVersion::V2);
        if !g.is_empty() {
          out.push_gps_sample(g);
        }
        let f = decode_v2_flight(payload);
        if !f.is_empty() {
          out.push_flight_sample(f);
        }
      }
      b"P3" => {
        // Same outer-loop continuation as P2 (Parrot.pm:838-839).
        let g = decode_v2_v3_gps(payload, ParrotRecordVersion::V3);
        if !g.is_empty() {
          out.push_gps_sample(g);
        }
        let f = decode_v3_flight(payload);
        if !f.is_empty() {
          out.push_flight_sample(f);
        }
      }
      b"E1" => {
        // E1 TimeStamp extension (Parrot.pm:541-551). ExifTool `HandleTag`s
        // the timestamp under the CURRENT `mett` sample's `DOC_NUM`
        // (Parrot.pm:844-850), so it must ride on a flight sample belonging
        // to THIS `process_mett` call. When the E1 is concatenated after a
        // P2/P3 in the SAME `mett` sample buffer (the common case — bundled
        // comments say the extensions are concat'd after the basic record),
        // fold it into that just-emitted flight sample. When it is the only
        // record in the sample (a SEPARATE `mett` sample carrying just an
        // E1 — its own `DOC_NUM`), PUSH a fresh TimeStamp-only sample so the
        // dispatch's `stamp_doc_from` assigns it the current `Doc<N>`/`Track`
        // (folding into a PRIOR call's flight sample would mis-attach the
        // timestamp to the wrong document and drop this sample's `Doc<N>`).
        if let Some(ts) = decode_e1_timestamp(payload) {
          // payload layout: [E1][nwords:u16-BE][int64u ts...].
          // decode_e1_timestamp reads the int64u at record offset 4.
          let folds_into_this_call = out.flight_sample_count() > flight_watermark;
          if let Some(last) = out
            .flight_samples_mut_last()
            .filter(|_| folds_into_this_call)
          {
            last.set_time_stamp_us(Some(ts));
          } else {
            let mut f = ParrotFlightSample::new(ParrotRecordVersion::V2);
            f.set_time_stamp_us(Some(ts));
            out.push_flight_sample(f);
          }
        }
      }
      b"E2" => {
        // E2 FollowMe extension (Parrot.pm:553-593). Concatenated after a
        // P2/P3 in the same `mett` sample buffer (or freestanding). Decode the
        // follow-me target waypoint + mode/animation.
        let s = decode_e2_followme(payload);
        if !s.is_empty() {
          out.push_follow_me_sample(s);
        }
      }
      b"E3" => {
        // E3 Automation extension (Parrot.pm:595-660). Framing + destination
        // waypoints + animation/flags.
        let s = decode_e3_automation(payload);
        if !s.is_empty() {
          out.push_automation_sample(s);
        }
      }
      _ => {
        // Unknown ID under [EP]\d (defensive — bundled has no
        // explicit fall-through, but we keep the walk going to mirror
        // ProcessBinaryData's `next` semantics).
      }
    }

    // Parrot.pm:851 `$pos += $size`.
    pos = effective_pos + size;
  }
}

/// Match the 2-char ID byte pattern `[EP]\d`. Parrot.pm:826
/// `$id !~ /^[EP]\d/`.
fn is_ep_id(id: &[u8; 2]) -> bool {
  matches!(id[0], b'E' | b'P') && id[1].is_ascii_digit()
}

/// Match the ARCore MetaType strings that bundled's `%mett` table
/// declares (Parrot.pm:60-83). Anything not on this list does NOT
/// switch the walker into the TLV branch, regardless of MetaType.
fn is_arcore_meta_type(s: &str) -> bool {
  matches!(
    s,
    "application/arcore-accel"
      | "application/arcore-accel-0"
      | "application/arcore-gyro"
      | "application/arcore-gyro-0"
      | "application/arcore-video-0"
      | "application/arcore-custom-event"
  )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  extern crate alloc;
  use super::*;
  use alloc::vec::Vec;

  fn p1_record(payload60: &[u8; 60]) -> Vec<u8> {
    // Parrot.pm:840-842 `$size = $nwords * 4 + 4` — P1 doesn't get a
    // size override (only P2 / P3 do). For nwords=14 the total size is
    // 4 + 14*4 = 60 bytes. The walker passes the WHOLE 60-byte slot to
    // the V1 decoder, with the bundled `[P1][nwords]` prefix occupying
    // record offsets 0..3. So bundled V1 field offsets (Parrot.pm:91+)
    // are positions WITHIN that 60-byte slot.
    //
    // Mirrors the `p2_record`/`p3_record` convention: the caller supplies
    // a 60-byte array whose indices match bundled record offsets directly
    // (e.g. GPSLatitude at record offset 28 ⇒ `payload60[28..32]`). The
    // helper overwrites slots 0..4 with `[P1][nwords=14]`.
    let mut v = Vec::with_capacity(60);
    v.extend_from_slice(b"P1");
    v.extend_from_slice(&14u16.to_be_bytes()); // nwords ⇒ size = 60
    v.extend_from_slice(&payload60[4..]); // skip the 4 prefix bytes
    assert_eq!(v.len(), 60);
    v
  }

  fn p2_record(payload56: &[u8; 56]) -> Vec<u8> {
    // For P2 the walker forces size = 56 regardless of nwords; the
    // 56-byte payload starts at the record's offset 0 (the [P2]
    // [nwords] prefix is INCLUDED in the 56 since bundled passes
    // `Start => pos` + `Size => 56` — i.e. the prefix is part of the
    // V2 table's offset 0..3).
    let mut v = Vec::with_capacity(56);
    v.extend_from_slice(b"P2");
    v.extend_from_slice(&13u16.to_be_bytes()); // nwords (ignored when override fires)
    v.extend_from_slice(&payload56[4..]); // skip the 4 prefix bytes
    assert_eq!(v.len(), 56);
    v
  }

  fn p3_record(payload72: &[u8; 72]) -> Vec<u8> {
    let mut v = Vec::with_capacity(72);
    v.extend_from_slice(b"P3");
    v.extend_from_slice(&17u16.to_be_bytes()); // nwords (ignored when override fires)
    v.extend_from_slice(&payload72[4..]);
    assert_eq!(v.len(), 72);
    v
  }

  #[test]
  fn walks_empty_buffer_no_panic() {
    let mut m = ParrotMeta::new();
    process_mett(&[], None, &mut m);
    assert!(m.is_empty());
  }

  #[test]
  fn v1_gps_decodes_lat_lon_alt_sv() {
    // V1 record: 60-byte payload where:
    //   offsets 28..32 = lat int32s @ 47.6062 * 0x100000 ≈ 0x02f9b71e
    //   offsets 32..36 = lon int32s @ -122.3321 * 0x100000 ≈ 0xf85d57e7
    //   offsets 36..40 = GPSAltitude word (Mask 0xffffff00 / 0x100) | SV count.
    // ExifTool decodes altitude as `((w & 0xffffff00) >> 8) / 0x100`
    // (Parrot.pm:156-162 + ExifTool.pm:10078-10079). To encode ALT metres
    // with the low byte carrying the SV count, set
    //   w = (alt_m * 0x10000) | sv   ⇒   ((w & 0xffffff00) >> 8)/256 = alt_m.
    // Worked example (audit): w=0x00320009 → (0x320000>>8)/256 = 12800/256 = 50.0.
    let lat_raw = (47.6062_f64 * f64::from(0x10_0000)).round() as i32;
    let lon_raw = (-122.3321_f64 * f64::from(0x10_0000)).round() as i32;
    let alt_m = 120_u32; // metres
    let sv_count = 9_u8;
    let alt_word = (alt_m * 0x1_0000) | u32::from(sv_count);
    let mut payload = [0u8; 60];
    // The walker reads at the WHOLE record offsets (not payload+4);
    // bundled `HandleTag ... Start => $pos` so V1's offset 28 is at
    // record offset 28 — which for our test fixture is payload[28].
    payload[28..32].copy_from_slice(&lat_raw.to_be_bytes());
    payload[32..36].copy_from_slice(&lon_raw.to_be_bytes());
    payload[36..40].copy_from_slice(&alt_word.to_be_bytes());
    let mut m = ParrotMeta::new();
    process_mett(&p1_record(&payload), None, &mut m);
    assert_eq!(m.gps_samples().len(), 1);
    let g = &m.gps_samples()[0];
    assert_eq!(g.version(), ParrotRecordVersion::V1);
    assert!((g.latitude().unwrap() - 47.6062).abs() < 1e-5);
    assert!((g.longitude().unwrap() - (-122.3321)).abs() < 1e-5);
    // Oracle: ((alt_word & 0xffffff00) >> 8) / 256.0 = 120.0.
    assert!((g.altitude_m().unwrap() - 120.0).abs() < 1e-6);
    assert_eq!(g.satellites(), Some(9));
  }

  #[test]
  fn v1_flight_decodes_battery_iso_exposure_state() {
    let mut payload = [0u8; 60];
    // ExposureTime: int16s @22, raw = 1/0x100/1000 ⇒ for 1/60 s → raw = 0x100 * 1000 / 60 ≈ 4267
    payload[22..24].copy_from_slice(&(4267_i16).to_be_bytes());
    // ISO @24
    payload[24..26].copy_from_slice(&(800_i16).to_be_bytes());
    // WifiRSSI @26 (int8s)
    payload[26] = (-65i8) as u8;
    // Battery @27
    payload[27] = 75;
    // FlyingState @54: 3 (Flying), with the high "Binning" bit cleared.
    payload[54] = 3;
    // PilotingMode @55: 1 (Return Home), with the high "Animation" bit cleared.
    payload[55] = 1;
    let mut m = ParrotMeta::new();
    process_mett(&p1_record(&payload), None, &mut m);
    let f = &m.flight_samples()[0];
    assert_eq!(f.version(), ParrotRecordVersion::V1);
    assert!((f.exposure_time_s().unwrap() - 4267.0 / 256.0 / 1000.0).abs() < 1e-9);
    assert_eq!(f.iso(), Some(800));
    assert_eq!(f.wifi_rssi_dbm(), Some(-65));
    assert_eq!(f.battery_percent(), Some(75));
    assert_eq!(f.flying_state(), Some(ParrotFlyingState::Flying));
    assert_eq!(f.piloting_mode(), Some(ParrotPilotingMode::ReturnHome));
  }

  #[test]
  fn v1_altitude_from_takeoff_and_distance_from_home() {
    let mut payload = [0u8; 60];
    // AltitudeFromTakeOff @40 int32s / 0x10000 — 15.5 m * 0x10000 = 1015808
    payload[40..44].copy_from_slice(&(1_015_808_i32).to_be_bytes());
    // DistanceFromHome @44 int32u / 0x10000 — 50.0 * 0x10000 = 3_276_800
    payload[44..48].copy_from_slice(&(3_276_800_u32).to_be_bytes());
    let mut m = ParrotMeta::new();
    process_mett(&p1_record(&payload), None, &mut m);
    let f = &m.flight_samples()[0];
    assert!((f.altitude_from_takeoff_m().unwrap() - 15.5).abs() < 1e-9);
    assert!((f.distance_from_home_m().unwrap() - 50.0).abs() < 1e-9);
  }

  #[test]
  fn v2_gps_and_flight_with_size_override() {
    // V2 record forced to 56 bytes via override.
    let lat_raw = (47.6062_f64 * f64::from(0x40_0000)).round() as i32;
    let lon_raw = (-122.3321_f64 * f64::from(0x40_0000)).round() as i32;
    // GPSAltitude (Mask 0xffffff00 / 0x100): w = alt_m*0x10000 | sv ⇒
    // ((w & 0xffffff00)>>8)/256 = alt_m. Here 50 m with SV count 11.
    let alt_word = (50_u32 * 0x1_0000) | 11;
    let mut payload = [0u8; 56];
    payload[8..12].copy_from_slice(&lat_raw.to_be_bytes());
    payload[12..16].copy_from_slice(&lon_raw.to_be_bytes());
    payload[16..20].copy_from_slice(&alt_word.to_be_bytes());
    // AirSpeed @26 raw int16s — 5.5 * 0x100 = 1408
    payload[26..28].copy_from_slice(&(1408_i16).to_be_bytes());
    // ExposureTime @48 int16u — 1/120 s ⇒ raw = 256000/120 ≈ 2133
    payload[48..50].copy_from_slice(&(2133_u16).to_be_bytes());
    // ISO @50
    payload[50..52].copy_from_slice(&(400_u16).to_be_bytes());
    // FlyingState @52: 2 Hovering
    payload[52] = 2;
    // PilotingMode @53: 0 Manual
    payload[53] = 0;
    // WifiRSSI @54 int8s
    payload[54] = (-55i8) as u8;
    // Battery @55
    payload[55] = 92;
    // Elevation @4 int32s / 0x10000 — 3.5 * 0x10000 = 229376
    payload[4..8].copy_from_slice(&(229_376_i32).to_be_bytes());
    let mut m = ParrotMeta::new();
    process_mett(&p2_record(&payload), None, &mut m);
    let g = &m.gps_samples()[0];
    assert_eq!(g.version(), ParrotRecordVersion::V2);
    assert!((g.latitude().unwrap() - 47.6062).abs() < 1e-5);
    assert!((g.longitude().unwrap() - (-122.3321)).abs() < 1e-5);
    assert!((g.altitude_m().unwrap() - 50.0).abs() < 1e-6);
    assert_eq!(g.satellites(), Some(11));
    let f = &m.flight_samples()[0];
    assert_eq!(f.version(), ParrotRecordVersion::V2);
    assert!((f.air_speed_mps().unwrap() - 5.5).abs() < 1e-6);
    assert!((f.exposure_time_s().unwrap() - 2133.0 / 256.0 / 1000.0).abs() < 1e-9);
    assert_eq!(f.iso(), Some(400));
    assert_eq!(f.flying_state(), Some(ParrotFlyingState::Hovering));
    assert_eq!(f.piloting_mode(), Some(ParrotPilotingMode::Manual));
    assert_eq!(f.wifi_rssi_dbm(), Some(-55));
    assert_eq!(f.battery_percent(), Some(92));
    assert!((f.elevation_m().unwrap() - 3.5).abs() < 1e-9);
  }

  #[test]
  fn v2_negative_air_speed_is_undef() {
    let mut payload = [0u8; 56];
    payload[26..28].copy_from_slice(&(-1_i16).to_be_bytes());
    let mut m = ParrotMeta::new();
    process_mett(&p2_record(&payload), None, &mut m);
    assert!(
      m.flight_samples()
        .iter()
        .all(|f| f.air_speed_mps().is_none())
    );
  }

  #[test]
  fn v3_gps_and_flight_with_size_override() {
    // V3 forced to 72 bytes.
    let lat_raw = (45.0_f64 * f64::from(0x40_0000)).round() as i32;
    let lon_raw = (8.0_f64 * f64::from(0x40_0000)).round() as i32;
    // GPSAltitude (Mask 0xffffff00 / 0x100): w = alt_m*0x10000 | sv ⇒
    // ((w & 0xffffff00)>>8)/256 = alt_m. Here 100 m with SV count 12.
    let alt_word = (100_u32 * 0x1_0000) | 12;
    let mut payload = [0u8; 72];
    payload[8..12].copy_from_slice(&lat_raw.to_be_bytes());
    payload[12..16].copy_from_slice(&lon_raw.to_be_bytes());
    payload[16..20].copy_from_slice(&alt_word.to_be_bytes());
    // AirSpeed @26
    payload[26..28].copy_from_slice(&(512_i16).to_be_bytes()); // 2.0 m/s
    // ExposureTime @52 int16u
    payload[52..54].copy_from_slice(&(2133_u16).to_be_bytes());
    // ISO @54 int16u
    payload[54..56].copy_from_slice(&(200_u16).to_be_bytes());
    // WifiRSSI @68
    payload[68] = (-70i8) as u8;
    // Battery @69
    payload[69] = 50;
    // FlyingState @70: 3 Flying
    payload[70] = 3;
    // PilotingMode @71: 4 Magic Carpet
    payload[71] = 4;
    // Elevation @4
    payload[4..8].copy_from_slice(&(459_776_i32).to_be_bytes()); // ~7.014 m
    let mut m = ParrotMeta::new();
    process_mett(&p3_record(&payload), None, &mut m);
    let g = &m.gps_samples()[0];
    assert_eq!(g.version(), ParrotRecordVersion::V3);
    assert!((g.latitude().unwrap() - 45.0).abs() < 1e-6);
    assert!((g.longitude().unwrap() - 8.0).abs() < 1e-6);
    assert!((g.altitude_m().unwrap() - 100.0).abs() < 1e-6);
    let f = &m.flight_samples()[0];
    assert_eq!(f.version(), ParrotRecordVersion::V3);
    assert!((f.air_speed_mps().unwrap() - 2.0).abs() < 1e-9);
    assert_eq!(f.iso(), Some(200));
    assert_eq!(f.wifi_rssi_dbm(), Some(-70));
    assert_eq!(f.battery_percent(), Some(50));
    assert_eq!(f.flying_state(), Some(ParrotFlyingState::Flying));
    assert_eq!(f.piloting_mode(), Some(ParrotPilotingMode::MagicCarpet));
  }

  #[test]
  fn v1_60_byte_fallback_no_id() {
    // Parrot.pm:827-833 — when the buffer is exactly 60 bytes AND
    // doesn't start with [EP]\d, the walker generates a fake P1 ID
    // and advances pos by 4 (the recording-frame timestamp goes
    // undecoded). Build a 60-byte fixture starting with NOT-EP bytes.
    let mut payload = [0u8; 60];
    payload[0] = 0xAB; // not [EP]
    payload[1] = 0xCD;
    // After `pos += 4`, the walker treats payload[4..] as the start of
    // the V1 record. So V1 offsets (e.g. lat @28 in the record) become
    // payload[4+28] = payload[32]. To put lat=45.0 in the right place:
    // payload[32..36] = lat int32s big-endian.
    let lat_raw = (45.0_f64 * f64::from(0x10_0000)).round() as i32;
    payload[32..36].copy_from_slice(&lat_raw.to_be_bytes());
    let mut m = ParrotMeta::new();
    process_mett(&payload, None, &mut m);
    // Per bundled (Parrot.pm:828 `last unless $dirEnd == 60`), this
    // fallback only fires when the WHOLE input buffer is exactly 60
    // bytes (the walker condition is on $dirEnd).
    assert_eq!(m.gps_samples().len(), 1);
    let g = &m.gps_samples()[0];
    assert_eq!(g.version(), ParrotRecordVersion::V1);
    assert!((g.latitude().unwrap() - 45.0).abs() < 1e-6);
  }

  #[test]
  fn v1_fallback_does_not_fire_for_non_60_byte_no_id() {
    // A non-EP buffer with size != 60 should produce nothing.
    let payload = [0xABu8; 100];
    let mut m = ParrotMeta::new();
    process_mett(&payload, None, &mut m);
    assert!(m.is_empty());
  }

  #[test]
  fn e1_timestamp_freestanding() {
    // [E1][nwords=2][int64u ts] — 12 bytes total. Nwords reports the
    // payload-in-u32-words, here 2 (= 8 bytes for the int64u).
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(b"E1");
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&1_234_567_890u64.to_be_bytes());
    // pad to make the buffer's dir_end > 12 (so the strict-less while
    // guard accepts the read; Parrot.pm:823 `while ($pos + 4 < $dirLen)`).
    buf.extend_from_slice(&[0u8; 4]);
    let mut m = ParrotMeta::new();
    process_mett(&buf, None, &mut m);
    assert_eq!(m.flight_samples().len(), 1);
    assert_eq!(m.flight_samples()[0].time_stamp_us(), Some(1_234_567_890));
  }

  #[test]
  fn e1_concatenated_after_p2_in_same_sample_folds_into_that_sample() {
    // The common case (Parrot.pm:836-837 + 844-850): a P2 basic record with an
    // E1 TimeStamp concatenated AFTER it, both in ONE `mett` sample buffer. The
    // E1 must fold into the P2's flight sample (one document), NOT push a second.
    let mut payload = [0u8; 56];
    payload[26..28].copy_from_slice(&(512_i16).to_be_bytes()); // AirSpeed 2.0 m/s
    let mut buf = p2_record(&payload);
    buf.extend_from_slice(b"E1");
    buf.extend_from_slice(&2u16.to_be_bytes()); // nwords = 2 ⇒ 8-byte int64u
    buf.extend_from_slice(&777_000u64.to_be_bytes());
    buf.extend_from_slice(&[0u8; 4]); // pad so the strict-less while guard reads the E1
    let mut m = ParrotMeta::new();
    process_mett(&buf, None, &mut m);
    // ONE flight sample (the P2's), now carrying the concatenated E1 timestamp.
    assert_eq!(m.flight_samples().len(), 1);
    assert!((m.flight_samples()[0].air_speed_mps().unwrap() - 2.0).abs() < 1e-9);
    assert_eq!(m.flight_samples()[0].time_stamp_us(), Some(777_000));
  }

  #[test]
  fn standalone_e1_in_separate_sample_gets_its_own_doc_not_previous() {
    // FINDING 1 regression. ExifTool's `Process_mett` `HandleTag`s every E1
    // under the CURRENT `mett` sample's `DOC_NUM` (Parrot.pm:844-850), set once
    // per sample by `ProcessSamples` (QuickTimeStream.pl:1517-1523). So a
    // standalone E1 in its OWN `mett` sample must land on a NEW flight sample
    // with that sample's `Doc<N>`/`Track<N>` — NOT mutate the prior sample's.
    // We drive the two `mett` samples exactly as the dispatch
    // (`process_samples`) does: watermark the flight vector, `process_mett`,
    // then `stamp_doc_from` the new records with the sample's doc/track.
    let mut m = ParrotMeta::new();

    // Sample 1: a P2 with a CONCATENATED E1 (its own timestamp) → Doc1/Track1.
    let mut p2 = [0u8; 56];
    p2[26..28].copy_from_slice(&(512_i16).to_be_bytes()); // AirSpeed 2.0 m/s
    let mut s1 = p2_record(&p2);
    s1.extend_from_slice(b"E1");
    s1.extend_from_slice(&2u16.to_be_bytes());
    s1.extend_from_slice(&111_000u64.to_be_bytes());
    s1.extend_from_slice(&[0u8; 4]);
    let (g0, f0, fm0, a0) = (
      m.gps_sample_count(),
      m.flight_sample_count(),
      m.follow_me_sample_count(),
      m.automation_sample_count(),
    );
    process_mett(&s1, None, &mut m);
    m.stamp_doc_from(
      g0,
      f0,
      fm0,
      a0,
      /*doc=*/ 1,
      /*track=*/ 1,
      Some(0.0),
      Some(1.0),
    );

    // Sample 2: ONLY a standalone E1 (a different timestamp) → Doc2/Track1.
    let mut s2 = Vec::new();
    s2.extend_from_slice(b"E1");
    s2.extend_from_slice(&2u16.to_be_bytes());
    s2.extend_from_slice(&222_000u64.to_be_bytes());
    s2.extend_from_slice(&[0u8; 4]);
    let (g1, f1, fm1, a1) = (
      m.gps_sample_count(),
      m.flight_sample_count(),
      m.follow_me_sample_count(),
      m.automation_sample_count(),
    );
    process_mett(&s2, None, &mut m);
    m.stamp_doc_from(
      g1,
      f1,
      fm1,
      a1,
      /*doc=*/ 2,
      /*track=*/ 1,
      Some(1.0),
      Some(1.0),
    );

    // Two distinct flight samples: the standalone E1 created its OWN.
    assert_eq!(m.flight_samples().len(), 2);
    // Sample 1 keeps its P2 + its concatenated E1's timestamp, at Doc1.
    let s1_flight = &m.flight_samples()[0];
    assert!((s1_flight.air_speed_mps().unwrap() - 2.0).abs() < 1e-9);
    assert_eq!(s1_flight.time_stamp_us(), Some(111_000));
    assert_eq!(s1_flight.doc(), 1);
    assert_eq!(s1_flight.track_index(), 1);
    // The standalone E1 landed on its OWN sample at Doc2 (NOT overwriting Doc1).
    let s2_flight = &m.flight_samples()[1];
    assert_eq!(s2_flight.time_stamp_us(), Some(222_000));
    assert!(s2_flight.air_speed_mps().is_none());
    assert_eq!(s2_flight.doc(), 2);
    assert_eq!(s2_flight.track_index(), 1);
  }

  #[test]
  fn arcore_meta_type_walks_without_panic() {
    // Build a TLV record `[0x0a][len=4][4 bytes payload]` — the walker
    // should step over it, not push any samples.
    let mut buf = Vec::new();
    buf.push(0x0a);
    buf.push(4);
    buf.extend_from_slice(&[0u8; 4]);
    let mut m = ParrotMeta::new();
    process_mett(&buf, Some("application/arcore-accel"), &mut m);
    assert!(m.is_empty());
  }

  #[test]
  fn is_ep_id_matches_pattern() {
    assert!(is_ep_id(b"P1"));
    assert!(is_ep_id(b"P9"));
    assert!(is_ep_id(b"E0"));
    assert!(is_ep_id(b"E3"));
    assert!(!is_ep_id(b"PX"));
    assert!(!is_ep_id(b"AB"));
    assert!(!is_ep_id(b"p1")); // lowercase doesn't match Perl's [EP]
    assert!(!is_ep_id(b"  "));
  }

  #[test]
  fn arcore_meta_type_classifier() {
    assert!(is_arcore_meta_type("application/arcore-accel"));
    assert!(is_arcore_meta_type("application/arcore-accel-0"));
    assert!(is_arcore_meta_type("application/arcore-gyro"));
    assert!(is_arcore_meta_type("application/arcore-gyro-0"));
    assert!(is_arcore_meta_type("application/arcore-video-0"));
    assert!(is_arcore_meta_type("application/arcore-custom-event"));
    assert!(!is_arcore_meta_type(""));
    assert!(!is_arcore_meta_type("application/meta"));
    assert!(!is_arcore_meta_type("application/microvideo-image-meta"));
  }
}
