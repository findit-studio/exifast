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
//! ## What this port surfaces
//!
//! Camera-indexing-relevant fields from `P1` / `P2` / `P3`:
//!  - GPS lat/lon/alt/SV count → [`ParrotGpsSample`];
//!  - Battery%, WifiRSSI, ISO, ExposureTime, FlyingState, PilotingMode,
//!    AltitudeFromTakeOff (V1 only), DistanceFromHome (V1 only),
//!    AirSpeed (V2/V3), Elevation (V2/V3) → [`ParrotFlightSample`];
//!  - `E1 TimeStamp` (us counter) concatenated onto the host
//!    `ParrotFlightSample`.
//!
//! ## What this port walks but discards
//!
//! Faithful but unsurfaced (the walker visits, the typed layer discards):
//!  - **DroneYaw / DronePitch / DroneRoll / CameraPan / CameraTilt /
//!    DroneQuaternion / FrameView / FrameBaseView** — drone-pose
//!    telemetry, not camera identity (FOLLOW-UP).
//!  - **E2 FollowMe / E3 Automation extensions** — these carry PLANNED
//!    target waypoint coordinates, not the actual drone fix (FOLLOW-UP).
//!  - **ARCore subtables** — phone-side AR telemetry, not drone-side
//!    GPS (FOLLOW-UP).
//!  - **Binning / Animation** — accessory flags (FOLLOW-UP).
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
  ParrotFlightSample, ParrotFlyingState, ParrotGpsSample, ParrotMeta, ParrotPilotingMode,
  ParrotRecordVersion,
};

// ===========================================================================
// Big-endian readers (Parrot inherits the QuickTime movie default 'MM')
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
  // Parrot.pm:156-162 — alt int32s @36 with Mask 0xffffff00 / 0x100.
  // (alt_raw & 0xffffff00) is interpreted as a signed int32 by Perl after
  // the mask (sign bit at 0x80000000 preserved). Bundled `$val = ($val &
  // 0xffffff00)` then `$val / 0x100` — equivalently an arithmetic right
  // shift by 8 (for a properly-signed result). The mask preserves the
  // top 24 bits; divide-by-0x100 = arithmetic shift right 8.
  if let Some(raw) = be_i32(payload, 36) {
    let alt = (raw >> 8) as f64; // arithmetic right shift preserves sign
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
  // Parrot.pm:254-260 / :395-401 — alt int32s @16 mask 0xffffff00 / 0x100.
  if let Some(raw) = be_i32(payload, 16) {
    g.set_altitude_m(Some(f64::from(raw >> 8)));
  }
  // Parrot.pm:261-265 / :402-406 — SV count = low byte of the alt word.
  if let Some(&b) = payload.get(19) {
    g.set_satellites(Some(b));
  }
  g
}

// ===========================================================================
// Per-version flight-telemetry decoders
// ===========================================================================

/// V1 flight-telemetry decode (Parrot.pm:121-228). Field offsets:
///  - `ExposureTime` int16s @22, ValueConv `$val / 0x100 / 1000` (sec).
///  - `ISO` int16s @24.
///  - `WifiRSSI` int8s @26 (dBm).
///  - `Battery` int8u @27 (%).
///  - `AltitudeFromTakeOff` int32s @40, ValueConv `$val / 0x10000` (m).
///  - `DistanceFromHome` int32u @44, ValueConv `$val / 0x10000`.
///  - `FlyingState` int8u @54, low 7 bits.
///  - `PilotingMode` int8u @55, low 7 bits.
fn decode_v1_flight(payload: &[u8]) -> ParrotFlightSample {
  let mut f = ParrotFlightSample::new(ParrotRecordVersion::V1);
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
  // Parrot.pm:199-211 — FlyingState int8u @54, low 7 bits.
  if let Some(&b) = payload.get(54) {
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:217-227 — PilotingMode int8u @55, low 7 bits.
  if let Some(&b) = payload.get(55) {
    f.set_piloting_mode(Some(ParrotPilotingMode::from_raw(b & 0x7f)));
  }
  f
}

/// V2 flight-telemetry decode (Parrot.pm:236-369). Field offsets:
///  - `Elevation` int32s @4, ValueConv `$val / 0x10000`.
///  - `AirSpeed` int16s @26 / 0x100, with `RawConv $val < 0 ? undef : $val`.
///  - `ExposureTime` int16u @48, ValueConv `$val / 0x100 / 1000`.
///  - `ISO` int16u @50.
///  - `FlyingState` int8u @52, low 7 bits.
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
  // Parrot.pm:307-313 — ExposureTime int16u @48 / 0x100 / 1000.
  if let Some(raw) = be_u16(payload, 48) {
    f.set_exposure_time_s(Some(f64::from(raw) / f64::from(0x100) / 1000.0));
  }
  // Parrot.pm:314-318 — ISO int16u @50.
  if let Some(raw) = be_u16(payload, 50) {
    f.set_iso(Some(i32::from(raw)));
  }
  // Parrot.pm:324-339 — FlyingState int8u @52, low 7 bits.
  if let Some(&b) = payload.get(52) {
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:345-356 — PilotingMode int8u @53, low 7 bits.
  if let Some(&b) = payload.get(53) {
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

/// V3 flight-telemetry decode (Parrot.pm:377-538). Field offsets:
///  - `Elevation` int32s @4, ValueConv `$val / 0x10000`.
///  - `AirSpeed` int16s @26 / 0x100, with `RawConv $val < 0 ? undef : $val`.
///  - `ExposureTime` int16u @52, ValueConv `$val / 0x100 / 1000`.
///  - `ISO` int16u @54.
///  - `WifiRSSI` int8s @68.
///  - `Battery` int8u @69.
///  - `FlyingState` int8u @70, low 7 bits.
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
  // Parrot.pm:443-449 — ExposureTime int16u @52 / 0x100 / 1000.
  if let Some(raw) = be_u16(payload, 52) {
    f.set_exposure_time_s(Some(f64::from(raw) / f64::from(0x100) / 1000.0));
  }
  // Parrot.pm:450-454 — ISO int16u @54.
  if let Some(raw) = be_u16(payload, 54) {
    f.set_iso(Some(i32::from(raw)));
  }
  // Parrot.pm:489-494 — WifiRSSI int8s @68.
  if let Some(&b) = payload.get(68) {
    f.set_wifi_rssi_dbm(Some(b as i8));
  }
  // Parrot.pm:495-499 — Battery int8u @69.
  if let Some(&b) = payload.get(69) {
    f.set_battery_percent(Some(b));
  }
  // Parrot.pm:505-520 — FlyingState int8u @70, low 7 bits.
  if let Some(&b) = payload.get(70) {
    f.set_flying_state(Some(ParrotFlyingState::from_raw(b & 0x7f)));
  }
  // Parrot.pm:526-538 — PilotingMode int8u @71, low 7 bits.
  if let Some(&b) = payload.get(71) {
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
    while pos + 2 <= dir_end {
      // Parrot.pm:805 `last unless substr(.., $pos, 1) eq "\x0a"`.
      if data[pos] != 0x0a {
        break;
      }
      let len_byte = data[pos + 1] as usize;
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
    let id_bytes: [u8; 2] = [data[pos], data[pos + 1]];
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

    let payload = &data[effective_pos..effective_pos + size];

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
        // E1 TimeStamp extension (Parrot.pm:541-551). When it follows a
        // P2/P3 in the SAME `mett` sample buffer (the common case —
        // bundled comments say the extensions are concat'd after the
        // basic record), attach the timestamp to the just-emitted
        // flight sample. Otherwise (freestanding E1 — defensive), push
        // a TimeStamp-only sample tagged V2 by convention.
        if let Some(ts) = decode_e1_timestamp(payload) {
          // payload layout: [E1][nwords:u16-BE][int64u ts...].
          // decode_e1_timestamp reads the int64u at record offset 4.
          if let Some(last) = out.flight_samples_mut_last() {
            last.set_time_stamp_us(Some(ts));
          } else {
            let mut f = ParrotFlightSample::new(ParrotRecordVersion::V2);
            f.set_time_stamp_us(Some(ts));
            out.push_flight_sample(f);
          }
        }
      }
      // E2 / E3 (FollowMe / Automation): bundled walks these as
      // planned-waypoint records. Camera-indexing irrelevant
      // (FOLLOW-UP). Walked silently.
      b"E2" | b"E3" => {}
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
    //   offsets 36..40 = (alt 120.5 << 8) | sv_count(9) = (0x7880 << 8) | 0x09 = 0x00788009
    let lat_raw = (47.6062_f64 * f64::from(0x10_0000)).round() as i32;
    let lon_raw = (-122.3321_f64 * f64::from(0x10_0000)).round() as i32;
    let alt_int = 120_i32; // metres (encoded shifted-left-by-8)
    let sv_count = 9_u8;
    let alt_word = (alt_int << 8) | i32::from(sv_count);
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
    let alt_word = (50_i32 << 8) | 11;
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
    let alt_word = (100_i32 << 8) | 12;
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
