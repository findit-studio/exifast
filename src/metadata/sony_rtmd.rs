//! Typed mirror of `Image::ExifTool::Sony::rtmd` — the "Real-Time
//! MetaData" timed records carried in a Sony Alpha A7 / FX / RX / Cinema-line
//! MP4 / MOV video. Faithful port of `Sony.pm:10686-10850` (tag table) +
//! `Sony.pm:11566-11602` (`Process_rtmd`).
//!
//! ## Format
//!
//! `rtmd` samples carry a 16-bit-tag / 16-bit-length walker — NOT classic
//! MISB BER-KLV. The header is `[hdrLen:int16u]` (typically `0x1c`); past
//! the header, each record is `[tag:int16u][len:int16u][value:len bytes]`.
//! Two special-cases (`Sony.pm:11586-11591`):
//!
//!  - `tag == 0x060e` ⇒ the length field is IGNORED; a fixed 16-byte SMPTE
//!    Universal Label follows (the record's own 4 bytes ARE part of those
//!    16, hence no `+= 4`).
//!  - `tag == 0x8300` ⇒ a container — skip the 4-byte header and recurse
//!    inline through the SAME pointer, NOT into a child slice.
//!
//! All multi-byte ints are big-endian (Sony rtmd inherits the
//! `Image::ExifTool::Sony` default Big-Endian byte order — Sony.pm:55).
//!
//! ## What this sub-port surfaces
//!
//! Per Sony.pm:10686-10850, only the camera-indexing-relevant tags are
//! decoded into typed fields:
//!
//!  - **Camera identity** — `0x8114 SerialNumber` (string, often
//!    `"<MODEL> <SERIAL>"`, e.g. `"ILCE-7SM3 5072108"`); we split it.
//!  - **Exposure** — `0x8109 ExposureTime` (rational64u seconds), `0x810b
//!    ISO` (int16u), `0xe301` (int32u; alt-ISO seen on FX-line cameras),
//!    `0x8000 FNumber` (`2^(8-val/8192)`, Sony.pm:10703), `0x810a
//!    MasterGainAdjustment` (int16u/100, dB).
//!  - **Lens / focal** — `0x8106 FrameRate` (rational64u; not lens, but
//!    capture; surfaced under `CaptureSettings`).
//!  - **GPS** — `0x8501-0x8512` (string ref, rational64u coordinates, GPS
//!    `ConvertTimeStamp`-formatted time and `ExifDate`-formatted date).
//!    Most Sony bodies LACK GPS hardware; these populate only when a phone
//!    is paired via Imaging Edge Mobile.
//!  - **Timestamp** — `0xe304 DateTime` (BCD-packed, Sony.pm:10832).
//!  - **White balance** — `0xe303` (Sony.pm:10818-10827 PrintConv).
//!
//! Tags marked `%hidUnk` in bundled (`Sony_rtmd_0x...` Hidden+Unknown) are
//! NOT surfaced — bundled itself hides them from `-j` output unless
//! `-u` is passed.

extern crate alloc;
use alloc::{string::ToString, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata, MetaProjectInto};

// ===========================================================================
// SonyRtmdGpsSample — the GPS family (Sony.pm:10738-10811)
// ===========================================================================

/// One Sony rtmd GPS sample — the merged shape of every `0x85xx` GPS
/// record (Sony.pm:10738-10811). All fields optional; a real-world Sony
/// MP4 carries the full set only when the camera was paired to a phone
/// (Imaging Edge Mobile) at capture time.
#[derive(Debug, Clone, PartialEq)]
pub struct SonyRtmdGpsSample {
  /// `0x8500 GPSVersionID` after `tr/ /./` (Sony.pm:10738-10743) —
  /// typically `"2.2.0.0"`.
  version_id: Option<SmolStr>,
  /// `0x8502 GPSLatitude` in decimal degrees — sign flipped to negative
  /// when `GPSLatitudeRef` is `'S'`. Sony.pm:10752-10759 stores the value
  /// post-`GPS::ToDegrees`, which for a `rational64u` reduces to the
  /// quotient.
  latitude: Option<f64>,
  /// `0x8501 GPSLatitudeRef` — `'N'` or `'S'` (Sony.pm:10744-10752).
  latitude_ref: Option<SmolStr>,
  /// `0x8504 GPSLongitude` in decimal degrees — sign flipped to negative
  /// when `GPSLongitudeRef` is `'W'`. Sony.pm:10769-10776.
  longitude: Option<f64>,
  /// `0x8503 GPSLongitudeRef` — `'E'` or `'W'` (Sony.pm:10760-10767).
  longitude_ref: Option<SmolStr>,
  /// `0x8507 GPSTimeStamp` after `GPS::ConvertTimeStamp` — the
  /// `HH:MM:SS[.s+]` UTC time-of-day string (Sony.pm:10776-10781,
  /// GPS.pm:459-474).
  time_stamp: Option<SmolStr>,
  /// `0x8509 GPSStatus` raw character — `'A'` (active) or `'V'` (void).
  /// Sony.pm:10783-10791.
  status: Option<SmolStr>,
  /// `0x850a GPSMeasureMode` raw character — `'2'` or `'3'`.
  /// Sony.pm:10792-10800.
  measure_mode: Option<SmolStr>,
  /// `0x8512 GPSMapDatum` string (Sony.pm:10801-10805) — typically
  /// `"WGS-84"`.
  map_datum: Option<SmolStr>,
  /// `0x851d GPSDateStamp` after `Exif::ExifDate` — `YYYY:MM:DD`
  /// (Sony.pm:10806-10811, Exif.pm:6068-6076).
  date_stamp: Option<SmolStr>,
}

impl SonyRtmdGpsSample {
  /// An empty GPS sample (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      version_id: None,
      latitude: None,
      latitude_ref: None,
      longitude: None,
      longitude_ref: None,
      time_stamp: None,
      status: None,
      measure_mode: None,
      map_datum: None,
      date_stamp: None,
    }
  }

  /// `GPSVersionID` (e.g. `"2.2.0.0"`).
  #[inline(always)]
  #[must_use]
  pub fn version_id(&self) -> Option<&str> {
    self.version_id.as_deref()
  }

  /// `GPSLatitude` (decimal degrees, signed).
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// `GPSLatitudeRef` (`'N'` / `'S'`).
  #[inline(always)]
  #[must_use]
  pub fn latitude_ref(&self) -> Option<&str> {
    self.latitude_ref.as_deref()
  }

  /// `GPSLongitude` (decimal degrees, signed).
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// `GPSLongitudeRef` (`'E'` / `'W'`).
  #[inline(always)]
  #[must_use]
  pub fn longitude_ref(&self) -> Option<&str> {
    self.longitude_ref.as_deref()
  }

  /// `GPSTimeStamp` (`HH:MM:SS[.s+]`).
  #[inline(always)]
  #[must_use]
  pub fn time_stamp(&self) -> Option<&str> {
    self.time_stamp.as_deref()
  }

  /// `GPSStatus` (`'A'` / `'V'`).
  #[inline(always)]
  #[must_use]
  pub fn status(&self) -> Option<&str> {
    self.status.as_deref()
  }

  /// `GPSMeasureMode` (`'2'` / `'3'`).
  #[inline(always)]
  #[must_use]
  pub fn measure_mode(&self) -> Option<&str> {
    self.measure_mode.as_deref()
  }

  /// `GPSMapDatum`.
  #[inline(always)]
  #[must_use]
  pub fn map_datum(&self) -> Option<&str> {
    self.map_datum.as_deref()
  }

  /// `GPSDateStamp` (`YYYY:MM:DD`).
  #[inline(always)]
  #[must_use]
  pub fn date_stamp(&self) -> Option<&str> {
    self.date_stamp.as_deref()
  }

  /// `true` when the sample carries a non-`None` coordinate pair (after
  /// the ref-sign application).
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    self.latitude.is_some() && self.longitude.is_some()
  }

  /// `true` when every field is `None`.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.version_id.is_none()
      && self.latitude.is_none()
      && self.latitude_ref.is_none()
      && self.longitude.is_none()
      && self.longitude_ref.is_none()
      && self.time_stamp.is_none()
      && self.status.is_none()
      && self.measure_mode.is_none()
      && self.map_datum.is_none()
      && self.date_stamp.is_none()
  }

  /// Assign `GPSVersionID`.
  #[inline(always)]
  pub fn set_version_id(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.version_id = v;
    self
  }

  /// Assign `GPSLatitude` (already signed).
  #[inline(always)]
  pub const fn set_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign `GPSLatitudeRef`.
  #[inline(always)]
  pub fn set_latitude_ref(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.latitude_ref = v;
    self
  }

  /// Assign `GPSLongitude` (already signed).
  #[inline(always)]
  pub const fn set_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }

  /// Assign `GPSLongitudeRef`.
  #[inline(always)]
  pub fn set_longitude_ref(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.longitude_ref = v;
    self
  }

  /// Assign `GPSTimeStamp`.
  #[inline(always)]
  pub fn set_time_stamp(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.time_stamp = v;
    self
  }

  /// Assign `GPSStatus`.
  #[inline(always)]
  pub fn set_status(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.status = v;
    self
  }

  /// Assign `GPSMeasureMode`.
  #[inline(always)]
  pub fn set_measure_mode(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.measure_mode = v;
    self
  }

  /// Assign `GPSMapDatum`.
  #[inline(always)]
  pub fn set_map_datum(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.map_datum = v;
    self
  }

  /// Assign `GPSDateStamp`.
  #[inline(always)]
  pub fn set_date_stamp(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_stamp = v;
    self
  }
}

impl Default for SonyRtmdGpsSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// SonyRtmdCameraSnapshot — the per-sample camera state
// ===========================================================================

/// One Sony rtmd camera-state snapshot — the union of every per-sample
/// non-GPS, non-motion record listed in `Sony.pm:10700-10847` that
/// carries indexing-relevant information.
///
/// Faithful by selection: tags marked `%hidUnk` (Hidden + Unknown) in
/// bundled are NOT surfaced — bundled itself hides them from `-j`
/// output unless `-u` is passed. The full set of decoded tags can be
/// recovered by extending [`SonyRtmdMeta`] in a follow-up port; the
/// fields here are camera-identification + exposure / WB / DateTime
/// — what the cross-format domain layer needs.
#[derive(Debug, Clone, PartialEq)]
pub struct SonyRtmdCameraSnapshot {
  /// `0x8114 SerialNumber` raw — the bundled tag (Sony.pm:10734).
  /// Real-world values include the camera model as a prefix, e.g.
  /// `"ILCE-7SM3 5072108"`. The parsed pieces also appear separately
  /// in [`Self::model`] / [`Self::serial`].
  serial_number: Option<SmolStr>,
  /// Camera model parsed out of [`Self::serial_number`] when it has the
  /// `"<MODEL> <SERIAL>"` shape; otherwise `None`. **exifast convenience,
  /// not a bundled-emitted tag** — the bundled `-j` output keeps the
  /// composite `SerialNumber` only.
  model: Option<SmolStr>,
  /// Camera serial parsed out of [`Self::serial_number`] (the trailing
  /// space-delimited token); otherwise `None`.
  serial: Option<SmolStr>,
  /// `0x8000 FNumber` (Sony.pm:10700-10705) — post-`ValueConv =
  /// 2^(8-val/8192)`, the linear f-number (e.g. `1.8`, `5.6`).
  f_number: Option<f64>,
  /// `0x8109 ExposureTime` in seconds (Sony.pm:10717-10721) — the
  /// rational64u quotient.
  exposure_time_s: Option<f64>,
  /// `0x810a MasterGainAdjustment` in dB (Sony.pm:10722-10727) — raw
  /// int16u / 100.
  master_gain_db: Option<f64>,
  /// `0x810b ISO` raw (Sony.pm:10728) — int16u. When the file uses the
  /// alternate `0xe301` int32u channel (older firmware), prefer that on
  /// read; this struct stores whichever the rtmd sample provided.
  iso: Option<u32>,
  /// `0x8106 FrameRate` (Sony.pm:10716) — rational64u quotient. Stored
  /// on the camera snapshot because each rtmd sample carries one (it is
  /// a per-clip property in practice).
  frame_rate: Option<f64>,
  /// `0xe303 WhiteBalance` raw (Sony.pm:10817-10827) — the bundled
  /// PrintConv key. exifast keeps the numeric raw (display-name lookup
  /// is a callers' concern).
  white_balance_raw: Option<u8>,
  /// `0xe304 DateTime` post-`ValueConv` (Sony.pm:10828-10833) — the
  /// `"YYYY:MM:DD HH:MM:SS"` string assembled from the BCD-packed
  /// 7-byte record.
  date_time: Option<SmolStr>,
}

impl SonyRtmdCameraSnapshot {
  /// An empty snapshot.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      serial_number: None,
      model: None,
      serial: None,
      f_number: None,
      exposure_time_s: None,
      master_gain_db: None,
      iso: None,
      frame_rate: None,
      white_balance_raw: None,
      date_time: None,
    }
  }

  /// `SerialNumber` raw composite (`"<MODEL> <SERIAL>"` on most bodies).
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }

  /// Camera model (parsed from the composite).
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// Camera serial (parsed from the composite).
  #[inline(always)]
  #[must_use]
  pub fn serial(&self) -> Option<&str> {
    self.serial.as_deref()
  }

  /// `FNumber` (linear f-number, post-ValueConv).
  #[inline(always)]
  #[must_use]
  pub const fn f_number(&self) -> Option<f64> {
    self.f_number
  }

  /// `ExposureTime` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time_s
  }

  /// `MasterGainAdjustment` in dB.
  #[inline(always)]
  #[must_use]
  pub const fn master_gain_db(&self) -> Option<f64> {
    self.master_gain_db
  }

  /// `ISO` raw.
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<u32> {
    self.iso
  }

  /// `FrameRate` (rational quotient).
  #[inline(always)]
  #[must_use]
  pub const fn frame_rate(&self) -> Option<f64> {
    self.frame_rate
  }

  /// `WhiteBalance` raw numeric key (lookup table in Sony.pm:10819-10826).
  #[inline(always)]
  #[must_use]
  pub const fn white_balance_raw(&self) -> Option<u8> {
    self.white_balance_raw
  }

  /// `DateTime` post-`ValueConv` (the joined `"YYYY:MM:DD HH:MM:SS"`).
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.serial_number.is_none()
      && self.model.is_none()
      && self.serial.is_none()
      && self.f_number.is_none()
      && self.exposure_time_s.is_none()
      && self.master_gain_db.is_none()
      && self.iso.is_none()
      && self.frame_rate.is_none()
      && self.white_balance_raw.is_none()
      && self.date_time.is_none()
  }

  /// Assign `SerialNumber`. If the value matches `"<MODEL> <SERIAL>"`
  /// (single space delimiter), also populate the parsed [`Self::model`]
  /// and [`Self::serial`] fields. exifast convenience — bundled keeps the
  /// composite tag only (Sony.pm:10734), the split is a downstream aid.
  #[inline]
  pub fn set_serial_number(&mut self, v: Option<SmolStr>) -> &mut Self {
    if let Some(ref s) = v {
      let (m, sn) = parse_model_serial(s);
      self.model = m;
      self.serial = sn;
    } else {
      self.model = None;
      self.serial = None;
    }
    self.serial_number = v;
    self
  }

  /// Assign `FNumber`.
  #[inline(always)]
  pub const fn set_f_number(&mut self, v: Option<f64>) -> &mut Self {
    self.f_number = v;
    self
  }

  /// Assign `ExposureTime`.
  #[inline(always)]
  pub const fn set_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }

  /// Assign `MasterGainAdjustment` (dB).
  #[inline(always)]
  pub const fn set_master_gain_db(&mut self, v: Option<f64>) -> &mut Self {
    self.master_gain_db = v;
    self
  }

  /// Assign `ISO`.
  #[inline(always)]
  pub const fn set_iso(&mut self, v: Option<u32>) -> &mut Self {
    self.iso = v;
    self
  }

  /// Assign `FrameRate`.
  #[inline(always)]
  pub const fn set_frame_rate(&mut self, v: Option<f64>) -> &mut Self {
    self.frame_rate = v;
    self
  }

  /// Assign `WhiteBalance` raw.
  #[inline(always)]
  pub const fn set_white_balance_raw(&mut self, v: Option<u8>) -> &mut Self {
    self.white_balance_raw = v;
    self
  }

  /// Assign `DateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }
}

impl Default for SonyRtmdCameraSnapshot {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// Split a Sony rtmd `SerialNumber` (Sony.pm:10734) into `(model,
/// serial)`. The bundled comment shows the real-world shape
/// `"ILCE-7SM3 5072108"` (model + single space + serial). When the
/// string contains exactly one space, treat the part before the space
/// as the model and the part after as the serial. Otherwise return
/// `(None, None)` and leave the composite as-is.
fn parse_model_serial(s: &str) -> (Option<SmolStr>, Option<SmolStr>) {
  // Trim NULs first — rtmd `string` records are NUL-padded.
  let s = s.trim_end_matches('\0').trim();
  if let Some((model, serial)) = s.split_once(' ') {
    let model = model.trim();
    let serial = serial.trim();
    // Both non-empty AND the serial contains no further whitespace ⇒ a
    // single-space-delimited "<MODEL> <SERIAL>". Otherwise fall back.
    if !model.is_empty() && !serial.is_empty() && !serial.contains(char::is_whitespace) {
      return (Some(SmolStr::new(model)), Some(SmolStr::new(serial)));
    }
  }
  (None, None)
}

// ===========================================================================
// SonyRtmdMeta — the aggregate per-track result
// ===========================================================================

/// The typed result of Sony `rtmd` extraction — the per-format mirror
/// of what `Image::ExifTool::Sony::Process_rtmd` (Sony.pm:11569-11602)
/// would emit for a video's `rtmd` metadata track.
///
/// Each rtmd sample produces ONE [`SonyRtmdCameraSnapshot`] + optionally
/// ONE [`SonyRtmdGpsSample`]. The vectors are in source order; the
/// `MediaMetadata` projection uses the FIRST non-empty entry of each.
///
/// Empty (`is_empty()`) when no rtmd track is present or every sample
/// failed to decode.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct SonyRtmdMeta {
  /// One per rtmd sample. Empty when no rtmd records were decoded.
  camera_snapshots: Vec<SonyRtmdCameraSnapshot>,
  /// One per rtmd sample that carried at least one `0x85xx` GPS record.
  /// Most Sony bodies LACK GPS hardware; this is empty unless a phone
  /// was paired at capture (Imaging Edge Mobile).
  gps_samples: Vec<SonyRtmdGpsSample>,
  /// `Sony rtmd`-level warnings, mirroring `ExifTool:Warning` from
  /// `Process_rtmd` (Sony.pm:11575 `return 0 if $end < 2`). Only the
  /// FIRST warning is retained, matching the bundled `-j` rendering.
  warning: Option<SmolStr>,
}

impl SonyRtmdMeta {
  /// An empty result (no rtmd data decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      camera_snapshots: Vec::new(),
      gps_samples: Vec::new(),
      warning: None,
    }
  }

  /// One [`SonyRtmdCameraSnapshot`] per rtmd sample.
  #[inline(always)]
  #[must_use]
  pub fn camera_snapshots(&self) -> &[SonyRtmdCameraSnapshot] {
    self.camera_snapshots.as_slice()
  }

  /// One [`SonyRtmdGpsSample`] per rtmd sample that carried GPS records.
  /// Empty unless a phone was paired (most Sony bodies lack GPS hardware).
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[SonyRtmdGpsSample] {
    self.gps_samples.as_slice()
  }

  /// The first decoded warning (e.g. truncated header).
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no record was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.camera_snapshots.is_empty() && self.gps_samples.is_empty()
  }

  /// The FIRST snapshot whose `model` OR `serial_number` is populated —
  /// the entry that feeds the [`crate::metadata::CameraInfo`] projection.
  #[inline]
  #[must_use]
  pub fn first_camera_snapshot(&self) -> Option<&SonyRtmdCameraSnapshot> {
    self
      .camera_snapshots
      .iter()
      .find(|s| s.serial_number.is_some() || s.model.is_some())
      .or_else(|| self.camera_snapshots.first())
  }

  /// The FIRST GPS sample carrying a coordinate pair — the entry that
  /// feeds the [`crate::metadata::GpsLocation`] projection.
  #[inline]
  #[must_use]
  pub fn first_fix(&self) -> Option<&SonyRtmdGpsSample> {
    self.gps_samples.iter().find(|g| g.has_coordinates())
  }

  /// The FIRST snapshot whose `f_number` OR `exposure_time_s` OR `iso`
  /// is populated — the entry that feeds
  /// [`crate::metadata::CaptureSettings`].
  #[inline]
  #[must_use]
  pub fn first_capture_snapshot(&self) -> Option<&SonyRtmdCameraSnapshot> {
    self
      .camera_snapshots
      .iter()
      .find(|s| s.f_number.is_some() || s.exposure_time_s.is_some() || s.iso.is_some())
  }

  /// Append a decoded camera-state snapshot.
  #[inline(always)]
  pub fn push_camera_snapshot(&mut self, snap: SonyRtmdCameraSnapshot) -> &mut Self {
    self.camera_snapshots.push(snap);
    self
  }

  /// Append a decoded GPS sample.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, sample: SonyRtmdGpsSample) -> &mut Self {
    self.gps_samples.push(sample);
    self
  }

  /// Set the first ProcessRtmd warning (subsequent calls are ignored —
  /// bundled `-j` reports only the first).
  #[inline]
  pub fn set_warning(&mut self, msg: SmolStr) -> &mut Self {
    if self.warning.is_none() {
      self.warning = Some(msg);
    }
    self
  }
}

impl Default for SonyRtmdMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — Sony rtmd projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for SonyRtmdMeta {
  /// Project Sony rtmd metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** Sony rtmd is the **THIRD-HIGHEST tier** of the camera
  /// priority chain. Make = `"Sony"` (every body that writes `rtmd` is
  /// Sony — Sony.pm:10691-10705). Model / Serial come from the parsed
  /// `SerialNumber` field (which Sony writes as `"<MODEL> <SERIAL>"` on
  /// most bodies). The projection skips silently when a higher-priority
  /// source (GoPro identity, or a future SP2 `udta/©mak + ©mod`) already
  /// set `md.camera()`.
  ///
  /// **CaptureSettings:** the FIRST non-empty capture snapshot populates
  /// `md.capture()` — `ExposureTime`, `ISO`, `FNumber` per Sony.pm:10718-
  /// 10727.
  ///
  /// **GpsLocation:** Sony rtmd GPS is phone-paired (Imaging Edge Mobile)
  /// but bundled-decoded as the camera's GPS record; ranks **THIRD-HIGHEST**
  /// in the GPS priority chain (below GoPro / CAMM on-device hardware,
  /// above Insta360 / SP3-stream). Sony rtmd does NOT carry altitude
  /// (no `0x8506` in Sony.pm's table); timestamp combines `GPSDateStamp` +
  /// `GPSTimeStamp` Exif-canonically.
  ///
  /// **Warnings:** any ProcessRtmd `warning()` (e.g. truncated header)
  /// propagates into `md.warnings()` with the `"[Sony rtmd] "` prefix.
  fn project_into(&self, md: &mut MediaMetadata) {
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none()
      && let Some(snap) = self.first_camera_snapshot()
    {
      let mut cam = CameraInfo::new();
      cam.update_make(Some("Sony".into()));
      cam.update_model(snap.model().map(str::to_string));
      cam.update_serial(snap.serial().map(str::to_string));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── CaptureSettings ────────────────────────────────────────────────
    if md.capture().is_none()
      && let Some(cap_snap) = self.first_capture_snapshot()
    {
      let mut cap = CaptureSettings::new();
      cap.update_exposure_time_s(cap_snap.exposure_time_s());
      cap.update_iso(cap_snap.iso());
      cap.update_f_number(cap_snap.f_number());
      if !cap.is_empty() {
        md.set_capture(cap);
      }
    }
    // ── GpsLocation ────────────────────────────────────────────────────
    if md.gps().is_none()
      && let Some(s) = self.first_fix()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(s.latitude())
        .update_longitude(s.longitude())
        // Sony rtmd never carries altitude (no `0x8506` in Sony.pm).
        .update_altitude_m(None)
        .update_timestamp(combine_date_time(s.date_stamp(), s.time_stamp()));
      md.set_gps(gps);
    }
    // ── Warnings ───────────────────────────────────────────────────────
    if let Some(w) = self.warning() {
      let mut msg = alloc::string::String::with_capacity(13 + w.len());
      msg.push_str("[Sony rtmd] ");
      msg.push_str(w);
      md.push_warning(msg);
    }
  }
}

/// Combine `GPSDateStamp` (`"YYYY:MM:DD"`) and `GPSTimeStamp`
/// (`"HH:MM:SS"`) into the Exif-canonical `"YYYY:MM:DD HH:MM:SS"` form for
/// [`GpsLocation::timestamp`]. Returns `None` when both are absent; uses
/// whichever of the two is present when only one is. Mirrors how ExifTool's
/// `GPSDateTime` Composite tag is assembled (Exif.pm Composite table —
/// `GPSDateStamp` + `GPSTimeStamp` joined by a single space).
fn combine_date_time(date: Option<&str>, time: Option<&str>) -> Option<alloc::string::String> {
  match (date, time) {
    (Some(d), Some(t)) => {
      let mut s = alloc::string::String::with_capacity(d.len() + 1 + t.len());
      s.push_str(d);
      s.push(' ');
      s.push_str(t);
      Some(s)
    }
    (Some(d), None) => Some(d.to_string()),
    (None, Some(t)) => Some(t.to_string()),
    (None, None) => None,
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
    let m = SonyRtmdMeta::new();
    assert!(m.is_empty());
    assert!(m.camera_snapshots().is_empty());
    assert!(m.gps_samples().is_empty());
    assert!(m.first_camera_snapshot().is_none());
    assert!(m.first_fix().is_none());
    assert!(m.first_capture_snapshot().is_none());
    assert!(m.warning().is_none());
  }

  #[test]
  fn serial_number_splits_model_and_serial() {
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108")));
    assert_eq!(s.serial_number(), Some("ILCE-7SM3 5072108"));
    assert_eq!(s.model(), Some("ILCE-7SM3"));
    assert_eq!(s.serial(), Some("5072108"));
  }

  #[test]
  fn serial_number_with_nul_padding_trims() {
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_serial_number(Some(SmolStr::new("ILCE-7M4 12345678\0\0\0")));
    // The composite preserves the NUL-padded bundled form, but the
    // parser strips it.
    assert_eq!(s.model(), Some("ILCE-7M4"));
    assert_eq!(s.serial(), Some("12345678"));
  }

  #[test]
  fn serial_number_no_space_keeps_composite_only() {
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_serial_number(Some(SmolStr::new("ILCE7SM3")));
    assert_eq!(s.serial_number(), Some("ILCE7SM3"));
    assert!(s.model().is_none());
    assert!(s.serial().is_none());
  }

  #[test]
  fn serial_number_three_tokens_keeps_composite_only() {
    // Multiple spaces ⇒ ambiguous; bundled stores the raw, exifast does
    // NOT guess. Composite is retained but model/serial stay None.
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108 EXTRA")));
    assert!(s.model().is_none());
    assert!(s.serial().is_none());
  }

  #[test]
  fn meta_first_camera_picks_first_populated() {
    let mut m = SonyRtmdMeta::new();
    // First snapshot: only F-number (no identity).
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_f_number(Some(2.8));
    m.push_camera_snapshot(a);
    // Second snapshot: carries serial composite.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_serial_number(Some(SmolStr::new("ILCE-7SM3 12345")));
    m.push_camera_snapshot(b);
    let first = m.first_camera_snapshot().expect("found");
    assert_eq!(first.model(), Some("ILCE-7SM3"));
  }

  #[test]
  fn meta_first_capture_picks_first_with_exposure() {
    let mut m = SonyRtmdMeta::new();
    // Snapshot 0: identity only.
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_serial_number(Some(SmolStr::new("ILCE-7M4 1")));
    m.push_camera_snapshot(a);
    // Snapshot 1: exposure-bearing.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_exposure_time_s(Some(0.004));
    b.set_iso(Some(800));
    m.push_camera_snapshot(b);
    let cap = m.first_capture_snapshot().expect("found");
    assert_eq!(cap.exposure_time_s(), Some(0.004));
    assert_eq!(cap.iso(), Some(800));
  }

  #[test]
  fn gps_sample_has_coordinates_requires_both() {
    let mut g = SonyRtmdGpsSample::new();
    assert!(!g.has_coordinates());
    g.set_latitude(Some(37.5));
    assert!(!g.has_coordinates());
    g.set_longitude(Some(-122.0));
    assert!(g.has_coordinates());
  }

  #[test]
  fn warning_set_once() {
    let mut m = SonyRtmdMeta::new();
    m.set_warning(SmolStr::new("first"));
    m.set_warning(SmolStr::new("second"));
    assert_eq!(m.warning(), Some("first"));
  }

  #[test]
  fn snapshot_set_serial_to_none_clears_parsed_fields() {
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108")));
    assert!(s.model().is_some());
    s.set_serial_number(None);
    assert!(s.model().is_none());
    assert!(s.serial().is_none());
    assert!(s.serial_number().is_none());
  }

  // P3-D project_into round-trips.

  #[test]
  fn project_into_empty_writes_nothing() {
    let m = SonyRtmdMeta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
    assert!(md.warnings().is_empty());
  }

  #[test]
  fn project_into_populates_camera_make_sony_and_model_from_serial_number() {
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108")));
    m.push_camera_snapshot(snap);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cam = md.camera().expect("camera populated");
    assert_eq!(cam.make(), Some("Sony"));
    assert_eq!(cam.model(), Some("ILCE-7SM3"));
    assert_eq!(cam.serial(), Some("5072108"));
  }

  #[test]
  fn project_into_propagates_warning_with_sony_rtmd_prefix() {
    let mut m = SonyRtmdMeta::new();
    m.set_warning(SmolStr::new("Truncated Sony rtmd"));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.warnings().len(), 1);
    assert_eq!(md.warnings()[0], "[Sony rtmd] Truncated Sony rtmd");
  }
}
