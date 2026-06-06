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

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata};
use crate::value::Rational;

// ===========================================================================
// SonyRtmdCoord — a present GPS coordinate's decoded state
// ===========================================================================

/// The decoded state of a PRESENT `0x8502 GPSLatitude` / `0x8504
/// GPSLongitude` record. `GPS::ToDegrees` (GPS.pm:582-600) returns a DEFINED
/// value for any present record: the decimal degrees when every D/M/S
/// component is finite, or the empty string `""` (GPS.pm:585 `return '' if
/// $val =~ /\b(inf|undef)\b/`) when ANY component is `inf`/`undef` (a
/// zero-denominator `rational64u`) OR the record is too short to carry even
/// the degrees component. So a present record never yields "no tag" — it
/// yields a number or `""`.
///
/// This enum distinguishes the two PRESENT outcomes; record ABSENCE is the
/// enclosing `Option<SonyRtmdCoord>` being `None`. Only [`Self::Value`]
/// participates in the cross-format `GpsLocation` projection — an
/// [`Self::Empty`] coordinate is a defined-but-bogus value that must NOT
/// poison the domain.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SonyRtmdCoord {
  /// A finite decimal-degree coordinate (every D/M/S component finite).
  Value(f64),
  /// A present record whose `GPS::ToDegrees` rendered `""` — any `inf`/`undef`
  /// component, or a record shorter than one `rational64u` component.
  Empty,
}

impl SonyRtmdCoord {
  /// `true` for [`Self::Value`].
  #[inline(always)]
  #[must_use]
  pub const fn is_value(&self) -> bool {
    matches!(self, Self::Value(_))
  }

  /// `true` for [`Self::Empty`].
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    matches!(self, Self::Empty)
  }

  /// The finite coordinate, or `None` for [`Self::Empty`]. Takes `self` by
  /// value (the enum is `Copy`) so it composes with `Option::and_then`.
  #[inline(always)]
  #[must_use]
  pub const fn value(self) -> Option<f64> {
    match self {
      Self::Value(v) => Some(v),
      Self::Empty => None,
    }
  }
}

// ===========================================================================
// NumericRead — a present NUMERIC record's decoded state (absent / empty / valid)
// ===========================================================================

/// The decoded state of a PRESENT Sony rtmd NUMERIC record — the generalization
/// of [`SonyRtmdCoord`] from GPS coordinates to the plain scalar/rational
/// numeric tags (`0x8000 FNumber`, `0x8106 FrameRate`, `0x8109 ExposureTime`,
/// `0x810a MasterGainAdjustment`, `0x810b ISO`, `0x810c
/// ElectricalExtenderMagnification`).
///
/// ExifTool's `Process_rtmd` walker (`while $pos+4 < $end`, Sony.pm:11582)
/// processes a NON-FINAL present record even when its value bytes are shorter
/// than the tag's `Format` width, and `ReadValue` returns the EMPTY STRING `''`
/// for such a sub-width (including zero-length) read (the `unless ($count) {
/// return '' if … $size < $len }` branch, ExifTool.pm:6297). Each tag's
/// ValueConv then NUMIFIES that `''` — `2^(8-''/8192) = 256` for FNumber,
/// `''/100 = 0` for MasterGainAdjustment, the bare `''` for the raw / rational
/// tags — so a PRESENT-but-sub-width numeric record emits a DEFINED value in
/// bundled, NOT a dropped tag.
///
/// A plain `Option<T>` cannot carry this: `None` would conflate "record ABSENT"
/// (a FINAL bare 4-byte header, excluded by the walker bound — emit nothing)
/// with "record PRESENT but sub-width/empty" (emit the ValueConv-of-`''`). This
/// enum nested in an `Option` separates the three states:
///  - `None` — the record is ABSENT (the walker never dispatched its decode);
///  - `Some(EmptyRead)` — the record is PRESENT but its value is sub-width /
///    empty (`ReadValue` ⇒ `''`); the emission renders the tag's
///    ValueConv-of-`''` (see `src/formats/quicktime.rs`);
///  - `Some(Valid(t))` — the record is PRESENT with enough bytes; `t` is the
///    fully-decoded typed value, rendered EXACTLY as before.
///
/// Only [`Self::Valid`] participates in the cross-format domain projection — an
/// [`Self::EmptyRead`] is a defined-but-degenerate value that must NOT reach
/// `CaptureSettings` (its accessors are consumed as real numbers downstream).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericRead<T> {
  /// A present record with a sufficient-width value — the fully-decoded `t`.
  Valid(T),
  /// A present record whose value was sub-width / empty (`ReadValue` ⇒ `''`);
  /// the emission renders the tag's ValueConv-of-`''`, the domain skips it.
  EmptyRead,
}

impl<T> NumericRead<T> {
  /// `true` for [`Self::Valid`].
  #[inline(always)]
  #[must_use]
  pub const fn is_valid(&self) -> bool {
    matches!(self, Self::Valid(_))
  }

  /// `true` for [`Self::EmptyRead`].
  #[inline(always)]
  #[must_use]
  pub const fn is_empty_read(&self) -> bool {
    matches!(self, Self::EmptyRead)
  }
}

impl<T: Copy> NumericRead<T> {
  /// The VALID typed value, or `None` for [`Self::EmptyRead`] — the accessor the
  /// DOMAIN consumes (a degenerate empty-read numeric never reaches the
  /// cross-format layer). Takes `self` by value (the enum is `Copy` for `T:
  /// Copy`) so it composes with `Option::and_then`.
  #[inline(always)]
  #[must_use]
  pub const fn value(self) -> Option<T> {
    match self {
      Self::Valid(v) => Some(v),
      Self::EmptyRead => None,
    }
  }
}

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
  /// `0x8502 GPSLatitude` — `None` when the record is ABSENT,
  /// `Some(SonyRtmdCoord::Value)` (sign flipped to negative when
  /// `GPSLatitudeRef` is `'S'`) for a finite coordinate, or
  /// `Some(SonyRtmdCoord::Empty)` when `GPS::ToDegrees` rendered `""` (any
  /// `inf`/`undef` component, or a too-short record — GPS.pm:585).
  /// Sony.pm:10752-10759 stores the value post-`GPS::ToDegrees`.
  latitude: Option<SonyRtmdCoord>,
  /// `0x8501 GPSLatitudeRef` — `'N'` or `'S'` (Sony.pm:10744-10752).
  latitude_ref: Option<SmolStr>,
  /// `0x8504 GPSLongitude` — `None` when ABSENT,
  /// `Some(SonyRtmdCoord::Value)` (negative when `GPSLongitudeRef` is `'W'`)
  /// for a finite coordinate, or `Some(SonyRtmdCoord::Empty)` for the
  /// `GPS::ToDegrees` `""` render. Sony.pm:10769-10776.
  longitude: Option<SonyRtmdCoord>,
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

  /// `GPSLatitude` — `None` (absent), `Some(Value)` (finite, signed), or
  /// `Some(Empty)` (`GPS::ToDegrees` `""`).
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<SonyRtmdCoord> {
    self.latitude
  }

  /// `GPSLatitudeRef` (`'N'` / `'S'`).
  #[inline(always)]
  #[must_use]
  pub fn latitude_ref(&self) -> Option<&str> {
    self.latitude_ref.as_deref()
  }

  /// `GPSLongitude` — `None` (absent), `Some(Value)` (finite, signed), or
  /// `Some(Empty)` (`GPS::ToDegrees` `""`).
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<SonyRtmdCoord> {
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

  /// `true` when the sample carries a FINITE coordinate pair (both a
  /// [`SonyRtmdCoord::Value`], after the ref-sign application). A present-empty
  /// ([`SonyRtmdCoord::Empty`]) coordinate does NOT count — it is a defined-but-
  /// bogus value that must not feed the `GpsLocation` projection.
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    matches!(self.latitude, Some(SonyRtmdCoord::Value(_)))
      && matches!(self.longitude, Some(SonyRtmdCoord::Value(_)))
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

  /// Assign `GPSLatitude` (a finite [`SonyRtmdCoord::Value`] is already signed).
  #[inline(always)]
  pub const fn set_latitude(&mut self, v: Option<SonyRtmdCoord>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign `GPSLatitudeRef`.
  #[inline(always)]
  pub fn set_latitude_ref(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.latitude_ref = v;
    self
  }

  /// Assign `GPSLongitude` (a finite [`SonyRtmdCoord::Value`] is already signed).
  #[inline(always)]
  pub const fn set_longitude(&mut self, v: Option<SonyRtmdCoord>) -> &mut Self {
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
  /// 2^(8-val/8192)`, the linear f-number (e.g. `1.8`, `5.6`). Carries a
  /// [`NumericRead`]: `None` = ABSENT, `Some(EmptyRead)` = PRESENT-but-sub-width
  /// (the emission renders the ValueConv-of-`''` `2^(8-0/8192) = 256`),
  /// `Some(Valid(f))` = the decoded linear f-number.
  f_number: Option<NumericRead<f64>>,
  /// `0x8109 ExposureTime` (Sony.pm:10717-10721) — the raw `rational64u`
  /// (NOT pre-divided), so the `-n` emission can render ExifTool's rational
  /// `%g` form (`0.01666666667`, not the 15-digit f64) and a zero
  /// denominator stays `undef`. The f64 seconds accessor computes the
  /// quotient on demand. A [`NumericRead`]: `Some(EmptyRead)` for a sub-width
  /// record (the emission renders the `PrintExposureTime('')` empty string).
  exposure_time: Option<NumericRead<Rational>>,
  /// `0x810a MasterGainAdjustment` in dB (Sony.pm:10722-10727) — raw
  /// int16u / 100. A [`NumericRead`]: `Some(EmptyRead)` for a sub-width record
  /// (the emission renders the ValueConv-of-`''` `''/100 = 0`).
  master_gain_db: Option<NumericRead<f64>>,
  /// `0x810b ISO` raw (Sony.pm:10728) — int16u. When the file uses the
  /// alternate `0xe301` int32u channel (older firmware), prefer that on
  /// read; this struct stores whichever the rtmd sample provided. A
  /// [`NumericRead`]: `Some(EmptyRead)` for a sub-width canonical `0x810b`
  /// record (the emission renders the raw `''` empty string).
  iso: Option<NumericRead<u32>>,
  /// `true` when [`Self::iso`] was populated from the CANONICAL `0x810b`
  /// tag (Sony.pm:10728), as opposed to the alternate `0xe301` int32u
  /// channel (Sony.pm:10814, a `%hidUnk` Hidden+Unknown tag bundled does
  /// NOT emit as `Sony:ISO`). The emission layer surfaces `Sony:ISO` only
  /// when this marker is set; the domain layer keeps using [`Self::iso`]
  /// as the `0x810b`-or-`0xe301` fallback regardless.
  iso_from_canonical: bool,
  /// `0x8106 FrameRate` (Sony.pm:10716) — the raw `rational64u` (NOT
  /// pre-divided), so the `-n` emission renders ExifTool's rational `%g`
  /// form (`29.97002997`, not the 15-digit f64). Stored on the camera
  /// snapshot because each rtmd sample carries one (a per-clip property in
  /// practice). The f64 quotient accessor computes on demand. A
  /// [`NumericRead`]: `Some(EmptyRead)` for a sub-width record (the emission
  /// renders the `sprintf("%.2f",'')` → `0.00` at `-j`, raw `''` at `-n`).
  frame_rate: Option<NumericRead<Rational>>,
  /// `0x810c ElectricalExtenderMagnification` raw (Sony.pm:10769-10772) —
  /// `int16u`, no conv. A default-visible (non-`%hidUnk`) tag — emitted
  /// verbatim in both modes, positioned after `0x810b ISO`. A [`NumericRead`]:
  /// `Some(EmptyRead)` for a sub-width record (the emission renders the raw
  /// `''` empty string).
  electrical_extender_magnification: Option<NumericRead<u16>>,
  /// `0xe303 WhiteBalance` raw (Sony.pm:10817-10827) — the bundled `int8u`
  /// PrintConv-hash key. exifast keeps the numeric raw (display-name lookup is a
  /// callers' concern). A [`NumericRead`]: `None` = ABSENT, `Some(EmptyRead)` =
  /// PRESENT-but-sub-width (a zero-length / empty `0xe303` record whose
  /// `ReadValue` ⇒ `''`; the emission renders the PrintConv-of-`''` `"Unknown ()"`
  /// at `-j` / the raw `''` at `-n`), `Some(Valid(v))` = the decoded `int8u` key.
  white_balance_raw: Option<NumericRead<u8>>,
  /// `0xe304 DateTime` post-`ValueConv` (Sony.pm:10828-10833) — the
  /// `"YYYY:MM:DD HH:MM:SS"` string assembled from the BCD-packed
  /// 7-byte record.
  date_time: Option<SmolStr>,
  /// `0xe43b PitchRollYaw` (Sony.pm:10877-10881) — `Format => 'int16s'`,
  /// `RawConv => 'substr($val, 8)'`. The stored value is the FINAL string
  /// ExifTool emits (identical at `-j` and `-n`, no PrintConv): the whole
  /// record decoded as a space-joined `int16s` array, then `substr` from
  /// CHARACTER index 8 of that rendered string (NOT an 8-byte skip — see
  /// the parser). `None` when the rendered string is shorter than 8 chars
  /// (ExifTool's `substr outside of string` ⇒ undef ⇒ dropped tag).
  pitch_roll_yaw: Option<SmolStr>,
  /// `0xe44b Accelerometer` (Sony.pm:10883-10887) — same shape as
  /// [`Self::pitch_roll_yaw`] (`int16s`, `RawConv => 'substr($val, 8)'`).
  accelerometer: Option<SmolStr>,
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
      exposure_time: None,
      master_gain_db: None,
      iso: None,
      iso_from_canonical: false,
      frame_rate: None,
      electrical_extender_magnification: None,
      white_balance_raw: None,
      date_time: None,
      pitch_roll_yaw: None,
      accelerometer: None,
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

  /// `true` when this snapshot carries REAL camera identity — a parsed `model`
  /// or `serial`, OR a composite `SerialNumber` that is non-empty after trimming
  /// trailing NULs + surrounding whitespace. A present-but-EMPTY `SerialNumber`
  /// (the `""` a zero-length / leading-NUL `0x8114` record emits) carries no
  /// identity. The snapshot SELECTOR ([`SonyRtmdMeta::first_camera_snapshot`])
  /// and the projection GATE ([`SonyRtmdMeta::project_into`]) MUST share this
  /// predicate — otherwise the selector picks an empty-serial sample that the
  /// gate then rejects, shadowing a LATER sample that does carry identity.
  fn has_identity(&self) -> bool {
    self.model().is_some()
      || self.serial().is_some()
      || self
        .serial_number()
        .is_some_and(|s| !s.trim_end_matches('\0').trim().is_empty())
  }

  /// `FNumber` (linear f-number, post-ValueConv) — the VALID value ONLY: `None`
  /// for an absent OR present-but-sub-width ([`NumericRead::EmptyRead`]) record,
  /// so a degenerate numeric never reaches the domain. The emission consumes the
  /// full read via [`Self::f_number_read`].
  #[inline(always)]
  #[must_use]
  pub const fn f_number(&self) -> Option<f64> {
    match self.f_number {
      Some(NumericRead::Valid(v)) => Some(v),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `FNumber` as the full [`NumericRead`] (absent / present-empty / valid) — the
  /// value the emission renders (a present-empty record emits the
  /// ValueConv-of-`''`). `None` only when the record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn f_number_read(&self) -> Option<NumericRead<f64>> {
    self.f_number
  }

  /// `ExposureTime` in seconds — the `rational64u` quotient computed on
  /// demand, the VALID value ONLY (`None` for an absent OR present-but-sub-width
  /// record). The cross-format domain layer consumes this f64.
  #[inline(always)]
  #[must_use]
  pub fn exposure_time_s(&self) -> Option<f64> {
    self
      .exposure_time
      .and_then(NumericRead::value)
      .map(|r| r.to_f64())
  }

  /// `ExposureTime` as the raw `rational64u` (num/den) — the VALID value ONLY,
  /// the value the `-n` emission of a non-degenerate record renders via
  /// ExifTool's rational `%g` formatter (preserving the zero-denominator `undef`
  /// case). `None` for an absent OR present-but-sub-width record; the emission
  /// distinguishes the present-empty case via [`Self::exposure_time_read`].
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_rational(&self) -> Option<Rational> {
    match self.exposure_time {
      Some(NumericRead::Valid(r)) => Some(r),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `ExposureTime` as the full [`NumericRead`] (absent / present-empty / valid)
  /// — the value the emission renders. `None` only when the record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_read(&self) -> Option<NumericRead<Rational>> {
    self.exposure_time
  }

  /// `MasterGainAdjustment` in dB — the VALID value ONLY (`None` for an absent OR
  /// present-but-sub-width record).
  #[inline(always)]
  #[must_use]
  pub const fn master_gain_db(&self) -> Option<f64> {
    match self.master_gain_db {
      Some(NumericRead::Valid(v)) => Some(v),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `MasterGainAdjustment` as the full [`NumericRead`] — the value the emission
  /// renders (a present-empty record emits the ValueConv-of-`''` `0`). `None`
  /// only when the record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn master_gain_db_read(&self) -> Option<NumericRead<f64>> {
    self.master_gain_db
  }

  /// `ISO` raw — the VALID value ONLY (`None` for an absent OR
  /// present-but-sub-width record). The `0x810b`-or-`0xe301` fallback value.
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<u32> {
    match self.iso {
      Some(NumericRead::Valid(v)) => Some(v),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `ISO` as the full [`NumericRead`] (absent / present-empty / valid) — the
  /// value the emission renders (a present-empty canonical record emits the raw
  /// `''`). `None` only when the canonical `0x810b` record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn iso_read(&self) -> Option<NumericRead<u32>> {
    self.iso
  }

  /// `true` when [`Self::iso`] came from the canonical `0x810b` tag (and so
  /// may be emitted as `Sony:ISO`), `false` when it came only from the
  /// alternate `0xe301` channel (which bundled does not emit as ISO) or
  /// when no ISO was decoded.
  #[inline(always)]
  #[must_use]
  pub const fn iso_from_canonical(&self) -> bool {
    self.iso_from_canonical
  }

  /// `FrameRate` (the `rational64u` quotient, computed on demand) — the VALID
  /// value ONLY (`None` for an absent OR present-but-sub-width record). The f64
  /// downstream arithmetic consumes.
  #[inline(always)]
  #[must_use]
  pub fn frame_rate(&self) -> Option<f64> {
    self
      .frame_rate
      .and_then(NumericRead::value)
      .map(|r| r.to_f64())
  }

  /// `FrameRate` as the raw `rational64u` (num/den) — the VALID value ONLY, the
  /// value the `-n` emission of a non-degenerate record renders via ExifTool's
  /// rational `%g` formatter. `None` for an absent OR present-but-sub-width
  /// record; the emission distinguishes via [`Self::frame_rate_read`].
  #[inline(always)]
  #[must_use]
  pub const fn frame_rate_rational(&self) -> Option<Rational> {
    match self.frame_rate {
      Some(NumericRead::Valid(r)) => Some(r),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `FrameRate` as the full [`NumericRead`] (absent / present-empty / valid) —
  /// the value the emission renders (a present-empty record emits `0.00` at `-j`,
  /// `''` at `-n`). `None` only when the record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn frame_rate_read(&self) -> Option<NumericRead<Rational>> {
    self.frame_rate
  }

  /// `ElectricalExtenderMagnification` raw `int16u` (Sony.pm:10769-10772) — the
  /// VALID value ONLY (`None` for an absent OR present-but-sub-width record).
  #[inline(always)]
  #[must_use]
  pub const fn electrical_extender_magnification(&self) -> Option<u16> {
    match self.electrical_extender_magnification {
      Some(NumericRead::Valid(v)) => Some(v),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `ElectricalExtenderMagnification` as the full [`NumericRead`] — the value
  /// the emission renders (a present-empty record emits the raw `''`). `None`
  /// only when the record was ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn electrical_extender_magnification_read(&self) -> Option<NumericRead<u16>> {
    self.electrical_extender_magnification
  }

  /// `WhiteBalance` raw numeric key (lookup table in Sony.pm:10819-10826) — the
  /// VALID value ONLY (`None` for an absent OR present-but-sub-width record). The
  /// emission consumes the full read via [`Self::white_balance_read`].
  #[inline(always)]
  #[must_use]
  pub const fn white_balance_raw(&self) -> Option<u8> {
    match self.white_balance_raw {
      Some(NumericRead::Valid(v)) => Some(v),
      Some(NumericRead::EmptyRead) | None => None,
    }
  }

  /// `WhiteBalance` as the full [`NumericRead`] (absent / present-empty / valid)
  /// — the value the emission renders (a present-empty record emits the
  /// PrintConv-of-`''` `"Unknown ()"` / `''`). `None` only when the record was
  /// ABSENT.
  #[inline(always)]
  #[must_use]
  pub const fn white_balance_read(&self) -> Option<NumericRead<u8>> {
    self.white_balance_raw
  }

  /// `DateTime` post-`ValueConv` (the joined `"YYYY:MM:DD HH:MM:SS"`).
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `PitchRollYaw` (`0xe43b`) — the post-`RawConv` space-joined `int16s`
  /// string (identical at `-j`/`-n`). See [`Self::pitch_roll_yaw`] field doc.
  #[inline(always)]
  #[must_use]
  pub fn pitch_roll_yaw(&self) -> Option<&str> {
    self.pitch_roll_yaw.as_deref()
  }

  /// `Accelerometer` (`0xe44b`) — the post-`RawConv` space-joined `int16s`
  /// string (identical at `-j`/`-n`). See [`Self::accelerometer`] field doc.
  #[inline(always)]
  #[must_use]
  pub fn accelerometer(&self) -> Option<&str> {
    self.accelerometer.as_deref()
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.serial_number.is_none()
      && self.model.is_none()
      && self.serial.is_none()
      && self.f_number.is_none()
      && self.exposure_time.is_none()
      && self.master_gain_db.is_none()
      && self.iso.is_none()
      && self.frame_rate.is_none()
      && self.electrical_extender_magnification.is_none()
      && self.white_balance_raw.is_none()
      && self.date_time.is_none()
      && self.pitch_roll_yaw.is_none()
      && self.accelerometer.is_none()
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

  /// Assign `FNumber` as a [`NumericRead`]: `None` (absent),
  /// `Some(NumericRead::EmptyRead)` (present-but-sub-width), or
  /// `Some(NumericRead::Valid(f))` (the decoded linear f-number).
  #[inline(always)]
  pub const fn set_f_number(&mut self, v: Option<NumericRead<f64>>) -> &mut Self {
    self.f_number = v;
    self
  }

  /// Assign `ExposureTime` from the raw `rational64u` (num/den) as a
  /// [`NumericRead`]. The f64 seconds accessor derives its quotient on demand
  /// from the [`NumericRead::Valid`] case.
  #[inline(always)]
  pub const fn set_exposure_time(&mut self, v: Option<NumericRead<Rational>>) -> &mut Self {
    self.exposure_time = v;
    self
  }

  /// Assign `MasterGainAdjustment` (dB) as a [`NumericRead`].
  #[inline(always)]
  pub const fn set_master_gain_db(&mut self, v: Option<NumericRead<f64>>) -> &mut Self {
    self.master_gain_db = v;
    self
  }

  /// Assign `ISO` as a [`NumericRead`].
  #[inline(always)]
  pub const fn set_iso(&mut self, v: Option<NumericRead<u32>>) -> &mut Self {
    self.iso = v;
    self
  }

  /// Mark whether [`Self::iso`] came from the canonical `0x810b` tag. Set by
  /// the parser when (and only when) `0x810b` fires — `0xe301` leaves it
  /// `false`. Gates `Sony:ISO` emission (bundled hides the `0xe301` channel).
  #[inline(always)]
  pub const fn set_iso_from_canonical(&mut self, v: bool) -> &mut Self {
    self.iso_from_canonical = v;
    self
  }

  /// Assign `FrameRate` from the raw `rational64u` (num/den) as a
  /// [`NumericRead`]. The f64 quotient accessor derives on demand from the
  /// [`NumericRead::Valid`] case.
  #[inline(always)]
  pub const fn set_frame_rate(&mut self, v: Option<NumericRead<Rational>>) -> &mut Self {
    self.frame_rate = v;
    self
  }

  /// Assign `ElectricalExtenderMagnification` (`0x810c`, raw `int16u`) as a
  /// [`NumericRead`].
  #[inline(always)]
  pub const fn set_electrical_extender_magnification(
    &mut self,
    v: Option<NumericRead<u16>>,
  ) -> &mut Self {
    self.electrical_extender_magnification = v;
    self
  }

  /// Assign `WhiteBalance` as a [`NumericRead`]: `None` (absent),
  /// `Some(NumericRead::EmptyRead)` (present-but-sub-width), or
  /// `Some(NumericRead::Valid(v))` (the decoded `int8u` key).
  #[inline(always)]
  pub const fn set_white_balance_raw(&mut self, v: Option<NumericRead<u8>>) -> &mut Self {
    self.white_balance_raw = v;
    self
  }

  /// Assign `DateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `PitchRollYaw` (`0xe43b`) — the final post-`RawConv` string.
  #[inline(always)]
  pub fn set_pitch_roll_yaw(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.pitch_roll_yaw = v;
    self
  }

  /// Assign `Accelerometer` (`0xe44b`) — the final post-`RawConv` string.
  #[inline(always)]
  pub fn set_accelerometer(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.accelerometer = v;
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
// SonyRtmdSample — one timed rtmd sample (camera + optional GPS, as a unit)
// ===========================================================================

/// One Sony rtmd TIMED SAMPLE — the unified result of decoding a single
/// `rtmd` metadata sample (one `Process_rtmd` call, Sony.pm:11569-11602).
///
/// Each sample carries its own [`SonyRtmdCameraSnapshot`] (always present,
/// possibly all-`None`) and — only when the sample contained at least one
/// `0x85xx` GPS record — its [`SonyRtmdGpsSample`]. Holding both on ONE
/// element keeps the camera and GPS data of a given sample correlated (the
/// pre-refactor parallel-vector layout could not: the GPS vector was sparse).
///
/// The `doc` / `track_index` / `sample_time` / `sample_duration` fields are
/// the per-sample sub-document / track / sample-table coordinates; they are
/// STAMPED after extraction by [`SonyRtmdMeta`] (see its `stamp_*` methods),
/// mirroring the [`crate::metadata::CammGpsSample`] stamping pattern.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below. The stamped fields have no public setters — stamping is
/// driven by the `pub(crate)` methods on [`SonyRtmdMeta`].
#[derive(Debug, Clone, PartialEq)]
pub struct SonyRtmdSample {
  /// This sample's camera snapshot (always present, may be all-`None`).
  camera: SonyRtmdCameraSnapshot,
  /// This sample's GPS sample — `Some` only when the sample carried at least
  /// one `0x85xx` GPS record (most Sony bodies lack GPS hardware).
  gps: Option<SonyRtmdGpsSample>,
  /// Family-3 sub-document ordinal (`0` = unstamped / Main). Stamped later.
  doc: u32,
  /// Family-1 `Track<N>` index (1-based; `0` = unstamped). Stamped later.
  track_index: u32,
  /// Sample-table `SampleTime` in seconds. Stamped later.
  sample_time: Option<f64>,
  /// Sample-table `SampleDuration` in seconds. Stamped later.
  sample_duration: Option<f64>,
}

impl SonyRtmdSample {
  /// Build an unstamped sample from a decoded camera snapshot and an optional
  /// GPS sample (`doc` / `track_index` = `0`, timing = `None`). The stamped
  /// fields are filled later by [`SonyRtmdMeta`]'s `stamp_*` methods.
  #[inline(always)]
  #[must_use]
  pub fn new(camera: SonyRtmdCameraSnapshot, gps: Option<SonyRtmdGpsSample>) -> Self {
    Self {
      camera,
      gps,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// This sample's camera snapshot.
  #[inline(always)]
  #[must_use]
  pub fn camera(&self) -> &SonyRtmdCameraSnapshot {
    &self.camera
  }

  /// This sample's GPS sample, or `None` when it carried no `0x85xx` record.
  #[inline(always)]
  #[must_use]
  pub fn gps(&self) -> Option<&SonyRtmdGpsSample> {
    self.gps.as_ref()
  }

  /// Family-3 sub-document ordinal (`0` = unstamped / Main).
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> u32 {
    self.doc
  }

  /// Family-1 `Track<N>` index (1-based; `0` = unstamped).
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// Sample-table `SampleTime` (seconds), or `None` until stamped.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// Sample-table `SampleDuration` (seconds), or `None` until stamped.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }
}

// ===========================================================================
// SonyRtmdMeta — the aggregate per-track result
// ===========================================================================

/// The typed result of Sony `rtmd` extraction — the per-format mirror
/// of what `Image::ExifTool::Sony::Process_rtmd` (Sony.pm:11569-11602)
/// would emit for a video's `rtmd` metadata track.
///
/// Each rtmd sample produces ONE [`SonyRtmdSample`] — that sample's
/// [`SonyRtmdCameraSnapshot`] plus, when the sample carried GPS, its
/// [`SonyRtmdGpsSample`]. The samples are in source order; the
/// `MediaMetadata` projection uses the FIRST matching sample for each domain.
///
/// Empty (`is_empty()`) when no rtmd track is present or every sample
/// failed to decode.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct SonyRtmdMeta {
  /// One per rtmd sample (camera + optional GPS, as a correlated unit).
  /// Empty when no rtmd records were decoded.
  samples: Vec<SonyRtmdSample>,
}

impl SonyRtmdMeta {
  /// An empty result (no rtmd data decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      samples: Vec::new(),
    }
  }

  /// One [`SonyRtmdSample`] per rtmd sample, in source order.
  #[inline(always)]
  #[must_use]
  pub fn samples(&self) -> &[SonyRtmdSample] {
    self.samples.as_slice()
  }

  /// `true` when no record was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.samples.is_empty()
  }

  /// The FIRST sample's snapshot that carries REAL identity
  /// ([`SonyRtmdCameraSnapshot::has_identity`]) — the entry that feeds the
  /// [`crate::metadata::CameraInfo`] projection. A present-but-empty
  /// `SerialNumber` sample is SKIPPED so it can't shadow a later valid one.
  /// Falls back to the first sample's snapshot when none carry identity (the
  /// projection gate rejects that fallback, so no bogus `make = "Sony"` lands).
  #[inline]
  #[must_use]
  pub fn first_camera_snapshot(&self) -> Option<&SonyRtmdCameraSnapshot> {
    self
      .samples
      .iter()
      .map(SonyRtmdSample::camera)
      .find(|c| c.has_identity())
      .or_else(|| self.samples.first().map(SonyRtmdSample::camera))
  }

  /// The FIRST GPS sample carrying a coordinate pair — the entry that
  /// feeds the [`crate::metadata::GpsLocation`] projection.
  #[inline]
  #[must_use]
  pub fn first_fix(&self) -> Option<&SonyRtmdGpsSample> {
    self
      .samples
      .iter()
      .filter_map(SonyRtmdSample::gps)
      .find(|g| g.has_coordinates())
  }

  /// The FIRST sample's snapshot whose `f_number` OR `exposure_time_s` OR
  /// the CANONICAL `iso` (`0x810b`) is populated WITH A DOMAIN-PROJECTABLE
  /// (finite, canonical) value — the entry that feeds
  /// [`crate::metadata::CaptureSettings`].
  ///
  /// The capture-bearing predicate requires FINITE exposure / f-number, NOT mere
  /// presence: `exposure_time_s()` (and, defensively, `f_number()`) is an `f64`
  /// that can be NON-FINITE — an `n/0` ExposureTime `rational64u` yields
  /// `Some(+inf)` and `0/0` yields `Some(NaN)` (faithfully surfaced upstream as
  /// the `"inf"`/`"undef"` tag). A NON-FINITE value is dropped by
  /// `project_into`'s `finite_or_none`, so treating a `Some(inf)` exposure as
  /// capture-bearing would SELECT that sample and then project NOTHING from it,
  /// SHADOWING a LATER sample whose finite exposure / f-number / canonical ISO is
  /// the real capture. Gating on `finite_or_none(...)` (mirroring the projection)
  /// keeps the selection in lock-step with what actually projects.
  ///
  /// The `iso` predicate requires [`SonyRtmdCameraSnapshot::iso_from_canonical`]:
  /// a sample carrying ONLY the Hidden+Unknown `0xe301` alt-ISO channel
  /// (`iso().is_some()` but not canonical) must NOT be treated as
  /// capture-bearing, else it would be selected and shadow a LATER sample whose
  /// canonical `0x810b` ISO would otherwise populate `CaptureSettings` (the
  /// projection gates `iso` on `iso_from_canonical()` too, so selecting the
  /// `0xe301`-only sample yields an empty capture and loses the real ISO).
  #[inline]
  #[must_use]
  pub fn first_capture_snapshot(&self) -> Option<&SonyRtmdCameraSnapshot> {
    self.samples.iter().map(SonyRtmdSample::camera).find(|c| {
      finite_or_none(c.exposure_time_s()).is_some()
        || finite_or_none(c.f_number()).is_some()
        || (c.iso().is_some() && c.iso_from_canonical())
    })
  }

  /// The FIRST sample carrying a CANONICAL `0x810b` ISO (`iso_from_canonical()`
  /// true), returned as `(iso, snapshot)`. Scanned INDEPENDENTLY of
  /// [`Self::first_capture_snapshot`]: a MIXED sample that carries exposure
  /// AND only the Hidden `0xe301` alt-ISO is selected by
  /// `first_capture_snapshot` (it has exposure) but projects no ISO (the
  /// alt-ISO is gated); a LATER sample whose canonical `0x810b` ISO is the
  /// real one would then be lost. Projecting the canonical ISO from this
  /// separate scan lets the mixed sample's exposure AND the later sample's
  /// canonical ISO both surface (Sony.pm:10728 canonical vs 10814 `%hidUnk`).
  #[inline]
  #[must_use]
  pub fn first_canonical_iso(&self) -> Option<u32> {
    self
      .samples
      .iter()
      .map(SonyRtmdSample::camera)
      .find(|c| c.iso().is_some() && c.iso_from_canonical())
      .and_then(SonyRtmdCameraSnapshot::iso)
  }

  /// The FIRST FINITE `ExposureTime` across all samples — projected
  /// INDEPENDENTLY of FNumber/ISO (R14): ExifTool surfaces each capture tag
  /// from its own first occurrence, so a sample carrying FNumber but no
  /// ExposureTime must NOT shadow a later sample's valid ExposureTime. A
  /// `Valid(n/0)` = `inf` exposure is skipped (`finite_or_none`).
  #[inline]
  #[must_use]
  pub fn first_finite_exposure_time_s(&self) -> Option<f64> {
    self
      .samples
      .iter()
      .map(SonyRtmdSample::camera)
      .find_map(|c| finite_or_none(c.exposure_time_s()))
  }

  /// The FIRST FINITE `FNumber` across all samples — projected independently
  /// (see [`Self::first_finite_exposure_time_s`]).
  #[inline]
  #[must_use]
  pub fn first_finite_f_number(&self) -> Option<f64> {
    self
      .samples
      .iter()
      .map(SonyRtmdSample::camera)
      .find_map(|c| finite_or_none(c.f_number()))
  }

  /// Append a decoded timed sample (camera + optional GPS).
  #[inline(always)]
  pub fn push_sample(&mut self, sample: SonyRtmdSample) -> &mut Self {
    self.samples.push(sample);
    self
  }

  /// The number of samples decoded so far — a watermark the stream walker
  /// takes BEFORE one `process_rtmd` call so it can stamp the sub-document /
  /// track coordinates onto exactly the samples that call appended (mirrors
  /// [`crate::metadata::CammMeta::gps_sample_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn sample_count(&self) -> usize {
    self.samples.len()
  }

  /// Stamp the family-3 `doc` ordinal AND the sample-table `sample_time` /
  /// `sample_duration` (seconds) onto every sample at or after `start` — the
  /// samples one `process_rtmd` call appended since the walker took its
  /// [`Self::sample_count`] watermark. Mirrors
  /// [`crate::metadata::CammMeta::stamp_gps_doc_from`].
  pub(crate) fn stamp_doc_from(
    &mut self,
    start: usize,
    doc: u32,
    sample_time: Option<f64>,
    sample_duration: Option<f64>,
  ) {
    if let Some(slice) = self.samples.get_mut(start..) {
      for s in slice {
        s.doc = doc;
        s.sample_time = sample_time;
        s.sample_duration = sample_duration;
      }
    }
  }

  /// Stamp the family-1 `track_index` (1-based) onto every sample at or after
  /// `start` — the samples decoded from a single rtmd `trak`. Mirrors
  /// [`crate::metadata::CammMeta::stamp_gps_track_index_from`].
  pub(crate) fn stamp_track_index_from(&mut self, start: usize, track_index: u32) {
    if let Some(slice) = self.samples.get_mut(start..) {
      for s in slice {
        s.track_index = track_index;
      }
    }
  }
}

impl Default for SonyRtmdMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Sony rtmd projection into MediaMetadata (inherent `project_into`, merged by
// `QuickTimeMeta`'s `Project` impl — mirrors `CammMeta`/`GoProMeta`).
// ===========================================================================

impl SonyRtmdMeta {
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
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    // ── CameraInfo ─────────────────────────────────────────────────────
    // Project the make/model/serial ONLY when the selected snapshot carries
    // REAL identity — a parsed `model`/`serial`, OR a non-empty (trimmed)
    // composite `SerialNumber`. A present-but-EMPTY `SerialNumber` (the `""` a
    // zero-length / leading-NUL `0x8114` record emits — faithfully surfaced as a
    // tag) carries no identity: projecting it would yield a misleading
    // `make = "Sony"` with no model/serial, a bogus identity that must not
    // poison the domain. `parse_model_serial` already returns `(None, None)` for
    // an empty / no-space / multi-space composite, so an empty composite reaches
    // here with `model`/`serial` both `None`; the trimmed-non-empty check inside
    // `has_identity` is what additionally rejects the `""` / whitespace-only case
    // (and rejects the no-identity fallback `first_camera_snapshot` may return).
    if md.camera().is_none()
      && let Some(snap) = self.first_camera_snapshot()
      && snap.has_identity()
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
    // Exposure / FNumber come from the FIRST capture-bearing snapshot; the
    // canonical `0x810b` ISO is scanned INDEPENDENTLY (see
    // [`Self::first_canonical_iso`]). Decoupling the two means a MIXED sample
    // (exposure + a Hidden `0xe301` alt-ISO) projects its exposure WHILE a
    // LATER sample's canonical `0x810b` ISO still projects — the alt-ISO is
    // never promoted (ExifTool hides `0xe301` from `Sony:ISO`, Sony.pm:10814
    // `%hidUnk`), but the real ISO is no longer shadowed/lost.
    if md.capture().is_none() {
      // Project each capture field from its OWN first-valid source.
      // ExifTool surfaces each tag independently (per tag name), so a sample
      // carrying FNumber but NO ExposureTime must NOT shadow a LATER sample's
      // valid ExposureTime — the prior single-`first_capture_snapshot()`
      // projection took exposure+FNumber from one snapshot and silently lost a
      // field that first appeared in a different sample. A non-finite value
      // (`+inf`/`NaN` from an `n/0`/`0/0` ExposureTime rational, faithfully
      // emitted upstream as `"inf"`/`"undef"`) NEVER reaches the domain — the
      // `first_finite_*` finders use `finite_or_none`; canonical ISO is gated.
      let exposure = self.first_finite_exposure_time_s();
      let f_number = self.first_finite_f_number();
      let canonical_iso = self.first_canonical_iso();
      if exposure.is_some() || f_number.is_some() || canonical_iso.is_some() {
        let mut cap = CaptureSettings::new();
        cap.update_exposure_time_s(exposure);
        cap.update_f_number(f_number);
        cap.update_iso(canonical_iso);
        if !cap.is_empty() {
          md.set_capture(cap);
        }
      }
    }
    // ── GpsLocation ────────────────────────────────────────────────────
    if md.gps().is_none()
      && let Some(s) = self.first_fix()
    {
      // `first_fix` already guarantees BOTH coordinates are a finite
      // `SonyRtmdCoord::Value` (`has_coordinates`), so the `.value()`
      // extraction never folds an `Empty` (defined-but-bogus `""`) coordinate
      // into the domain. `combine_date_time` likewise drops a bogus
      // `"Inf:NaN:…"` timestamp (it is not a valid `HH:MM:SS`).
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(s.latitude().and_then(SonyRtmdCoord::value))
        .update_longitude(s.longitude().and_then(SonyRtmdCoord::value))
        // Sony rtmd never carries altitude (no `0x8506` in Sony.pm).
        .update_altitude_m(None)
        .update_timestamp(combine_date_time(s.date_stamp(), s.time_stamp()));
      md.set_gps(gps);
    }
  }
}

/// Pass a finite `f64` through; map a NON-FINITE one (`±inf` / `NaN`) to `None`.
/// Gates the `CaptureSettings` exposure / f-number inputs so a faithfully-emitted
/// non-finite value (an `n/0` / `0/0` `rational64u` rendered `"inf"`/`"undef"`
/// upstream) can never poison the cross-format domain, which consumes these
/// accessors as real numbers.
fn finite_or_none(v: Option<f64>) -> Option<f64> {
  v.filter(|x| x.is_finite())
}

/// Combine `GPSDateStamp` (`"YYYY:MM:DD"`) and `GPSTimeStamp`
/// (`"HH:MM:SS"`) into the Exif-canonical `"YYYY:MM:DD HH:MM:SS"` form for
/// [`GpsLocation::timestamp`]. Returns `None` when both are absent; uses
/// whichever of the two is present when only one is. Mirrors how ExifTool's
/// `GPSDateTime` Composite tag is assembled (Exif.pm Composite table —
/// `GPSDateStamp` + `GPSTimeStamp` joined by a single space).
///
/// A BOGUS `GPSTimeStamp` — the `"Inf:NaN:000000000NaN"` string `GPS::
/// ConvertTimeStamp` emits for an `inf` (`n/0`) H/M/S component — is NOT a
/// valid `HH:MM:SS` and must NOT poison the domain timestamp; it is treated as
/// absent here (the faithful tag still emits the bogus value upstream).
/// Likewise a present-but-empty or non-`YYYY:MM:DD` `GPSDateStamp` (a DEFINED
/// Sony rtmd string that is not a real date — e.g. the `""` an empty/leading-NUL
/// record emits) is treated as absent, so it never corrupts the domain
/// timestamp into a leading-space `" HH:MM:SS"` (the faithful `GPSDateStamp` tag
/// still emits the empty value upstream).
fn combine_date_time(date: Option<&str>, time: Option<&str>) -> Option<alloc::string::String> {
  let date = date.filter(|d| is_valid_gps_date(d));
  let time = time.filter(|t| is_valid_time_of_day(t));
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

/// `true` when `t` is EXACTLY a `HH:MM:SS` time-of-day (two digits, `:`, two
/// digits, `:`, two digits) OPTIONALLY followed by a `.`-prefixed fractional
/// tail of one-or-more digits — the canonical `GPS::ConvertTimeStamp` output
/// shape (GPS.pm:459-474, `sprintf("%.2d:%.2d:%s")` with the seconds field
/// either `SS` or `SS.ddd…`). Used to exclude the bogus
/// `"Inf:NaN:000000000NaN"` timestamp — AND any OTHER malformed value that
/// merely OPENS with a valid head but carries trailing garbage (e.g. a faithful
/// `"11:19:15junk"`) — from the `GpsLocation` domain combine, so a defined-but-
/// malformed `GPSTimeStamp` can never poison the domain timestamp.
fn is_valid_time_of_day(t: &str) -> bool {
  let b = t.as_bytes();
  // `HH:MM:SS` is exactly 8 leading bytes; anything shorter cannot match.
  let head = matches!(b.first(), Some(c) if c.is_ascii_digit())
    && matches!(b.get(1), Some(c) if c.is_ascii_digit())
    && b.get(2) == Some(&b':')
    && matches!(b.get(3), Some(c) if c.is_ascii_digit())
    && matches!(b.get(4), Some(c) if c.is_ascii_digit())
    && b.get(5) == Some(&b':')
    && matches!(b.get(6), Some(c) if c.is_ascii_digit())
    && matches!(b.get(7), Some(c) if c.is_ascii_digit());
  if !head {
    return false;
  }
  // The ONLY permitted trailing bytes are a `ConvertTimeStamp` fractional
  // seconds tail: a single `.` followed by one-or-more digits. EXACTLY
  // `HH:MM:SS` (no tail) is also valid. Any other trailing byte ⇒ malformed.
  is_fractional_tail(b.get(8..))
}

/// `true` for the tail of a valid `ConvertTimeStamp` seconds field: either
/// EMPTY (a bare `HH:MM:SS`), or a `.` followed by one-or-more ASCII digits and
/// NOTHING else (`HH:MM:SS.ddd…`). Rejects a lone `.`, a non-`.` lead, or any
/// trailing non-digit.
fn is_fractional_tail(tail: Option<&[u8]>) -> bool {
  match tail {
    None | Some([]) => true,
    Some([b'.', rest @ ..]) => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
    Some(_) => false,
  }
}

/// `true` when `d` is EXACTLY a `YYYY:MM:DD` date (four digits, `:`, two digits,
/// `:`, two digits — length 10, NO trailing bytes) — the canonical
/// `Exif::ExifDate` `GPSDateStamp` shape. Used to exclude a present-but-empty or
/// otherwise malformed `GPSDateStamp` (e.g. the `""` an empty/leading-NUL record
/// emits, or a faithful `"2024:01:07junk"` with trailing garbage) from the
/// `GpsLocation` domain combine, so it never produces a corrupted
/// `"<date>junk HH:MM:SS"` / leading-space `" HH:MM:SS"` timestamp. The
/// length-10 exactness is what distinguishes this from a PREFIX check: a
/// trailing-garbage date must be treated as absent, not silently accepted.
fn is_valid_gps_date(d: &str) -> bool {
  let b = d.as_bytes();
  b.len() == 10
    && matches!(b.first(), Some(c) if c.is_ascii_digit())
    && matches!(b.get(1), Some(c) if c.is_ascii_digit())
    && matches!(b.get(2), Some(c) if c.is_ascii_digit())
    && matches!(b.get(3), Some(c) if c.is_ascii_digit())
    && b.get(4) == Some(&b':')
    && matches!(b.get(5), Some(c) if c.is_ascii_digit())
    && matches!(b.get(6), Some(c) if c.is_ascii_digit())
    && b.get(7) == Some(&b':')
    && matches!(b.get(8), Some(c) if c.is_ascii_digit())
    && matches!(b.get(9), Some(c) if c.is_ascii_digit())
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
    assert!(m.samples().is_empty());
    assert!(m.first_camera_snapshot().is_none());
    assert!(m.first_fix().is_none());
    assert!(m.first_capture_snapshot().is_none());
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
    // First sample: only F-number (no identity).
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_f_number(Some(NumericRead::Valid(2.8)));
    m.push_sample(SonyRtmdSample::new(a, None));
    // Second sample: carries serial composite.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_serial_number(Some(SmolStr::new("ILCE-7SM3 12345")));
    m.push_sample(SonyRtmdSample::new(b, None));
    let first = m.first_camera_snapshot().expect("found");
    assert_eq!(first.model(), Some("ILCE-7SM3"));
  }

  #[test]
  fn project_into_skips_iso_from_alt_0xe301_channel() {
    // A snapshot whose ISO came ONLY from the Hidden `0xe301` channel
    // (iso_from_canonical = false) must NOT populate `md.capture().iso()` —
    // ExifTool never surfaces ISO from `0xe301` (Sony.pm:10814 `%hidUnk`).
    // The other capture fields (exposure) still project, so `md.capture()`
    // is set but its ISO stays None.
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 250)))); // 0.004 s
    snap.set_iso(Some(NumericRead::Valid(12800))); // from 0xe301 — iso_from_canonical left false
    assert!(!snap.iso_from_canonical());
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture populated from exposure");
    assert_eq!(cap.exposure_time_s(), Some(0.004));
    assert!(
      cap.iso().is_none(),
      "ISO from the 0xe301 alt channel must not project"
    );
  }

  #[test]
  fn project_into_keeps_iso_from_canonical_0x810b() {
    // The canonical `0x810b` ISO (iso_from_canonical = true) DOES project.
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_iso(Some(NumericRead::Valid(800)));
    snap.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture populated from canonical ISO");
    assert_eq!(cap.iso(), Some(800));
  }

  #[test]
  fn first_capture_skips_alt_iso_only_sample_for_later_canonical() {
    // A sample carrying ONLY the Hidden `0xe301` alt-ISO (no
    // f_number, no exposure, iso_from_canonical = false) must NOT be selected as
    // the capture snapshot — selecting it would project an empty capture (the
    // projection gates ISO on canonical) and SHADOW a LATER sample whose
    // canonical `0x810b` ISO is the real one. The predicate gates the `iso`
    // term on `iso_from_canonical()`.
    let mut m = SonyRtmdMeta::new();
    // Sample 0: ONLY a hidden `0xe301` ISO (not canonical) — must be skipped.
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_iso(Some(NumericRead::Valid(12800)));
    assert!(!a.iso_from_canonical());
    m.push_sample(SonyRtmdSample::new(a, None));
    // Sample 1: the canonical `0x810b` ISO.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_iso(Some(NumericRead::Valid(800)));
    b.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(b, None));
    let cap = m
      .first_capture_snapshot()
      .expect("the canonical-ISO sample is selected, not the alt-ISO-only one");
    assert_eq!(cap.iso(), Some(800));
    assert!(cap.iso_from_canonical());
    // The projection surfaces the canonical ISO (not shadowed/lost).
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.capture().and_then(|c| c.iso()), Some(800));
  }

  #[test]
  fn project_into_mixed_exposure_alt_iso_then_later_canonical_iso() {
    // Sample 0 carries exposure AND a Hidden `0xe301`
    // alt-ISO (iso_from_canonical = false) — `first_capture_snapshot` selects
    // it (it has exposure) but the alt-ISO must NOT project; sample 1 carries
    // the canonical `0x810b` ISO. The projection must surface BOTH the
    // exposure (from sample 0) AND ISO = the canonical value (from sample 1).
    let mut m = SonyRtmdMeta::new();
    // Sample 0: exposure + hidden 0xe301 ISO (alt channel, not canonical).
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 250)))); // 0.004 s
    a.set_iso(Some(NumericRead::Valid(12800))); // from 0xe301 — iso_from_canonical left false
    assert!(!a.iso_from_canonical());
    m.push_sample(SonyRtmdSample::new(a, None));
    // Sample 1: the canonical `0x810b` ISO.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_iso(Some(NumericRead::Valid(640)));
    b.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(b, None));

    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture populated");
    assert_eq!(
      cap.exposure_time_s(),
      Some(0.004),
      "exposure projects from the mixed sample 0"
    );
    assert_eq!(
      cap.iso(),
      Some(640),
      "canonical ISO projects from the later sample 1, not the alt-ISO"
    );
  }

  #[test]
  fn meta_first_capture_picks_first_with_exposure() {
    let mut m = SonyRtmdMeta::new();
    // Sample 0: identity only.
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_serial_number(Some(SmolStr::new("ILCE-7M4 1")));
    m.push_sample(SonyRtmdSample::new(a, None));
    // Sample 1: exposure-bearing.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 250)))); // 0.004 s
    b.set_iso(Some(NumericRead::Valid(800)));
    m.push_sample(SonyRtmdSample::new(b, None));
    let cap = m.first_capture_snapshot().expect("found");
    assert_eq!(cap.exposure_time_s(), Some(0.004));
    assert_eq!(cap.iso(), Some(800));
  }

  #[test]
  fn gps_sample_has_coordinates_requires_both() {
    let mut g = SonyRtmdGpsSample::new();
    assert!(!g.has_coordinates());
    g.set_latitude(Some(SonyRtmdCoord::Value(37.5)));
    assert!(!g.has_coordinates());
    g.set_longitude(Some(SonyRtmdCoord::Value(-122.0)));
    assert!(g.has_coordinates());
  }

  #[test]
  fn gps_sample_has_coordinates_false_when_either_is_empty() {
    // A present-empty (`SonyRtmdCoord::Empty`) coordinate — `GPS::ToDegrees`
    // `""` for an inf/undef component — is a DEFINED-but-bogus value that must
    // NOT count as a fix (it must not poison the `GpsLocation` projection).
    let mut g = SonyRtmdGpsSample::new();
    g.set_latitude(Some(SonyRtmdCoord::Empty));
    g.set_longitude(Some(SonyRtmdCoord::Value(-122.0)));
    assert!(!g.has_coordinates(), "an Empty latitude is not a fix");
    g.set_latitude(Some(SonyRtmdCoord::Value(37.5)));
    g.set_longitude(Some(SonyRtmdCoord::Empty));
    assert!(!g.has_coordinates(), "an Empty longitude is not a fix");
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
  }

  #[test]
  fn project_into_populates_camera_make_sony_and_model_from_serial_number() {
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108")));
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cam = md.camera().expect("camera populated");
    assert_eq!(cam.make(), Some("Sony"));
    assert_eq!(cam.model(), Some("ILCE-7SM3"));
    assert_eq!(cam.serial(), Some("5072108"));
  }

  #[test]
  fn sample_new_defaults_are_unstamped() {
    let snap = SonyRtmdCameraSnapshot::new();
    let s = SonyRtmdSample::new(snap, None);
    assert_eq!(s.doc(), 0);
    assert_eq!(s.track_index(), 0);
    assert!(s.sample_time().is_none());
    assert!(s.sample_duration().is_none());
    assert!(s.gps().is_none());
    assert!(s.camera().is_empty());
  }

  #[test]
  fn stamp_doc_and_track_index_apply_from_watermark() {
    let mut m = SonyRtmdMeta::new();
    // Sample 0 pushed before the watermark must stay unstamped.
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), None));
    let start = m.sample_count();
    assert_eq!(start, 1);
    // Sample 1 pushed after the watermark gets stamped.
    let mut gps = SonyRtmdGpsSample::new();
    gps
      .set_latitude(Some(SonyRtmdCoord::Value(1.0)))
      .set_longitude(Some(SonyRtmdCoord::Value(2.0)));
    m.push_sample(SonyRtmdSample::new(
      SonyRtmdCameraSnapshot::new(),
      Some(gps),
    ));
    m.stamp_doc_from(start, 7, Some(1.5), Some(0.5));
    m.stamp_track_index_from(start, 3);

    // Sample 0 untouched.
    assert_eq!(m.samples()[0].doc(), 0);
    assert_eq!(m.samples()[0].track_index(), 0);
    assert!(m.samples()[0].sample_time().is_none());
    // Sample 1 stamped.
    assert_eq!(m.samples()[1].doc(), 7);
    assert_eq!(m.samples()[1].track_index(), 3);
    assert_eq!(m.samples()[1].sample_time(), Some(1.5));
    assert_eq!(m.samples()[1].sample_duration(), Some(0.5));
    assert!(m.samples()[1].gps().is_some());
  }

  #[test]
  fn first_fix_skips_samples_without_coordinates() {
    let mut m = SonyRtmdMeta::new();
    // Sample with GPS but no coordinates ⇒ skipped by first_fix.
    let mut g0 = SonyRtmdGpsSample::new();
    g0.set_latitude(Some(SonyRtmdCoord::Value(10.0))); // longitude missing ⇒ no pair
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g0)));
    // Sample with a full coordinate pair ⇒ the one first_fix returns.
    let mut g1 = SonyRtmdGpsSample::new();
    g1.set_latitude(Some(SonyRtmdCoord::Value(37.0)))
      .set_longitude(Some(SonyRtmdCoord::Value(-122.0)));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g1)));
    let fix = m.first_fix().expect("a fix with coordinates");
    assert_eq!(fix.latitude(), Some(SonyRtmdCoord::Value(37.0)));
    assert_eq!(fix.longitude(), Some(SonyRtmdCoord::Value(-122.0)));
  }

  #[test]
  fn first_fix_skips_present_empty_coordinate_sample() {
    // A sample whose lat/lon are PRESENT-but-empty (`SonyRtmdCoord::Empty`,
    // the `GPS::ToDegrees` `""` render for an inf/undef component) is NOT a fix
    // — `first_fix` must skip it for a sibling sample carrying a finite pair, so
    // the bogus value never reaches `GpsLocation`.
    let mut m = SonyRtmdMeta::new();
    let mut g0 = SonyRtmdGpsSample::new();
    g0.set_latitude(Some(SonyRtmdCoord::Empty))
      .set_longitude(Some(SonyRtmdCoord::Value(-122.0)));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g0)));
    let mut g1 = SonyRtmdGpsSample::new();
    g1.set_latitude(Some(SonyRtmdCoord::Value(37.0)))
      .set_longitude(Some(SonyRtmdCoord::Value(-122.0)));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g1)));
    let fix = m.first_fix().expect("the finite sibling fix");
    assert_eq!(fix.latitude(), Some(SonyRtmdCoord::Value(37.0)));

    // And the projection populates `md.gps()` from the finite sibling, never
    // the Empty sample.
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let g = md.gps().expect("gps populated from the finite sibling");
    assert!((g.latitude().expect("lat") - 37.0).abs() < 1e-9);
  }

  #[test]
  fn project_into_not_poisoned_by_empty_coordinate_or_bogus_timestamp() {
    // A LONE sample carrying ONLY an Empty coordinate + the bogus
    // `"Inf:NaN:000000000NaN"` timestamp must NOT populate `md.gps()` — the
    // Empty coordinate is not a fix and the bogus timestamp is not a valid
    // `HH:MM:SS`.
    let mut m = SonyRtmdMeta::new();
    let mut g = SonyRtmdGpsSample::new();
    g.set_latitude(Some(SonyRtmdCoord::Empty))
      .set_longitude(Some(SonyRtmdCoord::Empty))
      .set_time_stamp(Some(SmolStr::new("Inf:NaN:000000000NaN")))
      .set_date_stamp(Some(SmolStr::new("2024:01:07")));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g)));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(
      md.gps().is_none(),
      "an Empty-coordinate / bogus-timestamp sample must not populate the domain"
    );
  }

  #[test]
  fn project_into_finite_coords_with_present_empty_date_keeps_valid_time_only() {
    // A sample with FINITE coordinates (a real fix) + a valid
    // `GPSTimeStamp` + a present-empty `GPSDateStamp` (`""`) DOES populate
    // `md.gps()`, but its timestamp must be the valid TIME ALONE — the empty
    // date must NOT corrupt it into a leading-space `" 11:19:15"`.
    let mut m = SonyRtmdMeta::new();
    let mut g = SonyRtmdGpsSample::new();
    g.set_latitude(Some(SonyRtmdCoord::Value(47.6)))
      .set_longitude(Some(SonyRtmdCoord::Value(-122.1)))
      .set_time_stamp(Some(SmolStr::new("11:19:15")))
      .set_date_stamp(Some(SmolStr::new("")));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g)));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let gps = md
      .gps()
      .expect("finite coordinates populate the domain fix");
    assert_eq!(
      gps.timestamp(),
      Some("11:19:15"),
      "present-empty GPSDateStamp must not corrupt the domain timestamp"
    );
  }

  #[test]
  fn combine_date_time_excludes_bogus_inf_nan_timestamp() {
    // The bogus `"Inf:NaN:000000000NaN"` timestamp is not a valid `HH:MM:SS`
    // and must be treated as absent in the domain combine; a present DateStamp
    // still survives on its own.
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("Inf:NaN:000000000NaN")).as_deref(),
      Some("2024:01:07"),
      "bogus timestamp dropped, date kept"
    );
    assert_eq!(
      combine_date_time(None, Some("Inf:NaN:000000000NaN")),
      None,
      "a lone bogus timestamp yields no domain timestamp"
    );
    // A valid timestamp still combines.
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("11:19:15")).as_deref(),
      Some("2024:01:07 11:19:15")
    );
    // A fractional-seconds tail is still valid.
    assert_eq!(
      combine_date_time(None, Some("11:19:15.5")).as_deref(),
      Some("11:19:15.5")
    );
  }

  #[test]
  fn combine_date_time_excludes_present_empty_or_malformed_date() {
    // A present-but-empty `GPSDateStamp` (`""`, the defined value an
    // empty/leading-NUL record emits) plus a VALID time must NOT corrupt the
    // domain timestamp into a leading-space `" 11:19:15"` — the empty date is
    // treated as absent, so only the time survives.
    assert_eq!(
      combine_date_time(Some(""), Some("11:19:15")).as_deref(),
      Some("11:19:15"),
      "present-empty date dropped, time kept (no leading space)"
    );
    // An empty date with no valid time yields nothing (not `Some("")`).
    assert_eq!(combine_date_time(Some(""), None), None);
    assert_eq!(
      combine_date_time(Some(""), Some("Inf:NaN:000000000NaN")),
      None
    );
    // A non-`YYYY:MM:DD` date string is likewise treated as absent.
    assert_eq!(
      combine_date_time(Some("garbage"), Some("11:19:15")).as_deref(),
      Some("11:19:15")
    );
    // A valid `YYYY:MM:DD` date still combines (regression).
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("11:19:15")).as_deref(),
      Some("2024:01:07 11:19:15")
    );
    assert_eq!(
      combine_date_time(Some("2024:01:07"), None).as_deref(),
      Some("2024:01:07")
    );
  }

  #[test]
  fn combine_date_time_rejects_trailing_garbage_exact_shapes() {
    // The date/time validators are EXACT-shape, NOT
    // prefix-only. A faithfully-emitted-but-malformed value that merely OPENS
    // with a valid head but carries trailing garbage must be treated as absent
    // — it must NEVER poison the domain `combine_date_time`.
    //
    // A trailing-junk DATE (`"2024:01:07junk"` — was accepted by the old
    // prefix-only 10-byte check) is dropped; the valid time survives ALONE (no
    // `"2024:01:07junk 11:19:15"` poisoning).
    assert_eq!(
      combine_date_time(Some("2024:01:07junk"), Some("11:19:15")).as_deref(),
      Some("11:19:15"),
      "trailing-garbage date dropped, time kept"
    );
    // A trailing-junk TIME (`"11:19:15junk"`) is dropped; the valid date
    // survives ALONE (the malformed time must NOT be appended).
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("11:19:15junk")).as_deref(),
      Some("2024:01:07"),
      "trailing-garbage time dropped, date kept"
    );
    // BOTH malformed ⇒ nothing.
    assert_eq!(
      combine_date_time(Some("2024:01:07junk"), Some("11:19:15junk")),
      None
    );
    // The valid fractional-seconds tail (`HH:MM:SS.ddd…`) is STILL accepted
    // (the `ConvertTimeStamp` form) — only NON-fractional trailing bytes reject.
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("11:19:15.123456")).as_deref(),
      Some("2024:01:07 11:19:15.123456")
    );
    // A lone trailing `.` (no fractional digits) is malformed ⇒ time dropped.
    assert_eq!(
      combine_date_time(Some("2024:01:07"), Some("11:19:15.")).as_deref(),
      Some("2024:01:07"),
      "a bare trailing dot is not a valid fractional tail"
    );
    // A date with trailing whitespace is also exact-shape-rejected.
    assert_eq!(
      combine_date_time(Some("2024:01:07 "), Some("11:19:15")).as_deref(),
      Some("11:19:15")
    );
  }

  #[test]
  fn project_into_finite_coords_with_trailing_junk_date_keeps_time_only() {
    // A real fix (FINITE coords) + a valid `GPSTimeStamp`
    // + a TRAILING-GARBAGE `GPSDateStamp` (`"2024:01:07junk"`, a faithfully
    // surfaced malformed value) DOES populate `md.gps()`, but its timestamp must
    // be the valid TIME ALONE — the malformed date must NOT corrupt it into
    // `"2024:01:07junk 11:19:15"`.
    let mut m = SonyRtmdMeta::new();
    let mut g = SonyRtmdGpsSample::new();
    g.set_latitude(Some(SonyRtmdCoord::Value(47.6)))
      .set_longitude(Some(SonyRtmdCoord::Value(-122.1)))
      .set_time_stamp(Some(SmolStr::new("11:19:15")))
      .set_date_stamp(Some(SmolStr::new("2024:01:07junk")));
    m.push_sample(SonyRtmdSample::new(SonyRtmdCameraSnapshot::new(), Some(g)));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let gps = md
      .gps()
      .expect("finite coordinates populate the domain fix");
    assert_eq!(
      gps.timestamp(),
      Some("11:19:15"),
      "trailing-garbage GPSDateStamp must not corrupt the domain timestamp"
    );
  }

  #[test]
  fn project_into_skips_non_finite_exposure_and_f_number() {
    // `CaptureSettings` exposure / f-number
    // are `f64` that can be NON-FINITE (an `n/0` ExposureTime `rational64u` →
    // `+inf`; `0/0` → `NaN`; faithfully emitted upstream as the `"inf"`/`"undef"`
    // tag). A non-finite value must NEVER reach the domain. A LONE sample whose
    // ONLY capture signal is a non-finite exposure must yield NO `md.capture()`.
    for r in [
      Rational::rational64(1, 0), // n/0 → +inf
      Rational::rational64(0, 0), // 0/0 → NaN
    ] {
      let mut m = SonyRtmdMeta::new();
      let mut snap = SonyRtmdCameraSnapshot::new();
      snap.set_exposure_time(Some(NumericRead::Valid(r)));
      assert!(!snap.exposure_time_s().expect("present").is_finite());
      m.push_sample(SonyRtmdSample::new(snap, None));
      let mut md = MediaMetadata::new();
      m.project_into(&mut md);
      assert!(
        md.capture().is_none(),
        "a non-finite exposure ({r:?}) is the only capture signal ⇒ no capture"
      );
    }
  }

  #[test]
  fn project_into_drops_non_finite_exposure_but_keeps_finite_siblings() {
    // A sample carrying a non-finite exposure AND a finite f-number + canonical
    // ISO projects `md.capture()` WITHOUT the non-finite exposure (it is dropped
    // to `None`), while the finite f-number and ISO survive.
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 0)))); // +inf → dropped
    snap.set_f_number(Some(NumericRead::Valid(4.0))); // finite → kept
    snap.set_iso(Some(NumericRead::Valid(800)));
    snap.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md
      .capture()
      .expect("finite f-number / ISO populate capture");
    assert!(
      cap.exposure_time_s().is_none(),
      "the non-finite exposure must be dropped from the domain"
    );
    assert_eq!(cap.f_number(), Some(4.0));
    assert_eq!(cap.iso(), Some(800));
  }

  #[test]
  fn project_into_present_empty_serial_number_yields_no_camera() {
    // A PRESENT-but-EMPTY `SerialNumber`
    // (the `""` a zero-length / leading-NUL `0x8114` record emits, now a defined
    // tag) carries no identity. Projecting it would yield a bogus
    // `make = "Sony"` with no model/serial — that misleading identity must NOT
    // reach the domain. (The faithful empty `SerialNumber` tag still emits
    // upstream; only the domain projection is gated.)
    for serial in ["", "   ", "\0"] {
      let mut m = SonyRtmdMeta::new();
      let mut snap = SonyRtmdCameraSnapshot::new();
      snap.set_serial_number(Some(SmolStr::new(serial)));
      // The empty composite is a present tag (returned by first_camera_snapshot
      // only as the no-identity fallback) but parses to no model/serial.
      assert!(snap.model().is_none() && snap.serial().is_none());
      m.push_sample(SonyRtmdSample::new(snap, None));
      let mut md = MediaMetadata::new();
      m.project_into(&mut md);
      assert!(
        md.camera().is_none(),
        "an empty/whitespace SerialNumber ({serial:?}) must not produce a Sony-only CameraInfo"
      );
    }
  }

  #[test]
  fn project_into_no_space_serial_still_projects_make_sony() {
    // Regression: a non-empty no-space composite (`"ILCE7SM3"`) parses to no
    // model/serial but IS real identity data — it must STILL project
    // `make = "Sony"` (the trimmed-non-empty guard accepts it). This pins that
    // the empty-serial guard above does NOT over-reach to a legitimate composite.
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_serial_number(Some(SmolStr::new("ILCE7SM3")));
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cam = md
      .camera()
      .expect("a non-empty composite projects make=Sony");
    assert_eq!(cam.make(), Some("Sony"));
    assert!(cam.model().is_none());
    assert!(cam.serial().is_none());
  }

  #[test]
  fn project_into_empty_serial_first_does_not_shadow_later_valid_identity() {
    // A PRESENT-but-EMPTY `SerialNumber` first sample must
    // NOT shadow a LATER sample that carries real identity. The selector
    // (`first_camera_snapshot`) and the projection gate now share the
    // `has_identity` predicate, so the empty-serial sample is skipped and the
    // real `ILCE-7SM3 5072108` second sample projects. (With the old
    // `serial_number().is_some()` selector the empty sample was picked, the gate
    // rejected it, and the real identity was silently lost.)
    let mut m = SonyRtmdMeta::new();
    let mut empty = SonyRtmdCameraSnapshot::new();
    empty.set_serial_number(Some(SmolStr::new("")));
    m.push_sample(SonyRtmdSample::new(empty, None));
    let mut real = SonyRtmdCameraSnapshot::new();
    real.set_serial_number(Some(SmolStr::new("ILCE-7SM3 5072108")));
    m.push_sample(SonyRtmdSample::new(real, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cam = md
      .camera()
      .expect("later real identity must project, not be shadowed by empty serial");
    assert_eq!(cam.make(), Some("Sony"));
    assert_eq!(cam.model(), Some("ILCE-7SM3"));
    assert_eq!(cam.serial(), Some("5072108"));
  }

  // ── NumericRead accessors + domain isolation ───────────────────────────────

  #[test]
  fn numeric_read_value_unwraps_valid_drops_empty_read() {
    // The generic `value()` accessor — the domain consumer — returns the typed
    // value for `Valid` and `None` for `EmptyRead`, so a degenerate present-empty
    // numeric never reaches the cross-format layer.
    assert_eq!(NumericRead::Valid(4.0_f64).value(), Some(4.0));
    assert_eq!(NumericRead::<f64>::EmptyRead.value(), None);
    assert!(NumericRead::Valid(800_u32).is_valid());
    assert!(!NumericRead::Valid(800_u32).is_empty_read());
    assert!(NumericRead::<u32>::EmptyRead.is_empty_read());
    assert!(!NumericRead::<u32>::EmptyRead.is_valid());
  }

  #[test]
  fn snapshot_numeric_accessors_expose_valid_only_to_domain() {
    // The snapshot's domain accessors (`f_number`/`iso`/`exposure_time_s`/…)
    // surface a `Valid` read but DROP an `EmptyRead` to `None`; the `*_read`
    // accessors surface the full state for the emission.
    let mut s = SonyRtmdCameraSnapshot::new();
    // Valid FNumber → domain sees it; *_read carries Valid.
    s.set_f_number(Some(NumericRead::Valid(2.8)));
    assert_eq!(s.f_number(), Some(2.8));
    assert_eq!(s.f_number_read(), Some(NumericRead::Valid(2.8)));
    // EmptyRead FNumber → domain sees None; *_read carries EmptyRead.
    s.set_f_number(Some(NumericRead::EmptyRead));
    assert_eq!(
      s.f_number(),
      None,
      "EmptyRead FNumber is hidden from the domain"
    );
    assert_eq!(s.f_number_read(), Some(NumericRead::EmptyRead));
    // Absent FNumber → both None.
    s.set_f_number(None);
    assert_eq!(s.f_number(), None);
    assert_eq!(s.f_number_read(), None);

    // Same contract for the other numeric fields.
    let mut s = SonyRtmdCameraSnapshot::new();
    s.set_exposure_time(Some(NumericRead::EmptyRead));
    s.set_frame_rate(Some(NumericRead::EmptyRead));
    s.set_master_gain_db(Some(NumericRead::EmptyRead));
    s.set_iso(Some(NumericRead::EmptyRead));
    s.set_electrical_extender_magnification(Some(NumericRead::EmptyRead));
    assert_eq!(s.exposure_time_s(), None);
    assert_eq!(s.exposure_time_rational(), None);
    assert_eq!(s.frame_rate(), None);
    assert_eq!(s.frame_rate_rational(), None);
    assert_eq!(s.master_gain_db(), None);
    assert_eq!(s.iso(), None);
    assert_eq!(s.electrical_extender_magnification(), None);
    // …but every `*_read` carries the EmptyRead (so the emission can render it).
    assert_eq!(s.exposure_time_read(), Some(NumericRead::EmptyRead));
    assert_eq!(s.frame_rate_read(), Some(NumericRead::EmptyRead));
    assert_eq!(s.master_gain_db_read(), Some(NumericRead::EmptyRead));
    assert_eq!(s.iso_read(), Some(NumericRead::EmptyRead));
    assert_eq!(
      s.electrical_extender_magnification_read(),
      Some(NumericRead::EmptyRead)
    );
    // A snapshot carrying ONLY EmptyRead numerics is NOT `is_empty` (the records
    // were present), but carries no domain-visible value.
    assert!(!s.is_empty());
  }

  #[test]
  fn project_into_empty_read_numerics_do_not_populate_capture() {
    // A LONE sample whose ONLY capture signals are PRESENT-but-sub-width
    // (`EmptyRead`) numerics must yield NO `md.capture()` — the degenerate reads
    // are hidden from the domain accessors, so the projection sees nothing to
    // populate. (The faithful empty-read tags still emit upstream; only the
    // domain is isolated.)
    let mut m = SonyRtmdMeta::new();
    let mut snap = SonyRtmdCameraSnapshot::new();
    snap.set_f_number(Some(NumericRead::EmptyRead));
    snap.set_exposure_time(Some(NumericRead::EmptyRead));
    snap.set_master_gain_db(Some(NumericRead::EmptyRead));
    snap.set_frame_rate(Some(NumericRead::EmptyRead));
    snap.set_electrical_extender_magnification(Some(NumericRead::EmptyRead));
    // An EmptyRead canonical ISO: marker set (it WOULD emit `Sony:ISO ""`) but
    // the domain ISO is gated on a VALID read, so it must not project either.
    snap.set_iso(Some(NumericRead::EmptyRead));
    snap.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(snap, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(
      md.capture().is_none(),
      "present-empty numerics must not reach CaptureSettings"
    );
  }

  #[test]
  fn first_capture_skips_non_finite_exposure_for_later_valid_capture() {
    // Sample 0's ONLY capture signal is a NON-FINITE
    // ExposureTime (`1/0` → `Some(+inf)`). The old predicate treated
    // `exposure_time_s().is_some()` as capture-bearing, SELECTING sample 0 — but
    // `project_into`'s `finite_or_none` then drops the +inf, so the sample
    // projects NOTHING and SHADOWS sample 1's valid capture. The FINITE-gated
    // predicate skips sample 0, so `md.capture()` reflects sample 1's real
    // ExposureTime / FNumber.
    let mut m = SonyRtmdMeta::new();
    // Sample 0: ONLY a non-finite (n/0) exposure — no other capture signal.
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 0)))); // +inf
    assert!(!a.exposure_time_s().expect("present").is_finite());
    m.push_sample(SonyRtmdSample::new(a, None));
    // Sample 1: a valid ExposureTime + FNumber.
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 60)))); // ~0.01667 s
    b.set_f_number(Some(NumericRead::Valid(4.0)));
    m.push_sample(SonyRtmdSample::new(b, None));

    // The selector returns sample 1 (sample 0's only signal is non-finite).
    let cap_snap = m
      .first_capture_snapshot()
      .expect("the later valid-exposure sample is selected, not the +inf one");
    assert_eq!(cap_snap.f_number(), Some(4.0));

    // And the projection surfaces sample 1's finite capture (not shadowed/lost).
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md
      .capture()
      .expect("capture populated from the later valid sample");
    assert!(
      (cap.exposure_time_s().expect("finite exposure") - 1.0 / 60.0).abs() < 1e-9,
      "the later sample's valid ExposureTime projects"
    );
    assert_eq!(cap.f_number(), Some(4.0));
  }

  #[test]
  fn project_into_sparse_capture_fields_across_samples_all_surface() {
    // Capture fields appear in DIFFERENT samples — sample 0
    // has FNumber but NO ExposureTime; sample 1 ExposureTime but NO FNumber;
    // sample 2 the canonical ISO. The prior single-`first_capture_snapshot()`
    // projection took exposure+FNumber from ONE snapshot, silently losing a
    // field that first appeared in a different sample. Projecting each field
    // from its own first-valid source surfaces ALL THREE (ExifTool emits each
    // capture tag independently, per tag name).
    let mut m = SonyRtmdMeta::new();
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_f_number(Some(NumericRead::Valid(2.8)));
    m.push_sample(SonyRtmdSample::new(a, None));
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 125))));
    m.push_sample(SonyRtmdSample::new(b, None));
    let mut c = SonyRtmdCameraSnapshot::new();
    c.set_iso(Some(NumericRead::Valid(400)));
    c.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(c, None));

    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture populated from sparse fields");
    assert_eq!(cap.f_number(), Some(2.8), "FNumber from sample 0");
    assert!(
      (cap.exposure_time_s().expect("exposure") - 1.0 / 125.0).abs() < 1e-9,
      "ExposureTime from sample 1, not shadowed by sample 0's FNumber-only"
    );
    assert_eq!(cap.iso(), Some(400), "canonical ISO from sample 2");
  }

  #[test]
  fn project_into_empty_read_numerics_do_not_shadow_later_valid_capture() {
    // Sample 0 carries ONLY EmptyRead numerics (degenerate); sample 1 carries a
    // VALID exposure + canonical ISO. The projection must select sample 1's real
    // capture — the EmptyRead sample 0 is invisible to `first_capture_snapshot`
    // (its domain accessors are all `None`), so it cannot shadow the later fix.
    let mut m = SonyRtmdMeta::new();
    let mut a = SonyRtmdCameraSnapshot::new();
    a.set_f_number(Some(NumericRead::EmptyRead));
    a.set_exposure_time(Some(NumericRead::EmptyRead));
    a.set_iso(Some(NumericRead::EmptyRead));
    a.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(a, None));
    let mut b = SonyRtmdCameraSnapshot::new();
    b.set_exposure_time(Some(NumericRead::Valid(Rational::rational64(1, 250)))); // 0.004 s
    b.set_iso(Some(NumericRead::Valid(640)));
    b.set_iso_from_canonical(true);
    m.push_sample(SonyRtmdSample::new(b, None));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md
      .capture()
      .expect("the later valid sample populates capture");
    assert_eq!(cap.exposure_time_s(), Some(0.004));
    assert_eq!(cap.iso(), Some(640));
  }
}
