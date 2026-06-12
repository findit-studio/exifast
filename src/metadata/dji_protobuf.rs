// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Typed mirror of `Image::ExifTool::DJI::Protobuf` (DJI.pm:240-859) and the
//! nested message tables `Image::ExifTool::DJI::FrameInfo` /
//! `Image::ExifTool::DJI::GPSInfo` / `Image::ExifTool::DJI::DroneInfo` /
//! `Image::ExifTool::DJI::GimbalInfo` (DJI.pm:867-921). Faithful port of the
//! DJI `djmd` (real metadata) protobuf-format timed-metadata walker (the
//! sibling `dbgi` debug track is `Unknown => 2` and a default-options no-op) —
//! DJI's drones (Mavic 3/3 Pro/4 Pro, Air 3/3s,
//! Mini 4 Pro/Mini 5 Pro, Avata 2, Neo, Matrice 30/4E) and hand-held cams
//! (Osmo Action 4/5/6, Osmo Pocket 3, Osmo 360) all write one of these
//! tracks alongside their video.
//!
//! ## What this sub-port surfaces
//!
//! Per the per-protocol arms of DJI.pm:268-859 (each protocol corresponds
//! to one DJI body's `.proto`):
//!
//!  - **Drone identity** — `1-1-5` SerialNumber, `1-1-10` Model
//!    (DJI.pm:268-271 / :309-312 / :349-352 / :402-405 / :437-440 / :468-
//!    471 / :503-506 / :540-543 / :580-583 / :613-616 / :645-648 / :678-
//!    681 / :706-709 / :738-741 / :771-774 / :803-806 / :836-839 / :854-
//!    857).
//!  - **Per-sample GPS fix** — `GPSInfo` nested message (DJI.pm:889-918)
//!    carries `CoordinateUnits` (1-1-1), `GPSLatitude` (1-1-2), and
//!    `GPSLongitude` (1-1-3) as IEEE-754 doubles in either radians (units
//!    code 0 / unset) or degrees (units code nonzero). The walker converts
//!    each coordinate PER-LEAF using the persistent `coord_units` state active
//!    at its position (DJI.pm:929/935). The `Mavic4` / `Mini5Pro` arms force
//!    degrees through a `Condition => '$$self{CoordUnits} = 1'` side-effect
//!    (DJI.pm:857 + :872), reached before their child coordinates.
//!  - **Altitude pair** — `AbsoluteAltitude` (int64s / 1000 metres) +
//!    `RelativeAltitude` (float / 1000 metres) per arm; the absolute
//!    altitude branch handles bundled's int64s hack
//!    (Protobuf.pm:181-185).
//!  - **Camera settings** — ISO, ShutterSpeed, FNumber,
//!    ColorTemperature, DigitalZoom, Temperature per protocol arm
//!    (DJI.pm provides these for Action 4/5/6/AVATA2/Mavic3/Mavic3
//!    Pro/Air 3/3s/Mini 4 Pro/Mini 5 Pro/Pocket 3/Osmo 360/Mavic 4 Pro).
//!  - **Frame info** — `FrameInfo` (DJI.pm:885-893): FrameWidth,
//!    FrameHeight, FrameRate.
//!  - **Drone orientation** — `DroneInfo` (DJI.pm:867-872): DroneRoll,
//!    DronePitch, DroneYaw (each int64s / 10 degrees).
//!  - **Gimbal orientation** — `GimbalInfo` (DJI.pm:874-879):
//!    GimbalPitch, GimbalRoll, GimbalYaw (each int64s / 10 degrees).
//!  - **Per-sample timestamp** — `3-1-2` TimeStamp (`int64u`-style varint
//!    of micro-seconds since some unspecified anchor) on Avata 2/Mavic 3
//!    Pro/4 Pro/Air 3/3s/DJI Neo/Mini 4 Pro/Osmo 360/Pocket 3/Matrice
//!    4E.
//!  - **GPS-derived UTC date/time** — `GPSDateTime` string on the
//!    Action 4/5/6/Osmo 360 + Matrice 4E + Mavic 3 Pro arms (DJI.pm:296-
//!    303 / :335-342 / :374-381 / :756-763 / :790-797).
//!
//! ## What this port deliberately does NOT decode
//!
//! Faithfully but as walked-only (the walker visits, the typed layer discards):
//!  - **AccelerometerX/Y/Z** — Action 4/5/6 + Osmo 360 expose 3-axis
//!    accelerometer floats (DJI.pm:283-285 / :323-325 / :362-364 /
//!    :731-733). The camera-indexing product (Project memory:
//!    [[exifast-camera-metadata-rescope]]) does not need accelerometer
//!    triples; mirrors GoPro / Insta360 / Canon CTMD discard rationale.
//!  - **`dbgi` track** — DJI.pm:355 declares `Unknown => 2` (extraction
//!    requires `Unknown` option `>= 2`). Under the default `Unknown = 0`
//!    ExifTool's `ProcessSamples` does not process a `dbgi` sample at all, so
//!    exifast treats a `dbgi` MetaFormat as a complete no-op (no Doc, no
//!    protocol, no tag, no warning — see the `dbgi` arm in
//!    [`crate::formats::quicktime_stream`]).
//!  - **Per-protocol "model code" / version-number fields** — DJI.pm flags
//!    them with `Unknown => 1` and bundled does NOT extract them in the
//!    default table.
//!
//! `SerialNumber2` (`2-2-3-1`, AVATA2 + DJI Neo only — DJI.pm:399/:553) IS a
//! NAMED, default-extracted tag (no `Unknown` flag), so it IS surfaced (per
//! sample, like `SerialNumber`). Its `# (NC)` is a "Not Confirmed" source
//! comment, NOT a non-default marker.
//!
//! ## D8 compliance
//!
//! Every field is private; access through accessors. Setters return
//! `&mut Self` for chaining. `const fn` where types permit.

extern crate alloc;
use alloc::vec::Vec;

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata};

/// Perl-falsiness of a string scalar: `not $str` is TRUE for exactly the
/// empty string and `"0"` (alongside `undef`, modelled by `Option::None` at
/// the call sites). Every other string — incl. `"0.0"`, `"0E0"`, or a real
/// datetime — is Perl-TRUE. Mirrors the same `!s.is_empty() && s != "0"`
/// truthiness gate used in `formats::xmp` / `formats::ligogps`, inverted.
#[inline]
#[must_use]
fn is_perl_false(s: &str) -> bool {
  s.is_empty() || s == "0"
}

// ===========================================================================
// RationalValue — a typed `Format => 'rational'` reading (number or 'err')
// ===========================================================================

/// The decoded value of a DJI `Format => 'rational'` LEN field
/// (Protobuf.pm:201-205): either the numeric quotient or ExifTool's literal
/// `'err'` sentinel.
///
/// Protobuf.pm:205 is `$val = (defined $num and $den) ? $num/$den : 'err'` — a
/// missing numerator OR a Perl-false denominator (`den == 0`, or a missing
/// denominator `VarInt` returns as `undef`) yields the STRING `'err'`, and the
/// field is STILL `HandleTag`'d with it. So a zero/missing-denominator rational
/// EMITS a tag valued `err` (it does NOT vanish), while numerically `'err'` is
/// not a number — the `MediaMetadata` projection must skip it.
///
/// A plain `Option<f64>` cannot carry this: `None` would conflate "no rational
/// field" with "the rational decoded to `'err'`" (which must still emit a tag).
/// This enum nested in an `Option` separates the three states — `None` (absent),
/// `Some(Err)` (present-but-`'err'`), `Some(Num)` (present numeric) — mirroring
/// the sibling [`crate::metadata::NumericRead`] used for Sony rtmd.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RationalValue {
  /// A valid `num / den` quotient (`den != 0`).
  Num(f64),
  /// ExifTool's `'err'` sentinel — `den == 0`, a missing denominator, or a
  /// missing numerator. Emits the tag valued `err`; the domain skips it.
  Err,
}

impl RationalValue {
  /// ExifTool's literal sentinel string for [`Self::Err`] — emitted verbatim as
  /// the tag value (`-n` and `-j` alike; the `'err'` reading has no PrintConv).
  pub const ERR_STR: &'static str = "err";

  /// `true` for [`Self::Num`].
  #[inline(always)]
  #[must_use]
  pub const fn is_num(self) -> bool {
    matches!(self, Self::Num(_))
  }

  /// `true` for [`Self::Err`].
  #[inline(always)]
  #[must_use]
  pub const fn is_err(self) -> bool {
    matches!(self, Self::Err)
  }

  /// The VALID numeric value, or `None` for [`Self::Err`] — the accessor the
  /// DOMAIN consumes (an `'err'` reading never reaches the cross-format layer).
  /// Composes with `Option::and_then`.
  #[inline(always)]
  #[must_use]
  pub const fn value(self) -> Option<f64> {
    match self {
      Self::Num(v) => Some(v),
      Self::Err => None,
    }
  }
}

// ===========================================================================
// DjiWarning — one `$self->Warn` raised while decoding a djmd sample
// ===========================================================================

/// One `$self->Warn` raised while decoding a DJI `djmd` sample — the typed
/// mirror of an ExifTool `Warning` `FoundTag`, carrying the coordinates of the
/// sample that raised it.
///
/// `ProcessProtobuf` (Protobuf.pm) and `SetGPSDateTime`
/// (QuickTimeStream.pl:980-1009) raise these via `$self->Warn(msg[, minor])`,
/// which runs under the dispatched `djmd` sample's open `DOC_NUM` while
/// `SET_GROUP1 = "Track$num"` (active through `ProcessSamples`,
/// QuickTime.pm:10353) is the live family-1 group. A plain `$self->Warn(msg)`
/// `FoundTag`s `Warning` with an EMPTY `@grps` (ExifTool.pm:9601-9602), so
/// `SET_GROUP1` fills family-1 (the empty-family fill, ExifTool.pm:9474-9475):
/// the net group is family-0 `ExifTool`, family-1 `Track<N>` — a
/// `Track<N>:Warning` (NOT the document-level `ExifTool:Warning` the prior port
/// emitted). The four distinct sources:
///
///  - the unknown-protocol RawConv (`Unknown protocol $val (please submit
///    sample for testing)`, DJI.pm:261-264) — fired per `.proto` leaf, so it
///    recurs once per sample of an unknown-protocol track;
///  - `Protobuf format error` (Protobuf.pm:156) — a truncated / bad-wire
///    record stops the walk;
///  - `Truncated protobuf data` (Protobuf.pm:278) — fired at the TOP-LEVEL call
///    only (`unless $prefix`) when the walk stopped early (Pos != end), i.e.
///    AFTER a top-level `Protobuf format error`;
///  - the MINOR `Approximating GPSDateTime as CreateDate + SampleTime`
///    (`$et->Warn(.., 1)`, QuickTimeStream.pl:991) — fired by `SetGPSDateTime`
///    for every sample that SYNTHESIZES a GPSDateTime.
///
/// All share ExifTool's priority-0 first-wins `Warning` slot and the WAS_WARNED
/// `[xN]` message-dedup (ExifTool.pm:5632-5639 / 3196-3203): a distinct FINAL
/// message emits ONE `Track<N>:Warning` (numbered `Warning`/`Warning (1)`/… for
/// further distinct messages in the same group) with a `[xN]` suffix when that
/// message recurred N>1 times. IDENTICAL machinery to
/// [`crate::metadata::CanonCtmdWarning`] / [`crate::metadata::CammWarning`].
///
/// The `minor` flag distinguishes the `Approximating GPSDateTime` warning
/// (`Warn(.., 1)` ⇒ rendered `[minor] Approximating …`) from the three
/// non-minor ones; the emission applies the `[minor] ` prefix only when set.
///
/// **D8 compliance.** Fields are private; access via the accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct DjiWarning {
  /// The warning string WITHOUT any `[minor]` prefix (the prefix is applied at
  /// emit time from [`Self::minor`]).
  message: SmolStr,
  /// `true` for the `Warn(.., 1)` MINOR `Approximating GPSDateTime as CreateDate
  /// + SampleTime` warning; `false` for the three non-minor ones.
  minor: bool,
  /// The 1-based moov `Track<N>` index the warning is scoped to (`0` until the
  /// walker / dispatch arm stamps it; defaults to `Track1` at emit time).
  track_index: u32,
  /// The GLOBAL `Doc<N>` ordinal of the `djmd` sample that raised the warning
  /// (`0` until stamped). Surfaced as the `Doc<N>:` family-3 prefix at `-G3`;
  /// collapsed away at `-G1`.
  doc: u32,
}

impl DjiWarning {
  /// Build a warning carrying `message` and the `minor` flag (no track / doc
  /// yet — the dispatch arm stamps them after the `process_djmd` call).
  #[inline(always)]
  #[must_use]
  pub fn new(message: SmolStr, minor: bool) -> Self {
    Self {
      message,
      minor,
      track_index: 0,
      doc: 0,
    }
  }

  /// The warning string WITHOUT the `[minor]` prefix.
  #[inline(always)]
  #[must_use]
  pub fn message(&self) -> &str {
    self.message.as_str()
  }

  /// `true` for the MINOR `Approximating GPSDateTime …` warning (`Warn(.., 1)`)
  /// — the emission prepends `[minor] `.
  #[inline(always)]
  #[must_use]
  pub const fn minor(&self) -> bool {
    self.minor
  }

  /// The 1-based moov `Track<N>` index this warning is scoped to (`0` until
  /// stamped; defaults to `Track1` at emit time).
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> u32 {
    self.track_index
  }

  /// The GLOBAL `Doc<N>` ordinal of the `djmd` sample that raised this warning
  /// (`0` until stamped).
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> u32 {
    self.doc
  }

  /// Stamp the 1-based moov `Track<N>` index AND the GLOBAL `Doc<N>` ordinal of
  /// the sample that raised this warning (walker / dispatch-arm only).
  #[inline(always)]
  pub(crate) const fn set_scope(&mut self, track_index: u32, doc: u32) -> &mut Self {
    self.track_index = track_index;
    self.doc = doc;
    self
  }
}

// ===========================================================================
// DjiTelemetrySample — one decoded per-sample row
// ===========================================================================

/// One decoded per-sample row from a DJI `djmd` track — the camera- and
/// flight-state snapshot the drone or handheld cam wrote for one video
/// frame.
///
/// Each `djmd` track sample is one protobuf message that may carry any
/// SUBSET of the fields below depending on the device. Fields stay `None`
/// for protocols that don't emit them (e.g. `AbsoluteAltitude` on the
/// handheld Action / Pocket bodies).
///
/// Bundled-derived field semantics:
///  - `latitude` / `longitude` — `GPSInfo` 1-1-2 / 1-1-3 (DJI.pm:899-913),
///    IEEE-754 double in **radians or degrees** depending on the
///    `CoordinateUnits` (1-1-1) sibling field. The decoder converts to
///    decimal degrees BEFORE storing.
///  - `absolute_altitude_m` — `3-4-2-2` / `3-4-4-2` / `3-3-4-2` per arm
///    (DJI.pm:290-295 etc.), int64s scaled by `/1000` (i.e. millimetres
///    → metres). Bundled has a "hack for DJI drones" (Protobuf.pm:181-185)
///    that recovers a 64-bit signed number from a varint whose top 32
///    bits are all 1's — `decode_int64s_varint` mirrors that hack.
///  - `relative_altitude_m` — `3-4-5-1` / `3-3-5-1` (DJI.pm:295-296
///    etc.), 32-bit float scaled by `/1000` (millimetres → metres).
///  - `gps_date_time` — `3-4-2-6-1` / `3-3-4-6-1` (Action 4/5/6/Osmo 360
///    Matrice 4E, Mavic 3 Pro), ASCII `YYYY-MM-DD HH:MM:SS`
///    transliterated to `YYYY:MM:DD HH:MM:SS` (Exif-canonical form,
///    DJI.pm:300-302 `$val =~ tr/-/:/`).
///  - `time_stamp_us` — `3-1-2` (Avata 2/Mavic 3 Pro/4 Pro/Air 3/3s/DJI
///    Neo/Mini 4 Pro/Mini 5 Pro/Pocket 3/Osmo 360/Matrice 4E), `int64u`
///    microsecond counter (DJI.pm:425-432 etc.).
///  - `iso` / `shutter_speed_s` / `f_number` / `color_temperature` /
///    `digital_zoom` / `temperature_c` — camera-settings tags (offsets
///    vary by protocol; see per-protocol arms in DJI.pm).
///  - `frame_width` / `frame_height` / `frame_rate` — `FrameInfo`
///    nested message (DJI.pm:885-893).
///  - `drone_roll_deg` / `drone_pitch_deg` / `drone_yaw_deg` —
///    `DroneInfo` nested message (DJI.pm:867-872), int64s / 10.
///  - `gimbal_pitch_deg` / `gimbal_roll_deg` / `gimbal_yaw_deg` —
///    `GimbalInfo` nested message (DJI.pm:874-879), int64s / 10.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DjiTelemetrySample {
  /// Decimal-degree latitude (converted from radians or degrees per the
  /// `CoordinateUnits` sibling).
  latitude: Option<f64>,
  /// Decimal-degree longitude.
  longitude: Option<f64>,
  /// `AbsoluteAltitude` metres (int64s milliseconds scaled / 1000).
  absolute_altitude_m: Option<f64>,
  /// Which leaf KIND decoded [`Self::absolute_altitude_m`], so emission can pick
  /// the tag NAME PER-SAMPLE (a mid-track protocol switch can decode an altitude
  /// under one protocol's leaf but emit under another's name otherwise):
  /// `Some(true)` ⇒ the `GPSAltitude` unsigned leaf (ac203/ac204/ac206 `3-4-2-2`,
  /// DJI.pm:296-301); `Some(false)` ⇒ the `AbsoluteAltitude` int64s leaf (every
  /// other arm incl. oq101, DJI.pm:700); `None` ⇒ no altitude on this sample.
  altitude_is_gps_named: Option<bool>,
  /// `RelativeAltitude` metres (float / 1000).
  relative_altitude_m: Option<f64>,
  /// `GPSDateTime` in Exif-canonical form `"YYYY:MM:DD HH:MM:SS"` — the
  /// DECODED `.proto` leaf (the protocols that carry a GPSDateTime row). Emitted
  /// as `Protobuf:DJI:GPSDateTime`.
  gps_date_time: Option<SmolStr>,
  /// A SYNTHESIZED `GPSDateTime` from `SetGPSDateTime` (QuickTimeStream.pl
  /// lines 1531-1539 and 980-1009). For a djmd sample that decoded GPSLatitude
  /// AND GPSLongitude but has NO [`Self::gps_date_time`] leaf, ExifTool
  /// approximates the GPS time from `CreateDate + SampleTime` and `HandleTag`s
  /// it under `SET_GROUP0 = 'Composite'`. Kept SEPARATE from the decoded leaf
  /// because it surfaces under the `Composite` family-0 group
  /// (`Composite:GPSDateTime`), not `Protobuf:DJI`. The two never coexist
  /// (synthesis runs only when the leaf is absent). The string already carries
  /// the trailing `'Z'`.
  synth_gps_date_time: Option<SmolStr>,
  /// `TimeStamp` microsecond counter (Avata 2 / Mavic 3 Pro / 4 Pro
  /// etc.; DJI.pm:430-432).
  time_stamp_us: Option<u64>,
  /// `ISO` (float in the wire).
  iso: Option<f64>,
  /// `ShutterSpeed` seconds — a `Format => 'rational'` reading (the num/den
  /// quotient, or [`RationalValue::Err`] for a zero/missing denominator, which
  /// still emits the `'err'` tag; Protobuf.pm:201-205).
  shutter_speed_s: Option<RationalValue>,
  /// `FNumber` — a `Format => 'rational'` reading (the num/den quotient, or
  /// [`RationalValue::Err`]).
  f_number: Option<RationalValue>,
  /// `ColorTemperature` Kelvin.
  color_temperature: Option<u32>,
  /// `DigitalZoom` factor (float).
  digital_zoom: Option<f64>,
  /// `Temperature` degrees Celsius (float).
  temperature_c: Option<f64>,
  /// `FrameWidth` pixels.
  frame_width: Option<u32>,
  /// `FrameHeight` pixels.
  frame_height: Option<u32>,
  /// `FrameRate` Hz (float).
  frame_rate: Option<f64>,
  /// `DroneRoll` degrees (int64s / 10).
  drone_roll_deg: Option<f64>,
  /// `DronePitch` degrees (int64s / 10).
  drone_pitch_deg: Option<f64>,
  /// `DroneYaw` degrees (int64s / 10).
  drone_yaw_deg: Option<f64>,
  /// `GimbalPitch` degrees (int64s / 10).
  gimbal_pitch_deg: Option<f64>,
  /// `GimbalRoll` degrees (int64s / 10).
  gimbal_roll_deg: Option<f64>,
  /// `GimbalYaw` degrees (int64s / 10).
  gimbal_yaw_deg: Option<f64>,
  /// `Protocol` (`dvtm_<body>.proto`) — set ONLY on the sample whose own
  /// records carried a `.proto` leaf. ExifTool `HandleTag`s `Protocol` exactly
  /// when `$type == 2 and $buff =~ /\.proto$/` (Protobuf.pm:158-160), i.e.
  /// per-sample-when-seen, so a later data-only sample (which reuses the
  /// PERSISTED `ProtoPrefix` but has no `.proto` leaf of its own) emits NO
  /// `Protocol`. Distinct from the track-wide persisted protocol on
  /// [`DjiProtobufMeta`] (which drives table/altitude-name selection).
  protocol: Option<SmolStr>,
  /// `SerialNumber` (`1-1-5`) — set on the sample whose own records carried
  /// the `1-1-5` leaf (`HandleTag`-when-seen). Typically only the identity
  /// sample.
  serial_number: Option<SmolStr>,
  /// `SerialNumber2` (`2-2-3-1`) — set on the sample whose own records carried
  /// the `2-2-3-1` leaf (`HandleTag`-when-seen). A NAMED, default-extracted tag
  /// on the AVATA2 + DJI Neo arms ONLY (DJI.pm:399/:553); `None` on every other
  /// protocol (which declares no such leaf). Decoded as a plain ASCII string,
  /// like [`Self::serial_number`].
  serial_number_2: Option<SmolStr>,
  /// `Model` (`1-1-10`) — set on the sample whose own records carried the
  /// `1-1-10` leaf (`HandleTag`-when-seen).
  model: Option<SmolStr>,
  /// Family-3 sub-document ordinal (`0` = unstamped / Main). `ProcessSamples`
  /// opens ONE `Doc<N>` per `djmd` SAMPLE; every decoded tag of that sample
  /// shares it (QuickTimeStream.pl:1517-1523). Stamped by the `djmd` dispatch
  /// arm after the per-sample walk.
  doc: u32,
  /// Family-1 `Track<N>` index (1-based; `0` = unstamped) — the enclosing
  /// `djmd` `trak`'s number (`SET_GROUP1 = "Track$num"`).
  track_index: u32,
  /// Sample-table `SampleTime` (seconds), or `None` until stamped.
  sample_time: Option<f64>,
  /// Sample-table `SampleDuration` (seconds), or `None` until stamped.
  sample_duration: Option<f64>,
}

impl DjiTelemetrySample {
  /// An empty sample (no fields populated).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      latitude: None,
      longitude: None,
      absolute_altitude_m: None,
      altitude_is_gps_named: None,
      relative_altitude_m: None,
      gps_date_time: None,
      synth_gps_date_time: None,
      time_stamp_us: None,
      iso: None,
      shutter_speed_s: None,
      f_number: None,
      color_temperature: None,
      digital_zoom: None,
      temperature_c: None,
      frame_width: None,
      frame_height: None,
      frame_rate: None,
      drone_roll_deg: None,
      drone_pitch_deg: None,
      drone_yaw_deg: None,
      gimbal_pitch_deg: None,
      gimbal_roll_deg: None,
      gimbal_yaw_deg: None,
      protocol: None,
      serial_number: None,
      serial_number_2: None,
      model: None,
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// `GPSLatitude` decimal degrees (post-radians/degrees conversion).
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

  /// `AbsoluteAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn absolute_altitude_m(&self) -> Option<f64> {
    self.absolute_altitude_m
  }

  /// Whether [`Self::absolute_altitude_m`] was decoded via the `GPSAltitude`
  /// unsigned leaf (`Some(true)`) vs the `AbsoluteAltitude` int64s leaf
  /// (`Some(false)`) — drives the PER-SAMPLE emitted altitude tag name. `None`
  /// when this sample carried no altitude.
  #[inline(always)]
  #[must_use]
  pub const fn altitude_is_gps_named(&self) -> Option<bool> {
    self.altitude_is_gps_named
  }

  /// `RelativeAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn relative_altitude_m(&self) -> Option<f64> {
    self.relative_altitude_m
  }

  /// `GPSDateTime` in Exif-canonical form — the decoded `.proto` leaf.
  #[inline(always)]
  #[must_use]
  pub fn gps_date_time(&self) -> Option<&str> {
    self.gps_date_time.as_deref()
  }

  /// The SYNTHESIZED `GPSDateTime` (`SetGPSDateTime`) for a GPS sample lacking a
  /// decoded leaf — surfaced under the `Composite` family-0 group. Carries the
  /// trailing `'Z'`.
  #[inline(always)]
  #[must_use]
  pub fn synth_gps_date_time(&self) -> Option<&str> {
    self.synth_gps_date_time.as_deref()
  }

  /// The effective GPS timestamp for the [`crate::metadata::GpsLocation`]
  /// projection — the decoded leaf when it is **Perl-true**, else the
  /// synthesized value (`SetGPSDateTime`).
  ///
  /// ExifTool's `SetGPSDateTime` gate is `not $$et{GPSDateTime}`
  /// (QuickTimeStream.pl:1536), so a decoded leaf that is Perl-FALSE (`""` or
  /// `"0"` — a degraded/malformed `.proto` field) does NOT suppress synthesis;
  /// the synthesized `Composite:GPSDateTime` is what `$$et{GPSDateTime}`
  /// becomes, and so is what feeds the projection's timestamp. A Perl-true
  /// leaf (any other string, incl. `"0.0"`/`"0E0"` or a real datetime) wins.
  /// The two CAN coexist on one sample (the leaf still `HandleTag`s when it is
  /// `""`/`"0"`); this picks the value ExifTool's `GPSDateTime` key ends up
  /// holding.
  #[inline]
  #[must_use]
  pub fn effective_gps_date_time(&self) -> Option<&str> {
    match self.gps_date_time() {
      Some(s) if !is_perl_false(s) => Some(s),
      _ => self.synth_gps_date_time(),
    }
  }

  /// `TimeStamp` microsecond counter.
  #[inline(always)]
  #[must_use]
  pub const fn time_stamp_us(&self) -> Option<u64> {
    self.time_stamp_us
  }

  /// `ISO`.
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<f64> {
    self.iso
  }

  /// `ShutterSpeed` seconds — the VALID numeric reading ONLY (`None` for an
  /// `'err'` reading or absent). This is the DOMAIN accessor: a zero-denominator
  /// `'err'` reading is not a number and is skipped by the projection. Use
  /// [`Self::shutter_speed_read`] for the full (number / `'err'`) reading the
  /// `-ee` emission needs.
  #[inline(always)]
  #[must_use]
  pub const fn shutter_speed_s(&self) -> Option<f64> {
    match self.shutter_speed_s {
      Some(rv) => rv.value(),
      None => None,
    }
  }

  /// `ShutterSpeed` as the full [`RationalValue`] reading (number / `'err'` /
  /// absent) — the accessor the `-ee` emission consumes (it must emit `'err'`
  /// for a zero/missing-denominator rational).
  #[inline(always)]
  #[must_use]
  pub const fn shutter_speed_read(&self) -> Option<RationalValue> {
    self.shutter_speed_s
  }

  /// `FNumber` — the VALID numeric reading ONLY (`None` for an `'err'` reading
  /// or absent); the DOMAIN accessor (see [`Self::shutter_speed_s`]).
  #[inline(always)]
  #[must_use]
  pub const fn f_number(&self) -> Option<f64> {
    match self.f_number {
      Some(rv) => rv.value(),
      None => None,
    }
  }

  /// `FNumber` as the full [`RationalValue`] reading — the accessor the `-ee`
  /// emission consumes.
  #[inline(always)]
  #[must_use]
  pub const fn f_number_read(&self) -> Option<RationalValue> {
    self.f_number
  }

  /// `ColorTemperature` Kelvin.
  #[inline(always)]
  #[must_use]
  pub const fn color_temperature(&self) -> Option<u32> {
    self.color_temperature
  }

  /// `DigitalZoom` factor.
  #[inline(always)]
  #[must_use]
  pub const fn digital_zoom(&self) -> Option<f64> {
    self.digital_zoom
  }

  /// `Temperature` degrees Celsius.
  #[inline(always)]
  #[must_use]
  pub const fn temperature_c(&self) -> Option<f64> {
    self.temperature_c
  }

  /// `FrameWidth` pixels.
  #[inline(always)]
  #[must_use]
  pub const fn frame_width(&self) -> Option<u32> {
    self.frame_width
  }

  /// `FrameHeight` pixels.
  #[inline(always)]
  #[must_use]
  pub const fn frame_height(&self) -> Option<u32> {
    self.frame_height
  }

  /// `FrameRate` Hz.
  #[inline(always)]
  #[must_use]
  pub const fn frame_rate(&self) -> Option<f64> {
    self.frame_rate
  }

  /// `DroneRoll` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn drone_roll_deg(&self) -> Option<f64> {
    self.drone_roll_deg
  }

  /// `DronePitch` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn drone_pitch_deg(&self) -> Option<f64> {
    self.drone_pitch_deg
  }

  /// `DroneYaw` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn drone_yaw_deg(&self) -> Option<f64> {
    self.drone_yaw_deg
  }

  /// `GimbalPitch` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn gimbal_pitch_deg(&self) -> Option<f64> {
    self.gimbal_pitch_deg
  }

  /// `GimbalRoll` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn gimbal_roll_deg(&self) -> Option<f64> {
    self.gimbal_roll_deg
  }

  /// `GimbalYaw` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn gimbal_yaw_deg(&self) -> Option<f64> {
    self.gimbal_yaw_deg
  }

  /// `Protocol` (`dvtm_<body>.proto`) carried by THIS sample's own `.proto`
  /// leaf, or `None` when this sample reused the persisted protocol.
  #[inline(always)]
  #[must_use]
  pub fn protocol(&self) -> Option<&str> {
    self.protocol.as_deref()
  }

  /// `SerialNumber` carried by THIS sample's own `1-1-5` leaf.
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }

  /// `SerialNumber2` carried by THIS sample's own `2-2-3-1` leaf (AVATA2 / DJI
  /// Neo only).
  #[inline(always)]
  #[must_use]
  pub fn serial_number_2(&self) -> Option<&str> {
    self.serial_number_2.as_deref()
  }

  /// `Model` carried by THIS sample's own `1-1-10` leaf.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
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

  /// `true` when this sample carries NO decoded value — neither telemetry NOR
  /// its own identity (`Protocol`/`SerialNumber`/`Model`). The decoder pushes
  /// one row per dispatched `djmd` sample regardless (faithful to
  /// `FoundSomething` opening a `Doc<N>` per sample), so an `is_empty()` row is
  /// a Doc-with-only-SampleTime/Duration placeholder.
  #[inline]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.absolute_altitude_m.is_none()
      && self.relative_altitude_m.is_none()
      && self.gps_date_time.is_none()
      && self.time_stamp_us.is_none()
      && self.iso.is_none()
      && self.shutter_speed_s.is_none()
      && self.f_number.is_none()
      && self.color_temperature.is_none()
      && self.digital_zoom.is_none()
      && self.temperature_c.is_none()
      && self.frame_width.is_none()
      && self.frame_height.is_none()
      && self.frame_rate.is_none()
      && self.drone_roll_deg.is_none()
      && self.drone_pitch_deg.is_none()
      && self.drone_yaw_deg.is_none()
      && self.gimbal_pitch_deg.is_none()
      && self.gimbal_roll_deg.is_none()
      && self.gimbal_yaw_deg.is_none()
      && self.protocol.is_none()
      && self.serial_number.is_none()
      && self.serial_number_2.is_none()
      && self.model.is_none()
  }

  // ── pub(crate) setters: only the walker writes these ─────────────────
  #[inline(always)]
  pub(crate) const fn set_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_absolute_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.absolute_altitude_m = v;
    self
  }
  /// Record which leaf KIND decoded the altitude (`true` ⇒ `GPSAltitude`
  /// unsigned, `false` ⇒ `AbsoluteAltitude` int64s) so emission picks the
  /// PER-SAMPLE tag name.
  #[inline(always)]
  pub(crate) const fn set_altitude_is_gps_named(&mut self, v: Option<bool>) -> &mut Self {
    self.altitude_is_gps_named = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_relative_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.relative_altitude_m = v;
    self
  }
  #[inline(always)]
  pub(crate) fn set_gps_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.gps_date_time = v;
    self
  }
  /// Record the SYNTHESIZED `GPSDateTime` (`SetGPSDateTime`) for a GPS sample
  /// that decoded no GPSDateTime leaf — written by the `djmd` dispatch arm.
  #[inline(always)]
  pub(crate) fn set_synth_gps_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.synth_gps_date_time = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_time_stamp_us(&mut self, v: Option<u64>) -> &mut Self {
    self.time_stamp_us = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_iso(&mut self, v: Option<f64>) -> &mut Self {
    self.iso = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_shutter_speed_s(&mut self, v: Option<RationalValue>) -> &mut Self {
    self.shutter_speed_s = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_f_number(&mut self, v: Option<RationalValue>) -> &mut Self {
    self.f_number = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_color_temperature(&mut self, v: Option<u32>) -> &mut Self {
    self.color_temperature = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_digital_zoom(&mut self, v: Option<f64>) -> &mut Self {
    self.digital_zoom = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_temperature_c(&mut self, v: Option<f64>) -> &mut Self {
    self.temperature_c = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_frame_width(&mut self, v: Option<u32>) -> &mut Self {
    self.frame_width = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_frame_height(&mut self, v: Option<u32>) -> &mut Self {
    self.frame_height = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_frame_rate(&mut self, v: Option<f64>) -> &mut Self {
    self.frame_rate = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_drone_roll_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_roll_deg = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_drone_pitch_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_pitch_deg = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_drone_yaw_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.drone_yaw_deg = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_gimbal_pitch_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.gimbal_pitch_deg = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_gimbal_roll_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.gimbal_roll_deg = v;
    self
  }
  #[inline(always)]
  pub(crate) const fn set_gimbal_yaw_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.gimbal_yaw_deg = v;
    self
  }
  /// Set this sample's emitted `Protocol` scalar — LAST-WINS within one sample.
  ///
  /// ExifTool `HandleTag`s `Protocol` for EVERY `.proto` leaf in the message
  /// (Protobuf.pm:160), but within ONE `Doc<N>` a duplicate non-priority tag is
  /// LAST-wins in the `-j` / `-G3` JSON — one `Protocol` entry carrying the
  /// inner/last value. The `-G3` JSON is tag-key-order-insensitive, so the wire
  /// ORDER in which the leaves were walked is unobservable in the goldens. So a
  /// single scalar that keeps the LAST `.proto` value walked is golden-faithful
  /// to ExifTool's within-`Doc` `HandleTag` dedup (the merged camm/ctmd siblings
  /// use the same scalar-per-sample model and their goldens pass byte-exact).
  #[inline(always)]
  pub(crate) fn set_protocol(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.protocol = v;
    self
  }
  #[inline(always)]
  pub(crate) fn set_serial_number(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.serial_number = v;
    self
  }
  #[inline(always)]
  pub(crate) fn set_serial_number_2(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.serial_number_2 = v;
    self
  }
  #[inline(always)]
  pub(crate) fn set_model(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.model = v;
    self
  }
}

// ===========================================================================
// DjiProtobufMeta — the aggregate per-track result
// ===========================================================================

/// Typed result of decoding a DJI `djmd` track. One DJI body produces one
/// `djmd` track; the typed surface accumulates every per-sample row plus
/// the track-level identity (Protocol → Model, SerialNumber).
///
/// Empty (`is_empty()`) when no `djmd` sample was present or all records
/// failed to decode (the `dbgi` debug track is a default-options no-op).
///
/// **D8 compliance.** Every field is private; access through the accessors
/// below.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DjiProtobufMeta {
  /// `Protocol` — the `dvtm_<body>.proto` string seen on the first DJMD
  /// sample's top-level varint string field. Used internally as the
  /// tag-table prefix AND to pick the altitude tag NAME (GPSAltitude vs
  /// AbsoluteAltitude) at emission; surfaced verbatim for forensic /
  /// camera-indexing use. ONLY `djmd` samples set this — the `dbgi` track is a
  /// no-op under the default options (DJI.pm:355 `Unknown => 2`) so it
  /// contributes nothing to this or any other field.
  protocol: Option<SmolStr>,
  /// `SerialNumber` — `1-1-5` (DJI.pm:268 etc.).
  serial_number: Option<SmolStr>,
  /// `Model` — `1-1-10` (DJI.pm:271 etc.). DJI writes the human-readable
  /// product name here (e.g. `"FC8482"` for Mavic 3, `"FC8284"` for Air 3).
  model: Option<SmolStr>,
  /// Per-sample telemetry rows in source order.
  samples: Vec<DjiTelemetrySample>,
  /// Every walker / `SetGPSDateTime` warning, in raise order (`Unknown protocol
  /// …` DJI.pm:261-264, `Protobuf format error` + `Truncated protobuf data`
  /// Protobuf.pm:156/278, the minor `Approximating GPSDateTime …`
  /// QuickTimeStream.pl:991). ExifTool raises each via `$self->Warn`, which runs
  /// under the dispatched sample's open `DOC_NUM` + `SET_GROUP1 = "Track$num"`
  /// during `ProcessSamples` — so each carries that sample's `Doc<N>` /
  /// `Track<N>`, stamped after the `process_djmd` call (mirrors
  /// `CanonCtmdWarning` / `CammWarning`). The emission collapses recurring +
  /// distinct messages per ExifTool's WAS_WARNED `[xN]` + numbered-`Warning`
  /// machinery.
  warnings: Vec<DjiWarning>,
}

// NOTE: the MUTABLE per-track decode state — the last-wins `ProtoPrefix`
// (`$$et{ProtoPrefix}{$dirName}`, Protobuf.pm:143/159) and the persistent
// `$$self{CoordUnits}` (DJI.pm:922) — does NOT live here. It is keyed PER
// metadata track (one `djmd` `trak` = one `$dirName`, init EMPTY per track) and
// must never leak across tracks, so it lives on
// `crate::formats::dji_protobuf::DjiTrackState`, created fresh per `djmd` track
// (R15-F2). This aggregate spans ALL the file's `djmd` tracks (decoded samples,
// the FIRST-wins model identity, the warnings) and so is the WRONG scope for
// the per-track decode cursor.

impl DjiProtobufMeta {
  /// An empty result.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      protocol: None,
      serial_number: None,
      model: None,
      samples: Vec::new(),
      warnings: Vec::new(),
    }
  }

  /// The DJMD `Protocol` string (`dvtm_<body>.proto`) from the first decoded
  /// `djmd` sample — the protocol that drives DJMD payload emission and the
  /// altitude tag-name selection.
  #[inline(always)]
  #[must_use]
  pub fn protocol(&self) -> Option<&str> {
    self.protocol.as_deref()
  }

  /// `SerialNumber` (`1-1-5`).
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }

  /// `Model` (`1-1-10`).
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// Per-sample telemetry rows in source order.
  #[inline(always)]
  #[must_use]
  pub fn samples(&self) -> &[DjiTelemetrySample] {
    self.samples.as_slice()
  }

  /// Every walker / `SetGPSDateTime` warning, in raise order (each stamped with
  /// its raising sample's `Track<N>` / `Doc<N>`). The emission collapses these
  /// per ExifTool's WAS_WARNED `[xN]` + numbered-`Warning` machinery.
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[DjiWarning] {
    self.warnings.as_slice()
  }

  /// The FIRST warning's message (in raise order), or `None`. A test-only
  /// convenience over [`Self::warnings`] used by the walker tests that assert
  /// the message a `process_djmd` raised — the warning RAISING is unchanged by
  /// the move to a `Vec`; only the per-message `[xN]` / numbered emission lives
  /// in the emitter now.
  #[cfg(test)]
  #[inline]
  #[must_use]
  pub(crate) fn first_warning(&self) -> Option<&str> {
    self.warnings.first().map(DjiWarning::message)
  }

  /// `true` when nothing meaningful decoded — no identity field was populated
  /// AND every pushed sample is itself empty. The decoder pushes one row per
  /// dispatched `djmd` sample even when it decoded nothing (a `Doc<N>`
  /// placeholder), so a non-empty `samples` does NOT by itself make the track
  /// non-empty; only a row carrying a real value (or a track-level identity)
  /// does. Keeps the `MediaMetadata` projection from synthesising a bare
  /// `Make = "DJI"` for a placeholder-only track.
  #[inline]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.protocol.is_none()
      && self.serial_number.is_none()
      && self.model.is_none()
      && self.samples.iter().all(DjiTelemetrySample::is_empty)
  }

  /// `true` when this track carries DJMD content that should project a DJI
  /// camera / GPS / capture — a real `djmd` sample (telemetry OR its own
  /// identity), the track-level `Protocol`, or the track-level
  /// `SerialNumber` / `Model`. The `dbgi` debug track is a no-op under the
  /// default options (DJI.pm:355 `Unknown => 2`) so it never contributes here.
  #[inline]
  #[must_use]
  fn has_projectable_djmd(&self) -> bool {
    self.protocol.is_some()
      || self.serial_number.is_some()
      || self.model.is_some()
      || self.samples.iter().any(|s| !s.is_empty())
  }

  /// The FIRST sample with both latitude AND longitude populated —
  /// feeds the [`crate::metadata::GpsLocation`] projection.
  #[inline]
  #[must_use]
  pub fn first_fix(&self) -> Option<&DjiTelemetrySample> {
    self
      .samples
      .iter()
      .find(|s| s.latitude.is_some() && s.longitude.is_some())
  }

  /// The FIRST sample with a PROJECTABLE NUMERIC `iso`, `shutter_speed_s`, OR
  /// `f_number` — feeds the [`crate::metadata::CaptureSettings`] projection.
  /// Selects on the numeric accessors (NOT raw field presence) so a sample
  /// carrying only an `'err'` reading ([`RationalValue::Err`], which still emits
  /// a tag but is not a number) does NOT shadow a later sample with a valid
  /// reading — mirroring the Sony rtmd `first_finite_*` projection selection.
  #[inline]
  #[must_use]
  pub fn first_capture(&self) -> Option<&DjiTelemetrySample> {
    self
      .samples
      .iter()
      .find(|s| s.iso.is_some() || s.shutter_speed_s().is_some() || s.f_number().is_some())
  }

  // ── pub(crate) setters: the walker writes ────────────────────────────
  #[inline(always)]
  pub(crate) fn set_protocol(&mut self, v: SmolStr) -> &mut Self {
    self.protocol = Some(v);
    self
  }
  #[inline(always)]
  pub(crate) fn set_serial_number(&mut self, v: SmolStr) -> &mut Self {
    self.serial_number = Some(v);
    self
  }
  #[inline(always)]
  pub(crate) fn set_model(&mut self, v: SmolStr) -> &mut Self {
    self.model = Some(v);
    self
  }
  #[inline(always)]
  pub(crate) fn push_sample(&mut self, s: DjiTelemetrySample) -> &mut Self {
    self.samples.push(s);
    self
  }

  /// Append a walker / `SetGPSDateTime` warning. Every raise is recorded (NOT
  /// first-wins): ExifTool's WAS_WARNED counts each FINAL message's occurrences
  /// for the `[xN]` suffix (ExifTool.pm:5632-5639), so the unknown-protocol
  /// warning (fired per `.proto` leaf) and the minor `Approximating GPSDateTime`
  /// (fired per synth sample) must each land once per occurrence. The dispatch
  /// arm stamps the appended warnings' `Track<N>` / `Doc<N>` after the
  /// `process_djmd` call (see [`Self::stamp_warnings_from`]).
  #[inline]
  pub(crate) fn push_warning(&mut self, w: DjiWarning) -> &mut Self {
    self.warnings.push(w);
    self
  }

  /// The number of warnings recorded so far — a watermark the dispatch arm
  /// takes BEFORE one `process_djmd` call so it can stamp the `Track<N>` /
  /// `Doc<N>` onto exactly the warnings that call raised (mirrors
  /// [`crate::metadata::CanonCtmdMeta::warning_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn warning_count(&self) -> usize {
    self.warnings.len()
  }

  /// Stamp the 1-based moov `track_index` AND the GLOBAL `doc` ordinal onto
  /// every warning at or after `start` — the warnings the just-completed
  /// `process_djmd` call raised. The `doc` is the SAME ordinal the sample opened
  /// (`open_doc`, bumped once per dispatched djmd sample), and `SET_GROUP1 =
  /// "Track$num"` is active for the whole `ProcessProtobuf` call, so each
  /// warning rides that sample's `Track<N>` / `Doc<N>`. Mirrors the per-sample
  /// stamps + [`crate::metadata::CanonCtmdMeta::stamp_warning_from`].
  pub(crate) fn stamp_warnings_from(&mut self, start: usize, track_index: u32, doc: u32) {
    if let Some(slice) = self.warnings.get_mut(start..) {
      for w in slice {
        w.set_scope(track_index, doc);
      }
    }
  }

  /// The number of telemetry rows pushed so far — a watermark the stream
  /// walker takes BEFORE one `process_djmd` call so it can stamp the
  /// sub-document / track coordinates onto exactly the row that call appended
  /// (mirrors [`crate::metadata::SonyRtmdMeta::sample_count`]). A `djmd`
  /// sample pushes at most one row (none when fully empty).
  #[inline(always)]
  #[must_use]
  pub(crate) fn sample_count(&self) -> usize {
    self.samples.len()
  }

  /// Stamp the family-3 `doc` ordinal AND the sample-table `sample_time` /
  /// `sample_duration` (seconds) onto every row at or after `start` — the
  /// row one `process_djmd` call appended since the walker took its
  /// [`Self::sample_count`] watermark. Mirrors
  /// [`crate::metadata::SonyRtmdMeta::stamp_doc_from`].
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

  /// `true` when the row at `start` qualifies for `SetGPSDateTime` synthesis —
  /// it decoded GPSLatitude AND GPSLongitude while `GPSDateTime` is **not
  /// Perl-true** (`defined GPSLatitude and defined GPSLongitude and not
  /// GPSDateTime`, QuickTimeStream.pl:1536). ExifTool's `not $$et{GPSDateTime}`
  /// is TRUE — so synthesis fires — when the decoded leaf is absent OR is a
  /// Perl-FALSE string (`""` or `"0"`; a degraded/malformed sample). Any other
  /// leaf, incl. `"0.0"`/`"0E0"`/a real datetime, is Perl-TRUE ⇒ no synthesis.
  /// The decoded leaf is still HandleTag'd (emitted under `Protobuf:DJI`) even
  /// when it is `""`/`"0"`; the synthesized `Composite:GPSDateTime` coexists.
  /// The `djmd` dispatch arm reads this to decide whether to compute + store
  /// the synthesized value. `false` for an out-of-range index.
  #[inline]
  #[must_use]
  pub(crate) fn sample_wants_synth_gps_date_time(&self, start: usize) -> bool {
    self.samples.get(start).is_some_and(|s| {
      s.latitude().is_some()
        && s.longitude().is_some()
        && s.gps_date_time().is_none_or(is_perl_false)
    })
  }

  /// Store the synthesized `Composite:GPSDateTime` (`SetGPSDateTime`) on the row
  /// at `start` — written by the `djmd` dispatch arm after it confirms
  /// [`Self::sample_wants_synth_gps_date_time`] and computes the value. Out of
  /// range ⇒ a silent no-op.
  pub(crate) fn set_sample_synth_gps_date_time(&mut self, start: usize, value: SmolStr) {
    if let Some(s) = self.samples.get_mut(start) {
      s.set_synth_gps_date_time(Some(value));
    }
  }

  /// Stamp the family-1 `track_index` (1-based) onto every row at or after
  /// `start` — the row decoded from a single `djmd` `trak`. Mirrors
  /// [`crate::metadata::SonyRtmdMeta::stamp_track_index_from`].
  pub(crate) fn stamp_track_index_from(&mut self, start: usize, track_index: u32) {
    if let Some(slice) = self.samples.get_mut(start..) {
      for s in slice {
        s.track_index = track_index;
      }
    }
  }
}

// ===========================================================================
// DJI Protobuf projection into MediaMetadata
// ===========================================================================

impl DjiProtobufMeta {
  /// Project DJI `djmd` metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** DJI Protobuf ranks among the HIGHEST-PRIORITY camera
  /// identity tiers — every body that writes a `djmd` track is a DJI
  /// drone or hand-held cam, and the protobuf carries the
  /// `Make = "DJI"` + `Model` + `SerialNumber` directly. The projection
  /// skips silently when a higher-priority source (GoPro/CAMM identity)
  /// already populated `md.camera()`.
  ///
  /// **CaptureSettings:** the FIRST sample with `iso`, `shutter_speed_s`,
  /// or `f_number` populated feeds `md.capture()`. Skipped when
  /// `md.capture()` is already populated.
  ///
  /// **GpsLocation:** DJI Protobuf is on-drone hardware GNSS (dedicated
  /// drone GPS) — **slotted as the HIGHEST tier** of the GPS priority
  /// chain (above GoPro/CAMM only by chain ordering in
  /// [`crate::formats::quicktime::Meta::media_metadata`]). The FIRST
  /// sample with a latitude/longitude pair populates `md.gps()`;
  /// altitude prefers `absolute_altitude_m` over `relative_altitude_m`
  /// (relative altitude is takeoff-anchored, not WGS-84-anchored).
  ///
  /// **Warnings:** `MediaMetadata` carries no warnings channel, so a
  /// walker warning (e.g. "Unknown DJI protocol") is NOT propagated here;
  /// it stays on the typed surface ([`DjiProtobufMeta::warnings`]) for the
  /// per-format diagnostics path (cf. the Parrot mett projection).
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    // Gate CameraInfo on PROJECTABLE DJMD content (a real `djmd` sample, a
    // track-level Protocol, or SerialNumber/Model) so a track that opened a
    // placeholder Doc but decoded nothing does not synthesise a bare
    // `Make = "DJI"`.
    let projectable = self.has_projectable_djmd();
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none() && projectable {
      let mut cam = CameraInfo::new();
      cam.update_make(Some("DJI".into()));
      cam.update_model(self.model().map(alloc::string::ToString::to_string));
      cam.update_serial(self.serial_number().map(alloc::string::ToString::to_string));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── CaptureSettings ────────────────────────────────────────────────
    if md.capture().is_none()
      && let Some(s) = self.first_capture()
    {
      let mut cap = CaptureSettings::new();
      cap.update_exposure_time_s(s.shutter_speed_s());
      // ISO is a float in DJI's wire format; CaptureSettings stores u32.
      // Clamp negative / NaN out, round.
      cap.update_iso(s.iso().and_then(|v| {
        if v.is_finite() && v >= 0.0 && v <= f64::from(u32::MAX) {
          Some(v.round() as u32)
        } else {
          None
        }
      }));
      cap.update_f_number(s.f_number());
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
        // Prefer absolute altitude (WGS-84); fall back to None when the
        // body only writes relative-to-takeoff.
        .update_altitude_m(s.absolute_altitude_m())
        // The decoded GPSDateTime leaf if present, else the synthesized
        // `SetGPSDateTime` value (the protocols with a GPS fix but no
        // GPSDateTime row — e.g. dvtm_wm265e — get the synthesized timestamp).
        .update_timestamp(
          s.effective_gps_date_time()
            .map(alloc::string::ToString::to_string),
        );
      md.set_gps(gps);
    }
    // Walker warnings ("Unknown DJI protocol", "Truncated protobuf data")
    // are NOT propagated into `MediaMetadata` — it carries no warnings
    // channel (the `md.push_warning` path was removed; cf. the Parrot mett
    // projection). The walker warnings stay on the typed surface
    // ([`DjiProtobufMeta::warnings`]) for the per-format diagnostics path to
    // surface at emission time, matching the sibling timed-metadata ports.
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
    let m = DjiProtobufMeta::new();
    assert!(m.is_empty());
    assert!(m.protocol().is_none());
    assert!(m.serial_number().is_none());
    assert!(m.model().is_none());
    assert!(m.samples().is_empty());
    assert!(m.first_fix().is_none());
    assert!(m.first_capture().is_none());
    assert!(m.warnings().is_empty());
  }

  #[test]
  fn telemetry_sample_get_set_roundtrip() {
    let mut s = DjiTelemetrySample::new();
    assert!(s.is_empty());
    s.set_latitude(Some(40.7128));
    s.set_longitude(Some(-74.0060));
    s.set_absolute_altitude_m(Some(105.5));
    s.set_relative_altitude_m(Some(50.2));
    s.set_gps_date_time(Some(SmolStr::from("2025:01:15 12:34:56")));
    s.set_time_stamp_us(Some(1_234_567_890));
    s.set_iso(Some(100.0));
    s.set_shutter_speed_s(Some(RationalValue::Num(1.0 / 60.0)));
    s.set_f_number(Some(RationalValue::Num(2.8)));
    s.set_color_temperature(Some(5600));
    s.set_digital_zoom(Some(1.5));
    s.set_temperature_c(Some(42.0));
    s.set_frame_width(Some(3840));
    s.set_frame_height(Some(2160));
    s.set_frame_rate(Some(29.97));
    s.set_drone_roll_deg(Some(0.5));
    s.set_drone_pitch_deg(Some(-1.0));
    s.set_drone_yaw_deg(Some(90.0));
    s.set_gimbal_pitch_deg(Some(-30.0));
    s.set_gimbal_roll_deg(Some(0.0));
    s.set_gimbal_yaw_deg(Some(45.0));
    assert!(!s.is_empty());
    assert_eq!(s.latitude(), Some(40.7128));
    assert_eq!(s.longitude(), Some(-74.0060));
    assert_eq!(s.absolute_altitude_m(), Some(105.5));
    assert_eq!(s.relative_altitude_m(), Some(50.2));
    assert_eq!(s.gps_date_time(), Some("2025:01:15 12:34:56"));
    assert_eq!(s.time_stamp_us(), Some(1_234_567_890));
    assert_eq!(s.iso(), Some(100.0));
    assert_eq!(s.shutter_speed_s(), Some(1.0 / 60.0));
    assert_eq!(s.f_number(), Some(2.8));
    assert_eq!(s.color_temperature(), Some(5600));
    assert_eq!(s.digital_zoom(), Some(1.5));
    assert_eq!(s.temperature_c(), Some(42.0));
    assert_eq!(s.frame_width(), Some(3840));
    assert_eq!(s.frame_height(), Some(2160));
    assert_eq!(s.frame_rate(), Some(29.97));
    assert_eq!(s.drone_roll_deg(), Some(0.5));
    assert_eq!(s.drone_pitch_deg(), Some(-1.0));
    assert_eq!(s.drone_yaw_deg(), Some(90.0));
    assert_eq!(s.gimbal_pitch_deg(), Some(-30.0));
    assert_eq!(s.gimbal_roll_deg(), Some(0.0));
    assert_eq!(s.gimbal_yaw_deg(), Some(45.0));
  }

  #[test]
  fn meta_identity_setters_roundtrip() {
    let mut m = DjiProtobufMeta::new();
    m.set_protocol(SmolStr::from("dvtm_wm265e.proto"));
    m.set_serial_number(SmolStr::from("ABC123"));
    m.set_model(SmolStr::from("FC8482"));
    assert_eq!(m.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(m.serial_number(), Some("ABC123"));
    assert_eq!(m.model(), Some("FC8482"));
    assert!(!m.is_empty());
  }

  #[test]
  fn first_fix_picks_first_with_lat_and_lon() {
    let mut m = DjiProtobufMeta::new();
    // Sample 0: only altitude.
    let mut s0 = DjiTelemetrySample::new();
    s0.set_absolute_altitude_m(Some(10.0));
    m.push_sample(s0);
    // Sample 1: full fix.
    let mut s1 = DjiTelemetrySample::new();
    s1.set_latitude(Some(45.0));
    s1.set_longitude(Some(8.0));
    m.push_sample(s1);
    // Sample 2: also full.
    let mut s2 = DjiTelemetrySample::new();
    s2.set_latitude(Some(46.0));
    s2.set_longitude(Some(9.0));
    m.push_sample(s2);
    let f = m.first_fix().expect("fix");
    assert_eq!(f.latitude(), Some(45.0));
    assert_eq!(f.longitude(), Some(8.0));
  }

  #[test]
  fn first_capture_picks_first_with_any_capture_field() {
    let mut m = DjiProtobufMeta::new();
    let mut s0 = DjiTelemetrySample::new();
    s0.set_latitude(Some(45.0)); // no capture
    m.push_sample(s0);
    let mut s1 = DjiTelemetrySample::new();
    s1.set_iso(Some(100.0));
    m.push_sample(s1);
    let f = m.first_capture().expect("capture");
    assert_eq!(f.iso(), Some(100.0));
  }

  #[test]
  fn push_warning_records_every_occurrence_in_order() {
    // Unlike the old first-wins single-Option model, the Vec records EVERY
    // raise — ExifTool's WAS_WARNED counts occurrences for the `[xN]` suffix, so
    // a recurring message must land once per occurrence; the emit-time collapse
    // (one `Track<N>:Warning` per distinct message, numbered + `[xN]`) is the
    // emitter's job, not the recorder's.
    let mut m = DjiProtobufMeta::new();
    m.push_warning(DjiWarning::new(SmolStr::new("first"), false));
    m.push_warning(DjiWarning::new(SmolStr::new("first"), false));
    m.push_warning(DjiWarning::new(SmolStr::new("second"), true));
    assert_eq!(m.warnings().len(), 3);
    assert_eq!(m.warnings()[0].message(), "first");
    assert!(!m.warnings()[0].minor());
    assert_eq!(m.warnings()[2].message(), "second");
    assert!(m.warnings()[2].minor(), "the third warning is minor");
  }

  #[test]
  fn stamp_warnings_from_scopes_only_the_new_warnings() {
    // The dispatch arm takes a `warning_count()` watermark, calls `process_djmd`,
    // then stamps `Track<N>` / `Doc<N>` onto exactly the warnings that call
    // appended — earlier warnings keep their own (already-stamped) scope.
    let mut m = DjiProtobufMeta::new();
    m.push_warning(DjiWarning::new(SmolStr::new("first"), false));
    m.stamp_warnings_from(0, 1, 1);
    let watermark = m.warning_count();
    m.push_warning(DjiWarning::new(SmolStr::new("second"), false));
    m.stamp_warnings_from(watermark, 2, 5);
    assert_eq!(m.warnings()[0].track_index(), 1);
    assert_eq!(m.warnings()[0].doc(), 1);
    assert_eq!(m.warnings()[1].track_index(), 2, "second warning own track");
    assert_eq!(m.warnings()[1].doc(), 5, "second warning own doc");
  }

  #[test]
  fn project_into_empty_writes_nothing() {
    let m = DjiProtobufMeta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }

  #[test]
  fn project_into_populates_camera_make_dji_with_model_and_serial() {
    let mut m = DjiProtobufMeta::new();
    m.set_protocol(SmolStr::from("dvtm_wm265e.proto"));
    m.set_serial_number(SmolStr::from("ABC123"));
    m.set_model(SmolStr::from("FC8482"));
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(40.0)).set_longitude(Some(-74.0));
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cam = md.camera().expect("camera");
    assert_eq!(cam.make(), Some("DJI"));
    assert_eq!(cam.model(), Some("FC8482"));
    assert_eq!(cam.serial(), Some("ABC123"));
    let gps = md.gps().expect("gps");
    assert_eq!(gps.latitude(), Some(40.0));
    assert_eq!(gps.longitude(), Some(-74.0));
  }

  #[test]
  fn project_into_capture_takes_first_sample_with_capture() {
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_iso(Some(800.0));
    s.set_shutter_speed_s(Some(RationalValue::Num(1.0 / 250.0)));
    s.set_f_number(Some(RationalValue::Num(2.8)));
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture");
    assert_eq!(cap.iso(), Some(800));
    assert_eq!(cap.exposure_time_s(), Some(1.0 / 250.0));
    assert_eq!(cap.f_number(), Some(2.8));
  }

  #[test]
  fn project_into_clamps_invalid_iso() {
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    // Negative ISO must drop, not panic.
    s.set_iso(Some(-1.0));
    s.set_shutter_speed_s(Some(RationalValue::Num(0.01)));
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let cap = md.capture().expect("capture");
    assert!(cap.iso().is_none());
    assert_eq!(cap.exposure_time_s(), Some(0.01));
  }

  #[test]
  fn warning_is_retained_on_the_typed_surface() {
    // `MediaMetadata` carries no warnings channel (the `md.push_warning`
    // path was removed; cf. the Parrot mett projection). The walker warning
    // is STORED on the typed surface and `project_into` is a safe no-op for
    // it — the per-format diagnostics path surfaces it at emission time.
    let mut m = DjiProtobufMeta::new();
    m.push_warning(DjiWarning::new(SmolStr::new("Unknown DJI protocol"), false));
    assert_eq!(m.warnings().len(), 1);
    assert_eq!(m.warnings()[0].message(), "Unknown DJI protocol");
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }

  #[test]
  fn synth_gps_date_time_projects_when_no_decoded_leaf() {
    // A GPS sample with only a SYNTHESIZED GPSDateTime (no decoded leaf) projects
    // it into GpsLocation.timestamp via `effective_gps_date_time`.
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(45.0))
      .set_longitude(Some(8.0))
      .set_synth_gps_date_time(Some(SmolStr::from("1970:01:01 00:00:01.000Z")));
    assert_eq!(s.gps_date_time(), None);
    assert_eq!(s.synth_gps_date_time(), Some("1970:01:01 00:00:01.000Z"));
    assert_eq!(
      s.effective_gps_date_time(),
      Some("1970:01:01 00:00:01.000Z")
    );
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(
      md.gps().expect("gps").timestamp(),
      Some("1970:01:01 00:00:01.000Z")
    );
  }

  #[test]
  fn decoded_gps_date_time_leaf_wins_over_synth_in_effective() {
    // When both are set and the leaf is Perl-TRUE, the decoded leaf wins
    // (`effective_gps_date_time` prefers a Perl-true leaf, mirroring ExifTool's
    // `not $$et{GPSDateTime}` gate leaving the decoded value in place).
    let mut s = DjiTelemetrySample::new();
    s.set_gps_date_time(Some(SmolStr::from("2025:01:15 12:34:56")));
    s.set_synth_gps_date_time(Some(SmolStr::from("1970:01:01 00:00:01.000Z")));
    assert_eq!(s.effective_gps_date_time(), Some("2025:01:15 12:34:56"));
  }

  #[test]
  fn is_perl_false_matches_perl_truthiness() {
    // `not $str` in Perl: TRUE for exactly "" and "0".
    assert!(is_perl_false(""));
    assert!(is_perl_false("0"));
    // Every other string is Perl-TRUE ⇒ NOT perl-false.
    assert!(!is_perl_false("0.0"));
    assert!(!is_perl_false("0E0"));
    assert!(!is_perl_false("00"));
    assert!(!is_perl_false(" "));
    assert!(!is_perl_false("2025:01:15 12:34:56"));
  }

  #[test]
  fn synth_when_decoded_gps_date_time_empty() {
    // A degraded sample decoded an EMPTY GPSDateTime leaf ("") alongside a GPS
    // fix. ExifTool's gate `not $$et{GPSDateTime}` is TRUE for "" ⇒ synthesis
    // STILL fires. The decoded "" leaf is preserved on the typed surface (it
    // still HandleTag's → emits under Protobuf:DJI); the projection prefers the
    // synthesized value because the leaf is Perl-FALSE.
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(45.0))
      .set_longitude(Some(8.0))
      .set_gps_date_time(Some(SmolStr::from("")));
    m.push_sample(s);
    // The predicate fires despite a Some("") leaf.
    assert!(
      m.sample_wants_synth_gps_date_time(0),
      "empty GPSDateTime leaf is Perl-false ⇒ synth fires"
    );
    m.set_sample_synth_gps_date_time(0, SmolStr::from("1970:01:01 00:00:01.000Z"));
    let row = &m.samples()[0];
    // Coexistence: the decoded "" leaf is preserved.
    assert_eq!(row.gps_date_time(), Some(""), "decoded \"\" leaf preserved");
    assert_eq!(
      row.synth_gps_date_time(),
      Some("1970:01:01 00:00:01.000Z"),
      "synthesized value stored"
    );
    // Projection prefers the synthesized value (leaf is Perl-false).
    assert_eq!(
      row.effective_gps_date_time(),
      Some("1970:01:01 00:00:01.000Z"),
      "effective prefers synth when the leaf is Perl-false"
    );
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(
      md.gps().expect("gps").timestamp(),
      Some("1970:01:01 00:00:01.000Z")
    );
  }

  #[test]
  fn synth_when_decoded_gps_date_time_zero() {
    // Same as the empty case but with the Perl-false string "0".
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(45.0))
      .set_longitude(Some(8.0))
      .set_gps_date_time(Some(SmolStr::from("0")));
    m.push_sample(s);
    assert!(
      m.sample_wants_synth_gps_date_time(0),
      "\"0\" GPSDateTime leaf is Perl-false ⇒ synth fires"
    );
    m.set_sample_synth_gps_date_time(0, SmolStr::from("1970:01:01 00:00:01.000Z"));
    let row = &m.samples()[0];
    assert_eq!(
      row.gps_date_time(),
      Some("0"),
      "decoded \"0\" leaf preserved"
    );
    assert_eq!(
      row.effective_gps_date_time(),
      Some("1970:01:01 00:00:01.000Z"),
      "effective prefers synth when the leaf is \"0\""
    );
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(
      md.gps().expect("gps").timestamp(),
      Some("1970:01:01 00:00:01.000Z")
    );
  }

  #[test]
  fn no_synth_when_decoded_gps_date_time_truthy() {
    // A real datetime leaf is Perl-TRUE ⇒ ExifTool's gate is FALSE ⇒ NO
    // synthesis. The projection uses the decoded leaf.
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(45.0))
      .set_longitude(Some(8.0))
      .set_gps_date_time(Some(SmolStr::from("2025:01:15 12:34:56")));
    m.push_sample(s);
    assert!(
      !m.sample_wants_synth_gps_date_time(0),
      "a real datetime leaf is Perl-true ⇒ no synth"
    );
    let row = &m.samples()[0];
    assert!(
      row.synth_gps_date_time().is_none(),
      "no synthesized value stored"
    );
    assert_eq!(
      row.effective_gps_date_time(),
      Some("2025:01:15 12:34:56"),
      "effective uses the decoded leaf"
    );
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(
      md.gps().expect("gps").timestamp(),
      Some("2025:01:15 12:34:56")
    );
  }

  #[test]
  fn no_synth_when_decoded_gps_date_time_is_zero_point_zero() {
    // Perl `not "0.0"` is FALSE ("0.0" is Perl-TRUE — only "" and "0" are
    // false) ⇒ NO synthesis; the leaf "0.0" is used as-is.
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(45.0))
      .set_longitude(Some(8.0))
      .set_gps_date_time(Some(SmolStr::from("0.0")));
    m.push_sample(s);
    assert!(
      !m.sample_wants_synth_gps_date_time(0),
      "\"0.0\" is Perl-TRUE ⇒ no synth"
    );
    assert_eq!(
      m.samples()[0].effective_gps_date_time(),
      Some("0.0"),
      "effective uses the Perl-true \"0.0\" leaf"
    );
  }

  #[test]
  fn project_into_prefers_absolute_altitude_over_relative() {
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(40.0));
    s.set_longitude(Some(-74.0));
    s.set_absolute_altitude_m(Some(120.0));
    s.set_relative_altitude_m(Some(30.0));
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.gps().expect("gps").altitude_m(), Some(120.0));
  }

  #[test]
  fn project_into_falls_back_to_no_altitude_when_only_relative() {
    let mut m = DjiProtobufMeta::new();
    let mut s = DjiTelemetrySample::new();
    s.set_latitude(Some(40.0));
    s.set_longitude(Some(-74.0));
    s.set_relative_altitude_m(Some(30.0));
    m.push_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    // Relative altitude is takeoff-anchored, not WGS-84 — don't surface
    // it into GpsLocation.altitude_m.
    assert!(md.gps().expect("gps").altitude_m().is_none());
  }

  #[test]
  fn empty_track_projects_no_camera() {
    // A `dbgi`-only track is a default-options no-op (DJI.pm:355 `Unknown => 2`)
    // — it decodes nothing, so its `DjiProtobufMeta` is the EMPTY value. An
    // empty track must NOT synthesise a bare `Make = "DJI"` (the false-camera
    // bug): `project_into` gates on `has_projectable_djmd()`, which is false
    // here. (The end-to-end dbgi no-op is `dbgi_is_noop_under_default_options`
    // in the `quicktime_stream` dispatch tests.)
    let m = DjiProtobufMeta::new();
    assert!(m.is_empty(), "an empty (dbgi-only) track is empty");
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(
      md.camera().is_none(),
      "an empty track must NOT project a DJI camera"
    );
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }

  #[test]
  fn project_into_camera_only_when_higher_priority_unset() {
    let mut m = DjiProtobufMeta::new();
    m.set_model(SmolStr::from("FC8482"));
    let mut md = MediaMetadata::new();
    // Pre-populate camera (simulating a higher-priority source).
    let mut existing = CameraInfo::new();
    existing.update_make(Some("ExistingMake".into()));
    md.set_camera(existing);
    m.project_into(&mut md);
    // The DJI projection skipped because md.camera() was already set.
    assert_eq!(md.camera().expect("camera").make(), Some("ExistingMake"));
  }
}
