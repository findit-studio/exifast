//! Typed mirror of `Image::ExifTool::Canon::CTMD` — the "Canon Timed
//! MetaData" records carried in a Canon EOS R-line / Cinema-line CR3 / CRM /
//! MP4 / MOV. Faithful port of `Canon.pm:9790-9887` (the `CTMD` /
//! `FocalInfo` / `ExposureInfo` tag tables) + `Canon.pm:10758-10804`
//! (`ProcessCTMD` — the per-sample record walker).
//!
//! ## Format
//!
//! Each CTMD sample is a sequence of records; each record is shaped
//!
//! ```text
//! [size:int32u-LE][type:int16u-LE][header:6 bytes][payload]
//! ```
//!
//! where `size` covers the whole record (including the 4-byte size field),
//! and `payload` is `size - 12` bytes long. ExifTool's walker enters with
//! `SetByteOrder('II')` (Canon.pm:10765) — every multi-byte int in the
//! record is little-endian.
//!
//! The 6-byte "header" past the type word is opaque per `Canon.pm:10769-10780`
//! ("what is the meaning of the 6-byte header of these records?"); bundled
//! hex-dumps it under `Verbose=3` and otherwise skips it.
//!
//! Termination cases (Canon.pm:10781-10782):
//!
//!  - `size < 12` ⇒ `Short CTMD record` warning + stop.
//!  - `pos + size > dirLen` ⇒ `Truncated CTMD record` warning + stop.
//!
//! A trailing-byte residue (the loop ends with `pos != dirLen`) emits
//! `Error parsing Canon CTMD data` (Canon.pm:10802).
//!
//! ## What this sub-port surfaces
//!
//! Per `Canon.pm:9790-9887` the camera-indexing-relevant record types are:
//!
//!  - **Type 1 — `TimeStamp`** (Canon.pm:9798-9806). 12-byte payload:
//!    skip 2, then 2-byte LE year, then mo / d / h / mi / s / centisec
//!    (1 byte each). Rendered as `"YYYY:MM:DD HH:MM:SS.cc"`.
//!  - **Type 3 —** placeholder (Canon.pm:9807 says "4 bytes, seen: ff ff ff
//!    ff"). No tag is defined in the table; the walker skips it cleanly.
//!  - **Type 4 — `FocalInfo`** (Canon.pm:9808-9811, 9853-9864). The payload
//!    is a binary table with one `rational32u` entry: `FocalLength`
//!    (`Get16u(num)/Get16u(denom)` — **rational32u is 4 bytes total**,
//!    ExifTool.pm:6089-6094). Rendered as `"%.1f mm"`.
//!  - **Type 5 — `ExposureInfo`** (Canon.pm:9812-9815, 9866-9887). Binary
//!    table:
//!     - `FNumber` rational32u @ offset 0;
//!     - `ExposureTime` rational32u @ offset 4 (stride 4 bytes because the
//!       parent `FORMAT => 'int32u'` increment is 4);
//!     - `ISO` int32u @ offset 8 (with `ValueConv => $val & 0x7fffffff` —
//!       the high bit is masked off, see Canon.pm:9885).
//!  - **Types 7 / 8 / 9 — `ExifInfo7/8/9`** (Canon.pm:9816-9827). Each
//!    routes into [`Canon::ExifInfo`] which is a TIFF-format walker
//!    over a sequence of `[len:int32u][tag:int32u][value]` records, decoding
//!    `ExifIFD` (0x8769) and `MakerNoteCanon` (0x927c). **DEFERRED** here
//!    — the embedded TIFF walker lives on the Exif chain (this branch
//!    must not touch it; see PR body deferrals).
//!  - **Types 10 / 11** — "all-zero or padded" CRM-specific blobs
//!    (Canon.pm:9828-9829). No tag is defined; the walker skips them.
//!
//! ## What this surface deliberately does NOT decode
//!
//!  - **Embedded TIFF blocks (`ExifInfo7/8/9`)** — bundled re-dispatches
//!    into `Image::ExifTool::Exif::ProcessTIFF` to recover the embedded
//!    `ExifIFD` + `MakerNoteCanon` (lens / shutter / etc.). Per the task
//!    scope this PR stays on the QuickTime chain — the TIFF parse is the
//!    Exif port's responsibility and will be wired in a follow-up.
//!  - **CTMD GPS** — Canon bodies (EOS R-line + Cinema-line) DO record
//!    GPS, but bundled stores those values inside the TIFF blocks
//!    (ExifInfo7/8/9 → `GPSInfoIFD` 0x8825), NOT as a separate CTMD record
//!    type. The `Canon::CTMD` table (Canon.pm:9790-9830) declares no
//!    `0x85xx` / GPS-family tag. Surfaced GPS therefore lands when the
//!    deferred Exif TIFF hop is wired.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, LensInfo, MediaMetadata, MetaProjectInto};

// ===========================================================================
// CanonCtmdFocal — type 4 `FocalInfo` (Canon.pm:9853-9864)
// ===========================================================================

/// One Canon CTMD `FocalInfo` decode — the `rational32u` `FocalLength` in
/// millimetres. Faithful per Canon.pm:9859-9863 (`Format => 'rational32u'`,
/// `PrintConv => 'sprintf("%.1f mm",$val)'`).
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdFocal {
  /// `FocalLength` in mm (post-`Get16u(num) / Get16u(denom)`).
  focal_length_mm: Option<f64>,
}

impl CanonCtmdFocal {
  /// An empty focal record.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      focal_length_mm: None,
    }
  }

  /// `FocalLength` in mm.
  #[inline(always)]
  #[must_use]
  pub const fn focal_length_mm(&self) -> Option<f64> {
    self.focal_length_mm
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.focal_length_mm.is_none()
  }

  /// Assign `FocalLength` (mm).
  #[inline(always)]
  pub const fn set_focal_length_mm(&mut self, v: Option<f64>) -> &mut Self {
    self.focal_length_mm = v;
    self
  }
}

impl Default for CanonCtmdFocal {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// CanonCtmdExposure — type 5 `ExposureInfo` (Canon.pm:9866-9887)
// ===========================================================================

/// One Canon CTMD `ExposureInfo` decode — FNumber, ExposureTime, ISO.
///
/// The Canon binary table is `FORMAT => 'int32u'` (4-byte stride). Tags:
///
///  - **0 — `FNumber`** `rational32u` (4 bytes: `Get16u(num)/Get16u(denom)`).
///    Bundled stores the QUOTIENT (the `RoundFloat($num/$denom, 7)` value,
///    ExifTool.pm:6094). The `PrintConv` `PrintFNumber` rounds to 1 or 2
///    decimals; exifast keeps the raw quotient (matching the bundled
///    `Value` channel under `-n`).
///  - **1 — `ExposureTime`** `rational32u` at offset 4. Stored as the
///    quotient (seconds).
///  - **2 — `ISO`** `int32u` at offset 8 with `ValueConv => '$val &
///    0x7fffffff'` (Canon.pm:9885) — the high bit is reserved/unknown
///    and masked off.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdExposure {
  /// `FNumber` (linear f-number from `num/denom`; pre-PrintFNumber rounding).
  f_number: Option<f64>,
  /// `ExposureTime` in seconds (`num/denom`).
  exposure_time_s: Option<f64>,
  /// `ISO` post-`ValueConv` (high bit masked).
  iso: Option<u32>,
}

impl CanonCtmdExposure {
  /// An empty exposure record.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      f_number: None,
      exposure_time_s: None,
      iso: None,
    }
  }

  /// `FNumber` (quotient).
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

  /// `ISO` (post-`& 0x7fffffff` masking).
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<u32> {
    self.iso
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.f_number.is_none() && self.exposure_time_s.is_none() && self.iso.is_none()
  }

  /// Assign `FNumber`.
  #[inline(always)]
  pub const fn set_f_number(&mut self, v: Option<f64>) -> &mut Self {
    self.f_number = v;
    self
  }

  /// Assign `ExposureTime` (seconds).
  #[inline(always)]
  pub const fn set_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }

  /// Assign `ISO`.
  #[inline(always)]
  pub const fn set_iso(&mut self, v: Option<u32>) -> &mut Self {
    self.iso = v;
    self
  }
}

impl Default for CanonCtmdExposure {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// CanonCtmdSample — one CTMD timed-metadata sample
// ===========================================================================

/// One Canon CTMD sample — the merged shape of every per-record-type decode
/// for ONE call into `Process_ctmd`. A sample carries at most one of each
/// record type (real-world CR3 files write each type at most once per
/// sample; the walker keeps the FIRST non-empty decode if multiple
/// instances of the same type appear).
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdSample {
  /// `TimeStamp` (Canon.pm:9798-9806) — `"YYYY:MM:DD HH:MM:SS.cc"`.
  time_stamp: Option<SmolStr>,
  /// `FocalInfo` (type 4) decoded fields.
  focal: Option<CanonCtmdFocal>,
  /// `ExposureInfo` (type 5) decoded fields.
  exposure: Option<CanonCtmdExposure>,
}

impl CanonCtmdSample {
  /// An empty sample.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      time_stamp: None,
      focal: None,
      exposure: None,
    }
  }

  /// `TimeStamp` (Canon.pm:9798-9806).
  #[inline(always)]
  #[must_use]
  pub fn time_stamp(&self) -> Option<&str> {
    self.time_stamp.as_deref()
  }

  /// `FocalInfo` decode (Canon.pm:9853-9864).
  #[inline(always)]
  #[must_use]
  pub const fn focal(&self) -> Option<&CanonCtmdFocal> {
    self.focal.as_ref()
  }

  /// `ExposureInfo` decode (Canon.pm:9866-9887).
  #[inline(always)]
  #[must_use]
  pub const fn exposure(&self) -> Option<&CanonCtmdExposure> {
    self.exposure.as_ref()
  }

  /// `true` when every record is `None`.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.time_stamp.is_none() && self.focal.is_none() && self.exposure.is_none()
  }

  /// Assign `TimeStamp`.
  #[inline(always)]
  pub fn set_time_stamp(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.time_stamp = v;
    self
  }

  /// Assign the `FocalInfo` record (keeps the FIRST non-empty decode when
  /// called multiple times within the same sample).
  #[inline]
  pub fn set_focal(&mut self, v: Option<CanonCtmdFocal>) -> &mut Self {
    if self.focal.is_none() {
      self.focal = v;
    }
    self
  }

  /// Assign the `ExposureInfo` record (keeps the FIRST non-empty decode
  /// when called multiple times within the same sample).
  #[inline]
  pub fn set_exposure(&mut self, v: Option<CanonCtmdExposure>) -> &mut Self {
    if self.exposure.is_none() {
      self.exposure = v;
    }
    self
  }
}

impl Default for CanonCtmdSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// CanonCtmdMeta — the aggregate per-track result
// ===========================================================================

/// The typed result of Canon CTMD extraction — the per-format mirror of
/// what `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) emits
/// over every CTMD timed-metadata sample of a CR3 / CRM / MOV / MP4
/// container.
///
/// Each CTMD sample yields ONE [`CanonCtmdSample`] (which itself may
/// carry a TimeStamp, FocalInfo, and/or ExposureInfo). The vector is in
/// source order; the `MediaMetadata` projection uses the FIRST non-empty
/// entry of each record type.
///
/// Empty (`is_empty()`) when no CTMD track is present or every sample
/// failed to decode.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdMeta {
  /// One per CTMD sample. Empty when no CTMD records were decoded.
  samples: Vec<CanonCtmdSample>,
  /// `ProcessCTMD`-level warnings (Canon.pm:10781, 10782, 10802).
  /// Only the FIRST warning is retained, matching the bundled `-j`
  /// rendering.
  warning: Option<SmolStr>,
}

impl CanonCtmdMeta {
  /// An empty result (no CTMD data decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      samples: Vec::new(),
      warning: None,
    }
  }

  /// One [`CanonCtmdSample`] per CTMD sample.
  #[inline(always)]
  #[must_use]
  pub fn samples(&self) -> &[CanonCtmdSample] {
    self.samples.as_slice()
  }

  /// The first decoded warning (e.g. `Short CTMD record`).
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no sample was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.samples.is_empty()
  }

  /// The FIRST sample whose `focal` is populated — feeds the
  /// [`crate::metadata::LensInfo`] projection.
  #[inline]
  #[must_use]
  pub fn first_focal(&self) -> Option<&CanonCtmdFocal> {
    self.samples.iter().find_map(|s| s.focal.as_ref())
  }

  /// The FIRST sample whose `exposure` is populated — feeds the
  /// [`crate::metadata::CaptureSettings`] projection.
  #[inline]
  #[must_use]
  pub fn first_exposure(&self) -> Option<&CanonCtmdExposure> {
    self.samples.iter().find_map(|s| s.exposure.as_ref())
  }

  /// The FIRST sample whose `time_stamp` is populated.
  #[inline]
  #[must_use]
  pub fn first_time_stamp(&self) -> Option<&str> {
    self.samples.iter().find_map(|s| s.time_stamp.as_deref())
  }

  /// Append a decoded CTMD sample.
  #[inline(always)]
  pub fn push_sample(&mut self, sample: CanonCtmdSample) -> &mut Self {
    self.samples.push(sample);
    self
  }

  /// Set the first `ProcessCTMD` warning (subsequent calls are ignored —
  /// bundled `-j` reports only the first).
  #[inline]
  pub fn set_warning(&mut self, msg: SmolStr) -> &mut Self {
    if self.warning.is_none() {
      self.warning = Some(msg);
    }
    self
  }
}

impl Default for CanonCtmdMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — Canon CTMD projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for CanonCtmdMeta {
  /// Project Canon CTMD metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** Canon CTMD does NOT carry a Make/Model record — the
  /// CTMD table itself (Canon.pm:9790-9830) declares no identity fields;
  /// body model lives inside the embedded TIFF blocks (`ExifInfo7/8/9`,
  /// types 7/8/9) whose decode is DEFERRED to the Exif chain (#82). So
  /// today's projection sets only `Make = "Canon"` whenever any CTMD
  /// sample decoded (proof we saw a Canon CTMD track) and leaves
  /// Model/Serial empty for the future TIFF hop. Skips when a higher-
  /// priority source (GoPro / Sony rtmd) already set camera identity.
  ///
  /// **CaptureSettings:** the FIRST sample with non-empty exposure
  /// populates `md.capture()` (FNumber / ExposureTime / ISO from CTMD
  /// type-3 ExposureInfo, Canon.pm:9866-9879).
  ///
  /// **LensInfo:** the FIRST sample with non-empty focal info populates
  /// `md.lens()` (FocalLength from CTMD type-4 FocalInfo, Canon.pm:9853-
  /// 9864). Canon CTMD does NOT carry a LensModel string (also Exif-chain).
  ///
  /// **GpsLocation:** Canon CTMD does NOT currently surface GPS (deferred
  /// to #82 — Canon writes GPS via the embedded Exif TIFF blocks, not
  /// CTMD records directly); when it does, it would slot at the same
  /// tier as Sony rtmd (Canon body, phone-paired).
  ///
  /// **Warnings:** any ProcessCTMD `warning()` (Short / Truncated /
  /// `Error parsing Canon CTMD data`) propagates into `md.warnings()`
  /// with the `"[Canon CTMD] "` prefix.
  fn project_into(&self, md: &mut MediaMetadata) {
    if self.is_empty() {
      // Still need to surface a possibly-set warning even when the
      // payload was empty (e.g. truncated header).
      if let Some(w) = self.warning() {
        push_canon_warning(md, w);
      }
      return;
    }
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none() {
      let mut cam = CameraInfo::new();
      cam.update_make(Some("Canon".into()));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── CaptureSettings ────────────────────────────────────────────────
    if md.capture().is_none()
      && let Some(exp) = self.first_exposure()
    {
      let mut cap = CaptureSettings::new();
      cap.update_exposure_time_s(exp.exposure_time_s());
      cap.update_iso(exp.iso());
      cap.update_f_number(exp.f_number());
      if !cap.is_empty() {
        md.set_capture(cap);
      }
    }
    // ── LensInfo ───────────────────────────────────────────────────────
    if md.lens().is_none()
      && let Some(focal) = self.first_focal()
    {
      let mut lens = LensInfo::new();
      lens.update_focal_length_mm(focal.focal_length_mm());
      if !lens.is_empty() {
        md.set_lens(lens);
      }
    }
    // ── Warnings ───────────────────────────────────────────────────────
    if let Some(w) = self.warning() {
      push_canon_warning(md, w);
    }
  }
}

/// Append a Canon CTMD warning with the standard `"[Canon CTMD] "` prefix.
fn push_canon_warning(md: &mut MediaMetadata, w: &str) {
  let mut msg = String::with_capacity(13 + w.len());
  msg.push_str("[Canon CTMD] ");
  msg.push_str(w);
  md.push_warning(msg);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_meta_is_empty() {
    let m = CanonCtmdMeta::new();
    assert!(m.is_empty());
    assert!(m.samples().is_empty());
    assert!(m.first_focal().is_none());
    assert!(m.first_exposure().is_none());
    assert!(m.first_time_stamp().is_none());
    assert!(m.warning().is_none());
  }

  #[test]
  fn focal_record_get_set_roundtrip() {
    let mut f = CanonCtmdFocal::new();
    assert!(f.is_empty());
    f.set_focal_length_mm(Some(15.0));
    assert_eq!(f.focal_length_mm(), Some(15.0));
    assert!(!f.is_empty());
  }

  #[test]
  fn exposure_record_get_set_roundtrip() {
    let mut e = CanonCtmdExposure::new();
    assert!(e.is_empty());
    e.set_f_number(Some(3.5));
    e.set_exposure_time_s(Some(0.0125));
    e.set_iso(Some(12800));
    assert_eq!(e.f_number(), Some(3.5));
    assert_eq!(e.exposure_time_s(), Some(0.0125));
    assert_eq!(e.iso(), Some(12800));
    assert!(!e.is_empty());
  }

  #[test]
  fn sample_keeps_first_non_empty_focal() {
    let mut s = CanonCtmdSample::new();
    let mut first = CanonCtmdFocal::new();
    first.set_focal_length_mm(Some(15.0));
    s.set_focal(Some(first));
    // A second set must NOT overwrite the first.
    let mut second = CanonCtmdFocal::new();
    second.set_focal_length_mm(Some(50.0));
    s.set_focal(Some(second));
    assert_eq!(s.focal().unwrap().focal_length_mm(), Some(15.0));
  }

  #[test]
  fn sample_keeps_first_non_empty_exposure() {
    let mut s = CanonCtmdSample::new();
    let mut first = CanonCtmdExposure::new();
    first.set_iso(Some(100));
    s.set_exposure(Some(first));
    let mut second = CanonCtmdExposure::new();
    second.set_iso(Some(12800));
    s.set_exposure(Some(second));
    assert_eq!(s.exposure().unwrap().iso(), Some(100));
  }

  #[test]
  fn meta_first_accessors_pick_first_populated_sample() {
    let mut m = CanonCtmdMeta::new();
    // Sample 0: only TimeStamp.
    let mut a = CanonCtmdSample::new();
    a.set_time_stamp(Some(SmolStr::new("2018:02:21 12:08:56.21")));
    m.push_sample(a);
    // Sample 1: FocalInfo + Exposure.
    let mut b = CanonCtmdSample::new();
    let mut focal = CanonCtmdFocal::new();
    focal.set_focal_length_mm(Some(50.0));
    b.set_focal(Some(focal));
    let mut exp = CanonCtmdExposure::new();
    exp.set_iso(Some(800));
    b.set_exposure(Some(exp));
    m.push_sample(b);
    assert_eq!(m.first_time_stamp(), Some("2018:02:21 12:08:56.21"));
    assert_eq!(m.first_focal().unwrap().focal_length_mm(), Some(50.0));
    assert_eq!(m.first_exposure().unwrap().iso(), Some(800));
  }

  #[test]
  fn warning_set_once() {
    let mut m = CanonCtmdMeta::new();
    m.set_warning(SmolStr::new("first"));
    m.set_warning(SmolStr::new("second"));
    assert_eq!(m.warning(), Some("first"));
  }
}
