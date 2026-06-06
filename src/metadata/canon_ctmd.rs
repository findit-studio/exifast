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
use alloc::vec::Vec;

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, LensInfo, MediaMetadata};
use crate::value::Rational;

// ===========================================================================
// CanonCtmdFocal — type 4 `FocalInfo` (Canon.pm:9853-9864)
// ===========================================================================

/// One Canon CTMD `FocalInfo` decode — the `rational32u` `FocalLength` in
/// millimetres. Faithful per Canon.pm:9859-9863 (`Format => 'rational32u'`,
/// `PrintConv => 'sprintf("%.1f mm",$val)'`).
///
/// The value is stored as the raw `rational32u` [`Rational`] (num/denom, NOT
/// pre-divided), so the `-n` emission renders ExifTool's `GetRational32u`
/// `%.7g` form (e.g. `10/3` → `3.333333`, NOT the 15-digit f64) and a zero
/// denominator stays the bare `inf`/`undef` word. `Rational::rational32`
/// carries `sig = 7` (`ExifTool.pm:6094` `RoundFloat(n/d, 7)`). The f64-mm
/// accessor computes the quotient on demand for the cross-format domain layer
/// and the `%.1f mm` PrintConv.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdFocal {
  /// `FocalLength` as the raw `rational32u` (`Get16u(num)` / `Get16u(denom)`).
  focal_length: Option<Rational>,
}

impl CanonCtmdFocal {
  /// An empty focal record.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self { focal_length: None }
  }

  /// `FocalLength` in mm — the `rational32u` quotient computed on demand (the
  /// value the cross-format domain layer consumes). A zero denominator yields
  /// `inf` / `NaN` (Perl's float coercion of the rational scalar).
  #[inline(always)]
  #[must_use]
  pub fn focal_length_mm(&self) -> Option<f64> {
    self.focal_length.map(|r| r.to_f64())
  }

  /// `FocalLength` as the raw `rational32u` (num/denom) — the value the `-n`
  /// emission renders via ExifTool's `GetRational32u` `%.7g` formatter (the
  /// `inf` / `undef` words for a zero denominator are handled by the
  /// [`Rational`] serializer).
  #[inline(always)]
  #[must_use]
  pub const fn focal_length_rational(&self) -> Option<Rational> {
    self.focal_length
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.focal_length.is_none()
  }

  /// Assign `FocalLength` as the raw `rational32u` (num/denom).
  #[inline(always)]
  pub const fn set_focal_length(&mut self, v: Option<Rational>) -> &mut Self {
    self.focal_length = v;
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
///    Stored as the raw [`Rational`] (num/denom, NOT pre-divided), so the
///    `-n` emission renders ExifTool's `GetRational32u` `%.7g` form
///    (`ExifTool.pm:6094` `RoundFloat(n/d, 7)`) and a zero denominator stays
///    the bare `inf`/`undef` word. The `PrintConv` `PrintFNumber` rounds the
///    quotient to 1-2 decimals at `-j`.
///  - **1 — `ExposureTime`** `rational32u` at offset 4. Stored as the raw
///    [`Rational`] (seconds); the f64 accessor computes the quotient.
///  - **2 — `ISO`** `int32u` at offset 8 with `ValueConv => '$val &
///    0x7fffffff'` (Canon.pm:9885) — the high bit is reserved/unknown
///    and masked off.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdExposure {
  /// `FNumber` as the raw `rational32u` (`Get16u(num)` / `Get16u(denom)`).
  f_number: Option<Rational>,
  /// `ExposureTime` as the raw `rational32u` (seconds).
  exposure_time: Option<Rational>,
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
      exposure_time: None,
      iso: None,
    }
  }

  /// `FNumber` (the `rational32u` quotient, computed on demand) — the value
  /// the cross-format domain layer consumes. A zero denominator yields `inf`
  /// / `NaN`.
  #[inline(always)]
  #[must_use]
  pub fn f_number(&self) -> Option<f64> {
    self.f_number.map(|r| r.to_f64())
  }

  /// `FNumber` as the raw `rational32u` (num/denom) — the value the `-n`
  /// emission renders via ExifTool's `GetRational32u` `%.7g` formatter.
  #[inline(always)]
  #[must_use]
  pub const fn f_number_rational(&self) -> Option<Rational> {
    self.f_number
  }

  /// `ExposureTime` in seconds — the `rational32u` quotient computed on demand.
  #[inline(always)]
  #[must_use]
  pub fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time.map(|r| r.to_f64())
  }

  /// `ExposureTime` as the raw `rational32u` (num/denom) — the value the `-n`
  /// emission renders via ExifTool's `GetRational32u` `%.7g` formatter.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_rational(&self) -> Option<Rational> {
    self.exposure_time
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
    self.f_number.is_none() && self.exposure_time.is_none() && self.iso.is_none()
  }

  /// Assign `FNumber` as the raw `rational32u` (num/denom).
  #[inline(always)]
  pub const fn set_f_number(&mut self, v: Option<Rational>) -> &mut Self {
    self.f_number = v;
    self
  }

  /// Assign `ExposureTime` as the raw `rational32u` (num/denom).
  #[inline(always)]
  pub const fn set_exposure_time(&mut self, v: Option<Rational>) -> &mut Self {
    self.exposure_time = v;
    self
  }

  /// Assign `ISO`.
  #[inline(always)]
  pub const fn set_iso(&mut self, v: Option<u32>) -> &mut Self {
    self.iso = v;
    self
  }

  /// Merge the PRESENT (`Some`) fields of `other` over `self`, leaving every
  /// field `other` did not carry (`None`) untouched.
  ///
  /// Faithful to bundled's PER-TAG duplicate resolution: `ProcessBinaryData`
  /// emits ONLY the `ExposureInfo` fields whose offset fits the current record's
  /// payload (`ExifTool.pm:9917-9918`/`:9963-9964`), and a duplicate is resolved
  /// independently per emitted tag NAME (`ExifTool.pm:9514-9565`). So a partial
  /// `ExposureInfo` record (e.g. a 4-byte payload carrying only `FNumber`)
  /// overwrites JUST that tag and PRESERVES the `ExposureTime` / `ISO` an earlier
  /// fuller record decoded — it does NOT clobber them with the absent (`None`)
  /// fields. (A full record still overwrites every field, so the full-record
  /// last-wins behaviour is unchanged.)
  #[inline]
  pub fn merge_present(&mut self, other: &Self) -> &mut Self {
    if other.f_number.is_some() {
      self.f_number = other.f_number;
    }
    if other.exposure_time.is_some() {
      self.exposure_time = other.exposure_time;
    }
    if other.iso.is_some() {
      self.iso = other.iso;
    }
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
// CanonCtmdWarning — one ProcessCTMD / TimeStamp-RawConv warning
// ===========================================================================

/// One Canon CTMD warning, scoped to the timed SAMPLE that raised it.
///
/// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) raises three
/// walk-abort warnings — `Short CTMD record` (size < 12, Canon.pm:10781),
/// `Truncated CTMD record` (`pos + size > dirLen`, Canon.pm:10782) and
/// `Error parsing Canon CTMD data` (trailing-byte residue, Canon.pm:10802; a
/// `Warn(..., 1)` ⇒ MINOR, bundled prefixes `[minor] `). The type-1
/// `TimeStamp` `RawConv` (Canon.pm:9801-9805) raises two more when its
/// `unpack('x2vCCCCCC', $val)` runs on a SHORT payload — `'x' outside of
/// string in unpack` (len 0-1, the `x2` skip itself fails) and `Missing
/// argument in sprintf` (len 2-9, some `%.2d` fields have no value). All five
/// surface as `Doc<N>:Track<N>:Warning` through ONE channel: `ProcessSamples`
/// opens a `Doc<N>` per sample (`FoundSomething`) and `$et->Warn` `FoundTag`s
/// the `Warning` under that open `DOC_NUM` (oracle-verified vs bundled 13.59),
/// scoped to the trak's `Track<N>` (`SET_GROUP1`). They share ExifTool's
/// priority-0 first-wins `Warning` slot and its WAS_WARNED `[xN]` string-dedup
/// — IDENTICAL machinery to [`crate::metadata::CammWarning`].
///
/// The `minor` flag distinguishes the residue warning (`Warn(..., 1)` ⇒
/// rendered `[minor] Error parsing Canon CTMD data`) from the four non-minor
/// ones; the emission applies the `[minor] ` prefix only when it is set.
///
/// **D8 compliance.** Fields are private; access via the accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdWarning {
  /// The warning string WITHOUT any `[minor]` prefix (the prefix is applied at
  /// emit time from [`Self::minor`]).
  message: SmolStr,
  /// `true` for the `Warn(..., 1)` MINOR residue warning (`Error parsing Canon
  /// CTMD data`); `false` for the four non-minor ones.
  minor: bool,
  /// The 1-based moov `Track<N>` index the warning is scoped to (`None` until
  /// the walker stamps it; defaults to `Track1` at emit time).
  track_index: Option<u32>,
  /// The GLOBAL `Doc<N>` ordinal of the CTMD sample that raised the warning
  /// (`None` until the walker stamps it). Surfaced as the `Doc<N>:` family-3
  /// prefix at `-G3:1`; collapsed away at `-G1`.
  doc: Option<u32>,
  /// `SampleTime` (seconds) of the CTMD sample that raised the warning —
  /// emitted ahead of the `Warning` under that sample's `Doc<N>`. `None` until
  /// the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` (seconds) of the CTMD sample that raised the warning
  /// (paired with [`Self::sample_time`]). `None` until the walker stamps it.
  sample_duration: Option<f64>,
}

impl CanonCtmdWarning {
  /// Build a warning carrying `message` and the `minor` flag (no track / doc /
  /// timing yet — the walker stamps them after the `process_ctmd` call).
  #[inline(always)]
  #[must_use]
  pub fn new(message: SmolStr, minor: bool) -> Self {
    Self {
      message,
      minor,
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// The warning string WITHOUT the `[minor]` prefix.
  #[inline(always)]
  #[must_use]
  pub fn message(&self) -> &str {
    self.message.as_str()
  }

  /// `true` for the MINOR residue warning (`Error parsing Canon CTMD data`,
  /// `Warn(..., 1)`) — the emission prepends `[minor] `.
  #[inline(always)]
  #[must_use]
  pub const fn minor(&self) -> bool {
    self.minor
  }

  /// The 1-based moov `Track<N>` index this warning is scoped to.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// The GLOBAL `Doc<N>` ordinal of the CTMD sample that raised this warning.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `SampleTime` (seconds) of the CTMD sample that raised this warning.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` (seconds) of the CTMD sample that raised this warning.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the 1-based moov `Track<N>` index (walker-only).
  #[inline(always)]
  pub(crate) const fn set_track_index(&mut self, v: Option<u32>) -> &mut Self {
    self.track_index = v;
    self
  }

  /// Stamp the GLOBAL `Doc<N>` ordinal (walker-only).
  #[inline(always)]
  pub(crate) const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// Stamp the sample-table `SampleTime` / `SampleDuration` (seconds) of the
  /// CTMD sample that raised this warning (walker-only).
  #[inline(always)]
  pub(crate) const fn set_sample_timing(
    &mut self,
    time: Option<f64>,
    duration: Option<f64>,
  ) -> &mut Self {
    self.sample_time = time;
    self.sample_duration = duration;
    self
  }
}

// ===========================================================================
// CtmdExifInfo — type 7/8/9 `ExifInfo*` re-dispatch (Canon.pm:9818-9853)
// ===========================================================================

/// Which `%Canon::ExifInfo` entry an embedded TIFF block was tagged as —
/// `Canon.pm:9838`/`:9845`. `ProcessExifInfo` (Canon.pm:10730-10754) walks the
/// `[len:int32u-LE][tag:int32u-LE][TIFF]` records, keeping only the two tags
/// the table declares; the block's `tag` selects the re-dispatch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtmdExifTag {
  /// `0x8769` — `ExifIFD`: a full TIFF re-dispatched through
  /// `Image::ExifTool::Exif::Main` (`Canon.pm:9838-9844`, `ProcessProc =>
  /// ProcessTIFF`). The recovered EXIF/GPS tags emit under family-0 `EXIF`.
  ExifIfd,
  /// `0x927c` — `MakerNoteCanon`: a full TIFF whose IFD0 IS the Canon
  /// MakerNote, re-dispatched through `Image::ExifTool::Canon::Main`
  /// (`Canon.pm:9845-9852`, `MakerNotes => 1`, `ProcessProc => ProcessTIFF`).
  /// The recovered tags emit under family-0 `MakerNotes`.
  MakerNoteCanon,
}

impl CtmdExifTag {
  /// The raw `%Canon::ExifInfo` tag id (`0x8769` / `0x927c`).
  #[inline(always)]
  #[must_use]
  pub const fn tag_id(self) -> u32 {
    match self {
      Self::ExifIfd => 0x8769,
      Self::MakerNoteCanon => 0x927c,
    }
  }

  /// Map a `ProcessExifInfo` record tag to its [`CtmdExifTag`], or `None` for a
  /// tag the `%Canon::ExifInfo` table does not declare (the walker's
  /// `not $$tagTablePtr{$tag}` stop condition, `Canon.pm:10743`).
  #[inline(always)]
  #[must_use]
  pub const fn from_tag_id(tag: u32) -> Option<Self> {
    match tag {
      0x8769 => Some(Self::ExifIfd),
      0x927c => Some(Self::MakerNoteCanon),
      _ => None,
    }
  }

  /// `true` for the `ExifIFD` (`0x8769`) re-dispatch.
  #[inline(always)]
  #[must_use]
  pub const fn is_exif_ifd(self) -> bool {
    matches!(self, Self::ExifIfd)
  }

  /// `true` for the `MakerNoteCanon` (`0x927c`) re-dispatch.
  #[inline(always)]
  #[must_use]
  pub const fn is_maker_note(self) -> bool {
    matches!(self, Self::MakerNoteCanon)
  }
}

/// One embedded `ExifInfo*` TIFF block recovered by `ProcessExifInfo`
/// (Canon.pm:10730-10754) — the `[len][tag][TIFF]` record's `tag` (which table
/// it re-dispatches into) plus the owned `len - 8` TIFF bytes.
///
/// The TIFF is stored RAW (not pre-decoded) because the EXIF/MakerNote value
/// conversion is mode-dependent (`-j` PrintConv vs `-n` ValueConv); the
/// emission re-walks it through the SAME Exif / Canon-MakerNote machinery the
/// static-file path uses, once per output mode. Out-of-line value offsets in
/// the block are relative to its own start (ExifTool's `Base => $$dirInfo{Base}
/// + $pos + 8`, `DataPos => -($pos + 8)`, `Canon.pm:10747-10748`), so the block
/// is self-contained and walks at base 0.
///
/// ## Threaded `$$self{Model}` (per-sample, walk-order)
///
/// `ProcessExifInfo` processes a sample's `ExifInfo` entries IN ORDER
/// (Canon.pm:10739-10751). An earlier `0x8769` `ExifIFD` re-dispatch can set
/// `$$self{Model}` from its embedded TIFF's IFD0 `Model` (`0x0110`,
/// `Exif.pm:567-575` — bundled stores `$$self{Model}` from the top-level Exif
/// walk), and a LATER `0x927c` `MakerNoteCanon` entry's `Canon::Main` decode
/// then keys MODEL-CONDITIONAL tags on it (e.g. `Canon::ShotInfo`
/// `CameraTemperature`, `Canon.pm:2866-2877`; `Canon::FileInfo` position 1,
/// `Canon.pm:6848-6927`). Because each block is re-walked INDEPENDENTLY at emit
/// time, the model in effect at this block's walk position is captured HERE (at
/// parse time, where the entries are already walked in order) and threaded into
/// the emit-time `redispatch_ctmd_makernote` instead of an unconditional `None`
/// — so a crafted sample whose `0x8769` carries a `Model` that triggers a
/// model-conditional `0x927c` tag stays byte-exact vs bundled at `-ee -j` / `-n`.
/// `None` for an `ExifIFD` block (the `0x8769` re-dispatch consumes no model)
/// and for a `MakerNoteCanon` block with no preceding in-sample `0x8769` Model.
///
/// **D8 compliance.** Every field is private; access via the accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct CtmdExifInfo {
  /// Which `%Canon::ExifInfo` table this block re-dispatches into.
  tag: CtmdExifTag,
  /// The owned `len - 8` TIFF bytes (header + IFD), walked at base 0.
  tiff: Vec<u8>,
  /// The `$$self{Model}` in effect at this block's walk position — the TRIMMED
  /// IFD0 `Model` (`0x0110`) of the most recent preceding in-sample `0x8769`
  /// `ExifIFD` block, threaded into the emit-time `Canon::Main` re-dispatch for
  /// MODEL-CONDITIONAL tags. `None` for a `0x8769` block and for a `0x927c`
  /// block with no preceding in-sample `0x8769` Model.
  model: Option<SmolStr>,
}

impl CtmdExifInfo {
  /// Capture one re-dispatch block from its `%Canon::ExifInfo` tag + TIFF bytes,
  /// with no threaded `$$self{Model}` (a `0x8769` block, or a `0x927c` block
  /// reached with no preceding in-sample `0x8769` Model).
  #[inline(always)]
  #[must_use]
  pub const fn new(tag: CtmdExifTag, tiff: Vec<u8>) -> Self {
    Self {
      tag,
      tiff,
      model: None,
    }
  }

  /// Capture one re-dispatch block carrying the `$$self{Model}` in effect at its
  /// walk position — the trimmed IFD0 `Model` of the most recent preceding
  /// in-sample `0x8769` `ExifIFD` block. Used for a `0x927c` `MakerNoteCanon`
  /// block so the emit-time `Canon::Main` re-dispatch evaluates model-conditional
  /// tags (`Canon::ShotInfo` `CameraTemperature`, `Canon::FileInfo` position 1)
  /// against the handed-off Model — faithful to bundled's in-order
  /// `ProcessExifInfo` state (Canon.pm:10739-10751).
  #[inline(always)]
  #[must_use]
  pub const fn with_model(tag: CtmdExifTag, tiff: Vec<u8>, model: Option<SmolStr>) -> Self {
    Self { tag, tiff, model }
  }

  /// Which `%Canon::ExifInfo` table this block re-dispatches into.
  #[inline(always)]
  #[must_use]
  pub const fn tag(&self) -> CtmdExifTag {
    self.tag
  }

  /// The owned TIFF bytes (header + IFD), walked at base 0.
  #[inline(always)]
  #[must_use]
  pub fn tiff(&self) -> &[u8] {
    self.tiff.as_slice()
  }

  /// The `$$self{Model}` in effect at this block's walk position (the trimmed
  /// IFD0 `Model` of the most recent preceding in-sample `0x8769` `ExifIFD`
  /// block), threaded into the emit-time `Canon::Main` re-dispatch for
  /// model-conditional tags. `None` for a `0x8769` block / a `0x927c` block with
  /// no preceding in-sample Model.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }
}

// ===========================================================================
// CanonCtmdSample — one CTMD timed-metadata sample
// ===========================================================================

/// One Canon CTMD sample — the merged shape of every per-record-type decode
/// for ONE call into `Process_ctmd`. A sample carries at most one of each
/// record type (real-world CR3 files write each type at most once per
/// sample; if multiple instances of the same type appear the walker keeps
/// the LAST decode — bundled `HandleTag`s every record and a duplicate
/// same-Doc tag lets the later value win, ExifTool.pm:9437-9519).
///
/// The `doc` / `track_index` / `sample_time` / `sample_duration` fields are
/// the per-sample sub-document / track / sample-table coordinates; they are
/// STAMPED after extraction by [`CanonCtmdMeta`] (see its `stamp_*` methods),
/// mirroring the [`crate::metadata::SonyRtmdSample`] stamping pattern.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below. The stamped fields have no public setters — stamping is
/// driven by the `pub(crate)` methods on [`CanonCtmdMeta`].
#[derive(Debug, Clone, PartialEq)]
pub struct CanonCtmdSample {
  /// `TimeStamp` (Canon.pm:9798-9806) — `"YYYY:MM:DD HH:MM:SS.cc"`.
  time_stamp: Option<SmolStr>,
  /// `FocalInfo` (type 4) decoded fields.
  focal: Option<CanonCtmdFocal>,
  /// `ExposureInfo` (type 5) decoded fields.
  exposure: Option<CanonCtmdExposure>,
  /// `ExifInfo7/8/9` (types 7/8/9) embedded TIFF blocks, in walk order — each
  /// an `ExifIFD` (`0x8769`) or `MakerNoteCanon` (`0x927c`) re-dispatch
  /// (Canon.pm:9818-9853). Re-walked at emit time through the Exif /
  /// Canon-MakerNote machinery.
  exif_info: Vec<CtmdExifInfo>,
  /// Family-3 sub-document ordinal (`0` = unstamped / Main). Stamped later.
  doc: u32,
  /// Family-1 `Track<N>` index (1-based; `0` = unstamped). Stamped later.
  track_index: u32,
  /// Sample-table `SampleTime` in seconds. Stamped later.
  sample_time: Option<f64>,
  /// Sample-table `SampleDuration` in seconds. Stamped later.
  sample_duration: Option<f64>,
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
      exif_info: Vec::new(),
      doc: 0,
      track_index: 0,
      sample_time: None,
      sample_duration: None,
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

  /// The `ExifInfo7/8/9` embedded TIFF blocks (types 7/8/9), in walk order —
  /// each re-dispatched at emit time into the Exif (`0x8769`) or Canon
  /// MakerNote (`0x927c`) walker (Canon.pm:9818-9853).
  #[inline(always)]
  #[must_use]
  pub fn exif_info(&self) -> &[CtmdExifInfo] {
    self.exif_info.as_slice()
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

  /// `true` when every record is `None` and no `ExifInfo*` block was captured.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.time_stamp.is_none()
      && self.focal.is_none()
      && self.exposure.is_none()
      && self.exif_info.is_empty()
  }

  /// Assign `TimeStamp`.
  #[inline(always)]
  pub fn set_time_stamp(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.time_stamp = v;
    self
  }

  /// Assign the `FocalInfo` record. LAST-WINS within a sample: bundled
  /// `HandleTag`s every CTMD record (Canon.pm:10790-10800) and a duplicate
  /// same-Doc tag lets the later value win (ExifTool.pm:9437-9519), so a
  /// repeated type-4 record overwrites the earlier decode.
  #[inline]
  pub fn set_focal(&mut self, v: Option<CanonCtmdFocal>) -> &mut Self {
    self.focal = v;
    self
  }

  /// Assign the `ExposureInfo` record. LAST-WINS within a sample (see
  /// [`Self::set_focal`] — bundled `HandleTag` + later-duplicate-wins).
  #[inline]
  pub fn set_exposure(&mut self, v: Option<CanonCtmdExposure>) -> &mut Self {
    self.exposure = v;
    self
  }

  /// Merge one decoded `ExposureInfo` record into the sample PER FIELD —
  /// overwriting only the fields this record carried (`Some`) and preserving an
  /// earlier record's sibling fields it did not.
  ///
  /// Bundled `HandleTag`s every CTMD record (`Canon.pm:10792-10798`), and
  /// `ExposureInfo` is a `ProcessBinaryData` subtable of THREE independent field
  /// tags (`FNumber` @0 / `ExposureTime` @4 / `ISO` @8, `Canon.pm:9874-9887`).
  /// `ProcessBinaryData` emits only the fields whose offset fits the current
  /// payload (`ExifTool.pm:9917-9918`/`:9963-9964`) and duplicate resolution is
  /// per emitted tag NAME (`ExifTool.pm:9514-9565`), so a FULL record followed by
  /// a partial (e.g. 4-byte → only `FNumber`) overwrites JUST `FNumber` and keeps
  /// the earlier `ExposureTime` + `ISO`. The first record installs the struct;
  /// each later record merges its present fields over it (oracle-verified vs
  /// bundled 13.59: a full → 8-byte → 4-byte type-5 chain yields the LAST
  /// `FNumber`, the 8-byte `ExposureTime`, and the full record's `ISO`).
  #[inline]
  pub fn merge_exposure(&mut self, v: CanonCtmdExposure) -> &mut Self {
    match self.exposure.as_mut() {
      Some(existing) => {
        existing.merge_present(&v);
      }
      None => self.exposure = Some(v),
    }
    self
  }

  /// Append one `ExifInfo*` (type 7/8/9) re-dispatch block. Unlike the
  /// scalar records, every block is retained in walk order — a single CTMD
  /// `ExifInfo*` record can carry BOTH an `ExifIFD` and a `MakerNoteCanon`
  /// entry (Canon.pm:9818's "ExifIFD + MakerNotes"), and `ProcessExifInfo`
  /// `HandleTag`s each.
  #[inline(always)]
  pub fn push_exif_info(&mut self, info: CtmdExifInfo) -> &mut Self {
    self.exif_info.push(info);
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
  /// `ProcessCTMD` / `TimeStamp`-RawConv warnings (Canon.pm:10781, 10782,
  /// 10802, 9801-9805), in raise order. Each carries the SAMPLE it was raised
  /// under (doc / track / timing, stamped by the walker) so the emission can
  /// surface it as a `Doc<N>:Track<N>:Warning` — mirroring
  /// [`crate::metadata::CammWarning`]. The priority-0 first-wins + WAS_WARNED
  /// `[xN]` dedup are applied at emit time.
  warnings: Vec<CanonCtmdWarning>,
  /// The running `$$self{Model}` — ExifTool's OBJECT-level model state, set from
  /// a `0x8769` `ExifIFD` block's IFD0 `Model` and STICKY across every later
  /// `ProcessExifInfo` record AND every later CTMD SAMPLE of the file (oracle:
  /// bundled ExifTool 13.59 — a `Model` set in one sample's `0x8769` keys a
  /// model-conditional `0x927c` tag in a LATER sample). The walk reads it when
  /// capturing a `0x927c` block and overwrites it on each new `0x8769` Model
  /// (last-wins). PURELY a walk-time scratch cell: the per-block value is frozen
  /// onto each [`CtmdExifInfo`] at capture, so emission never consults it. It is
  /// `None` until the first `0x8769` Model and is set deterministically for a
  /// given input, so it does not perturb [`PartialEq`].
  model_state: Option<SmolStr>,
}

impl CanonCtmdMeta {
  /// An empty result (no CTMD data decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      samples: Vec::new(),
      warnings: Vec::new(),
      model_state: None,
    }
  }

  /// The running `$$self{Model}` walk cell (the most recent `0x8769` IFD0
  /// `Model`), threaded across samples for model-conditional `0x927c` tags.
  /// Walk-only.
  #[inline(always)]
  #[must_use]
  pub(crate) fn model_state(&self) -> Option<&str> {
    self.model_state.as_deref()
  }

  /// Overwrite the running `$$self{Model}` walk cell — called when a `0x8769`
  /// `ExifIFD` block yields an IFD0 `Model` (last-wins, sticky forward).
  /// Walk-only.
  #[inline(always)]
  pub(crate) fn set_model_state(&mut self, model: Option<SmolStr>) {
    self.model_state = model;
  }

  /// One [`CanonCtmdSample`] per CTMD sample.
  #[inline(always)]
  #[must_use]
  pub fn samples(&self) -> &[CanonCtmdSample] {
    self.samples.as_slice()
  }

  /// The `ProcessCTMD` / `TimeStamp`-RawConv warnings, in raise order — each
  /// scoped to the CTMD sample that raised it (`Short`/`Truncated`/`Error
  /// parsing Canon CTMD data` + the `unpack` short-`TimeStamp` warnings).
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[CanonCtmdWarning] {
    self.warnings.as_slice()
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

  /// The number of samples decoded so far — a watermark the stream walker
  /// takes BEFORE one `process_ctmd` call so it can stamp the sub-document /
  /// track coordinates onto exactly the samples that call appended (mirrors
  /// [`crate::metadata::SonyRtmdMeta::sample_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn sample_count(&self) -> usize {
    self.samples.len()
  }

  /// Stamp the family-3 `doc` ordinal AND the sample-table `sample_time` /
  /// `sample_duration` (seconds) onto every sample at or after `start` — the
  /// samples one `process_ctmd` call appended since the walker took its
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

  /// Stamp the family-1 `track_index` (1-based) onto every sample at or after
  /// `start` — the samples decoded from a single CTMD `trak`. Mirrors
  /// [`crate::metadata::SonyRtmdMeta::stamp_track_index_from`].
  pub(crate) fn stamp_track_index_from(&mut self, start: usize, track_index: u32) {
    if let Some(slice) = self.samples.get_mut(start..) {
      for s in slice {
        s.track_index = track_index;
      }
    }
  }

  /// Append a [`CanonCtmdWarning`] (no doc / track / timing yet — the walker
  /// stamps them after the `process_ctmd` call, the same way the camm walker
  /// stamps a [`crate::metadata::CammWarning`]).
  #[inline(always)]
  pub fn push_warning(&mut self, warning: CanonCtmdWarning) -> &mut Self {
    self.warnings.push(warning);
    self
  }

  /// The number of warnings recorded so far — a watermark the stream walker
  /// takes BEFORE one `process_ctmd` call so it can stamp the doc / track /
  /// timing onto exactly the warnings that call raised (mirrors
  /// [`crate::metadata::CammMeta::warning_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn warning_count(&self) -> usize {
    self.warnings.len()
  }

  /// Stamp the `track` / `doc` / sample-table `time` / `duration` onto every
  /// warning at or after `start` — the warnings one `process_ctmd` call raised
  /// since the walker took its [`Self::warning_count`] watermark. Mirrors
  /// [`crate::metadata::CammMeta::stamp_warning_from`].
  pub(crate) fn stamp_warning_from(
    &mut self,
    start: usize,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) {
    if let Some(slice) = self.warnings.get_mut(start..) {
      for w in slice {
        w.set_track_index(Some(track))
          .set_doc(Some(doc))
          .set_sample_timing(time, duration);
      }
    }
  }
}

impl Default for CanonCtmdMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Canon CTMD projection into MediaMetadata (inherent `project_into`, merged by
// `QuickTimeMeta`'s `media_metadata` projection — mirrors `SonyRtmdMeta`).
// ===========================================================================

impl CanonCtmdMeta {
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
  /// **Warnings:** the `MediaMetadata` projection carries NO warning channel
  /// (the Doc<N> architecture surfaces the `ProcessCTMD` / `TimeStamp`-RawConv
  /// warnings — Short / Truncated / `Error parsing Canon CTMD data` + the
  /// short-`TimeStamp` `unpack` warnings — as in-stream `Doc<N>:Track<N>:
  /// Warning` emitted tags via [`Self::warnings`], NOT through the domain
  /// projection, mirroring the camm `Warning` channel).
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    if self.is_empty() {
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
    let m = CanonCtmdMeta::new();
    assert!(m.is_empty());
    assert!(m.samples().is_empty());
    assert!(m.first_focal().is_none());
    assert!(m.first_exposure().is_none());
    assert!(m.first_time_stamp().is_none());
    assert!(m.warnings().is_empty());
  }

  #[test]
  fn focal_record_get_set_roundtrip() {
    let mut f = CanonCtmdFocal::new();
    assert!(f.is_empty());
    f.set_focal_length(Some(Rational::rational32(15, 1)));
    assert_eq!(f.focal_length_mm(), Some(15.0));
    assert_eq!(f.focal_length_rational(), Some(Rational::rational32(15, 1)));
    assert!(!f.is_empty());
  }

  #[test]
  fn exposure_record_get_set_roundtrip() {
    let mut e = CanonCtmdExposure::new();
    assert!(e.is_empty());
    e.set_f_number(Some(Rational::rational32(35, 10)));
    e.set_exposure_time(Some(Rational::rational32(1, 80)));
    e.set_iso(Some(12800));
    assert_eq!(e.f_number(), Some(3.5));
    assert_eq!(e.exposure_time_s(), Some(0.0125));
    assert_eq!(e.iso(), Some(12800));
    assert!(!e.is_empty());
  }

  #[test]
  fn sample_keeps_last_focal() {
    let mut s = CanonCtmdSample::new();
    let mut first = CanonCtmdFocal::new();
    first.set_focal_length(Some(Rational::rational32(15, 1)));
    s.set_focal(Some(first));
    // A second set OVERWRITES the first — bundled `HandleTag`s every CTMD
    // record and the later duplicate wins (last-wins).
    let mut second = CanonCtmdFocal::new();
    second.set_focal_length(Some(Rational::rational32(50, 1)));
    s.set_focal(Some(second));
    assert_eq!(s.focal().unwrap().focal_length_mm(), Some(50.0));
  }

  #[test]
  fn sample_keeps_last_exposure() {
    let mut s = CanonCtmdSample::new();
    let mut first = CanonCtmdExposure::new();
    first.set_iso(Some(100));
    s.set_exposure(Some(first));
    // Last-wins (see `sample_keeps_last_focal`).
    let mut second = CanonCtmdExposure::new();
    second.set_iso(Some(12800));
    s.set_exposure(Some(second));
    assert_eq!(s.exposure().unwrap().iso(), Some(12800));
  }

  #[test]
  fn merge_exposure_overwrites_present_fields_keeps_absent() {
    // R3-2: a partial-duplicate ExposureInfo merges PER FIELD — overwriting only
    // the fields the later record carried (Some) and preserving the rest.
    let mut s = CanonCtmdSample::new();
    // Full record: FNumber 3.5, ExposureTime 1/80, ISO 12800.
    let mut full = CanonCtmdExposure::new();
    full.set_f_number(Some(Rational::rational32(35, 10)));
    full.set_exposure_time(Some(Rational::rational32(1, 80)));
    full.set_iso(Some(12800));
    s.merge_exposure(full);
    // 8-byte record: FNumber 8.0 + ExposureTime 1/250, NO ISO.
    let mut eight = CanonCtmdExposure::new();
    eight.set_f_number(Some(Rational::rational32(80, 10)));
    eight.set_exposure_time(Some(Rational::rational32(1, 250)));
    s.merge_exposure(eight);
    // 4-byte record: FNumber 5.6 only.
    let mut four = CanonCtmdExposure::new();
    four.set_f_number(Some(Rational::rational32(56, 10)));
    s.merge_exposure(four);
    let e = s.exposure().expect("exposure");
    assert_eq!(e.f_number_rational(), Some(Rational::rational32(56, 10)));
    assert_eq!(
      e.exposure_time_rational(),
      Some(Rational::rational32(1, 250))
    );
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn merge_present_leaves_none_fields_untouched() {
    let mut base = CanonCtmdExposure::new();
    base.set_f_number(Some(Rational::rational32(35, 10)));
    base.set_iso(Some(100));
    // `other` carries ONLY exposure_time — f_number/iso stay from `base`.
    let mut other = CanonCtmdExposure::new();
    other.set_exposure_time(Some(Rational::rational32(1, 60)));
    base.merge_present(&other);
    assert_eq!(base.f_number_rational(), Some(Rational::rational32(35, 10)));
    assert_eq!(
      base.exposure_time_rational(),
      Some(Rational::rational32(1, 60))
    );
    assert_eq!(base.iso(), Some(100));
  }

  #[test]
  fn merge_exposure_into_empty_installs_record() {
    let mut s = CanonCtmdSample::new();
    let mut e = CanonCtmdExposure::new();
    e.set_f_number(Some(Rational::rational32(28, 10)));
    s.merge_exposure(e);
    assert_eq!(
      s.exposure().unwrap().f_number_rational(),
      Some(Rational::rational32(28, 10))
    );
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
    focal.set_focal_length(Some(Rational::rational32(50, 1)));
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
  fn warnings_carry_minor_flag_and_stamp() {
    let mut m = CanonCtmdMeta::new();
    m.push_warning(CanonCtmdWarning::new(
      SmolStr::new("Short CTMD record"),
      false,
    ));
    m.push_warning(CanonCtmdWarning::new(
      SmolStr::new("Error parsing Canon CTMD data"),
      true,
    ));
    assert_eq!(m.warnings().len(), 2);
    assert!(!m.warnings()[0].minor());
    assert!(m.warnings()[1].minor());
    // Stamp the second warning only (watermark = 1).
    m.stamp_warning_from(1, 1, 3, Some(2.0), Some(1.0));
    assert_eq!(
      m.warnings()[0].doc(),
      None,
      "the first warning is unstamped"
    );
    assert_eq!(m.warnings()[1].doc(), Some(3));
    assert_eq!(m.warnings()[1].track_index(), Some(1));
    assert_eq!(m.warnings()[1].sample_time(), Some(2.0));
    assert_eq!(m.warnings()[1].sample_duration(), Some(1.0));
  }
}
