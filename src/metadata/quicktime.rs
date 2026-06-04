//! The faithful QuickTime parse layer: a typed mirror of the core
//! structural atoms decoded by [`crate::formats::quicktime::ProcessMov`].
//!
//! These structs follow the source-format shape (ExifTool's `mvhd` /
//! `tkhd` / `mdhd` / `hdlr` atom tables, QuickTime.pm). The normalized
//! [`crate::metadata::MediaMetadata`] projection is built FROM this layer.

/// The QuickTime `hdlr` HandlerType (QuickTime.pm:8403-8444). An open
/// vocabulary — Apple and third parties keep adding handler codes — so the
/// four-character code is preserved losslessly in [`HandlerKind::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandlerKind {
  /// `vide` — a video track.
  Video,
  /// `soun` — an audio track.
  Audio,
  /// `hint` — a hint track.
  Hint,
  /// `text` — a text track.
  Text,
  /// `sbtl` / `subp` — a subtitle / subpicture track.
  Subtitle,
  /// `tmcd` — a timecode track.
  TimeCode,
  /// `meta` / `mdta` / `mdir` / `nrtm` — a metadata track.
  Metadata,
  /// Any handler code not covered above — preserved verbatim (4 chars,
  /// trailing spaces kept, e.g. `"url "`).
  Other(String),
}

impl HandlerKind {
  /// Classify a raw 4-character handler code (QuickTime.pm:8418-8444).
  /// Total — an unrecognized code becomes [`HandlerKind::Other`], never an
  /// error.
  #[inline(always)]
  #[must_use]
  pub fn from_code(code: &str) -> Self {
    match code {
      "vide" => Self::Video,
      "soun" => Self::Audio,
      "hint" => Self::Hint,
      "text" => Self::Text,
      "sbtl" | "subp" => Self::Subtitle,
      "tmcd" => Self::TimeCode,
      "meta" | "mdta" | "mdir" | "nrtm" => Self::Metadata,
      other => Self::Other(other.to_string()),
    }
  }

  /// The 4-character handler code this kind corresponds to. For the named
  /// variants this is the canonical code; for [`HandlerKind::Other`] it is
  /// the preserved original.
  #[inline(always)]
  #[must_use]
  pub fn code(&self) -> &str {
    match self {
      Self::Video => "vide",
      Self::Audio => "soun",
      Self::Hint => "hint",
      Self::Text => "text",
      Self::Subtitle => "sbtl",
      Self::TimeCode => "tmcd",
      Self::Metadata => "meta",
      Self::Other(s) => s.as_str(),
    }
  }

  /// `true` if this is a video track handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_video(&self) -> bool {
    matches!(self, Self::Video)
  }

  /// `true` if this is an audio track handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_audio(&self) -> bool {
    matches!(self, Self::Audio)
  }

  /// `true` if this is a hint track handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_hint(&self) -> bool {
    matches!(self, Self::Hint)
  }

  /// `true` if this is a text track handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_text(&self) -> bool {
    matches!(self, Self::Text)
  }

  /// `true` if this is a subtitle / subpicture handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_subtitle(&self) -> bool {
    matches!(self, Self::Subtitle)
  }

  /// `true` if this is a timecode handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_time_code(&self) -> bool {
    matches!(self, Self::TimeCode)
  }

  /// `true` if this is a metadata handler.
  #[inline(always)]
  #[must_use]
  pub const fn is_metadata(&self) -> bool {
    matches!(self, Self::Metadata)
  }

  /// `true` for an unrecognized handler code.
  #[inline(always)]
  #[must_use]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other(_))
  }
}

/// One QuickTime track — the typed mirror of a `trak` atom and its
/// `tkhd` / `mdia(mdhd, hdlr)` children (QuickTime.pm:1424-1582,
/// 7218-7327). All fields are optional: a fixture too short for a given
/// field leaves it `None` (the parser is bounds-checked).
#[derive(Debug, Clone, PartialEq)]
pub struct MediaTrack {
  /// `tkhd` version byte (QuickTime.pm:1500-1505).
  track_header_version: Option<u8>,
  /// `tkhd` TrackCreateDate, displayed (QuickTime.pm:1506-1513 timeInfo).
  track_create_date: Option<String>,
  /// `tkhd` TrackModifyDate, displayed (QuickTime.pm:1514-1521 timeInfo).
  track_modify_date: Option<String>,
  /// `tkhd` TrackID (QuickTime.pm:1522-1525).
  track_id: Option<u32>,
  /// `tkhd` TrackDuration, in seconds (movie-timescale-scaled —
  /// QuickTime.pm:1526-1532 + durationInfo).
  duration_seconds: Option<f64>,
  /// `tkhd` TrackLayer (int16u — QuickTime.pm:1539-1543).
  track_layer: Option<u16>,
  /// `tkhd` TrackVolume, the `$val / 256` ValueConv result
  /// (QuickTime.pm:1544-1550).
  track_volume: Option<f64>,
  /// `tkhd` MatrixStructure, the ValueConv-formatted 9-element string
  /// (QuickTime.pm:1551-1571).
  matrix_structure: Option<String>,
  /// `tkhd` ImageWidth — the `FixWrongFormat` result (QuickTime.pm:1572-1576).
  image_width: Option<u32>,
  /// `tkhd` ImageHeight (QuickTime.pm:1577-1581).
  image_height: Option<u32>,
  /// `mdhd` version byte (QuickTime.pm:7246-7249).
  media_header_version: Option<u8>,
  /// `mdhd` MediaCreateDate, displayed (QuickTime.pm:7250-7256 timeInfo).
  media_create_date: Option<String>,
  /// `mdhd` MediaModifyDate, displayed (QuickTime.pm:7257-7263 timeInfo).
  media_modify_date: Option<String>,
  /// `mdhd` MediaTimeScale (QuickTime.pm:7264-7267).
  media_time_scale: Option<u32>,
  /// `mdhd` MediaDuration, in seconds (media-timescale-scaled —
  /// QuickTime.pm:7268-7274).
  media_duration_seconds: Option<f64>,
  /// `mdhd` MediaLanguageCode, decoded (QuickTime.pm:7275-7286).
  media_language: Option<String>,
  /// `hdlr` raw 4-byte HandlerClass / ComponentType (body offset 4,
  /// QuickTime.pm:8395-8402). `None` when all-zero (`RawConv => '$val eq
  /// "\0\0\0\0" ? undef : $val'`). Drives the `HandlerClass` tag (PrintConv
  /// `mhlr`→Media Handler / `dhlr`→Data Handler).
  handler_class: Option<String>,
  /// `hdlr` raw 4-byte HandlerType code, preserved verbatim
  /// (QuickTime.pm:8403-8416). Drives the `HandlerType` tag + PrintConv;
  /// see also [`Self::handler`] for the normalized projection kind.
  handler_code: Option<String>,
  /// `hdlr` HandlerType normalized into a [`HandlerKind`] — used ONLY for
  /// the [`crate::metadata::MediaMetadata`] projection (track-kind
  /// classification). The flat `HandlerType` tag is emitted from
  /// [`Self::handler_code`] so distinct codes are never collapsed.
  handler: Option<HandlerKind>,
  /// The ExifTool family-1 `Track#` group number (QuickTime.pm:1427 `1 =>
  /// 'Track#'`). ExifTool's `$track` counter is a `my` local of each
  /// `ProcessMOV` invocation (QuickTime.pm:9944) that increments per `trak`
  /// (QuickTime.pm:10354 `'Track' . (++$track)`); since every top-level `moov`
  /// is a SEPARATE `ProcessMOV` call, the counter RESETS to 1 per `moov`. So a
  /// file with two top-level `moov`s each holding one `trak` yields two
  /// `Track1`s (NOT `Track1`+`Track2`). Stored here per `trak` so serialization
  /// groups by the ExifTool number, not the global Vec index (R4/F2). `None`
  /// only for tracks built directly in unit tests.
  track_group: Option<u32>,
  /// A `ProcessMOV` `Truncated '...' data` warning raised WHILE walking this
  /// `trak`'s sub-atoms (a header-valid but payload-overrunning tkhd / mdhd /
  /// …). ExifTool attaches such a warning to the *current* family-1 group, so
  /// a truncated atom inside `trak`/`mdia` surfaces under `Track#:Warning`
  /// (NOT the document-level `ExifTool:Warning`) — verified vs bundled
  /// (`Track1:Warning = "Truncated 'tkhd' data (missing 86 bytes)"`).
  warning: Option<String>,
}

impl MediaTrack {
  /// An empty track (every field `None`). Fields are filled as the parser
  /// walks the `trak` sub-atoms.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      track_header_version: None,
      track_create_date: None,
      track_modify_date: None,
      track_id: None,
      duration_seconds: None,
      track_layer: None,
      track_volume: None,
      matrix_structure: None,
      image_width: None,
      image_height: None,
      media_header_version: None,
      media_create_date: None,
      media_modify_date: None,
      media_time_scale: None,
      media_duration_seconds: None,
      media_language: None,
      handler_class: None,
      handler_code: None,
      handler: None,
      track_group: None,
      warning: None,
    }
  }

  /// `tkhd` version byte.
  #[inline(always)]
  #[must_use]
  pub const fn track_header_version(&self) -> Option<u8> {
    self.track_header_version
  }

  /// `tkhd` TrackCreateDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn track_create_date(&self) -> Option<&str> {
    self.track_create_date.as_deref()
  }

  /// `tkhd` TrackModifyDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn track_modify_date(&self) -> Option<&str> {
    self.track_modify_date.as_deref()
  }

  /// `tkhd` TrackID.
  #[inline(always)]
  #[must_use]
  pub const fn track_id(&self) -> Option<u32> {
    self.track_id
  }

  /// `tkhd` TrackLayer.
  #[inline(always)]
  #[must_use]
  pub const fn track_layer(&self) -> Option<u16> {
    self.track_layer
  }

  /// `tkhd` TrackVolume (post-ValueConv `$val / 256`).
  #[inline(always)]
  #[must_use]
  pub const fn track_volume(&self) -> Option<f64> {
    self.track_volume
  }

  /// `tkhd` MatrixStructure (ValueConv-formatted string).
  #[inline(always)]
  #[must_use]
  pub fn matrix_structure(&self) -> Option<&str> {
    self.matrix_structure.as_deref()
  }

  /// TrackDuration in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn duration_seconds(&self) -> Option<f64> {
    self.duration_seconds
  }

  /// ImageWidth (integer part of the 16.16 fixed-point value).
  #[inline(always)]
  #[must_use]
  pub const fn image_width(&self) -> Option<u32> {
    self.image_width
  }

  /// ImageHeight.
  #[inline(always)]
  #[must_use]
  pub const fn image_height(&self) -> Option<u32> {
    self.image_height
  }

  /// `mdhd` version byte.
  #[inline(always)]
  #[must_use]
  pub const fn media_header_version(&self) -> Option<u8> {
    self.media_header_version
  }

  /// `mdhd` MediaCreateDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn media_create_date(&self) -> Option<&str> {
    self.media_create_date.as_deref()
  }

  /// `mdhd` MediaModifyDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn media_modify_date(&self) -> Option<&str> {
    self.media_modify_date.as_deref()
  }

  /// `mdhd` MediaTimeScale.
  #[inline(always)]
  #[must_use]
  pub const fn media_time_scale(&self) -> Option<u32> {
    self.media_time_scale
  }

  /// MediaDuration in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn media_duration_seconds(&self) -> Option<f64> {
    self.media_duration_seconds
  }

  /// MediaLanguageCode (decoded string).
  #[inline(always)]
  #[must_use]
  pub fn media_language(&self) -> Option<&str> {
    self.media_language.as_deref()
  }

  /// The raw 4-byte `hdlr` HandlerType code (verbatim, trailing spaces
  /// kept). This is the value the flat `HandlerType` tag is emitted from
  /// (faithful: distinct codes such as `mdta`/`mdir`/`nrtm` are never
  /// collapsed). `None` if no `hdlr` was decoded.
  #[inline(always)]
  #[must_use]
  pub fn handler_code(&self) -> Option<&str> {
    self.handler_code.as_deref()
  }

  /// `hdlr` HandlerClass / ComponentType (raw 4-byte code), `None` when
  /// all-zero (the `RawConv` undef branch).
  #[inline(always)]
  #[must_use]
  pub fn handler_class(&self) -> Option<&str> {
    self.handler_class.as_deref()
  }

  /// The normalized track handler kind (`hdlr` HandlerType) — used for the
  /// [`crate::metadata::MediaMetadata`] track-kind projection only.
  #[inline(always)]
  #[must_use]
  pub const fn handler(&self) -> Option<&HandlerKind> {
    self.handler.as_ref()
  }

  /// The ExifTool family-1 `Track#` group number (QuickTime.pm:1427), reset
  /// per `moov` (per `ProcessMOV` invocation). Serialization uses this to form
  /// the `Track<N>` group instead of the global track-list index (R4/F2).
  #[inline(always)]
  #[must_use]
  pub const fn track_group(&self) -> Option<u32> {
    self.track_group
  }

  /// The `Truncated '...' data` warning raised while walking this `trak`
  /// (`None` if the track parsed cleanly). Surfaced as `Track#:Warning`.
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// Record a per-track `ProcessMOV` warning (first-wins — a later truncation
  /// never overwrites an earlier one, matching `ProcessMOV`'s single-`Warning`
  /// emission per directory walk).
  #[inline(always)]
  pub fn set_warning(&mut self, v: Option<String>) -> &mut Self {
    if self.warning.is_none() {
      self.warning = v;
    }
    self
  }

  /// Set the `tkhd` version byte.
  #[inline(always)]
  pub const fn set_track_header_version(&mut self, v: u8) -> &mut Self {
    self.track_header_version = Some(v);
    self
  }

  /// Assign the raw TrackCreateDate wrapper.
  #[inline(always)]
  pub fn set_track_create_date(&mut self, v: Option<String>) -> &mut Self {
    self.track_create_date = v;
    self
  }

  /// Assign the raw TrackModifyDate wrapper.
  #[inline(always)]
  pub fn set_track_modify_date(&mut self, v: Option<String>) -> &mut Self {
    self.track_modify_date = v;
    self
  }

  /// Assign the raw TrackID wrapper.
  #[inline(always)]
  pub const fn set_track_id(&mut self, v: Option<u32>) -> &mut Self {
    self.track_id = v;
    self
  }

  /// Assign the raw TrackLayer wrapper.
  #[inline(always)]
  pub const fn set_track_layer(&mut self, v: Option<u16>) -> &mut Self {
    self.track_layer = v;
    self
  }

  /// Assign the raw TrackVolume wrapper (post-ValueConv).
  #[inline(always)]
  pub const fn set_track_volume(&mut self, v: Option<f64>) -> &mut Self {
    self.track_volume = v;
    self
  }

  /// Assign the raw MatrixStructure wrapper (ValueConv-formatted string).
  #[inline(always)]
  pub fn set_matrix_structure(&mut self, v: Option<String>) -> &mut Self {
    self.matrix_structure = v;
    self
  }

  /// Assign the raw TrackDuration wrapper.
  #[inline(always)]
  pub const fn set_duration_seconds(&mut self, v: Option<f64>) -> &mut Self {
    self.duration_seconds = v;
    self
  }

  /// Assign the raw ImageWidth wrapper.
  #[inline(always)]
  pub const fn set_image_width(&mut self, v: Option<u32>) -> &mut Self {
    self.image_width = v;
    self
  }

  /// Assign the raw ImageHeight wrapper.
  #[inline(always)]
  pub const fn set_image_height(&mut self, v: Option<u32>) -> &mut Self {
    self.image_height = v;
    self
  }

  /// Set the `mdhd` version byte.
  #[inline(always)]
  pub const fn set_media_header_version(&mut self, v: u8) -> &mut Self {
    self.media_header_version = Some(v);
    self
  }

  /// Assign the raw MediaCreateDate wrapper.
  #[inline(always)]
  pub fn set_media_create_date(&mut self, v: Option<String>) -> &mut Self {
    self.media_create_date = v;
    self
  }

  /// Assign the raw MediaModifyDate wrapper.
  #[inline(always)]
  pub fn set_media_modify_date(&mut self, v: Option<String>) -> &mut Self {
    self.media_modify_date = v;
    self
  }

  /// Assign the raw MediaTimeScale wrapper.
  #[inline(always)]
  pub const fn set_media_time_scale(&mut self, v: Option<u32>) -> &mut Self {
    self.media_time_scale = v;
    self
  }

  /// Assign the raw MediaDuration wrapper.
  #[inline(always)]
  pub const fn set_media_duration_seconds(&mut self, v: Option<f64>) -> &mut Self {
    self.media_duration_seconds = v;
    self
  }

  /// Assign the raw MediaLanguageCode wrapper.
  #[inline(always)]
  pub fn set_media_language(&mut self, v: Option<String>) -> &mut Self {
    self.media_language = v;
    self
  }

  /// Set the raw 4-byte `hdlr` HandlerType code (verbatim) AND derive the
  /// normalized [`HandlerKind`] projection in one step.
  #[inline(always)]
  pub fn set_handler_code(&mut self, code: impl Into<String>) -> &mut Self {
    let code = code.into();
    self.handler = Some(HandlerKind::from_code(&code));
    self.handler_code = Some(code);
    self
  }

  /// Set the normalized track handler kind directly (projection-only; does
  /// NOT touch [`Self::handler_code`]). Used by unit tests.
  #[inline(always)]
  pub fn set_handler(&mut self, kind: HandlerKind) -> &mut Self {
    self.handler = Some(kind);
    self
  }

  /// Set the raw 4-byte `hdlr` HandlerClass / ComponentType (verbatim).
  #[inline(always)]
  pub fn set_handler_class(&mut self, v: Option<String>) -> &mut Self {
    self.handler_class = v;
    self
  }

  /// Set the ExifTool family-1 `Track#` group number (reset per `moov`).
  #[inline(always)]
  pub const fn set_track_group(&mut self, n: u32) -> &mut Self {
    self.track_group = Some(n);
    self
  }

  /// Fold the `tkhd`-derived fields from `other` into `self`. Used by the
  /// parser: a `trak` walk decodes `tkhd` into a fresh [`MediaTrack`] and
  /// merges only the header fields (the `mdia`/`hdlr` fields are filled
  /// separately on the same accumulator). Only `Some` values overwrite.
  pub fn merge_track_header(&mut self, other: MediaTrack) -> &mut Self {
    if other.track_header_version.is_some() {
      self.track_header_version = other.track_header_version;
    }
    if other.track_create_date.is_some() {
      self.track_create_date = other.track_create_date;
    }
    if other.track_modify_date.is_some() {
      self.track_modify_date = other.track_modify_date;
    }
    if other.track_id.is_some() {
      self.track_id = other.track_id;
    }
    if other.duration_seconds.is_some() {
      self.duration_seconds = other.duration_seconds;
    }
    if other.track_layer.is_some() {
      self.track_layer = other.track_layer;
    }
    if other.track_volume.is_some() {
      self.track_volume = other.track_volume;
    }
    if other.matrix_structure.is_some() {
      self.matrix_structure = other.matrix_structure;
    }
    if other.image_width.is_some() {
      self.image_width = other.image_width;
    }
    if other.image_height.is_some() {
      self.image_height = other.image_height;
    }
    self
  }
}

impl Default for MediaTrack {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// The four tags decoded from the top-level `frea` atom of Kodak PixPro
/// SP360 / 4KVR360 (and Rexing) MP4 videos — `Image::ExifTool::Kodak::frea`
/// (Kodak.pm:2977-2990), dispatched from the `%QuickTime::Main` `frea` entry
/// (QuickTime.pm:610-613). The table `GROUPS => { 0 => 'MakerNotes', 2 =>
/// 'Image' }`; ExifTool renders these under family-0 `MakerNotes`, family-1
/// `Kodak` (verified vs the bundled `-G0:1` oracle on a crafted `frea` MP4).
///
/// `KodakVersion` (the `'ver '` sub-atom) is the cross-module global ExifTool
/// stashes in `$$self{KodakVersion}` (Kodak.pm:2987 `RawConv =>
/// '$$self{KodakVersion} = $val'`) and reads back during the `mdat` freeGPS
/// scan to recognize a Rexing V1-4k dashcam and apply the Type-17b lat/lon
/// scaling (QuickTimeStream.pl:2323-2327) — see
/// [`crate::formats::quicktime_freegps`].
///
/// **D8 — no public fields, accessors only.**
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KodakFrea {
  /// `tima` Duration — raw `int32u` seconds (Kodak.pm:2980-2985). PrintConv is
  /// `ConvertDuration($val)`; there is no ValueConv, so the raw count IS the
  /// `-n` value and the seconds fed to `ConvertDuration`.
  duration_secs: Option<u32>,
  /// `'ver '` KodakVersion — the raw string value (Kodak.pm:2987). Also stashed
  /// as the cross-module `KodakVersion` global for the freeGPS Type-17b scan.
  version: Option<smol_str::SmolStr>,
  /// `thma` ThumbnailImage — the byte length of the binary payload (Kodak.pm:
  /// 2988, `Binary => 1`, group2 `Preview`). Rendered as the `(Binary data N
  /// bytes, use -b option to extract)` placeholder; the bytes are not retained.
  thumbnail_len: Option<u64>,
  /// `scra` PreviewImage — the byte length of the binary payload (Kodak.pm:
  /// 2989, `Binary => 1`, group2 `Preview`). Rendered as the placeholder.
  preview_len: Option<u64>,
}

impl KodakFrea {
  /// A fresh, empty `frea` decode (no sub-atoms seen yet).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      duration_secs: None,
      version: None,
      thumbnail_len: None,
      preview_len: None,
    }
  }

  /// `tima` Duration — raw `int32u` seconds (the `-n` value and the
  /// `ConvertDuration` input).
  #[inline(always)]
  #[must_use]
  pub const fn duration_secs(&self) -> Option<u32> {
    self.duration_secs
  }

  /// `'ver '` KodakVersion — the raw string value.
  #[inline(always)]
  #[must_use]
  pub fn version(&self) -> Option<&str> {
    match &self.version {
      Some(v) => Some(v.as_str()),
      None => None,
    }
  }

  /// `thma` ThumbnailImage — payload byte length (for the binary placeholder).
  #[inline(always)]
  #[must_use]
  pub const fn thumbnail_len(&self) -> Option<u64> {
    self.thumbnail_len
  }

  /// `scra` PreviewImage — payload byte length (for the binary placeholder).
  #[inline(always)]
  #[must_use]
  pub const fn preview_len(&self) -> Option<u64> {
    self.preview_len
  }

  /// `true` when no `frea` sub-atom was decoded.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.duration_secs.is_none()
      && self.version.is_none()
      && self.thumbnail_len.is_none()
      && self.preview_len.is_none()
  }

  /// Record the `tima` Duration (raw `int32u` seconds).
  #[inline(always)]
  pub const fn set_duration_secs(&mut self, v: Option<u32>) -> &mut Self {
    self.duration_secs = v;
    self
  }

  /// Record the `'ver '` KodakVersion string.
  #[inline(always)]
  pub fn set_version(&mut self, v: Option<smol_str::SmolStr>) -> &mut Self {
    self.version = v;
    self
  }

  /// Record the `thma` ThumbnailImage payload byte length.
  #[inline(always)]
  pub const fn set_thumbnail_len(&mut self, v: Option<u64>) -> &mut Self {
    self.thumbnail_len = v;
    self
  }

  /// Record the `scra` PreviewImage payload byte length.
  #[inline(always)]
  pub const fn set_preview_len(&mut self, v: Option<u64>) -> &mut Self {
    self.preview_len = v;
    self
  }
}

/// **SP2** — a QuickTime GPS coordinate from an ISO 6709 string (`©xyz` /
/// `com.apple.quicktime.location.ISO6709`). Mirrors `ConvertISO6709`
/// (QuickTime.pm:8884-8909): [`Self::value_conv`] is the faithful ValueConv
/// output (the `-n` `GPSCoordinates` value), ALWAYS present. When the string
/// decoded as a coordinate, [`Self::coords`] carries the numeric
/// `(latitude, longitude, optional altitude)` that feed the normalized
/// [`crate::metadata::GpsLocation`].
///
/// `ConvertISO6709` has NO `else` branch: on a string that matches none of the
/// three ISO 6709 forms it `return $val` UNCHANGED — so ExifTool STILL emits
/// `GPSCoordinates` (the raw string under `-n`; `PrintGPSCoordinates`-of-the-raw
/// string under `-j`). To stay faithful, a present-but-undecodable value is
/// represented as a `QuickTimeGps` whose `value_conv` is the RAW input and whose
/// [`Self::coords`] is `None` (the tag is emitted, but there is no usable
/// numeric lat/lon → no `GpsLocation` projection). The `GPSCoordinates`
/// PrintConv (`-j`, `PrintGPSCoordinates`) is derived from `value_conv` at emit
/// time and faithfully numifies its tokens-to-`0` like Perl.
#[derive(Debug, Clone, PartialEq)]
pub struct QuickTimeGps {
  /// `ConvertISO6709` ValueConv output — `"lat lon"` or `"lat lon alt"` (each
  /// number Perl-numified) when decoded, else the RAW undecodable input string.
  /// The `-n` `GPSCoordinates` value, verbatim. Always present.
  value_conv: String,
  /// The decoded numeric coordinate `(latitude, longitude, optional altitude in
  /// metres)`, or `None` when `ConvertISO6709` did not match (the raw-string
  /// pass-through). Latitude positive = north; longitude positive = east; the
  /// altitude component is present only when the ISO 6709 string carried a third
  /// (altitude) field (QuickTime.pm:8889).
  coords: Option<(f64, f64, Option<f64>)>,
}

impl QuickTimeGps {
  /// Construct a DECODED GPS from the ValueConv string and its numeric parts.
  #[inline(always)]
  #[must_use]
  pub const fn new(
    value_conv: String,
    latitude: f64,
    longitude: f64,
    altitude_m: Option<f64>,
  ) -> Self {
    Self {
      value_conv,
      coords: Some((latitude, longitude, altitude_m)),
    }
  }

  /// Construct a RAW (undecodable) GPS: `value_conv` is the verbatim input and
  /// there are no numeric coordinates (`ConvertISO6709` returned the string
  /// unchanged). The tag is still emitted; no [`crate::metadata::GpsLocation`]
  /// is projected.
  #[inline(always)]
  #[must_use]
  pub const fn raw(value_conv: String) -> Self {
    Self {
      value_conv,
      coords: None,
    }
  }

  /// The `ConvertISO6709` ValueConv string (the `-n` `GPSCoordinates` value).
  #[inline(always)]
  #[must_use]
  pub fn value_conv(&self) -> &str {
    self.value_conv.as_str()
  }

  /// The decoded numeric coordinate `(latitude, longitude, optional altitude in
  /// metres)`, or `None` for a raw-string-only (undecodable) GPS.
  #[inline(always)]
  #[must_use]
  pub const fn coords(&self) -> Option<(f64, f64, Option<f64>)> {
    self.coords
  }

  /// Latitude in decimal degrees (positive = north), when a coordinate was
  /// decoded.
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    match self.coords {
      Some((lat, _, _)) => Some(lat),
      None => None,
    }
  }

  /// Longitude in decimal degrees (positive = east), when a coordinate was
  /// decoded.
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    match self.coords {
      Some((_, lon, _)) => Some(lon),
      None => None,
    }
  }

  /// Altitude in metres, when a coordinate was decoded AND the ISO 6709 string
  /// carried an altitude component.
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    match self.coords {
      Some((_, _, alt)) => alt,
      None => None,
    }
  }
}

/// A field value carrying its ExifTool extraction priority — used by the
/// multi-source `%QuickTime::UserData` identity fields (Make / Model /
/// SerialNumber / FirmwareVersion), where several distinct atoms map to the
/// SAME tag Name and ExifTool's duplicate-tag resolution (ExifTool.pm:9468-
/// 9566) picks a winner.
///
/// **Verified model (vs bundled ExifTool 13.59).** Each tag has a default
/// priority — `1` for a normal entry, `0` for one flagged `Avoid => 1`
/// (ExifTool.pm:9472 `$priority = 0 if ... $$tagInfo{Avoid}`). On a duplicate
/// (ExifTool.pm:9564 `if ($priority >= $oldPriority ...)`, where an existing
/// 0-priority slot is first promoted to 1 at 9544-9551), the net rule collapses
/// to: **a priority-1 value ALWAYS overwrites; a priority-0 (Avoid) value only
/// fills an empty slot.** So among several `Avoid` atoms the FIRST in file order
/// wins, among several normal atoms the LAST wins, and a normal atom always
/// beats an `Avoid` one regardless of order (confirmed vs bundled: `manu`(Avoid)
/// vs the copyright-symbol Make; `modl`/`cmnm`/`CNMN`(Avoid) vs the
/// copyright-symbol Model; `slno` vs `SNum`(Avoid); `CNFV`/`info` vs
/// `FIRM`(Avoid)).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PriorityValue {
  value: String,
  /// `0` for an `Avoid => 1` source, `1` for a normal source.
  priority: u8,
}

/// **SP2** — the `udta` user-data camera/metadata atoms: a typed mirror of the
/// camera-identity / GPS / descriptive-text entries of `%QuickTime::UserData`
/// (QuickTime.pm:1585-1900). Only the camera-metadata-relevant atoms are
/// decoded (the media-indexing scope); every field is optional. Group
/// (`-G0:1`) `QuickTime:UserData`.
///
/// Make / Model / SerialNumber / FirmwareVersion are MULTI-SOURCE: several
/// distinct atoms map to each (e.g. Model from the copyright-symbol `mod`, plus
/// `modl` / `cmnm` / `CNMN` / the DJI `mdl`), so they are stored as a
/// [`PriorityValue`] and resolved by ExifTool's duplicate-tag priority rule.
/// The single-source fields keep a plain `Option<String>` (a later same-named
/// atom cannot occur).
#[derive(Debug, Clone, PartialEq)]
pub struct QuickTimeUserData {
  /// Make — the copyright-symbol `mak` (QuickTime.pm:1638, priority 1) or `manu`
  /// (1879, Avoid). The `@mak` Ricoh variant is out of scope (non-standard
  /// format — its value carries an undecoded length-byte prefix).
  make: Option<PriorityValue>,
  /// Model — the copyright-symbol `mod` (QuickTime.pm:1640, priority 1), `modl`
  /// (1885, Avoid), `cmnm` (1863, Avoid), `CNMN` (2037, Avoid), or the DJI
  /// copyright-symbol `mdl` (2156, Avoid).
  model: Option<PriorityValue>,
  /// SerialNumber — `slno` (QuickTime.pm:1895, priority 1) or `SNum` (2178,
  /// Avoid).
  serial_number: Option<PriorityValue>,
  /// FirmwareVersion — `CNFV` (QuickTime.pm:2043, priority 1), `info` (2509,
  /// priority 1), or `FIRM` (2118, Avoid).
  firmware_version: Option<PriorityValue>,
  /// SoftwareVersion — the copyright-symbol `swr` (QuickTime.pm:1652).
  software: Option<String>,
  /// `CNCV` CompressorVersion (QuickTime.pm:2036, Canon).
  compressor_version: Option<String>,
  /// `cmid` CameraID (QuickTime.pm:1862).
  camera_id: Option<String>,
  /// Title — the copyright-symbol `nam` (QuickTime.pm:1641).
  title: Option<String>,
  /// Comment — the copyright-symbol `cmt` (QuickTime.pm:1617).
  comment: Option<String>,
  /// Copyright — the copyright-symbol `cpy` (QuickTime.pm:1607, group2 Author).
  copyright: Option<String>,
  /// ContentCreateDate — the copyright-symbol `day`, ISO-8601 normalized
  /// (QuickTime.pm:1608-1612).
  content_create_date: Option<String>,
  /// `date` DateTimeOriginal, ISO-8601 normalized (QuickTime.pm:1869-1878).
  date_time_original: Option<String>,
  /// GPSCoordinates — the copyright-symbol `xyz`, decoded from ISO 6709
  /// (QuickTime.pm:1657-1664).
  gps: Option<QuickTimeGps>,
  /// `CAME` SerialNumberHash (QuickTime.pm:2120-2125, GoPro Hero4): the
  /// `ValueConv => 'unpack("H*",$val)'` result — the lower-case hex of the raw
  /// bytes. Code-valued, so HAND-ported (not in the generated conv-less map).
  serial_number_hash: Option<String>,
  /// `MUID` MediaUID (QuickTime.pm:2127, GoPro Hero4): the `ValueConv =>
  /// 'unpack("H*", $val)'` result — the lower-case hex of the raw bytes.
  /// Code-valued, HAND-ported.
  media_uid: Option<String>,
  /// The conv-less plain-string camera atoms decoded via the generated
  /// `4cc → Name` map ([`crate::formats::quicktime::quicktime_generated`]) —
  /// `(Name, value)` in walk order. These carry NO conversion and NO priority,
  /// so they are emitted verbatim under `QuickTime:UserData`; modeling them in
  /// one ordered sink (vs a typed field each) keeps the supplementary map the
  /// single source of truth (a new conv-less atom = regenerate, no Rust edit).
  convless: Vec<(smol_str::SmolStr, String)>,
}

impl QuickTimeUserData {
  /// An empty `udta` block (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      make: None,
      model: None,
      serial_number: None,
      firmware_version: None,
      software: None,
      compressor_version: None,
      camera_id: None,
      title: None,
      comment: None,
      copyright: None,
      content_create_date: None,
      date_time_original: None,
      gps: None,
      serial_number_hash: None,
      media_uid: None,
      convless: Vec::new(),
    }
  }

  /// Make (the copyright-symbol `mak` / `manu`, priority-resolved).
  #[inline(always)]
  #[must_use]
  pub fn make(&self) -> Option<&str> {
    self.make.as_ref().map(|p| p.value.as_str())
  }

  /// Model (the copyright-symbol `mod` / `modl` / `cmnm` / `CNMN` / DJI `mdl`,
  /// priority-resolved).
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_ref().map(|p| p.value.as_str())
  }

  /// SerialNumber (`slno` / `SNum`, priority-resolved).
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_ref().map(|p| p.value.as_str())
  }

  /// FirmwareVersion (`CNFV` / `info` / `FIRM`, priority-resolved).
  #[inline(always)]
  #[must_use]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_ref().map(|p| p.value.as_str())
  }

  /// SoftwareVersion (the copyright-symbol `swr`).
  #[inline(always)]
  #[must_use]
  pub fn software(&self) -> Option<&str> {
    self.software.as_deref()
  }

  /// `CNCV` CompressorVersion (Canon).
  #[inline(always)]
  #[must_use]
  pub fn compressor_version(&self) -> Option<&str> {
    self.compressor_version.as_deref()
  }

  /// `cmid` CameraID.
  #[inline(always)]
  #[must_use]
  pub fn camera_id(&self) -> Option<&str> {
    self.camera_id.as_deref()
  }

  /// Title (the copyright-symbol `nam`).
  #[inline(always)]
  #[must_use]
  pub fn title(&self) -> Option<&str> {
    self.title.as_deref()
  }

  /// Comment (the copyright-symbol `cmt`).
  #[inline(always)]
  #[must_use]
  pub fn comment(&self) -> Option<&str> {
    self.comment.as_deref()
  }

  /// Copyright (the copyright-symbol `cpy`).
  #[inline(always)]
  #[must_use]
  pub fn copyright(&self) -> Option<&str> {
    self.copyright.as_deref()
  }

  /// ContentCreateDate (the copyright-symbol `day`, ISO-8601 normalized).
  #[inline(always)]
  #[must_use]
  pub fn content_create_date(&self) -> Option<&str> {
    self.content_create_date.as_deref()
  }

  /// `date` DateTimeOriginal (ISO-8601 normalized).
  #[inline(always)]
  #[must_use]
  pub fn date_time_original(&self) -> Option<&str> {
    self.date_time_original.as_deref()
  }

  /// GPSCoordinates (the copyright-symbol `xyz`).
  #[inline(always)]
  #[must_use]
  pub const fn gps(&self) -> Option<&QuickTimeGps> {
    self.gps.as_ref()
  }

  /// `CAME` SerialNumberHash (the `unpack("H*")` hex of the raw bytes).
  #[inline(always)]
  #[must_use]
  pub fn serial_number_hash(&self) -> Option<&str> {
    self.serial_number_hash.as_deref()
  }

  /// `MUID` MediaUID (the `unpack("H*")` hex of the raw bytes).
  #[inline(always)]
  #[must_use]
  pub fn media_uid(&self) -> Option<&str> {
    self.media_uid.as_deref()
  }

  /// The conv-less plain-string atoms decoded via the generated map, as
  /// `(Name, value)` in walk order.
  #[inline(always)]
  #[must_use]
  pub fn convless(&self) -> &[(smol_str::SmolStr, String)] {
    &self.convless
  }

  /// `true` when no atom was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.make.is_none()
      && self.model.is_none()
      && self.serial_number.is_none()
      && self.firmware_version.is_none()
      && self.software.is_none()
      && self.compressor_version.is_none()
      && self.camera_id.is_none()
      && self.title.is_none()
      && self.comment.is_none()
      && self.copyright.is_none()
      && self.content_create_date.is_none()
      && self.date_time_original.is_none()
      && self.gps.is_none()
      && self.serial_number_hash.is_none()
      && self.media_uid.is_none()
      && self.convless.is_empty()
  }

  /// Merge a value into a multi-source [`PriorityValue`] slot per ExifTool's
  /// duplicate-tag rule: a priority-1 value always overwrites; a priority-0
  /// (`Avoid`) value only fills an empty slot (see [`PriorityValue`]).
  #[inline(always)]
  fn merge_priority(slot: &mut Option<PriorityValue>, value: String, priority: u8) {
    let replace = match slot {
      None => true,
      Some(_) => priority >= 1,
    };
    if replace {
      *slot = Some(PriorityValue { value, priority });
    }
  }

  /// Record a Make candidate (`priority` 1 for the copyright-symbol `mak`, 0 for
  /// the `Avoid` `manu`).
  #[inline(always)]
  pub fn set_make(&mut self, value: String, priority: u8) -> &mut Self {
    Self::merge_priority(&mut self.make, value, priority);
    self
  }

  /// Record a Model candidate (`priority` 1 for the copyright-symbol `mod`, 0
  /// for the `Avoid` `modl` / `cmnm` / `CNMN` / DJI `mdl`).
  #[inline(always)]
  pub fn set_model(&mut self, value: String, priority: u8) -> &mut Self {
    Self::merge_priority(&mut self.model, value, priority);
    self
  }

  /// Record a SerialNumber candidate (`priority` 1 for `slno`, 0 for the
  /// `Avoid` `SNum`).
  #[inline(always)]
  pub fn set_serial_number(&mut self, value: String, priority: u8) -> &mut Self {
    Self::merge_priority(&mut self.serial_number, value, priority);
    self
  }

  /// Record a FirmwareVersion candidate (`priority` 1 for `CNFV` / `info`, 0
  /// for the `Avoid` `FIRM`).
  #[inline(always)]
  pub fn set_firmware_version(&mut self, value: String, priority: u8) -> &mut Self {
    Self::merge_priority(&mut self.firmware_version, value, priority);
    self
  }

  /// Set SoftwareVersion (the copyright-symbol `swr`).
  #[inline(always)]
  pub fn set_software(&mut self, v: Option<String>) -> &mut Self {
    self.software = v;
    self
  }

  /// Set `CNCV` CompressorVersion.
  #[inline(always)]
  pub fn set_compressor_version(&mut self, v: Option<String>) -> &mut Self {
    self.compressor_version = v;
    self
  }

  /// Set `cmid` CameraID.
  #[inline(always)]
  pub fn set_camera_id(&mut self, v: Option<String>) -> &mut Self {
    self.camera_id = v;
    self
  }

  /// Set Title (the copyright-symbol `nam`).
  #[inline(always)]
  pub fn set_title(&mut self, v: Option<String>) -> &mut Self {
    self.title = v;
    self
  }

  /// Set Comment (the copyright-symbol `cmt`).
  #[inline(always)]
  pub fn set_comment(&mut self, v: Option<String>) -> &mut Self {
    self.comment = v;
    self
  }

  /// Set Copyright (the copyright-symbol `cpy`).
  #[inline(always)]
  pub fn set_copyright(&mut self, v: Option<String>) -> &mut Self {
    self.copyright = v;
    self
  }

  /// Set ContentCreateDate (the copyright-symbol `day`).
  #[inline(always)]
  pub fn set_content_create_date(&mut self, v: Option<String>) -> &mut Self {
    self.content_create_date = v;
    self
  }

  /// Set `date` DateTimeOriginal.
  #[inline(always)]
  pub fn set_date_time_original(&mut self, v: Option<String>) -> &mut Self {
    self.date_time_original = v;
    self
  }

  /// Set GPSCoordinates (the copyright-symbol `xyz`).
  #[inline(always)]
  pub fn set_gps(&mut self, v: Option<QuickTimeGps>) -> &mut Self {
    self.gps = v;
    self
  }

  /// Set `CAME` SerialNumberHash (the `unpack("H*")` hex string).
  #[inline(always)]
  pub fn set_serial_number_hash(&mut self, v: Option<String>) -> &mut Self {
    self.serial_number_hash = v;
    self
  }

  /// Set `MUID` MediaUID (the `unpack("H*")` hex string).
  #[inline(always)]
  pub fn set_media_uid(&mut self, v: Option<String>) -> &mut Self {
    self.media_uid = v;
    self
  }

  /// Record a conv-less plain-string atom (from the generated map) by its tag
  /// NAME and verbatim text value, preserving walk order.
  #[inline(always)]
  pub fn push_convless(&mut self, name: impl Into<smol_str::SmolStr>, value: String) -> &mut Self {
    self.convless.push((name.into(), value));
    self
  }
}

impl Default for QuickTimeUserData {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// **SP2** — the `moov/meta` Keys/ItemList camera/metadata, a typed mirror of
/// the camera-identity / GPS entries of `%QuickTime::Keys` (the `mdta`-handler
/// metadata, QuickTime.pm:6651-6760). The `com.apple.quicktime.` (or bare
/// `com.`) key prefix is stripped during parse. Group (`-G0:1`)
/// `QuickTime:Keys`.
#[derive(Debug, Clone, PartialEq)]
pub struct QuickTimeKeys {
  /// `make` Make (QuickTime.pm:6696).
  make: Option<String>,
  /// `model` Model (QuickTime.pm:6697).
  model: Option<String>,
  /// `software` Software (QuickTime.pm:6699).
  software: Option<String>,
  /// `creationdate` CreationDate, ISO-8601 normalized (QuickTime.pm:6683-6687).
  creation_date: Option<String>,
  /// `location.ISO6709` GPSCoordinates, decoded from ISO 6709
  /// (QuickTime.pm:6701-6712).
  gps: Option<QuickTimeGps>,
  /// `com.android.manufacturer` AndroidMake (QuickTime.pm:6764). This key is
  /// NOT in the `com.apple.quicktime` namespace, so after `ProcessKeys` strips
  /// the bare `com.` prefix the stripped form (`android.manufacturer`) does NOT
  /// match; the FULL key (`com.android.manufacturer`) does — see the
  /// stripped-then-full key fallback in [`crate::formats::quicktime`].
  android_make: Option<String>,
  /// `com.android.model` AndroidModel (QuickTime.pm:6765, full-key fallback).
  android_model: Option<String>,
  /// `com.android.version` AndroidVersion (QuickTime.pm:6762, full-key
  /// fallback).
  android_version: Option<String>,
  /// `com.android.capture.fps` AndroidCaptureFPS (QuickTime.pm:6763,
  /// `Writable => 'float'`). The `data`-atom value is an IEEE float/double
  /// (decoded by the flag-driven `QuickTimeFormat`, QuickTime.pm:9555-9569),
  /// NOT a string — so it is HAND-ported (not in the conv-less string map) and
  /// stored numerically.
  android_capture_fps: Option<f64>,
  /// `samsung.android.utc_offset` AndroidTimeZone (QuickTime.pm:6769): a non-
  /// `com.apple.quicktime` (full-key-fallback) key whose value is a plain
  /// string (e.g. `"+09:00"`). HAND-ported as a typed Keys field alongside the
  /// other Android keys (`Groups => { 2 => 'Time' }` is family-2 only).
  android_time_zone: Option<String>,
  /// The conv-less plain-string Keys atoms decoded via the generated
  /// `key → Name` map ([`crate::formats::quicktime::quicktime_generated`]) —
  /// `(Name, value)` in walk order. Emitted verbatim under `QuickTime:Keys`.
  convless: Vec<(smol_str::SmolStr, String)>,
}

impl QuickTimeKeys {
  /// An empty Keys block (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      make: None,
      model: None,
      software: None,
      creation_date: None,
      gps: None,
      android_make: None,
      android_model: None,
      android_version: None,
      android_capture_fps: None,
      android_time_zone: None,
      convless: Vec::new(),
    }
  }

  /// `make` Make.
  #[inline(always)]
  #[must_use]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }

  /// `model` Model.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// `software` Software.
  #[inline(always)]
  #[must_use]
  pub fn software(&self) -> Option<&str> {
    self.software.as_deref()
  }

  /// `creationdate` CreationDate (ISO-8601 normalized).
  #[inline(always)]
  #[must_use]
  pub fn creation_date(&self) -> Option<&str> {
    self.creation_date.as_deref()
  }

  /// `location.ISO6709` GPSCoordinates.
  #[inline(always)]
  #[must_use]
  pub const fn gps(&self) -> Option<&QuickTimeGps> {
    self.gps.as_ref()
  }

  /// `com.android.manufacturer` AndroidMake.
  #[inline(always)]
  #[must_use]
  pub fn android_make(&self) -> Option<&str> {
    self.android_make.as_deref()
  }

  /// `com.android.model` AndroidModel.
  #[inline(always)]
  #[must_use]
  pub fn android_model(&self) -> Option<&str> {
    self.android_model.as_deref()
  }

  /// `com.android.version` AndroidVersion.
  #[inline(always)]
  #[must_use]
  pub fn android_version(&self) -> Option<&str> {
    self.android_version.as_deref()
  }

  /// `com.android.capture.fps` AndroidCaptureFPS (the IEEE float/double value).
  #[inline(always)]
  #[must_use]
  pub const fn android_capture_fps(&self) -> Option<f64> {
    self.android_capture_fps
  }

  /// `samsung.android.utc_offset` AndroidTimeZone (the plain-string value).
  #[inline(always)]
  #[must_use]
  pub fn android_time_zone(&self) -> Option<&str> {
    self.android_time_zone.as_deref()
  }

  /// The conv-less plain-string Keys atoms decoded via the generated map, as
  /// `(Name, value)` in walk order.
  #[inline(always)]
  #[must_use]
  pub fn convless(&self) -> &[(smol_str::SmolStr, String)] {
    &self.convless
  }

  /// `true` when no key was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.make.is_none()
      && self.model.is_none()
      && self.software.is_none()
      && self.creation_date.is_none()
      && self.gps.is_none()
      && self.android_make.is_none()
      && self.android_model.is_none()
      && self.android_version.is_none()
      && self.android_capture_fps.is_none()
      && self.android_time_zone.is_none()
      && self.convless.is_empty()
  }

  /// Set `make` Make.
  #[inline(always)]
  pub fn set_make(&mut self, v: Option<String>) -> &mut Self {
    self.make = v;
    self
  }

  /// Set `model` Model.
  #[inline(always)]
  pub fn set_model(&mut self, v: Option<String>) -> &mut Self {
    self.model = v;
    self
  }

  /// Set `software` Software.
  #[inline(always)]
  pub fn set_software(&mut self, v: Option<String>) -> &mut Self {
    self.software = v;
    self
  }

  /// Set `creationdate` CreationDate.
  #[inline(always)]
  pub fn set_creation_date(&mut self, v: Option<String>) -> &mut Self {
    self.creation_date = v;
    self
  }

  /// Set `location.ISO6709` GPSCoordinates.
  #[inline(always)]
  pub fn set_gps(&mut self, v: Option<QuickTimeGps>) -> &mut Self {
    self.gps = v;
    self
  }

  /// Set `com.android.manufacturer` AndroidMake.
  #[inline(always)]
  pub fn set_android_make(&mut self, v: Option<String>) -> &mut Self {
    self.android_make = v;
    self
  }

  /// Set `com.android.model` AndroidModel.
  #[inline(always)]
  pub fn set_android_model(&mut self, v: Option<String>) -> &mut Self {
    self.android_model = v;
    self
  }

  /// Set `com.android.version` AndroidVersion.
  #[inline(always)]
  pub fn set_android_version(&mut self, v: Option<String>) -> &mut Self {
    self.android_version = v;
    self
  }

  /// Set `com.android.capture.fps` AndroidCaptureFPS (the IEEE float/double).
  #[inline(always)]
  pub const fn set_android_capture_fps(&mut self, v: Option<f64>) -> &mut Self {
    self.android_capture_fps = v;
    self
  }

  /// Set `samsung.android.utc_offset` AndroidTimeZone (plain string).
  #[inline(always)]
  pub fn set_android_time_zone(&mut self, v: Option<String>) -> &mut Self {
    self.android_time_zone = v;
    self
  }

  /// Record a conv-less plain-string Keys atom (from the generated map) by its
  /// tag NAME and verbatim text value, preserving walk order.
  #[inline(always)]
  pub fn push_convless(&mut self, name: impl Into<smol_str::SmolStr>, value: String) -> &mut Self {
    self.convless.push((name.into(), value));
    self
  }
}

impl Default for QuickTimeKeys {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// The faithful typed result of parsing a QuickTime / ISO-BMFF file's core
/// structural atoms — the SP1 mirror of `ProcessMOV`'s output for `ftyp`,
/// `moov`/`mvhd` and the `trak` tree, plus the **SP2** `udta` camera atoms and
/// `moov/meta` Keys/ItemList metadata. All movie-level fields are optional;
/// embedded Exif and brand variants are SP3-SP4 territory.
#[derive(Debug, Clone, PartialEq)]
pub struct QuickTimeMeta {
  /// `ftyp` MajorBrand, raw 4-byte code (trailing spaces KEPT — this is the
  /// exact `%ftypLookup` PrintConv key, QuickTime.pm:1035-1039). Trimmed
  /// only at the `File:FileType` resolution site.
  major_brand: Option<String>,
  /// `ftyp` MinorVersion, the `sprintf("%x.%x.%x", unpack("nCC", $val))`
  /// ValueConv result (QuickTime.pm:1040-1044).
  minor_version: Option<String>,
  /// `ftyp` CompatibleBrands — each 4-byte brand, NUL-containing entries
  /// dropped (QuickTime.pm:1045-1051 ValueConv).
  compatible_brands: Vec<String>,
  /// `mvhd` MovieHeaderVersion byte (QuickTime.pm:1350-1354).
  movie_header_version: Option<u8>,
  /// `mvhd` CreateDate, displayed (QuickTime.pm:1355-1374).
  create_date: Option<String>,
  /// `mvhd` ModifyDate, displayed (QuickTime.pm:1375-1381).
  modify_date: Option<String>,
  /// `mvhd` TimeScale (QuickTime.pm:1382-1385).
  time_scale: Option<u32>,
  /// `mvhd` Duration, the RAW timescale-count (QuickTime.pm:1386-1393).
  ///
  /// **R6/F1.** The `%durationInfo` ValueConv `$val / $$self{TimeScale}` runs
  /// at OUTPUT against the FINAL global movie `TimeScale` — which is
  /// last-wins across EVERY `mvhd` in the file (a later short `mvhd` can
  /// change the divisor without carrying a Duration of its own). So the raw
  /// count is stored here and divided only at serialization; see
  /// [`Self::duration_seconds`].
  duration_count: Option<u64>,
  /// `mvhd` PreferredRate, the `$val / 0x10000` ValueConv (QuickTime.pm:1394-1397).
  preferred_rate: Option<f64>,
  /// `mvhd` PreferredVolume, the `$val / 256` ValueConv (QuickTime.pm:1398-1403).
  preferred_volume: Option<f64>,
  /// `mvhd` MatrixStructure, the ValueConv-formatted 9-element string
  /// (QuickTime.pm:1404-1413).
  matrix_structure: Option<String>,
  /// `mvhd` PreviewTime, the RAW `%durationInfo` count (QuickTime.pm:1414).
  /// Divided by the final movie `TimeScale` at serialization (R6/F1).
  preview_time_count: Option<u32>,
  /// `mvhd` PreviewDuration, raw count (QuickTime.pm:1415).
  preview_duration_count: Option<u32>,
  /// `mvhd` PosterTime, raw count (QuickTime.pm:1416).
  poster_time_count: Option<u32>,
  /// `mvhd` SelectionTime, raw count (QuickTime.pm:1417).
  selection_time_count: Option<u32>,
  /// `mvhd` SelectionDuration, raw count (QuickTime.pm:1418).
  selection_duration_count: Option<u32>,
  /// `mvhd` CurrentTime, raw count (QuickTime.pm:1419).
  current_time_count: Option<u32>,
  /// `mvhd` NextTrackID (QuickTime.pm:1420).
  next_track_id: Option<u32>,
  /// `mdat-size` MediaDataSize — the `mdat` payload byte count
  /// (QuickTime.pm:689-696 + 10158-10160).
  media_data_size: Option<u64>,
  /// `mdat-offset` MediaDataOffset — the absolute file offset of the `mdat`
  /// payload (QuickTime.pm:697-700 + 10160).
  media_data_offset: Option<u64>,
  /// The top-level `frea` atom's `Image::ExifTool::Kodak::frea` tags
  /// (Kodak PixPro / Rexing — Kodak.pm:2977-2990). Empty for the common case
  /// (no `frea` atom). See [`KodakFrea`].
  kodak_frea: KodakFrea,
  /// One [`MediaTrack`] per `trak` atom, in file order.
  tracks: Vec<MediaTrack>,
  /// **SP2** — the `moov/meta` Metadata-handler HandlerType (the `hdlr`
  /// subtype, e.g. `"mdta"`). Surfaced as `QuickTime:HandlerType`
  /// (QuickTime.pm:8403-8444). `None` when the file has no `moov/meta/hdlr`.
  meta_handler_type: Option<String>,
  /// **SP2** — the `moov/meta` Metadata-handler HandlerClass / ComponentType
  /// (the `hdlr` body offset-4 code, e.g. `"mhlr"`). The SAME `%QuickTime::
  /// Handler` table drives `moov/meta/hdlr` and the per-`trak` hdlr
  /// (QuickTime.pm:8391-8402, used at 2824 + 7229/7321), so this is decoded
  /// with the same `RawConv => '$val eq "\0\0\0\0" ? undef : $val'` and the
  /// `mhlr`→Media Handler / `dhlr`→Data Handler PrintConv. Surfaced as
  /// `QuickTime:HandlerClass`. `None` for an all-zero ComponentType (the common
  /// case) or no `moov/meta/hdlr`.
  meta_handler_class: Option<String>,
  /// **SP2** — the `moov/udta` camera/metadata atoms. [`QuickTimeUserData`].
  user_data: QuickTimeUserData,
  /// **SP2** — the `moov/meta` Keys/ItemList camera/metadata. [`QuickTimeKeys`].
  keys: QuickTimeKeys,
}

impl QuickTimeMeta {
  /// An empty `QuickTimeMeta` (no atoms decoded yet).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      major_brand: None,
      minor_version: None,
      compatible_brands: Vec::new(),
      movie_header_version: None,
      create_date: None,
      modify_date: None,
      time_scale: None,
      duration_count: None,
      preferred_rate: None,
      preferred_volume: None,
      matrix_structure: None,
      preview_time_count: None,
      preview_duration_count: None,
      poster_time_count: None,
      selection_time_count: None,
      selection_duration_count: None,
      current_time_count: None,
      next_track_id: None,
      media_data_size: None,
      media_data_offset: None,
      kodak_frea: KodakFrea::new(),
      tracks: Vec::new(),
      meta_handler_type: None,
      meta_handler_class: None,
      user_data: QuickTimeUserData::new(),
      keys: QuickTimeKeys::new(),
    }
  }

  /// `ftyp` MajorBrand, raw 4-byte code (trailing spaces kept — the exact
  /// `%ftypLookup` PrintConv key).
  #[inline(always)]
  #[must_use]
  pub fn major_brand(&self) -> Option<&str> {
    self.major_brand.as_deref()
  }

  /// `ftyp` MinorVersion (`%x.%x.%x` ValueConv string).
  #[inline(always)]
  #[must_use]
  pub fn minor_version(&self) -> Option<&str> {
    self.minor_version.as_deref()
  }

  /// `ftyp` CompatibleBrands (NUL-free 4-byte brands, in file order).
  #[inline(always)]
  #[must_use]
  pub fn compatible_brands(&self) -> &[String] {
    self.compatible_brands.as_slice()
  }

  /// `mvhd` PreferredRate (post-ValueConv `$val / 0x10000`).
  #[inline(always)]
  #[must_use]
  pub const fn preferred_rate(&self) -> Option<f64> {
    self.preferred_rate
  }

  /// `mvhd` PreferredVolume (post-ValueConv `$val / 256`).
  #[inline(always)]
  #[must_use]
  pub const fn preferred_volume(&self) -> Option<f64> {
    self.preferred_volume
  }

  /// `mvhd` MatrixStructure (ValueConv-formatted string).
  #[inline(always)]
  #[must_use]
  pub fn matrix_structure(&self) -> Option<&str> {
    self.matrix_structure.as_deref()
  }

  /// `mvhd` PreviewTime — the RAW `%durationInfo` count (R6/F1). Divided by
  /// the final movie [`Self::time_scale`] at serialization.
  #[inline(always)]
  #[must_use]
  pub const fn preview_time_count(&self) -> Option<u32> {
    self.preview_time_count
  }

  /// `mvhd` PreviewDuration — raw `%durationInfo` count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn preview_duration_count(&self) -> Option<u32> {
    self.preview_duration_count
  }

  /// `mvhd` PosterTime — raw `%durationInfo` count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn poster_time_count(&self) -> Option<u32> {
    self.poster_time_count
  }

  /// `mvhd` SelectionTime — raw `%durationInfo` count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn selection_time_count(&self) -> Option<u32> {
    self.selection_time_count
  }

  /// `mvhd` SelectionDuration — raw `%durationInfo` count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn selection_duration_count(&self) -> Option<u32> {
    self.selection_duration_count
  }

  /// `mvhd` CurrentTime — raw `%durationInfo` count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn current_time_count(&self) -> Option<u32> {
    self.current_time_count
  }

  /// `mvhd` NextTrackID.
  #[inline(always)]
  #[must_use]
  pub const fn next_track_id(&self) -> Option<u32> {
    self.next_track_id
  }

  /// `mdat-size` MediaDataSize (byte count of the `mdat` payload).
  #[inline(always)]
  #[must_use]
  pub const fn media_data_size(&self) -> Option<u64> {
    self.media_data_size
  }

  /// `mdat-offset` MediaDataOffset (absolute file offset of the payload).
  #[inline(always)]
  #[must_use]
  pub const fn media_data_offset(&self) -> Option<u64> {
    self.media_data_offset
  }

  /// The top-level `frea` atom's [`KodakFrea`] tags (Kodak PixPro / Rexing).
  /// Empty (`KodakFrea::is_empty`) when no `frea` atom was decoded.
  #[inline(always)]
  #[must_use]
  pub const fn kodak_frea(&self) -> &KodakFrea {
    &self.kodak_frea
  }

  /// `mvhd` MovieHeaderVersion.
  #[inline(always)]
  #[must_use]
  pub const fn movie_header_version(&self) -> Option<u8> {
    self.movie_header_version
  }

  /// `mvhd` CreateDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn create_date(&self) -> Option<&str> {
    self.create_date.as_deref()
  }

  /// `mvhd` ModifyDate (displayed string).
  #[inline(always)]
  #[must_use]
  pub fn modify_date(&self) -> Option<&str> {
    self.modify_date.as_deref()
  }

  /// `mvhd` TimeScale.
  #[inline(always)]
  #[must_use]
  pub const fn time_scale(&self) -> Option<u32> {
    self.time_scale
  }

  /// `mvhd` Duration — the RAW timescale-count (R6/F1).
  #[inline(always)]
  #[must_use]
  pub const fn duration_count(&self) -> Option<u64> {
    self.duration_count
  }

  /// `mvhd` Duration in seconds — the `%durationInfo` ValueConv
  /// `$$self{TimeScale} ? $val / $$self{TimeScale} : $val`
  /// (QuickTime.pm:313-315) applied at OUTPUT against the FINAL global movie
  /// [`Self::time_scale`]. **R6/F1**: this division is deferred to here (not
  /// done at `mvhd` decode) so a later short `mvhd` that changes only the
  /// `TimeScale` divisor is honored — ExifTool's `$$self{TimeScale}` slot is
  /// last-wins across every `mvhd` in the file. `None` when no Duration count
  /// was decoded; a present count with no/zero `TimeScale` yields the raw
  /// count as seconds (the Perl `? :` falsy branch).
  #[inline(always)]
  #[must_use]
  pub fn duration_seconds(&self) -> Option<f64> {
    let raw = self.duration_count?;
    match self.time_scale {
      Some(ts) if ts != 0 => Some(raw as f64 / f64::from(ts)),
      _ => Some(raw as f64),
    }
  }

  /// The decoded tracks, in file order.
  #[inline(always)]
  #[must_use]
  pub fn tracks(&self) -> &[MediaTrack] {
    self.tracks.as_slice()
  }

  /// Mutable access to the track list (grow / shrink).
  #[inline(always)]
  pub const fn tracks_mut(&mut self) -> &mut Vec<MediaTrack> {
    &mut self.tracks
  }

  /// Assign the raw major-brand wrapper (4-byte code, trailing spaces kept).
  #[inline(always)]
  pub fn set_major_brand(&mut self, brand: impl Into<String>) -> &mut Self {
    self.major_brand = Some(brand.into());
    self
  }

  /// Assign the raw MinorVersion wrapper.
  #[inline(always)]
  pub fn set_minor_version(&mut self, v: Option<String>) -> &mut Self {
    self.minor_version = v;
    self
  }

  /// Replace the CompatibleBrands list.
  #[inline(always)]
  pub fn set_compatible_brands(&mut self, brands: Vec<String>) -> &mut Self {
    self.compatible_brands = brands;
    self
  }

  /// Assign the raw PreferredRate wrapper (post-ValueConv). Overwrites the
  /// prior value ONLY when `v` is `Some` — a field absent from a later short
  /// `mvhd` must not erase the earlier FoundTag value (R6/F1).
  #[inline(always)]
  pub const fn set_preferred_rate(&mut self, v: Option<f64>) -> &mut Self {
    if v.is_some() {
      self.preferred_rate = v;
    }
    self
  }

  /// Assign the raw PreferredVolume wrapper (post-ValueConv). Overwrites only
  /// when `Some` (R6/F1).
  #[inline(always)]
  pub const fn set_preferred_volume(&mut self, v: Option<f64>) -> &mut Self {
    if v.is_some() {
      self.preferred_volume = v;
    }
    self
  }

  /// Assign the raw MatrixStructure wrapper (ValueConv-formatted string).
  /// Overwrites only when `Some` (R6/F1).
  #[inline(always)]
  pub fn set_matrix_structure(&mut self, v: Option<String>) -> &mut Self {
    if v.is_some() {
      self.matrix_structure = v;
    }
    self
  }

  /// Assign the raw PreviewTime `%durationInfo` count, OVERWRITING the prior
  /// value ONLY when `v` is `Some` (R6/F1 — an absent field in a later `mvhd`
  /// must not erase the earlier FoundTag value).
  #[inline(always)]
  pub const fn set_preview_time_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.preview_time_count = v;
    }
    self
  }

  /// Assign the raw PreviewDuration count (overwrites only when `Some`, R6/F1).
  #[inline(always)]
  pub const fn set_preview_duration_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.preview_duration_count = v;
    }
    self
  }

  /// Assign the raw PosterTime count (overwrites only when `Some`, R6/F1).
  #[inline(always)]
  pub const fn set_poster_time_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.poster_time_count = v;
    }
    self
  }

  /// Assign the raw SelectionTime count (overwrites only when `Some`, R6/F1).
  #[inline(always)]
  pub const fn set_selection_time_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.selection_time_count = v;
    }
    self
  }

  /// Assign the raw SelectionDuration count (overwrites only when `Some`, R6/F1).
  #[inline(always)]
  pub const fn set_selection_duration_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.selection_duration_count = v;
    }
    self
  }

  /// Assign the raw CurrentTime count (overwrites only when `Some`, R6/F1).
  #[inline(always)]
  pub const fn set_current_time_count(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.current_time_count = v;
    }
    self
  }

  /// Assign the raw NextTrackID wrapper. Overwrites only when `Some` (R6/F1).
  #[inline(always)]
  pub const fn set_next_track_id(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.next_track_id = v;
    }
    self
  }

  /// Assign the raw MediaDataSize wrapper.
  #[inline(always)]
  pub const fn set_media_data_size(&mut self, v: Option<u64>) -> &mut Self {
    self.media_data_size = v;
    self
  }

  /// Assign the raw MediaDataOffset wrapper.
  #[inline(always)]
  pub const fn set_media_data_offset(&mut self, v: Option<u64>) -> &mut Self {
    self.media_data_offset = v;
    self
  }

  /// Mutable access to the [`KodakFrea`] tags — used by the `frea` atom
  /// handler ([`crate::formats::quicktime`]) to record `tima`/`ver`/`thma`/
  /// `scra` as they are decoded.
  #[inline(always)]
  pub const fn kodak_frea_mut(&mut self) -> &mut KodakFrea {
    &mut self.kodak_frea
  }

  /// Set the `mvhd` MovieHeaderVersion.
  #[inline(always)]
  pub const fn set_movie_header_version(&mut self, v: u8) -> &mut Self {
    self.movie_header_version = Some(v);
    self
  }

  /// Assign the raw CreateDate wrapper. Overwrites only when `Some` (R6/F1 —
  /// a field absent from a later short `mvhd` keeps the earlier value).
  #[inline(always)]
  pub fn set_create_date(&mut self, v: Option<String>) -> &mut Self {
    if v.is_some() {
      self.create_date = v;
    }
    self
  }

  /// Assign the raw ModifyDate wrapper. Overwrites only when `Some` (R6/F1).
  #[inline(always)]
  pub fn set_modify_date(&mut self, v: Option<String>) -> &mut Self {
    if v.is_some() {
      self.modify_date = v;
    }
    self
  }

  /// Assign the raw TimeScale wrapper. Overwrites only when `Some` — a
  /// `TimeScale` absent from a later short `mvhd` keeps the earlier slot, but
  /// a PRESENT `TimeScale` (last-wins, even zero) overwrites (R6/F1; the
  /// `$$self{TimeScale}` RawConv only runs when the tag is found,
  /// QuickTime.pm:1384).
  #[inline(always)]
  pub const fn set_time_scale(&mut self, v: Option<u32>) -> &mut Self {
    if v.is_some() {
      self.time_scale = v;
    }
    self
  }

  /// Assign the raw `mvhd` Duration COUNT (R6/F1), OVERWRITING the prior
  /// value ONLY when `v` is `Some` — an absent Duration in a later short
  /// `mvhd` must not delete the earlier FoundTag value (ExifTool keeps the
  /// raw found tag; only a present value, including a present zero,
  /// overwrites). The `%durationInfo` ValueConv divide is deferred to
  /// [`Self::duration_seconds`].
  #[inline(always)]
  pub const fn set_duration_count(&mut self, v: Option<u64>) -> &mut Self {
    if v.is_some() {
      self.duration_count = v;
    }
    self
  }

  /// Append a decoded track.
  #[inline(always)]
  pub fn push_track(&mut self, track: MediaTrack) -> &mut Self {
    self.tracks.push(track);
    self
  }

  /// **SP2** — the `moov/meta` HandlerType (`hdlr` subtype, e.g. `"mdta"`).
  #[inline(always)]
  #[must_use]
  pub fn meta_handler_type(&self) -> Option<&str> {
    self.meta_handler_type.as_deref()
  }

  /// **SP2** — the `moov/meta` HandlerClass / ComponentType (`hdlr` body
  /// offset-4 code, e.g. `"mhlr"`). `None` for an all-zero ComponentType.
  #[inline(always)]
  #[must_use]
  pub fn meta_handler_class(&self) -> Option<&str> {
    self.meta_handler_class.as_deref()
  }

  /// **SP2** — the decoded `moov/udta` camera/metadata atoms.
  #[inline(always)]
  #[must_use]
  pub const fn user_data(&self) -> &QuickTimeUserData {
    &self.user_data
  }

  /// **SP2** — mutable access to the `moov/udta` block (decode seam).
  #[inline(always)]
  pub const fn user_data_mut(&mut self) -> &mut QuickTimeUserData {
    &mut self.user_data
  }

  /// **SP2** — the decoded `moov/meta` Keys/ItemList camera/metadata.
  #[inline(always)]
  #[must_use]
  pub const fn keys(&self) -> &QuickTimeKeys {
    &self.keys
  }

  /// **SP2** — mutable access to the `moov/meta` Keys block (decode seam).
  #[inline(always)]
  pub const fn keys_mut(&mut self) -> &mut QuickTimeKeys {
    &mut self.keys
  }

  /// **SP2** — set the `moov/meta` HandlerType (`hdlr` subtype).
  #[inline(always)]
  pub fn set_meta_handler_type(&mut self, v: Option<String>) -> &mut Self {
    self.meta_handler_type = v;
    self
  }

  /// **SP2** — set the `moov/meta` HandlerClass / ComponentType (`hdlr` body
  /// offset-4 code). `None` for an all-zero ComponentType (RawConv-dropped).
  #[inline(always)]
  pub fn set_meta_handler_class(&mut self, v: Option<String>) -> &mut Self {
    self.meta_handler_class = v;
    self
  }
}

impl Default for QuickTimeMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn handler_kind_classification_and_roundtrip() {
    assert!(HandlerKind::from_code("vide").is_video());
    assert!(HandlerKind::from_code("soun").is_audio());
    assert!(HandlerKind::from_code("mdir").is_metadata());
    let other = HandlerKind::from_code("url ");
    assert!(other.is_other());
    assert_eq!(other.code(), "url "); // trailing space preserved
    // Named variant codes are canonical.
    assert_eq!(HandlerKind::Video.code(), "vide");
  }

  #[test]
  fn media_track_merge_only_overwrites_some() {
    let mut acc = MediaTrack::new();
    acc.set_handler(HandlerKind::Audio);
    let mut hdr = MediaTrack::new();
    hdr.set_track_id(Some(2)).set_image_width(Some(1920));
    acc.merge_track_header(hdr);
    // Header fields merged in.
    assert_eq!(acc.track_id(), Some(2));
    assert_eq!(acc.image_width(), Some(1920));
    // The pre-existing handler is untouched (merge only touches tkhd fields).
    assert!(acc.handler().expect("handler").is_audio());
  }

  #[test]
  fn quicktime_meta_track_accumulation() {
    let mut qt = QuickTimeMeta::new();
    qt.set_time_scale(Some(600)).set_movie_header_version(0);
    let mut t = MediaTrack::new();
    t.set_handler(HandlerKind::Video);
    qt.push_track(t);
    assert_eq!(qt.tracks().len(), 1);
    assert_eq!(qt.time_scale(), Some(600));
  }
}
