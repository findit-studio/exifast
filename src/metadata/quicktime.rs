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

/// The faithful typed result of parsing a QuickTime / ISO-BMFF file's core
/// structural atoms — the SP1 mirror of `ProcessMOV`'s output for `ftyp`,
/// `moov`/`mvhd` and the `trak` tree. All movie-level fields are optional;
/// camera/user-data atoms, embedded Exif and brand variants are SP2-SP4
/// territory and are not represented here yet.
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
