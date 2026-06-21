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

/// A `colr` `ColorRepresentation` sub-atom decoded via the
/// `%QuickTime::ColorRep` ProcessBinaryData table (QuickTime.pm:3106). The
/// `colr` box body begins with a 4-byte color-type 4cc (`ColorProfiles`); for
/// the `nclx`/`nclc` types the CICP coding-independent code points follow. The
/// `prof`/`rICC` types carry an ICC profile instead, so only `ColorProfiles`
/// is populated for them (the int16u fields stay `None` — their bytes are an
/// ICC blob, not CICP enums). `VideoFullRangeFlag` exists for `nclx` only (it
/// is the trailing range byte the `nclc` layout lacks); a short box leaves it
/// `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct ColorRepresentation {
  /// `ColorProfiles` (offset 0, `undef[4]`): the color-type 4cc — `nclx`,
  /// `nclc`, `prof`, or `rICC` (QuickTime.pm:3110). Emitted verbatim in both
  /// modes (no PrintConv). Drives `Track<N>:ColorProfiles`.
  color_profiles: Option<String>,
  /// `ColorPrimaries` (offset 4, `int16u`): the CICP colour-primaries index
  /// (QuickTime.pm:3111). `Some` only for `nclx`/`nclc`. The `%QuickTime::ColorRep`
  /// PrintConv maps the value at `-j`; the raw int rides at `-n`.
  color_primaries: Option<u16>,
  /// `TransferCharacteristics` (offset 6, `int16u`): the CICP transfer-function
  /// index (QuickTime.pm:3130). `Some` only for `nclx`/`nclc`.
  transfer_characteristics: Option<u16>,
  /// `MatrixCoefficients` (offset 8, `int16u`): the CICP matrix-coefficients
  /// index (QuickTime.pm:3153). `Some` only for `nclx`/`nclc`.
  matrix_coefficients: Option<u16>,
  /// `VideoFullRangeFlag` (offset 10, `Mask => 0x80`): the `nclx` full-range
  /// bit — `(byte >> 7) & 1` (QuickTime.pm:3175). PrintConv `0 => Limited`,
  /// `1 => Full`. `None` for `nclc` (no range byte) or a short box.
  video_full_range_flag: Option<u8>,
}

impl ColorRepresentation {
  /// An empty color representation (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      color_profiles: None,
      color_primaries: None,
      transfer_characteristics: None,
      matrix_coefficients: None,
      video_full_range_flag: None,
    }
  }

  /// `ColorProfiles` — the color-type 4cc.
  #[inline(always)]
  #[must_use]
  pub fn color_profiles(&self) -> Option<&str> {
    self.color_profiles.as_deref()
  }

  /// `ColorPrimaries` (CICP index, `nclx`/`nclc` only).
  #[inline(always)]
  #[must_use]
  pub const fn color_primaries(&self) -> Option<u16> {
    self.color_primaries
  }

  /// `TransferCharacteristics` (CICP index, `nclx`/`nclc` only).
  #[inline(always)]
  #[must_use]
  pub const fn transfer_characteristics(&self) -> Option<u16> {
    self.transfer_characteristics
  }

  /// `MatrixCoefficients` (CICP index, `nclx`/`nclc` only).
  #[inline(always)]
  #[must_use]
  pub const fn matrix_coefficients(&self) -> Option<u16> {
    self.matrix_coefficients
  }

  /// `VideoFullRangeFlag` (`nclx` only): the post-`Mask` `0` / `1` bit.
  #[inline(always)]
  #[must_use]
  pub const fn video_full_range_flag(&self) -> Option<u8> {
    self.video_full_range_flag
  }

  /// Set `ColorProfiles`.
  #[inline(always)]
  pub fn set_color_profiles(&mut self, v: Option<String>) -> &mut Self {
    self.color_profiles = v;
    self
  }

  /// Set `ColorPrimaries`.
  #[inline(always)]
  pub const fn set_color_primaries(&mut self, v: Option<u16>) -> &mut Self {
    self.color_primaries = v;
    self
  }

  /// Set `TransferCharacteristics`.
  #[inline(always)]
  pub const fn set_transfer_characteristics(&mut self, v: Option<u16>) -> &mut Self {
    self.transfer_characteristics = v;
    self
  }

  /// Set `MatrixCoefficients`.
  #[inline(always)]
  pub const fn set_matrix_coefficients(&mut self, v: Option<u16>) -> &mut Self {
    self.matrix_coefficients = v;
    self
  }

  /// Set `VideoFullRangeFlag`.
  #[inline(always)]
  pub const fn set_video_full_range_flag(&mut self, v: Option<u8>) -> &mut Self {
    self.video_full_range_flag = v;
    self
  }
}

impl Default for ColorRepresentation {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// A `btrt` `BitrateInfo` sub-atom decoded via the `%QuickTime::Bitrate`
/// ProcessBinaryData table (QuickTime.pm:1158). Three big-endian `int32u`
/// fields. The table carries `PRIORITY => 0` ("often filled with zeros"), so
/// the emitter marks these tags `Priority => 0` — a duplicate never overrides
/// (the first-extracted wins). Found as a child atom of BOTH the `vide` and the
/// `soun` sample description (`avc1`/`mp4a` both nest a `btrt`).
#[derive(Debug, Clone, PartialEq)]
pub struct Bitrate {
  /// `BufferSize` (offset 0, `int32u`, QuickTime.pm:1163).
  buffer_size: Option<u32>,
  /// `MaxBitrate` (offset 4, `int32u`, QuickTime.pm:1164).
  max_bitrate: Option<u32>,
  /// `AverageBitrate` (offset 8, `int32u`, QuickTime.pm:1165).
  average_bitrate: Option<u32>,
}

impl Bitrate {
  /// An empty bitrate record (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      buffer_size: None,
      max_bitrate: None,
      average_bitrate: None,
    }
  }

  /// `BufferSize`.
  #[inline(always)]
  #[must_use]
  pub const fn buffer_size(&self) -> Option<u32> {
    self.buffer_size
  }

  /// `MaxBitrate`.
  #[inline(always)]
  #[must_use]
  pub const fn max_bitrate(&self) -> Option<u32> {
    self.max_bitrate
  }

  /// `AverageBitrate`.
  #[inline(always)]
  #[must_use]
  pub const fn average_bitrate(&self) -> Option<u32> {
    self.average_bitrate
  }

  /// Set `BufferSize`.
  #[inline(always)]
  pub const fn set_buffer_size(&mut self, v: Option<u32>) -> &mut Self {
    self.buffer_size = v;
    self
  }

  /// Set `MaxBitrate`.
  #[inline(always)]
  pub const fn set_max_bitrate(&mut self, v: Option<u32>) -> &mut Self {
    self.max_bitrate = v;
    self
  }

  /// Set `AverageBitrate`.
  #[inline(always)]
  pub const fn set_average_bitrate(&mut self, v: Option<u32>) -> &mut Self {
    self.average_bitrate = v;
    self
  }

  /// Fold a later `btrt`'s fields into `self` with ExifTool `%QuickTime::Bitrate`
  /// `PRIORITY => 0` per-FIELD first-wins semantics (QuickTime.pm:1162): an
  /// already-present `BufferSize`/`MaxBitrate`/`AverageBitrate` is NEVER replaced
  /// (the existing slot is promoted to priority 1 at ExifTool.pm:9547, so the new
  /// priority-0 value's `>=` test fails), and a `None` field is filled from
  /// `other`. A present value of `0` still counts as present and wins — so a
  /// later zero-filled `btrt` does not overwrite an earlier non-zero field.
  #[inline]
  pub const fn merge_priority0(&mut self, other: &Self) {
    if self.buffer_size.is_none() {
      self.buffer_size = other.buffer_size;
    }
    if self.max_bitrate.is_none() {
      self.max_bitrate = other.max_bitrate;
    }
    if self.average_bitrate.is_none() {
      self.average_bitrate = other.average_bitrate;
    }
  }
}

impl Default for Bitrate {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// A `gmhd/gmin` Generic Media Info sub-atom decoded via the
/// `%QuickTime::GenMediaInfo` ProcessBinaryData table (QuickTime.pm:8342). The
/// table has no `FORMAT`, so the default `int8u` increment makes every key a
/// raw byte offset into the `gmin` body. Found in the `minf` of a generic
/// (text / timecode / NRT-metadata) track's `gmhd` Generic Media Header
/// (QuickTime.pm:7315-7318). All five tags are emitted even when zero.
#[derive(Debug, Clone, PartialEq)]
pub struct GenMediaInfo {
  /// `GenMediaVersion` (offset 0, `int8u`, QuickTime.pm:8345).
  version: Option<u8>,
  /// `GenFlags` (offset 1, `int8u[3]`, QuickTime.pm:8346): the space-joined
  /// 3-byte flag triplet (the `int8u[3]` `join(" ", ...)` ValueConv).
  flags: Option<String>,
  /// `GenGraphicsMode` (offset 4, `int16u`, `PrintHex => 1`,
  /// `PrintConv => \%graphicsMode`, QuickTime.pm:8347-8352): the QuickDraw
  /// transfer-mode index. PrintConv label at `-j` (a miss ⇒ `Unknown (0x%x)`
  /// since `PrintHex`), raw int at `-n`.
  graphics_mode: Option<u16>,
  /// `GenOpColor` (offset 6, `int16u[3]`, QuickTime.pm:8353): the space-joined
  /// RGB operand-colour triplet.
  op_color: Option<String>,
  /// `GenBalance` (offset 12, `fixed16s`, QuickTime.pm:8354): the rounded 8.8
  /// fixed-point sound balance (mode-invariant — ValueConv-shaped only).
  balance: Option<f64>,
}

impl GenMediaInfo {
  /// An empty generic media info record (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      version: None,
      flags: None,
      graphics_mode: None,
      op_color: None,
      balance: None,
    }
  }

  /// `GenMediaVersion`.
  #[inline(always)]
  #[must_use]
  pub const fn version(&self) -> Option<u8> {
    self.version
  }

  /// `GenFlags` — the space-joined `int8u[3]` triplet.
  #[inline(always)]
  #[must_use]
  pub fn flags(&self) -> Option<&str> {
    self.flags.as_deref()
  }

  /// `GenGraphicsMode` — the raw QuickDraw transfer-mode index.
  #[inline(always)]
  #[must_use]
  pub const fn graphics_mode(&self) -> Option<u16> {
    self.graphics_mode
  }

  /// `GenOpColor` — the space-joined `int16u[3]` RGB triplet.
  #[inline(always)]
  #[must_use]
  pub fn op_color(&self) -> Option<&str> {
    self.op_color.as_deref()
  }

  /// `GenBalance` — the rounded 8.8 fixed-point.
  #[inline(always)]
  #[must_use]
  pub const fn balance(&self) -> Option<f64> {
    self.balance
  }

  /// Set `GenMediaVersion`.
  #[inline(always)]
  pub const fn set_version(&mut self, v: Option<u8>) -> &mut Self {
    self.version = v;
    self
  }

  /// Set `GenFlags`.
  #[inline(always)]
  pub fn set_flags(&mut self, v: Option<String>) -> &mut Self {
    self.flags = v;
    self
  }

  /// Set `GenGraphicsMode`.
  #[inline(always)]
  pub const fn set_graphics_mode(&mut self, v: Option<u16>) -> &mut Self {
    self.graphics_mode = v;
    self
  }

  /// Set `GenOpColor`.
  #[inline(always)]
  pub fn set_op_color(&mut self, v: Option<String>) -> &mut Self {
    self.op_color = v;
    self
  }

  /// Set `GenBalance`.
  #[inline(always)]
  pub const fn set_balance(&mut self, v: Option<f64>) -> &mut Self {
    self.balance = v;
    self
  }

  /// Fold a later `gmin` child into `self` with ExifTool's per-field
  /// LAST-WINS-when-present semantics. ExifTool's `ProcessBinaryData` skips a
  /// field whose offset is past a SHORT atom but never DELETES an already-found
  /// tag, so a full `gmin` followed by a short duplicate keeps the earlier
  /// `Gen*` fields the short one could not reach, while overriding the ones it
  /// did decode. Mirrors [`VisualSampleDesc::merge_from`] (every field here is a
  /// plain last-wins — none is `PRIORITY => 0`). Verified against ExifTool
  /// 13.59 (full then short-Version+Flags ⇒ GraphicsMode/OpColor/Balance
  /// survive, Version/Flags last-win).
  #[inline]
  pub fn merge_from(&mut self, other: Self) {
    if other.version.is_some() {
      self.version = other.version;
    }
    if other.flags.is_some() {
      self.flags = other.flags;
    }
    if other.graphics_mode.is_some() {
      self.graphics_mode = other.graphics_mode;
    }
    if other.op_color.is_some() {
      self.op_color = other.op_color;
    }
    if other.balance.is_some() {
      self.balance = other.balance;
    }
  }
}

impl Default for GenMediaInfo {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// A `gmhd/tmcd/tcmi` Timecode Media Info sub-atom decoded via the
/// `%QuickTime::TCMediaInfo` ProcessBinaryData table (QuickTime.pm:8297). The
/// table has no `FORMAT` (default `int8u` increment), so every key is a raw
/// byte offset into the `tcmi` body. Found in a timecode track's `gmhd`
/// Generic Media Header, under the `tmcd` `TimeCode` SubDirectory (the `tcmi`
/// child — QuickTime.pm:8280-8294). It carries the text-overlay styling for a
/// burned-in timecode.
#[derive(Debug, Clone, PartialEq)]
pub struct TcMediaInfo {
  /// `TextFont` (offset 4, `int16u`, `PrintConv => { 0 => System }`,
  /// QuickTime.pm:8301-8304): the font ID. `0` ⇒ `System` at `-j`; any other
  /// value ⇒ `Unknown ($val)` (no BITMASK, no PrintHex). Raw int at `-n`.
  text_font: Option<u16>,
  /// `TextFace` (offset 6, `int16u`, `PrintConv => { 0 => Plain, BITMASK
  /// {...} }`, QuickTime.pm:8305-8320): the type-face style. `0` ⇒ `Plain`
  /// (the direct hash hit); any other value ⇒ the `DecodeBits` of the set
  /// Bold/Italic/Underline/Outline/Shadow/Condense/Extend bits at `-j`. Raw
  /// int at `-n`.
  text_face: Option<u16>,
  /// `TextSize` (offset 8, `int16u`, QuickTime.pm:8321-8324): the point size
  /// (bare int, both modes).
  text_size: Option<u16>,
  /// `TextColor` (offset 12, `int16u[3]`, QuickTime.pm:8326-8329): the
  /// space-joined RGB foreground triplet.
  text_color: Option<String>,
  /// `BackgroundColor` (offset 18, `int16u[3]`, QuickTime.pm:8330-8333): the
  /// space-joined RGB background triplet.
  background_color: Option<String>,
  /// `FontName` (offset 24, `pstring`, QuickTime.pm:8334-8338): the
  /// length-prefixed Pascal string, `Decode`d with `CharsetQuickTime`
  /// (MacRoman) by the ValueConv. Mode-invariant.
  font_name: Option<String>,
}

impl TcMediaInfo {
  /// An empty timecode media info record (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      text_font: None,
      text_face: None,
      text_size: None,
      text_color: None,
      background_color: None,
      font_name: None,
    }
  }

  /// `TextFont` — the raw font ID.
  #[inline(always)]
  #[must_use]
  pub const fn text_font(&self) -> Option<u16> {
    self.text_font
  }

  /// `TextFace` — the raw type-face style bits.
  #[inline(always)]
  #[must_use]
  pub const fn text_face(&self) -> Option<u16> {
    self.text_face
  }

  /// `TextSize` — the point size.
  #[inline(always)]
  #[must_use]
  pub const fn text_size(&self) -> Option<u16> {
    self.text_size
  }

  /// `TextColor` — the space-joined `int16u[3]` RGB triplet.
  #[inline(always)]
  #[must_use]
  pub fn text_color(&self) -> Option<&str> {
    self.text_color.as_deref()
  }

  /// `BackgroundColor` — the space-joined `int16u[3]` RGB triplet.
  #[inline(always)]
  #[must_use]
  pub fn background_color(&self) -> Option<&str> {
    self.background_color.as_deref()
  }

  /// `FontName` — the MacRoman-decoded Pascal string.
  #[inline(always)]
  #[must_use]
  pub fn font_name(&self) -> Option<&str> {
    self.font_name.as_deref()
  }

  /// Set `TextFont`.
  #[inline(always)]
  pub const fn set_text_font(&mut self, v: Option<u16>) -> &mut Self {
    self.text_font = v;
    self
  }

  /// Set `TextFace`.
  #[inline(always)]
  pub const fn set_text_face(&mut self, v: Option<u16>) -> &mut Self {
    self.text_face = v;
    self
  }

  /// Set `TextSize`.
  #[inline(always)]
  pub const fn set_text_size(&mut self, v: Option<u16>) -> &mut Self {
    self.text_size = v;
    self
  }

  /// Set `TextColor`.
  #[inline(always)]
  pub fn set_text_color(&mut self, v: Option<String>) -> &mut Self {
    self.text_color = v;
    self
  }

  /// Set `BackgroundColor`.
  #[inline(always)]
  pub fn set_background_color(&mut self, v: Option<String>) -> &mut Self {
    self.background_color = v;
    self
  }

  /// Set `FontName`.
  #[inline(always)]
  pub fn set_font_name(&mut self, v: Option<String>) -> &mut Self {
    self.font_name = v;
    self
  }

  /// Fold a later `tcmi` child into `self` with ExifTool's per-field
  /// LAST-WINS-when-present semantics (see [`GenMediaInfo::merge_from`]): a full
  /// `tcmi` followed by a short duplicate keeps the earlier `Text*`/`FontName`
  /// fields the short one could not reach. Every field is a plain last-wins.
  /// Verified against ExifTool 13.59 (full then short-TextFont ⇒ TextSize and
  /// FontName survive, TextFont last-wins).
  #[inline]
  pub fn merge_from(&mut self, other: Self) {
    if other.text_font.is_some() {
      self.text_font = other.text_font;
    }
    if other.text_face.is_some() {
      self.text_face = other.text_face;
    }
    if other.text_size.is_some() {
      self.text_size = other.text_size;
    }
    if other.text_color.is_some() {
      self.text_color = other.text_color;
    }
    if other.background_color.is_some() {
      self.background_color = other.background_color;
    }
    if other.font_name.is_some() {
      self.font_name = other.font_name;
    }
  }
}

impl Default for TcMediaInfo {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// A `vide`-track `stsd` Visual Sample Description (ExifTool
/// `%QuickTime::VisualSampleDesc`, QuickTime.pm:7585). The codec-identity
/// fields decoded by [`crate::formats::quicktime`] via the `ProcessHybrid`
/// binary layout (the table's default `FORMAT => 'int16u'` sets the per-key
/// byte stride to 2). Every field is optional: an entry too short for a given
/// offset leaves it `None`.
///
/// `ProcessSampleDesc` decodes EVERY `stsd` entry, so this struct accumulates
/// the per-tag LAST-WINS value across all entries (a later entry's present
/// field overrides an earlier one; an absent field does not clear it — see
/// [`VisualSampleDesc::merge_from`]).
#[derive(Debug, Clone, PartialEq)]
pub struct VisualSampleDesc {
  /// `CompressorID` (key 2 ⇒ byte 4, `string[4]`): the codec 4cc (`avc1`,
  /// `hvc1`, `mp4v`, …). Drives `Track<N>:CompressorID`.
  compressor_id: Option<String>,
  /// `VendorID` (key 10 ⇒ byte 20, `string[4]`, `RawConv => 'length $val ?
  /// $val : undef'`): `None` when the 4 bytes NUL-truncate to empty. Drives
  /// `Track<N>:VendorID` (the shared `%vendorID` PrintConv).
  vendor_id: Option<String>,
  /// `SourceImageWidth` (key 16 ⇒ byte 32, `int16u`).
  source_image_width: Option<u16>,
  /// `SourceImageHeight` (key 17 ⇒ byte 34, `int16u`).
  source_image_height: Option<u16>,
  /// `XResolution` (key 18 ⇒ byte 36, `fixed32u`): the rounded 16.16
  /// fixed-point DPI (`GetFixed32u`, ExifTool.pm:6139).
  x_resolution: Option<f64>,
  /// `YResolution` (key 20 ⇒ byte 40, `fixed32u`).
  y_resolution: Option<f64>,
  /// `CompressorName` (key 25 ⇒ byte 50, `string[32]`): the human-readable
  /// encoder name, post the Pascal/C-string `RawConv` (QuickTime.pm:7640).
  compressor_name: Option<String>,
  /// `BitDepth` (key 41 ⇒ byte 82, `int16u`).
  bit_depth: Option<u16>,
  /// The `colr` `ColorRepresentation` child atom (QuickTime.pm:7670), decoded
  /// after the fixed visual fields at the `ProcessHybrid` child-atom offset.
  /// `None` when the entry carries no `colr`.
  color_rep: Option<ColorRepresentation>,
  /// The `pasp` `PixelAspectRatio` child atom (QuickTime.pm:7675): the
  /// `join(":", unpack("N*", $val))` ValueConv result — two big-endian `int32u`
  /// joined by a colon (e.g. `"1:1"`), stored verbatim (mode-invariant).
  /// `None` when the entry carries no `pasp`.
  pixel_aspect_ratio: Option<String>,
  /// The `btrt` `BitrateInfo` child atom (QuickTime.pm:7574), a `PRIORITY => 0`
  /// table. `None` when the entry carries no `btrt`.
  bitrate: Option<Bitrate>,
}

impl VisualSampleDesc {
  /// An empty Visual Sample Description (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      compressor_id: None,
      vendor_id: None,
      source_image_width: None,
      source_image_height: None,
      x_resolution: None,
      y_resolution: None,
      compressor_name: None,
      bit_depth: None,
      color_rep: None,
      pixel_aspect_ratio: None,
      bitrate: None,
    }
  }

  /// `CompressorID` — the codec 4cc.
  #[inline(always)]
  #[must_use]
  pub fn compressor_id(&self) -> Option<&str> {
    self.compressor_id.as_deref()
  }

  /// `VendorID` — `None` when empty.
  #[inline(always)]
  #[must_use]
  pub fn vendor_id(&self) -> Option<&str> {
    self.vendor_id.as_deref()
  }

  /// `SourceImageWidth`.
  #[inline(always)]
  #[must_use]
  pub const fn source_image_width(&self) -> Option<u16> {
    self.source_image_width
  }

  /// `SourceImageHeight`.
  #[inline(always)]
  #[must_use]
  pub const fn source_image_height(&self) -> Option<u16> {
    self.source_image_height
  }

  /// `XResolution` (rounded 16.16 fixed-point).
  #[inline(always)]
  #[must_use]
  pub const fn x_resolution(&self) -> Option<f64> {
    self.x_resolution
  }

  /// `YResolution` (rounded 16.16 fixed-point).
  #[inline(always)]
  #[must_use]
  pub const fn y_resolution(&self) -> Option<f64> {
    self.y_resolution
  }

  /// `CompressorName` (post Pascal/C-string `RawConv`).
  #[inline(always)]
  #[must_use]
  pub fn compressor_name(&self) -> Option<&str> {
    self.compressor_name.as_deref()
  }

  /// `BitDepth`.
  #[inline(always)]
  #[must_use]
  pub const fn bit_depth(&self) -> Option<u16> {
    self.bit_depth
  }

  /// The `colr` `ColorRepresentation` child atom.
  #[inline(always)]
  #[must_use]
  pub const fn color_rep(&self) -> Option<&ColorRepresentation> {
    self.color_rep.as_ref()
  }

  /// The `pasp` `PixelAspectRatio` (the colon-joined `int32u` pair).
  #[inline(always)]
  #[must_use]
  pub fn pixel_aspect_ratio(&self) -> Option<&str> {
    self.pixel_aspect_ratio.as_deref()
  }

  /// The `btrt` `BitrateInfo` child atom.
  #[inline(always)]
  #[must_use]
  pub const fn bitrate(&self) -> Option<&Bitrate> {
    self.bitrate.as_ref()
  }

  /// Set `CompressorID`.
  #[inline(always)]
  pub fn set_compressor_id(&mut self, v: Option<String>) -> &mut Self {
    self.compressor_id = v;
    self
  }

  /// Set `VendorID`.
  #[inline(always)]
  pub fn set_vendor_id(&mut self, v: Option<String>) -> &mut Self {
    self.vendor_id = v;
    self
  }

  /// Set `SourceImageWidth`.
  #[inline(always)]
  pub const fn set_source_image_width(&mut self, v: Option<u16>) -> &mut Self {
    self.source_image_width = v;
    self
  }

  /// Set `SourceImageHeight`.
  #[inline(always)]
  pub const fn set_source_image_height(&mut self, v: Option<u16>) -> &mut Self {
    self.source_image_height = v;
    self
  }

  /// Set `XResolution`.
  #[inline(always)]
  pub const fn set_x_resolution(&mut self, v: Option<f64>) -> &mut Self {
    self.x_resolution = v;
    self
  }

  /// Set `YResolution`.
  #[inline(always)]
  pub const fn set_y_resolution(&mut self, v: Option<f64>) -> &mut Self {
    self.y_resolution = v;
    self
  }

  /// Set `CompressorName`.
  #[inline(always)]
  pub fn set_compressor_name(&mut self, v: Option<String>) -> &mut Self {
    self.compressor_name = v;
    self
  }

  /// Set `BitDepth`.
  #[inline(always)]
  pub const fn set_bit_depth(&mut self, v: Option<u16>) -> &mut Self {
    self.bit_depth = v;
    self
  }

  /// Set the `colr` `ColorRepresentation`.
  #[inline(always)]
  pub fn set_color_rep(&mut self, v: Option<ColorRepresentation>) -> &mut Self {
    self.color_rep = v;
    self
  }

  /// Set the `pasp` `PixelAspectRatio` (the colon-joined `int32u` pair).
  #[inline(always)]
  pub fn set_pixel_aspect_ratio(&mut self, v: Option<String>) -> &mut Self {
    self.pixel_aspect_ratio = v;
    self
  }

  /// Set the `btrt` `BitrateInfo`.
  #[inline(always)]
  pub fn set_bitrate(&mut self, v: Option<Bitrate>) -> &mut Self {
    self.bitrate = v;
    self
  }

  /// Fold a decoded `btrt` [`Bitrate`] into this descriptor's bitrate slot with
  /// `%QuickTime::Bitrate` `PRIORITY => 0` per-field first-wins semantics: the
  /// FIRST `btrt` seen establishes each field and a later (or zero-filled)
  /// `btrt` fills ONLY a still-`None` field, never overwriting a present one
  /// (see [`Bitrate::merge_priority0`]). Used for a REPEATED `btrt` inside one
  /// `stsd` entry.
  #[inline]
  pub fn fold_bitrate_priority0(&mut self, incoming: Bitrate) {
    match &mut self.bitrate {
      Some(existing) => existing.merge_priority0(&incoming),
      None => self.bitrate = Some(incoming),
    }
  }

  /// Fold a later `stsd` entry's Visual Sample Description into `self` with
  /// ExifTool `ProcessSampleDesc` per-tag LAST-WINS semantics: each field set
  /// (`Some`) in `other` overrides the prior value, while a field absent
  /// (`None`) in `other` leaves the earlier value intact. ExifTool re-runs
  /// `ProcessBinaryData` per entry, so a later entry's present tag overwrites
  /// the FoundTag and an absent one never erases it (QuickTime.pm:9640-9648).
  ///
  /// **`bitrate` is the exception** — `%QuickTime::Bitrate` is `PRIORITY => 0`,
  /// so its `BufferSize`/`MaxBitrate`/`AverageBitrate` are first-extracted-wins
  /// PER FIELD (QuickTime.pm:1162): a later entry's `btrt` fills only fields the
  /// earlier entries left `None`, and never replaces a present one (even `0`).
  #[inline]
  pub fn merge_from(&mut self, other: Self) {
    if other.compressor_id.is_some() {
      self.compressor_id = other.compressor_id;
    }
    if other.vendor_id.is_some() {
      self.vendor_id = other.vendor_id;
    }
    if other.source_image_width.is_some() {
      self.source_image_width = other.source_image_width;
    }
    if other.source_image_height.is_some() {
      self.source_image_height = other.source_image_height;
    }
    if other.x_resolution.is_some() {
      self.x_resolution = other.x_resolution;
    }
    if other.y_resolution.is_some() {
      self.y_resolution = other.y_resolution;
    }
    if other.compressor_name.is_some() {
      self.compressor_name = other.compressor_name;
    }
    if other.bit_depth.is_some() {
      self.bit_depth = other.bit_depth;
    }
    if other.color_rep.is_some() {
      self.color_rep = other.color_rep;
    }
    if other.pixel_aspect_ratio.is_some() {
      self.pixel_aspect_ratio = other.pixel_aspect_ratio;
    }
    // `btrt` is PRIORITY 0 (per-field first-wins), NOT last-wins like the
    // fields above: fill only fields earlier entries left `None`.
    if let Some(other_bitrate) = other.bitrate {
      self.fold_bitrate_priority0(other_bitrate);
    }
  }
}

impl Default for VisualSampleDesc {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// A `soun`-track `stsd` Audio Sample Description (ExifTool
/// `%QuickTime::AudioSampleDesc`, QuickTime.pm:7498). The audio-identity fields
/// decoded via `ProcessHybrid` (the table has no explicit `FORMAT`, so the
/// default `int8u` sets a per-key byte stride of 1). `Balance` is NOT here — it
/// comes from the track's `minf/smhd` AudioHeader (QuickTime.pm:7344), stored
/// on the [`MediaTrack`].
///
/// `ProcessSampleDesc` decodes EVERY `stsd` entry, so this struct accumulates
/// the per-tag LAST-WINS value across all entries (see
/// [`AudioSampleDesc::merge_from`]).
#[derive(Debug, Clone, PartialEq)]
pub struct AudioSampleDesc {
  /// `AudioFormat` (key 4 ⇒ byte 4, `undef[4]`): the codec 4cc (`mp4a`,
  /// `twos`, …). The `RawConv` returns `undef` unless the 4cc matches
  /// `/^[\w ]{4}$/i`, so a non-word/space code yields `None`
  /// (QuickTime.pm:7510). Drives `Track<N>:AudioFormat`.
  audio_format: Option<String>,
  /// `AudioVendorID` (key 20 ⇒ byte 20, `undef[4]`, `RawConv => '$val eq
  /// "\0\0\0\0" ? undef : $val'`, `Condition => '$$self{AudioFormat} ne
  /// "mp4s"'`): `None` when all-zero or the format is `mp4s`. Drives
  /// `Track<N>:AudioVendorID` (the shared `%vendorID` PrintConv).
  vendor_id: Option<String>,
  /// `AudioChannels` (key 24 ⇒ byte 24, `int16u`).
  channels: Option<u16>,
  /// `AudioBitsPerSample` (key 26 ⇒ byte 26, `int16u`).
  bits_per_sample: Option<u16>,
  /// `AudioSampleRate` (key 32 ⇒ byte 32, `fixed32u`): the rounded 16.16
  /// fixed-point sample rate (`GetFixed32u`).
  sample_rate: Option<f64>,
  /// The `btrt` `BitrateInfo` child atom (QuickTime.pm:7574), decoded after the
  /// fixed audio fields at the `ProcessHybrid` child-atom offset. The
  /// `%QuickTime::AudioSampleDesc` table lists `btrt` (but NOT `colr`/`pasp`),
  /// so an `mp4a` descriptor's `btrt` surfaces here. `PRIORITY => 0`. `None`
  /// when the entry carries no `btrt`.
  bitrate: Option<Bitrate>,
}

impl AudioSampleDesc {
  /// An empty Audio Sample Description (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      audio_format: None,
      vendor_id: None,
      channels: None,
      bits_per_sample: None,
      sample_rate: None,
      bitrate: None,
    }
  }

  /// `AudioFormat` — the codec 4cc (`None` if the `/^[\w ]{4}$/i` RawConv
  /// rejected it).
  #[inline(always)]
  #[must_use]
  pub fn audio_format(&self) -> Option<&str> {
    self.audio_format.as_deref()
  }

  /// `AudioVendorID` — `None` when empty or format `mp4s`.
  #[inline(always)]
  #[must_use]
  pub fn vendor_id(&self) -> Option<&str> {
    self.vendor_id.as_deref()
  }

  /// `AudioChannels`.
  #[inline(always)]
  #[must_use]
  pub const fn channels(&self) -> Option<u16> {
    self.channels
  }

  /// `AudioBitsPerSample`.
  #[inline(always)]
  #[must_use]
  pub const fn bits_per_sample(&self) -> Option<u16> {
    self.bits_per_sample
  }

  /// `AudioSampleRate` (rounded 16.16 fixed-point).
  #[inline(always)]
  #[must_use]
  pub const fn sample_rate(&self) -> Option<f64> {
    self.sample_rate
  }

  /// The `btrt` `BitrateInfo` child atom.
  #[inline(always)]
  #[must_use]
  pub const fn bitrate(&self) -> Option<&Bitrate> {
    self.bitrate.as_ref()
  }

  /// Set `AudioFormat`.
  #[inline(always)]
  pub fn set_audio_format(&mut self, v: Option<String>) -> &mut Self {
    self.audio_format = v;
    self
  }

  /// Set `AudioVendorID`.
  #[inline(always)]
  pub fn set_vendor_id(&mut self, v: Option<String>) -> &mut Self {
    self.vendor_id = v;
    self
  }

  /// Set `AudioChannels`.
  #[inline(always)]
  pub const fn set_channels(&mut self, v: Option<u16>) -> &mut Self {
    self.channels = v;
    self
  }

  /// Set `AudioBitsPerSample`.
  #[inline(always)]
  pub const fn set_bits_per_sample(&mut self, v: Option<u16>) -> &mut Self {
    self.bits_per_sample = v;
    self
  }

  /// Set `AudioSampleRate`.
  #[inline(always)]
  pub const fn set_sample_rate(&mut self, v: Option<f64>) -> &mut Self {
    self.sample_rate = v;
    self
  }

  /// Set the `btrt` `BitrateInfo`.
  #[inline(always)]
  pub fn set_bitrate(&mut self, v: Option<Bitrate>) -> &mut Self {
    self.bitrate = v;
    self
  }

  /// Fold a decoded `btrt` [`Bitrate`] into this descriptor's bitrate slot with
  /// `%QuickTime::Bitrate` `PRIORITY => 0` per-field first-wins semantics (see
  /// [`VisualSampleDesc::fold_bitrate_priority0`]). Used for a REPEATED `btrt`
  /// inside one `stsd` entry.
  #[inline]
  pub fn fold_bitrate_priority0(&mut self, incoming: Bitrate) {
    match &mut self.bitrate {
      Some(existing) => existing.merge_priority0(&incoming),
      None => self.bitrate = Some(incoming),
    }
  }

  /// Fold a later `stsd` entry's Audio Sample Description into `self` with
  /// ExifTool `ProcessSampleDesc` per-tag LAST-WINS semantics (see
  /// [`VisualSampleDesc::merge_from`]): a `Some` field in `other` overrides,
  /// a `None` field leaves the earlier value (QuickTime.pm:9640-9648). The
  /// `bitrate` field is the PRIORITY-0 exception — per-field first-wins, never
  /// overwriting a present field (QuickTime.pm:1162).
  #[inline]
  pub fn merge_from(&mut self, other: Self) {
    if other.audio_format.is_some() {
      self.audio_format = other.audio_format;
    }
    if other.vendor_id.is_some() {
      self.vendor_id = other.vendor_id;
    }
    if other.channels.is_some() {
      self.channels = other.channels;
    }
    if other.bits_per_sample.is_some() {
      self.bits_per_sample = other.bits_per_sample;
    }
    if other.sample_rate.is_some() {
      self.sample_rate = other.sample_rate;
    }
    // `btrt` is PRIORITY 0 (per-field first-wins), NOT last-wins.
    if let Some(other_bitrate) = other.bitrate {
      self.fold_bitrate_priority0(other_bitrate);
    }
  }
}

impl Default for AudioSampleDesc {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// The `%SampleTable` `stsd` sample-description table a `trak`'s descriptor was
/// routed to, decided at PARSE TIME from the handler SEEN SO FAR (file order).
///
/// ExifTool's `stsd` Condition chain (QuickTime.pm:7370-7405) tests
/// `$$self{HandlerType}` — which inits to `''` and is filled by the `hdlr` atom
/// — against `soun`/`vide`/`hint`/`meta` IN ORDER, routing each to its own
/// sample-description table, and falls through UNCONDITIONALLY to
/// `%OtherSampleDesc` for any other (or empty) handler. Because the chain reads
/// the handler-so-far, a track whose `stsd` PRECEDES its `hdlr` (or has no
/// `hdlr` at all) decodes under the empty handler and routes to
/// [`SampleDescRoute::Other`] REGARDLESS of the handler the `hdlr` later
/// assigns — the FINAL handler can never reclassify a descriptor that was
/// already decoded. Capturing the route the DECODE used (rather than re-deriving
/// it from the final handler at emission) is what keeps the emitted sample-desc
/// tags faithful for a reordered / handler-less `mdia` (verified vs bundled
/// ExifTool 13.59: a `meta` track with `stsd` before `hdlr` emits `OtherFormat`,
/// NOT `MetaFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleDescRoute {
  /// `soun` handler-so-far → `%AudioSampleDesc` (`AudioFormat`, AudioChannels, …).
  Audio,
  /// `vide` handler-so-far → `%VisualSampleDesc` (`CompressorID`, dimensions, …).
  Visual,
  /// `hint` handler-so-far → `%HintSampleDesc` (`HintFormat`, …).
  Hint,
  /// `meta` handler-so-far → `%MetaSampleDesc` (`MetaFormat`).
  Meta,
  /// Any OTHER handler-so-far, OR an empty handler (no `hdlr` yet / no `hdlr`)
  /// → the `%OtherSampleDesc` fallback (`OtherFormat`, `PlaybackFrameRate`).
  Other,
}

impl SampleDescRoute {
  /// Classify the handler SEEN SO FAR (the `stsd`-decode-time handler, file
  /// order) into the `%SampleTable` Condition chain's route
  /// (QuickTime.pm:7370-7405). `None` (no `hdlr` decoded yet) and every
  /// unmatched handler fall through to [`SampleDescRoute::Other`], mirroring
  /// ExifTool's empty-`$$self{HandlerType}` fallthrough.
  #[inline(always)]
  #[must_use]
  pub fn from_handler(handler: Option<&str>) -> Self {
    match handler {
      Some("soun") => Self::Audio,
      Some("vide") => Self::Visual,
      Some("hint") => Self::Hint,
      Some("meta") => Self::Meta,
      _ => Self::Other,
    }
  }

  /// A short label for the routed table (diagnostics / tests).
  #[inline(always)]
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Audio => "Audio",
      Self::Visual => "Visual",
      Self::Hint => "Hint",
      Self::Meta => "Meta",
      Self::Other => "Other",
    }
  }

  /// `true` for the `soun` → `%AudioSampleDesc` route.
  #[inline(always)]
  #[must_use]
  pub const fn is_audio(&self) -> bool {
    matches!(self, Self::Audio)
  }

  /// `true` for the `vide` → `%VisualSampleDesc` route.
  #[inline(always)]
  #[must_use]
  pub const fn is_visual(&self) -> bool {
    matches!(self, Self::Visual)
  }

  /// `true` for the `hint` → `%HintSampleDesc` route.
  #[inline(always)]
  #[must_use]
  pub const fn is_hint(&self) -> bool {
    matches!(self, Self::Hint)
  }

  /// `true` for the `meta` → `%MetaSampleDesc` route (gates `MetaFormat`).
  #[inline(always)]
  #[must_use]
  pub const fn is_meta(&self) -> bool {
    matches!(self, Self::Meta)
  }

  /// `true` for the `%OtherSampleDesc` fallback route (gates `OtherFormat` /
  /// `PlaybackFrameRate`) — an unmatched or empty handler-so-far.
  #[inline(always)]
  #[must_use]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other)
  }
}

/// The `mdia/minf/hdlr` data-reference handler triplet (QuickTime.pm:7319-7322
/// → `%QuickTime::Handler`): a track's SECOND `hdlr`, distinct from the
/// `mdia/hdlr` media handler. Carries the same four `%Handler` fields
/// (HandlerClass offset 4, HandlerType offset 8, HandlerVendorID offset 12,
/// HandlerDescription offset 24). Held separately on [`MediaTrack`] so the
/// per-track Handler dedup can choose between the media and the data handler
/// without the two clobbering one set of slots.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DataReferenceHandler {
  class: Option<String>,
  code: Option<String>,
  vendor_id: Option<String>,
  description: Option<String>,
}

impl DataReferenceHandler {
  /// `hdlr` HandlerClass / ComponentType (raw 4-byte code), `None` when all-zero.
  #[inline(always)]
  #[must_use]
  pub fn class(&self) -> Option<&str> {
    self.class.as_deref()
  }

  /// `hdlr` HandlerType (raw 4-byte code, verbatim — e.g. `"url "`).
  #[inline(always)]
  #[must_use]
  pub fn code(&self) -> Option<&str> {
    self.code.as_deref()
  }

  /// `hdlr` HandlerVendorID (`None` when all-zero).
  #[inline(always)]
  #[must_use]
  pub fn vendor_id(&self) -> Option<&str> {
    self.vendor_id.as_deref()
  }

  /// `hdlr` HandlerDescription (post the Pascal/C-string `RawConv`), `None`
  /// when empty.
  #[inline(always)]
  #[must_use]
  pub fn description(&self) -> Option<&str> {
    self.description.as_deref()
  }

  /// Set the raw 4-byte HandlerClass / ComponentType (already RawConv-filtered).
  #[inline(always)]
  pub fn set_class(&mut self, v: Option<String>) -> &mut Self {
    self.class = v;
    self
  }

  /// Set the raw 4-byte HandlerType code (verbatim).
  #[inline(always)]
  pub fn set_code(&mut self, v: Option<String>) -> &mut Self {
    self.code = v;
    self
  }

  /// Set the HandlerVendorID (already RawConv-filtered to non-zero).
  #[inline(always)]
  pub fn set_vendor_id(&mut self, v: Option<String>) -> &mut Self {
    self.vendor_id = v;
    self
  }

  /// Set the HandlerDescription (already RawConv-decoded).
  #[inline(always)]
  pub fn set_description(&mut self, v: Option<String>) -> &mut Self {
    self.description = v;
    self
  }

  /// Whether this `minf/hdlr` carried any extractable `%Handler` field — a
  /// HandlerType code, HandlerClass, HandlerVendorID or HandlerDescription. A
  /// short/empty/all-undef `minf/hdlr` (every field `None`) returns `false`: it
  /// extracts no tag, so it cannot own the bare `Track<N>:Handler*` key nor
  /// suppress the track's `mdia/hdlr` MEDIA handler (a fully-undef `hdlr`
  /// produces no `HandlerType` in bundled ExifTool — only the media handler
  /// shows). A present-but-zero HandlerType (`code == Some("\0\0\0\0")`) still
  /// counts as content: bundled emits `HandlerType => "Unknown ()"` for it.
  #[inline(always)]
  #[must_use]
  pub const fn has_content(&self) -> bool {
    self.class.is_some()
      || self.code.is_some()
      || self.vendor_id.is_some()
      || self.description.is_some()
  }

  /// Fold a later `minf/hdlr`'s decoded `%Handler` fields into this slot,
  /// PER FIELD (last-Some): a field the later box PROVIDES (`Some`) overrides,
  /// a field it OMITS (`None`) leaves the earlier value intact. This mirrors
  /// ExifTool's binary `%Handler` table — each of HandlerClass (offset 4),
  /// HandlerType (8), HandlerVendorID (12) and HandlerDescription (24) is an
  /// INDEPENDENT `FoundTag`, and a box whose RawConv yields `undef` for a field
  /// (an all-zero HandlerClass/VendorID, an empty HandlerDescription, or an
  /// offset past the box end) extracts NO tag for it, so it cannot override an
  /// earlier `minf/hdlr`'s value of that field. Two `minf/hdlr` boxes in one
  /// `trak` (`url ` full then a class-only `dhlr`) therefore retain the `url `'s
  /// HandlerType/Description while taking the later HandlerClass.
  #[inline(always)]
  pub fn merge_from(&mut self, other: &Self) {
    if other.class.is_some() {
      self.class = other.class.clone();
    }
    if other.code.is_some() {
      self.code = other.code.clone();
    }
    if other.vendor_id.is_some() {
      self.vendor_id = other.vendor_id.clone();
    }
    if other.description.is_some() {
      self.description = other.description.clone();
    }
  }
}

/// One walked `hdlr` box's four `%Handler` fields, recorded IN FILE ORDER as the
/// `trak` walk visits it — the `mdia/hdlr` MEDIA handler AND every `mdia/minf/hdlr`
/// DATA handler, each as a SEPARATE record (no media/data distinction stored).
/// ExifTool runs the `%Handler` binary-data table for EVERY `hdlr` box it walks
/// (QuickTime.pm:8391-8461 / 7319-7322), extracting HandlerClass (offset 4),
/// HandlerType (offset 8), HandlerVendorID (offset 12) and HandlerDescription
/// (offset 24) as FOUR independent `FoundTag`s, all into the same `Track<N>`
/// family-1 group. The position of a box in [`MediaTrack::handler_boxes`] IS its
/// monotonic parse-order sequence: the parser walks the `mdia` children in FILE
/// order, so a NORMAL `mdia(mdhd, hdlr, minf(hdlr))` records the media handler
/// before the data handler, whereas a REORDERED `mdia(mdhd, minf(hdlr), hdlr)`
/// records the data handler first and the media handler last. The per-track
/// Handler resolution (`resolve_per_track_handlers` in `formats/quicktime.rs`)
/// reads these boxes in actual file order — the per-field LAST-in-file-order
/// provider wins — with NO media-before-data assumption. A field a box does NOT
/// provide (its RawConv yields `undef` — an all-zero HandlerClass/VendorID, an
/// empty HandlerDescription, or an offset past the box end) is `None`, so it
/// never wins that field; an all-`None` box (a short/empty `hdlr`) contributes
/// nothing and can neither own a bare key nor suppress a neighbour.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HandlerBox {
  class: Option<String>,
  code: Option<String>,
  vendor_id: Option<String>,
  description: Option<String>,
}

impl HandlerBox {
  /// Build one walked `hdlr` box record from its four already-RawConv-filtered
  /// `%Handler` fields (HandlerClass / HandlerType / HandlerVendorID /
  /// HandlerDescription).
  #[inline(always)]
  #[must_use]
  pub const fn new(
    class: Option<String>,
    code: Option<String>,
    vendor_id: Option<String>,
    description: Option<String>,
  ) -> Self {
    Self {
      class,
      code,
      vendor_id,
      description,
    }
  }

  /// The box's HandlerClass / ComponentType (raw 4-byte code), `None` when
  /// all-zero or past the box end.
  #[inline(always)]
  #[must_use]
  pub fn class(&self) -> Option<&str> {
    self.class.as_deref()
  }

  /// The box's HandlerType (raw 4-byte code, verbatim), `None` when past the
  /// box end.
  #[inline(always)]
  #[must_use]
  pub fn code(&self) -> Option<&str> {
    self.code.as_deref()
  }

  /// The box's HandlerVendorID, `None` when all-zero or past the box end.
  #[inline(always)]
  #[must_use]
  pub fn vendor_id(&self) -> Option<&str> {
    self.vendor_id.as_deref()
  }

  /// The box's HandlerDescription (post the Pascal/C-string `RawConv`), `None`
  /// when empty or past the box end.
  #[inline(always)]
  #[must_use]
  pub fn description(&self) -> Option<&str> {
    self.description.as_deref()
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
  /// `stsd` sample-description 4-byte format code (`minf/stbl/stsd` entry, the
  /// `undef[4]` at offset 4 of the `%MetaSampleDesc` table — QuickTime.pm:7765),
  /// the value of the `MetaFormat` tag. Set ONLY for a `stsd` that was DECODED
  /// through the **`Meta` route** (the handler seen so far at decode time was
  /// `meta` — `Condition => '$$self{HandlerType} eq "meta"'`, QuickTime.pm:7393)
  /// — e.g. `"rtmd"` / `"camm"` / `"mebx"` for a Sony / Android / Apple
  /// timed-metadata track. `None` when no `stsd` routed `Meta`. The OtherFormat
  /// 4cc lives in the SEPARATE [`Self::other_format`] slot, so a multi-`minf`
  /// track that routes one `stsd` `Meta` and another `Other` carries BOTH
  /// without the two clobbering one shared slot (the per-`stsd` route carry of
  /// #309). Drives `Track<N>:MetaFormat`.
  meta_format: Option<String>,
  /// `stsd` sample-description 4-byte format code of a `stsd` decoded through
  /// the **`Other` route** (the `%OtherSampleDesc` fallback — an unmatched or
  /// EMPTY handler-so-far, QuickTime.pm:7802-7806; ExifTool stores it in the
  /// same `$$self{MetaFormat}` slot, but exifast keeps a distinct field so it
  /// never clobbers a `Meta`-routed `MetaFormat` from another `minf`). e.g. a
  /// `tmcd` time-code track or a `text` track. `None` when no `stsd` routed
  /// `Other`. Drives `Track<N>:OtherFormat`.
  other_format: Option<String>,
  /// `hdlr` HandlerVendorID (the `mdia/hdlr` body offset 12, `undef[4]`,
  /// QuickTime.pm:8446). `None` when all-zero (`RawConv => '$val eq
  /// "\0\0\0\0" ? undef : $val'`). Drives `Track<N>:HandlerVendorID` (the
  /// shared `%vendorID` PrintConv).
  handler_vendor_id: Option<String>,
  /// `hdlr` HandlerDescription (the `mdia/hdlr` body offset 24 to end,
  /// `string`, QuickTime.pm:8452). The post-`RawConv` value: a leading
  /// `\0`-`\x1f` byte marks a Pascal/counted string (`substr($val, 1,
  /// ord(first))`), else a NUL-terminated C string; an empty result is `None`.
  /// Drives `Track<N>:HandlerDescription`.
  handler_description: Option<String>,
  /// The `mdia/minf/hdlr` data-reference handler triplet (HandlerClass /
  /// HandlerType / HandlerVendorID / HandlerDescription), the SECOND `hdlr` in a
  /// `trak` (a `dhlr`/`url ` data handler, QuickTime.pm:7319-7322 →
  /// `%QuickTime::Handler`), kept DISTINCT from the `mdia/hdlr` media triplet
  /// above. ExifTool extracts BOTH `hdlr`s into the same `Track<N>` family-1
  /// group; its group-aware JSON dedup (exiftool:2745 + 2952) then keeps, per
  /// track, ONE `HandlerClass`/`HandlerType`/`HandlerDescription` — the bare
  /// tag key lands (via the FoundTag priority shuffle, ExifTool.pm:9564) on the
  /// LAST-extracted `hdlr` in the whole file, so only the FINAL `trak`'s
  /// `minf/hdlr` survives as its track's value while every earlier `trak` keeps
  /// its `mdia/hdlr` media triplet. The emission replays that selection (see
  /// the per-track Handler block in `formats/quicktime.rs`). `None` when this
  /// `trak` has no `minf/hdlr`.
  data_handler: Option<DataReferenceHandler>,
  /// EVERY raw 4-byte `hdlr` HandlerType code the `trak` walk encounters, in
  /// file order — the `mdia/hdlr` MEDIA handler followed by EACH `mdia/minf/hdlr`
  /// DATA handler, INCLUDING repeated `minf` boxes (the parser walks every
  /// `minf` child). Distinct from both [`Self::handler_code`] (the single
  /// `mdia/hdlr` 4cc that is the `HandlerType` tag) and [`Self::data_handler`]
  /// (the SINGLE last-wins data-reference triplet the Handler dedup may surface):
  /// each of those keeps only ONE code, whereas ExifTool runs the `%Handler`
  /// `HandlerType` RawConv (QuickTime.pm:8407-8414) for EVERY `hdlr` box it
  /// walks. This complete list is what the no-`ee` `EEWarn` iterates so the
  /// warning fires for ANY `%eeBox` code seen — even one carried by a `minf/hdlr`
  /// that a LATER `minf/hdlr` overwrites in the `data_handler` slot (a track with
  /// `mdia/hdlr=vide` + first `minf/hdlr=meta` + later `minf/hdlr=url ` still
  /// warns on the `meta`). The triplet emission is UNCHANGED (still the
  /// last-surviving `hdlr` per group). Empty when the `trak` has no `hdlr`.
  all_handler_codes: std::vec::Vec<String>,
  /// EVERY walked `hdlr` box's four `%Handler` fields ([`HandlerBox`]), recorded
  /// IN FILE ORDER — the `mdia/hdlr` MEDIA handler AND each `mdia/minf/hdlr` DATA
  /// handler, in the order the `trak` walk visits them (the `mdia` children are
  /// walked in file order). The `Vec` position is the box's monotonic parse-order
  /// sequence, so a NORMAL `mdia(hdlr, minf(hdlr))` lists the media box before the
  /// data box, while a REORDERED `mdia(minf(hdlr), hdlr)` lists the data box first.
  /// This is what `resolve_per_track_handlers` reads for the per-field
  /// LAST-in-file-order Handler resolution — NO media-before-data assumption. The
  /// per-`mdia/hdlr` media triplet ([`Self::handler_class`] etc.) and the merged
  /// [`Self::data_handler`] slot are KEPT for the [`crate::metadata::MediaMetadata`]
  /// projection and the existing accessors; this `Vec` is the additive provenance
  /// channel the resolver consults. Empty when the `trak` has no `hdlr`.
  handler_boxes: std::vec::Vec<HandlerBox>,
  /// `minf/smhd` AudioHeader Balance (the `%QuickTime::AudioHeader` key 2 ⇒
  /// byte 4, `fixed16s`, QuickTime.pm:7349). Present only for an audio track
  /// with an `smhd`. Drives `Track<N>:Balance` (the rounded 16.8 fixed-point).
  audio_balance: Option<f64>,
  /// The first `stsd` Visual Sample Description (a `vide`-handler track),
  /// [`VisualSampleDesc`]. `None` for a non-video track or an undecoded `stsd`.
  visual_sample_desc: Option<VisualSampleDesc>,
  /// The first `stsd` Audio Sample Description (a `soun`-handler track),
  /// [`AudioSampleDesc`]. `None` for a non-audio track or an undecoded `stsd`.
  audio_sample_desc: Option<AudioSampleDesc>,
  /// `minf/vmhd` VideoHeader GraphicsMode (the `%QuickTime::VideoHeader` key 2
  /// ⇒ byte 4, `int16u`, `PrintHex => 1`, `PrintConv => \%graphicsMode`,
  /// QuickTime.pm:7335-7340). Present only for a video track with a `vmhd`.
  /// Drives `Track<N>:GraphicsMode` (label at `-j`, raw int at `-n`).
  video_graphics_mode: Option<u16>,
  /// `minf/vmhd` VideoHeader OpColor (key 3 ⇒ byte 6, `int16u[3]`,
  /// QuickTime.pm:7341): the space-joined RGB operand-colour triplet. Drives
  /// `Track<N>:OpColor`.
  video_op_color: Option<String>,
  /// `tref/tmcd` TimecodeTrack — the referenced timecode track's ID
  /// (`%QuickTime::TrackRef` `tmcd` ⇒ `int32u`, QuickTime.pm:3428). The `tref`
  /// is a DIRECT child of `trak`. Drives `Track<N>:TimecodeTrack` (bare int).
  timecode_track: Option<u32>,
  /// `minf/gmhd/gmin` Generic Media Info ([`GenMediaInfo`],
  /// QuickTime.pm:8272-8275). Present for a generic (text / timecode /
  /// NRT-metadata) track with a `gmhd`. Drives the `Track<N>:Gen*` tags.
  gen_media_info: Option<GenMediaInfo>,
  /// `minf/gmhd/tmcd/tcmi` Timecode Media Info ([`TcMediaInfo`],
  /// QuickTime.pm:8280-8294). Present for a timecode track whose `gmhd` carries
  /// a `tmcd` `TimeCode` SubDirectory. Drives the `Track<N>` text-styling tags.
  tc_media_info: Option<TcMediaInfo>,
  /// `minf/stbl/stts`-derived VideoFrameRate (`%QuickTime::TimeToSampleTable`
  /// `stts` ⇒ `Name => 'VideoFrameRate'`, QuickTime.pm:7408-7417). The RAW
  /// `CalcSampleRate` quotient (`Σ sampleCount * MediaTimeScale / Σ
  /// sampleCount*sampleDelta`, QuickTime.pm:8856-8868) BEFORE the
  /// `int($val*1000+0.5)/1000` PrintConv — stored raw so the `-n` path emits the
  /// full `%.15g` value and the `-j` path applies the PrintConv. Computed ONLY
  /// for a `vide`-handler track (`Condition => '$$self{MediaType} eq "vide"'`)
  /// with a non-degenerate `stts` and a non-zero MediaTimeScale (else `None`,
  /// matching `CalcSampleRate`'s `return undef unless $num and $dur and
  /// $$et{MediaTS}`). Drives `Track<N>:VideoFrameRate`.
  video_frame_rate: Option<f64>,
  /// `minf/stbl/stsd` (OtherSampleDesc) PlaybackFrameRate — the `rational64u` at
  /// sample-entry offset 24 of a `tmcd` timecode descriptor (`%OtherSampleDesc`
  /// `24 => { Condition => '$$self{MetaFormat} eq "tmcd"', Name =>
  /// 'PlaybackFrameRate', Format => 'rational64u' }`, QuickTime.pm:7807-7811).
  /// Stored as the raw `(numerator, denominator)` `int32u` pair; the emission
  /// builds a `Rational::rational64` (no PrintConv, so both `-j`/`-n` render the
  /// `%.10g` quotient). `None` for a non-`tmcd` descriptor or a too-short entry.
  /// Drives `Track<N>:PlaybackFrameRate`.
  playback_frame_rate: Option<(u32, u32)>,
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
      meta_format: None,
      other_format: None,
      handler_vendor_id: None,
      handler_description: None,
      data_handler: None,
      all_handler_codes: std::vec::Vec::new(),
      handler_boxes: std::vec::Vec::new(),
      audio_balance: None,
      visual_sample_desc: None,
      audio_sample_desc: None,
      video_graphics_mode: None,
      video_op_color: None,
      timecode_track: None,
      gen_media_info: None,
      tc_media_info: None,
      video_frame_rate: None,
      playback_frame_rate: None,
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

  /// The `MetaFormat` 4cc of a `stsd` decoded through the `Meta` route (`"rtmd"`
  /// / `"camm"` / `"mebx"` for a timed-metadata track), or `None` when no `stsd`
  /// routed `Meta`. Drives `Track<N>:MetaFormat` (QuickTime.pm:7393
  /// `MetaSampleDesc`). The `Other`-route fallback 4cc is [`Self::other_format`].
  #[inline(always)]
  #[must_use]
  pub fn meta_format(&self) -> Option<&str> {
    self.meta_format.as_deref()
  }

  /// The `OtherFormat` 4cc of a `stsd` decoded through the `Other` route (the
  /// `%OtherSampleDesc` fallback — e.g. a `tmcd`/`text` track or a reordered /
  /// handler-less `stsd`), or `None` when no `stsd` routed `Other`. Drives
  /// `Track<N>:OtherFormat` (QuickTime.pm:7802-7806).
  #[inline(always)]
  #[must_use]
  pub fn other_format(&self) -> Option<&str> {
    self.other_format.as_deref()
  }

  /// `hdlr` HandlerVendorID (`None` when all-zero).
  #[inline(always)]
  #[must_use]
  pub fn handler_vendor_id(&self) -> Option<&str> {
    self.handler_vendor_id.as_deref()
  }

  /// `hdlr` HandlerDescription (post the Pascal/C-string `RawConv`), `None`
  /// when empty.
  #[inline(always)]
  #[must_use]
  pub fn handler_description(&self) -> Option<&str> {
    self.handler_description.as_deref()
  }

  /// The `mdia/minf/hdlr` data-reference handler triplet (the track's SECOND
  /// `hdlr`), or `None` when the `trak` has no `minf/hdlr`. Distinct from the
  /// `mdia/hdlr` media handler above; the per-track Handler dedup chooses
  /// between them.
  #[inline(always)]
  #[must_use]
  pub const fn data_handler(&self) -> Option<&DataReferenceHandler> {
    self.data_handler.as_ref()
  }

  /// Fold one `mdia/minf/hdlr` data-reference handler into the track's slot,
  /// PER FIELD (last-Some — [`DataReferenceHandler::merge_from`]). The parser
  /// builds the candidate from one `minf/hdlr` body and only calls this when the
  /// candidate carries content ([`DataReferenceHandler::has_content`]); a
  /// fully-undef `minf/hdlr` is a no-op at the walk source, so it can neither
  /// clear nor overwrite a prior valid handler (a short/empty box never erases
  /// an earlier `url ` triplet). When a `trak` carries SEVERAL `minf/hdlr`
  /// boxes, each contributes only the `%Handler` fields it provides, so the slot
  /// accumulates the per-field LAST value across them (a `url ` full then a
  /// class-only `dhlr` keeps the `url ` HandlerType/Description, takes the later
  /// HandlerClass) — exactly the bundled last-extracted-per-`FoundTag` result.
  #[inline(always)]
  pub fn merge_data_handler(&mut self, handler: &DataReferenceHandler) {
    match &mut self.data_handler {
      Some(slot) => slot.merge_from(handler),
      slot @ None => *slot = Some(handler.clone()),
    }
  }

  /// EVERY `hdlr` HandlerType code the `trak` walk encountered, in file order
  /// (`mdia/hdlr` then each `mdia/minf/hdlr`, including repeated `minf` boxes).
  /// The no-`ee` `EEWarn` iterates this complete list so it sees every
  /// `%eeBox` code regardless of which one won the single-slot
  /// [`Self::data_handler`] triplet.
  #[inline(always)]
  #[must_use]
  pub fn all_handler_codes(&self) -> &[String] {
    &self.all_handler_codes
  }

  /// EVERY walked `hdlr` box's four `%Handler` fields ([`HandlerBox`]), in FILE
  /// ORDER (the `mdia/hdlr` media handler and each `mdia/minf/hdlr` data handler,
  /// in walk order). The slice position is the box's parse-order sequence; the
  /// per-track Handler resolution reads it for the per-field LAST-in-file-order
  /// provider, with NO media-before-data assumption.
  #[inline(always)]
  #[must_use]
  pub fn handler_boxes(&self) -> &[HandlerBox] {
    &self.handler_boxes
  }

  /// `minf/smhd` Balance (the rounded 16.8 fixed-point), `None` for a track
  /// with no audio media header.
  #[inline(always)]
  #[must_use]
  pub const fn audio_balance(&self) -> Option<f64> {
    self.audio_balance
  }

  /// The merged `stsd` Visual Sample Description (a `vide`-handler track;
  /// per-tag last-wins across all sample-description entries).
  #[inline(always)]
  #[must_use]
  pub const fn visual_sample_desc(&self) -> Option<&VisualSampleDesc> {
    self.visual_sample_desc.as_ref()
  }

  /// The merged `stsd` Audio Sample Description (a `soun`-handler track;
  /// per-tag last-wins across all sample-description entries).
  #[inline(always)]
  #[must_use]
  pub const fn audio_sample_desc(&self) -> Option<&AudioSampleDesc> {
    self.audio_sample_desc.as_ref()
  }

  /// `minf/vmhd` VideoHeader GraphicsMode (the raw QuickDraw transfer-mode
  /// index, `int16u`).
  #[inline(always)]
  #[must_use]
  pub const fn video_graphics_mode(&self) -> Option<u16> {
    self.video_graphics_mode
  }

  /// `minf/vmhd` VideoHeader OpColor (the space-joined `int16u[3]` RGB triplet).
  #[inline(always)]
  #[must_use]
  pub fn video_op_color(&self) -> Option<&str> {
    self.video_op_color.as_deref()
  }

  /// `tref/tmcd` TimecodeTrack — the referenced timecode track's ID.
  #[inline(always)]
  #[must_use]
  pub const fn timecode_track(&self) -> Option<u32> {
    self.timecode_track
  }

  /// `minf/gmhd/gmin` Generic Media Info ([`GenMediaInfo`]).
  #[inline(always)]
  #[must_use]
  pub const fn gen_media_info(&self) -> Option<&GenMediaInfo> {
    self.gen_media_info.as_ref()
  }

  /// `minf/gmhd/tmcd/tcmi` Timecode Media Info ([`TcMediaInfo`]).
  #[inline(always)]
  #[must_use]
  pub const fn tc_media_info(&self) -> Option<&TcMediaInfo> {
    self.tc_media_info.as_ref()
  }

  /// The raw `stts`-derived VideoFrameRate quotient (BEFORE the
  /// `int($val*1000+0.5)/1000` PrintConv). `None` for a non-video track or a
  /// degenerate sample table.
  #[inline(always)]
  #[must_use]
  pub const fn video_frame_rate(&self) -> Option<f64> {
    self.video_frame_rate
  }

  /// The `tmcd` PlaybackFrameRate as the raw `(numerator, denominator)`
  /// `rational64u` pair (sample-entry offset 24). `None` when absent.
  #[inline(always)]
  #[must_use]
  pub const fn playback_frame_rate(&self) -> Option<(u32, u32)> {
    self.playback_frame_rate
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

  /// Append a raw 4-byte `hdlr` HandlerType code to the file-order
  /// [`Self::all_handler_codes`] accumulation. Called by the parser at EVERY
  /// `hdlr` box of the `trak` walk (`mdia/hdlr` AND every `mdia/minf/hdlr`,
  /// including repeated `minf` boxes) so the no-`ee` `EEWarn` sees the complete
  /// set — separate from the single-slot media/data-handler triplets.
  #[inline(always)]
  pub fn push_handler_code(&mut self, code: impl Into<String>) -> &mut Self {
    self.all_handler_codes.push(code.into());
    self
  }

  /// Append one walked `hdlr` box's four `%Handler` fields ([`HandlerBox`]) to
  /// the file-order [`Self::handler_boxes`] provenance. Called by the parser at
  /// EVERY `hdlr` box of the `trak` walk (the `mdia/hdlr` media handler AND each
  /// `mdia/minf/hdlr` data handler, in walk order), so the slice records the boxes
  /// in actual file order for the per-field LAST-in-file-order Handler resolution.
  /// A fully-undef box (every field `None`) is still recorded — it simply wins no
  /// field — so the caller need not pre-filter on content.
  #[inline(always)]
  pub fn push_handler_box(&mut self, handler: HandlerBox) -> &mut Self {
    self.handler_boxes.push(handler);
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

  /// Set the `Meta`-route `MetaFormat` 4cc (filled by the parser when a
  /// `mdia/minf/stbl/stsd` routes through the `meta` handler).
  #[inline(always)]
  pub fn set_meta_format(&mut self, v: Option<String>) -> &mut Self {
    self.meta_format = v;
    self
  }

  /// Set the `Other`-route `OtherFormat` 4cc (filled by the parser when a
  /// `mdia/minf/stbl/stsd` routes through the `%OtherSampleDesc` fallback).
  #[inline(always)]
  pub fn set_other_format(&mut self, v: Option<String>) -> &mut Self {
    self.other_format = v;
    self
  }

  /// Set the `hdlr` HandlerVendorID (already RawConv-filtered to non-zero).
  #[inline(always)]
  pub fn set_handler_vendor_id(&mut self, v: Option<String>) -> &mut Self {
    self.handler_vendor_id = v;
    self
  }

  /// Set the `hdlr` HandlerDescription (already RawConv-decoded).
  #[inline(always)]
  pub fn set_handler_description(&mut self, v: Option<String>) -> &mut Self {
    self.handler_description = v;
    self
  }

  /// Set the `minf/smhd` Balance.
  #[inline(always)]
  pub const fn set_audio_balance(&mut self, v: Option<f64>) -> &mut Self {
    self.audio_balance = v;
    self
  }

  /// Set the merged `stsd` Visual Sample Description.
  #[inline(always)]
  pub fn set_visual_sample_desc(&mut self, v: Option<VisualSampleDesc>) -> &mut Self {
    self.visual_sample_desc = v;
    self
  }

  /// Set the merged `stsd` Audio Sample Description.
  #[inline(always)]
  pub fn set_audio_sample_desc(&mut self, v: Option<AudioSampleDesc>) -> &mut Self {
    self.audio_sample_desc = v;
    self
  }

  /// Set the `minf/vmhd` VideoHeader GraphicsMode.
  #[inline(always)]
  pub const fn set_video_graphics_mode(&mut self, v: Option<u16>) -> &mut Self {
    self.video_graphics_mode = v;
    self
  }

  /// Set the `minf/vmhd` VideoHeader OpColor.
  #[inline(always)]
  pub fn set_video_op_color(&mut self, v: Option<String>) -> &mut Self {
    self.video_op_color = v;
    self
  }

  /// Set the `tref/tmcd` TimecodeTrack.
  #[inline(always)]
  pub const fn set_timecode_track(&mut self, v: Option<u32>) -> &mut Self {
    self.timecode_track = v;
    self
  }

  /// Set the `minf/gmhd/gmin` Generic Media Info.
  #[inline(always)]
  pub fn set_gen_media_info(&mut self, v: Option<GenMediaInfo>) -> &mut Self {
    self.gen_media_info = v;
    self
  }

  /// Set the `minf/gmhd/tmcd/tcmi` Timecode Media Info.
  #[inline(always)]
  pub fn set_tc_media_info(&mut self, v: Option<TcMediaInfo>) -> &mut Self {
    self.tc_media_info = v;
    self
  }

  /// Set the raw `stts`-derived VideoFrameRate quotient.
  #[inline(always)]
  pub const fn set_video_frame_rate(&mut self, v: Option<f64>) -> &mut Self {
    self.video_frame_rate = v;
    self
  }

  /// Set the `tmcd` PlaybackFrameRate `(numerator, denominator)` pair.
  #[inline(always)]
  pub const fn set_playback_frame_rate(&mut self, v: Option<(u32, u32)>) -> &mut Self {
    self.playback_frame_rate = v;
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
  /// The conv-less camera atoms decoded via the generated `4cc → Name` map
  /// ([`crate::formats::quicktime::quicktime_generated`]) — `(Name, value)` in
  /// walk order. These carry NO conversion and NO priority, so they are emitted
  /// verbatim under `QuickTime:UserData`; modeling them in one ordered sink (vs
  /// a typed field each) keeps the supplementary map the single source of truth
  /// (a new conv-less atom = regenerate, no Rust edit).
  ///
  /// The value is a [`crate::value::TagValue`] rather than a `String` because
  /// the `%QuickTime::UserData` table is `FORMAT => 'string'`, so a conv-less
  /// UserData atom is always read as a string and stored as
  /// [`crate::value::TagValue::Str`]. The richer value type is shared with the
  /// `Keys` block (whose table has NO `FORMAT`, so a conv-less `data` atom can
  /// faithfully be a number or binary placeholder — QuickTime.pm:10396-10416);
  /// keeping one value type across both keeps the emit path uniform.
  convless: Vec<(smol_str::SmolStr, crate::value::TagValue)>,
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

  /// The conv-less atoms decoded via the generated map, as `(Name, value)` in
  /// walk order. Each value is a [`crate::value::TagValue`] (always
  /// [`crate::value::TagValue::Str`] for UserData — see [`Self`]).
  #[inline(always)]
  #[must_use]
  pub fn convless(&self) -> &[(smol_str::SmolStr, crate::value::TagValue)] {
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
  ///
  /// This is a DIFFERENT dedup surface from the `(group, name)` tag-stream
  /// FoundTag dedup the shared [`crate::tagmap::effective_priority`] /
  /// [`crate::tagmap::dedup_override`] helpers govern: it selects WHICH SOURCE
  /// ATOM wins for one TYPED [`MediaMetadata`](crate::metadata::MediaMetadata)
  /// field (Make/Model/SerialNumber/FirmwareVersion — each fed by several
  /// distinct `udta` atoms), not which value survives in the rendered tag list.
  /// The field names are FIXED camera identifiers, never `Warning`/`Error`, so
  /// the effective-priority NAME coercion is meaningless here. Its NON-empty
  /// branch nonetheless coincides exactly with [`crate::tagmap::dedup_override`]
  /// (`priority >= 1` ≡ `priority != 0 && priority >= stored` for `priority`,
  /// `stored` ∈ `{0, 1}`); the `None => true` empty-fill is the typed analogue of
  /// the tag sinks' "new key ⇒ push" branch. Kept on this typed-domain shape
  /// (`Option<PriorityValue>`) by design — it is NOT a tag-collection collapse.
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

  /// Record a conv-less atom (from the generated map) by its tag NAME and
  /// decoded [`crate::value::TagValue`], preserving walk order. UserData passes
  /// a [`crate::value::TagValue::Str`]; the parameter is the richer value type
  /// shared with the `Keys` block (see [`Self`]).
  #[inline(always)]
  pub fn push_convless(
    &mut self,
    name: impl Into<smol_str::SmolStr>,
    value: crate::value::TagValue,
  ) -> &mut Self {
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
  /// `creationdate` CreationDate, ISO-8601 normalized (QuickTime.pm:6683-6687).
  /// CONV-BEARING (`%iso8601Date`), so it is decoded into a typed field rather
  /// than flowing through the conv-less cascade.
  creation_date: Option<String>,
  /// `location.ISO6709` GPSCoordinates, decoded from ISO 6709
  /// (QuickTime.pm:6701-6712). CONV-BEARING (`ConvertISO6709` + the
  /// `PrintGPSCoordinates` print-conv), so it is decoded into a typed field.
  gps: Option<QuickTimeGps>,
  /// Every CONV-LESS `%QuickTime::Keys` atom (no `Format`, no `ValueConv`), as
  /// `(Name, value)` in walk order — the camera-identity keys
  /// (`Make`/`Model`/`Software`/`AndroidMake`/`AndroidModel`/`AndroidVersion`/
  /// `AndroidCaptureFPS`/`AndroidTimeZone`) AND the generated map keys
  /// (`CameraDirection`/`CameraMotion`,
  /// [`crate::formats::quicktime::quicktime_generated`]). Emitted verbatim under
  /// `QuickTime:Keys`. Only `creation_date` / `gps` (conv-bearing) live in
  /// dedicated typed fields.
  ///
  /// The value is a [`crate::value::TagValue`]: the `%QuickTime::Keys` table has
  /// NO table-level `FORMAT` (unlike `%QuickTime::UserData`), so a conv-less
  /// `data` atom with no `Format`/`ValueConv` follows the full
  /// string→numeric→binary cascade (QuickTime.pm:10387-10416) — a string
  /// ([`crate::value::TagValue::Str`]), a number ([`crate::value::TagValue::U64`]
  /// / `I64` / `F64`, from `QuickTimeFormat`), or, with no usable format, the
  /// binary scalar-ref placeholder ([`crate::value::TagValue::Bytes`]). This is
  /// faithful to EVERY format flag — a `Make` written with a numeric flag emits
  /// a number, an `AndroidCaptureFPS` written with a string flag emits the
  /// string — whereas the prior per-key typed fields handled only one flavor.
  convless: Vec<(smol_str::SmolStr, crate::value::TagValue)>,
}

impl QuickTimeKeys {
  /// An empty Keys block (no key decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      creation_date: None,
      gps: None,
      convless: Vec::new(),
    }
  }

  /// The string value of the conv-less atom emitted under tag `name`, resolving
  /// duplicates the SAME way the emitted tag stream does: **last-wins**. A file
  /// with two `Make` atoms emits both, and the downstream tag dedup keeps the
  /// LAST (matching the prior typed `set_make` which overwrote on each later
  /// entry); the domain projection must read that same survivor. So this returns
  /// the LAST [`Self::convless`] entry named `name`, as a string — or `None` if
  /// that surviving entry's `data`-atom flag was numeric / binary (a non-`Str`
  /// value: the emitted tag is then a number, not a usable identity string,
  /// matching the typed-string source this replaced, which dropped non-string
  /// flags). NB: scanning for the last *`Str`* instead would disagree with the
  /// emitted (last-wins) tag when the surviving duplicate is non-string.
  #[inline]
  #[must_use]
  fn convless_str(&self, name: &str) -> Option<&str> {
    self
      .convless
      .iter()
      .rev()
      .find(|(n, _)| n == name)
      .and_then(|(_, v)| match v {
        crate::value::TagValue::Str(s) => Some(s.as_str()),
        _ => None,
      })
  }

  /// `make` Make — the conv-less `Make` atom's string value (the domain camera
  /// projection reads this). Backed by a [`Self::convless`] scan.
  #[inline]
  #[must_use]
  pub fn make(&self) -> Option<&str> {
    self.convless_str("Make")
  }

  /// `model` Model — the conv-less `Model` atom's string value.
  #[inline]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.convless_str("Model")
  }

  /// `software` Software — the conv-less `Software` atom's string value.
  #[inline]
  #[must_use]
  pub fn software(&self) -> Option<&str> {
    self.convless_str("Software")
  }

  /// `com.android.manufacturer` AndroidMake — the conv-less `AndroidMake` atom's
  /// string value (a full-key-fallback Keys atom routed through the SAME
  /// string→numeric→binary cascade as `Make`). Backed by a [`Self::convless`]
  /// scan (last-wins, string-or-`None`), like [`Self::make`].
  #[inline]
  #[must_use]
  pub fn android_make(&self) -> Option<&str> {
    self.convless_str("AndroidMake")
  }

  /// `com.android.model` AndroidModel — the conv-less `AndroidModel` atom's value.
  #[inline]
  #[must_use]
  pub fn android_model(&self) -> Option<&str> {
    self.convless_str("AndroidModel")
  }

  /// `com.android.version` AndroidVersion — the conv-less `AndroidVersion` value.
  #[inline]
  #[must_use]
  pub fn android_version(&self) -> Option<&str> {
    self.convless_str("AndroidVersion")
  }

  /// `samsung.android.utc_offset` AndroidTimeZone — the conv-less `AndroidTimeZone`
  /// atom's string value.
  #[inline]
  #[must_use]
  pub fn android_time_zone(&self) -> Option<&str> {
    self.convless_str("AndroidTimeZone")
  }

  /// `com.android.capture.fps` AndroidCaptureFPS — the conv-less `AndroidCaptureFPS`
  /// atom's value as an `f64` (the typed-float view). Last-wins (matching the
  /// emitted tag); `None` unless the surviving atom decoded to a number — a
  /// string/binary flag emits a non-`F64` value, which has no typed float here.
  #[inline]
  #[must_use]
  pub fn android_capture_fps(&self) -> Option<f64> {
    self
      .convless
      .iter()
      .rev()
      .find(|(n, _)| n == "AndroidCaptureFPS")
      .and_then(|(_, v)| match v {
        crate::value::TagValue::F64(f) => Some(*f),
        _ => None,
      })
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

  /// The conv-less Keys atoms, as `(Name, value)` in walk order — the
  /// camera-identity keys and the generated-map keys. Each value is a
  /// [`crate::value::TagValue`] (string, number, or binary placeholder — see
  /// [`Self`]).
  #[inline(always)]
  #[must_use]
  pub fn convless(&self) -> &[(smol_str::SmolStr, crate::value::TagValue)] {
    &self.convless
  }

  /// `true` when no key was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.creation_date.is_none() && self.gps.is_none() && self.convless.is_empty()
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

  /// Record a conv-less Keys atom by its tag NAME and decoded
  /// [`crate::value::TagValue`] (string / number / binary placeholder),
  /// preserving walk order.
  #[inline(always)]
  pub fn push_convless(
    &mut self,
    name: impl Into<smol_str::SmolStr>,
    value: crate::value::TagValue,
  ) -> &mut Self {
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
  /// (QuickTime.pm:689-696 + 10158-10160). Last-wins (the VISIBLE tag value, as
  /// ExifTool's `-G1` render keeps), so a multi-`mdat` file shows the LAST size.
  media_data_size: Option<u64>,
  /// The SUM of EVERY `mdat` payload size seen (each `set_media_data_size` adds
  /// to this running total). `Composite:AvgBitrate`'s RawConv reads `$val[0]`
  /// (the first MediaDataSize) then `NextTagKey`-loops to add the rest
  /// (QuickTime.pm:8649-8662) — i.e. the SUM of all `mdat` sizes — while the
  /// emitted `MediaDataSize` tag stays the single (last-wins) per-`mdat` value.
  /// The dedup-collapsing `TagMap` cannot preserve the duplicates, so the
  /// pre-summed total is threaded into the composite post-pass instead.
  media_data_total: Option<u64>,
  /// `mdat-offset` MediaDataOffset — the absolute file offset of the `mdat`
  /// payload (QuickTime.pm:697-700 + 10160).
  media_data_offset: Option<u64>,
  /// The top-level `skip` atom's `Image::ExifTool::QuickTime::SkipInfo` `'ver '`
  /// Version (QuickTime.pm:1020 — "found in 70mai Pro Plus+ MP4 videos", also
  /// the Viofo A119). The raw string value; no PrintConv/ValueConv. `None` for
  /// the common case (no SkipInfo `skip` atom).
  skip_version: Option<smol_str::SmolStr>,
  /// The top-level `skip` atom's `SkipInfo` `thma` ThumbnailImage payload byte
  /// length (QuickTime.pm:1022-1026, `Binary => 1`, group2 `Preview`). Rendered
  /// as the `(Binary data N bytes, use -b option to extract)` placeholder; the
  /// bytes are not retained. `None` when no SkipInfo `thma` was decoded.
  skip_thumbnail_len: Option<u64>,
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
  /// **SP2** — the `moov/meta` HandlerVendorID (`hdlr` body offset 12,
  /// `undef[4]`). `None` when all-zero. Surfaced as `QuickTime:HandlerVendorID`.
  meta_handler_vendor_id: Option<String>,
  /// **SP2** — the `moov/meta` HandlerDescription (`hdlr` body offset 24 to
  /// end, post the Pascal/C-string `RawConv`). Surfaced as
  /// `QuickTime:HandlerDescription`.
  meta_handler_description: Option<String>,
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
      media_data_total: None,
      media_data_offset: None,
      skip_version: None,
      skip_thumbnail_len: None,
      kodak_frea: KodakFrea::new(),
      tracks: Vec::new(),
      meta_handler_type: None,
      meta_handler_class: None,
      meta_handler_vendor_id: None,
      meta_handler_description: None,
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

  /// The top-level `skip` atom's `SkipInfo` `'ver '` Version (raw string).
  #[inline(always)]
  #[must_use]
  pub fn skip_version(&self) -> Option<&str> {
    match &self.skip_version {
      Some(v) => Some(v.as_str()),
      None => None,
    }
  }

  /// The top-level `skip` atom's `SkipInfo` `thma` ThumbnailImage payload byte
  /// length (for the binary placeholder).
  #[inline(always)]
  #[must_use]
  pub const fn skip_thumbnail_len(&self) -> Option<u64> {
    self.skip_thumbnail_len
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

  /// Assign the raw MediaDataSize wrapper (the VISIBLE last-wins per-`mdat` tag)
  /// AND fold it into the running [`media_data_total`](Self::media_data_total)
  /// (the SUM `Composite:AvgBitrate` needs — QuickTime.pm:8649). A `Some(sz)`
  /// adds `sz` to the total (saturating); a `None` clears the visible value but
  /// leaves the total (no production caller passes `None`).
  #[inline(always)]
  pub const fn set_media_data_size(&mut self, v: Option<u64>) -> &mut Self {
    self.media_data_size = v;
    if let Some(sz) = v {
      self.media_data_total = Some(match self.media_data_total {
        Some(t) => t.saturating_add(sz),
        None => sz,
      });
    }
    self
  }

  /// The SUM of every `mdat` payload size (`Composite:AvgBitrate`'s
  /// `NextTagKey`-summed `$val[0]`, QuickTime.pm:8649-8662). `None` when no
  /// `mdat` was seen.
  #[inline(always)]
  #[must_use]
  pub const fn media_data_total(&self) -> Option<u64> {
    self.media_data_total
  }

  /// Assign the raw MediaDataOffset wrapper.
  #[inline(always)]
  pub const fn set_media_data_offset(&mut self, v: Option<u64>) -> &mut Self {
    self.media_data_offset = v;
    self
  }

  /// Record the top-level `skip` atom's `SkipInfo` `'ver '` Version string.
  #[inline(always)]
  pub fn set_skip_version(&mut self, v: Option<smol_str::SmolStr>) -> &mut Self {
    self.skip_version = v;
    self
  }

  /// Record the top-level `skip` atom's `SkipInfo` `thma` ThumbnailImage payload
  /// byte length.
  #[inline(always)]
  pub const fn set_skip_thumbnail_len(&mut self, v: Option<u64>) -> &mut Self {
    self.skip_thumbnail_len = v;
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

  /// **SP2** — the `moov/meta` HandlerVendorID (`None` when all-zero).
  #[inline(always)]
  #[must_use]
  pub fn meta_handler_vendor_id(&self) -> Option<&str> {
    self.meta_handler_vendor_id.as_deref()
  }

  /// **SP2** — the `moov/meta` HandlerDescription (post the Pascal/C-string
  /// `RawConv`), `None` when empty.
  #[inline(always)]
  #[must_use]
  pub fn meta_handler_description(&self) -> Option<&str> {
    self.meta_handler_description.as_deref()
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

  /// **SP2** — set the `moov/meta` HandlerVendorID (RawConv-filtered).
  #[inline(always)]
  pub fn set_meta_handler_vendor_id(&mut self, v: Option<String>) -> &mut Self {
    self.meta_handler_vendor_id = v;
    self
  }

  /// **SP2** — set the `moov/meta` HandlerDescription (RawConv-decoded).
  #[inline(always)]
  pub fn set_meta_handler_description(&mut self, v: Option<String>) -> &mut Self {
    self.meta_handler_description = v;
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
  fn keys_convless_str_accessor_is_last_wins_or_none() {
    use crate::value::TagValue;
    // Two `Make` atoms (duplicate Keys): the emitted tag stream dedups
    // last-wins, so the domain accessor must read the LAST entry, not the first
    // (the prior typed `set_make` also overwrote on each later entry).
    let mut keys = QuickTimeKeys::new();
    keys
      .push_convless("Make", TagValue::Str("FIRST".into()))
      .push_convless("Make", TagValue::Str("SECOND".into()));
    assert_eq!(keys.make(), Some("SECOND"));
    // When the SURVIVING (last) duplicate is a non-string flag (numeric/binary),
    // the emitted `Make` is a number, so the string accessor yields `None` — even
    // though an EARLIER entry was a string. (Scanning for the last *`Str`* would
    // wrongly disagree with the emitted last-wins tag.)
    let mut keys2 = QuickTimeKeys::new();
    keys2
      .push_convless("Make", TagValue::Str("STR".into()))
      .push_convless("Make", TagValue::U64(300));
    assert_eq!(keys2.make(), None);
    // A single string entry resolves normally.
    let mut keys3 = QuickTimeKeys::new();
    keys3.push_convless("Model", TagValue::Str("iPhone".into()));
    assert_eq!(keys3.model(), Some("iPhone"));
  }

  #[test]
  fn keys_android_accessors_back_by_convless() {
    use crate::value::TagValue;
    // The Android Keys accessors are convless-backed (the atoms route through the
    // same cascade as the apple identity keys), preserving the public typed API.
    let mut keys = QuickTimeKeys::new();
    keys
      .push_convless("AndroidMake", TagValue::Str("motorola".into()))
      .push_convless("AndroidModel", TagValue::Str("Pixel".into()))
      .push_convless("AndroidVersion", TagValue::Str("13".into()))
      .push_convless("AndroidTimeZone", TagValue::Str("+09:00".into()))
      .push_convless("AndroidCaptureFPS", TagValue::F64(29.97));
    assert_eq!(keys.android_make(), Some("motorola"));
    assert_eq!(keys.android_model(), Some("Pixel"));
    assert_eq!(keys.android_version(), Some("13"));
    assert_eq!(keys.android_time_zone(), Some("+09:00"));
    assert_eq!(keys.android_capture_fps(), Some(29.97));
    // A non-`F64` AndroidCaptureFPS (e.g. a string flag) has no typed float view.
    let mut k2 = QuickTimeKeys::new();
    k2.push_convless("AndroidCaptureFPS", TagValue::Str("29.97".into()));
    assert_eq!(k2.android_capture_fps(), None);
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
