// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Faithful port of `ProcessID3` (ID3.pm:1431-1632) + `ProcessMP3`
//! (ID3.pm:1684-1728). ProcessID3 is the directory-level entry point
//! invoked by ProcessMP3 (and by other audio-format Process subs that
//! optionally chain through ID3 — AIFF, MPC, APE, WV, DSF, FLAC, etc.).
//!
//! The full chain for an MP3 file (FORMATS.md row 2 "ID3 infra + MP3
//! completion") is:
//!
//! 1. `ProcessMP3` (ID3.pm:1684-1728) — file-type dispatch entry.
//! 2. → `ProcessID3` (ID3.pm:1431-1632) — sniffs ID3v2 header at start,
//!    ID3v1 trailer at end, Lyrics3, then SetFileType('MP3') and pushes
//!    File:ID3Size + ID3v2/ID3v1 tags.
//! 3. → MPEG audio frame parser (`Image::ExifTool::MPEG::ParseMPEGAudio`)
//!    — emits `MPEG:*` tags. **OUT OF PR SCOPE** — MPEG.pm is row 17.
//! 4. → APE trailer (`Image::ExifTool::APE::ProcessAPE`) — **OUT OF PR
//!    SCOPE** — APE.pm is row 5.
//!
//! Our [`ProcessMp3`] implements steps 1-2 faithfully and documents the
//! deferral of 3-4 to their respective format ports.
//!
//! # Phase F2 typed-Meta layer
//!
//! On top of the legacy push-style engine, this module exposes:
//!
//! - [`Id3Meta<'a>`] — the typed output of the ID3 directory parser
//!   ([`ProcessId3`]). Carries unified ID3v1 + ID3v2 fields (title /
//!   artist / album / year / track / genre / comment), the ID3v2
//!   version, the ID3v2 frame iterator, optional ID3v1 subframe, and
//!   optional APIC picture payloads. Constructed by the parser; consumed
//!   by the `serialize_tags` sink path (CLI JSON) or by
//!   direct typed-accessor library callers.
//! - [`Mp3Meta<'a>`] — the typed output of the MP3 wrapper
//!   ([`ProcessMp3`]). Carries the optional ID3 sub-Meta plus borrowed
//!   raw passthrough for the MPEG audio body and the APE trailer; the
//!   APE/MPEG typed Metas land in F3/F4 respectively.
//!
//! Both implement [`crate::parser_new::FormatParser`] and
//! `serialize_tags`. The MP3 engine entry
//! [`ProcessMp3::process`] drives the typed `serialize_tags` path
//! into the engine `tagmap::TagMap` so the serialized
//! JSON stays byte-exact with bundled `perl exiftool`.
//!
//! # Byte-exact reproduction strategy
//!
//! Because ID3.pm threads a deep PrintConv/ValueConv/RawConv/CharSet
//! machinery through every frame (the v2 frame dispatch alone is
//! ~2000 LOC in `v2_process.rs`), the typed-Meta layer takes a
//! **stage-and-replay** posture: the parser runs the existing engine
//! into a staging [`crate::value::Metadata`] and lifts the resulting
//! [`crate::value::Tag`] list into [`Id3Meta`]'s `staged_tags` field.
//! the typed `serialize_tags` path then replays each staged tag
//! into the target writer, preserving the exact group/name/value triples
//! the legacy serializer pinned. The typed accessors
//! ([`Id3Meta::title`] et al.) index the staged-tag list by frame ID,
//! resolved against the ID3.pm tag table.
//!
//! This stage-and-replay is the same shape MOI/AAC/DV used internally
//! (`process_bit_stream → staging Metadata → typed Meta` for AAC), just
//! generalized over the full ID3 frame surface. Phase G is where the
//! engine could be re-shaped to produce typed scalars natively; doing
//! that under the F2 PR would be a multi-thousand-LOC rewrite of the
//! ID3.pm port, which is well beyond the F2 scope and risks the byte-
//! exact contract on the 60+ existing conformance fixtures.

use crate::{
  convert::ConvContext,
  formats::id3::{
    decode::unsync_safe,
    v1::{ID3V1_MAIN, process_id3v1},
    v2_2::ID3V2_2_MAIN,
    v2_3::ID3V2_3_MAIN,
    v2_4::ID3V2_4_MAIN,
    v2_process::process_id3v2,
  },
  parser_new::{FormatParser, SharedFlags, parser_sealed},
  value::{Group, Metadata, TagValue},
};
use smol_str::SmolStr;
use std::vec::Vec;

// ===========================================================================
// Legacy header parser — preserved verbatim for the old chained entry points
// ===========================================================================

/// Result of [`parse_v2_header`]. Carries the parsed header buffer + the
/// declared body size + the flags byte — the size and flags are needed by
/// the caller to compute bundled's `$hdrEnd` (ID3.pm:1504) faithfully,
/// because the footer-flag `flags & 0x10` seek (ID3.pm:1486) advances the
/// file position by 10 bytes BEFORE `$hdrEnd = $raf->Tell()`.
struct ParsedV2Header {
  h_buff: Vec<u8>,
  vers: u16,
  flags: u8,
  size: usize,
}

// ===========================================================================
// Phase F2 typed Meta — `Id3Meta`, `Mp3Meta`, sub-types
// ===========================================================================

/// ID3v2 major version, as carried by the typed [`Id3Meta`]. Faithful to
/// the bundled `unpack('n', ...)` (ID3.pm:1455) which encodes major and
/// minor revision in a 16-bit BE word — we decode the major (high byte)
/// for the typed enum and discard the minor since every ID3v2.x file
/// shares the same per-major frame layout.
///
/// D8 convention: newtype-style enum (no fields). The numeric value lives
/// in the variant identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id3v2Version {
  /// ID3v2.2 — 6-byte frame header (`a3Cn`), 3-character frame IDs.
  V2_2,
  /// ID3v2.3 — 10-byte frame header (`a4Nn`), 4-character frame IDs.
  V2_3,
  /// ID3v2.4 — 10-byte frame header (`a4Nn`), 4-character frame IDs,
  /// sync-safe length encoding.
  V2_4,
}

impl Id3v2Version {
  /// Family-1 group string for the version (e.g. `"ID3v2_3"`).
  #[must_use]
  #[inline(always)]
  pub const fn group1(self) -> &'static str {
    match self {
      Id3v2Version::V2_2 => "ID3v2_2",
      Id3v2Version::V2_3 => "ID3v2_3",
      Id3v2Version::V2_4 => "ID3v2_4",
    }
  }

  /// Dotted major.minor version string (`"2.2"` / `"2.3"` / `"2.4"`).
  /// Single source of truth for [`core::fmt::Display`]; distinct from the
  /// underscore-separated [`Id3v2Version::group1`] used for tag groups.
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      Id3v2Version::V2_2 => "2.2",
      Id3v2Version::V2_3 => "2.3",
      Id3v2Version::V2_4 => "2.4",
    }
  }

  /// `true` for ID3v2.2 (3-character frame IDs).
  #[must_use]
  #[inline(always)]
  pub const fn is_v2_2(self) -> bool {
    matches!(self, Id3v2Version::V2_2)
  }

  /// `true` for ID3v2.3.
  #[must_use]
  #[inline(always)]
  pub const fn is_v2_3(self) -> bool {
    matches!(self, Id3v2Version::V2_3)
  }

  /// `true` for ID3v2.4 (sync-safe frame lengths).
  #[must_use]
  #[inline(always)]
  pub const fn is_v2_4(self) -> bool {
    matches!(self, Id3v2Version::V2_4)
  }

  /// Decode from the bundled `unpack('n', ...)` 16-bit word. The high
  /// byte is the major version. Returns `None` for unsupported versions
  /// (`>= 2.5`) — caller emits the Warn and falls through.
  ///
  /// Currently only called from tests + by future direct-Meta-construction
  /// paths (Phase G).
  #[must_use]
  #[allow(dead_code)]
  #[inline]
  const fn from_packed(vers: u16) -> Option<Self> {
    if vers >= 0x0400 {
      Some(Id3v2Version::V2_4)
    } else if vers >= 0x0300 {
      Some(Id3v2Version::V2_3)
    } else if vers >= 0x0200 {
      Some(Id3v2Version::V2_2)
    } else {
      None
    }
  }
}

impl core::fmt::Display for Id3v2Version {
  #[inline(always)]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// A single staged tag — the post-ValueConv/PrintConv tuple captured during
/// engine extraction. Used internally by [`Id3Meta`]'s stage-and-replay sink
/// path; not part of the public Meta surface (typed accessors expose the
/// extracted data directly).
///
/// Family-0 is not stored: the legacy engine produces every ID3 group with
/// `family0 == "ID3"`, and the writer-side `group` argument uses family-1
/// (the `-G1` key the JSON serializer consumes). The engine
/// `tagmap::TagMap` mirrors the writer-side group to
/// BOTH family-0 and family-1 on push, which matches the legacy emission for
/// ID3 groups whose family-0 was `"ID3"` (the engine attribution paths
/// here go through `tagtable.group0()` + `def.group1()`, not via the
/// writer-side group). Verified across all 60+ ID3/MP3 conformance
/// fixtures.
#[derive(Debug, Clone)]
struct StagedTag {
  family1: SmolStr,
  name: SmolStr,
  value: TagValue,
}

/// A single ID3v2 frame as exposed by [`Id3Meta::frames`]. Represents one
/// post-conversion frame entry — the same `(group1, name, value)` triple
/// the legacy serializer emits, but typed via [`TagValue`] and
/// `Id3v2Version`.
///
/// D8 convention: private fields, accessors only.
#[derive(Debug, Clone)]
pub struct Id3v2Frame {
  /// Family-1 group (`"ID3v2_2"` / `"ID3v2_3"` / `"ID3v2_4"`).
  group1: SmolStr,
  /// Frame tag name (e.g. `"Title"`, `"Artist"`, `"Picture"`).
  name: SmolStr,
  /// Post-conversion value.
  value: TagValue,
}

impl Id3v2Frame {
  /// Family-1 group (`"ID3v2_2"` / `"ID3v2_3"` / `"ID3v2_4"`).
  #[must_use]
  #[inline(always)]
  pub fn group1(&self) -> &str {
    self.group1.as_str()
  }

  /// Frame tag name (e.g. `"Title"`, `"Artist"`, `"Picture"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// Post-conversion value (`TagValue::Str` / `I64` / `Bytes` / etc.).
  /// `_ref`-named per the crate accessor convention for a `&T` borrow of a
  /// non-`Copy` field (mirrors [`crate::value::Tag::value_ref`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &TagValue {
    &self.value
  }
}

/// A typed APIC (ID3v2.3/2.4) or PIC (ID3v2.2) picture frame. The payload
/// bytes are owned (cloned from the parsed frame), the MIME type and
/// description are owned `SmolStr`. The `picture_type` is the raw PIC-2 /
/// APIC-2 byte from the ID3.pm `%pictureType` hash.
///
/// D8 convention: private fields, accessors only.
#[derive(Debug, Clone)]
pub struct Id3Picture {
  /// Picture MIME type (e.g. `"image/jpeg"`, `"image/png"`). For PIC
  /// (ID3v2.2) this is the 3-byte format code (`"JPG"` / `"PNG"`)
  /// expanded via the bundled MIME lookup.
  mime: SmolStr,
  /// Picture type byte (`%pictureType`, ID3.pm:42-64). `0` = Other,
  /// `3` = Front Cover, etc.
  picture_type: u8,
  /// Picture description string (UTF-8 / Latin-1 decoded from the
  /// per-frame `enc` byte).
  description: SmolStr,
  /// Raw image bytes (the post-header binary payload).
  data: Vec<u8>,
}

impl Id3Picture {
  /// MIME type string.
  #[must_use]
  #[inline(always)]
  pub fn mime(&self) -> &str {
    self.mime.as_str()
  }

  /// Picture-type byte (`%pictureType`, ID3.pm:42-64).
  #[must_use]
  #[inline(always)]
  pub const fn picture_type(&self) -> u8 {
    self.picture_type
  }

  /// PrintConv name for the picture type (e.g. `"Front Cover"`). Returns
  /// `None` if the picture-type byte is outside the table; library
  /// callers can fall back to [`Id3Picture::picture_type`] for the raw
  /// byte. Sourced from the `PICTURE_TYPE` slice in
  /// [`crate::formats::id3::picture_type`].
  #[must_use]
  pub fn picture_type_name(&self) -> Option<&'static str> {
    crate::formats::id3::picture_type::PICTURE_TYPE
      .iter()
      .find_map(|(k, v)| {
        if k.parse::<u8>().ok()? == self.picture_type {
          match v {
            crate::tagtable::PrintValue::Str(s) => Some(*s),
            _ => None,
          }
        } else {
          None
        }
      })
  }

  /// Picture description text.
  #[must_use]
  #[inline(always)]
  pub fn description(&self) -> &str {
    self.description.as_str()
  }

  /// Raw image bytes. Projects the owned `Vec<u8>` to the `&[u8]` view
  /// (never exposes `&Vec<u8>`).
  #[must_use]
  #[inline(always)]
  pub fn data(&self) -> &[u8] {
    &self.data
  }
}

/// Typed ID3v1 subframe — the unified ID3v1 record from the 128-byte
/// `TAG` trailer (ID3.pm:335-378). Optional fields land as `None` when
/// the field is all-null in the source.
///
/// D8 convention: private fields, accessors only.
#[derive(Debug, Clone, Default)]
pub struct Id3v1Meta<'a> {
  title: Option<SmolStr>,
  artist: Option<SmolStr>,
  album: Option<SmolStr>,
  year: Option<SmolStr>,
  comment: Option<SmolStr>,
  /// ID3v1.1 track number (only present when byte 125 == 0 AND byte 126
  /// != 0). See `process_id3v1` for the bundled gate.
  track: Option<u8>,
  /// Raw genre byte (`%genre` lookup at PrintConv time).
  genre: Option<u8>,
  /// PrintConv-resolved genre name (when [`Id3v1Meta::genre`] is `Some`
  /// AND the byte is in `%genre`; else `None` and the byte renders as
  /// `Unknown (n)` via the sink).
  genre_name: Option<&'static str>,
  /// Phantom carrying the `'a` lifetime so future lifetimes-from-input
  /// optimizations are non-breaking. Today the typed Meta owns all
  /// strings via `SmolStr`; the `'a` is reserved for Phase G zero-alloc.
  _phantom: core::marker::PhantomData<&'a ()>,
}

impl Id3v1Meta<'_> {
  /// Song title (UTF-8). `None` if absent.
  #[must_use]
  #[inline(always)]
  pub fn title(&self) -> Option<&str> {
    self.title.as_deref()
  }

  /// Artist name. `None` if absent.
  #[must_use]
  #[inline(always)]
  pub fn artist(&self) -> Option<&str> {
    self.artist.as_deref()
  }

  /// Album name. `None` if absent.
  #[must_use]
  #[inline(always)]
  pub fn album(&self) -> Option<&str> {
    self.album.as_deref()
  }

  /// Year (4-character ASCII string). `None` if absent.
  #[must_use]
  #[inline(always)]
  pub fn year(&self) -> Option<&str> {
    self.year.as_deref()
  }

  /// Comment. `None` if absent.
  #[must_use]
  #[inline(always)]
  pub fn comment(&self) -> Option<&str> {
    self.comment.as_deref()
  }

  /// Track number (ID3v1.1 only). `None` for ID3v1.0 layout.
  #[must_use]
  #[inline(always)]
  pub const fn track(&self) -> Option<u8> {
    self.track
  }

  /// Genre byte (`%genre` lookup, ID3.pm:131-332).
  #[must_use]
  #[inline(always)]
  pub const fn genre(&self) -> Option<u8> {
    self.genre
  }

  /// PrintConv-resolved genre name (e.g. `"Hip-Hop"`). `None` if the
  /// genre byte is sparse (192..=254 except 255) or absent.
  #[must_use]
  #[inline(always)]
  pub const fn genre_name(&self) -> Option<&'static str> {
    self.genre_name
  }
}

/// Typed ID3 metadata — the lib-first output of [`ProcessId3`].
///
/// Carries the unified ID3v1 + ID3v2 view: common scalar fields (title,
/// artist, …) are exposed at the top level and resolve from ID3v2 first
/// (the modern format), falling back to ID3v1 when the v2 frame is
/// absent. The ID3v2 frame iterator ([`Id3Meta::frames`]) exposes every
/// raw post-conversion frame for callers that want the full surface; the
/// optional ID3v1 sub-Meta ([`Id3Meta::id3v1`]) carries the v1 trailer.
///
/// **D8 — no public fields, accessors only.**
#[derive(Debug, Clone, Default)]
pub struct Id3Meta<'a> {
  /// ID3v2 major version. `None` when only an ID3v1 trailer was found.
  v2_version: Option<Id3v2Version>,
  /// ID3v1 subframe — present iff a valid 128-byte TAG trailer was
  /// found.
  id3v1: Option<Id3v1Meta<'a>>,
  /// Total ID3 bytes consumed by header+trailer (the `File:ID3Size`
  /// tag). Aggregates ID3v2 header (10 + size [+ 10 if footer]) +
  /// ID3v1 trailer (128) + Enhanced TAG (227, when present).
  id3_size: i64,
  /// Owned passthrough of the full staged-tag list in **PrintConv (`-j`)**
  /// mode. The sink replays these into a `tagmap::TagMap` for `sink(true)`,
  /// preserving the bundled emission order + group/name/value tuples.
  /// Includes File:ID3Size + every `ID3v2_*:*` frame + every `ID3v1:*` v1
  /// field — the same set the legacy serializer pushed into a `Metadata`.
  /// The typed accessors ([`Id3Meta::title`], [`Id3Meta::genre`],
  /// [`Id3Meta::frames`], [`Id3Meta::picture`], …) ALWAYS read this
  /// PrintConv list (the human-readable contract).
  staged_tags: Vec<StagedTag>,
  /// Owned passthrough of the full staged-tag list in **raw (`-n`,
  /// post-ValueConv)** mode — the `sink(false)` source. Built from a
  /// second engine pass with `print_conv = false`, so PrintConv-toggled
  /// fields (ID3v1 Genre %genre ID3.pm:371-375; TLEN ValueConv/PrintConv
  /// split ID3.pm:592-595) carry the raw scalar (e.g. Genre `7`, Length
  /// `7`). Storing BOTH lets ONE `parse` serve BOTH `sink(true)` and
  /// `sink(false)` (Codex B-R2-1) — no mode-lock, no debug-assert.
  staged_tags_raw: Vec<StagedTag>,
  /// All warnings the engine emitted while parsing this ID3 directory.
  warnings: Vec<SmolStr>,
  /// All errors the engine emitted (rare; faithful to ExifTool's
  /// `$self->Error`). Today the ID3 engine only emits warnings.
  errors: Vec<SmolStr>,
  /// Phantom for the `'a` lifetime (Phase G zero-alloc reservation;
  /// today the Meta owns its strings).
  _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> Id3Meta<'a> {
  /// ID3v2 major version. `None` when only an ID3v1 trailer was found.
  #[must_use]
  #[inline(always)]
  pub const fn v2_version(&self) -> Option<Id3v2Version> {
    self.v2_version
  }

  /// Optional ID3v1 subframe.
  #[must_use]
  #[inline(always)]
  pub const fn id3v1(&self) -> Option<&Id3v1Meta<'a>> {
    self.id3v1.as_ref()
  }

  /// `File:ID3Size` value — total bytes consumed by ID3 metadata
  /// (ID3v2 header + ID3v1 trailer + Enhanced TAG when present).
  #[must_use]
  #[inline(always)]
  pub const fn id3_size(&self) -> i64 {
    self.id3_size
  }

  /// Unified Title — ID3v2 `Title` (TT2/TIT2) preferred, then
  /// ID3v1 `Title`. `None` if neither is present.
  #[must_use]
  pub fn title(&self) -> Option<&str> {
    self.find_str("Title")
  }

  /// Unified Artist — ID3v2 `Artist` (TP1/TPE1) preferred, then
  /// ID3v1 `Artist`.
  #[must_use]
  pub fn artist(&self) -> Option<&str> {
    self.find_str("Artist")
  }

  /// Unified Album — ID3v2 `Album` (TAL/TALB) preferred, then
  /// ID3v1 `Album`.
  #[must_use]
  pub fn album(&self) -> Option<&str> {
    self.find_str("Album")
  }

  /// Unified Year — ID3v1 `Year` (string[4]). ID3v2 stores year via
  /// the date/time frame family (TYE/TYER/TDRC); the typed accessor
  /// returns the first matching staged string.
  #[must_use]
  pub fn year(&self) -> Option<&str> {
    self
      .find_str("Year")
      .or_else(|| self.find_str("RecordingTime"))
  }

  /// Unified Track — ID3v2 `Track` (TRK/TRCK) preferred, then
  /// ID3v1 `Track`. Returns the raw string (ID3v2 stores as e.g.
  /// `"3/12"`); ID3v1 stores as a single byte exposed via the
  /// `id3v1.track()` accessor.
  #[must_use]
  pub fn track(&self) -> Option<&str> {
    self.find_str("Track")
  }

  /// Unified Genre — ID3v2 `Genre` (TCO/TCON) preferred, then
  /// ID3v1 `Genre`. ID3v2 emits via PrintConv (`PrintGenre`);
  /// ID3v1 emits the raw genre byte's `%genre` PrintConv string.
  #[must_use]
  pub fn genre(&self) -> Option<&str> {
    self.find_str("Genre")
  }

  /// Unified Comment — ID3v2 `Comment` (COM/COMM) preferred, then
  /// ID3v1 `Comment`. Note ID3v2 COMM has a lang-suffix rename
  /// (e.g. `Comment-fra` for French); the accessor returns the
  /// first match by base name.
  #[must_use]
  pub fn comment(&self) -> Option<&str> {
    self.find_str("Comment")
  }

  /// Iterate every ID3v2 frame in the order the engine emitted them
  /// (faithful to the bundled ID3.pm frame-walk + tag-table dispatch).
  /// Excludes `File:ID3Size` (which is the directory-level marker, not
  /// a frame) and ID3v1 fields (use [`Id3Meta::id3v1`] for those).
  #[must_use]
  pub fn frames(&self) -> impl Iterator<Item = Id3v2Frame> + '_ {
    self.staged_tags.iter().filter_map(|t| {
      let g1 = t.family1.as_str();
      if g1 == "ID3v2_2" || g1 == "ID3v2_3" || g1 == "ID3v2_4" {
        Some(Id3v2Frame {
          group1: t.family1.clone(),
          name: t.name.clone(),
          value: t.value.clone(),
        })
      } else {
        None
      }
    })
  }

  /// First APIC / PIC picture frame, if present. Bundles the
  /// `Picture` bytes + `PictureMIMEType` + `PictureType` +
  /// `PictureDescription` triple emitted by the engine as
  /// adjacent `ID3v2_*:*` tags. Returns `None` if no APIC/PIC frame
  /// was emitted.
  #[must_use]
  pub fn picture(&self) -> Option<Id3Picture> {
    // Scan for the `Picture` tag (TagValue::Bytes), then look at the
    // adjacent `PictureMIMEType` / `PictureType` / `PictureDescription`
    // tags by family-1 + position. The engine emits PIC/APIC in the
    // order: Picture, PictureMIMEType, PictureType, PictureDescription.
    let mut data: Option<Vec<u8>> = None;
    let mut mime: Option<SmolStr> = None;
    let mut ptype: Option<u8> = None;
    let mut desc: Option<SmolStr> = None;
    for t in &self.staged_tags {
      match t.name.as_str() {
        "Picture" => {
          if let TagValue::Bytes(b) = &t.value {
            if data.is_none() {
              data = Some(b.clone());
            }
          }
        }
        "PictureMIMEType" | "PictureFormat" => {
          if let TagValue::Str(s) = &t.value {
            if mime.is_none() {
              mime = Some(s.clone());
            }
          }
        }
        "PictureType" => {
          match &t.value {
            TagValue::I64(n) => {
              if ptype.is_none() {
                ptype = u8::try_from(*n).ok();
              }
            }
            TagValue::Str(s) => {
              // PrintConv-rendered: try to back-resolve the byte from
              // the `%pictureType` table.
              if ptype.is_none() {
                for (k, v) in crate::formats::id3::picture_type::PICTURE_TYPE {
                  if let crate::tagtable::PrintValue::Str(name) = v {
                    if *name == s.as_str() {
                      ptype = k.parse::<u8>().ok();
                      break;
                    }
                  }
                }
              }
            }
            _ => {}
          }
        }
        "PictureDescription" => {
          if let TagValue::Str(s) = &t.value {
            if desc.is_none() {
              desc = Some(s.clone());
            }
          }
        }
        _ => {}
      }
    }
    let data = data?;
    Some(Id3Picture {
      mime: mime.unwrap_or_else(|| SmolStr::new("")),
      picture_type: ptype.unwrap_or(0),
      description: desc.unwrap_or_else(|| SmolStr::new("")),
      data,
    })
  }

  /// Engine-emitted warnings (mirrors [`crate::value::Metadata::warnings_slice`]).
  /// Each entry is the literal Warn text the legacy serializer would surface
  /// under `ExifTool:Warning`. `_slice`-named per the crate convention for a
  /// `Vec<T>` field projected to `&[T]`.
  #[must_use]
  #[inline(always)]
  pub const fn warnings_slice(&self) -> &[SmolStr] {
    self.warnings.as_slice()
  }

  /// Engine-emitted errors (mirrors [`crate::value::Metadata::errors_slice`]).
  #[must_use]
  #[inline(always)]
  pub const fn errors_slice(&self) -> &[SmolStr] {
    self.errors.as_slice()
  }

  /// Find a staged tag's string value by name. Searches in insertion
  /// order — ID3v2 tags come first (emitted by `process_id3v2`), then
  /// ID3v1 (emitted by `process_id3v1`), matching the bundled-Perl
  /// header-then-trailer emission. The accessor returns the first
  /// match, so v2 wins over v1.
  fn find_str(&self, name: &str) -> Option<&str> {
    for t in &self.staged_tags {
      if t.name.as_str() == name {
        if let TagValue::Str(s) = &t.value {
          return Some(s.as_str());
        }
      }
    }
    None
  }
}

/// Typed MP3 wrapper metadata — the lib-first output of [`ProcessMp3`].
///
/// Combines the optional ID3 sub-Meta (when an ID3v1/v2 was detected)
/// with the typed MPEG-audio sub-Meta (frame header + Xing/LAME tail) and
/// the typed APE-trailer sub-Meta, mirroring bundled
/// `Image::ExifTool::ID3::ProcessMP3` (ID3.pm:1684-1728). The
/// `serialize_tags` impl emits ID3 → MPEG → APE in that order so the typed
/// path matches the legacy bridge byte-for-byte (Codex BF1/CF1).
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `Mp3Meta` carries `'a` (input borrow); the MPEG-audio
/// sub-Meta borrows its `encoder` field from the input. The ID3 + APE
/// sub-Metas own their strings (`'a` phantom there).
///
/// **Feature gate (Codex A-R2-1).** `Mp3Meta` and the [`ProcessMp3`]
/// wrapper are gated behind the `mp3` feature because they reference the
/// `mpeg` (`mpeg-audio` feature) and `ape` (`ape` feature) sub-Metas
/// directly. The plain `id3` feature (pulled by `flac`/`aiff`/`dsf`/`ape`
/// for the ID3-prefix chain) compiles without these — only
/// [`process_id3_chained`] / [`process_id3_v2_slice`] / the typed
/// [`ProcessId3`] / [`Id3Meta`] are needed there.
#[cfg(feature = "mp3")]
#[derive(Debug, Clone)]
pub struct Mp3Meta<'a> {
  /// Optional ID3 sub-Meta — present iff ID3v1 or ID3v2 was detected.
  /// `None` for pure MPEG audio with no ID3 prefix or trailer.
  id3: Option<Id3Meta<'a>>,
  /// Optional typed MPEG-audio sub-Meta — present when an MPEG audio frame
  /// sync was found in the scan window (ID3.pm:1696-1719
  /// `ParseMPEGAudio`). Borrows its `encoder` field from the input.
  mpeg: Option<crate::formats::mpeg::AudioMeta<'a>>,
  /// Optional typed APE-trailer sub-Meta — present when the APE-trailer
  /// fallback (ID3.pm:1722-1727 `APE::ProcessAPE`) found an APETAGEX
  /// footer. `'a` is phantom (APE Meta owns its data).
  ape: Option<crate::formats::ape::Meta<'a>>,
  /// `true` iff `ProcessID3` OR `ParseMPEGAudio` accepted (Perl `$rtnVal`
  /// at the end of `ProcessMP3`).
  found: bool,
}

#[cfg(feature = "mp3")]
impl<'a> Mp3Meta<'a> {
  /// Optional ID3 sub-Meta.
  #[must_use]
  #[inline(always)]
  pub const fn id3(&self) -> Option<&Id3Meta<'a>> {
    self.id3.as_ref()
  }

  /// Optional typed MPEG-audio sub-Meta (frame header + Xing/LAME tail).
  #[must_use]
  #[inline(always)]
  pub const fn mpeg(&self) -> Option<&crate::formats::mpeg::AudioMeta<'a>> {
    self.mpeg.as_ref()
  }

  /// Optional typed APE-trailer sub-Meta.
  #[must_use]
  #[inline(always)]
  pub const fn ape(&self) -> Option<&crate::formats::ape::Meta<'a>> {
    self.ape.as_ref()
  }

  /// `true` iff ProcessID3 + ParseMPEGAudio accepted the file as MP3
  /// (Perl `$rtnVal` at the end of ProcessMP3).
  #[must_use]
  #[inline(always)]
  pub const fn found(&self) -> bool {
    self.found
  }
}

// ===========================================================================
// `ProcessId3` and `ProcessMp3` — the lib-first parser entry points
// ===========================================================================

/// The ID3 directory parser. Faithful to `Image::ExifTool::ID3::ProcessID3`
/// (ID3.pm:1431-1632). This is the *new* parser type introduced in Phase
/// F2 for the typed-Meta API; the legacy chained entry points
/// ([`process_id3_chained`], [`process_id3_v2_slice`]) remain available for
/// the chained engine entries of APE, DSF, FLAC, AIFF, MPC, WavPack.
///
/// Note: ID3 is a *directory* parser (PROCESS_PROC in ID3.pm:78), not a
/// file-type entry, so it has no engine entry in
/// [`crate::parser_new::any_parser_for`]; only [`ProcessMp3`] is a file-type
/// entry. The standalone ID3 typed parser is exposed via [`FormatParser`]
/// for chained callers that want to materialize an [`Id3Meta`] over an
/// arbitrary byte slice.
#[derive(Debug, Clone, Copy)]
pub struct ProcessId3;

impl parser_sealed::Sealed for ProcessId3 {}

/// Context for the ID3 directory parser. Bundles the input slice with
/// the shared cross-format flags ([`SharedFlags`]) so the bundled
/// `$$et{DoneID3}` / `$$et{DoneAPE}` semantics (set by ID3, read by
/// APE; ID3.pm:1527 / APE.pm:169) propagate correctly through chained
/// dispatch.
pub struct Id3Context<'a> {
  data: &'a [u8],
  shared: &'a mut SharedFlags,
}

impl<'a> Id3Context<'a> {
  /// Construct a parser context over `data` with shared cross-format
  /// flags `shared`. The data slice is the full file bytes (ID3 head
  /// + body + trailer); the parser sniffs the ID3v2 magic at offset 0
  /// and the ID3v1 magic at offset `len - 128`.
  #[must_use]
  #[inline(always)]
  pub const fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self { data, shared }
  }

  /// Input bytes.
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }

  /// Shared cross-format flags (read/write).
  #[inline(always)]
  pub const fn shared(&mut self) -> &mut SharedFlags {
    self.shared
  }
}

impl FormatParser for ProcessId3 {
  /// GAT: the Meta is parameterized by `'a` (Id3Meta owns its strings via
  /// `SmolStr`, so `'a` is phantom; Codex AF2).
  type Meta<'a> = Id3Meta<'a>;
  type Context<'a> = Id3Context<'a>;
  type Error = Id3Error;

  /// Parse the ID3 directory at the start of `ctx.data()`. Returns
  /// `Ok(Some(meta))` when an ID3v1 OR ID3v2 was detected, `Ok(None)`
  /// otherwise. The cross-format `DoneID3` flag is set on the
  /// [`SharedFlags`] (faithful to ID3.pm:1527).
  ///
  /// Stages in `-j` PrintConv mode (the closed-dispatch convention; the
  /// Meta is mode-locked, Codex BF2 — sink with `sink(true, ...)`). For
  /// `-n` access use [`parse_id3_borrowed`] with `print_conv = false`.
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Self::Error> {
    parse_id3_inner(ctx.data, Some(ctx.shared), /* print_conv */ true).map(|(meta, _hdr_end)| meta)
  }
}

/// The MP3 file-type parser. Faithful to bundled Perl's
/// `Image::ExifTool::ID3::ProcessMP3` (ID3.pm:1684-1728); the chain to
/// MPEG / APE for the audio-frame / APE-trailer tags is documented
/// forward items (rows 17 / 5).
///
/// **Feature gate (Codex A-R2-1):** `mp3` — depends on `mpeg-audio` + `ape`.
#[cfg(feature = "mp3")]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMp3;

#[cfg(feature = "mp3")]
impl parser_sealed::Sealed for ProcessMp3 {}

/// Context for the MP3 wrapper. Bundles the input slice with shared
/// cross-format flags + the local file extension (needed for the
/// ID3.pm:1715-1717 `$mp3 = ($ext eq 'MUS') ? 0 : 1` Layer-II gate).
#[cfg(feature = "mp3")]
pub struct Mp3Context<'a> {
  data: &'a [u8],
  shared: &'a mut SharedFlags,
  /// Optional file extension (uppercase, no leading dot — e.g. `"MP3"`,
  /// `"MUS"`). Faithful to ExifTool's `$$self{FILE_EXT}` (ExifTool.pm:
  /// 5613-5615). `None` for dotless filenames (rare but exercised by
  /// the `process_mp3_layer_two_dotless_filename_rejected` test).
  ext: Option<&'a str>,
}

#[cfg(feature = "mp3")]
impl<'a> Mp3Context<'a> {
  /// Construct an MP3 parser context.
  #[must_use]
  #[inline(always)]
  pub const fn new(data: &'a [u8], shared: &'a mut SharedFlags, ext: Option<&'a str>) -> Self {
    Self { data, shared, ext }
  }

  /// Input bytes.
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }

  /// File extension (uppercase, no leading dot).
  #[must_use]
  #[inline(always)]
  pub const fn ext(&self) -> Option<&'a str> {
    self.ext
  }

  /// Shared cross-format flags.
  #[inline(always)]
  pub const fn shared(&mut self) -> &mut SharedFlags {
    self.shared
  }
}

#[cfg(feature = "mp3")]
impl FormatParser for ProcessMp3 {
  /// GAT: the Meta borrows from the input `'a` (the chained MPEG-audio
  /// sub-Meta borrows its `encoder` field; Codex AF2).
  type Meta<'a> = Mp3Meta<'a>;
  type Context<'a> = Mp3Context<'a>;
  type Error = Mp3Error;

  /// Parse a candidate MP3 file. Returns `Ok(Some(meta))` if ID3 OR
  /// MPEG audio sync was detected, `Ok(None)` otherwise. Faithful to
  /// bundled `Image::ExifTool::ID3::ProcessMP3` (ID3.pm:1684-1728): runs
  /// ID3 detection, then (when ID3 did not already accept) scans MPEG
  /// audio from `hdr_end` within the `$scanLen` window, then runs the
  /// APE-trailer fallback when a valid A/V file was found and APE has not
  /// already run. The typed sub-Metas are populated so the `serialize_tags`
  /// emits ID3 + MPEG + APE tags without the legacy bridge (Codex
  /// BF1/CF1).
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Self::Error> {
    parse_mp3_typed(ctx.data, ctx.ext, ctx.shared).map_err(Mp3Error::Id3)
  }
}

/// Faithful typed port of bundled `Image::ExifTool::ID3::ProcessMP3`
/// (ID3.pm:1684-1728), producing a fully-populated [`Mp3Meta`] (ID3 +
/// MPEG-audio + APE-trailer sub-Metas). Codex BF1/CF1: the prior typed
/// entry staged only ID3 and returned `Ok(None)` for raw-MPEG MP3.
///
/// Flow (ID3.pm:1691-1727):
/// 1. `unless ($$et{DoneID3}) { ProcessID3 }` — parse the leading/trailing
///    ID3 (ID3.pm:1691-1693). Yields the typed `Id3Meta` and `hdr_end`
///    (bundled `$hdrEnd`, the post-ID3v2-header file position).
/// 2. Scan MPEG audio from `hdr_end` within the `$scanLen` window
///    (ID3.pm:1696-1719). Faithful to the bridge's
///    `process_with_start_offset`: `$scanLen = ext eq 'MP3' ? 8192 : 256`
///    and `$mp3 = ext eq 'MUS' ? 0 : 1`. The MPEG scan runs regardless of
///    ID3 acceptance — bundled emits MPEG tags for ID3v2+audio files via
///    the ProcessID3 → audio-format-loop → recursive-ProcessMP3 dance
///    (the recursive call hits the `unless ($rtnVal)` branch because
///    `DoneID3` is set). Modeling it as an unconditional post-ID3 scan
///    produces the same tag set.
/// 3. `if ($rtnVal and not $$et{DoneAPE})` — run the APE-trailer fallback
///    (ID3.pm:1722-1727 `APE::ProcessAPE`). In an MP3 there is no leading
///    APE magic, so this is the trailer-only footer scan (APE.pm:165+),
///    threaded with `done_id3` for the APE.pm:169 footer shift.
///
/// `print_conv` is fixed to `true` (`-j`) for the typed entry: the ID3
/// sub-Meta is mode-locked (Codex BF2), and MPEG/APE sub-Metas apply
/// PrintConv at sink time. Sink the result with `sink(true, ...)`.
// `ext` borrows on an INDEPENDENT lifetime — `Mp3Meta` (and its MPEG
// sub-Meta) never store it; only `data` flows into the returned Meta's `'a`
// (Codex C-R2-2).
#[cfg(feature = "mp3")]
fn parse_mp3_typed<'a>(
  data: &'a [u8],
  ext: Option<&str>,
  shared: &mut SharedFlags,
) -> Result<Option<Mp3Meta<'a>>, Id3Error> {
  // -- 1. ID3 (ID3.pm:1691-1693) ------------------------------------------
  // `unless ($$et{DoneID3}) { $rtnVal = ProcessID3(...) }` (ID3.pm:1691-1693).
  // When a prior parser in the chain (e.g. APE/DSF/FLAC) already ran
  // `ProcessID3` and set `DoneID3`, the bundled `ProcessMP3` SKIPS the ID3
  // pass and lets MPEG scanning (from offset 0) decide acceptance. Modeling
  // it unconditionally would re-emit the ID3 sub-Meta a second time (Codex
  // B-R2-2).
  let (id3, hdr_end) = if shared.done_id3().is_none() {
    // Stage in `-j` mode (the typed MP3 entry's fixed mode). `parse_id3_inner`
    // sets BOTH the `DoneID3` "ran" marker (`Some(trailer)` on a hit, else
    // `Some(0)` — ID3.pm:1435-1436) AND the post-ID3v2-header offset (bundled
    // `$hdrEnd`) on `shared` so a subsequent chained parser / recursive MP3
    // dispatch observes them (Codex B-R3-1/B-R3-2). No manual marker patch
    // is needed here.
    parse_id3_inner(data, Some(&mut *shared), /* print_conv */ true)?
  } else {
    // DoneID3 already set ⇒ bundled `ProcessID3` returns 0 and the `unless`
    // skips it (ID3.pm:1691-1693). No ID3 sub-Meta. The bundled flow only
    // reaches this re-entry through the audio-format loop, which has already
    // `Seek($hdrEnd, 0)` (ID3.pm:1590); scan MPEG from the carried `$hdrEnd`,
    // NOT offset 0, so a large-ID3 file (MPEG frame after an ID3v2 body
    // > 8192 bytes) still yields MPEG tags (Codex B-R3-1). When the prior
    // pass never recorded a header end (e.g. `DoneID3` injected by a
    // non-ID3-running caller), default to 0 — the legacy offset-0 behavior.
    let hdr_end = shared.id3_hdr_end().unwrap_or(0);
    (None, hdr_end)
  };

  // -- 2. MPEG audio scan from hdr_end (ID3.pm:1696-1719) ------------------
  // Faithful scan-window + Layer-III/MUS gate, mirroring the bridge's
  // `process_with_start_offset`.
  let ext_is_mp3 = ext.is_some_and(|e| e.eq_ignore_ascii_case("MP3"));
  let scan_len = crate::formats::mpeg::id3_process_mp3_scan_len(ext_is_mp3);
  let mp3_flag = !ext.is_some_and(|e| e.eq_ignore_ascii_case("MUS"));
  let ext_str = ext.unwrap_or("");
  let post_id3 = data.get(hdr_end..).unwrap_or(&[]);
  let bounded = &post_id3[..scan_len.min(post_id3.len())];
  // `mpeg::AudioError` is uninhabited; the `Ok(None)` path covers "no sync".
  let mpeg = crate::formats::mpeg::parse_borrowed(bounded, mp3_flag, ext_str)
    .ok()
    .flatten();

  // -- rtnVal (ID3.pm:1722 `if ($rtnVal ...)`) ----------------------------
  let rtn_val = id3.is_some() || mpeg.is_some();
  if !rtn_val {
    // Perl returns 0 ⇒ no File:* promotion; the engine emits the
    // file-format error. The typed entry returns `Ok(None)`.
    return Ok(None);
  }

  // -- 3. APE trailer fallback (ID3.pm:1722-1727) -------------------------
  // `if ($rtnVal and not $$et{DoneAPE})`. An MP3 has no leading APE magic,
  // so this is the trailer-only footer scan (faithful to bundled
  // `ProcessAPE` falling through to the APETAGEX footer at APE.pm:165+).
  // `parse_trailer_only_owned` decouples the `shared` borrow from the
  // returned (owned, `'static`) Meta so the transient `shared` does not
  // pin the `Mp3Meta<'a>` lifetime; the owned Meta coerces to `'a`.
  let ape: Option<crate::formats::ape::Meta<'a>> = if shared.done_ape() {
    None
  } else {
    crate::formats::ape::parse_trailer_only_owned(data, shared)
  };

  Ok(Some(Mp3Meta {
    id3,
    mpeg,
    ape,
    found: rtn_val,
  }))
}

/// Lib-first direct entry for the MP3 wrapper with **decoupled `shared`
/// and `ext` lifetimes** — only `data` borrows for `'a` (and so does the
/// returned [`Mp3Meta`]), while `shared` and `ext` are transient borrows on
/// independent lifetimes that do NOT pin the returned Meta (Codex C-R2-2).
/// This is the entry the public [`parse_mp3`](crate::parse_mp3) uses with a
/// freshly-constructed [`SharedFlags`].
///
/// The ID3 sub-Meta is staged in `-j` PrintConv mode (sink with
/// `sink(true, ...)`); MPEG / APE sub-Metas apply PrintConv at sink time.
///
/// # Errors
///
/// Returns the per-format [`Mp3Error`].
#[cfg(feature = "mp3")]
pub fn parse_mp3_borrowed<'a>(
  data: &'a [u8],
  ext: Option<&str>,
  shared: &mut SharedFlags,
) -> Result<Option<Mp3Meta<'a>>, Mp3Error> {
  parse_mp3_typed(data, ext, shared).map_err(Mp3Error::Id3)
}

/// Rust-level fatal modes for ID3 parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`) or a non-fatal Warn that
/// lands as an [`Id3Meta::warnings_slice`] entry. Reserved for future I/O
/// wrappers.
///
/// §5: `Display` + `core::error::Error` are derived via `thiserror` (v2,
/// `default-features = false`) so the trait is present in every feature tier.
/// `#[non_exhaustive]` lets variants land later without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Id3Error {}

/// Rust-level fatal modes for MP3 parsing. Wraps [`Id3Error`] for the
/// nested ID3 dispatch.
///
/// §5: derived via `thiserror`; `#[from]` on the wrapped [`Id3Error`] gives a
/// free `From<Id3Error>` + `source()`. `#[non_exhaustive]` for additive growth.
#[cfg(feature = "mp3")]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Mp3Error {
  /// An ID3 parsing error bubbled up from the nested directory parser.
  #[error("MP3: ID3 parsing failed: {0}")]
  Id3(#[from] Id3Error),
}

// ===========================================================================
// Inner parser — builds typed Meta from a staged Metadata
// ===========================================================================

/// Run the push-style legacy engine (`process_id3_inner_legacy`) once into
/// a scratch [`Metadata`] at the given `print_conv` mode and lift its tag
/// list into a `Vec<StagedTag>`, preserving the bundled emission order.
/// Returns `(found, hdr_end, staged_tags, metadata)` — the `metadata` is
/// returned so the caller can read its `done_id3` / `warnings` / `errors`
/// (which are mode-independent).
fn run_id3_pass(data: &[u8], print_conv: bool) -> (bool, usize, Vec<StagedTag>, Metadata) {
  // INTERNAL STAGING (not output): the typed ID3 `parse` runs the push-style
  // legacy engine into a SCRATCH [`Metadata`] push-bag, then lifts its buffered
  // tags into `Id3Meta::staged_tags`. The scratch `Metadata` is purely the
  // internal collector the legacy `finalize` / `process_id3v2` / `process_id3v1`
  // push into; the caller reads its `tags`, `done_id3`, `warnings`, and `errors`
  // back. Nothing here touches the output JSON path.
  let mut staging = Metadata::new("staging.id3");
  let (found, hdr_end) = process_id3_inner_legacy(data, &mut staging, print_conv);
  let staged_tags: Vec<StagedTag> = staging
    .tags_slice()
    .iter()
    .map(|t| StagedTag {
      family1: SmolStr::new(t.group_ref().family1()),
      name: SmolStr::new(t.name()),
      value: t.value_ref().clone(),
    })
    .collect();
  (found, hdr_end, staged_tags, staging)
}

/// Stage-and-replay parser body. Runs the existing push-style engine
/// (`process_id3_inner_legacy`) into a temporary [`Metadata`], then lifts
/// the resulting `Tag` list into [`Id3Meta::staged_tags`] preserving the
/// bundled emission order. Updates `shared.done_id3` to the trailer size
/// (the `$$et{DoneID3}` flag that APE.pm:169 reads).
///
/// **Both modes (Codex B-R2-1).** The engine is run TWICE — once with
/// `print_conv = true` (the human-readable `-j` list, stored in
/// `staged_tags` and read by every typed accessor) and once with
/// `print_conv = false` (the raw `-n` list, stored in `staged_tags_raw`).
/// One `parse` therefore serves BOTH `sink(true)` and `sink(false)` with no
/// mode-lock. The `print_conv` argument is retained for source/signature
/// compatibility but no longer gates which list is built (both always are);
/// it selects nothing — the sink picks by its own argument.
fn parse_id3_inner<'a>(
  data: &'a [u8],
  shared: Option<&mut SharedFlags>,
  print_conv: bool,
) -> Result<(Option<Id3Meta<'a>>, usize), Id3Error> {
  let _ = print_conv; // no longer mode-locks (Codex B-R2-1); see fn docs.

  // ID3.pm:1435 `return 0 if $$et{DoneID3}` — the `ProcessID3` recursion
  // guard. A chained typed caller (APE/FLAC/DSF/MP3 → ID3) that has already
  // run ID3 must NOT re-enter and duplicate the work (Codex B-R3-2). Honored
  // here at the typed-ID3 chokepoint so EVERY typed entry
  // (`parse_id3_borrowed`, `ProcessId3::parse`, `parse_mp3_typed`) inherits
  // it. Returns the no-op shape (`hdr_end = 0`); the bundled skip path does
  // not produce a directory. `shared == None` (bridge-style scratch calls)
  // has no cross-format state to guard on — the legacy scratch `Metadata`
  // owns its own `DoneID3` for internal recursion.
  if shared.as_ref().is_some_and(|sf| sf.done_id3().is_some()) {
    return Ok((None, 0));
  }

  // PrintConv (`-j`) pass — the accessor + `sink(true)` source.
  let (found, hdr_end, staged_tags, staging) = run_id3_pass(data, true);

  // ID3.pm:1436 `$$et{DoneID3} = 1` — set the "ran" marker BEFORE scanning,
  // truthy even when NO ID3 is found. Combined with the post-ID3v2-header
  // offset (bundled `$hdrEnd`), recorded on the shared state for EVERY typed
  // ID3 run — found or not. A later chained `ProcessMP3` re-entering with
  // `DoneID3` set scans MPEG from this offset (the audio-format loop's
  // `$raf->Seek($hdrEnd, 0)`, ID3.pm:1590), not from 0, so a large-ID3 file
  // still yields MPEG tags (Codex B-R3-1). Done before the no-ID3 early
  // return so both side effects persist regardless of the return shape (the
  // FormatParser contract; Codex B-R3-2).
  if let Some(sf) = shared {
    sf.set_id3_hdr_end(hdr_end);
    // `done_id3` ends up the trailer size on a hit (APE.pm:169 reads it),
    // else the `Some(0)` "ran, no v1 trailer" marker (ID3.pm:1436's truthy
    // `1`; the APE `> 1` shift treats `0`/`1` identically). The legacy
    // `process_id3_inner_legacy` stores the trailer size on `staging`; mirror
    // it, falling back to `0` so a no-ID3 run still marks DoneID3 (B-R3-2).
    sf.set_done_id3(staging.done_id3().unwrap_or(0));
  }

  if !found {
    return Ok((None, hdr_end));
  }
  // Raw (`-n`) pass — the `sink(false)` source. Same input, same engine,
  // PrintConv disabled (ID3v1 Genre %genre ID3.pm:371-375; TLEN
  // ValueConv/PrintConv split ID3.pm:592-595 differ between the two).
  let (_found_raw, _hdr_end_raw, staged_tags_raw, _staging_raw) = run_id3_pass(data, false);
  // Determine the ID3v2 version + size + ID3v1 sub-Meta from the PrintConv
  // staged tags (the accessor list).
  let mut v2_version: Option<Id3v2Version> = None;
  let mut id3_size: i64 = 0;
  let mut id3v1: Option<Id3v1Meta<'_>> = None;
  for tag in &staged_tags {
    let g1 = tag.family1.as_str();
    let name = tag.name.as_str();
    if g1 == "ID3v2_2" {
      v2_version = Some(Id3v2Version::V2_2);
    } else if g1 == "ID3v2_3" {
      v2_version.get_or_insert(Id3v2Version::V2_3);
    } else if g1 == "ID3v2_4" {
      v2_version.get_or_insert(Id3v2Version::V2_4);
    }
    if name == "ID3Size" {
      if let TagValue::I64(n) = &tag.value {
        id3_size = *n;
      }
    }
    if g1 == "ID3v1" {
      let v1 = id3v1.get_or_insert_with(Id3v1Meta::default);
      stuff_id3v1_field(v1, name, &tag.value);
    }
  }
  let warnings: Vec<SmolStr> = staging.warnings_slice().iter().map(SmolStr::new).collect();
  let errors: Vec<SmolStr> = staging.errors_slice().iter().map(SmolStr::new).collect();
  Ok((
    Some(Id3Meta {
      v2_version,
      id3v1,
      id3_size,
      staged_tags,
      staged_tags_raw,
      warnings,
      errors,
      _phantom: core::marker::PhantomData,
    }),
    hdr_end,
  ))
}

/// Lift a single ID3v1-group tag into the typed [`Id3v1Meta`] subframe.
fn stuff_id3v1_field(v1: &mut Id3v1Meta<'_>, name: &str, value: &TagValue) {
  match (name, value) {
    ("Title", TagValue::Str(s)) => v1.title = nonempty(s),
    ("Artist", TagValue::Str(s)) => v1.artist = nonempty(s),
    ("Album", TagValue::Str(s)) => v1.album = nonempty(s),
    ("Year", TagValue::Str(s)) => v1.year = nonempty(s),
    ("Comment", TagValue::Str(s)) => v1.comment = nonempty(s),
    ("Track", TagValue::I64(n)) => v1.track = u8::try_from(*n).ok(),
    ("Genre", TagValue::I64(n)) => {
      v1.genre = u8::try_from(*n).ok();
    }
    ("Genre", TagValue::Str(s)) => {
      // PrintConv-rendered (e.g. "Hip-Hop"); back-resolve the byte for
      // the genre() accessor.
      v1.genre_name = id3v1_genre_byte_for_name(s.as_str()).map(|(_, name)| name);
      v1.genre = id3v1_genre_byte_for_name(s.as_str()).map(|(b, _)| b);
    }
    _ => {}
  }
}

/// `None` for an empty SmolStr; `Some(s)` otherwise. Avoids surfacing
/// empty `""` strings as `Some("")` (which would be observable as a
/// present-but-empty field — confusing to library callers).
fn nonempty(s: &SmolStr) -> Option<SmolStr> {
  if s.is_empty() { None } else { Some(s.clone()) }
}

/// Back-resolve a PrintConv genre name (e.g. `"Hip-Hop"`) to its raw
/// byte + `&'static str` name. Used to surface a useful
/// [`Id3v1Meta::genre_name`] when the staged value is already PrintConv'd.
fn id3v1_genre_byte_for_name(name: &str) -> Option<(u8, &'static str)> {
  // Iterate the genre table from `v1.rs` indirectly via the
  // `genre_name` helper in `genre.rs`. We can't easily import the
  // private GENRE_ENTRIES slice from v1; cross-reference via the
  // genre module's `genre_name` (numbered lookup).
  for byte in 0u8..=255 {
    if let Some(s) = crate::formats::id3::genre::genre_name(i64::from(byte)) {
      if s == name {
        // Found a hit; SAFETY: genre_name returns a &'static str.
        return Some((byte, s));
      }
    }
  }
  None
}

// ===========================================================================
// `serialize_tags` — replay staged tags into a TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl Id3Meta<'_> {
  /// Emit every staged ID3 tag in the order the legacy engine produced
  /// them. Faithful to ID3.pm: File:ID3Size first, then ID3v2 frames in
  /// tag-table order, then ID3v1 fields in `%v1` order.
  ///
  /// **`print_conv` contract (Codex B-R2-1).** ONE `parse` stages BOTH the
  /// PrintConv (`-j`) list and the raw (`-n`) list; `sink` honors its
  /// `print_conv` argument by replaying the matching list. So a single typed
  /// `parse(...)` serves BOTH `sink(true)` (PrintConv strings — Genre
  /// `Hip-Hop`, Length `7 s`) AND `sink(false)` (raw scalars — Genre `7`,
  /// Length `7`) with no mode-lock and no debug-assert. PrintConv-toggled
  /// fields (ID3v1 Genre %genre ID3.pm:371-375; TLEN ValueConv/PrintConv
  /// split ID3.pm:592-595) are the cases this distinguishes.
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    let tags = if print_conv {
      &self.staged_tags
    } else {
      &self.staged_tags_raw
    };
    for tag in tags {
      // Use the family-1 string as the writer's `group` argument; the
      // engine `TagMap` mirrors family-1 to BOTH
      // family-0 and family-1 on push, which matches the legacy
      // engine's emission for ID3 (every ID3 group has family-0 ==
      // family-1, e.g. `("ID3", "ID3v2_3")` is engineered via
      // `tagtable.group0()` + `def.group1()`, not via the writer-side
      // group). However, the writer-side `group` must encode family-1
      // (the `-G1 -j` key) because that's what the JSON serializer
      // keys on; the bridge handles family-0 by virtue of the legacy
      // engine's own family-0 attribution at push time, which we
      // preserved via the staged-tag list (`StagedTag::family0` is
      // not used by the writer path but is retained for debugging).
      let group = tag.family1.as_str();
      let name = tag.name.as_str();
      match &tag.value {
        TagValue::Str(s) => out.write_str(group, name, s.as_str())?,
        TagValue::I64(n) => out.write_i64(group, name, *n)?,
        TagValue::U64(n) => out.write_u64(group, name, *n)?,
        TagValue::F64(n) => out.write_f64(group, name, *n)?,
        TagValue::Bool(b) => out.write_u64(group, name, u64::from(*b))?,
        TagValue::Bytes(b) => out.write_bytes(group, name, b)?,
        TagValue::Rational(_) | TagValue::List(_) => {
          // ID3 today never produces Rational or List values; if a
          // future frame type does, extend this match with the
          // appropriate writer emission (e.g. a rational-to-decimal
          // write_fmt or a per-item write_str loop).
          //
          // For now, render via Display to surface the value rather
          // than silently dropping. Use write_fmt to avoid
          // intermediate String allocations.
          out.write_fmt(group, name, |w| write!(w, "{:?}", tag.value))?;
        }
      }
    }
    for warn in &self.warnings {
      out.write_warning(warn.as_str())?;
    }
    for err in &self.errors {
      out.write_error(err.as_str())?;
    }
    Ok(())
  }
}

#[cfg(feature = "mp3")]
#[cfg(feature = "alloc")]
impl Mp3Meta<'_> {
  /// Emit MP3 tags in bundled `ProcessMP3` order (ID3.pm:1684-1728):
  /// 1. ID3 sub-Meta (header frames + v1 trailer fields), when present;
  /// 2. MPEG-audio sub-Meta (frame header + Xing/LAME tail), when an
  ///    audio frame sync was found;
  /// 3. APE-trailer sub-Meta, when an APETAGEX footer was found.
  ///
  /// This typed sink emits the SAME tag set the engine entry `process`
  /// does, so library callers consuming `Mp3Meta` via `serialize_tags` get the
  /// complete picture (Codex BF1/CF1).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    if let Some(id3) = &self.id3 {
      id3.serialize_tags(print_conv, out)?;
    }
    if let Some(mpeg) = &self.mpeg {
      mpeg.serialize_tags(print_conv, out)?;
    }
    if let Some(ape) = &self.ape {
      ape.serialize_tags(print_conv, out)?;
    }
    Ok(())
  }
}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Shared push-style ID3 staging engine — the internal collector the typed
// `run_id3_pass` (and thus every `id3`-feature chained caller) lifts into
// `Id3Meta`. Ungated at the `id3` level (the whole module is `id3`-gated); no
// longer `mp3`-only now that the typed ID3 staging path uses it.
// ===========================================================================

/// Internal ProcessID3 entry. `do_set_file_type` is `true` for the MP3
/// dispatch path (ID3.pm:1604 `SetFileType('MP3')` runs after the audio
/// loop) and `false` for chained-from-{APE,DSF} where the outer parser
/// owns SetFileType (APE: ProcessAPE recursively invoked from the
/// ID3.pm:1582-1601 audio loop calls SetFileType to "APE" first; DSF:
/// ProcessDSF calls SetFileType to "DSF" before invoking the ID3 trailer
/// arm at DSF.pm:88-97). `data` is the slice to scan (`ctx.data()` for
/// the file-level path; a pre-sliced ID3v2 trailer for DSF).
///
/// Returns `(found, hdr_end)`. `found` is the bundled `$rtnVal`
/// (ID3.pm:1442 init, set to `1` at :1453 on `^ID3`, or at :1520 on
/// `^TAG` trailer). `hdr_end` is the bundled `$hdrEnd` (ID3.pm:1443 init
/// to 0, set at :1504 only AFTER a successful v2 header parse). When the
/// header parse hits any Warn-then-`last` path (:1454, :1457, :1459,
/// :1463, :1475, :1478), bundled leaves `$hdrEnd = 0` — the audio
/// loop's `$raf->Seek($hdrEnd, 0)` at :1590 then re-reads from offset 0.
/// We model the same: `0` ⇒ caller slices from offset 0.
///
/// **Naming note.** This push-style helper is `process_id3_inner_legacy`
/// to distinguish it from the typed-Meta inner parser [`parse_id3_inner`].
/// It is the shared engine for the chained callers (APE/DSF/FLAC/AIFF/MPC/WV)
/// and the MP3 engine entry's ID3 pass; the typed entries lift its staged
/// output into [`Id3Meta`].
fn process_id3_inner_legacy(
  data: &[u8],
  meta: &mut Metadata,
  print_conv_on: bool,
) -> (bool, usize) {
  // ID3.pm:1435-1436 `return 0 if $$et{DoneID3}; $$et{DoneID3} = 1;` —
  // avoids the cross-parser infinite recursion bundled relies on for the
  // ID3 → audio-format dispatch loop. (The scratch `Metadata` carries the
  // `DoneID3` flag for the internal staging pass.)
  if meta.done_id3().is_some() {
    return (false, 0);
  }
  meta.set_done_id3(0);

  let cctx = ConvContext::default();

  let mut id3_len: u64 = 0;
  let mut found_any = false;
  let mut header_data: Option<(Vec<u8>, u16)> = None;
  let mut hdr_end: usize = 0;

  if data.len() < 3 {
    return (false, 0);
  }

  if data.starts_with(b"ID3") {
    found_any = true; // ID3.pm:1453 `$rtnVal = 1`.
    if let Some(parsed) = parse_v2_header(data, meta) {
      id3_len += (parsed.h_buff.len() + 10) as u64;
      hdr_end = 10usize.saturating_add(parsed.size);
      if parsed.flags & 0x10 != 0 {
        hdr_end = hdr_end.saturating_add(10);
      }
      header_data = Some((parsed.h_buff, parsed.vers));
    }
  }

  let mut trailer_data: Option<Vec<u8>> = None;
  let mut enh_data: Option<Vec<u8>> = None;
  let mut trail_size_for_done_id3: usize = 0;
  if data.len() >= 128 {
    let tail = &data[data.len() - 128..];
    if tail.starts_with(b"TAG") {
      trailer_data = Some(tail.to_vec());
      id3_len += 128;
      found_any = true;
      trail_size_for_done_id3 = 128;
      // ID3.pm:1521-1525 — Enhanced TAG (TAG+, 227 bytes) preceding
      // the standard 128-byte TAG block. Detect via the regex
      // `^TAG+/` (literal `TA` + 1+ `G`s — `starts_with(b"TAG")`
      // covers). F4 (Codex adversarial): the pre-fix code sized the
      // block (DoneID3 += 227) but never CAPTURED the buffer. Now we
      // copy the 227 bytes so `finalize` → `process_id3v1_enh` can
      // emit the 7 `ID3v1_Enh:*` fields bundled does (ID3.pm:1618-1626).
      // Note: `id3_len` (the `File:ID3Size` value) does NOT include the
      // 227 bytes — Perl :1519 adds 128 to `$id3Len` but :1525 only adds
      // 227 to `$trailSize`. The committed golden's `File:ID3Size = 128`
      // pins this.
      if data.len() >= 128 + 227 {
        let e_start = data.len() - 128 - 227;
        let e_buf = &data[e_start..data.len() - 128];
        if e_buf.starts_with(b"TAG") {
          trail_size_for_done_id3 += 227;
          enh_data = Some(e_buf.to_vec());
        }
      }
    }
  }

  if trail_size_for_done_id3 > 0 {
    meta.set_done_id3(trail_size_for_done_id3);
  }
  let found = finalize(
    meta,
    print_conv_on,
    &cctx,
    id3_len,
    found_any,
    header_data,
    trailer_data,
    enh_data,
  );
  (found, hdr_end)
}

/// Parse the ID3v2 header (ID3.pm:1452-1505). Returns
/// `Some(ParsedV2Header)` when the header is fully valid; `None` when
/// any Warn-then-`last` path fires (the caller still proceeds to ID3v1
/// trailer detection — bundled behavior). Pushes Warns to
/// `ctx.metadata()` along the way. Faithful transliteration of the
/// bundled `while ($buff =~ /^ID3/) { ... last }` loop body.
fn parse_v2_header(data: &[u8], meta: &mut Metadata) -> Option<ParsedV2Header> {
  if data.len() < 10 {
    meta.push_warning("Short ID3 header");
    return None;
  }
  let h = &data[3..10];
  let vers = u16::from_be_bytes([h[0], h[1]]);
  let flags = h[2];
  let size_raw = u32::from_be_bytes([h[3], h[4], h[5], h[6]]);
  let size = match unsync_safe(size_raw) {
    Some(s) => s as usize,
    None => {
      meta.push_warning("Invalid ID3 header");
      return None;
    }
  };
  if vers >= 0x0500 {
    let ver_str = format!("2.{}.{}", vers >> 8, vers & 0xff);
    meta.push_warning(format!("Unsupported ID3 version: {ver_str}"));
    return None;
  }
  if 10 + size > data.len() {
    meta.push_warning("Truncated ID3 data");
    return None;
  }
  let mut h_buff: Vec<u8> = data[10..10 + size].to_vec();
  if flags & 0x80 != 0 && vers < 0x0400 {
    h_buff = reverse_unsync_inplace(&h_buff);
  }
  if flags & 0x40 != 0 {
    if h_buff.len() < 4 {
      meta.push_warning("Bad ID3 extended header");
      return None;
    }
    let ext_len_raw = u32::from_be_bytes([h_buff[0], h_buff[1], h_buff[2], h_buff[3]]);
    let ext_len = match unsync_safe(ext_len_raw) {
      Some(s) => s as usize,
      None => ext_len_raw as usize,
    };
    if ext_len > h_buff.len() {
      meta.push_warning("Truncated ID3 extended header");
      return None;
    }
    h_buff = h_buff[ext_len..].to_vec();
  }
  Some(ParsedV2Header {
    h_buff,
    vers,
    flags,
    size,
  })
}

fn finalize(
  meta: &mut Metadata,
  print_conv_on: bool,
  cctx: &ConvContext,
  id3_len: u64,
  found_any: bool,
  header_data: Option<(Vec<u8>, u16)>,
  trailer_data: Option<Vec<u8>>,
  enh_data: Option<Vec<u8>>,
) -> bool {
  if !found_any {
    return false;
  }
  // SetFileType is the engine's responsibility now (the typed
  // `extract_info` finalizes File:* via `AnyMeta::finalize_file_type`); this
  // internal staging pass only collects the ID3 tags. (The old MP3
  // `do_set_file_type` SetFileType('MP3') path is gone — bundled MP3 typing
  // is the detected candidate type, applied by the engine.)
  meta.push(
    Group::new("File", "File"),
    "ID3Size",
    TagValue::I64(id3_len as i64),
  );
  if let Some((h_buff, vers)) = header_data {
    let table = if vers >= 0x0400 {
      &ID3V2_4_MAIN
    } else if vers >= 0x0300 {
      &ID3V2_3_MAIN
    } else {
      &ID3V2_2_MAIN
    };
    process_id3v2(&h_buff, vers, table, meta, print_conv_on, cctx);
  }
  if let Some(t) = trailer_data {
    let _ = ID3V1_MAIN; // referenced for static link only
    process_id3v1(&t, meta, print_conv_on, cctx);
    // ID3.pm:1618-1626 — Enhanced TAG is processed AFTER the v1 trailer (the
    // bundled `if ($id3Trailer{EnhancedTAG})` block runs INSIDE the
    // `if (%id3Trailer)` arm at :1613). F4 (Codex adversarial): the pre-fix
    // engine sized the Enhanced TAG block (so `DoneID3` was right for the
    // APE.pm:169 footer shift) but never PARSED its 227-byte content, so the
    // golden had to be hand-trimmed. Now we extract the 7 `ID3v1_Enh:*`
    // fields faithfully.
    if let Some(e) = enh_data {
      let _ = crate::formats::id3::v1_enh::ID3V1_ENH_MAIN; // static link
      crate::formats::id3::v1_enh::process_id3v1_enh(&e, meta, print_conv_on, cctx);
    }
  }
  true
}

fn reverse_unsync_inplace(v: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(v.len());
  let mut i = 0;
  while i < v.len() {
    if v[i] == 0xff && i + 1 < v.len() && v[i + 1] == 0x00 {
      out.push(0xff);
      i += 2;
    } else {
      out.push(v[i]);
      i += 1;
    }
  }
  out
}

// ===========================================================================
// Public lib-first direct entries — borrow-from-input typed Meta
// ===========================================================================

/// Lib-first direct entry. Returns an [`Id3Meta`] that borrows from the
/// input buffer (Phase G zero-alloc reservation; `Id3Meta` owns all
/// strings via `SmolStr` today, so the borrow lifetime is phantom).
///
/// `print_conv = true` stages the tags in `-j` PrintConv mode (e.g. ID3v1
/// Genre `"Hip-Hop"`); `print_conv = false` stages in `-n` post-ValueConv
/// raw mode (e.g. Genre `7`). The returned Meta must be sinked in the same
/// mode (see `serialize_tags` for [`Id3Meta`]; Codex BF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_id3_borrowed<'a>(
  data: &'a [u8],
  shared: Option<&mut SharedFlags>,
  print_conv: bool,
) -> Result<Option<Id3Meta<'a>>, Id3Error> {
  parse_id3_inner(data, shared, print_conv).map(|(meta, _hdr_end)| meta)
}

/// As [`parse_id3_borrowed`], but ALSO returns the bundled `$hdrEnd`
/// (ID3.pm:1504) — the file offset PAST a leading ID3v2 header. Chained
/// callers that carry an ID3 PREFIX (e.g. APE: an ID3v2 tag in front of the
/// `MAC `/`APETAGEX` body, ID3.pm:1582-1601 audio loop → recursive
/// ProcessAPE on the post-ID3 slice) need the offset to slice the format
/// body. `0` when there is no valid ID3v2 prefix (the body begins at offset
/// 0). The `DoneID3` "ran" marker + trailer size are recorded on `shared`
/// exactly as [`parse_id3_borrowed`] does (so APE.pm:169's footer shift sees
/// the v1-trailer size).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today).
pub(crate) fn parse_id3_with_hdr_end<'a>(
  data: &'a [u8],
  shared: Option<&mut SharedFlags>,
  print_conv: bool,
) -> Result<(Option<Id3Meta<'a>>, usize), Id3Error> {
  parse_id3_inner(data, shared, print_conv)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // The `run` helper drives the `mp3`-gated `ProcessMp3` legacy bridge,
  // so it (and every test that calls it) is gated behind `mp3` (Codex
  // A-R2-1). Pure-ID3 tests below use `process_id3_inner_legacy` /
  // `parse_id3_borrowed` and stay ungated.
  /// Run the engine (`extract_info`) over `data` named `name` in `-j` mode and
  /// return the parsed file object (replacing the retired `ProcessMp3::process`
  /// + `TagMap` `run` helper). `tag(obj, "Name")` finds a tag by its
  /// bare name across any group prefix, returning its `serde_json::Value`.
  #[cfg(all(feature = "mp3", feature = "json"))]
  fn run(data: &[u8], name: &str) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info(name, data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  /// Find a tag by bare `name` (suffix after the `:` group prefix) in a
  /// `run`-produced object. `None` if no key ends with `:<name>`.
  #[cfg(all(feature = "mp3", feature = "json"))]
  fn find_tag<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
  ) -> Option<&'a serde_json::Value> {
    let suffix = std::format!(":{name}");
    obj
      .iter()
      .find(|(k, _)| k.ends_with(&suffix))
      .map(|(_, v)| v)
  }

  // -------------------------------------------------------------------------
  // Legacy regression pins — preserved verbatim from pre-F2 process.rs
  // -------------------------------------------------------------------------

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_empty_data_rejects() {
    let m = run(&[], "x.mp3");
    assert!(find_tag(&m, "FileType").is_none());
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_random_bytes_no_mpeg_sync_rejects() {
    let m = run(b"abcdefghij", "random.mp3");
    assert!(find_tag(&m, "FileType").is_none());
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_valid_mpeg_audio_frame_accepts_as_mp3() {
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfb;
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  // -------------------------------------------------------------------------
  // Typed-path (FormatParser / serialize_tags) regression — Codex BF1/CF1.
  // The prior typed `ProcessMp3::parse` staged only ID3 and returned
  // `Ok(None)` for raw-MPEG MP3 (`MP3.mp3` = `ff fb 90 4c`). The chained
  // typed parser now mirrors `ProcessMP3` (ID3 -> MPEG -> APE) and
  // populates the typed sub-Metas.
  // -------------------------------------------------------------------------

  /// `parse_mp3_borrowed(MP3.mp3)` returns `Some(Mp3Meta)` with the MPEG
  /// sub-Meta populated (no ID3). Bundled: `MP3.mp3` is MPEG-only
  /// (`ff fb 90 4c`), MPEGAudioVersion 1 / AudioLayer 3.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_mpeg_only_fixture_populates_mpeg() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let mut shared = SharedFlags::new();
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("MPEG-only MP3 must be Some(Mp3Meta), not None (Codex BF1/CF1)");
    assert!(meta.found());
    assert!(meta.id3().is_none(), "MP3.mp3 has no ID3");
    let mpeg = meta.mpeg().expect("MPEG sub-Meta populated");
    assert_eq!(
      mpeg.mpeg_audio_version(),
      crate::formats::mpeg::AudioVersion::V1
    );
    assert_eq!(mpeg.audio_layer(), crate::formats::mpeg::AudioLayer::L3);
    // Sink emits MPEG:* tags.
    let mut w = crate::tagmap::TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("MPEG", "MPEGAudioVersion"), Some("1".into()));
    assert_eq!(w.get_str("MPEG", "AudioBitrate"), Some("128 kbps".into()));
  }

  /// The crate-root [`crate::parse_mp3`] (local `SharedFlags`) also returns
  /// `Some(Mp3Meta)` for the MPEG-only fixture.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_public_entry_mpeg_only_is_some() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let meta = crate::parse_mp3(&bytes, Some("MP3"))
      .expect("ok")
      .expect("public parse_mp3 must be Some for MPEG-only MP3");
    assert!(meta.mpeg().is_some());
  }

  /// `parse_bytes(MP3.mp3)` dispatches to `AnyMeta::Mp3` with the MPEG
  /// sub-Meta populated (the closed-dispatch path; Codex CF1).
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_bytes_mp3_mpeg_only_dispatches_to_mp3_arm() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let meta = crate::parse_bytes(&bytes)
      .expect("ok")
      .expect("parse_bytes must accept MPEG-only MP3");
    match meta {
      crate::AnyMeta::Mp3(m) => {
        assert!(
          m.mpeg().is_some(),
          "MPEG sub-Meta populated via parse_bytes"
        );
      }
      other => panic!("expected AnyMeta::Mp3, got {other:?}"),
    }
  }

  /// `parse_mp3_borrowed(ID3v2_with_mpeg_audio.mp3)` populates BOTH the
  /// ID3 sub-Meta (Title="Test") and the MPEG sub-Meta — faithful to the
  /// bundled `ProcessMP3` recursion that emits ID3v2 + MPEG tags together.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_id3v2_plus_mpeg_populates_both() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ID3v2_with_mpeg_audio.mp3"),
    )
    .expect("read ID3v2_with_mpeg_audio.mp3 fixture");
    let mut shared = SharedFlags::new();
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("found");
    let id3 = meta.id3().expect("ID3 sub-Meta present");
    assert_eq!(id3.title(), Some("Test"));
    assert!(
      meta.mpeg().is_some(),
      "MPEG sub-Meta present for ID3v2+audio MP3 (ProcessMP3 recursion)"
    );
    // Sink emits BOTH ID3v2_3:Title and MPEG:* tags.
    let mut w = crate::tagmap::TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("ID3v2_3", "Title"), Some("Test".into()));
    assert_eq!(w.get_str("MPEG", "MPEGAudioVersion"), Some("1".into()));
  }

  /// `parse_bytes(ID3v2_with_mpeg_audio.mp3)` dispatches to `AnyMeta::Mp3`
  /// (NOT `AnyMeta::Ogg`) with BOTH the ID3 sub-Meta (Title="Test") and the
  /// MPEG sub-Meta populated. Regression for Codex C-R2-1: the OGG typed
  /// parser returns `Some(ogg::Meta { success: false })` for this ID3-prefixed
  /// input, which — before the fix — terminated the closed-dispatch
  /// candidate loop and mis-reported the file as `AnyMeta::Ogg`. The OGG arm
  /// now maps `success() == false` to `Ok(None)` so dispatch falls through
  /// to the MP3 candidate. Bundled `exiftool -j` reports FileType=MP3,
  /// Title=Test, MPEGAudioVersion=1.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_bytes_id3v2_plus_mpeg_dispatches_to_mp3_not_ogg() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ID3v2_with_mpeg_audio.mp3"),
    )
    .expect("read ID3v2_with_mpeg_audio.mp3 fixture");
    let meta = crate::parse_bytes(&bytes)
      .expect("ok")
      .expect("parse_bytes must accept ID3v2+MPEG MP3");
    match meta {
      crate::AnyMeta::Mp3(m) => {
        assert_eq!(
          m.id3().and_then(|id3| id3.title()),
          Some("Test"),
          "ID3 sub-Meta present with Title=Test"
        );
        assert!(
          m.mpeg().is_some(),
          "MPEG sub-Meta populated for ID3v2+audio MP3 via parse_bytes"
        );
      }
      other => panic!("expected AnyMeta::Mp3 (Codex C-R2-1), got {other:?}"),
    }
  }

  /// When `DoneID3` is already set on the shared flags (a prior chained
  /// parser ran `ProcessID3`), the typed MP3 wrapper must SKIP the ID3 pass
  /// (`unless ($$et{DoneID3})`, ID3.pm:1691-1693) and emit NO duplicate ID3
  /// sub-Meta — MPEG scanning alone decides acceptance. Regression for Codex
  /// B-R2-2: `parse_mp3_typed` previously called `parse_id3_inner`
  /// unconditionally, re-emitting the ID3 frames a second time.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_skips_id3_when_done_id3_already_set() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ID3v2_with_mpeg_audio.mp3"),
    )
    .expect("read ID3v2_with_mpeg_audio.mp3 fixture");
    let mut shared = SharedFlags::new();
    // Simulate a prior parser having already processed ID3 (ID3.pm:1436).
    shared.set_done_id3(0);
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("MPEG sync alone still accepts the file");
    assert!(
      meta.id3().is_none(),
      "no duplicate ID3 sub-Meta when DoneID3 already set (Codex B-R2-2)"
    );
    assert!(
      meta.mpeg().is_some(),
      "MPEG sub-Meta still populated (scan from offset 0)"
    );
  }

  /// Codex B-R3-1: when a chained caller already ran typed ID3 over the FULL
  /// buffer (setting `DoneID3` AND the carried `id3_hdr_end`), the typed MP3
  /// skip path must scan MPEG from that `$hdrEnd`, NOT offset 0. For
  /// `mp3_with_large_id3v2_artwork.mp3` the ID3v2 body is ~9261 bytes
  /// (`$hdrEnd` ≈ 9271 > the 8192 MP3 scan window), so a from-0 scan sees
  /// only ID3 bytes and emits NO MPEG tags; from `$hdrEnd` the MPEG frame
  /// sync is found. Faithful to the audio-format loop's `$raf->Seek($hdrEnd,
  /// 0)` (ID3.pm:1590) before the recursive `ProcessMP3`.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_done_id3_skip_scans_from_carried_hdr_end() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mp3_with_large_id3v2_artwork.mp3"),
    )
    .expect("read mp3_with_large_id3v2_artwork.mp3 fixture");

    // First, a chained caller runs typed ID3 over the FULL buffer. This sets
    // both `DoneID3` and the carried `id3_hdr_end` (the post-ID3v2 offset).
    let mut shared = SharedFlags::new();
    let id3 = parse_id3_borrowed(&bytes, Some(&mut shared), /* print_conv */ true)
      .expect("ok")
      .expect("large-ID3 artwork file has an ID3v2 directory");
    assert!(id3.v2_version().is_some(), "ID3v2 directory parsed");
    assert!(shared.done_id3().is_some(), "DoneID3 set by typed ID3 pass");
    let carried = shared
      .id3_hdr_end()
      .expect("typed ID3 pass records the post-ID3v2 hdr_end");
    assert!(
      carried > 8192,
      "ID3v2 body extends past the 8192 MP3 scan window (hdr_end={carried})"
    );

    // Now the typed MP3 wrapper re-enters with DoneID3 + hdr_end preset (the
    // bundled recursion-after-Seek path). It must scan from the carried
    // hdr_end and STILL emit MPEG tags.
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("MPEG frame after the large ID3v2 body still accepts the file");
    assert!(
      meta.id3().is_none(),
      "no duplicate ID3 sub-Meta when DoneID3 already set (Codex B-R2-2)"
    );
    assert!(
      meta.mpeg().is_some(),
      "MPEG sub-Meta populated by scanning from the carried hdr_end, not 0 (Codex B-R3-1)"
    );
  }

  /// Codex B-R3-1 negative control: DoneID3 preset by a caller that did NOT
  /// run typed ID3 (so `id3_hdr_end` is `None`) falls back to the legacy
  /// offset-0 scan. `ID3v2_with_mpeg_audio.mp3` has its MPEG sync within the
  /// first 8192 bytes, so the from-0 fallback still finds it — confirming the
  /// `unwrap_or(0)` default preserves the prior behavior.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_done_id3_without_carried_hdr_end_falls_back_to_zero() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ID3v2_with_mpeg_audio.mp3"),
    )
    .expect("read ID3v2_with_mpeg_audio.mp3 fixture");
    let mut shared = SharedFlags::new();
    shared.set_done_id3(0); // injected; no typed ID3 pass ran.
    assert_eq!(shared.id3_hdr_end(), None, "no carried hdr_end");
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("MPEG sync within first 8192 bytes still accepts via offset-0 fallback");
    assert!(
      meta.mpeg().is_some(),
      "offset-0 fallback still finds the sync"
    );
  }

  /// `parse_id3_inner` mirrors `ProcessID3`'s `$$et{DoneID3} = 1` side
  /// effect (ID3.pm:1435-1436): even when NO ID3 is found, the typed MP3
  /// wrapper sets `DoneID3` to `Some(0)` (no-trailer marker) so a downstream
  /// chained parser observes it (Codex B-R2-2). `MP3.mp3` is raw MPEG with
  /// no ID3.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_parse_mp3_sets_done_id3_even_when_no_id3_found() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let mut shared = SharedFlags::new();
    assert_eq!(shared.done_id3(), None, "precondition: DoneID3 unset");
    let meta = parse_mp3_borrowed(&bytes, Some("MP3"), &mut shared)
      .expect("ok")
      .expect("MPEG-only MP3 accepted");
    assert!(meta.id3().is_none(), "MP3.mp3 has no ID3");
    assert_eq!(
      shared.done_id3(),
      Some(0),
      "DoneID3 set to Some(0) even with no ID3 (ID3.pm:1435-1436)"
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_id3v1_only() {
    let mut data: Vec<u8> = vec![0; 256];
    let mut tag = Vec::with_capacity(128);
    tag.extend_from_slice(b"TAG");
    let pad = |s: &str, n: usize| {
      let mut v: Vec<u8> = s.bytes().collect();
      v.resize(n, 0);
      v
    };
    tag.extend_from_slice(&pad("Title", 30));
    tag.extend_from_slice(&pad("Artist", 30));
    tag.extend_from_slice(&pad("Album", 30));
    tag.extend_from_slice(b"2003");
    tag.extend_from_slice(&pad("Comment", 30));
    tag.push(7);
    assert_eq!(tag.len(), 128);
    data.extend_from_slice(&tag);
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
    assert_eq!(find_tag(&m, "ID3Size").and_then(|v| v.as_i64()), Some(128));
    assert_eq!(
      find_tag(&m, "Title").and_then(|v| v.as_str()),
      Some("Title")
    );
    assert_eq!(
      find_tag(&m, "Genre").and_then(|v| v.as_str()),
      Some("Hip-Hop")
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_id3v2_2_with_title_artist() {
    let title_frame: Vec<u8> = {
      let mut body: Vec<u8> = vec![0];
      body.extend_from_slice(b"Hello");
      let mut v = Vec::new();
      v.extend_from_slice(b"TT2");
      let len = body.len() as u32;
      v.push(((len >> 16) & 0xff) as u8);
      let lo = (len & 0xffff) as u16;
      v.extend_from_slice(&lo.to_be_bytes());
      v.extend_from_slice(&body);
      v
    };
    let artist_frame: Vec<u8> = {
      let mut body: Vec<u8> = vec![0];
      body.extend_from_slice(b"Phil");
      let mut v = Vec::new();
      v.extend_from_slice(b"TP1");
      let len = body.len() as u32;
      v.push(((len >> 16) & 0xff) as u8);
      let lo = (len & 0xffff) as u16;
      v.extend_from_slice(&lo.to_be_bytes());
      v.extend_from_slice(&body);
      v
    };
    let body: Vec<u8> = title_frame.into_iter().chain(artist_frame).collect();
    let size = body.len() as u32;
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x02);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(&body);
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "Title").and_then(|v| v.as_str()),
      Some("Hello")
    );
    assert_eq!(
      find_tag(&m, "Artist").and_then(|v| v.as_str()),
      Some("Phil")
    );
    assert_eq!(
      find_tag(&m, "ID3Size").and_then(|v| v.as_i64()),
      Some(10 + size as i64)
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_unsync_extheader_shrinks_below_4_does_not_panic() {
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x03);
    data.push(0x00);
    data.push(0xc0);
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
    data.extend_from_slice(&[0xff, 0x00, 0xff, 0x00]);
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "Warning").and_then(|v| v.as_str()),
      Some("Bad ID3 extended header")
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_layer_two_dotless_filename_rejected() {
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfd;
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "x");
    assert!(find_tag(&m, "FileType").is_none());
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_layer_two_mus_extension_accepted() {
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfd;
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "song.mus");
    assert_eq!(
      find_tag(&m, "FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_unsupported_id3v5_warns() {
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x05);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&[0u8, 0, 0, 0]);
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "Warning").and_then(|v| v.as_str()),
      Some("Unsupported ID3 version: 2.5.0")
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_truncated_warns() {
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x02);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&[0u8, 0, 0, 100]);
    data.extend_from_slice(&[0u8; 3]);
    let m = run(&data, "x.mp3");
    assert_eq!(
      find_tag(&m, "Warning").and_then(|v| v.as_str()),
      Some("Truncated ID3 data")
    );
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn process_mp3_short_header_warns() {
    let data = b"ID3\x02\x00";
    let m = run(data, "x.mp3");
    assert_eq!(
      find_tag(&m, "Warning").and_then(|v| v.as_str()),
      Some("Short ID3 header")
    );
  }

  #[test]
  fn process_id3_enhanced_tag_sets_done_id3_to_355() {
    let mut data: Vec<u8> = vec![0xaa; 100];
    let mut enhanced = vec![b'T', b'A', b'G', b'+'];
    enhanced.resize(227, 0);
    data.extend_from_slice(&enhanced);
    let mut id3v1 = vec![b'T', b'A', b'G'];
    id3v1.resize(128, 0);
    data.extend_from_slice(&id3v1);
    assert_eq!(data.len(), 100 + 227 + 128);

    let mut meta = Metadata::new("x.mp3");
    let (_found, _hdr_end) = process_id3_inner_legacy(&data, &mut meta, true);
    assert_eq!(meta.done_id3(), Some(355));
  }

  #[test]
  fn process_id3_standard_tag_only_sets_done_id3_to_128() {
    let mut data: Vec<u8> = vec![0xaa; 100 + 227];
    let mut id3v1 = vec![b'T', b'A', b'G'];
    id3v1.resize(128, 0);
    data.extend_from_slice(&id3v1);
    assert_eq!(data.len(), 100 + 227 + 128);

    let mut meta = Metadata::new("x.mp3");
    let (_found, _hdr_end) = process_id3_inner_legacy(&data, &mut meta, true);
    assert_eq!(meta.done_id3(), Some(128));
  }

  #[test]
  fn process_id3_v24_truncated_footer_does_not_panic() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x04);
    data.push(0x00);
    data.push(0x10);
    data.extend_from_slice(&[0u8, 0, 0, 24]);
    data.extend_from_slice(&vec![0u8; 24]);
    assert_eq!(data.len(), 34);

    let mut meta = Metadata::new("x.mp3");
    let (_found, hdr_end) = process_id3_inner_legacy(&data, &mut meta, true);
    assert_eq!(hdr_end, 44);
    assert!(hdr_end > data.len());
  }

  // -------------------------------------------------------------------------
  // Phase F2 typed-Meta tests
  // -------------------------------------------------------------------------

  fn build_id3v1_block() -> Vec<u8> {
    let mut tag = Vec::with_capacity(128);
    tag.extend_from_slice(b"TAG");
    let pad = |s: &str, n: usize| {
      let mut v: Vec<u8> = s.bytes().collect();
      v.resize(n, 0);
      v
    };
    tag.extend_from_slice(&pad("Hello", 30));
    tag.extend_from_slice(&pad("Phil", 30));
    tag.extend_from_slice(&pad("Album1", 30));
    tag.extend_from_slice(b"2003");
    tag.extend_from_slice(&pad("Comment1", 30));
    tag.push(7); // Hip-Hop
    assert_eq!(tag.len(), 128);
    tag
  }

  #[test]
  fn parse_id3_borrowed_returns_some_for_id3v1_trailer() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let meta = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    assert_eq!(meta.id3_size(), 128);
    assert_eq!(meta.title(), Some("Hello"));
    assert_eq!(meta.artist(), Some("Phil"));
    assert_eq!(meta.album(), Some("Album1"));
    assert_eq!(meta.year(), Some("2003"));
    assert_eq!(meta.comment(), Some("Comment1"));
    assert_eq!(meta.genre(), Some("Hip-Hop"));
  }

  #[test]
  fn parse_id3_borrowed_id3v1_subframe_populated() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let meta = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    let v1 = meta.id3v1().expect("v1 present");
    assert_eq!(v1.title(), Some("Hello"));
    assert_eq!(v1.artist(), Some("Phil"));
    assert_eq!(v1.album(), Some("Album1"));
    assert_eq!(v1.year(), Some("2003"));
    assert_eq!(v1.comment(), Some("Comment1"));
    assert_eq!(v1.genre_name(), Some("Hip-Hop"));
  }

  #[test]
  fn parse_id3_borrowed_returns_none_when_no_id3() {
    let data = vec![0u8; 64];
    assert!(parse_id3_borrowed(&data, None, true).expect("ok").is_none());
  }

  #[test]
  fn parse_id3_borrowed_v22_frames_populate_meta() {
    let title_frame: Vec<u8> = {
      let mut body: Vec<u8> = vec![0];
      body.extend_from_slice(b"Hello");
      let mut v = Vec::new();
      v.extend_from_slice(b"TT2");
      let len = body.len() as u32;
      v.push(((len >> 16) & 0xff) as u8);
      let lo = (len & 0xffff) as u16;
      v.extend_from_slice(&lo.to_be_bytes());
      v.extend_from_slice(&body);
      v
    };
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x02);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&(title_frame.len() as u32).to_be_bytes());
    data.extend_from_slice(&title_frame);
    let meta = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    assert_eq!(meta.v2_version(), Some(Id3v2Version::V2_2));
    assert_eq!(meta.title(), Some("Hello"));
    // The ID3v2.2 frame iterator should contain Title.
    let frames: Vec<Id3v2Frame> = meta.frames().collect();
    assert!(frames.iter().any(|f| f.name() == "Title"));
  }

  #[test]
  fn shared_flags_done_id3_updated_after_v1_trailer() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let mut shared = SharedFlags::new();
    let _ = parse_id3_borrowed(&data, Some(&mut shared), true).expect("ok");
    assert_eq!(shared.done_id3(), Some(128));
  }

  /// Codex B-R3-2: typed `ProcessID3` must honor the recursion guard
  /// `return 0 if $$et{DoneID3}` (ID3.pm:1435). With `DoneID3` already set, a
  /// chained typed caller (APE/FLAC → ID3, or `parse_id3_borrowed`) must
  /// return `Ok(None)` WITHOUT re-running — even over a buffer that DOES
  /// contain an ID3v1 trailer. The pre-existing `done_id3` value is left
  /// untouched (the guarded pass does not overwrite it).
  #[test]
  fn typed_id3_honors_done_id3_recursion_guard() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let mut shared = SharedFlags::new();
    // A prior parser already ran ID3 and consumed a 128-byte v1 trailer.
    shared.set_done_id3(128);
    let meta = parse_id3_borrowed(&data, Some(&mut shared), true).expect("ok");
    assert!(
      meta.is_none(),
      "guard returns Ok(None) without re-running (ID3.pm:1435)"
    );
    assert_eq!(
      shared.done_id3(),
      Some(128),
      "pre-existing DoneID3 left untouched by the guarded pass"
    );
  }

  /// Codex B-R3-2: the `$$et{DoneID3} = 1` marker (ID3.pm:1436) is set BEFORE
  /// scanning, so it persists even when NO ID3 is found. A no-ID3 typed run
  /// via `parse_id3_borrowed` must propagate `DoneID3 = Some(0)` (the
  /// ran-with-no-trailer marker) onto the shared state BEFORE returning
  /// `None` — the FormatParser side-effect-persists contract. `MP3.mp3` is
  /// raw MPEG with no ID3 directory.
  #[cfg(feature = "mp3")]
  #[test]
  fn typed_id3_no_id3_run_marks_done_id3_before_returning_none() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let mut shared = SharedFlags::new();
    assert_eq!(shared.done_id3(), None, "precondition: DoneID3 unset");
    let meta = parse_id3_borrowed(&bytes, Some(&mut shared), true).expect("ok");
    assert!(meta.is_none(), "MP3.mp3 has no ID3 directory");
    assert_eq!(
      shared.done_id3(),
      Some(0),
      "DoneID3 marked Some(0) before the no-ID3 None return (ID3.pm:1436, Codex B-R3-2)"
    );
  }

  #[test]
  fn format_parser_parse_id3_returns_meta_static() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let mut shared = SharedFlags::new();
    let ctx = Id3Context::new(&data, &mut shared);
    let meta = <ProcessId3 as FormatParser>::parse(&ProcessId3, ctx)
      .expect("ok")
      .expect("found");
    assert_eq!(meta.title(), Some("Hello"));
    assert_eq!(meta.id3_size(), 128);
  }

  #[cfg(feature = "mp3")]
  #[test]
  fn format_parser_parse_mp3_wraps_id3() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let mut shared = SharedFlags::new();
    let ctx = Mp3Context::new(&data, &mut shared, Some("MP3"));
    let meta = <ProcessMp3 as FormatParser>::parse(&ProcessMp3, ctx)
      .expect("ok")
      .expect("found");
    let id3 = meta.id3().expect("id3 sub-meta present");
    assert_eq!(id3.title(), Some("Hello"));
    assert!(meta.found());
  }

  #[test]
  fn id3_meta_sinker_replays_into_writer() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block());
    let meta = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    let mut w = crate::tagmap::TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("ID3v1", "Title"), Some("Hello".into()));
    assert_eq!(w.get_str("ID3v1", "Genre"), Some("Hip-Hop".into()));
    assert_eq!(w.get_str("File", "ID3Size"), Some("128".into()));
  }

  // -------------------------------------------------------------------------
  // Codex BF2 — Id3Meta::sink must honor `print_conv` (-n support).
  // The stage-and-replay used to hardcode `print_conv_enabled = true` and
  // `Id3Meta::sink` ignored its `print_conv` arg, so `sink(false)` wrongly
  // emitted PrintConv strings. Now the typed parse stages in the requested
  // mode and the sink honors it. Compared against bundled `exiftool -j -n`.
  // -------------------------------------------------------------------------

  /// ID3v1 Genre %genre PrintConv (ID3.pm:371-375): `-j` emits "Hip-Hop",
  /// `-n` emits the raw byte `7`. Bundled `exiftool -j -n` on an
  /// ID3v1-genre-7 file emits `"ID3v1:Genre": 7`.
  #[test]
  fn id3_typed_sink_n_mode_emits_raw_genre_byte() {
    let mut data: Vec<u8> = vec![0; 256];
    data.extend_from_slice(&build_id3v1_block()); // genre byte = 7 (Hip-Hop)

    // -j mode: parse + sink in PrintConv mode → "Hip-Hop".
    let meta_j = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    let mut wj = crate::tagmap::TagMap::new();
    meta_j.serialize_tags(true, &mut wj).unwrap();
    assert_eq!(wj.get_str("ID3v1", "Genre"), Some("Hip-Hop".into()));

    // -n mode: parse + sink in raw mode → "7" (the raw genre byte),
    // matching bundled `exiftool -j -n`.
    let meta_n = parse_id3_borrowed(&data, None, false)
      .expect("ok")
      .expect("found");
    let mut wn = crate::tagmap::TagMap::new();
    meta_n.serialize_tags(false, &mut wn).unwrap();
    assert_eq!(
      wn.get_str("ID3v1", "Genre"),
      Some("7".into()),
      "-n must emit the raw genre byte, not the PrintConv string (Codex BF2)"
    );
  }

  /// ID3v2 TLEN ValueConv/PrintConv split (ID3.pm:592-595): TLEN `"7000"`
  /// ms → ValueConv `7` (s) → PrintConv `"7 s"`. Bundled `exiftool -j`
  /// emits `"Length": "7 s"`; `-j -n` emits `"Length": 7`.
  #[test]
  fn id3_typed_sink_n_mode_emits_raw_tlen_seconds() {
    // ID3v2.3 directory carrying a single TLEN = "7000" frame.
    let mut frame: Vec<u8> = Vec::new();
    frame.extend_from_slice(b"TLEN");
    frame.extend_from_slice(&5u32.to_be_bytes()); // frame size
    frame.extend_from_slice(&[0, 0]); // flags
    frame.push(0); // text encoding = Latin-1
    frame.extend_from_slice(b"7000");
    let size = frame.len() as u32;
    let ss = [
      ((size >> 21) & 0x7f) as u8,
      ((size >> 14) & 0x7f) as u8,
      ((size >> 7) & 0x7f) as u8,
      (size & 0x7f) as u8,
    ];
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"ID3");
    data.extend_from_slice(&[0x03, 0x00, 0x00]); // v2.3, no flags
    data.extend_from_slice(&ss);
    data.extend_from_slice(&frame);

    // -j: "7 s" (PrintConv).
    let meta_j = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    let mut wj = crate::tagmap::TagMap::new();
    meta_j.serialize_tags(true, &mut wj).unwrap();
    assert_eq!(wj.get_str("ID3v2_3", "Length"), Some("7 s".into()));

    // -n: 7 (raw ValueConv seconds), matching bundled `exiftool -j -n`.
    let meta_n = parse_id3_borrowed(&data, None, false)
      .expect("ok")
      .expect("found");
    let mut wn = crate::tagmap::TagMap::new();
    meta_n.serialize_tags(false, &mut wn).unwrap();
    assert_eq!(
      wn.get_str("ID3v2_3", "Length"),
      Some("7".into()),
      "-n must emit raw ValueConv seconds, not the PrintConv \"7 s\" (Codex BF2)"
    );
  }

  /// **Codex B-R2-1.** A SINGLE `ProcessId3.parse(...)` must serve BOTH
  /// `sink(true)` (PrintConv `-j`) AND `sink(false)` (raw `-j -n`) — the
  /// library-correct contract (no mode-lock, no debug panic, no PrintConv
  /// strings leaking into `-n`). Combined fixture: ID3v2.3 TLEN=7000 header
  /// + ID3v1 genre=7 trailer. Compared to bundled `exiftool 13.58`:
  ///   -j     → ID3v2_3:Length "7 s",  ID3v1:Genre "Hip-Hop"
  ///   -j -n  → ID3v2_3:Length 7,      ID3v1:Genre 7
  #[test]
  fn id3_typed_one_parse_serves_both_sink_modes() {
    // ID3v2.3 directory carrying a single TLEN = "7000" frame.
    let mut frame: Vec<u8> = Vec::new();
    frame.extend_from_slice(b"TLEN");
    frame.extend_from_slice(&5u32.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.push(0); // Latin-1
    frame.extend_from_slice(b"7000");
    let size = frame.len() as u32;
    let ss = [
      ((size >> 21) & 0x7f) as u8,
      ((size >> 14) & 0x7f) as u8,
      ((size >> 7) & 0x7f) as u8,
      (size & 0x7f) as u8,
    ];
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"ID3");
    data.extend_from_slice(&[0x03, 0x00, 0x00]);
    data.extend_from_slice(&ss);
    data.extend_from_slice(&frame);
    data.extend_from_slice(&[0u8; 200]); // audio-area padding
    data.extend_from_slice(&build_id3v1_block()); // ID3v1 genre byte = 7

    // ONE parse via the typed `FormatParser` entry (stages BOTH lists).
    let mut shared = SharedFlags::new();
    let ctx = Id3Context::new(&data, &mut shared);
    let meta = <ProcessId3 as FormatParser>::parse(&ProcessId3, ctx)
      .expect("ok")
      .expect("ID3 found");

    // sink(true) — PrintConv `-j`.
    let mut wj = crate::tagmap::TagMap::new();
    meta.serialize_tags(true, &mut wj).unwrap();
    assert_eq!(
      wj.get_str("ID3v2_3", "Length"),
      Some("7 s".into()),
      "-j Length must be PrintConv \"7 s\" (bundled exiftool -j)"
    );
    assert_eq!(
      wj.get_str("ID3v1", "Genre"),
      Some("Hip-Hop".into()),
      "-j Genre must be PrintConv \"Hip-Hop\" (bundled exiftool -j)"
    );

    // sink(false) — raw `-j -n`, from the SAME `meta`.
    let mut wn = crate::tagmap::TagMap::new();
    meta.serialize_tags(false, &mut wn).unwrap();
    assert_eq!(
      wn.get_str("ID3v2_3", "Length"),
      Some("7".into()),
      "-n Length must be raw 7, not \"7 s\" — from the SAME parse (Codex B-R2-1)"
    );
    assert_eq!(
      wn.get_str("ID3v1", "Genre"),
      Some("7".into()),
      "-n Genre must be raw byte 7, not \"Hip-Hop\" — from the SAME parse (Codex B-R2-1)"
    );
  }

  #[test]
  fn id3_meta_picture_extracts_apic_payload() {
    // Build an ID3v2.3 ALBUM-only tag plus an APIC frame.
    // APIC body: enc(1) + mime(C-string) + pictype(1) + desc(C-string) + data.
    let mut apic_body: Vec<u8> = Vec::new();
    apic_body.push(0); // enc = Latin-1
    apic_body.extend_from_slice(b"image/jpeg\0");
    apic_body.push(3); // Front Cover
    apic_body.extend_from_slice(b"cover\0");
    apic_body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
    // Frame header (10 bytes for v2.3): id(4) len(4) flags(2).
    let mut apic_frame = Vec::new();
    apic_frame.extend_from_slice(b"APIC");
    apic_frame.extend_from_slice(&(apic_body.len() as u32).to_be_bytes());
    apic_frame.extend_from_slice(&[0, 0]); // flags
    apic_frame.extend_from_slice(&apic_body);
    // Build ID3v2.3 directory.
    let body = apic_frame;
    let size = body.len() as u32;
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x03);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(&body);
    let meta = parse_id3_borrowed(&data, None, true)
      .expect("ok")
      .expect("found");
    let pic = meta.picture().expect("picture present");
    assert_eq!(pic.mime(), "image/jpeg");
    assert_eq!(pic.picture_type(), 3);
    assert_eq!(pic.picture_type_name(), Some("Front Cover"));
    assert_eq!(pic.description(), "cover");
    assert_eq!(pic.data(), &[0xde, 0xad, 0xbe, 0xef]);
  }

  // -------------------------------------------------------------------------
  // §2 type-convention surface — Id3v2Version predicates / Display / as_str
  // -------------------------------------------------------------------------

  #[test]
  fn id3v2_version_predicates_are_mutually_exclusive() {
    for v in [Id3v2Version::V2_2, Id3v2Version::V2_3, Id3v2Version::V2_4] {
      let hits = u8::from(v.is_v2_2()) + u8::from(v.is_v2_3()) + u8::from(v.is_v2_4());
      assert_eq!(hits, 1, "exactly one predicate true for {v:?}");
    }
    assert!(Id3v2Version::V2_2.is_v2_2());
    assert!(Id3v2Version::V2_3.is_v2_3());
    assert!(Id3v2Version::V2_4.is_v2_4());
  }

  #[test]
  fn id3v2_version_display_matches_as_str_and_distinct_from_group1() {
    assert_eq!(Id3v2Version::V2_2.as_str(), "2.2");
    assert_eq!(Id3v2Version::V2_3.as_str(), "2.3");
    assert_eq!(Id3v2Version::V2_4.as_str(), "2.4");
    // Display routes through as_str (single source of truth).
    assert_eq!(Id3v2Version::V2_4.to_string(), "2.4");
    // group1 stays the underscore tag-group form (unchanged).
    assert_eq!(Id3v2Version::V2_4.group1(), "ID3v2_4");
  }

  #[test]
  fn id3v2_frame_value_ref_accessor() {
    let f = Id3v2Frame {
      group1: SmolStr::new("ID3v2_3"),
      name: SmolStr::new("Title"),
      value: TagValue::Str(SmolStr::new("Song")),
    };
    assert_eq!(f.group1(), "ID3v2_3");
    assert_eq!(f.name(), "Title");
    assert_eq!(f.value_ref(), &TagValue::Str(SmolStr::new("Song")));
  }
}
