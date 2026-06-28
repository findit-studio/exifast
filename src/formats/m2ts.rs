// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "m2ts")]
//! Faithful port of `Image::ExifTool::M2TS` (`lib/Image/ExifTool/M2TS.pm`):
//! reads MPEG-2 Transport Streams, the AVCHD camcorder container
//! (FORMATS.md row 25 / 26).
//!
//! ## Packet framing (M2TS.pm:581-615)
//!
//! An MPEG-2 transport stream is a sequence of fixed-size 188-byte packets.
//! Blu-ray / AVCHD wraps each packet in an additional 4-byte "BDAV"
//! arrival-time prefix, giving 192-byte packets. The bundled `ProcessM2TS`
//! reads ≥ 383 bytes, finds a `0x47` byte followed by another `0x47` 188 or
//! 192 bytes later, then VALIDATES the candidate stride against the next two
//! packets (M2TS.pm:606-614). The header-start offset `$start` may be < 0
//! when part of the first timecode is missing, in which case the loop
//! advances by one full packet (M2TS.pm:601). Set FileType = `"M2TS"` for a
//! 4-byte timecode prefix, `"M2T"` when no timecode is present
//! (M2TS.pm:617).
//!
//! ## Stream demux (M2TS.pm:651-985)
//!
//! Each 188-byte packet carries a 4-byte prefix:
//!
//! - bit 23 `payload_unit_start_indicator` — section / PES START flag
//! - bits 8-20 (13 bits) `PID` — the packet identifier (stream id)
//! - bit 5 `adaptation_field_exists` — adaptation field follows the prefix
//! - bit 4 `payload_data_exists` — payload follows the adaptation field
//!
//! PID == 0 carries the **PAT** (Program Association Table); each PAT entry
//! is a `(program_number, program_map_PID)` pair (M2TS.pm:817-828).
//!
//! The PIDs listed in the PAT carry **PMT** (Program Map Table) sections.
//! Each PMT lists every elementary stream in the program as a triplet
//! `(stream_type, elementary_PID, es_info_length)` followed by descriptors
//! (M2TS.pm:829-894).
//!
//! Elementary-stream PIDs carry **PES** (Packetized Elementary Stream) data
//! — H.264 NAL units, AC-3 audio frames, …. The walker accumulates the
//! first 256/1024 bytes of each elementary stream (1024 for unknown / H.264
//! / metadata streams, 256 otherwise) and dispatches to type-specific
//! decoders in [`parse_pid`] (M2TS.pm:283-575).
//!
//! ## Decoders ported (M2TS.pm:283-575)
//!
//! - **AC-3 audio (stream types 0x81 / 0x87 / 0x91, M2TS.pm:352-354).** The
//!   PES payload is scanned for the AC-3 sync pattern `0x0b 0x77 .. ..` and
//!   the next byte's top two bits ⇒ `AC3:AudioSampleRate` (0/1/2 ⇒
//!   48000/44100/32000, M2TS.pm:165-176).
//! - **AC-3 stream descriptor (type 0x81 in the PMT ES-descriptor loop,
//!   M2TS.pm:269-280 / M2TS.pm:887-890).** A 3-byte descriptor body decodes
//!   to `AC3:AudioBitrate` / `AC3:SurroundMode` / `AC3:AudioChannels`.
//! - **H.264 video (stream type 0x1b, M2TS.pm:342-351).** The PES payload is
//!   forwarded to [`crate::formats::h264::parse_borrowed`] — the existing
//!   1:1 port of `ParseH264Video`, which produces the AVCHD camera metadata
//!   (Make / Model / DateTimeOriginal / ApertureSetting / GPS / …) from the
//!   FIRST user-data SEI. The walk extent is `-ee`-gated (M2TS.pm:347): at `-ee`
//!   the forward pass runs to EOF (so a FIRST user-data SEI past the no-`ee`
//!   early-stop is reached + processed); at no-`ee` it early-stops as bundled
//!   does without `ExtractEmbedded`. What is STILL deferred is the per-frame
//!   LATER-SEI/MDPM `-ee` update (the AVCHD timed-GPS domain — later frames
//!   refreshing `DateTimeOriginal` / MDPM GPS / exposure, H264.pm:1079-1082
//!   `next unless ExtractEmbedded`): the `GotNAL06` latch suppresses every SEI
//!   AFTER the first regardless of render mode. Deferred to #304 (the AVCHD #132
//!   domain); see the H.264 arm in [`Walker::parse_pid`].
//!
//! ## What is deferred
//!
//! - **MPEG-1 / MPEG-2 audio + video** (stream types 0x01-0x04,
//!   M2TS.pm:300-307). The bundled `MPEG::ParseMPEGAudio` /
//!   `MPEG::ParseMPEGAudioVideo` produce no fixture-visible tags for the
//!   canonical Canon-AVCHD M2TS reference, and the video side of the
//!   exifast `mpeg` module is a Phase-2 forward item. Filed as a follow-up.
//! - **LIGOGPSINFO dashcam GPS** (`type == 6 and $pid == 0x0300`,
//!   M2TS.pm:308-318). IMPLEMENTED — the PES private stream (`%noSyntax`
//!   stream_id 0xbf) carrying a `LIGOGPSINFO\0` block is routed to the shared
//!   [`crate::formats::ligogps::process_ligogps`] decode (`noFuzz` =
//!   `length != 200`) and emitted under the family-1 `LIGO` group via the shared
//!   QuickTime `Stream` emitter ([`crate::formats::quicktime::emit_ligogps`]),
//!   one `Doc<N>` per record, `-ee`-gated. Driven by the Pruveeo D90 fixture
//!   (#138/#129). The OTHER dashcam GPS variants (M2TS.pm:319-572 — Viidure,
//!   INNOVV, `$GPSINFO`/`$GPRMC`, DOD_LS600W, forum11320, vsys a6l, Jomise,
//!   Blueskysea/Viofo freeGPS) each need their own real-device fixture and are
//!   deferred (#129); the `$type < 0` arms are unreachable without the
//!   `ExtractEmbedded > 2` `%gpsPID` unroll (not exposed).
//! - **MISB metadata** (stream type 0x15, M2TS.pm:357-364). Routed through
//!   `MISB::ParseMISB` (no exifast port).
//! - **PCR back-scan for last timestamp** (M2TS.pm:653-694). IMPLEMENTED —
//!   see [`Walker::backscan_last_pcr`]. The forward pass captures `$startTime`
//!   on the FIRST PCR-bearing packet and `$endTime` on each subsequent one, and
//!   STOPS as soon as every needed PID is parsed, switching to a backward scan
//!   from EOF for the LAST PCR. This is the no-`ee` behavior (and bundled's
//!   without `ExtractEmbedded`): the H.264 arm honours `ParseH264Video`'s own
//!   `$more`, so the forward pass early-stops and the backscan finds the last
//!   PCR. At `-ee` the H.264 arm forces `$more = 1` (M2TS.pm:347), keeping the
//!   H.264 PID in `%needPID` to EOF (the full scan that also reaches the
//!   LIGOGPSINFO PES), so the forward pass sees the LAST PCR directly and the
//!   backscan never fires. Either way `Duration = lastPCR - firstPCR` spans the
//!   program. On the canonical Canon-AVCHD fixture (7 packets) the single
//!   forward PCR gives `Duration = 0 s`.
//! - **`-fast` option** (M2TS.pm:659) — not exposed by the exifast surface.
//! - **`ExtractEmbedded > 2` PID scan** (M2TS.pm:643-648) — same gating.
//! - **LIGOGPSINFO trailer** (M2TS.pm:1016-1026) — same QuickTime chain.

// Golden-v2 Contract 3c (checked-indexing): parser panic-safety by
// construction — every raw index/slice over the (attacker-controlled) input
// bytes is a checked `.get()` form below (a guarded index → `.get(..)?` or a
// `let Some(..) = ..get(..) else {..}` with the same control flow ExifTool
// took at that `.pm` line). The only `#[allow]`s are narrow, justified
// const-fn / provably-bounded lookups and the `#[cfg(test)]` module.
#![deny(clippy::indexing_slicing)]

use core::time::Duration;
use std::{string::String, vec::Vec};

use crate::format_parser::{FormatParser, parser_sealed};
use crate::formats::ligogps as ligogps_fmt;

// ===========================================================================
// §1. Constants (M2TS.pm:38-128)
// ===========================================================================

/// One MPEG-2 TS packet, without the optional BDAV arrival-time prefix.
const PACKET_LEN_NO_TC: usize = 188;
/// One MPEG-2 TS packet with the 4-byte BDAV arrival-time prefix.
const PACKET_LEN_WITH_TC: usize = 192;
/// Sync byte (`G` in the bundled-Perl `eq 'G'` comparisons at M2TS.pm:608).
const SYNC_BYTE: u8 = 0x47;
/// Initial read size (M2TS.pm:592 `$raf->Read($buff, 383) == 383`) — large
/// enough to fit one full 192-byte packet plus a 0..191 byte run-in.
const MIN_INITIAL_BYTES: usize = 383;
/// Maximum elementary-stream prefix accumulated before dispatch (unknown
/// type / H.264 / metadata streams, M2TS.pm:958-961).
const SAVE_LEN_LARGE: usize = 1024;
/// Maximum elementary-stream prefix for known fixed-format streams
/// (M2TS.pm:962-964).
const SAVE_LEN_SMALL: usize = 256;
/// `PID == 0x1fff` — null packet (M2TS.pm:627).
const PID_NULL: u16 = 0x1fff;
/// `PID == 0` — Program Association Table.
const PID_PAT: u16 = 0;
/// `PID == 0x0300` — the elementary PID the LIGOGPSINFO dashcam GPS arm is
/// gated on (`$pid == 0x0300`, M2TS.pm:308). Both bundled samples (Pruveeo D90,
/// «Wrong Way pass») write the LIGOGPSINFO PES private stream on this exact PID.
const LIGO_DASHCAM_PID: u16 = 0x0300;
/// The byte length that marks a LIGOGPSINFO block as FUZZED. `noFuzz` is
/// `length($$dataPt) != 200` (M2TS.pm:314): the Pruveeo D90's 200-byte block IS
/// fuzzed (defuzzed at decode), the «Wrong Way pass» 160-byte one is not.
const LIGO_UNFUZZED_LEN: usize = 200;
/// Expected `table_id` for PAT (`pid == 0`, M2TS.pm:787) — `0x00`.
const TABLE_ID_PAT: u8 = 0x00;
/// Expected `table_id` for PMT (`pid != 0`, M2TS.pm:787) — `0x02`.
const TABLE_ID_PMT: u8 = 0x02;

/// `stream_type` lookup (M2TS.pm:37-92). Returned VERBATIM in PrintConv mode;
/// stream-type bytes absent here render via the `Reserved` (< 0x7f) /
/// `Private` (≥ 0x7f) fallbacks + `PrintHex` (`(0xXX)` suffix), M2TS.pm:856-
/// 857.
///
/// Stored as a sorted `(byte, name)` slice for O(log n) lookup via
/// `binary_search_by_key`; no `HashMap` allocation at parse time.
const STREAM_TYPE_TABLE: &[(u8, &str)] = &[
  (0x00, "Reserved"),
  (0x01, "MPEG-1 Video"),
  (0x02, "MPEG-2 Video"),
  (0x03, "MPEG-1 Audio"),
  (0x04, "MPEG-2 Audio"),
  (0x05, "ISO 13818-1 private sections"),
  (0x06, "ISO 13818-1 PES private data"),
  (0x07, "ISO 13522 MHEG"),
  (0x08, "ISO 13818-1 DSM-CC"),
  (0x09, "ISO 13818-1 auxiliary"),
  (0x0a, "ISO 13818-6 multi-protocol encap"),
  (0x0b, "ISO 13818-6 DSM-CC U-N msgs"),
  (0x0c, "ISO 13818-6 stream descriptors"),
  (0x0d, "ISO 13818-6 sections"),
  (0x0e, "ISO 13818-1 auxiliary"),
  (0x0f, "MPEG-2 AAC Audio"),
  (0x10, "MPEG-4 Video"),
  (0x11, "MPEG-4 LATM AAC Audio"),
  (0x12, "MPEG-4 generic"),
  (0x13, "ISO 14496-1 SL-packetized"),
  (0x14, "ISO 13818-6 Synchronized Download Protocol"),
  (0x15, "Packetized metadata"),
  (0x16, "Sectioned metadata"),
  (0x17, "ISO/IEC 13818-6 DSM CC Data Carousel metadata"),
  (0x18, "ISO/IEC 13818-6 DSM CC Object Carousel metadata"),
  (
    0x19,
    "ISO/IEC 13818-6 Synchronized Download Protocol metadata",
  ),
  (0x1a, "ISO/IEC 13818-11 IPMP"),
  (0x1b, "H.264 (AVC) Video"),
  (0x1c, "ISO/IEC 14496-3 (MPEG-4 raw audio)"),
  (0x1d, "ISO/IEC 14496-17 (MPEG-4 text)"),
  (0x1e, "ISO/IEC 23002-3 (MPEG-4 auxiliary video)"),
  (0x1f, "ISO/IEC 14496-10 SVC (MPEG-4 AVC sub-bitstream)"),
  (0x20, "ISO/IEC 14496-10 MVC (MPEG-4 AVC sub-bitstream)"),
  (0x21, "ITU-T Rec. T.800 and ISO/IEC 15444 (JPEG 2000 video)"),
  (0x24, "H.265 (HEVC) Video"),
  (0x42, "Chinese Video Standard"),
  (0x7f, "ISO/IEC 13818-11 IPMP (DRM)"),
  (0x80, "DigiCipher II Video"),
  (0x81, "A52/AC-3 Audio"),
  (0x82, "HDMV DTS Audio"),
  (0x83, "LPCM Audio"),
  (0x84, "SDDS Audio"),
  (0x85, "ATSC Program ID"),
  (0x86, "DTS-HD Audio"),
  (0x87, "E-AC-3 Audio"),
  (0x8a, "DTS Audio"),
  (0x90, "Presentation Graphic Stream (subtitle)"),
  (0x91, "A52b/AC-3 Audio"),
  (0x92, "DVD_SPU vls Subtitle"),
  (0x94, "SDDS Audio"),
  (0xa0, "MSCODEC Video"),
  (0xea, "Private ES (VC-1)"),
];

/// `%noSyntax` (M2TS.pm:118-128) — PES `stream_id` bytes for which a PES
/// syntax field DOES NOT exist (no extension header).
#[inline]
const fn is_no_syntax(stream_id: u8) -> bool {
  matches!(
    stream_id,
    0xbc | 0xbe | 0xbf | 0xf0 | 0xf1 | 0xf2 | 0xf8 | 0xff
  )
}

/// Stream-type → PrintConv name. `None` ⇒ the PrintHex fallback applies.
#[must_use]
fn stream_type_name(byte: u8) -> Option<&'static str> {
  // `binary_search_by_key` yields an in-range index on `Ok`; the checked
  // `.get` keeps that provably-safe lookup within the file-level deny.
  STREAM_TYPE_TABLE
    .binary_search_by_key(&byte, |&(k, _)| k)
    .ok()
    .and_then(|i| STREAM_TYPE_TABLE.get(i))
    .map(|&(_, name)| name)
}

/// The `%tableID`-derived section name `$name` used in the `Bad $name` /
/// `Invalid $name length` warnings (M2TS.pm:786 + 95-116). `$name =
/// ($tableID{$table_id} || sprintf 'Unknown (0x%x)', $table_id) . ' Table'`.
/// Only the table_ids actually reachable at the warn sites (0x00 PAT / 0x02
/// PMT — the rest exit earlier via the `expectedID` mismatch) need a literal;
/// any other value falls through to the bundled `Unknown (0x%x)` form.
#[cfg(feature = "alloc")]
fn table_name(table_id: u8) -> String {
  let base = match table_id {
    0x00 => "Program Association",
    0x01 => "Conditional Access",
    0x02 => "Program Map",
    0x03 => "Transport Stream Description",
    _ => return format!("Unknown (0x{table_id:x}) Table"),
  };
  format!("{base} Table")
}

/// `true` iff `byte` is `Audio` per M2TS.pm:860 — the PMT inner-loop only
/// auto-registers a stream to be parsed when its PrintConv name CONTAINS
/// the literal substring "Audio".
fn is_audio_stream_type(byte: u8) -> bool {
  stream_type_name(byte).is_some_and(|s| s.contains("Audio"))
}

/// `true` iff `byte` is `Video` per M2TS.pm:860 — the PMT inner-loop only
/// auto-registers a stream to be parsed when its PrintConv name CONTAINS
/// the literal substring "Video".
fn is_video_stream_type(byte: u8) -> bool {
  stream_type_name(byte).is_some_and(|s| s.contains("Video"))
}

// ===========================================================================
// §2. Magic / packet-size detection (M2TS.pm:592-615)
// ===========================================================================

/// Probe result: `(start_offset, timecode_len)` — `start_offset` is the byte
/// offset of the FIRST packet's sync byte (= the start of the
/// `timecode_len`-byte BDAV prefix when `timecode_len == 4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
  start: usize,
  tc_len: usize,
}

impl Probe {
  /// Packet stride = 188 + `tc_len`.
  const fn packet_len(self) -> usize {
    PACKET_LEN_NO_TC + self.tc_len
  }
}

/// Faithful port of M2TS.pm:592-615 — detect the packet stride (188 vs 192)
/// and the offset of the first sync byte. Returns `None` when the magic
/// regex doesn't match (M2TS.pm:594) or the validation loop never confirms
/// the stride (M2TS.pm:606-614).
fn probe(data: &[u8]) -> Option<Probe> {
  // M2TS.pm:592-593 — "test for magic number": at least 383 bytes, then the
  // `(.{0,190}?)\x47(.{187}|.{191})\x47` regex with `$tcLen = length($2) -
  // 187` (i.e. `tcLen = 0` if 187 bytes between syncs, `tcLen = 4` if 191).
  if data.len() < MIN_INITIAL_BYTES {
    return None;
  }
  // The non-greedy `(.{0,190}?)` prefers the shortest prefix, so we scan
  // forward and PREFER the 188-byte stride at this candidate position;
  // failing that fall back to the 192-byte stride.
  let max_prefix = 190usize.min(data.len() - 1);
  let mut found: Option<(usize, usize)> = None;
  'scan: for prefix in 0..=max_prefix {
    if data.get(prefix).copied() != Some(SYNC_BYTE) {
      continue;
    }
    // Try 188-byte stride first (matches Perl's `.{187}` first alternative).
    for &between in &[187usize, 191usize] {
      let next = prefix.checked_add(1).and_then(|n| n.checked_add(between))?;
      if data.get(next).copied() == Some(SYNC_BYTE) {
        let tc_len = between - 187;
        found = Some((prefix, tc_len));
        break 'scan;
      }
    }
  }
  let (prefix_len, mut tc_len) = found?;
  let mut start = prefix_len as isize - tc_len as isize;

  // M2TS.pm:599-614 — validate the next 3 packets. The bundled loop may
  // retry once if the FIRST byte we saw turned out to be the second byte
  // of a 4-byte timecode (it bumps `tcLen = 4` and rewinds `start -= 4`).
  for _retry in 0..2 {
    // M2TS.pm:601: `start += 192 if $start < 0`. Re-evaluated each loop
    // iteration (the rewind below may push `start` negative again).
    if start < 0 {
      start += PACKET_LEN_WITH_TC as isize;
    }
    let start_usize = start as usize;
    let p_len = PACKET_LEN_NO_TC + tc_len;
    let read_size = 64 * p_len;
    let end = start_usize.saturating_add(read_size).min(data.len());
    if end <= start_usize || end - start_usize < p_len * 4 {
      // M2TS.pm:605 `$raf->Read($buff, $readSize) >= $pLen * 4 or return 0`.
      return None;
    }
    // `start_usize < end <= data.len()` (checked just above) ⇒ the slice is in
    // range; `?` is unreachable but keeps the checked-indexing contract.
    let buff = data.get(start_usize..end)?;
    // M2TS.pm:607-613 — every sync byte 1..=3 packets ahead must be 0x47.
    let mut ok = true;
    for j in 1..4 {
      let off = tc_len + p_len * j;
      if buff.get(off).copied() != Some(SYNC_BYTE) {
        ok = false;
        break;
      }
    }
    if ok {
      return Some(Probe {
        start: start_usize,
        tc_len,
      });
    }
    // M2TS.pm:609: `return 0 if $tcLen` (already tried 4-byte stride).
    if tc_len != 0 {
      return None;
    }
    // M2TS.pm:610-612: try again with a 4-byte timecode, rewinding by 4.
    tc_len = 4;
    start -= 4;
  }
  None
}

// ===========================================================================
// §3. Typed Meta — `Meta<'a>` (D8 — accessors only)
// ===========================================================================

/// Typed M2TS metadata — the lib-first output of [`ProcessM2ts`].
///
/// Carries the structural tags emitted by `Image::ExifTool::M2TS::Main`
/// (M2TS.pm:133-163) plus the AC-3 audio descriptor / sample-rate tags
/// emitted by `Image::ExifTool::M2TS::AC3` (M2TS.pm:166-247) AND a nested
/// [`crate::formats::h264::H264Meta`] when the H.264 PES payload yielded
/// any AVCHD-camera tags. The H.264 sub-Meta is emitted by its own
/// `serialize_tags` (the `H264:*` family-1 group).
///
/// **File-type override.** [`file_type`] is `"M2TS"` for a 4-byte timecode
/// prefix and `"M2T"` for no timecode (M2TS.pm:617). The engine consumes
/// this via [`crate::format_parser::FileTypeFinalize::Explicit`].
///
/// **Faithful warning.** Every parsed file emits the bundled minor warning
/// `"[minor] The ExtractEmbedded option may find more tags in the video
/// data"` whenever an H.264 stream was seen and the `ExtractEmbedded` /
/// `Validate` options are off (M2TS.pm:349-351). exifast doesn't currently
/// expose those options, so the warning is emitted unconditionally when an
/// H.264 PES payload was forwarded to the H.264 decoder.
///
/// **D8 — no public fields, accessors only.** Construct only via
/// [`ProcessM2ts::parse`].
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// `M2TS` (4-byte timecode prefix) or `M2T` (no timecode) — the
  /// `SetFileType` value from M2TS.pm:617. SmolStr in the typed Meta so
  /// the file-type finalize path can borrow it via `Explicit(&'static str)`.
  file_type: FileTypeKind,
  /// `M2TS:VideoStreamType` — the first PMT-row stream type whose PrintConv
  /// name contains "Video" (M2TS.pm:860-863). Stored as raw byte; PrintConv
  /// looked up via [`stream_type_name`]; PrintHex fallback at emit.
  video_stream_type: Option<u8>,
  /// `M2TS:AudioStreamType` — analogous to `video_stream_type` for "Audio".
  audio_stream_type: Option<u8>,
  /// `M2TS:Duration` source-of-truth — the RAW integer 27 MHz PCR tick span
  /// `endTime - startTime` (M2TS.pm:991). The `$val / 27000000` ValueConv
  /// (M2TS.pm:156) is applied as a FULL-PRECISION f64 divide at emit time so
  /// `-n` matches bundled `exiftool` to the last digit (Codex finding #5).
  /// `None` when no PCR was observed.
  duration_ticks: Option<u64>,
  /// Nanosecond-resolution [`Duration`] (derived from `duration_ticks`), for
  /// the normalized [`crate::metadata::Project`] domain layer ONLY — never the
  /// `M2TS:Duration` tag (that rides `duration_ticks` to keep full precision).
  duration: Option<Duration>,
  /// `AC3:AudioBitrate` — `b[1] >> 2` decoded via the `%AC3.AudioBitrate`
  /// ValueConv (M2TS.pm:177-220) → bits/s (or special "max" strings, raw
  /// is the unconverted index byte).
  ac3_audio_bitrate: Option<u8>,
  /// `AC3:SurroundMode` — `b[1] & 0x03` (M2TS.pm:221-227).
  ac3_surround_mode: Option<u8>,
  /// `AC3:AudioChannels` — `(b[2] >> 1) & 0x0f` (M2TS.pm:228-247).
  ac3_audio_channels: Option<u8>,
  /// `AC3:AudioSampleRate` — top two bits of the post-sync byte
  /// (M2TS.pm:253-261) ⇒ {0:48000, 1:44100, 2:32000} (M2TS.pm:170-175).
  /// Stored as the RAW index byte; PrintConv lookup at emit. Bundled `-n`
  /// emits the raw index (a fixture shows `0` for 48000).
  ac3_audio_sample_rate: Option<u8>,
  /// `MPEG:ImageWidth/Height/AspectRatio/FrameRate/VideoBitrate` — the
  /// `%MPEG::Video` sequence-header decode of a stream-type-0x01/0x02 PES
  /// (M2TS.pm:300-307 → `MPEG::ParseMPEGAudioVideo`). `None` for an MPEG-2-
  /// video-free stream (the canonical H.264 `M2TS.mts`).
  mpeg_video: Option<crate::formats::mpeg::VideoMeta>,
  /// `$$self{VALUE}{FileSize}` (ExifTool.pm `SetFileType`) — the input byte
  /// length, threaded into the Composite engine for the `%MPEG::Composite`
  /// `Duration` def (MPEG.pm:386-415 `Require => FileSize`). Not emitted as a
  /// tag (the goldens exclude `File:FileSize`); carried only for the Composite
  /// `Duration = 8 * FileSize / (Audio+VideoBitrate)` derive.
  file_size: u64,
  /// Nested H.264 Meta when an H.264 PES payload was forwarded to the
  /// H.264 decoder. The H.264 Meta is fully owned (`'a` is a phantom in
  /// `H264Meta<'a>`), but is stored at the Meta's own `'a` for GAT
  /// uniformity with formats whose sub-Metas DO borrow from the input.
  h264: Option<crate::formats::h264::H264Meta<'a>>,
  /// The malformed-input `$et->Warn` corpus captured DURING the walk, in
  /// bundled emission order (M2TS.pm:618/708/733/764/783/796/798/831/838/930).
  /// Drained by the [`Diagnose`](crate::diagnostics::Diagnose) impl (Codex
  /// finding #9). Empty for a well-formed stream like the canonical fixture.
  warnings: Vec<crate::diagnostics::Diagnostic>,
  /// Decoded LIGOGPSINFO dashcam GPS (`type == 6 and $pid == 0x0300`,
  /// M2TS.pm:308-318). One [`crate::metadata::LigoGpsSample`] per decoded PES
  /// private-stream record, each stamped with its GLOBAL `Doc<N>` ordinal
  /// (LigoGPS.pm:243). `is_empty()` for a non-dashcam stream (the canonical
  /// `M2TS.mts`). Emitted under the family-1 `LIGO` group through the shared
  /// QuickTime `Stream` emitter and projected into [`crate::metadata::MediaMetadata::gps`].
  ligogps: crate::metadata::LigoGpsMeta,
  /// Decoded MISB (STANAG-4609 KLV) metadata (`0x15` packetized-metadata stream,
  /// M2TS.pm:355-364 → `MISB::ParseMISB`). One leaf per extracted KLV tag, each
  /// stamped with its `Doc<N>` (MISB.pm:398). `is_empty()` for a stream with no
  /// MISB-coded `0x15` PES. Emitted under the family-1 `MISB` group.
  misb: crate::formats::misb::MisbMeta,
}

/// The discriminator that drives `FileType` finalization (M2TS.pm:617).
///
/// Closed enum (only two variants in the bundled-Perl logic); marked
/// `#[non_exhaustive]` so future bundled additions are additive.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum FileTypeKind {
  /// 4-byte timecode prefix present (BDAV / AVCHD).
  M2ts,
  /// No timecode prefix (raw 188-byte packets).
  M2t,
}

impl FileTypeKind {
  /// The string passed to `SetFileType` (M2TS.pm:617).
  #[must_use]
  #[inline(always)]
  pub const fn as_file_type(self) -> &'static str {
    match self {
      Self::M2ts => "M2TS",
      Self::M2t => "M2T",
    }
  }
}

impl<'a> Meta<'a> {
  /// `M2TS` or `M2T` (M2TS.pm:617).
  #[must_use]
  #[inline(always)]
  pub const fn file_type(&self) -> FileTypeKind {
    self.file_type
  }

  /// `M2TS:VideoStreamType` — raw byte (matches bundled `-n`). PrintConv
  /// applied via [`stream_type_name`] at emit (PrintHex fallback for
  /// unknown bytes).
  #[must_use]
  #[inline(always)]
  pub const fn video_stream_type(&self) -> Option<u8> {
    self.video_stream_type
  }

  /// `M2TS:AudioStreamType` — raw byte (matches bundled `-n`).
  #[must_use]
  #[inline(always)]
  pub const fn audio_stream_type(&self) -> Option<u8> {
    self.audio_stream_type
  }

  /// `M2TS:Duration` as a nanosecond-resolution [`Duration`] (PCR span ÷
  /// 27 MHz, M2TS.pm:156). Built from [`Self::duration_ticks`] for the
  /// normalized domain layer; the `M2TS:Duration` TAG itself is emitted from
  /// the raw ticks to keep full f64 precision (Codex finding #5). `None` when
  /// no PCR was observed.
  #[must_use]
  #[inline(always)]
  pub const fn duration(&self) -> Option<Duration> {
    self.duration
  }

  /// The RAW 27 MHz PCR tick span `endTime - startTime` (M2TS.pm:991) backing
  /// `M2TS:Duration`. The `/ 27000000` ValueConv (M2TS.pm:156) is applied as a
  /// full-precision f64 divide at emit time, so this preserves the exact value
  /// bundled `exiftool -n` prints (e.g. `6_000_000` ticks ⇒
  /// `0.222222222222222`). `None` when no PCR was observed.
  #[must_use]
  #[inline(always)]
  pub const fn duration_ticks(&self) -> Option<u64> {
    self.duration_ticks
  }

  /// `AC3:AudioBitrate` — the raw 6-bit index (M2TS.pm:177-220 hash key).
  #[must_use]
  #[inline(always)]
  pub const fn ac3_audio_bitrate(&self) -> Option<u8> {
    self.ac3_audio_bitrate
  }

  /// `AC3:SurroundMode` — the raw 2-bit index (M2TS.pm:221-227 hash key).
  #[must_use]
  #[inline(always)]
  pub const fn ac3_surround_mode(&self) -> Option<u8> {
    self.ac3_surround_mode
  }

  /// `AC3:AudioChannels` — the raw 4-bit index (M2TS.pm:228-247 hash key).
  #[must_use]
  #[inline(always)]
  pub const fn ac3_audio_channels(&self) -> Option<u8> {
    self.ac3_audio_channels
  }

  /// `AC3:AudioSampleRate` — the raw 2-bit index (M2TS.pm:170-175 hash key).
  #[must_use]
  #[inline(always)]
  pub const fn ac3_audio_sample_rate(&self) -> Option<u8> {
    self.ac3_audio_sample_rate
  }

  /// The MPEG-1/2 video sequence-header decode (`%MPEG::Video`,
  /// M2TS.pm:300-307). `None` when no MPEG-2-video PES was decoded.
  #[must_use]
  #[inline(always)]
  pub const fn mpeg_video(&self) -> Option<&crate::formats::mpeg::VideoMeta> {
    self.mpeg_video.as_ref()
  }

  /// The input byte length (`$$self{VALUE}{FileSize}`), used by the Composite
  /// `%MPEG::Composite` `Duration` derive (MPEG.pm:386-415). `0` only for an
  /// empty input (never produced — `probe` rejects sub-`MIN_INITIAL_BYTES`).
  #[must_use]
  #[inline(always)]
  pub const fn file_size(&self) -> u64 {
    self.file_size
  }

  /// The H.264 sub-Meta when an H.264 PES payload was forwarded. Borrowed
  /// from the input buffer via `'a`. `None` when no H.264 PES was found
  /// (or it carried no SPS / MDPM).
  #[must_use]
  #[inline(always)]
  pub fn h264(&self) -> Option<&crate::formats::h264::H264Meta<'a>> {
    self.h264.as_ref()
  }

  /// Decoded LIGOGPSINFO dashcam GPS (`type == 6 and $pid == 0x0300`,
  /// M2TS.pm:308-318). `is_empty()` for a non-dashcam stream. Each sample
  /// carries its GLOBAL `Doc<N>` ordinal.
  #[must_use]
  #[inline(always)]
  pub const fn ligogps(&self) -> &crate::metadata::LigoGpsMeta {
    &self.ligogps
  }
}

// ===========================================================================
// §5. `ProcessM2ts` + parser
// ===========================================================================

/// MPEG-2 Transport Stream / AVCHD parser — faithful port of
/// `Image::ExifTool::M2TS::ProcessM2TS` (M2TS.pm:581-1029).
#[derive(Debug, Clone, Copy)]
pub struct ProcessM2ts;

impl parser_sealed::Sealed for ProcessM2ts {}

impl FormatParser for ProcessM2ts {
  type Meta<'a> = Meta<'a>;
  type Context<'a> = &'a [u8];

  /// `Some(meta)` when the buffer's first 383 bytes carry a recognised MPEG-2
  /// TS framing (M2TS.pm:592-615); `None` for "not an M2TS" (Perl `return 0`).
  /// There is no fallible path — every malformed input is either a rejected
  /// candidate (`None`) or a partial [`Meta`] carrying its `$et->Warn`s through
  /// the [`Diagnose`](crate::diagnostics::Diagnose) channel (Golden-v2 §4).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    // The trait entry is the faithful no-`ee` baseline (`extract_embedded =
    // false`): the H.264 arm early-stops as bundled does without
    // `ExtractEmbedded`. The `-ee` full scan (M2TS.pm:347, which reaches the
    // LIGOGPSINFO PES near EOF) is requested via [`parse_borrowed_with_ee`] from
    // the mode-aware closed dispatch.
    parse_inner(data, false)
  }
}

/// Lib-first direct entry. Returns a [`Meta`] borrowing from `data` when the
/// buffer's first 383 bytes carry a recognised MPEG-2 TS framing, else `None`
/// (faithful to M2TS.pm:594/605/609 `return 0`). Every malformed-but-accepted
/// input yields a partial `Meta` with any `$et->Warn`s on its
/// [`Diagnose`](crate::diagnostics::Diagnose) channel — never a Rust error.
#[must_use]
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data, false)
}

/// Like [`parse_borrowed`] but with the render-time `ExtractEmbedded` (`-ee`)
/// mode threaded into the walk. `extract_embedded = true` mirrors M2TS.pm:347's
/// `$more = 1` full scan — the H.264 arm keeps the forward pass running to EOF
/// so the LIGOGPSINFO dashcam-GPS PES private stream (`type == 6 and $pid ==
/// 0x0300`, M2TS.pm:308-318) is reached. `extract_embedded = false` is the
/// faithful no-`ee` baseline (identical to [`parse_borrowed`]): the H.264 arm
/// early-stops exactly as bundled does without `ExtractEmbedded`, so a late
/// first user-data SEI past the early-stop is never parsed and its `H264:*` /
/// GPS tags are not emitted (byte-identical to the pre-LIGOGPS behavior).
#[must_use]
pub fn parse_borrowed_with_ee(data: &[u8], extract_embedded: bool) -> Option<Meta<'_>> {
  parse_inner(data, extract_embedded)
}

/// Inner driver. `None` ⇒ no recognised M2TS framing. `extract_embedded`
/// mirrors ExifTool `-ee` (M2TS.pm:347) and is consumed ONLY by the walk
/// (the H.264 arm's `$more` / full-scan decision); tag EMISSION re-reads the
/// render mode from [`EmitOptions`](crate::emit::EmitOptions) at `tags()` time.
fn parse_inner(data: &[u8], extract_embedded: bool) -> Option<Meta<'_>> {
  let probe = probe(data)?;
  let mut walker = Walker::new(data, probe, extract_embedded);
  walker.run();
  Some(walker.finish())
}

// ===========================================================================
// §6. Walker — packet-by-packet driver
// ===========================================================================

/// Per-elementary-stream PES accumulator (M2TS.pm:897-984).
#[derive(Debug, Default)]
struct PesAcc {
  /// Accumulated payload bytes (M2TS.pm:936-952 `$data{$pid}`).
  data: Vec<u8>,
  /// Optional declared PES `packet_length` minus 8 (the PES-extension
  /// header skip, M2TS.pm:940-944 `$packLen{$pid}`).
  pack_len: Option<usize>,
  /// `$fromStart{$pid}` — `true` once this PES was started at its
  /// `payload_unit_start_indicator` (M2TS.pm:938).
  from_start: bool,
}

/// `%didPID` entry state (M2TS.pm:629). Perl's hash entry has THREE
/// observable states because the two gates that read it use DIFFERENT
/// semantics — DEFINEDNESS vs TRUTHINESS:
///
/// - absent (`undef`) — `not defined` is TRUE (the M2TS.pm:897 elementary-
///   stream path runs) and `unless ($didPID{...})` is TRUE (M2TS.pm:825/865/
///   886 descriptor + needPID gates fire);
/// - [`Self::SeededFalse`] (`$didPID{$pid} == 0`) — the three reserved PIDs
///   seeded `( 1 => 0, 2 => 0, 0x1fff => 0 )` (M2TS.pm:629). `defined` is TRUE
///   (so the :897 ES path is SKIPPED — we never parse these as streams) but
///   the value is Perl-FALSE (so a PMT carried on such a PID still seeds
///   needPID and STILL decodes its AC-3 descriptors, M2TS.pm:825/886);
/// - [`Self::Done`] (`$didPID{$pid} == 1`) — genuinely processed (M2TS.pm:791/
///   909/975/983). `defined` AND Perl-true: BOTH gates skip.
///
/// A single `bool done` collapsed `SeededFalse` and `Done`, which suppressed
/// the M2TS.pm:886 descriptor decode (and :825/:865 needPID seeding) for a
/// first PMT/PAT carried on PID 1, 2, or 0x1fff (Codex R2 finding A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DidPid {
  /// `$didPID{$pid} == 0` — defined but Perl-FALSE (a seeded reserved PID).
  SeededFalse,
  /// `$didPID{$pid} == 1` — defined AND Perl-true (really processed).
  Done,
}

/// Per-PID dispatch state (M2TS.pm:629-630 / 869).
#[derive(Debug, Default)]
struct PidState {
  /// `$pidType{$pid}` (M2TS.pm:869). `None` until a PMT row registers it;
  /// `Some(stream_type)` thereafter.
  stream_type: Option<u8>,
  /// `$didPID{$pid}` (M2TS.pm:629). `None` ⇒ `undef`; see [`DidPid`] for the
  /// defined-but-false (`SeededFalse`) vs defined-and-true (`Done`) split
  /// that the definedness (:897) and truthiness (:825/:865/:886) gates rely on.
  did: Option<DidPid>,
  /// `$needPID{$pid}` (M2TS.pm:630). `1` ⇒ need to parse; `-1` ⇒ found
  /// (but want more); absent ⇒ not on the watchlist.
  need: Option<NeedKind>,
}

/// `$needPID{$pid}` values (M2TS.pm:630 / 825 / 865 / 913 / 973).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeedKind {
  /// Bundled `1` — still hunting for the first usable payload.
  Hunting,
  /// Bundled `-1` — parsed once but want more (PES continuation).
  WantMore,
}

/// `ParsePID` return contract (M2TS.pm:285-288):
///
/// - `0` ⇒ stream parsed OK (don't want any more) — [`ParseOutcome::Done`];
/// - `1` ⇒ parsed but we want to parse more of these — [`ParseOutcome::More`];
/// - `-1` ⇒ can't parse yet because we don't know the type (the Program Map
///   Table may be later in the stream) — [`ParseOutcome::Unknown`].
///
/// The distinction matters at the call sites: Perl's `unless ($more)`
/// (M2TS.pm:907) treats BOTH `1` and `-1` as truthy (so an unknown-type PES
/// keeps the PID needed instead of marking it done), and `next if $more < 0`
/// (M2TS.pm:968) re-stages the accumulator while waiting for the PMT. A plain
/// `bool` cannot model the `-1` case — collapsing it to `false` is exactly
/// the premature-`didPID` bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseOutcome {
  /// Bundled `0` — parsed, satisfied (mark `didPID`).
  Done,
  /// Bundled `1` — parsed, want more of this PID.
  More,
  /// Bundled `-1` — type not yet known (PMT not seen); keep waiting.
  Unknown,
}

impl ParseOutcome {
  /// Perl truthiness of the `$more` return (`0` is false; `1` and `-1` are
  /// both true) — drives `unless ($more)` at M2TS.pm:907.
  const fn wants_more(self) -> bool {
    !matches!(self, Self::Done)
  }
}

#[derive(Debug)]
struct Walker<'a> {
  data: &'a [u8],
  probe: Probe,
  /// `%pidName` (M2TS.pm:622-628) — bookkeeping only, not emitted.
  // (we drop the name strings entirely; they only matter under verbose
  // tracing, which exifast does not expose).
  /// `%pmt` (M2TS.pm:586) — set of PIDs known to carry PMT sections.
  pmt_pids: Vec<u16>,
  /// Per-PID dispatch state.
  pid_state: std::collections::BTreeMap<u16, PidState>,
  /// Per-PID PES accumulator.
  pes: std::collections::BTreeMap<u16, PesAcc>,
  /// Per-PID PMT-section reassembly buffer (M2TS.pm:769-780 — when a
  /// PMT section spans multiple TS packets, accumulate then dispatch
  /// once `sectLen` bytes are buffered).
  section: std::collections::BTreeMap<u16, Vec<u8>>,
  /// Per-PID expected total PMT section length (`%sectLen`, M2TS.pm:586/802).
  section_len: std::collections::BTreeMap<u16, usize>,
  /// PCR forward-pass start / end (M2TS.pm:743-744 / 991).
  start_time: Option<u64>,
  end_time: Option<u64>,
  /// `%pidName` membership (M2TS.pm:622-628 + 824/835/868) — the set of PIDs
  /// that have been given a name string. The VALUE strings are never emitted,
  /// but MEMBERSHIP gates the PMT `unless ($pidName{$elementary_pid})` check
  /// (M2TS.pm:861) that decides whether a newly-seen Audio/Video elementary
  /// PID emits its `StreamType` tag. Pre-seeded with PIDs 0/1/2/0x1fff.
  pid_named: std::collections::BTreeSet<u16>,
  /// `M2TS:VideoStreamType` / `M2TS:AudioStreamType` — the survivor of the
  /// PMT Video/Audio rows. M2TS.pm:860-863 `HandleTag`s the StreamType for
  /// every newly-`pidName`-seen Audio/Video elementary PID, so a NORMAL
  /// last-wins tag resolves to the LAST such PID (Codex finding #2). Stored
  /// as RAW bytes (PrintConv applied at emit).
  video_stream_type: Option<u8>,
  audio_stream_type: Option<u8>,
  /// AC-3 descriptor decode (M2TS.pm:269-280 / 887-890). `ParseAC3Descriptor`
  /// `HandleTag`s AudioBitrate/SurroundMode/AudioChannels for EVERY 0x81
  /// descriptor in the first PMT (gated `unless ($didPID{$pmt_pid})`,
  /// M2TS.pm:886) — a normal last-wins tag, so the LAST descriptor in that PMT
  /// survives (Codex finding #3).
  ac3_audio_bitrate: Option<u8>,
  ac3_surround_mode: Option<u8>,
  ac3_audio_channels: Option<u8>,
  /// AC-3 PES payload decode (M2TS.pm:253-261).
  ac3_audio_sample_rate: Option<u8>,
  /// MPEG-1/2 video sequence-header decode (M2TS.pm:300-307 →
  /// `MPEG::ParseMPEGAudioVideo`). The `%MPEG::Video` tags
  /// (`ImageWidth`/`Height`/`AspectRatio`/`FrameRate`/`VideoBitrate`) extracted
  /// from the FIRST stream-type-0x01/0x02 PES whose payload carries a valid
  /// `\0\0\x01\xb3` sequence header. `HandleTag`s are last-wins, so the LAST
  /// successfully-decoded video PES survives (the inner `if let Some`).
  mpeg_video: Option<crate::formats::mpeg::VideoMeta>,
  /// Nested H.264 Meta when an H.264 PES payload was forwarded.
  h264: Option<crate::formats::h264::H264Meta<'a>>,
  /// `$$et{ParsedH264}` (H264.pm:1102-1103) — set once the first H.264 frame
  /// for the stream has been handed to `ParseH264Video`. The bundled
  /// `ParseH264Video` returns `1` ("parse one more frame") only when the
  /// first frame carried NO SEI/MDPM user data; the SECOND call sets
  /// `ParsedH264` and always returns `0` so a stream that never yields user
  /// data is bounded to two frames (H264.pm:1100-1104). `$$et` is per-file,
  /// so this state is shared across every H.264 PID in the stream — faithful
  /// to bundled.
  parsed_h264: bool,
  /// `$$et{GotNAL06}` / `$$et{GotNAL07}` (H264.pm:1079/1093) — the per-FILE
  /// H.264 NAL latches, carried across every `ParseH264Video` call so a later
  /// frame/PID does NOT re-emit an SPS already parsed (Codex finding #6).
  /// Threaded through [`crate::formats::h264::parse_borrowed_stateful`].
  h264_frame_state: crate::formats::h264::H264FrameState,
  /// Whether any PMT was parsed (gates the early `last unless %needPID`
  /// exit at M2TS.pm:653-654).
  need_count: usize,
  /// The `$et->Warn` corpus accumulated DURING the walk, in bundled emission
  /// order (M2TS.pm:618/708/733/764/783/796/798/831/838/930 …). Mostly the
  /// malformed-input warnings raised UNCONDITIONALLY, PLUS the mode-dependent
  /// `[minor] ExtractEmbedded` warning (M2TS.pm:350) pushed at the H.264 walk
  /// position at no-`ee` only (the walk knows `extract_embedded`). Drained by
  /// the [`Diagnose`](crate::diagnostics::Diagnose) impl in this walk order, so
  /// the document `ExifTool:Warning` priority-0 first-wins survivor is faithful.
  warnings: Vec<crate::diagnostics::Diagnostic>,
  /// `last` (M2TS.pm) — set when a ported `$et->Warn(...), last` site fires;
  /// stops the forward packet loop so subsequent packets are NOT processed
  /// (faithful to Perl terminating the `for(;;)` loop). The `next`-style Warn
  /// sites (`Bad PES syntax`, M2TS.pm:930) do NOT set this.
  stop_walk: bool,
  /// Decoded LIGOGPSINFO dashcam GPS — the `type == 6 and $pid == 0x0300`
  /// dashcam arm (M2TS.pm:308-318). Each PES private-stream record is routed to
  /// the shared [`crate::formats::ligogps::process_ligogps`] decode and its
  /// per-record samples appended here. `is_empty()` for a non-dashcam stream
  /// (the canonical `M2TS.mts`, which carries no PID-0x0300 LIGOGPSINFO stream).
  ligogps: crate::metadata::LigoGpsMeta,
  /// The shared GLOBAL document counter (`$$et{DOC_COUNT}`) consumed by the
  /// LIGOGPSINFO arm — bumped once per decoded record (`$$et{DOC_NUM} =
  /// ++$$et{DOC_COUNT}`, LigoGPS.pm:243). M2TS has no `mebx`/`camm`/freeGPS
  /// timed-metadata path that shares the counter (the dashcam GPS arm is the
  /// ONLY `Doc<N>` producer in `ProcessM2TS`), so a private walker-owned counter
  /// is faithful: each PID-0x0300 PES unit yields one record taking the next
  /// `Doc<N>` in file (walk) order. Used to stamp [`Self::ligogps`] via
  /// [`crate::metadata::LigoGpsMeta::stamp_doc_from`].
  ligo_doc_counter: u32,
  /// Decoded MISB (STANAG-4609 KLV) metadata — the `0x15` packetized-metadata
  /// arm (M2TS.pm:355-364 → `MISB::ParseMISB`). Each `0x15` PES whose payload
  /// carries the MISB code is decoded into [`crate::formats::misb::MisbMeta`].
  misb: crate::formats::misb::MisbMeta,
  /// The global document counter for the MISB arm (`$$et{DOC_COUNT}`,
  /// MISB.pm:398). Each `ParseMISB` packet that yields ≥1 tag opens one
  /// `Doc<N>`; a barren packet gives the count back (MISB.pm:448). A private
  /// counter like [`Self::ligo_doc_counter`] (no fixture combines MISB with the
  /// dashcam-GPS / H.264-MDPM `Doc<N>` producers).
  misb_doc_counter: u32,
  /// Latch — the LIGOGPSINFO walker's own `$et->Warn` (`LIGOGPSINFO format
  /// error` / `LIGOGPSINFO coordinates out of range`, LigoGPS.pm:235/254) has
  /// been pushed into [`Self::warnings`] AT ITS PES WALK POSITION. The warning
  /// is a DOCUMENT-level `$et->Warn` (no `SET_GROUP1='LIGO'` in effect — the
  /// same treatment the QuickTime LigoGPS path gives it), so it joins the
  /// walk-ordered [`Self::warnings`] corpus rather than being appended after it
  /// in `diagnostics()`: a malformed LIGOGPSINFO PES that decodes BEFORE a later
  /// structural / H.264 `$et->Warn` must remain the document `ExifTool:Warning`
  /// priority-0 FIRST-wins survivor (ExifTool.pm `%noDups`; Extra.pm Warning
  /// `Priority => 0`). The latch keeps it to a SINGLE emit at the FIRST bad
  /// record's position — faithful to first-wins, and matching the pre-existing
  /// single-slot [`crate::metadata::LigoGpsMeta::warning`] (one surviving
  /// message, never a `[x$n]` count).
  ligo_warning_pushed: bool,
  /// `$$et{OPTIONS}{ExtractEmbedded}` (M2TS.pm:347) — the render-time `-ee`
  /// mode, threaded in at parse time because it gates the WALK EXTENT (not just
  /// emission): the H.264 arm forces the `$more = 1` full scan to EOF (so the
  /// LIGOGPSINFO PES near EOF is reached) ONLY at `-ee`; at no-`ee` it restores
  /// `ParseH264Video`'s own `$more` so the walk early-stops as bundled does
  /// without `ExtractEmbedded` (no late H.264 SEI parsed ⇒ no-`ee` output
  /// byte-identical to the pre-LIGOGPS behavior). It ALSO gates, EXPLICITLY, the
  /// LIGOGPSINFO PID-0x0300 decode arm (`type==6` arm — LIGOGPS is an
  /// ExtractEmbedded feature): the decode runs ONLY at `-ee`, so the
  /// mode-independent `Project` GPS projection cannot surface a fix at no-`ee`
  /// regardless of where the PES sits in the walk (#307). And it gates the
  /// in-walk `[minor] ExtractEmbedded` warning (M2TS.pm:350 — pushed at no-`ee`
  /// only, at the H.264 walk position). The LIGOGPS emission re-reads the render
  /// mode from [`EmitOptions`](crate::emit::EmitOptions) at `tags()` time
  /// independently.
  extract_embedded: bool,
}

impl<'a> Walker<'a> {
  fn new(data: &'a [u8], probe: Probe, extract_embedded: bool) -> Self {
    // M2TS.pm:629-630 — initial `%didPID = ( 1 => 0, 2 => 0, 0x1fff => 0 )`
    // and `%needPID = ( 0 => 1 )`. The three reserved PIDs (Conditional Access
    // / Transport Stream Description / Null packets) are seeded DEFINED-BUT-
    // FALSE (`SeededFalse`): their definedness skips the M2TS.pm:897 elementary-
    // stream path (we never parse them as streams) while their Perl-falseness
    // still lets a PMT carried on one of them decode descriptors + seed needPID
    // (M2TS.pm:825/:886). PID 0 starts as "need" (the PAT).
    let mut pid_state = std::collections::BTreeMap::new();
    for pid in [1u16, 2u16, PID_NULL] {
      pid_state.insert(
        pid,
        PidState {
          did: Some(DidPid::SeededFalse),
          ..Default::default()
        },
      );
    }
    pid_state.insert(
      PID_PAT,
      PidState {
        need: Some(NeedKind::Hunting),
        ..Default::default()
      },
    );
    // M2TS.pm:623-628 — `%pidName` is pre-seeded with the four reserved PIDs
    // (0 PAT, 1 CAT, 2 TSDT, 0x1fff Null). MEMBERSHIP gates the PMT
    // `unless ($pidName{$elementary_pid})` StreamType emission (M2TS.pm:861).
    let pid_named = std::collections::BTreeSet::from([PID_PAT, 1u16, 2u16, PID_NULL]);
    Self {
      data,
      probe,
      pmt_pids: Vec::new(),
      pid_state,
      pes: std::collections::BTreeMap::new(),
      section: std::collections::BTreeMap::new(),
      section_len: std::collections::BTreeMap::new(),
      start_time: None,
      end_time: None,
      pid_named,
      video_stream_type: None,
      audio_stream_type: None,
      ac3_audio_bitrate: None,
      ac3_surround_mode: None,
      ac3_audio_channels: None,
      ac3_audio_sample_rate: None,
      mpeg_video: None,
      h264: None,
      parsed_h264: false,
      h264_frame_state: crate::formats::h264::H264FrameState::new(),
      need_count: 1, // PID 0 needed
      warnings: Vec::new(),
      stop_walk: false,
      ligogps: crate::metadata::LigoGpsMeta::new(),
      ligo_doc_counter: 0,
      ligo_warning_pushed: false,
      misb: crate::formats::misb::MisbMeta::new(),
      misb_doc_counter: 0,
      extract_embedded,
    }
  }

  /// Drive the packet loop (M2TS.pm:651-985).
  fn run(&mut self) {
    let p_len = self.probe.packet_len();
    let mut cursor = self.probe.start;
    // M2TS.pm:618 `$et->Warn("File doesn't begin with the start of a packet")
    // if $start` — a plain document-level warning when the first sync byte is
    // not at offset 0 (a partial/missing leading timecode). `probe.start` is
    // the absolute byte offset of that first sync byte.
    if self.probe.start != 0 {
      self.warnings.push(crate::diagnostics::Diagnostic::warn(
        "File doesn't begin with the start of a packet",
      ));
    }
    // `$pEnd` in absolute file bytes once the forward pass stops — the start
    // of the first packet we did NOT process (used to bound the backscan so
    // we never re-scan packets the forward pass already covered).
    let mut fwd_pos = self.data.len();
    while cursor + p_len <= self.data.len() {
      // M2TS.pm:653-679 — once every needed PID has been parsed, stop the
      // forward pass and switch to a BACKWARD scan for the LAST PCR (the
      // forward pass only saw the PCRs up to here, which on real AVCHD is
      // near the START of the file — see `backscan_last_pcr`).
      if self.need_count == 0 && self.start_time.is_some() {
        fwd_pos = cursor;
        break;
      }
      // Each packet: optional 4-byte timecode + 188-byte TS packet. The
      // `while cursor + p_len <= len` guard proves `cursor + tc_len .. cursor
      // + p_len` is in range (`tc_len <= p_len`); the checked `.get` keeps the
      // deny — a `None` (impossible here) ends the forward pass like Perl's
      // buffer-exhausted `last`.
      let Some(packet) = self.data.get(cursor + self.probe.tc_len..cursor + p_len) else {
        break;
      };
      cursor += p_len;
      // M2TS.pm:705-710 — sync byte must be 0x47 (the prefix's top byte).
      if packet.first().copied() != Some(SYNC_BYTE) {
        // M2TS.pm:708 `$et->Warn('M2TS synchronization error') unless defined
        // $backScan`, then `last`. The forward pass never has `$backScan`
        // defined (that is the separate `backscan_last_pcr` path), so the warn
        // always fires here; then the whole packet loop stops.
        self.warnings.push(crate::diagnostics::Diagnostic::warn(
          "M2TS synchronization error",
        ));
        break;
      }
      self.process_packet(packet);
      // M2TS.pm — a `$et->Warn(...), last` site fired inside the packet (e.g.
      // 'Invalid adaptation field length', 'Bad pointer field', 'Truncated
      // payload', 'Bad PES syntax'); Perl terminates the `for(;;)` loop, so we
      // stop the forward pass too (subsequent packets are not processed).
      if self.stop_walk {
        break;
      }
    }

    // M2TS.pm:653-694 — backward scan for the last PCR. Only runs when the
    // forward pass stopped early (`need_count == 0`) AND saw at least one PCR;
    // otherwise `end_time` already holds the last PCR the forward pass found
    // (the natural EOF / single-PCR case, e.g. the canonical `M2TS.mts`).
    if self.need_count == 0 && self.start_time.is_some() {
      self.backscan_last_pcr(fwd_pos);
    }
    // M2TS.pm:1009-1013 — final flush: parse any partial PID streams that
    // never reached the `save_len` threshold during the walk. This is
    // crucial for small fixtures (the bundled canonical M2TS.mts has only
    // ~7 packets — total H.264 accumulation < 1024 bytes ⇒ no in-loop
    // dispatch fires) and for any normal-sized stream where the last
    // elementary chunk doesn't reach the threshold before EOF.
    //
    // M2TS.pm:1010 `foreach $pid (sort keys %data)` — Perl's default `sort` is
    // LEXICOGRAPHIC on the STRINGIFIED PID, NOT numeric. When two pending PIDs
    // emit the same tag name at EOF, the last-wins survivor is the one that
    // sorts LAST as a string (e.g. "68" > "100"), so we replicate that order
    // rather than the `BTreeMap`'s numeric u16 key order (Codex finding #8).
    let mut pending: Vec<(u16, Vec<u8>)> =
      self.pes.iter().map(|(p, a)| (*p, a.data.clone())).collect();
    pending.sort_by(|(a, _), (b, _)| {
      let mut sa = String::new();
      let mut sb = String::new();
      let _ = core::fmt::write(&mut sa, core::format_args!("{a}"));
      let _ = core::fmt::write(&mut sb, core::format_args!("{b}"));
      sa.cmp(&sb)
    });
    for (pid, data) in pending {
      let stream_type = self.pid_state.get(&pid).and_then(|s| s.stream_type);
      // Drop the accumulator before dispatch (`parse_pid` may mutate state
      // via `mark_done` indirectly).
      self.pes.remove(&pid);
      let _ = self.parse_pid(pid, stream_type, &data);
    }
  }

  /// Backward scan for the LAST PCR in the file (M2TS.pm:653-694 + 988).
  ///
  /// The forward pass stops as soon as every needed PID has been parsed,
  /// which on real AVCHD happens near the START of the file (PAT/PMT + the
  /// first H.264/AC-3 chunk). At that point `end_time` holds only the PCR(s)
  /// seen so far — far short of the real program duration. Bundled therefore
  /// re-scans packets BACKWARD from EOF (for I/O efficiency) to find the last
  /// PCR; exifast has the whole buffer in memory, so the backward direction
  /// is just an efficient way to find the SAME value: the last PCR-bearing
  /// adaptation field at or before the final whole-packet boundary.
  ///
  /// `fwd_pos` is the absolute byte offset of the first packet the forward
  /// pass did NOT process; the backscan never reaches back past it (bundled
  /// `$maxBack = $fwdPos - $fsize`), and never more than 512 KB from EOF
  /// (bundled `$nMax = int(512000/$pLen)`; "have seen last PCR at -276k").
  /// When the allowed range yields no PCR, the last forward PCR is kept as a
  /// fallback (bundled `$fwdTime`).
  fn backscan_last_pcr(&mut self, fwd_pos: usize) {
    let p_len = self.probe.packet_len();
    let fsize = self.data.len();
    if p_len == 0 || fsize < p_len {
      return;
    }
    // M2TS.pm:657-658 — remember the forward last-PCR, then clear `end_time`
    // so the backscan can detect "found a PCR going backward".
    let save_time = self.end_time;
    self.end_time = None;

    // M2TS.pm:666 `$backScan = int($fsize/$pLen)*$pLen - $fsize` — a
    // non-positive offset from EOF marking the start of the LAST whole
    // packet. `last_packet_start` is its absolute byte offset.
    let last_packet_start = (fsize / p_len) * p_len;
    // M2TS.pm:668-676 — bound the backscan. `max_back_pos` is the absolute
    // byte offset we will not scan back past (the larger of the forward stop
    // and the 512 KB window). When the forward stop is within 512 KB of EOF
    // we keep `save_time` as a fallback (`fwd_time`); otherwise the window is
    // the 512 KB cap and there is no forward fallback.
    let n_max = 512_000 / p_len; // max packets to backscan (≥ 1, p_len ≤ 192)
    let window_start = last_packet_start.saturating_sub(n_max.saturating_mul(p_len));
    let (max_back_pos, fwd_time) = if window_start > fwd_pos {
      // Forward stop is more than 512 KB before EOF — cap at the window.
      (window_start, None)
    } else {
      // Forward stop within 512 KB — never scan past it; keep the fallback.
      (fwd_pos, save_time)
    };

    // M2TS.pm:682-694 — step back one packet at a time looking for a PCR.
    // The FIRST PCR found going backward is the LAST PCR in the file. PCRs
    // are read regardless of PID (M2TS.pm:743 stores any PCR).
    let mut pkt_start = last_packet_start;
    while pkt_start >= max_back_pos {
      // `pkt_start + p_len <= fsize` (= `data.len()`) and `tc_len <= p_len`
      // prove the slice is in range; the checked `.get` keeps the deny.
      if let Some(packet) = self
        .data
        .get(pkt_start + self.probe.tc_len..pkt_start + p_len)
      {
        // M2TS.pm:707-708 — a bad sync byte ends the backscan silently (no
        // `M2TS synchronization error` warning while `defined $backScan`).
        if packet.first().copied() != Some(SYNC_BYTE) {
          break;
        }
        if let Some(pcr) = packet_pcr(packet) {
          self.end_time = Some(pcr); // M2TS.pm:683 `last if defined $endTime`.
          break;
        }
      }
      // Step to the previous packet (M2TS.pm:684).
      match pkt_start.checked_sub(p_len) {
        Some(prev) => pkt_start = prev,
        None => break,
      }
    }

    // M2TS.pm:988 `$endTime = $fwdTime unless defined $endTime` — fall back
    // to the last forward PCR when the (bounded) backscan found none.
    if self.end_time.is_none() {
      self.end_time = fwd_time;
    }
  }

  /// One 188-byte TS packet (M2TS.pm:702-984).
  fn process_packet(&mut self, packet: &'a [u8]) {
    // Decode 4-byte prefix (M2TS.pm:705-718). A real TS packet is 188 bytes;
    // the checked `.get(..4)` keeps the deny (Perl's `unpack("x${pos}N")` on a
    // short buffer yields undef — we simply skip such a runt packet). The
    // length-4 slice → array conversion never fails (`unwrap_or_default` is
    // the codebase idiom for an infallible `try_into`).
    let Some(head) = packet.get(..4) else {
      return;
    };
    let prefix = u32::from_be_bytes(head.try_into().unwrap_or_default());
    let payload_unit_start = (prefix & 0x0040_0000) != 0;
    let pid = u16::try_from((prefix & 0x001f_ff00) >> 8).expect("13-bit PID fits in u16");
    let adaptation = (prefix & 0x0000_0020) != 0;
    let payload = (prefix & 0x0000_0010) != 0;

    // M2TS.pm:730-748 — adaptation field. Hold the cursor at offset 4 then
    // advance by `(1 + adaptation_field_length)`. Decode PCR if present
    // (flags bit 0x10).
    let mut pos = 4usize;
    if adaptation {
      // The adaptation_field_length byte itself (M2TS.pm:732).
      let Some(&len_byte) = packet.get(pos) else {
        return;
      };
      let len = len_byte as usize;
      pos += 1;
      let af_end = pos + len;
      if af_end > packet.len() {
        // M2TS.pm:733 `$pos + $len > $pEnd and $et->Warn('Invalid adaptation
        // field length'), last` — record the warning and STOP the walk (the
        // Perl `last` terminates the whole packet loop), Codex finding #9.
        self.warnings.push(crate::diagnostics::Diagnostic::warn(
          "Invalid adaptation field length",
        ));
        self.stop_walk = true;
        return;
      }
      // PCR (M2TS.pm:735-746) — `$endTime` on every PCR; `$startTime` on the
      // first. The 4-byte `$pos` offset of the adaptation flags byte is
      // exactly the start of `packet[5..]` here (`pos` already stepped past
      // the length byte).
      if let Some(new_end) = decode_pcr(packet, pos, len) {
        self.end_time = Some(new_end);
        if self.start_time.is_none() {
          self.start_time = Some(new_end);
        }
      }
      pos = af_end;
    }

    // M2TS.pm:752 — all done if no payload.
    if !payload {
      return;
    }

    // Dispatch.
    if pid == PID_PAT || self.pmt_pids.contains(&pid) {
      // PAT / PMT path (M2TS.pm:755-895).
      self.process_psi(pid, payload_unit_start, packet, pos);
    } else if !self.did_defined(pid) {
      // Elementary stream path (M2TS.pm:897 `elsif (not defined $didPID{$pid})`
      // — DEFINEDNESS, so a `SeededFalse` reserved PID is also skipped here).
      self.process_es(pid, payload_unit_start, packet, pos);
    }

    // M2TS.pm:979-984 — once a section was parsed for `pid`, drop it from
    // `needPID`. We do this at the end of `process_psi` itself.
  }

  /// PAT / PMT section processing (M2TS.pm:755-895).
  fn process_psi(&mut self, pid: u16, payload_unit_start: bool, packet: &[u8], mut pos: usize) {
    // M2TS.pm:759-781 — section reassembly. If this is the start of a
    // section, skip the pointer-field byte; otherwise accumulate into
    // `section[pid]` until `sectLen[pid]` bytes have been gathered.
    let section_buf: Vec<u8>;
    if payload_unit_start {
      let Some(&pointer_byte) = packet.get(pos) else {
        // M2TS.pm:762-764 — `Get8u(\$buff,$pos)` reads 0 off the end, then
        // `$pos += 1 + 0` makes `$pos >= $pEnd` ⇒ `Warn('Bad pointer field'),
        // last`. Record + stop the walk (Codex finding #9).
        self
          .warnings
          .push(crate::diagnostics::Diagnostic::warn("Bad pointer field"));
        self.stop_walk = true;
        return;
      };
      let pointer = pointer_byte as usize;
      pos += 1 + pointer;
      // M2TS.pm:764 `$pos >= $pEnd and $et->Warn('Bad pointer field'), last` —
      // the check is `>=`, so a pointer landing EXACTLY at packet end fires
      // too. `packet.get(pos..)` would SUCCEED for `pos == packet.len()` (an
      // empty slice) and fall through to the section-header guard, emitting the
      // WRONG "Truncated payload" warning (Codex R2 finding B). The explicit
      // `pos >= packet.len()` test mirrors Perl's `>=` and also covers the
      // `pos > packet.len()` case the slice would otherwise reject.
      if pos >= packet.len() {
        self
          .warnings
          .push(crate::diagnostics::Diagnostic::warn("Bad pointer field"));
        self.stop_walk = true;
        return;
      }
      // M2TS.pm:765-766 — `$buf2 = substr($buff, $pEnd-$pLen, $pLen)` keeps the
      // WHOLE packet payload (length `$pLen` = 188 + timecode) as the section
      // buffer, then `$pos -= $pEnd - $pLen` rebases `$pos` to be RELATIVE to
      // `$buf2`'s start. Bundled does NOT slice at the post-pointer offset, so
      // `$slen = length($buf2) = $pLen` stays the FULL packet length and `$pos`
      // stays nonzero. Slicing + resetting `pos = 0` (the old code) made
      // `slen = packet.len() - post_pointer`, diverging from bundled on the
      // section-length-relative gates (M2TS.pm:799 `$slen < $section_length+3`
      // and the PMT `$pos + k > $slen` bounds), Codex R3-B.
      //
      // Rust's `packet` is the 188-byte TS packet with the `tc_len` timecode
      // ALREADY STRIPPED (the prefix-walk slices `[cursor+tc_len, cursor+p_len)`)
      // and `pos` entered WITHOUT the timecode offset (it started at 4, not
      // `tc_len+4`). Bundled's `$buf2` instead INCLUDES the timecode at its
      // front (`$buf2[0..tc_len]` = timecode, `$buf2[tc_len..]` = TS packet) and
      // its rebased `$pos = tc_len + 4 + adapt + 1 + pointer`. To mirror bundled
      // EXACTLY — so both the coordinate gates AND the absolute `slen` in the
      // `slen < section_length+3` gate match — we reconstruct that frame: prepend
      // `tc_len` bytes (their values are irrelevant — `$pos >= tc_len+5` so
      // bundled never reads `$buf2[0..tc_len]`) and shift `pos` by `tc_len`.
      // Then `slen = tc_len + 188 = $pLen` and every `pos`/`slen` gate is
      // byte-for-byte bundled's.
      let tc_len = self.probe.tc_len;
      let mut buf2 = Vec::with_capacity(tc_len + packet.len());
      buf2.resize(tc_len, 0); // unread timecode slot (M2TS.pm:765 `$pEnd-$pLen`)
      buf2.extend_from_slice(packet);
      section_buf = buf2;
      pos += tc_len; // rebase to buf2 origin (the timecode start), matching `$pos`
    } else {
      let Some(want) = self.section_len.get(&pid).copied() else {
        return; // M2TS.pm:769 `next unless $sectLen{$pid}`.
      };
      let acc = self.section.entry(pid).or_default();
      let more = want.saturating_sub(acc.len());
      // `pos <= packet.len()` here (set from the prefix walk), so the slice is
      // in range; `size` is clamped to the remaining bytes.
      let avail = packet.get(pos..).map_or(0, <[u8]>::len);
      let size = avail.min(more);
      if let Some(chunk) = packet.get(pos..pos + size) {
        acc.extend_from_slice(chunk);
      }
      if size < more {
        return; // not yet complete
      }
      section_buf = std::mem::take(acc);
      self.section.remove(&pid);
      self.section_len.remove(&pid);
      pos = 0;
    }
    let slen = section_buf.len();

    // M2TS.pm:783-798 — section header validation. The `pos + 8 > slen` guard
    // proves every fixed `pos + k` read (k < 8) below is in range; the checked
    // forms (`.get` / `try_into().unwrap_or_default()`) keep the deny.
    if pos + 8 > slen {
      // M2TS.pm:783 `$pos + 8 > $slen and $et->Warn('Truncated payload'), last`.
      self
        .warnings
        .push(crate::diagnostics::Diagnostic::warn("Truncated payload"));
      self.stop_walk = true;
      return;
    }
    let table_id = section_buf.get(pos).copied().unwrap_or_default();
    let expected = if pid != 0 { TABLE_ID_PMT } else { TABLE_ID_PAT };
    if table_id != expected {
      // M2TS.pm:788-793 — `unless ($table_id == $expectedID) { delete
      // $needPID{$pid}; $didPID{$pid} = 1; next }` — SILENT (no warn), and a
      // `next` (not `last`), so the walk continues. Mark done, no warning.
      self.mark_done(pid);
      return;
    }
    // Section syntax indicator (M2TS.pm:795-796). `$name` is the `%tableID`
    // string for the (already-validated) table_id.
    let sect_byte = section_buf.get(pos + 1).copied().unwrap_or_default();
    if (sect_byte & 0xc0) != 0x80 {
      // M2TS.pm:796 `$section_syntax_indicator == 0x80 or $et->Warn("Bad
      // $name"), last`.
      self
        .warnings
        .push(crate::diagnostics::Diagnostic::warn(format!(
          "Bad {}",
          table_name(table_id)
        )));
      self.stop_walk = true;
      return;
    }
    let section_length = u16::from_be_bytes(
      section_buf
        .get(pos + 1..pos + 3)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default(),
    ) as usize
      & 0x0fff;
    if section_length > 1021 {
      // M2TS.pm:798 `$section_length > 1021 and $et->Warn("Invalid $name
      // length"), last`.
      self
        .warnings
        .push(crate::diagnostics::Diagnostic::warn(format!(
          "Invalid {} length",
          table_name(table_id)
        )));
      self.stop_walk = true;
      return;
    }
    if slen < section_length + 3 {
      // M2TS.pm:799-803 — buffer the partial section (`pos < slen` ⇒ in range).
      if let Some(partial) = section_buf.get(pos..) {
        self.section.insert(pid, partial.to_vec());
      }
      self.section_len.insert(pid, section_length + 3);
      return;
    }
    let program_number = u16::from_be_bytes(
      section_buf
        .get(pos + 3..pos + 5)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default(),
    );
    // M2TS.pm:815 `my $end = $pos + $section_length + 3 - 4` (drop the 4-byte
    // CRC). Perl computes a SIGNED value: a tiny section (`section_length == 0`
    // can still pass the guards above — byte `pos+1` = 0x80 sets the syntax
    // indicator AND a zero `section_length` low nibble) makes `$end` NEGATIVE,
    // and the row loops `while ($pos <= $end - 4/5)` simply never run. The
    // unsigned `pos + section_length + 3 - 4` would UNDERFLOW (debug panic /
    // release wrap → runaway reads), so we keep `end` SIGNED (Codex finding #1).
    let end: isize = pos as isize + section_length as isize + 3 - 4;
    pos += 8;

    if pid == PID_PAT {
      // M2TS.pm:817-828 — Program Association Table. `pos` is RELATIVE to the
      // section buffer (0 after continuation-reassembly, or the post-pointer
      // offset `tc_len + 4 + adapt + 1 + pointer` for a payload-unit-start
      // packet — Codex R3-B) and `slen` is the FULL packet length (`$pLen`),
      // exactly as bundled. The loop reads at `pos + 2 .. pos + 4` while
      // `pos + 4 <= end` (`end = pos + section_length + 3 - 4`); since a large
      // `pos` (a big pointer field) can push a read past `slen`, the reads use
      // checked `.get(...).unwrap_or_default()` ⇒ a beyond-buffer byte yields 0,
      // matching Perl's beyond-`$buf2` Get16u-as-0. A negative `end` (tiny
      // section) means the loop never runs (faithful to Perl).
      while pos as isize + 4 <= end {
        let pmt_pid = u16::from_be_bytes(
          section_buf
            .get(pos + 2..pos + 4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or_default(),
        ) & 0x1fff;
        if !self.pmt_pids.contains(&pmt_pid) {
          self.pmt_pids.push(pmt_pid);
        }
        // M2TS.pm:824 `$pidName{$program_map_PID} = $str` — name the PMT PID
        // (so a later PMT row whose elementary PID coincides with it is treated
        // as already-named, M2TS.pm:861).
        self.pid_named.insert(pmt_pid);
        // M2TS.pm:825 `$needPID{$program_map_PID} = 1 unless
        // $didPID{$program_map_PID}` — TRUTHINESS (`did_done`): a PAT that
        // routes a program to reserved PID 1/2/0x1fff (`SeededFalse`) still
        // seeds it as a need (`add_need` re-checks the same truthy gate).
        if !self.did_done(pmt_pid) {
          self.add_need(pmt_pid, NeedKind::Hunting);
        }
        pos += 4;
      }
    } else {
      // M2TS.pm:830-893 — Program Map Table.
      if pos + 4 > slen {
        // M2TS.pm:831 `$pos + 4 > $slen and $et->Warn('Truncated PMT'), last`.
        self
          .warnings
          .push(crate::diagnostics::Diagnostic::warn("Truncated PMT"));
        self.stop_walk = true;
        return;
      }
      // M2TS.pm:832-835 — `$pcr_pid = Get16u(pos) & 0x1fff`; name it
      // (`$pidName{$pcr_pid} = "Program N Clock Reference"`). Membership gates
      // the elementary-PID StreamType emission (M2TS.pm:861).
      let pcr_pid = u16::from_be_bytes(
        section_buf
          .get(pos..pos + 2)
          .and_then(|s| s.try_into().ok())
          .unwrap_or_default(),
      ) & 0x1fff;
      self.pid_named.insert(pcr_pid);
      let program_info_length = u16::from_be_bytes(
        section_buf
          .get(pos + 2..pos + 4)
          .and_then(|s| s.try_into().ok())
          .unwrap_or_default(),
      ) as usize
        & 0x0fff;
      pos += 4;
      if pos + program_info_length > slen {
        // M2TS.pm:838 `$pos + $program_info_length > $slen and
        // $et->Warn('Truncated program info'), last`.
        self.warnings.push(crate::diagnostics::Diagnostic::warn(
          "Truncated program info",
        ));
        self.stop_walk = true;
        return;
      }
      pos += program_info_length; // skip program-info descriptors
      let _ = program_number;

      // M2TS.pm:851-893 — elementary-stream loop. `pos` is RELATIVE (post-pointer
      // for a start packet, Codex R3-B) and `slen` is the FULL packet length;
      // the 5-byte ES header is read at `pos .. pos + 5` while `pos + 5 <= end`
      // (`end = pos + section_length + 3 - 4`). A large `pos` (big pointer field)
      // can push a read past `slen`, so the checked `.get(...).unwrap_or_default()`
      // forms yield 0 there, matching Perl's beyond-`$buf2` Get-as-0. `end` is
      // signed (a tiny/negative section never enters the loop — Codex finding #1).
      while pos as isize + 5 <= end {
        let stream_type = section_buf.get(pos).copied().unwrap_or_default();
        let elementary_pid = u16::from_be_bytes(
          section_buf
            .get(pos + 1..pos + 3)
            .and_then(|s| s.try_into().ok())
            .unwrap_or_default(),
        ) & 0x1fff;
        let es_info_length = u16::from_be_bytes(
          section_buf
            .get(pos + 3..pos + 5)
            .and_then(|s| s.try_into().ok())
            .unwrap_or_default(),
        ) as usize
          & 0x0fff;
        pos += 5;
        if pos + es_info_length > slen {
          // M2TS.pm:871 `$pos + $es_info_length > $slen and $et->Warn('Truncated
          // ES info'), $pos = $end, last` — this `last` exits the ES `while`
          // loop ONLY (not the packet loop), so warn + `break`, no `stop_walk`.
          self
            .warnings
            .push(crate::diagnostics::Diagnostic::warn("Truncated ES info"));
          break;
        }
        // M2TS.pm:860-866 — emit Video/Audio StreamType and mark elementary
        // PIDs we want to parse. The gate is `unless ($pidName{$elementary_pid})`
        // (M2TS.pm:861) — i.e. emit the StreamType for every elementary PID NOT
        // YET named; `$pidName{$elementary_pid}` is set just AFTER (M2TS.pm:868),
        // so within one PMT each distinct PID emits once, and the tag (a normal
        // last-wins `HandleTag`) resolves to the LAST newly-seen Audio/Video PID
        // (Codex finding #2 — was incorrectly first-wins via `is_none()`).
        let already_named = self.pid_named.contains(&elementary_pid);
        if is_video_stream_type(stream_type) {
          if !already_named {
            self.video_stream_type = Some(stream_type);
          }
          // M2TS.pm:865 `$needPID{$elementary_pid} = 1 unless
          // $didPID{$elementary_pid}` — TRUTHINESS (`did_done`).
          if !self.did_done(elementary_pid) {
            self.add_need(elementary_pid, NeedKind::Hunting);
          }
        } else if is_audio_stream_type(stream_type) {
          if !already_named {
            self.audio_stream_type = Some(stream_type);
          }
          // M2TS.pm:865 (same truthy gate as the video row).
          if !self.did_done(elementary_pid) {
            self.add_need(elementary_pid, NeedKind::Hunting);
          }
        }
        // M2TS.pm:868-869 — `$pidName{$elementary_pid} = $str` (name it) +
        // `$pidType{$elementary_pid} = $stream_type`.
        self.pid_named.insert(elementary_pid);
        self
          .pid_state
          .entry(elementary_pid)
          .or_default()
          .stream_type = Some(stream_type);

        // M2TS.pm:873-891 — elementary stream descriptors. `pos +
        // es_info_length <= slen` (checked above) plus the `j + … <=
        // es_info_length` loop bounds prove `pos + j + desc_len <= slen`;
        // checked forms keep the deny.
        //
        // M2TS.pm:886 `unless ($didPID{$pid})` — `$pid` is the PMT's own PID
        // (the section PID), NOT the elementary PID. This is TRUTHINESS, so a
        // FIRST PMT carried on a `SeededFalse` reserved PID (1/2/0x1fff) STILL
        // decodes — `did_done(pid)` is false for `SeededFalse` (Codex R2 finding
        // A; using definedness `did_defined` here would wrongly suppress it).
        // EVERY 0x81 descriptor in the first PMT decodes (its setters overwrite
        // ⇒ last-wins, Codex finding #3); a REPEATED PMT (after `mark_done(pid)`
        // ⇒ `Done`) does not revive decoding. `did_done(pid)` is false
        // throughout this first parse (`mark_done(pid)` runs at the end).
        let pmt_pid_done = self.did_done(pid);
        let mut j = 0usize;
        while j + 2 <= es_info_length {
          let desc_tag = section_buf.get(pos + j).copied().unwrap_or_default();
          let desc_len = section_buf.get(pos + j + 1).copied().unwrap_or_default() as usize;
          j += 2;
          if j + desc_len > es_info_length {
            break;
          }
          if !pmt_pid_done && desc_tag == 0x81 {
            if let Some(desc) = section_buf.get(pos + j..pos + j + desc_len) {
              self.decode_ac3_descriptor(desc);
            }
          }
          j += desc_len;
        }
        pos += es_info_length;
      }
    }

    self.mark_done(pid);
  }

  /// AC-3 stream descriptor (M2TS.pm:269-280).
  fn decode_ac3_descriptor(&mut self, desc: &[u8]) {
    // M2TS.pm:272 `return if length $$dataPt < 3`; the `<3` guard proves the
    // `[1]`/`[2]` reads are in range, so the checked `.get`s never miss.
    let (Some(&b1), Some(&b2)) = (desc.get(1), desc.get(2)) else {
      return;
    };
    self.ac3_audio_bitrate = Some(b1 >> 2);
    self.ac3_surround_mode = Some(b1 & 0x03);
    self.ac3_audio_channels = Some((b2 >> 1) & 0x0f);
  }

  /// Elementary stream PES processing (M2TS.pm:897-984).
  fn process_es(&mut self, pid: u16, payload_unit_start: bool, packet: &'a [u8], mut pos: usize) {
    let stream_type = self.pid_state.get(&pid).and_then(|s| s.stream_type);

    if payload_unit_start {
      // M2TS.pm:900-914 — flush any previously-accumulated payload.
      let prev = self.pes.remove(&pid).map(|p| p.data);
      if let Some(prev_data) = prev {
        // M2TS.pm:903-913. `unless ($more)` is Perl-truthy, so ONLY a `0`
        // (Done) marks the PID done; a `-1` (Unknown — PMT not seen yet) or
        // a `1` (More) keeps it needed via `$needPID{$pid} = -1`. Collapsing
        // Unknown to "done" here would skip a real elementary stream forever
        // once the PMT finally arrives (the PES-before-PMT bug).
        let outcome = self.parse_pid(pid, stream_type, &prev_data);
        if !outcome.wants_more() {
          self.mark_done(pid);
          // M2TS.pm:909-911 — `next` after marking done.
          return;
        }
        self.add_need(pid, NeedKind::WantMore);
      }

      // M2TS.pm:916-924 — check for PES header. The 6-byte read is guarded by
      // `.get(pos..pos + 6)` (Perl's `next if $pos + 6 > $pEnd`); the 6-byte
      // slice → array conversions are infallible.
      let Some(pes_hdr) = packet.get(pos..pos + 6) else {
        return;
      };
      let start_code = u32::from_be_bytes(
        pes_hdr
          .get(0..4)
          .and_then(|s| s.try_into().ok())
          .unwrap_or_default(),
      );
      if (start_code & 0xffff_ff00) != 0x0000_0100 {
        return; // M2TS.pm:918 `next unless ($start_code & 0xffffff00) == 0x100`.
      }
      let stream_id = (start_code & 0xff) as u8;
      let pes_packet_length = u16::from_be_bytes(
        pes_hdr
          .get(4..6)
          .and_then(|s| s.try_into().ok())
          .unwrap_or_default(),
      ) as usize;
      pos += 6;

      // M2TS.pm:926-935 — PES syntax + header skip.
      if !is_no_syntax(stream_id) {
        // `pos + 3 > packet.len()` ⇒ M2TS.pm:927 `next if $pos + 3 > $pEnd`.
        let Some(syntax_hdr) = packet.get(pos..pos + 3) else {
          return;
        };
        let syntax = syntax_hdr.first().copied().unwrap_or_default() & 0xc0;
        if syntax != 0x80 {
          // M2TS.pm:930 `$syntax == 0x80 or $et->Warn('Bad PES syntax'),
          // next` — record the warning, but `next` (skip THIS packet) is NOT
          // `last`, so the walk continues (no `stop_walk`), Codex finding #9.
          self
            .warnings
            .push(crate::diagnostics::Diagnostic::warn("Bad PES syntax"));
          return;
        }
        let pes_header_data_length = syntax_hdr.get(2).copied().unwrap_or_default() as usize;
        pos += 3 + pes_header_data_length;
        if pos >= packet.len() {
          return;
        }
      }
      // `pos <= packet.len()` here (the guards above ensure it); the checked
      // slice yields the remaining payload (possibly empty).
      let Some(payload) = packet.get(pos..) else {
        return;
      };
      let acc = self.pes.entry(pid).or_default();
      acc.data.clear();
      acc.data.extend_from_slice(payload);
      acc.from_start = true;
      // M2TS.pm:940-944 — save the PES packet length (- 8 PES-extension
      // bytes; bundled comment "(where are the 8 extra bytes? - PH)").
      if pes_packet_length > 8 {
        acc.pack_len = Some(pes_packet_length - 8);
      } else {
        acc.pack_len = None;
      }
    } else {
      // M2TS.pm:945-953 — continuation.
      let acc = match self.pes.get_mut(&pid) {
        Some(a) => a,
        None => return, // M2TS.pm:947 `next unless $gpsPID{$pid}` — we don't track those.
      };
      // `pos <= packet.len()` (from the prefix walk) ⇒ the checked slice is in
      // range (possibly empty); a `None` would simply append nothing.
      if let Some(tail) = packet.get(pos..) {
        acc.data.extend_from_slice(tail);
      }
    }

    // M2TS.pm:954-976 — dispatch when enough has accumulated.
    let acc = self.pes.get(&pid).expect("just inserted");
    let save_len = match stream_type {
      None | Some(0x1b) => SAVE_LEN_LARGE, // unknown or H.264
      Some(0x15) => {
        // Packetized metadata — bounded by pack_len when known.
        match acc.pack_len {
          Some(n) if n < SAVE_LEN_LARGE => n,
          _ => SAVE_LEN_LARGE,
        }
      }
      _ => SAVE_LEN_SMALL,
    };
    if acc.data.len() < save_len {
      return;
    }
    let from_start = acc.from_start;
    let acc = self.pes.remove(&pid).expect("just inserted");
    let outcome = self.parse_pid(pid, stream_type, &acc.data);
    // M2TS.pm:968 `next if $more < 0` — the PMT hasn't identified this PID
    // yet, so KEEP the accumulator in flight (bundled does NOT `delete
    // $data{$pid}` here) and leave `needPID` untouched. The stream stays
    // eligible to be parsed once the PMT arrives — never marked done.
    if outcome == ParseOutcome::Unknown {
      self.pes.insert(pid, acc);
      return;
    }
    // M2TS.pm:970 `$more = 1 if not $more and not $fromStart{$pid}` — if we
    // parsed nothing useful and may have missed the PES start, keep going.
    let more = outcome.wants_more() || !from_start;
    if more {
      self.add_need(pid, NeedKind::WantMore);
    } else {
      self.mark_done(pid);
    }
  }

  /// `ParsePID` dispatch (M2TS.pm:283-575). Tri-state return (see
  /// [`ParseOutcome`]).
  fn parse_pid(&mut self, pid: u16, stream_type: Option<u8>, payload: &[u8]) -> ParseOutcome {
    let Some(t) = stream_type else {
      // M2TS.pm:292 `return -1 unless defined $type` — the PMT hasn't
      // identified this PID yet; keep waiting (do NOT mark it done).
      return ParseOutcome::Unknown;
    };
    match t {
      // M2TS.pm:300-303 — MPEG-1/2 Video. `ParseMPEGAudioVideo` scans the
      // ≤256-byte PES payload for the `\0\0\x01\xb3` sequence-header start code
      // and bit-extracts the `%MPEG::Video` tags (`ImageWidth`/`Height`/
      // `AspectRatio`/`FrameRate`/`VideoBitrate`, MPEG.pm:258-313) into the
      // typed [`crate::formats::mpeg::VideoMeta`]. `HandleTag` is last-wins, so a
      // later valid sequence header overwrites (the inner `if let Some`); a PES
      // with no valid header leaves the prior decode intact. Bundled `$more`
      // stays 0 (`ParseMPEGAudioVideo` never sets it).
      0x01 | 0x02 => {
        if let Some(v) = crate::formats::mpeg::parse_mpeg_audio_video(payload) {
          self.mpeg_video = Some(v);
        }
        ParseOutcome::Done
      }
      // M2TS.pm:304-307 — MPEG-1/2 Audio (`MPEG::ParseMPEGAudio`). Deferred:
      // the embedded MPEG-audio-in-PES decode produces no tags for the camera/
      // dashcam M2TS references (which carry AC-3 / AAC audio on 0x81/0x0f, not
      // MPEG-1/2 audio on 0x03/0x04). Filed as the MPEG-audio-in-PES follow-up.
      0x03 | 0x04 => ParseOutcome::Done,
      // M2TS.pm:342-351 — H.264.
      0x1b => {
        let prev = self.h264.take();
        // `parse_borrowed_stateful` parses ONE frame while carrying the per-FILE
        // `GotNAL06`/`GotNAL07` latches (H264.pm:1079/1093) across calls, so a
        // SECOND frame/PID does NOT re-emit an SPS already parsed (Codex finding
        // #6) — without it a stateless re-parse would re-add `ImageWidth`/
        // `ImageHeight` and last-wins-clobber the FIRST frame's SPS dimensions.
        // The result is fully owned (the only `'a`-bearing field is a phantom —
        // see `H264Meta::into_rebound`); re-stamp the phantom to the M2TS Meta's
        // `'a` so it can live on the M2TS [`Meta<'a>`].
        let new_h = crate::formats::h264::parse_borrowed_stateful(
          payload,
          &mut self.h264_frame_state,
          self.extract_embedded,
        )
        .map(crate::formats::h264::H264Meta::into_rebound);
        // H264.pm — any `$et->Warn` raised INSIDE `ParseH264Video`/`ProcessSEI`
        // (the MDPM out-of-sequence H264.pm:989 / forbidden-bit H264.pm:1058)
        // fires AT THIS WALK POSITION, before the M2TS minor warning below
        // (M2TS.pm:350). Capture THIS frame's NEW warnings into the walk-ordered
        // accumulator so the document `ExifTool:Warning` first-wins survivor is
        // faithful (Codex finding #9). `merge_h264` would also carry them on the
        // merged Meta, but capturing per-frame here keeps true walk order.
        if let Some(h) = &new_h {
          for w in h.warnings() {
            self
              .warnings
              .push(crate::diagnostics::Diagnostic::warn(w.as_str()));
          }
        }
        // `ParseH264Video` return contract (H264.pm:1100-1104): it returns
        // `1` (want one more frame) ONLY when the first frame carried no
        // SEI/MDPM user data, then sets `$$et{ParsedH264}` so the second
        // call always returns `0`. `$foundUserData` for THIS frame is
        // `new_h.found_user_data()`; the per-file `ParsedH264` latch lives on
        // the walker.
        let found_user_data = new_h.as_ref().is_some_and(|h| h.found_user_data());
        let pieces = match (prev, new_h) {
          (Some(prev_h), Some(nh)) => Some(merge_h264(prev_h, nh)),
          (Some(prev_h), None) => Some(prev_h),
          (None, x) => x,
        };
        self.h264 = pieces;
        // M2TS.pm:349-351 — at no-`ee` (and `Validate` off) bundled raises
        // `$et->Warn('The ExtractEmbedded option may find more tags in the video
        // data', 7)` RIGHT HERE, at the H.264 walk position, AFTER
        // `ParseH264Video` returns. `Warn(msg, 7)` ⇒ ignorable-3 (`[minor] `) +
        // `no_count` (`0x04`); `WAS_WARNED` collapses the repeats across frames
        // to one. Push it into the walk-ordered structural corpus so the
        // document `ExifTool:Warning` priority-0 FIRST-wins survivor is faithful:
        // when a LATER structural `$et->Warn` follows (e.g. `M2TS synchronization
        // error`, M2TS.pm:708), this earlier minor warning wins, matching
        // bundled. At `-ee` bundled forces `$more = 1` INSTEAD of warning
        // (M2TS.pm:347), so gate the push on `!self.extract_embedded`. (When the
        // walk was render-mode-blind this had to live at TAG time; the
        // `-ee`-gated walk now sees the mode, so the in-walk push — faithful to
        // bundled's walk order — is restored.)
        if !self.extract_embedded {
          self.warnings.push(crate::diagnostics::Diagnostic::new(
            "The ExtractEmbedded option may find more tags in the video data".into(),
            crate::diagnostics::Severity::Warn,
            None,
            3,
            true,
          ));
        }
        // M2TS.pm:347-351 — `$more` is mode-dependent in the bundled, and the
        // walk traversal it drives is `-ee`-GATED:
        //   - `ExtractEmbedded` ON  ⇒ `$more = 1` (M2TS.pm:347) — keep parsing
        //     EVERY H.264 frame to EOF (so the forward pass never empties
        //     `%needPID` ⇒ never early-stops to the last-PCR backscan), which is
        //     how the dashcam GPS PES private stream (`type==6 $pid==0x0300`,
        //     processed via the M2TS.pm:897 ES path) gets REACHED at all — the
        //     backscan decodes NO payload (M2TS.pm:756 `not defined $backScan`).
        //   - `ExtractEmbedded` OFF ⇒ `$more` is `ParseH264Video`'s own return
        //     (one extra frame when the first had no user data) AND a `$et->Warn`
        //     fires (M2TS.pm:350) — the forward pass early-stops as soon as
        //     `%needPID` empties (NO full scan to EOF).
        //
        // The per-sample H.264 data is DECODED into `self.h264` either way (one
        // parse), but the WALK EXTENT is mode-aware exactly as the bundled
        // `$more` is: the `$more = 1` full scan (M2TS.pm:347) is itself inside
        // `if ($$et{OPTIONS}{ExtractEmbedded})`, so exifast force-`More`s ONLY at
        // `-ee` (`self.extract_embedded`). At no-`ee` it RESTORES `ParseH264Video`'s
        // own `$more` (`want_more` below) so the walk early-stops at exactly the
        // pre-LIGOGPS budget — i.e. no-`ee` output is byte-identical to the
        // pre-LIGOGPS behavior for EVERY file (a late FIRST user-data SEI lying
        // past the early-stop is NOT reached at no-`ee`, so its `H264:*` / GPS /
        // `DateTimeOriginal` tags are NOT emitted — matching ExifTool, which
        // also early-stops at no-`ee`). The `[minor] ExtractEmbedded` warning is
        // pushed above (in-walk, no-`ee` only, M2TS.pm:350).
        //
        // SCOPE — at `-ee` the full scan reaches EVERY PID (incl. the GPS 0x300
        // stream near EOF): the `-ee`-gated full scan is what makes the
        // LIGOGPSINFO PES extraction (the `type==6 $pid==0x0300` arm below)
        // reachable, AND it hands every LATER H.264 frame's PES to
        // `parse_borrowed_stateful`. The AVCHD per-frame timed MDPM (GPS +
        // DateTimeOriginal + exposure of LATER frames, the #304 domain) is now
        // processed there: `self.extract_embedded` is threaded into the H.264
        // decoder (H264.pm:1081), so a user-data SEI past the first is decoded
        // under the per-frame `Doc<N>` axis (`DOC_NUM = $$et{GotNAL06}`,
        // H264.pm:1082) instead of being suppressed by the `GotNAL06` latch. At
        // no-`ee` the latch still suppresses every later SEI (byte-identical
        // no-`ee` output), and `-ee -G1` collapses the per-frame `Doc<N>` to the
        // FIRST fix (the same first-fix-wins the LIGOGPS / mebx sources show).
        //
        // `ParseH264Video`'s own `$more` (H264.pm:1100-1104): want one more frame
        // ONLY when this frame carried no user data and we have not already
        // consumed our one extra frame (`ParsedH264`). This is the no-`ee` walk
        // extent; at `-ee` it is overridden by the force-`More` full scan.
        let want_more = !found_user_data && !self.parsed_h264;
        self.parsed_h264 = true; // H264.pm:1103 `$$et{ParsedH264} = 1`.
        if self.extract_embedded || want_more {
          ParseOutcome::More
        } else {
          ParseOutcome::Done
        }
      }
      // M2TS.pm:352-354 — AC-3 audio. `ParseAC3Audio` runs for EVERY AC-3 PID
      // parsed; its `HandleTag(AudioSampleRate => ...)` (M2TS.pm:259) is a
      // normal last-wins tag, so the LAST successfully-probed AC-3 PID survives
      // (Codex finding #4 — was first-wins via `is_none()`). The Perl regex only
      // `HandleTag`s ON a match, so a probe that finds no `0x0b 0x77` sync leaves
      // the previous value intact (hence the inner `if let Some`).
      0x81 | 0x87 | 0x91 => {
        if let Some(sr) = parse_ac3_audio_sample_rate(payload) {
          self.ac3_audio_sample_rate = Some(sr);
        }
        ParseOutcome::Done
      }
      // M2TS.pm:355-364 — packetized metadata (MISB). The PES payload (after the
      // 5-byte service header) carries a `06 0e 2b 34` SMPTE key prefix
      // (M2TS.pm:357 `/^.{5}\x06\x0e\x2b\x34/s`); `MISB::ParseMISB` then walks
      // the KLV records into [`crate::formats::misb::MisbMeta`], each packet
      // opening one `Doc<N>` (MISB.pm:398). Unlike the LIGOGPS arm, MISB is NOT
      // decode-gated on `-ee`: bundled runs `ParseMISB` whenever the walk reaches
      // this packet (M2TS.pm:357), in default OR `-ee` mode; `-ee` only governs
      // whether the walk reaches LATER packets (the `$more` below). The walk
      // reaches a `0x15` PES only when it stays alive — via an H.264 force-`More`
      // full scan, an `ExtractEmbedded > 2` whole-file scan, or (for a PES that
      // precedes its PMT) the end-of-scan in-flight flush (M2TS.pm:1009-1013),
      // where this return value is ignored.
      0x15 => {
        if crate::formats::misb::MisbMeta::has_misb_code(payload) {
          let before = self.misb_doc_counter;
          self.misb_doc_counter = self.misb.parse_packet(payload, before);
          let extracted = self.misb_doc_counter != before;
          // M2TS.pm:359-363 — `$more`: no-`ee` ⇒ 0 (only the first packet);
          // `-ee` ⇒ `ParseMISB`'s return (1 when this packet extracted a tag, so
          // the walk keeps reading subsequent `0x15` packets). exifast exposes no
          // `ExtractEmbedded > 2` level (the `%gpsPID` whole-file unroll).
          if self.extract_embedded && extracted {
            ParseOutcome::More
          } else {
            ParseOutcome::Done
          }
        } else {
          // M2TS.pm:357 false ⇒ `$more` stays 0 (not a MISB packet).
          ParseOutcome::Done
        }
      }
      // M2TS.pm:308-318 — LIGOGPSINFO dashcam GPS on `type == 6 and $pid ==
      // 0x0300`. The PES private stream (stream_id 0xbf, `%noSyntax`) carries a
      // `LIGOGPSINFO\0`-prefixed block which the bundled routes to
      // `LigoGPS::ProcessLigoGPS($et, {DataPt, DirName=>'Ligo0x0300'}, $tbl,
      // length($$dataPt)!=200)`. The `$pid == 0x0300` guard is essential — only
      // the Pruveeo-D90/«Wrong Way pass» dashcam variant lives here; a generic
      // type-6 private stream on another PID must NOT be misread (the other
      // dashcam arms — Viidure/INNOVV/$GPRMC/DOD_LS600W — need their own
      // fixtures and are left to #129). The remaining `type == 6` cases (the
      // commented-out forum16486 probe, M2TS.pm:365-371) are not ported.
      //
      // The decode is gated on `self.extract_embedded` (#307): LIGOGPSINFO is an
      // ExtractEmbedded feature — in bundled this PES is reached ONLY when the
      // `-ee` H.264 force-`More` full scan (M2TS.pm:347) keeps the walk running
      // (no-`ee` early-stops first), so the LIGOGPS decode is intrinsically
      // `-ee`-only. exifast's `Project` projection copies any decoded fix into
      // `MediaMetadata::gps` MODE-INDEPENDENTLY, so the gate must be on the
      // DECODE, not the incidental walk extent: an M2TS whose PID-0x0300 PES
      // precedes the early-stop (or that never early-stops, e.g. no PCR) would
      // otherwise decode + surface GPS at default no-`ee` parse, violating the
      // contract that this GPS is parse-time `-ee` only. At no-`ee` the arm is
      // skipped (falls to the `_` Done below) so NOTHING is decoded regardless of
      // PID position; at `-ee` it is unchanged (the Pruveeo D90 lies past the
      // early-stop, so it was already only reached at `-ee` — byte-identical).
      6 if self.extract_embedded
        && pid == LIGO_DASHCAM_PID
        && payload.starts_with(ligogps_fmt::HDR_LIGOGPSINFO_PREFIX) =>
      {
        self.parse_ligogps(payload);
        // M2TS.pm:316 `$more = 1` — keep parsing more PID-0x0300 records (every
        // subsequent PES unit carries the next timed sample). `$$et{FoundGoodGPS}
        // = 1` (M2TS.pm:315) only matters for the `$$et{FoundGoodGPS}` re-parse
        // arm of OTHER private-data records, which we don't reach.
        ParseOutcome::More
      }
      // M2TS.pm:373-573 — the `$type < 0` arms (the OTHER dashcam GPS variants:
      // Blueskysea/Viofo freeGPS, INNOVV, `$GPSINFO`, `$GPRMC`, forum11320,
      // DOD_LS600W, the `skip…LIGOGPSINFO` variant). Not reached: our `$type` is
      // always a real PMT stream type (no `-1` sentinel — that is only set when
      // ExtractEmbedded > 2 unrolls the `%gpsPID` set, which exifast doesn't
      // expose). Each needs its own real-device fixture (#129); deferred.
      _ => ParseOutcome::Done,
    }
  }

  /// LIGOGPSINFO dashcam GPS record (M2TS.pm:308-318). Decode the PES
  /// private-stream `LIGOGPSINFO\0` block via the shared
  /// [`crate::formats::ligogps::process_ligogps`] walker and stamp the new
  /// records with consecutive GLOBAL `Doc<N>` ordinals off [`Self::ligo_doc_counter`].
  ///
  /// `noFuzz` is `length($$dataPt) != 200` (M2TS.pm:314): the Pruveeo D90's
  /// 200-byte block IS fuzzed (`noFuzz == false` ⇒ the lat/lon are defuzzed by
  /// `process_ligogps`); the «Wrong Way pass» 160-byte variant is NOT
  /// (`noFuzz == true`). `ProcessLigoGPS` is called without a `LigoGPSScale`, so
  /// the default scale 1 applies (the `process_ligogps` — not
  /// `_with_scale` — entry).
  fn parse_ligogps(&mut self, payload: &[u8]) {
    let start = self.ligogps.sample_count();
    let no_fuzz = payload.len() != LIGO_UNFUZZED_LEN;
    ligogps_fmt::process_ligogps(payload, 0, &mut self.ligogps, no_fuzz);
    // LigoGPS.pm:243 `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` once per decoded record,
    // in walk order. Stamp the records this call just appended.
    self.ligo_doc_counter = self.ligogps.stamp_doc_from(start, self.ligo_doc_counter);
    // LigoGPS.pm:235/254 — the walker's own `$et->Warn('LIGOGPSINFO format error'
    // / 'LIGOGPSINFO coordinates out of range')` fires RIGHT HERE, at the
    // PID-0x0300 PES walk position, with no `SET_GROUP1='LIGO'` in effect (a
    // DOCUMENT-level warning — the QuickTime LigoGPS path treats it the same).
    // Push it into the walk-ordered [`Self::warnings`] corpus AT THIS POSITION
    // (mirroring the in-walk `[minor] ExtractEmbedded` push at M2TS.pm:350) so a
    // LATER structural / H.264 `$et->Warn` (e.g. `M2TS synchronization error`,
    // M2TS.pm:708) does NOT displace it: the document `ExifTool:Warning`
    // priority-0 FIRST-wins survivor stays this earlier LIGOGPS warning, exactly
    // bundled's `%noDups`. The `ligo_warning_pushed` latch keeps it to a SINGLE
    // emit at the FIRST bad record's position (`Diagnostic::warn` ⇒ plain
    // ignorable-0 Warn, identical shape to the QuickTime path), so repeated bad
    // PID-0x0300 records never double-count — matching the pre-existing
    // single-slot `LigoGpsMeta::warning`.
    if !self.ligo_warning_pushed
      && let Some(w) = self.ligogps.warning()
    {
      self.warnings.push(crate::diagnostics::Diagnostic::warn(w));
      self.ligo_warning_pushed = true;
    }
  }

  /// Mark `pid` as `$didPID{$pid} = 1` (M2TS.pm:791/909/975/983) — drop from
  /// the need set and record the entry as [`DidPid::Done`] (defined AND
  /// Perl-true).
  fn mark_done(&mut self, pid: u16) {
    if let Some(s) = self.pid_state.get_mut(&pid) {
      if s.need.is_some() {
        self.need_count = self.need_count.saturating_sub(1);
      }
      s.need = None;
      s.did = Some(DidPid::Done);
    } else {
      self.pid_state.insert(
        pid,
        PidState {
          did: Some(DidPid::Done),
          ..Default::default()
        },
      );
    }
  }

  /// Register `pid` as a needed stream — `$needPID{$pid} = 1` (M2TS.pm:825/865)
  /// or `-1` (M2TS.pm:913/973). The M2TS.pm:825/:865 form is gated `unless
  /// ($didPID{...})`, i.e. TRUTHINESS: a `SeededFalse` reserved PID is Perl-
  /// false, so it IS (re)added; only a [`DidPid::Done`] entry suppresses it.
  fn add_need(&mut self, pid: u16, kind: NeedKind) {
    let entry = self.pid_state.entry(pid).or_default();
    if entry.did == Some(DidPid::Done) {
      return;
    }
    if entry.need.is_none() {
      self.need_count += 1;
    }
    entry.need = Some(kind);
  }

  /// `defined $didPID{$pid}` (M2TS.pm:897) — TRUE for both a `SeededFalse`
  /// reserved PID and a `Done` PID. Gates the elementary-stream path: a defined
  /// entry (reserved OR processed) is NOT re-parsed as an ES.
  fn did_defined(&self, pid: u16) -> bool {
    self.pid_state.get(&pid).is_some_and(|s| s.did.is_some())
  }

  /// Perl truthiness of `$didPID{$pid}` (M2TS.pm:825/:865/:886) — TRUE only for
  /// a genuinely processed (`Done`) PID. A `SeededFalse` reserved PID is FALSE
  /// here, so a PMT/PAT carried on it still seeds needPID + decodes descriptors.
  fn did_done(&self, pid: u16) -> bool {
    self
      .pid_state
      .get(&pid)
      .is_some_and(|s| s.did == Some(DidPid::Done))
  }

  fn finish(self) -> Meta<'a> {
    // M2TS.pm:987-992 — `Duration = $endTime - $startTime`, kept as the RAW
    // integer 27 MHz PCR tick span. The `$val / 27000000` ValueConv (M2TS.pm:
    // 156) is deferred to emit time as a FULL-PRECISION f64 divide so `-n`
    // matches bundled `exiftool` exactly (Codex finding #5); the lossy
    // `Duration` (nanosecond-rounded) is built ONLY for the normalized
    // `Project` API, which has nanosecond resolution.
    let duration_ticks = match (self.start_time, self.end_time) {
      (Some(start), Some(end)) => Some(if start > end {
        // M2TS.pm:990 — 33-bit base wrap.
        end + 0x8000_0000u64 * 1200 - start
      } else {
        end - start
      }),
      _ => None,
    };
    // Nanosecond-resolution `Duration` for the `Project` domain layer only.
    let duration = duration_ticks.and_then(|span| {
      let nanos = (span as f64 / 27_000_000.0 * 1e9).round();
      (nanos.is_finite() && nanos >= 0.0 && nanos <= u64::MAX as f64)
        .then(|| Duration::from_nanos(nanos as u64))
    });
    let file_type = if self.probe.tc_len == 4 {
      FileTypeKind::M2ts
    } else {
      FileTypeKind::M2t
    };
    Meta {
      file_type,
      video_stream_type: self.video_stream_type,
      audio_stream_type: self.audio_stream_type,
      duration_ticks,
      duration,
      ac3_audio_bitrate: self.ac3_audio_bitrate,
      ac3_surround_mode: self.ac3_surround_mode,
      ac3_audio_channels: self.ac3_audio_channels,
      ac3_audio_sample_rate: self.ac3_audio_sample_rate,
      mpeg_video: self.mpeg_video,
      // `$$self{VALUE}{FileSize}` — the input length (ExifTool sets FileSize at
      // SetFileType). The Composite `%MPEG::Composite` `Duration` derive divides
      // by it (MPEG.pm:413); not emitted as a tag.
      file_size: self.data.len() as u64,
      h264: self.h264,
      warnings: self.warnings,
      ligogps: self.ligogps,
      misb: self.misb,
    }
  }
}

/// Combine two consecutive H.264 frame parses (M2TS.pm:342-351 +
/// H264.pm:1100-1104). Bundled parses up to two frames against ONE ExifTool
/// object whose `$$et` state is cumulative — an SPS is processed once and
/// each frame's MDPM user data is appended. exifast's H.264 parser is
/// per-call, so [`H264Meta::merge_frame`] folds the later (`new`) frame into
/// the earlier (`prev`) one with the earlier frame's entries kept first (its
/// SPS dimensions survive even when the later frame carries only the MDPM —
/// the Panasonic "SEI not in the first frame" case this extra-frame scan
/// exists for).
fn merge_h264<'a>(
  prev: crate::formats::h264::H264Meta<'a>,
  new: crate::formats::h264::H264Meta<'a>,
) -> crate::formats::h264::H264Meta<'a> {
  new.merge_frame(prev)
}

/// Decode the PCR from a TS-packet adaptation field (M2TS.pm:735-743).
///
/// `flags_pos` is the offset of the adaptation `flags` byte within `packet`
/// (i.e. one past the `adaptation_field_length` byte); `af_len` is the
/// `adaptation_field_length`. Returns the 27 MHz PCR value when the
/// `PCR_flag` (0x10) is set and `af_len > 6` (enough room for flags + the
/// 6-byte PCR), else `None`.
fn decode_pcr(packet: &[u8], flags_pos: usize, af_len: usize) -> Option<u64> {
  // M2TS.pm:735 `if ($len > 6)` — need the flags byte plus a 6-byte PCR. The
  // checked `.get(flags_pos..flags_pos + 7)` IS the `flags_pos + 7 > len` bail
  // (an out-of-range AF length yields `None`, no PCR — faithful to no read).
  if af_len <= 6 {
    return None;
  }
  let field = packet.get(flags_pos..flags_pos + 7)?;
  let flags = field.first().copied().unwrap_or_default();
  if flags & 0x10 == 0 {
    return None; // PCR_flag clear.
  }
  // M2TS.pm:739-740: 33-bit `program_clock_reference_base` + 9-bit extension.
  let pcr_base = u32::from_be_bytes(
    field
      .get(1..5)
      .and_then(|s| s.try_into().ok())
      .unwrap_or_default(),
  ) as u64;
  let pcr_ext = u16::from_be_bytes(
    field
      .get(5..7)
      .and_then(|s| s.try_into().ok())
      .unwrap_or_default(),
  ) as u64;
  // M2TS.pm:743 — exactly `300 * (2*base + (ext >> 15)) + (ext & 0x01ff)`.
  Some(300 * (2 * pcr_base + (pcr_ext >> 15)) + (pcr_ext & 0x01ff))
}

/// Standalone PCR decode for a complete TS packet (the BACKSCAN path,
/// M2TS.pm:730-746). Re-parses the 4-byte prefix to find the adaptation
/// field, then delegates to [`decode_pcr`]. Returns `None` when the packet
/// has no adaptation field, an invalid adaptation length, or no PCR.
fn packet_pcr(packet: &[u8]) -> Option<u64> {
  // The 5-byte head covers the prefix (0..4) + the adaptation-length byte (4);
  // `.get(..5)` IS the `packet.len() < 5` bail.
  let head = packet.get(..5)?;
  let prefix = u32::from_be_bytes(
    head
      .get(0..4)
      .and_then(|s| s.try_into().ok())
      .unwrap_or_default(),
  );
  // adaptation_field_exists (bit 5). M2TS.pm:716.
  if prefix & 0x0000_0020 == 0 {
    return None;
  }
  // M2TS.pm:732 — `adaptation_field_length` byte at offset 4, flags at 5.
  let af_len = head.get(4).copied().unwrap_or_default() as usize;
  // M2TS.pm:733 — `$pos + $len > $pEnd` is an invalid-length bail.
  if 5 + af_len > packet.len() {
    return None;
  }
  decode_pcr(packet, 5, af_len)
}

/// AC-3 PES payload scan — M2TS.pm:253-261.
/// Regex `\x0b\x77..(.)`, then `ord($1) >> 6` ⇒ AudioSampleRate index.
fn parse_ac3_audio_sample_rate(payload: &[u8]) -> Option<u8> {
  // Find first occurrence of `0x0b 0x77`, skip two bytes, peek the third.
  let mut i = 0;
  // The `i + 5 <= len` guard proves `i`, `i+1`, `i+4` are in range; `.get()`
  // keeps the scan free of raw indexing (clippy::indexing_slicing).
  while i + 5 <= payload.len() {
    if payload.get(i) == Some(&0x0b) && payload.get(i + 1) == Some(&0x77) {
      return payload.get(i + 4).map(|&b| b >> 6);
    }
    i += 1;
  }
  None
}

// ===========================================================================
// §7. `Taggable` — typed Meta → EmittedTag stream (golden L3)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield the M2TS / AC3 / H264 tags in bundled `perl exiftool` `FoundTag`
  /// insertion order (verified against the canonical Canon-AVCHD `M2TS.mts`):
  /// M2TS `VideoStreamType` / `AudioStreamType` / `Duration`, then the AC3
  /// descriptor block (`AudioBitrate`, `SurroundMode`, `AudioChannels`), then
  /// AC3 `AudioSampleRate`, then the nested H.264 sub-Meta's own tags (under
  /// their own family-1 groups — `H264` for the SPS / non-GPS MDPM tags, `GPS`
  /// for the MDPM GPS block, H264.pm:241-387).
  ///
  /// This is the golden-pattern parallel of the retired `serialize_tags`: the
  /// SINK changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead
  /// of `out.write_*`), while every per-tag PrintConv/ValueConv branch is
  /// preserved byte-for-byte. The H.264 sub-stream is folded in by chaining its
  /// own [`Taggable::tags`](crate::emit::Taggable::tags) — the same emission
  /// path the standalone H.264 conformance uses — so the `H264:*` / `GPS:*`
  /// entries stay identical.
  ///
  /// Group: family-0 = family-1 = `"M2TS"` for the structural tags and `"AC3"`
  /// for the AC-3 descriptor / sample-rate tags (M2TS.pm `%Image::ExifTool::
  /// M2TS::Main` GROUPS sets only `0 => 'M2TS', 1 => 'M2TS'`; the AC3 sub-table
  /// sets `0 => 'M2TS', 1 => 'AC3'`, so family-0 is `M2TS` but the `-G1`
  /// conformance key is `AC3`). Only family-1 reaches the `-G1` key; family-0
  /// is carried faithfully for the later `iter_tags`. No M2TS / AC3 table row
  /// is `Unknown => 1` ⇒ `unknown: false`.
  ///
  /// The `[minor] ExtractEmbedded` minor warning (M2TS.pm:347-350) is NOT part
  /// of this stream — the walk now knows `extract_embedded`, so it is pushed
  /// in-walk (no-`ee` only) into the structural corpus drained via
  /// [`Diagnose`](crate::diagnostics::Diagnose), matching bundled's walk-order
  /// first-wins. The
  /// LIGOGPSINFO dashcam GPS (`type == 6 and $pid == 0x0300`, M2TS.pm:308-318) is
  /// likewise emitted here through the shared QuickTime `Stream` emitter
  /// ([`crate::formats::quicktime::emit_ligogps`]), `-ee`-gated. The
  /// UNCONDITIONAL structural M2TS `$et->Warn`s and the nested H.264 `Warn`s are
  /// NOT part of this stream (`run_emission` has no warning channel); both are
  /// yielded by this `Meta`'s [`Diagnose`](crate::diagnostics::Diagnose) impl and
  /// drained by [`run_diagnostics`](crate::diagnostics::run_diagnostics).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // family-0/1 "M2TS" for the structural tags; "AC3" family-1 (family-0
    // stays "M2TS") for the AC-3 sub-table tags (see fn docs).
    let m2ts = || Group::new("M2TS", "M2TS");
    let ac3 = || Group::new("M2TS", "AC3");
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: Vec<EmittedTag> = Vec::new();

    // M2TS:VideoStreamType (M2TS.pm:141-145) — PrintHex + hash PrintConv.
    if let Some(byte) = self.video_stream_type {
      let value = if print_conv {
        TagValue::Str(print_hex_stream_type(byte).into())
      } else {
        TagValue::U64(u64::from(byte))
      };
      tags.push(EmittedTag::new(
        m2ts(),
        "VideoStreamType".into(),
        value,
        false,
      ));
    }
    // M2TS:AudioStreamType (M2TS.pm:146-150).
    if let Some(byte) = self.audio_stream_type {
      let value = if print_conv {
        TagValue::Str(print_hex_stream_type(byte).into())
      } else {
        TagValue::U64(u64::from(byte))
      };
      tags.push(EmittedTag::new(
        m2ts(),
        "AudioStreamType".into(),
        value,
        false,
      ));
    }
    // M2TS:Duration (M2TS.pm:151-158) — `ValueConv $val / 27000000` applied
    // HERE as a full-precision f64 divide on the RAW PCR tick span (Codex
    // finding #5: a 6_000_000-tick span must emit `0.222222222222222` in `-n`,
    // not a nanosecond-rounded `0.222222222`); PrintConv ConvertDuration.
    if let Some(ticks) = self.duration_ticks {
      let secs = ticks as f64 / 27_000_000.0;
      let value = if print_conv {
        TagValue::Str(convert_duration_string(secs).into())
      } else if ticks == 0 {
        // `-n` emits the post-ValueConv as a JSON number; bundled `perl
        // exiftool -n` on the canonical fixture emits `"M2TS:Duration": 0`
        // (an integer for an exact-zero value, a float otherwise).
        TagValue::U64(0)
      } else {
        TagValue::F64(secs)
      };
      tags.push(EmittedTag::new(m2ts(), "Duration".into(), value, false));
    }

    // AC3 audio sample rate / descriptor block (M2TS.pm:166-247) — emit
    // in bundled `FoundTag` order: AudioBitrate, SurroundMode,
    // AudioChannels, AudioSampleRate (the descriptor is parsed once per
    // PMT row; the sample-rate is decoded from the PES payload AFTER).
    if let Some(idx) = self.ac3_audio_bitrate {
      let value = if print_conv {
        match ac3_bitrate_value_conv(idx) {
          Some(Ac3Bitrate::Bps(bps)) => {
            TagValue::Str(convert_bitrate_string(f64::from(bps)).into())
          }
          Some(Ac3Bitrate::Max(bps)) => {
            TagValue::Str(convert_bitrate_str_string(&format!("{bps} max")).into())
          }
          // Bundled `-j` for an out-of-range index renders ConvertBitrate
          // applied to the raw integer string — a passthrough since the
          // integer alone isn't `IsFloat`'d, but `ConvertBitrate` numerics
          // route through `convert_bitrate`. Without a real fixture we keep
          // the same raw-byte numeric.
          None => TagValue::U64(u64::from(idx)),
        }
      } else {
        // `-n` emits the post-ValueConv bits/s number (or "max" string).
        match ac3_bitrate_value_conv(idx) {
          Some(Ac3Bitrate::Bps(bps)) => TagValue::U64(u64::from(bps)),
          Some(Ac3Bitrate::Max(bps)) => TagValue::Str(format!("{bps} max").into()),
          None => TagValue::U64(u64::from(idx)),
        }
      };
      tags.push(EmittedTag::new(ac3(), "AudioBitrate".into(), value, false));
    }
    if let Some(idx) = self.ac3_surround_mode {
      let value = if print_conv {
        TagValue::Str(ac3_surround_print_conv(idx).into())
      } else {
        TagValue::U64(u64::from(idx))
      };
      tags.push(EmittedTag::new(ac3(), "SurroundMode".into(), value, false));
    }
    if let Some(idx) = self.ac3_audio_channels {
      // M2TS.pm:228-247 — `AudioChannels` has `PrintConv` ONLY (no `ValueConv`),
      // so `-n` MUST emit the RAW index, not the PrintConv text (Codex finding
      // #7 — the prior code mapped idx→PrintConv→parse, which only happened to
      // be right for idx 2: idx 0 would emit "1 + 1", idx 4 "2/1", idx 8 "1"
      // instead of the raw 0/4/8). PrintConv text only in print_conv mode.
      let value = if print_conv {
        TagValue::Str(ac3_channels_print_conv(idx).into())
      } else {
        TagValue::U64(u64::from(idx))
      };
      tags.push(EmittedTag::new(ac3(), "AudioChannels".into(), value, false));
    }
    if let Some(idx) = self.ac3_audio_sample_rate {
      let value = if print_conv {
        match ac3_sample_rate_value_conv(idx) {
          Some(r) => TagValue::Str(r.to_string().into()),
          // PrintConv with an out-of-range key: bundled renders the raw
          // integer string. Hash-keyed PrintConv with no match falls
          // through to ExifTool's `PrintInverseLookup` of the raw value,
          // which stringifies it. We follow that here.
          None => TagValue::Str(idx.to_string().into()),
        }
      } else {
        TagValue::U64(u64::from(idx))
      };
      tags.push(EmittedTag::new(
        ac3(),
        "AudioSampleRate".into(),
        value,
        false,
      ));
    }

    // MPEG-1/2 video (`%MPEG::Video`, M2TS.pm:300-307 → MPEG.pm:258-313) — emit
    // in `%MPEG::Video` `ProcessFrameHeader` sort order (the `BitNN` keys sort
    // ImageWidth, ImageHeight, AspectRatio, FrameRate, VideoBitrate). Family-0 =
    // family-1 = `"MPEG"` (MPEG.pm:259 `GROUPS{2} => 'Video'` ⇒ family-0
    // defaults to the table name `"MPEG"`; the `-G1` key is `"MPEG"`).
    if let Some(v) = &self.mpeg_video {
      let mpeg = || Group::new("MPEG", "MPEG");
      // MPEG.pm:260/261 — ImageWidth / ImageHeight: no ValueConv/PrintConv,
      // raw integer in both modes.
      tags.push(EmittedTag::new(
        mpeg(),
        "ImageWidth".into(),
        TagValue::U64(u64::from(v.image_width())),
        false,
      ));
      tags.push(EmittedTag::new(
        mpeg(),
        "ImageHeight".into(),
        TagValue::U64(u64::from(v.image_height())),
        false,
      ));
      // MPEG.pm:262-295 — AspectRatio: ValueConv hash (raw idx → float) then
      // PrintConv hash (float → name). `-n` emits the ValueConv float; `-j` the
      // named string.
      let aspect = if print_conv {
        TagValue::Str(v.aspect_ratio_print().into())
      } else {
        TagValue::F64(v.aspect_ratio_value())
      };
      tags.push(EmittedTag::new(mpeg(), "AspectRatio".into(), aspect, false));
      // MPEG.pm:296-308 — FrameRate: ValueConv hash (raw idx → fps) then
      // `PrintConv => '"$val fps"'` (the ValueConv float interpolated, %.15g
      // NV stringification, e.g. `59.94 fps`).
      let frame_rate = if print_conv {
        TagValue::Str(format!("{} fps", crate::value::format_g(v.frame_rate_value(), 15)).into())
      } else {
        TagValue::F64(v.frame_rate_value())
      };
      tags.push(EmittedTag::new(
        mpeg(),
        "FrameRate".into(),
        frame_rate,
        false,
      ));
      // MPEG.pm:309-313 — VideoBitrate: `ValueConv => '$val eq 0x3ffff ?
      // "Variable" : $val * 400'`, `PrintConv => 'ConvertBitrate($val)'`. `-n`
      // emits the post-ValueConv integer (or the "Variable" string); `-j` the
      // ConvertBitrate text (or "Variable" passed through unchanged — it is not
      // `IsFloat`, so `ConvertBitrate` returns it verbatim).
      let bitrate = match v.video_bitrate() {
        crate::formats::mpeg::VideoBitrate::Variable => TagValue::Str("Variable".into()),
        crate::formats::mpeg::VideoBitrate::Bps(bps) => {
          if print_conv {
            let mut s = String::new();
            let _ = crate::formats::mpeg::write_convert_bitrate(&mut s, f64::from(bps));
            TagValue::Str(s.into())
          } else {
            TagValue::U64(u64::from(bps))
          }
        }
      };
      tags.push(EmittedTag::new(
        mpeg(),
        "VideoBitrate".into(),
        bitrate,
        false,
      ));
    }

    // H264 sub-Meta — fold in its own emission stream (the `H264:*` / `GPS:*`
    // tags under their own family-1 groups). Identical to the standalone H.264
    // conformance path.
    if let Some(h) = &self.h264 {
      tags.extend(h.tags(opts));
    }

    // LIGOGPSINFO dashcam GPS (M2TS.pm:308-318) — emitted through the SAME
    // shared QuickTime `Stream` emitter the bundled `GetTagTable('…QuickTime::
    // Stream')` routes to ([`crate::formats::quicktime::emit_ligogps`]): the
    // family-1 `LIGO` group, per-record `Doc<N>` axis under `-ee -G3`, the
    // first-wins doc collapse at `-G1`/no-`ee`, and the per-tag GPS PrintConvs
    // (lat/lon `ToDMS`, altitude `" m"`, speed/track `%.4f+0`). Gated on `-ee`
    // inside the emitter: the binary LigoGPS family surfaces ONLY under
    // ExtractEmbedded (these records live in the video PES, which the no-`ee`
    // run never extracts), so a default (no-`ee`) M2TS render emits NO `LIGO:*`
    // — matching the bundled `MPEG2_TS_pruveeo_d90.ts.json` no-`ee` golden.
    // M2TS has no `gpmd` MetaFormat track, so none of its LigoGPS records are
    // `gpmd`-dispatched; [`LigoSelect::All`] emits every record (identical to
    // the pre-split behaviour).
    if !self.ligogps.is_empty() {
      crate::formats::quicktime::emit_ligogps(
        &self.ligogps,
        opts,
        print_conv,
        crate::formats::quicktime::LigoSelect::All,
        &mut tags,
      );
    }

    // MISB (STANAG-4609 KLV) — the `0x15` packetized-metadata stream
    // (M2TS.pm:355-364). Emitted under the family-1 `MISB` group with each
    // leaf's `Doc<N>` (collapsed at `-G1`, `Doc<N>:`-prefixed at `-G3`). Unlike
    // LIGOGPS this is NOT `-ee`-gated (bundled extracts the first reached packet
    // in default mode too); the `Doc<N>` stamps were assigned at decode (walk)
    // time, so emission is a pure render.
    if !self.misb.is_empty() {
      self.misb.emit(opts, &mut tags);
    }

    tags.into_iter()
  }
}

/// PrintConv for `VideoStreamType` / `AudioStreamType` — hash lookup plus
/// `PrintHex` prefix (M2TS.pm:141-150). The bundled `PrintHex => 1` form
/// produces `"<name>"` for a hash hit and `"Unknown (0xHH)"` for a miss.
#[cfg(feature = "alloc")]
fn print_hex_stream_type(byte: u8) -> String {
  if let Some(name) = stream_type_name(byte) {
    name.to_string()
  } else {
    format!("Unknown (0x{byte:x})")
  }
}

/// `ConvertDuration($val)` → owned `String`. The retired `serialize_tags`
/// streamed the formatted text directly into the `write_fmt` sink (which built
/// a `TagValue::Str`); the golden `Taggable` builds the `TagValue::Str` value
/// up front, so this wraps the shared writer-based
/// [`crate::convert::write_convert_duration`] into a `String` — byte-identical
/// to the prior sink output.
#[cfg(feature = "alloc")]
fn convert_duration_string(secs: f64) -> String {
  let mut s = String::new();
  let _ = crate::convert::write_convert_duration(&mut s, secs);
  s
}

/// `ConvertBitrate($val)` (numeric path) → owned `String`. Wraps the shared
/// [`crate::convert::write_convert_bitrate`] (see [`convert_duration_string`]).
#[cfg(feature = "alloc")]
fn convert_bitrate_string(bitrate: f64) -> String {
  let mut s = String::new();
  let _ = crate::convert::write_convert_bitrate(&mut s, bitrate);
  s
}

/// `ConvertBitrate($val)` (string path, the `"<bps> max"` form) → owned
/// `String`. Wraps the shared [`crate::convert::write_convert_bitrate_str`]
/// (see [`convert_duration_string`]).
#[cfg(feature = "alloc")]
fn convert_bitrate_str_string(val: &str) -> String {
  let mut s = String::new();
  let _ = crate::convert::write_convert_bitrate_str(&mut s, val);
  s
}

/// AC-3 AudioBitrate ValueConv result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ac3Bitrate {
  /// Plain `bps` integer (M2TS.pm:177-201).
  Bps(u32),
  /// `bps max` string form (M2TS.pm:202-217).
  Max(u32),
}

/// `%AC3.AudioBitrate` ValueConv (M2TS.pm:177-220) — the 6-bit index → bps.
const fn ac3_bitrate_value_conv(idx: u8) -> Option<Ac3Bitrate> {
  use Ac3Bitrate::*;
  Some(match idx {
    0 => Bps(32_000),
    1 => Bps(40_000),
    2 => Bps(48_000),
    3 => Bps(56_000),
    4 => Bps(64_000),
    5 => Bps(80_000),
    6 => Bps(96_000),
    7 => Bps(112_000),
    8 => Bps(128_000),
    9 => Bps(160_000),
    10 => Bps(192_000),
    11 => Bps(224_000),
    12 => Bps(256_000),
    13 => Bps(320_000),
    14 => Bps(384_000),
    15 => Bps(448_000),
    16 => Bps(512_000),
    17 => Bps(576_000),
    18 => Bps(640_000),
    32 => Max(32_000),
    33 => Max(40_000),
    34 => Max(48_000),
    35 => Max(56_000),
    36 => Max(64_000),
    37 => Max(80_000),
    38 => Max(96_000),
    39 => Max(112_000),
    40 => Max(128_000),
    41 => Max(160_000),
    42 => Max(192_000),
    43 => Max(224_000),
    44 => Max(256_000),
    45 => Max(320_000),
    46 => Max(384_000),
    47 => Max(448_000),
    48 => Max(512_000),
    49 => Max(576_000),
    50 => Max(640_000),
    _ => return None,
  })
}

/// `%AC3.SurroundMode` PrintConv (M2TS.pm:221-227).
const fn ac3_surround_print_conv(idx: u8) -> &'static str {
  match idx {
    0 => "Not indicated",
    1 => "Not Dolby surround",
    2 => "Dolby surround",
    _ => "Unknown",
  }
}

/// `%AC3.AudioChannels` PrintConv (M2TS.pm:228-247).
const fn ac3_channels_print_conv(idx: u8) -> &'static str {
  match idx {
    0 => "1 + 1",
    1 => "1",
    2 => "2",
    3 => "3",
    4 => "2/1",
    5 => "3/1",
    6 => "2/2",
    7 => "3/2",
    8 => "1",
    9 => "2 max",
    10 => "3 max",
    11 => "4 max",
    12 => "5 max",
    13 => "6 max",
    _ => "Unknown",
  }
}

/// `%AC3.AudioSampleRate` PrintConv (M2TS.pm:170-175).
const fn ac3_sample_rate_value_conv(idx: u8) -> Option<u32> {
  match idx {
    0 => Some(48_000),
    1 => Some(44_100),
    2 => Some(32_000),
    _ => None,
  }
}

// ===========================================================================
// §8. `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project M2TS / AVCHD transport-stream metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain (the golden L2
  /// seam).
  ///
  /// M2TS is a thin transport container, so its OWN structural contributions
  /// are the program [`Duration`](crate::metadata::MediaInfo::duration) (the
  /// PCR-derived `M2TS:Duration`) and the per-program track kinds — one
  /// [`TrackKind::Video`](crate::metadata::TrackKind::Video) when the PMT
  /// carried a "Video" stream type and one
  /// [`TrackKind::Audio`](crate::metadata::TrackKind::Audio) for an "Audio"
  /// one (M2TS.pm:860-863). The richer camera facts ride on the nested H.264
  /// elementary stream: its `Make` (the AVCHD `0xe0` MakeModel MDPM record)
  /// surfaces as [`CameraInfo`](crate::metadata::CameraInfo), and its own
  /// [`Project`](crate::metadata::Project) projection (a video track) is
  /// folded in via [`MediaMetadata::merge`](crate::metadata::MediaMetadata::merge)
  /// so the elementary-stream domain is never dropped. Pixel dimensions stay
  /// in the tag stream only (H264:ImageWidth/Height) — the H.264 `Meta`
  /// exposes them as tags but not as clean domain accessors, matching that
  /// sub-port's own `project`.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::{CameraInfo, MediaMetadata, Project, TrackKind};

    let mut out = MediaMetadata::new();
    let media = out.media_mut();
    media.update_duration(self.duration);
    if self.video_stream_type.is_some() {
      media.track_kinds_mut().push(TrackKind::Video);
    }
    if self.audio_stream_type.is_some() {
      media.track_kinds_mut().push(TrackKind::Audio);
    }

    // Camera identity from the nested H.264 MakeModel record (0xe0).
    if let Some(h) = &self.h264
      && let Some(make) = h.make()
    {
      let mut camera = CameraInfo::new();
      camera.update_make(Some(make.to_string()));
      out.set_camera(camera);
    }

    // Fold in the H.264 elementary stream's own projection (the video
    // TrackKind it contributes), with M2TS's container-level facts winning.
    let mut out = match &self.h264 {
      Some(h) => out.merge(Project::project(h)),
      None => out,
    };

    // LIGOGPSINFO dashcam GPS (M2TS.pm:308-318) — the FIRST decoded fix
    // populates `MediaMetadata::gps` (lowest-tier dashcam vendor GPS, same as
    // the QuickTime LigoGPS path). This projection is mode-independent (it reads
    // whatever samples were decoded), but the DECODE itself is `-ee`-gated (the
    // PID-0x0300 arm in `parse_pid`, #307), so at no-`ee` there are NO
    // decoded samples and this surfaces nothing — regardless of where the PES
    // sat in the walk. At `-ee` the first fix flows through to the domain GPS.
    self.ligogps.project_into(&mut out);
    out
  }
}

// ===========================================================================
// §9. `Diagnose` — the golden-pattern diagnostics path (Phase B.1.5)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// Yield the STRUCTURAL M2TS `$et->Warn` corpus as
  /// [`Diagnostic`](crate::diagnostics::Diagnostic)s, in bundled WALK order —
  /// the order each UNCONDITIONAL `$et->Warn(...)` fired as `ProcessM2TS` ran the
  /// packet loop (M2TS.pm:618/708/733/764/783/796/798/831/838/930), with the
  /// per-frame H.264 sub-warnings (H264.pm:989/1058) captured AT THEIR walk
  /// positions too. [`run_diagnostics`](crate::diagnostics::run_diagnostics)
  /// resolves the document `ExifTool:Warning` first-wins (priority-0), so this
  /// true walk order is faithful (Codex finding #9).
  ///
  /// The mode-dependent `[minor] ExtractEmbedded` minor warning (M2TS.pm:347-350)
  /// IS in this drain: it is pushed at the H.264 walk position at no-`ee` only
  /// (`!extract_embedded`), so a LATER structural warning (e.g. `M2TS
  /// synchronization error`, M2TS.pm:708) does NOT displace it — exactly
  /// bundled's `%noDups` first-wins. For a clean stream (`M2TS.mts` / the
  /// Pruveeo D90 no-`ee`) it is the sole document warning.
  ///
  /// The corpus is assembled during the walk on the [`Walker`] and moved onto
  /// [`Meta`]; this impl is a pure drain. Each structural site is a plain
  /// `$et->Warn(msg)` (ignorable 0). The nested H.264 warnings are captured
  /// per-frame (NOT re-drained from the merged [`H264Meta`]) so the order is the
  /// true walk order. The `LIGOGPSINFO` walker's own out-of-range / format-error
  /// `$et->Warn` (LigoGPS.pm:235/254) is pushed IN-WALK at its PID-0x0300 PES
  /// position too (document-level, like the QuickTime LigoGPS path; latched to a
  /// single emit) so it joins the same priority-0 FIRST-wins resolution — empty
  /// for a clean decode.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    // Pure drain — the LIGOGPSINFO walker's own `$et->Warn` (`LIGOGPSINFO format
    // error` / `LIGOGPSINFO coordinates out of range`, LigoGPS.pm:235/254) is
    // ALREADY in `self.warnings` at its PID-0x0300 PES walk position (pushed
    // in-walk by `parse_ligogps`, latched to a single emit), so it takes part in
    // the same priority-0 FIRST-wins resolution as every structural / H.264
    // warning — no separate post-walk append (which would let a LATER structural
    // warning wrongly win). Empty for a clean decode (the Pruveeo D90).
    self.warnings.clone()
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// Test-builder helpers index fixed-layout buffers freely (an out-of-range
// index is a test-assertion failure, not a shipped panic), so the file-level
// `#![deny(clippy::indexing_slicing)]` is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  // -------- Packet framing detection -----------------------------------

  /// Build a minimal synthetic M2TS-style buffer: `n` packets of
  /// `payload_len`-byte content, each prefixed by either nothing
  /// (`tc_len=0`) or a 4-byte zero timecode (`tc_len=4`). The 0xff fill
  /// is inert (an idle TS packet body). The first byte after the
  /// (optional) timecode is the 0x47 sync byte.
  fn synth(n: usize, tc_len: usize) -> Vec<u8> {
    let p_len = PACKET_LEN_NO_TC + tc_len;
    let mut buf = Vec::with_capacity(n * p_len);
    for _ in 0..n {
      buf.extend(core::iter::repeat_n(0u8, tc_len));
      buf.push(SYNC_BYTE);
      // Null-packet header: PID 0x1fff, no adaptation, no payload.
      buf.push(0x1f);
      buf.push(0xff);
      buf.push(0x10);
      buf.extend(core::iter::repeat_n(0xff_u8, PACKET_LEN_NO_TC - 4));
    }
    buf
  }

  #[test]
  fn probe_detects_188_byte_packets() {
    let buf = synth(8, 0);
    let p = probe(&buf).expect("probe must accept 188-byte stream");
    assert_eq!(p.tc_len, 0);
    assert_eq!(p.start, 0);
    assert_eq!(p.packet_len(), 188);
  }

  #[test]
  fn probe_detects_192_byte_packets() {
    let buf = synth(8, 4);
    let p = probe(&buf).expect("probe must accept 192-byte stream");
    assert_eq!(p.tc_len, 4);
    assert_eq!(p.start, 0);
    assert_eq!(p.packet_len(), 192);
  }

  #[test]
  fn probe_rejects_too_short_input() {
    assert!(probe(&[0u8; 300]).is_none());
  }

  #[test]
  fn probe_rejects_no_sync_byte() {
    let buf = vec![0xffu8; 1024];
    assert!(probe(&buf).is_none());
  }

  #[test]
  fn probe_rejects_isolated_sync_byte() {
    // Single 0x47 surrounded by 0xff (no stride pattern).
    let mut buf = vec![0xffu8; 1024];
    buf[100] = SYNC_BYTE;
    assert!(probe(&buf).is_none());
  }

  // -------- Stream-type lookup -----------------------------------------

  #[test]
  fn stream_type_known_bytes() {
    assert_eq!(stream_type_name(0x1b), Some("H.264 (AVC) Video"));
    assert_eq!(stream_type_name(0x81), Some("A52/AC-3 Audio"));
    assert_eq!(stream_type_name(0x24), Some("H.265 (HEVC) Video"));
  }

  #[test]
  fn stream_type_unknown_byte() {
    assert!(stream_type_name(0xff).is_none());
    assert!(stream_type_name(0x99).is_none());
  }

  #[test]
  fn is_audio_video_classifiers() {
    assert!(is_video_stream_type(0x1b));
    assert!(is_video_stream_type(0x01));
    assert!(!is_video_stream_type(0x81));
    assert!(is_audio_stream_type(0x81));
    assert!(is_audio_stream_type(0x03));
    assert!(!is_audio_stream_type(0x1b));
  }

  // -------- AC-3 descriptor decoder ------------------------------------

  #[test]
  fn ac3_descriptor_decode() {
    // Bundled M2TS.pm:269-280 — `b[1] >> 2` ⇒ bitrate index, `b[1] & 0x03`
    // ⇒ surround mode, `(b[2] >> 1) & 0x0f` ⇒ channels. Build a desc with
    // bitrate idx 12 (256 kbps), surround 0, channels 2.
    let desc = [0x00u8, 12 << 2, 2 << 1, 0x00];
    let mut w = Walker::new(
      &[],
      Probe {
        start: 0,
        tc_len: 4,
      },
      false,
    );
    w.decode_ac3_descriptor(&desc);
    assert_eq!(w.ac3_audio_bitrate, Some(12));
    assert_eq!(w.ac3_surround_mode, Some(0));
    assert_eq!(w.ac3_audio_channels, Some(2));
  }

  #[test]
  fn ac3_descriptor_too_short() {
    let mut w = Walker::new(
      &[],
      Probe {
        start: 0,
        tc_len: 0,
      },
      false,
    );
    w.decode_ac3_descriptor(&[0, 0]);
    assert!(w.ac3_audio_bitrate.is_none());
  }

  // -------- AC-3 sample-rate PES scan ----------------------------------

  #[test]
  fn ac3_sample_rate_finds_sync() {
    // M2TS.pm:253-261 — regex `\x0b\x77..(.)`, then `ord($1) >> 6`. The
    // canonical AC-3 sample-rate byte after `0x0b 0x77 .. ..` should have
    // top 2 bits = 0 ⇒ index 0 ⇒ 48000 Hz.
    let payload = [0x00u8, 0x0b, 0x77, 0xaa, 0xbb, 0x3f, 0x00];
    assert_eq!(parse_ac3_audio_sample_rate(&payload), Some(0));
  }

  #[test]
  fn ac3_sample_rate_no_sync() {
    assert!(parse_ac3_audio_sample_rate(&[0u8; 32]).is_none());
  }

  // -------- File-type override ----------------------------------------

  #[test]
  fn file_type_override_m2ts_vs_m2t() {
    let buf192 = synth(4, 4);
    let m = parse_inner(&buf192, false).expect("must accept 192-byte stream");
    assert_eq!(m.file_type().as_file_type(), "M2TS");
    let buf188 = synth(4, 0);
    let m = parse_inner(&buf188, false).expect("must accept 188-byte stream");
    assert_eq!(m.file_type().as_file_type(), "M2T");
  }

  // -------- Real-fixture smoke (bundled t/images/M2TS.mts) -------------
  //
  // The canonical Canon AVCHD M2TS fixture lives in
  // `tests/fixtures/M2TS.mts`; the byte-exact `-j` / `-n` parity is
  // exercised in `tests/conformance.rs::m2ts_conformance`.

  // -------- Malformed-input tests -------------------------------------

  #[test]
  fn truncated_packet_buffer_yields_no_meta() {
    let buf = synth(2, 4);
    let truncated = &buf[..200];
    assert!(parse_inner(truncated, false).is_none());
  }

  #[test]
  fn bad_sync_run_yields_no_meta() {
    let mut buf = synth(4, 4);
    // Stomp every sync byte ⇒ no probe.
    for i in (4..buf.len()).step_by(192) {
      buf[i] = 0xff;
    }
    assert!(parse_inner(&buf, false).is_none());
  }

  #[test]
  fn pmt_pointing_at_nonexistent_pid_does_not_panic() {
    // A 188-byte stream whose PAT names a PMT PID that never appears.
    // Walker should run to EOF without emitting anything (no panic).
    let buf = synth(8, 0);
    let meta = parse_inner(&buf, false).expect("probe accepts pure null packets");
    assert!(meta.video_stream_type().is_none());
    assert!(meta.audio_stream_type().is_none());
    assert!(meta.h264().is_none());
  }

  /// Build a 188-byte PMT TS packet (timecode ALREADY stripped, as the
  /// prefix-walk hands to `process_psi`) whose `payload_unit_start` is set and
  /// whose pointer-field skips `pointer` padding bytes before the section. The
  /// section declares `section_length` and carries one video (0x1b) ES entry at
  /// the start of its body. `pid` is the (nonzero) PMT PID.
  ///
  /// Layout (post-pointer section start at offset `5 + pointer`): table_id 0x02,
  /// `0x80`-syntax | `section_length`, program_number 1, version, sect/last 0,
  /// pcr_pid 0x100, program_info_length 0, then ES = stream_type 0x1b /
  /// elementary_pid 0x200 / es_info_length 0. Bytes after the ES entry are 0.
  fn pmt_packet(pid: u16, pointer: u8, section_length: u16) -> Vec<u8> {
    let mut p = vec![0u8; PACKET_LEN_NO_TC];
    // 4-byte prefix: sync, payload_unit_start, PID, payload flag.
    let prefix: u32 = 0x4700_0010 | 0x0040_0000 | (u32::from(pid) << 8);
    p[0..4].copy_from_slice(&prefix.to_be_bytes());
    p[4] = pointer; // pointer_field
    let s = 5 + pointer as usize; // section start (post-pointer)
    p[s] = 0x02; // table_id (PMT)
    // section_syntax_indicator (0x80) + reserved (0x30) + 12-bit section_length.
    let sl = section_length & 0x0fff;
    p[s + 1] = 0xb0 | ((sl >> 8) as u8);
    p[s + 2] = (sl & 0xff) as u8;
    p[s + 3..s + 5].copy_from_slice(&1u16.to_be_bytes()); // program_number
    p[s + 5] = 0x01; // version / current_next
    p[s + 6] = 0x00; // section_number
    p[s + 7] = 0x00; // last_section_number
    p[s + 8..s + 10].copy_from_slice(&0xe100u16.to_be_bytes()); // pcr_pid 0x100
    p[s + 10..s + 12].copy_from_slice(&0xf000u16.to_be_bytes()); // program_info_length 0
    p[s + 12] = 0x1b; // stream_type H.264 (video)
    p[s + 13..s + 15].copy_from_slice(&0xe200u16.to_be_bytes()); // elementary_pid 0x200
    p[s + 15..s + 17].copy_from_slice(&0xf000u16.to_be_bytes()); // es_info_length 0
    p
  }

  /// R3-B regression — a payload-unit-start PSI packet with a NONZERO
  /// pointer_field and a section whose declared length fits in the FULL packet
  /// (`slen = $pLen`) but NOT in the post-pointer tail (`packet.len() -
  /// post_pointer`). Bundled M2TS.pm:765-766 keeps `$buf2` = the WHOLE packet
  /// payload and `$pos` RELATIVE, so `$slen = length($buf2) = $pLen`. The old
  /// Rust sliced at the post-pointer offset and reset `pos = 0`, shrinking
  /// `slen` and making the M2TS.pm:799 `slen < section_length + 3` gate buffer
  /// the section for (spurious) reassembly. After the fix the section must be
  /// parsed IN-PACKET (no buffering) and the ES StreamType emitted.
  #[test]
  fn psi_nonzero_pointer_parses_in_packet_not_buffered() {
    let pid = 0x0100u16;
    // tc_len = 0 (M2T): post_pointer = 5 + 5 = 10, old slen would be 188-10=178;
    // section_length+3 = 184 ∈ (178, 188] ⇒ OLD buffers, NEW (slen=188) parses.
    let packet = pmt_packet(pid, 5, 181);
    let mut w = Walker::new(
      &[],
      Probe {
        start: 0,
        tc_len: 0,
      },
      false,
    );
    w.pmt_pids.push(pid);
    // `pos = 4` mirrors the prefix-walk entry (process_packet sets pos past the
    // 4-byte prefix; this packet has no adaptation field).
    w.process_psi(pid, true, &packet, 4);
    // Parsed in-packet: the video StreamType was emitted and the elementary PID
    // recorded — NOT buffered for reassembly.
    assert_eq!(
      w.video_stream_type,
      Some(0x1b),
      "section must parse in-packet (slen = full packet length)"
    );
    assert!(
      w.pid_named.contains(&0x0200),
      "ES elementary PID must have been reached"
    );
    assert!(
      !w.section.contains_key(&pid),
      "section must NOT be buffered for reassembly"
    );
    assert!(
      !w.section_len.contains_key(&pid),
      "no partial-section length must be recorded"
    );
  }

  /// R3-B regression for the 192-byte (timecode) stride. Bundled's `$buf2`
  /// INCLUDES the `tc_len` timecode at its front, so `$slen = $pLen = 192`; the
  /// fix reconstructs that frame (prepend `tc_len`, shift `pos`). A
  /// `section_length` of 187 (`+3 = 190`) lies in (188, 192], so it parses only
  /// when `slen == 192` — catching BOTH the old post-pointer slice AND a
  /// would-be `slen == 188` (no-timecode-prepend) regression.
  #[test]
  fn psi_nonzero_pointer_uses_full_192_slen() {
    let pid = 0x0100u16;
    let packet = pmt_packet(pid, 5, 187);
    let mut w = Walker::new(
      &[],
      Probe {
        start: 0,
        tc_len: 4,
      },
      false,
    );
    w.pmt_pids.push(pid);
    w.process_psi(pid, true, &packet, 4);
    assert_eq!(
      w.video_stream_type,
      Some(0x1b),
      "section must parse in-packet with slen = 192 (= 188 + tc_len)"
    );
    assert!(w.pid_named.contains(&0x0200));
    assert!(
      !w.section.contains_key(&pid),
      "section must NOT be buffered for reassembly"
    );
    assert!(!w.section_len.contains_key(&pid));
  }

  // -------- Bitrate / surround / channel PrintConv ---------------------

  #[test]
  fn ac3_bitrate_value_conv_known() {
    assert_eq!(ac3_bitrate_value_conv(12), Some(Ac3Bitrate::Bps(256_000)));
    assert_eq!(ac3_bitrate_value_conv(50), Some(Ac3Bitrate::Max(640_000)));
    assert!(ac3_bitrate_value_conv(63).is_none());
  }

  #[test]
  fn ac3_surround_print_conv_known() {
    assert_eq!(ac3_surround_print_conv(0), "Not indicated");
    assert_eq!(ac3_surround_print_conv(1), "Not Dolby surround");
    assert_eq!(ac3_surround_print_conv(2), "Dolby surround");
  }

  #[test]
  fn ac3_channels_print_conv_known() {
    assert_eq!(ac3_channels_print_conv(2), "2");
    assert_eq!(ac3_channels_print_conv(4), "2/1");
    assert_eq!(ac3_channels_print_conv(8), "1");
  }

  #[test]
  fn ac3_sample_rate_value_conv_known() {
    assert_eq!(ac3_sample_rate_value_conv(0), Some(48_000));
    assert_eq!(ac3_sample_rate_value_conv(1), Some(44_100));
    assert_eq!(ac3_sample_rate_value_conv(2), Some(32_000));
    assert!(ac3_sample_rate_value_conv(3).is_none());
  }

  // -------- D8 accessors round-trip ------------------------------------

  #[test]
  fn meta_accessors_pass_through_synth() {
    let buf = synth(8, 4);
    let m = parse_inner(&buf, false).expect("probe");
    assert_eq!(m.file_type(), FileTypeKind::M2ts);
    assert_eq!(m.video_stream_type(), None);
    assert_eq!(m.audio_stream_type(), None);
    assert_eq!(m.duration(), None);
    assert_eq!(m.ac3_audio_bitrate(), None);
    assert!(m.h264().is_none());
  }
}
