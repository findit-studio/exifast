// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! JPEG container front-end for the Exif/GPS port — the marker walk that
//! reaches the embedded `APP1` Exif block.
//!
//! A camera JPEG is the primary camera-photo format. ExifTool extracts its
//! Make / Model / DateTime / GPS from the `APP1` segment whose payload begins
//! with the `Exif\0\0` header: that payload IS a standard TIFF block, decoded
//! by `ProcessTIFF` → `ProcessExif` (the same IFD walker a standalone `.tif`
//! uses). This module is the faithful port of the `APP1` Exif arm of
//! `Image::ExifTool::ProcessJPEG` (`ExifTool.pm:7260-7821`), narrowed to the
//! Exif dispatch.
//!
//! ## What is ported (the Exif path)
//!
//! - The JPEG container is ACCEPTED on its `SOI` marker alone. Bundled
//!   `ProcessJPEG` calls `$self->SetFileType()` at `ExifTool.pm:7304` —
//!   BEFORE the `Marker:` loop and INDEPENDENTLY of whether the `APP1` Exif
//!   arm ever runs — so a stripped / social-media / editor JPEG, or a camera
//!   JPEG with a damaged `APP1`, is still a `File:FileType == "JPEG"`. The
//!   front-end therefore ALWAYS returns an [`ExifMeta`] for a valid JPEG;
//!   Exif/GPS tags are attached only when an `APP1` Exif block parses.
//! - The marker walk from `SOI` (`\xff\xd8`): `ExifTool.pm:7287` validates
//!   `^\xff[\xd8\x4f\x01]`; the `Marker:` loop (`ExifTool.pm:7325`) reads
//!   ahead one segment at a time, stopping at `EOI` (`0xd9`) / `SOS` (`0xda`)
//!   / `SOD` (`0x93`) — `ExifTool.pm:7339-7340`.
//! - Standalone (length-less) markers: `%markerLenBytes` (`ExifTool.pm:7208-
//!   7219`). A marker NOT in that set carries a 2-byte big-endian length word
//!   (`unpack('n',$s)`, `ExifTool.pm:7361`) covering itself + the payload.
//! - The `APP1` (`0xe1`) Exif arm: `ExifTool.pm:7736-7821`. The payload is
//!   matched against `^(.{0,4})Exif\0.` (`ExifTool.pm:7739`); the 6-byte
//!   `$exifAPP1hdr = "Exif\0\0"` (`ExifTool.pm:1239`) plus 0-4 garbage bytes
//!   is stripped (`DirStart(\%dirInfo, $hdrLen, $hdrLen)`, `ExifTool.pm:7780`)
//!   and the remainder handed to `ProcessTIFF` (`ExifTool.pm:7783`) — here
//!   [`crate::exif::parse_exif_block`]. The Exif arm ends with `next`
//!   (`ExifTool.pm:7821`): the `Marker:` loop CONTINUES, so a later
//!   independent `APP1` Exif segment still contributes its tags.
//! - A bad TIFF block: `ProcessTIFF(...) or $self->Warn('Malformed APP1 EXIF
//!   segment')` (`ExifTool.pm:7783`). The failure is a non-fatal `Warn`, not a
//!   container rejection — the JPEG is still accepted and the walk continues.
//!
//! ## What is DEFERRED (a JPEG-container follow-up — see `docs/tracking.md`)
//!
//! Every other JPEG segment ExifTool understands is out of scope for the
//! Exif/GPS port and noted as a follow-up:
//! - `APP0` JFIF, `APP2` ICC_Profile / FlashPix / MPF, `APP13` Photoshop /
//!   IPTC (`ExifTool.pm:7861` `$psAPP13hdr`), `APP14` Adobe, the `COM`
//!   comment, and the `SOF` size tags (`File:ImageWidth`/`ImageHeight`/…,
//!   `ExifTool.pm:7430-7470`).
//! - Multi-segment **`APP1` XMP** (`$xmpAPP1hdr = "http://ns.adobe.com/xap/
//!   1.0/\0"`, `ExifTool.pm:1240`; `ExifTool.pm:7822` `ExtendedXMP`) — the
//!   XMP PR's concern.
//! - Multi-segment (extended) `APP1` Exif ASSEMBLY (`ExifTool.pm:7763-7776` —
//!   the `$combinedSegData` accumulator for `File contains multi-segment
//!   EXIF`). The `$combinedSegData` byte-concatenation of fragment segments is
//!   NOT ported. The front-end DOES port bundled's discriminator
//!   (`ExifTool.pm:7764-7765` — an `APP1` Exif followed by an `APP1` whose
//!   payload is `^Exif\0\0` NOT followed by a TIFF magic `MM\0\x2a`/`II\x2a\0`
//!   is multi-segment): such a chain is skipped SILENTLY (no merge, no
//!   malformed warning) so it neither mis-parses nor diverges from bundled —
//!   only the genuine *assembly* of the combined data is the deferred follow-
//!   up. Independent `APP1` Exif blocks (each a self-contained TIFF) ARE
//!   merged — see [`parse_jpeg_exif`].
//! - The FlashPix / MPF trailer scans and the preview-image trailer
//!   (`ExifTool.pm:7797-7815`).

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// the marker walk already reads ahead through `data.get(..)`; the few remaining
// raw index/slice sites (the SOI check, the `0xff` fill-run scan, the Exif-arm
// signature) each sit behind a length guard and become checked `.get()` forms.
#![deny(clippy::indexing_slicing)]

use std::{string::String, vec::Vec};

use super::ifd::{ByteOrder, get_u16};
use super::{ExifEntry, ExifMeta, MakerNote, SofInfo, parse_exif_block_with_base};

/// The 6-byte Exif `APP1` header — bundled `$exifAPP1hdr = "Exif\0\0"`
/// (`ExifTool.pm:1239`). Stripped before the TIFF block (`DirStart(…,
/// $hdrLen, $hdrLen)` with `$hdrLen = length($exifAPP1hdr)`,
/// `ExifTool.pm:7743` + `:7780`).
const EXIF_APP1_HDR: &[u8] = b"Exif\0\0";

/// `ProcessTIFF` failure on an `APP1` Exif segment — bundled `ExifTool.pm:7783`
/// `$self->ProcessTIFF(\%dirInfo) or $self->Warn('Malformed APP1 EXIF
/// segment')`. A non-fatal `Warn`, NOT a container rejection.
const MALFORMED_APP1_WARNING: &str = "Malformed APP1 EXIF segment";

/// One length-bearing JPEG segment captured during the marker walk: its
/// marker code and the file-offset range of its payload (the bytes after the
/// 2-byte length word). Standalone (length-less) markers are not captured.
///
/// `pub(super)` so the auxiliary `APP`-segment decoder
/// ([`super::jpeg_app::process_app_markers`]) can re-read the same marker walk
/// (JFIF/MPF/DJI thermal arms) the Exif arm uses.
pub(super) struct Segment {
  /// The JPEG marker code (e.g. `0xe1` for `APP1`).
  marker: u8,
  /// File offset of the segment payload's first byte (bundled `$segPos`,
  /// `ExifTool.pm:7363` — just past the 2-byte length word).
  payload_start: usize,
  /// File offset one past the segment payload's last byte.
  payload_end: usize,
}

impl Segment {
  /// The JPEG marker code (e.g. `0xe1` for `APP1`).
  #[inline]
  pub(super) const fn marker(&self) -> u8 {
    self.marker
  }
  /// File offset of the segment payload's first byte.
  #[inline]
  pub(super) const fn payload_start(&self) -> usize {
    self.payload_start
  }
  /// File offset one past the segment payload's last byte.
  #[inline]
  pub(super) const fn payload_end(&self) -> usize {
    self.payload_end
  }
}

/// Walk a JPEG file's markers and decode every independent `APP1` Exif block
/// into a single merged [`ExifMeta`].
///
/// Faithful to `ProcessJPEG` (`ExifTool.pm:7260-7821`):
///
/// - **The JPEG container is accepted on the `SOI` marker alone.** Bundled
///   `SetFileType` runs at `ExifTool.pm:7304` — before the `Marker:` loop and
///   independently of the `APP1` Exif arm — so this function returns
///   `Some(ExifMeta)` for ANY valid JPEG (`\xff\xd8` SOI). A stripped /
///   social-media / editor JPEG, or a camera JPEG with a damaged `APP1`,
///   yields an `ExifMeta` with no [`byte_order`](ExifMeta::byte_order) and no
///   IFD entries (the engine still finalizes `File:FileType == "JPEG"`).
/// - **The marker loop continues after a successful `APP1` Exif parse.** The
///   Exif arm ends with `next` (`ExifTool.pm:7821`), so a later INDEPENDENT
///   `APP1` Exif segment still contributes its tags; this merges every such
///   block (entries appended in walk order, warnings concatenated).
/// - **A bad TIFF block is a `Warn`, not a rejection** (`ExifTool.pm:7783`):
///   an `APP1` segment matching the Exif arm whose TIFF block fails to parse
///   records a [`MALFORMED_APP1_WARNING`] and the walk continues.
///
/// Returns `None` ONLY when `data` is not a JPEG at all (`ExifTool.pm:7287` —
/// no `\xff\xd8` SOI); a valid JPEG always returns `Some`.
#[must_use]
pub fn parse_jpeg_exif(data: &[u8]) -> Option<ExifMeta<'_>> {
  // The common case: the JPEG starts at file offset 0, so the embedded TIFF
  // block's file offset (its `Base`) is its in-buffer offset unmodified.
  parse_jpeg_exif_with_base(data, 0)
}

/// Walk a JPEG file's markers — like [`parse_jpeg_exif`] — when the JPEG body
/// does NOT start at file offset 0 because an unknown leading header was
/// skipped past (`ExifTool.pm:3026-3034` last-ditch JPEG/TIFF scan).
///
/// `data` is the byte slice from the `SOI` marker onward; `base_offset` is the
/// file offset at which that slice begins (Perl `$pos + $skip`, the value
/// `ExifTool.pm:3030` stores into `$dirInfo{Base}`). It is ADDED to every
/// embedded-`APP1` TIFF block's `Base` so an `IsOffset` value tag — most
/// notably `IFD1:ThumbnailOffset` — rebases to a TRUE absolute file offset:
/// bundled reads JPEG segments through a `RAF` positioned at `$pos+$skip`, so
/// its `$raf->Tell()` segment positions (`$segPos`) are already absolute and
/// `$$dirInfo{Base} = $segPos + $hdrLen` (`DirStart`, `ExifTool.pm:7780`)
/// includes the skipped bytes. `base_offset == 0` reduces this to
/// [`parse_jpeg_exif`].
///
/// Returns `None` ONLY when `data` is not a JPEG (`ExifTool.pm:7287`).
#[must_use]
pub fn parse_jpeg_exif_with_base(data: &[u8], base_offset: usize) -> Option<ExifMeta<'_>> {
  // `ExifTool.pm:7287`: `$s =~ /^\xff[\xd8\x4f\x01]/`. The Exif file dispatch
  // is for actual JPEG (`\xd8` SOI); `\x4f` (J2C) / `\x01` (EXV) reach
  // ProcessJPEG via other detection and carry no `APP1` Exif arm of interest
  // here — the camera-JPEG path needs `\xff\xd8`. A non-JPEG is the ONLY
  // `None`: a real TIFF never begins `\xff\xd8`, so the engine's JPEG branch
  // stays unambiguous. The checked `.first()`/`.get(1)` fold the `data.len() < 2`
  // guard into the byte comparison (a too-short slice yields `None != Some(_)`),
  // byte-identical to `data[0] != 0xff || data[1] != 0xd8`.
  if data.first() != Some(&0xff) || data.get(1) != Some(&0xd8) {
    return None;
  }

  // Pass 1: walk the markers and collect the length-bearing segments (a JPEG
  // carries a handful before the image data, so this `Vec` is tiny). A single
  // pass cannot decide "independent vs deferred multi-segment" for an `APP1`
  // Exif segment without seeing the NEXT segment (bundled's peek-ahead,
  // `ExifTool.pm:7764`), so the segments are materialized first.
  let segments = scan_jpeg_segments(data);

  // Pass 2: process the `APP1` Exif arm over the collected segments, merging
  // every independent block. `byte_order == None` until a TIFF block parses
  // (faithful: `File:ExifByteOrder` is `FoundTag`'d only inside
  // `DoProcessTIFF`, `ExifTool.pm:8691`).
  let mut entries: Vec<ExifEntry> = Vec::new();
  let mut warnings: Vec<String> = Vec::new();
  // Per-warning `sub Warn` ignorable level, index-aligned with `warnings`
  // (Phase C). The JPEG-level `Malformed APP1 EXIF segment` is a normal
  // warning (level 0); each merged block's own ignorable levels (e.g. the
  // excessive-count `[Minor]`) thread through `merge_exif_block`.
  let mut warnings_ignorable: Vec<u8> = Vec::new();
  let mut byte_order = None;
  // The FIRST captured `MakerNote` (0x927c) across the merged `APP1` Exif
  // blocks. A normal camera JPEG carries its MakerNote in the ExifIFD of its
  // `APP1` Exif block; preserving it here makes `ExifMeta::maker_note()` return
  // the MakerNote for JPEGs exactly as for a standalone TIFF (the seam #75+
  // consume). First-wins matches bundled keeping the PRIMARY MakerNote.
  let mut maker_note: Option<MakerNote<'_>> = None;
  // `true` while inside a deferred multi-segment (extended) EXIF chain — set
  // when bundled's discriminator (`ExifTool.pm:7764`) detects the chain START
  // and propagated across the continuation fragments (bundled keeps
  // `$combinedSegData` defined for the whole chain). Every `APP1` Exif segment
  // of the chain is skipped SILENTLY: the `$combinedSegData` byte-assembly is
  // a deferred follow-up, and skipping is what keeps the front-end from
  // mis-parsing a continuation fragment as a standalone TIFF (which would emit
  // a spurious `Malformed APP1 EXIF segment` warning bundled never raises).
  let mut in_multisegment = false;
  // File-order index of the `APP1` segment that ACTUALLY emits a MOVABLE EXIF
  // tag — the first whose `ProcessTIFF` (`parse_exif_block_with_base`) succeeds
  // AND whose [`ExifMeta::emits_movable_tag`] is `true`, i.e. its real
  // `Taggable::tags` output carries a default-visible tag in a family-0 group
  // OTHER than `File` (an `EXIF:*` IFD-walk entry OR a `MakerNotes:*` vendor
  // tag). FIRST-wins (the primary EXIF block, matching `byte_order`/
  // `maker_note`). This is the anchor a GoPro `APP6` block is ordered against.
  // It is NOT the first segment whose payload merely MATCHES the Exif arm
  // signature (a malformed / BigTIFF-skipped / deferred-multi-segment `APP1`
  // produces nothing), and it is NOT a byte-order-only `APP1` either: a
  // byte-order marker + empty IFD0 with no MakerNote parses to `Some` but emits
  // ONLY `File:ExifByteOrder` — the unconditional `File`-group prefix, not a
  // movable tag. A MakerNote-only `APP1` (an `ExifIFD` pointer + a decoded
  // vendor MakerNote, no other IFD0 entry) DOES anchor: it emits `MakerNotes:*`.
  // ExifTool then emits a GoPro `APP6` ahead of a non-effective leading `APP1`
  // BEFORE the EFFECTIVE (movable-tag-producing) EXIF block (see
  // [`attach_app6_gopro`]). Threaded out for the `quicktime`-gated GoPro
  // ordering only.
  #[cfg(feature = "quicktime")]
  let mut effective_exif_idx: Option<usize> = None;
  // The anchor is consumed ONLY by `attach_app6_gopro`, and only when a GoPro
  // `APP6` block actually attaches (`!gopro.is_empty()` there — which requires
  // at least one `GoPro\0`-prefixed `APP6` segment). [`ExifMeta::emits_movable_tag`]
  // is now derived from the full [`Taggable::tags`] stream (single source — no
  // hand-maintained channel list, so a future default-visible non-`File`
  // channel is covered for free), which renders values and clones the MakerNote
  // emissions. To keep that cost OFF the hot path for the overwhelming majority
  // of JPEGs (no GoPro `APP6`, so the result would be unused), only TRACK the
  // anchor when such a segment is present. This cannot change output: a JPEG
  // with no GoPro `APP6` never reads `effective_exif_idx`. The probe mirrors the
  // exact identifier `attach_app6_gopro` keys on (`0xe6` + `GoPro\0`).
  #[cfg(feature = "quicktime")]
  let has_gopro_app6 = segments.iter().any(|seg| {
    seg.marker == 0xe6
      && data
        .get(seg.payload_start..seg.payload_end)
        .is_some_and(|p| p.starts_with(b"GoPro\0"))
  });

  // The MUTABLE `$$self{Make} eq 'DJI'` state, captured per-segment in marker
  // order — the gate ExifTool's `Marker:` loop evaluates IN-LOOP for the JPEG
  // auxiliary DJI thermal `APP3`/`APP4`/`APP5` arms (`JPEG.pm:113`/`:150`/`:174`).
  // ExifTool sets `$$self{Make}` from each `APP1` Exif block's IFD0 `Make`
  // (`Exif.pm:585` `RawConv` `$$self{Make} = $val`, after trimming trailing
  // whitespace) as it processes that segment, so the state is LAST-WINS across
  // `APP1`s, not first-wins: a file ordered `APP1 Make=DJI`, then `APP1
  // Make=Canon`, then `APP4` leaves `$$self{Make}` == `Canon` at the `APP4` — the
  // thermal arm is SKIPPED. `make_is_dji_at[i]` is that running state AS OF
  // segment `i` (after processing every `APP1` at index `<= i`): `true` iff the
  // most-recent `APP1` whose `ProcessTIFF` succeeded had IFD0 `Make` trimming to
  // exactly `DJI`. An IFD1-only `Make` does NOT set it (the capture is IFD0-only,
  // reusing the main walker's [`ExifMeta::captured_make`]); `'DJI '` with
  // trailing space DOES (the `RawConv` trim normalizes it to `DJI`). The vector
  // is index-aligned with `segments`; `false` everywhere until the first DJI
  // `APP1`, then it follows the current IFD0 `Make` forward. A `ThermalParams2`
  // `APP4` is emitted by [`super::jpeg_app::process_app_markers`] only where this
  // is `true` at its own marker position. `APP7` (`DJI-DBG\0`) is NOT
  // `Make`-gated (it keys on its payload prefix) so it is unaffected.
  let mut make_is_dji_at: Vec<bool> = std::vec::Vec::with_capacity(segments.len());
  let mut current_make_is_dji = false;
  for (i, seg) in segments.iter().enumerate() {
    // The running `$$self{Make} eq 'DJI'` state is recorded ONCE per segment by
    // the `make_is_dji_at.push(current_make_is_dji)` after this labeled block:
    // every early exit from the `APP1` work below is a `break 'app1`, so the push
    // runs for EVERY marker position (an `APP1` that fails to parse, a non-`APP1`
    // segment, or a parsed `APP1` — which first updates `current_make_is_dji`).
    'app1: {
      // `ExifTool.pm:7736`: APP1 (EXIF / XMP / QVCI / PARROT). Only APP1.
      if seg.marker != 0xe1 {
        // Not an `APP1` — `$$self{Make}` is unchanged at this marker position.
        break 'app1;
      }
      let payload = match data.get(seg.payload_start..seg.payload_end) {
        Some(p) => p,
        None => break 'app1,
      };
      // Is this an `APP1` segment matching the Exif arm `^(.{0,4})Exif\0.`?
      let Some(garbage) = exif_arm_garbage(payload) else {
        // A non-Exif APP1 (XMP / extended-XMP / QVCI / PARROT) — its arms are a
        // deferred JPEG-container follow-up. Keep walking (`ExifTool.pm:7821`
        // `next`). `$$self{Make}` is unchanged here (no IFD0 was parsed).
        break 'app1;
      };

      // Bundled's extended-EXIF discriminator (`ExifTool.pm:7764-7765`): this
      // `APP1` Exif segment is a multi-segment EXIF chain link when EITHER it is
      // the chain START (the immediately-following `APP1` payload is `^Exif\0\0`
      // NOT followed by a TIFF magic) OR a prior segment already entered the
      // chain (`in_multisegment`). The combined-data ASSEMBLY is a deferred
      // follow-up; a chain link is skipped SILENTLY (no merge, no malformed
      // warning). `in_multisegment` stays set while more fragments follow and
      // clears on the LAST fragment (its `is_multisegment_chain` is `false`).
      if in_multisegment || is_multisegment_chain(data, &segments, i) {
        in_multisegment = is_multisegment_chain(data, &segments, i);
        break 'app1;
      }

      // `$hdrLen = length($exifAPP1hdr) + length($1)` = 6 + garbage. Strip it
      // (`DirStart(\%dirInfo, $hdrLen, $hdrLen)`, `ExifTool.pm:7780`) and hand
      // the remainder to ProcessTIFF (`ExifTool.pm:7783`).
      let hdr_len = garbage + EXIF_APP1_HDR.len();
      let Some(block) = payload.get(hdr_len..) else {
        break 'app1;
      };
      // The TIFF block's file offset (`$$dirInfo{Base}`): `$segPos + $hdrLen`
      // (`DirStart` sets `$$dirInfo{Base} = $$dirInfo{DataPos} + $base`,
      // `ExifTool.pm:7780`). `$segPos` is `$raf->Tell()` — an ABSOLUTE file
      // position — so when an unknown header was skipped past, `base_offset`
      // (Perl `$pos + $skip`) shifts every segment's TIFF block to its true
      // file offset; `base_offset == 0` for a JPEG that starts at offset 0.
      // `u32` matches ExifTool's 32-bit offset arithmetic; a JPEG cannot place
      // an `APP1` past 4 GiB, so the cast is lossless in practice (saturation
      // guards a pathological input rather than wrapping). `checked_add` across
      // all three terms BEFORE the cast: a huge caller-supplied `base_offset`
      // (direct-API caller, or a future container that rebases past `usize::MAX`)
      // would otherwise overflow `usize` and panic in debug / wrap in release
      // BEFORE the intended `u32::MAX` saturation. On any overflow, fall through
      // to the same `u32::MAX` fallback (preserving the saturation intent).
      let base = base_offset
        .checked_add(seg.payload_start)
        .and_then(|s| s.checked_add(hdr_len))
        .and_then(|s| u32::try_from(s).ok())
        .unwrap_or(u32::MAX);

      // `ProcessTIFF(...) or Warn('Malformed APP1 EXIF segment')`
      // (`ExifTool.pm:7783`). A bad TIFF block is a non-fatal `Warn` — the JPEG
      // container is still accepted and the walk continues.
      match parse_exif_block_with_base(block, base) {
        Some(exif) => {
          // Record the FIRST `APP1` that emits a MOVABLE EXIF tag — the EFFECTIVE
          // EXIF block a GoPro `APP6` is ordered against (first-wins, the primary
          // block, like `byte_order`/`maker_note`). A "movable" tag is any
          // default-visible tag in a family-0 group OTHER than `File`: the
          // `File:ExifByteOrder`/`File:PageCount` prefix is the unconditional
          // `File`-group prefix `Taggable::tags` emits FIRST regardless, so it
          // never participates in the GoPro-vs-EXIF ordering. The predicate is
          // computed by INSPECTING the block's REAL `Taggable::tags` output
          // ([`ExifMeta::emits_movable_tag`]) — `any(non-`File`, non-Unknown tag)`
          // — NOT by guessing which channels are movable: a valid-but-EMPTY TIFF
          // (byte-order marker + 0-entry IFD0) emits ONLY `File:ExifByteOrder` and
          // is NOT effective (`false`); an `APP1` with IFD entries emits `EXIF:*`
          // (`true`); an `APP1` carrying ONLY a decoded MakerNote (an `ExifIFD`
          // pointer + an `Apple`/`Canon`/… MakerNote, no other IFD0 entry, so
          // `entries` is EMPTY) emits `MakerNotes:*` (`true`) even though the old
          // `!entries.is_empty()` guess missed it. So a GoPro `APP6` ahead of such
          // a MakerNote-only `APP1` correctly emits BEFORE it. This mirrors the
          // GoPro-side anchor (the empty-to-non-empty `GoProMeta` accumulator
          // transition in [`attach_app6_gopro`]): both anchors are "first segment
          // producing a default-visible non-`File` tag". Inspecting the real
          // emission ends the channel-by-channel drift (this guess missed
          // `entries` at R8, then MakerNote at R9) and covers any future
          // non-`File` channel for free.
          #[cfg(feature = "quicktime")]
          if has_gopro_app6 && effective_exif_idx.is_none() && exif.emits_movable_tag() {
            effective_exif_idx = Some(i);
          }
          // Update the MUTABLE `$$self{Make} eq 'DJI'` state at THIS `APP1`'s
          // marker position (`Exif.pm:585` `$$self{Make} = $val`, last-wins): the
          // block's [`ExifMeta::captured_make`] is the IFD0-only, trailing-
          // whitespace-trimmed `Make` exactly as the main Exif walker captured it
          // (the SAME `is_perl_space` RawConv path — `'DJI '` trims to `DJI`; an
          // IFD1-only `Make` is excluded). ExifTool assigns `$$self{Make} = $val`
          // ONLY when an IFD0 `Make` tag is actually seen — an `APP1` with NO IFD0
          // `Make` (or only an IFD1 `Make`, or an unreadable one) never runs that
          // assignment, so it LEAVES the prior state intact rather than clearing
          // it. `captured_make()` is therefore `Some` only when an IFD0 `Make` was
          // captured; update the gate ONLY then. A later DJI `APP1` arms it; a
          // later non-DJI `APP1` flips it back OFF (its `captured_make` is a
          // non-DJI `Some`); a no-`Make` `APP1` carries the previous state forward
          // unchanged — faithful to ExifTool reaching a subsequent `APP4`
          // ThermalParams2 with `$$self{Make}` == the last Make actually assigned,
          // never cleared by an absent one. Read on the parsed block BEFORE
          // `merge_exif_block` consumes it.
          if let Some(make) = exif.captured_make() {
            current_make_is_dji = make == "DJI";
          }
          merge_exif_block(
            &mut entries,
            &mut warnings,
            &mut warnings_ignorable,
            &mut byte_order,
            &mut maker_note,
            exif,
          );
        }
        // `parse_exif_block_with_base` also returns `None` for a BigTIFF (0x2b)
        // header — a clean, deliberate no-Exif skip (bundled SUPPORTS BigTIFF, so
        // emitting a "Malformed APP1" warning would diverge). A genuinely
        // malformed CLASSIC (0x2a) header is what bundled warns on. So map only
        // a non-BigTIFF `None` to the warning; a BigTIFF block is skipped
        // silently (no warning, no Exif), matching the standalone-TIFF path.
        // `$$self{Make}` is unchanged on a parse failure (no IFD0 was walked).
        None if !is_bigtiff_block(block) => {
          warnings.push(String::from(MALFORMED_APP1_WARNING));
          warnings_ignorable.push(0); // normal warning (ExifTool.pm:7783)
        }
        None => {}
      }
    }
    // Record the running `$$self{Make} eq 'DJI'` state AS OF this segment — after
    // this `APP1`'s own update (if it parsed), else carried forward unchanged.
    // One push per segment keeps `make_is_dji_at` index-aligned with `segments`.
    make_is_dji_at.push(current_make_is_dji);
  }

  // A valid JPEG ALWAYS yields an `ExifMeta` (the container is accepted);
  // `entries`/`byte_order` are empty/`None` when no `APP1` Exif block parsed.
  #[allow(unused_mut)]
  let mut meta = ExifMeta::from_jpeg_parts(
    entries,
    warnings,
    warnings_ignorable,
    byte_order,
    maker_note,
  );
  // The JPEG auxiliary `APP`-segment tags: JFIF (`APP0`), MPF (`APP2`) and the
  // DJI thermal arms (`APP3`/`APP4`/`APP5`/`APP7`). Decoded for BOTH print-conv
  // modes (the values are converted at decode time) and attached for
  // [`Taggable::tags`] to append after the EXIF block. Empty for a JPEG
  // carrying none of these segments.
  {
    let app_pc =
      super::jpeg_app::process_app_markers(data, &segments, &make_is_dji_at, base_offset, true);
    let app_n =
      super::jpeg_app::process_app_markers(data, &segments, &make_is_dji_at, base_offset, false);
    if !app_pc.is_empty() || !app_n.is_empty() {
      meta.set_jpeg_app_tags(app_pc, app_n);
    }
  }
  // The `File:*` Start-Of-Frame dimension tags (`ExifTool.pm:7419-7462`): the
  // FIRST SOF segment yields `ImageWidth`/`ImageHeight`/`EncodingProcess`/
  // `BitsPerSample`/`ColorComponents`/`YCbCrSubSampling`. ExifTool `HandleTag`s
  // these in `ProcessJPEG` BEFORE the IFD walk (the `Marker:` loop reaches the
  // SOF before SOS), so `Taggable::tags` emits them right after the `File:`
  // prefix and ahead of the IFD blocks. A short / absent SOF yields `None`.
  if let Some(sof) = parse_sof_segment(data, &segments) {
    meta.set_jpeg_sof(sof);
  }
  // `APP6` "GoPro" GPMF (JPEG.pm:196-198): a GoPro still (`GOPR*.JPG`) carries
  // its device-settings GPMF stream in an `APP6` (`0xe6`) segment whose payload
  // begins with the 6-byte `GoPro\0` identifier. ExifTool's JPEG.pm `APP6`
  // (JPEG.pm:183-216) is a multi-arm `Condition`-dispatched segment; the GoPro
  // arm (`$$valPt =~ /^GoPro\0/`, JPEG.pm:196-198) hands the remainder to
  // `%GoPro::GPMF`'s `ProcessGoPro` (the KLV walker). Only the GoPro arm is in
  // scope here (the EPPIM / NITF / HP_TDHD / InfiRay / DJI / Motorola `APP6`
  // arms are separate ports). Attached with a flag recording whether the
  // `APP6` GoPro block preceded the `APP1` Exif block in marker order, so
  // `Taggable::tags` emits the GoPro tags before/after EXIF to match ExifTool's
  // `Marker:`-loop file order (the real GoPro layout — `APP1` then `APP6` —
  // emits GoPro after EXIF, unchanged).
  #[cfg(feature = "quicktime")]
  attach_app6_gopro(data, &segments, effective_exif_idx, &mut meta);
  Some(meta)
}

/// Scan the collected JPEG segments for every `APP6` (`0xe6`) "GoPro" segment
/// and decode each one's GPMF KLV stream into the `meta` (JPEG.pm:196-198).
///
/// The GoPro arm of JPEG.pm's multi-arm `APP6` is `$$valPt =~ /^GoPro\0/`
/// (JPEG.pm:197): strip the 6-byte `GoPro\0` prefix and dispatch the remainder
/// into `%GoPro::GPMF` via `ProcessGoPro` (the recursive Key-Length-Value
/// walker). ExifTool runs this `ProcessDirectory(GoPro::GPMF)` inside its
/// `Marker:` loop (ExifTool.pm:8176-8181), so it processes EVERY matching
/// `APP6` segment in file (marker) order — it does NOT stop at the first.
/// All tags accumulate into the one extracted-tag table (the typed equivalent
/// is a single [`GoProMeta`] walked across every GoPro `APP6`), so a leading
/// truncated / empty `GoPro\0` segment that decodes nothing does NOT suppress a
/// later valid one. A GoPro still normally carries exactly one such segment;
/// the multi-segment path matters only for malformed / crafted inputs.
///
/// Duplicate tag names across segments resolve under the emission engine's
/// last-wins dedup, matching ExifTool's default `%noDups` (these GoPro tags
/// have no `Priority => 0`). A segment that decodes no record contributes
/// nothing; the accumulator is attached only if at least one record landed, so
/// a non-GoPro `APP6` mislabeled with the prefix adds no spurious tags.
///
/// The accumulator is attached with a `before_exif` flag recording whether the
/// first TAG-PRODUCING GoPro `APP6` segment precedes the EFFECTIVE EXIF block —
/// the first `APP1` contributing a MOVABLE EXIF tag in the main loop
/// (`effective_exif_idx`: the first `APP1` whose real `Taggable::tags` emits a
/// movable, non-`File` tag — an `EXIF:*` IFD entry OR a `MakerNotes:*` vendor
/// tag, per [`ExifMeta::emits_movable_tag`]) — in file (marker)
/// order: ExifTool emits each segment's tags at its `Marker:`-loop position
/// (`ExifTool.pm:7325`), so a non-standard JPEG with a tag-producing `APP6`
/// ahead of the EFFECTIVE EXIF block emits the `GoPro:*` tags BEFORE the
/// `IFD0:*` tags. `File:ExifByteOrder` (and any `File:PageCount`) is NOT the
/// anchor: it is the unconditional `File`-group prefix that `Taggable::tags`
/// emits FIRST regardless, so only MOVABLE EXIF tags participate in the
/// GoPro-vs-EXIF ordering. BOTH anchors are EFFECTIVE (movable / default-visible
/// tag-producing), NOT merely signature-matching: on the EXIF side a malformed /
/// BigTIFF-skipped / deferred-multi-segment leading `APP1` produces NOTHING, and
/// a byte-order-only / empty-IFD0 `APP1` produces ONLY the `File:ExifByteOrder`
/// prefix (no movable tag); SYMMETRICALLY on the GoPro side a leading truncated /
/// empty `GoPro\0` `APP6` whose GPMF walker recognizes nothing produces NO GoPro
/// tag. So with `APP6(empty GoPro) → APP1(valid Exif) → APP6(valid GoPro)` the
/// first tag-producing GoPro segment is the LATER one (after the `APP1`), and
/// ExifTool emits `IFD0:*` BEFORE `GoPro:*` — anchoring on the inert first
/// `GoPro\0` segment would wrongly reverse them (the GoPro-side mirror of the
/// inert-leading-`APP1` case: an empty-IFD0 first `APP1` must not anchor EXIF
/// ahead of a GoPro `APP6` whose tags ExifTool emits between it and the later
/// movable EXIF block). A real GoPro still has its (single, valid) `APP1`
/// before `APP6` (`false`), so [`Taggable::tags`](crate::emit::Taggable::tags)
/// keeps the GoPro block after EXIF unchanged. With NO `APP1` ever contributing
/// a movable EXIF tag (`effective_exif_idx == None`) the GoPro block is the only
/// EXIF-or-GoPro content, so its absolute position is moot — `false` keeps the
/// simple after-`File`-group path (there is nothing to order against). (The
/// comparison is whole-block: one GoPro `APP6` vs the one effective `APP1` Exif
/// block — the realistic shapes; an `APP6`/`APP1`/`APP6` straddle is not
/// marker-order-replayed, see the field docs.)
#[cfg(feature = "quicktime")]
fn attach_app6_gopro(
  data: &[u8],
  segments: &[Segment],
  effective_exif_idx: Option<usize>,
  meta: &mut ExifMeta<'_>,
) {
  /// JPEG.pm:197 `$$valPt =~ /^GoPro\0/` — the GoPro `APP6` identifier.
  const GOPRO_APP6_HDR: &[u8] = b"GoPro\0";
  let mut gopro = crate::metadata::GoProMeta::new();
  // File-order index of the first GoPro `APP6` segment that ACTUALLY PRODUCES a
  // GoPro tag — the marker position at which ExifTool's GoPro arm first emits a
  // default-visible `GoPro:*` (or `Doc<N>:GoPro*`) tag. `None` until such a
  // segment is processed. NOT the first `GoPro\0`-prefixed segment: a leading
  // truncated / empty `GoPro\0` `APP6` whose GPMF walker recognizes nothing
  // emits no tag, so ExifTool's first GoPro key comes from a LATER segment —
  // possibly after an intervening `APP1` Exif block. Anchoring on the inert
  // first GoPro segment would wrongly order the (later, tag-producing) GoPro
  // block before the EXIF it actually follows. (The EXIF-side mirror of this is
  // `effective_exif_idx` in the main loop — the first `APP1` whose real
  // `Taggable::tags` emits a MOVABLE (non-`File`) tag ([`ExifMeta::emits_movable_tag`]):
  // an `EXIF:*` IFD entry OR a `MakerNotes:*` vendor tag, not the first
  // Exif-signature match and not a byte-order-only `APP1`. Both anchors are
  // symmetric: "first segment producing a default-visible non-`File` tag".)
  let mut first_gopro_idx: Option<usize> = None;
  for (i, seg) in segments.iter().enumerate() {
    // The GoPro arm fires only on the `APP6` marker (`0xe6`).
    if seg.marker != 0xe6 {
      continue;
    }
    let Some(payload) = data.get(seg.payload_start..seg.payload_end) else {
      continue;
    };
    // GoPro arm: payload begins `GoPro\0`. Strip the 6-byte prefix and hand the
    // GPMF KLV remainder to the shared `ProcessGoPro` walker, accumulating into
    // the SAME `GoProMeta` across every GoPro `APP6` in file order (ExifTool's
    // per-marker `ProcessDirectory`). A segment whose walker recognizes nothing
    // (truncated / mislabeled) simply adds nothing and the scan continues.
    let Some(gpmf) = payload.strip_prefix(GOPRO_APP6_HDR) else {
      continue;
    };
    // Snapshot whether the accumulator is empty BEFORE processing this segment;
    // `process_gopro` only ever ADDS records, so a transition from empty to
    // non-empty marks THIS segment as the first one that produced a tag (the
    // same "did this contribute anything" predicate as the `is_empty()` attach
    // gate below). Record its marker index as the GoPro-side ordering anchor.
    let was_empty = gopro.is_empty();
    let _ = crate::formats::gopro::process_gopro(gpmf, &mut gopro);
    if first_gopro_idx.is_none() && was_empty && !gopro.is_empty() {
      first_gopro_idx = Some(i);
    }
  }
  // Attach iff at least one GPMF record landed (ExifTool's `FoundEmbedded`);
  // a file with only empty / mislabeled GoPro `APP6` segments stays GoPro-free.
  if !gopro.is_empty() {
    // Attach the GoPro block at its marker position (`first_gopro_idx`, the
    // first TAG-PRODUCING GoPro `APP6`) alongside the EFFECTIVE EXIF block
    // position (`effective_exif_idx`, the `APP1` whose `ProcessTIFF` emitted a
    // movable tag). `Taggable::tags` interleaves them by ascending position, so
    // a GoPro block below the EXIF block emits before it, otherwise after —
    // reproducing exactly the old `first_gopro_idx < effective_exif_idx`
    // comparison. BOTH indices are tag-producing, not merely
    // signature/prefix-matching: a malformed / BigTIFF / deferred-multi-segment
    // `APP1` produces no EXIF tags (so does not anchor the EXIF side, leaving
    // `effective_exif_idx == None`), and a truncated / empty `GoPro\0` `APP6`
    // produces no GoPro tag (so does not advance `first_gopro_idx`). With no
    // `APP1` producing a parsed EXIF block (`effective_exif_idx == None`) the
    // EXIF block has no position — it sorts FIRST (`Option`'s `None < Some`), so
    // the GoPro block trails it, matching ExifTool (no `IFD0:*` tags to be
    // before/after).
    //
    // This whole-GoPro-block ordering is byte-exact for every
    // single-effective-`APP1` layout — all realistic GoPro JPEGs (one early
    // `APP1` Exif + a later GoPro `APP6`, e.g. `t/images/GoPro.jpg`). It also
    // matches the oracle for multi-independent-`APP1` and `APP6`/`APP1`/`APP6`
    // straddle layouts at the `-G1 -j` conformance target, because ExifTool's
    // JSON co-locates the family-1 `IFD0` group and decides `IFD0`-vs-`GoPro`
    // order by this same first-GoPro-vs-effective-EXIF index comparison. A
    // strict per-segment marker-order replay (under which the GoPro `HandleTag`
    // block would interleave BETWEEN two independent `APP1` tag blocks, or
    // straddle the EXIF block) is the engine-wide limitation tracked in
    // issue 233; it does not surface in `-G1 -j` output (see the
    // [`ExifMeta`] / [`JpegAuxBlock`](crate::exif::JpegAuxBlock) ordering docs).
    //
    // `first_gopro_idx` is `Some` here — it is set on the empty→non-empty
    // `GoProMeta` transition, which must have occurred for `!gopro.is_empty()`.
    // The `usize::MAX` fallback is unreachable; were it taken it would sort the
    // GoPro block last (after the EXIF block), the old `_ => false` behaviour.
    let gopro_pos = first_gopro_idx.unwrap_or(usize::MAX);
    meta.set_jpeg_gopro(gopro, gopro_pos, effective_exif_idx);
  }
}

/// Pass 1 of [`parse_jpeg_exif`]: walk the JPEG markers from just past `SOI`
/// and collect every length-bearing [`Segment`] up to `EOI` / `SOS` / `SOD`.
///
/// Faithful to the `Marker:` loop (`ExifTool.pm:7325-7375`): the walk skips
/// `0xff` fill bytes, stops at `EOI` (`0xd9`) / `SOS` (`0xda`) / `SOD`
/// (`0x93`) (`ExifTool.pm:7339-7340`), skips standalone markers
/// (`%markerLenBytes`, `ExifTool.pm:7358`), and reads the 2-byte big-endian
/// length word of every other marker (`ExifTool.pm:7360-7366`). A truncated
/// or malformed segment header simply ends the scan (bundled `last Marker`).
pub(super) fn scan_jpeg_segments(data: &[u8]) -> Vec<Segment> {
  let mut segments: Vec<Segment> = Vec::new();
  // Cursor sits just past the SOI marker. The `Marker:` loop reads ahead.
  let mut pos = 2usize;

  loop {
    // `ExifTool.pm:7343-7357`: skip to the next marker. JPEG markers begin
    // with one or more `0xff` fill bytes; the marker is the first non-`0xff`
    // byte after them.
    let Some(ff) = data
      .get(pos..)
      .and_then(|s| s.iter().position(|&b| b == 0xff))
    else {
      return segments;
    };
    pos += ff;
    // Consume the run of `0xff` fill bytes (`ExifTool.pm:7351-7356`). The
    // checked `data.get(pos) == Some(&0xff)` folds the `pos < data.len()` bound
    // into the comparison — byte-identical to `pos < data.len() && data[pos] ==
    // 0xff`.
    while data.get(pos) == Some(&0xff) {
      pos += 1;
    }
    // `$raf->Read($ch, 1) or last Marker` — need the marker byte.
    let Some(&marker) = data.get(pos) else {
      return segments;
    };
    pos += 1;

    // `ExifTool.pm:7339-7340`: the read-ahead loop stops at EOI (0xd9), SOS
    // (0xda) or SOD (0x93) — no further metadata segment beyond these.
    if marker == 0xd9 || marker == 0xda || marker == 0x93 {
      return segments;
    }
    // `ExifTool.pm:7358`: a marker in `%markerLenBytes` is standalone — no
    // length word, no payload. Skip it and continue the walk.
    if is_standalone_marker(marker) {
      continue;
    }
    // `ExifTool.pm:7360-7366`: the 2-byte big-endian length word includes its
    // own 2 bytes. `last Marker unless defined($len) and $len >= 2`.
    let (Some(&hi), Some(&lo)) = (data.get(pos), data.get(pos + 1)) else {
      return segments;
    };
    let len = u16::from_be_bytes([hi, lo]) as usize;
    if len < 2 {
      return segments;
    }
    let payload_start = pos + 2;
    // `last Marker unless $raf->Read($buff, $len) == $len`: a truncated
    // segment ends the walk.
    let Some(payload_end) = payload_start.checked_add(len - 2) else {
      return segments;
    };
    if payload_end > data.len() {
      return segments;
    }
    segments.push(Segment {
      marker,
      payload_start,
      payload_end,
    });
    // Advance past this segment to the next marker.
    pos = payload_end;
  }
}

/// `true` for a JPEG Start-Of-Frame marker — bundled `ExifTool.pm:7419`
/// `($marker & 0xf0) == 0xc0 and ($marker == 0xc0 or $marker & 0x03)`. This is
/// the SOF0-SOF15 set EXCEPT DHT (`0xc4`), JPGA (`0xc8`) and DAC (`0xcc`) — the
/// three `0xcX` markers that are NOT frame headers.
#[inline]
const fn is_sof_marker(marker: u8) -> bool {
  marker & 0xf0 == 0xc0 && (marker == 0xc0 || marker & 0x03 != 0)
}

/// Parse the FIRST JPEG Start-Of-Frame segment into a [`SofInfo`] — a faithful
/// port of the SOF arm of `ProcessJPEG` (`ExifTool.pm:7419-7462`).
///
/// Bundled handles the first SOF marker it reaches (`$gotSize` ignores any
/// later one in a corrupted JPEG, `ExifTool.pm:7430`) and `HandleTag`s the
/// `Image::ExifTool::JPEG::SOF` tags (group `File`, `ExifTool.pm:2163`). The
/// payload (after the 2-byte length word) is ALL big-endian regardless of the
/// embedded TIFF byte order — `unpack('Cn2C', …)` (`ExifTool.pm:7434`):
///
/// - byte 0: precision → `BitsPerSample`
/// - bytes 1-2: height (`n`, u16be) → `ImageHeight`
/// - bytes 3-4: width (`n`, u16be) → `ImageWidth`
/// - byte 5: component count → `ColorComponents`
/// - `EncodingProcess` = `marker - 0xc0`
/// - then `count` × 3-byte components `(id, samplingFactors, quantTable)`;
///   `YCbCrSubSampling` is derived from the sampling factors (below).
///
/// `ExifTool.pm:7429` `next if $length < 6` — a payload shorter than the 6-byte
/// header yields NO tags. Every read is bounds-checked (`.get()` / `get_u16`),
/// so a truncated SOF returns `None` rather than panicking.
fn parse_sof_segment(data: &[u8], segments: &[Segment]) -> Option<SofInfo> {
  // The FIRST SOF segment with a complete header. ExifTool advances `$gotSize`
  // only AFTER the length guard (`next if $length < 6 or $gotSize`,
  // ExifTool.pm:7429-7430), so a short/truncated SOF is SKIPPED and a later
  // valid SOF still supplies the dimensions — only once a valid SOF parses is a
  // subsequent SOF ignored.
  let (seg, payload) = segments.iter().find_map(|seg| {
    if !is_sof_marker(seg.marker) {
      return None;
    }
    // `next if $length < 6` (ExifTool.pm:7429): the 6-byte SOF header
    // (precision + height + width + components) must be present, else skip.
    let payload = data.get(seg.payload_start..seg.payload_end)?;
    (payload.len() >= 6).then_some((seg, payload))
  })?;
  // `unpack('Cn2C', …)` — precision(C), height(n), width(n), components(C); all
  // big-endian (`get_u16(_, _, ByteOrder::Big)`) irrespective of the Exif byte
  // order. The `< 6` guard above makes these `.get()`/`get_u16` reads succeed,
  // but they stay checked (panic-safe by construction).
  let bits_per_sample = *payload.first()?;
  let image_height = get_u16(payload, 1, ByteOrder::Big)?;
  let image_width = get_u16(payload, 3, ByteOrder::Big)?;
  let color_components = *payload.get(5)?;
  // `EncodingProcess = $marker - 0xc0` (ExifTool.pm:7437). `is_sof_marker`
  // guarantees `marker & 0xf0 == 0xc0`, so `marker >= 0xc0` and the subtraction
  // cannot underflow.
  let encoding_process = seg.marker.wrapping_sub(0xc0);

  // `YCbCrSubSampling` — `next unless $n == 3 and $length >= 15`
  // (ExifTool.pm:7438): derived ONLY for a 3-component frame whose payload holds
  // all three components' sampling factors (6-byte header + 3×3 = 15 bytes).
  let ycbcr_subsampling = parse_ycbcr_subsampling(payload, color_components);

  Some(SofInfo::new(
    image_width,
    image_height,
    encoding_process,
    bits_per_sample,
    color_components,
    ycbcr_subsampling,
  ))
}

/// Derive the raw `YCbCrSubSampling` string ("`h v`", e.g. `"2 2"`) from the SOF
/// component sampling factors — bundled `ExifTool.pm:7438-7462`.
///
/// `next unless $n == 3 and $length >= 15` (`ExifTool.pm:7438`): the value is
/// computed ONLY for a 3-component frame whose payload carries all three
/// components' sampling factors. The loop reads each component's
/// `samplingFactors` byte (`Get8u($segDataPt, 7 + 3*$i)`, `ExifTool.pm:7444`),
/// splits it into `hf = sf >> 4` / `vf = sf & 0x0f` (`ExifTool.pm:7450`), and
/// tracks the min/max horizontal & vertical frequencies. The result is emitted
/// only `if ($hmin and $vmin)` (`ExifTool.pm:7458`) — both minimums non-zero —
/// as `"$hmax/$hmin $vmax/$vmin"` (`ExifTool.pm:7459-7460`). The division is the
/// faithful `$hmax / $hmin`: an exact integer ratio renders as that integer
/// (matching the `%yCbCrSubSampling` map keys, ExifTool.pm:2149-2158); a rare
/// non-integer ratio renders as Perl's float stringification. Returns `None`
/// when not 3-component, the payload is short of 15 bytes, or a minimum is 0.
fn parse_ycbcr_subsampling(payload: &[u8], components: u8) -> Option<smol_str::SmolStr> {
  // `$n == 3 and $length >= 15`.
  if components != 3 || payload.len() < 15 {
    return None;
  }
  let mut hmin = 0u8;
  let mut hmax = 0u8;
  let mut vmin = 0u8;
  let mut vmax = 0u8;
  for i in 0..3usize {
    // `Get8u($segDataPt, 7 + 3 * $i)` — the component's sampling-factors byte.
    // `7 + 3*2 = 13 < 15`, so the read is in-bounds given the `>= 15` guard; it
    // stays a checked `.get()`.
    let sf = *payload.get(7 + 3 * i)?;
    let hf = sf >> 4;
    let vf = sf & 0x0f;
    if i == 0 {
      hmin = hf;
      hmax = hf;
      vmin = vf;
      vmax = vf;
    } else {
      hmin = hmin.min(hf);
      hmax = hmax.max(hf);
      vmin = vmin.min(vf);
      vmax = vmax.max(vf);
    }
  }
  // `if ($hmin and $vmin)` — both minimums must be non-zero (else a divide and a
  // meaningless value). A zero minimum ⇒ no tag (ExifTool.pm:7458).
  if hmin == 0 || vmin == 0 {
    return None;
  }
  // `sprintf` is not used: bundled interpolates `"$hs $vs"` with
  // `$hs = $hmax / $hmin` (a Perl number). An EXACT integer ratio (every real
  // JPEG — the `%yCbCrSubSampling` keys are integer pairs) stringifies as the
  // integer; a non-integer ratio uses the float form Perl would print.
  let mut out = String::with_capacity(7);
  push_ratio(&mut out, hmax, hmin);
  out.push(' ');
  push_ratio(&mut out, vmax, vmin);
  Some(smol_str::SmolStr::from(out))
}

/// Append the Perl-faithful stringification of `num / den` (both `> 0`) to
/// `out` — an exact integer quotient as that integer (the universal case for
/// real JPEG sampling factors), otherwise the `f64` ratio formatted as Perl's
/// default number stringification.
fn push_ratio(out: &mut String, num: u8, den: u8) {
  use std::fmt::Write as _;
  // `is_multiple_of(0)` is `num == 0`, so the `den != 0` intent is preserved:
  // a zero denominator falls to the `else` (the callers never pass one — `hmin`/
  // `vmin` are non-zero at the single call site).
  if den != 0 && num.is_multiple_of(den) {
    // Exact integer ratio — Perl prints `2`, not `2.0`.
    let _ = write!(out, "{}", num / den);
  } else {
    // A non-integer ratio (no real JPEG hits this; the map then falls back to
    // the raw string). Perl's `$hmax/$hmin` is a double; its default
    // stringification is `%.15g`-equivalent.
    let _ = write!(out, "{}", f64::from(num) / f64::from(den));
  }
}

/// Match an `APP1` payload against the Exif arm `/^(.{0,4})Exif\0./is`
/// (`ExifTool.pm:7750`) and return the count of leading garbage bytes (`$1`,
/// 0-4) when it matches, else `None`.
///
/// The regex requires `Exif\0` then any one byte (the trailing `.`), preceded
/// by 0-4 leading garbage bytes — i.e. `Exif\0` + ≥ 1 more byte must be
/// present after the 0-4-byte prefix (the 6th byte being the start of the
/// TIFF block in the common single-`\0` Kodak case).
///
/// The `/i` flag makes the literal `Exif` match CASE-INSENSITIVELY: bundled
/// accepts `EXIF\0`, `exif\0`, `eXiF\0`, … as the Exif APP1 identifier. The
/// fifth byte must still be a literal NUL (`\0` is not a letter, so `/i` does
/// not touch it). Note the multi-segment peek (`is_multisegment_chain`,
/// `ExifTool.pm:7776`) is a SEPARATE regex with NO `/i`, so it stays
/// case-sensitive.
fn exif_arm_garbage(payload: &[u8]) -> Option<usize> {
  for garbage in 0..=4usize {
    let sig = payload.get(garbage..)?;
    // `Exif` (case-insensitive, `/i`) + `\0` (5 bytes) then `.` (≥ 1 more
    // byte) must be present. With `sig.len() > 5`, `sig.get(..4)` / `sig.get(4)`
    // are `Some` — the checked, byte-identical form of `sig[..4]` / `sig[4]`.
    if sig.len() > 5
      && sig
        .get(..4)
        .is_some_and(|name| name.eq_ignore_ascii_case(b"Exif"))
      && sig.get(4) == Some(&0)
    {
      return Some(garbage);
    }
  }
  None
}

/// Bundled's extended-EXIF discriminator — `ExifTool.pm:7764-7765`
/// `if ($nextMarker == $marker and $$nextSegDataPt =~
/// /^$exifAPP1hdr(?!(MM\0\x2a|II\x2a\0))/)`.
///
/// `true` when the `APP1` Exif segment at `segments[i]` is IMMEDIATELY
/// followed by another `APP1` segment whose payload begins with the 6-byte
/// `Exif\0\0` header NOT followed by a TIFF byte-order magic (`MM\0\x2a` /
/// `II\x2a\0`) — bundled's signal that the pair is a multi-segment (extended)
/// EXIF chain rather than two independent EXIF blocks. The `$combinedSegData`
/// ASSEMBLY of such a chain is a deferred follow-up; the caller skips a
/// detected chain silently so it neither mis-parses the fragment as a
/// standalone TIFF nor diverges from bundled.
fn is_multisegment_chain(data: &[u8], segments: &[Segment], i: usize) -> bool {
  let Some(next) = segments.get(i + 1) else {
    return false;
  };
  // `$nextMarker == $marker` — the immediately-following segment is APP1 too.
  if next.marker != 0xe1 {
    return false;
  }
  let Some(payload) = data.get(next.payload_start..next.payload_end) else {
    return false;
  };
  // `^$exifAPP1hdr` — the 6-byte `Exif\0\0` header (no garbage tolerance in
  // bundled's peek-ahead regex).
  let Some(rest) = payload.strip_prefix(EXIF_APP1_HDR) else {
    return false;
  };
  // `(?!(MM\0\x2a|II\x2a\0))` — NOT a TIFF byte-order magic ⇒ multi-segment.
  !(rest.starts_with(b"MM\0\x2a") || rest.starts_with(b"II\x2a\0"))
}

/// Merge one decoded `APP1` Exif block into the accumulating JPEG-level
/// entries / warnings / byte order / `MakerNote`.
///
/// Faithful to bundled processing several independent `APP1` Exif segments in
/// `Marker:`-loop order (`ExifTool.pm:7736-7821`, the arm ending with `next`).
/// Entries are appended in walk order and warnings concatenated; the byte
/// order is taken from the FIRST block that carried one (it is a single
/// `File:ExifByteOrder` tag, and `%noDups` first-wins keeps the first —
/// `ExifTool.pm:2951`). For a tag present in more than one block the document
/// dedup decides the survivor downstream; the merge preserves every entry so
/// that decision is not pre-empted here.
///
/// The block's captured `MakerNote` (0x927c, the ExifIFD blob) is threaded up
/// with the SAME first-wins rule: the first independent `APP1` Exif block that
/// carried a MakerNote keeps it (the primary MakerNote — the real-world camera
/// JPEG carrier). The `'a` lifetime flows from the block (which borrows the
/// JPEG input) through to the accumulator, so the merged `MakerNote` is the
/// borrow of the original input bytes.
fn merge_exif_block<'a>(
  entries: &mut Vec<ExifEntry>,
  warnings: &mut Vec<String>,
  warnings_ignorable: &mut Vec<u8>,
  byte_order: &mut Option<ByteOrder>,
  maker_note: &mut Option<MakerNote<'a>>,
  block: ExifMeta<'a>,
) {
  let (block_entries, block_warnings, block_warnings_ignorable, block_order, block_maker_note) =
    block.into_jpeg_parts();
  if byte_order.is_none() {
    *byte_order = block_order;
  }
  // First captured MakerNote wins (the primary — faithful to ExifTool keeping
  // the first/primary MakerNote across the merged segments).
  if maker_note.is_none() {
    *maker_note = block_maker_note;
  }
  entries.extend(block_entries);
  warnings.extend(block_warnings);
  // Keep the parallel ignorable levels index-aligned with `warnings`.
  warnings_ignorable.extend(block_warnings_ignorable);
}

/// `true` when `block` begins with a BigTIFF header — a valid TIFF byte-order
/// marker (`II` / `MM`) followed by the 16-bit BigTIFF magic `0x2b` in that
/// order. The Exif IFD walker ([`parse_exif_block_with_base`]) deliberately
/// returns `None` for a BigTIFF header (its 8-byte-offset / 64-bit-count
/// layout differs from classic TIFF; a full BigTIFF walker is a deferred
/// port), and bundled DOES support BigTIFF — so the JPEG `APP1` arm must NOT
/// raise its "Malformed APP1 EXIF segment" warning for one. This mirrors the
/// magic gate in [`super::parse_tiff_with_base`]: a genuinely malformed
/// CLASSIC (`0x2a`) header — or any non-TIFF byte-order marker — is NOT a
/// BigTIFF and still warns.
fn is_bigtiff_block(block: &[u8]) -> bool {
  let Some(order) = ByteOrder::from_marker(block) else {
    return false;
  };
  get_u16(block, 2, order) == Some(0x2b)
}

/// Standalone (length-less) JPEG markers — bundled `%markerLenBytes`
/// (`ExifTool.pm:7208-7219`). A marker in this set carries no length word and
/// no payload, so the walk advances straight to the next marker. The J2C
/// 4-byte-length extensions (`0x74`/`0x75`/`0x77`) are NOT in this predicate:
/// they are not standalone, but they only appear in J2C streams (not the
/// camera-JPEG Exif path) and ExifTool's APP1 Exif arm never sees them; the
/// generic 2-byte-length branch below handles any non-standalone marker we
/// encounter before SOS, which is faithful for the markers a real JPEG carries
/// ahead of its image data.
#[inline]
const fn is_standalone_marker(marker: u8) -> bool {
  matches!(
    marker,
    // RST0-RST7, plus 0x00 / 0x01 / TEM, SOI/EOI/SOS, the J2C codestream
    // markers (0x30-0x3f, 0x4f), and 0x92/0x93. (`ExifTool.pm:7208-7219`.)
    0x00 | 0x01
    | 0xd0..=0xda
    | 0x30..=0x3f
    | 0x4f
    | 0x92 | 0x93
  )
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test JPEG/TIFF builders index fixed-layout
// buffers freely (an out-of-range index is a test failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::exif::parse_exif_block;
  use std::vec::Vec;

  /// A minimal big-endian TIFF block: one IFD0 entry `Make = "Canon"`,
  /// no IFD1. Offsets are relative to the block start (the embedded-Exif
  /// contract). Mirrors the IFD0 layout the `exif::mod` tests use.
  fn minimal_tiff() -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    t.extend_from_slice(&[0x00, 0x02]); // ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // value at offset 26
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t.extend_from_slice(b"Canon\0");
    t
  }

  /// Wrap `tiff` in a JPEG: `SOI` + an `APP1` `Exif\0\0` segment + (optional)
  /// extra leading APP0/COM segments + `EOI`. `garbage` leading bytes are
  /// inserted before `Exif\0\0` (the `^(.{0,4})Exif\0.` tolerance).
  fn jpeg_with_app1_exif(tiff: &[u8], garbage: usize, leading: &[(u8, &[u8])]) -> Vec<u8> {
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // Optional leading length-bearing segments (e.g. APP0 JFIF, COM).
    for (marker, payload) in leading {
      j.push(0xff);
      j.push(*marker);
      let len = (payload.len() + 2) as u16;
      j.extend_from_slice(&len.to_be_bytes());
      j.extend_from_slice(payload);
    }
    // APP1: marker, length (covers length word + payload), payload.
    j.push(0xff);
    j.push(0xe1);
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&std::vec![0u8; garbage]);
    payload.extend_from_slice(b"Exif\0\0");
    payload.extend_from_slice(tiff);
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(&payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    j
  }

  #[test]
  fn extracts_exif_from_app1() {
    let tiff = minimal_tiff();
    let j = jpeg_with_app1_exif(&tiff, 0, &[]);
    let meta = parse_jpeg_exif(&j).expect("APP1 Exif decoded");
    assert_eq!(
      meta.entry("Make").map(|e| e.name()),
      Some("Make"),
      "IFD0:Make must be extracted from the JPEG APP1 Exif block"
    );
  }

  #[test]
  fn base_offset_overflow_saturates_no_panic() {
    // `base_offset + seg.payload_start + hdr_len` is summed in `usize` BEFORE
    // the `u32::try_from(...).unwrap_or(u32::MAX)` saturation. A huge
    // caller-supplied `base_offset` (direct-API caller / future container)
    // would overflow `usize` and panic in debug / wrap in release without the
    // `checked_add` guard. With `usize::MAX`, the function must NOT panic and
    // must fall through to the `u32::MAX` saturation — i.e. it still returns
    // `Some` (a valid JPEG is always accepted) and does not unwind.
    let tiff = minimal_tiff();
    let j = jpeg_with_app1_exif(&tiff, 0, &[]);
    let meta = parse_jpeg_exif_with_base(&j, usize::MAX)
      .expect("a valid JPEG is still accepted even with a saturating base_offset");
    // The Exif block still decodes (the overflow only affects the absolute
    // rebase of `IsOffset` tags, which saturates rather than panicking).
    assert_eq!(
      meta.entry("Make").map(|e| e.name()),
      Some("Make"),
      "IFD0:Make is still extracted under a saturating base_offset"
    );

    // Sanity: a near-`usize::MAX` value that still overflows on the inner adds
    // also saturates cleanly (exercises the second `checked_add`).
    assert!(
      parse_jpeg_exif_with_base(&j, usize::MAX - 4).is_some(),
      "near-MAX base_offset must saturate, not panic"
    );
  }

  #[test]
  fn rejects_non_jpeg() {
    // No SOI marker — a standalone TIFF is NOT routed here.
    assert!(parse_jpeg_exif(&minimal_tiff()).is_none());
    assert!(parse_jpeg_exif(b"").is_none());
    assert!(parse_jpeg_exif(b"\xff").is_none());
    assert!(parse_jpeg_exif(b"\x89PNG").is_none());
  }

  #[test]
  fn skips_leading_segments_then_finds_exif() {
    // An APP0 JFIF + a COM comment precede the APP1 Exif — the walk must skip
    // both length-bearing segments and still reach the Exif APP1.
    let tiff = minimal_tiff();
    let j = jpeg_with_app1_exif(
      &tiff,
      0,
      &[
        (0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"),
        (0xfe, b"a comment"),
      ],
    );
    let meta = parse_jpeg_exif(&j).expect("APP1 Exif decoded after leading segments");
    assert!(meta.entry("Make").is_some());
  }

  #[test]
  fn tolerates_garbage_prefix() {
    // `^(.{0,4})Exif\0.` — up to 4 leading garbage bytes before `Exif\0\0`
    // (ExifTool.pm:7739, the Kodak/odd-second-header tolerance).
    for garbage in 0..=4 {
      let tiff = minimal_tiff();
      let j = jpeg_with_app1_exif(&tiff, garbage, &[]);
      let meta =
        parse_jpeg_exif(&j).unwrap_or_else(|| panic!("garbage={garbage} should still decode"));
      assert!(meta.entry("Make").is_some(), "garbage={garbage}");
    }
    // 5 garbage bytes is OUTSIDE the `.{0,4}` window ⇒ the APP1 does NOT match
    // the Exif arm. The JPEG container is still accepted (R17/F1) — `Some`
    // with no entries and no byte order (no TIFF block was processed).
    let j = jpeg_with_app1_exif(&minimal_tiff(), 5, &[]);
    let meta = parse_jpeg_exif(&j).expect("valid JPEG is accepted even with no Exif arm match");
    assert!(meta.entry("Make").is_none(), "5 garbage bytes is not Exif");
    assert!(meta.entries().is_empty());
    assert_eq!(meta.byte_order(), None, "no TIFF block ⇒ no ExifByteOrder");
  }

  /// Wrap `tiff` in a JPEG whose `APP1` payload uses `header` (the 6 bytes in
  /// place of `Exif\0\0`) — for the case-insensitive identifier test.
  fn jpeg_with_app1_header(tiff: &[u8], header: &[u8; 6]) -> Vec<u8> {
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.push(0xff);
    j.push(0xe1);
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(header);
    payload.extend_from_slice(tiff);
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(&payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    j
  }

  #[test]
  fn app1_exif_identifier_is_case_insensitive() {
    // `ExifTool.pm:7750` `/^(.{0,4})Exif\0./is` — the `/i` flag matches the
    // four `Exif` letters case-INSENSITIVELY (the `\0` is unaffected). Bundled
    // accepts `EXIF\0\0`, `exif\0\0`, `eXiF\0\0`, … as the Exif APP1 header.
    for header in [b"EXIF\0\0", b"exif\0\0", b"eXiF\0\0", b"Exif\0\0"] {
      let tiff = minimal_tiff();
      let j = jpeg_with_app1_header(&tiff, header);
      let meta = parse_jpeg_exif(&j)
        .unwrap_or_else(|| panic!("header {header:?} should decode as Exif APP1"));
      assert_eq!(
        meta.entry("Make").map(|e| e.name()),
        Some("Make"),
        "header {header:?} must be recognized case-insensitively"
      );
    }
    // The fifth byte is a LITERAL `\0` (not touched by `/i`); a non-NUL fifth
    // byte (`ExifX…`) must NOT match the Exif arm — the JPEG is still accepted
    // but carries no Exif entries.
    let j = jpeg_with_app1_header(&minimal_tiff(), b"ExifX\0");
    let meta = parse_jpeg_exif(&j).expect("valid JPEG is accepted");
    assert!(
      meta.entry("Make").is_none(),
      "a non-NUL 5th byte is not the Exif identifier"
    );
  }

  #[test]
  fn accepts_jpeg_with_no_app1_exif() {
    // R17/F1: a valid JPEG carrying only an APP1 XMP segment (not Exif),
    // followed by EOI. Bundled `ProcessJPEG` `SetFileType`s the JPEG at
    // ExifTool.pm:7304 regardless of the APP1 Exif arm — so the container is
    // ACCEPTED (`Some`), not rejected. No Exif entries, no byte order.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8, 0xff, 0xe1];
    let payload = b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>";
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("valid JPEG with only XMP is still accepted");
    assert!(
      meta.entries().is_empty(),
      "XMP arm is deferred — no entries"
    );
    assert!(
      meta.warnings().is_empty(),
      "a non-Exif APP1 is not malformed"
    );
    assert_eq!(meta.byte_order(), None);
  }

  #[test]
  fn accepts_jpeg_stopping_at_sos() {
    // SOI then SOS (0xda) — the walk stops at SOS (ExifTool.pm:7339) and never
    // scans the compressed image data. The JPEG is still ACCEPTED (R17/F1).
    let j: Vec<u8> = std::vec![0xff, 0xd8, 0xff, 0xda, 0x00, 0x02];
    let meta = parse_jpeg_exif(&j).expect("valid JPEG (SOI present) is accepted");
    assert!(meta.entries().is_empty());
    assert_eq!(meta.byte_order(), None);
  }

  #[test]
  fn accepts_jpeg_with_truncated_app1() {
    // APP1 declares a length longer than the bytes present ⇒ the truncated
    // read ends the segment scan (ExifTool.pm:7365 `last Marker unless Read`).
    // The JPEG container is still ACCEPTED (R17/F1) — `Some` with no entries.
    let j: Vec<u8> = std::vec![0xff, 0xd8, 0xff, 0xe1, 0x00, 0x40, b'E', b'x'];
    let meta = parse_jpeg_exif(&j).expect("valid JPEG (SOI present) is accepted");
    assert!(meta.entries().is_empty());
    assert_eq!(meta.byte_order(), None);
  }

  #[test]
  fn malformed_app1_exif_records_warning_not_rejection() {
    // R17/F1: an APP1 segment matching the Exif arm (`Exif\0\0` + bytes) whose
    // TIFF block is NOT valid ⇒ bundled `ProcessTIFF(...) or Warn('Malformed
    // APP1 EXIF segment')` (ExifTool.pm:7783). The JPEG is ACCEPTED and the
    // warning is recorded — never a whole-candidate rejection.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8, 0xff, 0xe1];
    let payload = b"Exif\0\0NOT-A-VALID-TIFF-BLOCK";
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("malformed-APP1 JPEG is still accepted");
    assert!(
      meta.entries().is_empty(),
      "a bad TIFF block yields no entries"
    );
    assert_eq!(
      meta.warnings(),
      &[String::from(MALFORMED_APP1_WARNING)],
      "a bad APP1 Exif TIFF block records the Malformed APP1 EXIF segment warning"
    );
    assert_eq!(
      meta.byte_order(),
      None,
      "no TIFF block parsed ⇒ no byte order"
    );
  }

  /// Wrap a raw APP1 `body` (the bytes after `Exif\0\0`) in a one-`APP1`-Exif
  /// JPEG: `SOI` + `APP1`(`Exif\0\0` + `body`) + `EOI`.
  fn jpeg_with_app1_exif_body(body: &[u8]) -> Vec<u8> {
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"Exif\0\0");
    payload.extend_from_slice(body);
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&[0xff, 0xe1]);
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(&payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    j
  }

  #[test]
  fn bigtiff_in_app1_skipped_without_malformed_warning() {
    // Codex R4/F2: the R3 BigTIFF fix makes `parse_exif_block_with_base`
    // return `None` for magic 0x2b — but the JPEG path mapped EVERY `None` to
    // a "Malformed APP1 EXIF segment" warning, so a BigTIFF header inside an
    // `APP1 Exif\0\0` payload produced a FALSE malformed warning. Bundled
    // SUPPORTS BigTIFF, so it raises NO such warning: a BigTIFF block must be
    // skipped SILENTLY (no warning, no Exif), exactly like the standalone-TIFF
    // path's clean BigTIFF skip.

    // Big-endian BigTIFF header (MM, magic 0x002b, bytesize 8, reserved 0,
    // 8-byte IFD0 offset, plus body) — the same shape the `exif::mod`
    // `embedded_bigtiff_magic_is_not_parsed` test uses.
    let mut be: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2b, 0x00, 0x08, 0x00, 0x00];
    be.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]);
    be.extend_from_slice(&[0u8; 32]);
    let j = jpeg_with_app1_exif_body(&be);
    let meta = parse_jpeg_exif(&j).expect("JPEG with a BigTIFF APP1 is still accepted");
    assert!(
      meta.warnings().is_empty(),
      "a BigTIFF APP1 block must NOT emit a Malformed APP1 warning (bundled supports BigTIFF): {:?}",
      meta.warnings()
    );
    assert!(
      meta.entries().is_empty(),
      "a BigTIFF block contributes no classic Exif tags"
    );
    assert_eq!(meta.byte_order(), None, "no classic TIFF block parsed");

    // Little-endian BigTIFF (II, magic 0x2b00, bytesize 8) — same silent skip.
    let mut le: Vec<u8> = std::vec![b'I', b'I', 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00];
    le.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    le.extend_from_slice(&[0u8; 32]);
    let jl = jpeg_with_app1_exif_body(&le);
    let meta_le = parse_jpeg_exif(&jl).expect("LE BigTIFF APP1 JPEG accepted");
    assert!(
      meta_le.warnings().is_empty(),
      "LE BigTIFF APP1 must not warn: {:?}",
      meta_le.warnings()
    );
    assert!(meta_le.entries().is_empty());
  }

  #[test]
  fn malformed_classic_tiff_still_warns_alongside_bigtiff_skip() {
    // The Fix-2 distinction: a genuinely malformed CLASSIC (0x2a) header is NOT
    // a BigTIFF and STILL produces the "Malformed APP1 EXIF segment" warning.
    // Here the header is a valid MM byte order + classic magic 0x2a but an
    // IFD0 offset of 4 (< 8) — `parse_exif_block_with_base` returns `None`
    // (`DoProcessTIFF` `$offset >= 8 or return 0`, ExifTool.pm:8645), and
    // because it is not BigTIFF the JPEG arm warns.
    let bad_classic = [b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x04];
    let j = jpeg_with_app1_exif_body(&bad_classic);
    let meta = parse_jpeg_exif(&j).expect("JPEG with a malformed classic APP1 is accepted");
    assert_eq!(
      meta.warnings(),
      &[String::from(MALFORMED_APP1_WARNING)],
      "a malformed CLASSIC (0x2a) header still warns — only BigTIFF (0x2b) is the silent skip"
    );
    assert!(meta.entries().is_empty());
    assert_eq!(meta.byte_order(), None);

    // A non-TIFF byte-order marker (not `II`/`MM`) is likewise NOT a BigTIFF
    // and still warns (guards the `is_bigtiff_block` byte-order gate).
    let j2 = jpeg_with_app1_exif_body(b"XX\0\x2b\0\0\0\x08");
    let meta2 = parse_jpeg_exif(&j2).expect("accepted");
    assert_eq!(
      meta2.warnings(),
      &[String::from(MALFORMED_APP1_WARNING)],
      "a non-II/MM marker is not a BigTIFF skip — it still warns"
    );
  }

  #[test]
  fn merges_two_independent_app1_exif_blocks() {
    // R17/F2: the marker walk CONTINUES after a successful APP1 Exif parse
    // (ExifTool.pm:7821 `next`). Two independent APP1 Exif blocks — each a
    // self-contained TIFF (`Exif\0\0MM\0\x2a...`) — contribute their tags.
    // Block 1: Make = "Canon"; block 2: Model = "EOS5D" (disjoint tags).
    fn tiff_entry(tag: [u8; 2], value: &[u8; 6]) -> Vec<u8> {
      let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
      t.extend_from_slice(&[0x00, 0x01]); // 1 entry
      t.extend_from_slice(&tag);
      t.extend_from_slice(&[0x00, 0x02]); // ASCII
      t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
      t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // value @ offset 26
      t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
      t.extend_from_slice(value);
      t
    }
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    for tiff in [
      tiff_entry([0x01, 0x0f], b"Canon\0"), // Make
      tiff_entry([0x01, 0x10], b"EOS5D\0"), // Model
    ] {
      let mut payload: Vec<u8> = Vec::new();
      payload.extend_from_slice(b"Exif\0\0");
      payload.extend_from_slice(&tiff);
      let len = (payload.len() + 2) as u16;
      j.push(0xff);
      j.push(0xe1);
      j.extend_from_slice(&len.to_be_bytes());
      j.extend_from_slice(&payload);
    }
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("two-APP1-Exif JPEG decoded");
    assert_eq!(
      meta.entry("Make").map(|e| e.name()),
      Some("Make"),
      "Make from the FIRST independent APP1 Exif block"
    );
    assert_eq!(
      meta.entry("Model").map(|e| e.name()),
      Some("Model"),
      "Model from the SECOND independent APP1 Exif block — the walk continued"
    );
  }

  #[test]
  fn multisegment_exif_chain_is_skipped_silently() {
    // The deferred multi-segment (extended) EXIF assembly: an APP1 Exif chain
    // START (`Exif\0\0MM\0\x2a...`) immediately followed by an APP1 whose
    // payload is `Exif\0\0` NOT followed by a TIFF magic (a continuation
    // fragment). Bundled's discriminator (ExifTool.pm:7764-7765) treats this
    // as multi-segment EXIF; the `$combinedSegData` assembly is deferred, so
    // the whole chain is skipped SILENTLY — no entries, NO spurious malformed
    // warning. The JPEG container itself is still accepted (R17/F1).
    let tiff = minimal_tiff(); // valid `MM\0\x2a` TIFF, Make = Canon
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // Chain-start APP1: `Exif\0\0` + a valid TIFF block.
    {
      let mut p: Vec<u8> = Vec::new();
      p.extend_from_slice(b"Exif\0\0");
      p.extend_from_slice(&tiff);
      let len = (p.len() + 2) as u16;
      j.extend_from_slice(&[0xff, 0xe1]);
      j.extend_from_slice(&len.to_be_bytes());
      j.extend_from_slice(&p);
    }
    // Continuation-fragment APP1: `Exif\0\0` + raw tail (NOT a TIFF magic).
    {
      let p = b"Exif\0\0\x01\x02\x03\x04continuation-tail";
      let len = (p.len() + 2) as u16;
      j.extend_from_slice(&[0xff, 0xe1]);
      j.extend_from_slice(&len.to_be_bytes());
      j.extend_from_slice(p);
    }
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG with a multi-segment EXIF chain is accepted");
    assert!(
      meta.entries().is_empty(),
      "a deferred multi-segment EXIF chain contributes no entries"
    );
    assert!(
      meta.warnings().is_empty(),
      "a deferred chain must NOT emit a spurious Malformed APP1 EXIF segment warning"
    );
    assert_eq!(meta.byte_order(), None);
  }

  #[test]
  fn rebases_thumbnail_offset_by_block_base() {
    // The `IsOffset` rebase (ExifTool.pm:7156-7170): a JPEG-embedded
    // ThumbnailOffset is the raw IFD value plus the TIFF block's file offset.
    // Build a TIFF with IFD0 + an IFD1 carrying ThumbnailOffset (0x0201) = 100
    // and ThumbnailLength (0x0202) = 4.
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry (Make), next-IFD points to IFD1.
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x01, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06]);
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x26]); // Make value @ offset 38
    // next-IFD (IFD1) offset — compute below; placeholder filled after.
    let ifd1_off_pos = t.len();
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    t.extend_from_slice(b"Canon\0"); // @ offset 38 (8+2+12+4+? — see below)
    // Now lay out IFD1 right after the string.
    let ifd1_off = t.len() as u32;
    t.extend_from_slice(&[0x00, 0x02]); // 2 entries
    // ThumbnailOffset (0x0201) int32u count1 value=100.
    t.extend_from_slice(&[0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&100u32.to_be_bytes());
    // ThumbnailLength (0x0202) int32u count1 value=4.
    t.extend_from_slice(&[0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
    t.extend_from_slice(&4u32.to_be_bytes());
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    // Patch the IFD1 offset into IFD0's next-IFD pointer.
    t[ifd1_off_pos..ifd1_off_pos + 4].copy_from_slice(&ifd1_off.to_be_bytes());

    // First integer of a `ThumbnailOffset` entry's decoded value.
    fn thumb_off(meta: &ExifMeta<'_>) -> u64 {
      match meta
        .entry("ThumbnailOffset")
        .expect("ThumbnailOffset present")
        .value_ref()
        .raw()
      {
        crate::exif::ifd::RawValue::U64(v) => v[0],
        other => panic!("ThumbnailOffset is not U64: {other:?}"),
      }
    }

    // Standalone TIFF: base 0 ⇒ ThumbnailOffset stays the raw 100.
    let standalone = parse_exif_block(&t).expect("standalone TIFF");
    assert_eq!(
      thumb_off(&standalone),
      100,
      "standalone base-0 ThumbnailOffset is the raw value"
    );
    // Wrap in JPEG: TIFF block base = 2 (SOI) + 4 (APP1 hdr) + 6 (Exif\0\0) = 12.
    let j = jpeg_with_app1_exif(&t, 0, &[]);
    let embedded = parse_jpeg_exif(&j).expect("JPEG APP1 Exif");
    assert_eq!(
      thumb_off(&embedded),
      112,
      "JPEG-embedded ThumbnailOffset is rebased by base 12 (100 + 12)"
    );
  }

  /// A standalone TIFF carrying an ExifIFD 0x927c MakerNote — mirrors the
  /// `exif::mod` `maker_note_captured_not_parsed` fixture: IFD0 → ExifOffset
  /// (0x8769) → ExifIFD → MakerNote (0x927c, UNDEF, count 8, the 8-byte blob
  /// at offset 44). The MakerNote bytes are captured via an IN-BLOCK offset
  /// (NOT rebased by the block `base`), so a standalone parse and a JPEG-
  /// embedded parse yield byte-identical MakerNote payloads.
  fn tiff_with_maker_note() -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0: 1 entry (ExifOffset 0x8769 → ExifIFD at 26).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x87, 0x69]); // tag 0x8769
    t.extend_from_slice(&[0x00, 0x04]); // LONG
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // ExifIFD offset 26
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
    // ExifIFD at 26: 1 entry (MakerNote 0x927c).
    t.extend_from_slice(&[0x00, 0x01]);
    t.extend_from_slice(&[0x92, 0x7c]); // tag 0x927c MakerNote
    t.extend_from_slice(&[0x00, 0x07]); // UNDEF
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // count 8 (> 4 ⇒ offset)
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]); // value offset 44
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
    // The 8-byte MakerNote blob at offset 44.
    t.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    t
  }

  #[test]
  fn jpeg_preserves_exififd_maker_note() {
    // Codex R4/F1: the JPEG merge path dropped the captured MakerNote — a
    // normal camera JPEG carrying an ExifIFD 0x927c MakerNote lost it
    // (`maker_note()` was `None`), breaking the MakerNotes seam (#75+) for the
    // primary real-world carrier (JPEG). After threading `Option<MakerNote>`
    // through `into_jpeg_parts → merge_exif_block → from_jpeg_parts`, the JPEG
    // path must surface the SAME MakerNote as the standalone-TIFF parse.
    let t = tiff_with_maker_note();
    let expected = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

    // Standalone TIFF: the baseline `maker_note()`.
    let standalone = parse_exif_block(&t).expect("standalone TIFF");
    let std_mn = standalone
      .maker_note()
      .expect("standalone TIFF captures the ExifIFD MakerNote");
    assert_eq!(std_mn.bytes(), expected);

    // JPEG-embedded: the MakerNote must now ALSO be present and IDENTICAL.
    let j = jpeg_with_app1_exif(&t, 0, &[]);
    let embedded = parse_jpeg_exif(&j).expect("JPEG APP1 Exif");
    let jpeg_mn = embedded
      .maker_note()
      .expect("JPEG path must preserve the captured MakerNote (R4/F1)");
    assert_eq!(
      jpeg_mn.bytes(),
      std_mn.bytes(),
      "the JPEG-path MakerNote must match the standalone-TIFF MakerNote byte-for-byte"
    );
    assert_eq!(jpeg_mn.len(), 8);
    // Vendor parsing is still deferred — no `MakerNote` leaf tag either way.
    assert!(embedded.entry("MakerNote").is_none());
  }

  #[test]
  fn jpeg_maker_note_first_block_wins() {
    // First-wins across merged APP1 Exif blocks: when TWO independent APP1
    // Exif blocks each carry a MakerNote, the FIRST (primary) is preserved —
    // faithful to ExifTool keeping the primary MakerNote. Build two blocks
    // with DISTINCT MakerNote payloads and assert the first wins.
    fn tiff_with_mn_payload(blob: [u8; 8]) -> Vec<u8> {
      let mut t = tiff_with_maker_note();
      // The blob sits at offset 44 (the trailing 8 bytes appended last).
      let n = t.len();
      t[n - 8..].copy_from_slice(&blob);
      t
    }
    let first = tiff_with_mn_payload([0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
    let second = tiff_with_mn_payload([0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8]);
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    for tiff in [first, second] {
      let mut payload: Vec<u8> = Vec::new();
      payload.extend_from_slice(b"Exif\0\0");
      payload.extend_from_slice(&tiff);
      let len = (payload.len() + 2) as u16;
      j.extend_from_slice(&[0xff, 0xe1]);
      j.extend_from_slice(&len.to_be_bytes());
      j.extend_from_slice(&payload);
    }
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("two-APP1-Exif JPEG decoded");
    let mn = meta.maker_note().expect("a MakerNote is preserved");
    assert_eq!(
      mn.bytes(),
      &[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8],
      "the FIRST block's MakerNote wins (the primary)"
    );
  }

  /// Build a JPEG carrying a Baseline-DCT `SOF0` (`0xc0`) segment plus a minimal
  /// `APP1` Exif block (so it is a complete, valid JPEG). The SOF payload is a
  /// 3-component frame: precision 8, height 80, width 120, component sampling
  /// factors `0x22`/`0x11`/`0x11` (→ `YCbCrSubSampling` "2 2"). Mirrors the
  /// real `t/images/GPS.jpg` SOF the conformance fixture exercises.
  fn jpeg_with_sof0() -> Vec<u8> {
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // SOF0 (0xc0): length word covers itself + the 15-byte payload (= 17).
    j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11]);
    j.push(0x08); // precision → BitsPerSample
    j.extend_from_slice(&80u16.to_be_bytes()); // height → ImageHeight
    j.extend_from_slice(&120u16.to_be_bytes()); // width → ImageWidth
    j.push(0x03); // 3 components → ColorComponents
    j.extend_from_slice(&[0x01, 0x22, 0x00]); // comp 0: id, sf (hf=2,vf=2), q
    j.extend_from_slice(&[0x02, 0x11, 0x01]); // comp 1: id, sf (hf=1,vf=1), q
    j.extend_from_slice(&[0x03, 0x11, 0x01]); // comp 2: id, sf (hf=1,vf=1), q
    // A minimal APP1 Exif block (IFD0 Make = "Canon") so the JPEG is complete.
    let tiff = minimal_tiff();
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"Exif\0\0");
    payload.extend_from_slice(&tiff);
    j.push(0xff);
    j.push(0xe1);
    let len = (payload.len() + 2) as u16;
    j.extend_from_slice(&len.to_be_bytes());
    j.extend_from_slice(&payload);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    j
  }

  /// Collect the `File:*` SOF tags `ExifMeta::tags` emits for `mode`, as
  /// `(name, rendered-string)` pairs. The value is stringified so the `-j`
  /// PrintConv text and the `-n` raw value are both comparable.
  fn sof_file_tags(
    meta: &ExifMeta<'_>,
    mode: crate::emit::ConvMode,
  ) -> std::collections::BTreeMap<String, String> {
    use crate::emit::Taggable as _;
    use crate::value::TagValue;
    let mut out = std::collections::BTreeMap::new();
    for et in meta.tags(crate::emit::EmitOptions::g1(mode, false)) {
      let tag = et.tag();
      if tag.group_ref().family1() != "File" {
        continue;
      }
      let name = tag.name();
      // Only the six SOF tags (ExifByteOrder is the other File:* tag).
      if !matches!(
        name,
        "ImageWidth"
          | "ImageHeight"
          | "EncodingProcess"
          | "BitsPerSample"
          | "ColorComponents"
          | "YCbCrSubSampling"
      ) {
        continue;
      }
      let rendered = match tag.value_ref() {
        TagValue::U64(n) => n.to_string(),
        TagValue::I64(n) => n.to_string(),
        TagValue::Str(s) => s.to_string(),
        other => std::format!("{other:?}"),
      };
      out.insert(name.to_string(), rendered);
    }
    out
  }

  #[test]
  fn emits_sof_file_tags_print_and_raw() {
    use crate::emit::ConvMode;
    let j = jpeg_with_sof0();
    let meta = parse_jpeg_exif(&j).expect("JPEG with SOF0 decoded");

    // `-j` (PrintConv): EncodingProcess + YCbCrSubSampling are mapped strings;
    // the four dimension tags are bare integers.
    let pj = sof_file_tags(&meta, ConvMode::PrintConv);
    assert_eq!(pj.get("ImageWidth").map(String::as_str), Some("120"));
    assert_eq!(pj.get("ImageHeight").map(String::as_str), Some("80"));
    assert_eq!(pj.get("BitsPerSample").map(String::as_str), Some("8"));
    assert_eq!(pj.get("ColorComponents").map(String::as_str), Some("3"));
    assert_eq!(
      pj.get("EncodingProcess").map(String::as_str),
      Some("Baseline DCT, Huffman coding"),
      "EncodingProcess -j is the SOF PrintConv label for code 0"
    );
    assert_eq!(
      pj.get("YCbCrSubSampling").map(String::as_str),
      Some("YCbCr4:2:0 (2 2)"),
      "YCbCrSubSampling -j maps the raw \"2 2\" via %yCbCrSubSampling"
    );

    // `-n` (ValueConv): EncodingProcess is the raw code; YCbCrSubSampling the
    // raw "h v" string; the dimension tags are unchanged.
    let nj = sof_file_tags(&meta, ConvMode::ValueConv);
    assert_eq!(nj.get("ImageWidth").map(String::as_str), Some("120"));
    assert_eq!(nj.get("ImageHeight").map(String::as_str), Some("80"));
    assert_eq!(nj.get("BitsPerSample").map(String::as_str), Some("8"));
    assert_eq!(nj.get("ColorComponents").map(String::as_str), Some("3"));
    assert_eq!(
      nj.get("EncodingProcess").map(String::as_str),
      Some("0"),
      "EncodingProcess -n is the raw code (marker 0xc0 - 0xc0 = 0)"
    );
    assert_eq!(
      nj.get("YCbCrSubSampling").map(String::as_str),
      Some("2 2"),
      "YCbCrSubSampling -n is the raw component-derived string"
    );
  }

  #[test]
  fn sof_absent_when_no_sof_segment() {
    // A valid JPEG with an APP1 Exif block but NO SOF segment (SOS then EOI)
    // emits NONE of the SOF File:* tags — matching ExifTool's SOF-less crafted
    // fixtures (JPEG_two_app1_exif etc.).
    let tiff = minimal_tiff();
    let j = jpeg_with_app1_exif(&tiff, 0, &[]);
    let meta = parse_jpeg_exif(&j).expect("JPEG decoded");
    assert!(
      sof_file_tags(&meta, crate::emit::ConvMode::PrintConv).is_empty(),
      "no SOF segment ⇒ no File:* SOF tags"
    );
  }

  #[test]
  fn sof_short_payload_emits_nothing() {
    // A SOF0 whose payload is < 6 bytes (only 3 bytes present) is below
    // ExifTool's `next if $length < 6` guard — no tags, no panic.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // SOF0 length = 5 (covers itself + 3 payload bytes).
    j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x05, 0x08, 0x00, 0x50]);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    assert!(
      sof_file_tags(&meta, crate::emit::ConvMode::PrintConv).is_empty(),
      "a SOF payload shorter than 6 bytes emits no tags"
    );
  }

  #[test]
  fn sof_short_then_valid_emits_valid_dims() {
    // A short bogus SOF (`next if $length < 6`) must be SKIPPED, not consumed,
    // so the LATER valid SOF still emits the dimensions (ExifTool.pm:7429-7430).
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // Short SOF1 (0xc1), length 5 -> 3 payload bytes, below the `< 6` guard.
    j.extend_from_slice(&[0xff, 0xc1, 0x00, 0x05, 0x08, 0x00, 0x50]);
    // The real, valid SOF0 (0xc0): 80x120, 3 components (15-byte payload).
    j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11]);
    j.push(0x08);
    j.extend_from_slice(&80u16.to_be_bytes());
    j.extend_from_slice(&120u16.to_be_bytes());
    j.push(0x03);
    j.extend_from_slice(&[0x01, 0x22, 0x00]);
    j.extend_from_slice(&[0x02, 0x11, 0x01]);
    j.extend_from_slice(&[0x03, 0x11, 0x01]);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let tags = sof_file_tags(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      tags.get("ImageWidth").map(String::as_str),
      Some("120"),
      "valid SOF0 after a short bogus SOF must still emit ImageWidth"
    );
    assert_eq!(tags.get("ImageHeight").map(String::as_str), Some("80"));
  }

  #[test]
  fn sof_grayscale_has_no_ycbcr_subsampling() {
    // A 1-component (grayscale) SOF0 still emits the 5 base tags but NOT
    // YCbCrSubSampling (`next unless $n == 3`, ExifTool.pm:7438).
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // SOF0, payload 9 bytes: precision 8, h 16, w 16, 1 component (id, sf, q).
    j.extend_from_slice(&[0xff, 0xc0, 0x00, 0x0b]);
    j.push(0x08);
    j.extend_from_slice(&16u16.to_be_bytes());
    j.extend_from_slice(&16u16.to_be_bytes());
    j.push(0x01); // 1 component
    j.extend_from_slice(&[0x01, 0x11, 0x00]);
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("grayscale JPEG accepted");
    let pj = sof_file_tags(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(pj.get("ColorComponents").map(String::as_str), Some("1"));
    assert_eq!(pj.get("ImageWidth").map(String::as_str), Some("16"));
    assert!(
      !pj.contains_key("YCbCrSubSampling"),
      "a 1-component frame has no YCbCrSubSampling"
    );
  }

  // ====================================================================
  // DJI auxiliary APP segments (#114 — Codex R1 findings 1/2/3)
  // ====================================================================

  /// A minimal big-endian TIFF block with a single IFD0 entry `Make = "DJI"`
  /// (NUL-padded to 4 bytes so it is INLINE in the value field — no out-of-line
  /// offset). The decoder NUL-trims it to `"DJI"`, matching the
  /// `$$self{Make} eq 'DJI'` gate.
  fn dji_make_tiff() -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    t.extend_from_slice(&[0x00, 0x02]); // ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4 (fits inline)
    t.extend_from_slice(b"DJI\0"); // inline value "DJI\0"
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t
  }

  /// A `DJI::ThermalParams2` `APP4` payload: the `\x2c\x01\x20\0` magic at
  /// payload offset 32 (so the decoder's `dir_start` is 0), and the
  /// little-endian `float` RelativeHumidity at directory offset 0x0c. The
  /// preceding 12 bytes (0x00..0x0c — AmbientTemperature/ObjectDistance/
  /// Emissivity) are left zero; the magic word lands at 32 regardless.
  fn dji_thermal_params2_app4(humidity_le: [u8; 4]) -> Vec<u8> {
    let mut p = std::vec![0u8; 36];
    // RelativeHumidity float @ dir_start(0) + 0x0c.
    p[0x0c..0x10].copy_from_slice(&humidity_le);
    // The ThermalParams2 magic `\x2c\x01\x20\0` at offset 32 (dir_start => 0).
    p[32..36].copy_from_slice(&[0x2c, 0x01, 0x20, 0x00]);
    p
  }

  /// Build a JPEG `APP` segment (`0xff`, `marker`, 2-byte BE length, payload).
  fn app_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut seg: Vec<u8> = std::vec![0xff, marker];
    let len = (payload.len() + 2) as u16;
    seg.extend_from_slice(&len.to_be_bytes());
    seg.extend_from_slice(payload);
    seg
  }

  /// One `APP1` `Exif\0\0` segment wrapping `tiff`.
  fn app1_exif_segment(tiff: &[u8]) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"Exif\0\0");
    payload.extend_from_slice(tiff);
    app_segment(0xe1, &payload)
  }

  /// Collect every emitted tag's rendered value keyed by `(family1, name)` —
  /// the JPEG `APP` (JFIF/MPF/DJI) tags appear here alongside EXIF.
  fn emitted_by_group(
    meta: &ExifMeta<'_>,
    mode: crate::emit::ConvMode,
  ) -> std::collections::BTreeMap<(String, String), String> {
    use crate::emit::Taggable as _;
    use crate::value::TagValue;
    let mut out = std::collections::BTreeMap::new();
    for et in meta.tags(crate::emit::EmitOptions::g1(mode, false)) {
      let tag = et.tag();
      let key = (
        tag.group_ref().family1().to_string(),
        tag.name().to_string(),
      );
      let rendered = match tag.value_ref() {
        TagValue::U64(n) => n.to_string(),
        TagValue::I64(n) => n.to_string(),
        TagValue::F64(n) => crate::value::format_g(*n, 15),
        TagValue::Str(s) => s.to_string(),
        other => std::format!("{other:?}"),
      };
      out.insert(key, rendered);
    }
    out
  }

  #[test]
  fn dji_thermal_params2_emitted_for_normal_marker_order() {
    // The NORMAL DJI layout — `APP1` Exif `Make=DJI` THEN `APP4`
    // ThermalParams2 — passes the marker-order `$$self{Make} eq 'DJI'` gate, so
    // the DJI:* thermal tags ARE emitted.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff()));
    // humidity raw 0.5 -> 50.0% -> "50 %" (the real-fixture value).
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      pj.get(&("DJI".to_string(), "RelativeHumidity".to_string()))
        .map(String::as_str),
      Some("50 %"),
      "APP4 ThermalParams2 after APP1 Make=DJI must emit DJI:RelativeHumidity"
    );
  }

  #[test]
  fn dji_thermal_params2_skipped_when_app4_precedes_make_dji() {
    // Reordered (recovered / partially-repaired) JPEG: `APP4` ThermalParams2
    // BEFORE the `APP1` Exif `Make=DJI` segment. ExifTool evaluates
    // `$$self{Make} eq 'DJI'` INSIDE its Marker: loop, so `$$self{Make}` is not
    // yet `'DJI'` when the APP4 is reached — the DJI thermal arm is SKIPPED. No
    // DJI:* tag may be emitted.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    // APP4 ThermalParams2 FIRST (before any Make).
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    // THEN the APP1 Exif block establishing Make=DJI.
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff()));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert!(
      !pj.keys().any(|(family1, _)| family1 == "DJI"),
      "an APP4 ThermalParams2 ahead of the APP1 Make=DJI must emit NO DJI tags \
       (marker-order $$self{{Make}} gate), got: {pj:?}"
    );
    // The IFD0:Make IS still extracted (the EXIF block is merged regardless).
    assert_eq!(meta.entry("Make").map(|e| e.name()), Some("Make"));
  }

  /// A big-endian TIFF whose IFD0 carries an inline `Make` of exactly the 4
  /// ASCII bytes `make` (e.g. `b"DJI "` — `DJI` + a trailing SPACE), no IFD1.
  /// The `Exif.pm:585` `Make` `RawConv` (`s/\s+$//`) trims the trailing
  /// whitespace, so the captured `$$self{Make}` is the trimmed string.
  fn ifd0_make4_tiff(make: [u8; 4]) -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    t.extend_from_slice(&[0x00, 0x02]); // ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4 (fits inline)
    t.extend_from_slice(&make); // inline 4-byte value
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t
  }

  /// A big-endian TIFF whose IFD0 carries a READABLE NON-STRING `Make` — tag
  /// `0x010f` encoded as `SHORT[2]` (`int16u`), value `1 2`. ExifTool's `Make`
  /// `RawConv` (`$val =~ s/\s+$//; $$self{Make} = $val`, `Exif.pm:585`) runs
  /// whenever the `Make` TAG is seen, NOT only for an `ascii` format, so this
  /// decodes through `ReadValue` to the space-joined `$val` `"1 2"` and
  /// assigns `$$self{Make} = "1 2"` — a readable Make that does NOT stringify
  /// to `'DJI'`. It must therefore CLEAR a prior DJI gate state (the
  /// non-string-Make edge), not preserve it like an absent Make does.
  fn ifd0_make_short_tiff() -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    t.extend_from_slice(&[0x00, 0x03]); // SHORT (int16u) — a NON-string format
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // count 2 (4 bytes, fits inline)
    t.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]); // inline BE SHORT[2] = 1, 2
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t
  }

  /// A big-endian TIFF whose IFD0 has NO `Make` (one benign `Orientation`
  /// entry) but whose IFD1 (reached via the next-IFD pointer) carries
  /// `Make='DJI'`. ExifTool stores `$$self{Make}` ONLY from the top-level IFD0
  /// walk (`Exif.pm:585`), so an IFD1 `Make` must NOT set it — the captured
  /// `Make` stays `None`, and the DJI thermal gate stays off.
  fn ifd1_only_make_dji_tiff() -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
    // IFD0 @8: one Orientation (0x0112, SHORT, value 1) — no Make.
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x12]); // tag 0x0112 Orientation
    t.extend_from_slice(&[0x00, 0x03]); // SHORT
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    t.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // value 1 (BE SHORT, left-justified)
    // Next-IFD pointer -> IFD1 at offset 26.
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]);
    // IFD1 @26: one Make=DJI inline.
    t.extend_from_slice(&[0x00, 0x01]); // 1 entry
    t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
    t.extend_from_slice(&[0x00, 0x02]); // ASCII
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    t.extend_from_slice(b"DJI\0"); // inline "DJI\0"
    t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    t
  }

  #[test]
  fn dji_thermal_params2_skipped_when_later_app1_make_is_non_dji() {
    // The MUTABLE `$$self{Make}` state: `APP1` Make=DJI, THEN a later `APP1`
    // Make=Canon, THEN `APP4` ThermalParams2. ExifTool updates `$$self{Make}`
    // from each `APP1`'s IFD0 `Make` as it walks the Marker: loop (last-wins),
    // so its CURRENT Make at the `APP4` is `Canon` — the DJI thermal arm is
    // SKIPPED. A gate that merely latched "the first APP1 was DJI" would WRONGLY
    // emit the thermal tags here; the per-segment current-Make state must not.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff())); // APP1 Make=DJI
    j.extend_from_slice(&app1_exif_segment(&minimal_tiff())); // APP1 Make=Canon
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert!(
      !pj.keys().any(|(family1, _)| family1 == "DJI"),
      "a later non-DJI APP1 (Make=Canon) flips $$self{{Make}} off, so an APP4 \
       ThermalParams2 after it must emit NO DJI tags, got: {pj:?}"
    );
  }

  #[test]
  fn dji_thermal_params2_skipped_when_make_is_ifd1_only() {
    // `Make='DJI'` lives ONLY in IFD1; IFD0 has no Make. ExifTool's
    // `$$self{Make}` is set from the IFD0 walk alone (`Exif.pm:585`), so it is
    // never `'DJI'` here — the `APP4` ThermalParams2 DJI arm is SKIPPED. A gate
    // that scanned ALL entries by name (the pre-fix `exif_ifd0_make_is_dji`)
    // would WRONGLY accept the IFD1 `Make`; the IFD0-only capture must not.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&ifd1_only_make_dji_tiff()));
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert!(
      !pj.keys().any(|(family1, _)| family1 == "DJI"),
      "an IFD1-only Make=DJI must NOT arm the DJI thermal gate (IFD0 $$self{{Make}} \
       is what gates), got: {pj:?}"
    );
  }

  #[test]
  fn dji_thermal_params2_emitted_when_no_make_app1_preserves_prior_dji() {
    // The MUTABLE `$$self{Make}` is NEVER cleared by an absent `Make`: `APP1`
    // Make=DJI (arms the state), THEN an independent `APP1` with NO IFD0 `Make`
    // (here an IFD1-only `Make`, so its `captured_make` is `None`), THEN `APP4`
    // ThermalParams2. ExifTool runs `$$self{Make} = $val` ONLY when an IFD0
    // `Make` tag is seen (`Exif.pm:585`), so the no-IFD0-Make `APP1` LEAVES the
    // prior `'DJI'` state intact — the gate must stay armed and the DJI:* thermal
    // tags MUST still be emitted at the `APP4`. A gate that overwrote the state
    // for EVERY parsed `APP1` (treating `captured_make == None` as an explicit
    // non-DJI Make) would WRONGLY clear the DJI state here and suppress the tags.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff())); // APP1 Make=DJI (arms)
    // An APP1 with NO IFD0 Make (IFD1-only Make) -> captured_make None -> the
    // marker-state Make is carried forward unchanged (still DJI), not cleared.
    j.extend_from_slice(&app1_exif_segment(&ifd1_only_make_dji_tiff()));
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      pj.get(&("DJI".to_string(), "RelativeHumidity".to_string()))
        .map(String::as_str),
      Some("50 %"),
      "an APP1 with no IFD0 Make must NOT clear the prior DJI $$self{{Make}} state, \
       so an APP4 ThermalParams2 after it still emits the DJI thermal tags, got: {pj:?}"
    );
  }

  #[test]
  fn dji_thermal_params2_skipped_when_later_app1_make_is_non_string() {
    // The marker-state Make edge where the LATER `Make` is READABLE but NOT a
    // string: `APP1` Make=DJI (arms the gate), THEN an `APP1` whose IFD0 `Make`
    // (`0x010f`) is encoded as a NUMERIC `SHORT[2]` (`int16u`, value `1 2`),
    // THEN `APP4` ThermalParams2. ExifTool's `Make` `RawConv`
    // (`$val =~ s/\s+$//; $$self{Make} = $val`, `Exif.pm:585`) runs whenever the
    // `Make` TAG is seen — NOT only when the format is `ascii` — so the SHORT
    // `Make` decodes through `ReadValue` and assigns `$$self{Make}` its
    // space-joined `$val` `"1 2"`. That is a readable, non-`'DJI'` Make: it must
    // CLEAR the prior DJI state, so the `APP4` ThermalParams2 emits NO DJI tags.
    // Contrast `*_when_no_make_app1_preserves_prior_dji` (an ABSENT Make leaves
    // the state intact); a readable non-string Make is a SEEN Make and clears.
    // The pre-fix capture taps only `RawValue::Text`, so the SHORT `Make` left
    // `captured_make == None`, the prior DJI state survived, and the thermal
    // tags were WRONGLY emitted.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff())); // APP1 Make=DJI (arms)
    // APP1 with a READABLE NON-STRING IFD0 Make (SHORT[2] = 1 2) -> $$self{Make}
    // becomes "1 2" (a seen, non-DJI Make) -> the DJI gate flips OFF.
    j.extend_from_slice(&app1_exif_segment(&ifd0_make_short_tiff()));
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert!(
      !pj.keys().any(|(family1, _)| family1 == "DJI"),
      "a later APP1 whose IFD0 Make is a readable non-string value (SHORT[2]) \
       still assigns $$self{{Make}} (its stringified $val), so it CLEARS the \
       prior DJI state — an APP4 ThermalParams2 after it must emit NO DJI tags, \
       got: {pj:?}"
    );
    // The IFD0:Make IS still extracted from the second APP1 (the EXIF block is
    // merged regardless of the gate); it is rendered as the numeric $val.
    assert_eq!(meta.entry("Make").map(|e| e.name()), Some("Make"));
  }

  #[test]
  fn dji_thermal_params2_emitted_for_ifd0_make_dji_trailing_space() {
    // IFD0 `Make='DJI '` (a trailing SPACE). The `Exif.pm:585` `Make` `RawConv`
    // (`s/\s+$//`) trims it to `'DJI'`, so `$$self{Make} eq 'DJI'` is TRUE and the
    // `APP4` ThermalParams2 DJI arm fires. Reusing the main walker's trimmed
    // `captured_make` (not a raw byte compare) is what makes this match.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&ifd0_make4_tiff(*b"DJI ")));
    j.extend_from_slice(&app_segment(
      0xe4,
      &dji_thermal_params2_app4(0.5f32.to_le_bytes()),
    ));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      pj.get(&("DJI".to_string(), "RelativeHumidity".to_string()))
        .map(String::as_str),
      Some("50 %"),
      "IFD0 Make='DJI ' (trailing space) must trim to 'DJI' and emit the DJI \
       thermal tags"
    );
  }

  #[test]
  fn dji_relative_humidity_uses_g6_not_g15() {
    // ExifTool's RelativeHumidity PrintConv is `sprintf("%g %%", $val*100)`;
    // Perl `%g` defaults to SIX significant digits. The crafted raw float
    // 0.123456 (LE 0x80 0xd6 0xfc 0x3d) decodes to f32 ~0.1234560013, so
    // `$val*100` ~= 12.34560013:
    //   %g  (6 sig) => "12.3456"   (what ExifTool emits, verified against the
    //                               bundled `exiftool`),
    //   %.15g       => "12.3456001281738" (the pre-fix output — WRONG).
    // The fix must produce the 6-sig-digit form.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff()));
    let humidity = [0x80u8, 0xd6, 0xfc, 0x3d]; // f32 0.123456 little-endian
    j.extend_from_slice(&app_segment(0xe4, &dji_thermal_params2_app4(humidity)));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      pj.get(&("DJI".to_string(), "RelativeHumidity".to_string()))
        .map(String::as_str),
      Some("12.3456 %"),
      "RelativeHumidity must render with %g's 6 significant digits (matching \
       `exiftool`), not %.15g"
    );
  }

  #[test]
  fn malformed_short_app_segments_no_panic() {
    // Truncated / short APP2 (MPF), APP3, APP4 and APP5 segments must be handled
    // gracefully (no panic, no out-of-bounds): the DJI gate is active (Make=DJI)
    // and every auxiliary decoder bails on a too-short payload via its
    // `payload.get(..)` guards.
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app1_exif_segment(&dji_make_tiff()));
    // APP2 "MPF\0" header only — no TIFF body (process_mpf's `payload.get(4..)`
    // yields an empty slice; the byte-order marker probe fails -> bail).
    j.extend_from_slice(&app_segment(0xe2, b"MPF\0"));
    // APP2 with a 1-byte truncated TIFF (no full byte-order marker).
    j.extend_from_slice(&app_segment(0xe2, b"MPF\0I"));
    // APP3 raw thermal: a 1-byte payload (consecutive-run sum stays tiny).
    j.extend_from_slice(&app_segment(0xe3, &[0x00]));
    // APP4 ThermalParams2 too short for the offset-32/64 magic probe -> bail
    // (the `payload.get(32..36)` / `get(64..68)` both yield None).
    j.extend_from_slice(&app_segment(0xe4, &[0x01, 0x02, 0x03]));
    // APP5 ThermalCalibration: empty payload.
    j.extend_from_slice(&app_segment(0xe5, &[]));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI
    // Must not panic in either conv mode.
    let meta = parse_jpeg_exif(&j).expect("JPEG accepted despite short APP segments");
    let pj = emitted_by_group(&meta, crate::emit::ConvMode::PrintConv);
    let nj = emitted_by_group(&meta, crate::emit::ConvMode::ValueConv);
    // The short APP4 produced no ThermalParams2 tags; the empty/short APP3/APP5
    // still emit their combined-blob binary placeholders (0-/1-byte length is a
    // valid combined-run sum), so we only assert no thermal-PARAM tag leaked and
    // that the call returned without panicking.
    assert!(
      !pj.contains_key(&("DJI".to_string(), "RelativeHumidity".to_string())),
      "a too-short APP4 must not emit RelativeHumidity"
    );
    let _ = nj; // exercised the -n path for panics too
  }

  #[test]
  fn mpf_image_start_rebased_by_base_offset() {
    // `MPImageStart` (`IsOffset => '$val'`) is rebased to an ABSOLUTE file
    // offset by the MPF TIFF Base = base_offset + payload_start + 4. A JPEG
    // recovered after a leading header (base_offset > 0) must therefore report
    // the skipped bytes in a non-zero MPImageStart; base_offset == 0 leaves it
    // at payload_start + 4 (the offset-0 case the goldens pin).
    //
    // Build a little-endian MPF APP2 with one MP entry whose MPImageStart raw
    // value is 0x1000, then parse the SAME JPEG body at base_offset 0 and at a
    // non-zero base_offset and confirm the emitted MPImageStart shifts by
    // exactly the base_offset delta.
    fn mpf_app2_payload() -> Vec<u8> {
      // "MPF\0" + little-endian classic TIFF.
      let mut p: Vec<u8> = Vec::new();
      p.extend_from_slice(b"MPF\0");
      let tiff_start = p.len();
      p.extend_from_slice(&[b'I', b'I', 0x2a, 0x00]); // II, 0x2a
      // IFD0 offset = 8 (relative to tiff start).
      p.extend_from_slice(&8u32.to_le_bytes());
      // IFD0 @ tiff_start + 8: 1 entry.
      p.extend_from_slice(&1u16.to_le_bytes());
      // Entry: tag 0xb002 MPImageList, format undef(7), count 16, value-offset.
      p.extend_from_slice(&0xb002u16.to_le_bytes());
      p.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
      p.extend_from_slice(&16u32.to_le_bytes()); // 16 bytes => out-of-line
      // The 16-byte MP-entry list goes right after the IFD (count + 1 entry +
      // next-IFD long): offset = 8 + 2 + 12 + 4 = 26 (relative to tiff start).
      let list_off = 26u32;
      p.extend_from_slice(&list_off.to_le_bytes());
      // next-IFD = 0.
      p.extend_from_slice(&0u32.to_le_bytes());
      assert_eq!(
        p.len() - tiff_start,
        list_off as usize,
        "list offset layout"
      );
      // The 16-byte MP entry: packed flags/format/type @0, length @4,
      // MPImageStart @8 = 0x1000, dep1/dep2 @12/14.
      p.extend_from_slice(&0u32.to_le_bytes()); // packed (type=0 => no preview)
      p.extend_from_slice(&100u32.to_le_bytes()); // MPImageLength
      p.extend_from_slice(&0x1000u32.to_le_bytes()); // MPImageStart raw
      p.extend_from_slice(&0u16.to_le_bytes()); // dep1
      p.extend_from_slice(&0u16.to_le_bytes()); // dep2
      p
    }
    let mut j: Vec<u8> = std::vec![0xff, 0xd8]; // SOI
    j.extend_from_slice(&app_segment(0xe2, &mpf_app2_payload()));
    j.extend_from_slice(&[0xff, 0xd9]); // EOI

    // The APP2 payload begins after SOI(2) + marker(2) + length(2) = byte 6, so
    // payload_start == 6; the MPF TIFF base at offset 0 is 6 + 4 = 10, and the
    // rebased MPImageStart is 0x1000 + 10 = 4106.
    let meta0 = parse_jpeg_exif_with_base(&j, 0).expect("base 0 JPEG accepted");
    let g0 = emitted_by_group(&meta0, crate::emit::ConvMode::ValueConv);
    let start0: u64 = g0
      .get(&("MPImage1".to_string(), "MPImageStart".to_string()))
      .expect("MPImage1:MPImageStart present")
      .parse()
      .expect("numeric MPImageStart");
    assert_eq!(
      start0,
      0x1000 + 6 + 4,
      "base 0 rebases by payload_start+4 only"
    );

    // The same body recovered after a 0x40 = 64-byte leading header: every
    // absolute offset shifts by exactly 64.
    let base = 0x40usize;
    let meta1 = parse_jpeg_exif_with_base(&j, base).expect("base>0 JPEG accepted");
    let g1 = emitted_by_group(&meta1, crate::emit::ConvMode::ValueConv);
    let start1: u64 = g1
      .get(&("MPImage1".to_string(), "MPImageStart".to_string()))
      .expect("MPImage1:MPImageStart present")
      .parse()
      .expect("numeric MPImageStart");
    assert_eq!(
      start1,
      start0 + base as u64,
      "base_offset must be threaded into the MPF Base so MPImageStart is absolute"
    );
  }
}
