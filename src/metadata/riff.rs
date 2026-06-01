// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Domain projection of RIFF / AVI metadata onto [`MediaMetadata`].
//!
//! The faithful-parse layer ([`crate::formats::riff::RiffMeta`]) owns the
//! emitted RIFF tags + per-stream records. This module builds the
//! camera-metadata projection from it: AVI fixtures typically carry
//! `INFO/ISFT` (Software) and `IDIT` (DateTimeOriginal), plus AVI header
//! dimensions/duration via the per-stream `strh` records. Camera-side
//! Make/Model live in the optional `LIST_exif` sub-chunks (RIFF.pm:1013-
//! 1027 `%RIFF::Exif` — `ecor`/`emdl`).
//!
//! D8 + no public fields convention applies — the [`crate::metadata::
//! MediaMetadata`] aggregate is read-through the existing accessors.

#![cfg(feature = "riff")]

use core::time::Duration;

use crate::formats::riff::{RiffMeta, RiffValue};
use crate::metadata::domain::{CameraInfo, MediaMetadata, TrackKind};

/// Build a [`MediaMetadata`] projection from a [`RiffMeta`] faithful-parse
/// layer.
///
/// Fills:
/// - [`MediaInfo::width`] / [`MediaInfo::height`] from AVI header
///   `RIFF:ImageWidth`/`RIFF:ImageHeight` (RIFF.pm:1106-1107).
/// - [`MediaInfo::duration`] from `RIFF:FrameCount` / `RIFF:FrameRate`
///   (AVI's FrameRate is the inverted `us-per-frame`, ProcessRIFF after
///   AVIHeader, RIFF.pm:1081-1086).
/// - [`MediaInfo::created`] from `RIFF:DateTimeOriginal` (IDIT, RIFF.pm:526-
///   532). The string is already converted to `YYYY:MM:DD HH:MM:SS` via
///   `ConvertRIFFDate`.
/// - [`MediaInfo::track_kinds`] from each [`RiffStream::stream_type`] —
///   `vids` → [`TrackKind::Video`], `auds` → [`TrackKind::Audio`], `txts` →
///   [`TrackKind::Subtitle`], everything else → [`TrackKind::Other`].
/// - [`CameraInfo::software`] from `RIFF:Software` (ISFT, RIFF.pm:869-874).
/// - [`CameraInfo::make`] / [`CameraInfo::model`] from `RIFF:Make` / `RIFF:Model`
///   (LIST_exif `ecor`/`emdl`, RIFF.pm:1020-1021).
pub fn from_riff(riff: &RiffMeta<'_>) -> MediaMetadata {
  let mut out = MediaMetadata::new();
  let mut camera = CameraInfo::new();

  // Walk the typed entries to fill the domain layer.
  let mut frame_rate: Option<f64> = None;
  let mut frame_count: Option<u32> = None;
  let mut video_frame_rate: Option<f64> = None;
  let mut video_frame_count: Option<u32> = None;
  for entry in riff.entries() {
    match (entry.group(), entry.name(), entry.value_ref()) {
      ("RIFF", "ImageWidth", &RiffValue::U32(w)) => {
        out.media_mut().update_width(Some(w));
      }
      ("RIFF", "ImageHeight", &RiffValue::U32(h)) => {
        out.media_mut().update_height(Some(h));
      }
      ("RIFF", "FrameRate", &RiffValue::F64(r)) => frame_rate = Some(r),
      ("RIFF", "FrameCount", &RiffValue::U32(c)) => frame_count = Some(c),
      ("RIFF", "VideoFrameRate", &RiffValue::F64(r)) => video_frame_rate = Some(r),
      ("RIFF", "VideoFrameCount", &RiffValue::U32(c)) => video_frame_count = Some(c),
      ("RIFF", "DateTimeOriginal", RiffValue::Str(s)) => {
        out.media_mut().update_created(Some(s.as_str().to_string()));
      }
      ("RIFF", "Software", RiffValue::Str(s)) => {
        camera.update_software(Some(s.as_str().to_string()));
      }
      ("RIFF", "Make", RiffValue::Str(s)) => {
        camera.update_make(Some(s.as_str().to_string()));
      }
      ("RIFF", "Model", RiffValue::Str(s)) => {
        camera.update_model(Some(s.as_str().to_string()));
      }
      _ => {}
    }
  }

  // Duration projection — faithful port of the Composite `Duration` /
  // `CalcDuration` decision logic (RIFF.pm:1548-1560, 1645-1693):
  //   `$dur1 = FrameCount / FrameRate` (Require'd: RIFF:FrameRate +
  //   RIFF:FrameCount). When BOTH VideoFrameRate and VideoFrameCount are
  //   present (Desire'd), `$dur2 = VideoFrameCount / VideoFrameRate` and
  //   `$rat = $dur1 / $dur2`; if `1.9 < $rat < 3.1` the AVI-header duration
  //   is 2-3x too long (multi-track FrameCount, e.g. FujiFilm REAL 3D), so
  //   `$dur1 = $dur2` — switch to the video-stream value (RIFF.pm:1652-1663).
  //
  // The concatenated-RIFF accumulation (summing `$totalDuration` over
  // `$$et{DOC_COUNT}` sub-documents, RIFF.pm:1665-1690) is OMITTED: this port
  // is single-document — the mid-stream `RIFF` re-trigger does not increment
  // `DOC_NUM` and no per-sub-document tag values are retained, so the extra
  // terms cannot be represented. A missing-extra-term duration is faithful
  // for the common single-segment AVI (which is `DOC_COUNT == 0` ⇒ the loop
  // runs once anyway); a concatenated AVI would under-report (documented gap,
  // exifast-phase2-forward-items.md), which is preferable to a wrong sum.
  if let (Some(fr), Some(fc)) = (frame_rate, frame_count)
    && fr > 0.0
  {
    let mut dur1 = fc as f64 / fr;
    if let (Some(vfr), Some(vfc)) = (video_frame_rate, video_frame_count)
      && vfr > 0.0
    {
      let dur2 = vfc as f64 / vfr;
      if dur2 > 0.0 {
        let rat = dur1 / dur2;
        if rat > 1.9 && rat < 3.1 {
          dur1 = dur2;
        }
      }
    }
    if dur1.is_finite() && dur1 >= 0.0 {
      out
        .media_mut()
        .update_duration(Some(Duration::from_secs_f64(dur1)));
    }
  }

  // Track-kinds from per-stream records.
  for stream in riff.streams() {
    if let Some(t) = stream.stream_type() {
      let kind = match t {
        "vids" => TrackKind::Video,
        "auds" => TrackKind::Audio,
        "txts" => TrackKind::Subtitle,
        other => TrackKind::Other(other.to_string()),
      };
      out.media_mut().track_kinds_mut().push(kind);
    }
  }

  if !camera.is_empty() {
    out.set_camera(camera);
  }
  out
}

/// Surface the [`from_riff`] projection on [`MediaMetadata`] for symmetry
/// with [`MediaMetadata::from_quicktime`]. Provided as a free function +
/// re-exported via the `metadata` module's `pub use`.
impl MediaMetadata {
  /// Build the projection from a RIFF faithful-parse layer. See
  /// [`crate::metadata::riff::from_riff`] for the field-by-field mapping.
  #[must_use]
  pub fn from_riff(riff: &RiffMeta<'_>) -> Self {
    from_riff(riff)
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

/// Project RIFF/AVI metadata onto the normalized [`MediaMetadata`] domain
/// (the golden-pattern **L2** seam). Reuses [`MediaMetadata::from_riff`] —
/// the field-by-field mapping (AVI header dimensions, FrameCount/FrameRate
/// duration, `IDIT` created, `ISFT` software, `LIST_exif` Make/Model,
/// per-stream track-kinds). Mirrors how the QuickTime port's `Project` impl
/// reuses [`MediaMetadata::from_quicktime`].
impl crate::metadata::Project for RiffMeta<'_> {
  fn project(&self) -> MediaMetadata {
    from_riff(self)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::formats::riff::parse_borrowed;
  use std::vec::Vec;

  fn minimal_avi_bytes() -> Vec<u8> {
    // A tiny synthetic AVI exercising the projection: dimensions, frames,
    // software, IDIT.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"AVI ");
    // LIST hdrl -> avih
    buf.extend_from_slice(b"LIST");
    let hdrl_size_off = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    let hdrl_start = buf.len();
    buf.extend_from_slice(b"hdrl");
    buf.extend_from_slice(b"avih");
    buf.extend_from_slice(&40u32.to_le_bytes());
    // us-per-frame = 66667 → FrameRate = 15.000150... (avoid degenerate)
    buf.extend_from_slice(&66667u32.to_le_bytes()); // 0
    buf.extend_from_slice(&0u32.to_le_bytes()); // 1: MaxDataRate
    buf.extend_from_slice(&0u32.to_le_bytes()); // 2
    buf.extend_from_slice(&0u32.to_le_bytes()); // 3
    buf.extend_from_slice(&90u32.to_le_bytes()); // 4: FrameCount=90
    buf.extend_from_slice(&0u32.to_le_bytes()); // 5
    buf.extend_from_slice(&1u32.to_le_bytes()); // 6: StreamCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7
    buf.extend_from_slice(&320u32.to_le_bytes()); // 8: ImageWidth
    buf.extend_from_slice(&240u32.to_le_bytes()); // 9: ImageHeight
    let hdrl_size = (buf.len() - hdrl_start) as u32;
    buf[hdrl_size_off..hdrl_size_off + 4].copy_from_slice(&hdrl_size.to_le_bytes());
    // LIST INFO with ISFT.
    buf.extend_from_slice(b"LIST");
    let info_size_off = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    let info_start = buf.len();
    buf.extend_from_slice(b"INFO");
    buf.extend_from_slice(b"ISFT");
    buf.extend_from_slice(&5u32.to_le_bytes());
    buf.extend_from_slice(b"Acme\0");
    buf.push(0); // odd pad? len=5 -> pad=1
    let info_size = (buf.len() - info_start) as u32;
    buf[info_size_off..info_size_off + 4].copy_from_slice(&info_size.to_le_bytes());
    // IDIT.
    buf.extend_from_slice(b"IDIT");
    let payload = b"Mon Mar 10 15:04:43 2003\0\0";
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());
    buf
  }

  #[test]
  fn from_riff_fills_media_info() {
    let bytes = minimal_avi_bytes();
    let meta = parse_borrowed(&bytes).expect("some");
    let projected = MediaMetadata::from_riff(&meta);
    assert_eq!(projected.media().width(), Some(320));
    assert_eq!(projected.media().height(), Some(240));
    assert_eq!(projected.media().created(), Some("2003:03:10 15:04:43"));
    let dur = projected.media().duration().expect("duration");
    // 90 frames / (1e6/66667) ≈ 6.00006 s
    let s = dur.as_secs_f64();
    assert!((s - 6.0006).abs() < 0.01, "secs={s}");
  }

  #[test]
  fn from_riff_fills_camera_software() {
    let bytes = minimal_avi_bytes();
    let meta = parse_borrowed(&bytes).expect("some");
    let projected = MediaMetadata::from_riff(&meta);
    let cam = projected.camera().expect("camera");
    assert_eq!(cam.software(), Some("Acme"));
  }

  /// Build a synthetic AVI whose avih FrameCount is `header_fc` and whose
  /// single `vids` stream has VideoFrameCount `vid_fc`. Both use the same
  /// frame rate (avih us-per-frame `us` ⇒ `1e6/us` fps; strh rate `1/vid_den`
  /// ⇒ `vid_den` fps), so the duration ratio is `header_fc / vid_fc`.
  fn avi_with_video_stream(us: u32, header_fc: u32, vid_den: u32, vid_fc: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"AVI ");
    buf.extend_from_slice(b"LIST");
    let hdrl_size_off = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    let hdrl_start = buf.len();
    buf.extend_from_slice(b"hdrl");
    // avih (40 bytes).
    buf.extend_from_slice(b"avih");
    buf.extend_from_slice(&40u32.to_le_bytes());
    buf.extend_from_slice(&us.to_le_bytes()); // 0: us per frame
    buf.extend_from_slice(&0u32.to_le_bytes()); // 1
    buf.extend_from_slice(&0u32.to_le_bytes()); // 2
    buf.extend_from_slice(&0u32.to_le_bytes()); // 3
    buf.extend_from_slice(&header_fc.to_le_bytes()); // 4: FrameCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // 5
    buf.extend_from_slice(&1u32.to_le_bytes()); // 6: StreamCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7
    buf.extend_from_slice(&320u32.to_le_bytes()); // 8: ImageWidth
    buf.extend_from_slice(&240u32.to_le_bytes()); // 9: ImageHeight
    // LIST strl (vids) → strh (48 bytes).
    buf.extend_from_slice(b"LIST");
    let strl_size_off = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    let strl_start = buf.len();
    buf.extend_from_slice(b"strl");
    buf.extend_from_slice(b"strh");
    buf.extend_from_slice(&48u32.to_le_bytes());
    buf.extend_from_slice(b"vids"); // 0
    buf.extend_from_slice(b"mjpg"); // 1
    buf.extend_from_slice(&[0u8; 12]); // 2/3/4
    buf.extend_from_slice(&1u32.to_le_bytes()); // 5 rate num (byte 20)
    buf.extend_from_slice(&vid_den.to_le_bytes()); // 5 rate den (byte 24)
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7 Start (byte 28)
    buf.extend_from_slice(&vid_fc.to_le_bytes()); // 8 VideoFrameCount (byte 32)
    buf.extend_from_slice(&[0u8; 12]); // 9/10/11 (bytes 36..48)
    let strl_size = (buf.len() - strl_start) as u32;
    buf[strl_size_off..strl_size_off + 4].copy_from_slice(&strl_size.to_le_bytes());
    let hdrl_size = (buf.len() - hdrl_start) as u32;
    buf[hdrl_size_off..hdrl_size_off + 4].copy_from_slice(&hdrl_size.to_le_bytes());
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());
    buf
  }

  #[test]
  fn duration_uses_video_stream_when_header_2_to_3x_too_long() {
    // FujiFilm-REAL-3D-style: avih FrameCount = 300 @25fps = 12s, but the
    // vids stream is 100 @25fps = 4s; ratio 3.0 ∈ (1.9, 3.1) ⇒ use the video
    // stream (RIFF.pm:1660-1663). Oracle: bundled Composite:Duration = 4.
    let bytes = avi_with_video_stream(40_000, 300, 25, 100);
    let meta = parse_borrowed(&bytes).expect("some");
    let dur = MediaMetadata::from_riff(&meta)
      .media()
      .duration()
      .expect("duration");
    assert!(
      (dur.as_secs_f64() - 4.0).abs() < 0.05,
      "expected ~4s (video-stream fallback), got {}",
      dur.as_secs_f64()
    );
  }

  #[test]
  fn duration_keeps_header_when_ratio_outside_window() {
    // Ratio 1.0 (header == video): NOT in (1.9, 3.1) ⇒ keep the avih
    // FrameCount/FrameRate duration. 100 @25fps = 4s.
    let bytes = avi_with_video_stream(40_000, 100, 25, 100);
    let meta = parse_borrowed(&bytes).expect("some");
    let dur = MediaMetadata::from_riff(&meta)
      .media()
      .duration()
      .expect("duration");
    assert!(
      (dur.as_secs_f64() - 4.0).abs() < 0.05,
      "expected ~4s (header kept), got {}",
      dur.as_secs_f64()
    );
  }

  #[test]
  fn empty_riff_yields_empty_projection() {
    // Outer RIFF/AVI with no sub-chunks.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(b"AVI ");
    let meta = parse_borrowed(&bytes).expect("some");
    let projected = MediaMetadata::from_riff(&meta);
    assert!(projected.camera().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().created().is_none());
  }
}
