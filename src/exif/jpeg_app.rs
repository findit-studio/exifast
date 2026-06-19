// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! JPEG `APP` auxiliary-segment metadata — the JFIF (`APP0`), MPF (`APP2`)
//! and DJI thermal (`APP3`/`APP4`/`APP5`/`APP7`) arms of `ProcessJPEG`.
//!
//! These are the JPEG-container segments OTHER than the `APP1` Exif block
//! (handled in [`super::jpeg`]) that a real camera JPEG — here the DJI
//! Matrice 30T / thermal RJPEG (#114) — carries. ExifTool dispatches each in
//! its `Marker:` loop (`ExifTool.pm:7977-8245`); this module ports the arms a
//! consumer-indexing build needs, producing already-rendered
//! [`EmittedTag`](crate::emit::EmittedTag)s appended to the JPEG's
//! [`ExifMeta`](super::ExifMeta) emission.
//!
//! The `-G1 -j` conformance compares the key MULTISET (object key order is
//! insensitive, `src/jsondiff.rs`), so these tags are appended without the
//! marker-position interleave the GoPro `APP6` path uses; their family-1
//! groups (`JFIF`/`MPF0`/`MPImage<N>`/`DJI`) and PrintConv text match bundled
//! exactly.
//!
//! ## Ported arms
//!
//! - **JFIF** (`APP0`, `$$valPt =~ /^JFIF\0/`, `ExifTool.pm:7979-7984`) —
//!   `DirStart(5)` + `SetByteOrder('MM')` + `ProcessBinaryData` over
//!   `%Image::ExifTool::JFIF::Main` (`ExifTool.pm:2197-2259`): `JFIFVersion`
//!   (`int8u[2]`, `sprintf("%d.%.2d")`), `ResolutionUnit` (`0=None`/`1=inches`/
//!   `2=cm`), `XResolution`/`YResolution` (`int16u`), and the optional
//!   `ThumbnailWidth`/`Height` (emitted only when non-zero — bundled's
//!   `RawConv => '$val ? … : undef'`).
//! - **MPF** (`APP2`, `$$valPt =~ /^MPF\0/`, `ExifTool.pm:8027-8038`) —
//!   `DirStart(4, 4)` + `ProcessTIFF` over `%Image::ExifTool::MPF::Main`
//!   (`MPF.pm:23-88`): the `MPFVersion`/`NumberOfImages`/`ImageUIDList`/
//!   `TotalFrames` header tags + the `MPImageList` sub-directory
//!   (`ProcessMPImageList`, `MPF.pm:239-253`) decoding each 16-byte MP Entry
//!   via the `%MPF::MPImage` binary table (`MPF.pm:91-158`) under group
//!   `MPImage<N>` (`SET_GROUP1 => '+'.($i+1)`, `MPF.pm:247`). The first "Large
//!   Thumbnail" MP image is re-extracted as `PreviewImage`
//!   (`ExtractMPImages`, `MPF.pm:190-233`).
//! - **DJI thermal** (`$$self{Make} eq 'DJI'`): `APP3` `ThermalData`
//!   (`JPEG.pm:113-117`, binary), `APP4` `%DJI::ThermalParams2`
//!   (`DJI.pm:123-134`, the M3T/M30T thermal floats), `APP5`
//!   `ThermalCalibration` (`JPEG.pm:174-178`, binary), and `APP7`
//!   `DJI-DBG\0` → `%DJI::Info` via `ProcessDJIInfo` (`DJI.pm:74-95`/`:960-983`,
//!   the bracketed `[sensor_id:…]` → `SensorID`). Every DJI thermal tag carries
//!   family-1 group `DJI` (the `Groups => { 1 => 'DJI' }` in JPEG.pm /
//!   `SET_GROUP0 => 'APP7'` resolves family-1 to `DJI`).

#![deny(clippy::indexing_slicing)]

use std::{string::String, vec::Vec};

use super::ifd::{ByteOrder, get_f32, get_u16, get_u32};
use super::jpeg::Segment;
use crate::emit::EmittedTag;
use crate::value::{Group, TagValue, binary_placeholder};
use smol_str::SmolStr;

/// Decode the JFIF / MPF / DJI-thermal `APP` segments of a JPEG into rendered
/// [`EmittedTag`]s — the auxiliary-segment companion to the `APP1` Exif walk.
///
/// `data` is the full JPEG byte slice; `segments` is the marker-walk output
/// from [`super::jpeg::scan_jpeg_segments`]. `base_offset` is the file offset
/// the JPEG body begins at (the same value [`super::jpeg::parse_jpeg_exif_with_base`]
/// adds to every embedded-`APP1` TIFF block's `Base`) — threaded through to the
/// MPF `IsOffset` rebase so an `APP2` `MPImageStart` recovered after a skipped
/// leading header reports a TRUE absolute file position; `0` for a JPEG that
/// starts at offset 0. `print_conv` selects ExifTool PrintConv (`-j`) vs the
/// raw ValueConv scalar (`-n`).
///
/// `make_is_dji_at` is the MUTABLE marker-order gate for the DJI thermal
/// `APP3`/`APP4`/`APP5` arms (`$$self{Make} eq 'DJI'`, `JPEG.pm:113`/`:150`/
/// `:174`), index-aligned with `segments`. ExifTool evaluates that `Condition`
/// INSIDE its `Marker:` loop against the CURRENT `$$self{Make}`, which it
/// updates from each `APP1` Exif block's IFD0 `Make` as it is processed
/// (`Exif.pm:585`, last-wins). `make_is_dji_at[i]` is that running state AS OF
/// segment `i`, so a DJI arm fires ONLY where it is `true`: an `APP4`
/// `ThermalParams2` BEFORE the `Make='DJI'` `APP1` is SKIPPED (the state is
/// still `false`), AND an `APP4` AFTER a later non-DJI `APP1` is ALSO skipped
/// (that `APP1` flipped the state back off) — both faithful to ExifTool's
/// in-loop `$$self{Make}`. The normal DJI layout (`APP1` `Make=DJI` then
/// `APP3`/`APP4`/`APP5`, no intervening non-DJI `Make`) keeps the state `true`,
/// so it still passes. The capture is IFD0-only and trailing-whitespace-trimmed
/// (the front-end reuses the main Exif walker's `$$self{Make}`), so an IFD1-only
/// `Make` does not arm it and `'DJI '` does. `APP7` (`DJI-DBG\0`) is NOT
/// `Make`-gated (it keys on its payload prefix) so it is unaffected.
#[must_use]
pub(super) fn process_app_markers(
  data: &[u8],
  segments: &[Segment],
  make_is_dji_at: &[bool],
  base_offset: usize,
  print_conv: bool,
) -> Vec<EmittedTag> {
  let mut out: Vec<EmittedTag> = Vec::new();
  // `$$self{Make} eq 'DJI'` AS OF this marker position — the running state the
  // front-end captured per segment (last-wins on each `APP1`'s IFD0 `Make`, so a
  // later non-DJI `APP1` turns it back off). `false` for an out-of-range index
  // (defensive; `make_is_dji_at` is index-aligned with `segments`).
  let make_is_dji = |i: usize| make_is_dji_at.get(i).copied().unwrap_or(false);
  for (i, seg) in segments.iter().enumerate() {
    let Some(payload) = data.get(seg.payload_start()..seg.payload_end()) else {
      continue;
    };
    match seg.marker() {
      // APP0 — JFIF (`ExifTool.pm:7979`). The only APP0 arm in scope.
      0xe0 if payload.starts_with(b"JFIF\0") => process_jfif(payload, print_conv, &mut out),
      // APP2 — MPF (`ExifTool.pm:8027`).
      0xe2 if payload.starts_with(b"MPF\0") => {
        process_mpf(
          payload,
          base_offset,
          seg.payload_start(),
          print_conv,
          &mut out,
        );
      }
      // APP3 — DJI raw `ThermalData` (`JPEG.pm:113`, `$$self{Make} eq 'DJI'`).
      // ExifTool accumulates CONSECUTIVE same-marker APP3 segments into one
      // `$combinedSegData` and emits a single combined blob when the next marker
      // differs (`ExifTool.pm:8041-8056`). A DJI thermal RJPEG splits its raw
      // thermal frame across many APP3 segments, so the combined `ThermalData`
      // length is the SUM of every consecutive APP3 payload — emitted once, on
      // the LAST segment of the run.
      0xe3 if make_is_dji(i) => {
        if !next_is_marker(segments, i, 0xe3) {
          let len = consecutive_run_len(data, segments, i, 0xe3);
          push_binary(&mut out, "APP3", "DJI", "ThermalData", len);
        }
      }
      // APP4 — DJI `ThermalParams2` (the M3T/M30T thermal floats). The
      // `ThermalParams`/`ThermalParams3` magic variants are out of scope for
      // this Matrice fixture (a follow-up); the discriminator below matches
      // ONLY the ThermalParams2 layout.
      0xe4 if make_is_dji(i) => process_dji_thermal_params2(payload, print_conv, &mut out),
      // APP5 — DJI `ThermalCalibration` (`JPEG.pm:174`, `$$self{Make} eq 'DJI'`).
      // Like APP3, ExifTool HandleTags the combined consecutive-APP5 blob
      // (`ExifTool.pm:8137-8141` via `JPEG::Main` `APP5`); emit once at run end.
      0xe5 if make_is_dji(i) => {
        if !next_is_marker(segments, i, 0xe5) {
          let len = consecutive_run_len(data, segments, i, 0xe5);
          push_binary(&mut out, "APP5", "DJI", "ThermalCalibration", len);
        }
      }
      // APP7 — DJI `DJI-DBG\0` → `%DJI::Info` (`ExifTool.pm:8224`).
      0xe7 if payload.starts_with(b"DJI-DBG\0") => process_dji_info(payload, &mut out),
      _ => {}
    }
  }
  out
}

/// `true` when the segment IMMEDIATELY following `segments[i]` has marker
/// `marker` — bundled's `$nextMarker == $marker` accumulate test
/// (`ExifTool.pm:8048`).
fn next_is_marker(segments: &[Segment], i: usize, marker: u8) -> bool {
  segments.get(i + 1).is_some_and(|n| n.marker() == marker)
}

/// Total payload length of the run of consecutive `marker` segments ENDING at
/// `segments[i]` — the combined-blob length ExifTool accumulates in
/// `$combinedSegData` (`ExifTool.pm:8043-8046`). Walks BACKWARD from `i` over
/// every immediately-preceding same-marker segment and sums their payloads.
fn consecutive_run_len(data: &[u8], segments: &[Segment], i: usize, marker: u8) -> usize {
  let mut total = 0usize;
  let mut j = i as isize;
  while j >= 0 {
    let Some(seg) = segments.get(j as usize) else {
      break;
    };
    if seg.marker() != marker {
      break;
    }
    if let Some(p) = data.get(seg.payload_start()..seg.payload_end()) {
      total = total.saturating_add(p.len());
    }
    j -= 1;
  }
  total
}

// ===========================================================================
// JFIF (APP0) — %Image::ExifTool::JFIF::Main (ExifTool.pm:2197-2259)
// ===========================================================================

/// `%Image::ExifTool::JFIF::Main` over the `APP0` payload — `DirStart(5)`
/// (skip the 5-byte `JFIF\0` header) then `ProcessBinaryData` in big-endian
/// (`SetByteOrder('MM')`, `ExifTool.pm:7982`). The binary-data offsets below
/// are relative to the post-`JFIF\0` directory start.
fn process_jfif(payload: &[u8], print_conv: bool, out: &mut Vec<EmittedTag>) {
  let Some(dir) = payload.get(5..) else {
    return;
  };
  // 0x00 `JFIFVersion` `int8u[2]` → `sprintf("%d.%.2d", split(" ",$val))`
  // (`ExifTool.pm:2204-2208`). `-n` is the raw space-joined `"major minor"`.
  if let (Some(&major), Some(&minor)) = (dir.first(), dir.get(1)) {
    let value = if print_conv {
      TagValue::Str(SmolStr::from(std::format!("{major}.{minor:02}")))
    } else {
      TagValue::Str(SmolStr::from(std::format!("{major} {minor}")))
    };
    push_jfif(out, "JFIFVersion", value);
  }
  // 0x02 `ResolutionUnit` `int8u` → `{0=>None,1=>inches,2=>cm}`
  // (`ExifTool.pm:2209-2220`).
  if let Some(&unit) = dir.get(2) {
    let value = if print_conv {
      TagValue::Str(SmolStr::new_static(match unit {
        0 => "None",
        1 => "inches",
        2 => "cm",
        _ => "",
      }))
    } else {
      TagValue::U64(u64::from(unit))
    };
    // A miss renders `Unknown (N)` like every HASH PrintConv (no `OTHER`).
    let value = match (&value, unit) {
      (TagValue::Str(s), u) if print_conv && s.is_empty() => {
        TagValue::Str(SmolStr::from(std::format!("Unknown ({u})")))
      }
      _ => value,
    };
    push_jfif(out, "ResolutionUnit", value);
  }
  // 0x03 `XResolution` `int16u` (big-endian) (`ExifTool.pm:2221-2228`).
  if let Some(x) = get_u16(dir, 3, ByteOrder::Big) {
    push_jfif(out, "XResolution", TagValue::U64(u64::from(x)));
  }
  // 0x05 `YResolution` `int16u` (`ExifTool.pm:2229-2236`).
  if let Some(y) = get_u16(dir, 5, ByteOrder::Big) {
    push_jfif(out, "YResolution", TagValue::U64(u64::from(y)));
  }
  // 0x07 `ThumbnailWidth` / 0x08 `ThumbnailHeight` — `RawConv => '$val ? … :
  // undef'` (`ExifTool.pm:2237-2244`): emitted ONLY when non-zero.
  if let Some(&w) = dir.get(7)
    && w != 0
  {
    push_jfif(out, "ThumbnailWidth", TagValue::U64(u64::from(w)));
  }
  if let Some(&h) = dir.get(8)
    && h != 0
  {
    push_jfif(out, "ThumbnailHeight", TagValue::U64(u64::from(h)));
  }
}

/// Append one JFIF tag (group `JFIF`:`JFIF`, `ExifTool.pm:2201`).
fn push_jfif(out: &mut Vec<EmittedTag>, name: &'static str, value: TagValue) {
  out.push(EmittedTag::new(
    Group::new("JFIF", "JFIF"),
    SmolStr::new_static(name),
    value,
    false,
  ));
}

// ===========================================================================
// MPF (APP2) — %Image::ExifTool::MPF::Main (MPF.pm:23-158)
// ===========================================================================

/// The MPF TIFF block over the `APP2` payload — `DirStart(4, 4)` (skip the
/// 4-byte `MPF\0` header) then `ProcessTIFF` over `%MPF::Main` (`MPF.pm:23`).
///
/// `payload_start` is the offset of the `APP2` payload's first byte WITHIN the
/// (possibly sliced) JPEG body `data`; `base_offset` is the file offset that
/// body begins at (`0` for a JPEG starting at offset 0). The MPF TIFF base
/// (`$$dirInfo{Base}`) is therefore `base_offset + payload_start + 4` — the
/// ABSOLUTE-file value `MPImageStart`'s `IsOffset => '$val'` adds
/// (`Exif.pm:7157-7170`) when the raw offset is non-zero. ExifTool reads the
/// `APP2` segment through a `RAF` positioned at `base_offset`, so its
/// `$raf->Tell()`-derived `DataPos` already includes the skipped leading bytes;
/// threading `base_offset` keeps a `MPImageStart` recovered after an unknown
/// leading header (`ExifTool.pm:3026-3034`) at its true absolute position
/// instead of under-reporting it by the skipped count. The terms are summed in
/// `usize` with `saturating_add` (the offsets cannot realistically overflow a
/// `usize` for a JPEG, but a pathological `base_offset` saturates rather than
/// wrapping/panicking — matching the `APP1` `Base` handling).
fn process_mpf(
  payload: &[u8],
  base_offset: usize,
  payload_start: usize,
  print_conv: bool,
  out: &mut Vec<EmittedTag>,
) {
  let Some(tiff) = payload.get(4..) else {
    return;
  };
  let Some(order) = ByteOrder::from_marker(tiff) else {
    return;
  };
  // Classic-TIFF magic check (`II\x2a\0` / `MM\0\x2a`); the MPF IFD is always
  // classic TIFF.
  if get_u16(tiff, 2, order) != Some(0x2a) {
    return;
  }
  let Some(ifd0_off) = get_u32(tiff, 4, order) else {
    return;
  };
  let base = base_offset.saturating_add(payload_start).saturating_add(4);
  walk_mpf_ifd(tiff, ifd0_off as usize, order, base, print_conv, out);
}

/// Walk the MPF MP-Attribute IFD (`%MPF::Main`). The header tags
/// (`MPFVersion`/`NumberOfImages`/`ImageUIDList`/`TotalFrames`) are scalars; the
/// `MPImageList` (0xb002) entry's value is a sub-directory of 16-byte MP Entries
/// decoded via [`process_mp_image_list`].
fn walk_mpf_ifd(
  tiff: &[u8],
  ifd_off: usize,
  order: ByteOrder,
  base: usize,
  print_conv: bool,
  out: &mut Vec<EmittedTag>,
) {
  let Some(count) = get_u16(tiff, ifd_off, order) else {
    return;
  };
  for i in 0..count as usize {
    // Each IFD entry: 2 tag + 2 format + 4 count + 4 value/offset = 12 bytes,
    // starting after the 2-byte count word.
    let entry_off = match ifd_off
      .checked_add(2)
      .and_then(|s| s.checked_add(i.checked_mul(12)?))
    {
      Some(o) => o,
      None => return,
    };
    let (Some(tag), Some(format), Some(value_count), Some(value_field)) = (
      get_u16(tiff, entry_off, order),
      get_u16(tiff, entry_off + 2, order),
      get_u32(tiff, entry_off + 4, order),
      get_u32(tiff, entry_off + 8, order),
    ) else {
      return;
    };
    // The value byte-size (`int8u/undef`=1, `int16u`=2, `int32u`=4, …) decides
    // inline vs out-of-line. Only the formats `%MPF::Main` uses are needed.
    let elt_size: usize = match format {
      1 | 2 | 6 | 7 => 1, // BYTE / ASCII / SBYTE / UNDEFINED
      3 | 8 => 2,         // SHORT / SSHORT
      4 | 9 | 11 => 4,    // LONG / SLONG / FLOAT
      _ => 4,
    };
    let total = (value_count as usize).saturating_mul(elt_size);
    // The value bytes: inline (≤ 4) in the value field, else out-of-line at the
    // 32-bit offset relative to the TIFF base.
    let value_off = if total <= 4 {
      entry_off + 8
    } else {
      value_field as usize
    };

    match tag {
      // 0xb000 `MPFVersion` `undef[4]` → ASCII version string `"0100"`.
      0xb000 => {
        if let Some(b) = tiff.get(value_off..value_off + 4) {
          let s: String = b
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect();
          push_mpf0(out, "MPFVersion", TagValue::Str(SmolStr::from(s)));
        }
      }
      // 0xb001 `NumberOfImages` `int32u`.
      0xb001 => {
        if let Some(n) = get_u32(tiff, value_off, order) {
          push_mpf0(out, "NumberOfImages", TagValue::U64(u64::from(n)));
        }
      }
      // 0xb002 `MPImageList` — the 16-byte-per-entry MP Entry sub-directory.
      0xb002 => {
        if let Some(list) = tiff.get(value_off..value_off + total) {
          process_mp_image_list(list, order, base, print_conv, out);
        }
      }
      // 0xb003 `ImageUIDList` (`Binary => 1`).
      0xb003 => push_binary(out, "MPF", "MPF0", "ImageUIDList", total),
      // 0xb004 `TotalFrames` `int32u`.
      0xb004 => {
        if let Some(n) = get_u32(tiff, value_off, order) {
          push_mpf0(out, "TotalFrames", TagValue::U64(u64::from(n)));
        }
      }
      _ => {}
    }
  }
}

/// `ProcessMPImageList` (`MPF.pm:239-253`) — decode each 16-byte MP Entry via
/// the `%MPF::MPImage` binary table (`MPF.pm:91-158`) under group `MPImage<N>`
/// (`SET_GROUP1 => '+'.($i+1)`). The first "Large Thumbnail" MP image is also
/// re-extracted as `PreviewImage` (`ExtractMPImages`, `MPF.pm:190-233`).
fn process_mp_image_list(
  list: &[u8],
  order: ByteOrder,
  base: usize,
  print_conv: bool,
  out: &mut Vec<EmittedTag>,
) {
  let num = list.len() / 16;
  let mut did_preview = false;
  for i in 0..num {
    let off = i.saturating_mul(16);
    let Some(entry) = list.get(off..off + 16) else {
      break;
    };
    let group1 = std::format!("MPImage{}", i + 1);
    // The packed int32u at offset 0 carries the masked MPImageFlags /
    // MPImageFormat / MPImageType (`MPF.pm:103-140`).
    let Some(packed) = get_u32(entry, 0, order) else {
      continue;
    };
    // MPImageFlags — Mask 0xf8000000, BitShift 27, BITMASK {2,3,4}.
    let flags = (packed & 0xf800_0000) >> 27;
    push_mpimage(
      out,
      &group1,
      "MPImageFlags",
      mp_image_flags(flags, print_conv),
    );
    // MPImageFormat — Mask 0x07000000, BitShift 24, {0=>JPEG}.
    let format = (packed & 0x0700_0000) >> 24;
    let fmt_val = if print_conv {
      TagValue::Str(SmolStr::new_static(if format == 0 { "JPEG" } else { "" }))
    } else {
      TagValue::U64(u64::from(format))
    };
    let fmt_val = match &fmt_val {
      TagValue::Str(s) if print_conv && s.is_empty() => {
        TagValue::Str(SmolStr::from(std::format!("Unknown ({format})")))
      }
      _ => fmt_val,
    };
    push_mpimage(out, &group1, "MPImageFormat", fmt_val);
    // MPImageType — Mask 0x00ffffff, BitShift 0, PrintHex hash.
    let mptype = packed & 0x00ff_ffff;
    push_mpimage(
      out,
      &group1,
      "MPImageType",
      mp_image_type(mptype, print_conv),
    );
    // MPImageLength `int32u` @ 4.
    let length = get_u32(entry, 4, order).unwrap_or(0);
    push_mpimage(
      out,
      &group1,
      "MPImageLength",
      TagValue::U64(u64::from(length)),
    );
    // MPImageStart `int32u` @ 8, `IsOffset => '$val'` — rebased by `base`
    // when non-zero (`Exif.pm:7157`).
    let start_raw = get_u32(entry, 8, order).unwrap_or(0);
    let start = if start_raw != 0 {
      (start_raw as u64).wrapping_add(base as u64)
    } else {
      0
    };
    push_mpimage(out, &group1, "MPImageStart", TagValue::U64(start));
    // DependentImage1/2EntryNumber `int16u` @ 12 / 14.
    let dep1 = get_u16(entry, 12, order).unwrap_or(0);
    let dep2 = get_u16(entry, 14, order).unwrap_or(0);
    push_mpimage(
      out,
      &group1,
      "DependentImage1EntryNumber",
      TagValue::U64(u64::from(dep1)),
    );
    push_mpimage(
      out,
      &group1,
      "DependentImage2EntryNumber",
      TagValue::U64(u64::from(dep2)),
    );
    // `ExtractMPImages` (`MPF.pm:202-209`): the FIRST Large Thumbnail
    // (`$type & 0x0f0000 == 0x010000`) with a non-zero offset+length is
    // re-extracted as `PreviewImage` under the SAME family-1 group.
    if !did_preview && start_raw != 0 && length != 0 && (mptype & 0x0f_0000) == 0x01_0000 {
      did_preview = true;
      push_binary(out, "MPF", &group1, "PreviewImage", length as usize);
    }
  }
}

/// `MPImageFlags` PrintConv — `DecodeBits` BITMASK `{2=>'Representative
/// image', 3=>'Dependent child image', 4=>'Dependent parent image'}`
/// (`MPF.pm:107-111`). `-n` is the raw shifted integer.
fn mp_image_flags(val: u32, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::U64(u64::from(val));
  }
  // ExifTool `DecodeBits` (`ExifTool.pm:8662`): `0` → empty here (no `0`
  // entry, so a clear value joins to ""), set bit `n` → its label or `[n]`,
  // joined by `, `.
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..32u32 {
    if val & (1 << bit) != 0 {
      let label = match bit {
        2 => "Representative image",
        3 => "Dependent child image",
        4 => "Dependent parent image",
        n => return decode_bits_unknown(val, n),
      };
      parts.push(String::from(label));
    }
  }
  TagValue::Str(SmolStr::from(parts.join(", ")))
}

/// `DecodeBits` for a bit with NO label — renders `[n]` (`ExifTool.pm:8669`).
/// Rebuilds the full join including the unknown bit at its position.
fn decode_bits_unknown(val: u32, _first_unknown: u32) -> TagValue {
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..32u32 {
    if val & (1 << bit) != 0 {
      let label = match bit {
        2 => String::from("Representative image"),
        3 => String::from("Dependent child image"),
        4 => String::from("Dependent parent image"),
        n => std::format!("[{n}]"),
      };
      parts.push(label);
    }
  }
  TagValue::Str(SmolStr::from(parts.join(", ")))
}

/// `MPImageType` PrintConv — `PrintHex` hash (`MPF.pm:122-140`). A miss renders
/// `Unknown (0x%x)` (`PrintHex => 1`). `-n` is the raw integer.
fn mp_image_type(val: u32, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::U64(u64::from(val));
  }
  let label = match val {
    0x000000 => "Undefined",
    0x010001 => "Large Thumbnail (VGA equivalent)",
    0x010002 => "Large Thumbnail (full HD equivalent)",
    0x010003 => "Large Thumbnail (4K equivalent)",
    0x010004 => "Large Thumbnail (8K equivalent)",
    0x010005 => "Large Thumbnail (16K equivalent)",
    0x020001 => "Multi-frame Panorama",
    0x020002 => "Multi-frame Disparity",
    0x020003 => "Multi-angle",
    0x030000 => "Baseline MP Primary Image",
    0x040000 => "Original Preservation Image",
    0x050000 => "Gain Map Image",
    other => return TagValue::Str(SmolStr::from(std::format!("Unknown (0x{other:x})"))),
  };
  TagValue::Str(SmolStr::new_static(label))
}

/// Append one MPF header tag (group `MPF`:`MPF0`, `MPF.pm:24`).
fn push_mpf0(out: &mut Vec<EmittedTag>, name: &'static str, value: TagValue) {
  out.push(EmittedTag::new(
    Group::new("MPF", "MPF0"),
    SmolStr::new_static(name),
    value,
    false,
  ));
}

/// Append one MP-Image tag (group `MPF`:`MPImage<N>`, `MPF.pm:96` +
/// `SET_GROUP1`).
fn push_mpimage(out: &mut Vec<EmittedTag>, group1: &str, name: &'static str, value: TagValue) {
  out.push(EmittedTag::new(
    Group::new("MPF", group1),
    SmolStr::new_static(name),
    value,
    false,
  ));
}

// ===========================================================================
// DJI thermal — DJI::ThermalParams2 (DJI.pm:123-134) + DJI::Info (DJI.pm:74-95)
// ===========================================================================

/// `%Image::ExifTool::DJI::ThermalParams2` over the `APP4` payload
/// (`DJI.pm:123-134`). The discriminator `/^(.{32})?.{32}\x2c\x01\x20\0/s`
/// (`JPEG.pm:150-152`) sets `DirStart` to 32 when the optional leading 32-byte
/// group is present (the M30T layout) — every tag offset below is relative to
/// that directory start.
fn process_dji_thermal_params2(payload: &[u8], print_conv: bool, out: &mut Vec<EmittedTag>) {
  // `\x2c\x01\x20\0` magic at directory-start + 32 decides the variant +
  // whether the optional leading 32-byte group is present (`$1 ? 32 : 0`).
  let dir_start = if payload.get(32..36) == Some(b"\x2c\x01\x20\0") {
    0
  } else if payload.get(64..68) == Some(b"\x2c\x01\x20\0") {
    32
  } else {
    return; // not the ThermalParams2 layout
  };
  let Some(dir) = payload.get(dir_start..) else {
    return;
  };
  // 0x00 AmbientTemperature float → `sprintf("%.1f C")`.
  if let Some(v) = get_f32(dir, 0x00, ByteOrder::Little) {
    push_dji(
      out,
      "AmbientTemperature",
      float_suffix(v, "C", 1, print_conv),
    );
  }
  // 0x04 ObjectDistance float → `sprintf("%.1f m")`.
  if let Some(v) = get_f32(dir, 0x04, ByteOrder::Little) {
    push_dji(out, "ObjectDistance", float_suffix(v, "m", 1, print_conv));
  }
  // 0x08 Emissivity float → `sprintf("%.2f")` (a bare numeric string ⇒ the
  // EscapeJSON number gate emits a bare JSON number).
  if let Some(v) = get_f32(dir, 0x08, ByteOrder::Little) {
    let val = if print_conv {
      TagValue::Str(SmolStr::from(std::format!("{:.2}", f64::from(v))))
    } else {
      TagValue::F64(f64::from(v))
    };
    push_dji(out, "Emissivity", val);
  }
  // 0x0c RelativeHumidity float → `sprintf("%g %%", $val*100)`. Perl `%g` with
  // no explicit precision defaults to SIX significant digits (C `printf`), so
  // the percent value is rendered with `format_g(.., 6)`, NOT 15. (The other
  // four ThermalParams2 PrintConvs are `%.1f`/`%.2f` fixed-precision, not `%g`,
  // and are handled by `float_suffix` / the `{:.2}` arm — RelativeHumidity is
  // the only `%g` tag in this table, so the class sweep touches only it.)
  if let Some(v) = get_f32(dir, 0x0c, ByteOrder::Little) {
    let val = if print_conv {
      let pct = crate::value::format_g(f64::from(v) * 100.0, 6);
      TagValue::Str(SmolStr::from(std::format!("{pct} %")))
    } else {
      TagValue::F64(f64::from(v))
    };
    push_dji(out, "RelativeHumidity", val);
  }
  // 0x10 ReflectedTemperature float → `sprintf("%.1f C")`.
  if let Some(v) = get_f32(dir, 0x10, ByteOrder::Little) {
    push_dji(
      out,
      "ReflectedTemperature",
      float_suffix(v, "C", 1, print_conv),
    );
  }
  // 0x65 IDString `string[16]` — NUL-trimmed ASCII (no PrintConv).
  if let Some(b) = dir.get(0x65..0x65 + 16) {
    let s: String = b
      .iter()
      .take_while(|&&c| c != 0)
      .map(|&c| c as char)
      .collect();
    push_dji(out, "IDString", TagValue::Str(SmolStr::from(s)));
  }
}

/// `sprintf("%.{prec}f {suffix}", $val)` for the temperature/distance tags;
/// `-n` is the raw float (`TagValue::F64`).
fn float_suffix(v: f32, suffix: &str, prec: usize, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::F64(f64::from(v));
  }
  TagValue::Str(SmolStr::from(std::format!(
    "{:.*} {suffix}",
    prec,
    f64::from(v)
  )))
}

/// `ProcessDJIInfo` (`DJI.pm:960-983`) over the `APP7` `DJI-DBG\0` payload —
/// `DirStart(8, 0)` (skip the 8-byte `DJI-DBG\0` header) then scan
/// `\[(.*?)\]` blocks, splitting each on the first `:` into `tag:val` and
/// mapping the tag id through `%DJI::Info` (`DJI.pm:74-95`). Only the
/// camera-indexing `sensor_id` → `SensorID` is emitted here.
fn process_dji_info(payload: &[u8], out: &mut Vec<EmittedTag>) {
  let Some(body) = payload.get(8..) else {
    return;
  };
  // Scan bracketed `[tag:val]` records. ExifTool's regex is
  // `\G\[(.*?)\](?=(\[|$))/sg`; a linear bracket scan reproduces it for the
  // well-formed `[sensor_id:…]` body.
  let mut i = 0usize;
  while i < body.len() {
    if body.get(i) != Some(&b'[') {
      i += 1;
      continue;
    }
    // Find the closing `]`.
    let Some(rel_end) = body
      .get(i + 1..)
      .and_then(|s| s.iter().position(|&b| b == b']'))
    else {
      break;
    };
    let inner_start = i + 1;
    let inner_end = inner_start + rel_end;
    let Some(inner) = body.get(inner_start..inner_end) else {
      break;
    };
    // Split on the FIRST `:` into tag / value.
    if let Some(colon) = inner.iter().position(|&b| b == b':') {
      let (tag, rest) = inner.split_at(colon);
      let val = rest.get(1..).unwrap_or(&[]);
      handle_dji_info_tag(tag, val, out);
    }
    i = inner_end + 1;
  }
}

/// Map one `[tag:val]` record to its `%DJI::Info` tag. The value's
/// `^([\x20-\x7e]+)\0*$` ASCII branch (`DJI.pm:974-975`) strips trailing NULs.
fn handle_dji_info_tag(tag: &[u8], val: &[u8], out: &mut Vec<EmittedTag>) {
  // `sensor_id` → `SensorID` (`DJI.pm:88`). The other %DJI::Info ids
  // (ae_dbg_info / awb_dbg_info / …) are debug blobs out of the
  // camera-indexing scope; only SensorID is emitted.
  if tag == b"sensor_id" {
    // ASCII value, trailing NULs stripped.
    let text: String = val
      .iter()
      .take_while(|&&c| c != 0)
      .map(|&c| c as char)
      .collect();
    out.push(EmittedTag::new(
      Group::new("APP7", "DJI"),
      SmolStr::new_static("SensorID"),
      TagValue::Str(SmolStr::from(text)),
      false,
    ));
  }
}

/// Append one DJI thermal tag (group family-1 `DJI`; family-0 `APP4` for the
/// ThermalParams2 tags per `Groups => { 0 => 'APP4' }`, `DJI.pm:127`). The
/// `-G1` key uses family-1 (`DJI:`), so family-0 is cosmetic here.
fn push_dji(out: &mut Vec<EmittedTag>, name: &'static str, value: TagValue) {
  out.push(EmittedTag::new(
    Group::new("APP4", "DJI"),
    SmolStr::new_static(name),
    value,
    false,
  ));
}

// ===========================================================================
// Shared binary-placeholder emit
// ===========================================================================

/// Append a binary tag rendered as the `(Binary data N bytes …)` placeholder
/// — bundled `Binary => 1` / a binary value with no `-b` option
/// (`exiftool:3982-3986`). `family1` is the `-G1` key prefix; `name` is the
/// tag name. The byte length is carried verbatim into the placeholder text.
fn push_binary(
  out: &mut Vec<EmittedTag>,
  family0: &'static str,
  family1: &str,
  name: &'static str,
  len: usize,
) {
  out.push(EmittedTag::new(
    Group::new(family0, family1),
    SmolStr::new_static(name),
    // A `TagValue::Bytes` of the right length renders to the placeholder via
    // the value serializer; carry only the length (an empty padding `Vec`)
    // since the bytes are never emitted in default (`-b`-less) output.
    TagValue::Str(binary_placeholder(len as u64)),
    false,
  ));
}
