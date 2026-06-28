// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon per-model `CameraInfo` sub-tables (`Canon.pm:3158-6002`).
//!
//! The `%Canon::Main` tag `0x0d` (`Canon.pm:1308-1494`) is a model-conditional
//! list of `Canon::CameraInfo<Model>` SubDirectories. This module ports the
//! EOS 5D table (`%Canon::CameraInfo5D`, `Canon.pm:3777-3964`, selected by
//! `$$self{Model} =~ /EOS 5D$/`) and the EOS 7D table (`%Canon::CameraInfo7D`,
//! `Canon.pm:4342-4489`, selected by `$$self{Model} =~ /EOS 7D$/`).
//!
//! `CameraInfo7D` is `FORMAT => 'int8u'`, `PRIORITY => 0`, with a
//! firmware-dependent `Hook`/`varSize` offset shift (`Canon.pm:4347-4402`): the
//! `0x00 FirmwareVersionLookAhead` RawConv probes the version string at 0x1a8
//! (`CanonFirm = 1`) then 0x1ac (`CanonFirm = 2`); the `0x1e` `Hook`
//! (`$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if $$self{CanonFirm} < 2`)
//! shifts every leaf at/after 0x1e accordingly. Its `0x327 PictureStyleInfo`
//! `IS_SUBDIR` points at the nested `%Canon::PSInfo` table (`Canon.pm:6018`,
//! `PRIORITY => 0`), emitted in the same `Canon` group.
//!
//! `CameraInfo5D` is `FORMAT => 'int8s'`, `FIRST_ENTRY => 0`, `PRIORITY => 0`,
//! so a tag at position `p` is at byte offset `p` (one `int8s` per unit) and
//! EVERY leaf is `Priority => 0` — a duplicate of an earlier higher-or-equal
//! leaf (the `CanonShotInfo`/`CanonFocalLength`/`CanonCameraSettings` values,
//! walked first) NEVER overrides it (`ExifTool.pm:9544-9560`). The dispatch
//! site emits each pair with `tag_priority == 0` for exactly that reason.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use super::camera_settings::canon_ev;
use super::canon_custom::word_bounded;
use super::lens_types;
use super::printconv::picture_style_label;
use super::shot_info::white_balance_label;
use crate::datetime::convert_unix_time;
use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// `true` when `model` selects `%Canon::CameraInfo5D` via the `0x0d`
/// conditional list (`Canon.pm:1342`, `$$self{Model} =~ /EOS 5D$/` — anchored,
/// so the original 5D only, NOT "5D Mark II/III").
#[must_use]
pub fn model_is_camera_info_5d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 5D"))
}

/// `true` when `model` selects `%Canon::CameraInfo6D` (`Canon.pm:1357`,
/// `$$self{Model} =~ /EOS 6D$/` — anchored, so the original 6D only, NOT
/// "6D Mark II").
#[must_use]
pub fn model_is_camera_info_6d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 6D"))
}

/// `true` when `model` selects `%Canon::CameraInfo1D` (`Canon.pm:1312`,
/// `$$self{Model} =~ /\b1DS?$/` — the original 1D or 1DS, case-sensitive `S`).
/// The dispatch `Condition` also assigns `$$self{CameraInfoCount} = $count`
/// (`Canon.pm:1312`) — a side-effect read by the count-keyed tables that follow
/// the model rows: the ported `CameraInfoPowerShot`/`PowerShot2` (their
/// `CameraTemperature` row) and the still-deferred `CameraInfoUnknown*`.
#[must_use]
pub fn model_is_camera_info_1d(model: Option<&str>) -> bool {
  model_is_1d_proper(model) || model_is_1ds(model)
}

/// The 1D proper (`/\b1D$/`) — gates the 1D-only rows of `%CameraInfo1D`.
fn model_is_1d_proper(model: Option<&str>) -> bool {
  model_ends_with(model, "1D")
}

/// The 1DS (`/\b1DS$/`) — gates the 1DS-only rows of `%CameraInfo1D`.
fn model_is_1ds(model: Option<&str>) -> bool {
  model_ends_with(model, "1DS")
}

/// `true` when `model` selects `%Canon::CameraInfo1DmkII` (`Canon.pm:1317`,
/// `$$self{Model} =~ /\b1Ds? Mark II$/` — the 1DmkII or 1DSmkII; the trailing
/// `$` excludes the "Mark II N" of the 1DmkIIN).
#[must_use]
pub fn model_is_camera_info_1dmkii(model: Option<&str>) -> bool {
  model_ends_with(model, "1D Mark II") || model_ends_with(model, "1Ds Mark II")
}

/// `true` when `model` selects `%Canon::CameraInfo1DmkIIN` (`Canon.pm:1322`,
/// `$$self{Model} =~ /\b1Ds? Mark II N$/`).
#[must_use]
pub fn model_is_camera_info_1dmkiin(model: Option<&str>) -> bool {
  model_ends_with(model, "1D Mark II N") || model_ends_with(model, "1Ds Mark II N")
}

/// `true` when `model` selects `%Canon::CameraInfo1DmkIII` (`Canon.pm:1327`,
/// `$$self{Model} =~ /\b1Ds? Mark III$/` — the 1DmkIII or 1DSmkIII).
#[must_use]
pub fn model_is_camera_info_1dmkiii(model: Option<&str>) -> bool {
  model_is_1dmkiii_proper(model) || model_ends_with(model, "1Ds Mark III")
}

/// The 1DmkIII proper (`/\b1D Mark III$/`) — gates the 1DmkIII-only `TimeStamp1`
/// leaf (`Canon.pm:3512`), which is absent on the 1DSmkIII.
fn model_is_1dmkiii_proper(model: Option<&str>) -> bool {
  model_ends_with(model, "1D Mark III")
}

/// `true` when `model` selects `%Canon::CameraInfo80D` (`Canon.pm:1387`,
/// `$$self{Model} =~ /EOS 80D$/`).
#[must_use]
pub fn model_is_camera_info_80d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 80D"))
}

/// `true` when `model` selects `%Canon::CameraInfo750D` — the 750D
/// (`Canon.pm:1422`, `/\b(750D|Rebel T6i|Kiss X8i)\b/`) or the 760D alias
/// (`Canon.pm:1427`, `/\b(760D|Rebel T6s|8000D)\b/`); both share the table with
/// every row unconditional. Note the mixed-case "Rebel" (vs the "REBEL" of the
/// older Rebel tables).
#[must_use]
pub fn model_is_camera_info_750d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "750D")
      || word_bounded(m, "Rebel T6i")
      || word_bounded(m, "Kiss X8i")
      || word_bounded(m, "760D")
      || word_bounded(m, "Rebel T6s")
      || word_bounded(m, "8000D")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo5DmkII` (`Canon.pm:1347`,
/// `$$self{Model} =~ /EOS 5D Mark II$/` — end-anchored, so the "Mark II", NOT the
/// "Mark III" (which ends with `III`, never matching the `II$`)).
#[must_use]
pub fn model_is_camera_info_5dmkii(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 5D Mark II"))
}

/// `true` when `model` selects `%Canon::CameraInfo1DmkIV` (`Canon.pm:1332`,
/// `$$self{Model} =~ /\b1D Mark IV$/` — word-anchored before `1D`, end-anchored).
#[must_use]
pub fn model_is_camera_info_1dmkiv(model: Option<&str>) -> bool {
  model_ends_with(model, "1D Mark IV")
}

/// `true` when `model` selects `%Canon::CameraInfo1DX` (`Canon.pm:1337`,
/// `$$self{Model} =~ /EOS-1D X$/` — end-anchored, so the "1D X", NOT the
/// "1D X Mark II/III" (which end with `II`/`III`, never `X$`)).
#[must_use]
pub fn model_is_camera_info_1dx(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS-1D X"))
}

/// `true` when `model` selects `%Canon::CameraInfo5DmkIII` (`Canon.pm:1352`,
/// `$$self{Model} =~ /EOS 5D Mark III$/`).
#[must_use]
pub fn model_is_camera_info_5dmkiii(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 5D Mark III"))
}

/// `true` when `model` selects `%Canon::CameraInfoR6` (`Canon.pm:1448`,
/// `$$self{Model} =~ /\bEOS R[56]$/` — the mirrorless EOS R5 or R6, end-anchored
/// so NOT the "R6 Mark II/III").
#[must_use]
pub fn model_is_camera_info_r6(model: Option<&str>) -> bool {
  model_ends_with(model, "EOS R5") || model_ends_with(model, "EOS R6")
}

/// `true` when `model` selects `%Canon::CameraInfoR6m2` (`Canon.pm:1453`,
/// `$$self{Model} =~ /\bEOS (R6m2|R8|R50)$/` — the EOS R6 Mark II / R8 / R50).
#[must_use]
pub fn model_is_camera_info_r6m2(model: Option<&str>) -> bool {
  model_ends_with(model, "EOS R6m2")
    || model_ends_with(model, "EOS R8")
    || model_ends_with(model, "EOS R50")
}

/// `true` when `model` selects `%Canon::CameraInfoR6m3` (`Canon.pm:1458`,
/// `$$self{Model} =~ /\bEOS R6 Mark III$/`).
#[must_use]
pub fn model_is_camera_info_r6m3(model: Option<&str>) -> bool {
  model_ends_with(model, "EOS R6 Mark III")
}

/// `true` when `model` selects `%Canon::CameraInfoG5XII` (`Canon.pm:1463`,
/// `$$self{Model} =~ /\bG5 X Mark II$/` — the PowerShot G5 X Mark II).
#[must_use]
pub fn model_is_camera_info_g5xii(model: Option<&str>) -> bool {
  model_ends_with(model, "G5 X Mark II")
}

/// Decode the `Canon::CameraInfo` block for the parent `model` via the `0x0d`
/// model-conditional list (`Canon.pm:1308-1494`), evaluated in ExifTool's order.
/// Ported variants: the 1-series no-Hook bodies (1D / 1DS / 1DmkII / 1DmkIIN /
/// 1DmkIII), the 5D / 6D / 7D, and the xxxD DSLR batch (40D / 50D / 60D / 70D /
/// 80D / 450D / 500D / 550D / 600D / 650D / 700D / 750D / 760D / 1000D, plus the
/// 1100D / 1200D aliases), and the pro multi-Hook bodies 5DmkII (1 Hook),
/// 1DmkIV (2 Hooks), 1DX (3 Hooks) and 5DmkIII (4 Hooks); the mirrorless bodies
/// EOS R6 (R5/R6), R6m2 (R6m2/R8/R50), R6m3 and the PowerShot G5XII; then — after
/// the model-conditional rows, keyed by the `0x0d` entry's `$count` + `$format`
/// (`Canon.pm:1466-1479`) rather than the model — the `int32u`
/// CameraInfoPowerShot (count 138/148) and CameraInfoPowerShot2 (count
/// 156/162/167/171/264) tables. Only the `CameraInfoUnknown*` catch-alls
/// (`Canon.pm:1480-1494`) stay deferred; any other model/count yields nothing.
/// `print_conv` selects the
/// PrintConv vs ValueConv view; `canon_lens_type` is the pre-scanned
/// `$$self{LensType}` (the CameraSettings DataMember) that gates the
/// `MacroMagnification` leaf (`%ciMacroMagnification`, `Canon.pm:3124-3133`).
/// `file_type` is the container `$$self{FileType}` (`File:FileType`) gating the
/// `%CameraInfoG5XII` JPEG/CR3 rows (`Canon.pm:4876`/`:4886`). `count` and
/// `is_int32u` are the `0x0d` entry's `$count` and `$format eq "int32u"` — the
/// PowerShot `Condition` keys (`Canon.pm:1468`/`:1475`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  file_type: Option<&str>,
  canon_lens_type: Option<u16>,
  count: usize,
  is_int32u: bool,
) -> Vec<(SmolStr, TagValue)> {
  if model_is_camera_info_1d(model) {
    camera_info_1d(data, order, print_conv, model)
  } else if model_is_camera_info_1dmkiin(model) {
    camera_info_1dmkiin(data, order, print_conv)
  } else if model_is_camera_info_1dmkii(model) {
    camera_info_1dmkii(data, order, print_conv)
  } else if model_is_camera_info_1dmkiii(model) {
    camera_info_1dmkiii(data, order, print_conv, model, canon_lens_type)
  } else if model_is_camera_info_1dmkiv(model) {
    camera_info_1dmkiv(data, order, print_conv)
  } else if model_is_camera_info_1dx(model) {
    camera_info_1dx(data, order, print_conv)
  } else if model_is_camera_info_5d(model) {
    camera_info_5d(data, order, print_conv)
  } else if model_is_camera_info_5dmkii(model) {
    camera_info_5dmkii(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_5dmkiii(model) {
    camera_info_5dmkiii(data, order, print_conv)
  } else if model_is_camera_info_6d(model) {
    camera_info_6d(data, order, print_conv)
  } else if model_is_camera_info_7d(model) {
    camera_info_7d(data, order, print_conv)
  } else if model_is_camera_info_40d(model) {
    camera_info_40d(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_50d(model) {
    camera_info_50d(data, order, print_conv)
  } else if model_is_camera_info_60d(model) {
    camera_info_60d(data, order, print_conv, model)
  } else if model_is_camera_info_70d(model) {
    camera_info_70d(data, order, print_conv)
  } else if model_is_camera_info_80d(model) {
    camera_info_80d(data, order, print_conv)
  } else if model_is_camera_info_450d(model) {
    camera_info_450d(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_500d(model) {
    camera_info_500d(data, order, print_conv)
  } else if model_is_camera_info_550d(model) {
    camera_info_550d(data, order, print_conv)
  } else if model_is_camera_info_600d(model) {
    camera_info_600d(data, order, print_conv)
  } else if model_is_camera_info_650d(model) {
    camera_info_650d(data, order, print_conv, model)
  } else if model_is_camera_info_750d(model) {
    camera_info_750d(data, order, print_conv)
  } else if model_is_camera_info_1000d(model) {
    camera_info_1000d(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_r6(model) {
    camera_info_r6(data, order, print_conv)
  } else if model_is_camera_info_r6m2(model) {
    camera_info_r6m2(data, order)
  } else if model_is_camera_info_r6m3(model) {
    camera_info_r6m3(data, order)
  } else if model_is_camera_info_g5xii(model) {
    camera_info_g5xii(data, order, file_type)
  } else if is_int32u && (count == 138 || count == 148) {
    // `%Canon::CameraInfoPowerShot` (`Canon.pm:1466-1469`): the model-conditional
    // rows above all failed, so ExifTool keys on the `0x0d` entry's `$format eq
    // "int32u"` and `$count` (138/148) instead of the model. `count` IS
    // `$$self{CameraInfoCount}` (set by the 1D row's side-effecting `Condition`,
    // `Canon.pm:1312`), which the in-table `CameraTemperature` row also reads.
    parse_camera_info_powershot(data, order, print_conv, count)
  } else if is_int32u && matches!(count, 156 | 162 | 167 | 171 | 264) {
    // `%Canon::CameraInfoPowerShot2` (`Canon.pm:1471-1479`), counts
    // 156/162/167/171/264 — same int32u gate.
    parse_camera_info_powershot2(data, order, print_conv, count)
  } else {
    // The `CameraInfoUnknown32`/`Unknown16`/`Unknown` catch-alls
    // (`Canon.pm:1480-1494`) stay deferred (#85).
    Vec::new()
  }
}

/// `true` when `model` selects `%Canon::CameraInfo40D` (`Canon.pm:1366`,
/// `$$self{Model} =~ /EOS 40D$/`).
#[must_use]
pub fn model_is_camera_info_40d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 40D"))
}

/// `true` when `model` selects `%Canon::CameraInfo50D` (`Canon.pm:1371`,
/// `$$self{Model} =~ /EOS 50D$/`).
#[must_use]
pub fn model_is_camera_info_50d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 50D"))
}

/// `true` when `model` selects `%Canon::CameraInfo60D` — either the 60D proper
/// (`Canon.pm:1377`, `$$self{Model} =~ /EOS 60D$/`) or the 1200D alias
/// (`Canon.pm:1442`, `/\b(1200D|REBEL T5|Kiss X70)\b/`), which share the table.
#[must_use]
pub fn model_is_camera_info_60d(model: Option<&str>) -> bool {
  model_is_60d_proper(model) || model_is_1200d(model)
}

/// The 60D proper (`/EOS 60D$/`) — gates the 60D-only rows of `%CameraInfo60D`.
fn model_is_60d_proper(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 60D"))
}

/// The 1200D alias (`/\b(1200D|REBEL T5|Kiss X70)\b/`) — gates the 1200D-only
/// rows of `%CameraInfo60D`.
fn model_is_1200d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "1200D") || word_bounded(m, "REBEL T5") || word_bounded(m, "Kiss X70")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo70D` (`Canon.pm:1382`,
/// `$$self{Model} =~ /EOS 70D$/`).
#[must_use]
pub fn model_is_camera_info_70d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 70D"))
}

/// `true` when `model` selects `%Canon::CameraInfo600D` — the 600D
/// (`Canon.pm:1407`, `/\b(600D|REBEL T3i|Kiss X5)\b/`) or the 1100D alias
/// (`Canon.pm:1437`, `/\b(1100D|REBEL T3|Kiss X50)\b/`); both share the table
/// with identical rows (no per-model `Condition`s).
#[must_use]
pub fn model_is_camera_info_600d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "600D")
      || word_bounded(m, "REBEL T3i")
      || word_bounded(m, "Kiss X5")
      || word_bounded(m, "1100D")
      || word_bounded(m, "REBEL T3")
      || word_bounded(m, "Kiss X50")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo650D` — the 650D
/// (`Canon.pm:1412`, `/\b(650D|REBEL T4i|Kiss X6i)\b/`) or the 700D alias
/// (`Canon.pm:1417`, `/\b(700D|REBEL T5i|Kiss X7i)\b/`); both share the table,
/// which carries per-model `Condition`s on FirmwareVersion/FileIndex/Dir.
#[must_use]
pub fn model_is_camera_info_650d(model: Option<&str>) -> bool {
  model_is_650d_proper(model) || model_is_700d(model)
}

/// The 650D proper (`/(650D|REBEL T4i|Kiss X6i)\b/`) — gates the 650D-location
/// FirmwareVersion/FileIndex/DirectoryIndex rows of `%CameraInfo650D`.
fn model_is_650d_proper(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "650D") || word_bounded(m, "REBEL T4i") || word_bounded(m, "Kiss X6i")
  })
}

/// The 700D alias (`/(700D|REBEL T5i|Kiss X7i)\b/`) — gates the 700D-location
/// FirmwareVersion/FileIndex/DirectoryIndex rows of `%CameraInfo650D`.
fn model_is_700d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "700D") || word_bounded(m, "REBEL T5i") || word_bounded(m, "Kiss X7i")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo450D` (`Canon.pm:1391`,
/// `$$self{Model} =~ /\b(450D|REBEL XSi|Kiss X2)\b/`).
#[must_use]
pub fn model_is_camera_info_450d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "450D") || word_bounded(m, "REBEL XSi") || word_bounded(m, "Kiss X2")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo500D` (`Canon.pm:1396`,
/// `$$self{Model} =~ /\b(500D|REBEL T1i|Kiss X3)\b/`).
#[must_use]
pub fn model_is_camera_info_500d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "500D") || word_bounded(m, "REBEL T1i") || word_bounded(m, "Kiss X3")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo550D` (`Canon.pm:1401`,
/// `$$self{Model} =~ /\b(550D|REBEL T2i|Kiss X4)\b/`).
#[must_use]
pub fn model_is_camera_info_550d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "550D") || word_bounded(m, "REBEL T2i") || word_bounded(m, "Kiss X4")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo1000D` (`Canon.pm:1431`,
/// `$$self{Model} =~ /\b(1000D|REBEL XS|Kiss F)\b/`).
#[must_use]
pub fn model_is_camera_info_1000d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "1000D") || word_bounded(m, "REBEL XS") || word_bounded(m, "Kiss F")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo7D` via the `0x0d`
/// conditional list (`Canon.pm:4338`, `$$self{Model} =~ /EOS 7D$/` — anchored,
/// so the original 7D only, NOT "7D Mark II").
#[must_use]
pub fn model_is_camera_info_7d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 7D"))
}

/// `%Canon::CameraInfo1D` (`Canon.pm:3158-3283`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook`. Shared by the
/// original 1D and 1DS, which carry several leaves at DIFFERENT offsets gated by
/// per-model `Condition`s (`/\b1D$/` vs `/\b1DS$/`). The focal-length leaves are
/// PLAIN `int16u` here (not the `int16uRev` of the shared `%ci*` defs), and the
/// `WhiteBalance` leaves are 1-byte `int8u` (no `Format` override).
fn camera_info_1d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let is_1d = model_is_1d_proper(model);
  let is_1ds = model_is_1ds(model);
  // 0x04 ExposureTime (%ciExposureTime, int8u, drop-0).
  emit_ci_exposure_time(data, 0x04, print_conv, &mut push);
  // 0x0a FocalLength — PLAIN int16u (file order, NOT int16uRev), RawConv drop-0.
  if let Some(v) = u16(data, 0x0a, order)
    && v != 0
  {
    push("FocalLength", mm_value(v, print_conv));
  }
  // 0x0d LensType (int16uRev, RawConv drop-0, %canonLensTypes). Overlaps the
  // 0x0e MinFocalLength leaf by one byte (faithful to the table key layout).
  if let Some(v) = u16_rev(data, 0x0d, order)
    && v != 0
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0x0e MinFocalLength / 0x10 MaxFocalLength — PLAIN int16u (file order).
  if let Some(v) = u16(data, 0x0e, order) {
    push("MinFocalLength", mm_value(v, print_conv));
  }
  if let Some(v) = u16(data, 0x10, order) {
    push("MaxFocalLength", mm_value(v, print_conv));
  }
  // The 1D-only block (`Condition => /\b1D$/`), emitted in table-key order.
  if is_1d {
    if let Some(v) = i8u(data, 0x41) {
      push(
        "SharpnessFrequency",
        enum8(v, print_conv, sharpness_frequency_label),
      );
    }
    if let Some(v) = i8s(data, 0x42) {
      push("Sharpness", TagValue::I64(v));
    }
    emit_white_balance_int8u(data, 0x44, print_conv, &mut push);
    emit_color_temperature(data, 0x48, order, &mut push);
    emit_picture_style(data, 0x4b, print_conv, &mut push);
  }
  // The 1DS-only block (`Condition => /\b1DS$/`): 0x48 is `Sharpness` here (it is
  // `ColorTemperature` for the 1D), and ColorTemperature moves to 0x4e.
  if is_1ds {
    if let Some(v) = i8u(data, 0x47) {
      push(
        "SharpnessFrequency",
        enum8(v, print_conv, sharpness_frequency_label),
      );
    }
    if let Some(v) = i8s(data, 0x48) {
      push("Sharpness", TagValue::I64(v));
    }
    emit_white_balance_int8u(data, 0x4a, print_conv, &mut push);
    emit_color_temperature(data, 0x4e, order, &mut push);
    emit_picture_style(data, 0x51, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo1DmkII` (`Canon.pm:3287-3361`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook`. Shared by the 1DmkII
/// and 1DSmkII. `LensType` (0x0c) is drop-0 int16uRev; `ColorTemperature` (0x37)
/// is int16uRev (unlike the plain-int16u variant elsewhere); `WhiteBalance`
/// (0x36) is 1-byte int8u; `ISO` (0x75) is a `string[5]`; `Saturation`/`ColorTone`/
/// `Contrast` use `Exif::printParameter` while `Sharpness` (0x72) is a plain int8s.
fn camera_info_1dmkii(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_ci_exposure_time(data, 0x04, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x09,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  if let Some(v) = u16_rev(data, 0x0c, order)
    && v != 0
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  emit_focal_mm(
    data,
    0x11,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x13,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  if let Some(v) = i8u(data, 0x2d) {
    push("FocalType", enum8(v, print_conv, focal_type_label));
  }
  emit_white_balance_int8u(data, 0x36, print_conv, &mut push);
  emit_color_temperature_rev(data, 0x37, order, &mut push);
  emit_canon_image_size(data, 0x39, order, print_conv, &mut push);
  if let Some(v) = i8u(data, 0x66) {
    push("JPEGQuality", TagValue::I64(v));
  }
  emit_picture_style(data, 0x6c, print_conv, &mut push);
  emit_print_parameter(data, 0x6e, "Saturation", print_conv, &mut push);
  emit_print_parameter(data, 0x6f, "ColorTone", print_conv, &mut push);
  if let Some(v) = i8s(data, 0x72) {
    push("Sharpness", TagValue::I64(v));
  }
  emit_print_parameter(data, 0x73, "Contrast", print_conv, &mut push);
  emit_string_leaf(data, 0x75, 5, "ISO", &mut push);
  out
}

/// `%Canon::CameraInfo1DmkIIN` (`Canon.pm:3365-3422`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook`. Like the 1DmkII but
/// without `FocalType`/`CanonImageSize`/`JPEGQuality`, and with the
/// `PictureStyle`/`Sharpness`/`Contrast`/`Saturation`/`ColorTone`/`ISO` leaves at
/// different (0x73-row) offsets.
fn camera_info_1dmkiin(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_ci_exposure_time(data, 0x04, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x09,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  if let Some(v) = u16_rev(data, 0x0c, order)
    && v != 0
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  emit_focal_mm(
    data,
    0x11,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x13,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance_int8u(data, 0x36, print_conv, &mut push);
  emit_color_temperature_rev(data, 0x37, order, &mut push);
  emit_picture_style(data, 0x73, print_conv, &mut push);
  if let Some(v) = i8s(data, 0x74) {
    push("Sharpness", TagValue::I64(v));
  }
  emit_print_parameter(data, 0x75, "Contrast", print_conv, &mut push);
  emit_print_parameter(data, 0x76, "Saturation", print_conv, &mut push);
  emit_print_parameter(data, 0x77, "ColorTone", print_conv, &mut push);
  emit_string_leaf(data, 0x79, 5, "ISO", &mut push);
  out
}

/// `%Canon::CameraInfo1DmkIII` (`Canon.pm:3425-3538`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook`, but `IS_SUBDIR =>
/// [0x2aa]` (the `PictureStyleInfo` walks `%Canon::PSInfo`). Shared by the
/// 1DmkIII and 1DSmkIII; carries the full `%ci*` triple plus `ShutterCount`
/// (int32u `$val+1`) and TWO timestamps — `TimeStamp1` (0x45a, 1DmkIII-only via
/// `/\b1D Mark III$/`) and `TimeStamp` (0x45e, both), each drop-0 + ConvertUnixTime.
fn camera_info_1dmkiii(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x5e, order, print_conv, &mut push);
  emit_color_temperature(data, 0x62, order, &mut push);
  emit_picture_style(data, 0x86, print_conv, &mut push);
  emit_lens_type(data, 0x111, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x113,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x115,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x136, false, &mut push);
  emit_file_index(data, 0x172, order, &mut push);
  // 0x176 ShutterCount (int32u, ValueConv `$val + 1`, no RawConv guard).
  if let Some(v) = u32(data, 0x176, order) {
    push("ShutterCount", TagValue::I64(v + 1));
  }
  emit_directory_index(data, 0x17e, order, true, &mut push);
  ps_info(data, 0x2aa, order, print_conv, &mut push);
  // 0x45a TimeStamp1 (1DmkIII proper only) / 0x45e TimeStamp (both) — int32u,
  // RawConv drop-0, ConvertUnixTime (rendered identically in `-j`/`-n`).
  if model_is_1dmkiii_proper(model)
    && let Some(v) = u32(data, 0x45a, order)
    && v != 0
  {
    push(
      "TimeStamp1",
      TagValue::Str(SmolStr::from(convert_unix_time(v))),
    );
  }
  if let Some(v) = u32(data, 0x45e, order)
    && v != 0
  {
    push(
      "TimeStamp",
      TagValue::Str(SmolStr::from(convert_unix_time(v))),
    );
  }
  out
}

/// `%Canon::CameraInfo80D` (`Canon.pm:4978-5039`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook` and NO
/// `PictureStyleInfo` subdir. Carries the `%ci*` triple, int16u
/// `ColorTemperature`, int16uRev `LensType`, and a `FirmwareVersion` (0x45a) with
/// NO `RawConv` guard; no `WhiteBalance`/`PictureStyle` leaf.
fn camera_info_80d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x96, print_conv, &mut push);
  emit_focus_distance(
    data,
    0xa5,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0xa7,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_color_temperature(data, 0x13a, order, &mut push);
  emit_lens_type(data, 0x189, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x18b,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x18d,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x45a, false, &mut push);
  emit_file_index(data, 0x4ae, order, &mut push);
  emit_directory_index(data, 0x4ba, order, true, &mut push);
  out
}

/// `%Canon::CameraInfo750D` (`Canon.pm:5554-5620`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`, NO firmware `Hook` and NO
/// `PictureStyleInfo` subdir. Shared by the 750D and 760D. Carries int16u
/// `WhiteBalance`/`ColorTemperature`, an int8u `PictureStyle`, an int16uRev
/// `LensType`, and TWO `FirmwareVersion` rows (0x43d firmware 6.7.2, 0x449
/// firmware 1.0.0) — both carrying the `/^\d+\.\d+\.\d+\s*$/` RawConv guard, so a
/// real file emits from whichever location holds the valid version string.
fn camera_info_750d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x96, print_conv, &mut push);
  emit_focus_distance(
    data,
    0xa5,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0xa7,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x131, order, print_conv, &mut push);
  emit_color_temperature(data, 0x135, order, &mut push);
  emit_picture_style(data, 0x169, print_conv, &mut push);
  emit_lens_type(data, 0x184, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x186,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x188,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x43d, true, &mut push);
  emit_firmware_version(data, 0x449, true, &mut push);
  out
}

/// `%Canon::CameraInfo5D` (`Canon.pm:3777-3964`).
fn camera_info_5d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  // 0x03 FNumber (int8u, RawConv drop-0, exp((val-8)/16*ln2), PrintConv %.2g).
  if let Some(raw) = i8u(data, 0x03)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  // 0x04 ExposureTime (int8u, RawConv drop-0, exp(4*ln2*(1-CanonEv(val-24)))).
  if let Some(raw) = i8u(data, 0x04)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
  // 0x06 ISO (int8u, 100*exp((val/8-9)*ln2), PrintConv %.0f).
  if let Some(raw) = i8u(data, 0x06) {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
  // 0x0c LensType (int16uRev, RawConv drop-0, %canonLensTypes).
  if let Some(v) = u16_rev(data, 0x0c, order)
    && v != 0
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0x17 CameraTemperature (int8u, val-128, "$val C").
  if let Some(raw) = i8u(data, 0x17) {
    let c = raw - 128;
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{c} C")))
      } else {
        TagValue::I64(c)
      },
    );
  }
  // 0x27 CameraOrientation (int8s, PrintConv).
  if let Some(v) = i8s(data, 0x27) {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
  // 0x28 FocalLength (int16uRev, RawConv drop-0, "$val mm").
  if let Some(v) = u16_rev(data, 0x28, order)
    && v != 0
  {
    push("FocalLength", mm_value(v, print_conv));
  }
  // 0x38 AFPointsInFocus5D (int16uRev, BITMASK).
  if let Some(v) = u16_rev(data, 0x38, order) {
    push(
      "AFPointsInFocus5D",
      if print_conv {
        TagValue::Str(SmolStr::from(af_points_in_focus_5d(v)))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x54 WhiteBalance (int16u, %canonWhiteBalance).
  if let Some(v) = u16(data, 0x54, order) {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x58 ColorTemperature (int16u, plain).
  if let Some(v) = u16(data, 0x58, order) {
    push("ColorTemperature", TagValue::I64(v));
  }
  // 0x6c PictureStyle (int8u, PrintHex, %pictureStyles).
  if let Some(v) = i8u(data, 0x6c) {
    push("PictureStyle", picture_style_value(v, print_conv));
  }
  // 0x93 MinFocalLength, 0x95 MaxFocalLength (int16uRev, "$val mm").
  if let Some(v) = u16_rev(data, 0x93, order) {
    push("MinFocalLength", mm_value(v, print_conv));
  }
  if let Some(v) = u16_rev(data, 0x95, order) {
    push("MaxFocalLength", mm_value(v, print_conv));
  }
  // 0x97 LensType (int16uRev, %canonLensTypes).
  if let Some(v) = u16_rev(data, 0x97, order) {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0xa4 FirmwareRevision (string[8]); 0xac ShortOwnerName (string[16]).
  if let Some(s) = read_string(data, 0xa4, 8) {
    push("FirmwareRevision", TagValue::Str(SmolStr::from(s)));
  }
  if let Some(s) = read_string(data, 0xac, 16) {
    push("ShortOwnerName", TagValue::Str(SmolStr::from(s)));
  }
  // 0xcc DirectoryIndex (int32u, plain).
  if let Some(v) = u32(data, 0xcc, order) {
    push("DirectoryIndex", TagValue::I64(v));
  }
  // 0xd0 FileIndex (int16u, ValueConv $val+1).
  if let Some(v) = u16(data, 0xd0, order) {
    push("FileIndex", TagValue::I64(v + 1));
  }
  // 0xe8..0x10b — plain int8s style scalars (no PrintConv).
  for &(off, name) in STYLE_SCALARS_5D {
    if let Some(v) = i8s(data, off) {
      push(name, TagValue::I64(v));
    }
  }
  // 0xff FilterEffectMonochrome, 0x108 ToningEffectMonochrome (int8s, PrintConv).
  if let Some(v) = i8s(data, 0xff) {
    push(
      "FilterEffectMonochrome",
      enum8(v, print_conv, filter_effect_label),
    );
  }
  if let Some(v) = i8s(data, 0x108) {
    push(
      "ToningEffectMonochrome",
      enum8(v, print_conv, toning_effect_label),
    );
  }
  // 0x10c/0x10e/0x110 UserDef{1,2,3}PictureStyle (int16u, %userDefStyles).
  for &(off, name) in &[
    (0x10c, "UserDef1PictureStyle"),
    (0x10e, "UserDef2PictureStyle"),
    (0x110, "UserDef3PictureStyle"),
  ] {
    if let Some(v) = u16(data, off, order) {
      push(name, user_def_style_value(v, print_conv));
    }
  }
  // 0x11c TimeStamp (int32u, RawConv drop-0, ConvertUnixTime ⇒ same in -j/-n).
  if let Some(v) = u32(data, 0x11c, order)
    && v != 0
  {
    push(
      "TimeStamp",
      TagValue::Str(SmolStr::from(convert_unix_time(v))),
    );
  }
  out
}

/// `%Canon::CameraInfo6D` (`Canon.pm:4261-4339`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `WhiteBalance` (0xc2) and a
/// PictureStyle leaf; `FirmwareVersion` (0x256) has NO `RawConv` guard. The
/// `0x3c6 PictureStyleInfo` `IS_SUBDIR` walks the nested `%Canon::PSInfo2` table
/// (the 60D-group variant with the extra `*Auto` style block).
fn camera_info_6d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x83, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x92,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x94,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0xc2, order, print_conv, &mut push);
  emit_color_temperature(data, 0xc6, order, &mut push);
  emit_picture_style(data, 0xfa, print_conv, &mut push);
  emit_lens_type(data, 0x161, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x163,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x165,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x256, false, &mut push);
  emit_file_index(data, 0x2aa, order, &mut push);
  emit_directory_index(data, 0x2b6, order, true, &mut push);
  ps_info2(data, 0x3c6, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo7D` (`Canon.pm:4342-4489`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`. The `0x1e` `Hook` shifts every leaf at/after 0x1e by
/// `varSize` (firmware-version dependent); the `0x327 PictureStyleInfo`
/// `IS_SUBDIR` walks the nested `%Canon::PSInfo` table.
fn camera_info_7d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  // 0x00 FirmwareVersionLookAhead (`Canon.pm:4354-4368`): probe the firmware
  // string position to set CanonFirm, which drives the 0x1e `Hook` shift.
  let canon_firm = canon_firm_7d(data);
  // 0x1e `Hook`: `$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if
  // $$self{CanonFirm} < 2` — applied to EVERY leaf at byte offset >= 0x1e.
  let var_size: i64 = if canon_firm < 2 {
    if canon_firm != 0 { -4 } else { 0x1_0000 }
  } else {
    0
  };
  // Map a table offset to its actual byte offset (the `Hook` shift fires at
  // 0x1e). `None` when the shifted offset is not representable (CanonFirm == 0
  // pushes every later leaf out of range — ExifTool emits nothing for them).
  let at = |off: usize| -> Option<usize> {
    let a: i64 = if off >= 0x1e {
      off as i64 + var_size
    } else {
      off as i64
    };
    usize::try_from(a).ok()
  };

  // 0x03 FNumber / 0x04 ExposureTime / 0x06 ISO (`%ciFNumber`/`%ciExposureTime`/
  // `%ciISO`, int8u). FNumber/ExposureTime collide with the walked-first
  // `ShotInfo` (`Priority => 0` ⇒ suppressed); ISO is the lone non-colliding leaf.
  if let Some(off) = at(0x03)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  if let Some(off) = at(0x04)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
  if let Some(off) = at(0x06)
    && let Some(raw) = i8u(data, off)
  {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
  // 0x07 HighlightTonePriority (int8u, %offOn).
  if let Some(off) = at(0x07)
    && let Some(v) = i8u(data, off)
  {
    push("HighlightTonePriority", enum8(v, print_conv, off_on_label));
  }
  // 0x08 MeasuredEV2 / 0x09 MeasuredEV (int8u, RawConv drop-0, `$val/8-6`,
  // NO PrintConv ⇒ a bare JSON number in both views).
  if let Some(off) = at(0x08)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    push("MeasuredEV2", ev_value(raw as f64 / 8.0 - 6.0));
  }
  if let Some(off) = at(0x09)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    push("MeasuredEV", ev_value(raw as f64 / 8.0 - 6.0));
  }
  // 0x15 FlashMeteringMode (int8u, PrintConv hash).
  if let Some(off) = at(0x15)
    && let Some(v) = i8u(data, off)
  {
    push(
      "FlashMeteringMode",
      enum8(v, print_conv, flash_metering_mode_label),
    );
  }
  // 0x19 CameraTemperature (`%ciCameraTemperature`, int8u, `$val-128`, "$val C").
  if let Some(off) = at(0x19)
    && let Some(raw) = i8u(data, off)
  {
    let c = raw - 128;
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{c} C")))
      } else {
        TagValue::I64(c)
      },
    );
  }
  // 0x1e FocalLength (`%ciFocalLength`, int16uRev, RawConv drop-0, "$val mm")
  // — the `Hook` leaf itself (read at the shifted offset).
  if let Some(off) = at(0x1e)
    && let Some(v) = u16_rev(data, off, order)
    && v != 0
  {
    push("FocalLength", mm_value(v, print_conv));
  }
  // 0x35 CameraOrientation (int8u, PrintConv).
  if let Some(off) = at(0x35)
    && let Some(v) = i8u(data, off)
  {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
  // 0x54 FocusDistanceUpper / 0x56 FocusDistanceLower (`%focusDistanceByteSwap`,
  // int16uRev, `$val/100`, ">655.345 ? inf : '$val m'"). Collide with the
  // higher-priority `FileInfo` leaves (walked later ⇒ they win).
  if let Some(off) = at(0x54)
    && let Some(raw) = u16_rev(data, off, order)
  {
    push("FocusDistanceUpper", focus_distance_value(raw, print_conv));
  }
  if let Some(off) = at(0x56)
    && let Some(raw) = u16_rev(data, off, order)
  {
    push("FocusDistanceLower", focus_distance_value(raw, print_conv));
  }
  // 0x77 WhiteBalance (int16u, %canonWhiteBalance).
  if let Some(off) = at(0x77)
    && let Some(v) = u16(data, off, order)
  {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x7b ColorTemperature (int16u, plain).
  if let Some(off) = at(0x7b)
    && let Some(v) = u16(data, off, order)
  {
    push("ColorTemperature", TagValue::I64(v));
  }
  // 0xaf CameraPictureStyle (int8u, PrintHex, model-specific hash).
  if let Some(off) = at(0xaf)
    && let Some(v) = i8u(data, off)
  {
    push(
      "CameraPictureStyle",
      camera_picture_style_value(v, print_conv),
    );
  }
  // 0xc9 HighISONoiseReduction (int8u, PrintConv hash).
  if let Some(off) = at(0xc9)
    && let Some(v) = i8u(data, off)
  {
    push(
      "HighISONoiseReduction",
      enum8(v, print_conv, high_iso_nr_label),
    );
  }
  // 0x112 LensType (int16uRev, %canonLensTypes).
  if let Some(off) = at(0x112)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0x114 MinFocalLength / 0x116 MaxFocalLength (int16uRev, "$val mm").
  if let Some(off) = at(0x114)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("MinFocalLength", mm_value(v, print_conv));
  }
  if let Some(off) = at(0x116)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("MaxFocalLength", mm_value(v, print_conv));
  }
  // 0x1ac FirmwareVersion (string[6], RawConv `/^\d+\.\d+\.\d+\s*$/`).
  if let Some(off) = at(0x1ac)
    && let Some(s) = read_string(data, off, 6)
    && is_firmware_version(&s)
  {
    push("FirmwareVersion", TagValue::Str(SmolStr::from(s)));
  }
  // 0x1eb FileIndex (int32u, ValueConv `$val + 1`).
  if let Some(off) = at(0x1eb)
    && let Some(v) = u32(data, off, order)
  {
    push("FileIndex", TagValue::I64(v + 1));
  }
  // 0x1f7 DirectoryIndex (int32u, ValueConv `$val - 1`).
  if let Some(off) = at(0x1f7)
    && let Some(v) = u32(data, off, order)
  {
    push("DirectoryIndex", TagValue::I64(v - 1));
  }
  // 0x327 PictureStyleInfo (`IS_SUBDIR` ⇒ `%Canon::PSInfo`, FIRST_ENTRY 0,
  // PRIORITY 0). The SubDirectory starts at the shifted 0x327.
  if let Some(ps_start) = at(0x327) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo40D` (`Canon.pm:4492-4581`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, NO firmware `Hook` (every leaf at its nominal offset). The
/// `0x25b PictureStyleInfo` `IS_SUBDIR` walks the nested `%Canon::PSInfo` table.
fn camera_info_40d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xd6, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xd8,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xda,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0xff, false, &mut push);
  emit_file_index(data, 0x133, order, &mut push);
  emit_directory_index(data, 0x13f, order, true, &mut push);
  ps_info(data, 0x25b, order, print_conv, &mut push);
  emit_string_leaf(data, 0x92b, 64, "LensModel", &mut push);
  out
}

/// `%Canon::CameraInfo50D` (`Canon.pm:4584-4715`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`. The `0x00 FirmwareVersionLookAhead` sets `CanonFirm` (probing
/// the version string at 0x15a then 0x15e); the `0xee` `Hook`
/// (`$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if $$self{CanonFirm} < 2`)
/// shifts every leaf AFTER 0xee. `0x2d7 PictureStyleInfo` walks `%Canon::PSInfo`.
fn camera_info_50d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_50d(data);
  let var_size: i64 = if canon_firm < 2 {
    if canon_firm != 0 { -4 } else { 0x1_0000 }
  } else {
    0
  };
  // The `0xee` Hook fires AFTER its own entry's value is read (ExifTool.pm:9957
  // computes the offset, :10049 runs the Hook, :10076 reads at the PRE-Hook
  // offset), so MaxFocalLength (0xee) is read UNSHIFTED and only leaves STRICTLY
  // after 0xee take the `varSize` shift. `None` ⇒ the shifted offset is out of
  // range (CanonFirm == 0 pushes every later leaf out — ExifTool emits nothing).
  let at = |off: usize| -> Option<usize> {
    let a: i64 = if off > 0xee {
      off as i64 + var_size
    } else {
      off as i64
    };
    usize::try_from(a).ok()
  };
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x31, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x50,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x52,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_picture_style(data, 0xa7, print_conv, &mut push);
  emit_high_iso_nr(data, 0xbd, print_conv, &mut push);
  emit_auto_lighting_optimizer(data, 0xbf, print_conv, &mut push);
  emit_lens_type(data, 0xea, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xec,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xee,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  if let Some(off) = at(0x15e) {
    emit_firmware_version(data, off, false, &mut push);
  }
  if let Some(off) = at(0x19b) {
    emit_file_index(data, off, order, &mut push);
  }
  if let Some(off) = at(0x1a7) {
    emit_directory_index(data, off, order, true, &mut push);
  }
  if let Some(ps_start) = at(0x2d7) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo50D` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:4601-4609`): `CanonFirm = 1` if a `D.D.D` version prefix sits at
/// 0x15a, else `2` if at 0x15e, else `0` (ExifTool warns then the `Hook` shifts
/// every later leaf out of range).
fn canon_firm_50d(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x15a) {
    1
  } else if firmware_prefix_at(data, 0x15e) {
    2
  } else {
    0
  }
}

/// Map a `CameraInfo` table offset to its byte offset under the firmware
/// `hooks`. Each `(hook_off, delta)` shifts every leaf STRICTLY after `hook_off`
/// by `delta`, and the shifts accumulate — a faithful port of ExifTool's
/// `varSize` mechanism (`ExifTool.pm:9957`/`10049`/`10076`): a tag's offset is
/// computed with the PRE-Hook `varSize`, its `Hook` then adjusts `varSize` for
/// every LATER tag, so the Hook-bearing entry itself is read UNSHIFTED (hence
/// `off > hook_off`, strictly). `None` ⇒ the shifted offset is not
/// representable — the unrecognized-firmware `+0x10000` abort pushes later
/// leaves out of range, where ExifTool (having `Warn`ed and set `CanonFirm = 0`)
/// emits nothing.
fn shifted_at(off: usize, hooks: &[(usize, i64)]) -> Option<usize> {
  let mut a = off as i64;
  for &(hook_off, delta) in hooks {
    if off > hook_off {
      a += delta;
    }
  }
  usize::try_from(a).ok()
}

/// `%Canon::CameraInfo5DmkII` (`Canon.pm:3967-4109`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`. The `0x00 FirmwareVersionLookAhead` sets
/// `CanonFirm` (probing the version string at 0x15a then 0x17e); the SINGLE
/// `0xea` `Hook` shifts every leaf AFTER 0xea. `0x2f7 PictureStyleInfo` walks
/// `%Canon::PSInfo`; `canon_lens_type` gates the `0x1b MacroMagnification` leaf.
fn camera_info_5dmkii(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_5dmkii(data);
  let hooks: [(usize, i64); 1] = [(0xea, hook_5dmkii_ea(canon_firm))];
  let at = |off: usize| shifted_at(off, &hooks);

  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_model(data, 0x13, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x31, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x50,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x52,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_picture_style(data, 0xa7, print_conv, &mut push);
  emit_high_iso_nr(data, 0xbd, print_conv, &mut push);
  emit_auto_lighting_optimizer(data, 0xbf, print_conv, &mut push);
  emit_lens_type(data, 0xe6, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xe8,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  // 0xea MaxFocalLength — the `Hook` entry, read at the UNSHIFTED 0xea.
  emit_focal_mm(
    data,
    0xea,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  // 0x17e FirmwareVersion (string[6], RawConv `/^\d+\.\d+\.\d+\s*$/`).
  if let Some(off) = at(0x17e) {
    emit_firmware_version(data, off, true, &mut push);
  }
  // 0x18e OwnerName (string[32], Priority 0).
  if let Some(off) = at(0x18e) {
    emit_string_leaf(data, off, 32, "OwnerName", &mut push);
  }
  if let Some(off) = at(0x1bb) {
    emit_file_index(data, off, order, &mut push);
  }
  if let Some(off) = at(0x1c7) {
    emit_directory_index(data, off, order, true, &mut push);
  }
  if let Some(ps_start) = at(0x2f7) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo5DmkII` `0xea` `Hook` `varSize` delta (`Canon.pm:4077`,
/// `$varSize += ($$self{CanonFirm} ? -36 : 0x10000) if $$self{CanonFirm} < 2`):
/// `-36` for firmware 1 (3.4.6/3.6.1), `+0x10000` (out-of-range abort) for an
/// unrecognized firmware (`CanonFirm == 0`, after the `Warn`), `0` for firmware
/// 2 (4.1.1/1.0.6).
fn hook_5dmkii_ea(canon_firm: u8) -> i64 {
  if canon_firm < 2 {
    if canon_firm != 0 { -36 } else { 0x1_0000 }
  } else {
    0
  }
}

/// `%Canon::CameraInfo5DmkII` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:3984-3992`): `CanonFirm = 1` if a `D.D.D` version prefix sits at
/// 0x15a, else `2` if at 0x17e, else `0` (ExifTool warns then the `Hook` shifts
/// every later leaf out of range).
fn canon_firm_5dmkii(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x15a) {
    1
  } else if firmware_prefix_at(data, 0x17e) {
    2
  } else {
    0
  }
}

/// A `MeasuredEV*` leaf (int8u, `RawConv => '$val ? $val : undef'`, `ValueConv =>
/// '$val / 8 - 6'`, NO PrintConv ⇒ a bare number in both views).
fn emit_measured_ev<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off)
    && raw != 0
  {
    push(name, ev_value(raw as f64 / 8.0 - 6.0));
  }
}

/// `%Canon::CameraInfo1DmkIV` (`Canon.pm:3541-3662`). Default `FORMAT` (int8u),
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`. TWO firmware Hooks — 0x56
/// (FocusDistanceLower) and 0x153 (MaxFocalLength) — whose `varSize` shifts
/// accumulate over every later leaf. The `0x00 FirmwareVersionLookAhead` probes
/// 0x1e8 (CanonFirm 1) then 0x1ed (CanonFirm 2). `0x368 PictureStyleInfo` walks
/// `%Canon::PSInfo`.
fn camera_info_1dmkiv(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_1dmkiv(data);
  let hooks: [(usize, i64); 2] = [
    (0x56, hook_1dmkiv_56(canon_firm)),
    (0x153, hook_1dmkiv_153(canon_firm)),
  ];
  let at = |off: usize| shifted_at(off, &hooks);

  // Leaves at/before the first Hook (0x56) read at their nominal offsets.
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_measured_ev(data, 0x08, "MeasuredEV2", &mut push);
  emit_measured_ev(data, 0x09, "MeasuredEV3", &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x35, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x54,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  // 0x56 FocusDistanceLower — the first Hook entry, read at the UNSHIFTED 0x56.
  emit_focus_distance(
    data,
    0x56,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  // Leaves after 0x56 take the 0x56 Hook; leaves after 0x153 add the 0x153 Hook.
  if let Some(o) = at(0x78) {
    emit_white_balance(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x7c) {
    emit_color_temperature(data, o, order, &mut push);
  }
  if let Some(o) = at(0x14f) {
    emit_lens_type(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x151) {
    emit_focal_mm(
      data,
      o,
      "MinFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x153 MaxFocalLength — the second Hook entry, read at 0x153 + the 0x56 Hook.
  if let Some(o) = at(0x153) {
    emit_focal_mm(
      data,
      o,
      "MaxFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x1ed FirmwareVersion (string[6], NO RawConv guard).
  if let Some(o) = at(0x1ed) {
    emit_firmware_version(data, o, false, &mut push);
  }
  if let Some(o) = at(0x22c) {
    emit_file_index(data, o, order, &mut push);
  }
  if let Some(o) = at(0x238) {
    emit_directory_index(data, o, order, true, &mut push);
  }
  if let Some(ps_start) = at(0x368) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo1DmkIV` 0x56 (FocusDistanceLower) `Hook` delta
/// (`Canon.pm:3615`, `$varSize += ($$self{CanonFirm} ? -1 : 0x10000) if
/// $$self{CanonFirm} < 2`): `-1` for firmware 1 (4.2.1), `+0x10000` (out-of-range
/// abort) for an unrecognized firmware, `0` for firmware 2 (1.0.4).
fn hook_1dmkiv_56(canon_firm: u8) -> i64 {
  if canon_firm < 2 {
    if canon_firm != 0 { -1 } else { 0x1_0000 }
  } else {
    0
  }
}

/// `%Canon::CameraInfo1DmkIV` 0x153 (MaxFocalLength) `Hook` delta
/// (`Canon.pm:3637`, `$varSize -= 4 if $$self{CanonFirm} < 2`): `-4` for firmware
/// 0/1, `0` for firmware 2.
fn hook_1dmkiv_153(canon_firm: u8) -> i64 {
  if canon_firm < 2 { -4 } else { 0 }
}

/// `%Canon::CameraInfo1DmkIV` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:3557-3564`): `CanonFirm = 1` if a `D.D.D` prefix sits at 0x1e8,
/// else `2` if at 0x1ed, else `0` (ExifTool warns then the Hooks shift later
/// leaves out of range).
fn canon_firm_1dmkiv(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x1e8) {
    1
  } else if firmware_prefix_at(data, 0x1ed) {
    2
  } else {
    0
  }
}

/// `%Canon::CameraInfo1DX` (`Canon.pm:3665-3773`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`. THREE firmware Hooks — 0x1b
/// (CameraTemperature), 0x8e (FocusDistanceLower) and 0x1ab (MaxFocalLength).
/// The `0x00 FirmwareVersionLookAhead` probes 0x271/0x279/0x280/0x285
/// (CanonFirm 1..4). `0x3f4 PictureStyleInfo` walks `%Canon::PSInfo2`. Note the
/// `+0x10000` abort lives on the THIRD Hook (0x1ab), so an unrecognized firmware
/// still emits the leaves up to 0x1a9 (each `-3`/`-7` shifted) before the rest
/// fall out of range.
fn camera_info_1dx(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_1dx(data);
  let hooks: [(usize, i64); 3] = [
    (0x1b, hook_1dx_1b(canon_firm)),
    (0x8e, hook_1dx_8e(canon_firm)),
    (0x1ab, hook_1dx_1ab(canon_firm)),
  ];
  let at = |off: usize| shifted_at(off, &hooks);

  // 0x03/0x04/0x06 and the 0x1b Hook entry read at their nominal offsets.
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  // Every leaf after 0x1b takes the 0x1b Hook; after 0x8e adds the 0x8e Hook;
  // after 0x1ab adds the 0x1ab Hook.
  if let Some(o) = at(0x23) {
    emit_focal_mm(data, o, "FocalLength", true, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x7d) {
    emit_camera_orientation(data, o, print_conv, &mut push);
  }
  if let Some(o) = at(0x8c) {
    emit_focus_distance(data, o, "FocusDistanceUpper", order, print_conv, &mut push);
  }
  // 0x8e FocusDistanceLower — the second Hook entry, read at 0x8e + the 0x1b Hook.
  if let Some(o) = at(0x8e) {
    emit_focus_distance(data, o, "FocusDistanceLower", order, print_conv, &mut push);
  }
  if let Some(o) = at(0xbc) {
    emit_white_balance(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0xc0) {
    emit_color_temperature(data, o, order, &mut push);
  }
  if let Some(o) = at(0xf4) {
    emit_picture_style(data, o, print_conv, &mut push);
  }
  if let Some(o) = at(0x1a7) {
    emit_lens_type(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x1a9) {
    emit_focal_mm(
      data,
      o,
      "MinFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x1ab MaxFocalLength — the third Hook entry, read at 0x1ab + the 0x1b/0x8e Hooks.
  if let Some(o) = at(0x1ab) {
    emit_focal_mm(
      data,
      o,
      "MaxFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x280 FirmwareVersion (string[6], NO RawConv guard).
  if let Some(o) = at(0x280) {
    emit_firmware_version(data, o, false, &mut push);
  }
  if let Some(o) = at(0x2d0) {
    emit_file_index(data, o, order, &mut push);
  }
  if let Some(o) = at(0x2dc) {
    emit_directory_index(data, o, order, true, &mut push);
  }
  if let Some(ps_start) = at(0x3f4) {
    ps_info2(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo1DX` 0x1b (CameraTemperature) `Hook` delta
/// (`Canon.pm:3700`, `$varSize -= 3 if $$self{CanonFirm} < 3`): `-3` for firmware
/// 0/1/2, `0` for firmware 3/4. (Unlike the other tables, the 1DX `0x1b` Hook
/// carries NO `0x10000` abort for an unrecognized firmware.)
fn hook_1dx_1b(canon_firm: u8) -> i64 {
  if canon_firm < 3 { -3 } else { 0 }
}

/// `%Canon::CameraInfo1DX` 0x8e (FocusDistanceLower) `Hook` delta
/// (`Canon.pm:3718`, `$varSize -= 4 if $$self{CanonFirm} < 3; $varSize += 5 if
/// $$self{CanonFirm} == 4`): `-4` for firmware 0/1/2, `+5` for firmware 4, `0`
/// for firmware 3.
fn hook_1dx_8e(canon_firm: u8) -> i64 {
  let lt3 = if canon_firm < 3 { -4 } else { 0 };
  let eq4 = if canon_firm == 4 { 5 } else { 0 };
  lt3 + eq4
}

/// `%Canon::CameraInfo1DX` 0x1ab (MaxFocalLength) `Hook` delta (`Canon.pm:3748`,
/// `$varSize += ($$self{CanonFirm} ? -8 : 0x10000) if $$self{CanonFirm} < 2`):
/// `-8` for firmware 1, `+0x10000` (out-of-range abort) for an unrecognized
/// firmware, `0` for firmware 2/3/4.
fn hook_1dx_1ab(canon_firm: u8) -> i64 {
  if canon_firm < 2 {
    if canon_firm != 0 { -8 } else { 0x1_0000 }
  } else {
    0
  }
}

/// `%Canon::CameraInfo1DX` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:3682-3693`): `CanonFirm = 1` if a `D.D.D` prefix sits at 0x271,
/// else `2` at 0x279, `3` at 0x280, `4` at 0x285, else `0` (ExifTool warns then
/// the 0x1ab Hook shifts the post-MaxFocal leaves out of range).
fn canon_firm_1dx(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x271) {
    1
  } else if firmware_prefix_at(data, 0x279) {
    2
  } else if firmware_prefix_at(data, 0x280) {
    3
  } else if firmware_prefix_at(data, 0x285) {
    4
  } else {
    0
  }
}

/// `LensSerialNumber` (`Canon.pm:4208-4214`, `undef[5]`, Priority 0, ValueConv
/// `unpack("H*",$val)` ⇒ lowercase hex). The CameraInfo row carries NO RawConv
/// (unlike `%Canon::LensInfo`), so a value beginning with NUL bytes still emits.
fn emit_lens_serial_number<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  push: &mut F,
) {
  if let Some(bytes) = data.get(off..off + 5) {
    let hex: String = bytes.iter().map(|b| std::format!("{b:02x}")).collect();
    push("LensSerialNumber", TagValue::Str(SmolStr::from(hex)));
  }
}

/// A `FileIndex*`/`DirectoryIndex*` int32u leaf named `name`, applying the
/// `ValueConv` `$val + 1` (FileIndex, `delta = 1`) or `$val - 1` (DirectoryIndex,
/// `delta = -1`). The 5DmkIII carries paired primary/`*2` variants.
fn emit_int32_index<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  name: &'static str,
  delta: i64,
  push: &mut F,
) {
  if let Some(v) = u32(data, off, order) {
    push(name, TagValue::I64(v + delta));
  }
}

/// `%Canon::CameraInfo5DmkIII` (`Canon.pm:4112-4258`). `FORMAT => 'int8u'`,
/// `FIRST_ENTRY => 0`, `PRIORITY => 0`. FOUR firmware Hooks — 0x1b
/// (CameraTemperature), 0x23 (FocalLength), 0x8e (FocusDistanceLower) and 0x157
/// (MaxFocalLength) — across five firmware versions. The `0x00
/// FirmwareVersionLookAhead` probes 0x22c/0x22d/0x23c/0x242/0x247 (CanonFirm
/// 1..5; 1.0.x ⇒ 3 is the nominal no-shift layout). `0x3b0 PictureStyleInfo`
/// walks `%Canon::PSInfo2`.
fn camera_info_5dmkiii(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_5dmkiii(data);
  let hooks: [(usize, i64); 4] = [
    (0x1b, hook_5dmkiii_1b(canon_firm)),
    (0x23, hook_5dmkiii_23(canon_firm)),
    (0x8e, hook_5dmkiii_8e(canon_firm)),
    (0x157, hook_5dmkiii_157(canon_firm)),
  ];
  let at = |off: usize| shifted_at(off, &hooks);

  // 0x03/0x04/0x06 and the 0x1b Hook entry read at their nominal offsets.
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  // 0x23 FocalLength — the second Hook entry, read at 0x23 + the 0x1b Hook.
  if let Some(o) = at(0x23) {
    emit_focal_mm(data, o, "FocalLength", true, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x7d) {
    emit_camera_orientation(data, o, print_conv, &mut push);
  }
  if let Some(o) = at(0x8c) {
    emit_focus_distance(data, o, "FocusDistanceUpper", order, print_conv, &mut push);
  }
  // 0x8e FocusDistanceLower — the third Hook entry, read at 0x8e + the 0x1b/0x23 Hooks.
  if let Some(o) = at(0x8e) {
    emit_focus_distance(data, o, "FocusDistanceLower", order, print_conv, &mut push);
  }
  if let Some(o) = at(0xbc) {
    emit_white_balance(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0xc0) {
    emit_color_temperature(data, o, order, &mut push);
  }
  if let Some(o) = at(0xf4) {
    emit_picture_style(data, o, print_conv, &mut push);
  }
  if let Some(o) = at(0x153) {
    emit_lens_type(data, o, order, print_conv, &mut push);
  }
  if let Some(o) = at(0x155) {
    emit_focal_mm(
      data,
      o,
      "MinFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x157 MaxFocalLength — the fourth Hook entry, read at 0x157 + the first 3 Hooks.
  if let Some(o) = at(0x157) {
    emit_focal_mm(
      data,
      o,
      "MaxFocalLength",
      false,
      order,
      print_conv,
      &mut push,
    );
  }
  // 0x164 LensSerialNumber (undef[5], unpack H*).
  if let Some(o) = at(0x164) {
    emit_lens_serial_number(data, o, &mut push);
  }
  // 0x23c FirmwareVersion (string[6], NO RawConv guard).
  if let Some(o) = at(0x23c) {
    emit_firmware_version(data, o, false, &mut push);
  }
  // 0x28c FileIndex / 0x290 FileIndex2 / 0x298 DirectoryIndex / 0x29c DirectoryIndex2.
  if let Some(o) = at(0x28c) {
    emit_int32_index(data, o, order, "FileIndex", 1, &mut push);
  }
  if let Some(o) = at(0x290) {
    emit_int32_index(data, o, order, "FileIndex2", 1, &mut push);
  }
  if let Some(o) = at(0x298) {
    emit_int32_index(data, o, order, "DirectoryIndex", -1, &mut push);
  }
  if let Some(o) = at(0x29c) {
    emit_int32_index(data, o, order, "DirectoryIndex2", -1, &mut push);
  }
  if let Some(ps_start) = at(0x3b0) {
    ps_info2(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo5DmkIII` 0x1b (CameraTemperature) `Hook` delta
/// (`Canon.pm:4151`, `$varSize += ($$self{CanonFirm} ? -1 : 0x10000) if
/// $$self{CanonFirm} < 3`): `-1` for firmware 1/2, `+0x10000` (out-of-range
/// abort) for an unrecognized firmware, `0` for firmware 3/4/5.
fn hook_5dmkiii_1b(canon_firm: u8) -> i64 {
  if canon_firm < 3 {
    if canon_firm != 0 { -1 } else { 0x1_0000 }
  } else {
    0
  }
}

/// `%Canon::CameraInfo5DmkIII` 0x23 (FocalLength) `Hook` delta
/// (`Canon.pm:4154-4158`): `-3` for firmware 1, `-2` for firmware 2, `+6` for
/// firmware 4/5, `0` for firmware 0/3.
fn hook_5dmkiii_23(canon_firm: u8) -> i64 {
  let mark = if canon_firm == 1 {
    -3
  } else if canon_firm == 2 {
    -2
  } else {
    0
  };
  let ge4 = if canon_firm >= 4 { 6 } else { 0 };
  mark + ge4
}

/// `%Canon::CameraInfo5DmkIII` 0x8e (FocusDistanceLower) `Hook` delta
/// (`Canon.pm:4175-4178`): `-4` for firmware 0/1/2, `+5` for firmware 5, `0` for
/// firmware 3/4.
fn hook_5dmkiii_8e(canon_firm: u8) -> i64 {
  let lt3 = if canon_firm < 3 { -4 } else { 0 };
  let gt4 = if canon_firm > 4 { 5 } else { 0 };
  lt3 + gt4
}

/// `%Canon::CameraInfo5DmkIII` 0x157 (MaxFocalLength) `Hook` delta
/// (`Canon.pm:4206`, `$varSize -= 8 if $$self{CanonFirm} < 3`): `-8` for firmware
/// 0/1/2, `0` for firmware 3/4/5.
fn hook_5dmkiii_157(canon_firm: u8) -> i64 {
  if canon_firm < 3 { -8 } else { 0 }
}

/// `%Canon::CameraInfo5DmkIII` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:4129-4143`): `CanonFirm = 1` if a `D.D.D` prefix sits at 0x22c,
/// else `2` at 0x22d, `3` at 0x23c, `4` at 0x242, `5` at 0x247, else `0`
/// (ExifTool warns then the 0x1b Hook shifts every later leaf out of range).
fn canon_firm_5dmkiii(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x22c) {
    1
  } else if firmware_prefix_at(data, 0x22d) {
    2
  } else if firmware_prefix_at(data, 0x23c) {
    3
  } else if firmware_prefix_at(data, 0x242) {
    4
  } else if firmware_prefix_at(data, 0x247) {
    5
  } else {
    0
  }
}

/// `%Canon::CameraInfo60D` (`Canon.pm:4719-4815`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Shared by the 60D and 1200D (`Canon.pm`
/// `0x0d` aliases both onto this table) — several rows carry per-model
/// `Condition`s: the `CameraOrientation` lives at 0x36 (60D) vs 0x3a (1200D), and
/// `FocusDistance*`/`ColorTemperature`/`FileIndex`/`DirectoryIndex` are 60D-only.
/// The `PictureStyleInfo` `IS_SUBDIR` (`%PSInfo2`) is at 0x2f9 (1200D) / 0x321
/// (60D).
fn camera_info_60d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let is_60d = model_is_60d_proper(model);
  let is_1200d = model_is_1200d(model);
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  if is_60d {
    emit_camera_orientation(data, 0x36, print_conv, &mut push);
  }
  if is_1200d {
    emit_camera_orientation(data, 0x3a, print_conv, &mut push);
  }
  if is_60d {
    emit_focus_distance(
      data,
      0x55,
      "FocusDistanceUpper",
      order,
      print_conv,
      &mut push,
    );
    emit_focus_distance(
      data,
      0x57,
      "FocusDistanceLower",
      order,
      print_conv,
      &mut push,
    );
    emit_color_temperature(data, 0x7d, order, &mut push);
  }
  emit_lens_type(data, 0xe8, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xea,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xec,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x199, false, &mut push);
  if is_60d {
    emit_file_index(data, 0x1d9, order, &mut push);
    emit_directory_index(data, 0x1e5, order, true, &mut push);
  }
  if is_1200d {
    ps_info2(data, 0x2f9, order, print_conv, &mut push);
  }
  if is_60d {
    ps_info2(data, 0x321, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo70D` (`Canon.pm:4908-4975`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Like the 6D but with NO `WhiteBalance`
/// leaf; `FirmwareVersion` (0x25e) has NO `RawConv` guard. The `0x3cf
/// PictureStyleInfo` `IS_SUBDIR` walks `%PSInfo2`.
fn camera_info_70d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x84, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x93,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x95,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_color_temperature(data, 0xc7, order, &mut push);
  emit_lens_type(data, 0x166, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x168,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x16a,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x25e, false, &mut push);
  emit_file_index(data, 0x2b3, order, &mut push);
  emit_directory_index(data, 0x2bf, order, true, &mut push);
  ps_info2(data, 0x3cf, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo450D` (`Canon.pm:5042-5130`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `OwnerName` (string[32]) and a
/// PLAIN `DirectoryIndex` (no `$val-1`); `0x263 PictureStyleInfo` walks `%PSInfo`.
fn camera_info_450d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xde, order, print_conv, &mut push);
  emit_firmware_version(data, 0x107, false, &mut push);
  emit_string_leaf(data, 0x10f, 32, "OwnerName", &mut push);
  emit_directory_index(data, 0x133, order, false, &mut push);
  emit_file_index(data, 0x13f, order, &mut push);
  ps_info(data, 0x263, order, print_conv, &mut push);
  emit_string_leaf(data, 0x933, 64, "LensModel", &mut push);
  out
}

/// `%Canon::CameraInfo500D` (`Canon.pm:5133-5243`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. `FirmwareVersion` carries the
/// `/^\d+\.\d+\.\d+\s*$/` RawConv guard; `0x30b PictureStyleInfo` walks `%PSInfo`.
fn camera_info_500d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x31, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x50,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x52,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x73, order, print_conv, &mut push);
  emit_color_temperature(data, 0x77, order, &mut push);
  emit_picture_style(data, 0xab, print_conv, &mut push);
  emit_high_iso_nr(data, 0xbc, print_conv, &mut push);
  emit_auto_lighting_optimizer(data, 0xbe, print_conv, &mut push);
  emit_lens_type(data, 0xf6, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xf8,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xfa,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x190, true, &mut push);
  emit_file_index(data, 0x1d3, order, &mut push);
  emit_directory_index(data, 0x1df, order, true, &mut push);
  ps_info(data, 0x30b, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo550D` (`Canon.pm:5247-5340`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Like the 500D but with NO
/// HighISONoiseReduction/AutoLightingOptimizer; `0x31c PictureStyleInfo` walks
/// `%PSInfo`.
fn camera_info_550d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x35, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x54,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x56,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x78, order, print_conv, &mut push);
  emit_color_temperature(data, 0x7c, order, &mut push);
  emit_picture_style(data, 0xb0, print_conv, &mut push);
  emit_lens_type(data, 0xff, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x101,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x103,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x1a4, true, &mut push);
  emit_file_index(data, 0x1e4, order, &mut push);
  emit_directory_index(data, 0x1f0, order, true, &mut push);
  ps_info(data, 0x31c, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo600D` (`Canon.pm:5343-5436`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Shared by the 600D and 1100D with every
/// row unconditional. Carries `HighlightTonePriority`/`FlashMeteringMode`/
/// `WhiteBalance`/`PictureStyle`; `FirmwareVersion` (0x19b) has the
/// `/^\d+\.\d+\.\d+\s*$/` RawConv guard. `0x2fb PictureStyleInfo` walks `%PSInfo2`.
fn camera_info_600d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x38, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x57,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x59,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x7b, order, print_conv, &mut push);
  emit_color_temperature(data, 0x7f, order, &mut push);
  emit_picture_style(data, 0xb3, print_conv, &mut push);
  emit_lens_type(data, 0xea, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xec,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xee,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x19b, true, &mut push);
  emit_file_index(data, 0x1db, order, &mut push);
  emit_directory_index(data, 0x1e7, order, true, &mut push);
  ps_info2(data, 0x2fb, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo650D` (`Canon.pm:5439-5551`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Shared by the 650D and 700D, which carry
/// the `FirmwareVersion`/`FileIndex`/`DirectoryIndex` leaves at DIFFERENT
/// firmware-location offsets selected by per-model `Condition`s (650D: 0x21b/
/// 0x270/0x27c; 700D: 0x220/0x274/0x280). All three FirmwareVersion variants have
/// the `/^\d+\.\d+\.\d+\s*$/` RawConv guard. `0x390 PictureStyleInfo` walks
/// `%PSInfo2` (both models).
fn camera_info_650d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let is_650d = model_is_650d_proper(model);
  let is_700d = model_is_700d(model);
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x7d, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x8c,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x8e,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0xbc, order, print_conv, &mut push);
  emit_color_temperature(data, 0xc0, order, &mut push);
  emit_picture_style(data, 0xf4, print_conv, &mut push);
  emit_lens_type(data, 0x127, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x129,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x12b,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  if is_650d {
    emit_firmware_version(data, 0x21b, true, &mut push);
  }
  if is_700d {
    emit_firmware_version(data, 0x220, true, &mut push);
  }
  if is_650d {
    emit_file_index(data, 0x270, order, &mut push);
  }
  if is_700d {
    emit_file_index(data, 0x274, order, &mut push);
  }
  if is_650d {
    emit_directory_index(data, 0x27c, order, true, &mut push);
  }
  if is_700d {
    emit_directory_index(data, 0x280, order, true, &mut push);
  }
  ps_info2(data, 0x390, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo1000D` (`Canon.pm:5623-5707`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `FlashModel` (`Mask => 0x7f`,
/// `%flashModel`), `MacroMagnification` (LensType==124), and a PLAIN
/// `DirectoryIndex` (no `$val-1`); `0x267 PictureStyleInfo` walks `%PSInfo`.
fn camera_info_1000d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_model(data, 0x13, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xe2, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xe4,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xe6,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x10b, false, &mut push);
  emit_directory_index(data, 0x137, order, false, &mut push);
  emit_file_index(data, 0x143, order, &mut push);
  ps_info(data, 0x267, order, print_conv, &mut push);
  emit_string_leaf(data, 0x937, 64, "LensModel", &mut push);
  out
}

/// `%Canon::CameraInfoR6` (`Canon.pm:4817-4840`). The mirrorless EOS R5/R6
/// `CameraInfo` (`%binaryDataAttrs` ⇒ `FORMAT => 'int8u'`, `FIRST_ENTRY => 0`,
/// `PRIORITY => 0`), keyed by byte offset like the DSLR `int8u` tables; emitted
/// by ascending offset (CameraTemperature 0x09da, ShutterCount 0x0af1).
fn camera_info_r6(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  // 0x09da CameraTemperature (`Canon.pm:4825`, int8u, `$val-128`, "$val C").
  emit_camera_temperature(data, 0x09da, print_conv, &mut push);
  // 0x0af1 ShutterCount (`Canon.pm:4832`, `Format => 'int32u'`, no conv).
  emit_int32_index(data, 0x0af1, order, "ShutterCount", 0, &mut push);
  out
}

/// `%Canon::CameraInfoR6m2` (`Canon.pm:4842-4853`). The EOS R6 Mark II / R8 / R50
/// `CameraInfo` (int8u, byte-keyed): a single `Format => 'int32u'` ShutterCount
/// (`Canon.pm:4848`). No PrintConv ⇒ identical in both views.
fn camera_info_r6m2(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  // 0x0d29 ShutterCount (`Canon.pm:4848`, `Format => 'int32u'`).
  emit_int32_index(data, 0x0d29, order, "ShutterCount", 0, &mut push);
  out
}

/// `%Canon::CameraInfoR6m3` (`Canon.pm:4855-4866`). The EOS R6 Mark III
/// `CameraInfo` (int8u, byte-keyed): a single `Format => 'int16u'` ImageCount
/// (`Canon.pm:4861`, resets to 0 when the SD card is formatted).
fn camera_info_r6m3(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  // 0x086d ImageCount (`Canon.pm:4861`, `Format => 'int16u'`, no conv).
  if let Some(v) = u16(data, 0x086d, order) {
    push("ImageCount", TagValue::I64(v));
  }
  out
}

/// `%Canon::CameraInfoG5XII` (`Canon.pm:4868-4904`). The PowerShot G5 X Mark II
/// `CameraInfo` (int8u, byte-keyed). Every leaf is `$$self{FileType}`-gated: the
/// JPEG rows (ShutterCount 0x0293, DirectoryIndex 0x0b21, FileIndex 0x0b2d) and
/// the CR3 row (ShutterCount 0x0a95). No PrintConv ⇒ identical in both views.
/// Emitted by ascending offset, exactly as `ProcessBinaryData` walks the indices.
fn camera_info_g5xii(
  data: &[u8],
  order: ByteOrder,
  file_type: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let is_jpeg = file_type == Some("JPEG");
  let is_cr3 = file_type == Some("CR3");
  // 0x0293 ShutterCount (`Canon.pm:4871`, `Format => 'int32u'`) — JPEG only.
  if is_jpeg {
    emit_int32_index(data, 0x0293, order, "ShutterCount", 0, &mut push);
  }
  // 0x0a95 ShutterCount (`Canon.pm:4885`, `Format => 'int32u'`) — CR3 only.
  if is_cr3 {
    emit_int32_index(data, 0x0a95, order, "ShutterCount", 0, &mut push);
  }
  // 0x0b21 DirectoryIndex (`Canon.pm:4891`, `Format => 'int32u'`, no conv) — JPEG.
  if is_jpeg {
    emit_directory_index(data, 0x0b21, order, false, &mut push);
  }
  // 0x0b2d FileIndex (`Canon.pm:4897`, `Format => 'int32u'`, `$val + 1`) — JPEG.
  if is_jpeg {
    emit_file_index(data, 0x0b2d, order, &mut push);
  }
  out
}

// ─── count-selected PowerShot `CameraInfo` tables (Canon.pm:5711-5847) ────────
// Dispatched (`Canon.pm:1466-1479`) AFTER the model-conditional rows, by the
// `0x0d` entry's `$format eq "int32u"` + `$count`, NOT the model. Unlike the
// model tables (`undef`-format, byte-keyed), these are `FORMAT => 'int32s'`,
// `FIRST_ENTRY => 0`, `PRIORITY => 0`: a `ProcessBinaryData` index `i` reads an
// `int32s` at byte offset `i * 4` (`ExifTool.pm:9957`, `$entry = int($index) *
// $formatSize{int32s}`). The on-disk value is read as `int32u[$count]`, so the
// caller widens each word back to 4 bytes (`reserialize_int32_array`); the int16
// blob the model tables use would truncate every word. The shared leaf set
// (ISO/FNumber/ExposureTime/Rotation/CameraTemperature) carries NO `RawConv`
// guard, so every in-range field emits.

/// `%Canon::CameraInfoPowerShot` (`Canon.pm:5711-5768`) — counts 138/148. The
/// `CameraTemperature` leaf sits at index `CameraInfoCount - 3` (135 for 138, 145
/// for 148), each gated on its exact count (`Canon.pm:5751`/`:5758`).
fn parse_camera_info_powershot(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  count: usize,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_powershot_iso(data, 0x00, order, print_conv, &mut push);
  emit_powershot_fnumber(data, 0x05, order, print_conv, &mut push);
  emit_powershot_exposure_time(data, 0x06, order, print_conv, &mut push);
  emit_powershot_rotation(data, 0x17, order, &mut push);
  // CameraTemperature at index `count - 3` (135 for count 138, 145 for 148).
  if count == 138 {
    emit_powershot_camera_temperature(data, 135, order, print_conv, &mut push);
  } else if count == 148 {
    emit_powershot_camera_temperature(data, 145, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfoPowerShot2` (`Canon.pm:5771-5847`) — counts
/// 156/162/167/171/264. The `CameraTemperature` leaf sits at index
/// `CameraInfoCount - 3` (153/159/164/168/261), each gated on its exact count
/// (`Canon.pm:5809`-`:5846`).
fn parse_camera_info_powershot2(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  count: usize,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_powershot_iso(data, 0x01, order, print_conv, &mut push);
  emit_powershot_fnumber(data, 0x06, order, print_conv, &mut push);
  emit_powershot_exposure_time(data, 0x07, order, print_conv, &mut push);
  emit_powershot_rotation(data, 0x18, order, &mut push);
  // CameraTemperature at index `count - 3`.
  let temp_index = match count {
    156 => 153,
    162 => 159,
    167 => 164,
    171 => 168,
    264 => 261,
    _ => return out,
  };
  emit_powershot_camera_temperature(data, temp_index, order, print_conv, &mut push);
  out
}

// The PowerShot `int32s` leaf emitters. Each takes the `ProcessBinaryData` index
// (the table key) and reads at byte offset `index * 4` (the `int32s` stride).

/// `ISO` (`Canon.pm:5722`/`:5784`) — `100*exp((($val-411)/96)*log(2))`, PrintConv
/// `sprintf("%.0f")`. No `RawConv`.
fn emit_powershot_iso<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  index: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i32s(data, index * 4, order) {
    let vc = 100.0 * (((raw as f64 - 411.0) / 96.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
}

/// `FNumber` (`Canon.pm:5730`/`:5792`) — `exp($val/192*log(2))`, PrintConv
/// `sprintf("%.2g")`. No `RawConv`.
fn emit_powershot_fnumber<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  index: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i32s(data, index * 4, order) {
    let vc = (raw as f64 / 192.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
}

/// `ExposureTime` (`Canon.pm:5738`/`:5800`) — `exp(-$val/96*log(2))`, PrintConv
/// `PrintExposureTime`. No `RawConv`.
fn emit_powershot_exposure_time<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  index: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i32s(data, index * 4, order) {
    let vc = (-(raw as f64) / 96.0 * std::f64::consts::LN_2).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
}

/// `Rotation` (`Canon.pm:5746`/`:5808`) — plain `int32s`, no conv (identical in
/// both views).
fn emit_powershot_rotation<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  index: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(raw) = i32s(data, index * 4, order) {
    push("Rotation", TagValue::I64(raw));
  }
}

/// `CameraTemperature` (`Canon.pm:5751`+/`:5809`+) — raw `int32s`, PrintConv
/// `"$val C"` (no ValueConv).
fn emit_powershot_camera_temperature<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  index: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i32s(data, index * 4, order) {
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{raw} C")))
      } else {
        TagValue::I64(raw)
      },
    );
  }
}

// ─── shared per-field emitters for the int8u xxxD `CameraInfo` tables ─────────
// Each reads at the byte offset the caller already resolved (applying any
// firmware `Hook` shift) and pushes the rendered leaf, reusing the same value
// renderers as the 5D/7D tables. Faithful to the shared `%ci*` common defs
// (`Canon.pm:3086-3153`) and the inline rows of each per-model table.

/// `%ciFNumber` (0x03) / `%ciExposureTime` (0x04) / `%ciISO` (0x06) — the int8u
/// exposure triple shared by every xxxD `CameraInfo` table at fixed offsets
/// (`Canon.pm:3087-3115`). FNumber/ExposureTime drop a zero raw; ISO does not.
fn emit_exposure_triple<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, 0x03)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  emit_ci_exposure_time(data, 0x04, print_conv, push);
  if let Some(raw) = i8u(data, 0x06) {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
}

/// `%ciExposureTime` (`Canon.pm:3097-3106`, int8u, drop-0,
/// `exp(4*ln2*(1-CanonEv(val-24)))`, `PrintExposureTime`). The lone exposure
/// leaf for the 1-series tables (`%CameraInfo1D`/`1DmkII`/`1DmkIIN`), which carry
/// no `%ciFNumber`/`%ciISO`.
fn emit_ci_exposure_time<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
}

/// `%ciCameraTemperature` (`Canon.pm:3116`, int8u, `$val-128`, "$val C").
fn emit_camera_temperature<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off) {
    let c = raw - 128;
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{c} C")))
      } else {
        TagValue::I64(c)
      },
    );
  }
}

/// `%ciMacroMagnification` (`Canon.pm:3124-3133`): gated on the pre-scanned
/// `$$self{LensType} == 124` (the MP-E 65mm Macro), `exp((75-$val)*ln2*3/40)`,
/// PrintConv `%.1fx`.
fn emit_macro_magnification<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  canon_lens_type: Option<u16>,
  print_conv: bool,
  push: &mut F,
) {
  if canon_lens_type != Some(124) {
    return;
  }
  if let Some(raw) = i8u(data, off) {
    let vc = ((75.0 - raw as f64) * std::f64::consts::LN_2 * 3.0 / 40.0).exp();
    let value = if print_conv {
      TagValue::Str(SmolStr::from(std::format!("{vc:.1}x")))
    } else if vc.fract() == 0.0 && vc.is_finite() {
      TagValue::I64(vc as i64)
    } else {
      TagValue::F64(vc)
    };
    push("MacroMagnification", value);
  }
}

/// `%ciFocalLength`/`%ciMinFocal`/`%ciMaxFocal` (`Canon.pm:3134-3153`, int16uRev,
/// "$val mm"). `drop_zero` mirrors `%ciFocalLength`'s `RawConv => '$val ? $val :
/// undef'` (Min/Max focal carry no such drop).
fn emit_focal_mm<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  drop_zero: bool,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16_rev(data, off, order) {
    if drop_zero && v == 0 {
      return;
    }
    push(name, mm_value(v, print_conv));
  }
}

/// `CameraOrientation` (int8u, `%camera_orientation_label`).
fn emit_camera_orientation<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
}

/// `FocusDistanceUpper`/`FocusDistanceLower` (`%focusDistanceByteSwap`, int16uRev,
/// `$val/100`, `>655.345 ? inf : '$val m'`).
fn emit_focus_distance<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = u16_rev(data, off, order) {
    push(name, focus_distance_value(raw, print_conv));
  }
}

/// `WhiteBalance` (int16u, `%canonWhiteBalance`).
fn emit_white_balance<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16(data, off, order) {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
}

/// `ColorTemperature` (int16u, plain integer).
fn emit_color_temperature<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(v) = u16(data, off, order) {
    push("ColorTemperature", TagValue::I64(v));
  }
}

/// `ColorTemperature` as an `int16uRev` word (the 1DmkII / 1DmkIIN 0x37 rows,
/// `Canon.pm:3319-3322`/`:3390-3393`) — byte order reversed vs the plain-int16u
/// `ColorTemperature` of the other tables.
fn emit_color_temperature_rev<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(v) = u16_rev(data, off, order) {
    push("ColorTemperature", TagValue::I64(v));
  }
}

/// `CanonImageSize` (`%canonImageSize`, int16u) — the 1DmkII 0x39 leaf. The hash
/// carries no `PrintHex`, so an unresolved value renders the DECIMAL
/// `Unknown (N)` fallback.
fn emit_canon_image_size<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16(data, off, order) {
    let value = if print_conv {
      match canon_image_size_label(v) {
        Some(l) => TagValue::Str(SmolStr::new_static(l)),
        None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
      }
    } else {
      TagValue::I64(v)
    };
    push("CanonImageSize", value);
  }
}

/// An `Exif::printParameter` int8s leaf (`Saturation`/`ColorTone`/`Contrast`).
fn emit_print_parameter<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8s(data, off) {
    push(name, print_parameter_value(v, print_conv));
  }
}

/// `WhiteBalance` as a 1-byte `int8u` (`%canonWhiteBalance`). The 1D / 1DmkII /
/// 1DmkIIN rows have no `Format` override, so they read a single byte (unlike the
/// `int16u` `WhiteBalance` of the later tables).
fn emit_white_balance_int8u<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
}

/// `LensType` (int16uRev, `%canonLensTypes`, `PrintInt`).
fn emit_lens_type<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16_rev(data, off, order) {
    push("LensType", lens_type_value(v, print_conv));
  }
}

/// `PictureStyle` (int8u, `PrintHex`, `%pictureStyles`).
fn emit_picture_style<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push("PictureStyle", picture_style_value(v, print_conv));
  }
}

/// `HighlightTonePriority` (int8u, `%offOn`).
fn emit_highlight_tone_priority<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push("HighlightTonePriority", enum8(v, print_conv, off_on_label));
  }
}

/// `HighISONoiseReduction` (int8u, `Canon.pm:4663-4669`).
fn emit_high_iso_nr<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "HighISONoiseReduction",
      enum8(v, print_conv, high_iso_nr_label),
    );
  }
}

/// `AutoLightingOptimizer` (int8u, `Canon.pm:4672-4678`).
fn emit_auto_lighting_optimizer<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "AutoLightingOptimizer",
      enum8(v, print_conv, auto_lighting_optimizer_label),
    );
  }
}

/// `FirmwareVersion` (string[6]). `validate` mirrors the `RawConv =>
/// '$val=~/^\d+\.\d+\.\d+\s*$/ ? $val : undef'` carried by the 500D/550D rows
/// (`Canon.pm:5224`/`:5320`); the 40D/50D/450D/1000D rows have no such guard.
fn emit_firmware_version<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  validate: bool,
  push: &mut F,
) {
  if let Some(s) = read_string(data, off, 6) {
    if validate && !is_firmware_version(&s) {
      return;
    }
    push("FirmwareVersion", TagValue::Str(SmolStr::from(s)));
  }
}

/// A plain `string[len]` leaf (`OwnerName`/`LensModel`).
fn emit_string_leaf<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  len: usize,
  name: &'static str,
  push: &mut F,
) {
  if let Some(s) = read_string(data, off, len) {
    push(name, TagValue::Str(SmolStr::from(s)));
  }
}

/// `FileIndex` (int32u, ValueConv `$val + 1`).
fn emit_file_index<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(v) = u32(data, off, order) {
    push("FileIndex", TagValue::I64(v + 1));
  }
}

/// `DirectoryIndex` (int32u). `minus_one` applies the `ValueConv => '$val - 1'`
/// carried by the 40D/50D/500D/550D rows; the 450D/1000D rows emit the raw value.
fn emit_directory_index<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  minus_one: bool,
  push: &mut F,
) {
  if let Some(v) = u32(data, off, order) {
    let value = if minus_one { v - 1 } else { v };
    push("DirectoryIndex", TagValue::I64(value));
  }
}

/// `FlashMeteringMode` (int8u, `Canon.pm:4503-4512`).
fn emit_flash_metering_mode<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "FlashMeteringMode",
      enum8(v, print_conv, flash_metering_mode_label),
    );
  }
}

/// `AutoLightingOptimizer` PrintConv (`Canon.pm:4672-4678`) — the same labels as
/// `HighISONoiseReduction`, kept distinct to mirror the source table structure.
fn auto_lighting_optimizer_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// `FlashModel` (`Canon.pm:5634`, `Mask => 0x7f`, `%flashModel`). The mask has no
/// `BitShift`, so the value is `raw & 0x7f`; a hash miss renders the DECIMAL
/// `Unknown (N)` (the row carries no `PrintHex`).
fn emit_flash_model<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off) {
    let v = raw & 0x7f;
    let value = if print_conv {
      match flash_model_label(v) {
        Some(l) => TagValue::Str(SmolStr::new_static(l)),
        None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
      }
    } else {
      TagValue::I64(v)
    };
    push("FlashModel", value);
  }
}

/// `%flashModel` (`Canon.pm:1029-1049`).
fn flash_model_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    4 => "Speedlite 540EZ",
    5 => "Speedlite 380EX",
    6 => "Speedlite 550EX",
    8 => "Speedlite ST-E2",
    9 => "Speedlite MR-14EX",
    12 => "Speedlite 580EX",
    13 => "Speedlite 430EX",
    17 => "Speedlite 580EX II",
    18 => "Speedlite 430EX II",
    22 => "Speedlite 600EX-RT",
    23 => "Speedlite 600EX II-RT",
    24 => "Speedlite 90EX",
    25 => "Speedlite 430EX III-RT",
    31 => "Speedlite EL-1 ver2",
    33 => "Speedlite EL-5",
    34 => "Speedlite EL-10",
    _ => return None,
  })
}

/// `%Canon::CameraInfo7D` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:4359-4366`): `CanonFirm = 1` if a `D.D.D` version prefix sits at
/// 0x1a8, else `2` if at 0x1ac, else `0` (ExifTool warns then the `Hook` shifts
/// every later leaf out of range).
fn canon_firm_7d(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x1a8) {
    1
  } else if firmware_prefix_at(data, 0x1ac) {
    2
  } else {
    0
  }
}

/// `substr($val, $off, 6) =~ /^\d+\.\d+\.\d+/` — a `D.D.D` version prefix in the
/// 6-byte window at `off`.
fn firmware_prefix_at(data: &[u8], off: usize) -> bool {
  data
    .get(off..off + 6)
    .is_some_and(|b| version_prefix_len(b).is_some())
}

/// Perl `\w` byte — `[0-9A-Za-z_]`.
fn is_word_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

/// `\bTOKEN$` against the trailing-whitespace-trimmed model: `token` is a suffix
/// (the `$`, which also tolerates trailing whitespace) preceded by a non-word
/// byte or the string start (the `\b`). The 1-series `0x0d` `Condition`s are
/// end-anchored (`/\b1DS?$/`, `/\b1Ds? Mark II$/`, …), so a plain substring or
/// the both-sided `word_bounded` test would mis-handle e.g. "1D Mark II".
fn model_ends_with(model: Option<&str>, token: &str) -> bool {
  model.is_some_and(|m| match m.trim_end().strip_suffix(token) {
    Some(prefix) => prefix.as_bytes().last().is_none_or(|&b| !is_word_byte(b)),
    None => false,
  })
}

/// `/^\d+\.\d+\.\d+\s*$/` — the `0x1ac FirmwareVersion` RawConv (`Canon.pm:4469`):
/// a full `D.D.D` version, optionally trailing whitespace, NOTHING else.
fn is_firmware_version(s: &str) -> bool {
  match version_prefix_len(s.as_bytes()) {
    Some(n) => s.as_bytes().get(n..).is_some_and(|t| {
      t.iter()
        .all(|&c| c == b' ' || c == b'\t' || c == b'\r' || c == b'\n')
    }),
    None => false,
  }
}

/// Length of a leading `\d+\.\d+\.\d+` (digits, dot, digits, dot, digits), or
/// `None` if the bytes do not start with one.
fn version_prefix_len(b: &[u8]) -> Option<usize> {
  let mut i = 0usize;
  let digits = |i: &mut usize| -> bool {
    let start = *i;
    while b.get(*i).is_some_and(u8::is_ascii_digit) {
      *i += 1;
    }
    *i > start
  };
  if !digits(&mut i) {
    return None;
  }
  if b.get(i) != Some(&b'.') {
    return None;
  }
  i += 1;
  if !digits(&mut i) {
    return None;
  }
  if b.get(i) != Some(&b'.') {
    return None;
  }
  i += 1;
  if !digits(&mut i) {
    return None;
  }
  Some(i)
}

/// `%Canon::PSInfo` (`Canon.pm:6018-6175`). FORMAT int32s, FIRST_ENTRY 0,
/// PRIORITY 0. The `Unknown => 1` rows (the per-style FilterEffect/ToningEffect
/// for Standard..Faithful, and Saturation/ColorTone Monochrome) are suppressed.
fn ps_info<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  start: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  // The plain int32s scalars (`%psConv`: 0xdeadbeef ⇒ "n/a", else passthrough).
  for &(off, name) in PS_SCALARS {
    if let Some(v) = i32s(data, start + off, order) {
      push(name, ps_scalar_value(v, print_conv));
    }
  }
  // FilterEffect/ToningEffect (Monochrome + the three UserDefs) — explicit
  // PrintConv hashes (with 0xdeadbeef ⇒ "n/a").
  for &(off, name, toning) in PS_EFFECTS {
    if let Some(v) = i32s(data, start + off, order) {
      let label = if toning {
        ps_toning_effect_label(v)
      } else {
        ps_filter_effect_label(v)
      };
      push(name, ps_effect_value(v, print_conv, label));
    }
  }
  // UserDef{1,2,3}PictureStyle (int16u, %userDefStyles). PSInfo's entries carry
  // NO `PrintHex` (`Canon.pm:6152-6169`), so an unresolved value renders the
  // DECIMAL `Unknown (N)` fallback (unlike the `CameraInfo5D` UserDef1 leaf).
  for &(off, name) in &[
    (0xd8usize, "UserDef1PictureStyle"),
    (0xda, "UserDef2PictureStyle"),
    (0xdc, "UserDef3PictureStyle"),
  ] {
    if let Some(v) = u16(data, start + off, order) {
      let value = if print_conv {
        match user_def_style_label(v) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      };
      push(name, value);
    }
  }
}

/// `%Canon::PSInfo2` (`Canon.pm:6178-6356`) — the 60D-group nested subdir
/// (5DmkIII / 60D / 600D / 1100D etc.). Identical to `%PSInfo` but with an extra
/// `*Auto` picture-style block inserted at 0x90 (Contrast/Sharpness/Saturation/
/// ColorTone + Filter/ToningEffectAuto), which shifts the three UserDef blocks
/// +0x18 and moves the int16u `UserDef{1,2,3}PictureStyle` leaves to
/// 0xf0/0xf2/0xf4. Same `%psInfo` suppression of the `Unknown => 1` rows.
fn ps_info2<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  start: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  // The plain int32s scalars (`%psConv`: 0xdeadbeef ⇒ "n/a", else passthrough).
  for &(off, name) in PS_SCALARS2 {
    if let Some(v) = i32s(data, start + off, order) {
      push(name, ps_scalar_value(v, print_conv));
    }
  }
  // FilterEffect/ToningEffect (Monochrome + Auto + the three UserDefs) —
  // explicit PrintConv hashes (with 0xdeadbeef ⇒ "n/a").
  for &(off, name, toning) in PS_EFFECTS2 {
    if let Some(v) = i32s(data, start + off, order) {
      let label = if toning {
        ps_toning_effect_label(v)
      } else {
        ps_filter_effect_label(v)
      };
      push(name, ps_effect_value(v, print_conv, label));
    }
  }
  // UserDef{1,2,3}PictureStyle (int16u, %userDefStyles). As with `%PSInfo`, the
  // entries carry NO `PrintHex` (`Canon.pm:6336-6353`), so an unresolved value
  // renders the DECIMAL `Unknown (N)` fallback.
  for &(off, name) in &[
    (0xf0usize, "UserDef1PictureStyle"),
    (0xf2, "UserDef2PictureStyle"),
    (0xf4, "UserDef3PictureStyle"),
  ] {
    if let Some(v) = u16(data, start + off, order) {
      let value = if print_conv {
        match user_def_style_label(v) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      };
      push(name, value);
    }
  }
}

/// The plain `%psInfo` scalars emitted for the 7D (`Canon.pm:6025-6130`, minus
/// the `Unknown => 1` FilterEffect/ToningEffect Standard..Faithful + Saturation/
/// ColorTone Monochrome rows).
const PS_SCALARS: &[(usize, &str)] = &[
  (0x00, "ContrastStandard"),
  (0x04, "SharpnessStandard"),
  (0x08, "SaturationStandard"),
  (0x0c, "ColorToneStandard"),
  (0x18, "ContrastPortrait"),
  (0x1c, "SharpnessPortrait"),
  (0x20, "SaturationPortrait"),
  (0x24, "ColorTonePortrait"),
  (0x30, "ContrastLandscape"),
  (0x34, "SharpnessLandscape"),
  (0x38, "SaturationLandscape"),
  (0x3c, "ColorToneLandscape"),
  (0x48, "ContrastNeutral"),
  (0x4c, "SharpnessNeutral"),
  (0x50, "SaturationNeutral"),
  (0x54, "ColorToneNeutral"),
  (0x60, "ContrastFaithful"),
  (0x64, "SharpnessFaithful"),
  (0x68, "SaturationFaithful"),
  (0x6c, "ColorToneFaithful"),
  (0x78, "ContrastMonochrome"),
  (0x7c, "SharpnessMonochrome"),
  (0x90, "ContrastUserDef1"),
  (0x94, "SharpnessUserDef1"),
  (0x98, "SaturationUserDef1"),
  (0x9c, "ColorToneUserDef1"),
  (0xa8, "ContrastUserDef2"),
  (0xac, "SharpnessUserDef2"),
  (0xb0, "SaturationUserDef2"),
  (0xb4, "ColorToneUserDef2"),
  (0xc0, "ContrastUserDef3"),
  (0xc4, "SharpnessUserDef3"),
  (0xc8, "SaturationUserDef3"),
  (0xcc, "ColorToneUserDef3"),
];

/// The FilterEffect/ToningEffect PSInfo entries that carry an explicit PrintConv
/// (`Canon.pm:6059-6149`): `(offset, name, is_toning)`.
const PS_EFFECTS: &[(usize, &str, bool)] = &[
  (0x88, "FilterEffectMonochrome", false),
  (0x8c, "ToningEffectMonochrome", true),
  (0xa0, "FilterEffectUserDef1", false),
  (0xa4, "ToningEffectUserDef1", true),
  (0xb8, "FilterEffectUserDef2", false),
  (0xbc, "ToningEffectUserDef2", true),
  (0xd0, "FilterEffectUserDef3", false),
  (0xd4, "ToningEffectUserDef3", true),
];

/// `%Canon::PSInfo2` plain int32s scalars (`Canon.pm:6185-6314`, minus the
/// `Unknown => 1` rows). Differs from `PS_SCALARS` by the `*Auto` block at
/// 0x90-0x9c and the +0x18 shift of every UserDef scalar.
const PS_SCALARS2: &[(usize, &str)] = &[
  (0x00, "ContrastStandard"),
  (0x04, "SharpnessStandard"),
  (0x08, "SaturationStandard"),
  (0x0c, "ColorToneStandard"),
  (0x18, "ContrastPortrait"),
  (0x1c, "SharpnessPortrait"),
  (0x20, "SaturationPortrait"),
  (0x24, "ColorTonePortrait"),
  (0x30, "ContrastLandscape"),
  (0x34, "SharpnessLandscape"),
  (0x38, "SaturationLandscape"),
  (0x3c, "ColorToneLandscape"),
  (0x48, "ContrastNeutral"),
  (0x4c, "SharpnessNeutral"),
  (0x50, "SaturationNeutral"),
  (0x54, "ColorToneNeutral"),
  (0x60, "ContrastFaithful"),
  (0x64, "SharpnessFaithful"),
  (0x68, "SaturationFaithful"),
  (0x6c, "ColorToneFaithful"),
  (0x78, "ContrastMonochrome"),
  (0x7c, "SharpnessMonochrome"),
  (0x90, "ContrastAuto"),
  (0x94, "SharpnessAuto"),
  (0x98, "SaturationAuto"),
  (0x9c, "ColorToneAuto"),
  (0xa8, "ContrastUserDef1"),
  (0xac, "SharpnessUserDef1"),
  (0xb0, "SaturationUserDef1"),
  (0xb4, "ColorToneUserDef1"),
  (0xc0, "ContrastUserDef2"),
  (0xc4, "SharpnessUserDef2"),
  (0xc8, "SaturationUserDef2"),
  (0xcc, "ColorToneUserDef2"),
  (0xd8, "ContrastUserDef3"),
  (0xdc, "SharpnessUserDef3"),
  (0xe0, "SaturationUserDef3"),
  (0xe4, "ColorToneUserDef3"),
];

/// The `%Canon::PSInfo2` FilterEffect/ToningEffect entries with an explicit
/// PrintConv (`Canon.pm:6219-6333`): `(offset, name, is_toning)`. Adds the
/// `*Auto` pair (0xa0/0xa4) and shifts the UserDef pairs +0x18 vs `PS_EFFECTS`.
const PS_EFFECTS2: &[(usize, &str, bool)] = &[
  (0x88, "FilterEffectMonochrome", false),
  (0x8c, "ToningEffectMonochrome", true),
  (0xa0, "FilterEffectAuto", false),
  (0xa4, "ToningEffectAuto", true),
  (0xb8, "FilterEffectUserDef1", false),
  (0xbc, "ToningEffectUserDef1", true),
  (0xd0, "FilterEffectUserDef2", false),
  (0xd4, "ToningEffectUserDef2", true),
  (0xe8, "FilterEffectUserDef3", false),
  (0xec, "ToningEffectUserDef3", true),
];

/// `%offOn` (`Canon.pm:1218`).
fn off_on_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `FlashMeteringMode` PrintConv (`Canon.pm:4392-4398`).
fn flash_metering_mode_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "E-TTL",
    3 => "TTL",
    4 => "External Auto",
    5 => "External Manual",
    6 => "Off",
    _ => return None,
  })
}

/// `SharpnessFrequency` PrintConv (`Canon.pm:3206-3213`) — the `%CameraInfo1D`
/// "PatternSharpness?" leaf.
fn sharpness_frequency_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Lowest",
    2 => "Low",
    3 => "Standard",
    4 => "High",
    5 => "Highest",
    _ => return None,
  })
}

/// `FocalType` PrintConv (`Canon.pm:3307-3313`) — the `%CameraInfo1DmkII` 0x2d leaf.
fn focal_type_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Fixed",
    2 => "Zoom",
    _ => return None,
  })
}

/// `HighISONoiseReduction` PrintConv (`Canon.pm:4447-4452`).
fn high_iso_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// `CameraPictureStyle` (`Canon.pm:4431-4443`, `PrintHex`): the label, or
/// `Unknown (0xNN)`.
fn camera_picture_style_value(v: i64, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  let label = match v {
    0x21 => "User Defined 1",
    0x22 => "User Defined 2",
    0x23 => "User Defined 3",
    0x81 => "Standard",
    0x82 => "Portrait",
    0x83 => "Landscape",
    0x84 => "Neutral",
    0x85 => "Faithful",
    0x86 => "Monochrome",
    _ => return TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  };
  TagValue::Str(SmolStr::new_static(label))
}

/// `%focusDistanceByteSwap` (`Canon.pm:1200-1208`): `$val/100`, then
/// `$val > 655.345 ? "inf" : "$val m"`.
fn focus_distance_value(raw: i64, print_conv: bool) -> TagValue {
  let v = raw as f64 / 100.0;
  if print_conv {
    if v > 655.345 {
      TagValue::Str(SmolStr::new_static("inf"))
    } else {
      TagValue::Str(SmolStr::from(std::format!("{v} m")))
    }
  } else if v.fract() == 0.0 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// `%canonImageSize` (`Canon.pm:1062-1082`).
fn canon_image_size_label(v: i64) -> Option<&'static str> {
  Some(match v {
    -1 => "n/a",
    0 => "Large",
    1 => "Medium",
    2 => "Small",
    5 => "Medium 1",
    6 => "Medium 2",
    7 => "Medium 3",
    8 => "Postcard",
    9 => "Widescreen",
    10 => "Medium Widescreen",
    14 => "Small 1",
    15 => "Small 2",
    16 => "Small 3",
    128 => "640x480 Movie",
    129 => "Medium Movie",
    130 => "Small Movie",
    137 => "1280x720 Movie",
    142 => "1920x1080 Movie",
    143 => "4096x2160 Movie",
    _ => return None,
  })
}

/// `%Image::ExifTool::Exif::printParameter` (`Exif.pm:327-332`): `0 => 'Normal'`,
/// `OTHER => PrintParameter` (`Exif.pm:5628-5640`, `$val > 0 ⇒ "+$val"`, else
/// `$val`). The `$val > 0xfff0` negative-in-disguise branch is unreachable for an
/// int8s source. Raw int under `-n`.
fn print_parameter_value(v: i64, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  if v == 0 {
    TagValue::Str(SmolStr::new_static("Normal"))
  } else if v > 0 {
    TagValue::Str(SmolStr::from(std::format!("+{v}")))
  } else {
    TagValue::Str(SmolStr::from(std::format!("{v}")))
  }
}

/// `%psConv` (`Canon.pm:1168-1171`): `-559038737` (0xdeadbeef) ⇒ "n/a", else
/// the raw int passes through (`OTHER => sub { shift }`). `PrintHex` never fires
/// (the `OTHER` catch-all returns the value unchanged).
fn ps_scalar_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv && v == -559_038_737 {
    TagValue::Str(SmolStr::new_static("n/a"))
  } else {
    TagValue::I64(v)
  }
}

/// `FilterEffect`/`ToningEffect` PSInfo PrintConv: the label (with `0xdeadbeef
/// ⇒ "n/a"`), or the `PrintHex` `Unknown (0xNN)` fallback; raw int under `-n`.
fn ps_effect_value(v: i64, print_conv: bool, label: Option<&'static str>) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  match label {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None if v == -559_038_737 => TagValue::Str(SmolStr::new_static("n/a")),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  }
}

/// PSInfo `FilterEffect*` PrintConv (`Canon.pm:6083-6091`).
fn ps_filter_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Yellow",
    2 => "Orange",
    3 => "Red",
    4 => "Green",
    _ => return None,
  })
}

/// PSInfo `ToningEffect*` PrintConv (`Canon.pm:6093-6101`).
fn ps_toning_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Sepia",
    2 => "Blue",
    3 => "Purple",
    4 => "Green",
    _ => return None,
  })
}

/// `MeasuredEV`/`MeasuredEV2` (`$val/8-6`, no PrintConv): a bare number —
/// integral values collapse to `I64` (so `-j`/`-n` agree, e.g. `4` not `4.0`).
fn ev_value(v: f64) -> TagValue {
  if v.fract() == 0.0 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// Read one signed 32-bit word at byte `off` in the file's byte order.
fn i32s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
}

/// The plain `int8s` per-style scalars (`Contrast`/`Sharpness`/`Saturation`/
/// `ColorTone` × the style set, `Canon.pm:3877-3933`). No PrintConv.
const STYLE_SCALARS_5D: &[(usize, &str)] = &[
  (0xe8, "ContrastStandard"),
  (0xe9, "ContrastPortrait"),
  (0xea, "ContrastLandscape"),
  (0xeb, "ContrastNeutral"),
  (0xec, "ContrastFaithful"),
  (0xed, "ContrastMonochrome"),
  (0xee, "ContrastUserDef1"),
  (0xef, "ContrastUserDef2"),
  (0xf0, "ContrastUserDef3"),
  (0xf1, "SharpnessStandard"),
  (0xf2, "SharpnessPortrait"),
  (0xf3, "SharpnessLandscape"),
  (0xf4, "SharpnessNeutral"),
  (0xf5, "SharpnessFaithful"),
  (0xf6, "SharpnessMonochrome"),
  (0xf7, "SharpnessUserDef1"),
  (0xf8, "SharpnessUserDef2"),
  (0xf9, "SharpnessUserDef3"),
  (0xfa, "SaturationStandard"),
  (0xfb, "SaturationPortrait"),
  (0xfc, "SaturationLandscape"),
  (0xfd, "SaturationNeutral"),
  (0xfe, "SaturationFaithful"),
  (0x100, "SaturationUserDef1"),
  (0x101, "SaturationUserDef2"),
  (0x102, "SaturationUserDef3"),
  (0x103, "ColorToneStandard"),
  (0x104, "ColorTonePortrait"),
  (0x105, "ColorToneLandscape"),
  (0x106, "ColorToneNeutral"),
  (0x107, "ColorToneFaithful"),
  (0x109, "ColorToneUserDef1"),
  (0x10a, "ColorToneUserDef2"),
  (0x10b, "ColorToneUserDef3"),
];

/// `CameraOrientation` PrintConv (`Canon.pm:3800-3804`).
fn camera_orientation_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Horizontal (normal)",
    1 => "Rotate 90 CW",
    2 => "Rotate 270 CW",
    _ => return None,
  })
}

/// `FilterEffectMonochrome` PrintConv (`Canon.pm:3902-3910`).
fn filter_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Yellow",
    2 => "Orange",
    3 => "Red",
    4 => "Green",
    _ => return None,
  })
}

/// `ToningEffectMonochrome` PrintConv (`Canon.pm:3921-3929`).
fn toning_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Sepia",
    2 => "Blue",
    3 => "Purple",
    4 => "Green",
    _ => return None,
  })
}

/// `%userDefStyles` (`Canon.pm:1149-1165`).
fn user_def_style_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0x41 => "PC 1",
    0x42 => "PC 2",
    0x43 => "PC 3",
    0x81 => "Standard",
    0x82 => "Portrait",
    0x83 => "Landscape",
    0x84 => "Neutral",
    0x85 => "Faithful",
    0x86 => "Monochrome",
    0x87 => "Auto",
    _ => return None,
  })
}

/// `AFPointsInFocus5D` (`Canon.pm:3807-3830`) — `0 => '(none)'`, else a
/// `BITMASK` joined with `", "` (DecodeBits: a set bit `n` renders its label or
/// `"[n]"`).
fn af_points_in_focus_5d(v: i64) -> String {
  if v == 0 {
    return String::from("(none)");
  }
  const LABELS: &[&str] = &[
    "Center",
    "Top",
    "Bottom",
    "Upper-left",
    "Upper-right",
    "Lower-left",
    "Lower-right",
    "Left",
    "Right",
    "AI Servo1",
    "AI Servo2",
    "AI Servo3",
    "AI Servo4",
    "AI Servo5",
    "AI Servo6",
  ];
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..32u32 {
    if v & (1i64 << bit) != 0 {
      match LABELS.get(bit as usize) {
        Some(l) => parts.push(String::from(*l)),
        None => parts.push(std::format!("[{bit}]")),
      }
    }
  }
  parts.join(", ")
}

/// Render a `%canonLensTypes` PrintConv (`PrintInt`): the resolved name, or
/// `Unknown (N)`; raw int under `-n`.
fn lens_type_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match u16::try_from(v).ok().and_then(lens_types::lookup_name) {
      Some(name) => TagValue::Str(name),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render `%pictureStyles` (`PrintHex`): the label, or `Unknown (0xNN)`.
fn picture_style_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match picture_style_label(v) {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render `%userDefStyles` (`PrintHex` on `UserDef1` only — irrelevant once a
/// label resolves): the label, or `Unknown (0xNN)`.
fn user_def_style_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match user_def_style_label(v) {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render a `"$val mm"` focal-length leaf; raw int under `-n`.
fn mm_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    TagValue::Str(SmolStr::from(std::format!("{v} mm")))
  } else {
    TagValue::I64(v)
  }
}

/// Render an `int8s` enum PrintConv (label or `Unknown (N)`); raw under `-n`.
fn enum8(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if print_conv {
    hash16(v, label(v))
  } else {
    TagValue::I64(v)
  }
}

/// A hash PrintConv result: the label, or `Unknown (N)`.
fn hash16(v: i64, label: Option<&'static str>) -> TagValue {
  match label {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Choose the `-j` print text or the `-n` ValueConv number (whole-vs-fractional).
fn value_or_print(print_conv: bool, vc: f64, print: String) -> TagValue {
  if print_conv {
    TagValue::Str(SmolStr::from(print))
  } else if vc.fract() == 0.0 && vc.is_finite() {
    TagValue::I64(vc as i64)
  } else {
    TagValue::F64(vc)
  }
}

/// `sprintf("%.2g", $val)` — ExifTool's FNumber PrintConv.
fn format_g2(v: f64) -> String {
  crate::value::format_g(v, 2)
}

/// `Image::ExifTool::Exif::PrintExposureTime` (`Exif.pm`).
fn print_exposure_time(secs: f64) -> String {
  if secs > 0.0 && secs < 0.25001 {
    return std::format!("1/{}", (0.5 + 1.0 / secs) as i64);
  }
  let s = std::format!("{secs:.1}");
  String::from(s.strip_suffix(".0").unwrap_or(&s))
}

// ─── byte readers (FORMAT int8s ⇒ byte offset == word position) ──────────────

/// Read one signed 8-bit byte at `off`.
fn i8s(data: &[u8], off: usize) -> Option<i64> {
  data.get(off).map(|&b| b as i8 as i64)
}

/// Read one unsigned 8-bit byte at `off`.
fn i8u(data: &[u8], off: usize) -> Option<i64> {
  data.get(off).map(|&b| b as i64)
}

/// Read an unsigned 16-bit word at byte `off` in the file's byte order.
fn u16(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// Read an `int16uRev` word at byte `off` — the 16-bit value is stored with the
/// REVERSED byte order (big-endian for a little-endian file, `Canon.pm:3789`).
fn u16_rev(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_be_bytes(arr),
    ByteOrder::Big => u16::from_le_bytes(arr),
  } as i64)
}

/// Read an unsigned 32-bit word at byte `off` in the file's byte order.
fn u32(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  } as i64)
}

/// Read a `string[len]` at byte `off`: the bytes up to the first NUL, decoded
/// as Latin-1/ASCII (the owner name is ASCII). `None` if the field is past the
/// end of `data`.
fn read_string(data: &[u8], off: usize, len: usize) -> Option<String> {
  let bytes = data.get(off..off + len)?;
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  let slice = bytes.get(..end)?;
  Some(slice.iter().map(|&b| b as char).collect())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// The model-table `parse` arity the per-model unit tests drive. `file_type`
  /// defaults to `None` (every model-table row these tests exercise is
  /// `FileType`-independent); `count`/`is_int32u` are `0`/`false`, so the
  /// count-keyed PowerShot arms never fire — these tests reach a table by MODEL.
  fn parse_model(
    data: &[u8],
    order: ByteOrder,
    print_conv: bool,
    model: Option<&str>,
    canon_lens_type: Option<u16>,
  ) -> Vec<(SmolStr, TagValue)> {
    super::parse(
      data,
      order,
      print_conv,
      model,
      None,
      canon_lens_type,
      0,
      false,
    )
  }

  /// Build a CameraInfo5D blob with the named bytes set (the rest zero).
  fn blob() -> Vec<u8> {
    let mut b = vec![0u8; 0x120];
    b[0x06] = 88; // ISO raw
    b[0x27] = 0; // CameraOrientation
    // AFPointsInFocus5D int16uRev: bytes "00 01" ⇒ BE ⇒ 1.
    b[0x38] = 0x00;
    b[0x39] = 0x01;
    b[0x58] = 0x50; // ColorTemperature LE 0x1450 = 5200
    b[0x59] = 0x14;
    b[0x6c] = 0x81; // PictureStyle 0x81
    b[0xa4..0xac].copy_from_slice(b"1.1.1.2\0");
    b[0xac..0xbc].copy_from_slice(b"Julian Tolchard\0");
    b[0xd0] = 0x93; // FileIndex LE 0x0593 = 1427 ⇒ +1 = 1428
    b[0xd1] = 0x05;
    b[0xf1] = 3; // SharpnessStandard
    b[0x10c] = 0x81; // UserDef1PictureStyle 0x0081
    // TimeStamp int32u LE 1370690080 = 0x51B31220.
    b[0x11c..0x120].copy_from_slice(&1_370_690_080u32.to_le_bytes());
    b
  }

  #[test]
  fn camera_info_5d_print_values() {
    let data = blob();
    let em = parse_model(&data, ByteOrder::Little, true, Some("Canon EOS 5D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Horizontal (normal)".into()))
    );
    assert_eq!(
      find("AFPointsInFocus5D"),
      Some(TagValue::Str("Center".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("FirmwareRevision"),
      Some(TagValue::Str("1.1.1.2".into()))
    );
    assert_eq!(
      find("ShortOwnerName"),
      Some(TagValue::Str("Julian Tolchard".into()))
    );
    assert_eq!(find("FileIndex"), Some(TagValue::I64(1428)));
    assert_eq!(find("SharpnessStandard"), Some(TagValue::I64(3)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Standard".into()))
    );
    assert_eq!(
      find("TimeStamp"),
      Some(TagValue::Str("2013:06:08 11:14:40".into()))
    );
  }

  #[test]
  fn camera_info_5d_numeric_iso() {
    let data = blob();
    let em = parse_model(&data, ByteOrder::Little, false, Some("Canon EOS 5D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::I64(400)));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(1428)));
  }

  #[test]
  fn dispatch_anchored() {
    assert!(model_is_camera_info_5d(Some("Canon EOS 5D")));
    assert!(!model_is_camera_info_5d(Some("Canon EOS 5D Mark II")));
    assert!(!model_is_camera_info_5d(Some("Canon EOS 7D")));
    assert!(model_is_camera_info_7d(Some("Canon EOS 7D")));
    assert!(!model_is_camera_info_7d(Some("Canon EOS 7D Mark II")));
    assert!(!model_is_camera_info_7d(Some("Canon EOS 5D")));
    // The `/EOS 5D Mark II$/` anchor matches the Mark II but not the plain 5D nor
    // the Mark III (which ends with `III`, never `II$`).
    assert!(model_is_camera_info_5dmkii(Some("Canon EOS 5D Mark II")));
    assert!(!model_is_camera_info_5dmkii(Some("Canon EOS 5D")));
    assert!(!model_is_camera_info_5dmkii(Some("Canon EOS 5D Mark III")));
    // A short blob yields nothing even for a ported table: the R6 leaves sit at
    // 0x09da+ (CameraTemperature) / 0x0af1 (ShutterCount), past this 0x120 blob.
    assert!(
      parse_model(
        &[0u8; 0x120],
        ByteOrder::Little,
        true,
        Some("Canon EOS R6"),
        None
      )
      .is_empty()
    );
  }

  #[test]
  fn dispatch_anchored_40d_50d() {
    assert!(model_is_camera_info_40d(Some("Canon EOS 40D")));
    assert!(!model_is_camera_info_40d(Some("Canon EOS 400D")));
    assert!(model_is_camera_info_50d(Some("Canon EOS 50D")));
    assert!(!model_is_camera_info_50d(Some("Canon EOS 500D")));
    assert!(!model_is_camera_info_50d(Some("Canon EOS 5D")));
  }

  /// `%Canon::CameraInfo40D` (no firmware `Hook`) print values + the
  /// `MacroMagnification` LensType gate + the `PSInfo` subdir.
  #[test]
  fn camera_info_40d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1b] = 75; // MacroMagnification raw (1.0x when LensType == 124)
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength int16uRev = 50
    b[0x30] = 1; // CameraOrientation Rotate 90 CW
    b[0x73] = 0x50;
    b[0x74] = 0x14; // ColorTemperature 5200
    b[0xd8] = 0x00;
    b[0xd9] = 0x0a; // MinFocalLength 10
    b[0xda] = 0x00;
    b[0xdb] = 0xc8; // MaxFocalLength 200
    b[0xff..0x105].copy_from_slice(b"1.0.3\0"); // FirmwareVersion string[6]
    b[0x133..0x137].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x13f..0x143].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x92b..0x934].copy_from_slice(b"EF24-70mm"); // LensModel string[64]
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 40D"),
      Some(124),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(
      find("MacroMagnification"),
      Some(TagValue::Str("1.0x".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.3".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("LensModel"), Some(TagValue::Str("EF24-70mm".into())));
    // MacroMagnification is gated on the pre-scanned LensType == 124.
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 40D"), Some(50));
    assert!(em2.iter().all(|(k, _)| k != "MacroMagnification"));
    // -n view: ISO / FileIndex render as bare integers.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 40D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("ISO"), Some(TagValue::I64(400)));
    assert_eq!(findn("FileIndex"), Some(TagValue::I64(101)));
  }

  /// Per-field availability: a blob that ends before the later leaves emits the
  /// in-range tags only (each leaf gated on `buf.get(off..off+size)`).
  #[test]
  fn camera_info_40d_truncated_per_field() {
    let mut b = vec![0u8; 0x80];
    b[0x06] = 88; // ISO 400 (in range)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 40D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert!(find("FirmwareVersion").is_none());
    assert!(find("FileIndex").is_none());
    assert!(find("LensModel").is_none());
    assert!(find("MinFocalLength").is_none());
  }

  /// `%Canon::CameraInfo50D` firmware-1 (`CanonFirm == 1`): the `0xee` `Hook`
  /// shifts every leaf AFTER 0xee by `-4`; the Hook entry (MaxFocalLength) and
  /// the earlier leaves stay at their nominal offsets.
  #[test]
  fn camera_info_50d_firmware1_shift() {
    let mut b = vec![0u8; 0x3c0];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0xa7] = 0x81; // PictureStyle 0x81 Standard
    b[0xbd] = 2; // HighISONoiseReduction Strong
    b[0xbf] = 1; // AutoLightingOptimizer Low
    b[0xee] = 0x00;
    b[0xef] = 0x64; // MaxFocalLength 100 (Hook entry — read UNSHIFTED)
    b[0x15a..0x160].copy_from_slice(b"2.6.1\0"); // version prefix at 0x15a ⇒ CanonFirm 1
    b[0x197..0x19b].copy_from_slice(&200u32.to_le_bytes()); // FileIndex @ 0x19b-4
    b[0x1a3..0x1a7].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex @ 0x1a7-4
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 50D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Strong".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Low".into()))
    );
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("100 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.6.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
  }

  /// `%Canon::CameraInfo50D` firmware-2 (`CanonFirm == 2`): no `varSize` shift —
  /// the post-Hook leaves stay at their nominal offsets.
  #[test]
  fn camera_info_50d_firmware2_no_shift() {
    let mut b = vec![0u8; 0x3c0];
    b[0xee] = 0x00;
    b[0xef] = 0x64; // MaxFocalLength 100
    b[0x15e..0x164].copy_from_slice(b"1.0.3\0"); // version prefix at 0x15e ⇒ CanonFirm 2
    b[0x19b..0x19f].copy_from_slice(&200u32.to_le_bytes()); // FileIndex @ 0x19b
    b[0x1a7..0x1ab].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex @ 0x1a7
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 50D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("100 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.3".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
  }

  /// `/EOS 5D Mark II$/` routes to the 5DmkII table; the plain `EOS 5D` selects a
  /// different table (it has `FirmwareRevision`, never `FirmwareVersion`).
  #[test]
  fn dispatch_anchored_5dmkii() {
    let mut b = vec![0u8; 0x400];
    b[0x17e..0x184].copy_from_slice(b"1.0.6\0"); // CanonFirm 2
    let mk2 = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    assert!(mk2.iter().any(|(k, _)| k == "FirmwareVersion"));
    let plain = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 5D"), None);
    assert!(plain.iter().all(|(k, _)| k != "FirmwareVersion"));
  }

  /// `%Canon::CameraInfo5DmkII` firmware-2 (`CanonFirm == 2`): no `varSize` shift,
  /// every leaf at its nominal offset.
  #[test]
  fn camera_info_5dmkii_firmware2_fields() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x13] = 17; // FlashModel (Mask 0x7f) ⇒ Speedlite 580EX II
    b[0x15] = 0; // FlashMeteringMode E-TTL
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength int16uRev (BE) 0x0032 = 50 mm
    b[0x31] = 1; // CameraOrientation Rotate 90 CW
    b[0x73] = 0x50;
    b[0x74] = 0x14; // ColorTemperature int16u LE 0x1450 = 5200
    b[0xa7] = 0x81; // PictureStyle 0x81 Standard
    b[0xbd] = 2; // HighISONoiseReduction Strong
    b[0xbf] = 1; // AutoLightingOptimizer Low
    b[0xe8] = 0x00;
    b[0xe9] = 0x18; // MinFocalLength 24 mm
    b[0xea] = 0x00;
    b[0xeb] = 0x69; // MaxFocalLength 105 mm (Hook entry, read UNSHIFTED)
    b[0x17e..0x184].copy_from_slice(b"1.0.6\0"); // version at 0x17e ⇒ CanonFirm 2
    b[0x18e..0x193].copy_from_slice(b"Owner"); // OwnerName string[32]
    b[0x1bb..0x1bf].copy_from_slice(&200u32.to_le_bytes()); // FileIndex ⇒ +1 = 201
    b[0x1c7..0x1cb].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex ⇒ -1 = 199
    b[0x2f7..0x2fb].copy_from_slice(&5i32.to_le_bytes()); // PSInfo ContrastStandard = 5
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("FlashModel"),
      Some(TagValue::Str("Speedlite 580EX II".into()))
    );
    assert_eq!(
      find("FlashMeteringMode"),
      Some(TagValue::Str("E-TTL".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Strong".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Low".into()))
    );
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.6".into())));
    assert_eq!(find("OwnerName"), Some(TagValue::Str("Owner".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
  }

  /// `%Canon::CameraInfo5DmkII` firmware-1 (`CanonFirm == 1`, version prefix at
  /// 0x15a): `varSize -= 36` for every leaf AFTER the 0xea Hook; MaxFocalLength
  /// (0xea, the Hook entry) is read UNSHIFTED.
  #[test]
  fn camera_info_5dmkii_firmware1_shift() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0xea] = 0x00;
    b[0xeb] = 0x69; // MaxFocalLength 105 mm (Hook entry, UNSHIFTED)
    b[0x15a..0x160].copy_from_slice(b"3.4.6\0"); // prefix at 0x15a ⇒ CanonFirm 1
    // Post-Hook leaves shift by -0x24: FirmwareVersion 0x17e ⇒ 0x15a (reuses the
    // version string), OwnerName 0x18e ⇒ 0x16a, FileIndex 0x1bb ⇒ 0x197,
    // DirectoryIndex 0x1c7 ⇒ 0x1a3, PSInfo 0x2f7 ⇒ 0x2d3.
    b[0x16a..0x16f].copy_from_slice(b"Mike\0");
    b[0x197..0x19b].copy_from_slice(&500u32.to_le_bytes());
    b[0x1a3..0x1a7].copy_from_slice(&500u32.to_le_bytes());
    b[0x2d3..0x2d7].copy_from_slice(&7i32.to_le_bytes());
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("3.4.6".into())));
    assert_eq!(find("OwnerName"), Some(TagValue::Str("Mike".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(501)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(499)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(7)));
  }

  /// `%Canon::CameraInfo5DmkII` unrecognized firmware (`CanonFirm == 0`): the
  /// 0xea Hook adds `+0x10000`, pushing every post-Hook leaf out of range
  /// (ExifTool `Warn`s and emits nothing for them); pre-Hook leaves still emit.
  #[test]
  fn camera_info_5dmkii_unrecognized_firmware() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0xea] = 0x00;
    b[0xeb] = 0x69; // MaxFocalLength 105 (Hook entry, still emitted)
    b[0x17e..0x184].copy_from_slice(b"badfw\0"); // not a version ⇒ CanonFirm 0
    b[0x1bb..0x1bf].copy_from_slice(&200u32.to_le_bytes()); // nominal FileIndex (dropped)
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), None);
    assert_eq!(find("FileIndex"), None);
    assert_eq!(find("DirectoryIndex"), None);
    assert!(em.iter().all(|(k, _)| k != "ContrastStandard"));
  }

  /// `%Canon::CameraInfo5DmkII` `0x1b MacroMagnification` (`%ciMacroMagnification`)
  /// is gated on the pre-scanned `LensType == 124`.
  #[test]
  fn camera_info_5dmkii_macro_magnification() {
    let mut b = vec![0u8; 0x400];
    b[0x1b] = 75; // 75 ⇒ 1.0x
    b[0x17e..0x184].copy_from_slice(b"1.0.6\0"); // CanonFirm 2
    let with = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      Some(124),
    );
    assert_eq!(
      with
        .iter()
        .find(|(k, _)| k == "MacroMagnification")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("1.0x".into()))
    );
    let without = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    assert!(without.iter().all(|(k, _)| k != "MacroMagnification"));
  }

  /// `/\b1D Mark IV$/` routes to the 1DmkIV table and is not swallowed by the
  /// 1D / 1DmkII / 1DmkIII arms nor matched by the Mark II/III.
  #[test]
  fn dispatch_anchored_1dmkiv() {
    assert!(model_is_camera_info_1dmkiv(Some("Canon EOS-1D Mark IV")));
    assert!(!model_is_camera_info_1dmkiv(Some("Canon EOS-1D Mark III")));
    assert!(!model_is_camera_info_1dmkiv(Some("Canon EOS-1D Mark II")));
    assert!(!model_is_camera_info_1d(Some("Canon EOS-1D Mark IV")));
    assert!(!model_is_camera_info_1dmkiii(Some("Canon EOS-1D Mark IV")));
  }

  /// `%Canon::CameraInfo1DmkIV` firmware-2 (`CanonFirm == 2`): no `varSize` shift.
  #[test]
  fn camera_info_1dmkiv_firmware2_fields() {
    let mut b = vec![0u8; 0x460];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x08] = 80; // MeasuredEV2 = 80/8-6 = 4
    b[0x09] = 72; // MeasuredEV3 = 72/8-6 = 3
    b[0x15] = 3; // FlashMeteringMode TTL
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50 mm
    b[0x35] = 2; // CameraOrientation Rotate 270 CW
    b[0x7c] = 0x50;
    b[0x7d] = 0x14; // ColorTemperature int16u LE 5200
    b[0x151] = 0x00;
    b[0x152] = 0x18; // MinFocalLength 24 mm
    b[0x153] = 0x00;
    b[0x154] = 0x69; // MaxFocalLength 105 mm (second Hook entry)
    b[0x1ed..0x1f3].copy_from_slice(b"1.0.4\0"); // version at 0x1ed ⇒ CanonFirm 2
    b[0x22c..0x230].copy_from_slice(&200u32.to_le_bytes()); // FileIndex ⇒ 201
    b[0x238..0x23c].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex ⇒ 199
    b[0x368..0x36c].copy_from_slice(&5i32.to_le_bytes()); // PSInfo ContrastStandard
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark IV"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(find("MeasuredEV2"), Some(TagValue::I64(4)));
    assert_eq!(find("MeasuredEV3"), Some(TagValue::I64(3)));
    assert_eq!(find("FlashMeteringMode"), Some(TagValue::Str("TTL".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.4".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
  }

  /// `%Canon::CameraInfo1DmkIV` firmware-1 (`CanonFirm == 1`): the CUMULATIVE
  /// shift — leaves between the two Hooks take only the 0x56 Hook (`-1`), while
  /// leaves after 0x153 take both (`-1` + `-4` = `-5`).
  #[test]
  fn camera_info_1dmkiv_firmware1_cumulative_shift() {
    let mut b = vec![0u8; 0x460];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x1e8..0x1ee].copy_from_slice(b"4.2.1\0"); // prefix at 0x1e8 ⇒ CanonFirm 1
    // -1 (0x56 Hook only): MinFocalLength 0x151 ⇒ 0x150, MaxFocalLength 0x153 ⇒ 0x152.
    b[0x150] = 0x00;
    b[0x151] = 0x18; // MinFocalLength 24 mm
    b[0x152] = 0x00;
    b[0x153] = 0x69; // MaxFocalLength 105 mm
    // -5 (both Hooks): FirmwareVersion 0x1ed ⇒ 0x1e8 (reuses the version string),
    // FileIndex 0x22c ⇒ 0x227, DirectoryIndex 0x238 ⇒ 0x233, PSInfo 0x368 ⇒ 0x363.
    b[0x227..0x22b].copy_from_slice(&500u32.to_le_bytes());
    b[0x233..0x237].copy_from_slice(&500u32.to_le_bytes());
    b[0x363..0x367].copy_from_slice(&7i32.to_le_bytes());
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark IV"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("4.2.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(501)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(499)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(7)));
  }

  /// `%Canon::CameraInfo1DmkIV` unrecognized firmware (`CanonFirm == 0`): the
  /// 0x56 Hook adds `+0x10000`, dropping every leaf after 0x56; the leaves up to
  /// and including the 0x56 Hook entry still emit.
  #[test]
  fn camera_info_1dmkiv_unrecognized_firmware() {
    let mut b = vec![0u8; 0x460];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x56] = 0x00;
    b[0x57] = 0x64; // FocusDistanceLower at 0x56 (Hook entry, still emitted)
    b[0x22c..0x230].copy_from_slice(&200u32.to_le_bytes()); // nominal FileIndex (dropped)
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark IV"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert!(em.iter().any(|(k, _)| k == "FocusDistanceLower"));
    assert_eq!(find("MinFocalLength"), None);
    assert_eq!(find("MaxFocalLength"), None);
    assert_eq!(find("FirmwareVersion"), None);
    assert_eq!(find("FileIndex"), None);
    assert!(em.iter().all(|(k, _)| k != "ContrastStandard"));
  }

  /// `/EOS-1D X$/` routes to the 1DX table; the "1D X Mark II/III" do not match
  /// the `X$` anchor, and the generic 1D arm does not swallow it.
  #[test]
  fn dispatch_anchored_1dx() {
    assert!(model_is_camera_info_1dx(Some("Canon EOS-1D X")));
    assert!(!model_is_camera_info_1dx(Some("Canon EOS-1D X Mark II")));
    assert!(!model_is_camera_info_1dx(Some("Canon EOS-1D X Mark III")));
    assert!(!model_is_camera_info_1d(Some("Canon EOS-1D X")));
  }

  /// `%Canon::CameraInfo1DX` firmware-3 (`CanonFirm == 3`, the table's nominal
  /// 1.0.2 layout): all three Hooks contribute `0`, so no `varSize` shift.
  #[test]
  fn camera_info_1dx_firmware3_fields() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C (first Hook entry)
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 50 mm
    b[0x7d] = 1; // CameraOrientation Rotate 90 CW
    b[0xc0] = 0x50;
    b[0xc1] = 0x14; // ColorTemperature int16u LE 5200
    b[0xf4] = 0x81; // PictureStyle 0x81 Standard
    b[0x1a9] = 0x00;
    b[0x1aa] = 0x18; // MinFocalLength 24 mm
    b[0x1ab] = 0x00;
    b[0x1ac] = 0x69; // MaxFocalLength 105 mm (third Hook entry)
    b[0x280..0x286].copy_from_slice(b"1.0.2\0"); // version at 0x280 ⇒ CanonFirm 3
    b[0x2d0..0x2d4].copy_from_slice(&200u32.to_le_bytes()); // FileIndex ⇒ 201
    b[0x2dc..0x2e0].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex ⇒ 199
    b[0x3f4..0x3f8].copy_from_slice(&5i32.to_le_bytes()); // PSInfo2 ContrastStandard
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D X"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.2".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
  }

  /// `%Canon::CameraInfo1DX` firmware-1 (`CanonFirm == 1`): the three-Hook
  /// CUMULATIVE shift — `-3` after 0x1b, `-7` after 0x8e, `-15` after 0x1ab.
  #[test]
  fn camera_info_1dx_firmware1_cumulative_shift() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x271..0x277].copy_from_slice(b"5.7.1\0"); // prefix at 0x271 ⇒ CanonFirm 1
    b[0x20] = 0x00;
    b[0x21] = 0x32; // FocalLength 0x23 ⇒ 0x20 (-3)
    b[0x1a2] = 0x00;
    b[0x1a3] = 0x18; // MinFocalLength 0x1a9 ⇒ 0x1a2 (-7)
    b[0x1a4] = 0x00;
    b[0x1a5] = 0x69; // MaxFocalLength 0x1ab ⇒ 0x1a4 (-7)
    b[0x2c1..0x2c5].copy_from_slice(&500u32.to_le_bytes()); // FileIndex 0x2d0 ⇒ 0x2c1 (-15)
    b[0x2cd..0x2d1].copy_from_slice(&500u32.to_le_bytes()); // DirectoryIndex 0x2dc ⇒ 0x2cd (-15)
    b[0x3e5..0x3e9].copy_from_slice(&7i32.to_le_bytes()); // PSInfo2 0x3f4 ⇒ 0x3e5 (-15)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D X"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("5.7.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(501)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(499)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(7)));
  }

  /// `%Canon::CameraInfo1DX` firmware-4 (`CanonFirm == 4`): the 0x8e Hook is the
  /// only POSITIVE-shift case (`+5`), leaving 0x1b/0x1ab at `0`.
  #[test]
  fn camera_info_1dx_firmware4_positive_shift() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400
    b[0x285..0x28b].copy_from_slice(b"2.1.0\0"); // prefix only at 0x285 ⇒ CanonFirm 4
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 0x23 (0 shift)
    b[0x1ae] = 0x00;
    b[0x1af] = 0x18; // MinFocalLength 0x1a9 ⇒ 0x1ae (+5)
    b[0x1b0] = 0x00;
    b[0x1b1] = 0x69; // MaxFocalLength 0x1ab ⇒ 0x1b0 (+5)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D X"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.1.0".into())));
  }

  /// `%Canon::CameraInfo1DX` unrecognized firmware (`CanonFirm == 0`): the
  /// `+0x10000` abort lives on the THIRD Hook (0x1ab), so the leaves up to 0x1a9
  /// still emit (each `-3`/`-7` shifted) while the post-0x1ab leaves drop out.
  #[test]
  fn camera_info_1dx_unrecognized_firmware_partial() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x1b] = 148; // CameraTemperature 20 C (first Hook entry, emits)
    b[0x20] = 0x00;
    b[0x21] = 0x32; // FocalLength 0x23 ⇒ 0x20 (-3, still emits)
    b[0x1a4] = 0x00;
    b[0x1a5] = 0x69; // MaxFocalLength 0x1ab ⇒ 0x1a4 (-7, still emits)
    b[0x2d0..0x2d4].copy_from_slice(&200u32.to_le_bytes()); // nominal FileIndex (dropped)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D X"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    // Everything after the 0x1ab Hook is pushed out of range.
    assert_eq!(find("FirmwareVersion"), None);
    assert_eq!(find("FileIndex"), None);
    assert!(em.iter().all(|(k, _)| k != "ContrastStandard"));
  }

  /// `/EOS 5D Mark III$/` routes to the 5DmkIII table; the Mark II and the plain
  /// 5D do not, and the Mark II/III matchers are mutually exclusive.
  #[test]
  fn dispatch_anchored_5dmkiii() {
    assert!(model_is_camera_info_5dmkiii(Some("Canon EOS 5D Mark III")));
    assert!(!model_is_camera_info_5dmkiii(Some("Canon EOS 5D Mark II")));
    assert!(!model_is_camera_info_5dmkiii(Some("Canon EOS 5D")));
    assert!(!model_is_camera_info_5dmkii(Some("Canon EOS 5D Mark III")));
  }

  /// `%Canon::CameraInfo5DmkIII` firmware-3 (`CanonFirm == 3`, the nominal 1.0.x
  /// layout): all four Hooks contribute `0`, so no `varSize` shift. Exercises the
  /// new LensSerialNumber, FileIndex2/DirectoryIndex2 and the PSInfo2 subdir.
  #[test]
  fn camera_info_5dmkiii_firmware3_fields() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C (first Hook entry)
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 50 mm (second Hook entry)
    b[0x7d] = 2; // CameraOrientation Rotate 270 CW
    b[0xc0] = 0x50;
    b[0xc1] = 0x14; // ColorTemperature int16u LE 5200
    b[0xf4] = 0x81; // PictureStyle 0x81 Standard
    b[0x153] = 0x00;
    b[0x154] = 0x01; // LensType int16uRev = 1
    b[0x155] = 0x00;
    b[0x156] = 0x18; // MinFocalLength 24 mm
    b[0x157] = 0x00;
    b[0x158] = 0x69; // MaxFocalLength 105 mm (fourth Hook entry)
    b[0x164..0x169].copy_from_slice(&[0xab, 0xcd, 0xef, 0x12, 0x34]); // LensSerialNumber
    b[0x23c..0x242].copy_from_slice(b"1.0.3\0"); // version at 0x23c ⇒ CanonFirm 3
    b[0x28c..0x290].copy_from_slice(&100u32.to_le_bytes()); // FileIndex ⇒ 101
    b[0x290..0x294].copy_from_slice(&200u32.to_le_bytes()); // FileIndex2 ⇒ 201
    b[0x298..0x29c].copy_from_slice(&300u32.to_le_bytes()); // DirectoryIndex ⇒ 299
    b[0x29c..0x2a0].copy_from_slice(&400u32.to_le_bytes()); // DirectoryIndex2 ⇒ 399
    b[0x3b0..0x3b4].copy_from_slice(&5i32.to_le_bytes()); // PSInfo2 ContrastStandard
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark III"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert!(em.iter().any(|(k, _)| k == "LensType"));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(
      find("LensSerialNumber"),
      Some(TagValue::Str("abcdef1234".into()))
    );
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.3".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("FileIndex2"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(299)));
    assert_eq!(find("DirectoryIndex2"), Some(TagValue::I64(399)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
  }

  /// `%Canon::CameraInfo5DmkIII` firmware-1 (`CanonFirm == 1`): the four-Hook
  /// CUMULATIVE shift through all tiers — `-1` after 0x1b, `-4` after 0x23, `-8`
  /// after 0x8e, `-16` after 0x157.
  #[test]
  fn camera_info_5dmkiii_firmware1_cumulative_shift() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x22c..0x232].copy_from_slice(b"4.5.4\0"); // prefix at 0x22c ⇒ CanonFirm 1
    b[0x22] = 0x00;
    b[0x23] = 0x32; // FocalLength 0x23 ⇒ 0x22 (-1)
    b[0x79] = 1; // CameraOrientation 0x7d ⇒ 0x79 (-4)
    b[0x14d] = 0x00;
    b[0x14e] = 0x18; // MinFocalLength 0x155 ⇒ 0x14d (-8)
    b[0x14f] = 0x00;
    b[0x150] = 0x69; // MaxFocalLength 0x157 ⇒ 0x14f (-8)
    b[0x154..0x159].copy_from_slice(&[0xab, 0xcd, 0xef, 0x12, 0x34]); // LensSerial 0x164 ⇒ 0x154 (-16)
    b[0x27c..0x280].copy_from_slice(&500u32.to_le_bytes()); // FileIndex 0x28c ⇒ 0x27c (-16)
    b[0x3a0..0x3a4].copy_from_slice(&7i32.to_le_bytes()); // PSInfo2 0x3b0 ⇒ 0x3a0 (-16)
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark III"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(
      find("LensSerialNumber"),
      Some(TagValue::Str("abcdef1234".into()))
    );
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("4.5.4".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(501)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(7)));
  }

  /// `%Canon::CameraInfo5DmkIII` firmware-5 (`CanonFirm == 5`): the POSITIVE
  /// cumulative shift — `0` after 0x1b, `+6` after 0x23, `+11` after 0x8e (and
  /// after 0x157, since the 0x157 Hook is `0` for firmware >= 3).
  #[test]
  fn camera_info_5dmkiii_firmware5_positive_shift() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400
    b[0x247..0x24d].copy_from_slice(b"1.3.5\0"); // prefix only at 0x247 ⇒ CanonFirm 5
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 0x23 (0 shift)
    b[0x83] = 1; // CameraOrientation 0x7d ⇒ 0x83 (+6)
    b[0xff] = 0x81; // PictureStyle 0xf4 ⇒ 0xff (+11)
    b[0x160] = 0x00;
    b[0x161] = 0x18; // MinFocalLength 0x155 ⇒ 0x160 (+11)
    b[0x162] = 0x00;
    b[0x163] = 0x69; // MaxFocalLength 0x157 ⇒ 0x162 (+11)
    b[0x16f..0x174].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // LensSerial 0x164 ⇒ 0x16f (+11)
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark III"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("24 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("105 mm".into())));
    assert_eq!(
      find("LensSerialNumber"),
      Some(TagValue::Str("0102030405".into()))
    );
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.3.5".into())));
  }

  /// `%Canon::CameraInfo5DmkIII` unrecognized firmware (`CanonFirm == 0`): the
  /// 0x1b Hook adds `+0x10000`, dropping every leaf after 0x1b; only the leaves
  /// up to and including the 0x1b Hook entry emit.
  #[test]
  fn camera_info_5dmkiii_unrecognized_firmware() {
    let mut b = vec![0u8; 0x500];
    b[0x06] = 88; // ISO 400 (pre-Hook)
    b[0x1b] = 148; // CameraTemperature 20 C (Hook entry, emits)
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength nominal (shifted out)
    b[0x23c..0x240].copy_from_slice(&200u32.to_le_bytes()); // nominal FW region (no version)
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark III"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), None);
    assert_eq!(find("MaxFocalLength"), None);
    assert_eq!(find("FirmwareVersion"), None);
    assert!(em.iter().all(|(k, _)| k != "ContrastStandard"));
  }

  #[test]
  fn dispatch_word_bounded_450d_500d_550d() {
    assert!(model_is_camera_info_450d(Some("Canon EOS 450D")));
    assert!(model_is_camera_info_450d(Some("Canon EOS REBEL XSi")));
    assert!(model_is_camera_info_450d(Some("Canon EOS Kiss X2")));
    assert!(model_is_camera_info_500d(Some("Canon EOS 500D")));
    assert!(model_is_camera_info_500d(Some("Canon EOS REBEL T1i")));
    assert!(model_is_camera_info_550d(Some("Canon EOS 550D")));
    assert!(model_is_camera_info_550d(Some("Canon EOS Kiss X4")));
    // `\bREBEL XS\b` (a 1000D) must NOT match the 450D `REBEL XSi` token.
    assert!(!model_is_camera_info_450d(Some("Canon EOS REBEL XS")));
    // No cross-matching between the three.
    assert!(!model_is_camera_info_450d(Some("Canon EOS 500D")));
    assert!(!model_is_camera_info_550d(Some("Canon EOS 450D")));
  }

  /// `%Canon::CameraInfo450D`: OwnerName + the PLAIN DirectoryIndex (no `$val-1`,
  /// unlike 40D/50D/500D/550D) + the LensType MacroMagnification gate.
  #[test]
  fn camera_info_450d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength 50
    b[0x107..0x10d].copy_from_slice(b"1.2.4\0"); // FirmwareVersion (no RawConv guard)
    b[0x10f..0x117].copy_from_slice(b"Jane Doe"); // OwnerName string[32]
    b[0x133..0x137].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex PLAIN = 200
    b[0x13f..0x143].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x933..0x93e].copy_from_slice(b"EF-S18-55mm"); // LensModel
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 450D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.2.4".into())));
    assert_eq!(find("OwnerName"), Some(TagValue::Str("Jane Doe".into())));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(200))); // PLAIN, no -1
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("LensModel"), Some(TagValue::Str("EF-S18-55mm".into())));
  }

  /// `%Canon::CameraInfo500D`: HighlightTonePriority/PictureStyle/HighISO/ALO +
  /// the `/^\d+\.\d+\.\d+\s*$/` FirmwareVersion RawConv guard.
  #[test]
  fn camera_info_500d_fields() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0xab] = 0x81; // PictureStyle Standard
    b[0xbc] = 2; // HighISONoiseReduction Strong
    b[0xbe] = 1; // AutoLightingOptimizer Low
    b[0xf8] = 0x00;
    b[0xf9] = 0x0a; // MinFocalLength 10
    b[0xfa] = 0x00;
    b[0xfb] = 0xc8; // MaxFocalLength 200
    b[0x190..0x196].copy_from_slice(b"1.1.1\0"); // FirmwareVersion (valid)
    b[0x1d3..0x1d7].copy_from_slice(&200u32.to_le_bytes()); // FileIndex 201
    b[0x1df..0x1e3].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex 199
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 500D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Strong".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Low".into()))
    );
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.1.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // The RawConv drops a non-version FirmwareVersion string.
    b[0x190..0x196].copy_from_slice(b"BADVER");
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 500D"), None);
    assert!(em2.iter().all(|(k, _)| k != "FirmwareVersion"));
  }

  /// `%Canon::CameraInfo550D`: like 500D but with NO HighISONoiseReduction /
  /// AutoLightingOptimizer rows (different offsets throughout).
  #[test]
  fn camera_info_550d_fields() {
    let mut b = vec![0u8; 0x410];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x35] = 1; // CameraOrientation Rotate 90 CW
    b[0xb0] = 0x81; // PictureStyle Standard
    b[0x101] = 0x00;
    b[0x102] = 0x0a; // MinFocalLength 10
    b[0x103] = 0x00;
    b[0x104] = 0xc8; // MaxFocalLength 200
    b[0x1a4..0x1aa].copy_from_slice(b"2.0.0\0"); // FirmwareVersion (valid)
    b[0x1e4..0x1e8].copy_from_slice(&200u32.to_le_bytes()); // FileIndex 201
    b[0x1f0..0x1f4].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex 199
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 550D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.0.0".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // 550D has no HighISONoiseReduction / AutoLightingOptimizer rows.
    assert!(em.iter().all(|(k, _)| k != "HighISONoiseReduction"));
    assert!(em.iter().all(|(k, _)| k != "AutoLightingOptimizer"));
  }

  #[test]
  fn dispatch_word_bounded_1000d() {
    assert!(model_is_camera_info_1000d(Some("Canon EOS 1000D")));
    assert!(model_is_camera_info_1000d(Some("Canon EOS REBEL XS")));
    assert!(model_is_camera_info_1000d(Some("Canon EOS Kiss F")));
    // `REBEL XS` (1000D) is distinct from `REBEL XSi` (450D).
    assert!(!model_is_camera_info_1000d(Some("Canon EOS REBEL XSi")));
    assert!(!model_is_camera_info_450d(Some("Canon EOS REBEL XS")));
  }

  /// `%Canon::CameraInfo1000D`: FlashModel (Mask 0x7f drops the high bit) +
  /// MacroMagnification + a PLAIN DirectoryIndex.
  #[test]
  fn camera_info_1000d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x13] = 0x91; // FlashModel: 0x91 & 0x7f = 0x11 (17) ⇒ Speedlite 580EX II
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1b] = 75; // MacroMagnification raw (1.0x when LensType == 124)
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength 50
    b[0xe4] = 0x00;
    b[0xe5] = 0x0a; // MinFocalLength 10
    b[0xe6] = 0x00;
    b[0xe7] = 0xc8; // MaxFocalLength 200
    b[0x10b..0x111].copy_from_slice(b"1.0.7\0"); // FirmwareVersion
    b[0x137..0x13b].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex PLAIN = 200
    b[0x143..0x147].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x937..0x943].copy_from_slice(b"EF-S55-250mm"); // LensModel
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 1000D"),
      Some(124),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("FlashModel"),
      Some(TagValue::Str("Speedlite 580EX II".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(
      find("MacroMagnification"),
      Some(TagValue::Str("1.0x".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.7".into())));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(200))); // PLAIN, no -1
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(
      find("LensModel"),
      Some(TagValue::Str("EF-S55-250mm".into()))
    );
    // -n view: FlashModel renders the masked raw integer.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 1000D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("FlashModel"), Some(TagValue::I64(17)));
    // A FlashModel value absent from %flashModel ⇒ decimal "Unknown (N)".
    b[0x13] = 0x7f; // 127 (not in the hash)
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 1000D"), None);
    assert_eq!(
      em2
        .iter()
        .find(|(k, _)| k == "FlashModel")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("Unknown (127)".into()))
    );
  }

  #[test]
  fn dispatch_anchored_6d() {
    assert!(model_is_camera_info_6d(Some("Canon EOS 6D")));
    assert!(!model_is_camera_info_6d(Some("Canon EOS 6D Mark II")));
    // /EOS 6D$/ must NOT match the 60D (which ends "60D", not "6D").
    assert!(!model_is_camera_info_6d(Some("Canon EOS 60D")));
  }

  /// `%Canon::PSInfo2` descent: the inserted `*Auto` block at 0x90/0xa0 and the
  /// +0x18-shifted UserDef blocks + the 0xf0 `UserDef1PictureStyle` leaf.
  #[test]
  fn ps_info2_auto_block() {
    let mut b = vec![0u8; 0x100];
    b[0x00..0x04].copy_from_slice(&5i32.to_le_bytes()); // ContrastStandard
    b[0x04..0x08].copy_from_slice(&(-559_038_737i32).to_le_bytes()); // Sharpness n/a
    b[0x90..0x94].copy_from_slice(&7i32.to_le_bytes()); // ContrastAuto (PSInfo2 only)
    b[0xa0..0xa4].copy_from_slice(&1i32.to_le_bytes()); // FilterEffectAuto -> Yellow
    b[0xa8..0xac].copy_from_slice(&9i32.to_le_bytes()); // ContrastUserDef1 (shifted +0x18)
    b[0xe4..0xe8].copy_from_slice(&3i32.to_le_bytes()); // ColorToneUserDef3
    b[0xf0..0xf2].copy_from_slice(&0x82u16.to_le_bytes()); // UserDef1PictureStyle -> Portrait
    let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
    let mut push = |n: &'static str, v: TagValue| out.push((SmolStr::new_static(n), v));
    ps_info2(&b, 0, ByteOrder::Little, true, &mut push);
    let find = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
    assert_eq!(find("SharpnessStandard"), Some(TagValue::Str("n/a".into())));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(7)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(find("ContrastUserDef1"), Some(TagValue::I64(9)));
    assert_eq!(find("ColorToneUserDef3"), Some(TagValue::I64(3)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Portrait".into()))
    );
    // 0x9c is the Auto block's ColorTone slot in PSInfo2 (it is ColorToneUserDef1
    // in plain PSInfo) — confirm the PSInfo2 mapping is used.
    assert_eq!(find("ColorToneAuto"), Some(TagValue::I64(0)));
  }

  /// `%Canon::CameraInfo6D` print values + the nested `%PSInfo2` subdir.
  #[test]
  fn camera_info_6d_fields() {
    let mut b = vec![0u8; 0x4c0];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength int16uRev = 50
    b[0x83] = 1; // CameraOrientation Rotate 90 CW
    b[0x92] = 0x01;
    b[0x93] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x94] = 0x01;
    b[0x95] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0xc2] = 0x02; // WhiteBalance raw 2 (checked in -n)
    b[0xc6] = 0x50;
    b[0xc7] = 0x14; // ColorTemperature 5200
    b[0xfa] = 0x81; // PictureStyle Standard
    b[0x161] = 0x00;
    b[0x162] = 0x01; // LensType int16uRev = 1 (checked in -n)
    b[0x163] = 0x00;
    b[0x164] = 0x0a; // MinFocalLength 10
    b[0x165] = 0x00;
    b[0x166] = 0xc8; // MaxFocalLength 200
    b[0x256..0x25c].copy_from_slice(b"1.1.6\0"); // FirmwareVersion (no guard)
    b[0x2aa..0x2ae].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x2b6..0x2ba].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex - 1 = 199
    // nested PSInfo2 at 0x3c6:
    b[0x3c6..0x3ca].copy_from_slice(&3i32.to_le_bytes()); // ContrastStandard
    b[0x456..0x45a].copy_from_slice(&2i32.to_le_bytes()); // ContrastAuto (0x3c6+0x90)
    b[0x466..0x46a].copy_from_slice(&1i32.to_le_bytes()); // FilterEffectAuto (0x3c6+0xa0)
    b[0x4b6..0x4b8].copy_from_slice(&0x81u16.to_le_bytes()); // UserDef1PictureStyle (0x3c6+0xf0)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 6D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.1.6".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // nested PSInfo2 tags:
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(3)));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(2)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Standard".into()))
    );
    // -n view: WhiteBalance / LensType render as bare masked integers.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 6D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("WhiteBalance"), Some(TagValue::I64(2)));
    assert_eq!(findn("LensType"), Some(TagValue::I64(1)));
  }

  #[test]
  fn dispatch_60d_1200d() {
    assert!(model_is_camera_info_60d(Some("Canon EOS 60D")));
    assert!(model_is_camera_info_60d(Some("Canon EOS 1200D")));
    assert!(model_is_camera_info_60d(Some("Canon EOS REBEL T5")));
    assert!(model_is_camera_info_60d(Some("Canon EOS Kiss X70")));
    // REBEL T5 (1200D) is distinct from REBEL T5i (700D).
    assert!(!model_is_camera_info_60d(Some("Canon EOS REBEL T5i")));
    // /EOS 60D$/ must NOT match the 6D.
    assert!(!model_is_camera_info_60d(Some("Canon EOS 6D")));
    // per-model discriminators used inside the table:
    assert!(model_is_60d_proper(Some("Canon EOS 60D")));
    assert!(!model_is_60d_proper(Some("Canon EOS 1200D")));
    assert!(model_is_1200d(Some("Canon EOS 1200D")));
    assert!(!model_is_1200d(Some("Canon EOS 60D")));
  }

  /// `%Canon::CameraInfo60D` shared 60D/1200D table: the per-model
  /// `CameraOrientation` offset (0x36 vs 0x3a), the 60D-only FocusDistance/
  /// ColorTemperature/File/Dir rows, and the `%PSInfo2` subdir at 0x321 (60D) vs
  /// 0x2f9 (1200D).
  #[test]
  fn camera_info_60d_and_1200d_alias() {
    let mut b = vec![0u8; 0x420];
    b[0x06] = 88; // ISO 400
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x36] = 2; // CameraOrientation 60D -> Rotate 270 CW
    b[0x3a] = 1; // CameraOrientation 1200D -> Rotate 90 CW
    b[0x55] = 0x01;
    b[0x56] = 0xf4; // FocusDistanceUpper 500 -> 5 m (60D only)
    b[0x57] = 0x01;
    b[0x58] = 0x2c; // FocusDistanceLower 300 -> 3 m (60D only)
    b[0x7d] = 0x50;
    b[0x7e] = 0x14; // ColorTemperature 5200 (60D only)
    b[0xe8] = 0x00;
    b[0xe9] = 0x01; // LensType int16uRev = 1 (-n)
    b[0xea] = 0x00;
    b[0xeb] = 0x0a; // MinFocalLength 10
    b[0xec] = 0x00;
    b[0xed] = 0xc8; // MaxFocalLength 200
    b[0x199..0x19f].copy_from_slice(b"2.8.1\0"); // FirmwareVersion (no guard, both)
    b[0x1d9..0x1dd].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101 (60D only)
    b[0x1e5..0x1e9].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99 (60D only)
    b[0x2f9..0x2fd].copy_from_slice(&5i32.to_le_bytes()); // PSInfo2(1200D) ContrastStandard
    b[0x321..0x325].copy_from_slice(&3i32.to_le_bytes()); // PSInfo2(60D) ContrastStandard

    // 60D proper:
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 60D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.8.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(3))); // from 0x321

    // 1200D alias:
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 1200D"), None);
    let find2 = |n: &str| em2.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find2("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into())) // 0x3a
    );
    assert_eq!(
      find2("FirmwareVersion"),
      Some(TagValue::Str("2.8.1".into()))
    );
    assert_eq!(find2("ContrastStandard"), Some(TagValue::I64(5))); // from 0x2f9
    // 60D-only rows are absent for the 1200D.
    assert!(find2("FocusDistanceUpper").is_none());
    assert!(find2("FocusDistanceLower").is_none());
    assert!(find2("ColorTemperature").is_none());
    assert!(find2("FileIndex").is_none());
    assert!(find2("DirectoryIndex").is_none());
  }

  #[test]
  fn dispatch_anchored_70d() {
    assert!(model_is_camera_info_70d(Some("Canon EOS 70D")));
    assert!(!model_is_camera_info_70d(Some("Canon EOS 7D")));
    // /EOS 70D$/ must NOT match the 700D.
    assert!(!model_is_camera_info_70d(Some("Canon EOS 700D")));
  }

  /// `%Canon::CameraInfo70D` print values + the nested `%PSInfo2` subdir; the
  /// table carries NO `WhiteBalance` leaf.
  #[test]
  fn camera_info_70d_fields() {
    let mut b = vec![0u8; 0x4d0];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 50
    b[0x84] = 1; // CameraOrientation Rotate 90 CW
    b[0x93] = 0x01;
    b[0x94] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x95] = 0x01;
    b[0x96] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0xc7] = 0x50;
    b[0xc8] = 0x14; // ColorTemperature 5200
    b[0x166] = 0x00;
    b[0x167] = 0x01; // LensType int16uRev = 1 (-n)
    b[0x168] = 0x00;
    b[0x169] = 0x0a; // MinFocalLength 10
    b[0x16a] = 0x00;
    b[0x16b] = 0xc8; // MaxFocalLength 200
    b[0x25e..0x264].copy_from_slice(b"6.1.2\0"); // FirmwareVersion (no guard)
    b[0x2b3..0x2b7].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x2bf..0x2c3].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x3cf..0x3d3].copy_from_slice(&4i32.to_le_bytes()); // PSInfo2 ContrastStandard
    b[0x45f..0x463].copy_from_slice(&2i32.to_le_bytes()); // PSInfo2 ContrastAuto (0x3cf+0x90)
    b[0x4bf..0x4c1].copy_from_slice(&0x86u16.to_le_bytes()); // UserDef1PictureStyle (0x3cf+0xf0)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 70D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("6.1.2".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(4)));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(2)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Monochrome".into()))
    );
    // The 70D table has no WhiteBalance row.
    assert!(find("WhiteBalance").is_none());
    // -n view: LensType renders the bare integer.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 70D"), None);
    assert_eq!(
      emn
        .iter()
        .find(|(k, _)| k == "LensType")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(1))
    );
  }

  #[test]
  fn dispatch_600d_1100d() {
    assert!(model_is_camera_info_600d(Some("Canon EOS 600D")));
    assert!(model_is_camera_info_600d(Some("Canon EOS REBEL T3i")));
    assert!(model_is_camera_info_600d(Some("Canon EOS Kiss X5")));
    assert!(model_is_camera_info_600d(Some("Canon EOS 1100D")));
    assert!(model_is_camera_info_600d(Some("Canon EOS REBEL T3")));
    assert!(model_is_camera_info_600d(Some("Canon EOS Kiss X50")));
    // REBEL T3 (1100D) vs REBEL T3i (600D): the T3i token must not leak into the
    // T5 (1200D) family, and Kiss X6i (650D) must not match.
    assert!(!model_is_camera_info_600d(Some("Canon EOS REBEL T5")));
    assert!(!model_is_camera_info_600d(Some("Canon EOS Kiss X6i")));
  }

  /// `%Canon::CameraInfo600D` shared 600D/1100D table (all rows unconditional):
  /// print values, the `FirmwareVersion` RawConv guard, and the `%PSInfo2` subdir.
  #[test]
  fn camera_info_600d_fields() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x15] = 0; // FlashMeteringMode E-TTL
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x38] = 2; // CameraOrientation Rotate 270 CW
    b[0x57] = 0x01;
    b[0x58] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x59] = 0x01;
    b[0x5a] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0x7b] = 0x02; // WhiteBalance raw 2 (-n)
    b[0x7f] = 0x50;
    b[0x80] = 0x14; // ColorTemperature 5200
    b[0xb3] = 0x81; // PictureStyle Standard
    b[0xea] = 0x00;
    b[0xeb] = 0x01; // LensType int16uRev = 1 (-n)
    b[0xec] = 0x00;
    b[0xed] = 0x0a; // MinFocalLength 10
    b[0xee] = 0x00;
    b[0xef] = 0xc8; // MaxFocalLength 200
    b[0x19b..0x1a1].copy_from_slice(b"1.0.2\0"); // FirmwareVersion (valid, guarded)
    b[0x1db..0x1df].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x1e7..0x1eb].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x2fb..0x2ff].copy_from_slice(&6i32.to_le_bytes()); // PSInfo2 ContrastStandard
    b[0x39b..0x39f].copy_from_slice(&1i32.to_le_bytes()); // PSInfo2 FilterEffectAuto (0x2fb+0xa0)
    b[0x3eb..0x3ed].copy_from_slice(&0x83u16.to_le_bytes()); // UserDef1PictureStyle (0x2fb+0xf0)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 600D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("FlashMeteringMode"),
      Some(TagValue::Str("E-TTL".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.2".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(6)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Landscape".into()))
    );
    // 1100D alias yields the identical table.
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 1100D"), None);
    let find2 = |n: &str| em2.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find2("FirmwareVersion"),
      Some(TagValue::Str("1.0.2".into()))
    );
    assert_eq!(find2("ContrastStandard"), Some(TagValue::I64(6)));
    // The RawConv guard drops a non-version FirmwareVersion string.
    b[0x19b..0x1a1].copy_from_slice(b"BADVER");
    let em3 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 600D"), None);
    assert!(em3.iter().all(|(k, _)| k != "FirmwareVersion"));
    // -n view: WhiteBalance / LensType render as bare integers.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 600D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("WhiteBalance"), Some(TagValue::I64(2)));
    assert_eq!(findn("LensType"), Some(TagValue::I64(1)));
  }

  #[test]
  fn dispatch_650d_700d() {
    assert!(model_is_camera_info_650d(Some("Canon EOS 650D")));
    assert!(model_is_camera_info_650d(Some("Canon EOS REBEL T4i")));
    assert!(model_is_camera_info_650d(Some("Canon EOS Kiss X6i")));
    assert!(model_is_camera_info_650d(Some("Canon EOS 700D")));
    assert!(model_is_camera_info_650d(Some("Canon EOS REBEL T5i")));
    assert!(model_is_camera_info_650d(Some("Canon EOS Kiss X7i")));
    // per-model discriminators used inside the table:
    assert!(model_is_650d_proper(Some("Canon EOS 650D")));
    assert!(!model_is_650d_proper(Some("Canon EOS 700D")));
    assert!(model_is_700d(Some("Canon EOS 700D")));
    assert!(!model_is_700d(Some("Canon EOS 650D")));
    // REBEL T5i (700D) is distinct from REBEL T5 (1200D), across both tables.
    assert!(!model_is_camera_info_650d(Some("Canon EOS REBEL T5")));
    assert!(!model_is_camera_info_60d(Some("Canon EOS REBEL T5i")));
  }

  /// `%Canon::CameraInfo650D` shared 650D/700D table: the per-model
  /// FirmwareVersion/FileIndex/DirectoryIndex offsets and the common `%PSInfo2`
  /// subdir. Two blobs (the firmware leaves at 0x21b/0x220 physically overlap).
  #[test]
  fn camera_info_650d_and_700d_alias() {
    let base = |b: &mut [u8]| {
      b[0x06] = 88; // ISO 400
      b[0x1b] = 148; // CameraTemperature 20 C
      b[0x23] = 0x00;
      b[0x24] = 0x32; // FocalLength 50
      b[0x7d] = 1; // CameraOrientation Rotate 90 CW
      b[0x8c] = 0x01;
      b[0x8d] = 0xf4; // FocusDistanceUpper 500 -> 5 m
      b[0x8e] = 0x01;
      b[0x8f] = 0x2c; // FocusDistanceLower 300 -> 3 m
      b[0xbc] = 0x02; // WhiteBalance raw 2
      b[0xc0] = 0x50;
      b[0xc1] = 0x14; // ColorTemperature 5200
      b[0xf4] = 0x81; // PictureStyle Standard
      b[0x127] = 0x00;
      b[0x128] = 0x01; // LensType int16uRev = 1
      b[0x129] = 0x00;
      b[0x12a] = 0x0a; // MinFocalLength 10
      b[0x12b] = 0x00;
      b[0x12c] = 0xc8; // MaxFocalLength 200
      b[0x390..0x394].copy_from_slice(&7i32.to_le_bytes()); // PSInfo2 ContrastStandard
      b[0x480..0x482].copy_from_slice(&0x84u16.to_le_bytes()); // UserDef1PictureStyle (0x390+0xf0)
    };

    // 650D: FirmwareVersion@0x21b, FileIndex@0x270, DirectoryIndex@0x27c.
    let mut b = vec![0u8; 0x490];
    base(&mut b);
    b[0x21b..0x221].copy_from_slice(b"1.0.1\0");
    b[0x270..0x274].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x27c..0x280].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 650D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(7)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Neutral".into()))
    );

    // 700D alias: FirmwareVersion@0x220, FileIndex@0x274, DirectoryIndex@0x280.
    let mut b2 = vec![0u8; 0x490];
    base(&mut b2);
    b2[0x220..0x226].copy_from_slice(b"2.1.1\0");
    b2[0x274..0x278].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b2[0x280..0x284].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex - 1 = 199
    let em2 = parse_model(&b2, ByteOrder::Little, true, Some("Canon EOS 700D"), None);
    let find2 = |n: &str| em2.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find2("FirmwareVersion"),
      Some(TagValue::Str("2.1.1".into()))
    );
    assert_eq!(find2("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find2("DirectoryIndex"), Some(TagValue::I64(199)));
    assert_eq!(find2("ContrastStandard"), Some(TagValue::I64(7))); // shared PSInfo2
    // The 650D-location leaves are not read for the 700D (and vice versa).
    assert_eq!(find2("FocalLength"), Some(TagValue::Str("50 mm".into())));
  }

  #[test]
  fn dispatch_1d_1ds() {
    assert!(model_is_camera_info_1d(Some("Canon EOS-1D")));
    assert!(model_is_camera_info_1d(Some("Canon EOS-1DS")));
    // lowercase "1Ds" does NOT match the case-sensitive /\b1DS?$/.
    assert!(!model_is_camera_info_1d(Some("Canon EOS-1Ds")));
    // the mk-series and the longer model numbers must not match the bare 1D.
    assert!(!model_is_camera_info_1d(Some("Canon EOS-1D Mark II")));
    assert!(!model_is_camera_info_1d(Some("Canon EOS-1D Mark III")));
    assert!(!model_is_camera_info_1d(Some("Canon EOS 1000D")));
    assert!(!model_is_camera_info_1d(Some("Canon EOS 100D")));
    // per-model discriminators used inside the table:
    assert!(model_is_1d_proper(Some("Canon EOS-1D")));
    assert!(!model_is_1d_proper(Some("Canon EOS-1DS")));
    assert!(model_is_1ds(Some("Canon EOS-1DS")));
    assert!(!model_is_1ds(Some("Canon EOS-1D")));
  }

  /// `%Canon::CameraInfo1D` 1D-proper: the PLAIN int16u focal lengths, the
  /// drop-zero int16uRev LensType (overlapping MinFocalLength by a byte), the
  /// 1-byte int8u WhiteBalance, and the 1D-only offsets (0x41/0x42/0x44/0x48/0x4b).
  #[test]
  fn camera_info_1d_proper_fields() {
    let mut b = vec![0u8; 0x60];
    b[0x04] = 0x20; // ExposureTime raw (non-zero ⇒ emitted)
    b[0x0a] = 0x32;
    b[0x0b] = 0x00; // FocalLength int16u plain = 50
    b[0x0d] = 0x00;
    b[0x0e] = 0x0a; // LensType int16uRev = BE(00 0a) = 10; also MinFocalLength low byte
    b[0x0f] = 0x00; // MinFocalLength int16u plain = 0x000a = 10
    b[0x10] = 0xc8;
    b[0x11] = 0x00; // MaxFocalLength int16u plain = 200
    b[0x41] = 3; // SharpnessFrequency Standard
    b[0x42] = 0xfe; // Sharpness int8s = -2
    b[0x44] = 1; // WhiteBalance int8u Daylight
    b[0x48] = 0x50;
    b[0x49] = 0x14; // ColorTemperature int16u = 5200
    b[0x4b] = 0x81; // PictureStyle Standard
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert!(find("ExposureTime").is_some());
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(
      find("SharpnessFrequency"),
      Some(TagValue::Str("Standard".into()))
    );
    assert_eq!(find("Sharpness"), Some(TagValue::I64(-2)));
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Daylight".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    // -n view: LensType renders the bare int16uRev value (10).
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS-1D"), None);
    assert_eq!(
      emn
        .iter()
        .find(|(k, _)| k == "LensType")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(10))
    );
  }

  /// `%Canon::CameraInfo1D` 1DS-proper: the 1DS-only offsets — note 0x48 is
  /// `Sharpness` (int8s) here, not `ColorTemperature`, which moves to 0x4e.
  #[test]
  fn camera_info_1ds_proper_fields() {
    let mut b = vec![0u8; 0x60];
    b[0x04] = 0x20; // ExposureTime (non-zero)
    b[0x0a] = 0x32;
    b[0x0b] = 0x00; // FocalLength = 50
    b[0x47] = 4; // SharpnessFrequency High
    b[0x48] = 0x03; // Sharpness int8s = 3 (1DS interpretation of 0x48)
    b[0x4a] = 2; // WhiteBalance int8u Cloudy
    b[0x4e] = 0x88;
    b[0x4f] = 0x13; // ColorTemperature int16u = 5000
    b[0x51] = 0x82; // PictureStyle Portrait
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1DS"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("SharpnessFrequency"),
      Some(TagValue::Str("High".into()))
    );
    assert_eq!(find("Sharpness"), Some(TagValue::I64(3)));
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Cloudy".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5000)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Portrait".into())));
  }

  /// Per-field availability: a blob ending before the later leaves emits only the
  /// in-range tags (each leaf gated on `data.get(off..off+size)`).
  #[test]
  fn camera_info_1d_truncated_per_field() {
    let mut b = vec![0u8; 0x05];
    b[0x04] = 0x20; // ExposureTime (in range)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS-1D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert!(find("ExposureTime").is_some());
    assert!(find("FocalLength").is_none());
    assert!(find("LensType").is_none());
    assert!(find("MinFocalLength").is_none());
    assert!(find("WhiteBalance").is_none());
  }

  #[test]
  fn dispatch_1dmkii_1dmkiin() {
    assert!(model_is_camera_info_1dmkii(Some("Canon EOS-1D Mark II")));
    assert!(model_is_camera_info_1dmkii(Some("Canon EOS-1Ds Mark II")));
    // the IIN must NOT match the mkII condition (the trailing `$`).
    assert!(!model_is_camera_info_1dmkii(Some("Canon EOS-1D Mark II N")));
    assert!(!model_is_camera_info_1dmkii(Some("Canon EOS-1D Mark III")));
    assert!(model_is_camera_info_1dmkiin(Some("Canon EOS-1D Mark II N")));
    assert!(model_is_camera_info_1dmkiin(Some(
      "Canon EOS-1Ds Mark II N"
    )));
    assert!(!model_is_camera_info_1dmkiin(Some("Canon EOS-1D Mark II")));
  }

  /// `%Canon::CameraInfo1DmkII`: int16uRev FocalLength/LensType/Min/Max, the
  /// int16uRev `ColorTemperature` (0x37), int8u `WhiteBalance`, `FocalType`,
  /// `CanonImageSize`, plain int8s `Sharpness`, `printParameter` Sat/Tone/Contrast,
  /// and the `string[5]` ISO.
  #[test]
  fn camera_info_1dmkii_fields() {
    let mut b = vec![0u8; 0x80];
    b[0x04] = 0x20; // ExposureTime present
    b[0x0a] = 0x32; // FocalLength int16uRev BE(00 32) = 50
    b[0x0d] = 0x01; // LensType int16uRev BE(00 01) = 1
    b[0x12] = 0x0a; // MinFocalLength int16uRev = 10
    b[0x14] = 0xc8; // MaxFocalLength int16uRev = 200
    b[0x2d] = 2; // FocalType Zoom
    b[0x36] = 3; // WhiteBalance int8u Tungsten
    b[0x37] = 0x14;
    b[0x38] = 0x50; // ColorTemperature int16uRev BE(14 50) = 5200
    b[0x39] = 0x01; // CanonImageSize int16u LE = 1 => Medium
    b[0x66] = 7; // JPEGQuality 7
    b[0x6c] = 0x83; // PictureStyle Landscape
    b[0x6e] = 0x02; // Saturation +2
    b[0x6f] = 0xfe; // ColorTone -2
    b[0x72] = 0x03; // Sharpness plain int8s = 3
    b[0x73] = 0x00; // Contrast Normal
    b[0x75..0x78].copy_from_slice(b"100"); // ISO string[5]
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark II"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert!(find("ExposureTime").is_some());
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FocalType"), Some(TagValue::Str("Zoom".into())));
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Tungsten".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("CanonImageSize"), Some(TagValue::Str("Medium".into())));
    assert_eq!(find("JPEGQuality"), Some(TagValue::I64(7)));
    assert_eq!(
      find("PictureStyle"),
      Some(TagValue::Str("Landscape".into()))
    );
    assert_eq!(find("Saturation"), Some(TagValue::Str("+2".into())));
    assert_eq!(find("ColorTone"), Some(TagValue::Str("-2".into())));
    assert_eq!(find("Sharpness"), Some(TagValue::I64(3)));
    assert_eq!(find("Contrast"), Some(TagValue::Str("Normal".into())));
    assert_eq!(find("ISO"), Some(TagValue::Str("100".into())));
    // -n view: LensType / CanonImageSize / Saturation render as bare values.
    let emn = parse_model(
      &b,
      ByteOrder::Little,
      false,
      Some("Canon EOS-1D Mark II"),
      None,
    );
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("LensType"), Some(TagValue::I64(1)));
    assert_eq!(findn("CanonImageSize"), Some(TagValue::I64(1)));
    assert_eq!(findn("Saturation"), Some(TagValue::I64(2)));
  }

  /// `%Canon::CameraInfo1DmkIIN`: like the 1DmkII but without FocalType /
  /// CanonImageSize / JPEGQuality, and with PictureStyle/Sharpness/Contrast/
  /// Saturation/ColorTone/ISO at the 0x73-row offsets.
  #[test]
  fn camera_info_1dmkiin_fields() {
    let mut b = vec![0u8; 0x80];
    b[0x04] = 0x20; // ExposureTime
    b[0x0a] = 0x32; // FocalLength 50
    b[0x0d] = 0x01; // LensType 1
    b[0x12] = 0x0a; // MinFocalLength 10
    b[0x14] = 0xc8; // MaxFocalLength 200
    b[0x36] = 2; // WhiteBalance Cloudy
    b[0x37] = 0x14;
    b[0x38] = 0x50; // ColorTemperature int16uRev = 5200
    b[0x73] = 0x86; // PictureStyle Monochrome
    b[0x74] = 0x04; // Sharpness plain int8s = 4
    b[0x75] = 0x03; // Contrast +3
    b[0x76] = 0xfd; // Saturation -3
    b[0x77] = 0x00; // ColorTone Normal
    b[0x79..0x7c].copy_from_slice(b"200"); // ISO string[5]
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark II N"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Cloudy".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(
      find("PictureStyle"),
      Some(TagValue::Str("Monochrome".into()))
    );
    assert_eq!(find("Sharpness"), Some(TagValue::I64(4)));
    assert_eq!(find("Contrast"), Some(TagValue::Str("+3".into())));
    assert_eq!(find("Saturation"), Some(TagValue::Str("-3".into())));
    assert_eq!(find("ColorTone"), Some(TagValue::Str("Normal".into())));
    assert_eq!(find("ISO"), Some(TagValue::Str("200".into())));
    // The 1DmkIIN table has no FocalType / CanonImageSize / JPEGQuality rows.
    assert!(find("FocalType").is_none());
    assert!(find("CanonImageSize").is_none());
    assert!(find("JPEGQuality").is_none());
  }

  #[test]
  fn dispatch_1dmkiii() {
    assert!(model_is_camera_info_1dmkiii(Some("Canon EOS-1D Mark III")));
    assert!(model_is_camera_info_1dmkiii(Some("Canon EOS-1Ds Mark III")));
    assert!(!model_is_camera_info_1dmkiii(Some("Canon EOS-1D Mark II")));
    assert!(!model_is_camera_info_1dmkiii(Some("Canon EOS-1D Mark IV")));
    // TimeStamp1 discriminator: 1DmkIII proper only, not the 1DSmkIII.
    assert!(model_is_1dmkiii_proper(Some("Canon EOS-1D Mark III")));
    assert!(!model_is_1dmkiii_proper(Some("Canon EOS-1Ds Mark III")));
  }

  /// `%Canon::CameraInfo1DmkIII`: the full `%ci*` triple, int16u WhiteBalance/
  /// ColorTemperature, the int16uRev LensType, `ShutterCount` (+1), the nested
  /// `%PSInfo` subdir at 0x2aa, and both `TimeStamp1` (1DmkIII-only) + `TimeStamp`.
  #[test]
  fn camera_info_1dmkiii_proper_fields() {
    let mut b = vec![0u8; 0x470];
    b[0x04] = 0x20; // ExposureTime present
    b[0x06] = 88; // ISO 400
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x32; // FocalLength int16uRev = 50
    b[0x30] = 1; // CameraOrientation Rotate 90 CW
    b[0x43] = 0x01;
    b[0x44] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x45] = 0x01;
    b[0x46] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0x5e] = 0x02; // WhiteBalance int16u raw 2 -> Cloudy
    b[0x62] = 0x50;
    b[0x63] = 0x14; // ColorTemperature 5200
    b[0x86] = 0x81; // PictureStyle Standard
    b[0x112] = 0x01; // LensType int16uRev = 1
    b[0x114] = 0x0a; // MinFocalLength int16uRev = 10
    b[0x116] = 0xc8; // MaxFocalLength int16uRev = 200
    b[0x136..0x13c].copy_from_slice(b"1.1.0\0"); // FirmwareVersion (no guard)
    b[0x172..0x176].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x176..0x17a].copy_from_slice(&5000u32.to_le_bytes()); // ShutterCount + 1 = 5001
    b[0x17e..0x182].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x2aa..0x2ae].copy_from_slice(&3i32.to_le_bytes()); // PSInfo ContrastStandard
    b[0x45a..0x45e].copy_from_slice(&1_370_690_080u32.to_le_bytes()); // TimeStamp1
    b[0x45e..0x462].copy_from_slice(&1_370_690_080u32.to_le_bytes()); // TimeStamp
    let em = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark III"),
      None,
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert!(find("ExposureTime").is_some());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Cloudy".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.1.0".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("ShutterCount"), Some(TagValue::I64(5001)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(3))); // PSInfo @ 0x2aa
    assert_eq!(
      find("TimeStamp1"),
      Some(TagValue::Str("2013:06:08 11:14:40".into()))
    );
    assert_eq!(
      find("TimeStamp"),
      Some(TagValue::Str("2013:06:08 11:14:40".into()))
    );
    // -n view: LensType renders the bare int16uRev value.
    let emn = parse_model(
      &b,
      ByteOrder::Little,
      false,
      Some("Canon EOS-1D Mark III"),
      None,
    );
    assert_eq!(
      emn
        .iter()
        .find(|(k, _)| k == "LensType")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(1))
    );
    // The 1DSmkIII shares the table but has NO TimeStamp1 leaf.
    let ems = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS-1Ds Mark III"),
      None,
    );
    assert!(ems.iter().all(|(k, _)| k != "TimeStamp1"));
    assert_eq!(
      ems
        .iter()
        .find(|(k, _)| k == "TimeStamp")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("2013:06:08 11:14:40".into()))
    );
  }

  #[test]
  fn dispatch_80d_750d() {
    assert!(model_is_camera_info_80d(Some("Canon EOS 80D")));
    // "8000D" routes to the 750D table, NOT the 80D (the `EOS 80D$` anchor).
    assert!(!model_is_camera_info_80d(Some("Canon EOS 8000D")));
    assert!(model_is_camera_info_750d(Some("Canon EOS 750D")));
    assert!(model_is_camera_info_750d(Some("Canon EOS 760D")));
    assert!(model_is_camera_info_750d(Some("Canon EOS Rebel T6i")));
    assert!(model_is_camera_info_750d(Some("Canon EOS Rebel T6s")));
    assert!(model_is_camera_info_750d(Some("Canon EOS Kiss X8i")));
    assert!(model_is_camera_info_750d(Some("Canon EOS 8000D")));
    // No cross-matching between the two tables.
    assert!(!model_is_camera_info_750d(Some("Canon EOS 80D")));
    assert!(!model_is_camera_info_80d(Some("Canon EOS 750D")));
  }

  /// `%Canon::CameraInfo80D`: the `%ci*` triple, int16u ColorTemperature,
  /// int16uRev LensType, the unguarded FirmwareVersion (0x45a), and the
  /// File/DirectoryIndex; no WhiteBalance/PictureStyle/PSInfo.
  #[test]
  fn camera_info_80d_fields() {
    let mut b = vec![0u8; 0x4c0];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x24] = 0x32; // FocalLength int16uRev = 50
    b[0x96] = 1; // CameraOrientation Rotate 90 CW
    b[0xa5] = 0x01;
    b[0xa6] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0xa7] = 0x01;
    b[0xa8] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0x13a] = 0x50;
    b[0x13b] = 0x14; // ColorTemperature 5200
    b[0x18a] = 0x01; // LensType int16uRev = 1
    b[0x18c] = 0x0a; // MinFocalLength int16uRev = 10
    b[0x18e] = 0xc8; // MaxFocalLength int16uRev = 200
    b[0x45a..0x460].copy_from_slice(b"1.0.1\0"); // FirmwareVersion (no guard)
    b[0x4ae..0x4b2].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x4ba..0x4be].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 80D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    // 80D has no WhiteBalance / PictureStyle leaf.
    assert!(find("WhiteBalance").is_none());
    assert!(find("PictureStyle").is_none());
    // FirmwareVersion (0x45a) has NO RawConv guard — a non-version string emits.
    b[0x45a..0x460].copy_from_slice(b"BADVER");
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 80D"), None);
    assert_eq!(
      em2
        .iter()
        .find(|(k, _)| k == "FirmwareVersion")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("BADVER".into()))
    );
    // -n view: LensType renders the bare int16uRev value.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS 80D"), None);
    assert_eq!(
      emn
        .iter()
        .find(|(k, _)| k == "LensType")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(1))
    );
  }

  /// `%Canon::CameraInfo750D` (shared 750D/760D): int16u WhiteBalance, int8u
  /// PictureStyle, int16uRev LensType, and the TWO guarded FirmwareVersion rows
  /// (0x43d / 0x449) — a real file emits from whichever holds the valid string.
  #[test]
  fn camera_info_750d_and_760d_alias() {
    let mut b = vec![0u8; 0x450];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x24] = 0x32; // FocalLength int16uRev = 50
    b[0x96] = 1; // CameraOrientation Rotate 90 CW
    b[0xa5] = 0x01;
    b[0xa6] = 0xf4; // FocusDistanceUpper 5 m
    b[0x131] = 0x02; // WhiteBalance int16u raw 2 -> Cloudy
    b[0x135] = 0x50;
    b[0x136] = 0x14; // ColorTemperature 5200
    b[0x169] = 0x81; // PictureStyle Standard
    b[0x185] = 0x01; // LensType int16uRev = 1
    b[0x187] = 0x0a; // MinFocalLength int16uRev = 10
    b[0x189] = 0xc8; // MaxFocalLength int16uRev = 200
    b[0x449..0x44f].copy_from_slice(b"6.7.2\0"); // FirmwareVersion @ 0x449 (valid)
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 750D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Cloudy".into())));
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    // Only the 0x449 location holds a valid version (0x43d is zeroed).
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("6.7.2".into())));
    // 760D alias yields the identical table.
    let em2 = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS 760D"), None);
    assert_eq!(
      em2
        .iter()
        .find(|(k, _)| k == "FirmwareVersion")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("6.7.2".into()))
    );
    // The other FirmwareVersion location (0x43d) is read independently.
    let mut b3 = b.clone();
    b3[0x449..0x44f].copy_from_slice(b"\0\0\0\0\0\0");
    b3[0x43d..0x443].copy_from_slice(b"1.2.3\0");
    let em3 = parse_model(&b3, ByteOrder::Little, true, Some("Canon EOS 760D"), None);
    assert_eq!(
      em3
        .iter()
        .find(|(k, _)| k == "FirmwareVersion")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("1.2.3".into()))
    );
    // The RawConv guard drops a non-version string at either location.
    let mut b4 = b.clone();
    b4[0x449..0x44f].copy_from_slice(b"BADVER");
    let em4 = parse_model(&b4, ByteOrder::Little, true, Some("Canon EOS 750D"), None);
    assert!(em4.iter().all(|(k, _)| k != "FirmwareVersion"));
  }

  // ─── mirrorless CameraInfo tables (R6 / R6m2 / R6m3 / G5XII) ────────────────

  #[test]
  fn camera_info_r6_dispatch_and_leaves() {
    // `/\bEOS R[56]$/` — the EOS R5/R6 only, NOT the R6m2 nor the R6 Mark III.
    assert!(model_is_camera_info_r6(Some("Canon EOS R5")));
    assert!(model_is_camera_info_r6(Some("Canon EOS R6")));
    assert!(!model_is_camera_info_r6(Some("Canon EOS R6m2")));
    assert!(!model_is_camera_info_r6(Some("Canon EOS R6 Mark III")));
    assert!(!model_is_camera_info_r6(Some("Canon EOS R7")));

    let mut b = vec![0u8; 0x0b00];
    b[0x09da] = 200; // CameraTemperature raw ⇒ 200 - 128 = 72
    b[0x0af1..0x0af5].copy_from_slice(&74_565u32.to_le_bytes()); // ShutterCount int32u
    // Emission walks ascending offset: CameraTemperature (0x09da), ShutterCount (0x0af1).
    let em = parse_model(&b, ByteOrder::Little, true, Some("Canon EOS R6"), None);
    assert_eq!(
      em.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
      ["CameraTemperature", "ShutterCount"]
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("72 C".into()))
    );
    assert_eq!(find("ShutterCount"), Some(TagValue::I64(74_565)));
    // -n view: the temperature renders as the bare ValueConv integer.
    let emn = parse_model(&b, ByteOrder::Little, false, Some("Canon EOS R5"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("CameraTemperature"), Some(TagValue::I64(72)));
    assert_eq!(findn("ShutterCount"), Some(TagValue::I64(74_565)));
    // A blob too short for ShutterCount emits only the in-range leaf (no panic).
    let short = parse_model(
      &b[..0x0a00],
      ByteOrder::Little,
      true,
      Some("Canon EOS R6"),
      None,
    );
    assert_eq!(
      short.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
      ["CameraTemperature"]
    );
  }

  #[test]
  fn camera_info_r6m2_shutter_count() {
    // `/\bEOS (R6m2|R8|R50)$/`.
    assert!(model_is_camera_info_r6m2(Some("Canon EOS R6m2")));
    assert!(model_is_camera_info_r6m2(Some("Canon EOS R8")));
    assert!(model_is_camera_info_r6m2(Some("Canon EOS R50")));
    assert!(!model_is_camera_info_r6m2(Some("Canon EOS R6")));
    assert!(!model_is_camera_info_r6m2(Some("Canon EOS R5")));

    let mut b = vec![0u8; 0x0d40];
    b[0x0d29..0x0d2d].copy_from_slice(&1_000_000u32.to_le_bytes());
    // No PrintConv ⇒ identical in both views.
    for pc in [true, false] {
      let em = parse_model(&b, ByteOrder::Little, pc, Some("Canon EOS R8"), None);
      assert_eq!(
        em.iter()
          .map(|(k, v)| (k.as_str(), v.clone()))
          .collect::<Vec<_>>(),
        vec![("ShutterCount", TagValue::I64(1_000_000))]
      );
    }
  }

  #[test]
  fn camera_info_r6m3_image_count_int16u() {
    assert!(model_is_camera_info_r6m3(Some("Canon EOS R6 Mark III")));
    assert!(!model_is_camera_info_r6m3(Some("Canon EOS R6")));
    assert!(!model_is_camera_info_r6m3(Some("Canon EOS R6m2")));

    let mut b = vec![0u8; 0x0900];
    b[0x086d..0x086f].copy_from_slice(&0x1234u16.to_le_bytes()); // 4660
    let em = parse_model(
      &b,
      ByteOrder::Big,
      true,
      Some("Canon EOS R6 Mark III"),
      None,
    );
    // Big-endian read of the LE-written bytes ⇒ 0x3412 = 13330.
    assert_eq!(
      em.iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect::<Vec<_>>(),
      vec![("ImageCount", TagValue::I64(0x3412))]
    );
    let le = parse_model(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS R6 Mark III"),
      None,
    );
    assert_eq!(
      le.first().map(|(_, v)| v.clone()),
      Some(TagValue::I64(0x1234))
    );
  }

  #[test]
  fn camera_info_g5xii_filetype_gated() {
    // `/\bG5 X Mark II$/` — the PowerShot G5 X Mark II.
    assert!(model_is_camera_info_g5xii(Some(
      "Canon PowerShot G5 X Mark II"
    )));
    assert!(!model_is_camera_info_g5xii(Some("Canon PowerShot G5 X")));

    let mut b = vec![0u8; 0x0b40];
    b[0x0293..0x0297].copy_from_slice(&111u32.to_le_bytes()); // ShutterCount (JPEG)
    b[0x0a95..0x0a99].copy_from_slice(&222u32.to_le_bytes()); // ShutterCount (CR3)
    b[0x0b21..0x0b25].copy_from_slice(&50u32.to_le_bytes()); // DirectoryIndex (JPEG)
    b[0x0b2d..0x0b31].copy_from_slice(&1_427u32.to_le_bytes()); // FileIndex ⇒ +1 = 1428

    // JPEG: ShutterCount(0x0293), DirectoryIndex(0x0b21), FileIndex(0x0b2d)+1.
    let jpeg = camera_info_g5xii(&b, ByteOrder::Little, Some("JPEG"));
    assert_eq!(
      jpeg.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
      ["ShutterCount", "DirectoryIndex", "FileIndex"]
    );
    let jf = |n: &str| jpeg.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(jf("ShutterCount"), Some(TagValue::I64(111)));
    assert_eq!(jf("DirectoryIndex"), Some(TagValue::I64(50)));
    assert_eq!(jf("FileIndex"), Some(TagValue::I64(1_428)));

    // CR3: only the 0x0a95 ShutterCount.
    let cr3 = camera_info_g5xii(&b, ByteOrder::Little, Some("CR3"));
    assert_eq!(
      cr3
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect::<Vec<_>>(),
      vec![("ShutterCount", TagValue::I64(222))]
    );

    // Any other / unknown FileType ⇒ nothing (every row is FileType-gated).
    assert!(camera_info_g5xii(&b, ByteOrder::Little, Some("MP4")).is_empty());
    assert!(camera_info_g5xii(&b, ByteOrder::Little, None).is_empty());

    // Routed through the 0x0d dispatch with the container `$$self{FileType}`.
    // G5XII is reached by MODEL, so the count/format keys are inert here.
    let routed = super::parse(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon PowerShot G5 X Mark II"),
      Some("JPEG"),
      None,
      0,
      false,
    );
    assert_eq!(
      routed.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
      ["ShutterCount", "DirectoryIndex", "FileIndex"]
    );
  }

  /// Build an `int32s` PowerShot blob of `count` elements (little-endian) with the
  /// named `(index, value)` words set; every other word is zero. Mirrors how the
  /// dispatch widens the on-disk `int32u[$count]` value to its byte blob.
  fn ps_blob(count: usize, words: &[(usize, i32)]) -> Vec<u8> {
    let mut b = vec![0u8; count * 4];
    for &(idx, v) in words {
      b[idx * 4..idx * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    b
  }

  /// `%CameraInfoPowerShot` (`Canon.pm:5711`) — the model rows fail, so the
  /// int32u + count(138/148) gate selects it; `CameraTemperature` tracks the count
  /// (index 135 for 138, 145 for 148).
  #[test]
  fn camera_info_powershot_count_138_and_148() {
    // ISO 507 ⇒ 200; FNumber 192 ⇒ f/2; ExposureTime 384 ⇒ 1/16; Rotation plain.
    let b138 = ps_blob(
      138,
      &[(0x00, 507), (0x05, 192), (0x06, 384), (0x17, 6), (135, 35)],
    );
    let out = super::parse(
      &b138,
      ByteOrder::Little,
      true,
      Some("Canon PowerShot A450"),
      None,
      None,
      138,
      true,
    );
    let get = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(get("ISO"), Some(TagValue::Str("200".into())));
    assert_eq!(get("FNumber"), Some(TagValue::Str("2".into())));
    assert_eq!(get("ExposureTime"), Some(TagValue::Str("1/16".into())));
    assert_eq!(get("Rotation"), Some(TagValue::I64(6)));
    assert_eq!(get("CameraTemperature"), Some(TagValue::Str("35 C".into())));

    // count 148: CameraTemperature reads index 145, NOT 135 (the 138 row's index).
    let b148 = ps_blob(148, &[(135, 99), (145, 40)]);
    let out = super::parse(&b148, ByteOrder::Little, true, None, None, None, 148, true);
    let temp = out
      .iter()
      .find(|(k, _)| k == "CameraTemperature")
      .map(|(_, v)| v.clone());
    assert_eq!(temp, Some(TagValue::Str("40 C".into())));
  }

  /// `%CameraInfoPowerShot2` (`Canon.pm:5771`) — each count selects its own
  /// `CameraTemperature` index (`Canon.pm:5809`-`:5846`).
  #[test]
  fn camera_info_powershot2_all_counts() {
    for &(count, temp_idx) in &[
      (156usize, 153usize),
      (162, 159),
      (167, 164),
      (171, 168),
      (264, 261),
    ] {
      let b = ps_blob(
        count,
        &[
          (0x01, 507),
          (0x06, 192),
          (0x07, 96),
          (0x18, 3),
          (temp_idx, 22),
        ],
      );
      let out = super::parse(&b, ByteOrder::Little, true, None, None, None, count, true);
      let get = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
      assert_eq!(
        get("ISO"),
        Some(TagValue::Str("200".into())),
        "count {count}"
      );
      assert_eq!(
        get("FNumber"),
        Some(TagValue::Str("2".into())),
        "count {count}"
      );
      assert_eq!(
        get("ExposureTime"),
        Some(TagValue::Str("0.5".into())),
        "count {count}"
      );
      assert_eq!(get("Rotation"), Some(TagValue::I64(3)), "count {count}");
      assert_eq!(
        get("CameraTemperature"),
        Some(TagValue::Str("22 C".into())),
        "count {count}"
      );
    }
  }

  /// The `$format eq "int32u"` gate AND the model-first dispatch order
  /// (`Canon.pm:1466`-`:1479`, evaluated after every model row).
  #[test]
  fn camera_info_powershot_format_and_model_gates() {
    let b = ps_blob(138, &[(0x00, 507), (135, 35)]);
    // Right count, but `$format` is not int32u ⇒ the PowerShot rows never fire.
    assert!(super::parse(&b, ByteOrder::Little, true, None, None, None, 138, false).is_empty());
    // int32u but an UNLISTED count ⇒ nothing (the deferred `CameraInfoUnknown*`).
    assert!(
      super::parse(
        &ps_blob(100, &[(0x00, 507)]),
        ByteOrder::Little,
        true,
        None,
        None,
        None,
        100,
        true,
      )
      .is_empty()
    );
    // A matching MODEL precedes the count keys: a G5 X Mark II at int32u/138 routes
    // to G5XII, so the PowerShot ISO/CameraTemperature leaves are NOT emitted.
    let routed = super::parse(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon PowerShot G5 X Mark II"),
      Some("JPEG"),
      None,
      138,
      true,
    );
    assert!(
      routed
        .iter()
        .all(|(k, _)| k != "ISO" && k != "CameraTemperature")
    );
  }

  /// The numeric (`-n`) view: the ValueConv floats render bare-int / `F64` exactly
  /// like the model tables (`value_or_print`).
  #[test]
  fn camera_info_powershot_numeric_view() {
    let b = ps_blob(138, &[(0x00, 507), (0x05, 192), (0x06, 96), (135, 35)]);
    let out = super::parse(&b, ByteOrder::Little, false, None, None, None, 138, true);
    let get = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(get("ISO"), Some(TagValue::I64(200)));
    assert_eq!(get("FNumber"), Some(TagValue::I64(2)));
    assert_eq!(get("ExposureTime"), Some(TagValue::F64(0.5)));
    assert_eq!(get("CameraTemperature"), Some(TagValue::I64(35)));
  }

  /// `int32s` signed decode + per-field availability (a truncated blob drops the
  /// out-of-range leaves while the in-range ones still emit).
  #[test]
  fn camera_info_powershot_signed_and_truncation() {
    let mut b = ps_blob(138, &[(0x17, -1)]);
    b[135 * 4..135 * 4 + 4].copy_from_slice(&(-5i32).to_le_bytes());
    let out = super::parse(&b, ByteOrder::Little, true, None, None, None, 138, true);
    let get = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(get("Rotation"), Some(TagValue::I64(-1)));
    assert_eq!(get("CameraTemperature"), Some(TagValue::Str("-5 C".into())));

    // Truncate to 28 bytes: indices 0/5/6 (bytes 0..28) survive; Rotation (index
    // 23 ⇒ byte 92) and CameraTemperature (index 135) fall out of range.
    let full = ps_blob(
      138,
      &[(0x00, 507), (0x05, 192), (0x06, 96), (0x17, 6), (135, 35)],
    );
    let out = super::parse(
      &full[..28],
      ByteOrder::Little,
      true,
      None,
      None,
      None,
      138,
      true,
    );
    let names: Vec<_> = out.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"ISO"));
    assert!(names.contains(&"FNumber"));
    assert!(names.contains(&"ExposureTime"));
    assert!(!names.contains(&"Rotation"));
    assert!(!names.contains(&"CameraTemperature"));
  }
}
