// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony MakerNotes — Phase-3 port.
//!
//! Bundled source: `lib/Image/ExifTool/Sony.pm` —
//! `%Image::ExifTool::Sony::Main` (`Sony.pm:688-2687`) plus
//! `%sonyLensTypes2` (`Sony.pm:56-387`) plus the inline `SonyModelID`
//! PrintConv (`Sony.pm:2131-2248`).
//!
//! ## Phase 3 scope
//!
//! - The Sony body walk — accepts the dispatcher-provided body-offset
//!   (12 for the `SONY DSC `/`SONY CAM ` variants, 0 for `MakerNoteSony5`
//!   headerless), walks the IFD entries. This now runs through the shared
//!   `Walker` isolated helper `crate::exif::sony_makernote_isolated`; the
//!   standalone `body::walk_sony_in_tiff` oracle was deleted in #243 phase 5.
//! - The faithful tag table ([`tags::SONY_TAGS`]) — every named LEAF tag
//!   in `%Sony::Main` with a clean PrintConv. The big conditional-list
//!   SubDirectory rows (`CameraInfo`/`CameraSettings`/`FocusInfo`/
//!   `ExtraInfo`/`Tag2010`/`Tag9050`-`Tag9416`/`AFInfo`) are surfaced as
//!   `SubTable::…` entries; the per-table walkers are deferred (see
//!   "Deferred" below).
//! - Per-tag PrintConv ([`printconv::SonyPrintConv`]) — Quality,
//!   WhiteBalance, MultiBurstMode, Contrast/Saturation/Sharpness/
//!   Brightness, LongExposureNR, HighISONR, PictureEffect, SoftSkinEffect,
//!   PrioritySetInAWB, Macro, FocusMode/AFAreaMode, ExposureMode (SCN),
//!   DynamicRangeOptimizer, ZoneMatching, the model-id + lens-type
//!   lookup-driven PrintConv arms.
//! - [`lens_types::SONY_LENS_TYPES`] — 265 sorted entries from
//!   `%sonyLensTypes2`.
//! - [`model_ids::SONY_MODEL_IDS`] — 112 sorted entries from the
//!   `SonyModelID` PrintConv hash.
//! - A typed [`MakerNotesSony`] struct with D8 accessors over the parsed
//!   fields — body identity (model ID + name from %sonyModelID, image
//!   stabilisation, creative style, picture effect) + lens identity
//!   (lens-type ID + resolved name).
//!
//! ## Deferred (Phase 3+1 follow-up issues — see #62 umbrella)
//!
//! - **Sony color/RAW sub-tables** (mirror Canon ColorData umbrella) —
//!   color-data sub-tables in `Sony::Tag9405a/b`, `Tag2010x`, etc.; raw-
//!   processing-only.
//! - **Sony per-model CameraInfo<XXX>** — `CameraInfo` / `CameraInfo2` /
//!   `CameraInfo3` / `CameraInfoUnknown` (`Sony.pm:2722-3170`) — each
//!   gated by `$count`; defer.
//! - **Sony AFInfo / FocusInfo** (`Sony.pm:3171-3502`, `9431-9876`) —
//!   AF-point sensor data; defer.
//! - **Sony CustomFunctions** — no dedicated CustomFunctions tag table
//!   in Sony.pm (Canon-style); Sony embeds these in the per-model
//!   CameraSettings sub-tables which are themselves deferred.
//! - **Sony model-conditional position decoders** in CameraSettings3 etc.
//!   — defer.
//! - **Sony Tag9xxx series** (`Tag9050a/b/c/d`, `Tag9400a/b/c`, `Tag9401`,
//!   etc.) — these carry the per-model fine-grained shot/AF/lens info that
//!   newer bodies use INSTEAD of the legacy CameraInfo sub-tables. Their
//!   per-position offsets vary by body and bundled gates with `MetaVersion`
//!   / `Model` regex; defer.
//! - **Sony FX-/Cinema-specific MakerNotes** — the FX3/FX30/FX2 cinema
//!   bodies write extra timecode/recording-state info in the Tag2010+
//!   tables that are themselves deferred. The model-ID lookup already
//!   resolves the body name (e.g. `385 => 'ILME-FX3'`); finer FX-specific
//!   decoding is part of the Tag9xxx deferral.
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future Phase 3-bis can add fields without a
//! breaking change.

#![deny(clippy::indexing_slicing)]

pub mod amount_lens_types;
pub mod decipher;
pub mod lens_types;
pub mod model_ids;
pub mod printconv;
pub mod sr2;
pub mod tag202a;
pub mod tag9050;
pub mod tag9400;
pub mod tag9401;
pub mod tag9402;
pub mod tag9406;
pub mod tag940c;
pub mod tag9416;
pub mod tags;

use crate::value::TagValue;
use smol_str::SmolStr;

pub use lens_types::{SONY_LENS_TYPES, SonyLensType};
pub use model_ids::{SONY_MODEL_IDS, SonyModelEntry};
pub use printconv::{
  CONDITION_GATED_IDS, RAWCONV_DROP_IDS, SonyPrintConv, rawconv_drops, single_hash_condition_holds,
};
pub use tags::{SONY_TAGS, SonyTag, SubTable, format_override, lookup};

use super::super::super::ifd::RawValue;

/// Decoded Sony MakerNotes data — populated by
/// `crate::exif::sony_makernote_isolated` when the dispatcher resolved
/// [`Vendor::Sony`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MakerNotesSony {
  // ---- camera-identity ----
  /// Sony Main 0xb001 (`SonyModelID`) — int16u body ID.
  model_id: Option<u16>,
  /// Resolved model name from `%sonyModelID`.
  model_name: Option<SmolStr>,
  /// Sony Main 0xb020 (`CreativeStyle`) — string from the body.
  creative_style: Option<SmolStr>,
  // ---- lens identity ----
  /// Sony Main 0xb027 (`LensType`) — A-mount lens-type id (filled in
  /// runtime from `%minoltaLensTypes`; the E-mount equivalents live in
  /// %sonyLensTypes2). Phase 3's lookup table uses `%sonyLensTypes2`
  /// (E-mount) — the A-mount ports are deferred.
  lens_type: Option<u32>,
  /// Resolved lens name from `%sonyLensTypes2` (E-mount). `None` when the
  /// ID isn't in the table (e.g. A-mount IDs that resolve via the
  /// deferred `%minoltaLensTypes`).
  lens_name: Option<SmolStr>,
  // ---- capture metadata ----
  /// Sony Main 0x0102 (`Quality`).
  quality: Option<u32>,
  /// Sony Main 0x0115 (`WhiteBalance`).
  white_balance: Option<u32>,
  /// Sony Main 0xb026 (`ImageStabilization`).
  image_stabilization: Option<u32>,
  /// Sony Main 0x200e (`PictureEffect`).
  picture_effect: Option<u32>,
  /// Sony Main 0xb023 (`SceneMode`).
  scene_mode: Option<u32>,
  /// Sony Main 0xb025 (`DynamicRangeOptimizer`).
  dynamic_range_optimizer: Option<u32>,
  /// Sony Main 0xb041 (`ExposureMode`) — scene/program mode.
  exposure_mode: Option<u32>,
  /// Sony Main 0xb054 (`WhiteBalance` — newer variant).
  white_balance_2: Option<u32>,
}

impl MakerNotesSony {
  /// Build an empty Sony metadata bag.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      model_id: None,
      model_name: None,
      creative_style: None,
      lens_type: None,
      lens_name: None,
      quality: None,
      white_balance: None,
      image_stabilization: None,
      picture_effect: None,
      scene_mode: None,
      dynamic_range_optimizer: None,
      exposure_mode: None,
      white_balance_2: None,
    }
  }

  /// `SonyModelID` (`Sony.pm:2131`) — int16u body identification.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u16> {
    self.model_id
  }

  /// Resolved model name from `%sonyModelID`.
  #[must_use]
  #[inline]
  pub fn model_name(&self) -> Option<&str> {
    self.model_name.as_deref()
  }

  /// `CreativeStyle` (`Sony.pm:2251-2282`) — Sony creative-style string.
  #[must_use]
  #[inline]
  pub fn creative_style(&self) -> Option<&str> {
    self.creative_style.as_deref()
  }

  /// Sony LensType ID (`Sony.pm:0xb027`).
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<u32> {
    self.lens_type
  }

  /// Resolved lens name from `%sonyLensTypes2` (E-mount). `None` for
  /// A-mount IDs (which resolve via the deferred `%minoltaLensTypes`).
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }

  /// `Quality` (`Sony.pm:751-767`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn quality(&self) -> Option<u32> {
    self.quality
  }

  /// `WhiteBalance` (`Sony.pm:817-834`) — integer (Sony PrintHex hash).
  #[must_use]
  #[inline(always)]
  pub const fn white_balance(&self) -> Option<u32> {
    self.white_balance
  }

  /// `ImageStabilization` (`Sony.pm:0xb026`).
  #[must_use]
  #[inline(always)]
  pub const fn image_stabilization(&self) -> Option<u32> {
    self.image_stabilization
  }

  /// `PictureEffect` (`Sony.pm:1025-1066`).
  #[must_use]
  #[inline(always)]
  pub const fn picture_effect(&self) -> Option<u32> {
    self.picture_effect
  }

  /// `SceneMode` (`Sony.pm:0xb023`).
  #[must_use]
  #[inline(always)]
  pub const fn scene_mode(&self) -> Option<u32> {
    self.scene_mode
  }

  /// `DynamicRangeOptimizer` (`Sony.pm:2310-2342`).
  #[must_use]
  #[inline(always)]
  pub const fn dynamic_range_optimizer(&self) -> Option<u32> {
    self.dynamic_range_optimizer
  }

  /// `ExposureMode` (`Sony.pm:2411-2451`) — scene/program mode.
  #[must_use]
  #[inline(always)]
  pub const fn exposure_mode(&self) -> Option<u32> {
    self.exposure_mode
  }

  /// `WhiteBalance` newer variant (`Sony.pm:0xb054`).
  #[must_use]
  #[inline(always)]
  pub const fn white_balance_2(&self) -> Option<u32> {
    self.white_balance_2
  }
}

/// `true` iff a `Vendor::Sony` blob routes to `%Sony::Main` (and so the
/// Sony Main IFD walker `crate::exif::sony_makernote_isolated` should run on
/// it).
///
/// The dispatcher collapses ALL seven Sony `MakerNotes.pm` variants
/// (`:1031-1099`) to [`Vendor::Sony`](crate::exif::makernotes::Vendor::Sony),
/// but only TWO use `Image::ExifTool::Sony::Main`; the rest route to a
/// DIFFERENT table whose parser is not (yet) ported, so running the Main
/// walker on them is UNFAITHFUL (it can emit spurious tags on a coincidental
/// tag-id collision — e.g. a `SEMC MS\0` Ericsson blob decodes a bogus
/// `Quality` through `%Sony::Main`). This predicate is the call-site gate,
/// mirroring `%Main` order:
///
/// - `MakerNoteSony` (`:1032`) — blob starts with `SONY DSC`/`SONY CAM`/
///   `SONY MOBILE` / `\0\0SONY PIC\0` (TF1) / `VHAB     \0` ⇒ **Sony::Main**.
/// - `MakerNoteSony2` (`:1044`, `SONY PI\0`) ⇒ `Olympus::Main` — NOT Main.
/// - `MakerNoteSony3` (`:1054`, `PREMI\0`) ⇒ `Olympus::Main` — NOT Main.
/// - `MakerNoteSony4` (`:1064`, `SONY PIC\0`) ⇒ `Sony::PIC` — NOT Main.
/// - `MakerNoteSony5` (`:1070`) — `(Make=~/^SONY/ or (Make=~/^HASSELBLAD/
///   and Model=~/^(HV|Stellar|Lusso|Lunar)/)) and blob !~ /^\x01\x00/`, and
///   the blob matched none of the earlier prefixed arms ⇒ **Sony::Main**.
///   Tested BEFORE SonyEricsson, so a `SEMC MS\0` blob whose Make is `/^SONY/`
///   is claimed HERE (`%Sony::Main`), exactly as ExifTool's `%Main` order.
/// - `MakerNoteSonyEricsson` (`:1083`, `SEMC MS\0`) ⇒ `Sony::Ericsson`
///   (`Base => '$start - 8'`) — NOT Main. Reached only when Sony5 did NOT
///   admit the blob (Make not `/^SONY/`, e.g. the real `"Sony Ericsson"`).
/// - `MakerNoteSonySRF` (`:1093`, Make `^SONY` + the `\x01\x00` case) ⇒
///   `Sony::SRF` — NOT Main.
///
/// `Sony::Ericsson`, `Sony::PIC`, `Sony::SRF` and the Olympus cross-routes
/// are deferred long-tail items (the Phase-3 port ships `%Sony::Main` only —
/// see the module docs); until they land, the call site must not feed those
/// blobs to the Main walker.
#[must_use]
pub fn routes_to_main(blob: &[u8], make: Option<&str>, model: Option<&str>) -> bool {
  // MakerNoteSony — the offset-12 prefixed group (`:1036`). The
  // `blob.len() >= 11` guard makes each `.get(..)` below `Some`; the checked
  // forms preserve the exact short-circuit boolean — byte-identical.
  let is_tf1 = blob.len() >= 11
    && blob.get(..2) == Some(b"\x00\x00".as_slice())
    && blob.get(2..10) == Some(b"SONY PIC".as_slice())
    && blob.get(10) == Some(&0);
  if blob.starts_with(b"SONY DSC")
    || blob.starts_with(b"SONY CAM")
    || blob.starts_with(b"SONY MOBILE")
    || is_tf1
    || blob.starts_with(b"VHAB     \x00")
  {
    return true;
  }
  // The earlier non-Main prefixed arms (tested BEFORE Sony5 in `%Main`):
  // a blob matching one of these is claimed by Sony2/3/4, never Sony5.
  if blob.starts_with(b"SONY PI\x00")   // Sony2 → Olympus::Main
    || blob.starts_with(b"PREMI\x00")   // Sony3 → Olympus::Main
    || blob.starts_with(b"SONY PIC\x00")
  // Sony4 → Sony::PIC
  {
    return false;
  }
  // MakerNoteSony5 (`:1070`) — make-gated, headerless, blob NOT `\x01\x00`
  // (`:1072-1075`). This is tested BEFORE SonyEricsson (`:1083`) in `%Main`, so
  // a `SEMC MS\0` blob whose parent Make matches `/^SONY/` is claimed by Sony5
  // → `Sony::Main` here (ExifTool decodes it through `%Main`, even into bogus
  // tags) — the SEMC rejection below only fires for a blob Sony5 did NOT admit
  // (the common real Ericsson case, Make `"Sony Ericsson"`, which is not
  // `/^SONY/`). The `\x01\x00` case is SonySRF (`Sony::SRF`), excluded here by
  // the `!~ /^\x01\x00/` lookahead and rejected as non-Main below. This mirrors
  // the dispatcher's own `%Main`-order classification (`dispatcher.rs:1325`
  // Sony5 precedes `:1341` SonyEricsson) so the two cannot drift.
  let make_ok = matches!(make, Some(m) if m.starts_with("SONY"))
    || (matches!(make, Some(m) if m.starts_with("HASSELBLAD"))
      && matches!(model, Some(m) if {
        m.starts_with("HV") || m.starts_with("Stellar") || m.starts_with("Lusso") || m.starts_with("Lunar")
      }));
  if make_ok && !blob.starts_with(b"\x01\x00") {
    return true;
  }
  // SonyEricsson (`:1083`) / SonySRF (`:1093`) — NOT Main, tested AFTER Sony5
  // (`%Main` order). A `SEMC MS\0` blob reaches here only when Sony5's make gate
  // did NOT admit it (Make not `/^SONY/`) ⇒ `Sony::Ericsson`. Any other body
  // that fell through Sony5 (a `\x01\x00` SonySRF blob, or a non-`SONY`/
  // non-Hasselblad Make) is likewise NOT `%Sony::Main`.
  if blob.starts_with(b"SEMC MS\x00") {
    return false; // → Sony::Ericsson
  }
  // SonySRF (`Make=~/^SONY/`, the `\x01\x00` case) and every other fall-through
  // are NOT Main.
  false
}

/// Populate the typed struct from one Sony Main-IFD leaf-tag emission. `raw` is
/// the entry's post-Format-decode [`RawValue`]; `val` the already-rendered
/// [`TagValue`] (read ONLY by 0xb020's string fallback).
///
/// MUST be called ONLY for an entry that PASSED every suppression gate (the
/// SubDirectory-skip / single-HASH / RawConv-drop / conditional-AF checks,
/// alongside the emission) — a rawconv-dropped 0xb041, for instance, must
/// populate NEITHER the emission NOR `exposure_mode`. The shared-`Walker` Sony
/// capture (`exif::mod::emit_sony_value`) preserves that ordering by calling this
/// from the SAME gate-passing path it emits from (#243 phase 3).
pub(crate) fn populate_typed(
  typed: &mut MakerNotesSony,
  tag_id: u16,
  raw: &RawValue,
  val: &TagValue,
) {
  match tag_id {
    0x0102 => {
      typed.quality = first_u32(raw);
    }
    0x0115 => {
      typed.white_balance = first_u32(raw);
    }
    0x200e => {
      typed.picture_effect = first_u32(raw);
    }
    0xb001 => {
      if let Some(n) = first_u32(raw) {
        let id = u16::try_from(n).unwrap_or(0);
        typed.model_id = Some(id);
        typed.model_name = model_ids::lookup_name(id);
      }
    }
    0xb020 => {
      // CreativeStyle — string passthrough.
      if let RawValue::Text { text: s, .. } = raw {
        typed.creative_style = Some(s.as_str().into());
      } else if let TagValue::Str(s) = val {
        typed.creative_style = Some(s.clone());
      }
    }
    0xb023 => {
      typed.scene_mode = first_u32(raw);
    }
    0xb025 => {
      typed.dynamic_range_optimizer = first_u32(raw);
    }
    0xb026 => {
      typed.image_stabilization = first_u32(raw);
    }
    0xb027 => {
      if let Some(n) = first_u32(raw) {
        typed.lens_type = Some(n);
        // 0xb027 uses the A-mount `%sonyLensTypes` (`Sony.pm:2370`), NOT the
        // E-mount `%sonyLensTypes2` — 65535 ⇒ the E-mount sentinel name.
        typed.lens_name = amount_lens_types::lookup_name(n);
      }
    }
    0xb041 => {
      typed.exposure_mode = first_u32(raw);
    }
    0xb054 => {
      typed.white_balance_2 = first_u32(raw);
    }
    _ => {}
  }
}

fn first_u32(raw: &RawValue) -> Option<u32> {
  match raw {
    RawValue::U64(v) => v.first().copied().and_then(|n| u32::try_from(n).ok()),
    RawValue::I64(v) => v
      .first()
      .copied()
      .and_then(|n| if n >= 0 { u32::try_from(n).ok() } else { None }),
    _ => None,
  }
}

/// `%releaseMode2` PrintConv hash (`Sony.pm:6195-6226`) — shared by the
/// `Tag9050x`/`Tag9400x`/`Tag2010x` `ReleaseMode2` rows. `None` for an
/// unmapped value (ExifTool then prints the raw integer).
#[must_use]
pub(crate) fn release_mode2_print(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Continuous",
    2 => "Continuous - Exposure Bracketing",
    3 => "DRO or White Balance Bracketing",
    5 => "Continuous - Burst",
    6 => "Single Frame - Capture During Movie",
    7 => "Continuous - Sweep Panorama",
    8 => "Continuous - Anti-Motion Blur, Hand-held Twilight",
    9 => "Continuous - HDR",
    10 => "Continuous - Background defocus",
    13 => "Continuous - 3D Sweep Panorama",
    15 => "Continuous - High Resolution Sweep Panorama",
    16 => "Continuous - 3D Image",
    17 => "Continuous - Burst 2",
    18 => "Normal - iAuto+",
    19 => "Continuous - Speed/Advance Priority",
    20 => "Continuous - Multi Frame NR",
    23 => "Single-frame - Exposure Bracketing",
    26 => "Continuous Low",
    27 => "Continuous - High Sensitivity",
    28 => "Smile Shutter",
    29 => "Continuous - Tele-zoom Advance Priority",
    146 => "Single Frame - Movie Capture",
    _ => return None,
  })
}

/// 0x201c's `AFAreaILCE`/`AFAreaILCA` DataMember side-effect
/// (`Sony.pm:1278-1279,1295-1296`): the `RawConv => '$$self{AFAreaILCx} = $val'`
/// runs only on the NEX/ILCE (branch 2) or ILCA (branch 3) `Condition`, storing
/// 0x201c's raw `$val`. Takes the [`RawValue`] + the body `$$self{Model}`
/// directly so the shared-`Walker` Sony capture
/// (`exif::mod::sony_makernote_isolated`) can thread the same in-IFD side-effect
/// 0x201e reads (#243 phase 3). Returns `Some(raw)` when this body sets it, else
/// `None` (SLT/HV branch 1, or no branch — neither sets a DataMember).
#[must_use]
pub(crate) fn af_area_data_member_from_raw(raw: &RawValue, model: Option<&str>) -> Option<i64> {
  if SonyPrintConv::af_area_sets_data_member(model) {
    first_i64(raw)
  } else {
    None
  }
}

fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;
  use crate::exif::makernotes::vendors::VendorEmission;
  use crate::value::{Group, Metadata};
  use std::vec::Vec;

  // The per-vendor oracle entry points (`sony::parse` / `parse_in_tiff` /
  // `parse_into_metadata`) were retired in #243 phase 5; the production decode now
  // runs through the shared-`Walker` isolated helper
  // `crate::exif::sony_makernote_isolated` (proven byte-identical by the
  // conformance suite + the deleted differential tests). These thin shims preserve
  // the old signatures so the per-entry-gate decode tests below exercise the SAME
  // tables/convs/gates through the surviving path. The isolated helper gates on
  // `routes_to_main`, which the un-gated oracle did not; every parse test below
  // uses a `%Sony::Main` body (`SONY DSC` header or a headerless Sony5 shape), so
  // the shims pass `make = Some("SONY")` — the Sony5 make-gate (and a no-op for the
  // prefixed variants) — to route them exactly as the oracle decoded. (Routes-AWAY
  // bodies are covered by the surviving `routes_to_main` unit tests above.)
  fn parse(
    blob: &[u8],
    body_offset: usize,
    order: ByteOrder,
  ) -> (MakerNotesSony, Vec<VendorEmission>) {
    parse_in_tiff(blob, 0, blob.len(), body_offset, order, true, None)
  }

  fn parse_in_tiff(
    blob: &[u8],
    mn_offset: usize,
    mn_len: usize,
    body_offset: usize,
    order: ByteOrder,
    print_conv: bool,
    model: Option<&str>,
  ) -> (MakerNotesSony, Vec<VendorEmission>) {
    // `build_blob` always materializes the 12-byte `SONY DSC` prefix, so the IFD
    // is at the fixed body offset 12 (the `MakerNoteSony` Start) regardless of the
    // caller's `body_offset` argument (the retired headerless oracle path took 0).
    debug_assert!(
      body_offset == 0 || body_offset == 12,
      "sony test bodies use the headerless(0)/SONY-DSC(12) offsets"
    );
    match crate::exif::sony_makernote_isolated(
      blob,
      mn_offset,
      mn_len,
      12,
      order,
      Some("SONY"),
      model,
      None,
      print_conv,
    ) {
      Some((emissions, typed)) => (typed, emissions),
      None => (MakerNotesSony::new(), Vec::new()),
    }
  }

  fn parse_into_metadata(
    blob: &[u8],
    body_offset: usize,
    order: ByteOrder,
    print_conv: bool,
    model: Option<&str>,
    into: &mut Metadata,
  ) {
    use crate::exif::makernotes::Vendor;
    let g1 = Vendor::Sony.group1();
    let group = Group::new(g1, g1);
    let (_typed, emissions) =
      parse_in_tiff(blob, 0, blob.len(), body_offset, order, print_conv, model);
    for e in emissions {
      if e.unknown() {
        continue;
      }
      into.push(group.clone(), e.name(), e.value().clone());
    }
  }

  /// Build a synthetic Sony blob: optional header + N entries.
  ///
  /// An EMPTY `header` is materialized as the 12-byte `SONY DSC \0\0\0`
  /// `MakerNoteSony` prefix so the body unambiguously routes to `%Sony::Main`
  /// through the gated `sony_makernote_isolated` (the retired oracle decoded
  /// headerless bodies un-gated, but a bare IFD whose count word is `\x01\x00`
  /// collides with the SonySRF signature and a make-less body fails the Sony5
  /// make-gate). Every parse shim below therefore walks the body at the fixed
  /// `SONY DSC` offset 12; `build_blob` computes out-of-line offsets against the
  /// full (prefixed) buffer, so the leaf decode is unchanged.
  fn build_blob(header: &[u8], entries: &[(u16, u16, u32, Vec<u8>)]) -> Vec<u8> {
    let header: &[u8] = if header.is_empty() {
      b"SONY DSC \x00\x00\x00"
    } else {
      header
    };
    let mut blob = Vec::new();
    blob.extend_from_slice(header);
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let entries_start = blob.len();
    let dir_size = 12 * entries.len();
    let mut data_off = entries_start + dir_size;
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    for (tag, format, count, value) in entries {
      let elem_size = elem_sizes[*format as usize];
      let total = elem_size * (*count as usize);
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if total <= 4 {
        let mut padded = [0u8; 4];
        padded[..value.len().min(4)].copy_from_slice(&value[..value.len().min(4)]);
        blob.extend_from_slice(&padded);
      } else {
        blob.extend_from_slice(&(data_off as u32).to_le_bytes());
        data_off += total;
        pending.push(value.clone());
      }
    }
    for v in pending {
      blob.extend_from_slice(&v);
    }
    blob
  }

  /// `routes_to_main` admits ONLY the two `%Sony::Main` variants
  /// (`MakerNoteSony` prefixes + `MakerNoteSony5`) and rejects every
  /// non-Main variant (Sony2/3 → Olympus, Sony4 → PIC, Ericsson, SRF), in the
  /// EXACT `%Main` order the dispatcher uses — Sony5 (`:1070`) BEFORE
  /// SonyEricsson (`:1083`), so a `SEMC MS\0` blob with an uppercase `SONY` Make
  /// is claimed by Sony5 → Main, not dropped to Ericsson.
  #[test]
  fn routes_to_main_gates_non_main_variants() {
    // MakerNoteSony prefixes → Main (signature-only).
    assert!(routes_to_main(b"SONY DSC \x00\x00\x00", None, None));
    assert!(routes_to_main(b"SONY CAM \x00\x00\x00", None, None));
    assert!(routes_to_main(b"SONY MOBILE\x00", None, None));
    assert!(routes_to_main(b"VHAB     \x00rest", None, None));
    // TF1 `\0\0SONY PIC\0` → Main.
    assert!(routes_to_main(b"\x00\x00SONY PIC\x00rest", None, None));

    // MakerNoteSony5 — make-gated headerless, blob not `\x01\x00`.
    assert!(routes_to_main(&[0x12, 0x34, 0x56], Some("SONY"), None));
    // Hasselblad rebadge (HV/Stellar/Lusso/Lunar).
    assert!(routes_to_main(
      &[0x12, 0x34],
      Some("HASSELBLAD"),
      Some("Stellar")
    ));

    // NON-Main variants — must be rejected.
    assert!(!routes_to_main(b"SONY PI\x00rest", Some("SONY"), None)); // Sony2 → Olympus
    assert!(!routes_to_main(b"PREMI\x00rest", Some("SONY"), None)); // Sony3 → Olympus
    assert!(!routes_to_main(b"SONY PIC\x00rest", Some("SONY"), None)); // Sony4 → Sony::PIC
    assert!(!routes_to_main(
      b"SEMC MS\x00rest",
      Some("Sony Ericsson"),
      None
    )); // Ericsson (Make not `^SONY` ⇒ Sony5 does NOT claim it)
    assert!(!routes_to_main(&[0x01, 0x00, 0x09], Some("SONY"), None)); // SonySRF (\x01\x00)

    // %Main ORDER: MakerNoteSony5 (`:1070`) is tested BEFORE
    // MakerNoteSonyEricsson (`:1083`), so a `SEMC MS\0` blob whose parent Make
    // matches `/^SONY/` (uppercase) is claimed by Sony5 → `%Sony::Main` (ExifTool
    // decodes it through Main, even into bogus tags), NOT rejected to Ericsson.
    // This mirrors the dispatcher's own `%Main`-order classification
    // (`dispatcher.rs` Sony5 precedes SonyEricsson) so the two cannot drift.
    assert!(routes_to_main(b"SEMC MS\x00rest", Some("SONY"), None));
    // The `\x01\x00` SonySRF lookahead still excludes a `\x01\x00` body from
    // Sony5 even with an uppercase `SONY` Make ⇒ NOT Main (→ SonySRF).
    assert!(!routes_to_main(b"\x01\x00SEMC", Some("SONY"), None));
    // A non-SONY make with no signature is not Main (would be Unknown).
    assert!(!routes_to_main(&[0x12, 0x34], Some("Canon"), None));
    assert!(!routes_to_main(&[0x12, 0x34], None, None));
    // Hasselblad WITHOUT a rebadge model is not Sony5.
    assert!(!routes_to_main(
      &[0x12, 0x34],
      Some("HASSELBLAD"),
      Some("H6D")
    ));
  }

  #[test]
  fn parse_quality_inline_headerless() {
    // Quality (0x0102) int32u count 1 value 2 ⇒ "Fine"
    let blob = build_blob(&[], &[(0x0102, 0x04, 1, std::vec![0x02, 0, 0, 0])]);
    let (typed, emissions) = parse(&blob, 0, ByteOrder::Little);
    assert_eq!(typed.quality(), Some(2));
    assert_eq!(emissions[0].name(), "Quality");
    assert_eq!(emissions[0].value(), &TagValue::Str("Fine".into()));
  }

  #[test]
  fn parse_quality_with_dsc_header() {
    // 12-byte "SONY DSC \0\0\0" header + Quality (0x0102) value 0 ⇒ "RAW"
    let blob = build_blob(
      b"SONY DSC \x00\x00\x00",
      &[(0x0102, 0x04, 1, std::vec![0x00, 0, 0, 0])],
    );
    let (typed, emissions) = parse(&blob, 12, ByteOrder::Little);
    assert_eq!(typed.quality(), Some(0));
    assert_eq!(emissions[0].value(), &TagValue::Str("RAW".into()));
  }

  #[test]
  fn parse_sony_model_id_resolves_name() {
    // SonyModelID (0xb001) = 358 ⇒ "ILCE-9"
    let blob = build_blob(&[], &[(0xb001, 0x03, 1, std::vec![0x66, 0x01, 0, 0])]);
    let (typed, emissions) = parse(&blob, 0, ByteOrder::Little);
    assert_eq!(typed.model_id(), Some(358));
    assert_eq!(typed.model_name(), Some("ILCE-9"));
    assert_eq!(emissions[0].value(), &TagValue::Str("ILCE-9".into()));
  }

  #[test]
  fn parse_sony_lens_type_resolves_name() {
    // LensType (0xb027) resolves against the A-mount `%sonyLensTypes`
    // (`Sony.pm:2370`). int32u 65535 (0xFFFF) is the E-mount sentinel ⇒
    // "E-Mount, T-Mount, Other Lens or no lens" (`Minolta.pm:545`) — the
    // value written here for every E-mount lens (`Sony.pm:2368`).
    let blob = build_blob(&[], &[(0xb027, 0x03, 1, std::vec![0xFF, 0xFF, 0, 0])]);
    let (typed, emissions) = parse(&blob, 0, ByteOrder::Little);
    assert_eq!(typed.lens_type(), Some(65535));
    assert_eq!(
      typed.lens_name(),
      Some("E-Mount, T-Mount, Other Lens or no lens")
    );
    assert_eq!(
      emissions[0].value(),
      &TagValue::Str("E-Mount, T-Mount, Other Lens or no lens".into())
    );

    // A real A-mount (Minolta-derived) ID resolves to its A-mount name, NOT
    // the E-mount `%sonyLensTypes2` entry for the same numeric key.
    let blob0 = build_blob(&[], &[(0xb027, 0x03, 1, std::vec![0, 0, 0, 0])]);
    let (typed0, _) = parse(&blob0, 0, ByteOrder::Little);
    assert_eq!(typed0.lens_type(), Some(0));
    assert_eq!(typed0.lens_name(), Some("Minolta AF 28-85mm F3.5-4.5 New"));
  }

  #[test]
  fn parse_picture_effect_pop_color() {
    // PictureEffect (0x200e) = 2 ⇒ "Pop Color"
    let blob = build_blob(&[], &[(0x200e, 0x03, 1, std::vec![0x02, 0, 0, 0])]);
    let (typed, emissions) = parse(&blob, 0, ByteOrder::Little);
    assert_eq!(typed.picture_effect(), Some(2));
    assert_eq!(emissions[0].value(), &TagValue::Str("Pop Color".into()));
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], 0, ByteOrder::Little);
    assert_eq!(typed, MakerNotesSony::new());
    assert!(emissions.is_empty());
  }

  /// `parse_into_metadata` must push under the Sony MakerNote group
  /// (`Vendor::Sony.group1()` = `"Sony"`, both family-0 and family-1), NOT
  /// the literal `("MakerNotes","MakerNotes")` — `exiftool -j -G1` emits
  /// `Sony:Quality` on a Sony body. Regression guard for Finding 3.
  #[test]
  fn parse_into_metadata_uses_sony_group_no_makernotes_leak() {
    let blob = build_blob(&[], &[(0x0102, 0x04, 1, std::vec![0x02, 0, 0, 0])]);
    let mut md = Metadata::new("test.arw");
    parse_into_metadata(&blob, 0, ByteOrder::Little, true, None, &mut md);
    let tags = md.tags_slice();
    assert!(!tags.is_empty(), "expected at least the Quality tag");
    for t in tags {
      assert_eq!(
        t.group_ref().family1(),
        "Sony",
        "tag {:?} leaked group {:?} instead of Sony",
        t.name(),
        t.group_ref().family1()
      );
      assert_eq!(t.group_ref().family0(), "Sony");
      assert_ne!(
        t.group_ref().family1(),
        "MakerNotes",
        "MakerNotes: leak for {:?}",
        t.name()
      );
    }
    let q = tags
      .iter()
      .find(|t| t.name() == "Quality")
      .expect("Quality");
    assert_eq!(q.value_ref(), &TagValue::Str("Fine".into()));
  }

  /// `parse_into_metadata` suppresses `Unknown => 1` tags (the
  /// `%unknownCipherData` rows, `Sony.pm:675-681`) from the default sink,
  /// matching `run_emission` / `ExifTool.pm:9179-9185`. 0x9407 is a
  /// single-HASH cipher row (`Unknown => 1`); it must NOT appear, while a
  /// sibling non-Unknown leaf does.
  #[test]
  fn parse_into_metadata_suppresses_unknown_cipher_rows() {
    // 0x9407 Sony_0x9407 (Unknown=1) alongside 0x0102 Quality (not Unknown).
    let blob = build_blob(
      &[],
      &[
        (0x0102, 0x04, 1, std::vec![0x02, 0, 0, 0]),
        (0x9407, 0x07, 4, std::vec![0x00, 0x00, 0x00, 0x00]),
      ],
    );
    let mut md = Metadata::new("test.arw");
    parse_into_metadata(&blob, 0, ByteOrder::Little, true, None, &mut md);
    let names: Vec<&str> = md.tags_slice().iter().map(|t| t.name()).collect();
    assert!(names.contains(&"Quality"), "Quality should be present");
    assert!(
      !names.iter().any(|n| n.starts_with("Sony_0x9407")),
      "Unknown cipher row 0x9407 must be suppressed, got {names:?}"
    );
  }

  /// SubDirectory rows are DESCENDED-INTO, never emitted as a parent value. A
  /// `%Sony::Main` body carrying 0x0010 CameraInfo (`Sony.pm:716-747`,
  /// SubDirectory → `Sony::CameraInfo`*) must emit NO `CameraInfo` raw key —
  /// ExifTool's `if ($subdir)` block descends + `next`s before `FoundTag`
  /// (`Exif.pm:6919,7103-7104,7180`), and Phase 3 defers the child walk.
  /// 0x0010 is an `unknown=false` SubDirectory row, so prior to the fix it
  /// would have LEAKED a bogus `Sony:CameraInfo` value. A sibling leaf (0x0102
  /// Quality) IS still emitted, proving targeted suppression.
  #[test]
  fn subdir_camerainfo_not_emitted() {
    // Entries MUST be tag-id sorted: 0x0010, 0x0102. Headerless Sony5 body.
    let blob = build_blob(
      &[],
      &[
        (0x0010, 0x07, 4, std::vec![0x01, 0x02, 0x03, 0x04]), // CameraInfo undef[4]
        (0x0102, 0x04, 1, std::vec![0x02, 0, 0, 0]),          // Quality int32u = 2 ("Fine")
      ],
    );
    for print_conv in [true, false] {
      let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, print_conv, None);
      assert_eq!(
        emit_value(&em, "CameraInfo"),
        None,
        "Sony:CameraInfo (0x0010 SubDirectory) must NOT be emitted \
         (print_conv={print_conv})"
      );
      // The sibling leaf is retained (value form differs by mode: "Fine" in
      // print-conv, raw 2 in value-conv — only presence matters here).
      assert!(
        emit_value(&em, "Quality").is_some(),
        "sibling leaf Quality must still be emitted (print_conv={print_conv})"
      );
    }
    // In print-conv mode the leaf renders via PrintConv (`Sony.pm:770-786`).
    let (_tp, emp) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&emp, "Quality"),
      Some(TagValue::Str("Fine".into()))
    );

    // Also assert through the Metadata sink: no `Sony:CameraInfo` key.
    let mut md = Metadata::new("test.arw");
    parse_into_metadata(&blob, 0, ByteOrder::Little, true, None, &mut md);
    let names: Vec<&str> = md.tags_slice().iter().map(|t| t.name()).collect();
    assert!(
      !names.contains(&"CameraInfo"),
      "no SubDirectory parent may reach the Metadata sink, got {names:?}"
    );
    assert!(
      names.contains(&"Quality"),
      "Quality must reach the sink, got {names:?}"
    );
  }

  /// Find an emission by name.
  fn emit_value(em: &[VendorEmission], name: &str) -> Option<TagValue> {
    em.iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().clone())
  }

  /// End-to-end DataMember threading (`Sony.pm:1278-1279,1326-1330`): 0x201c
  /// sets `AFAreaILCE = $val` (RawConv side-effect on the NEX/ILCE branch),
  /// and 0x201e's branch-1 Condition reads it (`... and $$self{AFAreaILCE}
  /// == 4`). On an ILCE body with 0x201c == 4, 0x201e renders via branch 1
  /// (the directional hash → 5="Lower-right"); with 0x201c != 4 it falls to
  /// branch 5 (NEX/ILCE Zone → 5="Bottom Zone"). The walk sees 0x201c before
  /// 0x201e (IFD tag-id order), so the DataMember is set in time. Oracle
  /// labels from the bundled ExifTool dispatch.
  #[test]
  fn af_point_selected_reads_0x201c_data_member() {
    // 0x201c = 4 (AFAreaILCE=4 ⇒ "Flexible Spot (LA-EA4)"), 0x201e = 5.
    let blob_ea4 = build_blob(
      &[],
      &[
        (0x201c, 0x01, 1, std::vec![0x04, 0, 0, 0]),
        (0x201e, 0x01, 1, std::vec![0x05, 0, 0, 0]),
      ],
    );
    let (_t, em) = parse_in_tiff(
      &blob_ea4,
      0,
      blob_ea4.len(),
      0,
      ByteOrder::Little,
      true,
      Some("ILCE-7RM2"),
    );
    assert_eq!(
      emit_value(&em, "AFAreaModeSetting"),
      Some(TagValue::Str("Flexible Spot (LA-EA4)".into()))
    );
    // 0x201e branch 1 (ILCE + AFAreaILCE==4): 5 → "Lower-right".
    assert_eq!(
      emit_value(&em, "AFPointSelected"),
      Some(TagValue::Str("Lower-right".into()))
    );

    // 0x201c = 3 (AFAreaILCE=3 ≠ 4) ⇒ 0x201e falls to branch 5 (Zone).
    let blob_zone = build_blob(
      &[],
      &[
        (0x201c, 0x01, 1, std::vec![0x03, 0, 0, 0]),
        (0x201e, 0x01, 1, std::vec![0x05, 0, 0, 0]),
      ],
    );
    let (_t2, em2) = parse_in_tiff(
      &blob_zone,
      0,
      blob_zone.len(),
      0,
      ByteOrder::Little,
      true,
      Some("ILCE-7RM2"),
    );
    assert_eq!(
      emit_value(&em2, "AFAreaModeSetting"),
      Some(TagValue::Str("Flexible Spot".into()))
    );
    assert_eq!(
      emit_value(&em2, "AFPointSelected"),
      Some(TagValue::Str("Bottom Zone".into())),
      "AFAreaILCE != 4 ⇒ 0x201e branch 5 (Zone)"
    );
  }

  /// 0x2020 AFPointsUsed BITMASK threaded through the full parse path on an
  /// SLT body (branch 1): int8u[10] with bit0 set in word0 → "Center"
  /// (`Sony.pm:1428-1456`); on a DSC body NO `Condition` branch matches, so
  /// ExifTool's `GetTagInfo` finds no tag info and the entry is ABSENT from
  /// the output — the emission must be SUPPRESSED, not rendered raw.
  #[test]
  fn af_points_used_threaded_through_parse() {
    // int8u count 10, word0 = 1 (bit0) → "Center".
    let mut val = std::vec![0u8; 10];
    val[0] = 1;
    let blob = build_blob(&[], &[(0x2020, 0x01, 10, val.clone())]);
    let (_t, em) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      0,
      ByteOrder::Little,
      true,
      Some("SLT-A99V"),
    );
    assert_eq!(
      emit_value(&em, "AFPointsUsed"),
      Some(TagValue::Str("Center".into()))
    );
    // NEGATIVE oracle — DSC body matches no branch ⇒ the tag is SUPPRESSED
    // (absent from the emissions), NOT emitted as a raw space-joined list.
    let (_t2, em2) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      0,
      ByteOrder::Little,
      true,
      Some("DSC-RX100"),
    );
    assert_eq!(
      emit_value(&em2, "AFPointsUsed"),
      None,
      "DSC-RX100 matches no 0x2020 branch ⇒ tag must be absent (not raw)"
    );
  }

  /// End-to-end suppression for all four conditional-ARRAY AF tags
  /// (`Sony.pm:1256-1306,1321-1421,1426-1468,1487-1507`): on a body matching
  /// NONE of a tag's `Condition` branches, the entry is ABSENT from output
  /// (matching ExifTool's `GetTagInfo`-returns-nothing) rather than emitted
  /// raw. Negative-oracle models verified against the bundled 13.59 dispatch.
  #[test]
  fn conditional_af_tags_suppressed_on_no_branch_match() {
    // 0x201c on DSC-RX100 (old DSC, not in the new-DSC list) → no branch.
    // 0x201e on the same body would match branch 5 (DSC-RX), so use the
    // standalone single-tag blobs per the verified per-tag oracle.
    let one = |tag: u16| build_blob(&[], &[(tag, 0x01, 1, std::vec![0x05, 0, 0, 0])]);

    // 0x201c — DSC-RX100 matches no branch ⇒ absent.
    let (_t, em) = parse_in_tiff(
      &one(0x201c),
      0,
      one(0x201c).len(),
      0,
      ByteOrder::Little,
      true,
      Some("DSC-RX100"),
    );
    assert_eq!(
      emit_value(&em, "AFAreaModeSetting"),
      None,
      "0x201c DSC-RX100 ⇒ suppressed"
    );

    // 0x201e — ILCE-9 with NO AFAreaILCE set (single tag, 0x201c absent) ⇒
    // branch 1 needs AFAreaILCE==4 (undef), branch 5 needs NEX/.../DSC-RX
    // (ILCE-9 IS in branch 5's NEX/ILCE set) → matches branch 5. So instead
    // verify the genuine 0x201e miss: an ILCA body without AFAreaILCA set.
    let (_t2, em2) = parse_in_tiff(
      &one(0x201e),
      0,
      one(0x201e).len(),
      0,
      ByteOrder::Little,
      true,
      Some("ILCA-77M2"),
    );
    assert_eq!(
      emit_value(&em2, "AFPointSelected"),
      None,
      "0x201e ILCA-77M2 without AFAreaILCA DataMember ⇒ suppressed"
    );

    // 0x2020 — a ZV body matches no branch ⇒ absent.
    let mut bits = std::vec![0u8; 10];
    bits[0] = 1;
    let blob2020 = build_blob(&[], &[(0x2020, 0x01, 10, bits)]);
    let (_t3, em3) = parse_in_tiff(
      &blob2020,
      0,
      blob2020.len(),
      0,
      ByteOrder::Little,
      true,
      Some("ZV-1"),
    );
    assert_eq!(
      emit_value(&em3, "AFPointsUsed"),
      None,
      "0x2020 ZV-1 ⇒ suppressed"
    );

    // 0x2022 — ILCE-9 writes neither variant ⇒ absent.
    let (_t4, em4) = parse_in_tiff(
      &one(0x2022),
      0,
      one(0x2022).len(),
      0,
      ByteOrder::Little,
      true,
      Some("ILCE-9"),
    );
    assert_eq!(
      emit_value(&em4, "FocalPlaneAFPointsUsed"),
      None,
      "0x2022 ILCE-9 ⇒ suppressed"
    );

    // POSITIVE control — a matching body still emits the tag.
    let (_t5, em5) = parse_in_tiff(
      &one(0x2022),
      0,
      one(0x2022).len(),
      0,
      ByteOrder::Little,
      true,
      Some("ILCE-7RM2"),
    );
    assert_eq!(
      emit_value(&em5, "FocalPlaneAFPointsUsed"),
      Some(TagValue::Str("[0], [2]".into())),
      "0x2022 ILCE-7RM2 (value 5) ⇒ bits [0],[2]"
    );
  }

  /// Single-HASH model-`Condition` suppression for 0x201b FocusMode
  /// (`Sony.pm:1244`): `($$self{Model} !~ /^DSC-/) or ($$self{Model} =~
  /// /^DSC-(RX10M4|RX100M6|RX100M7|RX100M5A|HX95|HX99|RX0M2|RX1RM3)/)`. On an
  /// old DSC body (DSC-RX100) ExifTool's `GetTagInfo` finds no tag info ⇒ the
  /// tag is ABSENT; on a supported body it emits the FocusMode2 label.
  /// Negative/positive models + the rendered label verified against bundled
  /// 13.59 `GetTagInfo`.
  #[test]
  fn focus_mode_0x201b_model_suppression() {
    // int8u value 3 (→ "AF-C" via FocusMode2).
    let blob = build_blob(&[], &[(0x201b, 0x01, 1, std::vec![0x03, 0, 0, 0])]);
    let neg = |model: &str| {
      let (_t, em) = parse_in_tiff(
        &blob,
        0,
        blob.len(),
        0,
        ByteOrder::Little,
        true,
        Some(model),
      );
      emit_value(&em, "FocusMode")
    };
    // NEGATIVE — old DSC: suppressed.
    assert_eq!(neg("DSC-RX100"), None, "0x201b DSC-RX100 ⇒ suppressed");
    // POSITIVE — new-DSC and ILCE bodies emit.
    assert_eq!(
      neg("DSC-RX100M6"),
      Some(TagValue::Str("AF-C".into())),
      "0x201b DSC-RX100M6 (new-DSC) ⇒ present"
    );
    assert_eq!(
      neg("ILCE-7RM2"),
      Some(TagValue::Str("AF-C".into())),
      "0x201b ILCE-7RM2 ⇒ present"
    );
  }

  /// 0x201d FlexibleSpotPosition (`Sony.pm:1313`): `$$self{Model} =~
  /// /^(NEX-|ILCE-|ILME-|ZV-|DSC-(RX10M4|…|RX1RM3))/`. No PrintConv (int16u[2]
  /// rendered raw as "X Y"). NEGATIVE on SLT/ILCA/old-DSC; POSITIVE on
  /// NEX/ILCE/new-DSC. Verified against bundled `GetTagInfo`.
  #[test]
  fn flexible_spot_position_0x201d_model_suppression() {
    // int16u[2] = (320, 240) ⇒ raw "320 240".
    let blob = build_blob(
      &[],
      &[(
        0x201d,
        0x03,
        2,
        std::vec![0x40, 0x01, 0xF0, 0x00], // 320, 240 little-endian
      )],
    );
    let go = |model: &str| {
      let (_t, em) = parse_in_tiff(
        &blob,
        0,
        blob.len(),
        0,
        ByteOrder::Little,
        true,
        Some(model),
      );
      emit_value(&em, "FlexibleSpotPosition")
    };
    // NEGATIVE — SLT/ILCA/old-DSC: suppressed.
    assert_eq!(go("SLT-A99V"), None, "0x201d SLT-A99V ⇒ suppressed");
    assert_eq!(go("ILCA-77M2"), None, "0x201d ILCA-77M2 ⇒ suppressed");
    assert_eq!(go("DSC-RX100"), None, "0x201d old DSC ⇒ suppressed");
    // POSITIVE — NEX/ILCE/new-DSC: present, raw "320 240".
    assert_eq!(
      go("ILCE-7RM2"),
      Some(TagValue::Str("320 240".into())),
      "0x201d ILCE-7RM2 ⇒ present (raw int16u pair)"
    );
    assert_eq!(
      go("DSC-RX100M6"),
      Some(TagValue::Str("320 240".into())),
      "0x201d DSC-RX100M6 (new-DSC) ⇒ present"
    );
  }

  /// 0x2021 AFTracking (`Sony.pm:1473`): same Condition as 0x201b. NEGATIVE on
  /// old DSC; POSITIVE on SLT/ILCE (label via AfTracking). Verified vs bundled.
  #[test]
  fn af_tracking_0x2021_model_suppression() {
    // int8u value 1 (→ "Face tracking").
    let blob = build_blob(&[], &[(0x2021, 0x01, 1, std::vec![0x01, 0, 0, 0])]);
    let go = |model: &str| {
      let (_t, em) = parse_in_tiff(
        &blob,
        0,
        blob.len(),
        0,
        ByteOrder::Little,
        true,
        Some(model),
      );
      emit_value(&em, "AFTracking")
    };
    assert_eq!(go("DSC-RX100"), None, "0x2021 DSC-RX100 ⇒ suppressed");
    assert_eq!(
      go("SLT-A99V"),
      Some(TagValue::Str("Face tracking".into())),
      "0x2021 SLT-A99V ⇒ present"
    );
    assert_eq!(
      go("DSC-HX99"),
      Some(TagValue::Str("Face tracking".into())),
      "0x2021 DSC-HX99 (new-DSC) ⇒ present"
    );
  }

  /// 0x205c StepCropShooting (`Sony.pm:1761`): `$$self{Model} =~
  /// /^(DSC-RX1RM3)\b/`. ONLY DSC-RX1RM3 emits; everything else (incl. other
  /// new-DSC bodies and ILCE) is suppressed. Verified vs bundled `GetTagInfo`.
  #[test]
  fn step_crop_shooting_0x205c_model_suppression() {
    // int8u value 1 (→ "50mm").
    let blob = build_blob(&[], &[(0x205c, 0x01, 1, std::vec![0x01, 0, 0, 0])]);
    let go = |model: &str| {
      let (_t, em) = parse_in_tiff(
        &blob,
        0,
        blob.len(),
        0,
        ByteOrder::Little,
        true,
        Some(model),
      );
      emit_value(&em, "StepCropShooting")
    };
    assert_eq!(go("DSC-RX100M6"), None, "0x205c non-RX1RM3 ⇒ suppressed");
    assert_eq!(go("ILCE-7RM2"), None, "0x205c ILCE ⇒ suppressed");
    assert_eq!(
      go("DSC-RX1RM3"),
      Some(TagValue::Str("50mm".into())),
      "0x205c DSC-RX1RM3 ⇒ present"
    );
  }

  /// 0xb050 HighISONoiseReduction2 (`Sony.pm:2662`): `$$self{Model} =~
  /// /^(DSC-|Stellar)/`. POSITIVE on any DSC/Stellar; NEGATIVE on
  /// ILCE/SLT/ILCA/NEX/ZV. Verified vs bundled `GetTagInfo`.
  #[test]
  fn high_iso_nr2_0xb050_model_suppression() {
    // int16u value 0 (→ "Normal" via HighIsoNr2).
    let blob = build_blob(&[], &[(0xb050, 0x03, 1, std::vec![0x00, 0x00, 0, 0])]);
    let go = |model: &str| {
      let (_t, em) = parse_in_tiff(
        &blob,
        0,
        blob.len(),
        0,
        ByteOrder::Little,
        true,
        Some(model),
      );
      emit_value(&em, "HighISONoiseReduction2")
    };
    // NEGATIVE — ILCE/SLT: suppressed.
    assert_eq!(go("ILCE-7RM2"), None, "0xb050 ILCE-7RM2 ⇒ suppressed");
    assert_eq!(go("SLT-A99V"), None, "0xb050 SLT-A99V ⇒ suppressed");
    // POSITIVE — DSC (incl. old DSC-RX100) + Stellar: present.
    assert_eq!(
      go("DSC-RX100"),
      Some(TagValue::Str("Normal".into())),
      "0xb050 DSC-RX100 ⇒ present"
    );
    assert_eq!(
      go("Stellar"),
      Some(TagValue::Str("Normal".into())),
      "0xb050 Stellar ⇒ present"
    );
  }

  /// `$format`-gated MultiBurst rows (`Sony.pm:882,890,895`): 0x1000
  /// MultiBurstMode needs `$format eq "undef"`; 0x1001 MultiBurstImageWidth /
  /// 0x1002 MultiBurstImageHeight need `$format eq "int16u"`. On a body that
  /// re-uses the id with a different on-disk format ExifTool's `GetTagInfo`
  /// returns nothing ⇒ ABSENT. Verified vs bundled `GetTagInfo`.
  #[test]
  fn multi_burst_0x1000_0x1001_format_suppression() {
    // 0x1001 as int16u (format code 3) ⇒ present (raw 640); as int32u
    // (format code 4) ⇒ suppressed.
    let ok16 = build_blob(&[], &[(0x1001, 0x03, 1, std::vec![0x80, 0x02, 0, 0])]); // 640
    let (_t, em) = parse_in_tiff(&ok16, 0, ok16.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em, "MultiBurstImageWidth"),
      Some(TagValue::I64(640)),
      "0x1001 int16u ⇒ present"
    );
    let bad32 = build_blob(&[], &[(0x1001, 0x04, 1, std::vec![0x80, 0x02, 0, 0])]);
    let (_t2, em2) = parse_in_tiff(&bad32, 0, bad32.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em2, "MultiBurstImageWidth"),
      None,
      "0x1001 int32u ⇒ suppressed ($format ne int16u)"
    );
    // 0x1000 needs $format eq "undef"; an int32u entry ⇒ suppressed.
    let bad1000 = build_blob(&[], &[(0x1000, 0x04, 1, std::vec![0x01, 0, 0, 0])]);
    let (_t3, em3) = parse_in_tiff(&bad1000, 0, bad1000.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em3, "MultiBurstMode"),
      None,
      "0x1000 int32u ⇒ suppressed ($format ne undef)"
    );
  }

  /// RawConv undef-drop for the `$val == 65535 ? undef` rows
  /// (`Sony.pm:2427,2438,2478,2498,2535,2547,2585,2598,2609`). The int16u
  /// sentinel 65535 ⇒ the tag is ABSENT; a normal raw ⇒ present + converted.
  /// Verified against bundled: 0xb040 Macro 1 → "On", 0xb049 ReleaseMode 2 →
  /// "Continuous"; 65535 has a `65535 => 'n/a'` PrintConv key that the RawConv
  /// drop PRE-EMPTS (so the body never shows "n/a" — it shows nothing).
  #[test]
  fn rawconv_drop_65535_rows_suppressed() {
    let one = |tag: u16, v: u16| build_blob(&[], &[(tag, 0x03, 1, v.to_le_bytes().to_vec())]);
    let go = |tag: u16, v: u16, name: &str| {
      let blob = one(tag, v);
      let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
      emit_value(&em, name)
    };
    // NEGATIVE — the sentinel 65535 is dropped on every int16u row.
    for (tag, name) in [
      (0xb040u16, "Macro"),
      (0xb041, "ExposureMode"),
      (0xb042, "FocusMode"),
      (0xb043, "AFAreaMode"),
      (0xb044, "AFIlluminator"),
      (0xb047, "JPEGQuality"),
      (0xb049, "ReleaseMode"),
      (0xb04a, "SequenceNumber"),
      (0xb04b, "Anti-Blur"),
    ] {
      assert_eq!(
        go(tag, 65535, name),
        None,
        "0x{tag:x} raw 65535 ⇒ RawConv undef-drop ⇒ tag must be absent"
      );
    }
    // POSITIVE — a normal raw value is present and converted.
    assert_eq!(
      go(0xb040, 1, "Macro"),
      Some(TagValue::Str("On".into())),
      "0xb040 Macro 1 ⇒ present (\"On\")"
    );
    assert_eq!(
      go(0xb049, 2, "ReleaseMode"),
      Some(TagValue::Str("Continuous".into())),
      "0xb049 ReleaseMode 2 ⇒ present (\"Continuous\")"
    );
  }

  /// 0xb048 FlashLevel model-conditional drop (`Sony.pm:2559`): `($val == -1
  /// and $$self{Model} =~ /DSLR-A100\b/) ? undef : $val`. The int16s raw `-1`
  /// is DROPPED only on the DSLR-A100; on any other body it renders the
  /// `-1 => '-1/3'` PrintConv label. A non-sentinel raw is unaffected on
  /// either body. Verified against bundled `GetTagInfo`/RawConv + PrintConv.
  #[test]
  fn flash_level_0xb048_a100_conditional_drop() {
    // int16s -1 (0xffff LE).
    let neg1 = build_blob(&[], &[(0xb048, 0x08, 1, std::vec![0xFF, 0xFF, 0, 0])]);
    let go = |blob: &[u8], model: &str| {
      let (_t, em) = parse_in_tiff(blob, 0, blob.len(), 0, ByteOrder::Little, true, Some(model));
      emit_value(&em, "FlashLevel")
    };
    // NEGATIVE — DSLR-A100 drops raw -1 (the tag is absent).
    assert_eq!(
      go(&neg1, "DSLR-A100"),
      None,
      "0xb048 raw -1 on DSLR-A100 ⇒ RawConv undef-drop ⇒ absent"
    );
    // POSITIVE — a non-A100 body renders -1 via the PrintConv (`-1 => -1/3`).
    assert_eq!(
      go(&neg1, "DSLR-A700"),
      Some(TagValue::Str("-1/3".into())),
      "0xb048 raw -1 on non-A100 ⇒ present (\"-1/3\")"
    );
    // A100 with a non-sentinel raw is unaffected: 0 → "Normal".
    let zero = build_blob(&[], &[(0xb048, 0x08, 1, std::vec![0x00, 0x00, 0, 0])]);
    assert_eq!(
      go(&zero, "DSLR-A100"),
      Some(TagValue::Str("Normal".into())),
      "0xb048 raw 0 on DSLR-A100 ⇒ present (\"Normal\"; only -1 is dropped)"
    );
    // The `\b` boundary: a Model that merely CONTAINS "DSLR-A100" as a prefix
    // of a longer token does NOT match (so -1 is NOT dropped). ExifTool's
    // regex is unanchored with a trailing `\b`.
    let a100x = build_blob(&[], &[(0xb048, 0x08, 1, std::vec![0xFF, 0xFF, 0, 0])]);
    assert_eq!(
      go(&a100x, "DSLR-A100X"),
      Some(TagValue::Str("-1/3".into())),
      "0xb048 raw -1 on DSLR-A100X ⇒ present (\\b boundary fails the match)"
    );
  }

  // ===========================================================================
  // Parse-level Format-override oracle cases (Exif.pm:6735-6744). Each encodes
  // an entry with its ON-DISK format + bytes; the override re-interprets the
  // SAME bytes. Expected values verified against bundled 13.59 via
  // `Image::ExifTool::ReadValue` + the row's PrintConv (see commit notes).
  // ===========================================================================

  /// 0x200a HDR (`Sony.pm:1004-1031`) — `Format => 'int16u', Count => 2`,
  /// `Writable => 'int32u'`. On-disk int32u (4 bytes) `01 00 01 00` (LE) is
  /// re-read as two int16u ⇒ `[1, 1]` (verified: `ReadValue('int16u',2,…)` of
  /// `01000100` II = "1 1"). PrintConv positional [{A550},{A580}] (PrintHex):
  /// 0x01→"Auto", 1→"HDR image (good)", joined "; " ⇒ "Auto; HDR image
  /// (good)". Without the override the walker reads int32u ⇒ U64(65537) ⇒ the
  /// PrintConv mis-renders a single "Unknown (0x10001)".
  #[test]
  fn format_override_0x200a_hdr_int16u_pair() {
    // On-disk int32u (code 4) count 1, inline bytes 01 00 01 00.
    let blob = build_blob(&[], &[(0x200a, 0x04, 1, std::vec![0x01, 0x00, 0x01, 0x00])]);
    let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em, "HDR"),
      Some(TagValue::Str("Auto; HDR image (good)".into())),
      "0x200a int32u 01 00 01 00 ⇒ int16u[2] [1,1] ⇒ \"Auto; HDR image (good)\""
    );
    // `-n` shape: the two int16u joined with a space ("1 1").
    let (_t2, em2) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, false, None);
    assert_eq!(
      emit_value(&em2, "HDR"),
      Some(TagValue::Str("1 1".into())),
      "0x200a -n ⇒ int16u[2] raw \"1 1\""
    );
    // A second HDR pattern: 0x10 0x03 ⇒ position0 0x10 → "1.0 EV"; position1
    // 3 → "HDR image (fail 2)".
    let blob2 = build_blob(&[], &[(0x200a, 0x04, 1, std::vec![0x10, 0x00, 0x03, 0x00])]);
    let (_t3, em3) = parse_in_tiff(&blob2, 0, blob2.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em3, "HDR"),
      Some(TagValue::Str("1.0 EV; HDR image (fail 2)".into()))
    );
  }

  /// 0x0112 WhiteBalanceFineTune (`Sony.pm:798-802`) — `Format => 'int32s'`,
  /// `Writable => 'int32u'`. On-disk int32u `FF FF FF FF` is re-read as int32s
  /// ⇒ -1 (not 4294967295). No PrintConv ⇒ rendered as the signed int.
  #[test]
  fn format_override_0x0112_white_balance_fine_tune_int32s() {
    let blob = build_blob(&[], &[(0x0112, 0x04, 1, std::vec![0xFF, 0xFF, 0xFF, 0xFF])]);
    let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em, "WhiteBalanceFineTune"),
      Some(TagValue::I64(-1)),
      "0x0112 int32u FF*4 ⇒ int32s override ⇒ -1"
    );
  }

  /// 0xb022 ColorCompensationFilter (`Sony.pm:2310-2315`) — `Format =>
  /// 'int32s'`, `Writable => 'int32u'` ("written incorrectly as unsigned by
  /// Sony"). On-disk int32u `FB FF FF FF` (LE) ⇒ int32s -5 (negative = green).
  #[test]
  fn format_override_0xb022_color_compensation_filter_int32s() {
    let blob = build_blob(&[], &[(0xb022, 0x04, 1, std::vec![0xFB, 0xFF, 0xFF, 0xFF])]);
    let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em, "ColorCompensationFilter"),
      Some(TagValue::I64(-5)),
      "0xb022 int32u FB FF FF FF ⇒ int32s override ⇒ -5"
    );
    // A positive raw is unchanged by the signed re-interpretation.
    let blob2 = build_blob(&[], &[(0xb022, 0x04, 1, std::vec![0x05, 0x00, 0x00, 0x00])]);
    let (_t2, em2) = parse_in_tiff(&blob2, 0, blob2.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em2, "ColorCompensationFilter"),
      Some(TagValue::I64(5))
    );
  }

  /// 0x2037 FocusFrameSize (`Sony.pm:1717-1727`) — `Format => 'int16u', Count
  /// => '3'`. Three int16u, sprintf "%3dx%3d" unless the 3rd is 0 ("n/a").
  /// Encoded out-of-line as int16u[3] (on-disk already int16u ⇒ the override
  /// is a value-identical no-op; the row still carries it for the oracle).
  #[test]
  fn format_override_0x2037_focus_frame_size_int16u_triple() {
    // int16u count 3 = (640, 480, 257) ⇒ "640x480"; 6 bytes ⇒ out-of-line.
    let blob = build_blob(
      &[],
      &[(
        0x2037,
        0x03,
        3,
        std::vec![0x80, 0x02, 0xE0, 0x01, 0x01, 0x01],
      )],
    );
    let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    assert_eq!(
      emit_value(&em, "FocusFrameSize"),
      Some(TagValue::Str("640x480".into()))
    );
  }

  /// 0xb02a LensSpec (`Sony.pm:2391-2404`) — `Format => 'undef', Count => 8`,
  /// `Writable => 'int8u'`. The 8 value bytes are re-read as raw `undef`; the
  /// ConvLensSpec/PrintLensSpec chain decodes them. (On-disk int8u[8] decodes
  /// the same 8 bytes value-identically, so the override is faithful but not a
  /// value change — included in the oracle's handled set.) Bytes from the
  /// bundled `Sony.pm` PrintLensSpec example for "DT 18-55mm F3.5-5.6 SAM".
  #[test]
  fn format_override_0xb02a_lens_spec_undef8() {
    // Bytes 40 00 18 00 55 35 56 40 ⇒ ConvLensSpec "40 18 55 3.5 5.6 40" ⇒
    // PrintLensSpec "PZ 18-55mm F3.5-5.6 Reflex" (verified vs bundled). The
    // focal-length substring "18-55mm" is the stable assertion.
    let bytes = std::vec![0x40, 0x00, 0x18, 0x00, 0x55, 0x35, 0x56, 0x40];
    let blob = build_blob(&[], &[(0xb02a, 0x01, 8, bytes)]); // on-disk int8u[8]
    let (_t, em) = parse_in_tiff(&blob, 0, blob.len(), 0, ByteOrder::Little, true, None);
    let got = emit_value(&em, "LensSpec");
    assert!(
      matches!(&got, Some(TagValue::Str(s)) if s.contains("18-55mm")),
      "0xb02a LensSpec ⇒ a decoded lens-spec string, got {got:?}"
    );
  }
}
