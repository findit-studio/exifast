// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Pentax MakerNotes — Phase-1 port.
//!
//! Bundled source: `lib/Image/ExifTool/Pentax.pm` —
//! `%Image::ExifTool::Pentax::Main` (`Pentax.pm:859-3171`) plus
//! `%pentaxLensTypes` (`:75-422`), `%pentaxModelID` (`:425-540`) and
//! `%pentaxCities` (`:575-...`). The dispatcher (`MakerNotes.pm:762-803`)
//! collapses every Pentax variant (`AOC\0` primary, `PENTAX \0`, `S1…`,
//! the digit-prefixed Pentax4, the Asahi Pentax2/3) to
//! [`Vendor::Pentax`](crate::exif::makernotes::Vendor); the primary `AOC\0`
//! variant the K10D `Pentax.jpg` fixture uses walks `%Pentax::Main`.
//!
//! ## Phase 1 scope (camera-indexing leaves)
//!
//! - The Pentax body walk — runs through the shared `Walker` isolated helper
//!   [`crate::exif::pentax_makernote_isolated`]. The primary `AOC\0` variant is
//!   `body_offset 0`, `Base => Inherit`, `ByteOrder => Unknown` (probe) +
//!   `FixBase => 1` (`MakerNotes.pm:777`), processed via `ProcessUnknown`
//!   (`LocateIFD` then `ProcessExif`, `:1816`), so the isolated walker threads
//!   those modes from the dispatched [`DetectedMakerNote`].
//! - The faithful tag table ([`tags::PENTAX_TAGS`]) — the cleanly-portable
//!   plain LEAF tags (scalar / enum-hash / simple-ValueConv) the K10D fixture
//!   emits, plus the `0x003f LensRec` SubDirectory (the only sub-table needed
//!   for `LensType`).
//! - Per-tag PrintConv ([`printconv::PentaxPrintConv`]).
//! - [`lens_types`] (`%pentaxLensTypes`), [`model_ids`] (`%pentaxModelID`),
//!   [`cities`] (`%pentaxCities`).
//! - A typed [`MakerNotesPentax`] struct with D8 accessors over the parsed
//!   camera-identity fields (model id + name, lens type id + name, quality,
//!   white balance, ISO, image tone).
//!
//! ## Deferred (Phase 1+ follow-up — excluded from the conformance golden via
//! `-x`)
//!
//! The model-/`$count`-/`$format`-CONDITIONAL leaves (FocusMode 0x000d,
//! AFPointSelected 0x000e, ExposureCompensation 0x0016, FocalLength 0x001d,
//! EffectiveLV 0x002d, PictureMode 0x000b/0x0033, RawDevelopmentProcess
//! 0x0062), the multi-element-array PrintConvs (FlashMode 0x000c,
//! AutoBracketing 0x0018, DriveMode 0x0034), the encrypted ShutterCount
//! (0x005d), the still-deferred binary SubDirectory tables (LensInfo 0x0207,
//! CameraInfo 0x0215, BatteryInfo 0x0216, AFInfo 0x021f, …) and the
//! `PreviewImage` binary placeholder.
//!
//! ## Phase 2a (#262) — three binary SubDirectory tables
//!
//! [`subtables`] ports the K10D variant of `%Pentax::CameraSettings` (0x0205),
//! `%Pentax::AEInfo` (0x0206) and `%Pentax::FlashInfo` (0x0208), each selected
//! by its `$count` `Condition` (the scope-fence: a non-K10D record size falls
//! through to the deferred variant and emits nothing). The capture loop in
//! [`crate::exif::pentax_makernote_isolated`] dispatches them by the SubTable
//! marker exactly as it does the `0x003f LensRec` child.
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future Phase 1-bis can add fields without a
//! breaking change.

#![deny(clippy::indexing_slicing)]

pub mod cities;
pub mod lens_types;
pub mod model_ids;
pub mod printconv;
pub mod subtables;
pub mod tags;

use smol_str::SmolStr;

pub use printconv::PentaxPrintConv;
pub use tags::{
  PENTAX_TAGS, PentaxTag, SubTable, format_override, is_implicit_undef_subdir, lookup,
};

use super::super::super::ifd::RawValue;

/// Decoded Pentax MakerNotes data — populated by
/// [`crate::exif::pentax_makernote_isolated`] when the dispatcher resolved
/// [`Vendor::Pentax`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `Eq` is derivable (no `f64` fields —
/// the camera-identity fields are integer ids + interned strings).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MakerNotesPentax {
  // ---- camera-identity ----
  /// `PentaxModelID` (0x0005) — int32u body ID (`%pentaxModelID` key).
  model_id: Option<u32>,
  /// Resolved model name from `%pentaxModelID` (e.g. `K10D`).
  model_name: Option<SmolStr>,
  // ---- lens identity ----
  /// `LensType` (`%Pentax::LensRec` position 0) — the `(series, model)` byte
  /// pair packed as `(series << 8) | model`.
  lens_type: Option<u16>,
  /// Resolved lens name from `%pentaxLensTypes` (e.g.
  /// `Sigma or Tamron Lens (3 44)`).
  lens_name: Option<SmolStr>,
  // ---- capture metadata ----
  /// `Quality` (0x0008).
  quality: Option<u32>,
  /// `WhiteBalance` (0x0019).
  white_balance: Option<u32>,
  /// `ISO` (0x0014) — the raw `%pentaxISO`-keyed index.
  iso: Option<u32>,
  /// `ImageTone` (0x004f).
  image_tone: Option<u32>,
}

impl MakerNotesPentax {
  /// Build an empty Pentax metadata bag.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      model_id: None,
      model_name: None,
      lens_type: None,
      lens_name: None,
      quality: None,
      white_balance: None,
      iso: None,
      image_tone: None,
    }
  }

  /// `PentaxModelID` (0x0005) — int32u body identification.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u32> {
    self.model_id
  }

  /// Resolved model name from `%pentaxModelID`.
  #[must_use]
  #[inline]
  pub fn model_name(&self) -> Option<&str> {
    self.model_name.as_deref()
  }

  /// `LensType` `(series, model)` packed as `(series << 8) | model`.
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<u16> {
    self.lens_type
  }

  /// Resolved lens name from `%pentaxLensTypes`.
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }

  /// `Quality` (0x0008) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn quality(&self) -> Option<u32> {
    self.quality
  }

  /// `WhiteBalance` (0x0019) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn white_balance(&self) -> Option<u32> {
    self.white_balance
  }

  /// `ISO` (0x0014) — the raw `%pentaxISO`-keyed index.
  #[must_use]
  #[inline(always)]
  pub const fn iso(&self) -> Option<u32> {
    self.iso
  }

  /// `ImageTone` (0x004f) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn image_tone(&self) -> Option<u32> {
    self.image_tone
  }
}

/// Populate the typed struct from one Pentax Main-IFD leaf-tag emission. `raw`
/// is the entry's post-Format-decode [`RawValue`].
///
/// Called from the SAME gate-passing capture path the emission runs through
/// (the shared-`Walker` Pentax capture), so a tag that did not emit populates
/// no field. The lens identity is set separately by [`emit_lens_rec`] (it reads
/// the LensRec byte pair, not a single scalar).
pub(crate) fn populate_typed_value(typed: &mut MakerNotesPentax, tag_id: u16, raw: &RawValue) {
  match tag_id {
    0x0005 => {
      if let Some(n) = first_u32(raw) {
        typed.model_id = Some(n);
        typed.model_name = model_ids::lookup_name(n);
      }
    }
    0x0008 => typed.quality = first_u32(raw),
    0x0014 => typed.iso = first_u32(raw),
    0x0019 => typed.white_balance = first_u32(raw),
    0x004f => typed.image_tone = first_u32(raw),
    _ => {}
  }
}

/// Emit the `LensType` leaf from the `%Pentax::LensRec` `0x003f` SubDirectory
/// block (`Pentax.pm:4199-4207`).
///
/// Position 0 is `Format => 'int8u[2]'` — the `(series, model)` pair. The
/// default ValueConv is the space-joined `"series model"` string (`-n`); the
/// PrintConv resolves it against `%pentaxLensTypes` (with the firmware-rewrite
/// `OTHER` sub) for the named lens (`-j`). A block too short to hold the two
/// bytes emits NOTHING (matching ExifTool's `GetTagInfo` miss), mirroring the
/// Nikon `emit_af_info` SubDirectory pattern. The trailing `ExtenderStatus`
/// byte (position 3) is deferred.
pub(crate) fn emit_lens_rec(
  block: &[u8],
  print_conv: bool,
  emissions: &mut std::vec::Vec<super::VendorEmission<'_>>,
) {
  let (Some(&series), Some(&model)) = (block.first(), block.get(1)) else {
    return;
  };
  let value = if print_conv {
    // PrintConv: `%pentaxLensTypes` (+ the `OTHER` firmware-rewrite sub). A miss
    // falls back to the raw `"series model"` pair, exactly as ExifTool renders an
    // unknown key.
    match lens_types::lookup_with_other(series, model) {
      Some(name) => crate::value::TagValue::Str(name),
      None => crate::value::TagValue::Str(SmolStr::from(std::format!("{series} {model}"))),
    }
  } else {
    // ValueConv: the default space-joined int8u[2] pair, e.g. `"3 44"`.
    crate::value::TagValue::Str(SmolStr::from(std::format!("{series} {model}")))
  };
  // `%Pentax::LensRec` `LensType` (pos 0) is `Priority => 0` (`Pentax.pm:4202`):
  // a duplicate never overrides an earlier same-`(doc, family1, name)` tag
  // (`ExifTool.pm:9544-9560`).
  emissions.push(super::VendorEmission::new_with_priority(
    "LensType".into(),
    value,
    false,
    0,
  ));
  // Position 3: `ExtenderStatus` (`Pentax.pm:4208-4212`, `{0=>'Not attached',
  // 1=>'Attached'}`). Bounds-checked: the K10D `Pentax.jpg` LensRec is only 3
  // bytes (byte 3 absent ⇒ no emit), but the K-S2 record is 4 bytes ⇒ byte 3 = 0
  // → 'Not attached'. `-n` ⇒ the raw int.
  if let Some(&ext) = block.get(3) {
    let value = if print_conv {
      crate::value::TagValue::Str(SmolStr::new_static(match ext {
        0 => "Not attached",
        1 => "Attached",
        _ => "",
      }))
    } else {
      crate::value::TagValue::I64(i64::from(ext))
    };
    // A miss (ext not 0/1) renders the decimal `Unknown (N)` fallback under -j.
    let value = if print_conv && !matches!(ext, 0 | 1) {
      crate::value::TagValue::Str(SmolStr::from(std::format!("Unknown ({ext})")))
    } else {
      value
    };
    emissions.push(super::VendorEmission::new(
      "ExtenderStatus".into(),
      value,
      false,
    ));
  }
}

/// Populate the typed lens identity from the LensRec byte pair — the typed-slot
/// analogue of [`emit_lens_rec`] (`-j` only, mirroring the per-leaf populate).
pub(crate) fn populate_lens_type(typed: &mut MakerNotesPentax, block: &[u8]) {
  let (Some(&series), Some(&model)) = (block.first(), block.get(1)) else {
    return;
  };
  typed.lens_type = Some((u16::from(series) << 8) | u16::from(model));
  typed.lens_name = lens_types::lookup_with_other(series, model);
}

/// Decode the Pentax AVI MakerNote (the `hymn` / `mknt` RIFF chunk) through the
/// shared `%Pentax::Main` walker — the bridge from [`crate::formats::riff`] to
/// the Phase-1 Pentax module (#157), mirroring the Canon CTMD precedent
/// [`crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote`].
///
/// ExifTool's `%Pentax::AVI` (`Pentax.pm:6373-6395`) routes the `hymn` (and the
/// Q-S1 `mknt`) chunk into a `SubDirectory` with `TagTable => Pentax::Main`,
/// `Start => 10`, `Base => '$start'`, `ByteOrder => 'Unknown'`. The chunk
/// payload is `'PENTAX \0'` (8) + the `MM`/`II` byte-order marker (2) — a
/// 10-byte header — then the IFD entry-count word at offset 10; offsets inside
/// the IFD are relative to the chunk-data start (`Base => '$start'`).
///
/// This builds the matching [`DetectedMakerNote`] (`body_offset 10`,
/// [`BaseRule::StartItself`], [`ChildByteOrder::Unknown`], `NotIFD` off, no
/// `FixBase` — the AVI table carries none) and walks the chunk through the SAME
/// isolated shared-`Walker` helper the static-file `-j`/`-n` dispatch uses
/// ([`crate::exif::pentax_makernote_isolated`]) with `mn_offset 0` over the
/// chunk payload (so `Base => '$start'` ⇒ `value_offset_base 0` resolves
/// pointers at `payload[off]`). The parent byte order is `Little` — ExifTool's
/// global order during `ProcessRIFF` (RIFF is little-endian); the `ByteOrder =>
/// 'Unknown'` entry-count probe then flips it to big-endian for a big-endian
/// body (the K-x), faithful to `Exif.pm:6982-6993`. No `$$self{Make}`/`Model`
/// is in effect in the RIFF context, so both are `None` (the AVI path runs no
/// `FixBase` heuristic that would read them).
///
/// Returns the [`VendorEmission`]s for `print_conv` (`Unknown => 1` preserved
/// for the caller's engine to suppress). An empty `Vec` for a chunk too short to
/// hold the IFD count word. The typed [`MakerNotesPentax`] slot is discarded —
/// the RIFF output is the emission stream only.
#[cfg(feature = "alloc")]
#[must_use]
pub fn redispatch_avi_makernote<'e>(
  hymn_payload: &[u8],
  print_conv: bool,
) -> std::vec::Vec<super::VendorEmission<'e>> {
  use crate::exif::ifd::ByteOrder;
  use crate::exif::makernotes::{BaseRule, ChildByteOrder, DetectedMakerNote, Vendor};
  // `%Pentax::AVI` hymn/mknt SubDirectory directives (`Pentax.pm:6376-6394`):
  // `Start => 10` ⇒ `body_offset 10`; `Base => '$start'` ⇒ `StartItself`;
  // `ByteOrder => 'Unknown'` ⇒ probe; `NotIFD` off (it IS an IFD); no `FixBase`.
  let detected = DetectedMakerNote::new(
    Vendor::Pentax,
    10,
    BaseRule::StartItself,
    ChildByteOrder::Unknown,
    false,
  );
  // Walk the chunk payload as a standalone blob at `mn_offset 0` (so the
  // `Base => '$start'` ⇒ blob-relative pointers resolve against `payload[..]`).
  // The parent order is RIFF's little-endian; the `Unknown` probe flips it for a
  // big-endian body. No Make/Model in the RIFF context.
  let (emissions, _typed) = crate::exif::pentax_makernote_isolated(
    hymn_payload,
    0,
    hymn_payload.len(),
    detected,
    ByteOrder::Little,
    /* make */ None,
    /* model */ None,
    print_conv,
  )
  .unwrap_or_default();
  emissions
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

#[cfg(test)]
mod tests;
