// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Samsung MakerNotes — `%Image::ExifTool::Samsung::Type2` Phase-1 port.
//!
//! Bundled source: `lib/Image/ExifTool/Samsung.pm` —
//! `%Image::ExifTool::Samsung::Type2` (`Samsung.pm:129-648`, the EXIF-format
//! maker notes of newer Samsung bodies) plus the `%samsungLensTypes`
//! (`Samsung.pm:35-55`) and inline `SamsungModelID`/`DeviceType` PrintConv
//! hashes, and the `%Samsung::PictureWizard` `ProcessBinaryData` sub-table
//! (`Samsung.pm:650-705`).
//!
//! ## Scope
//!
//! - The Samsung Type2 body walk runs through the shared `Walker` isolated
//!   helper [`crate::exif::samsung_makernote_isolated`] — the dispatcher
//!   (`MakerNoteSamsung2`, `MakerNotes.pm:965-979`) gives body offset 0,
//!   inherit base, `ByteOrder => Unknown` (probed) and `FixBase => 1`, all
//!   threaded into `process_subdir(TableRef::Samsung)`.
//! - The faithful tag table ([`tags::SAMSUNG_TAGS`]) — the Type2 plain
//!   scalar/enum/string/lookup LEAVES + the 16 Crypt-encrypted leaves.
//! - Per-tag conversions ([`printconv::SamsungPrintConv`]).
//! - [`lens_types::SAMSUNG_LENS_TYPES`] / [`model_ids::SAMSUNG_MODEL_IDS`].
//! - The `0x0021 PictureWizard` `ProcessBinaryData` SubDirectory, surfaced by
//!   [`emit_picture_wizard`].
//! - The `Image::ExifTool::Samsung::Crypt` decryption ([`crypt`], #242): the
//!   isolated walker captures the `0xa020 EncryptionKey` DataMember
//!   ([`encryption_key_from_raw`]) and decrypts the 16 `0xa021`..`0xa043`
//!   `RawConv => Samsung::Crypt(...)` leaves ([`emit_crypt`]) — WB_RGGBLevels*,
//!   ColorMatrix*, CbCr*, ToneCurve* — byte-exactly to bundled ExifTool.
//! - A typed [`MakerNotesSamsung`] struct with D8 accessors over the parsed
//!   camera-identity fields (DeviceType + SamsungModelID + name, LensType +
//!   name, FirmwareName).
//!
//! ## Deferred (see [`tags`])
//!
//! The `Unknown => 1` Crypt rows (`0xa048 RawData`, `0xa050`-`0xa057`
//! Distortion/ChromaticAberration/Vignetting*) — `Unknown` suppresses them from
//! default `-j` output — and the `0x0011 OrientationInfo` / `0x0035 PreviewIFD`
//! SubDirectory rows (absent from the NX500 fixture; crafted-input only).
//! Three plain leaves in/near the Crypt range ARE ported: the `$$valPt`-gated
//! `0xa002 SerialNumber` (value-`Condition` gate in
//! [`SamsungPrintConv::condition_holds`]), `0xa020 EncryptionKey` (its RawConv
//! returns `$val` unchanged — a plain int32u[11] passthrough — AND seeds the
//! Crypt key), and `0xa025 HighlightLinearityLimit` (the plain int32u row wins
//! the duplicate-id last-wins over the `0xa025 DigitalGain` Crypt row).
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future phase can add fields without a breaking
//! change.

#![deny(clippy::indexing_slicing)]

pub mod crypt;
pub mod lens_types;
pub mod model_ids;
pub mod printconv;
pub mod tags;

use crate::exif::ifd::RawValue;
use crate::exif::makernotes::VendorEmission;
use smol_str::SmolStr;
use std::vec::Vec;

pub use crypt::{Salt, crypt};
pub use lens_types::{SAMSUNG_LENS_TYPES, SamsungLensType};
pub use model_ids::{SAMSUNG_MODEL_IDS, SamsungModelEntry};
pub use printconv::SamsungPrintConv;
pub use tags::{CryptTag, SAMSUNG_TAGS, SamsungTag, SubTable, format_override, lookup};

/// Decoded Samsung Type2 MakerNotes data — populated by
/// [`crate::exif::samsung_makernote_isolated`] when the dispatcher resolved
/// [`Vendor::Samsung`](crate::exif::makernotes::Vendor::Samsung) via the
/// `MakerNoteSamsung2` arm.
///
/// D8: no public fields; accessor-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MakerNotesSamsung {
  // ---- camera identity ----
  /// Type2 0x0002 (`DeviceType`) — int32u body class.
  device_type: Option<u32>,
  /// Type2 0x0003 (`SamsungModelID`) — int32u body ID.
  model_id: Option<u32>,
  /// Resolved model name from the `SamsungModelID` PrintConv.
  model_name: Option<SmolStr>,
  /// Type2 0xa001 (`FirmwareName`) — firmware string.
  firmware_name: Option<SmolStr>,
  // ---- lens identity ----
  /// Type2 0xa003 (`LensType`) — int16u lens-type ID.
  lens_type: Option<u32>,
  /// Resolved lens name from `%samsungLensTypes`.
  lens_name: Option<SmolStr>,
}

impl MakerNotesSamsung {
  /// Build an empty Samsung metadata bag.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      device_type: None,
      model_id: None,
      model_name: None,
      firmware_name: None,
      lens_type: None,
      lens_name: None,
    }
  }

  /// `DeviceType` (`Samsung.pm:140-152`) — int32u body class.
  #[must_use]
  #[inline(always)]
  pub const fn device_type(&self) -> Option<u32> {
    self.device_type
  }

  /// `SamsungModelID` (`Samsung.pm:153-245`) — int32u body ID.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u32> {
    self.model_id
  }

  /// Resolved model name from the `SamsungModelID` PrintConv.
  #[must_use]
  #[inline]
  pub fn model_name(&self) -> Option<&str> {
    self.model_name.as_deref()
  }

  /// `FirmwareName` (`Samsung.pm:399-403`).
  #[must_use]
  #[inline]
  pub fn firmware_name(&self) -> Option<&str> {
    self.firmware_name.as_deref()
  }

  /// `LensType` (`Samsung.pm:410-416`) — int16u lens-type ID.
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<u32> {
    self.lens_type
  }

  /// Resolved lens name from `%samsungLensTypes`. `None` when the ID isn't in
  /// the table.
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }
}

/// Populate the typed struct from one gate-passing Samsung Type2 leaf-tag
/// emission. `raw` is the entry's post-Format-decode [`RawValue`].
///
/// MUST be called ONLY for an entry that the capture loop actually emits, so a
/// dropped entry populates no typed field — mirroring the Sony/Pentax contract.
pub(crate) fn populate_typed(typed: &mut MakerNotesSamsung, tag_id: u16, raw: &RawValue) {
  match tag_id {
    0x0002 => {
      typed.device_type = first_u32(raw);
    }
    0x0003 => {
      if let Some(n) = first_u32(raw) {
        typed.model_id = Some(n);
        typed.model_name = model_ids::lookup_name(n);
      }
    }
    0xa001 => {
      if let RawValue::Text { text: s, .. } = raw {
        typed.firmware_name = Some(s.as_str().into());
      }
    }
    0xa003 => {
      if let Some(n) = first_u32(raw) {
        typed.lens_type = Some(n);
        typed.lens_name = lens_types::lookup_name(n);
      }
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

/// Emit the five `%Samsung::PictureWizard` members from the `0x0021`
/// SubDirectory's DECODED int16u array (`Samsung.pm:650-705`).
///
/// `%Samsung::PictureWizard` is a `ProcessBinaryData` table with `FORMAT =>
/// 'int16u'` and `FIRST_ENTRY => 0`. The shared `Walker` already decoded the
/// `0x0021` entry as `int16u[N]` in the maker-note's RESOLVED (probed) byte
/// order — the SubDirectory inherits that order — so member `N` is simply the
/// `N`-th element of `members`, no manual byte-order handling. The five members
/// are:
///
/// - 0 `PictureWizardMode` — int16u label hash.
/// - 1 `PictureWizardColor` — int16u, raw.
/// - 2 `PictureWizardSaturation` — int16u, ValueConv `$val - 4`.
/// - 3 `PictureWizardSharpness` — int16u, ValueConv `$val - 4`.
/// - 4 `PictureWizardContrast` — int16u, ValueConv `$val - 4`.
///
/// A member whose index is past the end of `members` is skipped (ExifTool's
/// `ProcessBinaryData` stops once an entry runs past the data). The members
/// carry the `MakerNotes`/`Samsung` group like every other Type2 leaf.
pub(crate) fn emit_picture_wizard(
  members: &[u64],
  print_conv: bool,
  out: &mut Vec<VendorEmission>,
) {
  // (member index, name, conv) — FORMAT int16u ⇒ array index N.
  const MEMBERS: &[(usize, &str, SamsungPrintConv)] = &[
    (0, "PictureWizardMode", SamsungPrintConv::PictureWizardMode),
    (1, "PictureWizardColor", SamsungPrintConv::None),
    (
      2,
      "PictureWizardSaturation",
      SamsungPrintConv::PictureWizardMinus4,
    ),
    (
      3,
      "PictureWizardSharpness",
      SamsungPrintConv::PictureWizardMinus4,
    ),
    (
      4,
      "PictureWizardContrast",
      SamsungPrintConv::PictureWizardMinus4,
    ),
  ];
  for &(idx, name, conv) in MEMBERS {
    let Some(&v) = members.get(idx) else {
      continue;
    };
    let raw = RawValue::U64(std::vec![v]);
    let value = conv.apply(&raw, print_conv);
    out.push(VendorEmission::new(SmolStr::from(name), value, false));
  }
}

/// Render a decoded [`RawValue`] to the `i64` integer vector ExifTool's
/// `split(" ",$val)` produces — the SHARED domain both the `0xa020`
/// `EncryptionKey` DataMember capture and the `Samsung::Crypt` value path
/// operate on.
///
/// Samsung.pm never inspects the TIFF type: the `EncryptionKey` DataMember is
/// `$$self{EncryptionKey} = [ split(" ",$val) ]` (`Samsung.pm:489-490`) and the
/// cipher opens with `@a = split ' ', $val` (`Samsung.pm:1582`) — both split the
/// RENDERED value string. So this splitter is format-agnostic: an int32u entry
/// arrives as [`RawValue::U64`] (widened to `i64`, exact for `0..=u32::MAX`) and
/// an int32s entry as [`RawValue::I64`] — either way the elements ARE the
/// space-separated integer tokens of `$val`, for any arity, signed or unsigned.
///
/// Returns `None` for a shape that does NOT render to a clean integer vector
/// (`F64`/`Rational`/`Text`/`Bytes` — never produced for an `int32u`/`int32s`
/// Crypt row, but reachable on a parseable wrong-format input). The two callers
/// take the faithful `Crypt`-returns-`undef` path on `None`: the key capture
/// leaves the key empty, and [`emit_crypt`] emits NOTHING (it does NOT decrypt
/// an artificial empty vector to `Some("")`).
#[must_use]
fn split_val_to_ints(raw: &RawValue) -> Option<Vec<i64>> {
  match raw {
    RawValue::U64(v) => Some(v.iter().map(|&n| n as i64).collect()),
    RawValue::I64(v) => Some(v.clone()),
    _ => None,
  }
}

/// Capture the `0xa020 EncryptionKey` as the `i64` key vector the [`crypt`]
/// cipher indexes — the DataMember `$$self{EncryptionKey} = [ split(" ",$val) ]`
/// (`Samsung.pm:489-490`). Renders `$val` through [`split_val_to_ints`], so the
/// key is captured for ANY integer encoding (int32u → [`RawValue::U64`], or a
/// parseable wrong-format int32s → [`RawValue::I64`]), matching ExifTool's
/// type-agnostic `split(" ",$val)`. A shape that does not render to integers
/// yields an empty key ⇒ later Crypt tags emit nothing (the faithful
/// `$key or return undef`).
#[must_use]
pub(crate) fn encryption_key_from_raw(raw: &RawValue) -> Vec<i64> {
  split_val_to_ints(raw).unwrap_or_default()
}

/// Decrypt one `%Samsung::Type2` Crypt leaf (`0xa021`..`0xa043` of the emitted
/// 16) and push the plaintext emission — the emit-time port of the row's
/// `RawConv => Image::ExifTool::Samsung::Crypt($self,$val,$tagInfo,SALT…)`.
///
/// `raw` is the entry's decoded value; `key` the captured `EncryptionKey`. The
/// raw value is rendered to integers through [`split_val_to_ints`] (the
/// type-agnostic `split(" ",$val)`), then the cipher ([`crypt`]) runs over those
/// integers with the tag's `Writable` format + salts, returning the space-joined
/// plaintext (the FINAL value — a Crypt row has no further PrintConv, so `-j` and
/// `-n` render identically). NOTHING is emitted — exactly as ExifTool's RawConv
/// `return undef` drops the tag — in three cases: the raw value does not render
/// to integers ([`split_val_to_ints`] is `None`, a parseable wrong-format entry,
/// so no artificial empty vector is decrypted to `Some("")`); the key is empty
/// (`EncryptionKey` absent/malformed); or the format has no `%formatMinMax`
/// entry. The emission carries the row's `Unknown=>1` flag (only the deferred
/// `0xa048`/`0xa05x` rows are Unknown; none of the 16 emitted are, so this is
/// `false` for them).
pub(crate) fn emit_crypt(
  name: &str,
  crypt_tag: tags::CryptTag,
  raw: &RawValue,
  key: &[i64],
  unknown: bool,
  out: &mut Vec<VendorEmission>,
) {
  // `split(" ",$val)` over the RENDERED value — `None` for a shape that does not
  // render to integers (a parseable wrong-format Crypt entry). ExifTool's RawConv
  // would still operate, but the faithful target is `Crypt`-returns-`undef`: emit
  // NOTHING rather than decrypt an artificial empty vector to `Some("")`.
  let Some(ints) = split_val_to_ints(raw) else {
    return;
  };
  let Some(plain) = crypt(&ints, key, crypt_tag.format(), crypt_tag.salts()) else {
    return;
  };
  out.push(VendorEmission::new(
    SmolStr::from(name),
    crate::value::TagValue::Str(SmolStr::from(plain.as_str())),
    unknown,
  ));
}

#[cfg(test)]
mod tests;
