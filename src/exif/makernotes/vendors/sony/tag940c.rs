// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag940c` (`Sony.pm:9348-9449`) — the enciphered
//! `Tag940c` `ProcessBinaryData` block, the E-mount lens-mount / lens-firmware
//! table (`NOTES => 'E-mount cameras only.'`, `Sony.pm:9357`).
//!
//! The `0x940c` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:2079-2086`): the `Tag940c` table is selected when the body matches
//! `/^(NEX-|ILCE-|ILME-|Lunar|ZV-E10|ZV-E10M2|ZV-E1)\b/` (`Sony.pm:2081`); the
//! FX3 (`ILME-FX3`) matches the `ILME-` alternative. The block is enciphered
//! (`PROCESS_PROC => \&ProcessEnciphered`, `Sony.pm:9349`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED bytes;
//! `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:9352,9354`).
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). The
//! `DataMember` 0x0008 (`LensMount`) is read first because the later
//! `LensType3`/`LensE-mountVersion`/`LensFirmwareVersion` rows gate on it.

use super::lens_types;
use crate::value::TagValue;

/// One emitted `Tag940c` leaf — the resolved tag name and rendered value.
pub struct Tag940cEmission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Read a little-endian `int16u` at byte `off` of the deciphered block.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// 0x0008 `LensMount2` PrintConv hash (`Sony.pm:9365-9370`).
fn print_lens_mount2(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "A-mount (1)",
    4 => "E-mount",
    5 => "A-mount (5)",
    _ => return None,
  })
}

/// `sprintf("%x.%.2x",$val>>8,$val&0xff)` (`Sony.pm:9389,9408`) — the E-mount
/// version render shared by `CameraE-mountVersion` and `LensE-mountVersion`.
fn print_emount_version(v: u16) -> std::string::String {
  std::format!("{:x}.{:02x}", v >> 8, v & 0xff)
}

/// Walk the DECIPHERED `Tag940c` block and emit the camera-metadata leaves the
/// FX3 activation golden needs.
///
/// `buf` is the DECIPHERED `0x940c` block — the dispatcher already confirmed the
/// model gate ([`selects_tag940c`]) and ran
/// [`process_enciphered`](super::decipher::process_enciphered) (twice for a
/// double-enciphered body). `print_conv` selects `-j` (PrintConv) vs `-n` (raw
/// `$val`).
#[must_use]
pub fn parse_tag940c(buf: &[u8], print_conv: bool) -> Vec<Tag940cEmission> {
  let mut out = std::vec::Vec::new();

  // 0x0008 LensMount2 — int8u, DataMember `$$self{LensMount} = $val`
  // (Sony.pm:9362-9371). Captured first to gate the rows below.
  let lens_mount = buf.get(0x08).copied();
  if let Some(raw) = lens_mount {
    let value = super::hash_print_value(raw, print_lens_mount2(raw), print_conv);
    out.push(Tag940cEmission {
      name: "LensMount2",
      value,
    });
  }

  // 0x0009 LensType3 — int16u, `%sonyLensTypes2` (`PrintInt => 1`),
  // `RawConv => '(($$self{LensMount} != 0) or ($val > 0 and $val < 32784)) ?
  // $val : undef'` (Sony.pm:9378-9385). The `LensMount` DataMember is undef when
  // 0x0008 was out of range, which the Perl `!=` treats as 0.
  if let Some(raw) = read_u16(buf, 0x09) {
    let mount = lens_mount.unwrap_or(0);
    if mount != 0 || (raw > 0 && raw < 32784) {
      let value = if print_conv {
        match lens_types::lookup_name(u32::from(raw)) {
          Some(name) => TagValue::Str(name),
          // A miss renders `"Unknown ($val)"` (`ExifTool.pm:3622`): `PrintInt =>
          // 1` is a `BuildTagLookup`-only doc flag, NOT a runtime PrintConv
          // directive, so an id absent from `%sonyLensTypes2` takes the standard
          // hash-PrintConv miss, exactly as `SonyPrintConv::LensType` renders it
          // (verified vs bundled: an out-of-table id ⇒ `"Unknown (60000)"`).
          None => TagValue::Str(smol_str::SmolStr::from(std::format!("Unknown ({raw})"))),
        }
      } else {
        TagValue::I64(i64::from(raw))
      };
      out.push(Tag940cEmission {
        name: "LensType3",
        value,
      });
    }
  }

  // 0x000b CameraE-mountVersion — int16u,
  // `sprintf("%x.%.2x",$val>>8,$val&0xff)` (Sony.pm:9386-9403).
  if let Some(raw) = read_u16(buf, 0x0b) {
    let value = if print_conv {
      TagValue::Str(print_emount_version(raw).into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag940cEmission {
      name: "CameraE-mountVersion",
      value,
    });
  }

  // 0x000d LensE-mountVersion — int16u, `Condition => '$$self{LensMount} != 0'`,
  // `sprintf("%x.%.2x",$val>>8,$val&0xff)` (Sony.pm:9404-9432).
  if lens_mount.unwrap_or(0) != 0
    && let Some(raw) = read_u16(buf, 0x0d)
  {
    let value = if print_conv {
      TagValue::Str(print_emount_version(raw).into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag940cEmission {
      name: "LensE-mountVersion",
      value,
    });
  }

  // 0x0014 LensFirmwareVersion — int16u, `Condition => '$$self{LensMount} != 0'`,
  // `sprintf("Ver.%.2x.%.3d",$val>>8,$val&0xff)` (Sony.pm:9442-9447). No `-n`
  // ValueConv ⇒ the raw int16u.
  if lens_mount.unwrap_or(0) != 0
    && let Some(raw) = read_u16(buf, 0x14)
  {
    let value = if print_conv {
      TagValue::Str(std::format!("Ver.{:02x}.{:03}", raw >> 8, raw & 0xff).into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag940cEmission {
      name: "LensFirmwareVersion",
      value,
    });
  }

  out
}

/// `Tag940c` model `Condition` (`Sony.pm:2081`):
/// `$$self{Model} =~ /^(NEX-|ILCE-|ILME-|Lunar|ZV-E10|ZV-E10M2|ZV-E1)\b/`.
#[must_use]
pub fn selects_tag940c(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  m.starts_with("NEX-")
    || m.starts_with("ILCE-")
    || m.starts_with("ILME-")
    || m.starts_with("Lunar")
    || m.starts_with("ZV-E10")
    || m.starts_with("ZV-E1")
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag940c_tests.rs"]
mod tests;
