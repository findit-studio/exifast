// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag900b` (`Sony.pm:7549-7578`) — the `0x900b`
//! Main-table SubDirectory dispatched when the (still-enciphered) first value
//! byte is `0xae` (`Condition => '$$valPt =~ /^\xae/'`, `Sony.pm:1078-1082`).
//!
//! The block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`); the
//! dispatcher [`process_enciphered`](super::decipher::process_enciphered)s it
//! (once, or twice for a double-enciphered body) and hands this table the
//! DECIPHERED bytes. Per the `ProcessBinaryData` contract each tag is emitted
//! IFF its byte range is in the deciphered block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]).
//!
//! Both leaves use indirect hash PrintConvs (the deciphered byte is an opaque
//! code, NOT the face count): `FacesDetected` (0x0002) maps 98→'1', 57→'2', …
//! and `FaceDetection` (0x00bd) maps 0→'Off', 98→'On'.

use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{SubEmission, model_is_a4xx_exact};

/// `FacesDetected` (0x0002) PrintConv (`Sony.pm:7556-7567`) — the deciphered
/// byte is an opaque code, decoded to the face-count string.
fn faces_detected(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "0",
    98 => "1",
    57 => "2",
    93 => "3",
    77 => "4",
    33 => "5",
    168 => "6",
    241 => "7",
    115 => "8",
    _ => return None,
  })
}

/// `FaceDetection` (0x00bd) PrintConv (`Sony.pm:7572-7577`) — `0 => Off`,
/// `98 => On`.
fn face_detection(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    98 => "On",
    _ => return None,
  })
}

/// Render a hash leaf where the deciphered byte is opaque: a PrintConv hit gives
/// the label; a miss gives `"Unknown ($val)"` (`-j`). `-n` keeps the raw byte.
fn opaque_hash_value(raw: u8, hit: Option<&'static str>, print_conv: bool) -> TagValue {
  match (print_conv, hit) {
    (true, Some(s)) => TagValue::Str(SmolStr::new(s)),
    (true, None) => TagValue::Str(SmolStr::new(std::format!("Unknown ({raw})"))),
    (false, _) => TagValue::I64(i64::from(raw)),
  }
}

/// Walk the DECIPHERED `Tag900b` block and emit the face leaves.
///
/// `buf` is the DECIPHERED `0x900b` block — the dispatcher confirmed the `0xae`
/// gate on the raw bytes and ran
/// [`process_enciphered`](super::decipher::process_enciphered). `model` gates
/// the `0x00bd` `FaceDetection` row (`!~ /^DSLR-(A450|A500|A550)$/`).
#[must_use]
pub fn parse_tag900b(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  // 0x0002 FacesDetected.
  if let Some(&raw) = buf.get(0x0002) {
    out.push(SubEmission {
      priority: 1,
      name: "FacesDetected",
      value: opaque_hash_value(raw, faces_detected(raw), print_conv),
    });
  }

  // 0x00bd FaceDetection — `Condition !~ /^DSLR-(A450|A500|A550)$/` ($-anchored
  // EXACT, Sony.pm:7571) — NOT the `\b` boundary, so a suffixed A4xx body still
  // emits FaceDetection.
  if !model_is_a4xx_exact(model)
    && let Some(&raw) = buf.get(0x00bd)
  {
    out.push(SubEmission {
      priority: 1,
      name: "FaceDetection",
      value: opaque_hash_value(raw, face_detection(raw), print_conv),
    });
  }

  out
}

#[cfg(test)]
// The module-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag900b_tests.rs"]
mod tests;
