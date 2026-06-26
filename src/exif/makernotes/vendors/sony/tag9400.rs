// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9400c` (`Sony.pm:8518-8640`) — the enciphered
//! `Tag9400c` `ProcessBinaryData` block (shot/sequence info for a broad set of
//! bodies incl. ILCE-1/7SM3 and ILME-FX3, `Sony.pm:8524-8528`).
//!
//! The `0x9400` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:1826-1861`) that selects `Tag9400a`/`b`/`c` BY THE ENCIPHERED FIRST
//! BYTE of the value (`$$valPt`, NOT the model): `Tag9400c` when the first byte
//! is one of `0x23 0x24 0x26 0x28 0x31 0x32 0x33 0x41 0x43` (`Sony.pm:1856`).
//! The FX3 activation fixture's first byte is `0x31` (`Sony.pm:1837`, decoding
//! to `40`). The block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`,
//! `Sony.pm:8519`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED bytes;
//! `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:8522,8530`).
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). Only
//! the camera-metadata leaves the FX3 activation golden needs are ported; the
//! model-conditional `ShotNumberSincePowerUp`/`ModelReleaseYear`/`ShutterType`
//! rows (whose `Condition`s do not include ILME-FX3) are not.

use crate::value::TagValue;

/// One emitted `Tag9400c` leaf — the resolved tag name and rendered value.
pub struct Tag9400Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Read a little-endian `int32u` at byte `off` of the deciphered block.
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

/// `Tag9400c` enciphered first bytes selecting this variant (`Sony.pm:1856`).
const TAG9400C_FIRST_BYTES: [u8; 9] = [0x23, 0x24, 0x26, 0x28, 0x31, 0x32, 0x33, 0x41, 0x43];

/// `true` when the enciphered `0x9400` value selects the `Tag9400c` variant —
/// its first (still-enciphered) byte ∈ {0x23,0x24,0x26,0x28,0x31,0x32,0x33,
/// 0x41,0x43} (`Sony.pm:1856`). Tested against the RAW on-disk bytes (the Perl
/// `$$valPt` is pre-decipher).
#[must_use]
pub fn selects_tag9400c(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(b) if TAG9400C_FIRST_BYTES.contains(b))
}

/// The `Tag9400a` `Condition` side-effect that latches `$$self{DoubleCipher} = 1`
/// (`Sony.pm:1847`): the enciphered `0x9400` first byte ∈ {0x5e,0xe7,0x04} — the
/// DOUBLE-enciphered forms of 0x07/0x09/0x0a (the single-cipher `Tag9400a` first
/// bytes), produced by the ExifTool 9.04-9.10 double-encipher write bug. When
/// this fires, `ProcessEnciphered` deciphers every 0x94xx block twice
/// (`Sony.pm:11553-11556`). Tested against the RAW on-disk bytes (pre-decipher).
#[must_use]
pub fn detects_double_cipher(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(0x5e | 0xe7 | 0x04))
}

/// 0x0016 `SequenceLength` PrintConv hash (the "N shots" form, `Sony.pm:8542`).
fn print_sequence_length_shots(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Continuous",
    1 => "1 shot",
    2 => "2 shots",
    3 => "3 shots",
    4 => "4 shots",
    5 => "5 shots",
    6 => "6 shots",
    7 => "7 shots",
    9 => "9 shots",
    10 => "10 shots",
    12 => "12 shots",
    16 => "16 shots",
    100 => "Continuous - iSweep Panorama",
    200 => "Continuous - Sweep Panorama",
    _ => return None,
  })
}

/// 0x001e `SequenceLength` PrintConv hash (the "N files" form, `Sony.pm:8562`).
fn print_sequence_length_files(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Continuous",
    1 => "1 file",
    2 => "2 files",
    3 => "3 files",
    5 => "5 files",
    7 => "7 files",
    9 => "9 files",
    10 => "10 files",
    _ => return None,
  })
}

/// 0x0029 `CameraOrientation` PrintConv hash (`Sony.pm:8576-8584`).
fn print_camera_orientation(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Horizontal (normal)",
    3 => "Rotate 180",
    6 => "Rotate 90 CW",
    8 => "Rotate 270 CW",
    _ => return None,
  })
}

/// 0x002a `Quality2` — the SECOND variant's PrintConv hash (`Sony.pm:8594-8603`),
/// used for the modern bodies (ILCE-1/.../ILME-FX3, …) that are EXCLUDED from the
/// first variant's `Condition` (`Sony.pm:8587`).
fn print_quality2_modern(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "JPEG",
    2 => "RAW",
    3 => "RAW + JPEG",
    4 => "HEIF",
    6 => "RAW + HEIF",
    _ => return None,
  })
}

/// `true` when `model` is EXCLUDED from the first `Quality2` variant's
/// `Condition` (`Sony.pm:8587`), i.e. one of the modern bodies that use the
/// second (HEIF-aware) `Quality2` PrintConv. The bundled exclusion regex is
/// `/^(DSC-RX1RM3|ILCE-(1|1M2|6700|7CM2|7CR|7M4|7M5|7RM5|7RM6|7SM3|9M3)|ILME-(FX2|FX3A?|FX30)|ILX-LR1|ZV-(E1|E10M2))\b/`.
fn quality2_uses_modern_variant(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  // `\b` after each alternative ⇒ the token must end at a word boundary; for an
  // ASCII model string that means the next char (if any) is a non-word char.
  // The FX3 (`ILME-FX3`) matches `ILME-FX3A?` (the optional `A`).
  let ends_at_boundary = |stem: &str| -> bool {
    m.strip_prefix(stem).is_some_and(|rest| {
      rest
        .chars()
        .next()
        .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
  };
  // DSC-RX1RM3
  if ends_at_boundary("DSC-RX1RM3") {
    return true;
  }
  // ILCE-(1|1M2|6700|7CM2|7CR|7M4|7M5|7RM5|7RM6|7SM3|9M3)
  for tok in [
    "ILCE-1M2",
    "ILCE-1",
    "ILCE-6700",
    "ILCE-7CM2",
    "ILCE-7CR",
    "ILCE-7M4",
    "ILCE-7M5",
    "ILCE-7RM5",
    "ILCE-7RM6",
    "ILCE-7SM3",
    "ILCE-9M3",
  ] {
    if ends_at_boundary(tok) {
      return true;
    }
  }
  // ILME-(FX2|FX3A?|FX30): FX3 with an optional trailing `A`, FX2, FX30.
  if ends_at_boundary("ILME-FX2") || ends_at_boundary("ILME-FX30") {
    return true;
  }
  if let Some(rest) = m.strip_prefix("ILME-FX3") {
    // `FX3A?` then `\b`: an optional single `A`, then a word boundary.
    let rest = rest.strip_prefix('A').unwrap_or(rest);
    if rest
      .chars()
      .next()
      .is_none_or(|c| !c.is_ascii_alphanumeric())
    {
      return true;
    }
  }
  // ILX-LR1
  if ends_at_boundary("ILX-LR1") {
    return true;
  }
  // ZV-(E1|E10M2)
  ends_at_boundary("ZV-E10M2") || ends_at_boundary("ZV-E1")
}

/// Push an `int8u` row whose PrintConv is a lookup hash, raw `$val` for `-n`.
fn push_u8_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  hash: impl Fn(u8) -> Option<&'static str>,
  out: &mut std::vec::Vec<Tag9400Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  let value = if print_conv {
    match hash(raw) {
      Some(s) => TagValue::Str(s.into()),
      None => TagValue::I64(i64::from(raw)),
    }
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(Tag9400Emission { name, value });
}

/// Push an `int32u` row with `ValueConv => '$val + 1'` (SequenceImageNumber /
/// SequenceFileNumber, `Sony.pm:6180-6194`). Same rendered value in `-j`/`-n`
/// (no PrintConv).
fn push_sequence_plus1(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag9400Emission>,
) {
  if let Some(raw) = read_u32(buf, off) {
    out.push(Tag9400Emission {
      name,
      value: TagValue::I64(i64::from(raw) + 1),
    });
  }
}

/// Walk the DECIPHERED `Tag9400c` block and emit the camera-metadata leaves the
/// FX3 activation golden needs.
///
/// `buf` is the DECIPHERED `0x9400` block — the dispatcher already confirmed
/// [`selects_tag9400c`] on the raw bytes and ran
/// [`process_enciphered`](super::decipher::process_enciphered) (twice for a
/// double-enciphered body). `model` selects the `Quality2` PrintConv variant.
/// `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_tag9400c(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9400Emission> {
  let mut out = std::vec::Vec::new();

  // 0x0009 ReleaseMode2 — int8u %releaseMode2 (Sony.pm:8533).
  push_u8_hash(
    buf,
    0x09,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );

  // 0x0012 SequenceImageNumber — int32u, `$val + 1` (Sony.pm:8540).
  push_sequence_plus1(buf, 0x12, "SequenceImageNumber", &mut out);

  // 0x0016 SequenceLength — int8u "N shots" form (Sony.pm:8541).
  push_u8_hash(
    buf,
    0x16,
    "SequenceLength",
    print_conv,
    print_sequence_length_shots,
    &mut out,
  );

  // 0x001a SequenceFileNumber — int32u, `$val + 1` (Sony.pm:8560).
  push_sequence_plus1(buf, 0x1a, "SequenceFileNumber", &mut out);

  // 0x001e SequenceLength — int8u "N files" form (Sony.pm:8561). Same name as
  // 0x0016 ⇒ last-wins; the bundled walk emits both, this one final. The
  // `Hook => '$varSize -= 1 …'` shifts later offsets by -1 only for ILCE-7M5/
  // 7RM6 (Sony.pm:8564) — not the FX3-class bodies ported here.
  push_u8_hash(
    buf,
    0x1e,
    "SequenceLength",
    print_conv,
    print_sequence_length_files,
    &mut out,
  );

  // 0x0029 CameraOrientation — int8u hash (Sony.pm:8576).
  push_u8_hash(
    buf,
    0x29,
    "CameraOrientation",
    print_conv,
    print_camera_orientation,
    &mut out,
  );

  // 0x002a Quality2 — int8u; the model selects the first ("JPEG/RAW/RAW+JPEG/
  // JPEG+MPO") or second ("JPEG/RAW/RAW+JPEG/HEIF/RAW+HEIF") PrintConv variant
  // (Sony.pm:8585-8603). Only the modern (second) variant is ported — it is the
  // one the FX3-class bodies select; an older body reaching here keeps its raw
  // value rather than mis-rendering with the wrong table.
  if let Some(&raw) = buf.get(0x2a) {
    let value = if print_conv && quality2_uses_modern_variant(model) {
      match print_quality2_modern(raw) {
        Some(s) => TagValue::Str(s.into()),
        None => TagValue::I64(i64::from(raw)),
      }
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag9400Emission {
      name: "Quality2",
      value,
    });
  }

  out
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9400_tests.rs"]
mod tests;
