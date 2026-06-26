// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9050c` (`Sony.pm:8205-8307`) — the enciphered
//! `Tag9050c` `ProcessBinaryData` block (`0x9050` value for the July-2020+ bodies
//! ILCE-1/7SM3 and ILME-FX3, `Sony.pm:8211`).
//!
//! The `0x9050` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:1789-1825`) that selects `Tag9050a`/`b`/`c`/`d` BY MODEL; the FX3
//! activation fixture matches the `Tag9050c` branch
//! (`$$self{Model} =~ /^(ILCE-(1\b|7M4|7RM5|7SM3)|ILME-FX3)/`, `Sony.pm:1810`).
//! The block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`,
//! `Sony.pm:8206`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED bytes.
//! `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:8209,8214`):
//! every offset is a byte index into the deciphered block, and a tag's `Format`
//! overrides the read width.
//!
//! Per the `ProcessBinaryData` contract, each tag is emitted IFF its byte range
//! is in the deciphered block (`buf.get(off .. off+size)`), never all-or-nothing
//! ([[exifast-processbinarydata-per-field]]). Only the camera-metadata leaves
//! the FX3 activation golden needs are ported here; the variant's other
//! model-conditional rows (e.g. `0x008a` InternalSerialNumber for ILCE-1) are
//! gated by the model exactly as the bundled `Condition`s.

use crate::exif::tables::{print_exposure_time, print_fnumber};
use crate::value::TagValue;

/// One emitted `Tag9050c` leaf — the resolved tag name and its already-rendered
/// value (PrintConv-applied or raw, per `print_conv`).
pub struct Tag9050Emission {
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

/// Read a little-endian `int32u` at byte `off` of the deciphered block.
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

/// `Tag9050c` 0x0026 `Shutter` PrintConv (`Sony.pm:8217-8227`):
/// `'0 0 0' => 'Silent / Electronic (0 0 0)'`, OTHER ⇒ `"Mechanical ($val)"`.
/// `$val` is the space-joined `int16u[3]`.
fn print_shutter(joined: &str) -> std::string::String {
  if joined == "0 0 0" {
    "Silent / Electronic (0 0 0)".into()
  } else {
    std::format!("Mechanical ({joined})")
  }
}

/// `Tag9050c` 0x0039 `FlashStatus` PrintConv hash (`Sony.pm:8228-8240`).
fn print_flash_status(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "No Flash present",
    2 => "Flash Inhibited",
    64 => "Built-in Flash present",
    65 => "Built-in Flash Fired",
    66 => "Built-in Flash Inhibited",
    128 => "External Flash present",
    129 => "External Flash Fired",
    _ => return None,
  })
}

/// Push the `int16u[3]` `Shutter` (0x0026) when present (`Sony.pm:8217-8227`).
fn push_shutter(buf: &[u8], print_conv: bool, out: &mut std::vec::Vec<Tag9050Emission>) {
  let (Some(a), Some(b), Some(c)) = (
    read_u16(buf, 0x26),
    read_u16(buf, 0x28),
    read_u16(buf, 0x2a),
  ) else {
    return;
  };
  let joined = std::format!("{a} {b} {c}");
  let value = if print_conv {
    TagValue::Str(print_shutter(&joined).into())
  } else {
    TagValue::Str(joined.into())
  };
  out.push(Tag9050Emission {
    name: "Shutter",
    value,
  });
}

/// Push `SonyExposureTime` (0x0046 / 0x0066, `Sony.pm:8249-8256,8275-8282`):
/// `int16u`, `ValueConv => '$val ? 2 ** (16 - $val/256) : 0'`,
/// `PrintConv => '$val ? PrintExposureTime($val) : "Bulb"'`.
fn push_exposure_time(
  buf: &[u8],
  off: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9050Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let secs = if raw != 0 {
    2f64.powf(16.0 - f64::from(raw) / 256.0)
  } else {
    0.0
  };
  let value = if print_conv {
    if raw != 0 {
      TagValue::Str(print_exposure_time(secs).into())
    } else {
      TagValue::Str("Bulb".into())
    }
  } else {
    TagValue::F64(secs)
  };
  out.push(Tag9050Emission {
    name: "SonyExposureTime",
    value,
  });
}

/// Push `SonyFNumber` (0x0048 / 0x0068, `Sony.pm:8257-8264,8283-8290`):
/// `int16u`, `ValueConv => '2 ** (($val/256 - 16) / 2)'`,
/// `PrintConv => 'sprintf("%.1f",$val)'`.
fn push_fnumber(
  buf: &[u8],
  off: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9050Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let fnum = 2f64.powf((f64::from(raw) / 256.0 - 16.0) / 2.0);
  let value = if print_conv {
    TagValue::Str(print_fnumber(fnum).into())
  } else {
    TagValue::F64(fnum)
  };
  out.push(Tag9050Emission {
    name: "SonyFNumber",
    value,
  });
}

/// Push `ReleaseMode2` (0x004b / 0x006b, `%releaseMode2` `Sony.pm:6195-6226`):
/// `int8u` PrintConv hash, raw value for `-n`.
fn push_release_mode2(
  buf: &[u8],
  off: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9050Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  let value = if print_conv {
    match super::release_mode2_print(raw) {
      Some(s) => TagValue::Str(s.into()),
      None => TagValue::I64(i64::from(raw)),
    }
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(Tag9050Emission {
    name: "ReleaseMode2",
    value,
  });
}

/// Walk the DECIPHERED `Tag9050c` block of the FX3-class bodies and emit the
/// camera-metadata leaves the activation golden needs.
///
/// `buf` is the DECIPHERED `0x9050` block — the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered) (`Sony.pm:11552`,
/// twice for a double-enciphered body), so this table reads plaintext directly.
/// `model` gates the model-conditional rows exactly as the bundled `Condition`s.
/// `print_conv` selects `-j` (PrintConv) vs `-n` (raw `$val`).
#[must_use]
pub fn parse_tag9050c(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9050Emission> {
  let mut out = std::vec::Vec::new();

  // 0x0026 Shutter — int16u[3] (Sony.pm:8217).
  push_shutter(buf, print_conv, &mut out);

  // 0x0039 FlashStatus — int8u; `RawConv => '$$self{FlashFired} = $val'`
  // (Sony.pm:8228). Captured below to gate 0x0050 ShutterCount2.
  let flash_fired = buf.get(0x39).copied();
  if let Some(v) = flash_fired {
    let value = if print_conv {
      match print_flash_status(v) {
        Some(s) => TagValue::Str(s.into()),
        None => TagValue::I64(i64::from(v)),
      }
    } else {
      TagValue::I64(i64::from(v))
    };
    out.push(Tag9050Emission {
      name: "FlashStatus",
      value,
    });
  }

  // 0x003a ShutterCount — int32u, `RawConv => '$val & 0x00ffffff'` (Sony.pm:8241).
  if let Some(raw) = read_u32(buf, 0x3a) {
    out.push(Tag9050Emission {
      name: "ShutterCount",
      value: TagValue::I64(i64::from(raw & 0x00ff_ffff)),
    });
  }

  // 0x0046 SonyExposureTime (Sony.pm:8249), 0x0048 SonyFNumber (Sony.pm:8257).
  push_exposure_time(buf, 0x46, print_conv, &mut out);
  push_fnumber(buf, 0x48, print_conv, &mut out);
  // 0x004b ReleaseMode2 (Sony.pm:8265).
  push_release_mode2(buf, 0x4b, print_conv, &mut out);

  // 0x0050 ShutterCount2 — int32u, `RawConv => '$val & 0x00ffffff'`,
  // `Condition => '($$self{FlashFired} & 0x01) != 1'` (Sony.pm:8269-8274). The
  // DataMember `$$self{FlashFired}` is undef when 0x0039 was out of range, in
  // which case the Perl `&` treats it as 0 (so the condition holds).
  let flash_fired_bit = flash_fired.unwrap_or(0) & 0x01;
  if flash_fired_bit != 1
    && let Some(raw) = read_u32(buf, 0x50)
  {
    out.push(Tag9050Emission {
      name: "ShutterCount2",
      value: TagValue::I64(i64::from(raw & 0x00ff_ffff)),
    });
  }

  // 0x0066 SonyExposureTime, 0x0068 SonyFNumber, 0x006b ReleaseMode2 — the
  // not-valid-in-HDR-mode duplicates (Sony.pm:8275,8283,8291). Same names →
  // last-wins; the bundled walk emits both, and the second pair wins.
  push_exposure_time(buf, 0x66, print_conv, &mut out);
  push_fnumber(buf, 0x68, print_conv, &mut out);
  push_release_mode2(buf, 0x6b, print_conv, &mut out);

  // 0x0088 InternalSerialNumber — int8u[6],
  // `Condition => '$$self{Model} =~ /^(ILCE-(7M4|7RM5|7SM3)|ILME-FX3)/'`,
  // `PrintConv => 'unpack "H*", pack "C*", split " ", $val'` (Sony.pm:8295).
  if model_is_fx3_serial_88(model)
    && let Some(bytes) = buf.get(0x88..0x88 + 6)
  {
    let value = if print_conv {
      let mut hex = std::string::String::with_capacity(12);
      for b in bytes {
        use core::fmt::Write;
        let _ = write!(hex, "{b:02x}");
      }
      TagValue::Str(hex.into())
    } else {
      let mut joined = std::string::String::new();
      for (i, b) in bytes.iter().enumerate() {
        use core::fmt::Write;
        if i > 0 {
          joined.push(' ');
        }
        let _ = write!(joined, "{b}");
      }
      TagValue::Str(joined.into())
    };
    out.push(Tag9050Emission {
      name: "InternalSerialNumber",
      value,
    });
  }

  out
}

/// `Condition` for the 0x0088 `InternalSerialNumber` row
/// (`$$self{Model} =~ /^(ILCE-(7M4|7RM5|7SM3)|ILME-FX3)/`, `Sony.pm:8297`).
fn model_is_fx3_serial_88(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  m.starts_with("ILCE-7M4")
    || m.starts_with("ILCE-7RM5")
    || m.starts_with("ILCE-7SM3")
    || m.starts_with("ILME-FX3")
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9050_tests.rs"]
mod tests;
