// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9416` (`Sony.pm:9979-10244`) — the enciphered
//! `Tag9416` `ProcessBinaryData` block, the modern CameraSettings/lens table
//! that "replaces 0x9405 for the Sony ILCE-7SM3, from July 2020"
//! (`Sony.pm:2115`) and is valid for the ILCE-1/.../ILME-FX2/FX3/FX30 family
//! (`Sony.pm:9985-9988`).
//!
//! The `0x9416` Main-table row dispatches this table UNCONDITIONALLY
//! (`Sony.pm:2115-2118`). The block is enciphered (`PROCESS_PROC =>
//! \&ProcessEnciphered`, `Sony.pm:9980`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED bytes;
//! `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:9983,9989`).
//!
//! ## Offsets are the BASE table offsets for the FX3
//!
//! Several rows carry a `Hook` that shifts `$varSize` for specific bodies:
//! `+4` after 0x0000 for ILCE-7M5/7RM6 (`Sony.pm:9995`), `-2` after 0x002b for
//! the same (`Sony.pm:10041`), `+1` after 0x0037 for ILME-FX2/ILCE-7M5/7RM6
//! (`Sony.pm:10053`). The ILME-FX3 matches NONE of these, so every offset below
//! is the unshifted base offset. The model-conditional array rows
//! (`VignettingCorrParams`/`APS-CSizeCapture`/`ChromaticAberrationCorrParams`)
//! have FX3-specific offsets selected by `Condition`
//! (`/^(ILCE-(1|7SM3)|ILME-FX3A?)\b/`): 0x088f / 0x08b5 / 0x0914.
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). The
//! `DataMember` 0x004a (`LensMount`) is read first because `LensType2`/
//! `LensType` gate on it.

use super::lens_types;
use crate::exif::tables::print_exposure_time;
use crate::value::TagValue;

/// One emitted `Tag9416` leaf — the resolved tag name and rendered value.
pub struct Tag9416Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`/ValueConv).
  pub value: TagValue,
}

/// Read a little-endian `int16u` at byte `off` of the deciphered block.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// `sprintf("%.1f mm",$val)` after `ValueConv => '$val / 10'` — the
/// FocalLength/MinFocalLength/MaxFocalLength render (`Sony.pm:10130-10153`).
fn push_focal_length(
  buf: &[u8],
  off: usize,
  name: &'static str,
  drop_zero: bool,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9416Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  // 0x0075 MaxFocalLength: `RawConv => '$val || undef'` ⇒ a 0 drops the tag
  // (a fixed-focal-length lens, `Sony.pm:10148`).
  if drop_zero && raw == 0 {
    return;
  }
  let mm = f64::from(raw) / 10.0;
  let value = if print_conv {
    TagValue::Str(std::format!("{mm:.1} mm").into())
  } else {
    TagValue::F64(mm)
  };
  out.push(Tag9416Emission { name, value });
}

/// `2 ** (($val/256 - 16) / 2)` then `sprintf("%.1f",$val)` — the
/// SonyFNumber2 / SonyMaxApertureValue render (`Sony.pm:10022-10037`).
fn push_aperture(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9416Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let val = 2f64.powf((f64::from(raw) / 256.0 - 16.0) / 2.0);
  let value = if print_conv {
    TagValue::Str(std::format!("{val:.1}").into())
  } else {
    TagValue::F64(val)
  };
  out.push(Tag9416Emission { name, value });
}

/// An `int8u` row whose PrintConv is a lookup hash. A hash MISS renders
/// `"Unknown ($val)"` in `-j` / the raw `$val` in `-n`
/// ([`super::hash_print_value`]).
fn push_u8_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  hash: impl Fn(u8) -> Option<&'static str>,
  out: &mut std::vec::Vec<Tag9416Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  let value = super::hash_print_value(raw, hash(raw), print_conv);
  out.push(Tag9416Emission { name, value });
}

/// An `int16s[count]` array row — space-joined for BOTH `-j` and `-n` (no
/// PrintConv; ExifTool joins a multi-element value with spaces). Emitted IFF the
/// whole `count`-element span is in range.
fn push_i16_array(
  buf: &[u8],
  off: usize,
  count: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag9416Emission>,
) {
  let Some(end) = count.checked_mul(2).and_then(|n| off.checked_add(n)) else {
    return;
  };
  let Some(span) = buf.get(off..end) else {
    return;
  };
  let mut joined = std::string::String::new();
  for (i, pair) in span.chunks_exact(2).enumerate() {
    use core::fmt::Write;
    if i > 0 {
      joined.push(' ');
    }
    // `chunks_exact(2)` yields 2-byte slices; the slice-pattern read avoids an
    // index (the panic-safety `indexing_slicing` deny).
    let v = match pair {
      &[lo, hi] => i16::from_le_bytes([lo, hi]),
      _ => continue,
    };
    let _ = write!(joined, "{v}");
  }
  out.push(Tag9416Emission {
    name,
    value: TagValue::Str(joined.into()),
  });
}

/// 0x0035 `ExposureProgram` — `%sonyExposureProgram3` (`Sony.pm:10044-10049`,
/// `Sony.pm:464-499`).
fn print_exposure_program3(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Program AE",
    1 => "Aperture-priority AE",
    2 => "Shutter speed priority AE",
    3 => "Manual",
    4 => "Auto",
    5 => "iAuto",
    6 => "Superior Auto",
    7 => "iAuto+",
    8 => "Portrait",
    9 => "Landscape",
    10 => "Twilight",
    11 => "Twilight Portrait",
    12 => "Sunset",
    14 => "Action (High speed)",
    16 => "Sports",
    17 => "Handheld Night Shot",
    18 => "Anti Motion Blur",
    19 => "High Sensitivity",
    21 => "Beach",
    22 => "Snow",
    23 => "Fireworks",
    26 => "Underwater",
    27 => "Gourmet",
    28 => "Pet",
    29 => "Macro",
    30 => "Backlight Correction HDR",
    33 => "Sweep Panorama",
    36 => "Background Defocus",
    37 => "Soft Skin",
    42 => "3D Image",
    43 => "Cont. Priority AE",
    45 => "Document",
    46 => "Party",
    _ => return None,
  })
}

/// 0x0037 `CreativeStyle` PrintConv hash (`Sony.pm:10054-10075`).
fn print_creative_style(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Vivid",
    2 => "Neutral",
    3 => "Portrait",
    4 => "Landscape",
    5 => "B&W",
    6 => "Clear",
    7 => "Deep",
    8 => "Light",
    9 => "Sunset",
    10 => "Night View/Portrait",
    11 => "Autumn Leaves",
    13 => "Sepia",
    15 => "FL",
    16 => "VV2",
    17 => "IN",
    18 => "SH",
    19 => "FL2",
    20 => "FL3",
    255 => "Off",
    _ => return None,
  })
}

/// 0x0048 / 0x004a `LensMount` PrintConv hashes (`Sony.pm:10080-10085`,
/// `Sony.pm:10100-10104`). 0x0048 adds `3 => 'A-mount (3)'`.
fn print_lens_mount_48(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "A-mount",
    2 => "E-mount",
    3 => "A-mount (3)",
    _ => return None,
  })
}

/// 0x004a `LensMount` PrintConv hash (`Sony.pm:10100-10104`).
fn print_lens_mount_4a(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "A-mount",
    2 => "E-mount",
    _ => return None,
  })
}

/// 0x0049 `LensFormat` PrintConv hash (`Sony.pm:10090-10094`).
fn print_lens_format(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "APS-C",
    2 => "Full-frame",
    _ => return None,
  })
}

/// 0x0070 `PictureProfile` — `%pictureProfile2010` (`Sony.pm:10128`,
/// `Sony.pm:6382+`). Only the value range the FX3 family emits is mapped; an
/// unmapped value falls back to the raw integer.
fn print_picture_profile(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Gamma Still - Standard/Neutral (PP2)",
    1 => "Gamma Still - Portrait",
    3 => "Gamma Still - Night View/Portrait",
    4 => "Gamma Still - B&W/Sepia",
    5 => "Gamma Still - Clear",
    6 => "Gamma Still - Deep",
    7 => "Gamma Still - Light",
    8 => "Gamma Still - Vivid",
    9 => "Gamma Still - Real",
    10 => "Gamma Movie (PP1)",
    22 => "Gamma ITU709 (PP3 or PP4)",
    24 => "Gamma Cine1 (PP5)",
    25 => "Gamma Cine2 (PP6)",
    26 => "Gamma Cine3",
    27 => "Gamma Cine4",
    28 => "Gamma S-Log2 (PP7)",
    29 => "Gamma ITU709 (800%)",
    31 => "Gamma S-Log3 (PP8 or PP9)",
    33 => "Gamma HLG2 (PP10)",
    34 => "Gamma HLG3",
    36 => "Off",
    _ => return None,
  })
}

/// `true` when `model` selects the FX3-class array offsets (0x088f/0x08b5/
/// 0x0914) — `Condition => '$$self{Model} =~ /^(ILCE-(1|7SM3)|ILME-FX3A?)\b/'`
/// (`Sony.pm:10192,10207,10231`).
fn is_fx3_class_array(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  let ends_at_boundary = |stem: &str| -> bool {
    m.strip_prefix(stem).is_some_and(|rest| {
      rest
        .chars()
        .next()
        .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
  };
  if ends_at_boundary("ILCE-1") || ends_at_boundary("ILCE-7SM3") {
    return true;
  }
  // `ILME-FX3A?\b`: an optional trailing `A`, then a word boundary.
  if let Some(rest) = m.strip_prefix("ILME-FX3") {
    let rest = rest.strip_prefix('A').unwrap_or(rest);
    return rest
      .chars()
      .next()
      .is_none_or(|c| !c.is_ascii_alphanumeric());
  }
  false
}

/// Walk the DECIPHERED `Tag9416` block of the FX3-class bodies and emit the
/// camera-metadata leaves the activation golden needs.
///
/// `buf` is the DECIPHERED `0x9416` block — the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered) (`0x9416`
/// dispatches unconditionally; twice for a double-enciphered body). `model`
/// selects the FX3-class array offsets. `print_conv` selects `-j` (PrintConv) vs
/// `-n` (raw `$val`/ValueConv).
#[must_use]
pub fn parse_tag9416(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9416Emission> {
  let mut out = std::vec::Vec::new();

  // 0x0004 SonyISO — int16u, `ValueConv => '100 * 2**(16 - $val/256)'`,
  // `PrintConv => 'sprintf("%.0f",$val)'` (Sony.pm:9999-10006).
  if let Some(raw) = read_u16(buf, 0x04) {
    let iso = 100.0 * 2f64.powf(16.0 - f64::from(raw) / 256.0);
    let value = if print_conv {
      TagValue::Str(std::format!("{iso:.0}").into())
    } else {
      TagValue::F64(iso)
    };
    out.push(Tag9416Emission {
      name: "SonyISO",
      value,
    });
  }

  // 0x0006 StopsAboveBaseISO (%gain2010) — int16u, `ValueConv => '16 - $val/256'`,
  // `PrintConv => '$val ? sprintf("%.1f",$val) : $val'` (Sony.pm:6274-6286).
  if let Some(raw) = read_u16(buf, 0x06) {
    let stops = 16.0 - f64::from(raw) / 256.0;
    let value = if print_conv {
      // `$val ? sprintf("%.1f",$val) : $val` — a ValueConv of exactly 0 prints
      // the bare 0; otherwise "%.1f".
      if stops == 0.0 {
        TagValue::F64(0.0)
      } else {
        TagValue::Str(std::format!("{stops:.1}").into())
      }
    } else {
      TagValue::F64(stops)
    };
    out.push(Tag9416Emission {
      name: "StopsAboveBaseISO",
      value,
    });
  }

  // 0x000a SonyExposureTime2 — int16u, `ValueConv => '$val ? 2 ** (16 - $val/256)
  // : 0'`, `PrintConv => '$val ? PrintExposureTime($val) : "Bulb"'`
  // (Sony.pm:10008-10015).
  if let Some(raw) = read_u16(buf, 0x0a) {
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
    out.push(Tag9416Emission {
      name: "SonyExposureTime2",
      value,
    });
  }

  // 0x000c ExposureTime — rational32u, `PrintConv => '$val ? PrintExposureTime
  // ($val) : "Bulb"'` (Sony.pm:10016-10021). No ValueConv ⇒ the rational's float.
  push_exposure_time_rational(buf, 0x0c, print_conv, &mut out);

  // 0x0010 SonyFNumber2 (Sony.pm:10022), 0x0012 SonyMaxApertureValue
  // (Sony.pm:10030).
  push_aperture(buf, 0x10, "SonyFNumber2", print_conv, &mut out);
  push_aperture(buf, 0x12, "SonyMaxApertureValue", print_conv, &mut out);

  // 0x001d SequenceImageNumber (%sequenceImageNumber) — int32u, `$val + 1`
  // (Sony.pm:10038, 6180-6187). Same value in `-j`/`-n`.
  if let Some(raw) = read_u32_le(buf, 0x1d) {
    out.push(Tag9416Emission {
      name: "SequenceImageNumber",
      value: TagValue::I64(i64::from(raw) + 1),
    });
  }

  // 0x002b ReleaseMode2 (%releaseMode2) — int8u hash (Sony.pm:10039-10043).
  push_u8_hash(
    buf,
    0x2b,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );

  // 0x0035 ExposureProgram — int8u, %sonyExposureProgram3 (Sony.pm:10044-10049).
  push_u8_hash(
    buf,
    0x35,
    "ExposureProgram",
    print_conv,
    print_exposure_program3,
    &mut out,
  );

  // 0x0037 CreativeStyle — int8u hash (Sony.pm:10050-10076).
  push_u8_hash(
    buf,
    0x37,
    "CreativeStyle",
    print_conv,
    print_creative_style,
    &mut out,
  );

  // 0x0048 LensMount — int8u hash; `Condition => '$$self{Model} !~ /^(DSC-)/'`
  // (Sony.pm:10077-10086). The caller only reaches a non-DSC body.
  push_u8_hash(
    buf,
    0x48,
    "LensMount",
    print_conv,
    print_lens_mount_48,
    &mut out,
  );

  // 0x0049 LensFormat — int8u hash (Sony.pm:10087-10095).
  push_u8_hash(
    buf,
    0x49,
    "LensFormat",
    print_conv,
    print_lens_format,
    &mut out,
  );

  // 0x004a LensMount — int8u hash, DataMember `$$self{LensMount} = $val`
  // (Sony.pm:10096-10105). Same name as 0x0048 ⇒ last-wins.
  let lens_mount = buf.get(0x4a).copied();
  push_u8_hash(
    buf,
    0x4a,
    "LensMount",
    print_conv,
    print_lens_mount_4a,
    &mut out,
  );

  // 0x004b LensType2 — int16u, `Condition => '$$self{LensMount} == 2'`,
  // `%sonyLensTypes2` (Sony.pm:10106-10113). A miss renders `"Unknown ($val)"`
  // (`-j`) / the raw int16u (`-n`) — `PrintInt => 1` is a `BuildTagLookup`-only
  // doc flag, NOT a runtime PrintConv directive, so the standard hash-PrintConv
  // miss (`ExifTool.pm:3622`) applies, exactly as `SonyPrintConv::LensType2`
  // renders it (verified vs bundled: an out-of-table id ⇒ `"Unknown (60000)"`).
  if lens_mount == Some(2)
    && let Some(raw) = read_u16(buf, 0x4b)
  {
    let value = if print_conv {
      match lens_types::lookup_name(u32::from(raw)) {
        Some(name) => TagValue::Str(name),
        None => TagValue::Str(smol_str::SmolStr::from(std::format!("Unknown ({raw})"))),
      }
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag9416Emission {
      name: "LensType2",
      value,
    });
  }

  // 0x004f DistortionCorrParams — int16s[16] (Sony.pm:10124-10127).
  push_i16_array(buf, 0x4f, 16, "DistortionCorrParams", &mut out);

  // 0x0070 PictureProfile (%pictureProfile2010) — int8u hash (Sony.pm:10128).
  push_u8_hash(
    buf,
    0x70,
    "PictureProfile",
    print_conv,
    print_picture_profile,
    &mut out,
  );

  // 0x0071 FocalLength (Sony.pm:10129), 0x0073 MinFocalLength (Sony.pm:10137),
  // 0x0075 MaxFocalLength (`RawConv => '$val || undef'`, Sony.pm:10145).
  push_focal_length(buf, 0x71, "FocalLength", false, print_conv, &mut out);
  push_focal_length(buf, 0x73, "MinFocalLength", false, print_conv, &mut out);
  push_focal_length(buf, 0x75, "MaxFocalLength", true, print_conv, &mut out);

  // The FX3-class array rows (model-conditional offsets, Sony.pm:10190-10243):
  // VignettingCorrParams 0x088f int16s[16], APS-CSizeCapture 0x08b5 int8u,
  // ChromaticAberrationCorrParams 0x0914 int16s[32].
  if is_fx3_class_array(model) {
    push_i16_array(buf, 0x088f, 16, "VignettingCorrParams", &mut out);
    if let Some(&raw) = buf.get(0x08b5) {
      let value = if print_conv {
        match raw {
          0 => TagValue::Str("Off".into()),
          1 => TagValue::Str("On".into()),
          _ => TagValue::I64(i64::from(raw)),
        }
      } else {
        TagValue::I64(i64::from(raw))
      };
      out.push(Tag9416Emission {
        name: "APS-CSizeCapture",
        value,
      });
    }
    push_i16_array(buf, 0x0914, 32, "ChromaticAberrationCorrParams", &mut out);
  }

  out
}

/// Read a little-endian `int32u` at byte `off` of the deciphered block.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

/// 0x000c `ExposureTime` — `rational32u` (`GetRational32u`, `ExifTool.pm:6255`):
/// 4 bytes = num `int16u` + den `int16u`, value `RoundFloat(num/den, 7)`; a 0
/// denominator yields `'inf'` (num != 0) or `'undef'`. No ValueConv;
/// `PrintConv => '$val ? PrintExposureTime($val) : "Bulb"'` (`Sony.pm:10016`).
fn push_exposure_time_rational(
  buf: &[u8],
  off: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9416Emission>,
) {
  let (Some(num), Some(den)) = (
    read_u16(buf, off),
    off.checked_add(2).and_then(|o| read_u16(buf, o)),
  ) else {
    return;
  };
  if den == 0 {
    // `GetRational32u`: den 0 ⇒ 'inf' (num != 0) or 'undef' (num == 0); the
    // 'undef' case drops the tag. 'inf' renders verbatim in both modes
    // (`PrintExposureTime` passes a non-numeric string through unchanged).
    if num != 0 {
      out.push(Tag9416Emission {
        name: "ExposureTime",
        value: TagValue::Str("inf".into()),
      });
    }
    return;
  }
  let secs = round_float(f64::from(num) / f64::from(den), 7);
  let value = if print_conv {
    if secs != 0.0 {
      TagValue::Str(print_exposure_time(secs).into())
    } else {
      TagValue::Str("Bulb".into())
    }
  } else {
    TagValue::F64(secs)
  };
  out.push(Tag9416Emission {
    name: "ExposureTime",
    value,
  });
}

/// `RoundFloat($val, $sig)` (`ExifTool.pm`) — round to `sig` SIGNIFICANT digits
/// via the `%.*g` round-trip (`sprintf("%.*g") + 0`).
fn round_float(val: f64, sig: usize) -> f64 {
  crate::value::format_g(val, sig)
    .parse::<f64>()
    .unwrap_or(val)
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9416_tests.rs"]
mod tests;
