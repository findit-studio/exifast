// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::FocalLength` (`Canon.pm:2693-2769`).
//!
//! Binary-data sub-table — `FORMAT => 'int16u'`, `FIRST_ENTRY => 0`.
//! Four words: FocalType / FocalLength / FocalPlaneXSize / FocalPlaneYSize.
//!
//! Ports FocalType + FocalLength + the model-conditional
//! FocalPlaneXSize/FocalPlaneYSize at positions 2/3. The FocalPlane
//! sizes are emitted only when the bundled `Condition` (`Canon.pm:2735-
//! 2739`/`:2754-2758`) selects the `FocalPlaneXSize`/`FocalPlaneYSize`
//! arm rather than the `Unknown` arm; see [`focal_plane_size_valid`].

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length/count guard
// and converted to a checked `.get()` form (re-asserts the parent `exif`
// deny over the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Parse a FocalLength blob. `focal_units` is the FocalUnits value (
/// CameraSettings tag 25) — needed because ExifTool's
/// `ValueConv => '$val / FocalUnits'` is the conversion from raw
/// machine-units to mm. `model` is the parent body's `$$self{Model}`
/// (from IFD0), needed to evaluate the FocalPlaneX/YSize `Condition`.
#[must_use]
pub fn parse(
  data: &[u8],
  parent_order: crate::exif::ifd::ByteOrder,
  print_conv: bool,
  focal_units: Option<u16>,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if data.len() < 4 {
    return out;
  }
  let order = parent_order;
  let units = focal_units.unwrap_or(1).max(1) as f64;
  // FocalType — position 0.
  if let Some(focal_type) = read_u16(data, 0, order)
    && focal_type != 0
  {
    let val = if print_conv {
      match focal_type {
        1 => TagValue::Str("Fixed".into()),
        2 => TagValue::Str("Zoom".into()),
        other => TagValue::Str(SmolStr::from(std::format!("Unknown ({other})"))),
      }
    } else {
      TagValue::U64(focal_type as u64)
    };
    out.push(("FocalType".into(), val));
  }
  // FocalLength — position 1.
  if let Some(focal_raw) = read_u16(data, 2, order)
    && focal_raw != 0
  {
    let mm = focal_raw as f64 / units;
    let val = if print_conv {
      let s = if mm.fract() == 0.0 {
        std::format!("{} mm", mm as i64)
      } else {
        std::format!("{mm} mm")
      };
      TagValue::Str(s.into())
    } else {
      TagValue::F64(mm)
    };
    out.push(("FocalLength".into(), val));
  }
  // FocalPlaneXSize / FocalPlaneYSize — positions 2/3. Bundled has a
  // conditional list: the active `FocalPlane*Size` arm vs an `Unknown`
  // arm. ExifTool suppresses `Unknown => 1` tags by default, so when the
  // `Condition` is FALSE we emit NOTHING (`Canon.pm:2726-2768`).
  if focal_plane_size_valid(model) {
    for (pos, name) in [(4usize, "FocalPlaneXSize"), (6usize, "FocalPlaneYSize")] {
      if let Some(raw) = read_u16(data, pos, order)
        // `RawConv => '$val < 40 ? undef : $val'` (`Canon.pm:2741`/`:2759`).
        && raw >= 40
      {
        // `ValueConv => '$val * 25.4 / 1000'` — 1/1000 inch ⇒ mm.
        let size_mm = raw as f64 * 25.4 / 1000.0;
        let val = if print_conv {
          // `PrintConv => 'sprintf("%.2f mm",$val)'`.
          TagValue::Str(SmolStr::from(std::format!("{size_mm:.2} mm")))
        } else {
          TagValue::F64(size_mm)
        };
        out.push((name.into(), val));
      }
    }
  }
  out
}

/// Bundled FocalPlaneX/YSize `Condition` (`Canon.pm:2735-2739` and the
/// identical `:2754-2758`):
///
/// ```text
/// $$self{Model} !~ /EOS/ or
/// $$self{Model} =~ /\b(1DS?|5D|D30|D60|10D|20D|30D|K236)$/ or
/// $$self{Model} =~ /\b((300D|350D|400D) DIGITAL|REBEL( XTi?)?|Kiss Digital( [NX])?)$/
/// ```
///
/// Returns `true` when the FocalPlane*Size arm is selected. A `None`
/// model mirrors an undef `$$self{Model}`: `undef !~ /EOS/` is true, so
/// the conversion applies (treated as a non-EOS / PowerShot body).
#[must_use]
fn focal_plane_size_valid(model: Option<&str>) -> bool {
  let Some(m) = model else {
    return true; // undef Model: !~ /EOS/ is true.
  };
  // Clause 1: Model does NOT contain "EOS".
  if !m.contains("EOS") {
    return true;
  }
  // Clause 2: `\b(1DS?|5D|D30|D60|10D|20D|30D|K236)$`.
  const C2: [&str; 9] = ["1DS", "1D", "5D", "D30", "D60", "10D", "20D", "30D", "K236"];
  if C2.iter().any(|tok| ends_with_word_boundary(m, tok)) {
    return true;
  }
  // Clause 3: `\b((300D|350D|400D) DIGITAL|REBEL( XTi?)?|Kiss Digital( [NX])?)$`.
  const C3: [&str; 9] = [
    "300D DIGITAL",
    "350D DIGITAL",
    "400D DIGITAL",
    "REBEL XTi",
    "REBEL XT",
    "REBEL",
    "Kiss Digital N",
    "Kiss Digital X",
    "Kiss Digital",
  ];
  C3.iter().any(|tok| ends_with_word_boundary(m, tok))
}

/// Faithful `\bTOKEN$` test for an end-anchored, word-character-leading
/// token: `s` ends with `token`, and the byte preceding `token` (if any)
/// is a non-word character (`[^A-Za-z0-9_]`) — i.e. a `\b` boundary. All
/// the FocalPlane condition tokens start with a word character, so the
/// boundary requires a `\W` (or string start) just before them.
fn ends_with_word_boundary(s: &str, token: &str) -> bool {
  let Some(prefix) = s.strip_suffix(token) else {
    return false;
  };
  match prefix.as_bytes().last() {
    None => true, // token is the whole string ⇒ boundary at start.
    Some(&b) => !(b.is_ascii_alphanumeric() || b == b'_'),
  }
}

fn read_u16(data: &[u8], pos: usize, order: crate::exif::ifd::ByteOrder) -> Option<u16> {
  // `get(pos..pos+2)` yields exactly 2 bytes, so `try_into()` to `[u8; 2]`
  // always succeeds — the checked, byte-identical form of `[b[0], b[1]]`.
  let arr: [u8; 2] = data.get(pos..pos + 2)?.try_into().ok()?;
  Some(match order {
    crate::exif::ifd::ByteOrder::Little => u16::from_le_bytes(arr),
    crate::exif::ifd::ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;

  #[test]
  fn focal_length_zoom_and_value() {
    // FocalType=2 (Zoom), FocalLength=50, FocalUnits=1 ⇒ 50 mm.
    let mut data = std::vec![0u8; 8];
    data[0..2].copy_from_slice(&(2u16).to_le_bytes());
    data[2..4].copy_from_slice(&(50u16).to_le_bytes());
    let emissions = parse(&data, ByteOrder::Little, true, Some(1), None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "FocalType" && *v == TagValue::Str("Zoom".into()))
    );
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "FocalLength" && *v == TagValue::Str("50 mm".into()))
    );
  }

  #[test]
  fn focal_length_with_focal_units_scaling() {
    // FocalLength=170 raw, FocalUnits=10 ⇒ 17 mm.
    let mut data = std::vec![0u8; 8];
    data[0..2].copy_from_slice(&(1u16).to_le_bytes());
    data[2..4].copy_from_slice(&(170u16).to_le_bytes());
    let emissions = parse(&data, ByteOrder::Little, true, Some(10), None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "FocalLength" && *v == TagValue::Str("17 mm".into()))
    );
  }

  #[test]
  fn raw_conv_zero_skipped() {
    let data = std::vec![0u8; 8];
    let emissions = parse(&data, ByteOrder::Little, true, Some(1), None);
    assert!(!emissions.iter().any(|(n, _)| n == "FocalType"));
    assert!(!emissions.iter().any(|(n, _)| n == "FocalLength"));
  }

  /// Build an 8-byte FocalLength blob with FocalPlaneXSize (pos 2) and
  /// FocalPlaneYSize (pos 3) raw words.
  fn blob_with_planes(x: u16, y: u16) -> std::vec::Vec<u8> {
    let mut data = std::vec![0u8; 8];
    data[0..2].copy_from_slice(&(2u16).to_le_bytes()); // FocalType=Zoom
    data[2..4].copy_from_slice(&(50u16).to_le_bytes()); // FocalLength=50
    data[4..6].copy_from_slice(&x.to_le_bytes());
    data[6..8].copy_from_slice(&y.to_le_bytes());
    data
  }

  /// FocalPlaneXSize/YSize for a qualifying model (300D-style): ValueConv
  /// `$val * 25.4 / 1000` + PrintConv `"%.2f mm"`. Raw 5000 ⇒ 127.00 mm.
  #[test]
  fn focal_plane_sizes_for_qualifying_model() {
    let data = blob_with_planes(5000, 3000);
    let model = Some("Canon EOS 300D DIGITAL");
    let pc = parse(&data, ByteOrder::Little, true, Some(1), model);
    assert!(
      pc.iter()
        .any(|(n, v)| n == "FocalPlaneXSize" && *v == TagValue::Str("127.00 mm".into())),
      "got {pc:?}"
    );
    assert!(
      pc.iter()
        .any(|(n, v)| n == "FocalPlaneYSize" && *v == TagValue::Str("76.20 mm".into()))
    );
    // -n (value-conv) emits the float.
    let vc = parse(&data, ByteOrder::Little, false, Some(1), model);
    assert!(
      vc.iter().any(|(n, v)| n == "FocalPlaneXSize"
        && matches!(v, TagValue::F64(f) if (*f - 127.0).abs() < 1e-9))
    );
  }

  /// A PowerShot (non-EOS) model qualifies via clause 1 (`!~ /EOS/`).
  #[test]
  fn focal_plane_sizes_for_powershot() {
    let data = blob_with_planes(5000, 3000);
    let v = parse(
      &data,
      ByteOrder::Little,
      true,
      Some(1),
      Some("Canon PowerShot S30"),
    );
    assert!(v.iter().any(|(n, _)| n == "FocalPlaneXSize"));
  }

  /// A `None` model behaves like an undef `$$self{Model}` (`!~ /EOS/` ⇒
  /// true), so the sizes ARE emitted.
  #[test]
  fn focal_plane_sizes_for_none_model() {
    let data = blob_with_planes(5000, 3000);
    let v = parse(&data, ByteOrder::Little, true, Some(1), None);
    assert!(v.iter().any(|(n, _)| n == "FocalPlaneXSize"));
  }

  /// A non-qualifying EOS model (e.g. 40D — not in the condition lists)
  /// emits NOTHING for the FocalPlane sizes (the `Unknown` arm, which
  /// ExifTool suppresses by default).
  #[test]
  fn focal_plane_sizes_suppressed_for_nonqualifying_eos() {
    let data = blob_with_planes(5000, 3000);
    let v = parse(
      &data,
      ByteOrder::Little,
      true,
      Some(1),
      Some("Canon EOS 40D"),
    );
    assert!(!v.iter().any(|(n, _)| n == "FocalPlaneXSize"));
    assert!(!v.iter().any(|(n, _)| n == "FocalPlaneYSize"));
  }

  /// `RawConv => '$val < 40 ? undef'`: a sub-40 raw word is dropped even
  /// for a qualifying model.
  #[test]
  fn focal_plane_size_below_40_skipped() {
    let data = blob_with_planes(39, 3000);
    let v = parse(
      &data,
      ByteOrder::Little,
      true,
      Some(1),
      Some("Canon EOS 5D"),
    );
    assert!(!v.iter().any(|(n, _)| n == "FocalPlaneXSize"));
    // Y (3000) is still valid.
    assert!(v.iter().any(|(n, _)| n == "FocalPlaneYSize"));
  }

  /// The `\b...$` boundary: "EOS 5D" matches `\b5D$`, but "EOS 15D"
  /// (hypothetical) would NOT match `\b5D$` (no boundary before "5").
  #[test]
  fn word_boundary_anchoring() {
    assert!(focal_plane_size_valid(Some("Canon EOS 5D")));
    assert!(focal_plane_size_valid(Some("Canon EOS-1DS")));
    assert!(focal_plane_size_valid(Some("Canon EOS 30D")));
    assert!(focal_plane_size_valid(Some("Canon EOS DIGITAL REBEL")));
    assert!(focal_plane_size_valid(Some("Canon EOS DIGITAL REBEL XTi")));
    assert!(focal_plane_size_valid(Some("Canon EOS Kiss Digital N")));
    // Non-qualifying EOS models.
    assert!(!focal_plane_size_valid(Some("Canon EOS 40D")));
    assert!(!focal_plane_size_valid(Some("Canon EOS 7D")));
    assert!(!focal_plane_size_valid(Some("Canon EOS 5D Mark II")));
    // "5DX" must NOT match \b5D$ (D is followed by X, not end).
    assert!(!focal_plane_size_valid(Some("Canon EOS 5DX")));
  }
}
