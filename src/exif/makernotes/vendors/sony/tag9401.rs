// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9401` (`Sony.pm:8642-8673`) — the enciphered
//! `Tag9401` `ProcessBinaryData` block, and its nested `%Sony::ISOInfo`
//! sub-block (`Sony.pm:8675-8682`).
//!
//! The `0x9401` Main-table row dispatches to `Tag9401` unconditionally
//! (`Sony.pm:1862-1864`). The block is enciphered (`PROCESS_PROC =>
//! \&ProcessEnciphered`, `Sony.pm:8643`) — the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED bytes.
//!
//! `Tag9401` carries `DATAMEMBER => [0]` and a 19-entry `IS_SUBDIR` list
//! (`Sony.pm:8650-8651`). The DataMember `0x0000 Ver9401` (`Sony.pm:8652`,
//! `Hidden => 1`, only displayed with `Unknown >= 2` — never emitted here) is
//! the deciphered first byte; the `ISOInfo` sub-block lives at exactly ONE of
//! the 19 candidate byte-offsets, selected by a `Condition` on `Ver9401` (+ for
//! a few rows `$$self{Software}` / `$$self{Model}`, `Sony.pm:8654-8672`). Each
//! `ISOInfo` row is `Format => 'int8u[5]'` — a 5-byte slice the
//! `%Sony::ISOInfo` `ProcessBinaryData` table reads from the ALREADY-deciphered
//! `Tag9401` buffer (NOT re-deciphered).
//!
//! `%Sony::ISOInfo` emits three leaves — `ISOSetting` (0x00), `ISOAutoMin`
//! (0x02), `ISOAutoMax` (0x04) — each `ValueConv => \%isoSetting2010`
//! (`Sony.pm:8679-8681`). Because the conversion is a *ValueConv* hash, its
//! result (a number, the word `Auto`, or `"Unknown (N)"` for a missing key —
//! `ExifTool.pm:3614-3635`) applies in BOTH `-j` and `-n`; there is no separate
//! PrintConv. Per the `ProcessBinaryData` contract each leaf is emitted IFF its
//! byte is in range ([[exifast-processbinarydata-per-field]]).

use crate::value::TagValue;

/// One emitted `Tag9401`/`ISOInfo` leaf — the resolved tag name and value.
pub struct Tag9401Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (the `ValueConv` result, identical for `-j` and `-n`).
  pub value: TagValue,
}

/// Decipher the `Tag9401` block, locate the `ISOInfo` sub-block via the
/// `Ver9401`/`Software`/`Model` `IS_SUBDIR` conditions, and emit its three
/// ISO leaves.
///
/// `buf` is the DECIPHERED `0x9401` block — the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered) (`0x9401`
/// dispatches unconditionally; twice for a double-enciphered body). `model` /
/// `software` are the dispatcher's `$$self{Model}` / `$$self{Software}` (IFD0,
/// RawConv-trimmed).
#[must_use]
pub fn parse_tag9401(
  buf: &[u8],
  model: Option<&str>,
  software: Option<&str>,
) -> Vec<Tag9401Emission> {
  let mut out = std::vec::Vec::new();

  // 0x0000 Ver9401 — the deciphered first byte (DataMember; not emitted).
  let Some(&ver) = buf.get(0x00) else {
    return out;
  };

  // The ONE ISOInfo byte-offset selected by Ver9401 (+ Software/Model). `None`
  // ⇒ no candidate matched this body ⇒ no ISOInfo leaves (deferred).
  let Some(iso_off) = iso_info_offset(ver, model, software) else {
    return out;
  };

  // `%Sony::ISOInfo` (Format int8u[5]) over the deciphered buffer at `iso_off`.
  // 0x00 ISOSetting / 0x02 ISOAutoMin / 0x04 ISOAutoMax — each int8u through
  // the `%isoSetting2010` ValueConv hash (`Sony.pm:8679-8681`).
  for (sub_off, name) in [
    (0x00usize, "ISOSetting"),
    (0x02, "ISOAutoMin"),
    (0x04, "ISOAutoMax"),
  ] {
    if let Some(off) = iso_off.checked_add(sub_off)
      && let Some(&raw) = buf.get(off)
    {
      out.push(Tag9401Emission {
        name,
        value: iso_setting_2010(raw),
      });
    }
  }

  out
}

/// `%isoSetting2010` ValueConv hash (`Sony.pm:6418-6462`). A *ValueConv* hash:
/// a hit yields the mapped value (the word `Auto` for 0, else a plain ISO
/// number); a miss yields `"Unknown (N)"` (`ExifTool.pm:3633`, the
/// hash-lookup-miss fallback that applies to BOTH ValueConv and PrintConv).
#[must_use]
fn iso_setting_2010(raw: u8) -> TagValue {
  let mapped: Option<i64> = match raw {
    5 => Some(25),
    7 => Some(40),
    8 => Some(50),
    9 => Some(64),
    10 => Some(80),
    11 => Some(100),
    12 => Some(125),
    13 => Some(160),
    14 => Some(200),
    15 => Some(250),
    16 => Some(320),
    17 => Some(400),
    18 => Some(500),
    19 => Some(640),
    20 => Some(800),
    21 => Some(1000),
    22 => Some(1250),
    23 => Some(1600),
    24 => Some(2000),
    25 => Some(2500),
    26 => Some(3200),
    27 => Some(4000),
    28 => Some(5000),
    29 => Some(6400),
    30 => Some(8000),
    31 => Some(10000),
    32 => Some(12800),
    33 => Some(16000),
    34 => Some(20000),
    35 => Some(25600),
    36 => Some(32000),
    37 => Some(40000),
    38 => Some(51200),
    39 => Some(64000),
    40 => Some(80000),
    41 => Some(102400),
    42 => Some(128000),
    43 => Some(160000),
    44 => Some(204800),
    45 => Some(256000),
    46 => Some(320000),
    47 => Some(409600),
    _ => None,
  };
  match mapped {
    Some(n) => TagValue::I64(n),
    // 0 => 'Auto'; every other miss => "Unknown (N)".
    None if raw == 0 => TagValue::Str("Auto".into()),
    None => TagValue::Str(std::format!("Unknown ({raw})").into()),
  }
}

/// Select the `ISOInfo` sub-block byte-offset from the `Ver9401` (+ optional
/// `Software`/`Model`) `IS_SUBDIR` `Condition`s (`Sony.pm:8654-8672`),
/// transcribed in table order (the first matching row wins, as ExifTool tests
/// `IS_SUBDIR` offsets in declaration order).
///
/// Two regex forms appear in the bundled conditions: `Ver9401 == N` (numeric
/// equality) and `Ver9401 =~ /^(A|B|…)/` (an UNANCHORED-tail prefix match on
/// the DECIMAL STRING of `Ver9401`). Since `Ver9401` is a single `int8u`
/// (`0..=255`) and every alternative is a distinct 2–3-digit literal, the
/// prefix forms are reproduced by a decimal-string prefix test.
#[must_use]
fn iso_info_offset(ver: u8, model: Option<&str>, software: Option<&str>) -> Option<usize> {
  // `$$self{Software}` / `$$self{Model}` regex helpers.
  let sw = software.unwrap_or("");
  let md = model.unwrap_or("");
  // `Ver9401 =~ /^(a|b|…)/` — decimal-string prefix match (UNANCHORED tail).
  let ver_str = itoa_u8(ver);
  let ver_prefix = |alts: &[&str]| -> bool { alts.iter().any(|a| ver_str.as_str().starts_with(a)) };

  // Table order (`Sony.pm:8654-8672`); first match wins.
  if ver == 181 {
    return Some(0x03e2);
  }
  if ver_prefix(&["185", "186", "187"]) {
    return Some(0x03f4);
  }
  if ver_prefix(&["178", "201"]) {
    return Some(0x044e);
  }
  if ver == 198 {
    return Some(0x0453);
  }
  if ver == 148 {
    return Some(0x0498);
  }
  if ver == 167 && !sw_matches_ilce7m4_v2_v3(sw) {
    return Some(0x049d);
  }
  if ver == 167 && sw_matches_ilce7m4_v2_v3(sw) {
    return Some(0x049e);
  }
  if ver_prefix(&["160", "164"]) && !sw.starts_with("ILCE-1 v2") {
    return Some(0x04a1);
  }
  if (ver_prefix(&["152", "154", "155"]) && !md.starts_with("ZV-1M2"))
    || (ver == 164 && sw.starts_with("ILCE-1 v2"))
  {
    return Some(0x04a2);
  }
  if ver == 155 && md.starts_with("ZV-1M2") {
    return Some(0x04ba);
  }
  if ver_prefix(&["144", "146"]) {
    return Some(0x059d);
  }
  if ver == 68 {
    return Some(0x0634);
  }
  if ver_prefix(&["73", "74"]) {
    return Some(0x0636);
  }
  if ver == 78 {
    return Some(0x064c);
  }
  if ver == 90 {
    return Some(0x0653);
  }
  if ver_prefix(&["93", "94"]) {
    return Some(0x0678);
  }
  if ver_prefix(&["100", "103"]) {
    return Some(0x06b8);
  }
  if ver_prefix(&["124", "125"]) {
    return Some(0x06de);
  }
  if ver_prefix(&["127", "128", "130"]) {
    return Some(0x06e7);
  }
  None
}

/// `$$self{Software} =~ /^ILCE-7M4 (v2|v3)/` (`Sony.pm:8659-8660`).
#[must_use]
fn sw_matches_ilce7m4_v2_v3(sw: &str) -> bool {
  sw.starts_with("ILCE-7M4 v2") || sw.starts_with("ILCE-7M4 v3")
}

/// Format a `u8` as its decimal ASCII string (for the `Ver9401` `/^(a|b)/`
/// prefix tests). `SmolStr` keeps the 1–3-digit value inline (no heap).
#[must_use]
fn itoa_u8(v: u8) -> smol_str::SmolStr {
  smol_str::SmolStr::new(std::format!("{v}"))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9401_tests.rs"]
mod tests;
