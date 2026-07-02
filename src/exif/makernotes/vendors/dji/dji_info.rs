// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::DJI::Info` bracketed-string parser — `ProcessDJIInfo`
//! (`DJI.pm:74-95` table, `:960-983` proc).
//!
//! Some DJI drones write a debug MakerNote whose 0x927C value is NOT an IFD
//! but a flat run of `[key:val]` bracket pairs, e.g.
//! `[ae_dbg_info:...][awb_dbg_info:...][sensor_id:...]`. `MakerNotes.pm:93-97`
//! routes a 0x927C value matching `^\[ae_dbg_info:/` (`NotIFD => 1`) to
//! `%DJI::Info` / [`ProcessDJIInfo`](https://exiftool.org), which walks the
//! brackets and emits one tag per pair.
//!
//! ## Faithful parse (`DJI.pm:960-983`)
//!
//! ```text
//! while ($$dataPt =~ /\G\[(.*?)\](?=(\[|$))/sg) {
//!     my ($tag, $val) = split /:/, $1, 2;
//!     next unless defined $tag and defined $val;
//!     if ($val =~ /^([\x20-\x7e]+)\0*$/) { $val = $1; }
//!     else { $val = \$buff; }                 # binary scalar ref
//!     $et->HandleTag($tagTbl, $tag, $val, MakeTagInfo => 1);
//! }
//! ```
//!
//! Each iteration:
//! - `\G\[(.*?)\](?=(\[|$))` — anchored at the previous match end, captures
//!   the SHORTEST `[...]` whose closing `]` is immediately followed by another
//!   `[` or end-of-string. `/s` makes `.` match NUL/newline. The `\G` anchor +
//!   trailing-context lookahead means: the FIRST pair must start at offset 0
//!   (the dispatch guarantees `[ae_dbg_info:`), every following pair must abut
//!   the previous one's `]`, and any trailing byte after the last `]` that is
//!   NOT `[` makes that final `]` fail the lookahead — so the non-greedy `.*?`
//!   extends the capture to the LAST `]` that satisfies the lookahead, or the
//!   match fails entirely (yielding zero tags from that point on).
//! - `split /:/, $1, 2` — first `:` separates key from value; a value may
//!   itself contain `:` (kept verbatim). No `:` ⇒ `$val` is undef ⇒ the pair
//!   is SKIPPED (`next unless defined $val`). A leading `:` ⇒ empty key (still
//!   defined ⇒ emitted, via `MakeTagInfo` → `Tag`).
//! - `^([\x20-\x7e]+)\0*$` — a value of one-or-more printable-ASCII bytes
//!   optionally followed by trailing NULs becomes the printable prefix (NULs
//!   stripped). ANYTHING else (empty, non-printable byte anywhere, an interior
//!   NUL) is a BINARY value (`(Binary data N bytes, …)` placeholder).
//! - `HandleTag(... MakeTagInfo => 1)` — a key absent from `%DJI::Info` gets a
//!   tag synthesized from the key via the [`make_tag_info_name`] derivation
//!   (`ExifTool.pm:9312-9317`).
//!
//! `%DJI::Info` carries NO PrintConv/ValueConv — every leaf is `{ Name => … }`
//! — so the `-j` (PrintConv) and `-n` (ValueConv) renderings are IDENTICAL.

#![deny(clippy::indexing_slicing)]

use crate::exif::makernotes::vendors::VendorEmission;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// The DJIInfo dispatch signature (`MakerNotes.pm:95`):
/// `$$valPt =~ /^\[ae_dbg_info:/`.
pub const DJI_INFO_SIGNATURE: &[u8] = b"[ae_dbg_info:";

/// `true` when `blob` is a DJIInfo bracketed-string body (starts with the
/// `[ae_dbg_info:` signature `MakerNotes.pm:95` matches).
#[must_use]
#[inline]
pub fn is_dji_info(blob: &[u8]) -> bool {
  blob.starts_with(DJI_INFO_SIGNATURE)
}

/// One named row of `%DJI::Info` (`DJI.pm:80-94`). Keys NOT present here are
/// synthesized via [`make_tag_info_name`] (`MakeTagInfo => 1`).
struct InfoTag {
  key: &'static [u8],
  name: &'static str,
}

/// `%DJI::Info` named leaves (`DJI.pm:80-94`), in source order. Every entry is
/// a bare `{ Name => … }` (no Conv) so only the rename matters.
const INFO_TAGS: &[InfoTag] = &[
  InfoTag {
    key: b"ae_dbg_info",
    name: "AEDebugInfo",
  }, // DJI.pm:80
  InfoTag {
    key: b"ae_histogram_info",
    name: "AEHistogramInfo",
  }, // DJI.pm:81
  InfoTag {
    key: b"ae_local_histogram",
    name: "AELocalHistogram",
  }, // DJI.pm:82
  InfoTag {
    key: b"ae_liveview_histogram_info",
    name: "AELiveViewHistogramInfo",
  }, // DJI.pm:83
  InfoTag {
    key: b"ae_liveview_local_histogram",
    name: "AELiveViewLocalHistogram",
  }, // DJI.pm:84
  InfoTag {
    key: b"awb_dbg_info",
    name: "AWBDebugInfo",
  }, // DJI.pm:85
  InfoTag {
    key: b"af_dbg_info",
    name: "AFDebugInfo",
  }, // DJI.pm:86
  InfoTag {
    key: b"hiso",
    name: "Histogram",
  }, // DJI.pm:87
  InfoTag {
    key: b"xidiri",
    name: "Xidiri",
  }, // DJI.pm:88
  InfoTag {
    key: b"GimbalDegree(Y,P,R)",
    name: "GimbalDegree",
  }, // DJI.pm:89
  InfoTag {
    key: b"FlightDegree(Y,P,R)",
    name: "FlightDegree",
  }, // DJI.pm:90
  InfoTag {
    key: b"adj_dbg_info",
    name: "ADJDebugInfo",
  }, // DJI.pm:91
  InfoTag {
    key: b"sensor_id",
    name: "SensorID",
  }, // DJI.pm:92
  InfoTag {
    key: b"FlightSpeed(X,Y,Z)",
    name: "FlightSpeed",
  }, // DJI.pm:93
  InfoTag {
    key: b"hyperlapse_dbg_info",
    name: "HyperlapsDebugInfo",
  }, // DJI.pm:94
];

/// Resolve a bracket key to its `%DJI::Info` `Name`, falling back to the
/// `MakeTagInfo` synthesis for unknown keys (`DJI.pm:80` table + the
/// `MakeTagInfo => 1` of `ProcessDJIInfo`).
fn resolve_name(key: &[u8]) -> SmolStr {
  for t in INFO_TAGS {
    if t.key == key {
      return SmolStr::new(t.name);
    }
  }
  make_tag_info_name(key)
}

/// `MakeTagInfo`'s tag-name derivation (`ExifTool.pm:9312-9317`), applied to a
/// raw key when no table row matches:
///
/// ```text
/// my $name = $tag;
/// $name =~ s/([A-Z]) ([A-Z][ A-Z])/${1}_$2/g; # underline between acronyms
/// $name =~ s/([^A-Za-z])([a-z])/$1\u$2/g;      # capitalize words
/// $name =~ tr/-_a-zA-Z0-9//dc;                 # remove illegal characters
/// $name = "Tag$name" if length($name) < 2 or $name =~ /^[-0-9]/;
/// $tagInfo = { Name => ucfirst($name) };
/// ```
///
/// The key is on-disk bytes; ExifTool treats it as a Perl string, so the
/// transforms operate per-byte (only ASCII letters/digits are special — every
/// other byte is "illegal" and deleted by the `tr///dc`). The result is ASCII,
/// so a `SmolStr` from the byte run is valid UTF-8.
#[must_use]
pub fn make_tag_info_name(key: &[u8]) -> SmolStr {
  // Step 1: `s/([A-Z]) ([A-Z][ A-Z])/${1}_$2/g` — replace the SPACE in a
  // run `<upper> <upper><upper-or-space>` with `_`. Perl's `/g` resumes
  // scanning AFTER each replacement (past the consumed `${1} $2` text), so
  // overlapping matches do not re-fire on already-consumed bytes.
  let mut s: Vec<u8> = Vec::with_capacity(key.len());
  {
    let n = key.len();
    let mut i = 0usize;
    while i < n {
      // Match `[A-Z] [A-Z][ A-Z]` starting at i: bytes i, i+1(space), i+2,
      // i+3. `$2 = [A-Z][ A-Z]` is two chars (an upper then upper-or-space).
      let b0 = key.get(i).copied();
      let b1 = key.get(i + 1).copied();
      let b2 = key.get(i + 2).copied();
      let b3 = key.get(i + 3).copied();
      let is_upper = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_uppercase());
      let is_upper_or_space =
        |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_uppercase() || c == b' ');
      if is_upper(b0) && b1 == Some(b' ') && is_upper(b2) && is_upper_or_space(b3) {
        // Emit `${1}_$2` = b0, '_', b2, b3; resume after the consumed run.
        if let (Some(c0), Some(c2), Some(c3)) = (b0, b2, b3) {
          s.push(c0);
          s.push(b'_');
          s.push(c2);
          s.push(c3);
        }
        i += 4;
      } else if let Some(c0) = b0 {
        s.push(c0);
        i += 1;
      } else {
        break;
      }
    }
  }

  // Step 2: `s/([^A-Za-z])([a-z])/$1\u$2/g` — when a lowercase letter follows
  // a NON-letter byte, uppercase that letter. `/g` resumes after the
  // (now-uppercased) `$2`, so a letter is examined only against its immediate
  // predecessor in the ORIGINAL stream. A lowercase letter at index 0 has no
  // predecessor, so it is untouched here (the final `ucfirst` handles it).
  {
    let len = s.len();
    let mut i = 1usize;
    while i < len {
      let prev = s.get(i - 1).copied();
      let cur = s.get(i).copied();
      let is_letter = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_alphabetic());
      let is_lower = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_lowercase());
      if !is_letter(prev)
        && is_lower(cur)
        && let Some(slot) = s.get_mut(i)
      {
        *slot = slot.to_ascii_uppercase();
      }
      i += 1;
    }
  }

  // Step 3: `tr/-_a-zA-Z0-9//dc` — delete every byte NOT in the class
  // `-_a-zA-Z0-9`.
  s.retain(|&b| b == b'-' || b == b'_' || b.is_ascii_alphanumeric());

  // Step 4: `$name = "Tag$name" if length($name) < 2 or $name =~ /^[-0-9]/`.
  let prepend_tag =
    s.len() < 2 || matches!(s.first().copied(), Some(c) if c == b'-' || c.is_ascii_digit());
  if prepend_tag {
    let mut t: Vec<u8> = Vec::with_capacity(s.len() + 3);
    t.extend_from_slice(b"Tag");
    t.extend_from_slice(&s);
    s = t;
  }

  // Step 5: `ucfirst($name)` — uppercase the first byte if it is a lowercase
  // ASCII letter.
  if let Some(slot) = s.first_mut() {
    *slot = slot.to_ascii_uppercase();
  }

  // The transforms keep only ASCII (`tr///dc` class is ASCII, the `Tag`
  // prefix is ASCII), so `from_utf8` cannot fail; fall back defensively.
  match std::str::from_utf8(&s) {
    Ok(text) => SmolStr::new(text),
    Err(_) => SmolStr::new_inline("Tag"),
  }
}

/// The value half of a bracket pair, classified per the
/// `^([\x20-\x7e]+)\0*$` test (`DJI.pm:974`).
fn classify_value(val: &[u8]) -> TagValue {
  // `^([\x20-\x7e]+)\0*$`: ONE-or-more printable-ASCII (0x20..=0x7e) bytes,
  // then zero-or-more trailing NULs, anchored to the whole value. On match,
  // `$val = $1` (the printable run WITHOUT the trailing NULs).
  //
  // Perl's default-mode `$` (no `/m`) matches at end-of-string OR immediately
  // before a `\n` that is the LAST byte. So a value ending in exactly one
  // trailing `\n` anchors the regex BEFORE that `\n`: the final newline is
  // ignored for the `$` anchor and breaks neither the printable run nor the
  // `\0*` tail (ground-truthed vs ExifTool 13.59: `ok\n` ⇒ printable `ok`).
  // The newline must be the *last* byte: `ok\n\0` is binary (last byte `\0` ⇒
  // `$` is at true end ⇒ `\0*` cannot consume the `\n`), whereas `ok\0\n` is
  // printable `ok` (last byte `\n` ⇒ `\0*` consumes the NUL, `$` before `\n`).
  let anchor = match val.split_last() {
    Some((&b'\n', rest)) => rest, // single final `\n` ⇒ anchor before it
    _ => val,
  };
  let printable_end = anchor
    .iter()
    .position(|&b| !(0x20..=0x7e).contains(&b))
    .unwrap_or(anchor.len());
  let printable = anchor.get(..printable_end).unwrap_or(&[]);
  let trailing = anchor.get(printable_end..).unwrap_or(&[]);
  if !printable.is_empty() && trailing.iter().all(|&b| b == 0) {
    // All printable (≥1) + only-NUL tail ⇒ string of the printable prefix.
    // The prefix is ASCII 0x20..=0x7e ⇒ valid UTF-8.
    match std::str::from_utf8(printable) {
      Ok(text) => TagValue::Str(SmolStr::new(text)),
      // Unreachable (the range is ASCII); keep the bytes rather than panic.
      Err(_) => TagValue::Bytes(val.to_vec()),
    }
  } else {
    // Empty, or a non-printable byte anywhere (incl. an interior NUL), or a
    // non-NUL trailing byte ⇒ binary scalar ref ⇒ `(Binary data N bytes, …)`.
    TagValue::Bytes(val.to_vec())
  }
}

/// Find the end index of the bracket capture starting at `open` (the index of
/// a `[`), faithful to `\G\[(.*?)\](?=(\[|$))`. Returns `(inner, next)` where
/// `inner` is the captured bytes BETWEEN the brackets (`$1`) and `next` is the
/// index just past the closing `]` (the next `\G` anchor) — or `None` when no
/// closing `]` satisfies the lookahead (the loop then terminates, matching
/// Perl's `while` exiting on a failed match).
fn match_bracket(data: &[u8], open: usize) -> Option<(&[u8], usize)> {
  debug_assert_eq!(data.get(open), Some(&b'['));
  // Non-greedy `.*?` followed by `]` with `(?=(\[|$))`: scan forward for the
  // FIRST `]` (from just after the `[`) whose following byte satisfies the
  // lookahead. `/s` ⇒ `.` matches any byte including NUL, so no early stop.
  //
  // Perl's default-mode `$` (no `/m`; `/s` does not affect `$`) matches at
  // end-of-string OR immediately before a `\n` that is the LAST byte of the
  // string (`perlre` "$" assertion). So the lookahead `(?=(\[|$))` succeeds
  // when the byte after `]` is `[`, is absent (true EOF), or is a `\n` that is
  // itself the final byte of `data`. A `\n` that is NOT the last byte (e.g.
  // `]\n[`) does NOT satisfy `$` ⇒ the lookahead fails there and the non-greedy
  // `.*?` extends to a LATER `]` (ground-truthed vs ExifTool 13.59: `]\n[…]`
  // captures one pair spanning the `]\n[`).
  let content_start = open.checked_add(1)?;
  let mut j = content_start;
  while let Some(&b) = data.get(j) {
    if b == b']' {
      let after = j.checked_add(1)?;
      let lookahead_ok = match data.get(after) {
        None => true, // end-of-string `$`
        Some(&c) => c == b'[' || (c == b'\n' && after.checked_add(1) == Some(data.len())),
        // next pair `\[`, or a single final `\n` (the `$`-before-last-newline).
      };
      if lookahead_ok {
        let inner = data.get(content_start..j).unwrap_or(&[]);
        return Some((inner, after));
      }
      // This `]` fails the lookahead ⇒ the non-greedy `.*?` keeps expanding to
      // a LATER `]`.
    }
    j = j.checked_add(1)?;
  }
  None
}

/// `split /:/, $1, 2` — split the captured inner bytes on the FIRST `:` into
/// `(key, Some(val))`; `None` for the value when there is no `:`
/// (`next unless defined $val`).
fn split_first_colon(inner: &[u8]) -> (&[u8], Option<&[u8]>) {
  match inner.iter().position(|&b| b == b':') {
    Some(c) => {
      let key = inner.get(..c).unwrap_or(&[]);
      let val = inner.get(c + 1..).unwrap_or(&[]);
      (key, Some(val))
    }
    None => (inner, None),
  }
}

/// Parse a DJIInfo bracketed-string body (`ProcessDJIInfo`, `DJI.pm:960-983`)
/// into vendor emissions. `blob` is the whole 0x927C value (`NotIFD => 1`, so
/// `DirStart = 0` — the entire blob is the data).
///
/// `%DJI::Info` carries no Conv, so the result is independent of `print_conv`
/// (the parameter is accepted for call-site symmetry with the IFD path).
#[must_use]
pub fn parse_dji_info<'e>(blob: &[u8]) -> Vec<VendorEmission<'e>> {
  let mut emissions: Vec<VendorEmission<'e>> = Vec::new();
  // `/\G.../g`: the first capture must begin at offset 0 (the dispatch
  // guarantees `[ae_dbg_info:`); each subsequent `\G` anchor is the index
  // just past the previous `]`. A failed match terminates the loop.
  let mut pos = 0usize;
  while let Some(&b) = blob.get(pos) {
    if b != b'[' {
      // `\G\[` requires a `[` at the anchor; anything else fails the match
      // and ends the `while`.
      break;
    }
    let Some((inner, next)) = match_bracket(blob, pos) else {
      break;
    };
    // Guard against a zero-width advance (cannot happen — `next > pos` since
    // `match_bracket` returns `j+1 >= open+1 > open`), keeping the loop finite.
    if next <= pos {
      break;
    }
    let (key, val) = split_first_colon(inner);
    if let Some(val) = val {
      // `next unless defined $tag and defined $val`: a present `:` ⇒ both are
      // defined (an empty key is still defined). Emit.
      let name = resolve_name(key);
      let value = classify_value(val);
      emissions.push(VendorEmission::new(name, value, false));
    }
    pos = next;
  }
  emissions
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test assertions index the fixed-length emission
// vectors freely (an out-of-range index is a test-assertion failure, not a
// shipped panic), so the deny is relaxed here — matching the sibling DJI tests.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::value::TagValue;

  fn names<'s>(emis: &'s [VendorEmission<'_>]) -> Vec<&'s str> {
    emis.iter().map(VendorEmission::name).collect()
  }

  #[test]
  fn signature_predicate() {
    assert!(is_dji_info(b"[ae_dbg_info:x]"));
    assert!(!is_dji_info(b"[awb_dbg_info:x]"));
    assert!(!is_dji_info(b"DJIxxx"));
    assert!(!is_dji_info(b""));
  }

  #[test]
  fn named_tags_resolve_to_canonical_names() {
    // Bundled: DJI:AEDebugInfo / DJI:AEHistogramInfo / DJI:AWBDebugInfo /
    // DJI:GimbalDegree / DJI:FlightDegree / DJI:SensorID.
    let blob = b"[ae_dbg_info:Ver=1.0,exp=auto]\
[ae_histogram_info:0 1 2 3 4 5]\
[awb_dbg_info:r=1.5 g=1.0 b=1.8]\
[GimbalDegree(Y,P,R):-12.3,4.5,0.0]\
[FlightDegree(Y,P,R):10,20,30]\
[sensor_id:ABC123]";
    let emis = parse_dji_info(blob);
    assert_eq!(
      names(&emis),
      std::vec![
        "AEDebugInfo",
        "AEHistogramInfo",
        "AWBDebugInfo",
        "GimbalDegree",
        "FlightDegree",
        "SensorID",
      ]
    );
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Str("Ver=1.0,exp=auto".into())
    );
    assert_eq!(
      emis[1].value().as_ref(),
      &TagValue::Str("0 1 2 3 4 5".into())
    );
    assert_eq!(
      emis[3].value().as_ref(),
      &TagValue::Str("-12.3,4.5,0.0".into())
    );
  }

  #[test]
  fn unknown_key_uses_make_tag_info() {
    // Bundled: `[some_unknown_tag:hello world]` ⇒ DJI:Some_Unknown_Tag.
    let emis = parse_dji_info(b"[ae_dbg_info:x][some_unknown_tag:hello world]");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo", "Some_Unknown_Tag"]);
    assert_eq!(
      emis[1].value().as_ref(),
      &TagValue::Str("hello world".into())
    );
  }

  #[test]
  fn value_with_colon_keeps_remainder() {
    // `split /:/, $1, 2` ⇒ value = "a:b:c=1". Bundled: DJI:AEDebugInfo "a:b:c=1".
    let emis = parse_dji_info(b"[ae_dbg_info:a:b:c=1]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("a:b:c=1".into()));
  }

  #[test]
  fn missing_colon_pair_is_skipped() {
    // `[noColon]` ⇒ `split` yields no `$val` ⇒ skipped. Bundled emits only the
    // `[awb_dbg_info:ok]` pair.
    let emis = parse_dji_info(b"[ae_dbg_info:x][noColon][awb_dbg_info:ok]");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo", "AWBDebugInfo"]);
  }

  #[test]
  fn empty_key_becomes_tag() {
    // `[:emptykey]` ⇒ key = "" (defined) ⇒ MakeTagInfo("") ⇒ "Tag". Bundled:
    // DJI:Tag "emptykey".
    let emis = parse_dji_info(b"[ae_dbg_info:x][:emptykey]");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo", "Tag"]);
    assert_eq!(emis[1].value().as_ref(), &TagValue::Str("emptykey".into()));
  }

  #[test]
  fn empty_value_is_binary_zero_bytes() {
    // `[ae_dbg_info:]` ⇒ val = "" ⇒ printable regex needs ≥1 char ⇒ binary.
    // Bundled: "(Binary data 0 bytes, use -b option to extract)".
    let emis = parse_dji_info(b"[ae_dbg_info:]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Bytes(std::vec![]));
  }

  #[test]
  fn trailing_nuls_stripped_from_printable_value() {
    // `hello\0\0\0` ⇒ printable prefix "hello", trailing NULs stripped.
    let emis = parse_dji_info(b"[ae_dbg_info:hello\x00\x00\x00]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("hello".into()));
  }

  #[test]
  fn interior_nul_value_is_binary() {
    // `ab\0cd` ⇒ NUL is interior (non-NUL byte follows) ⇒ binary 5 bytes.
    // Bundled: "(Binary data 5 bytes, …)".
    let emis = parse_dji_info(b"[ae_dbg_info:ab\x00cd]");
    assert_eq!(emis.len(), 1);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Bytes(b"ab\x00cd".to_vec())
    );
  }

  #[test]
  fn nonprintable_value_is_binary() {
    // `\x01\x02\x03\xff\xfe` ⇒ no printable prefix ⇒ binary 5 bytes.
    let emis = parse_dji_info(b"[ae_dbg_info:\x01\x02\x03\xff\xfe]");
    assert_eq!(emis.len(), 1);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Bytes(b"\x01\x02\x03\xff\xfe".to_vec())
    );
  }

  #[test]
  fn trailing_junk_after_last_bracket_yields_nothing() {
    // `[ae_dbg_info:ok]trailingjunk` ⇒ the FIRST `]` is followed by `t` (not
    // `[`/EOS) ⇒ lookahead fails at offset 0 ⇒ whole match fails ⇒ ZERO tags.
    // Bundled emits no DJI tags.
    let emis = parse_dji_info(b"[ae_dbg_info:ok]trailingjunk");
    assert!(emis.is_empty());
  }

  #[test]
  fn interior_junk_extends_capture_via_nongreedy() {
    // `[ae_dbg_info:ok]x[awb_dbg_info:y]` ⇒ the first `]` (after "ok") is
    // followed by `x` ⇒ lookahead fails; `.*?` extends to the FINAL `]`
    // (followed by EOS). So ONE pair: key=ae_dbg_info, val="ok]x[awb_dbg_info:y".
    let emis = parse_dji_info(b"[ae_dbg_info:ok]x[awb_dbg_info:y]");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo"]);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Str("ok]x[awb_dbg_info:y".into())
    );
  }

  #[test]
  fn empty_blob_yields_nothing() {
    assert!(parse_dji_info(b"").is_empty());
  }

  #[test]
  fn non_bracket_start_yields_nothing() {
    // `\G\[` requires `[` at offset 0.
    assert!(parse_dji_info(b"ae_dbg_info:x]").is_empty());
  }

  // ---- Perl `$` = end-of-string OR before ONE final `\n` (default-mode, no
  // /m; /s does not affect `$`). Both the `(?=(\[|$))` bracket lookahead and
  // the `^([\x20-\x7e]+)\0*$` value classifier honor this. Each oracle below
  // was ground-truthed against bundled ExifTool 13.59. ----

  #[test]
  fn bracket_lookahead_succeeds_before_single_final_newline() {
    // `[ae_dbg_info:ok]\n` — the only `]` is followed by a `\n` that is the
    // LAST byte; Perl `$` matches there, so the lookahead succeeds and the pair
    // is captured. Bundled 13.59: DJI:AEDebugInfo "ok".
    let emis = parse_dji_info(b"[ae_dbg_info:ok]\n");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo"]);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("ok".into()));
  }

  #[test]
  fn bracket_lookahead_multi_pair_final_newline_emits_all() {
    // `[ae_dbg_info:a:1][b:2]\n` — interior `]` abuts `[`; the final `]` is
    // before the single trailing `\n`. Both pairs emit. `b` (len 1 < 2) →
    // MakeTagInfo "Tagb". Bundled 13.59: DJI:AEDebugInfo "a:1", DJI:Tagb 2.
    let emis = parse_dji_info(b"[ae_dbg_info:a:1][b:2]\n");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo", "Tagb"]);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("a:1".into()));
    assert_eq!(emis[1].value().as_ref(), &TagValue::Str("2".into()));
  }

  #[test]
  fn bracket_lookahead_two_trailing_newlines_yields_nothing() {
    // `[ae_dbg_info:ok]\n\n` — Perl `$` matches only before the LAST `\n`, so
    // the `]` (followed by `\n\n`, i.e. NOT before-final-`\n`) fails the
    // lookahead; the non-greedy `.*?` finds no later `]` ⇒ the whole match
    // fails ⇒ ZERO tags. Bundled 13.59 emits no DJI tags.
    let emis = parse_dji_info(b"[ae_dbg_info:ok]\n\n");
    assert!(emis.is_empty());
  }

  #[test]
  fn bracket_lookahead_newline_not_last_byte_extends_capture() {
    // `[ae_dbg_info:ok]\n[awb_dbg_info:y]` — the first `]` is followed by `\n`
    // that is NOT the last byte (a `[` follows), so `$` does NOT match there
    // and the next byte is not `[`; the lookahead fails and `.*?` extends to
    // the FINAL `]` (at true EOF). ONE pair, value `ok]\n[awb_dbg_info:y`
    // (contains `]` + a non-NUL/non-printable `\n` ⇒ binary 19 bytes).
    // Bundled 13.59: DJI:AEDebugInfo "(Binary data 19 bytes, …)".
    let emis = parse_dji_info(b"[ae_dbg_info:ok]\n[awb_dbg_info:y]");
    assert_eq!(names(&emis), std::vec!["AEDebugInfo"]);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Bytes(b"ok]\n[awb_dbg_info:y".to_vec())
    );
  }

  #[test]
  fn classify_value_single_final_newline_is_printable() {
    // `[ae_dbg_info:ok\n]` — value is `ok\n`; Perl `$` anchors before the final
    // `\n`, so `ok` is the printable prefix (the trailing `\n` is ignored for
    // the anchor). Bundled 13.59: DJI:AEDebugInfo "ok".
    let emis = parse_dji_info(b"[ae_dbg_info:ok\n]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("ok".into()));
  }

  #[test]
  fn classify_value_two_trailing_newlines_is_binary() {
    // `[ae_dbg_info:ok\n\n]` — value `ok\n\n`; `$` anchors before only the LAST
    // `\n`, leaving `ok\n` — the interior `\n` is neither printable nor a NUL,
    // so the printable/NUL-tail regex fails ⇒ binary (the FULL value, 4 bytes).
    // Bundled 13.59: DJI:AEDebugInfo "(Binary data 4 bytes, …)".
    let emis = parse_dji_info(b"[ae_dbg_info:ok\n\n]");
    assert_eq!(emis.len(), 1);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Bytes(b"ok\n\n".to_vec())
    );
  }

  #[test]
  fn classify_value_nul_then_final_newline_is_printable() {
    // `[ae_dbg_info:ok\0\n]` — value `ok\0\n`; the LAST byte is `\n` ⇒ `$`
    // anchors before it ⇒ `\0*` consumes the interior NUL ⇒ printable `ok`
    // (the NULs are stripped). Bundled 13.59: DJI:AEDebugInfo "ok".
    let emis = parse_dji_info(b"[ae_dbg_info:ok\x00\n]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("ok".into()));
  }

  #[test]
  fn classify_value_newline_then_nul_is_binary() {
    // `[ae_dbg_info:ok\n\0]` — the LAST byte is `\0`, NOT `\n`, so `$` is at
    // true end-of-string; the `\0*` tail then cannot consume the interior `\n`
    // ⇒ the regex fails ⇒ binary (the FULL value, 4 bytes). Bundled 13.59:
    // DJI:AEDebugInfo "(Binary data 4 bytes, …)".
    let emis = parse_dji_info(b"[ae_dbg_info:ok\n\x00]");
    assert_eq!(emis.len(), 1);
    assert_eq!(
      emis[0].value().as_ref(),
      &TagValue::Bytes(b"ok\n\x00".to_vec())
    );
  }

  #[test]
  fn classify_value_lone_newline_is_binary_one_byte() {
    // `[ae_dbg_info:\n]` — value is a single `\n`; trimming it for the `$`
    // anchor leaves an empty run, and the printable regex needs ≥1 char ⇒
    // binary (the full 1-byte value). Bundled 13.59: "(Binary data 1 bytes,…)".
    let emis = parse_dji_info(b"[ae_dbg_info:\n]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Bytes(b"\n".to_vec()));
  }

  #[test]
  fn classify_value_nuls_then_final_newline_is_printable() {
    // `[ae_dbg_info:hello\0\0\n]` — last byte `\n` ⇒ anchor before it ⇒
    // `\0*` consumes both NULs ⇒ printable `hello`. Bundled 13.59:
    // DJI:AEDebugInfo "hello".
    let emis = parse_dji_info(b"[ae_dbg_info:hello\x00\x00\n]");
    assert_eq!(emis.len(), 1);
    assert_eq!(emis[0].value().as_ref(), &TagValue::Str("hello".into()));
  }

  // ---- MakeTagInfo name-derivation unit coverage (ExifTool.pm:9312-9317) ----

  #[test]
  fn make_tag_info_lowercase_underscore_words() {
    // `some_unknown_tag`: `_u`→`_U`, `_t`→`_T` (step 2), then ucfirst ⇒
    // `Some_Unknown_Tag`.
    assert_eq!(make_tag_info_name(b"some_unknown_tag"), "Some_Unknown_Tag");
  }

  #[test]
  fn make_tag_info_short_name_gets_tag_prefix() {
    // length < 2 ⇒ prefix "Tag". `a` ⇒ `Taga`.
    assert_eq!(make_tag_info_name(b"a"), "Taga");
    // empty ⇒ "Tag".
    assert_eq!(make_tag_info_name(b""), "Tag");
  }

  #[test]
  fn make_tag_info_leading_digit_gets_tag_prefix() {
    // `3d`: step-2 uppercases `d` (it follows the non-letter `3`) ⇒ `3D`, then
    // the leading-digit rule prepends `Tag` ⇒ `Tag3D` (verified vs bundled).
    assert_eq!(make_tag_info_name(b"3d"), "Tag3D");
  }

  #[test]
  fn make_tag_info_illegal_chars_deleted() {
    // `tr/-_a-zA-Z0-9//dc` deletes `(`, `,`, `)`. Step 2 first uppercases a
    // lowercase letter following a non-letter (`(a`→`(A`, `,b`→`,B`), then the
    // illegal `(`/`,`/`)` are deleted ⇒ `FooAB`.
    assert_eq!(make_tag_info_name(b"foo(a,b)"), "FooAB");
  }

  #[test]
  fn make_tag_info_acronym_underline_then_capitalize() {
    // Step 1 `s/([A-Z]) ([A-Z][ A-Z])/${1}_$2/g`: `A BC` ⇒ `A_BC`.
    assert_eq!(make_tag_info_name(b"A BC"), "A_BC");
  }
}
