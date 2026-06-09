// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::LigoGPS` (LigoGPS.pm, 431 lines) —
//! the dashcam vendor GPS module used by various MP4/M2TS dashcam
//! firmwares (iiway s1, XGODY 12" 4K, ABASK A8 4K, Rexing V1GW-4K,
//! Kingslim D4, BlueSkySea DV688, Redtiger F9 4K, Yada RoadCam Pro 4K
//! BT58189, …).
//!
//! ## Two reach paths
//!
//! 1. **`&&&& `-prefixed trailer at file end** (QuickTime.pm:9906-9907 +
//!    :10658-10668) — `IdentifyTrailers` reads 40 bytes from `EOF-40` and
//!    matches `/\&\&\&\&(.{4})$/` to extract the trailer length (BE u32 at
//!    `EOF-4`, the 4 bytes immediately after the `&&&&` magic). The full
//!    trailer begins `[size:u32-BE][skip:4-bytes]`
//!    (`skip` ASCII atom name); after those 8 bytes the payload starts
//!    with `LIGOGPSINFO\0` and is passed to [`process_ligogps`].
//! 2. **`LIGOGPSINFO\0`-prefixed embedded sample** (QuickTimeStream.pl
//!    :1843-1888) — bundled detects the fingerprint at offset 16/48/80
//!    inside a `freeGPS` block, sets `LigoGPSScale = 3` when the offset-
//!    16 ABASK A8 4K variant fingerprint hits, and dispatches to
//!    [`process_ligogps`] with `DirStart = $pos`.
//!
//! Both binary paths route through the SAME `ProcessLigoGPS`
//! (LigoGPS.pm:289-320) and are matched on the binary magic `LIGOGPSINFO\0`
//! ONLY (QuickTime.pm:639 / :10661 / QuickTimeStream.pl:1843). The JSON form
//! (`LIGOGPSINFO {`, a space then `{`) is a DIFFERENT ExifTool path — it is
//! reached solely through the `udta` `LigoJSON` / `GKUData` Conditions
//! (QuickTime.pm:835/:842), never through the freeGPS / trailer binary sites
//! (see "JSON variant" below).
//!
//! ## Record format
//!
//! `ProcessLigoGPS` walks the dir starting at `DirStart + 0x14` (the 20
//! bytes past the `LIGOGPSINFO\0\0\0\0\xNN` 0x14-byte preamble) in
//! fixed-stride 0x84 (132)-byte records. Each record is either:
//!  - **`####`-prefixed encrypted record** — decrypted by
//!    [`decrypt_record`] (LigoGPS.pm:50-99). The decrypted output is a
//!    16-byte counter + 4 unknown bytes + ASCII text of the form
//!    `"YYYY/MM/DD HH:MM:SS N:lat W:lon spd km/h A:track H:alt M:magvar
//!    x:ax y:ay z:az"`. Parsed by [`parse_decoded_record`]
//!    (LigoGPS.pm:229-267).
//!  - **Non-encrypted ASCII record (Redtiger F9 4K)** — LigoGPS.pm:304-307.
//!    Same text shape, no `####` prefix; flags = `0x03` (not fuzzed, kph
//!    speed unit).
//!
//! ## Fuzzing
//!
//! Encrypted records have their lat/lon values "fuzzed" by a per-firmware
//! scaling formula. [`unfuzz`] applies the bundled inverse
//! (LigoGPS.pm:38-44):
//!   - `lat2 = int(lat / 10) * 10`
//!   - `lon2 = int(lon / 10) * 10`
//!   - `unfuzzed_lat = lat2 + (lon - lon2) * scale`
//!   - `unfuzzed_lon = lon2 + (lat - lat2) * scale`
//!
//! The scale factor is selected from the per-firmware scale ID (bundled
//! `%gpsScl` lookup: 1 → 1.524855137, 2 → 1.456027985, 3 → 1.15368). The
//! ABASK A8 4K fingerprint at offset 16 forces scale 3
//! (QuickTimeStream.pl:1886).
//!
//! ## JSON variant
//!
//! `ProcessLigoJSON` (LigoGPS.pm:334-398) handles the Yada RoadCam Pro 4K
//! BT58189 dashcam, which writes chained records starting
//! `LIGOGPSINFO {"Hour": "23", ...}`. This is a lighter parser (no
//! decryption, no fuzzing) — [`process_ligogps_json`]. It is reached in
//! production ONLY through the `udta` Conditions (QuickTime.pm:834-846), wired
//! in `quicktime::dispatch_udta_ligogps`:
//!  - `LigoJSON` (QuickTime.pm:835 `^LIGOGPSINFO \{`) → [`process_ligogps_json`].
//!  - `GKUData` (QuickTime.pm:842 `^.{8}__V35AX_QVDATA__`) → [`process_gku`], a
//!    thin wrapper that reads the LE u32 offset at the udta-payload start and
//!    feeds the inner `LIGOGPSINFO {` JSON to [`process_ligogps_json`]
//!    (LigoGPS.pm:273-281).
//!
//! The JSON variant additionally emits `GPSLatitude2`/`GPSLongitude2` from the
//! JSON `OLatitude`/`OLongitude` fields (LigoGPS.pm:387-388). It is NOT reached
//! through the binary freeGPS / trailer detection sites — ExifTool keeps the
//! two LigoGPS encodings on entirely separate dispatch paths.
//!
//! ## DecipherLigoGPS deferral
//!
//! The bundled `DecipherLigoGPS` fallback (LigoGPS.pm:143-221) fires when
//! `DecryptLigoGPS` fails — it accumulates the per-second seconds-digit
//! transitions across multiple records until it can determine a cipher
//! table by sequence inversion. This adds significant multi-record
//! cipher-discovery state with limited real-world utility (modern dashcam
//! files always decode via `DecryptLigoGPS` on the first try). Tracked as
//! FOLLOW-UP under issue #70.
//!
//! ## GPS priority chain
//!
//! LigoGPS records feed the **LOWEST tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from
//! a QuickTime file: GoPro GPMF → Android CAMM → Parrot mett → Sony rtmd
//! → Canon CTMD → Insta360 trailer → SP3 stream → freeGPS-variants →
//! **LigoGPS**. LigoGPS is best-effort dashcam vendor GPS (same tier as
//! the freeGPS-variants and SP3 stream sources); ordered last by
//! implementation arrival.

// Parser-panic-safety by construction: every raw index/slice in the decode
// path is a checked `.get()` (matches the sibling QuickTime parser modules).
#![deny(clippy::indexing_slicing)]

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{LigoGpsMeta, LigoGpsSample};

// ===========================================================================
// Constants
// ===========================================================================

/// Conversion factor knots → km/h (LigoGPS.pm:20).
const KNOTS_TO_KPH: f64 = 1.852;

/// Default speed scale factor for fuzzed encrypted records (LigoGPS.pm:242).
const DEFAULT_FUZZED_SPD_SCL: f64 = 1.85407333;

/// LIGOGPSINFO header magic bytes (the 12-byte ASCII prefix +
/// `LIGOGPSINFO\0`). Length is hard-coded throughout the bundled module.
pub(crate) const HDR_LIGOGPSINFO: &[u8; 12] = b"LIGOGPSINFO\0";

/// JSON-variant LIGOGPSINFO magic (`LIGOGPSINFO {` — a SPACE then `{`).
/// ExifTool distinguishes the JSON `ProcessLigoJSON` form from the binary
/// `ProcessLigoGPS` form by this byte-after-`LIGOGPSINFO` (QuickTime.pm:835
/// `^LIGOGPSINFO \{` / GKU LigoGPS.pm:278 `LIGOGPSINFO {`).
pub(crate) const HDR_LIGOGPSINFO_JSON: &[u8; 13] = b"LIGOGPSINFO {";

/// GKUData `udta` Condition marker (`^.{8}__V35AX_QVDATA__`, QuickTime.pm:842).
/// The 8 bytes preceding the marker carry a LE u32 offset (at byte 0) to the
/// inner `LIGOGPSINFO {` JSON (LigoGPS.pm:277-280 `ProcessGKU`).
pub(crate) const GKU_MARKER: &[u8; 16] = b"__V35AX_QVDATA__";

/// Fixed record stride within `ProcessLigoGPS` (LigoGPS.pm:301 `$pos+=0x84`).
const RECORD_STRIDE: usize = 0x84;

/// The header preamble between the `LIGOGPSINFO\0` magic and the start of
/// records (LigoGPS.pm:293 `$pos = $$dirInfo{DirStart} + 0x14`). The 20-
/// byte preamble is `[LIGOGPSINFO\0][4-byte ver-or-counter][\x01\x14 or
/// random byte][3 bytes]`.
const RECORDS_OFFSET: usize = 0x14;

// ===========================================================================
// Trailer signature constants — QuickTime.pm:9906-9907
// ===========================================================================

/// The 4-byte ASCII signature `"&&&&"` that anchors the LigoGPS trailer
/// (`/\&\&\&\&(.{4})$/`, QuickTime.pm:9906). The trailer DISCOVERY (the magic +
/// the BE u32 length at the captured 4 bytes) lives in the shared
/// `IdentifyTrailers` port [`crate::formats::insta360::identify_trailers`]; this
/// constant is retained only to build the trailer-shape unit fixtures.
#[cfg(test)]
const TRAILER_MAGIC: &[u8; 4] = b"&&&&";

/// Per-`skip`-atom prefix size: the 8-byte `[size:u32-BE][skip]` atom
/// header that QuickTime.pm:10658 reads at the trailer start
/// (`$raf->Read($buff, 8) == 8 and $buff =~ /skip$/i`).
const SKIP_ATOM_HEADER: usize = 8;

// ===========================================================================
// Endian helpers
// ===========================================================================

/// LE u32 — the `####`-encrypted record's output-byte count (LigoGPS.pm:53
/// `Get32u` after `SetByteOrder('II')`).
#[inline]
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map(u32::from_le_bytes)
}

/// BE u32 — the `skip`-atom declared size (QuickTime.pm:10660 `Get32u(buff,0)`
/// in the default `MM` order at the trailer).
#[inline]
fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map(u32::from_be_bytes)
}

// ===========================================================================
// process_trailer — decode a discovered file-end LigoGPS trailer (QuickTime.pm
// :10658-10668)
// ===========================================================================

/// Decode a LigoGPS trailer that [`crate::formats::insta360::identify_trailers`]
/// (the shared port of `IdentifyTrailers`, QuickTime.pm:9897-9926) already
/// LOCATED at `[trailer_start, trailer_start + trailer_len)`. The caller (the
/// `ProcessMOV` trailer loop, [`crate::formats::quicktime`]) owns the discovery
/// (the `&&&&` magic + LE u32 length) and the box-walk-consumed gate, exactly
/// like the Insta360 trailer; this fn does only the LigoGPS-specific PROCESSING
/// (QuickTime.pm:10658-10668).
///
/// `trailer_start` is `$$trailer[1]` (the trailer's absolute file offset) and
/// `trailer_len` is `$$trailer[2]`. The trailer body begins with an 8-byte
/// `[size:u32-BE][skip]` atom header (QuickTime.pm:10658 `$buff =~ /skip$/i`);
/// the inner `Get32u(buff,0) - 16` bytes start with `LIGOGPSINFO\0` and are
/// dispatched to [`process_ligogps`].
///
/// ## Error / pathological cases (faithful to QuickTime.pm:10657-10668)
///
/// - `trailer_start`/`trailer_len` out of range (a bad-size trailer whose
///   declared length exceeds the file) → no-op, no warning (bundled's
///   `Seek($$trailer[1], 0)` fails on the wrapped-negative start ⇒ `last`).
/// - `skip` atom check fails (or the 8-byte read is short) → no-op, no warning
///   (the bundled `if` condition is false ⇒ falls through the `elsif` arms,
///   none of which match a 'LigoGPS'-typed trailer).
/// - `skip` matched but the inner `Get32u-16` length is `<= 0`, the inner read
///   is short, OR the buffer doesn't begin `LIGOGPSINFO\0` → `Unrecognized
///   data in LigoGPS trailer` warning (the bundled `else`, QuickTime.pm:10667).
// TODO(cluster follow-up): ExifTool emits a "Use the ExtractEmbedded option to
// extract embedded GPS" notice when the trailer is present but `-ee` is OFF.
// exifast decodes the trailer unconditionally (decode-always design), so this
// is warning-parity only — no real-input data difference.
pub fn process_trailer(
  data: &[u8],
  trailer_start: usize,
  trailer_len: usize,
  out: &mut LigoGpsMeta,
) {
  let Some(trailer_end) = trailer_start.checked_add(trailer_len) else {
    return;
  };
  // QuickTime.pm:10657 `$raf->Seek($$trailer[1], 0)`. The trailer span must be
  // wholly within the file (a bad-size trailer overruns it → `Get*`/`Read`
  // fails in the reference; here the `.get` is `None` and we bail).
  let Some(trailer) = data.get(trailer_start..trailer_end) else {
    return;
  };
  // QuickTime.pm:10658 `if ($$trailer[0] eq 'LigoGPS' and $raf->Read($buff, 8)
  // == 8 and $buff =~ /skip$/i)`. The 8-byte read is `[size:u32-BE][skip]`; the
  // atom name lives at bytes 4..8, matched case-insensitively per the bundled
  // `/i`. When the 8-byte read OR the `/skip$/i` check FAILS, the whole `if`
  // condition is false: bundled falls through to the `elsif` arms (none match a
  // 'LigoGPS'-typed trailer) and emits NO warning. Mirror that — bail silently.
  let Some(head) = trailer.get(..SKIP_ATOM_HEADER) else {
    return;
  };
  if !head
    .get(4..8)
    .is_some_and(|n| n.eq_ignore_ascii_case(b"skip"))
  {
    return;
  }
  // The `skip` atom matched. From here, bundled is inside the `if` body: any
  // failure of the INNER condition (QuickTime.pm:10661) hits the `else` arm
  // (:10667) ⇒ `Warn('Unrecognized data in LigoGPS trailer')`. The closure
  // returns the decoded `payload` on the full success path, or `None` to warn.
  // The trailer condition is binary-only — `$buff =~ /^LIGOGPSINFO\0/`
  // (QuickTime.pm:10661); the JSON `LIGOGPSINFO {` form is reached solely via
  // the `udta` `LigoJSON` Condition (QuickTime.pm:835), NEVER through the
  // trailer, so this path matches `LIGOGPSINFO\0` only.
  let payload = (|| {
    // QuickTime.pm:10660 `my $len = Get32u(\$buff, 0) - 16`. The skip atom's
    // declared BE size minus 16 (the 8-byte read + an 8-byte inner header). In
    // Perl this is signed: an `atom_size < 16` yields `$len <= 0`, failing the
    // `$len > 0` guard. Mirror with `checked_sub` (→ `None` ⇒ warn).
    let atom_size = be_u32(head, 0)? as usize;
    let inner_len = atom_size.checked_sub(16)?;
    // QuickTime.pm:10661 `$len > 0`.
    if inner_len == 0 {
      return None;
    }
    // QuickTime.pm:10661 `$raf->Read($buff, $len) == $len` — the inner buffer is
    // `inner_len` bytes read from `trailer_start + 8`. A short read (the bytes
    // are not all present before the trailer end) fails the `== $len` guard.
    let payload_end = SKIP_ATOM_HEADER.checked_add(inner_len)?;
    let payload = trailer.get(SKIP_ATOM_HEADER..payload_end)?;
    // QuickTime.pm:10661 `$buff =~ /^LIGOGPSINFO\0/` — binary form only.
    if payload.get(..HDR_LIGOGPSINFO.len()) == Some(HDR_LIGOGPSINFO.as_slice()) {
      Some(payload)
    } else {
      None
    }
  })();
  let Some(payload) = payload else {
    // QuickTime.pm:10667 `$et->Warn('Unrecognized data in LigoGPS trailer')`.
    out.set_warning(SmolStr::new("Unrecognized data in LigoGPS trailer"));
    return;
  };
  // QuickTime.pm:10663-10665 `Image::ExifTool::LigoGPS::ProcessLigoGPS($et,
  // \%dirInfo, $tbl)`. The bundled `%dirInfo` carries no `DirStart`, so it
  // defaults to 0: the buffer starts with the `LIGOGPSINFO\0` magic and record
  // dispatch begins at offset 0x14 inside it (LigoGPS.pm:293).
  process_ligogps(payload, 0, out, /*no_fuzz=*/ false);
}

// ===========================================================================
// process_ligogps — main walker, LigoGPS.pm:289-320
// ===========================================================================

/// Faithful port of `Image::ExifTool::LigoGPS::ProcessLigoGPS`
/// (LigoGPS.pm:289-320). Walks `data` starting at `dir_start + 0x14` in
/// fixed `0x84`-byte strides; each record is either a `####`-prefixed
/// encrypted record (decrypted by [`decrypt_record`] + parsed by
/// [`parse_decoded_record`]) or a plain ASCII LIGOGPSINFO record
/// (Redtiger F9 4K variant — LigoGPS.pm:304-307).
///
/// `no_fuzz = true` skips the unfuzz step (LigoGPS.pm:248) — set by the
/// trailer code path AND by the BlueSkySeaDV688 / unknown-0x14 firmware
/// detection (LigoGPS.pm:299).
///
/// `ligogps_scale` is the per-file fuzz scale ID (1/2/3, mapping to the
/// `%gpsScl` table at LigoGPS.pm:241). The freeGPS embedded path uses
/// `Some(3)` for the offset-16 ABASK A8 4K fingerprint
/// (QuickTimeStream.pl:1886); the trailer path uses `None` (defaults to
/// scale = 1.0, i.e. no rescale beyond the integer-overflow defuzz).
pub fn process_ligogps(data: &[u8], dir_start: usize, out: &mut LigoGpsMeta, no_fuzz: bool) {
  process_ligogps_with_scale(data, dir_start, out, no_fuzz, None);
}

/// `process_ligogps` variant accepting an explicit per-file fuzz scale
/// ID (Some(1)/Some(2)/Some(3)) — used by the freeGPS embedded path to
/// pass `LigoGPSScale = 3` for the ABASK A8 4K firmware
/// (QuickTimeStream.pl:1886).
pub fn process_ligogps_with_scale(
  data: &[u8],
  dir_start: usize,
  out: &mut LigoGpsMeta,
  mut no_fuzz: bool,
  ligogps_scale: Option<u32>,
) {
  // LigoGPS.pm:293 `$pos = ($$dirInfo{DirStart} || 0) + 0x14`.
  let mut pos = dir_start.saturating_add(RECORDS_OFFSET);
  // LigoGPS.pm:294 `return undef if $pos > length $$dataPt`.
  if pos > data.len() {
    return;
  }
  // LigoGPS.pm:299 `$noFuzz = 1 if substr($$dataPt, $pos-8, 4) =~
  // /^\0\0\0[\x01\x14]/`. The 4 bytes at `pos-8` start `\0\0\0` and end
  // with `\x01` (BlueSkySeaDV688) or `\x14` (unknown) → don't unfuzz.
  if pos >= 8 && matches!(data.get(pos - 8..pos - 4), Some([0, 0, 0, 0x01 | 0x14])) {
    no_fuzz = true;
  }
  // LigoGPS.pm:301 `for (; $pos + 0x84 <= length($$dataPt); $pos += 0x84)`.
  while pos + RECORD_STRIDE <= data.len() {
    // The `while` guard proves `pos + RECORD_STRIDE <= data.len()`, so this
    // `.get` is always `Some`; `break` on the impossible miss is byte-identical.
    let Some(rec) = data.get(pos..pos + RECORD_STRIDE) else {
      break;
    };
    pos += RECORD_STRIDE;

    // LigoGPS.pm:303-309 — non-encrypted ASCII record (Redtiger F9 4K).
    // The bundled `next unless $dat =~ m(^.{4}\d{4}/\d{2}/\d{2} )s` allows
    // 4-byte counter + ASCII date prefix.
    if !rec.starts_with(b"####") {
      if is_plain_ascii_date_record(rec) {
        // LigoGPS.pm:306 `$dat =~ s/\0+$//`. Strip trailing nulls.
        let trimmed = strip_trailing_nulls(rec);
        // LigoGPS.pm:307 `ParseLigoGPS($et, $dat, $tagTbl, 0x03)` — flag
        // 0x03 = not fuzzed (0x01) AND km/h speed (0x02).
        parse_decoded_record(trimmed, 0x03, ligogps_scale, no_fuzz, out);
      }
      // (otherwise: bundled `next` — silently skip blank/null records).
      continue;
    }
    // LigoGPS.pm:311 — bundled would attempt `DecipherLigoGPS` first if a
    // cipher table is already known. We DEFER cipher discovery (issue
    // #70 FOLLOW-UP), so the only path is `DecryptLigoGPS`.
    let Some(decoded) = decrypt_record(rec) else {
      // LigoGPS.pm:313 — `defined $str or DecipherLigoGPS(...), next`.
      // Cipher discovery is deferred; record a one-time warning so the
      // file's diagnostic is visible.
      out.set_warning(SmolStr::new(
        "LigoGPS record decryption failed (cipher discovery deferred)",
      ));
      continue;
    };
    // LigoGPS.pm:315 `ParseLigoGPS($et, $str, $tagTbl, $noFuzz)`.
    // `$noFuzz` is just the 0x01 bit; speed-units bit (0x02) is unset
    // for encrypted records (so speed uses the LigoGPS-internal scale
    // factor 1.85407333).
    let flags = if no_fuzz { 0x01 } else { 0x00 };
    parse_decoded_record(&decoded, flags, ligogps_scale, no_fuzz, out);
  }
}

/// Return `true` when the bundled `m(^.{4}\d{4}/\d{2}/\d{2} )s` pattern
/// matches (LigoGPS.pm:304). The first 4 bytes are arbitrary (counter),
/// then 10 bytes of `YYYY/MM/DD ` ASCII.
fn is_plain_ascii_date_record(rec: &[u8]) -> bool {
  // Bytes 4..15 = `YYYY/MM/DD ` (the 4-byte counter precedes it). A slice
  // pattern binds the 11 bytes and bounds-checks in one step.
  let Some(&[y0, y1, y2, y3, sl0, m0, m1, sl1, d0, d1, sp]) = rec.get(4..15) else {
    return false;
  };
  y0.is_ascii_digit()
    && y1.is_ascii_digit()
    && y2.is_ascii_digit()
    && y3.is_ascii_digit()
    && sl0 == b'/'
    && m0.is_ascii_digit()
    && m1.is_ascii_digit()
    && sl1 == b'/'
    && d0.is_ascii_digit()
    && d1.is_ascii_digit()
    && sp == b' '
}

/// Strip trailing `\0` bytes (LigoGPS.pm:306 `$dat =~ s/\0+$//`).
fn strip_trailing_nulls(rec: &[u8]) -> &[u8] {
  let mut end = rec.len();
  while end > 0 && rec.get(end - 1) == Some(&0) {
    end -= 1;
  }
  rec.get(..end).unwrap_or(rec)
}

// ===========================================================================
// decrypt_record — LigoGPS.pm:50-99 `DecryptLigoGPS`
// ===========================================================================

/// Faithful port of `Image::ExifTool::LigoGPS::DecryptLigoGPS`
/// (LigoGPS.pm:50-99). Decrypts one `####`-prefixed encrypted record. The
/// 8-byte header is `####` (4 bytes) + `[u32-LE counter]` (4 bytes). The
/// 4-byte LE u32 immediately after `####` is the number of OUTPUT bytes
/// (capped at 0x84 — record-stride safety).
///
/// The decryption operates byte-by-byte, where each input byte's upper
/// 3 bits steer one of four decryption modes (4 output bytes from 5
/// input, 4 from 4, 4 from 4 in a different layout, 1 from 2). Returns
/// the decoded ASCII text (the 4-byte counter is RE-PRESERVED at the
/// start), or `None` on a malformed cipher stream.
pub(crate) fn decrypt_record(rec: &[u8]) -> Option<Vec<u8>> {
  // LigoGPS.pm:53 `my $num = unpack('x4V', $str)`. The 4-byte LE u32 at
  // offset 4 is the OUTPUT-byte count (bundled output buffer size).
  if rec.len() < 8 {
    return None;
  }
  let mut num = le_u32(rec, 4)? as usize;
  // LigoGPS.pm:54 `return undef if $num < 4`.
  if num < 4 {
    return None;
  }
  // LigoGPS.pm:55 `$num = 0x84 if $num > 0x84`.
  if num > 0x84 {
    num = 0x84;
  }
  // LigoGPS.pm:56 `my @in = unpack("x8C$num", $str)` — take `num` input
  // bytes starting at offset 8.
  let in_end = 8usize.checked_add(num)?;
  let mut input = rec.get(8..in_end)?.iter().copied();
  // Output preserved header — bundled keeps the 4-byte counter at the
  // start (caller re-prepends it). We allocate enough headroom for the
  // 4 output bytes per steering round; +4 for the header. The output
  // CANNOT exceed 0x80 + 4 = 0x84.
  let mut out: Vec<u8> = Vec::with_capacity(0x84);
  // Caller (ParseLigoGPS) re-adds the 4-byte header from the rec; we
  // emit only the decrypted body (LigoGPS.pm:217 `"$pre$str"` where
  // `$pre = substr($str, 4, 4)`). But ProcessLigoGPS calls ParseLigoGPS
  // directly with the OUTPUT of DecryptLigoGPS. Looking at LigoGPS.pm:315
  // — `ParseLigoGPS($et, $str, $tagTbl, $noFuzz)` — passes the decrypted
  // string `$str` directly. ParseLigoGPS expects ".{4}DATE TIME..." so
  // the first 4 bytes of the OUTPUT are the counter (LigoGPS.pm:225-227).
  // Bundled DecryptLigoGPS includes the counter in `@out`? Let me re-read:
  // LigoGPS.pm:98 `return pack 'C*', @out`. `@out` is filled exclusively
  // by the steering-decryption pushes. So the counter is NOT in `@out`.
  // Then where does ParseLigoGPS's `.{4}` come from? Reading more
  // carefully: LigoGPS.pm:53 `$num = unpack('x4V', $str)`. `'x4'` skips
  // 4 bytes then reads V (u32-LE). So the LE u32 is at offset 4. But the
  // OUTPUT `@out` is just the decrypted body. ParseLigoGPS at :231 does
  // `$str =~ /^.{4}(\S+ \S+)\s+/` — the `.{4}` matches FOUR ARBITRARY
  // BYTES at the start. So ParseLigoGPS is being given OUTPUT that has
  // some 4-byte header. Where is that header? In ProcessLigoGPS at :315
  // we see ParseLigoGPS called with `$str` (the OUTPUT of DecryptLigoGPS).
  // Wait — re-reading LigoGPS.pm:314: `$et->VPrint(... unpack('V',$str)
  // ...)` — the verbose print extracts the FIRST u32 of `$str` as the
  // counter. So the counter IS the first 4 bytes of `$str`. Looking at
  // LigoGPS.pm:51-98, `@out` is the DECRYPTED body. The verbose at :314
  // reads `unpack('V', $str)` — but `$str` here is the SAME `$str` that
  // was passed to ProcessLigoGPS (the OUTPUT). So `@out` DOES contain
  // the counter; the cipher emits 4 bytes per round and one of those
  // rounds emits the counter. Reading the encryption code more carefully:
  // the loop runs `num` rounds; each round emits 1 or 4 output bytes.
  // The TOTAL output size = sum of per-round outputs. For ParseLigoGPS
  // to see `.{4}` followed by the date, the FIRST 4 output bytes are
  // the counter — that is, the FIRST decryption round emits 4 bytes
  // (the counter). All subsequent rounds emit the ASCII payload.
  //
  // So the output is just `@out` — no separate prepend needed. Good.
  while let Some(b) = input.next() {
    let steering = b & 0xe0;
    if steering >= 0xc0 {
      // LigoGPS.pm:62-67 — next 4 bytes are encrypted data.
      let i1 = input.next()?;
      let i2 = input.next()?;
      let i3 = input.next()?;
      let i4 = input.next()?;
      out.push((i1 | (b & 0x01)) ^ 0x20);
      out.push((i2 | (b & 0x02)) ^ 0x20);
      out.push((i3 | (b & 0x0c)) ^ 0x20);
      // LigoGPS.pm:67 `shift(@in) ^ 0x20 | $b & 0x30` — note the Perl
      // precedence: `^` binds tighter than `|`, so this is
      // `(shift(@in) ^ 0x20) | ($b & 0x30)`.
      out.push((i4 ^ 0x20) | (b & 0x30));
    } else if steering >= 0x40 {
      // LigoGPS.pm:68-90 — next 3 bytes are encrypted data with one of
      // four sub-modes by the exact steering value.
      let i1 = input.next()?;
      let i2 = input.next()?;
      let i3 = input.next()?;
      match steering {
        0x40 => {
          // LigoGPS.pm:70-74
          out.push(0x20);
          out.push((i1 | (b & 0x01)) ^ 0x20);
          out.push((i2 | (b & 0x06)) ^ 0x20);
          out.push((i3 | (b & 0x18)) ^ 0x20);
        }
        0x60 => {
          // LigoGPS.pm:75-79
          out.push((i1 | (b & 0x03)) ^ 0x20);
          out.push(0x20);
          out.push((i2 | (b & 0x04)) ^ 0x20);
          out.push((i3 | (b & 0x18)) ^ 0x20);
        }
        0x80 => {
          // LigoGPS.pm:80-84
          out.push((i1 | (b & 0x03)) ^ 0x20);
          out.push((i2 | (b & 0x0c)) ^ 0x20);
          out.push(0x20);
          out.push((i3 | (b & 0x10)) ^ 0x20);
        }
        _ => {
          // LigoGPS.pm:85-89 — the bundled `else` covers `0xa0`.
          out.push((i1 | (b & 0x01)) ^ 0x20);
          out.push((i2 | (b & 0x06)) ^ 0x20);
          out.push((i3 | (b & 0x18)) ^ 0x20);
          out.push(0x20);
        }
      }
    } else if steering == 0x00 {
      // LigoGPS.pm:91-93 — next byte is encrypted data (single-output).
      let i1 = input.next()?;
      out.push(i1 | (b & 0x13));
    } else {
      // LigoGPS.pm:94-96 — bundled `else { return undef }`. Shouldn't
      // happen on valid input; we propagate the failure.
      return None;
    }
  }
  Some(out)
}

// ===========================================================================
// parse_decoded_record — LigoGPS.pm:229-267 `ParseLigoGPS`
// ===========================================================================

/// Parse a decrypted-or-plain LIGOGPSINFO text record. The buffer is
/// `[4 bytes counter][YYYY/MM/DD HH:MM:SS] [LATREF]:[neg?]LAT [LONREF]:
/// [neg?]LON SPEED [optional " km/h"] [optional " A:TRK"] [optional " H:ALT"]
/// [optional " M:MAGVAR"] [optional " x:AX y:AY z:AZ"]`.
///
/// `flags` is the bundled `$flags`:
///  - `0x01` = NOT fuzzed (skip the `UnfuzzLigoGPS` step).
///  - `0x02` = speed is already in km/h (skip the knots→km/h conversion).
///
/// `scale_id` is the per-file `LigoGPSScale` (LigoGPS.pm:249) — drives
/// the `%gpsScl` lookup at LigoGPS.pm:241 (1 → 1.524855137 / 2 →
/// 1.456027985 / 3 → 1.15368).
pub(crate) fn parse_decoded_record(
  buf: &[u8],
  flags: u8,
  scale_id: Option<u32>,
  no_fuzz_override: bool,
  out: &mut LigoGpsMeta,
) {
  // Re-apply the `0x01` bit if the caller said `no_fuzz_override` (LigoGPS
  // .pm:248 reads `$flags & 0x01` — so we OR it in).
  let flags = if no_fuzz_override {
    flags | 0x01
  } else {
    flags
  };

  // First 4 bytes are the counter (LigoGPS.pm:235 `^.{4}`); the rest is the
  // text body. Bundled tolerates trailing zero pads (the `parse_ligogps`
  // regex anchors are tolerant). Use lossy UTF-8 — the text is ASCII per the
  // format spec but a malformed record may carry garbage. A buffer shorter
  // than the 4-byte counter has no body (`.get(4..)` is `None`) ⇒ early
  // return; an empty body parses to no sample (the date regex needs content).
  let Some(body_bytes) = buf.get(4..) else {
    return;
  };
  let body = match core::str::from_utf8(body_bytes) {
    Ok(s) => s,
    Err(_) => {
      // Try lossy: strip non-UTF8 bytes by taking the longest valid
      // prefix (everything up to the first NUL).
      let cut = body_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(body_bytes.len());
      body_bytes
        .get(..cut)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
    }
  };
  // Bundled regex (LigoGPS.pm:235):
  //   /^.{4}(\S+ \S+)\s+([NS?]):(-?)([.\d]+)\s+([EW?]):(-?)([\.\d]+)\s+([.\d]+)/s
  // (note `.{4}` is already consumed by our slice). The captures:
  //   1: "YYYY/MM/DD HH:MM:SS"
  //   2: "N"|"S"|"?"
  //   3: "-" or empty (lat sign)
  //   4: lat magnitude (e.g. "31.285065")
  //   5: "E"|"W"|"?"
  //   6: "-" or empty (lon sign)
  //   7: lon magnitude
  //   8: speed magnitude
  let Some(fields) = parse_lead_fields(body) else {
    out.set_warning(SmolStr::new("LIGOGPSINFO format error"));
    return;
  };
  let (date_time_str, lat_ref, lat_neg, mut lat, lon_ref, lon_neg, mut lon, spd_raw) = fields;

  // LigoGPS.pm:244 — `$time =~ tr(/)(:)` — normalise the date separators.
  let date_time = date_time_str.replace('/', ":");

  // LigoGPS.pm:241-242 — speed scale lookup.
  let mut spd_scl = if flags & 0x01 != 0 {
    if flags & 0x02 != 0 {
      // km/h record, no scaling.
      1.0
    } else {
      // knots record, convert.
      KNOTS_TO_KPH
    }
  } else {
    DEFAULT_FUZZED_SPD_SCL
  };

  // LigoGPS.pm:247 — DDMM.MMMMMM detection: if the lat magnitude has 3
  // leading digits before the first decimal (bundled `$lat =~ /^\d{3}/`),
  // the format is degrees+minutes (NMEA-style) and we re-scale to
  // decimal degrees. The bundled regex matches when the magnitude is
  // ≥ 100 (3-digit integer part).
  if has_three_leading_digits_f64(lat) {
    convert_lat_lon_dm_to_decimal(&mut lat, &mut lon);
    spd_scl = 1.0; // bundled comment: "speed wasn't scaled in my 1 sample"
  }

  // LigoGPS.pm:248-252 — unfuzz the coordinates if `flags & 0x01 == 0`.
  //   my $scl = $$et{OPTIONS}{LigoGPSScale} || $$et{LigoGPSScale} || 1;
  //   $scl = $gpsScl{$scl} if $gpsScl{$scl};
  // The UNSET scale defaults to `1`, which then remaps through
  // `%gpsScl{1} = 1.524855137` (LigoGPS.pm:241,249-250) — NOT a literal 1.0.
  // A scale ID outside `%gpsScl{1,2,3}` passes through as its raw numeric
  // value (the `$gpsScl{$scl}` guard leaves `$scl` unchanged on a miss).
  if flags & 0x01 == 0 {
    let scl = match scale_id {
      None | Some(1) => 1.524855137_f64,
      Some(2) => 1.456027985_f64,
      Some(3) => 1.15368_f64,
      Some(n) => f64::from(n),
    };
    let (ul, ulon) = unfuzz(lat, lon, scl);
    lat = ul;
    lon = ulon;
  }

  // LigoGPS.pm:254 — the final sanity check, which runs AFTER LigoGPS.pm:243
  // `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`. So a rejected (out-of-range) record has
  // ALREADY burned a global `Doc<N>`: push a doc-consuming-but-suppressed
  // placeholder so the deferred `stamp_doc_from` advances the shared counter for
  // it (the NEXT good record's `Doc<N>` is this burned slot's successor),
  // matching bundled. It emits no GPS tags, only the warning. (Contrast the
  // LigoGPS.pm:236-237 format-error / the :312-313 decrypt-failure returns, which
  // are BEFORE the :243 bump and so do NOT burn a doc — left untouched.)
  if lat > 90.0 || lon > 180.0 {
    out.set_warning(SmolStr::new("LIGOGPSINFO coordinates out of range"));
    out.push_sample(LigoGpsSample::new_suppressed());
    return;
  }

  // LigoGPS.pm:256-263 — emit the GPS tags.
  let mut sample = LigoGpsSample::new();
  sample.set_date_time(Some(SmolStr::new(date_time)));
  // LigoGPS.pm:258 — `$lat * (($latNeg or $latRef eq 'S') ? -1 : 1)`.
  let lat_signed = if lat_neg || lat_ref == 'S' { -lat } else { lat };
  // LigoGPS.pm:259 — `$lon * (($lonNeg or $lonRef eq 'W') ? -1 : 1)`.
  let lon_signed = if lon_neg || lon_ref == 'W' { -lon } else { lon };
  sample.set_latitude(Some(lat_signed));
  sample.set_longitude(Some(lon_signed));
  // LigoGPS.pm:260 — `$spd * $spdScl`.
  sample.set_speed_kph(Some(spd_raw * spd_scl));

  // LigoGPS.pm:261-265 — optional fields (Track, Altitude, MagVar, Accel).
  if let Some(v) = extract_value(body, " A:") {
    sample.set_track_deg(Some(v));
  }
  if let Some(v) = extract_value(body, " H:") {
    sample.set_altitude_m(Some(v));
  }
  if let Some(v) = extract_value(body, " M:") {
    sample.set_magnetic_variation(Some(v));
  }
  if let Some((ax, ay, az)) = extract_acceleration(body) {
    // LigoGPS.pm:265 — `"$1 $2 $3"`. The bundled tab-separator is
    // accepted by `\s` in the regex; we space-join in the output.
    let mut s = String::with_capacity(24);
    s.push_str(ax);
    s.push(' ');
    s.push_str(ay);
    s.push(' ');
    s.push_str(az);
    sample.set_accelerometer(Some(SmolStr::new(s)));
  }
  out.push_sample(sample);
}

/// Decoded `ParseLigoGPS` lead-line fields (LigoGPS.pm:235 regex captures).
/// Tuple components: `(date_time_str, lat_ref, lat_neg, lat_magnitude,
/// lon_ref, lon_neg, lon_magnitude, speed_raw)`.
type LeadFields = (String, char, bool, f64, char, bool, f64, f64);

/// Parse the lead-line fields. Faithful to the bundled regex
/// `^(\S+ \S+)\s+([NS?]):(-?)([.\d]+)\s+([EW?]):(-?)([\.\d]+)\s+([.\d]+)`
/// (LigoGPS.pm:235).
fn parse_lead_fields(body: &str) -> Option<LeadFields> {
  // Field 1: \S+ \S+ — date + " " + time. Walk to first whitespace
  // (date), then through following whitespace, then to the next
  // whitespace (time). The bundled regex (LigoGPS.pm:235) captures ANY
  // non-space `\S+` date token — it does NOT require slashes; the date is
  // then normalised by `tr(/)(:)` (LigoGPS.pm:244, applied downstream in
  // `parse_decoded_record`), a NO-OP for an already-colon / dash date. So a
  // record ExifTool accepts with e.g. `2024-01-15` must NOT be dropped here:
  // do not impose a slash-only guard (the dropped record would lose its GPS
  // fix AND shift every following `Doc<N>` below the oracle, since the
  // out-of-range doc-burn at LigoGPS.pm:243 has already consumed an ordinal).
  let date_end = body.find(char::is_whitespace)?;
  let date = &body[..date_end];
  let after_date = body[date_end..].trim_start();
  let time_end = after_date.find(char::is_whitespace)?;
  let time = &after_date[..time_end];

  let mut date_time = String::with_capacity(date.len() + 1 + time.len());
  date_time.push_str(date);
  date_time.push(' ');
  date_time.push_str(time);

  let tail = after_date[time_end..].trim_start();

  // Lat ref + sign + magnitude.
  let (lat_ref, after_lat_ref) = take_ref(tail, &['N', 'S', '?'])?;
  if !after_lat_ref.starts_with(':') {
    return None;
  }
  let after_colon = &after_lat_ref[1..];
  let (lat_neg, after_lat_sign) = if let Some(stripped) = after_colon.strip_prefix('-') {
    (true, stripped)
  } else {
    (false, after_colon)
  };
  let (lat_mag_str, after_lat) = take_numeric(after_lat_sign)?;
  let lat: f64 = lat_mag_str.parse().ok()?;
  let after_lat = after_lat.trim_start();

  // Lon ref + sign + magnitude.
  let (lon_ref, after_lon_ref) = take_ref(after_lat, &['E', 'W', '?'])?;
  if !after_lon_ref.starts_with(':') {
    return None;
  }
  let after_colon = &after_lon_ref[1..];
  let (lon_neg, after_lon_sign) = if let Some(stripped) = after_colon.strip_prefix('-') {
    (true, stripped)
  } else {
    (false, after_colon)
  };
  let (lon_mag_str, after_lon) = take_numeric(after_lon_sign)?;
  let lon: f64 = lon_mag_str.parse().ok()?;
  let after_lon = after_lon.trim_start();

  // Speed magnitude.
  let (spd_str, _) = take_numeric(after_lon)?;
  let spd: f64 = spd_str.parse().ok()?;

  Some((date_time, lat_ref, lat_neg, lat, lon_ref, lon_neg, lon, spd))
}

/// Take a single character if it's one of the allowed reference chars
/// (`['N', 'S', '?']` for latitude, `['E', 'W', '?']` for longitude).
fn take_ref<'a>(s: &'a str, allowed: &[char]) -> Option<(char, &'a str)> {
  let mut chars = s.chars();
  let first = chars.next()?;
  if allowed.contains(&first) {
    Some((first, &s[first.len_utf8()..]))
  } else {
    None
  }
}

/// Take the longest numeric prefix (`[.\d]+` per LigoGPS.pm:235).
fn take_numeric(s: &str) -> Option<(&str, &str)> {
  let end = s
    .char_indices()
    .take_while(|(_, c)| c.is_ascii_digit() || *c == '.')
    .last()
    .map(|(i, c)| i + c.len_utf8())
    .unwrap_or(0);
  if end == 0 {
    return None;
  }
  Some((&s[..end], &s[end..]))
}

/// `true` when `s` starts with at least 3 digits (LigoGPS.pm:247
/// `$lat =~ /^\d{3}/` — the bundled regex matches when the FIRST 3
/// characters are digits, no anchor on what follows). Used by the
/// tests; the production path uses [`has_three_leading_digits_f64`]
/// which avoids the string→f64 reparse.
#[cfg(test)]
fn has_three_leading_digits(s: &str) -> bool {
  s.chars().take(3).filter(|c| c.is_ascii_digit()).count() == 3
}

/// `true` when the lat magnitude has a 3-digit integer part — equivalent
/// to the bundled `$lat =~ /^\d{3}/` regex once the magnitude is parsed
/// as f64. Matches when the integer part is in `100..=9999` (4-digit
/// max for the bundled DDMM format).
fn has_three_leading_digits_f64(lat: f64) -> bool {
  let trunc = lat.trunc();
  (100.0..10000.0).contains(&trunc)
}

/// Faithful port of `Image::ExifTool::QuickTime::ConvertLatLon`
/// (referenced from LigoGPS.pm:247). Bundled converts DDMM.MMMMMM →
/// DD.DDDDDD in-place: `$_ = int($_/100) + ($_ - int($_/100)*100) / 60
/// foreach ($lat, $lon)`.
fn convert_lat_lon_dm_to_decimal(lat: &mut f64, lon: &mut f64) {
  for v in [lat, lon] {
    let degrees = (*v / 100.0).trunc();
    let minutes = *v - degrees * 100.0;
    *v = degrees + minutes / 60.0;
  }
}

/// Faithful port of `UnfuzzLigoGPS` (LigoGPS.pm:38-44):
///   `$lat2 = int($lat/10) * 10`
///   `$lon2 = int($lon/10) * 10`
///   `return ($lat2 + ($lon - $lon2) * $scl, $lon2 + ($lat - $lat2) * $scl)`.
fn unfuzz(lat: f64, lon: f64, scl: f64) -> (f64, f64) {
  let lat2 = (lat / 10.0).trunc() * 10.0;
  let lon2 = (lon / 10.0).trunc() * 10.0;
  (lat2 + (lon - lon2) * scl, lon2 + (lat - lat2) * scl)
}

/// Extract a numeric value following the `key` literal (e.g. `" A:"`,
/// `" H:"`, `" M:"`). Bundled regex pattern `\bA:(\S+)` —
/// LigoGPS.pm:261-263.
// TODO(cluster follow-up): the bundled `\b` word boundary before `A:`/`H:`/`M:`
// matches at more positions than a literal leading space (e.g. start-of-string
// or after punctuation). Real records use the space separator shown in the
// sample, so this is a CRAFTED/hostile-input faithfulness edge only.
fn extract_value(body: &str, key: &str) -> Option<f64> {
  let idx = body.find(key)?;
  let after = &body[idx + key.len()..];
  // Take \S+ (any non-whitespace).
  let end = after
    .find(|c: char| c.is_ascii_whitespace())
    .unwrap_or(after.len());
  after[..end].parse().ok()
}

/// Extract the 3-axis accelerometer triplet (LigoGPS.pm:265 regex
/// `x:(\S+)\sy:(\S+)\sz:(\S+)`). Returns `(ax, ay, az)` as substring
/// references into `body`.
fn extract_acceleration(body: &str) -> Option<(&str, &str, &str)> {
  let xi = body.find("x:")?;
  let after_x = &body[xi + 2..];
  let xe = after_x
    .find(|c: char| c.is_ascii_whitespace())
    .unwrap_or(after_x.len());
  let ax = &after_x[..xe];
  let rest_after_x = &after_x[xe..].trim_start();
  let after_y = rest_after_x.strip_prefix("y:")?;
  let ye = after_y
    .find(|c: char| c.is_ascii_whitespace())
    .unwrap_or(after_y.len());
  let ay = &after_y[..ye];
  let rest_after_y = &after_y[ye..].trim_start();
  let after_z = rest_after_y.strip_prefix("z:")?;
  let ze = after_z
    .find(|c: char| c.is_ascii_whitespace())
    .unwrap_or(after_z.len());
  let az = &after_z[..ze];
  Some((ax, ay, az))
}

// ===========================================================================
// process_ligogps_json — LigoGPS.pm:334-398 `ProcessLigoJSON`
// ===========================================================================

/// Faithful port of `Image::ExifTool::LigoGPS::ProcessLigoJSON`
/// (LigoGPS.pm:334-398) — the JSON-format variant used by the Yada
/// RoadCam Pro 4K BT58189 dashcam (chained 512-byte records starting
/// with `LIGOGPSINFO {`).
///
/// Walks `data` for every `LIGOGPSINFO {…}` segment and decodes the
/// inner JSON into a [`LigoGpsSample`]. Only `status == "A"` records
/// produce a sample (LigoGPS.pm:353).
///
/// The bundled `while ($$dataPt =~ /LIGOGPSINFO (\{.*?\})/g)` (LigoGPS.pm:342)
/// matches on the RAW byte string — the `GKUData` / `LigoJSON` `udta`
/// containers are BINARY (a JSON object followed by binary padding, FINDING 2),
/// so requiring the whole payload to be UTF-8 would reject a valid record. We
/// mirror Perl: locate `LIGOGPSINFO {` on BYTES, take the braced object up to
/// its matching `}` (the non-greedy `\{.*?\}` — `.` matches any byte EXCEPT
/// newline since there is no `/s` flag), and UTF-8-convert ONLY that object for
/// parsing. A non-UTF-8 braced object is skipped (the digit/quote JSON the
/// decoder reads is ASCII).
pub fn process_ligogps_json(data: &[u8], out: &mut LigoGpsMeta) {
  let mut search_start = 0;
  while let Some(rel) = find_subslice(
    data.get(search_start..).unwrap_or_default(),
    b"LIGOGPSINFO {",
  ) {
    // Position of the `{` (the captured group starts at the brace — the literal
    // space in `LIGOGPSINFO ` is consumed before the capture).
    let brace = search_start + rel + b"LIGOGPSINFO ".len();
    // The non-greedy `\{.*?\}` captures up to the FIRST `}` reachable without
    // crossing a newline (`.` does not match `\n` without `/s`). A `\n` before
    // any `}` fails the match at this start → advance past the magic and retry.
    let Some(close) = find_brace_close(data, brace) else {
      search_start = brace;
      continue;
    };
    let json_end = close + 1;
    // UTF-8-convert ONLY the braced object (NOT the trailing binary padding).
    if let Some(json_text) = data
      .get(brace..json_end)
      .and_then(|b| core::str::from_utf8(b).ok())
      && let Some(mut sample) = decode_ligo_json_object(json_text)
    {
      // FINDING 1 — tag the JSON family so the emitter applies ProcessLigoJSON's
      // no-`ee` FIRST-record semantics (LigoGPS.pm:390-393).
      sample.set_source(crate::metadata::LigoSource::UdtaJson);
      out.push_sample(sample);
    }
    search_start = json_end;
  }
}

/// Byte-substring search (no UTF-8 requirement). Returns the index of the first
/// occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() {
    return Some(0);
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find the matching `}` for the `{` at `brace`, scanning forward on BYTES.
/// Mirrors the non-greedy `\{.*?\}` without `/s`: stop (no match) at a newline
/// (`\n`, 0x0A) before any `}` — `.` does not match `\n`. Returns the absolute
/// index of the closing brace.
fn find_brace_close(data: &[u8], brace: usize) -> Option<usize> {
  let rest = data.get(brace + 1..)?;
  for (i, &b) in rest.iter().enumerate() {
    match b {
      b'}' => return Some(brace + 1 + i),
      b'\n' => return None,
      _ => {}
    }
  }
  None
}

/// Faithful port of `Image::ExifTool::LigoGPS::ProcessGKU`
/// (LigoGPS.pm:273-281) — the GKU dashcam `udta` variant. The `udta`
/// payload begins `[offset:u32-LE][..]__V35AX_QVDATA__` (the marker is
/// the `udta` `GKUData` Condition trigger, QuickTime.pm:842); the LE u32
/// at offset 0 points to the inner `LIGOGPSINFO {` JSON, which is then
/// decoded by [`process_ligogps_json`].
///
/// LigoGPS.pm:278 `return 0 if $pos + 13 > length $$dataPt or
/// substr($$dataPt, $pos, 13) ne 'LIGOGPSINFO {'` — a missing/short
/// header or a non-`LIGOGPSINFO {` payload at `$pos` decodes nothing.
pub fn process_gku(data: &[u8], out: &mut LigoGpsMeta) {
  // LigoGPS.pm:277 `my $pos = unpack('V', $$dataPt)`.
  let Some(pos) = le_u32(data, 0).map(|v| v as usize) else {
    return;
  };
  // LigoGPS.pm:278 — bounds + the `LIGOGPSINFO {` check at `$pos`.
  let Some(inner) = data.get(pos..) else {
    return;
  };
  if inner.get(..HDR_LIGOGPSINFO_JSON.len()) != Some(HDR_LIGOGPSINFO_JSON.as_slice()) {
    return;
  }
  // LigoGPS.pm:279-280 `pos($$dataPt) = $pos; return ProcessLigoJSON(...)` —
  // scan the JSON starting at `$pos` (`process_ligogps_json` finds the magic at
  // the slice start, equivalent to seeding the regex `pos()`).
  process_ligogps_json(inner, out);
}

/// Decode a single LIGOGPSINFO JSON-object into a [`LigoGpsSample`].
/// Faithful per LigoGPS.pm:342-393.
fn decode_ligo_json_object(json: &str) -> Option<LigoGpsSample> {
  // Tiny one-pass JSON-object scanner: extract `"key": "value"` or
  // `"key": <number>` pairs. The bundled `Image::ExifTool::Import::Read
  // JSON` is a full parser, but LIGOGPSINFO records are flat
  // `{"key": "val", ...}` so a flat scanner suffices.
  let mut hour: Option<u32> = None;
  let mut minute: Option<u32> = None;
  let mut second: Option<u32> = None;
  let mut year: Option<u32> = None;
  let mut month: Option<u32> = None;
  let mut day: Option<u32> = None;
  let mut m_hour: Option<u32> = None;
  let mut m_minute: Option<u32> = None;
  let mut m_second: Option<u32> = None;
  let mut m_year: Option<u32> = None;
  let mut m_month: Option<u32> = None;
  let mut m_day: Option<u32> = None;
  let mut status: Option<String> = None;
  let mut ns: Option<String> = None;
  let mut ew: Option<String> = None;
  let mut latitude: Option<f64> = None;
  let mut longitude: Option<f64> = None;
  // The RAW JSON string of `Latitude`/`Longitude` — kept so the primary-pair
  // emission can apply Perl string truthiness (`$$info{Latitude} and
  // $$info{Longitude}`, LigoGPS.pm:362), which treats `""` and `"0"` as FALSE
  // (so an exactly-`"0"` equator/prime-meridian coordinate suppresses the
  // primary tags) while a parsed `0.0` from `"0.0"`/`"0.00000"` stays truthy.
  let mut latitude_raw: Option<SmolStr> = None;
  let mut longitude_raw: Option<SmolStr> = None;
  let mut o_latitude: Option<f64> = None;
  let mut o_longitude: Option<f64> = None;
  let mut speed: Option<f64> = None;
  let mut gsensor_x: Option<String> = None;
  let mut gsensor_y: Option<String> = None;
  let mut gsensor_z: Option<String> = None;

  for (key, val) in iter_json_pairs(json) {
    match key {
      "Hour" => hour = val.parse().ok(),
      "Minute" => minute = val.parse().ok(),
      "Second" => second = val.parse().ok(),
      "Year" => year = val.parse().ok(),
      "Month" => month = val.parse().ok(),
      "Day" => day = val.parse().ok(),
      "MHour" => m_hour = val.parse().ok(),
      "MMinute" => m_minute = val.parse().ok(),
      "MSecond" => m_second = val.parse().ok(),
      "MYear" => m_year = val.parse().ok(),
      "MMonth" => m_month = val.parse().ok(),
      "MDay" => m_day = val.parse().ok(),
      "status" => status = Some(val.to_string()),
      "NS" => ns = Some(val.to_string()),
      "EW" => ew = Some(val.to_string()),
      "Latitude" => {
        latitude = val.parse().ok();
        latitude_raw = Some(SmolStr::new(val));
      }
      "Longitude" => {
        longitude = val.parse().ok();
        longitude_raw = Some(SmolStr::new(val));
      }
      "OLatitude" => o_latitude = val.parse().ok(),
      "OLongitude" => o_longitude = val.parse().ok(),
      "Speed" => speed = val.parse().ok(),
      "GsensorX" => gsensor_x = Some(val.to_string()),
      "GsensorY" => gsensor_y = Some(val.to_string()),
      "GsensorZ" => gsensor_z = Some(val.to_string()),
      _ => {}
    }
  }

  // LigoGPS.pm:353 — `next unless defined $$info{status} and $$info{status}
  // eq 'A'` — only emit when GPS is active.
  if status.as_deref() != Some("A") {
    return None;
  }

  let mut sample = LigoGpsSample::new();
  // LigoGPS.pm:357-361 — GPSDateTime (UTC, with Z suffix).
  if let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) =
    (year, month, day, hour, minute, second)
  {
    let dt = String::from(&format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}Z"));
    sample.set_date_time(Some(SmolStr::new(dt)));
  }
  // LigoGPS.pm:362-369 — Latitude/Longitude. The bundled `if ($$info{Latitude}
  // and $$info{Longitude})` is PERL TRUTHINESS, NOT a `defined` check (contrast
  // OLatitude/OLongitude below). A JSON string of exactly `"0"` (or `""`) is
  // Perl-FALSE, so a coordinate sitting on the equator / prime-meridian written
  // as `"0"` does NOT emit the primary GPSLatitude/GPSLongitude (the record
  // still consumed its `Doc<N>`). `"0.0"`/`"0.00000"` are Perl-TRUE and emit.
  let perl_truthy = |s: &Option<SmolStr>| s.as_deref().is_some_and(|v| !v.is_empty() && v != "0");
  if perl_truthy(&latitude_raw)
    && perl_truthy(&longitude_raw)
    && let (Some(lat0), Some(lon0)) = (latitude, longitude)
  {
    let lat = if ns.as_deref() == Some("S") {
      -lat0
    } else {
      lat0
    };
    let lon = if ew.as_deref() == Some("W") {
      -lon0
    } else {
      lon0
    };
    sample.set_latitude(Some(lat));
    sample.set_longitude(Some(lon));
  }
  // LigoGPS.pm:370 — Speed (knots → km/h).
  if let Some(sp) = speed {
    sample.set_speed_kph(Some(sp * KNOTS_TO_KPH));
  }
  // LigoGPS.pm:371-373 — Gsensor (raw, space-joined; bundled comment says
  // "don't know conversion factor").
  if let (Some(x), Some(y), Some(z)) = (gsensor_x, gsensor_y, gsensor_z) {
    let mut s = String::with_capacity(x.len() + y.len() + z.len() + 2);
    s.push_str(&x);
    s.push(' ');
    s.push_str(&y);
    s.push(' ');
    s.push_str(&z);
    sample.set_accelerometer(Some(SmolStr::new(s)));
  }
  // LigoGPS.pm:376-380 — DateTimeOriginal (dashcam local clock).
  if let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) =
    (m_year, m_month, m_day, m_hour, m_minute, m_second)
  {
    let dt = format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}");
    sample.set_date_time_local(Some(SmolStr::new(dt)));
  }
  // LigoGPS.pm:382-388 — GPSLatitude2/GPSLongitude2 from OLatitude/OLongitude.
  // Gated on `defined` (NOT truthy as the primary lat/lon is — the bundled uses
  // `if (defined $$info{OLatitude} and defined $$info{OLongitude})`), then signed
  // by the SAME `NS`/`EW` refs.
  if let (Some(olat0), Some(olon0)) = (o_latitude, o_longitude) {
    let olat = if ns.as_deref() == Some("S") {
      -olat0
    } else {
      olat0
    };
    let olon = if ew.as_deref() == Some("W") {
      -olon0
    } else {
      olon0
    };
    sample.set_latitude2(Some(olat));
    sample.set_longitude2(Some(olon));
  }
  Some(sample)
}

/// Iterate over `"key": "value"` or `"key": <number>` pairs in a JSON
/// flat object. Designed for the LIGOGPSINFO JSON variant only — no
/// nested objects, no escape sequences in values.
fn iter_json_pairs(json: &str) -> impl Iterator<Item = (&str, &str)> {
  // Find quoted-string keys followed by `:` and either a quoted string
  // value or a numeric value.
  let s = json.trim().trim_start_matches('{').trim_end_matches('}');
  s.split(',').filter_map(|pair| {
    let colon = pair.find(':')?;
    let key_raw = pair[..colon].trim();
    let key = key_raw.trim_matches('"').trim();
    let val_raw = pair[colon + 1..].trim();
    // Strip surrounding quotes if present.
    let val = if val_raw.starts_with('"') && val_raw.ends_with('"') && val_raw.len() >= 2 {
      &val_raw[1..val_raw.len() - 1]
    } else {
      val_raw
    };
    Some((key, val))
  })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  // ── decrypt_record ────────────────────────────────────────────────────────

  #[test]
  fn decrypt_record_rejects_short_header() {
    assert!(decrypt_record(&[0u8; 4]).is_none());
    assert!(decrypt_record(&[]).is_none());
  }

  #[test]
  fn decrypt_record_rejects_num_too_small() {
    // num < 4 → return undef
    let mut buf = vec![b'#', b'#', b'#', b'#'];
    buf.extend_from_slice(&3u32.to_le_bytes()); // num = 3
    assert!(decrypt_record(&buf).is_none());
  }

  #[test]
  fn decrypt_record_caps_num_at_0x84() {
    // num = 1000 (capped at 0x84 = 132); provide 132 bytes of single-output
    // mode 0x00 (steering 0x00 → 1 input byte, 1 output byte).
    let mut buf = vec![b'#', b'#', b'#', b'#'];
    buf.extend_from_slice(&1000u32.to_le_bytes());
    // 132 rounds of (steering=0x00, input_byte=0x10). Each round consumes
    // 2 bytes (the steering and the input), emitting 1 byte.
    for _ in 0..132 {
      buf.push(0x00); // steering
      buf.push(0x40); // input byte (0x40 | 0x13 = 0x53 = 'S')
    }
    let out = decrypt_record(&buf).expect("decrypts");
    // num was capped at 0x84 = 132, but since each steering=0x00 round
    // consumes 2 input bytes (steering+1 input), num input bytes only
    // produces num/2 rounds = 66 output bytes. Bundled consumes `num`
    // input bytes total.
    assert!(!out.is_empty());
  }

  #[test]
  fn decrypt_record_steering_zero_single_byte() {
    // Mode 0x00: next byte combined with `b & 0x13` (so b=0x00 means
    // output = next_byte | 0 = next_byte).
    let mut buf = vec![b'#', b'#', b'#', b'#'];
    buf.extend_from_slice(&8u32.to_le_bytes()); // num = 8 (4 rounds × 2 bytes)
    // 4 rounds of (steering=0x00, input=0x41='A')
    for _ in 0..4 {
      buf.push(0x00);
      buf.push(0x41);
    }
    let out = decrypt_record(&buf).expect("decrypts");
    assert_eq!(out, b"AAAA");
  }

  // ── unfuzz ────────────────────────────────────────────────────────────────

  #[test]
  fn unfuzz_identity_when_scale_one() {
    // With scale = 1 the formula does NOT recover the original; this
    // verifies the math matches the bundled algorithm.
    // Pre-fuzz: lat=31.5, lon=124.7
    // lat2 = floor(3.15)*10 = 30, lon2 = floor(12.47)*10 = 120
    // result = (30 + (124.7-120)*1, 120 + (31.5-30)*1) = (34.7, 121.5)
    let (ul, ulon) = unfuzz(31.5, 124.7, 1.0);
    assert!((ul - 34.7).abs() < 1e-9);
    assert!((ulon - 121.5).abs() < 1e-9);
  }

  #[test]
  fn unfuzz_scale_three_for_abask() {
    // scale = 1.15368 (ABASK A8 4K, QuickTimeStream.pl:1886).
    let (ul, _ulon) = unfuzz(31.5, 124.7, 1.15368);
    // lat2 = 30, lon2 = 120, ul = 30 + (124.7-120)*1.15368 = 30 + 5.422... ≈ 35.422
    assert!((ul - 35.4229_f64).abs() < 1e-3);
  }

  #[test]
  fn parse_record_fuzzed_default_scale_uses_gps_scl_1_not_unity() {
    // LigoGPS.pm:248-251 — when the record IS fuzzed (`flags & 0x01 == 0`)
    // and NO LigoGPSScale is set (`scale_id = None`), the default scale is
    // `1`, which remaps to `%gpsScl{1} = 1.524855137` (LigoGPS.pm:241,250) —
    // NOT a literal 1.0. This is the iiway s1 / XGODY / Rexing / Kingslim
    // default-scale path (offsets 16/48/80 set no LigoGPSScale).
    //
    // Raw fuzzed lat=31.5, lon=124.7 (both < 100 ⇒ no DDMM conversion). The
    // ASCII record carries N: / E: refs (positive), and `flags = 0` selects
    // the fuzzed branch. Speed scale is irrelevant to lat/lon.
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]); // 4-byte counter (consumed by `.{4}`)
    buf.extend_from_slice(b"2024/01/15 10:00:00 N:31.5 E:124.7 30.0");
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x00, None, false, &mut out);

    // Oracle (UnfuzzLigoGPS, LigoGPS.pm:38-44) with scl = %gpsScl{1}:
    //   scl  = 1.524855137
    //   lat2 = int(31.5 / 10) * 10  = 30
    //   lon2 = int(124.7 / 10) * 10 = 120
    //   lat' = lat2 + (lon - lon2) * scl = 30  + (124.7-120)*scl
    //   lon' = lon2 + (lat - lat2) * scl = 120 + (31.5-30)*scl
    let scl = 1.524_855_137_f64;
    let exp_lat = 30.0 + (124.7 - 120.0) * scl;
    let exp_lon = 120.0 + (31.5 - 30.0) * scl;
    let s = out
      .samples()
      .first()
      .expect("decoded fuzzed default-scale record");
    assert!(
      (s.latitude().unwrap() - exp_lat).abs() < 1e-9,
      "lat {:?} != oracle {exp_lat} (scl=%gpsScl{{1}})",
      s.latitude()
    );
    assert!(
      (s.longitude().unwrap() - exp_lon).abs() < 1e-9,
      "lon {:?} != oracle {exp_lon} (scl=%gpsScl{{1}})",
      s.longitude()
    );
    // Guard against a regression to the old `.unwrap_or(1.0)`: scl=1.0 would
    // give lat'=34.7, lon'=121.5 — assert we are NOT producing that.
    assert!(
      (s.latitude().unwrap() - 34.7).abs() > 1e-3,
      "must not use scl=1.0"
    );
    assert!(
      (s.longitude().unwrap() - 121.5).abs() > 1e-3,
      "must not use scl=1.0"
    );
  }

  // ── parse_decoded_record ──────────────────────────────────────────────────

  #[test]
  fn parse_record_known_good_kph_no_fuzz() {
    // From LigoGPS.pm:234 sample: "....2022/09/19 12:45:24 N:31.285065
    // W:124.759483 46.93 km/h x:-0.000 y:-0.000 z:-0.000".
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // counter
    buf.extend_from_slice(
      b"2022/09/19 12:45:24 N:31.285065 W:124.759483 46.93 km/h x:-0.000 y:-0.000 z:-0.000",
    );
    let mut out = LigoGpsMeta::new();
    // flags = 0x03 = not-fuzzed + kph (matches Redtiger F9 4K plain-ASCII path).
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.date_time(), Some("2022:09:19 12:45:24"));
    // W means longitude is negative.
    assert_eq!(s.latitude(), Some(31.285065));
    assert_eq!(s.longitude(), Some(-124.759483));
    assert_eq!(s.speed_kph(), Some(46.93));
    assert_eq!(s.accelerometer(), Some("-0.000 -0.000 -0.000"));
  }

  #[test]
  fn parse_record_with_track_alt_magvar() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(
      b"2024/01/15 10:00:00 N:45.500 E:170.500 30.0 A:180.5 H:123.4 M:12.5 x:0 y:0 z:0",
    );
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.track_deg(), Some(180.5));
    assert_eq!(s.altitude_m(), Some(123.4));
    assert_eq!(s.magnetic_variation(), Some(12.5));
  }

  #[test]
  fn parse_record_south_latitude_signs_correctly() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(b"2024/01/15 10:00:00 S:45.500 E:170.500 30.0 km/h");
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.latitude(), Some(-45.500));
    assert_eq!(s.longitude(), Some(170.500));
  }

  #[test]
  fn parse_record_explicit_negative_sign() {
    // The bundled regex captures an explicit `-` in `($latNeg)` (group 3).
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(b"2024/01/15 10:00:00 N:-45.500 E:-170.500 30.0 km/h");
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.latitude(), Some(-45.500));
    assert_eq!(s.longitude(), Some(-170.500));
  }

  #[test]
  fn parse_record_accepts_non_slash_date() {
    // FINDING 1 — ExifTool's `ParseLigoGPS` regex (LigoGPS.pm:235
    // `^.{4}(\S+ \S+)\s+([NS?]):...`) captures ANY non-space date token, then
    // normalises it with `tr(/)(:)` (LigoGPS.pm:244 — a NO-OP for a non-slash
    // date). A decrypted/binary record with a dash date `2024-01-15` is ACCEPTED
    // (it decodes, bumps DOC_COUNT, emits GPS); the old slash-only guard DROPPED
    // it. Assert the sample emits with the `/`→`:`-normalised (here unchanged)
    // GPSDateTime.
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]); // 4-byte counter (the `.{4}` prefix)
    buf.extend_from_slice(b"2024-01-15 10:00:00 N:45.5 E:170.5 30.0 km/h");
    let mut out = LigoGpsMeta::new();
    // flags = 0x03 (not fuzzed + km/h) — the plain raw lat/lon survive.
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    assert!(
      out.warning().is_none(),
      "a non-slash date is accepted, not a format error: {:?}",
      out.warning()
    );
    let s = out.samples().first().expect("non-slash record decodes");
    // `tr(/)(:)` leaves a dash date unchanged (no `/` to translate).
    assert_eq!(s.date_time(), Some("2024-01-15 10:00:00"));
    assert_eq!(s.latitude(), Some(45.5));
    assert_eq!(s.longitude(), Some(170.5));
  }

  #[test]
  fn non_slash_record_takes_its_doc_so_next_record_ordinal_is_successor() {
    // FINDING 1 — the regression the slash-guard caused on `Doc<N>`. In ExifTool
    // a non-slash record PASSES the `ParseLigoGPS` regex (LigoGPS.pm:235) and so
    // reaches `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` (LigoGPS.pm:243): it consumes a
    // global doc ordinal and the FOLLOWING record is its successor. The old port
    // dropped the non-slash record BEFORE that bump, so every following record's
    // `Doc<N>` sat one BELOW the oracle. Two records (non-slash then slash), both
    // accepted ⇒ doc 1 then doc 2.
    let mut out = LigoGpsMeta::new();
    let mut rec1 = Vec::new();
    rec1.extend_from_slice(&[0; 4]);
    rec1.extend_from_slice(b"2024-01-15 10:00:00 N:45.5 E:170.5 30.0 km/h");
    parse_decoded_record(&rec1, 0x03, None, false, &mut out);
    let mut rec2 = Vec::new();
    rec2.extend_from_slice(&[0; 4]);
    rec2.extend_from_slice(b"2024/01/15 10:00:01 N:46.5 E:171.5 31.0 km/h");
    parse_decoded_record(&rec2, 0x03, None, false, &mut out);
    // Stamp from the shared counter (start at 0 — both records take docs 1, 2).
    let next = out.stamp_doc_from(0, 0);
    assert_eq!(out.samples().len(), 2, "both records produce a sample");
    assert_eq!(
      out.samples()[0].doc(),
      Some(1),
      "non-slash record takes Doc1"
    );
    assert_eq!(
      out.samples()[1].doc(),
      Some(2),
      "the slash record's ordinal is the non-slash record's successor"
    );
    assert_eq!(next, 2, "the shared counter advanced for BOTH records");
  }

  #[test]
  fn parse_record_emits_format_error_on_garbage() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(b"NOT A VALID RECORD");
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    assert!(out.samples().is_empty());
    assert_eq!(out.warning(), Some("LIGOGPSINFO format error"));
  }

  #[test]
  fn parse_record_emits_oor_when_out_of_range() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(b"2024/01/15 10:00:00 N:91.0 E:181.0 0.0 km/h");
    let mut out = LigoGpsMeta::new();
    parse_decoded_record(&buf, 0x03, None, false, &mut out);
    // LigoGPS.pm:243 bumps `++DOC_COUNT` BEFORE the :254 out-of-range `return`,
    // so the rejected record BURNS a `Doc<N>`: a single doc-consuming-but-
    // suppressed placeholder is pushed (no GPS fields, the warning set).
    assert_eq!(out.samples().len(), 1);
    let s = &out.samples()[0];
    assert!(s.is_suppressed());
    assert_eq!(s.latitude(), None);
    assert_eq!(s.longitude(), None);
    assert_eq!(out.warning(), Some("LIGOGPSINFO coordinates out of range"));
  }

  // ── process_ligogps trailer-shape walker ─────────────────────────────────

  #[test]
  fn process_ligogps_too_short_is_silent() {
    let mut out = LigoGpsMeta::new();
    process_ligogps(b"too short", 0, &mut out, false);
    assert!(out.is_empty());
  }

  #[test]
  fn process_ligogps_walks_single_plain_record() {
    // Trailer-style: `LIGOGPSINFO\0\0\0\0\x14` (20-byte preamble),
    // then ONE 0x84-byte plain ASCII record.
    let mut buf = Vec::new();
    buf.extend_from_slice(HDR_LIGOGPSINFO);
    // 8 more bytes of preamble (the 0x14 byte at offset 0x13 — bytes
    // [pos-8..pos-4] = [\0,\0,\0,\x14] triggers no_fuzz auto-detect).
    buf.extend_from_slice(&[0, 0, 0, 0, 0x14, 0, 0, 0]);
    // record body: 0x84 bytes total. Counter (4) + ASCII payload +
    // padding.
    let mut record = Vec::with_capacity(0x84);
    record.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    record.extend_from_slice(b"2024/01/15 10:00:00 N:45.5 E:170.5 30.0 km/h");
    while record.len() < 0x84 {
      record.push(0);
    }
    buf.extend_from_slice(&record);
    let mut out = LigoGpsMeta::new();
    process_ligogps(&buf, 0, &mut out, false);
    assert_eq!(out.samples().len(), 1);
    let s = &out.samples()[0];
    assert_eq!(s.latitude(), Some(45.5));
    assert_eq!(s.longitude(), Some(170.5));
  }

  // ── process_trailer (via identify_trailers discovery) ───────────────────────

  /// Drive the FULL trailer path the way `quicktime::parse_inner` does: the
  /// shared `IdentifyTrailers` port (`insta360::identify_trailers`) discovers
  /// the `&&&&`-anchored LigoGPS trailer, then [`process_trailer`] decodes its
  /// `skip`-atom body. Returns the populated [`LigoGpsMeta`].
  fn scan_trailer(data: &[u8]) -> LigoGpsMeta {
    let mut out = LigoGpsMeta::new();
    let trailers = crate::formats::insta360::identify_trailers(data);
    if let Some(entry) = trailers.iter().find(|e| e.kind().is_ligogps()) {
      // The box walk never runs in these unit fixtures, so the trailer is never
      // "consumed by an atom" — process it directly (mirrors the `last_pos <=
      // start` gate in `quicktime.rs`, trivially true here).
      process_trailer(data, entry.start() as usize, entry.len() as usize, &mut out);
    }
    out
  }

  #[test]
  fn scan_trailer_no_signature_leaves_out_empty() {
    let out = scan_trailer(&[0u8; 100]);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_short_file_silent() {
    let out = scan_trailer(&[0u8; 10]);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_bad_size_is_silent() {
    // The `&&&&` signature with a trailer length larger than the file. Bundled's
    // `Seek($$trailer[1], 0)` fails on the wrapped-negative start ⇒ `last`, no
    // warning. (The #135 "Bad LigoGPS trailer size" warning was non-faithful —
    // it has no source in QuickTime.pm/LigoGPS.pm.)
    let mut data = vec![0u8; 80];
    data[80 - 8..80 - 4].copy_from_slice(TRAILER_MAGIC);
    data[80 - 4..].copy_from_slice(&999u32.to_le_bytes());
    let out = scan_trailer(&data);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_missing_skip_atom_is_silent() {
    // Valid `&&&&` signature + in-range length, but the trailer body does NOT
    // begin with a `skip` atom. Bundled's `if (... and $buff =~ /skip$/i)` is
    // false ⇒ falls through the `elsif` arms (none match 'LigoGPS') ⇒ NO warning.
    let mut data = vec![0u8; 100];
    let trailer_len: u32 = 40;
    let trailer_start = data.len() - trailer_len as usize;
    // First 8 bytes: a non-`skip` atom name at bytes 4..8.
    data[trailer_start..trailer_start + 8]
      .copy_from_slice(&[0, 0, 0, 0x40, b'j', b'u', b'n', b'k']);
    let sig_off = data.len() - 8;
    data[sig_off..sig_off + 4].copy_from_slice(TRAILER_MAGIC);
    data[sig_off + 4..].copy_from_slice(&trailer_len.to_le_bytes());
    let out = scan_trailer(&data);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_warns_on_missing_ligogpsinfo_magic() {
    // Valid skip atom but no LIGOGPSINFO\0 at payload start.
    let mut buf = Vec::new();
    // Body: 8-byte skip header + random payload.
    let body_len = SKIP_ATOM_HEADER + 32usize;
    let mut body = vec![0u8; body_len];
    // skip atom header: [size:u32-BE][skip]
    body[..4].copy_from_slice(&(body_len as u32).to_be_bytes());
    body[4..8].copy_from_slice(b"skip");
    // Payload: 24 random bytes (no LIGOGPSINFO\0).
    for i in 0..24 {
      body[8 + i] = (i + 0x40) as u8;
    }
    // Build the full file: padding + trailer body + signature + len.
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&body);
    let trailer_len = (body.len() + 8) as u32; // body + signature(4) + len(4)
    buf.extend_from_slice(TRAILER_MAGIC);
    // `IdentifyTrailers` reads the LigoGPS trailer length as BE `Get32u(buff,36)`
    // (QuickTime.pm:9907, default `MM` order — see `insta360::identify_trailers`).
    buf.extend_from_slice(&trailer_len.to_be_bytes());
    let out = scan_trailer(&buf);
    assert_eq!(out.warning(), Some("Unrecognized data in LigoGPS trailer"));
  }

  #[test]
  fn scan_trailer_decodes_minimal_plain_ascii() {
    // Build a valid trailer with the plain-ASCII Redtiger-F9-4K
    // record format.
    //
    // File layout:
    //   [padding 16 bytes]
    //   [trailer body:
    //     [skip atom header: size:u32-BE = body_len, "skip"]
    //     [LIGOGPSINFO\0]
    //     [8 more bytes of preamble incl. \0\0\0\x14 at offset 12]
    //     [0x84 bytes of plain ASCII record]
    //   ]
    //   [&&&& : 4 bytes]
    //   [trailer_len : u32-LE]
    //
    // The body the bundled code passes to ProcessLigoGPS is
    // `LIGOGPSINFO\0...records...` (atom payload). Our scan_trailer
    // dispatches `process_ligogps` on the *atom payload* (post 8-byte
    // skip header), with DirStart=0; ProcessLigoGPS starts records at
    // offset 0x14.
    let mut payload = Vec::new();
    payload.extend_from_slice(HDR_LIGOGPSINFO);
    payload.extend_from_slice(&[0, 0, 0, 0x14, 0, 0, 0, 0]); // preamble: 8 more bytes
    let mut record = Vec::with_capacity(0x84);
    record.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    record.extend_from_slice(b"2024/01/15 10:00:00 N:45.5 E:170.5 30.0 km/h");
    while record.len() < 0x84 {
      record.push(0);
    }
    payload.extend_from_slice(&record);

    // Body = [skip atom header][payload]. QuickTime.pm:10660 reads the inner
    // buffer as `$len = Get32u(buff,0) - 16` bytes, so the skip atom's declared
    // SIZE field must be `16 + payload.len()` for the read to capture the FULL
    // `LIGOGPSINFO\0...` payload (the #135 fixture wrote `8 + payload.len()`,
    // i.e. `trailer_len - 8`, which truncated the record under the faithful
    // `- 16` rule — corrected here).
    let skip_atom_size = (16 + payload.len()) as u32;
    let mut body = Vec::with_capacity(SKIP_ATOM_HEADER + payload.len());
    body.extend_from_slice(&skip_atom_size.to_be_bytes());
    body.extend_from_slice(b"skip");
    body.extend_from_slice(&payload);

    let trailer_len = (body.len() + 8) as u32;
    let mut file = Vec::new();
    file.extend_from_slice(&[0u8; 64]); // padding
    file.extend_from_slice(&body);
    file.extend_from_slice(TRAILER_MAGIC);
    // BE trailer length (QuickTime.pm:9907 `Get32u(buff,36)`, default `MM`).
    file.extend_from_slice(&trailer_len.to_be_bytes());

    let out = scan_trailer(&file);
    assert_eq!(
      out.samples().len(),
      1,
      "expected 1 sample, got {} (warning: {:?})",
      out.samples().len(),
      out.warning()
    );
    let s = &out.samples()[0];
    assert_eq!(s.latitude(), Some(45.5));
    assert_eq!(s.longitude(), Some(170.5));
  }

  // ── process_ligogps_json ─────────────────────────────────────────────────

  #[test]
  fn ligogps_json_decodes_active_record() {
    let data = br#"LIGOGPSINFO {"Hour": "10", "Minute": "00", "Second": "00", "Year": "2024", "Month": "01", "Day": "15", "status": "A", "NS": "N", "EW": "E", "Latitude": "45.5", "Longitude": "170.5", "Speed": "20"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.date_time(), Some("2024:01:15 10:00:00Z"));
    assert_eq!(s.latitude(), Some(45.5));
    assert_eq!(s.longitude(), Some(170.5));
    // Speed = 20 knots * 1.852 = 37.04 km/h
    assert_eq!(s.speed_kph(), Some(37.04));
  }

  #[test]
  fn ligogps_json_skips_inactive_record() {
    let data = br#"LIGOGPSINFO {"status": "V", "Latitude": "45.5"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    assert!(out.samples().is_empty());
  }

  #[test]
  fn ligogps_json_decodes_local_time() {
    let data = br#"LIGOGPSINFO {"status": "A", "MHour": "11", "MMinute": "30", "MSecond": "45", "MYear": "2024", "MMonth": "01", "MDay": "15"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.date_time_local(), Some("2024:01:15 11:30:45"));
  }

  #[test]
  fn ligogps_json_south_negates_latitude() {
    let data = br#"LIGOGPSINFO {"status": "A", "NS": "S", "EW": "W", "Latitude": "45.5", "Longitude": "170.5"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.latitude(), Some(-45.5));
    assert_eq!(s.longitude(), Some(-170.5));
  }

  #[test]
  fn ligogps_json_decodes_olatitude_olongitude_as_lat2_lon2() {
    // LigoGPS.pm:382-388 — OLatitude/OLongitude → GPSLatitude2/GPSLongitude2,
    // signed by the SAME NS/EW refs as the primary lat/lon.
    let data = br#"LIGOGPSINFO {"status": "A", "NS": "S", "EW": "W", "Latitude": "12.5", "Longitude": "34.5", "OLatitude": "12.25", "OLongitude": "34.75"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    let s = out.samples().first().expect("decoded");
    assert_eq!(s.latitude(), Some(-12.5));
    assert_eq!(s.longitude(), Some(-34.5));
    assert_eq!(s.latitude2(), Some(-12.25));
    assert_eq!(s.longitude2(), Some(-34.75));
  }

  #[test]
  fn process_ligogps_json_tags_source_as_udta_json() {
    // FINDING 1 — every record decoded by ProcessLigoJSON carries the UdtaJson
    // source so the emitter can apply the no-`ee` FIRST-record semantics.
    let data = br#"LIGOGPSINFO {"status": "A", "NS": "N", "EW": "E", "Latitude": "1.5", "Longitude": "2.5"}"#;
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(data, &mut out);
    let s = out.samples().first().expect("decoded");
    assert!(
      s.source().is_udta_json(),
      "ProcessLigoJSON records are the udta-JSON family (Finding 1)"
    );
  }

  #[test]
  fn process_ligogps_json_decodes_across_non_utf8_padding() {
    // FINDING 2 — a valid `LIGOGPSINFO {...}` object followed by BINARY (non-UTF8)
    // padding must still decode: ExifTool matches the braced object on RAW BYTES
    // (`/LIGOGPSINFO (\{.*?\})/`), it does NOT require the whole payload to be
    // UTF-8. The previous `from_utf8(WHOLE slice)` rejected such a record.
    let mut data = Vec::new();
    data.extend_from_slice(
      br#"LIGOGPSINFO {"status": "A", "NS": "N", "EW": "E", "Latitude": "5.5", "Longitude": "6.5"}"#,
    );
    // Binary padding (invalid UTF-8: a lone 0xFF / 0xFE / 0x80 run + NULs).
    data.extend_from_slice(&[0xff, 0xfe, 0x80, 0x00, 0x00, 0x81, 0xc0]);
    let mut out = LigoGpsMeta::new();
    process_ligogps_json(&data, &mut out);
    let s = out
      .samples()
      .first()
      .expect("the JSON object decodes despite trailing binary padding");
    assert_eq!(s.latitude(), Some(5.5));
    assert_eq!(s.longitude(), Some(6.5));
  }

  #[test]
  fn gku_decodes_json_followed_by_non_utf8_padding() {
    // FINDING 2 — the `GKUData` container is BINARY: the LE u32 at offset 0 points
    // at an inner `LIGOGPSINFO {...}` object that is itself followed by binary
    // padding. ExifTool decodes the object regardless (ProcessGKU → ProcessLigoJSON
    // on the raw bytes, LigoGPS.pm:277-280). Build `[offset:u32-LE][pad..][JSON]
    // [binary padding]`.
    let json = br#"LIGOGPSINFO {"status": "A", "NS": "N", "EW": "W", "Latitude": "7.5", "Longitude": "8.5"}"#;
    let json_off: u32 = 16;
    let mut data = Vec::new();
    data.extend_from_slice(&json_off.to_le_bytes()); // bytes 0..4 = offset
    data.extend_from_slice(&[0u8; 12]); // pad to `offset`
    assert_eq!(data.len(), json_off as usize);
    data.extend_from_slice(json); // inner `LIGOGPSINFO {...}` at `offset`
    data.extend_from_slice(&[0xff, 0x00, 0xfe, 0x90, 0x00]); // trailing binary padding
    let mut out = LigoGpsMeta::new();
    process_gku(&data, &mut out);
    let s = out
      .samples()
      .first()
      .expect("GKU decodes the JSON object before the binary padding");
    assert_eq!(s.latitude(), Some(7.5));
    // EW=W ⇒ negative longitude.
    assert_eq!(s.longitude(), Some(-8.5));
    assert!(
      s.source().is_udta_json(),
      "GKU routes through ProcessLigoJSON"
    );
  }

  #[test]
  fn scan_trailer_rejects_json_variant() {
    // The file-end trailer Condition is binary-only — `$buff =~ /^LIGOGPSINFO\0/`
    // (QuickTime.pm:10661). A `LIGOGPSINFO {` JSON payload (12th byte = space) is
    // NOT a binary trailer, so it falls into the `else` arm (QuickTime.pm:10667)
    // ⇒ `Unrecognized data in LigoGPS trailer` and decodes NOTHING. The JSON form
    // is reached only via the `udta` `LigoJSON` Condition (QuickTime.pm:835).
    let mut payload = Vec::new();
    payload.extend_from_slice(
      br#"LIGOGPSINFO {"status": "A", "NS": "N", "EW": "E", "Latitude": "1.5", "Longitude": "2.5"}"#,
    );
    let skip_atom_size = (16 + payload.len()) as u32;
    let mut body = Vec::with_capacity(SKIP_ATOM_HEADER + payload.len());
    body.extend_from_slice(&skip_atom_size.to_be_bytes());
    body.extend_from_slice(b"skip");
    body.extend_from_slice(&payload);

    let trailer_len = (body.len() + 8) as u32;
    let mut file = Vec::new();
    file.extend_from_slice(&[0u8; 64]); // padding
    file.extend_from_slice(&body);
    file.extend_from_slice(TRAILER_MAGIC);
    file.extend_from_slice(&trailer_len.to_be_bytes());

    let out = scan_trailer(&file);
    assert!(
      out.samples().is_empty(),
      "JSON trailer must NOT decode via the binary trailer walker"
    );
    assert_eq!(out.warning(), Some("Unrecognized data in LigoGPS trailer"));
  }

  // ── DM→Decimal conversion ─────────────────────────────────────────────────

  #[test]
  fn convert_dm_to_decimal_round_trip() {
    // 4500.5 = 45° + 0.5/60 = 45.00833...
    let mut lat = 4500.5_f64;
    let mut lon = 12030.0_f64;
    convert_lat_lon_dm_to_decimal(&mut lat, &mut lon);
    assert!((lat - 45.00833333333).abs() < 1e-6);
    assert!((lon - 120.5).abs() < 1e-6);
  }

  #[test]
  fn has_three_leading_digits_detects_dm() {
    assert!(has_three_leading_digits("4500.5"));
    assert!(has_three_leading_digits("12030.000"));
    assert!(!has_three_leading_digits("45.5"));
    assert!(!has_three_leading_digits("1.5"));
  }

  // ── Plain ASCII record detection ─────────────────────────────────────────

  #[test]
  fn is_plain_ascii_date_record_accepts_expected_shape() {
    // The detector matches `m(^.{4}\d{4}/\d{2}/\d{2} )` (LigoGPS.pm:304)
    // — 4 leading bytes (counter), then `YYYY/MM/DD `.
    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 4-byte counter
    rec.extend_from_slice(b"2024/01/15 ...");
    assert!(is_plain_ascii_date_record(&rec));
  }

  #[test]
  fn is_plain_ascii_date_record_rejects_short() {
    assert!(!is_plain_ascii_date_record(b"short"));
  }

  #[test]
  fn is_plain_ascii_date_record_rejects_non_date() {
    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    rec.extend_from_slice(b"NOT DATE FORMAT");
    assert!(!is_plain_ascii_date_record(&rec));
  }
}
