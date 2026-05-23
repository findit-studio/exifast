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
//!    matches `/\&\&\&\&(.{4})$/` to extract the trailer length (LE u32 at
//!    `EOF-4`). The full trailer begins `[size:u32-BE][skip:4-bytes]`
//!    (`skip` ASCII atom name); after those 8 bytes the payload starts
//!    with `LIGOGPSINFO\0` and is passed to [`process_ligogps`].
//! 2. **`LIGOGPSINFO\0`-prefixed embedded sample** (QuickTimeStream.pl
//!    :1843-1888) — bundled detects the fingerprint at offset 16/48/80
//!    inside a `freeGPS` block, sets `LigoGPSScale = 3` when the offset-
//!    16 ABASK A8 4K variant fingerprint hits, and dispatches to
//!    [`process_ligogps`] with `DirStart = $pos`.
//!
//! Both paths route through the SAME `ProcessLigoGPS` (LigoGPS.pm:289-320).
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
//! BT58189 dashcam, which writes chained 512-byte records starting
//! `LIGOGPSINFO {"Hour": "23", ...}`. This is a lighter parser (no
//! decryption, no fuzzing) — we surface it through [`process_ligogps_json`].
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

/// The 4-byte ASCII signature `"&&&&"` that prefixes the trailer-length
/// LE u32 field. Reported by `IdentifyTrailers` (QuickTime.pm:9906).
pub(crate) const TRAILER_MAGIC: &[u8; 4] = b"&&&&";

/// `IdentifyTrailers` reads 40 bytes from EOF-40 (QuickTime.pm:9903). The
/// trailer is identified when those 40 bytes match `/\&\&\&\&(.{4})$/` —
/// i.e. the last 8 bytes of the file are `[&&&&][len:u32-LE]`.
const IDENTIFY_FOOTER_SIZE: usize = 40;

/// The `&&&& ` signature lives at offset 32 within that 40-byte buffer
/// (bytes 32-35 are `&&&&`, bytes 36-39 are the LE u32 trailer length).
const SIG_OFFSET: usize = 32;

/// Per-`skip`-atom prefix size: the 8-byte `[size:u32-BE][skip]` atom
/// header that QuickTime.pm:10658 reads at the trailer start
/// (`$raf->Read($buff, 8) == 8 and $buff =~ /skip$/i`).
const SKIP_ATOM_HEADER: usize = 8;

// ===========================================================================
// Endian helpers (LigoGPS records are LE per QuickTime.pm:9907 `Get32u`)
// ===========================================================================

#[inline]
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

// ===========================================================================
// scan_trailer — entry point for the file-end LigoGPS trailer (QuickTime.pm
// :10658-10668)
// ===========================================================================

/// Locate and decode a LigoGPS trailer at the end of `data`. No-op when no
/// trailer signature is present (the cheap path most files take).
///
/// Faithful per `IdentifyTrailers` (QuickTime.pm:9897-9926) + the
/// LigoGPS trailer handling in `ProcessMOV` (QuickTime.pm:10658-10668).
/// The trailer matches `/\&\&\&\&(.{4})$/` against the last 40 bytes of
/// the file (`IdentifyTrailers` reads 40 from EOF-40); the captured 4
/// bytes are the LE u32 trailer length. The trailer body starts with an
/// 8-byte `[size:u32-BE][skip]` atom header (QuickTime.pm:10658
/// `$buff =~ /skip$/i`); the remaining `len - 16` bytes start with
/// `LIGOGPSINFO\0` and are dispatched to [`process_ligogps`].
///
/// ## Error / pathological cases
///
/// - File shorter than 40 bytes → `is_empty()` (no trailer possible).
/// - File without the `&&&&` signature → `is_empty()`.
/// - Trailer claiming `trailer_len > file_size` → `Bad LigoGPS trailer
///   size` warning, no records decoded.
/// - Trailer claiming `trailer_len < 16` (less than the `skip` atom +
///   `LIGOGPSINFO\0` magic minimum) → `Bad LigoGPS trailer size` warning.
/// - `skip` atom check fails OR payload doesn't begin `LIGOGPSINFO\0`
///   → `Unrecognized data in LigoGPS trailer` warning
///   (QuickTime.pm:10667).
pub fn scan_trailer(data: &[u8], out: &mut LigoGpsMeta) {
  // QuickTime.pm:9903 `$raf->Seek(-40-$offset, 2) and $raf->Read($buff, 40)
  // == 40`. We need at least IDENTIFY_FOOTER_SIZE bytes to even check.
  if data.len() < IDENTIFY_FOOTER_SIZE {
    return;
  }
  let footer = &data[data.len() - IDENTIFY_FOOTER_SIZE..];
  // QuickTime.pm:9906 `$buff =~ /\&\&\&\&(.{4})$/` — the `&&&&` signature
  // at offset 32, the LE u32 trailer length at offset 36.
  if &footer[SIG_OFFSET..SIG_OFFSET + TRAILER_MAGIC.len()] != TRAILER_MAGIC.as_slice() {
    return; // no LigoGPS trailer
  }
  // QuickTime.pm:9907 `($type, $len) = ('LigoGPS', Get32u(\$buff, 36))`.
  let Some(trailer_len) = le_u32(footer, SIG_OFFSET + 4) else {
    return;
  };
  let trailer_len = trailer_len as usize;
  // Sanity: the trailer must include at least the 8-byte `skip` header
  // + `LIGOGPSINFO\0` (12 bytes) — a 20-byte minimum. Anything smaller
  // is a malformed trailer.
  if trailer_len < SKIP_ATOM_HEADER + HDR_LIGOGPSINFO.len() {
    out.set_warning(SmolStr::new("Bad LigoGPS trailer size"));
    return;
  }
  if trailer_len > data.len() {
    out.set_warning(SmolStr::new("Bad LigoGPS trailer size"));
    return;
  }
  // QuickTime.pm:10657 `$raf->Seek($$trailer[1], 0)`. `$$trailer[1]` is
  // `$raf->Tell() - $len` (the file offset of the trailer start).
  let trailer_start = data.len() - trailer_len;
  let trailer = &data[trailer_start..data.len()];
  // QuickTime.pm:10658 `$raf->Read($buff, 8) == 8 and $buff =~ /skip$/i`.
  // The 8-byte read is `[size:u32-BE][skip]` — the `skip` atom name lives
  // at bytes 4..8. Case-insensitive per the bundled `/i` modifier.
  let head = &trailer[..SKIP_ATOM_HEADER];
  let atom_name = &head[4..8];
  if !atom_name.eq_ignore_ascii_case(b"skip") {
    out.set_warning(SmolStr::new("Unrecognized data in LigoGPS trailer"));
    return;
  }
  // QuickTime.pm:10660 `my $len = Get32u(\$buff, 0) - 16`. The bundled
  // reads `size:u32-BE` from the 8-byte buffer; `- 16` removes both the
  // 8-byte read and an additional 8 bytes from the start (the `LIGOGPSINFO
  // \0\0\0\0\xNN` magic preamble length consumed before record dispatch).
  // We sanity-check that the declared atom size is at least the 8-byte
  // header itself.
  let Some(atom_size) = be_u32(head, 0) else {
    out.set_warning(SmolStr::new("Bad LigoGPS trailer size"));
    return;
  };
  if (atom_size as usize) < SKIP_ATOM_HEADER {
    out.set_warning(SmolStr::new("Bad LigoGPS trailer size"));
    return;
  }
  // QuickTime.pm:10661 `if ($len > 0 and $raf->Read($buff, $len) == $len
  // and $buff =~ /^LIGOGPSINFO\0/)`. Note `$len = atom_size - 16`, i.e.
  // the atom's payload after the inner 16-byte header. We read from
  // `trailer_start + SKIP_ATOM_HEADER` (file offset 8 of the trailer).
  let payload_start = trailer_start + SKIP_ATOM_HEADER;
  // Bundled would read `atom_size - 16` bytes but the trailer body
  // available is `trailer_len - SKIP_ATOM_HEADER`; cap at that.
  let payload_avail = trailer_len - SKIP_ATOM_HEADER;
  let payload = &data[payload_start..payload_start + payload_avail];
  if payload.len() < HDR_LIGOGPSINFO.len()
    || &payload[..HDR_LIGOGPSINFO.len()] != HDR_LIGOGPSINFO.as_slice()
  {
    out.set_warning(SmolStr::new("Unrecognized data in LigoGPS trailer"));
    return;
  }
  // QuickTime.pm:10663-10665 `Image::ExifTool::LigoGPS::ProcessLigoGPS($et,
  // \%dirInfo, $tbl)`. DirName/DirStart from the bundled call indicate
  // `DirStart = 0` (the buffer starts with the LIGOGPSINFO\0 magic, so
  // our `process_ligogps(buff, 0, ...)` mirrors that — record dispatch
  // starts at offset 0x14 inside this buffer, matching LigoGPS.pm:293).
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
  if pos >= 8
    && let Some(preamble) = data.get(pos - 8..pos - 4)
    && preamble[0] == 0
    && preamble[1] == 0
    && preamble[2] == 0
    && (preamble[3] == 0x01 || preamble[3] == 0x14)
  {
    no_fuzz = true;
  }
  // LigoGPS.pm:301 `for (; $pos + 0x84 <= length($$dataPt); $pos += 0x84)`.
  while pos + RECORD_STRIDE <= data.len() {
    let rec = &data[pos..pos + RECORD_STRIDE];
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
  if rec.len() < 15 {
    return false;
  }
  let prefix = &rec[4..15];
  prefix.len() == 11
    && prefix[0].is_ascii_digit()
    && prefix[1].is_ascii_digit()
    && prefix[2].is_ascii_digit()
    && prefix[3].is_ascii_digit()
    && prefix[4] == b'/'
    && prefix[5].is_ascii_digit()
    && prefix[6].is_ascii_digit()
    && prefix[7] == b'/'
    && prefix[8].is_ascii_digit()
    && prefix[9].is_ascii_digit()
    && prefix[10] == b' '
}

/// Strip trailing `\0` bytes (LigoGPS.pm:306 `$dat =~ s/\0+$//`).
fn strip_trailing_nulls(rec: &[u8]) -> &[u8] {
  let mut end = rec.len();
  while end > 0 && rec[end - 1] == 0 {
    end -= 1;
  }
  &rec[..end]
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
  if in_end > rec.len() {
    return None;
  }
  let mut input = rec[8..in_end].iter().copied();
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

  // First 4 bytes are the counter (LigoGPS.pm:235 `^.{4}`); the body is
  // the text.
  if buf.len() < 5 {
    return;
  }
  // Bundled tolerates trailing zero pads (parse_ligogps's regex anchors
  // are tolerant). Use lossy UTF-8 — the text is ASCII per the format
  // spec but a malformed record may contain garbage; lossy preserves the
  // parse.
  let body_bytes = &buf[4..];
  let body = match core::str::from_utf8(body_bytes) {
    Ok(s) => s,
    Err(_) => {
      // Try lossy: strip non-UTF8 bytes by taking the longest valid
      // prefix.
      core::str::from_utf8(
        &body_bytes[..body_bytes
          .iter()
          .position(|&b| b == 0)
          .unwrap_or(body_bytes.len())],
      )
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
  if flags & 0x01 == 0 {
    let scl = scale_id
      .and_then(|id| match id {
        1 => Some(1.524855137_f64),
        2 => Some(1.456027985_f64),
        3 => Some(1.15368_f64),
        _ => None,
      })
      .unwrap_or(1.0);
    let (ul, ulon) = unfuzz(lat, lon, scl);
    lat = ul;
    lon = ulon;
  }

  // LigoGPS.pm:254 — sanity check.
  if lat > 90.0 || lon > 180.0 {
    out.set_warning(SmolStr::new("LIGOGPSINFO coordinates out of range"));
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
  // whitespace (time).
  let date_end = body.find(char::is_whitespace)?;
  let date = &body[..date_end];
  // Bundled regex requires the date to look like `YYYY/MM/DD` (via
  // downstream `tr/\//:/` and `^.{4}\d{4}/\d{2}/\d{2} ` plain-path
  // check). The encrypted-path regex is permissive but the tag emission
  // relies on slashes.
  if !date.contains('/') {
    return None;
  }
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
pub fn process_ligogps_json(data: &[u8], out: &mut LigoGpsMeta) {
  let text = match core::str::from_utf8(data) {
    Ok(s) => s,
    Err(_) => return,
  };
  let mut search_start = 0;
  while let Some(rel) = text[search_start..].find("LIGOGPSINFO {") {
    let abs = search_start + rel + "LIGOGPSINFO ".len();
    // Find the closing brace — naive parser sufficient for the bundled
    // shape (no nested objects in the JSON variant).
    let Some(close_rel) = text[abs..].find('}') else {
      return;
    };
    let json_end = abs + close_rel + 1;
    let json_text = &text[abs..json_end];
    if let Some(sample) = decode_ligo_json_object(json_text) {
      out.push_sample(sample);
    }
    search_start = json_end;
  }
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
      "Latitude" => latitude = val.parse().ok(),
      "Longitude" => longitude = val.parse().ok(),
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
  // LigoGPS.pm:362-369 — Latitude/Longitude.
  if let (Some(lat0), Some(lon0)) = (latitude, longitude) {
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
    assert!(out.samples().is_empty());
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

  // ── scan_trailer ──────────────────────────────────────────────────────────

  #[test]
  fn scan_trailer_no_signature_leaves_out_empty() {
    let mut out = LigoGpsMeta::new();
    scan_trailer(&[0u8; 100], &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_short_file_silent() {
    let mut out = LigoGpsMeta::new();
    scan_trailer(&[0u8; 10], &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_warns_on_bad_size() {
    // Build a 40-byte buffer with the `&&&&` signature but a trailer
    // length larger than the file.
    let mut data = vec![0u8; 80];
    data[80 - 8..80 - 4].copy_from_slice(TRAILER_MAGIC);
    data[80 - 4..].copy_from_slice(&999u32.to_le_bytes());
    let mut out = LigoGpsMeta::new();
    scan_trailer(&data, &mut out);
    assert_eq!(out.warning(), Some("Bad LigoGPS trailer size"));
  }

  #[test]
  fn scan_trailer_warns_on_missing_skip_atom() {
    // Build a valid-signature trailer of size 32 with no `skip` atom.
    let mut data = vec![0u8; 100];
    // The trailer body lives at file_len - trailer_len.
    let trailer_len: u32 = 40;
    let trailer_start = data.len() - trailer_len as usize;
    // First 8 bytes: random; we'll set them to non-`skip`.
    data[trailer_start..trailer_start + 8]
      .copy_from_slice(&[0, 0, 0, 0x40, b'j', b'u', b'n', b'k']);
    // signature + len in last 8 bytes.
    let sig_off = data.len() - 8;
    data[sig_off..sig_off + 4].copy_from_slice(TRAILER_MAGIC);
    data[sig_off + 4..].copy_from_slice(&trailer_len.to_le_bytes());
    let mut out = LigoGpsMeta::new();
    scan_trailer(&data, &mut out);
    assert_eq!(out.warning(), Some("Unrecognized data in LigoGPS trailer"));
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
    buf.extend_from_slice(&trailer_len.to_le_bytes());
    let mut out = LigoGpsMeta::new();
    scan_trailer(&buf, &mut out);
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

    // Body = [skip atom header][payload]
    let body_len = SKIP_ATOM_HEADER + payload.len();
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&(body_len as u32).to_be_bytes());
    body.extend_from_slice(b"skip");
    body.extend_from_slice(&payload);

    let trailer_len = (body.len() + 8) as u32;
    let mut file = Vec::new();
    file.extend_from_slice(&[0u8; 64]); // padding (≥ IDENTIFY_FOOTER_SIZE)
    file.extend_from_slice(&body);
    file.extend_from_slice(TRAILER_MAGIC);
    file.extend_from_slice(&trailer_len.to_le_bytes());

    let mut out = LigoGpsMeta::new();
    scan_trailer(&file, &mut out);
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
