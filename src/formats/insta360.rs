// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTimeStream::ProcessInsta360`
//! (QuickTimeStream.pl:3252-3478) — the Insta360 trailer walker. Backed
//! by the `%insvDataLen` record-length catalogue (QuickTimeStream.pl:85-
//! 99), the `INSV_MakerNotes` identity table (QuickTimeStream.pl:696-707),
//! and the `QuickTime::Stream` GPS/Exposure tags (QuickTimeStream.pl
//! :107-169).
//!
//! ## Trailer locator
//!
//! The trailer is identified by `IdentifyTrailers` in QuickTime.pm:9897-
//! 9926: read 40 bytes from `EOF - 40`, the last 32 bytes must be the
//! ASCII string `"8db42d694ccc418790edff439fe026bf"` (Insta360's signature
//! UUID); the first 4 bytes are the LE u32 trailer length. (Multiple
//! trailers can chain — this walker only handles one.)
//!
//! `ProcessInsta360` then re-reads 78 bytes from `EOF - 78` and walks
//! backwards from the LAST record to the FIRST, using the 6-byte
//! `[id:u16-LE][len:u32-LE]` footer of each record to step. If a
//! directory-table record (id `0x000`) is encountered, the walker
//! switches to forward-by-index dispatch (QuickTimeStream.pl:3437-3469).
//!
//! ## Per-record-type dispatch
//!
//! `%insvDataLen` (QuickTimeStream.pl:85-99) keys length-per-row to
//! record id; QuickTimeStream.pl:3326-3346 expands the zero-length
//! placeholders. The decoders ported here are the camera-indexing
//! priorities:
//!
//!  - **`0x101` Identity** (QuickTimeStream.pl:3427-3436). NOT in
//!    `%insvDataLen` — the walker reaches it via the `} elsif ($id ==
//!    0x101)` fork. The record body is a sequence of `[tag:u8]
//!    [len:u8][value:len bytes]` items; the first 4 items are surfaced
//!    via the `INSV_MakerNotes` table (`0x0a SerialNumber`, `0x12 Model`,
//!    `0x1a Firmware`, `0x2a Parameters`).
//!  - **`0x700` GPS** (QuickTimeStream.pl:3397-3425). 53-byte rows;
//!    each `status == 'A'` row yields one [`Insta360GpsSample`].
//!  - **`0x400` Exposure** (QuickTimeStream.pl:3386-3391). 16-byte rows;
//!    each row yields one [`Insta360ExposureSample`].
//!  - **`0x300` Accelerometer** (QuickTimeStream.pl:3326-3346 stride probe +
//!    3372-3385). 56-byte (6 doubles) or 20-byte (6 int16) rows; each yields
//!    one [`Insta360AccelSample`] (Accelerometer + AngularVelocity 3-axis).
//!  - **`0x600` VideoTimeStamp** (QuickTimeStream.pl:3392-3396). 8-byte rows;
//!    each yields one [`Insta360VideoTimeSample`].
//!
//! Every surfaced timed row across these types shares ONE global `DOC_NUM`
//! counter (`++` per row, in walk order — last record first), so a faithful
//! `-ee` parse can emit each under its own `Doc<N>`. The `0x200`
//! PreviewImage record is still walked (loop-shape faithful) but not
//! surfaced — heavy + low indexing value (FOLLOW-UP).
//!
//! ## Endianness
//!
//! `ProcessInsta360` opens with `SetByteOrder('II')` (QuickTimeStream.pl
//! :3308) — every multi-byte int in the trailer is little-endian.
//!
//! ## GPS priority chain
//!
//! Insta360 trailer GPS feeds the **FOURTH tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. Insta360 GPS is phone-paired via
//! the Insta360 Studio app — same fidelity tier as Sony rtmd; ordered
//! after Sony because Sony's `GPSStatus 'A'/'V'` flag is explicit while
//! Insta360 only ever surfaces `'A'` (active fix) rows.

extern crate alloc;
use alloc::vec::Vec;

use smol_str::SmolStr;

use crate::metadata::{
  Insta360AccelSample, Insta360ExposureSample, Insta360GpsSample, Insta360Identity, Insta360Meta,
  Insta360VideoTimeSample,
};

// ===========================================================================
// Trailer signature (QuickTime.pm:9904)
// ===========================================================================

/// The 32-byte ASCII hex string that identifies an Insta360 trailer
/// (QuickTime.pm:9904 + QuickTimeStream.pl:3271). It's a `&str` because
/// the bundled `eq` compares the bytes as a textual hex string, NOT
/// the underlying 16 raw UUID bytes.
pub(crate) const MAGIC: &[u8; 32] = b"8db42d694ccc418790edff439fe026bf";

/// Bytes from EOF to the trailer total-length field — the EOF-40 `IdentifyTrailers`
/// locator (QuickTime.pm:9897-9926): `[trailerLen:u32-LE][4 opaque][32-byte magic]`.
/// Equals `unpack('x38V')` offset 38 within the 78-byte `ProcessInsta360` footer
/// (78 − 38 = 40), so it reads the same length field on any file ≥ 78 bytes.
const TRAILER_LEN_FROM_EOF: usize = 40;

/// Total footer size read by `ProcessInsta360`
/// (QuickTimeStream.pl:3270 `$raf->Read($buff, 78)`).
const FOOTER_SIZE: usize = 78;

/// Per-record 6-byte footer = `[id:u16-LE][len:u32-LE]`
/// (QuickTimeStream.pl:3311 `unpack('vV', $buff)`).
const RECORD_FOOTER_SIZE: usize = 6;

// ===========================================================================
// Record IDs (QuickTimeStream.pl:85-99 + 3326-3453)
// ===========================================================================

const ID_DIRECTORY_TABLE: u16 = 0x000;
const ID_IDENTITY: u16 = 0x101;
/// PreviewImage / PreviewTIFF (QuickTimeStream.pl:3358-3371). Walked
/// but not surfaced — heavy + low indexing value (FOLLOW-UP).
#[allow(dead_code)]
const ID_PREVIEW_IMAGE: u16 = 0x200;
const ID_ACCELEROMETER: u16 = 0x300;
const ID_EXPOSURE: u16 = 0x400;
/// VideoTimeStamp (QuickTimeStream.pl:3392-3396): 8-byte rows.
const ID_VIDEO_TIMESTAMP: u16 = 0x600;
const ID_GPS: u16 = 0x700;

// ===========================================================================
// INSV_MakerNotes identity tags (QuickTimeStream.pl:696-707)
// ===========================================================================

const TAG_SERIAL_NUMBER: u8 = 0x0a;
const TAG_MODEL: u8 = 0x12;
const TAG_FIRMWARE: u8 = 0x1a;
const TAG_PARAMETERS: u8 = 0x2a;

// ===========================================================================
// `%insvLimit` defaults — `0x300` accelerometer cap
// (QuickTimeStream.pl:103-105: cap of 20000 records)
// ===========================================================================

/// Maximum 0x300 records we walk before truncating — matches bundled's
/// `%insvLimit` (QuickTimeStream.pl:103-105).
const INSV_LIMIT_0X300: u64 = 20000;

// ===========================================================================
// Little-endian readers
// ===========================================================================

#[inline]
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .and_then(|s| <[u8; 2]>::try_from(s).ok())
    .map(u16::from_le_bytes)
}

#[inline]
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map(u32::from_le_bytes)
}

#[inline]
fn le_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .and_then(|s| <[u8; 8]>::try_from(s).ok())
    .map(u64::from_le_bytes)
}

#[inline]
fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  le_u64(b, off).map(f64::from_bits)
}

// ---------------------------------------------------------------------------
// Big-endian readers — `IdentifyTrailers` only. The Insta360 trailer BODY is
// always little-endian (`SetByteOrder('II')`); these decode the LigoGPS (always
// `MM`) and MIE (`MM`/`II` per signature) trailer LENGTH fields during the
// linked-list walk (QuickTime.pm:9906-9914).
// ---------------------------------------------------------------------------

#[inline]
fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map(u32::from_be_bytes)
}

#[inline]
fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .and_then(|s| <[u8; 8]>::try_from(s).ok())
    .map(u64::from_be_bytes)
}

// ===========================================================================
// Trailer signature detection
// ===========================================================================

/// `true` when `data` ends with an Insta360 trailer (last 32 bytes match
/// the magic ASCII hex). Faithful per `IdentifyTrailers`
/// (QuickTime.pm:9903-9905) — bundled reads 40 bytes from `EOF-40`, but
/// the actual signature check `eq` is on the LAST 32 bytes of that
/// buffer (`substr($buff, 8) eq '...'`); equivalent to "the file's last
/// 32 bytes are the magic".
#[must_use]
pub fn has_trailer(data: &[u8]) -> bool {
  let Some(tail_start) = data.len().checked_sub(MAGIC.len()) else {
    return false;
  };
  data.get(tail_start..) == Some(MAGIC.as_slice())
}

/// Parse the trailer length via ExifTool's `IdentifyTrailers` 40-byte LOCATOR
/// (QuickTime.pm:9897-9926), NOT the 78-byte `ProcessInsta360` footer. The
/// 40 bytes ending at `trail_end` are `[trailerLen:u32-LE][4 opaque][32-byte
/// ASCII magic]`, so the magic is at `trail_end-32` and the length at
/// `trail_end-40`. This needs only 40 bytes — so a trailer-bearing region of
/// 40..77 bytes is still IDENTIFIED (its positional `[minor] … trailer at
/// offset …` warning + the `scan_end` box bound), even though the 78-byte
/// record walk in [`walk_records`] then cannot run (it returns the trailer +
/// no records). For a region of >= 78 bytes the length offset (`trail_end-40`)
/// is identical to the old `unpack('x38V')` of the 78-byte footer, so the
/// common path is byte-for-byte unchanged.
///
/// `trail_end` is the file offset one-past the LAST byte of the Insta360
/// trailer (`= file_size` for a standalone trailer at EOF, `= entry.start +
/// entry.len` for an Insta360 trailer that `IdentifyTrailers` found behind a
/// later LigoGPS/MIE trailer — see [`identify_trailers`]).
fn read_trailer_len(data: &[u8], trail_end: usize) -> Option<u32> {
  let trail_end = trail_end.min(data.len());
  // QuickTime.pm:9903 — the signature is the LAST 32 bytes (`substr($buff, 8)`).
  let magic_start = trail_end.checked_sub(MAGIC.len())?;
  if data.get(magic_start..trail_end) != Some(MAGIC.as_slice()) {
    return None;
  }
  // The LE u32 length sits 40 bytes before `trail_end` (offset 0 of the 40-byte
  // locator, == `unpack('x38V')` offset 38 within the 78-byte footer).
  let len_off = trail_end.checked_sub(TRAILER_LEN_FROM_EOF)?;
  le_u32(data, len_off)
}

// ===========================================================================
// Linked-list trailer discovery (IdentifyTrailers, QuickTime.pm:9897-9926)
// ===========================================================================

/// `&&&&` magic at `buff[32..36]` — the LigoGPS trailer signature
/// (QuickTime.pm:9906 `$buff =~ /\&\&\&\&(.{4})$/`).
const LIGOGPS_MAGIC: &[u8; 4] = b"&&&&";

/// One trailer kind `IdentifyTrailers` (QuickTime.pm:9897-9926) recognizes at
/// the end of a QuickTime file. exifast only EXTRACTS the [`Self::Insta360`]
/// trailer; [`Self::LigoGPS`] / [`Self::Mie`] are recognized solely so the
/// backward [`identify_trailers`] walk can step PAST them to reach an Insta360
/// trailer that is not the final block, and so `ProcessMOV` bounds its box walk
/// to the EARLIEST trailer's start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrailerKind {
  /// The Insta360 INSV/INSP trailer (`ProcessInsta360`).
  Insta360,
  /// The LigoGPS trailer (`Image::ExifTool::LigoGPS`) — recognized, not parsed.
  LigoGPS,
  /// The MIE trailer (`Image::ExifTool::MIE`) — recognized, not parsed.
  Mie,
}

impl TrailerKind {
  /// The ExifTool trailer name (`'Insta360'` / `'LigoGPS'` / `'MIE'`,
  /// QuickTime.pm:9905-9912) — drives the positional `'%s trailer at offset
  /// 0x%x (%d bytes)'` warning (QuickTime.pm:10600).
  #[inline(always)]
  pub(crate) const fn as_str(&self) -> &'static str {
    match self {
      Self::Insta360 => "Insta360",
      Self::LigoGPS => "LigoGPS",
      Self::Mie => "MIE",
    }
  }

  /// `true` iff this is the Insta360 trailer. The [`identify_trailers`] consumer
  /// dispatches on this to drive `ProcessInsta360`.
  #[inline(always)]
  pub(crate) const fn is_insta360(&self) -> bool {
    matches!(self, Self::Insta360)
  }

  /// `true` iff this is the LigoGPS trailer. The [`identify_trailers`] consumer
  /// dispatches on this to drive
  /// [`crate::formats::ligogps::process_trailer`] (QuickTime.pm:10658-10668).
  /// MIE is still only stepped past (no dedicated predicate, matched via `==`).
  #[inline(always)]
  pub(crate) const fn is_ligogps(&self) -> bool {
    matches!(self, Self::LigoGPS)
  }
}

/// One trailer found by [`identify_trailers`]: its kind plus the absolute file
/// span. Mirrors a node of ExifTool's `IdentifyTrailers` linked list
/// (`[type, start, len, next]`, QuickTime.pm:9920).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrailerEntry {
  kind: TrailerKind,
  /// Absolute file offset of the trailer's FIRST byte (`$raf->Tell() - $len`,
  /// QuickTime.pm:9920). WRAPS (negative→unsigned, faithful to Perl's negative
  /// `start`) on a bad-size trailer whose `len` exceeds the bytes before it.
  start: u64,
  /// The trailer length as declared by its locator (QuickTime.pm:9920 `$len`).
  len: u64,
}

impl TrailerEntry {
  /// This trailer's [`TrailerKind`].
  #[inline(always)]
  pub(crate) const fn kind(&self) -> TrailerKind {
    self.kind
  }

  /// Absolute file offset of the trailer's first byte (see field doc — wraps on
  /// a bad-size trailer).
  #[inline(always)]
  pub(crate) const fn start(&self) -> u64 {
    self.start
  }

  /// The declared trailer length.
  #[inline(always)]
  pub(crate) const fn len(&self) -> u64 {
    self.len
  }
}

/// Maximum trailers the backward walk visits before giving up — a defensive cap
/// on a crafted chain (each iteration must consume ≥1 byte of `offset`, but a
/// `len == 0` is already rejected, so this is belt-and-suspenders only). Far
/// above any real-world QuickTime trailer count.
const MAX_TRAILERS: u32 = 1024;

/// Port of `IdentifyTrailers` (QuickTime.pm:9897-9926): a BACKWARD linked-list
/// walk from EOF that classifies each 40-byte block by signature
/// (Insta360 / LigoGPS / MIE), steps PAST it by its declared length, and stops
/// at the first unrecognized block. The returned `Vec` is HEAD-FIRST — the
/// EARLIEST (closest-to-BOF) trailer first, mirroring the linked-list head
/// ExifTool returns (`$trailer`, the last node prepended).
///
/// Faithful to the reference:
/// - `Seek(-40-offset, 2)` + `Read 40`: read the 40 bytes ending at
///   `file_size - offset`. `$raf->Tell()` after the read is `file_size -
///   offset`, so each trailer's `start = (file_size - offset) - len`.
/// - **Insta360** (QuickTime.pm:9904): `substr($buff,8)` (the LAST 32 bytes)
///   equals the magic; `len = unpack('V', buff)` (LE u32 at `buff[0..4]`).
/// - **LigoGPS** (QuickTime.pm:9906): `buff[32..36] == "&&&&"`; `len =
///   Get32u(buff, 36)` in the DEFAULT (BE/`MM`) order.
/// - **MIE** (QuickTime.pm:9907-9915): one of two end-anchored signatures; byte
///   order is `MM` when the `[\x10\x18]` group is `\x10` else `II`; `len =
///   Get32u(buff, 34)` (4-byte form) or `Get64u(buff, 30)` (8-byte form).
/// - else: stop (the reference `last`).
///
/// After each find, `offset += len`. A `len == 0` (would re-read the same
/// block forever) or a `Seek`/`Read` that cannot be satisfied (the block would
/// start before BOF, or `40 + offset > file_size`) stops the walk — matching
/// the reference's `Seek(...) and Read(...) == 40` loop guard. All arithmetic
/// is checked so a crafted `len` can neither panic nor loop unbounded.
#[must_use]
pub(crate) fn identify_trailers(data: &[u8]) -> Vec<TrailerEntry> {
  let file_size = data.len() as u64;
  // Built EOF-ward-first (each newly-found trailer is closer to BOF), then
  // reversed so the returned head is the EARLIEST trailer (the linked-list head).
  let mut found: Vec<TrailerEntry> = Vec::new();
  let mut offset: u64 = 0;
  let mut guard = MAX_TRAILERS;

  loop {
    if guard == 0 {
      break;
    }
    guard -= 1;

    // `Seek(-40-offset, 2)` then `Read 40`: the 40-byte window is
    // `[file_size - offset - 40, file_size - offset)`. Both bounds must be
    // in-range for the seek+read to succeed.
    let Some(window_end) = file_size.checked_sub(offset) else {
      break;
    };
    let Some(window_start) = window_end.checked_sub(TRAILER_LEN_FROM_EOF as u64) else {
      break; // not enough bytes before this point for a 40-byte read
    };
    let Some(buff) = data.get(window_start as usize..window_end as usize) else {
      break;
    };
    // `buff` is exactly 40 bytes here.

    let (kind, len) = if buff.get(8..) == Some(MAGIC.as_slice()) {
      // QuickTime.pm:9904-9905 — Insta360: LE u32 length at buff[0..4].
      let Some(len) = le_u32(buff, 0) else {
        break;
      };
      (TrailerKind::Insta360, u64::from(len))
    } else if buff.get(32..36) == Some(LIGOGPS_MAGIC.as_slice())
      && buff
        .get(36..40)
        .is_some_and(|len_bytes| !len_bytes.contains(&0x0A))
    {
      // QuickTime.pm:9906 — LigoGPS: BE u32 length at buff[36..40]. The regex
      // `/\&\&\&\&(.{4})$/` has NO `/s` flag, so the 4 captured length bytes
      // (`.`) must contain NO newline (`0x0A`); a length byte of `0x0A` fails
      // the match, so we fall through to the MIE/`last` arms (faithful).
      let Some(len) = be_u32(buff, 36) else {
        break;
      };
      (TrailerKind::LigoGPS, u64::from(len))
    } else if let Some(len) = mie_trailer_len(buff) {
      // QuickTime.pm:9907-9915 — MIE: byte-order- and form-dependent length.
      (TrailerKind::Mie, len)
    } else {
      break; // QuickTime.pm:9916 `last` — no recognized trailer here.
    };

    // A zero-length trailer would leave `offset` unchanged and re-read the same
    // block forever; the reference never advances on `len == 0` either (the next
    // Seek targets the identical position), so stop.
    if len == 0 {
      break;
    }

    // QuickTime.pm:9920 `[$type, $raf->Tell() - $len, $len, $nextTrail]`. Tell()
    // == window_end; `start` WRAPS like Perl's negative value on a bad-size len.
    let start = window_end.wrapping_sub(len);
    found.push(TrailerEntry { kind, start, len });

    // QuickTime.pm:9921 `$offset += $len`.
    let Some(next_offset) = offset.checked_add(len) else {
      break;
    };
    offset = next_offset;
  }

  // The reference returns the HEAD = the EARLIEST trailer (the last one found in
  // this EOF-ward walk). Reverse so callers see head-first.
  found.reverse();
  found
}

/// MIE trailer length per QuickTime.pm:9907-9915, or `None` when `buff` (the
/// 40-byte window) matches neither MIE signature. Both signatures are
/// END-ANCHORED (`/…$/s`), so they sit at fixed tail offsets of the 40-byte
/// window. In BOTH forms the byte-order byte is `buff[38]` (`MM` iff `0x10`,
/// else `II`) and the form marker is `buff[39]` (`\x04` / `\x08`):
///  - 4-byte form (18 bytes, `buff[22..40]`):
///    `~\0\x04\0` `zmie` `~\0\0\x06` `.{4}` `[\x10\x18]` `\x04`;
///    `len = Get32u(buff, 34)` (the `.{4}` wild bytes at `buff[34..38]`).
///  - 8-byte form (22 bytes, `buff[18..40]`):
///    `~\0\x04\0` `zmie` `~\0\0\x0a` `.{8}` `[\x10\x18]` `\x08`;
///    `len = Get64u(buff, 30)` (the `.{8}` wild bytes at `buff[30..38]`).
fn mie_trailer_len(buff: &[u8]) -> Option<u64> {
  /// `~\0\x04\0zmie` — the fixed 8-byte head shared by both MIE forms.
  const HEAD: &[u8; 8] = b"~\0\x04\0zmie";

  let bo_byte = buff.get(38)?;
  let order_be = match bo_byte {
    0x10 => true,  // QuickTime.pm:9911 `$1 eq "\x10" ? 'MM'` → big-endian
    0x18 => false, // → 'II' little-endian
    _ => return None,
  };
  match buff.get(39) {
    // 4-byte form: head at buff[22..30], `~\0\0\x06` at buff[30..34].
    Some(0x04)
      if buff.get(22..30) == Some(HEAD.as_slice())
        && buff.get(30..34) == Some(b"~\0\0\x06".as_slice()) =>
    {
      if order_be {
        be_u32(buff, 34)
      } else {
        le_u32(buff, 34)
      }
      .map(u64::from)
    }
    // 8-byte form: head at buff[18..26], `~\0\0\x0a` at buff[26..30].
    Some(0x08)
      if buff.get(18..26) == Some(HEAD.as_slice())
        && buff.get(26..30) == Some(b"~\0\0\x0a".as_slice()) =>
    {
      if order_be {
        be_u64(buff, 30)
      } else {
        le_u64(buff, 30)
      }
    }
    _ => None,
  }
}

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// Decode one 0x101 INSV_MakerNotes identity record
/// (QuickTimeStream.pl:3427-3436). The record body is a sequence of
/// `[tag:u8][len:u8][value:len bytes]` items; the bundled loop walks at
/// most 4 items.
fn decode_identity(buff: &[u8]) -> Insta360Identity {
  let mut out = Insta360Identity::new();
  let mut p = 0usize;
  // Bundled: `for ($i=0, $p=0; $i<4; ++$i) { ... }`. Walk up to 4 items.
  for _ in 0..4 {
    let (Some(&t), Some(&n_raw)) = (buff.get(p), buff.get(p + 1)) else {
      break;
    };
    let n = n_raw as usize;
    let Some(val) = buff.get(p + 2..p + 2 + n) else {
      break;
    };
    // QuickTimeStream.pl:3434 `$et->HandleTag($tagTablePtr, $t, $val)`.
    // These INSV maker-note values are raw byte substrings (QuickTimeStream.pl
    // :3433 `substr` + HandleTag — no Format/charset/RawConv), so bundled emits
    // them through the FULL JSON `EscapeJSON` order: it first CLASSIFIES the
    // ORIGINAL value (NULs and all) against the boolean/number gate
    // (exiftool:3805/3810) and, ONLY for a non-match, DELETES every NUL
    // (`tr/\0//d`, exiftool:3820) and THEN runs `FixUTF8` (exiftool:3824). The
    // classify PRECEDES the NUL-strip, so a NUL-bearing original always fails
    // the anchored gate → it is a QUOTED string, NOT a bare token: a NUL-split
    // numeric `31 00 32 00` → `"12"` (NOT bare `12`) and `74 00 72 00 75 00
    // 65 00` → `"true"` (NOT bare `true`). The NUL-strip-before-`FixUTF8` order
    // also rejoins a NUL-SPLIT UTF-8 sequence (`C2 00 A9` → `©`, not `??`). A
    // NUL-free clean-number/boolean original DOES pass the gate → BARE.
    //
    // `escape_json_raw_bytes_classified` returns that verdict
    // ([`EscapedJson::Bare`]/[`EscapedJson::Quoted`]); we store it via the
    // `*_json` setters so the emit can map `Bare`→`TagValue::Str` (the
    // serializer renders it bare) and `Quoted`→`TagValue::JsonStr` (forced
    // quoted, bypassing the serializer's re-run of the gate on the
    // ALREADY-NUL-stripped text). For the real all-ASCII device strings (no
    // NUL, valid UTF-8) the verdict is `Quoted` and the content is identity —
    // byte-identical to bundled's quoted output (#53/FU-12).
    use crate::convert::escape_json_raw_bytes_classified;
    match t {
      TAG_SERIAL_NUMBER => {
        out.set_serial_number_json(Some(escape_json_raw_bytes_classified(val, false)));
      }
      TAG_MODEL => {
        out.set_model_json(Some(escape_json_raw_bytes_classified(val, false)));
      }
      TAG_FIRMWARE => {
        out.set_firmware_json(Some(escape_json_raw_bytes_classified(val, false)));
      }
      TAG_PARAMETERS => {
        // QuickTimeStream.pl:705 `ValueConv => '$val =~ tr/_/ /; $val'`. The
        // `tr/_/ /` runs on the RAW `$val` BEFORE the `EscapeJSON` classify, so
        // map `_`→` ` on the raw bytes first, then classify the result — a
        // value that becomes number-shaped only after the `tr` is judged on the
        // post-`tr` lexeme exactly as ExifTool does (the `_`→` ` is ASCII and
        // commutes with the later NUL-strip + `FixUTF8`). No `_` ⇒ classify the
        // value in place (no allocation).
        if val.contains(&b'_') {
          let mapped: std::vec::Vec<u8> = val
            .iter()
            .map(|&b| if b == b'_' { b' ' } else { b })
            .collect();
          out.set_parameters_json(Some(escape_json_raw_bytes_classified(&mapped, false)));
        } else {
          out.set_parameters_json(Some(escape_json_raw_bytes_classified(val, false)));
        }
      }
      _ => {} // Unknown tag; bundled HandleTag with no-table-entry is a no-op.
    }
    p += 2 + n;
  }
  out
}

/// Decode one 0x400 exposure record row (QuickTimeStream.pl:3386-3391).
/// Each row is 16 bytes `[timestamp_ms:u64-LE][exposure_time_s:double-LE]`.
fn decode_exposure_row(row: &[u8]) -> Option<Insta360ExposureSample> {
  if row.len() < 16 {
    return None;
  }
  let mut s = Insta360ExposureSample::new();
  if let Some(ts) = le_u64(row, 0) {
    s.set_timestamp_ms(Some(ts));
  }
  if let Some(et) = le_f64(row, 8) {
    s.set_exposure_time_s(Some(et));
  }
  Some(s)
}

/// Decode one 0x700 GPS record row (QuickTimeStream.pl:3397-3425).
/// Returns `None` for void fixes (status `'V'`) or unrecognized NS/EW
/// chars (the latter is the bundled `Unrecognized INSV GPS format`
/// warning — return that to the caller).
fn decode_gps_row(row: &[u8]) -> Result<Option<Insta360GpsSample>, &'static str> {
  // unpack('VVvaa8aa8aa8a8a8', $tmp) ⇒ 4+4+2+1+8+1+8+1+8+8+8 = 53 bytes.
  if row.len() < 53 {
    return Ok(None);
  }
  // $a[0] u32 = unixtime, $a[1] u32 = unknown, $a[2] u16 = ms,
  // $a[3] = status char, $a[4] lat_bytes (8), $a[5] = NS char,
  // $a[6] lon_bytes (8), $a[7] = EW char,
  // $a[8] speed_bytes (8), $a[9] track_bytes (8), $a[10] alt_bytes (8).
  let unixtime = le_u32(row, 0).ok_or("short row")?;
  // $a[1] @ offset 4 is unused (the bundled `Unknown02` debug tag).
  let ms = le_u16(row, 8).ok_or("short row")?;
  let status = *row.get(10).ok_or("short row")?;
  let lat_raw = le_f64(row, 11).ok_or("short row")?;
  let ns = *row.get(19).ok_or("short row")?;
  let lon_raw = le_f64(row, 20).ok_or("short row")?;
  let ew = *row.get(28).ok_or("short row")?;
  let speed = le_f64(row, 29).ok_or("short row")?;
  let track = le_f64(row, 37).ok_or("short row")?;
  let alt = le_f64(row, 45).ok_or("short row")?;

  // QuickTimeStream.pl:3401-3409: validate NS/EW chars first.
  let ns_ok = ns == b'N' || ns == b'S';
  // `'O'` is the French "Ouest" variant some firmware emits
  // (QuickTimeStream.pl:3403-3405).
  let ew_ok = ew == b'E' || ew == b'W' || ew == b'O';
  if !(ns_ok && ew_ok) {
    // QuickTimeStream.pl:3407 `next if $a[3] eq 'V'` — void fixes don't
    // have valid N/S E/W; skip silently. Otherwise raise the bundled
    // 'Unrecognized INSV GPS format' warning.
    if status == b'V' {
      return Ok(None);
    }
    return Err("Unrecognized INSV GPS format");
  }
  // QuickTimeStream.pl:3411 `next unless $a[3] eq 'A'` — ignore void fixes.
  if status != b'A' {
    return Ok(None);
  }

  // QuickTimeStream.pl:3414 `$a[4] = -abs($a[4]) if $a[5] eq 'S'`.
  let lat = if ns == b'S' { -lat_raw.abs() } else { lat_raw };
  // QuickTimeStream.pl:3415 `$a[6] = -abs($a[6]) if $a[7] ne 'E'`
  // (both 'W' and 'O' flip the sign).
  let lon = if ew != b'E' { -lon_raw.abs() } else { lon_raw };

  // QuickTimeStream.pl:3416-3418 — render GPSDateTime as
  // `ConvertUnixTime($a[0]) . $ms . 'Z'`, where `$ms` is
  // `sprintf('.%.3d', $a[2])` with trailing zeros stripped, and is
  // empty when `$a[2]` is 0.
  let datetime_base = crate::datetime::convert_unix_time(unixtime as i64);
  let ms_suffix = if ms == 0 {
    SmolStr::new("")
  } else {
    // `sprintf('.%.3d', $a[2])` then `s/0+$//`.
    let raw = alloc::format!(".{:03}", ms);
    let trimmed = raw.trim_end_matches('0');
    // After the regex, if everything after the dot trimmed away, bundled
    // keeps the bare dot. Match that.
    SmolStr::new(trimmed)
  };
  let date_time = SmolStr::new(alloc::format!("{datetime_base}{ms_suffix}Z"));

  // QuickTimeStream.pl:74 `my $mpsToKph = 3.6` then :3421
  // `$et->HandleTag($tagTbl, GPSSpeed => $a[8] * $mpsToKph)`.
  let speed_kph = speed * 3.6;

  let mut out = Insta360GpsSample::new();
  out
    .set_date_time(Some(date_time))
    .set_latitude(Some(lat))
    .set_longitude(Some(lon))
    .set_speed_kph(Some(speed_kph))
    .set_track_deg(Some(track))
    .set_altitude_m(Some(alt));
  Ok(Some(out))
}

/// Pick the per-row stride for a 0x300 accelerometer record
/// (QuickTimeStream.pl:3327-3346). Each row is either 56 bytes (6 doubles) or
/// 20 bytes (6 int16). `len` is the record's DECLARED length (`$len`); the two
/// modulo arms key off it. `file_tail` is the FILE bytes from the record-body
/// start to EOF (NOT clamped to the trailer) — bundled's else-branch probe is
/// `$raf->Read($buff, 20)` against the RAF (the file), so it reads PAST a short
/// body into whatever follows (the next record's footer, the terminal block, …)
/// and succeeds whenever ≥ 20 bytes remain to EOF.
///
/// The bundled probe:
///  - `$len % 20 != 0 and $len % 56 == 0` ⇒ 56;
///  - `$len % 56 != 0 and $len % 20 == 0` ⇒ 20;
///  - else (`$len` a multiple of BOTH 20 and 56, e.g. 280; OR of NEITHER, e.g.
///    10/18/19/30): `Read($buff, 20) == 20` then probe `substr($buff,16,3)`:
///    all-zero ⇒ 56, else 20. If that 20-byte read FAILS (fewer than 20 bytes
///    remain from the body start to EOF) `$dlen` stays `0` and the record is
///    SILENTLY skipped (no rows, no warning) — the `0` return below.
///
/// Returns the per-row stride (56 or 20), or **`0`** as the faithful "skip
/// silently" sentinel for the else-branch `Read(20)`-FAILED case
/// (QuickTimeStream.pl:3340 ⇒ `$dlen` unchanged at 0 ⇒ `if ($dlen)` at :3355 is
/// false). Callers MUST treat a `0` stride as "decode nothing, warn nothing"
/// (the cap, the non-multiple check, and the per-row decode all guard against
/// it). A SHORT body that is a multiple of neither (e.g. 10 bytes) but has ≥ 20
/// file bytes after it does NOT skip: the probe succeeds → stride 20/56 → the
/// record's `len % stride != 0` then drives the `Unexpected … length` warning
/// downstream (faithful to bundled, which reads past the short body).
fn accel_stride(len: usize, file_tail: &[u8]) -> usize {
  if !len.is_multiple_of(20) && len.is_multiple_of(56) {
    56
  } else if !len.is_multiple_of(56) && len.is_multiple_of(20) {
    20
  } else if file_tail.len() >= 20 {
    // QuickTimeStream.pl:3340 `$raf->Read($buff, 20) == 20` — the read targets
    // the FILE at the record-body start, so it reads up to 20 bytes regardless
    // of the record's own (possibly short) body. `substr($buff, 16, 3) eq
    // "\0\0\0"`: in a 56-byte doubles row bytes 16..18 are the low 3 bytes of
    // the SECOND value (the double at offset 16), zero for the small magnitudes
    // Insta360 writes; in a 20-byte int16 row they are packed u16 data,
    // generally non-zero.
    if file_tail.get(16..19) == Some([0u8, 0, 0].as_slice()) {
      56
    } else {
      20
    }
  } else {
    // QuickTimeStream.pl:3340 `Read($buff, 20) == 20` FAILED — fewer than 20
    // bytes remain from the body start to EOF, so `$dlen` stays 0 and `if
    // ($dlen)` (:3355) skips the record SILENTLY (no rows, NO `Unexpected …
    // length` warning). `0` is the skip sentinel (see the fn doc).
    0
  }
}

/// Decode one 0x300 accelerometer row (QuickTimeStream.pl:3372-3385).
/// `dlen` is 56 (6 doubles) or 20 (6 int16, each `(v - 0x8000) / 1000`).
/// Returns `None` if the slot is too short for the stride.
fn decode_accel_row(row: &[u8], dlen: usize) -> Option<Insta360AccelSample> {
  let mut s = Insta360AccelSample::new();
  s.set_timecode_ms(Some(le_u64(row, 0)?));
  let mut comps = [0f64; 6];
  if dlen == 56 {
    for (i, c) in comps.iter_mut().enumerate() {
      *c = le_f64(row, 8 + 8 * i)?;
    }
  } else {
    for (i, c) in comps.iter_mut().enumerate() {
      // QuickTimeStream.pl:3382 `($_ - 0x8000) / 1000`.
      *c = (f64::from(le_u16(row, 8 + 2 * i)?) - 32768.0) / 1000.0;
    }
  }
  s.set_accelerometer(Some([comps[0], comps[1], comps[2]]));
  s.set_angular_velocity(Some([comps[3], comps[4], comps[5]]));
  Some(s)
}

/// Decode one 0x600 video-timestamp row (QuickTimeStream.pl:3392-3396).
/// Each row is 8 bytes `[VideoTimeStamp:u64-LE]`.
fn decode_videotime_row(row: &[u8]) -> Option<Insta360VideoTimeSample> {
  let mut s = Insta360VideoTimeSample::new();
  s.set_timecode_ms(Some(le_u64(row, 0)?));
  Some(s)
}

// ===========================================================================
// Shared record walk (the backward-chaining / dir-table / 0x300-cap loop)
// ===========================================================================

/// One record yielded by [`walk_records`] to its visitor. `body` is the
/// record's value-bytes (already CAPPED for an oversized 0x300 — see
/// [`RecordView::accel_capped`]); the walker has validated its length.
struct RecordView<'a> {
  /// The 2-byte record id (`%insvDataLen` key + the 0x000/0x101 forks).
  id: u16,
  /// The record value-bytes, EXCLUDING the 6-byte footer. For an oversized
  /// 0x300 this is the FIRST `20000 * stride` bytes (QuickTimeStream.pl
  /// :3347-3352).
  body: &'a [u8],
  /// `Some(stride)` for a 0x300 record — the per-row stride probed ONCE on
  /// the FULL (pre-cap) body (QuickTimeStream.pl:3326-3346); `None`
  /// otherwise. Passed through so the decoder does NOT re-probe the capped
  /// slice (R2 finding).
  accel_dlen: Option<usize>,
  /// `true` when this 0x300 record's body was truncated to the `%insvLimit`
  /// cap (QuickTimeStream.pl:3347-3352) — the driver owns the matching
  /// `Insta360 ... data is huge` warning. Only ever `true` for the FIRST
  /// capped 0x300 in walk order (bundled warns once).
  accel_capped: bool,
  /// `true` when this record has a FIXED per-row stride (0x300 → the probed
  /// `accel_dlen`, 0x400 → 16, 0x600 → 8) and its post-cap length is NOT a
  /// multiple of that stride. QuickTimeStream.pl:3355-3357: the FIRST branch
  /// of `if ($dlen) { if ($len % $dlen and $id != 0x700) { Warn } elsif ... }`
  /// — a non-multiple fixed-stride record (0x700 EXEMPT) emits ZERO rows (the
  /// `elsif` decode is skipped) and the walk CONTINUES. The visitor owns the
  /// `Unexpected Insta360 record 0x%x length` warning + the decode-nothing.
  non_multiple: bool,
}

/// The shared `ProcessInsta360` walk (QuickTimeStream.pl:3252-3478): locate
/// the trailer, then step LAST-record-first (with the 0x000 dir-table
/// forward-by-index fork + the 0x300 `%insvLimit` cap), invoking `visitor`
/// once per non-dir-table record. The visitor returns
/// [`ControlFlow::Break`] to stop the walk early (the light path uses this
/// once it has the whole domain summary) or [`ControlFlow::Continue`] to
/// keep walking (the full `-ee` decode always continues).
///
/// This is the ONE place the backward-chaining / dir-table / 0x300-cap +
/// stride-probe logic lives — both [`scan_trailer`] (light) and
/// [`decode_all_records`] (full) drive it. Per-row decode + the global
/// `DOC_NUM` counter live in the visitors, NOT here.
///
/// Faithful behaviour notes:
///
/// - QuickTimeStream.pl:3270-3271: read the last 78 bytes; verify the last
///   32 bytes are the magic ASCII hex string.
/// - QuickTimeStream.pl:3276: trailer length is at offset 38 within the
///   footer (LE u32).
/// - QuickTimeStream.pl:3277: `trailerLen > $trailEnd` ⇒ the `Bad Insta360
///   trailer size` soft-fail. ExifTool emits the positional trailer warning
///   with the WRAPPED (negative→unsigned) offset, then suppresses the bad-size
///   warning via priority-0 first-wins; so we surface the trailer (so the
///   positional warning emits) but decode nothing (return before the walk).
/// - QuickTimeStream.pl:3308: `SetByteOrder('II')` — all multi-byte ints in
///   the trailer body are LE.
/// - QuickTimeStream.pl:3310-3470: walk LAST-to-FIRST from `$epos = -78`
///   (footer offset). Each iteration reads `[id:u16-LE][len:u32-LE]`, seeks
///   to the body, dispatches, then steps back 6 bytes (or, in dir-table
///   mode, jumps forward-by-index).
///
/// **`trail_end`** is the file offset one-past the LAST byte of the Insta360
/// trailer — `data.len()` for a standalone trailer at EOF, or `entry.start +
/// entry.len` for an Insta360 trailer that `IdentifyTrailers` found behind a
/// later LigoGPS/MIE trailer ([`identify_trailers`]). Every EOF anchor below is
/// `trail_end` (NOT `data.len()`): the locator is read at `trail_end-40` and the
/// record walk steps backward from `trail_end`. When `trail_end == data.len()`
/// (the standalone case) the behaviour is byte-identical to anchoring at EOF.
///
/// **Edge cases.**
/// - A region shorter than 78 bytes / without the magic UUID → no trailer
///   (`None`).
/// - A trailer claiming `trailerLen > trail_end` → `Some((wrapped_offset,
///   trailer_len))` (so the positional warning emits), no records walked.
/// - A record `len` overflow / position past start-of-trailer → stop the
///   walk cleanly (per the bundled guards).
fn walk_records<V>(data: &[u8], trail_end: usize, visitor: &mut V) -> Option<(u64, u32)>
where
  V: FnMut(RecordView<'_>) -> core::ops::ControlFlow<()>,
{
  // The trailer cannot end past EOF; clamp defensively so every offset below is
  // in-bounds even for a crafted `trail_end`.
  let trail_end_usize = trail_end.min(data.len());
  // QuickTimeStream.pl:3270-3271 — locate footer + verify magic.
  let trailer_len_raw = read_trailer_len(data, trail_end_usize)?; // None ⇒ no trailer
  let trailer_len = trailer_len_raw as u64;
  // `$raf->Tell()` after the locator read is at the trailer's END; bundled's
  // `$trailEnd = $raf->Tell()`. For a standalone trailer this is the file size.
  let trail_end = trail_end_usize as u64;
  // QuickTimeStream.pl:3277 `$trailerLen > $trailEnd and $et->Warn(...)`. On a
  // bad size, ExifTool emits the positional trailer warning with the WRAPPED
  // (negative→unsigned) offset (`trail_end - trailer_len` < 0 as u64), then
  // suppresses "Bad Insta360 trailer size" via priority-0 first-wins. So we
  // surface the trailer (so the positional warning emits) but decode NOTHING —
  // return before the walk loop, visiting no records.
  if trailer_len > trail_end {
    return Some((trail_end.wrapping_sub(trailer_len), trailer_len_raw));
  }
  // The identified trailer's `(file_offset, byte_size)`. The trailer spans
  // `[trail_end - trailer_len, trail_end)`; the offset is its start. (Valid
  // case: `trail_end >= trailer_len`, so the wrap is a no-op.)
  let outcome_trailer = Some((trail_end.wrapping_sub(trailer_len), trailer_len_raw));
  // Trailer spans `[trail_end - trailer_len, trail_end)` in file bytes.
  // Bundled tracks position as a NEGATIVE offset from `trail_end`:
  //   $epos = -78  ⇒ footer start
  //   $epos -= $len after parsing each record body
  // The loop terminates when `$epos + $trailerLen < 0` (we've gone past the
  // trailer's start). Translate to positive file offsets:
  //   abs_pos = trail_end + epos   (since epos < 0)
  // The trailer's start in file coords is `trail_end - trailer_len`.

  // Bundled `Seek(-78, 2)` (== `trail_end - 78`); the footer read fails when the
  // trailer ends within its first 78 bytes.
  if trail_end < FOOTER_SIZE as u64 {
    return outcome_trailer;
  }
  // `epos` is the (negative) offset-from-`trail_end` of the CURRENT 6-byte
  // footer.
  let mut epos: i64 = -(FOOTER_SIZE as i64);

  // QuickTimeStream.pl:3311 `unpack('vV', $buff)` — the FIRST 6 bytes of the
  // 78-byte footer ARE the last record's footer. The footer sits at
  // `trail_end - 78` (INSIDE the trailer), so its 6 read bytes never reach a
  // following LigoGPS/MIE trailer.
  let Some(footer_buf) = (trail_end as usize)
    .checked_sub(FOOTER_SIZE)
    .and_then(|start| data.get(start..))
  else {
    return outcome_trailer;
  };
  let mut cur_id = match le_u16(footer_buf, 0) {
    Some(v) => v,
    None => return outcome_trailer,
  };
  let mut cur_len = match le_u32(footer_buf, 2) {
    Some(v) => v,
    None => return outcome_trailer,
  };

  // Directory table state (QuickTimeStream.pl:3449-3466). When a `0x000`
  // record is encountered, we LATCH the dir-table payload and switch to
  // forward-by-index dispatch. `dir_table_pos` advances by 10 bytes per entry
  // (`[id:u16-LE][siz:u32-LE][off:u32-LE]`).
  let mut dir_table: Option<&[u8]> = None;
  let mut dir_table_pos = 0usize;

  // Per-record cap latch — bundle's `%insvLimit` (0x300 only, warns once —
  // QuickTimeStream.pl:3347-3352).
  let mut accel_capped_once = false;

  // Hard guard on the number of records we walk (defensive against a
  // malformed dir table or len that would infinite-loop). 2_000_000 is well
  // above any real-world Insta360 trailer's record count.
  let mut hard_guard: u32 = 2_000_000;

  loop {
    if hard_guard == 0 {
      break;
    }
    hard_guard -= 1;

    let id = cur_id;
    let len = cur_len;

    // QuickTimeStream.pl:3312 `($epos -= $len) + $trailerLen < 0 and last`.
    epos = epos.saturating_sub(len as i64);
    if (epos + trailer_len as i64) < 0 {
      break;
    }

    // QuickTimeStream.pl:3313 `$raf->Seek($epos-$offset, 2) or last` — seek to
    // the record body start.
    let body_abs = (trail_end as i64) + epos;
    if body_abs < 0 || (body_abs as u64) + (len as u64) > trail_end {
      break;
    }
    let body_start = body_abs as usize;

    // QuickTimeStream.pl:3327-3346: probe the 0x300 stride ONCE, keyed off the
    // record's DECLARED `len` plus the FILE bytes from the body start to EOF
    // (`data[body_start..]`, NOT clamped to the trailer — bundled's else-branch
    // probe `$raf->Read($buff, 20)` reads the FILE past a short body). This
    // single `dlen` is retained for BOTH the cap (QuickTimeStream.pl:3347-3352)
    // AND the decode (3372-3385) — it is NOT re-probed on the capped slice. A
    // capped length can be a multiple of BOTH 20 and 56 (e.g. a 56-byte record
    // capped to 1120000 B); a re-probe there falls to the byte-16 heuristic,
    // which a real doubles row (non-zero bytes 16..18) flips to stride 20,
    // emitting 56000 bogus rows (R2 finding).
    let accel_dlen: Option<usize> = (id == ID_ACCELEROMETER)
      .then(|| accel_stride(len as usize, data.get(body_start..).unwrap_or(&[])));

    // QuickTimeStream.pl:3340/3355 — the else-branch `Read($buff, 20)` FAILED
    // (`accel_dlen == Some(0)`): `$dlen` stays 0, so `if ($dlen)` is false and
    // (0x300 being neither 0x101 nor 0x000) the record matches NO dispatch
    // branch — it is SKIPPED SILENTLY (no rows, no `Unexpected … length`
    // warning, no cap). `accel_skip` carries that down to the dispatch block so
    // the visitor is NOT called; the shared footer-step at the loop tail then
    // advances correctly for BOTH the sequential and dir-table modes. (A 0x300
    // is never a dir-table record, but routing through the shared step keeps the
    // stepping logic in one place.) The non-ZERO non-multiple case — e.g. a
    // 10-byte body with ≥ 20 file bytes after it → stride 20 → `len % 20 != 0` —
    // does NOT come here; it reaches the visitor's `non_multiple` warning path.
    let accel_skip = accel_dlen == Some(0);

    // QuickTimeStream.pl:3347-3352 — `%insvLimit` cap (0x300 only) = 20000 *
    // dlen. A 20-byte-stride record caps at 400000 B, a 56-byte one at 1120000
    // B — NOT a blanket 56-byte cap (which would let a 20-byte trailer of
    // 400001..1120000 B escape the cap entirely and over-emit). A `dlen == 0`
    // skip sentinel is filtered out below, so it never feeds `20000 * 0`.
    let mut this_accel_capped = false;
    let effective_len = if let Some(dlen) = accel_dlen.filter(|&d| d != 0) {
      // `if ($dlen and $insvLimit{$id} ...)` (QuickTimeStream.pl:3347) — a
      // `dlen == 0` (the short-body skip sentinel) is falsy, so it is NEVER
      // capped (the `.filter(|d| d != 0)` mirrors the `$dlen and` guard).
      let cap = INSV_LIMIT_0X300.saturating_mul(dlen as u64);
      if (len as u64) > cap {
        // Bundled emits the `Insta360 ... data is huge` warning here (once);
        // the driver owns the warning channel, so flag the FIRST capped 0x300.
        if !accel_capped_once {
          this_accel_capped = true;
          accel_capped_once = true;
        }
        cap as u32
      } else {
        len
      }
    } else {
      len
    };

    let Some(body) = data.get(body_start..body_start + effective_len as usize) else {
      break;
    };

    // QuickTimeStream.pl:3355-3357 — the FIXED per-row stride (if any) for the
    // `if ($dlen) { if ($len % $dlen and $id != 0x700) { ... } }` non-multiple
    // check. 0x300 → the probed stride; 0x400 → 16; 0x600 → 8. 0x700 (53) is
    // EXEMPT (it decodes complete rows on a non-multiple length), and 0x200 sets
    // `$dlen = $len` (always a multiple) — so neither carries a fixed stride
    // here. 0x101/0x000 are not in `%insvDataLen` at all. The check uses the
    // POST-cap `effective_len` (matching bundled's post-cap `$len`).
    let fixed_stride: Option<usize> = match id {
      ID_ACCELEROMETER => accel_dlen,
      ID_EXPOSURE => Some(16),
      ID_VIDEO_TIMESTAMP => Some(8),
      _ => None,
    };
    let non_multiple =
      fixed_stride.is_some_and(|d| d != 0 && !(effective_len as usize).is_multiple_of(d));

    // QuickTimeStream.pl:3437 `} elsif ($id == 0x0) { ... }` — directory table
    // latch (QuickTimeStream.pl:3437-3453).
    if id == ID_DIRECTORY_TABLE {
      // `last if not $len` — bundled stops the LAST-to-FIRST walk if the
      // directory table is empty.
      if len == 0 {
        break;
      }
      // Latch the directory table contents (only the FIRST one seen). BORROW
      // the body slice (it lives in `data`) instead of cloning — a crafted
      // 0x000 record can be as large as the trailer permits, and the table is
      // read sequentially in 10-byte entries, so an owned copy of
      // attacker-sized bytes is an avoidable allocation (R2 finding).
      if dir_table.is_none() {
        dir_table = Some(body);
        dir_table_pos = 0;
      }
    } else if accel_skip {
      // QuickTimeStream.pl:3340/3355 — a 0x300 whose else-branch `Read(20)`
      // failed (`$dlen == 0`) matches NO dispatch branch: skip the visitor
      // entirely (no rows, no warning), fall through to the shared footer-step.
    } else {
      // Hand every other record to the visitor. (Note: bundled has a specific
      // `if ($dlen) { ... } elsif ($id == 0x101)` structure — the 0x101 path
      // is NOT inside `%insvDataLen` so it falls into the `elsif`. The visitor
      // handles 0x101 by id.) The visitor may stop the walk early.
      let flow = visitor(RecordView {
        id,
        body,
        accel_dlen,
        accel_capped: this_accel_capped,
        non_multiple,
      });
      if flow.is_break() {
        break;
      }
    }

    // QuickTimeStream.pl:3455-3469: if a dir-table was latched, choose the next
    // record's FOOTER position by index; otherwise step back 6 bytes to the
    // previous record's footer. BOTH paths only set `epos` here — the actual
    // `(id, len)` for the next iteration is read from the 6-byte FOOTER at
    // `epos` by the SHARED seek+read below (QuickTimeStream.pl:3470-3471), NEVER
    // taken from the dir-table entry (which carries `(id, siz, off)` used solely
    // to compute `$epos = $off + $siz - $trailerLen`).
    if let Some(dt) = dir_table {
      // Walk dir-table entries until we find a usable one.
      let mut found_next = false;
      loop {
        if dir_table_pos + 10 > dt.len() {
          break;
        }
        let next_id = match le_u16(dt, dir_table_pos) {
          Some(v) => v,
          None => break,
        };
        let next_siz = match le_u32(dt, dir_table_pos + 2) {
          Some(v) => v,
          None => break,
        };
        let next_off = match le_u32(dt, dir_table_pos + 6) {
          Some(v) => v,
          None => break,
        };
        dir_table_pos += 10;
        // QuickTimeStream.pl:3461 `if ($id and $siz and $off + $siz <
        // $trailerLen)`.
        if next_id != 0 && next_siz != 0 && (next_off as u64) + (next_siz as u64) < trailer_len {
          // QuickTimeStream.pl:3462 `$epos = $off + $siz - $trailerLen` — the
          // next record's FOOTER offset (NEGATIVE). The table's id/siz are NOT
          // adopted as the record's id/len; the footer read below supplies them.
          epos = (next_off as i64) + (next_siz as i64) - (trailer_len as i64);
          found_next = true;
          break;
        }
      }
      if !found_next {
        // QuickTimeStream.pl:3466 `last unless defined $epos` — dir table is
        // exhausted or yielded no usable entry.
        break;
      }
      // NOTE: the dir-table branch does NOT subtract 6 (it jumps to an absolute
      // footer offset); fall through to the SHARED footer read below.
    } else {
      // QuickTimeStream.pl:3468 `($epos -= 6) + $trailerLen < 0 and last`.
      epos = epos.saturating_sub(RECORD_FOOTER_SIZE as i64);
      if (epos + trailer_len as i64) < 0 {
        break;
      }
    }

    // QuickTimeStream.pl:3470-3471 `$raf->Seek($epos-$offset, 2) or last;
    // $raf->Read($buff, 6) == 6 or last` — read the ACTUAL 6-byte footer at
    // `epos`; the next iteration's `unpack('vV')` (3311) dispatches on the id/len
    // FROM THIS FOOTER. Shared by both the sequential and dir-table paths so a
    // crafted dir-table entry cannot make the walker decode arbitrary bytes as
    // its claimed id/size.
    let next_footer_abs = (trail_end as i64) + epos;
    if next_footer_abs < 0 || (next_footer_abs as u64) + (RECORD_FOOTER_SIZE as u64) > trail_end {
      break;
    }
    let Some(next_footer_buf) =
      data.get(next_footer_abs as usize..next_footer_abs as usize + RECORD_FOOTER_SIZE)
    else {
      break;
    };
    cur_id = match le_u16(next_footer_buf, 0) {
      Some(v) => v,
      None => break,
    };
    cur_len = match le_u32(next_footer_buf, 2) {
      Some(v) => v,
      None => break,
    };
  }

  outcome_trailer
}

// ===========================================================================
// Full decode (the `-ee` path) — all per-row decode + DOC_NUM + warnings
// ===========================================================================

/// Every timed row + identity `ProcessInsta360` surfaces for a trailer,
/// decoded EAGERLY — produced by [`decode_all_records`] at `-ee` emit time
/// (NOT during the opts-agnostic parse). The Vecs are in walk order (last
/// record visited first, so ascending `Doc<N>`); each carries its global
/// `DOC_NUM` stamp.
#[derive(Debug, Default, PartialEq)]
pub struct Insta360FullDecode {
  /// `0x700` GPS samples (each `status == 'A'` fix), ascending `Doc<N>`.
  gps: Vec<Insta360GpsSample>,
  /// `0x400` exposure-time samples, ascending `Doc<N>`.
  exposure: Vec<Insta360ExposureSample>,
  /// `0x600` video-timestamp samples, ascending `Doc<N>`.
  videotime: Vec<Insta360VideoTimeSample>,
  /// `0x300` accelerometer samples, ascending `Doc<N>`.
  accel: Vec<Insta360AccelSample>,
  /// The `0x101` identity record WITH its sticky `DOC_NUM` (inherits the
  /// value the last surfaced timed row left — QuickTimeStream.pl:3427-3436).
  identity: Option<Insta360Identity>,
  /// Decode-time warnings in walk order, each STAMPED with the `DOC_NUM` that
  /// was current (sticky) when it was raised (`Insta360 ... data is huge`
  /// :3349, `Unexpected Insta360 record 0x%x length` :3357, `Unrecognized INSV
  /// GPS format` :3408). ALL are raised inside `ProcessInsta360` while
  /// `SET_GROUP0='Trailer'`/`SET_GROUP1='Insta360'` is active, so they surface
  /// as `Trailer`/`Insta360` `Warning` tags (priority-0 first-wins), NOT
  /// `ExifTool:Warning` — at `-G3` each rides its stamped `Doc<N>`. The
  /// parse-time `Bad Insta360 trailer size` is NOT here (surfaced by
  /// [`scan_trailer`] via the positional trailer warning).
  warnings: Vec<(u32, SmolStr)>,
}

impl Insta360FullDecode {
  /// `0x700` GPS samples (each `status == 'A'` fix), ascending `Doc<N>`.
  #[inline(always)]
  #[must_use]
  pub fn gps(&self) -> &[Insta360GpsSample] {
    self.gps.as_slice()
  }

  /// `0x400` exposure-time samples, ascending `Doc<N>`.
  #[inline(always)]
  #[must_use]
  pub fn exposure(&self) -> &[Insta360ExposureSample] {
    self.exposure.as_slice()
  }

  /// `0x600` video-timestamp samples, ascending `Doc<N>`.
  #[inline(always)]
  #[must_use]
  pub fn videotime(&self) -> &[Insta360VideoTimeSample] {
    self.videotime.as_slice()
  }

  /// `0x300` accelerometer samples, ascending `Doc<N>`.
  #[inline(always)]
  #[must_use]
  pub fn accel(&self) -> &[Insta360AccelSample] {
    self.accel.as_slice()
  }

  /// The `0x101` identity record (with its sticky `DOC_NUM`), if any.
  #[inline(always)]
  #[must_use]
  pub const fn identity(&self) -> Option<&Insta360Identity> {
    self.identity.as_ref()
  }

  /// Decode-time warnings in walk order, each paired with the sticky `Doc<N>`
  /// it was raised under (`0` ⇒ Main). Emitted as `Trailer`/`Insta360`
  /// `Warning` tags (priority-0 first-wins; at `-G3` under the stamped doc).
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[(u32, SmolStr)] {
    self.warnings.as_slice()
  }
}

/// EAGERLY decode every timed row + identity from an Insta360 trailer — the
/// `-ee` path of `ProcessInsta360` (QuickTimeStream.pl:3252-3478). This is
/// the FULL walk (all per-row decode + the GLOBAL `DOC_NUM` stamping + the
/// `Insta360 ... data is huge` / `Unrecognized INSV GPS format` warnings).
///
/// Deferred out of the opts-agnostic parse so a crafted trailer of millions
/// of rows (esp. 0x600 VideoTimeStamp at 8 bytes/row) does NOT allocate
/// those Vecs unless `-ee` actually asks for them. Returns an empty
/// [`Insta360FullDecode`] when `raw` carries no decodable trailer.
///
/// `trail_end` is the file offset one-past the LAST byte of the Insta360
/// trailer — `raw.len()` when it sits at EOF, or `entry.start + entry.len`
/// when [`identify_trailers`] found it behind a later LigoGPS/MIE trailer.
///
/// The GLOBAL `DOC_NUM` counter (QuickTimeStream.pl `++$$et{DOC_NUM}`) is
/// `++`'d once per SURFACED timed row across ALL record types in walk order
/// (last record first); a void/skipped GPS row does NOT bump it, and the
/// `0x101` identity INHERITS the current (sticky) value
/// (QuickTimeStream.pl:3427-3436 has no `FoundSomething`).
///
/// `doc_base` is the SHARED `$$et{DOC_COUNT}` value at the moment
/// `ProcessInsta360` runs in `ProcessMOV`'s trailer loop (after every moov-timed
/// + `udta`-LigoGPS + earlier-chain trailer source), so each surfaced row gets
/// `Doc<doc_base + N>` — continuing the ONE global sequence (`$$et{DOC_NUM} =
/// ++$$et{DOC_COUNT}`). For an Insta360-only file `doc_base == 0` and the first
/// surfaced row is `Doc1` (byte-identical to the pre-unification local counter).
/// The STICKY current doc (`$$et{DOC_NUM}`, which the `0x101` identity + the
/// warnings inherit) starts UNDEF (rendered Main / `0`) at trailer start — it is
/// NOT seeded from `doc_base`: a warning/identity BEFORE any timed row stays Main
/// even when `doc_base > 0` (ExifTool `delete`s `$$et{DOC_NUM}` between subs, so
/// it is undef until the first row's `FoundSomething`).
#[must_use]
pub fn decode_all_records(raw: &[u8], trail_end: usize, doc_base: u32) -> Insta360FullDecode {
  let mut out = Insta360FullDecode::default();
  // The SHARED global running count (`$$et{DOC_COUNT}`): `++` once per surfaced
  // timed row; starts at `doc_base`, so the first surfaced row becomes
  // `Doc<doc_base + 1>`.
  let mut doc_count: u32 = doc_base;
  // The STICKY current doc (`$$et{DOC_NUM}`) the identity + warnings inherit;
  // UNDEF (Main → `0`) until the first surfaced row, then the last row's global
  // doc. Tracked SEPARATELY from `doc_count` so a warning/identity before any row
  // stays Main even when `doc_base > 0` (ExifTool starts each sub with `$$et
  // {DOC_NUM}` deleted).
  let mut sticky_doc: u32 = 0;

  let mut visit = |rec: RecordView<'_>| -> core::ops::ControlFlow<()> {
    if rec.accel_capped {
      // QuickTimeStream.pl:3347-3352 — the once-only `%insvLimit` warning,
      // raised before this record's row loop, so it rides the sticky DOC_NUM.
      out.warnings.push((
        sticky_doc,
        SmolStr::new(
          "[Minor] Insta360 accelerometer data is huge. Processing only the first 20000 records",
        ),
      ));
    }
    // QuickTimeStream.pl:3355-3357 — a fixed-stride record (0x300/0x400/0x600;
    // 0x700 exempt) whose post-cap length is NOT a multiple of the stride emits
    // ZERO rows (the `elsif` decode branch is skipped) and the walk CONTINUES.
    // Bundled raises `Unexpected Insta360 record 0x%x length` (a `Trailer`/
    // `Insta360` `Warning`, priority-0 first-wins) under the sticky DOC_NUM.
    if rec.non_multiple {
      out.warnings.push((
        sticky_doc,
        SmolStr::from(alloc::format!(
          "Unexpected Insta360 record 0x{:x} length",
          rec.id
        )),
      ));
      return core::ops::ControlFlow::Continue(());
    }
    match rec.id {
      ID_IDENTITY => {
        let mut id_dec = decode_identity(rec.body);
        if !id_dec.is_empty() {
          // Sticky DOC_NUM: the identity rides whatever the last surfaced
          // timed row left the counter at (0 ⇒ flat/Main). Bundled emits at
          // most one 0x101 per trailer — keep the FIRST.
          id_dec.set_doc(Some(sticky_doc));
          if out.identity.is_none() {
            out.identity = Some(id_dec);
          }
        }
      }
      ID_ACCELEROMETER => {
        // QuickTimeStream.pl:3372-3385 decode. The stride was probed ONCE on
        // the FULL body in walk_records and passed in — do NOT re-probe the
        // (capped) slice (R2 finding). The local re-probe is a defensive
        // fallback only (walk_records always sets `accel_dlen` for a 0x300, and
        // a `Some(0)` skip sentinel never reaches the visitor); it probes the
        // body slice as both the length and file-tail. A `0` stride means
        // decode nothing.
        let dlen = rec
          .accel_dlen
          .unwrap_or_else(|| accel_stride(rec.body.len(), rec.body));
        if dlen != 0 {
          let mut p = 0usize;
          while let Some(slot) = rec.body.get(p..p + dlen) {
            if let Some(mut s) = decode_accel_row(slot, dlen) {
              doc_count += 1;
              sticky_doc = doc_count;
              s.set_doc(Some(doc_count));
              out.accel.push(s);
            }
            p += dlen;
          }
        }
      }
      ID_EXPOSURE => {
        // QuickTimeStream.pl:3386-3391 — stride is the entry in `%insvDataLen`
        // (16 bytes).
        let dlen = 16usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          if let Some(mut s) = decode_exposure_row(slot) {
            doc_count += 1;
            sticky_doc = doc_count;
            s.set_doc(Some(doc_count));
            out.exposure.push(s);
          }
          p += dlen;
        }
      }
      ID_VIDEO_TIMESTAMP => {
        // QuickTimeStream.pl:3392-3396 — 8-byte rows.
        let dlen = 8usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          if let Some(mut s) = decode_videotime_row(slot) {
            doc_count += 1;
            sticky_doc = doc_count;
            s.set_doc(Some(doc_count));
            out.videotime.push(s);
          }
          p += dlen;
        }
      }
      ID_GPS => {
        // QuickTimeStream.pl:3397-3425 — stride is 53 bytes; bundled tolerates
        // non-multiple lengths (the `if ($len % $dlen and $id != 0x700)` guard
        // explicitly exempts 0x700).
        let dlen = 53usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          match decode_gps_row(slot) {
            Ok(Some(mut s)) => {
              // QuickTimeStream.pl:3411-3424 — only an 'A' fix surfaces, and
              // `FoundSomething` (the `++$$et{DOC_NUM}`) runs only then; a void
              // ('V') row is `next`-skipped and does NOT advance the counter.
              doc_count += 1;
              sticky_doc = doc_count;
              s.set_doc(Some(doc_count));
              out.gps.push(s);
            }
            Ok(None) => {} // void fix or NS/EW indicated 'V' status — no doc bump
            Err(w) => {
              // QuickTimeStream.pl:3408 — raised BEFORE this row's DOC_NUM bump,
              // so it rides the sticky doc (the last surfaced row's, or 0).
              out.warnings.push((sticky_doc, SmolStr::new(w)));
              // QuickTimeStream.pl:3409 `last;` — stop walking this record's
              // remaining rows on a format-warning. The outer record-loop
              // continues with the next record.
              break;
            }
          }
          p += dlen;
        }
      }
      // 0x000 directory-table is handled inside walk_records (never reaches a
      // visitor). 0x200 PreviewImage — walked but not surfaced.
      _ => {}
    }
    core::ops::ControlFlow::Continue(())
  };

  let _ = walk_records(raw, trail_end, &mut visit);
  out
}

// ===========================================================================
// Streaming decode (the `-ee -G1` path) — one row at a time, NO per-row storage
// ===========================================================================

/// One item yielded by [`stream_records`], in WALK order (last record first).
/// Each timed-row variant is a single decoded sample; [`Self::Identity`] is the
/// `0x101` record; [`Self::Warning`] is a decode-time warning (`Insta360 ...
/// data is huge`, `Unexpected Insta360 record 0x%x length`, `Unrecognized INSV
/// GPS format`). Carries NO `Doc<N>` — the `-ee -G1` collapse is pure
/// walk-order first-wins-by-name, so the doc axis is unnecessary
/// (QuickTimeStream.pl assigns `++$$et{DOC_NUM}` per row in walk order, which is
/// doc-ascending, and every row's tag names are unique within its own doc, so a
/// `-G1` `%noDups` collapse degenerates to walk-order first-wins).
pub enum Insta360StreamItem {
  /// A `0x700` GPS `'A'` fix (QuickTimeStream.pl:3397-3425).
  Gps(Insta360GpsSample),
  /// A `0x400` exposure-time row (QuickTimeStream.pl:3386-3391).
  Exposure(Insta360ExposureSample),
  /// A `0x600` video-timestamp row (QuickTimeStream.pl:3392-3396).
  VideoTime(Insta360VideoTimeSample),
  /// A `0x300` accelerometer row (QuickTimeStream.pl:3372-3385).
  Accel(Insta360AccelSample),
  /// The `0x101` identity record (QuickTimeStream.pl:3427-3436) — the FIRST one
  /// in walk order (bundled keeps the first).
  Identity(Insta360Identity),
  /// A decode-time warning, yielded at its walk position.
  Warning(SmolStr),
}

/// STREAM every timed row + identity + decode-warning of an Insta360 trailer to
/// `visitor`, one at a time in WALK order, WITHOUT materializing any per-row Vec
/// — the bounded-memory `-ee -G1` path of `ProcessInsta360`. This is the same
/// walk as [`decode_all_records`] but it stamps no `DOC_NUM` and stores nothing:
/// the caller's `-G1` first-wins-by-name collapse is O(distinct names), so a
/// crafted huge 0x600/0x300 record cannot force O(rows) memory.
///
/// The per-record handling is byte-identical to [`decode_all_records`]'s visitor
/// minus the storage + the doc counter: the once-only `%insvLimit` "data is
/// huge" warning fires first, a non-multiple fixed-stride record yields its
/// `Unexpected … length` warning and is otherwise skipped (0x700 exempt), and a
/// GPS row-format warning `last`s this record's remaining rows (the outer walk
/// continues).
///
/// `trail_end` is the file offset one-past the LAST byte of the Insta360
/// trailer (see [`decode_all_records`]) — `raw.len()` for a standalone trailer.
pub fn stream_records<V>(raw: &[u8], trail_end: usize, visitor: &mut V)
where
  V: FnMut(Insta360StreamItem),
{
  let mut have_identity = false;

  let mut visit = |rec: RecordView<'_>| -> core::ops::ControlFlow<()> {
    if rec.accel_capped {
      visitor(Insta360StreamItem::Warning(SmolStr::new(
        "[Minor] Insta360 accelerometer data is huge. Processing only the first 20000 records",
      )));
    }
    // QuickTimeStream.pl:3355-3357 — a non-multiple fixed-stride record decodes
    // NOTHING (0x700 exempt). Same `Unexpected … length` warning as the full
    // decode; then skip.
    if rec.non_multiple {
      visitor(Insta360StreamItem::Warning(SmolStr::from(alloc::format!(
        "Unexpected Insta360 record 0x{:x} length",
        rec.id
      ))));
      return core::ops::ControlFlow::Continue(());
    }
    match rec.id {
      ID_IDENTITY => {
        let id_dec = decode_identity(rec.body);
        if !id_dec.is_empty() && !have_identity {
          have_identity = true;
          visitor(Insta360StreamItem::Identity(id_dec));
        }
      }
      ID_ACCELEROMETER => {
        // The stride was probed in walk_records and passed in; the fallback is
        // defensive only (a `Some(0)` skip sentinel never reaches the visitor).
        // A `0` stride ⇒ yield nothing.
        let dlen = rec
          .accel_dlen
          .unwrap_or_else(|| accel_stride(rec.body.len(), rec.body));
        if dlen != 0 {
          let mut p = 0usize;
          while let Some(slot) = rec.body.get(p..p + dlen) {
            if let Some(s) = decode_accel_row(slot, dlen) {
              visitor(Insta360StreamItem::Accel(s));
            }
            p += dlen;
          }
        }
      }
      ID_EXPOSURE => {
        let dlen = 16usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          if let Some(s) = decode_exposure_row(slot) {
            visitor(Insta360StreamItem::Exposure(s));
          }
          p += dlen;
        }
      }
      ID_VIDEO_TIMESTAMP => {
        let dlen = 8usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          if let Some(s) = decode_videotime_row(slot) {
            visitor(Insta360StreamItem::VideoTime(s));
          }
          p += dlen;
        }
      }
      ID_GPS => {
        let dlen = 53usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          match decode_gps_row(slot) {
            Ok(Some(s)) => visitor(Insta360StreamItem::Gps(s)),
            Ok(None) => {}
            Err(w) => {
              visitor(Insta360StreamItem::Warning(SmolStr::new(w)));
              break; // QuickTimeStream.pl:3409 `last` — stop this record's rows.
            }
          }
          p += dlen;
        }
      }
      _ => {}
    }
    core::ops::ControlFlow::Continue(())
  };

  let _ = walk_records(raw, trail_end, &mut visit);
}

/// Count the SURFACED timed rows of an Insta360 trailer — exactly the number of
/// `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` bumps `ProcessInsta360` performs
/// (QuickTimeStream.pl:3374/3388/3394/3412): one per emitted `0x300`/`0x400`/
/// `0x600`/`0x700`-'A' row. The `0x101` identity + every decode-warning are NOT
/// counted (they ride the sticky doc, no `FoundSomething`).
///
/// Run at PARSE time, in `ProcessMOV`'s trailer phase, to advance the SHARED
/// global counter past the Insta360 doc range so any LATER chain trailer
/// (LigoGPS/MIE) takes the next ordinals. Reuses [`stream_records`] — the same
/// surfacing walk as [`decode_all_records`] — so the count is byte-identical to
/// the rows the `-ee` decode later emits, but allocation-free (it stores no
/// row): a crafted huge `0x600`/`0x300` trailer cannot force O(rows) memory here.
/// Saturating, so a hostile row count cannot wrap.
#[must_use]
pub fn count_surfaced_rows(raw: &[u8], trail_end: usize) -> u32 {
  let mut count: u32 = 0;
  stream_records(raw, trail_end, &mut |item| match item {
    Insta360StreamItem::Gps(_)
    | Insta360StreamItem::Exposure(_)
    | Insta360StreamItem::VideoTime(_)
    | Insta360StreamItem::Accel(_) => count = count.saturating_add(1),
    Insta360StreamItem::Identity(_) | Insta360StreamItem::Warning(_) => {}
  });
  count
}

// ===========================================================================
// Scan-trailer (the per-file LIGHT entry point)
// ===========================================================================

/// The LIGHT `ProcessInsta360` parse (QuickTimeStream.pl:3252-3478) run
/// during the opts-agnostic QuickTime parse: locate the Insta360 trailer
/// ending at `trail_end`, record its `(offset, size)` + a borrow of the input
/// bytes (for the deferred `-ee` decode), and collect ONLY the BOUNDED domain
/// summary — the `0x101` identity, the FIRST valid `0x700` GPS `'A'` fix, and
/// the FIRST `0x400` exposure row. The heavy per-row decode of the timed
/// records (GPS / exposure / videotime / accelerometer) is DEFERRED to
/// [`decode_all_records`] at `-ee` emit time, so a crafted trailer of
/// millions of rows allocates nothing here.
///
/// `trail_end` is the file offset one-past the Insta360 trailer's LAST byte —
/// `data.len()` when it sits at EOF, or `entry.start + entry.len` when
/// [`identify_trailers`] found it behind a later LigoGPS/MIE trailer.
///
/// The light walk SKIPS the 0x300 / 0x600 records entirely (they feed no
/// domain summary) and STOPS early once all three summary slots are filled.
/// If no Insta360 trailer is present, `out` is left unchanged
/// (`is_empty()` stays `true`).
///
/// **What this LIGHT path does NOT do** (vs the full `-ee` decode):
/// - It does NOT stamp `DOC_NUM` (the summary fixes are not doc-bearing).
/// - It does NOT raise the decode-time `Insta360 ... data is huge` /
///   `Unrecognized INSV GPS format` warnings — those are produced by
///   [`decode_all_records`] and surfaced at `-ee` emit time.
///
/// **Edge cases.**
/// - A file shorter than 78 bytes / without the magic UUID → `is_empty()`.
/// - A trailer claiming `trailerLen > file size` → the trailer is still
///   recorded with the WRAPPED (negative→unsigned) offset (so the positional
///   `[minor] … trailer at offset …` warning emits, matching bundled, which
///   suppresses "Bad trailer size" via priority-0 first-wins), but no records
///   are decoded (the walk returns before its loop, so the deferred `-ee`
///   decode also yields nothing).
pub fn scan_trailer<'a>(data: &'a [u8], trail_end: usize, out: &mut Insta360Meta<'a>) {
  // The light visitor collects only the domain summary; it STOPS the walk as
  // soon as all three slots are filled. It never touches the global DOC_NUM
  // and never raises decode-time warnings (deferred to decode_all_records).
  let mut have_identity = false;
  let mut have_gps = false;
  let mut have_exposure = false;

  let mut visit = |rec: RecordView<'_>| -> core::ops::ControlFlow<()> {
    // QuickTimeStream.pl:3355-3357 — a fixed-stride record (0x300/0x400/0x600)
    // whose post-cap length is NOT a multiple of the stride decodes NO rows in
    // bundled; the light path collects nothing from it (this is what fixes the
    // false-CaptureSettings-from-a-malformed-0x400 case). 0x700 is exempt (no
    // fixed stride), so a non-multiple GPS record still surfaces its summary fix.
    if rec.non_multiple {
      return core::ops::ControlFlow::Continue(());
    }
    match rec.id {
      ID_IDENTITY => {
        let id_dec = decode_identity(rec.body);
        if !id_dec.is_empty() {
          out.set_identity(id_dec);
          have_identity = true;
        }
      }
      ID_EXPOSURE => {
        // FIRST row of the FIRST exposure record reached in walk order — all
        // the CaptureSettings projection needs (QuickTimeStream.pl:3386-3391).
        if !have_exposure
          && let Some(slot) = rec.body.get(0..16)
          && let Some(s) = decode_exposure_row(slot)
        {
          out.set_first_exposure(s);
          have_exposure = true;
        }
      }
      // FIRST valid 'A' fix reached in walk order — all the GpsLocation
      // projection needs (QuickTimeStream.pl:3397-3425). Walk this record's
      // rows only until one surfaces; a row-format warning stops THIS record
      // (faithful `last`) but the light path neither stores nor surfaces it.
      ID_GPS if !have_gps => {
        let dlen = 53usize;
        let mut p = 0usize;
        while let Some(slot) = rec.body.get(p..p + dlen) {
          match decode_gps_row(slot) {
            Ok(Some(s)) => {
              out.set_first_gps(s);
              have_gps = true;
              break;
            }
            Ok(None) => {}
            Err(_) => break, // QuickTimeStream.pl:3409 `last` (warning deferred)
          }
          p += dlen;
        }
      }
      // 0x300 / 0x600 feed no domain summary — SKIP entirely (the whole point
      // of the light path). 0x200 PreviewImage is not surfaced either.
      _ => {}
    }
    // Early-stop once the whole bounded summary is collected.
    if have_identity && have_gps && have_exposure {
      core::ops::ControlFlow::Break(())
    } else {
      core::ops::ControlFlow::Continue(())
    }
  };

  if let Some((offset, size)) = walk_records(data, trail_end, &mut visit) {
    // The always-on `[minor] … trailer at offset …` positional warning
    // (QuickTime.pm:10600) is driven off this; the deferred `-ee` decode reads
    // `raw`. On a bad-size trailer this records the WRAPPED offset + the raw
    // borrow, but the light visitor collected no records and the deferred
    // `decode_all_records` also yields nothing (the walk returns before its
    // loop) — so a bad-size trailer emits the positional warning and no
    // records, matching bundled.
    out.set_trailer(offset, size);
    out.set_raw(data);
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ----- helpers --------------------------------------------------------

  /// Build the 78-byte Insta360 footer: `[last_id:u16][last_len:u32]
  /// [32 opaque][trailer_len:u32][4 opaque][32-byte ASCII magic]`.
  fn footer(last_id: u16, last_len: u32, trailer_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(FOOTER_SIZE);
    out.extend_from_slice(&last_id.to_le_bytes());
    out.extend_from_slice(&last_len.to_le_bytes());
    out.resize(out.len() + 32, 0); // opaque
    out.extend_from_slice(&trailer_len.to_le_bytes());
    out.resize(out.len() + 4, 0); // opaque
    out.extend_from_slice(MAGIC);
    assert_eq!(out.len(), FOOTER_SIZE);
    out
  }

  /// One 6-byte record footer.
  fn record_footer(id: u16, len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out
  }

  /// Build an identity body: `[tag:u8][len:u8][value]` items.
  fn identity_body(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in items {
      out.push(*t);
      out.push(v.len() as u8);
      out.extend_from_slice(v);
    }
    out
  }

  /// Build one 53-byte GPS row.
  #[allow(clippy::too_many_arguments)]
  fn gps_row(
    unixtime: u32,
    ms: u16,
    status: u8,
    lat: f64,
    ns: u8,
    lon: f64,
    ew: u8,
    speed_mps: f64,
    track_deg: f64,
    altitude_m: f64,
  ) -> Vec<u8> {
    let mut out = Vec::with_capacity(53);
    out.extend_from_slice(&unixtime.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // unknown
    out.extend_from_slice(&ms.to_le_bytes());
    out.push(status);
    out.extend_from_slice(&lat.to_le_bytes());
    out.push(ns);
    out.extend_from_slice(&lon.to_le_bytes());
    out.push(ew);
    out.extend_from_slice(&speed_mps.to_le_bytes());
    out.extend_from_slice(&track_deg.to_le_bytes());
    out.extend_from_slice(&altitude_m.to_le_bytes());
    assert_eq!(out.len(), 53);
    out
  }

  /// Build one 16-byte exposure row.
  fn exposure_row(timestamp_ms: u64, exposure_s: f64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&exposure_s.to_le_bytes());
    out
  }

  /// Build one 56-byte accelerometer row: `[TimeCode:u64][6×double]`.
  fn accel56_row(tc_ms: u64, accel: [f64; 3], angvel: [f64; 3]) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&tc_ms.to_le_bytes());
    for v in accel.iter().chain(angvel.iter()) {
      out.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(out.len(), 56);
    out
  }

  /// Build one 20-byte accelerometer row: `[TimeCode:u64][6×u16]`.
  fn accel20_row(tc_ms: u64, vals: [u16; 6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&tc_ms.to_le_bytes());
    for v in &vals {
      out.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(out.len(), 20);
    out
  }

  /// Build one 8-byte video-timestamp row.
  fn videotime_row(tc_ms: u64) -> Vec<u8> {
    tc_ms.to_le_bytes().to_vec()
  }

  /// Build a trailer with the supplied (id, body) records in FILE
  /// ORDER (i.e. first-to-last); a 6-byte footer is appended after
  /// each record body, and the final 78-byte trailer footer ties it
  /// off. Returns a Vec representing the full file.
  ///
  /// File layout:
  ///   [non-trailer prefix bytes][record0_body][record0_footer]
  ///   [record1_body][record1_footer] ... [78-byte trailer footer]
  fn build_file(prefix: &[u8], records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(prefix);
    // Records in file order: each body, then its 6-byte footer.
    for (id, body) in records {
      file.extend_from_slice(body);
      file.extend_from_slice(&record_footer(*id, body.len() as u32));
    }
    // The trailer's 78-byte footer encodes:
    //   - first 6 bytes = LAST record's (id, len) — same as the LAST
    //     record's footer (the 6 bytes immediately before the trailer
    //     footer ARE this same 6 bytes — bundled treats them as the
    //     same thing; the `Read 78` includes those 6 bytes).
    // Actually rereading the bundled code: `Seek -78, Read 78` and then
    // `unpack('vV', $buff)` reads from offset 0 of the 78-byte buffer.
    // That offset 0 IS the last record's footer (we just wrote
    // `record_footer` as the LAST 6 bytes before "where the trailer
    // footer starts"). So: the LAST record's 6-byte footer IS the first
    // 6 bytes of the 78-byte trailer footer. We need to TRIM the last
    // 6 bytes we added (the LAST record_footer) and replace them with
    // the 78-byte trailer footer (whose first 6 bytes = the same).
    let (last_id, last_len) = if let Some((id, body)) = records.last() {
      (*id, body.len() as u32)
    } else {
      (0u16, 0u32)
    };
    // Strip the trailing 6-byte footer (it's redundant with the 78-byte
    // footer's first 6 bytes).
    let last6_start = file.len() - 6;
    file.truncate(last6_start);

    // Compute trailer_len: total bytes of (every record body + every
    // record's 6-byte footer). The LAST record's footer is INSIDE the
    // 78-byte trailer footer, so it counts.
    let trailer_start = prefix.len();
    let trailer_len = (file.len() - trailer_start) as u32 + FOOTER_SIZE as u32;
    let trailer_footer = footer(last_id, last_len, trailer_len);
    file.extend_from_slice(&trailer_footer);
    file
  }

  // ----- has_trailer / read_trailer_len --------------------------------

  #[test]
  fn has_trailer_false_for_short_input() {
    assert!(!has_trailer(&[]));
    assert!(!has_trailer(&[0u8; 10]));
    assert!(!has_trailer(&[0u8; 31]));
  }

  #[test]
  fn has_trailer_true_when_magic_at_eof() {
    let mut buf = vec![0u8; 100];
    buf.extend_from_slice(MAGIC);
    assert!(has_trailer(&buf));
  }

  #[test]
  fn has_trailer_false_when_magic_present_but_not_at_eof() {
    let mut buf = vec![0u8; 50];
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&[0u8; 10]); // append 10 extra bytes after magic
    assert!(!has_trailer(&buf));
  }

  #[test]
  fn read_trailer_len_returns_value_at_offset_38() {
    // Build a 78-byte buffer; trailer_len = 0xdeadbeef at offset 38.
    let mut buf = vec![0u8; 100]; // pad
    let ft = footer(0x101, 16, 0xdeadbeef);
    buf.extend_from_slice(&ft);
    assert_eq!(read_trailer_len(&buf, buf.len()), Some(0xdeadbeef));
  }

  #[test]
  fn read_trailer_len_none_without_magic() {
    let buf = vec![0u8; 200];
    assert!(read_trailer_len(&buf, buf.len()).is_none());
  }

  // ----- per-record-type decoders --------------------------------------

  #[test]
  fn decode_identity_decodes_all_four_tags() {
    let body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"IXX00123"),
      (TAG_MODEL, b"Insta360 X3"),
      (TAG_FIRMWARE, b"1.0.07"),
      (TAG_PARAMETERS, b"2_6_4032_3024"),
    ]);
    let id = decode_identity(&body);
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    // tr/_/ / underscore substitution (QuickTimeStream.pl:705).
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
  }

  #[test]
  fn decode_identity_truncated_stops_cleanly() {
    let mut body = identity_body(&[(TAG_MODEL, b"Insta360 X3")]);
    body.push(TAG_FIRMWARE);
    body.push(50); // claims 50 bytes but none follow
    let id = decode_identity(&body);
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), None);
  }

  #[test]
  fn decode_identity_caps_at_four_items() {
    // Five items; the 5th must NOT decode (bundled `for ($i=0; $i<4; ++$i)`).
    let body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"S"),
      (TAG_MODEL, b"M"),
      (TAG_FIRMWARE, b"F"),
      (TAG_PARAMETERS, b"P"),
      (0xff, b"extra"),
    ]);
    let id = decode_identity(&body);
    assert_eq!(id.serial_number(), Some("S"));
    assert_eq!(id.parameters(), Some("P"));
    // The 5th tag (0xff) was outside the cap; nothing extra to verify.
  }

  #[test]
  fn decode_identity_nul_split_utf8_reassembles_via_escapejson_order() {
    // A crafted identity value whose UTF-8 sequence is SPLIT by an embedded NUL:
    // `C2 00 A9` is `©` (`C2 A9`) with a NUL between the leader and continuation.
    // Bundled's `EscapeJSON` deletes NULs FIRST (`tr/\0//d`, exiftool:3820) then
    // runs `FixUTF8` (exiftool:3824), so the NUL-strip rejoins `C2 A9` → `©`.
    // A `FixUTF8`-first order would instead flag the `C2`/`A9` halves separately
    // (the NUL breaks the sequence) → `??`, and the trailing NUL of the
    // round-tripped `Str` would then be stripped → still `??`. The fix routes
    // through `escape_json_raw_bytes` (NUL-strip → `FixUTF8`), so each field is
    // the faithful `©`.
    let split = b"\xc2\x00\xa9"; // © split by a NUL
    let id = decode_identity(&identity_body(&[
      (TAG_SERIAL_NUMBER, split),
      (TAG_MODEL, split),
      (TAG_FIRMWARE, split),
      // Parameters additionally runs `tr/_/ /`; `_` is absent here, so the
      // EscapeJSON repair alone applies (still `©`).
      (TAG_PARAMETERS, split),
    ]));
    assert_eq!(id.serial_number(), Some("©"));
    assert_eq!(id.model(), Some("©"));
    assert_eq!(id.firmware(), Some("©"));
    assert_eq!(id.parameters(), Some("©"));
  }

  #[test]
  fn decode_identity_real_ascii_is_byte_identical_under_escapejson() {
    // Real all-ASCII device strings carry no NUL and are valid UTF-8, so
    // `escape_json_raw_bytes` is identity on them — byte-identical to the prior
    // `fix_utf8` path (no golden change). Underscores in Parameters still map to
    // spaces (QuickTimeStream.pl:705 `tr/_/ /`).
    let id = decode_identity(&identity_body(&[
      (TAG_SERIAL_NUMBER, b"IXX00123"),
      (TAG_MODEL, b"Insta360 X3"),
      (TAG_FIRMWARE, b"1.0.07"),
      (TAG_PARAMETERS, b"2_6_4032_3024"),
    ]));
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
    // Every real device string fails the number/boolean gate (letters, dots,
    // spaces) → QUOTED. Emit renders each as `TagValue::JsonStr` ⇒ the SAME
    // quoted token the prior `TagValue::Str` produced (byte-identical golden).
    use crate::convert::EscapedJson;
    assert!(matches!(id.serial_number_json(), Some(EscapedJson::Quoted(s)) if s == "IXX00123"));
    assert!(matches!(id.model_json(), Some(EscapedJson::Quoted(s)) if s == "Insta360 X3"));
    assert!(matches!(id.firmware_json(), Some(EscapedJson::Quoted(s)) if s == "1.0.07"));
    assert!(matches!(id.parameters_json(), Some(EscapedJson::Quoted(s)) if s == "2 6 4032 3024"));
  }

  #[test]
  fn decode_identity_nul_split_numeric_is_quoted_not_bare() {
    // The #53 finding: a NUL-SPLIT numeric `31 00 32 00` (`"1\02\0"`). ExifTool's
    // `EscapeJSON` CLASSIFIES the ORIGINAL (NULs and all) FIRST — the anchored
    // number regex rejects the embedded NUL — so it is a QUOTED string, and the
    // `tr/\0//d` that follows yields the lexeme `"12"`: bundled emits `"12"`, NOT
    // a bare `12`. Classifying AFTER the NUL-strip (the bug) would see `12` and
    // wrongly emit it bare. The fix carries the `Quoted` verdict so emit forces
    // `TagValue::JsonStr` ⇒ `"12"`.
    let nul_split_num = b"1\x002\x00";
    let id = decode_identity(&identity_body(&[
      (TAG_SERIAL_NUMBER, nul_split_num),
      (TAG_MODEL, nul_split_num),
      (TAG_FIRMWARE, nul_split_num),
      (TAG_PARAMETERS, nul_split_num),
    ]));
    use crate::convert::EscapedJson;
    // Content (NUL-stripped) is `12`, but the verdict is QUOTED (the original
    // failed the gate), so it must NOT be coerced to a bare number.
    for v in [
      id.serial_number_json(),
      id.model_json(),
      id.firmware_json(),
      id.parameters_json(),
    ] {
      assert!(
        matches!(v, Some(EscapedJson::Quoted(s)) if s == "12"),
        "NUL-split numeric must be Quoted(\"12\"), got {v:?}"
      );
    }
    assert_eq!(id.serial_number(), Some("12")); // content accessor sees `12`
  }

  #[test]
  fn decode_identity_nul_split_boolean_is_quoted_not_bare() {
    // The boolean half of #53: `74 00 72 00 75 00 65 00` (`"t\0r\0u\0e\0"`). The
    // NUL-bearing original fails `/^(true|false)$/i` (anchored, no NUL), so it is
    // a QUOTED string; `tr/\0//d` then yields `"true"`. Bundled emits `"true"`,
    // NOT a bare `true`. The `Quoted` verdict ⇒ `TagValue::JsonStr` ⇒ `"true"`.
    let nul_split_bool = b"t\x00r\x00u\x00e\x00";
    let id = decode_identity(&identity_body(&[
      (TAG_SERIAL_NUMBER, nul_split_bool),
      (TAG_MODEL, nul_split_bool),
    ]));
    use crate::convert::EscapedJson;
    assert!(matches!(id.serial_number_json(), Some(EscapedJson::Quoted(s)) if s == "true"));
    assert!(matches!(id.model_json(), Some(EscapedJson::Quoted(s)) if s == "true"));
    assert_eq!(id.serial_number(), Some("true"));
  }

  #[test]
  fn decode_identity_clean_numeric_no_nul_is_bare() {
    // The complement: a CLEAN number original (no NUL) `31 32 33 34` (`"1234"`)
    // DOES pass the gate, so `EscapeJSON` returns it VERBATIM as a BARE token —
    // `escape_json_raw_bytes` is identity on it. The `Bare` verdict ⇒
    // `TagValue::Str` ⇒ the serializer's own gate renders it bare `1234`.
    let id = decode_identity(&identity_body(&[(TAG_SERIAL_NUMBER, b"1234")]));
    use crate::convert::EscapedJson;
    assert!(matches!(id.serial_number_json(), Some(EscapedJson::Bare(s)) if s == "1234"));
    assert_eq!(id.serial_number(), Some("1234"));
  }

  #[test]
  fn decode_identity_nul_split_utf8_is_quoted() {
    // The R2 NUL-split UTF-8 `C2 00 A9` → `©` now flows via the verdict path:
    // the NUL-bearing original fails the number/boolean gate → QUOTED, and the
    // NUL-strip-then-`FixUTF8` order reassembles `C2 A9` → `©`. Emit forces
    // `TagValue::JsonStr` ⇒ the quoted `"©"` (byte-identical to the prior
    // `TagValue::Str("©")` rendering — `©` is non-numeric either way).
    let split = b"\xc2\x00\xa9";
    let id = decode_identity(&identity_body(&[
      (TAG_SERIAL_NUMBER, split),
      (TAG_PARAMETERS, split),
    ]));
    use crate::convert::EscapedJson;
    assert!(matches!(id.serial_number_json(), Some(EscapedJson::Quoted(s)) if s == "©"));
    assert!(matches!(id.parameters_json(), Some(EscapedJson::Quoted(s)) if s == "©"));
    assert_eq!(id.serial_number(), Some("©"));
  }

  #[test]
  fn decode_identity_parameters_tr_underscore_before_classify() {
    // Parameters runs `tr/_/ /` (QuickTimeStream.pl:705) on the RAW `$val`
    // BEFORE `EscapeJSON` classifies. A value that is number-shaped ONLY before
    // the `tr` (`"1_2"`) becomes `"1 2"` (a space → fails the number gate) →
    // QUOTED `"1 2"`, matching ExifTool's `tr`-then-classify order. A value that
    // stays a clean number after the (absent) `tr` (`"12"`, no `_`/NUL) is BARE.
    let id_underscore = decode_identity(&identity_body(&[(TAG_PARAMETERS, b"1_2")]));
    use crate::convert::EscapedJson;
    assert!(matches!(id_underscore.parameters_json(), Some(EscapedJson::Quoted(s)) if s == "1 2"));
    let id_clean = decode_identity(&identity_body(&[(TAG_PARAMETERS, b"12")]));
    assert!(matches!(id_clean.parameters_json(), Some(EscapedJson::Bare(s)) if s == "12"));
  }

  #[test]
  fn decode_exposure_row_extracts_timestamp_and_exposure() {
    let row = exposure_row(123456789, 0.00125);
    let s = decode_exposure_row(&row).expect("decoded");
    assert_eq!(s.timestamp_ms(), Some(123456789));
    assert!((s.exposure_time_s().unwrap() - 0.00125).abs() < 1e-12);
  }

  #[test]
  fn decode_exposure_row_short_returns_none() {
    let row = vec![0u8; 8];
    assert!(decode_exposure_row(&row).is_none());
  }

  #[test]
  fn decode_accel_row_56_byte_doubles() {
    let row = accel56_row(1000, [0.1, 0.2, 9.8], [0.01, -0.02, 0.03]);
    let s = decode_accel_row(&row, 56).expect("decoded");
    assert_eq!(s.timecode_ms(), Some(1000));
    let a = s.accelerometer().unwrap();
    assert!((a[0] - 0.1).abs() < 1e-12 && (a[2] - 9.8).abs() < 1e-12);
    let w = s.angular_velocity().unwrap();
    assert!((w[1] - -0.02).abs() < 1e-12);
  }

  #[test]
  fn decode_accel_row_20_byte_int16() {
    // 32768->0, 33768->1, 31768->-1, 32868->0.1, 32668->-0.1, 41768->9.
    let row = accel20_row(2000, [32768, 33768, 31768, 32868, 32668, 41768]);
    let s = decode_accel_row(&row, 20).expect("decoded");
    assert_eq!(s.timecode_ms(), Some(2000));
    let a = s.accelerometer().unwrap();
    assert!((a[0] - 0.0).abs() < 1e-12);
    assert!((a[1] - 1.0).abs() < 1e-12);
    assert!((a[2] - -1.0).abs() < 1e-12);
    let w = s.angular_velocity().unwrap();
    assert!((w[0] - 0.1).abs() < 1e-12);
    assert!((w[1] - -0.1).abs() < 1e-12);
    assert!((w[2] - 9.0).abs() < 1e-12);
  }

  #[test]
  fn accel_stride_probe_picks_correctly() {
    // `accel_stride(len, file_tail)` — `len` is the record's DECLARED length;
    // `file_tail` is the FILE bytes from the body start to EOF (the else-branch
    // probe reads the file, not just the record body).
    // 56 only: len 56 (56 % 20 != 0, 56 % 56 == 0). file_tail is irrelevant.
    assert_eq!(accel_stride(56, &[]), 56);
    // 20 only: len 20 (20 % 56 != 0, 20 % 20 == 0). file_tail is irrelevant.
    assert_eq!(accel_stride(20, &[]), 20);
    // 280 is a common multiple (5×56 = 280, 14×20 = 280): the else-branch
    // byte-probe at file_tail[16..19] decides (QuickTimeStream.pl:3340-3345).
    // Zero there (with ≥ 20 file bytes) ⇒ 56.
    let amb_zero = vec![0u8; 280];
    assert_eq!(accel_stride(280, &amb_zero), 56);
    // Non-zero there ⇒ 20.
    let mut amb_nz = vec![0u8; 280];
    amb_nz[16] = 0x9a;
    amb_nz[17] = 0x99;
    amb_nz[18] = 0x99;
    assert_eq!(accel_stride(280, &amb_nz), 20);
  }

  #[test]
  fn accel_stride_short_record_probes_file_tail_not_body() {
    // R8 fix: the else-branch probe is `$raf->Read($buff, 20)` against the FILE
    // at the body start, so for a SHORT record (len a multiple of neither 20 nor
    // 56) it reads PAST the body into the following bytes and succeeds whenever
    // ≥ 20 file bytes remain. A 10-byte record with ≥ 20 file bytes after the
    // body start (its footer + the next records + the terminal all follow) →
    // file_tail[16..19] non-zero ⇒ stride 20 (the record then `len % 20 != 0`
    // → the `Unexpected … length` warning downstream, NOT a silent skip).
    let mut tail = vec![0u8; 20];
    tail[16] = 0x01; // bytes 16..18 non-zero ⇒ 20
    assert_eq!(accel_stride(10, &tail), 20);
    // Same len 10, but file_tail[16..18] all zero ⇒ 56.
    assert_eq!(accel_stride(10, &vec![0u8; 20]), 56);

    // Fewer than 20 file bytes remain ⇒ `Read(20)` FAILS ⇒ `$dlen` 0 (silent
    // skip). A 10-byte record at the very END of the file (only its own short
    // body before EOF) yields the 0 sentinel.
    assert_eq!(accel_stride(10, &vec![0u8; 19]), 0);
    assert_eq!(accel_stride(10, &vec![0u8; 10]), 0);
    assert_eq!(accel_stride(10, &[]), 0);

    // len 18 (multiple of neither) with ≥ 20 file bytes ⇒ probed (20 or 56);
    // non-zero bytes 16..18 ⇒ 20, all-zero ⇒ 56.
    let mut t18 = vec![0u8; 24];
    t18[16] = 0xff;
    assert_eq!(accel_stride(18, &t18), 20);
    assert_eq!(accel_stride(18, &vec![0u8; 24]), 56);

    // len 280 (multiple of BOTH) also takes the else-branch; ≥ 20 file bytes +
    // bytes 16..18 zero ⇒ 56.
    assert_eq!(accel_stride(280, &vec![0u8; 20]), 56);
  }

  #[test]
  fn scan_trailer_caps_0x300_using_probed_stride_not_blanket_56() {
    // QuickTimeStream.pl:3347-3352: a 0x300 record longer than `20000 * dlen`
    // is truncated to the first 20000 rows (+ the "data is huge" warning). The
    // cap MUST use the PROBED stride. For a 20-byte-stride record that is
    // `20000 * 20 = 400000`; a blanket `20000 * 56 = 1120000` cap would let a
    // 400001..1120000-byte 20-byte record ESCAPE the cap entirely and
    // over-emit (breaking Doc<N> numbering + the OOM guard). 20001 rows × 20 =
    // 400020 bytes (> 400000) ⇒ exactly 20000 surfaced + the warning.
    let mut body = Vec::with_capacity(20001 * 20);
    for i in 0..20001u64 {
      body.extend_from_slice(&accel20_row(i, [32768, 33768, 31768, 32768, 33768, 31768]));
    }
    let file = build_file(b"PREFIX-BYTES", &[(ID_ACCELEROMETER, body)]);
    // The 0x300 cap lives in the shared walk and is exercised by the FULL
    // (`-ee`) decode — the light scan_trailer skips 0x300 entirely.
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(
      full.accel().len(),
      20000,
      "0x300 must cap at 20000 * the probed 20-byte stride, not over-emit"
    );
    assert_eq!(
      full.warnings(),
      // Raised before any surfaced row ⇒ sticky DOC_NUM 0 (Main).
      &[(
        0,
        SmolStr::new(
          "[Minor] Insta360 accelerometer data is huge. Processing only the first 20000 records"
        )
      )]
    );
  }

  #[test]
  fn scan_trailer_0x300_56byte_cap_keeps_probed_stride_not_reprobe() {
    // R2 regression: a 56-byte record of 20001 rows caps to 1120000 bytes,
    // which is divisible by BOTH 20 and 56 — so a re-probe of the CAPPED slice
    // hits the byte-16 heuristic, and a real doubles row (non-zero bytes
    // 16..18) would make it wrongly pick stride 20 and emit 56000 rows. The
    // stride probed ONCE on the full body (56) must be retained for the capped
    // decode ⇒ exactly 20000 rows.
    let mut body = Vec::with_capacity(20001 * 56);
    for i in 0..20001u64 {
      // accel[1] = 0.2 ⇒ the f64 at row offset 16 has non-zero low bytes 16..18,
      // which is exactly what would flip a (wrong) re-probe to stride 20.
      body.extend_from_slice(&accel56_row(i, [0.1, 0.2, 9.8], [0.01, -0.02, 0.03]));
    }
    let file = build_file(b"PFX", &[(ID_ACCELEROMETER, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(
      full.accel().len(),
      20000,
      "56-byte 0x300 must retain the probed stride (56), not re-probe the capped slice to 20"
    );
  }

  #[test]
  fn scan_trailer_large_0x000_dir_table_is_borrowed_not_cloned() {
    // R2 finding: a 0x000 directory table is BORROWED from `data`, never
    // `to_vec()`-cloned, so a crafted oversized table cannot force a second
    // attacker-sized allocation. A large (200000-byte) all-zero table has only
    // id-0 entries (each skipped), so the walk latches the borrowed table,
    // finds no routable entry, and terminates cleanly — no records, no panic,
    // no proportional duplicate allocation.
    let big_table = vec![0u8; 200_000];
    let file = build_file(b"PFX", &[(ID_DIRECTORY_TABLE, big_table)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    assert!(out.identity().is_none());
    assert!(out.first_gps().is_none());
    assert!(out.first_exposure().is_none());
    // The full (`-ee`) decode over the same borrowed table is also clean.
    let full = decode_all_records(&file, file.len(), 0);
    assert!(full.identity().is_none());
    assert!(full.gps().is_empty());
    assert!(full.accel().is_empty());
    assert!(full.exposure().is_empty());
    assert!(full.videotime().is_empty());
  }

  #[test]
  fn dir_table_dispatches_per_footer_not_table_entry() {
    // FIX 3 (QuickTimeStream.pl:3455-3471): a 0x000 dir-table entry's
    // `(id, siz, off)` is used ONLY to compute the next FOOTER position
    // (`$epos = $off + $siz - $trailerLen`); the walker then SEEKS there and
    // READS the actual 6-byte footer, and the NEXT iteration's `unpack('vV')`
    // dispatches on the id/len FROM THAT FOOTER — NOT from the table entry. So a
    // crafted table whose entry id DISAGREES with the real footer must still
    // dispatch per the footer.
    //
    // Layout (file order; walk is reverse): a real 0x600 VideoTimeStamp record
    // (one 8-byte row) then a 0x000 dir-table (walked FIRST). The table has ONE
    // 10-byte entry `[id=0x400][siz=8][off=0]`: `off+siz == 8 == target_len`, so
    // `$epos = 8 - trailerLen` lands EXACTLY on the 0x600 record's footer. With
    // the fix the footer's real id (0x600) drives dispatch ⇒ one VideoTimeStamp
    // row, no warning. The (buggy) table-derived id (0x400, stride 16) would
    // instead make the 8-byte record a non-multiple 0x400 ⇒ zero rows + an
    // `Unexpected Insta360 record 0x400 length` warning.
    let target_body = videotime_row(1234); // 8 bytes, 0x600
    let dir_entry = {
      let mut e = Vec::with_capacity(10);
      e.extend_from_slice(&0x400u16.to_le_bytes()); // id (DISAGREES with the footer)
      e.extend_from_slice(&(target_body.len() as u32).to_le_bytes()); // siz == 8
      e.extend_from_slice(&0u32.to_le_bytes()); // off == 0 ⇒ off+siz == target_len
      e
    };
    let file = build_file(
      b"PFX",
      &[
        (ID_VIDEO_TIMESTAMP, target_body),
        (ID_DIRECTORY_TABLE, dir_entry),
      ],
    );
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(
      full.videotime().len(),
      1,
      "dir-table must dispatch the target per its real 0x600 footer"
    );
    assert_eq!(full.videotime()[0].timecode_ms(), Some(1234));
    assert!(
      full.warnings().is_empty(),
      "no `Unexpected … 0x400` warning — the table entry id is NOT adopted"
    );
  }

  #[test]
  fn decode_videotime_row_basic() {
    let row = videotime_row(1500);
    let s = decode_videotime_row(&row).expect("decoded");
    assert_eq!(s.timecode_ms(), Some(1500));
  }

  #[test]
  fn decode_videotime_row_short_returns_none() {
    assert!(decode_videotime_row(&[0u8; 4]).is_none());
  }

  #[test]
  fn decode_gps_row_basic_north_east_fix() {
    let row = gps_row(
      1717250400, // 2024:06:01 14:00:00 UTC
      0, b'A', 37.7749, b'N', -122.4194, b'W', // value is "-122.4194" raw
      10.0, 180.0, 15.5,
    );
    // For W: bundled does `-abs(lon_raw)` ⇒ -abs(-122.4194) = -122.4194.
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.latitude().unwrap() - 37.7749).abs() < 1e-9);
    assert!((s.longitude().unwrap() - -122.4194).abs() < 1e-9);
    assert!((s.altitude_m().unwrap() - 15.5).abs() < 1e-9);
    assert!((s.speed_kph().unwrap() - 36.0).abs() < 1e-9); // 10 m/s * 3.6
    assert!((s.track_deg().unwrap() - 180.0).abs() < 1e-9);
    assert_eq!(s.date_time(), Some("2024:06:01 14:00:00Z"));
  }

  #[test]
  fn decode_gps_row_south_flips_lat_sign() {
    let row = gps_row(1717250400, 0, b'A', 12.345, b'S', 0.0, b'E', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.latitude().unwrap() - -12.345).abs() < 1e-9);
  }

  #[test]
  fn decode_gps_row_french_o_treated_as_west() {
    let row = gps_row(1717250400, 0, b'A', 0.0, b'N', 5.0, b'O', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.longitude().unwrap() - -5.0).abs() < 1e-9);
  }

  #[test]
  fn decode_gps_row_void_status_returns_none() {
    let row = gps_row(0, 0, b'V', 0.0, b'N', 0.0, b'E', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok");
    assert!(s.is_none());
  }

  #[test]
  fn decode_gps_row_invalid_ns_with_valid_status_returns_warning() {
    let row = gps_row(0, 0, b'A', 0.0, b'X', 0.0, b'E', 0.0, 0.0, 0.0);
    assert!(decode_gps_row(&row).is_err());
  }

  #[test]
  fn decode_gps_row_void_status_with_invalid_ns_returns_none() {
    // QuickTimeStream.pl:3407 — void fixes skipped even if NS/EW is invalid.
    let row = gps_row(0, 0, b'V', 0.0, b'X', 0.0, b'Y', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok");
    assert!(s.is_none());
  }

  #[test]
  fn decode_gps_row_ms_field_renders_as_dot_fraction() {
    let row = gps_row(1717250400, 100, b'A', 0.0, b'N', 0.0, b'E', 0.0, 0.0, 0.0);
    // .100 ⇒ trim trailing zeros ⇒ `.1`. Then `Z` suffix.
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert_eq!(s.date_time(), Some("2024:06:01 14:00:00.1Z"));
  }

  // ----- scan_trailer / walker -----------------------------------------

  #[test]
  fn scan_trailer_no_signature_leaves_out_empty() {
    let data = vec![0u8; 200];
    let mut out = Insta360Meta::new();
    scan_trailer(&data, data.len(), &mut out);
    assert!(out.is_empty());
    assert!(out.trailer().is_none());
  }

  #[test]
  fn scan_trailer_short_file_leaves_out_empty() {
    let data = vec![0u8; 50];
    let mut out = Insta360Meta::new();
    scan_trailer(&data, data.len(), &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_identity_only_single_record() {
    // Build a trailer with one 0x101 identity record.
    let id_body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"IXX00123"),
      (TAG_MODEL, b"Insta360 X3"),
      (TAG_FIRMWARE, b"1.0.07"),
      (TAG_PARAMETERS, b"2_6_4032_3024"),
    ]);
    let file = build_file(b"prefix-bytes-here-1234", &[(ID_IDENTITY, id_body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let id = out.identity().expect("identity decoded");
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
  }

  #[test]
  fn scan_trailer_gps_record_single_row() {
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
    ));
    let file = build_file(b"prefix", &[(ID_GPS, gps_body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let fix = out.first_gps().expect("fix");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
    assert!((fix.longitude().unwrap() - 8.0).abs() < 1e-9);
    assert!((fix.altitude_m().unwrap() - 200.0).abs() < 1e-9);
    assert!((fix.speed_kph().unwrap() - 36.0).abs() < 1e-9);
  }

  #[test]
  fn scan_trailer_identity_and_gps_records() {
    let id_body = identity_body(&[(TAG_MODEL, b"Insta360 ONE RS"), (TAG_FIRMWARE, b"1.0.01")]);
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 0.0, 0.0, 0.0,
    ));
    let file = build_file(
      b"prefix-bytes-",
      &[(ID_IDENTITY, id_body), (ID_GPS, gps_body)],
    );
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let id = out.identity().expect("identity");
    assert_eq!(id.model(), Some("Insta360 ONE RS"));
    let fix = out.first_gps().expect("fix");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
  }

  #[test]
  fn scan_trailer_exposure_record_extracts_rows() {
    let mut body = Vec::new();
    body.extend_from_slice(&exposure_row(1000, 0.008));
    body.extend_from_slice(&exposure_row(2000, 0.016));
    let file = build_file(b"prefix", &[(ID_EXPOSURE, body)]);
    // The light path stores only the FIRST exposure row (the domain summary).
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let first = out.first_exposure().expect("first exposure");
    assert_eq!(first.timestamp_ms(), Some(1000));
    assert!((first.exposure_time_s().unwrap() - 0.008).abs() < 1e-12);
    // The FULL (`-ee`) decode materializes every row.
    let full = decode_all_records(&file, file.len(), 0);
    let samples = full.exposure();
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].timestamp_ms(), Some(1000));
    assert!((samples[0].exposure_time_s().unwrap() - 0.008).abs() < 1e-12);
    assert_eq!(samples[1].timestamp_ms(), Some(2000));
  }

  #[test]
  fn scan_trailer_bad_trailer_size_records_wrapped_trailer_and_no_records() {
    // A trailer footer that claims trailer_len > file size. Bundled emits the
    // POSITIONAL trailer warning with the WRAPPED (negative→unsigned) offset,
    // then suppresses "Bad Insta360 trailer size" via priority-0 first-wins. So
    // exifast records the trailer with `file_size.wrapping_sub(trailer_len)` as
    // the offset (driving the positional warning) but decodes NO records.
    let mut buf = vec![0u8; 100];
    let big_trailer_len = 1_000_000u32; // way bigger than the 178-byte file
    let ft = footer(0x101, 16, big_trailer_len);
    buf.extend_from_slice(&ft);
    let file_size = buf.len() as u64;
    let mut out = Insta360Meta::new();
    scan_trailer(&buf, buf.len(), &mut out);
    // The trailer is recorded with the WRAPPED offset.
    let (off, size) = out.trailer().expect("wrapped trailer recorded");
    assert_eq!(off, file_size.wrapping_sub(big_trailer_len as u64));
    assert_eq!(size, big_trailer_len);
    // No domain summary surfaced (the walk returned before its loop).
    assert!(out.identity().is_none());
    assert!(out.first_gps().is_none());
    assert!(out.first_exposure().is_none());
    // The deferred `-ee` decode over the same bytes yields NOTHING.
    let full = decode_all_records(&buf, buf.len(), 0);
    assert!(full.gps().is_empty());
    assert!(full.exposure().is_empty());
    assert!(full.videotime().is_empty());
    assert!(full.accel().is_empty());
    assert!(full.identity().is_none());
  }

  #[test]
  fn scan_trailer_records_trailer_offset_and_size() {
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 0.0, 0.0, 0.0,
    ));
    let file = build_file(b"prefix-bytes", &[(ID_GPS, gps_body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let (off, size) = out.trailer().expect("trailer recorded");
    // offset = file_size - trailer_len; size = trailer_len.
    assert_eq!(off + size as u64, file.len() as u64);
  }

  #[test]
  fn decode_all_records_global_doc_counter_across_record_types() {
    // The GLOBAL DOC_NUM stamping lives in the FULL (`-ee`) decode now.
    // Mirror the fixture's file order: identity, accel56, accel20, videotime,
    // exposure, GPS (GPS is LAST in file ⇒ walked FIRST ⇒ Doc1/Doc2).
    let identity = identity_body(&[(TAG_MODEL, b"Insta360 X3"), (TAG_FIRMWARE, b"1.0.07")]);
    let accel56 = accel56_row(1000, [0.1, 0.2, 9.8], [0.01, -0.02, 0.03]);
    let accel20 = accel20_row(2000, [32768, 33768, 31768, 32868, 32668, 41768]);
    let mut videotime = Vec::new();
    videotime.extend_from_slice(&videotime_row(1000));
    videotime.extend_from_slice(&videotime_row(2000));
    let mut exposure = Vec::new();
    exposure.extend_from_slice(&exposure_row(1000, 0.008));
    exposure.extend_from_slice(&exposure_row(2000, 0.004));
    let mut gps = Vec::new();
    gps.extend_from_slice(&gps_row(
      1704626355, 0, b'A', 37.7749, b'N', 122.4194, b'W', 5.0, 90.0, 100.5,
    ));
    gps.extend_from_slice(&gps_row(
      1704626356, 0, b'A', 33.8688, b'S', 151.2093, b'E', 0.0, 0.0, 10.0,
    ));
    // Third GPS row is void ('V') — skipped, must NOT advance DOC_NUM.
    gps.extend_from_slice(&gps_row(1704626357, 0, b'V', 0.0, 0, 0.0, 0, 0.0, 0.0, 0.0));

    let file = build_file(
      b"prefix-bytes",
      &[
        (ID_IDENTITY, identity),
        (ID_ACCELEROMETER, accel56),
        (ID_ACCELEROMETER, accel20),
        (ID_VIDEO_TIMESTAMP, videotime),
        (ID_EXPOSURE, exposure),
        (ID_GPS, gps),
      ],
    );
    let full = decode_all_records(&file, file.len(), 0);

    // GPS walked first: row1 -> Doc1, row2 -> Doc2 (void -> no doc).
    assert_eq!(full.gps().len(), 2);
    assert_eq!(full.gps()[0].doc(), Some(1));
    assert_eq!(full.gps()[1].doc(), Some(2));
    // Exposure: Doc3, Doc4.
    assert_eq!(full.exposure().len(), 2);
    assert_eq!(full.exposure()[0].doc(), Some(3));
    assert_eq!(full.exposure()[1].doc(), Some(4));
    // VideoTime: Doc5, Doc6.
    assert_eq!(full.videotime().len(), 2);
    assert_eq!(full.videotime()[0].doc(), Some(5));
    assert_eq!(full.videotime()[1].doc(), Some(6));
    // Accelerometer: the accel20 record (walked before accel56) -> Doc7,
    // then accel56 -> Doc8. (Walk is last-record-first; accel20 is later in
    // file than accel56, so accel20 walks first.)
    assert_eq!(full.accel().len(), 2);
    assert_eq!(full.accel()[0].doc(), Some(7));
    assert_eq!(full.accel()[1].doc(), Some(8));
    // Identity walked LAST -> inherits the sticky DOC_NUM = 8.
    assert_eq!(full.identity().unwrap().doc(), Some(8));
  }

  #[test]
  fn decode_all_records_continues_shared_counter_from_doc_base() {
    // The Insta360 trailer draws its `Doc<N>` from the SHARED global counter, NOT
    // a local 0-based one. With `doc_base = 5` (5 docs already consumed by
    // moov-timed + earlier sources) the FIRST surfaced row is `Doc6`
    // (`++$$et{DOC_COUNT}`), continuing the ONE global sequence.
    let gps = {
      let mut g = Vec::new();
      g.extend_from_slice(&gps_row(
        1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
      ));
      g.extend_from_slice(&gps_row(
        1717250401, 0, b'A', 46.0, b'N', 9.0, b'E', 11.0, 91.0, 201.0,
      ));
      g
    };
    let exposure = {
      let mut e = exposure_row(1000, 0.008);
      e.extend_from_slice(&exposure_row(1001, 0.009));
      e
    };
    // Identity is LAST in the file ⇒ walked FIRST (last-record-first) ⇒ before any
    // timed row ⇒ inherits the sticky doc, which is STILL Main (0), NOT `doc_base`.
    let identity = identity_body(&[(TAG_MODEL, b"Insta360 X3")]);
    let file = build_file(
      b"prefix-bytes",
      &[
        (ID_GPS, gps),
        (ID_EXPOSURE, exposure),
        (ID_IDENTITY, identity),
      ],
    );

    let full = decode_all_records(&file, file.len(), 5);
    // The walk is LAST-record-first, so the file order [GPS, EXPOSURE, IDENTITY]
    // is visited IDENTITY → EXPOSURE → GPS. The identity (before any timed row)
    // rides sticky Main (0); then EXPOSURE rows take Doc6/Doc7, GPS rows Doc8/Doc9.
    assert_eq!(full.exposure().len(), 2);
    assert_eq!(full.exposure()[0].doc(), Some(6));
    assert_eq!(full.exposure()[1].doc(), Some(7));
    assert_eq!(full.gps().len(), 2);
    assert_eq!(full.gps()[0].doc(), Some(8));
    assert_eq!(full.gps()[1].doc(), Some(9));
    // The identity walked BEFORE any timed row ⇒ sticky doc Main (0), NOT 5: a
    // record before the first `FoundSomething` rides undef `$$et{DOC_NUM}`.
    assert_eq!(full.identity().unwrap().doc(), Some(0));

    // `count_surfaced_rows` (the parse-time advance) == the 4 surfaced rows,
    // INDEPENDENT of `doc_base` (it counts bumps, not absolute ordinals).
    assert_eq!(count_surfaced_rows(&file, file.len()), 4);
  }

  #[test]
  fn non_multiple_0x400_decodes_no_rows_and_warns() {
    // QuickTimeStream.pl:3355-3357: a 0x400 (stride 16) record whose length is
    // NOT a multiple of 16 emits ZERO rows (the `elsif` decode is skipped) +
    // the `Unexpected Insta360 record 0x400 length` warning. 17 bytes = one
    // 16-byte row + 1 trailing byte → bundled decodes nothing.
    let mut body = exposure_row(1000, 0.008);
    body.push(0xff); // 17 bytes total — not a multiple of 16
    let file = build_file(b"PFX", &[(ID_EXPOSURE, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert!(
      full.exposure().is_empty(),
      "a non-multiple 0x400 must emit no exposure rows"
    );
    assert_eq!(
      full.warnings(),
      &[(0, SmolStr::new("Unexpected Insta360 record 0x400 length"))]
    );
  }

  #[test]
  fn non_multiple_0x600_decodes_no_rows_and_warns() {
    // A 0x600 (stride 8) record of 9 bytes = one 8-byte row + 1 trailing byte
    // → bundled decodes nothing + warns.
    let mut body = videotime_row(1000);
    body.push(0xff); // 9 bytes total — not a multiple of 8
    let file = build_file(b"PFX", &[(ID_VIDEO_TIMESTAMP, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert!(
      full.videotime().is_empty(),
      "a non-multiple 0x600 must emit no videotime rows"
    );
    assert_eq!(
      full.warnings(),
      &[(0, SmolStr::new("Unexpected Insta360 record 0x600 length"))]
    );
  }

  #[test]
  fn non_multiple_0x300_decodes_no_rows_and_warns() {
    // A 0x300 record probed to stride 20 (a 20-byte row) but with 1 trailing
    // byte (21 bytes) is not a multiple of 20 → no accel rows + the warning.
    let mut body = accel20_row(2000, [32768, 33768, 31768, 32868, 32668, 41768]);
    body.push(0xff); // 21 bytes — not a multiple of 20 (probed stride)
    let file = build_file(b"PFX", &[(ID_ACCELEROMETER, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert!(
      full.accel().is_empty(),
      "a non-multiple 0x300 must emit no accel rows"
    );
    assert_eq!(
      full.warnings(),
      &[(0, SmolStr::new("Unexpected Insta360 record 0x300 length"))]
    );
  }

  #[test]
  fn short_0x300_with_following_records_warns_not_silent() {
    // R8 fix: a 0x300 whose length is a multiple of NEITHER 20 nor 56 reaches
    // the else-branch `$raf->Read($buff, 20)` probe, which reads the FILE at the
    // body start. When records follow (here a 0x700 GPS fix walked first), ≥ 20
    // file bytes remain, so the probe SUCCEEDS → stride 20/56 → the 10-byte
    // 0x300's `len % stride != 0` raises the `Unexpected … length` warning (NOT
    // a silent skip — the prior fix wrongly skipped these). The GPS fix still
    // surfaces.
    let body = vec![0u8; 10];
    let gps = gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
    );
    // File order: 0x300 first, GPS last (so GPS walks first → Doc1, then the
    // 0x300 record is reached with the terminal block still after it → ≥ 20
    // file bytes from its body start to EOF → probe succeeds).
    let file = build_file(b"PFX", &[(ID_ACCELEROMETER, body), (ID_GPS, gps)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert!(
      full.accel().is_empty(),
      "a non-multiple 0x300 emits no rows"
    );
    assert_eq!(full.gps().len(), 1, "the GPS fix still surfaces");
    assert_eq!(
      full.warnings(),
      // Raised under the sticky DOC_NUM left by the GPS fix (Doc1).
      &[(1, SmolStr::new("Unexpected Insta360 record 0x300 length"))]
    );
    // The streaming path agrees: no Accel, one GPS, one Warning.
    let mut accels = 0usize;
    let mut gps_items = 0usize;
    let mut warnings: Vec<SmolStr> = Vec::new();
    stream_records(&file, file.len(), &mut |item| match item {
      Insta360StreamItem::Accel(_) => accels += 1,
      Insta360StreamItem::Gps(_) => gps_items += 1,
      Insta360StreamItem::Warning(w) => warnings.push(w),
      _ => {}
    });
    assert_eq!(accels, 0);
    assert_eq!(gps_items, 1);
    assert_eq!(
      warnings,
      vec![SmolStr::new("Unexpected Insta360 record 0x300 length")]
    );
  }

  #[test]
  fn short_0x300_standalone_reads_past_body_into_footer_and_warns() {
    // R8 fix: the else-branch `$raf->Read($buff, 20)` reads the FILE past a
    // short body. Even a STANDALONE short 0x300 (no records after it) has its
    // 6-byte footer + the 78-byte trailer footer following the body, so
    // body-start..EOF is ≫ 20 — the probe SUCCEEDS. Here the probed
    // file_tail[16..18] falls in the footer's opaque-zero region ⇒ stride 56 ⇒
    // `10 % 56 != 0` ⇒ the `Unexpected … length` warning (sticky Doc 0), NOT a
    // silent skip. The genuine `Read(20)`-FAILED silent-skip path (< 20 bytes to
    // EOF) is unreachable through a well-formed `build_file` trailer and is
    // pinned at the `accel_stride` unit level instead.
    let body = vec![0u8; 10];
    let file = build_file(b"PFX", &[(ID_ACCELEROMETER, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert!(full.accel().is_empty());
    assert_eq!(
      full.warnings(),
      &[(0, SmolStr::new("Unexpected Insta360 record 0x300 length"))]
    );
  }

  #[test]
  fn non_multiple_0x700_is_exempt_and_decodes_complete_rows() {
    // QuickTimeStream.pl:3356 `$id != 0x700` — GPS is EXEMPT from the
    // non-multiple guard: it decodes its complete rows even on a non-multiple
    // length. One 53-byte fix + 5 trailing bytes (58 bytes) → still 1 fix, no
    // warning.
    let mut body = gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
    );
    body.extend_from_slice(&[0u8; 5]); // 58 bytes — not a multiple of 53
    let file = build_file(b"PFX", &[(ID_GPS, body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(
      full.gps().len(),
      1,
      "0x700 is exempt: a non-multiple GPS record still decodes its complete rows"
    );
    assert!(full.warnings().is_empty());
  }

  #[test]
  fn scan_trailer_skips_non_multiple_0x400_no_false_capture_settings() {
    // The LIGHT path must NOT surface a first-exposure summary from a malformed
    // (non-multiple) 0x400 — bundled decodes no rows from it, so there is no
    // CaptureSettings projection source.
    let mut body = exposure_row(1000, 0.008);
    body.push(0xff); // 17 bytes — not a multiple of 16
    let file = build_file(b"PFX", &[(ID_EXPOSURE, body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    assert!(
      out.first_exposure().is_none(),
      "the light path must skip a non-multiple 0x400 (no false CaptureSettings)"
    );
  }

  #[test]
  fn decode_all_records_identity_only_doc_is_zero() {
    // No timed rows walked before the identity ⇒ sticky DOC_NUM stays 0
    // (the flat/Main document case).
    let id_body = identity_body(&[(TAG_MODEL, b"Insta360 X3")]);
    let file = build_file(b"prefix", &[(ID_IDENTITY, id_body)]);
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(full.identity().unwrap().doc(), Some(0));
  }

  // ----- lazy-decode / DoS gate ----------------------------------------

  #[test]
  fn scan_trailer_defers_heavy_0x600_decode_to_full() {
    // A LARGE 0x600 VideoTimeStamp record (100000 rows × 8 bytes) plus one
    // valid 0x700 GPS fix. The LIGHT parse must NOT materialize the 100000
    // videotime rows (it skips 0x600 entirely and stores only the domain
    // summary); the FULL decode must yield all 100000 rows. This proves the
    // heavy decode is deferred out of the opts-agnostic parse (the DoS guard).
    const ROWS: u64 = 100_000;
    let mut videotime = Vec::with_capacity((ROWS as usize) * 8);
    for i in 0..ROWS {
      videotime.extend_from_slice(&videotime_row(i));
    }
    let gps = gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
    );
    // File order: videotime first, GPS last (so the light walk reaches GPS
    // first and can early-stop before ever touching the giant 0x600 record).
    let file = build_file(b"prefix", &[(ID_VIDEO_TIMESTAMP, videotime), (ID_GPS, gps)]);

    // (a) The light parse populates the GPS summary but materializes NO
    // videotime Vec — only the bounded domain summary is set on the meta (the
    // struct has no per-sample Vec to populate at all).
    let mut out = Insta360Meta::new();
    scan_trailer(&file, file.len(), &mut out);
    let fix = out.first_gps().expect("first GPS fix in the light summary");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
    assert!(out.first_exposure().is_none());
    assert!(out.identity().is_none());
    // The raw borrow is recorded for the deferred decode, but nothing heavy ran.
    assert!(out.raw().is_some());
    assert!(out.trailer().is_some());

    // (b) The full decode over the same bytes yields all 100000 videotime rows.
    let full = decode_all_records(&file, file.len(), 0);
    assert_eq!(full.videotime().len(), ROWS as usize);
    assert_eq!(full.gps().len(), 1);
  }

  #[test]
  fn stream_records_g1_collapse_is_bounded_for_huge_0x600() {
    // The `-ee -G1` streaming collapse (Finding 2): a trailer with 100000 0x600
    // VideoTimeStamp rows must collapse to ONE `VideoTimeStamp` tag WITHOUT ever
    // building a 100000-element vector. `stream_records` yields one row at a time;
    // the `-G1` first-wins-by-name accumulator (the production collapse, mimicked
    // here) commits only the FIRST occurrence of each name → O(distinct names),
    // never O(rows).
    const ROWS: u64 = 100_000;
    let mut videotime = Vec::with_capacity((ROWS as usize) * 8);
    for i in 0..ROWS {
      videotime.extend_from_slice(&videotime_row(i));
    }
    let file = build_file(b"prefix", &[(ID_VIDEO_TIMESTAMP, videotime)]);

    // The committed-names set IS the entire `-G1` memory footprint of the timed
    // rows. A bounded run keeps this tiny regardless of `ROWS`.
    let mut committed: Vec<SmolStr> = Vec::new();
    let mut rows_seen: u64 = 0;
    let mut peak_committed = 0usize;
    let mut visit = |item: Insta360StreamItem| {
      if let Insta360StreamItem::VideoTime(s) = item {
        rows_seen += 1;
        // First-wins-by-name: the production `-G1` collapse commits only the
        // first occurrence of each tag name (here the single `VideoTimeStamp`).
        let name = SmolStr::new("VideoTimeStamp");
        if !committed.contains(&name) {
          committed.push(name);
          // (the real path would push the formatted EmittedTag into `tags` here)
        }
        let _ = s; // value is formatted in the production path; unused in the gate
        peak_committed = peak_committed.max(committed.len());
      }
    };
    stream_records(&file, file.len(), &mut visit);

    // The stream visited all 100000 rows ONE AT A TIME …
    assert_eq!(rows_seen, ROWS, "every 0x600 row is streamed");
    // … but the committed-names set (the `-G1` memory) never exceeded ONE entry.
    assert_eq!(
      committed.len(),
      1,
      "the -G1 collapse keeps exactly one VideoTimeStamp tag"
    );
    assert_eq!(
      peak_committed, 1,
      "the -G1 committed-names set is O(distinct names), never O(rows)"
    );
  }

  #[test]
  fn stream_records_skips_non_multiple_and_warns() {
    // A non-multiple 0x400 (17 bytes) must yield NO Exposure items, only the
    // `Unexpected … length` warning — matching the full decode + the `-G1` path.
    let mut body = exposure_row(1000, 0.008);
    body.push(0xff);
    let file = build_file(b"PFX", &[(ID_EXPOSURE, body)]);
    let mut exposures = 0usize;
    let mut warnings: Vec<SmolStr> = Vec::new();
    stream_records(&file, file.len(), &mut |item| match item {
      Insta360StreamItem::Exposure(_) => exposures += 1,
      Insta360StreamItem::Warning(w) => warnings.push(w),
      _ => {}
    });
    assert_eq!(exposures, 0);
    assert_eq!(
      warnings,
      vec![SmolStr::new("Unexpected Insta360 record 0x400 length")]
    );
  }

  // ----- identify_trailers (linked-list discovery) ---------------------

  /// One minimal LigoGPS trailer block: `&&&&` + a BE u32 length (the
  /// QuickTime.pm:9906 signature). With `len == 8` (its own size) the backward
  /// walk steps exactly to the preceding trailer's end.
  fn ligogps_block(len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(LIGOGPS_MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out
  }

  #[test]
  fn identify_trailers_finds_insta360_behind_ligogps() {
    // A valid Insta360 trailer FOLLOWED BY an 8-byte LigoGPS block — the
    // chained case. `IdentifyTrailers` (QuickTime.pm:9897-9926) walks backward:
    // it finds the LigoGPS block at EOF, steps past it by its declared length
    // (8), then finds the Insta360 trailer (now ending at EOF-8). The returned
    // Vec is HEAD-FIRST: the EARLIEST (Insta360) trailer first.
    let prefix = b"prefix-bytes-here";
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 0.0, 0.0, 0.0,
    ));
    let insta = build_file(prefix, &[(ID_GPS, gps_body)]);
    let insta_start = prefix.len() as u64;
    let insta_len = insta.len() as u64 - insta_start;

    let mut file = insta.clone();
    file.extend_from_slice(&ligogps_block(8));

    let trailers = identify_trailers(&file);
    assert_eq!(trailers.len(), 2, "Insta360 + LigoGPS chain");
    // Head-first: Insta360 (earliest) then LigoGPS (EOF-ward).
    assert_eq!(trailers[0].kind(), TrailerKind::Insta360);
    assert_eq!(trailers[0].start(), insta_start);
    assert_eq!(trailers[0].len(), insta_len);
    assert_eq!(trailers[1].kind(), TrailerKind::LigoGPS);
    assert_eq!(trailers[1].start(), insta.len() as u64);
    assert_eq!(trailers[1].len(), 8);

    // The Insta360 trailer, though NOT at EOF, decodes fully when anchored at
    // its own end (`start + len`).
    let entry = &trailers[0];
    let entry_end = (entry.start() + entry.len()) as usize;
    let mut out = Insta360Meta::new();
    scan_trailer(&file, entry_end, &mut out);
    let fix = out
      .first_gps()
      .expect("GPS fix from the non-last Insta360 trailer");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
  }

  #[test]
  fn identify_trailers_standalone_insta360_single_entry() {
    // A standalone Insta360 trailer at EOF ⇒ a one-entry head-first Vec whose
    // span matches the EOF-anchored walk (the common case must be unchanged).
    let prefix = b"PFX";
    let id_body = identity_body(&[(TAG_MODEL, b"Insta360 X3")]);
    let file = build_file(prefix, &[(ID_IDENTITY, id_body)]);
    let trailers = identify_trailers(&file);
    assert_eq!(trailers.len(), 1);
    assert_eq!(trailers[0].kind(), TrailerKind::Insta360);
    assert_eq!(trailers[0].start(), prefix.len() as u64);
    assert_eq!(trailers[0].start() + trailers[0].len(), file.len() as u64);
  }

  #[test]
  fn identify_trailers_none_without_signature() {
    let data = vec![0u8; 200];
    assert!(identify_trailers(&data).is_empty());
    // Too short for even a 40-byte window.
    assert!(identify_trailers(&[0u8; 10]).is_empty());
  }

  #[test]
  fn identify_trailers_zero_len_does_not_loop() {
    // A LigoGPS block declaring len == 0 would re-read the same 40 bytes
    // forever; the walk must stop (matching the reference, which never advances
    // `offset` on a zero length). The block is found (so it could be returned),
    // but the `len == 0` guard halts before recording it. The file must be ≥ 40
    // bytes so the signature window IS readable (so this exercises the zero-len
    // guard, not the too-short-to-read break).
    let mut file = vec![0u8; 40]; // padding so the 40-byte window is readable
    file.extend_from_slice(&ligogps_block(0)); // BE len = 0
    let trailers = identify_trailers(&file);
    // Zero-length ⇒ the walk stops without recording an entry (no infinite loop).
    assert!(trailers.is_empty(), "a zero-length trailer halts the walk");
  }

  #[test]
  fn identify_trailers_huge_len_does_not_panic_or_loop() {
    // A LigoGPS block with a HUGE declared length: the block is recognized + the
    // (bad-size, wrapped-start) entry is recorded, but `offset += huge` then
    // overflows the next backward Seek ⇒ the walk stops cleanly (no panic, no
    // unbounded loop). The recorded `start` WRAPS like Perl's negative value.
    // The prefix must be ≥ 32 bytes so the 40-byte signature window is readable.
    let mut file = vec![0u8; 40]; // padding so file >= 40 bytes
    file.extend_from_slice(&ligogps_block(u32::MAX)); // absurd length
    let trailers = identify_trailers(&file);
    assert_eq!(trailers.len(), 1, "the bad-size LigoGPS is recorded once");
    assert_eq!(trailers[0].kind(), TrailerKind::LigoGPS);
    assert_eq!(trailers[0].len(), u64::from(u32::MAX));
    // start = window_end (file.len()) - huge_len, wrapped.
    assert_eq!(
      trailers[0].start(),
      (file.len() as u64).wrapping_sub(u64::from(u32::MAX))
    );
  }

  #[test]
  fn identify_trailers_caps_iteration_on_crafted_chain() {
    // Defensive: a long run of contiguous 8-byte LigoGPS blocks (each stepping
    // back exactly 8 bytes) must terminate within the MAX_TRAILERS cap, never
    // looping unbounded. Build many back-to-back 8-byte LigoGPS blocks.
    let mut file = Vec::new();
    file.extend_from_slice(b"head");
    for _ in 0..50 {
      file.extend_from_slice(&ligogps_block(8));
    }
    let trailers = identify_trailers(&file);
    // Each 8-byte block steps back 8 bytes; the walk finds blocks until the
    // window no longer carries `&&&&` at offset 32 (or runs out of bytes). The
    // exact count is bounded; the invariant is "terminates + ≤ MAX_TRAILERS".
    assert!(trailers.len() <= MAX_TRAILERS as usize);
    assert!(!trailers.is_empty());
    for t in &trailers {
      assert_eq!(t.kind(), TrailerKind::LigoGPS);
    }
  }

  #[test]
  fn ligogps_length_with_newline_byte_not_recognized() {
    // FIX 4 (QuickTime.pm:9906): the LigoGPS regex `/\&\&\&\&(.{4})$/` has NO
    // `/s` flag, so the 4 captured length bytes (`.{4}`) must contain NO newline
    // (`0x0A`). A LigoGPS-magic block whose BE u32 length has a `0x0A` byte
    // therefore FAILS the match and is NOT taken as a LigoGPS trailer (the walk
    // falls through to the MIE/`last` arms). Length `0x0000_0A08` → BE bytes
    // `[0x00, 0x00, 0x0A, 0x08]` (contains 0x0A).
    let mut with_newline = vec![0u8; 40]; // padding so the 40-byte window reads
    with_newline.extend_from_slice(&ligogps_block(0x0000_0A08));
    assert!(
      identify_trailers(&with_newline).is_empty(),
      "a LigoGPS length containing 0x0A must NOT match (no /s flag)"
    );

    // Control: the SAME block with a newline-free length (0x0000_0008) IS
    // recognized as a LigoGPS trailer.
    let mut clean = vec![0u8; 40];
    clean.extend_from_slice(&ligogps_block(8));
    let trailers = identify_trailers(&clean);
    assert_eq!(trailers.len(), 1);
    assert_eq!(trailers[0].kind(), TrailerKind::LigoGPS);
  }

  #[test]
  fn mie_trailer_len_decodes_both_forms() {
    // The 4-byte MIE form: `~\0\x04\0zmie~\0\0\x06 .{4} BO \x04` at buff[22..40].
    // BO = 0x10 ⇒ MM (big-endian) length at buff[34..38].
    let mut buff = vec![0u8; 40];
    buff[22..30].copy_from_slice(b"~\0\x04\0zmie");
    buff[30..34].copy_from_slice(b"~\0\0\x06");
    buff[34..38].copy_from_slice(&0x12345678u32.to_be_bytes()); // length (MM)
    buff[38] = 0x10; // MM
    buff[39] = 0x04; // 4-byte form marker
    assert_eq!(mie_trailer_len(&buff), Some(0x1234_5678));

    // The 8-byte MIE form: `~\0\x04\0zmie~\0\0\x0a .{8} BO \x08` at buff[18..40].
    // BO = 0x18 ⇒ II (little-endian) 64-bit length at buff[30..38].
    let mut b8 = vec![0u8; 40];
    b8[18..26].copy_from_slice(b"~\0\x04\0zmie");
    b8[26..30].copy_from_slice(b"~\0\0\x0a");
    b8[30..38].copy_from_slice(&0x0000_00ff_dead_beefu64.to_le_bytes()); // length (II)
    b8[38] = 0x18; // II
    b8[39] = 0x08; // 8-byte form marker
    assert_eq!(mie_trailer_len(&b8), Some(0x0000_00ff_dead_beef));

    // A non-MIE 40-byte window decodes to None.
    assert_eq!(mie_trailer_len(&[0u8; 40]), None);
  }
}
