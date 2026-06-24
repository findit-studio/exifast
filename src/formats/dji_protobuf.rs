// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Protobuf::ProcessProtobuf`
//! (Protobuf.pm:128-300) driven by the `%Image::ExifTool::DJI::Protobuf`
//! tag table (DJI.pm:235-859) plus its nested message tables
//! `DJI::FrameInfo` / `DJI::GPSInfo` / `DJI::DroneInfo` / `DJI::GimbalInfo`
//! (DJI.pm:867-921). Decodes the DJI `djmd` (real metadata) protobuf-format
//! timed-metadata samples reached through the `djmd` MetaFormat dispatch in
//! [`crate::formats::quicktime_stream`]. (QuickTimeStream.pl:349-358 routes
//! both `djmd` AND `dbgi` SubDirectories into `Image::ExifTool::DJI::Protobuf`,
//! but the `dbgi` table is `Unknown => 2`, QuickTimeStream.pl:355 — under the
//! default `Unknown = 0` `ProcessSamples` does not process a `dbgi` sample at
//! all, so exifast's default-options port treats `dbgi` as a complete no-op and
//! this module decodes only `djmd`.)
//!
//! ## Wire format (Protobuf.pm:18-117, ref protobuf.dev/.../encoding)
//!
//! A protobuf message is a flat sequence of records, each:
//! `[tag varint][payload]`, where `tag = (field_number << 3) | wire_type`.
//! Four wire types are produced by DJI bodies:
//!  - **0 = VARINT** — base-128 little-endian, ≤10 bytes for a u64
//!    ([`read_varint`]).
//!  - **1 = I64** — 8 fixed bytes (a `double` for DJI's I64 fields).
//!  - **2 = LEN** — `[len varint][len bytes]` — a string, a packed
//!    `rational` (two inner varints num/den), OR a nested message.
//!  - **5 = I32** — 4 fixed bytes (a `float` for DJI's I32 fields).
//!
//! Wire types 3/4 (deprecated start/end group) carry an empty payload
//! (Protobuf.pm:99-103); the walker accepts and skips them.
//!
//! ## Tag ID's are hierarchical paths
//!
//! DJI's tag table keys (e.g. `dvtm_ac203_3-4-2-2`) are the `.proto` file
//! name (minus `.proto`) joined to the chain of protobuf field numbers from
//! the top-level message down to the leaf (DJI.pm:244 NOTES). The walker
//! recurses into every nested (wire-type-2) message, accumulating the field
//! path, and matches each leaf `(protocol, path)` against the per-protocol
//! dispatch table ([`PROTOCOLS`]).
//!
//! ## The `int64s` "hack" (Protobuf.pm:181-185)
//!
//! DJI drones store 64-bit SIGNED integers improperly: a small negative
//! value is written as a varint whose top 32 bits are all 1's. Bundled
//! recovers the signed value when `val >= 0xffffffff00000000` by `val -
//! 0xffffffff00000000 - 0x100000000` (two subtractions to avoid 64-bit
//! overflow). [`decode_int64s`] mirrors this. `AbsoluteAltitude` and the
//! Drone/Gimbal orientation angles are all `int64s` fields.
//!
//! ## GPS coordinate conversion (DJI.pm:900-920)
//!
//! `GPSInfo` carries `CoordinateUnits` (field 1), `GPSLatitude` (field 2),
//! and `GPSLongitude` (field 3) as IEEE-754 doubles. When `CoordinateUnits`
//! is 0 / unset (the default), the lat/lon are in RADIANS and bundled converts
//! to degrees via `$val * 180 / 3.141592653589793`; when nonzero, they are
//! already degrees (DJI.pm:929/935, Perl-truthy). ExifTool reads
//! `$$self{CoordUnits}` PER-LEAF in each coordinate's RawConv at the moment it
//! is handled, so the conversion is done HERE the instant each
//! `GPSLatitude`/`GPSLongitude` is walked ([`coord_to_degrees`]) — a coordinate
//! preceding its `CoordinateUnits` sibling converts under the prior state. The
//! Mavic 4 Pro / Mini 5 Pro arms set `$$self{CoordUnits} = 1` via a
//! SubDirectory `Condition` evaluated when the GPSInfo message is reached
//! (DJI.pm:857 + :872), i.e. before its child coordinates. `CoordUnits` is
//! `$self`-scoped state that PERSISTS across samples within a track.
//!
//! ## What is decoded vs walked-only
//!
//! The typed surface [`crate::metadata::DjiProtobufMeta`] keeps the
//! camera-indexing fields (identity, GPS, altitude, capture settings, frame
//! info, orientation, timestamp). AccelerometerX/Y/Z (DJI.pm:286-288 etc.) and
//! per-protocol "model code" `# (NC)` fields are walked but discarded — matching
//! the bundled default-options gate where `Unknown` is unset. The `dbgi` debug
//! track (DJI.pm:355 `Unknown => 2`) is not processed at all under the default
//! options (a complete no-op — see the `dbgi` MetaFormat arm in
//! [`crate::formats::quicktime_stream`]).

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;

use smol_str::SmolStr;

use crate::metadata::{DjiProtobufMeta, DjiTelemetrySample, RationalValue};

// ===========================================================================
// Wire-format primitives (Protobuf.pm:50-107)
// ===========================================================================

/// `0xffffffff00000000` — the smallest unsigned varint bundled interprets as
/// an improperly-stored 64-bit signed integer (Protobuf.pm:31 `$int64sMin`).
const INT64S_MIN: u64 = 0xffff_ffff_0000_0000;

/// The continuation-byte count at which reading bails — a byte-exact mirror of
/// `VarInt`'s `return undef if ++$i > 32` bound (Protobuf.pm:67). Perl reads
/// the 1st byte OUTSIDE its loop and does NOT count it; its `$i` counts only the
/// continuation bytes read inside the loop, bailing the moment `++$i` exceeds 32
/// (so 33 continuation bytes past the first are accepted and the 34th trips it).
/// This port re-reads the first byte inside its loop and so counts EVERY
/// continuation byte (including the first) in `cont`; matching Perl's bound
/// therefore means bailing when `cont` reaches 34 (the 34th continuation byte
/// overall = Perl's 33rd loop-read one). Verified against a direct `VarInt`
/// trace: 33 leading `0x80` + a terminator decodes; 34 + a terminator is fatal.
/// The accumulated MAGNITUDE never causes failure in Perl (it folds into a lossy
/// double); only this bound and a byte running off the buffer end are fatal.
const VARINT_MAX_CONTINUATION: u32 = 34;

/// Outcome of reading one base-128 little-endian varint (Protobuf.pm:50-72
/// `VarInt`), modelling `VarInt`'s EXACT fatal/non-fatal split.
///
/// `VarInt` returns `undef` (fatal) on ONLY two conditions: a byte read runs
/// off the buffer end (truncation), or more than ~33 continuation bytes
/// (`++$i > 32`). A value that exceeds the 64-bit range is NOT fatal — Perl
/// accumulates it into a lossy double and returns it, advancing the cursor past
/// the whole well-formed varint. This port reproduces that three-way split so
/// the read path is never STRICTER than ExifTool: a value `< 2^64` decodes
/// exactly ([`Value`](Self::Value)); a well-formed value `≥ 2^64` is consumed
/// and reported as [`Overflow`](Self::Overflow) (the cursor still advances and
/// `bit0` / the low 3 bits remain available); a truncated / over-long varint is
/// [`Truncated`](Self::Truncated) — the ONLY case mapping to `VarInt` `undef`.
///
/// A varint extended with high-order ALL-ZERO 7-bit groups (a non-canonical but
/// well-formed encoding) is NOT overflow: each zero group adds `0` in `VarInt`'s
/// `$val += (ord & 0x7f) * $mult`, never changing the value or making it undef.
/// So such a varint decodes to its sub-`u64` value as [`Value`](Self::Value) (it
/// is [`Overflow`](Self::Overflow) only if a NONZERO payload bit lands at/past
/// bit 64). The continuation-count bound still applies: zero-extension past
/// [`VARINT_MAX_CONTINUATION`] is still [`Truncated`](Self::Truncated) (`VarInt`
/// undef), exactly as a nonzero over-long varint is.
#[derive(Debug)]
enum VarintRead<'a> {
  /// A well-formed varint whose value fits in `u64`. Carries the value, bit 0
  /// of the first byte (`$$dirInfo{Bit0}`), and the slice after it. This is the
  /// 99.999% real-data path and is byte-identical to the pre-refactor decode.
  Value(u64, bool, &'a [u8]),
  /// A well-formed varint (terminator within the continuation bound) whose
  /// accumulated value EXCEEDS `u64` via a NONZERO high-order payload bit. The
  /// whole varint was consumed; `low3` is the low 3 bits of the first byte (so a
  /// TAG varint can still recover its wire type and `bit0`), and the slice is
  /// positioned AFTER the varint — decoding continues, mirroring Perl folding the
  /// value into a lossy double and advancing `Pos`. Never produced for a real DJI
  /// value (nor for a merely zero-extended one — see [`Value`](Self::Value)).
  Overflow { low3: u8, rest: &'a [u8] },
  /// A byte ran off the buffer end, or the continuation count exceeded
  /// [`VARINT_MAX_CONTINUATION`]. The ONLY outcome that maps to `VarInt`
  /// returning `undef` — i.e. the ONLY fatal varint case. `rest` is the slice
  /// where `VarInt` left the cursor (`$$dirInfo{Pos}`): `&[]` when a byte ran
  /// off the buffer end (Perl's failed `GetBytes` leaves `Pos` at the end), or
  /// the bytes after the continuation-bound cutoff for an over-long varint. A
  /// caller that treats an undef length leniently (the LEN-length branch of
  /// [`read_tag`], `$len` undef ⇒ EMPTY record) resumes the walk from `rest`.
  Truncated { rest: &'a [u8] },
}

/// Read one base-128 little-endian varint (Protobuf.pm:50-72 `VarInt`).
///
/// Mirrors `VarInt`'s loop structure exactly so the fatal cases are byte-for-
/// byte ExifTool's: [`VarintRead::Truncated`] on a byte off the end or more
/// than [`VARINT_MAX_CONTINUATION`] continuation bytes; otherwise the varint is
/// well-formed and is either [`VarintRead::Value`] (fits `u64`) or
/// [`VarintRead::Overflow`] (well-formed but `> u64::MAX`, cursor advanced).
/// The accumulation is overflow-SAFE (no UB, no panic): once a payload bit
/// would land at or past bit 64 the value is flagged overflowed but the loop
/// keeps consuming bytes to find the terminator (so the cursor advances past
/// the WHOLE varint, exactly as Perl's lossy-double accumulation does).
#[inline]
fn read_varint(buf: &[u8]) -> VarintRead<'_> {
  let Some(&first) = buf.first() else {
    // GetBytes off the end on the very first byte ⇒ `VarInt` undef. The cursor
    // is at the (empty) buffer end.
    return VarintRead::Truncated { rest: buf };
  };
  let low3 = first & 0x07;
  let bit0 = first & 0x01 == 0x01;
  let mut val: u64 = 0;
  let mut shift: u32 = 0;
  let mut overflow = false;
  // `cont` counts every continuation byte read (the analogue of Perl's `$i`,
  // shifted by one because this loop re-reads the first byte — see
  // VARINT_MAX_CONTINUATION); it trips the read at that bound.
  let mut cont: u32 = 0;
  let mut i = 0usize;
  loop {
    let Some(&byte) = buf.get(i) else {
      // A byte read ran off the buffer end ⇒ `VarInt` undef (truncation). The
      // failed read left the cursor at the buffer end (`i == buf.len()`), so
      // `rest` is empty — exactly where Perl's failed `GetBytes` leaves `Pos`.
      return VarintRead::Truncated {
        rest: buf.get(i..).unwrap_or(&[]),
      };
    };
    let payload = u64::from(byte & 0x7f);
    // Fold the 7-bit payload in at `shift`. An ALL-ZERO 7-bit group contributes
    // nothing (`$val += 0 * $mult` in Perl) — it can never change the value or
    // overflow, regardless of `shift`; skip the shift/add entirely (so a
    // zero-extended varint past bit 64 stays a `Value`, NOT `Overflow`). Only a
    // NONZERO payload bit landing at/past bit 64 is true overflow: flag it
    // (never panic) but KEEP consuming so the cursor reaches the terminator —
    // Perl folds the excess into a lossy double and advances.
    if payload != 0 {
      match payload.checked_shl(shift) {
        Some(chunk) if chunk >> shift == payload => match val.checked_add(chunk) {
          Some(sum) => val = sum,
          None => overflow = true,
        },
        // `shift >= 64` (the 11th byte+) OR a bit shifted past bit 63 ⇒ over u64.
        _ => overflow = true,
      }
    }
    i += 1;
    if byte & 0x80 == 0 {
      // Terminator: the varint is well-formed. `buf.get(i..)` cannot fail
      // (`i <= buf.len()` after a successful `buf.get(i-1)`).
      let rest = buf.get(i..).unwrap_or(&[]);
      return if overflow {
        VarintRead::Overflow { low3, rest }
      } else {
        VarintRead::Value(val, bit0, rest)
      };
    }
    shift += 7;
    // Match `return undef if ++$i > 32`: this continuation byte itself
    // continues, so bump the counter and bail past the bound. The cursor is
    // past the byte that tripped the bound (`i` already incremented), matching
    // where `VarInt` leaves `Pos` on its over-long `return undef`.
    cont += 1;
    if cont >= VARINT_MAX_CONTINUATION {
      return VarintRead::Truncated {
        rest: buf.get(i..).unwrap_or(&[]),
      };
    }
  }
}

/// Wire types (Protobuf.pm:85-107).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireType {
  /// 0 — base-128 varint.
  Varint,
  /// 1 — 8 fixed bytes.
  I64,
  /// 2 — length-delimited (string / packed rational / nested message).
  Len,
  /// 3 / 4 — deprecated start/end group (empty payload).
  Group,
  /// 5 — 4 fixed bytes.
  I32,
}

impl WireType {
  /// Map the low 3 bits of a record tag to a wire type.
  #[inline]
  const fn from_bits(bits: u8) -> Option<Self> {
    match bits {
      0 => Some(Self::Varint),
      1 => Some(Self::I64),
      2 => Some(Self::Len),
      3 | 4 => Some(Self::Group),
      5 => Some(Self::I32),
      _ => None, // 6 / 7 are not valid wire types
    }
  }
}

/// A field-number sentinel for a record whose TAG varint overflowed `u64`
/// (`id = key >> 3` would exceed `u64`, so the true id is `> 2^61`). No
/// `%DJI::Protobuf` path contains a number this large, so it matches no leaf
/// and no branch ⇒ the record is consumed and skipped as an unknown tag —
/// exactly as ExifTool keeps the (huge, lossy-double) id and matches nothing.
const FIELD_OVERFLOW_SENTINEL: u64 = u64::MAX;

/// One decoded record: its field number, wire type, and payload.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Record<'a> {
  /// The protobuf field number (`id = key >> 3`). A `u64` because `ReadRecord`
  /// places NO cap on the id (`$val >> 3`, Protobuf.pm:86) — a huge id is read
  /// and simply matches no DJI path. A tag varint that overflowed `u64` carries
  /// [`FIELD_OVERFLOW_SENTINEL`].
  field: u64,
  wire: WireType,
  /// For VARINT: the payload is empty and `varint` carries the value. For
  /// I64/I32/LEN: the raw payload bytes.
  payload: &'a [u8],
  /// VARINT value + bit0 (only meaningful when `wire == Varint`).
  varint: u64,
  bit0: bool,
  /// `true` when this is a VARINT record whose VALUE varint overflowed `u64`
  /// (well-formed but `> u64::MAX`): the cursor was advanced past it and the
  /// value is NOT representable, so a known numeric leaf SKIPS it (see
  /// [`varint_value`]). `false` for every normal record.
  varint_overflow: bool,
}

/// Read one record's tag + payload (Protobuf.pm:78-107 `ReadRecord`).
///
/// Returns `Ok((record, rest))` on success, or `Err(post_rest)` on the EXACT
/// set of cases where `ReadRecord` returns `undef`. `post_rest` is the slice at
/// the position `$$dirInfo{Pos}` would hold after the failed `ReadRecord` — so
/// `post_rest.is_empty()` ⟺ `Pos == dirEnd`, the predicate the caller's
/// `Truncated protobuf data` gate (Protobuf.pm:278 `unless … Pos == dirEnd`)
/// needs. `GetBytes` advances `Pos` ONLY on success (Protobuf.pm:44 `$$dirInfo
/// {Pos} += $n` after the `$pos + $n > length` undef guard, :43), so a failed
/// fixed/LEN-body read leaves `Pos` exactly where `VarInt` left it (after the
/// last successfully-read varint), NOT at the buffer end. The fatal cases:
///  - the TAG varint is [`VarintRead::Truncated`] (off the end / `> ~33`
///    continuation bytes) ⇒ `VarInt` undef ⇒ `ReadRecord`
///    `return undef unless defined $val` (Protobuf.pm:84-85). `post_rest` =
///    `VarInt`'s leftover (`&[]` when a byte ran off the end);
///  - a VALUE (wire-0) varint is `Truncated` ⇒ `$buff = VarInt(...)` undef ⇒
///    the caller's `defined $buff or Warn` (Protobuf.pm:91/155). `post_rest` =
///    that `VarInt`'s leftover (`&[]` off-end);
///  - a fixed (I64/I32) body runs off the buffer end (`GetBytes` undef) ⇒
///    `post_rest` = the slice after the tag varint (`GetBytes` did not advance);
///  - a LEN body runs off the buffer end (`GetBytes($len)` undef, `$len` >
///    remaining) ⇒ `post_rest` = the slice after the LENGTH varint (the bytes
///    that exist but number fewer than `$len`; `&[]` for the no-body case);
///  - the LEN LENGTH varint [`Overflow`](VarintRead::Overflow)s `u64` — a huge
///    but DEFINED (Perl-truthy) length ⇒ `if ($len)` true ⇒ `GetBytes(huge)`
///    runs off the end ⇒ undef (Protobuf.pm:95-96) ⇒ `post_rest` = the slice
///    after the LENGTH varint;
///  - the wire type is 6/7 (matches none of `ReadRecord`'s if/elsif chain,
///    leaving `$buff` undef) ⇒ `post_rest` = the slice after the tag varint
///    (`VarInt` consumed the tag; no further read happened).
///
/// `ReadRecord` is otherwise LENIENT and this mirrors it: `$id = $val >> 3`
/// has NO cap (field is a `u64`; an id-0 or huge id reads fine and the caller
/// skips it as an unknown tag), and a TAG or VALUE varint whose value EXCEEDS
/// `u64` is NOT fatal — Perl folds it into a lossy double and advances `Pos`.
/// So a tag varint that [`Overflow`](VarintRead::Overflow)s yields a skippable
/// record (wire type from the first byte's low 3 bits, field =
/// [`FIELD_OVERFLOW_SENTINEL`], payload consumed by wire type), and a value
/// varint that overflows yields a VARINT record flagged `varint_overflow` (its
/// value is dropped by a known leaf — see [`Record::varint_overflow`]).
///
/// ASYMMETRY — only the LEN LENGTH varint is lenient on undef. `ReadRecord`'s
/// LEN branch is `my $len = VarInt(...); if ($len) { ... } else { $buff = '' }`
/// (Protobuf.pm:94-100), and `if ($len)` is Perl-FALSE for BOTH `undef` AND `0`.
/// So a LEN LENGTH varint that is [`Truncated`](VarintRead::Truncated) (`$len`
/// undef) is NOT fatal — it yields a DEFINED EMPTY LEN record positioned at the
/// cursor (`rest`), and the walk continues (ending cleanly when `rest` is the
/// buffer end). Contrast a tag/value varint `Truncated`, which IS fatal (above).
fn read_tag(buf: &[u8]) -> Result<(Record<'_>, &[u8]), &[u8]> {
  // The tag varint. `Value` ⇒ a normal id+wire; `Overflow` ⇒ a huge id we keep
  // (wire from the first byte's low 3 bits) and skip; `Truncated` ⇒ fatal.
  // `rest` is the slice AFTER the tag varint — the position `VarInt` left `Pos`
  // at (Protobuf.pm:84 read the tag before any failure below), so a wire-6/7 or
  // off-end-body failure returns `Err(rest_after_tag)`.
  let (field, low3, rest) = match read_varint(buf) {
    VarintRead::Value(key, _, rest) => (key >> 3, (key & 0x07) as u8, rest),
    VarintRead::Overflow { low3, rest } => {
      // The id (`key >> 3`) is `> 2^61`; keep a sentinel that matches no path.
      (FIELD_OVERFLOW_SENTINEL, low3, rest)
    }
    // A TAG varint undef is FATAL: `VarInt` undef ⇒ `ReadRecord` `return undef
    // unless defined $val` (Protobuf.pm:84-85). NOT lenient (contrast a LEN
    // length, below). `Pos` is where this `VarInt` left it (`&[]` off-end).
    VarintRead::Truncated { rest } => return Err(rest),
  };
  // Wire type 6/7 matches none of `ReadRecord`'s if/elsif chain ⇒ `$buff` stays
  // undef ⇒ FATAL. `VarInt` already consumed the tag and no later read happened,
  // so `Pos` is right after the tag varint (`rest`).
  let Some(wire) = WireType::from_bits(low3) else {
    return Err(rest);
  };
  match wire {
    WireType::Varint => {
      // A value varint that overflows `u64` is NOT fatal: Perl keeps the lossy
      // double and advances. Consume it and flag the value undecodable.
      let (val, bit0, varint_overflow, rest2) = match read_varint(rest) {
        VarintRead::Value(val, bit0, rest2) => (val, bit0, false, rest2),
        VarintRead::Overflow { low3, rest } => (0, low3 & 0x01 == 0x01, true, rest),
        // A VALUE varint undef is FATAL: `$buff = VarInt(...)` = undef ⇒ the
        // caller's `defined $buff or Warn('Protobuf format error')`
        // (Protobuf.pm:91/155). NOT lenient (contrast a LEN length, below).
        // `Pos` is where this VALUE `VarInt` left it (`&[]` when off-end).
        VarintRead::Truncated { rest } => return Err(rest),
      };
      Ok((
        Record {
          field,
          wire,
          payload: &[],
          varint: val,
          bit0,
          varint_overflow,
        },
        rest2,
      ))
    }
    WireType::I64 => {
      // A fixed-body `GetBytes(8)` that runs off the end leaves `Pos` unmoved
      // (Protobuf.pm:43-44 advances ONLY on success), i.e. right after the tag
      // varint (`rest`).
      let Some((body, rest2)) = take(rest, 8) else {
        return Err(rest);
      };
      Ok((
        Record {
          field,
          wire,
          payload: body,
          varint: 0,
          bit0: false,
          varint_overflow: false,
        },
        rest2,
      ))
    }
    WireType::I32 => {
      // As I64: a failed `GetBytes(4)` leaves `Pos` after the tag varint.
      let Some((body, rest2)) = take(rest, 4) else {
        return Err(rest);
      };
      Ok((
        Record {
          field,
          wire,
          payload: body,
          varint: 0,
          bit0: false,
          varint_overflow: false,
        },
        rest2,
      ))
    }
    WireType::Len => {
      // The LEN length varint. Perl: `my $len = VarInt(...); if ($len) {
      // $buff = GetBytes($dirInfo, $len) } else { $buff = '' }` (Protobuf.pm:
      // 94-100). `if ($len)` is Perl-FALSE for BOTH `undef` AND `0`, so:
      //  - `Value(0)` (a literal 0 length)          ⇒ EMPTY payload (`take(_,0)`).
      //  - `Truncated{rest}` (`$len` undef — a length varint that ran off the
      //    end or over-extended)                    ⇒ EMPTY payload, NOT fatal.
      //    UNLIKE a tag/value varint undef (which is fatal), an undef LEN length
      //    is `$len` Perl-false ⇒ `$buff = ''` ⇒ a DEFINED empty record. The walk
      //    resumes from `rest` (the buffer end for an off-end truncation ⇒ the
      //    loop then ends cleanly; the bytes after the bound otherwise).
      //  - `Value(n)` with `n > remaining`          ⇒ FATAL: `GetBytes($len)`
      //    truncates (`$pos + $n > length` ⇒ undef) ⇒ `ReadRecord` undef.
      //  - `Overflow` (a huge but DEFINED, Perl-TRUTHY length)
      //                                             ⇒ FATAL: `if ($len)` true ⇒
      //    `GetBytes(huge)` runs off the end ⇒ undef ⇒ `ReadRecord` undef.
      let (len, rest2) = match read_varint(rest) {
        VarintRead::Value(len, _, rest2) => (len, rest2),
        VarintRead::Truncated { rest } => {
          // `$len` undef ⇒ `$buff = ''` ⇒ an EMPTY LEN record at the cursor.
          return Ok((
            Record {
              field,
              wire,
              payload: &[],
              varint: 0,
              bit0: false,
              varint_overflow: false,
            },
            rest,
          ));
        }
        // A huge but DEFINED (Perl-truthy) length ⇒ `GetBytes` off the end.
        // `Pos` is right after the LENGTH varint (`rest`) — `GetBytes` failed
        // without advancing.
        VarintRead::Overflow { rest, .. } => return Err(rest),
      };
      // A LEN body that runs off the end: `GetBytes($len)` undef leaves `Pos`
      // right after the LENGTH varint (`rest2`) — the bytes that DO exist but
      // number fewer than `$len` (the no-body case is `&[]`). A `len` exceeding
      // `usize` cannot fit the buffer either ⇒ the same off-end cursor.
      let Ok(n) = usize::try_from(len) else {
        return Err(rest2);
      };
      let Some((body, rest3)) = take(rest2, n) else {
        return Err(rest2);
      };
      Ok((
        Record {
          field,
          wire,
          payload: body,
          varint: 0,
          bit0: false,
          varint_overflow: false,
        },
        rest3,
      ))
    }
    WireType::Group => {
      // Deprecated start/end group: empty payload, no length (Protobuf.pm:99).
      Ok((
        Record {
          field,
          wire,
          payload: &[],
          varint: 0,
          bit0: false,
          varint_overflow: false,
        },
        rest,
      ))
    }
  }
}

/// Split off the first `n` bytes, or `None` if the slice is shorter.
#[inline]
fn take(buf: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
  if buf.len() < n {
    return None;
  }
  Some(buf.split_at(n))
}

/// `true` if any byte of `buf` lies outside printable ASCII `0x20..=0x7e` —
/// the first half of ExifTool's speculative-protobuf gate
/// (`$buff =~ /[^\x20-\x7e]/`, Protobuf.pm:174). A wholly-printable payload (a
/// string / version field) fails this and is skipped without recursing.
#[inline]
fn has_non_printable(buf: &[u8]) -> bool {
  buf.iter().any(|&b| !(0x20..=0x7e).contains(&b))
}

/// `true` when `buf` parses CLEANLY as a sequence of protobuf records that
/// EXACTLY consumes it — a faithful port of `sub IsProtobuf` (Protobuf.pm:
/// 115-123): repeatedly `ReadRecord`; return false the moment a record fails to
/// parse; return true the moment a record read leaves the cursor exactly at the
/// end of the buffer. An empty buffer is NOT protobuf (the first `read_tag`
/// fails — matching ExifTool, whose loop calls `ReadRecord` on a zero-length
/// buffer and gets `undef`). The walk-depth/record-count is bounded by the
/// strictly-shrinking slice (each `read_tag` consumes ≥ 1 byte) plus an
/// explicit cap as a belt-and-braces guard against a non-shrinking step.
#[inline]
fn is_protobuf(buf: &[u8]) -> bool {
  let mut rest = buf;
  // Each record consumes ≥ 1 byte, so the loop is bounded by `buf.len()`; the
  // explicit cap mirrors that bound defensively (a record can never grow the
  // slice, but the cap removes any doubt about termination).
  for _ in 0..=buf.len() {
    let Ok((_, next)) = read_tag(rest) else {
      // `ReadRecord` undef ⇒ `IsProtobuf` returns 0 (Protobuf.pm:120).
      return false;
    };
    if next.is_empty() {
      // The records consumed the buffer EXACTLY (`Pos == length`).
      return true;
    }
    if next.len() >= rest.len() {
      // No forward progress (cannot happen — read_tag consumes ≥ 1 byte).
      return false;
    }
    rest = next;
  }
  false
}

// ===========================================================================
// Typed-value decoders (Protobuf.pm:160-228 — the per-Format conversions)
// ===========================================================================

/// `int64s` VARINT decode with the DJI "improper 64-bit signed" hack
/// (Protobuf.pm:194-199), returning an `f64` — the faithful representation of
/// `$val` as ExifTool carries it into the dividing ValueConv (÷1000 / ÷10).
///
/// ExifTool fires the hack ONLY when `$val >= $int64sMin`
/// (`0xffffffff00000000`): `$val = $val - $int64sMin - 4294967296`, i.e.
/// `$val - 2^64` — a small negative. For `$val < $int64sMin`, `$val` is left
/// as the UNSIGNED magnitude (a Perl double for large values), NOT wrapped to a
/// negative i64. A varint in `[2^63, $int64sMin)` therefore stays a HUGE
/// POSITIVE — modelling it as `f64` preserves that magnitude (exact for the
/// `< 2^53` real altitude/orientation data, approximate but sign-correct
/// above), whereas `as i64` would wrap it negative.
#[inline]
fn decode_int64s(val: u64) -> f64 {
  if val >= INT64S_MIN {
    // The DJI hack: `$val - 2^64`, a small negative. i128 avoids overflow;
    // the result is in `[-2^32, -1]` so the f64 cast is exact.
    #[allow(clippy::cast_precision_loss)]
    {
      (i128::from(val) - (1i128 << 64)) as f64
    }
  } else {
    // The unsigned magnitude — huge positive for `val >= 2^63`, exact below
    // 2^53 (all real DJI altitude/orientation values).
    #[allow(clippy::cast_precision_loss)]
    {
      val as f64
    }
  }
}

/// Decode a packed `rational` LEN payload: two inner varints num/den
/// (Protobuf.pm:201-205). Mirrors `$val = (defined $num and $den) ? $num/$den :
/// 'err'`:
///  - the numerator varint is missing/truncated (`VarInt` ⇒ `undef`) ⇒
///    [`RationalValue::Err`];
///  - the denominator varint is missing/truncated (`undef`, Perl-false) ⇒
///    [`RationalValue::Err`];
///  - `den == 0` (Perl-false) ⇒ [`RationalValue::Err`];
///  - otherwise ⇒ [`RationalValue::Num`] of the `f64` quotient.
///
/// An inner varint that OVERFLOWS `u64` is, in Perl, a defined lossy double
/// (`$num`/`$den` defined ⇒ a numeric quotient) — but a `> u64` numerator or
/// denominator is hostile/non-real input whose exact lossy-double value this
/// typed surface will not fabricate, so it is reported as [`RationalValue::Err`]
/// (a PRESENT `'err'` reading — the field still emits and the walk continues, it
/// is NOT a dropped value or an abort). This decode never aborts the walk.
///
/// Never "absent": a typed rational always produces a value (number or `err`),
/// because ExifTool always `HandleTag`s the field.
#[inline]
fn decode_rational(payload: &[u8]) -> RationalValue {
  let VarintRead::Value(num, _, rest) = read_varint(payload) else {
    // `$num` undef (truncated) or a `> u64` lossy double ⇒ 'err'.
    return RationalValue::Err;
  };
  let VarintRead::Value(den, _, _) = read_varint(rest) else {
    // `$den` undef / `> u64` ⇒ 'err'.
    return RationalValue::Err;
  };
  if den == 0 {
    // `$den` == 0 (Perl-false) ⇒ 'err'.
    return RationalValue::Err;
  }
  // f64 division (bundled uses `$num/$den` — Perl numeric division).
  #[allow(clippy::cast_precision_loss)]
  RationalValue::Num(num as f64 / den as f64)
}

/// An I64 (wire type 1) `double` (Protobuf.pm:208 `GetDouble`, little-endian
/// per `SetByteOrder('II')` Protobuf.pm:147).
#[inline]
fn decode_double(payload: &[u8]) -> Option<f64> {
  let b: [u8; 8] = payload.get(0..8)?.try_into().ok()?;
  Some(f64::from_le_bytes(b))
}

/// An I32 (wire type 5) `float` (Protobuf.pm:227 `GetFloat`, little-endian).
#[inline]
fn decode_float(payload: &[u8]) -> Option<f32> {
  let b: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
  Some(f32::from_le_bytes(b))
}

// ===========================================================================
// Field-semantics dispatch
// ===========================================================================

/// What a known leaf field decodes to + where it lands in the typed surface.
/// Each variant captures the bundled `Format` + `ValueConv` for one
/// `(protocol, path)` row of `%DJI::Protobuf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
  /// `1-1-5` SerialNumber — LEN ASCII string (DJI.pm:271 etc.).
  SerialNumber,
  /// `2-2-3-1` SerialNumber2 — LEN ASCII string. A NAMED tag (no `Unknown`
  /// flag) on the AVATA2 + DJI Neo arms (`'dvtm_AVATA2_2-2-3-1' =>
  /// 'SerialNumber2'` DJI.pm:399, `'dvtm_dji_neo_2-2-3-1' => 'SerialNumber2'`
  /// DJI.pm:553), so ExifTool extracts it by default at `-ee`. Has NO `Format`,
  /// so a LEN payload decodes as a plain ASCII string exactly like
  /// [`Self::SerialNumber`] (Protobuf.pm:239-256). The `# (NC)` on both rows is a
  /// "Not Confirmed" source comment, NOT a non-default marker.
  SerialNumber2,
  /// `1-1-10` Model — LEN ASCII string (DJI.pm:273 etc.).
  Model,
  /// `FrameNumber` (`3-1-1`), `Format => 'unsigned'` (a VARINT) — a per-frame
  /// counter declared on all 16 protocol arms (DJI.pm:279/:320/:361/:404 etc.,
  /// `#forum17996`). No ValueConv/PrintConv ⇒ emitted as the raw integer. Lives
  /// in the per-frame `3-1` message alongside [`Self::TimeStamp`] (`3-1-2`), so
  /// it lands PER `djmd` sample (one `Doc<N>` each), not clip-level.
  FrameNumber,
  /// `ISO`, `Format => 'float'` (an I32 float wire value).
  Iso,
  /// `ShutterSpeed`, `Format => 'rational'` (a LEN packed rational, seconds).
  ShutterSpeed,
  /// `FNumber`, `Format => 'rational'` (a LEN packed rational).
  FNumber,
  /// `ColorTemperature`, `Format => 'unsigned'` (a VARINT, Kelvin).
  ColorTemperature,
  /// `DigitalZoom`, `Format => 'float'` (an I32 float).
  DigitalZoom,
  /// `Temperature`, `Format => 'float'` (an I32 float, Celsius).
  Temperature,
  /// `AbsoluteAltitude`, `Format => 'int64s'`, `$val / 1000` (a VARINT,
  /// millimetres → metres). Every arm EXCEPT ac203/ac204/ac206 (and incl.
  /// oq101 — DJI.pm:700).
  AbsoluteAltitude,
  /// `GPSAltitude`, `Format => 'unsigned'`, `$val / 1000` (a PLAIN VARINT,
  /// millimetres → metres) — the ac203/ac204/ac206 `3-4-2-2` leaf
  /// (DJI.pm:296-301/:336/:377). Distinct from [`Self::AbsoluteAltitude`]
  /// in the emitted tag NAME (`GPSAltitude`) and in skipping the int64s
  /// hack (a plain unsigned, never the negative-recovery path). Stored on
  /// the same `absolute_altitude_m` typed field (it is the GPS altitude).
  GpsAltitude,
  /// `RelativeAltitude`, `Format => 'float'`, `$val / 1000` (an I32 float,
  /// millimetres → metres).
  RelativeAltitude,
  /// `GPSDateTime`, `Format => 'string'`, `tr/-/:/` (a LEN ASCII string).
  GpsDateTime,
  /// `TimeStamp`, `Format => 'unsigned'` (a VARINT, microsecond counter).
  /// Bundled divides by 1e6 for display; the typed surface keeps the raw
  /// microsecond `u64`.
  TimeStamp,
  /// `FrameInfo.FrameWidth` (field 1), `Format => 'unsigned'` (a VARINT).
  FrameWidth,
  /// `FrameInfo.FrameHeight` (field 2), `Format => 'unsigned'` (a VARINT).
  FrameHeight,
  /// `FrameInfo.FrameRate` (field 3), `Format => 'float'` (an I32 float).
  FrameRate,
  /// `GPSInfo.CoordinateUnits` (field 1), `Format => 'unsigned'` — NOT
  /// surfaced; sets the per-sample radians/degrees flag (DJI.pm:905).
  CoordinateUnits,
  /// `GPSInfo.GPSLatitude` (field 2), `Format => 'double'` (radians or
  /// degrees per CoordinateUnits).
  GpsLatitude,
  /// `GPSInfo.GPSLongitude` (field 3), `Format => 'double'`.
  GpsLongitude,
  /// `DroneInfo.DroneRoll` (field 1), `Format => 'int64s'`, `$val / 10`.
  DroneRoll,
  /// `DroneInfo.DronePitch` (field 2), `int64s`, `/ 10`.
  DronePitch,
  /// `DroneInfo.DroneYaw` (field 3), `int64s`, `/ 10`.
  DroneYaw,
  /// `GimbalInfo.GimbalPitch` (field 1), `int64s`, `/ 10`.
  GimbalPitch,
  /// `GimbalInfo.GimbalRoll` (field 2), `int64s`, `/ 10`.
  GimbalRoll,
  /// `GimbalInfo.GimbalYaw` (field 3), `int64s`, `/ 10`.
  GimbalYaw,
}

impl FieldKind {
  /// `true` when this leaf is a CHILD of one of DJI's four NAMED `SubDirectory`
  /// tables (`DJI::FrameInfo` / `DJI::GPSInfo` / `DJI::DroneInfo` /
  /// `DJI::GimbalInfo`, DJI.pm:886-921) — i.e. a field spliced in from a nested
  /// message table, NOT a leaf declared directly on a `%DJI::Protobuf` path.
  ///
  /// These twelve kinds are the ONLY rows whose immediate parent path is a named
  /// SubDirectory: each is generated by splicing one of the four nested tables in
  /// at its `SubDirectory` key (e.g. GPSInfo at `3-4-2-1` → child paths
  /// `3-4-2-1-{1,2,3}` carrying `CoordinateUnits`/`GpsLatitude`/`GpsLongitude`).
  /// A path is therefore a named SubDirectory exactly when it is the parent of a
  /// row with one of these kinds ([`Protocol::is_named_subdir`]) — verified to
  /// partition cleanly against the per-protocol DIRECT leaves
  /// (`GPSAltitude`/`GPSDateTime`/`AbsoluteAltitude`/… reached through UNNAMED
  /// wrappers), which never share a parent with a nested-table leaf.
  ///
  /// The distinction drives the recursion gate (Protobuf.pm:171-179 vs :227): a
  /// named SubDirectory is descended UNCONDITIONALLY, whereas an UNNAMED
  /// intermediate wrapper is descended only when its payload passes the
  /// `Unknown`-tag IsProtobuf gate (`has_non_printable && is_protobuf`).
  #[inline]
  const fn is_nested_leaf(self) -> bool {
    matches!(
      self,
      Self::FrameWidth
        | Self::FrameHeight
        | Self::FrameRate
        | Self::CoordinateUnits
        | Self::GpsLatitude
        | Self::GpsLongitude
        | Self::DroneRoll
        | Self::DronePitch
        | Self::DroneYaw
        | Self::GimbalPitch
        | Self::GimbalRoll
        | Self::GimbalYaw
    )
  }
}

/// One table row: a field path (chain of protobuf field numbers from the
/// top-level message to the leaf) + its semantics.
struct Row {
  /// Field-number path, e.g. `&[3, 4, 2, 2]` for `dvtm_ac203_3-4-2-2`. Each
  /// element is a `u64` to match [`Record::field`] (the protobuf id domain has
  /// no cap); real DJI paths are all small numbers.
  path: &'static [u64],
  kind: FieldKind,
}

/// One protocol's dispatch table: the `.proto` name (with `.proto` stripped,
/// matching `$$et{ProtoPrefix}` Protobuf.pm:159) + its rows, sorted by `path`
/// for binary search.
struct Protocol {
  /// The protocol name WITHOUT the `.proto` suffix (e.g. `dvtm_ac203`).
  name: &'static str,
  rows: &'static [Row],
}

include!("dji_protobuf_tables.rs");

/// Look up a protocol's table by its (suffix-stripped) name.
fn protocol_for(name: &str) -> Option<&'static Protocol> {
  PROTOCOLS.iter().find(|p| p.name == name)
}

/// Look up a leaf field's semantics by path within a protocol table.
fn field_for(proto: &Protocol, path: &[u64]) -> Option<FieldKind> {
  proto
    .rows
    .binary_search_by(|r| r.path.cmp(path))
    .ok()
    .and_then(|i| proto.rows.get(i))
    .map(|r| r.kind)
}

/// `true` when `path` is a PREFIX of any row's path in the protocol — i.e.
/// the field at `path` is a nested message we must recurse into to reach a
/// known leaf. Mirrors the bundled SubDirectory descent (the intermediate
/// `GPSInfo` / `DroneInfo` / `FrameInfo` / per-protocol container fields are
/// not leaves but parents of known leaves).
fn is_branch(proto: &Protocol, path: &[u64]) -> bool {
  // rows are path-sorted; a prefix match is contiguous. Linear scan is fine
  // (each protocol has ≤ ~16 rows).
  proto
    .rows
    .iter()
    .any(|r| r.path.len() > path.len() && r.path.starts_with(path))
}

/// Resolve a raw `GPSLatitude` / `GPSLongitude` double to decimal degrees
/// using the `CoordUnits` value ACTIVE at the moment the leaf is handled
/// (DJI.pm:929/935 `$$self{CoordUnits} ? $val : $val * 180 / 3.141592653589793`).
/// Perl truthiness: ANY nonzero units code (e.g. 1/2/3) ⇒ already-degrees;
/// `Some(0)` or `None` (unset / radians) ⇒ radians → degrees. ExifTool reads
/// `$$self{CoordUnits}` PER-LEAF at the coordinate's position, so an earlier
/// coordinate converts under the prior state and a later one under whatever a
/// `CoordinateUnits` sibling (or a force-degrees arm) set in between.
///
/// The radians→degrees expression is `(raw * 180) / pi` — Perl evaluates
/// `$val * 180 / 3.141592653589793` STRICTLY LEFT-TO-RIGHT (`*` and `/` are
/// left-associative, equal precedence), so the multiply happens BEFORE the
/// divide. Reassociating as `raw * (180 / pi)` (a precomputed factor) differs by
/// 1 ULP on ~1.8% of real radian inputs — visible at `exifast -ee -n` (the raw
/// F64 emit; the default DMS path masks it). The literal `3.141592653589793` is
/// bit-identical to [`core::f64::consts::PI`] (`0x400921fb54442d18`), so the
/// constant is exact; only the operation ORDER is load-bearing.
#[inline]
fn coord_to_degrees(raw: f64, coord_units: Option<u64>) -> f64 {
  if coord_units.is_some_and(|u| u != 0) {
    raw
  } else {
    (raw * 180.0) / core::f64::consts::PI
  }
}

/// Maximum nested-message recursion depth for the sequential walk. DJI's
/// deepest real leaf is `3-4-2-6-1` / `3-4-2-1-2` (five levels); the bound is
/// a generous panic-guard against a hostile deeply-nested LEN payload
/// (`ProcessProtobuf` recurses per nested message, Protobuf.pm:236 — bundled
/// relies on Perl's own stack-depth limit; we cap explicitly).
const MAX_WALK_DEPTH: u32 = 64;

/// The STICKY `IsProtobuf` verdict ExifTool stores on the `$tagInfo` of an
/// UNNAMED (`Unknown => 1`, `AddTagToTable`) protobuf wrapper, keyed by the full
/// tag path (Protobuf.pm:171-179). The two enumerated states are the only ones
/// ExifTool PERSISTS; the implicit third "unevaluated" state is the ABSENCE of a
/// map entry (ExifTool's `not defined $$tagInfo{IsProtobuf}`).
///
/// ## The tri-state (Protobuf.pm:171-179)
///
/// ```text
/// if ($$tagInfo{IsProtobuf}) {                    # currently Yes
///     $$tagInfo{IsProtobuf} = 0 unless IsProtobuf(\$buff);   # → No (sticky) if THIS payload isn't protobuf
/// } elsif (not defined $$tagInfo{IsProtobuf} and  # currently unevaluated
///          $buff =~ /[^\x20-\x7e]/ and IsProtobuf(\$buff)) {
///     $$tagInfo{IsProtobuf} = 1;                  # → Yes
/// }
/// next unless $$tagInfo{IsProtobuf} or $unknown;  # skip (no recurse) unless Yes
/// ```
///
///  - **unevaluated** (no entry): evaluate `has_non_printable && is_protobuf` on
///    THIS payload. If both hold ⇒ become [`Self::Yes`] and recurse. Otherwise
///    NO entry is written (ExifTool leaves `IsProtobuf` undef — the `elsif` only
///    ASSIGNS on success), the payload is skipped, and a LATER payload at the
///    same path is re-evaluated fresh. In particular a corrupt-FIRST payload
///    leaves the path unevaluated, NOT [`Self::No`].
///  - [`Self::Yes`]: re-check ONLY `is_protobuf` on THIS payload (the
///    non-printable test is NOT re-applied once Yes). Still protobuf ⇒ stays Yes
///    and recurses; NOT protobuf ⇒ flips to [`Self::No`] (the sole sticky
///    true→false transition) and is skipped.
///  - [`Self::No`]: skipped immediately — neither branch fires (the `if` needs
///    Yes, the `elsif` needs unevaluated), so it STAYS No (sticky) and every
///    subsequent payload at this path is suppressed WITHOUT re-evaluation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IsProtobufVerdict {
  /// `$$tagInfo{IsProtobuf}` truthy — descend the unnamed wrapper.
  Yes,
  /// `$$tagInfo{IsProtobuf}` defined-false — STICKY; skip this and all later
  /// payloads at this path (set only by a `Yes → No` flip on a corrupt payload).
  No,
}

/// The per-track sticky `IsProtobuf` cache — ExifTool's per-`$dirName` tag table
/// IsProtobuf storage (Protobuf.pm:163-179), keyed by the FULL unknown tag path
/// `"$$et{ProtoPrefix}{$dirName}$prefix$id"` (Protobuf.pm:162). The key is
/// `(active ProtoPrefix bytes, field-number path)`:
///  - the FIRST component is the active `ProtoPrefix` BYTES
///    (`$$et{ProtoPrefix}{$dirName}` = `substr($buff, 0, -6) . '_'`, Protobuf.pm:
///    159) — the RAW `.proto`-leaf payload with its last 6 bytes stripped and a
///    `_` appended ([`DjiTrackState::raw_proto_prefix`]), `None` for the empty
///    `''` prefix (no `.proto` leaf seen yet);
///  - the `Vec<u64>` is the `$prefix$id` field-number chain.
///
/// Keying by the EXACT RAW prefix BYTES — NOT the lossy DISPLAY string and NOT
/// the RESOLVED known [`Protocol`] — is byte-for-byte what ExifTool does: its
/// `$tag` interpolates the raw-byte `ProtoPrefix`, so empty, each KNOWN protocol
/// (`dvtm_ac203_`), AND each UNKNOWN protocol (`dvtm_unknownA_` vs
/// `dvtm_unknownB_`) all yield DISTINCT tag keys → DISTINCT `$tagInfo` →
/// independent sticky `IsProtobuf` verdicts. Two subtle classes the lossy DISPLAY
/// string ([`DjiTrackState::decode_prefix`]) would mis-bucket but the raw bytes
/// get right:
///  - DISTINCT non-UTF-8 prefixes `\xff.proto` and `\xfe.proto` are DIFFERENT
///    `ProtoPrefix` (`\xff_` vs `\xfe_`) in ExifTool but [`String::from_utf8_lossy`]
///    renders BOTH to the same replacement-char display string — keying by that
///    string would falsely collide them (a `Yes → No` flip under one suppressing
///    the other);
///  - the suffix edges `X..proto` and `X.proto\n` collapse to the SAME
///    `ProtoPrefix` `X._` in ExifTool (both strip their last 6 bytes to `X.`) but
///    are DISTINCT full display strings — keying by the string would wrongly keep
///    them separate.
///
/// (Keying by the resolved `Protocol` would collapse the empty prefix and EVERY
/// unknown prefix to one `None` bucket, so a sticky-`No` flip under one unknown
/// `.proto` would wrongly suppress a later clean wrapper under a DISTINCT unknown
/// `.proto` at the same path — which ExifTool re-evaluates fresh under its own tag
/// key.) Lives for the track's lifetime ([`DjiTrackState`]) just as the cloned tag
/// table lives for the file extraction.
type IsProtobufCache =
  BTreeMap<(Option<alloc::vec::Vec<u8>>, alloc::vec::Vec<u64>), IsProtobufVerdict>;

// ===========================================================================
// Public entry points
// ===========================================================================

/// The MUTABLE per-track decode state of ONE DJI `djmd` `trak` — exactly
/// ExifTool's per-`$dirName` `ProtoPrefix` plus the `$self`-scoped `CoordUnits`,
/// scoped to one metadata track.
///
/// ## Why per-track and not file-level (R15-F2)
///
/// ExifTool keys `ProtoPrefix` PER metadata track: `$$et{ProtoPrefix}{$dirName}
/// = '' unless defined` (Protobuf.pm:143) initializes it EMPTY for each track's
/// `$dirName` and never inherits from another track. One DJI `djmd` `trak` is
/// one `$dirName`, so a SECOND `djmd` track that begins data-only (or with a
/// coordinate before its own protocol / `CoordinateUnits` leaf) must NOT decode
/// under the FIRST track's prefix/units — doing so would fabricate GPS / camera
/// tags for the wrong track. This state is created FRESH for each `djmd` `trak`
/// ([`DjiTrackState::new`], the empty `''` init) and PERSISTS across that trak's
/// samples (R4 within-track last-wins — the `=`-overwrite on every `.proto`
/// leaf, the carried `CoordUnits`). The stream walker
/// ([`crate::formats::quicktime_stream`]) constructs one per `djmd` track and
/// threads it through every sample of that track.
///
/// Distinct from the file-level [`DjiProtobufMeta`] AGGREGATE (decoded samples,
/// the FIRST-wins model identity [`DjiProtobufMeta::protocol`], the warnings),
/// which spans ALL of the file's `djmd` tracks. Splitting the two is what keeps
/// the per-track model: the decode prefix/units never leak across tracks, while
/// the decoded rows + identity + warnings still aggregate file-wide.
pub(crate) struct DjiTrackState {
  /// The CURRENT last-wins `.proto`-leaf value rendered for DISPLAY (the verbatim
  /// payload; non-UTF-8 bytes go through [`String::from_utf8_lossy`]). This is the
  /// emitted `Protocol` name source and the input to [`strip_and_lookup`] for
  /// table resolution — NOT the sticky-cache key. `None` = the initial empty `''`
  /// (no table active yet). Distinct from [`Self::raw_proto_prefix`], the
  /// byte-exact ExifTool `ProtoPrefix` used to key the cache.
  decode_prefix: Option<SmolStr>,
  /// `$$et{ProtoPrefix}{$dirName}` (Protobuf.pm:159) — the byte-EXACT active
  /// `ProtoPrefix` = `substr($buff, 0, -6) . '_'` of the last-wins `.proto` leaf:
  /// its RAW payload bytes with the last 6 stripped and a `_` appended. `None` =
  /// the empty `''` prefix (no `.proto` leaf seen yet). This — NOT the lossy
  /// [`Self::decode_prefix`] display string — is the sticky-cache key prefix
  /// ([`IsProtobufCache`]), so it is byte-for-byte ExifTool's interpolated tag key
  /// (no lossy collision of distinct non-UTF-8 prefixes, no suffix-edge mismatch
  /// of `X..proto` vs `X.proto\n`).
  raw_proto_prefix: Option<alloc::vec::Vec<u8>>,
  /// `$$self{CoordUnits}` (DJI.pm:922) — the persistent radians/degrees state
  /// read per-leaf by the GPS RawConv. `None` ⇒ unset (radians); `Some(0)` ⇒
  /// explicit radians; `Some(n != 0)` ⇒ degrees (Perl-truthy, DJI.pm:929/935).
  coord_units: Option<u64>,
  /// The STICKY `IsProtobuf` verdicts ExifTool stores on each UNNAMED wrapper's
  /// `$tagInfo`, keyed by `(active ProtoPrefix bytes, full path)` (Protobuf.pm:
  /// 171-179) — the active `ProtoPrefix` being the byte-exact
  /// [`Self::raw_proto_prefix`] (distinct for empty / each known / each unknown
  /// protocol, mirroring ExifTool's interpolated raw-byte `$tag`). PERSISTS across
  /// this track's samples — once a path flips to [`IsProtobufVerdict::No`] (a
  /// corrupt payload after a clean one), every later payload at that SAME
  /// prefix+path is suppressed, matching ExifTool's per-`$dirName` tag table.
  /// Created EMPTY per `djmd` `trak` (the cloned-table analogue) and never shared
  /// across tracks.
  is_protobuf_cache: IsProtobufCache,
}

impl DjiTrackState {
  /// A FRESH per-track decode state — the empty `''` `ProtoPrefix` + unset
  /// `CoordUnits` ExifTool starts each `$dirName` with (Protobuf.pm:143).
  /// Constructed once per `djmd` `trak`.
  #[inline]
  #[must_use]
  pub(crate) const fn new() -> Self {
    Self {
      decode_prefix: None,
      raw_proto_prefix: None,
      coord_units: None,
      is_protobuf_cache: BTreeMap::new(),
    }
  }

  /// The CURRENT (last-wins) decode prefix the next data-only sample of THIS
  /// track decodes under.
  #[inline]
  #[must_use]
  fn decode_prefix(&self) -> Option<&str> {
    self.decode_prefix.as_deref()
  }

  /// OVERWRITE the DISPLAY decode prefix last-wins (every `.proto` leaf,
  /// Protobuf.pm:159) — the lossy `Protocol`-name / [`strip_and_lookup`] source.
  #[inline]
  fn set_decode_prefix(&mut self, v: SmolStr) {
    self.decode_prefix = Some(v);
  }

  /// OVERWRITE the byte-exact active `ProtoPrefix` last-wins from a matched
  /// `.proto`-leaf `payload` (Protobuf.pm:159 `$$et{ProtoPrefix}{$dirName} =
  /// substr($buff, 0, -6) . '_'`): the RAW payload bytes with the LAST 6 stripped
  /// (a clean `.proto` ending drops `.proto`; a `.proto\n` ending drops `proto\n`,
  /// leaving the trailing `.` — so `X..proto` and `X.proto\n` both → `X._`) and a
  /// `_` appended. `payload` always has length ≥ 6 here ([`proto_suffix`] matched
  /// `.proto`/`.proto\n`), so the `.get(..)` cut never hits its `&[]` fallback.
  #[inline]
  fn set_raw_proto_prefix(&mut self, payload: &[u8]) {
    let mut prefix = payload
      .get(..payload.len().saturating_sub(6))
      .unwrap_or(&[])
      .to_vec();
    prefix.push(b'_');
    self.raw_proto_prefix = Some(prefix);
  }

  /// The persistent `CoordUnits` (DJI.pm:922) active right now.
  #[inline]
  #[must_use]
  const fn coord_units(&self) -> Option<u64> {
    self.coord_units
  }

  /// Update `CoordUnits` (a `CoordinateUnits` leaf, DJI.pm:922; or a
  /// Mavic4/Mini5Pro force-degrees arm, DJI.pm:857/872).
  #[inline]
  const fn set_coord_units(&mut self, v: u64) {
    self.coord_units = Some(v);
  }

  /// Decide whether to descend an UNNAMED protobuf wrapper at `path` under the
  /// CURRENT active `ProtoPrefix`, applying — and MUTATING — ExifTool's STICKY
  /// per-`$tagInfo` `IsProtobuf` tri-state (Protobuf.pm:171-179). `payload` is
  /// THIS record's RAW body; its predicates (`$buff =~ /[^\x20-\x7e]/` and
  /// `IsProtobuf(\$buff)`) are evaluated LAZILY, ONLY in the branch that needs
  /// them. Returns `true` to recurse (verdict [`IsProtobufVerdict::Yes`]),
  /// `false` to skip.
  ///
  /// The cache key's prefix component is the byte-exact active `ProtoPrefix`
  /// ([`Self::raw_proto_prefix`], `$$et{ProtoPrefix}{$dirName}`) — so empty, each
  /// KNOWN, and each UNKNOWN `.proto` get DISTINCT sticky verdicts, exactly as
  /// ExifTool's interpolated raw-byte `$tag` (Protobuf.pm:162) keys a DISTINCT
  /// `$tagInfo` per prefix (no lossy collision of distinct non-UTF-8 prefixes, no
  /// suffix-edge mismatch — see [`IsProtobufCache`]).
  ///
  /// This is the stateful analogue of the formerly-stateless `has_non_printable
  /// && is_protobuf` gate: the verdict for a (prefix, path) is cached and carried
  /// across every payload there for the track's lifetime, so a corrupt payload
  /// that flips a previously-`Yes` path to sticky-`No` suppresses ALL subsequent
  /// (even clean) payloads there — exactly as ExifTool stores `IsProtobuf = 0` on
  /// the `$tagInfo` and `next unless $$tagInfo{IsProtobuf}` thereafter.
  ///
  /// ## Early-skip ordering (Protobuf.pm:172-179)
  ///
  /// The cache is consulted FIRST and the payload is scanned ONLY when ExifTool
  /// would scan it: a sticky-`No` path short-circuits with NO `has_non_printable`
  /// / `is_protobuf` evaluation (ExifTool's defined-false `$tagInfo{IsProtobuf}`
  /// fires NEITHER the `if` nor the `elsif`, then `next unless …` skips — it
  /// never calls `IsProtobuf`), a `Yes` path evaluates ONLY `is_protobuf` (the
  /// `if` re-check), and an unevaluated path evaluates `has_non_printable` then
  /// (short-circuit) `is_protobuf` (the `elsif`'s `$buff =~ … and IsProtobuf`).
  /// This avoids the wasted re-scan of a sticky-`No` path's payload on hostile
  /// input with many large LEN bodies after a `Yes → No` flip.
  fn unnamed_wrapper_should_recurse(&mut self, path: &[u64], payload: &[u8]) -> bool {
    use alloc::collections::btree_map::Entry;
    // The active `ProtoPrefix` (`$$et{ProtoPrefix}{$dirName}` = `substr($buff, 0,
    // -6) . '_'`): the byte-EXACT last-wins `.proto`-leaf prefix, `None` for the
    // empty `''` prefix. DISTINCT per known AND per unknown protocol, byte-for-byte
    // ExifTool's interpolated tag key — see [`IsProtobufCache`].
    let prefix = self.raw_proto_prefix.clone();
    match self.is_protobuf_cache.entry((prefix, path.to_vec())) {
      Entry::Occupied(mut e) => match e.get() {
        // `$$tagInfo{IsProtobuf}` already truthy (Protobuf.pm:172): re-check ONLY
        // `IsProtobuf(\$buff)` on THIS payload — the non-printable test is NOT
        // re-applied. Still protobuf ⇒ stays Yes, recurse; not protobuf ⇒ flip to
        // sticky `No` (`$$tagInfo{IsProtobuf} = 0 unless IsProtobuf(\$buff)`) and
        // skip (`next unless $$tagInfo{IsProtobuf}`).
        IsProtobufVerdict::Yes => {
          if is_protobuf(payload) {
            true
          } else {
            e.insert(IsProtobufVerdict::No);
            false
          }
        }
        // Sticky `No` (Protobuf.pm: defined-false fires NEITHER branch, then
        // `next unless` skips): suppress WITHOUT scanning the payload — no
        // `has_non_printable` / `is_protobuf` evaluation — leaving the verdict
        // `No`. This is the early-skip short-circuit.
        IsProtobufVerdict::No => false,
      },
      // `not defined $$tagInfo{IsProtobuf}` (Protobuf.pm:174): the `elsif` ASSIGNS
      // `IsProtobuf = 1` ONLY when the payload is non-printable AND parses as
      // protobuf; otherwise it leaves the flag undef (NO entry written here), so
      // the path stays unevaluated and a later payload is judged fresh. A
      // corrupt-first payload therefore does NOT become sticky `No`. Evaluated in
      // ExifTool's order (`$buff =~ /[^\x20-\x7e]/ and IsProtobuf(\$buff)`):
      // `has_non_printable` first, `is_protobuf` only if it holds.
      Entry::Vacant(slot) => {
        if has_non_printable(payload) && is_protobuf(payload) {
          slot.insert(IsProtobufVerdict::Yes);
          true
        } else {
          false
        }
      }
    }
  }
}

/// Decode ONE DJI `djmd` timed-metadata sample (QuickTimeStream.pl:349-352
/// → `Image::ExifTool::DJI::Protobuf`).
///
/// One sample is one top-level protobuf message. ExifTool calls
/// `FoundSomething` (which opens a fresh `Doc<N>` + emits `SampleTime`/
/// `SampleDuration`) for EVERY dispatched `djmd` sample, then `ProcessProtobuf`
/// `HandleTag`s that sample's own decoded leaves under it (QuickTimeStream.pl:
/// 1502 + Protobuf.pm:160-162). To keep the row↔`Doc<N>` mapping 1:1 with the
/// `open_doc()` the `quicktime_stream` arm performs per sample, this ALWAYS
/// pushes exactly ONE [`DjiTelemetrySample`] row, carrying whatever this sample
/// decoded — `Protocol` only when this sample's own records held a `.proto`
/// leaf (`HandleTag`-when-seen), `SerialNumber`/`Model`/telemetry when present.
/// An identity-only or even empty sample still pushes a row (a Doc placeholder
/// the arm stamps with `SampleTime`/`SampleDuration`).
///
/// ## Cross-sample protocol persistence (Protobuf.pm:143/159/162)
///
/// `$$et{ProtoPrefix}{$dirName}` is PER-TRACK persistent state: initialized
/// `''` once PER track (Protobuf.pm:143), OVERWRITTEN (`=`, last-wins) from
/// EVERY `.proto` leaf, and used by EVERY record's tag (line 162) using the
/// CURRENT (persisted) prefix. So a later data-only sample (no `.proto` leaf of
/// its own) decodes its records with the LAST protocol any prior sample's
/// `.proto` leaf set IN THE SAME TRACK. That per-track state is [`DjiTrackState`]
/// — created fresh per `djmd` `trak`, threaded through every sample of that
/// track, and NEVER inherited by another track (R15-F2). The persistent
/// `CoordUnits` lives on it too. (Distinct from the FIRST-wins file-level
/// [`DjiProtobufMeta::protocol`] model identity, which aggregates across all
/// tracks.) The DECODED samples still append into the file-level aggregate
/// `out`.
pub(crate) fn process_djmd(buff: &[u8], state: &mut DjiTrackState, out: &mut DjiProtobufMeta) {
  let mut sample = DjiTelemetrySample::new();
  // SINGLE sequential pass (Protobuf.pm:151-238). The CURRENT protocol prefix
  // is seeded from the track-persisted LAST-WINS prefix
  // (`$$et{ProtoPrefix}{$dirName}` carries across this track's `ProcessProtobuf`
  // calls and is `=`-overwritten on every `.proto` leaf, Protobuf.pm:159) and
  // may be UPDATED mid-walk by a `.proto` leaf. The persistent `CoordUnits`
  // likewise carries across this track's samples. Both live on the per-track
  // `state` (fresh per `djmd` `trak`), NOT the file-level aggregate, so a second
  // track starts EMPTY (R15-F2). A truncated/bad-wire record stops the walk with
  // a `Protobuf format error` warning but KEEPS everything decoded before it.
  let mut proto = state.decode_prefix().and_then(strip_and_lookup);
  let mut path: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(8);
  // The TOP-LEVEL `ProcessProtobuf` has an empty `$prefix` (Protobuf.pm:143-147),
  // so `Truncated protobuf data` can fire here ⇒ `fresh_prefix = true`.
  walk(
    buff,
    &mut proto,
    &mut path,
    0,
    true,
    state,
    &mut sample,
    out,
  );
  // ALWAYS push exactly one row per dispatched `djmd` sample (1:1 with the
  // arm's `open_doc()`), even when empty — `FoundSomething` opens the document
  // unconditionally (QuickTimeStream.pl:1502 + 969).
  out.push_sample(sample);
}

/// Strip a `.proto` suffix and resolve the per-protocol dispatch table, or
/// `None` for an unknown protocol (identity/warning is the caller's concern).
fn strip_and_lookup(protocol: &str) -> Option<&'static Protocol> {
  protocol_for(protocol.strip_suffix(".proto").unwrap_or(protocol))
}

/// Record the verbatim `Protocol` string (first-wins MODEL identity) + raise the
/// unknown-protocol warning (DJI.pm:259-266 RawConv).
///
/// ExifTool `HandleTag`s the rendered `Protocol` tag on EVERY `.proto` leaf
/// (Protobuf.pm:160); the tag's value is output-deduped FIRST-wins, so the
/// surfaced [`DjiProtobufMeta::protocol`] keeps the FIRST protocol. But the
/// `Protocol` RawConv (DJI.pm:259-266) — which raises the unknown-protocol
/// warning — RUNS on every leaf, so a later unknown protocol STILL warns even
/// after a known first one. Hence the warning is raised on every call here,
/// independent of the first-wins identity store.
fn record_protocol(protocol: &str, out: &mut DjiProtobufMeta) {
  // First-wins MODEL identity (the de-duped rendered `Protocol` value).
  if out.protocol().is_none() {
    out.set_protocol(SmolStr::new(protocol));
  }
  // The `Protocol` RawConv warning fires on EVERY leaf (NOT gated by the
  // first-wins identity above): a later `.proto` leaf carrying an unknown
  // protocol must still warn, AND a recurring unknown protocol warns once per
  // sample (ExifTool's WAS_WARNED counts the occurrences for the `[xN]` suffix
  // — so this is recorded per raise, NOT first-wins).
  if !is_known_protocol(protocol) && !protocol.starts_with("dbginfo") {
    // DJI.pm:262-264: `Unknown protocol $val (please submit sample for
    // testing)` — store ExifTool's full wording incl. the parenthetical.
    let mut msg = String::with_capacity(17 + protocol.len() + 36);
    msg.push_str("Unknown protocol ");
    msg.push_str(protocol);
    msg.push_str(" (please submit sample for testing)");
    out.push_warning(crate::metadata::DjiWarning::new(SmolStr::new(msg), false));
  }
}

/// `Some(payload)` when `payload`'s RAW BYTES match Perl's `/\.proto$/`
/// (Protobuf.pm:157) — i.e. they end in `.proto` OR in `.proto\n` (EXACTLY one
/// trailing line-feed). A faithful port of ExifTool's `$type == 2 and $buff =~
/// /\.proto$/`: the match is on the RAW payload bytes (the six bytes `2e 70 72
/// 6f 74 6f`) with NO UTF-8/printable requirement and NO protobuf-shape
/// condition, so a BINARY LEN payload matching `/\.proto$/` switches the
/// protocol exactly like a printable `dvtm_*.proto` string does — overwriting
/// `$$et{ProtoPrefix}` to the new (here unknown) protocol and stopping
/// subsequent records from decoding under the prior known prefix.
///
/// ## The `$`-before-final-`\n` edge (R15-F1)
///
/// Perl's `$` (no `/m`, no `/s`) anchors at end-of-string OR IMMEDIATELY BEFORE
/// a SINGLE final `\n`. So `dvtm_X.proto\n` MATCHES `/\.proto$/` and switches the
/// prefix, whereas a plain `payload.ends_with(b".proto")` would miss it (leaving
/// a STALE prior prefix — the stale-prefix class). `$` matches ONLY one trailing
/// `\n`: `.proto\r\n` and `.proto\n\n` do NOT match (verified against Perl). This
/// returns the WHOLE payload (incl. the trailing `\n`) so [`switch_protocol`]
/// emits `Protocol => $buff` as the FULL value (Protobuf.pm:159) and feeds the
/// full bytes to the prefix computation. ExifTool's prefix is `substr($buff, 0,
/// -6) . '_'` — it removes the LAST 6 BYTES (not the regex match), so a `.proto`
/// ending drops a clean `.proto` (e.g. `dvtm_X.proto` → `dvtm_X_`) but a
/// `.proto\n` ending drops `proto\n`, LEAVING the trailing `.` (e.g.
/// `dvtm_X.proto\n` → `dvtm_X._`). Such a trailing-`.` name is never a known DJI
/// protocol, so it flows through [`strip_and_lookup`] → `None` (the
/// stale-prefix-stopping sentinel) + the unknown-protocol warning — byte-for-byte
/// ExifTool's outcome (the `dvtm_X._<path>` table key matches no `%DJI::Protobuf`
/// row either). The `ends_with` checks are length-safe (false when the payload is
/// shorter than the 6- / 7-byte needle).
///
/// Line 157 fires UNCONDITIONALLY for every type-2 record matching `/\.proto$/`,
/// BEFORE the tag lookup, the `Unknown`-tag IsProtobuf gate (171-179), and the
/// SubDirectory/IsProtobuf recursion (227-237). Detection here and the recursion
/// in [`dispatch_record`] are INDEPENDENT and SEQUENTIAL: a record that both
/// matches `/\.proto$/` AND is a clean protobuf sub-message both switches the
/// prefix HERE and is descended into THERE. ExifTool overwrites `ProtoPrefix` to
/// the OUTER value, then recurses, and a deeper genuine `.proto` leaf overwrites
/// it again (last-wins, Protobuf.pm:159 `=`), so the net prefix is the deepest
/// leaf. The port mirrors that by switching unconditionally here and recursing
/// independently below — never suppressing the switch to keep an enclosing
/// message un-switched. (In real DJI the `.proto` leaf is a string field FOLLOWED
/// by serial/model fields in its container, so only the leaf's own bytes end in
/// `.proto` and the container does not — exactly one switch per genuine leaf.)
#[inline]
fn proto_suffix(payload: &[u8]) -> Option<&[u8]> {
  // Perl `/\.proto$/`: end-of-string OR before a SINGLE final `\n`. `ends_with`
  // is length-safe; `.proto\r\n` / `.proto\n\n` correctly miss both arms.
  (payload.ends_with(b".proto") || payload.ends_with(b".proto\n")).then_some(payload)
}

/// Record the verbatim `Protocol` value + OVERWRITE the persistent last-wins
/// track prefix when a `.proto` leaf is seen DURING the sequential walk
/// (Protobuf.pm:157-160), and switch the CURRENT dispatch table to it. Mirrors
/// ExifTool overwriting `$$et{ProtoPrefix}{$dirName}` then `HandleTag`-ing
/// `Protocol` AT THIS record's position — the new prefix governs every
/// subsequent record (and an earlier record already decoded under the prior
/// prefix). The three uses of "protocol" are kept distinct:
///  - `sample` gets the per-row emitted `Protocol` (`HandleTag`-when-seen, R2);
///  - `state.decode_prefix` is OVERWRITTEN last-wins (seeds the next sample's
///    decode IN THIS TRACK — Protobuf.pm:159 `=` assignment; per-track, R15-F2);
///  - `out.protocol` (the file-level model identity) + the unknown-protocol
///    warning are handled by [`record_protocol`] (first-wins identity, per-leaf
///    warning — both aggregate file-wide).
///
/// `payload` is the RAW protocol bytes (Protobuf.pm:157 matches on raw bytes —
/// no printable/UTF-8 gate). A protocol whose bytes are not valid UTF-8 cannot
/// be stored verbatim in the `SmolStr` surface, so it is rendered LOSSILY for
/// the `Protocol` tag (matching the project's lossy convention for non-UTF-8
/// stored strings). Such a name is never in `%knownProtocol`, so the lookup
/// below yields `None` — the unknown/sentinel state in which no subsequent
/// record decodes under any known path (and the unknown-protocol warning fires
/// via [`record_protocol`]). This is byte-identical to the existing handling of
/// a printable-but-unknown `dvtm_*.proto` name, whose table lookup is also
/// `None`.
///
/// `cur` is the in-flight protocol the walk threads through; `state` is the
/// per-track decode state whose `decode_prefix` (the lossy DISPLAY string) and
/// `raw_proto_prefix` (the byte-exact `ProtoPrefix` cache key) are BOTH overwritten
/// last-wins. The two are kept SEPARATE: the lossy display drives the `Protocol`
/// name + table lookup, while the raw bytes alone key the sticky cache — so a
/// non-UTF-8 prefix cannot collide via the replacement char, and `X..proto` vs
/// `X.proto\n` (distinct displays, identical raw `X._`) are bucketed as ExifTool
/// buckets them.
fn switch_protocol(
  payload: &[u8],
  cur: &mut Option<&'static Protocol>,
  state: &mut DjiTrackState,
  sample: &mut DjiTelemetrySample,
  out: &mut DjiProtobufMeta,
) {
  let rendered = match core::str::from_utf8(payload) {
    Ok(s) => SmolStr::new(s),
    Err(_) => SmolStr::new(String::from_utf8_lossy(payload)),
  };
  sample.set_protocol(Some(rendered.clone()));
  // Last-wins PER-TRACK decode prefix (seeds the NEXT data-only sample of this
  // track; never leaks to another track — R15-F2). Two faces of the same
  // overwrite: the lossy DISPLAY string and the byte-exact `ProtoPrefix` cache key.
  state.set_decode_prefix(rendered.clone());
  state.set_raw_proto_prefix(payload);
  // First-wins file-level model identity + per-leaf unknown-protocol warning.
  record_protocol(&rendered, out);
  // A UTF-8 KNOWN name resolves its table; any unknown name (printable-but-
  // unknown OR a lossily-rendered binary one, which can never match a known
  // protocol) yields `None` ⇒ the sentinel that stops decoding under the prior
  // prefix.
  *cur = strip_and_lookup(&rendered);
}

/// SINGLE sequential walk of a (possibly nested) protobuf message, mirroring
/// `ProcessProtobuf`'s one `for(;;)` loop (Protobuf.pm:151-238). `proto` is the
/// CURRENT dispatch table — it may be `None` (no protocol active yet, an empty
/// `$$et{ProtoPrefix}`) and is UPDATED in place the moment a `.proto` leaf is
/// reached, so records are decoded under the prefix ACTIVE AT THEIR POSITION.
///
/// On a truncated / bad-wire record the walk stops with a `Protobuf format
/// error` warning (Protobuf.pm:156) but KEEPS everything decoded before it —
/// the partial sample survives. `depth` panic-bounds nested recursion;
/// `fresh_prefix` is the analogue of `$prefix` being EMPTY (the top-level call
/// and a named-SubDirectory descent), gating the `Truncated protobuf data`
/// second warning (Protobuf.pm:278 `unless $prefix`).
// The walk threads the full decode context (data, dispatch table, path, depth,
// the fresh-prefix flag, the per-track state, the per-sample row, and the
// file-level aggregate) — one shared frame for the recursion, matching the
// project convention for the other deep walkers (quicktime_stream / gopro /
// flash all `#[allow]` this).
#[allow(clippy::too_many_arguments)]
fn walk(
  buff: &[u8],
  proto: &mut Option<&'static Protocol>,
  path: &mut alloc::vec::Vec<u64>,
  depth: u32,
  fresh_prefix: bool,
  state: &mut DjiTrackState,
  sample: &mut DjiTelemetrySample,
  out: &mut DjiProtobufMeta,
) {
  if depth >= MAX_WALK_DEPTH {
    return;
  }
  let mut rest = buff;
  while !rest.is_empty() {
    let (rec, next) = match read_tag(rest) {
      Ok(pair) => pair,
      Err(post_rest) => {
        // Truncated / malformed record (Protobuf.pm:156 `ReadRecord` failure):
        // `$self->Warn('Protobuf format error')` then `last` — STOP but keep
        // every record handled before this one (the partial sample survives).
        out.push_warning(crate::metadata::DjiWarning::new(
          SmolStr::new_static("Protobuf format error"),
          false,
        ));
        // Protobuf.pm:278 — AFTER the loop, `$et->Warn('Truncated protobuf data')
        // unless $prefix or $$dirInfo{Pos} == $dirEnd`. So the second warning
        // fires ONLY when (a) this `ProcessProtobuf` call has an EMPTY `$prefix`
        // (`fresh_prefix`) AND (b) the failed read left the cursor BEFORE the
        // buffer end (`Pos != dirEnd`). `post_rest` is `ReadRecord`'s post-failure
        // cursor (`Pos`); `!post_rest.is_empty()` ⟺ `Pos < dirEnd`. A failure that
        // consumes EXACTLY to EOF (`Pos == dirEnd` ⟺ `post_rest` empty — a
        // tag/value varint off the end, an at-EOF LEN length declaring a body with
        // 0 bytes left, or a wire-6/7 byte as the LAST byte) emits ONLY the format
        // error.
        //
        // `fresh_prefix` is the analogue of `$prefix` being EMPTY: it is `true`
        // for the TOP-LEVEL call AND for a NAMED `SubDirectory` descent — ExifTool
        // reaches a named SubDirectory via `HandleTag` → a FRESH `ProcessProtobuf`
        // with `$prefix` UNDEF (Protobuf.pm:227-228 falls through to the
        // SubDirectory handler, which starts the child table with no prefix), so a
        // truncation inside a named SubDirectory DOES emit `Truncated protobuf
        // data` (bundled-verified). It is `false` ONLY for the SPECULATIVE
        // `Unknown`-tag IsProtobuf recursion (Protobuf.pm:236), which passes
        // `$prefix = "$prefix$id-"` (truthy) — and which can never truncate
        // anyway, since it recurses ONLY into a payload `IsProtobuf` already proved
        // consumes EXACTLY (no leftover ⇒ no inner truncation).
        if fresh_prefix && !post_rest.is_empty() {
          out.push_warning(crate::metadata::DjiWarning::new(
            SmolStr::new_static("Truncated protobuf data"),
            false,
          ));
        }
        return;
      }
    };
    // A `.proto`-suffixed type-2 record UPDATES the active prefix HERE
    // (Protobuf.pm:157-160) — before its own tag is built and before any later
    // record is dispatched. The suffix is matched UNCONDITIONALLY on the RAW BYTES
    // (a binary `.proto` leaf switches the prefix too; no printable/IsProtobuf
    // condition). This fires BEFORE the `Unknown`-tag IsProtobuf recursion gate in
    // `dispatch_record` (the order of Protobuf.pm:157 vs :171-179) and is
    // INDEPENDENT of it: a record that both ends in `.proto` AND is a clean
    // protobuf sub-message both switches the prefix here and is descended into
    // below — ExifTool overwrites `ProtoPrefix` to this (outer) value, then
    // recurses, and a deeper genuine leaf overwrites it last-wins. DJI writes the
    // leaf at `1-1-1`, so this fires during the nested recursion at the correct
    // walk position.
    if rec.wire == WireType::Len
      && let Some(payload) = proto_suffix(rec.payload)
    {
      switch_protocol(payload, proto, state, sample, out);
    }
    // Dispatch the record at its path — INCLUDING an id-0, a huge, or an
    // overflowed-tag record (`field` is a `u64`, with FIELD_OVERFLOW_SENTINEL
    // for a tag varint that exceeded `u64`). `read_tag` is lenient (faithful to
    // `ReadRecord`, which caps neither the id nor the value's magnitude), so any
    // such record reaches here; no DJI table row contains a 0 / huge number ⇒
    // `field_for`/`is_branch` never match, a non-LEN one is a skipped unknown
    // tag, and a zero-length / printable LEN fails the speculative IsProtobuf
    // gate ⇒ skipped without recursing or warning. The record already advanced
    // the cursor above (its tag + payload), so subsequent telemetry continues to
    // decode (Protobuf.pm:152-178).
    path.push(rec.field);
    dispatch_record(&rec, proto, path, depth, state, sample, out);
    path.pop();
    if next.len() >= rest.len() {
      // No forward progress (should not happen — read_tag consumed ≥1 byte).
      break;
    }
    rest = next;
  }
}

/// Dispatch one record at the current `path` under the CURRENT protocol.
fn dispatch_record(
  rec: &Record<'_>,
  proto: &mut Option<&'static Protocol>,
  path: &mut alloc::vec::Vec<u64>,
  depth: u32,
  state: &mut DjiTrackState,
  sample: &mut DjiTelemetrySample,
  out: &mut DjiProtobufMeta,
) {
  // No active protocol (empty `$$et{ProtoPrefix}`) ⇒ no table key matches and
  // bundled extracts nothing under default options — but a deeper `.proto`
  // leaf may still switch us on, so recurse into nested messages regardless.
  let cur = *proto;
  // A known leaf field under the active protocol?
  if let Some(p) = cur
    && let Some(kind) = field_for(p, path)
  {
    apply_leaf(kind, rec, state, sample, out);
    return;
  }
  if rec.wire != WireType::Len {
    // A non-LEN unknown field (varint / fixed). Bundled extracts these only
    // under the Unknown option; the default gate discards them. Never recurse.
    return;
  }
  // A LEN field at a NAMED `SubDirectory` path in the ACTIVE protocol
  // (`DJI::FrameInfo`/`GPSInfo`/`DroneInfo`/`GimbalInfo`, DJI.pm:886-921).
  // ExifTool descends into a KNOWN SubDirectory UNCONDITIONALLY: the `$tagInfo`
  // carries a `SubDirectory`, so the type-2 handler falls straight through to
  // process it (Protobuf.pm:227-228) and the `Unknown`-tag IsProtobuf gate
  // (171-179) NEVER applies (a SubDirectory tag is not `Unknown`). So a corrupt
  // byte buried inside a named SubDirectory DOES surface a `Protobuf format
  // error` (bundled-verified), exactly as the unconditional `walk` here does.
  if let Some(p) = cur
    && is_branch(p, path)
    && p.is_named_subdir(path)
  {
    // Mavic4 / Mini5Pro `GPSInfo` arms set `$$self{CoordUnits} = 1` via a
    // SubDirectory `Condition` evaluated WHEN the GPSInfo message is reached
    // (DJI.pm:857/872) — i.e. BEFORE its child coordinates are handled, so a
    // child coordinate with no `CoordinateUnits` sibling still reads degrees.
    if p.forces_degrees_at(path) {
      state.set_coord_units(1);
    }
    // A named SubDirectory is a FRESH `ProcessProtobuf` (`$prefix` undef,
    // Protobuf.pm:227-228 → HandleTag → the child table started with no prefix),
    // so a truncation inside it CAN emit `Truncated protobuf data` ⇒ `fresh_prefix`.
    walk(
      rec.payload,
      proto,
      path,
      depth + 1,
      true,
      state,
      sample,
      out,
    );
    return;
  }
  // An UNKNOWN-to-the-table LEN field — one of:
  //  - an UNNAMED intermediate wrapper (a branch prefix that is NOT a named
  //    SubDirectory: the per-protocol `3` / `3-4` / `3-4-2` / `3-3-4` containers
  //    that PARENT a named SubDirectory and/or direct leaves but carry no
  //    `SubDirectory`/`Format` of their own);
  //  - a non-branch LEN under a known protocol (an unknown field);
  //  - any LEN while no protocol is active yet (a nested `.proto` leaf may still
  //    switch us on by descending).
  // ExifTool has NO `%DJI::Protobuf` row for such a path, so the tag is an
  // `Unknown` type-2 tag (AddTagToTable `{ Unknown => 1 }`, Protobuf.pm:168) and
  // descent is GATED by the IsProtobuf check (Protobuf.pm:171-179, :229), recurse
  // ONLY when the payload (a) contains a non-printable byte (`/[^\x20-\x7e]/`)
  // AND (b) parses cleanly as protobuf (`IsProtobuf`). A corrupt byte buried in
  // an unnamed wrapper makes (b) FALSE, so bundled SKIPS it WITHOUT a `Protobuf
  // format error` (bundled-verified) — unlike a named SubDirectory, which is
  // descended unconditionally above and DOES surface the error. This gate is
  // INDEPENDENT of the `.proto` protocol-switch in `walk` (that already ran
  // UNCONDITIONALLY on the raw bytes, Protobuf.pm:157, before this :171-179 gate):
  // a clean nested protobuf message that ALSO ends in `.proto` both switched the
  // prefix above AND is recursed here (a deeper genuine leaf overwrites
  // last-wins inside). A printable `.proto`/version string fails (a) ⇒ SKIP
  // SILENTLY; a non-printable payload that is NOT clean protobuf fails (b) ⇒
  // SKIP. This prevents a speculative descent into opaque/string/corrupt bytes
  // from surfacing a spurious `Protobuf format error` when fields are reordered
  // or a wrapper holds a stray byte.
  //
  // The (a)+(b) test is the FIRST evaluation of a path; ExifTool then STORES the
  // verdict on the `Unknown` tag's `$tagInfo` (keyed by the full tag string
  // `"$$et{ProtoPrefix}{$dirName}$prefix$id"`, Protobuf.pm:162) and reuses it
  // STICKILY for every later payload at that path (Protobuf.pm:171-179). So a
  // path proven protobuf once, then handed a CORRUPT payload, flips to
  // defined-false and SUPPRESSES all subsequent — even clean — payloads there
  // (`next unless $$tagInfo{IsProtobuf}`). [`DjiTrackState::unnamed_wrapper_should_recurse`]
  // applies that tri-state, keyed by `(active ProtoPrefix, full path)` (the RAW
  // last-wins `.proto` value — DISTINCT per known AND per unknown protocol, so a
  // sticky-`No` under one unknown `.proto` never suppresses a clean wrapper under
  // a DIFFERENT unknown `.proto`) and persisted for the track. The predicates are
  // NOT computed here: the method scans the payload LAZILY, ONLY in the branch
  // that needs it (Protobuf.pm:172 vs :174) — so a sticky-`No` path SHORT-CIRCUITS
  // with no payload scan (matching `next unless $$tagInfo{IsProtobuf}`, which
  // never calls `IsProtobuf` for a defined-false tag).
  if state.unnamed_wrapper_should_recurse(path, rec.payload) {
    // The SPECULATIVE `Unknown`-tag descent passes a TRUTHY `$prefix`
    // (`"$prefix$id-"`, Protobuf.pm:236), so `Truncated protobuf data` is
    // SUPPRESSED here ⇒ `fresh_prefix = false`. (`is_protobuf` already proved the
    // payload consumes EXACTLY, so an inner truncation cannot arise regardless.)
    walk(
      rec.payload,
      proto,
      path,
      depth + 1,
      false,
      state,
      sample,
      out,
    );
  }
}

/// Apply a known leaf field's value to the per-sample row / track identity AT
/// its sequential walk position. GPS coordinates are converted PER-LEAF using
/// the PER-TRACK `CoordUnits` state active right now (`state.coord_units()`),
/// matching ExifTool's per-leaf RawConv (DJI.pm:929/935). A `CoordinateUnits`
/// leaf updates that per-track state; identity/telemetry land on the per-sample
/// `sample` (+ first-wins identity on the file-level `out`).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn apply_leaf(
  kind: FieldKind,
  rec: &Record<'_>,
  state: &mut DjiTrackState,
  sample: &mut DjiTelemetrySample,
  out: &mut DjiProtobufMeta,
) {
  let s = &mut *sample;
  match kind {
    // ── Identity (LEN strings) — `HandleTag`-when-seen ──────────────────
    // ExifTool `HandleTag`s `SerialNumber`/`Model` at the position of the
    // sample whose records carry the `1-1-5`/`1-1-10` leaf (Protobuf.pm:162),
    // so the value lands under THAT sample's `Doc<N>`. Record it on the
    // per-sample row (drives `-ee` emission) AND first-wins onto the aggregate
    // (drives the track-wide `MediaMetadata` projection).
    FieldKind::SerialNumber => {
      if rec.wire == WireType::Len
        && let Ok(v) = core::str::from_utf8(rec.payload)
      {
        s.set_serial_number(Some(SmolStr::new(v)));
        if out.serial_number().is_none() {
          out.set_serial_number(SmolStr::new(v));
        }
      }
    }
    FieldKind::SerialNumber2 => {
      // `2-2-3-1` SerialNumber2 (AVATA2 / DJI Neo, DJI.pm:399/553) — a NAMED tag
      // with no `Format`, decoded as a plain ASCII string exactly like
      // SerialNumber (Protobuf.pm:239-256). `HandleTag`-when-seen on the
      // per-sample row; there is no track-level SerialNumber2 aggregate identity.
      if rec.wire == WireType::Len
        && let Ok(v) = core::str::from_utf8(rec.payload)
      {
        s.set_serial_number_2(Some(SmolStr::new(v)));
      }
    }
    FieldKind::Model => {
      if rec.wire == WireType::Len
        && let Ok(v) = core::str::from_utf8(rec.payload)
      {
        s.set_model(Some(SmolStr::new(v)));
        if out.model().is_none() {
          out.set_model(SmolStr::new(v));
        }
      }
    }
    // ── Capture settings ────────────────────────────────────────────────
    FieldKind::Iso => {
      // Format => 'float' (I32). Stored as f64.
      if let Some(f) = float_value(rec) {
        s.set_iso(Some(f64::from(f)));
      }
    }
    FieldKind::ShutterSpeed => {
      // Protobuf.pm:201-205: a `Format == 'rational'` LEN field is ALWAYS
      // HandleTag'd — with the quotient, or the literal `'err'` for a
      // zero/missing denominator (or missing numerator). So set the value
      // unconditionally for a LEN record (Num or Err); only a non-LEN wire type
      // (which DJI never writes for a rational) decodes nothing.
      if rec.wire == WireType::Len {
        s.set_shutter_speed_s(Some(decode_rational(rec.payload)));
      }
    }
    FieldKind::FNumber => {
      if rec.wire == WireType::Len {
        s.set_f_number(Some(decode_rational(rec.payload)));
      }
    }
    FieldKind::ColorTemperature => {
      // Format => 'unsigned' (VARINT). Kelvin. The typed surface narrows the
      // `u64` varint to `u32`; an absurd `> u32::MAX` value (#221 item-4) is
      // DELIBERATELY DROPPED (`u32::try_from(..).ok()` → None), NOT truncated to
      // a wrong low-32-bit value. ExifTool emits the full `u64`, but such a Kelvin
      // is physically impossible; a real ColorTemperature is a few thousand. Same
      // narrowing applies to FrameWidth/FrameHeight below.
      if let Some(v) = varint_value(rec) {
        s.set_color_temperature(u32::try_from(v).ok());
      }
    }
    FieldKind::DigitalZoom => {
      if let Some(f) = float_value(rec) {
        s.set_digital_zoom(Some(f64::from(f)));
      }
    }
    FieldKind::Temperature => {
      if let Some(f) = float_value(rec) {
        s.set_temperature_c(Some(f64::from(f)));
      }
    }
    // ── Altitude ────────────────────────────────────────────────────────
    FieldKind::AbsoluteAltitude => {
      // Format => 'int64s', ValueConv => '$val / 1000'.
      if let Some(v) = varint_value(rec) {
        let metres = decode_int64s(v) / 1000.0;
        s.set_absolute_altitude_m(Some(metres));
        // Emitted under the `AbsoluteAltitude` NAME (PER-SAMPLE, from THIS leaf's
        // kind — not the aggregate protocol; a mid-track switch can mix names).
        s.set_altitude_is_gps_named(Some(false));
      }
    }
    FieldKind::GpsAltitude => {
      // Format => 'unsigned', ValueConv => '$val / 1000' — a PLAIN varint
      // (ac203/ac204/ac206), NOT the int64s hack. Identical to
      // AbsoluteAltitude for real altitudes; differs only on a hostile
      // varint ≥ INT64S_MIN. Stored on the same typed field.
      if let Some(v) = varint_value(rec) {
        #[allow(clippy::cast_precision_loss)]
        let metres = v as f64 / 1000.0;
        s.set_absolute_altitude_m(Some(metres));
        // Emitted under the `GPSAltitude` NAME (PER-SAMPLE, from THIS leaf).
        s.set_altitude_is_gps_named(Some(true));
      }
    }
    FieldKind::RelativeAltitude => {
      // Format => 'float', ValueConv => '$val / 1000'.
      if let Some(f) = float_value(rec) {
        s.set_relative_altitude_m(Some(f64::from(f) / 1000.0));
      }
    }
    // ── Time ────────────────────────────────────────────────────────────
    FieldKind::GpsDateTime => {
      // Format => 'string', ValueConv => '$val =~ tr/-/:/' (DJI.pm:305).
      if rec.wire == WireType::Len
        && let Ok(v) = core::str::from_utf8(rec.payload)
      {
        let converted: String = v.chars().map(|c| if c == '-' { ':' } else { c }).collect();
        s.set_gps_date_time(Some(SmolStr::new(converted)));
      }
    }
    FieldKind::FrameNumber => {
      // `3-1-1` FrameNumber, Format => 'unsigned' (VARINT), no conversions
      // (DJI.pm:279 etc.). Per-frame counter — kept as the raw `u64`.
      if let Some(v) = varint_value(rec) {
        s.set_frame_number(Some(v));
      }
    }
    FieldKind::TimeStamp => {
      // Format => 'unsigned' (VARINT). Raw microsecond counter (bundled
      // divides by 1e6 for display; the typed surface keeps the raw value).
      if let Some(v) = varint_value(rec) {
        s.set_time_stamp_us(Some(v));
      }
    }
    // ── Frame info ──────────────────────────────────────────────────────
    FieldKind::FrameWidth => {
      // FrameInfo.FrameWidth (unsigned VARINT). A `> u32::MAX` value (#221
      // item-4) is DELIBERATELY DROPPED by the `u32` narrowing (impossible real
      // dimension), NOT truncated — see ColorTemperature.
      if let Some(v) = varint_value(rec) {
        s.set_frame_width(u32::try_from(v).ok());
      }
    }
    FieldKind::FrameHeight => {
      // As FrameWidth: a `> u32::MAX` FrameHeight is dropped (#221 item-4).
      if let Some(v) = varint_value(rec) {
        s.set_frame_height(u32::try_from(v).ok());
      }
    }
    FieldKind::FrameRate => {
      if let Some(f) = float_value(rec) {
        s.set_frame_rate(Some(f64::from(f)));
      }
    }
    // ── GPS triple (converted PER-LEAF at walk position) ────────────────
    FieldKind::CoordinateUnits => {
      // DJI.pm:922 `$$self{CoordUnits} = $val; undef` — UPDATE the persistent
      // PER-TRACK units state when this leaf is handled (not surfaced as a tag).
      // A later coordinate sibling reads it; an EARLIER coordinate already
      // converted under the prior state. Never inherited by another track
      // (R15-F2).
      if let Some(v) = varint_value(rec) {
        state.set_coord_units(v);
      }
    }
    FieldKind::GpsLatitude => {
      // DJI.pm:929 — convert HERE using the per-track `$$self{CoordUnits}` as it
      // stands at this leaf's position (radians→degrees unless units is truthy).
      if let Some(d) = double_value(rec) {
        s.set_latitude(Some(coord_to_degrees(d, state.coord_units())));
      }
    }
    FieldKind::GpsLongitude => {
      // DJI.pm:935 — same per-leaf conversion as GPSLatitude.
      if let Some(d) = double_value(rec) {
        s.set_longitude(Some(coord_to_degrees(d, state.coord_units())));
      }
    }
    // ── Drone orientation (int64s / 10) ─────────────────────────────────
    FieldKind::DroneRoll => {
      if let Some(v) = varint_value(rec) {
        s.set_drone_roll_deg(Some(decode_int64s(v) / 10.0));
      }
    }
    FieldKind::DronePitch => {
      if let Some(v) = varint_value(rec) {
        s.set_drone_pitch_deg(Some(decode_int64s(v) / 10.0));
      }
    }
    FieldKind::DroneYaw => {
      if let Some(v) = varint_value(rec) {
        s.set_drone_yaw_deg(Some(decode_int64s(v) / 10.0));
      }
    }
    // ── Gimbal orientation (int64s / 10) ────────────────────────────────
    FieldKind::GimbalPitch => {
      if let Some(v) = varint_value(rec) {
        s.set_gimbal_pitch_deg(Some(decode_int64s(v) / 10.0));
      }
    }
    FieldKind::GimbalRoll => {
      if let Some(v) = varint_value(rec) {
        s.set_gimbal_roll_deg(Some(decode_int64s(v) / 10.0));
      }
    }
    FieldKind::GimbalYaw => {
      if let Some(v) = varint_value(rec) {
        s.set_gimbal_yaw_deg(Some(decode_int64s(v) / 10.0));
      }
    }
  }
}

/// Read a `Format => 'float'` value. DJI always writes these as I32 (wire
/// type 5). Returns `None` for any other wire type.
#[inline]
fn float_value(rec: &Record<'_>) -> Option<f32> {
  if rec.wire == WireType::I32 {
    decode_float(rec.payload)
  } else {
    None
  }
}

/// Read a `Format => 'double'` value. DJI always writes these as I64 (wire
/// type 1).
#[inline]
fn double_value(rec: &Record<'_>) -> Option<f64> {
  if rec.wire == WireType::I64 {
    decode_double(rec.payload)
  } else {
    None
  }
}

/// The `u64` value of a VARINT record, or `None` when the record is not a
/// VARINT or its value OVERFLOWED `u64` (a well-formed but `> u64::MAX` varint —
/// hostile/non-real input). A known numeric leaf uses this so an overflowed
/// value is SKIPPED rather than misrepresented: Perl would carry the lossy
/// double through the `/1000`÷`/10` ValueConv, but rather than fabricate that
/// (or a NaN), the field is dropped and the walk continues to later records.
/// The cursor already advanced past the varint in [`read_tag`].
#[inline]
fn varint_value(rec: &Record<'_>) -> Option<u64> {
  if rec.wire == WireType::Varint && !rec.varint_overflow {
    Some(rec.varint)
  } else {
    None
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  // The parent `formats` module sets `#![deny(clippy::indexing_slicing)]`
  // (formats/mod.rs) for parser panic-safety; in test code a `samples()[0]` /
  // `w[0]` index is a fixed-shape assertion where a panic IS the intended test
  // failure, so allow raw indexing throughout the test module (mirrors
  // `formats/xmp.rs`'s test-only allow).
  #![allow(clippy::indexing_slicing)]

  use super::*;

  extern crate alloc;
  use alloc::vec::Vec;

  // ── wire-format encoders (test helpers) ──────────────────────────────
  fn enc_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
      let mut b = (v & 0x7f) as u8;
      v >>= 7;
      if v != 0 {
        b |= 0x80;
      }
      out.push(b);
      if v == 0 {
        break;
      }
    }
    out
  }
  fn tag(field: u32, wire: u8) -> Vec<u8> {
    enc_varint((u64::from(field) << 3) | u64::from(wire))
  }
  fn rec_varint(field: u32, v: u64) -> Vec<u8> {
    let mut o = tag(field, 0);
    o.extend(enc_varint(v));
    o
  }
  fn rec_i64(field: u32, v: f64) -> Vec<u8> {
    let mut o = tag(field, 1);
    o.extend_from_slice(&v.to_le_bytes());
    o
  }
  fn rec_i32(field: u32, v: f32) -> Vec<u8> {
    let mut o = tag(field, 5);
    o.extend_from_slice(&v.to_le_bytes());
    o
  }
  fn rec_len(field: u32, body: &[u8]) -> Vec<u8> {
    let mut o = tag(field, 2);
    o.extend(enc_varint(body.len() as u64));
    o.extend_from_slice(body);
    o
  }
  fn rec_str(field: u32, s: &str) -> Vec<u8> {
    rec_len(field, s.as_bytes())
  }
  fn rec_rational(field: u32, num: u64, den: u64) -> Vec<u8> {
    let mut body = enc_varint(num);
    body.extend(enc_varint(den));
    rec_len(field, &body)
  }
  /// Wrap children into a nested LEN message at `field`.
  fn nest(field: u32, children: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for c in children {
      body.extend_from_slice(c);
    }
    rec_len(field, &body)
  }

  /// The FAITHFUL DJI protocol-identity block `1-1` = `{ 1-1-1: name (the
  /// `.proto` leaf), 1-1-5: serial }`. The trailing SerialNumber field means
  /// neither the `1-1` container nor the enclosing `1` record ends in the bytes
  /// `.proto` — only the leaf's OWN bytes do — so ExifTool's line-157 switch
  /// (`$buff =~ /\.proto$/`, raw-byte, unconditional) fires EXACTLY ONCE, on the
  /// genuine leaf. This mirrors real DJI, where the `.proto` string at `1-1-1` is
  /// followed by serial/model fields in its container. (The bare
  /// `nest(1,&[nest(1,&[rec_str(1,name)])])` shape is NON-faithful: the leaf is
  /// the container's LAST field, so the container bytes ALSO end in `.proto` and
  /// ExifTool fires the switch on every enclosing message too — overwriting
  /// ProtoPrefix to garbage and warning — verified against
  /// `Image::ExifTool::Protobuf::ProcessProtobuf`.)
  fn proto_block(name: &str) -> Vec<u8> {
    nest(1, &[nest(1, &[rec_str(1, name), rec_str(5, "SERIAL123")])])
  }

  // ── read_varint ───────────────────────────────────────────────────────
  /// Destructure a [`VarintRead::Value`] in a test, panicking on any other
  /// outcome (the old `.unwrap()` on the pre-refactor `Option` tuple).
  fn unwrap_value(r: VarintRead<'_>) -> (u64, bool, &[u8]) {
    match r {
      VarintRead::Value(v, bit0, rest) => (v, bit0, rest),
      VarintRead::Overflow { .. } => panic!("expected Value, got Overflow"),
      VarintRead::Truncated { .. } => panic!("expected Value, got Truncated"),
    }
  }

  #[test]
  fn varint_single_byte() {
    let (v, bit0, rest) = unwrap_value(read_varint(&[0x01]));
    assert_eq!(v, 1);
    assert!(bit0);
    assert!(rest.is_empty());
  }

  #[test]
  fn varint_zero() {
    let (v, bit0, _) = unwrap_value(read_varint(&[0x00]));
    assert_eq!(v, 0);
    assert!(!bit0);
  }

  #[test]
  fn varint_multi_byte_300() {
    // 300 = 0b100101100 → bytes 0xAC 0x02 (protobuf.dev canonical example).
    let (v, _, rest) = unwrap_value(read_varint(&[0xac, 0x02]));
    assert_eq!(v, 300);
    assert!(rest.is_empty());
  }

  #[test]
  fn varint_max_u64() {
    let enc = enc_varint(u64::MAX);
    let (v, _, _) = unwrap_value(read_varint(&enc));
    assert_eq!(v, u64::MAX);
  }

  #[test]
  fn varint_truncated_continuation_is_truncated() {
    // Continuation bit set but no following byte ⇒ a byte runs off the end ⇒
    // VarInt undef ⇒ Truncated (the fatal case). The cursor (`rest`) is at the
    // buffer end — Perl's failed GetBytes leaves Pos there.
    match read_varint(&[0x80]) {
      VarintRead::Truncated { rest } => assert!(rest.is_empty(), "off-end ⇒ cursor at end"),
      other => panic!("expected Truncated, got {other:?}"),
    }
  }

  #[test]
  fn varint_empty_is_truncated() {
    // GetBytes off the end on the very first byte ⇒ VarInt undef ⇒ Truncated.
    match read_varint(&[]) {
      VarintRead::Truncated { rest } => assert!(rest.is_empty()),
      other => panic!("expected Truncated, got {other:?}"),
    }
  }

  #[test]
  fn varint_runs_off_end_is_truncated() {
    // 11 continuation bytes with NO terminator: the read runs off the buffer
    // end (well before the ~33-continuation bound) ⇒ Truncated, cursor at end.
    let bad = [0x80u8; 11];
    match read_varint(&bad) {
      VarintRead::Truncated { rest } => assert!(rest.is_empty()),
      other => panic!("expected Truncated, got {other:?}"),
    }
  }

  #[test]
  fn varint_over_u64_is_overflow_not_truncated() {
    // RE-DERIVED (pre-refactor this returned None). A 10-byte varint whose 10th
    // (terminating) byte carries a payload > 1 is WELL-FORMED (terminator within
    // the continuation bound) but its value exceeds u64 — bit 1 of the 10th byte
    // would land at bit 64. ExifTool does NOT fail on magnitude (it folds the
    // value into a lossy double and advances Pos), so this is Overflow, NOT
    // Truncated: the cursor advances past the whole varint and bit0/low3 stay
    // available. 9 leading 0x80 (payload 0, low3 == 0) then a terminating 0x02.
    let mut over = std::vec![0x80u8; 9];
    over.push(0x02);
    over.push(0xAA); // a trailing byte to prove the cursor advanced PAST the varint
    match read_varint(&over) {
      VarintRead::Overflow { low3, rest } => {
        assert_eq!(low3, 0, "low3 = first byte (0x80) & 0x07 = 0");
        assert_eq!(rest, &[0xAA], "the cursor advanced past the 10-byte varint");
      }
      other => panic!("expected Overflow, got {other:?}"),
    }
    // The boundary case — a 10-byte varint encoding exactly u64::MAX (10th byte
    // payload == 1) — still decodes losslessly as a Value (NOT Overflow).
    let max = enc_varint(u64::MAX);
    assert_eq!(max.len(), 10, "u64::MAX is a 10-byte varint");
    assert_eq!(*max.last().unwrap() & 0x7f, 1, "its 10th byte payload is 1");
    let (v, _, rest) = unwrap_value(read_varint(&max));
    assert_eq!(v, u64::MAX);
    assert!(rest.is_empty());
  }

  #[test]
  fn varint_overflow_preserves_bit0() {
    // bit0 must remain extractable on Overflow (the zig-zag `signed` decode of a
    // > i64 value needs it). A 10-byte varint whose FIRST byte is 0x81 (bit0 set)
    // and whose 10th byte payload is 2 (over u64): Overflow with low3 carrying
    // bit0. 0x81 then 8×0x80 then 0x02.
    let mut over = std::vec![0x81u8];
    over.extend(std::iter::repeat_n(0x80u8, 8));
    over.push(0x02);
    match read_varint(&over) {
      VarintRead::Overflow { low3, rest } => {
        assert_eq!(low3 & 0x01, 0x01, "bit0 (0x81 & 1) survives on Overflow");
        assert!(rest.is_empty(), "cursor consumed the whole 10-byte varint");
      }
      other => panic!("expected Overflow, got {other:?}"),
    }
  }

  #[test]
  fn varint_continuation_bound_matches_perl_plus_minus_one() {
    // A byte-exact check of the `++$i > 32` bound (Protobuf.pm:67), verified
    // against a direct VarInt trace: 33 leading 0x80 continuation bytes + a
    // terminator (34 bytes) is WELL-FORMED, but 34 leading 0x80 + a terminator
    // (35 bytes) trips the continuation bound ⇒ Truncated (the fatal `return
    // undef`). To keep the within-bound case a genuine `> u64` (NOT a merely
    // zero-extended 0 — which F2 decodes to `Value(0)`, covered separately),
    // the terminator carries a NONZERO high payload (0x7f at shift 33×7=231),
    // so a set bit lands far past bit 63 ⇒ Overflow.
    let mut ok = std::vec![0x80u8; 33];
    ok.push(0x7f);
    assert!(
      matches!(read_varint(&ok), VarintRead::Overflow { .. }),
      "33 continuation bytes + a nonzero terminator is within the bound (well-formed, > u64)"
    );
    // Over the bound is Truncated regardless of payload (zero OR nonzero).
    let mut bad = std::vec![0x80u8; 34];
    bad.push(0x00);
    assert!(
      matches!(read_varint(&bad), VarintRead::Truncated { .. }),
      "34 continuation bytes trips `++$i > 32` ⇒ fatal Truncated"
    );
  }

  // ── read_tag ────────────────────────────────────────────────────────
  #[test]
  fn tag_decode_varint_record() {
    let buf = rec_varint(5, 42);
    let (rec, rest) = read_tag(&buf).unwrap();
    assert_eq!(rec.field, 5);
    assert_eq!(rec.wire, WireType::Varint);
    assert_eq!(rec.varint, 42);
    assert!(rest.is_empty());
  }

  #[test]
  fn tag_decode_len_record() {
    let buf = rec_str(10, "FC8482");
    let (rec, _) = read_tag(&buf).unwrap();
    assert_eq!(rec.field, 10);
    assert_eq!(rec.wire, WireType::Len);
    assert_eq!(rec.payload, b"FC8482");
  }

  #[test]
  fn tag_decode_i64_and_i32() {
    let b64 = rec_i64(1, 1.5);
    let (r64, _) = read_tag(&b64).unwrap();
    assert_eq!(r64.wire, WireType::I64);
    assert_eq!(decode_double(r64.payload), Some(1.5));
    let b32 = rec_i32(2, 2.5);
    let (r32, _) = read_tag(&b32).unwrap();
    assert_eq!(r32.wire, WireType::I32);
    assert_eq!(decode_float(r32.payload), Some(2.5));
  }

  #[test]
  fn tag_field_zero_is_read() {
    // `ReadRecord` is LENIENT: it never rejects field number 0 (Protobuf.pm:
    // 86-88 set `$id = $val >> 3` with no id-0 guard). So an id-0 record READS
    // fine and the caller skips it as an unknown tag — `read_tag` must return it,
    // NOT `None`. (Pre-R10 the port rejected field 0, which made a benign id-0
    // padding record fatally abort the walk.)
    // tag byte 0x02 = field 0, wire 2 (zero-length LEN), 0x00 = len 0.
    let (rec, rest) = read_tag(&[0x02, 0x00]).expect("id-0 record reads, not None");
    assert_eq!(rec.field, 0, "id-0 record carries field 0");
    assert_eq!(rec.wire, WireType::Len);
    assert!(rec.payload.is_empty(), "zero-length LEN ⇒ empty payload");
    assert!(
      rest.is_empty(),
      "the 2-byte record consumes the buffer exactly"
    );
    // tag byte 0x00 = field 0, wire 0 (VARINT), 0x00 = value 0.
    let (rec2, rest2) = read_tag(&[0x00, 0x00]).expect("id-0 varint reads, not None");
    assert_eq!(rec2.field, 0);
    assert_eq!(rec2.wire, WireType::Varint);
    assert_eq!(rec2.varint, 0);
    assert!(rest2.is_empty());
  }

  #[test]
  fn tag_oversized_len_is_err() {
    // field 1, wire 2, len 200 but no body. `GetBytes(200)` fails WITHOUT
    // advancing `Pos`, which is already at EOF after the length varint ⇒ the
    // post-failure cursor is EMPTY (`Pos == dirEnd`) — verified against a perl
    // `ReadRecord` trace (Pos=end). So a TOP-LEVEL such failure emits ONLY the
    // format error, never `Truncated protobuf data`.
    let mut buf = tag(1, 2);
    buf.extend(enc_varint(200));
    let post = read_tag(&buf).expect_err("len>remaining ⇒ Err");
    assert!(
      post.is_empty(),
      "the length varint ended at EOF ⇒ Pos == dirEnd"
    );
  }

  #[test]
  fn tag_truncated_i64_is_err() {
    // field 1, wire 1 (I64), but only 3 of 8 body bytes. `GetBytes(8)` fails
    // WITHOUT advancing `Pos` (Protobuf.pm:43-44 advances only on success), so
    // `Pos` stays right after the tag varint — the 3 leftover bytes (verified
    // against perl: Pos=1, remaining=3). The post-failure cursor is NON-EMPTY
    // (`Pos < dirEnd`) ⇒ a TOP-LEVEL such failure emits BOTH warnings.
    let mut buf = tag(1, 1);
    buf.extend_from_slice(&[0, 0, 0]); // only 3 of 8 bytes
    let post = read_tag(&buf).expect_err("truncated I64 body ⇒ Err");
    assert_eq!(
      post,
      &[0, 0, 0],
      "Pos stays after the tag (GetBytes didn't advance)"
    );
  }

  // ── decode_int64s (the DJI hack) ────────────────────────────────────
  #[test]
  fn int64s_small_positive_passthrough() {
    assert_eq!(decode_int64s(105_500), 105_500.0);
  }

  #[test]
  fn int64s_dji_negative_hack() {
    // -1 stored improperly as 0xffffffffffffffff.
    assert_eq!(decode_int64s(0xffff_ffff_ffff_ffff), -1.0);
    // -1000 stored as 0xfffffffffffffc18.
    assert_eq!(decode_int64s(0xffff_ffff_ffff_fc18), -1000.0);
  }

  #[test]
  fn int64s_boundary_at_min() {
    // exactly INT64S_MIN → 0 - 0x100000000 = -4294967296.
    assert_eq!(decode_int64s(INT64S_MIN), -4_294_967_296.0);
  }

  #[test]
  fn int64s_below_hack_threshold_keeps_unsigned_magnitude() {
    // A varint with the high bit set but BELOW INT64S_MIN
    // (`[2^63, 0xffffffff00000000)`) is NOT the DJI hack: ExifTool leaves
    // `$val` as the unsigned magnitude (a huge POSITIVE double), it does NOT
    // wrap negative. `0x8000000000000000` = 2^63.
    let v = decode_int64s(0x8000_0000_0000_0000);
    assert_eq!(v, 9_223_372_036_854_775_808.0, "2^63 stays a huge positive");
    assert!(
      v > 0.0,
      "below INT64S_MIN ⇒ unsigned magnitude, NOT negative"
    );
    // Just under INT64S_MIN is still positive (the hack starts AT INT64S_MIN).
    let just_under = decode_int64s(INT64S_MIN - 1);
    assert!(
      just_under > 0.0,
      "INT64S_MIN-1 is below the hack ⇒ huge positive, got {just_under}"
    );
  }

  #[test]
  fn int64s_hack_range_is_small_negative() {
    // A varint AT/ABOVE INT64S_MIN fires the hack → a small negative
    // (`$val - 2^64`). 0xffffffffffffff38 = 2^64 - 200 ⇒ -200; ÷1000 = -0.2.
    let v = decode_int64s(0xffff_ffff_ffff_ff38);
    assert_eq!(v, -200.0, "hack range ⇒ small negative");
    assert_eq!(
      v / 1000.0,
      -0.2,
      "÷1000 matches ExifTool's AbsoluteAltitude"
    );
  }

  #[test]
  fn int64s_normal_value_exact() {
    // A real altitude varint (well below 2^53) is exact through ÷1000.
    assert_eq!(decode_int64s(123_456) / 1000.0, 123.456);
  }

  // ── decode_rational ─────────────────────────────────────────────────
  #[test]
  fn rational_basic() {
    let body = {
      let mut b = enc_varint(1);
      b.extend(enc_varint(250));
      b
    };
    assert_eq!(decode_rational(&body), RationalValue::Num(1.0 / 250.0));
  }

  #[test]
  fn decode_rational_zero_denominator_is_err() {
    // Protobuf.pm:205 `$val = (defined $num and $den) ? $num/$den : 'err'`:
    // `den == 0` is Perl-false ⇒ the literal `'err'` (RationalValue::Err), which
    // STILL emits a tag — NOT a dropped/absent value.
    let body = {
      let mut b = enc_varint(1);
      b.extend(enc_varint(0));
      b
    };
    assert_eq!(
      decode_rational(&body),
      RationalValue::Err,
      "den==0 ⇒ ExifTool 'err', not dropped"
    );
  }

  #[test]
  fn decode_rational_missing_numerator_is_err() {
    // `$num` undef (empty payload — `VarInt` returns undef) ⇒ 'err'.
    assert_eq!(
      decode_rational(&[]),
      RationalValue::Err,
      "missing numerator ⇒ 'err'"
    );
    // `$num` present but `$den` missing (truncated payload) ⇒ `$den` undef
    // (Perl-false) ⇒ 'err'.
    let num_only = enc_varint(1);
    assert_eq!(
      decode_rational(&num_only),
      RationalValue::Err,
      "missing denominator ⇒ 'err'"
    );
  }

  // ── protocol + field lookup ──────────────────────────────────────────
  #[test]
  fn protocol_lookup_known() {
    assert!(protocol_for("dvtm_ac203").is_some());
    assert!(protocol_for("dvtm_wm265e").is_some());
    assert!(protocol_for("dvtm_NOT_REAL").is_none());
  }

  #[test]
  fn all_protocol_tables_sorted() {
    // Binary search requires path-sorted rows.
    for p in PROTOCOLS {
      for w in p.rows.windows(2) {
        assert!(
          w[0].path < w[1].path,
          "protocol {} rows not sorted: {:?} !< {:?}",
          p.name,
          w[0].path,
          w[1].path
        );
      }
    }
  }

  #[test]
  fn field_lookup_ac203_gps_altitude() {
    let p = protocol_for("dvtm_ac203").unwrap();
    // ac203 `3-4-2-2` is the `GPSAltitude` (unsigned) leaf, NOT the int64s
    // `AbsoluteAltitude` (FIX 2 / DJI.pm:296-301).
    assert_eq!(field_for(p, &[3, 4, 2, 2]), Some(FieldKind::GpsAltitude));
    assert_eq!(field_for(p, &[1, 1, 10]), Some(FieldKind::Model));
    assert!(field_for(p, &[9, 9, 9]).is_none());
    // oq101 keeps the int64s `AbsoluteAltitude` at the same path (DJI.pm:700).
    let oq = protocol_for("dvtm_oq101").unwrap();
    assert_eq!(
      field_for(oq, &[3, 4, 2, 2]),
      Some(FieldKind::AbsoluteAltitude)
    );
  }

  #[test]
  fn branch_detection() {
    let p = protocol_for("dvtm_ac203").unwrap();
    // 3-4-2 is the parent of 3-4-2-2 (GPSAltitude) and 3-4-2-1 (GPSInfo).
    assert!(is_branch(p, &[3, 4, 2]));
    // 1-1-10 (Model) is a leaf, not a branch.
    assert!(!is_branch(p, &[1, 1, 10]));
  }

  // ── full sample happy paths ──────────────────────────────────────────
  #[test]
  fn djmd_mavic3_identity_and_gps() {
    // dvtm_wm265e: Protocol(1-1-1) string, SerialNumber 1-1-5, Model 1-1-10,
    // GPSInfo at 3-3-4-1 (CoordinateUnits + lat/lon), AbsoluteAltitude 3-3-4-2.
    // The `1-1` message carries proto (1-1-1), serial (1-1-5), model (1-1-10).
    let lvl11_body = {
      let mut v = Vec::new();
      v.extend(rec_str(1, "dvtm_wm265e.proto"));
      v.extend(rec_str(5, "SERIAL123"));
      v.extend(rec_str(10, "FC8482"));
      v
    };
    let lvl1 = nest(1, &[rec_len(1, &lvl11_body)]);

    // GPSInfo nested: CoordinateUnits=1 (degrees), lat=45.0, lon=8.0.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // GPSLatitude
      v.extend(rec_i64(3, 8.0)); // GPSLongitude
      v
    };
    // 3-3-4: contains 4-1 (GPSInfo) and 4-2 (AbsoluteAltitude).
    let lvl334 = {
      let mut v = Vec::new();
      v.extend(nest(1, &[gps_info])); // 3-3-4-1 GPSInfo
      v.extend(rec_varint(2, 105_500)); // 3-3-4-2 AbsoluteAltitude (105.5 m)
      v
    };
    let lvl33 = nest(3, &[nest(4, &[lvl334])]); // 3-3 -> 4 -> {...}
    let lvl3 = nest(3, &[lvl33]);

    let mut buf = Vec::new();
    buf.extend(lvl1);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(out.serial_number(), Some("SERIAL123"));
    assert_eq!(out.model(), Some("FC8482"));
    assert!(out.first_warning().is_none(), "wm265e is a known protocol");
    let s = out.first_fix().expect("a GPS fix");
    assert_eq!(s.latitude(), Some(45.0));
    assert_eq!(s.longitude(), Some(8.0));
    assert_eq!(s.absolute_altitude_m(), Some(105.5));
  }

  #[test]
  fn emit_dji_absolute_altitude_high_bit_varint() {
    // A wm265e AbsoluteAltitude (int64s `3-3-4-2`) whose varint sits in
    // `[2^63, INT64S_MIN)` — the high bit is set but it is BELOW the DJI-hack
    // threshold, so ExifTool keeps the UNSIGNED magnitude (a huge POSITIVE
    // double) rather than wrapping it negative. ÷1000 then yields a huge
    // positive altitude; the `as i64` pre-fix model produced a NEGATIVE here.
    let raw: u64 = 0x8000_0000_0000_0000; // 2^63 — below INT64S_MIN
    let expected = (raw as f64) / 1000.0; // huge POSITIVE metres (finite)
    assert!(expected > 0.0 && expected.is_finite());
    // wm265e: GPSInfo at 3-3-4-1 (so the projection has a fix) + AbsoluteAltitude
    // at 3-3-4-2 carrying the high-bit varint.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // GPSLatitude
      v.extend(rec_i64(3, 8.0)); // GPSLongitude
      v
    };
    let lvl334 = {
      let mut v = Vec::new();
      v.extend(nest(1, &[gps_info])); // 3-3-4-1 GPSInfo
      v.extend(rec_varint(2, raw)); // 3-3-4-2 AbsoluteAltitude (high-bit varint)
      v
    };
    let lvl3 = nest(3, &[nest(3, &[nest(4, &[lvl334])])]);
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = &out.samples()[0];
    // It is the int64s `AbsoluteAltitude` leaf (NOT the GPSAltitude unsigned name).
    assert_eq!(s.altitude_is_gps_named(), Some(false));
    assert_eq!(
      s.absolute_altitude_m(),
      Some(expected),
      "high-bit-but-below-hack varint keeps ExifTool's POSITIVE magnitude"
    );
    assert!(
      s.absolute_altitude_m().is_some_and(|a| a > 0.0),
      "the sign matches ExifTool (positive), NOT an i64-wrap negative"
    );
    // The projection altitude carries the same huge positive (finite ⇒ no NaN/inf).
    let mut md = crate::metadata::MediaMetadata::new();
    out.project_into(&mut md);
    let gps = md.gps().expect("a GPS fix projects");
    assert_eq!(gps.altitude_m(), Some(expected));
  }

  #[test]
  fn djmd_radians_converted_to_degrees() {
    // Action 4 (dvtm_ac203): GPSInfo at 3-4-2-1, no CoordinateUnits ⇒ radians.
    // lat = 0.7853981633974483 rad (π/4) → 45°.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_i64(2, core::f64::consts::FRAC_PI_4)); // lat π/4 rad
      v.extend(rec_i64(3, core::f64::consts::FRAC_PI_6)); // lon π/6 rad → 30°
      v
    };
    // 3-4-2: 2-1 (GPSInfo). dvtm_ac203 GPSInfo is at 3-4-2-1.
    let lvl342 = nest(2, &[nest(1, &[gps_info])]); // 3-4 -> 2 -> 1 -> {...}
    let lvl34 = nest(4, &[lvl342]);
    let lvl3 = nest(3, &[lvl34]);
    let proto = proto_block("dvtm_ac203.proto");

    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = out.first_fix().expect("fix");
    assert!(
      (s.latitude().unwrap() - 45.0).abs() < 1e-9,
      "got {:?}",
      s.latitude()
    );
    assert!(
      (s.longitude().unwrap() - 30.0).abs() < 1e-9,
      "got {:?}",
      s.longitude()
    );
  }

  #[test]
  fn coord_to_degrees_matches_perl_left_to_right() {
    // DJI.pm:929/935 RawConv is `$val * 180 / 3.141592653589793`, which Perl
    // evaluates LEFT-TO-RIGHT as `(raw * 180) / pi` (left-associative `*`/`/`).
    // `coord_to_degrees` must reproduce that operation order EXACTLY — NOT the
    // reassociated `raw * (180 / pi)`, which differs by 1 ULP on ~1.8% of real
    // radian inputs (visible at `-ee -n`, the raw-F64 emit).
    let raw = -0.123_445_945_787_334_39_f64;
    let got = coord_to_degrees(raw, None);
    // (1) The function computes EXACTLY `(raw * 180) / pi`.
    assert_eq!(
      got.to_bits(),
      ((raw * 180.0) / core::f64::consts::PI).to_bits(),
      "coord_to_degrees must be (raw * 180) / pi, bit-for-bit"
    );
    // (2) This is the value Perl produces for this input. Perl's
    //     `$val * 180 / 3.141592653589793` yields `-7.0729316916150244`
    //     (full-precision), which rounds to `-7.072931691615` at Perl's default
    //     `%.14g`. Assert BOTH the rounded display string (the user-visible
    //     value) AND that the full-precision result is within 0.5 ULP of it.
    assert_eq!(
      std::format!("{got:.13}"),
      "-7.0729316916150",
      "got {got:?} — must match the Perl left-to-right result"
    );
    assert!(
      (got - (-7.072_931_691_615_024_4_f64)).abs() <= f64::EPSILON,
      "got {got:?} — within 1 ULP of the Perl left-to-right value -7.0729316916150244"
    );
    // (3) NON-VACUOUS: the OLD reassociated `raw * (180 / pi)` differs in the
    //     last bit for this input, so the fix is not a no-op.
    #[allow(clippy::excessive_precision)]
    let old = raw * (180.0_f64 / core::f64::consts::PI);
    assert_ne!(
      got.to_bits(),
      old.to_bits(),
      "the left-to-right result must differ from the precomputed-factor result \
       (else the test does not prove the fix)"
    );
    // The 1-ULP gap is exactly that: the two results are adjacent f64s.
    let ulp_gap = got.to_bits().abs_diff(old.to_bits());
    assert_eq!(ulp_gap, 1, "the difference is exactly 1 ULP, got {ulp_gap}");
    // The degrees passthrough path (units truthy) is unchanged — a non-radian
    // coordinate is returned verbatim regardless of the operation-order fix.
    assert_eq!(
      coord_to_degrees(raw, Some(1)),
      raw,
      "units truthy ⇒ passthrough"
    );
  }

  #[test]
  fn djmd_capture_settings_mavic3() {
    // dvtm_wm265e: ISO 3-2-2-1 (float), ShutterSpeed 3-2-3-1 (rational),
    // DigitalZoom 3-2-6-1 (float). `lvl32_body` = the records inside the
    // `3-2` message (fields 2/3/6, each wrapping a field-1 leaf).
    let lvl32_body = {
      let mut v = Vec::new();
      v.extend(nest(2, &[rec_i32(1, 800.0)])); // 3-2-2-1 ISO
      v.extend(nest(3, &[rec_rational(1, 1, 250)])); // 3-2-3-1 ShutterSpeed
      v.extend(nest(6, &[rec_i32(1, 2.0)])); // 3-2-6-1 DigitalZoom
      v
    };
    let lvl3 = nest(3, &[rec_len(2, &lvl32_body)]);
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = out.first_capture().expect("capture");
    assert_eq!(s.iso(), Some(800.0));
    assert_eq!(s.shutter_speed_s(), Some(1.0 / 250.0));
    assert_eq!(s.digital_zoom(), Some(2.0));
  }

  #[test]
  fn djmd_shutterspeed_zero_denominator_decodes_err() {
    // A wm265e ShutterSpeed leaf (3-2-3-1) whose packed rational has a ZERO
    // denominator decodes to ExifTool's `'err'` (Protobuf.pm:205) — the field is
    // PRESENT (`shutter_speed_read()` is `Some(Err)`, so the row is NOT empty and
    // the tag emits `'err'`), but the numeric domain accessor returns `None` (it
    // is not a number ⇒ the projection skips it).
    let lvl32_body = nest(3, &[rec_rational(1, 1, 0)]); // 3-2-3-1 ShutterSpeed, den 0
    let lvl3 = nest(3, &[rec_len(2, &lvl32_body)]);
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = &out.samples()[0];
    assert_eq!(
      s.shutter_speed_read(),
      Some(RationalValue::Err),
      "den==0 ⇒ the field is present as the 'err' reading"
    );
    assert_eq!(
      s.shutter_speed_s(),
      None,
      "the 'err' reading is hidden from the numeric domain accessor"
    );
    assert!(
      !s.is_empty(),
      "a present 'err' ShutterSpeed makes the row non-empty (the tag emits)"
    );
    // It is NOT selected as the capture sample (no projectable number) — so an
    // 'err'-only track projects no CaptureSettings.
    assert!(
      out.first_capture().is_none(),
      "an 'err'-only ShutterSpeed is not a projectable capture sample"
    );
  }

  /// Build a one-sample djmd buffer for `proto` carrying ISO at `3-2-3-1`
  /// (an I32 float leaf). Shared by the ac203/ac204/ac206 ISO-path tests.
  fn djmd_iso_at_3231(proto: &str, iso: f32) -> Vec<u8> {
    // 3-2-3-1: nest(3, nest(2, nest(3, rec_i32(1, iso)))).
    let lvl3 = nest(3, &[nest(2, &[nest(3, &[rec_i32(1, iso)])])]);
    let mut buf = proto_block(proto);
    buf.extend(lvl3);
    buf
  }

  #[test]
  fn djmd_iso_ac203_at_3_2_3_1() {
    // ac203 ISO is the `3-2-3-1` leaf (DJI.pm:280), NOT the WRONG `3-2-2-1`
    // (DJI.pm:278, commented out in bundled).
    let buf = djmd_iso_at_3231("dvtm_ac203.proto", 400.0);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].iso(), Some(400.0));
    // The OLD WRONG path 3-2-2-1 must NOT decode an ISO.
    let p = protocol_for("dvtm_ac203").unwrap();
    assert!(field_for(p, &[3, 2, 2, 1]).is_none());
    assert_eq!(field_for(p, &[3, 2, 3, 1]), Some(FieldKind::Iso));
  }

  #[test]
  fn djmd_iso_ac204_at_3_2_3_1() {
    // ac204 ISO `3-2-3-1` (DJI.pm:321).
    let buf = djmd_iso_at_3231("dvtm_ac204.proto", 200.0);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].iso(), Some(200.0));
    let p = protocol_for("dvtm_ac204").unwrap();
    assert_eq!(field_for(p, &[3, 2, 3, 1]), Some(FieldKind::Iso));
  }

  #[test]
  fn djmd_iso_ac206_at_3_2_3_1() {
    // ac206 ISO `3-2-3-1` (DJI.pm:362).
    let buf = djmd_iso_at_3231("dvtm_ac206.proto", 800.0);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].iso(), Some(800.0));
    let p = protocol_for("dvtm_ac206").unwrap();
    assert_eq!(field_for(p, &[3, 2, 3, 1]), Some(FieldKind::Iso));
  }

  #[test]
  fn djmd_ac203_gps_altitude_unsigned_plain_varint() {
    // ac203 GPSAltitude `3-4-2-2` is `Format => 'unsigned'` + `/1000`
    // (DJI.pm:296-301) — a PLAIN varint, NOT the int64s hack. A real altitude
    // decodes the same as int64s would; verify the value lands.
    let lvl342 = {
      let mut v = Vec::new();
      v.extend(rec_varint(2, 123_456)); // 3-4-2-2 GPSAltitude → 123.456 m
      v
    };
    let lvl3 = nest(3, &[nest(4, &[nest(2, &[lvl342])])]);
    let proto = proto_block("dvtm_ac203.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].absolute_altitude_m(), Some(123.456));
    let p = protocol_for("dvtm_ac203").unwrap();
    assert_eq!(field_for(p, &[3, 4, 2, 2]), Some(FieldKind::GpsAltitude));
  }

  #[test]
  fn djmd_coordinate_units_two_is_degrees() {
    // Bundled's GPS RawConv is `$$self{CoordUnits} ? degrees : radians`
    // (DJI.pm:929/935) — Perl-truthy, so units code 2 (or any nonzero) ⇒
    // already-degrees, NOT just 1. ac203 GPSInfo at 3-4-2-1.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 2)); // CoordinateUnits = 2 (truthy ⇒ degrees)
      v.extend(rec_i64(2, 45.0)); // GPSLatitude (already degrees)
      v.extend(rec_i64(3, 8.0)); // GPSLongitude
      v
    };
    let lvl342 = nest(2, &[nest(1, &[gps_info])]); // 3-4-2-1
    let lvl3 = nest(3, &[nest(4, &[lvl342])]);
    let proto = proto_block("dvtm_ac203.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = out.first_fix().expect("fix");
    // CoordUnits=2 is truthy ⇒ NOT multiplied by 180/pi.
    assert_eq!(s.latitude(), Some(45.0));
    assert_eq!(s.longitude(), Some(8.0));
  }

  #[test]
  fn djmd_drone_and_gimbal_orientation() {
    // dvtm_wm265e: DroneInfo at 3-3-3 (fields 1/2/3 = roll/pitch/yaw),
    // GimbalInfo at 3-4-3.
    let drone = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 5)); // DroneRoll 0.5°
      v.extend(rec_varint(2, 0xffff_ffff_ffff_ff9c)); // DronePitch -100 → -10.0°
      v.extend(rec_varint(3, 900)); // DroneYaw 90.0°
      v
    };
    let gimbal = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 0xffff_ffff_ffff_fed4)); // GimbalPitch -300 → -30.0°
      v.extend(rec_varint(3, 450)); // GimbalYaw 45.0°
      v
    };
    let lvl3 = {
      let mut v = Vec::new();
      v.extend(nest(3, &[nest(3, &[drone])])); // 3-3-3 DroneInfo
      v.extend(nest(4, &[nest(3, &[gimbal])])); // 3-4-3 GimbalInfo
      v
    };
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(nest(3, &[lvl3]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = &out.samples()[0];
    assert_eq!(s.drone_roll_deg(), Some(0.5));
    assert_eq!(s.drone_pitch_deg(), Some(-10.0));
    assert_eq!(s.drone_yaw_deg(), Some(90.0));
    assert_eq!(s.gimbal_pitch_deg(), Some(-30.0));
    assert_eq!(s.gimbal_yaw_deg(), Some(45.0));
  }

  #[test]
  fn djmd_gps_date_time_dash_to_colon() {
    // dvtm_ac203 GPSDateTime at 3-4-2-6-1.
    let dt = nest(6, &[rec_str(1, "2025-01-15 12:34:56")]); // 3-4-2-6-1
    let lvl342 = nest(2, &[dt]);
    let lvl34 = nest(4, &[lvl342]);
    let lvl3 = nest(3, &[lvl34]);
    let proto = proto_block("dvtm_ac203.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.samples()[0].gps_date_time(),
      Some("2025:01:15 12:34:56")
    );
  }

  #[test]
  fn djmd_timestamp_avata2() {
    // dvtm_AVATA2 TimeStamp at 3-1-2 (unsigned microseconds).
    let lvl31 = nest(1, &[rec_varint(2, 1_234_567_890)]); // 3-1-2
    let lvl3 = nest(3, &[lvl31]);
    let proto = proto_block("dvtm_AVATA2.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].time_stamp_us(), Some(1_234_567_890));
  }

  #[test]
  fn field_lookup_frame_number_all_protocols() {
    // `3-1-1` FrameNumber (Format => 'unsigned') is a NAMED, default-extracted
    // leaf on EVERY protocol arm (DJI.pm:279/:320/:361/:404/:446/:479/:515/:558/
    // :598/:639/:677/:721/:744/:782/:833/:868, `#forum17996`).
    for kp in [
      "dvtm_ac203",
      "dvtm_ac204",
      "dvtm_ac206",
      "dvtm_AVATA2",
      "dvtm_wm265e",
      "dvtm_pm320",
      "dvtm_Mini4_Pro",
      "dvtm_dji_neo",
      "dvtm_Air3",
      "dvtm_Air3s",
      "dvtm_oq101",
      "dvtm_PP-101",
      "dvtm_wa345e",
      "dvtm_wm261",
      "dvtm_Mavic4",
      "dvtm_Mini5Pro",
    ] {
      let p = protocol_for(kp).unwrap();
      assert_eq!(
        field_for(p, &[3, 1, 1]),
        Some(FieldKind::FrameNumber),
        "{kp} 3-1-1 must map to FrameNumber"
      );
    }
  }

  #[test]
  fn djmd_frame_number_decodes_per_sample() {
    // FrameNumber `3-1-1` (unsigned VARINT) lands on the per-sample row (one
    // `Doc<N>` each), like TimeStamp `3-1-2`. Decode an ac203 sample carrying a
    // `3-1-1` varint and assert the raw counter on the sample.
    let lvl31 = nest(1, &[rec_varint(1, 1701)]); // 3-1-1 FrameNumber
    let lvl3 = nest(3, &[lvl31]);
    let proto = proto_block("dvtm_ac203.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].frame_number(), Some(1701));
  }

  #[test]
  fn avata2_serial_number_2_decodes_and_emits() {
    // `'dvtm_AVATA2_2-2-3-1' => 'SerialNumber2'` (DJI.pm:399) and
    // `'dvtm_dji_neo_2-2-3-1' => 'SerialNumber2'` (DJI.pm:553) — a NAMED tag with
    // NO `Unknown` flag, so ExifTool extracts `Protobuf:DJI:SerialNumber2` by
    // default at `-ee`. No `Format` ⇒ a LEN payload decodes as a plain ASCII
    // string (Protobuf.pm:239-256), exactly like SerialNumber. Adding the
    // `2-2-3-1` leaf makes `2-2` and `2-2-3` branch-prefixes, so `is_branch`
    // descends into the (previously unreachable) `2-2` container end-to-end.
    //
    // `2-2-3-1`: top-2 → 2 → 3 → 1 (leaf).
    let serial2 = nest(2, &[nest(2, &[nest(3, &[rec_str(1, "SN2-ABCDEF")])])]);
    for proto_name in ["dvtm_AVATA2.proto", "dvtm_dji_neo.proto"] {
      let mut buf = Vec::new();
      buf.extend(proto_block(proto_name));
      buf.extend(serial2.clone());

      let mut out = DjiProtobufMeta::new();
      let mut dji_st = DjiTrackState::new();
      process_djmd(&buf, &mut dji_st, &mut out);
      // The `1-1` identity block (proto_block) pushes sample 0; this single
      // top-level message holds BOTH `1-1` and `2-2-3-1`, so it is sample 0.
      let s = &out.samples()[0];
      assert_eq!(
        s.serial_number_2(),
        Some("SN2-ABCDEF"),
        "{proto_name}: the 2-2-3-1 leaf decodes onto serial_number_2()"
      );
      // SerialNumber (1-1-5) is unaffected (proto_block carries SERIAL123).
      assert_eq!(
        s.serial_number(),
        Some("SERIAL123"),
        "{proto_name}: 1-1-5 still decodes"
      );
    }
  }

  #[test]
  fn serial_number_2_only_on_avata2_and_dji_neo() {
    // Confirm the OTHER 14 protocols declare no `2-2-3-1` SerialNumber2 row, so
    // an identical `2-2-3-1` string leaf decodes NOTHING there (it is an unknown
    // path under those protocols). Only AVATA2 + DJI Neo carry the row.
    let serial2 = nest(2, &[nest(2, &[nest(3, &[rec_str(1, "SN2-ABCDEF")])])]);
    for proto in PROTOCOLS {
      let has_row = proto.rows.iter().any(|r| r.path == [2, 2, 3, 1]);
      let expected = matches!(proto.name, "dvtm_AVATA2" | "dvtm_dji_neo");
      assert_eq!(
        has_row, expected,
        "{}: SerialNumber2 row presence must be AVATA2/dji_neo-only",
        proto.name
      );
      if expected {
        continue;
      }
      // End-to-end: under a protocol WITHOUT the row, the leaf decodes nothing.
      let mut buf = Vec::new();
      let proto_name = std::format!("{}.proto", proto.name);
      buf.extend(proto_block(&proto_name));
      buf.extend(serial2.clone());
      let mut out = DjiProtobufMeta::new();
      let mut dji_st = DjiTrackState::new();
      process_djmd(&buf, &mut dji_st, &mut out);
      assert_eq!(
        out.samples()[0].serial_number_2(),
        None,
        "{}: a 2-2-3-1 leaf must NOT decode (no SerialNumber2 row)",
        proto.name
      );
    }
  }

  #[test]
  fn djmd_frame_info() {
    // dvtm_wm265e FrameInfo at 2-2 (fields 1/2/3 = w/h/rate).
    let frame = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 3840));
      v.extend(rec_varint(2, 2160));
      v.extend(rec_i32(3, 29.97));
      v
    };
    let lvl2 = nest(2, &[nest(2, &[frame])]); // 2-2
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl2);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = &out.samples()[0];
    assert_eq!(s.frame_width(), Some(3840));
    assert_eq!(s.frame_height(), Some(2160));
    assert_eq!(s.frame_rate(), Some(f64::from(29.97_f32)));
  }

  #[test]
  fn djmd_mavic4_forces_degrees_without_coord_units() {
    // dvtm_Mavic4 GPSInfo at 3-3-4-1 forces degrees (no CoordinateUnits).
    // Raw lat = 45.0 must stay 45.0 (NOT multiplied by 180/pi).
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_i64(2, 45.0));
      v.extend(rec_i64(3, 8.0));
      v
    };
    let lvl334 = nest(4, &[nest(1, &[gps_info])]); // 3-3-4-1
    let lvl33 = nest(3, &[lvl334]);
    let lvl3 = nest(3, &[lvl33]);
    let proto = proto_block("dvtm_Mavic4.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = out.first_fix().expect("fix");
    assert_eq!(s.latitude(), Some(45.0), "Mavic4 forces degrees");
    assert_eq!(s.longitude(), Some(8.0));
  }

  // ── malformed input safety ───────────────────────────────────────────
  #[test]
  fn unknown_protocol_warns() {
    let proto = proto_block("dvtm_FUTURE99.proto");
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&proto, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_FUTURE99.proto"));
    assert_eq!(
      out.first_warning(),
      Some("Unknown protocol dvtm_FUTURE99.proto (please submit sample for testing)")
    );
    // ExifTool `HandleTag`s the `Protocol` for an unknown protocol too
    // (Protobuf.pm:160 fires before the table lookup), so the sample's row
    // carries it even though no telemetry table matched.
    assert_eq!(out.samples().len(), 1, "one row per dispatched sample");
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_FUTURE99.proto"));
    assert!(
      out.samples()[0].latitude().is_none(),
      "unknown protocol decodes no telemetry"
    );
  }

  #[test]
  fn djmd_protocol_persists_across_samples() {
    // ExifTool's `$$et{ProtoPrefix}{$dirName}` is PER-TRACK persistent state
    // (Protobuf.pm:145/159/162): once a djmd sample sets the protocol, a LATER
    // sample with NO `.proto` leaf decodes its records using that PERSISTED
    // prefix. Sample 1 = `dvtm_wm265e.proto` leaf ONLY (identity); sample 2 =
    // GPS/capture fields with NO `.proto` leaf — both must decode (sample 2's
    // GPS extracted with the persisted wm265e protocol).
    let mut out = DjiProtobufMeta::new();

    // Sample 1: identity only (the `1-1` block: proto + serial + model).
    let lvl11_body = {
      let mut v = Vec::new();
      v.extend(rec_str(1, "dvtm_wm265e.proto"));
      v.extend(rec_str(5, "SERIAL123"));
      v.extend(rec_str(10, "FC8482"));
      v
    };
    let sample1 = nest(1, &[rec_len(1, &lvl11_body)]);
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "sample 1 persists protocol"
    );
    assert_eq!(out.samples().len(), 1);
    // Sample 1's row carries the identity it physically held.
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(out.samples()[0].serial_number(), Some("SERIAL123"));
    assert_eq!(out.samples()[0].model(), Some("FC8482"));
    assert!(out.samples()[0].latitude().is_none(), "sample 1 has no GPS");

    // Sample 2: GPS (CoordinateUnits=1 degrees, lat 45, lon 8) + AbsoluteAltitude
    // at the wm265e paths — but NO `.proto` leaf. Must decode via the PERSISTED
    // wm265e protocol.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // 3-3-4-1-1 CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // 3-3-4-1-2 GPSLatitude
      v.extend(rec_i64(3, 8.0)); // 3-3-4-1-3 GPSLongitude
      v
    };
    let lvl334 = {
      let mut v = Vec::new();
      v.extend(nest(1, &[gps_info])); // 3-3-4-1 GPSInfo
      v.extend(rec_varint(2, 105_500)); // 3-3-4-2 AbsoluteAltitude (105.5 m)
      v
    };
    let sample2 = nest(3, &[nest(3, &[nest(4, &[lvl334])])]);
    process_djmd(&sample2, &mut dji_st, &mut out);

    assert_eq!(out.samples().len(), 2, "one row per dispatched sample");
    // Sample 2 has NO `.proto` leaf of its own ⇒ no per-row Protocol.
    assert!(
      out.samples()[1].protocol().is_none(),
      "data-only sample emits no Protocol (HandleTag-when-seen)"
    );
    // …but it DECODED with the persisted wm265e protocol.
    assert_eq!(out.samples()[1].latitude(), Some(45.0));
    assert_eq!(out.samples()[1].longitude(), Some(8.0));
    assert_eq!(
      out.samples()[1].absolute_altitude_m(),
      Some(105.5),
      "GPS/altitude decoded via the persisted protocol"
    );
    assert!(out.first_warning().is_none(), "wm265e is known; no warning");
  }

  #[test]
  fn djmd_persisted_protocol_uses_correct_per_protocol_table() {
    // The persisted-protocol reuse must decode the data sample's fields with
    // the SAME per-protocol table the identity sample established — e.g. ac203's
    // `3-4-2-2` is the unsigned `GPSAltitude` leaf (DJI.pm:296-301), proving the
    // reuse picks the ac203 table (not a generic/empty prefix).
    let mut out = DjiProtobufMeta::new();
    // Sample 1: ac203 identity only.
    let sample1 = proto_block("dvtm_ac203.proto");
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    // Sample 2: data-only, ac203 GPSAltitude at 3-4-2-2 (unsigned plain varint).
    let lvl342 = {
      let mut v = Vec::new();
      v.extend(rec_varint(2, 123_456)); // 3-4-2-2 GPSAltitude → 123.456 m
      v
    };
    let sample2 = nest(3, &[nest(4, &[nest(2, &[lvl342])])]);
    process_djmd(&sample2, &mut dji_st, &mut out);
    assert_eq!(out.samples().len(), 2);
    assert_eq!(
      out.samples()[1].absolute_altitude_m(),
      Some(123.456),
      "ac203 3-4-2-2 decoded as the unsigned GPSAltitude via the persisted ac203 table"
    );
  }

  // ── R4-F2: the persisted DECODE prefix is LAST-WINS (not first-wins) ─────
  #[test]
  fn djmd_protocol_a_then_b_then_data_only_uses_b() {
    // ExifTool `=`-OVERWRITES `$$et{ProtoPrefix}{$dirName}` on EVERY `.proto`
    // leaf (Protobuf.pm:159, last-wins). So when sample1 sets protocol A and
    // sample2 sets protocol B, the persisted decode prefix is B — and a sample3
    // with NO `.proto` leaf of its own decodes under B, NOT A. The pre-R4 model
    // seeded the next sample from the FIRST-wins aggregate `protocol()`, so it
    // would have reverted to A — the bug this fixes.
    //
    // The `3-4-2-2` leaf differs per protocol:
    //   - ac203 → GPSAltitude (unsigned plain varint; DJI.pm:296-301)
    //   - oq101 → AbsoluteAltitude (int64s; DJI.pm:700)
    // Both store on `absolute_altitude_m`, but proving sample3 decoded the
    // int64s hack (an oq101-only behaviour) confirms it used B = oq101's table.
    let mut out = DjiProtobufMeta::new();
    // Sample 1: protocol A = ac203 (identity only).
    let sample1 = proto_block("dvtm_ac203.proto");
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    // Sample 2: protocol B = oq101 (identity only).
    let sample2 = proto_block("dvtm_oq101.proto");
    process_djmd(&sample2, &mut dji_st, &mut out);
    // The FIRST-wins MODEL identity stays A; the LAST-wins decode prefix is B.
    assert_eq!(
      out.protocol(),
      Some("dvtm_ac203.proto"),
      "aggregate model identity is FIRST-wins (A)"
    );
    assert_eq!(
      dji_st.decode_prefix(),
      Some("dvtm_oq101.proto"),
      "decode prefix is LAST-wins (B)"
    );
    // Sample 3: data-only `3-4-2-2`, a varint in the DJI int64s-hack range
    // (≥ INT64S_MIN). Under oq101 (B, int64s) it recovers a NEGATIVE altitude;
    // under ac203 (A, unsigned) it would be a huge positive — so the sign proves
    // which table B/A decoded it.
    let lvl342 = {
      let mut v = Vec::new();
      v.extend(rec_varint(2, 0xffff_ffff_ffff_fc18)); // int64s -1000 → -1.0 m
      v
    };
    let sample3 = nest(3, &[nest(4, &[nest(2, &[lvl342])])]);
    process_djmd(&sample3, &mut dji_st, &mut out);
    assert_eq!(out.samples().len(), 3);
    assert_eq!(
      out.samples()[2].absolute_altitude_m(),
      Some(-1.0),
      "sample3 decoded under B = oq101 (int64s hack ⇒ negative), NOT A = ac203 (unsigned)"
    );
  }

  #[test]
  fn djmd_later_unknown_protocol_still_warns() {
    // The `Protocol` RawConv (DJI.pm:259-266) runs on EVERY `.proto` leaf, so a
    // KNOWN first protocol (no warning) followed by a LATER UNKNOWN protocol
    // STILL raises the unknown-protocol warning. The pre-R4 `record_protocol`
    // early-returned once the aggregate identity was set, skipping the later
    // leaf's warning — the bug this fixes.
    let mut out = DjiProtobufMeta::new();
    // Sample 1: a KNOWN protocol — no warning.
    let sample1 = proto_block("dvtm_ac203.proto");
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "known first protocol must not warn"
    );
    // Sample 2: a LATER UNKNOWN protocol leaf — must warn.
    let sample2 = proto_block("dvtm_unknownX.proto");
    process_djmd(&sample2, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Unknown protocol dvtm_unknownX.proto (please submit sample for testing)"),
      "a later unknown protocol leaf still warns"
    );
    // First-wins identity keeps the original known protocol; last-wins decode
    // prefix moved to the unknown one (its table is None ⇒ a data-only follower
    // decodes nothing).
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    assert_eq!(dji_st.decode_prefix(), Some("dvtm_unknownX.proto"));
  }

  #[test]
  fn djmd_no_persisted_protocol_first_sample_notfound_noops() {
    // A clean djmd sample with records but NO `.proto` leaf AND no prior
    // persisted protocol. ExifTool walks with an empty `ProtoPrefix` and
    // matches no DJI field — a no-op DECODE. But `FoundSomething` still opened
    // a `Doc<N>`, so the faithful model pushes exactly ONE placeholder row
    // (carrying no protocol / no telemetry — only the arm's SampleTime/
    // Duration are stamped later). No protocol is persisted, no warning.
    let buf = rec_varint(1, 42);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.protocol().is_none(),
      "no `.proto` leaf ⇒ no persisted protocol"
    );
    assert!(
      out.first_warning().is_none(),
      "a clean no-leaf sample must not warn"
    );
    assert_eq!(
      out.samples().len(),
      1,
      "one placeholder row per dispatched sample"
    );
    assert!(
      out.samples()[0].is_empty(),
      "the placeholder row carries no decoded value"
    );
  }

  #[test]
  fn malformed_sample_without_protocol_warns_format_error() {
    // A djmd sample whose only top-level record is malformed (a LEN record
    // declaring 200 bytes with no body — a truncated/bad-wire record) BEFORE
    // any `.proto` leaf. ExifTool's `ProcessProtobuf` reads records first and
    // `$self->Warn('Protobuf format error')` on the failed `ReadRecord`
    // (Protobuf.pm:156), even with no protocol found. We must surface that.
    let mut bad = tag(1, 2); // field 1, wire 2 (LEN)
    bad.extend(enc_varint(200)); // declares 200 bytes …
    // … but no body follows ⇒ read_tag fails at the TOP level.
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&bad, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a malformed no-protocol sample must warn"
    );
    // The LENGTH varint ended EXACTLY at EOF (the declared 200-byte body has 0
    // bytes left), so `GetBytes(200)` fails WITHOUT advancing — `Pos == dirEnd`.
    // Protobuf.pm:278 fires `Truncated protobuf data` only `unless … Pos ==
    // dirEnd`, so this consume-to-EOF failure emits ONLY the format error
    // (verified against a top-level `ProcessProtobuf` perl trace → `[Protobuf
    // format error]`). The both-warnings case (leftover bytes ⇒ Pos < dirEnd) is
    // `len_claiming_more_with_leftover_emits_both` (#163 R17).
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error"],
      "a consume-to-EOF failure (Pos == dirEnd) emits ONLY the format error"
    );
    assert!(out.protocol().is_none());
    // `FoundSomething` already opened the `Doc<N>` before `ProcessProtobuf`
    // warned, so this still pushes one placeholder row (no protocol/telemetry).
    assert_eq!(
      out.samples().len(),
      1,
      "one placeholder row per dispatched sample"
    );
    assert!(out.samples()[0].is_empty());

    // A CLEAN sample with no `.proto` leaf (a valid top-level varint, no read
    // failure) does NOT warn (ExifTool's `ReadRecord` did not fail), but still
    // pushes one placeholder row for its `Doc<N>`.
    let clean = rec_varint(1, 42);
    let mut out2 = DjiProtobufMeta::new();
    // A SEPARATE aggregate ⇒ a SEPARATE (fresh) per-track decode state.
    let mut dji_st2 = DjiTrackState::new();
    process_djmd(&clean, &mut dji_st2, &mut out2);
    assert!(
      out2.first_warning().is_none(),
      "a clean no-leaf sample must not warn"
    );
    assert!(out2.protocol().is_none());
    assert_eq!(out2.samples().len(), 1);
    assert!(out2.samples()[0].is_empty());
  }

  #[test]
  fn empty_buffer_djmd_pushes_placeholder_row() {
    // ExifTool reads a 0-byte djmd sample (`Read($buff,0)==0==$size`,
    // QuickTimeStream.pl:1438) and STILL dispatches it: `FoundSomething` opens
    // a `Doc<N>` (+ SampleTime/Duration) then `ProcessProtobuf` on the empty
    // buffer matches nothing (no warning). So an empty djmd sample pushes one
    // placeholder row (mirrors the `rtmd` sibling). (`dbgi` is a default-options
    // no-op at the dispatch arm — see `dbgi_is_noop_under_default_options` in
    // `quicktime_stream` — so there is no `process_dbgi` to exercise here.)
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&[], &mut dji_st, &mut out);
    assert_eq!(out.samples().len(), 1, "empty djmd ⇒ one placeholder row");
    assert!(out.samples()[0].is_empty());
    assert!(out.first_warning().is_none());
  }

  #[test]
  fn truncated_payload_does_not_panic() {
    // Valid protocol then a truncated record. Must not panic; identity kept.
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = proto;
    buf.extend(tag(3, 2)); // LEN tag with no length/body
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
  }

  #[test]
  fn bad_wire_type_truncates_walk() {
    // wire type 6 is invalid; read_tag returns None, walk stops gracefully.
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = proto;
    buf.extend(tag(3, 6)); // invalid wire type
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
  }

  #[test]
  fn wire_type_6_7_still_warns() {
    // CLASS-SWEEP guard: the id-0 leniency must NOT make the whole record reader
    // lenient. Wire types 6 and 7 match NONE of `ReadRecord`'s if/elsif chain
    // (Protobuf.pm:90-106) ⇒ `$buff` stays undef ⇒ `return undef` ⇒ the loop's
    // `defined $buff or $et->Warn('Protobuf format error'), last` (Protobuf.pm:
    // 155). So an invalid wire type 6/7 is STILL the fatal `Protobuf format
    // error` case (contrast id-0, which is read+skipped). Verify BOTH 6 and 7.
    for bad_wire in [6u8, 7u8] {
      let proto = proto_block("dvtm_wm265e.proto");
      let mut buf = proto;
      buf.extend(tag(3, bad_wire)); // invalid wire type
      let mut out = DjiProtobufMeta::new();
      let mut dji_st = DjiTrackState::new();
      process_djmd(&buf, &mut dji_st, &mut out);
      assert_eq!(
        out.first_warning(),
        Some("Protobuf format error"),
        "wire type {bad_wire} is invalid ⇒ Protobuf format error"
      );
      // Everything before the bad-wire record survives.
      assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    }
  }

  #[test]
  fn group_wire_type_is_skipped() {
    // A wire-type-3 (start group) record between protocol and a known leaf
    // must not derail the walk.
    let proto = proto_block("dvtm_AVATA2.proto");
    let mut buf = proto;
    buf.extend(tag(7, 3)); // start group, empty
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 999)])])); // 3-1-2 TimeStamp
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(999)
    );
  }

  #[test]
  fn wire_type_group_3_4_skipped_empty() {
    // CLASS-SWEEP: `ReadRecord` reads a wire-type-3 (start group) AND wire-type-4
    // (end group) as an EMPTY record (`$buff = ''`, tag byte consumed, NO payload
    // bytes — Protobuf.pm:99-103) and returns it; the loop skips it as an unknown
    // tag. A wire-3 OR wire-4 record before a valid later DJI record must be
    // skipped (empty, no warning) and the later record must still decode. (The
    // sibling `group_wire_type_is_skipped` covers wire 3; this adds wire 4 and
    // asserts no warning explicitly.)
    for group_wire in [3u8, 4u8] {
      let proto = proto_block("dvtm_AVATA2.proto");
      let mut buf = proto;
      buf.extend(tag(5, group_wire)); // a group record (empty payload), field 5
      buf.extend(nest(3, &[nest(1, &[rec_varint(2, 777)])])); // 3-1-2 TimeStamp after it
      let mut out = DjiProtobufMeta::new();
      let mut dji_st = DjiTrackState::new();
      process_djmd(&buf, &mut dji_st, &mut out);
      assert!(
        out.first_warning().is_none(),
        "wire type {group_wire} (group) is skipped empty, no warning, got {:?}",
        out.first_warning()
      );
      assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
      assert_eq!(
        out
          .samples()
          .first()
          .and_then(DjiTelemetrySample::time_stamp_us),
        Some(777),
        "the record after the wire-{group_wire} group still decodes"
      );
    }
  }

  #[test]
  fn id_zero_zero_len_len_record_skipped() {
    // CLASS-SWEEP / R10-F1: a `[0x02, 0x00]` record — field 0, wire 2 (LEN),
    // length 0 — is id-0 padding. `ReadRecord` reads it (no id-0 rejection); the
    // loop AddTagToTable's an Unknown tag, then the empty `$buff` fails
    // `$buff =~ /[^\x20-\x7e]/` ⇒ IsProtobuf never set ⇒ `next` (Protobuf.pm:
    // 169-178). So it must be SKIPPED (no warning, no decode, no recurse) and a
    // valid later DJI record must still decode. Pre-R10 the id-0 rejection turned
    // this into a fatal `Protobuf format error` that DROPPED the later telemetry.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    buf.extend([0x02, 0x00]); // id-0 zero-length LEN padding record
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 555)])])); // 3-1-2 TimeStamp after it
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "an id-0 zero-length LEN is skipped, NOT a format error, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(555),
      "telemetry after the id-0 record still decodes"
    );
  }

  #[test]
  fn id_zero_varint_record_skipped() {
    // CLASS-SWEEP / R10-F1: a `[0x00, 0x00]` record — field 0, wire 0 (VARINT),
    // value 0 — is id-0 padding. `ReadRecord` reads it; the loop's
    // `next unless $type == 2 or $unknown` skips it (type 0, default Unknown=0 —
    // Protobuf.pm:164). So no warning, no decode, and a valid later DJI record
    // still decodes.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    buf.extend([0x00, 0x00]); // id-0 varint value 0 padding record
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 321)])])); // 3-1-2 TimeStamp after it
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "an id-0 varint record is skipped, NOT a format error, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(321),
      "telemetry after the id-0 varint record still decodes"
    );
  }

  // ── R11 read-strictness class: huge/overflowed field ids + varint values ─
  // ExifTool's ONLY fatal read cases are truncation (off the buffer end), > ~33
  // continuation bytes, and wire type 6/7. A huge field id, and a varint whose
  // value exceeds u64, are ALL non-fatal — consumed and skipped, decode CONTINUES.

  /// A VARINT record whose field number is an arbitrary `u64` (`rec_varint`'s
  /// helper only reaches a `u32` field).
  fn rec_varint_field_u64(field: u64, v: u64) -> Vec<u8> {
    let mut o = enc_varint(field << 3); // wire 0 (low 3 bits clear)
    o.extend(enc_varint(v));
    o
  }

  /// A 10-byte WELL-FORMED varint whose value exceeds `u64` (9 × 0x80 payload-0
  /// continuation bytes then a terminating 0x02 — bit 1 of the 10th byte lands
  /// past bit 63). `low3` of the first byte is 0 (so as a TAG it reads wire 0).
  fn enc_varint_over_u64() -> Vec<u8> {
    let mut v = std::vec![0x80u8; 9];
    v.push(0x02);
    v
  }

  #[test]
  fn unknown_field_2pow32_wire0_skipped_then_later_leaf_decodes() {
    // THE REPORTED REGRESSION (R11-F1). A known protocol, then an UNKNOWN field
    // 2^32 wire-0 varint record (which the pre-fix `u32::try_from(key >> 3)`
    // ABORTED — field 2^32 > u32::MAX), then a valid later DJI leaf. ExifTool
    // keeps the (huge) id, matches no path, skips the record, and continues. So:
    // no warning, the 2^32 field is skipped, and the later leaf decodes.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    buf.extend(rec_varint_field_u64(1u64 << 32, 12_345)); // field 2^32, wire 0 — unknown
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 999)])])); // 3-1-2 TimeStamp after it
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "an unknown 2^32 field is skipped, NOT a format error, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(999),
      "the DJI leaf after the 2^32-field record still decodes"
    );
  }

  #[test]
  fn tag_varint_overflow_u64_skipped_then_later_decodes() {
    // A TAG varint whose value exceeds u64 but is well-formed (≤ the
    // continuation bound). ExifTool's `$id = $val >> 3` is a lossy double that
    // matches nothing; `$type = $val & 0x07` (here 0 = varint) is read and the
    // value consumed; the record is skipped. So: no warning, and a valid later
    // record decodes. The over-u64 tag is `enc_varint_over_u64()` (low3 = 0 ⇒
    // wire 0) followed by a value varint.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    let mut over_tag_rec = enc_varint_over_u64(); // a > u64 tag, wire 0
    over_tag_rec.extend(enc_varint(7)); // its (skipped) varint value
    buf.extend(over_tag_rec);
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 888)])])); // 3-1-2 TimeStamp after it
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a > u64 tag varint is skipped, NOT fatal, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(888),
      "the record after the over-u64 tag still decodes"
    );
  }

  #[test]
  fn value_varint_overflow_u64_skipped() {
    // A wire-0 record on a KNOWN numeric leaf whose VALUE varint exceeds u64.
    // ExifTool advances past the lossy-double value and continues; the faithful
    // typed choice is to SKIP that field's value (no abort, no NaN) and keep
    // decoding later records. AVATA2 TimeStamp is at 3-1-2 (unsigned varint):
    // give it a > u64 value (skipped ⇒ time_stamp_us stays None), then a SECOND
    // sample-level leaf (DroneRoll 3-4-3-1) with a normal value still decodes.
    let over_val = enc_varint_over_u64(); // a > u64 varint VALUE
    let mut ts_rec = tag(2, 0); // 3-1-2 leaf: field 2, wire 0
    ts_rec.extend(over_val);
    let lvl31 = nest(1, &[ts_rec]); // 3-1 -> 2
    let drone = nest(4, &[nest(3, &[rec_varint(1, 5)])]); // 3-4-3-1 DroneRoll 0.5°
    let mut lvl3body = Vec::new();
    lvl3body.extend(lvl31);
    lvl3body.extend(drone);
    let lvl3 = nest(3, &[lvl3body]);
    let proto = proto_block("dvtm_AVATA2.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a > u64 value varint is skipped, NOT fatal, got {:?}",
      out.first_warning()
    );
    let s = &out.samples()[0];
    assert_eq!(
      s.time_stamp_us(),
      None,
      "the over-u64 TimeStamp value is skipped (not misrepresented, no NaN)"
    );
    assert_eq!(
      s.drone_roll_deg(),
      Some(0.5),
      "decoding continued to the later DroneRoll leaf"
    );
  }

  #[test]
  fn varint_truncated_off_end_still_fatal() {
    // A TAG varint whose continuation runs off the buffer end is STILL the fatal
    // `Protobuf format error` (VarInt undef ⇒ ReadRecord undef ⇒ Protobuf.pm:156).
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.push(0x80); // a lone continuation byte: a tag varint that runs off the end
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a truncated varint (off the end) is still fatal"
    );
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "earlier records survive"
    );
  }

  #[test]
  fn varint_over_32_continuation_bytes_fatal() {
    // A varint with MORE than ~33 continuation bytes trips VarInt's
    // `return undef if ++$i > 32` (Protobuf.pm:67) ⇒ fatal. 34 leading 0x80 +
    // a terminator is past the bound (33 + terminator would be Overflow). As a
    // top-level tag this is the fatal `Protobuf format error`.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.extend(std::iter::repeat_n(0x80u8, 34)); // 34 continuation bytes …
    buf.push(0x00); // … then a terminator — over the ++$i>32 bound
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "> 33 continuation bytes is fatal (mirrors VarInt `++$i > 32`)"
    );
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "earlier records survive"
    );
    // The boundary BELOW the bound (33 continuation bytes + terminator) is a
    // well-formed over-u64 tag varint ⇒ skipped, NOT fatal, decode continues.
    let mut ok = Vec::new();
    ok.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    let mut over_tag = std::vec![0x80u8; 33];
    over_tag.push(0x00); // terminator: 33 continuation bytes ⇒ within the bound
    over_tag.extend(enc_varint(1)); // the (skipped) wire-0 value
    ok.extend(over_tag);
    ok.extend(nest(3, &[nest(1, &[rec_varint(2, 444)])])); // 3-1-2 TimeStamp after it
    let mut out2 = DjiProtobufMeta::new();
    // A SEPARATE aggregate ⇒ a SEPARATE (fresh) per-track decode state.
    let mut dji_st2 = DjiTrackState::new();
    process_djmd(&ok, &mut dji_st2, &mut out2);
    assert!(
      out2.first_warning().is_none(),
      "33 continuation bytes (within the bound) is a skipped over-u64 tag, got {:?}",
      out2.first_warning()
    );
    assert_eq!(
      out2
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(444),
      "decode continues past the within-bound over-u64 tag"
    );
  }

  // ── R12-F1: a LEN LENGTH that comes back undef ⇒ EMPTY record, NOT fatal ──
  // Protobuf.pm:94-100 `my $len = VarInt(...); if ($len) { $buff = GetBytes($len)
  // } else { $buff = '' }`. `if ($len)` is Perl-FALSE for BOTH undef AND 0, so a
  // LEN length that runs off the end / over-extends (VarInt undef) yields a
  // DEFINED EMPTY payload — the record is processed (as an unknown/empty tag) and
  // the loop continues from where VarInt left the cursor. It does NOT warn. Only
  // the LEN LENGTH varint is lenient on undef; a TAG or VALUE varint undef stays
  // fatal (the asymmetry guard below).

  #[test]
  fn len_length_truncated_off_end_returns_empty_record() {
    // UNIT: a field-2 LEN record whose length varint is a lone 0x80 (continuation
    // bit set, no following byte ⇒ runs off the end ⇒ VarInt undef). `read_tag`
    // must return an EMPTY field-2 LEN record (NOT None), with the cursor at the
    // buffer end. Perl-verified: `ReadRecord` ⇒ id=2 type=2 body='' Pos=2.
    let buf = [0x12u8, 0x80]; // tag = field 2 wire 2, then a truncated length
    let (rec, rest) = read_tag(&buf).expect("LEN-length undef ⇒ EMPTY record, NOT None");
    assert_eq!(rec.field, 2, "field 2");
    assert_eq!(rec.wire, WireType::Len);
    assert!(
      rec.payload.is_empty(),
      "an undef length ⇒ DEFINED EMPTY payload"
    );
    assert!(
      rest.is_empty(),
      "the cursor is at the buffer end (off-end truncation)"
    );
  }

  #[test]
  fn len_length_truncated_off_end_is_empty_record_not_fatal() {
    // INTEGRATION: a valid protocol, then a field-2 LEN record with a truncated
    // length at the tail. The empty LEN record is processed as an unknown tag and
    // the loop ends cleanly (cursor at end) — NO `Protobuf format error`, and the
    // earlier protocol survives.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.extend([0x12u8, 0x80]); // field 2 LEN with a truncated length varint
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a LEN length that runs off the end ⇒ EMPTY record, NOT a format error, got {:?}",
      out.first_warning()
    );
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "the earlier protocol survives"
    );
  }

  #[test]
  fn len_length_truncated_then_walk_ends_clean() {
    // A valid known leaf, THEN a record whose LEN length is truncated at the tail.
    // The earlier leaf is preserved and there is NO `Protobuf format error` (the
    // truncated-length record is an empty unknown tag, and the walk ends cleanly).
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    buf.extend(nest(3, &[nest(1, &[rec_varint(2, 12_345)])])); // 3-1-2 TimeStamp (valid leaf)
    buf.extend([0x12u8, 0x80]); // tail: field 2 LEN with a truncated length
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a truncated LEN length at the tail must NOT warn, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_AVATA2.proto"));
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(12_345),
      "the leaf before the truncated-length record is preserved"
    );
  }

  #[test]
  fn len_length_overcontinuation_is_empty_record_carrying_cursor() {
    // The OTHER `$len` undef sub-case: a LEN length varint that exceeds the
    // continuation bound (34 × 0x80 then 0x00) ⇒ VarInt undef ⇒ EMPTY record. The
    // cursor must resume from where VarInt bailed (past the bound), so trailing
    // bytes after it are NOT consumed by this record. Perl-verified: ReadRecord
    // leaves Pos past the cutoff (3 trailing bytes remain).
    let mut buf = Vec::new();
    buf.push(0x12); // tag = field 2 wire 2
    buf.extend(std::iter::repeat_n(0x80u8, 34)); // 34 continuation bytes …
    buf.push(0x00); // … then a terminator the bound never reaches
    buf.extend([0xAAu8, 0xAA]); // trailing bytes AFTER the bad-length cutoff
    let (rec, rest) = read_tag(&buf).expect("over-continuation LEN length ⇒ EMPTY record");
    assert_eq!(rec.field, 2);
    assert_eq!(rec.wire, WireType::Len);
    assert!(
      rec.payload.is_empty(),
      "an undef length ⇒ DEFINED EMPTY payload"
    );
    // VarInt bails the instant `++$i > 32` trips — AFTER the 34th 0x80 but BEFORE
    // the 0x00 terminator, so that terminator is part of `rest`. Perl-verified:
    // ReadRecord leaves Pos=35 of 38 ⇒ 3 remaining bytes (the 0x00 + two 0xAA).
    assert_eq!(
      rest,
      &[0x00u8, 0xAA, 0xAA],
      "the cursor resumes from where VarInt bailed (past the 34th continuation byte)"
    );
  }

  #[test]
  fn len_length_overflow_still_fatal_getbytes_off_end() {
    // A huge but DEFINED (Perl-truthy) LEN length is NOT the lenient case: `if
    // ($len)` is TRUE ⇒ `GetBytes(huge)` runs off the end ⇒ undef ⇒ fatal. A
    // field-2 LEN whose length varint is `enc_varint_over_u64()` (a well-formed
    // > u64 length) ⇒ read_tag Err. `GetBytes` fails WITHOUT advancing `Pos`,
    // which is right after the LENGTH varint (the 4 leftover body bytes — perl
    // trace: Pos=12, remaining=4), so the post-failure cursor is NON-EMPTY
    // (`Pos < dirEnd`) ⇒ a top-level such failure emits BOTH warnings.
    let mut buf = tag(2, 2); // field 2 wire 2
    buf.extend(enc_varint_over_u64()); // a > u64 (Perl-truthy) length
    buf.extend([0x00u8; 4]); // some body bytes (never enough for a > u64 length)
    let post = read_tag(&buf).expect_err("a > u64 LEN length ⇒ GetBytes off-end ⇒ fatal Err");
    assert_eq!(
      post, &[0u8; 4],
      "Pos is right after the LENGTH varint (GetBytes didn't advance)"
    );
  }

  #[test]
  fn len_length_value_zero_is_empty_record() {
    // The explicit `Value(0)` half of `if ($len) {} else { $buff = '' }`: a
    // literal 0 length ⇒ an EMPTY LEN record (NOT fatal, NOT a recurse). Already
    // covered by `tag_field_zero_is_read` for field 0; this pins a NONZERO field
    // with a 0 length.
    let buf = [0x12u8, 0x00]; // field 2 wire 2, length 0
    let (rec, rest) = read_tag(&buf).expect("length 0 ⇒ EMPTY record");
    assert_eq!(rec.field, 2);
    assert_eq!(rec.wire, WireType::Len);
    assert!(rec.payload.is_empty());
    assert!(rest.is_empty());
  }

  #[test]
  fn tag_varint_truncated_still_fatal() {
    // ASYMMETRY GUARD: a TAG varint that runs off the end is FATAL (`VarInt` undef
    // ⇒ `ReadRecord` `return undef unless defined $val`, Protobuf.pm:84-85) ⇒
    // `Protobuf format error`. ONLY the LEN length is lenient on undef.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.push(0x80); // a lone continuation byte AS A TAG varint ⇒ off the end
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a truncated TAG varint stays fatal (NOT lenient like a LEN length)"
    );
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "earlier records survive"
    );
  }

  #[test]
  fn value_varint_truncated_still_fatal() {
    // ASYMMETRY GUARD: a VALUE (wire-0) varint that runs off the end is FATAL
    // (`$buff = VarInt(...)` undef ⇒ `defined $buff or Warn`, Protobuf.pm:91/155).
    // A wire-0 record whose tag is fine but whose value varint is a lone 0x80.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.extend(tag(5, 0)); // field 5, wire 0 (VARINT) — a valid tag
    buf.push(0x80); // its value varint runs off the end ⇒ VarInt undef
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a truncated VALUE varint stays fatal (NOT lenient like a LEN length)"
    );
    assert_eq!(
      out.protocol(),
      Some("dvtm_wm265e.proto"),
      "earlier records survive"
    );
  }

  // ── R12-F2: zero-extended (non-canonical) varints decode to their value ──
  // Protobuf.pm:54-72 `VarInt`: `$val += (ord & 0x7f) * $mult` — a ZERO payload
  // group adds 0, never changing the value or making it undef. So a varint with
  // extra high-order ALL-ZERO groups (encoded past bit 63) is the SAME sub-u64
  // value and decodes normally; it is `Overflow` ONLY if a NONZERO payload bit
  // lands at/past bit 64. The continuation-count bound is unchanged: zero-
  // extension past the bound is still `Truncated`.

  /// A varint encoding `v` padded with 14 extra high-order ALL-ZERO continuation
  /// groups, so its highest zero groups land WELL PAST bit 64 (≥ group index 10,
  /// shift ≥ 70) yet its value is unchanged. This genuinely exercises the
  /// `payload != 0` overflow guard: without it, a zero group at `shift >= 64`
  /// would falsely flag overflow. Stays within [`VARINT_MAX_CONTINUATION`] (the
  /// longest canonical form is 10 bytes ⇒ ≤ 24 groups total). The final group is
  /// the terminator (no continuation bit).
  fn enc_varint_zero_extended(v: u64) -> Vec<u8> {
    let mut canon = enc_varint(v);
    // The canonical encoding's last byte has no continuation bit; set it so the
    // zero groups become a continuation OF this varint.
    if let Some(last) = canon.last_mut() {
      *last |= 0x80;
    }
    // 14 high-order zero groups; the final one terminates (no 0x80). With a
    // ≥ 1-byte canonical prefix this puts a zero group at group index ≥ 14
    // (shift ≥ 98) — comfortably past bit 64.
    for _ in 0..13 {
      canon.push(0x80); // zero payload, continues
    }
    canon.push(0x00); // zero payload, terminator
    canon
  }

  #[test]
  fn zero_extended_varint_decodes_to_canonical_value() {
    // UNIT: a zero-extended encoding of 7 (its high groups all zero, past bit 64)
    // decodes to `Value(7)`, NOT `Overflow`. (Each zero group adds 0 in VarInt.)
    let enc = enc_varint_zero_extended(7);
    assert!(
      enc.len() > 10,
      "the encoding genuinely extends past bit 64 (a zero group at shift ≥ 70)"
    );
    let (v, _, rest) = unwrap_value(read_varint(&enc));
    assert_eq!(
      v, 7,
      "zero high groups contribute nothing ⇒ canonical value 7"
    );
    assert!(rest.is_empty(), "the whole varint is consumed");
  }

  #[test]
  fn zero_extended_tag_varint_decodes_to_canonical_value() {
    // A TAG varint zero-extended past bit 64 ⇒ the field decodes (NOT skipped via
    // FIELD_OVERFLOW_SENTINEL). field 5 wire 0 ⇒ key 0x28; zero-extend it.
    let mut buf = enc_varint_zero_extended((5u64 << 3) | 0); // tag key, zero-extended
    buf.extend(enc_varint(42)); // its value
    let (rec, rest) = read_tag(&buf).expect("a zero-extended tag decodes");
    assert_eq!(
      rec.field, 5,
      "the zero-extended tag yields field 5 (NOT the sentinel)"
    );
    assert_eq!(rec.wire, WireType::Varint);
    assert_eq!(rec.varint, 42);
    assert!(!rec.varint_overflow);
    assert!(rest.is_empty());
  }

  #[test]
  fn zero_extended_value_varint_decodes() {
    // A wire-0 VALUE varint with zero high groups ⇒ the canonical value (NOT
    // varint_overflow). Perl-verified: ReadRecord ⇒ value 7.
    let mut buf = tag(5, 0); // field 5, wire 0
    buf.extend(enc_varint_zero_extended(7)); // value 7, zero-extended past bit 64
    let (rec, rest) = read_tag(&buf).expect("decodes");
    assert_eq!(rec.field, 5);
    assert_eq!(rec.wire, WireType::Varint);
    assert_eq!(rec.varint, 7, "the zero-extended value decodes to 7");
    assert!(
      !rec.varint_overflow,
      "a zero-extended value is NOT overflow"
    );
    assert!(rest.is_empty());
    // And it surfaces on a known numeric leaf (TimeStamp 3-1-2 in AVATA2).
    let mut full = Vec::new();
    full.extend(proto_block("dvtm_AVATA2.proto")); // protocol
    let mut ts = tag(2, 0); // 3-1-2 leaf inner field 2, wire 0
    ts.extend(enc_varint_zero_extended(999)); // zero-extended TimeStamp value
    full.extend(nest(3, &[nest(1, &[ts])]));
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&full, &mut dji_st, &mut out);
    assert!(out.first_warning().is_none());
    assert_eq!(
      out
        .samples()
        .first()
        .and_then(DjiTelemetrySample::time_stamp_us),
      Some(999),
      "a zero-extended TimeStamp value decodes (NOT skipped as overflow)"
    );
  }

  #[test]
  fn zero_extended_len_length_decodes() {
    // A LEN LENGTH varint with zero high groups ⇒ reads the body (NOT a false
    // fatal/overflow). Perl-verified: ReadRecord ⇒ body 'ABC'. field 2, length 3
    // zero-extended, then 3 body bytes.
    let mut buf = tag(2, 2); // field 2, wire 2
    buf.extend(enc_varint_zero_extended(3)); // length 3, zero-extended past bit 64
    buf.extend([0x41u8, 0x42, 0x43]); // body "ABC"
    let (rec, rest) = read_tag(&buf).expect("a zero-extended LEN length reads the body");
    assert_eq!(rec.field, 2);
    assert_eq!(rec.wire, WireType::Len);
    assert_eq!(
      rec.payload, b"ABC",
      "the body is read (length decoded from zero-ext)"
    );
    assert!(rest.is_empty());
  }

  #[test]
  fn nonzero_high_bit_still_overflow() {
    // A genuine > u64 value (a NONZERO bit past bit 63) is STILL Overflow — F2
    // only spares zero-extension. 9 × 0x80 (zero) then 0x02 (bit 1 at shift 63
    // ⇒ value bit 64 set). As a tag varint ⇒ the skippable sentinel record.
    let over = enc_varint_over_u64();
    match read_varint(&over) {
      VarintRead::Overflow { low3, .. } => assert_eq!(low3, 0),
      other => panic!("expected Overflow (nonzero high bit), got {other:?}"),
    }
    // As a read_tag tag varint it is the FIELD_OVERFLOW_SENTINEL record.
    let mut tagrec = enc_varint_over_u64();
    tagrec.extend(enc_varint(1)); // its (skipped) wire-0 value
    let (rec, _) = read_tag(&tagrec).expect("a > u64 tag is skippable, not None");
    assert_eq!(rec.field, FIELD_OVERFLOW_SENTINEL);
  }

  #[test]
  fn zero_extended_beyond_continuation_bound_still_truncated() {
    // The continuation bound is UNCHANGED by F2: a zero-extended varint with more
    // than the bound's continuation bytes is still `Truncated` (VarInt undef),
    // exactly like a nonzero over-long varint. 34 × 0x80 (zero payload) + 0x00.
    let mut bad = std::vec![0x80u8; 34];
    bad.push(0x00);
    assert!(
      matches!(read_varint(&bad), VarintRead::Truncated { .. }),
      "zero-extension past the ++$i>32 bound is still Truncated"
    );
    // 33 continuation bytes (within the bound), all zero, terminator ⇒ Value(0).
    let mut ok = std::vec![0x80u8; 33];
    ok.push(0x00);
    let (v, _, _) = unwrap_value(read_varint(&ok));
    assert_eq!(
      v, 0,
      "33 zero groups within the bound ⇒ Value(0), NOT Truncated/Overflow"
    );
  }

  // ── is_protobuf / has_non_printable helpers ──────────────────────────────
  #[test]
  fn is_protobuf_recognises_clean_records_and_rejects_strings() {
    // A clean run of records that exactly consumes the buffer ⇒ protobuf.
    let mut clean = rec_varint(1, 42);
    clean.extend(rec_str(2, "x"));
    assert!(is_protobuf(&clean));
    // A printable string is NOT clean protobuf (its bytes do not parse as
    // exactly-consuming records) and has no non-printable byte.
    let s = b"dvtm_wm265e.proto";
    assert!(
      !has_non_printable(s),
      "a printable string has no control byte"
    );
    // An empty buffer is not protobuf (the first ReadRecord fails).
    assert!(!is_protobuf(&[]));
    // A record declaring more bytes than remain ⇒ not protobuf (ReadRecord fails).
    let mut trunc = tag(1, 2);
    trunc.extend(enc_varint(50)); // 50-byte LEN, no body
    assert!(!is_protobuf(&trunc));
    // Trailing garbage after a valid record ⇒ does not end exactly ⇒ the
    // garbage must itself parse; a lone 0x80 (unterminated varint) fails.
    let mut tail = rec_varint(1, 1);
    tail.push(0x80);
    assert!(!is_protobuf(&tail));
  }

  #[test]
  fn reordered_djmd_printable_len_before_proto_no_warning() {
    // Protobuf field order is NOT fixed. A valid wm265e sample whose `1-1`
    // message carries a PRINTABLE string LEN field (a version string at id 2)
    // BEFORE the `.proto` leaf (id 1). ExifTool skips the printable unknown LEN
    // silently (Protobuf.pm:174 — no non-printable byte ⇒ IsProtobuf never set ⇒
    // `next`), still detects the `.proto` leaf (line 157, which runs before the
    // gate), and decodes the fields after it. The pre-fix walk descended into
    // the printable string (cur=None) ⇒ a FALSE `Protobuf format error`.
    let lvl11_body = {
      let mut v = Vec::new();
      v.extend(rec_str(2, "v01.23.4567")); // printable LEN BEFORE the .proto leaf
      v.extend(rec_str(1, "dvtm_wm265e.proto")); // the protocol leaf
      v.extend(rec_str(5, "SERIAL123")); // 1-1-5 SerialNumber (after .proto)
      v.extend(rec_str(10, "FC8482")); // 1-1-10 Model (after .proto)
      v
    };
    let lvl1 = nest(1, &[rec_len(1, &lvl11_body)]);
    // A GPS fix after the identity block, to prove decoding continues.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0));
      v.extend(rec_i64(3, 8.0));
      v
    };
    let lvl334 = nest(1, &[gps_info]); // 3-3-4-1 GPSInfo
    let lvl3 = nest(3, &[nest(3, &[nest(4, &[lvl334])])]);
    let mut buf = Vec::new();
    buf.extend(lvl1);
    buf.extend(lvl3);

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a printable LEN before the .proto leaf must NOT warn, got {:?}",
      out.first_warning()
    );
    // The protocol is still identified (the `.proto` detection runs regardless).
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    // Fields after the `.proto` leaf still decode.
    assert_eq!(out.serial_number(), Some("SERIAL123"));
    assert_eq!(out.model(), Some("FC8482"));
    let s = out
      .first_fix()
      .expect("the GPS fix after the identity block decodes");
    assert_eq!(s.latitude(), Some(45.0));
    assert_eq!(s.longitude(), Some(8.0));
  }

  #[test]
  fn unknown_len_nonprintable_non_protobuf_skipped_silently() {
    // A wm265e sample with an unknown LEN field at the TOP level (no active
    // protocol context for it yet — id 7) carrying NON-printable bytes that do
    // NOT parse as protobuf (a truncated record: a LEN tag claiming more bytes
    // than present). is_protobuf is false ⇒ ExifTool skips it (Protobuf.pm:175)
    // ⇒ no recurse, NO warning, and the rest of the sample still decodes.
    let opaque = {
      // 0xff 0x00 0x80 — has non-printable bytes; as protobuf the leading
      // varint 0xff,0x00 = key 127 ⇒ wire type 7 (invalid) ⇒ ReadRecord fails
      // ⇒ not protobuf.
      std::vec![0xffu8, 0x00, 0x80]
    };
    assert!(has_non_printable(&opaque));
    assert!(!is_protobuf(&opaque), "invalid wire type ⇒ not protobuf");
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.extend(rec_len(7, &opaque)); // unknown opaque LEN — must be skipped silently
    // A known leaf after it still decodes (TimeStamp not in wm265e; use ISO 3-2-2-1).
    buf.extend(nest(3, &[nest(2, &[nest(2, &[rec_i32(1, 800.0)])])])); // 3-2-2-1 ISO

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert!(
      out.first_warning().is_none(),
      "a non-protobuf opaque LEN is skipped silently, got {:?}",
      out.first_warning()
    );
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(
      out.samples()[0].iso(),
      Some(800.0),
      "the known leaf after the skipped opaque field still decodes"
    );
  }

  #[test]
  fn top_level_malformed_record_still_warns() {
    // The R2 guarantee: a TRULY malformed TOP-LEVEL record (a LEN tag declaring
    // 200 bytes with no body — ReadRecord fails at the top level,
    // Protobuf.pm:156) still raises `Protobuf format error`. The F2 gate only
    // suppresses SPECULATIVE descent into a payload; it must not weaken the
    // top-level read-failure warning.
    let mut bad = tag(4, 2); // field 4, wire 2 (LEN)
    bad.extend(enc_varint(200)); // declares 200 bytes, none follow
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&bad, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a malformed top-level record still warns"
    );
  }

  #[test]
  fn known_nested_submessage_still_decodes_after_gate() {
    // Guard that the F2 gate does NOT break KNOWN sub-message recursion: a
    // wm265e DroneInfo (3-3-3) + GimbalInfo (3-4-3) nested decode still works
    // (the known-branch path recurses unconditionally, like a known
    // SubDirectory). Mirrors `djmd_drone_and_gimbal_orientation` but kept here
    // as an explicit post-gate regression guard.
    let drone = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 5)); // DroneRoll 0.5°
      v.extend(rec_varint(3, 900)); // DroneYaw 90.0°
      v
    };
    let gimbal = nest(3, &[rec_varint(1, 0xffff_ffff_ffff_fed4)]); // GimbalPitch -30.0°
    let lvl3 = {
      let mut v = Vec::new();
      v.extend(nest(3, &[nest(3, &[drone])])); // 3-3-3 DroneInfo
      v.extend(nest(4, &[gimbal])); // 3-4-3 GimbalInfo
      v
    };
    let proto = proto_block("dvtm_wm265e.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(nest(3, &[lvl3]));
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = &out.samples()[0];
    assert_eq!(s.drone_roll_deg(), Some(0.5));
    assert_eq!(s.drone_yaw_deg(), Some(90.0));
    assert_eq!(s.gimbal_pitch_deg(), Some(-30.0));
    assert!(out.first_warning().is_none());
  }

  // ── #221 item-1: the is_branch recursion gate (named vs unnamed) ──────────
  //
  // Protobuf.pm:171-179 (the Unknown-tag IsProtobuf gate) vs :227 (the named
  // SubDirectory unconditional fall-through). Bundled (perl ExifTool 13.59,
  // `ProcessProtobuf` over `%DJI::Protobuf`):
  //   A. corrupt byte INSIDE a NAMED GPSInfo (3-4-2-1) ⇒ `Protobuf format error`
  //      (descended unconditionally; the lat decoded before the byte survives).
  //   B. corrupt byte INSIDE an UNNAMED wrapper (3-4-2) ⇒ NO warning (the
  //      IsProtobuf gate fails on the corrupt container ⇒ never descended).
  //   C. clean ⇒ no warning.
  // The pre-fix port recursed UNCONDITIONALLY on any `is_branch` prefix, so case
  // B emitted a SPURIOUS `Protobuf format error` bundled suppresses.

  /// CASE B (the fix): a corrupt byte buried in an UNNAMED intermediate
  /// container (`3-4-2`, the parent of GPSAltitude `3-4-2-2` and GPSInfo
  /// `3-4-2-1`) must be SKIPPED SILENTLY — no `Protobuf format error` — matching
  /// bundled, which reaches `3-4-2` only via the speculative IsProtobuf gate and
  /// finds the corrupt container is not clean protobuf.
  #[test]
  fn corrupt_byte_in_unnamed_container_suppresses_format_error() {
    // 3-4-2 body: a valid GPSAltitude leaf (field 2 = varint) then a lone 0x80
    // (an unterminated varint) ⇒ the container does NOT parse cleanly as
    // protobuf ⇒ the IsProtobuf gate fails ⇒ no descent ⇒ no error.
    let unnamed_342 = {
      let mut v = rec_varint(2, 105_500); // 3-4-2-2 GPSAltitude (would be 105.5 m)
      v.push(0x80); // CORRUPT trailing byte
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[nest(4, &[rec_len(2, &unnamed_342)])])); // 3 -> 4 -> 2

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    // Identity still extracted (the `1-1` block is clean and precedes the wrapper).
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    assert_eq!(out.serial_number(), Some("SERIAL123"));
    // The spurious error is SUPPRESSED (bundled-verified: WARNINGS: (none)).
    assert!(
      out.first_warning().is_none(),
      "a corrupt byte in an UNNAMED wrapper must NOT warn (bundled suppresses), got {:?}",
      out.first_warning()
    );
    // The GPSAltitude leaf inside the never-descended wrapper is NOT extracted
    // (bundled extracts only Protocol + SerialNumber here).
    assert_eq!(out.samples()[0].absolute_altitude_m(), None);
  }

  /// CASE A (unchanged): a corrupt byte buried in a NAMED SubDirectory (GPSInfo
  /// at `3-4-2-1`) IS descended unconditionally (a SubDirectory tag is never
  /// `Unknown`, so the IsProtobuf gate does not apply — Protobuf.pm:227), so the
  /// read failure DOES surface a `Protobuf format error`, and the coordinate
  /// decoded before the corrupt byte survives — byte-for-byte bundled.
  #[test]
  fn corrupt_byte_in_named_subdir_still_warns() {
    // GPSInfo (3-4-2-1) body: CoordinateUnits=1 (degrees), GpsLatitude=45.0,
    // then a lone 0x80 corrupt byte.
    let gps_info = {
      let mut v = rec_varint(1, 1); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // GpsLatitude
      v.push(0x80); // CORRUPT trailing byte
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    // 3 -> 4 -> 2 -> 1 (GPSInfo named SubDirectory).
    buf.extend(nest(3, &[nest(4, &[nest(2, &[rec_len(1, &gps_info)])])]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    // The named SubDirectory IS descended ⇒ the read failure warns (bundled:
    // WARNINGS: Protobuf format error).
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a corrupt byte in a NAMED SubDirectory DOES warn (descended unconditionally)"
    );
    // The latitude decoded BEFORE the corrupt byte survives (bundled:
    // GPSLatitude = 45). ac203 GPSInfo has no force-degrees, units=1 ⇒ degrees.
    assert_eq!(out.samples()[0].latitude(), Some(45.0));
  }

  /// CASE C (control): a CLEAN named GPSInfo under an unnamed wrapper decodes
  /// the coordinates with no warning — the unnamed wrapper passes the IsProtobuf
  /// gate (it is clean protobuf) and the named GPSInfo is then descended.
  #[test]
  fn clean_named_subdir_under_unnamed_wrapper_decodes() {
    let gps_info = {
      let mut v = rec_varint(1, 1); // degrees
      v.extend(rec_i64(2, 45.0));
      v.extend(rec_i64(3, 8.0));
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[nest(4, &[nest(2, &[rec_len(1, &gps_info)])])])); // 3-4-2-1

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert!(out.first_warning().is_none(), "clean input must not warn");
    let s = &out.samples()[0];
    assert_eq!(s.latitude(), Some(45.0));
    assert_eq!(s.longitude(), Some(8.0));
  }

  /// The named SubDirectory descent is INDEPENDENT of an enclosing unnamed
  /// wrapper's own corruption: a corrupt byte buried in the unnamed wrapper
  /// AFTER a clean GPSInfo child still makes the WRAPPER fail the IsProtobuf gate
  /// ⇒ the wrapper (and the clean child within it) is never descended ⇒ no
  /// warning, no GPS — exactly bundled (the gate examines the WHOLE wrapper).
  #[test]
  fn corrupt_byte_after_clean_child_in_unnamed_wrapper_suppresses() {
    let gps_info = {
      let mut v = rec_varint(1, 1);
      v.extend(rec_i64(2, 45.0));
      v.extend(rec_i64(3, 8.0));
      v
    };
    // 3-4-2 body: a clean GPSInfo child (field 1) THEN a corrupt 0x80.
    let unnamed_342 = {
      let mut v = rec_len(1, &gps_info); // 3-4-2-1 GPSInfo (clean)
      v.push(0x80); // CORRUPT byte in the WRAPPER, after the clean child
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[nest(4, &[rec_len(2, &unnamed_342)])]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert!(
      out.first_warning().is_none(),
      "a corrupt wrapper fails the IsProtobuf gate as a whole ⇒ no descent, no warning, got {:?}",
      out.first_warning()
    );
    // The clean GPSInfo inside the rejected wrapper is NOT reached.
    assert_eq!(out.samples()[0].latitude(), None);
  }

  // ── #221 item-1 follow-up: the STICKY `IsProtobuf` tri-state ──────────────
  //
  // Protobuf.pm:171-179 stores `IsProtobuf` on the UNNAMED wrapper's `$tagInfo`
  // (keyed by the full path) and reuses it across EVERY payload at that path for
  // the directory's lifetime. The pre-fix port recomputed `has_non_printable &&
  // is_protobuf` per payload (STATELESS), so it would re-decode a later clean
  // payload that ExifTool suppresses after a corrupt one flipped the path to
  // sticky-false.
  //
  // Oracle (perl ExifTool 13.59, `ProcessProtobuf` over `%DJI::Protobuf`, default
  // `Unknown = 0`) — a `dvtm_ac203` sample whose `3-4` message repeats the
  // UNNAMED `3-4-2` wrapper three times, each holding a named GPSInfo (`3-4-2-1`):
  //   clean(45N,8E) → corrupt → clean(46N,9E)  ⇒  raw VALUE hash:
  //     GPSLatitude = 45, GPSLongitude = 8   (the 2nd clean SUPPRESSED), no Warning
  //   corrupt → clean(45N,8E) → clean(46N,9E)  ⇒  raw VALUE hash:
  //     GPSLatitude = 46 (last-wins) + GPSLatitude(1) = 45  (BOTH cleans extracted)
  // The difference is entirely the sticky `Yes → No` flip: a corrupt payload
  // after a clean one makes the path defined-false, suppressing all later cleans;
  // a corrupt payload BEFORE any clean leaves the path unevaluated (not sticky).

  /// The reviewer's exact regression — a REPEATED unnamed `3-4-2` wrapper
  /// (clean → corrupt → clean). The first clean payload proves the path is
  /// protobuf (`Yes`); the corrupt payload flips it to STICKY `No`; the second
  /// clean payload is SUPPRESSED (not re-decoded). So the per-sample latitude
  /// retains the FIRST clean coordinate (45), NOT the second (46) — matching
  /// bundled's `GPSLatitude = 45`. The stateless pre-fix gate would have decoded
  /// the second clean wrapper and overwritten latitude to 46 (last-wins).
  #[test]
  fn sticky_isprotobuf_suppresses_clean_payload_after_corrupt_flip() {
    // Three repeated `3-4-2` wrappers under one `3-4` message.
    let gps_a = {
      let mut v = rec_varint(1, 1); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // GpsLatitude
      v.extend(rec_i64(3, 8.0)); // GpsLongitude
      v
    };
    let gps_c = {
      let mut v = rec_varint(1, 1);
      v.extend(rec_i64(2, 46.0));
      v.extend(rec_i64(3, 9.0));
      v
    };
    let wrap_clean_a = rec_len(1, &gps_a); // 3-4-2 holding a clean GPSInfo (45,8)
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500); // 3-4-2-2 GPSAltitude leaf
      v.push(0x80); // CORRUPT trailing byte ⇒ NOT clean protobuf
      v
    };
    let wrap_clean_c = rec_len(1, &gps_c); // 3-4-2 holding a clean GPSInfo (46,9)
    // 3 -> 4 -> [ (2: clean A), (2: corrupt), (2: clean C) ]
    let field4 = {
      let mut v = rec_len(2, &wrap_clean_a);
      v.extend(rec_len(2, &wrap_corrupt));
      v.extend(rec_len(2, &wrap_clean_c));
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[rec_len(4, &field4)]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    // No `Protobuf format error` — the corrupt wrapper is judged by the
    // IsProtobuf gate, never descended (bundled: WARNINGS (none)).
    assert!(
      out.first_warning().is_none(),
      "the corrupt wrapper must not warn (gated, not descended), got {:?}",
      out.first_warning()
    );
    // The 2nd clean wrapper is SUPPRESSED by the sticky-false flip ⇒ latitude is
    // the FIRST clean coordinate (45), exactly bundled's `GPSLatitude = 45`. A
    // stateless gate would have decoded the 2nd clean wrapper ⇒ latitude 46.
    let s = &out.samples()[0];
    assert_eq!(
      s.latitude(),
      Some(45.0),
      "sticky IsProtobuf must suppress the 2nd clean payload (bundled keeps 45)"
    );
    assert_eq!(s.longitude(), Some(8.0));
  }

  /// The contrast that pins the transition: corrupt-FIRST then clean → clean. A
  /// corrupt payload reaching an UNEVALUATED path does NOT set it sticky-false
  /// (ExifTool's `elsif` only ASSIGNS `IsProtobuf = 1`; a failed evaluation
  /// leaves it undef). So the first clean payload sets it `Yes` and the second
  /// stays `Yes` — BOTH decode, latitude last-wins to 46 — matching bundled's
  /// `GPSLatitude = 46` (+ duplicate 45). This proves the suppression in the
  /// previous test is the `Yes → No` flip, not merely "a corrupt sibling exists".
  #[test]
  fn corrupt_first_leaves_path_unevaluated_both_cleans_decode() {
    let gps_a = {
      let mut v = rec_varint(1, 1);
      v.extend(rec_i64(2, 45.0));
      v.extend(rec_i64(3, 8.0));
      v
    };
    let gps_c = {
      let mut v = rec_varint(1, 1);
      v.extend(rec_i64(2, 46.0));
      v.extend(rec_i64(3, 9.0));
      v
    };
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500);
      v.push(0x80);
      v
    };
    // 3 -> 4 -> [ (2: corrupt FIRST), (2: clean 45), (2: clean 46) ]
    let field4 = {
      let mut v = rec_len(2, &wrap_corrupt);
      v.extend(rec_len(2, &rec_len(1, &gps_a)));
      v.extend(rec_len(2, &rec_len(1, &gps_c)));
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[rec_len(4, &field4)]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert!(out.first_warning().is_none());
    // Both clean wrappers decode (the corrupt-first never flipped the path
    // sticky-false) ⇒ latitude last-wins to the SECOND clean coordinate (46),
    // matching bundled's `GPSLatitude = 46`.
    let s = &out.samples()[0];
    assert_eq!(
      s.latitude(),
      Some(46.0),
      "corrupt-first leaves the path unevaluated ⇒ both cleans decode, last-wins 46"
    );
    assert_eq!(s.longitude(), Some(9.0));
  }

  /// The sticky verdict PERSISTS across `process_djmd` samples WITHIN one track
  /// (ExifTool's per-`$dirName` tag table outlives each `ProcessProtobuf` call).
  /// Sample 1: clean `3-4-2` (→ `Yes`) then corrupt `3-4-2` (→ sticky `No`).
  /// Sample 2 (SAME `DjiTrackState`, no `.proto` of its own — decodes under the
  /// track-persisted `dvtm_ac203`): a clean `3-4-2` must be SUPPRESSED, because
  /// the path is already sticky-false from sample 1.
  #[test]
  fn sticky_isprotobuf_persists_across_samples_in_a_track() {
    let gps = |lat: f64, lon: f64| {
      let mut v = rec_varint(1, 1);
      v.extend(rec_i64(2, lat));
      v.extend(rec_i64(3, lon));
      v
    };
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500);
      v.push(0x80);
      v
    };
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();

    // Sample 1: carries the `.proto` leaf, then a clean `3-4-2` (45,8) then a
    // corrupt `3-4-2` ⇒ the `3-4-2` path flips Yes → sticky No.
    let mut s1 = proto_block("dvtm_ac203.proto");
    let field4_s1 = {
      let mut v = rec_len(2, &rec_len(1, &gps(45.0, 8.0)));
      v.extend(rec_len(2, &wrap_corrupt));
      v
    };
    s1.extend(nest(3, &[rec_len(4, &field4_s1)]));
    process_djmd(&s1, &mut dji_st, &mut out);
    assert_eq!(out.samples()[0].latitude(), Some(45.0), "sample 1 keeps 45");

    // Sample 2: NO `.proto` leaf (decodes under the track-persisted protocol),
    // a single CLEAN `3-4-2` (46,9). The `3-4-2` path is already sticky-false
    // from sample 1 ⇒ this clean wrapper is SUPPRESSED (no GPS on sample 2).
    let s2 = nest(3, &[rec_len(4, &rec_len(2, &rec_len(1, &gps(46.0, 9.0))))]);
    process_djmd(&s2, &mut dji_st, &mut out);
    assert_eq!(
      out.samples()[1].latitude(),
      None,
      "sample 2's clean wrapper is suppressed by sample 1's sticky-false verdict"
    );
    assert!(out.first_warning().is_none());
  }

  /// FINDING-1: the sticky cache is keyed by the RAW active `ProtoPrefix`
  /// (`$$et{ProtoPrefix}{$dirName}`, Protobuf.pm:162), NOT the RESOLVED known
  /// [`Protocol`]. So a sticky-`No` flip established under one UNKNOWN `.proto`
  /// must NOT suppress a clean wrapper at the SAME field path under a DISTINCT
  /// unknown `.proto`: ExifTool interpolates the prefix STRING into `$tag`, so
  /// `dvtm_unknownA_…` and `dvtm_unknownB_…` are DIFFERENT tag keys → DIFFERENT
  /// `$tagInfo` → independent verdicts. The buggy key (`cur.map(|p| p.name)`)
  /// resolved BOTH unknown prefixes to `None` (same bucket as the empty prefix),
  /// so B's clean wrapper was wrongly suppressed and the nested `.proto` it would
  /// otherwise descend into was never reached.
  ///
  /// Observable: under unknown protocol B, the same-path wrapper is a CLEAN
  /// protobuf message whose body is a nested `.proto` leaf for a THIRD distinct
  /// unknown protocol C. If B's wrapper is EVALUATED (the fix — fresh
  /// `(unknownB, path)` key) it recurses and the C `.proto` leaf fires the
  /// unknown-protocol warning (DJI.pm:259-266); if it were SUPPRESSED (the bug —
  /// shared `None` key, sticky-`No` from A) the C leaf is never reached and no C
  /// warning appears.
  #[test]
  fn sticky_isprotobuf_unknown_prefixes_keyed_distinctly() {
    // Field 5 is an UNNAMED wrapper path: under an UNKNOWN protocol the table is
    // `None`, so NO field is a known leaf / named SubDirectory and EVERY LEN
    // record reaches the `unnamed_wrapper_should_recurse` gate.
    let clean_inert = rec_varint(1, 1); // clean protobuf, non-printable (08 01)
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500); // a LEN body that is NOT clean protobuf
      v.push(0x80); // trailing continuation byte ⇒ IsProtobuf false
      v
    };
    // B's same-path wrapper body: clean protobuf carrying a nested `.proto` leaf
    // for unknown protocol C, FOLLOWED by a benign trailing field so the body does
    // NOT itself end in `.proto` (keeping `walk`'s unconditional Protobuf.pm:157
    // `proto_suffix` check from switching on the wrapper's own payload). The C
    // `.proto` leaf — and thus C's unknown-protocol warning — is reached ONLY by
    // DESCENDING the body, i.e. only if the wrapper is EVALUATED+recursed (not
    // suppressed by A's sticky-No under a shared key).
    let nested_c_leaf = {
      let mut v = rec_str(1, "dvtm_unknownC.proto");
      v.extend(rec_varint(99, 0)); // benign trailing field ⇒ body !ends_with .proto
      v
    };

    let mut buf = Vec::new();
    // Switch to UNKNOWN protocol A (table `None`); A warns once.
    buf.extend(rec_str(7, "dvtm_unknownA.proto"));
    // (unknownA, [5]) Yes (clean) then → sticky No (corrupt).
    buf.extend(rec_len(5, &clean_inert));
    buf.extend(rec_len(5, &wrap_corrupt));
    // Switch to a DISTINCT UNKNOWN protocol B (table `None`); B warns.
    buf.extend(rec_str(7, "dvtm_unknownB.proto"));
    // (unknownB, [5]) is a FRESH key under the fix ⇒ EVALUATED ⇒ recurse ⇒ C.
    buf.extend(rec_len(5, &nested_c_leaf));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    let saw = |needle: &str| out.warnings().iter().any(|w| w.message().contains(needle));
    assert!(
      saw("dvtm_unknownA.proto"),
      "A is an unknown protocol — warns"
    );
    assert!(
      saw("dvtm_unknownB.proto"),
      "B is an unknown protocol — warns"
    );
    assert!(
      saw("dvtm_unknownC.proto"),
      "B's clean same-path wrapper must be EVALUATED under its OWN prefix key (not \
       suppressed by A's sticky-No) ⇒ recursion reaches the nested C `.proto` leaf; \
       the buggy shared-`None` key would suppress it. warnings: {:?}",
      out
        .warnings()
        .iter()
        .map(|w| w.message())
        .collect::<Vec<_>>()
    );
  }

  /// FINDING-2: a sticky-`No` path SHORT-CIRCUITS — it is skipped from the cache
  /// WITHOUT scanning the payload (`has_non_printable` / `is_protobuf`), matching
  /// ExifTool's `next unless $$tagInfo{IsProtobuf}` for a defined-false tag (which
  /// fires NEITHER the `if` re-check NOR the `elsif`, so `IsProtobuf` is never
  /// called, Protobuf.pm:172-179). The behavioural proxy for "no predicate
  /// re-evaluation": the post-flip payload is itself CLEAN protobuf with a
  /// non-printable byte AND carries a nested `.proto` leaf — so IF the predicates
  /// were re-evaluated as-if-unevaluated it would re-flip to `Yes` and recurse
  /// (firing the nested protocol's warning). The sticky-`No` short-circuit skips
  /// it instead, so NO nested warning appears and the wrapper is suppressed —
  /// proving the cache verdict, not a fresh predicate eval, decided the skip.
  #[test]
  fn sticky_isprotobuf_no_short_circuits_before_payload_scan() {
    let gps = |lat: f64, lon: f64| {
      let mut v = rec_varint(1, 1); // CoordinateUnits = degrees
      v.extend(rec_i64(2, lat)); // 3-4-2-1-2 GpsLatitude
      v.extend(rec_i64(3, lon)); // 3-4-2-1-3 GpsLongitude
      v
    };
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500);
      v.push(0x80); // ⇒ NOT clean protobuf ⇒ flips the 3-4-2 path Yes → No
      v
    };
    // The post-flip 3-4-2 wrapper body: CLEAN protobuf (so a fresh mis-evaluation
    // would flip it back to Yes and recurse) carrying a nested `.proto` leaf for
    // unknown protocol Z, FOLLOWED by a benign trailing field. The trailing field
    // keeps the body from ENDING in `.proto`, so `walk`'s unconditional
    // `proto_suffix` check (Protobuf.pm:157) does NOT switch on the wrapper's own
    // payload — the Z `.proto` leaf is reached (firing Z's warning) ONLY by
    // DESCENDING into the body, i.e. only if the wrapper is recursed. Under the
    // correct sticky-`No` short-circuit the body is never scanned/descended ⇒ Z
    // never fires.
    let post_flip = {
      let mut v = rec_str(1, "dvtm_unknownZ.proto");
      v.extend(rec_varint(99, 0)); // benign trailing field ⇒ body !ends_with .proto
      v
    };

    // 3 -> 4 -> [ (2: clean GPSInfo 45,8), (2: corrupt), (2: clean nested-Z) ]
    let field4 = {
      let mut v = rec_len(2, &rec_len(1, &gps(45.0, 8.0)));
      v.extend(rec_len(2, &wrap_corrupt));
      v.extend(rec_len(2, &post_flip));
      v
    };
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[rec_len(4, &field4)]));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    // Suppression holds (latitude is the FIRST clean coordinate only).
    let s = &out.samples()[0];
    assert_eq!(
      s.latitude(),
      Some(45.0),
      "3-4-2 sticky-No suppresses later wrappers"
    );
    assert_eq!(s.longitude(), Some(8.0));
    // The short-circuit proof: the clean post-flip payload was NOT scanned/
    // descended (no fresh predicate eval re-flipped it to Yes), so its nested Z
    // `.proto` leaf never fired ⇒ no Z warning.
    assert!(
      !out
        .warnings()
        .iter()
        .any(|w| w.message().contains("dvtm_unknownZ.proto")),
      "a sticky-No path must short-circuit BEFORE scanning the payload — the clean \
       nested-`.proto` body must NOT be descended; warnings: {:?}",
      out
        .warnings()
        .iter()
        .map(|w| w.message())
        .collect::<Vec<_>>()
    );

    // Direct method-level guard on the short-circuit ORDER: seed a sticky-`No`
    // verdict for a (prefix, path), then call the gate with a CLEAN-protobuf,
    // non-printable payload (one that, evaluated fresh, would assign `Yes`). The
    // sticky-`No` arm must return `false` AND leave the cached verdict `No` —
    // i.e. the cache is consulted FIRST and the predicates are never reached. A
    // structuring that evaluated `has_non_printable`/`is_protobuf` before the
    // cache (the FINDING-2 ordering bug) could re-flip the entry to `Yes`.
    let mut st = DjiTrackState::new();
    let path = std::vec![3u64, 4, 2];
    st.is_protobuf_cache
      .insert((None, path.clone()), IsProtobufVerdict::No);
    let clean = rec_varint(1, 1); // is_protobuf == true, has_non_printable == true
    assert!(is_protobuf(&clean) && has_non_printable(&clean));
    assert!(
      !st.unnamed_wrapper_should_recurse(&path, &clean),
      "sticky-No must suppress even a clean payload"
    );
    assert_eq!(
      st.is_protobuf_cache.get(&(None, path)),
      Some(&IsProtobufVerdict::No),
      "sticky-No must NOT be re-evaluated/flipped by a later clean payload — the \
       cache short-circuits before the predicate path that assigns Yes"
    );
  }

  /// FINDING (R2 sticky-cache, non-UTF-8 prefix class): the sticky cache is keyed
  /// by the byte-EXACT active `ProtoPrefix` (`substr($buff, 0, -6) . '_'`,
  /// Protobuf.pm:159/162), NOT the lossy DISPLAY string. Two DISTINCT non-UTF-8
  /// `.proto` prefixes that differ ONLY in a high byte — `\xff.proto` and
  /// `\xfe.proto` — are DIFFERENT `ProtoPrefix` in ExifTool (`\xff_` vs `\xfe_`)
  /// and so key DIFFERENT `$tagInfo` → independent verdicts. The buggy lossy-string
  /// key ([`String::from_utf8_lossy`]) rendered BOTH to the same replacement-char
  /// display (`\u{FFFD}.proto`), collapsing them to one bucket — so a sticky-`No`
  /// flip under `\xff.proto` wrongly suppressed a clean same-path wrapper under
  /// `\xfe.proto`.
  ///
  /// Observable (mirrors FINDING-1): under `\xfe.proto` the same-path wrapper is a
  /// CLEAN protobuf whose body nests a `.proto` leaf for a THIRD distinct unknown
  /// protocol C. With the byte-exact key (`\xfe_` ≠ `\xff_`) B's wrapper is a fresh
  /// key ⇒ EVALUATED ⇒ recurses ⇒ the C leaf fires C's unknown-protocol warning;
  /// the buggy shared lossy key would suppress it (no C warning). C's name is the
  /// discriminator because A's and B's OWN warnings render to the identical lossy
  /// text and cannot be told apart.
  #[test]
  fn sticky_isprotobuf_non_utf8_prefixes_keyed_distinctly() {
    let clean_inert = rec_varint(1, 1); // clean protobuf, non-printable (08 01)
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500); // a LEN body that is NOT clean protobuf
      v.push(0x80); // trailing continuation byte ⇒ IsProtobuf false
      v
    };
    // B's same-path wrapper body: clean protobuf carrying a nested `.proto` leaf
    // for unknown protocol C, then a benign trailing field so the body itself does
    // NOT end in `.proto` (keeping `walk`'s unconditional Protobuf.pm:157 switch
    // from firing on the wrapper's own payload). C is reached ONLY by DESCENDING.
    let nested_c_leaf = {
      let mut v = rec_str(1, "dvtm_unknownC.proto");
      v.extend(rec_varint(99, 0));
      v
    };
    // Two non-UTF-8 `.proto` prefixes differing only in the leading high byte.
    // Both render via from_utf8_lossy to the SAME `\u{FFFD}.proto` display string,
    // but their RAW `ProtoPrefix` (`\xff_` vs `\xfe_`) is distinct.
    let ff_proto = std::vec![0xffu8, b'.', b'p', b'r', b'o', b't', b'o'];
    let fe_proto = std::vec![0xfeu8, b'.', b'p', b'r', b'o', b't', b'o'];
    assert!(
      core::str::from_utf8(&ff_proto).is_err() && core::str::from_utf8(&fe_proto).is_err(),
      "both prefixes must be non-UTF-8 (the lossy-collision precondition)"
    );

    let mut buf = Vec::new();
    // Switch to non-UTF-8 protocol A (`\xff.proto` ⇒ raw prefix `\xff_`); A warns.
    buf.extend(rec_len(7, &ff_proto));
    // (\xff_, [5]) Yes (clean) then → sticky No (corrupt).
    buf.extend(rec_len(5, &clean_inert));
    buf.extend(rec_len(5, &wrap_corrupt));
    // Switch to a DISTINCT non-UTF-8 protocol B (`\xfe.proto` ⇒ raw prefix `\xfe_`).
    buf.extend(rec_len(7, &fe_proto));
    // (\xfe_, [5]) is a FRESH key under the byte-exact fix ⇒ EVALUATED ⇒ C.
    buf.extend(rec_len(5, &nested_c_leaf));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    let saw = |needle: &str| out.warnings().iter().any(|w| w.message().contains(needle));
    // A and B both render to the identical lossy text, so this single check
    // confirms the non-UTF-8 protocol warned (at least once).
    assert!(
      saw("\u{FFFD}.proto"),
      "a non-UTF-8 protocol warns under its lossy-rendered name"
    );
    assert!(
      saw("dvtm_unknownC.proto"),
      "B's clean same-path wrapper must be EVALUATED under its OWN byte-exact prefix \
       key `\\xfe_` (not suppressed by A's `\\xff_` sticky-No — the buggy lossy key \
       collapsed both to `\u{FFFD}.proto`) ⇒ recursion reaches the nested C `.proto` \
       leaf. warnings: {:?}",
      out
        .warnings()
        .iter()
        .map(|w| w.message())
        .collect::<Vec<_>>()
    );

    // Direct key-identity guard: the two non-UTF-8 prefixes seed DISTINCT raw-byte
    // cache keys, so the entries coexist (the lossy-string key would have produced
    // ONE entry shared by both).
    let mut st = DjiTrackState::new();
    st.set_raw_proto_prefix(&ff_proto);
    let key_ff = st.raw_proto_prefix.clone();
    st.set_raw_proto_prefix(&fe_proto);
    let key_fe = st.raw_proto_prefix.clone();
    assert_eq!(
      key_ff.as_deref(),
      Some(&b"\xff_"[..]),
      "`\\xff.proto` ⇒ `\\xff_`"
    );
    assert_eq!(
      key_fe.as_deref(),
      Some(&b"\xfe_"[..]),
      "`\\xfe.proto` ⇒ `\\xfe_`"
    );
    assert_ne!(
      key_ff, key_fe,
      "distinct non-UTF-8 prefixes must yield DISTINCT raw-byte cache keys"
    );
  }

  /// FINDING (R2 sticky-cache, suffix-edge class): ExifTool's `ProtoPrefix` strips
  /// the LAST 6 BYTES of the matched `.proto` payload (`substr($buff, 0, -6)`,
  /// Protobuf.pm:159), so the two suffix edges `X..proto` and `X.proto\n` collapse
  /// to the SAME `ProtoPrefix` `X._` (`X..proto` drops `.proto`; `X.proto\n` drops
  /// `proto\n`, both leaving `X.`). They therefore SHARE one sticky `$tagInfo`. The
  /// buggy full-DISPLAY-string key kept them DISTINCT (`X..proto` ≠ `X.proto\n`),
  /// wrongly evaluating the second fresh.
  ///
  /// Observable (inverse of the non-UTF-8 test): under `X..proto` the path-`[5]`
  /// wrapper flips Yes → sticky-`No`; then a `X.proto\n` leaf switches to the SAME
  /// raw prefix `X._`; the same-path-`[5]` wrapper — a clean body nesting a C
  /// `.proto` leaf — must be SUPPRESSED by the shared sticky-`No` ⇒ NO C warning.
  /// The buggy full-string key would give `X.proto\n` a fresh bucket ⇒ evaluate ⇒
  /// fire C.
  #[test]
  fn sticky_isprotobuf_suffix_edges_share_raw_prefix_key() {
    let clean_inert = rec_varint(1, 1);
    let wrap_corrupt = {
      let mut v = rec_varint(2, 105_500);
      v.push(0x80);
      v
    };
    let nested_c_leaf = {
      let mut v = rec_str(1, "dvtm_unknownC.proto");
      v.extend(rec_varint(99, 0));
      v
    };
    // `dvtm_aa..proto` (strip `.proto` ⇒ `dvtm_aa.` + `_`) and `dvtm_aa.proto\n`
    // (strip `proto\n` ⇒ `dvtm_aa.` + `_`) ⇒ the SAME raw `ProtoPrefix` `dvtm_aa._`,
    // but DISTINCT full display strings.
    let dot_proto = b"dvtm_aa..proto".to_vec();
    let proto_nl = b"dvtm_aa.proto\n".to_vec();
    assert!(
      proto_suffix(&dot_proto).is_some() && proto_suffix(&proto_nl).is_some(),
      "both edges must match Perl `/\\.proto$/`"
    );

    let mut buf = Vec::new();
    buf.extend(rec_len(7, &dot_proto)); // switch to raw prefix `dvtm_aa._`
    buf.extend(rec_len(5, &clean_inert)); // (dvtm_aa._, [5]) Yes
    buf.extend(rec_len(5, &wrap_corrupt)); //               → sticky No
    buf.extend(rec_len(7, &proto_nl)); // switch to the SAME raw prefix `dvtm_aa._`
    buf.extend(rec_len(5, &nested_c_leaf)); // (dvtm_aa._, [5]) sticky No ⇒ SUPPRESSED

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert!(
      !out
        .warnings()
        .iter()
        .any(|w| w.message().contains("dvtm_unknownC.proto")),
      "`X..proto` and `X.proto\\n` share the raw `ProtoPrefix` `dvtm_aa._`, so the \
       second wrapper inherits the first's sticky-No and must NOT descend (the buggy \
       full-string key would evaluate it fresh and fire C). warnings: {:?}",
      out
        .warnings()
        .iter()
        .map(|w| w.message())
        .collect::<Vec<_>>()
    );

    // Direct key-identity guard: both suffix edges produce the IDENTICAL raw-byte
    // cache key `dvtm_aa._` (the full-string key would have differed).
    let mut st = DjiTrackState::new();
    st.set_raw_proto_prefix(&dot_proto);
    let key_dot = st.raw_proto_prefix.clone();
    st.set_raw_proto_prefix(&proto_nl);
    let key_nl = st.raw_proto_prefix.clone();
    assert_eq!(
      key_dot.as_deref(),
      Some(&b"dvtm_aa._"[..]),
      "`dvtm_aa..proto` strips its last 6 bytes ⇒ `dvtm_aa._`"
    );
    assert_eq!(
      key_nl, key_dot,
      "`dvtm_aa.proto\\n` strips its last 6 bytes ⇒ the SAME `dvtm_aa._` raw key"
    );
  }

  // ── #221 items 2-4: deliberate hostile-input drops (NOT misrepresented) ───

  /// item-2: a VALUE varint that overflows `u64` in a known numeric leaf is
  /// DROPPED (`varint_value` → `None`), NOT folded into a lossy double. ExifTool
  /// carries the lossy double through the ÷ ValueConv; this typed surface refuses
  /// to fabricate it. Real DJI varints are never ≥ 2^64. Documented at
  /// [`Record::varint_overflow`] / [`varint_value`].
  #[test]
  fn item2_value_varint_over_u64_is_dropped_not_lossy() {
    // ColorTemperature (3-2-6-1, Format=unsigned VARINT) with a > u64 value:
    // 9×0x80 then a terminating 0x02 (bit 1 lands at bit 64 ⇒ Overflow).
    let over = {
      let mut v = std::vec![0x80u8; 9];
      v.push(0x02);
      v
    };
    let mut ct_body = tag(1, 0); // 3-2-6-1, wire 0 (varint)
    ct_body.extend_from_slice(&over);
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(3, &[nest(2, &[nest(6, &[ct_body])])])); // 3-2-6-1

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    // The leaf is DROPPED (None) — not a wrapped/garbage value, not a warning.
    assert_eq!(
      out.samples()[0].color_temperature(),
      None,
      "a > u64 varint leaf is dropped, not misrepresented"
    );
    assert!(
      out.first_warning().is_none(),
      "the overflow is silent (walk continues)"
    );
    // Identity before it is unaffected (the overflow varint was consumed whole).
    assert_eq!(out.serial_number(), Some("SERIAL123"));
  }

  /// item-3: a packed rational whose numerator/denominator varint overflows
  /// `u64` emits the `'err'` sentinel (a PRESENT reading), NOT ExifTool's lossy
  /// quotient. Documented at [`decode_rational`]. Verified directly on the
  /// decoder (the `RationalValue::Err` contract).
  #[test]
  fn item3_rational_over_u64_is_err_sentinel() {
    // A rational body whose numerator varint is > u64 (Overflow): 9×0x80 + 0x02.
    let over = {
      let mut v = std::vec![0x80u8; 9];
      v.push(0x02);
      v
    };
    // num = overflow, den = 1 (the den read does not matter — num already Err).
    let mut body = over.clone();
    body.extend(enc_varint(1));
    assert_eq!(
      decode_rational(&body),
      RationalValue::Err,
      "a > u64 numerator ⇒ 'err' sentinel (not the lossy quotient)"
    );
    // And a > u64 DENOMINATOR likewise ⇒ err.
    let mut body2 = enc_varint(1);
    body2.extend_from_slice(&over);
    assert_eq!(decode_rational(&body2), RationalValue::Err);
  }

  /// item-4: an absurd `> u32::MAX` value in a typed-u32 leaf
  /// (ColorTemperature / FrameWidth / FrameHeight) is DROPPED by the `u32`
  /// narrowing (`u32::try_from(..).ok()` → None), NOT truncated to a wrong u32.
  /// ExifTool emits the full u64; such values are physically impossible. The
  /// `varint_value` itself is fine (≤ u64) — only the typed narrowing drops it.
  #[test]
  fn item4_over_u32_typed_leaf_is_dropped() {
    // FrameWidth (2-3-1 FrameInfo, unsigned VARINT) = 0x1_0000_0000 (> u32::MAX,
    // ≤ u64). The varint decodes fine; the u32 store drops it.
    let big: u64 = 0x1_0000_0000;
    let mut buf = proto_block("dvtm_ac203.proto");
    buf.extend(nest(2, &[nest(3, &[rec_varint(1, big)])])); // 2-3-1 FrameWidth

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert_eq!(
      out.samples()[0].frame_width(),
      None,
      "a > u32::MAX FrameWidth is dropped by the typed narrowing, not truncated"
    );
    assert!(out.first_warning().is_none());
  }

  // ── R3-F1: single-pass sequential prefix is active-at-position ───────────
  #[test]
  fn djmd_protocol_change_mid_track_uses_active_prefix() {
    // ExifTool's `ProcessProtobuf` is a SINGLE sequential loop: a `.proto`
    // record UPDATES `$$et{ProtoPrefix}{$dirName}` (Protobuf.pm:159) at ITS
    // position, so records BEFORE it decode under the prior prefix and records
    // AFTER under the new one. The pre-scan 2-pass model (find protocol, decode
    // whole buffer with it) got this WRONG.
    //
    // The `3-2-3-1` leaf means different things per protocol:
    //   - ac203 → ISO (an I32 float; DJI.pm:280)
    //   - wm265e → ShutterSpeed (a LEN rational; DJI.pm:442)
    // Sample 1 persists ac203. Sample 2, in order:
    //   (a) `3-2-3-1` = I32 float 400.0  — under the PERSISTED ac203 ⇒ ISO=400
    //   (b) `1-1-1` = "dvtm_wm265e.proto" — switches the prefix to wm265e
    //   (c) `3-2-3-1` = rational 1/250   — under the SWITCHED wm265e ⇒ Shutter
    // Active-at-position decoding yields BOTH; a single-protocol pass over the
    // whole sample (whichever it picked) could decode only one.
    let mut out = DjiProtobufMeta::new();
    let sample1 = proto_block("dvtm_ac203.proto");
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));

    let rec_a = nest(3, &[nest(2, &[nest(3, &[rec_i32(1, 400.0)])])]); // 3-2-3-1 I32
    let rec_b = proto_block("dvtm_wm265e.proto"); // switch
    let rec_c = nest(3, &[nest(2, &[nest(3, &[rec_rational(1, 1, 250)])])]); // 3-2-3-1 rat
    let mut sample2 = Vec::new();
    sample2.extend(rec_a);
    sample2.extend(rec_b);
    sample2.extend(rec_c);
    process_djmd(&sample2, &mut dji_st, &mut out);

    let s = &out.samples()[1];
    assert_eq!(
      s.iso(),
      Some(400.0),
      "record (a) decoded under the PRIOR ac203 prefix (ISO at 3-2-3-1)"
    );
    assert_eq!(
      s.shutter_speed_s(),
      Some(1.0 / 250.0),
      "record (c) decoded under the SWITCHED wm265e prefix (ShutterSpeed at 3-2-3-1)"
    );
    // The mid-sample `.proto` leaf is recorded on this row + persists the track
    // protocol (first-wins keeps the original ac203 on the aggregate).
    assert_eq!(s.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(
      out.protocol(),
      Some("dvtm_ac203.proto"),
      "aggregate protocol is first-wins"
    );
  }

  // ── R13-F1: `.proto` detection is on RAW BYTES (not UTF-8/printable-gated) ─
  #[test]
  fn proto_suffix_checked_on_raw_bytes() {
    // Protobuf.pm:157 matches `$buff =~ /\.proto$/` on the RAW payload bytes —
    // no UTF-8/printable requirement. A non-UTF-8 payload that ENDS in the raw
    // six bytes `.proto` (2e 70 72 6f 74 6f) is detected; one that does not is
    // not.
    let binary_proto = std::vec![0xffu8, 0x00, 0x80, b'.', b'p', b'r', b'o', b't', b'o'];
    assert!(
      core::str::from_utf8(&binary_proto).is_err(),
      "the crafted payload is intentionally non-UTF-8"
    );
    assert_eq!(
      proto_suffix(&binary_proto),
      Some(binary_proto.as_slice()),
      "a non-UTF-8 payload ending in raw `.proto` is detected"
    );
    // A payload NOT ending in `.proto` (even printable) is not detected.
    assert!(proto_suffix(b"dvtm_wm265e.protoXX").is_none());
    assert!(proto_suffix(b"not a proto").is_none());
  }

  // ── R15-F1: `/\.proto$/` matches before a SINGLE final `\n` ──────────────
  #[test]
  fn proto_suffix_matches_trailing_lf() {
    // Perl `$` (no /m, no /s) anchors at end-of-string OR immediately before a
    // SINGLE final `\n`, so `dvtm_FUTURE.proto\n` MATCHES `/\.proto$/`
    // (Protobuf.pm:157) and SWITCHES `$$et{ProtoPrefix}`. A plain
    // `ends_with(".proto")` would miss it (the stale-prefix bug this fixes).
    // ExifTool's prefix is `substr($buff,0,-6).'_'` — dropping the last 6 bytes
    // (`proto\n`) leaves the trailing `.` ⇒ `dvtm_FUTURE._`, a name no DJI table
    // matches, so the active table becomes None (stops decode) + the
    // unknown-protocol warning fires; `Protocol` is the FULL `$buff` (incl. \n).
    assert_eq!(
      proto_suffix(b"dvtm_FUTURE.proto\n"),
      Some(b"dvtm_FUTURE.proto\n".as_slice()),
      "`.proto\\n` matches Perl `/\\.proto$/`"
    );

    // Track sample 1 sets a KNOWN prefix (ac203). Sample 2 (same track ⇒ same
    // state) carries a top-level `.proto\n` leaf FOLLOWED by a `3-4-2-2` record
    // that WOULD decode as GPSAltitude under ac203. The `.proto\n` switch
    // overwrites the (known) ac203 prefix with the unknown `dvtm_FUTURE.proto\n`
    // ⇒ the trailing `3-4-2-2` does NOT decode.
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&proto_block("dvtm_ac203.proto"), &mut dji_st, &mut out);
    assert!(out.first_warning().is_none(), "ac203 is a known protocol");

    let mut sample2 = Vec::new();
    sample2.extend(rec_str(9, "dvtm_FUTURE.proto\n")); // top-level `.proto\n` leaf
    sample2.extend(nest(3, &[nest(4, &[nest(2, &[rec_varint(2, 123_456)])])])); // 3-4-2-2
    process_djmd(&sample2, &mut dji_st, &mut out);

    let s2 = &out.samples()[1];
    // The full payload (incl. the trailing \n) is emitted as `Protocol`.
    assert_eq!(
      s2.protocol(),
      Some("dvtm_FUTURE.proto\n"),
      "Protocol = the FULL $buff (incl. the trailing LF)"
    );
    // The unknown protocol (incl. its trailing \n) warned.
    assert_eq!(
      out.first_warning(),
      Some("Unknown protocol dvtm_FUTURE.proto\n (please submit sample for testing)"),
      "the `.proto\\n` name is unknown ⇒ warns"
    );
    // The `3-4-2-2` record did NOT decode (the prior ac203 prefix was switched
    // away to the unknown `dvtm_FUTURE.proto\n`).
    assert_eq!(
      s2.absolute_altitude_m(),
      None,
      "the known-path record does NOT decode under the switched-away prefix"
    );

    // CONTROL: the SAME bytes but with `\r\n` (which Perl `$` does NOT match) do
    // NOT switch ⇒ the prior ac203 prefix STANDS ⇒ the `3-4-2-2` record DOES
    // decode as GPSAltitude. This proves it is the trailing-LF switch (not the
    // record itself) that stopped the decode above.
    let mut outc = DjiProtobufMeta::new();
    let mut dji_stc = DjiTrackState::new();
    process_djmd(&proto_block("dvtm_ac203.proto"), &mut dji_stc, &mut outc);
    let mut sample2c = Vec::new();
    sample2c.extend(rec_str(9, "dvtm_FUTURE.proto\r\n")); // `\r\n` ⇒ NO match
    sample2c.extend(nest(3, &[nest(4, &[nest(2, &[rec_varint(2, 123_456)])])])); // 3-4-2-2
    process_djmd(&sample2c, &mut dji_stc, &mut outc);
    assert_eq!(
      outc.samples()[1].absolute_altitude_m(),
      Some(123.456),
      "WITHOUT the trailing-LF switch, the `3-4-2-2` record decodes under ac203"
    );
    assert!(
      outc.samples()[1].protocol().is_none(),
      "a `.proto\\r\\n` payload does not switch ⇒ no per-sample Protocol"
    );
  }

  #[test]
  fn proto_suffix_rejects_crlf_and_double_lf() {
    // Perl `$` matches ONLY ONE trailing `\n`: `.proto\r\n` and `.proto\n\n` do
    // NOT match `/\.proto$/` (verified against Perl), so neither switches the
    // protocol. (A bare `.proto` and a single `.proto\n` DO — see the matching
    // test above.)
    assert!(
      proto_suffix(b"dvtm_X.proto\r\n").is_none(),
      "`.proto\\r\\n` does NOT match Perl `$`"
    );
    assert!(
      proto_suffix(b"dvtm_X.proto\n\n").is_none(),
      "`.proto\\n\\n` (two LFs) does NOT match Perl `$`"
    );
    // Positive controls (the only two matching forms).
    assert!(proto_suffix(b"dvtm_X.proto").is_some());
    assert!(proto_suffix(b"dvtm_X.proto\n").is_some());
    // Length guard: too-short payloads cannot match either needle.
    assert!(proto_suffix(b".proto").is_some(), "exactly 6 bytes matches");
    assert!(
      proto_suffix(b"proto\n").is_none(),
      "6 bytes, not `.proto`/.proto\\n"
    );
    assert!(proto_suffix(b"roto").is_none());
    assert!(proto_suffix(b"").is_none());
  }

  #[test]
  fn printable_proto_still_detected() {
    // Guard: the NORMAL ASCII `dvtm_wm265e.proto` case still switches the
    // protocol (raw-byte detection is a SUPERSET of the old printable-only one).
    let buf = proto_block("dvtm_wm265e.proto");
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(dji_st.decode_prefix(), Some("dvtm_wm265e.proto"));
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
    assert!(out.first_warning().is_none(), "wm265e is a known protocol");
  }

  #[test]
  fn binary_proto_payload_switches_protocol_and_stops_known_decode() {
    // A track with a KNOWN protocol decoding fields, then a NON-PRINTABLE LEN
    // payload ending in the raw bytes `.proto`. ExifTool OVERWRITES
    // `$$et{ProtoPrefix}{$dirName}` to that binary (unknown) protocol
    // (Protobuf.pm:157-159) and `HandleTag`s `Protocol => $buff`; subsequent
    // records, now prefixed with the unknown name, match NO known DJI table key
    // and stop decoding. The pre-fix port (UTF-8/printable-gated detection)
    // ignored the binary `.proto`, kept the old known prefix, and wrongly decoded
    // the trailing record.
    //
    // ac203 reads `3-2-3-1` as ISO (an I32 float; DJI.pm:280). Sample 2, in
    // order:
    //   (a) `3-2-3-1` = I32 float 400.0    — under PERSISTED ac203 ⇒ ISO=400
    //   (b) a top-level binary LEN ending in raw `.proto` — switches the prefix
    //       to the unknown binary name ⇒ active table becomes None
    //   (c) `3-2-3-1` = I32 float 999.0    — under the now-UNKNOWN prefix ⇒ NOT
    //       decoded (would have been ISO=999 if the old prefix had stuck)
    let mut out = DjiProtobufMeta::new();
    let sample1 = proto_block("dvtm_ac203.proto");
    let mut dji_st = DjiTrackState::new();
    process_djmd(&sample1, &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    assert!(out.first_warning().is_none(), "ac203 is a known protocol");

    // A non-UTF-8 protocol name ending in raw `.proto`. Its leading bytes
    // (0xff 0x00) read as wire-type 7 ⇒ `is_protobuf` is false ⇒ the R9-F2
    // recursion gate (`has_non_printable && is_protobuf`) does NOT recurse, so
    // the switch is the ONLY effect.
    let binary_name = std::vec![0xffu8, 0x00, 0x80, b'.', b'p', b'r', b'o', b't', b'o'];
    assert!(
      !is_protobuf(&binary_name),
      "guard: leading bytes are not protobuf"
    );
    assert!(
      has_non_printable(&binary_name),
      "guard: payload has non-printable bytes"
    );
    let rec_a = nest(3, &[nest(2, &[nest(3, &[rec_i32(1, 400.0)])])]); // 3-2-3-1 I32
    let rec_b = rec_len(7, &binary_name); // top-level binary `.proto` switch
    let rec_c = nest(3, &[nest(2, &[nest(3, &[rec_i32(1, 999.0)])])]); // 3-2-3-1 I32
    let mut sample2 = Vec::new();
    sample2.extend(rec_a);
    sample2.extend(rec_b);
    sample2.extend(rec_c);
    process_djmd(&sample2, &mut dji_st, &mut out);

    let s = &out.samples()[1];
    assert_eq!(
      s.iso(),
      Some(400.0),
      "record (a) decoded under the PRIOR known ac203 prefix (ISO at 3-2-3-1)"
    );
    // The binary `.proto` switched the active protocol to the unknown one, so
    // record (c) — which WOULD have matched ac203's `3-2-3-1` ISO leaf — is NOT
    // decoded under it. ISO is the value from (a), not overwritten by (c).
    assert_ne!(
      s.iso(),
      Some(999.0),
      "record (c) must NOT decode under the old known prefix after the switch"
    );
    // The unknown-protocol warning fired (DJI.pm:262 RawConv), exactly as the
    // printable-unknown case does.
    let w = out
      .first_warning()
      .expect("the binary unknown protocol warns");
    assert!(
      w.starts_with("Unknown protocol ") && w.ends_with(" (please submit sample for testing)"),
      "unknown-protocol warning, got {w:?}"
    );
    // The per-sample `Protocol` is the lossily-rendered binary value (the
    // project's convention for a non-UTF-8 stored string); decode_prefix mirrors
    // it (last-wins) and a follower would seed a None table from it.
    let lossy = alloc::string::String::from_utf8_lossy(&binary_name);
    assert_eq!(
      s.protocol(),
      Some(lossy.as_ref()),
      "the per-sample Protocol is the lossy binary value"
    );
    assert_eq!(dji_st.decode_prefix(), Some(lossy.as_ref()));
    // First-wins aggregate identity keeps the original known ac203.
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
  }

  // ── R14-F1: line-157 switch fires UNCONDITIONALLY, BEFORE recursion ──────
  #[test]
  fn clean_nested_proto_payload_switches_before_recursion() {
    // ExifTool's `$type == 2 and $buff =~ /\.proto$/` (Protobuf.pm:157) fires on
    // EVERY LEN record whose RAW bytes end in `.proto` — including an OUTER nested
    // message that ALSO happens to be a clean protobuf the walk will recurse into
    // (Protobuf.pm:236). Detection (157) and recursion (236) are INDEPENDENT and
    // SEQUENTIAL: the switch overwrites `$$et{ProtoPrefix}{$dirName}` to the OUTER
    // value (garbage, unknown) FIRST, THEN the message is descended, so a child
    // BEFORE the inner leaf decodes under the (now garbage) prefix — i.e. it does
    // NOT match any known DJI path. A deeper genuine `.proto` leaf then overwrites
    // last-wins. The R13 over-correction suppressed the outer switch for a clean
    // nested protobuf ending in `.proto`, so the child wrongly decoded under the
    // STALE prior prefix — the bug this re-fixes.
    //
    // Ground-truthed against `Image::ExifTool::Protobuf::ProcessProtobuf` (DJI
    // table): final ProtoPrefix `dvtm_wm265e_`, an unknown-protocol Warning for
    // the outer garbage value, and NO `GPSAltitude` (the child did NOT decode).
    let mut out = DjiProtobufMeta::new();
    // Sample 1: a faithful KNOWN ac203 identity (no warning, one switch).
    let mut dji_st = DjiTrackState::new();
    process_djmd(&proto_block("dvtm_ac203.proto"), &mut dji_st, &mut out);
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
    assert!(out.first_warning().is_none(), "ac203 is a known protocol");

    // Sample 2: a top-level field-3 message M whose body is
    //   [ 3-4-2-2 GPSAltitude=123456 (decodable under ac203) , 3-1 inner .proto ]
    // so M's RAW bytes END in `.proto` AND M is a clean protobuf with non-printable
    // framing (so the IsProtobuf recursion gate ALSO descends into it).
    let child = nest(4, &[nest(2, &[rec_varint(2, 123_456)])]); // 3-4-2-2 under ac203
    let inner_leaf = rec_str(1, "dvtm_wm265e.proto"); // 3-1 inner protocol leaf (LAST field)
    let mut m_body = Vec::new();
    m_body.extend(child);
    m_body.extend(inner_leaf);
    let m = rec_len(3, &m_body); // field-3 LEN, body ends in `.proto`
    // Guard: M's body BOTH ends in `.proto` AND is a clean protobuf w/ non-printable
    // bytes — the exact case the R13 gate suppressed.
    assert!(m_body.ends_with(b".proto"), "M body ends in .proto");
    assert!(
      has_non_printable(&m_body) && is_protobuf(&m_body),
      "M body is a clean protobuf with non-printable framing"
    );
    process_djmd(&m, &mut dji_st, &mut out);

    let s = &out.samples()[1];
    // (a) The OUTER switch fired: the last-wins decode prefix moved through the
    //     garbage OUTER value to the deeper inner leaf `dvtm_wm265e.proto`.
    assert_eq!(
      dji_st.decode_prefix(),
      Some("dvtm_wm265e.proto"),
      "the deeper inner .proto leaf overwrites last-wins"
    );
    // (b) The child `3-4-2-2` did NOT decode: by the time the walk recursed into M
    //     and reached the child, the OUTER switch had already changed the prefix
    //     to the garbage value, so `<garbage>3-4-2-2` matched no ac203 path.
    assert_eq!(
      s.absolute_altitude_m(),
      None,
      "the child does NOT decode under the stale prior ac203 prefix"
    );
    // (c) The outer garbage value raised the unknown-protocol warning (line-157
    //     side effect, fired BEFORE recursion).
    let w = out
      .first_warning()
      .expect("the outer garbage .proto value warns");
    assert!(
      w.starts_with("Unknown protocol ") && w.ends_with(" (please submit sample for testing)"),
      "unknown-protocol warning for the outer garbage value, got {w:?}"
    );
    // First-wins aggregate identity keeps the original known ac203.
    assert_eq!(out.protocol(), Some("dvtm_ac203.proto"));
  }

  // ── PIN: repeated Protocol (outer + deeper inner leaf) = inner last-wins ──
  #[test]
  fn outer_and_inner_proto_emits_inner_protocol_last_wins() {
    // PIN: ExifTool `HandleTag`s `Protocol` for BOTH an outer LEN whose raw bytes
    // end in `.proto` AND a deeper genuine inner `.proto` leaf (Protobuf.pm:160).
    // But within ONE Doc a duplicate non-priority tag is LAST-wins in the `-j` /
    // `-G3` JSON (one `Protocol` entry = the inner/last value), and the `-G3` JSON
    // is tag-key-order-insensitive so the wire ORDER is unobservable in the
    // goldens. So the port's `set_protocol` LAST-WINS (the deeper inner leaf,
    // walked last) MATCHES ExifTool — this is NOT a divergence and the scalar
    // sample model is golden-faithful (the merged camm/ctmd siblings use the same
    // model and pass byte-exact). This test pins that behaviour.
    //
    // ONE sample: a single top-level field-3 LEN whose body is EXACTLY the inner
    // leaf `1 = "dvtm_ac203.proto"` (a known protocol). The inner leaf is the
    // body's LAST (only) record, so the OUTER record's RAW bytes ALSO end in
    // `.proto` — line-157 fires on the OUTER first (switching to the garbage outer
    // value, which is unknown ⇒ warns), then the walk recurses into the body and
    // line-157 fires on the deeper INNER leaf (switching to `dvtm_ac203.proto`),
    // which wins last.
    let inner_leaf = rec_str(1, "dvtm_ac203.proto"); // the genuine deeper .proto leaf
    let outer = rec_len(3, &inner_leaf); // field-3 LEN; its raw bytes end in `.proto`
    // Guards: the outer body ends in `.proto`, and is a clean non-printable
    // protobuf (so the speculative IsProtobuf gate descends into it).
    assert!(inner_leaf.ends_with(b".proto"), "outer body ends in .proto");
    assert!(
      has_non_printable(&inner_leaf) && is_protobuf(&inner_leaf),
      "outer body is a clean protobuf with non-printable framing"
    );

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&outer, &mut dji_st, &mut out);

    // (1) The emitted per-sample `Protocol` scalar = the INNER value (last-wins).
    let s = &out.samples()[0];
    assert_eq!(
      s.protocol(),
      Some("dvtm_ac203.proto"),
      "the deeper inner .proto leaf wins last in the per-sample scalar"
    );
    // (2) The active decode_prefix = the inner protocol (deeper leaf last-wins).
    assert_eq!(
      dji_st.decode_prefix(),
      Some("dvtm_ac203.proto"),
      "the inner leaf overwrote the decode prefix last"
    );
    // (3) The unknown-outer warning still fired (line-157 side effect on the outer
    //     garbage value, BEFORE the recursion reached the inner leaf).
    let w = out
      .first_warning()
      .expect("the outer garbage .proto value warns");
    assert!(
      w.starts_with("Unknown protocol ") && w.ends_with(" (please submit sample for testing)"),
      "unknown-protocol warning for the outer garbage value, got {w:?}"
    );
    // First-wins aggregate identity keeps the FIRST protocol seen (the outer
    // garbage), independent of the per-sample last-wins scalar.
    assert!(
      out.protocol().is_some_and(|p| p != "dvtm_ac203.proto"),
      "aggregate identity is first-wins (the outer garbage), got {:?}",
      out.protocol()
    );
  }

  #[test]
  fn proto_leaf_followed_by_fields_only_leaf_matches() {
    // The FAITHFUL real-DJI identity shape: the `.proto` leaf at `1-1-1` FOLLOWED
    // by SerialNumber (1-1-5) + Model (1-1-10) in the SAME `1-1` container. Only
    // the leaf's OWN bytes end in `.proto`; neither the `1-1` container nor the
    // enclosing `1` record does — so ExifTool's line-157 switch fires EXACTLY
    // ONCE, on the genuine leaf, with NO spurious intermediate switch/warning, and
    // the trailing serial/model fields decode normally.
    //
    // Ground-truthed against `ProcessProtobuf`: ProtoPrefix `dvtm_wm265e_`, a
    // single `Protocol = dvtm_wm265e.proto`, `SerialNumber`, `Model`, no warning.
    let inner = {
      let mut v = Vec::new();
      v.extend(rec_str(1, "dvtm_wm265e.proto")); // 1-1-1 the .proto leaf
      v.extend(rec_str(5, "SERIAL123")); // 1-1-5 SerialNumber (AFTER the leaf)
      v.extend(rec_str(10, "FC8482")); // 1-1-10 Model (AFTER the leaf)
      v
    };
    let buf = nest(1, &[rec_len(1, &inner)]);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    // Exactly one switch: the surfaced + per-sample Protocol is the clean leaf.
    assert_eq!(out.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(dji_st.decode_prefix(), Some("dvtm_wm265e.proto"));
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
    // No spurious intermediate switch ⇒ no unknown-protocol warning.
    assert!(
      out.first_warning().is_none(),
      "a faithful proto-leaf-then-fields block fires exactly one switch, got {:?}",
      out.first_warning()
    );
    // The trailing serial/model decode under the (single, correct) wm265e prefix.
    assert_eq!(out.serial_number(), Some("SERIAL123"));
    assert_eq!(out.samples()[0].serial_number(), Some("SERIAL123"));
    assert_eq!(out.samples()[0].model(), Some("FC8482"));
  }

  // ── R15-F2: DJI decode state is PER-TRACK (one `djmd` trak = one $dirName) ──
  #[test]
  fn two_djmd_tracks_second_data_only_does_not_inherit_first_protocol() {
    // ExifTool keys `ProtoPrefix` per `$dirName` (`$$et{ProtoPrefix}{$dirName} =
    // '' unless defined`, Protobuf.pm:143) — one `djmd` trak = one $dirName,
    // init EMPTY per track. The stream walker constructs a FRESH `DjiTrackState`
    // per trak, so a SECOND `djmd` track that begins data-only must NOT decode
    // under the FIRST track's prefix. The decoded rows still aggregate into the
    // shared file-level `out` (as the walker accumulates across traks).
    let mut out = DjiProtobufMeta::new();

    // Track 1 (its own state): set ac203 + decode a `3-4-2-2` GPSAltitude.
    let mut st1 = DjiTrackState::new();
    let mut t1 = Vec::new();
    t1.extend(proto_block("dvtm_ac203.proto")); // protocol leaf ⇒ ac203
    t1.extend(nest(3, &[nest(4, &[nest(2, &[rec_varint(2, 50_000)])])])); // 3-4-2-2 = 50 m
    process_djmd(&t1, &mut st1, &mut out);
    assert_eq!(
      out.samples()[0].absolute_altitude_m(),
      Some(50.0),
      "track 1 decoded GPSAltitude under its own ac203 prefix"
    );
    assert_eq!(
      st1.decode_prefix(),
      Some("dvtm_ac203.proto"),
      "track 1's per-track prefix is ac203"
    );

    // Track 2 (a FRESH state — the new trak's empty $dirName): a DATA-ONLY
    // sample, the SAME `3-4-2-2` record but with NO `.proto` leaf. With no active
    // prefix it must NOT decode (no known DJI tag fabricated for the wrong track).
    let mut st2 = DjiTrackState::new();
    let data_only = nest(3, &[nest(4, &[nest(2, &[rec_varint(2, 99_000)])])]); // 3-4-2-2
    process_djmd(&data_only, &mut st2, &mut out);
    assert!(
      st2.decode_prefix().is_none(),
      "track 2 starts with the empty `''` prefix (no inheritance)"
    );
    assert_eq!(
      out.samples()[1].absolute_altitude_m(),
      None,
      "track 2's data-only `3-4-2-2` does NOT decode under track 1's ac203 prefix"
    );

    // CONTROL: the SAME data-only sample, fed under track 1's (ac203) state,
    // DOES decode — proving it is the per-track reset, not the record, that
    // stopped the decode above.
    let mut outc = DjiProtobufMeta::new();
    let mut stc = DjiTrackState::new();
    process_djmd(&t1, &mut stc, &mut outc); // seed ac203 into stc
    process_djmd(&data_only, &mut stc, &mut outc); // SAME state ⇒ still ac203
    assert_eq!(
      outc.samples()[1].absolute_altitude_m(),
      Some(99.0),
      "under the SAME (track-1) state the data-only record decodes — confirms the reset is the cause"
    );
  }

  #[test]
  fn two_djmd_tracks_second_coord_units_not_inherited() {
    // `$$self{CoordUnits}` (DJI.pm:922) is per-track decode state too: a SECOND
    // `djmd` track starts with the FRESH default (unset ⇒ radians), NOT the
    // degrees a FIRST track established. Otherwise track 2's coordinate (handled
    // before its own units leaf) would be taken as degrees under track 1's
    // leftover `CoordUnits=1` — a cross-track state leak (R15-F2).
    let mut out = DjiProtobufMeta::new();

    // Track 1: ac203 GPSInfo (3-4-2-1) with CoordinateUnits=1 (degrees) FIRST,
    // then lat/lon already in degrees ⇒ decoded verbatim; leaves st1.CoordUnits=1.
    let gps1 = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees (3-4-2-1-1)
      v.extend(rec_i64(2, 45.0)); // GPSLatitude already degrees (3-4-2-1-2)
      v.extend(rec_i64(3, 8.0)); // GPSLongitude already degrees (3-4-2-1-3)
      v
    };
    let mut st1 = DjiTrackState::new();
    let mut t1 = Vec::new();
    t1.extend(proto_block("dvtm_ac203.proto"));
    t1.extend(nest(3, &[nest(4, &[nest(2, &[nest(1, &[gps1])])])])); // 3-4-2-1 GPSInfo
    process_djmd(&t1, &mut st1, &mut out);
    assert_eq!(
      out.samples()[0].latitude(),
      Some(45.0),
      "track 1: degrees verbatim"
    );
    assert_eq!(
      st1.coord_units(),
      Some(1),
      "track 1 established CoordUnits = 1 (degrees)"
    );

    // Track 2 (a FRESH state): ac203 GPSInfo with a coordinate but NO
    // CoordinateUnits leaf of its own. Under track 2's fresh default (unset ⇒
    // radians) the raw π/4 converts to 45° via ×180/π — it must NOT be taken as
    // degrees (which would yield the raw 0.785… ) by inheriting track 1's units.
    let gps2 = {
      let mut v = Vec::new();
      v.extend(rec_i64(2, core::f64::consts::FRAC_PI_4)); // lat π/4 rad (3-4-2-1-2)
      v
    };
    let mut st2 = DjiTrackState::new();
    let mut t2 = Vec::new();
    t2.extend(proto_block("dvtm_ac203.proto"));
    t2.extend(nest(3, &[nest(4, &[nest(2, &[nest(1, &[gps2])])])])); // 3-4-2-1 GPSInfo
    process_djmd(&t2, &mut st2, &mut out);
    assert!(
      st2.coord_units().is_none(),
      "track 2 starts with the fresh unset CoordUnits (no inheritance)"
    );
    let lat2 = out.samples()[1].latitude().expect("track 2 lat");
    assert!(
      (lat2 - 45.0).abs() < 1e-9,
      "track 2's coordinate converts as RADIANS (fresh default), got {lat2:?} — \
       NOT taken as degrees under track 1's leftover CoordUnits=1"
    );
  }

  #[test]
  fn djmd_malformed_tail_preserves_earlier_records() {
    // A sample with valid GPS + capture records FOLLOWED by a malformed tail.
    // ExifTool's `ReadRecord` failure `$self->Warn('Protobuf format error')`
    // then `last` (Protobuf.pm:156) STOPS the loop but KEEPS everything already
    // handled — the partial sample survives.
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees
      v.extend(rec_i64(2, 45.0)); // GPSLatitude
      v.extend(rec_i64(3, 8.0)); // GPSLongitude
      v
    };
    // wm265e: GPSInfo 3-3-4-1, AbsoluteAltitude 3-3-4-2, ISO 3-2-2-1.
    let lvl334 = {
      let mut v = Vec::new();
      v.extend(nest(1, &[gps_info]));
      v.extend(rec_varint(2, 105_500)); // AbsoluteAltitude 105.5 m
      v
    };
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto")); // protocol
    buf.extend(nest(3, &[nest(2, &[nest(2, &[rec_i32(1, 800.0)])])])); // 3-2-2-1 ISO
    buf.extend(nest(3, &[nest(3, &[nest(4, &[lvl334])])])); // GPS + altitude
    // Malformed TAIL: a top-level LEN record declaring 200 bytes with no body.
    buf.extend(tag(4, 2));
    buf.extend(enc_varint(200));

    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);

    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "the malformed tail raises the format-error warning"
    );
    assert_eq!(out.samples().len(), 1);
    let s = &out.samples()[0];
    // Everything BEFORE the malformed tail survived.
    assert_eq!(s.protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(s.iso(), Some(800.0), "ISO before the tail survives");
    assert_eq!(s.latitude(), Some(45.0), "GPS before the tail survives");
    assert_eq!(s.longitude(), Some(8.0));
    assert_eq!(
      s.absolute_altitude_m(),
      Some(105.5),
      "altitude before the tail survives"
    );
  }

  #[test]
  fn djmd_corrupt_unnamed_wrapper_payload_suppressed_not_warned() {
    // #221 item-1 (corrected — this test PREVIOUSLY asserted the pre-fix
    // unconditional-recursion behavior): wm265e field `3` is an UNNAMED
    // intermediate wrapper (a branch prefix of `3-2-2-1` ISO etc. but with NO
    // `SubDirectory` of its own). Bundled reaches it ONLY via the `Unknown`-tag
    // IsProtobuf gate (Protobuf.pm:171-179). A `3` LEN record whose payload is a
    // lone continuation byte `0x80` is NON-printable but NOT clean protobuf
    // (`IsProtobuf` fails on the truncated tag varint), so the gate SKIPS it ⇒
    // NO `Protobuf format error`. Bundled-verified (perl `ProcessProtobuf` over
    // `%DJI::Protobuf`: `WARNINGS: (none)`). The pre-fix port recursed
    // unconditionally on the branch prefix and emitted a spurious error.
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto"));
    buf.extend(rec_len(3, &[0x80])); // corrupt UNNAMED-wrapper payload
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert!(
      msgs.is_empty(),
      "a corrupt UNNAMED-wrapper payload is skipped silently by the IsProtobuf \
       gate (bundled emits no warning), got {msgs:?}"
    );
    // The protocol decoded before the skipped wrapper survives.
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
  }

  #[test]
  fn djmd_nested_truncation_in_named_subdir_warns_format_error() {
    // The depth>=1 `Protobuf format error` path, exercised through a NAMED
    // SubDirectory (the only branch the port recurses into unconditionally after
    // #221 item-1). wm265e DroneInfo is the named SubDirectory `3-3-3`
    // (DJI.pm:732). Reached via the CLEAN unnamed wrappers `3` then `3-3` (each a
    // well-formed LEN record ⇒ they pass the IsProtobuf gate), the corrupt byte
    // lives INSIDE the named `3-3-3` DroneInfo message: a valid DroneRoll
    // (`3-3-3-1`) varint then a lone `0x80`. The named SubDirectory is descended
    // unconditionally ⇒ the truncated TAG varint ⇒ fatal `read_tag` Err ⇒
    // `Protobuf format error`. Bundled-verified: `WARNINGS: Protobuf format
    // error`. (The value decoded before the corrupt byte survives.)
    let drone = {
      let mut v = rec_varint(1, 5); // DroneRoll 0.5°
      v.push(0x80); // CORRUPT trailing byte INSIDE the named DroneInfo
      v
    };
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto"));
    buf.extend(nest(3, &[nest(3, &[rec_len(3, &drone)])])); // 3 -> 3 -> 3 DroneInfo
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    assert_eq!(
      out.first_warning(),
      Some("Protobuf format error"),
      "a corrupt byte in a NAMED SubDirectory (descended unconditionally) warns"
    );
    // The protocol + the DroneRoll decoded before the corrupt byte survive.
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
    assert_eq!(out.samples()[0].drone_roll_deg(), Some(0.5));
  }

  // ── #163 R17: `Truncated protobuf data` gates on `Pos != dirEnd` ─────────
  //
  // Protobuf.pm:278 is `$et->Warn('Truncated protobuf data') unless $prefix or
  // $$dirInfo{Pos} == $dirEnd`. So at the TOP level the second warning fires
  // ONLY when the failed read left LEFTOVER bytes (`Pos < dirEnd`). A failure
  // that consumed EXACTLY to EOF (`Pos == dirEnd`) emits ONLY the format error.
  // Each fixture's `Pos` vs `dirEnd` was verified against a perl
  // `ProcessProtobuf` trace (the warns list is reproduced in each test).

  /// A TOP-LEVEL record whose TAG varint runs off the end (a lone continuation
  /// byte). `VarInt`'s `GetBytes(1)` fails at `Pos == end` ⇒ `Pos == dirEnd` ⇒
  /// ONLY `Protobuf format error` (perl: `[Protobuf format error]`).
  #[test]
  fn truncated_tag_varint_at_eof_only_format_error() {
    let buf = [0x80u8]; // a single continuation byte — a truncated tag varint
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error"],
      "a tag varint off the end consumes to EOF (Pos == dirEnd) ⇒ ONLY format error"
    );
  }

  /// A TOP-LEVEL wire-0 record whose VALUE varint runs off the end. The tag is
  /// read, then the value `VarInt`'s `GetBytes(1)` fails at `Pos == end` ⇒
  /// `Pos == dirEnd` ⇒ ONLY format error (perl: `[Protobuf format error]`).
  #[test]
  fn truncated_value_varint_at_eof_only_format_error() {
    let mut buf = tag(1, 0); // field 1, wire 0 (varint)
    buf.push(0x80); // a truncated VALUE varint (continuation byte at EOF)
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error"],
      "a value varint off the end consumes to EOF (Pos == dirEnd) ⇒ ONLY format error"
    );
  }

  /// An invalid WIRE TYPE 6 byte as the LAST byte. The tag varint consumes it
  /// (`Pos == end`), `$buff` stays undef (no if/elsif arm) ⇒ `Pos == dirEnd` ⇒
  /// ONLY format error (perl: `[Protobuf format error]`). Covers wire 7 too.
  #[test]
  fn invalid_wire_type_at_eof_only_format_error() {
    for bad_wire in [6u8, 7u8] {
      let buf = tag(1, bad_wire); // field 1, invalid wire 6/7 — the whole buffer
      let mut out = DjiProtobufMeta::new();
      let mut dji_st = DjiTrackState::new();
      process_djmd(&buf, &mut dji_st, &mut out);
      let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
      assert_eq!(
        msgs,
        std::vec!["Protobuf format error"],
        "an invalid wire {bad_wire} as the LAST byte consumes to EOF (Pos == dirEnd) ⇒ ONLY format error"
      );
    }
  }

  /// A LEN record whose LENGTH varint ends EXACTLY at EOF and declares N>0 body
  /// bytes with 0 remaining. `GetBytes(N)` fails WITHOUT advancing, `Pos` is
  /// already at end ⇒ `Pos == dirEnd` ⇒ ONLY format error (perl: `[Protobuf
  /// format error]`). The standalone twin of the LEN case in
  /// `malformed_sample_without_protocol_warns_format_error`.
  #[test]
  fn len_length_no_body_at_eof_only_format_error() {
    let mut buf = tag(1, 2); // field 1, wire 2 (LEN)
    buf.extend(enc_varint(200)); // declares 200 bytes, length varint ends at EOF
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error"],
      "a LEN length ending at EOF with 0 body bytes left (Pos == dirEnd) ⇒ ONLY format error"
    );
  }

  /// A LEN record claiming length > remaining WITH leftover bytes AFTER the
  /// length varint (the length varint resolves, but `GetBytes($len)` fails with
  /// some — fewer than `$len` — bytes still present). `GetBytes` does not
  /// advance, so `Pos` is right after the length varint ⇒ `Pos < dirEnd` ⇒ BOTH
  /// `Protobuf format error` AND `Truncated protobuf data` (perl: `[Protobuf
  /// format error, Truncated protobuf data]`).
  #[test]
  fn len_claiming_more_with_leftover_emits_both() {
    let mut buf = tag(1, 2); // field 1, wire 2 (LEN)
    buf.extend(enc_varint(10)); // declares 10 bytes …
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // … but only 3 remain ⇒ Pos < dirEnd
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error", "Truncated protobuf data"],
      "a LEN body off the end WITH leftover bytes (Pos < dirEnd) ⇒ BOTH warnings"
    );
  }

  /// A truncation INSIDE a NAMED `SubDirectory` (a FRESH `ProcessProtobuf` with
  /// `$prefix` UNDEF) that leaves LEFTOVER bytes (`Pos < dirEnd`) emits BOTH
  /// `Protobuf format error` AND `Truncated protobuf data` — exactly like a
  /// top-level truncation. ExifTool reaches a named SubDirectory via `HandleTag`
  /// → a fresh `ProcessProtobuf` whose `$prefix` is empty, so the line-278 gate
  /// (`unless $prefix or Pos == dirEnd`) fires its second warning. CONTRAST the
  /// SPECULATIVE `Unknown`-tag recursion (an UNNAMED wrapper, `$prefix` truthy),
  /// which never truncates (its payload is proven clean by `IsProtobuf`) and is
  /// gated out entirely when corrupt — see
  /// `djmd_corrupt_unnamed_wrapper_payload_suppressed_not_warned`.
  ///
  /// wm265e DroneInfo is the named SubDirectory `3-3-3`, reached via the CLEAN
  /// unnamed wrappers `3` then `3-3` (well-formed LEN records ⇒ they pass the
  /// IsProtobuf gate). The DroneInfo body is a wire-6 tag byte WITH a trailing
  /// byte (`Pos < dirEnd` inside the SubDirectory). Bundled-verified: `[Protobuf
  /// format error, Truncated protobuf data]`.
  #[test]
  fn named_subdir_truncation_with_leftover_emits_both() {
    let mut buf = Vec::new();
    buf.extend(proto_block("dvtm_wm265e.proto"));
    // 3 -> 3 -> 3 (DroneInfo named SubDirectory); body = [wire-6 tag, trailing].
    buf.extend(nest(3, &[nest(3, &[rec_len(3, &[tag(1, 6)[0], 0xAA])])]));
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let msgs: Vec<&str> = out.warnings().iter().map(|w| w.message()).collect();
    assert_eq!(
      msgs,
      std::vec!["Protobuf format error", "Truncated protobuf data"],
      "a truncation with leftover bytes inside a NAMED SubDirectory (fresh \
       `$prefix`) emits BOTH warnings"
    );
    assert_eq!(out.samples()[0].protocol(), Some("dvtm_wm265e.proto"));
  }

  // ── R3-F3: GPS CoordUnits is read PER-LEAF at the coordinate's position ──
  #[test]
  fn gps_latlon_before_coordinate_units_uses_state_at_leaf() {
    // ExifTool reads `$$self{CoordUnits}` in the GPSLatitude/GPSLongitude
    // RawConv AT THE MOMENT each coordinate leaf is handled (DJI.pm:929/935),
    // and the CoordinateUnits leaf sets it when ITS turn comes (DJI.pm:922).
    // So when lat/lon PRECEDE CoordinateUnits in the wire, each coordinate
    // converts under the state ACTIVE AT ITS POSITION — here unset ⇒ radians —
    // NOT the value CoordinateUnits sets afterwards. The buffer-and-resolve
    // model (apply units at flush) got this backwards.
    //
    // ac203 GPSInfo at 3-4-2-1; emit field 2 (lat) and 3 (lon) BEFORE field 1
    // (CoordinateUnits).
    let gps_info = {
      let mut v = Vec::new();
      v.extend(rec_i64(2, core::f64::consts::FRAC_PI_4)); // lat π/4 rad, units unset ⇒ ×180/π
      v.extend(rec_i64(3, core::f64::consts::FRAC_PI_6)); // lon π/6 rad ⇒ ×180/π
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees — set AFTER the coords
      v
    };
    let lvl342 = nest(2, &[nest(1, &[gps_info])]); // 3-4-2-1
    let lvl3 = nest(3, &[nest(4, &[lvl342])]);
    let proto = proto_block("dvtm_ac203.proto");
    let mut buf = Vec::new();
    buf.extend(proto);
    buf.extend(lvl3);
    let mut out = DjiProtobufMeta::new();
    let mut dji_st = DjiTrackState::new();
    process_djmd(&buf, &mut dji_st, &mut out);
    let s = out.first_fix().expect("fix");
    assert!(
      (s.latitude().unwrap() - 45.0).abs() < 1e-9,
      "lat converted as RADIANS (units unset at its position): {:?}",
      s.latitude()
    );
    assert!(
      (s.longitude().unwrap() - 30.0).abs() < 1e-9,
      "lon converted as RADIANS (units unset at its position): {:?}",
      s.longitude()
    );

    // …and the NORMAL DJI order (CoordinateUnits FIRST) is unchanged: units=1
    // ⇒ the coordinates are taken as degrees verbatim.
    let gps_info_normal = {
      let mut v = Vec::new();
      v.extend(rec_varint(1, 1)); // CoordinateUnits = degrees FIRST
      v.extend(rec_i64(2, 45.0)); // lat already degrees
      v.extend(rec_i64(3, 8.0)); // lon already degrees
      v
    };
    let lvl342n = nest(2, &[nest(1, &[gps_info_normal])]);
    let lvl3n = nest(3, &[nest(4, &[lvl342n])]);
    let proton = proto_block("dvtm_ac203.proto");
    let mut bufn = Vec::new();
    bufn.extend(proton);
    bufn.extend(lvl3n);
    let mut outn = DjiProtobufMeta::new();
    // A SEPARATE aggregate (a fresh track) ⇒ a SEPARATE per-track decode state:
    // the first scenario left `coord_units = Some(1)` (its trailing
    // CoordinateUnits leaf), and that must NOT leak into this track (R15-F2).
    let mut dji_st_n = DjiTrackState::new();
    process_djmd(&bufn, &mut dji_st_n, &mut outn);
    let sn = outn.first_fix().expect("fix");
    assert_eq!(
      sn.latitude(),
      Some(45.0),
      "normal order: units-first ⇒ degrees"
    );
    assert_eq!(sn.longitude(), Some(8.0));
  }
}
