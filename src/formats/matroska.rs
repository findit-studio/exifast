// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "matroska")]
//! Faithful port of `Image::ExifTool::Matroska` (lib/Image/ExifTool/Matroska.pm).
//!
//! Matroska/WebM/MKA/MKS share the EBML (Extensible Binary Meta Language)
//! container: a stream of nested elements identified by VINT-encoded IDs and
//! sized by VINT-encoded lengths (see EBML spec). The bundled `ProcessMKV`
//! (Matroska.pm:988-1248) walks the EBML tree, looking up each element ID in
//! `%Image::ExifTool::Matroska::Main` to obtain a `(Name, Format, PrintConv,
//! ValueConv, …)` descriptor, then emits the decoded value into the engine.
//!
//! ## VINT (Variable-Length Integer)
//!
//! The first byte's leading-zero count (counting from the MSB) tells the byte
//! length: `0x80` ⇒ 1 byte, `0x40` ⇒ 2 bytes, `0x20` ⇒ 3, … `0x01` ⇒ 8.
//! Element IDs preserve the length marker bit (per EBML spec); sizes strip it
//! (Matroska.pm:956-982 `GetVInt`).
//!
//! ## Group naming (family-1)
//!
//! - Default → `"Matroska"`
//! - After entering `Info` (`0x549a966`) → `"Info"` (Matroska.pm:1120-1123)
//! - After encountering `TrackNumber` (`0x57`) → `"Track<N>"`
//!   (Matroska.pm:1203-1206)
//! - After entering `ChapterAtom` (`0x36`) → `"Chapter<n>"` with `n` the
//!   1-based chapter count (Matroska.pm:1117-1119)
//!
//! ## Format decoders (Matroska.pm:1168-1202)
//!
//! - `unsigned` — big-endian unsigned integer, variable byte length
//! - `signed` — big-endian signed integer (sign-extended from top bit)
//! - `float` — 4-byte IEEE-754 single OR 8-byte double (BE)
//! - `string` — ASCII, NUL-trimmed at first `\0`
//! - `utf8` — UTF-8, NUL-trimmed at first `\0`
//! - `date` — i64 nanoseconds since 2001-01-01T00:00:00 UTC; converted to the
//!   `"YYYY:MM:DD HH:MM:SS"` form with a trailing `"Z"` via
//!   [`crate::datetime::convert_unix_time`] (Matroska.pm:1193-1198).

use core::time::Duration;
use smol_str::SmolStr;
use std::{borrow::Cow, vec::Vec};

use crate::datetime::convert_unix_time;
use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// EBML magic
// ===========================================================================

/// EBML header magic — bundled `Matroska.pm:996` `/^\x1a\x45\xdf\xa3/`.
pub const EBML_MAGIC: [u8; 4] = [0x1a, 0x45, 0xdf, 0xa3];

// ===========================================================================
// VINT decoder (Matroska.pm:956-982 `GetVInt`)
// ===========================================================================

/// Outcome of [`get_vint`]: the decoded numeric value AND the number of bytes
/// it consumed from the buffer. Faithful to bundled Perl which mutates its
/// position-in-buffer argument by reference — we return the consumed length
/// so the caller can advance their cursor explicitly (matches every other
/// Rust port in this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VInt {
  /// Decoded numeric value. `i64::MIN` is reserved for the "unknown / reserved"
  /// case (Perl `return -1`) — wider than `u64::MAX` would require, but every
  /// EBML element-id / size that fits in 8 bytes also fits in `i64::MAX`
  /// (highest VINT length is 8 ⇒ 56 data bits ⇒ ≤ `2^56 - 1` ≤ `i64::MAX`).
  value: i64,
  /// Whether the decoded value is the "unknown / reserved" sentinel (Perl
  /// `return -1` arm; every data bit was 1 ⇒ EBML reserved encoding).
  unknown: bool,
  /// Number of bytes consumed from the input buffer.
  consumed: usize,
}

impl VInt {
  /// Decoded numeric value (or `i64::MIN` for the unknown/reserved case).
  #[must_use]
  #[inline(always)]
  pub const fn value(self) -> i64 {
    self.value
  }
  /// `true` for the "unknown / reserved" arm (Perl `return -1`).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(self) -> bool {
    self.unknown
  }
  /// Number of bytes consumed from the buffer.
  #[must_use]
  #[inline(always)]
  pub const fn consumed(self) -> usize {
    self.consumed
  }
}

/// Read one VINT from `buf` at `pos`. Returns `None` on insufficient bytes
/// (matches Perl `return undef` — Matroska.pm:958/962/974).
///
/// The decoded value always has the EBML length-marker bit stripped. This
/// matches the bundled Perl `GetVInt` behavior used by this port for both
/// element IDs and sizes; Matroska tag IDs in the bundled tables are stored
/// without the length designation bits (Matroska.pm:39-40).
#[must_use]
pub fn get_vint(buf: &[u8], pos: usize) -> Option<VInt> {
  if pos >= buf.len() {
    return None; // Matroska.pm:958 `return undef if $_[1] >= length $_[0]`
  }
  let first = buf[pos];
  let mut num: usize = 0; // additional bytes to read
  let val_first = if first == 0 {
    // Matroska.pm:961-966 — leading zero byte ⇒ jump 7 ahead.
    if pos + 1 >= buf.len() {
      return None;
    }
    let second = buf[pos + 1];
    if second == 0 {
      return None; // Matroska.pm:964 `return undef unless $val` (too large)
    }
    num = 7;
    second
  } else {
    first
  };
  // Matroska.pm:967-971 — find the length marker bit (highest set bit).
  let mut mask: u8 = 0x7f;
  let mut shift = 0u32;
  let mut v = val_first;
  while v == (v & mask) {
    mask >>= 1;
    shift += 1;
  }
  num += shift as usize;
  v &= mask;
  let mut unknown = v == mask;
  // The total length is 1 (the first non-zero byte) + num extra bytes.
  // When `first` was 0, we skipped 1 byte and `num` starts at 7, so the
  // total is 9 bytes — Perl uses `$num=7` BEFORE counting `shift`, so the
  // total bytes consumed are `1 (first 0) + 1 (val_first) + (7 + shift)`.
  // Actually re-read Perl: `$_[1]++` runs THREE times across `++` reads:
  // once for the initial byte (offset 1 of the buffer), once again for
  // the zero-skip branch (line 963), and once per extra byte in the
  // `while ($num)` loop (line 976). Total = 1 + (1 if zero-skip) + num.
  let first_consumed: usize = if first == 0 { 2 } else { 1 };
  if pos + first_consumed + num > buf.len() {
    return None; // Matroska.pm:974 `return undef if $_[1] + $num > length $_[0]`
  }
  let mut acc: i64 = i64::from(v);
  let mut i = 0usize;
  while i < num {
    let b = buf[pos + first_consumed + i];
    if b != 0xff {
      unknown = false;
    }
    // `acc * 256 + b` — every fit-in-8-VINT case is ≤ 2^56-1 ≤ i64::MAX.
    acc = acc.wrapping_mul(256).wrapping_add(i64::from(b));
    i += 1;
  }
  let value = if unknown { i64::MIN } else { acc };
  Some(VInt {
    value,
    unknown,
    consumed: first_consumed + num,
  })
}

// ===========================================================================
// Tag table (Matroska.pm:41-708)
// ===========================================================================

/// Element semantic — what to do with the value bytes the EBML walker reads.
///
/// `SubDir` is a container (recurse). The other variants describe leaf
/// decode (Format) + post-decode conversions (PrintConv hash, ValueConv).
///
/// Some variants (`Signed`, `DefaultDuration`, `VideoFrameRate`) are never
/// referenced from the static `TAG_TABLE` today because the fixture's
/// Matroska elements all go through `Unsigned`/`Float`/conditional
/// dispatch. They remain as exhaustive documentation of the Matroska.pm
/// format set and so that future tag-table additions can use them
/// without re-introducing the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Kind {
  /// EBML container — recurse into the body. Faithful to the
  /// `SubDirectory => { TagTable => Image::ExifTool::Matroska::Main }`
  /// arm (Matroska.pm:60-708, every `SubDir => {…}` entry).
  SubDir,
  /// Skip silently — Matroska.pm `NoSave => 1` arm (Matroska.pm:80, 204,
  /// 209-210, 220, 237, 251) AND every `Unknown => 1` arm. Bundled
  /// ExifTool walks past these without emitting any tag.
  Skip,
  /// Master container that stops the walker (faithful to bundled's
  /// default Cluster handling — Matroska.pm:1096-1105). When the walker
  /// encounters `Cluster` and `$processAll < 2` (default; no `-v`, no
  /// `-U > 1`, no `-ee`), bundled tries the SeekHead Tags-jump and
  /// otherwise `last`s the walk. We don't have SeekHead support yet so
  /// our equivalent of "no Tags-jump available" is the `last` path:
  /// stop walking entirely the first time we see a Cluster.
  ///
  /// This means Tags / Attachments / etc. that appear AFTER a Cluster
  /// (without a SeekHead pointer that we could honor) WILL be missed —
  /// faithful to bundled's default behaviour. Documented +
  /// visibility-deferred SeekHead support is in `docs/tracking.md`.
  ///
  /// Why not advance-past-body? That's bundled's `-ee` mode, NOT the
  /// default. Round-1 finding F3's plan suggested it, but bundled
  /// default `-j -G1:1 -api struct=1` (our parity reference) takes the
  /// `last` path — so we faithfully stop.
  SkipBody,
  /// Binary leaf — emit raw bytes as the ExifTool
  /// `(Binary data <N> bytes, use -b option to extract)` placeholder.
  /// Faithful to the `Format => 'binary'` / `Binary => 1` rows in
  /// Matroska.pm (AttachedFileData line 552 `# Binary`, TagBinary line
  /// 695 `# Binary`).
  Binary,
  /// `Format => 'unsigned'` — BE big-int decoded into i64.
  Unsigned(PrintConv),
  /// `Format => 'signed'` — BE big-int with sign-extension.
  Signed(PrintConv),
  /// `Format => 'float'` — 4-byte single OR 8-byte double, BE.
  Float(FloatConv),
  /// `Format => 'string'` — ASCII, NUL-trimmed.
  AsciiString,
  /// `Format => 'utf8'` — UTF-8, NUL-trimmed.
  Utf8String,
  /// `Format => 'date'` — i64 nanoseconds since 2001-01-01.
  Date,
  /// `Format => 'string'` with `ValueConv => 'unpack("H*",$val)'` — Matroska
  /// `%uidInfo` (Matroska.pm:33-36): the tag is emitted as the lowercase
  /// hex string of the on-disk bytes.
  UidHex,
  /// Unsigned but with a one-shot ValueConv that uses `TimecodeScale` (an
  /// element of the same Info container) — `TimecodeScale` itself
  /// (Matroska.pm:160-166), `Duration` (Matroska.pm:167-172), and
  /// `DefaultDuration` (Matroska.pm:301-306).
  TimecodeScale,
  /// `Duration` (Matroska.pm:167-172) — `Format => 'float'`, `ValueConv =>
  /// '$$self{TimecodeScale} ? $val * $$self{TimecodeScale} / 1e9 : $val /
  /// 1000'`, `PrintConv => '$$self{TimecodeScale} ? ConvertDuration($val) :
  /// $val'`.
  Duration,
  /// `DefaultDuration` (Matroska.pm:302-306) — `Format => 'unsigned'`,
  /// `ValueConv => '$val / 1e9'`, `PrintConv => '($val * 1000) . " ms"'`.
  DefaultDuration,
  /// `VideoFrameRate` (Matroska.pm:294-301) — `Format => 'unsigned'`,
  /// `ValueConv => '$val ? 1e9 / $val : 0'`, `PrintConv =>
  /// 'int($val * 1000 + 0.5) / 1000'`.
  VideoFrameRate,
  /// `ChapterTimeStart` / `ChapterTimeEnd` (Matroska.pm:580-592) —
  /// `Format => 'unsigned'`, `ValueConv => '$val / 1e9'`,
  /// `PrintConv => 'ConvertDuration($val)'`. The raw u64 nanoseconds are
  /// stored; the output-time emission path divides by 1e9 to seconds and
  /// (in `-j` mode) runs `ConvertDuration` for the `H:MM:SS` rendering.
  ChapterTimeNs,
}

/// PrintConv (the -j string) variations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrintConv {
  /// Identity — emit the post-ValueConv value as-is.
  Identity,
  /// Map raw u64 → `&'static str` via a static-slice lookup.
  Map(&'static [(u64, &'static str)]),
  /// `\%noYes` — `0 => "No"`, `1 => "Yes"` (Matroska.pm:22).
  NoYes,
}

/// Float decoding variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloatConv {
  /// Default float — pure ValueConv identity.
  Identity,
}

/// One EBML element descriptor.
#[derive(Debug, Clone, Copy)]
struct TagDef {
  /// Element ID (without length marker — Matroska.pm:39-40).
  id: i64,
  /// Tag name (`Name => '…'`).
  name: &'static str,
  /// Decode + conversion semantics.
  kind: Kind,
}

/// One-shot exhaustive lookup table — Matroska.pm:41-708. Every ported
/// element is listed by integer ID. Returns `None` for an unknown ID
/// (faithful to Matroska.pm:1127-1129 "Unknown tag" verbose log + walk
/// past).
const TAG_TABLE: &[TagDef] = &[
  // --- EBML Header (Matroska.pm:60-75) -----------------------------------
  TagDef {
    id: 0xa45dfa3,
    name: "EBMLHeader",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x286,
    name: "EBMLVersion",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x2f7,
    name: "EBMLReadVersion",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x2f2,
    name: "EBMLMaxIDLength",
    kind: Kind::Skip,
  }, // Unknown => 1
  TagDef {
    id: 0x2f3,
    name: "EBMLMaxSizeLength",
    kind: Kind::Skip,
  }, // Unknown => 1
  TagDef {
    id: 0x282,
    name: "DocType",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x287,
    name: "DocTypeVersion",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x285,
    name: "DocTypeReadVersion",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  // --- General (Matroska.pm:79-80) ---------------------------------------
  TagDef {
    id: 0x3f,
    name: "CRC-32",
    kind: Kind::Skip,
  }, // Unknown => 1
  TagDef {
    id: 0x6c,
    name: "Void",
    kind: Kind::Skip,
  }, // NoSave => 1
  // --- Signature (Matroska.pm:84-100) ------------------------------------
  TagDef {
    id: 0xb538667,
    name: "SignatureSlot",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x3e8a,
    name: "SignatureAlgo",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x3e9a,
    name: "SignatureHash",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x3ea5,
    name: "SignaturePublicKey",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x3eb5,
    name: "Signature",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x3e5b,
    name: "SignatureElements",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x3e7b,
    name: "SignatureElementList",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x2532,
    name: "SignedElement",
    kind: Kind::Skip,
  },
  // --- Segment (Matroska.pm:104-134) -------------------------------------
  TagDef {
    id: 0x8538067,
    name: "SegmentHeader",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x14d9b74,
    name: "SeekHead",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0xdbb,
    name: "Seek",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x13ab,
    name: "SeekID",
    kind: Kind::Skip,
  }, // Unknown => 1
  TagDef {
    id: 0x13ac,
    name: "SeekPosition",
    kind: Kind::Skip,
  }, // Unknown => 1
  // --- Segment Info (Matroska.pm:138-182) --------------------------------
  TagDef {
    id: 0x549a966,
    name: "Info",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x33a4,
    name: "SegmentUID",
    kind: Kind::Skip,
  }, // Unknown=>1
  TagDef {
    id: 0x3384,
    name: "SegmentFileName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x1cb923,
    name: "PrevUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1c83ab,
    name: "PrevFileName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x1eb923,
    name: "NextUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1e83bb,
    name: "NextFileName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x0444,
    name: "SegmentFamily",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2924,
    name: "ChapterTranslate",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x29fc,
    name: "ChapterTranslateEditionUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x29bf,
    name: "ChapterTranslateCodec",
    kind: Kind::Unsigned(PrintConv::Map(&[(0, "Matroska Script"), (1, "DVD Menu")])),
  },
  TagDef {
    id: 0x29a5,
    name: "ChapterTranslateID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0xad7b1,
    name: "TimecodeScale",
    kind: Kind::TimecodeScale,
  },
  TagDef {
    id: 0x489,
    name: "Duration",
    kind: Kind::Duration,
  },
  TagDef {
    id: 0x461,
    name: "DateTimeOriginal",
    kind: Kind::Date,
  },
  TagDef {
    id: 0x3ba9,
    name: "Title",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0xd80,
    name: "MuxingApp",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x1741,
    name: "WritingApp",
    kind: Kind::Utf8String,
  },
  // --- Cluster (Matroska.pm:186-251) -------------------------------------
  // Cluster is the media-payload container. Bundled's DEFAULT behavior
  // (Matroska.pm:1096-1105 — no `-v`, no `-U > 1`, no `-ee`) is to
  // `last` the walker entirely the first time it sees a Cluster (no
  // metadata in cluster bodies). We use `Kind::SkipBody`, which our
  // walker maps to `break` — faithful to bundled default mode. See the
  // `Kind::SkipBody` enum doc for the SeekHead-deferral rationale.
  TagDef {
    id: 0xf43b675,
    name: "Cluster",
    kind: Kind::SkipBody,
  },
  TagDef {
    id: 0x67,
    name: "TimeCode",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x1854,
    name: "SilentTracks",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x18d7,
    name: "SilentTrackNumber",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x27,
    name: "Position",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x2b,
    name: "PrevSize",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x23,
    name: "SimpleBlock",
    kind: Kind::Skip,
  }, // NoSave
  TagDef {
    id: 0x20,
    name: "BlockGroup",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x21,
    name: "Block",
    kind: Kind::Skip,
  }, // NoSave
  TagDef {
    id: 0x22,
    name: "BlockVirtual",
    kind: Kind::Skip,
  }, // NoSave
  TagDef {
    id: 0x35a1,
    name: "BlockAdditions",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x26,
    name: "BlockMore",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x6e,
    name: "BlockAddID",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x25,
    name: "BlockAdditional",
    kind: Kind::Skip,
  }, // NoSave
  TagDef {
    id: 0x1b,
    name: "BlockDuration",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x7a,
    name: "ReferencePriority",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x7b,
    name: "ReferenceBlock",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x7d,
    name: "ReferenceVirtual",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x24,
    name: "CodecState",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x0e,
    name: "Slices",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x68,
    name: "TimeSlice",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x4c,
    name: "LaceNumber",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x4d,
    name: "FrameNumber",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x4b,
    name: "BlockAdditionalID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x4e,
    name: "Delay",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x4f,
    name: "ClusterDuration",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2f,
    name: "EncryptedBlock",
    kind: Kind::Skip,
  }, // NoSave
  // --- Tracks (Matroska.pm:255-359) --------------------------------------
  TagDef {
    id: 0x654ae6b,
    name: "Tracks",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x2e,
    name: "TrackEntry",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x57,
    name: "TrackNumber",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x33c5,
    name: "TrackUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x03,
    name: "TrackType",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0x01, "Video"),
      (0x02, "Audio"),
      (0x03, "Complex"),
      (0x10, "Logo"),
      (0x11, "Subtitle"),
      (0x12, "Buttons"),
      (0x20, "Control"),
    ])),
  },
  TagDef {
    id: 0x39,
    name: "TrackUsed",
    kind: Kind::Unsigned(PrintConv::NoYes),
  },
  TagDef {
    id: 0x08,
    name: "TrackDefault",
    kind: Kind::Unsigned(PrintConv::NoYes),
  },
  TagDef {
    id: 0x15aa,
    name: "TrackForced",
    kind: Kind::Unsigned(PrintConv::NoYes),
  },
  TagDef {
    id: 0x1c,
    name: "TrackLacing",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2de7,
    name: "MinCache",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2df8,
    name: "MaxCache",
    kind: Kind::Skip,
  }, // Unknown
  // 0x3e383 — VideoFrameRate (Track1 ⇒ TrackType==Video) OR
  // DefaultDuration (Track2 ⇒ TrackType!=Video) — Matroska.pm:294-307.
  TagDef {
    id: 0x3e383,
    name: "_TrackDefault0x3e383",
    kind: Kind::Skip,
  }, // dispatched by context
  TagDef {
    id: 0x3314f,
    name: "TrackTimecodeScale",
    kind: Kind::Float(FloatConv::Identity),
  },
  TagDef {
    id: 0x137f,
    name: "TrackOffset",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x15ee,
    name: "MaxBlockAdditionID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x136e,
    name: "TrackName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x2b59c,
    name: "TrackLanguage",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x2b59d,
    name: "TrackLanguageIETF",
    kind: Kind::AsciiString,
  },
  // 0x06 — Video/Audio/CodecID conditional (Matroska.pm:314-327) — same
  // dispatch as 0x3e383 above.
  TagDef {
    id: 0x06,
    name: "_CodecID0x06",
    kind: Kind::Skip,
  }, // dispatched by context
  TagDef {
    id: 0x23a2,
    name: "CodecPrivate",
    kind: Kind::Skip,
  }, // Unknown
  // 0x58688 — VideoCodecName/AudioCodecName/CodecName conditional.
  TagDef {
    id: 0x58688,
    name: "_CodecName0x58688",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x3446,
    name: "TrackAttachmentUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x1a9697,
    name: "CodecSettings",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x1b4040,
    name: "CodecInfoURL",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x6b240,
    name: "CodecDownloadURL",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x2a,
    name: "CodecDecodeAll",
    kind: Kind::Unsigned(PrintConv::NoYes),
  },
  TagDef {
    id: 0x2fab,
    name: "TrackOverlay",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2624,
    name: "TrackTranslate",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x26fc,
    name: "TrackTranslateEditionUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x26bf,
    name: "TrackTranslateCodec",
    kind: Kind::Unsigned(PrintConv::Map(&[(0, "Matroska Script"), (1, "DVD Menu")])),
  },
  TagDef {
    id: 0x26a5,
    name: "TrackTranslateTrackID",
    kind: Kind::Skip,
  },
  // --- Video (Matroska.pm:363-416) ---------------------------------------
  TagDef {
    id: 0x60,
    name: "Video",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x1a,
    name: "VideoScanType",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Undetermined"),
      (1, "Interlaced"),
      (2, "Progressive"),
    ])),
  },
  TagDef {
    id: 0x13b8,
    name: "Stereo3DMode",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Mono"),
      (1, "Right Eye"),
      (2, "Left Eye"),
      (3, "Both Eyes"),
    ])),
  },
  TagDef {
    id: 0x30,
    name: "ImageWidth",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x3a,
    name: "ImageHeight",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14aa,
    name: "CropBottom",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14bb,
    name: "CropTop",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14cc,
    name: "CropLeft",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14dd,
    name: "CropRight",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14b0,
    name: "DisplayWidth",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14ba,
    name: "DisplayHeight",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x14b2,
    name: "DisplayUnit",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Pixels"),
      (1, "cm"),
      (2, "inches"),
      (3, "Display Aspect Ratio"),
      (4, "Unknown"),
    ])),
  },
  TagDef {
    id: 0x14b3,
    name: "AspectRatioType",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Free Resizing"),
      (1, "Keep Aspect Ratio"),
      (2, "Fixed"),
    ])),
  },
  TagDef {
    id: 0xeb524,
    name: "ColorSpace",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0xfb523,
    name: "Gamma",
    kind: Kind::Float(FloatConv::Identity),
  },
  TagDef {
    id: 0x383e3,
    name: "FrameRate",
    kind: Kind::Float(FloatConv::Identity),
  },
  // --- Audio (Matroska.pm:420-433) ---------------------------------------
  TagDef {
    id: 0x61,
    name: "Audio",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x35,
    name: "AudioSampleRate",
    kind: Kind::Float(FloatConv::Identity),
  },
  TagDef {
    id: 0x38b5,
    name: "OutputAudioSampleRate",
    kind: Kind::Float(FloatConv::Identity),
  },
  TagDef {
    id: 0x1f,
    name: "AudioChannels",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  TagDef {
    id: 0x3d7b,
    name: "ChannelPositions",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x2264,
    name: "AudioBitsPerSample",
    kind: Kind::Unsigned(PrintConv::Identity),
  },
  // --- Content Encoding (Matroska.pm:437-502) ----------------------------
  TagDef {
    id: 0x2d80,
    name: "ContentEncodings",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x2240,
    name: "ContentEncoding",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x1031,
    name: "ContentEncodingOrder",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1032,
    name: "ContentEncodingScope",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1033,
    name: "ContentEncodingType",
    kind: Kind::Unsigned(PrintConv::Map(&[(0, "Compression"), (1, "Encryption")])),
  },
  TagDef {
    id: 0x1034,
    name: "ContentCompression",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x254,
    name: "ContentCompressionAlgorithm",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "zlib"),
      (1, "bzlib"),
      (2, "lzo1x"),
      (3, "Header Stripping"),
    ])),
  },
  TagDef {
    id: 0x255,
    name: "ContentCompressionSettings",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1035,
    name: "ContentEncryption",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x7e1,
    name: "ContentEncryptionAlgorithm",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Not Encrypted"),
      (1, "DES"),
      (2, "3DES"),
      (3, "Twofish"),
      (4, "Blowfish"),
      (5, "AES"),
    ])),
  },
  TagDef {
    id: 0x7e2,
    name: "ContentEncryptionKeyID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x7e3,
    name: "ContentSignature",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x7e4,
    name: "ContentSignatureKeyID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x7e5,
    name: "ContentSignatureAlgorithm",
    kind: Kind::Unsigned(PrintConv::Map(&[(0, "Not Signed"), (1, "RSA")])),
  },
  TagDef {
    id: 0x7e6,
    name: "ContentSignatureHashAlgorithm",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (0, "Not Signed"),
      (1, "SHA1-160"),
      (2, "MD5"),
    ])),
  },
  // --- Cues (Matroska.pm:506-542) ----------------------------------------
  TagDef {
    id: 0xc53bb6b,
    name: "Cues",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x3b,
    name: "CuePoint",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x33,
    name: "CueTime",
    kind: Kind::Skip,
  }, // Unknown
  TagDef {
    id: 0x37,
    name: "CueTrackPositions",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x77,
    name: "CueTrack",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x71,
    name: "CueClusterPosition",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x1378,
    name: "CueBlockNumber",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x6a,
    name: "CueCodecState",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x5b,
    name: "CueReference",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x16,
    name: "CueRefTime",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x17,
    name: "CueRefCluster",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x135f,
    name: "CueRefNumber",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x6b,
    name: "CueRefCodecState",
    kind: Kind::Skip,
  },
  // --- Attachments (Matroska.pm:546-559) ---------------------------------
  TagDef {
    id: 0x941a469,
    name: "Attachments",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x21a7,
    name: "AttachedFile",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x67e,
    name: "AttachedFileDescription",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x66e,
    name: "AttachedFileName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x660,
    name: "AttachedFileMIMEType",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x65c,
    name: "AttachedFileData",
    kind: Kind::Binary,
  }, // Binary (Matroska.pm:552; bundled emits as `(Binary data N bytes, use -b option to extract)` placeholder)
  TagDef {
    id: 0x6ae,
    name: "AttachedFileUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x675,
    name: "AttachedFileReferral",
    kind: Kind::Skip,
  },
  // --- Chapters (Matroska.pm:563-647) ------------------------------------
  TagDef {
    id: 0x43a770,
    name: "Chapters",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x5b9,
    name: "EditionEntry",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x5bc,
    name: "EditionUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x5bd,
    name: "EditionFlagHidden",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x5db,
    name: "EditionFlagDefault",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x5dd,
    name: "EditionFlagOrdered",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x36,
    name: "ChapterAtom",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x33c4,
    name: "ChapterUID",
    kind: Kind::Skip,
  },
  TagDef {
    // Matroska.pm:580-586 — `Format => 'unsigned'`, `ValueConv => '$val /
    // 1e9'`, `PrintConv => 'ConvertDuration($val)'`. Group `Chapter#` per
    // `Groups => { 1 => 'Chapter#' }`; the family-1 switch is handled at
    // the `ChapterAtom` SubDir enter (Matroska.pm:1117-1118).
    id: 0x11,
    name: "ChapterTimeStart",
    kind: Kind::ChapterTimeNs,
  },
  TagDef {
    // Matroska.pm:587-592 — same `unsigned` + `/1e9` + `ConvertDuration`
    // semantics as ChapterTimeStart (note Matroska.pm:588 omits the
    // `Groups => { 1 => 'Chapter#' }` for ChapterTimeEnd but the family-1
    // group still comes from the surrounding ChapterAtom SET_GROUP1 push).
    id: 0x12,
    name: "ChapterTimeEnd",
    kind: Kind::ChapterTimeNs,
  },
  TagDef {
    id: 0x18,
    name: "ChapterFlagHidden",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x598,
    name: "ChapterFlagEnabled",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x2e67,
    name: "ChapterSegmentUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x2ebc,
    name: "ChapterSegmentEditionUID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x23c3,
    name: "ChapterPhysicalEquivalent",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (10, "Index"),
      (20, "Track"),
      (30, "Session"),
      (40, "Layer"),
      (50, "Side"),
      (60, "CD / DVD"),
      (70, "Set / Package"),
    ])),
  },
  TagDef {
    id: 0x0f,
    name: "ChapterTrack",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x09,
    name: "ChapterTrackNumber",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x00,
    name: "ChapterDisplay",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x05,
    name: "ChapterString",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x37c,
    name: "ChapterLanguage",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x37e,
    name: "ChapterCountry",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x2944,
    name: "ChapterProcess",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x2955,
    name: "ChapterProcessCodecID",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x50d,
    name: "ChapterProcessPrivate",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x2911,
    name: "ChapterProcessCommand",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x2922,
    name: "ChapterProcessTime",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x2933,
    name: "ChapterProcessData",
    kind: Kind::Skip,
  },
  // --- Tags (Matroska.pm:651-692) ----------------------------------------
  TagDef {
    id: 0x254c367,
    name: "Tags",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x3373,
    name: "Tag",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x23c0,
    name: "Targets",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x28ca,
    name: "TargetTypeValue",
    kind: Kind::Unsigned(PrintConv::Map(&[
      (10, "Shot"),
      (20, "Scene/Subtrack"),
      (30, "Chapter/Track"),
      (40, "Session"),
      (50, "Movie/Album"),
      (60, "Season/Edition"),
      (70, "Collection"),
    ])),
  },
  TagDef {
    id: 0x23ca,
    name: "TargetType",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x23c5,
    name: "TagTrackUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x23c9,
    name: "TagEditionUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x23c4,
    name: "TagChapterUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x23c6,
    name: "TagAttachmentUID",
    kind: Kind::UidHex,
  },
  TagDef {
    id: 0x27c8,
    name: "SimpleTag",
    kind: Kind::SubDir,
  },
  TagDef {
    id: 0x5a3,
    name: "TagName",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x47a,
    name: "TagLanguage",
    kind: Kind::AsciiString,
  },
  TagDef {
    id: 0x484,
    name: "TagDefault",
    kind: Kind::Unsigned(PrintConv::NoYes),
  },
  TagDef {
    id: 0x487,
    name: "TagString",
    kind: Kind::Utf8String,
  },
  TagDef {
    id: 0x485,
    name: "TagBinary",
    kind: Kind::Binary,
  }, // Binary (Matroska.pm:695; bundled emits as `(Binary data N bytes, use -b option to extract)` placeholder)
];

/// Resolve `id` → `TagDef`. `None` for unknown ID (faithful to
/// Matroska.pm:1127-1129 — "unknown tag, verbose log, skip past size bytes").
fn tag_def(id: i64) -> Option<&'static TagDef> {
  TAG_TABLE.iter().find(|t| t.id == id)
}

// ===========================================================================
// StdTag table — Matroska.pm:750-891 `%Image::ExifTool::Matroska::StdTag`
// ===========================================================================

/// One entry in the SimpleTag-key → canonical-tag-name table.
///
/// Faithful port of the static rows from `%Image::ExifTool::Matroska::StdTag`
/// (Matroska.pm:750-891). The Perl Map maps SimpleTag `TagName` text →
/// canonical tag identifier; rows like `DATE_RELEASED => { Name =>
/// 'DateReleased', %dateInfo }` are encoded as `StdTagEntry { key:
/// "DATE_RELEASED", name: "DateReleased", is_date: true }`.
///
/// Entries with `%dateInfo` ⇒ `is_date = true`: the SimpleTag's `TagString`
/// is post-processed via `dateInfo.ValueConv` (Matroska.pm:29 — `s/^(\d{4})-
/// (\d{2})-/$1:$2:/`) before emission.
///
/// Entries without `%dateInfo` ⇒ `is_date = false`: emitted as-is.
///
/// Note (deferred): the Perl table also has `IsList`-typed rows
/// (`INSTRUMENTS`, `KEYWORDS`) that split on `,\s?`, and embedded
/// SubDirectory rows (`spherical-video` → XMP). These are NOT exercised by
/// the synthetic fixture and are documented + visibility-deferred.
#[derive(Debug, Clone, Copy)]
struct StdTagEntry {
  /// The TagName text as it appears in the on-disk SimpleTag (e.g.
  /// `"TITLE"`, `"DATE_RELEASED"`).
  key: &'static str,
  /// The canonical tag name to emit (e.g. `"Title"`, `"DateReleased"`).
  name: &'static str,
  /// Whether the value should pass through dateInfo's `ValueConv`
  /// (`s/^(\d{4})-(\d{2})-/$1:$2:/` — replace the first two `-` with `:`).
  is_date: bool,
}

/// `%Image::ExifTool::Matroska::StdTag` (Matroska.pm:750-891). Faithful
/// port of the static rows. Lookup is linear (table is short by Matroska's
/// standards; sub-100 ns even at this size).
const STD_TAG_TABLE: &[StdTagEntry] = &[
  // ----- Container/grouping (Matroska.pm:758-767) -----------------------
  StdTagEntry {
    key: "ORIGINAL",
    name: "Original",
    is_date: false,
  },
  StdTagEntry {
    key: "SAMPLE",
    name: "Sample",
    is_date: false,
  },
  StdTagEntry {
    key: "COUNTRY",
    name: "Country",
    is_date: false,
  },
  // ----- Numbering (Matroska.pm:761-763) --------------------------------
  StdTagEntry {
    key: "TOTAL_PARTS",
    name: "TotalParts",
    is_date: false,
  },
  StdTagEntry {
    key: "PART_NUMBER",
    name: "PartNumber",
    is_date: false,
  },
  StdTagEntry {
    key: "PART_OFFSET",
    name: "PartOffset",
    is_date: false,
  },
  // ----- Identification (Matroska.pm:764-767) ---------------------------
  StdTagEntry {
    key: "TITLE",
    name: "Title",
    is_date: false,
  },
  StdTagEntry {
    key: "SUBTITLE",
    name: "Subtitle",
    is_date: false,
  },
  StdTagEntry {
    key: "URL",
    name: "URL",
    is_date: false,
  },
  StdTagEntry {
    key: "SORT_WITH",
    name: "SortWith",
    is_date: false,
  },
  // ----- Contact (Matroska.pm:773-776) ----------------------------------
  StdTagEntry {
    key: "EMAIL",
    name: "Email",
    is_date: false,
  },
  StdTagEntry {
    key: "ADDRESS",
    name: "Address",
    is_date: false,
  },
  StdTagEntry {
    key: "FAX",
    name: "FAX",
    is_date: false,
  },
  StdTagEntry {
    key: "PHONE",
    name: "Phone",
    is_date: false,
  },
  // ----- People (Matroska.pm:777-808) -----------------------------------
  StdTagEntry {
    key: "ARTIST",
    name: "Artist",
    is_date: false,
  },
  StdTagEntry {
    key: "LEAD_PERFORMER",
    name: "LeadPerformer",
    is_date: false,
  },
  StdTagEntry {
    key: "ACCOMPANIMENT",
    name: "Accompaniment",
    is_date: false,
  },
  StdTagEntry {
    key: "COMPOSER",
    name: "Composer",
    is_date: false,
  },
  StdTagEntry {
    key: "ARRANGER",
    name: "Arranger",
    is_date: false,
  },
  StdTagEntry {
    key: "LYRICS",
    name: "Lyrics",
    is_date: false,
  },
  StdTagEntry {
    key: "LYRICIST",
    name: "Lyricist",
    is_date: false,
  },
  StdTagEntry {
    key: "CONDUCTOR",
    name: "Conductor",
    is_date: false,
  },
  StdTagEntry {
    key: "DIRECTOR",
    name: "Director",
    is_date: false,
  },
  StdTagEntry {
    key: "ASSISTANT_DIRECTOR",
    name: "AssistantDirector",
    is_date: false,
  },
  StdTagEntry {
    key: "DIRECTOR_OF_PHOTOGRAPHY",
    name: "DirectorOfPhotography",
    is_date: false,
  },
  StdTagEntry {
    key: "SOUND_ENGINEER",
    name: "SoundEngineer",
    is_date: false,
  },
  StdTagEntry {
    key: "ART_DIRECTOR",
    name: "ArtDirector",
    is_date: false,
  },
  StdTagEntry {
    key: "PRODUCTION_DESIGNER",
    name: "ProductionDesigner",
    is_date: false,
  },
  StdTagEntry {
    key: "CHOREGRAPHER",
    name: "Choregrapher",
    is_date: false,
  },
  StdTagEntry {
    key: "COSTUME_DESIGNER",
    name: "CostumeDesigner",
    is_date: false,
  },
  StdTagEntry {
    key: "ACTOR",
    name: "Actor",
    is_date: false,
  },
  StdTagEntry {
    key: "CHARACTER",
    name: "Character",
    is_date: false,
  },
  StdTagEntry {
    key: "WRITTEN_BY",
    name: "WrittenBy",
    is_date: false,
  },
  StdTagEntry {
    key: "SCREENPLAY_BY",
    name: "ScreenplayBy",
    is_date: false,
  },
  StdTagEntry {
    key: "EDITED_BY",
    name: "EditedBy",
    is_date: false,
  },
  StdTagEntry {
    key: "PRODUCER",
    name: "Producer",
    is_date: false,
  },
  StdTagEntry {
    key: "COPRODUCER",
    name: "Coproducer",
    is_date: false,
  },
  StdTagEntry {
    key: "EXECUTIVE_PRODUCER",
    name: "ExecutiveProducer",
    is_date: false,
  },
  StdTagEntry {
    key: "DISTRIBUTED_BY",
    name: "DistributedBy",
    is_date: false,
  },
  StdTagEntry {
    key: "MASTERED_BY",
    name: "MasteredBy",
    is_date: false,
  },
  StdTagEntry {
    key: "ENCODED_BY",
    name: "EncodedBy",
    is_date: false,
  },
  StdTagEntry {
    key: "MIXED_BY",
    name: "MixedBy",
    is_date: false,
  },
  StdTagEntry {
    key: "REMIXED_BY",
    name: "RemixedBy",
    is_date: false,
  },
  StdTagEntry {
    key: "PRODUCTION_STUDIO",
    name: "ProductionStudio",
    is_date: false,
  },
  StdTagEntry {
    key: "THANKS_TO",
    name: "ThanksTo",
    is_date: false,
  },
  StdTagEntry {
    key: "PUBLISHER",
    name: "Publisher",
    is_date: false,
  },
  StdTagEntry {
    key: "LABEL",
    name: "Label",
    is_date: false,
  },
  // ----- Categories (Matroska.pm:810-823) -------------------------------
  StdTagEntry {
    key: "GENRE",
    name: "Genre",
    is_date: false,
  },
  StdTagEntry {
    key: "MOOD",
    name: "Mood",
    is_date: false,
  },
  StdTagEntry {
    key: "ORIGINAL_MEDIA_TYPE",
    name: "OriginalMediaType",
    is_date: false,
  },
  StdTagEntry {
    key: "CONTENT_TYPE",
    name: "ContentType",
    is_date: false,
  },
  StdTagEntry {
    key: "SUBJECT",
    name: "Subject",
    is_date: false,
  },
  StdTagEntry {
    key: "DESCRIPTION",
    name: "Description",
    is_date: false,
  },
  // KEYWORDS: deferred IsList split (Matroska.pm:816-820) — emitted as
  // joined string for now.
  StdTagEntry {
    key: "KEYWORDS",
    name: "Keywords",
    is_date: false,
  },
  StdTagEntry {
    key: "SUMMARY",
    name: "Summary",
    is_date: false,
  },
  StdTagEntry {
    key: "SYNOPSIS",
    name: "Synopsis",
    is_date: false,
  },
  StdTagEntry {
    key: "INITIAL_KEY",
    name: "InitialKey",
    is_date: false,
  },
  StdTagEntry {
    key: "PERIOD",
    name: "Period",
    is_date: false,
  },
  StdTagEntry {
    key: "LAW_RATING",
    name: "LawRating",
    is_date: false,
  },
  // ----- Dates (Matroska.pm:826-832) -- is_date = true ------------------
  StdTagEntry {
    key: "DATE_RELEASED",
    name: "DateReleased",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_RECORDED",
    name: "DateTimeOriginal",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_ENCODED",
    name: "DateEncoded",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_TAGGED",
    name: "DateTagged",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_DIGITIZED",
    name: "CreateDate",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_WRITTEN",
    name: "DateWritten",
    is_date: true,
  },
  StdTagEntry {
    key: "DATE_PURCHASED",
    name: "DatePurchased",
    is_date: true,
  },
  // ----- Geo + composition (Matroska.pm:833-836) ------------------------
  StdTagEntry {
    key: "RECORDING_LOCATION",
    name: "RecordingLocation",
    is_date: false,
  },
  StdTagEntry {
    key: "COMPOSITION_LOCATION",
    name: "CompositionLocation",
    is_date: false,
  },
  StdTagEntry {
    key: "COMPOSER_NATIONALITY",
    name: "ComposerNationality",
    is_date: false,
  },
  // ----- Comments + rating (Matroska.pm:836-840) ------------------------
  StdTagEntry {
    key: "COMMENT",
    name: "Comment",
    is_date: false,
  },
  StdTagEntry {
    key: "PLAY_COUNTER",
    name: "PlayCounter",
    is_date: false,
  },
  StdTagEntry {
    key: "RATING",
    name: "Rating",
    is_date: false,
  },
  // ----- Encoder (Matroska.pm:839-844) ----------------------------------
  StdTagEntry {
    key: "ENCODER",
    name: "Encoder",
    is_date: false,
  },
  StdTagEntry {
    key: "ENCODER_SETTINGS",
    name: "EncoderSettings",
    is_date: false,
  },
  StdTagEntry {
    key: "BPS",
    name: "BPS",
    is_date: false,
  },
  StdTagEntry {
    key: "FPS",
    name: "FPS",
    is_date: false,
  },
  StdTagEntry {
    key: "BPM",
    name: "BPM",
    is_date: false,
  },
  StdTagEntry {
    key: "MEASURE",
    name: "Measure",
    is_date: false,
  },
  StdTagEntry {
    key: "TUNING",
    name: "Tuning",
    is_date: false,
  },
  // ----- Replaygain (Matroska.pm:846-847) -------------------------------
  StdTagEntry {
    key: "REPLAYGAIN_GAIN",
    name: "ReplaygainGain",
    is_date: false,
  },
  StdTagEntry {
    key: "REPLAYGAIN_PEAK",
    name: "ReplaygainPeak",
    is_date: false,
  },
  // ----- Identifiers (Matroska.pm:848-857) ------------------------------
  StdTagEntry {
    key: "ISRC",
    name: "ISRC",
    is_date: false,
  },
  StdTagEntry {
    key: "MCDI",
    name: "MCDI",
    is_date: false,
  },
  StdTagEntry {
    key: "ISBN",
    name: "ISBN",
    is_date: false,
  },
  StdTagEntry {
    key: "BARCODE",
    name: "Barcode",
    is_date: false,
  },
  StdTagEntry {
    key: "CATALOG_NUMBER",
    name: "CatalogNumber",
    is_date: false,
  },
  StdTagEntry {
    key: "LABEL_CODE",
    name: "LabelCode",
    is_date: false,
  },
  StdTagEntry {
    key: "LCCN",
    name: "Lccn",
    is_date: false,
  },
  StdTagEntry {
    key: "IMDB",
    name: "IMDB",
    is_date: false,
  },
  StdTagEntry {
    key: "TMDB",
    name: "TMDB",
    is_date: false,
  },
  StdTagEntry {
    key: "TVDB",
    name: "TVDB",
    is_date: false,
  },
  // ----- Purchase (Matroska.pm:858-862) ---------------------------------
  StdTagEntry {
    key: "PURCHASE_ITEM",
    name: "PurchaseItem",
    is_date: false,
  },
  StdTagEntry {
    key: "PURCHASE_INFO",
    name: "PurchaseInfo",
    is_date: false,
  },
  StdTagEntry {
    key: "PURCHASE_OWNER",
    name: "PurchaseOwner",
    is_date: false,
  },
  StdTagEntry {
    key: "PURCHASE_PRICE",
    name: "PurchasePrice",
    is_date: false,
  },
  StdTagEntry {
    key: "PURCHASE_CURRENCY",
    name: "PurchaseCurrency",
    is_date: false,
  },
  // ----- Rights (Matroska.pm:863-866) -----------------------------------
  StdTagEntry {
    key: "COPYRIGHT",
    name: "Copyright",
    is_date: false,
  },
  StdTagEntry {
    key: "PRODUCTION_COPYRIGHT",
    name: "ProductionCopyright",
    is_date: false,
  },
  StdTagEntry {
    key: "LICENSE",
    name: "License",
    is_date: false,
  },
  StdTagEntry {
    key: "TERMS_OF_USE",
    name: "TermsOfUse",
    is_date: false,
  },
  // ----- "Other tags seen" (Matroska.pm:885-890) ------------------------
  StdTagEntry {
    key: "_STATISTICS_WRITING_DATE_UTC",
    name: "StatisticsWritingDateUTC",
    is_date: true,
  },
  StdTagEntry {
    key: "_STATISTICS_WRITING_APP",
    name: "StatisticsWritingApp",
    is_date: false,
  },
  StdTagEntry {
    key: "_STATISTICS_TAGS",
    name: "StatisticsTags",
    is_date: false,
  },
  StdTagEntry {
    key: "DURATION",
    name: "Duration",
    is_date: false,
  },
  StdTagEntry {
    key: "NUMBER_OF_FRAMES",
    name: "NumberOfFrames",
    is_date: false,
  },
  StdTagEntry {
    key: "NUMBER_OF_BYTES",
    name: "NumberOfBytes",
    is_date: false,
  },
];

/// Resolve a SimpleTag's `TagName` to its canonical tag name. Returns
/// `None` for unknown keys — the caller falls back to the bundled-Perl
/// "synthesize a name" path (Matroska.pm:905-911).
fn std_tag_lookup(key: &str) -> Option<StdTagEntry> {
  STD_TAG_TABLE.iter().find(|e| e.key == key).copied()
}

/// Synthesize a canonical tag name from an off-table TagName key — faithful
/// port of Matroska.pm:905-911:
///
/// ```perl
/// my $name = ucfirst lc $tag;
/// $name =~ tr/0-9a-zA-Z_//dc;       # drop non-alphanumeric_underscore
/// $name =~ s/_([a-z])/\U$1/g;       # camelCase _x -> X
/// $name = "Tag_$name" if length $name < 2;
/// ```
///
/// Order of operations matters: lowercase ALL, capitalize first character,
/// then trim non-alphanumeric_underscore, then process `_X` ⇒ `X` (camelCase).
fn synthesize_tag_name(raw: &str) -> String {
  // Step 1: lowercase
  let lc: String = raw.chars().map(|c| c.to_ascii_lowercase()).collect();
  // Step 2: capitalize first char (Perl `ucfirst`)
  let mut chars = lc.chars();
  let first = chars.next().map(|c| c.to_ascii_uppercase());
  let rest: String = chars.collect();
  let mut name = String::with_capacity(raw.len());
  if let Some(f) = first {
    name.push(f);
  }
  name.push_str(&rest);
  // Step 3: drop non-alphanumeric_underscore (Perl `tr/0-9a-zA-Z_//dc`)
  name.retain(|c| c.is_ascii_alphanumeric() || c == '_');
  // Step 4: `_x` ⇒ `X` (camelCase — Perl `s/_([a-z])/\U$1/g`)
  let mut out = String::with_capacity(name.len());
  let mut chars = name.chars();
  while let Some(c) = chars.next() {
    if c == '_' {
      if let Some(next) = chars.next() {
        if next.is_ascii_lowercase() {
          out.push(next.to_ascii_uppercase());
        } else {
          out.push('_');
          out.push(next);
        }
      } else {
        out.push('_');
      }
    } else {
      out.push(c);
    }
  }
  // Step 5: short-name guard (Matroska.pm:909)
  if out.len() < 2 {
    let mut prefixed = String::with_capacity(out.len() + 4);
    prefixed.push_str("Tag_");
    prefixed.push_str(&out);
    out = prefixed;
  }
  out
}

// ===========================================================================
// PrintConv helpers
// ===========================================================================

/// Lookup `code` in the static `(u64, &str)` slice; `None` on miss.
fn lookup_map(map: &'static [(u64, &'static str)], code: u64) -> Option<&'static str> {
  map.iter().find_map(|(k, v)| (*k == code).then_some(*v))
}

/// `\%noYes` PrintConv (Matroska.pm:22 — `0 => 'No', 1 => 'Yes'`). Returns
/// `None` for off-table codes (verbose Perl prints them as bare digits,
/// faithful here as fallthrough to the integer raw rendering).
const fn no_yes_print_conv(code: u64) -> Option<&'static str> {
  match code {
    0 => Some("No"),
    1 => Some("Yes"),
    _ => None,
  }
}

// ===========================================================================
// Typed value carrier — `Value<'a>`
// ===========================================================================

/// Decoded leaf value for one EBML element. Carries the raw post-format
/// scalar (faithful to the Perl `$val` that flows through `HandleTag`).
///
/// D8 newtype-style — every variant is a single-field newtype data
/// carrier. `#[non_exhaustive]` so future Matroska elements can grow new
/// value kinds without breaking downstream matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Value<'a> {
  /// Decoded unsigned integer (BE big-int up to 8 bytes).
  U64(u64),
  /// Decoded signed integer (BE big-int, sign-extended).
  I64(i64),
  /// Decoded float (4- or 8-byte BE IEEE-754).
  F64(f64),
  /// Decoded string — borrows from input when possible (raw ASCII or UTF-8
  /// slice, NUL-trimmed).
  Str(Cow<'a, str>),
  /// Decoded date — i64 nanoseconds since 2001-01-01 (raw on-disk value).
  /// The PrintConv string is rendered at emit time via
  /// [`crate::datetime::convert_unix_time`].
  Date(i64),
  /// `%uidInfo` hex string — bytes stored as lowercase hex (Matroska.pm:33-36
  /// `ValueConv => 'unpack("H*",$val)'`).
  UidHex(SmolStr),
  /// `TimecodeScale` — raw u64 nanoseconds. ValueConv `/1e9` (Matroska.pm:
  /// 160-166); PrintConv `($val * 1000) . " ms"`.
  TimecodeScaleRaw(u64),
  /// `Duration` — raw f64 from the float decoder. ValueConv and PrintConv
  /// (Matroska.pm:170-171) are applied at output time with the FINAL
  /// `$$self{TimecodeScale}` (RawConv at Matroska.pm:163 stores it into
  /// `$$self`, ValueConv/PrintConv read it lazily during `FoundTag`'s
  /// downstream `GetValue` / `PrintValue` evaluation — empirically
  /// verified by feeding bundled-Perl a fixture with TimecodeScale AFTER
  /// Duration: the FINAL TimecodeScale drives both branches, even with
  /// multiple TimecodeScale values where the LAST one wins).
  ///
  /// Two faithfulness traps the previous implementation missed:
  /// - Perl truthiness for `$$self{TimecodeScale}` — `0` is FALSY, so an
  ///   explicit `TimecodeScale = 0` must take the `$val / 1000` branch
  ///   (NOT `$val * 0 / 1e9 = 0`). Handled by an explicit `ts != 0` guard
  ///   in [`emit_one`].
  /// - PrintConv branch must mirror ValueConv's truthiness (both gate on
  ///   the SAME `$$self{TimecodeScale} ?` ternary), so when the falsy
  ///   branch fires we emit the bare numeric `$val` (`-j` and `-n` both
  ///   become numeric).
  DurationRawF64(f64),
  /// `DefaultDuration` — raw u64 nanoseconds. ValueConv `/1e9`; PrintConv
  /// `($val * 1000) . " ms"` (Matroska.pm:301-306).
  DefaultDurationRaw(u64),
  /// `VideoFrameRate` — raw u64 nanoseconds-per-frame. ValueConv `1e9/$val`
  /// when non-zero, else 0; PrintConv `int($val * 1000 + 0.5) / 1000`
  /// (Matroska.pm:294-301).
  VideoFrameRateRaw(u64),
  /// `ChapterTimeStart` / `ChapterTimeEnd` (Matroska.pm:580-592) — raw u64
  /// nanoseconds. ValueConv `$val / 1e9` (seconds, f64), PrintConv
  /// `ConvertDuration($val)`. Both keys are emitted under the synthesized
  /// family-1 group `Chapter<n>` set when the enclosing `ChapterAtom` was
  /// entered (Matroska.pm:1117-1119).
  ChapterTimeRawNs(u64),
  /// Binary blob — emitted as ExifTool's
  /// `(Binary data <N> bytes, use -b option to extract)` placeholder
  /// in both `-j` and `-n` modes (TagValue::Bytes serialization in
  /// `value.rs`). Faithful to Matroska.pm:552 (AttachedFileData) and
  /// 695 (TagBinary) — `# Binary`.
  Bytes(Cow<'a, [u8]>),
}

/// One emitted tag in [`Meta::entries`]: family-1 group, tag name, raw
/// post-format value.
///
/// `name` is a [`SmolStr`] so SimpleTag synthesized names (Matroska.pm:
/// 905-911) — which produce dynamically-computed canonical names for
/// off-StdTag-table keys — can be carried alongside the static-string
/// names from `TAG_TABLE` without a separate variant. SmolStr inlines
/// strings up to 23 bytes, so every static `&'static str` from the
/// Matroska tag tables stays heap-free; only the rare synthesized name
/// allocates.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
  group: SmolStr,
  name: SmolStr,
  value: Value<'a>,
}

impl<'a> Entry<'a> {
  /// Family-1 group (e.g. `"Matroska"`, `"Info"`, `"Track1"`).
  #[must_use]
  #[inline(always)]
  pub fn group(&self) -> &str {
    self.group.as_str()
  }
  /// Tag name (e.g. `"DocType"`, `"TimecodeScale"`, `"TrackNumber"`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Decoded raw value (borrow of the non-`Copy` [`Value`]).
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &Value<'a> {
    &self.value
  }
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed Matroska metadata — the lib-first output of [`ProcessMatroska`].
///
/// D8 convention: no public fields; accessors only.
///
/// `Meta` carries an ordered list of [`Entry`] tags (faithful to Perl's
/// `FoundTag` call order), plus a few `Option<>` accessors for known-
/// scalar fields (DocType, TimecodeScale-ns) that callers commonly probe.
/// PrintConv strings are rendered at emit time via the
/// [`Taggable`](crate::emit::Taggable) impl; the raw values stored here are
/// post-Format-decode but pre-conversion.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  entries: Vec<Entry<'a>>,
  /// Cached `DocType` (Matroska.pm:68-72) — `"matroska"`, `"webm"`, etc.
  doc_type: Option<SmolStr>,
  /// Cached `TimecodeScale` raw nanoseconds (Matroska.pm:160-166). Drives
  /// the Duration / DefaultDuration / etc. ValueConv at emit time.
  timecode_scale_ns: Option<u64>,
  /// The `$et->Warn` channel (Phase B.1.5). Each entry is a faithful
  /// `$et->Warn(msg)` raised during the walk, carrying the family-1 group
  /// active at `Warn` time (the port's `current_group`, mapped to `None`
  /// when no `SET_GROUP1` was active — see [`Walker::push_warning`]):
  /// `Some("Info")`/`Some("Track1")` ⇒ a `<group>:Warning` TAG;
  /// `None` ⇒ the document-level `ExifTool:Warning`. Drained by the
  /// [`Diagnose`](crate::diagnostics::Diagnose) impl.
  ///
  /// Sites (Matroska.pm): `Illegal float size` (1179, group-scoped),
  /// `Invalid or corrupted … master element` (1075, group-scoped when a
  /// `SET_GROUP1` is active else document), `Truncated Matroska header`
  /// (1006, document-level — see [`Meta::suppress_file_type`]).
  warnings: Vec<crate::diagnostics::Diagnostic>,
  /// `true` when the EBML header was truncated (Matroska.pm:1006 `return 1`
  /// WITHOUT a preceding `SetFileType`) — the engine must then emit NO
  /// `File:*` triplet. The walk produced no `entries` and a single
  /// document-level `Truncated Matroska header` warning.
  suppress_file_type: bool,
}

impl<'a> Meta<'a> {
  /// Every emitted tag in walk order. (`Vec` slice — never expose `&Vec`.)
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[Entry<'a>] {
    &self.entries
  }
  /// `DocType` (`"matroska"` / `"webm"` / etc.) if the EBML header was seen.
  #[must_use]
  #[inline(always)]
  pub fn doc_type(&self) -> Option<&str> {
    self.doc_type.as_deref()
  }
  /// `true` when the file's EBML `DocType` is `"webm"` (Matroska.pm:72
  /// `OverrideFileType("WEBM")`).
  #[must_use]
  #[inline(always)]
  pub fn is_webm(&self) -> bool {
    self.doc_type.as_deref() == Some("webm")
  }
  /// Raw `TimecodeScale` nanoseconds (Matroska.pm:160-166), if it was
  /// present in `Info`.
  #[must_use]
  #[inline(always)]
  pub const fn timecode_scale_ns(&self) -> Option<u64> {
    self.timecode_scale_ns
  }
  /// `TimecodeScale` as a [`core::time::Duration`] (nanosecond-precise),
  /// if present. Helper for ergonomic library use.
  #[must_use]
  pub fn timecode_scale(&self) -> Option<Duration> {
    self.timecode_scale_ns.map(Duration::from_nanos)
  }
  /// `true` when the EBML header was truncated (Matroska.pm:1006 `$et->Warn(
  /// 'Truncated Matroska header'), return 1` — emitted BEFORE `SetFileType`).
  /// The engine then emits NO `File:*` triplet (the bundled `return 1`
  /// short-circuits before any `SetFileType`); `entries()` is empty and the
  /// lone `Truncated Matroska header` document warning rides the
  /// [`Diagnose`](crate::diagnostics::Diagnose) channel.
  #[must_use]
  #[inline(always)]
  pub const fn suppress_file_type(&self) -> bool {
    self.suppress_file_type
  }
}

// ===========================================================================
// `ProcessMatroska` — the lib-first parser
// ===========================================================================

/// Matroska / MKV / MKA / MKS / WebM parser — faithful port of
/// `Image::ExifTool::Matroska::ProcessMKV` (Matroska.pm:988-1248).
#[derive(Debug, Clone, Copy)]
pub struct ProcessMatroska;

impl parser_sealed::Sealed for ProcessMatroska {}

impl FormatParser for ProcessMatroska {
  type Meta<'a> = Meta<'a>;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Returns a [`Meta`] borrowing string slices from
/// the input buffer.
///
/// # Errors
///
/// Returns `Err` only for Rust-level fatal modes (none today — every bad
/// input is `Ok(None)` per Matroska.pm `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

/// EBML walker state.
struct Walker<'a> {
  data: &'a [u8],
  /// Current cursor.
  pos: usize,
  /// Stack of `(traversal_end, declared_end, container_name)` for nested
  /// `SubDir`s. The walker pops as soon as the cursor crosses an entry's
  /// `traversal_end` (Matroska.pm:1023-1051). `traversal_end` is the
  /// `data.len()`-CLAMPED end (drives the pop + leaf-read capping — preserving
  /// the "oversized Segment traversed to EOF" behavior); `declared_end` is the
  /// UNCLAMPED declared end (`usize::MAX` for an unknown-size master — the
  /// `$size = 1e20` sentinel, Matroska.pm:1073), used ONLY by the
  /// "Invalid or corrupted … master element" overrun check
  /// (Matroska.pm:1074, `$pos + $dataPos + $size > $dirEnd[-1][0]`).
  ends: Vec<(usize, usize, &'static str)>,
  entries: Vec<Entry<'a>>,
  doc_type: Option<SmolStr>,
  /// `$$self{TimecodeScale}` (Matroska.pm:163 `RawConv => '$$self{
  /// TimecodeScale} = $val'`). Set when `0xad7b1` is read.
  timecode_scale_ns: Option<u64>,
  /// Currently-active family-1 group (Matroska.pm:1117-1123 + 1203-1206):
  /// switches to `"Info"` on the Info subdir, `"Track<N>"` after a
  /// TrackNumber read inside a TrackEntry, `"Chapter<n>"` on a ChapterAtom.
  current_group: SmolStr,
  /// Whether `current_group` was set by a Track/Chapter/Info push (we
  /// restore to `"Matroska"` when the corresponding container ends).
  group_locked_at_depth: Option<usize>,
  /// 1-based chapter counter (Matroska.pm:1018 `my $chapterNum = 0` ⇒
  /// pre-increment on ChapterAtom enter, Matroska.pm:1117-1118).
  chapter_num: u32,
  /// Last-seen TrackType inside the active TrackEntry (Matroska.pm:262-263
  /// `Condition => 'delete $$self{TrackType}; 1'` resets at TrackEntry,
  /// Matroska.pm:272 `RawConv` records it). `None` outside a TrackEntry,
  /// or before the TrackType element was read.
  track_type: Option<u64>,
  /// Currently-open SimpleTag struct accumulator (Matroska.pm:1115 `$struct
  /// = { } if $dirName eq 'SimpleTag'`). Set when a TOP-LEVEL SimpleTag is
  /// entered; populated by EVERY leaf child via Matroska.pm:1224-1226
  /// `if ($$tagInfo{NoSave} or $struct) { ... $$struct{$tagName} = $val if
  /// $struct; }` — plain Perl hash assignment, hence:
  ///
  /// - **Universal absorption**: while the struct is active, ANY leaf-kind
  ///   child (TagName, TagString, TagBinary, TagLanguage, TagDefault, …) is
  ///   routed into the struct (or silently dropped when the struct does not
  ///   model that slot) instead of being emitted as a top-level entry.
  ///   Pre-R5 the absorb path was guarded by `def.name == "TagBinary" |
  ///   "TagName" | "TagString"` — TagDefault (`Format => 'unsigned'`,
  ///   Matroska.pm:690) fell through `Kind::Unsigned` and leaked as a
  ///   spurious `Tags:TagDefault` top-level tag.
  /// - **Last-wins overwrite**: a repeated child within one SimpleTag
  ///   overwrites the prior slot — Perl hash assignment is overwrite, and
  ///   HandleStruct (Matroska.pm:902-927) only reads the FINAL hash
  ///   values. Pre-R5 the slots were first-wins.
  ///
  /// Flushed via the StdTag table by [`flush_simple_tag`] on SimpleTag close
  /// (Matroska.pm:1043-1045 `HandleStruct($et, $struct)`).
  ///
  /// **Deferred at flush time**: TagLanguage (Matroska.pm:688) and
  /// TagLanguageBCP47 (Matroska.pm:689) are absorbed into the struct (so they
  /// no longer leak as top-level entries) BUT the language-suffixed key
  /// emission (Matroska.pm:932-934 `GetLangInfo($tagInfo, $code)`) is a
  /// visible Phase-2 deferral — see `docs/tracking.md`. Faithful absorb
  /// today; lang-suffix later.
  ///
  /// NESTED SimpleTag support is deliberately DEFERRED in this pass — see
  /// the inline comment near `flush_simple_tag`. Real-world MKVs that use
  /// nested SimpleTags will see the inner-tag values absorbed into the
  /// outer struct via last-wins overwrite (the inner SimpleTag re-binds
  /// the outer's slots, so the inner's TagName/TagString wins instead of
  /// being emitted as a `<Outer>/<Inner>` nested key). Visibility-deferral
  /// noted in `docs/tracking.md`.
  simple_tag: Option<SimpleTagStruct<'a>>,
  /// Depth (`w.ends.len()` at SimpleTag push time) where the active
  /// SimpleTag was entered — used to scope which subsequent leaf elements
  /// populate the struct (everything at depth > this is part of the same
  /// struct). `None` when no SimpleTag is open.
  simple_tag_depth: Option<usize>,
  /// `%trackNum` (Matroska.pm:992 `my %trackNum`): raw TrackUID bytes →
  /// `Track<N>` group string. Populated at Matroska.pm:1207-1209 (when
  /// TrackUID is read INSIDE a TrackEntry whose `SET_GROUP1` is the
  /// `Track<N>` set by the prior TrackNumber). The key is the raw on-disk
  /// bytes of the UID, NOT the lowercase-hex `UidHex` render — Perl's
  /// hash uses the `Format => 'string'` decoded value (Matroska.pm:1170-
  /// 1172), which for `%uidInfo` is the raw bytes (the `unpack("H*",$val)`
  /// happens later, in ValueConv). Looked up at TagTrackUID time
  /// (Matroska.pm:1210-1216) to override `SET_GROUP1` for the duration of
  /// the surrounding `Tag` master.
  track_uid_to_group: std::collections::HashMap<Vec<u8>, SmolStr>,
  /// The `$et->Warn` channel accumulated during the walk (Phase B.1.5). Each
  /// is pushed via [`Walker::push_warning`], which captures the family-1 group
  /// active at `Warn` time. Moved into [`Meta::warnings`] at parse end.
  warnings: Vec<crate::diagnostics::Diagnostic>,
}

impl Walker<'_> {
  /// Raise a faithful `$et->Warn(msg)` (Matroska.pm). The family-1 group is the
  /// active `SET_GROUP1`: the port models that as `current_group` while a
  /// group is locked, and `DEFAULT_GROUP` ("Matroska") when none is — which is
  /// exactly when bundled's `$$et{SET_GROUP1}` is unset, so the warning is
  /// DOCUMENT-level (`ExifTool:Warning`, `ExifTool.pm:9475`). When a group IS
  /// active (`Info` / `Track<N>` / `Chapter<n>`) the warning is the group-
  /// scoped `<group>:Warning` TAG.
  fn push_warning(&mut self, message: impl Into<SmolStr>) {
    let d = if self.current_group.as_str() == DEFAULT_GROUP {
      crate::diagnostics::Diagnostic::warn(message)
    } else {
      crate::diagnostics::Diagnostic::warn_in_group(self.current_group.clone(), message)
    };
    self.warnings.push(d);
  }
}

/// One in-flight SimpleTag struct (Matroska.pm `HandleStruct` inputs).
///
/// Captures the canonical SimpleTag children HandleStruct (Matroska.pm:
/// 897-948) actually reads:
/// - `TagName` (Matroska.pm:687) — the StdTag-lookup key
/// - `TagString` (Matroska.pm:691) — the string value (preferred)
/// - `TagBinary` (Matroska.pm:695) — the binary value (fallback when no
///   TagString)
///
/// Other SimpleTag children Perl absorbs but never reads (TagDefault,
/// TagLanguage, TagOriginal, …) are silently dropped by the walker — the
/// observable output is identical to Perl populating then ignoring those
/// hash slots at HandleStruct time (Matroska.pm:929 explicitly notes
/// "not currently handling TagDefault attribute"; Matroska.pm:928 reads
/// TagLanguageBCP47/TagLanguage but the lang-suffix is a Phase-2 deferral
/// — see [`Walker::simple_tag`]).
///
/// **Last-wins overwrite semantics** on each captured slot — Perl
/// `$$struct{$tagName} = $val` is plain hash assignment (Matroska.pm:1226),
/// so a second occurrence of `TagString` within the same SimpleTag
/// overwrites the first. Pre-R5 we kept the first occurrence; that
/// diverged from bundled for repeated-child SimpleTags.
#[derive(Debug, Default)]
struct SimpleTagStruct<'a> {
  /// `TagName` (Matroska.pm:687 `Name => 'TagName', Format => 'utf8'`).
  tag_name: Option<Cow<'a, str>>,
  /// `TagString` (Matroska.pm:691 `Name => 'TagString', Format => 'utf8'`).
  tag_string: Option<Cow<'a, str>>,
  /// `TagBinary` (Matroska.pm:695 `Name => 'TagBinary'`; binary blob).
  tag_binary: Option<Cow<'a, [u8]>>,
}

const DEFAULT_GROUP: &str = "Matroska";

/// Inner parser body. Returns `Ok(None)` if the EBML magic is not present
/// or the header VINT is malformed; `Ok(Some(_))` for everything else.
///
/// IMPORTANT: the 4-byte EBML magic (`\x1aE\xdf\xa3`) IS the VINT-encoded
/// element ID `0xa45dfa3` (EBMLHeader; Matroska.pm:60-63). The bundled
/// `ProcessMKV` (Matroska.pm:996-1009) calls `GetVInt` at offset 0 to
/// recover both the magic-as-ID and the subsequent header-body-size
/// VINT — the magic check (`buff =~ /^\x1a\x45\xdf\xa3/`) is just a fast
/// pre-validation. We walk from offset 0; the walker re-reads the
/// (already-validated) magic-as-ID and the EBMLHeader body size, then
/// descends into the EBML header sub-elements.
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  if data.len() < 4 || data[..4] != EBML_MAGIC {
    return None; // Matroska.pm:996 — magic gate
  }
  // Matroska.pm:1003-1006 — verify the EBML header length BEFORE `SetFileType`.
  // Bundled reads the 4-byte magic, then `$hlen = GetVInt($buff, $pos)` over
  // the post-magic buffer (`$dataPos = 4`), and `return 1` WITHOUT
  // `SetFileType` when `$pos + $hlen > $dataLen` (i.e. the header body
  // overruns the file). Over the whole `data` slice that is: the EBMLHeader's
  // declared body END (magic(4) + size-VINT length + `hlen`) exceeds
  // `data.len()`. A missing / zero / unknown-sentinel header length is the
  // `return 0 unless $hlen and $hlen > 0` rejection (`Ok(None)`).
  match get_vint(data, 4) {
    None => return None, // header-size VINT unreadable ⇒ `GetVInt` undef ⇒ return 0
    Some(hlen_v) => {
      // `return 0 unless $hlen and $hlen > 0` (Matroska.pm:1005): the unknown
      // sentinel or a non-positive length rejects the file.
      if hlen_v.is_unknown() || hlen_v.value() <= 0 {
        return None;
      }
      let header_body_end = 4usize
        .checked_add(hlen_v.consumed())
        .and_then(|p| p.checked_add(hlen_v.value() as usize));
      // `$pos + $hlen > $dataLen` ⇒ truncated header: warn + `return 1` with
      // NO `SetFileType` (no `File:*`) and NO further parsing.
      if header_body_end.is_none_or(|end| end > data.len()) {
        let mut warnings = Vec::new();
        warnings.push(crate::diagnostics::Diagnostic::warn(
          "Truncated Matroska header",
        ));
        return Some(Meta {
          entries: Vec::new(),
          doc_type: None,
          timecode_scale_ns: None,
          warnings,
          suppress_file_type: true,
        });
      }
    }
  }
  let mut w = Walker {
    data,
    pos: 0, // start at first VINT (the 4-byte EBML magic IS the EBMLHeader id)
    ends: Vec::new(),
    entries: Vec::new(),
    doc_type: None,
    timecode_scale_ns: None,
    current_group: SmolStr::new_static(DEFAULT_GROUP),
    group_locked_at_depth: None,
    chapter_num: 0,
    track_type: None,
    simple_tag: None,
    simple_tag_depth: None,
    track_uid_to_group: std::collections::HashMap::new(),
    warnings: Vec::new(),
  };
  walk(&mut w);
  Some(Meta {
    entries: w.entries,
    doc_type: w.doc_type,
    timecode_scale_ns: w.timecode_scale_ns,
    warnings: w.warnings,
    suppress_file_type: false,
  })
}

/// Main EBML walk. Faithful loop port of Matroska.pm:1022-1236. Stops on
/// any malformed element header (defensive — Perl's `last`).
fn walk(w: &mut Walker<'_>) {
  let data = w.data;
  loop {
    // ---- Pop ended containers (Matroska.pm:1023-1057) -------------------
    while let Some(&(end, _, _)) = w.ends.last() {
      if w.pos >= end {
        // The locked depth records the INDEX at which the locking container
        // was pushed — i.e. `w.ends.len() - 1` at push time. The locking
        // container is the one whose end-marker we are about to cross when
        // `w.ends.len() == d + 1`. Restore BEFORE pop so the next sibling
        // observes the restored group (Matroska.pm:1050 `delete
        // $$et{SET_GROUP1} if $trackIndent and $trackIndent eq $$et{INDENT}`
        // — Perl resets exactly at the closing brace).
        if let Some(d) = w.group_locked_at_depth {
          if w.ends.len() == d + 1 {
            // Exiting the SubDir that locked the group ⇒ restore default.
            w.current_group = SmolStr::new_static(DEFAULT_GROUP);
            w.group_locked_at_depth = None;
            // TrackType also resets when its TrackEntry closes
            // (Matroska.pm:262-263 `Condition => 'delete $$self{TrackType};
            // 1'` runs at TrackEntry entry, but conceptually it scopes per
            // TrackEntry).
            w.track_type = None;
          }
        }
        // ---- SimpleTag close: flush via StdTag --------------------------
        // Matroska.pm:1043-1045 `HandleStruct($et, $struct); undef $struct`
        // fires when a TOP-LEVEL SimpleTag's end-marker is crossed. Nested
        // SimpleTags (Matroska.pm:1037-1041) recurse — DEFERRED, see the
        // `simple_tag` doc comment.
        if let Some(d) = w.simple_tag_depth {
          if w.ends.len() == d + 1 {
            flush_simple_tag(w);
            w.simple_tag = None;
            w.simple_tag_depth = None;
          }
        }
        w.ends.pop();
      } else {
        break;
      }
    }

    // ---- Read element header (ID + size) -------------------------------
    let Some(id_v) = get_vint(data, w.pos) else {
      break;
    };
    // Matroska.pm:1068 `last unless defined $tag and $tag >= 0` — ID == 0 is
    // VALID (used by ChapterDisplay, Matroska.pm:615-618), only the unknown-
    // VINT sentinel (Perl `-1` / our `i64::MIN`) or a negative decode is a
    // walk-terminator.
    if id_v.is_unknown() || id_v.value() < 0 {
      break;
    }
    w.pos += id_v.consumed();
    let Some(size_v) = get_vint(data, w.pos) else {
      break;
    };
    w.pos += size_v.consumed();
    // Unknown-size pre-classification (Matroska.pm:1073 — `$size < 0` ⇒
    // `$unknownSize = 1, $size = 1e20`). Faithful semantics differ for
    // master vs leaf:
    //   - master (SubDir / SkipBody): descend into the body until EOF or
    //     parent's declared end (Matroska.pm:1073/1114 pushes
    //     `[pos + 1e20, name, ...]` — the 1e20 sentinel is never reached
    //     within a real buffer, so the body effectively extends to EOF
    //     within Perl's read window).
    //   - leaf: `last if $unknownSize` (Matroska.pm:1130) — no
    //     decodable bound for the leaf body, so we faithfully STOP.
    //   - Cluster (SkipBody): `last` (Matroska.pm:1105 default arm — no
    //     way to advance past an unknown-size body without parsing the
    //     children, which is exactly what SkipBody is avoiding).
    let unknown_size = size_v.is_unknown();
    let elem_end_declared: usize;
    // The UNCLAMPED declared end (`$pos + $dataPos + $size`, Matroska.pm:1074)
    // for the corruption-overrun check below + the `w.ends` push. For an
    // unknown-size element this is the `$size = 1e20` sentinel
    // (Matroska.pm:1073) ⇒ `usize::MAX` (never `<= any finite container end`,
    // so an unknown-size element inside a finite container IS "corrupted" —
    // faithful — and an unknown-size container's children compare against
    // `usize::MAX` and never trip it).
    let declared_end_unclamped: usize;
    if unknown_size {
      declared_end_unclamped = usize::MAX;
      // Peek at the tag def to decide whether this is a master we can
      // descend OR a leaf where we must stop. The conditional IDs
      // (`0x3e383`, `0x06`, `0x58688`) are always leaves.
      let id = id_v.value();
      let is_conditional_leaf = matches!(id, 0x3e383 | 0x06 | 0x58688);
      let kind = (!is_conditional_leaf)
        .then(|| tag_def(id))
        .flatten()
        .map(|d| d.kind);
      let is_master_subdir = matches!(kind, Some(Kind::SubDir));
      if is_master_subdir {
        // Set the effective end at parent's bound (if any) or EOF —
        // faithful to Matroska.pm:1114 `[pos + $dataPos + $size, …]`
        // where `$size = 1e20` ⇒ end always > buffer length.
        elem_end_declared = w
          .ends
          .last()
          .map(|&(e, _, _)| e)
          .unwrap_or(data.len())
          .min(data.len());
      } else {
        // Leaf, SkipBody (Cluster), or unknown ID with unknown size —
        // faithful Perl `last if $unknownSize` (Matroska.pm:1130) OR
        // `last` at Matroska.pm:1105 (Cluster default arm). We stop.
        break;
      }
    } else {
      let size = size_v.value() as usize;
      // Declared end (Matroska.pm:1073-1085). For a SubDir whose declared end
      // exceeds the buffer (Matroska files commonly declare a Segment size
      // that overshoots the on-disk body — mkvmerge "unknown size", live
      // streams), the bundled walker still enters and traverses every child
      // until natural EOF. We clamp the SubDir end to `data.len()` so the
      // walker keeps stepping. The match arms below handle SubDir vs leaf
      // separately: SubDir uses the clamped end; leaves either fit the
      // declared end (we use that as `elem_end`) or bail (Matroska.pm:
      // 1130-1161 `last` after the failed streaming read).
      declared_end_unclamped = w.pos.checked_add(size).unwrap_or(usize::MAX);
      elem_end_declared = declared_end_unclamped.min(data.len());
    }
    // ---- Invalid/corrupted master element (Matroska.pm:1074-1085) ------
    // `if (@dirEnd and $pos + $dataPos + $size > $dirEnd[-1][0])`: the current
    // element's declared body END exceeds the INNERMOST open container's
    // declared end ⇒ `$et->Warn("Invalid or corrupted <name> master element")`,
    // then `$pos = $dirEnd[-1][0] - $dataPos; next` — recover by jumping the
    // cursor to the container's (traversal-capped) end and re-running the pop
    // loop. The warning's family-1 group is the active `SET_GROUP1`
    // (`push_warning`: group-scoped when one is locked, else document — e.g.
    // `Info:Warning` inside Info, `ExifTool:Warning` directly inside Segment).
    if let Some(&(cont_traversal_end, cont_declared_end, cont_name)) = w.ends.last() {
      if declared_end_unclamped > cont_declared_end {
        let mut msg = std::string::String::with_capacity(48);
        let _ = core::fmt::Write::write_fmt(
          &mut msg,
          format_args!("Invalid or corrupted {cont_name} master element"),
        );
        w.push_warning(msg);
        // Matroska.pm:1076 `$pos = $dirEnd[-1][0] - $dataPos`. The container's
        // traversal end is already `data.len()`-capped, so the jump lands at
        // most at EOF; the pop loop at the top then closes the container.
        w.pos = cont_traversal_end;
        continue;
      }
    }
    // The unified `elem_end` used by every leaf arm below — defaults to
    // declared but capped at data.len() so reads don't slice past EOF; if
    // the leaf would overflow the buffer we cap and let the decoder return
    // a short / partial result (matches bundled Perl's behaviour when the
    // streaming-read shortens itself).
    let elem_end = elem_end_declared.min(data.len());

    // ---- Conditional IDs (Matroska.pm:294-307, 314-327, 329-342) -------
    // Three IDs map to different tag names based on `$$self{TrackType}`.
    // These must be handled BEFORE the static `TAG_TABLE` lookup (which
    // carries only the canonical placeholder rows for documentation).
    let id = id_v.value();
    if matches!(id, 0x3e383 | 0x06 | 0x58688) {
      let body = &data[w.pos..elem_end];
      if maybe_handle_conditional(w, id, body) {
        w.pos = elem_end;
        continue;
      }
    }

    // ---- Resolve ID → TagDef -------------------------------------------
    let Some(def) = tag_def(id_v.value()) else {
      // Matroska.pm:1162-1165 — `unless ($tagInfo) { ignore the element;
      // $pos += $size; next; }`. Walk past the unknown element silently.
      w.pos = elem_end;
      continue;
    };

    // ---- Dispatch ------------------------------------------------------
    match def.kind {
      Kind::SubDir => {
        // Matroska.pm:1109-1124 — "just fall through into the contained
        // EBML elements" + group bookkeeping. Push BOTH the `data.len()`-
        // clamped traversal end (pop + leaf-read capping) and the unclamped
        // declared end (the overrun check for this container's children).
        w.ends.push((elem_end, declared_end_unclamped, def.name));
        // Group switches (family-1 SET_GROUP1).
        if def.name == "Info" && w.group_locked_at_depth.is_none() {
          w.current_group = SmolStr::new_static("Info");
          w.group_locked_at_depth = Some(w.ends.len() - 1);
        } else if def.name == "ChapterAtom" {
          w.chapter_num += 1;
          // Format `Chapter<n>` lazily; SmolStr inlines short numerics.
          let mut s = std::string::String::with_capacity(8);
          let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Chapter{}", w.chapter_num));
          w.current_group = SmolStr::new(&s);
          w.group_locked_at_depth = Some(w.ends.len() - 1);
        } else if def.name == "TrackEntry" {
          // Track group is set when TrackNumber is encountered INSIDE this
          // TrackEntry; the lock-depth is the TrackEntry's own depth.
          w.group_locked_at_depth = Some(w.ends.len() - 1);
          w.track_type = None;
        } else if def.name == "SimpleTag" && w.simple_tag.is_none() {
          // Matroska.pm:1115 — `$struct = { } if $dirName eq 'SimpleTag'`.
          // Only TOP-LEVEL SimpleTag opens a struct (nested SimpleTags are
          // recursed into the parent's struct via Matroska.pm:1037-1041 —
          // DEFERRED, see `simple_tag` doc).
          w.simple_tag = Some(SimpleTagStruct::default());
          w.simple_tag_depth = Some(w.ends.len() - 1);
        }
        // Cursor stays at the start of the SubDir's children (we don't
        // advance by `size` — we descend into the body).
        continue;
      }
      Kind::Skip => {
        // NoSave / Unknown → walk past.
        w.pos = elem_end;
        continue;
      }
      Kind::SkipBody => {
        // Matroska.pm:1096-1105 (default Cluster handling): `last` the
        // walk. Cluster is the only user of this kind. We don't (yet)
        // honor SeekHead's Tags pointer to skip ahead to Tags after
        // the Cluster, so the faithful default is to stop entirely —
        // matches `perl exiftool -j -G1:1 -api struct=1` output (our
        // parity reference). See the `Kind::SkipBody` doc above for
        // the deferred-SeekHead note.
        break;
      }
      Kind::Binary => {
        // Matroska.pm:552 (AttachedFileData) + 695 (TagBinary) —
        // `Format => 'binary'` / `Binary => 1`. ExifTool emits these as
        // the no-`-b` placeholder `(Binary data <N> bytes, use -b option
        // to extract)` in both `-j` and `-n` modes.
        let body = &data[w.pos..elem_end];
        // Matroska.pm:1224-1226 — if a SimpleTag struct is active, route
        // ALL leaf-kind children into the struct (or silently drop if no
        // modeled slot) instead of emitting a top-level tag. Last-wins
        // overwrite per `$$struct{$tagName} = $val` (plain hash assignment).
        if let Some(st) = w.simple_tag.as_mut() {
          if def.name == "TagBinary" {
            st.tag_binary = Some(Cow::Borrowed(body));
          }
          // else: absorbed-then-dropped (no struct slot models this leaf;
          // HandleStruct at flush time would never read it either —
          // Matroska.pm:902-927 only looks at TagName/TagString/TagBinary).
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::Bytes(Cow::Borrowed(body)));
        w.pos = elem_end;
        continue;
      }
      Kind::Unsigned(_pc) => {
        // PrintConv is resolved at emit time via the tag-name lookup
        // (`kind_for_name` in `emit_one`), so the `pc` payload here is
        // discarded.
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // ----- TrackType bookkeeping (Matroska.pm:267-282) ---------------
        // Order: bookkeeping FIRST, absorb-or-emit decision SECOND. This
        // mirrors Matroska.pm:1203-1217 (bookkeeping inside `if
        // ($$tagInfo{Format})`) preceding line 1224's `if (...{NoSave} or
        // $struct) { ... }` absorb branch. In well-formed MKV these
        // bookkeeping triggers (TrackType/TrackNumber) never appear inside
        // a SimpleTag, but the ordering is faithful regardless.
        if def.name == "TrackType" {
          w.track_type = Some(raw);
        }
        // ----- TrackNumber bookkeeping (Matroska.pm:1203-1206) -----------
        if def.name == "TrackNumber" {
          let mut s = std::string::String::with_capacity(8);
          let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Track{raw}"));
          w.current_group = SmolStr::new(&s);
          // Don't reset group_locked_at_depth — we're already inside a
          // TrackEntry that locked it.
        }
        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag. TagDefault (0x484,
        // Matroska.pm:690) is the concrete unsigned-kind child that pre-R5
        // leaked here.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::U64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Signed(_pc) => {
        let raw = decode_signed(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::I64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Float(_fc) => {
        // FrameRate / SampleRate / Gamma / etc. (`Format => 'float'`,
        // Matroska.pm:1173-1180). A non-4/8-byte size is the
        // `Illegal float size` branch: `$val` stays UNDEF and bundled warns.
        let body = &data[w.pos..elem_end];
        let raw = decode_float(body);
        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag. (An illegal-size float
        // inside a SimpleTag is still warned by bundled BEFORE the struct
        // absorb — Matroska.pm:1179 runs in the `Format` block, the struct
        // assignment at :1226 then stores the undef — so the warning fires
        // even when the leaf is absorbed.)
        let illegal = raw.is_none();
        if illegal {
          // Matroska.pm:1179 `$et->Warn("Illegal float size ($size)")`.
          let mut msg = std::string::String::with_capacity(24);
          let _ = core::fmt::Write::write_fmt(
            &mut msg,
            format_args!("Illegal float size ({})", body.len()),
          );
          w.push_warning(msg);
        }
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        match raw {
          Some(v) => push_entry(w, def.name, Value::F64(v)),
          // Undef leaf (no ValueConv on a plain `Format => 'float'` row) ⇒
          // the stored undef stringifies to the empty string under `-j`/`-n`
          // (oracle: `Track1:AudioSampleRate: ""`). Emit an empty string.
          None => push_entry(w, def.name, Value::Str(Cow::Borrowed(""))),
        }
        w.pos = elem_end;
        continue;
      }
      Kind::AsciiString => {
        let s = decode_ascii(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag. TagLanguage (0x47a,
        // Matroska.pm:688, `Format => 'string'`) is the concrete ascii-
        // kind child. Pre-R5 it leaked as a top-level `Tags:TagLanguage`.
        // The struct does not model a `tag_language` slot — the lang-
        // suffix emission (Matroska.pm:932-934) is a Phase-2 deferral;
        // we absorb-then-drop for now, see [`Walker::simple_tag`].
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::Str(s));
        w.pos = elem_end;
        continue;
      }
      Kind::Utf8String => {
        let s = decode_utf8(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 `$$struct{$tagName} = $val if $struct`:
        // when an open SimpleTag struct is active, TagName / TagString
        // children populate the struct instead of being emitted as
        // standalone tags. The struct's flush at SimpleTag-close (see
        // `flush_simple_tag`) emits the canonical StdTag-mapped key.
        //
        // **Last-wins**: the assignment is plain Perl hash overwrite
        // (NOT first-wins). A repeated TagString within one SimpleTag
        // replaces the prior slot; HandleStruct (Matroska.pm:926-927)
        // reads only the FINAL value. Same for TagName — a repeated
        // TagName re-binds the canonical StdTag-lookup key, which can
        // change the synthesized name (see the duplicates fixture's
        // `REPLACED_ARTIST` case).
        if let Some(st) = w.simple_tag.as_mut() {
          match def.name {
            "TagName" => st.tag_name = Some(s),
            "TagString" => st.tag_string = Some(s),
            // Any other utf8 leaf inside SimpleTag is absorbed-then-dropped
            // (no slot in the struct; HandleStruct would not read it).
            _ => {}
          }
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::Str(s));
        w.pos = elem_end;
        continue;
      }
      Kind::Date => {
        let raw = decode_signed(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::Date(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::UidHex => {
        // Matroska.pm:33-36 — `Format => 'string'` + `ValueConv =>
        // 'unpack("H*",$val)'`. The bytes are the raw element body; we
        // store the lowercase-hex synthesis directly into a SmolStr.
        let body = &data[w.pos..elem_end];
        let hex = hex_lower(body);

        // Matroska.pm:1207-1209 — `TrackUID` inside a TrackEntry with
        // SET_GROUP1 active records `(raw_bytes → Track<N>)` for later
        // TagTrackUID lookup. Perl uses `$val` (the Format='string'
        // raw-bytes scalar) as the hash key; we faithfully use the raw
        // bytes (NOT the lowercase-hex render).
        //
        // The "SET_GROUP1 active" guard is `$$et{SET_GROUP1}` truthy in
        // Perl — i.e. any of {Track<N>, Chapter<n>, Info}. For TrackUID
        // specifically, only the Track<N> case is interesting; an Info or
        // Chapter group would mean a spec-illegal placement (TrackUID
        // outside TrackEntry) and Perl's hash entry would never be
        // looked up anyway. We mirror the lenient Perl semantic.
        //
        // Bookkeeping runs BEFORE the absorb-or-emit decision, mirroring
        // Matroska.pm:1203-1216 (inside `if $$tagInfo{Format}`) preceding
        // line 1224 (absorb branch).
        if def.name == "TrackUID"
          && w.current_group.as_str() != DEFAULT_GROUP
          && w.group_locked_at_depth.is_some()
        {
          w.track_uid_to_group
            .insert(body.to_vec(), w.current_group.clone());
        } else if def.name == "TagTrackUID" {
          // Matroska.pm:1210-1216 — `TagTrackUID` with a matching
          // `$trackNum{$val}` overrides SET_GROUP1 for the duration of
          // the enclosing Tag master. Perl sets `$trackIndent = substr(
          // $$et{INDENT}, 0, -2)` — i.e. the reset triggers ONE level UP
          // from the current INDENT (where current is the Targets
          // container). Our lock-depth index corresponds to the Tag's
          // position in `w.ends`: TagTrackUID is read inside Targets, so
          // `ends.last()` is Targets and `ends[ends.len() - 2]` is Tag.
          if let Some(target_group) = w.track_uid_to_group.get(body).cloned() {
            w.current_group = target_group;
            // Reset fires when the parent of Targets (which is Tag)
            // closes — i.e. when `ends.len() == lock_depth + 1` after
            // Targets is already popped. We need `lock_depth + 1 = Tag's
            // index + 1 = (ends.len() - 2) + 1 = ends.len() - 1`. After
            // the Targets-close pop, ends.len() decreases by 1, so the
            // condition becomes `(ends.len() - 1) - 1 + 1 = ends.len() -
            // 1` matches when Tag is the top-of-stack about to close.
            // Concretely: lock_depth = ends.len() - 2 (Tag's stack index
            // computed when we are INSIDE Targets).
            if w.ends.len() >= 2 {
              w.group_locked_at_depth = Some(w.ends.len() - 2);
            }
          }
        }

        // Matroska.pm:1224-1226 — absorb-into-struct (no top-level emit)
        // for ANY leaf child of an active SimpleTag. UID-class children
        // (TagTrackUID, TagEditionUID, TagChapterUID, TagAttachmentUID)
        // legally appear inside `Targets`, NOT inside `SimpleTag`, but
        // an adversarial / malformed file could place one there; the
        // absorb-then-drop is faithful Perl semantics.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }

        push_entry(w, def.name, Value::UidHex(hex));
        w.pos = elem_end;
        continue;
      }
      Kind::TimecodeScale => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // Bookkeeping FIRST (faithful to Perl `DataMember`/`RawConv`,
        // Matroska.pm:160-166), absorb-or-emit SECOND.
        w.timecode_scale_ns = Some(raw);
        // Matroska.pm:1224-1226 — absorb-into-struct for ANY leaf child of
        // an active SimpleTag. Spec-illegal placement, but faithful.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::TimecodeScaleRaw(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Duration => {
        // Matroska.pm:167-172 — `Format => 'float'`. ValueConv/PrintConv
        // are deferred to output time and read the FINAL `$$self{
        // TimecodeScale}` (verified empirically with adversarial
        // fixtures — see `Value::DurationRawF64`).
        let body = &data[w.pos..elem_end];
        let raw = decode_float(body);
        let illegal = raw.is_none();
        if illegal {
          // Matroska.pm:1179 `$et->Warn("Illegal float size ($size)")` — the
          // Duration `Format => 'float'` decode is the SAME code path.
          let mut msg = std::string::String::with_capacity(24);
          let _ = core::fmt::Write::write_fmt(
            &mut msg,
            format_args!("Illegal float size ({})", body.len()),
          );
          w.push_warning(msg);
        }
        // Matroska.pm:1224-1226 — absorb-into-struct for ANY leaf child of
        // an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        // Undef leaf (illegal float size) ⇒ Duration's ValueConv on undef:
        // `undef * scale / 1e9` or `undef / 1000`, both `0` in Perl's numeric
        // context (oracle: `Info:Duration: 0` with no scale, `"0 s"` /`0`
        // with scale). `DurationRawF64(0.0)` reproduces that exactly via the
        // shared emit path (`ConvertDuration(0.0) == "0 s"`,
        // `0.0 / 1000 == 0`).
        let stored = raw.unwrap_or(0.0);
        push_entry(w, def.name, Value::DurationRawF64(stored));
        w.pos = elem_end;
        continue;
      }
      Kind::DefaultDuration => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct for ANY leaf child of
        // an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::DefaultDurationRaw(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::VideoFrameRate => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct for ANY leaf child of
        // an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::VideoFrameRateRaw(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::ChapterTimeNs => {
        // Matroska.pm:580-592 — `Format => 'unsigned'`, store raw u64 ns and
        // defer ValueConv (`$val / 1e9`) + PrintConv (`ConvertDuration`) to
        // emit time. The `Chapter<n>` family-1 group is already in
        // `w.current_group` from the enclosing ChapterAtom enter.
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // Matroska.pm:1224-1226 — absorb-into-struct for ANY leaf child of
        // an active SimpleTag.
        if w.simple_tag.is_some() {
          w.pos = elem_end;
          continue;
        }
        push_entry(w, def.name, Value::ChapterTimeRawNs(raw));
        w.pos = elem_end;
        continue;
      }
    }
  }
}

/// Pre-name dispatch for the two conditional Matroska elements that map to
/// different tags depending on the enclosing TrackEntry's `TrackType`:
///
/// - `0x3e383` ⇒ `VideoFrameRate` when `TrackType == 0x01 (Video)`, else
///   `DefaultDuration` (Matroska.pm:294-307).
/// - `0x06` ⇒ `VideoCodecID` when `TrackType == 0x01`, `AudioCodecID` when
///   `TrackType == 0x02`, else `CodecID` (Matroska.pm:314-327).
/// - `0x58688` ⇒ `VideoCodecName` when `TrackType == 0x01`, `AudioCodecName`
///   when `TrackType == 0x02`, else `CodecName` (Matroska.pm:329-342).
///
/// Faithful to the Perl array-of-Condition entry shape.
fn resolve_conditional_name(
  id: i64,
  track_type: Option<u64>,
) -> Option<(&'static str, ConditionalKind)> {
  match id {
    0x3e383 => {
      let name = match track_type {
        Some(0x01) => "VideoFrameRate",
        _ => "DefaultDuration",
      };
      Some((
        name,
        if matches!(track_type, Some(0x01)) {
          ConditionalKind::VideoFrameRate
        } else {
          ConditionalKind::DefaultDuration
        },
      ))
    }
    0x06 => {
      let name = match track_type {
        Some(0x01) => "VideoCodecID",
        Some(0x02) => "AudioCodecID",
        _ => "CodecID",
      };
      Some((name, ConditionalKind::AsciiString))
    }
    0x58688 => {
      let name = match track_type {
        Some(0x01) => "VideoCodecName",
        Some(0x02) => "AudioCodecName",
        _ => "CodecName",
      };
      Some((name, ConditionalKind::Utf8String))
    }
    _ => None,
  }
}

/// Returned by [`resolve_conditional_name`] to drive the decode path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionalKind {
  VideoFrameRate,
  DefaultDuration,
  AsciiString,
  Utf8String,
}

fn push_entry<'a>(w: &mut Walker<'a>, name: &'static str, value: Value<'a>) {
  // Cache DocType so the public accessor can read it without rescanning.
  if name == "DocType" {
    if let Value::Str(Cow::Borrowed(s)) = &value {
      w.doc_type = Some(SmolStr::new(*s));
    } else if let Value::Str(Cow::Owned(s)) = &value {
      w.doc_type = Some(SmolStr::new(s));
    }
  }
  w.entries.push(Entry {
    group: w.current_group.clone(),
    name: SmolStr::new_static(name),
    value,
  });
}

/// Variant of [`push_entry`] for SimpleTag synthesized names (Matroska.pm:
/// 905-911) — the `name` is a runtime [`SmolStr`] (inlined if short, heap
/// otherwise) rather than a `&'static str` from `TAG_TABLE`.
fn push_entry_named<'a>(w: &mut Walker<'a>, name: SmolStr, value: Value<'a>) {
  w.entries.push(Entry {
    group: w.current_group.clone(),
    name,
    value,
  });
}

/// Emit the buffered SimpleTag via [`STD_TAG_TABLE`] → canonical-or-
/// synthesized tag name. Faithful port of `HandleStruct`
/// (Matroska.pm:897-948) — the simplified single-tag path (we currently
/// defer nested SimpleTag recursion + TagLanguage suffix, both noted in
/// the `simple_tag` doc comment).
///
/// Emission rules:
/// - If both `TagName` AND (`TagString` OR `TagBinary`) are present →
///   emit `<StdTagName>` = value (Matroska.pm:926).
/// - If `TagName` is in [`STD_TAG_TABLE`]:
///   - For static rows (`name = &'static str`), uses the static name
///     directly (cheap SmolStr inlining).
///   - For date rows (`is_date = true`), the TagString is post-processed
///     via `dateInfo.ValueConv` (Matroska.pm:29 — replace the first two
///     `-` separators in a YYYY-MM-... string with `:`).
/// - If `TagName` is NOT in the table → synthesize via
///   [`synthesize_tag_name`] (Matroska.pm:905-911).
/// - If `TagName` is absent → silently drop (faithful: bundled
///   `$tag = $$struct{TagName}` followed by `$$tagTbl{$tag}` lookup is a
///   no-op for an undef `$tag`).
fn flush_simple_tag(w: &mut Walker<'_>) {
  let Some(st) = w.simple_tag.as_ref() else {
    return;
  };
  let Some(tag_name_text) = st.tag_name.as_ref() else {
    return;
  };
  let key = tag_name_text.as_ref();
  // Resolve canonical name + is_date flag.
  let (canonical, is_date) = match std_tag_lookup(key) {
    Some(e) => (SmolStr::new_static(e.name), e.is_date),
    None => (SmolStr::new(&synthesize_tag_name(key)), false),
  };
  // Prefer TagString over TagBinary (Matroska.pm:927 `defined
  // $$struct{TagString} ? $$struct{TagString} : \$$struct{TagBinary}`).
  let value = if let Some(s) = st.tag_string.as_ref() {
    // Apply dateInfo.ValueConv if marked is_date — `s/^(\d{4})-(\d{2})-
    // /$1:$2:/`. Faithful to Matroska.pm:29.
    if is_date {
      Value::Str(Cow::Owned(date_separator_convert(s.as_ref())))
    } else {
      // Re-wrap as Owned to avoid borrowing from the SimpleTag struct's
      // own Cow (which would tie Entry's lifetime to the struct's slot).
      Value::Str(Cow::Owned(s.as_ref().to_owned()))
    }
  } else if let Some(b) = st.tag_binary.as_ref() {
    Value::Bytes(Cow::Owned(b.as_ref().to_vec()))
  } else {
    // No value child (Matroska.pm:926 guard: neither TagString nor
    // TagBinary defined) — bundled emits nothing.
    return;
  };
  push_entry_named(w, canonical, value);
}

/// `dateInfo.ValueConv` (Matroska.pm:29) — `s/^(\d{4})-(\d{2})-/$1:$2:/`.
/// Replace the first two `-` separators (the year-month and month-day
/// boundaries) with `:` for a YYYY-MM-DDTHH:MM:SS-style input. Preserves
/// timezone separators (e.g. `2010-12-31T00:00:00-05:00` ⇒
/// `2010:12:31T00:00:00-05:00`).
fn date_separator_convert(s: &str) -> String {
  let bytes = s.as_bytes();
  if bytes.len() >= 8 // YYYY-MM-D…
    && bytes[..4].iter().all(|b| b.is_ascii_digit())
    && bytes[4] == b'-'
    && bytes[5..7].iter().all(|b| b.is_ascii_digit())
    && bytes[7] == b'-'
  {
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..4]);
    out.push(':');
    out.push_str(&s[5..7]);
    out.push(':');
    out.push_str(&s[8..]);
    return out;
  }
  s.to_owned()
}

// ===========================================================================
// Format decoders
// ===========================================================================

/// Matroska.pm:1199-1201 — `unsigned`: BE big-int (size in 1..=8 bytes).
/// We cap at 8 bytes (longer than that would overflow `u64` in any case;
/// real Matroska elements use ≤ 8). Returns 0 for an empty body
/// (Matroska.pm `@vals = unpack("x${pos}C$size", $buff); $val = 0` then
/// the loop is empty).
fn decode_unsigned(b: &[u8]) -> u64 {
  let mut v: u64 = 0;
  for &byte in b.iter().take(8) {
    v = v.wrapping_mul(256).wrapping_add(u64::from(byte));
  }
  v
}

/// Matroska.pm:1184-1191 — `signed`/`date`: BE big-int sign-extended from
/// top bit.
fn decode_signed(b: &[u8]) -> i64 {
  if b.is_empty() {
    return 0;
  }
  let mut v: i64 = 0;
  let mut over: i64 = 1;
  for &byte in b.iter().take(8) {
    v = v.wrapping_mul(256).wrapping_add(i64::from(byte));
    over = over.wrapping_mul(256);
  }
  if b[0] & 0x80 != 0 {
    v = v.wrapping_sub(over);
  }
  v
}

/// Matroska.pm:1173-1180 — `float`: 4-byte single OR 8-byte double, BE.
/// Any OTHER size is the `else { $et->Warn("Illegal float size ($size)") }`
/// branch (Matroska.pm:1178-1180): `$val` is left UNDEF (the assignment is
/// skipped) and a warning is raised. We model that undef as `None`; the call
/// site raises the `Illegal float size (N)` warning and emits the
/// undef→ValueConv leaf (`0` for `Duration`, `""` for a plain float — see the
/// `Kind::Float` / `Kind::Duration` arms).
fn decode_float(b: &[u8]) -> Option<f64> {
  match b.len() {
    4 => {
      let arr: [u8; 4] = [b[0], b[1], b[2], b[3]];
      Some(f64::from(f32::from_be_bytes(arr)))
    }
    8 => {
      let arr: [u8; 8] = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
      Some(f64::from_be_bytes(arr))
    }
    _ => None,
  }
}

/// Matroska.pm:1170-1171 — `string`: NUL-trimmed ASCII (Latin-1 in Perl;
/// `\0.*` regex strips everything from the first NUL onward).
fn decode_ascii(b: &[u8]) -> Cow<'_, str> {
  let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
  // ASCII is a UTF-8 subset; non-ASCII bytes here would be Latin-1 in Perl.
  // The fixture's `string`-format tags ("V_MPEG4/ISO/AVC", "und", etc.) are
  // pure ASCII. For non-ASCII bytes, lossy-convert to keep the &str shape.
  match core::str::from_utf8(&b[..end]) {
    Ok(s) => Cow::Borrowed(s),
    Err(_) => Cow::Owned(String::from_utf8_lossy(&b[..end]).into_owned()),
  }
}

/// Matroska.pm:1171-1172 — `utf8`: NUL-trimmed, decoded as UTF-8.
fn decode_utf8(b: &[u8]) -> Cow<'_, str> {
  let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
  match core::str::from_utf8(&b[..end]) {
    Ok(s) => Cow::Borrowed(s),
    Err(_) => Cow::Owned(String::from_utf8_lossy(&b[..end]).into_owned()),
  }
}

/// `unpack("H*", $val)` — lowercase-hex stringification of bytes
/// (Matroska.pm:35).
fn hex_lower(b: &[u8]) -> SmolStr {
  use core::fmt::Write as _;
  let mut s = std::string::String::with_capacity(b.len() * 2);
  for byte in b {
    let _ = write!(&mut s, "{byte:02x}");
  }
  SmolStr::new(&s)
}

// ===========================================================================
// `Diagnose` — the golden-pattern diagnostics path (Phase B.1.5)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// Matroska's `$et->Warn` channel, in walk (FoundTag) order. Each
  /// [`Diagnostic`](crate::diagnostics::Diagnostic) already carries its
  /// family-1 group (the active `$$et{SET_GROUP1}` at `Warn` time —
  /// [`Walker::push_warning`]): a group-scoped one (`Info` / `Track<N>` /
  /// `Chapter<n>`) surfaces as the `<group>:Warning` TAG, an ungrouped one as
  /// the document `ExifTool:Warning`. Sites:
  /// - `Illegal float size (N)` (Matroska.pm:1179) — group-scoped to the
  ///   active group (e.g. `Info:Warning` for a bad-size `Duration`,
  ///   `Track<N>:Warning` for a bad-size `AudioSampleRate`).
  /// - `Invalid or corrupted <name> master element` (Matroska.pm:1075) —
  ///   group-scoped when a `SET_GROUP1` is active, else document.
  /// - `Truncated Matroska header` (Matroska.pm:1006) — document-level (the
  ///   `Meta` then also reports [`Meta::suppress_file_type`]).
  ///
  /// (`Processing large block`, Matroska.pm:1140, is `LargeFileSupport==2`-
  /// gated — this port exposes no such option, so it is unreachable and never
  /// queued.)
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    self.warnings.clone()
  }
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

// Use the rust standard library's String for transient builders.
use std::string::String;

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield Matroska tags in extraction order (Perl `FoundTag` call sequence)
  /// — the golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead of
  /// `out.write_*`), the per-tag PrintConv/ValueConv branches are preserved
  /// verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: `family0` = `"Matroska"` (the `%Matroska::Main` table group —
  /// Matroska.pm:60 `GROUPS => { 2 => 'Video' }`, so family0 defaults to the
  /// module name); `family1` = `entry.group()` (the per-entry `-G1` key —
  /// `"Matroska"`, `"Info"`, `"Track<N>"`, …), byte-identical to the retired
  /// sink. Every Matroska tag is a known table/SimpleTag row (no
  /// `Unknown => 1`) ⇒ `unknown: false`.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<EmittedTag> = Vec::with_capacity(self.entries.len());
    for entry in &self.entries {
      push_one(&mut tags, entry, self.timecode_scale_ns, print_conv);
    }
    tags.into_iter()
  }
}

/// Resolve `name` → `Kind` by re-looking it up in `TAG_TABLE`. Used by
/// `push_one` to know which PrintConv to apply. Accepts `&str` so it works
/// for both static-table names AND SimpleTag synthesized names (which won't
/// match — the caller falls back to `PrintConv::Identity`).
fn kind_for_name(name: &str) -> Option<Kind> {
  TAG_TABLE
    .iter()
    .find_map(|t| (t.name == name).then(|| t.kind))
}

/// Push a single Matroska entry as an [`EmittedTag`] (family0 `"Matroska"`,
/// family1 = `entry.group()`, `unknown: false`). Preserves every per-value
/// PrintConv/ValueConv branch of the retired `emit_one` verbatim.
#[cfg(feature = "alloc")]
fn push_one(
  tags: &mut Vec<crate::emit::EmittedTag>,
  entry: &Entry<'_>,
  ts_ns: Option<u64>,
  print_conv: bool,
) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let name = entry.name();
  // family0 = "Matroska" (table group0); family1 = the per-entry group.
  let group = || Group::new("Matroska", entry.group());
  let mut push = |value: TagValue| tags.push(EmittedTag::new(group(), name.into(), value, false));
  match entry.value_ref() {
    Value::U64(n) => {
      // Lookup the PrintConv variant for this name.
      let pc = match kind_for_name(name) {
        Some(Kind::Unsigned(p)) => p,
        _ => PrintConv::Identity,
      };
      if print_conv {
        match pc {
          PrintConv::Identity => push(TagValue::U64(*n)),
          PrintConv::Map(map) => {
            if let Some(label) = lookup_map(map, *n) {
              push(TagValue::Str(label.into()));
            } else {
              // Off-table ⇒ Perl emits the bare numeric (verbose tracks
              // the unknown but tag value is the raw integer).
              push(TagValue::U64(*n));
            }
          }
          PrintConv::NoYes => {
            if let Some(label) = no_yes_print_conv(*n) {
              push(TagValue::Str(label.into()));
            } else {
              push(TagValue::U64(*n));
            }
          }
        }
      } else {
        push(TagValue::U64(*n));
      }
    }
    Value::I64(n) => {
      push(TagValue::I64(*n));
    }
    Value::F64(x) => {
      push(TagValue::F64(*x));
    }
    Value::Str(s) => {
      push(TagValue::Str(s.as_ref().into()));
    }
    Value::Date(raw_ns) => {
      // Matroska.pm:1193-1198 — `$t = $val / 1e9; $t += (((2001-1970)*365+8)
      // *24*3600); $val = ConvertUnixTime($t, undef, -9) . 'Z'`. The dec=-9
      // argument enables fractional-second formatting (9 decimal places) with
      // trailing-zero trimming. See `convert_matroska_date` below for the
      // faithful transliteration of `ConvertUnixTime`'s fractional branch
      // (ExifTool.pm:6773-6800).
      let s = convert_matroska_date(*raw_ns);
      push(TagValue::Str(s.into()));
    }
    Value::UidHex(hex) => {
      // Matroska.pm:33-36 — `ValueConv => 'unpack("H*",$val)'`. Same
      // string under -j and -n (no PrintConv).
      push(TagValue::Str(hex.as_str().into()));
    }
    Value::TimecodeScaleRaw(raw_ns) => {
      // Matroska.pm:160-166 — ValueConv `$val / 1e9`, PrintConv
      // `($val * 1000) . " ms"`.
      let vc = (*raw_ns as f64) / 1e9;
      if print_conv {
        // `($val * 1000) . " ms"` — `$val` here is the POST-ValueConv
        // f64 (vc). The Perl string concatenation auto-stringifies a
        // float in Perl's compact form; for whole-number values
        // (`vc * 1000` is an integer-valued float), Perl emits `"1"`
        // rather than `"1.0"`. We mimic that via a small helper.
        let ms = vc * 1000.0;
        let mut s = String::new();
        write_perl_compact_num(&mut s, ms);
        s.push_str(" ms");
        push(TagValue::Str(s.into()));
      } else {
        push(TagValue::F64(vc));
      }
    }
    Value::DurationRawF64(raw) => {
      // Matroska.pm:170-171 — `ValueConv => '$$self{TimecodeScale} ? $val
      // * $$self{TimecodeScale} / 1e9 : $val / 1000'`,
      // `PrintConv => '$$self{TimecodeScale} ? ConvertDuration($val) : $val'`.
      //
      // Both branches gate on the SAME `$$self{TimecodeScale} ?` ternary,
      // which is PERL TRUTHINESS — `0` is falsy, NOT just `undef`. The
      // pre-fix code matched `Some(ts) => raw * ts / 1e9` unconditionally,
      // which mis-converted `TimecodeScale = 0` to `0` instead of taking
      // the `$val / 1000` fallback. Use an explicit `ts != 0` guard so
      // both `None` AND `Some(0)` fall through to the bare fallback —
      // and ensure PrintConv picks the matching numeric `$val` arm.
      //
      // ValueConv/PrintConv read `$$self{TimecodeScale}` LAZILY at output
      // time (not during the walk), so we use the FINAL scale `ts_ns`
      // even when `TimecodeScale` appears AFTER `Duration` (verified
      // empirically against bundled-Perl 13.58 — last-wins on duplicate
      // `TimecodeScale` entries too).
      let truthy_scale = ts_ns.filter(|ts| *ts != 0);
      let vc = match truthy_scale {
        Some(ts) => raw * (ts as f64) / 1e9,
        None => raw / 1000.0,
      };
      if print_conv {
        if truthy_scale.is_some() {
          let s = crate::datetime::convert_duration(vc);
          push(TagValue::Str(s.into()));
        } else {
          push(TagValue::F64(vc));
        }
      } else {
        push(TagValue::F64(vc));
      }
    }
    Value::DefaultDurationRaw(raw_ns) => {
      // Matroska.pm:301-306 — ValueConv `$val / 1e9`, PrintConv
      // `($val * 1000) . " ms"`.
      let vc = (*raw_ns as f64) / 1e9;
      if print_conv {
        let ms = vc * 1000.0;
        let mut s = String::new();
        write_perl_compact_num(&mut s, ms);
        s.push_str(" ms");
        push(TagValue::Str(s.into()));
      } else {
        push(TagValue::F64(vc));
      }
    }
    Value::VideoFrameRateRaw(raw_ns_per_frame) => {
      // Matroska.pm:294-301 — ValueConv `$val ? 1e9 / $val : 0`,
      // PrintConv `int($val * 1000 + 0.5) / 1000`.
      let vc = if *raw_ns_per_frame == 0 {
        0.0
      } else {
        1e9 / (*raw_ns_per_frame as f64)
      };
      if print_conv {
        // `int($val * 1000 + 0.5) / 1000` = round-to-3-decimals via
        // truncate-after-shift. Perl's `int` truncates toward zero.
        let shifted = vc * 1000.0 + 0.5;
        let trunc = shifted.trunc(); // POSITIVE finite ⇒ same as int()
        let rounded = trunc / 1000.0;
        // Same compact stringification as TimecodeScale (no " ms" suffix here;
        // FrameRate has no unit appended).
        let mut s = String::new();
        write_perl_compact_num(&mut s, rounded);
        push(TagValue::Str(s.into()));
      } else {
        push(TagValue::F64(vc));
      }
    }
    Value::Bytes(b) => {
      // Matroska.pm:552 (AttachedFileData) + 695 (TagBinary). ExifTool's
      // universal no-`-b` placeholder is rendered by `TagValue::Bytes`'s
      // Serialize impl (`value.rs`) — identical bytes for `-j` and `-n`.
      push(TagValue::Bytes(b.as_ref().to_vec()));
    }
    Value::ChapterTimeRawNs(raw_ns) => {
      // Matroska.pm:580-592 — `ValueConv => '$val / 1e9'`,
      // `PrintConv => 'ConvertDuration($val)'`. Both ChapterTimeStart and
      // ChapterTimeEnd share these conv forms; `-j` emits the
      // ConvertDuration string ("H:MM:SS" / "MM.MM s" form, see
      // `datetime::convert_duration`), `-n` emits the bare post-ValueConv
      // f64 seconds.
      let vc = (*raw_ns as f64) / 1e9;
      if print_conv {
        let s = crate::datetime::convert_duration(vc);
        push(TagValue::Str(s.into()));
      } else {
        push(TagValue::F64(vc));
      }
    }
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project Matroska metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// Matroska / WebM is a multimedia container; the faithful structural
  /// contribution is a single video [`TrackKind`](crate::metadata::TrackKind)
  /// (the dominant kind for the container — a precise per-track kind would
  /// require decoding each `TrackType` enum, which the typed `Meta` carries
  /// only as a raw tag-stream value, not a clean accessor). Duration /
  /// dimensions / created are left `None`: the decoded `Duration` is a raw
  /// edit-unit value whose seconds form depends on the lazily-read
  /// `TimecodeScale` (resolved only inside the tag-emission path), not a
  /// clean wall-clock accessor the projection can consume. Camera / lens /
  /// GPS / capture stay `None` (Matroska carries no such facts here).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Video);
    media
  }
}

/// Matroska date epoch offset — seconds from 1970-01-01 to 2001-01-01
/// (`(2001 - 1970) * 365 + 8` leap days × 86400 = `978307200`).
/// Matroska.pm:1196 `(((2001-1970)*365+8)*24*3600)`.
const EPOCH_OFFSET_2001_TO_1970_SECS: i64 = ((2001 - 1970) * 365 + 8) * 24 * 3600;

/// Faithful transliteration of `Matroska.pm:1193-1198` +
/// `ExifTool.pm:6773-6800 ConvertUnixTime($t, undef, -9) . 'Z'`. Input:
/// signed nanoseconds since the Matroska epoch (`2001-01-01T00:00:00Z`).
///
/// Algorithm (line-by-line vs Perl source):
///
/// ```text
/// Matroska.pm:1194  my $t = $val / 1e9;                     # secs (Matroska epoch)
/// Matroska.pm:1196  $t += (((2001-1970)*365+8)*24*3600);    # → Unix epoch
/// Matroska.pm:1197  ConvertUnixTime($t, undef, -9) . 'Z'    # with dec=-9 (trim)
///
/// ExifTool.pm:6776   return '0000:00:00 00:00:00' if $time == 0
/// ExifTool.pm:6779   $dec < 0 and $dec = -$dec, $trim = 1    # dec=-9 → 9 + trim
/// ExifTool.pm:6780   my $itime = int($time)                  # truncate toward zero
/// ExifTool.pm:6781   my $frac = $time - $itime
/// ExifTool.pm:6782   $frac < 0 and $frac += 1, $itime -= 1
/// ExifTool.pm:6783   $dec = sprintf('%.*f', $dec, $frac)     # "0.123456789" / "1.000000000"
/// ExifTool.pm:6785   $dec =~ s/^(\d)// and $1 eq '1' and $itime += 1
/// ExifTool.pm:6786   $dec =~ s/\.?0+$//                      # strip trailing zeros
/// ExifTool.pm:6788   @tm = gmtime($itime); $tz = ''          # $toLocal == undef
/// ExifTool.pm:6797   sprintf "%4d:%.2d:%.2d %.2d:%.2d:%.2d$dec%s"
/// ```
///
/// The Perl `$val / 1e9` math is f64-lossy by design (Perl's NV is also
/// f64); transliterating it line-for-line preserves byte-equivalence with
/// the Perl oracle even where the format would mathematically support more
/// precision. The zero-input shortcut fires on the POST-offset `$t`, i.e.
/// when `raw_ns == -978_307_200_000_000_000` (the Unix epoch expressed in
/// Matroska-relative nanoseconds), NOT when `raw_ns == 0` (which is the
/// Matroska epoch `2001:01:01 00:00:00Z`).
fn convert_matroska_date(raw_ns: i64) -> String {
  // Matroska.pm:1184-1191 — `$val` is the post-decode signed integer.
  // For an EBML signed/date element, bundled Perl accumulates each byte
  // into `$val = $val * 256 + $byte` (lines 1186-1188); IF the high bit
  // was set (line 1191), `$val -= $over` where `$over = 256^len`. The
  // accumulator is a Perl SCALAR which promotes from IV → NV (f64) the
  // moment the magnitude exceeds IV range (~`2^63`). For an 8-byte
  // DateUTC with the high bit set, the pre-subtract magnitude reaches
  // `~2^64`, so the result LOSES precision via f64 rounding — and the
  // canonical EBML 8-byte DateUTC layout is what every real Matroska
  // writer emits.
  //
  // To match Perl byte-for-byte we replay the same f64 promotion path
  // for negative raw_ns: `raw_ns as u64` recovers the original unsigned
  // accumulator value (2^64 + raw_ns since raw_ns < 0), `as f64` applies
  // the same IEEE round-to-nearest as Perl's NV promotion, then the
  // `- 2^64` subtraction (also in f64) recovers Perl's lossy negative.
  // For non-negative raw_ns (high bit clear), Perl never enters the
  // subtract branch and `raw_ns as f64` produces the same value as
  // Perl's accumulator (`x.x.y.z as f64` is identical regardless of how
  // you build x.x.y.z, since IEEE rounding is deterministic).
  //
  // Assumes 8-byte input — the canonical EBML DateUTC width (Matroska
  // spec; every real-world writer emits 8 bytes for `Format => 'date'`).
  // A non-8-byte DateUTC (extremely rare; the EBML grammar permits 1-8
  // bytes for any signed integer) would compute Perl's `$over = 256^len`
  // with a SMALLER value, so the correction here would diverge. If a
  // fixture ever surfaces this case, plumb the byte length through from
  // `decode_signed` and parameterize the correction. Until then the
  // 8-byte assumption is byte-faithful for every real Matroska file.
  let raw_f64 = if raw_ns < 0 {
    // `$over = 256^8 = 2^64` (exact in f64 — it's a power of two within
    // the representable range). `(raw_ns as u64) as f64` recovers Perl's
    // pre-subtract NV; the subtraction in f64 mirrors line 1191.
    const POW_2_64: f64 = 18_446_744_073_709_551_616.0; // 2^64 exact in f64
    (raw_ns as u64) as f64 - POW_2_64
  } else {
    raw_ns as f64
  };

  // Matroska.pm:1194-1196 — f64 division + addition, deliberately lossy
  // to match Perl's NV arithmetic byte-for-byte.
  let secs_2001 = raw_f64 / 1e9;
  let time = secs_2001 + EPOCH_OFFSET_2001_TO_1970_SECS as f64;

  // ExifTool.pm:6776 — special-case input zero. This fires when `time`
  // (post-Matroska-offset Unix seconds) is exactly 0.0, i.e. the Unix
  // epoch expressed as a Matroska date. Matroska then appends 'Z'.
  if time == 0.0 {
    return "0000:00:00 00:00:00Z".to_string();
  }

  // ExifTool.pm:6779 — dec=-9 → dec=9, trim=1.
  // ExifTool.pm:6780-6782 — split into truncate-toward-zero integer seconds
  // plus non-negative fractional. Perl's `int()` on a float truncates
  // toward zero; Rust's `f64::trunc()` does the same. The `frac < 0`
  // correction keeps frac in `[0.0, 1.0)` (matching Perl's algorithm).
  let mut itime = time.trunc() as i64;
  let mut frac = time - time.trunc();
  if frac < 0.0 {
    frac += 1.0;
    itime -= 1;
  }

  // ExifTool.pm:6783 — `sprintf('%.9f', $frac)` → "0.123456789" /
  // "1.000000000" (the `%.9f` printf format always emits a single leading
  // digit before the decimal for `frac` in `[0.0, 1.0]`, but rounding can
  // promote frac to 1.000000000 at the %.9f boundary, which the next line
  // detects and folds into itime).
  let mut dec_str = format!("{frac:.9}");

  // ExifTool.pm:6785 — `s/^(\d)//` strips one leading digit; if it was '1'
  // (i.e. frac rounded UP to 1.000000000 at %.9f), increment itime.
  // The first byte of `dec_str` is always an ASCII '0' or '1' (the integer
  // part of a [0.0, 1.0] %.9f format never overflows into multi-digit), so
  // we can peel it off via byte slicing — safe because the format string
  // guarantees this shape.
  debug_assert!(dec_str.starts_with('0') || dec_str.starts_with('1'));
  let leading_was_one = dec_str.starts_with('1');
  dec_str.remove(0);
  if leading_was_one {
    itime += 1;
  }

  // ExifTool.pm:6786 — `$dec =~ s/\.?0+$//` strips trailing zeros and a
  // trailing '.' if present. Applied unconditionally because `trim = 1`
  // (Matroska always passes negative dec).
  while dec_str.ends_with('0') {
    dec_str.pop();
  }
  if dec_str.ends_with('.') {
    dec_str.pop();
  }

  // ExifTool.pm:6788-6789 — `gmtime($itime); $tz = ''` (toLocal == undef).
  // ExifTool.pm:6797 — `sprintf("%4d:%.2d:%.2d %.2d:%.2d:%.2d$dec%s", ...)`.
  // Matroska.pm:1197 — append 'Z'. We share `gmtime` via the public
  // `convert_unix_time` helper for `itime != 0`; for the post-correction
  // itime == 0 path we bypass its special-case shortcut (Perl's shortcut
  // is on the ORIGINAL `$time`, not `$itime`, and at this point
  // `$time != 0`).
  let mut s = if itime == 0 {
    // gmtime(0) ⇒ 1970:01:01 00:00:00 (the Unix epoch components). We
    // can't call `convert_unix_time(0)` because that returns the
    // `"0000:00:00 00:00:00"` shortcut, but Perl's shortcut here was
    // already bypassed (input `$time != 0`).
    "1970:01:01 00:00:00".to_string()
  } else {
    convert_unix_time(itime)
  };
  s.push_str(&dec_str);
  s.push('Z');
  s
}

/// Perl-style "compact" float-to-string for a finite f64. When the value
/// is exactly an integer (e.g. `1.0`, `25.0`, `24.0`), Perl's default
/// stringification emits `"1"` / `"25"` / `"24"`; for fractional values
/// it emits up to 15 significant digits. This matches the `($val * 1000)
/// . " ms"` and `int($val * 1000 + 0.5) / 1000` rendering used by
/// Matroska.pm:166 / 300 etc.
fn write_perl_compact_num(out: &mut String, val: f64) {
  use core::fmt::Write as _;
  if val.is_finite() && val == val.trunc() && val.abs() < 1e16 {
    // Render as integer.
    let n = val as i64;
    let _ = write!(out, "{n}");
  } else {
    // Render with up to 15 significant digits. The most common case (the
    // fixture's `1` / `25` / `24`) is handled above; this branch is
    // reserved for fractional values.
    let _ = write!(out, "{val}");
  }
}

// ===========================================================================
// Conditional dispatch (0x3e383, 0x06, 0x58688)
// ===========================================================================
//
// The above `walk` matches via `tag_def(id)` which always returns the
// `_TrackDefault…` `Kind::Skip` placeholder for the conditional element IDs.
// We have to intercept BEFORE the table lookup so the decode path uses the
// per-TrackType name. The cleanest fix is to dispatch by id in `walk()`
// before calling `tag_def`. The placeholder TagDef rows keep the table
// exhaustive for documentation; the actual decode lives below.

/// Conditional-id pre-dispatch — called from `walk()` BEFORE `tag_def`.
/// Returns `Some(())` and pushes the right Entry when `id` is one of the
/// three conditional IDs; the caller advances the cursor and continues.
///
/// Matroska.pm:1224-1226 — when a SimpleTag struct is active, ALL leaves
/// (including these conditional-tag leaves) are absorbed-then-dropped
/// instead of emitted. These IDs (VideoFrameRate, CodecID, CodecName)
/// legally live inside TrackEntry, not SimpleTag, but the absorb guard
/// is universal in Perl.
fn maybe_handle_conditional<'a>(w: &mut Walker<'a>, id: i64, body: &'a [u8]) -> bool {
  let Some((name, kind)) = resolve_conditional_name(id, w.track_type) else {
    return false;
  };
  // Absorb-into-struct (no top-level emit) when SimpleTag is active.
  // Spec-illegal placement, but faithful to Matroska.pm:1224-1226.
  if w.simple_tag.is_some() {
    return true;
  }
  match kind {
    ConditionalKind::VideoFrameRate => {
      let raw = decode_unsigned(body);
      push_entry(w, name, Value::VideoFrameRateRaw(raw));
    }
    ConditionalKind::DefaultDuration => {
      let raw = decode_unsigned(body);
      push_entry(w, name, Value::DefaultDurationRaw(raw));
    }
    ConditionalKind::AsciiString => {
      let s = decode_ascii(body);
      push_entry(w, name, Value::Str(s));
    }
    ConditionalKind::Utf8String => {
      let s = decode_utf8(body);
      push_entry(w, name, Value::Str(s));
    }
  }
  true
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Drive the `Meta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for `print_conv` and
  /// return the resulting [`TagMap`](crate::tagmap::TagMap) — the production
  /// sink path that replaced the retired `serialize_tags`.
  #[cfg(feature = "alloc")]
  fn emit_into_tagmap(meta: &Meta<'_>, print_conv: bool) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(
      meta,
      crate::emit::ConvMode::from_print_conv(print_conv),
      &mut w,
    );
    w
  }
  #[test]
  fn get_vint_single_byte_id() {
    // 0x82 ⇒ length-marker bit at 0x80, value = 0x02 (the DocType ID's
    // size byte position, not the ID itself; pick a sample).
    let v = get_vint(&[0x82], 0).unwrap();
    assert_eq!(v.consumed(), 1);
    assert_eq!(v.value(), 0x02);
    assert!(!v.is_unknown());
  }

  #[test]
  fn get_vint_two_byte_id() {
    // 0x42 0x86 ⇒ length-marker bit at 0x40, value = 0x0286 (EBMLVersion).
    let v = get_vint(&[0x42, 0x86], 0).unwrap();
    assert_eq!(v.consumed(), 2);
    assert_eq!(v.value(), 0x286);
  }

  #[test]
  fn get_vint_four_byte_ebml_magic() {
    // 0x1a 0x45 0xdf 0xa3 — the EBML header magic. 4-byte VINT with marker
    // at 0x10, value = 0x0a45dfa3.
    let v = get_vint(&[0x1a, 0x45, 0xdf, 0xa3], 0).unwrap();
    assert_eq!(v.consumed(), 4);
    assert_eq!(v.value(), 0xa45dfa3);
  }

  #[test]
  fn get_vint_unknown_size() {
    // 0xff ⇒ 1-byte VINT with every data bit set ⇒ "unknown" arm.
    let v = get_vint(&[0xff], 0).unwrap();
    assert!(v.is_unknown());
  }

  #[test]
  fn get_vint_short_buffer_returns_none() {
    // 0x42 declares a 2-byte VINT but only 1 byte is present.
    assert!(get_vint(&[0x42], 0).is_none());
  }

  #[test]
  fn decode_unsigned_be_big_int() {
    assert_eq!(decode_unsigned(&[]), 0);
    assert_eq!(decode_unsigned(&[0x2c]), 0x2c);
    assert_eq!(decode_unsigned(&[0x01, 0x00]), 256);
    assert_eq!(decode_unsigned(&[0x00, 0x0f, 0x42, 0x40]), 1_000_000);
  }

  #[test]
  fn decode_signed_sign_extends() {
    assert_eq!(decode_signed(&[0x7f]), 127);
    assert_eq!(decode_signed(&[0x80]), -128);
    assert_eq!(decode_signed(&[0xff]), -1);
    assert_eq!(decode_signed(&[0xff, 0xff]), -1);
  }

  #[test]
  fn decode_float_handles_4_and_8_byte() {
    assert_eq!(decode_float(&1.5f32.to_be_bytes()), Some(1.5_f64));
    assert_eq!(decode_float(&2.5f64.to_be_bytes()), Some(2.5_f64));
    // Illegal size ⇒ `None` (the `else { $et->Warn(...) }` undef branch).
    assert_eq!(decode_float(&[0x00, 0x01]), None);
    assert_eq!(decode_float(&[0x00, 0x01, 0x02]), None);
  }

  #[test]
  fn hex_lower_emits_lowercase_hex() {
    assert_eq!(hex_lower(&[0xa1, 0x69, 0x29, 0x0f]).as_str(), "a169290f");
    assert_eq!(hex_lower(&[]).as_str(), "");
  }

  #[test]
  fn perl_compact_num_renders_integer_as_int() {
    let mut s = String::new();
    write_perl_compact_num(&mut s, 25.0);
    assert_eq!(s, "25");
    s.clear();
    write_perl_compact_num(&mut s, 24.0);
    assert_eq!(s, "24");
    s.clear();
    write_perl_compact_num(&mut s, 1.5);
    assert_eq!(s, "1.5");
  }

  #[test]
  fn epoch_offset_constant_matches_perl() {
    // (((2001-1970)*365+8)*24*3600) = 978307200
    assert_eq!(EPOCH_OFFSET_2001_TO_1970_SECS, 978_307_200);
  }

  // -- convert_matroska_date ----------------------------------------------
  // Bundled-Perl oracle (LC_ALL=C TZ=UTC) on
  // `Image::ExifTool::ConvertUnixTime($val/1e9 + 978_307_200, undef, -9)
  // . 'Z'` for each `raw_ns` below. Confirms our faithful transliteration
  // of the fractional branch (`ExifTool.pm:6773-6800`) matches Perl's NV
  // arithmetic byte-for-byte.

  #[test]
  fn convert_matroska_date_matroska_epoch_is_2001_jan_01() {
    // raw_ns = 0 ⇒ Matroska epoch ⇒ 2001:01:01 00:00:00Z (NOT the
    // ExifTool.pm:6776 shortcut — that triggers when post-offset $t == 0).
    assert_eq!(convert_matroska_date(0), "2001:01:01 00:00:00Z");
  }

  #[test]
  fn convert_matroska_date_unix_epoch_hits_zero_shortcut() {
    // raw_ns = -978_307_200_000_000_000 ⇒ post-offset $t == 0 ⇒
    // ExifTool.pm:6776 shortcut fires; Matroska appends 'Z'.
    let unix_epoch_ns = -(EPOCH_OFFSET_2001_TO_1970_SECS * 1_000_000_000);
    assert_eq!(convert_matroska_date(unix_epoch_ns), "0000:00:00 00:00:00Z");
  }

  #[test]
  fn convert_matroska_date_integer_seconds_have_no_fractional() {
    // Bundled Matroska.mkv carries DateTimeOriginal that maps to
    // "2010:02:03 21:17:48Z" (no fractional). Synthetic exact whole-second
    // example: raw_ns ≡ (1264965468 - 978307200) * 1e9 = 286658268000000000.
    // Bundled-Perl on $t=1264965468.0 yields "2010:01:31 19:17:48" (no
    // fractional after trim).
    let raw_ns = 286_658_268_i64 * 1_000_000_000;
    assert_eq!(convert_matroska_date(raw_ns), "2010:01:31 19:17:48Z");
  }

  #[test]
  fn convert_matroska_date_half_second_renders_dot_five() {
    // raw_ns = (1264965468 - 978307200) * 1e9 + 500_000_000 ⇒ $t = .5
    // ⇒ Bundled-Perl: "2010:01:31 19:17:48.5". Verifies trailing-zero
    // trim collapses ".500000000" → ".5".
    let raw_ns = 286_658_268_i64 * 1_000_000_000 + 500_000_000;
    assert_eq!(convert_matroska_date(raw_ns), "2010:01:31 19:17:48.5Z");
  }

  #[test]
  fn convert_matroska_date_high_precision_subseconds_lossy_to_f64() {
    // raw_ns = (1264965468 - 978307200) * 1e9 + 123456789 ⇒ Bundled-Perl
    // on $t=1264965468.123456789 yields ".123456717" (f64 precision loss
    // by design — Perl's NV / 1e9 has the same loss).
    let raw_ns = 286_658_268_i64 * 1_000_000_000 + 123_456_789;
    assert_eq!(
      convert_matroska_date(raw_ns),
      "2010:01:31 19:17:48.123456717Z"
    );
  }

  #[test]
  fn convert_matroska_date_negative_raw_ns_pre_2001() {
    // raw_ns = -1_500_000_000 ⇒ Perl's 8-byte signed-decode loop
    // accumulates 0xFFFFFFFFA697D100 → NV-promotes to f64
    // (1.84467440722095514e+19), then `- 2^64` in f64 yields -1500000256
    // (off by 256 from the exact -1.5e9, due to f64 rounding at the
    // ~2^64 magnitude). `$t = -1500000256/1e9 + 978307200 ≈
    // 978307198.499999744` ⇒ Bundled-Perl emits "2000:12:31
    // 23:59:58.499999762Z" — byte-exact via our u64-as-f64-minus-2^64
    // replay. Exercises (a) the negative-i64 → f64 lossy-cast path and
    // (b) the `$frac < 0 → frac += 1; itime -= 1` branch via the
    // POSITIVE fractional component that results from a non-integral
    // post-offset $t.
    let raw_ns = -1_500_000_000_i64;
    assert_eq!(
      convert_matroska_date(raw_ns),
      "2000:12:31 23:59:58.499999762Z"
    );
  }

  #[test]
  fn convert_matroska_date_round_up_carries_into_seconds() {
    // raw_ns chosen so $t = ...9999999995 rounds UP to .000000000 at
    // %.9f boundary and the increment-itime branch fires. Bundled-Perl
    // on 1264965468.9999999995 = "2010:01:31 19:17:49" (whole second
    // after round-up + trim of trailing zeros).
    // (1264965468 - 978307200) * 1e9 + 999999999 = 286658268999999999
    let raw_ns = 286_658_268_999_999_999_i64;
    // f64 imprecision near .9999999995 promotes to next second.
    // Verify against the bundled-Perl direct oracle (line for 1264965468
    // .9999999995 captured 2026-05-22).
    assert_eq!(convert_matroska_date(raw_ns), "2010:01:31 19:17:49Z");
  }

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(&[0x1a, 0x45, 0xdf]).is_none()); // 3-byte
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    assert!(parse_borrowed(&[0x00, 0x00, 0x00, 0x00]).is_none());
  }

  #[test]
  fn parse_borrowed_accepts_fixture() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read Matroska.mkv fixture");
    let meta = parse_borrowed(&bytes).expect("matroska accepted");
    assert_eq!(meta.doc_type(), Some("matroska"));
    assert!(!meta.is_webm());
    assert_eq!(meta.timecode_scale_ns(), Some(1_000_000));
  }

  // -------------------------------------------------------------------
  // Round-1 finding unit tests (F1, F2, F3, F4, F5)
  // -------------------------------------------------------------------

  #[test]
  fn f4_group_restore_after_info_sibling_uses_default_group() {
    // PR #31 R1 F4 — pre-fix the group-restore comparison fired only when
    // the PARENT ended; siblings AFTER Info inherited the `Info:` group.
    // Test: synthesize a fixture where the Tracks element appears AFTER
    // Info inside the Segment. Pre-F4 the TrackEntry / TrackNumber
    // emissions would carry an `Info:` group; post-F4 they carry the
    // correct `Track1:` group.
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_unknown_segment.mkv"
    ))
    .expect("read F4 fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, true);
    // Info emitted under `Info:`
    assert_eq!(tm.get_str("Info", "TimecodeScale"), Some("1 ms".into()));
    assert_eq!(tm.get_str("Info", "MuxingApp"), Some("unkseg".into()));
    // TrackEntry siblings AFTER Info must be under `Track1:`, NOT `Info:`.
    assert_eq!(tm.get_str("Track1", "TrackNumber"), Some("1".into()));
    assert_eq!(tm.get_str("Track1", "TrackType"), Some("Video".into()));
    // Sanity: TrackNumber MUST NOT leak into `Info:` group.
    assert_eq!(tm.get_str("Info", "TrackNumber"), None);
  }

  #[test]
  fn f3_cluster_stops_walker_at_first_cluster() {
    // PR #31 R1 F3 — bundled default Cluster handling (Matroska.pm:1105
    // `last`). Our `Kind::SkipBody` → `break` matches: Tags AFTER Cluster
    // are NOT emitted (faithful to bundled).
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_cluster_skip.mkv"
    ))
    .expect("read F3 fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, true);
    // Info BEFORE cluster: emitted
    assert_eq!(tm.get_str("Info", "TimecodeScale"), Some("1 ms".into()));
    assert_eq!(tm.get_str("Info", "MuxingApp"), Some("clu".into()));
    // Cluster body should NOT be descended (TimeCode, SimpleBlock inside
    // Cluster are NoSave anyway; verify we don't even attempt to emit)
    // Tags AFTER cluster MUST NOT appear — bundled stops at first Cluster.
    assert_eq!(tm.get_str("Matroska", "Title"), None);
  }

  #[test]
  fn f5_binary_emits_placeholder_in_both_modes() {
    // PR #31 R1 F5 — AttachedFileData emits the no-`-b` placeholder string
    // in both `-j` and `-n` modes. `tm.get_str` hex-encodes Bytes for the
    // raw-storage probe; the placeholder is rendered by
    // `TagValue::Bytes::Serialize` (`src/value.rs:711-716`), which we
    // verify via the JSON round-trip below.
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_attachment.mkv"
    ))
    .expect("read F5 fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    for print_conv in [true, false] {
      let tm = emit_into_tagmap(&meta, print_conv);
      // The raw `TagValue::Bytes` storage stringifies as lower-hex via
      // `tm.get_str` — a sanity check that the 32-byte attachment WAS
      // captured (vs the pre-F5 silent drop).
      let hex = tm
        .get_str("Matroska", "AttachedFileData")
        .expect("F5 captured");
      assert_eq!(hex.len(), 32 * 2);
      assert!(hex.starts_with("ffd8ffe0"), "JPEG magic preserved");
      // String/utf8 attachments remain emitted as their normal Str value.
      assert_eq!(
        tm.get_str("Matroska", "AttachedFileName"),
        Some("cover.jpg".into())
      );
    }
  }

  #[test]
  fn f1_simpletag_maps_via_std_tag_table() {
    // PR #31 R1 F1 — Tags → SimpleTag → StdTag-mapped tag emission.
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_simpletag.mkv"
    ))
    .expect("read F1 fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, true);
    // TITLE → Title, ARTIST → Artist (Matroska.pm:764, 777).
    assert_eq!(tm.get_str("Matroska", "Title"), Some("Hello World".into()));
    assert_eq!(tm.get_str("Matroska", "Artist"), Some("Test Artist".into()));
    // DATE_RELEASED → DateReleased + dateInfo separator conversion
    // (Matroska.pm:826 + 29): "2010-01-15" → "2010:01:15".
    assert_eq!(
      tm.get_str("Matroska", "DateReleased"),
      Some("2010:01:15".into())
    );
    // Raw TagName/TagString must NOT be emitted alongside (they are
    // absorbed into the SimpleTag struct and flushed via StdTag).
    assert_eq!(tm.get_str("Matroska", "TagName"), None);
    assert_eq!(tm.get_str("Matroska", "TagString"), None);
  }

  #[test]
  fn f1_synthesize_tag_name_matroska_pm_rules() {
    // Matroska.pm:905-911 — verbatim porting smoke test for the
    // `ucfirst lc / strip / camelCase / Tag_<short>` rules.
    // "FOO" → lc "foo" → ucfirst "Foo" → strip nothing → "Foo".
    assert_eq!(synthesize_tag_name("FOO"), "Foo");
    // "MY_CUSTOM_TAG" → "my_custom_tag" → "My_custom_tag" → camelCase
    // _c → C, _t → T → "MyCustomTag".
    assert_eq!(synthesize_tag_name("MY_CUSTOM_TAG"), "MyCustomTag");
    // "tag-with-dashes" → lc no-op → "Tag-with-dashes" → strip `-` →
    // "Tagwithdashes" (no `_x` => X conversion).
    assert_eq!(synthesize_tag_name("tag-with-dashes"), "Tagwithdashes");
    // Short name guard: "x" → "X" → length 1 → "Tag_X".
    assert_eq!(synthesize_tag_name("x"), "Tag_X");
    // Empty input → empty post-trim → "Tag_" prefix.
    assert_eq!(synthesize_tag_name(""), "Tag_");
  }

  #[test]
  fn f1_date_separator_convert_matches_perl_regex() {
    // dateInfo.ValueConv (Matroska.pm:29) — `s/^(\d{4})-(\d{2})-/$1:$2:/`.
    assert_eq!(date_separator_convert("2010-01-15"), "2010:01:15");
    assert_eq!(
      date_separator_convert("2010-01-15T00:00:00"),
      "2010:01:15T00:00:00"
    );
    // Timezone separator is NOT converted (only the first two `-`).
    assert_eq!(
      date_separator_convert("2010-01-15T00:00:00-05:00"),
      "2010:01:15T00:00:00-05:00"
    );
    // Non-date input: pass through unchanged.
    assert_eq!(date_separator_convert("not a date"), "not a date");
    // ISO with `:` already: pass through unchanged.
    assert_eq!(date_separator_convert("2010:01:15"), "2010:01:15");
  }

  #[test]
  fn f1_std_tag_lookup_finds_canonical_and_date_rows() {
    let e = std_tag_lookup("TITLE").expect("TITLE present");
    assert_eq!(e.name, "Title");
    assert!(!e.is_date);
    let e = std_tag_lookup("DATE_RELEASED").expect("DATE_RELEASED present");
    assert_eq!(e.name, "DateReleased");
    assert!(e.is_date);
    assert!(std_tag_lookup("THIS_IS_NOT_A_REAL_KEY").is_none());
  }

  #[test]
  fn r3_duration_perl_truthy_guard_treats_some_zero_as_falsy() {
    // PR #31 R3 — the actual pre-fix bug. Direct fixture-based unit
    // test (the conformance test `matroska_duration_zero_scale_*` is
    // the load-bearing one; this one PINS the truthy-guard branch in
    // isolation so a regression diagnosis can localize quickly).
    //
    // Fixture: Info[TimecodeScale=0, Duration=60000.0]. Pre-fix Rust:
    // `Some(0) => raw * 0 / 1e9 = 0.0`. Post-fix: explicit `ts != 0`
    // guard ⇒ falsy branch ⇒ `60000 / 1000 = 60.0`. Bundled-Perl
    // confirms: `"Info:Duration": 60` (bare numeric — PrintConv mirrors
    // the same truthiness).
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_duration_zero_scale.mkv"
    ))
    .expect("read R3 zero-scale fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    // Sanity: TimecodeScale captured as 0.
    assert_eq!(meta.timecode_scale_ns(), Some(0));
    // -j mode: both Duration and TimecodeScale render as bare numeric
    // (PerlConv falsy branch fires for both). TimecodeScale's PrintConv
    // is `($val * 1000) . " ms"` ⇒ "0 ms" (no truthy guard there —
    // unconditional). Duration's PrintConv is `$$self{TimecodeScale} ?
    // ConvertDuration($val) : $val` ⇒ falsy branch ⇒ bare 60.0.
    let tm_j = emit_into_tagmap(&meta, true);
    assert_eq!(tm_j.get_str("Info", "TimecodeScale"), Some("0 ms".into()));
    assert_eq!(tm_j.get_str("Info", "Duration"), Some("60".into()));
    // -n mode: same — Duration falls through to the numeric fallback.
    let tm_n = emit_into_tagmap(&meta, false);
    assert_eq!(tm_n.get_str("Info", "Duration"), Some("60".into()));
  }

  #[test]
  fn r3_duration_before_scale_uses_final_timecode_scale() {
    // PR #31 R3 — ValueConv/PrintConv are output-time, NOT walk-time.
    // Fixture: Info[Duration BEFORE TimecodeScale=1ms]. Bundled-Perl
    // uses the FINAL `$$self{TimecodeScale}` = 1 ms ⇒
    // `60000 * 1e6 / 1e9 = 60.0 s = "0:01:00"`. A walk-time-only
    // implementation that read `$$self{TimecodeScale}` BEFORE
    // TimecodeScale was seen would emit `60` (falsy branch) — which
    // contradicts bundled. Pin the correct semantic here.
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_duration_before_scale.mkv"
    ))
    .expect("read R3 order-skewed fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    assert_eq!(meta.timecode_scale_ns(), Some(1_000_000));
    let tm_j = emit_into_tagmap(&meta, true);
    assert_eq!(tm_j.get_str("Info", "Duration"), Some("0:01:00".into()));
    assert_eq!(tm_j.get_str("Info", "TimecodeScale"), Some("1 ms".into()));
  }

  #[test]
  fn f2_unknown_size_master_descends_to_eof() {
    // PR #31 R1 F2 — Segment with unknown-size VINT must be descended.
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska_unknown_segment.mkv"
    ))
    .expect("read F2 fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    // Pre-F2: walker breaks on the unknown-size VINT → Info/Tracks lost.
    // Post-F2: Info+Tracks descended.
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(tm.get_str("Info", "TimecodeScale"), Some("1 ms".into()));
    assert_eq!(tm.get_str("Info", "MuxingApp"), Some("unkseg".into()));
    assert_eq!(tm.get_str("Track1", "TrackNumber"), Some("1".into()));
  }

  #[test]
  fn fixture_emits_expected_tags() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(tm.get_str("Matroska", "DocType"), Some("matroska".into()));
    assert_eq!(tm.get_str("Info", "TimecodeScale"), Some("1 ms".into()));
    assert_eq!(tm.get_str("Info", "Duration"), Some("0:02:29".into()));
    assert_eq!(
      tm.get_str("Info", "DateTimeOriginal"),
      Some("2010:02:03 21:17:48Z".into())
    );
    assert_eq!(tm.get_str("Track1", "TrackNumber"), Some("1".into()));
    assert_eq!(tm.get_str("Track1", "TrackUID"), Some("a169290f".into()));
    assert_eq!(tm.get_str("Track1", "TrackType"), Some("Video".into()));
    assert_eq!(
      tm.get_str("Track1", "VideoCodecID"),
      Some("V_MPEG4/ISO/AVC".into())
    );
    assert_eq!(tm.get_str("Track2", "TrackNumber"), Some("2".into()));
    assert_eq!(
      tm.get_str("Track2", "AudioCodecID"),
      Some("A_MPEG/L3".into())
    );
    assert_eq!(
      tm.get_str("Track2", "AudioSampleRate"),
      Some("48000".into())
    );
  }

  #[test]
  fn taggable_group_is_matroska_family0_and_entry_family1() {
    use crate::emit::{ConvMode, Taggable};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tags: Vec<_> = meta.tags(ConvMode::PrintConv).collect();
    // No Matroska tag carries `Unknown => 1`.
    assert!(tags.iter().all(|t| !t.unknown()));
    // family0 is the constant "Matroska" table group; family1 is the
    // per-entry `-G1` key ("Matroska", "Info", "Track<N>", …).
    assert!(
      tags
        .iter()
        .all(|t| t.tag().group_ref().family0() == "Matroska")
    );
    let doc_type = tags
      .iter()
      .find(|t| t.tag().name() == "DocType")
      .expect("DocType emitted");
    assert_eq!(doc_type.tag().group_ref().family1(), "Matroska");
    let tcs = tags
      .iter()
      .find(|t| t.tag().name() == "TimecodeScale")
      .expect("TimecodeScale emitted");
    assert_eq!(tcs.tag().group_ref().family1(), "Info");
    let track_no = tags
      .iter()
      .find(|t| t.tag().name() == "TrackNumber")
      .expect("TrackNumber emitted");
    assert_eq!(track_no.tag().group_ref().family1(), "Track1");
  }

  #[test]
  fn project_populates_video_track() {
    use crate::metadata::{Project, TrackKind};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let projected = meta.project();
    // Matroska projects to a video container; the rest of MediaInfo is empty.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Video]);
    assert!(projected.media().has_video());
    assert!(projected.media().duration().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().created().is_none());
    // Matroska carries no camera / lens / GPS / capture facts here.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }
}
