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
/// `keep_marker` controls whether the length-marker bit is retained in the
/// decoded value (`true` for element IDs per EBML spec; `false` for sizes,
/// which strip it — Matroska.pm:967-972 masks it off in both cases, but
/// element IDs are decoded with the marker BIT preserved because they're
/// looked up against tables that include the marker. The bundled Perl uses
/// `GetVInt` for BOTH IDs and sizes and the IDs in `%Image::ExifTool::
/// Matroska::Main` are stored WITHOUT the length marker — Matroska.pm:39-40
/// "The tag ID's in the Matroska documentation include the length
/// designation (the upper bits), which is not included in the tag ID's
/// below."). So `keep_marker = false` in both cases for faithfulness.
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
  TagDef {
    id: 0xf43b675,
    name: "Cluster",
    kind: Kind::SubDir,
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
    kind: Kind::Skip,
  }, // Binary
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
    id: 0x11,
    name: "ChapterTimeStart",
    kind: Kind::Skip,
  },
  TagDef {
    id: 0x12,
    name: "ChapterTimeEnd",
    kind: Kind::Skip,
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
    kind: Kind::Skip,
  }, // Binary
];

/// Resolve `id` → `TagDef`. `None` for unknown ID (faithful to
/// Matroska.pm:1127-1129 — "unknown tag, verbose log, skip past size bytes").
fn tag_def(id: i64) -> Option<&'static TagDef> {
  TAG_TABLE.iter().find(|t| t.id == id)
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
  /// `Duration` — raw f64 from the float decoder. ValueConv (when
  /// `TimecodeScale` is set, the typical case) multiplies by
  /// `TimecodeScale_ns/1e9` (Matroska.pm:167-172).
  DurationRawF64(f64),
  /// `DefaultDuration` — raw u64 nanoseconds. ValueConv `/1e9`; PrintConv
  /// `($val * 1000) . " ms"` (Matroska.pm:301-306).
  DefaultDurationRaw(u64),
  /// `VideoFrameRate` — raw u64 nanoseconds-per-frame. ValueConv `1e9/$val`
  /// when non-zero, else 0; PrintConv `int($val * 1000 + 0.5) / 1000`
  /// (Matroska.pm:294-301).
  VideoFrameRateRaw(u64),
}

/// One emitted tag in [`Meta::entries`]: family-1 group, tag name, raw
/// post-format value.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
  group: SmolStr,
  name: &'static str,
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
  pub const fn name(&self) -> &'static str {
    self.name
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
/// PrintConv strings are rendered at emit time via [`Self::serialize_tags`];
/// the raw values stored here are post-Format-decode but pre-conversion.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  entries: Vec<Entry<'a>>,
  /// Cached `DocType` (Matroska.pm:68-72) — `"matroska"`, `"webm"`, etc.
  doc_type: Option<SmolStr>,
  /// Cached `TimecodeScale` raw nanoseconds (Matroska.pm:160-166). Drives
  /// the Duration / DefaultDuration / etc. ValueConv at emit time.
  timecode_scale_ns: Option<u64>,
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
  type Error = Error;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
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
pub fn parse_borrowed(data: &[u8]) -> Result<Option<Meta<'_>>, Error> {
  parse_inner(data)
}

/// EBML walker state.
struct Walker<'a> {
  data: &'a [u8],
  /// Current cursor.
  pos: usize,
  /// Stack of (end_offset, container_name) for nested `SubDir`s. The walker
  /// pops as soon as the cursor crosses an entry's end (Matroska.pm:1023-1051).
  ends: Vec<(usize, &'static str)>,
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
fn parse_inner(data: &[u8]) -> Result<Option<Meta<'_>>, Error> {
  if data.len() < 4 || data[..4] != EBML_MAGIC {
    return Ok(None); // Matroska.pm:996 — magic gate
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
  };
  walk(&mut w);
  Ok(Some(Meta {
    entries: w.entries,
    doc_type: w.doc_type,
    timecode_scale_ns: w.timecode_scale_ns,
  }))
}

/// Main EBML walk. Faithful loop port of Matroska.pm:1022-1236. Stops on
/// any malformed element header (defensive — Perl's `last`).
fn walk(w: &mut Walker<'_>) {
  let data = w.data;
  loop {
    // ---- Pop ended containers (Matroska.pm:1023-1057) -------------------
    while let Some(&(end, _)) = w.ends.last() {
      if w.pos >= end {
        // Container ended; check whether we should restore the group.
        if let Some(d) = w.group_locked_at_depth {
          if w.ends.len() <= d {
            // We exited the SubDir that locked the group ⇒ restore default.
            w.current_group = SmolStr::new_static(DEFAULT_GROUP);
            w.group_locked_at_depth = None;
            // TrackType also resets when its TrackEntry closes
            // (Matroska.pm:262-263 `Condition => 'delete $$self{TrackType};
            // 1'` runs at TrackEntry entry, but conceptually it scopes per
            // TrackEntry).
            w.track_type = None;
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
    if id_v.is_unknown() || id_v.value() <= 0 {
      break;
    }
    w.pos += id_v.consumed();
    let Some(size_v) = get_vint(data, w.pos) else {
      break;
    };
    w.pos += size_v.consumed();
    if size_v.is_unknown() {
      // Matroska.pm:1073 — `$size < 0` ⇒ `$unknownSize = 1, $size = 1e20`.
      // Matroska.pm:1130 — `last if $unknownSize`. We can't continue
      // meaningfully without a size; faithful stop.
      break;
    }
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
    let elem_end_declared = w.pos.checked_add(size).unwrap_or(data.len());
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
        // EBML elements" + group bookkeeping.
        w.ends.push((elem_end, def.name));
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
      Kind::Unsigned(_pc) => {
        // PrintConv is resolved at emit time via the tag-name lookup
        // (`kind_for_name` in `emit_one`), so the `pc` payload here is
        // discarded.
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        // ----- TrackType bookkeeping (Matroska.pm:267-282) ---------------
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
        push_entry(w, def.name, Value::U64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Signed(_pc) => {
        let raw = decode_signed(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::I64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Float(_fc) => {
        let raw = decode_float(&data[w.pos..elem_end]);
        // FrameRate / SampleRate / etc.
        push_entry(w, def.name, Value::F64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::AsciiString => {
        let s = decode_ascii(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::Str(s));
        w.pos = elem_end;
        continue;
      }
      Kind::Utf8String => {
        let s = decode_utf8(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::Str(s));
        w.pos = elem_end;
        continue;
      }
      Kind::Date => {
        let raw = decode_signed(&data[w.pos..elem_end]);
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
        push_entry(w, def.name, Value::UidHex(hex));
        w.pos = elem_end;
        continue;
      }
      Kind::TimecodeScale => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        w.timecode_scale_ns = Some(raw);
        push_entry(w, def.name, Value::TimecodeScaleRaw(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::Duration => {
        // Matroska.pm:167-172 — `Format => 'float'`.
        let raw = decode_float(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::DurationRawF64(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::DefaultDuration => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::DefaultDurationRaw(raw));
        w.pos = elem_end;
        continue;
      }
      Kind::VideoFrameRate => {
        let raw = decode_unsigned(&data[w.pos..elem_end]);
        push_entry(w, def.name, Value::VideoFrameRateRaw(raw));
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
    name,
    value,
  });
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
/// Other sizes return `f64::NAN` (Perl warns `Illegal float size`).
fn decode_float(b: &[u8]) -> f64 {
  match b.len() {
    4 => {
      let arr: [u8; 4] = [b[0], b[1], b[2], b[3]];
      f64::from(f32::from_be_bytes(arr))
    }
    8 => {
      let arr: [u8; 8] = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
      f64::from_be_bytes(arr)
    }
    _ => f64::NAN,
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
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

// Use the rust standard library's String for transient builders.
use std::string::String;

#[cfg(feature = "alloc")]
impl Meta<'_> {
  /// Emit Matroska tags into the writer in extraction order (Perl
  /// `FoundTag` call sequence).
  ///
  /// `print_conv = true` ⇒ PrintConv strings (`-j` mode);
  /// `print_conv = false` ⇒ post-ValueConv raw scalars (`-n` mode).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    for entry in &self.entries {
      emit_one(entry, self.timecode_scale_ns, print_conv, out)?;
    }
    Ok(())
  }
}

/// Resolve `name` → `Kind` by re-looking it up in `TAG_TABLE`. Used by
/// `emit_one` to know which PrintConv to apply.
fn kind_for_name(name: &'static str) -> Option<Kind> {
  TAG_TABLE
    .iter()
    .find_map(|t| (t.name == name).then(|| t.kind))
}

fn emit_one(
  entry: &Entry<'_>,
  ts_ns: Option<u64>,
  print_conv: bool,
  out: &mut crate::tagmap::TagMap,
) -> Result<(), core::convert::Infallible> {
  let group = entry.group();
  let name = entry.name();
  match entry.value_ref() {
    Value::U64(n) => {
      // Lookup the PrintConv variant for this name.
      let pc = match kind_for_name(name) {
        Some(Kind::Unsigned(p)) => p,
        _ => PrintConv::Identity,
      };
      if print_conv {
        match pc {
          PrintConv::Identity => out.write_u64(group, name, *n)?,
          PrintConv::Map(map) => {
            if let Some(label) = lookup_map(map, *n) {
              out.write_str(group, name, label)?;
            } else {
              // Off-table ⇒ Perl emits the bare numeric (verbose tracks
              // the unknown but tag value is the raw integer).
              out.write_u64(group, name, *n)?;
            }
          }
          PrintConv::NoYes => {
            if let Some(label) = no_yes_print_conv(*n) {
              out.write_str(group, name, label)?;
            } else {
              out.write_u64(group, name, *n)?;
            }
          }
        }
      } else {
        out.write_u64(group, name, *n)?;
      }
    }
    Value::I64(n) => {
      out.write_i64(group, name, *n)?;
    }
    Value::F64(x) => {
      out.write_f64(group, name, *x)?;
    }
    Value::Str(s) => {
      out.write_str(group, name, s.as_ref())?;
    }
    Value::Date(raw_ns) => {
      // Matroska.pm:1193-1198 — `$t = $val / 1e9; $t += (((2001-1970)*365+8)
      // *24*3600); $val = ConvertUnixTime($t, undef, -9) . 'Z'`.
      let secs_2001 = (*raw_ns as f64) / 1e9;
      let secs_unix = secs_2001 + EPOCH_OFFSET_2001_TO_1970_SECS as f64;
      let mut s = convert_unix_time(secs_unix as i64);
      s.push('Z');
      out.write_str(group, name, &s)?;
    }
    Value::UidHex(hex) => {
      // Matroska.pm:33-36 — `ValueConv => 'unpack("H*",$val)'`. Same
      // string under -j and -n (no PrintConv).
      out.write_str(group, name, hex.as_str())?;
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
        out.write_str(group, name, &s)?;
      } else {
        out.write_f64(group, name, vc)?;
      }
    }
    Value::DurationRawF64(raw) => {
      // Matroska.pm:167-172 — `ValueConv => '$$self{TimecodeScale} ? $val
      // * $$self{TimecodeScale} / 1e9 : $val / 1000'`,
      // `PrintConv => '$$self{TimecodeScale} ? ConvertDuration($val) : $val'`.
      let vc = match ts_ns {
        Some(ts) => raw * (ts as f64) / 1e9,
        None => raw / 1000.0,
      };
      if print_conv {
        if ts_ns.is_some() {
          let s = crate::datetime::convert_duration(vc);
          out.write_str(group, name, &s)?;
        } else {
          out.write_f64(group, name, vc)?;
        }
      } else {
        out.write_f64(group, name, vc)?;
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
        out.write_str(group, name, &s)?;
      } else {
        out.write_f64(group, name, vc)?;
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
        out.write_str(group, name, &s)?;
      } else {
        out.write_f64(group, name, vc)?;
      }
    }
  }
  Ok(())
}

/// Matroska date epoch offset — seconds from 1970-01-01 to 2001-01-01
/// (`(2001 - 1970) * 365 + 8` leap days × 86400 = `978307200`).
/// Matroska.pm:1196 `(((2001-1970)*365+8)*24*3600)`.
const EPOCH_OFFSET_2001_TO_1970_SECS: i64 = ((2001 - 1970) * 365 + 8) * 24 * 3600;

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
fn maybe_handle_conditional<'a>(w: &mut Walker<'a>, id: i64, body: &'a [u8]) -> bool {
  let Some((name, kind)) = resolve_conditional_name(id, w.track_type) else {
    return false;
  };
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
// `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for Matroska parsing. Currently empty — every
/// bad input produces `Ok(None)` (Perl `return 0`) or walks past silently
/// (unknown EBML IDs). Reserved for future I/O wrappers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn matroska_error_is_core_error() {
    fn assert_error<E: core::error::Error>() {}
    assert_error::<Error>();
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
    assert_eq!(decode_float(&1.5f32.to_be_bytes()), 1.5_f64);
    assert_eq!(decode_float(&2.5f64.to_be_bytes()), 2.5_f64);
    assert!(decode_float(&[0x00, 0x01]).is_nan()); // illegal size
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

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(&[0x1a, 0x45, 0xdf]).unwrap().is_none()); // 3-byte
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    assert!(parse_borrowed(&[0x00, 0x00, 0x00, 0x00]).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_accepts_fixture() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read Matroska.mkv fixture");
    let meta = parse_borrowed(&bytes)
      .expect("ok")
      .expect("matroska accepted");
    assert_eq!(meta.doc_type(), Some("matroska"));
    assert!(!meta.is_webm());
    assert_eq!(meta.timecode_scale_ns(), Some(1_000_000));
  }

  #[test]
  fn fixture_emits_expected_tags() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Matroska.mkv"
    ))
    .expect("read fixture");
    let meta = parse_borrowed(&bytes).expect("ok").expect("accepted");
    let mut tm = crate::tagmap::TagMap::new();
    meta.serialize_tags(true, &mut tm).unwrap();
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
}
