// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTime::ProcessMOV`
//! (`lib/Image/ExifTool/QuickTime.pm`) — **Sub-Port 1: the box/atom walker
//! and core structural atoms only**.
//!
//! QuickTime / ISO-BMFF files are a tree of *atoms* (boxes). Every atom
//! begins with an 8-byte header (QuickTime.pm:9966-9973):
//!
//! ```text
//!   int32u size      (big-endian)
//!   char[4] type
//! ```
//!
//! `size` counts the header itself. Three special values
//! (QuickTime.pm:10035-10078):
//!  - `size == 1` ⇒ a 64-bit extended size follows the type (`int64u`);
//!    the real payload size is `extended - 16`. With the default
//!    `LargeFileSupport => 1` (ExifTool.pm:1167) a 64-bit size `> 0x7fffffff`
//!    is PARSED and the walk continues (only `hi > 0x7fffffff` is rejected) —
//!    so a real >2GB `mdat` is skipped by its declared size to reach a
//!    trailing `moov` (R12/F1, QuickTime.pm:10062-10074).
//!  - `size == 0` ⇒ the atom extends to end-of-file (QuickTime.pm:10036-10056).
//!  - `size < 8` (and not 0/1) ⇒ `'Invalid atom size'` — stop.
//!
//! The whole file is **big-endian** (QuickTime.pm:10014 `SetByteOrder('MM')`).
//!
//! ## SP1 scope
//!
//! This sub-port implements the walker plus the core structural atoms:
//! `ftyp` (major brand), `moov`/`mvhd`, `trak`/`tkhd`, `mdia`/`mdhd`,
//! `hdlr`. The camera/user-data atoms (`udta`, Keys, ItemList) and brand
//! variants are deferred to SP2 / SP4 (see `docs/tracking.md`).
//!
//! ## SP3 — embedded timed GPS metadata
//!
//! **SP3** layers the QuickTimeStream timed-metadata extraction on top:
//! [`parse_inner`] runs [`quicktime_stream::extract_stream`] over the file,
//! decoding per-frame GPS / sensor telemetry (dashcam / action-cam / drone
//! videos) into [`crate::metadata::QuickTimeStreamMeta`] — exposed via
//! [`Meta::stream`]. It also DETECTS embedded Exif/TIFF blocks
//! ([`Meta::embedded_exif_deferred`]); the actual Exif IFD parse is deferred
//! until the Exif+GPS port lands (see [`detect_embedded_exif`]).
//!
//! The faithful-parse output is the typed [`Meta`] (wrapping
//! [`crate::metadata::QuickTimeMeta`] + the SP3 stream layer); the
//! normalized [`crate::metadata::MediaMetadata`] projection — incl. the
//! [`crate::metadata::GpsLocation`] from the first embedded GPS fix — is
//! built from it via [`Meta::media_metadata`].

#![deny(clippy::indexing_slicing)]

use crate::{
  datetime::{convert_datetime, convert_duration, convert_unix_time},
  format_parser::{FormatParser, parser_sealed},
  formats::{insta360 as insta360_fmt, quicktime_freegps, quicktime_stream},
  metadata::{
    CammMeta, CanonCtmdMeta, GoProConv, GoProMeta, GoProTag, GoProTagValue, Insta360Meta,
    MediaTrack, QuickTimeGps, QuickTimeMeta, QuickTimeStreamMeta, SonyRtmdMeta,
  },
  value::{binary_placeholder, format_g},
};

/// QuickTime epoch offset: seconds between 1904-01-01 (the Mac/QuickTime
/// time zero) and 1970-01-01 (the Unix epoch).
/// `(66 * 365 + 17) * 24 * 3600` — QuickTime.pm:1361.
const QT_EPOCH_OFFSET: i64 = (66 * 365 + 17) * 24 * 3600;

/// Max container-atom recursion depth for the box/atom walk (Golden-v2
/// Contract 3a). ExifTool's `ProcessMOV` has no hard cap (it relies on the
/// finite atom sizes + EOF), but a maliciously deep box tree would recurse
/// `walk_atoms`→`walk_trak`→`walk_atoms` (or the freeGPS/embedded-Exif
/// `udta`/`meta` scans) until the stack overflows — a DoS. Real media nests
/// single-digit deep (`moov`→`trak`→`mdia`→`minf`→`stbl`→…), so this cap is a
/// large superset that never trips on a real file; the output stays
/// byte-identical. Exceeding the cap simply stops recursion (no warning),
/// faithful to a truncated/garbage subtree contributing no tags.
const MAX_ATOM_DEPTH: u32 = 100;

// ===========================================================================
// SP2 supplementary conv-less camera-atom map (xtask `--kind quicktime`)
// ===========================================================================

/// One entry of the generated SP2 conv-less camera-atom map: a `udta` 4-cc
/// (`K = &[u8]`) or `Keys` key string (`K = &str`) and the ExifTool tag NAME it
/// emits. The map covers ONLY atoms that are GENUINELY conv-less in
/// `QuickTime.pm` — plain `string`/text with no RawConv/ValueConv/PrintConv-sub
/// and no `Avoid`/`Priority` — so the walker can emit a `QuickTime:UserData` /
/// `QuickTime:Keys` tag by Name with the verbatim text value (no conversion).
/// Atoms that carry a conv/priority stay HAND-ported in the typed walker (see
/// [`quicktime_generated::UNPORTED`]).
///
/// **D8 — no public fields, accessors only.**
pub struct ConvlessAtom<K: 'static> {
  key: K,
  name: &'static str,
}

impl<K: 'static> ConvlessAtom<K> {
  /// Construct a map entry (the generated table is a `const` slice of these).
  #[inline(always)]
  #[must_use]
  pub const fn new(key: K, name: &'static str) -> Self {
    Self { key, name }
  }

  /// The emitted ExifTool tag NAME (e.g. `"GoProType"`).
  #[inline(always)]
  #[must_use]
  pub const fn name(&self) -> &'static str {
    self.name
  }
}

impl ConvlessAtom<&'static [u8]> {
  /// The raw 4-character-code key bytes (the `udta` atom type).
  #[inline(always)]
  #[must_use]
  pub const fn key(&self) -> &'static [u8] {
    self.key
  }
}

impl ConvlessAtom<&'static str> {
  /// The `Keys` key string (after the `com.apple.quicktime.` strip).
  #[inline(always)]
  #[must_use]
  pub const fn key(&self) -> &'static str {
    self.key
  }
}

/// The generated conv-less camera-atom map (`xtask gen-tables --kind quicktime`,
/// from `exiftool -listx` 13.59). Consulted by [`walk_udta`] / [`apply_key`].
pub mod quicktime_generated {
  include!("quicktime_generated.rs");
}

/// Look up a `udta` 4-cc in the generated conv-less UserData map, returning the
/// tag NAME to emit (or `None` if the atom is not a verified-conv-less one).
#[inline]
#[must_use]
fn userdata_convless_name(four_cc: &[u8]) -> Option<&'static str> {
  quicktime_generated::QUICKTIME_USERDATA_CONVLESS
    .iter()
    .find(|a| a.key() == four_cc)
    .map(ConvlessAtom::name)
}

/// Look up a `Keys` key string in the generated conv-less Keys map, returning
/// the tag NAME to emit (or `None`). The lookup is over the key as written in
/// the table (the candidate keys — `direction.facing` / `direction.motion` —
/// are in the `com.apple.quicktime` namespace, so they match the stripped key).
#[inline]
#[must_use]
fn keys_convless_name(key: &str) -> Option<&'static str> {
  quicktime_generated::QUICKTIME_KEYS_CONVLESS
    .iter()
    .find(|a| a.key() == key)
    .map(ConvlessAtom::name)
}

/// The `xtask --kind quicktime` allowlist of `%QuickTime::UserData` atoms
/// hand-verified CONV-LESS against `QuickTime.pm` (plain `'Name'` mappings, no
/// RawConv/ValueConv/PrintConv-sub, no `Avoid`/`Priority`) — by emitted NAME.
/// The emitter generates a `4cc → Name` map entry for each (cross-referencing
/// the bundled `-listx` for the on-disk bytes); a NAME here that is absent from
/// the table is a generator error. KEEP IN SYNC with [`USERDATA_UNPORTED`].
///
/// Verified at QuickTime.pm 13.59:
///  - `GoPr` GoProType (2117), `LENS` LensSerialNumber (2119), `FOV\0`
///    FieldOfView (2131) — bare `'Name'`, plain `string`/text.
///  - `©mal` MakerURL (1639), `©gpt` CameraPitch (2148), `©gyw` CameraYaw
///    (2149), `©grl` CameraRoll (2150) — bare `'Name'`, international-text.
pub const QUICKTIME_USERDATA_CONVLESS_ALLOW: &[&str] = &[
  "GoProType",
  "LensSerialNumber",
  "FieldOfView",
  "MakerURL",
  "CameraPitch",
  "CameraYaw",
  "CameraRoll",
];

/// The `xtask --kind quicktime` allowlist of `%QuickTime::Keys` atoms verified
/// CONV-LESS against `QuickTime.pm` — `direction.facing` CameraDirection (6735)
/// / `direction.motion` CameraMotion (6736): bare `Name` + only a family-2
/// `Groups => { 2 => 'Location' }` (irrelevant to the family-0/1 emission), no
/// conv/`Avoid`/`Priority`, plain-string value. KEEP IN SYNC with
/// [`KEYS_UNPORTED`].
pub const QUICKTIME_KEYS_CONVLESS_ALLOW: &[&str] = &["CameraDirection", "CameraMotion"];

/// `%QuickTime::UserData` candidate atoms that LOOK conv-less in `-listx`
/// (`type='string'`) but carry a `ValueConv` in `QuickTime.pm`, so they are NOT
/// codegen'd — they stay HAND-ported in [`walk_udta`] (faithful to the conv):
///  - `CAME` SerialNumberHash (2120-2125): `ValueConv => 'unpack("H*",$val)'`.
///  - `MUID` MediaUID (2127): `ValueConv => 'unpack("H*", $val)'`.
pub const USERDATA_UNPORTED: &[&str] = &["SerialNumberHash", "MediaUID"];

/// `%QuickTime::Keys` candidate atoms kept OUT of the generated conv-less map —
/// dispatched by an EXPLICIT arm in [`apply_key_name`] instead. Both are
/// genuinely CONV-LESS (no `Format`, no `ValueConv`), so each routes its
/// `data`-atom value through the SAME full string→numeric→binary cascade as a
/// map entry ([`ilst_data_convless`], QuickTime.pm:10387-10416) — NOT a typed
/// single-flavor field. They are hand-dispatched (not auto-codegen'd from the
/// `-listx` allowlist, which intentionally covers only `direction.*`) because
/// they resolve via the full-key fallback, not the bare `mdta`-stripped key:
///  - `com.android.capture.fps` AndroidCaptureFPS (6763): `Writable => 'float'`
///    is a WRITER hint, NOT a read `Format` ⇒ conv-less. The cascade reads a
///    float/double flag as an IEEE number, a string flag as the string, etc.
///  - `samsung.android.utc_offset` AndroidTimeZone (6769): a non-
///    `com.apple.quicktime` (full-key-fallback) conv-less key.
///
/// `Make`/`Model`/`Software` and the other `com.android.*` keys are likewise
/// conv-less explicit arms, but are NOT listed here: they carry string readers
/// (`make()`/`model()`/`software()`) for the domain projection, so they live as
/// named arms rather than UNPORTED documentation entries.
pub const KEYS_UNPORTED: &[&str] = &["AndroidCaptureFPS", "AndroidTimeZone"];

// ===========================================================================
// Atom header reading (QuickTime.pm:9966-10078)
// ===========================================================================

/// One atom header: the payload byte range `[payload_start, payload_end)`
/// within the file slice, and the 4-byte type. `payload_end == data.len()`
/// for a `size == 0` (extends-to-EOF) atom.
struct AtomHeader {
  /// 4-byte atom type (`b"moov"`, `b"ftyp"`, …).
  atom_type: [u8; 4],
  /// First byte of the payload (past the 8- or 16-byte header).
  payload_start: usize,
  /// One-past-the-last payload byte.
  payload_end: usize,
}

/// The outcome of reading one atom header.
enum HeaderOutcome {
  /// A parsed header plus the offset of the next sibling atom.
  Atom(AtomHeader, usize),
  /// A *contained* `size == 0` atom: QuickTime.pm:10036-10043 treats this as
  /// a TERMINATOR (Canon's CNTH trick) — the walk stops here with NO payload
  /// processed for this atom. **F5**: this branch is reached only when the
  /// header is being read inside a container (`top_level == false`); a
  /// top-level `size == 0` instead extends to EOF as an [`ExtendsToEof`]
  /// terminator (R4/F1).
  ///
  /// [`ExtendsToEof`]: HeaderOutcome::ExtendsToEof
  Terminator,
  /// A TOP-LEVEL `size == 0` atom (QuickTime.pm:10044-10056): the atom is
  /// declared to extend to end-of-file, but ExifTool **does NOT process its
  /// payload** — it prints "extends to end of file", records the synthetic
  /// `$tag-size`/`$tag-offset` tags **only if those tags exist in the table**
  /// (i.e. only for `mdat`, QuickTime.pm:689-700), then `last` — STOPS the
  /// top-level walk entirely (R4/F1). Carries the atom type and the absolute
  /// payload start so the caller can synthesize `mdat-size`/`mdat-offset`. The
  /// payload itself (e.g. a `moov`'s `mvhd`) is never decoded.
  ExtendsToEof {
    atom_type: [u8; 4],
    payload_start: usize,
  },
  /// An atom whose 8-/16-byte header was fully read and whose declared size
  /// is valid (`>= 8`), but whose declared payload OVERRUNS the available
  /// data (`payload_end > data.len()`).
  ///
  /// **R6/F2.** ExifTool gates the format on the 4-byte `$tag` ALONE
  /// (QuickTime.pm:9984 `$$tagTablePtr{$tag} or return 0`) — the declared
  /// `$size` is not consulted by that gate. It then `SetFileType`s, records
  /// the synthetic `$tag-size`/`$tag-offset` from the DECLARED size BEFORE
  /// reading the payload (QuickTime.pm:10156-10158), and only afterwards does
  /// `$raf->Read($val,$size)` come up short and trigger the
  /// `Truncated '...' data` warning + `last` (QuickTime.pm:10238-10242). So a
  /// file whose first atom is a recognized top-level atom with an
  /// overrunning size is STILL QuickTime: the format is accepted, the file
  /// type finalized, `mdat` size/offset synthesized from the declared size,
  /// then the walk stops. Carries the type, the absolute payload start, and
  /// the DECLARED payload byte count (used for the synthetic `mdat-size`).
  ///
  /// **R12/F1.** `declared_payload_len` is a `u64` (not `usize`): with the
  /// default `LargeFileSupport => 1` (ExifTool.pm:1167) a `size == 1` 64-bit
  /// `mdat` may declare a payload `> 0x7fffffff` (a real >2GB video) or even
  /// `> 4GB` (`hi != 0`). ExifTool records the FULL 64-bit `$tag-size`
  /// (`$size = $hi*4294967296 + $lo - 16`, QuickTime.pm:10074) before the
  /// short read, so this carries the full 64-bit count — never a `usize`-
  /// truncated value (faithful on 32-bit platforms too).
  TruncatedAtom {
    atom_type: [u8; 4],
    payload_start: usize,
    declared_payload_len: u64,
  },
  /// An atom whose 8-byte tag/size header WAS read, but whose declared size
  /// is structurally invalid: a `size` in `2..=7` (`Invalid atom size`,
  /// QuickTime.pm:10058), a `size == 1` whose 8-byte extended-size header is
  /// truncated (`Truncated atom header`, QuickTime.pm:10059), a 64-bit size
  /// whose HIGH word alone exceeds `0x7fffffff` (`Invalid atom size`,
  /// QuickTime.pm:10064-10066), or an extended size `< 16` (`Invalid extended
  /// size`, QuickTime.pm:10075).
  ///
  /// **R12/F1.** The `not LargeFileSupport ⇒ 'End of processing at large
  /// atom'` branch (QuickTime.pm:10067-10069) is NOT reachable here:
  /// `LargeFileSupport` defaults to `1` (ExifTool.pm:1167) and the gen-golden
  /// config never disables it, so a merely-large 64-bit size (`hi == 0` with
  /// `lo > 0x7fffffff`, or any `hi <= 0x7fffffff`) is PARSED, not rejected.
  /// Only a genuinely out-of-range value (`hi > 0x7fffffff`) is `Malformed`.
  ///
  /// **R8/F1.** QuickTime.pm validates the declared size INSIDE the per-atom
  /// `for(;;)` loop (QuickTime.pm:10035-10075) — *after* the first-atom tag
  /// gate (QuickTime.pm:9984) and `SetFileType` (QuickTime.pm:9986-10012)
  /// have already run. So a file whose FIRST atom carries a recognized magic
  /// type but a structurally invalid size is STILL accepted as QuickTime:
  /// the type passes the gate, the file type is finalized, then the size
  /// check sets `$warnStr` and `last`s the walk. The first-atom TYPE is read
  /// directly from the raw 8-byte header by [`parse_inner`] (which never
  /// consults this outcome for recognition), so this variant only needs to
  /// carry the bundled `$warnStr` for the caller to surface.
  Malformed { warning: &'static str },
}

/// Read the atom header starting at `pos` within `data`. `top_level` is
/// QuickTime.pm's `$dataPt` distinction: `true` while walking the file's
/// top-level atom sequence (read from the RAF — `$dataPt` undef), `false`
/// while walking a *contained* directory buffer (`$dataPt` set). Returns the
/// outcome, or `None` when the header is truncated / the size is invalid
/// (faithful to QuickTime.pm's `last` branches — the walker simply stops).
fn read_atom_header(data: &[u8], pos: usize, top_level: bool) -> Option<HeaderOutcome> {
  // QuickTime.pm:9966 `$raf->Read($buff,8) == 8 or return 0`.
  if pos + 8 > data.len() {
    return None;
  }
  // QuickTime.pm:9973 `($size, $tag) = unpack('Na4', $buff)`. The `pos + 8 >
  // len` guard proves both reads succeed (the bounds-checking `be_u32` returns
  // `Some` here); `?` on the impossible miss returns `None`, matching the guard.
  let size32 = be_u32(data, pos)?;
  let atom_type: [u8; 4] = data.get(pos + 4..pos + 8)?.try_into().ok()?;

  // QuickTime.pm:10035-10078: resolve the three special-size cases.
  let (payload_start, payload_end): (usize, usize) = if size32 == 0 {
    // QuickTime.pm:10036-10056: `$size == 0`.
    if top_level {
      // QuickTime.pm:10044-10056: a top-level zero-size atom extends to EOF
      // but its payload is NOT processed — ExifTool records the synthetic
      // `$tag-size`/`$tag-offset` (only for `mdat`, the lone table entry with
      // those tags, QuickTime.pm:689-700) then `last` to STOP the walk (R4/F1).
      // Surface this as a distinct STOP outcome so the caller never decodes the
      // payload of a size-0 `moov`.
      return Some(HeaderOutcome::ExtendsToEof {
        atom_type,
        payload_start: pos + 8,
      });
    } else {
      // QuickTime.pm:10036-10043: a CONTAINED zero-size atom is a
      // terminator — stop the walk, no payload (F5).
      return Some(HeaderOutcome::Terminator);
    }
  } else if size32 == 1 {
    // QuickTime.pm:10058-10075: extended 64-bit size follows the type.
    if pos + 16 > data.len() {
      // QuickTime.pm:10059 `$raf->Read($buff,8) == 8 or $warnStr =
      // 'Truncated atom header', last`. The 8-byte tag/size header WAS read,
      // so the type is known — surface a Malformed outcome (R8/F1) so the
      // first-atom caller still recognizes the format.
      return Some(HeaderOutcome::Malformed {
        warning: "Truncated atom header",
      });
    }
    // The `pos + 16 > len` guard above proves both 32-bit reads are in range;
    // `be_u32` returns `Some` here, so `?` is byte-identical to the raw read.
    let hi = be_u32(data, pos + 8)?;
    let lo = be_u32(data, pos + 12)?;
    // QuickTime.pm:10062-10071. **R12/F1.** ExifTool guards a `size == 1`
    // 64-bit size as:
    //
    // ```perl
    // if ($hi or $lo > 0x7fffffff) {
    //     if ($hi > 0x7fffffff) { $warnStr = 'Invalid atom size'; last; }
    //     elsif (not $et->Options('LargeFileSupport')) {
    //         $warnStr = 'End of processing at large atom ...'; last;
    //     } elsif ($et->Options('LargeFileSupport') eq '2') { ...warn... }
    // }
    // ```
    //
    // `LargeFileSupport` DEFAULTS to `1` (ExifTool.pm:1167 `[ 'LargeFileSupport',
    // 1, ... ]`) and the gen-golden config never disables it, so:
    //   * `hi > 0x7fffffff` ⇒ `Invalid atom size` (the lone truly-invalid case);
    //   * the `not LargeFileSupport` and `eq '2'` branches are DEAD under the
    //     default ⇒ a merely-large 64-bit size is PARSED and the walk continues.
    // This is the bug R12/F1 fixes: real >2GB videos commonly carry a `size == 1`
    // 64-bit `mdat` (`lo > 0x7fffffff`, sometimes `hi != 0`) before a trailing
    // `moov`; the walker MUST skip it by its declared size to reach that `moov`.
    if hi > 0x7fff_ffff {
      // QuickTime.pm:10064-10066: high word alone overflows int31 ⇒ a size that
      // cannot be a valid 63-bit-ish QuickTime offset. Bundled `Invalid atom size`.
      return Some(HeaderOutcome::Malformed {
        warning: "Invalid atom size",
      });
    }
    let ext = (u64::from(hi) << 32) | u64::from(lo);
    // QuickTime.pm:10074 `$size = $hi*4294967296 + $lo - 16`; :10075
    // `$size < 0 ⇒ 'Invalid extended size'`.
    if ext < 16 {
      return Some(HeaderOutcome::Malformed {
        warning: "Invalid extended size",
      });
    }
    // The DECLARED 64-bit payload byte count (`$size`). Kept as `u64` so the
    // synthetic `mdat-size` is faithful even when it exceeds the in-memory
    // buffer (a real >2GB `mdat`) or, on a 32-bit target, `usize`.
    let declared = ext - 16;
    let start = pos + 16;
    // Resolve the payload to an in-buffer range. Three things make the declared
    // payload UNREPRESENTABLE in this in-memory buffer model — all of which are
    // the SAME ExifTool outcome (the `$raf->Read($val,$size)` short read ⇒
    // `Truncated '...' data`), NOT the LargeFileSupport stop:
    //   * `declared` exceeds `usize` (only possible on a 32-bit target);
    //   * `start + declared` overflows `usize`;
    //   * `start + declared` runs past the actual input length.
    // In every such case surface a `TruncatedAtom` carrying the FULL 64-bit
    // declared count (so `mdat-size` is the faithful `$size`), letting the
    // top-level caller still recognize the format and record `mdat`
    // size/offset before stopping (QuickTime.pm:10156-10158, 10238-10242).
    let fits = usize::try_from(declared)
      .ok()
      .and_then(|p| start.checked_add(p))
      .filter(|&end| end <= data.len());
    match fits {
      Some(end) => (start, end),
      None => {
        return Some(HeaderOutcome::TruncatedAtom {
          atom_type,
          payload_start: start,
          declared_payload_len: declared,
        });
      }
    }
  } else if size32 < 8 {
    // QuickTime.pm:10058 `$size == 1 or $warnStr = 'Invalid atom size'`. The
    // 8-byte header WAS read (a recognized magic type for the first atom is
    // already determined) — surface a Malformed outcome rather than `None`
    // so a structurally-invalid first-atom size still finalizes the format
    // (R8/F1).
    return Some(HeaderOutcome::Malformed {
      warning: "Invalid atom size",
    });
  } else {
    // QuickTime.pm:10077 `$size -= 8` — normal atom. A 32-bit `$size` is at
    // most ~4GB, so the payload fits `usize` on every supported target.
    let payload = size32 as usize - 8;
    let start = pos + 8;
    let end = start.checked_add(payload)?;
    if end > data.len() {
      // R6/F2: header fully read, declared payload overruns EOF ('Truncated
      // data'). Surface a TruncatedAtom — the top-level caller recognizes the
      // format on the 4-byte tag and finalizes the file type before stopping.
      return Some(HeaderOutcome::TruncatedAtom {
        atom_type,
        payload_start: start,
        declared_payload_len: payload as u64,
      });
    }
    (start, end)
  };
  Some(HeaderOutcome::Atom(
    AtomHeader {
      atom_type,
      payload_start,
      payload_end,
    },
    payload_end,
  ))
}

/// March the TOP-LEVEL atom sequence by DECLARED size to reproduce ExifTool's
/// in-loop trailer stop (QuickTime.pm:10597-10602) and return
/// `(last_pos, box_region_end)`:
///
///  - **`last_pos`** — the file offset one-past the LAST COMPLETE atom (= Perl
///    `$lastPos`, updated only at the BOTTOM of the `for(;;)` loop after an atom
///    is fully handled). An atom that aborts the walk mid-loop (a declared size
///    that overruns EOF ⇒ a short read; a structurally invalid size) does NOT
///    advance it (Perl `last`s before the `$lastPos = Tell()` update). This is
///    the value the trailer-processing loop compares against each trailer's
///    start (`next if $lastPos > $$trailer[1]`, :10656) — i.e. exifast's
///    Insta360 EXTRACTION gate.
///  - **`box_region_end`** — the furthest file offset the box walk's atom READS
///    reach: the max over every processed atom's declared end, clamped to EOF
///    (a truncated/overrunning atom reads only the bytes available before EOF).
///    This bounds the box view (`scan_data`) + every downstream box-region scan
///    so the trailer's bytes are never mis-read as a top-level atom in the
///    normal case, yet a legitimately-spanning atom is read in full.
///
/// `head_signed_start` is the EARLIEST trailer's SIGNED start (`$$trailer[1]`):
/// `Some(start)` stops the march after the atom whose end reaches `start` (a
/// NEGATIVE bad-size start stops after the very first atom, since any real
/// `last_pos >= 0 > start`); `None` (no trailer) marches to natural end and
/// returns `box_region_end == data.len()`.
fn box_walk_extent(data: &[u8], head_signed_start: Option<i64>) -> (usize, usize) {
  // No trailer: the box region is the whole file (the downstream scans see all
  // of `data`, byte-identical to the pre-FIX behaviour).
  let Some(trailer_start) = head_signed_start else {
    return (0, data.len());
  };
  let mut pos = 0usize;
  let mut last_pos = 0usize;
  let mut box_region_end = 0usize;
  loop {
    match read_atom_header(data, pos, true) {
      Some(HeaderOutcome::Atom(header, next)) => {
        // This atom is fully present in `data`; its reads reach `payload_end`.
        box_region_end = box_region_end.max(header.payload_end);
        last_pos = next;
        // QuickTime.pm:10598-10602 — after a COMPLETE atom, stop if the cursor
        // reached the trailer. The SIGNED compare preserves the bad-size
        // (negative start ⇒ first-atom-only) behaviour.
        if (last_pos as i64) >= trailer_start {
          break;
        }
        if next <= pos {
          break; // hostile non-advancing size
        }
        pos = next;
      }
      Some(HeaderOutcome::TruncatedAtom { .. }) => {
        // QuickTime.pm:10238-10242 / 10585-10591 — the atom's declared payload
        // overruns EOF: ExifTool reads only the available bytes (to EOF) and
        // `last`s with a truncation warning WITHOUT updating `$lastPos`. So the
        // box reads reach EOF, but `last_pos` stays at the previous complete
        // atom (so a trailer the walk did NOT pass is still extracted).
        box_region_end = data.len();
        break;
      }
      // A top-level size-0 atom (`ExtendsToEof`) extends to EOF and STOPS the
      // walk (QuickTime.pm:10044-10056); a structurally invalid size
      // (`Malformed`) sets `$warnStr` and `last`s (:10058-10075). Either way the
      // walk ends here; the box view reaches EOF and `last_pos` is unchanged.
      Some(HeaderOutcome::ExtendsToEof { .. } | HeaderOutcome::Malformed { .. }) => {
        box_region_end = data.len();
        break;
      }
      Some(HeaderOutcome::Terminator) | None => break,
    }
  }
  (last_pos, box_region_end)
}

/// Format the `Truncated '...' data (missing N bytes)` warning for a contained
/// atom whose header was read but whose declared payload overruns the
/// available data (QuickTime.pm:10242 — `$missing = $size - $raf->Read(...)`).
/// A contained atom is never pre-read, so `missing` is the declared payload
/// minus the bytes still available before the buffer end.
fn truncated_atom_warning(
  atom_type: &[u8; 4],
  payload_start: usize,
  declared: u64,
  end: usize,
) -> String {
  // `declared` is the full 64-bit `$size` (R12/F1), so compute the shortfall in
  // u64 — a contained >2GB atom's `missing` count must not wrap a 32-bit math.
  let available = end.saturating_sub(payload_start) as u64;
  let missing = declared.saturating_sub(available);
  let tag = String::from_utf8_lossy(atom_type).into_owned();
  std::format!("Truncated '{tag}' data (missing {missing} bytes)")
}

/// The QuickTime atom 4-CCs ExifTool's `%QuickTime::*` tables recognize (every
/// 4-byte key across all QuickTime container/leaf tables, snapshotted from
/// bundled 13.59), encoded big-endian as `u32` and SORTED for binary search.
/// Drives the truncation-warning FORMAT only (see [`contained_truncation_warning`]):
/// an overrunning atom whose type is in a table takes ExifTool's READ path
/// (`Truncated '..' data (missing N bytes)`, QuickTime.pm:10242), while an
/// UNKNOWN type (no `GetTagInfo`, Unknown option off) takes the SKIP path
/// (`Truncated '..' data at offset 0x%x`, QuickTime.pm:10590). The `\xa9`-prefixed
/// (`©…`) UserData atoms are included: ExifTool synthesizes a tagInfo for them
/// (QuickTime.pm:10138-10142), so they too take the READ path.
#[rustfmt::skip]
const RECOGNIZED_QT_ATOMS: [u32; 521] = [
  0x2d2d2d2d, 0x32312e31, 0x32312e32, 0x33676620, 0x40505354, 0x40646179, 0x406d616b, 0x406d6f64, 0x40707069, 0x40707469,
  0x40736563, 0x40737469, 0x40737772, 0x4078797a, 0x41414352, 0x41505246, 0x416c6c46, 0x43414d45, 0x4344454b, 0x43444554,
  0x43444931, 0x434d5031, 0x434e4356, 0x434e4656, 0x434e4d4e, 0x434e4f50, 0x434e5448, 0x44634d44, 0x46464d56, 0x4649524d,
  0x464f5600, 0x46505246, 0x47504d46, 0x47505320, 0x47554944, 0x476f5072, 0x49444954, 0x494e464f, 0x4a504547, 0x4c454943,
  0x4c454e53, 0x4c4f4f50, 0x4c766c6d, 0x4d4d4130, 0x4d4d4131, 0x4d4f4f44, 0x4d544454, 0x4d554944, 0x4d565447, 0x4e424344,
  0x4e434454, 0x4f4c594d, 0x50414e41, 0x50454e54, 0x50494354, 0x50584d4e, 0x50585448, 0x51564d49, 0x52445441, 0x52445442,
  0x52445443, 0x52445447, 0x5244544c, 0x5249434f, 0x524d4b4e, 0x52544855, 0x52544f53, 0x53413344, 0x53444c4e, 0x5345414c,
  0x5349474d, 0x534e756d, 0x53656c4f, 0x54414753, 0x5449504c, 0x54544144, 0x5454484c, 0x54544944, 0x54544d44, 0x54545644,
  0x54545649, 0x56415253, 0x56455253, 0x56505246, 0x574c4f43, 0x584d505f, 0x58747261, 0x5f63785f, 0x5f63795f, 0x5f687463,
  0x5f796177, 0x61415254, 0x61627274, 0x61636266, 0x61636566, 0x61647a63, 0x61647a65, 0x61647a6d, 0x616b4944, 0x616c626d,
  0x616c6272, 0x616e676c, 0x61704944, 0x61706d64, 0x61726474, 0x61744944, 0x61757468, 0x61757843, 0x6175786c, 0x61763143,
  0x61766343, 0x61766572, 0x62726174, 0x62746563, 0x62747274, 0x62786d6c, 0x63616d6d, 0x63617467, 0x63626d70, 0x63636964,
  0x63646376, 0x63646973, 0x63647363, 0x63657274, 0x6368616e, 0x63686170, 0x6368706c, 0x63697473, 0x636c6170, 0x636c6370,
  0x636c6566, 0x636c666e, 0x636c6964, 0x636c6c69, 0x636c7366, 0x636d4944, 0x636d6964, 0x636d6e63, 0x636d6e6d, 0x636d6f76,
  0x636e4944, 0x636f3634, 0x636f6c6c, 0x636f6c72, 0x636f7672, 0x6370696c, 0x63707274, 0x63726563, 0x63736c67, 0x63746278,
  0x63747473, 0x63757374, 0x63766572, 0x63767275, 0x64616d72, 0x64617461, 0x64617465, 0x64636f6d, 0x64657363, 0x64696d67,
  0x64696d6d, 0x64696e66, 0x6469736b, 0x646d6178, 0x646d6564, 0x64726566, 0x64726570, 0x64736370, 0x65676964, 0x656c6e67,
  0x656e6461, 0x656e6f66, 0x65717569, 0x66616c6c, 0x6669656c, 0x66696e6d, 0x666f6c77, 0x666f7263, 0x66726561, 0x66726565,
  0x66726d61, 0x66736964, 0x66746162, 0x66747970, 0x67616d61, 0x67646174, 0x67654944, 0x676d6864, 0x676d696e, 0x676e7265,
  0x67707320, 0x67707330, 0x6772706c, 0x67727570, 0x6773656e, 0x67736868, 0x6773706d, 0x67737075, 0x67737364, 0x67737374,
  0x67737464, 0x68646c72, 0x68647664, 0x68696e66, 0x68696e76, 0x686d6864, 0x686e7469, 0x68746362, 0x68746b61, 0x68766343,
  0x69636e75, 0x69646174, 0x69647363, 0x69696363, 0x69696e66, 0x696c6f63, 0x696c7374, 0x696d6972, 0x696e6665, 0x696e6669,
  0x696e666f, 0x696e6675, 0x696e6974, 0x696e7374, 0x696f6473, 0x6970636f, 0x69706d61, 0x69706d63, 0x6970726f, 0x69707270,
  0x69726566, 0x69726f74, 0x69737065, 0x69746e75, 0x69766976, 0x6a756e6b, 0x6b657920, 0x6b657973, 0x6b657977, 0x6b666978,
  0x6b677474, 0x6b737462, 0x6b766172, 0x6b797764, 0x6c646573, 0x6c6d7263, 0x6c6f6369, 0x6c726375, 0x6c766c6d, 0x6d616b65,
  0x6d616e75, 0x6d617872, 0x6d637672, 0x6d646174, 0x6d64656c, 0x6d646864, 0x6d646961, 0x6d65616e, 0x6d65636f, 0x6d656469,
  0x6d657265, 0x6d657461, 0x6d666864, 0x6d696e66, 0x6d6e6970, 0x6d6e6f70, 0x6d6f6465, 0x6d6f646c, 0x6d6f6f66, 0x6d6f6f76,
  0x6d706f64, 0x6d707664, 0x6d726c64, 0x6d726c68, 0x6d726c76, 0x6d766864, 0x6e61696c, 0x6e616d65, 0x6e626d74, 0x6e62706c,
  0x6e6d6864, 0x6e70636b, 0x6e756d70, 0x6f707072, 0x6f776e72, 0x70616430, 0x70616462, 0x70616b62, 0x70616b64, 0x70616b66,
  0x70617370, 0x70617974, 0x70637374, 0x70657266, 0x70676170, 0x70696374, 0x70696e66, 0x7069746d, 0x70697869, 0x706c4944,
  0x706c6174, 0x706d6178, 0x706d6363, 0x706e6f74, 0x706f7365, 0x70724944, 0x70726864, 0x70726d6d, 0x70726f66, 0x70726f6a,
  0x70727274, 0x70746368, 0x70746e6d, 0x70747268, 0x70747620, 0x70757264, 0x7075726c, 0x72616473, 0x72617465, 0x7265656c,
  0x72696768, 0x726c6474, 0x726c6f63, 0x726f6c6c, 0x72746e67, 0x72747020, 0x73626770, 0x7362746c, 0x7363656e, 0x73636869,
  0x7363686d, 0x73637074, 0x7363726e, 0x73646573, 0x73647020, 0x73647064, 0x73647470, 0x73656664, 0x73657475, 0x73664944,
  0x73677064, 0x73686f74, 0x7368776d, 0x73696e66, 0x736b6970, 0x736c6d74, 0x736c6e6f, 0x736d6864, 0x736d7461, 0x736e616c,
  0x736e726f, 0x736f6161, 0x736f616c, 0x736f6172, 0x736f636f, 0x736f6e67, 0x736f6e6d, 0x736f736e, 0x736f756e, 0x73726371,
  0x73737263, 0x73743364, 0x7374626c, 0x7374636f, 0x73746470, 0x7374696b, 0x73747073, 0x73747363, 0x73747364, 0x73747368,
  0x73747373, 0x7374737a, 0x7374746d, 0x73747473, 0x73747a32, 0x73756273, 0x73763364, 0x73766864, 0x73796e63, 0x74616773,
  0x74617074, 0x74627566, 0x74636d69, 0x74657874, 0x74686d20, 0x74686d61, 0x74686d62, 0x7468756d, 0x74696d65, 0x74696d73,
  0x7469746c, 0x746b6864, 0x746d6178, 0x746d6364, 0x746d696e, 0x746d706f, 0x746e616c, 0x746e616d, 0x746f6f6c, 0x746f746c,
  0x74706159, 0x74706179, 0x7470796c, 0x74726166, 0x7472616b, 0x7472616e, 0x74726566, 0x74726b6e, 0x74727059, 0x74727079,
  0x7473726f, 0x7476656e, 0x74766573, 0x74766e6e, 0x74767368, 0x7476736e, 0x75627566, 0x75646174, 0x75647461, 0x75726174,
  0x75726c00, 0x75726c20, 0x75726e20, 0x75727372, 0x75736572, 0x75756964, 0x76627271, 0x76654944, 0x76657220, 0x76657273,
  0x76696465, 0x766d6864, 0x766e6472, 0x76706b3f, 0x76726f74, 0x77617665, 0x77696465, 0x78696420, 0x786d6c20, 0x79656172,
  0x79727263, 0xa9415254, 0xa954494d, 0xa9545343, 0xa954535a, 0xa9616c62, 0xa9617264, 0xa9617267, 0xa961726b, 0xa9617574,
  0xa9636d74, 0xa9636f6b, 0xa9636f6d, 0xa9636f6e, 0xa9637079, 0xa9646179, 0xa9646573, 0xa9646972, 0xa9646a69, 0xa9656431,
  0xa9656432, 0xa9656433, 0xa9656434, 0xa9656435, 0xa9656436, 0xa9656437, 0xa9656438, 0xa9656439, 0xa9656e63, 0xa9666d74,
  0xa9667074, 0xa966726c, 0xa9667977, 0xa967656e, 0xa9677074, 0xa967726c, 0xa9677270, 0xa9677977, 0xa9696e66, 0xa9697372,
  0xa96c6162, 0xa96c616c, 0xa96c7972, 0xa96d616b, 0xa96d616c, 0xa96d646c, 0xa96d6f64, 0xa96d7663, 0xa96d7669, 0xa96d766e,
  0xa96e616d, 0xa96e7274, 0xa96f7065, 0xa970646b, 0xa9706867, 0xa9707264, 0xa9707266, 0xa970726b, 0xa970726c, 0xa9707562,
  0xa9726571, 0xa9726573, 0xa9736e65, 0xa9736e6b, 0xa9736e6d, 0xa9736f6c, 0xa9737263, 0xa9737433, 0xa9737766, 0xa973776b,
  0xa9737772, 0xa9746f6f, 0xa974726b, 0xa9756964, 0xa977726b, 0xa9777274, 0xa9787064, 0xa9787370, 0xa978797a, 0xa9797370,
  0xa97a7370,
];

/// `true` iff `atom_type` is a known `%QuickTime::*` atom — i.e. ExifTool's
/// `GetTagInfo` would return a tagInfo for it (with the Unknown option off) and
/// take the READ path on a truncation. See [`RECOGNIZED_QT_ATOMS`].
#[inline]
fn is_recognized_qt_atom(atom_type: &[u8; 4]) -> bool {
  RECOGNIZED_QT_ATOMS
    .binary_search(&u32::from_be_bytes(*atom_type))
    .is_ok()
}

/// Format the truncation warning for a CONTAINED atom that overruns its
/// container, choosing ExifTool's two distinct messages by atom recognition:
///  - a RECOGNIZED atom (a `%QuickTime::*` table key) takes the READ path
///    (`$raf->Read($val,$size)` short read) ⇒
///    `Truncated '..' data (missing N bytes)` (QuickTime.pm:10242);
///  - an UNKNOWN atom (no `GetTagInfo`, Unknown off) takes the SKIP path
///    (`Seek($seekTo-1)` fails) ⇒ `Truncated '..' data at offset 0x%x`
///    (QuickTime.pm:10590), where the offset is `$lastPos` — the atom's START
///    file offset = `file_base + header_pos`.
///
/// `header_file_offset` is the absolute file offset of this atom's 8-byte header
/// (`file_base + pos`); `payload_start`/`end` are buffer-relative (for the
/// `missing` byte count). Verified vs bundled 13.59 (`Truncated 'udta' data
/// (missing …)` for a known atom, `Truncated 'ZZZZ' data at offset 0x..` /
/// `Truncated 'SE12' data at offset 0x8c` for unknown ones).
fn contained_truncation_warning(
  atom_type: &[u8; 4],
  header_file_offset: usize,
  payload_start: usize,
  declared: u64,
  end: usize,
) -> String {
  if is_recognized_qt_atom(atom_type) {
    truncated_atom_warning(atom_type, payload_start, declared, end)
  } else {
    let tag = String::from_utf8_lossy(atom_type).into_owned();
    std::format!("Truncated '{tag}' data at offset {header_file_offset:#x}")
  }
}

/// `true` when the header at `pos` is the directory's BARE trailing 8-byte
/// header — i.e. a prior atom was already walked (`pos > start`) and exactly
/// the 8-byte header remains before the container end (`end - pos == 8`).
///
/// ExifTool's contained `ProcessMOV` loop validates an atom's `size` only
/// AFTER its bottom-of-loop guard reads the next header; when the previous
/// atom advanced `$dataPos` to within 8 bytes of `$dirEnd`, the trailing 8
/// bytes are consumed as the loop terminator (`last if $dataPos >= $dirEnd` /
/// the short next-header read), NEVER reaching the `$size < 8` / overrun check.
/// So a bare trailing header carrying a structurally-invalid or overrunning
/// `size` word emits NO warning (verified vs bundled 13.59 across `size`
/// `0..=7`, `size == 1` truncated-extended, and a `>EOF` size). The FIRST atom
/// (`pos == start`) IS validated (it is read before the loop body, so an
/// invalid first-atom size still warns), and a trailing header WITH a body
/// (`end - pos > 8`) is a real over-/under-sized atom that ExifTool reads and
/// warns on — both excluded here. This only suppresses a spurious warning on
/// malformed input; a well-formed directory never ends on a bare malformed
/// header, so the happy path is byte-identical.
///
/// The SAME rule applies to a *valid* bare trailing header (`size == 8`, a
/// header-only atom with a zero-length body): ExifTool's `last if $dataPos >=
/// $dirEnd` (QuickTime.pm:10597, "ignores last value if 0 bytes") fires on the
/// preceding atom's advance, so the trailing 0-byte atom is never read and
/// emits NO tag either. The `walk_atoms` `Atom` arm checks this predicate
/// (plus an empty-body assertion) to skip dispatching such an atom.
#[inline]
fn is_bare_trailing_header(pos: usize, start: usize, end: usize) -> bool {
  pos > start && end.saturating_sub(pos) == 8
}

/// Iterate the *contained* sibling atoms in `data[start..end]` (a directory
/// buffer — QuickTime.pm `$dataPt` set), invoking `f` for each. Stops on the
/// first malformed/truncated header OR a contained `size == 0` terminator
/// (faithful to `ProcessMOV`'s `last`).
///
/// **R7/F2 + R9/F2.** A contained malformed header is NOT silently dropped:
/// ExifTool's `ProcessMOV` runs the same per-atom loop on the directory
/// buffer, so BOTH a `TruncatedAtom` (a header-valid atom whose declared
/// payload overruns the container ⇒ `Truncated '...' data`) AND a `Malformed`
/// header (an invalid `size` 2-7 / truncated extended-size header / invalid
/// extended size ⇒ `Invalid atom size` etc.) inside moov/trak/mdia still set
/// `$warnStr` and emit the warning before the `last`. The first such warning
/// is recorded into `warning` (first-wins, threaded through nested walks).
///
/// `depth` is the recursion budget (Golden-v2 Contract 3a): a `walk_atoms`
/// re-entered from inside another `walk_atoms`/`walk_trak` closure passes the
/// enclosing `depth + 1`; the top-level/entry walks pass `0`. When `depth`
/// reaches [`MAX_ATOM_DEPTH`] the walk stops, bounding stack use on a hostile
/// file with no effect on real media (whose nesting is single-digit, far below
/// the cap — so the output is byte-identical).
fn walk_atoms(
  depth: u32,
  data: &[u8],
  start: usize,
  end: usize,
  warning: &mut Option<String>,
  f: impl FnMut(&AtomHeader, &[u8], &mut Option<String>),
) {
  walk_atoms_based(depth, data, 0, start, end, warning, f);
}

/// Like [`walk_atoms`] but carries `file_base` — the absolute file offset of
/// `data[0]` — so the SKIP-path truncation warning of an UNKNOWN contained atom
/// can report its FILE offset (`Truncated '..' data at offset 0x%x`, where the
/// offset is `file_base + pos`; see [`contained_truncation_warning`]). Entry
/// decoders that walk a sub-slice of the file pass that slice's file offset;
/// the public [`walk_atoms`] (sub-slices already file-offset-agnostic, or
/// warning-discarding scans) passes `0`. Nested re-entries pass
/// `file_base + inner.payload_start` so the offset stays absolute through depth.
fn walk_atoms_based(
  depth: u32,
  data: &[u8],
  file_base: usize,
  start: usize,
  end: usize,
  warning: &mut Option<String>,
  mut f: impl FnMut(&AtomHeader, &[u8], &mut Option<String>),
) {
  // Golden-v2 3a — recursion-depth guard. Real QuickTime nesting is
  // single-digit (`moov`→`trak`→`mdia`→`minf`→…); `MAX_ATOM_DEPTH` is a
  // superset, so this never trips on a real file (byte-identical output) but
  // caps stack growth on a maliciously deep box tree (a stack-overflow DoS).
  if depth >= MAX_ATOM_DEPTH {
    return;
  }
  let mut pos = start;
  while pos < end {
    match read_atom_header(data, pos, false) {
      Some(HeaderOutcome::Atom(header, next)) => {
        // A BARE trailing 8-byte header carrying a VALID `size == 8` (a
        // header-only atom with a ZERO-length body) after ≥1 already-walked
        // atom is NOT processed by ExifTool: the *preceding* atom's
        // `$dataPos += $size + 8` advances `$dataPos` to exactly `$dirEnd`, so
        // `last if $dataPos >= $dirEnd` (QuickTime.pm:10597, commented "ignores
        // last value if 0 bytes") fires BEFORE the bottom-of-loop next-header
        // read — the trailing 8 bytes are never read as an atom and no tag is
        // emitted. Verified vs bundled 13.59: a `udta(©mak, <bare size-8
        // CAME>)` yields `Make` but NO `SerialNumberHash`, whereas the same
        // `CAME` with ANY body byte DOES emit it. `is_bare_trailing_header`
        // already encodes "post-first (`pos > start`) with exactly the 8-byte
        // remainder (`end - pos == 8`)"; for a non-overrunning `Atom` that
        // implies `size == 8` ⇒ an empty body (`payload_start == payload_end`),
        // asserted here so a FIRST atom or a NON-trailing empty atom is
        // unaffected — only the LAST, empty, non-first atom is skipped,
        // matching `last if $dataPos >= $dirEnd`. The malformed/truncated
        // trailing-header arms below carry the same rule for invalid sizes.
        if is_bare_trailing_header(pos, start, end) && header.payload_start == header.payload_end {
          break;
        }
        // Clamp the payload to the parent's declared end (a child must not
        // overrun its container).
        if header.payload_end > end {
          // For a well-formed tree `payload_start <= end <= data.len()`, so
          // `.get` is `Some` and this is byte-identical; a hostile header that
          // overruns its parent yields an empty payload here (no-panic).
          f(
            &header,
            data.get(header.payload_start..end).unwrap_or_default(),
            warning,
          );
          break;
        }
        f(
          &header,
          data
            .get(header.payload_start..header.payload_end)
            .unwrap_or_default(),
          warning,
        );
        if next <= pos {
          break; // never advance backwards (hostile size)
        }
        pos = next;
      }
      Some(HeaderOutcome::TruncatedAtom {
        atom_type,
        payload_start,
        declared_payload_len,
      }) => {
        // R7/F2: a contained atom whose header was read but whose declared
        // payload overruns EOF — surface the same `Truncated '...' data`
        // warning the top-level loop emits, then stop (`last`).
        //
        // …UNLESS it is a BARE trailing 8-byte header after ≥1 already-walked
        // atom (see [`is_bare_trailing_header`]): ExifTool treats the final 8
        // bytes of a directory as a non-atom (the loop's `last if $dataPos >=
        // $dirEnd` / short next-header read fires BEFORE the size check), so a
        // size word that would overrun is NEVER validated there. Verified vs
        // bundled 13.59: `moov(mvhd, <size=200 'free' bare header>)` emits NO
        // warning, whereas the same with ANY body byte emits `Truncated …`.
        if is_bare_trailing_header(pos, start, end) {
          break;
        }
        warning.get_or_insert_with(|| {
          // ExifTool picks two distinct truncation messages by atom recognition:
          // a `%QuickTime::*` table atom → READ path `(missing N bytes)`; an
          // UNKNOWN atom → SKIP path `at offset 0x%x` (the atom's START file
          // offset = `file_base + pos`). See `contained_truncation_warning`.
          contained_truncation_warning(
            &atom_type,
            file_base + pos,
            payload_start,
            declared_payload_len,
            end,
          )
        });
        break;
      }
      Some(HeaderOutcome::Malformed { warning: w }) => {
        // Same directory-boundary rule as `TruncatedAtom`: a structurally
        // invalid size in a BARE trailing 8-byte header after a prior atom is
        // the directory's end to ExifTool, not a validated atom — so it emits
        // no warning. Verified vs bundled 13.59: `moov(mvhd, <size in 1..=7,
        // bare header>)` ⇒ NONE; a FIRST such atom (`pos == start`) or one with
        // a body (`end - pos > 8`) still warns (the existing first-atom +
        // mid-stream tests). Must run BEFORE the `get_or_insert` below.
        if is_bare_trailing_header(pos, start, end) {
          break;
        }
        // R9/F2: a CONTAINED atom whose 8-byte tag/size header WAS read but
        // whose declared size is structurally invalid — a `size` in `2..=7`
        // (`Invalid atom size`), a `size == 1` with a truncated 8-byte
        // extended-size header (`Truncated atom header`), a 64-bit `size`
        // whose high word alone exceeds `0x7fffffff` (`Invalid atom size`,
        // R12/F1 — a merely-large 64-bit size is PARSED, not malformed), or an
        // extended size `< 16` (`Invalid extended size`).
        // ExifTool runs the SAME `ProcessMOV` per-atom `for(;;)` loop on a
        // contained directory buffer (`$dataPt` set, QuickTime.pm:10035-
        // 10075), so the size check sets `$warnStr` and `last`s here exactly
        // as it does at the top level — `$warnStr` is then emitted by the
        // `$et->Warn` at the directory's exit (attributed to the enclosing
        // family-1 group: `ExifTool:Warning` for a `moov`-level directory, a
        // `Track#:Warning` for a `trak`-level one — the threaded `warning`
        // slot is the one `walk_trak` / `decode_moov_*` passed in). Previously
        // `walk_atoms` grouped this with the size-0 terminator and broke
        // SILENTLY, dropping the warning. First-wins, like every other slot.
        warning.get_or_insert_with(|| w.to_string());
        break;
      }
      // A contained size-0 terminator (`Terminator`, the Canon CNTH trick),
      // a truncated header or `None`: stop with no warning. `ExtendsToEof` is
      // unreachable here — `read_atom_header(.., top_level=false)` surfaces a
      // contained size-0 atom as `Terminator`, never `ExtendsToEof` — so this
      // arm is purely defensive (mirrors `parse_inner`'s defensive
      // `Terminator` arm, which is the converse top-level-only unreachable).
      Some(HeaderOutcome::ExtendsToEof { .. } | HeaderOutcome::Terminator) | None => break,
    }
  }
}

// ── Big-endian field readers ─────────────────────────────────────────────

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  Some(u64::from_be_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

// ===========================================================================
// Conversions (QuickTime.pm timeInfo / durationInfo / hdlr PrintConv)
// ===========================================================================

/// `timeInfo` RawConv + ValueConv + PrintConv (QuickTime.pm:243-294, 1359-
/// 1371). Decodes a QuickTime epoch second-count to the displayed date
/// string.
///
/// The conformance goldens are generated with `-api QuickTimeUTC=1` (the
/// `tools/gen_golden.sh` `COMMON` set) AND `TZ=UTC`. With QuickTimeUTC the
/// RawConv ALWAYS subtracts the 1904→1970 offset (QuickTime.pm:1362
/// `$val >= $offset or $$self{OPTIONS}{QuickTimeUTC}`), and the
/// ValueConv passes `$toLocal = QuickTimeUTC` truthy to `ConvertUnixTime`
/// (QuickTime.pm:280). Under `TZ=UTC`, `localtime == gmtime`, so
/// `TimeZoneString` (ExifTool.pm:6795) yields `"+00:00"` — the suffix the
/// bundled output carries. This port reproduces that exact pinned-TZ
/// behaviour: subtract the offset unconditionally and append `+00:00`.
///
/// A RAW zero is NOT dropped: the timeInfo RawConv only `undef`s a zero date
/// under the `StrictDate` option (QuickTime.pm:265-266 `undef $val if
/// $self->Options('StrictDate')`), which is unimplemented here and is OFF in
/// the gen-golden config. With `StrictDate` off the zero passes through the
/// RawConv unchanged, then the ValueConv `ConvertUnixTime(0, …)` returns the
/// zero sentinel `"0000:00:00 00:00:00"` (ExifTool.pm:6776) — emitted by
/// CreateDate/ModifyDate/Track*Date/Media*Date. So `raw == 0` ⇒
/// `Some("0000:00:00 00:00:00")`, never `None` (F1).
fn qt_date_string(raw: u64) -> Option<String> {
  if raw == 0 {
    // QuickTime.pm:264-266 — StrictDate (unimplemented, off in gen-golden) is
    // the ONLY thing that drops a zero date; otherwise the ValueConv emits the
    // zero sentinel verbatim (no TZ suffix, ExifTool.pm:6776).
    return Some("0000:00:00 00:00:00".to_string());
  }
  // QuickTime.pm:1362 with QuickTimeUTC ⇒ always subtract the 1904→1970
  // offset (the value is interpreted as a UTC 1904-epoch timestamp).
  let unix = raw as i64 - QT_EPOCH_OFFSET;
  // ConvertUnixTime($val, $toLocal=1); $tz = TimeZoneString = "+00:00"
  // under the pinned TZ=UTC of gen_golden.sh (ExifTool.pm:6793-6798).
  let mut s = convert_datetime(&convert_unix_time(unix));
  // The zero sentinel "0000:00:00 00:00:00" never carries a TZ suffix
  // (ConvertUnixTime returns it before the $tz append, ExifTool.pm:6776).
  if s != "0000:00:00 00:00:00" {
    s.push_str("+00:00");
  }
  Some(s)
}

/// Faithful `Image::ExifTool::GetFixed32s` (ExifTool.pm:6121-6127): read a
/// big-endian `int32s`, divide by `0x10000` (16.16 fixed-point), then ROUND
/// to 5 decimal places to "remove insignificant digits":
/// `int($val * 1e5 + ($val>0 ? 0.5 : -0.5)) / 1e5`. This rounding is what
/// turns raw `0x00000001` (`1/65536 = 1.52587890625e-05`) into `2e-05`
/// rather than the full Rust float — it happens BEFORE the MatrixStructure
/// right-column `/0x4000` (so the right column carries the rounded value
/// divided by `0x4000`, NOT a re-rounded value).
fn get_fixed32s(raw: i32) -> f64 {
  let val = f64::from(raw) / 65536.0;
  // Perl `int()` truncates toward zero; `(val as i64)` matches for the
  // magnitudes reachable here (a 16.16 fixed32s is at most ~32768).
  let bias = if val > 0.0 { 0.5 } else { -0.5 };
  ((val * 1e5 + bias) as i64) as f64 / 1e5
}

/// QuickTime `fixed32s` / 16.16-fixed-point matrix `MatrixStructure`
/// ValueConv (QuickTime.pm:1404-1413, 1552-1565). The `Format =>
/// 'fixed32s[9]'` reads all 9 entries through [`get_fixed32s`] (so each is
/// the rounded 16.16 value), then the ValueConv splits `$val` and applies
/// `$_ /= 0x4000` to the right column (entries 2, 5, 8) which is stored as
/// 2.30 fixed-point. Returns the space-joined `"@a"` string, each entry
/// stringified with Perl's default `%.15g` NV stringification ([`format_g`],
/// e.g. `2e-05`, `1.220703125e-09`).
///
/// `payload[off..off+36]` holds 9 big-endian `int32s` (16.16). Returns
/// `None` if the slice is short.
fn matrix_structure_string(payload: &[u8], off: usize) -> Option<String> {
  let slice = payload.get(off..off + 36)?;
  let mut out = String::with_capacity(24);
  for i in 0..9 {
    // `slice` is 36 bytes and `i < 9`, so each 4-byte window `i*4..i*4+4`
    // is in range; `?` on the impossible miss is byte-identical.
    let arr: [u8; 4] = slice.get(i * 4..i * 4 + 4)?.try_into().ok()?;
    let raw = i32::from_be_bytes(arr);
    // Format 'fixed32s[9]' ⇒ GetFixed32s (divide by 0x10000 + 5-dp round).
    let mut v = get_fixed32s(raw);
    // ValueConv: the right column (2,5,8) is 2.30 ⇒ an extra / 0x4000,
    // applied to the already-rounded fixed32s value (QuickTime.pm:1410).
    if matches!(i, 2 | 5 | 8) {
      v /= 16384.0;
    }
    if i != 0 {
      out.push(' ');
    }
    // Perl interpolates the number into `"@a"` via default NV
    // stringification == sprintf("%.15g") (ExifTool.pm RoundFloat note).
    out.push_str(&format_g(v, 15));
  }
  Some(out)
}

/// `%ftypLookup` MajorBrand PrintConv table (QuickTime.pm:130-237). A plain
/// hash PrintConv: an exact-key hit returns the description; a miss yields
/// `None` (the caller emits `Unknown ($val)` per the hash-PrintConv default,
/// ExifTool.pm:3622). Keyed by the EXACT raw 4-byte brand (trailing spaces
/// significant — e.g. `"qt  "`, `"M4A "`).
fn ftyp_lookup(brand: &str) -> Option<&'static str> {
  Some(match brand {
    "3g2a" => "3GPP2 Media (.3G2) compliant with 3GPP2 C.S0050-0 V1.0",
    "3g2b" => "3GPP2 Media (.3G2) compliant with 3GPP2 C.S0050-A V1.0.0",
    "3g2c" => "3GPP2 Media (.3G2) compliant with 3GPP2 C.S0050-B v1.0",
    "3ge6" => "3GPP (.3GP) Release 6 MBMS Extended Presentations",
    "3ge7" => "3GPP (.3GP) Release 7 MBMS Extended Presentations",
    "3gg6" => "3GPP Release 6 General Profile",
    "3gp1" => "3GPP Media (.3GP) Release 1 (probably non-existent)",
    "3gp2" => "3GPP Media (.3GP) Release 2 (probably non-existent)",
    "3gp3" => "3GPP Media (.3GP) Release 3 (probably non-existent)",
    "3gp4" => "3GPP Media (.3GP) Release 4",
    "3gp5" => "3GPP Media (.3GP) Release 5",
    // Note: QuickTime.pm:142-144 defines '3gp6' three times; the last
    // assignment wins in a Perl hash (the Streaming Servers variant).
    "3gp6" => "3GPP Media (.3GP) Release 6 Streaming Servers",
    "3gs7" => "3GPP Media (.3GP) Release 7 Streaming Servers",
    "aax " => "Audible Enhanced Audiobook (.AAX)",
    "avc1" => "MP4 Base w/ AVC ext [ISO 14496-12:2005]",
    "CAEP" => "Canon Digital Camera",
    "caqv" => "Casio Digital Camera",
    "CDes" => "Convergent Design",
    "da0a" => "DMB MAF w/ MPEG Layer II aud, MOT slides, DLS, JPG/PNG/MNG images",
    "da0b" => "DMB MAF, extending DA0A, with 3GPP timed text, DID, TVA, REL, IPMP",
    "da1a" => "DMB MAF audio with ER-BSAC audio, JPG/PNG/MNG images",
    "da1b" => "DMB MAF, extending da1a, with 3GPP timed text, DID, TVA, REL, IPMP",
    "da2a" => "DMB MAF aud w/ HE-AAC v2 aud, MOT slides, DLS, JPG/PNG/MNG images",
    "da2b" => "DMB MAF, extending da2a, with 3GPP timed text, DID, TVA, REL, IPMP",
    "da3a" => "DMB MAF aud with HE-AAC aud, JPG/PNG/MNG images",
    "da3b" => "DMB MAF, extending da3a w/ BIFS, 3GPP timed text, DID, TVA, REL, IPMP",
    "dmb1" => "DMB MAF supporting all the components defined in the specification",
    "dmpf" => "Digital Media Project",
    "drc1" => "Dirac (wavelet compression), encapsulated in ISO base media (MP4)",
    "dv1a" => "DMB MAF vid w/ AVC vid, ER-BSAC aud, BIFS, JPG/PNG/MNG images, TS",
    "dv1b" => "DMB MAF, extending dv1a, with 3GPP timed text, DID, TVA, REL, IPMP",
    "dv2a" => "DMB MAF vid w/ AVC vid, HE-AAC v2 aud, BIFS, JPG/PNG/MNG images, TS",
    "dv2b" => "DMB MAF, extending dv2a, with 3GPP timed text, DID, TVA, REL, IPMP",
    "dv3a" => "DMB MAF vid w/ AVC vid, HE-AAC aud, BIFS, JPG/PNG/MNG images, TS",
    "dv3b" => "DMB MAF, extending dv3a, with 3GPP timed text, DID, TVA, REL, IPMP",
    "dvr1" => "DVB (.DVB) over RTP",
    "dvt1" => "DVB (.DVB) over MPEG-2 Transport Stream",
    "F4A " => "Audio for Adobe Flash Player 9+ (.F4A)",
    "F4B " => "Audio Book for Adobe Flash Player 9+ (.F4B)",
    "F4P " => "Protected Video for Adobe Flash Player 9+ (.F4P)",
    "F4V " => "Video for Adobe Flash Player 9+ (.F4V)",
    "isc2" => "ISMACryp 2.0 Encrypted File",
    "iso2" => "MP4 Base Media v2 [ISO 14496-12:2005]",
    "iso3" => "MP4 Base Media v3",
    "iso4" => "MP4 Base Media v4",
    "iso5" => "MP4 Base Media v5",
    "iso6" => "MP4 Base Media v6",
    "iso7" => "MP4 Base Media v7",
    "iso8" => "MP4 Base Media v8",
    "iso9" => "MP4 Base Media v9",
    "isom" => "MP4 Base Media v1 [IS0 14496-12:2003]",
    "JP2 " => "JPEG 2000 Image (.JP2) [ISO 15444-1 ?]",
    "JP20" => "Unknown, from GPAC samples (prob non-existent)",
    "jpm " => "JPEG 2000 Compound Image (.JPM) [ISO 15444-6]",
    "jpx " => "JPEG 2000 with extensions (.JPX) [ISO 15444-2]",
    "KDDI" => "3GPP2 EZmovie for KDDI 3G cellphones",
    "M4A " => "Apple iTunes AAC-LC (.M4A) Audio",
    "M4B " => "Apple iTunes AAC-LC (.M4B) Audio Book",
    "M4P " => "Apple iTunes AAC-LC (.M4P) AES Protected Audio",
    "M4V " => "Apple iTunes Video (.M4V) Video",
    "M4VH" => "Apple TV (.M4V)",
    "M4VP" => "Apple iPhone (.M4V)",
    "mj2s" => "Motion JPEG 2000 [ISO 15444-3] Simple Profile",
    "mjp2" => "Motion JPEG 2000 [ISO 15444-3] General Profile",
    "mmp4" => "MPEG-4/3GPP Mobile Profile (.MP4/3GP) (for NTT)",
    "mp21" => "MPEG-21 [ISO/IEC 21000-9]",
    "mp41" => "MP4 v1 [ISO 14496-1:ch13]",
    "mp42" => "MP4 v2 [ISO 14496-14]",
    "mp71" => "MP4 w/ MPEG-7 Metadata [per ISO 14496-12]",
    "MPPI" => "Photo Player, MAF [ISO/IEC 23000-3]",
    "mqt " => "Sony / Mobile QuickTime (.MQV) US Patent 7,477,830 (Sony Corp)",
    "MSNV" => "MPEG-4 (.MP4) for SonyPSP",
    "NDAS" => "MP4 v2 [ISO 14496-14] Nero Digital AAC Audio",
    "NDSC" => "MPEG-4 (.MP4) Nero Cinema Profile",
    "NDSH" => "MPEG-4 (.MP4) Nero HDTV Profile",
    "NDSM" => "MPEG-4 (.MP4) Nero Mobile Profile",
    "NDSP" => "MPEG-4 (.MP4) Nero Portable Profile",
    "NDSS" => "MPEG-4 (.MP4) Nero Standard Profile",
    "NDXC" => "H.264/MPEG-4 AVC (.MP4) Nero Cinema Profile",
    "NDXH" => "H.264/MPEG-4 AVC (.MP4) Nero HDTV Profile",
    "NDXM" => "H.264/MPEG-4 AVC (.MP4) Nero Mobile Profile",
    "NDXP" => "H.264/MPEG-4 AVC (.MP4) Nero Portable Profile",
    "NDXS" => "H.264/MPEG-4 AVC (.MP4) Nero Standard Profile",
    "odcf" => "OMA DCF DRM Format 2.0 (OMA-TS-DRM-DCF-V2_0-20060303-A)",
    "opf2" => "OMA PDCF DRM Format 2.1 (OMA-TS-DRM-DCF-V2_1-20070724-C)",
    "opx2" => "OMA PDCF DRM + XBS extensions (OMA-TS-DRM_XBS-V1_0-20070529-C)",
    "pana" => "Panasonic Digital Camera",
    "qt  " => "Apple QuickTime (.MOV/QT)",
    "ROSS" => "Ross Video",
    "sdv " => "SD Memory Card Video",
    "ssc1" => "Samsung stereoscopic, single stream",
    "ssc2" => "Samsung stereoscopic, dual stream",
    "XAVC" => "Sony XAVC",
    "heic" => "High Efficiency Image Format HEVC still image (.HEIC)",
    "hevc" => "High Efficiency Image Format HEVC sequence (.HEICS)",
    "mif1" => "High Efficiency Image Format still image (.HEIF)",
    "msf1" => "High Efficiency Image Format sequence (.HEIFS)",
    "heix" => "High Efficiency Image Format still image (.HEIF)",
    "avif" => "AV1 Image File Format (.AVIF)",
    "avis" => "AV1 Image Sequence (.AVIF)",
    "avio" => "AV1 Intra-Only Image (.AVIF)",
    "miaf" => "Multi-Image Application Format (.AVIF)",
    "crx " => "Canon Raw (.CRX)",
    _ => return None,
  })
}

/// `MinorVersion` ValueConv (QuickTime.pm:1043 `sprintf("%x.%x.%x",
/// unpack("nCC", $val))`). `val` is the 4-byte minor-version field: a
/// big-endian `int16u` (high) + two `int8u`. Returns `None` if short.
fn minor_version_string(val: &[u8]) -> Option<String> {
  let b = val.get(0..4)?;
  // `b` is exactly 4 bytes, so `be_u16(b, 0)` and `b.get(2)`/`b.get(3)`
  // always succeed; `?` is byte-identical to the raw indexing.
  let n = be_u16(b, 0)?;
  Some(format!("{n:x}.{:x}.{:x}", b.get(2)?, b.get(3)?))
}

/// The no-`ee` `EEWarn` string (QuickTime.pm:9548, `Warn(msg, 3)`). The `3`rd
/// `Warn` argument is `ignorable = 1` ⇒ the rendered Warning value carries the
/// `[minor] ` prefix (Extra.pm `[minor]` convention). The group-scoped
/// `Track<N>:Warning` is emitted IN-STREAM as a verbatim tag value (the
/// structural `trak`-walk warning channel, unlike the doc-level `Diagnostic`
/// pipeline), so the prefix is part of the literal here.
const EE_WARNING: &str = "[minor] The ExtractEmbedded option may find more tags in the media data";

/// `true` iff `code` is a `trak` handler type that triggers the no-`ee`
/// `EEWarn` — a member of `%eeBox` (QuickTime.pm:523-533) EXCEPT the `vide`
/// handler (which is gated on the `stsd` sample-description, not the handler
/// type, QuickTime.pm:8407 `$val eq 'vide'`) and the empty-key `''` /`gps `
/// top-level (no-handler) entry. `meta` covers the `mebx`/`camm` NRT-metadata
/// tracks (their `stsd` `MetaFormat` differs but the `hdlr` type is `meta`).
fn is_ee_handler(code: &str) -> bool {
  matches!(code, "text" | "meta" | "sbtl" | "data" | "camm" | "ctbx")
}

/// `hdlr` HandlerType PrintConv table (QuickTime.pm:8418-8444).
fn handler_type_print(code: &str) -> &'static str {
  match code {
    "alis" => "Alias Data",
    "crsm" => "Clock Reference",
    "hint" => "Hint Track",
    "ipsm" => "IPMP",
    "m7sm" => "MPEG-7 Stream",
    "meta" => "NRT Metadata",
    "mdir" => "Metadata",
    "mdta" => "Metadata Tags",
    "mjsm" => "MPEG-J",
    "ocsm" => "Object Content",
    "odsm" => "Object Descriptor",
    "priv" => "Private",
    "sdsm" => "Scene Description",
    "soun" => "Audio Track",
    "text" => "Text",
    "tmcd" => "Time Code",
    "url " => "URL",
    "vide" => "Video Track",
    "subp" => "Subpicture",
    "nrtm" => "Non-Real Time Metadata",
    "pict" => "Picture",
    "camm" => "Camera Metadata",
    "psmd" => "Panasonic Static Metadata",
    "data" => "Data",
    "sbtl" => "Subtitle",
    _ => "",
  }
}

/// `hdlr` HandlerClass / ComponentType PrintConv (QuickTime.pm:8398-8401).
/// `mhlr`→Media Handler / `dhlr`→Data Handler; any other code is a hash miss
/// (empty ⇒ the caller renders `Unknown ($val)`).
fn handler_class_print(code: &str) -> &'static str {
  match code {
    "mhlr" => "Media Handler",
    "dhlr" => "Data Handler",
    _ => "",
  }
}

/// `MediaLanguageCode` ValueConv (QuickTime.pm:7280): a 16-bit code that is
/// either a Macintosh language id (`< 0x400` or `0x7fff`) or a packed ISO
/// 639-2 three-letter code (three 5-bit groups, each offset by `0x60`).
///
/// This is the post-RawConv (`$val ? $val : undef`, QuickTime.pm:7279) +
/// ValueConv (QuickTime.pm:7280) value. For a Macintosh code the ValueConv is
/// the bare NUMBER (`($val < 0x400 or $val == 0x7fff) ? $val : pack …`), so the
/// typed layer stores its decimal string; the PrintConv-only Macintosh
/// language-name mapping is applied at serialize time via
/// [`mac_language_print`] (F4).
fn media_language(code: u16) -> Option<String> {
  if code == 0 {
    return None; // QuickTime.pm:7279 `$val ? $val : undef`.
  }
  if code < 0x400 || code == 0x7fff {
    // Macintosh numeric code — the ValueConv keeps the raw number.
    return Some(code.to_string());
  }
  let c0 = (((code >> 10) & 0x1f) + 0x60) as u8;
  let c1 = (((code >> 5) & 0x1f) + 0x60) as u8;
  let c2 = ((code & 0x1f) + 0x60) as u8;
  Some(String::from_utf8_lossy(&[c0, c1, c2]).into_owned())
}

/// `MediaLanguageCode` PrintConv (QuickTime.pm:7281-7285): a NUMERIC value
/// (a Macintosh code, since the ValueConv leaves Mac codes as the bare number
/// while ISO codes become 3-letter strings) is mapped through
/// `$Image::ExifTool::Font::ttLang{Macintosh}` (Font.pm:92-117), falling back
/// to `Unknown ($val)`; a non-numeric value (an ISO 3-letter code) is
/// returned unchanged (`return $val unless $val =~ /^\d+$/`). `lang` is the
/// post-ValueConv stored string. Returns the PrintConv string.
fn mac_language_print(lang: &str) -> String {
  // QuickTime.pm:7282 `return $val unless $val =~ /^\d+$/` — only an all-digit
  // value (the Macintosh numeric code) goes through the table.
  let Ok(code) = lang.parse::<u32>() else {
    return lang.to_string();
  };
  // QuickTime.pm:7284 `$ttLang{Macintosh}{$val} || "Unknown ($val)"`.
  match tt_lang_macintosh(code) {
    Some(name) => name.to_string(),
    None => {
      let mut s = String::with_capacity(lang.len() + 10);
      s.push_str("Unknown (");
      s.push_str(lang);
      s.push(')');
      s
    }
  }
}

/// `$Image::ExifTool::Font::ttLang{Macintosh}` (Font.pm:92-117) — Macintosh
/// language id ⇒ language tag. Used only by [`mac_language_print`] (the
/// MediaLanguageCode PrintConv). A miss yields `None` ⇒ `Unknown ($val)`.
/// (Note: `32 => ''` maps to the EMPTY string in Font.pm, which is falsy in
/// the `||` PrintConv, so code 32 also falls through to `Unknown (32)`.)
fn tt_lang_macintosh(code: u32) -> Option<&'static str> {
  Some(match code {
    0 => "en",
    1 => "fr",
    2 => "de",
    3 => "it",
    4 => "nl-NL",
    5 => "sv",
    6 => "es",
    7 => "da",
    8 => "pt",
    9 => "no",
    10 => "he",
    11 => "ja",
    12 => "ar",
    13 => "fi",
    14 => "el",
    15 => "is",
    16 => "mt",
    17 => "tr",
    18 => "hr",
    19 => "zh-TW",
    20 => "ur",
    21 => "hi",
    22 => "th",
    23 => "ko",
    24 => "lt",
    25 => "pl",
    26 => "hu",
    27 => "et",
    28 => "lv",
    29 => "smi",
    30 => "fo",
    31 => "fa",
    32 => "ru",
    33 => "zh-CN",
    34 => "nl-BE",
    35 => "ga",
    36 => "sq",
    37 => "ro",
    38 => "cs",
    39 => "sk",
    40 => "sl",
    41 => "yi",
    42 => "sr",
    43 => "mk",
    44 => "bg",
    45 => "uk",
    46 => "be",
    47 => "uz",
    48 => "kk",
    49 => "az",
    50 => "az",
    51 => "hy",
    52 => "ka",
    53 => "ro",
    54 => "ky",
    55 => "tg",
    56 => "tk",
    57 => "mn-MN",
    58 => "mn-CN",
    59 => "ps",
    60 => "ku",
    61 => "ks",
    62 => "sd",
    63 => "bo",
    64 => "ne",
    65 => "sa",
    66 => "mr",
    67 => "bn",
    68 => "as",
    69 => "gu",
    70 => "pa",
    71 => "or",
    72 => "ml",
    73 => "kn",
    74 => "ta",
    75 => "te",
    76 => "si",
    77 => "my",
    78 => "km",
    79 => "lo",
    80 => "vi",
    81 => "id",
    82 => "tl",
    83 => "ms-MY",
    84 => "ms-BN",
    85 => "am",
    86 => "ti",
    87 => "om",
    88 => "so",
    89 => "sw",
    90 => "rw",
    91 => "rn",
    92 => "ny",
    93 => "mg",
    94 => "eo",
    128 => "cy",
    129 => "eu",
    130 => "ca",
    131 => "la",
    132 => "qu",
    133 => "gn",
    134 => "ay",
    135 => "tt",
    136 => "ug",
    137 => "dz",
    138 => "jv",
    139 => "su",
    140 => "gl",
    141 => "af",
    142 => "br",
    144 => "gd",
    145 => "gv",
    146 => "ga",
    147 => "to",
    148 => "el",
    149 => "kl",
    150 => "az",
    _ => return None,
  })
}

/// `%durationInfo` ValueConv `$$self{TimeScale} ? $val / $$self{TimeScale} :
/// $val` (QuickTime.pm:313-315) — converts a RAW timescale-count to seconds.
/// A `None` or zero (falsy) TimeScale returns the bare count (R6/F1 — the
/// mvhd `%durationInfo` tags defer this conversion to OUTPUT time so the
/// FINAL global movie `TimeScale` is used).
fn durationinfo_value_conv(raw: u64, timescale: Option<u32>) -> f64 {
  match timescale {
    Some(ts) if ts != 0 => raw as f64 / f64::from(ts),
    // No timescale ⇒ Perl returns the raw count unchanged.
    _ => raw as f64,
  }
}

/// [`durationinfo_value_conv`] lifted over `Option` — `None` when the raw
/// duration is absent. Used for the per-track `tkhd`/`mdhd` durations, which
/// are converted at decode time against an already-final TimeScale.
fn duration_seconds(raw: Option<u64>, timescale: Option<u32>) -> Option<f64> {
  Some(durationinfo_value_conv(raw?, timescale))
}

// ===========================================================================
// ftyp (QuickTime.pm:9986-10008, 1031-1052)
// ===========================================================================

/// Decode the `ftyp` MajorBrand / MinorVersion / CompatibleBrands into `qt`
/// (QuickTime.pm:1031-1052). MajorBrand keeps trailing spaces (the
/// `%ftypLookup` key); MinorVersion is the `%x.%x.%x` ValueConv; the
/// compatible-brand list drops any 4-byte group containing a NUL
/// (QuickTime.pm:1050).
fn decode_ftyp(payload: &[u8], qt: &mut QuickTimeMeta) {
  if let Some(brand) = payload.get(0..4) {
    qt.set_major_brand(String::from_utf8_lossy(brand).into_owned());
  }
  // MinorVersion: undef[4] at int32u index 1 ⇒ byte offset 4.
  if let Some(mv) = payload.get(4..8).and_then(minor_version_string) {
    qt.set_minor_version(Some(mv));
  }
  // CompatibleBrands: undef[$size-8] at byte offset 8; split into 4-byte
  // groups, drop any group containing a NUL (QuickTime.pm:1050).
  let mut brands = Vec::new();
  let mut i = 8;
  while i + 4 <= payload.len() {
    // The `while` guard proves `i + 4 <= len`, so `.get` is always `Some`;
    // the `else` break matches the guard turning false (byte-identical).
    let Some(g) = payload.get(i..i + 4) else {
      break;
    };
    if !g.contains(&0) {
      brands.push(String::from_utf8_lossy(g).into_owned());
    }
    i += 4;
  }
  qt.set_compatible_brands(brands);
}

/// Resolve the `File:FileType` from an `ftyp` atom payload. The major brand
/// is the first 4 bytes; compatible brands follow at offset 8 in 4-byte
/// groups (QuickTime.pm:9993-10002). Returns `(file_type, mime)`.
fn file_type_from_ftyp(payload: &[u8]) -> (&'static str, &'static str) {
  // QuickTime.pm:9993 `$ftypLookup{$type}` — SP1 covers the common
  // brands; the full %ftypLookup table is an SP4 item. `payload.get(0..4)`
  // is `None` exactly when `payload.len() < 4`, byte-identical to the guard.
  if let Some(brand) = payload.get(0..4) {
    match brand {
      b"qt  " => return ("MOV", "video/quicktime"),
      b"M4A " => return ("M4A", "audio/mp4"),
      b"M4V " => return ("M4V", "video/x-m4v"),
      b"M4B " => return ("M4B", "audio/mp4"),
      _ => {}
    }
  }
  // QuickTime.pm:9996-10001: scan compatible brands. ExifTool matches three
  // `elsif` regexes against the WHOLE ftyp buffer, in this order:
  //   `/^.{8}(.{4})+(mp41|mp42|avc1)/s`  ⇒ MP4
  //   `/^.{8}(.{4})+(f4v )/s`            ⇒ F4V
  //   `/^.{8}(.{4})+(qt  )/s`            ⇒ MOV
  // The leading `^.{8}` skips the 4-byte major brand + 4-byte minor version;
  // the `(.{4})+` then requires **one or more** 4-byte compatible-brand slots
  // BEFORE the matched brand. So the matched brand must sit at buffer offset
  // ≥ 12 — a `qt  `/`mp4x`/`f4v ` in the FIRST compatible-brand slot (offset 8)
  // can NOT trigger the match (R9/F1: an `isom\0\0\0\0qt  ` payload stays MP4).
  // The three regexes are tried in `elsif` order, so `mp4x`/`avc1` anywhere in
  // a non-first slot wins over a `qt  ` / `f4v ` in another non-first slot.
  let non_first_slot = |needles: &[&[u8; 4]]| -> bool {
    let mut i = 12; // skip major+minor (offset 8) AND the first compat slot.
    while i + 4 <= payload.len() {
      // The `while` guard proves `i + 4 <= len`, so `.get` is always `Some`;
      // the comparison is byte-identical to the raw slice.
      let Some(slot) = payload.get(i..i + 4) else {
        break;
      };
      if needles.iter().any(|n| slot == &n[..]) {
        return true;
      }
      i += 4;
    }
    false
  };
  if non_first_slot(&[b"mp41", b"mp42", b"avc1"]) {
    return ("MP4", "video/mp4");
  }
  if non_first_slot(&[b"f4v "]) {
    return ("F4V", "video/mp4");
  }
  if non_first_slot(&[b"qt  "]) {
    return ("MOV", "video/quicktime");
  }
  // QuickTime.pm:10004 `$fileType or $fileType = 'MP4'`.
  ("MP4", "video/mp4")
}

/// `%useExt` — "use extension to determine file type" (QuickTime.pm:240).
///
/// The WHOLE table is a single entry: `( GLV => 'MP4' )`. The promotion at
/// QuickTime.pm:10007 fires only when ALL of the following hold:
///
/// ```perl
/// my $ext = $$et{FILE_EXT};
/// $fileType = $ext if $ext and $useExt{$ext} and $fileType eq $useExt{$ext};
/// ```
///
/// i.e. the file extension is set, IS a `%useExt` key, AND the ftyp-derived
/// `$fileType` equals the value that key maps to. So a `.glv` file whose ftyp
/// resolves to the generic `MP4` (the GLV mapped value) is promoted to `GLV`;
/// a `.glv` whose ftyp resolves to anything else (`MOV`, `M4A`, …) is NOT
/// promoted here — the generic `SetFileType` sub-type-by-extension block
/// (ExifTool.pm:9686-9692, ported in `resolve_file_type`) handles those, since
/// every QuickTime sub-type shares the `MOV` root in `%fileTypeLookup`.
///
/// `$$et{FILE_EXT}` is the UPPERCASED, dotless extension (ExifTool.pm:9096-
/// 9106 `GetFileExtension`), so `ext` here is the engine's `file_ext_for_name`
/// value (already uppercased); the lone key `GLV` is uppercase, matched
/// case-insensitively for robustness.
///
/// Returns the promoted file type when the predicate fires, else `None`.
fn use_ext(file_type: &str, ext: Option<&str>) -> Option<&'static str> {
  let ext = ext?;
  // `%useExt = ( GLV => 'MP4' )` — the entire table (QuickTime.pm:240).
  if ext.eq_ignore_ascii_case("GLV") && file_type == "MP4" {
    // QuickTime.pm:10007 `$fileType = $ext` — the canonical uppercase key.
    return Some("GLV");
  }
  None
}

// ===========================================================================
// mvhd / tkhd / mdhd binary-data decoders
// ===========================================================================

/// Decode the `mvhd` (Movie Header) atom into `qt`
/// (`%QuickTime::MovieHeader`, QuickTime.pm:1343-1421).
///
/// The table FORMAT is `int32u`, so binary-data index `N` maps to byte
/// offset `4*N + varSize` (ExifTool.pm:9946). The TRUTHY-version Hook
/// (`$$self{MovieHeaderVersion} and ...`) widens entries 1 (CreateDate),
/// 2 (ModifyDate) and 4 (Duration) to `int64u`, each adding 4 to `varSize`
/// as it is processed; so every entry with index ≥ 5 sits 12 bytes later
/// (`varSize == 12`) in a non-v0 mvhd (QuickTime.pm:1373/1380/1390 Hooks).
fn decode_mvhd(payload: &[u8], qt: &mut QuickTimeMeta) {
  let Some(&version) = payload.first() else {
    return;
  };
  // **R10/F2.** The mvhd Hooks widen on a TRUTHY version
  // (`$$self{MovieHeaderVersion} and $format = "int64u"`,
  // QuickTime.pm:1373/1380/1390), not strictly `== 1` — so any non-zero
  // version takes the int64u layout. v0/v1 are the only spec-defined cases
  // (so the observable behavior is unchanged), but this matches Perl exactly.
  let wide = version != 0;
  // create(idx1)=4, modify(idx2)=8/16, ts(idx3)=12/20, duration(idx4)=16/24.
  let (create, modify, ts_off): (Option<u64>, Option<u64>, usize) = if wide {
    (be_u64(payload, 4), be_u64(payload, 12), 20)
  } else {
    (
      be_u32(payload, 4).map(u64::from),
      be_u32(payload, 8).map(u64::from),
      12,
    )
  };
  let timescale = be_u32(payload, ts_off);
  let duration = if wide {
    be_u64(payload, ts_off + 4)
  } else {
    be_u32(payload, ts_off + 4).map(u64::from)
  };
  // varSize for indices ≥ 5: 12 in a v1 mvhd, 0 otherwise.
  let vs: usize = if wide { 12 } else { 0 };
  let off = |idx: usize| 4 * idx + vs;

  // **R6/F1.** Every `set_*` below overwrites the prior `mvhd` state ONLY
  // when the field is actually present in THIS `mvhd` (`Some`) — a field
  // absent from a later short `mvhd` keeps the earlier FoundTag value, while
  // a present field (including a present zero) overwrites last-wins. The
  // `%durationInfo` ValueConv divide is NOT applied here: the raw timescale
  // COUNTS are stored and divided at serialization against the FINAL global
  // movie `TimeScale` (a later short `mvhd` can change only the divisor).
  qt.set_movie_header_version(version);
  qt.set_create_date(create.and_then(qt_date_string));
  qt.set_modify_date(modify.and_then(qt_date_string));
  qt.set_time_scale(timescale);
  // Duration (idx4): the RAW timescale-count (QuickTime.pm:1386-1393); the
  // durationInfo ValueConv `$val / $TimeScale` is deferred to serialization.
  qt.set_duration_count(duration);
  // PreferredRate (idx5): int32u / 0x10000 (QuickTime.pm:1394-1397).
  qt.set_preferred_rate(be_u32(payload, off(5)).map(|v| f64::from(v) / 65536.0));
  // PreferredVolume (idx6, int16u): / 256 (QuickTime.pm:1398-1403).
  qt.set_preferred_volume(be_u16(payload, off(6)).map(|v| f64::from(v) / 256.0));
  // MatrixStructure (idx9, fixed32s[9]) (QuickTime.pm:1404-1413).
  qt.set_matrix_structure(matrix_structure_string(payload, off(9)));
  // Preview/Poster/Selection/Current durationInfo tags (idx18-23) — the RAW
  // %durationInfo counts; divided by the FINAL movie TimeScale at output
  // (QuickTime.pm:1414-1419).
  qt.set_preview_time_count(be_u32(payload, off(18)));
  qt.set_preview_duration_count(be_u32(payload, off(19)));
  qt.set_poster_time_count(be_u32(payload, off(20)));
  qt.set_selection_time_count(be_u32(payload, off(21)));
  qt.set_selection_duration_count(be_u32(payload, off(22)));
  qt.set_current_time_count(be_u32(payload, off(23)));
  // NextTrackID (idx24) (QuickTime.pm:1420).
  qt.set_next_track_id(be_u32(payload, off(24)));
}

/// `FixWrongFormat` (QuickTime.pm:8872-8877): the tkhd ImageWidth/Height
/// entries are declared `int32u` in the table FORMAT but actually store a
/// 16.16 fixed-point value. ExifTool reads the int32u then, if the high
/// bits are set (`$val & 0xfff00000`), takes the HIGH 16 bits
/// (`unpack('n', pack('N', $val))`); otherwise returns the value unchanged
/// (a literal small pixel count). A zero value returns `undef`.
fn fix_wrong_format(raw: u32) -> Option<u32> {
  if raw == 0 {
    return None; // QuickTime.pm:8875 `return undef unless $val`.
  }
  if raw & 0xfff0_0000 != 0 {
    Some(u32::from((raw >> 16) as u16)) // high 16 bits
  } else {
    Some(raw)
  }
}

/// Decode a `tkhd` (Track Header) atom into a [`MediaTrack`]
/// (`%QuickTime::TrackHeader`, QuickTime.pm:1493-1582). `movie_timescale`
/// converts `TrackDuration` (the durationInfo ValueConv uses the MOVIE
/// TimeScale).
///
/// As with mvhd, the table FORMAT is `int32u` so binary-data index `N` maps
/// to byte offset `4*N + varSize`. The TRUTHY-version Hook
/// (`$$self{TrackHeaderVersion} and ...`) widens entries 1 (TrackCreateDate),
/// 2 (TrackModifyDate) and 5 (TrackDuration) to `int64u`; every entry with
/// index ≥ 6 is therefore 12 bytes later in a non-v0 tkhd. **(R1/F2)**: v1
/// ImageWidth/ImageHeight (indices 19/20)
/// are at byte offsets 88/92 (`4*19+12` / `4*20+12`), NOT 96/100 — only
/// three time/duration fields widen, adding 12 bytes, not 20.
fn decode_tkhd(payload: &[u8], movie_timescale: Option<u32>) -> MediaTrack {
  let mut track = MediaTrack::new();
  let Some(&version) = payload.first() else {
    return track;
  };
  // **R10/F2.** The tkhd Hooks widen on a TRUTHY version
  // (`$$self{TrackHeaderVersion} and $format = "int64u"`,
  // QuickTime.pm:1512/1520/1531), not strictly `== 1`. v0/v1 are the only
  // spec-defined cases; this matches Perl's predicate exactly.
  let wide = version != 0;
  // create(idx1)=4; modify(idx2)=8/12; id(idx3)=12/20; duration(idx5)=20/28.
  // For v1 the create int64u occupies bytes 4-11, so modify int64u starts at
  // byte 12 (idx2 = 4*2 + varSize=4).
  let (create, modify, track_id_off, duration_off): (Option<u64>, Option<u64>, usize, usize) =
    if wide {
      (be_u64(payload, 4), be_u64(payload, 12), 20, 28)
    } else {
      (
        be_u32(payload, 4).map(u64::from),
        be_u32(payload, 8).map(u64::from),
        12,
        20,
      )
    };
  let track_id = be_u32(payload, track_id_off);
  let duration = if wide {
    be_u64(payload, duration_off)
  } else {
    be_u32(payload, duration_off).map(u64::from)
  };
  // varSize for indices ≥ 6: 12 in a v1 tkhd, 0 otherwise.
  let vs: usize = if wide { 12 } else { 0 };
  let off = |idx: usize| 4 * idx + vs;
  // TrackLayer (idx8, int16u), TrackVolume (idx9, int16u / 256),
  // MatrixStructure (idx10, fixed32s[9]).
  let layer = be_u16(payload, off(8));
  let volume = be_u16(payload, off(9)).map(|v| f64::from(v) / 256.0);
  let matrix = matrix_structure_string(payload, off(10));
  // ImageWidth/Height (idx19/20) via FixWrongFormat.
  let width = be_u32(payload, off(19)).and_then(fix_wrong_format);
  let height = be_u32(payload, off(20)).and_then(fix_wrong_format);

  track.set_track_header_version(version);
  track.set_track_create_date(create.and_then(qt_date_string));
  track.set_track_modify_date(modify.and_then(qt_date_string));
  track.set_track_id(track_id);
  track.set_duration_seconds(duration_seconds(duration, movie_timescale));
  track.set_track_layer(layer);
  track.set_track_volume(volume);
  track.set_matrix_structure(matrix);
  track.set_image_width(width);
  track.set_image_height(height);
  track
}

/// Decode the `mdhd` (Media Header) atom into `track`
/// (`%QuickTime::MediaHeader`, QuickTime.pm:7239-7287). The TRUTHY-version
/// Hook (`$$self{MediaHeaderVersion} and ...`) widens MediaCreateDate (idx1),
/// MediaModifyDate (idx2) and MediaDuration (idx4) to `int64u`.
fn decode_mdhd(payload: &[u8], track: &mut MediaTrack) {
  let Some(&version) = payload.first() else {
    return;
  };
  // **R10/F2.** The mdhd Hooks widen on a TRUTHY version
  // (`$$self{MediaHeaderVersion} and $format = "int64u"`,
  // QuickTime.pm:7255/7262/7273), not strictly `== 1`. v0/v1 are the only
  // spec-defined cases; this matches Perl's predicate exactly.
  let wide = version != 0;
  // create(idx1)=4; modify(idx2)=8/12; ts(idx3)=12/20. For v1 the create
  // int64u occupies bytes 4-11, so modify int64u starts at byte 12.
  let (create, modify, ts_off): (Option<u64>, Option<u64>, usize) = if wide {
    (be_u64(payload, 4), be_u64(payload, 12), 20)
  } else {
    (
      be_u32(payload, 4).map(u64::from),
      be_u32(payload, 8).map(u64::from),
      12,
    )
  };
  let timescale = be_u32(payload, ts_off);
  let duration = if wide {
    be_u64(payload, ts_off + 4)
  } else {
    be_u32(payload, ts_off + 4).map(u64::from)
  };
  // MediaLanguageCode is the int16u right after the duration field.
  let lang_off = if wide { ts_off + 12 } else { ts_off + 8 };
  let lang = be_u16(payload, lang_off);

  // **R7/F1.** Each `set_*` overwrites the prior `mdhd` state ONLY when the
  // field is actually present in THIS `mdhd` (`Some`) — a field absent from a
  // later short `mdhd` keeps the earlier FoundTag value, while a present field
  // (including a present zero) overwrites last-wins. Bundled ExifTool never
  // erases an earlier FoundTag when a later binary-data field is absent: a
  // short mdhd carrying only MediaTimeScale must NOT clear an earlier
  // MediaDuration. Same pattern as the R6/F1 mvhd fix, extended to mdhd.
  track.set_media_header_version(version);
  if let Some(d) = create.and_then(qt_date_string) {
    track.set_media_create_date(Some(d));
  }
  if let Some(d) = modify.and_then(qt_date_string) {
    track.set_media_modify_date(Some(d));
  }
  if timescale.is_some() {
    track.set_media_time_scale(timescale);
  }
  if let Some(secs) = duration_seconds(duration, timescale) {
    track.set_media_duration_seconds(Some(secs));
  }
  if let Some(l) = lang.and_then(media_language) {
    track.set_media_language(Some(l));
  }
}

/// Read the `hdlr` atom's raw 4-byte HandlerType code (QuickTime.pm:8403-
/// 8416 — `undef[4]` at byte offset 8). The raw code is preserved verbatim
/// (F3): distinct codes (`mdta`/`mdir`/`nrtm`/`subp`/…) must NOT be
/// collapsed at the flat-tag layer. Returns the lossless 4-char string.
fn decode_hdlr(payload: &[u8]) -> Option<String> {
  let raw = payload.get(8..12)?;
  Some(String::from_utf8_lossy(raw).into_owned())
}

/// Read the `hdlr` atom's raw 4-byte HandlerClass / ComponentType
/// (QuickTime.pm:8395-8402 — `undef[4]` at body offset 4). `RawConv => '$val eq
/// "\0\0\0\0" ? undef : $val'` ⇒ an all-zero ComponentType is `None` (ExifTool
/// omits the tag). Returns the lossless 4-char string otherwise.
fn decode_hdlr_class(payload: &[u8]) -> Option<String> {
  let raw = payload.get(4..8)?;
  if raw == [0, 0, 0, 0] {
    return None;
  }
  Some(String::from_utf8_lossy(raw).into_owned())
}

/// Read the `stsd` (Sample Description) box's first-entry 4-byte format code
/// (the `MetaFormat` / `OtherFormat` value — `undef[4]` at offset 4 of the
/// sample-description entry, QuickTime.pm:7765/7803). The `stsd` body is
/// `[version+flags:4][entry-count:4]` then each entry `[size:4][format:4]…`, so
/// the FIRST entry's format 4cc is at body offset 12. Mirrors the stream
/// walker's `walk_stsd` bounds (entry size >= 16, entry within the box). Returns
/// the lossless 4-char string, or `None` when the box is too short / malformed.
/// Timed-metadata tracks carry exactly one entry; ExifTool's `MetaFormat` is
/// last-wins, but a single entry is the universal real-world shape.
fn decode_stsd_meta_format(payload: &[u8]) -> Option<String> {
  // Walk ALL sample-description entries, LAST-WINS — ExifTool's
  // `ProcessSampleDesc` per-entry `RawConv => '$$self{MetaFormat} = $val'`
  // makes a later entry's format overwrite the earlier (QuickTime.pm:9640-
  // 9648). A single entry (the universal real-world shape) resolves to itself.
  // Each entry is `[size:4][format:4][reserved:6][data-ref-index:2]` + children.
  let count = be_u32(payload, 4)? as usize;
  let mut pos = 8usize;
  let mut last: Option<String> = None;
  for _ in 0..count {
    let Some(size) = be_u32(payload, pos).map(|s| s as usize) else {
      break;
    };
    // ExifTool `ProcessSampleDesc` stops only on `$size < 8` (the entry needs at
    // least the `[size:4][format:4]` header) or an overrunning entry
    // (QuickTime.pm:9642-9643) — keeping the last-wins format accumulated so
    // far. An 8-15 byte entry still contributes its offset-4 format. `checked_add`
    // so a crafted overflowing `size` breaks rather than wrapping/panicking.
    let Some(entry_end) = pos.checked_add(size) else {
      break;
    };
    if size < 8 || entry_end > payload.len() {
      break;
    }
    if let Some(raw) = payload.get(pos + 4..pos + 8) {
      last = Some(String::from_utf8_lossy(raw).into_owned());
    }
    pos = entry_end;
  }
  last
}

/// Decode every `mvhd` inside one `moov` atom into `qt` (QuickTime.pm:660-
/// 700, 1343-1421). This is the FIRST of the two top-level passes (see
/// [`parse_inner`]): it establishes the movie `TimeScale` (and the movie
/// `Duration`, dates, matrix, …) WITHOUT decoding any `trak`.
///
/// **F4 / R3-F2 — TimeScale is GLOBAL, applied at OUTPUT.** The Codex F4
/// finding claimed the parser must thread "whatever TimeScale is present at
/// the file-order point" so that a `trak` appearing BEFORE `mvhd` would use
/// no movie TimeScale. That is NOT what bundled ExifTool does: the
/// `TrackDuration` / movie `Duration` tags use `%durationInfo`, whose
/// `$$self{TimeScale} ? $val/$$self{TimeScale} : $val` is a **ValueConv** —
/// and ExifTool runs ValueConv at OUTPUT (GetInfo) time, not parse time
/// (ExifTool.pm `GetValue`). The `mvhd` `TimeScale` RawConv (`$$self{TimeScale}
/// = $val`, QuickTime.pm:1384) writes a SINGLE global slot, last-wins across
/// EVERY `mvhd` in the file — including a SECOND top-level `moov`. By output
/// time the movie TimeScale is therefore the FINAL one, regardless of
/// mvhd/trak order OR which moov a track lives in.
///
/// R3-F2 fixture: `moov(mvhd TimeScale=600, tkhd Duration=1200)` then a second
/// top-level `moov(mvhd TimeScale=300)` ⇒ bundled `Track1:TrackDuration = 4`
/// (`1200/300`), NOT `1200/600 = 2`. So the file walk must decode ALL mvhds
/// (global last-wins TimeScale) BEFORE converting ANY TrackDuration — handled
/// by the two-pass loop in [`parse_inner`].
///
/// (Contrast `MediaDuration`, which is a *RawConv* using the per-track
/// `$$self{MediaTS}` set by the SAME mdhd table — that one IS parse-order
/// and is handled inside [`decode_mdhd`].)
fn decode_moov_mvhd(
  payload: &[u8],
  payload_file_offset: usize,
  qt: &mut QuickTimeMeta,
  warning: &mut Option<String>,
) {
  // Top-level entry (the `parse_inner` file loop) — depth 0. `payload_file_offset`
  // is this moov body's absolute file offset, so a truncated UNKNOWN child (e.g.
  // the trailer bytes a SPANNING moov reads in, parsed as `SE12`) reports its
  // correct `at offset 0x%x` (QuickTime.pm:10590).
  walk_atoms_based(
    0,
    payload,
    payload_file_offset,
    0,
    payload.len(),
    warning,
    |inner, ibody, _w| {
      if &inner.atom_type == b"mvhd" {
        decode_mvhd(ibody, qt);
      }
    },
  );
}

/// Decode the top-level `frea` atom — a `SubDirectory` dispatched to
/// `Image::ExifTool::Kodak::frea` from the `%QuickTime::Main` `frea` entry
/// (QuickTime.pm:610-613). The `frea` atom is a CONTAINER holding the four
/// Kodak PixPro / Rexing sub-atoms (Kodak.pm:2977-2990):
///
///  - `tima` → **Duration** (`int32u` seconds; PrintConv `ConvertDuration`).
///  - `'ver '` → **KodakVersion** (string; ExifTool also stashes it as the
///    `$$self{KodakVersion}` global the freeGPS Type-17b scan reads).
///  - `thma` → **ThumbnailImage** (`Binary => 1` ⇒ the `(Binary data N bytes…)`
///    placeholder; group2 `Preview`).
///  - `scra` → **PreviewImage** (`Binary => 1` ⇒ placeholder; group2 `Preview`).
///
/// ExifTool re-uses `ProcessMOV` to walk the `frea` SubDirectory, so each
/// sub-atom is a standard `[size:4][type:4][payload]` box. The decoded values
/// land on [`QuickTimeMeta::kodak_frea`]; the cross-module `KodakVersion`
/// global is THIS [`KodakFrea::version`](crate::metadata::KodakFrea::version),
/// threaded into the `mdat` freeGPS scan via [`parse_inner`].
fn decode_frea(payload: &[u8], qt: &mut QuickTimeMeta, warning: &mut Option<String>) {
  // Top-level entry (the `parse_inner` file loop) — depth 0.
  walk_atoms(0, payload, 0, payload.len(), warning, |inner, ibody, _w| {
    let frea = qt.kodak_frea_mut();
    match &inner.atom_type {
      // `tima` Duration — `int32u` (Kodak.pm:2980-2985). ExifTool's `int32u`
      // default byte order is big-endian (`Get32u` without `SetByteOrder`).
      b"tima" => {
        if let Some(v) = be_u32(ibody, 0) {
          frea.set_duration_secs(Some(v));
        }
      }
      // `'ver '` KodakVersion — the raw string value (Kodak.pm:2987). ExifTool
      // stores the bytes verbatim; trailing NULs (a NUL-padded box) are
      // dropped so the global compares cleanly against `'3.01.054'`.
      b"ver " => {
        let s = core::str::from_utf8(ibody)
          .unwrap_or("")
          .trim_end_matches('\0');
        if !s.is_empty() {
          frea.set_version(Some(smol_str::SmolStr::new(s)));
        }
      }
      // `thma` ThumbnailImage — `Binary => 1` (Kodak.pm:2988). Record only the
      // payload byte length for the `(Binary data N bytes…)` placeholder; the
      // bytes are never materialized.
      b"thma" => {
        frea.set_thumbnail_len(Some(ibody.len() as u64));
      }
      // `scra` PreviewImage — `Binary => 1` (Kodak.pm:2989).
      b"scra" => {
        frea.set_preview_len(Some(ibody.len() as u64));
      }
      _ => {}
    }
  });
}

/// Decode every `trak` inside one `moov` atom, converting `TrackDuration`
/// against the FINAL global movie `TimeScale` (`movie_ts`) established by the
/// first pass over ALL top-level moovs (see [`decode_moov_mvhd`] /
/// [`parse_inner`]).
fn decode_moov_trak(
  payload: &[u8],
  movie_ts: Option<u32>,
  qt: &mut QuickTimeMeta,
  warning: &mut Option<String>,
) {
  // ExifTool's `$track` counter is a `my` local of THIS `moov`'s `ProcessMOV`
  // invocation (QuickTime.pm:9944), starting undef⇒0 and `++`-incremented per
  // `trak` (QuickTime.pm:10353-10354). Reset it to 0 here so each top-level
  // `moov`'s tracks number from `Track1` again — two single-`trak` moovs both
  // get the family-1 group `Track1` (R4/F2). The serializer then drops the
  // later same-group track (first-wins) so default JSON keeps the FIRST moov's
  // `Track1`.
  let mut track_num: u32 = 0;
  // Top-level entry (the `parse_inner` file loop) — this `moov` walk is depth
  // 0; `walk_trak` re-enters `walk_atoms` so it starts one level deeper (1).
  walk_atoms(0, payload, 0, payload.len(), warning, |inner, ibody, _w| {
    if &inner.atom_type == b"trak" {
      track_num += 1; // QuickTime.pm:10354 `++$track`
      let mut track = walk_trak(1, ibody, movie_ts);
      track.set_track_group(track_num);
      qt.push_track(track);
    }
  });
}

/// Walk one `trak` atom, collecting tkhd / mdia(mdhd,hdlr) into a
/// [`MediaTrack`] (QuickTime.pm:1424-1490 + 7218-7327).
///
/// **R7/F2 + R9/F2.** A contained malformed header (a truncated tkhd / mdhd,
/// or one with a structurally invalid size) is NOT silently dropped: ExifTool
/// attaches the `Truncated '...' data` / `Invalid atom size` warning to the
/// *current* family-1 group, so the warning is recorded ON THE TRACK (surfaced
/// as `Track#:Warning`), not the document-level `ExifTool:Warning`.
fn walk_trak(depth: u32, payload: &[u8], movie_timescale: Option<u32>) -> MediaTrack {
  let mut track = MediaTrack::new();
  let mut track_warning: Option<String> = None;
  walk_atoms(
    depth,
    payload,
    0,
    payload.len(),
    &mut track_warning,
    |atom, body, w| {
      match &atom.atom_type {
        b"tkhd" => {
          let decoded = decode_tkhd(body, movie_timescale);
          track.merge_track_header(decoded);
        }
        b"mdia" => {
          // mdia contains mdhd + hdlr + minf (QuickTime.pm:7218-7237). This
          // re-enters `walk_atoms` from inside the trak walk, so it runs one
          // level deeper than the enclosing `walk_trak` (Golden-v2 3a).
          walk_atoms(
            depth + 1,
            body,
            0,
            body.len(),
            w,
            |inner, ibody, iw| match &inner.atom_type {
              b"mdhd" => decode_mdhd(ibody, &mut track),
              b"hdlr" => {
                if let Some(code) = decode_hdlr(ibody) {
                  track.set_handler_code(code);
                }
                track.set_handler_class(decode_hdlr_class(ibody));
              }
              // `minf/stbl/stsd` carries the sample-description 4-byte format
              // code (the `MetaFormat`). Descend two more levels and pull it onto
              // the track so the emission can surface `Track<N>:MetaFormat` for a
              // `meta`-handler timed-metadata track (QuickTime.pm:7765/7803).
              b"minf" => {
                walk_atoms(depth + 2, ibody, 0, ibody.len(), iw, |m, mbody, mw| {
                  if &m.atom_type == b"stbl" {
                    walk_atoms(depth + 3, mbody, 0, mbody.len(), mw, |s, sbody, _sw| {
                      if &s.atom_type == b"stsd"
                        && let Some(fmt) = decode_stsd_meta_format(sbody)
                      {
                        track.set_meta_format(Some(fmt));
                      }
                    });
                  }
                });
              }
              _ => {}
            },
          );
        }
        _ => {}
      }
    },
  );
  track.set_warning(track_warning);
  track
}

// ===========================================================================
// SP2 — udta camera atoms + moov/meta Keys/ItemList (QuickTime.pm:1585-1900,
// 2809-2900, 6651-6760, 9779-9878)
// ===========================================================================

/// Walk one `moov` atom's DIRECT children for the **SP2** `udta` camera atoms
/// and the `moov/meta` Keys/ItemList metadata, decoding into `qt`
/// (QuickTime.pm:2058/2070 — `udta`/`meta` are `%QuickTime::Movie` keys). The
/// box walk runs at `depth` (the enclosing Pass-1 moov walk passes its child
/// depth); a contained malformed atom surfaces a warning through `warning`
/// (first-wins, like `decode_moov_mvhd`). A second top-level `moov` re-enters
/// here, last-wins per field (TagMap semantics) — matching the GoPro/multimoov
/// flat-accumulation pattern.
fn decode_moov_udta_meta(
  depth: u32,
  payload: &[u8],
  qt: &mut QuickTimeMeta,
  warning: &mut Option<String>,
) {
  walk_atoms(
    depth,
    payload,
    0,
    payload.len(),
    warning,
    |atom, body, w| match &atom.atom_type {
      b"udta" => walk_udta(depth + 1, body, w, qt.user_data_mut()),
      b"meta" => walk_meta(depth + 1, body, w, qt),
      _ => {}
    },
  );
}

/// Walk one `udta` atom payload, decoding the camera/GPS/capture-identity
/// atoms into `ud` (QuickTime.pm:1585-1900). Two atom families are handled:
///
///   - **International-text atoms** (4-cc beginning with the copyright symbol
///     0xA9): Make / Model / SoftwareVersion / Title / Comment / Copyright /
///     ContentCreateDate / GPSCoordinates. Decoded via [`decode_itext_first`].
///   - **Plain 4-cc atoms** (`manu` / `modl` / `cmnm` / `CNMN` / DJI copyright
///     `mdl` / `slno` / `SNum` / `CNCV` / `CNFV` / `FIRM` / `info` / `cmid` /
///     `date`). These carry their value as a table-`FORMAT => 'string'` value
///     (NUL-terminated) — except `manu` / `modl`, which apply the Canon/Samsung
///     RawConv `s/^\0{4}..//s; s/\0.*//`.
///
/// Make / Model / SerialNumber / FirmwareVersion are MULTI-SOURCE: their setters
/// take the source's ExifTool priority (1 = normal, 0 = `Avoid`) and the typed
/// layer resolves duplicates (see
/// [`crate::metadata::QuickTimeUserData`]). A contained malformed atom surfaces
/// a warning through `w`.
fn walk_udta(
  depth: u32,
  payload: &[u8],
  w: &mut Option<String>,
  ud: &mut crate::metadata::QuickTimeUserData,
) {
  const CR: u8 = 0xA9; // the copyright-symbol prefix.
  walk_atoms(depth, payload, 0, payload.len(), w, |atom, body, _w| {
    let t = atom.atom_type;
    // ── International-text (copyright-symbol-prefixed) atoms ───────────────
    if t.first() == Some(&CR) {
      let Some(text) = decode_itext_first(body) else {
        return;
      };
      match t.get(1..4) {
        // `©mak` Make (no Avoid ⇒ priority 1).
        Some(b"mak") => {
          ud.set_make(text, 1);
        }
        // `©mod` Model (no Avoid ⇒ priority 1).
        Some(b"mod") => {
          ud.set_model(text, 1);
        }
        Some(b"swr") => {
          ud.set_software(Some(text));
        }
        Some(b"nam") => {
          ud.set_title(Some(text));
        }
        Some(b"cmt") => {
          ud.set_comment(Some(text));
        }
        Some(b"cpy") => {
          ud.set_copyright(Some(text));
        }
        Some(b"day") => {
          ud.set_content_create_date(Some(convert_iso8601_date(&text)));
        }
        Some(b"xyz") => {
          // The `xyz` GPS atom is PRESENT, so the GPS tag is always emitted (the
          // raw string when undecodable — `ConvertISO6709` returns `$val`
          // unchanged).
          ud.set_gps(Some(parse_iso6709(&text)));
        }
        Some(b"mdl") => {
          // The DJI non-standard `©mdl` Model atom (QuickTime.pm:2156, Avoid ⇒
          // priority 0, Format => 'string'). It still arrives as a
          // copyright-symbol atom but its value is a plain NUL-terminated
          // string, so re-decode the body as a string (NOT international text).
          ud.set_model(decode_qt_string(body), 0);
        }
        _ => {
          // A copyright-symbol atom NOT special-cased above (`©mal` MakerURL,
          // `©gpt` CameraPitch, `©gyw` CameraYaw, `©grl` CameraRoll): consult
          // the generated conv-less map by the FULL 4-cc. These are bare
          // `'Name'` international-text atoms (QuickTime.pm:1639/2148-2150),
          // emitted verbatim under `QuickTime:UserData` (always a string — the
          // `%QuickTime::UserData` table is `FORMAT => 'string'`).
          if let Some(name) = userdata_convless_name(&t) {
            ud.push_convless(name, crate::value::TagValue::Str(text.into()));
          }
        }
      }
      return;
    }
    // ── Plain 4-cc camera/GPS/capture-identity atoms ───────────────────────
    match &t {
      // `manu` Make / `modl` Model (Canon SX280 / Samsung GT-S8530): Avoid ⇒
      // priority 0; RawConv `s/^\0{4}..//s; s/\0.*//` strips the optional Canon
      // 6-byte prefix then truncates at the first NUL (QuickTime.pm:1879-1891).
      b"manu" => {
        ud.set_make(decode_manu_modl(body), 0);
      }
      b"modl" => {
        ud.set_model(decode_manu_modl(body), 0);
      }
      // `cmnm` / `CNMN` Model (Format => 'string', Avoid ⇒ priority 0).
      b"cmnm" | b"CNMN" => {
        ud.set_model(decode_qt_string(body), 0);
      }
      // `slno` SerialNumber (Format => 'string', no Avoid ⇒ priority 1).
      b"slno" => {
        ud.set_serial_number(decode_qt_string(body), 1);
      }
      // `SNum` SerialNumber (Kodak, Avoid ⇒ priority 0).
      b"SNum" => {
        ud.set_serial_number(decode_qt_string(body), 0);
      }
      // `CNFV` FirmwareVersion (Canon, Format => 'string', no Avoid ⇒ 1).
      b"CNFV" => {
        ud.set_firmware_version(decode_qt_string(body), 1);
      }
      // `info` FirmwareVersion (Nextbase, no Avoid ⇒ priority 1).
      b"info" => {
        ud.set_firmware_version(decode_qt_string(body), 1);
      }
      // `FIRM` FirmwareVersion (GoPro Hero4, Avoid ⇒ priority 0).
      b"FIRM" => {
        ud.set_firmware_version(decode_qt_string(body), 0);
      }
      // `CNCV` CompressorVersion (Canon, Format => 'string', single-source).
      b"CNCV" => {
        ud.set_compressor_version(Some(decode_qt_string(body)));
      }
      // `cmid` CameraID (Apple, Format => 'string', single-source).
      b"cmid" => {
        ud.set_camera_id(Some(decode_qt_string(body)));
      }
      // `date` DateTimeOriginal (Apple, %iso8601Date over the string value).
      b"date" => {
        ud.set_date_time_original(Some(convert_iso8601_date(&decode_qt_string(body))));
      }
      // `CAME` SerialNumberHash (QuickTime.pm:2120-2125, GoPro Hero4):
      // `ValueConv => 'unpack("H*",$val)'` — the lower-case hex of the RAW
      // bytes (NO `string` NUL-truncation; the whole body is hashed). HAND-
      // ported (code-valued, kept out of the generated conv-less map).
      b"CAME" => {
        ud.set_serial_number_hash(Some(unpack_h_star(body)));
      }
      // `MUID` MediaUID (QuickTime.pm:2127, GoPro Hero4): `ValueConv =>
      // 'unpack("H*", $val)'` — the lower-case hex of the raw bytes. HAND-
      // ported.
      b"MUID" => {
        ud.set_media_uid(Some(unpack_h_star(body)));
      }
      // Any OTHER plain 4-cc atom: consult the generated conv-less map (`GoPr`
      // GoProType, `LENS` LensSerialNumber, `FOV\0` FieldOfView — bare `'Name'`
      // plain-string atoms, QuickTime.pm:2117/2119/2131). Emitted verbatim
      // under `QuickTime:UserData` via the `string`-format NUL-terminated read
      // (the `%QuickTime::UserData` table is `FORMAT => 'string'`).
      other => {
        if let Some(name) = userdata_convless_name(other) {
          ud.push_convless(
            name,
            crate::value::TagValue::Str(decode_qt_string(body).into()),
          );
        }
      }
    }
  });
}

/// Perl `unpack("H*", $val)` — render every byte of `bytes` as two lower-case
/// hex digits, high-nibble first, concatenated (QuickTime.pm `CAME` / `MUID`
/// ValueConv). An empty input yields the empty string (still emitted).
fn unpack_h_star(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
    s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
  }
  s
}

/// Decode a plain (non-international-text) `udta` string-atom value, faithful to
/// the table `FORMAT => 'string'` reading of `%QuickTime::UserData` — a
/// NUL-terminated string (`ReadValue` with the `string` format reads up to the
/// first NUL, QuickTime.pm:1592). The bytes are otherwise interpreted as UTF-8
/// (lossy); trailing data after the first NUL is dropped.
fn decode_qt_string(body: &[u8]) -> String {
  let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
  let s = body.get(..end).unwrap_or_default();
  String::from_utf8_lossy(s).into_owned()
}

/// The `manu` Make / `modl` Model RawConv `$val=~s/^\0{4}..//s; $val=~s/\0.*//`
/// (QuickTime.pm:1883/1890). Canon prepends 6 unknown bytes (`\0\0\0\0` then 2
/// more) before the value; the first substitution drops exactly those 6 bytes
/// WHEN the value starts with 4 NULs, then the value is truncated at the next
/// NUL. A value not starting with 4 NULs (e.g. Samsung `SAMSUNG\0`) keeps its
/// leading bytes and is just NUL-truncated. An all-stripped value yields the
/// empty string (still emitted by ExifTool).
fn decode_manu_modl(body: &[u8]) -> String {
  // `s/^\0{4}..//s` — only when the value begins with 4 NUL bytes, drop those
  // 4 plus the following 2 bytes (6 total). Perl's `.` matches any byte under
  // `/s`, so the 2 trailing bytes are unconditional once the 4 NULs match.
  let rest = if body.len() >= 6 && body.get(..4) == Some(&[0u8, 0, 0, 0]) {
    body.get(6..).unwrap_or_default()
  } else {
    body
  };
  // `s/\0.*//` — truncate at the first NUL.
  let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
  let s = rest.get(..end).unwrap_or_default();
  String::from_utf8_lossy(s).into_owned()
}

/// One `data` value decoded from an `ilst` item, with its format flags.
struct IlstData {
  /// The `data`-atom flags `int32u` (the high byte selects the value format —
  /// `%stringEncoding`, QuickTime.pm:357-363).
  flags: u32,
  /// The value bytes (after the 8-byte flags+locale header).
  bytes: std::vec::Vec<u8>,
}

/// Parse the first `data` child of an `ilst` item atom (QuickTime.pm:10378-
/// 10417): `int32u flags`, `int32u reserved` (country/language), then the
/// value. A contained malformed atom surfaces a warning through `w`.
fn decode_ilst_data(depth: u32, payload: &[u8], w: &mut Option<String>) -> Option<IlstData> {
  let mut result: Option<IlstData> = None;
  walk_atoms(depth, payload, 0, payload.len(), w, |atom, body, _w| {
    if &atom.atom_type == b"data"
      && result.is_none()
      && let Some(flag_bytes) = body.get(0..4)
      && let Some(value) = body.get(8..)
    {
      let flags = u32::from_be_bytes(flag_bytes.try_into().unwrap_or([0; 4]));
      result = Some(IlstData {
        flags,
        bytes: value.to_vec(),
      });
    }
  });
  result
}

/// Render an `ilst` `data` value as a string, faithful to the `%stringEncoding`
/// branch of the `data`-atom handler (QuickTime.pm:357-363, 10396-10399).
///
/// ExifTool string-decodes the value ONLY when the FULL `int32u` flags word is a
/// `%stringEncoding` key — `1`/`4` = UTF-8, `2`/`5` = UTF-16BE, `3` = ShiftJIS
/// (QuickTime.pm:357-363). The flags are read as a whole word
/// (`unpack("...N...")`, QuickTime.pm:10383), so the comparison is exact — a
/// non-string flag (binary `0x00`, JPEG `0x0d`, int `0x15`/`0x16`, float `0x17`,
/// double `0x18`, …) takes the `else` branch and is decoded by
/// `QuickTimeFormat`/left as a binary scalar ref, NOT rendered as text. Such a
/// value is therefore NOT a string, so `None` is returned and the caller drops
/// the (string-typed) tag rather than mis-rendering arbitrary bytes as UTF-8.
///
/// ShiftJIS (flag `3`) has no dedicated decoder here, so it falls back to the
/// UTF-8 path (a pre-existing charset-coverage gap, not a leniency: ExifTool
/// DOES emit a string for flag `3`, just via `Decode(..., 'ShiftJIS')`).
/// Trailing NULs are stripped (QuickTime.pm:10398 `s/\0$//`).
fn ilst_data_string(data: &IlstData) -> Option<String> {
  let mut s = match data.flags {
    2 | 5 => decode_utf16be(&data.bytes),
    1 | 3 | 4 => String::from_utf8_lossy(&data.bytes).into_owned(),
    _ => return None,
  };
  while s.ends_with('\0') {
    s.pop();
  }
  Some(s)
}

/// One `keys`-box entry: the `mdta`-stripped key plus the FULL (un-stripped)
/// key. ExifTool's `ProcessKeys` resolves a key by trying the stripped form
/// first, then falling back to the FULL form (QuickTime.pm:9807-9824 `for(;;)`
/// loop). Carrying both lets [`apply_key`] reproduce that fallback so keys NOT
/// in the `com.apple.quicktime` namespace — e.g. `com.android.manufacturer`,
/// whose table id keeps the `com.` prefix — still resolve.
struct KeyName {
  /// The key after the `mdta` `s/^com\.(apple\.quicktime\.)?//` strip.
  stripped: String,
  /// The key as written (before stripping).
  full: String,
}

/// Parse the `keys` box payload into the ordered list of key names
/// (QuickTime.pm:9779-9824 `ProcessKeys`). Layout: `int32u version/flags`,
/// `int32u entry-count`, then each entry `int32u size`, `char[4] namespace`,
/// `char[size-8]` key. The `com.apple.quicktime.` / `com.` prefix is stripped
/// for `mdta`-namespace keys (QuickTime.pm:9803), but the FULL key is retained
/// alongside so [`apply_key`] can reproduce the stripped-then-full fallback.
fn parse_keys_box(payload: &[u8]) -> std::vec::Vec<KeyName> {
  let mut keys = std::vec::Vec::new();
  // QuickTime.pm:9790 `$pos = 8` — skip the 4-byte version/flags AND the
  // 4-byte entry-count (the loop is bounded by `$dirLen`, not the count).
  let mut pos = 8usize;
  while let Some(len) = be_u32(payload, pos).map(|v| v as usize) {
    // QuickTime.pm:9797 `last if $len < 8 or $pos + $len > $dirLen`.
    if len < 8 || pos.checked_add(len).is_none_or(|e| e > payload.len()) {
      break;
    }
    let ns = payload.get(pos + 4..pos + 8).unwrap_or_default();
    let raw = payload.get(pos + 8..pos + len).unwrap_or_default();
    // QuickTime.pm:9801 `$tag =~ s/\0.*//s` — truncate at the first NUL.
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let truncated = raw.get(..end).unwrap_or_default();
    let full = String::from_utf8_lossy(truncated).into_owned();
    // QuickTime.pm:9803 — strip the apple quicktime domain for mdta keys.
    let stripped = if ns == b"mdta" {
      strip_apple_quicktime_prefix(&full)
    } else {
      full.clone()
    };
    keys.push(KeyName { stripped, full });
    pos += len;
  }
  keys
}

/// QuickTime.pm:9803 `$tag =~ s/^com\.(apple\.quicktime\.)?//` — strip a
/// leading `com.apple.quicktime.` (or bare `com.`) domain prefix.
fn strip_apple_quicktime_prefix(tag: &str) -> String {
  if let Some(rest) = tag.strip_prefix("com.apple.quicktime.") {
    rest.to_string()
  } else if let Some(rest) = tag.strip_prefix("com.") {
    rest.to_string()
  } else {
    tag.to_string()
  }
}

/// Walk one `moov/meta` atom payload in a **single, file-order pass**, decoding
/// the `hdlr` HandlerType / HandlerClass, the `keys` box(es) and the `ilst`
/// camera-metadata into `qt` (QuickTime.pm:2809-2900 `%Meta` table).
///
/// **Single-pass faithfulness (file order).** ExifTool's `ProcessMOV` walks the
/// `meta` children in order with NO look-ahead: `ProcessKeys` registers the
/// ItemList key tags as ids `"$KeysCount.$index"` ONLY when a `keys` atom is
/// reached (QuickTime.pm:9857 `AddTagToTable($itemList, "$KeysCount.$index")`),
/// and an `ilst` item resolves its id `"$KeysCount.unpack('N')"` against the
/// table built SO FAR (QuickTime.pm:10132). Consequences this loop reproduces:
///   - an `ilst` appearing BEFORE any `keys` finds no registered id ⇒ it is
///     dropped (the prior two-pass design wrongly resolved it against a future
///     `keys` table);
///   - `$$et{KeysCount}` is bumped per `keys` directory and an `ilst` item id is
///     always `currentKeysCount.N`, so with multiple `keys` boxes each `ilst`
///     resolves only against the MOST-RECENT `keys` box (a later box's count
///     shadows the earlier one's ids) — hence `key_names` is REPLACED, not
///     appended, when a new `keys` box is seen.
///
/// The `keys` box supplies the ordered key names; each `ilst` item is an atom
/// whose 4-byte type is the 1-based index into that list. A contained malformed
/// atom surfaces a warning through `w`.
fn walk_meta(depth: u32, payload: &[u8], w: &mut Option<String>, qt: &mut QuickTimeMeta) {
  // The key list of the most-recent `keys` box seen so far (file order). An
  // `ilst` reached before any `keys` box resolves against an empty list ⇒ drops
  // every item, matching ExifTool's single-pass `KeysCount.index` lookup.
  let mut key_names: std::vec::Vec<KeyName> = std::vec::Vec::new();
  walk_atoms(depth, payload, 0, payload.len(), w, |atom, body, w| {
    match &atom.atom_type {
      // The `moov/meta` Metadata-handler `hdlr`: the SAME `%QuickTime::Handler`
      // table as the trak hdlr (QuickTime.pm:2824 / 8391-8444). HandlerClass =
      // body offset-4 ComponentType (all-zero ⇒ None via the RawConv); the
      // HandlerType = subtype at body offset 8.
      b"hdlr" => {
        qt.set_meta_handler_class(decode_hdlr_class(body));
        if let Some(code) = decode_hdlr(body) {
          qt.set_meta_handler_type(Some(code));
        }
      }
      // A `keys` box REPLACES the active key list (see the multi-box note above).
      b"keys" => key_names = parse_keys_box(body),
      // An `ilst` resolves each item against the keys seen SO FAR.
      b"ilst" => {
        walk_atoms(depth + 1, body, 0, body.len(), w, |item, item_body, iw| {
          // The item atom's 4-byte type is a big-endian 1-based key index.
          let index = u32::from_be_bytes(item.atom_type) as usize;
          let Some(key) = index.checked_sub(1).and_then(|i| key_names.get(i)) else {
            return;
          };
          let Some(data) = decode_ilst_data(depth + 2, item_body, iw) else {
            return;
          };
          apply_key(key, &data, qt.keys_mut());
        });
      }
      _ => {}
    }
  });
}

/// Project one resolved `keys` entry onto [`crate::metadata::QuickTimeKeys`],
/// faithful to the `%QuickTime::Keys` table (QuickTime.pm:6651-6770). Only the
/// camera/GPS/capture-identity keys are decoded.
///
/// **Stripped-then-full key fallback (QuickTime.pm:9807-9824).** ExifTool tries
/// the `mdta`-stripped key first, then the FULL (un-stripped) key. So the
/// `com.apple.quicktime.*` keys match their stripped names (`make`, `model`,
/// …), while the keys that are NOT in the `com.apple.quicktime` namespace
/// (`com.android.version` / `com.android.manufacturer` / `com.android.model`,
/// whose table ids keep the `com.` prefix) match only the FULL key — the bare
/// `com.` strip yields `android.*`, which is not a table id.
fn apply_key(key: &KeyName, data: &IlstData, keys_out: &mut crate::metadata::QuickTimeKeys) {
  if apply_key_name(&key.stripped, data, keys_out) {
    return;
  }
  // Stripped key did not match a modeled tag — fall back to the FULL key
  // (skip the redundant retry when stripping was a no-op).
  if key.full != key.stripped {
    apply_key_name(&key.full, data, keys_out);
  }
}

/// Resolve a single key NAME against the modeled `%QuickTime::Keys` identity
/// set. Returns `true` when the name matched a modeled tag (so the caller does
/// not retry the alternate form).
fn apply_key_name(
  name: &str,
  data: &IlstData,
  keys_out: &mut crate::metadata::QuickTimeKeys,
) -> bool {
  // The CONV-BEARING keys (`creationdate` has `%iso8601Date`, `location.ISO6709`
  // has `ValueConv => \&ConvertISO6709`, QuickTime.pm:6683-6712) stay bespoke:
  // they carry a value conversion that the generic conv-less cascade does NOT
  // apply, so they decode as typed fields. They return `true` (name matched,
  // ExifTool's `for(;;)` key lookup QuickTime.pm:9807-9824) regardless of
  // whether the `data` atom is a string — a non-string flag yields `None` from
  // [`ilst_data_string`] and the typed field is simply not set, mirroring
  // ExifTool turning a non-string data atom for that tag into a binary scalar
  // ref this layer does not model.
  //
  // EVERY OTHER modeled key (`make`/`model`/`software`/`direction.*`/the
  // `com.android.*` / `samsung.android.utc_offset` identity set) is genuinely
  // CONV-LESS in `%QuickTime::Keys` (no `Format`, no `ValueConv` — the table has
  // no table-level FORMAT either), so it MUST follow the SAME full
  // string→numeric→binary `data`-atom cascade ExifTool's `ProcessMOV` runs for
  // a conv-less tag (QuickTime.pm:10387-10416 / [`ilst_data_convless`]). Routing
  // each through [`crate::metadata::QuickTimeKeys::push_convless`] (by the exact
  // table `Name`, walk order) keeps EVERY format flag faithful — a `Make` with a
  // numeric flag emits a number, an `AndroidCaptureFPS` with a string flag emits
  // the string — instead of the prior typed paths that only handled one flavor.
  match name {
    "creationdate" => {
      // ValueConv-bearing (`%iso8601Date` ⇒ `ConvertXMPDate`). ExifTool feeds the
      // pre-ValueConv `data`-atom value — a string flag → decoded; a numeric flag
      // → the `ReadValue` number; any other flag → the RAW bytes (the binary
      // scalar-ref placeholder is gated on NO ValueConv, QuickTime.pm:10411, so it
      // does NOT apply here) — to the date ValueConv, which passes a NON-date
      // through verbatim. So `creationdate` ALWAYS emits for ANY flag: a numeric
      // flag emits the bare number (the `"300"` passthrough re-numberifies via the
      // terminal EscapeJSON gate), a non-date string emits itself. See
      // [`ilst_data_valueconv_str`].
      keys_out.set_creation_date(Some(convert_iso8601_date(&ilst_data_valueconv_str(data))));
    }
    "location.ISO6709" => {
      // ValueConv-bearing (`ConvertISO6709` + `PrintGPSCoordinates`). Same
      // pre-ValueConv `$val` as `creationdate`. `ConvertISO6709`/
      // `PrintGPSCoordinates` ALWAYS yield a value (a non-numeric field → `0` via
      // `ToDMS`), so the GPS tag ALWAYS emits for ANY flag — a numeric flag → e.g.
      // `"300 deg 0' 0.00\" N, "`, raw/undecodable bytes → parsed or `0`-filled
      // coordinates.
      keys_out.set_gps(Some(parse_iso6709(&ilst_data_valueconv_str(data))));
    }
    // Conv-less Apple identity keys (`com.apple.quicktime.*`, stripped form).
    "make" => {
      keys_out.push_convless("Make", ilst_data_convless(data));
    }
    "model" => {
      keys_out.push_convless("Model", ilst_data_convless(data));
    }
    "software" => {
      keys_out.push_convless("Software", ilst_data_convless(data));
    }
    // Conv-less keys NOT in the com.apple.quicktime namespace (full-key
    // fallback): the table id keeps the `com.`/vendor prefix, so the stripped
    // form does not match and the FULL key resolves here.
    "com.android.manufacturer" => {
      keys_out.push_convless("AndroidMake", ilst_data_convless(data));
    }
    "com.android.model" => {
      keys_out.push_convless("AndroidModel", ilst_data_convless(data));
    }
    "com.android.version" => {
      keys_out.push_convless("AndroidVersion", ilst_data_convless(data));
    }
    // `com.android.capture.fps` AndroidCaptureFPS (QuickTime.pm:6763): the
    // `Writable => 'float'` is a WRITER hint, NOT a read `Format`, and there is
    // no `ValueConv` ⇒ the tag is CONV-LESS. So the data-atom value follows the
    // cascade like any other: a float/double flag (`0x17`/`0x18`) reads an IEEE
    // number, a string flag emits the string, etc. — NOT a typed-float-only path.
    "com.android.capture.fps" => {
      keys_out.push_convless("AndroidCaptureFPS", ilst_data_convless(data));
    }
    // `samsung.android.utc_offset` AndroidTimeZone (QuickTime.pm:6769): a non-
    // `com.apple.quicktime` (full-key fallback) conv-less key.
    "samsung.android.utc_offset" => {
      keys_out.push_convless("AndroidTimeZone", ilst_data_convless(data));
    }
    // Any OTHER key: consult the generated conv-less Keys map (`direction.facing`
    // CameraDirection, `direction.motion` CameraMotion — bare `Name` keys with
    // NO Format/ValueConv, QuickTime.pm:6735-6736). Same full cascade
    // ([`ilst_data_convless`]), which ALWAYS yields a value (the binary
    // scalar-ref branch is the catch-all). Emitted verbatim under `QuickTime:Keys`.
    other => match keys_convless_name(other) {
      Some(name) => {
        keys_out.push_convless(name, ilst_data_convless(data));
      }
      None => return false,
    },
  }
  true
}

/// Decode a conv-less `Keys`/`ItemList` `data`-atom value — a tag with NO
/// `Format` and NO `ValueConv` — into a [`TagValue`], faithful to the full
/// `data`-atom cascade of `ProcessMOV` (QuickTime.pm:10396-10416). The
/// `%QuickTime::Keys` table has no table-level `FORMAT`, so its conv-less tags
/// (e.g. `direction.facing` ⇒ `CameraDirection`) reach this cascade:
///
///   1. **String** — `if ($stringEncoding{$flags})` (QuickTime.pm:10396): the
///      value is decoded as a string (UTF-8 / UTF-16BE / ShiftJIS-via-UTF-8) and
///      one trailing NUL stripped (10398). Reuses [`ilst_data_string`].
///   2. **Numeric** — `else { $format = QuickTimeFormat($flags,$len) }`
///      (QuickTime.pm:10402): a `0x15` signed / `0x16` unsigned / `0x17` float /
///      `0x18` double / `0x00` (len 1|2) int flag with a length in `{1,2,4,8}`
///      yields a single-element `ReadValue` NUMBER (QuickTime.pm:9560-9569 +
///      10409). Emitted as a [`TagValue::I64`] / [`TagValue::U64`] /
///      [`TagValue::F64`] (a JSON number in both `-j` and `-n`).
///   3. **Binary** — `elsif (not $$tagInfo{ValueConv}) { $value = \$buf }`
///      (QuickTime.pm:10411-10414): no string flag and no usable numeric format
///      (e.g. flag `0x00`/`0x0d` with a length not in `{1,2}`/`{1,2,4,8}`). The
///      raw bytes become a scalar reference, which `FoundTag` still records
///      (10442 `if defined $value` — a ref is defined) and the writer renders as
///      the `(Binary data N bytes, use -b option to extract)` placeholder. Modeled
///      as [`TagValue::Bytes`] (serializes to exactly that placeholder,
///      value.rs:1088), so this branch ALWAYS yields a value — matching ExifTool.
///
/// Mirrors `QuickTimeFormat`'s EXACT full-`int32u`-flags-word comparison: the
/// flags are read whole (`unpack("...N...")`, QuickTime.pm:10383), so a word
/// that merely *ends* in a known flag byte is neither a string nor a number and
/// falls to the binary branch.
/// The pre-ValueConv `$val` ExifTool passes to a **ValueConv-bearing** Keys
/// `data` atom (`creationdate` ⇒ `ConvertXMPDate`, `location.ISO6709` ⇒
/// `ConvertISO6709`), faithful to `ProcessMOV` (QuickTime.pm:10396-10416). A
/// ValueConv-bearing tag NEVER takes the binary scalar-ref placeholder branch
/// (10411 `elsif (not $$tagInfo{ValueConv})`), so the value is always a defined
/// scalar fed straight to the ValueConv: a `%stringEncoding` flag → the decoded
/// string; a `QuickTimeFormat` numeric flag → the `ReadValue` number, stringified
/// (the ValueConv operates on it in string context); any OTHER flag (no usable
/// format) → the RAW bytes as a lossy string. ALWAYS returns a value (these tags
/// always `FoundTag`). A numeric string re-numberifies through the terminal
/// EscapeJSON gate where the ValueConv passes it through (e.g. a numeric
/// `creationdate` emits the bare number, matching bundled 13.59).
///
/// Contrast [`ilst_data_convless`] (NO ValueConv): there a non-string/non-numeric
/// flag becomes the `(Binary data N bytes…)` placeholder; here it stays raw for
/// the ValueConv.
fn ilst_data_valueconv_str(data: &IlstData) -> String {
  use crate::value::TagValue;
  // 1. String-encoding flag ⇒ the decoded string.
  if let Some(s) = ilst_data_string(data) {
    return s;
  }
  // 2. A `QuickTimeFormat` numeric flag ⇒ the `ReadValue` number, stringified.
  let len = data.bytes.len();
  match data.flags {
    0x15 => {
      if let Some(v) = read_be_int_signed(&data.bytes, len) {
        return v.to_string();
      }
    }
    0x16 => {
      if let Some(v) = read_be_int_unsigned(&data.bytes, len) {
        return v.to_string();
      }
    }
    0x17 | 0x18 => match read_be_floats(&data.bytes, if data.flags == 0x17 { 4 } else { 8 }) {
      TagValue::F64(f) => return perl_num(f),
      // Empty (short) or the space-joined multi-value string.
      TagValue::Str(s) => return s.to_string(),
      _ => {}
    },
    0x00 => {
      if len == 1 || len == 2 {
        if let Some(v) = read_be_int_unsigned(&data.bytes, len) {
          return v.to_string();
        }
      }
    }
    _ => {}
  }
  // 3. No string, no usable numeric format ⇒ the RAW bytes, lossy (fed to the
  //    ValueConv verbatim — NOT the binary placeholder, which needs no ValueConv).
  String::from_utf8_lossy(&data.bytes).into_owned()
}

fn ilst_data_convless(data: &IlstData) -> crate::value::TagValue {
  use crate::value::TagValue;
  // 1. String formats (the `%stringEncoding` flags 1..=5).
  if let Some(s) = ilst_data_string(data) {
    return TagValue::Str(s.into());
  }
  // 2. A numeric format from `QuickTimeFormat($flags, $len)`. For the INTEGER
  //    flags the format is length-gated (`{...}->{$len}` is defined only for a
  //    length in `{1,2,4,8}`, and `{1,2}` for `0x00`), so `ReadValue` reads
  //    exactly one element — a single scalar number — or, for any other length,
  //    yields no format and falls to the binary branch. The FLOAT/DOUBLE flags
  //    are NOT length-gated (handled in [`read_be_floats`]).
  let len = data.bytes.len();
  match data.flags {
    // `0x15` signed int: int8s/int16s/int32s/int64s by length.
    0x15 => {
      if let Some(v) = read_be_int_signed(&data.bytes, len) {
        return TagValue::I64(v);
      }
    }
    // `0x16` unsigned int: int8u/int16u/int32u/int64u by length.
    0x16 => {
      if let Some(v) = read_be_int_unsigned(&data.bytes, len) {
        return TagValue::U64(v);
      }
    }
    // `0x17` float / `0x18` double. UNLIKE the integer flags, `QuickTimeFormat`
    // returns the float/double format UNCONDITIONALLY (QuickTime.pm:9562-9565 —
    // no `->{$len}` length gate), so this branch NEVER falls through to the
    // binary scalar-ref case. `ReadValue` with an undef count (ExifTool.pm:
    // 6296-6331) reads `int(len/elem)` values: the empty scalar for a payload
    // shorter than one element, a single number, or a space-joined string for
    // multiple — see [`read_be_floats`].
    0x17 | 0x18 => {
      let elem = if data.flags == 0x17 { 4 } else { 8 };
      return read_be_floats(&data.bytes, elem);
    }
    // `0x00` binary: int8u (len 1) / int16u (len 2); any other length ⇒ no
    // format ⇒ the binary branch below (QuickTime.pm:9568 `{1,2}->{$len}`).
    0x00 => {
      if len == 1 || len == 2 {
        if let Some(v) = read_be_int_unsigned(&data.bytes, len) {
          return TagValue::U64(v);
        }
      }
    }
    _ => {}
  }
  // 3. No string, no numeric format, no ValueConv ⇒ a binary scalar ref. Stored
  //    as the raw bytes; the serializer renders the universal binary placeholder
  //    derived from the byte length (value.rs:1088).
  TagValue::Bytes(data.bytes.clone())
}

/// `ReadValue` for a big-endian unsigned `int8u`/`int16u`/`int32u`/`int64u` of
/// `len` bytes — the [`QuickTimeFormat`]-selected unsigned numeric read
/// (QuickTime.pm:9560). Returns `None` for a length not in `{1,2,4,8}` or a
/// short buffer (the `{...}->{$len}` undef ⇒ no format ⇒ the binary branch).
fn read_be_int_unsigned(bytes: &[u8], len: usize) -> Option<u64> {
  match len {
    1 => bytes.first().map(|&b| u64::from(b)),
    2 => {
      let b: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
      Some(u64::from(u16::from_be_bytes(b)))
    }
    4 => {
      let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
      Some(u64::from(u32::from_be_bytes(b)))
    }
    8 => {
      let b: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
      Some(u64::from_be_bytes(b))
    }
    _ => None,
  }
}

/// `ReadValue` for a big-endian signed `int8s`/`int16s`/`int32s`/`int64s` of
/// `len` bytes — the [`QuickTimeFormat`]-selected signed numeric read
/// (QuickTime.pm:9560). Returns `None` for a length not in `{1,2,4,8}` or a
/// short buffer.
fn read_be_int_signed(bytes: &[u8], len: usize) -> Option<i64> {
  match len {
    1 => bytes.first().map(|&b| i64::from(b as i8)),
    2 => {
      let b: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
      Some(i64::from(i16::from_be_bytes(b)))
    }
    4 => {
      let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
      Some(i64::from(i32::from_be_bytes(b)))
    }
    8 => {
      let b: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
      Some(i64::from_be_bytes(b))
    }
    _ => None,
  }
}

/// `ReadValue` for a big-endian `float` (`elem` = 4) / `double` (`elem` = 8)
/// list read with an undef `count` — the conv-less `0x17`/`0x18` data-atom path.
/// `QuickTimeFormat` selects the format from the flag ALONE (QuickTime.pm:
/// 9562-9565), so the read is NOT length-gated and never falls to the binary
/// branch. Mirrors `ReadValue` (ExifTool.pm:6296-6331) for `count` undef: a
/// payload shorter than one element yields the empty scalar (`return ''`);
/// otherwise `n = int(len / elem)` values are read and returned as a single
/// [`TagValue::F64`] number (`n == 1`) or a space-joined [`perl_num`] string
/// (`n > 1`). A trailing partial element is ignored, exactly as `ReadValue`'s
/// `int($size / $len)` truncates the count.
fn read_be_floats(bytes: &[u8], elem: usize) -> crate::value::TagValue {
  use crate::value::TagValue;
  let vals: Vec<f64> = bytes
    .chunks_exact(elem)
    .map(|c| {
      if elem == 4 {
        f64::from(f32::from_be_bytes(c.try_into().unwrap_or([0; 4])))
      } else {
        f64::from_be_bytes(c.try_into().unwrap_or([0; 8]))
      }
    })
    .collect();
  match vals.as_slice() {
    // `ReadValue` `return ''` when the payload is shorter than one element.
    [] => TagValue::Str("".into()),
    [one] => TagValue::F64(*one),
    many => TagValue::Str(
      many
        .iter()
        .map(|v| perl_num(*v))
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
  }
}

// ── SP2 text decode (international text + UTF-16BE) ───────────────────────

/// Decode the FIRST non-empty international-text entry of a `©`-prefixed `udta`
/// atom payload, faithful to the `$tag =~ /^\xa9/` entry loop of `ProcessMOV`
/// (QuickTime.pm:10461-10524). Each entry is `int16u len`, `int16u lang`, then
/// `len` bytes of text. The loop is reproduced exactly:
///
///   - `last if $pos + 4 > $size` (10472): stop when no 4-byte header remains.
///   - read `($len,$lang)`, `$pos += 4` (10473-10474).
///   - **len-overrun retry** (10477-10480): "nobody adds the 4 header bytes to
///     `$len`, so try either" — `if ($pos+$len > $size) { $len -= 4; last if
///     $pos+$len > $size or $len < 0 }`. With unsigned `len`, the `$len -= 4`
///     underflow (when `len < 4`) is the `$len < 0` bail.
///   - **skip empty entries** (10483): `next if not $len and $pos`. `$pos` is
///     already advanced (`>= 4`), so this skips EVERY zero-length entry — it
///     does NOT bail the loop. A leading empty/NUL-padding entry is stepped over
///     and the next entry is tried.
///   - otherwise decode `substr($val,$pos,$len)` via [`decode_qt_text`] (the
///     lang/charset branch, 10485-10516) and `$pos += $len`.
///
/// ExifTool's loop `FoundTag`s EVERY non-empty entry; this typed layer surfaces
/// the camera-metadata atom's value, so it returns the FIRST non-empty decoded
/// entry (an all-empty/short payload yields `None` ⇒ no tag).
fn decode_itext_first(payload: &[u8]) -> Option<String> {
  let size = payload.len();
  let mut pos = 0usize;
  loop {
    // QuickTime.pm:10472 `last if $pos + 4 > $size`.
    if pos.checked_add(4).is_none_or(|e| e > size) {
      return None;
    }
    // QuickTime.pm:10473 `($len,$lang) = unpack("x${pos}nn",$val)`.
    let mut len = be_u16(payload, pos)? as usize;
    let lang = be_u16(payload, pos + 2)?;
    // QuickTime.pm:10474 `$pos += 4`.
    pos += 4;
    // QuickTime.pm:10477-10480 — len-overrun retry (allow for the 4 header bytes
    // either being included in `$len` or not).
    if pos.checked_add(len).is_none_or(|e| e > size) {
      // `$len -= 4`; `last if $pos + $len > $size or $len < 0` (the unsigned
      // underflow for `len < 4` IS the `$len < 0` bail).
      let Some(adj) = len.checked_sub(4) else {
        return None;
      };
      len = adj;
      if pos.checked_add(len).is_none_or(|e| e > size) {
        return None;
      }
    }
    // QuickTime.pm:10483 `next if not $len and $pos` — skip an empty entry (pos
    // is always >= 4 here) and continue to the next (the bottom `$pos += $len`
    // is reached only after a FoundTag, so a skipped entry advances `pos` only
    // by its already-consumed 4-byte header).
    if len == 0 {
      continue;
    }
    // QuickTime.pm:10484 `$str = substr($val, $pos, $len)`.
    let text_slice = payload.get(pos..pos + len)?;
    return Some(decode_qt_text(text_slice, lang));
  }
}

/// Decode a `udta` international-text byte slice, faithful to the
/// language/charset branch of `ProcessMOV` (QuickTime.pm:10485-10516).
///
/// The branch hinges on the language code (`$lang < 0x400 or $lang == 0x7fff`,
/// and no leading UTF-16BE BOM ⇒ "Macintosh language code"):
///   - **Mac language (non-zero `lang < 0x400`, or `0x7fff`):** the bytes are
///     the QuickTime charset, which defaults to MacRoman
///     (`CharsetQuickTime => 'MacRoman'`, ExifTool.pm:1122). QuickTime.pm:10506
///     `$enc = $charsetQuickTime unless $enc`.
///   - **Default language `0x0000`:** QuickTime.pm:10499-10502 — "use UTF-8
///     instead of the CharsetQuickTime setting if obviously UTF8", i.e.
///     `$enc = 'UTF8' if IsUTF8(\$str) > 0`, ELSE fall through to MacRoman.
///     `IsUTF8 > 0` means the bytes contain at least one high byte AND form
///     valid UTF-8 (ExifTool.pm:4673); equivalently `str::from_utf8` succeeds
///     with a non-ASCII byte. A pure-ASCII string is `IsUTF8 == 0` ⇒ MacRoman,
///     but MacRoman is byte-identical to ASCII for `< 0x80`, so the result
///     matches UTF-8 either way (keeping ASCII `udta` text unchanged). This
///     fixes the prior bug where `lang 0` was unconditionally UTF-8, corrupting
///     genuine MacRoman bytes (e.g. `Caf\x8e Clip` ⇒ `Café Clip`, not U+FFFD).
///   - **Otherwise (a non-Mac language code, or a UTF-16BE BOM is present):**
///     QuickTime.pm:10508-10511 — a leading `\xfe\xff` BOM selects UTF-16BE,
///     else UTF-8.
///
/// Trailing NULs are stripped (QuickTime.pm:10515 `$str =~ s/\0+$//`).
fn decode_qt_text(bytes: &[u8], lang: u16) -> String {
  let has_bom = bytes.starts_with(&[0xFE, 0xFF]);
  let mut s = if (lang < 0x400 || lang == 0x7fff) && !has_bom {
    // Macintosh language code (QuickTime.pm:10485). For the default language 0,
    // prefer UTF-8 only when the bytes are "obviously UTF8" (IsUTF8 > 0); every
    // other Mac-language case — and the non-UTF8 default case — is MacRoman
    // (CharsetQuickTime). `from_utf8` succeeding is the IsUTF8>0 test (a
    // pure-ASCII string decodes identically under MacRoman, so routing it
    // through MacRoman here is byte-identical).
    if lang == 0
      && let Ok(utf8) = std::str::from_utf8(bytes)
    {
      utf8.to_owned()
    } else {
      crate::charset::decode_macroman(bytes)
    }
  } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
    // QuickTime.pm:10510 — a UTF-16BE BOM.
    decode_utf16be(rest)
  } else {
    // A non-Mac language code with no BOM ⇒ UTF-8 (QuickTime.pm:10511).
    String::from_utf8_lossy(bytes).into_owned()
  };
  // QuickTime.pm:10515 `$str =~ s/\0+$//` — strip trailing NULs.
  while s.ends_with('\0') {
    s.pop();
  }
  s
}

/// Decode a UTF-16BE byte slice (lossy — an odd trailing byte / unpaired
/// surrogate is replaced, matching `Encode`'s tolerance).
fn decode_utf16be(bytes: &[u8]) -> String {
  // `chunks_exact(2)` yields exactly-2-byte slices, so `try_into` is infallible
  // — but stay on the checked path (`#![deny(clippy::indexing_slicing)]`).
  let units = bytes
    .chunks_exact(2)
    .map(|c| u16::from_be_bytes(c.try_into().unwrap_or([0, 0])));
  char::decode_utf16(units)
    .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect()
}

// ── SP2 ISO-8601 date conversion (%iso8601Date, QuickTime.pm:289-311) ─────

/// Normalize an ISO 8601 date string to the ExifTool EXIF date form — a
/// faithful port of `XMP::ConvertXMPDate` followed by the `%iso8601Date`
/// ValueConv's timezone-colon insertion (QuickTime.pm:289-311).
/// `"2024-01-02T03:04:05+0000"` ⇒ `"2024:01:02 03:04:05+00:00"`.
fn convert_iso8601_date(val: &str) -> String {
  // ConvertXMPDate: `^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$`.
  if let Some(converted) = xmp_date_full(val) {
    // %iso8601Date ValueConv: `s/([-+]\d{2})(\d{2})$/$1:$2/` — colon the TZ.
    return insert_tz_colon(&converted);
  }
  // ConvertXMPDate fallback: a bare `^(\d{4})(-\d{2}){0,2}` ⇒ `tr/-/:/`.
  if all_ascii_digits(val.as_bytes().get(0..4)) {
    return val.replace('-', ":");
  }
  val.to_string()
}

/// `ConvertXMPDate`'s full-form branch: `YYYY-MM-DD[T ]HH:MM[:SS] [TZ]` ⇒
/// `YYYY:MM:DD HH:MM[:SS][TZ]`. Returns `None` if the string does not match.
fn xmp_date_full(val: &str) -> Option<String> {
  let b = val.as_bytes();
  // `\d{4}-\d{2}-\d{2}` then `[T ]` then `\d{2}:\d{2}`.
  if !(all_ascii_digits(b.get(0..4))
    && b.get(4) == Some(&b'-')
    && all_ascii_digits(b.get(5..7))
    && b.get(7) == Some(&b'-')
    && all_ascii_digits(b.get(8..10))
    && matches!(b.get(10), Some(&b'T') | Some(&b' '))
    && all_ascii_digits(b.get(11..13))
    && b.get(13) == Some(&b':')
    && all_ascii_digits(b.get(14..16)))
  {
    return None;
  }
  // Slices are bounds-checked above (each `all_ascii_digits`/byte-eq guards
  // the same range), so these `.get(..).?` are `Some`.
  let mut date = String::with_capacity(val.len() + 1);
  date.push_str(val.get(0..4)?);
  date.push(':');
  date.push_str(val.get(5..7)?);
  date.push(':');
  date.push_str(val.get(8..10)?);
  date.push(' ');
  date.push_str(val.get(11..13)?);
  date.push(':');
  date.push_str(val.get(14..16)?);
  let mut rest = val.get(16..)?;
  // optional `(:\d{2})` seconds.
  if rest.as_bytes().first() == Some(&b':') && all_ascii_digits(rest.as_bytes().get(1..3)) {
    date.push_str(rest.get(0..3)?);
    rest = rest.get(3..)?;
  }
  // `\s*(\S*)$` — trailing whitespace then a no-space tail (the timezone).
  let tz = rest.trim_start();
  if tz.contains(char::is_whitespace) {
    return None; // `\S*$` would not match an interior space.
  }
  date.push_str(tz);
  Some(date)
}

/// `%iso8601Date` ValueConv's `s/([-+]\d{2})(\d{2})$/$1:$2/` — insert a colon
/// into a trailing `±HHMM` timezone offset.
fn insert_tz_colon(val: &str) -> String {
  let b = val.as_bytes();
  let n = b.len();
  if let Some(tail) = b.get(n.wrapping_sub(5)..n).filter(|_| n >= 5)
    && matches!(tail.first(), Some(&b'+') | Some(&b'-'))
    && tail
      .get(1..)
      .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
  {
    // `val[..n-2] : val[n-2..]` — both bounds are ASCII byte offsets.
    if let (Some(head), Some(off)) = (val.get(..n - 2), val.get(n - 2..)) {
      return std::format!("{head}:{off}");
    }
  }
  val.to_string()
}

/// `true` when `s` is `Some` non-empty slice of all ASCII digits.
fn all_ascii_digits(s: Option<&[u8]>) -> bool {
  s.is_some_and(|b| !b.is_empty() && b.iter().all(u8::is_ascii_digit))
}

// ── SP2 ISO 6709 GPS coordinate conversion (QuickTime.pm:8884-8909) ───────

/// Decode an ISO 6709 string into a [`QuickTimeGps`]. ExifTool's
/// `ConvertISO6709` (QuickTime.pm:8884-8909) has NO `else` branch — on a string
/// matching none of the three forms it `return $val` UNCHANGED, so the tag is
/// STILL emitted (the raw string under `-n`; `PrintGPSCoordinates`-of-it under
/// `-j`). So a successful decode returns a coordinate-bearing GPS (its
/// `value_conv` = the ValueConv string + numeric lat/lon/alt), while an
/// undecodable-but-PRESENT value returns a [`QuickTimeGps::raw`] carrying the
/// verbatim input and NO numeric coords (faithful: emit the tag, project no
/// `GpsLocation`). Returns `Some` for any present value; an absent atom/key
/// passes its own `None` through (no tag).
fn parse_iso6709(val: &str) -> QuickTimeGps {
  match convert_iso6709(val) {
    Some((lat, lon, alt, value_conv)) => QuickTimeGps::new(value_conv, lat, lon, alt),
    // No form matched: `ConvertISO6709` returns the raw string unchanged.
    None => QuickTimeGps::raw(val.to_string()),
  }
}

/// `ConvertISO6709` (QuickTime.pm:8884-8909) — decode an ISO 6709 coordinate
/// string into `(latitude, longitude, altitude, value_conv_string)`. The three
/// forms are tried in source order. Returns `None` when no form matches.
#[allow(clippy::type_complexity)]
fn convert_iso6709(val: &str) -> Option<(f64, f64, Option<f64>, String)> {
  iso6709_decimal(val)
    .or_else(|| iso6709_dm(val))
    .or_else(|| iso6709_dms(val))
}

/// `+DD.DDD+DDD.DDD+AA.AAA` decimal-degree form (QuickTime.pm:8887). The
/// ValueConv string is `($1+0) . ' ' . ($2+0) [. ' ' . ($3+0)]` — Perl
/// NUMIFIES each matched substring to a double then stringifies it (default
/// ~15 significant digits, `Inf`/`NaN` for non-finite). It is NOT a verbatim
/// string normalization: a token carrying more than ~15 significant fractional
/// digits (e.g. `+12.123456789012345678901`) is f64-rounded by Perl
/// (`12.1234567890123`), so build the ValueConv from the PARSED f64 via
/// [`perl_num`] (consistent with the computed DM/DMS branches) rather than a
/// digit-preserving string transform. For normal coordinates this is identical
/// to Perl (`(+37.3318+0)` = `37.3318` = `perl_num(37.3318)`).
#[allow(clippy::type_complexity)]
fn iso6709_decimal(val: &str) -> Option<(f64, f64, Option<f64>, String)> {
  let (lat_s, rest) = take_signed_decimal(val, 2)?;
  let (lon_s, rest) = take_signed_decimal(rest, 3)?;
  let alt_s = take_signed_decimal(rest, usize::MAX).map(|(a, _)| a);
  let lat = lat_s.parse::<f64>().ok()?;
  let lon = lon_s.parse::<f64>().ok()?;
  let alt = match alt_s.as_deref() {
    Some(a) => Some(a.parse::<f64>().ok()?),
    None => None,
  };
  // ValueConv: `($1+0) . ' ' . ($2+0) [. ' ' . ($3+0)]` — numify-then-stringify.
  let mut vc = std::format!("{} {}", perl_num(lat), perl_num(lon));
  if let Some(a) = alt {
    vc.push(' ');
    vc.push_str(&perl_num(a));
  }
  Some((lat, lon, alt, vc))
}

/// `+DDMM.MMM+DDDMM.MMM+AA.AAA` degree-minute form (QuickTime.pm:8892). The
/// lat/lon are COMPUTED (`$d + $m/60`), so the ValueConv string stringifies the
/// computed float (`"$lat $lon"`) — Perl default-precision numification.
#[allow(clippy::type_complexity)]
fn iso6709_dm(val: &str) -> Option<(f64, f64, Option<f64>, String)> {
  let b = val.as_bytes();
  let (lat_neg, p) = take_sign(b, 0)?;
  let lat_deg = take_fixed_digits(b, p, 2)?;
  let (lat_min, p) = take_minutes(b, p + 2)?;
  let mut lat = lat_deg as f64 + lat_min / 60.0;
  if lat_neg {
    lat = -lat;
  }
  let (lon_neg, p) = take_sign(b, p)?;
  let lon_deg = take_fixed_digits(b, p, 3)?;
  let (lon_min, p) = take_minutes(b, p + 3)?;
  let mut lon = lon_deg as f64 + lon_min / 60.0;
  if lon_neg {
    lon = -lon;
  }
  let alt_s = val
    .get(p..)
    .and_then(|t| take_signed_decimal(t, usize::MAX).map(|(a, _)| a));
  let alt = match alt_s.as_deref() {
    Some(a) => Some(a.parse::<f64>().ok()?),
    None => None,
  };
  let mut vc = std::format!("{} {}", perl_num(lat), perl_num(lon));
  if let Some(a) = alt {
    // `($7+0)` — numify-then-stringify (same f64-rounding as the lat/lon).
    vc.push(' ');
    vc.push_str(&perl_num(a));
  }
  Some((lat, lon, alt, vc))
}

/// `+DDMMSS.SSS+DDDMMSS.SSS+AA.AAA` DMS form (QuickTime.pm:8900).
#[allow(clippy::type_complexity)]
fn iso6709_dms(val: &str) -> Option<(f64, f64, Option<f64>, String)> {
  let b = val.as_bytes();
  let (lat_neg, p) = take_sign(b, 0)?;
  let lat_deg = take_fixed_digits(b, p, 2)?;
  let lat_min = take_fixed_digits(b, p + 2, 2)?;
  let (lat_sec, p) = take_minutes(b, p + 4)?;
  let mut lat = lat_deg as f64 + lat_min as f64 / 60.0 + lat_sec / 3600.0;
  if lat_neg {
    lat = -lat;
  }
  let (lon_neg, p) = take_sign(b, p)?;
  let lon_deg = take_fixed_digits(b, p, 3)?;
  let lon_min = take_fixed_digits(b, p + 3, 2)?;
  let (lon_sec, p) = take_minutes(b, p + 5)?;
  let mut lon = lon_deg as f64 + lon_min as f64 / 60.0 + lon_sec / 3600.0;
  if lon_neg {
    lon = -lon;
  }
  let alt_s = val
    .get(p..)
    .and_then(|t| take_signed_decimal(t, usize::MAX).map(|(a, _)| a));
  let alt = match alt_s.as_deref() {
    Some(a) => Some(a.parse::<f64>().ok()?),
    None => None,
  };
  let mut vc = std::format!("{} {}", perl_num(lat), perl_num(lon));
  if let Some(a) = alt {
    // `($9+0)` — numify-then-stringify (same f64-rounding as the lat/lon).
    vc.push(' ');
    vc.push_str(&perl_num(a));
  }
  Some((lat, lon, alt, vc))
}

/// Parse a leading `[-+]` sign at `b[off]`; returns `(is_negative, off+1)`.
fn take_sign(b: &[u8], off: usize) -> Option<(bool, usize)> {
  match b.get(off)? {
    b'+' => Some((false, off + 1)),
    b'-' => Some((true, off + 1)),
    _ => None,
  }
}

/// Parse exactly `n` ASCII digits at `b[off..off+n]` as a `u32`.
fn take_fixed_digits(b: &[u8], off: usize, n: usize) -> Option<u32> {
  let slice = b.get(off..off.checked_add(n)?)?;
  if slice.is_empty() || !slice.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let mut v = 0u32;
  for &d in slice {
    v = v.checked_mul(10)?.checked_add(u32::from(d - b'0'))?;
  }
  Some(v)
}

/// Parse a `DD(.DDD)?` minutes/seconds component at `b[off..]` — exactly two
/// integer digits then an optional fractional part. Returns the value and the
/// offset just past it.
fn take_minutes(b: &[u8], off: usize) -> Option<(f64, usize)> {
  let int = take_fixed_digits(b, off, 2)?;
  let mut value = int as f64;
  let mut pos = off + 2;
  if b.get(pos) == Some(&b'.') {
    let mut frac = 0.0f64;
    let mut scale = 0.1f64;
    let mut any = false;
    pos += 1;
    while let Some(&d) = b.get(pos) {
      if !d.is_ascii_digit() {
        break;
      }
      frac += f64::from(d - b'0') * scale;
      scale /= 10.0;
      pos += 1;
      any = true;
    }
    if !any {
      return None; // a trailing '.' with no digits is not the minutes form.
    }
    value += frac;
  }
  Some((value, pos))
}

/// Parse a leading `[-+]\d{1,max}(\.\d*)?` signed decimal at the start of `s`,
/// returning the matched substring (verbatim, including sign) and the unparsed
/// tail. `max` caps the integer-digit count (Perl `\d{1,2}`/`\d{1,3}`;
/// `usize::MAX` for the altitude's `\d+`).
fn take_signed_decimal(s: &str, max: usize) -> Option<(String, &str)> {
  let b = s.as_bytes();
  let (_, mut pos) = take_sign(b, 0)?;
  let int_start = pos;
  while pos < b.len() && b.get(pos).is_some_and(u8::is_ascii_digit) && pos - int_start < max {
    pos += 1;
  }
  if pos == int_start {
    return None; // need at least one integer digit.
  }
  // optional `\.\d*`
  if b.get(pos) == Some(&b'.') {
    pos += 1;
    while pos < b.len() && b.get(pos).is_some_and(u8::is_ascii_digit) {
      pos += 1;
    }
  }
  let matched = s.get(..pos)?.to_string();
  Some((matched, s.get(pos..)?))
}

/// Perl default float→string for a COMPUTED coordinate — the `ConvertISO6709`
/// `"$lat $lon"` (DM/DMS branches) and the now-numified decimal branch
/// (`($1+0)` per [`iso6709_decimal`]), plus `PrintGPSCoordinates`'s Below-Sea-
/// Level `-$v[2]`. Perl stringifies a double with up to 15 significant digits
/// then trims — `%.15g` with trailing-zero stripping ([`format_g`]) — but Perl's
/// DEFAULT NV→string differs from C `sprintf("%g")` (which `format_g` models) in
/// two cases that ARE reachable here:
///
/// * **Non-finite** (`±Inf`/`NaN`): Perl prints `Inf` / `-Inf` / `NaN`
///   (titlecase), whereas `format_g` falls through to Rust's lowercase
///   `inf`/`-inf`. Reached on the raw-passthrough path when a malformed `©xyz`
///   carries `inf`/`-inf`/`nan` tokens (`ToDMS(Inf,"N")` → `Inf deg NaN' NaN"`;
///   the `-inf` altitude → `-(-Inf)` = `Inf` in the Below branch).
/// * **Negative zero**: Perl's default stringify normalizes `-0.0` to `0`
///   (e.g. `-($lat=0.0)` prints `0`, and `("-00"+0)` is `0`), whereas
///   `sprintf("%g",-0.0)` (and thus `format_g`) preserves the sign as `-0`.
///   Reached for an all-zero negative coordinate like `-00-000/` (decimal) or
///   `-0000.0-00000.0/` (DM), which Perl renders `0 0`, never `-0 0`.
fn perl_num(val: f64) -> String {
  if let Some(s) = crate::value::perl_nonfinite_str(val) {
    return s.to_string();
  }
  let out = format_g(val, 15);
  // Perl default NV→string has no negative zero (`-0.0` ⇒ `0`); `format_g`
  // models C `%g`, which keeps `-0`. Collapse it to match Perl.
  if out == "-0" {
    return "0".to_string();
  }
  out
}

/// Build the `GPSCoordinates` tag value for a [`QuickTimeGps`]: `-n` (ValueConv)
/// is the `ConvertISO6709` string verbatim; `-j` (PrintConv) is
/// [`print_gps_coordinates`].
fn gps_coordinates_value(gps: &QuickTimeGps, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    TagValue::Str(print_gps_coordinates(gps.value_conv()).into())
  } else {
    TagValue::Str(gps.value_conv().into())
  }
}

/// `PrintGPSCoordinates` (QuickTime.pm:8957-8971) — the `GPSCoordinates`
/// PrintConv. Input is the `ConvertISO6709` ValueConv string: usually the
/// space-separated numeric `lat lon [alt]`, but ALSO (faithfully) a RAW
/// undecodable string passed through by `ConvertISO6709`. ExifTool does
/// `@v = split ' ', $val` then `ToDMS($v[0],"N") . ', ' . ToDMS($v[1],"E")`
/// [`. ', ' . ($v[2]…) . ' Sea Level'` when `defined $v[2]`]. `split ' '`
/// collapses runs of whitespace and drops the leading/trailing empties
/// ([`str::split_whitespace`]); a MISSING field is `undef` and a non-numeric
/// field NUMIFIES to `0` inside `ToDMS` — so e.g. `"hello"` →
/// `"0 deg 0' 0.00\" N, "` (a defined-but-non-numeric latitude, an `undef`
/// longitude rendering as the empty string). Output is `"<lat-DMS> N/S,
/// <lon-DMS> E/W[, <alt> m Above/Below Sea Level]"` via `GPS::ToDMS`
/// ([`crate::exif::gps::to_dms`]).
fn print_gps_coordinates(value_conv: &str) -> String {
  let mut parts = value_conv.split_whitespace();
  let lat = parts.next();
  let lon = parts.next();
  // `$v[2]` — the ValueConv altitude token (already Perl-numified on the decoded
  // path; a raw token on the pass-through path).
  let alt = parts.next();
  // `ToDMS($et, $v[0], 1, "N") . ', ' . ToDMS($et, $v[1], 1, "E")`.
  let mut out = std::format!(
    "{}, {}",
    to_dms_with_ref(lat, 'N', 'S'),
    to_dms_with_ref(lon, 'E', 'W'),
  );
  if let Some(alt_s) = alt {
    // `$prt .= ', ' . ($v[2] < 0 ? -$v[2]." m Below" : $v[2]." m Above") . ' Sea
    // Level'` — emitted whenever `defined $v[2]`. The Above case prints `$v[2]`
    // VERBATIM (its raw/already-numified string); the Below case prints
    // `-$v[2]` — Perl unary negation, which NUMIFIES the token THEN negates
    // THEN stringifies (NOT a string-strip of the leading `-`). For a decimal
    // token this equals sign-stripping, but a non-decimal/exponent token (only
    // reachable on the raw-passthrough path, e.g. `-1e3`) must yield `1000`,
    // not `1e3`. Mirror it via the numeric negate + Perl stringification.
    let alt_n = crate::convert::perl_str_to_f64(alt_s);
    if alt_n < 0.0 {
      out.push_str(&std::format!(", {} m Below Sea Level", perl_num(-alt_n)));
    } else {
      out.push_str(&std::format!(", {alt_s} m Above Sea Level"));
    }
  }
  out
}

/// `GPS::ToDMS($et, $val, 1, $ref)` for the `PrintGPSCoordinates` lat/lon
/// (QuickTime.pm:8961-8962). A MISSING field (`undef` — Perl's `split ' '` left
/// no token) renders as the EMPTY string (`ToDMS` returns `$val` for a zero-
/// length value under `$doPrintConv eq '1'`, GPS.pm:500-503). Otherwise the
/// token is Perl-numified (a non-numeric string → `0`; [`crate::convert::perl_str_to_f64`]) and
/// formatted `q{%d deg %d' %.2f"} . " <ref>"`, where `<ref>` is `ref_pos` for a
/// non-negative value or `ref_neg` for a negative one (`{N=>'S', E=>'W'}`);
/// [`crate::exif::gps::to_dms`] formats the magnitude.
fn to_dms_with_ref(val: Option<&str>, ref_pos: char, ref_neg: char) -> String {
  // `unless (length $val)` — a missing (`undef`) field yields the empty string.
  let Some(s) = val else {
    return String::new();
  };
  let n = crate::convert::perl_str_to_f64(s);
  let r = if n < 0.0 { ref_neg } else { ref_pos };
  std::format!("{} {}", crate::exif::gps::to_dms(n), r)
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed QuickTime metadata — the lib-first output of [`ProcessMov`].
///
/// SP1 carries the core structural atoms; **SP3** adds the embedded
/// timed-metadata GPS layer ([`QuickTimeStreamMeta`]). The payload is the
/// faithful-parse [`QuickTimeMeta`] from [`crate::metadata`]. The `'a`
/// lifetime is phantom — `QuickTimeMeta` owns its data (the structural atoms
/// are decoded into owned strings/Vecs, not borrowed) — but the
/// [`FormatParser`] GAT requires it.
///
/// **D8 — no public fields, accessors only.** Construct only via
/// [`ProcessMov::parse`].
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// The faithful-parse QuickTime structural data.
  qt: QuickTimeMeta,
  /// **SP3** — the embedded QuickTimeStream timed GPS / sensor metadata
  /// (`Image::ExifTool::QuickTime::Stream`, QuickTimeStream.pl). Empty for a
  /// video with no timed metadata (the common case).
  stream: QuickTimeStreamMeta,
  /// **SP4** — the decoded GoPro GPMF metadata. Reached either through the
  /// `gpmd` timed-metadata sample dispatch or the brute-force `GP\x06\0\0`
  /// scan in `mdat` (see [`crate::formats::gopro`]). Empty
  /// ([`GoProMeta::is_empty`]) for a non-GoPro video.
  gopro: GoProMeta,
  /// **SP4** — Android Google CAMM (Camera Motion Metadata) — decoded
  /// through the `camm` MetaFormat dispatch in [`quicktime_stream`]. Empty
  /// ([`CammMeta::is_empty`]) for a non-Android video (or one whose CAMM
  /// track is absent).
  android_camm: CammMeta,
  /// **SP4** — Sony Alpha / FX / RX `rtmd` ("Real-Time MetaData") — decoded
  /// through the `rtmd` MetaFormat dispatch in [`quicktime_stream`]. Empty
  /// ([`SonyRtmdMeta::is_empty`]) for a non-Sony video (or one whose `rtmd`
  /// track is absent). Each timed sample is one `Doc<N>` sub-document carrying
  /// that frame's camera + GPS tags. Faithful port of
  /// `Image::ExifTool::Sony::Process_rtmd` + the `Sony::rtmd` tag table.
  sony_rtmd: SonyRtmdMeta,
  /// **SP4** — Canon EOS R-line / Cinema-line `CTMD` ("Canon Timed
  /// MetaData") — decoded through the `CTMD` MetaFormat dispatch in
  /// [`quicktime_stream`]. Empty ([`CanonCtmdMeta::is_empty`]) for a non-Canon
  /// video (or one whose `CTMD` track is absent). Each timed sample is one
  /// `Doc<N>` sub-document carrying that frame's TimeStamp / FocalInfo /
  /// ExposureInfo. Faithful port of `Image::ExifTool::Canon::ProcessCTMD`
  /// (Canon.pm:10758-10804) + the `Canon::CTMD` / `FocalInfo` / `ExposureInfo`
  /// tag tables (Canon.pm:9790-9887).
  canon_ctmd: CanonCtmdMeta,
  /// **SP4** — Insta360 INSV/INSP trailer metadata (identity / GPS /
  /// exposure-time records). Decoded by [`insta360_fmt::scan_trailer`]
  /// at the end of the QuickTime parse — Insta360 is a file-end
  /// trailer, NOT a `gpmd`/`camm`/`CTMD`-style timed-metadata track.
  /// Empty ([`Insta360Meta::is_empty`]) for a non-Insta360 video.
  /// Faithful port of `Image::ExifTool::QuickTimeStream::ProcessInsta360`
  /// (QuickTimeStream.pl:3252-3478) and the `INSV_MakerNotes` identity
  /// table (QuickTimeStream.pl:696-707). Holds a BOUNDED domain summary +
  /// a borrow of the input bytes (`'a`); the heavy timed-row decode is
  /// deferred to `-ee` emit time (lazy-decode DoS guard).
  insta360: Insta360Meta<'a>,
  /// **SP3** — `true` when an embedded Exif/TIFF block (a `QVMI` / `MVTG` /
  /// `uuid`-Exif atom) was DETECTED but its parse is DEFERRED until the
  /// Exif+GPS port (`exif::parse_exif_block`, PR #36 / `lib/exif-gps`) lands.
  /// Surfaces as an `ExifTool:Warning` so the gap is visible (see
  /// `docs/tracking.md`).
  embedded_exif_deferred: bool,
  /// The detected file type + MIME, derived from `ftyp` (or the MOV
  /// default). Drives [`crate::format_parser::FileTypeFinalize`].
  file_type: &'static str,
  /// MIME type for the resolved `file_type`.
  mime: &'static str,
  /// The FIRST `ProcessMOV` warning, if any — surfaced as `ExifTool:Warning`
  /// (ExifTool emits only the first under default `-j`). **R6/F2**: a
  /// truncated recognized first atom (an `ftyp`/`mdat` whose declared size
  /// overruns EOF) is accepted as QuickTime but stops the walk with a
  /// `Truncated '...' data` warning (QuickTime.pm:10242 / 10590).
  warning: Option<String>,
}

impl Meta<'_> {
  /// The faithful-parse QuickTime structural data (core SP1 atoms).
  #[must_use]
  #[inline(always)]
  pub const fn quicktime(&self) -> &QuickTimeMeta {
    &self.qt
  }

  /// The detected file type (`MOV` / `MP4` / `M4A` / …), derived from the
  /// `ftyp` major / compatible brands (QuickTime.pm:9986-10008).
  #[must_use]
  #[inline(always)]
  pub const fn file_type(&self) -> &'static str {
    self.file_type
  }

  /// The MIME type for [`Self::file_type`].
  #[must_use]
  #[inline(always)]
  pub const fn mime(&self) -> &'static str {
    self.mime
  }

  /// The FIRST `ProcessMOV` warning, if any — surfaced by the
  /// [`AnyMeta::QuickTime`](crate::format_parser) emission arm as the
  /// document-level `ExifTool:Warning` (the `Taggable` stream has no warning
  /// channel; R6/F2, QuickTime.pm:10242/10590). A header-valid but
  /// payload-overrunning recognized first atom is still accepted as QuickTime,
  /// then stops the walk with this warning.
  #[must_use]
  #[inline(always)]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// **SP3** — the embedded QuickTimeStream timed GPS / sensor metadata.
  /// [`QuickTimeStreamMeta::is_empty`] for a video with no timed metadata.
  #[must_use]
  #[inline(always)]
  pub const fn stream(&self) -> &QuickTimeStreamMeta {
    &self.stream
  }

  /// **SP4** — the decoded GoPro GPMF metadata. [`GoProMeta::is_empty`] for
  /// a non-GoPro video (or one whose GoPro records were not located by
  /// either the timed-metadata `gpmd` dispatch or the brute-force
  /// `GP\x06\0\0` `mdat` scan).
  #[must_use]
  #[inline(always)]
  pub const fn gopro(&self) -> &GoProMeta {
    &self.gopro
  }

  /// **SP4** — Android Google CAMM (Camera Motion Metadata).
  /// [`CammMeta::is_empty`] for a non-Android video (or one whose `camm`
  /// metadata track is absent).
  ///
  /// Faithful port of `Image::ExifTool::QuickTime::ProcessCAMM`
  /// (QuickTimeStream.pl:3481-3506) and the seven `%QuickTime::camm<N>` tag
  /// tables (QuickTimeStream.pl:405-572). Populated by the `camm`
  /// MetaFormat dispatch in [`quicktime_stream`].
  #[must_use]
  #[inline(always)]
  pub const fn android_camm(&self) -> &CammMeta {
    &self.android_camm
  }

  /// **SP4** — Sony Alpha / FX / RX `rtmd` ("Real-Time MetaData").
  /// [`SonyRtmdMeta::is_empty`] for a non-Sony video (or one whose `rtmd`
  /// track is absent). Faithful port of `Image::ExifTool::Sony::Process_rtmd`
  /// + the `Image::ExifTool::Sony::rtmd` tag table. Populated by the `rtmd`
  /// MetaFormat dispatch in [`quicktime_stream`].
  #[must_use]
  #[inline(always)]
  pub const fn sony_rtmd(&self) -> &SonyRtmdMeta {
    &self.sony_rtmd
  }

  /// **SP4** — Canon EOS R-line / Cinema-line `CTMD` ("Canon Timed
  /// MetaData"). [`CanonCtmdMeta::is_empty`] for a non-Canon video (or one
  /// whose `CTMD` metadata track is absent). Faithful port of
  /// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) + the
  /// `Image::ExifTool::Canon::CTMD` / `FocalInfo` / `ExposureInfo` tag tables
  /// (Canon.pm:9790-9887). Populated by the `CTMD` MetaFormat dispatch in
  /// [`quicktime_stream`].
  #[must_use]
  #[inline(always)]
  pub const fn canon_ctmd(&self) -> &CanonCtmdMeta {
    &self.canon_ctmd
  }

  /// **SP4** — Insta360 INSV/INSP trailer metadata.
  /// [`Insta360Meta::is_empty`] for a non-Insta360 file (or one whose
  /// trailer signature is absent).
  ///
  /// Faithful port of `Image::ExifTool::QuickTimeStream::ProcessInsta360`
  /// (QuickTimeStream.pl:3252-3478) and the `INSV_MakerNotes` identity
  /// table (QuickTimeStream.pl:696-707). Populated by a direct
  /// file-end pass after the QuickTime moov walk — Insta360 trailers
  /// live AFTER the QuickTime box hierarchy.
  #[must_use]
  #[inline(always)]
  pub const fn insta360(&self) -> &Insta360Meta<'_> {
    &self.insta360
  }

  /// **SP3** — `true` when an embedded Exif/TIFF block was detected but its
  /// parse is deferred until the Exif+GPS port lands (see [`Meta`]).
  #[must_use]
  #[inline(always)]
  pub const fn embedded_exif_deferred(&self) -> bool {
    self.embedded_exif_deferred
  }

  /// Build the normalized [`crate::metadata::MediaMetadata`] projection from
  /// this faithful-parse layer. SP1 populates the `MediaInfo` basics
  /// (duration / dimensions / created / track kinds); **SP3** fills
  /// [`crate::metadata::GpsLocation`] from the FIRST embedded timed-metadata
  /// GPS fix; **SP4** fills [`crate::metadata::CameraInfo`] AND
  /// [`crate::metadata::GpsLocation`] from the decoded GoPro GPMF (model,
  /// serial, firmware, GPS samples). Lens / capture stay `None` for SP2+ and
  /// the embedded-Exif hop to fill.
  #[must_use]
  #[inline(always)]
  pub fn media_metadata(&self) -> crate::metadata::MediaMetadata {
    let mut md = crate::metadata::MediaMetadata::from_quicktime(&self.qt);
    // The per-port projection seam: each `XxxMeta` writes its own Camera /
    // Lens / GPS / Capture contribution into `md`. Order ENCODES the
    // cross-format priority chain (highest-priority FIRST — each port no-ops
    // if a higher-priority source already populated the domain it would
    // write). GoPro on-device GNSS is the HIGHEST GPS tier.
    self.gopro.project_into(&mut md);
    // **SP2** — the `udta` / Keys camera identity, capture date and GPS. Sits
    // BELOW GoPro on-device telemetry but ABOVE the SP3 timed-metadata scan: it
    // is explicit container camera metadata. Keys (the iOS `mdta` ItemList) is
    // preferred over `udta` per ExifTool's ItemList-over-UserData rule
    // (QuickTime.pm:1601).
    self.project_sp2_into(&mut md);
    // **SP4 — Android CAMM** on-device GNSS (camm5/camm6). Sits BELOW GoPro
    // and the explicit SP2 container metadata but ABOVE the generic SP3
    // timed-metadata scan. Set-once per domain (no-ops when a higher-priority
    // source already populated GPS); fills only the GPS domain (CAMM carries
    // no camera-identity record).
    self.android_camm.project_into(&mut md);
    // **SP4 — Sony rtmd** phone-paired GPS (Imaging Edge Mobile) + camera
    // identity/capture. THIRD-HIGHEST tier — below GoPro / CAMM on-device
    // hardware, above the generic SP3 timed-metadata scan. Set-once per domain
    // (no-ops when a higher-priority source already populated camera / GPS).
    self.sony_rtmd.project_into(&mut md);
    // **SP4 — Canon CTMD** camera identity (Make="Canon") + capture / lens from
    // the timed CTMD records. Sits at the SAME tier as Sony rtmd (below GoPro /
    // CAMM on-device hardware, above the generic SP3 timed-metadata scan).
    // Set-once per domain (no-ops when a higher-priority source already
    // populated the domain it would write). Canon CTMD surfaces no GPS today
    // (Canon writes GPS via the embedded Exif TIFF blocks, deferred — #82).
    self.canon_ctmd.project_into(&mut md);
    // **SP4 — Insta360 trailer** camera identity (Make="Insta360") + GPS +
    // exposure-time from the file-end INSV/INSP trailer. FOURTH GPS tier
    // (below GoPro / CAMM / Sony rtmd, above the generic SP3 timed-metadata
    // scan); phone-paired GPS via the Insta360 Studio app. Set-once per
    // domain (no-ops when a higher-priority source already populated the
    // domain it would write).
    self.insta360.project_into(&mut md);
    // SP3 stream sits at the LOWEST tier of the GPS priority chain — only
    // populates when no higher-priority source set `md.gps()`.
    if md.gps().is_none()
      && let Some(fix) = self.stream.first_fix()
    {
      let mut gps = crate::metadata::GpsLocation::new();
      gps
        .update_latitude(fix.latitude())
        .update_longitude(fix.longitude())
        .update_altitude_m(fix.altitude_m())
        .update_timestamp(fix.date_time().map(str::to_string));
      md.set_gps(gps);
    }
    md
  }

  /// **SP2** projection — fold the `udta` / Keys camera identity, capture date
  /// and GPS into `md`. Keys (the iOS `mdta` ItemList) is preferred over `udta`
  /// (QuickTime.pm:1601). Set-once per domain (a higher-priority source already
  /// in `md` is not overwritten); does nothing when neither block decoded.
  fn project_sp2_into(&self, md: &mut crate::metadata::MediaMetadata) {
    use crate::metadata::{CameraInfo, GpsLocation};
    let ud = self.qt.user_data();
    let keys = self.qt.keys();

    // ── CameraInfo (make / model / software) — Keys over UserData ──────
    if md.camera().is_none() {
      let mut cam = CameraInfo::new();
      cam
        .update_make(keys.make().or_else(|| ud.make()).map(str::to_string))
        .update_model(keys.model().or_else(|| ud.model()).map(str::to_string))
        .update_serial(ud.serial_number().map(str::to_string))
        .update_software(
          keys
            .software()
            .or_else(|| ud.software())
            .map(str::to_string),
        );
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }

    // ── Capture date (CreationDate / ContentCreateDate) ────────────────
    // `MediaInfo::created` is set by `from_quicktime` from the `mvhd`
    // CreateDate; the explicit camera capture date (the iOS `creationdate`,
    // else `©day`) is a higher-quality signal, so override it here.
    if let Some(date) = keys.creation_date().or_else(|| ud.content_create_date()) {
      md.media_mut().update_created(Some(date.to_string()));
    }

    // ── GpsLocation — Keys `location.ISO6709` over `©xyz` ──────────────
    // Only a DECODED coordinate (numeric lat/lon) projects a `GpsLocation`; a
    // present-but-undecodable value still emits the `GPSCoordinates` tag (the
    // raw string) but carries no usable lat/lon, so it is skipped here.
    if md.gps().is_none()
      && let Some((lat, lon, alt)) = keys
        .gps()
        .or_else(|| ud.gps())
        .and_then(QuickTimeGps::coords)
    {
      let mut loc = GpsLocation::new();
      loc
        .update_latitude(Some(lat))
        .update_longitude(Some(lon))
        .update_altitude_m(alt);
      md.set_gps(loc);
    }
  }
}

// ===========================================================================
// `ProcessMov` — the lib-first parser
// ===========================================================================

/// QuickTime parser — faithful **SP1 subset** of
/// `Image::ExifTool::QuickTime::ProcessMOV` (QuickTime.pm:9932-10600): the
/// box walker + core structural atoms.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMov;

impl parser_sealed::Sealed for ProcessMov {}

impl FormatParser for ProcessMov {
  /// Leaf format: the typed Meta owns its data (phantom `'a`).
  type Meta<'a> = Meta<'a>;
  /// Leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; QuickTime parsing has no I/O modes).

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    // The leaf `FormatParser::parse` carries no extension channel; the
    // closed dispatch in `format_parser.rs` routes the `%useExt` rule
    // through the extension-aware [`parse_with_ext`] entry instead.
    parse_inner(data, None)
  }
}

/// Lib-first direct entry — borrow-from-input (phantom `'a`; the Meta owns
/// its data, so the lifetime is purely a GAT anchor). Equivalent to
/// [`parse_with_ext`] with no extension (`%useExt` never fires; faithful to a
/// QuickTime buffer with an unknown source name).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data, None)
}

/// Extension-aware QuickTime entry — faithful to `ProcessMOV` reading
/// `$$et{FILE_EXT}` for the `%useExt` rule (QuickTime.pm:240, 10006-10007).
///
/// `ext` is the uppercased, dotless file extension (`$$self{FILE_EXT}`,
/// ExifTool.pm:2966/9096) — e.g. `Some("GLV")`, or `None` when the source has
/// no extension. It is consumed only during this call; the returned [`Meta`]
/// owns its data, so a transient `ext` string may be dropped while the meta
/// lives on.
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today).
pub fn parse_with_ext<'a>(data: &'a [u8], ext: Option<&str>) -> Option<Meta<'a>> {
  parse_inner(data, ext)
}

/// Inner parser. Returns `Ok(None)` (Perl `return 0`) when the first
/// top-level atom is not a recognized `%QuickTime::Main` key
/// (QuickTime.pm:9984).
///
/// `ext` is the uppercased `$$et{FILE_EXT}` (ExifTool.pm:2966), used only for
/// the `%useExt` rule (QuickTime.pm:10006-10007).
fn parse_inner<'a>(data: &'a [u8], ext: Option<&str>) -> Option<Meta<'a>> {
  // QuickTime.pm:9966 `$raf->Read($buff,8) == 8 or return 0` — the FIRST step
  // is a plain 8-byte read; QuickTime.pm:9973 `($size, $tag) = unpack('Na4',
  // $buff)` then yields the RAW 32-bit `$size` and the 4-byte `$tag`.
  //
  // **R8/F1.** ExifTool gates / finalizes the file type entirely from this
  // 8-byte read, BEFORE the per-atom `for(;;)` loop validates the declared
  // size (QuickTime.pm:10035-10075). So first-atom RECOGNITION must run on
  // the raw `(size32, tag)` directly — NOT on `read_atom_header`'s
  // post-validation outcome. A first atom whose declared size is structurally
  // invalid (`size` 2-7, a truncated extended-size header, `size == 1` with
  // an out-of-range 64-bit value) STILL carries a usable 4-byte type: the
  // type passes the QuickTime.pm:9984 gate, `SetFileType` runs, and only
  // then does the size check set `$warnStr` and `last`. So such a file is
  // accepted as QuickTime with the bundled warning, never `Ok(None)`.
  if data.len() < 8 {
    return None; // QuickTime.pm:9966 `$raf->Read($buff,8) == 8 or return 0`.
  }
  // The `data.len() < 8` guard proves both reads succeed; `?` on the
  // impossible miss returns `None`, matching that guard (byte-identical).
  let raw_size32 = be_u32(data, 0)?;
  let first: [u8; 4] = data.get(4..8)?.try_into().ok()?;

  // QuickTime.pm:9984 `$$tagTablePtr{$tag} or return 0` — the first top-level
  // atom's 4-byte TYPE must be a recognized Main-table key. Keyed on `$tag`
  // ALONE, never on `$size` (so an invalid/size-0/truncated size still
  // passes if the type is recognized).
  if !is_known_top_level(&first) {
    return None;
  }

  // QuickTime.pm:9986-10012: resolve the file type from the RAW first
  // header. The `ftyp` brand path runs ONLY for `$tag eq 'ftyp' and $size >=
  // 12` — and `$size` here is the RAW 32-bit value (the extended-size decode
  // at QuickTime.pm:10058+ happens later, INSIDE the loop). So a short
  // `ftyp` (`size32 < 12`, e.g. 8/11) AND an extended-size `ftyp` (`size32
  // == 1`) BOTH fail `$size >= 12` and take the `else { SetFileType() }` ⇒
  // MOV branch (verified vs bundled). Only a `ftyp` whose RAW 32-bit size is
  // `>= 12` drives the sub-type from its brands.
  //
  // **R6/F2.** A TRUNCATED first `ftyp` (`size32 >= 12` but the brand payload
  // overruns EOF) follows QuickTime.pm:9988-10004: `$raf->Read($buff,$size-8)`
  // comes up short, the brand-detection `if` body is skipped, `$fileType`
  // stays undef, and `$fileType or $fileType = 'MP4'` defaults it to MP4.
  let (mut file_type, mut mime): (&'static str, &'static str) =
    if &first == b"ftyp" && raw_size32 >= 12 {
      // The `ftyp` brand path: read whatever payload is available. A full
      // `Atom` gives the whole brand list; a `TruncatedAtom` (overrun) gives
      // nothing readable ⇒ `file_type_from_ftyp` of an empty/short slice
      // defaults to MP4, matching the bundled short-read default.
      match read_atom_header(data, 0, true) {
        Some(HeaderOutcome::Atom(header, _)) => file_type_from_ftyp(
          data
            .get(header.payload_start..header.payload_end)
            .unwrap_or_default(),
        ),
        // A truncated `ftyp` with `size32 >= 12`: brand read fails ⇒ MP4
        // (QuickTime.pm:10004). `read_atom_header` cannot surface a
        // size-0/Malformed `ftyp` here (`size32 >= 12` excludes both).
        _ => ("MP4", "video/mp4"),
      }
    } else {
      // QuickTime.pm:10012 `else { SetFileType() }` ⇒ MOV: a non-`ftyp` first
      // atom, a short `ftyp` (`size32 < 12`), or an extended-size `ftyp`.
      ("MOV", "video/quicktime")
    };

  // **R11/F1.** The `%useExt` rule (QuickTime.pm:240, 10006-10007). ExifTool
  // applies it INSIDE the `if ($tag eq 'ftyp' and $size >= 12)` branch, after
  // the ftyp-derived `$fileType` and BEFORE `SetFileType` — so it can promote
  // `MP4` (the only `%useExt` mapped value) to the extension type. The lone
  // table entry is `GLV => 'MP4'`: a `.glv` file with an MP4-compatible ftyp
  // becomes `File:FileType=GLV`. Because `%useExt` only ever maps to `MP4` and
  // the non-`ftyp` `else` branch above yields `MOV` (never `MP4`), running the
  // promotion here is equivalent to running it inside the ftyp branch — the
  // `MOV` result can never satisfy `use_ext`'s `file_type == "MP4"` predicate.
  // The MIME is recomputed exactly as `SetFileType($fileType,
  // $mimeLookup{$fileType} || 'video/mp4')` would: `%mimeLookup` has no `GLV`
  // entry, so it falls back to `video/mp4` (which the MP4 source already
  // carried). This MUST run BEFORE the post-walk MP4→M4A override below, which
  // is gated on `$$et{FileType} eq 'MP4'` (QuickTime.pm:10619) — once promoted
  // to GLV the audio-only override no longer fires (verified vs bundled).
  if let Some(promoted) = use_ext(file_type, ext) {
    file_type = promoted;
    // QuickTime.pm:10008 `$mimeLookup{$fileType} || 'video/mp4'` for `GLV`.
    mime = "video/mp4";
  }

  // Walk the TOP-LEVEL atoms in FILE ORDER, in TWO passes (R3-F2). The movie
  // `TimeScale` set by `mvhd`'s RawConv is a single GLOBAL slot, last-wins
  // across EVERY `mvhd` in the file (including a second top-level `moov`); the
  // `TrackDuration` durationInfo ValueConv runs at OUTPUT against that FINAL
  // value. So we must learn the final TimeScale (and the rest of the
  // mvhd-level state) BEFORE converting any TrackDuration. `pos` is the
  // absolute file offset, so an atom's `payload_start` is the file offset used
  // for `mdat-offset`. F5's top-level-vs-contained size-0 distinction is
  // threaded via `read_atom_header(.., top_level=true)`.
  //
  // **SP4** — Insta360 INSV/INSP trailer (QuickTime.pm:9975-9979 +
  // QuickTime.pm:10669-10673 + QuickTimeStream.pl:3258-3478). ExifTool's
  // `IdentifyTrailers` (QuickTime.pm:9897-9926) runs up-front and `ProcessMOV`
  // then walks the top-level atoms BY THEIR DECLARED SIZE, stopping IN-LOOP
  // after the atom whose end reaches the trailer (`$lastPos >= $$trailer[1]`,
  // QuickTime.pm:10597-10602). The trailer-processing loop afterward SKIPS a
  // trailer an atom already consumed (`next if $lastPos > $$trailer[1]`,
  // :10656). So we do NOT pre-bound the box view to the trailer's start (which
  // would truncate an atom that legitimately spans into the trailer, e.g. an
  // over-large `moov`, and mis-report it). Instead we compute the box region's
  // effective END from the in-loop stop — the declared end of the atom that
  // tripped the trailer check — and gate Insta360 EXTRACTION on whether the box
  // walk consumed the trailer.
  //
  // `IdentifyTrailers` is a BACKWARD linked-list walk: each block at EOF is
  // classified (Insta360 / LigoGPS / MIE) and stepped past by its declared
  // length, so an Insta360 trailer is found EVEN when it is not the final block
  // (followed by a LigoGPS/MIE trailer). exifast extracts only the Insta360
  // trailer; the others are recognized solely to walk past them + bound the box
  // scan. `trailers` is HEAD-FIRST (earliest trailer first).
  let trailers = insta360_fmt::identify_trailers(data);
  let mut insta360_meta = Insta360Meta::new();
  // The HEAD (earliest) trailer drives BOTH the box-walk stop and the positional
  // warning (QuickTime.pm:10599-10600 use `$$trailer[1]`/`[0]`/`[2]` of the
  // linked-list head). Record its `(name, start, len)` for the always-on
  // positional warning (emitted in `emit_insta360`); the box walk stops where
  // the trailer chain begins.
  let head_signed_start: Option<i64> = trailers.first().map(|head| {
    insta360_meta.set_head_trailer(head.kind().as_str(), head.start(), head.len());
    // The head's SIGNED start (`$$trailer[1]`, QuickTime.pm:9920). `start` is
    // stored u64-WRAPPED, so `as i64` recovers Perl's negative value on a
    // bad-size trailer (`trailerLen > file size`) — preserving the
    // first-atom-only stop in that case.
    head.start() as i64
  });
  // Walk the top-level atoms by declared size to find the in-loop trailer stop
  // (QuickTime.pm:10597-10602). `last_pos` is the position after the LAST
  // COMPLETE atom (= ExifTool `$lastPos`, updated only at the bottom of the loop
  // — a truncated/malformed atom that aborts mid-loop does NOT advance it);
  // `box_region_end` is the furthest file offset the box walk's atom reads reach
  // (the bound every downstream box-region scan uses). For a trailer-less file
  // `head_signed_start` is `None` and `box_region_end == data.len()`.
  let (last_pos, box_region_end) = box_walk_extent(data, head_signed_start);
  // The bounded view the box walk + the downstream scans see. In the NORMAL case
  // an atom ends exactly at (or before) the trailer start, so `box_region_end ==
  // trailer.start` and the trailer's bytes are never read. In the SPANNING case
  // an atom's declared size overruns the trailer start, so `box_region_end` is
  // that atom's declared end (≥ trailer.start, possibly EOF) — the atom is read
  // in full (matching bundled), and a truncated child inside it warns. For a
  // trailer-less file `box_region_end == data.len()`.
  let scan_end = box_region_end;
  let scan_data: &[u8] = data.get(..scan_end).unwrap_or(data);
  // EXTRACT the Insta360 trailer only when the box walk did NOT consume it
  // (`$lastPos <= $$trailer[1]`, the negation of QuickTime.pm:10656's
  // `next if $lastPos > $$trailer[1]`). When an atom SPANNED the trailer the
  // reference still emits the positional warning (via `head_trailer` above, then
  // suppressed by the box-walk's own earlier `ExifTool:Warning` under
  // priority-0 first-wins) but does NOT re-process the trailer as a trailer.
  if let Some(entry) = trailers.iter().find(|e| e.kind().is_insta360()) {
    let entry_signed_start = entry.start() as i64;
    if (last_pos as i64) <= entry_signed_start {
      // Scan the FIRST Insta360 trailer in the chain (its body ends at `start +
      // len`, which == EOF for a standalone trailer at the file end). A bad-size
      // trailer (`trailerLen > file size`) has a NEGATIVE signed start, so the
      // gate is false and we skip extraction — the positional warning still
      // fires off `head_trailer`, and bundled likewise decodes no records.
      let entry_end = entry
        .start()
        .saturating_add(entry.len())
        .min(data.len() as u64) as usize;
      insta360_fmt::scan_trailer(data, entry_end, &mut insta360_meta);
      insta360_meta.set_trail_end(entry_end);
    }
  }

  // Pass 1: ftyp + every moov's mvhd (last-wins TimeScale) + mdat.
  let mut qt = QuickTimeMeta::new();
  // R6/F2: the FIRST `ProcessMOV` warning (`ExifTool:Warning` under `-j`).
  let mut warning: Option<String> = None;
  let mut pos = 0usize;
  while pos < scan_end {
    match read_atom_header(scan_data, pos, true) {
      Some(HeaderOutcome::Atom(header, next)) => {
        let body_end = header.payload_end.min(scan_data.len());
        // `body_end <= scan_data.len()` and a well-formed `payload_start <=
        // body_end`, so `.get` is `Some` (byte-identical); a hostile overrun
        // yields an empty body (no-panic).
        let body = scan_data
          .get(header.payload_start..body_end)
          .unwrap_or_default();
        match &header.atom_type {
          b"ftyp" => decode_ftyp(body, &mut qt),
          b"moov" => {
            // `header.payload_start` is the moov body's absolute file offset, so
            // a SPANNING moov's truncated UNKNOWN child reports its correct
            // `at offset 0x%x` (FIX 2 / QuickTime.pm:10590).
            decode_moov_mvhd(body, header.payload_start, &mut qt, &mut warning);
            // **SP2** — the `moov/udta` camera atoms + `moov/meta` Keys/ItemList
            // metadata. Decoded in Pass 1 (alongside `mvhd`) so the typed
            // UserData/Keys are populated before emission; the box walk runs at
            // the moov child depth (1, one level below the top-level walk).
            decode_moov_udta_meta(1, body, &mut qt, &mut warning);
          }
          // The top-level `frea` atom (Kodak PixPro / Rexing — QuickTime.pm:610
          // `%QuickTime::Main` ⇒ `Image::ExifTool::Kodak::frea`). Decoded in
          // Pass 1 so `KodakVersion` is populated BEFORE the `mdat` freeGPS
          // scan (which reads it to apply the Type-17b lat/lon scaling).
          b"frea" => decode_frea(body, &mut qt, &mut warning),
          b"mdat" => {
            // QuickTime.pm:10158-10160 — the synthetic `mdat-size`/`mdat-offset`
            // tags: payload byte count + absolute payload file offset.
            qt.set_media_data_size(Some((body_end - header.payload_start) as u64));
            qt.set_media_data_offset(Some(header.payload_start as u64));
          }
          _ => {}
        }
        if next <= pos {
          break; // never advance backwards (hostile size)
        }
        pos = next;
      }
      Some(HeaderOutcome::ExtendsToEof {
        atom_type,
        payload_start,
      }) => {
        // QuickTime.pm:10044-10056: a top-level size-0 atom. Record the
        // synthetic `mdat-size`/`mdat-offset` ONLY for `mdat` (the lone table
        // entry with those tags), then STOP — the payload is NOT decoded, so a
        // size-0 `moov` (or any other atom) contributes NOTHING here (R4/F1).
        if &atom_type == b"mdat" {
          qt.set_media_data_size(Some((scan_data.len() - payload_start) as u64));
          qt.set_media_data_offset(Some(payload_start as u64));
        }
        break;
      }
      Some(HeaderOutcome::TruncatedAtom {
        atom_type,
        payload_start,
        declared_payload_len,
      }) => {
        // R6/F2: a top-level atom whose 8-/16-byte header was read but whose
        // declared payload overruns EOF. ExifTool records the synthetic
        // `$tag-size`/`$tag-offset` from the DECLARED `$size` BEFORE the short
        // `$raf->Read` (QuickTime.pm:10156-10158), then the read fails and the
        // `Truncated '...' data` warning + `last` stops the walk. So `mdat`
        // size/offset come from the declared size; a truncated `moov` (or any
        // other atom) contributes nothing — its payload is never decoded.
        if &atom_type == b"mdat" {
          // R12/F1: `declared_payload_len` is the full 64-bit `$size`, so a
          // real >2GB `mdat` records its true `MediaDataSize` (no usize cast).
          qt.set_media_data_size(Some(declared_payload_len));
          qt.set_media_data_offset(Some(payload_start as u64));
          // `mdat` carries `Unknown => 1` (QuickTime.pm:688), so `GetTagInfo`
          // returns undef without the Unknown option ⇒ the seek-past `else`
          // branch fires `Truncated '${t}' data at offset 0x%x`
          // (QuickTime.pm:10590), where `$lastPos` is the atom's file offset.
          warning.get_or_insert_with(|| std::format!("Truncated 'mdat' data at offset {pos:#x}"));
        } else {
          // A recognized atom WITH a real tagInfo (e.g. `ftyp`, `moov`) takes
          // the `$raf->Read($val,$size)` path; the short read yields
          // `Truncated '${t}' data (missing $missing bytes)`
          // (QuickTime.pm:10242). `$missing = $size - $raf->Read($val,$size)`.
          //
          // For the FIRST atom when it is `ftyp` the file-type detection
          // ALREADY consumed every available payload byte via the
          // `$raf->Read($buff, $size-8)` pre-read (QuickTime.pm:9988) whose
          // `Seek`-back is gated on a SUCCESSFUL read — so a short pre-read
          // leaves the RAF at EOF and the loop's subsequent `Read` returns 0
          // bytes ⇒ `$missing` is the WHOLE declared payload. Any other
          // recognized atom is not pre-read, so `$missing` is the declared
          // payload minus the bytes still available before EOF.
          let available = scan_data.len().saturating_sub(payload_start) as u64;
          let consumed_by_ftyp_preread = pos == 0 && &atom_type == b"ftyp";
          let missing = if consumed_by_ftyp_preread {
            declared_payload_len
          } else {
            declared_payload_len.saturating_sub(available)
          };
          let tag = String::from_utf8_lossy(&atom_type).into_owned();
          warning.get_or_insert_with(|| {
            std::format!("Truncated '{tag}' data (missing {missing} bytes)")
          });
        }
        break;
      }
      Some(HeaderOutcome::Malformed { warning: w }) => {
        // R8/F1: a top-level atom whose 8-byte header was read but whose
        // declared size is structurally invalid (`size` 2-7 / truncated
        // extended-size header / out-of-range 64-bit size). ExifTool's
        // per-atom loop sets `$warnStr` and `last`s (QuickTime.pm:10058-
        // 10075); `$warnStr` is then emitted via `$et->Warn` at the end of
        // `ProcessMOV`. For the FIRST atom `$lastTag` is empty, so it is the
        // plain warning (not the `Unknown trailer with ...` mdat/moov wrap).
        warning.get_or_insert_with(|| w.to_string());
        break;
      }
      // `read_atom_header(.., top_level=true)` never yields `Terminator` (that
      // is the contained-only CNTH branch); stop defensively if it ever does.
      Some(HeaderOutcome::Terminator) | None => break,
    }
  }

  // Pass 2: decode every moov's `trak` against the FINAL global movie
  // TimeScale (in file order, so TrackN numbering is unchanged).
  let movie_ts = qt.time_scale();
  let mut pos = 0usize;
  while pos < scan_end {
    // A top-level size-0 atom (`ExtendsToEof`) STOPS the walk with NO payload
    // decoded — never decode `trak`s out of a size-0 `moov` (R4/F1).
    let Some(HeaderOutcome::Atom(header, next)) = read_atom_header(scan_data, pos, true) else {
      break;
    };
    let body_end = header.payload_end.min(scan_data.len());
    // `body_end <= scan_data.len()` and a well-formed `payload_start <=
    // body_end`, so `.get` is `Some` (byte-identical); a hostile header that
    // overruns its declared end yields an empty body (no-panic).
    let body = scan_data
      .get(header.payload_start..body_end)
      .unwrap_or_default();
    if &header.atom_type == b"moov" {
      decode_moov_trak(body, movie_ts, &mut qt, &mut warning);
    }
    if next <= pos {
      break;
    }
    pos = next;
  }

  // **R10/F1.** Post-walk MP4→M4A override (QuickTime.pm:10619-10624):
  //
  // ```perl
  // if ($topLevel and $$et{FileType} and $$et{FileType} eq 'MP4' and
  //     $$et{save_ftyp} and $$et{HasHandler} and $$et{save_ftyp} =~ /^(iso|dash|mp42)/ and
  //     $$et{HasHandler}{soun} and not $$et{HasHandler}{vide})
  // {
  //     $et->OverrideFileType('M4A', 'audio/mp4');
  // }
  // ```
  //
  // `$$et{save_ftyp}` is the `ftyp` MAJOR brand (the first 4 bytes,
  // QuickTime.pm:9990-9991) — here `qt.major_brand()`. `$$et{HasHandler}{$h}`
  // records every `hdlr` HandlerType seen (QuickTime.pm:8414); `soun`/`vide`
  // only ever appear as the MEDIA handler in `trak/mdia/hdlr` (SP1's sole
  // `hdlr` decode site), so the per-track handler codes are the faithful
  // source for these two keys. The override fires only when the resolved type
  // is MP4, the major brand starts with `iso`/`dash`/`mp42`, at least one
  // track is a `soun` handler, and NO track is a `vide` handler — flipping the
  // common audio-only `.m4a` (e.g. `ftyp isom` + a lone `soun` track) to
  // `File:FileType=M4A` / `File:MIMEType=audio/mp4`. `OverrideFileType`
  // additionally rewrites `FileTypeExtension` to `uc($fileTypeExt{M4A} //
  // 'M4A') = 'M4A'` (PrintConv `lc` ⇒ `m4a`); the engine derives that from
  // the new `file_type` via the shared `resolve_file_type`, so setting the
  // type + MIME here is sufficient (verified vs bundled ExifTool 13.58).
  if file_type == "MP4"
    && qt
      .major_brand()
      .is_some_and(|b| b.starts_with("iso") || b.starts_with("dash") || b.starts_with("mp42"))
    && qt.tracks().iter().any(|t| t.handler_code() == Some("soun"))
    && !qt.tracks().iter().any(|t| t.handler_code() == Some("vide"))
  {
    file_type = "M4A";
    mime = "audio/mp4";
  }

  // **SP3** — extract the embedded QuickTimeStream timed GPS / sensor
  // metadata (QuickTimeStream.pl `ProcessSamples`). ExifTool gates this on
  // the `ExtractEmbedded` option; exifast always decodes the self-contained
  // timed-metadata atoms (the camera-metadata product goal, see
  // `docs/tracking.md`). `GPSDateTime` synthesis uses the `mvhd` CreateDate
  // RAW 1904-epoch seconds — the `qt_date_string`-formatted value can't be
  // re-parsed, so we re-derive the raw count from the first decoded `mvhd`
  // via `qt`'s stored Duration timescale-count is unrelated; instead the
  // stream walker is given the raw CreateDate it can recover from the file.
  // Bounded to `scan_data` (the box hierarchy ends at the Insta360 trailer's
  // start) so a trailer's bytes are never mis-read as a top-level atom.
  let create_date_raw = first_moov_create_date_raw(scan_data);
  // The Kodak `frea`-atom `KodakVersion` global (set in Pass 1) is visible to
  // EVERY `ProcessFreeGPS` call — including the `moov`-level `gps ` offset-box
  // path inside `extract_stream` — so a Rexing dashcam that references its
  // freeGPS blocks from that box (rather than burying them in `mdat`) also gets
  // the Type-17b scaling. Threaded as a `&str` borrow (mvhd/frea are already
  // decoded into `qt` at this point).
  let kodak_version = qt.kodak_frea().version();
  // **SP4** — the GoPro `gpmd` MetaFormat dispatch in [`quicktime_stream`]
  // fills `gopro_meta` for each GoPro-style timed-metadata sample. The
  // same meta is then ALSO populated by the `moov/udta/GPMF` atom walk and
  // by the brute-force `GP\x06\0\0` scan (some GoPro firmware writes
  // unreferenced GPMF records in `mdat` outside of a metadata track).
  let mut gopro_meta = GoProMeta::new();
  // **SP4 — Android CAMM**: the `camm` MetaFormat dispatch in
  // [`quicktime_stream`] populates `camm_meta` for each timed-metadata sample
  // whose track carries Google Camera Motion Metadata. Threaded ALONGSIDE the
  // GoPro meta + the `found_embedded`/`kodak_version` state below (the camm arm
  // is purely additive to the existing per-format sample dispatch).
  let mut camm_meta = CammMeta::new();
  // **SP4 — Sony rtmd** accumulator, populated by the `rtmd` MetaFormat dispatch
  // in [`quicktime_stream`] for each timed-metadata sample of a Sony video's
  // `rtmd` track (one `SonyRtmdSample` per sample). Additive to the existing
  // per-format sample dispatch, exactly like `camm_meta`.
  let mut sony_rtmd_meta = SonyRtmdMeta::new();
  // **SP4 — Canon CTMD** accumulator, populated by the `CTMD` MetaFormat
  // dispatch in [`quicktime_stream`] for each timed-metadata sample of a Canon
  // CR3 / CRM / MOV / MP4 video's `CTMD` track (one `CanonCtmdSample` per
  // sample). Additive to the existing per-format sample dispatch, exactly like
  // `sony_rtmd_meta`.
  let mut canon_ctmd_meta = CanonCtmdMeta::new();
  // `found_embedded` is ExifTool's `$$et{FoundEmbedded}` (QuickTimeStream.pl:1650):
  // set when a `moov`-level `gps ` box dispatched a `freeGPS ` block into
  // `ProcessFreeGPS`, OR when a GoPro source entered `ProcessGoPro`
  // (GoPro.pm:822) — a `gpmd` GoPro timed-metadata sample OR a `moov/udta/GPMF`
  // atom. It is NOT set by the generic per-sample `FoundSomething` output
  // (gps0/gsen/`GPS `/3gf/mebx — QuickTimeStream.pl:967-973). It is the sole
  // gate for the `mdat` scan below.
  //
  // **SP4 (R9).** BOTH GoPro sources — the `gpmd` timed-metadata samples AND
  // the `moov/udta/GPMF` atoms (QuickTime.pm:2132-2135) — are now processed by
  // [`quicktime_stream::extract_stream`] inside ONE ordered moov-child walk
  // ([`quicktime_stream::walk_moov`]), each at its atom position, populating
  // this single `gopro_meta`. ExifTool's `for(;;)` walk (QuickTime.pm:10032)
  // reaches a `udta/GPMF` when it descends that `udta` child
  // (`ProcessDirectory`, QuickTime.pm:10359) and a `trak`'s `gpmd` samples when
  // that `trak`'s `stbl` box exits (QuickTime.pm:10369-10371) — so they
  // interleave by atom layout, and the flat `gopro_meta` accumulates in walk
  // order instead of the prior fixed "all `gpmd` then all `udta/GPMF`" post-
  // pass. NOTE (oracle-verified, ExifTool 13.59): when a `moov` carries BOTH
  // sources ExifTool keeps them in DIFFERENT groups (`Track<N>:` for `gpmd`
  // vs `GoPro:` for `udta/GPMF`), so there is no single cross-source last-wins
  // to match — the flat `GoProMeta` collapses both, a divergence this ordered
  // walk does not by itself resolve (see `walk_moov` doc). The walk completes
  // BEFORE the `mdat` scan, and a visited `udta/GPMF` (like a
  // `gpmd` sample) folds into `found_embedded`, so the `mdat` scan is still
  // suppressed by the mere PRESENCE of any dispatched GoPro source
  // (`return if $$et{FoundEmbedded}`, QuickTimeStream.pl:3689). A direct
  // `moov/GPMF` child stays IGNORED (GPMF is reached only via `udta` — R8);
  // the R7 multi-moov order is preserved (the walk runs per top-level `moov`
  // in file order).
  // Bounded to `scan_data`: ExifTool's stream sources (the moov-level
  // `gps `/timed-metadata trak walk AND the `mdat` `ScanMediaData` brute-force
  // freeGPS/GP6 scan) all live inside the QuickTime box hierarchy, which ends
  // at the Insta360 trailer's start — the trailer's bytes must not be scanned
  // for a freeGPS signature.
  let (mut stream, found_embedded) = quicktime_stream::extract_stream(
    scan_data,
    create_date_raw,
    kodak_version,
    &mut gopro_meta,
    &mut camm_meta,
    &mut sony_rtmd_meta,
    &mut canon_ctmd_meta,
  );

  // **SP3.5** — `ProcessFreeGPS` + brute-force scan of `mdat`
  // (QuickTimeStream.pl `ScanMediaData`:3679-3789). Faithful: ExifTool only
  // scans mdat when no `freeGPS ` block was already decoded — i.e. when
  // `$$et{FoundEmbedded}` is unset (QuickTimeStream.pl:3689 `return if
  // $$et{FoundEmbedded}`), which a `gps `-box decode sets (:1650). It is NOT
  // gated on per-sample output: a movie with a `gsen`/`gps0`/`GPS `/`3gf`/`mebx`
  // timed-metadata stream but NO decoded freeGPS still gets `mdat` scanned, so a
  // `freeGPS ` block buried in padding alongside such a stream is recovered
  // (action-cams, dashcams, drones) — see `quicktime_freegps`.
  //
  // **SP4** — the brute-force scanner ALSO reports GoPro `GP\x06\0\0`
  // records (QuickTimeStream.pl:3717-3748); each one re-dispatches into
  // `Image::ExifTool::GoPro::ProcessGP6` which parses the contained GPMF
  // KLV. exifast routes both through this single call: `scan_media_data`
  // now appends to the freeGPS-style stream samples AND fills `gopro`.
  if let (Some(off), Some(size)) = (qt.media_data_offset(), qt.media_data_size()) {
    let already = found_embedded;
    // `-ee`-only source (the brute-force `mdat` scan runs inside
    // `ScanMediaData`, fully `-ee` gated): watermark-then-stamp `FreeGpsScan`
    // onto exactly the fixes the scan appends so the emitter keeps them gated
    // (no no-`ee` fix, no file-level warning).
    let scan_start = stream.gps_sample_count();
    // Bounded to `scan_data` (the box hierarchy / mdat end at the Insta360
    // trailer's start): the brute-force freeGPS scan + its first-GP6 window
    // expansion must NOT reach into the trailer, which is `ProcessInsta360`'s
    // domain — re-scanning those bytes as freeGPS would double-extract. For a
    // trailer-less file `scan_data == data`, so this is a no-op. Passing
    // `scan_data` clamps both the `size` window and the GP6 EOF-expansion to
    // `scan_end` regardless of the declared `size`.
    quicktime_freegps::scan_media_data(
      scan_data,
      off,
      size,
      create_date_raw,
      kodak_version,
      already,
      &mut stream,
      &mut gopro_meta,
    );
    stream.stamp_gps_origin_from(scan_start, crate::metadata::GpsOrigin::FreeGpsScan);
    // The brute-force `mdat` freeGPS scan runs LAST in ExifTool's walk
    // (`ScanMediaData`, after `ProcessMOV`), `++DOC_COUNT` per fix it appends:
    // stamp the GLOBAL doc onto exactly those fixes, continuing the shared
    // counter after every earlier source (P1 + cross-source #214).
    stream.stamp_gps_doc_from(scan_start);
  }

  // **SP3** — embedded Exif/TIFF hop. ExifTool dispatches certain atoms
  // (`QVMI` Casio, `MVTG` FujiFilm, `uuid`-Exif) to
  // `Image::ExifTool::Exif::ProcessExif` (QuickTime.pm:2058-2110). exifast's
  // Exif IFD parser is on the UNMERGED PR #36 (`lib/exif-gps`); detect the
  // block here and DEFER the parse.
  // DEFERRED: wire exif::parse_exif_block once #36 (Exif+GPS) merges.
  // Bounded to `scan_data` (the embedded-Exif atoms live in `moov`/`udta`,
  // inside the box hierarchy — never in the file-end trailer).
  let embedded_exif_deferred = detect_embedded_exif(scan_data);

  // **SP4** — the Insta360 INSV/INSP trailer (`insta360_meta`) was already
  // decoded up-front (before the box walk), because `IdentifyTrailers`
  // (QuickTime.pm:9897-9926) bounds the atom walk to the trailer's start. See
  // the `scan_trailer` call near Pass 1.

  Some(Meta {
    qt,
    stream,
    gopro: gopro_meta,
    android_camm: camm_meta,
    sony_rtmd: sony_rtmd_meta,
    canon_ctmd: canon_ctmd_meta,
    insta360: insta360_meta,
    embedded_exif_deferred,
    file_type,
    mime,
    warning,
  })
}

/// Recover the FIRST `moov`/`mvhd` CreateDate as the RAW 1904-epoch second
/// count (QuickTime.pm:1355-1374 — the `timeInfo` RawConv input, BEFORE the
/// epoch subtraction). Used by [`quicktime_stream`] for `GPSDateTime`
/// synthesis (`SetGPSDateTime` adds the raw create-date to the sample time).
///
/// This re-walks for `moov`→`mvhd` because [`QuickTimeMeta`] stores only the
/// already-formatted `CreateDate` string, which cannot be re-parsed back to
/// the raw count. `None` when no `mvhd` carried a (non-zero) create date.
fn first_moov_create_date_raw(data: &[u8]) -> Option<u64> {
  let mut found: Option<u64> = None;
  let mut pos = 0usize;
  while pos < data.len() {
    let Some(HeaderOutcome::Atom(header, next)) = read_atom_header(data, pos, true) else {
      break;
    };
    if &header.atom_type == b"moov" {
      let body = data
        .get(header.payload_start..header.payload_end.min(data.len()))
        .unwrap_or_default();
      // Top-level scan (the file loop above) — depth 0.
      walk_atoms(0, body, 0, body.len(), &mut None, |inner, ibody, _w| {
        if &inner.atom_type == b"mvhd"
          && let Some(&version) = ibody.first()
        {
          // mvhd CreateDate (idx 1): int32u at byte 4 (v0) / int64u at byte
          // 4 (v1, the truthy-version-widened layout).
          let raw = if version != 0 {
            be_u64(ibody, 4)
          } else {
            be_u32(ibody, 4).map(u64::from)
          };
          // Last-wins, like the SP1 mvhd state — and skip a zero date
          // (a zero CreateDate cannot anchor a GPSDateTime).
          if let Some(r) = raw
            && r != 0
          {
            found = Some(r);
          }
        }
      });
    }
    if next <= pos {
      break;
    }
    pos = next;
  }
  found
}

/// Detect an embedded Exif/TIFF block inside a QuickTime file — the atoms
/// QuickTime.pm dispatches to `Image::ExifTool::Exif::ProcessExif`
/// (QuickTime.pm:2058-2110, 2299-2357): the Casio `QVMI`, FujiFilm `MVTG`
/// and a `uuid`-Exif atom (a `uuid` whose payload begins with the JFIF/TIFF
/// `Exif\0\0` marker or a bare TIFF byte-order mark).
///
/// **DEFERRED.** exifast's Exif IFD parser (`exif::parse_exif_block`) lives
/// on the unmerged PR #36 (`lib/exif-gps`). This function only performs the
/// QuickTime-side DETECTION so the deferral is visible (`embedded_exif_*`);
/// the actual IFD parse is wired once #36 merges. Returns `true` when such a
/// block is present.
fn detect_embedded_exif(data: &[u8]) -> bool {
  let mut detected = false;
  // Walk top-level atoms; the embedded-Exif atoms sit inside `moov`/`udta`.
  let mut pos = 0usize;
  while pos < data.len() {
    let Some(HeaderOutcome::Atom(header, next)) = read_atom_header(data, pos, true) else {
      break;
    };
    let body = data
      .get(header.payload_start..header.payload_end.min(data.len()))
      .unwrap_or_default();
    detected |= match &header.atom_type {
      // Top-level entry into the directory scan — depth 0.
      b"moov" => detect_embedded_exif_in_dir(0, body),
      // A top-level `uuid` carrying an `Exif` TIFF block.
      b"uuid" => is_uuid_exif_payload(body),
      _ => false,
    };
    if next <= pos {
      break;
    }
    pos = next;
  }
  detected
}

/// Recursively scan a `moov`/`udta`/`meta` directory for an embedded-Exif
/// atom (`QVMI` / `MVTG` / `Exif` / `uuid`-Exif). QuickTime.pm nests these
/// under `moov`→`udta` (QuickTime.pm:2058, 2070).
///
/// `depth` is the recursion budget (Golden-v2 3a): the `udta`/`meta`/`trak`
/// self-recursion passes `depth + 1`, and the `walk_atoms` walk runs at the
/// same `depth` — so a hostile deeply-nested `udta` chain is bounded by
/// [`MAX_ATOM_DEPTH`] on both the self-recursion and the box walk.
fn detect_embedded_exif_in_dir(depth: u32, body: &[u8]) -> bool {
  if depth >= MAX_ATOM_DEPTH {
    return false;
  }
  let mut found = false;
  walk_atoms(depth, body, 0, body.len(), &mut None, |inner, ibody, _w| {
    found |= match &inner.atom_type {
      // Casio `QVMI` / FujiFilm `MVTG` — standard Exif IFD blocks
      // (QuickTime.pm:2056-2080) — and a bare `Exif`-type atom (TIFF block).
      b"QVMI" | b"MVTG" | b"Exif" => true,
      b"uuid" => is_uuid_exif_payload(ibody),
      // Recurse into nested containers (`udta`, `meta`, `trak`) — one level
      // deeper than the enclosing directory scan.
      b"udta" | b"meta" | b"trak" => detect_embedded_exif_in_dir(depth + 1, ibody),
      _ => false,
    };
  });
  found
}

/// `true` when a `uuid` atom payload carries an embedded Exif/TIFF block —
/// the payload (after the 16-byte UUID) begins with the JFIF `Exif\0\0`
/// marker or a TIFF byte-order mark (`II*\0` / `MM\0*`).
fn is_uuid_exif_payload(body: &[u8]) -> bool {
  // 16-byte UUID, then the embedded block.
  let Some(rest) = body.get(16..) else {
    return false;
  };
  rest.starts_with(b"Exif\0\0") || rest.starts_with(b"II*\0") || rest.starts_with(b"MM\0*")
}

/// The QuickTime / MOV first-atom acceptance gate.
///
/// ExifTool recognizes a MOV-family file by the `%magicNumber` regex
/// (`ExifTool.pm:995`):
///
/// ```text
///   MOV => '.{4}(free|skip|wide|ftyp|pnot|PICT|pict|moov|mdat|junk|uuid)'
/// ```
///
/// The leading `.{4}` skips the 4-byte atom *size* (any value — even `< 8`
/// or `0`); the file is a MOV iff the 4-byte atom *type* at offset 4 is one
/// of EXACTLY these eleven atoms. That magic test runs BEFORE `ProcessMOV`,
/// and `ProcessMOV`'s own `$$tagTablePtr{$tag}` gate (QuickTime.pm:9984) is
/// a superset check that always passes once the magic test did (all eleven
/// are `%QuickTime::Main` keys). So this set IS the magic regex verbatim.
///
/// **R8/F2.** The magic regex matches BOTH `PICT` and lowercase `pict`
/// (`%QuickTime::Main` defines `pict => PreviewPICT`, QuickTime.pm:125), so a
/// file leading with a `pict` atom is a MOV — `pict` must be present.
/// Conversely `meta` (a `%QuickTime::Main` key but NOT in the magic regex)
/// is NOT a recognized first atom: a file starting with `meta` is
/// `Unknown file type` (verified vs bundled ExifTool 13.58).
fn is_known_top_level(t: &[u8; 4]) -> bool {
  matches!(
    t,
    b"free"
      | b"skip"
      | b"wide"
      | b"ftyp"
      | b"pnot"
      | b"PICT"
      | b"pict"
      | b"moov"
      | b"mdat"
      | b"junk"
      | b"uuid"
  )
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path (replaces `serialize_tags`)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// QuickTime's diagnostics in the retired drain order: (a) the FIRST
  /// `ProcessMOV` warning (`Truncated '...' data` / `Invalid atom size`,
  /// QuickTime.pm:10242/10590) — the per-track truncation warnings ride the
  /// TAG stream under `Track<N>:Warning`, not here (R6/F2); (b) the SP3
  /// embedded-Exif-hop deferral notice when an Exif/TIFF block was detected
  /// (`embedded_exif_deferred`, awaiting the Exif+GPS port). Byte-identical
  /// net `TagMap`.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    if let Some(w) = self.warning() {
      out.push(crate::diagnostics::Diagnostic::warn(w));
    }
    if self.embedded_exif_deferred() {
      out.push(crate::diagnostics::Diagnostic::warn(
        "Embedded Exif/TIFF block detected; parse deferred (awaiting Exif+GPS port)",
      ));
    }
    out
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield `QuickTime:*` / `Track<N>:*` (+ SP4 `GoPro:*`) tags in ExifTool's
  /// atom-walk order (mvhd fields, then per-track fields, then the embedded
  /// SP3 stream + SP4 GoPro GPMF) — the golden-pattern parallel to the retired
  /// inherent `serialize_tags`: the SINK changes (an
  /// [`EmittedTag`](crate::emit::EmittedTag) per value instead of `out.write_*`),
  /// but the per-tag PrintConv/ValueConv branches, the emission ORDER, the
  /// per-track iteration, the first-wins `Track<N>` dedup, and the
  /// `CompatibleBrands` list are preserved VERBATIM.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: family0 = `"QuickTime"` (the `%QuickTime::Main` table group,
  /// QuickTime.pm:1424) for every emitted SP1 tag; family1 is `"QuickTime"` for
  /// the main/ftyp/mvhd/mdat atoms and the per-`moov` `Track<N>` string for the
  /// track atoms (QuickTime.pm:1427 `1 => 'Track#'`). Every QuickTime SP1 tag
  /// is a known table key (no `Unknown => 1`) ⇒ `unknown: false`. The SP4 GoPro
  /// GPMF tags carry their own family-0/family-1 `GoPro` group (the
  /// `%GoPro::GPMF` / `GPS5` / `GPS9` tables, GoPro.pm:67-69/489-490/518-519),
  /// summarizing the FIRST GPS fix + the block-level identity/GPS scalars (the
  /// per-sample `Doc<N>` list is on [`Meta::gopro`]); like the PLIST subdir
  /// tags above, these ride QuickTime's `tags()` under a foreign group.
  ///
  /// The `ProcessMOV` warning (`Meta::warning`) is NOT part of this stream —
  /// `run_emission` has no warning channel; the `AnyMeta::QuickTime` arm drains
  /// [`Meta::warning`] into `out.write_warning` (R6/F2).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // family0/family1 = "QuickTime" for the main/ftyp/mvhd/mdat atoms (see
    // fn docs). Track atoms compute their own family1 below.
    let main = || Group::new("QuickTime", "QuickTime");
    // `-j` (PrintConv) vs `-n` (ValueConv) maps to the `print_conv` bool the
    // retired `serialize_tags` threaded.
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: std::vec::Vec<EmittedTag> = std::vec::Vec::new();

    // ── ftyp ───────────────────────────────────────────────────────────
    if let Some(brand) = self.qt.major_brand() {
      // MajorBrand PrintConv `%ftypLookup` (QuickTime.pm:1036-1038); a hash
      // miss yields `Unknown ($val)` (ExifTool.pm:3622). -n emits the raw
      // 4-byte brand string.
      let value = if print_conv {
        match ftyp_lookup(brand) {
          Some(desc) => TagValue::Str(desc.into()),
          None => TagValue::Str(std::format!("Unknown ({brand})").into()),
        }
      } else {
        TagValue::Str(brand.into())
      };
      tags.push(EmittedTag::new(main(), "MajorBrand".into(), value, false));
    }
    if let Some(mv) = self.qt.minor_version() {
      // MinorVersion: ValueConv only, no PrintConv (QuickTime.pm:1040-1044).
      tags.push(EmittedTag::new(
        main(),
        "MinorVersion".into(),
        TagValue::Str(mv.into()),
        false,
      ));
    }
    if !self.qt.compatible_brands().is_empty() {
      // CompatibleBrands List (QuickTime.pm:1045-1051). One EmittedTag carrying
      // a `TagValue::List` of the per-brand `TagValue::Str` (byte-identical to
      // the retired `out.write_str_list` — see `TagMap::write_str_list`).
      let items: std::vec::Vec<TagValue> = self
        .qt
        .compatible_brands()
        .iter()
        .map(|b| TagValue::Str(b.as_str().into()))
        .collect();
      tags.push(EmittedTag::new(
        main(),
        "CompatibleBrands".into(),
        TagValue::List(items),
        false,
      ));
    }

    // ── mvhd ───────────────────────────────────────────────────────────
    if let Some(v) = self.qt.movie_header_version() {
      tags.push(EmittedTag::new(
        main(),
        "MovieHeaderVersion".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(d) = self.qt.create_date() {
      tags.push(EmittedTag::new(
        main(),
        "CreateDate".into(),
        TagValue::Str(d.into()),
        false,
      ));
    }
    if let Some(d) = self.qt.modify_date() {
      tags.push(EmittedTag::new(
        main(),
        "ModifyDate".into(),
        TagValue::Str(d.into()),
        false,
      ));
    }
    let movie_ts = self.qt.time_scale();
    if let Some(ts) = movie_ts {
      tags.push(EmittedTag::new(
        main(),
        "TimeScale".into(),
        TagValue::U64(u64::from(ts)),
        false,
      ));
    }
    // R6/F1: the mvhd `%durationInfo` tags store RAW timescale-counts; the
    // ValueConv `$$self{TimeScale} ? $val / $$self{TimeScale} : $val` is
    // applied HERE against the FINAL global movie `TimeScale` (last-wins
    // across every `mvhd` in the file) — see `durationinfo_value_conv`.
    if let Some(count) = self.qt.duration_count() {
      let secs = durationinfo_value_conv(count, movie_ts);
      tags.push(EmittedTag::new(
        main(),
        "Duration".into(),
        duration_value(secs, movie_ts, print_conv),
        false,
      ));
    }
    if let Some(r) = self.qt.preferred_rate() {
      // PreferredRate: ValueConv `$val / 0x10000`, no PrintConv.
      tags.push(EmittedTag::new(
        main(),
        "PreferredRate".into(),
        TagValue::F64(r),
        false,
      ));
    }
    if let Some(v) = self.qt.preferred_volume() {
      // PreferredVolume PrintConv `sprintf("%.2f%%", $val * 100)`.
      tags.push(EmittedTag::new(
        main(),
        "PreferredVolume".into(),
        volume_value(v, print_conv),
        false,
      ));
    }
    if let Some(m) = self.qt.matrix_structure() {
      tags.push(EmittedTag::new(
        main(),
        "MatrixStructure".into(),
        TagValue::Str(m.into()),
        false,
      ));
    }
    // The Preview/Poster/Selection/Current `%durationInfo` counts (idx18-23).
    for (count, name) in [
      (self.qt.preview_time_count(), "PreviewTime"),
      (self.qt.preview_duration_count(), "PreviewDuration"),
      (self.qt.poster_time_count(), "PosterTime"),
      (self.qt.selection_time_count(), "SelectionTime"),
      (self.qt.selection_duration_count(), "SelectionDuration"),
      (self.qt.current_time_count(), "CurrentTime"),
    ] {
      if let Some(c) = count {
        let secs = durationinfo_value_conv(u64::from(c), movie_ts);
        tags.push(EmittedTag::new(
          main(),
          name.into(),
          duration_value(secs, movie_ts, print_conv),
          false,
        ));
      }
    }
    if let Some(id) = self.qt.next_track_id() {
      tags.push(EmittedTag::new(
        main(),
        "NextTrackID".into(),
        TagValue::U64(u64::from(id)),
        false,
      ));
    }

    // ── mdat (synthetic) ───────────────────────────────────────────────
    if let Some(sz) = self.qt.media_data_size() {
      tags.push(EmittedTag::new(
        main(),
        "MediaDataSize".into(),
        TagValue::U64(sz),
        false,
      ));
    }
    if let Some(off) = self.qt.media_data_offset() {
      tags.push(EmittedTag::new(
        main(),
        "MediaDataOffset".into(),
        TagValue::U64(off),
        false,
      ));
    }

    // ── frea (Kodak PixPro / Rexing — Kodak.pm:2977-2990) ──────────────
    // The top-level `frea` atom's `Image::ExifTool::Kodak::frea` SubDirectory
    // (QuickTime.pm:610-613). Group: family-0 `MakerNotes`, family-1 `Kodak`
    // (the table `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`; family-1
    // defaults to the table's family-0 name → `Kodak`; verified vs the bundled
    // `-G0:1` oracle). Every tag is a known table key ⇒ `unknown: false`.
    let frea = self.qt.kodak_frea();
    if !frea.is_empty() {
      let kodak = || Group::new("MakerNotes", "Kodak");
      // `tima` Duration: PrintConv `ConvertDuration($val)` (Kodak.pm:2984), no
      // ValueConv — so the raw `int32u` seconds IS the `-n` value and the
      // `ConvertDuration` input (NOT the `%durationInfo` timescale divide).
      if let Some(secs) = frea.duration_secs() {
        let value = if print_conv {
          TagValue::Str(convert_duration(f64::from(secs)).into())
        } else {
          TagValue::U64(u64::from(secs))
        };
        tags.push(EmittedTag::new(kodak(), "Duration".into(), value, false));
      }
      // `'ver '` KodakVersion: the raw string (Kodak.pm:2987), mode-invariant
      // (no PrintConv/ValueConv beyond the RawConv stash).
      if let Some(ver) = frea.version() {
        tags.push(EmittedTag::new(
          kodak(),
          "KodakVersion".into(),
          TagValue::Str(ver.into()),
          false,
        ));
      }
      // `thma` ThumbnailImage / `scra` PreviewImage: `Binary => 1` ⇒ the
      // `(Binary data N bytes, use -b option to extract)` placeholder in BOTH
      // modes (Kodak.pm:2988-2989).
      if let Some(len) = frea.thumbnail_len() {
        tags.push(EmittedTag::new(
          kodak(),
          "ThumbnailImage".into(),
          TagValue::Str(binary_placeholder(len)),
          false,
        ));
      }
      if let Some(len) = frea.preview_len() {
        tags.push(EmittedTag::new(
          kodak(),
          "PreviewImage".into(),
          TagValue::Str(binary_placeholder(len)),
          false,
        ));
      }
    }

    // ── per-track (tkhd / mdhd / hdlr) ─────────────────────────────────
    // ExifTool's `Track#` family-1 group (QuickTime.pm:1427) is driven by the
    // per-`moov` `$track` counter (RESET per `ProcessMOV`/`moov`), stored on
    // each track during parsing (R4/F2) — NOT the global Vec index. So two
    // top-level `moov`s each holding one `trak` BOTH carry `Track1`. In ExifTool
    // the default `-j` output keeps the FIRST occurrence of each rendered tag
    // KEY (the `%noDups` render-stage first-wins, ExifTool.pm:2950-2951). That
    // collision is per `(family-1 group, tag name)` KEY, NOT per group: two
    // top-level moovs both assigning `Track1` STILL emit the distinct tags a
    // later `Track1` carries that the first lacked (R5/F1) — e.g. moov1's
    // `Track1` from a bare `tkhd` (TrackID, …) plus moov2's `Track1` from a bare
    // `mdhd`/`hdlr` (MediaTimeScale, MediaDuration, HandlerType, …) BOTH appear.
    // Only a tag already emitted under that exact `Track<N>:Name` key is dropped.
    //
    // The `run_emission` sink (TagMap) is LAST-wins in place, so we cannot rely
    // on it for first-wins; we suppress duplicates HERE per full `(group, name)`
    // key — only the NOVEL tags reach the `Vec<EmittedTag>`. We walk EVERY track
    // using its stored `Track<N>` group, recording each emitted key in
    // `emitted_keys` so a later same-group track contributes only its novel
    // tags. `Vec<SmolStr>` of `"Track<N>:Name"` keys (counts are tiny).
    let mut emitted_keys: std::vec::Vec<smol_str::SmolStr> = std::vec::Vec::new();
    // ExifTool's `$$self{HasHandler}{$val}` dedup for the no-`ee` EEWarn
    // (QuickTime.pm:8407,8414): the warning fires once per DISTINCT handler type
    // — for the FIRST `trak` carrying each `%eeBox` code — and `HasHandler{$val}`
    // is set when that code is first SEEN (independent of whether the Warning
    // itself survives the `%noDups` first-wins). This file-level set of already-
    // seen eeBox codes mirrors that (the realistic file has one such track).
    let mut ee_warned: std::vec::Vec<&str> = std::vec::Vec::new();
    // First-wins gate: `true` (and records the key) only the FIRST time a
    // `(grp, name)` pair is seen; a repeat returns `false` so the caller skips
    // the push, leaving the earlier value in place (ExifTool.pm:2950-2951).
    let mut first_seen = |grp: &str, name: &str| -> bool {
      let key = smol_str::SmolStr::new(std::format!("{grp}:{name}"));
      if emitted_keys.contains(&key) {
        return false;
      }
      emitted_keys.push(key);
      true
    };
    for (idx, track) in self.qt.tracks().iter().enumerate() {
      // Fall back to the 1-based Vec index only for tracks built directly in
      // unit tests (no `track_group` recorded).
      let group_num = track.track_group().unwrap_or((idx + 1) as u32);
      let grp_owned = alloc_track_group(group_num as usize);
      let grp = grp_owned.as_str();
      // The per-track family1 is the computed `Track<N>` string; family0 stays
      // "QuickTime" (the `%QuickTime::Main` table group).
      let track_group = || Group::new("QuickTime", grp);
      // R7/F2: a `Truncated '...' data` warning raised inside this `trak`'s
      // walk (a header-valid but payload-overrunning tkhd / mdhd) surfaces
      // under this track's family-1 group — ExifTool attaches the warning to
      // the CURRENT group, not the document `ExifTool:Warning`.
      if let Some(w) = track.warning()
        && first_seen(grp, "Warning")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "Warning".into(),
          TagValue::Str(w.into()),
          false,
        ));
      }
      // Each emission is a `let Some(..)` value-presence test let-chained with
      // the `first_seen` first-wins gate: the gate's side effect (recording the
      // key) runs ONLY when the value is present (`&&` short-circuits past a
      // `let` non-match), exactly as a nested `if`/`if` would.
      if let Some(v) = track.track_header_version()
        && first_seen(grp, "TrackHeaderVersion")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackHeaderVersion".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(d) = track.track_create_date()
        && first_seen(grp, "TrackCreateDate")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackCreateDate".into(),
          TagValue::Str(d.into()),
          false,
        ));
      }
      if let Some(d) = track.track_modify_date()
        && first_seen(grp, "TrackModifyDate")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackModifyDate".into(),
          TagValue::Str(d.into()),
          false,
        ));
      }
      if let Some(id) = track.track_id()
        && first_seen(grp, "TrackID")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackID".into(),
          TagValue::U64(u64::from(id)),
          false,
        ));
      }
      if let Some(secs) = track.duration_seconds()
        && first_seen(grp, "TrackDuration")
      {
        // TrackDuration durationInfo uses the MOVIE TimeScale.
        tags.push(EmittedTag::new(
          track_group(),
          "TrackDuration".into(),
          duration_value(secs, movie_ts, print_conv),
          false,
        ));
      }
      if let Some(l) = track.track_layer()
        && first_seen(grp, "TrackLayer")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackLayer".into(),
          TagValue::U64(u64::from(l)),
          false,
        ));
      }
      if let Some(v) = track.track_volume()
        && first_seen(grp, "TrackVolume")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "TrackVolume".into(),
          volume_value(v, print_conv),
          false,
        ));
      }
      if let Some(m) = track.matrix_structure()
        && first_seen(grp, "MatrixStructure")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MatrixStructure".into(),
          TagValue::Str(m.into()),
          false,
        ));
      }
      if let Some(w) = track.image_width()
        && first_seen(grp, "ImageWidth")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "ImageWidth".into(),
          TagValue::U64(u64::from(w)),
          false,
        ));
      }
      if let Some(h) = track.image_height()
        && first_seen(grp, "ImageHeight")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "ImageHeight".into(),
          TagValue::U64(u64::from(h)),
          false,
        ));
      }
      if let Some(v) = track.media_header_version()
        && first_seen(grp, "MediaHeaderVersion")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MediaHeaderVersion".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(d) = track.media_create_date()
        && first_seen(grp, "MediaCreateDate")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MediaCreateDate".into(),
          TagValue::Str(d.into()),
          false,
        ));
      }
      if let Some(d) = track.media_modify_date()
        && first_seen(grp, "MediaModifyDate")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MediaModifyDate".into(),
          TagValue::Str(d.into()),
          false,
        ));
      }
      let media_ts = track.media_time_scale();
      if let Some(ts) = media_ts
        && first_seen(grp, "MediaTimeScale")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MediaTimeScale".into(),
          TagValue::U64(u64::from(ts)),
          false,
        ));
      }
      if let Some(secs) = track.media_duration_seconds()
        && first_seen(grp, "MediaDuration")
      {
        // MediaDuration durationInfo uses the MEDIA TimeScale
        // (QuickTime.pm:7270-7271 `$$self{MediaTS}`).
        tags.push(EmittedTag::new(
          track_group(),
          "MediaDuration".into(),
          duration_value(secs, media_ts, print_conv),
          false,
        ));
      }
      if let Some(lang) = track.media_language()
        && first_seen(grp, "MediaLanguageCode")
      {
        // MediaLanguageCode: ValueConv-only for ISO codes; a NUMERIC
        // (Macintosh) value gets the ttLang{Macintosh} PrintConv with an
        // `Unknown ($val)` fallback (QuickTime.pm:7281-7285, F4). -n emits
        // the post-ValueConv raw string (the bare number or 3-letter code).
        let value = if print_conv {
          TagValue::Str(mac_language_print(lang).into())
        } else {
          TagValue::Str(lang.into())
        };
        tags.push(EmittedTag::new(
          track_group(),
          "MediaLanguageCode".into(),
          value,
          false,
        ));
      }
      if let Some(class) = track.handler_class()
        && first_seen(grp, "HandlerClass")
      {
        // HandlerClass / ComponentType (QuickTime.pm:8395-8402); emitted only
        // for a non-zero ComponentType (the RawConv undef branch is applied at
        // decode). PrintConv `mhlr`→Media Handler / `dhlr`→Data Handler; a hash
        // miss yields `Unknown ($val)`. `-n` emits the raw 4-char code.
        let value = if print_conv {
          let printed = handler_class_print(class);
          if printed.is_empty() {
            TagValue::Str(std::format!("Unknown ({class})").into())
          } else {
            TagValue::Str(printed.into())
          }
        } else {
          TagValue::Str(class.into())
        };
        tags.push(EmittedTag::new(
          track_group(),
          "HandlerClass".into(),
          value,
          false,
        ));
      }
      // No-`ee` EEWarn (QuickTime.pm:8407-8411, `HandlerType` RawConv): without
      // `-ee`, the FIRST `trak` carrying each `%eeBox` handler type
      // (`text`/`meta`/`sbtl`/`data`/`camm`/`ctbx`; `vide` is excluded — it is
      // gated on the `stsd` sample-description, not the handler) raises `[minor]
      // The ExtractEmbedded option may find more tags in the media data`, scoped
      // to this track's family-1 group, just BEFORE `HandlerType` is emitted.
      // The `mebx`/`camm` timed-metadata tracks carry the `meta` handler, so the
      // oracle shows `Track<N>:Warning` between `HandlerClass` and `HandlerType`.
      // The code is latched as SEEN here (the `HasHandler{$val}` set, independent
      // of the Warning surviving); `first_seen` then keeps the priority-0
      // first-wins `Warning` (a truncation warning raised earlier in THIS track's
      // walk takes precedence). The per-sample GPS stays `-ee` gated (see
      // `emit_timed_samples`).
      if !opts.extract_embedded
        && let Some(code) = track.handler_code()
        && is_ee_handler(code)
        && !ee_warned.contains(&code)
      {
        ee_warned.push(code);
        if first_seen(grp, "Warning") {
          tags.push(EmittedTag::new(
            track_group(),
            "Warning".into(),
            TagValue::Str(EE_WARNING.into()),
            false,
          ));
        }
      }
      if let Some(code) = track.handler_code()
        && first_seen(grp, "HandlerType")
      {
        // HandlerType: the flat tag is driven by the RAW 4-byte code (F3).
        let value = if print_conv {
          // hdlr HandlerType PrintConv (QuickTime.pm:8418-8444); a hash miss
          // yields `Unknown ($val)` (ExifTool.pm:3622).
          let printed = handler_type_print(code);
          if printed.is_empty() {
            TagValue::Str(std::format!("Unknown ({code})").into())
          } else {
            TagValue::Str(printed.into())
          }
        } else {
          // -n: the raw post-RawConv value is the 4-char code string.
          TagValue::Str(code.into())
        };
        tags.push(EmittedTag::new(
          track_group(),
          "HandlerType".into(),
          value,
          false,
        ));
      }
      // MetaFormat (`stsd` 4cc): the `MetaSampleDesc` `MetaFormat` tag, emitted
      // ONLY for a `meta`-handler track (QuickTime.pm:7393 `Condition =>
      // '$$self{HandlerType} eq "meta"'`) — a `soun`/`vide`/`hint` track routes
      // to its own sample-desc table, an unmatched handler to `OtherSampleDesc`'s
      // `OtherFormat` (NOT `MetaFormat`). Positioned at the family-1 `Track<N>`
      // level right AFTER `HandlerType` (the golden order; track-level, NOT under
      // `Doc<N>`). Emit the raw 4-char code verbatim in both modes (no PrintConv
      // — `Format => 'undef[4]'`, the RawConv only stashes `$$self{MetaFormat}`).
      // Verified vs bundled 13.59: `Track1:MetaFormat = rtmd`/`camm`/`mebx`.
      if let Some(fmt) = track.meta_format()
        && track.handler_code() == Some("meta")
        && first_seen(grp, "MetaFormat")
      {
        tags.push(EmittedTag::new(
          track_group(),
          "MetaFormat".into(),
          TagValue::Str(fmt.into()),
          false,
        ));
      }
    }

    // ── SP3: embedded timed-metadata (QuickTimeStream) ─────────────────
    // ExifTool surfaces these per-sample tags ONLY under `-ee` (ExtractEmbedded)
    // and opens one `Doc<N>` sub-document per GPS fix (`$$et{DOC_NUM} =
    // ++$$et{DOC_COUNT}`, QuickTimeStream.pl:967-973). The shared
    // [`emit_timed_samples`] reproduces both: gated on `opts.extract_embedded`,
    // it emits every fix as a `Doc<N>` row at `-G3` and the first-fix-wins
    // collapse at `-G1`. The SP3 stream is MOOV-level / freeGPS-scanned, so its
    // family-1 group is `QuickTime` for every fix (oracle: `QuickTime:GPSLatitude`
    // / `Doc1:QuickTime:GPSLatitude`). lat/lon → `GPS::ToDMS` at `-j`
    // (QuickTimeStream.pl:116-117), altitude → the `+ 0` `%.4f` `" m"` PrintConv
    // (:120), both raw `F64` at `-n`. GPSSpeed (km/h, the typed layer's
    // post-ValueConv value) and GPSTrack are the per-source columns; GPSDateTime
    // is the common ConvertDateTime string.
    emit_timed_samples(
      self.stream.gps_samples(),
      |_s| Group::new("QuickTime", "QuickTime"),
      opts,
      print_conv,
      // The SP3 stream carries no GPSMeasureMode column — never invoked.
      |m, _pc| TagValue::U64(u64::from(m)),
      |_s, _a, pc| gps_altitude_stream_value(_a, pc),
      |s, group, scratch| {
        // GPSSpeed (`%QuickTime::Stream`, QuickTimeStream.pl:121): the typed
        // layer already holds km/h (post-ValueConv); the `sprintf("%.4f")+0`
        // PrintConv only rounds/strips, value-identical for the camera-clean
        // speeds — emit the raw `F64` (a bare JSON number) in both modes.
        if let Some(spd) = s.speed_kph() {
          scratch.push(EmittedTag::new(
            group.clone(),
            "GPSSpeed".into(),
            TagValue::F64(spd),
            false,
          ));
        }
        // Accelerometer (QuickTimeStream.pl:149): the space-joined 3-axis
        // string, NO PrintConv (a `Notes`-only tag) — emit verbatim in both
        // modes (oracle `moov_gps`: `Accelerometer "0 0 0"`; `gsen`:
        // `Accelerometer "1 -2 3"`).
        if let Some(acc) = s.accelerometer() {
          scratch.push(EmittedTag::new(
            group.clone(),
            "Accelerometer".into(),
            TagValue::Str(acc.into()),
            false,
          ));
        }
        // TimeCode (QuickTimeStream.pl:159): a plain numeric tag — NO PrintConv,
        // NO ValueConv (the table entry is bare). `Process_3gf` HandleTags
        // `$tc / 1000` (:2703); the typed layer already holds that f64. Emit the
        // raw `F64` (a bare JSON number) in both modes.
        if let Some(tc) = s.time_code() {
          scratch.push(EmittedTag::new(
            group.clone(),
            "TimeCode".into(),
            TagValue::F64(tc),
            false,
          ));
        }
      },
      &mut tags,
    );
    // No-`ee` DOCUMENT-level `EEWarn` (QuickTime.pm:9545-9549 `EEWarn` →
    // `Warn('The ExtractEmbedded option may find more tags in the media data',
    // 3)`): a TOP-LEVEL magic box (`gps0`/`gsen`/`3gf`) holding more than one
    // record is TRUNCATED to its first record at no-`ee` and raises this
    // file-level warning (QuickTimeStream.pl:2693/2738/2776). Unlike the eeBox
    // `Track<N>:Warning` above (a HANDLER-track RawConv, scoped to that track's
    // family-1 group), these magic boxes are NOT `trak`s — no `SET_GROUP1` is
    // active — so the warning is DOCUMENT-level (`ExifTool:Warning`). Emitted
    // IN-STREAM as a family-0/1 `ExifTool` `Warning` tag (the `tags()` path is
    // the only one that sees `opts.extract_embedded`; the `Diagnose` channel
    // does not). It lands in the `Warning` priority-0 first-wins slot, so a real
    // document warning raised earlier (a `ProcessMOV` `ExifTool:Warning`, which
    // rides the `Diagnose` accumulator into the orchestration object) still wins
    // — no incorrect double-warn. The `-ee`-only sources (moov-`gps `-box /
    // Kenwood / freeGPS-scan) never set the flag — they raise different warnings
    // the oracle shows ABSENT at no-`ee`.
    if !opts.extract_embedded && self.stream.magic_box_truncated_no_ee() {
      tags.push(EmittedTag::new(
        Group::new("ExifTool", "ExifTool"),
        "Warning".into(),
        TagValue::Str(EE_WARNING.into()),
        false,
      ));
    }
    // The Apple `mebx` key/value pairs — ExifTool emits these per timed sample
    // under the enclosing `Track<N>` (family-1) at its `Doc<N>` (oracle:
    // `Track1:GPSCoordinates` / `Doc1:Track1:GPSCoordinates`), preceded by the
    // sample-table `SampleTime`/`SampleDuration` (`ConvertDuration` PrintConv,
    // QuickTimeStream.pl:161-162). Gated on `-ee`; `-G1` collapses to the FIRST
    // sample per `(Track<N>, name)`. The per-sample `track_index` is the moov
    // track number stamped by the walker (default `Track1`).
    if opts.extract_embedded {
      let g3 = matches!(opts.group_mode, crate::serialize_key::GroupMode::G3);
      // `doc` is the FALLBACK running ordinal for any `mebx` sample left
      // unstamped (none in practice — the walker stamps every record). When the
      // extraction stamp is present (`sample.doc()`), it is used VERBATIM, so all
      // records of ONE timed sample share ONE `Doc<N>` (ExifTool sets `DOC_NUM`
      // once per sample via `FoundSomething`, then `HandleTag`s every record under
      // it — QuickTimeStream.pl:2644). The stamp is also GLOBAL across the file's
      // stream sources (e.g. a `gps0` box after this `mebx` track continues the
      // ordinal). The legacy per-record `doc += 1` would have scattered a
      // multi-key sample (mebx_keys/detface) across `Doc1..DocN`.
      let mut doc: u32 = 0;
      let mut mebx_scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
      // `-G1` collapse state (unused at `-G3`). ExifTool's `-ee -G1` collapses
      // every `Doc<N>` to one `(family1, name)` row with TWO precedence rules,
      // BOTH driven by the per-record `Doc<N>`:
      //   * WITHIN one document (one timed sample — its records share a doc):
      //     LAST-wins, because each record `HandleTag`s into the same
      //     `(DOC_NUM, tag)` VALUE slot and a later record OVERWRITES the earlier
      //     (the `detected-face` sample's two faces ⇒ the SECOND face's
      //     `DetectedFace*` win — QuickTimeStream.pl:2644/2671).
      //   * ACROSS documents: FIRST-document-wins (the same first-fix-wins the
      //     GPS sources show at `-ee -G1`: gps0/gsen keep the Doc1 fix, not Doc2).
      // So: accumulate one document's records with within-doc last-wins
      // (`doc_vals`), and on the doc boundary FLUSH them into `tags` honoring
      // across-doc first-wins (`mebx_committed`). At `-G3` neither buffer is used —
      // the records emit verbatim and the last-wins-within-doc collapse happens in
      // the flat `TagMap` sink (a later same-key `Doc<N>:` row overwrites).
      // Keyed by `(family1, name)`, NOT bare `name`: ExifTool's `%noDups`
      // collapse is per FULL tag (group included), so two `mebx` `trak`s emitting
      // the SAME key (`Track1:SceneIlluminance` + `Track2:SceneIlluminance`) are
      // DISTINCT rows and BOTH survive `-ee -G1` (a name-only set would drop the
      // later track's value). The family-1 group is the per-`trak` `Track<N>`.
      let mut mebx_committed: std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)> =
        std::vec::Vec::new();
      // ((family1, name), EmittedTag) for the document currently being
      // accumulated, plus the doc number it belongs to. `None` until the first
      // sample opens a doc.
      let mut doc_vals: std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)> =
        std::vec::Vec::new();
      let mut cur_doc: Option<u32> = None;
      // Flush one accumulated document's last-wins values into `tags`, dropping a
      // `(family1, name)` already committed by an EARLIER document (across-doc
      // first-wins). Emits in first-seen order within the document.
      let flush_doc =
        |doc_vals: &mut std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)>,
         committed: &mut std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)>,
         tags: &mut std::vec::Vec<EmittedTag>| {
          for (key, tag) in doc_vals.drain(..) {
            if committed.contains(&key) {
              continue;
            }
            committed.push(key);
            tags.push(tag);
          }
        };
      for sample in self.stream.mebx_samples() {
        let doc_n = sample.doc().unwrap_or_else(|| {
          doc += 1;
          doc
        });
        let track = std::format!("Track{}", sample.track_index().unwrap_or(1));
        let group = if g3 {
          Group::with_doc("QuickTime", track.as_str(), doc_n)
        } else {
          Group::new("QuickTime", track.as_str())
        };
        mebx_scratch.clear();
        // SampleTime / SampleDuration (`ConvertDuration` at `-j`, raw seconds
        // at `-n`) — the sample-table timing ExifTool's `ProcessSamples` emits
        // ahead of the decoded value.
        for (val, name) in [
          (sample.sample_time(), "SampleTime"),
          (sample.sample_duration(), "SampleDuration"),
        ] {
          if let Some(secs) = val {
            let value = if print_conv {
              TagValue::Str(crate::datetime::convert_duration(secs).into())
            } else {
              TagValue::F64(secs)
            };
            mebx_scratch.push(EmittedTag::new(group.clone(), name.into(), value, false));
          }
        }
        mebx_scratch.push(EmittedTag::new(
          group.clone(),
          sample.name().into(),
          TagValue::Str(sample.value().into()),
          false,
        ));
        if g3 {
          tags.append(&mut mebx_scratch);
        } else {
          // A new document — flush the previous one (across-doc first-wins).
          if cur_doc != Some(doc_n) {
            flush_doc(&mut doc_vals, &mut mebx_committed, &mut tags);
            cur_doc = Some(doc_n);
          }
          // Accumulate this record's tags with WITHIN-doc last-wins by
          // `(family1, name)` (the records of one timed sample all share that
          // sample's `Track<N>`, so this matches the cross-doc collapse key).
          for tag in mebx_scratch.drain(..) {
            let key = (
              smol_str::SmolStr::new(tag.tag().group_ref().family1()),
              smol_str::SmolStr::new(tag.tag().name()),
            );
            if let Some(slot) = doc_vals.iter_mut().find(|(k, _)| *k == key) {
              slot.1 = tag;
            } else {
              doc_vals.push((key, tag));
            }
          }
        }
      }
      // Flush the final accumulated document (no-op at `-G3` / when empty).
      flush_doc(&mut doc_vals, &mut mebx_committed, &mut tags);
      // Tags from a `mebx` `SubDirectory` key (currently only `smartstyle-info`'s
      // embedded binary PLIST, QuickTime.pm:6847-6852). These were rendered by
      // the nested PLIST `Taggable` stream and stored as fully-typed [`Tag`]s —
      // each KEEPS the PLIST table's family-0 group (`PLIST`) and the camel-cased
      // PLIST key name, faithful to the bundled `-ee -G0`/`-G3` oracle (family-0
      // `PLIST`, document `Doc<N>`). The family-1 group divergence (the oracle
      // re-scopes these to the enclosing `Track<N>`, while exifast's flat TagMap
      // cannot reproduce the per-sample `Doc<N>` shape) is an accepted SP3
      // limitation. Emitted verbatim, gated on `-ee`.
      for tag in self.stream.plist_subdir_tags() {
        tags.push(EmittedTag::new(
          tag.group_ref().clone(),
          tag.name().into(),
          tag.value_ref().clone(),
          false,
        ));
      }
    }

    // ── SP4: Sony rtmd per-sample camera + GPS (Image::ExifTool::Sony) ──
    // `Process_rtmd` (Sony.pm:11569-11602) decodes ONE timed sample per `rtmd`
    // sample-table entry; ExifTool's `ProcessSamples` opens a `Doc<N>` per
    // sample and `HandleTag`s every decoded record under it, scoped to the
    // enclosing `Track<N>` (family-1; oracle: `Doc1:Track1:FNumber`,
    // `Doc1:Track1:GPSLatitude`) — IDENTICAL group machinery to the `mebx`
    // block above. Gated on `-ee`; `-G1` collapses every `Doc<N>` to one
    // `(Track<N>, name)` row (within-sample last-wins, across-sample
    // first-wins). Each sample's records emit in the fixed Sony.pm tag order
    // (SampleTime/SampleDuration, then the camera scalars, then the `0x85xx`
    // GPS family) so the rendered key order matches the oracle token-for-token.
    if opts.extract_embedded {
      let g3 = matches!(opts.group_mode, crate::serialize_key::GroupMode::G3);
      // Fallback running ordinal for any unstamped sample (none in practice —
      // the walker stamps `doc()` on every sample); when stamped, used verbatim
      // so all of one sample's records share ONE `Doc<N>`.
      let mut doc: u32 = 0;
      let mut sony_scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
      // `-G1` collapse state (unused at `-G3`), keyed by `(family1, name)` —
      // the same two-rule collapse the `mebx` block documents: within one
      // sample last-wins, across samples first-wins.
      let mut sony_committed: std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)> =
        std::vec::Vec::new();
      let mut doc_vals: std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)> =
        std::vec::Vec::new();
      let mut cur_doc: Option<u32> = None;
      let flush_doc =
        |doc_vals: &mut std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)>,
         committed: &mut std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)>,
         tags: &mut std::vec::Vec<EmittedTag>| {
          for (key, tag) in doc_vals.drain(..) {
            if committed.contains(&key) {
              continue;
            }
            committed.push(key);
            tags.push(tag);
          }
        };
      for sample in self.sony_rtmd.samples() {
        let doc_n = if sample.doc() == 0 {
          doc += 1;
          doc
        } else {
          sample.doc()
        };
        let track = std::format!("Track{}", {
          let t = sample.track_index();
          if t == 0 { 1 } else { t }
        });
        let group = if g3 {
          Group::with_doc("QuickTime", track.as_str(), doc_n)
        } else {
          Group::new("QuickTime", track.as_str())
        };
        sony_scratch.clear();
        // SampleTime / SampleDuration (`ConvertDuration` at `-j`, raw seconds at
        // `-n`) — the sample-table timing emitted ahead of the decoded payload.
        for (val, name) in [
          (sample.sample_time(), "SampleTime"),
          (sample.sample_duration(), "SampleDuration"),
        ] {
          if let Some(secs) = val {
            let value = if print_conv {
              TagValue::Str(crate::datetime::convert_duration(secs).into())
            } else {
              TagValue::F64(secs)
            };
            sony_scratch.push(EmittedTag::new(group.clone(), name.into(), value, false));
          }
        }
        // ── camera scalars (Sony.pm:10700-10833 order) ─────────────────────
        let cam = sample.camera();
        // FNumber (0x8000): a PRESENT record is always a DEFINED tag — the
        // post-ValueConv linear f-number for a `Valid` read (`PrintFNumber` at
        // `-j`, raw F64 at `-n`), OR the ValueConv-of-`''` `2^(8-0/8192) = 256`
        // for an `EmptyRead` (a sub-width record — `256.0` at `-j`, `256` at
        // `-n`, verified vs bundled 13.59). See the helper.
        if let Some(read) = cam.f_number_read() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "FNumber".into(),
            sony_rtmd_fnumber_value(read, print_conv),
            false,
          ));
        }
        // FrameRate (0x8106): `sprintf("%.2f")` PrintConv at `-j` (oracle
        // `29.97`), the raw `rational64u` at `-n` — ExifTool reads `0x8106`
        // as `rational64u` and `-n` renders its rational `%g` form
        // (`30000/1001` → `29.97002997`, NOT the 15-digit f64). A zero
        // denominator stays `undef`; an `EmptyRead` (sub-width record) is the
        // ValueConv-of-`''`: `0.00` at `-j` (`sprintf("%.2f",'')` numifies `''`
        // to 0), `''` at `-n` (verified vs bundled 13.59).
        if let Some(read) = cam.frame_rate_read() {
          let value = sony_rtmd_frame_rate_read_value(read, print_conv);
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "FrameRate".into(),
            value,
            false,
          ));
        }
        // ExposureTime (0x8109): `PrintExposureTime` at `-j` (oracle `"1/60"`),
        // the raw `rational64u` at `-n` (`1/60` → `0.01666666667`, the
        // rational `%g` form, not the f64; zero denominator → `undef`). An
        // `EmptyRead` (sub-width record) is the ValueConv-of-`''`: the EMPTY
        // STRING `''` at BOTH `-j` and `-n` (`PrintExposureTime('')` returns its
        // argument unchanged — `IsFloat('')` is false — verified vs bundled).
        if let Some(read) = cam.exposure_time_read() {
          let value = sony_rtmd_exposure_time_read_value(read, print_conv);
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "ExposureTime".into(),
            value,
            false,
          ));
        }
        // MasterGainAdjustment (0x810a): `sprintf("%.2f dB")` PrintConv at `-j`
        // (oracle `"6.00 dB"`), raw F64 dB at `-n`. An `EmptyRead` (sub-width
        // record) is the ValueConv-of-`''` `''/100 = 0`: `"0.00 dB"` at `-j`,
        // `0` at `-n` (verified vs bundled 13.59).
        if let Some(read) = cam.master_gain_db_read() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "MasterGainAdjustment".into(),
            sony_rtmd_master_gain_value(read, print_conv),
            false,
          ));
        }
        // ISO (0x810b): emitted ONLY when the CANONICAL `0x810b` tag was present
        // — the alternate `0xe301` int32u channel is `%hidUnk` (Hidden+Unknown),
        // which bundled does not surface as `Sony:ISO`. Plain integer for a
        // `Valid` read; an `EmptyRead` (sub-width canonical record) is the raw
        // `''` EMPTY STRING in BOTH modes (verified vs bundled 13.59).
        if cam.iso_from_canonical()
          && let Some(read) = cam.iso_read()
        {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "ISO".into(),
            sony_rtmd_raw_int_read_value(read),
            false,
          ));
        }
        // ElectricalExtenderMagnification (0x810c): `int16u`, no conv — the plain
        // integer for a `Valid` read, the raw `''` EMPTY STRING for an
        // `EmptyRead` (sub-width record), in both modes; positioned after `ISO`
        // per tag-id order (Sony.pm:10769-10772, verified vs bundled 13.59).
        if let Some(read) = cam.electrical_extender_magnification_read() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "ElectricalExtenderMagnification".into(),
            sony_rtmd_raw_int_read_value(read),
            false,
          ));
        }
        // SerialNumber (0x8114): the raw composite (`"<MODEL> <SERIAL>"`), no
        // conv — emit verbatim in both modes.
        if let Some(v) = cam.serial_number() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "SerialNumber".into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
        // WhiteBalance (0xe303): Sony.pm:10818-10827 `int8u` + PrintConv hash. A
        // `Valid` read → the hash PrintConv at `-j` (an out-of-table code →
        // `Unknown ($val)`, oracle `"Unknown (0)"`) / the raw key at `-n`. An
        // `EmptyRead` (present zero-length record, `ReadValue` ⇒ `''`) → the
        // PrintConv-of-`''` `"Unknown ()"` at `-j` / `''` at `-n` (verified vs
        // bundled 13.59).
        if let Some(read) = cam.white_balance_read() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "WhiteBalance".into(),
            sony_rtmd_white_balance_read_value(read, print_conv),
            false,
          ));
        }
        // DateTime (0xe304): the assembled `"YYYY:MM:DD HH:MM:SS"` (or a PARTIAL
        // BCD string for a sub-width record — `unpack` fills each field from the
        // bytes that remain, e.g. a 4-byte record → `"2024:03: ::"`). No PrintConv
        // distinction (`ConvertDateTime` passes a malformed value through) — emit
        // verbatim in both modes. The decoder always yields a string for a present
        // record, so a degenerate DateTime still surfaces (verified vs bundled
        // 13.59 for each length 0..8).
        if let Some(v) = cam.date_time() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "DateTime".into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
        // PitchRollYaw (0xe43b) / Accelerometer (0xe44b): the typed layer holds
        // the FINAL post-`RawConv` string (the whole record's `int16s` array
        // space-joined, then `substr` from CHARACTER index 8 — see the parser).
        // No PrintConv ⇒ emit verbatim in both modes, positioned after
        // `DateTime` per tag-id order (Sony.pm:10877-10887).
        if let Some(v) = cam.pitch_roll_yaw() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "PitchRollYaw".into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
        if let Some(v) = cam.accelerometer() {
          sony_scratch.push(EmittedTag::new(
            group.clone(),
            "Accelerometer".into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
        // ── GPS family (Sony.pm:10738-10811 order) ─────────────────────────
        if let Some(gps) = sample.gps() {
          // GPSVersionID (0x8500): the typed layer holds the DOTTED form
          // (`"2.2.0.0"`, post-`tr/ /./`); `-j` emits it verbatim, `-n` the
          // pre-PrintConv SPACE-joined form (`"2 2 0 0"`).
          if let Some(v) = gps.version_id() {
            let value = if print_conv {
              TagValue::Str(v.into())
            } else {
              TagValue::Str(v.replace('.', " ").into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSVersionID".into(),
              value,
              false,
            ));
          }
          // GPSLatitudeRef (0x8501): `%printConvLatRef` `N`→North / `S`→South at
          // `-j`; the raw char at `-n`.
          if let Some(v) = gps.latitude_ref() {
            let value = if print_conv {
              TagValue::Str(sony_rtmd_lat_ref_print(v).into())
            } else {
              TagValue::Str(v.into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSLatitudeRef".into(),
              value,
              false,
            ));
          }
          // GPSLatitude (0x8502): a PRESENT record is always a DEFINED tag —
          // the UNSIGNED magnitude (the hemisphere is the separate `Ref` tag)
          // for a finite `SonyRtmdCoord::Value` (`GPS::ToDMS` at `-j`, NO
          // hemisphere suffix — oracle `"47 deg 37' 42.30\""`; raw F64 at
          // `-n`), OR the EMPTY STRING `""` for a `SonyRtmdCoord::Empty` (the
          // `GPS::ToDegrees` `""` render of an inf/undef component — emitted at
          // BOTH `-j` and `-n`, verified vs bundled 13.59).
          if let Some(coord) = gps.latitude() {
            let value = sony_rtmd_gps_coord_value(coord, print_conv);
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSLatitude".into(),
              value,
              false,
            ));
          }
          // GPSLongitudeRef (0x8503): `%printConvLonRef` `E`→East / `W`→West.
          if let Some(v) = gps.longitude_ref() {
            let value = if print_conv {
              TagValue::Str(sony_rtmd_lon_ref_print(v).into())
            } else {
              TagValue::Str(v.into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSLongitudeRef".into(),
              value,
              false,
            ));
          }
          // GPSLongitude (0x8504): same shape as GPSLatitude — the UNSIGNED
          // magnitude (`ToDMS` at `-j`) for a finite `Value`, or `""` for an
          // `Empty` (the `GPS::ToDegrees` `""` render).
          if let Some(coord) = gps.longitude() {
            let value = sony_rtmd_gps_coord_value(coord, print_conv);
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSLongitude".into(),
              value,
              false,
            ));
          }
          // GPSTimeStamp (0x8507): the stored value is the post-ValueConv
          // (`ConvertTimeStamp`) `HH:MM:SS[.ddd…]` string (up to 9 fractional
          // digits) — emitted verbatim at `-n`. At `-j` the PrintConv
          // `PrintTimeStamp` ROUNDS the fractional seconds to microseconds
          // (6 digits); a whole-second value is unchanged.
          if let Some(v) = gps.time_stamp() {
            let value = if print_conv {
              TagValue::Str(sony_rtmd_print_time_stamp(v).into())
            } else {
              TagValue::Str(v.into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSTimeStamp".into(),
              value,
              false,
            ));
          }
          // GPSStatus (0x8509): `A`→"Measurement Active" / `V`→"Measurement
          // Void" at `-j`; the raw char at `-n`.
          if let Some(v) = gps.status() {
            let value = if print_conv {
              TagValue::Str(sony_rtmd_gps_status_print(v).into())
            } else {
              TagValue::Str(v.into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSStatus".into(),
              value,
              false,
            ));
          }
          // GPSMeasureMode (0x850a): `2`/`3`→"<n>-Dimensional Measurement" at
          // `-j`; the raw char at `-n`.
          if let Some(v) = gps.measure_mode() {
            let value = if print_conv {
              TagValue::Str(sony_rtmd_gps_measure_mode_print(v).into())
            } else {
              TagValue::Str(v.into())
            };
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSMeasureMode".into(),
              value,
              false,
            ));
          }
          // GPSMapDatum (0x8512): the datum string (`"WGS-84"`), no conv.
          if let Some(v) = gps.map_datum() {
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSMapDatum".into(),
              TagValue::Str(v.into()),
              false,
            ));
          }
          // GPSDateStamp (0x851d): the `YYYY:MM:DD` string, no conv.
          if let Some(v) = gps.date_stamp() {
            sony_scratch.push(EmittedTag::new(
              group.clone(),
              "GPSDateStamp".into(),
              TagValue::Str(v.into()),
              false,
            ));
          }
        }
        if g3 {
          tags.append(&mut sony_scratch);
        } else {
          if cur_doc != Some(doc_n) {
            flush_doc(&mut doc_vals, &mut sony_committed, &mut tags);
            cur_doc = Some(doc_n);
          }
          for tag in sony_scratch.drain(..) {
            let key = (
              smol_str::SmolStr::new(tag.tag().group_ref().family1()),
              smol_str::SmolStr::new(tag.tag().name()),
            );
            if let Some(slot) = doc_vals.iter_mut().find(|(k, _)| *k == key) {
              slot.1 = tag;
            } else {
              doc_vals.push((key, tag));
            }
          }
        }
      }
      flush_doc(&mut doc_vals, &mut sony_committed, &mut tags);
    }

    // ── SP4: Canon CTMD per-sample TimeStamp / Focal / Exposure (Canon) ──
    // `ProcessCTMD` (Canon.pm:10758-10804) decodes ONE timed sample per `CTMD`
    // sample-table entry; ExifTool's `ProcessSamples` opens a `Doc<N>` per
    // sample and `HandleTag`s every decoded record under it, scoped to the
    // enclosing `Track<N>` (family-1). NOTE (oracle-verified vs bundled 13.59):
    // although `%Canon::CTMD` declares `GROUPS => { 1 => 'Canon' }`, the timed-
    // metadata `ProcessSamples` machinery re-scopes every record's family-1 to
    // the trak's `Track<N>` (oracle `Doc1:Track1:TimeStamp`, NOT `Canon:…`) —
    // IDENTICAL group machinery to the `rtmd` / `mebx` blocks above. Gated on
    // `-ee`; `-G1` collapses every `Doc<N>` to one `(Track<N>, name)` row
    // (within-sample last-wins, across-sample first-wins). Each sample's records
    // emit in the fixed Canon.pm record order (SampleTime/SampleDuration, then
    // TimeStamp, FocalLength, then the ExposureInfo FNumber/ExposureTime/ISO) so
    // the rendered key order matches the oracle token-for-token.
    if opts.extract_embedded {
      let g3 = matches!(opts.group_mode, crate::serialize_key::GroupMode::G3);
      // Fallback running ordinal for any unstamped sample (none in practice —
      // the walker stamps `doc()` on every sample); when stamped, used verbatim
      // so all of one sample's records share ONE `Doc<N>`.
      let mut doc: u32 = 0;
      let mut ctmd_scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
      // `-G1` collapse state (unused at `-G3`), keyed by `(family1, name)` —
      // the same two-rule collapse the `rtmd` block documents: within one
      // sample last-wins, across samples first-wins.
      let mut ctmd_committed: std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)> =
        std::vec::Vec::new();
      let mut doc_vals: std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)> =
        std::vec::Vec::new();
      let mut cur_doc: Option<u32> = None;
      let flush_doc =
        |doc_vals: &mut std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)>,
         committed: &mut std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)>,
         tags: &mut std::vec::Vec<EmittedTag>| {
          for (key, tag) in doc_vals.drain(..) {
            if committed.contains(&key) {
              continue;
            }
            committed.push(key);
            tags.push(tag);
          }
        };
      for sample in self.canon_ctmd.samples() {
        let doc_n = if sample.doc() == 0 {
          doc += 1;
          doc
        } else {
          sample.doc()
        };
        let track = std::format!("Track{}", {
          let t = sample.track_index();
          if t == 0 { 1 } else { t }
        });
        let group = if g3 {
          Group::with_doc("QuickTime", track.as_str(), doc_n)
        } else {
          Group::new("QuickTime", track.as_str())
        };
        ctmd_scratch.clear();
        // SampleTime / SampleDuration (`ConvertDuration` at `-j`, raw seconds at
        // `-n`) — the sample-table timing emitted ahead of the decoded payload.
        for (val, name) in [
          (sample.sample_time(), "SampleTime"),
          (sample.sample_duration(), "SampleDuration"),
        ] {
          if let Some(secs) = val {
            let value = if print_conv {
              TagValue::Str(crate::datetime::convert_duration(secs).into())
            } else {
              TagValue::F64(secs)
            };
            ctmd_scratch.push(EmittedTag::new(group.clone(), name.into(), value, false));
          }
        }
        // TimeStamp (type 1, Canon.pm:9798-9806): the assembled
        // `"YYYY:MM:DD HH:MM:SS.cc"` string. The PrintConv is `ConvertDateTime`,
        // which passes this already-formatted Date/Time string through
        // unchanged — emit verbatim in BOTH `-j` and `-n` (oracle-verified).
        if let Some(v) = sample.time_stamp() {
          ctmd_scratch.push(EmittedTag::new(
            group.clone(),
            "TimeStamp".into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
        // FocalLength (type 4, Canon.pm:9853-9864): `rational32u`, stored as the
        // raw [`Rational`] (num/denom). At `-j` the PrintConv `sprintf("%.1f
        // mm",$val)` → e.g. `"15.0 mm"` / `"3.3 mm"` for a finite quotient, or
        // the numified non-finite (`"Inf mm"` for `n/0`, `"0.0 mm"` for `0/0`);
        // at `-n` the raw `rational32u` `%.7g` form (`10/3` → `3.333333`,
        // `inf`/`undef` for a zero denominator). See the helper.
        if let Some(focal) = sample.focal()
          && let Some(r) = focal.focal_length_rational()
        {
          ctmd_scratch.push(EmittedTag::new(
            group.clone(),
            "FocalLength".into(),
            canon_ctmd_focal_length_value(r, print_conv),
            false,
          ));
        }
        // ── ExposureInfo (type 5, Canon.pm:9866-9887) ─────────────────────
        if let Some(exp) = sample.exposure() {
          // FNumber (index 0): `rational32u`, stored as the raw [`Rational`]. At
          // `-j` the PrintConv `Exif::PrintFNumber` of the ValueConv string
          // (a finite quotient rounds to 1-2 decimals, e.g. `3.5`; a zero
          // denominator's `undef`/`inf` word passes through unchanged); at `-n`
          // the raw `rational32u` `%.7g` form. See the helper.
          if let Some(r) = exp.f_number_rational() {
            ctmd_scratch.push(EmittedTag::new(
              group.clone(),
              "FNumber".into(),
              canon_ctmd_fnumber_value(r, print_conv),
              false,
            ));
          }
          // ExposureTime (index 1): `rational32u`, stored as the raw
          // [`Rational`]. At `-j` the PrintConv `Exif::PrintExposureTime` of the
          // ValueConv string (`1/80` → `"1/80"`; a zero denominator's
          // `undef`/`inf` passes through); at `-n` the raw `rational32u` `%.7g`
          // form (`1/3` → `0.3333333`). See the helper.
          if let Some(r) = exp.exposure_time_rational() {
            ctmd_scratch.push(EmittedTag::new(
              group.clone(),
              "ExposureTime".into(),
              canon_ctmd_exposure_time_value(r, print_conv),
              false,
            ));
          }
          // ISO (index 2): `int32u` with `ValueConv => '$val & 0x7fffffff'`
          // (already masked in the typed layer). No PrintConv — the plain
          // integer in BOTH modes (oracle `12800`).
          if let Some(iso) = exp.iso() {
            ctmd_scratch.push(EmittedTag::new(
              group.clone(),
              "ISO".into(),
              TagValue::U64(u64::from(iso)),
              false,
            ));
          }
        }
        // ── ExifInfo7/8/9 (types 7/8/9, Canon.pm:9818-9853) ───────────────
        // Re-dispatch each embedded TIFF block through the Exif / Canon
        // MakerNote walker, re-stamped to the bundled group (the EXIF tags
        // re-scope to `EXIF:ExifIFD`, the MakerNote tags to `MakerNotes:
        // Track<N>`, ExifByteOrder to `File:Track<N>` — all under this
        // sample's `Doc<N>`). The blocks ride after the type-1/4/5 scalars in
        // walk order; the same g3 / first-wins dedup below folds them.
        for info in sample.exif_info() {
          emit_ctmd_exif_info(
            info,
            track.as_str(),
            doc_n,
            g3,
            print_conv,
            &mut ctmd_scratch,
          );
        }
        if g3 {
          tags.append(&mut ctmd_scratch);
        } else {
          if cur_doc != Some(doc_n) {
            flush_doc(&mut doc_vals, &mut ctmd_committed, &mut tags);
            cur_doc = Some(doc_n);
          }
          for tag in ctmd_scratch.drain(..) {
            let key = (
              smol_str::SmolStr::new(tag.tag().group_ref().family1()),
              smol_str::SmolStr::new(tag.tag().name()),
            );
            if let Some(slot) = doc_vals.iter_mut().find(|(k, _)| *k == key) {
              slot.1 = tag;
            } else {
              doc_vals.push((key, tag));
            }
          }
        }
      }
      flush_doc(&mut doc_vals, &mut ctmd_committed, &mut tags);
    }

    // ── SP4: Canon CTMD ProcessCTMD / TimeStamp-RawConv warnings ───────────
    // `ProcessCTMD` (Canon.pm:10781/10782/10802) + the type-1 `TimeStamp`
    // `RawConv` (Canon.pm:9801-9805) raise warnings under the SAMPLE that
    // raised them — `ProcessSamples` opens a `Doc<N>` per sample
    // (`FoundSomething`) and `$et->Warn` `FoundTag`s the `Warning` under that
    // open `DOC_NUM`, scoped to the trak's `Track<N>`. The per-sample
    // SampleTime/SampleDuration are already emitted by the CTMD payload block
    // above (every CTMD sample — warning-only ones included — gets one), so
    // this emitter pushes ONLY the `Warning` payload (priority-0 first-wins +
    // WAS_WARNED `[xN]` dedup), exactly like [`emit_camm_warnings`]. The
    // MINOR residue warning (`Warn(..., 1)`) carries the `[minor] ` prefix.
    emit_ctmd_warnings(self.canon_ctmd.warnings(), opts, &mut first_seen, &mut tags);

    // ── SP4: Insta360 INSV/INSP trailer (ProcessInsta360) ──────────────────
    // The file-END trailer's tags (QuickTimeStream.pl:3252-3478) under the
    // family-1 `Insta360` group: the always-on `[minor]` trailer warning
    // (QuickTime.pm:10600, every mode), then — at `-ee` — the timed records
    // (GPS/exposure/videotimestamp/accelerometer) on the shared global
    // `Doc<N>` axis + the sticky-doc identity. The two-rule `%noDups` `-G1`
    // collapse is applied over the doc-ORDERED UNION of ALL record types (so
    // the cross-type `TimeCode` collision resolves to the lowest doc). See
    // [`emit_insta360`].
    emit_insta360(&self.insta360, opts, print_conv, &mut first_seen, &mut tags);

    // ── SP4: GoPro GPMF (Image::ExifTool::GoPro) ───────────────────────
    // The `%GoPro::GPMF` / `%GoPro::GPS5` / `%GoPro::GPS9` tables emit under
    // family-0 `GoPro` (the module group) and family-1 `GoPro`
    // (GoPro.pm:67-69, 489-490/518-519 `GROUPS => { 1 => 'GoPro' }`). Like the
    // SP3 stream above, ExifTool emits one `Doc<N>` sub-document per GPS row;
    // exifast's flat TagMap cannot reproduce that shape, so the FIRST GPS fix
    // is summarized here (the typed [`Meta::gopro`] accessor exposes the full
    // per-sample list). The block-level camera-identity + GPSU/GPSF/GPSP/GPSA
    // scalars are one-per-file. Emitted under `GoPro`:`GoPro`.
    {
      let gp = &self.gopro;
      // family0 = family1 = "GoPro" for every GoPro GPMF tag.
      let gpg = || Group::new("GoPro", "GoPro");
      // ── camera identity (block-level, `c` ASCII; no conv) ──────────────
      // DVNM/MINF/CASN/FMWR (GoPro.pm:57/286-290/121/195). Plain ASCII strings
      // with no ValueConv/PrintConv — emit verbatim in both modes.
      for (val, name) in [
        (gp.device_name(), "DeviceName"),
        (gp.model(), "Model"),
        (gp.camera_serial_number(), "CameraSerialNumber"),
        (gp.firmware_version(), "FirmwareVersion"),
      ] {
        if let Some(s) = val {
          tags.push(EmittedTag::new(
            gpg(),
            name.into(),
            TagValue::Str(s.into()),
            false,
          ));
        }
      }
      // MUID `MediaUniqueID` (GoPro.pm:456-462): the typed layer stores the
      // RAW space-joined `u32` list (ExifTool's ValueConv). `-n` emits that
      // raw value; `-j` (PrintConv) hex-renders each element and concatenates.
      if let Some(raw) = gp.media_uid() {
        tags.push(EmittedTag::new(
          gpg(),
          "MediaUniqueID".into(),
          media_uid_value(raw, print_conv),
          false,
        ));
      }
      // ── block-level GPS scalars ────────────────────────────────────────
      // GPSU `GPSDateTime` (GoPro.pm:242-248): the typed layer stores the
      // post-ValueConv `20YY:MM:DD HH:MM:SS[.fff]` (NO timezone suffix — the
      // `ConvertDateTime` PrintConv adds none by default); it is a no-op
      // cosmetic on that shape (emit in both modes).
      if let Some(dt) = gp.gps_date_time() {
        tags.push(EmittedTag::new(
          gpg(),
          "GPSDateTime".into(),
          TagValue::Str(dt.into()),
          false,
        ));
      }
      // GPSF `GPSMeasureMode` (GoPro.pm:230-236): PrintConv 2/3 →
      // "<n>-Dimensional Measurement"; `-n` emits the raw code.
      if let Some(mode) = gp.gps_measure_mode() {
        tags.push(EmittedTag::new(
          gpg(),
          "GPSMeasureMode".into(),
          gps_measure_mode_value(mode, print_conv),
          false,
        ));
      }
      // GPSP `GPSHPositioningError` (GoPro.pm:237-241): ValueConv `$val / 100`
      // (cm→m) already applied in the typed layer; no PrintConv. F64 metres.
      if let Some(err_m) = gp.gps_h_positioning_error_m() {
        tags.push(EmittedTag::new(
          gpg(),
          "GPSHPositioningError".into(),
          TagValue::F64(err_m),
          false,
        ));
      }
      // GPSA `GPSAltitudeSystem` (GoPro.pm:472): 4-char ID, no conv.
      if let Some(sys) = gp.gps_altitude_system() {
        tags.push(EmittedTag::new(
          gpg(),
          "GPSAltitudeSystem".into(),
          TagValue::Str(sys.into()),
          false,
        ));
      }
      // SYST `SystemTime` (GoPro.pm:390-405): a DEFAULT tag (no
      // `Unknown`/`Hidden`), emitted by `exiftool -ee`. The typed layer stores
      // the post-`SCAL` space-joined display string of the FIRST `SYST` record
      // (the calibration side-effect lives on the `SystemTimeList`). No
      // ValueConv/PrintConv beyond the `RawConv` pass-through ⇒ emit verbatim in
      // both modes.
      if let Some(st) = gp.system_time() {
        tags.push(EmittedTag::new(
          gpg(),
          "SystemTime".into(),
          TagValue::Str(st.into()),
          false,
        ));
      }
      // ── first GPS5/GPS9 fix (summarized; full list via `Meta::gopro`) ──
      if let Some(fix) = gp.first_fix() {
        // GPSLatitude/GPSLongitude: the `GPS::ToDMS` PrintConv
        // (GoPro.pm:493-499) is a GPS-port dependency (same deferral as the
        // SP3 stream above); emit post-ValueConv decimal degrees in BOTH
        // modes.
        if let (Some(lat), Some(lon)) = (fix.latitude(), fix.longitude()) {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSLatitude".into(),
            TagValue::F64(lat),
            false,
          ));
          tags.push(EmittedTag::new(
            gpg(),
            "GPSLongitude".into(),
            TagValue::F64(lon),
            false,
          ));
        }
        // GPSAltitude (GoPro.pm:500-503): typed layer stores metres; the
        // `"$val m"` PrintConv is deferred (consistent with the SP3 stream's
        // raw-F64 altitude). Emit F64 metres in both modes.
        if let Some(alt) = fix.altitude_m() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSAltitude".into(),
            TagValue::F64(alt),
            false,
          ));
        }
        // GPSSpeed / GPSSpeed3D (GoPro.pm:504-513): ValueConv `$val * 3.6`
        // converts the stored m/s to KM/H — applied HERE on emission (the
        // typed [`GoProGpsSample`] keeps m/s). No PrintConv ⇒ faithful in both
        // `-j`/`-n`.
        if let Some(spd) = fix.speed_2d_mps() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSSpeed".into(),
            TagValue::F64(spd * 3.6),
            false,
          ));
        }
        if let Some(s3d) = fix.speed_3d_mps() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSSpeed3D".into(),
            TagValue::F64(s3d * 3.6),
            false,
          ));
        }
        // GPS9-only per-sample columns (GoPro.pm:543-562). `GPSDateTime` here
        // is the per-sample value (derived from the GPS-days/seconds columns);
        // it overrides the block-level GPSU above under the sink's last-wins
        // when a GPS9 file also carried a GPSU (a GPS9 file normally does not).
        if let Some(dt) = fix.date_time() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSDateTime".into(),
            TagValue::Str(dt.into()),
            false,
          ));
        }
        if let Some(dop) = fix.dop() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSDOP".into(),
            TagValue::F64(dop),
            false,
          ));
        }
        if let Some(mode) = fix.measure_mode() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSMeasureMode".into(),
            gps_measure_mode_value(mode, print_conv),
            false,
          ));
        }
      }
      // ── Karma GLPI (`GPSPos`, GoPro.pm:197-204/598-626) ────────────────
      // Like the GPS5/GPS9 fix above, ExifTool emits one `Doc<N>` per GLPI
      // row; the FIRST sample is summarized here (the full per-sample list is
      // on [`Meta::gopro`]'s `glpi_samples()`). Column order = table order
      // (GoPro.pm:602-625): GPSDateTime, GPSLatitude, GPSLongitude,
      // GPSAltitude, GPSSpeedX/Y/Z, GPSTrack. The `Unknown`/`Hidden` col 4 is
      // not emitted. Lat/lon defer the `GPS::ToDMS` PrintConv (raw decimal
      // degrees, like GPS5/GPS9); altitude defers its `"$val m"` PrintConv (raw
      // F64). The speeds (cols 5-7) DO apply their `'"$val m/s"'` PrintConv in
      // `-j` mode (R6-C) — GLPI speeds carry NO `*3.6` km/h `ValueConv` (the
      // table has only the suffix PrintConv), so they stay m/s; `-n` emits the
      // raw F64. `GPSTrack` (col 8) has no PrintConv (raw both modes).
      // `GPSDateTime` is the `ConvertSystemTime` string emitted verbatim (incl.
      // the `<uncalibrated>` / `0000:00:00 00:00:00` literals).
      if let Some(g) = gp.first_glpi_fix() {
        if let Some(dt) = g.date_time() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSDateTime".into(),
            TagValue::Str(dt.into()),
            false,
          ));
        }
        if let (Some(lat), Some(lon)) = (g.latitude(), g.longitude()) {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSLatitude".into(),
            TagValue::F64(lat),
            false,
          ));
          tags.push(EmittedTag::new(
            gpg(),
            "GPSLongitude".into(),
            TagValue::F64(lon),
            false,
          ));
        }
        if let Some(alt) = g.altitude_m() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSAltitude".into(),
            TagValue::F64(alt),
            false,
          ));
        }
        // GPSSpeedX/Y/Z (GoPro.pm:622-624): PrintConv `'"$val m/s"'`. `-j`
        // renders the scaled m/s value with the ` m/s` suffix
        // ([`unit_suffix_value`]); `-n` (ValueConv) emits the raw F64.
        for (val, name) in [
          (g.speed_x_mps(), "GPSSpeedX"),
          (g.speed_y_mps(), "GPSSpeedY"),
          (g.speed_z_mps(), "GPSSpeedZ"),
        ] {
          if let Some(v) = val {
            tags.push(EmittedTag::new(
              gpg(),
              name.into(),
              unit_suffix_value(v, " m/s", print_conv),
              false,
            ));
          }
        }
        if let Some(tr) = g.track_deg() {
          tags.push(EmittedTag::new(
            gpg(),
            "GPSTrack".into(),
            TagValue::F64(tr),
            false,
          ));
        }
      }
      // ── Karma KBAT (`BatteryStatus`, GoPro.pm:264-270/628-649) ─────────
      // The FIRST battery record is summarized (full list on
      // [`Meta::gopro`]'s `kbat_records()`). Column order = table order
      // (GoPro.pm:634-648): BatteryCurrent, BatteryCapacity,
      // BatteryTemperature, BatteryVoltage1..4, BatteryTime, BatteryLevel.
      // The `Unknown`/`Hidden` cols (2/9/10-13) are not emitted. Each named
      // column carries a unit-suffix PrintConv (GoPro.pm:634-648) applied in
      // `-j` (PrintConv) mode via [`unit_suffix_value`]; `-n` (ValueConv) emits
      // the raw scaled F64. `BatteryTime` (col 8) instead uses
      // `ConvertDuration(int($val + 0.5))` — emitted in column order, before
      // `BatteryLevel`.
      if let Some(k) = gp.kbat_records().first() {
        // (value, name, PrintConv): `Suffix` = `'"$val <unit>"'`; `Duration` =
        // `ConvertDuration(int($val + 0.5))`.
        enum KbatConv {
          Suffix(&'static str),
          Duration,
        }
        for (val, name, conv) in [
          (k.current_a(), "BatteryCurrent", KbatConv::Suffix(" A")),
          (k.capacity_ah(), "BatteryCapacity", KbatConv::Suffix(" Ah")),
          (
            k.temperature_c(),
            "BatteryTemperature",
            KbatConv::Suffix(" C"),
          ),
          (k.voltage1_v(), "BatteryVoltage1", KbatConv::Suffix(" V")),
          (k.voltage2_v(), "BatteryVoltage2", KbatConv::Suffix(" V")),
          (k.voltage3_v(), "BatteryVoltage3", KbatConv::Suffix(" V")),
          (k.voltage4_v(), "BatteryVoltage4", KbatConv::Suffix(" V")),
          (k.time_s(), "BatteryTime", KbatConv::Duration),
          (k.level_pct(), "BatteryLevel", KbatConv::Suffix(" %")),
        ] {
          if let Some(v) = val {
            let value = match conv {
              KbatConv::Suffix(unit) => unit_suffix_value(v, unit, print_conv),
              // `int($val + 0.5)` rounds the scaled seconds to the nearest
              // second (Perl `int()` truncates toward zero; battery time is a
              // non-negative duration) before `ConvertDuration` ([`convert_duration`]);
              // `-n` emits the raw scaled F64 seconds.
              KbatConv::Duration if print_conv => {
                TagValue::Str(convert_duration((v + 0.5).trunc()).into())
              }
              KbatConv::Duration => TagValue::F64(v),
            };
            tags.push(EmittedTag::new(gpg(), name.into(), value, false));
          }
        }
      }
      // ── every OTHER default-visible %GoPro::GPMF tag (table-driven) ────
      // ExifTool's `ProcessGoPro` `HandleTag`s every default-visible tag
      // (GoPro.pm:885); the typed surface above models the GPS/Karma/camera-id
      // subset, and [`GoProMeta::generic_tags`] carries the remaining ~95
      // (sensor streams + Protune/codec settings + calibrations) decoded in
      // walk order. Each is rendered to its `-n`/`-j` value here by conv family
      // ([`gopro_generic_value`]) under the same `GoPro`:`GoPro` group. A
      // `Binary => 1` tag renders as the `(Binary data N bytes…)` placeholder
      // in BOTH modes (GoPro.pm `Binary` → ValueConv `'\$val'`), N = byte length
      // of the post-`ScaleValues` value string (exiftool:3987).
      for gt in gp.generic_tags() {
        tags.push(EmittedTag::new(
          gpg(),
          gt.name().into(),
          gopro_generic_value(gt, print_conv),
          false,
        ));
      }
    }

    // ── SP4: Android CAMM cross-kind `-G1` SampleTime/SampleDuration ────────
    // At `-ee -G1` the single `Track<N>:SampleTime`/`SampleDuration` is the timing
    // of that track's MINIMUM-`doc()` (FIRST) camm SAMPLE across ALL record kinds
    // — GPS, motion (camm2/3/4/7 + camm1 exposure), AND `ProcessCAMM` warnings —
    // because ExifTool emits each sample's timing in sample order BEFORE
    // dispatching that sample's packets and `%noDups` is first-wins
    // (QuickTimeStream.pl:1518-1523; [`camm_min_doc_timing`]). exifast's per-kind
    // emitters below drain records in EMITTER-KIND order (warnings, then GPS, then
    // motion), NOT sample order, so the cross-kind minimum cannot be found by a
    // per-kind first-wins gate (a track whose first sample is a kind emitted LATER
    // would wrongly keep an earlier-emitted-but-later-sample kind's timing). So
    // precompute the min-`doc()` timing per track HERE and emit it FIRST through
    // the shared `first_seen` gate: it occupies the priority-0 first-wins
    // `(Track<N>, SampleTime)`/`SampleDuration` slot, and the per-kind emitters'
    // own `-G1` timing (now `-G3`-only) is gated out. This SUPERSEDES the previous
    // per-emitter `-G1` timing gating (the warning path's `push_timing`-through-
    // `first_seen`, the GPS path's post-emit filter, the motion path's
    // `timing_first_seen`), which only happened to work when the FIRST emitter
    // (warnings) owned the minimum sample. At `-G3` each `Doc<N>` keeps its own
    // sample's timing (no precompute — this block is `-G1`-only).
    if opts.extract_embedded && !matches!(opts.group_mode, crate::serialize_key::GroupMode::G3) {
      for (track, st, sd) in camm_min_doc_timing(&self.android_camm) {
        let group = Group::new("QuickTime", std::format!("Track{track}").as_str());
        for (val, name) in [(st, "SampleTime"), (sd, "SampleDuration")] {
          if let Some(secs) = val
            && first_seen(group.family1(), name)
          {
            let value = if print_conv {
              TagValue::Str(crate::datetime::convert_duration(secs).into())
            } else {
              TagValue::F64(secs)
            };
            tags.push(EmittedTag::new(group.clone(), name.into(), value, false));
          }
        }
      }
    }

    // ── SP4: Android CAMM ProcessCAMM warnings (QuickTimeStream.pl:3495-96) ─
    // `ProcessCAMM` `$et->Warn`s then `last`s on an UNKNOWN packet type
    // (`Unknown camm record type N`, incl. type 0) or a TRUNCATED packet
    // (`Truncated camm record N`). Both are plain `$et->Warn(msg)` calls (NO
    // `ignorable` arg) ⇒ NO `[minor]` prefix (contrast the eeBox EEWarn's
    // `Warn(msg, 3)`). `ProcessCAMM` runs only under `ExtractEmbedded`, so the
    // warning surfaces ONLY at `-ee`; a no-`ee` parse instead shows the
    // `[minor]` EEWarn raised in the `HandlerType` RawConv above. See
    // [`emit_camm_warnings`] for the `WAS_WARNED` string-dedup (`[xN]` count),
    // the `Doc<N>:Track<N>` axis, and the priority-0 first-wins `-G1` collapse.
    emit_camm_warnings(
      self.android_camm.warnings(),
      opts,
      print_conv,
      &mut first_seen,
      &mut tags,
    );

    // ── SP4: Android CAMM (Image::ExifTool::QuickTime::camm5/camm6) ─────
    // The `%QuickTime::camm5`/`camm6` GPS tables (QuickTimeStream.pl:479-560)
    // emit one `Doc<N>` sub-document per CAMM packet, family-1 `Track<N>` (the
    // moov track number `ProcessCAMM` runs under; oracle: `Track1:GPSLatitude` /
    // `Doc1:Track1:GPSLatitude`). The shared [`emit_timed_samples`] reproduces
    // that, gated on `-ee`: every fix as a `Doc<N>` row at `-G3`, the
    // first-fix-wins collapse at `-G1` (so a camm6-only column following two
    // camm5 fixes still surfaces). The per-sample track is the `track_index`
    // the walker stamped (default `Track1`); the altitude PrintConv differs by
    // packet type (camm5 `%.6f`, camm6 `%.3f`). The camm6 accuracy / velocity
    // columns (no PrintConv) ride `emit_extra` as raw `F64` (the f32→f64
    // widening the oracle prints, e.g. `0.100000001490116`). `SampleTime`/
    // `SampleDuration` (the sample-table timing): at `-G3` each `Doc<N>` carries
    // its own via `sample_timing()` (`None` for the stream-GPS / magic-box sources,
    // so none leak onto gps0/gsen/3gf/Kenwood/moov-`gps `/freeGPS); at `-G1` the
    // single `Track<N>:SampleTime` is the cross-kind MINIMUM-`doc()` sample's,
    // emitted by the [`camm_min_doc_timing`] precompute block above (through the
    // shared first-wins gate), so `emit_timed_samples` no longer emits any `-G1`
    // timing for the GPS path to reconcile.
    emit_timed_samples(
      self.android_camm.gps_samples(),
      |s| {
        Group::new(
          "QuickTime",
          std::format!("Track{}", s.track_index().unwrap_or(1)),
        )
      },
      opts,
      print_conv,
      camm_gps_measure_mode_value,
      |s, alt, pc| gps_altitude_camm_value(alt, s.packet_type(), pc),
      |s, group, scratch| {
        // camm6 GPSHorizontalAccuracy / GPSVerticalAccuracy / GPSVelocity{East,
        // North,Up} / GPSSpeedAccuracy (QuickTimeStream.pl:554-559): `float`
        // columns with NO PrintConv — emit the raw value (f32 widened to f64,
        // matching the oracle's `%.15g` of the widened float) in both modes.
        for (val, name) in [
          (s.horizontal_accuracy_m(), "GPSHorizontalAccuracy"),
          (s.vertical_accuracy_m(), "GPSVerticalAccuracy"),
          (s.velocity_east_mps(), "GPSVelocityEast"),
          (s.velocity_north_mps(), "GPSVelocityNorth"),
          (s.velocity_up_mps(), "GPSVelocityUp"),
          (s.speed_accuracy_mps(), "GPSSpeedAccuracy"),
        ] {
          if let Some(v) = val {
            scratch.push(EmittedTag::new(
              group.clone(),
              name.into(),
              TagValue::F64(f64::from(v)),
              false,
            ));
          }
        }
      },
      &mut tags,
    );

    // ── SP4: Android CAMM MOTION (camm1-4/7 — QuickTimeStream.pl:428-569) ──
    // The non-GPS camm records `ProcessCAMM` `HandleTag`s — camm2 AngularVelocity
    // / camm3 Acceleration / camm4 Position / camm7 MagneticField (`float[3]`
    // space-joined, mode-invariant) and camm1 PixelExposureTime /
    // RollingShutterSkewTime (seconds, `sprintf("%.4g ms")` PrintConv at `-j`).
    // ExifTool emits each under the same `Track<N>` / `Doc<N>` axis as the GPS
    // camm fixes (one doc per camm SAMPLE; a sample with both a GPS and a motion
    // packet shares the doc — stamped at extraction). `-ee`-gated like the GPS
    // path (camm is a handler `trak`): at no-`ee` nothing here surfaces. camm0's
    // `AngleAxis` is intentionally absent — type 0 is not in `ProcessCAMM`'s
    // `%size`, so the walk `last`s on it (the typed `angle_axis` vec stays empty).
    // Each vector type carries a DISTINCT tag name, so the per-type collapse is
    // independent (no cross-type `(family1, name)` collision).
    for (samples, name) in [
      (self.android_camm.angular_velocity(), "AngularVelocity"),
      (self.android_camm.acceleration(), "Acceleration"),
      (self.android_camm.position(), "Position"),
      (self.android_camm.magnetic_field(), "MagneticField"),
    ] {
      emit_camm_motion(
        samples,
        crate::metadata::CammVector3::doc,
        crate::metadata::CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        print_conv,
        |v, group, scratch| {
          scratch.push(EmittedTag::new(
            group.clone(),
            name.into(),
            camm_vec3_value(v),
            false,
          ));
        },
        opts,
        &mut tags,
      );
    }
    emit_camm_motion(
      self.android_camm.exposure(),
      crate::metadata::CammExposure::doc,
      crate::metadata::CammExposure::track_index,
      |e| (e.sample_time(), e.sample_duration()),
      print_conv,
      |e, group, scratch| {
        // camm1: PixelExposureTime THEN RollingShutterSkewTime (the table's
        // offset order, 4 before 8 — QuickTimeStream.pl:429/435), both with the
        // `%.4g ms` PrintConv at `-j`.
        scratch.push(EmittedTag::new(
          group.clone(),
          "PixelExposureTime".into(),
          camm_exposure_ms_value(e.pixel_exposure_time_s(), print_conv),
          false,
        ));
        scratch.push(EmittedTag::new(
          group.clone(),
          "RollingShutterSkewTime".into(),
          camm_exposure_ms_value(e.rolling_shutter_skew_time_s(), print_conv),
          false,
        ));
      },
      opts,
      &mut tags,
    );

    // ── SP4: Android CAMM TIMING-ONLY samples (recognized-empty) ───────────
    // A recognized first-packet camm sample (its first packet matched a
    // `camm0..camm7` Condition) that `ProcessCAMM` decoded to NO stored record —
    // no GPS / motion / exposure fix AND no `Unknown`/`Truncated` warning (e.g. a
    // 4-byte-only header sample). ExifTool's `FoundSomething` still emitted its
    // `SampleTime`/`SampleDuration` under the sample's `Doc<N>`
    // (QuickTimeStream.pl:1523; oracle `QuickTime_camm_emptypayload.mov`). At `-G3`
    // emit that timing on the marker's own `Doc<N>`/`Track<N>`; at `-G1` the timing
    // is owned by the cross-kind min-`doc()` precompute above (these markers are
    // among its candidates), so nothing is emitted here.
    emit_camm_timing_only(self.android_camm.timing_only(), opts, print_conv, &mut tags);

    // ── SP2: moov/meta HandlerClass + HandlerType (QuickTime.pm:8391-8444) ─
    // The `moov/meta` `hdlr` uses the SAME `%QuickTime::Handler` table as the
    // trak hdlr, so it emits BOTH HandlerClass (offset-4 ComponentType, dropped
    // when all-zero) and HandlerType (offset-8 subtype) — group `QuickTime`
    // (family-0/1), NOT a `Track<N>` (the track hdlr above is per-`trak`). The
    // ComponentType (`HandlerClass`) is emitted BEFORE the subtype
    // (`HandlerType`), matching the `%Handler` binary-table field order (offset
    // 4 before 8). `-j` applies the PrintConv; `-n` emits the raw 4-char code.
    if let Some(class) = self.qt.meta_handler_class() {
      // HandlerClass / ComponentType (QuickTime.pm:8395-8402): PrintConv
      // `mhlr`→Media Handler / `dhlr`→Data Handler; a hash miss yields
      // `Unknown ($val)`. The all-zero RawConv-undef branch is applied at decode
      // (`decode_hdlr_class` returns `None`), so a present value is non-zero.
      let value = if print_conv {
        let printed = handler_class_print(class);
        if printed.is_empty() {
          TagValue::Str(std::format!("Unknown ({class})").into())
        } else {
          TagValue::Str(printed.into())
        }
      } else {
        TagValue::Str(class.into())
      };
      tags.push(EmittedTag::new(main(), "HandlerClass".into(), value, false));
    }
    if let Some(code) = self.qt.meta_handler_type() {
      let value = if print_conv {
        let printed = handler_type_print(code);
        if printed.is_empty() {
          TagValue::Str(std::format!("Unknown ({code})").into())
        } else {
          TagValue::Str(printed.into())
        }
      } else {
        TagValue::Str(code.into())
      };
      tags.push(EmittedTag::new(main(), "HandlerType".into(), value, false));
    }

    // ── SP2: udta camera atoms (QuickTime.pm:1585-1900) ────────────────
    // Group `QuickTime:UserData` (family-0 `QuickTime`, family-1 `UserData` —
    // the `%QuickTime::UserData` table `GROUPS => { 1 => 'UserData' }`, verified
    // vs the `-G1` oracle). All are known table keys ⇒ `unknown: false`. The
    // text fields are mode-invariant (no PrintConv/ValueConv beyond the charset
    // decode); ContentCreateDate is a ValueConv-only date (same in both modes);
    // GPSCoordinates carries the ValueConv string (`-n`) / DMS PrintConv (`-j`).
    let ud = self.qt.user_data();
    if !ud.is_empty() {
      let user_data = || Group::new("QuickTime", "UserData");
      for (val, name) in [
        (ud.make(), "Make"),
        (ud.model(), "Model"),
        (ud.serial_number(), "SerialNumber"),
        (ud.software(), "SoftwareVersion"),
        (ud.firmware_version(), "FirmwareVersion"),
        (ud.compressor_version(), "CompressorVersion"),
        (ud.camera_id(), "CameraID"),
        (ud.title(), "Title"),
        (ud.copyright(), "Copyright"),
        (ud.content_create_date(), "ContentCreateDate"),
        (ud.date_time_original(), "DateTimeOriginal"),
      ] {
        if let Some(v) = val {
          tags.push(EmittedTag::new(
            user_data(),
            name.into(),
            TagValue::Str(v.into()),
            false,
          ));
        }
      }
      if let Some(gps) = ud.gps() {
        tags.push(EmittedTag::new(
          user_data(),
          "GPSCoordinates".into(),
          gps_coordinates_value(gps, print_conv),
          false,
        ));
      }
      // `©cmt` Comment — emitted after GPSCoordinates to match the `©`-atom
      // file order (cosmetic; the conformance gate is key-order-insensitive).
      if let Some(v) = ud.comment() {
        tags.push(EmittedTag::new(
          user_data(),
          "Comment".into(),
          TagValue::Str(v.into()),
          false,
        ));
      }
      // HAND-ported code-valued atoms: `CAME` SerialNumberHash / `MUID`
      // MediaUID (both the `unpack("H*")` hex string, mode-invariant).
      if let Some(v) = ud.serial_number_hash() {
        tags.push(EmittedTag::new(
          user_data(),
          "SerialNumberHash".into(),
          TagValue::Str(v.into()),
          false,
        ));
      }
      if let Some(v) = ud.media_uid() {
        tags.push(EmittedTag::new(
          user_data(),
          "MediaUID".into(),
          TagValue::Str(v.into()),
          false,
        ));
      }
      // The generated conv-less atoms (`GoProType` / `LensSerialNumber` /
      // `FieldOfView` / `MakerURL` / `CameraPitch` / `CameraYaw` / `CameraRoll`),
      // emitted by Name in walk order. Conv-less ⇒ the stored [`TagValue`] is
      // mode-invariant (always a string for UserData); all are known table keys
      // ⇒ `unknown: false`.
      for (name, value) in ud.convless() {
        tags.push(EmittedTag::new(
          user_data(),
          name.clone(),
          value.clone(),
          false,
        ));
      }
    }

    // ── SP2: moov/meta Keys/ItemList (QuickTime.pm:6651-6760) ──────────
    // Group `QuickTime:Keys` (family-0 `QuickTime`, family-1 `Keys`). All the
    // CONV-LESS identity keys (`Make`/`Model`/`Software`/`AndroidMake`/
    // `AndroidModel`/`AndroidVersion`/`AndroidCaptureFPS`/`AndroidTimeZone`/
    // `CameraDirection`/`CameraMotion`) flow through the generic `convless` loop
    // below — each carries its full string→numeric→binary cascade `TagValue`
    // ([`ilst_data_convless`], mode-invariant), so a string flag emits a string,
    // a numeric flag a number, a float flag the IEEE value, etc. Only the two
    // CONV-BEARING keys are emitted typed here: `CreationDate` (`%iso8601Date`)
    // and `GPSCoordinates` (`ConvertISO6709` + `PrintGPSCoordinates`).
    let keys = self.qt.keys();
    if !keys.is_empty() {
      let keys_group = || Group::new("QuickTime", "Keys");
      if let Some(date) = keys.creation_date() {
        tags.push(EmittedTag::new(
          keys_group(),
          "CreationDate".into(),
          TagValue::Str(date.into()),
          false,
        ));
      }
      if let Some(gps) = keys.gps() {
        tags.push(EmittedTag::new(
          keys_group(),
          "GPSCoordinates".into(),
          gps_coordinates_value(gps, print_conv),
          false,
        ));
      }
      // The conv-less Keys atoms (every modeled key except CreationDate/GPS),
      // emitted by Name in walk order. The stored [`TagValue`] carries the full
      // string→numeric→binary cascade result ([`ilst_data_convless`]) and is
      // mode-invariant (conv-less ⇒ identical under `-j`/`-n`).
      for (name, value) in keys.convless() {
        tags.push(EmittedTag::new(
          keys_group(),
          name.clone(),
          value.clone(),
          false,
        ));
      }
    }

    // NOTE: the SP3 embedded-Exif hop deferral warning is NOT part of the
    // `Taggable` stream (`run_emission` has no warning channel). It flows
    // through the sibling `Diagnose` channel ([`Meta::diagnostics`]) alongside
    // the `ProcessMOV` warning.
    tags.into_iter()
  }
}

/// Emit a timed-metadata GPS sample series faithfully. `extract_embedded=false`
/// ⇒ emit nothing (without `-ee` ExifTool surfaces no per-sample stream — the
/// `[minor] ExtractEmbedded` warning is emitted elsewhere). `-G3` emits EVERY
/// coordinate fix as its own `Doc<N>`
/// row (Doc1 = first fix); `-G1` collapses the family-3 doc axis to ONE row per
/// `(family1, name)`, FIRST-wins — exactly ExifTool's `%noDups` collapse of the
/// `Doc<N>` sub-documents (so a column carried only by a LATER fix, e.g. a camm6
/// `GPSMeasureMode` that follows two camm5 fixes, still surfaces; the COMMON
/// columns keep the FIRST fix's value).
///
/// `group_for` yields each sample's BASE (doc-0) [`Group`] — fixed
/// (`QuickTime:QuickTime`) for the moov-level stream, or per-sample
/// `QuickTime:Track<N>` for a track-scoped camm packet (the family-1 group can
/// differ per sample). The common columns (lat/lon/alt/track/dop/measure-mode/
/// date_time) render mode-dependently here; the per-source speed/extra columns
/// are written by `emit_extra` (it has the quicktime PrintConv helpers). At `-j`
/// (`print_conv`) lat/lon become the `GPS::ToDMS` DMS string with the N/S · E/W
/// hemisphere and altitude gets its per-source `" m"` PrintConv (`alt_render`);
/// at `-n` both are the raw post-ValueConv [`TagValue::F64`].
///
/// Doc numbering mirrors ExifTool `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`
/// (QuickTimeStream.pl:967-973): `++doc` ONLY for a coordinate-bearing fix, so a
/// no-coordinate sample neither emits nor consumes a `Doc<N>` slot.
#[cfg(feature = "alloc")]
fn emit_timed_samples<S: crate::metadata::TimedSample>(
  samples: &[S],
  group_for: impl Fn(&S) -> crate::value::Group,
  opts: crate::emit::EmitOptions,
  print_conv: bool,
  measure_mode_render: impl Fn(u32, bool) -> crate::value::TagValue,
  alt_render: impl Fn(&S, f64, bool) -> crate::value::TagValue,
  mut emit_extra: impl FnMut(&S, &crate::value::Group, &mut std::vec::Vec<crate::emit::EmittedTag>),
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::serialize_key::GroupMode;
  use crate::value::{Group, TagValue};
  // Per-sample no-`ee` gate (Task 10b): a sample emits when `-ee` is on OR its
  // box-of-origin is one ExifTool processes WITHOUT `-ee` (the top-level
  // `gps0`/`gsen`/`3gf` magic boxes — `emits_without_ee`). Every other source
  // (GoPro / camm / moov-`gps `-box / Kenwood / freeGPS-scan) stays fully `-ee`
  // gated. When NOTHING qualifies (the common no-`ee` case with no top-level
  // magic box), bail before paying the dedup bookkeeping — the doc-0 hot path is
  // unchanged.
  let any = opts.extract_embedded || samples.iter().any(|s| s.emits_without_ee());
  if !any {
    return;
  }
  // Without `-ee` ExifTool opens NO `Doc<N>` sub-document (`++DOC_COUNT` is the
  // `FoundSomething`/ExtractEmbedded path) and TRUNCATES a top-level magic box
  // to its FIRST record, so the qualifying fix surfaces FLAT (`QuickTime:…`).
  // Force the `Doc<N>` axis off + the first-wins `(family1, name)` collapse on
  // at no-`ee` (regardless of the requested `-G3`), so only the first
  // emits-without-`ee` fix's columns survive. With `-ee` on, the requested
  // group mode drives the doc axis exactly as before.
  let g3 = opts.extract_embedded && matches!(opts.group_mode, GroupMode::G3);
  // `-G1` collapses every `Doc<N>` to one `(family1, name)` row with ExifTool's
  // TWO precedence rules (the same the `mebx` collapse uses, mirrored here so
  // both timed paths agree):
  //   * WITHIN one document (one camm SAMPLE — its packets share a `doc()`):
  //     LAST-wins, because each packet `HandleTag`s into the same `(DOC_NUM, tag)`
  //     VALUE slot and a later packet OVERWRITES the earlier (ExifTool.pm:9564-
  //     9604). A camm sample with two camm5 GPS packets thus keeps the SECOND
  //     fix's lat/lon/alt at `-ee -G1`.
  //   * ACROSS documents: FIRST-document-wins (the first-fix-wins the GPS sources
  //     show at `-ee -G1`: gps0/gsen keep the Doc1 fix, not Doc2 —
  //     QuickTimeStream.pl:967-973).
  // So accumulate one document's tags with within-doc last-wins (`doc_vals`), and
  // on the doc boundary FLUSH them honoring across-doc first-wins (`committed`).
  // At `-G3` neither buffer is used — the records emit verbatim and the
  // within-doc last-wins collapse happens in the flat `TagMap` sink (a later
  // same-key `Doc<N>:` row overwrites). The grouping key is `(family1, name)`,
  // NOT bare `name`: two `camm` `trak`s emitting the SAME key under DISTINCT
  // `Track<N>` groups are separate rows that BOTH survive (group-aware `%noDups`).
  let mut doc: u32 = 0;
  let mut scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
  // ((family1, name), EmittedTag) for the document currently being accumulated,
  // plus its doc number; `committed` records the `(family1, name)` pairs an
  // EARLIER document already flushed (across-doc first-wins).
  let mut doc_vals: std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)> =
    std::vec::Vec::new();
  let mut committed: std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)> = std::vec::Vec::new();
  let mut cur_doc: Option<u32> = None;
  // Flush one accumulated document's last-wins values into `out`, dropping a
  // `(family1, name)` already committed by an EARLIER document (across-doc
  // first-wins). Emits in first-seen order within the document.
  let flush_doc =
    |doc_vals: &mut std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)>,
     committed: &mut std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)>,
     out: &mut std::vec::Vec<EmittedTag>| {
      for (key, tag) in doc_vals.drain(..) {
        if committed.contains(&key) {
          continue;
        }
        committed.push(key);
        out.push(tag);
      }
    };
  // At no-`ee` only the emits-without-`ee` origins (gps0/gsen/3gf) contribute;
  // with `-ee` every emittable sample does. The gate is `has_emittable_data`
  // (NOT `has_coordinates`): ExifTool opens a `Doc<N>` + `HandleTag`s for every
  // record that yields any `%QuickTime::Stream` tag, which includes the
  // accelerometer/timecode-only `gsen`/`3gf` records (`Process_gsen`/
  // `Process_3gf`). For the GPS sources `has_emittable_data == has_coordinates`,
  // so their Doc numbering + output are unchanged.
  //
  // At no-`ee`, a magic-box (`gps0`/`gsen`/`3gf`) origin is additionally
  // PHYSICAL-RECORD-0-only: `Process_*` truncates `$dirLen = $recLen` BEFORE the
  // loop (QuickTimeStream.pl:2738), so ONLY physical record 0 is inspected. A
  // valid fix decoded from a LATER physical record (e.g. record 1, when record 0
  // was an out-of-range `next`-skip) must NOT surface — the truncation stops at
  // record 0. The `magic_box_record_index` carried from the decoder (stamped per
  // PHYSICAL record, including skipped ones) is the faithful test. With `-ee` on
  // every emittable record surfaces (no truncation).
  for s in samples.iter().filter(|s| {
    s.has_emittable_data()
      && (opts.extract_embedded || (s.emits_without_ee() && s.magic_box_record_index() == Some(0)))
  }) {
    doc += 1;
    let base = group_for(s);
    // `Doc<N>` number (QuickTimeStream.pl `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`):
    // EVERY production sample reaching this emitter now carries the GLOBAL
    // ordinal stamped at extraction off the SHARED `QuickTimeStreamMeta` doc
    // counter — the `gps0`/`gsen`/`3gf` magic boxes (per PHYSICAL record, incl.
    // a `next`-skipped one), the Kenwood `GPS ` box, the `moov`-`gps `-box +
    // brute-force freeGPS scan, AND camm (one doc per camm sample, in
    // `CammMeta`). `s.doc()` is therefore used VERBATIM, so the doc axis is
    // GLOBAL across the file's sources in walk order (no per-source restart) and
    // supersedes both the running `doc` and the legacy `magic_box_record_index
    // + 1`. The `unwrap_or_else` is now ONLY a defensive fallback for UNSTAMPED
    // unit-built samples (the in-crate emitter tests): a magic-box origin falls
    // back to `magic_box_record_index + 1` (the original per-box formula), any
    // other to the running per-call `doc`. Computed for BOTH modes: `-G3` puts it
    // in the group; `-G1` groups the within-doc-last-wins buffer by it (so two
    // packets that share one camm sample's doc collapse last-wins).
    let doc_n = s.doc().unwrap_or_else(|| {
      s.magic_box_record_index()
        .map_or(doc, |idx| idx.saturating_add(1))
    });
    let group = if g3 {
      Group::with_doc(base.family0(), base.family1(), doc_n)
    } else {
      base
    };
    scratch.clear();
    // SampleTime / SampleDuration (`ConvertDuration` at `-j`, raw seconds at
    // `-n`) — the sample-table timing ExifTool's `ProcessSamples` emits AHEAD of
    // the decoded GPS payload. ONLY the SAMPLE-TABLE TRACK sources carry it
    // (`sample_timing()` is `Some` only for camm; gps0/gsen/3gf/Kenwood/moov-`gps `
    // /freeGPS keep the trait default `None`, so NO SampleTime leaks onto the
    // stream-GPS / magic-box emission — their goldens have none). Emitted before
    // lat/lon, matching the camm goldens (SampleTime, SampleDuration, then the GPS
    // columns) and the `mebx` path. EMITTED ONLY at `-G3` (each `Doc<N>` keeps its
    // own sample's timing): the single `-G1` `Track<N>:SampleTime` is the
    // cross-kind MINIMUM-`doc()` sample's, precomputed by [`camm_min_doc_timing`]
    // at the camm call site and emitted there through the shared first-wins gate
    // (so it wins over this GPS sample's whenever a smaller-`doc()` sample of any
    // kind exists). Non-camm sources have `sample_timing() == None` regardless.
    if g3 && let Some((st, sd)) = s.sample_timing() {
      for (val, name) in [(st, "SampleTime"), (sd, "SampleDuration")] {
        if let Some(secs) = val {
          let value = if print_conv {
            TagValue::Str(crate::datetime::convert_duration(secs).into())
          } else {
            TagValue::F64(secs)
          };
          scratch.push(EmittedTag::new(group.clone(), name.into(), value, false));
        }
      }
    }
    if let (Some(lat), Some(lon)) = (s.latitude(), s.longitude()) {
      // `GPS::ToDMS($val, 1, "N"/"E")` at `-j` (with the hemisphere suffix);
      // the raw decimal-degree `F64` at `-n`.
      let lat_v = if print_conv {
        TagValue::Str(dms_signed(lat, 'N', 'S').into())
      } else {
        TagValue::F64(lat)
      };
      let lon_v = if print_conv {
        TagValue::Str(dms_signed(lon, 'E', 'W').into())
      } else {
        TagValue::F64(lon)
      };
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSLatitude".into(),
        lat_v,
        false,
      ));
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSLongitude".into(),
        lon_v,
        false,
      ));
    }
    if let Some(a) = s.altitude_m() {
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSAltitude".into(),
        alt_render(s, a, print_conv),
        false,
      ));
    }
    if let Some(t) = s.track_deg() {
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSTrack".into(),
        TagValue::F64(t),
        false,
      ));
    }
    if let Some(d) = s.dop() {
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSDOP".into(),
        TagValue::F64(d),
        false,
      ));
    }
    if let Some(m) = s.measure_mode() {
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSMeasureMode".into(),
        measure_mode_render(m, print_conv),
        false,
      ));
    }
    if let Some(dt) = s.date_time() {
      scratch.push(EmittedTag::new(
        group.clone(),
        "GPSDateTime".into(),
        TagValue::Str(dt.into()),
        false,
      ));
    }
    emit_extra(s, &group, &mut scratch);
    if g3 {
      out.append(&mut scratch);
    } else {
      // A new document — flush the previous one (across-doc first-wins) before
      // accumulating this sample's packets. Consecutive samples that share a
      // `doc_n` (two camm5 packets in one camm sample) accumulate into the SAME
      // document buffer, so a later packet's value overwrites the earlier
      // (within-doc last-wins).
      if cur_doc != Some(doc_n) {
        flush_doc(&mut doc_vals, &mut committed, out);
        cur_doc = Some(doc_n);
      }
      for tag in scratch.drain(..) {
        let key = (
          smol_str::SmolStr::new(tag.tag().group_ref().family1()),
          smol_str::SmolStr::new(tag.tag().name()),
        );
        if let Some(slot) = doc_vals.iter_mut().find(|(k, _)| *k == key) {
          slot.1 = tag;
        } else {
          doc_vals.push((key, tag));
        }
      }
    }
  }
  // Flush the final accumulated document (no-op at `-G3` / when empty).
  flush_doc(&mut doc_vals, &mut committed, out);
}

/// Emit, at `-ee -G1`, ONE `Track<N>:SampleTime` + `Track<N>:SampleDuration` per
/// camm track from that track's MINIMUM-`doc()` (first) camm SAMPLE, across ALL
/// camm record kinds (GPS, motion vectors camm2/3/4/7, camm1 exposure, AND
/// `ProcessCAMM` warnings).
///
/// ExifTool processes camm samples SEQUENTIALLY: `ProcessSamples` runs
/// `FoundSomething` (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) and emits this sample's
/// `SampleTime`/`SampleDuration` BEFORE dispatching `ProcessCAMM` for that sample
/// (QuickTimeStream.pl:1518-1523), which then `HandleTag`s the sample's packets.
/// JSON `%noDups` is FIRST-wins by walk order (exiftool:2952-2953), so the single
/// `-ee -G1` `Track<N>:SampleTime` is the FIRST (minimum-`doc()`) camm sample's —
/// regardless of which packet KIND that sample carried (a GPS, a motion vector, an
/// exposure pair, or just a `ProcessCAMM` warning).
///
/// exifast's per-kind emitters (`emit_camm_warnings`, then the camm GPS
/// `emit_timed_samples`, then the per-type `emit_camm_motion`s) drain records in
/// EMITTER-KIND order, NOT sample order, so a per-kind first-wins timing gate
/// would record whichever KIND emits first — wrong when a later-emitted kind owns
/// the earlier (smaller-`doc()`) sample. This precompute is correct-by-
/// construction: it scans every kind, keeps the smallest `doc()` per
/// `track_index`, and (routed through the shared `first_seen` gate by the caller)
/// emits ONLY that sample's timing at `-G1` — so the per-kind emitters' own
/// `-G1` timing is gated out and the min-`doc()` sample's wins. At `-G3` this is
/// NOT used: each `Doc<N>` carries its own sample's timing.
///
/// Returns `(track_index, sample_time, sample_duration)` per track in ascending
/// `track_index` order (deterministic emission). The `doc()` ordinal is GLOBAL
/// and monotonic in walk order (`CammMeta` stamps it once per camm sample off the
/// shared `QuickTimeStreamMeta` doc counter), so "smallest `doc()`" is exactly
/// "first sample" for the track.
#[cfg(feature = "alloc")]
fn camm_min_doc_timing(
  camm: &crate::metadata::CammMeta,
) -> std::vec::Vec<(u32, Option<f64>, Option<f64>)> {
  // (track_index, min_doc, sample_time, sample_duration) — linear-scanned, as the
  // camm emitters do (one entry per camm track; realistic files carry 1-2 tracks).
  let mut per_track: std::vec::Vec<(u32, u32, Option<f64>, Option<f64>)> = std::vec::Vec::new();
  let mut consider = |track: Option<u32>, doc: Option<u32>, st: Option<f64>, sd: Option<f64>| {
    // A sample with no stamped `doc()` cannot be ordered against the others, so it
    // cannot establish the per-track minimum — skip it (production camm samples are
    // always stamped; this guards only unit-built records). `track` defaults to
    // `Track1`, matching every camm emitter's `track_index().unwrap_or(1)`.
    let Some(doc) = doc else { return };
    let track = track.unwrap_or(1);
    if let Some(slot) = per_track.iter_mut().find(|(t, ..)| *t == track) {
      if doc < slot.1 {
        *slot = (track, doc, st, sd);
      }
    } else {
      per_track.push((track, doc, st, sd));
    }
  };
  for s in camm.gps_samples() {
    consider(
      s.track_index(),
      s.doc(),
      s.sample_time(),
      s.sample_duration(),
    );
  }
  for samples in [
    camm.angular_velocity(),
    camm.acceleration(),
    camm.position(),
    camm.magnetic_field(),
  ] {
    for v in samples {
      consider(
        v.track_index(),
        v.doc(),
        v.sample_time(),
        v.sample_duration(),
      );
    }
  }
  for e in camm.exposure() {
    consider(
      e.track_index(),
      e.doc(),
      e.sample_time(),
      e.sample_duration(),
    );
  }
  for w in camm.warnings() {
    consider(
      w.track_index(),
      w.doc(),
      w.sample_time(),
      w.sample_duration(),
    );
  }
  // TIMING-ONLY markers (recognized-empty samples) carry their own min-doc
  // candidate timing — ExifTool's `FoundSomething` emitted their
  // SampleTime/SampleDuration too (QuickTimeStream.pl:1523), so a track whose
  // FIRST (smallest-`doc()`) sample is a recognized-empty one owns the `-G1`
  // `Track<N>:SampleTime` (oracle `QuickTime_camm_emptypayload.mov`).
  for m in camm.timing_only() {
    consider(
      m.track_index(),
      m.doc(),
      m.sample_time(),
      m.sample_duration(),
    );
  }
  per_track.sort_by_key(|(t, ..)| *t);
  per_track
    .into_iter()
    .map(|(t, _doc, st, sd)| (t, st, sd))
    .collect()
}

/// Emit the `ProcessCAMM` per-packet warnings (`Unknown camm record type N` /
/// `Truncated camm record N`, QuickTimeStream.pl:3495-3496) as `Track<N>:Warning`
/// tags. Both are plain `$et->Warn(msg)` (NO `ignorable` arg) ⇒ NO `[minor]`
/// prefix, and `ProcessCAMM` runs only under `ExtractEmbedded`, so they surface
/// ONLY at `-ee`. WAS_WARNED dedups identical strings file-wide (a warning string
/// is recorded once, `ExifTool.pm` `sub Warn`), so an identical message repeated
/// across camm samples emits a single `Warning`. At `-ee -G3` the warning carries
/// its camm sample's stamped `Doc<N>`; at `-ee -G1` it collapses to one
/// `Track<N>:Warning` via the shared priority-0 first-wins `first_seen` gate (a
/// truncation warning thus takes precedence over the no-`ee` EEWarn — which does
/// not fire at `-ee` anyway). `first_seen` keys on `(family1, name)`, matching the
/// `TagMap` sink's priority-0 first-wins for the `Warning` pseudo-tag.
#[cfg(feature = "alloc")]
fn emit_camm_warnings<F: FnMut(&str, &str) -> bool>(
  warnings: &[crate::metadata::CammWarning],
  opts: crate::emit::EmitOptions,
  print_conv: bool,
  first_seen: &mut F,
  tags: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  // `ProcessCAMM` runs only under `ExtractEmbedded` → these surface only at `-ee`.
  if !opts.extract_embedded {
    return;
  }
  let g3 = matches!(opts.group_mode, crate::serialize_key::GroupMode::G3);
  // WAS_WARNED (`ExifTool.pm:5632-5639`): a warning string is recorded once
  // file-wide; a repeat only bumps an occurrence COUNT. The surviving (first-
  // emitted) `Warning` tag then gains a ` [x$n]` suffix when `n > 1`
  // (`ExifTool.pm:3196-3203`) — that end-of-extraction pass rewrites the
  // `Warning` value in the flat `$$self{VALUE}` hash keyed on the message string,
  // so it applies to a group-scoped `Track<N>:Warning` too (oracle: TWO
  // duplicate-message camm warning samples → ONE `Warning "… [x2]"`). Precompute
  // the per-message count over ALL camm warnings so the suffix reflects the final
  // total even though only the FIRST occurrence emits a tag.
  let count_of = |msg: &str| -> usize { warnings.iter().filter(|w| w.message() == msg).count() };
  // Build the WAS_WARNED-suffixed value: ` [x$n]` when the message recurs.
  let warning_value = |msg: &str| -> TagValue {
    let n = count_of(msg);
    let text = if n > 1 {
      smol_str::SmolStr::from(std::format!("{msg} [x{n}]"))
    } else {
      smol_str::SmolStr::from(msg)
    };
    TagValue::Str(text)
  };
  // Message strings whose surviving `Warning` tag has already been emitted (the
  // WAS_WARNED first-occurrence gate, keyed on the message string — a SECOND
  // sample with the same message emits NO further `Warning`, only its own timing).
  let mut warned_msgs: std::vec::Vec<smol_str::SmolStr> = std::vec::Vec::new();
  // The sample-table `SampleTime`/`SampleDuration` (`ConvertDuration` at `-j`, raw
  // seconds at `-n`) ExifTool's `ProcessSamples` emits AHEAD of a warning under the
  // raising sample's `Doc<N>` — `FoundSomething` runs PER SAMPLE before the
  // `ProcessCAMM` dispatch (QuickTimeStream.pl:1518-1523), so EVERY warning
  // sample's timing exists even when its later `Warn` is WAS_WARNED-deduped (oracle
  // `QuickTime_camm_dup_warn.mov`: `Doc2:Track1:SampleTime`/`SampleDuration` with NO
  // `Doc2:…Warning`). EMITTED ONLY at `-G3` (each `Doc<N>` keeps its own warning
  // sample's timing) — and ALWAYS, BEFORE the message-dedup. At `-G1` the single
  // `Track<N>:SampleTime` is the cross-kind MINIMUM-`doc()` sample's, precomputed by
  // [`camm_min_doc_timing`] at the camm call site (this emitter runs AFTER that
  // block, so the warning sample's timing — when it is NOT the minimum — is
  // correctly gated out, and when it IS the minimum the precompute already emitted
  // it). This emitter therefore never touches `-G1` timing; it only emits the
  // `Track<N>:Warning` payload (priority-0 first-wins via `first_seen`).
  fn push_timing_g3(
    w: &crate::metadata::CammWarning,
    group: &Group,
    print_conv: bool,
    tags: &mut std::vec::Vec<EmittedTag>,
  ) {
    for (val, name) in [
      (w.sample_time(), "SampleTime"),
      (w.sample_duration(), "SampleDuration"),
    ] {
      if let Some(secs) = val {
        let value = if print_conv {
          TagValue::Str(crate::datetime::convert_duration(secs).into())
        } else {
          TagValue::F64(secs)
        };
        tags.push(EmittedTag::new(group.clone(), name.into(), value, false));
      }
    }
  }
  for w in warnings {
    let family1 = std::format!("Track{}", w.track_index().unwrap_or(1));
    if g3 {
      // `-G3`: the warning carries its camm sample's `Doc<N>`; the `TagMap` sink
      // keeps distinct `(doc, family1, name)` rows.
      let group = Group::with_doc("QuickTime", family1.as_str(), w.doc().unwrap_or(0));
      // EVERY warning sample emits its OWN `Doc<N>` timing — BEFORE the WAS_WARNED
      // message-dedup, so a duplicate-message second sample keeps its
      // `Doc<N>:SampleTime`/`SampleDuration` even when its `Warning` text is deduped.
      push_timing_g3(w, &group, print_conv, tags);
      let msg = smol_str::SmolStr::from(w.message());
      if !warned_msgs.contains(&msg) {
        warned_msgs.push(msg);
        tags.push(EmittedTag::new(
          group,
          "Warning".into(),
          warning_value(w.message()),
          false,
        ));
      }
    } else if first_seen(family1.as_str(), "Warning") {
      // `-G1`: one `Track<N>:Warning` (priority-0 first-wins via the shared gate).
      // Timing is owned by the cross-kind min-`doc()` precompute (above).
      tags.push(EmittedTag::new(
        Group::new("QuickTime", family1.as_str()),
        "Warning".into(),
        warning_value(w.message()),
        false,
      ));
    }
  }
}

/// Emit the Canon CTMD `ProcessCTMD` / `TimeStamp`-RawConv warnings as
/// `Track<N>:Warning` tags — the CTMD counterpart of [`emit_camm_warnings`].
///
/// `ProcessCTMD` raises `Short CTMD record` / `Truncated CTMD record` (plain
/// `$et->Warn`, Canon.pm:10781-10782) and the MINOR `Error parsing Canon CTMD
/// data` (`$et->Warn(..., 1)`, Canon.pm:10802 ⇒ rendered `[minor] …`); the
/// type-1 `TimeStamp` `RawConv` raises `'x' outside of string in unpack` /
/// `Missing argument in sprintf` for a short payload (Canon.pm:9801-9805). All
/// `FoundTag` a `Warning` under the raising SAMPLE's open `Doc<N>`
/// (`ProcessSamples` opens one per sample), scoped to the trak's `Track<N>`.
/// `ProcessCTMD` runs only under `ExtractEmbedded`, so they surface ONLY at
/// `-ee`.
///
/// WAS_WARNED (`ExifTool.pm:5632-5639`) records each FINAL warning string once
/// file-wide and bumps an occurrence COUNT; the surviving (first-emitted)
/// `Warning` then gains a ` [x$n]` suffix when `n > 1` (`ExifTool.pm:3196-3203`)
/// — applied to the `[minor] `-prefixed string (oracle: TWO residue samples →
/// `[minor] Error parsing Canon CTMD data [x2]`). At `-ee -G3` the warning
/// carries its CTMD sample's stamped `Doc<N>`; at `-ee -G1` it collapses to one
/// `Track<N>:Warning` via the shared priority-0 first-wins `first_seen` gate.
/// The per-sample SampleTime/SampleDuration are emitted by the CTMD payload
/// block, so this emitter pushes ONLY the `Warning` payload.
#[cfg(feature = "alloc")]
fn emit_ctmd_warnings<F: FnMut(&str, &str) -> bool>(
  warnings: &[crate::metadata::CanonCtmdWarning],
  opts: crate::emit::EmitOptions,
  first_seen: &mut F,
  tags: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  // `ProcessCTMD` runs only under `ExtractEmbedded` → these surface only at `-ee`.
  if !opts.extract_embedded {
    return;
  }
  let g3 = matches!(opts.group_mode, crate::serialize_key::GroupMode::G3);
  // The FINAL rendered message (the `[minor] ` prefix applied for a minor
  // warning) — the string WAS_WARNED keys + counts on, and the value bundled
  // emits (before the ` [x$n]` suffix).
  let rendered = |w: &crate::metadata::CanonCtmdWarning| -> std::string::String {
    if w.minor() {
      std::format!("[minor] {}", w.message())
    } else {
      w.message().to_string()
    }
  };
  // WAS_WARNED occurrence count over ALL CTMD warnings, keyed on the FINAL
  // rendered string (so the ` [x$n]` suffix reflects the file-wide total even
  // though only the first occurrence emits a tag).
  let count_of = |msg: &str| -> usize { warnings.iter().filter(|w| rendered(w) == msg).count() };
  let warning_value = |msg: &str| -> TagValue {
    let n = count_of(msg);
    let text = if n > 1 {
      smol_str::SmolStr::from(std::format!("{msg} [x{n}]"))
    } else {
      smol_str::SmolStr::from(msg)
    };
    TagValue::Str(text)
  };
  // FINAL-message strings whose surviving `Warning` has already been emitted at
  // `-G3` (the WAS_WARNED first-occurrence gate — a later same-message sample
  // emits no further `Warning`, only the CTMD payload block's own timing).
  let mut warned_msgs: std::vec::Vec<smol_str::SmolStr> = std::vec::Vec::new();
  for w in warnings {
    let family1 = std::format!("Track{}", w.track_index().unwrap_or(1));
    let msg = rendered(w);
    if g3 {
      // `-G3`: the warning carries its CTMD sample's `Doc<N>`; the `TagMap` sink
      // keeps distinct `(doc, family1, name)` rows. WAS_WARNED still suppresses a
      // duplicate FINAL message after the first occurrence.
      let key = smol_str::SmolStr::from(msg.as_str());
      if !warned_msgs.contains(&key) {
        warned_msgs.push(key);
        let group = Group::with_doc("QuickTime", family1.as_str(), w.doc().unwrap_or(0));
        tags.push(EmittedTag::new(
          group,
          "Warning".into(),
          warning_value(&msg),
          false,
        ));
      }
    } else if first_seen(family1.as_str(), "Warning") {
      // `-G1`: one `Track<N>:Warning` (priority-0 first-wins via the shared gate).
      tags.push(EmittedTag::new(
        Group::new("QuickTime", family1.as_str()),
        "Warning".into(),
        warning_value(&msg),
        false,
      ));
    }
  }
}

/// Format one Insta360 `0x700` GPS fix into its `Insta360:*` tags
/// (QuickTimeStream.pl:3397-3425), appending to `out` under `base`. SHARED by
/// both the `-G3` (per-Doc) and the streaming `-G1` emission paths so the
/// per-sample PrintConv lives in ONE place. The `Doc<N>` re-stamp (`-G3`) and
/// the first-wins collapse (`-G1`) are applied by the caller.
#[cfg(feature = "alloc")]
fn push_insta360_gps_tags(
  s: &crate::metadata::Insta360GpsSample,
  base: &crate::value::Group,
  print_conv: bool,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::TagValue;
  let push = |out: &mut std::vec::Vec<EmittedTag>, name: &str, v: TagValue| {
    out.push(EmittedTag::new(base.clone(), name.into(), v, false));
  };
  if let Some(dt) = s.date_time() {
    push(out, "GPSDateTime", TagValue::Str(dt.into()));
  }
  if let Some(lat) = s.latitude() {
    let v = if print_conv {
      TagValue::Str(dms_signed(lat, 'N', 'S').into())
    } else {
      TagValue::F64(lat)
    };
    push(out, "GPSLatitude", v);
  }
  if let Some(lon) = s.longitude() {
    let v = if print_conv {
      TagValue::Str(dms_signed(lon, 'E', 'W').into())
    } else {
      TagValue::F64(lon)
    };
    push(out, "GPSLongitude", v);
  }
  if let Some(sp) = s.speed_kph() {
    // `%QuickTime::Stream` GPSSpeed PrintConv `sprintf("%.4f", $val) + 0`
    // (QuickTimeStream.pl:121): round to 4 decimals, drop trailing zeros (the
    // `+ 0` numify re-stringifies the rounded NV with `%.15g`). `-n` emits the
    // raw km/h F64. Same `%.4f`+0 idiom as the Stream GPSAltitude (extracted
    // into `round_to_decimals` + `format_g`).
    let v = if print_conv {
      TagValue::Str(crate::value::format_g(round_to_decimals(sp, 4), 15).into())
    } else {
      TagValue::F64(sp)
    };
    push(out, "GPSSpeed", v);
  }
  if let Some(tr) = s.track_deg() {
    // GPSTrack PrintConv `sprintf("%.4f", $val) + 0` (QuickTimeStream.pl:123) —
    // the same `%.4f`+0 numeric strip as GPSSpeed.
    let v = if print_conv {
      TagValue::Str(crate::value::format_g(round_to_decimals(tr, 4), 15).into())
    } else {
      TagValue::F64(tr)
    };
    push(out, "GPSTrack", v);
  }
  if let Some(alt) = s.altitude_m() {
    push(
      out,
      "GPSAltitude",
      gps_altitude_stream_value(alt, print_conv),
    );
  }
}

/// Format one Insta360 `0x400` exposure row into `TimeCode`/`ExposureTime`
/// (QuickTimeStream.pl:3386-3391). SHARED by `-G3` and the streaming `-G1`.
#[cfg(feature = "alloc")]
fn push_insta360_exposure_tags(
  s: &crate::metadata::Insta360ExposureSample,
  base: &crate::value::Group,
  print_conv: bool,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::TagValue;
  if let Some(ms) = s.timestamp_ms() {
    // `TimeCode` PrintConv `sprintf('%.3f', $val/1000)` — both modes (the `.3f`
    // string is emitted at `-n` too; no separate ValueConv form in the oracle).
    let v = TagValue::Str(std::format!("{:.3}", ms as f64 / 1000.0).into());
    out.push(EmittedTag::new(base.clone(), "TimeCode".into(), v, false));
  }
  if let Some(et) = s.exposure_time_s() {
    let v = if print_conv {
      TagValue::Str(crate::exif::tables::print_exposure_time(et).into())
    } else {
      TagValue::F64(et)
    };
    out.push(EmittedTag::new(
      base.clone(),
      "ExposureTime".into(),
      v,
      false,
    ));
  }
}

/// Format one Insta360 `0x600` video-timestamp row into `VideoTimeStamp`
/// (QuickTimeStream.pl:3392-3396). SHARED by `-G3` and the streaming `-G1`.
#[cfg(feature = "alloc")]
fn push_insta360_videotime_tags(
  s: &crate::metadata::Insta360VideoTimeSample,
  base: &crate::value::Group,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::TagValue;
  if let Some(ms) = s.timecode_ms() {
    // Same `%.3f` (ms → s) rendering as `TimeCode`, both modes.
    let v = TagValue::Str(std::format!("{:.3}", ms as f64 / 1000.0).into());
    out.push(EmittedTag::new(
      base.clone(),
      "VideoTimeStamp".into(),
      v,
      false,
    ));
  }
}

/// Format one Insta360 `0x300` accelerometer row into
/// `TimeCode`/`Accelerometer`/`AngularVelocity` (QuickTimeStream.pl:3372-3385).
/// The vec3 tags carry NO PrintConv — three f64 space-joined via Perl's `%.15g`
/// (`"@a"`), mode-invariant. SHARED by `-G3` and the streaming `-G1`.
#[cfg(feature = "alloc")]
fn push_insta360_accel_tags(
  s: &crate::metadata::Insta360AccelSample,
  base: &crate::value::Group,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::TagValue;
  let vec3 = |v: [f64; 3]| -> TagValue {
    let mut s = crate::value::format_g(v[0], 15);
    s.push(' ');
    s.push_str(&crate::value::format_g(v[1], 15));
    s.push(' ');
    s.push_str(&crate::value::format_g(v[2], 15));
    TagValue::Str(s.into())
  };
  if let Some(ms) = s.timecode_ms() {
    let v = TagValue::Str(std::format!("{:.3}", ms as f64 / 1000.0).into());
    out.push(EmittedTag::new(base.clone(), "TimeCode".into(), v, false));
  }
  if let Some(a) = s.accelerometer() {
    out.push(EmittedTag::new(
      base.clone(),
      "Accelerometer".into(),
      vec3(a),
      false,
    ));
  }
  if let Some(w) = s.angular_velocity() {
    out.push(EmittedTag::new(
      base.clone(),
      "AngularVelocity".into(),
      vec3(w),
      false,
    ));
  }
}

/// Format the Insta360 `0x101` identity into its `SerialNumber`/`Model`/
/// `Firmware`/`Parameters` tags (QuickTimeStream.pl:3427-3436) under `group`.
/// SHARED by `-G3` (group carries the sticky `Doc<N>`) and the streaming `-G1`
/// (group is the bare `Insta360`; the names are file-unique so they survive the
/// collapse).
#[cfg(feature = "alloc")]
fn push_insta360_identity_tags(
  id: &crate::metadata::Insta360Identity,
  group: &crate::value::Group,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::TagValue;
  for (val, name) in [
    (id.serial_number(), "SerialNumber"),
    (id.model(), "Model"),
    (id.firmware(), "Firmware"),
    (id.parameters(), "Parameters"),
  ] {
    if let Some(v) = val {
      out.push(EmittedTag::new(
        group.clone(),
        name.into(),
        TagValue::Str(v.into()),
        false,
      ));
    }
  }
}

/// The streaming `-ee -G1` Insta360 timed-record + identity emission — bounded
/// to O(distinct tag names) memory (Finding 2). Drives
/// [`insta360_fmt::stream_records`] (one decoded row at a time, NO per-row Vec)
/// and accumulates FIRST-WINS-by-name directly into `tags`: because the walk
/// visits records in doc-ascending order and every row's tag names are unique
/// within its own doc, the `-G1` `%noDups` collapse reduces to "the first
/// occurrence of each name in walk order wins" — identical output to the
/// doc-sorted two-rule collapse the `-G3` path's full decode would feed, but
/// without ever storing all rows. Decode-time warnings route through the shared
/// priority-0 first-wins `ExifTool:Warning` gate (in practice suppressed by the
/// earlier positional trailer warning). The identity record is walked LAST, so
/// its (file-unique) tags land after the timed rows — matching the oracle.
#[cfg(feature = "alloc")]
fn emit_insta360_g1_streaming<F: FnMut(&str, &str) -> bool>(
  raw: &[u8],
  trail_end: usize,
  print_conv: bool,
  first_seen: &mut F,
  tags: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::formats::insta360::Insta360StreamItem;
  use crate::value::{Group, TagValue};

  let base = Group::new("Trailer", "Insta360");
  // The committed-names set IS the entire `-G1` memory of the timed rows:
  // O(distinct names), never O(rows).
  let mut committed: std::vec::Vec<smol_str::SmolStr> = std::vec::Vec::new();
  // A small reused scratch buffer for the (≤3) tags one row formats into.
  let mut scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();

  // First-wins-accumulate the formatted tags of one row/identity into `tags`.
  let commit = |scratch: &mut std::vec::Vec<EmittedTag>,
                committed: &mut std::vec::Vec<smol_str::SmolStr>,
                tags: &mut std::vec::Vec<EmittedTag>| {
    for tag in scratch.drain(..) {
      let name = smol_str::SmolStr::new(tag.tag().name());
      if committed.contains(&name) {
        continue; // an earlier (lower-doc) row already emitted this name.
      }
      committed.push(name);
      tags.push(tag);
    }
  };

  insta360_fmt::stream_records(raw, trail_end, &mut |item| match item {
    Insta360StreamItem::Warning(w) => {
      // A `Trailer`/`Insta360` `Warning` (raised under `SET_GROUP1='Insta360'`),
      // priority-0 first-wins. At `-G1` the doc axis collapses, so all such
      // warnings reduce to ONE `Insta360:Warning` — emit only the FIRST (the
      // `first_seen` gate keeps this bounded: a crafted run of thousands of
      // non-multiple records still pushes a single tag). NOT `ExifTool:Warning`.
      if first_seen("Insta360", "Warning") {
        tags.push(EmittedTag::new(
          base.clone(),
          "Warning".into(),
          TagValue::Str(w),
          false,
        ));
      }
    }
    Insta360StreamItem::Gps(s) => {
      push_insta360_gps_tags(&s, &base, print_conv, &mut scratch);
      commit(&mut scratch, &mut committed, tags);
    }
    Insta360StreamItem::Exposure(s) => {
      push_insta360_exposure_tags(&s, &base, print_conv, &mut scratch);
      commit(&mut scratch, &mut committed, tags);
    }
    Insta360StreamItem::VideoTime(s) => {
      push_insta360_videotime_tags(&s, &base, &mut scratch);
      commit(&mut scratch, &mut committed, tags);
    }
    Insta360StreamItem::Accel(s) => {
      push_insta360_accel_tags(&s, &base, &mut scratch);
      commit(&mut scratch, &mut committed, tags);
    }
    Insta360StreamItem::Identity(id) => {
      push_insta360_identity_tags(&id, &base, &mut scratch);
      commit(&mut scratch, &mut committed, tags);
    }
  });
}

/// Emit the Insta360 INSV/INSP trailer's tags faithfully — the
/// `ProcessInsta360` output (QuickTimeStream.pl:3252-3478) under the
/// family-1 `Insta360` group (family-0 `Trailer`, the `SET_GROUP0` of the
/// trailer walker; QuickTime.pm:10669-10673).
///
/// Three independent pieces, all driven off the typed [`Insta360Meta`]:
///
///  1. **The always-on trailer warning.** `ProcessMOV` raises
///     `Warn(sprintf('%s trailer at offset 0x%x (%d bytes)', …), 1)` whenever
///     its box walk reaches a trailer (QuickTime.pm:10600) — present in EVERY
///     mode (incl. no-`-ee`; the oracle's `.json` carries it). The `1`st
///     `Warn` arg ⇒ ignorable ⇒ the rendered value carries the `[minor] `
///     prefix. Emitted UNCONDITIONALLY when a trailer is detected, as a
///     document-level `ExifTool:Warning` tag through the shared priority-0
///     first-wins [`first_seen`] gate (a real earlier `ProcessMOV` warning
///     still wins). On a bad-size trailer (`trailerLen > file size`) the offset
///     is the WRAPPED (negative→unsigned) value — bundled emits this positional
///     warning then suppresses "Bad trailer size" via the same first-wins rule.
///  2. **The timed records** (`-ee`-only — `ProcessInsta360` runs under
///     `ExtractEmbedded`): GPS (`0x700`), exposure (`0x400`), videotimestamp
///     (`0x600`), accelerometer (`0x300`). Each surfaced row carries its
///     global `Doc<N>` stamp. At `-ee -G3` every row emits under
///     `Doc<N>:Insta360:*`; at `-ee -G1` the doc axis collapses with the SAME
///     two-rule `%noDups` precedence as [`emit_camm_motion`] — within one
///     `Doc<N>` LAST-wins, ACROSS documents FIRST-wins (lowest `Doc<N>`) by
///     `(family1, name)` — applied over the doc-ORDERED UNION of ALL record
///     types (so e.g. the `TimeCode` shared by exposure Doc3/4 and accel
///     Doc7/8 collapses to the single lowest-doc Doc3 value).
///  3. **The identity** (`0x101`): SerialNumber / Model / Firmware /
///     Parameters. NOT incremented into `DOC_NUM` — it inherits the sticky
///     value the last surfaced timed row left (QuickTimeStream.pl:3427-3436).
///     At `-G3` it rides `Doc<N>:Insta360:*` (the sticky doc, or Main when 0);
///     at `-G1` its names are file-unique so they always survive. Emitted at
///     BOTH `-ee` and no-`-ee` (the identity is not gated on `ExtractEmbedded`
///     in the typed layer — but in practice `ProcessInsta360` itself runs
///     under `-ee`, so a no-`-ee` parse decodes no trailer records at all;
///     this matches the oracle's no-`-ee` `.json`, which shows ONLY the
///     warning).
#[cfg(feature = "alloc")]
fn emit_insta360<F: FnMut(&str, &str) -> bool>(
  meta: &crate::metadata::Insta360Meta<'_>,
  opts: crate::emit::EmitOptions,
  print_conv: bool,
  first_seen: &mut F,
  tags: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::serialize_key::GroupMode;
  use crate::value::{Group, TagValue};

  // Push one document-level `ExifTool:Warning` through the shared priority-0
  // first-wins gate (a real earlier `ProcessMOV` warning still wins).
  let push_warning =
    |first_seen: &mut F, tags: &mut std::vec::Vec<EmittedTag>, msg: smol_str::SmolStr| {
      if first_seen("ExifTool", "Warning") {
        tags.push(EmittedTag::new(
          Group::new("ExifTool", "ExifTool"),
          "Warning".into(),
          TagValue::Str(msg),
          false,
        ));
      }
    };

  // ── (1) the always-on `[minor]` trailer warning ──────────────────────────
  // Emitted whenever a trailer is detected — NOT `-ee`-gated, NOT
  // `print_conv`-gated (the oracle shows it in every mode). Driven off the
  // linked-list HEAD trailer (QuickTime.pm:10600 warns `$$trailer[0/1/2]`):
  // usually the Insta360 trailer itself, but its NAME reflects the head kind so
  // a LigoGPS/MIE head reports that kind faithfully.
  if let Some((name, start, len)) = meta.head_trailer() {
    push_warning(
      first_seen,
      tags,
      std::format!("[minor] {name} trailer at offset 0x{start:x} ({len} bytes)").into(),
    );
  }

  // The timed records are `ProcessInsta360`-under-`-ee` only. The identity
  // record only ever decodes under `-ee` too (same routine), so the whole
  // record body below is `-ee`-gated; the no-`-ee` path emitted just the
  // warning(s) above.
  if !opts.extract_embedded {
    return;
  }
  // DEFERRED heavy decode: only NOW (under `-ee`) do we materialize the timed
  // rows from the borrowed input bytes — the opts-agnostic parse stored only a
  // bounded domain summary (lazy-decode DoS guard). No trailer ⇒ nothing.
  let Some(raw) = meta.raw() else {
    return;
  };
  // The Insta360 trailer's end offset (== EOF for a standalone trailer, or its
  // `start + len` when found behind a later LigoGPS/MIE trailer) — the backward
  // anchor the record walk reads from.
  let trail_end = meta.trail_end();
  let g3 = matches!(opts.group_mode, GroupMode::G3);

  if !g3 {
    // ── (2+3) the `-ee -G1` path — STREAMED (Finding 2) ────────────────────
    // O(distinct names) memory: never materialize the full per-row Vecs nor a
    // sorted union. Walk-order first-wins reproduces the `-G1` two-rule
    // collapse byte-for-byte (each row is its own doc with file-unique names).
    emit_insta360_g1_streaming(raw, trail_end, print_conv, first_seen, tags);
    return;
  }

  // ── (2+3) the `-ee -G3` path — full decode + doc-sorted per-Doc emission ──
  // Inherently O(rows) = O(output) (one `Doc<N>` per row, matching ExifTool).
  let full = insta360_fmt::decode_all_records(raw, trail_end);

  // Build the doc-ORDERED UNION of every timed record's tags as
  // `(doc, EmittedTag)` pairs (the per-sample formatting is the SHARED
  // `push_insta360_*_tags` helpers, also used by the streaming `-G1` path).
  // The per-Vec order is already ascending-doc, but we sort by `doc` (STABLE)
  // so the per-Doc emission is correct even when record types interleave in the
  // file (so `full.gps()`/`full.exposure()` are individually doc-ascending but
  // their concatenation is not).
  let base = Group::new("Trailer", "Insta360");
  let mut rows: std::vec::Vec<(u32, EmittedTag)> = std::vec::Vec::new();
  let mut scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
  let stamp = |rows: &mut std::vec::Vec<(u32, EmittedTag)>,
               scratch: &mut std::vec::Vec<EmittedTag>,
               doc: u32| {
    for tag in scratch.drain(..) {
      rows.push((doc, tag));
    }
  };
  for s in full.gps() {
    push_insta360_gps_tags(s, &base, print_conv, &mut scratch);
    stamp(&mut rows, &mut scratch, s.doc().unwrap_or(0));
  }
  for s in full.exposure() {
    push_insta360_exposure_tags(s, &base, print_conv, &mut scratch);
    stamp(&mut rows, &mut scratch, s.doc().unwrap_or(0));
  }
  for s in full.videotime() {
    push_insta360_videotime_tags(s, &base, &mut scratch);
    stamp(&mut rows, &mut scratch, s.doc().unwrap_or(0));
  }
  for s in full.accel() {
    push_insta360_accel_tags(s, &base, &mut scratch);
    stamp(&mut rows, &mut scratch, s.doc().unwrap_or(0));
  }
  // Decode-time warnings (`Insta360 ... data is huge` :3349, `Unexpected
  // Insta360 record 0x%x length` :3357, `Unrecognized INSV GPS format` :3408) —
  // raised inside `ProcessInsta360` while `SET_GROUP1='Insta360'` is active, so
  // they are `Trailer`/`Insta360` `Warning` tags (NOT `ExifTool:Warning`),
  // riding the STICKY `Doc<N>` they were raised under. Push AFTER the row tags
  // so the STABLE doc-sort keeps each warning after its own doc's payload rows
  // (the bundled FoundTag order); the downstream `TagMap` first-wins on
  // `(doc, Insta360, Warning)` then keeps only the first per doc (priority-0).
  for (doc, w) in full.warnings() {
    rows.push((
      *doc,
      EmittedTag::new(
        base.clone(),
        "Warning".into(),
        TagValue::Str(w.clone()),
        false,
      ),
    ));
  }

  rows.sort_by_key(|(doc, _)| *doc);

  // Each row under its own `Doc<N>:Insta360:*` (Main when doc 0). Re-stamp the
  // group's doc; MOVE the name + value out (no clone).
  for (doc, tag) in rows {
    let (_, name, value) = tag.into_tag().into_parts();
    let group = Group::with_doc("Trailer", "Insta360", doc);
    tags.push(EmittedTag::new(group, name, value, false));
  }

  // ── (3) the identity (`0x101`) ───────────────────────────────────────────
  // SerialNumber / Model / Firmware / Parameters ride the sticky `Doc<N>`
  // (Main when 0/None) at `-G3`.
  if let Some(id) = full.identity() {
    let group = Group::with_doc("Trailer", "Insta360", id.doc().unwrap_or(0));
    push_insta360_identity_tags(id, &group, tags);
  }
}

/// Emit the per-sample `SampleTime`/`SampleDuration` for camm TIMING-ONLY markers
/// — recognized first-packet samples (their first packet matched a
/// `camm0..camm7` Condition) that `ProcessCAMM` decoded to NO stored record (no
/// GPS / motion / exposure fix AND no `Unknown`/`Truncated` warning, e.g. a
/// 4-byte-only header sample). ExifTool's `FoundSomething` still emitted their
/// timing under the sample's `Doc<N>` (QuickTimeStream.pl:1523; oracle
/// `QuickTime_camm_emptypayload.mov` → `Doc1:Track1:SampleTime`/`SampleDuration`,
/// no payload). `-ee`-gated like every other camm emitter (camm is a handler
/// `trak`). EMITTED ONLY at `-G3`: each marker writes its own
/// `Doc<N>:Track<N>:SampleTime`/`SampleDuration`. At `-G1` the single
/// `Track<N>:SampleTime` is the cross-kind MINIMUM-`doc()` sample's, owned by the
/// [`camm_min_doc_timing`] precompute at the call site (these markers are among
/// its candidates), so this emitter pushes nothing at `-G1`.
#[cfg(feature = "alloc")]
fn emit_camm_timing_only(
  markers: &[crate::metadata::CammTimingOnly],
  opts: crate::emit::EmitOptions,
  print_conv: bool,
  tags: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::serialize_key::GroupMode;
  use crate::value::{Group, TagValue};
  // `-ee`-only (a camm `trak` source); and the timing emits ONLY at `-G3` (at
  // `-G1` the min-doc precompute owns it).
  if !opts.extract_embedded || !matches!(opts.group_mode, GroupMode::G3) || markers.is_empty() {
    return;
  }
  for m in markers {
    let track = std::format!("Track{}", m.track_index().unwrap_or(1));
    let group = Group::with_doc("QuickTime", track.as_str(), m.doc().unwrap_or(0));
    for (val, name) in [
      (m.sample_time(), "SampleTime"),
      (m.sample_duration(), "SampleDuration"),
    ] {
      if let Some(secs) = val {
        let value = if print_conv {
          TagValue::Str(crate::datetime::convert_duration(secs).into())
        } else {
          TagValue::F64(secs)
        };
        tags.push(EmittedTag::new(group.clone(), name.into(), value, false));
      }
    }
  }
}

/// Emit one camm MOTION sample-vector (camm1-4/7) under the shared `-ee` `Doc<N>`
/// / `Track<N>` axis — the motion counterpart of [`emit_timed_samples`] for the
/// records `ProcessCAMM` `HandleTag`s that are NOT GPS fixes (camm1
/// PixelExposureTime/RollingShutterSkewTime, camm2 AngularVelocity, camm3
/// Acceleration, camm4 Position, camm7 MagneticField — QuickTimeStream.pl:428-
/// 569). Fully `-ee`-gated (camm is a handler `trak`; no no-`ee` magic-box path),
/// so at no-`ee` NOTHING here surfaces (only the `Track<N>:Warning` raised
/// elsewhere). At `-ee -G3` each sample is its own `Doc<N>` (its stamped `doc()`)
/// under its stamped `Track<N>`, carrying its own `SampleTime`/`SampleDuration`;
/// at `-ee -G1` the motion PAYLOAD takes the SAME two-rule `%noDups` collapse
/// [`emit_timed_samples`] uses — within one document (one camm sample, its packets
/// share a `doc()`) LAST-wins, across documents FIRST-wins — while the single
/// `Track<N>:SampleTime`/`SampleDuration` is owned by the cross-kind min-`doc()`
/// [`camm_min_doc_timing`] precompute (so this emitter pushes timing only at
/// `-G3`). `push` renders the format-specific tag(s) for one sample into the
/// scratch buffer (the vec3 space-join, or the camm1 exposure PrintConv).
#[cfg(feature = "alloc")]
fn emit_camm_motion<T>(
  samples: &[T],
  doc_of: impl Fn(&T) -> Option<u32>,
  track_of: impl Fn(&T) -> Option<u32>,
  timing_of: impl Fn(&T) -> (Option<f64>, Option<f64>),
  print_conv: bool,
  push: impl Fn(&T, &crate::value::Group, &mut std::vec::Vec<crate::emit::EmittedTag>),
  opts: crate::emit::EmitOptions,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::serialize_key::GroupMode;
  use crate::value::{Group, TagValue};
  // Motion is `-ee`-only (a camm `trak` source). The no-`ee` path emits no
  // per-sample record; bail before any bookkeeping.
  if !opts.extract_embedded || samples.is_empty() {
    return;
  }
  let g3 = matches!(opts.group_mode, GroupMode::G3);
  // Two-rule `-G1` collapse state (unused at `-G3`), mirroring `emit_timed_samples`.
  let mut doc_vals: std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)> =
    std::vec::Vec::new();
  let mut committed: std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)> = std::vec::Vec::new();
  let mut cur_doc: Option<u32> = None;
  let mut running: u32 = 0;
  let mut scratch: std::vec::Vec<EmittedTag> = std::vec::Vec::new();
  let flush_doc =
    |doc_vals: &mut std::vec::Vec<((smol_str::SmolStr, smol_str::SmolStr), EmittedTag)>,
     committed: &mut std::vec::Vec<(smol_str::SmolStr, smol_str::SmolStr)>,
     out: &mut std::vec::Vec<EmittedTag>| {
      for (key, tag) in doc_vals.drain(..) {
        if committed.contains(&key) {
          continue;
        }
        committed.push(key);
        out.push(tag);
      }
    };
  for s in samples {
    running += 1;
    // The stamped GLOBAL `Doc<N>` (verbatim, as `emit_timed_samples` does); the
    // `running` per-call ordinal is the fallback for an UNSTAMPED unit-built
    // sample only. `Track<N>` defaults to `Track1`.
    let doc_n = doc_of(s).unwrap_or(running);
    let track = std::format!("Track{}", track_of(s).unwrap_or(1));
    let group = if g3 {
      Group::with_doc("QuickTime", track.as_str(), doc_n)
    } else {
      Group::new("QuickTime", track.as_str())
    };
    scratch.clear();
    // SampleTime / SampleDuration ahead of this sample's motion payload — the
    // sample-table timing ExifTool emits per camm SAMPLE (`ConvertDuration` at
    // `-j`, raw seconds at `-n`), under the same `Doc<N>`/`Track<N>`. EMITTED ONLY
    // at `-G3` (each `Doc<N>` carries its own sample's timing). At `-G1` the single
    // `Track<N>:SampleTime` is the cross-kind MINIMUM-`doc()` sample's, precomputed
    // by [`camm_min_doc_timing`] at the camm call site (which runs BEFORE the five
    // per-type `emit_camm_motion` calls and the camm GPS path), so a motion
    // sample's timing is correctly used iff it is that track's first sample — and
    // emitted by the precompute, not here. The motion PAYLOAD still rides the
    // within-call two-rule `%noDups` collapse below (its tag names are per-type-
    // unique, so no cross-call gate is needed for it).
    if g3 {
      let (st, sd) = timing_of(s);
      for (val, name) in [(st, "SampleTime"), (sd, "SampleDuration")] {
        if let Some(secs) = val {
          let value = if print_conv {
            TagValue::Str(crate::datetime::convert_duration(secs).into())
          } else {
            TagValue::F64(secs)
          };
          scratch.push(EmittedTag::new(group.clone(), name.into(), value, false));
        }
      }
    }
    push(s, &group, &mut scratch);
    if g3 {
      out.append(&mut scratch);
    } else {
      if cur_doc != Some(doc_n) {
        flush_doc(&mut doc_vals, &mut committed, out);
        cur_doc = Some(doc_n);
      }
      for tag in scratch.drain(..) {
        let key = (
          smol_str::SmolStr::new(tag.tag().group_ref().family1()),
          smol_str::SmolStr::new(tag.tag().name()),
        );
        if let Some(slot) = doc_vals.iter_mut().find(|(k, _)| *k == key) {
          slot.1 = tag;
        } else {
          doc_vals.push((key, tag));
        }
      }
    }
  }
  flush_doc(&mut doc_vals, &mut committed, out);
}

/// A camm `float[3]` value rendered as the three components space-joined via
/// Perl's default `%.15g` stringification — ExifTool's `"@a"` interpolation of
/// the `Format => 'float[3]'` array (QuickTimeStream.pl:448/460/472/568). Each
/// `f32` is widened to `f64` and rendered by [`format_g`], matching the oracle
/// (`AngularVelocity "0.100000001490116 -0.200000002980232 0.300000011920929"`).
/// Mode-invariant — the vec3 tags carry NO PrintConv (`Notes`-only).
#[cfg(feature = "alloc")]
fn camm_vec3_value(v: &crate::metadata::CammVector3) -> crate::value::TagValue {
  use crate::value::format_g;
  let g = |x: f32| format_g(f64::from(x), 15);
  let mut s = g(v.x());
  s.push(' ');
  s.push_str(&g(v.y()));
  s.push(' ');
  s.push_str(&g(v.z()));
  crate::value::TagValue::Str(s.into())
}

/// A camm1 exposure / rolling-shutter time value. The typed layer already holds
/// SECONDS (post-`ValueConv $val * 1e-9`). At `-j` the PrintConv
/// `sprintf("%.4g ms", $val * 1000)` (QuickTimeStream.pl:432/438) renders e.g.
/// `0.008 → "8 ms"`; at `-n` the raw `F64` seconds (`0.008`) is emitted.
#[cfg(feature = "alloc")]
fn camm_exposure_ms_value(seconds: f64, print_conv: bool) -> crate::value::TagValue {
  use crate::value::{TagValue, format_g};
  if print_conv {
    let mut s = format_g(seconds * 1000.0, 4);
    s.push_str(" ms");
    TagValue::Str(s.into())
  } else {
    TagValue::F64(seconds)
  }
}

/// `GPS::ToDMS($self, $val, 1, $ref)` for a timed-GPS lat/lon (the
/// `%QuickTime::Stream` / `camm5` / `camm6` PrintConv,
/// QuickTimeStream.pl:116/494/541): the magnitude formatted
/// `q{%d deg %d' %.2f"}` ([`crate::exif::gps::to_dms`]) plus a space and the
/// hemisphere char — `ref_pos` for a non-negative value, `ref_neg` for a
/// negative one (`{N=>'S', E=>'W'}`). The f64 form (no Perl-numify round-trip)
/// of [`to_dms_with_ref`].
#[cfg(feature = "alloc")]
fn dms_signed(val: f64, ref_pos: char, ref_neg: char) -> std::string::String {
  let r = if val < 0.0 { ref_neg } else { ref_pos };
  std::format!("{} {}", crate::exif::gps::to_dms(val), r)
}

/// `GPSAltitude` value for the `%QuickTime::Stream` SP3 source. PrintConv
/// `(sprintf("%.4f", $val) + 0) . " m"` (QuickTimeStream.pl:120) — round to 4
/// decimals, drop the trailing zeros via Perl's numeric `+0` (its default
/// `%.15g` NV stringification, [`format_g`]), then append `" m"`. `-n` emits the
/// raw metres [`TagValue::F64`].
#[cfg(feature = "alloc")]
fn gps_altitude_stream_value(val: f64, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    // `sprintf("%.4f", $val)` then `+ 0` (numify) ⇒ Perl re-stringifies the
    // rounded NV with `%.15g`. Round the f64 to 4 decimals first, then render
    // with `format_g` — the `%.15g` of a 4-decimal value never re-expands.
    let rounded = round_to_decimals(val, 4);
    let mut s = format_g(rounded, 15);
    s.push_str(" m");
    TagValue::Str(s.into())
  } else {
    TagValue::F64(val)
  }
}

/// `GPSAltitude` value for the Android `camm5`/`camm6` sources. PrintConv
/// `$_ = sprintf("%.Nf", $val); s/\.?0+$//; "$_ m"` — N = 6 for camm5
/// (QuickTimeStream.pl:499), 3 for camm6 (:552) — i.e. format to N decimals,
/// STRING-strip the trailing zeros (and a now-bare dot), then append `" m"`.
/// `-n` emits the raw metres [`TagValue::F64`]. Distinct from the Stream
/// `+ 0` numeric strip ([`gps_altitude_stream_value`]) both in precision and in
/// the strip mechanism (a regex on the fixed-notation string, never exponent
/// notation).
#[cfg(feature = "alloc")]
fn gps_altitude_camm_value(val: f64, packet_type: u8, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    let prec = if packet_type == 6 { 3 } else { 6 };
    // `sprintf("%.{prec}f", $val)` — fixed-point, matching Perl's `sprintf`.
    let mut s = std::format!("{val:.prec$}");
    // `s/\.?0+$//` — strip a trailing run of zeros, plus a `.` it leaves bare.
    if s.contains('.') {
      while s.ends_with('0') {
        s.pop();
      }
      if s.ends_with('.') {
        s.pop();
      }
    }
    s.push_str(" m");
    TagValue::Str(s.into())
  } else {
    TagValue::F64(val)
  }
}

/// Round `val` to `decimals` fractional digits the way Perl `sprintf("%.Nf")`
/// does (round half away from zero), returning the rounded f64. Used by the
/// Stream `GPSAltitude` `+ 0` numeric strip (the value is then re-rendered by
/// `format_g`).
#[cfg(feature = "alloc")]
fn round_to_decimals(val: f64, decimals: u32) -> f64 {
  if !val.is_finite() {
    return val;
  }
  let factor = 10f64.powi(decimals as i32);
  // `sprintf` rounds half away from zero; `f64::round` does the same.
  (val * factor).round() / factor
}

/// Sony rtmd `0xe303 WhiteBalance` PrintConv (Sony.pm:10818-10827). A code
/// OUTSIDE the table falls through to `Unknown ($val)` (ExifTool.pm:3622) —
/// the real fixture carries `0`, so the oracle shows `"Unknown (0)"`.
#[cfg(feature = "alloc")]
fn sony_rtmd_white_balance_print(v: u8) -> std::string::String {
  match v {
    1 => "Incandescent".to_string(),
    2 => "Fluorescent".to_string(),
    4 => "Daylight".to_string(),
    5 => "Cloudy".to_string(),
    6 => "Custom".to_string(),
    255 => "Preset".to_string(),
    other => std::format!("Unknown ({other})"),
  }
}

/// `0xe303 WhiteBalance` from a [`crate::metadata::NumericRead`] (Sony.pm:10817-
/// 10827, `int8u` + PrintConv hash). `Valid(v)` ⇒ the hash PrintConv at `-j`
/// (an out-of-table code → `Unknown ($val)`) / the raw numeric key at `-n`.
/// `EmptyRead` (a present zero-length record whose `ReadValue` ⇒ `''`) ⇒ the
/// PrintConv-of-`''`: the hash MISSES the empty string (no `0`/empty key) so
/// bundled renders `"Unknown ()"` at `-j`, and the raw `''` EMPTY STRING at
/// `-n` (verified byte-exact vs bundled ExifTool 13.59).
#[cfg(feature = "alloc")]
fn sony_rtmd_white_balance_read_value(
  read: crate::metadata::NumericRead<u8>,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  match read {
    NumericRead::Valid(v) => {
      if print_conv {
        TagValue::Str(sony_rtmd_white_balance_print(v).into())
      } else {
        TagValue::U64(u64::from(v))
      }
    }
    NumericRead::EmptyRead => {
      if print_conv {
        // The hash has no key for `''` and no `OTHER`/`BITMASK` → `Unknown ()`.
        TagValue::Str(print_conv_unknown("").into())
      } else {
        TagValue::Str("".into())
      }
    }
  }
}

/// ExifTool's default PrintConv hash-miss rendering (ExifTool.pm:3633,
/// `$value = "Unknown ($val)"`) — for a value with no matching hash key and no
/// `OTHER`/`BITMASK`/`PrintHex`. The Sony rtmd GPS ref / status / measure-mode
/// tables are bare inline hashes (Sony.pm:10788/10804/10827/10836) with NO
/// `OTHER` handler, so ANY out-of-table value (incl. a DEFINED EMPTY STRING from
/// a leading-NUL record) renders `Unknown (<val>)` — e.g. an empty value →
/// `"Unknown ()"`, `"X"` → `"Unknown (X)"`. Verified against bundled ExifTool
/// 13.59. (These tags never set `PrintHex`, so the hex branch never applies.)
#[cfg(feature = "alloc")]
fn print_conv_unknown(v: &str) -> std::string::String {
  std::format!("Unknown ({v})")
}

/// Sony rtmd `0x8501 GPSLatitudeRef` PrintConv (Sony.pm:10788, a bare
/// `{ N => 'North', S => 'South' }` hash): `N`→North / `S`→South. Any other
/// value renders ExifTool's default `Unknown (<val>)` (no `OTHER` handler).
#[cfg(feature = "alloc")]
fn sony_rtmd_lat_ref_print(v: &str) -> std::string::String {
  match v {
    "N" => "North".to_string(),
    "S" => "South".to_string(),
    other => print_conv_unknown(other),
  }
}

/// Sony rtmd `0x8503 GPSLongitudeRef` PrintConv (Sony.pm:10804, a bare
/// `{ E => 'East', W => 'West' }` hash): `E`→East / `W`→West. Any other value
/// renders `Unknown (<val>)`.
#[cfg(feature = "alloc")]
fn sony_rtmd_lon_ref_print(v: &str) -> std::string::String {
  match v {
    "E" => "East".to_string(),
    "W" => "West".to_string(),
    other => print_conv_unknown(other),
  }
}

/// Sony rtmd `0x8509 GPSStatus` PrintConv (Sony.pm:10827, a bare
/// `{ A => 'Measurement Active', V => 'Measurement Void' }` hash). Any other
/// value renders `Unknown (<val>)`.
#[cfg(feature = "alloc")]
fn sony_rtmd_gps_status_print(v: &str) -> std::string::String {
  match v {
    "A" => "Measurement Active".to_string(),
    "V" => "Measurement Void".to_string(),
    other => print_conv_unknown(other),
  }
}

/// Sony rtmd `0x850a GPSMeasureMode` PrintConv (Sony.pm:10836, a bare
/// `{ 2 => '2-Dimensional Measurement', 3 => '3-Dimensional Measurement' }`
/// hash). Any other value renders `Unknown (<val>)`.
#[cfg(feature = "alloc")]
fn sony_rtmd_gps_measure_mode_print(v: &str) -> std::string::String {
  match v {
    "2" => "2-Dimensional Measurement".to_string(),
    "3" => "3-Dimensional Measurement".to_string(),
    other => print_conv_unknown(other),
  }
}

/// `Image::ExifTool::GPS::PrintTimeStamp` (GPS.pm:480-486) — the PrintConv on
/// `GPSTimeStamp` (`0x8507`). The stored value is the post-`ConvertTimeStamp`
/// `HH:MM:SS[.ddd…]` string (the `-n` / ValueConv form, up to 9 fractional
/// digits); at `-j` the fractional seconds are ROUNDED to microseconds:
///
/// ```text
/// return $val unless $val =~ s/:(\d{2}\.\d+)$//;   # only a fractional :SS.d…
/// my $s = int($1 * 1000000 + 0.5) / 1000000;       # round to 1e-6
/// $s = "0$s" if $s < 10;                            # re-pad a single digit
/// return "${val}:$s";
/// ```
///
/// A whole-second timestamp (`:SS` with no fraction) does NOT match the
/// regex and is returned unchanged. The rounded number is stringified with
/// Perl's default `%g` (≤ 15 sig-figs) — [`crate::value::format_g`] with
/// precision 15 reproduces that (e.g. `3.123456789` → `3.123457`).
/// Render a Sony rtmd `0x8502 GPSLatitude` / `0x8504 GPSLongitude`
/// [`crate::metadata::SonyRtmdCoord`] for emission. A present record is always
/// a DEFINED tag:
///  - [`crate::metadata::SonyRtmdCoord::Value`] — the UNSIGNED magnitude (the
///    hemisphere is the separate `*Ref` tag): `GPS::ToDMS` at `-j`
///    (`print_conv` true), the raw F64 magnitude at `-n`;
///  - [`crate::metadata::SonyRtmdCoord::Empty`] — the EMPTY STRING `""` at BOTH
///    modes (the `GPS::ToDegrees` `""` render for an inf/undef / too-short
///    component, GPS.pm:585; verified byte-exact vs bundled ExifTool 13.59).
///
/// Emitting the `Empty` as a real `Str("")` entry (rather than dropping the
/// tag) reproduces bundled's `-G1` first-wins collapse: a Doc1 present-empty
/// coordinate keeps `""` over a later Doc's finite value (the empty string is a
/// defined value extracted first).
#[cfg(feature = "alloc")]
fn sony_rtmd_gps_coord_value(
  coord: crate::metadata::SonyRtmdCoord,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::SonyRtmdCoord;
  use crate::value::TagValue;
  match coord {
    SonyRtmdCoord::Value(v) => {
      if print_conv {
        TagValue::Str(crate::exif::gps::to_dms(v.abs()).into())
      } else {
        TagValue::F64(v.abs())
      }
    }
    SonyRtmdCoord::Empty => TagValue::Str("".into()),
  }
}

#[cfg(feature = "alloc")]
fn sony_rtmd_print_time_stamp(val: &str) -> std::string::String {
  // Match a trailing `:` + exactly two digits + `.` + one-or-more digits.
  // Find the LAST ':' and test the tail shape (no regex dependency).
  let Some(colon) = val.rfind(':') else {
    return val.to_string();
  };
  let (head, tail) = val.split_at(colon); // tail starts with ':'
  let frac = &tail[1..]; // drop the ':'
  let Some(dot) = frac.find('.') else {
    return val.to_string(); // whole second — unchanged
  };
  let (sec, rest) = frac.split_at(dot); // sec = "SS", rest = ".ddd…"
  let dec = &rest[1..]; // drop the '.'
  // Faithful to `\d{2}\.\d+`: exactly two leading second digits, ≥ 1
  // fractional digit, all ASCII digits. Anything else ⇒ no match.
  if sec.len() != 2
    || !sec.bytes().all(|b| b.is_ascii_digit())
    || dec.is_empty()
    || !dec.bytes().all(|b| b.is_ascii_digit())
  {
    return val.to_string();
  }
  // `$1` is the whole `SS.ddd…` number.
  let Ok(num) = frac.parse::<f64>() else {
    return val.to_string();
  };
  // `int($1 * 1e6 + 0.5) / 1e6` — Perl `int()` truncates toward zero; the
  // input is non-negative so `trunc()` matches. Stringify the result via
  // Perl's default `%g` (15 sig-figs).
  let rounded = (num * 1_000_000.0 + 0.5).trunc() / 1_000_000.0;
  let mut s = crate::value::format_g(rounded, 15);
  if rounded < 10.0 {
    s.insert(0, '0');
  }
  std::format!("{head}:{s}")
}

/// Numify a rational's ValueConv string the way Perl `sprintf("%.2f", $val)`
/// would, for `0x8106 FrameRate`'s `sprintf("%.2f",$val)` PrintConv. The
/// ValueConv result is `GetRational64u` ([`crate::value::Rational::exiftool_val_str`]):
/// a `%.10g` number for a finite quotient, or the non-numeric word `"undef"`
/// (`0/0`) / `"inf"` (`n/0`).
///
/// Perl `sprintf("%.2f", $s)` NUMIFIES `$s` first: `"undef"` → `0` →
/// `"0.00"` (a bare JSON number), `"inf"` → `Inf` → `"Inf"` (Perl's `%f`
/// titlecases infinity → a quoted JSON string), a finite number → `"%.2f"`.
/// Verified empirically against bundled ExifTool 13.59 (a `0/0` FrameRate
/// renders `0.00` at `-j`, an `n/0` FrameRate renders `"Inf"`).
fn sony_rtmd_frame_rate_value(
  r: crate::value::Rational,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  if !print_conv {
    // `-n` (ValueConv): the rational renders its `%.10g` value, or the
    // `"undef"`/`"inf"` word for a zero denominator (handled by the
    // `Rational` serializer).
    return TagValue::Rational(r);
  }
  let val_str = r.exiftool_val_str();
  // Perl numification of the ValueConv scalar: a finite `%.10g` number parses;
  // `"undef"` → 0.0; `"inf"` → +∞ (numerator of a `rational64u` is unsigned,
  // so `-inf` is unreachable, but `parse` would handle it).
  let numified = val_str.parse::<f64>().unwrap_or(0.0);
  if numified.is_finite() {
    TagValue::Str(std::format!("{numified:.2}").into())
  } else {
    // Perl `%f` of a non-finite value: titlecase `Inf` / `-Inf` / `NaN`.
    match crate::value::perl_nonfinite_str(numified) {
      Some(text) => TagValue::Str(text.into()),
      None => TagValue::Str(val_str.into()),
    }
  }
}

/// `0x8109 ExposureTime`'s `PrintExposureTime($val)` PrintConv applied to the
/// rational's ValueConv string. `PrintExposureTime` returns its argument
/// UNCHANGED `unless IsFloat($val)` (ExifTool.pm `IsFloat` rejects `"undef"`
/// and `"inf"`), so a zero-denominator value passes through verbatim
/// (`0/0` → `"undef"`, `n/0` → `"inf"` — both verified against bundled 13.59);
/// a finite quotient runs the normal `1/x` / `%.1f` shaping.
fn sony_rtmd_exposure_time_value(
  r: crate::value::Rational,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  if !print_conv {
    return TagValue::Rational(r);
  }
  let val_str = r.exiftool_val_str();
  match val_str.parse::<f64>() {
    // A finite ValueConv number ⇒ the normal PrintExposureTime shaping.
    Ok(f) if f.is_finite() => TagValue::Str(crate::exif::tables::print_exposure_time(f).into()),
    // `"undef"` / `"inf"` (zero denominator) ⇒ `IsFloat` is false ⇒
    // PrintExposureTime returns the value-string verbatim.
    _ => TagValue::Str(val_str.into()),
  }
}

// ── Canon CTMD rational32u emission (FocalLength / FNumber / ExposureTime) ──
//
// Canon CTMD stores these three records as the RAW `rational32u`
// ([`crate::value::Rational`] with `sig = 7`), so `-n` (ValueConv) renders
// ExifTool's `GetRational32u` `%.7g` form (`10/3` → `3.333333`, NOT the
// 15-digit f64) and a zero denominator keeps the bare `inf`/`undef` word — both
// handled by the `Rational` serializer via [`TagValue::Rational`]. `-j`
// (PrintConv) numifies the SAME ValueConv string the way each Perl PrintConv
// does, all oracle-verified vs bundled ExifTool 13.59.

/// `FocalLength`'s `sprintf("%.1f mm",$val)` PrintConv (Canon.pm:9863) applied
/// to the `rational32u` ValueConv string. The Perl PrintConv has NO `IsFloat`
/// guard — it always `sprintf`-numifies: a finite quotient → `"%.1f mm"`
/// (`3.333…` → `"3.3 mm"`), `"undef"` (`0/0`) numifies to `0` → `"0.0 mm"`,
/// `"inf"` (`n/0`) numifies to `Inf` → `"Inf mm"` (Perl `%f` titlecases
/// infinity). `-n` is the raw [`Rational`].
#[cfg(feature = "alloc")]
fn canon_ctmd_focal_length_value(
  r: crate::value::Rational,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  if !print_conv {
    return TagValue::Rational(r);
  }
  let val_str = r.exiftool_val_str();
  // Perl numification of the ValueConv scalar: a finite `%.7g` number parses;
  // `"undef"` → 0.0; `"inf"` → +∞.
  let numified = val_str.parse::<f64>().unwrap_or(0.0);
  if numified.is_finite() {
    TagValue::Str(std::format!("{numified:.1} mm").into())
  } else {
    // Perl `sprintf("%.1f mm", non-finite)`: titlecase `Inf`/`NaN`, then ` mm`.
    match crate::value::perl_nonfinite_str(numified) {
      Some(text) => TagValue::Str(std::format!("{text} mm").into()),
      None => TagValue::Str(std::format!("{val_str} mm").into()),
    }
  }
}

/// `FNumber`'s `Exif::PrintFNumber($val)` PrintConv applied to the `rational32u`
/// ValueConv string. `PrintFNumber` returns its argument UNCHANGED unless
/// `IsFloat($val) and $val > 0` (Exif.pm:5715-5723), so a zero-denominator
/// `"undef"`/`"inf"` passes through verbatim; a finite quotient rounds to 2
/// decimals (`< 1`) or 1 decimal (`≥ 1`). `-n` is the raw [`Rational`].
#[cfg(feature = "alloc")]
fn canon_ctmd_fnumber_value(r: crate::value::Rational, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if !print_conv {
    return TagValue::Rational(r);
  }
  let val_str = r.exiftool_val_str();
  match val_str.parse::<f64>() {
    // A finite ValueConv number ⇒ the normal PrintFNumber shaping.
    Ok(f) if f.is_finite() => TagValue::Str(crate::exif::tables::print_fnumber(f).into()),
    // `"undef"` / `"inf"` ⇒ `IsFloat` is false ⇒ PrintFNumber returns it verbatim.
    _ => TagValue::Str(val_str.into()),
  }
}

/// `ExposureTime`'s `Exif::PrintExposureTime($val)` PrintConv applied to the
/// `rational32u` ValueConv string — IDENTICAL shaping to
/// [`sony_rtmd_exposure_time_value`] (the `1/x` / `%.1f` form for a finite
/// value, the `"undef"`/`"inf"` word passed through for a zero denominator),
/// but over a `sig = 7` rational. `-n` is the raw [`Rational`].
#[cfg(feature = "alloc")]
fn canon_ctmd_exposure_time_value(
  r: crate::value::Rational,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  if !print_conv {
    return TagValue::Rational(r);
  }
  let val_str = r.exiftool_val_str();
  match val_str.parse::<f64>() {
    Ok(f) if f.is_finite() => TagValue::Str(crate::exif::tables::print_exposure_time(f).into()),
    _ => TagValue::Str(val_str.into()),
  }
}

/// Re-dispatch one Canon CTMD `ExifInfo*` (type 7/8/9) embedded TIFF block and
/// push its recovered tags into `out`, re-stamped to the bundled-faithful group
/// (oracle-verified vs ExifTool 13.59 `-ee -G3:1:0`).
///
/// `Image::ExifTool::Canon::ProcessExifInfo` (Canon.pm:10730-10754) re-dispatches
/// each `[len][tag][TIFF]` block via `ProcessTIFF` under the CTMD sample's open
/// `Doc<N>` / `Track<N>` scope. The recovered tags carry these groups (which the
/// standalone Exif / Canon-MakerNote walkers do NOT produce verbatim, so we
/// re-stamp):
///
///  - **`0x8769` `ExifIFD`** → the standard Exif walker
///    ([`parse_standalone_tiff_with_base`](crate::exif::parse_standalone_tiff_with_base)).
///    Its `File:ExifByteOrder` re-scopes to family-1 `Track<N>` (family-0
///    `File`); the walker's TOP-LEVEL `IFD0` tags emit under family-0 `EXIF`,
///    family-1 `ExifIFD` (the 0x8769 directory's bundled name) — but a NESTED
///    sub-IFD keeps its own DirName (`InteropIFD` via 0xa005, `IFD1`, …), and a
///    GPS-IFD tag re-scopes family-1 to `Track<N>` (still family-0 `EXIF`). All
///    under `Doc<N>` (`-G3`).
///  - **`0x927c` `MakerNoteCanon`** → the Canon MakerNote walker
///    ([`canon::redispatch_ctmd_makernote`](crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote)).
///    Every recovered tag emits under family-0 `MakerNotes`, family-1
///    `Track<N>`, `Doc<N>` (NO `ExifByteOrder` — the MakerNote re-dispatch does
///    not surface it).
///
/// `print_conv` selects `-j` (PrintConv) vs `-n` (ValueConv); `g3` adds the
/// `Doc<N>` family-3 axis (collapsed at `-G1`, where the across-doc first-wins
/// dedup in the caller keeps the first sample's value per `family1:name`).
#[cfg(feature = "alloc")]
fn emit_ctmd_exif_info(
  info: &crate::metadata::CtmdExifInfo,
  track: &str,
  doc_n: u32,
  g3: bool,
  print_conv: bool,
  out: &mut std::vec::Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::{EmittedTag, Taggable};
  use crate::value::Group;
  // Build a group on the CTMD sample's family-3 axis: `Doc<N>` when `-G3`, else
  // collapsed (doc 0) — the caller's first-wins dedup folds the doc axis.
  let scoped = |family0: &str, family1: &str| -> Group {
    if g3 {
      Group::with_doc(family0, family1, doc_n)
    } else {
      Group::new(family0, family1)
    }
  };
  match info.tag() {
    crate::metadata::CtmdExifTag::ExifIfd => {
      // The embedded TIFF is self-contained (base 0); `ProcessExifInfo`'s
      // `DataPos => -($pos + 8)` makes its out-of-line offsets block-relative.
      // No-RAF re-dispatch: bundled re-frames `$dataPt` to the embedded block
      // with no `RAF`, so an out-of-bounds out-of-line value warns `Bad offset
      // for ExifIFD <tag>` and CONTINUES (the value is dropped) — NOT the
      // RAF path's `Error reading value` + directory abort that would drop
      // every LATER valid entry too. The diagnostic harvest
      // ([`crate::formats::canon_ctmd`]) uses the same no-RAF entry point.
      let Some(meta) = crate::exif::parse_ctmd_exif_ifd_redispatch(info.tiff()) else {
        return;
      };
      let opts =
        crate::emit::EmitOptions::g1(crate::emit::ConvMode::from_print_conv(print_conv), false);
      for tag in meta.tags(opts) {
        let unknown = tag.unknown();
        let (group, name, value) = tag.into_tag().into_parts();
        let family0 = group.family0();
        let family1 = group.family1();
        // Re-stamp per the oracle (ExifTool 13.59, `-ee -G3:1`): the 0x8769
        // SubDirectory is `ProcessTIFF`ed via `Exif::Main`, which names the
        // top-level directory `ExifIFD` (Canon.pm:9838-9843; Exif.pm SET_GROUP1)
        // but PRESERVES the DirName of any NESTED sub-IFD reached from it. So:
        //   - `File:ExifByteOrder` → `File:Track<N>` (the byte-order marker rides
        //     the sample's track scope);
        //   - a GPS-IFD tag → `EXIF:Track<N>` (the GPS sub-IFD collapses onto the
        //     track, oracle-confirmed);
        //   - the generic walker's TOP-LEVEL `IFD0` → `EXIF:ExifIFD` (the 0x8769
        //     directory's bundled name);
        //   - every OTHER nested family-1 group (InteropIFD via 0xa005, IFD1, a
        //     nested ExifIFD, …) keeps its DirName — bundled emits e.g.
        //     `Doc1:InteropIFD:InteropIndex`, NOT collapsed to ExifIFD.
        let restamped = if family0 == "File" {
          scoped("File", track)
        } else if family1 == "GPS" {
          scoped("EXIF", track)
        } else if family1 == "IFD0" {
          scoped("EXIF", "ExifIFD")
        } else {
          scoped("EXIF", family1)
        };
        out.push(EmittedTag::new(restamped, name, value, unknown));
      }
    }
    crate::metadata::CtmdExifTag::MakerNoteCanon => {
      // The `0x927c` block is a complete TIFF whose IFD0 IS the Canon
      // MakerNote — route it through `Canon::Main` (the same machinery the
      // static-file MakerNote path uses). `model` is the `$$self{Model}` in
      // effect at this block's `ProcessExifInfo` walk position — the IFD0 `Model`
      // of a preceding in-sample `0x8769` `ExifIFD` block (captured at parse
      // time, Canon.pm:10739-10751), so model-conditional Canon sub-tables
      // (`Canon::ShotInfo` `CameraTemperature`, `Canon::FileInfo` position 1)
      // evaluate against the handed-off Model exactly as bundled does. `None`
      // when no preceding `0x8769` set one.
      let emissions = crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote(
        info.tiff(),
        print_conv,
        info.model(),
      );
      let group = scoped("MakerNotes", track);
      for e in emissions {
        // The engine's Unknown-suppression runs centrally; the caller's CTMD
        // scratch is appended into the engine sink, so carry the flag through.
        out.push(EmittedTag::new(
          group.clone(),
          smol_str::SmolStr::new(e.name()),
          e.value().clone(),
          e.unknown(),
        ));
      }
    }
  }
}

// ── Sony rtmd NUMERIC-tag `NumericRead` emission (present sub-width records) ──
//
// A PRESENT Sony rtmd numeric record always emits a DEFINED tag (Sony.pm:11582
// `while $pos+4 < $end` walks a NON-FINAL present record even when its value is
// sub-width; `ReadValue` returns `''`, the tag's ValueConv NUMIFIES it). These
// helpers render a [`crate::metadata::NumericRead`]: `Valid(t)` EXACTLY as the
// non-degenerate path did (byte-identical for valid input), `EmptyRead` as the
// ValueConv-of-`''` measured against bundled ExifTool 13.59. Record ABSENCE (a
// FINAL bare header) never reaches here — the emission `if let Some(read)` is
// the absent gate.

/// `0x8000 FNumber` from a [`crate::metadata::NumericRead`]. `Valid(f)` ⇒
/// `PrintFNumber(f)` at `-j` / raw F64 at `-n` (unchanged). `EmptyRead` ⇒ the
/// ValueConv-of-`''` `2^(8-0/8192) = 256` rendered the SAME way: `PrintFNumber(256)`
/// = `"256.0"` at `-j`, `256` at `-n` (the integer-valued F64 serializes `256`).
#[cfg(feature = "alloc")]
fn sony_rtmd_fnumber_value(
  read: crate::metadata::NumericRead<f64>,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  // `EmptyRead` ⇒ the ValueConv numifies `''` to 0 ⇒ `2^(8-0/8192) = 256`.
  let v = match read {
    NumericRead::Valid(v) => v,
    NumericRead::EmptyRead => 256.0,
  };
  if print_conv {
    TagValue::Str(crate::exif::tables::print_fnumber(v).into())
  } else {
    TagValue::F64(v)
  }
}

/// `0x810a MasterGainAdjustment` from a [`crate::metadata::NumericRead`].
/// `Valid(v)` ⇒ `sprintf("%.2f dB",v)` at `-j` / raw F64 at `-n` (unchanged).
/// `EmptyRead` ⇒ the ValueConv-of-`''` `''/100 = 0`: `"0.00 dB"` at `-j`, `0`
/// at `-n`.
#[cfg(feature = "alloc")]
fn sony_rtmd_master_gain_value(
  read: crate::metadata::NumericRead<f64>,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  let v = match read {
    NumericRead::Valid(v) => v,
    NumericRead::EmptyRead => 0.0,
  };
  if print_conv {
    TagValue::Str(std::format!("{v:.2} dB").into())
  } else {
    TagValue::F64(v)
  }
}

/// A no-conv raw-integer numeric tag (`0x810b ISO`, `0x810c
/// ElectricalExtenderMagnification`) from a [`crate::metadata::NumericRead`].
/// `Valid(v)` ⇒ the plain integer in both modes (unchanged). `EmptyRead` ⇒ the
/// raw `''` EMPTY STRING in both modes (no ValueConv to numify it — `ReadValue`
/// returns `''` and there is no conv, so bundled emits `""`).
#[cfg(feature = "alloc")]
fn sony_rtmd_raw_int_read_value<T: Into<u64>>(
  read: crate::metadata::NumericRead<T>,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  match read {
    NumericRead::Valid(v) => TagValue::U64(v.into()),
    NumericRead::EmptyRead => TagValue::Str("".into()),
  }
}

/// `0x8106 FrameRate` from a [`crate::metadata::NumericRead`]. `Valid(r)` ⇒ the
/// existing rational rendering (`sprintf("%.2f")` at `-j`, raw `rational64u` at
/// `-n`). `EmptyRead` ⇒ the ValueConv-of-`''`: `sprintf("%.2f",'')` numifies
/// `''` to 0 ⇒ `0.00` (a bare number) at `-j`, the raw `''` EMPTY STRING at
/// `-n`.
#[cfg(feature = "alloc")]
fn sony_rtmd_frame_rate_read_value(
  read: crate::metadata::NumericRead<crate::value::Rational>,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  match read {
    NumericRead::Valid(r) => sony_rtmd_frame_rate_value(r, print_conv),
    NumericRead::EmptyRead => {
      if print_conv {
        // `sprintf("%.2f",'')` → `0.00`. `Str("0.00")` routes through the
        // numeric-gate → a bare number (value-equal to bundled's `0.00`).
        TagValue::Str("0.00".into())
      } else {
        TagValue::Str("".into())
      }
    }
  }
}

/// `0x8109 ExposureTime` from a [`crate::metadata::NumericRead`]. `Valid(r)` ⇒
/// the existing rational rendering (`PrintExposureTime` at `-j`, raw
/// `rational64u` at `-n`). `EmptyRead` ⇒ the ValueConv-of-`''`: the EMPTY STRING
/// `''` in BOTH modes (`PrintExposureTime('')` returns its argument unchanged —
/// `IsFloat('')` is false).
#[cfg(feature = "alloc")]
fn sony_rtmd_exposure_time_read_value(
  read: crate::metadata::NumericRead<crate::value::Rational>,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::metadata::NumericRead;
  use crate::value::TagValue;
  match read {
    NumericRead::Valid(r) => sony_rtmd_exposure_time_value(r, print_conv),
    NumericRead::EmptyRead => TagValue::Str("".into()),
  }
}

/// Build a GoPro unit-suffix tag value — the `'"$val <unit>"'` PrintConv shared
/// by the Karma GLPI speeds (`" m/s"`, GoPro.pm:622-624) and the KBAT
/// current/capacity/temperature/voltage/level columns (GoPro.pm:634-648). `-j`
/// (PrintConv) stringifies the scaled F64 with Perl's default `%.15g` NV
/// stringification ([`format_g`]) and appends `unit` (which carries its own
/// leading space, e.g. `" m/s"`, matching the literal Perl interpolation);
/// `-n` (ValueConv) emits the raw [`TagValue::F64`].
#[cfg(feature = "alloc")]
fn unit_suffix_value(val: f64, unit: &str, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    let mut s = format_g(val, 15);
    s.push_str(unit);
    TagValue::Str(s.into())
  } else {
    TagValue::F64(val)
  }
}

/// Build a GoPro `GPSMeasureMode` tag value: the `%GoPro::GPMF` `GPSF` /
/// `%GoPro::GPS9` col-8 PrintConv (`2 => '2-Dimensional Measurement'`,
/// `3 => '3-Dimensional Measurement'`, GoPro.pm:230-236 / 560-562). `-j`
/// (PrintConv) yields the description (an out-of-table code falls through to
/// the bare number via `ExifTool.pm:3622` `Unknown ($val)` — but GoPro only
/// ever writes 2/3, so the unknown arm renders the raw code as a string);
/// `-n` (ValueConv) yields the raw [`TagValue::U64`].
#[cfg(feature = "alloc")]
fn gps_measure_mode_value(mode: u32, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    match mode {
      2 => TagValue::Str("2-Dimensional Measurement".into()),
      3 => TagValue::Str("3-Dimensional Measurement".into()),
      other => TagValue::Str(std::format!("Unknown ({other})").into()),
    }
  } else {
    TagValue::U64(u64::from(mode))
  }
}

/// Build an Android CAMM `GPSMeasureMode` tag value (`%QuickTime::camm6`,
/// QuickTimeStream.pl:527-535). PrintConv hash `{0 => 'No Measurement',
/// 2 => '2-Dimensional Measurement', 3 => '3-Dimensional Measurement'}` — note
/// camm6 carries the extra `0 => 'No Measurement'` entry the GoPro GPSF table
/// lacks, so this cannot share [`gps_measure_mode_value`]. A hash miss yields
/// `Unknown ($val)` (ExifTool.pm:3622); `-n` (ValueConv) emits the raw code.
fn camm_gps_measure_mode_value(mode: u32, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    match mode {
      0 => TagValue::Str("No Measurement".into()),
      2 => TagValue::Str("2-Dimensional Measurement".into()),
      3 => TagValue::Str("3-Dimensional Measurement".into()),
      other => TagValue::Str(std::format!("Unknown ({other})").into()),
    }
  } else {
    TagValue::U64(u64::from(mode))
  }
}

/// Build a GoPro `MediaUniqueID` tag value (`%GoPro::GPMF` `MUID`,
/// GoPro.pm:456-462). The stored `raw` is ExifTool's ValueConv — the
/// space-joined `u32` list. `-j` (PrintConv) hex-renders each element with
/// `%.8x` and concatenates (`my @a = split ' ', $val; $_ = sprintf('%.8x',$_)
/// foreach @a; join('', @a)`); `-n` (ValueConv) emits the raw space-joined
/// value verbatim.
#[cfg(feature = "alloc")]
fn media_uid_value(raw: &str, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    // Hex-concatenate the parsed u32s. A non-numeric element falls back to a
    // bare `0` slot only if `parse` fails — but the parser always emits
    // decimal u32s, so every element parses. Faithful `sprintf('%.8x',$_)`.
    let mut hex = std::string::String::new();
    for tok in raw.split(' ') {
      if tok.is_empty() {
        continue;
      }
      let v: u32 = tok.parse().unwrap_or(0);
      hex.push_str(&std::format!("{v:08x}"));
    }
    TagValue::Str(hex.into())
  } else {
    TagValue::Str(raw.into())
  }
}

/// Render a table-driven generic `%GoPro::GPMF` tag ([`GoProTag`]) to its
/// `-n`/`-j` [`TagValue`]. The decode already produced the post-`ScaleValues` /
/// post-`ValueConv` value ([`GoProTagValue`]); this applies the per-tag
/// `PrintConv` (the `conv` family) for `-j` and leaves the value verbatim for
/// `-n` (except `Binary`/`AddUnits`, which transform the value identically in
/// both modes / only in `-j` respectively).
///
/// Faithful to GoPro.pm:
///  - `Binary` → `(Binary data N bytes, use -b option to extract)` in BOTH
///    modes (`Binary => 1` ⇒ ValueConv `'\$val'` scalar ref), `N = length` of
///    the would-be value string (exiftool:3987 `length($$obj)`).
///  - the `%noYes` / `AutoRotation` / `Protune` / `FieldOfView` / `MeasureMode`
///    hashes map the raw token in `-j` (a miss → `Unknown (val)`, ExifTool.pm
///    :3622), the raw token in `-n`.
///  - `Version` (`tr/ /./`), `FrameRate` (first space → `/`),
///    `FrameSize` (first space → `x`), `TempC` (`"$val C"`),
///    `TimeZone` (`TimeZoneString`), `ExposureTimes` (`PrintExposureTime` per
///    element), `MediaUid` (`%.8x` hex join), `AddUnits` (interleave units) —
///    each is a `-j`-only transform of the verbatim `-n` value.
#[cfg(feature = "alloc")]
fn gopro_generic_value(tag: &GoProTag, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  let value = tag.value();
  // `Binary => 1`: the placeholder in BOTH modes, length = the value string.
  if matches!(tag.conv(), GoProConv::Binary) {
    // The scalar-ref `\$val` renders `length($$obj)` (exiftool:3987). A complex
    // `?` MULTI-ROW Binary tag (CSEN/CYTS) has `$val = \@rows`, so ExifTool
    // emits a JSON ARRAY with ONE placeholder per row, each N = that row's value
    // string length (oracle-verified). A single row / flat list is ONE
    // placeholder over the whole value string.
    if let GoProTagValue::Rows(rows) = value
      && rows.len() > 1
    {
      return TagValue::List(
        rows
          .iter()
          .map(|r| TagValue::Str(binary_placeholder(r.len() as u64)))
          .collect(),
      );
    }
    let n = gopro_value_string(value).len() as u64;
    return TagValue::Str(binary_placeholder(n));
  }
  // `-n` (ValueConv): the verbatim decoded value (the AddUnits/PrintConv
  // transforms are `-j`-only; the value-affecting ValueConvs were folded at
  // decode). For a complex `?` multi-row value this is the JSON array.
  if !print_conv {
    return gopro_value_tagvalue(value);
  }
  // `-j` (PrintConv) by conv family.
  match tag.conv() {
    // Hash PrintConvs operate on the raw scalar token (the value string).
    GoProConv::NoYes => gopro_hash_pc(value, |t| match t {
      "N" => Some("No"),
      "Y" => Some("Yes"),
      _ => None,
    }),
    GoProConv::AutoRotation => gopro_hash_pc(value, |t| match t {
      "U" => Some("Up"),
      "D" => Some("Down"),
      "A" => Some("Auto"),
      _ => None,
    }),
    GoProConv::Protune => gopro_hash_pc(value, |t| match t {
      "N" => Some("Off"),
      "Y" => Some("On"),
      _ => None,
    }),
    GoProConv::FieldOfView => gopro_hash_pc(value, |t| match t {
      "W" => Some("Wide"),
      "S" => Some("Super View"),
      "L" => Some("Linear"),
      _ => None,
    }),
    // Regex / suffix string PrintConvs operate on the value string.
    GoProConv::Version => {
      // `$val =~ tr/ /./` — replace ALL spaces with dots.
      TagValue::Str(gopro_value_string(value).replace(' ', ".").into())
    }
    GoProConv::FrameRate => {
      // `$val =~ s( )(/)` — replace the FIRST space with `/`.
      TagValue::Str(replace_first(&gopro_value_string(value), ' ', '/').into())
    }
    GoProConv::FrameSize => {
      // `$val =~ s/ /x/` — replace the FIRST space with `x`.
      TagValue::Str(replace_first(&gopro_value_string(value), ' ', 'x').into())
    }
    GoProConv::TempC => {
      // `"$val C"` — append a space + `C`.
      let mut s = gopro_value_string(value);
      s.push_str(" C");
      TagValue::Str(s.into())
    }
    GoProConv::TimeZone => {
      // `TimeZoneString($val)` — minutes → `±HH:MM`.
      match value {
        GoProTagValue::Num(v) => TagValue::Str(time_zone_string(*v).into()),
        // A non-numeric TZON never occurs (fmt `s`); fall back to the value.
        _ => gopro_value_tagvalue(value),
      }
    }
    GoProConv::ExposureTimes => {
      // `PrintExposureTime` per space-separated element (GoPro.pm:356-360).
      let mapped: Vec<String> = gopro_value_string(value)
        .split(' ')
        .filter(|t| !t.is_empty())
        .map(print_exposure_time)
        .collect();
      TagValue::Str(mapped.join(" ").into())
    }
    GoProConv::AddUnits => gopro_add_units(value, tag.units()),
    // `Plain` (and the value-folded ValueConv tags) — verbatim.
    GoProConv::Plain | GoProConv::Binary => gopro_value_tagvalue(value),
  }
}

/// The `-n` (verbatim) [`TagValue`] for a [`GoProTagValue`]: a string stays a
/// string; a single number is an `F64`; a flat numeric list is the
/// space-joined string ([`crate::formats::gopro`] already produced the scaled
/// values); a complex `?` record is a scalar string for one row or a
/// [`TagValue::List`] of per-row strings for several (`$val = @v>1 ? \@v :
/// $v[0]`, GoPro.pm:863 → the JSON array).
#[cfg(feature = "alloc")]
fn gopro_value_tagvalue(value: &GoProTagValue) -> crate::value::TagValue {
  use crate::value::TagValue;
  match value {
    GoProTagValue::Str(s) => TagValue::Str(s.clone()),
    GoProTagValue::Num(v) => TagValue::F64(*v),
    GoProTagValue::NumList(vs) => TagValue::Str(join_g_q(vs).into()),
    GoProTagValue::Rows(rows) => match rows.as_slice() {
      [one] => TagValue::Str(one.clone()),
      _ => TagValue::List(rows.iter().map(|r| TagValue::Str(r.clone())).collect()),
    },
  }
}

/// The flat value STRING of a [`GoProTagValue`] — used to compute the `Binary`
/// placeholder length and as the input to the regex/suffix PrintConvs. A
/// multi-row complex value joins its rows with a space (the Binary sensor tags
/// are never multi-row complex, so this only affects the length of an
/// edge-case; ExifTool's scalar-ref length is over the single-row string).
#[cfg(feature = "alloc")]
fn gopro_value_string(value: &GoProTagValue) -> String {
  match value {
    GoProTagValue::Str(s) => s.as_str().to_string(),
    GoProTagValue::Num(v) => format_g(*v, 15),
    GoProTagValue::NumList(vs) => join_g_q(vs),
    GoProTagValue::Rows(rows) => rows.join(" "),
  }
}

/// Join scaled `f64`s with single spaces via Perl `%.15g` ([`format_g`]) — the
/// emission-side mirror of `crate::formats::gopro`'s `join_g` (kept local to the
/// emission layer, which owns the value→string rendering).
#[cfg(feature = "alloc")]
fn join_g_q(vals: &[f64]) -> String {
  let mut s = String::new();
  for (i, &v) in vals.iter().enumerate() {
    if i > 0 {
      s.push(' ');
    }
    s.push_str(&format_g(v, 15));
  }
  s
}

/// Apply a hash `PrintConv` to a generic tag's scalar token: `-j` maps the raw
/// value string through `lookup`; a miss renders `Unknown ($val)`
/// (ExifTool.pm:3622). The token is the whole value string (these PrintConv-hash
/// tags are always single-value `c`/numeric records).
#[cfg(feature = "alloc")]
fn gopro_hash_pc(
  value: &GoProTagValue,
  lookup: impl Fn(&str) -> Option<&'static str>,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  let token = gopro_value_string(value);
  match lookup(&token) {
    Some(desc) => TagValue::Str(desc.into()),
    None => TagValue::Str(std::format!("Unknown ({token})").into()),
  }
}

/// `%addUnits` PrintConv (GoPro.pm:727-743). ExifTool's `AddUnits` runs once
/// per element of `$val`: a SCALAR `$val` (single row) yields one string; an
/// ARRAYREF `$val` (a complex `?` MULTI-row record, `$val = \@rows`) yields a
/// JSON ARRAY with `AddUnits` applied to EACH row (oracle-verified). Each row
/// interleaves its space-separated values with the matching unit, but ONLY when
/// the unit count equals that row's value count (`if (@$u == @a)`); empty units
/// are not appended (`if $$u[$i]`).
#[cfg(feature = "alloc")]
fn gopro_add_units(value: &GoProTagValue, units: &[smol_str::SmolStr]) -> crate::value::TagValue {
  use crate::value::TagValue;
  match value {
    // Multi-row complex `?`: one AddUnits string per row → a JSON array.
    GoProTagValue::Rows(rows) if rows.len() > 1 => TagValue::List(
      rows
        .iter()
        .map(|r| TagValue::Str(add_units_to_row(r, units).into()))
        .collect(),
    ),
    // Single row / flat list / scalar: one AddUnits string.
    _ => TagValue::Str(add_units_to_row(&gopro_value_string(value), units).into()),
  }
}

/// Apply `%addUnits` to ONE row string (GoPro.pm:733-739): interleave each
/// space-separated value with the matching unit when the counts agree;
/// otherwise return the row unchanged.
#[cfg(feature = "alloc")]
fn add_units_to_row(row: &str, units: &[smol_str::SmolStr]) -> String {
  let vals: Vec<&str> = row.split(' ').filter(|t| !t.is_empty()).collect();
  if units.is_empty() || units.len() != vals.len() {
    // `@$u != @a` (or no units) — the PrintConv returns the row unchanged.
    return row.to_string();
  }
  let mut out = String::new();
  for (i, v) in vals.iter().enumerate() {
    if i > 0 {
      out.push(' ');
    }
    out.push_str(v);
    // `$a[$i] .= ' ' . $$u[$i] if $$u[$i]` — append non-empty unit.
    if let Some(u) = units.get(i)
      && !u.is_empty()
    {
      out.push(' ');
      out.push_str(u.as_str());
    }
  }
  out
}

/// `TimeZoneString($min)` (ExifTool.pm:6764-6776): minutes east of UTC →
/// `±HH:MM`, rounded to the nearest minute.
#[cfg(feature = "alloc")]
fn time_zone_string(min: f64) -> String {
  let (sign, mut m) = if min < 0.0 { ('-', -min) } else { ('+', min) };
  // `int($min + 0.5)` — round to the nearest minute.
  let total = (m + 0.5).trunc();
  m = total;
  let h = (m / 60.0).trunc();
  let mins = m - h * 60.0;
  std::format!("{sign}{:02}:{:02}", h as i64, mins as i64)
}

/// `PrintExposureTime($secs)` (Exif.pm:5701-5711): `1/N` for a short exposure
/// (`0 < secs < 0.25001`), else `%.1f` with a trailing `.0` stripped. A
/// non-float token is returned unchanged (`unless IsFloat`).
#[cfg(feature = "alloc")]
fn print_exposure_time(tok: &str) -> String {
  let Ok(secs) = tok.parse::<f64>() else {
    return tok.to_string();
  };
  if !secs.is_finite() {
    return tok.to_string();
  }
  if secs > 0.0 && secs < 0.250_01 {
    // `sprintf("1/%d", int(0.5 + 1/$secs))`.
    let denom = (0.5 + 1.0 / secs).trunc();
    return std::format!("1/{}", denom as i64);
  }
  // `sprintf("%.1f", $secs)` then `s/\.0$//`.
  let s = std::format!("{secs:.1}");
  s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

/// Replace the FIRST occurrence of `from` with `to` in `s` (Perl `s/from/to/`
/// without `/g`).
#[cfg(feature = "alloc")]
fn replace_first(s: &str, from: char, to: char) -> String {
  match s.find(from) {
    Some(idx) => {
      let mut out = String::with_capacity(s.len());
      out.push_str(&s[..idx]);
      out.push(to);
      out.push_str(&s[idx + from.len_utf8()..]);
      out
    }
    None => s.to_string(),
  }
}

/// Build a `%durationInfo` tag value: PrintConv `$$self{TimeScale} ?
/// ConvertDuration($val) : $val` (QuickTime.pm:315); -n yields the raw
/// post-ValueConv float seconds. The PrintConv gate is on the TimeScale's
/// TRUTHINESS, not merely its presence — a `TimeScale == 0` is falsy in Perl,
/// so the PrintConv yields the bare value `$val` (which the matching
/// ValueConv `$$self{TimeScale} ? $val/$$self{TimeScale} : $val` already left
/// as the raw count). So only a `Some(ts)` with `ts != 0` runs ConvertDuration
/// (F3); a `None` or `Some(0)` TimeScale yields the bare float
/// ([`TagValue::F64`], byte-identical to the retired `write_f64`).
#[cfg(feature = "alloc")]
fn duration_value(secs: f64, timescale: Option<u32>, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  // QuickTime.pm:315 `$$self{TimeScale} ? ...` — a zero TimeScale is falsy.
  let truthy_ts = matches!(timescale, Some(ts) if ts != 0);
  if print_conv && truthy_ts {
    TagValue::Str(convert_duration(secs).into())
  } else {
    TagValue::F64(secs)
  }
}

/// Build a volume tag value: PreferredVolume / TrackVolume PrintConv
/// `sprintf("%.2f%%", $val * 100)` (QuickTime.pm:1402, 1549); -n yields the
/// raw post-ValueConv float ([`TagValue::F64`], `$val / 256`).
#[cfg(feature = "alloc")]
fn volume_value(val: f64, print_conv: bool) -> crate::value::TagValue {
  use crate::value::TagValue;
  if print_conv {
    TagValue::Str(format!("{:.2}%", val * 100.0).into())
  } else {
    TagValue::F64(val)
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project QuickTime metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain. SP1 populates
  /// the `MediaInfo` basics (duration / dimensions / created / track kinds)
  /// via [`MediaMetadata::from_quicktime`](crate::metadata::MediaMetadata::from_quicktime);
  /// **SP3** additionally fills [`GpsLocation`](crate::metadata::GpsLocation)
  /// from the FIRST embedded timed-metadata GPS fix. Identical to the
  /// [`Meta::media_metadata`] convenience accessor (the single source of
  /// truth for the QuickTime projection). Camera / lens / capture stay `None`
  /// for SP2+ and the embedded-Exif hop to fill.
  fn project(&self) -> crate::metadata::MediaMetadata {
    self.media_metadata()
  }
}

/// Build the `Track<N>` family-1 group string (QuickTime.pm:1427 `1 =>
/// 'Track#'`). One small allocation per track at serialize time.
#[cfg(feature = "alloc")]
fn alloc_track_group(n: usize) -> String {
  let mut s = String::with_capacity(8);
  s.push_str("Track");
  // `n` is a small track index; format without an extra alloc.
  s.push_str(&n.to_string());
  s
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Drive a `Meta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for `mode` and return the
  /// resulting [`TagMap`](crate::tagmap::TagMap) — the production sink path
  /// (the inherent `serialize_tags` was retired in favor of `Taggable`).
  #[cfg(feature = "alloc")]
  fn emit_into_tagmap(meta: &Meta<'_>, mode: crate::emit::ConvMode) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(meta, crate::emit::EmitOptions::g1(mode, false), &mut w);
    w
  }

  /// `unpack("H*",$val)` (CAME/MUID ValueConv) → lower-case hex of every byte,
  /// high-nibble first; empty input → empty string.
  #[test]
  fn unpack_h_star_lowercase_hex() {
    assert_eq!(
      unpack_h_star(&[0x00, 0x11, 0xde, 0xad, 0xbe, 0xef]),
      "0011deadbeef"
    );
    assert_eq!(unpack_h_star(&[0xca, 0xfe, 0xf0, 0x0d]), "cafef00d");
    assert_eq!(unpack_h_star(&[]), "");
  }

  /// The GENERATED conv-less maps resolve only their verified-allowlist atoms
  /// (by 4cc / key) and reject everything else. The conv-BEARING `CAME`/`MUID`
  /// must NOT leak into the UserData map; the hand-dispatched Keys identity atoms
  /// (`make`/`com.android.capture.fps`/`samsung.android.utc_offset`, …) are
  /// EXPLICIT arms in [`apply_key_name`], NOT generated-map entries — so they too
  /// must be absent from the generated lookup (they still route through the same
  /// [`ilst_data_convless`] cascade, just by hand).
  #[test]
  fn convless_lookup_covers_only_verified_atoms() {
    assert_eq!(userdata_convless_name(b"GoPr"), Some("GoProType"));
    assert_eq!(userdata_convless_name(b"LENS"), Some("LensSerialNumber"));
    assert_eq!(userdata_convless_name(b"FOV\0"), Some("FieldOfView"));
    assert_eq!(userdata_convless_name(b"\xa9mal"), Some("MakerURL"));
    assert_eq!(userdata_convless_name(b"\xa9gpt"), Some("CameraPitch"));
    assert_eq!(userdata_convless_name(b"\xa9gyw"), Some("CameraYaw"));
    assert_eq!(userdata_convless_name(b"\xa9grl"), Some("CameraRoll"));
    // The code-valued atoms are HAND-ported, NEVER in the conv-less map.
    assert_eq!(userdata_convless_name(b"CAME"), None);
    assert_eq!(userdata_convless_name(b"MUID"), None);
    assert_eq!(userdata_convless_name(b"manu"), None);

    // The GENERATED Keys map covers only the `direction.*` allowlist.
    assert_eq!(
      keys_convless_name("direction.facing"),
      Some("CameraDirection")
    );
    assert_eq!(keys_convless_name("direction.motion"), Some("CameraMotion"));
    // The hand-dispatched explicit-arm keys are NOT in the generated map (they
    // route through `ilst_data_convless` via their own match arms instead).
    assert_eq!(keys_convless_name("com.android.capture.fps"), None);
    assert_eq!(keys_convless_name("samsung.android.utc_offset"), None);
    assert_eq!(keys_convless_name("make"), None);
  }

  /// The rerouted conv-less identity keys (`make` / `com.android.capture.fps`)
  /// now run through [`ilst_data_convless`] like any other conv-less Keys atom,
  /// so EVERY format flag is faithful — a `Make` with a NUMERIC flag emits a
  /// number (`U64`), an `AndroidCaptureFPS` with a STRING flag emits the string,
  /// a multi-float emits the space-joined string — matching the bundled-13.59
  /// oracle for the crafted `QuickTime_sp2_keys_*` fixtures. (The OLD per-key
  /// typed paths required one specific flavor and dropped/truncated the rest.)
  #[test]
  fn rerouted_keys_follow_convless_cascade_on_every_flag() {
    use crate::metadata::QuickTimeKeys;
    use crate::value::TagValue;

    // `make` with a NUMERIC flag (0x16 int16u 0x012c = 300) ⇒ U64(300), emitted
    // under tag `Make` in walk order (bundled: `Keys:Make` = the number 300).
    let mut k = QuickTimeKeys::new();
    assert!(apply_key_name(
      "make",
      &IlstData {
        flags: 0x16,
        bytes: vec![0x01, 0x2c],
      },
      &mut k,
    ));
    assert_eq!(
      k.convless(),
      [("Make".into(), TagValue::U64(300))],
      "numeric-flag Make must emit the number, not be dropped"
    );

    // `com.android.capture.fps` with a STRING flag (0x01 "29.97") ⇒ Str.
    let mut k = QuickTimeKeys::new();
    assert!(apply_key_name(
      "com.android.capture.fps",
      &IlstData {
        flags: 0x01,
        bytes: b"29.97".to_vec(),
      },
      &mut k,
    ));
    assert_eq!(
      k.convless(),
      [("AndroidCaptureFPS".into(), TagValue::Str("29.97".into()))],
      "string-flag AndroidCaptureFPS must emit the string, not be dropped"
    );

    // `com.android.capture.fps` SHORT float (0x17, 2 bytes) ⇒ "" (empty string).
    let mut k = QuickTimeKeys::new();
    apply_key_name(
      "com.android.capture.fps",
      &IlstData {
        flags: 0x17,
        bytes: vec![0x3f, 0xc0],
      },
      &mut k,
    );
    assert_eq!(
      k.convless(),
      [("AndroidCaptureFPS".into(), TagValue::Str("".into()))]
    );

    // `com.android.capture.fps` MULTI float (0x17, two floats 1.5 2.5) ⇒
    // "1.5 2.5" (space-joined; the OLD typed path read only the first element).
    let mut k = QuickTimeKeys::new();
    let mut bytes = 1.5_f32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&2.5_f32.to_be_bytes());
    apply_key_name(
      "com.android.capture.fps",
      &IlstData { flags: 0x17, bytes },
      &mut k,
    );
    assert_eq!(
      k.convless(),
      [("AndroidCaptureFPS".into(), TagValue::Str("1.5 2.5".into()))]
    );
  }

  /// After rerouting Make/Model/Software through the conv-less cascade, the
  /// domain-layer accessors `make()`/`model()`/`software()` are backed by a
  /// `convless` scan and STILL return the string value when the `data` atom is a
  /// string (the iOS camera case the `CameraInfo` projection reads). A
  /// non-string flag stores a non-`Str` value ⇒ the accessor yields `None`
  /// (faithful to the typed-string source it replaced, which also dropped it).
  #[test]
  fn keys_make_model_software_accessors_back_by_convless_scan() {
    use crate::metadata::QuickTimeKeys;
    use crate::value::TagValue;

    let mut k = QuickTimeKeys::new();
    for (key, val) in [
      ("make", "Apple Computer"),
      ("model", "iPhone 15 Pro Max"),
      ("software", "17.3"),
    ] {
      assert!(apply_key_name(
        key,
        &IlstData {
          flags: 0x01,
          bytes: val.as_bytes().to_vec(),
        },
        &mut k,
      ));
    }
    assert_eq!(k.make(), Some("Apple Computer"));
    assert_eq!(k.model(), Some("iPhone 15 Pro Max"));
    assert_eq!(k.software(), Some("17.3"));

    // A numeric-flag Make stores U64, so the string accessor returns None even
    // though the `Make` tag IS emitted (as a number) via `convless()`.
    let mut k = QuickTimeKeys::new();
    apply_key_name(
      "make",
      &IlstData {
        flags: 0x16,
        bytes: vec![0x01, 0x2c],
      },
      &mut k,
    );
    assert_eq!(k.make(), None);
    assert_eq!(k.convless(), [("Make".into(), TagValue::U64(300))]);
  }

  /// `ilst_data_convless` implements the FULL conv-less `data`-atom cascade
  /// (QuickTime.pm:10396-10416): a `%stringEncoding` flag ⇒ a string; else a
  /// `QuickTimeFormat` numeric flag ⇒ a number; else (no usable format, no
  /// ValueConv) ⇒ the binary scalar-ref placeholder. EVERY branch yields a value
  /// (the binary branch is the catch-all). Pins all three against the byte forms
  /// the bundled 13.59 oracle produced for the crafted Keys fixtures.
  #[test]
  fn ilst_data_convless_string_numeric_binary_cascade() {
    use crate::value::TagValue;
    // 1. STRING (flag 0x01 UTF-8) ⇒ TagValue::Str.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x01,
        bytes: b"front".to_vec(),
      }),
      TagValue::Str("front".into())
    );
    // 2a. NUMERIC unsigned (0x16, len 2 = 0x012c) ⇒ TagValue::U64(300) — the
    //     bundled oracle emits the JSON number `300`.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x16,
        bytes: vec![0x01, 0x2c],
      }),
      TagValue::U64(300)
    );
    // 2b. NUMERIC unsigned (0x16, len 4) ⇒ TagValue::U64.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x16,
        bytes: vec![0x00, 0x00, 0x04, 0xd2],
      }),
      TagValue::U64(1234)
    );
    // 2c. NUMERIC signed (0x15, len 2 = 0xffff = -1) ⇒ TagValue::I64(-1).
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x15,
        bytes: vec![0xff, 0xff],
      }),
      TagValue::I64(-1)
    );
    // 2d. NUMERIC float (0x17) / double (0x18) ⇒ TagValue::F64.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x17,
        bytes: 29.97_f32.to_be_bytes().to_vec(),
      }),
      TagValue::F64(f64::from(29.97_f32))
    );
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x18,
        bytes: 1.5_f64.to_be_bytes().to_vec(),
      }),
      TagValue::F64(1.5)
    );
    // 2e. `0x00` with len 1 / 2 IS int8u / int16u (QuickTimeFormat 9568).
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x00,
        bytes: vec![0x2a],
      }),
      TagValue::U64(42)
    );
    // 3a. BINARY: flag `0x00` with len 3 ⇒ no QuickTimeFormat ⇒ binary scalar
    //     ref ⇒ TagValue::Bytes (renders `(Binary data 3 bytes, ...)`). This is
    //     the exact byte form the bundled oracle produced.
    let bin = ilst_data_convless(&IlstData {
      flags: 0x00,
      bytes: vec![0x01, 0x02, 0x03],
    });
    assert_eq!(bin, TagValue::Bytes(vec![0x01, 0x02, 0x03]));
    // 3b. BINARY: JPEG flag `0x0d` (not a string, not a numeric format).
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x0d,
        bytes: vec![0xff, 0xd8, 0xff],
      }),
      TagValue::Bytes(vec![0xff, 0xd8, 0xff])
    );
    // 3c. BINARY: an unsigned-int flag (0x16) with a non-{1,2,4,8} length (3) ⇒
    //     QuickTimeFormat returns undef ⇒ the binary branch (NOT a number).
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x16,
        bytes: vec![0x01, 0x02, 0x03],
      }),
      TagValue::Bytes(vec![0x01, 0x02, 0x03])
    );
    // 3d. BINARY: a high-bit flags word that merely ENDS in a known flag byte is
    //     neither string nor numeric (full-word compare) ⇒ binary.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x0100_0016,
        bytes: vec![0x00, 0x01],
      }),
      TagValue::Bytes(vec![0x00, 0x01])
    );
  }

  /// `read_be_floats` mirrors `ReadValue` with an undef count (ExifTool.pm:
  /// 6296-6331) for the conv-less `0x17` float / `0x18` double path, where
  /// `QuickTimeFormat` is NOT length-gated: a payload shorter than one element
  /// is the empty scalar (`""`), one element is a single `F64` number, and
  /// several are a space-joined `perl_num` string. A trailing partial element is
  /// ignored (`int(size/len)` truncation). The byte forms + emitted values are
  /// exactly what the bundled 13.59 oracle produced for the crafted float/double
  /// fixtures (`""`, `1.5`, `"1.5 2.5"`).
  #[test]
  fn read_be_floats_mirrors_readvalue_count_undef() {
    use crate::value::TagValue;
    // SHORT: flag 0x17 (float, elem 4) with only 2 bytes ⇒ ReadValue `return ''`
    // ⇒ empty string (NOT the binary placeholder, NOT dropped).
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x17,
        bytes: vec![0x3f, 0xc0],
      }),
      TagValue::Str("".into())
    );
    // SINGLE: one big-endian float 1.5 ⇒ a single F64 number.
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x17,
        bytes: 1.5_f32.to_be_bytes().to_vec(),
      }),
      TagValue::F64(1.5)
    );
    // MULTI float: two floats 1.5, 2.5 ⇒ "1.5 2.5" (space-joined string).
    let mut two_floats = 1.5_f32.to_be_bytes().to_vec();
    two_floats.extend_from_slice(&2.5_f32.to_be_bytes());
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x17,
        bytes: two_floats,
      }),
      TagValue::Str("1.5 2.5".into())
    );
    // MULTI double: two doubles 1.5, 2.5 (elem 8) ⇒ "1.5 2.5".
    let mut two_doubles = 1.5_f64.to_be_bytes().to_vec();
    two_doubles.extend_from_slice(&2.5_f64.to_be_bytes());
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x18,
        bytes: two_doubles,
      }),
      TagValue::Str("1.5 2.5".into())
    );
    // TRAILING PARTIAL: float 1.5 + 2 extra bytes (len 6) ⇒ int(6/4)=1 value ⇒
    // F64(1.5); the partial trailing element is ignored, as `ReadValue` truncates.
    let mut one_and_partial = 1.5_f32.to_be_bytes().to_vec();
    one_and_partial.extend_from_slice(&[0xff, 0xff]);
    assert_eq!(
      ilst_data_convless(&IlstData {
        flags: 0x17,
        bytes: one_and_partial,
      }),
      TagValue::F64(1.5)
    );
  }

  /// `ilst_data_valueconv_str` extracts the pre-ValueConv `$val` that a
  /// ValueConv-bearing Keys atom (creationdate/location) feeds to its conv
  /// (QuickTime.pm:10396-10416): a string flag → the decoded string; a numeric
  /// flag → the `ReadValue` number stringified; any OTHER flag → the RAW bytes
  /// (lossy) — NEVER the binary placeholder (that branch needs no ValueConv).
  /// Always returns a value.
  #[test]
  fn ilst_data_valueconv_str_is_the_pre_valueconv_scalar() {
    // string flag (0x01) → the decoded string.
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x01,
        bytes: b"2024".to_vec(),
      }),
      "2024"
    );
    // numeric unsigned (0x16, 300) → "300" (re-numberifies via the downstream gate).
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x16,
        bytes: vec![0x01, 0x2c],
      }),
      "300"
    );
    // numeric signed (0x15, 0xffff = -1) → "-1".
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x15,
        bytes: vec![0xff, 0xff],
      }),
      "-1"
    );
    // float (0x17, 1.5) → "1.5".
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x17,
        bytes: 1.5_f32.to_be_bytes().to_vec(),
      }),
      "1.5"
    );
    // binary/no-format flag (0x00, len 12) → the raw bytes, lossy (fed to the
    // ValueConv verbatim — e.g. an ISO6709 string carried under a binary flag).
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x00,
        bytes: b"+12.3+045.6/".to_vec(),
      }),
      "+12.3+045.6/"
    );
    // a numeric flag with a non-{1,2,4,8} length yields NO format ⇒ raw bytes.
    assert_eq!(
      ilst_data_valueconv_str(&IlstData {
        flags: 0x16,
        bytes: vec![0x41, 0x42, 0x43],
      }),
      "ABC"
    );
  }

  /// `ilst_data_string` decodes ONLY the `%stringEncoding` flags (the FULL word
  /// ∈ {1,2,3,4,5}, QuickTime.pm:357-363). A non-string flag (binary `0x00`,
  /// JPEG `0x0d`, int `0x16`, float `0x17`, double `0x18`, or a high-bit word
  /// like `0x01000001`) is NOT string-decoded by ExifTool, so it returns `None`
  /// and the caller drops the (string-typed) tag rather than mis-rendering the
  /// bytes as lossy UTF-8.
  #[test]
  fn ilst_data_string_matches_string_encoding_flags() {
    let utf8 = IlstData {
      flags: 0x01,
      bytes: b"front".to_vec(),
    };
    assert_eq!(ilst_data_string(&utf8).as_deref(), Some("front"));
    let utf8_sort = IlstData {
      flags: 0x04,
      bytes: b"front".to_vec(),
    };
    assert_eq!(ilst_data_string(&utf8_sort).as_deref(), Some("front"));
    let utf16 = IlstData {
      flags: 0x02,
      bytes: vec![0x00, 0x66, 0x00, 0x6f, 0x00, 0x6f], // "foo" UTF-16BE
    };
    assert_eq!(ilst_data_string(&utf16).as_deref(), Some("foo"));
    // Trailing NUL stripped (QuickTime.pm:10398-10399).
    let utf8_nul = IlstData {
      flags: 0x01,
      bytes: b"front\0".to_vec(),
    };
    assert_eq!(ilst_data_string(&utf8_nul).as_deref(), Some("front"));
    // Non-string flags ⇒ None (not rendered as UTF-8 text).
    for flag in [
      0x00u32,
      0x0d,
      0x0e,
      0x15,
      0x16,
      0x17,
      0x18,
      0x1b,
      0x0100_0001,
    ] {
      assert_eq!(
        ilst_data_string(&IlstData {
          flags: flag,
          bytes: b"front".to_vec(),
        }),
        None,
        "flag {flag:#x} is not a %stringEncoding key and must not string-decode"
      );
    }
  }

  /// The international-text loop SKIPS empty entries and CONTINUES to later ones
  /// (QuickTime.pm:10483 `next if not $len and $pos`), it does NOT bail. So an
  /// empty first entry followed by a real one yields the real one; an only-empty
  /// (or too-short-for-a-second-header) payload yields no value. Verified vs
  /// bundled 13.59 (the crafted `QuickTime_sp2_itext_empty_*` fixtures).
  #[test]
  fn decode_itext_first_skips_empty_and_continues() {
    // Only entry is empty (len=0) ⇒ no value (next header would overrun).
    assert_eq!(decode_itext_first(&[0x00, 0x00, 0x00, 0x00]), None);
    // Empty header + only 2 trailing bytes ⇒ no room for a second 4-byte header
    // (`pos=4`, `pos+4=8 > size=6`) ⇒ no value.
    assert_eq!(
      decode_itext_first(&[0x00, 0x00, 0x00, 0x00, b'h', b'i']),
      None
    );
    // Empty first entry FOLLOWED BY a valid (len=2, lang=0, "Hi") entry ⇒ the
    // empty one is skipped and the later one is returned (the Finding-2 fix; the
    // pre-fix code bailed on the empty first entry and returned None).
    assert_eq!(
      decode_itext_first(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, b'H', b'i']).as_deref(),
      Some("Hi")
    );
    // Two empty entries then a valid one ⇒ still reaches the valid one.
    assert_eq!(
      decode_itext_first(&[
        0x00, 0x00, 0x00, 0x00, // empty entry 1
        0x00, 0x00, 0x00, 0x00, // empty entry 2
        0x00, 0x03, 0x00, 0x00, b'a', b'b', b'c', // "abc"
      ])
      .as_deref(),
      Some("abc")
    );
    // A lone non-empty entry (len=2, lang=0, "Hi") decodes directly.
    assert_eq!(
      decode_itext_first(&[0x00, 0x02, 0x00, 0x00, b'H', b'i']).as_deref(),
      Some("Hi")
    );
    // len-overrun retry: a `len` that includes the 4 header bytes (len=6 for a
    // 2-byte "Hi") is accepted via the `$len -= 4` path.
    assert_eq!(
      decode_itext_first(&[0x00, 0x06, 0x00, 0x00, b'H', b'i']).as_deref(),
      Some("Hi")
    );
  }

  /// `ConvertISO6709` has NO `else` branch: an undecodable string is returned
  /// UNCHANGED, so the GPS tag is still emitted. `parse_iso6709` must surface
  /// this as a raw [`QuickTimeGps`] (verbatim `value_conv`, no numeric coords),
  /// and `print_gps_coordinates` must faithfully numify the tokens to `0` —
  /// matching the bundled-13.59 oracle for `©xyz = "hello"`:
  ///   `-n` GPSCoordinates = `hello`;
  ///   `-j` GPSCoordinates = `0 deg 0' 0.00" N, `.
  #[test]
  fn parse_iso6709_passes_through_undecodable_string() {
    // RAW pass-through: the tag is still produced, but with no numeric coords.
    let gps = parse_iso6709("hello");
    assert_eq!(gps.value_conv(), "hello");
    assert_eq!(gps.coords(), None);
    assert_eq!(gps.latitude(), None);
    assert_eq!(gps.longitude(), None);
    assert_eq!(gps.altitude_m(), None);

    // `-n` (ValueConv) = the raw string verbatim.
    assert_eq!(
      gps_coordinates_value(&gps, false),
      crate::value::TagValue::Str("hello".into())
    );
    // `-j` (PrintConv) = `PrintGPSCoordinates("hello")` = ToDMS-of-0 latitude
    // (non-numeric token numifies to 0) + an EMPTY longitude (the missing
    // `$v[1]` is `undef`, which `ToDMS` returns unchanged → empty string),
    // joined by the literal `, ` — EXACT bundled-13.59 oracle output.
    assert_eq!(print_gps_coordinates("hello"), "0 deg 0' 0.00\" N, ");
    assert_eq!(
      gps_coordinates_value(&gps, true),
      crate::value::TagValue::Str("0 deg 0' 0.00\" N, ".into())
    );

    // The decoded happy path is unchanged: a real ISO 6709 string still yields
    // numeric coords and the full DMS PrintConv (the existing fixture golden).
    let ok = parse_iso6709("+37.3318-122.0312+010.500/");
    assert_eq!(ok.value_conv(), "37.3318 -122.0312 10.5");
    assert_eq!(ok.coords(), Some((37.3318, -122.0312, Some(10.5))));
    assert_eq!(
      print_gps_coordinates(ok.value_conv()),
      "37 deg 19' 54.48\" N, 122 deg 1' 52.32\" W, 10.5 m Above Sea Level"
    );
  }

  #[test]
  fn print_gps_below_sea_altitude_uses_perl_numeric_negation() {
    // R2 [medium]: Perl `-$v[2]` (the below-sea branch, QuickTime.pm:8957-8971)
    // NUMIFIES the token then negates then stringifies — NOT a string-strip of
    // the leading `-`. For a decimal token both agree, but a non-decimal /
    // exponent-form token (reachable only on the raw-passthrough path) must
    // yield the numified value: `-1e3` → `1000`, not `1e3`. The lat/lon tokens
    // (`foo`/`bar`) numify to 0 (ToDMS-of-0, as the badgps fixture pins).
    assert_eq!(
      print_gps_coordinates("foo bar -1e3"),
      "0 deg 0' 0.00\" N, 0 deg 0' 0.00\" E, 1000 m Below Sea Level"
    );
    assert!(!print_gps_coordinates("foo bar -1e3").contains("1e3"));
    // Decimal below-sea is unchanged (numify+negate == sign-strip there).
    assert!(print_gps_coordinates("12.5 13.5 -35.5").ends_with("35.5 m Below Sea Level"));
  }

  /// Codex [medium] #1: the `ConvertISO6709` DECIMAL form builds its ValueConv
  /// from `($1+0)`/`($2+0)`/`($3+0)` — Perl NUMIFIES each matched token to an
  /// f64 then stringifies (~15 significant digits), so a token carrying more
  /// fractional digits than a double holds is ROUNDED, not preserved verbatim.
  /// Oracle (bundled 13.59, `©xyz` = the long-fractional decimal, `-n`):
  ///   `12.1234567890123 -34.9876543210988 10.1234567890123`.
  /// Mirrors `QuickTime_sp2_iso6709long.mov`.
  #[test]
  fn iso6709_decimal_numifies_long_fraction_to_f64() {
    let gps =
      parse_iso6709("+12.123456789012345678901-034.9876543210987654321+010.123456789012345/");
    // The ValueConv (`-n`) is the f64-rounded numification, NOT the 21-digit
    // verbatim string the pre-fix string-normalizer would have kept.
    assert_eq!(
      gps.value_conv(),
      "12.1234567890123 -34.9876543210988 10.1234567890123"
    );
    assert!(!gps.value_conv().contains("123456789012345678901"));
    // Numeric coords still decode (full-precision f64 from the raw substrings).
    let (lat, lon, alt) = gps.coords().expect("decimal form decodes");
    assert!((lat - 12.123_456_789_012_345_678_901).abs() < 1e-9);
    assert!((lon + 34.987_654_321_098_765_432_1).abs() < 1e-9);
    assert!((alt.expect("alt") - 10.123_456_789_012_345).abs() < 1e-9);
    // The `-j` PrintConv matches the bundled oracle exactly.
    assert_eq!(
      print_gps_coordinates(gps.value_conv()),
      "12 deg 7' 24.44\" N, 34 deg 59' 15.56\" W, 10.1234567890123 m Above Sea Level"
    );

    // Negative-zero faithfulness: Perl `($1+0)` / `"$lat"` normalize `-0.0` to
    // `0` (default NV stringify has no negative zero), e.g. `-00-000/` → `0 0`
    // (bundled oracle), NOT `-0 0`. `perl_num` collapses the `format_g` `-0`.
    assert_eq!(parse_iso6709("-00-000/").value_conv(), "0 0");
    assert_eq!(parse_iso6709("-0.0-0.0/").value_conv(), "0 0");
  }

  /// Codex [medium] #2: a malformed `©xyz` whose tokens are non-finite
  /// (`inf inf -inf`) reaches `ConvertISO6709`, which returns it UNCHANGED (no
  /// form matches). Under `-n` the raw lowercase string passes through verbatim;
  /// under `-j` `PrintGPSCoordinates`/`GPS::ToDMS` + Perl numeric stringify
  /// produce Perl's TITLECASE `Inf`/`-Inf`/`NaN`. Oracle (bundled 13.59):
  ///   `-n`: `inf inf -inf`;
  ///   `-j`: `Inf deg NaN' NaN" N, Inf deg NaN' NaN" E, Inf m Below Sea Level`.
  /// Mirrors `QuickTime_sp2_infgps.mov`.
  #[test]
  fn print_gps_non_finite_tokens_use_perl_inf_nan_casing() {
    // Raw pass-through: no numeric coords, verbatim (lowercase) ValueConv.
    let gps = parse_iso6709("inf inf -inf");
    assert_eq!(gps.value_conv(), "inf inf -inf");
    assert_eq!(gps.coords(), None);
    assert_eq!(
      gps_coordinates_value(&gps, false),
      crate::value::TagValue::Str("inf inf -inf".into())
    );
    // PrintConv: titlecase Inf/NaN; the `-inf` altitude is `-(-Inf)` = `Inf` in
    // the Below-Sea-Level branch.
    assert_eq!(
      print_gps_coordinates("inf inf -inf"),
      "Inf deg NaN' NaN\" N, Inf deg NaN' NaN\" E, Inf m Below Sea Level"
    );
    assert_eq!(
      gps_coordinates_value(&gps, true),
      crate::value::TagValue::Str(
        "Inf deg NaN' NaN\" N, Inf deg NaN' NaN\" E, Inf m Below Sea Level".into()
      )
    );
    // `nan` latitude/longitude → `NaN deg NaN' NaN"`; a `nan` altitude is NOT
    // numified in the Above branch (it prints `$v[2]` verbatim → lowercase
    // `nan`), and `nan < 0` is false so it never enters the Below branch.
    assert_eq!(
      print_gps_coordinates("nan nan nan"),
      "NaN deg NaN' NaN\" N, NaN deg NaN' NaN\" E, nan m Above Sea Level"
    );
    // A signed mix: `-inf` lat keeps magnitude `Inf` with the S ref; `-inf` lon
    // → `Inf … W`.
    assert_eq!(
      print_gps_coordinates("-inf -inf nan"),
      "Inf deg NaN' NaN\" S, Inf deg NaN' NaN\" W, nan m Above Sea Level"
    );
    // `perl_num` titlecases a bare non-finite (the Below-altitude `-$v[2]`
    // path and the DM/DMS computed-coord path both route through it).
    assert_eq!(perl_num(f64::INFINITY), "Inf");
    assert_eq!(perl_num(f64::NEG_INFINITY), "-Inf");
    assert_eq!(perl_num(f64::NAN), "NaN");
  }

  /// The `manu`/`modl` RawConv `s/^\0{4}..//s; s/\0.*//`: a value starting
  /// with 4 NUL bytes drops those 4 plus the next 2 (the Canon 6-byte prefix),
  /// then truncates at the first NUL. A value NOT starting with 4 NULs keeps its
  /// leading bytes (Samsung `SAMSUNG\0` → `SAMSUNG`). An all-stripped value is
  /// the empty string (still emitted by ExifTool). Verified vs bundled 13.59.
  #[test]
  fn decode_manu_modl_strips_canon_prefix_then_truncates() {
    // Canon SX280: 6-byte prefix `00 00 00 00 15 c7` then the value + NUL.
    assert_eq!(decode_manu_modl(b"\0\0\0\0\x15\xc7Canon\0"), "Canon");
    assert_eq!(
      decode_manu_modl(b"\0\0\0\0\x15\xc7Canon PowerShot SX280 HS\0junk"),
      "Canon PowerShot SX280 HS"
    );
    // Samsung GT-S8530: no 4-NUL prefix, just the NUL-terminated value.
    assert_eq!(decode_manu_modl(b"SAMSUNG\0"), "SAMSUNG");
    // Exactly the 6-byte prefix, nothing after ⇒ empty string (still a value).
    assert_eq!(decode_manu_modl(b"\0\0\0\0XY"), "");
    // Fewer than 6 bytes with a leading-NUL run is NOT stripped (the `..` needs
    // 2 more bytes); the `s/\0.*//` then truncates at the first NUL ⇒ empty.
    assert_eq!(decode_manu_modl(b"\0\0\0\0"), "");
  }

  /// The plain (non-international-text) `udta` string atoms use the table
  /// `FORMAT => 'string'` reading — NUL-terminated, truncating any trailing
  /// data after the first NUL (verified vs bundled for `slno`/`CNCV`/etc.).
  #[test]
  fn decode_qt_string_truncates_at_first_nul() {
    assert_eq!(decode_qt_string(b"SN123\0GARBAGE"), "SN123");
    assert_eq!(decode_qt_string(b"CCV1\0\0\0"), "CCV1");
    assert_eq!(decode_qt_string(b"NoNul"), "NoNul");
  }

  /// ExifTool's duplicate-tag priority rule for the multi-source `udta` identity
  /// fields (verified vs bundled 13.59): a priority-1 (normal) source ALWAYS
  /// overrides; a priority-0 (`Avoid`) source only fills an empty slot — so
  /// among `Avoid` atoms the FIRST wins, among normal atoms the LAST wins, and a
  /// normal atom beats an `Avoid` one regardless of file order.
  #[test]
  fn user_data_priority_resolution_matches_exiftool() {
    use crate::metadata::QuickTimeUserData;

    // Two Avoid Model atoms (cmnm then CNMN, both priority 0): FIRST wins.
    let mut ud = QuickTimeUserData::new();
    ud.set_model("cmnm_val".into(), 0);
    ud.set_model("CNMN_val".into(), 0);
    assert_eq!(ud.model(), Some("cmnm_val"));

    // A later non-Avoid model (the copyright-symbol `mod`, priority 1) WINS over
    // the earlier Avoid one.
    ud.set_model("CR_mod".into(), 1);
    assert_eq!(ud.model(), Some("CR_mod"));

    // A non-Avoid source set FIRST is still kept when a later Avoid arrives.
    let mut ud2 = QuickTimeUserData::new();
    ud2.set_make("CR_mak".into(), 1); // copyright-symbol `mak`
    ud2.set_make("manu_val".into(), 0); // Avoid `manu`
    assert_eq!(ud2.make(), Some("CR_mak"));

    // Two normal (priority-1) FirmwareVersion sources (CNFV then info): LAST.
    let mut ud3 = QuickTimeUserData::new();
    ud3.set_firmware_version("CNFV_val".into(), 1);
    ud3.set_firmware_version("info_val".into(), 1);
    assert_eq!(ud3.firmware_version(), Some("info_val"));
    // A trailing Avoid FIRM does not displace the priority-1 winner.
    ud3.set_firmware_version("FIRM_val".into(), 0);
    assert_eq!(ud3.firmware_version(), Some("info_val"));
  }

  /// Build a 4-byte-size + type atom around `body`.
  fn atom(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let size = (body.len() + 8) as u32;
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(t);
    v.extend_from_slice(body);
    v
  }

  /// Write `src` at `off` (the test-fixture builders' `buf[off..off+N] =`
  /// shape) without raw slice-indexing; panics on an out-of-range fixture,
  /// matching the previous `[..]` write.
  fn wr(buf: &mut [u8], off: usize, src: &[u8]) {
    buf
      .get_mut(off..off + src.len())
      .unwrap()
      .copy_from_slice(src);
  }

  /// Write a single byte at `i` (the `buf[i] = b` fixture shape).
  fn wb(buf: &mut [u8], i: usize, b: u8) {
    *buf.get_mut(i).unwrap() = b;
  }

  /// Unwrap a [`HeaderOutcome::Atom`] in tests.
  fn read_atom(data: &[u8], pos: usize, top_level: bool) -> (AtomHeader, usize) {
    match read_atom_header(data, pos, top_level).expect("header") {
      HeaderOutcome::Atom(h, next) => (h, next),
      HeaderOutcome::Terminator => panic!("unexpected terminator"),
      HeaderOutcome::ExtendsToEof { .. } => panic!("unexpected extends-to-eof"),
      HeaderOutcome::TruncatedAtom { .. } => panic!("unexpected truncated atom"),
      HeaderOutcome::Malformed { .. } => panic!("unexpected malformed header"),
    }
  }
  #[test]
  fn reads_simple_atom_header() {
    let data = atom(b"ftyp", b"qt  \0\0\0\0");
    let (h, next) = read_atom(&data, 0, true);
    assert_eq!(&h.atom_type, b"ftyp");
    assert_eq!(h.payload_start, 8);
    assert_eq!(next, data.len());
  }

  #[test]
  fn extended_64bit_size() {
    // size==1, then 64-bit size = 8 (header) + 8 (ext) + 4 (payload) = 20.
    let mut data = 1u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"mdat");
    data.extend_from_slice(&20u64.to_be_bytes());
    data.extend_from_slice(b"DATA");
    let (h, next) = read_atom(&data, 0, true);
    assert_eq!(&h.atom_type, b"mdat");
    assert_eq!(h.payload_start, 16);
    assert_eq!(h.payload_end, 20);
    assert_eq!(next, 20);
  }

  /// Build a `size == 1` 64-bit extended-size atom header with `total` as the
  /// declared 64-bit size (includes the 16-byte header), plus `body` bytes.
  fn ext_atom64(t: &[u8; 4], total: u64, body: &[u8]) -> Vec<u8> {
    let mut v = 1u32.to_be_bytes().to_vec();
    v.extend_from_slice(t);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(body);
    v
  }

  #[test]
  fn ext_size_above_int31_is_parsed_not_large_file_rejected() {
    // R12/F1: a `size == 1` 64-bit `mdat` whose declared total `> 0x7fffffff`
    // (here 0x8000_0010, hi==0, lo > 0x7fffffff) — the real >2GB shape. With
    // the DEFAULT `LargeFileSupport => 1` (ExifTool.pm:1167) this is PARSED,
    // NOT rejected. The 2GB payload overruns the tiny header buffer, so the
    // outcome is a `TruncatedAtom` carrying the FULL 64-bit declared payload
    // (`0x8000_0010 - 16 = 2147483648`) — never the old `Malformed
    // { "End of processing at large atom (LargeFileSupport not enabled)" }`.
    let data = ext_atom64(b"mdat", 0x8000_0010, &[]);
    match read_atom_header(&data, 0, true).expect("header") {
      HeaderOutcome::TruncatedAtom {
        atom_type,
        payload_start,
        declared_payload_len,
      } => {
        assert_eq!(&atom_type, b"mdat");
        assert_eq!(payload_start, 16);
        assert_eq!(declared_payload_len, 0x8000_0000); // 2147483648, full 64-bit
      }
      _ => panic!("expected TruncatedAtom for a >0x7fffffff 64-bit mdat (LFS=1 parses it)"),
    }
  }

  #[test]
  fn ext_size_high_word_set_is_parsed_not_large_file_rejected() {
    // R12/F1: a 64-bit `mdat` with `hi != 0` (here total 0x1_0000_0010 — a
    // genuinely >4GB atom). `hi == 1 <= 0x7fffffff`, so this is NOT the
    // `Invalid atom size` case; with default LargeFileSupport it is PARSED and
    // (overrunning the buffer) surfaces a `TruncatedAtom` carrying the full
    // 64-bit declared payload `0x1_0000_0010 - 16 = 4294967296`.
    let data = ext_atom64(b"mdat", 0x1_0000_0010, &[]);
    match read_atom_header(&data, 0, true).expect("header") {
      HeaderOutcome::TruncatedAtom {
        declared_payload_len,
        ..
      } => assert_eq!(declared_payload_len, 0x1_0000_0000), // 4294967296
      _ => panic!("expected TruncatedAtom for a hi!=0 64-bit mdat (LFS=1 parses it)"),
    }
  }

  #[test]
  fn ext_size_high_word_above_int31_is_invalid() {
    // R12/F1: the LONE truly-invalid 64-bit case (QuickTime.pm:10064-10066) —
    // the HIGH word alone exceeds 0x7fffffff. Bundled `$warnStr = 'Invalid atom
    // size'`. (This branch is unchanged by the fix; pinned to guard the edge.)
    let data = ext_atom64(b"mdat", 0xFFFF_FFFF_0000_0000, &[]);
    assert!(matches!(
      read_atom_header(&data, 0, true),
      Some(HeaderOutcome::Malformed {
        warning: "Invalid atom size"
      })
    ));
  }

  #[test]
  fn ext_size_64bit_atom_that_fits_advances_to_sibling() {
    // R12/F1: a fitting `size == 1` 64-bit `mdat` (declared total 24, 8-byte
    // payload) decodes as a NORMAL `Atom` and its `next` points at the trailing
    // sibling so the walk REACHES it. (The `> 0x7fffffff` fitting case can only
    // be proven against the oracle — a 2GB buffer is impractical in a unit
    // test — and is covered by the `QuickTime_mdat64_moov` golden.)
    let mut data = ext_atom64(b"mdat", 16 + 8, b"PAYLOAD!"); // 8-byte payload
    let sibling_at = data.len();
    data.extend_from_slice(&atom(b"moov", b"")); // trailing sibling
    let (h, next) = read_atom(&data, 0, true);
    assert_eq!(&h.atom_type, b"mdat");
    assert_eq!(next, sibling_at, "next must point at the trailing sibling");
    let (h2, _) = read_atom(&data, next, true);
    assert_eq!(&h2.atom_type, b"moov");
  }

  #[test]
  fn ext_size_64bit_mdat_walk_reaches_trailing_moov() {
    // R12/F1 end-to-end (small, fitting 64-bit `mdat`): ftyp + a `size == 1`
    // 64-bit `mdat` (fits) + a trailing `moov` with an `mvhd`. The walker MUST
    // skip the 64-bit `mdat` by its declared size and DECODE the trailing
    // `moov` — proving real >2GB videos (64-bit `mdat` before a trailing
    // `moov`) still yield duration/timescale/dates. Mirrors the
    // `QuickTime_mdat64_moov` golden.
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    // mvhd v0: TimeScale=1000 (offset 12), Duration=5000 (offset 16).
    let mut mvhd_payload = vec![0u8; 100];
    wr(&mut mvhd_payload, 12, &1000u32.to_be_bytes());
    wr(&mut mvhd_payload, 16, &5000u32.to_be_bytes());
    let moov = atom(b"moov", &atom(b"mvhd", &mvhd_payload));
    // 64-bit mdat: size==1, total = 16 + 32 (fits).
    let mdat = ext_atom64(b"mdat", 16 + 32, &[0xABu8; 32]);
    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("meta");
    // Walker reached the trailing moov ⇒ mvhd state present.
    assert_eq!(meta.qt.time_scale(), Some(1000));
    assert_eq!(meta.qt.movie_header_version(), Some(0));
    assert_eq!(meta.qt.duration_count(), Some(5000));
    // And the synthetic mdat tags reflect the 64-bit atom (size 32).
    assert_eq!(meta.qt.media_data_size(), Some(32));
  }

  #[test]
  fn ext_size_64bit_mdat_overrun_records_full_size_and_truncates() {
    // R12/F1 end-to-end (overrunning 64-bit `mdat`, the >2GB shape): ftyp + a
    // `size == 1` `mdat` declaring 0x8000_0010 in a tiny file. The walk records
    // the FULL 64-bit MediaDataSize (0x8000_0000 = 2147483648) and emits the
    // `Truncated 'mdat' data at offset …` warning — never the LargeFileSupport
    // rejection. Mirrors the `QuickTime_mdat64_large` golden.
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    let mdat = ext_atom64(b"mdat", 0x8000_0010, &[]);
    let mdat_offset = ftyp.len(); // header start of the mdat atom
    let mut data = ftyp;
    data.extend_from_slice(&mdat);

    let meta = parse_inner(&data, None).expect("meta");
    assert_eq!(meta.qt.media_data_size(), Some(2_147_483_648));
    assert_eq!(meta.qt.media_data_offset(), Some((mdat_offset + 16) as u64));
    assert_eq!(meta.file_type, "MOV");
    assert_eq!(
      meta.warning.as_deref(),
      Some(&format!("Truncated 'mdat' data at offset {mdat_offset:#x}")[..])
    );
  }

  #[test]
  fn top_level_zero_size_is_extends_to_eof_terminator() {
    // R4/F1: a TOP-LEVEL size-0 atom is an EXTENDS-TO-EOF terminator — its
    // payload is NOT processed (the walk stops). For `mdat` the caller still
    // records the synthetic size/offset from the carried `payload_start`.
    let mut data = 0u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"mdat");
    data.extend_from_slice(b"trailing bytes");
    match read_atom_header(&data, 0, true).expect("header") {
      HeaderOutcome::ExtendsToEof {
        atom_type,
        payload_start,
      } => {
        assert_eq!(&atom_type, b"mdat");
        assert_eq!(payload_start, 8);
        // size = EOF - payload_start = len - 8.
        assert_eq!(data.len() - payload_start, b"trailing bytes".len());
      }
      _ => panic!("expected ExtendsToEof for a top-level size-0 atom"),
    }
  }

  #[test]
  fn top_level_size0_moov_payload_not_decoded() {
    // R4/F1 end-to-end: ftyp + a top-level size-0 `moov` containing an `mvhd`.
    // ExifTool prints "extends to end of file" and STOPS — the `mvhd` is never
    // decoded — so ONLY the ftyp tags survive (no TimeScale/CreateDate/etc.).
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    // A real-looking mvhd payload (version 0, TimeScale=600 at offset 12).
    let mut mvhd_payload = vec![0u8; 100];
    wb(&mut mvhd_payload, 15, 0); // ts high bytes 0
    wb(&mut mvhd_payload, 12, 0);
    wb(&mut mvhd_payload, 13, 0);
    wb(&mut mvhd_payload, 14, 2);
    wb(&mut mvhd_payload, 15, 88); // TimeScale = 600
    let mvhd = atom(b"mvhd", &mvhd_payload);
    // size-0 moov: 4-byte size 0, type, then payload extends to EOF.
    let mut moov_zero = 0u32.to_be_bytes().to_vec();
    moov_zero.extend_from_slice(b"moov");
    moov_zero.extend_from_slice(&mvhd);
    let mut data = ftyp;
    data.extend_from_slice(&moov_zero);

    let meta = parse_inner(&data, None).expect("meta");
    // ftyp tags ARE present.
    assert_eq!(meta.qt.major_brand(), Some("qt  "));
    // The size-0 moov payload was NOT decoded: no mvhd-derived state.
    assert_eq!(meta.qt.time_scale(), None);
    assert_eq!(meta.qt.create_date(), None);
    assert_eq!(meta.qt.movie_header_version(), None);
    assert!(meta.qt.tracks().is_empty());
    // No `mdat-size`/`-offset` either (moov has no `-size` tag in the table).
    assert_eq!(meta.qt.media_data_size(), None);
    assert_eq!(meta.qt.media_data_offset(), None);
  }

  #[test]
  fn top_level_size0_mdat_records_size_offset_only() {
    // R4/F1: a top-level size-0 `mdat` DOES record the synthetic
    // `mdat-size`/`mdat-offset` (the lone table entry with those tags), then
    // stops.
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mut mdat_zero = 0u32.to_be_bytes().to_vec();
    mdat_zero.extend_from_slice(b"mdat");
    mdat_zero.extend_from_slice(b"PAYLOAD-BYTES");
    let mut data = ftyp.clone();
    let payload_start = data.len() + 8; // after ftyp + the mdat 8-byte header
    data.extend_from_slice(&mdat_zero);

    let meta = parse_inner(&data, None).expect("meta");
    assert_eq!(meta.qt.media_data_offset(), Some(payload_start as u64));
    assert_eq!(
      meta.qt.media_data_size(),
      Some(b"PAYLOAD-BYTES".len() as u64)
    );
  }

  #[test]
  fn contained_zero_size_is_terminator() {
    // F5: a CONTAINED size-0 atom is a terminator (no payload, walk stops).
    let mut data = 0u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"junk");
    data.extend_from_slice(b"more bytes");
    assert!(matches!(
      read_atom_header(&data, 0, false),
      Some(HeaderOutcome::Terminator)
    ));
  }

  #[test]
  fn nested_zero_size_terminates_without_consuming_sibling() {
    // F5 end-to-end: a moov containing a size-0 child followed by an mvhd —
    // the contained size-0 must TERMINATE the moov walk so the trailing
    // bytes are NOT (mis)read as an extends-to-EOF payload. Build moov with
    // [size-0 'free'] then a real mvhd; the walker must stop at the size-0
    // and decode nothing past it.
    let mut moov_body = 0u32.to_be_bytes().to_vec(); // size-0 atom
    moov_body.extend_from_slice(b"free");
    // a would-be mvhd after the terminator (must be ignored)
    let mut mvhd_payload = vec![0u8; 100];
    wb(&mut mvhd_payload, 0, 0); // version 0
    let mvhd = atom(b"mvhd", &mvhd_payload);
    moov_body.extend_from_slice(&mvhd);
    let mut decoded_mvhd = false;
    let mut warn = None;
    walk_atoms(0, &moov_body, 0, moov_body.len(), &mut warn, |a, _, _| {
      if &a.atom_type == b"mvhd" {
        decoded_mvhd = true;
      }
    });
    assert!(
      !decoded_mvhd,
      "contained size-0 must terminate the walk before the trailing mvhd"
    );
  }

  #[test]
  fn invalid_small_size_is_malformed_not_none() {
    // R8/F1: a size in 2..=7 is `Invalid atom size` (QuickTime.pm:10058). The
    // 8-byte tag/size header WAS read, so `read_atom_header` surfaces a
    // `Malformed` outcome carrying the bundled warning — NOT `None`. (Before
    // R8 this returned `None`, which made `parse_inner` reject the file
    // outright; bundled instead `SetFileType`s then warns.)
    let data = vec![0, 0, 0, 4, b'j', b'u', b'n', b'k'];
    assert!(matches!(
      read_atom_header(&data, 0, true),
      Some(HeaderOutcome::Malformed {
        warning: "Invalid atom size"
      })
    ));
    // A header shorter than 8 bytes still yields `None` (QuickTime.pm:9966
    // `$raf->Read($buff,8) == 8 or return 0` — no header was read at all).
    assert!(read_atom_header(&[0, 0, 0, 4, b'j'], 0, true).is_none());
  }

  #[test]
  fn ftyp_brand_resolution() {
    assert_eq!(file_type_from_ftyp(b"qt  \0\0\0\0").0, "MOV");
    assert_eq!(file_type_from_ftyp(b"M4A \0\0\0\0").0, "M4A");
    // Unknown major brand defaults to MP4.
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0").0, "MP4");
    // Compatible-brand scan picks MP4 from mp42 (a NON-first slot).
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0xxxxmp42").0, "MP4");
  }

  #[test]
  fn ftyp_first_compatible_brand_does_not_override() {
    // R9/F1: ExifTool's compatible-brand regexes are `/^.{8}(.{4})+(brand)/s`
    // — the `^.{8}` skips major brand + minor version, then `(.{4})+` needs
    // ONE OR MORE 4-byte slots BEFORE the matched brand. So a brand in the
    // FIRST compatible-brand slot (buffer offset 8) can NOT trigger a match;
    // the match needs a brand at offset ≥ 12. Verified vs bundled ExifTool
    // 13.58.
    //
    // `isom` major + `qt  ` as the FIRST compatible brand ⇒ MP4 (the default),
    // NOT MOV — the first-slot `qt  ` does not override.
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0qt  ").0, "MP4");
    // `qt  ` in the SECOND compatible slot DOES override ⇒ MOV.
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0xxxxqt  ").0, "MOV");
    // First-slot `mp42`, then a NON-first `qt  ` ⇒ MOV: the `mp41|mp42|avc1`
    // regex needs a slot BEFORE its brand, so a first-slot `mp42` does NOT
    // match it; the `qt  ` at the (non-first) second slot DOES match the `qt`
    // regex. Verified vs bundled (`isom`/minor/`mp42`/`qt  ` ⇒ MOV).
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0mp42qt  ").0, "MOV");
    // `mp42` (non-first) wins over `qt  ` (non-first) — the `mp41|mp42|avc1`
    // regex is the FIRST `elsif`, tried before the `qt  ` one. Verified vs
    // bundled (`isom`/minor/`xxxx`/`qt  `/`mp42` ⇒ MP4).
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0xxxxqt  mp42").0, "MP4");
    // `f4v ` in a NON-first slot ⇒ F4V (the compatible-brand branch SP1
    // previously omitted entirely, QuickTime.pm:9998-9999); MIME video/mp4.
    let (ft, mime) = file_type_from_ftyp(b"isom\0\0\0\0xxxxf4v ");
    assert_eq!((ft, mime), ("F4V", "video/mp4"));
    // `f4v ` in the FIRST slot does not override ⇒ MP4 default.
    assert_eq!(file_type_from_ftyp(b"isom\0\0\0\0f4v ").0, "MP4");
  }

  #[test]
  fn walk_atoms_surfaces_contained_malformed_warning() {
    // R9/F2: a CONTAINED atom whose 8-byte header was read but whose declared
    // `size == 4` is structurally invalid (`< 8`). ExifTool runs the same
    // `ProcessMOV` per-atom loop on a directory buffer, so the size check sets
    // `$warnStr = 'Invalid atom size'` and `last`s — the warning is emitted at
    // the directory's exit (verified vs bundled). `walk_atoms` previously
    // grouped a contained `Malformed` outcome with the size-0 terminator and
    // broke SILENTLY, dropping the warning.
    let mut moov_body = 4u32.to_be_bytes().to_vec(); // declared size 4 (< 8)
    moov_body.extend_from_slice(b"mvhd");
    let mut warn: Option<String> = None;
    let mut decoded = false;
    walk_atoms(0, &moov_body, 0, moov_body.len(), &mut warn, |a, _, _| {
      if &a.atom_type == b"mvhd" {
        decoded = true;
      }
    });
    assert!(!decoded, "a malformed-size child must not be decoded");
    assert_eq!(warn.as_deref(), Some("Invalid atom size"));
  }

  #[test]
  fn qt_date_offset_conversion() {
    // A 1904-epoch value at exactly the offset ⇒ Unix epoch 0;
    // `convert_unix_time(0)` is the canonical zero sentinel
    // `"0000:00:00 00:00:00"` (datetime.rs) — NO TZ suffix (ExifTool.pm:6776
    // returns it before the $tz append).
    assert_eq!(
      qt_date_string(QT_EPOCH_OFFSET as u64),
      Some("0000:00:00 00:00:00".to_string())
    );
    // One day past the offset ⇒ 1970-01-02, with the QuickTimeUTC `+00:00`
    // suffix (TZ=UTC TimeZoneString — the gen_golden.sh pinned config).
    assert_eq!(
      qt_date_string(QT_EPOCH_OFFSET as u64 + 86400),
      Some("1970:01:02 00:00:00+00:00".to_string())
    );
    // F1: a raw zero is NOT dropped — StrictDate (the only thing that would
    // `undef` it, QuickTime.pm:265) is unimplemented/off, so the zero passes
    // through to the ValueConv zero sentinel "0000:00:00 00:00:00".
    assert_eq!(qt_date_string(0), Some("0000:00:00 00:00:00".to_string()));
  }

  #[test]
  fn minor_version_value_conv() {
    // unpack("nCC", "\x00\x00\x02\x00") = (0, 2, 0) ⇒ sprintf "%x.%x.%x".
    assert_eq!(
      minor_version_string(b"\x00\x00\x02\x00"),
      Some("0.2.0".to_string())
    );
    assert_eq!(
      minor_version_string(b"\x01\x02\x0a\x0f"),
      Some("102.a.f".to_string())
    );
  }

  #[test]
  fn matrix_structure_identity() {
    // Identity matrix: a=1.0 (0x10000), the rest 0; right column (2,5,8) is
    // u=0/v=0/w=1.0 (0x40000000 / 0x4000 = 1.0).
    let mut buf = vec![0u8; 36];
    wr(&mut buf, 0, &0x0001_0000u32.to_be_bytes()); // a = 1.0
    wr(&mut buf, 16, &0x0001_0000u32.to_be_bytes()); // d = 1.0
    wr(&mut buf, 32, &0x4000_0000u32.to_be_bytes()); // w = 1.0 (2.30)
    assert_eq!(
      matrix_structure_string(&buf, 0),
      Some("1 0 0 0 1 0 0 0 1".to_string())
    );
  }

  #[test]
  fn matrix_structure_fractional_rounds_like_get_fixed32s() {
    // R3-F1: a fractional matrix exercises GetFixed32s' 5-decimal rounding
    // (ExifTool.pm:6121-6127) + Perl `%.15g` stringification. Raw 0x00000001
    // in the 16.16 fixed32s slots: 1/65536 = 1.52587890625e-05, rounded to
    // 5 dp = 2e-05; the right column (entry 8 here, raw 1) is that rounded
    // value / 0x4000 = 1.220703125e-09. Verified against bundled GetFixed32s:
    // `2e-05 0 0 0 2e-05 0 0 0 1.220703125e-09`.
    let mut buf = vec![0u8; 36];
    wr(&mut buf, 0, &1u32.to_be_bytes()); // a (entry 0) = raw 1
    wr(&mut buf, 16, &1u32.to_be_bytes()); // d (entry 4) = raw 1
    wr(&mut buf, 32, &1u32.to_be_bytes()); // w (entry 8) = raw 1
    assert_eq!(
      matrix_structure_string(&buf, 0),
      Some("2e-05 0 0 0 2e-05 0 0 0 1.220703125e-09".to_string())
    );

    // A 0.5 (0x8000) entry rounds exactly (0.5), and a 1.5 (0x18000) too.
    let mut buf2 = vec![0u8; 36];
    wr(&mut buf2, 0, &0x0000_8000u32.to_be_bytes()); // a = 0.5
    wr(&mut buf2, 16, &0x0001_8000u32.to_be_bytes()); // d = 1.5
    wr(&mut buf2, 32, &0x4000_0000u32.to_be_bytes()); // w = 1.0
    assert_eq!(
      matrix_structure_string(&buf2, 0),
      Some("0.5 0 0 0 1.5 0 0 0 1".to_string())
    );
  }

  #[test]
  fn get_fixed32s_matches_exiftool_rounding() {
    // ExifTool.pm:6121-6127: Get32s/0x10000, then int(val*1e5 + sign*0.5)/1e5.
    assert_eq!(get_fixed32s(1), 2e-05); // 1/65536 → 2e-05
    assert_eq!(get_fixed32s(0x0001_0000), 1.0); // exactly 1.0
    assert_eq!(get_fixed32s(0), 0.0);
    assert_eq!(get_fixed32s(-0x0001_0000), -1.0);
    assert_eq!(get_fixed32s(0x0000_8000), 0.5);
    // Negative tiny value rounds toward zero magnitude with -0.5 bias.
    assert_eq!(get_fixed32s(-1), -2e-05);
  }

  #[test]
  fn fix_wrong_format_takes_high_word() {
    // 1920 << 16 = 0x07800000; high bits set ⇒ take the high 16 bits = 1920.
    assert_eq!(fix_wrong_format(1920 << 16), Some(1920));
    // A small literal value (no high bits) is returned unchanged.
    assert_eq!(fix_wrong_format(1920), Some(1920));
    // Zero ⇒ undef.
    assert_eq!(fix_wrong_format(0), None);
  }

  #[test]
  fn media_language_iso_unpack() {
    // 'eng' packed: ('e'-0x60)<<10 | ('n'-0x60)<<5 | ('g'-0x60).
    let packed =
      (((b'e' - 0x60) as u16) << 10) | (((b'n' - 0x60) as u16) << 5) | ((b'g' - 0x60) as u16);
    assert_eq!(media_language(packed), Some("eng".to_string()));
    assert_eq!(media_language(0), None);
  }

  #[test]
  fn parse_inner_rejects_unknown_first_atom() {
    let data = atom(b"XXXX", b"\0\0\0\0");
    assert!(parse_inner(&data, None).is_none());
  }

  #[test]
  fn parse_inner_accepts_ftyp_and_resolves_type() {
    let data = atom(b"ftyp", b"M4A \0\0\0\0M4A mp42");
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "M4A");
    // MajorBrand keeps the trailing space (the %ftypLookup PrintConv key).
    assert_eq!(meta.quicktime().major_brand(), Some("M4A "));
    // MinorVersion ValueConv from "\0\0\0\0".
    assert_eq!(meta.quicktime().minor_version(), Some("0.0.0"));
    // CompatibleBrands: "M4A " and "mp42" (no NULs ⇒ both kept).
    assert_eq!(meta.quicktime().compatible_brands(), &["M4A ", "mp42"]);
  }

  /// Codex R3 (pipeline negative) — a real `trak` whose `hdlr` HandlerType is
  /// `gps ` must NOT suppress the brute-force `mdat` scan. ExifTool ignores
  /// such a track (no `$eeBox{'gps '}`), so `extract_stream` runs no
  /// `ProcessFreeGPS` and returns `FoundEmbedded = false`, and `ScanMediaData`
  /// still decodes a real `freeGPS ` block buried in `mdat`
  /// (QuickTimeStream.pl:3689). The single decoded sample therefore comes from
  /// the SCAN, not the ignored track.
  ///
  /// VERIFIED against bundled 13.59 (`exiftool -ee` on this exact layout):
  /// `Track1:HandlerType = Unknown (gps )` (the track is recognized but yields
  /// no GPS) while the scan emits ONE fix — GPSLatitude `47 deg 37' 42.30" N`,
  /// GPSLongitude `122 deg 9' 54.08" W`, GPSDateTime `2024:07:15 14:30:45Z`.
  /// The `mdat` is padded past `0x8000` because `ScanMediaData` bails on a
  /// chunk shorter than one GPS-block window (`last if length $buff <
  /// $gpsBlockSize`, QuickTimeStream.pl:3756) — so a sub-`0x8000` `mdat` would
  /// not be scanned by the oracle either.
  #[test]
  fn gps_handler_track_does_not_suppress_mdat_scan() {
    // A Type-6 (Akaso) freeGPS block; the scan magic is `\0..\0freeGPS ` and a
    // 0x100 BE size word (`00 00 01 00`) satisfies the byte-0/byte-3 = \0 mask.
    let mut blk = vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x30, &14u32.to_le_bytes());
    wr(&mut blk, 0x34, &30u32.to_le_bytes());
    wr(&mut blk, 0x38, &45u32.to_le_bytes());
    wr(&mut blk, 0x58, &2024u32.to_le_bytes());
    wr(&mut blk, 0x5c, &7u32.to_le_bytes());
    wr(&mut blk, 0x60, &15u32.to_le_bytes());
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    // Layout = ftyp || mdat(freeGPS-block + >=0x8000 pad) || moov, so the
    // block's ABSOLUTE file offset = ftyp.len() + 8 (the `mdat` payload start)
    // is fixed up front. The padding makes the scan window a full GPS block
    // (the oracle's `last if length $buff < $gpsBlockSize` guard, :3756).
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mut mdat_payload = blk.clone();
    mdat_payload.extend_from_slice(&[0u8; 0x8000]);
    let mdat = atom(b"mdat", &mdat_payload);
    let block_offset = (ftyp.len() + 8) as u32;

    // A `gps `-HandlerType trak whose sample table REFERENCES the same block.
    let mut hdlr_body = vec![0u8; 24];
    wr(&mut hdlr_body, 8, b"gps ");
    let hdlr = atom(b"hdlr", &hdlr_body);
    let mut mdhd_body = vec![0u8; 24];
    wr(&mut mdhd_body, 12, &1000u32.to_be_bytes());
    let mdhd = atom(b"mdhd", &mdhd_body);
    let mut stsd_body = vec![0u8; 8];
    wr(&mut stsd_body, 4, &1u32.to_be_bytes());
    let mut entry = vec![0u8; 16];
    wr(&mut entry, 0, &16u32.to_be_bytes());
    wr(&mut entry, 4, b"gps ");
    stsd_body.extend_from_slice(&entry);
    let stsd = atom(b"stsd", &stsd_body);
    let mut stco_body = vec![0u8; 8];
    wr(&mut stco_body, 4, &1u32.to_be_bytes());
    stco_body.extend_from_slice(&block_offset.to_be_bytes());
    let stco = atom(b"stco", &stco_body);
    let mut stsc_body = vec![0u8; 8];
    wr(&mut stsc_body, 4, &1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    let stsc = atom(b"stsc", &stsc_body);
    let mut stsz_body = vec![0u8; 8];
    wr(&mut stsz_body, 4, &0u32.to_be_bytes());
    stsz_body.extend_from_slice(&1u32.to_be_bytes());
    stsz_body.extend_from_slice(&(blk.len() as u32).to_be_bytes());
    let stsz = atom(b"stsz", &stsz_body);
    let mut stbl_body = stsd;
    stbl_body.extend_from_slice(&stco);
    stbl_body.extend_from_slice(&stsc);
    stbl_body.extend_from_slice(&stsz);
    let stbl = atom(b"stbl", &stbl_body);
    let minf = atom(b"minf", &stbl);
    let mut mdia_body = mdhd;
    mdia_body.extend_from_slice(&hdlr);
    mdia_body.extend_from_slice(&minf);
    let mdia = atom(b"mdia", &mdia_body);
    let trak = atom(b"trak", &mdia);
    let mvhd = atom(b"mvhd", &[0u8; 100]);
    let mut moov_body = mvhd;
    moov_body.extend_from_slice(&trak);
    let moov = atom(b"moov", &moov_body);

    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("accepted");
    // The `gps `-handler track contributed nothing; the `mdat` scan decoded the
    // buried block. Exactly one sample, from the scan.
    assert_eq!(
      meta.stream().gps_samples().len(),
      1,
      "the mdat scan must still decode the buried freeGPS block"
    );
    assert!(
      meta
        .stream()
        .gps_samples()
        .first()
        .unwrap()
        .has_coordinates()
    );
  }

  /// Codex R3 (dedup) — finding step 3: a block referenced by the `moov`-level
  /// `gps ` offset box must NOT be double-emitted by the `mdat` scan. The box
  /// decode runs `ProcessFreeGPS`, which sets ExifTool's `FoundEmbedded`
  /// (QuickTimeStream.pl:1650), and that flag — threaded out of
  /// `extract_stream` — gates `ScanMediaData` (:3689). VERIFIED against bundled
  /// 13.59 (`exiftool -ee` on this exact layout: a `moov` `gps ` box pointing at
  /// a block that also lies in a `>=0x8000` `mdat`) — ONE GPSLatitude key, not
  /// two.
  #[test]
  fn moov_gps_box_decode_suppresses_redundant_mdat_scan() {
    let mut blk = vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x30, &14u32.to_le_bytes());
    wr(&mut blk, 0x34, &30u32.to_le_bytes());
    wr(&mut blk, 0x38, &45u32.to_le_bytes());
    wr(&mut blk, 0x58, &2024u32.to_le_bytes());
    wr(&mut blk, 0x5c, &7u32.to_le_bytes());
    wr(&mut blk, 0x60, &15u32.to_le_bytes());
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    // Layout = ftyp || mdat(block + >=0x8000 pad) || moov(gps-box → same block).
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mut mdat_payload = blk.clone();
    mdat_payload.extend_from_slice(&[0u8; 0x8000]);
    let mdat = atom(b"mdat", &mdat_payload);
    let block_offset = (ftyp.len() + 8) as u32;

    // The `moov`-level `gps ` offset box pointing at the SAME block in `mdat`.
    let mut gps_body = vec![0u8; 8];
    wr(&mut gps_body, 4, &1u32.to_be_bytes());
    gps_body.extend_from_slice(&block_offset.to_be_bytes());
    gps_body.extend_from_slice(&(blk.len() as u32).to_be_bytes());
    let gps_box = atom(b"gps ", &gps_body);
    let mvhd = atom(b"mvhd", &[0u8; 100]);
    let mut moov_body = mvhd;
    moov_body.extend_from_slice(&gps_box);
    let moov = atom(b"moov", &moov_body);

    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("accepted");
    // The box decoded the block once; the scan is suppressed — NOT doubled.
    assert_eq!(
      meta.stream().gps_samples().len(),
      1,
      "the moov gps ' box must decode once and suppress the redundant mdat scan"
    );
  }

  /// **R8-B class-sweep** — a `moov/udta/GPMF` atom sets ExifTool's
  /// `$$et{FoundEmbedded}` (it routes through `GoPro::ProcessGoPro`, which sets
  /// the flag on ENTRY, GoPro.pm:822), and in ExifTool the `moov` walk runs
  /// BEFORE `ScanMediaData` — so the mere PRESENCE of a `moov/udta/GPMF` atom
  /// SUPPRESSES the brute-force `mdat` freeGPS scan (QuickTimeStream.pl:3689).
  /// The port therefore processes `moov/udta/GPMF` inside the single ordered
  /// `walk_moov` pass (run by `extract_stream` BEFORE the scan) and folds its
  /// "entered ProcessGoPro" result into the `FoundEmbedded` gate (consistent
  /// FoundEmbedded semantics with the `gpmd`-sample path).
  ///
  /// Oracle-verified vs ExifTool 13.59 (`exiftool -ee` on this exact layout: a
  /// `moov/udta/GPMF` carrying `DVNM=Hero8 Black` plus a `freeGPS ` block buried
  /// in a `>=0x8000` `mdat`): DeviceName is extracted and NO GPSLatitude/
  /// GPSLongitude is emitted (the scan is suppressed). The matching control
  /// without the `udta/GPMF` DOES emit the GPS fix (see
  /// [`nonfreegps_stream_sample_does_not_suppress_mdat_scan`] for the un-gated
  /// shape). Pre-fix (moov-GPMF walked AFTER the scan) the port emitted the GPS
  /// fix here — a real divergence.
  #[test]
  fn moov_udta_gpmf_suppresses_mdat_scan() {
    // A Type-6 (Akaso) freeGPS block buried in `mdat`.
    let mut blk = vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x30, &14u32.to_le_bytes());
    wr(&mut blk, 0x34, &30u32.to_le_bytes());
    wr(&mut blk, 0x38, &45u32.to_le_bytes());
    wr(&mut blk, 0x58, &2024u32.to_le_bytes());
    wr(&mut blk, 0x5c, &7u32.to_le_bytes());
    wr(&mut blk, 0x60, &15u32.to_le_bytes());
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    // Layout = ftyp || mdat(block + >=0x8000 pad) || moov(mvhd + udta/GPMF).
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mut mdat_payload = blk.clone();
    mdat_payload.extend_from_slice(&[0u8; 0x8000]);
    let mdat = atom(b"mdat", &mdat_payload);

    // A real GoPro `moov/udta/GPMF` carrying a DEVC/DVNM (DeviceName).
    let gpmf = devc_dvnm(b"Hero8 Black");
    let udta = atom(b"udta", &atom(b"GPMF", &gpmf));
    let mvhd = atom(b"mvhd", &[0u8; 100]);
    let mut moov_body = mvhd;
    moov_body.extend_from_slice(&udta);
    let moov = atom(b"moov", &moov_body);

    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("accepted");
    // The `moov/udta/GPMF` was processed (DeviceName extracted) AND it set
    // FoundEmbedded, so the buried freeGPS block is NOT scanned: zero samples.
    assert_eq!(
      meta.gopro().device_name(),
      Some("Hero8 Black"),
      "the moov/udta/GPMF DeviceName is extracted"
    );
    assert_eq!(
      meta.stream().gps_samples().len(),
      0,
      "a moov/udta/GPMF must suppress the brute-force mdat freeGPS scan (FoundEmbedded on ProcessGoPro entry)"
    );
  }

  /// Codex R6 (real-input) — the `mdat` scan must be gated on ExifTool's
  /// `$$et{FoundEmbedded}` (set ONLY by `ProcessFreeGPS`, QuickTimeStream.pl:1650),
  /// NOT on per-sample output. A real dashcam / action-cam can carry a timed
  /// metadata stream (here a `gps0` box — DuDuBell M1 / VSYS M6L, decoded by
  /// `Process_gps0` via the generic `FoundSomething`, QuickTimeStream.pl:967-973,
  /// which never touches `FoundEmbedded`) AND a `freeGPS ` block buried in `mdat`
  /// padding. ExifTool extracts BOTH: the `gps0` sample, and — because
  /// `FoundEmbedded` is still unset after the `gps0` decode — the buried block
  /// via `ScanMediaData` (:3689). The pre-fix port gated on `!stream.is_empty()`,
  /// so the `gps0` sample alone suppressed the scan and the freeGPS fix was LOST;
  /// gating on `FoundEmbedded` restores it.
  #[test]
  fn nonfreegps_stream_sample_does_not_suppress_mdat_scan() {
    // A Type-6 (Akaso) freeGPS block buried in `mdat` (block-relative offsets;
    // distinct coordinates from the `gps0` record so we can tell them apart).
    let mut blk = vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x30, &14u32.to_le_bytes());
    wr(&mut blk, 0x34, &30u32.to_le_bytes());
    wr(&mut blk, 0x38, &45u32.to_le_bytes());
    wr(&mut blk, 0x58, &2024u32.to_le_bytes());
    wr(&mut blk, 0x5c, &7u32.to_le_bytes());
    wr(&mut blk, 0x60, &15u32.to_le_bytes());
    // freeGPS lat 4737.7053 ⇒ 47.628..., lon 12209.901 ⇒ -122.165... (W).
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    // Layout = ftyp || mdat(freeGPS-block + >=0x8000 pad) || gps0 || moov(mvhd).
    // The padding makes the scan window a full GPS block (the oracle's
    // `last if length $buff < $gpsBlockSize` guard, QuickTimeStream.pl:3756).
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mut mdat_payload = blk.clone();
    mdat_payload.extend_from_slice(&[0u8; 0x8000]);
    let mdat = atom(b"mdat", &mdat_payload);

    // A top-level `gps0` box: one valid 32-byte LE record (Process_gps0). This
    // populates `stream` via `FoundSomething` WITHOUT touching `FoundEmbedded`,
    // so `stream.is_empty()` is false but `found_embedded` is false. Distinct
    // coordinates from the buried freeGPS block: the `gps0` binary variant has
    // no N/S/E/W sign bytes, so lat 3000.0 ⇒ +30.0, lon 10000.0 ⇒ +100.0.
    let mut rec = vec![0u8; 32];
    wr(&mut rec, 0, &3000.0f64.to_le_bytes()); // lat 30deg00.0'
    wr(&mut rec, 8, &10000.0f64.to_le_bytes()); // lon 100deg00.0'
    wr(&mut rec, 0x10, &50i32.to_le_bytes()); // altitude
    wr(&mut rec, 0x14, &42u16.to_le_bytes()); // speed
    wr(&mut rec, 0x16, &[24, 1, 7, 11, 19, 14]); // y m d H M S
    wb(&mut rec, 0x1c, 10); // track/2
    let gps0 = atom(b"gps0", &rec);

    let mvhd = atom(b"mvhd", &[0u8; 100]);
    let moov = atom(b"moov", &mvhd);

    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&gps0);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("accepted");
    let samples = meta.stream().gps_samples();
    // BOTH sources extracted: the `gps0` record AND the scanned freeGPS block.
    // (Pre-fix: only the `gps0` sample — the scan was wrongly suppressed.)
    assert_eq!(
      samples.len(),
      2,
      "the gps0 sample must NOT suppress the mdat scan of the buried freeGPS block"
    );
    // The freeGPS block contributes its distinctive ~47.6N / ~122.2W fix.
    assert!(
      samples
        .iter()
        .any(|s| s.latitude().is_some_and(|v| (47.0..48.0).contains(&v))
          && s.longitude().is_some_and(|v| (-123.0..-122.0).contains(&v))),
      "the buried freeGPS fix (~47.6N, ~122.2W) must be present"
    );
    // The `gps0` record's own ~30N / ~100E fix is still there too.
    assert!(
      samples
        .iter()
        .any(|s| s.latitude().is_some_and(|v| (29.0..31.0).contains(&v))),
      "the gps0 sample (~30N) must also be present"
    );
  }

  #[test]
  fn mp4_override_to_m4a_predicate() {
    // R10/F1: the post-walk MP4→M4A override (QuickTime.pm:10619-10624).
    // Build `ftyp <major> <minor> mp42` + `moov{ <hdlr handlers> }` so the
    // brands resolve to MP4 (a non-first `mp42` compat slot), then vary the
    // handler set. The override fires iff major brand ∈ {iso*,dash,mp42},
    // a `soun` handler exists, and NO `vide` handler exists.
    let hdlr = |code: &[u8; 4]| atom(b"hdlr", &[&[0u8; 8], &code[..], &[0u8; 12]].concat());
    let build = |major: &[u8; 4], handlers: &[&[u8; 4]]| {
      // ftyp = major + minor + <first compat slot> + `mp42` (a NON-first compat
      // slot ⇒ `file_type_from_ftyp` resolves MP4 for any non-`qt  ` major).
      let ftyp = atom(
        b"ftyp",
        &[&major[..], &[0u8; 4], &major[..], b"mp42"].concat(),
      );
      let traks: Vec<u8> = handlers
        .iter()
        .flat_map(|h| atom(b"trak", &atom(b"mdia", &hdlr(h))))
        .collect();
      let moov = atom(b"moov", &traks);
      [ftyp, moov].concat()
    };
    let ft = |major: &[u8; 4], handlers: &[&[u8; 4]]| {
      let data = build(major, handlers);
      let meta = parse_inner(&data, None).expect("accepted");
      (meta.file_type(), meta.mime())
    };

    // soun only + `isom` major ⇒ override to M4A / audio/mp4.
    assert_eq!(ft(b"isom", &[b"soun"]), ("M4A", "audio/mp4"));
    // soun + vide ⇒ a `vide` handler present suppresses the override ⇒ MP4.
    assert_eq!(ft(b"isom", &[b"soun", b"vide"]), ("MP4", "video/mp4"));
    // vide only ⇒ no `soun` handler ⇒ MP4.
    assert_eq!(ft(b"isom", &[b"vide"]), ("MP4", "video/mp4"));
    // soun only but a `qt  ` major (resolves to MOV, not MP4) ⇒ no override.
    assert_eq!(ft(b"qt  ", &[b"soun"]), ("MOV", "video/quicktime"));
    // soun only with `dash` / `mp42` / `iso2` majors ⇒ all override to M4A.
    assert_eq!(ft(b"dash", &[b"soun"]), ("M4A", "audio/mp4"));
    assert_eq!(ft(b"mp42", &[b"soun"]), ("M4A", "audio/mp4"));
    assert_eq!(ft(b"iso2", &[b"soun"]), ("M4A", "audio/mp4"));
    // A non-matching major brand (`3gp4` ⇒ resolves to MP4 via the mp42 compat
    // slot, but the brand does not start with iso/dash/mp42) ⇒ no override.
    assert_eq!(ft(b"3gp4", &[b"soun"]), ("MP4", "video/mp4"));
  }

  #[test]
  fn use_ext_table_is_glv_to_mp4_only() {
    // R11/F1: `%useExt = ( GLV => 'MP4' )` (QuickTime.pm:240) — the WHOLE
    // table is this single entry, and the predicate (QuickTime.pm:10007)
    // `$fileType = $ext if $ext and $useExt{$ext} and $fileType eq
    // $useExt{$ext}` fires only when ALL three hold.

    // The lone covered entry: ext `GLV` AND ftyp-derived `MP4` ⇒ promote GLV.
    assert_eq!(use_ext("MP4", Some("GLV")), Some("GLV"));
    // `$$et{FILE_EXT}` is uppercased upstream; accept any case defensively.
    assert_eq!(use_ext("MP4", Some("glv")), Some("GLV"));
    assert_eq!(use_ext("MP4", Some("Glv")), Some("GLV"));

    // Predicate guard: ext is a `%useExt` key but `$fileType ne $useExt{$ext}`
    // ⇒ NO promotion. A `.glv` whose ftyp resolved to anything but MP4 is left
    // for the generic `SetFileType` sub-type-by-extension path (the `MOV` root
    // shared by GLV handles MOV→GLV; M4A/M4V/M4B are NOT promoted there).
    assert_eq!(use_ext("MOV", Some("GLV")), None);
    assert_eq!(use_ext("M4A", Some("GLV")), None);
    assert_eq!(use_ext("M4V", Some("GLV")), None);
    assert_eq!(use_ext("F4V", Some("GLV")), None);

    // Predicate guard: ext is NOT a `%useExt` key ⇒ NO promotion, regardless
    // of the ftyp-derived type. (`%useExt` has exactly one key — `GLV`.)
    assert_eq!(use_ext("MP4", Some("MP4")), None);
    assert_eq!(use_ext("MP4", Some("MOV")), None);
    assert_eq!(use_ext("MP4", Some("M4A")), None);
    assert_eq!(use_ext("MP4", Some("MKV")), None);
    // Predicate guard: `$ext` undef (dotless source name) ⇒ NO promotion.
    assert_eq!(use_ext("MP4", None), None);
  }

  #[test]
  fn use_ext_glv_promotion_suppresses_m4a_override() {
    // R11/F1 end-to-end: the BYTE-IDENTICAL audio-only `isom` file resolves to
    // MP4, then either the `%useExt` GLV promotion OR the post-walk MP4→M4A
    // override applies depending ONLY on the extension. `%useExt` runs FIRST
    // (QuickTime.pm:10007, before the atom loop), so a `.glv` ext flips the
    // type to GLV and the M4A override (gated on `FileType eq 'MP4'`,
    // QuickTime.pm:10619) no longer fires.
    let hdlr = atom(b"hdlr", &[&[0u8; 8], &b"soun"[..], &[0u8; 12]].concat());
    // ftyp `isom` + a non-first `mp42` compat slot ⇒ resolves MP4; audio-only.
    let ftyp = atom(
      b"ftyp",
      &[&b"isom"[..], &[0u8; 4], &b"isom"[..], b"mp42"].concat(),
    );
    let moov = atom(b"moov", &atom(b"trak", &atom(b"mdia", &hdlr)));
    let data = [ftyp, moov].concat();

    // `.glv` extension ⇒ `%useExt` promotes MP4→GLV (override skipped).
    let glv = parse_inner(&data, Some("GLV")).expect("accepted");
    assert_eq!(glv.file_type(), "GLV");
    // `%mimeLookup{GLV}` is undef ⇒ the `'video/mp4'` fallback (QuickTime.pm:10008).
    assert_eq!(glv.mime(), "video/mp4");

    // Same bytes, NO `.glv` ext ⇒ MP4 not promoted ⇒ the audio-only MP4→M4A
    // override fires (QuickTime.pm:10619-10624).
    let m4a = parse_inner(&data, None).expect("accepted");
    assert_eq!(m4a.file_type(), "M4A");
    assert_eq!(m4a.mime(), "audio/mp4");

    // A `.glv` ext on a `qt  ` major (resolves MOV, not MP4) ⇒ `%useExt` does
    // NOT fire here (MOV ne MP4); the parser leaves MOV and the generic engine
    // path performs the MOV→GLV sub-type promotion downstream.
    let qt_ftyp = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    let qt_data = [
      qt_ftyp,
      atom(
        b"moov",
        &atom(
          b"trak",
          &atom(
            b"mdia",
            &atom(b"hdlr", &[&[0u8; 8], &b"vide"[..], &[0u8; 12]].concat()),
          ),
        ),
      ),
    ]
    .concat();
    let qt = parse_inner(&qt_data, Some("GLV")).expect("accepted");
    assert_eq!(qt.file_type(), "MOV");
    assert_eq!(qt.mime(), "video/quicktime");
  }

  #[test]
  fn v1_tkhd_dimensions_at_offsets_88_92() {
    // F2: a version-1 tkhd. Lay out create/modify/id/reserved/duration as
    // int64u where the Hook widens, then place ImageWidth/Height at byte
    // offsets 88/92. Verify the decoder reads 1280x720 there (NOT 96/100).
    let mut p = vec![0u8; 104];
    wb(&mut p, 0, 1); // version 1
    // width 1280 (16.16) at offset 88, height 720 at 92.
    wr(&mut p, 88, &(1280u32 << 16).to_be_bytes());
    wr(&mut p, 92, &(720u32 << 16).to_be_bytes());
    let track = decode_tkhd(&p, Some(600));
    assert_eq!(track.image_width(), Some(1280));
    assert_eq!(track.image_height(), Some(720));
    assert_eq!(track.track_header_version(), Some(1));
  }

  #[test]
  fn out_of_order_moov_trak_before_mvhd_uses_final_timescale() {
    // F4 (REFUTED): a moov whose trak comes BEFORE mvhd. The TrackDuration
    // durationInfo is a ValueConv applied at OUTPUT time using the FINAL
    // movie TimeScale — so even though the trak is parsed first, its
    // TrackDuration is converted with mvhd's TimeScale=600 ⇒ 1200/600 = 2.0
    // (verified against bundled ExifTool). NOT the raw 1200.
    let mut tkhd = vec![0u8; 84];
    wb(&mut tkhd, 0, 0); // version 0
    wr(&mut tkhd, 20, &1200u32.to_be_bytes()); // duration idx5
    let trak = atom(b"trak", &atom(b"tkhd", &tkhd));
    let mut mvhd = vec![0u8; 100];
    wb(&mut mvhd, 0, 0);
    wr(&mut mvhd, 12, &600u32.to_be_bytes()); // TimeScale idx3
    wr(&mut mvhd, 16, &3000u32.to_be_bytes()); // Duration idx4
    let mut moov_body = trak.clone();
    moov_body.extend_from_slice(&atom(b"mvhd", &mvhd));
    let data = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    let mut full = data;
    full.extend_from_slice(&atom(b"moov", &moov_body));
    let meta = parse_inner(&full, None).expect("accepted");
    let track = meta.quicktime().tracks().first().unwrap();
    // 1200 / 600 = 2.0 — the final movie TimeScale is used regardless of the
    // trak-before-mvhd file order (faithful durationInfo ValueConv).
    assert_eq!(track.duration_seconds(), Some(2.0));
    assert_eq!(meta.quicktime().time_scale(), Some(600));
    assert_eq!(meta.quicktime().duration_seconds(), Some(5.0));
  }

  #[test]
  fn multi_moov_trackduration_uses_final_global_timescale() {
    // R3-F2: two TOP-LEVEL moov atoms. The first carries the track
    // (tkhd Duration=1200) under mvhd TimeScale=600; a SECOND top-level moov
    // overwrites the GLOBAL movie TimeScale to 300. ExifTool's TimeScale slot
    // is last-wins across every mvhd in the file, and the TrackDuration
    // durationInfo ValueConv runs at output against that FINAL value ⇒
    // 1200/300 = 4 (verified against bundled ExifTool: `Track1:TrackDuration =
    // 4`), NOT 1200/600 = 2.
    let mut tkhd = vec![0u8; 84];
    wb(&mut tkhd, 0, 0); // version 0
    wr(&mut tkhd, 12, &1u32.to_be_bytes()); // TrackID idx3 = 1
    wr(&mut tkhd, 20, &1200u32.to_be_bytes()); // duration idx5
    let trak = atom(b"trak", &atom(b"tkhd", &tkhd));

    let mut mvhd1 = vec![0u8; 100];
    wb(&mut mvhd1, 0, 0);
    wr(&mut mvhd1, 12, &600u32.to_be_bytes()); // TimeScale idx3
    let moov1 = atom(b"moov", &{
      let mut b = atom(b"mvhd", &mvhd1);
      b.extend_from_slice(&trak);
      b
    });

    let mut mvhd2 = vec![0u8; 100];
    wb(&mut mvhd2, 0, 0);
    wr(&mut mvhd2, 12, &300u32.to_be_bytes()); // TimeScale idx3
    let moov2 = atom(b"moov", &atom(b"mvhd", &mvhd2));

    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov1);
    full.extend_from_slice(&moov2);

    let meta = parse_inner(&full, None).expect("accepted");
    // Final global TimeScale is the SECOND moov's (last-wins).
    assert_eq!(meta.quicktime().time_scale(), Some(300));
    let track = meta.quicktime().tracks().first().unwrap();
    assert_eq!(track.track_id(), Some(1));
    // 1200 / 300 = 4.0 — converted against the FINAL global TimeScale.
    assert_eq!(track.duration_seconds(), Some(4.0));
  }

  #[test]
  fn multi_moov_movie_duration_uses_final_timescale_and_preserves_count() {
    // R6/F1: two TOP-LEVEL moov atoms. moov1's `mvhd` carries TimeScale=600 +
    // Duration count 3000; moov2's `mvhd` is a SHORT 16-byte payload carrying
    // only version/create/modify/TimeScale=300 — NO Duration field. The movie
    // `Duration` is a `%durationInfo` tag: its ValueConv `$val/TimeScale`
    // runs at OUTPUT against the FINAL global TimeScale (300), and an absent
    // Duration in the later short `mvhd` must NOT erase moov1's found count.
    // Verified vs bundled: `QuickTime:Duration = 10` (3000/300).
    let mut mvhd1 = vec![0u8; 100];
    wb(&mut mvhd1, 0, 0); // version 0
    wr(&mut mvhd1, 12, &600u32.to_be_bytes()); // TimeScale idx3
    wr(&mut mvhd1, 16, &3000u32.to_be_bytes()); // Duration idx4
    let moov1 = atom(b"moov", &atom(b"mvhd", &mvhd1));
    // A SHORT mvhd: only 16 bytes (version + flags + create + modify + ts),
    // no Duration field present.
    let mut mvhd2 = vec![0u8; 16];
    wb(&mut mvhd2, 0, 0);
    wr(&mut mvhd2, 12, &300u32.to_be_bytes()); // TimeScale idx3
    let moov2 = atom(b"moov", &atom(b"mvhd", &mvhd2));

    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov1);
    full.extend_from_slice(&moov2);

    let meta = parse_inner(&full, None).expect("accepted");
    let qt = meta.quicktime();
    // The raw Duration COUNT survives moov2's short mvhd (absent ⇒ no erase).
    assert_eq!(qt.duration_count(), Some(3000));
    // Final global TimeScale is moov2's (last-wins, the field IS present).
    assert_eq!(qt.time_scale(), Some(300));
    // durationInfo ValueConv at OUTPUT: 3000 / 300 = 10.0 (NOT 3000/600 = 5).
    assert_eq!(qt.duration_seconds(), Some(10.0));
  }

  #[test]
  fn truncated_first_ftyp_is_accepted_as_mp4_with_warning() {
    // R6/F2: a 12-byte file whose first atom is `ftyp` with a DECLARED size
    // of 100 — the 8-byte header is intact but the brand payload overruns
    // EOF. ExifTool gates the format on the 4-byte `$tag` ALONE
    // (QuickTime.pm:9984), so the file IS accepted as QuickTime; the short
    // brand pre-read leaves `$fileType` undef ⇒ default MP4
    // (QuickTime.pm:10004) and a `Truncated 'ftyp' data` warning stops the
    // walk. `$missing` is the WHOLE declared payload (the pre-read consumed
    // the available bytes).
    let mut data = 100u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"ftyp");
    data.extend_from_slice(b"mp42"); // 12 bytes total
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "MP4");
    assert_eq!(meta.mime(), "video/mp4");
    // Truncated payload ⇒ no ftyp tags decoded.
    assert_eq!(meta.quicktime().major_brand(), None);
    assert_eq!(
      meta.warning.as_deref(),
      Some("Truncated 'ftyp' data (missing 92 bytes)")
    );
  }

  #[test]
  fn overrun_first_mdat_records_declared_size_offset_with_warning() {
    // R6/F2: a 12-byte file whose first atom is `mdat` with a DECLARED size
    // of 100. ExifTool records the synthetic `mdat-size`/`mdat-offset` from
    // the DECLARED size BEFORE the short payload read; `mdat` is `Unknown` so
    // the seek-past `else` branch fires `Truncated 'mdat' data at offset 0x0`
    // (QuickTime.pm:10590). Verified vs bundled: FileType MOV +
    // MediaDataSize=92 + MediaDataOffset=8.
    let mut data = 100u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"mdat");
    data.extend_from_slice(b"XXXX"); // 12 bytes total
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    // mdat-size/offset from the DECLARED size (100 - 8 = 92), offset = 8.
    assert_eq!(meta.quicktime().media_data_size(), Some(92));
    assert_eq!(meta.quicktime().media_data_offset(), Some(8));
    assert_eq!(
      meta.warning.as_deref(),
      Some("Truncated 'mdat' data at offset 0x0")
    );
  }

  #[test]
  fn truncated_first_ftyp_short_declared_size_falls_to_mov() {
    // R6/F2 edge: a truncated first `ftyp` whose DECLARED size is < 12 takes
    // ExifTool's `else { SetFileType() }` branch (the `$size >= 12` ftyp gate
    // fails) ⇒ MOV, not the MP4 default. Declared size 10, only 9 bytes of
    // data ⇒ the 2-byte payload overruns EOF (a `TruncatedAtom`).
    let mut data = 10u32.to_be_bytes().to_vec(); // declared size 10 (< 12)
    data.extend_from_slice(b"ftyp");
    data.push(b'm'); // 9 bytes total, declared 2-byte payload overruns
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
  }

  #[test]
  fn first_atom_invalid_size_accepted_as_mov_with_warning() {
    // R8/F1: a file whose first atom carries a recognized magic type but a
    // structurally-invalid `size < 8`. ExifTool gates on the 4-byte `$tag`
    // (QuickTime.pm:9984), `SetFileType`s ⇒ MOV, THEN the per-atom loop's
    // `$size < 8` check sets `$warnStr = 'Invalid atom size'` and `last`s
    // (QuickTime.pm:10058). Verified vs bundled (`00000004 66747970` ⇒
    // FileType MOV + `ExifTool:Warning = "Invalid atom size"`). Before R8 the
    // port returned `Ok(None)`, losing the QuickTime result entirely.
    for size in 2u32..=7 {
      let mut data = size.to_be_bytes().to_vec();
      data.extend_from_slice(b"ftyp");
      let meta = parse_inner(&data, None).expect("accepted");
      assert_eq!(meta.file_type(), "MOV", "size {size}: file type");
      assert_eq!(
        meta.warning.as_deref(),
        Some("Invalid atom size"),
        "size {size}: warning"
      );
    }
    // The same for a `moov`/`mdat` first atom — any magic type is accepted.
    let mut moov4 = 4u32.to_be_bytes().to_vec();
    moov4.extend_from_slice(b"moov");
    let meta = parse_inner(&moov4, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.warning.as_deref(), Some("Invalid atom size"));
  }

  #[test]
  fn first_atom_truncated_extended_size_header_accepted_with_warning() {
    // R8/F1: a `size == 1` first atom whose 8-byte extended-size header is
    // truncated (fewer than 16 bytes total). QuickTime.pm:10059 `$raf->Read(
    // $buff,8) == 8 or $warnStr = 'Truncated atom header', last` — but the
    // 8-byte tag/size header was already read and `SetFileType` already ran.
    // Verified vs bundled: FileType MOV + `ExifTool:Warning = "Truncated atom
    // header"`. Before R8 the port returned `Ok(None)`.
    let mut data = 1u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"ftyp");
    data.extend_from_slice(&[0u8; 4]); // only 4 of the 8 ext-size bytes
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.warning.as_deref(), Some("Truncated atom header"));

    // The same for an extended-size `mdat` first atom.
    let mut mdat = 1u32.to_be_bytes().to_vec();
    mdat.extend_from_slice(b"mdat");
    mdat.extend_from_slice(&[0u8; 3]);
    let meta = parse_inner(&mdat, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.warning.as_deref(), Some("Truncated atom header"));
  }

  #[test]
  fn short_ftyp_first_atom_is_mov_not_mp4() {
    // R8/F1: a first `ftyp` whose RAW 32-bit size is `< 12` (8 or 11) fails
    // ExifTool's `$tag eq 'ftyp' and $size >= 12` gate and takes the `else {
    // SetFileType() }` ⇒ MOV branch (QuickTime.pm:9986/10012). Before R8 the
    // port defaulted a short `ftyp` to MP4. Verified vs bundled: an 8-byte
    // `size=8 ftyp` and an 11-byte `size=11 ftyp` are both MOV.
    let size8 = 8u32
      .to_be_bytes()
      .iter()
      .chain(b"ftyp")
      .copied()
      .collect::<Vec<u8>>();
    let meta = parse_inner(&size8, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.mime(), "video/quicktime");

    // size=11 ftyp: 8-byte header + a 3-byte payload "qt ".
    let mut size11 = 11u32.to_be_bytes().to_vec();
    size11.extend_from_slice(b"ftyp");
    size11.extend_from_slice(b"qt ");
    let meta = parse_inner(&size11, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
  }

  #[test]
  fn extended_size_ftyp_first_atom_is_mov_regardless_of_brand() {
    // R8/F1: an EXTENDED-size first `ftyp` (`size32 == 1`). The `$size >= 12`
    // gate sees the RAW 32-bit `$size == 1` (the 64-bit decode happens later,
    // inside the loop), so it FAILS ⇒ `else { SetFileType() }` ⇒ MOV — even
    // when the brand would otherwise resolve to MP4. Verified vs bundled: an
    // extended-size `ftyp` with the `isom` brand is FileType MOV (NOT MP4),
    // with `QuickTime:MajorBrand` still decoded from the proper atom walk.
    let mut data = 1u32.to_be_bytes().to_vec(); // size32 == 1 (extended)
    data.extend_from_slice(b"ftyp");
    data.extend_from_slice(&24u64.to_be_bytes()); // 64-bit size = 24
    data.extend_from_slice(b"isom"); // major brand
    data.extend_from_slice(&[0u8; 4]); // minor version
    let meta = parse_inner(&data, None).expect("accepted");
    // MOV via SetFileType(), NOT MP4 from the `isom` brand.
    assert_eq!(meta.file_type(), "MOV");
    // The brand is still decoded from the (valid) extended-size atom walk.
    assert_eq!(meta.quicktime().major_brand(), Some("isom"));
  }

  #[test]
  fn lowercase_pict_first_atom_accepted_as_mov() {
    // R8/F2: a file whose first atom is a lowercase `pict` — the `%magicNumber`
    // MOV regex (`ExifTool.pm:995`) matches BOTH `PICT` and `pict`, and
    // `%QuickTime::Main` defines `pict => PreviewPICT` (QuickTime.pm:125).
    // Verified vs bundled: FileType MOV. Before R8 `is_known_top_level` had
    // uppercase `PICT` only ⇒ a lowercase `pict` file was rejected.
    let mut data = 16u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"pict");
    data.extend_from_slice(&[0u8; 8]);
    let meta = parse_inner(&data, None).expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
  }

  #[test]
  fn meta_first_atom_is_rejected() {
    // R8/F2 audit: `meta` IS a `%QuickTime::Main` key but is NOT in the
    // `%magicNumber` MOV regex (`ExifTool.pm:995`). A file whose first atom is
    // `meta` is `Unknown file type` — verified vs bundled. Before R8 the port
    // wrongly listed `meta` in `is_known_top_level`.
    let mut data = 16u32.to_be_bytes().to_vec();
    data.extend_from_slice(b"meta");
    data.extend_from_slice(&[0u8; 8]);
    assert!(
      parse_inner(&data, None).is_none(),
      "`meta` is not a magic-regex first atom — must be rejected"
    );
    // `moof` / `udta` likewise: Main keys but not magic atoms.
    for tag in [b"moof", b"udta"] {
      let mut d = 16u32.to_be_bytes().to_vec();
      d.extend_from_slice(tag);
      d.extend_from_slice(&[0u8; 8]);
      assert!(parse_inner(&d, None).is_none());
    }
  }

  #[test]
  fn short_duplicate_mdhd_preserves_earlier_media_duration() {
    // R7/F1: a `trak/mdia` with a FULL mdhd (TimeScale=600, Duration=1200)
    // followed by a SHORT mdhd carrying only version/flags/create/modify +
    // TimeScale=300 (NO Duration field). `MediaDuration`/`MediaTimeScale` are
    // per-track binary-data fields; bundled ExifTool never erases an earlier
    // FoundTag when a later field is absent, so the absent Duration in the
    // short mdhd must NOT clear the earlier 2.00 s while MediaTimeScale still
    // takes the later 300 (last-wins). Verified vs bundled ExifTool:
    // `Track1:MediaDuration = 2.00 s`, `Track1:MediaTimeScale = 300`.
    //
    // mdhd v0 layout: 4 (ver+flags) 4 (create) 4 (modify) 4 (TimeScale)
    // 4 (Duration) 2 (Language) 2 (Quality).
    let mut mdhd_full = vec![0u8; 24];
    wb(&mut mdhd_full, 0, 0); // version 0
    wr(&mut mdhd_full, 12, &600u32.to_be_bytes()); // TimeScale
    wr(&mut mdhd_full, 16, &1200u32.to_be_bytes()); // Duration
    // Short mdhd: only 16 bytes (ver+flags + create + modify + TimeScale),
    // no Duration field present.
    let mut mdhd_short = vec![0u8; 16];
    wb(&mut mdhd_short, 0, 0);
    wr(&mut mdhd_short, 12, &300u32.to_be_bytes()); // TimeScale

    let mdia = atom(b"mdia", &{
      let mut b = atom(b"mdhd", &mdhd_full);
      b.extend_from_slice(&atom(b"mdhd", &mdhd_short));
      b
    });
    let moov = atom(b"moov", &atom(b"trak", &mdia));
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov);

    let meta = parse_inner(&full, None).expect("accepted");
    let track = meta.quicktime().tracks().first().unwrap();
    // MediaTimeScale is last-wins (the field IS present in the short mdhd).
    assert_eq!(track.media_time_scale(), Some(300));
    // MediaDuration is the MediaDuration RawConv (raw / MediaTS), parse-order:
    // the FULL mdhd computed 1200/600 = 2.0; the short mdhd has no Duration so
    // it must NOT erase the earlier 2.0 (R7/F1).
    assert_eq!(track.media_duration_seconds(), Some(2.0));
  }

  #[test]
  fn nested_truncated_mvhd_surfaces_warning() {
    // R7/F2: a truncated `mvhd` CONTAINED inside `moov` — declared size 100
    // (92-byte payload) but only 4 payload bytes present. `walk_atoms` must
    // surface the same `Truncated '...' data (missing N bytes)` warning the
    // top-level loop emits. Verified vs bundled ExifTool:
    // `ExifTool:Warning = "Truncated 'mvhd' data (missing 88 bytes)"`.
    let mut moov_body = 100u32.to_be_bytes().to_vec(); // declared size 100
    moov_body.extend_from_slice(b"mvhd");
    moov_body.extend_from_slice(b"XXXX"); // only 4 of 92 payload bytes
    let moov = atom(b"moov", &moov_body);
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov);

    let meta = parse_inner(&full, None).expect("accepted");
    assert_eq!(
      meta.warning.as_deref(),
      Some("Truncated 'mvhd' data (missing 88 bytes)")
    );
  }

  #[test]
  fn nested_truncated_tkhd_and_mdhd_surface_track_warning() {
    // R7/F2: a `TruncatedAtom` nested two levels deep — a truncated `tkhd`
    // inside `moov/trak`, and a truncated `mdhd` inside `moov/trak/mdia`.
    // ExifTool attaches the `Truncated '...' data` warning to the CURRENT
    // family-1 group, so it surfaces as `Track1:Warning` (NOT the document
    // `ExifTool:Warning`). Verified vs bundled ExifTool.
    // tkhd: declared 90-byte payload, only 4 bytes present ⇒ missing 86.
    let mut trak_body = 98u32.to_be_bytes().to_vec(); // size 98 ⇒ 90 payload
    trak_body.extend_from_slice(b"tkhd");
    trak_body.extend_from_slice(b"XXXX");
    let moov_tkhd = atom(b"moov", &atom(b"trak", &trak_body));
    let mut full_tkhd = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full_tkhd.extend_from_slice(&moov_tkhd);
    let meta = parse_inner(&full_tkhd, None).expect("accepted");
    // The truncation is per-track, NOT a document-level warning.
    assert_eq!(meta.warning, None);
    let track = meta.quicktime().tracks().first().unwrap();
    assert_eq!(track.track_group(), Some(1));
    assert_eq!(
      track.warning(),
      Some("Truncated 'tkhd' data (missing 86 bytes)")
    );

    // mdhd: declared 40-byte payload, only 4 bytes present ⇒ missing 36.
    let mut mdia_body = 48u32.to_be_bytes().to_vec(); // size 48 ⇒ 40 payload
    mdia_body.extend_from_slice(b"mdhd");
    mdia_body.extend_from_slice(b"XXXX");
    let moov_mdhd = atom(b"moov", &atom(b"trak", &atom(b"mdia", &mdia_body)));
    let mut full_mdhd = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full_mdhd.extend_from_slice(&moov_mdhd);
    let meta = parse_inner(&full_mdhd, None).expect("accepted");
    assert_eq!(meta.warning, None);
    let track = meta.quicktime().tracks().first().unwrap();
    assert_eq!(
      track.warning(),
      Some("Truncated 'mdhd' data (missing 36 bytes)")
    );
  }

  #[test]
  fn nested_invalid_mvhd_size_surfaces_document_warning() {
    // R9/F2: a `moov` containing an `mvhd` whose declared `size == 4` is
    // structurally invalid (`< 8`). ExifTool runs the same `ProcessMOV`
    // per-atom loop on the `moov` directory (QuickTime.pm:10035-10075), so the
    // `size < 8` check sets `$warnStr = 'Invalid atom size'` and `last`s; the
    // warning is emitted at the directory exit, attributed to the document
    // (`moov`-level directory ⇒ no family-1 group ⇒ `ExifTool:Warning`).
    // Verified vs bundled. `walk_atoms` previously broke SILENTLY on a
    // contained `Malformed` outcome.
    let mut moov_body = 4u32.to_be_bytes().to_vec(); // mvhd size = 4 (invalid)
    moov_body.extend_from_slice(b"mvhd");
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0");
    full.extend_from_slice(&atom(b"moov", &moov_body));
    let meta = parse_inner(&full, None).expect("accepted");
    assert_eq!(meta.warning.as_deref(), Some("Invalid atom size"));
    // The invalid-size mvhd is never decoded.
    assert_eq!(meta.quicktime().time_scale(), None);
  }

  #[test]
  fn nested_invalid_tkhd_size_surfaces_track_warning() {
    // R9/F2: a `tkhd` with an invalid declared `size == 4` inside `moov/trak`.
    // ExifTool attaches the `Invalid atom size` warning to the CURRENT
    // family-1 group — the enclosing `trak`'s `Track#` — so it surfaces as
    // `Track1:Warning`, NOT the document-level `ExifTool:Warning`. Verified vs
    // bundled.
    let mut trak_body = 4u32.to_be_bytes().to_vec(); // tkhd size = 4 (invalid)
    trak_body.extend_from_slice(b"tkhd");
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0");
    full.extend_from_slice(&atom(b"moov", &atom(b"trak", &trak_body)));
    let meta = parse_inner(&full, None).expect("accepted");
    // Per-track, NOT a document-level warning.
    assert_eq!(meta.warning, None);
    let track = meta.quicktime().tracks().first().unwrap();
    assert_eq!(track.track_group(), Some(1));
    assert_eq!(track.warning(), Some("Invalid atom size"));
  }

  #[test]
  fn two_top_level_moovs_each_trak_both_track1() {
    // R4/F2: two TOP-LEVEL moov atoms, each holding ONE trak. ExifTool's
    // `$track` counter is a `my` local of each moov's ProcessMOV call, so it
    // RESETS to 1 per moov ⇒ BOTH traks are `Track1` (NOT Track1 + Track2).
    // Verified vs bundled (`Track1:TrackID = 1`, second trak dropped on the
    // family-1 collision in default JSON).
    let mk_trak = |track_id: u32, dur: u32| {
      let mut tkhd = vec![0u8; 84];
      wb(&mut tkhd, 0, 0); // version 0
      wr(&mut tkhd, 12, &track_id.to_be_bytes()); // TrackID idx3
      wr(&mut tkhd, 20, &dur.to_be_bytes()); // duration idx5
      atom(b"trak", &atom(b"tkhd", &tkhd))
    };
    let mk_moov = |ts: u32, trak: &[u8]| {
      let mut mvhd = vec![0u8; 100];
      wb(&mut mvhd, 0, 0);
      wr(&mut mvhd, 12, &ts.to_be_bytes()); // TimeScale idx3
      atom(b"moov", &{
        let mut b = atom(b"mvhd", &mvhd);
        b.extend_from_slice(trak);
        b
      })
    };
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&mk_moov(600, &mk_trak(1, 600))); // Track1 (first)
    full.extend_from_slice(&mk_moov(600, &mk_trak(2, 1200))); // Track1 again

    let meta = parse_inner(&full, None).expect("accepted");
    let tracks = meta.quicktime().tracks();
    assert_eq!(tracks.len(), 2, "both traks are decoded into the list");
    // BOTH tracks carry family-1 group Track1 (per-moov reset).
    assert_eq!(tracks.first().unwrap().track_group(), Some(1));
    assert_eq!(tracks.get(1).unwrap().track_group(), Some(1));
    assert_eq!(tracks.first().unwrap().track_id(), Some(1));
    assert_eq!(tracks.get(1).unwrap().track_id(), Some(2));

    // Default JSON: drive the golden engine into the TagMap. BOTH traks emit
    // `Track1:*`; the FIRST moov's `Track1:TrackID` survives at its
    // first-occurrence position (matching bundled `Track1:TrackID = 1`) because
    // the `Taggable` first-wins gate suppresses the second moov's duplicate
    // before it reaches the sink, and NO `Track2` group exists.
    let map = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      map.get_str("Track1", "TrackID").as_deref(),
      Some("1"),
      "first moov's Track1:TrackID wins on the family-1 collision"
    );
    assert!(
      map.get("Track2", "TrackID").is_none(),
      "no Track2 group is emitted (Track# resets per moov)"
    );
  }

  #[test]
  fn media_language_mac_print_conv() {
    // F4: a Macintosh numeric ValueConv goes through ttLang{Macintosh} in the
    // PrintConv (12 => "ar"); an unknown numeric falls to "Unknown ($val)".
    assert_eq!(mac_language_print("12"), "ar");
    assert_eq!(mac_language_print("0"), "en");
    // ttLang{Macintosh}{32} is '' (empty/falsy) ⇒ Unknown (32).
    assert_eq!(mac_language_print("32"), "ru"); // 32 maps to 'ru' in ttLang
    assert_eq!(mac_language_print("999"), "Unknown (999)");
    // A non-numeric ISO 3-letter ValueConv is returned unchanged
    // (`return $val unless $val =~ /^\d+$/`).
    assert_eq!(mac_language_print("eng"), "eng");
  }

  #[test]
  fn duration_value_zero_timescale_emits_bare_value() {
    // F3: a zero TimeScale is falsy in the durationInfo PrintConv gate, so the
    // duration value is the bare raw float (here 1200.0) even in print_conv
    // mode — `TagValue::F64`, NOT a ConvertDuration string.
    use crate::value::TagValue;
    assert_eq!(duration_value(1200.0, Some(0), true), TagValue::F64(1200.0));
    // A non-zero TimeScale runs ConvertDuration in print_conv mode (a Str).
    assert_eq!(
      duration_value(2.0, Some(600), true),
      TagValue::Str(convert_duration(2.0).into())
    );
    assert_ne!(
      duration_value(2.0, Some(600), true),
      TagValue::Str("2".into())
    );
    // A None TimeScale (no mvhd TimeScale at all) also emits the bare value.
    assert_eq!(duration_value(42.0, None, true), TagValue::F64(42.0));
    // `-n` (print_conv=false) is always the bare float regardless of TimeScale.
    assert_eq!(duration_value(2.0, Some(600), false), TagValue::F64(2.0));
  }

  #[test]
  fn media_uid_value_splits_printconv_hex_from_raw() {
    // GoPro MUID (GoPro.pm:456-462): the stored RAW is the space-joined u32
    // list (ExifTool ValueConv). `-j` (PrintConv) hex-renders each `%.8x` and
    // concatenates; `-n` (ValueConv) emits the raw value verbatim. This is
    // the bug fix — bundled `-n` cannot match a pre-hex'd string.
    use crate::value::TagValue;
    // 0x491b313c 0xa89d1416 0xa556fce1 0xd0cc7e5a.
    let raw = "1226518844 2828866582 2773941473 3503062618";
    // `-j` → 32-char concatenated hex.
    assert_eq!(
      media_uid_value(raw, true),
      TagValue::Str("491b313ca89d1416a556fce1d0cc7e5a".into())
    );
    // `-n` → raw space-joined decimal list (NOT hex).
    assert_eq!(media_uid_value(raw, false), TagValue::Str(raw.into()));
  }

  #[test]
  fn unit_suffix_value_matches_perl_string_interpolation() {
    // R6-C: the shared `'"$val <unit>"'` PrintConv (GLPI speeds GoPro.pm:622-624;
    // KBAT A/Ah/C/V/% GoPro.pm:634-648). Oracle (`perl` string-eval): `$val`
    // stringifies via `%.15g` (4.0 → "4", -1.0 → "-1"); `-n` is the raw F64.
    use crate::value::TagValue;
    assert_eq!(
      unit_suffix_value(1.5, " m/s", true),
      TagValue::Str("1.5 m/s".into())
    );
    assert_eq!(
      unit_suffix_value(-1.0, " m/s", true),
      TagValue::Str("-1 m/s".into())
    );
    assert_eq!(
      unit_suffix_value(1.5, " A", true),
      TagValue::Str("1.5 A".into())
    );
    assert_eq!(
      unit_suffix_value(2.0, " Ah", true),
      TagValue::Str("2 Ah".into())
    );
    assert_eq!(
      unit_suffix_value(35.0, " C", true),
      TagValue::Str("35 C".into())
    );
    assert_eq!(
      unit_suffix_value(4.1, " V", true),
      TagValue::Str("4.1 V".into())
    );
    assert_eq!(
      unit_suffix_value(95.0, " %", true),
      TagValue::Str("95 %".into())
    );
    // `-n` (ValueConv) is the raw numeric in every case.
    assert_eq!(unit_suffix_value(1.5, " m/s", false), TagValue::F64(1.5));
    assert_eq!(unit_suffix_value(95.0, " %", false), TagValue::F64(95.0));
  }

  #[test]
  fn battery_time_print_conv_uses_convert_duration_rounded() {
    // R6-C: KBAT BatteryTime PrintConv `ConvertDuration(int($val + 0.5))`
    // (GoPro.pm:642). Oracle (`perl` 13.59): int(36000.5)=36000 → "10:00:00";
    // int(5.5)=5 (<30) → "5.00 s"; int(0.5)=0 → "0 s"; int(90061.5)=90061 →
    // "1 days 1:01:01". The `-j` value is the duration string; `-n` is the raw
    // scaled seconds. (Composition mirrors the in-tags() BatteryTime branch.)
    let pc = |secs: f64| convert_duration((secs + 0.5).trunc());
    assert_eq!(pc(36000.0), "10:00:00");
    assert_eq!(pc(35_999.998_122), "10:00:00");
    assert_eq!(pc(5.0), "5.00 s");
    assert_eq!(pc(0.0), "0 s");
    assert_eq!(pc(90_061.0), "1 days 1:01:01");
  }

  /// Build one GoPro GPMF KLV record (4-byte tag, 1-byte fmt, 1-byte sample
  /// size, big-endian u16 count, payload padded to a 4-byte boundary — the
  /// `ProcessGoPro` header shape, GoPro.pm:831-837).
  fn gpmf_klv(tag: &[u8; 4], fmt: u8, sample_size: u8, count: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag);
    out.push(fmt);
    out.push(sample_size);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
      out.push(0);
    }
    out
  }

  /// Parse a `moov > udta > GPMF` MP4 whose GPMF body is `gpmf_stream`, via the
  /// production entry point. exifast decodes the GLPI/KBAT/SYST complex `?`
  /// records inline from this static-atom path (unlike ExifTool, whose
  /// `ProcessString` pointer cannot reach them through a static `udta` atom —
  /// a pre-existing extraction-path difference, orthogonal to the conversions
  /// under test; SystemTime emits identically through both paths). Leaks the
  /// buffer so the borrowed `Meta` is `'static` for the test.
  fn gpmf_meta(gpmf_stream: &[u8]) -> Meta<'static> {
    let gpmf = atom(b"GPMF", gpmf_stream);
    let udta = atom(b"udta", &gpmf);
    let moov = atom(b"moov", &udta);
    let mut full = atom(b"ftyp", b"mp41\0\0\0\0mp41");
    full.extend_from_slice(&moov);
    let leaked: &'static [u8] = std::boxed::Box::leak(full.into_boxed_slice());
    parse_borrowed(leaked).expect("parsed GPMF fixture")
  }

  /// A `DEVC { STRM { TYPE=LllllsssS, SCAL, GLPI } }` with one GLPI row that
  /// scales to lat 4.2, lon -10.5, alt 1500, spdX 1.5, spdY 2.5, spdZ -1.0,
  /// track 180 (matches the `gopro.rs` GLPI oracle row).
  fn glpi_devc() -> Vec<u8> {
    let type_rec = gpmf_klv(b"TYPE", 0x63, 1, 9, b"LllllsssS");
    let scal_p: Vec<u8> = [
      1000u32, 10_000_000, 10_000_000, 1000, 1000, 100, 100, 100, 100,
    ]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
    let scal = gpmf_klv(b"SCAL", 0x4c, 4, 9, &scal_p);
    let mut row = Vec::new();
    row.extend_from_slice(&5000u32.to_be_bytes()); // systime
    row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat → 4.2
    row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon → -10.5
    row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt → 1500
    row.extend_from_slice(&2000i32.to_be_bytes()); // unk4
    row.extend_from_slice(&150i16.to_be_bytes()); // spdX → 1.5
    row.extend_from_slice(&250i16.to_be_bytes()); // spdY → 2.5
    row.extend_from_slice(&(-100i16).to_be_bytes()); // spdZ → -1.0
    row.extend_from_slice(&18000u16.to_be_bytes()); // track → 180
    let glpi = gpmf_klv(b"GLPI", 0x3f, 28, 1, &row);
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&scal);
    body.extend_from_slice(&glpi);
    let strm = gpmf_klv(b"STRM", 0, 1, body.len() as u16, &body);
    gpmf_klv(b"DEVC", 0, 1, strm.len() as u16, &strm)
  }

  #[test]
  fn gopro_glpi_speeds_honour_conv_mode() {
    // R6-C: GLPI GPSSpeedX/Y/Z PrintConv `'"$val m/s"'` (GoPro.pm:622-624).
    // `-j` → "<v> m/s"; `-n` → raw F64. GPSTrack (col 8) has no PrintConv (raw
    // both modes). Oracle (`perl` ProcessGoPro ValueConv + the `"$val m/s"`
    // string-eval): spd 1.5/2.5/-1 → "1.5 m/s"/"2.5 m/s"/"-1 m/s"; track 180.
    let meta = gpmf_meta(&glpi_devc());
    let pj = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(pj.get_str("GoPro", "GPSSpeedX").as_deref(), Some("1.5 m/s"));
    assert_eq!(pj.get_str("GoPro", "GPSSpeedY").as_deref(), Some("2.5 m/s"));
    assert_eq!(pj.get_str("GoPro", "GPSSpeedZ").as_deref(), Some("-1 m/s"));
    assert_eq!(pj.get_str("GoPro", "GPSTrack").as_deref(), Some("180"));
    let pn = emit_into_tagmap(&meta, crate::emit::ConvMode::ValueConv);
    assert_eq!(pn.get_str("GoPro", "GPSSpeedX").as_deref(), Some("1.5"));
    assert_eq!(pn.get_str("GoPro", "GPSSpeedY").as_deref(), Some("2.5"));
    assert_eq!(pn.get_str("GoPro", "GPSSpeedZ").as_deref(), Some("-1"));
    assert_eq!(pn.get_str("GoPro", "GPSTrack").as_deref(), Some("180"));
  }

  /// A `DEVC { STRM { TYPE=lLlsSSSSSSSBBBb, SCAL(f32), KBAT } }` whose one row
  /// scales to current 1.5 A, capacity 2 Ah, temp 35 C, V1-4 4/4.1/4.2/4.3,
  /// time 36000 s, level 95 % (matches the `gopro.rs` KBAT oracle row).
  fn kbat_devc() -> Vec<u8> {
    let type_rec = gpmf_klv(b"TYPE", 0x63, 1, 15, b"lLlsSSSSSSSBBBb");
    let ks = [
      1000.0f32,
      1000.0,
      0.01,
      100.0,
      1000.0,
      1000.0,
      1000.0,
      1000.0,
      0.016_666_668,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
      1.0,
    ];
    let scal_p: Vec<u8> = ks.iter().flat_map(|v| v.to_be_bytes()).collect();
    let scal = gpmf_klv(b"SCAL", 0x66, 4, 15, &scal_p);
    let mut row = Vec::new();
    row.extend_from_slice(&1500i32.to_be_bytes()); // current → 1.5
    row.extend_from_slice(&2000u32.to_be_bytes()); // capacity → 2
    row.extend_from_slice(&100i32.to_be_bytes()); // unk2 (dropped)
    row.extend_from_slice(&3500i16.to_be_bytes()); // temp → 35
    row.extend_from_slice(&4000u16.to_be_bytes()); // V1 → 4
    row.extend_from_slice(&4100u16.to_be_bytes()); // V2 → 4.1
    row.extend_from_slice(&4200u16.to_be_bytes()); // V3 → 4.2
    row.extend_from_slice(&4300u16.to_be_bytes()); // V4 → 4.3
    row.extend_from_slice(&600u16.to_be_bytes()); // time → 36000 s
    row.extend_from_slice(&88u16.to_be_bytes()); // unk9 (dropped)
    row.extend_from_slice(&7u16.to_be_bytes()); // unk10 (dropped)
    row.push(11); // unk11
    row.push(12); // unk12
    row.push(13); // unk13
    row.extend_from_slice(&95i8.to_be_bytes()); // level → 95
    let kbat = gpmf_klv(b"KBAT", 0x3f, 32, 1, &row);
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&scal);
    body.extend_from_slice(&kbat);
    let strm = gpmf_klv(b"STRM", 0, 1, body.len() as u16, &body);
    gpmf_klv(b"DEVC", 0, 1, strm.len() as u16, &strm)
  }

  #[test]
  fn gopro_kbat_units_and_duration_honour_conv_mode() {
    // R6-C: KBAT unit-suffix PrintConvs (A/Ah/C/V/%, GoPro.pm:634-648) and
    // BatteryTime `ConvertDuration(int($val + 0.5))` (GoPro.pm:642). `-j` →
    // "<v> <unit>" / "10:00:00"; `-n` → raw F64. Oracle: current 1.5 A,
    // capacity 2 Ah, temp 35 C, V1 4 V, V2 4.1 V, level 95 %, time 36000 s →
    // ConvertDuration(36000) = "10:00:00".
    let meta = gpmf_meta(&kbat_devc());
    let pj = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(
      pj.get_str("GoPro", "BatteryCurrent").as_deref(),
      Some("1.5 A")
    );
    assert_eq!(
      pj.get_str("GoPro", "BatteryCapacity").as_deref(),
      Some("2 Ah")
    );
    assert_eq!(
      pj.get_str("GoPro", "BatteryTemperature").as_deref(),
      Some("35 C")
    );
    assert_eq!(
      pj.get_str("GoPro", "BatteryVoltage1").as_deref(),
      Some("4 V")
    );
    assert_eq!(
      pj.get_str("GoPro", "BatteryVoltage2").as_deref(),
      Some("4.1 V")
    );
    assert_eq!(pj.get_str("GoPro", "BatteryLevel").as_deref(), Some("95 %"));
    assert_eq!(
      pj.get_str("GoPro", "BatteryTime").as_deref(),
      Some("10:00:00")
    );
    let pn = emit_into_tagmap(&meta, crate::emit::ConvMode::ValueConv);
    assert_eq!(
      pn.get_str("GoPro", "BatteryCurrent").as_deref(),
      Some("1.5")
    );
    assert_eq!(pn.get_str("GoPro", "BatteryLevel").as_deref(), Some("95"));
    // BatteryTime `-n` is the raw scaled seconds (≈ 36000), NOT the duration.
    let bt: f64 = pn
      .get_str("GoPro", "BatteryTime")
      .as_deref()
      .unwrap()
      .parse()
      .unwrap();
    assert!((bt - 36000.0).abs() < 1.0, "raw scaled seconds, got {bt}");
  }

  /// A `DEVC { STRM { TYPE=JJ, SCAL=1000000 1000, SYST } }` single-row record.
  fn syst_devc_single() -> Vec<u8> {
    let type_rec = gpmf_klv(b"TYPE", 0x63, 1, 2, b"JJ");
    let scal_p: Vec<u8> = [1_000_000u32, 1000]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = gpmf_klv(b"SCAL", 0x4c, 4, 2, &scal_p);
    let mut row = Vec::new();
    row.extend_from_slice(&5_000_000u64.to_be_bytes());
    row.extend_from_slice(&1_551_484_800_000u64.to_be_bytes());
    let syst = gpmf_klv(b"SYST", 0x3f, 16, 1, &row);
    let mut body = Vec::new();
    body.extend_from_slice(&type_rec);
    body.extend_from_slice(&scal);
    body.extend_from_slice(&syst);
    let strm = gpmf_klv(b"STRM", 0, 1, body.len() as u16, &body);
    gpmf_klv(b"DEVC", 0, 1, strm.len() as u16, &strm)
  }

  #[test]
  fn gopro_system_time_emitted_both_modes() {
    // R6-B: `SystemTime` is a DEFAULT tag (no Unknown/Hidden) emitted by
    // `exiftool -ee`. Oracle (real `exiftool -ee -G1` on a moov>udta>GPMF MP4):
    // `GoPro:SystemTime = "5 1551484800"` (the post-SCAL 2-column join) in BOTH
    // `-j` and `-n` (no ValueConv/PrintConv beyond the RawConv pass-through).
    let meta = gpmf_meta(&syst_devc_single());
    for mode in [
      crate::emit::ConvMode::PrintConv,
      crate::emit::ConvMode::ValueConv,
    ] {
      let w = emit_into_tagmap(&meta, mode);
      assert_eq!(
        w.get_str("GoPro", "SystemTime").as_deref(),
        Some("5 1551484800"),
        "SystemTime ({mode:?}) = post-SCAL 2-column join"
      );
    }
  }

  #[test]
  fn handler_type_raw_code_preserved() {
    // F3: distinct hdlr codes are preserved verbatim (not collapsed). A
    // 'mdta' handler keeps its raw code (not normalized to 'meta').
    let mut hdlr = vec![0u8; 24];
    wr(&mut hdlr, 8, b"mdta");
    let mut track = MediaTrack::new();
    track.set_handler_code(decode_hdlr(&hdlr).expect("code"));
    assert_eq!(track.handler_code(), Some("mdta"));
    // The normalized projection kind is still Metadata (for MediaMetadata).
    assert!(track.handler().expect("kind").is_metadata());
  }

  // ---------- golden-pattern `Taggable` / `Project` surface --------------

  /// Parse the `QuickTime_sp1.mov` fixture (a two-track MOV: a 1920×1080 video
  /// track + an audio track, 30 s, `qt  ` major brand) through the production
  /// entry point — the shared input for the golden-pattern tests below.
  fn sp1_meta() -> Meta<'static> {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/QuickTime_sp1.mov"),
    )
    .expect("read QuickTime_sp1.mov fixture");
    // `Meta` owns its data (phantom `'a`); leak the buffer so the returned
    // `Meta` is `'static` for the test helper (the process exits after tests).
    let leaked: &'static [u8] = std::boxed::Box::leak(bytes.into_boxed_slice());
    parse_borrowed(leaked).expect("parsed")
  }

  #[test]
  fn taggable_emits_main_atoms_printconv() {
    // `-j`: representative ftyp/mvhd/mdat atoms render their PrintConv forms,
    // byte-identical to the `QuickTime_sp1.mov.json` golden.
    let meta = sp1_meta();
    let w = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    // MajorBrand %ftypLookup PrintConv (qt  ⇒ the Apple description).
    assert_eq!(
      w.get_str("QuickTime", "MajorBrand").as_deref(),
      Some("Apple QuickTime (.MOV/QT)")
    );
    assert_eq!(
      w.get_str("QuickTime", "MinorVersion").as_deref(),
      Some("0.2.0")
    );
    // Duration durationInfo PrintConv (ConvertDuration vs the 600 TimeScale).
    assert_eq!(
      w.get_str("QuickTime", "Duration").as_deref(),
      Some("0:00:30")
    );
    // PreferredVolume PrintConv sprintf("%.2f%%", $val*100).
    assert_eq!(
      w.get_str("QuickTime", "PreferredVolume").as_deref(),
      Some("100.00%")
    );
    assert_eq!(w.get_str("QuickTime", "TimeScale").as_deref(), Some("600"));
    assert_eq!(
      w.get_str("QuickTime", "MediaDataSize").as_deref(),
      Some("16")
    );
  }

  #[test]
  fn taggable_emits_compatible_brands_list() {
    // The CompatibleBrands List tag is ONE EmittedTag carrying a
    // `TagValue::List` of per-brand `TagValue::Str` (byte-identical to the
    // retired `write_str_list`) — identical under `-j` and `-n`.
    use crate::emit::{ConvMode, Taggable};
    use crate::value::TagValue;
    let meta = sp1_meta();
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let list = meta
        .tags(crate::emit::EmitOptions::g1(mode, false))
        .find(|t| t.tag().name() == "CompatibleBrands")
        .expect("CompatibleBrands emitted");
      assert_eq!(
        list.tag().value_ref(),
        &TagValue::List(std::vec![TagValue::Str("qt  ".into())]),
        "CompatibleBrands is a single List value of the brand strings"
      );
      assert_eq!(list.tag().group_ref().family1(), "QuickTime");
      assert!(!list.unknown());
    }
  }

  #[test]
  fn taggable_emits_raw_values_valueconv() {
    // `-n`: the SAME atoms render their post-ValueConv raw scalars,
    // byte-identical to the `QuickTime_sp1.mov.n.json` golden.
    let meta = sp1_meta();
    let w = emit_into_tagmap(&meta, crate::emit::ConvMode::ValueConv);
    // MajorBrand -n is the raw 4-byte brand string (no %ftypLookup).
    assert_eq!(
      w.get_str("QuickTime", "MajorBrand").as_deref(),
      Some("qt  ")
    );
    // Duration -n is the bare post-ValueConv float seconds.
    assert_eq!(w.get_str("QuickTime", "Duration").as_deref(), Some("30"));
    // PreferredVolume -n is the raw float ($val/256 = 1).
    assert_eq!(
      w.get_str("QuickTime", "PreferredVolume").as_deref(),
      Some("1")
    );
    // Per-track HandlerType -n is the raw 4-byte code.
    assert_eq!(w.get_str("Track1", "HandlerType").as_deref(), Some("vide"));
    assert_eq!(w.get_str("Track2", "HandlerType").as_deref(), Some("soun"));
  }

  #[test]
  fn taggable_emits_per_track_printconv() {
    // `-j`: the per-track family1 = `Track<N>` group carries the tkhd/mdhd/hdlr
    // PrintConv values, byte-identical to the golden's `Track1:`/`Track2:` keys.
    let meta = sp1_meta();
    let w = emit_into_tagmap(&meta, crate::emit::ConvMode::PrintConv);
    assert_eq!(w.get_str("Track1", "TrackID").as_deref(), Some("1"));
    assert_eq!(w.get_str("Track1", "ImageWidth").as_deref(), Some("1920"));
    assert_eq!(w.get_str("Track1", "ImageHeight").as_deref(), Some("1080"));
    assert_eq!(
      w.get_str("Track1", "HandlerType").as_deref(),
      Some("Video Track")
    );
    assert_eq!(
      w.get_str("Track1", "MediaLanguageCode").as_deref(),
      Some("eng")
    );
    assert_eq!(w.get_str("Track2", "TrackID").as_deref(), Some("2"));
    assert_eq!(
      w.get_str("Track2", "HandlerType").as_deref(),
      Some("Audio Track")
    );
  }

  #[test]
  fn taggable_group_family0_quicktime_family1_main_and_track() {
    // family0 = "QuickTime" for EVERY tag (the %QuickTime::Main table group);
    // family1 = "QuickTime" for the main/ftyp/mvhd/mdat atoms and "Track<N>"
    // for the per-track atoms. No tag carries Unknown=>1 in SP1.
    use crate::emit::{ConvMode, Taggable};
    let meta = sp1_meta();
    let tags: std::vec::Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    for t in &tags {
      assert_eq!(
        t.tag().group_ref().family0(),
        "QuickTime",
        "family0 is the %QuickTime::Main table group for every tag"
      );
      assert!(!t.unknown(), "QuickTime SP1 has no Unknown=>1 tags");
      let f1 = t.tag().group_ref().family1();
      assert!(
        f1 == "QuickTime" || f1.starts_with("Track"),
        "family1 is QuickTime or Track<N>, got {f1:?}"
      );
    }
    // The main atoms (first ones emitted) carry family1 "QuickTime".
    assert_eq!(tags.first().unwrap().tag().name(), "MajorBrand");
    assert_eq!(
      tags.first().unwrap().tag().group_ref().family1(),
      "QuickTime"
    );
    // At least one Track1 tag exists with family1 "Track1".
    assert!(
      tags
        .iter()
        .any(|t| t.tag().group_ref().family1() == "Track1"),
      "the video track emits under family1 Track1"
    );
  }

  #[test]
  fn project_reuses_from_quicktime() {
    // `Project::project` reuses `MediaMetadata::from_quicktime` against the
    // wrapped `QuickTimeMeta`: duration (30 s), the primary video track's
    // dimensions (1920×1080), and BOTH track kinds (video + audio).
    use crate::metadata::{Project, TrackKind};
    let meta = sp1_meta();
    let projected = meta.project();
    // Identical to the pre-existing `media_metadata` convenience accessor.
    let via_accessor = meta.media_metadata();
    assert_eq!(
      projected.media().duration(),
      via_accessor.media().duration()
    );
    assert_eq!(projected.media().width(), via_accessor.media().width());

    // 30 s movie duration (mvhd Duration 18000 / TimeScale 600).
    assert_eq!(
      projected.media().duration(),
      Some(core::time::Duration::from_secs(30))
    );
    // Primary (video) track tkhd dimensions.
    assert_eq!(projected.media().width(), Some(1920));
    assert_eq!(projected.media().height(), Some(1080));
    // mvhd CreateDate.
    assert_eq!(
      projected.media().created(),
      Some("2024:01:02 03:04:05+00:00")
    );
    // Both track kinds, in track order (video then audio).
    assert_eq!(
      projected.media().track_kinds(),
      &[TrackKind::Video, TrackKind::Audio]
    );
    assert!(projected.media().has_video());
    assert!(projected.media().has_audio());
    // SP1 carries no camera / lens / GPS / capture facts.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  #[test]
  fn deeply_nested_atoms_do_not_overflow_the_stack() {
    // Golden-v2 Contract 3a — a hostile file can nest container atoms
    // arbitrarily deep. The production walk recurses on `trak`/`mdia` (and
    // the freeGPS / embedded-Exif scans recurse on `udta`/`meta`); a
    // closure that re-enters `walk_atoms` per nested container is exactly
    // that pattern. Without a recursion budget this blows the stack
    // (a DoS); with `MAX_ATOM_DEPTH` the walk simply stops at the cap and
    // returns. The nesting here (100_000) is a superset of any real file's
    // single-digit nesting, so the cap never triggers on a real input.
    const N: usize = 100_000;
    // Build N nested `moov` containers: innermost is an 8-byte empty `moov`,
    // each outer frame wraps the previous one's bytes.
    let mut buf = atom(b"moov", &[]);
    for _ in 1..N {
      buf = atom(b"moov", &buf);
    }

    // A recursive walker mirroring the production `walk_trak`/`mdia` shape:
    // each nested `moov` re-enters `walk_atoms` at `depth + 1`.
    fn recurse(depth: u32, body: &[u8], count: &mut u64) {
      walk_atoms(depth, body, 0, body.len(), &mut None, |inner, ibody, _w| {
        if &inner.atom_type == b"moov" {
          *count += 1;
          recurse(depth + 1, ibody, count);
        }
      });
    }

    let mut count = 0u64;
    recurse(0, &buf, &mut count);
    // The budget bounds the walk; at least one container was visited and we
    // returned without overflowing.
    assert!(count >= 1, "expected to visit at least one nested moov");
    assert!(
      count <= u64::from(MAX_ATOM_DEPTH),
      "the recursion budget must cap the walk at MAX_ATOM_DEPTH containers"
    );
  }

  /// Build a GPMF KLV record (8-byte header + value, 4-byte-aligned).
  fn klv(tag: &[u8; 4], fmt: u8, len: u8, count: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(tag);
    v.push(fmt);
    v.push(len);
    v.extend_from_slice(&count.to_be_bytes());
    v.extend_from_slice(value);
    while v.len() % 4 != 0 {
      v.push(0);
    }
    v
  }

  /// A GPMF payload = one `DEVC` (fmt-0) container holding a single `DVNM`
  /// (DeviceName, ASCII) record with `name`.
  fn devc_dvnm(name: &[u8]) -> Vec<u8> {
    let dvnm = klv(b"DVNM", 0x63, 1, name.len() as u16, name);
    klv(b"DEVC", 0x00, 1, dvnm.len() as u16, &dvnm)
  }

  /// **R7/F1 (now via the integrated `walk_moov`)** — a `udta/GPMF` carried by
  /// a LATER top-level `moov` (the FIRST `moov` has none) is still extracted.
  /// `extract_stream`'s top-level loop runs `walk_moov` per `moov` in file
  /// order, and `walk_moov`'s `udta` arm dispatches the GPMF — so the GoPro
  /// `DeviceName` decodes end-to-end and `FoundEmbedded` is set.
  #[test]
  fn moov_udta_gpmf_visits_a_later_moov() {
    let gpmf = devc_dvnm(b"Hero8 Black");
    let udta = atom(b"udta", &atom(b"GPMF", &gpmf));
    // moov1: an `mvhd`-only movie with NO udta/GPMF.
    let moov1 = atom(b"moov", &atom(b"mvhd", &[0u8; 4]));
    // moov2: carries the GoPro udta/GPMF.
    let moov2 = atom(b"moov", &udta);
    let mut data = atom(b"ftyp", b"qt  ");
    data.extend_from_slice(&moov1);
    data.extend_from_slice(&moov2);

    let mut meta = GoProMeta::new();
    let (_stream, found_embedded) = quicktime_stream::extract_stream(
      &data,
      None,
      None,
      &mut meta,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert_eq!(meta.device_name(), Some("Hero8 Black"));
    assert!(
      found_embedded,
      "a dispatched udta/GPMF sets FoundEmbedded (GoPro.pm:822)"
    );
  }

  /// The integrated `walk_moov` accumulates EVERY `moov/udta/GPMF` across
  /// MULTIPLE `moov` in atom-list ORDER (first moov before later moov), so the
  /// scalar `DeviceName` is last-wins on the LATER moov — mirroring ExifTool's
  /// per-atom `HandleTag` accumulation (default same-priority overwrite).
  #[test]
  fn moov_udta_gpmf_accumulates_in_order() {
    let moov1 = atom(
      b"moov",
      &atom(b"udta", &atom(b"GPMF", &devc_dvnm(b"First"))),
    );
    let moov2 = atom(
      b"moov",
      &atom(b"udta", &atom(b"GPMF", &devc_dvnm(b"Second"))),
    );
    let mut data = atom(b"ftyp", b"qt  ");
    data.extend_from_slice(&moov1);
    data.extend_from_slice(&moov2);

    let mut meta = GoProMeta::new();
    let _ = quicktime_stream::extract_stream(
      &data,
      None,
      None,
      &mut meta,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert_eq!(
      meta.device_name(),
      Some("Second"),
      "last GPMF (later moov, file order) wins the scalar DeviceName"
    );
  }

  /// **R8-A** — `GPMF` is dispatched ONLY through `moov/udta/GPMF` (the
  /// UserData table, QuickTime.pm:1585/2132); a *direct* `moov/GPMF` child is
  /// NEVER processed by ExifTool's `for(;;)` walk (the top-level Movie table
  /// has no `GPMF` entry). The integrated `walk_moov` only fires its GPMF
  /// dispatch from the `udta` arm, so in a single `moov` carrying BOTH a
  /// `udta/GPMF` and a direct `moov/GPMF`, the `udta` device-name wins
  /// REGARDLESS of which child comes first. Oracle-verified vs ExifTool 13.59
  /// (`-ee -DeviceName`): both layouts report the `udta` name.
  #[test]
  fn moov_udta_gpmf_ignores_direct_moov_gpmf() {
    let g_udta = devc_dvnm(b"XfromUDTA");
    let g_direct = devc_dvnm(b"YfromDIRECT");

    // Layout 1: udta/GPMF FIRST, then direct moov/GPMF.
    let moov_a = atom(
      b"moov",
      &[
        atom(b"mvhd", &[0u8; 4]),
        atom(b"udta", &atom(b"GPMF", &g_udta)),
        atom(b"GPMF", &g_direct),
      ]
      .concat(),
    );
    let mut data_a = atom(b"ftyp", b"qt  ");
    data_a.extend_from_slice(&moov_a);
    let mut meta_a = GoProMeta::new();
    let _ = quicktime_stream::extract_stream(
      &data_a,
      None,
      None,
      &mut meta_a,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert_eq!(
      meta_a.device_name(),
      Some("XfromUDTA"),
      "udta wins; direct moov/GPMF ignored (oracle: exiftool 13.59 -ee -DeviceName)"
    );

    // Layout 2: direct moov/GPMF FIRST, then udta/GPMF — same result.
    let moov_b = atom(
      b"moov",
      &[
        atom(b"mvhd", &[0u8; 4]),
        atom(b"GPMF", &g_direct),
        atom(b"udta", &atom(b"GPMF", &g_udta)),
      ]
      .concat(),
    );
    let mut data_b = atom(b"ftyp", b"qt  ");
    data_b.extend_from_slice(&moov_b);
    let mut meta_b = GoProMeta::new();
    let _ = quicktime_stream::extract_stream(
      &data_b,
      None,
      None,
      &mut meta_b,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert_eq!(
      meta_b.device_name(),
      Some("XfromUDTA"),
      "udta wins regardless of atom order (oracle: exiftool 13.59)"
    );
  }

  /// The single-moov `udta/GPMF` path is unchanged (no regression).
  #[test]
  fn moov_udta_gpmf_single_moov() {
    let moov = atom(
      b"moov",
      &atom(b"udta", &atom(b"GPMF", &devc_dvnm(b"Hero6 Black"))),
    );
    let mut data = atom(b"ftyp", b"qt  ");
    data.extend_from_slice(&moov);
    let mut meta = GoProMeta::new();
    let (_stream, found_embedded) = quicktime_stream::extract_stream(
      &data,
      None,
      None,
      &mut meta,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert_eq!(meta.device_name(), Some("Hero6 Black"));
    assert!(found_embedded);
  }

  /// A file with no `moov`/`GPMF` yields nothing (and does not panic on a
  /// truncated tail). `FoundEmbedded` stays false (no GoPro source dispatched).
  #[test]
  fn moov_udta_gpmf_none_and_truncation_safe() {
    let data = atom(b"ftyp", b"qt  ");
    let mut meta = GoProMeta::new();
    let (_stream, found_embedded) = quicktime_stream::extract_stream(
      &data,
      None,
      None,
      &mut meta,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert!(meta.is_empty());
    assert!(!found_embedded);

    // A `moov` whose declared size overruns the buffer must stop the walk
    // without panicking (checked `.get()`).
    let mut trunc = Vec::new();
    trunc.extend_from_slice(&1000u32.to_be_bytes());
    trunc.extend_from_slice(b"moov");
    trunc.extend_from_slice(b"\x00\x00\x00\x10udta"); // truncated body
    let mut meta2 = GoProMeta::new();
    let _ = quicktime_stream::extract_stream(
      &trunc,
      None,
      None,
      &mut meta2,
      &mut crate::metadata::CammMeta::new(),
      &mut crate::metadata::SonyRtmdMeta::new(),
      &mut crate::metadata::CanonCtmdMeta::new(),
    );
    assert!(meta2.is_empty());
  }

  // ===========================================================================
  // Golden-v2 robustness contracts — box/atom walker hardening (SP2 Part 3)
  // ===========================================================================

  /// A minimal valid v0 `mvhd` payload (100 bytes) carrying `TimeScale` and
  /// `Duration`, used to assert "tags decoded before a malformed sibling are
  /// preserved" (Contract 2 — do NOT drop tags already extracted).
  fn mvhd_ts_dur(ts: u32, dur: u32) -> Vec<u8> {
    let mut v = 108u32.to_be_bytes().to_vec(); // size word (8 + 100 payload)
    v.extend_from_slice(b"mvhd");
    let mut payload = vec![0u8; 100];
    wr(&mut payload, 12, &ts.to_be_bytes()); // TimeScale @ idx 3
    wr(&mut payload, 16, &dur.to_be_bytes()); // Duration  @ idx 4
    v.extend_from_slice(&payload);
    v
  }

  /// Wrap a `moov(body)` behind a recognized `ftyp` so [`parse_inner`] accepts
  /// the file (the first-atom gate keys on the 4-cc only).
  fn file_with_moov(moov_body: &[u8]) -> Vec<u8> {
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&atom(b"moov", moov_body));
    full
  }

  /// **Contract 2 (recovery Step + tags-before-corruption preserved).** A valid
  /// `mvhd` followed by a malformed sibling: the `mvhd`-derived `TimeScale` /
  /// `Duration` MUST survive (the walk stops at the bad atom but keeps what it
  /// already decoded), faithful to ExifTool's `last`-after-extract.
  ///
  /// **Diagnostics faithfulness (Contract 4).** A BARE trailing 8-byte
  /// malformed header after a prior atom is the directory boundary to ExifTool
  /// (the loop terminates BEFORE the size check), so it emits NO warning —
  /// across `size` `1..=7`, `size == 0`, a truncated `size == 1` extended
  /// header, and a `>EOF` size. Each row here was verified against bundled
  /// ExifTool 13.59 (`moov(mvhd, <trailer>)` ⇒ the listed warning/none).
  #[test]
  fn valid_tags_survive_trailing_malformed_sibling() {
    let hdr = |sz: u32, t: &[u8; 4]| {
      let mut v = sz.to_be_bytes().to_vec();
      v.extend_from_slice(t);
      v
    };
    // (trailer bytes, expected document warning) — oracle-verified, ExifTool 13.59.
    let bare_none: &[(Vec<u8>, Option<&str>)] = &[
      (hdr(0, b"free"), None),   // size-0 terminator
      (hdr(1, b"junk"), None),   // truncated extended-size header, bare
      (hdr(2, b"junk"), None),   // invalid size, bare trailing
      (hdr(4, b"junk"), None),   // invalid size, bare trailing
      (hdr(7, b"junk"), None),   // invalid size, bare trailing
      (hdr(200, b"free"), None), // declared payload overruns EOF, bare trailing
    ];
    for (trailer, expect) in bare_none {
      let mut body = mvhd_ts_dur(1000, 5000);
      body.extend_from_slice(trailer);
      let file = file_with_moov(&body);
      let meta = parse_inner(&file, None).expect("accepted");
      // Tags decoded BEFORE the malformed atom are preserved (Contract 2).
      assert_eq!(
        meta.quicktime().time_scale(),
        Some(1000),
        "TimeScale must survive the trailing malformed atom"
      );
      assert_eq!(meta.quicktime().duration_count(), Some(5000));
      assert_eq!(meta.quicktime().movie_header_version(), Some(0));
      // …and the bare trailing malformed header emits NO spurious warning.
      assert_eq!(meta.warning.as_deref(), *expect, "trailer {trailer:02x?}");
    }

    // A malformed atom WITH a body (`end - pos > 8`) after the valid mvhd IS a
    // real atom to ExifTool ⇒ it warns `Invalid atom size` (and still keeps the
    // mvhd tags). Verified vs bundled.
    let mut with_body = mvhd_ts_dur(1000, 5000);
    with_body.extend_from_slice(&hdr(4, b"junk"));
    with_body.extend_from_slice(&[0xAA; 4]); // one+ body byte past the header
    let file = file_with_moov(&with_body);
    let meta = parse_inner(&file, None).expect("accepted");
    assert_eq!(meta.quicktime().time_scale(), Some(1000));
    assert_eq!(meta.warning.as_deref(), Some("Invalid atom size"));
  }

  /// The bare-trailing suppression must NOT swallow a malformed FIRST atom
  /// (`pos == start`): ExifTool reads the first header before the loop body, so
  /// an invalid first-atom size still warns. (Guards the `pos > start` half of
  /// [`is_bare_trailing_header`].) Verified vs bundled ExifTool 13.59.
  #[test]
  fn malformed_first_child_still_warns_despite_bare_trailing_rule() {
    let first = |sz: u32, t: &[u8; 4], expect: Option<&str>| {
      let mut body = sz.to_be_bytes().to_vec();
      body.extend_from_slice(t);
      let file = file_with_moov(&body);
      let meta = parse_inner(&file, None).expect("accepted");
      assert_eq!(meta.warning.as_deref(), expect, "first child size={sz}");
      // The invalid-size atom is never decoded.
      assert_eq!(meta.quicktime().time_scale(), None);
    };
    first(4, b"junk", Some("Invalid atom size"));
    first(7, b"junk", Some("Invalid atom size"));
    first(1, b"junk", Some("Truncated atom header"));
    first(
      200,
      b"free",
      Some("Truncated 'free' data (missing 192 bytes)"),
    );
  }

  /// [`is_bare_trailing_header`] truth table (unit-level): only a post-first
  /// header (`pos > start`) with exactly the 8-byte remainder (`end - pos == 8`)
  /// is the directory's bare trailing header.
  #[test]
  fn bare_trailing_header_predicate() {
    assert!(is_bare_trailing_header(108, 0, 116)); // after a prior atom, 8 bytes left
    assert!(!is_bare_trailing_header(0, 0, 8)); // FIRST atom, even if 8 bytes
    assert!(!is_bare_trailing_header(108, 0, 120)); // 12 bytes left ⇒ has a body
    assert!(!is_bare_trailing_header(108, 0, 108)); // 0 bytes left (no header)
    assert!(!is_bare_trailing_header(108, 108, 116)); // pos == start (first here)
  }

  /// A VALID `size == 8` trailing atom (header only, ZERO body) after ≥1
  /// already-walked sibling is NOT emitted — ExifTool's `last if $dataPos >=
  /// $dirEnd` (QuickTime.pm:10597, "ignores last value if 0 bytes") fires on the
  /// PRECEDING atom's advance, so the trailing 0-byte atom is never read. The
  /// skip is scoped to the trailing position (`pos > start` + 8-byte remainder):
  /// a FIRST/only empty atom IS still emitted (it is read before the loop body),
  /// and a trailing atom WITH a body is processed normally. Every case below was
  /// verified against bundled ExifTool 13.59.
  #[test]
  fn valid_trailing_empty_udta_atom_is_skipped() {
    use crate::metadata::QuickTimeUserData;

    // `©mak` international-text body: `int16u len`, `int16u lang`, then text.
    let mak = |text: &[u8]| {
      let mut b = (text.len() as u16).to_be_bytes().to_vec();
      b.extend_from_slice(&0u16.to_be_bytes()); // lang 0
      b.extend_from_slice(text);
      atom(b"\xa9mak", &b)
    };
    // A bare size-8 (header-only, zero-body) atom — its declared size word is 8,
    // so `payload_start == payload_end`.
    let bare8 = |t: &[u8; 4]| {
      8u32
        .to_be_bytes()
        .iter()
        .copied()
        .chain(*t)
        .collect::<Vec<u8>>()
    };

    // (1) valid `©mak` THEN a bare trailing empty `CAME`: Make survives, the
    // trailing empty `CAME` emits NO SerialNumberHash (ExifTool: `Make` only).
    let mut body = mak(b"TrailingEmptyTest");
    body.extend_from_slice(&bare8(b"CAME"));
    let mut ud = QuickTimeUserData::new();
    let mut w = None;
    walk_udta(1, &body, &mut w, &mut ud);
    assert_eq!(ud.make(), Some("TrailingEmptyTest"));
    assert_eq!(
      ud.serial_number_hash(),
      None,
      "a bare size-8 trailing CAME must NOT emit SerialNumberHash"
    );
    assert_eq!(w, None, "the trailing empty atom emits no warning");

    // (2) valid `©mak` THEN a trailing `CAME` WITH a body: ExifTool DOES emit
    // the hash (the skip is body-gated, not type-gated) — proves the fix does
    // not over-suppress a real trailing atom.
    let mut body2 = mak(b"TrailingEmptyTest");
    body2.extend_from_slice(&atom(b"CAME", &[0x01, 0x02, 0x03, 0x04]));
    let mut ud2 = QuickTimeUserData::new();
    let mut w2 = None;
    walk_udta(1, &body2, &mut w2, &mut ud2);
    assert_eq!(ud2.make(), Some("TrailingEmptyTest"));
    assert_eq!(
      ud2.serial_number_hash(),
      Some("01020304"),
      "a trailing CAME WITH a body must still emit"
    );

    // (3) a bare empty `CAME` as the FIRST/only atom (`pos == start`): ExifTool
    // reads the first header before the loop body, so it IS emitted (empty hash,
    // `unpack("H*","") == ""`) — the skip must NOT fire here.
    let mut ud3 = QuickTimeUserData::new();
    let mut w3 = None;
    walk_udta(1, &bare8(b"CAME"), &mut w3, &mut ud3);
    assert_eq!(
      ud3.serial_number_hash(),
      Some(""),
      "a FIRST/only empty CAME is still emitted (empty hash)"
    );
  }

  /// **Contracts 1+2+3 (no-panic / bounded / recovery) — malformed-input
  /// matrix.** Every shape the task enumerates is driven through the public
  /// [`parse_inner`] entry: it must return WITHOUT panicking, OOB-indexing, or
  /// looping unboundedly. `parse_inner` returning at all (vs hanging/aborting)
  /// is the bound; the `#![deny(clippy::indexing_slicing)]` on this module plus
  /// the checked `.get()` reads are the no-OOB guarantee. Where a valid prefix
  /// precedes the corruption, the prefix tags are asserted to survive.
  #[test]
  fn malformed_input_matrix_never_panics_and_is_bounded() {
    let mvhd = mvhd_ts_dur(600, 1200);

    // 1) Empty + sub-header buffers (below the 8-byte first-read).
    for n in 0..8usize {
      assert!(parse_inner(&vec![0u8; n], None).is_none(), "len {n}");
    }

    // 2) A recognized first atom (`ftyp`) with a structurally invalid size word
    //    (size in 2..=7) — accepted, warns, no decode, no panic.
    for sz in 2u32..=7 {
      let mut data = sz.to_be_bytes().to_vec();
      data.extend_from_slice(b"ftyp");
      // Pad so the buffer is longer than the 8-byte header.
      data.extend_from_slice(&[0u8; 8]);
      let _ = parse_inner(&data, None); // must not panic
    }

    // 3) size == 0 first atom (extends-to-EOF / terminator) — no panic.
    {
      let mut data = 0u32.to_be_bytes().to_vec();
      data.extend_from_slice(b"moov");
      data.extend_from_slice(&mvhd);
      let _ = parse_inner(&data, None);
    }

    // 4) A `moov` whose declared size FAR exceeds the buffer (size > file): the
    //    top-level TruncatedAtom path records nothing decodable and stops.
    {
      let mut data = atom(b"ftyp", b"qt  \0\0\0\0");
      data.extend_from_slice(&0x7fff_ffffu32.to_be_bytes()); // ~2GB moov
      data.extend_from_slice(b"moov");
      data.extend_from_slice(&mvhd); // only a few real bytes present
      let meta = parse_inner(&data, None).expect("accepted (ftyp recognized)");
      // The overrunning moov is never descended ⇒ no TimeScale.
      assert_eq!(meta.quicktime().time_scale(), None);
    }

    // 5) Garbage 4-cc as the first atom ⇒ rejected (not QuickTime), no panic.
    {
      let data = atom(b"\xff\x00\xee\x01", &[0u8; 16]);
      assert!(parse_inner(&data, None).is_none());
    }

    // 6) Truncated mid-box: a valid `moov`+`mvhd`, then the file is cut in the
    //    middle of a trailing atom's header/body. Walk both halves; the mvhd
    //    tags must survive every cut, and none may panic.
    {
      let mut full = file_with_moov(&mvhd);
      // Append a partial trailing top-level atom header (cut at every length).
      full.extend_from_slice(&[0u8, 0, 1, 0, b'j', b'u']); // 6 of 8 header bytes
      for cut in 8..full.len() {
        let meta = parse_inner(full.get(..cut).unwrap_or_default(), None);
        if let Some(m) = meta {
          // If the moov survived the cut, its mvhd tags are intact.
          if m.quicktime().time_scale().is_some() {
            assert_eq!(m.quicktime().time_scale(), Some(600));
            assert_eq!(m.quicktime().duration_count(), Some(1200));
          }
        }
      }
    }

    // 7) Non-advancing / self-nesting bomb: a `moov` containing a child whose
    //    size word is 8 (header only, zero body) repeated, plus a deeply nested
    //    `udta` chain — both must terminate (the zero-advance break + the
    //    MAX_ATOM_DEPTH cap), not hang.
    {
      // 4096 zero-body `free` atoms inside a moov (each advances by 8; a
      // zero-SIZE one would break — exercised in (3)). Bounded by `end`.
      let mut body = Vec::new();
      for _ in 0..4096 {
        body.extend_from_slice(&8u32.to_be_bytes());
        body.extend_from_slice(b"free");
      }
      let _ = parse_inner(&file_with_moov(&body), None); // returns, no hang

      // A 2000-deep nested `udta` chain (detect_embedded_exif / GPMF scans
      // recurse on udta) — capped by MAX_ATOM_DEPTH, no stack overflow.
      let mut nested = atom(b"udta", &[]);
      for _ in 0..2000 {
        nested = atom(b"udta", &nested);
      }
      let _ = parse_inner(&file_with_moov(&nested), None);
    }
  }

  // ── emit_timed_samples (shared `-ee` Doc<N> emitter) ──────────────────────
  mod emit_timed_samples_tests {
    use super::*;
    use crate::emit::{ConvMode, EmitOptions, EmittedTag};
    use crate::metadata::TimedSample;
    use crate::serialize_key::GroupMode;
    use crate::value::TagValue;

    /// A minimal coordinate-bearing sample: lat + lon only. A `None`-coordinate
    /// fixture is built with `T::no_coord()`.
    struct T {
      lat: Option<f64>,
      lon: Option<f64>,
    }
    impl T {
      const fn fix(lat: f64, lon: f64) -> Self {
        Self {
          lat: Some(lat),
          lon: Some(lon),
        }
      }
      const fn no_coord() -> Self {
        Self {
          lat: None,
          lon: None,
        }
      }
    }
    impl TimedSample for T {
      fn latitude(&self) -> Option<f64> {
        self.lat
      }
      fn longitude(&self) -> Option<f64> {
        self.lon
      }
    }

    /// Two coordinate fixes bracketing one no-coordinate sample (the no-coord
    /// row must be skipped AND not advance the Doc counter).
    fn series() -> [T; 3] {
      [T::fix(1.0, 2.0), T::no_coord(), T::fix(3.0, 4.0)]
    }

    /// A never-called measure-mode renderer (these `T` fixtures carry no
    /// measure-mode column) — exercises the "caller passes a never-called
    /// closure" path.
    fn no_measure(_m: u32, _pc: bool) -> TagValue {
      unreachable!("T samples carry no measure-mode")
    }

    /// The default per-sample altitude renderer for the structural `T` tests
    /// (no altitude column → never invoked). Returns the raw `F64`.
    fn raw_alt<S>(_s: &S, val: f64, _pc: bool) -> TagValue {
      TagValue::F64(val)
    }

    /// A fixed `QuickTime:QuickTime` base group (the moov-level stream form).
    fn group_qt<S>(_s: &S) -> crate::value::Group {
      crate::value::Group::new("QuickTime", "QuickTime")
    }

    /// `extract_embedded=false` ⇒ the emitter writes NOTHING (without `-ee`
    /// ExifTool surfaces no per-sample stream).
    #[test]
    fn ee_disabled_emits_nothing() {
      let samples = series();
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::PrintConv, false),
        true,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      assert!(out.is_empty(), "ee-disabled ⇒ no tags");
    }

    /// Task 10b — at no-`ee` a `GpsSample` whose origin is a top-level magic box
    /// (`Gps0`) emits ONLY physical record 0 FLAT (`doc == 0`, no `Doc<N>`), even
    /// with `-G3` requested; the SECOND magic-box record (physical index 1) is
    /// dropped (truncate-to-first), reproducing ExifTool's `$dirLen = $recLen`.
    /// An `-ee`-only origin (`Kenwood`) in the same series contributes nothing at
    /// no-`ee`.
    #[test]
    fn noee_emits_first_magic_box_fix_flat_only() {
      use crate::metadata::{GpsOrigin, GpsSample};
      let mk = |lat: f64, lon: f64, o: GpsOrigin, idx: Option<u32>| {
        let mut s = GpsSample::new();
        s.set_latitude(Some(lat))
          .set_longitude(Some(lon))
          .set_origin(Some(o))
          .set_magic_box_record_index(idx);
        s
      };
      // Two gps0 records (physical 0 + 1; no-ee → record 0 only, flat) + a
      // Kenwood fix (-ee only, no physical index → dropped at no-ee).
      let samples = [
        mk(1.0, 2.0, GpsOrigin::Gps0, Some(0)),
        mk(3.0, 4.0, GpsOrigin::Gps0, Some(1)),
        mk(9.0, 9.0, GpsOrigin::Kenwood, None),
      ];
      let mut out = std::vec::Vec::new();
      // `-G3` requested + no `-ee`: the emitter must still force the flat,
      // first-wins form (ExifTool opens no `Doc<N>` without `-ee`).
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::with_group_mode(ConvMode::ValueConv, false, GroupMode::G3),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      let lats: std::vec::Vec<(u32, &TagValue)> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| (t.tag().group_ref().doc(), t.tag().value_ref()))
        .collect();
      // Exactly ONE GPSLatitude: physical record 0's fix, at the Main group (doc 0).
      assert_eq!(lats, [(0, &TagValue::F64(1.0))]);
    }

    /// The PHYSICAL-record fix (the confirmed [high] finding): when magic-box
    /// physical record 0 is OUT-OF-RANGE (skipped during decode → no sample with
    /// `magic_box_record_index == 0`) and record 1 is valid (carries index 1):
    ///   - no-`ee` emits NOTHING (record 0 was the only inspected record; the
    ///     truncate-to-first stops there).
    ///   - `-ee -G3` emits the valid record-1 fix at `Doc2` (record 0 consumed a
    ///     doc number via `++DOC_COUNT`-before-skip → `index + 1 == 2`).
    ///   - `-ee -G1` emits the valid record-1 fix collapsed FLAT (`doc == 0`).
    /// Oracle-pinned by `QuickTime_gps0_oor0.mov` in the conformance suite; this
    /// unit test exercises the emitter directly with the post-skip sample shape.
    #[test]
    fn noee_skips_when_physical_record0_out_of_range() {
      use crate::metadata::{GpsOrigin, GpsSample};
      // Only the VALID record survives decoding; it carries PHYSICAL index 1
      // (record 0 was `next`-skipped but still bumped the index).
      let mut rec1 = GpsSample::new();
      rec1
        .set_latitude(Some(33.752))
        .set_longitude(Some(151.205_67))
        .set_origin(Some(GpsOrigin::Gps0))
        .set_magic_box_record_index(Some(1));
      let samples = [rec1];

      // no-`ee` (even with `-G3` requested) ⇒ NOTHING: no sample has physical
      // index 0, so the truncate-to-first surfaces no fix.
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::with_group_mode(ConvMode::ValueConv, false, GroupMode::G3),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      assert!(
        out.is_empty(),
        "no-ee: out-of-range record 0 ⇒ no GPS (truncate-to-first stops at record 0)"
      );

      // `-ee -G3` ⇒ the valid record-1 fix at Doc2 (index 1 + 1).
      let mut out_g3 = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::with_group_mode(ConvMode::ValueConv, true, GroupMode::G3),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out_g3,
      );
      let g3_lats: std::vec::Vec<(u32, &TagValue)> = out_g3
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| (t.tag().group_ref().doc(), t.tag().value_ref()))
        .collect();
      assert_eq!(
        g3_lats,
        [(2, &TagValue::F64(33.752))],
        "-ee -G3: valid record-1 fix lands at Doc2 (record 0 consumed Doc1)"
      );

      // `-ee -G1` ⇒ the valid record-1 fix collapsed flat (doc 0).
      let mut out_g1 = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::ValueConv, true),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out_g1,
      );
      let g1_lats: std::vec::Vec<(u32, &TagValue)> = out_g1
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| (t.tag().group_ref().doc(), t.tag().value_ref()))
        .collect();
      assert_eq!(
        g1_lats,
        [(0, &TagValue::F64(33.752))],
        "-ee -G1: valid record-1 fix collapses to the first-present row (doc 0)"
      );
    }

    /// When a magic-box sample carries a STAMPED global `doc()` (the structural
    /// fix — the decoder now stamps it off the meta-wide counter), the `-ee -G3`
    /// emitter uses it VERBATIM, superseding the legacy `magic_box_record_index +
    /// 1` formula. A deliberately MISMATCHED pair (`doc = 5`, physical index `0`)
    /// pins the precedence: the stamped global ordinal wins, so a magic box that
    /// follows earlier embedded docs in the same file numbers correctly.
    #[test]
    fn stamped_global_doc_supersedes_record_index_at_g3() {
      use crate::metadata::{GpsOrigin, GpsSample};
      let mut s = GpsSample::new();
      s.set_latitude(Some(1.0))
        .set_longitude(Some(2.0))
        .set_origin(Some(GpsOrigin::Gps0))
        .set_magic_box_record_index(Some(0)) // legacy formula would say Doc1
        .set_doc(Some(5)); // global ordinal: this record is the 5th doc in-file
      let samples = [s];
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::with_group_mode(ConvMode::ValueConv, true, GroupMode::G3),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      let g3_docs: std::vec::Vec<u32> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| t.tag().group_ref().doc())
        .collect();
      assert_eq!(
        g3_docs,
        [5],
        "the stamped global doc (5) wins over magic_box_record_index + 1 (1)"
      );
    }

    /// At no-`ee`, a series of ONLY `-ee`-only origins (`MoovGpsBox`) emits
    /// NOTHING — the early-`any` bail keeps the gate closed.
    #[test]
    fn noee_emits_nothing_for_ee_only_origins() {
      use crate::metadata::{GpsOrigin, GpsSample};
      let mut s = GpsSample::new();
      s.set_latitude(Some(1.0))
        .set_longitude(Some(2.0))
        .set_origin(Some(GpsOrigin::MoovGpsBox));
      let samples = [s];
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::ValueConv, false),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      assert!(out.is_empty(), "-ee-only origins ⇒ no no-ee tags");
    }

    /// With `-ee` ON, ALL origins emit and the `Doc<N>` axis is honored —
    /// proving the no-`ee` gate does not perturb the `-ee` path.
    #[test]
    fn ee_on_emits_all_origins_with_doc_axis() {
      use crate::metadata::{GpsOrigin, GpsSample};
      let mk = |lat: f64, lon: f64, o: GpsOrigin| {
        let mut s = GpsSample::new();
        s.set_latitude(Some(lat))
          .set_longitude(Some(lon))
          .set_origin(Some(o));
        s
      };
      let samples = [
        mk(1.0, 2.0, GpsOrigin::Gps0),
        mk(3.0, 4.0, GpsOrigin::Kenwood),
      ];
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::with_group_mode(ConvMode::ValueConv, true, GroupMode::G3),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      let lats: std::vec::Vec<(u32, &TagValue)> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| (t.tag().group_ref().doc(), t.tag().value_ref()))
        .collect();
      // Both fixes, each its own Doc<N> row (Doc1 gps0, Doc2 Kenwood).
      assert_eq!(lats, [(1, &TagValue::F64(1.0)), (2, &TagValue::F64(3.0))]);
    }

    /// `-G1` (the default) ⇒ the doc axis collapses to ONE row per
    /// `(family1, name)`, FIRST-wins: with two fixes, exactly one GPSLatitude
    /// carrying the FIRST fix, at the Main group (`doc == 0`). Rendered in
    /// ValueConv so the value stays the raw `F64` (PrintConv would be the DMS
    /// string — covered by the byte-exact conformance suite).
    #[test]
    fn g1_collapses_to_first_fix_at_doc0() {
      let samples = series();
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::ValueConv, true),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      // Project each GPSLatitude into (doc, value, family1) to assert without
      // panicking `Vec` indexing (clippy `indexing_slicing`).
      let lats: std::vec::Vec<(u32, &TagValue, &str)> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| {
          (
            t.tag().group_ref().doc(),
            t.tag().value_ref(),
            t.tag().group_ref().family1(),
          )
        })
        .collect();
      // -G1 collapses to the FIRST fix: one row, Main group (doc 0).
      assert_eq!(lats, std::vec![(0u32, &TagValue::F64(1.0), "QuickTime")]);
      // Every emitted tag sits at doc 0 under `-G1`.
      assert!(out.iter().all(|t| t.tag().group_ref().doc() == 0));
    }

    /// `-G1` FIRST-wins collapse keeps a column carried ONLY by a LATER fix
    /// (the camm6-after-camm5 GPSMeasureMode case): a series whose first fix has
    /// no GPSDateTime and whose second does still surfaces the second fix's
    /// GPSDateTime (at doc 0), while the COMMON GPSLatitude keeps the FIRST
    /// fix's value.
    #[test]
    fn g1_keeps_later_only_column() {
      use crate::metadata::GpsSample;
      let mut a = GpsSample::new();
      a.set_latitude(Some(1.0)).set_longitude(Some(2.0));
      let mut b = GpsSample::new();
      b.set_latitude(Some(3.0))
        .set_longitude(Some(4.0))
        .set_date_time(Some("2024:02:02 00:00:00Z".into()));
      let samples = [a, b];
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::ValueConv, true),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      // GPSLatitude collapses to the FIRST fix; GPSDateTime (only in fix 2) still
      // appears. Both at doc 0.
      let lat = out
        .iter()
        .find(|t| t.tag().name() == "GPSLatitude")
        .expect("GPSLatitude");
      assert_eq!(lat.tag().value_ref(), &TagValue::F64(1.0));
      assert_eq!(lat.tag().group_ref().doc(), 0);
      let dt = out
        .iter()
        .find(|t| t.tag().name() == "GPSDateTime")
        .expect("GPSDateTime from the later fix must survive the -G1 collapse");
      assert_eq!(
        dt.tag().value_ref(),
        &TagValue::Str("2024:02:02 00:00:00Z".into())
      );
      assert_eq!(dt.tag().group_ref().doc(), 0);
      // Exactly one GPSLatitude (no duplicate at doc 0).
      assert_eq!(
        out
          .iter()
          .filter(|t| t.tag().name() == "GPSLatitude")
          .count(),
        1
      );
    }

    /// `-G3` ⇒ EVERY coordinate fix as its own `Doc<N>` row (Doc1 = first fix,
    /// Doc2 = second). The no-coordinate sample neither emits nor advances `doc`.
    #[test]
    fn g3_emits_each_fix_as_docn() {
      let samples = series();
      let opts = EmitOptions {
        mode: ConvMode::ValueConv,
        extract_embedded: true,
        group_mode: GroupMode::G3,
      };
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        opts,
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      // Doc1 = first fix (lat 1.0); Doc2 = second fix (lat 3.0). The no-coord
      // middle sample did NOT consume a doc number. Project to (doc, value)
      // pairs and assert the whole sequence (no panicking indexing).
      let lats: std::vec::Vec<(u32, &TagValue)> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| (t.tag().group_ref().doc(), t.tag().value_ref()))
        .collect();
      assert_eq!(
        lats,
        std::vec![(1u32, &TagValue::F64(1.0)), (2u32, &TagValue::F64(3.0))],
        "-G3 emits one Doc<N> row per coordinate fix"
      );
    }

    /// The `emit_extra` closure receives the per-fix `Group` (carrying the right
    /// `Doc<N>`) and can push per-source columns; with two `-G3` fixes it fires
    /// once per fix at the matching doc.
    #[test]
    fn emit_extra_runs_per_fix_with_doc_group() {
      let samples = series();
      let opts = EmitOptions {
        mode: ConvMode::ValueConv,
        extract_embedded: true,
        group_mode: GroupMode::G3,
      };
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        |_s| crate::value::Group::new("GoPro", "GoPro"),
        opts,
        false,
        no_measure,
        raw_alt,
        |_s, g, o| {
          o.push(EmittedTag::new(
            g.clone(),
            "GPSSpeed".into(),
            TagValue::F64(99.0),
            false,
          ));
        },
        &mut out,
      );
      // emit_extra fires once per coordinate fix, at the matching Doc<N> and
      // family1. Project to (doc, family1) and assert the sequence.
      let speeds: std::vec::Vec<(u32, &str)> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSSpeed")
        .map(|t| (t.tag().group_ref().doc(), t.tag().group_ref().family1()))
        .collect();
      assert_eq!(speeds, std::vec![(1u32, "GoPro"), (2u32, "GoPro")]);
    }

    /// A GpsSample series exercises the real `TimedSample` impl end-to-end: the
    /// common GPSAltitude / GPSTrack / GPSDateTime columns flow through the
    /// emitter, and a no-coordinate (accelerometer-only) sample still opens its
    /// own `Doc<N>` (faithful to `Process_gsen`/`Process_3gf`).
    #[test]
    fn gps_sample_series_common_columns_g3() {
      use crate::metadata::GpsSample;
      let mut a = GpsSample::new();
      a.set_latitude(Some(10.0))
        .set_longitude(Some(20.0))
        .set_altitude_m(Some(100.0))
        .set_track(Some(45.0))
        .set_date_time(Some("2024:01:01 00:00:00Z".into()));
      let mut accel_only = GpsSample::new();
      accel_only.set_accelerometer(Some("1 2 3".into()));
      let mut b = GpsSample::new();
      b.set_latitude(Some(11.0)).set_longitude(Some(21.0));
      let samples = [a, accel_only, b];

      let opts = EmitOptions {
        mode: ConvMode::ValueConv,
        extract_embedded: true,
        group_mode: GroupMode::G3,
      };
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        opts,
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      // The accelerometer-only sample is EMITTABLE (`Process_gsen`/`Process_3gf`
      // `++DOC_COUNT` + `HandleTag` it without coordinates), so it opens Doc2 and
      // advances the counter — the two coordinate fixes land at Doc1 and Doc3.
      let lat_docs: std::vec::Vec<u32> = out
        .iter()
        .filter(|t| t.tag().name() == "GPSLatitude")
        .map(|t| t.tag().group_ref().doc())
        .collect();
      assert_eq!(lat_docs, std::vec![1u32, 3u32]);
      // Doc1 carries the common columns of the first fix.
      let doc1: std::vec::Vec<&EmittedTag> = out
        .iter()
        .filter(|t| t.tag().group_ref().doc() == 1)
        .collect();
      let alt = doc1
        .iter()
        .find(|t| t.tag().name() == "GPSAltitude")
        .expect("GPSAltitude");
      assert_eq!(alt.tag().value_ref(), &TagValue::F64(100.0));
      let trk = doc1
        .iter()
        .find(|t| t.tag().name() == "GPSTrack")
        .expect("GPSTrack");
      assert_eq!(trk.tag().value_ref(), &TagValue::F64(45.0));
      let dt = doc1
        .iter()
        .find(|t| t.tag().name() == "GPSDateTime")
        .expect("GPSDateTime");
      assert_eq!(
        dt.tag().value_ref(),
        &TagValue::Str("2024:01:01 00:00:00Z".into())
      );
      // The second coordinate fix (Doc3) carries no altitude/track/date_time.
      assert!(
        !out
          .iter()
          .any(|t| t.tag().group_ref().doc() == 3 && t.tag().name() == "GPSAltitude")
      );
    }

    /// lat/lon render mode-dependently: `-j` (PrintConv) → the `GPS::ToDMS`
    /// string with the N/S · E/W hemisphere; `-n` (ValueConv) → the raw decimal
    /// `F64`.
    #[test]
    fn lat_lon_dms_in_print_conv_raw_in_value_conv() {
      let samples = [T::fix(47.6284216666667, -122.165016666667)];
      // -j: DMS strings with hemisphere (S/W for the negative longitude).
      let mut pc = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::PrintConv, true),
        true,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut pc,
      );
      let lat = pc
        .iter()
        .find(|t| t.tag().name() == "GPSLatitude")
        .expect("GPSLatitude");
      assert_eq!(
        lat.tag().value_ref(),
        &TagValue::Str("47 deg 37' 42.32\" N".into())
      );
      let lon = pc
        .iter()
        .find(|t| t.tag().name() == "GPSLongitude")
        .expect("GPSLongitude");
      assert_eq!(
        lon.tag().value_ref(),
        &TagValue::Str("122 deg 9' 54.06\" W".into())
      );
      // -n: raw decimal-degree F64 (no DMS, no hemisphere).
      let mut nc = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::ValueConv, true),
        false,
        no_measure,
        raw_alt,
        |_s, _g, _o| {},
        &mut nc,
      );
      let lat_n = nc
        .iter()
        .find(|t| t.tag().name() == "GPSLatitude")
        .expect("GPSLatitude");
      assert_eq!(lat_n.tag().value_ref(), &TagValue::F64(47.6284216666667));
    }

    /// The measure-mode renderer IS invoked for a source that carries the
    /// column — a CammGpsSample (camm6) series renders `GPSMeasureMode` through
    /// the passed closure.
    #[test]
    fn measure_mode_rendered_for_camm6() {
      use crate::metadata::CammGpsSample;
      let mut s = CammGpsSample::new(6);
      s.set_latitude(Some(37.0))
        .set_longitude(Some(-122.0))
        .set_measure_mode(Some(3));
      let samples = [s];
      let mut out = std::vec::Vec::new();
      emit_timed_samples(
        &samples,
        group_qt,
        EmitOptions::g1(ConvMode::PrintConv, true),
        true,
        camm_gps_measure_mode_value,
        raw_alt,
        |_s, _g, _o| {},
        &mut out,
      );
      let mm = out
        .iter()
        .find(|t| t.tag().name() == "GPSMeasureMode")
        .expect("GPSMeasureMode emitted");
      assert_eq!(
        mm.tag().value_ref(),
        &TagValue::Str("3-Dimensional Measurement".into())
      );
    }

    // ── camm MOTION value rendering + emission ───────────────────────────────

    /// `camm_vec3_value` renders the three `f32` components space-joined via
    /// `%.15g` of each widened to `f64` — byte-exact to the bundled oracle
    /// `"@a"` interpolation (e.g. `AngularVelocity
    /// "0.100000001490116 -0.200000002980232 0.300000011920929"`).
    #[test]
    fn camm_vec3_value_space_joins_with_perl_g() {
      use crate::metadata::CammVector3;
      let v = CammVector3::new(0.1, -0.2, 0.3);
      assert_eq!(
        camm_vec3_value(&v),
        TagValue::Str("0.100000001490116 -0.200000002980232 0.300000011920929".into())
      );
      // Whole numbers print with no fraction (`Position "1 2 3"`).
      let p = CammVector3::new(1.0, 2.0, 3.0);
      assert_eq!(camm_vec3_value(&p), TagValue::Str("1 2 3".into()));
    }

    /// camm1 exposure: `-j` applies `sprintf("%.4g ms", $val*1000)`; `-n` emits
    /// the raw `F64` seconds.
    #[test]
    fn camm_exposure_ms_value_print_vs_raw() {
      // 0.008 s ⇒ "8 ms" at -j, 0.008 at -n.
      assert_eq!(
        camm_exposure_ms_value(0.008, true),
        TagValue::Str("8 ms".into())
      );
      assert_eq!(camm_exposure_ms_value(0.008, false), TagValue::F64(0.008));
      // 0.0015 s ⇒ "1.5 ms".
      assert_eq!(
        camm_exposure_ms_value(0.0015, true),
        TagValue::Str("1.5 ms".into())
      );
    }

    /// `emit_camm_motion` is fully `-ee`-gated: with `-ee` OFF nothing is
    /// emitted (camm is a handler `trak` source — its motion records surface
    /// only under `-ee`, like the GPS camm path).
    #[test]
    fn emit_camm_motion_no_ee_emits_nothing() {
      use crate::metadata::CammVector3;
      let mut v = CammVector3::new(1.0, 2.0, 3.0);
      v.set_track_index(Some(1)).set_doc(Some(1));
      let samples = [v];
      let mut out = std::vec::Vec::new();
      emit_camm_motion(
        &samples,
        CammVector3::doc,
        CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        false,
        |s, g, sc| {
          sc.push(EmittedTag::new(
            g.clone(),
            "Acceleration".into(),
            camm_vec3_value(s),
            false,
          ))
        },
        EmitOptions::with_group_mode(ConvMode::PrintConv, false, GroupMode::G3), // -ee OFF
        &mut out,
      );
      assert!(out.is_empty(), "motion is -ee-only");
    }

    /// `-ee -G3`: each stamped sample is its own `Doc<N>` under its `Track<N>`,
    /// the doc taken VERBATIM from the stamp (GLOBAL ordinal), so a Doc2 motion
    /// record following a Doc1 fix keeps Doc2 (no per-source restart).
    #[test]
    fn emit_camm_motion_g3_uses_stamped_doc_and_track() {
      use crate::metadata::CammVector3;
      let mut a = CammVector3::new(1.0, 1.0, 1.0);
      a.set_track_index(Some(1)).set_doc(Some(2));
      let mut b = CammVector3::new(9.0, 9.0, 9.0);
      b.set_track_index(Some(1)).set_doc(Some(5));
      let samples = [a, b];
      let mut out = std::vec::Vec::new();
      emit_camm_motion(
        &samples,
        CammVector3::doc,
        CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        false,
        |s, g, sc| {
          sc.push(EmittedTag::new(
            g.clone(),
            "Acceleration".into(),
            camm_vec3_value(s),
            false,
          ))
        },
        EmitOptions::with_group_mode(ConvMode::PrintConv, true, GroupMode::G3),
        &mut out,
      );
      let docs: std::vec::Vec<u32> = out.iter().map(|t| t.tag().group_ref().doc()).collect();
      assert_eq!(docs, [2, 5], "stamped global docs used verbatim");
      assert!(
        out
          .iter()
          .all(|t| t.tag().group_ref().family1() == "Track1")
      );
    }

    /// `-ee -G1` two-rule collapse for motion: TWO records sharing ONE doc keep
    /// the LAST (within-doc last-wins); records in SEPARATE docs keep the FIRST
    /// (across-doc first-wins). The same two-rule collapse the camm5 GPS path uses.
    #[test]
    fn emit_camm_motion_g1_within_doc_last_then_across_doc_first() {
      use crate::metadata::CammVector3;
      // Doc1 holds TWO Acceleration packets (1 1 1 then 2 2 2 → last wins);
      // Doc2 holds one (3 3 3 → dropped, Doc1 already committed the name).
      let mut p1 = CammVector3::new(1.0, 1.0, 1.0);
      p1.set_track_index(Some(1)).set_doc(Some(1));
      let mut p2 = CammVector3::new(2.0, 2.0, 2.0);
      p2.set_track_index(Some(1)).set_doc(Some(1));
      let mut p3 = CammVector3::new(3.0, 3.0, 3.0);
      p3.set_track_index(Some(1)).set_doc(Some(2));
      let samples = [p1, p2, p3];
      let mut out = std::vec::Vec::new();
      emit_camm_motion(
        &samples,
        CammVector3::doc,
        CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        false,
        |s, g, sc| {
          sc.push(EmittedTag::new(
            g.clone(),
            "Acceleration".into(),
            camm_vec3_value(s),
            false,
          ))
        },
        EmitOptions::g1(ConvMode::PrintConv, true),
        &mut out,
      );
      let accel: std::vec::Vec<&EmittedTag> = out
        .iter()
        .filter(|t| t.tag().name() == "Acceleration")
        .collect();
      assert_eq!(accel.len(), 1, "one collapsed row");
      assert_eq!(
        accel
          .first()
          .expect("one Acceleration row")
          .tag()
          .value_ref(),
        &TagValue::Str("2 2 2".into()),
        "within Doc1 the SECOND packet wins; Doc2 dropped (across-doc first-wins)"
      );
    }

    /// `-ee -G3`: the camm sample-table `SampleTime`/`SampleDuration` are emitted
    /// AHEAD of the motion payload, under the sample's `Doc<N>`, via the
    /// `ConvertDuration` PrintConv (`"0 s"` / `"1.00 s"` at `-j`). One per camm
    /// sample (the timing the walker stamped); the raw seconds surface at `-n`.
    #[test]
    fn emit_camm_motion_g3_emits_sample_timing_via_convert_duration() {
      use crate::metadata::CammVector3;
      let mut a = CammVector3::new(1.0, 1.0, 1.0);
      a.set_track_index(Some(1))
        .set_doc(Some(1))
        .set_sample_timing(Some(0.0), Some(1.0));
      let samples = [a];
      // -j: ConvertDuration applied.
      let mut out = std::vec::Vec::new();
      emit_camm_motion(
        &samples,
        CammVector3::doc,
        CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        true,
        |s, g, sc| {
          sc.push(EmittedTag::new(
            g.clone(),
            "Acceleration".into(),
            camm_vec3_value(s),
            false,
          ))
        },
        EmitOptions::with_group_mode(ConvMode::PrintConv, true, GroupMode::G3),
        &mut out,
      );
      let rows: std::vec::Vec<(&str, &TagValue, u32)> = out
        .iter()
        .map(|t| {
          (
            t.tag().name(),
            t.tag().value_ref(),
            t.tag().group_ref().doc(),
          )
        })
        .collect();
      assert_eq!(
        rows,
        [
          ("SampleTime", &TagValue::Str("0 s".into()), 1),
          ("SampleDuration", &TagValue::Str("1.00 s".into()), 1),
          ("Acceleration", &TagValue::Str("1 1 1".into()), 1),
        ],
        "timing (ConvertDuration) precedes the motion payload, under the sample's Doc"
      );

      // -n: raw seconds (F64), no ConvertDuration.
      let mut raw = std::vec::Vec::new();
      emit_camm_motion(
        &samples,
        CammVector3::doc,
        CammVector3::track_index,
        |v| (v.sample_time(), v.sample_duration()),
        false,
        |s, g, sc| {
          sc.push(EmittedTag::new(
            g.clone(),
            "Acceleration".into(),
            camm_vec3_value(s),
            false,
          ))
        },
        EmitOptions::with_group_mode(ConvMode::ValueConv, true, GroupMode::G3),
        &mut raw,
      );
      let raw_timing: std::vec::Vec<(&str, &TagValue)> = raw
        .iter()
        .filter(|t| matches!(t.tag().name(), "SampleTime" | "SampleDuration"))
        .map(|t| (t.tag().name(), t.tag().value_ref()))
        .collect();
      assert_eq!(
        raw_timing,
        [
          ("SampleTime", &TagValue::F64(0.0)),
          ("SampleDuration", &TagValue::F64(1.0)),
        ],
        "-n emits raw seconds, no ConvertDuration"
      );
    }
  }

  // ── Sony rtmd `PrintTimeStamp` (0x8507 GPSTimeStamp PrintConv) ─────────────
  // Oracle-pinned against bundled ExifTool 13.59
  // (`Image::ExifTool::GPS::PrintTimeStamp`): the fractional seconds are
  // ROUNDED to microseconds at `-j`; a whole second is unchanged.
  #[cfg(feature = "alloc")]
  #[test]
  fn sony_rtmd_print_time_stamp_rounds_to_microseconds() {
    // >6 fractional digits ⇒ rounded to 6 (the finding-1 case).
    assert_eq!(
      sony_rtmd_print_time_stamp("01:02:03.123456789"),
      "01:02:03.123457"
    );
    // Exactly-6 / fewer digits pass through (no spurious change).
    assert_eq!(
      sony_rtmd_print_time_stamp("01:02:03.1234561"),
      "01:02:03.123456"
    );
    assert_eq!(sony_rtmd_print_time_stamp("10:20:30.5"), "10:20:30.5");
    // A fraction that rounds the seconds up to / past a 2-digit value: the
    // single-digit re-pad (`$s = "0$s" if $s < 10`) and the no-carry behaviour.
    assert_eq!(sony_rtmd_print_time_stamp("00:00:09.9999999"), "00:00:10");
    assert_eq!(sony_rtmd_print_time_stamp("01:02:59.9999996"), "01:02:60");
    // A fraction that rounds down to a whole second drops the decimal entirely
    // (Perl stringifies `3.0` as `3`).
    assert_eq!(sony_rtmd_print_time_stamp("01:02:03.0000001"), "01:02:03");
    // A whole-second timestamp does NOT match the regex ⇒ unchanged.
    assert_eq!(sony_rtmd_print_time_stamp("11:19:15"), "11:19:15");
    assert_eq!(sony_rtmd_print_time_stamp("00:00:00"), "00:00:00");
  }

  // ── Sony rtmd FrameRate / ExposureTime `-n` rational64u rendering ──────────
  // The parser stores `0x8106`/`0x8109` as the raw `rational64u`; the `-n`
  // emission emits `TagValue::Rational`, whose serialized number is
  // `Rational::exiftool_val_str` (ExifTool's `RoundFloat(n/d, 10)` = `%.10g`).
  // Oracle-pinned: bundled `-ee -n` shows `FrameRate 29.97002997` (NOT the
  // 15-digit f64 `29.97002997002997`) and `ExposureTime 0.01666666667`.
  #[test]
  fn sony_rtmd_frame_rate_exposure_n_render_rational_not_f64() {
    use crate::formats::sony_rtmd::process_rtmd;
    use crate::metadata::SonyRtmdMeta;
    // Build a minimal rtmd sample: 0x1c header, then FrameRate 30000/1001 +
    // ExposureTime 1/60.
    let mut records = std::vec::Vec::new();
    // FrameRate 0x8106, len 8, num=30000 den=1001.
    records.extend_from_slice(&[0x81, 0x06, 0x00, 0x08]);
    records.extend_from_slice(&30_000u32.to_be_bytes());
    records.extend_from_slice(&1001u32.to_be_bytes());
    // ExposureTime 0x8109, len 8, num=1 den=60.
    records.extend_from_slice(&[0x81, 0x09, 0x00, 0x08]);
    records.extend_from_slice(&1u32.to_be_bytes());
    records.extend_from_slice(&60u32.to_be_bytes());
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&0x001cu16.to_be_bytes());
    data.extend(core::iter::repeat_n(0u8, 0x1c - 2));
    data.extend_from_slice(&records);

    let mut meta = SonyRtmdMeta::new();
    process_rtmd(&data, &mut meta);
    let cam = meta.samples()[0].camera();

    // The `-n` emission path emits `TagValue::Rational(r)`; its serialized
    // number is `exiftool_val_str()`.
    let fr = cam.frame_rate_rational().expect("frame rate rational");
    assert_eq!(fr.exiftool_val_str(), "29.97002997");
    let et = cam.exposure_time_rational().expect("exposure rational");
    assert_eq!(et.exiftool_val_str(), "0.01666666667");

    // The f64 accessors still derive the quotient for the domain / `-j` path.
    assert!((cam.frame_rate().unwrap() - 30_000.0 / 1001.0).abs() < 1e-9);
    assert!((cam.exposure_time_s().unwrap() - 1.0 / 60.0).abs() < 1e-12);
  }

  // A zero denominator on the rational64u FrameRate stays `undef` at `-n`
  // (ExifTool `n/0` with n==0 ⇒ `undef`), never a NaN — the rational
  // preserves the case the old pre-divided f64 would have lost.
  #[test]
  fn sony_rtmd_frame_rate_zero_denominator_is_undef() {
    use crate::formats::sony_rtmd::process_rtmd;
    use crate::metadata::SonyRtmdMeta;
    let mut records = std::vec::Vec::new();
    records.extend_from_slice(&[0x81, 0x06, 0x00, 0x08]);
    records.extend_from_slice(&0u32.to_be_bytes()); // num = 0
    records.extend_from_slice(&0u32.to_be_bytes()); // den = 0
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&0x001cu16.to_be_bytes());
    data.extend(core::iter::repeat_n(0u8, 0x1c - 2));
    data.extend_from_slice(&records);
    let mut meta = SonyRtmdMeta::new();
    process_rtmd(&data, &mut meta);
    let r = meta.samples()[0]
      .camera()
      .frame_rate_rational()
      .expect("rational stored even with zero denominator");
    assert_eq!(r.exiftool_val_str(), "undef");
  }

  // ── Sony rtmd FrameRate / ExposureTime `-j` zero-denominator value typing ──
  // The `-j` (PrintConv) path must NOT format a zero-denominator rational's
  // NaN/inf quotient as `"NaN"`. Oracle-pinned vs
  // bundled ExifTool 13.59 (`-ee -j`): a `0/0` FrameRate renders the bare
  // number `0.00` (`sprintf("%.2f","undef")` numifies to 0), an `n/0`
  // FrameRate renders the quoted `"Inf"`; ExposureTime passes the
  // `"undef"`/`"inf"` ValueConv word through (`PrintExposureTime` `IsFloat`
  // gate). The serde typing (bare number vs quoted string) is asserted.
  #[cfg(feature = "alloc")]
  #[test]
  fn sony_rtmd_frame_rate_j_zero_denominator_numifies() {
    use crate::value::{Rational, TagValue};
    // `0/0` → `sprintf("%.2f","undef")` → the value-string "0.00". The
    // `TagValue::Str` serializer runs ExifTool's `EscapeJSON` number gate, so
    // "0.00" emits as a BARE JSON NUMBER (0.0) — the value-faithful form the
    // conformance comparator equates to the golden's `0.00`. The crux of the
    // fix: it is a NUMBER, never the quoted `"NaN"` the old `to_f64` path made.
    let v = sony_rtmd_frame_rate_value(Rational::rational64(0, 0), true);
    match &v {
      TagValue::Str(s) => assert_eq!(s.as_str(), "0.00"),
      other => panic!("expected Str(\"0.00\"), got {other:?}"),
    }
    let jv: serde_json::Value =
      serde_json::from_str(&serde_json::to_string(&v).expect("serialize")).expect("json");
    assert_eq!(
      jv,
      serde_json::json!(0.0),
      "0/0 FrameRate -j is the number 0.0"
    );

    // `n/0` (n != 0) → `sprintf("%.2f","inf")` → "Inf" as a JSON STRING.
    let vi = sony_rtmd_frame_rate_value(Rational::rational64(30_000, 0), true);
    match &vi {
      TagValue::Str(s) => assert_eq!(s.as_str(), "Inf"),
      other => panic!("expected Str(\"Inf\"), got {other:?}"),
    }
    assert_eq!(serde_json::to_string(&vi).expect("serialize"), "\"Inf\"");

    // A finite quotient still renders `%.2f` (as the number 29.97).
    let vf = sony_rtmd_frame_rate_value(Rational::rational64(30_000, 1001), true);
    let jf: serde_json::Value =
      serde_json::from_str(&serde_json::to_string(&vf).expect("serialize")).expect("json");
    assert_eq!(jf, serde_json::json!(29.97));
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn sony_rtmd_exposure_time_j_zero_denominator_passes_word_through() {
    use crate::value::{Rational, TagValue};
    // `0/0` → ValueConv "undef" → PrintExposureTime returns it verbatim.
    let v = sony_rtmd_exposure_time_value(Rational::rational64(0, 0), true);
    match &v {
      TagValue::Str(s) => assert_eq!(s.as_str(), "undef"),
      other => panic!("expected Str(\"undef\"), got {other:?}"),
    }
    assert_eq!(serde_json::to_string(&v).expect("serialize"), "\"undef\"");

    // `n/0` → ValueConv "inf" → PrintExposureTime returns it verbatim.
    let vi = sony_rtmd_exposure_time_value(Rational::rational64(1, 0), true);
    assert_eq!(serde_json::to_string(&vi).expect("serialize"), "\"inf\"");

    // A finite quotient → the `1/x` shaping (1/60 → "1/60").
    let vf = sony_rtmd_exposure_time_value(Rational::rational64(1, 60), true);
    assert_eq!(serde_json::to_string(&vf).expect("serialize"), "\"1/60\"");
  }

  #[test]
  fn decode_stsd_meta_format_crafted_overflow_size_preserves_prior() {
    // A crafted entry `size` must not overflow `pos + size`
    // (a usize wrap → potential OOB / panic). The `checked_add` guard breaks on
    // the giant entry while PRESERVING the last-wins format from a valid prior
    // entry. Layout: `[version/flags:4][count:4]` then each entry
    // `[size:4][format:4][reserved:6][data-ref-index:2]…`.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0, 0, 0, 0]); // version/flags
    payload.extend_from_slice(&2u32.to_be_bytes()); // entry count = 2
    // Entry 0: a well-formed 16-byte `mebx` descriptor.
    payload.extend_from_slice(&16u32.to_be_bytes());
    payload.extend_from_slice(b"mebx");
    payload.extend_from_slice(&[0; 8]); // reserved(6) + data-ref-index(2)
    // Entry 1: a crafted `size = 0xffffffff` that would overflow `pos + size`.
    payload.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
    payload.extend_from_slice(b"rtmd");
    // The giant entry overruns → break; the prior `mebx` survives (no panic, no
    // OOB read, no silent override by the unreachable `rtmd`).
    assert_eq!(decode_stsd_meta_format(&payload).as_deref(), Some("mebx"));
  }

  #[test]
  fn decode_stsd_meta_format_crafted_overflow_only_entry_yields_none() {
    // A lone crafted `0xffffffff` entry resolves to no format (the guard breaks
    // before reading the format), with no panic.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    payload.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
    payload.extend_from_slice(b"rtmd");
    assert!(decode_stsd_meta_format(&payload).is_none());
  }
}
