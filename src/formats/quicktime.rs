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

use crate::{
  datetime::{convert_datetime, convert_duration, convert_unix_time},
  format_parser::{FormatParser, parser_sealed},
  formats::quicktime_stream,
  metadata::{MediaTrack, QuickTimeMeta, QuickTimeStreamMeta},
  value::format_g,
};

/// QuickTime epoch offset: seconds between 1904-01-01 (the Mac/QuickTime
/// time zero) and 1970-01-01 (the Unix epoch).
/// `(66 * 365 + 17) * 24 * 3600` — QuickTime.pm:1361.
const QT_EPOCH_OFFSET: i64 = (66 * 365 + 17) * 24 * 3600;

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
  // QuickTime.pm:9973 `($size, $tag) = unpack('Na4', $buff)`.
  let size32 = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
  let mut atom_type = [0u8; 4];
  atom_type.copy_from_slice(&data[pos + 4..pos + 8]);

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
    let hi = u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
    let lo = u32::from_be_bytes([
      data[pos + 12],
      data[pos + 13],
      data[pos + 14],
      data[pos + 15],
    ]);
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
fn walk_atoms(
  data: &[u8],
  start: usize,
  end: usize,
  warning: &mut Option<String>,
  mut f: impl FnMut(&AtomHeader, &[u8], &mut Option<String>),
) {
  let mut pos = start;
  while pos < end {
    match read_atom_header(data, pos, false) {
      Some(HeaderOutcome::Atom(header, next)) => {
        // Clamp the payload to the parent's declared end (a child must not
        // overrun its container).
        if header.payload_end > end {
          f(&header, &data[header.payload_start..end], warning);
          break;
        }
        f(
          &header,
          &data[header.payload_start..header.payload_end],
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
        warning.get_or_insert_with(|| {
          truncated_atom_warning(&atom_type, payload_start, declared_payload_len, end)
        });
        break;
      }
      Some(HeaderOutcome::Malformed { warning: w }) => {
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
  b.get(off..off + 2)
    .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
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
    let raw = i32::from_be_bytes([
      slice[i * 4],
      slice[i * 4 + 1],
      slice[i * 4 + 2],
      slice[i * 4 + 3],
    ]);
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
  let n = u16::from_be_bytes([b[0], b[1]]);
  Some(format!("{n:x}.{:x}.{:x}", b[2], b[3]))
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
  if payload.len() >= 4 {
    qt.set_major_brand(String::from_utf8_lossy(&payload[0..4]).into_owned());
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
    let g = &payload[i..i + 4];
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
  if payload.len() >= 4 {
    // QuickTime.pm:9993 `$ftypLookup{$type}` — SP1 covers the common
    // brands; the full %ftypLookup table is an SP4 item.
    match &payload[0..4] {
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
      if needles.iter().any(|n| payload[i..i + 4] == n[..]) {
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
fn decode_moov_mvhd(payload: &[u8], qt: &mut QuickTimeMeta, warning: &mut Option<String>) {
  walk_atoms(payload, 0, payload.len(), warning, |inner, ibody, _w| {
    if &inner.atom_type == b"mvhd" {
      decode_mvhd(ibody, qt);
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
  walk_atoms(payload, 0, payload.len(), warning, |inner, ibody, _w| {
    if &inner.atom_type == b"trak" {
      track_num += 1; // QuickTime.pm:10354 `++$track`
      let mut track = walk_trak(ibody, movie_ts);
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
fn walk_trak(payload: &[u8], movie_timescale: Option<u32>) -> MediaTrack {
  let mut track = MediaTrack::new();
  let mut track_warning: Option<String> = None;
  walk_atoms(
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
          // mdia contains mdhd + hdlr + minf (QuickTime.pm:7218-7237).
          walk_atoms(body, 0, body.len(), w, |inner, ibody, _w| {
            match &inner.atom_type {
              b"mdhd" => decode_mdhd(ibody, &mut track),
              b"hdlr" => {
                if let Some(code) = decode_hdlr(ibody) {
                  track.set_handler_code(code);
                }
              }
              _ => {}
            }
          });
        }
        _ => {}
      }
    },
  );
  track.set_warning(track_warning);
  track
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
  /// Phantom anchor for the [`FormatParser::Meta`] GAT lifetime.
  _marker: core::marker::PhantomData<&'a ()>,
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
  /// [`crate::metadata::GpsLocation`] from the FIRST embedded
  /// timed-metadata GPS fix. Camera / lens / capture stay `None` for SP2+
  /// and the embedded-Exif hop to fill.
  #[must_use]
  #[inline(always)]
  pub fn media_metadata(&self) -> crate::metadata::MediaMetadata {
    let mut md = crate::metadata::MediaMetadata::from_quicktime(&self.qt);
    // SP3: project the first GPS fix from the embedded timed metadata into
    // the normalized GpsLocation domain.
    if let Some(fix) = self.stream.first_fix() {
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
  type Error = Error;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
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
pub fn parse_borrowed(data: &[u8]) -> Result<Option<Meta<'_>>, Error> {
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
pub fn parse_with_ext<'a>(data: &'a [u8], ext: Option<&str>) -> Result<Option<Meta<'a>>, Error> {
  parse_inner(data, ext)
}

/// Inner parser. Returns `Ok(None)` (Perl `return 0`) when the first
/// top-level atom is not a recognized `%QuickTime::Main` key
/// (QuickTime.pm:9984).
///
/// `ext` is the uppercased `$$et{FILE_EXT}` (ExifTool.pm:2966), used only for
/// the `%useExt` rule (QuickTime.pm:10006-10007).
fn parse_inner<'a>(data: &'a [u8], ext: Option<&str>) -> Result<Option<Meta<'a>>, Error> {
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
    return Ok(None); // QuickTime.pm:9966 `$raf->Read($buff,8) == 8 or return 0`.
  }
  let raw_size32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
  let mut first = [0u8; 4];
  first.copy_from_slice(&data[4..8]);

  // QuickTime.pm:9984 `$$tagTablePtr{$tag} or return 0` — the first top-level
  // atom's 4-byte TYPE must be a recognized Main-table key. Keyed on `$tag`
  // ALONE, never on `$size` (so an invalid/size-0/truncated size still
  // passes if the type is recognized).
  if !is_known_top_level(&first) {
    return Ok(None);
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
        Some(HeaderOutcome::Atom(header, _)) => {
          file_type_from_ftyp(&data[header.payload_start..header.payload_end])
        }
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
  // Pass 1: ftyp + every moov's mvhd (last-wins TimeScale) + mdat.
  let mut qt = QuickTimeMeta::new();
  // R6/F2: the FIRST `ProcessMOV` warning (`ExifTool:Warning` under `-j`).
  let mut warning: Option<String> = None;
  let mut pos = 0usize;
  while pos < data.len() {
    match read_atom_header(data, pos, true) {
      Some(HeaderOutcome::Atom(header, next)) => {
        let body_end = header.payload_end.min(data.len());
        let body = &data[header.payload_start..body_end];
        match &header.atom_type {
          b"ftyp" => decode_ftyp(body, &mut qt),
          b"moov" => decode_moov_mvhd(body, &mut qt, &mut warning),
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
          qt.set_media_data_size(Some((data.len() - payload_start) as u64));
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
          let available = data.len().saturating_sub(payload_start) as u64;
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
  while pos < data.len() {
    // A top-level size-0 atom (`ExtendsToEof`) STOPS the walk with NO payload
    // decoded — never decode `trak`s out of a size-0 `moov` (R4/F1).
    let Some(HeaderOutcome::Atom(header, next)) = read_atom_header(data, pos, true) else {
      break;
    };
    let body_end = header.payload_end.min(data.len());
    let body = &data[header.payload_start..body_end];
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
  let create_date_raw = first_moov_create_date_raw(data);
  let stream = quicktime_stream::extract_stream(data, create_date_raw);

  // **SP3** — embedded Exif/TIFF hop. ExifTool dispatches certain atoms
  // (`QVMI` Casio, `MVTG` FujiFilm, `uuid`-Exif) to
  // `Image::ExifTool::Exif::ProcessExif` (QuickTime.pm:2058-2110). exifast's
  // Exif IFD parser is on the UNMERGED PR #36 (`lib/exif-gps`); detect the
  // block here and DEFER the parse.
  // DEFERRED: wire exif::parse_exif_block once #36 (Exif+GPS) merges.
  let embedded_exif_deferred = detect_embedded_exif(data);

  Ok(Some(Meta {
    qt,
    stream,
    embedded_exif_deferred,
    file_type,
    mime,
    warning,
    _marker: core::marker::PhantomData,
  }))
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
      let body = &data[header.payload_start..header.payload_end.min(data.len())];
      walk_atoms(body, 0, body.len(), &mut None, |inner, ibody, _w| {
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
    let body = &data[header.payload_start..header.payload_end.min(data.len())];
    detected |= match &header.atom_type {
      b"moov" => detect_embedded_exif_in_dir(body),
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
fn detect_embedded_exif_in_dir(body: &[u8]) -> bool {
  let mut found = false;
  walk_atoms(body, 0, body.len(), &mut None, |inner, ibody, _w| {
    found |= match &inner.atom_type {
      // Casio `QVMI` / FujiFilm `MVTG` — standard Exif IFD blocks
      // (QuickTime.pm:2056-2080) — and a bare `Exif`-type atom (TIFF block).
      b"QVMI" | b"MVTG" | b"Exif" => true,
      b"uuid" => is_uuid_exif_payload(ibody),
      // Recurse into nested containers (`udta`, `meta`, `trak`).
      b"udta" | b"meta" | b"trak" => detect_embedded_exif_in_dir(ibody),
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
impl crate::emit::Taggable for Meta<'_> {
  /// Yield `QuickTime:*` / `Track<N>:*` tags in ExifTool's atom-walk order
  /// (mvhd fields, then per-track fields) — the golden-pattern parallel to the
  /// retired inherent `serialize_tags`: the SINK changes (an
  /// [`EmittedTag`](crate::emit::EmittedTag) per value instead of `out.write_*`),
  /// but the per-tag PrintConv/ValueConv branches, the emission ORDER, the
  /// per-track iteration, the first-wins `Track<N>` dedup, and the
  /// `CompatibleBrands` list are preserved VERBATIM.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: family0 = `"QuickTime"` (the `%QuickTime::Main` table group,
  /// QuickTime.pm:1424) for every emitted tag; family1 is `"QuickTime"` for the
  /// main/ftyp/mvhd/mdat atoms and the per-`moov` `Track<N>` string for the
  /// track atoms (QuickTime.pm:1427 `1 => 'Track#'`). Every QuickTime SP1 tag
  /// is a known table key (no `Unknown => 1`) ⇒ `unknown: false`.
  ///
  /// The `ProcessMOV` warning (`Meta::warning`) is NOT part of this stream —
  /// `run_emission` has no warning channel; the `AnyMeta::QuickTime` arm drains
  /// [`Meta::warning`] into `out.write_warning` (R6/F2).
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
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
    }

    // ── SP3: embedded timed-metadata (QuickTimeStream) ─────────────────
    // Golden-pattern parallel to the retired `serialize_tags` SP3 block: the
    // SINK changes (an `EmittedTag` per value rather than `out.write_*`), but
    // the per-tag values and the `QuickTime` family-1 group are preserved
    // VERBATIM. ExifTool emits one `Doc<N>` sub-document per timed sample;
    // exifast's flat TagMap cannot reproduce that JSON shape, so the FIRST GPS
    // fix is summarized under the `QuickTime` group (the typed [`Meta::stream`]
    // accessor exposes the full per-sample list). Faithful to the
    // `%QuickTime::Stream` PrintConv/ValueConv (QuickTimeStream.pl:116-162).
    if let Some(fix) = self.stream.first_fix() {
      // GPSLatitude/GPSLongitude: the `%QuickTime::Stream` PrintConv is
      // `GPS::ToDMS` (QuickTimeStream.pl:116-117) — a GPS-port dependency.
      // The typed layer keeps post-ValueConv decimal degrees; emit those in
      // both modes (the DMS PrintConv is wired with the Exif+GPS port).
      let _ = print_conv;
      if let (Some(lat), Some(lon)) = (fix.latitude(), fix.longitude()) {
        tags.push(EmittedTag::new(
          main(),
          "GPSLatitude".into(),
          TagValue::F64(lat),
          false,
        ));
        tags.push(EmittedTag::new(
          main(),
          "GPSLongitude".into(),
          TagValue::F64(lon),
          false,
        ));
      }
      if let Some(alt) = fix.altitude_m() {
        tags.push(EmittedTag::new(
          main(),
          "GPSAltitude".into(),
          TagValue::F64(alt),
          false,
        ));
      }
      if let Some(spd) = fix.speed_kph() {
        tags.push(EmittedTag::new(
          main(),
          "GPSSpeed".into(),
          TagValue::F64(spd),
          false,
        ));
      }
      if let Some(trk) = fix.track() {
        tags.push(EmittedTag::new(
          main(),
          "GPSTrack".into(),
          TagValue::F64(trk),
          false,
        ));
      }
      if let Some(dt) = fix.date_time() {
        tags.push(EmittedTag::new(
          main(),
          "GPSDateTime".into(),
          TagValue::Str(dt.into()),
          false,
        ));
      }
    }
    // The Apple `mebx` key/value pairs — emitted under the `QuickTime`
    // group by their resolved key name (QuickTimeStream.pl Process_mebx).
    for sample in self.stream.mebx_samples() {
      tags.push(EmittedTag::new(
        main(),
        sample.name().into(),
        TagValue::Str(sample.value().into()),
        false,
      ));
    }
    // Tags from a `mebx` `SubDirectory` key (currently only `smartstyle-info`'s
    // embedded binary PLIST, QuickTime.pm:6847-6852). These were rendered by
    // the nested PLIST `Taggable` stream and stored as fully-typed [`Tag`]s —
    // each KEEPS the PLIST table's family-0 group (`PLIST`) and the camel-cased
    // PLIST key name, faithful to the bundled `-ee -G0`/`-G3` oracle (family-0
    // `PLIST`, document `Doc<N>`). The family-1 group divergence (the oracle
    // re-scopes these to the enclosing `Track<N>`, while exifast's flat TagMap
    // cannot reproduce the per-sample `Doc<N>` shape) is the SAME accepted SP3
    // limitation as the scalar `mebx` pairs above. Emitted verbatim.
    for tag in self.stream.plist_subdir_tags() {
      tags.push(EmittedTag::new(
        tag.group_ref().clone(),
        tag.name().into(),
        tag.value_ref().clone(),
        false,
      ));
    }

    // NOTE: the SP3 embedded-Exif hop deferral warning is NOT part of the
    // `Taggable` stream (`run_emission` has no warning channel). It is drained
    // by the `AnyMeta::QuickTime` arm of `drain_diagnostics`
    // (`format_parser.rs`) alongside the `ProcessMOV` warning.
    tags.into_iter()
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
// `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for QuickTime parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers.
///
/// §5: derived via `thiserror` (`Display` + `core::error::Error` in every
/// feature tier). `#[non_exhaustive]` lets the first real variant land
/// without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

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
    crate::emit::run_emission(meta, mode, &mut w);
    w
  }

  /// Build a 4-byte-size + type atom around `body`.
  fn atom(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let size = (body.len() + 8) as u32;
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(t);
    v.extend_from_slice(body);
    v
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
  fn quicktime_error_is_core_error() {
    fn assert_error<E: core::error::Error>() {}
    assert_error::<Error>();
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
    mvhd_payload[12..16].copy_from_slice(&1000u32.to_be_bytes());
    mvhd_payload[16..20].copy_from_slice(&5000u32.to_be_bytes());
    let moov = atom(b"moov", &atom(b"mvhd", &mvhd_payload));
    // 64-bit mdat: size==1, total = 16 + 32 (fits).
    let mdat = ext_atom64(b"mdat", 16 + 32, &[0xABu8; 32]);
    let mut data = ftyp;
    data.extend_from_slice(&mdat);
    data.extend_from_slice(&moov);

    let meta = parse_inner(&data, None).expect("parse ok").expect("meta");
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

    let meta = parse_inner(&data, None).expect("parse ok").expect("meta");
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
    mvhd_payload[15] = 0; // ts high bytes 0
    mvhd_payload[12] = 0;
    mvhd_payload[13] = 0;
    mvhd_payload[14] = 2;
    mvhd_payload[15] = 88; // TimeScale = 600
    let mvhd = atom(b"mvhd", &mvhd_payload);
    // size-0 moov: 4-byte size 0, type, then payload extends to EOF.
    let mut moov_zero = 0u32.to_be_bytes().to_vec();
    moov_zero.extend_from_slice(b"moov");
    moov_zero.extend_from_slice(&mvhd);
    let mut data = ftyp;
    data.extend_from_slice(&moov_zero);

    let meta = parse_inner(&data, None).expect("parse ok").expect("meta");
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

    let meta = parse_inner(&data, None).expect("parse ok").expect("meta");
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
    mvhd_payload[0] = 0; // version 0
    let mvhd = atom(b"mvhd", &mvhd_payload);
    moov_body.extend_from_slice(&mvhd);
    let mut decoded_mvhd = false;
    let mut warn = None;
    walk_atoms(&moov_body, 0, moov_body.len(), &mut warn, |a, _, _| {
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
    walk_atoms(&moov_body, 0, moov_body.len(), &mut warn, |a, _, _| {
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
    buf[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // a = 1.0
    buf[16..20].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // d = 1.0
    buf[32..36].copy_from_slice(&0x4000_0000u32.to_be_bytes()); // w = 1.0 (2.30)
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
    buf[0..4].copy_from_slice(&1u32.to_be_bytes()); // a (entry 0) = raw 1
    buf[16..20].copy_from_slice(&1u32.to_be_bytes()); // d (entry 4) = raw 1
    buf[32..36].copy_from_slice(&1u32.to_be_bytes()); // w (entry 8) = raw 1
    assert_eq!(
      matrix_structure_string(&buf, 0),
      Some("2e-05 0 0 0 2e-05 0 0 0 1.220703125e-09".to_string())
    );

    // A 0.5 (0x8000) entry rounds exactly (0.5), and a 1.5 (0x18000) too.
    let mut buf2 = vec![0u8; 36];
    buf2[0..4].copy_from_slice(&0x0000_8000u32.to_be_bytes()); // a = 0.5
    buf2[16..20].copy_from_slice(&0x0001_8000u32.to_be_bytes()); // d = 1.5
    buf2[32..36].copy_from_slice(&0x4000_0000u32.to_be_bytes()); // w = 1.0
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
    assert!(parse_inner(&data, None).expect("ok").is_none());
  }

  #[test]
  fn parse_inner_accepts_ftyp_and_resolves_type() {
    let data = atom(b"ftyp", b"M4A \0\0\0\0M4A mp42");
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
    assert_eq!(meta.file_type(), "M4A");
    // MajorBrand keeps the trailing space (the %ftypLookup PrintConv key).
    assert_eq!(meta.quicktime().major_brand(), Some("M4A "));
    // MinorVersion ValueConv from "\0\0\0\0".
    assert_eq!(meta.quicktime().minor_version(), Some("0.0.0"));
    // CompatibleBrands: "M4A " and "mp42" (no NULs ⇒ both kept).
    assert_eq!(meta.quicktime().compatible_brands(), &["M4A ", "mp42"]);
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
      let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let glv = parse_inner(&data, Some("GLV"))
      .expect("ok")
      .expect("accepted");
    assert_eq!(glv.file_type(), "GLV");
    // `%mimeLookup{GLV}` is undef ⇒ the `'video/mp4'` fallback (QuickTime.pm:10008).
    assert_eq!(glv.mime(), "video/mp4");

    // Same bytes, NO `.glv` ext ⇒ MP4 not promoted ⇒ the audio-only MP4→M4A
    // override fires (QuickTime.pm:10619-10624).
    let m4a = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let qt = parse_inner(&qt_data, Some("GLV"))
      .expect("ok")
      .expect("accepted");
    assert_eq!(qt.file_type(), "MOV");
    assert_eq!(qt.mime(), "video/quicktime");
  }

  #[test]
  fn v1_tkhd_dimensions_at_offsets_88_92() {
    // F2: a version-1 tkhd. Lay out create/modify/id/reserved/duration as
    // int64u where the Hook widens, then place ImageWidth/Height at byte
    // offsets 88/92. Verify the decoder reads 1280x720 there (NOT 96/100).
    let mut p = vec![0u8; 104];
    p[0] = 1; // version 1
    // width 1280 (16.16) at offset 88, height 720 at 92.
    p[88..92].copy_from_slice(&(1280u32 << 16).to_be_bytes());
    p[92..96].copy_from_slice(&(720u32 << 16).to_be_bytes());
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
    tkhd[0] = 0; // version 0
    tkhd[20..24].copy_from_slice(&1200u32.to_be_bytes()); // duration idx5
    let trak = atom(b"trak", &atom(b"tkhd", &tkhd));
    let mut mvhd = vec![0u8; 100];
    mvhd[0] = 0;
    mvhd[12..16].copy_from_slice(&600u32.to_be_bytes()); // TimeScale idx3
    mvhd[16..20].copy_from_slice(&3000u32.to_be_bytes()); // Duration idx4
    let mut moov_body = trak.clone();
    moov_body.extend_from_slice(&atom(b"mvhd", &mvhd));
    let data = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    let mut full = data;
    full.extend_from_slice(&atom(b"moov", &moov_body));
    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
    let track = &meta.quicktime().tracks()[0];
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
    tkhd[0] = 0; // version 0
    tkhd[12..16].copy_from_slice(&1u32.to_be_bytes()); // TrackID idx3 = 1
    tkhd[20..24].copy_from_slice(&1200u32.to_be_bytes()); // duration idx5
    let trak = atom(b"trak", &atom(b"tkhd", &tkhd));

    let mut mvhd1 = vec![0u8; 100];
    mvhd1[0] = 0;
    mvhd1[12..16].copy_from_slice(&600u32.to_be_bytes()); // TimeScale idx3
    let moov1 = atom(b"moov", &{
      let mut b = atom(b"mvhd", &mvhd1);
      b.extend_from_slice(&trak);
      b
    });

    let mut mvhd2 = vec![0u8; 100];
    mvhd2[0] = 0;
    mvhd2[12..16].copy_from_slice(&300u32.to_be_bytes()); // TimeScale idx3
    let moov2 = atom(b"moov", &atom(b"mvhd", &mvhd2));

    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov1);
    full.extend_from_slice(&moov2);

    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
    // Final global TimeScale is the SECOND moov's (last-wins).
    assert_eq!(meta.quicktime().time_scale(), Some(300));
    let track = &meta.quicktime().tracks()[0];
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
    mvhd1[0] = 0; // version 0
    mvhd1[12..16].copy_from_slice(&600u32.to_be_bytes()); // TimeScale idx3
    mvhd1[16..20].copy_from_slice(&3000u32.to_be_bytes()); // Duration idx4
    let moov1 = atom(b"moov", &atom(b"mvhd", &mvhd1));
    // A SHORT mvhd: only 16 bytes (version + flags + create + modify + ts),
    // no Duration field present.
    let mut mvhd2 = vec![0u8; 16];
    mvhd2[0] = 0;
    mvhd2[12..16].copy_from_slice(&300u32.to_be_bytes()); // TimeScale idx3
    let moov2 = atom(b"moov", &atom(b"mvhd", &mvhd2));

    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov1);
    full.extend_from_slice(&moov2);

    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
      let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&moov4, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.warning.as_deref(), Some("Truncated atom header"));

    // The same for an extended-size `mdat` first atom.
    let mut mdat = 1u32.to_be_bytes().to_vec();
    mdat.extend_from_slice(b"mdat");
    mdat.extend_from_slice(&[0u8; 3]);
    let meta = parse_inner(&mdat, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&size8, None).expect("ok").expect("accepted");
    assert_eq!(meta.file_type(), "MOV");
    assert_eq!(meta.mime(), "video/quicktime");

    // size=11 ftyp: 8-byte header + a 3-byte payload "qt ".
    let mut size11 = 11u32.to_be_bytes().to_vec();
    size11.extend_from_slice(b"ftyp");
    size11.extend_from_slice(b"qt ");
    let meta = parse_inner(&size11, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&data, None).expect("ok").expect("accepted");
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
      parse_inner(&data, None).expect("ok").is_none(),
      "`meta` is not a magic-regex first atom — must be rejected"
    );
    // `moof` / `udta` likewise: Main keys but not magic atoms.
    for tag in [b"moof", b"udta"] {
      let mut d = 16u32.to_be_bytes().to_vec();
      d.extend_from_slice(tag);
      d.extend_from_slice(&[0u8; 8]);
      assert!(parse_inner(&d, None).expect("ok").is_none());
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
    mdhd_full[0] = 0; // version 0
    mdhd_full[12..16].copy_from_slice(&600u32.to_be_bytes()); // TimeScale
    mdhd_full[16..20].copy_from_slice(&1200u32.to_be_bytes()); // Duration
    // Short mdhd: only 16 bytes (ver+flags + create + modify + TimeScale),
    // no Duration field present.
    let mut mdhd_short = vec![0u8; 16];
    mdhd_short[0] = 0;
    mdhd_short[12..16].copy_from_slice(&300u32.to_be_bytes()); // TimeScale

    let mdia = atom(b"mdia", &{
      let mut b = atom(b"mdhd", &mdhd_full);
      b.extend_from_slice(&atom(b"mdhd", &mdhd_short));
      b
    });
    let moov = atom(b"moov", &atom(b"trak", &mdia));
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&moov);

    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
    let track = &meta.quicktime().tracks()[0];
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

    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&full_tkhd, None)
      .expect("ok")
      .expect("accepted");
    // The truncation is per-track, NOT a document-level warning.
    assert_eq!(meta.warning, None);
    let track = &meta.quicktime().tracks()[0];
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
    let meta = parse_inner(&full_mdhd, None)
      .expect("ok")
      .expect("accepted");
    assert_eq!(meta.warning, None);
    let track = &meta.quicktime().tracks()[0];
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
    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
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
    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
    // Per-track, NOT a document-level warning.
    assert_eq!(meta.warning, None);
    let track = &meta.quicktime().tracks()[0];
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
      tkhd[0] = 0; // version 0
      tkhd[12..16].copy_from_slice(&track_id.to_be_bytes()); // TrackID idx3
      tkhd[20..24].copy_from_slice(&dur.to_be_bytes()); // duration idx5
      atom(b"trak", &atom(b"tkhd", &tkhd))
    };
    let mk_moov = |ts: u32, trak: &[u8]| {
      let mut mvhd = vec![0u8; 100];
      mvhd[0] = 0;
      mvhd[12..16].copy_from_slice(&ts.to_be_bytes()); // TimeScale idx3
      atom(b"moov", &{
        let mut b = atom(b"mvhd", &mvhd);
        b.extend_from_slice(trak);
        b
      })
    };
    let mut full = atom(b"ftyp", b"qt  \0\0\0\0qt  ");
    full.extend_from_slice(&mk_moov(600, &mk_trak(1, 600))); // Track1 (first)
    full.extend_from_slice(&mk_moov(600, &mk_trak(2, 1200))); // Track1 again

    let meta = parse_inner(&full, None).expect("ok").expect("accepted");
    let tracks = meta.quicktime().tracks();
    assert_eq!(tracks.len(), 2, "both traks are decoded into the list");
    // BOTH tracks carry family-1 group Track1 (per-moov reset).
    assert_eq!(tracks[0].track_group(), Some(1));
    assert_eq!(tracks[1].track_group(), Some(1));
    assert_eq!(tracks[0].track_id(), Some(1));
    assert_eq!(tracks[1].track_id(), Some(2));

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
  fn handler_type_raw_code_preserved() {
    // F3: distinct hdlr codes are preserved verbatim (not collapsed). A
    // 'mdta' handler keeps its raw code (not normalized to 'meta').
    let mut hdlr = vec![0u8; 24];
    hdlr[8..12].copy_from_slice(b"mdta");
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
    parse_borrowed(leaked).expect("ok").expect("parsed")
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
        .tags(mode)
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
    let tags: std::vec::Vec<_> = meta.tags(ConvMode::PrintConv).collect();
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
    assert_eq!(tags[0].tag().name(), "MajorBrand");
    assert_eq!(tags[0].tag().group_ref().family1(), "QuickTime");
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
}
