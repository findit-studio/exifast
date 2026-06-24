// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! QuickTime / ISO-BMFF brand-variant container dispatch (SP4).
//!
//! Faithful port of the `ftyp`-driven brand routing layer above the
//! `Image::ExifTool::QuickTime` core walker:
//!
//!  - **`%ftypLookup`** (QuickTime.pm:130-237) — the brand → file-type +
//!    MIME table used by `ProcessMOV` at QuickTime.pm:9986-10008.
//!    Bundled extracts the file extension from the parenthesized
//!    `(.XYZ)` substring in each table value via the regex
//!    `/\(\.(\w+)/` (QuickTime.pm:9993). exifast caches the
//!    pre-computed `(file_type, mime)` pairs in
//!    [`file_type_from_ftyp_brand`] for cycle-free lookup.
//!
//!  - **HEIF / HEIC / AVIF `meta` box** (QuickTime.pm:2834-2916,
//!    9131-9523) — the iinf / iloc / ipma / ipco / iref / pitm
//!    walker that locates per-item Exif/XMP/HEVC/AV1 payloads.
//!    Implemented here in [`walk_heif_meta`] using the typed surface
//!    [`crate::metadata::HeifMeta`].
//!
//!  - **CR3 / CRM (`crx ` brand)** — the Canon UUID atom
//!    `85 c0 b6 87 82 0f 11 e0 81 11 f4 ce 46 2b 6a 48`
//!    (QuickTime.pm:1236-1242) dispatches to `Image::ExifTool::Canon::uuid`
//!    (Canon.pm:9657-9738) — the CNCV `CompressorVersion` flips the
//!    `crx ` brand to either `CR3` or `CRM`, and the CMT1/CMT2/CMT3/
//!    CMT4 children mark per-block TIFF/Exif locations. Implemented in
//!    [`walk_canon_uuid`] using [`crate::metadata::Cr3Meta`].
//!
//!  - **JP2 / JPX / JPM (`jp2 ` / `jpx ` / `jpm ` brands)** — the JPEG
//!    2000 sibling-box walker that follows the 12-byte JP2 signature
//!    (Jpeg2000.pm:1548-1597). Implemented in [`walk_jp2`] using
//!    [`crate::metadata::Jp2Meta`]. The JP2 sub-type is derived from
//!    the inner `ftyp` brand (Jpeg2000.pm:1580-1587); UUID-Exif /
//!    UUID-XMP boxes (Jpeg2000.pm:279-352) are located but their TIFF
//!    bodies are deferred to PR #36.
//!
//! ## Faithfulness mandate
//!
//! Every `match` / brand / box-tag cite includes the bundled QuickTime.pm
//! / Canon.pm / Jpeg2000.pm line range. No new behaviour is introduced
//! beyond what bundled does today — the only Rust-idiomatic divergences
//! are the typed `Cr3Meta`/`HeifMeta`/`Jp2Meta` surfaces (which replace
//! bundled's `$$et{ItemInfo}` / `$$et{save_ftyp}` / `$$et{FileType}`
//! ambient hashes) and SmolStr for ≤32-char strings.
//!
//! ## Where this hooks into `parse_inner`
//!
//! [`brand_dispatch`] is called from `parse_inner` AFTER the `ftyp`
//! brand has been decoded into [`crate::metadata::QuickTimeMeta`] but
//! BEFORE the SP3 timed-metadata extractor runs. It populates per-brand
//! typed metas which then ride out of `parse_inner` on the
//! [`crate::formats::quicktime::Meta`] surface; downstream
//! `MediaMetadata` projection happens via the per-meta
//! [`crate::metadata::MetaProjectInto`] impls.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
  collections::{BTreeMap, BTreeSet},
  string::String,
  vec::Vec,
};

use smol_str::SmolStr;

use crate::formats::quicktime::MAX_ATOM_DEPTH;
use crate::metadata::{
  Cr3Block, Cr3CmtKind, Cr3Meta, HeifExtent, HeifItem, HeifMeta, Jp2Block, Jp2Meta,
};

// ===========================================================================
// %ftypLookup brand → (file_type, MIME)
// ===========================================================================
//
// `ProcessMOV` derives the file type by looking up the brand in
// `%ftypLookup` (QuickTime.pm:130-237), then extracting the parenthesized
// extension from the description string via the regex `/\(\.(\w+)/`
// (QuickTime.pm:9993). The MIME comes from `%mimeLookup`
// (QuickTime.pm:103-126) defaulting to `'video/mp4'`.
//
// exifast pre-computes both lookups into a single brand → (file_type,
// mime) table so the runtime cost is a const-time match.

/// Resolve `(file_type, mime)` for a 4-byte ftyp major brand.
///
/// Faithful to `$ftypLookup{$type} =~ /\(\.(\w+)/` (QuickTime.pm:9993)
/// FOLLOWED BY `SetFileType($fileType, $mimeLookup{$fileType} ||
/// 'video/mp4')` (QuickTime.pm:10008). `None` when the brand has no
/// `%ftypLookup` entry OR its description has no `(.EXT)` substring —
/// in which case `parse_inner` falls through to the compatible-brands
/// scan (`mp41`/`mp42`/`avc1` → MP4, `f4v ` → F4V, `qt  ` → MOV).
///
/// **R6 (SP4).** The returned strings are `&'static str` (the same
/// literal lifetime as the existing `file_type_from_ftyp` returns).
/// All MIME values come from `%mimeLookup` (QuickTime.pm:103-126)
/// EXCEPT the few where the bundled comment listed a different MIME
/// (e.g. `MOV` → `video/quicktime`, `audio/3gpp2` for `3G2` audio
/// brands) — those are preserved verbatim.
#[must_use]
pub const fn file_type_from_ftyp_brand(brand: &[u8; 4]) -> Option<(&'static str, &'static str)> {
  // SP4 brand dispatch begin (QuickTime.pm:130-237 + 103-126).
  Some(match brand {
    // ── 3GPP family ────────────────────────────────────────────────
    b"3g2a" | b"3g2b" | b"3g2c" => ("3G2", "video/3gpp2"),
    // `3ge6`/`3ge7` descriptions DO carry `(.3GP)` (QuickTime.pm:134-135)
    // so they map. `3gg6` (`'3GPP Release 6 General Profile'`,
    // QuickTime.pm:136) has NO `(.EXT)` → falls through (listed in the
    // no-`(.EXT)` block below).
    b"3ge6" | b"3ge7" | b"3gp1" | b"3gp2" | b"3gp3" | b"3gp4" | b"3gp5" | b"3gp6" | b"3gs7" => {
      ("3GP", "video/3gpp")
    }
    // ── Audible ────────────────────────────────────────────────────
    b"aax " => ("AAX", "audio/vnd.audible.aax"),
    // ── Apple iTunes audio/video ──────────────────────────────────
    b"M4A " => ("M4A", "audio/mp4"),
    b"M4B " => ("M4B", "audio/mp4"),
    b"M4P " => ("M4P", "audio/mp4"),
    b"M4V " | b"M4VH" | b"M4VP" => ("M4V", "video/x-m4v"),
    // ── Adobe Flash ───────────────────────────────────────────────
    b"F4A " => ("F4A", "audio/mp4"),
    b"F4B " => ("F4B", "audio/mp4"),
    // QuickTime.pm:172 `'F4P ' => 'Protected Video for Adobe Flash
    // Player 9+ (.F4P)'` — its OWN extension is `F4P`, distinct from
    // `F4V `. MIME = `%mimeLookup` default `video/mp4` (no F4P entry).
    b"F4P " => ("F4P", "video/mp4"),
    b"F4V " => ("F4V", "video/mp4"),
    // ── DVB ───────────────────────────────────────────────────────
    b"dvr1" | b"dvt1" => ("DVB", "video/vnd.dvb.file"),
    // ── JPEG 2000 family ──────────────────────────────────────────
    // QuickTime.pm:184: `'JP2 ' => 'JPEG 2000 Image (.JP2)'`. The
    // brand has a trailing space; the extension is `JP2`.
    b"JP2 " => ("JP2", "image/jp2"),
    b"jpm " => ("JPM", "image/jpm"),
    b"jpx " => ("JPX", "image/jpx"),
    // `mj2s`/`mjp2` are in %ftypLookup (QuickTime.pm:196-197) but their
    // descriptions `'Motion JPEG 2000 [ISO 15444-3] Simple/General
    // Profile'` have NO `(.EXT)` substring — the bundled regex
    // `/\(\.(\w+)/` fails, so they FALL THROUGH to the compatible-brand
    // scan (→ default `MP4`/`video/mp4`). They are listed in the
    // no-`(.EXT)` block below as deliberate no-ops.
    // ── HEIF / HEIC / AVIF ────────────────────────────────────────
    b"heic" => ("HEIC", "image/heic"),
    // QuickTime.pm:228 `'hevc' => 'High Efficiency Image Format HEVC
    // sequence (.HEICS)'`. The parenthesized extension is `HEICS`
    // (NOT `HEVC`), so the bundled regex `/\(\.(\w+)/` extracts `HEICS`.
    // MIME = `%mimeLookup{HEICS}` = `image/heic-sequence`.
    b"hevc" => ("HEICS", "image/heic-sequence"),
    b"mif1" => ("HEIF", "image/heif"),
    b"msf1" => ("HEIFS", "image/heif-sequence"),
    b"heix" => ("HEIF", "image/heif"),
    b"avif" | b"avis" | b"avio" | b"miaf" => ("AVIF", "image/avif"),
    // ── Canon CR3 / CRM ───────────────────────────────────────────
    // QuickTime.pm:236: `'crx ' => 'Canon Raw (.CRX)' #PH (CR3 or
    // CRM; use Canon CompressorVersion to decide)`. The default is
    // `CRX`; the Canon UUID's CNCV later flips to `CR3` or `CRM`
    // (Canon.pm:9667).
    b"crx " => ("CRX", "video/x-canon-crx"),
    // ── Apple QuickTime / Sony MQV ────────────────────────────────
    // QuickTime.pm:221 `'qt  ' => 'Apple QuickTime (.MOV/QT)'` —
    // the bundled regex `/\(\.(\w+)/` captures only `MOV` (\w+ stops
    // at the `/`), so the extracted ext is `MOV`.
    b"qt  " => ("MOV", "video/quicktime"),
    // QuickTime.pm:204 `'mqt ' => 'Sony / Mobile QuickTime (.MQV) ...'`.
    b"mqt " => ("MQV", "video/quicktime"),
    // ── Brands whose description carries an explicit `(.MP4)` ──────
    // These %ftypLookup entries DO contain a `(.MP4)` substring, so
    // the bundled FIRST regex `/\(\.(\w+)/` extracts `MP4` directly —
    // ExifTool never reaches the compatible-brand `elsif` scan for
    // them. MIME = `%mimeLookup{MP4}` (absent) → default `video/mp4`.
    //   QuickTime.pm:198 `'MSNV' => 'MPEG-4 (.MP4) for SonyPSP'`
    //   QuickTime.pm:205 `'mmp4' => 'MPEG-4/3GPP Mobile Profile (.MP4/3GP)…'`
    //   QuickTime.pm:207-216 `'NDSx'/'NDXx' => '… (.MP4) Nero … Profile'`
    // (NOTE: `NDAS` is EXCLUDED — its description `'MP4 v2 [ISO
    // 14496-14] Nero Digital AAC Audio'` has NO `(.EXT)`, so it falls
    // through to the compat scan below.)
    b"MSNV" | b"mmp4" | b"NDSC" | b"NDSH" | b"NDSM" | b"NDSP" | b"NDSS" | b"NDXC" | b"NDXH"
    | b"NDXM" | b"NDXP" | b"NDXS" => ("MP4", "video/mp4"),
    // ── MP4 family — NOT in this table ────────────────────────────
    // `isom`, `iso2`-`iso9`, `mp21`, `mp41`, `mp42`, `mp71`, `avc1`
    // ARE in `%ftypLookup` but their description strings have NO
    // `(.EXT)` substring (e.g. `'MP4 Base Media v5'`, no parens),
    // so the bundled regex `/\(\.(\w+)/` doesn't match and the
    // elsif chain runs (QuickTime.pm:9994-10001):
    //   - `mp41|mp42|avc1` → MP4 (the FIRST elsif).
    //   - `qt  ` → MOV.
    // So these brands MUST fall through here (returning `None`) so
    // the compatible-brand scan in `resolve_ftyp_file_type` picks
    // them up.
    //
    // The `resolve_ftyp_file_type` post-scan checks `mp41|mp42|avc1`
    // in the COMPATIBLE-brand slots (offset ≥ 12) — for a file with
    // `isom` (or any other no-(.EXT) brand) as the major, the
    // post-scan finds the same triggers there.
    //
    // ── Brands present in %ftypLookup but lacking (.EXT) ──────────
    // The bundled algorithm treats these as "no override" — they
    // ALSO fall through. exifast lists them here as deliberate
    // no-ops so the line cite is documented.
    b"caqv"     // Casio Digital Camera (no .EXT)
    | b"CAEP"   // Canon Digital Camera (no .EXT)
    | b"CDes"   // Convergent Design (no .EXT)
    | b"isom" | b"iso2" | b"iso3" | b"iso4" | b"iso5" | b"iso6" | b"iso7" | b"iso8" | b"iso9"
    | b"mp21" | b"mp41" | b"mp42" | b"mp71"
    | b"avc1"
    | b"dmpf"   // Digital Media Project (no .EXT)
    | b"dmb1"   // DMB MAF (no .EXT)
    | b"drc1"   // Dirac (no .EXT)
    | b"isc2"   // ISMACryp 2.0 (no .EXT)
    | b"JP20"   // unknown GPAC (no .EXT)
    | b"KDDI"   // 3GPP2 EZmovie KDDI (no .EXT)
    | b"MPPI"   // Photo Player MAF (no .EXT)
    | b"3gg6"   // 3GPP Release 6 General Profile (no .EXT)
    | b"mj2s" | b"mjp2"  // Motion JPEG 2000 Simple/General Profile (no .EXT)
    | b"NDAS"   // Nero Digital AAC Audio — 'MP4 v2 …' (no .EXT)
    | b"odcf" | b"opf2" | b"opx2"  // OMA DRM (no .EXT)
    | b"pana"   // Panasonic Digital Camera (no .EXT)
    | b"ROSS"   // Ross Video (no .EXT)
    | b"sdv "   // SD Memory Card Video (no .EXT)
    | b"ssc1" | b"ssc2"  // Samsung stereoscopic (no .EXT)
    | b"XAVC"   // Sony XAVC (no .EXT)
    | b"da0a" | b"da0b" | b"da1a" | b"da1b" | b"da2a" | b"da2b" | b"da3a" | b"da3b"
      // DMB MAF (no .EXT)
    | b"dv1a" | b"dv1b" | b"dv2a" | b"dv2b" | b"dv3a" | b"dv3b"  // DMB MAF (no .EXT)
    => return None,
    // Any other 4-byte brand not in `%ftypLookup` at all ⇒ `None`.
    // Caller falls through to the compatible-brands scan
    // (QuickTime.pm:9996-10001).
    _ => return None,
  })
  // SP4 brand dispatch end.
}

// ===========================================================================
// File-type derivation — replaces parse_inner's narrow file_type_from_ftyp
// ===========================================================================

/// Resolve the `File:FileType` and MIME from an `ftyp` atom payload —
/// the SP4-expanded version of `file_type_from_ftyp` in
/// [`crate::formats::quicktime`]. Honors the full `%ftypLookup` brand
/// table (HEIC/AVIF/CR3/JP2 + the 60-ish other brands) and falls
/// through to the bundled compatible-brand scan.
///
/// Returns `(file_type, mime)`. Faithful to QuickTime.pm:9986-10008
/// (the `ftyp` brand branch of `ProcessMOV`).
#[must_use]
pub fn resolve_ftyp_file_type(payload: &[u8]) -> (&'static str, &'static str) {
  // QuickTime.pm:9991 `my $type = substr($buff, 0, 4)`. A short ftyp
  // (< 4 bytes) falls through to the default.
  if let Some(brand) = payload.get(0..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
    if let Some(out) = file_type_from_ftyp_brand(&brand) {
      return out;
    }
  }
  // QuickTime.pm:9996-10001 — compatible-brands scan. The match runs
  // on `^.{8}(.{4})+(NEEDLE)/s` ⇒ NEEDLE must be at a non-first compat
  // slot (offset ≥ 12). Tried in this `elsif` order: mp41/mp42/avc1 →
  // MP4, f4v → F4V, qt → MOV.
  let non_first_slot = |needles: &[&[u8; 4]]| -> bool {
    let mut i = 12usize;
    while i + 4 <= payload.len() {
      // The `while` guard proves `i + 4 <= len`, so `.get` is `Some`.
      if let Some(slot) = payload.get(i..i + 4)
        && needles.iter().any(|n| slot == &n[..])
      {
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

// ===========================================================================
// ISO-BMFF box-walker utilities (private to this module)
// ===========================================================================

/// A walked ISO-BMFF box. Bundled's `ReadAtomHeader` in WriteQuickTime
/// returns essentially this (QuickTime.pm:10042-10059).
#[derive(Debug, Clone, Copy)]
struct BoxHeader<'a> {
  /// 4-byte box type.
  tag: &'a [u8],
  /// Absolute file offset of the box's PAYLOAD first byte — the box-header
  /// start plus the REAL header length (8 for a normal/size-0 box, 16 for a
  /// `size == 1` largesize box). Bundled tracks the actual header length
  /// (QuickTime.pm `ReadAtomHeader`), so every downstream body offset uses
  /// this instead of hard-coding `header_start + 8`, which is 8 bytes short
  /// for a largesize box.
  body_abs_start: u64,
  /// Slice of the box's payload (header bytes stripped). Its length is the
  /// exact payload byte count for all three size cases (normal, size-0,
  /// largesize), so a payload length is simply `body.len()` — no header
  /// subtraction from a full-box size is needed.
  body: &'a [u8],
}

/// How a `size == 0` box header is interpreted by [`walk_boxes`].
///
/// The two ISO-BMFF dialects exifast walks disagree on the meaning of a
/// declared box size of 0:
///
///  - **QuickTime / ISO-BMFF** (`ProcessMOV`, QuickTime.pm:10036-10056) —
///    a size-0 atom is a *Terminator* when contained (it ends the
///    container) and *ExtendsToEof* at the top level (it extends to EOF);
///    in BOTH cases `ProcessMOV` STOPS and NEVER decodes the size-0 atom's
///    body as child boxes. The brand re-walks (`scan_heif_meta`,
///    `scan_canon_uuid`, the `meta`-box parsers) therefore use [`Self::Stop`]
///    so they cannot emit a HEIF Meta / CR3 override the oracle never
///    produces.
///
///  - **JPEG 2000 in-memory boxes** (`ProcessJpeg2000Box`, the
///    `$dataPt` / no-`$raf` branch at Jpeg2000.pm:1117/1137 —
///    `$boxLen = $dirEnd - $pos`) — a size-0 box's data RUNS TO THE END OF
///    THE PARENT and the box IS processed normally. The nested `jp2h`
///    children walk uses [`Self::ToParentEnd`] so a `jp2h{ size-0 ihdr }`
///    still decodes ImageHeight/Width/Components/etc.
///
/// NOTE the asymmetry within JP2 itself: the TOP-LEVEL `ProcessJP2` walk is
/// driven from a file handle (`RAF => $raf`, Jpeg2000.pm:1542/1591), so a
/// size-0 box at the JP2 *top level* hits the `$raf` arm (line 1135) and
/// `last`s — i.e. it is [`Self::Stop`], the SAME as QuickTime. Only the
/// in-memory `jp2h` SubDirectory recursion (no `$raf`) runs to parent end.
/// `walk_jp2` / `walk_jxl` (top level) therefore keep [`Self::Stop`]; only
/// the `jp2h`-children walk inside [`handle_jp2_box`] uses
/// [`Self::ToParentEnd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size0Behavior {
  /// A size-0 box STOPS the walk without decoding its body (QuickTime
  /// Terminator / ExtendsToEof, and the JP2/JXL `$raf` top-level walk).
  Stop,
  /// A size-0 box's body runs to the END OF THE PARENT buffer and IS
  /// decoded (the in-memory `ProcessJpeg2000Box` `$dataPt` branch,
  /// Jpeg2000.pm:1137).
  ToParentEnd,
}

/// Walk a flat list of ISO-BMFF boxes, invoking `f` for each. The walker
/// stops at the first malformed header / size < 8 / size overrun.
///
/// `abs_offset` is the absolute file offset of `buf`'s first byte —
/// passed through so the callback can fold it into per-extent offsets.
///
/// `size0` selects the size-0 dialect: [`Size0Behavior::Stop`] for the
/// QuickTime atom hierarchy (and the JP2/JXL `$raf` top-level walk) versus
/// [`Size0Behavior::ToParentEnd`] for an in-memory JP2 `jp2h`-children box
/// list. See [`Size0Behavior`] for the per-call-site oracle.
///
/// The closure receives a `BoxHeader<'a>` whose lifetime matches `buf`,
/// so the closure body MAY capture `h.body` / `h.tag` into outer
/// `Option<&[u8]>` accumulators.
fn walk_boxes<'a>(
  buf: &'a [u8],
  abs_offset: u64,
  size0: Size0Behavior,
  mut f: impl FnMut(&BoxHeader<'a>),
) {
  let mut pos = 0usize;
  while pos + 8 <= buf.len() {
    // The `while` guard proves `pos + 8 <= len`, so both reads are `Some`
    // (byte-identical to the raw index); the `else return` matches the
    // guard turning false.
    let (Some(size), Some(tag)) = (be_u32(buf, pos), buf.get(pos + 4..pos + 8)) else {
      return;
    };
    let size = size as usize;
    let (body_start, body_end, next) = if size == 1 {
      // 64-bit extended size at bytes 8..16.
      let Some(hdr16) = pos.checked_add(16) else {
        return;
      };
      if hdr16 > buf.len() {
        return;
      }
      // `pos + 16 <= len` proven above, so `be_u64` is `Some`.
      let Some(ext) = be_u64(buf, pos + 8) else {
        return;
      };
      // A 64-bit declared size can exceed `usize::MAX` (on 32-bit) or
      // overflow `pos + ext` (on 64-bit). Reject out-of-range / overflow
      // cleanly — stop the walk, never panic or wrap.
      let Ok(ext) = usize::try_from(ext) else {
        return;
      };
      if ext < 16 {
        return;
      }
      let Some(end) = pos.checked_add(ext) else {
        return;
      };
      (hdr16, end, end)
    } else if size == 0 {
      // A `size == 0` box. The interpretation depends on the dialect:
      //
      //  - `Size0Behavior::Stop` (QuickTime, and the JP2/JXL `$raf`
      //    top-level walk) — the box STOPS the walk WITHOUT decoding its
      //    payload, matching the core `read_atom_header`
      //    (`src/formats/quicktime.rs`) and ProcessMOV
      //    (QuickTime.pm:10036-10056): a CONTAINED size-0 atom is a
      //    Terminator (ends the container) and a TOP-LEVEL one is
      //    ExtendsToEof (extends to EOF); in BOTH cases ProcessMOV never
      //    decodes the size-0 atom's body as child boxes. The JP2 `$raf`
      //    top-level walk likewise `last`s (Jpeg2000.pm:1135). A re-walk
      //    here must therefore never invoke the callback on the body —
      //    otherwise it would emit HEIF Meta/Warning (`meta`) or a CR3
      //    override (`moov{Canon uuid}`) the oracle never produces.
      //
      //  - `Size0Behavior::ToParentEnd` (an in-memory JP2 `jp2h`-children
      //    walk) — the box's data RUNS TO THE END OF THE PARENT buffer and
      //    IS decoded, faithful to `ProcessJpeg2000Box`'s `$dataPt`/no-`$raf`
      //    branch `$boxLen = $dirEnd - $pos` (Jpeg2000.pm:1137). The body is
      //    `pos+8 .. buf.len()`, the callback fires once, and the walk then
      //    ends (the next position is past the buffer).
      match size0 {
        Size0Behavior::Stop => return,
        Size0Behavior::ToParentEnd => (pos + 8, buf.len(), buf.len()),
      }
    } else if size < 8 {
      return;
    } else {
      // `pos + 8 <= len` proven by the guard; `pos + size` can overflow
      // for a large declared `size`, so add it checked.
      let Some(end) = pos.checked_add(size) else {
        return;
      };
      (pos + 8, end, end)
    };
    if body_end > buf.len() {
      return;
    }
    // `body_end <= len` (checked) and `body_start <= body_end`, so `.get`
    // is `Some` — byte-identical to the raw slice.
    let Some(body) = buf.get(body_start..body_end) else {
      return;
    };
    let header = BoxHeader {
      tag,
      // `body_start` is the payload's byte offset within `buf` (16 for
      // largesize, 8 for normal/size-0), so the absolute payload offset is
      // `abs_offset + body_start`.
      body_abs_start: abs_offset + body_start as u64,
      body,
    };
    f(&header);
    if next <= pos {
      return;
    }
    pos = next;
  }
}

/// Big-endian u16 at byte offset `off`. `None` for short slices.
#[inline]
fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Big-endian u32 at byte offset `off`. `None` for short slices.
#[inline]
fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Big-endian u64 at byte offset `off`. `None` for short slices.
#[inline]
fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  Some(u64::from_be_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Big-endian variable-length integer at byte offset `*pos`,
/// `byte_len` bytes wide. Byte-identical to `GetVarInt($dataPt, $pos,
/// $n, $default)` (QuickTime.pm:9042-9056):
///
/// - The cursor is ALWAYS advanced by `$n` first (`$_[1] = $pos + $n`,
///   line 9046) — even on the short-read / `n==0` / invalid-width paths.
/// - Returns `None` when `$pos + $n > $len` (line 9047), regardless of
///   `$n`.
/// - `$n == 0` → the default (`$default || 0`, line 9049); exifast passes
///   the default explicitly via `default`.
/// - `$n == 4` → big-endian u32 (`Get32u`, line 9051).
/// - `$n == 8` → big-endian u64 (`Get64u`, line 9053).
/// - EVERY OTHER `$n` → `None` (the fall-through `return undef`, line
///   9055). Only 0/4/8 are valid; the four `iloc` `siz` nibbles are
///   constrained to those by spec, and a non-conforming nibble aborts
///   the parse exactly as bundled rejects it.
fn get_var_int(buf: &[u8], pos: &mut usize, byte_len: u8, default: u64) -> Option<u64> {
  let n = byte_len as usize;
  // Faithful to line 9046: advance the cursor by `n` unconditionally,
  // BEFORE the bounds check and width dispatch.
  let start = *pos;
  let end = start.saturating_add(n);
  *pos = end;
  // Line 9047: `return undef if $pos + $n > $len`.
  if end > buf.len() {
    return None;
  }
  match byte_len {
    0 => Some(default),
    4 => be_u32(buf, start).map(u64::from),
    8 => be_u64(buf, start),
    _ => None,
  }
}

/// Read a UTF-8 string starting at byte `pos`, mirroring ExifTool's
/// `GetString` (QuickTime.pm:9062-9075). The cursor is advanced past the
/// terminating NUL when one is found; otherwise the loop runs to
/// end-of-buffer and the cursor lands at `len`.
///
/// `GetString` NEVER fails on a missing terminator: it returns ALL bytes
/// accumulated before EOF (`return $str` at :9074). So an unterminated
/// TRAILING string yields `Some(remaining)` (with `pos = len`), not
/// `None` — `ParseItemInfoEntry` (:9244-9266) assigns Name/ContentType
/// unconditionally, so a missing terminator must still ASSIGN (and, for a
/// duplicate id, OVERWRITE), never be dropped as "absent".
///
/// `None` is reserved for a genuinely undecodable case: the bytes are not
/// valid UTF-8 (ExifTool builds a raw byte string, but exifast stores
/// typed UTF-8 and the iloc/infe callers treat `None` as "field
/// untouched"). The empty-string case is `Some("")`, distinct from `None`.
fn get_string(buf: &[u8], pos: &mut usize) -> Option<SmolStr> {
  let start = *pos;
  while *pos < buf.len() {
    // The `while` guard proves `*pos < len`, so the byte read is `Some`.
    if buf.get(*pos).copied() == Some(0) {
      // Advance the cursor PAST the NUL FIRST — ExifTool's `GetString`
      // increments through the terminator (:9069 `++$pos`) BEFORE returning,
      // independent of the string's content. Capturing the end index here
      // means a non-UTF-8 value (which exifast maps to `None`) still leaves
      // the cursor past the terminator, so the NEXT `get_string` reads the
      // following field (e.g. a `mime` item's ContentType) instead of
      // re-reading the NUL and desynchronising every subsequent string.
      let str_end = *pos;
      *pos += 1;
      // `start <= str_end < len`, so the slice is `Some` — byte-identical.
      let s = core::str::from_utf8(buf.get(start..str_end)?).ok()?;
      return Some(SmolStr::from(s));
    }
    *pos += 1;
  }
  // No NUL before EOF: faithful to `GetString` returning the remaining
  // bytes (`return $str`) with `pos` advanced to `len`. `*pos` already
  // equals `buf.len()` here (the loop ran to the end). `start <= len`, so
  // the slice is `Some` — only a non-UTF-8 tail yields `None`.
  let s = core::str::from_utf8(buf.get(start..)?).ok()?;
  Some(SmolStr::from(s))
}

// ===========================================================================
// HEIF/HEIC/AVIF meta-box walker
// ===========================================================================

/// Walk a top-level `meta` box body and populate `out` with the items
/// + primary item + idat location. Faithful port of `ProcessMOV`'s
///   `meta`-recursive descent at QuickTime.pm:10262-10373 PLUS the
///   dedicated parsers `ParseItemInfoEntry` (:9228-9281),
///   `ParseItemLocation` (:9131-9195), `ParseItemPropAssoc` (:9287-9338),
///   `HandleItemInfo` (:9343-9526).
///
/// `meta_abs_offset` is the absolute file offset of `body`'s first byte
/// — used so `iloc` extent offsets stay file-absolute (bundled's
/// `BaseOffset + extent_offset` arithmetic, QuickTime.pm:9397).
///
/// `child_start` is the byte offset of the first child box within `body`
/// — the `SubDirectory` `Start` of the enclosing `meta` entry (R18-F2).
/// ExifTool wires the SAME `QuickTime::Meta` table (which carries the HEIF
/// item boxes `iinf`/`iloc`/`pitm`/`iprp` AND the iTunes `ilst`/`keys`)
/// from TWO entries with DIFFERENT `Start`:
///  - `%QuickTime::Main` top-level `meta` → `Start => 4` (skip the 1-byte
///    version + 3-byte flags FullBox header, QuickTime.pm:552-556) ⇒ pass 4.
///  - `%QuickTime::Movie` `moov/meta` → NO `Start` (children begin at offset
///    0; the Sony/Casio MOV `moov/meta` is not a FullBox,
///    QuickTime.pm:1218-1221) ⇒ pass 0.
///
/// Hard-coding 4 here shifted a `moov/meta`'s children by 4 bytes; the
/// caller now supplies the table-correct offset.
///
/// SP4 scope: surface the per-item Type/Name/Extents + PrimaryItem +
/// idat. The `ipco` property dispatch (ImageSpatialExtent / Rotation /
/// Mirroring / ColorSpec) and `iref` deep relationships are DEFERRED;
/// only `cdsc` (ContentDescribes) item-id refs are noted as a warning
/// when present.
pub fn walk_heif_meta(
  body: &[u8],
  meta_abs_offset: u64,
  child_start: usize,
  out: &mut HeifMeta,
  iloc_extents_remaining: &mut u64,
) {
  let Some(children) = body.get(child_start..) else {
    out.set_warning_at(Some(String::from("Truncated meta box")), meta_abs_offset);
    return;
  };
  let children_abs = meta_abs_offset + child_start as u64;
  let mut item_ref_version: u8 = 0;
  // ExifTool keys items by id in the single `$$et{ItemInfo}` hash that
  // lives for the WHOLE file walk (QuickTime.pm:9138/9234) — every `meta`
  // box parsed into the same ExifTool object autovivifies into the SAME
  // per-id slot. exifast mirrors that keyed view as a side index (id → Vec
  // slot) so `item_slot_index`'s "seen this id?" lookup is O(log n), not a
  // per-item linear scan. To stay faithful when `scan_heif_meta` walks more
  // than one `meta` box into the same `HeifMeta out` (the persistent
  // ItemInfo), SEED the index from the items already present so a reused id
  // resolves to its existing slot (last-wins overwrite) instead of being
  // appended as a duplicate.
  let mut id_index: BTreeMap<u32, usize> = out
    .items()
    .iter()
    .enumerate()
    .map(|(idx, it)| (it.id(), idx))
    .collect();
  // #146 — the `iprp` property store: each decoded `ispe`'s 1-based `ipco`
  // property index + dims, plus the `ipma` item→property associations. Both are
  // collected during the walk and resolved into `File:ImageWidth`/`Height` AFTER
  // it completes, mirroring ExifTool's delayed `ipco` processing (QuickTime.pm:
  // 10361-10364 defers `ipco` until `ipma` + `pitm` are known). The property
  // index is a `u32` with a checked increment so an `ipco` with >65535 children
  // cannot overflow a narrower counter and alias one property index onto another.
  let mut ispe_props: Vec<(u32, u32, u32)> = Vec::new();
  let mut ipma_assoc: Vec<(u32, Vec<u16>)> = Vec::new();
  // #149 — the decoded `av1C` (AV1 Codec Configuration) from `ipco`. Collected
  // into a local (NOT written through `out`) so the inner `ipco` property-walk
  // closure does not capture `out` mutably — the surrounding `iprp` closure
  // already holds it (the same nesting reason `ispe_props` is a local). Written
  // to `out` after the walk; the LAST `av1C` in the surviving `ipco` wins.
  let mut av1_config_found: Option<crate::metadata::Av1Config> = None;
  // #218 — the iloc extent budget is CUMULATIVE across every `iloc` child of
  // this `meta` AND across every OTHER `meta` box in the file: `walk_heif_meta`
  // does NOT own it. The caller ([`scan_quicktime_brands`]) holds ONE
  // remaining-budget (init [`MAX_ILOC_EXTENTS`]) at file scope and threads the
  // SAME `&mut` through every `walk_heif_meta` call that writes into the SAME
  // `HeifMeta`, so a crafted file cannot defeat the ceiling by splitting its
  // zero-width-extent flood across many tiny iloc boxes OR many top-level meta
  // boxes. Each materialized extent decrements it; once the GLOBAL count
  // reaches the ceiling, all further iloc extent parsing stops file-wide.
  walk_boxes(children, children_abs, Size0Behavior::Stop, |h| {
    match h.tag {
      // pitm — PrimaryItemReference (QuickTime.pm:2883-2892).
      b"pitm" if !h.body.is_empty() => {
        let version = h.body.first().copied().unwrap_or(0);
        // Version 0: 4-byte version/flags + 2-byte id (n).
        // Version >=1: 4-byte version/flags + 4-byte id (N).
        let id_opt = if version == 0 {
          be_u16(h.body, 4).map(u32::from)
        } else {
          be_u32(h.body, 4)
        };
        if let Some(id) = id_opt {
          out.set_primary_item(Some(id));
        }
      }
      // iinf — ItemInformation (QuickTime.pm:2844-2857).
      // Version 0: 4-byte version/flags + 2-byte count, then N infe boxes.
      // Version >=1: 4-byte version/flags + 4-byte count, then N infe boxes.
      b"iinf" => {
        let Some(&version) = h.body.first() else {
          return;
        };
        let infe_start = if version == 0 { 6 } else { 8 };
        let Some(infe_buf) = h.body.get(infe_start..) else {
          out.set_warning_at(Some(String::from("Truncated iinf")), meta_abs_offset);
          return;
        };
        // Walk the infe children. Note: `walk_boxes` uses the inner
        // buffer's offsets — we don't propagate `abs_offset` into
        // `out` for infe (only iloc carries file offsets).
        //
        // Each `infe` writes its OWN fields (Type/Name/ContentType) into
        // the keyed slot, OVERWRITING a prior `infe` for the same id
        // (last-wins, QuickTime.pm:9244-9265 plain `=`). A prior `iloc`'s
        // BaseOffset/Extents on the slot are left untouched (cross-merge).
        // The faithful assignment model (mirroring which `$$items{$id}{...}`
        // lines run per version): Name is assigned by EVERY infe (:9244 /
        // :9260) → ALWAYS overwrite (even to `None`/`""`); Type is assigned
        // ONLY in the v2/3/4+ else-branch (:9258) → overwrite only when
        // `type_assigned()` (so a v0/1 entry never nulls a Type set by an
        // earlier v2 entry, while a v2 non-UTF-8 Type — value `None`, flag
        // true — CLEARS the prior Type); ContentType is assigned in v0/1
        // (:9245) and the v2/3/4+ `mime` arm (:9262) → overwrite only when
        // `content_type_assigned()` (a v2 `Exif`/`uri ` entry keeps the
        // prior ContentType). A plain `Some`/`None` value cannot distinguish
        // "assigned to None" from "not assigned", so the per-field flags
        // drive the overwrite decision.
        // ExifTool's `ParseItemInfoEntry` warns when item-info entries are
        // not in strictly-ascending id order (QuickTime.pm:9275-9279:
        // `unless ($id > $$et{LastItemID}) { Warn('Item info entries are out
        // of order') }` then `$$et{LastItemID} = $id`). The check runs AFTER
        // the field assignment, so the item is still merged. ExifTool RESETS
        // `$$self{LastItemID} = -1` at the START of EACH `iinf` box (the iinf
        // tag Condition, QuickTime.pm:2846), so tracking it per-`iinf` here is
        // FAITHFUL — not a simplification. Modeling the sentinel -1 as
        // `Option<u32>` (`None` = the initial -1) makes the first entry never
        // warn (any id beats -1) while preserving the `id <= prev` test for
        // every subsequent entry — including a first id of 0, which a literal
        // `0`-initialised counter would have wrongly flagged (`0 <= 0`).
        let mut last_item_id: Option<u32> = None;
        walk_boxes(infe_buf, 0, Size0Behavior::Stop, |infe| {
          if infe.tag == b"infe"
            && let Some(item) = parse_infe(infe.body)
          {
            let id = item.id();
            if let Some(prev) = last_item_id
              && id <= prev
            {
              out.set_warning_at(
                Some(String::from("Item info entries are out of order")),
                meta_abs_offset,
              );
            }
            last_item_id = Some(id);
            // Read the parsed entry's fields + assignment flags into locals
            // BEFORE borrowing `out.items_mut()` (the slot borrow conflicts
            // with reading `item`, but the locals are owned).
            let name = item.name().map(SmolStr::from);
            let type_assigned = item.type_assigned();
            let item_type = item.item_type().map(SmolStr::from);
            let content_type_assigned = item.content_type_assigned();
            let content_type = item.content_type().map(SmolStr::from);
            let idx = item_slot_index(out, &mut id_index, id);
            if let Some(slot) = out.items_mut().get_mut(idx) {
              // Name: assigned by every infe → ALWAYS overwrite (last-wins,
              // possibly to `None`/`""`).
              slot.set_name(name);
              // Type: overwrite only when THIS entry assigned it (v2/3/4+);
              // a non-UTF-8 Type (value `None`) clears the prior.
              if type_assigned {
                slot.set_item_type(item_type);
              }
              // ContentType: overwrite only when assigned (v0/1, or the
              // v2/3/4+ `mime` arm).
              if content_type_assigned {
                slot.set_content_type(content_type);
              }
            }
          }
        });
      }
      // iloc — ItemLocation (QuickTime.pm:9131-9195). The extent budget is
      // SHARED across every iloc box of every meta in the file (#218 cumulative
      // DoS floor), so pass the caller-owned `iloc_extents_remaining` rather
      // than letting each box (or each meta) restart at the full ceiling.
      b"iloc" => {
        if let Err(w) = parse_iloc_remaining(h.body, out, &mut id_index, iloc_extents_remaining) {
          out.set_warning_at(Some(w), meta_abs_offset);
        }
      }
      // iref — ItemReference. The first byte after the 4-byte flags
      // is the version that drives whether ids are u16/u32. We only
      // capture `cdsc` (ContentDescribes, QuickTime.pm:9201-9222) as
      // a warning so the deferred deep-walk is visible — full `iref`
      // is a P3 follow-up (issue: HEIF iref deep relationships).
      b"iref" if h.body.len() > 4 => {
        item_ref_version = h.body.first().copied().unwrap_or(0);
        let _ = item_ref_version; // suppress unused
        // Walk inner refs starting at offset 4 (the version/flags).
        // `h.body.len() > 4` proven by the guard, so `.get(4..)` is `Some`.
        let mut has_cdsc = false;
        if let Some(inner) = h.body.get(4..) {
          walk_boxes(inner, 0, Size0Behavior::Stop, |r| {
            if r.tag == b"cdsc" {
              has_cdsc = true;
            }
          });
        }
        if has_cdsc {
          // Faithful: bundled processes cdsc into
          // `$$et{ItemInfo}{$id}{RefersTo}` — exifast records its
          // presence as a DEFERRED warning so downstream logic knows
          // iref content existed.
          out.set_warning_at(
            Some(String::from(
              "iref cdsc relations present (deep walk deferred — see #63)",
            )),
            meta_abs_offset,
          );
        }
      }
      // idat — embedded item data (QuickTime.pm:2910-2916). Recorded
      // as offset+length so construction_method == 1 extents can be
      // resolved.
      // TODO(#146): the HEIC `MetaImageSize` tag (QuickTime.pm:2906-2909)
      // reads the idat BODY as `int16u[4]` (W/H pairs); SP4 records only the
      // idat location, so MetaImageSize emission is deferred to #146.
      b"idat" => {
        out.set_idat_offset(Some(h.body_abs_start));
        // `h.body.len()` is the exact payload length for every size case
        // (normal, size-0, largesize) — no header subtraction needed.
        out.set_idat_length(Some(h.body.len() as u64));
      }
      // iprp — ItemProperties (QuickTime.pm:2897-2900). A container whose
      // children are `ipco` (the property store) and `ipma` (the item→
      // property associations).
      //
      // #146 — decode the `ipco` `ispe` (ImageSpatialExtent) property boxes
      // keyed by their 1-based property index, AND capture the `ipma`
      // associations, so the primary item's `ispe` resolves to
      // `File:ImageWidth`/`File:ImageHeight` after the walk. `ipma_order_walk`
      // also keeps the out-of-order warning (the sibling of the `iinf` check).
      // The `irot`/`colr`/`pixi` properties are NOT surfaced (no bundled HEIC
      // fixture exercises them to ground-truth the group/PrintConv).
      b"iprp" => {
        walk_boxes(h.body, 0, Size0Behavior::Stop, |child| {
          match child.tag {
            b"ipco" => {
              // The `ipco` children are property boxes in declaration order;
              // ExifTool addresses them by 1-based index (QuickTime.pm:9119,
              // the `ipma` Association indices). Record each `ispe`'s decoded
              // dims at its index for the deferred-resolution pass below.
              //
              // A SECOND `ipco` in the same `meta` REPLACES the first — it does
              // NOT accumulate. ExifTool DEFERS the `ipco` directory by a plain
              // ASSIGNMENT `$$et{ItemPropertyContainer} = [ \%dirInfo, ... ]`
              // (QuickTime.pm:10363) and `%dupDirOK` whitelists `ipco`
              // (QuickTime.pm:510), so a later `ipco` overwrites the stored
              // container and ONLY the LAST one is processed after the meta walk
              // (QuickTime.pm:9530-9534). The `ipma` association indices then
              // refer into the LAST `ipco`'s property list. So decode each
              // `ipco` into a FRESH per-container list and OVERWRITE the pending
              // `ispe_props` — a stale earlier-`ipco` `ispe` must not survive
              // (oracle: ipco#1[ispe…] + ipco#2[ispe(W×H)] → the dims resolve
              // against ipco#2 only).
              //
              // The counter is a `u32` with a CHECKED increment so an `ipco`
              // with >65535 children cannot overflow a narrower type (a debug
              // panic / release wrap that would alias a high property index
              // onto a low one). EVERY decoded `ispe` is recorded regardless of
              // index: ExifTool walks every `ipco` child positionally and a
              // property is bound to an item only by an `ipma` association, so
              // an `ispe` at a high index that no `ipma` row references is still
              // a "main-document" property and FoundTags `ImageWidth`/`Height`
              // (oracle: a lone `ispe` at `ipco` index 65537 → `File:ImageWidth`
              // = its width). The list is input-bounded — each `ispe` box is
              // ≥20 bytes in the file, so the count cannot exceed `len / 20`.
              let mut this_ipco: Vec<(u32, u32, u32)> = Vec::new();
              // A FRESH per-`ipco` `av1C` slot — like `this_ipco`, it OVERWRITES
              // the pending value (a later `ipco` with no `av1C` clears an
              // earlier one, matching ExifTool processing only the LAST stored
              // `ItemPropertyContainer`). Multiple `av1C` boxes WITHIN this
              // `ipco` MERGE per tag (see the walk below). #149.
              let mut this_av1c: Option<crate::metadata::Av1Config> = None;
              let mut prop_index: u32 = 0;
              walk_boxes(child.body, 0, Size0Behavior::Stop, |prop| {
                let Some(next) = prop_index.checked_add(1) else {
                  return;
                };
                prop_index = next;
                if prop.tag == b"ispe"
                  && let Some((w, hh)) = decode_ispe(prop.body)
                {
                  this_ipco.push((prop_index, w, hh));
                }
                // av1C (AV1 Codec Configuration, QuickTime.pm:3079-3082 → the
                // `AV1Config` ProcessBinaryData table). ExifTool walks every
                // `ipco` child and re-runs `AV1Config` on each `av1C` box; each
                // re-run FoundTag-overwrites the tags THAT box contains, so
                // duplicate `av1C` boxes resolve PER TAG (last-wins per tag, not
                // whole-record). MERGE each decoded box into the pending one: a
                // later truncated `av1C` overwrites only `AV1ConfigurationVersion`
                // and leaves an earlier `ChromaFormat`/`ChromaSamplePosition`
                // intact (oracle: full 4-byte then 1-byte `av1C` → chroma from
                // the first, version from the second). The `ispe`-vs-`av1C`
                // resolution differs from the dimension path (an `av1C` is NOT
                // item-associated), so this is independent of `ispe_props`/`ipma`.
                // #149.
                else if prop.tag == b"av1C"
                  && let Some(cfg) = decode_av1c(prop.body)
                {
                  match &mut this_av1c {
                    Some(existing) => existing.merge(cfg),
                    None => this_av1c = Some(cfg),
                  }
                }
              });
              ispe_props = this_ipco;
              av1_config_found = this_av1c;
            }
            b"ipma" => {
              ipma_order_walk(child.body, meta_abs_offset, out, &mut ipma_assoc);
            }
            _ => {}
          }
        });
      }
      // hdlr inside meta — bundled records `$$self{HandlerType}`
      // (QuickTime.pm:8403-8413). SP4 ignores this; the handler type
      // doesn't change the item-list shape.
      b"hdlr" => {}
      _ => {}
    }
  });
  // #146 — emit `File:ImageWidth`/`ImageHeight` from the `ipco` `ispe` boxes.
  // Done AFTER the walk so `pitm` + `ipma` are known regardless of box order
  // (ExifTool defers `ipco` until both are set, QuickTime.pm:10361-10364).
  //
  // Run whenever THIS meta decoded at least one `ispe`; the association list may
  // be empty (an unassociated `ispe` is still main-document, see
  // [`emit_ispe_dimensions`]). `scan_quicktime_brands` walks EVERY `meta` box
  // into the SAME `HeifMeta`; ExifTool FoundTags `ImageWidth`/`Height` per
  // main-document `ispe` cumulatively over the whole file, so this NEVER clears
  // — a later `meta` with no main-document `ispe` (or no `ispe` at all) leaves
  // the earlier dims intact, and a later main-document `ispe` overrides them
  // (last-wins).
  if !ispe_props.is_empty() {
    emit_ispe_dimensions(&ispe_props, &ipma_assoc, out);
  }
  // #149 — record the `av1C` config decoded from this `meta`'s surviving `ipco`.
  // Only WRITE when this `meta` actually decoded one, so (like the `ispe`
  // dimensions) a later `av1C`-less `meta` over the SHARED `HeifMeta` leaves an
  // earlier config intact. A later `av1C` MERGES per tag into the earlier (the
  // same per-tag last-wins ExifTool's whole-file FoundTag applies — each
  // non-list scalar tag is overwritten by the last box that contains it,
  // regardless of which `meta`), so a later truncated `av1C` overrides only the
  // fields it carries. A real AVIF has exactly one `meta` carrying exactly one
  // `av1C`.
  if let Some(cfg) = av1_config_found {
    match out.av1_config() {
      Some(mut existing) => {
        existing.merge(cfg);
        out.set_av1_config(Some(existing));
      }
      None => {
        out.set_av1_config(Some(cfg));
      }
    }
  }
}

/// Parse a single `infe` box body into a [`HeifItem`]. Faithful port of
/// `ParseItemInfoEntry` (QuickTime.pm:9228-9281).
fn parse_infe(buf: &[u8]) -> Option<HeifItem> {
  let Some(&version) = buf.first() else {
    return None;
  };
  if buf.len() < 4 {
    return None;
  }
  let mut item = HeifItem::new();
  let mut pos = 4usize; // skip 1-byte version + 3-byte flags.
  // QuickTime.pm:9239 `return undef if $pos + 4 > $len` — AFTER `$pos = 4`,
  // BEFORE the version branch — so EVERY version needs len >= 8 (the 2-byte
  // id + 2-byte ProtectionIndex must both fit). Without this a 6/7-byte v0/1
  // body would read the id but advance past a ProtectionIndex that does not
  // exist, minting a phantom item that then skews the out-of-order check.
  if buf.len() < pos + 4 {
    return None;
  }
  if version == 0 || version == 1 {
    let id = u32::from(be_u16(buf, pos)?);
    item.set_id(id);
    pos += 2;
    // version 0/1: 2-byte ProtectionIndex (skipped); name/contentType/
    // contentEncoding strings.
    pos += 2;
    // Name string — ExifTool assigns UNCONDITIONALLY in EVERY version
    // (`$$items{$id}{Name} = GetString(...)`, QuickTime.pm:9244 here, :9260
    // in the v2/3/4+ branch). `GetString` returns `''` (a real value) when
    // the string is empty, NOT undef, so the value is `Some("")`/`Some(str)`,
    // or `None` only for a non-UTF-8 string. The keyed `iinf` merge ALWAYS
    // overwrites the slot's name with this value (last-wins) — no flag is
    // needed because Name is set by every infe.
    item.set_name(get_string(buf, &mut pos));
    // ContentType — assigned UNCONDITIONALLY in v0/1 (QuickTime.pm:9245).
    // Flag it so the merge overwrites the slot's content_type (to `Some` or
    // `None`); contrast a v2/3/4+ non-`mime` entry, which leaves it unset.
    item.set_content_type_assigned(true);
    item.set_content_type(get_string(buf, &mut pos));
    // ContentEncoding string also follows but we don't surface it
    // (DEFERRED — only matters for `deflate` items which exifast
    // doesn't decompress). Read it only to keep the cursor honest.
    let _ = get_string(buf, &mut pos);
    // (v0/1 never assigns Type — `type_assigned` stays false.)
  } else {
    // QuickTime.pm:9247 `else { ... }` runs for ALL versions >= 2. Only
    // v2/v3 set `$id` (and advance `$pos`); for v4+ NEITHER arm runs, so
    // `$id` stays UNDEF and `$pos` stays 4. Perl's `undef` numifies to 0 in
    // the order check (`$id > LastItemID`) and in `LastItemID = $id`, so we
    // represent the v4+ id as `0`.
    let id = if version == 2 {
      let id = u32::from(be_u16(buf, pos)?);
      pos += 2;
      id
    } else if version == 3 {
      let id = be_u32(buf, pos)?;
      pos += 4;
      id
    } else {
      // version 4+: `$id` stays undef (→ 0) and `$pos` stays 4. The string
      // layout below still runs exactly as for v2/v3.
      // NOTE: ExifTool keys an undef-id item by the empty STRING `''`; here
      // it is keyed by `0`. A file carrying BOTH a v4 (undef) item AND a
      // real id-0 item would key them together here but separately in
      // ExifTool — a quadruple-crafted, output-invisible edge (items are not
      // emitted; extraction is #36-deferred), so the numeric `0` is faithful
      // for every observable behaviour (the order check + slot merge).
      0u32
    };
    item.set_id(id);
    // ProtectionIndex (2 bytes, skipped) + ItemType (4 bytes).
    if buf.len() < pos + 6 {
      return None;
    }
    pos += 2;
    // ExifTool assigns `$$items{$id}{Type}` from the raw 4 bytes
    // UNCONDITIONALLY in this branch (`substr($val, $pos+2, 4)`,
    // QuickTime.pm:9257-9258) — a non-UTF-8 type does NOT abort the entry.
    // Flag the assignment so the merge overwrites the slot's item_type even
    // when the value is `None` (a non-UTF-8 type CLEARS a prior Type). The
    // surfaced value is `Some(utf8)` only when the 4 bytes decode (real item
    // types are ASCII 4CCs like `hvc1`/`Exif`/`mime`); the raw `item_type`
    // bytes still drive the `mime`/`uri ` branch below even when not UTF-8.
    // `buf.len() >= pos + 4` proven above, so the slice is `Some`.
    let item_type = <[u8; 4]>::try_from(buf.get(pos..pos + 4)?).ok()?;
    item.set_type_assigned(true);
    if let Ok(s) = core::str::from_utf8(&item_type) {
      item.set_item_type(Some(SmolStr::from(s)));
    }
    pos += 4;
    // Name string — assigned UNCONDITIONALLY (QuickTime.pm:9260), `Some("")`
    // when empty so it overwrites a prior Name (last-wins), `None` only for
    // a non-UTF-8 string (which also overwrites/clears).
    item.set_name(get_string(buf, &mut pos));
    // QuickTime.pm:9261-9266 — type-specific suffix (driven by the RAW
    // `item_type` bytes, so it fires even for a non-UTF-8 4CC):
    //   `mime` → ContentType + ContentEncoding strings (assigned, may be "").
    //   `uri ` → URI string.
    //   any OTHER type ('Exif'/'hvc1'/'av01'/…) → assigns NEITHER, so the
    //     merge KEEPS any prior ContentType (`content_type_assigned` stays
    //     false).
    if &item_type == b"mime" {
      item.set_content_type_assigned(true);
      item.set_content_type(get_string(buf, &mut pos));
      // ContentEncoding deferred.
    } else if &item_type == b"uri " {
      // URI string — not stored (DEFERRED, only PLIST detection uses
      // it and PLIST items are out of camera-indexing scope).
      let _ = get_string(buf, &mut pos);
    }
  }
  Some(item)
}

/// Walk an `ipma` (ItemPropertyAssociation) body for the order check ONLY.
/// Faithful port of the id-walk + warning in `ParseItemPropAssoc`
/// (QuickTime.pm:9287-9337). The per-item Association/Essential VALUES are
/// DEFERRED to #146; this discards the association bytes (advancing the
/// cursor past them exactly as bundled does) and emits the
/// `Item property association entries are out of order` warning — the exact
/// sibling of the `iinf` out-of-order warning. `meta_abs_offset` is the
/// enclosing `meta` box's absolute file offset, recorded alongside the warning
/// (first-wins) so the document-level drain can order it by file position (#159).
fn ipma_order_walk(
  body: &[u8],
  meta_abs_offset: u64,
  out: &mut HeifMeta,
  assoc_out: &mut Vec<(u32, Vec<u16>)>,
) {
  // QuickTime.pm:9295 `return undef if $len < 8`.
  if body.len() < 8 {
    return;
  }
  let len = body.len();
  // QuickTime.pm:9296-9298. `$ver` is the FullBox version (top byte of the
  // version/flags word); `$flg & 1` is the association-index-size flag.
  let Some(ver) = body.first().copied() else {
    return;
  };
  let Some(flg) = be_u32(body, 0) else {
    return;
  };
  let Some(num) = be_u32(body, 4) else {
    return;
  };
  let mut pos = 8usize;
  // QuickTime.pm:9300 `$lastID = -1` — modeled as `None` (the first id never
  // warns; any later id <= a prior id warns).
  let mut last_id: Option<u32> = None;
  // QuickTime.pm:9301 `for ($i=0; $i<$num; ++$i)`. `num` is a file-supplied
  // u32 but every body read below `return`s on truncation, so the loop is
  // naturally bounded by `len`; also stop once the cursor reaches the end.
  for _ in 0..num {
    if pos >= len {
      return;
    }
    let id = if ver == 0 {
      // QuickTime.pm:9303 `return undef if $pos + 3 > $len`.
      if pos + 3 > len {
        return;
      }
      let Some(id) = be_u16(body, pos) else {
        return;
      };
      pos += 2;
      u32::from(id)
    } else {
      // QuickTime.pm:9307 `return undef if $pos + 5 > $len`.
      if pos + 5 > len {
        return;
      }
      let Some(id) = be_u32(body, pos) else {
        return;
      };
      pos += 4;
      id
    };
    // QuickTime.pm:9311 `my $n = Get8u(\$val, $pos++)`. The `+3`/`+5` guards
    // above proved this byte exists.
    let Some(n) = body.get(pos).copied() else {
      return;
    };
    pos += 1;
    // QuickTime.pm:9313-9328 — 2 bytes per association when the flags low bit
    // is set, else 1 byte. The low 15/7 bits are the 1-based `ipco` property
    // index; the top bit is the Essential flag (#146 records the index only —
    // the property store dispatch needs it to resolve the primary item's `ispe`).
    let assoc_bytes = if flg & 0x01 != 0 {
      usize::from(n) * 2
    } else {
      usize::from(n)
    };
    // QuickTime.pm:9314/9322 `return undef if $pos + $n*… > $len`.
    if pos + assoc_bytes > len {
      return;
    }
    let mut indices: Vec<u16> = Vec::with_capacity(usize::from(n));
    if flg & 0x01 != 0 {
      // 2-byte entries: `Get16u & 0x7fff` (QuickTime.pm:9317).
      for j in 0..usize::from(n) {
        if let Some(tmp) = be_u16(body, pos + j * 2) {
          indices.push(tmp & 0x7fff);
        }
      }
    } else {
      // 1-byte entries: `Get8u & 0x7f` (QuickTime.pm:9324).
      for j in 0..usize::from(n) {
        if let Some(&tmp) = body.get(pos + j) {
          indices.push(u16::from(tmp & 0x7f));
        }
      }
    }
    assoc_out.push((id, indices));
    pos += assoc_bytes;
    // QuickTime.pm:9334 `Warn(...) unless $id > $lastID`; 9335 `$lastID = $id`.
    if let Some(prev) = last_id
      && id <= prev
    {
      out.set_warning_at(
        Some(String::from(
          "Item property association entries are out of order",
        )),
        meta_abs_offset,
      );
    }
    last_id = Some(id);
  }
}

/// Decode an `ispe` (ImageSpatialExtent) box body → `(width, height)` (#146).
///
/// Faithful to QuickTime.pm:3034-3046: the box is `[version/flags 4 bytes]
/// [width int32u BE][height int32u BE]`, gated on `Condition => $$valPt =~
/// /^\0{4}/` (version/flags == 0). The `RawConv` `unpack("x4N*", $val)` skips
/// the 4-byte FullBox header and reads the u32 BE dimension array; `return undef
/// if @dim < 2`. Returns `None` for a non-zero version/flags word or a body
/// shorter than 12 bytes.
fn decode_ispe(body: &[u8]) -> Option<(u32, u32)> {
  // `Condition => '$$valPt =~ /^\0{4}/'` — version/flags must be all-zero.
  if body.get(..4) != Some(&[0, 0, 0, 0]) {
    return None;
  }
  let width = be_u32(body, 4)?;
  let height = be_u32(body, 8)?;
  Some((width, height))
}

/// Decode an `av1C` (AV1 Codec Configuration Record) box body into the three
/// non-`Unknown` `AV1Config` fields (#149).
///
/// Faithful to `%Image::ExifTool::QuickTime::AV1Config` (QuickTime.pm:3308-3367),
/// a `ProcessBinaryData` table (`FIRST_ENTRY => 0`, no `FORMAT` ⇒ each entry is
/// an `int8u` at its byte offset). The box body is the raw
/// `AV1CodecConfigurationRecord` — NO version/flags FullBox prefix. Each `Mask`d
/// field is `($byte & Mask) >> BitShift`, where `BitShift` is the mask's
/// trailing-zero count (ExifTool.pm:5916-5921 + :10079):
///   * byte 0: `AV1ConfigurationVersion` = `b0 & 0x7f` (BitShift 0).
///   * byte 2: `ChromaFormat` = `(b2 & 0x1c) >> 2`, `ChromaSamplePosition` =
///     `b2 & 0x03` (BitShift 0).
///
/// The `Unknown => 1` fields (`SeqProfile`/`SeqLevelIdx0` at byte 1,
/// `SeqTier0`/`HighBitDepth`/`TwelveBit` at byte 2, `InitialDelaySamples` at
/// byte 3) are not surfaced (exifast does not emit `-U`/`Unknown` tags), so they
/// are not decoded.
///
/// PER-FIELD availability matches `ProcessBinaryData` (ExifTool.pm:9963-9964):
/// each tag emits IFF its byte offset is within the body length —
/// `len >= 1` → `AV1ConfigurationVersion` (byte 0), INDEPENDENTLY of byte 2;
/// `len >= 3` → `ChromaFormat` + `ChromaSamplePosition` (byte 2).
/// So a 1- or 2-byte truncated `av1C` decodes ONLY `AV1ConfigurationVersion`
/// (`chroma_*` left `None`), and a 3+-byte body decodes all three (oracle:
/// crafted 1/2-byte AVIF → version only; 3+-byte → all three). A real record is
/// always ≥ 4 bytes; the truncated cases are only reached for a crafted box.
///
/// Returns `None` only for an EMPTY body (byte 0 absent ⇒ no field emits) — the
/// caller then leaves any earlier `av1C` config untouched.
fn decode_av1c(body: &[u8]) -> Option<crate::metadata::Av1Config> {
  let &b0 = body.first()?;
  let version = b0 & 0x7f;
  // byte 2 (`ChromaFormat`/`ChromaSamplePosition`) only when the body reaches it.
  let (chroma_format, chroma_sample_position) = match body.get(2) {
    Some(&b2) => (Some((b2 & 0x1c) >> 2), Some(b2 & 0x03)),
    None => (None, None),
  };
  Some(crate::metadata::Av1Config::new(
    Some(version),
    chroma_format,
    chroma_sample_position,
  ))
}

/// Emit `File:ImageWidth`/`File:ImageHeight` from this `meta`'s decoded `ipco`
/// `ispe` boxes, applying ExifTool's `DOC_NUM` main-document gate (#146).
///
/// ExifTool FoundTags `ImageWidth`/`ImageHeight` from the `ispe` `RawConv`
/// `unless ($$self{DOC_NUM})` (QuickTime.pm:3037-3045). The `ipco` container is
/// processed LAST (after `ipma` + `pitm`, QuickTime.pm:10361-10364) with
/// `IsItemProperty` set, and `DOC_NUM` is then derived per property index from
/// the item→property associations (QuickTime.pm:10196-10238):
///   * A property whose index NO item associates → `DOC_NUM` left undef → main
///     document → emits.
///   * A property associated with the PRIMARY item (`pitm`) → main document →
///     emits. (For `ispe`, `%dontInherit{ispe} == 1` (QuickTime.pm:497) disables
///     the refers-to-primary inheritance branches, so ONLY a direct primary
///     association — or no association at all — counts as main-document.)
///   * A property associated ONLY by non-primary item(s) → a sub-document
///     `DOC_NUM` → gated OUT (no dims).
///
/// Among all main-document `ispe`, ExifTool's duplicate-`ImageWidth` handling is
/// last-FoundTag-wins (the non-list `File:ImageWidth` is overwritten in `ipco`
/// walk order). So this walks `ispe_props` in `ipco` order and keeps the LAST
/// main-document one (oracle: two unassociated `ispe` 640×480 then 1280×960 →
/// `File:ImageWidth` = 1280; QuickTime.heic's primary `ispe` at index 2 →
/// 1596×1064, its index-4 thumbnail `ispe` gated out).
///
/// NEVER clears `out`: ExifTool's FoundTag is cumulative across the whole file,
/// so a later `meta` with no main-document `ispe` leaves the earlier dims intact
/// (oracle: meta1 primary `ispe` 640×480 + meta2 whose `ispe` is associated only
/// to a non-primary item → `File:ImageWidth` stays 640), while a later
/// main-document `ispe` overrides (oracle: meta2's primary `ispe` 11×22 wins).
fn emit_ispe_dimensions(
  ispe_props: &[(u32, u32, u32)],
  assoc: &[(u32, Vec<u16>)],
  out: &mut HeifMeta,
) {
  // `$$et{PrimaryItem} || 0` (QuickTime.pm:10199): ExifTool's Perl `|| 0` folds
  // a MISSING `pitm` (or a `pitm` of 0) to the EFFECTIVE primary item id `0`. So
  // an `ipma` row for item id 0 then matches the primary (`$id == $primary`) and
  // its associated `ispe` is main-document — a no-`pitm` file with an item-0
  // association DOES emit dims (oracle: no `pitm` + `ipma`{0 → ispe(111×222)} →
  // `File:ImageWidth` 111). With no `pitm` and only non-zero-id associations,
  // item 0 has no row so every associated `ispe` is a sub-document and only
  // UNassociated `ispe` stay main-document.
  let primary = out.primary_item().unwrap_or(0);

  // Precompute the effective association ONCE, instead of rescanning `assoc`
  // per `ispe`. A duplicate `ipma` row for an id overwrites the prior one
  // (QuickTime.pm:9331 `$$items{$id}{Association} = \@association`, a plain `=`),
  // so the LAST row per id is authoritative. Iterating rows in file order and
  // overwriting the per-id entry reproduces that last-wins rule (the old
  // `rfind`-per-distinct-id walk computed the same set, just quadratically).
  let mut effective: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
  for (id, indices) in assoc {
    effective.insert(*id, indices.iter().map(|&i| u32::from(i)).collect());
  }

  // Derive the two per-`ipco`-index lookups in one pass over the effective sets:
  // every property index referenced by ANY item, and those referenced by the
  // PRIMARY item. Total work is O(distinct ids × associations per id) = O(input),
  // done once rather than once per `ispe`.
  let mut associated_by_any: BTreeSet<u32> = BTreeSet::new();
  let mut associated_by_primary: BTreeSet<u32> = BTreeSet::new();
  for (id, indices) in &effective {
    associated_by_any.extend(indices.iter().copied());
    if *id == primary {
      associated_by_primary = indices.clone();
    }
  }

  // Walk `ispe_props` in `ipco` order ONCE. Main-document iff no item associates
  // the index OR the primary does; the in-order walk keeps the LAST such `ispe`.
  for &(index, w, h) in ispe_props {
    if !associated_by_any.contains(&index) || associated_by_primary.contains(&index) {
      out.set_image_width(Some(w));
      out.set_image_height(Some(h));
    }
  }
}

/// Crafted-magnitude safety bound on the TOTAL extents materialized by ALL
/// the `iloc` boxes across EVERY `meta` box in the file — a DoS floor, NOT a
/// faithful ExifTool count (ExifTool's `ParseItemLocation` has no such cap).
///
/// `ParseItemLocation` (QuickTime.pm:9155-9192) is an UNBOUNDED `num`
/// (Get16u for ver<2, a full Get32u — up to ~4.3 billion — for ver≥2) ×
/// `ext_num` (Get16u, up to 65535) double loop that `push`es one Perl
/// hash per extent. A crafted ~400 KB `iloc` whose `siz` nibbles are all
/// zero (zero-width extents consume NO bytes, so `GetVarInt` with `$n==0`
/// advances 0) can declare ~65535 items × ~65535 extents ⇒ ~4.3 billion
/// pushes — ExifTool itself runs out of memory and `die`s before it emits
/// anything.
///
/// The ceiling is CUMULATIVE across every `iloc` child of EVERY `meta` box in
/// the file, NOT reset per `iloc` box and NOT reset per `meta`. Either
/// granularity is defeatable by the SAME amplification one container level
/// apart: a crafted file can repeat MANY tiny `iloc` boxes (one `meta`), OR
/// MANY tiny top-level `meta` boxes (each with one just-under-cap `iloc`),
/// each declaring just under the cap so no single box trips it, yet the
/// summed retained extents are O(num_boxes × cap) — still OOM from a small
/// input. [`scan_quicktime_brands`] (the file-scope caller that loops the
/// `meta` boxes) therefore owns ONE shared remaining-budget (init to this
/// constant) and threads a `&mut` to it through every recursive call and into
/// every [`walk_heif_meta`] → [`parse_iloc_remaining`] call; once the GLOBAL
/// count of materialized extents reaches the ceiling, further extent parsing
/// stops regardless of which box (or which meta) it occurs in.
///
/// This bounds the work WITHOUT diverging on any real input: a real HEIF
/// has a handful of items each with a few extents (even an 8K image tiled
/// into 64×64 blocks is ~20K extents), and a real file has ONE `meta` with
/// ONE `iloc`, so the cumulative total is orders of magnitude below
/// `1 << 20` — this NEVER fires on a conforming file and the
/// byte-identical-conformance guarantee holds. Mirrors the
/// [`MAX_EXPANDED_SAMPLES`](crate::formats::quicktime_stream) timed-sample
/// magnitude bound.
pub(crate) const MAX_ILOC_EXTENTS: u64 = 1 << 20;

/// Parse the `iloc` body. Faithful port of `ParseItemLocation`
/// (QuickTime.pm:9131-9195). Returns `Err(warning)` on a structurally
/// malformed iloc (truncated header / count overflow). Bounds the total
/// extent work at [`MAX_ILOC_EXTENTS`] (a crafted-magnitude DoS floor;
/// see [`parse_iloc_remaining`]).
///
/// Test-only convenience: this 3-arg form allocates a FRESH per-call budget,
/// so each standalone `iloc` parses fully up to the cap on its own. The
/// production walk does NOT use it — [`scan_quicktime_brands`] threads one
/// shared budget through [`walk_heif_meta`] into [`parse_iloc_remaining`] so
/// the ceiling is CUMULATIVE across every `iloc` child of every `meta` box in
/// the file (see [`MAX_ILOC_EXTENTS`]).
#[cfg(test)]
fn parse_iloc(
  buf: &[u8],
  out: &mut HeifMeta,
  id_index: &mut BTreeMap<u32, usize>,
) -> Result<(), String> {
  parse_iloc_capped(buf, out, id_index, MAX_ILOC_EXTENTS)
}

/// [`parse_iloc`] with an explicit total-extent ceiling, so a test can
/// prove the bound with a small synthetic budget instead of crafting the
/// full billions-magnitude input. The budget is local to this call.
#[cfg(test)]
fn parse_iloc_capped(
  buf: &[u8],
  out: &mut HeifMeta,
  id_index: &mut BTreeMap<u32, usize>,
  max_extents: u64,
) -> Result<(), String> {
  let mut remaining = max_extents;
  parse_iloc_remaining(buf, out, id_index, &mut remaining)
}

/// Parse one `iloc` body (the worker behind [`parse_iloc`]), threading a
/// SHARED, decrement-to-zero extent budget owned by the caller. This is the
/// production entry the `meta` walk uses. [`scan_quicktime_brands`] holds one
/// `remaining` (init [`MAX_ILOC_EXTENTS`]) at FILE scope and passes the SAME
/// `&mut` — through every recursive call and every [`walk_heif_meta`] — to
/// EVERY `iloc` child of EVERY `meta` box, so the cap is CUMULATIVE file-wide
/// rather than resetting per `iloc` box or per `meta`. A crafted file cannot
/// defeat the bound by splitting its flood into many tiny boxes (or many
/// meta boxes) each just under a per-box cap. Each materialized extent
/// decrements `*remaining`; when it hits 0 the walk stops (returning the
/// in-budget prefix) — and a subsequent item row is refused at the top of the
/// `num` loop so a post-cap zero-extent row cannot overwrite a retained item
/// — bounding the cumulative retained extents regardless of how many `iloc`
/// boxes precede or follow.
fn parse_iloc_remaining(
  buf: &[u8],
  out: &mut HeifMeta,
  id_index: &mut BTreeMap<u32, usize>,
  remaining: &mut u64,
) -> Result<(), String> {
  let ver = *buf.first().ok_or_else(|| String::from("Truncated iloc"))?;
  if buf.len() < 8 {
    return Err(String::from("Truncated iloc"));
  }
  let siz = be_u16(buf, 4).ok_or_else(|| String::from("Truncated iloc siz"))?;
  // QuickTime.pm:9143-9146: extract the 4 nibbles (each 0/4/8).
  let noff = ((siz >> 12) & 0x0f) as u8;
  let nlen = ((siz >> 8) & 0x0f) as u8;
  let nbas = ((siz >> 4) & 0x0f) as u8;
  let nind = (siz & 0x0f) as u8;
  // QuickTime.pm:9147-9154: item count is u16 for ver<2, u32 for ver==2.
  let (num, mut pos): (u32, usize) = if ver < 2 {
    let n = be_u16(buf, 6).ok_or_else(|| String::from("Truncated iloc num"))? as u32;
    (n, 8)
  } else {
    if buf.len() < 10 {
      return Err(String::from("Truncated iloc num32"));
    }
    let n = be_u32(buf, 6).ok_or_else(|| String::from("Truncated iloc num32"))?;
    (n, 10)
  };
  // The `num` × `ext_num` nesting (QuickTime.pm:9155 `for $i<$num` / 9178
  // `for $j<$ext_num`) is faithfully UNbounded in COUNT — `num` is a u16
  // (ver<2) or a full Get32u (ver≥2), `ext_num` a u16 — but the cumulative
  // extents materialized are capped by the caller-owned `*remaining` budget
  // ([`MAX_ILOC_EXTENTS`] in production, threaded across ALL iloc boxes of
  // EVERY meta box in the file). Zero-width extents (every `siz` nibble 0)
  // consume NO bytes,
  // so a crafted iloc CAN declare billions of empty extents that ExifTool
  // would OOM on; once `*remaining` reaches 0 we stop the walk (returning
  // the in-budget prefix), bounding the pushes WITHOUT diverging on any real
  // input (a real iloc is orders of magnitude under the ceiling). See
  // [`MAX_ILOC_EXTENTS`] for why this can never fire on a conforming HEIF.
  for _ in 0..num {
    // #218 — STOP before COMMITTING any item row once the shared, caller-owned
    // extent budget is exhausted. The per-extent guard below stops the EXTENT
    // loop, but an item with `ext_num == 0` never enters that loop, so without
    // this row-level check a post-cap zero-extent iloc row for an id reused
    // from an already-retained item would still reach the unconditional slot
    // writeback and OVERWRITE that item's BaseOffset + Extents with an empty
    // vector — making the post-ceiling tail observable. Checking `*remaining`
    // here makes EVERY post-cap row (including `ext_num == 0`) a complete
    // no-op: parsing stops, no slot is mutated, and the in-budget prefix
    // already merged survives intact. (ExifTool would have OOM'd materializing
    // the declared billions of extents, so this tail is unobservable anyway;
    // unreachable on any real HEIF — see [`MAX_ILOC_EXTENTS`].)
    if *remaining == 0 {
      return Ok(());
    }
    // Item id (u16 for ver<2, u32 for ver>=2).
    let id = if ver < 2 {
      let id = u32::from(be_u16(buf, pos).ok_or_else(|| String::from("Truncated iloc id"))?);
      pos += 2;
      id
    } else {
      let id = be_u32(buf, pos).ok_or_else(|| String::from("Truncated iloc id32"))?;
      pos += 4;
      id
    };
    // ConstructionMethod for ver==1 or ver==2 (2-byte u16, low nibble).
    // QuickTime.pm:9165-9168 assigns `$$items{$id}{ConstructionMethod}`
    // ONLY inside the `if ($ver == 1 or $ver == 2)` branch — a v0 iloc row
    // never touches the field, so a prior v1/v2 row's value must persist.
    // `None` therefore means "this row did not assign it" (merge keeps
    // prior); `Some(cm)` overwrites (last-wins).
    let construction_method = if ver == 1 || ver == 2 {
      if pos + 2 > buf.len() {
        return Err(String::from("Truncated iloc constMeth"));
      }
      let cm = be_u16(buf, pos).ok_or_else(|| String::from("Truncated iloc constMeth"))? & 0x0f;
      pos += 2;
      Some(cm)
    } else {
      None
    };
    // DataReferenceIndex (always 2 bytes, present in every version).
    if pos + 2 > buf.len() {
      return Err(String::from("Truncated iloc dataRefIdx"));
    }
    pos += 2; // skipped — bundled stores it but exifast doesn't use it.
    // BaseOffset (nbas bytes). QuickTime.pm:9173 `GetVarInt(\$val, $pos,
    // $nbas)` — no explicit default, so `$default || 0` yields 0.
    let base_offset = get_var_int(buf, &mut pos, nbas, 0).unwrap_or(0);
    // Extent count (2 bytes).
    if pos + 2 > buf.len() {
      return Err(String::from("Truncated iloc ext_num"));
    }
    let ext_num = be_u16(buf, pos).ok_or_else(|| String::from("Truncated iloc ext_num"))? as u32;
    pos += 2;
    let mut extents: Vec<HeifExtent> = Vec::new();
    for _ in 0..ext_num {
      // ExtentIndex (nind bytes, only for ver 1/2) — discarded.
      // QuickTime.pm:9180 `GetVarInt(\$val, $pos, $nind, 1)` — default 1.
      if ver == 1 || ver == 2 {
        let _ = get_var_int(buf, &mut pos, nind, 1);
      }
      // QuickTime.pm:9182 `GetVarInt(\$val, $pos, $noff)` — default 0.
      let extent_offset = get_var_int(buf, &mut pos, noff, 0).unwrap_or(0);
      // QuickTime.pm:9183 `$extent_length = GetVarInt(\$val, $pos, $nlen)`
      // (default 0), then QuickTime.pm:9184 `return undef unless defined
      // $extent_length` — a `None` here aborts the WHOLE iloc parse.
      //
      // `GetVarInt` only returns `None` (undef) on a short read OR an
      // invalid width (`$n` not in {0,4,8}); `$nlen == 0` returns the
      // DEFINED default 0, so a zero length-size nibble keeps a length-0
      // extent (the `parse_iloc_nlen_zero_keeps_item_with_zero_length`
      // case). A non-conforming nibble (e.g. 2 or 5) yields `None` → abort.
      let extent_length = match get_var_int(buf, &mut pos, nlen, 0) {
        Some(v) => v,
        None => return Err(String::from("Truncated iloc extent length")),
      };
      // Crafted-magnitude DoS floor (extent granularity): once the shared,
      // caller-owned extent budget is exhausted MID-item, STOP the walk. The
      // budget is CUMULATIVE across every iloc box of every meta in the file
      // (`*remaining` is owned by `scan_quicktime_brands` and threaded through
      // `walk_heif_meta`), so a flood split over many tiny boxes — or many
      // meta boxes — is bounded in total. This per-extent guard handles a
      // budget that drains BETWEEN extents of one item; the row-level guard at
      // the top of `for _ in 0..num` handles a budget already drained when a
      // (possibly `ext_num == 0`) item row BEGINS, so the post-cap slot
      // writeback below can never run. ExifTool would have OOM'd materializing
      // the declared billions of extents, so the post-ceiling tail is
      // unobservable; exifast keeps the fully-merged prior items and drops the
      // in-progress one — bounded, no OOM, no spin. Unreachable on any real
      // HEIF (see [`MAX_ILOC_EXTENTS`]).
      if *remaining == 0 {
        return Ok(());
      }
      *remaining -= 1;
      let mut e = HeifExtent::new();
      // Fold BaseOffset in (faithful to QuickTime.pm:9397 `my $base =
      // ($$item{BaseOffset} || 0) + (...)`).
      e.set_offset(base_offset.saturating_add(extent_offset))
        .set_length(extent_length);
      extents.push(e);
    }
    // Write the iloc-owned fields into the keyed slot, OVERWRITING any
    // prior iloc row for this id (last-wins) — `BaseOffset` (:9173, ALWAYS
    // assigned) and the whole `Extents` vector (:9192, `= \@extents` →
    // REPLACE, never append) are written unconditionally; `ConstructionMethod`
    // (:9167) is written only when THIS row assigned it (v1/v2 → `Some`),
    // leaving a prior value when this is a v0 row (`None`). Any `infe`-owned
    // Name/Type/ContentType already on the slot are left untouched (the
    // iinf/iloc cross-merge).
    let idx = item_slot_index(out, id_index, id);
    if let Some(slot) = out.items_mut().get_mut(idx) {
      slot.set_base_offset(base_offset);
      if let Some(cm) = construction_method {
        slot.set_construction_method(cm);
      }
      slot.set_extents(extents);
    }
  }
  Ok(())
}

/// Find — or first-time create — the [`HeifItem`] slot keyed by item id,
/// returning its index in `out.items()`. Mirrors ExifTool's
/// `$$items{$id}` autovivifying hash access (QuickTime.pm:9167-9192,
/// 9242-9265): the FIRST box (`iloc` or `infe`) to mention an id creates
/// the entry, and EVERY box thereafter for that id resolves to the SAME
/// entry and assigns its own fields into it.
///
/// The "have I seen this id?" test is an O(log n) `id_index` probe
/// (`BTreeMap<item-id → Vec index>`) carried across the whole `meta`
/// walk, NOT a linear `items_mut().find()` per item — that per-item
/// linear scan made an n-unique-id `iloc`/`iinf` O(n²). A new id is
/// appended (preserving first-appearance walk order) and its index
/// recorded; a known id resolves to its existing slot. The map mirrors
/// ExifTool's keyed `$$items{$id}` exactly (insert-once, lookup-many).
///
/// Faithfulness — field OWNERSHIP, last-wins overwrite (NOT first-wins,
/// NOT concat). ExifTool's two parsers assign DISJOINT field sets per
/// id, each with a plain `=` (so a repeat of the SAME box overwrites
/// that box's fields — the LAST assignment wins):
///  - `ParseItemLocation`/`iloc` assigns `ConstructionMethod`
///    (QuickTime.pm:9167), `DataReferenceIndex` (:9171), `BaseOffset`
///    (:9173) and `Extents` (:9192, `= \@extents` — REPLACE the whole
///    vector, never append).
///  - `ParseItemInfoEntry`/`infe` assigns `ProtectionIndex`
///    (:9242/:9256), `Name` (:9244/:9260), `ContentType` (:9245/:9262),
///    `ContentEncoding` (:9246/:9263), `Type` (:9258, ver 2/3) and `URI`
///    (:9265, type `uri ` only).
///
/// Because the sets are disjoint, a normal item (in BOTH iinf and iloc)
/// cross-merges — `infe`'s Name/Type and `iloc`'s Extents coexist — while
/// a repeat of ONE source overwrites only that source's fields. The two
/// call sites below ([`parse_iloc_remaining`] and the `iinf` arm of
/// [`walk_heif_meta`]) each write EXACTLY their owned subset into the
/// returned slot; `DataReferenceIndex`/`ProtectionIndex`/
/// `ContentEncoding`/`URI` are not surfaced by [`HeifItem`] and so are
/// parsed-past but not stored.
fn item_slot_index(out: &mut HeifMeta, id_index: &mut BTreeMap<u32, usize>, id: u32) -> usize {
  if let Some(&idx) = id_index.get(&id) {
    return idx;
  }
  let new_index = out.items().len();
  let mut it = HeifItem::new();
  it.set_id(id);
  out.push_item(it);
  id_index.insert(id, new_index);
  new_index
}

// ===========================================================================
// Canon CR3 — UUID walker (Canon::uuid table at Canon.pm:9657-9738)
// ===========================================================================

/// The Canon UUID prefix from QuickTime.pm:1237:
/// `85 c0 b6 87 82 0f 11 e0 81 11 f4 ce 46 2b 6a 48`. Inside any `uuid`
/// box whose 16-byte payload begins with this prefix, the remaining
/// bytes are a sequence of Canon-specific sub-boxes (Canon.pm:9657-9738).
const CANON_UUID: [u8; 16] = [
  0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
];

/// Render one parsed CMT Exif block (`ExifMeta`) into [`EmittedTag`]s for the
/// requested conv mode, re-stamping its TOP-LEVEL `IFD0` directory to
/// `top_family1` (CMT1 → `"IFD0"`; CMT2 → `"ExifIFD"`). The
/// `File:ExifByteOrder` marker (family-0 `File`) and any NESTED sub-IFD group
/// (ExifIFD/GPS/InteropIFD/IFD1) pass through verbatim — mirroring the CTMD
/// re-stamp. `meta` is borrowed, so this is called twice (once per mode) on the
/// SAME parse.
#[cfg(feature = "alloc")]
fn render_exif_block(
  meta: &crate::exif::ExifMeta<'_>,
  top_family1: &str,
  print_conv: bool,
) -> Vec<crate::emit::EmittedTag> {
  use crate::emit::{EmittedTag, Taggable};
  use crate::value::Group;
  let opts =
    crate::emit::EmitOptions::g1(crate::emit::ConvMode::from_print_conv(print_conv), false);
  let mut out = Vec::new();
  for tag in meta.tags(opts) {
    let unknown = tag.unknown();
    let (group, name, value) = tag.into_tag().into_parts();
    let restamped = if group.family0() == "File" {
      // `File:ExifByteOrder` (and the gated `File:PageCount`, never set for an
      // embedded block) keep their `File:File` group.
      group
    } else if group.family1() == "IFD0" {
      // The generic walker's top-level directory → the box's SubDirectory Name.
      Group::new("EXIF", top_family1)
    } else {
      // A nested sub-IFD (ExifIFD/GPS/InteropIFD/IFD1) keeps its DirName.
      group
    };
    out.push(EmittedTag::new(restamped, name, value, unknown));
  }
  out
}

/// Render a CMT3 Canon-MakerNote block (a self-contained TIFF whose IFD0 IS the
/// Canon MakerNote) into `MakerNotes:Canon` [`EmittedTag`]s for the requested
/// mode, threading `model` (`$$self{Model}` of the most-recent PRECEDING CMT1)
/// into `Canon::Main` for its model-conditional sub-tables. Routes through
/// [`redispatch_ctmd_makernote`](crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote)
/// (the SAME `ProcessTIFF`-under-`Canon::Main` machinery CTMD's `0x927c` uses).
#[cfg(feature = "alloc")]
fn render_cmt3_block(
  body: &[u8],
  print_conv: bool,
  model: Option<&str>,
) -> Vec<crate::emit::EmittedTag> {
  use crate::emit::EmittedTag;
  use crate::value::Group;
  let group = Group::new("MakerNotes", "Canon");
  crate::exif::makernotes::vendors::canon::redispatch_ctmd_makernote(body, print_conv, model)
    .into_iter()
    .map(|e| {
      EmittedTag::new(
        group.clone(),
        smol_str::SmolStr::new(e.name()),
        e.value().clone(),
        e.unknown(),
      )
    })
    .collect()
}

/// Render a CMT4 GPS block (walked top-level against the GPS table) into
/// [`EmittedTag`]s for the requested mode. `meta` is borrowed, so this is
/// called twice (once per mode) on the SAME parse.
#[cfg(feature = "alloc")]
fn render_gps_block(
  meta: &crate::exif::ExifMeta<'_>,
  print_conv: bool,
) -> Vec<crate::emit::EmittedTag> {
  use crate::emit::Taggable;
  let opts =
    crate::emit::EmitOptions::g1(crate::emit::ConvMode::from_print_conv(print_conv), false);
  meta.tags(opts).collect()
}

/// Walk a Canon-UUID atom body and populate `out`. The UUID prefix has
/// ALREADY been stripped — `body` is the post-`Start => 16` payload
/// (QuickTime.pm:1240).
///
/// `abs_offset` is the absolute file offset of `body`'s first byte —
/// used so CMT block offsets stay file-absolute.
///
/// Each CMT1-4 box is a self-contained TIFF / Canon-MakerNote block that
/// ExifTool re-dispatches through `ProcessTIFF` / `ProcessCMT3`
/// (Canon.pm:9686-9726): CMT1 → IFD0 (`Exif::Main`), CMT2 → ExifIFD
/// (`Exif::Main`), CMT3 → MakerNoteCanon (`Canon::Main` via `ProcessCMT3`),
/// CMT4 → GPS (`GPS::Main`). Those bodies are parsed EAGERLY here, in FILE
/// order, while the input buffer is in scope — the body is a SUB-SLICE of the
/// loaded input ([`walk_boxes`] rejects any box whose declared length exceeds
/// the buffer), so the parse borrows it with NO copy. The decoded tags are
/// rendered for BOTH conv modes (`-j` PrintConv + `-n` ValueConv, since
/// emission is mode-dependent) and the resulting OWNED [`EmittedTag`]s stored
/// on `out` ([`Cr3Meta::push_cmt_tags`]). The raw box bytes are NEVER retained;
/// only the box LOCATION (offset + length) is recorded
/// ([`Cr3Meta::record_cmt_location`], a fixed per-kind slot).
///
/// This bounds the total CMT allocation to the parsed TAG count (the Exif
/// walker already caps IFD entries) — proportional to the input size, with NO
/// per-box growth (an empty CMT box yields no tags) and NO per-`uuid`-atom
/// amplification (every box appends to the SAME `out`, there is no running
/// per-atom budget to reset). So multiple moov-level Canon `uuid` atoms, or
/// millions of tiny / empty CMT boxes, can neither blow memory nor spin CPU.
///
/// `$$self{Model}` is FILE-WALK object state, NOT per-`uuid`-atom: ExifTool sets
/// it whenever ANY IFD0 / CMT1 `Model` (0x0110) is handled, and it persists for
/// the rest of the moov tree walk. So a CMT3's model-conditional dispatch reads
/// the most-recent PRECEDING CMT1 `Model` even when that CMT1 was in an EARLIER
/// Canon `uuid` atom. To match that, the model state is owned by the SCAN
/// ([`scan_quicktime_brands`]) and threaded in through `current_model` so it
/// survives across multiple Canon `uuid` atoms in file order. This entry point
/// is a thin wrapper that runs an ISOLATED walk with a FRESH `None` state (for
/// standalone callers); the scan uses [`walk_canon_uuid_with_state`] directly.
/// ExifTool only ASSIGNS `$$self{Model}` when a `Model` tag is handled, so a
/// model-LESS CMT1 does NOT clear an earlier Model, and a CMT3 before ANY CMT1
/// sees `None`.
pub fn walk_canon_uuid(body: &[u8], abs_offset: u64, out: &mut Cr3Meta) {
  let mut current_model: Option<SmolStr> = None;
  walk_canon_uuid_with_state(body, abs_offset, out, &mut current_model);
}

/// [`walk_canon_uuid`] threaded with the FILE-WALK `$$self{Model}` state
/// (`current_model`) so it persists across multiple Canon `uuid` atoms — the
/// IFD0 `Model` of the most-recent PRECEDING CMT1 that actually carried one. A
/// CMT1 with a `Model` UPDATES it; a model-less CMT1 leaves it; a CMT3 READS it
/// for model-conditional Canon MakerNote sub-tables (Canon.pm:1834, `0x96`).
pub fn walk_canon_uuid_with_state(
  body: &[u8],
  abs_offset: u64,
  out: &mut Cr3Meta,
  current_model: &mut Option<SmolStr>,
) {
  walk_boxes(body, abs_offset, Size0Behavior::Stop, |h| {
    match h.tag {
      // CNCV — CompressorVersion (Canon.pm:9666-9669). The body is an ASCII
      // string `"CanonCR3 0.x.xx"` / `"CanonCRM 0.x.xx"` / `"CanonMP4 0.x.xx"`.
      b"CNCV" => {
        // OVERRIDE — ExifTool runs `$val =~ /^Canon(\w{3})/i` on the RAW value
        // (Canon.pm:9669 RawConv): anchored `^Canon` (case-insensitive), then
        // capture 3 Perl-`\w` bytes (`[A-Za-z0-9_]`, INCLUDING underscore).
        // Derive it from the RAW BYTES, NOT a UTF-8/trimmed display string —
        // a LEADING SPACE must NOT match (the pattern is anchored) and a
        // TRAILING non-UTF-8 byte must NOT suppress the ASCII-prefix match.
        // `$1` is captured as-is (real CNCV codes are uppercase ASCII 4CCs:
        // `CR3`/`CRM`/`MP4`); the downstream FileType override only fires for
        // known codes.
        if h
          .body
          .get(..5)
          .is_some_and(|p| p.eq_ignore_ascii_case(b"Canon"))
          && let Some(three) = h.body.get(5..8)
          && three
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
          && let Ok(code) = core::str::from_utf8(three)
        {
          out.set_override_file_type(Some(SmolStr::from(code)));
        }
        // VALUE — `$val` is returned unchanged (Canon.pm:9669). exifast stores
        // it as a display string (UTF-8, trailing-NUL trimmed); a non-UTF-8
        // body yields an empty/best-effort value but does NOT affect the
        // raw-byte override above (the two are now decoupled).
        let s = core::str::from_utf8(h.body)
          .unwrap_or("")
          .trim_end_matches('\0');
        if !s.is_empty() {
          out.set_compressor_version(Some(SmolStr::from(s)));
        }
      }
      // CMT1 — IFD0 (`Exif::Main`). Parsed ONCE; the parse both updates the
      // file-walk `$$self{Model}` (read by a later CMT3, even one in a LATER
      // Canon `uuid` atom) and renders the IFD0 tags for both modes. The Model
      // is updated ONLY when this CMT1 actually carries one (a model-less CMT1
      // does not clear an earlier Model).
      b"CMT1" => {
        out.record_cmt_location(
          Cr3CmtKind::Cmt1,
          Cr3Block::at(h.body_abs_start, h.body.len() as u64),
        );
        if let Some(meta) = crate::exif::parse_exif_block(h.body) {
          if let Some(model) = meta.dispatcher_model() {
            *current_model = Some(SmolStr::new(model));
          }
          let print = render_exif_block(&meta, "IFD0", true);
          let value = render_exif_block(&meta, "IFD0", false);
          out.push_cmt_tags(print, value);
        }
      }
      // CMT2 — ExifIFD (`Exif::Main`).
      b"CMT2" => {
        out.record_cmt_location(
          Cr3CmtKind::Cmt2,
          Cr3Block::at(h.body_abs_start, h.body.len() as u64),
        );
        if let Some(meta) = crate::exif::parse_exif_block(h.body) {
          let print = render_exif_block(&meta, "ExifIFD", true);
          let value = render_exif_block(&meta, "ExifIFD", false);
          out.push_cmt_tags(print, value);
        }
      }
      // CMT3 — MakerNoteCanon (`Canon::Main` via `ProcessCMT3`), threaded with
      // the file-walk `$$self{Model}` of the most-recent PRECEDING CMT1 (or
      // `None`) — which may have been set in an EARLIER Canon `uuid` atom.
      b"CMT3" => {
        out.record_cmt_location(
          Cr3CmtKind::Cmt3,
          Cr3Block::at(h.body_abs_start, h.body.len() as u64),
        );
        let print = render_cmt3_block(h.body, true, current_model.as_deref());
        let value = render_cmt3_block(h.body, false, current_model.as_deref());
        out.push_cmt_tags(print, value);
      }
      // CMT4 — GPS (`GPS::Main`).
      b"CMT4" => {
        out.record_cmt_location(
          Cr3CmtKind::Cmt4,
          Cr3Block::at(h.body_abs_start, h.body.len() as u64),
        );
        if let Some(meta) = crate::exif::parse_gps_block(h.body) {
          let print = render_gps_block(&meta, true);
          let value = render_gps_block(&meta, false);
          out.push_cmt_tags(print, value);
        }
      }
      // CNTH — CanonCNTH preview (Canon.pm:9670-9673).
      b"CNTH" => {
        out.set_cnth(Some(Cr3Block::at(h.body_abs_start, h.body.len() as u64)));
      }
      // THMB — ThumbnailImage (Canon.pm:9727-9733).
      // TODO(#159-followup: CR3 ThumbnailImage): only the THMB block location
      // is recorded; the `(Binary data N bytes, …)` ThumbnailImage extraction
      // is out of camera-indexing scope.
      b"THMB" => {
        out.set_thmb(Some(Cr3Block::at(h.body_abs_start, h.body.len() as u64)));
      }
      _ => {}
    }
  });
}

// ===========================================================================
// Container-table-context brand dispatch (the unified meta + Canon-uuid walk)
// ===========================================================================

/// A `Image::ExifTool::QuickTime::*` container table, used to drive the
/// brand-variant `meta` / Canon-`uuid` dispatch with the SAME container
/// context ExifTool's `ProcessMOV` carries via the `SubDirectory` `TagTable`
/// chain. Each ISO-BMFF container atom maps to the table that `ProcessMOV`
/// would process its children through; that table decides
///  - at WHICH offset a child `meta` box's items begin
///    ([`Self::meta_child_start`]) — the `SubDirectory` `Start` of the `meta`
///    entry in that table, and
///  - WHETHER a Canon-prefix `uuid` is dispatched to `Canon::uuid`
///    ([`Self::dispatches_canon_uuid`]) — present ONLY in `%Movie`, and
///  - which CHILD table a sub-container recurses into
///    ([`Self::child_table`]).
///
/// This replaces the two earlier flat re-walks (`scan_heif_meta` +
/// `scan_canon_uuid`) and their ad-hoc `in_moov` booleans with one walker
/// that mirrors ExifTool's container hierarchy faithfully — so a `meta`
/// parses at its table-correct offset in EVERY position (Main / Movie /
/// Track / MovieFragment / TrackFragment / UserData), not just at the file
/// root and one `moov` deep.
///
/// SP4 scope: only the tables that can REACH a `meta` (HEIF items) or a
/// Canon `uuid` (CR3 override) are modeled. The leaf tables `Media`/`minf`/
/// `stbl` carry no `meta`/Canon-`uuid`, so the recursion stops at `mdia`
/// (`child_table` returns `None` for it) — descending further would find
/// nothing for this scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QtTable {
  /// `%Image::ExifTool::QuickTime::Main` — the top-level file table
  /// (QuickTime.pm:548). Its `meta` is a FullBox (`Start => 4`,
  /// QuickTime.pm:556).
  Main,
  /// `%Image::ExifTool::QuickTime::Movie` (`moov`, QuickTime.pm:1201). Its
  /// `meta` has NO `Start` (offset 0, QuickTime.pm:1218); it is the ONLY
  /// table that dispatches the Canon `uuid` (QuickTime.pm:1239).
  Movie,
  /// `%Image::ExifTool::QuickTime::Track` (`trak`, QuickTime.pm:1424). `meta`
  /// at offset 0 (QuickTime.pm:1440).
  Track,
  /// `%Image::ExifTool::QuickTime::MovieFragment` (`moof`,
  /// QuickTime.pm:1293). `meta` at offset 0 (QuickTime.pm:1305).
  MovieFragment,
  /// `%Image::ExifTool::QuickTime::TrackFragment` (`traf`,
  /// QuickTime.pm:1320). `meta` at offset 0 (QuickTime.pm:1324).
  TrackFragment,
  /// `%Image::ExifTool::QuickTime::UserData` (`udta`, QuickTime.pm:1585). Its
  /// `meta` is a FullBox (`Start => 4`, QuickTime.pm:1691).
  UserData,
}

impl QtTable {
  /// The byte offset at which a child `meta` box's items begin in THIS table
  /// — the `SubDirectory` `Start` of the table's `meta` entry. `4` for the
  /// two FullBox positions (`%Main` QuickTime.pm:556, `%UserData`
  /// QuickTime.pm:1691 — skip the 1-byte version + 3-byte flags); `0`
  /// everywhere else (`%Movie`/`%Track`/`%MovieFragment`/`%TrackFragment`
  /// `meta` carry NO `Start`, so their children begin at offset 0 — the
  /// Sony/Casio MOV `moov/meta` is not a FullBox, QuickTime.pm:1218).
  const fn meta_child_start(self) -> usize {
    match self {
      Self::Main | Self::UserData => 4,
      Self::Movie | Self::Track | Self::MovieFragment | Self::TrackFragment => 0,
    }
  }

  /// Whether a Canon-prefix `uuid` (`85 c0 b6 87 …`) found directly in THIS
  /// table is dispatched to `Image::ExifTool::Canon::uuid` (CNCV + the
  /// CR3/CRM FileType override). The `UUID-Canon` entry is wired ONLY in
  /// `%QuickTime::Movie` (QuickTime.pm:1239); no other QuickTime container
  /// table — not `%Main`, not `%Track`, not `%UserData` — carries it. So a
  /// `crx ` file with a TOP-LEVEL or `trak`-level `85 c0 b6 87 …` uuid is
  /// left as CRX (no promotion), exactly as ExifTool leaves it. (`%Main`'s
  /// only Canon `uuid` is `UUID-Canon2`, the `21 0f 16 87 …` prefix →
  /// `Canon::uuid2`, QuickTime.pm:731-738 — a DIFFERENT box, out of SP4
  /// scope.)
  const fn dispatches_canon_uuid(self) -> bool {
    matches!(self, Self::Movie)
  }

  /// The child container table a sub-box recurses into, per ExifTool's
  /// `SubDirectory` `TagTable` edges — `None` when the box is not a container
  /// that can reach a `meta` / Canon-`uuid` for this scan (so the walk does
  /// not descend it). The modeled edges:
  ///  - `%Main`: `moov`→`%Movie` (QuickTime.pm:678), `moof`→`%MovieFragment`
  ///    (QuickTime.pm:682). The top-level `udta` is a `%QuickTime::Stream`
  ///    SubDirectory (KenwoodData/LigoJSON/…, QuickTime.pm:826) — NOT
  ///    `%UserData` — and carries no HEIF `meta`, so it is NOT descended.
  ///  - `%Movie`: `trak`→`%Track` (QuickTime.pm:1211), `udta`→`%UserData`
  ///    (QuickTime.pm:1214).
  ///  - `%Track`: `udta`→`%UserData` (QuickTime.pm:1432). `mdia`→`%Media`
  ///    (QuickTime.pm:1440) leads only to `minf`/`stbl`, which carry no
  ///    `meta`/Canon-`uuid`, so SP4 returns `None` for `mdia` (the recursion
  ///    stops there rather than walking a `%Media` variant that reaches
  ///    nothing).
  ///  - `%MovieFragment`: `traf`→`%TrackFragment` (QuickTime.pm:1303).
  ///  - `%TrackFragment`, `%UserData`: leaves for SP4 — their only
  ///    meta-bearing child is `meta` itself (handled directly), with no
  ///    further meta-bearing container.
  fn child_table(self, tag: &[u8]) -> Option<Self> {
    match (self, tag) {
      (Self::Main, b"moov") => Some(Self::Movie),
      (Self::Main, b"moof") => Some(Self::MovieFragment),
      (Self::Movie, b"trak") => Some(Self::Track),
      (Self::Movie, b"udta") => Some(Self::UserData),
      (Self::Track, b"udta") => Some(Self::UserData),
      (Self::MovieFragment, b"traf") => Some(Self::TrackFragment),
      _ => None,
    }
  }
}

/// Walk a QuickTime container atom's boxes in the context of `table` (an
/// `Image::ExifTool::QuickTime::*` table), populating the HEIF item view
/// `heif` and the Canon CR3 view `cr3`. This is the unified brand-variant
/// dispatch — the faithful container-table-context replacement for the two
/// earlier flat re-walks (the `meta`-finding `scan_heif_meta` and the
/// Canon-`uuid`-finding `scan_canon_uuid`).
///
/// For each box in `boxes`:
///  - a `meta` box → its HEIF items are parsed via [`walk_heif_meta`] at the
///    table-correct child offset ([`QtTable::meta_child_start`]). The SAME
///    `QuickTime::Meta` table holds the HEIF item parsers (`iinf`/`iloc`/
///    `pitm`/`iprp`) in EVERY position, so a `moov/meta` / `trak/meta` / etc.
///    carrying item info IS parsed — at the position-correct offset.
///  - a Canon-prefix `uuid` box → dispatched to [`walk_canon_uuid_with_state`]
///    ONLY when `table.dispatches_canon_uuid()` (i.e. `table == Movie`,
///    QuickTime.pm:1239); otherwise it is IGNORED (a top-level / `trak` /
///    `udta` Canon `uuid` is not in those tables, so the file stays CRX).
///  - any other box that is a recursion edge ([`QtTable::child_table`]) →
///    recurse into it with the child table.
///
/// `current_model` is the file-walk `$$self{Model}` — a single mutable value
/// threaded through the WHOLE recursive walk in file order so a CMT3's
/// model-conditional Canon MakerNote dispatch reads the most-recent preceding
/// CMT1 `Model` even across multiple Canon `uuid` atoms (or recursion edges).
/// The top-level caller seeds it with `None`.
///
/// `iloc_extents_remaining` is the FILE-SCOPED HEIF `iloc` extent budget
/// (#218): a single remaining-count the top-level caller seeds with
/// [`MAX_ILOC_EXTENTS`] and that is threaded — by the SAME `&mut` — through
/// every recursive call AND into every [`walk_heif_meta`] invocation. So ONE
/// ceiling bounds the total materialized extents across ALL `meta` boxes
/// anywhere in the file, not per-meta and not per-`iloc`-box. This closes the
/// container-level amplification a crafted file otherwise gets from many small
/// `meta` boxes, each carrying a just-under-cap zero-width `iloc` (the same
/// flood one level up from the multi-`iloc` case `walk_heif_meta` already
/// bounds). A conforming file has one `meta` with one `iloc` of a few extents,
/// so the budget never fires and the byte-identical-conformance guarantee
/// holds (see [`MAX_ILOC_EXTENTS`]).
///
/// `boxes` is the atom's payload, `abs_offset` its absolute file offset
/// (folded into per-extent / per-block offsets), `depth` the recursion
/// budget (Golden-v2 Contract 3a: capped at [`MAX_ATOM_DEPTH`] — the SAME
/// cap the core `walk_atoms` walker uses — so a crafted file with thousands
/// of nested containers stops CLEANLY instead of recursing to a stack
/// overflow; real CR3/HEIF nest a single container deep). The walk uses
/// [`Size0Behavior::Stop`] (QuickTime/ISO-BMFF semantics: a size-0 atom is a
/// Terminator/ExtendsToEof — `ProcessMOV` never decodes its body as child
/// boxes, QuickTime.pm:10036-10056).
pub fn scan_quicktime_brands(
  boxes: &[u8],
  abs_offset: u64,
  table: QtTable,
  depth: u32,
  heif: &mut HeifMeta,
  cr3: &mut Cr3Meta,
  current_model: &mut Option<SmolStr>,
  iloc_extents_remaining: &mut u64,
) {
  if depth >= MAX_ATOM_DEPTH {
    return;
  }
  walk_boxes(boxes, abs_offset, Size0Behavior::Stop, |h| {
    if h.tag == b"meta" {
      // The shared `QuickTime::Meta` table parses the HEIF item boxes
      // unconditionally; the only per-position difference is the child
      // offset (`Start => 4` for the FullBox positions Main/UserData, else
      // 0). A `moov/meta` that is iTunes-style (hdlr/keys/ilst, no
      // iinf/iloc) simply yields no HEIF items — correct.
      walk_heif_meta(
        h.body,
        h.body_abs_start,
        table.meta_child_start(),
        heif,
        iloc_extents_remaining,
      );
    } else if h.tag == b"uuid"
      && h.body.get(..16) == Some(&CANON_UUID[..])
      && let Some(rest) = h.body.get(16..)
    {
      // A Canon-prefix `uuid` is dispatched (CNCV + CR3/CRM override) ONLY
      // from `%Movie` (QuickTime.pm:1239); elsewhere it is not in the table,
      // so leave the file as CRX. The file-walk `$$self{Model}` is threaded
      // in so a CMT3 here sees a CMT1 `Model` from an EARLIER Canon uuid.
      if table.dispatches_canon_uuid() {
        walk_canon_uuid_with_state(rest, h.body_abs_start + 16, cr3, current_model);
      }
    } else if let Some(child) = table.child_table(h.tag) {
      scan_quicktime_brands(
        h.body,
        h.body_abs_start,
        child,
        depth + 1,
        heif,
        cr3,
        current_model,
        iloc_extents_remaining,
      );
    }
  });
}

// ===========================================================================
// JPEG XL codestream dimension decoder (ProcessJXLCodestream, GetBits)
// ===========================================================================

/// LSB-first little-endian bit reader over a fixed 12-byte JPEG XL header
/// window — the faithful equivalent of `GetBits` (Jpeg2000.pm:1365-1385).
///
/// `GetBits` treats its byte array as an LSB-first bit stream: each output
/// bit is the low bit of byte 0, and after every bit the whole array is
/// shifted right by one (`$$a[$i] >>= 1`, with the next byte's low bit fed
/// into the current byte's high bit, Jpeg2000.pm:1374-1381). Reading `n`
/// bits therefore consumes bits `[cursor .. cursor+n)` of the
/// little-endian view of the array, LSB first — which is EXACTLY
/// `(buf >> cursor) & ((1 << n) - 1)` when `buf` is the array loaded via
/// `u128::from_le_bytes` (byte 0 in the low 8 bits, bit 0 = byte0 & 1).
///
/// The window is the 12 bytes `unpack 'x2C12'` extracts after the
/// `\xff\x0a` codestream marker (Jpeg2000.pm:1488) — 96 bits. The reads
/// the dimension decoder makes total at most `1 + 2 + 30 + 3 + 2 + 30 = 68`
/// bits, so the 96-bit window never underflows; a read past the window
/// would simply yield zero-padding (the buffer is zero-extended to 16
/// bytes), never a panic.
#[derive(Debug, Clone, Copy)]
struct JxlBitReader {
  /// The 12-byte header window loaded as a little-endian `u128` (top 4
  /// bytes always zero — they are the zero-padding `from_le_bytes`
  /// supplies, matching `GetBits` reading off the end of a short array as 0).
  buf: u128,
  /// Number of bits already consumed (the shift amount). `GetBits` reads
  /// strictly forward, so this only grows.
  cursor: u32,
}

impl JxlBitReader {
  /// Build a reader over the 12-byte window. `window` is the
  /// `unpack 'x2C12'` slice (Jpeg2000.pm:1488). Only the first 12 bytes
  /// are used; a shorter slice is zero-extended (so reads past it yield 0,
  /// faithful to `GetBits` shifting in 0 once the array is exhausted).
  #[must_use]
  fn new(window: &[u8]) -> Self {
    let mut bytes = [0u8; 16];
    let n = window.len().min(12);
    // `n <= 12 <= 16` and `n <= window.len()`, so both slices are in-bounds.
    if let (Some(dst), Some(src)) = (bytes.get_mut(..n), window.get(..n)) {
      dst.copy_from_slice(src);
    }
    Self {
      buf: u128::from_le_bytes(bytes),
      cursor: 0,
    }
  }

  /// Read `n` bits (`n <= 30` for every JXL dimension field — and `n <= 96`
  /// always, since the window is 96 bits) LSB-first, advancing the cursor.
  /// Faithful to `GetBits(\@a, $n)` (Jpeg2000.pm:1365-1385): returns the
  /// next `n` bits as an integer, then "shifts" the stream by `n`.
  ///
  /// Defensive against `n` or `cursor` overflow: the mask is computed with
  /// `checked_shl` and a saturating cursor advance, so a degenerate `n`
  /// (>127) yields a full-window read instead of an undefined `1 << n`
  /// shift — never a panic. For the in-range dimension reads this is a
  /// plain `(buf >> cursor) & ((1 << n) - 1)`.
  fn read(&mut self, n: u32) -> u32 {
    if n == 0 {
      return 0;
    }
    // `(1 << n) - 1`, guarding the shift: `n >= 128` (impossible for the
    // dimension reads) would make `1u128 << n` UB, so fall back to the
    // all-ones mask. For `n <= 30` this is the exact `(1<<n)-1`.
    let mask = 1u128
      .checked_shl(n)
      .map_or(u128::MAX, |m| m.wrapping_sub(1));
    let shifted = self.buf.checked_shr(self.cursor).unwrap_or(0);
    let v = (shifted & mask) as u64;
    self.cursor = self.cursor.saturating_add(n);
    // Every dimension field is `<= 30` bits, so the value fits in u32; the
    // `as u32` truncation only loses bits a caller never requests.
    v as u32
  }
}

/// Decode the `ImageWidth` / `ImageHeight` from a JPEG XL codestream —
/// the faithful port of `ProcessJXLCodestream` (Jpeg2000.pm:1469-1510).
///
/// `data` is the codestream bytes: either a raw codestream starting
/// `\xff\x0a`, or a `jxlc`/`jxlp` box body (which may carry a leading
/// 4-byte `jxlp` header word before `\xff\x0a`, Jpeg2000.pm:1473/1487).
/// Returns `Some((width, height))` on success, or `None` when the data is
/// not a codestream (`return 0 unless $$dataPt =~ /^(\0\0\0\0)?\xff\x0a/`,
/// :1473).
///
/// The decoder reads the JXL `SizeHeader` bitstream (libjxl spec): a
/// `small` flag, a height (5-bit small / `[9,13,18,30]`-selected), an
/// aspect `ratio`, and a width (decoded directly when `ratio == 0`, else
/// derived from height × a fixed ratio). Faithful to lines 1488-1506.
#[must_use]
fn process_jxl_codestream(data: &[u8]) -> Option<(u32, u32)> {
  // Jpeg2000.pm:1473 — validate `^(\0\0\0\0)?\xff\x0a`.
  let after_word = match data.get(..4) {
    Some([0, 0, 0, 0]) => data.get(4..),
    _ => Some(data),
  };
  let stream = after_word?;
  if stream.get(..2) != Some(&[0xff, 0x0a]) {
    return None;
  }
  // Jpeg2000.pm:1480-1486 — work with the first 64 bytes; pad to >= 18 if
  // shorter (so `unpack 'x2C12'` always has 12 bytes after the 2-byte
  // marker), else as-is. We strip the optional leading jxlp word FIRST
  // (already done via `after_word`), matching `$dat =~ s/^\0\0\0\0//`
  // (:1487) which removes the word before the unpack.
  //
  // `unpack 'x2C12'` (:1488): skip the 2-byte `\xff\x0a`, take the next 12
  // bytes into the bit window (zero-padded when the codestream is short).
  let window: &[u8] = stream.get(2..).unwrap_or(&[]);
  let mut bits = JxlBitReader::new(window);

  // Jpeg2000.pm:1490-1495 — height.
  let small = bits.read(1);
  let y: u32 = if small != 0 {
    (bits.read(5) + 1) * 8
  } else {
    let sel = bits.read(2) as usize;
    // `[9, 13, 18, 30]->[sel]`; `sel` is 2 bits so always 0..=3, in-bounds.
    let dist = [9u32, 13, 18, 30].get(sel).copied().unwrap_or(9);
    bits.read(dist) + 1
  };

  // Jpeg2000.pm:1496-1506 — aspect ratio + width.
  let ratio = bits.read(3);
  let x: u32 = if ratio == 0 {
    if small != 0 {
      (bits.read(5) + 1) * 8
    } else {
      let sel = bits.read(2) as usize;
      let dist = [9u32, 13, 18, 30].get(sel).copied().unwrap_or(9);
      bits.read(dist) + 1
    }
  } else {
    // `[[1,1],[12,10],[4,3],[3,2],[16,9],[5,4],[2,1]]->[$ratio-1]`
    // (Jpeg2000.pm:1504). `ratio` is 1..=7 here (0 handled above; 3 bits
    // ⇒ max 7), so `ratio - 1` is 0..=6, in-bounds. `int($y * $r[0]/$r[1])`
    // — integer division, computed in u64 to avoid overflow for a 30-bit y.
    const RATIOS: [(u64, u64); 7] = [(1, 1), (12, 10), (4, 3), (3, 2), (16, 9), (5, 4), (2, 1)];
    let idx = (ratio - 1) as usize;
    let (num, den) = RATIOS.get(idx).copied().unwrap_or((1, 1));
    // `den` is never 0 in the table; the division is total.
    ((u64::from(y) * num) / den) as u32
  };

  Some((x, y))
}

// ===========================================================================
// JPEG 2000 (JP2) walker
// ===========================================================================

/// The 12-byte JP2 signature from Jpeg2000.pm:1548-1549:
/// `00 00 00 0c 6A 50 20 20 0D 0A 87 0A` (`jP  \r\n\x87\n`).
const JP2_SIGNATURE: [u8; 12] = [
  0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];

/// Alternative JP2 signature `00 00 00 0c jP\x1a\x1a \r\n\x87\n`
/// (Jpeg2000.pm:1549). Used by some JP2 variants.
const JP2_SIGNATURE_ALT: [u8; 12] = [
  0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x1a, 0x1a, 0x0d, 0x0a, 0x87, 0x0a,
];

/// The raw JPEG 2000 codestream signature `ff 4f ff 51 00`
/// (Jpeg2000.pm:1552 `$hdr =~ /^\xff\x4f\xff\x51\0/`) — the SOC (`ff 4f`)
/// then SIZ (`ff 51`) marker start of a bare J2C / J2K / JPC codestream
/// that is NOT wrapped in a boxed JP2 container. ExifTool folds this
/// alternative into the JP2 magic-number regex too, so a J2C file is routed
/// to the JP2 parser (filetype_data.rs JP2 magic), where `ProcessJP2`
/// recognizes it and `SetFileType('J2C')` (Jpeg2000.pm:1561).
const J2C_SIGNATURE: [u8; 5] = [0xff, 0x4f, 0xff, 0x51, 0x00];

/// The 12-byte boxed-JPEG-XL signature from Jpeg2000.pm:1611:
/// `00 00 00 0c 4A 58 4C 20 0D 0A 87 0A` (`\0\0\0\x0cJXL \x0d\x0a\x87\x0a`).
/// It is the JP2 `jP  ` signature box with the brand bytes replaced by
/// `JXL ` — the ISO-BMFF wrapper of a JPEG XL codestream. `ProcessJXL`
/// sets `$$et{IsJXL}=1` then walks the SAME box structure as JP2
/// (Jpeg2000.pm:1611-1639).
const JXL_SIGNATURE: [u8; 12] = [
  0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
];

/// `true` when `data` starts with one of the boxed JP2 signatures.
#[must_use]
pub fn is_jp2_signature(data: &[u8]) -> bool {
  matches!(data.get(..12), Some(sig) if sig == JP2_SIGNATURE || sig == JP2_SIGNATURE_ALT)
}

/// `true` when `data` starts with the 12-byte boxed-JXL signature
/// (`\0\0\0\x0cJXL \x0d\x0a\x87\x0a`, Jpeg2000.pm:1611) — JPEG XL in an
/// ISO-BMFF container.
#[must_use]
pub fn is_jxl_boxed_signature(data: &[u8]) -> bool {
  data.get(..12) == Some(&JXL_SIGNATURE[..])
}

/// `true` when `data` starts with the raw JXL codestream marker `ff 0a`
/// (Jpeg2000.pm:1614 `$hdr =~ /^\xff\x0a/`) — a bare JPEG XL codestream,
/// NOT wrapped in an ISO-BMFF container.
///
/// Requires at least 12 bytes: `ProcessJXL` reads a 12-byte header
/// (`$raf->Read($hdr,12) == 12`, Jpeg2000.pm:1610) and `return 0`s BEFORE the
/// raw-codestream branch, so a buffer shorter than 12 bytes is rejected and
/// never finalized as JXL (mirrors the J2C 12-byte gate at
/// [`is_j2c_signature`]).
#[must_use]
pub fn is_jxl_codestream_signature(data: &[u8]) -> bool {
  data.len() >= 12 && data.get(..2) == Some(&[0xff, 0x0a])
}

/// `true` when `data` starts with the raw J2C codestream signature
/// `ff 4f ff 51 00` (Jpeg2000.pm:1552) — a bare codestream, NOT a boxed
/// JP2 container.
///
/// `ProcessJP2` first requires a full 12-byte header read
/// (`return 0 unless $raf->Read($hdr,12) == 12`, Jpeg2000.pm:1547) BEFORE
/// testing `$hdr =~ /^\xff\x4f\xff\x51\0/` (line 1552). So a 5..11-byte
/// buffer that merely starts with the SOC/SIZ prefix is REJECTED, never
/// finalized as J2C — the 12-byte gate matches that read and aligns with
/// the boxed JP2 signatures, which are already 12 bytes.
#[must_use]
pub fn is_j2c_signature(data: &[u8]) -> bool {
  data.len() >= 12 && data.get(..5) == Some(&J2C_SIGNATURE[..])
}

/// JPEG 2000 UUID prefixes — the small set bundled handles
/// (Jpeg2000.pm:279-352). EXIF and XMP are surfaced; the other
/// variants (Photoshop / IPTC / GeoJP2) are recorded as a warning
/// since their data is out of camera-indexing scope.
const JP2_UUID_EXIF: [u8; 16] = [
  // `^JpgTiffExif->JP2` (16 chars exactly). Jpeg2000.pm:283.
  0x4a, 0x70, 0x67, 0x54, 0x69, 0x66, 0x66, 0x45, 0x78, 0x69, 0x66, 0x2d, 0x3e, 0x4a, 0x50, 0x32,
];

const JP2_UUID_EXIF2: [u8; 16] = [
  0x05, 0x37, 0xcd, 0xab, 0x9d, 0x0c, 0x44, 0x31, 0xa7, 0x2a, 0xfa, 0x56, 0x1f, 0x2a, 0x11, 0x3e,
];

const JP2_UUID_XMP: [u8; 16] = [
  0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];

/// Walk a JP2 (`data` starts with the 12-byte JP2 signature) and
/// populate `out`. Faithful port of `ProcessJP2`
/// (Jpeg2000.pm:1538-1597) + `ProcessJpeg2000Box` UUID dispatch
/// (Jpeg2000.pm:279-352).
///
/// Sub-type detection (Jpeg2000.pm:1577-1587): if the box following
/// the signature is `ftyp`, take the brand and map JPX/JPM/JXL/JPH;
/// otherwise default to JP2.
///
/// A bare J2C codestream (`ff 4f ff 51 00`, NOT a boxed container) is
/// recognized too: ExifTool's `ProcessJP2` falls into the
/// `/^\xff\x4f\xff\x51\0/` arm (Jpeg2000.pm:1552-1563), `SetFileType('J2C')`
/// and hands off to `ProcessJPEG`. exifast mirrors the `SetFileType('J2C')`
/// (sub_type `J2C` ⇒ `File:FileType=J2C`, MIME `image/x-j2c`); a bare
/// codestream has NO JP2 boxes / no embedded camera metadata, so the JPEG
/// marker scan is out of scope and NO box walk runs.
pub fn walk_jp2(data: &[u8], out: &mut Jp2Meta) {
  if is_j2c_signature(data) && !is_jp2_signature(data) {
    // Raw J2C codestream — `SetFileType('J2C')`, no box walk. ExifTool hands
    // the codestream to `ProcessJPEG`, whose SIZ (0xFF51) marker handler
    // decodes the dimensions (ExifTool.pm:8442 `unpack('x2N2', $segDataPt)`).
    // For a buffer `FF 4F FF 51 [Lsiz:2 @4] [Rsiz:2 @6] [Xsiz:4 @8]
    // [Ysiz:4 @12] …`, ProcessJPEG reads the SIZ marker's `Lsiz` length word
    // (`unpack('n')` at offset 4), then reads EXACTLY `Lsiz`-2 bytes of
    // segment data starting at the byte after the length field (offset 6 =
    // Rsiz); a short read (segment runs past EOF) does `last Marker` — the
    // SIZ handler never runs and NO dims are emitted (ExifTool.pm:7370-7377).
    // The handler's `unpack('x2N2', $segDataPt)` then needs >= 10 segment
    // bytes (`x2` skips Rsiz, `N2` reads Xsiz then Ysiz) ⇒ `Lsiz` >= 12. So
    // emit dimensions ONLY when the declared segment is fully present
    // (`Lsiz` >= 12 AND `data.len()` >= `4 + Lsiz`); ImageWidth =
    // `be_u32(data, 8)` (Xsiz) and ImageHeight = `be_u32(data, 12)` (Ysiz).
    // These reuse the JXL `image_width`/`image_height` fields ⇒ emitted as
    // `File:ImageWidth` / `File:ImageHeight` by `Jp2Meta::tags()`.
    //
    // `SetFileType('J2C')` happens BEFORE ProcessJPEG (Jpeg2000.pm:1556), so
    // the J2C sub_type is set UNCONDITIONALLY even when the dims are gated
    // off. (A bare codestream carries no JP2 boxes / no embedded camera
    // metadata, so no box walk runs.)
    out.set_sub_type(Some(SmolStr::new_static("J2C")));
    let lsiz = be_u16(data, 4).map_or(0usize, |v| v as usize);
    if lsiz >= 12
      && data.len() >= 4 + lsiz
      && let (Some(w), Some(h)) = (be_u32(data, 8), be_u32(data, 12))
    {
      out.set_image_width(Some(w));
      out.set_image_height(Some(h));
    }
    return;
  }
  if !is_jp2_signature(data) {
    return;
  }
  // `is_jp2_signature` proves `data.len() >= 12`, so `.get(12..)` is `Some`.
  let Some(rest) = data.get(12..) else {
    return;
  };
  let abs = 12u64;
  // Sub-type promotion — faithful to ProcessJP2 (Jpeg2000.pm:1578-1587).
  // ExifTool reads ONLY the next 12 bytes after the signature and matches
  // `$buff =~ /^.{4}ftyp(.{4})/s` — i.e. bytes 4..8 must be `ftyp` and
  // bytes 8..12 are the brand. That is precisely the SINGLE box that
  // immediately follows the signature: its tag (`rest[4..8]`) and the
  // first 4 bytes of its body (`rest[8..12]`). If that immediate box is
  // NOT `ftyp` (or the bytes are short), the file type stays `JP2`
  // (`SetFileType(undef)` → the detected JP2). We do NOT walk later
  // siblings looking for a `ftyp`.
  let sub_type: SmolStr = match (rest.get(4..8), rest.get(8..12)) {
    (Some(b"ftyp"), Some(brand)) => match brand {
      b"jpx " => SmolStr::new_static("JPX"),
      b"jpm " => SmolStr::new_static("JPM"),
      b"jxl " => SmolStr::new_static("JXL"),
      b"jph " => SmolStr::new_static("JPH"),
      _ => SmolStr::new_static("JP2"),
    },
    _ => SmolStr::new_static("JP2"),
  };
  out.set_sub_type(Some(sub_type));
  // Walk for UUID-Exif / UUID-XMP / ihdr. This is the TOP-LEVEL JP2 walk,
  // which `ProcessJP2` drives from a file handle (`RAF => $raf`,
  // Jpeg2000.pm:1591) — so a size-0 box here hits the `$raf` arm
  // (Jpeg2000.pm:1135) and `last`s, exactly like QuickTime ⇒
  // `Size0Behavior::Stop`. Only the in-memory `jp2h`-children walk inside
  // `handle_jp2_box` runs a size-0 box to parent end.
  walk_boxes(rest, abs, Size0Behavior::Stop, |h| handle_jp2_box(h, out));
}

/// Decode the `ftyp` box body into `out`'s MajorBrand / MinorVersion /
/// CompatibleBrands fields — a faithful port of the
/// `%Image::ExifTool::Jpeg2000::FileType` ProcessBinaryData table
/// (Jpeg2000.pm:556-582).
///
/// The body layout (`undef[4]` MajorBrand, `undef[4]` MinorVersion,
/// `undef[$size-8]` CompatibleBrands) is:
///  - MajorBrand  = `body[0..4]` (raw 4-char; PrintConv at emit).
///  - MinorVersion = `sprintf("%x.%x.%x", unpack("nCC", body[4..8]))`
///    (Jpeg2000.pm:571) — `be_u16(body,4)`, `body[6]`, `body[7]`.
///  - CompatibleBrands = `body[8..]` split into 4-byte chunks, dropping
///    any chunk containing a NUL byte (Jpeg2000.pm:580).
///
/// Each field is guarded independently: a body too short for the
/// MinorVersion / CompatibleBrands slice simply leaves that field unset
/// (ProcessBinaryData skips a short read, it does not abort).
fn decode_ftyp(body: &[u8], out: &mut Jp2Meta) {
  if let Some(brand) = body.get(0..4)
    && let Ok(s) = core::str::from_utf8(brand)
  {
    out.set_major_brand(Some(SmolStr::new(s)));
  } else if let Some(brand) = body.get(0..4) {
    // Non-UTF-8 brand bytes: fall back to a lossy ASCII rendering so the
    // raw 4 bytes still surface (the PrintConv hash miss path then emits
    // them verbatim, matching ExifTool's `undef[4]` byte passthrough).
    let mut s = String::with_capacity(4);
    for &b in brand {
      s.push(b as char);
    }
    out.set_major_brand(Some(SmolStr::from(s)));
  }
  if let (Some(hi), Some(&mid), Some(&lo)) = (be_u16(body, 4), body.get(6), body.get(7)) {
    out.set_minor_version(Some(SmolStr::from(alloc::format!("{hi:x}.{mid:x}.{lo:x}"))));
  }
  if let Some(rest) = body.get(8..) {
    let brands: Vec<SmolStr> = rest
      .chunks_exact(4)
      .filter(|c| !c.contains(&0))
      .map(|c| {
        // Each chunk is 4 bytes with no NUL; render as ASCII (a non-UTF-8
        // brand chunk renders byte-for-byte via the `as char` cast).
        let mut s = String::with_capacity(4);
        for &b in c {
          s.push(b as char);
        }
        SmolStr::from(s)
      })
      .collect();
    if !brands.is_empty() {
      out.set_compatible_brands(brands);
    }
  }
}

/// Decode the `ihdr` Image Header box body into `out` — a faithful port of
/// the `%Image::ExifTool::Jpeg2000::ImageHeader` ProcessBinaryData table
/// (Jpeg2000.pm:513-550). The 12-byte body holds: ImageHeight `int32u`@0,
/// ImageWidth `int32u`@4, NumberOfComponents `int16u`@8, BitsPerComponent
/// byte@10, Compression byte@11. Each field is guarded independently (a
/// short body sets only the fields that fit — ProcessBinaryData skips a
/// short read rather than aborting). The BitsPerComponent / Compression
/// PrintConvs are applied at emission; the RAW bytes are stored here.
fn decode_ihdr(body: &[u8], out: &mut Jp2Meta) {
  if let Some(h) = be_u32(body, 0) {
    out.set_ihdr_height(Some(h));
  }
  if let Some(w) = be_u32(body, 4) {
    out.set_ihdr_width(Some(w));
  }
  if let Some(n) = be_u16(body, 8) {
    out.set_ihdr_components(Some(n));
  }
  if let Some(&b) = body.get(10) {
    out.set_ihdr_bits_per_component(Some(b));
  }
  if let Some(&c) = body.get(11) {
    out.set_ihdr_compression(Some(c));
  }
}

/// Decode the `colr` Color Specification box body into `out` — a faithful
/// port of the `%Image::ExifTool::Jpeg2000::ColorSpec` ProcessBinaryData
/// table (Jpeg2000.pm:631-728, `FORMAT => 'int8s'`). The table-level
/// `int8s` makes offsets 0/1/2 ALL signed. Layout:
///  - ColorSpecMethod        `int8s`@0 (signed; PrintConv at emit; drives
///    offset-3 — the `== 1` Condition is over the signed value).
///  - ColorSpecPrecedence    `int8s`@1 (signed; emitted as a bare int).
///  - ColorSpecApproximation `int8s`@2 (signed; PrintConv at emit).
///  - offset 3 is CONDITIONAL on ColorSpecMethod:
///      * method 1 ⇒ ColorSpace `int32u`@3 (enum PrintConv at emit).
///      * method 2/3 ⇒ ICC_Profile (DEFERRED — `TODO(ICC)`).
///      * method 4 ⇒ ColorSpecData binary (DEFERRED).
///
/// Each field is guarded; a short body simply leaves the missing field
/// unset.
fn decode_colr(body: &[u8], out: &mut Jp2Meta) {
  let Some(&method) = body.get(0) else {
    return;
  };
  let method = method as i8;
  out.set_color_spec_method(Some(method));
  if let Some(&prec) = body.get(1) {
    out.set_color_spec_precedence(Some(prec as i8));
  }
  if let Some(&approx) = body.get(2) {
    out.set_color_spec_approximation(Some(approx as i8));
  }
  // Offset 3 is a single ordered Condition list (Jpeg2000.pm:687-728): only
  // the `ColorSpecMethod == 1` arm yields an emittable ColorSpace `int32u`.
  // The Condition is over the SIGNED method (0x01 → 1 either way; a crafted
  // byte >= 0x80 → negative → not 1 → no ColorSpace). Methods 2/3
  // (ICC_Profile) and 4 (ColorSpecData) are DEFERRED.
  if method == 1 {
    if let Some(cs) = be_u32(body, 3) {
      out.set_color_space(Some(cs));
    }
  }
  // TODO(ICC): ColorSpecMethod 2 (Restricted ICC) / 3 (Any ICC) carry an
  // ICC profile at body[3..] (Jpeg2000.pm:688-696) — decode deferred to the
  // ICC_Profile subsystem.
  // TODO(#159-followup: colr method-4 ColorSpecData): vendor-color binary
  // payload at body[3..] (Jpeg2000.pm:729-733) — out of camera-indexing
  // scope.
}

/// Handle one top-level JP2 / JXL box — the shared box dispatch driven by
/// both [`walk_jp2`] and [`walk_jxl`]. Faithful to the `Jpeg2000::Main`
/// table's `uuid` (Jpeg2000.pm:279-352) + `jp2h`/`ihdr` (Jpeg2000.pm:
/// 152-173) entries: it LOCATES the UUID-Exif / UUID-XMP TIFF blocks and
/// the `ihdr` Image Header, recording their absolute offset + length.
///
/// JXL adds the `jxlc` / `jxlp` codestream boxes (Jpeg2000.pm:451/460,
/// `isImageData` :38) — those are handled separately by [`walk_jxl`]
/// (this shared helper covers ONLY the boxes common to both), so a plain
/// JP2 never touches the codestream path and stays byte-identical.
fn handle_jp2_box(h: &BoxHeader<'_>, out: &mut Jp2Meta) {
  match h.tag {
    b"uuid" if h.body.len() >= 16 => {
      // The arm guard proves `h.body.len() >= 16`, so `.get(..16)` is `Some`.
      let Some(prefix) = h.body.get(..16) else {
        return;
      };
      if prefix == JP2_UUID_EXIF || prefix == JP2_UUID_EXIF2 {
        // Body[16..] is normally the TIFF/Exif block (Jpeg2000.pm:283
        // `Start => '$valuePtr + 16'`). BUT the Digikam-written
        // `UUID-EXIF_bad` variant (Jpeg2000.pm:304-315) puts a spurious
        // `Exif\0\0` marker AFTER the 16-byte `JpgTiffExif->JP2` prefix
        // and the real TIFF starts at `+22`. ExifTool models this as two
        // ordered Conditions: the GOOD arm has a negative lookahead
        // `/^JpgTiffExif->JP2(?!Exif\0\0)/` → +16; when that lookahead
        // fails (the next bytes ARE `Exif\0\0`) the `UUID-EXIF_bad` arm
        // `/^JpgTiffExif->JP2/` → +22 fires. The Photoshop `UUID-EXIF2`
        // prefix always uses +16.
        const EXIF_MARKER: &[u8; 6] = b"Exif\0\0";
        let tiff_start: usize =
          if prefix == JP2_UUID_EXIF && h.body.get(16..22) == Some(&EXIF_MARKER[..]) {
            22
          } else {
            16
          };
        let mut b = Jp2Block::new();
        b.set_offset(h.body_abs_start + tiff_start as u64);
        b.set_length((h.body.len() - tiff_start) as u64);
        if out.uuid_exif().is_none() {
          out.set_uuid_exif(Some(b));
        }
      } else if prefix == JP2_UUID_XMP {
        let mut b = Jp2Block::new();
        b.set_offset(h.body_abs_start + 16);
        b.set_length((h.body.len() - 16) as u64);
        if out.uuid_xmp().is_none() {
          out.set_uuid_xmp(Some(b));
        }
      }
      // Other UUIDs (Photoshop / IPTC / GeoJP2) recorded only as a
      // warning — DEFERRED to PR #36.
    }
    // ftyp → FileType box (Jpeg2000.pm:556). Decode MajorBrand /
    // MinorVersion / CompatibleBrands from the full box body. (The sub_type
    // promotion in `walk_jp2` / `walk_jxl` separately peeks bytes 8..12 for
    // the `File:FileType` finalize — faithful to ExifTool's `/^.{4}ftyp/`
    // signature peek vs the `FileType` table that decodes the whole box.)
    // FIRST box wins, mirroring the once-extracted FileType table.
    b"ftyp" if out.major_brand().is_none() => {
      decode_ftyp(h.body, out);
    }
    // jp2h → ihdr + colr nested. Walk inner (Jpeg2000.pm:152-173).
    //
    // This is the IN-MEMORY `jp2h` SubDirectory recursion: ExifTool descends
    // it via `ProcessDirectory`/`ProcessJpeg2000Box` with a `$dataPt` and NO
    // `$raf`, so a size-0 child box runs to the END OF THE PARENT (`$boxLen =
    // $dirEnd - $pos`, Jpeg2000.pm:1137) and IS decoded ⇒
    // `Size0Behavior::ToParentEnd`. So a `jp2h{ size-0 ihdr }` still emits
    // ImageHeight/Width/Components/BitsPerComponent/Compression (R18-F3 — the
    // R16-F1 blanket size-0 stop wrongly dropped this).
    b"jp2h" => {
      walk_boxes(
        h.body,
        h.body_abs_start,
        Size0Behavior::ToParentEnd,
        |inner| match inner.tag {
          b"ihdr" if out.ihdr().is_none() => {
            let mut b = Jp2Block::new();
            b.set_offset(inner.body_abs_start);
            b.set_length(inner.body.len() as u64);
            out.set_ihdr(Some(b));
            // Decode the 5 ihdr scalars (height/width/components/bits/
            // compression) — Jpeg2000.pm:513-550.
            decode_ihdr(inner.body, out);
          }
          // colr → ColorSpec box (Jpeg2000.pm:631). FIRST colr wins (a JP2 may
          // carry several colr methods; ExifTool's ProcessBinaryData extracts
          // each, but the camera-indexing surface keeps the first decoded).
          b"colr" if out.color_spec_method().is_none() => {
            decode_colr(inner.body, out);
          }
          // TODO(#159-followup: JP2 resc/resd resolution boxes): the `res `
          // box's `resc` (CaptureResolution) / `resd` (DisplayResolution)
          // children (Jpeg2000.pm:583-630) carry the image resolution. No
          // bundled fixture exercises them — Jpeg2000.jp2's resolution comes
          // from its embedded Exif (#36) — so the decode is deferred.
          _ => {}
        },
      );
    }
    _ => {}
  }
}

// ===========================================================================
// JPEG XL walker — `ProcessJXL` (Jpeg2000.pm:1603-1653)
// ===========================================================================

/// Walk a JPEG XL container and populate `out`. Faithful port of
/// `ProcessJXL` (Jpeg2000.pm:1603-1653) for the read path (exifast has no
/// write path, so the BMFF-wrapping write branch :1616-1626 is dropped).
///
/// Two forms (Jpeg2000.pm:1610-1636):
///  - **Boxed JXL** (`\0\0\0\x0cJXL \x0d\x0a\x87\x0a`, :1611) — sets the
///    `is_jxl` flag and walks the SAME ISO-BMFF box structure as JP2
///    (`ProcessJP2`, :1639): the sub-type promotes from the inner `ftyp`
///    brand `jxl ` → "JXL" (:1583), and any `jxlc` / `jxlp` box body feeds
///    [`process_jxl_codestream`] for `ImageWidth`/`ImageHeight`
///    (Jpeg2000.pm:451/460, `isImageData` :38).
///  - **Raw codestream** (`^\xff\x0a`, :1614) — sets `is_jxl` +
///    `jxl_raw_codestream` (`SetFileType('JXL Codestream','image/jxl',
///    'jxl')`, :1628) and decodes the dimensions directly (:1632). No box
///    walk (a bare codestream has no boxes).
///
/// The `jxlc` / `jxlp` dimension decode is once-guarded by
/// `processed_codestream` (mirroring `$$et{ProcessedJXLCodestream}`,
/// :1475) so a boxed JXL with several partial `jxlp` boxes decodes from
/// the first only.
pub fn walk_jxl(data: &[u8], out: &mut Jp2Meta) {
  if is_jxl_codestream_signature(data) {
    // Raw codestream form (Jpeg2000.pm:1614-1632).
    out.set_is_jxl(true).set_jxl_raw_codestream(true);
    decode_jxl_codestream_once(data, out);
    return;
  }
  if !is_jxl_boxed_signature(data) {
    return;
  }
  // Boxed JXL (Jpeg2000.pm:1611-1639). `is_jxl_boxed_signature` proves
  // `data.len() >= 12`, so `.get(12..)` is `Some`.
  out.set_is_jxl(true);
  let Some(rest) = data.get(12..) else {
    return;
  };
  let abs = 12u64;
  // Sub-type promotion — `ProcessJP2` reads the box immediately after the
  // signature and matches `/^.{4}ftyp(.{4})/s` (Jpeg2000.pm:1580). For a
  // boxed JXL that box is `ftyp` with brand `jxl ` → "JXL" (:1583), so the
  // `File:FileType` finalizes to JXL. (A malformed boxed JXL whose first
  // box is NOT `ftyp jxl ` keeps `is_jxl` but takes the detected `JXL`
  // candidate — faithful to `SetFileType(undef)` falling back to the
  // detector's JXL type.)
  let sub_type: SmolStr = match (rest.get(4..8), rest.get(8..12)) {
    (Some(b"ftyp"), Some(b"jxl ")) => SmolStr::new_static("JXL"),
    _ => SmolStr::new_static("JXL"),
  };
  out.set_sub_type(Some(sub_type));
  // Walk the boxes: shared UUID-Exif / UUID-XMP / ihdr handling PLUS the
  // JXL-only codestream + deferred-payload boxes. Like `walk_jp2`, this is
  // the TOP-LEVEL `$raf`-driven walk (Jpeg2000.pm:1639 reuses `ProcessJP2`'s
  // box walk), so a size-0 box `last`s ⇒ `Size0Behavior::Stop`. A size-0 box
  // inside a nested `jp2h` is handled (ToParentEnd) by `handle_jp2_box`.
  walk_boxes(rest, abs, Size0Behavior::Stop, |h| {
    match h.tag {
      // jxlc — full JXL codestream (Jpeg2000.pm:451). Decode dimensions
      // (once-guarded).
      b"jxlc" => decode_jxl_codestream_once(h.body, out),
      // jxlp — partial JXL codestream (Jpeg2000.pm:460). May carry a
      // leading 4-byte index word before `\xff\x0a`; `process_jxl_codestream`
      // strips it. Decode the FIRST only (the once-guard, :1475).
      b"jxlp" => decode_jxl_codestream_once(h.body, out),
      // Exif box — TIFF/Exif block. DEFERRED (#36, same as the HEIF/CR3
      // embedded-Exif path in this PR): located but not decoded.
      b"Exif" => {
        // TODO(#36): decode the boxed-JXL Exif TIFF block (Jpeg2000.pm:469,
        // `Start => $valuePtr + 4 + unpack 'N'`). Located here, decode
        // deferred to the embedded-Exif wave.
        let mut b = Jp2Block::new();
        b.set_offset(h.body_abs_start)
          .set_length(h.body.len() as u64);
        if out.uuid_exif().is_none() {
          out.set_uuid_exif(Some(b));
        }
      }
      // xml  box — XMP packet. DEFERRED (#37): located but not decoded.
      b"xml " => {
        // TODO(#37): decode the boxed-JXL `xml ` XMP packet.
        let mut b = Jp2Block::new();
        b.set_offset(h.body_abs_start)
          .set_length(h.body.len() as u64);
        if out.uuid_xmp().is_none() {
          out.set_uuid_xmp(Some(b));
        }
      }
      // brob box — Brotli-compressed Exif/XMP/JUMBF (Jpeg2000.pm:485-510).
      // Needs a Brotli decompressor exifast does not depend on.
      b"brob" => {
        // TODO(#159-followup: JXL brob/Brotli): the payload is a
        // Brotli-compressed `xml `/`exif`/`jumb` block (ProcessBrotli,
        // Jpeg2000.pm:1392-1463). Located only; decoding needs a Brotli
        // dependency that is out of scope here.
        out.set_warning(Some(String::from(
          "JXL brob (Brotli-compressed metadata) present — decode deferred",
        )));
      }
      // JUMBF / C2PA boxes (Jpeg2000.pm:1516-1532 ProcessJUMBF). A separate
      // subsystem; located only.
      b"jumb" => {
        // TODO(#159-followup: JUMBF/C2PA): the JUMBF box carries C2PA /
        // JUMBF metadata (ProcessJUMBF, Jpeg2000.pm:1516). Located only;
        // the JUMBF walk is a separate subsystem out of scope here.
        out.set_warning(Some(String::from(
          "JXL JUMBF/C2PA box present — walk deferred",
        )));
      }
      // Every other box (incl. `jp2h`/`ihdr`, `uuid`-Exif/XMP) is handled
      // by the shared JP2 box dispatch.
      _ => handle_jp2_box(h, out),
    }
  });
}

/// Decode a `jxlc` / `jxlp` / raw codestream body into `ImageWidth` /
/// `ImageHeight`, honouring the once-guard. Mirrors `ProcessJXLCodestream`'s
/// `return 0 if $$et{ProcessedJXLCodestream}` early-out (Jpeg2000.pm:1475):
/// only the FIRST codestream sets the dimensions; subsequent `jxlp` boxes
/// are no-ops.
fn decode_jxl_codestream_once(body: &[u8], out: &mut Jp2Meta) {
  if out.processed_codestream() {
    return;
  }
  // `process_jxl_codestream` returns `None` when the body is not a
  // codestream (`^(\0\0\0\0)?\xff\x0a` fails) — in which case we do NOT
  // set the guard (faithful to `ProcessJXLCodestream` returning 0 BEFORE
  // setting `$$et{ProcessedJXLCodestream}`, Jpeg2000.pm:1473-1476), so a
  // later well-formed codestream box can still be decoded.
  if let Some((w, h)) = process_jxl_codestream(body) {
    out.set_processed_codestream(true);
    out.set_image_width(Some(w));
    out.set_image_height(Some(h));
  }
}

// ===========================================================================
// JP2 standalone entry point — `ProcessJP2` (Jpeg2000.pm:1538-1597)
// ===========================================================================

/// The JPEG 2000 (`JP2`/`JPX`/`JPM`/`JPH`/`JXL`) standalone container
/// parser — the exifast counterpart of `Image::ExifTool::Jpeg2000::
/// ProcessJP2` (Jpeg2000.pm:1538-1597).
///
/// A real `.jp2` does NOT start with a QuickTime `ftyp` atom; it starts
/// with the 12-byte JP2 signature box `00 00 00 0c 6A 50 20 20 0D 0A 87
/// 0A` (or the `jP\x1a\x1a` alternate). ExifTool routes JP2 through a
/// SEPARATE process proc keyed off the `JP2` file type
/// (`%moduleName{JP2} = 'Jpeg2000'`); exifast mirrors this with a
/// dedicated [`crate::format_parser::AnyParser::Jp2`] arm so the
/// signature-detected `JP2` candidate dispatches here instead of failing
/// the QuickTime `ftyp`/`moov` top-level gate.
///
/// `parse` returns `Some(Jp2Meta)` for any input that begins with one of
/// the two boxed JP2 signatures OR with the raw `\xff\x4f\xff\x51\0` J2C
/// codestream signature (Jpeg2000.pm:1552 — `ProcessJP2` accepts it and
/// `SetFileType('J2C')` at :1561). The FileType + MIME are then finalized
/// by the engine from [`Jp2Meta::sub_type`] via
/// [`crate::format_parser::FileTypeFinalize`] (sub_type `J2C` ⇒
/// `File:FileType=J2C`, MIME `image/x-j2c`). It returns `None` for a
/// non-JP2 input (no recognized signature). The J2C path takes NO box
/// walk and does NOT run the `ProcessJPEG` marker scan (a bare codestream
/// has no JP2 boxes / no embedded camera metadata), mirroring just the
/// `SetFileType('J2C')`.
#[derive(Debug, Clone, Copy)]
pub struct ProcessJp2;

impl crate::format_parser::parser_sealed::Sealed for ProcessJp2 {}

impl crate::format_parser::FormatParser for ProcessJp2 {
  type Meta<'a> = Jp2Meta;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_jp2_borrowed(data)
  }
}

/// Lib-first direct entry — parse a whole JP2 file buffer into a typed
/// [`Jp2Meta`]. Returns `None` ONLY for a non-JP2 (no boxed-JP2 and no
/// raw-J2C signature), faithful to `ProcessJP2`'s `return 0 unless …`
/// signature gate (Jpeg2000.pm:1547-1552). A raw `\xff\x4f\xff\x51\0`
/// J2C codestream is accepted (sub_type `J2C`).
#[must_use]
pub fn parse_jp2_borrowed(data: &[u8]) -> Option<Jp2Meta> {
  if !is_jp2_signature(data) && !is_j2c_signature(data) {
    return None;
  }
  let mut meta = Jp2Meta::new();
  walk_jp2(data, &mut meta);
  // `walk_jp2` always sets a sub_type when a signature matched (boxed JP2
  // defaults to `JP2`; a raw codestream sets `J2C`), so `is_empty()` is
  // false here — the parse is a success even when no UUID-Exif / ihdr
  // boxes were present.
  Some(meta)
}

// ===========================================================================
// JXL standalone entry point — `ProcessJXL` (Jpeg2000.pm:1603-1653)
// ===========================================================================

/// The JPEG XL (`JXL` / `JXL Codestream`) standalone container parser —
/// the exifast counterpart of `Image::ExifTool::Jpeg2000::ProcessJXL`
/// (Jpeg2000.pm:1603-1653).
///
/// A JXL file is detected by the filetype magic (`\xff\x0a` raw codestream
/// OR `\0\0\0\x0cJXL ` boxed, filetype_data.rs:1164) → file type "JXL"
/// (base module `Jpeg2000`). ExifTool routes it through `ProcessJXL`,
/// which detects the form then REUSES `ProcessJP2`'s box walk for the
/// boxed case (:1639); exifast mirrors that via [`walk_jxl`] (which shares
/// [`handle_jp2_box`] with the JP2 walker, then adds the `jxlc`/`jxlp`
/// codestream decode).
///
/// `parse` returns `Some(Jp2Meta)` for either JXL form and `None`
/// otherwise. The FileType + MIME are finalized by the engine:
///  - boxed JXL → `File:FileType = JXL`, MIME `image/jxl` (the inner
///    `ftyp jxl ` brand, :1583);
///  - raw codestream → `File:FileType = JXL Codestream`, MIME `image/jxl`
///    (`SetFileType('JXL Codestream','image/jxl','jxl')`, :1628).
///
/// Both routes are wired in [`crate::format_parser::AnyMeta::finalize_file_type`].
#[derive(Debug, Clone, Copy)]
pub struct ProcessJxl;

impl crate::format_parser::parser_sealed::Sealed for ProcessJxl {}

impl crate::format_parser::FormatParser for ProcessJxl {
  type Meta<'a> = Jp2Meta;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_jxl_borrowed(data)
  }
}

/// Lib-first direct entry — parse a whole JPEG XL file buffer into a typed
/// [`Jp2Meta`]. Returns `None` ONLY for a non-JXL input (neither the boxed
/// `\0\0\0\x0cJXL ` signature nor the raw `\xff\x0a` codestream marker),
/// faithful to `ProcessJXL`'s `return 0` gate (Jpeg2000.pm:1610-1635).
#[must_use]
pub fn parse_jxl_borrowed(data: &[u8]) -> Option<Jp2Meta> {
  if !is_jxl_boxed_signature(data) && !is_jxl_codestream_signature(data) {
    return None;
  }
  let mut meta = Jp2Meta::new();
  walk_jxl(data, &mut meta);
  // `walk_jxl` always sets `is_jxl` when a signature matched, so
  // `is_empty()` is false here — the parse is a success even when a boxed
  // JXL carried no codestream box (dimensions stay `None`).
  Some(meta)
}

/// `%Jpeg2000::FileType` MajorBrand PrintConv (Jpeg2000.pm:559-565). A hash
/// miss returns the RAW 4-char brand string verbatim (ExifTool's
/// `undef[4]` value passthrough — there is NO `Unknown ($val)` wrap for a
/// PrintConv HASH miss on an `undef`-format value; the raw string is shown).
fn jp2_major_brand_print(brand: &str) -> SmolStr {
  match brand {
    "jp2 " => SmolStr::new_static("JPEG 2000 Image (.JP2)"),
    "jpm " => SmolStr::new_static("JPEG 2000 Compound Image (.JPM)"),
    "jpx " => SmolStr::new_static("JPEG 2000 with extensions (.JPX)"),
    "jxl " => SmolStr::new_static("JPEG XL Image (.JXL)"),
    "jph " => SmolStr::new_static("High-throughput JPEG 2000 (.JPH)"),
    other => SmolStr::new(other),
  }
}

/// `%Jpeg2000::ImageHeader` BitsPerComponent PrintConv (Jpeg2000.pm:528-537):
/// `0xff → "Variable"`, else `"(N&0x7f)+1 Bits, Signed|Unsigned"` where the
/// 0x80 bit selects Signed.
fn jp2_bits_per_component_print(v: u8) -> SmolStr {
  if v == 0xff {
    return SmolStr::new_static("Variable");
  }
  let sign = if v & 0x80 != 0 { "Signed" } else { "Unsigned" };
  SmolStr::from(alloc::format!("{} Bits, {sign}", (v & 0x7f) + 1))
}

/// `%Jpeg2000::ImageHeader` Compression PrintConv (Jpeg2000.pm:538-550). A
/// hash miss yields `Unknown (N)` (the ExifTool default for a numeric
/// PrintConv HASH miss, ExifTool.pm:3622).
fn jp2_compression_print(v: u8) -> SmolStr {
  match v {
    0 => SmolStr::new_static("Uncompressed"),
    1 => SmolStr::new_static("Modified Huffman"),
    2 => SmolStr::new_static("Modified READ"),
    3 => SmolStr::new_static("Modified Modified READ"),
    4 => SmolStr::new_static("JBIG"),
    5 => SmolStr::new_static("JPEG"),
    6 => SmolStr::new_static("JPEG-LS"),
    7 => SmolStr::new_static("JPEG 2000"),
    8 => SmolStr::new_static("JBIG2"),
    other => SmolStr::from(alloc::format!("Unknown ({other})")),
  }
}

/// `%Jpeg2000::ColorSpec` ColorSpecMethod PrintConv (Jpeg2000.pm:653-668).
/// The value is `int8s` (table `FORMAT => 'int8s'`, Jpeg2000.pm:636), so a
/// hash miss yields `Unknown (N)` over the SIGNED value (e.g. `0xff` →
/// `Unknown (-1)`).
fn jp2_color_spec_method_print(v: i8) -> SmolStr {
  match v {
    1 => SmolStr::new_static("Enumerated"),
    2 => SmolStr::new_static("Restricted ICC"),
    3 => SmolStr::new_static("Any ICC"),
    4 => SmolStr::new_static("Vendor Color"),
    other => SmolStr::from(alloc::format!("Unknown ({other})")),
  }
}

/// `%Jpeg2000::ColorSpec` ColorSpecApproximation PrintConv
/// (Jpeg2000.pm:673-684). The value is `int8s` (Jpeg2000.pm:636), so a
/// hash miss yields `Unknown (N)` over the SIGNED value.
fn jp2_color_spec_approximation_print(v: i8) -> SmolStr {
  match v {
    0 => SmolStr::new_static("Not Specified"),
    1 => SmolStr::new_static("Accurate"),
    2 => SmolStr::new_static("Exceptional Quality"),
    3 => SmolStr::new_static("Reasonable Quality"),
    4 => SmolStr::new_static("Poor Quality"),
    other => SmolStr::from(alloc::format!("Unknown ({other})")),
  }
}

/// `%Jpeg2000::ColorSpec` ColorSpace PrintConv (Jpeg2000.pm:698-728, the
/// enumerated `int32u` color space, ref 15444-2). A hash miss yields
/// `Unknown (N)`.
fn jp2_color_space_print(v: u32) -> SmolStr {
  match v {
    0 => SmolStr::new_static("Bi-level"),
    1 => SmolStr::new_static("YCbCr(1)"),
    3 => SmolStr::new_static("YCbCr(2)"),
    4 => SmolStr::new_static("YCbCr(3)"),
    9 => SmolStr::new_static("PhotoYCC"),
    11 => SmolStr::new_static("CMY"),
    12 => SmolStr::new_static("CMYK"),
    13 => SmolStr::new_static("YCCK"),
    14 => SmolStr::new_static("CIELab"),
    15 => SmolStr::new_static("Bi-level(2)"),
    16 => SmolStr::new_static("sRGB"),
    17 => SmolStr::new_static("Grayscale"),
    18 => SmolStr::new_static("sYCC"),
    19 => SmolStr::new_static("CIEJab"),
    20 => SmolStr::new_static("e-sRGB"),
    21 => SmolStr::new_static("ROMM-RGB"),
    22 => SmolStr::new_static("YPbPr(1125/60)"),
    23 => SmolStr::new_static("YPbPr(1250/50)"),
    24 => SmolStr::new_static("e-sYCC"),
    other => SmolStr::from(alloc::format!("Unknown ({other})")),
  }
}

impl crate::emit::Taggable for Jp2Meta {
  /// Emit the JPEG 2000 / JPEG XL container tags.
  ///
  /// **`File`/`File` group** — the JXL codestream / J2C SIZ dimensions
  /// (`ImageWidth` / `ImageHeight`). A JXL whose codestream was decoded
  /// (`ProcessJXLCodestream`, Jpeg2000.pm:1507-1508) and a bare J2C
  /// codestream (ProcessJPEG SIZ, ExifTool.pm:8442) both emit these in the
  /// `%Image::ExifTool::Extra` default group (ExifTool.pm:1286 `GROUPS =>
  /// { 0 => 'File', 1 => 'File' }`) — matching `exiftool -G1` `[File]
  /// ImageWidth/ImageHeight`. The values are `int` (`TagValue::U64`).
  ///
  /// **`Jpeg2000`/`Jpeg2000` group** — the boxed-container tags ExifTool
  /// extracts through the `Jpeg2000::FileType` (`ftyp`),
  /// `Jpeg2000::ImageHeader` (`ihdr`), and `Jpeg2000::ColorSpec` (`colr`)
  /// ProcessBinaryData tables (all `GROUPS => family-0 'Jpeg2000'`, the
  /// module default). Emitted in box-processing order: ftyp (MajorBrand,
  /// MinorVersion, CompatibleBrands) → ihdr (ImageHeight, ImageWidth,
  /// NumberOfComponents, BitsPerComponent, Compression) → colr
  /// (ColorSpecMethod, ColorSpecPrecedence, ColorSpecApproximation,
  /// ColorSpace). The camera identity inside the UUID-Exif TIFF body stays
  /// deferred to PR #36; `File:FileType`/`File:MIMEType` come from the
  /// engine via [`Jp2Meta::sub_type`] + [`crate::format_parser::FileTypeFinalize`].
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars (the PrintConv tags emit the raw
  /// `int`; MajorBrand emits the raw 4-char brand; MinorVersion /
  /// CompatibleBrands / the ihdr int tags / ColorSpecPrecedence are
  /// PrintConv-less ⇒ mode-invariant).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};
    let print_conv = matches!(opts.mode, crate::emit::ConvMode::PrintConv);
    let j2k = || Group::new("Jpeg2000", "Jpeg2000");
    let mut tags: alloc::vec::Vec<EmittedTag> = alloc::vec::Vec::new();
    // ── File:ImageWidth / File:ImageHeight (JXL codestream / J2C SIZ) ────
    // ProcessJXLCodestream emits ImageWidth BEFORE ImageHeight
    // (Jpeg2000.pm:1507-1508).
    if let Some(w) = self.image_width() {
      tags.push(EmittedTag::new(
        Group::new("File", "File"),
        "ImageWidth".into(),
        TagValue::U64(u64::from(w)),
        false,
      ));
    }
    if let Some(h) = self.image_height() {
      tags.push(EmittedTag::new(
        Group::new("File", "File"),
        "ImageHeight".into(),
        TagValue::U64(u64::from(h)),
        false,
      ));
    }

    // ── ftyp (Jpeg2000::FileType, Jpeg2000.pm:556-582) ──────────────────
    if let Some(brand) = self.major_brand() {
      let value = if print_conv {
        TagValue::Str(jp2_major_brand_print(brand))
      } else {
        // `-n`: the raw 4-char brand string (the `undef[4]` value).
        TagValue::Str(brand.into())
      };
      tags.push(EmittedTag::new(j2k(), "MajorBrand".into(), value, false));
    }
    if let Some(mv) = self.minor_version() {
      // MinorVersion: ValueConv only, no PrintConv ⇒ mode-invariant.
      tags.push(EmittedTag::new(
        j2k(),
        "MinorVersion".into(),
        TagValue::Str(mv.into()),
        false,
      ));
    }
    if !self.compatible_brands().is_empty() {
      // CompatibleBrands List (Jpeg2000.pm:574-581). One EmittedTag carrying
      // a `TagValue::List` of per-brand `TagValue::Str` (the NUL-containing
      // chunks were already dropped at decode).
      let items: alloc::vec::Vec<TagValue> = self
        .compatible_brands()
        .iter()
        .map(|b| TagValue::Str(b.clone()))
        .collect();
      tags.push(EmittedTag::new(
        j2k(),
        "CompatibleBrands".into(),
        TagValue::List(items),
        false,
      ));
    }

    // ── ihdr (Jpeg2000::ImageHeader, Jpeg2000.pm:513-550) ───────────────
    // Ascending-offset order: ImageHeight@0, ImageWidth@4, Components@8,
    // BitsPerComponent@10, Compression@11.
    if let Some(h) = self.ihdr_height() {
      tags.push(EmittedTag::new(
        j2k(),
        "ImageHeight".into(),
        TagValue::U64(u64::from(h)),
        false,
      ));
    }
    if let Some(w) = self.ihdr_width() {
      tags.push(EmittedTag::new(
        j2k(),
        "ImageWidth".into(),
        TagValue::U64(u64::from(w)),
        false,
      ));
    }
    if let Some(n) = self.ihdr_components() {
      tags.push(EmittedTag::new(
        j2k(),
        "NumberOfComponents".into(),
        TagValue::U64(u64::from(n)),
        false,
      ));
    }
    if let Some(b) = self.ihdr_bits_per_component() {
      // BitsPerComponent: PrintConv only (the RAW byte is the `-n` value).
      let value = if print_conv {
        TagValue::Str(jp2_bits_per_component_print(b))
      } else {
        TagValue::U64(u64::from(b))
      };
      tags.push(EmittedTag::new(
        j2k(),
        "BitsPerComponent".into(),
        value,
        false,
      ));
    }
    if let Some(c) = self.ihdr_compression() {
      let value = if print_conv {
        TagValue::Str(jp2_compression_print(c))
      } else {
        TagValue::U64(u64::from(c))
      };
      tags.push(EmittedTag::new(j2k(), "Compression".into(), value, false));
    }

    // ── colr (Jpeg2000::ColorSpec, Jpeg2000.pm:631-728) ─────────────────
    if let Some(m) = self.color_spec_method() {
      // `int8s` ⇒ the `-n` raw is the SIGNED value (e.g. 0xff → -1).
      let value = if print_conv {
        TagValue::Str(jp2_color_spec_method_print(m))
      } else {
        TagValue::I64(i64::from(m))
      };
      tags.push(EmittedTag::new(
        j2k(),
        "ColorSpecMethod".into(),
        value,
        false,
      ));
    }
    if let Some(p) = self.color_spec_precedence() {
      // ColorSpecPrecedence: `int8s`, no PrintConv ⇒ a bare signed int in
      // both modes.
      tags.push(EmittedTag::new(
        j2k(),
        "ColorSpecPrecedence".into(),
        TagValue::I64(i64::from(p)),
        false,
      ));
    }
    if let Some(a) = self.color_spec_approximation() {
      // `int8s` ⇒ the `-n` raw is the SIGNED value (e.g. 0xff → -1).
      let value = if print_conv {
        TagValue::Str(jp2_color_spec_approximation_print(a))
      } else {
        TagValue::I64(i64::from(a))
      };
      tags.push(EmittedTag::new(
        j2k(),
        "ColorSpecApproximation".into(),
        value,
        false,
      ));
    }
    if let Some(cs) = self.color_space() {
      // ColorSpace (method-1 only): PrintConv enum; raw `int32u` at `-n`.
      let value = if print_conv {
        TagValue::Str(jp2_color_space_print(cs))
      } else {
        TagValue::U64(u64::from(cs))
      };
      tags.push(EmittedTag::new(j2k(), "ColorSpace".into(), value, false));
    }

    tags.into_iter()
  }
}

impl crate::diagnostics::Diagnose for Jp2Meta {
  /// Surface the JP2 box-walk warning (if any) as a document-level
  /// `Warning`. The typed surface stores at most one warning
  /// ([`Jp2Meta::warning`]); there is no group scope (a JP2 has no
  /// track/document axis), so it rides the default (doc-level) group.
  fn diagnostics(&self) -> alloc::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = alloc::vec::Vec::new();
    if let Some(w) = self.warning() {
      out.push(crate::diagnostics::Diagnostic::warn(w));
    }
    out
  }
}

impl crate::metadata::Project for Jp2Meta {
  /// Project JP2 facts into the normalized [`crate::metadata::MediaMetadata`]
  /// domain. SP4 surfaces only the deferred-warning channel (the camera
  /// identity is in the UUID-Exif body, PR #36), so this delegates to the
  /// existing [`Jp2Meta::project_into`].
  fn project(&self) -> crate::metadata::MediaMetadata {
    let mut md = crate::metadata::MediaMetadata::new();
    self.project_into(&mut md);
    md
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Build a top-level ISO-BMFF box: [size:u32][tag:4 bytes][body...].
  fn box_bytes(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let size = 8u32 + body.len() as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
  }

  /// Test shim: run the unified [`scan_quicktime_brands`] from the top-level
  /// `%QuickTime::Main` table over `data`, surfacing only the HEIF item view
  /// (the brand walk a HEIF-only fixture exercises). Equivalent to the old
  /// standalone `scan_heif_meta` entry point.
  fn scan_heif_meta(data: &[u8], out: &mut HeifMeta) {
    let mut cr3 = Cr3Meta::new();
    let mut model = None;
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    scan_quicktime_brands(
      data,
      0,
      QtTable::Main,
      0,
      out,
      &mut cr3,
      &mut model,
      &mut iloc_budget,
    );
  }

  /// Test shim: run the unified [`scan_quicktime_brands`] from `%Main` over
  /// `data`, surfacing the Canon CR3 view. Returns `true` when the Canon
  /// `uuid` was dispatched (i.e. it sat under `moov`, populating at least one
  /// CR3 block) — the same observable the old standalone `scan_canon_uuid`
  /// boolean reported (a top-level Canon `uuid` is not in `%Main`, so it is
  /// never dispatched and `cr3` stays empty).
  fn scan_canon_uuid(data: &[u8], out: &mut Cr3Meta) -> bool {
    let mut heif = HeifMeta::new();
    let mut model = None;
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    scan_quicktime_brands(
      data,
      0,
      QtTable::Main,
      0,
      &mut heif,
      out,
      &mut model,
      &mut iloc_budget,
    );
    !out.is_empty()
  }

  #[test]
  fn walk_boxes_enormous_extended_size_stops_cleanly() {
    // A box header declaring `size == 1` (extended-size marker) followed
    // by a 64-bit size near u64::MAX. `body_end`/`next` = pos + ext would
    // overflow `usize`; the checked arithmetic must stop the walk cleanly
    // — no debug panic, no release wrap — visiting zero boxes.
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_be_bytes()); // size = 1 → extended
    data.extend_from_slice(b"mdat"); // tag
    data.extend_from_slice(&(u64::MAX - 3).to_be_bytes()); // 64-bit ext size
    data.extend_from_slice(&[0u8; 8]); // a little payload
    let mut visited = 0usize;
    walk_boxes(&data, 0, Size0Behavior::Stop, |_h| {
      visited += 1;
    });
    assert_eq!(visited, 0, "overflowing extended size must abort the walk");
  }

  #[test]
  fn ftyp_brand_lookup_heic() {
    let (ft, mime) = file_type_from_ftyp_brand(b"heic").unwrap();
    assert_eq!(ft, "HEIC");
    assert_eq!(mime, "image/heic");
  }

  #[test]
  fn ftyp_brand_lookup_avif() {
    let (ft, mime) = file_type_from_ftyp_brand(b"avif").unwrap();
    assert_eq!(ft, "AVIF");
    assert_eq!(mime, "image/avif");
  }

  #[test]
  fn ftyp_brand_lookup_crx() {
    let (ft, mime) = file_type_from_ftyp_brand(b"crx ").unwrap();
    assert_eq!(ft, "CRX");
    assert_eq!(mime, "video/x-canon-crx");
  }

  #[test]
  fn ftyp_brand_lookup_jp2() {
    let (ft, mime) = file_type_from_ftyp_brand(b"JP2 ").unwrap();
    assert_eq!(ft, "JP2");
    assert_eq!(mime, "image/jp2");
  }

  #[test]
  fn ftyp_brand_lookup_hevc_is_heics() {
    // QuickTime.pm:228 desc `'… HEVC sequence (.HEICS)'` ⇒ extracted
    // FileType = HEICS (NOT HEVC); MIME = `%mimeLookup{HEICS}`.
    let (ft, mime) = file_type_from_ftyp_brand(b"hevc").unwrap();
    assert_eq!(ft, "HEICS");
    assert_eq!(mime, "image/heic-sequence");
  }

  #[test]
  fn ftyp_brand_lookup_f4p_distinct_from_f4v() {
    // QuickTime.pm:172 desc `'Protected Video … (.F4P)'` ⇒ FileType F4P.
    let (ft, mime) = file_type_from_ftyp_brand(b"F4P ").unwrap();
    assert_eq!(ft, "F4P");
    assert_eq!(mime, "video/mp4");
    // F4V stays F4V.
    assert_eq!(file_type_from_ftyp_brand(b"F4V ").unwrap().0, "F4V");
  }

  #[test]
  fn ftyp_brand_lookup_mj2_brands_fall_through() {
    // `mj2s`/`mjp2` descriptions (QuickTime.pm:196-197) have NO `(.EXT)`
    // ⇒ fall through (return None → compat scan → MP4).
    assert!(file_type_from_ftyp_brand(b"mj2s").is_none());
    assert!(file_type_from_ftyp_brand(b"mjp2").is_none());
    // A bare-major MJ2 file with no compat trigger defaults to MP4.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"mj2s");
    payload.extend_from_slice(&[0u8; 4]);
    assert_eq!(resolve_ftyp_file_type(&payload).0, "MP4");
  }

  #[test]
  fn ftyp_brand_lookup_3gg6_falls_through() {
    // `3gg6` desc `'3GPP Release 6 General Profile'` (QuickTime.pm:136)
    // has NO `(.EXT)` ⇒ fall through (contrast `3ge6` which maps 3GP).
    assert!(file_type_from_ftyp_brand(b"3gg6").is_none());
    assert_eq!(file_type_from_ftyp_brand(b"3ge6").unwrap().0, "3GP");
  }

  #[test]
  fn ftyp_brand_lookup_explicit_mp4_descriptions() {
    // These descriptions carry `(.MP4)` ⇒ FileType MP4, MIME video/mp4
    // (QuickTime.pm:198,205,207-216).
    for brand in [
      b"MSNV", b"mmp4", b"NDSC", b"NDSH", b"NDSM", b"NDSP", b"NDSS", b"NDXC", b"NDXH", b"NDXM",
      b"NDXP", b"NDXS",
    ] {
      let (ft, mime) = file_type_from_ftyp_brand(brand).unwrap();
      assert_eq!(ft, "MP4", "brand {:?}", core::str::from_utf8(brand));
      assert_eq!(mime, "video/mp4", "brand {:?}", core::str::from_utf8(brand));
    }
    // NDAS has no `(.EXT)` → falls through (NOT a direct MP4 map).
    assert!(file_type_from_ftyp_brand(b"NDAS").is_none());
  }

  #[test]
  fn ftyp_brand_lookup_iso5_returns_none() {
    // `iso5` IS in %ftypLookup (QuickTime.pm:178) but its value
    // `'MP4 Base Media v5'` has NO `(.EXT)` substring — bundled's
    // regex `/\(\.(\w+)/` fails, so the brand FALLS THROUGH to the
    // compatible-brand elsif chain. Mirror by returning `None`.
    assert!(file_type_from_ftyp_brand(b"iso5").is_none());
  }

  #[test]
  fn ftyp_brand_lookup_unknown_returns_none() {
    assert!(file_type_from_ftyp_brand(b"xxxx").is_none());
    // hvc1 is a sample-description code, NOT an ftyp brand — bundled
    // does not list it in %ftypLookup so it returns None.
    assert!(file_type_from_ftyp_brand(b"hvc1").is_none());
  }

  #[test]
  fn resolve_ftyp_falls_through_to_mp4() {
    // Major brand `xxxx` + compat brand `mp42` at offset 12 → MP4.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"xxxx"); // major
    payload.extend_from_slice(&[0u8; 4]); // minor version
    payload.extend_from_slice(b"isom"); // first compat slot (ignored)
    payload.extend_from_slice(b"mp42"); // second compat slot — hit
    let (ft, mime) = resolve_ftyp_file_type(&payload);
    assert_eq!(ft, "MP4");
    assert_eq!(mime, "video/mp4");
  }

  #[test]
  fn resolve_ftyp_heic_major() {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"heic");
    payload.extend_from_slice(&[0u8; 4]);
    payload.extend_from_slice(b"mif1");
    let (ft, mime) = resolve_ftyp_file_type(&payload);
    assert_eq!(ft, "HEIC");
    assert_eq!(mime, "image/heic");
  }

  #[test]
  fn resolve_ftyp_short_buffer_defaults_to_mp4() {
    // < 4 bytes → no brand readable → falls through to MP4 default.
    let (ft, _mime) = resolve_ftyp_file_type(&[]);
    assert_eq!(ft, "MP4");
  }

  #[test]
  fn walk_boxes_iterates_in_order() {
    let mut blob = Vec::new();
    blob.extend(box_bytes(b"AAAA", &[1, 2, 3]));
    blob.extend(box_bytes(b"BBBB", &[4]));
    blob.extend(box_bytes(b"CCCC", &[]));
    let mut seen: Vec<[u8; 4]> = Vec::new();
    walk_boxes(&blob, 0, Size0Behavior::Stop, |h| {
      let mut t = [0u8; 4];
      t.copy_from_slice(h.tag);
      seen.push(t);
    });
    assert_eq!(seen, vec![*b"AAAA", *b"BBBB", *b"CCCC"]);
  }

  #[test]
  fn walk_boxes_stops_on_size_lt_8() {
    let mut blob = Vec::new();
    blob.extend(box_bytes(b"AAAA", &[1]));
    // Malformed: size 4, type "BAD!". Walker should stop after AAAA.
    blob.extend_from_slice(&4u32.to_be_bytes());
    blob.extend_from_slice(b"BAD!");
    let mut seen: Vec<[u8; 4]> = Vec::new();
    walk_boxes(&blob, 0, Size0Behavior::Stop, |h| {
      let mut t = [0u8; 4];
      t.copy_from_slice(h.tag);
      seen.push(t);
    });
    assert_eq!(seen, vec![*b"AAAA"]);
  }

  #[test]
  fn walk_boxes_size0_box_stops_without_decoding() {
    // A `size == 0` box STOPS the walk WITHOUT invoking the callback —
    // mirroring the core `read_atom_header` (ExtendsToEof at top level /
    // Terminator when contained, QuickTime.pm:10036-10056): in neither case
    // does ProcessMOV decode a size-0 atom's body. So box A (before the
    // size-0 box) IS visited, and box C (after it) is UNREACHED.
    let mut blob = Vec::new();
    blob.extend(box_bytes(b"AAAA", &[1, 2, 3]));
    // A size-0 box `BBBB` (4-byte size of 0 + tag, then some payload bytes).
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(b"BBBB");
    blob.extend_from_slice(&[9, 9, 9, 9]);
    blob.extend(box_bytes(b"CCCC", &[7]));
    let mut seen: Vec<[u8; 4]> = Vec::new();
    walk_boxes(&blob, 0, Size0Behavior::Stop, |h| {
      let mut t = [0u8; 4];
      t.copy_from_slice(h.tag);
      seen.push(t);
    });
    assert_eq!(
      seen,
      vec![*b"AAAA"],
      "only the box before the size-0 box is visited (size-0 stops the walk; the trailing box is unreached)"
    );
  }

  #[test]
  fn walk_boxes_stops_on_overrun() {
    let mut blob = Vec::new();
    blob.extend(box_bytes(b"AAAA", &[1]));
    // Declared size larger than remaining buffer.
    blob.extend_from_slice(&999u32.to_be_bytes());
    blob.extend_from_slice(b"OVER");
    blob.extend_from_slice(&[0u8; 4]);
    let mut seen: Vec<[u8; 4]> = Vec::new();
    walk_boxes(&blob, 0, Size0Behavior::Stop, |h| {
      let mut t = [0u8; 4];
      t.copy_from_slice(h.tag);
      seen.push(t);
    });
    assert_eq!(seen, vec![*b"AAAA"]);
  }

  #[test]
  fn jp2_signature_recognized() {
    assert!(is_jp2_signature(&JP2_SIGNATURE));
    assert!(is_jp2_signature(&JP2_SIGNATURE_ALT));
    let mut buf = JP2_SIGNATURE.to_vec();
    buf.push(0);
    assert!(is_jp2_signature(&buf));
    assert!(!is_jp2_signature(&[]));
    assert!(!is_jp2_signature(b"ftypmp42xx"));
  }

  #[test]
  fn j2c_signature_recognized_and_distinct_from_jp2() {
    // The raw J2C codestream signature `ff 4f ff 51 00` (Jpeg2000.pm:1552)
    // is recognized by `is_j2c_signature` (for a ≥12-byte buffer — see the
    // 12-byte gate below) but NOT by `is_jp2_signature` (a bare codestream
    // is not a boxed JP2), and vice versa.
    let mut buf = J2C_SIGNATURE.to_vec();
    buf.extend_from_slice(&[0u8; 8]); // ≥12 bytes total
    assert!(is_j2c_signature(&buf));
    assert!(!is_j2c_signature(&[]));
    assert!(!is_j2c_signature(b"ftypmp42")); // not a codestream
    assert!(!is_j2c_signature(&JP2_SIGNATURE)); // boxed JP2 ≠ J2C
    assert!(!is_jp2_signature(&J2C_SIGNATURE)); // J2C ≠ boxed JP2
  }

  #[test]
  fn j2c_signature_requires_full_12_byte_header() {
    // `ProcessJP2` reads 12 bytes (`return 0 unless $raf->Read($hdr,12) ==
    // 12`, Jpeg2000.pm:1547) BEFORE testing the `\xff\x4f\xff\x51\0` prefix
    // (line 1552), so a buffer that starts with the SOC/SIZ prefix but is
    // shorter than 12 bytes is REJECTED — never finalized as J2C.
    // The bare 5-byte signature: prefix present but < 12 bytes → rejected.
    assert!(!is_j2c_signature(&J2C_SIGNATURE));
    // An 11-byte prefixed buffer: still one byte short → rejected.
    let mut eleven = J2C_SIGNATURE.to_vec();
    eleven.extend_from_slice(&[0u8; 6]); // 5 + 6 = 11 bytes
    assert_eq!(eleven.len(), 11);
    assert!(!is_j2c_signature(&eleven));
    // Exactly 12 bytes with the prefix → accepted.
    let mut twelve = J2C_SIGNATURE.to_vec();
    twelve.extend_from_slice(&[0u8; 7]); // 5 + 7 = 12 bytes
    assert_eq!(twelve.len(), 12);
    assert!(is_j2c_signature(&twelve));
  }

  #[test]
  fn walk_jp2_raw_j2c_codestream_sets_subtype_j2c() {
    // `ProcessJP2`'s `/^\xff\x4f\xff\x51\0/` arm `SetFileType('J2C')`
    // (Jpeg2000.pm:1561) — exifast sets sub_type `J2C` and does NO box walk.
    let mut data = J2C_SIGNATURE.to_vec();
    data.extend_from_slice(&[0u8; 16]); // a little SIZ payload (ignored)
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("J2C"));
    // No JP2 boxes are walked for a bare codestream.
    assert!(m.uuid_exif().is_none());
    assert!(m.ihdr().is_none());
  }

  #[test]
  fn parse_jp2_borrowed_accepts_raw_j2c() {
    // The lib-first entry accepts a raw J2C codestream (returns Some with
    // sub_type J2C), where the pre-fix code returned None and dead-ended.
    let mut data = J2C_SIGNATURE.to_vec();
    data.extend_from_slice(&[0u8; 8]);
    let m = parse_jp2_borrowed(&data).expect("raw J2C accepted");
    assert_eq!(m.sub_type(), Some("J2C"));
    // A non-JP2, non-J2C input is still rejected.
    assert!(parse_jp2_borrowed(b"not a jp2 or j2c").is_none());
  }

  #[test]
  fn walk_jp2_detects_subtype_jpx() {
    // Build a JP2: signature + ftyp(brand="jpx ").
    let mut data = JP2_SIGNATURE.to_vec();
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"jpx "); // major brand
    ftyp_body.extend_from_slice(&[0u8; 4]); // minor
    data.extend(box_bytes(b"ftyp", &ftyp_body));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("JPX"));
  }

  #[test]
  fn walk_jp2_default_subtype_is_jp2() {
    let mut data = JP2_SIGNATURE.to_vec();
    // No ftyp → default JP2.
    data.extend(box_bytes(b"free", &[0u8; 8]));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("JP2"));
  }

  #[test]
  fn walk_jp2_later_ftyp_does_not_promote() {
    // Faithful to ProcessJP2 (Jpeg2000.pm:1578-1587): the sub-type is
    // derived ONLY from the single box immediately after the 12-byte
    // signature. Here that box is `jp2h` (NOT `ftyp`), so the type stays
    // JP2 even though a `ftyp jpx ` box follows later. The pre-fix walker
    // scanned every sibling and would wrongly promote to JPX.
    let mut data = JP2_SIGNATURE.to_vec();
    // First box after the signature: jp2h (no ftyp) → no promotion.
    let mut ihdr_body = Vec::new();
    ihdr_body.extend_from_slice(&100u32.to_be_bytes());
    ihdr_body.extend_from_slice(&100u32.to_be_bytes());
    ihdr_body.extend_from_slice(&3u16.to_be_bytes());
    ihdr_body.extend_from_slice(&[7, 7, 0, 0]);
    data.extend(box_bytes(b"jp2h", &box_bytes(b"ihdr", &ihdr_body)));
    // A LATER ftyp with brand `jpx ` — must be ignored for sub-type.
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"jpx ");
    ftyp_body.extend_from_slice(&[0u8; 4]);
    data.extend(box_bytes(b"ftyp", &ftyp_body));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("JP2"));
  }

  #[test]
  fn walk_jp2_locates_uuid_exif() {
    let mut data = JP2_SIGNATURE.to_vec();
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&JP2_UUID_EXIF);
    uuid_body.extend_from_slice(b"FAKETIFFDATA");
    data.extend(box_bytes(b"uuid", &uuid_body));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    let e = m.uuid_exif().expect("uuid_exif");
    assert_eq!(e.length(), 12); // "FAKETIFFDATA"
  }

  #[test]
  fn walk_jp2_digikam_bad_uuid_exif_uses_plus_22() {
    // Jpeg2000.pm:304-315 `UUID-EXIF_bad` (written by Digikam): the
    // 16-byte `JpgTiffExif->JP2` prefix is FOLLOWED by `Exif\0\0`, so
    // the negative-lookahead `(?!Exif\0\0)` on the GOOD `UUID-EXIF` arm
    // (Jpeg2000.pm:283) fails and the `UUID-EXIF_bad` arm
    // (`Start => '$valuePtr + 22'`) fires — the real TIFF starts at +22,
    // not +16. The 6 skipped bytes are exactly `Exif\0\0` (16 + 6 = 22).
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&JP2_UUID_EXIF);
    uuid_body.extend_from_slice(b"Exif\0\0");
    uuid_body.extend_from_slice(b"MM\0*FAKETIFF"); // 12-byte fake TIFF
    let mut data = JP2_SIGNATURE.to_vec();
    data.extend(box_bytes(b"uuid", &uuid_body));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    let e = m.uuid_exif().expect("uuid_exif");
    // The uuid box starts after the 12-byte signature; its body is at
    // box_start + 8; the TIFF is a further +22 in.
    let uuid_box_start = JP2_SIGNATURE.len() as u64;
    assert_eq!(e.offset(), uuid_box_start + 8 + 22);
    assert_eq!(e.length(), 12); // "MM\0*FAKETIFF"
  }

  #[test]
  fn walk_jp2_good_uuid_exif_uses_plus_16() {
    // The GOOD `UUID-EXIF` arm: the `JpgTiffExif->JP2` prefix is NOT
    // followed by `Exif\0\0`, so `Start => '$valuePtr + 16'` applies.
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&JP2_UUID_EXIF);
    uuid_body.extend_from_slice(b"MM\0*FAKETIFF"); // TIFF immediately at +16
    let mut data = JP2_SIGNATURE.to_vec();
    data.extend(box_bytes(b"uuid", &uuid_body));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    let e = m.uuid_exif().expect("uuid_exif");
    let uuid_box_start = JP2_SIGNATURE.len() as u64;
    assert_eq!(e.offset(), uuid_box_start + 8 + 16);
    assert_eq!(e.length(), 12);
  }

  #[test]
  fn walk_jp2_ignores_non_signature() {
    let data = b"NOT A JP2";
    let mut m = Jp2Meta::new();
    walk_jp2(data, &mut m);
    assert!(m.is_empty());
  }

  #[test]
  fn walk_canon_uuid_decodes_cncv_cr3() {
    let mut data = Vec::new();
    // CNCV `CanonCR3 0.1.00`
    let cncv = b"CanonCR3 0.1.00";
    data.extend(box_bytes(b"CNCV", cncv));
    // CMT1 (Exif IFD0) — empty body for the test.
    data.extend(box_bytes(b"CMT1", &[0xAB; 16]));
    // CMT3 — empty body.
    data.extend(box_bytes(b"CMT3", &[0xCD; 8]));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 100, &mut m);
    assert_eq!(m.compressor_version(), Some("CanonCR3 0.1.00"));
    assert_eq!(m.override_file_type(), Some("CR3"));
    let c1 = m.cmt1().unwrap();
    // CNCV is 15 bytes payload → box len 23; CMT1 starts at 100 + 23 = 123
    // and its body is at +8 = 131. Length is 16.
    assert_eq!(c1.offset(), 100 + (8 + 15) + 8);
    assert_eq!(c1.length(), 16);
    let c3 = m.cmt3().unwrap();
    assert_eq!(c3.length(), 8);
  }

  #[test]
  fn walk_canon_uuid_decodes_cncv_crm() {
    let mut data = Vec::new();
    data.extend(box_bytes(b"CNCV", b"CanonCRM 0.1.00"));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 0, &mut m);
    assert_eq!(m.override_file_type(), Some("CRM"));
  }

  #[test]
  fn walk_canon_uuid_ignores_unknown_cncv() {
    let mut data = Vec::new();
    data.extend(box_bytes(b"CNCV", b"OtherFOO 0.1.00"));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 0, &mut m);
    assert_eq!(m.compressor_version(), Some("OtherFOO 0.1.00"));
    assert!(m.override_file_type().is_none());
  }

  #[test]
  fn cncv_leading_space_does_not_override() {
    // R17: ExifTool's `/^Canon(\w{3})/i` is ANCHORED — a leading space means
    // `^Canon` does NOT match, so a crafted `" CanonCR3 ..."` must NOT override
    // CRX→CR3. (The pre-fix `.trim()` wrongly stripped the space and matched.)
    let mut data = Vec::new();
    data.extend(box_bytes(b"CNCV", b" CanonCR3 0.1.00"));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 0, &mut m);
    assert!(
      m.override_file_type().is_none(),
      "leading space → anchored ^Canon does not match → no override"
    );
  }

  #[test]
  fn cncv_trailing_non_utf8_still_overrides() {
    // R17: the override matches the RAW bytes' ASCII prefix, so a trailing
    // non-UTF-8 byte must NOT suppress it (the pre-fix whole-body `from_utf8`
    // returned "" and missed the override). `^Canon(\w{3})` = "CR3".
    let mut data = Vec::new();
    data.extend(box_bytes(b"CNCV", b"CanonCR3 0.1.00\xff"));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 0, &mut m);
    assert_eq!(
      m.override_file_type(),
      Some("CR3"),
      "trailing non-UTF-8 byte must not suppress the ASCII-prefix override"
    );
  }

  #[test]
  fn cncv_underscore_is_word_char() {
    // R17: Perl `\w` includes underscore, so `Canon_R3` captures `_R3`.
    let mut data = Vec::new();
    data.extend(box_bytes(b"CNCV", b"Canon_R3 0.1.00"));
    let mut m = Cr3Meta::new();
    walk_canon_uuid(&data, 0, &mut m);
    assert_eq!(m.override_file_type(), Some("_R3"));
  }

  #[test]
  fn scan_canon_top_level_uuid_not_dispatched() {
    // R18-F1: the `UUID-Canon` entry (the `85 c0 b6 87 …` prefix →
    // `Canon::uuid`) is wired ONLY in `%QuickTime::Movie` (moov children,
    // QuickTime.pm:1234-1242). The TOP-LEVEL `%QuickTime::Main` `uuid` list
    // (QuickTime.pm:702-822) does NOT include it. So a TOP-LEVEL Canon-prefix
    // uuid is NOT scanned for the Canon table — `scan_canon_uuid` returns
    // `false` and the CMT1 child is never recorded (contrast the in-moov case,
    // `scan_canon_uuid_finds_in_moov`).
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend_from_slice(&box_bytes(b"CMT1", &[0x42; 4]));
    let blob = box_bytes(b"uuid", &uuid_body);
    let mut m = Cr3Meta::new();
    assert!(
      !scan_canon_uuid(&blob, &mut m),
      "a top-level Canon UUID is not in %Main → not dispatched"
    );
    assert!(m.cmt1().is_none());
    assert!(m.is_empty());
  }

  #[test]
  fn scan_canon_uuid_finds_in_moov() {
    // moov { uuid[Canon] { CMT3 } }
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend(box_bytes(b"CMT3", &[0x55; 6]));
    let mut moov_body = Vec::new();
    moov_body.extend(box_bytes(b"uuid", &uuid_body));
    let blob = box_bytes(b"moov", &moov_body);
    let mut m = Cr3Meta::new();
    assert!(scan_canon_uuid(&blob, &mut m));
    assert_eq!(m.cmt3().unwrap().length(), 6);
  }

  #[test]
  fn scan_canon_uuid_returns_false_for_non_cr3() {
    let blob = box_bytes(b"moov", &box_bytes(b"mvhd", &[0u8; 100]));
    let mut m = Cr3Meta::new();
    assert!(!scan_canon_uuid(&blob, &mut m));
    assert!(m.is_empty());
  }

  #[test]
  fn walk_heif_meta_decodes_pitm_v0() {
    // meta is a FullBox: 4-byte version+flags, then children.
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // version 0 + flags
    // pitm v0: 4-byte verflags + 2-byte id.
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&42u16.to_be_bytes());
    body.extend(box_bytes(b"pitm", &pitm_body));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.primary_item(), Some(42));
  }

  #[test]
  fn walk_heif_meta_decodes_pitm_v1() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]);
    // pitm v1: 4-byte verflags(ver=1) + 4-byte id.
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[1, 0, 0, 0]);
    pitm_body.extend_from_slice(&100_000u32.to_be_bytes());
    body.extend(box_bytes(b"pitm", &pitm_body));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.primary_item(), Some(100_000));
  }

  /// Build an `infe` v2 body for a given (id, type, name).
  fn infe_v2(id: u16, item_type: &[u8; 4], name: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[2, 0, 0, 0]); // version 2 + flags
    b.extend_from_slice(&id.to_be_bytes()); // 2-byte id
    b.extend_from_slice(&[0, 0]); // 2-byte ProtectionIndex
    b.extend_from_slice(item_type); // 4-byte ItemType
    b.extend_from_slice(name); // Name string
    b.push(0); // NUL terminator
    b
  }

  #[test]
  fn parse_infe_v2_exif() {
    let body = infe_v2(7, b"Exif", b"exif");
    let it = parse_infe(&body).expect("parsed");
    assert_eq!(it.id(), 7);
    assert_eq!(it.item_type(), Some("Exif"));
    assert_eq!(it.name(), Some("exif"));
  }

  #[test]
  fn parse_infe_v2_mime_xmp() {
    let mut body = Vec::new();
    body.extend_from_slice(&[2, 0, 0, 0]);
    body.extend_from_slice(&9u16.to_be_bytes());
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(b"mime");
    body.extend_from_slice(b"\0"); // empty name
    body.extend_from_slice(b"application/rdf+xml\0");
    let it = parse_infe(&body).expect("parsed");
    assert_eq!(it.id(), 9);
    assert_eq!(it.item_type(), Some("mime"));
    assert_eq!(it.content_type(), Some("application/rdf+xml"));
  }

  #[test]
  fn parse_infe_v2_non_utf8_item_type_still_parses() {
    // R13: ExifTool stores the raw 4-byte item Type and continues
    // (`substr`, QuickTime.pm:9257) — a non-UTF-8 type must NOT abort the
    // entry. The item is still created; the type is simply left unset.
    let body = infe_v2(5, b"\xff\xfe\xfd\xfc", b"x");
    let it = parse_infe(&body).expect("non-UTF-8 item type must not abort parse");
    assert_eq!(it.id(), 5);
    assert_eq!(
      it.item_type(),
      None,
      "non-UTF-8 type unset; item still created"
    );
  }

  #[test]
  fn iinf_out_of_order_non_utf8_type_still_warns() {
    // R13: descending ids 2 then 1 where the SECOND v2 infe has a non-UTF-8
    // item type — ExifTool still creates the item and reaches the out-of-order
    // check, so the warning fires and both items merge. Pre-fix the non-UTF-8
    // type aborted the second entry, dropping the item AND the warning.
    let meta = meta_with_iinf(&iinf_v0(&[
      infe_v2(2, b"hvc1", b"a"),
      infe_v2(1, b"\xff\xfe\xfd\xfc", b"b"),
    ]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&meta, &mut m);
    assert_eq!(m.warning(), Some("Item info entries are out of order"));
    assert_eq!(
      m.items().len(),
      2,
      "both items merged despite non-UTF-8 type"
    );
  }

  #[test]
  fn parse_infe_v0_truncated_no_item() {
    // R12-F3: ExifTool's `return undef if $pos + 4 > $len` (QuickTime.pm:9239,
    // after `$pos = 4`) requires len >= 8 for ALL versions — the 2-byte id +
    // 2-byte ProtectionIndex must both fit. A 6- or 7-byte v0 body must yield
    // `None`, NOT a phantom item that then skews the iinf order check.
    // 6 bytes: version/flags(4) + id(2), no ProtectionIndex.
    let mut six = Vec::new();
    six.extend_from_slice(&[0, 0, 0, 0]);
    six.extend_from_slice(&1u16.to_be_bytes());
    assert_eq!(six.len(), 6);
    assert!(parse_infe(&six).is_none(), "6-byte v0 infe → None");
    // 7 bytes: one byte into ProtectionIndex — still short of len >= 8.
    let mut seven = six.clone();
    seven.push(0);
    assert_eq!(seven.len(), 7);
    assert!(parse_infe(&seven).is_none(), "7-byte v0 infe → None");
    // Via the iinf walk: a truncated infe merges NO phantom item and raises
    // NO order warning. Wrap the 6-byte body in an `infe` box inside iinf v0.
    let body = meta_inner(&iinf_v0(&[six]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert!(
      m.items().is_empty(),
      "a truncated infe produces no phantom item"
    );
    assert_eq!(m.warning(), None, "no order warning from a dropped infe");
  }

  #[test]
  fn walk_heif_meta_iinf_iloc_merge() {
    // Build meta body:
    //   pitm(v0, id=1)
    //   iinf(v0, count=1) { infe(v2, id=1, type='Exif') }
    //   iloc(v1, siz=0x4400, count=1, item(id=1, base=0, ext_num=1,
    //        offset=0x100, len=0x40))
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags

    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&1u16.to_be_bytes());
    body.extend(box_bytes(b"pitm", &pitm_body));

    let mut iinf_body = Vec::new();
    iinf_body.extend_from_slice(&[0, 0, 0, 0]); // version 0 + flags
    iinf_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iinf_body.extend(box_bytes(b"infe", &infe_v2(1, b"Exif", b"")));
    body.extend(box_bytes(b"iinf", &iinf_body));

    // iloc v1: noff=4, nlen=4, nbas=0, nind=0 ⇒ siz=0x4400.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4400u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    // Item id=1, constMeth=0, dataRefIdx=0, base=skipped (nbas=0),
    // ext_num=1, extent(ext_index=skipped (nind=0), offset=0x100,
    // length=0x40).
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // id
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth (0)
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    iloc_body.extend_from_slice(&0x100u32.to_be_bytes()); // offset
    iloc_body.extend_from_slice(&0x40u32.to_be_bytes()); // length
    body.extend(box_bytes(b"iloc", &iloc_body));

    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.primary_item(), Some(1));
    assert_eq!(m.items().len(), 1);
    let it = &m.items()[0];
    assert_eq!(it.id(), 1);
    assert_eq!(it.item_type(), Some("Exif"));
    assert_eq!(it.extents().len(), 1);
    assert_eq!(it.extents()[0].offset(), 0x100);
    assert_eq!(it.extents()[0].length(), 0x40);
    // The lookup helpers should find the Exif item.
    assert_eq!(m.exif_item().unwrap().id(), 1);
  }

  #[test]
  fn parse_iloc_nlen_zero_keeps_item_with_zero_length() {
    // QuickTime.pm:9047-9050: `GetVarInt` with `$n == 0` returns
    // `$default || 0` (DEFINED, 0) — it does NOT signal truncation. So
    // an iloc whose length-size nibble `nlen == 0` yields extent length
    // 0 and the item is KEPT (NOT dropped, NOT an error that aborts the
    // whole iloc).
    //
    // iloc v1: noff=4, nlen=0, nbas=0, nind=0 ⇒ siz = 0x4000.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4000u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iloc_body.extend_from_slice(&9u16.to_be_bytes()); // id
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    // extent: ext_index skipped (nind=0), offset 4 bytes (noff=4),
    // length skipped (nlen=0).
    iloc_body.extend_from_slice(&0x200u32.to_be_bytes()); // offset

    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    assert!(parse_iloc(&iloc_body, &mut out, &mut id_index).is_ok());
    assert!(out.warning().is_none(), "nlen==0 is not a truncation");
    assert_eq!(out.items().len(), 1);
    let it = &out.items()[0];
    assert_eq!(it.id(), 9);
    assert_eq!(it.extents().len(), 1);
    assert_eq!(it.extents()[0].offset(), 0x200);
    assert_eq!(it.extents()[0].length(), 0);
  }

  #[test]
  fn parse_iloc_invalid_nlen_width_2_aborts() {
    // GetVarInt (QuickTime.pm:9048-9055) only accepts $n in {0,4,8}; any
    // other width falls through to `return undef`. A length-size nibble
    // of 2 therefore makes `$extent_length` undef, and line 9184
    // `return undef unless defined $extent_length` aborts the WHOLE iloc.
    // Enough bytes are present that this is the WIDTH (not a short read)
    // that rejects it.
    //
    // iloc v1: noff=4, nlen=2, nbas=0, nind=0 ⇒ siz = 0x4200.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4200u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iloc_body.extend_from_slice(&7u16.to_be_bytes()); // id
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    iloc_body.extend_from_slice(&0x200u32.to_be_bytes()); // offset (noff=4)
    iloc_body.extend_from_slice(&[0u8, 0u8]); // length bytes present (nlen=2)

    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    assert!(
      parse_iloc(&iloc_body, &mut out, &mut id_index).is_err(),
      "nlen=2 is an invalid GetVarInt width → abort"
    );
  }

  #[test]
  fn parse_iloc_invalid_nlen_width_5_aborts() {
    // Same as above for nlen=5 (also not in {0,4,8}). Bytes for the
    // 5-wide length field ARE present, so the rejection is the width, not
    // truncation.
    //
    // iloc v1: noff=4, nlen=5, nbas=0, nind=0 ⇒ siz = 0x4500.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4500u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iloc_body.extend_from_slice(&8u16.to_be_bytes()); // id
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    iloc_body.extend_from_slice(&0x200u32.to_be_bytes()); // offset (noff=4)
    iloc_body.extend_from_slice(&[0u8; 5]); // length bytes present (nlen=5)

    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    assert!(
      parse_iloc(&iloc_body, &mut out, &mut id_index).is_err(),
      "nlen=5 is an invalid GetVarInt width → abort"
    );
  }

  #[test]
  fn walk_heif_meta_handles_truncated_iloc() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]);
    // iloc with only 4 bytes — too short.
    body.extend(box_bytes(b"iloc", &[0, 0, 0, 0]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert!(m.warning().is_some());
  }

  /// #218 — a crafted `iloc` whose `num` × `ext_num` product is enormous but
  /// whose `siz` nibbles are all zero (zero-width extents consume NO input
  /// bytes) must NOT materialize billions of extents. ExifTool's
  /// `ParseItemLocation` would `push` one Perl hash per declared extent and run
  /// out of memory; exifast's [`MAX_ILOC_EXTENTS`] ceiling bounds the TOTAL
  /// extent work across all items. Proven cheaply with a tiny synthetic budget
  /// via [`parse_iloc_capped`]: the walk stops the instant the cumulative
  /// extent count reaches the budget, so only `budget` extents are ever
  /// materialized regardless of the declared magnitude.
  ///
  /// The body is ~393 KB (matching the issue's ~400 KB crafted-input figure):
  /// 65535 items × 4 declared extents each = 262 140 declared extents. A
  /// 64-extent budget caps the materialized total at 64 (16 fully-merged items)
  /// and halts the walk — bounded, no OOM, no hang.
  #[test]
  fn parse_iloc_zero_width_extent_flood_is_bounded() {
    // ver 0, siz = 0x0000 → noff=nlen=nbas=nind=0. Per-item header is
    // id(2) + dataRefIdx(2) + ext_num(2) = 6 bytes; each declared extent then
    // reads 0 offset + 0 length bytes (the GetVarInt `$n==0` default path
    // advances the cursor by 0), so the inner loop is pure CPU + the push.
    // EXT_PER_ITEM is kept BELOW the budget so whole items merge and the
    // cumulative cap is observed crossing an item boundary.
    const ITEMS: u32 = u16::MAX as u32; // 65535 (max count for a ver<2 iloc)
    const EXT_PER_ITEM: u16 = 4;
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[0, 0, 0, 0]); // ver=0, flags=0
    iloc_body.extend_from_slice(&0x0000u16.to_be_bytes()); // siz: all nibbles 0
    iloc_body.extend_from_slice(&(ITEMS as u16).to_be_bytes()); // count (u16, ver<2)
    for id in 0..ITEMS {
      iloc_body.extend_from_slice(&(id as u16).to_be_bytes()); // id
      iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
      iloc_body.extend_from_slice(&EXT_PER_ITEM.to_be_bytes()); // ext_num
      // zero extent bytes (noff=nlen=0)
    }
    // Sanity: ~393 KB body declaring 262K extents — far past the budget.
    assert!(
      (390_000..400_000).contains(&iloc_body.len()),
      "the crafted iloc body is ~393 KB, got {}",
      iloc_body.len()
    );
    let declared = u64::from(ITEMS) * u64::from(EXT_PER_ITEM);
    assert_eq!(declared, 262_140, "262K declared extents");

    const BUDGET: u64 = 64;
    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    // Returns Ok promptly (the budget stops the walk) — no OOM, no hang.
    assert!(parse_iloc_capped(&iloc_body, &mut out, &mut id_index, BUDGET).is_ok());
    // The TOTAL extents materialized across every merged item is bounded by the
    // budget — proof the `num` × `ext_num` flood cannot allocate the declared
    // 262K (let alone the ~4.3 billion a full Get32u-count iloc could declare).
    let total_extents: u64 = out.items().iter().map(|it| it.extents().len() as u64).sum();
    assert!(
      total_extents <= BUDGET,
      "materialized {total_extents} extents, budget was {BUDGET}"
    );
    // EXT_PER_ITEM (4) divides BUDGET (64) exactly, so the walk stops on an
    // item boundary after 16 fully-merged items (16 × 4 == 64), proving the
    // cap accumulates ACROSS items rather than per-item.
    assert_eq!(
      total_extents, BUDGET,
      "the cap halts after exactly 64 extents"
    );
    assert_eq!(
      out.items().len(),
      (BUDGET / u64::from(EXT_PER_ITEM)) as usize,
      "16 items merged before the cumulative cap stopped the walk"
    );
  }

  /// #218 (R1 follow-up) — the extent budget must be CUMULATIVE across MANY
  /// `iloc` boxes, not reset per box. A per-box cap is defeatable: repeat
  /// several small zero-width `iloc` boxes whose DECLARED extents each sit
  /// just under the cap, so no single box trips it, yet the SUMMED retained
  /// extents would be O(num_boxes × cap) and still OOM. This proves the
  /// budget threaded through [`parse_iloc_remaining`] is shared: three boxes
  /// declaring 40 extents each (120 total) against a 64-extent budget retain
  /// EXACTLY 64 — the cap accumulates across the box boundary rather than
  /// granting each box a fresh 40.
  #[test]
  fn parse_iloc_cumulative_budget_spans_multiple_boxes() {
    // Build one ver-0 iloc body: `count` items, each with a single
    // zero-width extent (siz nibbles all 0 ⇒ noff=nlen=nbas=nind=0). Per
    // item: id(2) + dataRefIdx(2) + ext_num(2), then 0 extent bytes. Using
    // EXT_PER_ITEM == 1 makes any budget land on an item boundary, so a
    // partial (dropped) item never muddies the retained count.
    fn iloc_box(first_id: u32, count: u16) -> Vec<u8> {
      let mut b = Vec::new();
      b.extend_from_slice(&[0, 0, 0, 0]); // ver=0, flags=0
      b.extend_from_slice(&0x0000u16.to_be_bytes()); // siz: all nibbles 0
      b.extend_from_slice(&count.to_be_bytes()); // item count (u16, ver<2)
      for i in 0..count {
        let id = first_id + u32::from(i);
        b.extend_from_slice(&(id as u16).to_be_bytes()); // id
        b.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
        b.extend_from_slice(&1u16.to_be_bytes()); // ext_num = 1
        // zero extent bytes (noff=nlen=0)
      }
      b
    }

    const PER_BOX: u16 = 40;
    const BUDGET: u64 = 64;
    // DISJOINT id ranges per box so each box creates its own slots (no
    // last-wins merge collapsing the retained count).
    let box1 = iloc_box(100, PER_BOX);
    let box2 = iloc_box(1_000, PER_BOX);
    let box3 = iloc_box(10_000, PER_BOX);

    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    // The SAME `remaining` is threaded through all three calls — exactly what
    // `walk_heif_meta` does for the meta's iloc children.
    let mut remaining: u64 = BUDGET;
    assert!(parse_iloc_remaining(&box1, &mut out, &mut id_index, &mut remaining).is_ok());
    assert!(parse_iloc_remaining(&box2, &mut out, &mut id_index, &mut remaining).is_ok());
    assert!(parse_iloc_remaining(&box3, &mut out, &mut id_index, &mut remaining).is_ok());

    // 3 boxes × 40 = 120 declared, but the cumulative cap retains only 64.
    let total_extents: u64 = out.items().iter().map(|it| it.extents().len() as u64).sum();
    assert_eq!(
      total_extents, BUDGET,
      "the cumulative cap bounds the TOTAL across all 3 iloc boxes (got \
       {total_extents}, declared 120), proving the budget is not reset per box"
    );
    assert_eq!(remaining, 0, "the shared budget is fully consumed");
    // 64 items kept (40 from box1 + 24 from box2 before the cap halted the
    // walk on an item boundary); box3 contributed none.
    assert_eq!(
      out.items().len(),
      BUDGET as usize,
      "64 single-extent items retained across the box boundary, not 3×40"
    );

    // Integration: the SAME cumulative bound holds when `walk_heif_meta`
    // loops the meta's iloc children at the PRODUCTION ceiling. Many tiny
    // v2 iloc boxes, each declaring just under `MAX_ILOC_EXTENTS` worth of
    // zero-width extents across disjoint ids, declare FAR more than the cap
    // in total — but the retained extents stay bounded by the single shared
    // budget (no OOM, no hang).
    fn iloc_v2_box(first_id: u32, items: u32, ext_each: u16) -> Vec<u8> {
      let mut b = Vec::new();
      b.extend_from_slice(&[2, 0, 0, 0]); // ver=2, flags=0
      b.extend_from_slice(&0x0000u16.to_be_bytes()); // siz: all nibbles 0
      b.extend_from_slice(&items.to_be_bytes()); // count (u32, ver==2)
      for i in 0..items {
        b.extend_from_slice(&(first_id + i).to_be_bytes()); // id (u32, ver==2)
        b.extend_from_slice(&0u16.to_be_bytes()); // constMeth (ver 2)
        b.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
        b.extend_from_slice(&ext_each.to_be_bytes()); // ext_num
        // each declared extent: ext_index(nind=0) + offset(noff=0) +
        // length(nlen=0) → ZERO bytes consumed.
      }
      b
    }

    // 16 items × 65535 extents = 1_048_560 declared per box (just under the
    // 1<<20 == 1_048_576 cap), matching the finding's per-box magnitude.
    const ITEMS_PER_BOX: u32 = 16;
    const EXT_EACH: u16 = u16::MAX; // 65535
    const NUM_BOXES: u32 = 4;
    let declared_per_box = u64::from(ITEMS_PER_BOX) * u64::from(EXT_EACH);
    assert!(
      declared_per_box < MAX_ILOC_EXTENTS,
      "each box stays just under the per-box magnitude ({declared_per_box} < {MAX_ILOC_EXTENTS})"
    );
    let declared_total = declared_per_box * u64::from(NUM_BOXES);
    assert!(
      declared_total > MAX_ILOC_EXTENTS,
      "the summed declaration far exceeds the cap ({declared_total} > {MAX_ILOC_EXTENTS})"
    );

    let mut meta_body = Vec::new();
    meta_body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    for b in 0..NUM_BOXES {
      // Disjoint id windows so boxes never share slots.
      meta_body.extend(box_bytes(
        b"iloc",
        &iloc_v2_box(1 + b * 1_000_000, ITEMS_PER_BOX, EXT_EACH),
      ));
    }
    let mut m = HeifMeta::new();
    // Returns promptly (the shared budget halts the walk) — no OOM, no hang.
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&meta_body, 0, 4, &mut m, &mut iloc_budget);
    let walked_total: u64 = m.items().iter().map(|it| it.extents().len() as u64).sum();
    assert!(
      walked_total <= MAX_ILOC_EXTENTS,
      "walk_heif_meta retained {walked_total} extents across {NUM_BOXES} iloc boxes \
       (declared {declared_total}); the cumulative cap is {MAX_ILOC_EXTENTS}"
    );
    // The cap genuinely fired (one box alone nearly fills it; the rest push it
    // over), so the bound is the cumulative ceiling, not the trivially-small
    // declaration.
    assert!(
      walked_total > declared_per_box / 2,
      "the cap was exercised (retained {walked_total}), not a degenerate empty walk"
    );
  }

  /// #218 (R2 finding 1) — the extent budget must be CUMULATIVE across EVERY
  /// top-level `meta` box in the file, not reset per `meta`. The R1/R2 work
  /// hoisted the budget to be cumulative across the `iloc` children of ONE
  /// `meta`; this proves the SAME bound holds one container level up. A
  /// crafted file with MANY tiny `meta` boxes, each carrying a single
  /// just-under-cap zero-width `iloc` over disjoint ids, declares FAR more
  /// than `MAX_ILOC_EXTENTS` in total — but the file-scope budget owned by
  /// `scan_quicktime_brands` (threaded into every `walk_heif_meta`) bounds the
  /// TOTAL retained extents to ONE ceiling, not N times it.
  #[test]
  fn iloc_budget_cumulative_across_meta_boxes() {
    // One ver-2 zero-width iloc body (siz nibbles all 0 → no extent bytes),
    // `items` ids each declaring `ext_each` empty extents. The same shape the
    // cumulative-across-iloc test uses, here split one-per-`meta`.
    fn iloc_v2_zero_width(first_id: u32, items: u32, ext_each: u16) -> Vec<u8> {
      let mut b = Vec::new();
      b.extend_from_slice(&[2, 0, 0, 0]); // ver=2, flags=0
      b.extend_from_slice(&0x0000u16.to_be_bytes()); // siz: all nibbles 0
      b.extend_from_slice(&items.to_be_bytes()); // count (u32, ver==2)
      for i in 0..items {
        b.extend_from_slice(&(first_id + i).to_be_bytes()); // id (u32)
        b.extend_from_slice(&0u16.to_be_bytes()); // constMeth (ver 2)
        b.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
        b.extend_from_slice(&ext_each.to_be_bytes()); // ext_num
        // ext_index(nind=0)+offset(noff=0)+length(nlen=0) → ZERO bytes each.
      }
      b
    }

    // One top-level `meta` box body: [version+flags][iloc box].
    fn meta_box(iloc_body: &[u8]) -> Vec<u8> {
      let mut meta = Vec::new();
      meta.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
      meta.extend(box_bytes(b"iloc", iloc_body));
      box_bytes(b"meta", &meta)
    }

    // 16 items × 65535 extents = 1_048_560 declared per meta box (just under
    // the 1<<20 == 1_048_576 cap), so NO single meta trips the ceiling.
    const ITEMS_PER_META: u32 = 16;
    const EXT_EACH: u16 = u16::MAX; // 65535
    const NUM_META: u32 = 4;
    let declared_per_meta = u64::from(ITEMS_PER_META) * u64::from(EXT_EACH);
    assert!(
      declared_per_meta < MAX_ILOC_EXTENTS,
      "each meta's lone iloc stays just under the per-box cap \
       ({declared_per_meta} < {MAX_ILOC_EXTENTS})"
    );
    let declared_total = declared_per_meta * u64::from(NUM_META);
    assert!(
      declared_total > MAX_ILOC_EXTENTS,
      "the SUMMED declaration across all meta boxes far exceeds one ceiling \
       ({declared_total} > {MAX_ILOC_EXTENTS})"
    );

    // A file = several top-level `meta` boxes, each over a DISJOINT id window
    // so no last-wins merge collapses the retained count.
    let mut file = Vec::new();
    for m in 0..NUM_META {
      file.extend(meta_box(&iloc_v2_zero_width(
        1 + m * 1_000_000,
        ITEMS_PER_META,
        EXT_EACH,
      )));
    }

    let mut heif = HeifMeta::new();
    // `scan_heif_meta` is the file-scope entry (`scan_quicktime_brands` over
    // `%Main`): it seeds ONE budget and threads it through every `meta`'s
    // `walk_heif_meta`. Returns promptly (the shared budget halts the walk) —
    // no OOM, no hang — even though the declaration is multi-meta.
    scan_heif_meta(&file, &mut heif);

    let walked_total: u64 = heif
      .items()
      .iter()
      .map(|it| it.extents().len() as u64)
      .sum();
    assert!(
      walked_total <= MAX_ILOC_EXTENTS,
      "the file-scope budget bounds the TOTAL retained extents across all \
       {NUM_META} meta boxes to ONE ceiling (retained {walked_total}, declared \
       {declared_total}, cap {MAX_ILOC_EXTENTS}) — NOT {NUM_META}× the cap"
    );
    // The cap genuinely fired (one meta nearly fills it; the rest push it over
    // a SINGLE ceiling), so the bound is the cumulative file-scope ceiling, not
    // a trivially-small declaration nor a per-meta reset.
    assert!(
      walked_total > declared_per_meta / 2,
      "the cap was exercised across meta boxes (retained {walked_total}), not a \
       degenerate empty walk"
    );
  }

  /// #218 (R2 finding 2) — a post-cap iloc ROW must be a COMPLETE no-op, even
  /// when it declares ZERO extents. The per-extent guard lives INSIDE the
  /// extent loop, so an `ext_num == 0` row skips it and would otherwise reach
  /// the unconditional slot writeback, OVERWRITING an already-retained item's
  /// base offset + extents with an empty vector once the budget has drained.
  /// The row-level guard at the top of the `num` loop refuses every post-cap
  /// row, so a later zero-extent iloc reusing a retained id leaves it intact.
  #[test]
  fn parse_iloc_post_cap_zero_extent_row_does_not_overwrite() {
    // Box A (ver 0): id 7 with a non-zero BaseOffset (nbas=4) and 2 zero-width
    // extents (noff=nlen=0). siz nibbles: noff=0, nlen=0, nbas=4, nind=0 ⇒
    // 0x0040. Per item: id(2) + dataRefIdx(2) + base(4) + ext_num(2), then 0
    // extent bytes. The 2 extents EXACTLY drain a budget of 2.
    // `HeifItem::base_offset` is a u64; a 4-byte (nbas=4) BaseOffset reads as
    // its low 32 bits.
    const BASE: u64 = 0xDEAD_BEEF;
    let mut box_a = Vec::new();
    box_a.extend_from_slice(&[0, 0, 0, 0]); // ver=0, flags=0
    box_a.extend_from_slice(&0x0040u16.to_be_bytes()); // siz: nbas=4 nibble
    box_a.extend_from_slice(&1u16.to_be_bytes()); // count = 1 item
    box_a.extend_from_slice(&7u16.to_be_bytes()); // id = 7
    box_a.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    box_a.extend_from_slice(&(BASE as u32).to_be_bytes()); // BaseOffset (nbas=4)
    box_a.extend_from_slice(&2u16.to_be_bytes()); // ext_num = 2
    // 2 zero-width extents → ZERO bytes consumed.

    // Box B (ver 0): id 7 again with ext_num == 0 and a DIFFERENT declared
    // BaseOffset. This is the post-cap row that must NOT touch the slot.
    let mut box_b = Vec::new();
    box_b.extend_from_slice(&[0, 0, 0, 0]); // ver=0, flags=0
    box_b.extend_from_slice(&0x0040u16.to_be_bytes()); // siz: nbas=4 nibble
    box_b.extend_from_slice(&1u16.to_be_bytes()); // count = 1 item
    box_b.extend_from_slice(&7u16.to_be_bytes()); // id = 7 (SAME id)
    box_b.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    box_b.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // would-be base
    box_b.extend_from_slice(&0u16.to_be_bytes()); // ext_num = 0

    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    // Shared budget of exactly 2 — box A consumes it fully.
    let mut remaining: u64 = 2;
    assert!(parse_iloc_remaining(&box_a, &mut out, &mut id_index, &mut remaining).is_ok());
    assert_eq!(remaining, 0, "box A drained the shared budget to 0");
    assert_eq!(out.items().len(), 1, "id 7 was retained by box A");
    assert_eq!(out.items()[0].extents().len(), 2, "id 7 kept its 2 extents");
    assert_eq!(out.items()[0].base_offset(), BASE, "id 7 kept box A's base");

    // Box B's zero-extent row arrives with the budget already at 0. The
    // row-level guard fires BEFORE the slot writeback, so id 7 is untouched —
    // its base and extents survive (the post-ceiling tail stays unobservable).
    assert!(parse_iloc_remaining(&box_b, &mut out, &mut id_index, &mut remaining).is_ok());
    assert_eq!(remaining, 0, "the budget stays exhausted");
    assert_eq!(
      out.items().len(),
      1,
      "no new slot was created by the no-op row"
    );
    assert_eq!(
      out.items()[0].extents().len(),
      2,
      "the post-cap zero-extent row did NOT erase id 7's retained extents"
    );
    assert_eq!(
      out.items()[0].base_offset(),
      BASE,
      "the post-cap zero-extent row did NOT overwrite id 7's base offset"
    );
  }

  #[test]
  fn walk_heif_meta_records_idat() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend(box_bytes(b"idat", &[0xAA, 0xBB, 0xCC]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    // Normal (8-byte header) box: idat starts at body[4], its 8-byte
    // header ends at body[12], so the payload offset is 12 and the length
    // is exactly the 3 payload bytes (REGRESSION guard for the
    // `body_abs_start` rework — must equal the old `abs_start + 8`).
    assert_eq!(m.idat_offset(), Some(12));
    assert_eq!(m.idat_length(), Some(3));
  }

  /// Build a `size == 1` largesize box: [1:u32][tag:4][realsize:u64][body].
  /// The real header is 16 bytes; `realsize` is the FULL box length
  /// (16 + body).
  fn largesize_box_bytes(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let real_size = 16u64 + body.len() as u64;
    let mut out = Vec::with_capacity(real_size as usize);
    out.extend_from_slice(&1u32.to_be_bytes()); // size == 1 → largesize
    out.extend_from_slice(tag);
    out.extend_from_slice(&real_size.to_be_bytes()); // 64-bit real size
    out.extend_from_slice(body);
    out
  }

  #[test]
  fn walk_heif_meta_records_largesize_idat() {
    // A largesize-encoded `idat` (size field == 1, real size in the 64-bit
    // field, 16-byte header). The body offset must skip ALL 16 header bytes
    // (NOT the hard-coded 8), and the length must be the true payload.
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    body.extend(largesize_box_bytes(b"idat", &[0xAA, 0xBB, 0xCC, 0xDD]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    // idat box starts at body[4]; its 16-byte largesize header ends at
    // body[20], so the payload begins at absolute offset 20 (a plain
    // `abs_start + 8` would WRONGLY report 12 and read 8 header bytes as
    // payload). Length is the exact 4-byte payload.
    assert_eq!(
      m.idat_offset(),
      Some(20),
      "largesize body must start past the full 16-byte header"
    );
    assert_eq!(m.idat_length(), Some(4));
  }

  #[test]
  fn walk_boxes_largesize_body_abs_start_and_len() {
    // Direct walk-level check: a largesize box's `body_abs_start` skips a
    // full 16-byte header, its `body` slice is exactly the payload, and the
    // caller's `abs_offset` is folded through. Also confirm a NORMAL box in
    // the same buffer reports an 8-byte header (regression — the two header
    // lengths must diverge correctly).
    let mut data = Vec::new();
    data.extend(box_bytes(b"norm", &[1, 2, 3])); // 8-byte header, 3 payload
    let large_start = data.len();
    data.extend(largesize_box_bytes(b"larg", &[9, 9, 9, 9, 9])); // 16-byte header
    let abs_base = 1000u64;
    let mut seen: Vec<(Vec<u8>, u64, usize)> = Vec::new();
    walk_boxes(&data, abs_base, Size0Behavior::Stop, |h| {
      seen.push((h.tag.to_vec(), h.body_abs_start, h.body.len()));
    });
    assert_eq!(seen.len(), 2, "both boxes walked");
    // Normal box at file offset `abs_base`: body starts 8 bytes in.
    assert_eq!(seen[0].0, b"norm");
    assert_eq!(seen[0].1, abs_base + 8, "normal header is 8 bytes");
    assert_eq!(seen[0].2, 3);
    // Largesize box at `abs_base + large_start`: body starts 16 bytes in.
    assert_eq!(seen[1].0, b"larg");
    assert_eq!(
      seen[1].1,
      abs_base + large_start as u64 + 16,
      "largesize header is 16 bytes"
    );
    assert_eq!(seen[1].2, 5, "body slice is the exact payload");
  }

  #[test]
  fn scan_heif_meta_finds_top_level() {
    let mut meta_body = Vec::new();
    meta_body.extend_from_slice(&[0, 0, 0, 0]);
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&5u16.to_be_bytes());
    meta_body.extend(box_bytes(b"pitm", &pitm_body));
    let blob = box_bytes(b"meta", &meta_body);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(m.primary_item(), Some(5));
  }

  /// Wrap `inner` in `levels` nested `moov` boxes (innermost first), so the
  /// outermost box is `levels` containers deep.
  fn nest_in_moov(inner: Vec<u8>, levels: usize) -> Vec<u8> {
    let mut acc = inner;
    for _ in 0..levels {
      acc = box_bytes(b"moov", &acc);
    }
    acc
  }

  #[test]
  fn scan_canon_uuid_deep_nesting_stops_cleanly() {
    // The Canon-UUID scanner recurses into `moov`. A file nesting `moov`
    // far past MAX_ATOM_DEPTH must STOP at the budget — no stack overflow /
    // process abort — and (because the real Canon UUID is buried below the
    // cap) contribute no CR3 override.
    let levels = (MAX_ATOM_DEPTH as usize) + 50;
    // Innermost payload: a Canon uuid atom with a CMT1 child. If the guard
    // were absent the scanner would descend all `levels` and find it; with
    // the guard it never reaches this depth.
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend(box_bytes(b"CMT1", &[0x42; 4]));
    let innermost = box_bytes(b"uuid", &uuid_body);
    let blob = nest_in_moov(innermost, levels);
    let mut m = Cr3Meta::new();
    // Must return cleanly (no panic / overflow). The buried UUID is past the
    // depth cap, so it is NOT found and no CR3 block is recorded.
    let found = scan_canon_uuid(&blob, &mut m);
    assert!(
      !found,
      "UUID buried past MAX_ATOM_DEPTH must not be reached"
    );
    assert!(m.cmt1().is_none());
  }

  #[test]
  fn scan_heif_meta_deep_nesting_stops_cleanly() {
    // The HEIF scanner recurses into `moov`. A `meta` buried under a `moov`
    // chain far past MAX_ATOM_DEPTH must trigger a CLEAN stop at the budget
    // (no stack overflow); the buried `meta` is never reached.
    let levels = (MAX_ATOM_DEPTH as usize) + 50;
    let mut meta_body = Vec::new();
    meta_body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&7u16.to_be_bytes());
    meta_body.extend(box_bytes(b"pitm", &pitm_body));
    let innermost = box_bytes(b"meta", &meta_body);
    let blob = nest_in_moov(innermost, levels);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m); // must not overflow
    assert_eq!(
      m.primary_item(),
      None,
      "meta buried past MAX_ATOM_DEPTH must not be reached"
    );
  }

  #[test]
  fn scan_heif_meta_finds_moov_meta_at_offset_0() {
    // R18-F2: a `moov/meta` is the `%QuickTime::Movie` entry, which has NO
    // `Start` (QuickTime.pm:1218-1221) — its children begin at offset 0, NOT
    // the FullBox offset 4 that the top-level `%Main` `meta` uses
    // (`Start => 4`, QuickTime.pm:552-556). The SAME `QuickTime::Meta` table
    // carries `pitm`/`iinf`/`iloc` in both positions, so a `moov/meta` IS
    // parsed — at offset 0. The body therefore starts with the `pitm` box
    // IMMEDIATELY (no 4-byte version/flags prefix); the scanner must find it.
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&9u16.to_be_bytes());
    // moov/meta body: children begin at offset 0 (no FullBox header).
    let meta_body = box_bytes(b"pitm", &pitm_body);
    let blob = nest_in_moov(box_bytes(b"meta", &meta_body), 1);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.primary_item(),
      Some(9),
      "moov/meta children parse at offset 0 (no FullBox skip)"
    );
  }

  #[test]
  fn scan_heif_moov_meta_iinf_parsed_at_offset_0_not_shifted() {
    // R18-F2 (the explicit finding): a `moov{ meta{ iinf … } }`. With the old
    // hard-coded 4-byte skip the scanner shifted the moov/meta children by 4
    // bytes (reading mid-`iinf` garbage). Faithfully, `moov/meta` has no Start
    // → the `iinf` is at offset 0 and its single item parses correctly. The
    // body is the iinf box with NO leading 4-byte FullBox header.
    let iinf = iinf_v0(&[infe_v0(7, b"hvc1item", b"image/heic")]);
    let meta_body = box_bytes(b"iinf", &iinf);
    let blob = nest_in_moov(box_bytes(b"meta", &meta_body), 1);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    // Exactly one item, parsed at the correct (offset-0) alignment.
    assert_eq!(m.items().len(), 1, "moov/meta iinf parses at offset 0");
    assert_eq!(m.items()[0].id(), 7);
    assert_eq!(m.items()[0].name(), Some("hvc1item"));
    assert_eq!(m.items()[0].content_type(), Some("image/heic"));
    // The same body fed as a TOP-LEVEL meta (Start => 4) is what the FullBox
    // prefix is for; here there is none, so a top-level (offset-4) parse of
    // this same body would NOT find the item — proving the offset matters.
    let mut top = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&meta_body, 0, 4, &mut top, &mut iloc_budget);
    assert!(
      top.items().is_empty(),
      "the same body parsed at offset 4 (top-level) finds nothing — offset 0 is required for moov/meta"
    );
  }

  /// A `pitm` v0 box body carrying primary-item id `id` (4-byte verflags +
  /// 2-byte id). The id is observable via `HeifMeta::primary_item()`, so it
  /// is the cheapest probe for "did the meta parse at the right offset?".
  fn pitm_v0_box(id: u16) -> Vec<u8> {
    let mut pitm_body = Vec::new();
    pitm_body.extend_from_slice(&[0, 0, 0, 0]);
    pitm_body.extend_from_slice(&id.to_be_bytes());
    box_bytes(b"pitm", &pitm_body)
  }

  /// A FullBox `meta` body (4-byte version/flags prefix, then `child`) — the
  /// `Start => 4` shape used by `%Main` and `%UserData`.
  fn fullbox_meta(child: &[u8]) -> Vec<u8> {
    let mut meta_body = Vec::new();
    meta_body.extend_from_slice(&[0, 0, 0, 0]);
    meta_body.extend_from_slice(child);
    box_bytes(b"meta", &meta_body)
  }

  /// A non-FullBox `meta` body (children begin at offset 0) — the no-`Start`
  /// shape used by `%Movie`/`%Track`/`%MovieFragment`/`%TrackFragment`.
  fn plain_meta(child: &[u8]) -> Vec<u8> {
    box_bytes(b"meta", child)
  }

  #[test]
  fn top_level_meta_at_offset_4() {
    // `%QuickTime::Main` `meta` is a FullBox (`Start => 4`,
    // QuickTime.pm:556): children begin after the 4-byte version/flags.
    let blob = fullbox_meta(&pitm_v0_box(5));
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.primary_item(),
      Some(5),
      "top-level meta parses at offset 4"
    );
  }

  #[test]
  fn moov_meta_at_offset_0() {
    // `%Movie` `meta` has no `Start` (QuickTime.pm:1218): children at
    // offset 0 (the body starts with the `pitm` box immediately).
    let blob = box_bytes(b"moov", &plain_meta(&pitm_v0_box(7)));
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(m.primary_item(), Some(7), "moov/meta parses at offset 0");
  }

  #[test]
  fn moov_trak_meta_iinf_parsed_at_offset_0() {
    // R19: `moov{ trak{ meta{ pitm/iinf } } }`. The `meta` is reached through
    // the Movie→Track recursion edge (QuickTime.pm:1211); `%Track`'s `meta`
    // has no `Start` (QuickTime.pm:1440), so the HEIF items parse at offset 0.
    // The pre-refactor flat scanner only descended `moov` (never `trak`), so
    // this `meta` was MISSED entirely; now it is parsed.
    let mut meta_children = pitm_v0_box(9);
    meta_children.extend(box_bytes(
      b"iinf",
      &iinf_v0(&[infe_v0(9, b"hvc1item", b"image/heic")]),
    ));
    let trak = box_bytes(b"trak", &plain_meta(&meta_children));
    let blob = box_bytes(b"moov", &trak);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.primary_item(),
      Some(9),
      "moov/trak/meta pitm parses (reached via Movie→Track)"
    );
    assert_eq!(m.items().len(), 1, "moov/trak/meta iinf parses at offset 0");
    assert_eq!(m.items()[0].id(), 9);
    assert_eq!(m.items()[0].name(), Some("hvc1item"));
    assert_eq!(m.items()[0].content_type(), Some("image/heic"));
  }

  #[test]
  fn udta_meta_at_offset_4() {
    // `moov{ udta{ meta{ pitm } } }`. `udta` is reached via Movie→UserData
    // (QuickTime.pm:1214); `%UserData`'s `meta` IS a FullBox (`Start => 4`,
    // QuickTime.pm:1691) — so its children begin at offset 4 (unlike the
    // sibling moov/meta at offset 0). A FullBox-shaped meta body is required.
    let udta = box_bytes(b"udta", &fullbox_meta(&pitm_v0_box(11)));
    let blob = box_bytes(b"moov", &udta);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.primary_item(),
      Some(11),
      "moov/udta/meta parses at offset 4 (UserData FullBox)"
    );
  }

  #[test]
  fn moof_traf_meta_at_offset_0() {
    // `moof{ traf{ meta{ pitm } } }`. Reached via Main→MovieFragment
    // (QuickTime.pm:682) then MovieFragment→TrackFragment (QuickTime.pm:1303);
    // `%TrackFragment`'s `meta` has no `Start` (QuickTime.pm:1324) → offset 0.
    let traf = box_bytes(b"traf", &plain_meta(&pitm_v0_box(13)));
    let blob = box_bytes(b"moof", &traf);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.primary_item(),
      Some(13),
      "moof/traf/meta parses at offset 0"
    );
  }

  #[test]
  fn canon_uuid_only_in_moov() {
    // The Canon `uuid` is dispatched ONLY from `%Movie` (QuickTime.pm:1239).
    // The SAME uuid bytes:
    //  - at the file root (`%Main`) → NOT dispatched (no CR3 block),
    //  - under `trak` (`%Track`) → NOT dispatched,
    //  - under `moov` (`%Movie`) → dispatched (CR3 block recorded).
    let mut uuid_body = Vec::new();
    uuid_body.extend_from_slice(&CANON_UUID);
    uuid_body.extend(box_bytes(b"CMT1", &[0x42; 4]));
    let uuid = box_bytes(b"uuid", &uuid_body);

    // Top-level: not in %Main → ignored.
    let mut top = Cr3Meta::new();
    assert!(
      !scan_canon_uuid(&uuid, &mut top),
      "top-level Canon uuid not in %Main"
    );
    assert!(top.cmt1().is_none());

    // Under trak (Movie→Track): %Track has no Canon uuid → ignored.
    let trak_blob = box_bytes(b"moov", &box_bytes(b"trak", &uuid));
    let mut tr = Cr3Meta::new();
    assert!(
      !scan_canon_uuid(&trak_blob, &mut tr),
      "a trak-level Canon uuid is %Track-scoped → not dispatched"
    );
    assert!(tr.cmt1().is_none());

    // Under moov (%Movie): dispatched.
    let moov_blob = box_bytes(b"moov", &uuid);
    let mut mv = Cr3Meta::new();
    assert!(
      scan_canon_uuid(&moov_blob, &mut mv),
      "moov-level Canon uuid is %Movie-scoped"
    );
    assert_eq!(mv.cmt1().unwrap().length(), 4);
  }

  /// Build a v0/v1 `infe` body for `(id, name, content_type)`. Both strings
  /// are written as NUL-terminated; a v0/v1 entry carries NO `Type`.
  fn infe_v0(id: u16, name: &[u8], content_type: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0, 0, 0]); // version 0 + flags
    b.extend_from_slice(&id.to_be_bytes()); // 2-byte id
    b.extend_from_slice(&[0, 0]); // 2-byte ProtectionIndex
    b.extend_from_slice(name);
    b.push(0); // Name NUL
    b.extend_from_slice(content_type);
    b.push(0); // ContentType NUL
    b.push(0); // ContentEncoding (empty) NUL
    b
  }

  /// Wrap a list of `infe` bodies in an `iinf` (v0) body.
  fn iinf_v0(infes: &[Vec<u8>]) -> Vec<u8> {
    let mut iinf = Vec::new();
    iinf.extend_from_slice(&[0, 0, 0, 0]); // iinf version 0 + flags
    iinf.extend_from_slice(&(infes.len() as u16).to_be_bytes()); // count
    for infe in infes {
      iinf.extend(box_bytes(b"infe", infe));
    }
    iinf
  }

  /// Wrap an `iinf` body in a top-level `meta` box.
  fn meta_with_iinf(iinf_body: &[u8]) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    meta.extend(box_bytes(b"iinf", iinf_body));
    box_bytes(b"meta", &meta)
  }

  #[test]
  fn scan_heif_two_meta_boxes_same_id_overwrites_one_slot() {
    // F1 regression: ExifTool keeps ONE `$$et{ItemInfo}` hash for the whole
    // file walk, so a second `meta` box reusing an item id resolves to the
    // SAME per-id slot and OVERWRITES (last-wins) — it must NOT append a
    // duplicate. exifast threads the keyed index across `meta` boxes by
    // seeding `walk_heif_meta`'s index from the items already collected.
    let first = meta_with_iinf(&iinf_v0(&[infe_v0(1, b"first", b"image/heic")]));
    let second = meta_with_iinf(&iinf_v0(&[infe_v0(1, b"second", b"image/avif")]));
    let mut blob = first;
    blob.extend(second);

    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    assert_eq!(
      m.items().len(),
      1,
      "same id across two meta boxes = one slot"
    );
    let it = &m.items()[0];
    assert_eq!(it.id(), 1);
    assert_eq!(it.name(), Some("second"), "second meta box Name wins");
    assert_eq!(
      it.content_type(),
      Some("image/avif"),
      "second meta box ContentType wins"
    );
  }

  #[test]
  fn iinf_out_of_order_item_ids_emits_warning() {
    // R11: ExifTool's ParseItemInfoEntry warns when item-info entries are not
    // in strictly-ascending id order (QuickTime.pm:9275-9279). Ids 2 then 1
    // (descending) must raise the warning — and BOTH items still merge (the
    // check runs after field assignment).
    let meta = meta_with_iinf(&iinf_v0(&[
      infe_v0(2, b"a", b"image/heic"),
      infe_v0(1, b"b", b"image/heic"),
    ]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&meta, &mut m);
    assert_eq!(m.warning(), Some("Item info entries are out of order"));
    assert_eq!(m.items().len(), 2, "out-of-order items are still merged");
  }

  #[test]
  fn iinf_ascending_item_ids_no_warning() {
    // Strictly-ascending ids (1 then 2) → no out-of-order warning.
    let meta = meta_with_iinf(&iinf_v0(&[
      infe_v0(1, b"a", b"image/heic"),
      infe_v0(2, b"b", b"image/heic"),
    ]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&meta, &mut m);
    assert_eq!(m.warning(), None);
    assert_eq!(m.items().len(), 2);
  }

  #[test]
  fn iinf_first_item_id_zero_no_warning() {
    // R12-F2: ExifTool resets `LastItemID = -1` at the start of each iinf
    // (QuickTime.pm:2846), so the FIRST entry (any id, including 0) satisfies
    // `$id > $lastID` and never warns. Modeling the sentinel as `Option<u32>`
    // makes a lone id-0 infe produce NO warning (the old `0`-init counter
    // wrongly flagged `0 <= 0`).
    let meta = meta_with_iinf(&iinf_v0(&[infe_v0(0, b"a", b"image/heic")]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&meta, &mut m);
    assert_eq!(m.warning(), None, "a first item with id 0 must not warn");
    assert_eq!(m.items().len(), 1);
  }

  #[test]
  fn iinf_duplicate_id_zero_warns() {
    // R12-F2: two infe entries both with id 0 → the SECOND `0 <= 0` triggers
    // the out-of-order warning (a non-ascending repeat), and both still merge.
    let meta = meta_with_iinf(&iinf_v0(&[
      infe_v0(0, b"a", b"image/heic"),
      infe_v0(0, b"b", b"image/heic"),
    ]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&meta, &mut m);
    assert_eq!(
      m.warning(),
      Some("Item info entries are out of order"),
      "a duplicate id 0 (second 0 <= first 0) warns"
    );
    assert_eq!(m.items().len(), 1, "same id = one slot");
  }

  /// Build an `ipma` (v0) body: [version=0|flags:3][num:u32] then, per entry,
  /// [id:u16][assoc_count:u8][assoc bytes…]. `low_flag` sets the flags low
  /// bit (2-byte associations when set, else 1-byte). Each entry's
  /// association bytes are `assoc_count` × (2 or 1) zero bytes — the VALUES
  /// are #146; only their LENGTH advance is exercised.
  fn ipma_v0(low_flag: bool, entries: &[(u16, u8)]) -> Vec<u8> {
    let mut b = Vec::new();
    let flags_lo = if low_flag { 1u8 } else { 0u8 };
    b.extend_from_slice(&[0, 0, 0, flags_lo]); // version 0 + 24-bit flags
    b.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for &(id, n) in entries {
      b.extend_from_slice(&id.to_be_bytes());
      b.push(n);
      let assoc_len = usize::from(n) * if low_flag { 2 } else { 1 };
      b.resize(b.len() + assoc_len, 0u8);
    }
    b
  }

  /// Wrap an `ipma` body in an `iprp` container, then a `meta` BODY (the
  /// shape `walk_heif_meta` consumes directly).
  fn meta_with_iprp_ipma(ipma_body: &[u8]) -> Vec<u8> {
    let iprp = box_bytes(b"ipma", ipma_body);
    let mut meta = Vec::new();
    meta.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    meta.extend(box_bytes(b"iprp", &iprp));
    meta
  }

  #[test]
  fn ipma_out_of_order_emits_warning() {
    // R12-F1: ParseItemPropAssoc (QuickTime.pm:9334) warns when ipma entries
    // are not in ascending item-id order — the sibling of the iinf warning.
    // Ids 2 then 1 (descending) → the warning. The port reaches ipma by
    // descending into the iprp container.
    let body = meta_with_iprp_ipma(&ipma_v0(false, &[(2, 0), (1, 0)]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(
      m.warning(),
      Some("Item property association entries are out of order")
    );
  }

  #[test]
  fn ipma_ascending_no_warning() {
    // Ascending ids (1 then 2) → no out-of-order warning.
    let body = meta_with_iprp_ipma(&ipma_v0(false, &[(1, 0), (2, 0)]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.warning(), None);
  }

  #[test]
  fn ipma_v0_flags_assoc_sizes() {
    // R12-F1: when the flags low bit is set each association is 2 bytes
    // (QuickTime.pm:9313-9320). Two ascending entries each with 1 association
    // (2 bytes) must parse WITHOUT a false truncation `return` — so no
    // warning, and the second entry's id is reached (ascending → none).
    let body = meta_with_iprp_ipma(&ipma_v0(true, &[(1, 1), (2, 1)]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(
      m.warning(),
      None,
      "2-byte associations must advance correctly (no false truncation)"
    );
    // A descending pair with the same 2-byte associations still warns — proves
    // the cursor landed on the real second id, not mid-association.
    let body2 = meta_with_iprp_ipma(&ipma_v0(true, &[(5, 1), (3, 1)]));
    let mut m2 = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body2, 0, 4, &mut m2, &mut iloc_budget);
    assert_eq!(
      m2.warning(),
      Some("Item property association entries are out of order")
    );
  }

  #[test]
  fn walk_heif_standalone_seeds_index_from_existing_items() {
    // The standalone `walk_heif_meta(body, off, out)` entry point still
    // works on a pre-populated `HeifMeta`: it SEEDS its keyed index from
    // `out.items()` so a `meta` body reusing an id already present
    // overwrites that slot rather than appending a duplicate.
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(
      &meta_inner(&iinf_v0(&[infe_v0(2, b"orig", b"image/heic")])),
      0,
      4,
      &mut m,
      &mut iloc_budget,
    );
    assert_eq!(m.items().len(), 1);
    // Second standalone call into the SAME HeifMeta, same id 2.
    walk_heif_meta(
      &meta_inner(&iinf_v0(&[infe_v0(2, b"updated", b"image/avif")])),
      0,
      4,
      &mut m,
      &mut iloc_budget,
    );
    assert_eq!(m.items().len(), 1, "reused id overwrites the seeded slot");
    assert_eq!(m.items()[0].name(), Some("updated"));
    assert_eq!(m.items()[0].content_type(), Some("image/avif"));
  }

  /// Build a `meta` BODY (version+flags + an `iinf`) — i.e. what
  /// `walk_heif_meta` takes directly (NOT wrapped in a `meta` box header).
  fn meta_inner(iinf_body: &[u8]) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    meta.extend(box_bytes(b"iinf", iinf_body));
    meta
  }

  #[test]
  fn infe_duplicate_empty_name_clears_prior() {
    // F2: a v0 `GetString` returns `''` (a real value), assigned
    // unconditionally (QuickTime.pm:9244). So a second infe for the same id
    // with an EMPTY Name assigns `Some("")` and CLEARS the first's Name —
    // it does NOT keep the prior non-empty value.
    let body = meta_inner(&iinf_v0(&[
      infe_v0(1, b"hello", b""),
      infe_v0(1, b"", b""), // empty Name → clears
    ]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1);
    assert_eq!(
      m.items()[0].name(),
      Some(""),
      "empty Name in the second infe CLEARS the first's"
    );
  }

  #[test]
  fn infe_v2_exif_after_mime_keeps_prior_content_type() {
    // F2: a v2/3 entry whose type is NOT 'mime'/'uri ' (e.g. 'Exif')
    // assigns NEITHER ContentType nor URI (QuickTime.pm:9261-9266 — the
    // else branch is empty). So after a prior mime infe set ContentType,
    // a later 'Exif' infe for the SAME id must LEAVE ContentType intact
    // (the merge keeps prior because content_type stays `None`).
    let mut mime = Vec::new();
    mime.extend_from_slice(&[2, 0, 0, 0]);
    mime.extend_from_slice(&5u16.to_be_bytes());
    mime.extend_from_slice(&[0, 0]);
    mime.extend_from_slice(b"mime");
    mime.extend_from_slice(b"\0"); // empty name
    mime.extend_from_slice(b"application/rdf+xml\0"); // ContentType
    let body = meta_inner(&iinf_v0(&[mime, infe_v2(5, b"Exif", b"exif")]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1);
    let it = &m.items()[0];
    assert_eq!(it.item_type(), Some("Exif"), "later Exif Type wins");
    assert_eq!(
      it.content_type(),
      Some("application/rdf+xml"),
      "non-mime else branch must NOT clobber the prior ContentType"
    );
  }

  #[test]
  fn infe_later_empty_mime_content_type_clears_prior() {
    // F2: a later `mime` infe whose ContentType string is EMPTY assigns
    // `Some("")` (QuickTime.pm:9262 `GetString` → '') and CLEARS the prior
    // `application/rdf+xml` — last-wins, empty included.
    let mut first = Vec::new();
    first.extend_from_slice(&[2, 0, 0, 0]);
    first.extend_from_slice(&9u16.to_be_bytes());
    first.extend_from_slice(&[0, 0]);
    first.extend_from_slice(b"mime");
    first.extend_from_slice(b"\0"); // empty name
    first.extend_from_slice(b"application/rdf+xml\0");
    let mut second = Vec::new();
    second.extend_from_slice(&[2, 0, 0, 0]);
    second.extend_from_slice(&9u16.to_be_bytes());
    second.extend_from_slice(&[0, 0]);
    second.extend_from_slice(b"mime");
    second.extend_from_slice(b"\0"); // empty name
    second.extend_from_slice(b"\0"); // EMPTY ContentType → clears
    let body = meta_inner(&iinf_v0(&[first, second]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1);
    assert_eq!(
      m.items()[0].content_type(),
      Some(""),
      "empty mime ContentType CLEARS application/rdf+xml"
    );
  }

  #[test]
  fn infe_v0_then_v2_type_only_from_v2() {
    // F2 corollary: a v0/v1 infe carries NO Type (it never enters the v2/3
    // branch, QuickTime.pm:9240-9246), so `item_type` stays `None` and the
    // merge KEEPS any prior Type. Here a v2 'hvc1' Type is set, then a v0
    // entry for the same id (Name only) must NOT null the Type.
    let body = meta_inner(&iinf_v0(&[
      infe_v2(3, b"hvc1", b"img"),
      infe_v0(3, b"renamed", b""),
    ]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1);
    let it = &m.items()[0];
    assert_eq!(
      it.item_type(),
      Some("hvc1"),
      "v0 entry must not null the v2 Type"
    );
    assert_eq!(it.name(), Some("renamed"), "v0 Name still overwrites");
  }

  /// Build an `infe` body for a version >= 4 (the undef-id case). Layout
  /// mirrors the v2/3/4+ else-branch with NO id field (`$pos` stays 4):
  /// version/flags(4) + ProtectionIndex(2) + 4-byte Type + Name + NUL.
  fn infe_v4(item_type: &[u8; 4], name: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[4, 0, 0, 0]); // version 4 + flags
    b.extend_from_slice(&[0, 0]); // ProtectionIndex (read at pos=4)
    b.extend_from_slice(item_type); // 4-byte ItemType (pos 6..10)
    b.extend_from_slice(name); // Name string
    b.push(0); // NUL terminator
    b
  }

  #[test]
  fn parse_infe_v4_unknown_version_creates_item() {
    // R14-F1: ExifTool's `else` branch (QuickTime.pm:9247) runs for ALL
    // versions >= 2. For v4+ NEITHER the `ver==2` nor `elsif ver==3` arm runs,
    // so `$id` stays undef (→ 0) and `$pos` stays 4 — then it reads
    // ProtectionIndex@4 / Type@6 / Name and (:9258) ASSIGNS the Type. The port
    // pre-fix dropped the entry (returned None); it must now create an item.
    let body = infe_v4(b"hvc1", b"x");
    assert!(body.len() >= 10, "v4 body must satisfy the len>=10 guard");
    let it = parse_infe(&body).expect("v4 infe must create an item, not drop it");
    assert_eq!(it.id(), 0, "v4 undef id is represented as 0");
    assert!(
      it.type_assigned(),
      "the v2/3/4+ else-branch assigns Type (QuickTime.pm:9258)"
    );
    assert_eq!(it.item_type(), Some("hvc1"));
  }

  #[test]
  fn iinf_v4_after_id1_warns_and_creates_item() {
    // R14-F1 via the iinf walk: a v2 id=1 then a v4 (undef→0) entry. The order
    // check compares `0 <= 1` → the `Item info entries are out of order`
    // warning fires, and BOTH items merge (the v4 item is keyed by id 0).
    let body = meta_inner(&iinf_v0(&[
      infe_v2(1, b"hvc1", b"a"),
      infe_v4(b"av01", b"b"),
    ]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(
      m.warning(),
      Some("Item info entries are out of order"),
      "a v4 (id 0) after id 1 is out of order"
    );
    assert_eq!(
      m.items().len(),
      2,
      "the v4 entry creates its own (id-0) item"
    );
  }

  #[test]
  fn iinf_dup_id_non_utf8_type_overwrites_prior_exif() {
    // R14-F2: a v2 id=5 type='Exif' then a v2 id=5 with a NON-UTF-8 type. The
    // second entry ASSIGNS Type (QuickTime.pm:9258, `type_assigned`) but the 4
    // bytes don't decode → value `None`, so the merge CLEARS the prior 'Exif'.
    // The slot's item_type ends up `None`, so `exif_item()` does NOT match.
    let body = meta_inner(&iinf_v0(&[
      infe_v2(5, b"Exif", b"a"),
      infe_v2(5, b"\xff\xfe\xfd\xfc", b"b"),
    ]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1, "same id = one slot");
    assert_eq!(
      m.items()[0].item_type(),
      None,
      "the non-UTF-8 Type assignment CLEARS the prior 'Exif'"
    );
    assert!(
      m.exif_item().is_none(),
      "a cleared Type must not be claimed as the Exif item"
    );
  }

  #[test]
  fn iinf_dup_id_name_overwrite_incl_non_utf8() {
    // Latent sibling: Name is assigned by EVERY infe (QuickTime.pm:9260), so a
    // duplicate id OVERWRITES Name unconditionally — including to `None` for a
    // non-UTF-8 Name. Here id=5 Name='first' then id=5 with a non-UTF-8 Name;
    // the slot's name must be `None` (overwritten/cleared), not the stale
    // 'first'.
    let body = meta_inner(&iinf_v0(&[
      infe_v2(5, b"hvc1", b"first"),
      infe_v2(5, b"hvc1", b"\xff\xfe"),
    ]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1, "same id = one slot");
    assert_eq!(
      m.items()[0].name(),
      None,
      "a non-UTF-8 Name OVERWRITES (clears) the prior 'first'"
    );
  }

  #[test]
  fn get_string_terminated_and_empty() {
    // Terminated: returns the string and advances PAST the NUL.
    let buf = b"abc\0xyz";
    let mut pos = 0usize;
    assert_eq!(get_string(buf, &mut pos).as_deref(), Some("abc"));
    assert_eq!(pos, 4, "cursor lands just past the NUL");
    // Empty (immediate NUL): `Some("")`, cursor past the NUL.
    let buf2 = b"\0rest";
    let mut p2 = 0usize;
    assert_eq!(get_string(buf2, &mut p2).as_deref(), Some(""));
    assert_eq!(p2, 1);
  }

  #[test]
  fn get_string_unterminated_returns_remaining() {
    // F2: no NUL before EOF — `GetString` (QuickTime.pm:9067-9074) returns
    // ALL remaining bytes with `pos` advanced to `len`, it NEVER fails.
    let buf = b"tail-no-nul";
    let mut pos = 0usize;
    assert_eq!(
      get_string(buf, &mut pos).as_deref(),
      Some("tail-no-nul"),
      "unterminated trailing string is returned, not None"
    );
    assert_eq!(pos, buf.len(), "cursor advanced to end-of-buffer");
    // A mid-buffer unterminated tail after a consumed terminated field.
    let buf2 = b"first\0second";
    let mut p2 = 0usize;
    assert_eq!(get_string(buf2, &mut p2).as_deref(), Some("first"));
    assert_eq!(get_string(buf2, &mut p2).as_deref(), Some("second"));
    assert_eq!(p2, buf2.len());
  }

  #[test]
  fn get_string_non_utf8_is_none() {
    // A non-UTF-8 byte run (exifast stores typed UTF-8) → `None`, distinct
    // from the empty / unterminated cases.
    let buf = &[0xFF, 0xFE, 0xFD];
    let mut pos = 0usize;
    assert_eq!(get_string(buf, &mut pos), None);
  }

  #[test]
  fn get_string_non_utf8_terminated_advances_cursor() {
    // R6: a NON-UTF-8 but TERMINATED string returns `None` for the value,
    // but the cursor must still advance PAST the NUL (ExifTool's `GetString`
    // increments through the terminator regardless of content, :9069). So
    // the NEXT `get_string` reads the FOLLOWING field, not the swallowed NUL.
    let buf = b"\xFF\xFE\0next";
    let mut pos = 0usize;
    assert_eq!(get_string(buf, &mut pos), None, "non-UTF-8 value → None");
    assert_eq!(
      pos, 3,
      "cursor advanced past the NUL despite the None value"
    );
    assert_eq!(
      get_string(buf, &mut pos).as_deref(),
      Some("next"),
      "the following field is read, not desynchronised"
    );
  }

  #[test]
  fn infe_v2_mime_non_utf8_name_keeps_content_type() {
    // R6 real-impact case: a `mime` item whose Name is non-UTF-8 (terminated)
    // must NOT lose its ContentType. Pre-fix the cursor stuck on the Name NUL
    // and ContentType read as empty, dropping `application/rdf+xml`.
    let mut infe = Vec::new();
    infe.extend_from_slice(&[2, 0, 0, 0]); // version 2 + flags
    infe.extend_from_slice(&1u16.to_be_bytes()); // id
    infe.extend_from_slice(&[0, 0]); // ProtectionIndex
    infe.extend_from_slice(b"mime"); // ItemType
    infe.extend_from_slice(b"\xFF\xFE\0"); // Name: non-UTF-8, terminated
    infe.extend_from_slice(b"application/rdf+xml\0"); // ContentType
    let it = parse_infe(&infe).expect("parsed");
    assert_eq!(it.id(), 1);
    assert_eq!(it.name(), None, "non-UTF-8 Name is None (not stored)");
    assert_eq!(
      it.content_type(),
      Some("application/rdf+xml"),
      "ContentType is read faithfully — the non-UTF-8 Name did not desync the cursor"
    );
  }

  #[test]
  fn infe_v0_unterminated_name_is_assigned() {
    // F2: a v0 infe whose Name has NO NUL terminator before the box ends.
    // `GetString` returns the remaining bytes, so Name is ASSIGNED (not
    // dropped as None). Build the infe body by hand: version+flags, id,
    // ProtectionIndex, then a Name with no trailing NUL.
    let mut infe = Vec::new();
    infe.extend_from_slice(&[0, 0, 0, 0]); // version 0 + flags
    infe.extend_from_slice(&1u16.to_be_bytes()); // id
    infe.extend_from_slice(&[0, 0]); // ProtectionIndex
    infe.extend_from_slice(b"unterm"); // Name, NO NUL → runs to EOF
    let it = parse_infe(&infe).expect("parsed");
    assert_eq!(it.id(), 1);
    assert_eq!(
      it.name(),
      Some("unterm"),
      "unterminated Name is the remaining string, assigned not None"
    );
  }

  #[test]
  fn infe_duplicate_unterminated_content_type_overwrites_prior() {
    // F2: a duplicate id whose SECOND entry's ContentType is unterminated
    // still ASSIGNS (GetString returns the remaining bytes), so it
    // OVERWRITES the first entry's ContentType (last-wins) — it is NOT left
    // stale by being treated as absent.
    let first = infe_v0(7, b"", b"application/rdf+xml"); // terminated CT
    // Second: a mime v2 infe whose ContentType has NO trailing NUL.
    let mut second = Vec::new();
    second.extend_from_slice(&[2, 0, 0, 0]); // version 2 + flags
    second.extend_from_slice(&7u16.to_be_bytes()); // SAME id
    second.extend_from_slice(&[0, 0]); // ProtectionIndex
    second.extend_from_slice(b"mime"); // ItemType
    second.push(0); // empty Name NUL
    second.extend_from_slice(b"image/heic"); // ContentType, NO NUL → EOF
    let body = meta_inner(&iinf_v0(&[first, second]));
    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1, "same id = one slot");
    assert_eq!(
      m.items()[0].content_type(),
      Some("image/heic"),
      "unterminated ContentType overwrites the prior (not stale)"
    );
  }

  #[test]
  fn parse_iloc_v0_after_v1_keeps_construction_method() {
    // iloc class-sweep: `ConstructionMethod` is assigned ONLY in the v1/v2
    // branch (QuickTime.pm:9165-9168). A v0 iloc row for an id that a prior
    // v1 row set must LEAVE the prior ConstructionMethod (the merge keeps it
    // because the v0 row reports `None`), while BaseOffset/Extents (always
    // assigned) are replaced.
    let mut out = HeifMeta::new();
    let mut id_index: BTreeMap<u32, usize> = BTreeMap::new();

    // v1 iloc, id=7, constMeth=1, noff=4,nlen=4,nbas=0,nind=0 ⇒ siz=0x4400.
    let mut v1 = Vec::new();
    v1.extend_from_slice(&[1, 0, 0, 0]); // ver=1
    v1.extend_from_slice(&0x4400u16.to_be_bytes());
    v1.extend_from_slice(&1u16.to_be_bytes()); // count
    v1.extend_from_slice(&7u16.to_be_bytes()); // id
    v1.extend_from_slice(&1u16.to_be_bytes()); // constMeth = 1
    v1.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    v1.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    v1.extend_from_slice(&0x100u32.to_be_bytes()); // offset
    v1.extend_from_slice(&0x10u32.to_be_bytes()); // length
    assert!(parse_iloc(&v1, &mut out, &mut id_index).is_ok());
    assert_eq!(out.items()[0].construction_method(), 1);

    // v0 iloc, SAME id=7 (no ConstructionMethod field present in v0).
    let mut v0 = Vec::new();
    v0.extend_from_slice(&[0, 0, 0, 0]); // ver=0
    v0.extend_from_slice(&0x4400u16.to_be_bytes());
    v0.extend_from_slice(&1u16.to_be_bytes()); // count
    v0.extend_from_slice(&7u16.to_be_bytes()); // id
    v0.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx (NO constMeth)
    v0.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    v0.extend_from_slice(&0x200u32.to_be_bytes()); // offset
    v0.extend_from_slice(&0x20u32.to_be_bytes()); // length
    assert!(parse_iloc(&v0, &mut out, &mut id_index).is_ok());
    assert_eq!(out.items().len(), 1, "same id resolves to one slot");
    let it = &out.items()[0];
    assert_eq!(
      it.construction_method(),
      1,
      "v0 row must keep the prior v1 ConstructionMethod"
    );
    assert_eq!(it.extents()[0].offset(), 0x200, "v0 row replaces Extents");
  }

  /// Write the `iloc`-owned fields into the keyed slot exactly as
  /// [`parse_iloc`] does (overwrite BaseOffset/ConstructionMethod, REPLACE
  /// Extents) — a test stand-in for the iloc source so the keyed
  /// find-or-create + last-wins overwrite can be exercised directly.
  fn iloc_write(
    out: &mut HeifMeta,
    id_index: &mut BTreeMap<u32, usize>,
    id: u32,
    base: u64,
    exts: &[(u64, u64)],
  ) {
    let idx = item_slot_index(out, id_index, id);
    if let Some(slot) = out.items_mut().get_mut(idx) {
      slot.set_base_offset(base);
      let mut v = Vec::new();
      for &(off, len) in exts {
        let mut e = HeifExtent::new();
        e.set_offset(off).set_length(len);
        v.push(e);
      }
      slot.set_extents(v);
    }
  }

  #[test]
  fn item_slot_keyed_order_and_iloc_replace() {
    // The keyed (BTreeMap id→index) find-or-create preserves first-appearance
    // push order across BOTH branches (a known id resolves to its slot; a new
    // id appends). Arrival order: 1 (new), 2 (new), 1 (dup → SAME slot,
    // last-wins REPLACE), 3 (new). The duplicate iloc row for id 1 REPLACES
    // its extents (it does NOT concatenate — QuickTime.pm:9192 `= \@extents`).
    let mut out = HeifMeta::new();
    let mut id_index: BTreeMap<u32, usize> = BTreeMap::new();
    iloc_write(&mut out, &mut id_index, 1, 0, &[(0x10, 0x4)]);
    iloc_write(&mut out, &mut id_index, 2, 0, &[(0x20, 0x8)]);
    iloc_write(&mut out, &mut id_index, 1, 0, &[(0x30, 0xC)]); // dup id 1 → replace
    iloc_write(&mut out, &mut id_index, 3, 0, &[(0x40, 0x2)]);

    // Push order is by FIRST appearance: [1, 2, 3].
    let ids: Vec<u32> = out.items().iter().map(HeifItem::id).collect();
    assert_eq!(ids, vec![1, 2, 3], "first-appearance push order preserved");
    let it1 = &out.items()[0];
    assert_eq!(it1.id(), 1);
    assert_eq!(
      it1.extents().len(),
      1,
      "duplicate iloc REPLACES extents (not concat)"
    );
    assert_eq!(
      it1.extents()[0].offset(),
      0x30,
      "the SECOND iloc row's extent wins"
    );
    assert_eq!(out.items()[1].id(), 2);
    assert_eq!(out.items()[1].extents().len(), 1);
    assert_eq!(out.items()[2].id(), 3);
    assert_eq!(out.items()[2].extents()[0].offset(), 0x40);
    // The side index points each id at its real slot.
    assert_eq!(id_index.get(&1).copied(), Some(0));
    assert_eq!(id_index.get(&2).copied(), Some(1));
    assert_eq!(id_index.get(&3).copied(), Some(2));
  }

  #[test]
  fn item_merge_duplicate_iinf_last_wins() {
    // Two `infe` v2 entries for the SAME id (1) inside one `iinf`: the
    // SECOND's Name / Type / ContentType OVERWRITE the first's
    // (QuickTime.pm:9258-9265 plain `=`, last assignment wins).
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    let mut iinf_body = Vec::new();
    iinf_body.extend_from_slice(&[0, 0, 0, 0]); // iinf version 0 + flags
    iinf_body.extend_from_slice(&2u16.to_be_bytes()); // count = 2
    // First infe: id=1, type=Exif, name="first".
    iinf_body.extend(box_bytes(b"infe", &infe_v2(1, b"Exif", b"first")));
    // Second infe: id=1, type=mime, name="second", contentType set.
    let mut infe2 = Vec::new();
    infe2.extend_from_slice(&[2, 0, 0, 0]); // version 2 + flags
    infe2.extend_from_slice(&1u16.to_be_bytes()); // id = 1 (duplicate)
    infe2.extend_from_slice(&[0, 0]); // ProtectionIndex
    infe2.extend_from_slice(b"mime"); // ItemType
    infe2.extend_from_slice(b"second\0"); // Name
    infe2.extend_from_slice(b"application/rdf+xml\0"); // ContentType (mime)
    iinf_body.extend(box_bytes(b"infe", &infe2));
    body.extend(box_bytes(b"iinf", &iinf_body));

    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1, "same id collapses to one slot");
    let it = &m.items()[0];
    assert_eq!(it.id(), 1);
    assert_eq!(it.item_type(), Some("mime"), "second infe Type wins");
    assert_eq!(it.name(), Some("second"), "second infe Name wins");
    assert_eq!(
      it.content_type(),
      Some("application/rdf+xml"),
      "second infe ContentType wins"
    );
  }

  #[test]
  fn item_merge_duplicate_iloc_replaces_extents() {
    // Two `iloc` rows for the SAME id (5): the SECOND's BaseOffset +
    // ConstructionMethod + Extents REPLACE the first's. Extents are a fresh
    // vector (`= \@extents`, QuickTime.pm:9192) — never concatenated.
    let mut out = HeifMeta::new();
    let mut id_index: BTreeMap<u32, usize> = BTreeMap::new();

    // First iloc row for id 5: base 0x1000, two extents, constMeth 0.
    let idx = item_slot_index(&mut out, &mut id_index, 5);
    if let Some(slot) = out.items_mut().get_mut(idx) {
      slot.set_base_offset(0x1000);
      slot.set_construction_method(0);
      let mut v = Vec::new();
      for &(off, len) in &[(0x10u64, 0x4u64), (0x20, 0x4)] {
        let mut e = HeifExtent::new();
        e.set_offset(off).set_length(len);
        v.push(e);
      }
      slot.set_extents(v);
    }
    // Second iloc row for id 5: base 0x2000, ONE extent, constMeth 1.
    let idx2 = item_slot_index(&mut out, &mut id_index, 5);
    assert_eq!(idx2, idx, "same id resolves to the same slot");
    if let Some(slot) = out.items_mut().get_mut(idx2) {
      slot.set_base_offset(0x2000);
      slot.set_construction_method(1);
      let mut v = Vec::new();
      let mut e = HeifExtent::new();
      e.set_offset(0x99).set_length(0x8);
      v.push(e);
      slot.set_extents(v);
    }

    assert_eq!(out.items().len(), 1);
    let it = &out.items()[0];
    assert_eq!(it.id(), 5);
    assert_eq!(it.base_offset(), 0x2000, "second BaseOffset wins");
    assert_eq!(
      it.construction_method(),
      1,
      "second ConstructionMethod wins"
    );
    assert_eq!(
      it.extents().len(),
      1,
      "extents REPLACED (not concatenated to 3)"
    );
    assert_eq!(it.extents()[0].offset(), 0x99, "the second row's extent");
  }

  #[test]
  fn item_merge_iinf_iloc_cross_merge() {
    // A normal item present in BOTH iinf (Name/Type — infe-owned) AND iloc
    // (Extents/BaseOffset — iloc-owned): the two DISJOINT field sets coexist
    // on the one slot. Order: iinf first, then iloc.
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags

    let mut iinf_body = Vec::new();
    iinf_body.extend_from_slice(&[0, 0, 0, 0]); // iinf version 0 + flags
    iinf_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iinf_body.extend(box_bytes(b"infe", &infe_v2(3, b"Exif", b"exif")));
    body.extend(box_bytes(b"iinf", &iinf_body));

    // iloc v1: noff=4, nlen=4, nbas=4, nind=0 ⇒ siz=0x4440 (base present).
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4440u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iloc_body.extend_from_slice(&3u16.to_be_bytes()); // id (same as infe)
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth (0)
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&0x500u32.to_be_bytes()); // BaseOffset (nbas=4)
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    iloc_body.extend_from_slice(&0x10u32.to_be_bytes()); // extent offset
    iloc_body.extend_from_slice(&0x40u32.to_be_bytes()); // extent length
    body.extend(box_bytes(b"iloc", &iloc_body));

    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1, "one merged slot");
    let it = &m.items()[0];
    assert_eq!(it.id(), 3);
    // infe-owned fields survive.
    assert_eq!(it.item_type(), Some("Exif"), "infe Type present");
    assert_eq!(it.name(), Some("exif"), "infe Name present");
    // iloc-owned fields present alongside.
    assert_eq!(it.base_offset(), 0x500, "iloc BaseOffset present");
    assert_eq!(it.extents().len(), 1, "iloc extent present");
    // Extent offset is BaseOffset + extent_offset = 0x500 + 0x10.
    assert_eq!(it.extents()[0].offset(), 0x510);
    assert_eq!(it.extents()[0].length(), 0x40);
  }

  #[test]
  fn item_merge_iloc_then_iinf_cross_merge_order() {
    // The reverse order: iloc FIRST, then iinf. The infe-owned Name/Type
    // must merge onto the iloc-created slot WITHOUT disturbing its Extents —
    // proving the cross-merge is order-independent (mixed-order coverage).
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags

    // iloc v1: noff=4, nlen=4, nbas=0, nind=0 ⇒ siz=0x4400.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4400u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iloc_body.extend_from_slice(&4u16.to_be_bytes()); // id
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth
    iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
    iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
    iloc_body.extend_from_slice(&0x200u32.to_be_bytes()); // extent offset
    iloc_body.extend_from_slice(&0x80u32.to_be_bytes()); // extent length
    body.extend(box_bytes(b"iloc", &iloc_body));

    // iinf AFTER iloc, same id 4.
    let mut iinf_body = Vec::new();
    iinf_body.extend_from_slice(&[0, 0, 0, 0]); // iinf version 0 + flags
    iinf_body.extend_from_slice(&1u16.to_be_bytes()); // count
    iinf_body.extend(box_bytes(b"infe", &infe_v2(4, b"hvc1", b"image")));
    body.extend(box_bytes(b"iinf", &iinf_body));

    let mut m = HeifMeta::new();
    let mut iloc_budget = MAX_ILOC_EXTENTS;
    walk_heif_meta(&body, 0, 4, &mut m, &mut iloc_budget);
    assert_eq!(m.items().len(), 1);
    let it = &m.items()[0];
    assert_eq!(it.id(), 4);
    assert_eq!(it.item_type(), Some("hvc1"), "late infe Type merged in");
    assert_eq!(it.name(), Some("image"), "late infe Name merged in");
    assert_eq!(it.extents().len(), 1, "iloc extent preserved");
    assert_eq!(it.extents()[0].offset(), 0x200, "iloc extent untouched");
  }

  #[test]
  fn parse_iloc_large_unique_ids_completes_fast() {
    // An iloc with many UNIQUE ids exercises the new-id push path n times.
    // With the keyed lookup this is O(n log n); the pre-fix per-item linear
    // scan was O(n²). Kept modest so it adds negligible test time while
    // proving the keyed path stays correct at scale (every id distinct ⇒
    // items().len() == n, each with one extent).
    let n: u32 = 4096;
    // iloc v1: noff=4, nlen=4, nbas=0, nind=0 ⇒ siz=0x4400.
    let mut iloc_body = Vec::new();
    iloc_body.extend_from_slice(&[1, 0, 0, 0]); // ver=1, flags=0
    iloc_body.extend_from_slice(&0x4400u16.to_be_bytes()); // siz nibbles
    iloc_body.extend_from_slice(&(n as u16).to_be_bytes()); // count (n < 65536)
    for i in 0..n {
      iloc_body.extend_from_slice(&(i as u16).to_be_bytes()); // unique id
      iloc_body.extend_from_slice(&0u16.to_be_bytes()); // constMeth
      iloc_body.extend_from_slice(&0u16.to_be_bytes()); // dataRefIdx
      iloc_body.extend_from_slice(&1u16.to_be_bytes()); // ext_num
      iloc_body.extend_from_slice(&((i as u32) * 0x10).to_be_bytes()); // offset
      iloc_body.extend_from_slice(&0x8u32.to_be_bytes()); // length
    }
    let mut out = HeifMeta::new();
    let mut id_index = BTreeMap::new();
    assert!(parse_iloc(&iloc_body, &mut out, &mut id_index).is_ok());
    assert_eq!(out.items().len(), n as usize);
    assert_eq!(id_index.len(), n as usize);
    // Spot-check first / last to confirm ordering + extent fidelity.
    assert_eq!(out.items()[0].id(), 0);
    assert_eq!(out.items()[(n - 1) as usize].id(), n - 1);
    assert_eq!(
      out.items()[(n - 1) as usize].extents()[0].offset(),
      (n - 1) as u64 * 0x10
    );
  }

  // ----- JXL codestream decoder -------------------------------------------

  #[test]
  fn jxl_bit_reader_lsb_first_little_endian() {
    // GetBits consumes bits LSB-first over a little-endian byte view
    // (Jpeg2000.pm:1365-1385). For bytes [0x01, 0x02]:
    //   bit0 = byte0 & 1 = 1, bits1..7 = 0 (byte0 = 0b00000001),
    //   bit8 = byte1 & 1 = 0, bit9 = (byte1>>1)&1 = 1, …
    // so read(1)=1, read(1)=0 (the next bit), read(8) over bits 2..9 = the
    // value 0b0_0000000 with bit9 set at position 7 → 0x80? Trace precisely:
    //   read(1) -> bit0 = 1
    //   read(1) -> bit1 = 0
    //   read(1) -> bit2 = 0
    //   read(8) -> bits 3..10: byte0 bits3-7 = 0, byte1 bit0(=bit8)=0,
    //             byte1 bit1(=bit9)=1, byte1 bit2(=bit10)=0
    //             ⇒ LSB-first [0,0,0,0,0,0,1,0] = 0b01000000 = 0x40.
    let mut r = JxlBitReader::new(&[0x01, 0x02]);
    assert_eq!(r.read(1), 1);
    assert_eq!(r.read(1), 0);
    assert_eq!(r.read(1), 0);
    assert_eq!(r.read(8), 0x40);
  }

  #[test]
  fn jxl_bit_reader_multi_byte_value() {
    // Read a 16-bit little-endian value directly: bytes [0x34, 0x12] read
    // as read(16) LSB-first = 0x1234.
    let mut r = JxlBitReader::new(&[0x34, 0x12]);
    assert_eq!(r.read(16), 0x1234);
  }

  #[test]
  fn jxl_bit_reader_read_zero_is_zero() {
    let mut r = JxlBitReader::new(&[0xff; 12]);
    assert_eq!(r.read(0), 0);
    // Cursor unmoved: the next read still starts at bit 0.
    assert_eq!(r.read(4), 0x0f);
  }

  #[test]
  fn process_jxl_codestream_real_fixture_200x130() {
    // The bundled `t/images/JXL.jxl` raw codestream header (verified vs
    // `exiftool -ImageWidth -ImageHeight` ⇒ 200x130). First bytes:
    //   ff 0a 08 04 8e 81 3c 64 75 6d 6d 79 20 6a ...
    // small=0, dist-selector path ⇒ y=130, ratio=0 ⇒ x=200.
    let data = [
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
    ];
    let (w, h) = process_jxl_codestream(&data).expect("codestream decoded");
    assert_eq!(w, 200, "ImageWidth");
    assert_eq!(h, 130, "ImageHeight");
  }

  #[test]
  fn process_jxl_codestream_jxlp_word_prefix() {
    // A `jxlp` partial-codestream box body carries a leading 4-byte index
    // word before `\xff\x0a` (Jpeg2000.pm:1473/1487 strip `^\0\0\0\0`).
    // Prefix the real header with `00 00 00 00` ⇒ same 200x130 result.
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]); // jxlp header word
    data.extend_from_slice(&[
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
    ]);
    let (w, h) = process_jxl_codestream(&data).expect("jxlp codestream decoded");
    assert_eq!((w, h), (200, 130));
  }

  #[test]
  fn process_jxl_codestream_small_form() {
    // Build a `small` header by hand: small=1, height-field=5 bits, ratio=0,
    // small width=5 bits. Bits are LSB-first after the 2-byte `ff 0a`.
    //   small        = 1          (1 bit)
    //   height5      = 9          (5 bits) ⇒ y = (9+1)*8 = 80
    //   ratio        = 0          (3 bits)
    //   width5       = 4          (5 bits) ⇒ x = (4+1)*8 = 40
    // Pack LSB-first into the 12-byte window: bit positions
    //   [0]=small=1
    //   [1..6)=height5=9=0b01001 ⇒ bits 1,2,3,4,5 = 1,0,0,1,0
    //   [6..9)=ratio=0 ⇒ bits 6,7,8 = 0,0,0
    //   [9..14)=width5=4=0b00100 ⇒ bits 9..13 = 0,0,1,0,0
    // Byte 0 (bits0-7): 1,1,0,0,1, 0,0,0 = 0b00010011 = 0x13
    // Byte 1 (bits8-13 in bits0-5): 0, 0,0,1,0,0 = 0b00001000 = 0x08
    let mut window = [0u8; 12];
    window[0] = 0b0001_0011; // bits 0..7
    window[1] = 0b0000_1000; // bits 8..15 (only 8..13 used)
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff, 0x0a]);
    data.extend_from_slice(&window);
    let (w, h) = process_jxl_codestream(&data).expect("small-form decoded");
    assert_eq!(h, 80, "small height (9+1)*8");
    assert_eq!(w, 40, "small width (4+1)*8");
  }

  #[test]
  fn process_jxl_codestream_ratio_nonzero() {
    // small=0 ⇒ height via dist selector; ratio != 0 ⇒ width derived from
    // height × a fixed aspect ratio (Jpeg2000.pm:1504).
    //   small   = 0      (1 bit)
    //   sel     = 0      (2 bits) ⇒ dist = 9
    //   height9 = 99     (9 bits) ⇒ y = 99+1 = 100
    //   ratio   = 2      (3 bits) ⇒ [12,10] ⇒ x = int(100*12/10) = 120
    // LSB-first bit layout:
    //   bit0      = small = 0
    //   bits1..3  = sel   = 0,0
    //   bits3..12 = height9 = 100? no: y=100 means read(9)=99=0b001100011
    //               LSB-first bits (lowest first): [1,1,0,0,0,1,1,0,0]
    //   bits12..15= ratio = 2 = 0b010 ⇒ LSB-first [0,1,0]
    // Lay into bytes:
    //   bit0=0, bit1=0, bit2=0,
    //   bits3..12 (9 bits) = height9 LSB-first = 1,1,0,0,0,1,1,0,0
    //   bits12..15 (3 bits) = ratio LSB-first = 0,1,0
    // Byte0 bits0-7: 0,0,0, 1,1,0,0,0 = 0b00011000 = 0x18
    // Byte1 bits8-15: (bit8=height9[5]=1, bit9=height9[6]=1, bit10=height9[7]=0,
    //                  bit11=height9[8]=0, bit12=ratio[0]=0, bit13=ratio[1]=1,
    //                  bit14=ratio[2]=0, bit15=0)
    //   = 1,1,0,0,0,1,0,0 = 0b00100011 = 0x23
    let mut window = [0u8; 12];
    window[0] = 0b0001_1000;
    window[1] = 0b0010_0011;
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff, 0x0a]);
    data.extend_from_slice(&window);
    let (w, h) = process_jxl_codestream(&data).expect("ratio-form decoded");
    assert_eq!(h, 100, "height 99+1");
    assert_eq!(w, 120, "width int(100*12/10)");
  }

  #[test]
  fn process_jxl_codestream_rejects_non_codestream() {
    // No `\xff\x0a` marker (after the optional jxlp word) ⇒ None
    // (Jpeg2000.pm:1473 `return 0 unless …`).
    assert!(process_jxl_codestream(b"not a codestream").is_none());
    assert!(process_jxl_codestream(&[0xff, 0x4f, 0xff, 0x51, 0x00]).is_none());
    assert!(process_jxl_codestream(&[]).is_none());
  }

  // ----- JXL walker + dispatch --------------------------------------------

  #[test]
  fn walk_jxl_raw_codestream_sets_flags_and_dimensions() {
    let data = [
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
    ];
    let mut m = Jp2Meta::new();
    walk_jxl(&data, &mut m);
    assert!(m.is_jxl());
    assert!(m.jxl_raw_codestream());
    assert_eq!(m.image_width(), Some(200));
    assert_eq!(m.image_height(), Some(130));
    assert!(m.processed_codestream());
  }

  /// Build a boxed JXL: signature + ftyp(brand=jxl ) + jxlc(codestream).
  fn synthetic_boxed_jxl(codestream: &[u8]) -> Vec<u8> {
    let mut data = JXL_SIGNATURE.to_vec();
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"jxl "); // major brand
    ftyp_body.extend_from_slice(&[0, 0, 0, 0]); // minor
    ftyp_body.extend_from_slice(b"jxl "); // compat
    data.extend(box_bytes(b"ftyp", &ftyp_body));
    data.extend(box_bytes(b"jxlc", codestream));
    data
  }

  #[test]
  fn walk_jxl_boxed_decodes_jxlc_dimensions() {
    let codestream = [
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
    ];
    let data = synthetic_boxed_jxl(&codestream);
    let mut m = Jp2Meta::new();
    walk_jxl(&data, &mut m);
    assert!(m.is_jxl());
    assert!(!m.jxl_raw_codestream(), "boxed JXL is not a raw codestream");
    assert_eq!(m.sub_type(), Some("JXL"));
    assert_eq!(m.image_width(), Some(200));
    assert_eq!(m.image_height(), Some(130));
  }

  #[test]
  fn walk_jxl_jxlp_once_guard_first_wins() {
    // A boxed JXL with TWO `jxlp` partial-codestream boxes: only the FIRST
    // is decoded (Jpeg2000.pm:1475 `$$et{ProcessedJXLCodestream}`). The
    // second carries a DIFFERENT (small-form 80x40) header that must be
    // IGNORED.
    let mut data = JXL_SIGNATURE.to_vec();
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"jxl ");
    ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
    data.extend(box_bytes(b"ftyp", &ftyp_body));
    // First jxlp: leading word + the real 200x130 header.
    let mut first = Vec::new();
    first.extend_from_slice(&[0, 0, 0, 0]); // jxlp index word
    first.extend_from_slice(&[
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79, 0x20, 0x6a,
    ]);
    data.extend(box_bytes(b"jxlp", &first));
    // Second jxlp: a small-form 80x40 header (must be ignored).
    let mut window = [0u8; 12];
    window[0] = 0b0001_0011;
    window[1] = 0b0000_1000;
    let mut second = Vec::new();
    second.extend_from_slice(&[0, 0, 0, 1]); // different index word
    second.extend_from_slice(&[0xff, 0x0a]);
    second.extend_from_slice(&window);
    data.extend(box_bytes(b"jxlp", &second));

    let mut m = Jp2Meta::new();
    walk_jxl(&data, &mut m);
    // Dimensions come from the FIRST jxlp only.
    assert_eq!(m.image_width(), Some(200));
    assert_eq!(m.image_height(), Some(130));
  }

  #[test]
  fn walk_jxl_ignores_non_jxl() {
    let mut m = Jp2Meta::new();
    walk_jxl(b"NOT A JXL FILE", &mut m);
    assert!(m.is_empty());
    assert!(!m.is_jxl());
  }

  #[test]
  fn parse_jxl_borrowed_accepts_both_forms_rejects_other() {
    // Raw codestream.
    let raw = [
      0xff, 0x0a, 0x08, 0x04, 0x8e, 0x81, 0x3c, 0x64, 0x75, 0x6d, 0x6d, 0x79,
    ];
    let m = parse_jxl_borrowed(&raw).expect("raw JXL accepted");
    assert!(m.jxl_raw_codestream());
    // Boxed JXL.
    let boxed = synthetic_boxed_jxl(&raw);
    let m2 = parse_jxl_borrowed(&boxed).expect("boxed JXL accepted");
    assert!(m2.is_jxl() && !m2.jxl_raw_codestream());
    // Neither form → None.
    assert!(parse_jxl_borrowed(b"plain text").is_none());
    // A JP2 signature is NOT a JXL.
    assert!(parse_jxl_borrowed(&JP2_SIGNATURE).is_none());
  }

  #[test]
  fn is_jxl_signatures_distinct_from_jp2() {
    assert!(is_jxl_boxed_signature(&JXL_SIGNATURE));
    assert!(!is_jxl_boxed_signature(&JP2_SIGNATURE));
    // Raw codestream needs >= 12 bytes (ProcessJXL's 12-byte read gate,
    // Jpeg2000.pm:1610): a 12-byte `ff 0a …` is accepted, a short one is not.
    assert!(is_jxl_codestream_signature(&[
      0xff, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]));
    assert!(!is_jxl_codestream_signature(&[0xff, 0x0a]));
    assert!(!is_jxl_codestream_signature(&[0xff, 0x0a, 0x00]));
    assert!(!is_jxl_codestream_signature(&J2C_SIGNATURE));
    // Boxed JXL signature is NOT a JP2 signature and vice versa.
    assert!(!is_jp2_signature(&JXL_SIGNATURE));
  }

  #[test]
  fn parse_jxl_borrowed_rejects_short_codestream() {
    // R8: a raw `ff 0a` buffer shorter than 12 bytes is below ProcessJXL's
    // 12-byte read gate (Jpeg2000.pm:1610 `return 0 unless $raf->Read($hdr,12)
    // == 12`), so ExifTool returns 0 BEFORE `SetFileType` — it must NOT be
    // accepted/finalized as JXL (pre-fix it became "JXL Codestream" 1x1).
    assert!(parse_jxl_borrowed(&[0xff, 0x0a]).is_none());
    assert!(parse_jxl_borrowed(&[0xff, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
    // 12 bytes is the boundary ExifTool accepts (reads exactly 12, proceeds).
    assert!(parse_jxl_borrowed(&[0xff, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_some());
  }

  // ==========================================================================
  // SP4 #159-audit: ftyp / ihdr / colr decode + J2C SIZ + Jpeg2000 emission
  // ==========================================================================

  /// Render `Jp2Meta::tags()` (PrintConv `-j`) into a `(name, value)` list for
  /// assertion. Filters to the `Jpeg2000`/`Jpeg2000` family-1 group.
  fn jp2_jpeg2000_tags(m: &Jp2Meta) -> Vec<(String, crate::value::TagValue)> {
    use crate::emit::{ConvMode, EmitOptions, Taggable};
    m.tags(EmitOptions::g1(ConvMode::PrintConv, false))
      .filter(|t| t.tag().group_ref().family1() == "Jpeg2000")
      .map(|t| (t.tag().name().to_string(), t.tag().value_ref().clone()))
      .collect()
  }

  fn find_str(tags: &[(String, crate::value::TagValue)], name: &str) -> Option<String> {
    tags.iter().find(|(n, _)| n == name).and_then(|(_, v)| {
      if let crate::value::TagValue::Str(s) = v {
        Some(s.to_string())
      } else {
        None
      }
    })
  }

  fn find_u64(tags: &[(String, crate::value::TagValue)], name: &str) -> Option<u64> {
    tags.iter().find(|(n, _)| n == name).and_then(|(_, v)| {
      if let crate::value::TagValue::U64(u) = v {
        Some(*u)
      } else {
        None
      }
    })
  }

  /// Build a 12-byte ihdr ImageHeader body: H, W, NC, bpc, C (Jpeg2000.pm:
  /// 513-550). The extra `unkc`/`ipr` trailing bytes are not read.
  fn ihdr_body(h: u32, w: u32, nc: u16, bpc: u8, comp: u8) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&nc.to_be_bytes());
    b.push(bpc);
    b.push(comp);
    b
  }

  #[test]
  fn decode_ihdr_scalars_and_printconv() {
    // 16x16, 3 components, 8-bit unsigned, JPEG 2000 — the Jpeg2000.jp2
    // ihdr values (Jpeg2000.pm:516-550).
    let mut m = Jp2Meta::new();
    decode_ihdr(&ihdr_body(16, 16, 3, 7, 7), &mut m);
    assert_eq!(m.ihdr_height(), Some(16));
    assert_eq!(m.ihdr_width(), Some(16));
    assert_eq!(m.ihdr_components(), Some(3));
    assert_eq!(m.ihdr_bits_per_component(), Some(7));
    assert_eq!(m.ihdr_compression(), Some(7));
    // BitsPerComponent PrintConv: `(7&0x7f)+1 = 8 Bits, Unsigned`.
    assert_eq!(jp2_bits_per_component_print(7), "8 Bits, Unsigned");
    // Compression PrintConv: 7 → "JPEG 2000".
    assert_eq!(jp2_compression_print(7), "JPEG 2000");
    // Emit and check the rendered tags.
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(find_u64(&tags, "ImageHeight"), Some(16));
    assert_eq!(find_u64(&tags, "ImageWidth"), Some(16));
    assert_eq!(find_u64(&tags, "NumberOfComponents"), Some(3));
    assert_eq!(
      find_str(&tags, "BitsPerComponent").as_deref(),
      Some("8 Bits, Unsigned")
    );
    assert_eq!(find_str(&tags, "Compression").as_deref(), Some("JPEG 2000"));
  }

  #[test]
  fn decode_ihdr_bits_per_component_variable_and_signed() {
    // 0xff → "Variable" (Jpeg2000.pm:530); the high bit selects Signed.
    assert_eq!(jp2_bits_per_component_print(0xff), "Variable");
    // 0x8b = 0x80 | 0x0b ⇒ (0x0b)+1 = 12 Bits, Signed.
    assert_eq!(jp2_bits_per_component_print(0x8b), "12 Bits, Signed");
    // 0x0f ⇒ 16 Bits, Unsigned.
    assert_eq!(jp2_bits_per_component_print(0x0f), "16 Bits, Unsigned");
    // A `0xff` BitsPerComponent emits the "Variable" string.
    let mut m = Jp2Meta::new();
    decode_ihdr(&ihdr_body(8, 8, 1, 0xff, 5), &mut m);
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "BitsPerComponent").as_deref(),
      Some("Variable")
    );
    // Compression 5 → "JPEG".
    assert_eq!(find_str(&tags, "Compression").as_deref(), Some("JPEG"));
  }

  #[test]
  fn decode_ihdr_short_body_skips_missing_tags() {
    // A 9-byte body has Height/Width/NumberOfComponents but no bpc/Compression
    // (ProcessBinaryData skips a short read, not abort — Jpeg2000.pm:513).
    let mut b = Vec::new();
    b.extend_from_slice(&100u32.to_be_bytes());
    b.extend_from_slice(&50u32.to_be_bytes());
    b.push(0x00); // only the high byte of NumberOfComponents present
    let mut m = Jp2Meta::new();
    decode_ihdr(&b, &mut m);
    assert_eq!(m.ihdr_height(), Some(100));
    assert_eq!(m.ihdr_width(), Some(50));
    assert_eq!(m.ihdr_components(), None);
    assert_eq!(m.ihdr_bits_per_component(), None);
    assert_eq!(m.ihdr_compression(), None);
  }

  #[test]
  fn decode_ftyp_brand_minor_compatible() {
    // MajorBrand `jp2 `, MinorVersion 0.0.0, CompatibleBrands [`jp2 `] — the
    // Jpeg2000.jp2 ftyp box (Jpeg2000.pm:556-582).
    let mut body = Vec::new();
    body.extend_from_slice(b"jp2 "); // major
    body.extend_from_slice(&[0, 0, 0, 0]); // minor → 0.0.0
    body.extend_from_slice(b"jp2 "); // compat 1
    let mut m = Jp2Meta::new();
    decode_ftyp(&body, &mut m);
    assert_eq!(m.major_brand(), Some("jp2 "));
    assert_eq!(m.minor_version(), Some("0.0.0"));
    assert_eq!(m.compatible_brands(), &[SmolStr::new_static("jp2 ")]);
    // MajorBrand PrintConv.
    assert_eq!(
      jp2_major_brand_print("jp2 "),
      SmolStr::new_static("JPEG 2000 Image (.JP2)")
    );
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "MajorBrand").as_deref(),
      Some("JPEG 2000 Image (.JP2)")
    );
    assert_eq!(find_str(&tags, "MinorVersion").as_deref(), Some("0.0.0"));
  }

  #[test]
  fn decode_ftyp_minor_version_nonzero_hex_render() {
    // MinorVersion `sprintf("%x.%x.%x", unpack("nCC", $val))` (Jpeg2000.pm:
    // 571): bytes 4..8 = [0x00,0x10, 0x2a, 0x0b] → "10.2a.b".
    let mut body = Vec::new();
    body.extend_from_slice(b"jpx ");
    body.extend_from_slice(&[0x00, 0x10, 0x2a, 0x0b]);
    let mut m = Jp2Meta::new();
    decode_ftyp(&body, &mut m);
    assert_eq!(m.minor_version(), Some("10.2a.b"));
  }

  #[test]
  fn decode_ftyp_compatible_brands_drops_nul_chunk() {
    // CompatibleBrands drops any 4-byte chunk containing a NUL byte
    // (Jpeg2000.pm:580 `@a=grep(!/\0/,@a)`): `jpx ` kept, `\0\0\0\0` dropped,
    // `jp2 ` kept.
    let mut body = Vec::new();
    body.extend_from_slice(b"jpx "); // major
    body.extend_from_slice(&[0, 0, 0, 0]); // minor
    body.extend_from_slice(b"jpx "); // compat: kept
    body.extend_from_slice(&[0, 0, 0, 0]); // compat: NUL chunk → dropped
    body.extend_from_slice(b"jp2 "); // compat: kept
    body.extend_from_slice(&[b'a', b'b', 0, b'd']); // partial NUL → dropped
    let mut m = Jp2Meta::new();
    decode_ftyp(&body, &mut m);
    assert_eq!(
      m.compatible_brands(),
      &[SmolStr::new_static("jpx "), SmolStr::new_static("jp2 ")]
    );
    // The List emission carries exactly the surviving chunks.
    use crate::emit::{ConvMode, EmitOptions, Taggable};
    use crate::value::TagValue;
    let list = m
      .tags(EmitOptions::g1(ConvMode::PrintConv, false))
      .find(|t| t.tag().name() == "CompatibleBrands")
      .map(|t| t.tag().value_ref().clone());
    assert_eq!(
      list,
      Some(TagValue::List(vec![
        TagValue::Str(SmolStr::new_static("jpx ")),
        TagValue::Str(SmolStr::new_static("jp2 ")),
      ]))
    );
  }

  #[test]
  fn decode_colr_method1_enumerated_srgb() {
    // colr method 1 (Enumerated): ColorSpace `int32u`@3 = 16 → sRGB. The
    // Jpeg2000.jp2 colr values (Jpeg2000.pm:653-728).
    let mut body = Vec::new();
    body.push(1); // ColorSpecMethod = Enumerated
    body.push(0); // ColorSpecPrecedence = 0
    body.push(0); // ColorSpecApproximation = Not Specified
    body.extend_from_slice(&16u32.to_be_bytes()); // ColorSpace = sRGB
    let mut m = Jp2Meta::new();
    decode_colr(&body, &mut m);
    assert_eq!(m.color_spec_method(), Some(1));
    assert_eq!(m.color_spec_precedence(), Some(0));
    assert_eq!(m.color_spec_approximation(), Some(0));
    assert_eq!(m.color_space(), Some(16));
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "ColorSpecMethod").as_deref(),
      Some("Enumerated")
    );
    assert_eq!(
      find_str(&tags, "ColorSpecApproximation").as_deref(),
      Some("Not Specified")
    );
    assert_eq!(find_str(&tags, "ColorSpace").as_deref(), Some("sRGB"));
    // ColorSpecPrecedence is a bare signed int.
    use crate::value::TagValue;
    let prec = tags.iter().find(|(n, _)| n == "ColorSpecPrecedence");
    assert_eq!(prec.map(|(_, v)| v.clone()), Some(TagValue::I64(0)));
  }

  #[test]
  fn decode_colr_precedence_signed() {
    // ColorSpecPrecedence is `int8s` (Jpeg2000.pm:669) — 0xfe → -2.
    let mut body = Vec::new();
    body.push(1);
    body.push(0xfe); // -2 as int8s
    body.push(1); // Accurate
    body.extend_from_slice(&17u32.to_be_bytes()); // Grayscale
    let mut m = Jp2Meta::new();
    decode_colr(&body, &mut m);
    assert_eq!(m.color_spec_precedence(), Some(-2));
    assert_eq!(m.color_space(), Some(17));
    let tags = jp2_jpeg2000_tags(&m);
    use crate::value::TagValue;
    assert_eq!(
      tags
        .iter()
        .find(|(n, _)| n == "ColorSpecPrecedence")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(-2))
    );
    assert_eq!(
      find_str(&tags, "ColorSpecApproximation").as_deref(),
      Some("Accurate")
    );
    assert_eq!(find_str(&tags, "ColorSpace").as_deref(), Some("Grayscale"));
  }

  #[test]
  fn decode_colr_method2_icc_no_colorspace() {
    // colr method 2 (Restricted ICC): the bytes at offset 3 are an ICC
    // profile (DEFERRED) — ColorSpace MUST NOT be emitted (Jpeg2000.pm:
    // 688-696 the offset-3 Condition selects ICC_Profile, not ColorSpace).
    let mut body = Vec::new();
    body.push(2); // Restricted ICC
    body.push(0);
    body.push(0);
    body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // would-be ICC bytes
    let mut m = Jp2Meta::new();
    decode_colr(&body, &mut m);
    assert_eq!(m.color_spec_method(), Some(2));
    assert_eq!(m.color_space(), None);
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "ColorSpecMethod").as_deref(),
      Some("Restricted ICC")
    );
    assert!(
      tags.iter().all(|(n, _)| n != "ColorSpace"),
      "method-2 (ICC) must NOT emit ColorSpace"
    );
  }

  #[test]
  fn decode_colr_method_approximation_int8s_signed_unknown() {
    // `%ColorSpec` has table-level `FORMAT => 'int8s'` (Jpeg2000.pm:636), so
    // ColorSpecMethod@0 and ColorSpecApproximation@2 are SIGNED. A crafted
    // 0xff byte is -1: ExifTool emits `Unknown (-1)` (PrintConv) / -1 (`-n`),
    // NOT `Unknown (255)` / 255. Method=-1 is not 1 ⇒ no ColorSpace.
    let body = vec![0xff_u8, 0x00, 0xff, 0xde, 0xad, 0xbe, 0xef];
    let mut m = Jp2Meta::new();
    decode_colr(&body, &mut m);
    assert_eq!(m.color_spec_method(), Some(-1));
    assert_eq!(m.color_spec_approximation(), Some(-1));
    assert_eq!(
      m.color_space(),
      None,
      "method -1 (not 1) must NOT emit ColorSpace"
    );

    use crate::emit::{ConvMode, EmitOptions, Taggable};
    use crate::value::TagValue;
    // PrintConv (`-j`): signed Unknown fallback.
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "ColorSpecMethod").as_deref(),
      Some("Unknown (-1)")
    );
    assert_eq!(
      find_str(&tags, "ColorSpecApproximation").as_deref(),
      Some("Unknown (-1)")
    );
    // Raw (`-n`): the SIGNED int (-1), not 255.
    let raw: Vec<(String, TagValue)> = m
      .tags(EmitOptions::g1(ConvMode::ValueConv, false))
      .filter(|t| t.tag().group_ref().family1() == "Jpeg2000")
      .map(|t| (t.tag().name().to_string(), t.tag().value_ref().clone()))
      .collect();
    assert_eq!(
      raw
        .iter()
        .find(|(n, _)| n == "ColorSpecMethod")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(-1))
    );
    assert_eq!(
      raw
        .iter()
        .find(|(n, _)| n == "ColorSpecApproximation")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(-1))
    );
  }

  #[test]
  fn walk_jp2_j2c_codestream_decodes_siz_dimensions() {
    // A raw J2C codestream `FF 4F FF 51 [Lsiz][Rsiz][Xsiz][Ysiz]` — ExifTool
    // delegates to ProcessJPEG's SIZ handler (ExifTool.pm:8442 `unpack
    // 'x2N2'`): ImageWidth = Xsiz@8, ImageHeight = Ysiz@12. The `Lsiz`
    // length word (>= 12, the real 1-component SIZ minimum 0x0029=41) must
    // be present and cover the segment (`data.len()` >= `4 + Lsiz`).
    let lsiz: u16 = 41; // real SIZ minimum for 1 component
    let mut data = vec![0xff, 0x4f, 0xff, 0x51]; // SOC + SIZ marker
    data.extend_from_slice(&lsiz.to_be_bytes()); // Lsiz @4 (declared length)
    data.extend_from_slice(&0u16.to_be_bytes()); // Rsiz @6 (skipped by x2)
    data.extend_from_slice(&640u32.to_be_bytes()); // Xsiz @8 → ImageWidth
    data.extend_from_slice(&480u32.to_be_bytes()); // Ysiz @12 → ImageHeight
    // Pad the buffer out to the full declared segment (4 + Lsiz bytes).
    data.resize(4 + lsiz as usize, 0);
    assert!(data.len() >= 4 + lsiz as usize);
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("J2C"));
    assert_eq!(m.image_width(), Some(640));
    assert_eq!(m.image_height(), Some(480));
    // These ride the `File` group ImageWidth/ImageHeight emission.
    use crate::emit::{ConvMode, EmitOptions, Taggable};
    use crate::value::TagValue;
    let file_tags: Vec<(String, TagValue)> = m
      .tags(EmitOptions::g1(ConvMode::PrintConv, false))
      .filter(|t| t.tag().group_ref().family1() == "File")
      .map(|t| (t.tag().name().to_string(), t.tag().value_ref().clone()))
      .collect();
    assert!(file_tags.contains(&("ImageWidth".to_string(), TagValue::U64(640))));
    assert!(file_tags.contains(&("ImageHeight".to_string(), TagValue::U64(480))));
  }

  #[test]
  fn walk_jp2_j2c_short_buffer_no_dimensions() {
    // A J2C buffer shorter than 16 bytes (no full Xsiz/Ysiz) sets the sub_type
    // but NO dimensions (the guarded `be_u32` reads return None).
    let mut data = vec![0xff, 0x4f, 0xff, 0x51, 0, 0, 0, 0]; // 8 bytes
    data.extend_from_slice(&[0u8; 5]); // 13 bytes total (>=12 to be a J2C sig)
    assert!(is_j2c_signature(&data));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("J2C"));
    assert_eq!(m.image_width(), None);
    assert_eq!(m.image_height(), None);
  }

  #[test]
  fn walk_jp2_j2c_lsiz_too_small_emits_no_dimensions() {
    // ExifTool's SIZ handler needs `Lsiz` >= 12 to reach Xsiz/Ysiz
    // (`unpack('x2N2')` over `Lsiz`-2 >= 10 segment bytes). A codestream
    // with `Lsiz` 0 or 11 but real bytes at 8/12 must NOT emit dims — only
    // the sub_type stays J2C (`SetFileType('J2C')` precedes ProcessJPEG).
    for bad_lsiz in [0u16, 11u16] {
      let mut data = vec![0xff, 0x4f, 0xff, 0x51];
      data.extend_from_slice(&bad_lsiz.to_be_bytes()); // Lsiz @4 (too small)
      data.extend_from_slice(&0u16.to_be_bytes()); // Rsiz @6
      data.extend_from_slice(&640u32.to_be_bytes()); // padding Xsiz @8
      data.extend_from_slice(&480u32.to_be_bytes()); // padding Ysiz @12
      data.resize(64, 0); // plenty long — only the Lsiz gate matters
      assert!(is_j2c_signature(&data));
      let mut m = Jp2Meta::new();
      walk_jp2(&data, &mut m);
      assert_eq!(
        m.sub_type(),
        Some("J2C"),
        "Lsiz={bad_lsiz}: sub_type stays J2C"
      );
      assert_eq!(m.image_width(), None, "Lsiz={bad_lsiz}: no ImageWidth");
      assert_eq!(m.image_height(), None, "Lsiz={bad_lsiz}: no ImageHeight");
    }
  }

  #[test]
  fn walk_jp2_j2c_lsiz_beyond_eof_emits_no_dimensions() {
    // `Lsiz` declares a segment that runs past EOF — ExifTool's
    // `$raf->Read($buff,$len) == $len` short-read does `last Marker` (no SIZ
    // handler, no dims). Here `Lsiz`=41 but the buffer is only 16 bytes
    // (< 4 + 41), so dimensions are gated off; sub_type stays J2C.
    let lsiz: u16 = 41;
    let mut data = vec![0xff, 0x4f, 0xff, 0x51];
    data.extend_from_slice(&lsiz.to_be_bytes()); // Lsiz @4 (>= 12)
    data.extend_from_slice(&0u16.to_be_bytes()); // Rsiz @6
    data.extend_from_slice(&640u32.to_be_bytes()); // Xsiz @8
    data.extend_from_slice(&480u32.to_be_bytes()); // Ysiz @12 — buffer ends @16
    assert_eq!(data.len(), 16);
    assert!(data.len() < 4 + lsiz as usize);
    assert!(is_j2c_signature(&data));
    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("J2C"));
    assert_eq!(m.image_width(), None);
    assert_eq!(m.image_height(), None);
  }

  #[test]
  fn walk_jp2_decodes_ftyp_ihdr_colr_end_to_end() {
    // A full boxed JP2 (signature + ftyp jp2 + jp2h{ihdr,colr}) decodes all
    // three sub-tables — the Jpeg2000.jp2 shape (Jpeg2000.pm:1538-1597).
    let mut data = JP2_SIGNATURE.to_vec();
    let mut ftyp_body = Vec::new();
    ftyp_body.extend_from_slice(b"jp2 ");
    ftyp_body.extend_from_slice(&[0, 0, 0, 0]);
    ftyp_body.extend_from_slice(b"jp2 ");
    data.extend(box_bytes(b"ftyp", &ftyp_body));
    // jp2h { ihdr, colr }.
    let mut jp2h = Vec::new();
    jp2h.extend(box_bytes(b"ihdr", &ihdr_body(16, 16, 3, 7, 7)));
    let mut colr_body = Vec::new();
    colr_body.push(1); // Enumerated
    colr_body.push(0); // precedence
    colr_body.push(0); // Not Specified
    colr_body.extend_from_slice(&16u32.to_be_bytes()); // sRGB
    jp2h.extend(box_bytes(b"colr", &colr_body));
    data.extend(box_bytes(b"jp2h", &jp2h));

    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("JP2"));
    assert_eq!(m.major_brand(), Some("jp2 "));
    assert_eq!(m.minor_version(), Some("0.0.0"));
    assert_eq!(m.compatible_brands(), &[SmolStr::new_static("jp2 ")]);
    assert_eq!(m.ihdr_height(), Some(16));
    assert_eq!(m.ihdr_width(), Some(16));
    assert_eq!(m.ihdr_components(), Some(3));
    assert_eq!(m.color_spec_method(), Some(1));
    assert_eq!(m.color_space(), Some(16));
    // The full Jpeg2000-group emission is byte-identical to Jpeg2000.jp2.
    let tags = jp2_jpeg2000_tags(&m);
    assert_eq!(
      find_str(&tags, "MajorBrand").as_deref(),
      Some("JPEG 2000 Image (.JP2)")
    );
    assert_eq!(find_u64(&tags, "ImageWidth"), Some(16));
    assert_eq!(find_str(&tags, "ColorSpace").as_deref(), Some("sRGB"));
  }

  #[test]
  fn walk_jp2_jp2h_size0_ihdr_emits_dimensions() {
    // R18-F3 (regression from R16-F1): a `jp2h{ size-0 ihdr }`. The `ihdr`
    // declares size 0; inside the IN-MEMORY `jp2h` SubDirectory walk
    // `ProcessJpeg2000Box` (no `$raf`) sets `$boxLen = $dirEnd - $pos`
    // (Jpeg2000.pm:1137) — the box runs to the END OF THE PARENT (`jp2h`) and
    // IS decoded. So ImageHeight/Width/Components/BitsPerComponent/Compression
    // must still be emitted. The R16-F1 blanket size-0 `Stop` wrongly dropped
    // this; the `Size0Behavior::ToParentEnd` mode for the `jp2h`-children walk
    // restores it.
    let mut data = JP2_SIGNATURE.to_vec();
    // jp2h body: a SINGLE size-0 `ihdr` (4-byte size of 0 + tag + 12-byte
    // body). It is the last/only child, so "runs to parent end" == its own
    // 12-byte body here.
    let mut jp2h = Vec::new();
    jp2h.extend_from_slice(&0u32.to_be_bytes()); // size == 0
    jp2h.extend_from_slice(b"ihdr");
    jp2h.extend_from_slice(&ihdr_body(16, 24, 3, 7, 7));
    data.extend(box_bytes(b"jp2h", &jp2h));

    let mut m = Jp2Meta::new();
    walk_jp2(&data, &mut m);
    assert_eq!(m.sub_type(), Some("JP2"));
    assert_eq!(
      m.ihdr_height(),
      Some(16),
      "size-0 ihdr runs to jp2h end and IS decoded (height)"
    );
    assert_eq!(m.ihdr_width(), Some(24), "size-0 ihdr decoded (width)");
    assert_eq!(m.ihdr_components(), Some(3));
    assert_eq!(m.ihdr_bits_per_component(), Some(7));
    assert_eq!(m.ihdr_compression(), Some(7));
    // The ihdr block location is recorded too (offset past the 4+4 header).
    assert!(m.ihdr().is_some(), "size-0 ihdr block location recorded");
  }

  /// Wrap one-or-more `av1C` bodies in a minimal `meta { iprp { ipco { av1C+ } } }`
  /// so the brand walk decodes them through the real `ipco` property-walk path.
  fn meta_with_av1c(av1c_bodies: &[&[u8]]) -> Vec<u8> {
    let mut ipco = Vec::new();
    for body in av1c_bodies {
      ipco.extend(box_bytes(b"av1C", body));
    }
    let iprp = box_bytes(b"iprp", &box_bytes(b"ipco", &ipco));
    let mut meta = Vec::new();
    meta.extend_from_slice(&[0, 0, 0, 0]); // meta version+flags
    meta.extend(iprp);
    box_bytes(b"meta", &meta)
  }

  // A canonical 4-byte `av1C` record: byte0 = 0x81 (marker bit + version 1 ⇒
  // `& 0x7f` == 1), byte2 = 0x0C ⇒ ChromaFormat `(0x0C & 0x1c) >> 2` == 3
  // (YUV 4:2:0), ChromaSamplePosition `0x0C & 0x03` == 0 (Unknown). Matches the
  // crafted-oracle bytes run against bundled ExifTool 13.59.
  const AV1C_FULL: [u8; 4] = [0x81, 0x00, 0x0C, 0x00];

  #[test]
  fn decode_av1c_three_bytes_emits_all_three() {
    // 3-byte body (byte 2 present) ⇒ all three tags, like a real 4-byte record.
    // Oracle (crafted 3-byte AVIF, bundled 13.59): AV1ConfigurationVersion 1,
    // ChromaFormat "YUV 4:2:0"/3, ChromaSamplePosition "Unknown"/0.
    let cfg = decode_av1c(&AV1C_FULL[..3]).expect("3-byte av1C decodes");
    assert_eq!(cfg.version(), Some(1));
    assert_eq!(cfg.chroma_format(), Some(3));
    assert_eq!(cfg.chroma_sample_position(), Some(0));
  }

  #[test]
  fn decode_av1c_one_byte_emits_version_only() {
    // 1-byte body: byte 0 present (AV1ConfigurationVersion) but byte 2 absent, so
    // ChromaFormat/ChromaSamplePosition do NOT emit — ProcessBinaryData skips a
    // tag whose offset is past the data length (ExifTool.pm:9963-9964). Oracle
    // (crafted 1-byte AVIF, bundled 13.59): AV1ConfigurationVersion 1 ONLY.
    let cfg = decode_av1c(&AV1C_FULL[..1]).expect("1-byte av1C decodes version");
    assert_eq!(cfg.version(), Some(1));
    assert_eq!(cfg.chroma_format(), None, "byte 2 absent ⇒ no ChromaFormat");
    assert_eq!(
      cfg.chroma_sample_position(),
      None,
      "byte 2 absent ⇒ no ChromaSamplePosition"
    );
  }

  #[test]
  fn decode_av1c_two_bytes_emits_version_only() {
    // 2-byte body: byte 2 still absent ⇒ version only (oracle: crafted 2-byte
    // AVIF, bundled 13.59 → AV1ConfigurationVersion 1 ONLY).
    let cfg = decode_av1c(&AV1C_FULL[..2]).expect("2-byte av1C decodes version");
    assert_eq!(cfg.version(), Some(1));
    assert_eq!(cfg.chroma_format(), None);
    assert_eq!(cfg.chroma_sample_position(), None);
  }

  #[test]
  fn decode_av1c_empty_body_is_none() {
    // An empty `av1C` body has no byte 0 ⇒ no field emits ⇒ no record at all.
    assert!(decode_av1c(&[]).is_none(), "empty av1C ⇒ None");
  }

  #[test]
  fn walk_av1c_one_byte_meta_emits_version_only() {
    // End-to-end through the `ipco` walk: a 1-byte `av1C` populates only the
    // version field on the shared `HeifMeta`.
    let blob = meta_with_av1c(&[&AV1C_FULL[..1]]);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    let cfg = m.av1_config().expect("1-byte av1C recorded");
    assert_eq!(cfg.version(), Some(1));
    assert_eq!(cfg.chroma_format(), None);
    assert_eq!(cfg.chroma_sample_position(), None);
  }

  #[test]
  fn walk_av1c_three_byte_meta_emits_all_three() {
    let blob = meta_with_av1c(&[&AV1C_FULL[..3]]);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    let cfg = m.av1_config().expect("3-byte av1C recorded");
    assert_eq!(cfg.version(), Some(1));
    assert_eq!(cfg.chroma_format(), Some(3));
    assert_eq!(cfg.chroma_sample_position(), Some(0));
  }

  #[test]
  fn walk_av1c_duplicate_full_then_truncated_is_per_tag_last_wins() {
    // Two `av1C` boxes in one `ipco`: a full 4-byte record then a 1-byte
    // truncated one whose byte 0 = 0x82 (version `& 0x7f` == 2). ProcessBinaryData
    // re-runs per box and FoundTag-overwrites PER TAG, so the second box
    // overwrites AV1ConfigurationVersion (→ 2) but leaves the first box's
    // ChromaFormat/ChromaSamplePosition intact. Oracle (crafted dup AVIF,
    // bundled 13.59): ChromaFormat "YUV 4:2:0"/3, ChromaSamplePosition
    // "Unknown"/0, AV1ConfigurationVersion 2.
    let truncated = [0x82u8];
    let blob = meta_with_av1c(&[&AV1C_FULL, &truncated]);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    let cfg = m.av1_config().expect("duplicate av1C recorded");
    assert_eq!(
      cfg.version(),
      Some(2),
      "later 1-byte av1C overwrites version"
    );
    assert_eq!(
      cfg.chroma_format(),
      Some(3),
      "earlier full av1C ChromaFormat survives a later truncated box"
    );
    assert_eq!(
      cfg.chroma_sample_position(),
      Some(0),
      "earlier full av1C ChromaSamplePosition survives"
    );
  }

  #[test]
  fn walk_av1c_duplicate_truncated_then_full_overwrites_all() {
    // Reverse order: a 1-byte box (version 2) then a full 4-byte box (version 1 +
    // chroma). The second box contains every tag, so it overwrites all three —
    // version reverts to 1 and chroma is set (per-tag last-wins, full box last).
    let truncated = [0x82u8];
    let blob = meta_with_av1c(&[&truncated, &AV1C_FULL]);
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    let cfg = m.av1_config().expect("duplicate av1C recorded");
    assert_eq!(cfg.version(), Some(1), "later full av1C overwrites version");
    assert_eq!(cfg.chroma_format(), Some(3));
    assert_eq!(cfg.chroma_sample_position(), Some(0));
  }

  #[test]
  fn walk_av1c_two_meta_boxes_merge_per_tag() {
    // Two separate `meta` boxes over the SAME `HeifMeta`: meta1 a full av1C,
    // meta2 a 1-byte truncated av1C (version 2). ExifTool's whole-file FoundTag
    // is per-tag last-wins regardless of which meta, so the result is meta1's
    // chroma + meta2's version (the cross-meta merge mirrors the within-ipco one).
    let truncated = [0x82u8];
    let mut blob = meta_with_av1c(&[&AV1C_FULL]);
    blob.extend(meta_with_av1c(&[&truncated]));
    let mut m = HeifMeta::new();
    scan_heif_meta(&blob, &mut m);
    let cfg = m.av1_config().expect("av1C recorded across meta boxes");
    assert_eq!(cfg.version(), Some(2), "second meta's version wins");
    assert_eq!(
      cfg.chroma_format(),
      Some(3),
      "first meta's ChromaFormat survives a later truncated meta"
    );
    assert_eq!(cfg.chroma_sample_position(), Some(0));
  }
}
