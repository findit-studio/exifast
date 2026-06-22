// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! JPEG IPTC (APP13 8BIM IIM) + the `COM`-segment `File:Comment` — the
//! Photoshop / IPTC arm of `ProcessJPEG` (`ExifTool.pm:8371-8400`) plus the
//! IPTC IIM record walker (`IPTC.pm` `ProcessIPTC`, `IPTC.pm:1050-1267`).
//!
//! A JPEG carries IPTC inside an `APP13` (`0xed`) segment whose payload begins
//! with the 14-byte `Photoshop 3.0\0` identifier (`$psAPP13hdr`,
//! `ExifTool.pm:1243`). The remainder is a Photoshop IRB — a run of `8BIM`
//! resource blocks (`ProcessPhotoshop`, `Photoshop.pm:1019-1118`). The IPTC
//! resource is block `0x0404` (`IPTCData`, `Photoshop.pm:150-156`), whose data
//! is the IIM byte stream: a sequence of `0x1c <record> <dataset> <len:u16be>
//! <value>` fields (`IPTC.pm:1129-1262`). Record 2 (the ApplicationRecord,
//! `IPTC.pm:251-695`) carries the camera-indexing datasets (`ObjectName`,
//! `Keywords`, `DateCreated`, `By-line`, `Credit`, `CopyrightNotice`, …).
//!
//! `File:CurrentIPTCDigest` is the MD5 of the `0x0404` IPTC block, rendered as
//! lowercase hex (`unpack("H*", $val)`, `ExifTool.pm:1771-1779`), computed
//! only for IPTC in the standard JPEG location (`IsStandardIPTC`,
//! `IPTC.pm:1037-1043` — `JPEG-APP13-Photoshop-IPTC`). The MD5 is a tiny,
//! self-contained, no_std integer routine (RFC 1321), so it needs no external
//! crate — see [`md5`].
//!
//! `File:Comment` is the `COM` (`0xfe`) segment payload with trailing nulls
//! stripped (`ExifTool.pm:8429-8432`). Family-0 `File`, `Priority => 0`
//! (`ExifTool.pm:1311-1316` — preserves JPEG COM order).
//!
//! ## Charset
//!
//! ExifTool decodes IPTC strings from `CharsetIPTC` (default `Latin` =
//! ISO-8859-1) to the output charset (UTF-8). The translation runs ONLY for a
//! string value containing a high byte (`\x80-\xff`) and only when no ISO-2022
//! shift is active (`IPTC.pm:1228-1240` / `TranslateCodedString`,
//! `IPTC.pm:1016-1030`). A leading `CodedCharacterSet` (record 1, dataset 90,
//! `IPTC.pm:216-235`) of `\x1b%G` selects UTF-8 (then values pass through
//! unchanged); any other escape flags the data as already-decoded. Pure-ASCII
//! datasets (the common camera case) are byte-identical under every charset.

#![deny(clippy::indexing_slicing)]

use std::{string::String, vec::Vec};

use crate::emit::EmittedTag;
use crate::value::{Group, TagValue};
use smol_str::SmolStr;

/// `$psAPP13hdr = "Photoshop 3.0\0"` (`ExifTool.pm:1243`) — the 14-byte `APP13`
/// Photoshop IRB identifier. `ProcessJPEG` matches it (`ExifTool.pm:8373`),
/// strips it (`$hdrLen = 14`, `ExifTool.pm:8387`), and hands the remaining IRB
/// to `ProcessPhotoshop`.
const PS_APP13_HDR: &[u8] = b"Photoshop 3.0\0";

/// `$psAPP13old = 'Adobe_Photoshop2.5:'` (`ExifTool.pm:1244`) — the legacy
/// 27-byte Photoshop 2.5 IRB identifier (`$hdrLen = 27`, `ExifTool.pm:8387`).
/// Matched as a fallback so a 2.5-era JPEG still decodes its IRB.
const PS_APP13_OLD: &[u8] = b"Adobe_Photoshop2.5:";

/// The legacy Photoshop 2.5 IRB header length (`$isOld ? 27 : 14`,
/// `ExifTool.pm:8387`).
const PS_APP13_OLD_LEN: usize = 27;

/// The IIM field marker (`0x1c`) every IPTC dataset begins with
/// (`unpack("CCCn", …)` then `$id == 0x1c`, `IPTC.pm:1131-1132`).
const IIM_MARKER: u8 = 0x1c;

/// IPTC Application Record number (record 2), the `%IPTC::ApplicationRecord`
/// table (`IPTC.pm:103-106`/`:251`). The only record carrying the
/// camera-indexing datasets this port emits.
const REC_APPLICATION: u8 = 2;

/// IPTC Envelope Record number (record 1), the `%IPTC::EnvelopeRecord` table
/// (`IPTC.pm:96-100`/`:142`). Only its `CodedCharacterSet` (dataset 90) is
/// consulted, to set the decode charset for later records
/// (`IPTC.pm:1233-1235`).
const REC_ENVELOPE: u8 = 1;

/// `CodedCharacterSet` dataset number (1:90, `IPTC.pm:216`) — handled specially
/// in `ProcessIPTC` (`$tag == 90` in `$rec == 1`) to update `$xlat`.
const DS_CODED_CHARACTER_SET: u8 = 90;

/// The IPTC parse outcome attached to a JPEG's [`super::ExifMeta`]: the rendered
/// `IPTC:*` / `File:*` tags for both conv modes, plus the surfaced
/// `File:CurrentIPTCDigest` and `File:Comment`.
#[derive(Debug, Clone, Default)]
pub(crate) struct IptcMeta {
  /// The `IPTC:*` ApplicationRecord tags rendered for `-j` (PrintConv).
  tags_pc: Vec<EmittedTag>,
  /// The `IPTC:*` ApplicationRecord tags rendered for `-n` (ValueConv).
  tags_n: Vec<EmittedTag>,
  /// `File:CurrentIPTCDigest` (lowercase MD5 hex of the `0x0404` block), set
  /// only for standard-location IPTC. Conv-mode-independent (the `ValueConv`
  /// hex is the same in `-j`/`-n`).
  digest: Option<SmolStr>,
  /// `File:Comment` (the `COM` segment, trailing nulls stripped). Multiple
  /// `COM` segments accumulate (last-wins under the engine's `Priority => 0`
  /// dedup, preserving first position — `ExifTool.pm:1311-1316`).
  comments: Vec<SmolStr>,
}

impl IptcMeta {
  /// `true` when nothing was decoded (no IPTC block, no digest, no comment) —
  /// the caller skips attaching an empty `IptcMeta`.
  #[inline]
  pub(crate) fn is_empty(&self) -> bool {
    self.tags_pc.is_empty() && self.digest.is_none() && self.comments.is_empty()
  }

  /// Append this `IptcMeta`'s `File:*` prefix tags (`CurrentIPTCDigest`, then
  /// each `Comment`) to `out`. `File:CurrentIPTCDigest` is `FoundTag`'d inside
  /// `ProcessIPTC` (`IPTC.pm:1083`) and `File:Comment` in the `COM` arm
  /// (`ExifTool.pm:8432`); both are family-0 `File`. Object key ORDER is
  /// conformance-insensitive (`src/jsondiff.rs`), so the relative placement of
  /// these `File:*` tags within the prefix is irrelevant — only their presence
  /// + value matter.
  pub(crate) fn push_file_tags(&self, out: &mut Vec<EmittedTag>) {
    if let Some(digest) = &self.digest {
      out.push(EmittedTag::new(
        Group::new("File", "File"),
        SmolStr::new_static("CurrentIPTCDigest"),
        TagValue::Str(digest.clone()),
        false,
      ));
    }
    for comment in &self.comments {
      // `Comment` is `Priority => 0` (`ExifTool.pm:1315`): a duplicate never
      // overrides, so the FIRST `COM` segment's value wins while keeping its
      // position. `new_with_priority(..., 0)` threads that into the sink.
      out.push(EmittedTag::new_with_priority(
        Group::new("File", "File"),
        SmolStr::new_static("Comment"),
        TagValue::Str(comment.clone()),
        false,
        0,
      ));
    }
  }

  /// Append this `IptcMeta`'s `IPTC:*` ApplicationRecord tags for `print_conv`
  /// (`-j`) or ValueConv (`-n`) to `out` — the pre-rendered vector for the
  /// active mode (cloned, mirroring the JPEG `APP`-tag path).
  pub(crate) fn push_iptc_tags(&self, print_conv: bool, out: &mut Vec<EmittedTag>) {
    let src = if print_conv {
      &self.tags_pc
    } else {
      &self.tags_n
    };
    out.extend(src.iter().cloned());
  }

  /// Record a `File:Comment` from a `COM` (`0xfe`) segment payload with trailing
  /// nulls stripped (`$$segDataPt =~ s/\0+$//`, `ExifTool.pm:8431`). Decoded
  /// Latin1→UTF-8 lossily for the rare high-byte comment (ExifTool stores the
  /// raw bytes, but the `-j` JSON re-encodes as UTF-8; pure-ASCII comments — the
  /// realistic `Lavc…` encoder tag — are byte-identical).
  pub(crate) fn push_comment(&mut self, payload: &[u8]) {
    let end = payload.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let bytes = payload.get(..end).unwrap_or(payload);
    self
      .comments
      .push(SmolStr::from(decode_string(bytes, None)));
  }
}

/// Process a JPEG `APP13` (`0xed`) segment payload — the Photoshop / IPTC arm of
/// `ProcessJPEG` (`ExifTool.pm:8371-8400`). When the payload begins with the
/// `Photoshop 3.0\0` (or legacy `Adobe_Photoshop2.5:`) identifier, walk its
/// `8BIM` IRB for the `0x0404` IPTC resource, parse its IIM stream into
/// `meta.tags_*`, and (for standard JPEG-location IPTC) compute
/// `File:CurrentIPTCDigest`.
///
/// `payload` is the full `APP13` segment payload (after the JPEG length word) —
/// or, for an IPTC block that spanned several consecutive `Photoshop 3.0\0`
/// `APP13` segments (each JPEG `APPn` is capped at ~64 KB), the buffer
/// reassembled by [`reassemble_app13_run`]. Bounds-checked throughout; a
/// truncated / malformed IRB simply stops the walk (matching
/// `ProcessPhotoshop`'s `last` on a bad resource block,
/// `Photoshop.pm:1064`/`:1074`/`:1081`) rather than panicking.
pub(crate) fn process_app13(payload: &[u8], meta: &mut IptcMeta) {
  // `$$segDataPt =~ /^$psAPP13hdr/ or ($$segDataPt =~ /^$psAPP13old/ and
  // $isOld=1)` (`ExifTool.pm:8373`): strip the IRB identifier (14 or 27 bytes,
  // `ExifTool.pm:8387`) and walk the remainder as a Photoshop IRB.
  let irb = if let Some(rest) = payload.strip_prefix(PS_APP13_HDR) {
    rest
  } else if payload.starts_with(PS_APP13_OLD) {
    match payload.get(PS_APP13_OLD_LEN..) {
      Some(rest) => rest,
      None => return,
    }
  } else {
    // `Adobe_CM` and the non-Photoshop `APP13` arms are out of scope.
    return;
  };
  process_photoshop_irb(irb, meta);
}

/// `true` when an `APP13` (`0xed`) segment payload begins with the
/// `Photoshop 3.0\0` identifier (`$$segDataPt =~ /^$psAPP13hdr/`,
/// `ExifTool.pm:8373`/`:8382`) — the membership test for a reassembly run.
///
/// Only the `Photoshop 3.0\0` (new) form participates in the multi-segment
/// `$combinedSegData` concatenation: ExifTool's run-continuation peek
/// (`ExifTool.pm:8382`) tests `$$nextSegDataPt =~ /^$psAPP13hdr/` exclusively —
/// the legacy `Adobe_Photoshop2.5:` form never extends a run (it stays a
/// single-segment block, processed directly by [`process_app13`]).
pub(crate) fn is_photoshop_app13_segment(payload: &[u8]) -> bool {
  payload.starts_with(PS_APP13_HDR)
}

/// Reassemble a run of consecutive `Photoshop 3.0\0` `APP13` segment payloads
/// into one IRB buffer, faithful to `ProcessJPEG`'s `$combinedSegData`
/// accumulation (`ExifTool.pm:8375-8385`).
///
/// A single Photoshop IRB can exceed one JPEG `APPn`'s ~64 KB cap, so a large
/// IPTC `0x0404` block is split across several consecutive `APP13` segments.
/// ExifTool concatenates them in FILE ORDER before the single `ProcessPhotoshop`
/// call: the FIRST segment is kept whole (its `Photoshop 3.0\0` header is
/// stripped later, at process time, via `DirStart = 14`,
/// `ExifTool.pm:8387`/`:8394`), and each SUBSEQUENT segment contributes only its
/// post-header bytes (`$combinedSegData .= substr($$segDataPt, length($psAPP13hdr))`,
/// `ExifTool.pm:8378` — `length($psAPP13hdr) == 14`). The run is broken by any
/// non-`APP13` segment or an `APP13` not starting with `Photoshop 3.0\0`
/// (`ExifTool.pm:8382`), so `payloads` must be exactly the maximal consecutive
/// run; the caller ([`super::jpeg`]) is responsible for that grouping.
///
/// `payloads` is non-empty (the caller enters the run on its first member). A
/// single-segment run reassembles to that segment unchanged (the common case —
/// `ExifGPS.jpg` / Pentax K-S2 — so byte-identical output is preserved). The
/// result is then handed to [`process_app13`], which strips the leading
/// `Photoshop 3.0\0` and walks the combined IRB once (so the `0x0404` block
/// crossing a segment boundary is intact for both the IIM parse and the
/// `CurrentIPTCDigest` MD5). Bounds-safe: `strip_prefix` returns `None` for a
/// short subsequent segment, which contributes nothing rather than panicking.
pub(crate) fn reassemble_app13_run(payloads: &[&[u8]], meta: &mut IptcMeta) {
  // Fast path: a lone segment (the realistic single-`APP13` IPTC layout) is
  // processed in place — no allocation, byte-identical to the pre-reassembly
  // behavior.
  if let [only] = payloads {
    process_app13(only, meta);
    return;
  }
  // `$combinedSegData = $$segDataPt` (first segment, whole, header included —
  // `ExifTool.pm:8384`), then `.= substr($$segDataPt, length($psAPP13hdr))` for
  // each later segment (header stripped — `ExifTool.pm:8378`).
  let mut combined: Vec<u8> = Vec::new();
  for (i, payload) in payloads.iter().enumerate() {
    if i == 0 {
      combined.extend_from_slice(payload);
    } else {
      // Strip this segment's `Photoshop 3.0\0` header before appending. A short
      // / malformed continuation segment (no full header) yields `None` ⇒
      // contributes nothing, matching the bounds-safe spirit (ExifTool would
      // never have peeked into a run it past such a segment).
      if let Some(rest) = payload.strip_prefix(PS_APP13_HDR) {
        combined.extend_from_slice(rest);
      }
    }
  }
  process_app13(&combined, meta);
}

/// Walk a Photoshop IRB for the `0x0404` IPTC resource — the resource-block
/// scanner of `ProcessPhotoshop` (`Photoshop.pm:1054-1109`).
///
/// IRB block layout (`Photoshop.pm:1049-1053`): `Type` (4 bytes), `TagID`
/// (2 bytes, big-endian), `Name` (a Pascal string padded to an even total
/// length), `Size` (4 bytes, big-endian), `Data` (Size bytes, padded to an even
/// length). A block whose `Type` is `8BIM` is keyed against the main Photoshop
/// table (where `0x0404` IPTC lives); the rare `PHUT`/`DCSR`/`AgHg`/`MeSa`
/// signatures (`Photoshop.pm:1059`) are valid IRB resources too — ExifTool
/// routes them to `Photoshop::Unknown` and KEEPS SCANNING (so an `8BIM 0x0404`
/// IPTC block that follows one is still reached). Only `8BIM 0x0404` carries
/// IPTC, so this port reads + skips every valid block by its layout and decodes
/// IPTC only from `8BIM 0x0404`. A `Type` outside the valid set is a corrupt
/// IRB ⇒ stop (`Photoshop.pm:1061-1064` `last`).
fn process_photoshop_irb(irb: &[u8], meta: &mut IptcMeta) {
  let mut pos = 0usize;
  // `while ($pos + 8 < $dirEnd)` (`Photoshop.pm:1054`) — STRICTLY less-than, so
  // a block needs its full 8-byte fixed header (4 type + 2 id + ≥1 name + ≥…)
  // ahead. Bundled's `+ 8` is the minimum-header guard; the per-field `.get()`s
  // below give the precise bounds.
  while pos + 8 < irb.len() {
    // `my $type = substr($$dataPt, $pos, 4)` (`Photoshop.pm:1055`) → either the
    // main table (`8BIM`) or `Photoshop::Unknown` (`PHUT`/`DCSR`/`AgHg`/`MeSa`,
    // `Photoshop.pm:1057-1060`); any other 4 bytes are a corrupt IRB ⇒ `last`
    // (`Photoshop.pm:1061-1064`). The non-`8BIM` signatures are still consumed
    // (id + name + size + data) and the loop continues past them, so a later
    // `8BIM 0x0404` IPTC resource is reached — we just never parse IPTC from a
    // non-`8BIM` block (its `0x0404` ID resolves against `Unknown`, not the
    // main `IPTCData` SubDirectory).
    let Some(ty) = irb.get(pos..pos + 4) else {
      return;
    };
    let is_8bim = ty == b"8BIM";
    if !is_8bim && !matches!(ty, b"PHUT" | b"DCSR" | b"AgHg" | b"MeSa") {
      // A genuinely-invalid signature — `last` (no `0x0404` beyond a corrupt
      // resource can be trusted).
      return;
    }
    // `my $tag = Get16u($dataPt, $pos + 4)` (`Photoshop.pm:1066`) — the resource
    // ID, big-endian.
    let (Some(&idhi), Some(&idlo)) = (irb.get(pos + 4), irb.get(pos + 5)) else {
      return;
    };
    let resource_id = u16::from_be_bytes([idhi, idlo]);
    pos += 6; // `$pos += 6` — point to start of name (`Photoshop.pm:1067`).
    // `my $nameLen = Get8u($dataPt, $pos)` (`Photoshop.pm:1068`). The Pascal
    // string is the length byte + `nameLen` bytes, padded to an even TOTAL
    // (`++$pos unless $nameLen & 0x01`, `Photoshop.pm:1072`): the length byte +
    // an even name needs one pad byte, an odd name none.
    let Some(&name_len) = irb.get(pos) else {
      return;
    };
    pos += 1; // step past the length byte (`$namePos = ++$pos`).
    pos += usize::from(name_len);
    if name_len & 0x01 == 0 {
      pos += 1;
    }
    // `if ($pos + 4 > $dirEnd) { Warn 'Bad Photoshop resource block'; last }`
    // (`Photoshop.pm:1073-1076`).
    let (Some(&s0), Some(&s1), Some(&s2), Some(&s3)) = (
      irb.get(pos),
      irb.get(pos + 1),
      irb.get(pos + 2),
      irb.get(pos + 3),
    ) else {
      return;
    };
    let size = u32::from_be_bytes([s0, s1, s2, s3]) as usize;
    pos += 4; // `$pos += 4` past the size word (`Photoshop.pm:1078`).
    // `if ($size + $pos > $dirEnd) { Warn 'Bad Photoshop resource data size';
    // last }` (`Photoshop.pm:1079-1082`).
    let Some(block) = irb.get(pos..).and_then(|r| r.get(..size)) else {
      return;
    };
    // `0x0404 => IPTCData` SubDirectory → `%IPTC::Main` (`Photoshop.pm:150-156`)
    // → `ProcessIPTC` over the block. The digest is the MD5 of this exact block
    // (`IPTC.pm:1075`). This SubDirectory lives ONLY in the main `8BIM` table,
    // so a `0x0404` ID under a `PHUT`/`DCSR`/`AgHg`/`MeSa` resource (which keys
    // against `Photoshop::Unknown`) is NOT IPTC — gate on `is_8bim`. A real
    // JPEG has one IPTC resource; should a second appear, ExifTool keeps a
    // single family-1 `IPTC` group (the `STD_IPTC` flag, `IPTC.pm:1067-1069`) —
    // `process_iptc` last-wins-dedups by name, so re-parsing would overwrite in
    // place, matching that single-group rule.
    if is_8bim && resource_id == 0x0404 {
      meta.digest = Some(md5::hex(block));
      process_iptc(block, meta);
    }
    // `$size += 1 if $size & 0x01; $pos += $size` — data is padded to an even
    // length (`Photoshop.pm:1107-1108`).
    pos += size + (size & 0x01);
  }
}

/// Parse one IPTC IIM byte stream (the `0x0404` resource data) into
/// `meta.tags_*` — the field walker of `ProcessIPTC` (`IPTC.pm:1129-1263`).
///
/// Each field is `0x1c <record:u8> <dataset:u8> <len:u16be> <value:len>`
/// (`unpack("CCCn", …)`, `IPTC.pm:1131`). An extended-length field
/// (`$len & 0x8000`, `IPTC.pm:1144-1155`) encodes the real length as a
/// big-endian integer in the next `len & 0x7fff` bytes. A non-`0x1c` marker
/// ends the walk (the trailing-null pad both fixtures carry, and the iMatch
/// all-null pad, `IPTC.pm:1132-1141`). Record 2 datasets are looked up in the
/// ApplicationRecord table ([`application_record`]); record 1's
/// `CodedCharacterSet` updates the decode charset; other records are skipped.
fn process_iptc(data: &[u8], meta: &mut IptcMeta) {
  // `my $xlat = $et->Options('CharsetIPTC')` then `undef if eq Charset`
  // (`IPTC.pm:1105-1106`): the default CharsetIPTC is `Latin`, the default
  // output Charset is UTF-8, so `xlat = Some(Latin)` initially (decode high
  // bytes). A `CodedCharacterSet` of `\x1b%G` (UTF-8) sets it to `None`.
  let mut xlat: Option<Charset> = Some(Charset::Latin);
  // The List-flagged ApplicationRecord datasets accumulate their occurrences
  // (`Flags => 'List'`): a dataset seen once emits a scalar, seen N>1 times a
  // `TagValue::List` (ExifTool's `FoundTag` builds the list). Keyed by dataset
  // number; the value carries the (insertion-ordered) rendered occurrences.
  let mut lists: Vec<(u8, ListAccum)> = Vec::new();

  let mut pos = 0usize;
  while pos + 5 <= data.len() {
    // `unpack("CCCn", $buff)` (`IPTC.pm:1130-1131`).
    let (Some(&id), Some(&rec), Some(&tag)) = (data.get(pos), data.get(pos + 1), data.get(pos + 2))
    else {
      break;
    };
    let (Some(&lhi), Some(&llo)) = (data.get(pos + 3), data.get(pos + 4)) else {
      break;
    };
    if id != IIM_MARKER {
      // `unless ($id)` — a `0x00` may be trailing pad; bundled scans the rest
      // and only warns if non-zero is found (`IPTC.pm:1132-1140`). Either way it
      // stops parsing fields here. A bad non-zero marker is a `Warn` + `last`.
      break;
    }
    let mut len = usize::from(u16::from_be_bytes([lhi, llo]));
    pos += 5; // step past the 5-byte field header (`IPTC.pm:1142`).
    // Extended IPTC entry (`$len & 0x8000`, `IPTC.pm:1144-1155`): the next
    // `n = len & 0x7fff` bytes are the real length, a big-endian variable int.
    if len & 0x8000 != 0 {
      let n = len & 0x7fff;
      if pos + n > data.len() || n > 8 {
        break; // invalid extended entry (`IPTC.pm:1146-1150`).
      }
      len = 0;
      for _ in 0..n {
        let Some(&b) = data.get(pos) else {
          return;
        };
        len = len * 256 + usize::from(b);
        pos += 1;
      }
    }
    // `if ($pos + $len > $dirEnd)` — a value running past the block ends the
    // walk (`IPTC.pm:1156-1160`).
    let Some(value) = data.get(pos..).and_then(|r| r.get(..len)) else {
      break;
    };

    if rec == REC_ENVELOPE && tag == DS_CODED_CHARACTER_SET {
      // `$xlat = HandleCodedCharset($et, $val)` (`IPTC.pm:1235`): `\x1b%G`
      // selects UTF-8 (⇒ no translation needed); any other escape we treat as
      // pass-through (faithful to the common "already UTF-8" / unsupported
      // cases — we never mojibake by mis-decoding).
      xlat = handle_coded_charset(value);
    } else if rec == REC_APPLICATION
      && let Some(def) = application_record(tag)
    {
      // A record-2 dataset in the ApplicationRecord table is rendered + emitted;
      // an UNMAPPED record-2 dataset is `Unknown => 1` in ExifTool
      // (`AddTagToTable`, `IPTC.pm:1184-1187`) ⇒ suppressed from default output,
      // so it contributes no tag here. Records other than 1/2 (NewsPhoto,
      // ObjectData, …) carry no camera-indexing datasets in scope; their fields
      // are skipped by `len`.
      emit_dataset(&def, value, xlat, &mut lists, meta);
    }

    pos += len; // `$pos += $len` — next field (`IPTC.pm:1262`).
  }

  // Emit the accumulated List-flagged datasets (one tag each — scalar for a
  // single occurrence, `TagValue::List` for several), in their first-occurrence
  // order to match ExifTool's `FoundTag` sequence.
  for (_, accum) in lists {
    accum.emit(meta);
  }
}

/// An accumulator for a `Flags => 'List'` ApplicationRecord dataset: it gathers
/// each occurrence's rendered value (separately for the two conv modes) and the
/// shared group/name, emitting one tag (scalar if a single occurrence, a
/// `TagValue::List` if several — ExifTool's `FoundTag` list-building,
/// `ExifTool.pm:9437`).
#[derive(Debug)]
struct ListAccum {
  group: &'static str,
  name: &'static str,
  values_pc: Vec<TagValue>,
  values_n: Vec<TagValue>,
}

impl ListAccum {
  fn new(def: &Dataset) -> Self {
    Self {
      group: def.group,
      name: def.name,
      values_pc: Vec::new(),
      values_n: Vec::new(),
    }
  }

  /// Emit this accumulator's tag for both conv modes onto `meta`.
  fn emit(self, meta: &mut IptcMeta) {
    emit_pair(
      meta,
      self.group,
      self.name,
      collapse_list(self.values_pc),
      collapse_list(self.values_n),
    );
  }
}

/// One occurrence → a scalar `TagValue`; several → a `TagValue::List`
/// (ExifTool emits a single-occurrence List-flagged tag as a scalar, a repeated
/// one as an array).
fn collapse_list(mut values: Vec<TagValue>) -> TagValue {
  if values.len() == 1 {
    values.pop().unwrap_or(TagValue::Str(SmolStr::default()))
  } else {
    TagValue::List(values)
  }
}

/// Render one ApplicationRecord dataset's value (per its `Format`/`ValueConv`/
/// `PrintConv`) and either emit it (scalar dataset) or push it onto its
/// List accumulator (a `Flags => 'List'` dataset).
fn emit_dataset(
  def: &Dataset,
  value: &[u8],
  xlat: Option<Charset>,
  lists: &mut Vec<(u8, ListAccum)>,
  meta: &mut IptcMeta,
) {
  let (pc, n) = render_dataset(def, value, xlat);
  if def.list {
    // Find or create this dataset's accumulator (preserving first-occurrence
    // order), then append the occurrence's two rendered values.
    if let Some((_, accum)) = lists.iter_mut().find(|(t, _)| *t == def.dataset) {
      accum.values_pc.push(pc);
      accum.values_n.push(n);
    } else {
      let mut accum = ListAccum::new(def);
      accum.values_pc.push(pc);
      accum.values_n.push(n);
      lists.push((def.dataset, accum));
    }
  } else {
    emit_pair(meta, def.group, def.name, pc, n);
  }
}

/// Render one ApplicationRecord dataset value into its `(PrintConv, ValueConv)`
/// pair of [`TagValue`]s, faithful to the dataset's `Format` + any
/// `ValueConv`/`PrintConv` (`IPTC.pm` `ProcessIPTC` per-format handling +
/// the table entries).
fn render_dataset(def: &Dataset, value: &[u8], xlat: Option<Charset>) -> (TagValue, TagValue) {
  match def.format {
    // `Format =~ /^int/` → big-endian accumulate (`IPTC.pm:1220-1227`), limited
    // to ≤8 bytes. `ApplicationRecordVersion` (int16u) → the integer 2 / 4.
    // No PrintConv on the version ⇒ same in both modes.
    Format::Int => {
      let raw = int_be(value);
      let v = TagValue::U64(raw);
      (v.clone(), v)
    }
    // `Format =~ /^digits/` (`IPTC.pm:1241-1244`): strip trailing nulls; the
    // raw value is ASCII digits. `DateCreated` (2:55) carries a
    // `ValueConv => ExifDate` (`IPTC.pm:407-416`) ⇒ both modes show the
    // `YYYY:MM:DD` form (no separate PrintConv in default `-j`).
    Format::Digits => {
      let raw = strip_trailing_nulls(value);
      let text = decode_string(raw, xlat);
      let converted = match def.conv {
        Conv::ExifDate => exif_date(&text),
        Conv::ExifTime => exif_time(&text),
        Conv::None | Conv::UrgencyPrint => text,
      };
      let v = TagValue::Str(SmolStr::from(converted));
      (v.clone(), v)
    }
    // `Format =~ /^string/` (`IPTC.pm:1228-1240`): strip trailing nulls, then
    // charset-translate high bytes. `TimeCreated` (2:60) is `string[11]` with a
    // `ValueConv => ExifTime`. `Urgency`/`Category`/… carry PrintConvs.
    Format::String => {
      let raw = strip_trailing_nulls(value);
      let text = decode_string(raw, xlat);
      match def.conv {
        Conv::ExifTime => {
          let v = TagValue::Str(SmolStr::from(exif_time(&text)));
          (v.clone(), v)
        }
        Conv::ExifDate => {
          let v = TagValue::Str(SmolStr::from(exif_date(&text)));
          (v.clone(), v)
        }
        Conv::UrgencyPrint => (
          TagValue::Str(SmolStr::from(urgency_print(&text))),
          TagValue::Str(SmolStr::from(text)),
        ),
        Conv::None => {
          let v = TagValue::Str(SmolStr::from(text));
          (v.clone(), v)
        }
      }
    }
  }
}

/// Emit a `(PrintConv, ValueConv)` rendered pair under family-0 `IPTC`,
/// family-1 `def.group` (the ApplicationRecord `Groups => { 2 => … }` resolves
/// the family-1 group to `IPTC` for the `-G1` key), pushing the PrintConv value
/// onto `tags_pc` and the ValueConv onto `tags_n`.
fn emit_pair(meta: &mut IptcMeta, group: &str, name: &str, pc: TagValue, n: TagValue) {
  meta.tags_pc.push(EmittedTag::new(
    Group::new("IPTC", group),
    SmolStr::new(name),
    pc,
    false,
  ));
  meta.tags_n.push(EmittedTag::new(
    Group::new("IPTC", group),
    SmolStr::new(name),
    n,
    false,
  ));
}

/// `Format =~ /^int/` (`IPTC.pm:1220-1227`): accumulate a big-endian unsigned
/// integer over the value bytes, capped at 8 bytes (`if $len <= 8`). A value
/// longer than 8 bytes keeps ExifTool's behavior (the raw `substr` is left
/// untouched there) — out of scope for the int datasets this port emits
/// (`ApplicationRecordVersion` is 2 bytes).
fn int_be(value: &[u8]) -> u64 {
  let mut acc: u64 = 0;
  for &b in value.iter().take(8) {
    acc = acc.wrapping_mul(256).wrapping_add(u64::from(b));
  }
  acc
}

/// Strip trailing null bytes (`$val =~ s/\0+$//`, `IPTC.pm:1230`/`:1242`) —
/// "some braindead softwares add null terminators".
fn strip_trailing_nulls(value: &[u8]) -> &[u8] {
  let end = value.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
  value.get(..end).unwrap_or(value)
}

/// `Exif::ExifDate($val)` (`Exif.pm:6068-6076`): strip a trailing null, then
/// `s/(\d{4})\D*(\d{2})\D*(\d{2})$/$1:$2:$3/` — `"20020620"` → `"2002:06:20"`.
/// A value that doesn't match the 8-digit shape is returned unchanged (after
/// the null strip), faithful to the substitution's "leave alone if no match".
fn exif_date(date: &str) -> String {
  let date = date.strip_suffix('\0').unwrap_or(date);
  // The Perl regex anchors at the END (`…$`): the last 4+2+2 digit groups,
  // separated by runs of non-digits. The realistic IPTC value is exactly
  // 8 digits; match that canonical case, otherwise pass through.
  if date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()) {
    let mut out = String::with_capacity(10);
    // `YYYY:MM:DD` — colons after the 4th and 6th digit. Building from the char
    // iterator avoids raw byte indexing (the module denies `indexing_slicing`).
    for (i, ch) in date.chars().enumerate() {
      if i == 4 || i == 6 {
        out.push(':');
      }
      out.push(ch);
    }
    out
  } else {
    String::from(date)
  }
}

/// `Exif::ExifTime($val)` (`Exif.pm:6085-6094`): `tr/ /:/`, strip a trailing
/// null, `s/^(\d2)(\d2)(\d2)/$1:$2:$3/` then
/// `s/([+-]\d2)(\d2)\s*$/$1:$2/` — `"111726+0900"` → `"11:17:26+09:00"`.
fn exif_time(time: &str) -> String {
  // `tr/ /:/` — spaces become colons.
  let translated: String = time
    .chars()
    .map(|c| if c == ' ' { ':' } else { c })
    .collect();
  let translated = translated.strip_suffix('\0').unwrap_or(&translated);
  let mut out = String::with_capacity(translated.len() + 2);
  // `s/^(\d2)(\d2)(\d2)/$1:$2:$3/` — insert `:` after the first two pairs IFF
  // the value starts with 6 digits (the head). Insert the colons after the 2nd
  // and 4th leading digit, leaving the tail (timezone etc.) untouched.
  let head_is_six_digits = translated
    .bytes()
    .take(6)
    .filter(u8::is_ascii_digit)
    .count()
    == 6
    && translated.len() >= 6;
  if head_is_six_digits {
    for (i, ch) in translated.chars().enumerate() {
      if i == 2 || i == 4 {
        out.push(':');
      }
      out.push(ch);
    }
  } else {
    out.push_str(translated);
  }
  // `s/([+-]\d2)(\d2)\s*$/$1:$2/` — colonize the timezone `+HHMM` → `+HH:MM`,
  // trimming trailing whitespace. Operate on the END of the string built so
  // far: find a `[+-]` followed by exactly 4 digits at the (whitespace-trimmed)
  // tail.
  colonize_timezone(out)
}

/// Apply ExifTime's timezone substitution `s/([+-]\d2)(\d2)\s*$/$1:$2/` to an
/// already head-formatted time string: a trailing `[+-]HHMM` (after trimming
/// trailing whitespace) becomes `[+-]HH:MM`.
fn colonize_timezone(s: String) -> String {
  let trimmed = s.trim_end();
  let n = trimmed.len();
  // Need at least `[+-]` + 4 digits = 5 chars at the tail. `get(n - 5..)` keeps
  // the bound checked (the module denies `indexing_slicing`).
  if let Some(tz) = n.checked_sub(5).and_then(|start| trimmed.get(start..)) {
    let mut tz_bytes = tz.bytes();
    let sign_ok = matches!(tz_bytes.next(), Some(b'+' | b'-'));
    if sign_ok && tz_bytes.all(|b| b.is_ascii_digit()) {
      // Split `[+-]HHMM` → `[+-]HH` + `:` + `MM` at `n - 2`.
      if let (Some(head), Some(mm)) = (trimmed.get(..n - 2), trimmed.get(n - 2..)) {
        let mut out = String::with_capacity(trimmed.len() + 1);
        out.push_str(head);
        out.push(':');
        out.push_str(mm);
        return out;
      }
    }
  }
  // No timezone tail — return the whitespace-trimmed string (the `\s*$` of the
  // regex trims trailing whitespace even when the `[+-]` group doesn't match,
  // because the head-substitution result already has no trailing whitespace for
  // the realistic value; keep `trimmed` to honor the `\s*$`).
  String::from(trimmed)
}

/// `Urgency` PrintConv (`IPTC.pm:288-299`): the labeled extremes
/// (`0 (reserved)`, `1 (most urgent)`, `5 (normal urgency)`, `8 (least urgent)`,
/// `9 (user-defined priority)`); the others (`2`-`4`, `6`-`7`) render as the
/// bare digit. A value outside `0-9` (or non-numeric) renders verbatim (the
/// hash has no `OTHER`, but a missing key in ExifTool's numeric PrintConv with
/// `$val` outside the map falls back to the raw `$val`).
fn urgency_print(val: &str) -> String {
  let label = match val {
    "0" => "0 (reserved)",
    "1" => "1 (most urgent)",
    "5" => "5 (normal urgency)",
    "8" => "8 (least urgent)",
    "9" => "9 (user-defined priority)",
    other => other,
  };
  String::from(label)
}

/// `HandleCodedCharset($et, $val)` (`IPTC.pm:994-1009`) restricted to the cases
/// that reach the output: `\x1b%G` (the UTF-8 escape) selects UTF-8 ⇒ return
/// `None` (no translation, values are already UTF-8). Any other escape
/// (`\x1b%…`) is an unsupported coding (`'bad'`) and an empty / unrecognized
/// value falls back to the default Latin charset. We never mis-decode: an
/// unsupported coding leaves bytes as lossy-UTF-8 pass-through.
fn handle_coded_charset(val: &[u8]) -> Option<Charset> {
  let val = strip_trailing_nulls(val);
  if val == b"\x1b%G" {
    // UTF-8 selected — output charset is UTF-8, so no translation.
    None
  } else if val.starts_with(b"\x1b%") {
    // Unsupported coding: bundled flags it 'bad' and stops translating. We pass
    // bytes through lossily rather than apply Latin1.
    None
  } else {
    // Empty / unrecognized ⇒ default CharsetIPTC (Latin).
    Some(Charset::Latin)
  }
}

/// The IPTC string charset selected for decoding a dataset value. Only `Latin`
/// (ISO-8859-1, the `CharsetIPTC` default) is materialized — the UTF-8 case is
/// `None` (pass-through). ISO-2022 shifted sets are unsupported by ExifTool on
/// read (`IPTC.pm:1026-1029`) and never reach the output decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
  /// ISO-8859-1 (Latin1) — every byte `0x80-0xff` maps to the same Unicode
  /// code point.
  Latin,
}

/// Decode IPTC `value` bytes to a UTF-8 `String` under `xlat`
/// (`IPTC.pm:1237-1239` `TranslateCodedString`, decode direction). Translation
/// runs ONLY for a value containing a high byte (`\x80-\xff`); a pure-ASCII
/// value is identical under every charset. `None` (UTF-8 selected) or an
/// already-UTF-8 value passes through as lossy UTF-8.
fn decode_string(value: &[u8], xlat: Option<Charset>) -> String {
  // `if $xlat and $val =~ /[\x80-\xff]/` (`IPTC.pm:1237`): only then translate.
  let has_high = value.iter().any(|&b| b >= 0x80);
  match (xlat, has_high) {
    (Some(Charset::Latin), true) => {
      // ISO-8859-1 → UTF-8: every byte is its own code point.
      value.iter().map(|&b| char::from(b)).collect()
    }
    _ => String::from_utf8_lossy(value).into_owned(),
  }
}

/// The `Format` archetype of an ApplicationRecord dataset (the prefix of its
/// `Format =>` string), driving the per-format handling in `ProcessIPTC`.
#[derive(Debug, Clone, Copy)]
enum Format {
  /// `int8u`/`int16u`/… — big-endian integer accumulate (`IPTC.pm:1220`).
  Int,
  /// `string[…]` — trailing-null strip + charset translate (`IPTC.pm:1228`).
  String,
  /// `digits[…]` — trailing-null strip, ASCII digits (`IPTC.pm:1241`).
  Digits,
}

/// The value-conversion an ApplicationRecord dataset applies after format
/// handling — the table `ValueConv`/`PrintConv` entries this port needs.
#[derive(Debug, Clone, Copy)]
enum Conv {
  /// No conversion (the raw string / integer is the value).
  None,
  /// `ValueConv => Exif::ExifDate` (`IPTC.pm:412`) — `YYYYMMDD` → `YYYY:MM:DD`.
  ExifDate,
  /// `ValueConv => Exif::ExifTime` (`IPTC.pm:422`) — `HHMMSS±HHMM` →
  /// `HH:MM:SS±HH:MM`.
  ExifTime,
  /// `PrintConv` of the `Urgency` extremes (`IPTC.pm:288-299`).
  UrgencyPrint,
}

/// One ApplicationRecord dataset definition (the fields of a `%IPTC::
/// ApplicationRecord` table entry this port consults): its number, emitted
/// `Name`, family-1 `Groups => { 1 => … }` group, `Format` archetype, any
/// `ValueConv`/`PrintConv`, and the `Flags => 'List'` repeatable marker.
#[derive(Debug, Clone, Copy)]
struct Dataset {
  dataset: u8,
  name: &'static str,
  group: &'static str,
  format: Format,
  conv: Conv,
  list: bool,
}

/// Build a [`Dataset`] for a non-List, no-conv string dataset under the default
/// family-1 IPTC group — the common ApplicationRecord case.
const fn d_str(dataset: u8, name: &'static str) -> Dataset {
  Dataset {
    dataset,
    name,
    group: "IPTC",
    format: Format::String,
    conv: Conv::None,
    list: false,
  }
}

/// Look up an ApplicationRecord (record 2) dataset by number — the
/// `%IPTC::ApplicationRecord` table (`IPTC.pm:251-695`), restricted to the
/// datasets a camera-indexing / Pentax-K-S2 build emits. An unmapped dataset
/// returns `None` (ExifTool's `Unknown => 1` auto-tag ⇒ suppressed from default
/// output).
///
/// The family-1 group is `IPTC` for all of these (the table `GROUPS => { 2 =>
/// 'Other' }` sets only family-2; the family-1 group comes from the IPTC
/// directory name, `IPTC.pm:153`). Names/formats mirror the table exactly.
fn application_record(dataset: u8) -> Option<Dataset> {
  let def = match dataset {
    // 2:00 `ApplicationRecordVersion` `int16u`, Mandatory (`IPTC.pm:256-260`).
    0 => Dataset {
      dataset: 0,
      name: "ApplicationRecordVersion",
      group: "IPTC",
      format: Format::Int,
      conv: Conv::None,
      list: false,
    },
    // 2:05 `ObjectName` `string[0,64]` (`IPTC.pm:270-273`).
    5 => d_str(5, "ObjectName"),
    // 2:10 `Urgency` `digits[1]` + PrintConv (`IPTC.pm:285-300`). Stored as a
    // single ASCII digit (`string`-like); render via the Urgency PrintConv.
    10 => Dataset {
      dataset: 10,
      name: "Urgency",
      group: "IPTC",
      format: Format::String,
      conv: Conv::UrgencyPrint,
      list: false,
    },
    // 2:15 `Category` `string[0,3]` (`IPTC.pm:306-309`).
    15 => d_str(15, "Category"),
    // 2:20 `SupplementalCategories` `string[0,32]`, List (`IPTC.pm:310-314`).
    20 => Dataset {
      list: true,
      ..d_str(20, "SupplementalCategories")
    },
    // 2:25 `Keywords` `string[0,64]`, List (`IPTC.pm:319-323`).
    25 => Dataset {
      list: true,
      ..d_str(25, "Keywords")
    },
    // 2:55 `DateCreated` `digits[8]` + `ValueConv => ExifDate`
    // (`IPTC.pm:407-416`).
    55 => Dataset {
      dataset: 55,
      name: "DateCreated",
      group: "IPTC",
      format: Format::Digits,
      conv: Conv::ExifDate,
      list: false,
    },
    // 2:60 `TimeCreated` `string[11]` + `ValueConv => ExifTime`
    // (`IPTC.pm:417-426`).
    60 => Dataset {
      dataset: 60,
      name: "TimeCreated",
      group: "IPTC",
      format: Format::String,
      conv: Conv::ExifTime,
      list: false,
    },
    // 2:80 `By-line` `string[0,32]`, List (`IPTC.pm:464-469`).
    80 => Dataset {
      list: true,
      ..d_str(80, "By-line")
    },
    // 2:85 `By-lineTitle` `string[0,32]`, List (`IPTC.pm:470-475`).
    85 => Dataset {
      list: true,
      ..d_str(85, "By-lineTitle")
    },
    // 2:90 `City` `string[0,32]` (`IPTC.pm:476-480`).
    90 => d_str(90, "City"),
    // 2:92 `Sub-location` `string[0,32]` (`IPTC.pm:481-485`).
    92 => d_str(92, "Sub-location"),
    // 2:95 `Province-State` `string[0,32]` (`IPTC.pm:486-490`).
    95 => d_str(95, "Province-State"),
    // 2:100 `Country-PrimaryLocationCode` `string[3]` (`IPTC.pm:491-495`).
    100 => d_str(100, "Country-PrimaryLocationCode"),
    // 2:101 `Country-PrimaryLocationName` `string[0,64]` (`IPTC.pm:496-500`).
    101 => d_str(101, "Country-PrimaryLocationName"),
    // 2:103 `OriginalTransmissionReference` `string[0,32]` (`IPTC.pm:501-505`).
    103 => d_str(103, "OriginalTransmissionReference"),
    // 2:105 `Headline` `string[0,256]` (`IPTC.pm:506-509`).
    105 => d_str(105, "Headline"),
    // 2:110 `Credit` `string[0,32]` (`IPTC.pm:510-514`).
    110 => d_str(110, "Credit"),
    // 2:115 `Source` `string[0,32]` (`IPTC.pm:515-519`).
    115 => d_str(115, "Source"),
    // 2:116 `CopyrightNotice` `string[0,128]` (`IPTC.pm:520-524`).
    116 => d_str(116, "CopyrightNotice"),
    // 2:118 `Contact` `string[0,128]`, List (`IPTC.pm:525-530`).
    118 => Dataset {
      list: true,
      ..d_str(118, "Contact")
    },
    // 2:120 `Caption-Abstract` `string[0,2000]` (`IPTC.pm:531-534`).
    120 => d_str(120, "Caption-Abstract"),
    // 2:122 `Writer-Editor` `string[0,32]`, List (`IPTC.pm:545-550`).
    122 => Dataset {
      list: true,
      ..d_str(122, "Writer-Editor")
    },
    _ => return None,
  };
  Some(def)
}

/// A self-contained RFC 1321 MD5 — the digest `ProcessIPTC` computes over the
/// `0x0404` IPTC block (`Digest::MD5::md5`, `IPTC.pm:1075`) for
/// `File:CurrentIPTCDigest` (`ValueConv => unpack("H*", $val)`,
/// `ExifTool.pm:1779`). Pure integer arithmetic ⇒ no external crate and
/// no_std-clean (uses only `core` + the `alloc` `String`/`Vec` already in
/// scope). The single public entry [`hex`] returns the lowercase 32-char hex.
mod md5 {
  use std::string::String;

  /// The per-round left-rotation amounts `s[0..64]` (RFC 1321 §3.4).
  const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  /// The per-round sine-derived constants `K[i] = floor(2^32 * abs(sin(i+1)))`
  /// (RFC 1321 §3.4) — precomputed so the routine stays `core`-only (no libm).
  const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
  ];

  /// Compute the MD5 of `data`, returning the lowercase 32-character hex string
  /// (`unpack("H*", $digest)`, `ExifTool.pm:1779`).
  pub(super) fn hex(data: &[u8]) -> smol_str::SmolStr {
    /// Map a nibble (`0..=15`) to its lowercase hex char.
    const fn nibble(n: u8) -> char {
      match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
      }
    }
    let digest = digest(data);
    let mut out = String::with_capacity(32);
    for byte in digest {
      // Lowercase hex, two chars per byte.
      out.push(nibble(byte >> 4));
      out.push(nibble(byte & 0x0f));
    }
    smol_str::SmolStr::from(out)
  }

  /// The raw 16-byte MD5 digest of `data`.
  fn digest(data: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    // Pre-processing: append `0x80`, pad with `0x00` to 56 mod 64, then the
    // 64-bit little-endian bit length (RFC 1321 §3.1-3.2).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
      msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 64-byte chunk.
    for chunk in msg.chunks_exact(64) {
      // Decode the chunk into 16 little-endian 32-bit words. `chunks_exact(4)`
      // over a 64-byte chunk yields exactly 16 four-byte groups; `try_into`
      // keeps the bound checked (no raw indexing, honoring the module deny).
      let mut m = [0u32; 16];
      for (word, group) in m.iter_mut().zip(chunk.chunks_exact(4)) {
        let arr: [u8; 4] = group.try_into().unwrap_or([0; 4]);
        *word = u32::from_le_bytes(arr);
      }

      let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
      // Iterate the 64 rounds via the per-round `K`/`S` tables, so each round's
      // constant comes from the iterator (no `K[i]`/`S[i]` indexing). `g` selects
      // the message word; `m.get(g)` keeps that lookup checked.
      for (i, (&k, &s)) in K.iter().zip(S.iter()).enumerate() {
        let (f, g) = match i {
          0..=15 => ((b & c) | (!b & d), i),
          16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
          32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
          _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let mg = m.get(g).copied().unwrap_or(0);
        let f = f.wrapping_add(a).wrapping_add(k).wrapping_add(mg);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(f.rotate_left(s));
      }
      a0 = a0.wrapping_add(a);
      b0 = b0.wrapping_add(b);
      c0 = c0.wrapping_add(c);
      d0 = d0.wrapping_add(d);
    }

    // Concatenate the four state words as little-endian → the 16-byte digest.
    let mut out = [0u8; 16];
    for (dst, src) in out.chunks_exact_mut(4).zip([a0, b0, c0, d0]) {
      dst.copy_from_slice(&src.to_le_bytes());
    }
    out
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// `int_be` accumulates big-endian: `ApplicationRecordVersion` int16u
  /// `00 02` → 2, `00 04` → 4 (`IPTC.pm:1220-1227`).
  #[test]
  fn int_be_big_endian_u16() {
    assert_eq!(int_be(&[0x00, 0x02]), 2);
    assert_eq!(int_be(&[0x00, 0x04]), 4);
    assert_eq!(int_be(&[0x01, 0x00]), 256);
  }

  /// `exif_date` colonizes an 8-digit `YYYYMMDD` and passes anything else
  /// through (`Exif.pm:6068-6076`).
  #[test]
  fn exif_date_colonizes() {
    assert_eq!(exif_date("20020620"), "2002:06:20");
    assert_eq!(exif_date("20150327"), "2015:03:27");
    // Non-8-digit ⇒ unchanged.
    assert_eq!(exif_date("2015"), "2015");
  }

  /// `exif_time` inserts `HH:MM:SS` separators and colonizes the timezone
  /// (`Exif.pm:6085-6094`).
  #[test]
  fn exif_time_colonizes() {
    assert_eq!(exif_time("111726+0900"), "11:17:26+09:00");
    assert_eq!(exif_time("120000-0500"), "12:00:00-05:00");
    // No timezone tail.
    assert_eq!(exif_time("153000"), "15:30:00");
  }

  /// `urgency_print` labels the extremes and passes the mid digits through
  /// (`IPTC.pm:288-299`).
  #[test]
  fn urgency_print_labels() {
    assert_eq!(urgency_print("5"), "5 (normal urgency)");
    assert_eq!(urgency_print("1"), "1 (most urgent)");
    assert_eq!(urgency_print("3"), "3");
  }

  /// `strip_trailing_nulls` drops a trailing `\0` run (`IPTC.pm:1230`).
  #[test]
  fn strip_trailing_nulls_drops_run() {
    assert_eq!(strip_trailing_nulls(b"abc\0\0"), b"abc");
    assert_eq!(strip_trailing_nulls(b"abc"), b"abc");
    assert_eq!(strip_trailing_nulls(b"\0\0"), b"");
  }

  /// Latin1 high bytes decode to their Unicode code points only when present;
  /// pure-ASCII is identical (`IPTC.pm:1237-1239`).
  #[test]
  fn decode_string_latin1() {
    assert_eq!(
      decode_string(b"Ian Britton", Some(Charset::Latin)),
      "Ian Britton"
    );
    // 0xe9 = é in Latin1.
    assert_eq!(
      decode_string(&[0x63, 0x61, 0x66, 0xe9], Some(Charset::Latin)),
      "café"
    );
    // UTF-8 selected ⇒ pass-through (already-UTF-8 é bytes).
    assert_eq!(decode_string("café".as_bytes(), None), "café");
  }

  /// `handle_coded_charset` maps the UTF-8 escape to no-translation and the
  /// default to Latin (`IPTC.pm:994-1009`).
  #[test]
  fn coded_charset_utf8_vs_default() {
    assert_eq!(handle_coded_charset(b"\x1b%G"), None);
    assert_eq!(handle_coded_charset(b""), Some(Charset::Latin));
  }

  /// The ExifGPS.jpg IPTC block decodes to its 18 ApplicationRecord tags +
  /// the matching `09f7f522…` MD5 digest (the real fixture's `0x0404` block).
  #[test]
  fn exif_gps_block_parses() {
    // The exact 274-byte IPTC block from ExifGPS.jpg's APP13 0x0404 resource.
    let block: &[u8] = &[
      0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x02, 0x1c, 0x02, 0x78, 0x00, 0x0e, 0x43, 0x6f, 0x6d,
      0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1c, 0x02, 0x7a, 0x00,
      0x0b, 0x49, 0x61, 0x6e, 0x20, 0x42, 0x72, 0x69, 0x74, 0x74, 0x6f, 0x6e, 0x1c, 0x02, 0x69,
      0x00, 0x0e, 0x43, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
      0x73, 0x1c, 0x02, 0x50, 0x00, 0x0b, 0x49, 0x61, 0x6e, 0x20, 0x42, 0x72, 0x69, 0x74, 0x74,
      0x6f, 0x6e, 0x1c, 0x02, 0x55, 0x00, 0x0c, 0x50, 0x68, 0x6f, 0x74, 0x6f, 0x67, 0x72, 0x61,
      0x70, 0x68, 0x65, 0x72, 0x1c, 0x02, 0x6e, 0x00, 0x0b, 0x49, 0x61, 0x6e, 0x20, 0x42, 0x72,
      0x69, 0x74, 0x74, 0x6f, 0x6e, 0x1c, 0x02, 0x73, 0x00, 0x0c, 0x46, 0x72, 0x65, 0x65, 0x46,
      0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x1c, 0x02, 0x05, 0x00, 0x0e, 0x43, 0x6f, 0x6d,
      0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1c, 0x02, 0x37, 0x00,
      0x08, 0x32, 0x30, 0x30, 0x32, 0x30, 0x36, 0x32, 0x30, 0x1c, 0x02, 0x5a, 0x00, 0x01, 0x20,
      0x1c, 0x02, 0x5f, 0x00, 0x01, 0x20, 0x1c, 0x02, 0x65, 0x00, 0x0e, 0x55, 0x6e, 0x69, 0x74,
      0x65, 0x64, 0x20, 0x4b, 0x69, 0x6e, 0x67, 0x64, 0x6f, 0x6d, 0x1c, 0x02, 0x0f, 0x00, 0x03,
      0x42, 0x55, 0x53, 0x1c, 0x02, 0x14, 0x00, 0x0e, 0x43, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69,
      0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1c, 0x02, 0x0a, 0x00, 0x01, 0x35, 0x1c, 0x02,
      0x19, 0x00, 0x0e, 0x43, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
      0x6e, 0x73, 0x1c, 0x02, 0x74, 0x00, 0x1a, 0x69, 0x61, 0x6e, 0x20, 0x42, 0x72, 0x69, 0x74,
      0x74, 0x6f, 0x6e, 0x20, 0x2d, 0x20, 0x46, 0x72, 0x65, 0x65, 0x46, 0x6f, 0x74, 0x6f, 0x2e,
      0x63, 0x6f, 0x6d, 0x00,
    ];
    assert_eq!(block.len(), 274);
    assert_eq!(md5::hex(block), "09f7f522cf163e96cf778a81de1a9c2b");

    let mut meta = IptcMeta::default();
    process_iptc(block, &mut meta);
    // 18 ApplicationRecord tags (each occurs once ⇒ scalar).
    assert_eq!(meta.tags_pc.len(), 18);
    let find = |name: &str| -> Option<TagValue> {
      meta
        .tags_pc
        .iter()
        .find(|t| t.tag().name() == name)
        .map(|t| t.tag().value_ref().clone())
    };
    assert_eq!(find("ApplicationRecordVersion"), Some(TagValue::U64(2)));
    assert_eq!(
      find("Headline"),
      Some(TagValue::Str(SmolStr::new("Communications")))
    );
    assert_eq!(
      find("DateCreated"),
      Some(TagValue::Str(SmolStr::new("2002:06:20")))
    );
    assert_eq!(
      find("Urgency"),
      Some(TagValue::Str(SmolStr::new("5 (normal urgency)")))
    );
    assert_eq!(find("City"), Some(TagValue::Str(SmolStr::new(" "))));
    assert_eq!(
      find("CopyrightNotice"),
      Some(TagValue::Str(SmolStr::new("ian Britton - FreeFoto.com")))
    );
    // Every emitted tag is family-1 IPTC.
    assert!(
      meta
        .tags_pc
        .iter()
        .all(|t| t.tag().group_ref().family1() == "IPTC")
    );
  }

  /// The KS-2 IPTC block decodes ApplicationRecordVersion 4 + DateCreated +
  /// TimeCreated, MD5 `8ddc6730…`, and its `COM` segment strips the trailing
  /// null (the #318 prerequisite shape).
  #[test]
  fn ks2_block_parses() {
    let block: &[u8] = &[
      0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x04, 0x1c, 0x02, 0x37, 0x00, 0x08, 0x32, 0x30, 0x31,
      0x35, 0x30, 0x33, 0x32, 0x37, 0x1c, 0x02, 0x3c, 0x00, 0x0b, 0x31, 0x31, 0x31, 0x37, 0x32,
      0x36, 0x2b, 0x30, 0x39, 0x30, 0x30,
    ];
    assert_eq!(block.len(), 36);
    assert_eq!(md5::hex(block), "8ddc6730e07ee1144dc4cbfb4c9f2942");

    let mut meta = IptcMeta::default();
    process_iptc(block, &mut meta);
    let find = |name: &str| -> Option<TagValue> {
      meta
        .tags_pc
        .iter()
        .find(|t| t.tag().name() == name)
        .map(|t| t.tag().value_ref().clone())
    };
    assert_eq!(find("ApplicationRecordVersion"), Some(TagValue::U64(4)));
    assert_eq!(
      find("DateCreated"),
      Some(TagValue::Str(SmolStr::new("2015:03:27")))
    );
    assert_eq!(
      find("TimeCreated"),
      Some(TagValue::Str(SmolStr::new("11:17:26+09:00")))
    );

    // COM: "Lavc62.28.101\0" → trailing null stripped.
    meta.push_comment(b"Lavc62.28.101\0");
    assert_eq!(
      meta.comments.last().map(SmolStr::as_str),
      Some("Lavc62.28.101")
    );
  }

  /// A repeated List-flagged dataset (`Keywords`, 2:25) collapses to a
  /// `TagValue::List`; a single occurrence stays a scalar.
  #[test]
  fn list_dataset_accumulates() {
    // Two Keywords (2:25) fields: "a" then "bb".
    let block: &[u8] = &[
      0x1c, 0x02, 0x19, 0x00, 0x01, 0x61, // 2:25 "a"
      0x1c, 0x02, 0x19, 0x00, 0x02, 0x62, 0x62, // 2:25 "bb"
    ];
    let mut meta = IptcMeta::default();
    process_iptc(block, &mut meta);
    let kw = meta
      .tags_pc
      .iter()
      .find(|t| t.tag().name() == "Keywords")
      .map(|t| t.tag().value_ref().clone());
    assert_eq!(
      kw,
      Some(TagValue::List(std::vec![
        TagValue::Str(SmolStr::new("a")),
        TagValue::Str(SmolStr::new("bb")),
      ]))
    );
  }

  /// `process_app13` walks the full `Photoshop 3.0\0` + 8BIM 0x0404 path,
  /// computing the digest and the IPTC tags (end-to-end over the IRB).
  #[test]
  fn process_app13_end_to_end() {
    // Build a minimal APP13 payload: "Photoshop 3.0\0" + one 8BIM 0x0404 block
    // wrapping a tiny IPTC stream (just ApplicationRecordVersion 2).
    let iptc: &[u8] = &[0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x02];
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    payload.extend_from_slice(b"8BIM"); // type
    payload.extend_from_slice(&[0x04, 0x04]); // resource id 0x0404
    payload.push(0x00); // name length 0
    payload.push(0x00); // pad (even name)
    payload.extend_from_slice(&(iptc.len() as u32).to_be_bytes()); // size
    payload.extend_from_slice(iptc);
    if iptc.len() & 1 == 1 {
      payload.push(0x00); // even-pad the data
    }

    let mut meta = IptcMeta::default();
    process_app13(&payload, &mut meta);
    assert!(meta.digest.is_some());
    assert_eq!(meta.tags_pc.len(), 1);
    assert_eq!(
      meta.tags_pc.first().map(|t| t.tag().name()),
      Some("ApplicationRecordVersion")
    );
    assert_eq!(meta.digest.as_deref(), Some(md5::hex(iptc).as_str()));
  }

  /// Push one IRB resource block (`Type` + id + Pascal-name [padded even] +
  /// size + data [padded even]) onto `out`, mirroring `ProcessPhotoshop`'s
  /// layout (`Photoshop.pm:1049-1108`). `name` is the (already-even-or-odd)
  /// Pascal-name bytes; the length byte + name is padded to an even total.
  fn push_irb_block(out: &mut std::vec::Vec<u8>, ty: &[u8; 4], id: u16, name: &[u8], data: &[u8]) {
    out.extend_from_slice(ty);
    out.extend_from_slice(&id.to_be_bytes());
    // Pascal name: length byte + bytes, padded to an even TOTAL
    // (`++$pos unless $nameLen & 0x01`).
    let name_len = name.len() as u8;
    out.push(name_len);
    out.extend_from_slice(name);
    if name_len & 0x01 == 0 {
      out.push(0x00);
    }
    // Size (4 bytes BE) + data, padded to an even length
    // (`$size += 1 if $size & 0x01`).
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    if data.len() & 0x01 == 1 {
      out.push(0x00);
    }
  }

  /// A `PHUT` (or `DCSR`/`AgHg`/`MeSa`) resource block BEFORE the `8BIM 0x0404`
  /// IPTC block is a valid Photoshop IRB layout (`Photoshop.pm:1059`): the
  /// scanner must route the non-`8BIM` block to `Photoshop::Unknown` and KEEP
  /// SCANNING, reaching the IPTC + emitting `CurrentIPTCDigest`. Regression for
  /// the abort-on-first-non-8BIM bug.
  #[test]
  fn phut_before_iptc_is_skipped() {
    let iptc: &[u8] = &[0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x02];
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    // A leading PHUT resource (ImageReady) carrying arbitrary data + a
    // non-empty Pascal name (exercises the even-name padding) — must be skipped.
    push_irb_block(
      &mut payload,
      b"PHUT",
      0x0bb7,
      b"PH",
      &[0xde, 0xad, 0xbe, 0xef],
    );
    // Then the real 8BIM 0x0404 IPTC resource (empty name → one pad byte).
    push_irb_block(&mut payload, b"8BIM", 0x0404, b"", iptc);

    let mut meta = IptcMeta::default();
    process_app13(&payload, &mut meta);
    // The PHUT was skipped and the IPTC reached: digest + the one tag.
    assert_eq!(meta.digest.as_deref(), Some(md5::hex(iptc).as_str()));
    assert_eq!(meta.tags_pc.len(), 1);
    assert_eq!(
      meta.tags_pc.first().map(|t| t.tag().name()),
      Some("ApplicationRecordVersion")
    );
  }

  /// A `0x0404` ID under a non-`8BIM` resource is NOT IPTC (the `IPTCData`
  /// SubDirectory lives only in the main `8BIM` table, `Photoshop.pm:1057-1060`)
  /// — the scanner skips it, then decodes the genuine `8BIM 0x0404` that
  /// follows.
  #[test]
  fn phut_0x0404_is_not_iptc() {
    let iptc: &[u8] = &[0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x04];
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    // A DCSR block with the IPTC resource ID 0x0404 — must NOT be parsed as IPTC
    // (it keys against Photoshop::Unknown, not the main IPTCData SubDirectory).
    push_irb_block(
      &mut payload,
      b"DCSR",
      0x0404,
      b"",
      &[0x1c, 0x02, 0x00, 0x00, 0x02, 0xff, 0xff],
    );
    // The real IPTC follows under 8BIM.
    push_irb_block(&mut payload, b"8BIM", 0x0404, b"", iptc);

    let mut meta = IptcMeta::default();
    process_app13(&payload, &mut meta);
    // Only the 8BIM 0x0404 produced the digest + tags; the DCSR 0x0404 was skipped.
    assert_eq!(meta.digest.as_deref(), Some(md5::hex(iptc).as_str()));
    assert_eq!(meta.tags_pc.len(), 1);
    assert_eq!(
      meta.tags_pc.first().map(|t| t.tag().value_ref().clone()),
      Some(TagValue::U64(4))
    );
  }

  /// A genuinely-invalid (non-`8BIM`, non-`PHUT`/`DCSR`/`AgHg`/`MeSa`) signature
  /// stops the scan (`Photoshop.pm:1061-1064` `last`) — anything after a corrupt
  /// resource is untrusted, so no IPTC beyond it is decoded.
  #[test]
  fn bad_signature_stops_scan() {
    let iptc: &[u8] = &[0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x02];
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    // A bogus signature aborts the walk; the trailing 8BIM 0x0404 is never read.
    push_irb_block(&mut payload, b"XXXX", 0x0001, b"", &[0x00, 0x00]);
    push_irb_block(&mut payload, b"8BIM", 0x0404, b"", iptc);

    let mut meta = IptcMeta::default();
    process_app13(&payload, &mut meta);
    assert!(meta.digest.is_none());
    assert!(meta.tags_pc.is_empty());
  }

  /// A PHUT block whose declared `Size` runs past the buffer (a malformed /
  /// truncated resource) stops the walk GRACEFULLY — no panic, no OOB read
  /// (`Photoshop.pm:1079-1082` `last`), honoring the module's
  /// `deny(indexing_slicing)`.
  #[test]
  fn short_phut_resource_stops_gracefully() {
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    // PHUT, id, empty name (1 len byte + 1 pad), then a size of 0xffff with only
    // a couple of data bytes present ⇒ the `block` bounds check fails ⇒ stop.
    payload.extend_from_slice(b"PHUT");
    payload.extend_from_slice(&0x0001u16.to_be_bytes());
    payload.push(0x00); // name length 0
    payload.push(0x00); // pad
    payload.extend_from_slice(&0xffffu32.to_be_bytes()); // bogus huge size
    payload.extend_from_slice(&[0x11, 0x22]); // far too few data bytes

    let mut meta = IptcMeta::default();
    // Must not panic; nothing decoded.
    process_app13(&payload, &mut meta);
    assert!(meta.digest.is_none());
    assert!(meta.tags_pc.is_empty());
  }

  /// Build a full single-`APP13` Photoshop payload (`Photoshop 3.0\0` + one
  /// `8BIM 0x0404` IRB wrapping `iptc`), so a split test can slice it across a
  /// segment boundary and prove the reassembly reconstructs it byte-for-byte.
  fn ps_app13_payload(iptc: &[u8]) -> std::vec::Vec<u8> {
    let mut payload: std::vec::Vec<u8> = std::vec::Vec::new();
    payload.extend_from_slice(b"Photoshop 3.0\0");
    push_irb_block(&mut payload, b"8BIM", 0x0404, b"", iptc);
    payload
  }

  /// A `0x0404` IPTC block split across TWO consecutive `Photoshop 3.0\0`
  /// `APP13` segments (each JPEG `APPn` is ~64 KB-capped) must reassemble — in
  /// file order, with each continuation segment's 14-byte header stripped — into
  /// the SAME buffer a single `APP13` would carry (`$combinedSegData`,
  /// `ExifTool.pm:8375-8385`), so the full IPTC tags + the `CurrentIPTCDigest`
  /// MD5 (over the reassembled `0x0404` block) match the unsplit decode exactly.
  #[test]
  fn split_app13_reassembles() {
    // Two ApplicationRecord datasets so the IRB body is long enough to split:
    // ApplicationRecordVersion (2:00) = 4, then ObjectName (2:05) = "Split".
    let iptc: &[u8] = &[
      0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x04, // 2:00 version 4
      0x1c, 0x02, 0x05, 0x00, 0x05, b'S', b'p', b'l', b'i', b't', // 2:05 ObjectName
    ];
    let full = ps_app13_payload(iptc);

    // The unsplit reference decode (a lone-segment run reassembles to itself).
    let mut want = IptcMeta::default();
    super::process_app13(&full, &mut want);
    assert!(want.digest.is_some());
    assert_eq!(want.tags_pc.len(), 2);

    // Split the FULL payload at a boundary inside the IRB body (well past the
    // 14-byte `Photoshop 3.0\0` header so the second segment carries IRB bytes),
    // then re-prefix the second half with its own `Photoshop 3.0\0` header — the
    // exact wire shape of a 2-segment APP13 run.
    let cut = PS_APP13_HDR.len() + 12; // mid-IRB (inside the IPTC data region)
    let (head, tail) = full.split_at(cut);
    let mut seg1: std::vec::Vec<u8> = std::vec::Vec::new();
    seg1.extend_from_slice(PS_APP13_HDR);
    seg1.extend_from_slice(tail);
    let run: [&[u8]; 2] = [head, &seg1];

    let mut got = IptcMeta::default();
    super::reassemble_app13_run(&run, &mut got);

    // The reassembled decode equals the unsplit one: same digest + same tags.
    assert_eq!(got.digest, want.digest);
    assert_eq!(got.digest.as_deref(), Some(md5::hex(iptc).as_str()));
    assert_eq!(got.tags_pc.len(), 2);
    let find = |meta: &IptcMeta, name: &str| -> Option<TagValue> {
      meta
        .tags_pc
        .iter()
        .find(|t| t.tag().name() == name)
        .map(|t| t.tag().value_ref().clone())
    };
    assert_eq!(
      find(&got, "ApplicationRecordVersion"),
      Some(TagValue::U64(4))
    );
    assert_eq!(
      find(&got, "ObjectName"),
      Some(TagValue::Str(SmolStr::new("Split")))
    );
  }

  /// A single-segment run reassembles to that segment UNCHANGED (no
  /// concatenation, no extra header) — the realistic IPTC layout
  /// (`ExifGPS.jpg` / Pentax K-S2). Guards the fast path that keeps single-`APP13`
  /// output byte-identical.
  #[test]
  fn single_segment_run_is_identity() {
    let iptc: &[u8] = &[0x1c, 0x02, 0x00, 0x00, 0x02, 0x00, 0x02];
    let full = ps_app13_payload(iptc);

    let mut direct = IptcMeta::default();
    super::process_app13(&full, &mut direct);

    let mut viarun = IptcMeta::default();
    super::reassemble_app13_run(&[&full], &mut viarun);

    assert_eq!(direct.digest, viarun.digest);
    assert_eq!(direct.tags_pc.len(), viarun.tags_pc.len());
    assert_eq!(viarun.digest.as_deref(), Some(md5::hex(iptc).as_str()));
  }

  /// MD5 of the empty input + a known vector ("abc") — guards the RFC 1321
  /// routine.
  #[test]
  fn md5_known_vectors() {
    assert_eq!(md5::hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5::hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
      md5::hex(b"The quick brown fox jumps over the lazy dog"),
      "9e107d9d372bb6826bd81d3542a419d6"
    );
  }
}
