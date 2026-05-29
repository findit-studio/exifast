// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `MakerNotes.pm`'s `@Image::ExifTool::MakerNotes::Main` dispatch table —
//! the vendor-signature/make matcher that maps a raw MakerNote blob (the
//! ExifIFD's 0x927c value) to its [`Vendor`] + the `SubDirectory`
//! `Start`/`Base`/`ByteOrder` directives that drive the child IFD walk.
//!
//! Faithful to bundled `MakerNotes.pm` lines 35-1127. Each entry of the
//! Perl array becomes one arm in [`dispatch`] (`MakerNotes.pm:38-46` →
//! [`Vendor::Apple`], etc.). The match order is the bundled file's order:
//! the FIRST condition that matches wins (ExifTool's `Condition` evaluation
//! is sequential — `ExifTool.pm:9395-9405`).
//!
//! ## Conditions modelled
//!
//! Bundled conditions have two inputs (and one obscure third):
//!
//! - `$$valPt =~ /…/`: a regex on the raw MakerNote bytes. The port runs
//!   the equivalent byte-prefix / pattern match in [`signature_matches`]
//!   below. Every regex is anchored at start (`/^…/`) — bundled relies on
//!   this convention.
//! - `$$self{Make}` / `$$self{Model}`: a regex on the parent's `Make` /
//!   `Model` string (already parsed from IFD0 — `Exif.pm:585`/`:599`). The
//!   port carries the Make string into [`dispatch`] as `make`.
//! - `$$self{TIFF_TYPE} eq 'SRW'`: bundled's "is this a Samsung SRW raw?"
//!   probe (`ExifTool.pm:8715` sets `TIFF_TYPE` from the detected file
//!   type). [`dispatch`] takes it as the `tiff_type` input and the
//!   `MakerNoteSamsung2` arm consumes it (`MakerNotes.pm:969`). The
//!   current Exif-block hook does not yet have the container's file type
//!   plumbed through the IFD walker, so it passes `None`; the Samsung2 SRW
//!   clause then degrades to its EXIF-format-magic clause (`MakerNotes.pm:
//!   970`), which is faithful for every Samsung body whose blob carries
//!   the magic. The SRW-WITHOUT-magic case (a Samsung `.srw` raw whose
//!   MakerNote blob lacks the magic) is the only residual Phase-1 gap, and
//!   it closes the moment a caller threads `tiff_type = Some("SRW")`.
//!
//! ## Subdir parsing — `SubDirectory` directives
//!
//! Each `SubDirectory` entry in `MakerNotes.pm` carries a set of
//! directives. Each dispatch arm below encodes, as a
//! [`DetectedMakerNote`], the directives Phase 1 MODELS:
//!
//! - `body_offset` (bundled `Start`), `offset_pt` (bundled `OffsetPt`),
//!   `base_rule` (bundled `Base`), `byte_order` (bundled `ByteOrder`),
//!   `not_ifd` (bundled `NotIFD`), `fix_base` (bundled `FixBase` — flag
//!   only), `entry_based` (bundled `EntryBased`).
//!
//! Directives Phase 1 does NOT model (deferred Phase-2+ follow-ups):
//!
//! - the `FixBase` offset-correction HEURISTIC itself (only the flag is
//!   captured), `FixOffsets` (`MakerNotes.pm:158`/`:1003`), `Validate`,
//!   `ProcessProc`/`WriteProc`.
//!
//! Cite each modelled directive inline (the `MakerNotes.pm:<line>`
//! comment).
//!
//! Phase 1's job is ONLY to surface these directives — Phase 2+ feeds
//! them to the IFD walker. So [`dispatch`] is a SIGNATURE classifier, not
//! a walker; it does NOT recurse into the body.

use super::detected::{BaseRule, ChildByteOrder, DetectedMakerNote};
use super::vendor::Vendor;
use crate::exif::ifd::ByteOrder;

/// Dispatch a raw MakerNote blob to its [`Vendor`] + `SubDirectory`
/// directives.
///
/// Inputs (faithful to `MakerNotes.pm`'s `Condition` evaluation):
///
/// - `blob`: the raw MakerNote bytes — bundled's `$$valPt`.
/// - `make`: the parent's `$$self{Make}` (parsed from IFD0; `None` if
///   the parent walker hadn't seen `Make` yet — degenerate but tolerated).
/// - `model`: the parent's `$$self{Model}` (parsed from IFD0; `None`
///   like `make`).
/// - `tiff_type`: the container's `$$self{TIFF_TYPE}` (`ExifTool.pm:8715`
///   `$$self{TIFF_TYPE} = $fileType`) — the detected file type of the
///   enclosing TIFF stream (`"SRW"`, `"NEF"`, `"TIFF"`, `"APP1"`, …). The
///   ONLY arm that reads it is `MakerNoteSamsung2` (`MakerNotes.pm:969`
///   `$$self{TIFF_TYPE} eq 'SRW'`). Pass `None` when the file type is not
///   known to the caller (the current Exif-block hook does not yet thread
///   `TIFF_TYPE`; see [`crate::exif`]'s MakerNote dispatch) — the Samsung2
///   SRW clause then degrades to its signature clause, which is faithful
///   for every Samsung body that carries the EXIF-format magic.
///
/// Returns a [`DetectedMakerNote`]. The dispatcher is TOTAL —
/// [`Vendor::Unknown`] is the catch-all for blobs no signature/make
/// matches (`MakerNotes.pm:1117-1126` `MakerNoteUnknown`).
///
/// ## Match order
///
/// Bundled walks `@Image::ExifTool::MakerNotes::Main` top-to-bottom; the
/// first matching condition wins. Some early-vs-late ordering matters
/// (the Nikon comment at `MakerNotes.pm:50-51` explicitly notes the
/// Nikon signature must be tested BEFORE Apple — Nikon Capture NX
/// generates NEF images with Nikon MakerNotes copied from non-Nikon
/// cameras, and the Apple signature could pick those up). The port
/// preserves this order line-by-line.
#[must_use]
pub fn dispatch(
  blob: &[u8],
  make: Option<&str>,
  model: Option<&str>,
  tiff_type: Option<&str>,
) -> DetectedMakerNote {
  // ----- Nikon FIRST (`MakerNotes.pm:48-58` — must precede Apple, see
  // the `MakerNoteNikon` comment "must check Nikon signature first
  // because Nikon Capture NX can generate NEF images containing Nikon
  // maker notes from JPEG images of any camera model").
  if starts_with(blob, b"Nikon\x00\x02") {
    return DetectedMakerNote::new(
      Vendor::Nikon,
      18,                            // `Start => '$valuePtr + 18'` (`MakerNotes.pm:55`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:56`)
      ChildByteOrder::Unknown,       // `ByteOrder => 'Unknown'` (`MakerNotes.pm:57`)
      false,
    );
  }

  // ----- Apple iOS — `MakerNoteApple` (`MakerNotes.pm:38-46`).
  if starts_with(blob, b"Apple iOS\x00") {
    return DetectedMakerNote::new(
      Vendor::Apple,
      14,                             // `Start => '$valuePtr + 14'` (`MakerNotes.pm:42`)
      BaseRule::RelativeToStart(-14), // `Base => '$start - 14'` (`MakerNotes.pm:43`)
      ChildByteOrder::Unknown,        // `ByteOrder => 'Unknown'` (`MakerNotes.pm:44`)
      false,
    );
  }

  // ----- Canon — `MakerNoteCanon` (`MakerNotes.pm:60-68`).
  // No signature; identifies by Make only. `$$self{Make} =~ /^Canon/`.
  if make_starts_with(make, "Canon") {
    return DetectedMakerNote::new(
      Vendor::Canon,
      0,                       // No `Start` directive — defaults to `$valuePtr` (no header)
      BaseRule::Inherit,       // No `Base` directive
      ChildByteOrder::Unknown, // `ByteOrder => 'Unknown'` (`MakerNotes.pm:67`)
      false,
    );
  }

  // ----- Casio (newer) — `MakerNoteCasio2` (`MakerNotes.pm:81-91`).
  // `$$valPt =~ /^(QVC|DCI)\0/`.
  // (Tested BEFORE `MakerNoteCasio` because the negative-lookahead in
  // `MakerNoteCasio` excludes these prefixes — bundled puts Casio2 after,
  // but its conditions are mutually exclusive, so the port's order is
  // observationally identical.)
  if starts_with(blob, b"QVC\x00") || starts_with(blob, b"DCI\x00") {
    return DetectedMakerNote::new(
      Vendor::Casio,
      6, // `Start => '$valuePtr + 6'` (`MakerNotes.pm:88`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    )
    .with_fix_base(); // `FixBase => 1` (`MakerNotes.pm:90`)
  }

  // ----- Casio (older) — `MakerNoteCasio` (`MakerNotes.pm:71-79`).
  // `$$self{Make}=~/^CASIO/ and $$valPt!~/^(QVC|DCI)\0/`. The Make anchor is
  // case-SENSITIVE (no `/i` flag, unlike Nikon3/Minolta/Sigma/Kodak which DO
  // carry `/i`), so this uses the case-sensitive [`make_starts_with`], NOT
  // [`make_starts_with_ci`] — a CI gate here would be BROADER than Perl
  // (would wrongly capture a lowercase `casio…` Make). Real Casio bodies
  // report `Make => "CASIO COMPUTER CO.,LTD."` (uppercase). The
  // `$$valPt!~/^(QVC|DCI)\0/` negative guard is satisfied by ORDER: the
  // Casio2 `QVC\0`/`DCI\0` arm above already returned for those prefixes.
  if make_starts_with(make, "CASIO") {
    return DetectedMakerNote::new(
      Vendor::Casio,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- DJI Info — `MakerNoteDJIInfo` (`MakerNotes.pm:93-97`).
  // `$$valPt =~ /^\[ae_dbg_info:/` ; `NotIFD => 1`.
  if starts_with(blob, b"[ae_dbg_info:") {
    return DetectedMakerNote::new(
      Vendor::Dji,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true, // `NotIFD => 1`
    );
  }

  // ----- DJI — `MakerNoteDJI` (`MakerNotes.pm:99-106`).
  // `$$self{Make} eq "DJI" and $$valPt !~ /^(...\@AMBA|DJI)/s`.
  // The negative-lookahead carves out two GoPro-style signatures DJI
  // shares with action-cam relatives. Phase 1 routes the carved-out
  // shapes to `Unknown` (Phase 4 / deferred).
  if make_eq(make, "DJI") && !starts_with(blob, b"DJI") && !ambarella_at_amba(blob) {
    return DetectedMakerNote::new(
      Vendor::Dji,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:104`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- FLIR — `MakerNoteFLIR` (`MakerNotes.pm:108-117`).
  // `$$self{Make} =~ /^(FLIR Systems|Teledyne FLIR)/`.
  if make_starts_with(make, "FLIR Systems") || make_starts_with(make, "Teledyne FLIR") {
    return DetectedMakerNote::new(
      Vendor::Flir,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:114`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- FujiFilm — `MakerNoteFujiFilm` (`MakerNotes.pm:118-134`).
  // `$$valPt =~ /^(FUJIFILM|GENERALE)/`. Fuji has NO `Start` directive —
  // `OffsetPt => '$valuePtr+8'` (`MakerNotes.pm:128`) means a 4-byte IFD
  // POINTER is read at in-blob offset 8 (NOT "skip 8 bytes"); `Base =>
  // '$start'` (`:131`) anchors the child to the blob body. So
  // `offset_pt=Some(8)`, `body_offset=0`.
  if starts_with(blob, b"FUJIFILM") || starts_with(blob, b"GENERALE") {
    return DetectedMakerNote::new(
      Vendor::Fuji,
      0,                                           // no `Start` directive (`MakerNotes.pm:118-134`)
      BaseRule::StartItself,                       // `Base => '$start'` (`MakerNotes.pm:131`)
      ChildByteOrder::Explicit(ByteOrder::Little), // `ByteOrder => 'LittleEndian'` (`MakerNotes.pm:132`)
      false,
    )
    .with_offset_pt(8); // `OffsetPt => '$valuePtr+8'` (`MakerNotes.pm:128`)
  }

  // ----- GE2 — `MakerNoteGE2` (`MakerNotes.pm:146-160`).
  // `$$valPt =~ /^GE\x0c\0\0\0\x16\0\0\0/`.
  // (Tested BEFORE `MakerNoteGE` — its more specific signature.)
  if starts_with(blob, b"GE\x0c\x00\x00\x00\x16\x00\x00\x00") {
    return DetectedMakerNote::new(
      Vendor::Ge,
      12,                            // `Start => '$valuePtr + 12'` (`MakerNotes.pm:154`)
      BaseRule::RelativeToStart(-6), // `Base => '$start - 6'` (`MakerNotes.pm:155`)
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:156`
      false,
    );
  }

  // ----- GE — `MakerNoteGE` (`MakerNotes.pm:135-145`).
  // `$$valPt =~ /^GE(\0\0|NIC\0)/`.
  if starts_with(blob, b"GE\x00\x00") || starts_with(blob, b"GENIC\x00") {
    return DetectedMakerNote::new(
      Vendor::Ge,
      18,                // `Start => '$valuePtr + 18'` (`MakerNotes.pm:140`)
      BaseRule::Inherit, // no explicit `Base` line
      ChildByteOrder::Unknown,
      false,
    )
    .with_fix_base(); // `FixBase => 1` (`MakerNotes.pm:141`; `AutoFix => 1`
    // and GE2's `FixOffsets`, `MakerNotes.pm:158`, deferred)
  }

  // ----- Google HDR+ — `MakerNoteGoogle` (`MakerNotes.pm:161-167`).
  // `$$valPt =~ /^HDRP[\x02\x03]/` ; `NotIFD => 1`.
  if blob.len() >= 5 && &blob[..4] == b"HDRP" && (blob[4] == 0x02 || blob[4] == 0x03) {
    return DetectedMakerNote::new(
      Vendor::Google,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true, // `NotIFD => 1`
    );
  }

  // ----- Hasselblad — `MakerNoteHasselblad` (`MakerNotes.pm:169-182`).
  // `$$self{Make} eq "Hasselblad"`. `Base => 0` is a LITERAL absolute 0
  // (`MakerNotes.pm:176` — the bundled comment notes "avoids warnings
  // since maker notes are not self-contained"), NOT an inherited base.
  if make_eq(make, "Hasselblad") {
    return DetectedMakerNote::new(
      Vendor::Hasselblad,
      0,                    // `Start => '$valuePtr'` (`MakerNotes.pm:175`)
      BaseRule::Literal(0), // `Base => 0` (literal! `MakerNotes.pm:176`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- HP family — `MakerNoteHP` (`MakerNotes.pm:185-192`).
  // `$$valPt =~ /^(Hewlett-Packard|Vivitar)/`.
  if starts_with(blob, b"Hewlett-Packard") || starts_with(blob, b"Vivitar") {
    return DetectedMakerNote::new(
      Vendor::Hp,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- HP2 — `MakerNoteHP2` (`MakerNotes.pm:194-204`).
  // `$$valPt =~ /^610[\0-\4]/` ; `NotIFD => 1`.
  if blob.len() >= 4 && &blob[..3] == b"610" && blob[3] <= 0x04 {
    return DetectedMakerNote::new(
      Vendor::Hp,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:201`)
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:202`
      true,                                        // `NotIFD => 1`
    );
  }

  // ----- HP4 — `MakerNoteHP4` (`MakerNotes.pm:205-213`).
  // `$$valPt =~ /^IIII[\x04|\x05]\0/`. (Bundled has a Perl typo
  // `[\x04|\x05]` — a CHARACTER class that includes `|`, `\x04`,
  // `\x05` — the port matches the same set faithfully.)
  if blob.len() >= 6
    && &blob[..4] == b"IIII"
    && (blob[4] == 0x04 || blob[4] == 0x05 || blob[4] == b'|')
    && blob[5] == 0x00
  {
    return DetectedMakerNote::new(
      Vendor::Hp,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:210`)
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:212`
      true,                                        // `NotIFD => 1`
    );
  }

  // ----- HP6 — `MakerNoteHP6` (`MakerNotes.pm:215-224`).
  // `$$valPt =~ /^IIII\x06\0/`.
  if blob.len() >= 6 && &blob[..4] == b"IIII" && blob[4] == 0x06 && blob[5] == 0x00 {
    return DetectedMakerNote::new(
      Vendor::Hp,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little),
      true,
    );
  }

  // ----- ISL — `MakerNoteISL` (`MakerNotes.pm:225-234`).
  // `$$valPt =~ /^ISLMAKERNOTE000\0/`.
  if starts_with(blob, b"ISLMAKERNOTE000\x00") {
    return DetectedMakerNote::new(
      Vendor::Isl,
      24,                            // `Start => '$valuePtr + 24'` (`MakerNotes.pm:231`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:232`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- JVC binary — `MakerNoteJVC` (`MakerNotes.pm:236-243`).
  // `$$valPt=~/^JVC /`.
  if starts_with(blob, b"JVC ") {
    return DetectedMakerNote::new(
      Vendor::Jvc,
      4, // `Start => '$valuePtr + 4'` (`MakerNotes.pm:241`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- JVC text — `MakerNoteJVCText` (`MakerNotes.pm:245-251`).
  // `$$self{Make}=~/^(JVC|Victor)/ and $$valPt=~/^VER:/`. `NotIFD => 1`.
  if (make_starts_with(make, "JVC") || make_starts_with(make, "Victor"))
    && starts_with(blob, b"VER:")
  {
    return DetectedMakerNote::new(
      Vendor::Jvc,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true, // `NotIFD => 1`
    );
  }

  // ----- Kodak family — bundled has SEVENTEEN arms `MakerNoteKodak1a`..
  // `MakerNoteKodak12` + `MakerNoteKodakUnknown` (`MakerNotes.pm:253-481`).
  // Phase 1 collapses the per-variant TAG TABLES (`Kodak::Type2`..`Type11`,
  // `Kodak::Unknown`) to `Vendor::Kodak` — the table fan-out is the deferred
  // long-tail (phases 2-4). But every arm's CONDITION + `SubDirectory`
  // directives (`Start`/`Base`/`ByteOrder`/`NotIFD`) are ported FAITHFULLY,
  // one Rust arm per Perl entry, in EXACT `%Main` top-down order (first match
  // wins). This is NOT a single Make/Model-gated block: two Kodak arms
  // (`Kodak2`, `Kodak9`) have a SIGNATURE-ONLY `Condition` (no Make/Model
  // test), so they MUST fire for non-Kodak makes too (e.g. an HP, Pentax or
  // Minolta body carrying a Kodak2-shaped blob — `MakerNotes.pm:274` "used by
  // various Kodak, HP, Pentax and Minolta models"). Gating the whole block on
  // `Make=~/Kodak/i || Model=~/.../` would hide those two — the R2 finding.
  //
  // Ordering vs OTHER vendors: the whole Kodak block sits between `JVCText`
  // (`MakerNotes.pm:245`) and `Kyocera` (`:483`) in `%Main`, so every arm
  // above (Apple..JVC) out-ranks it. The two signature-only arms' patterns
  // are disjoint from every earlier arm: `Kodak2`'s `\x01\0…` / `…Eastman
  // Kodak` and `Kodak9`'s `IIII[\x02\x03]\0` don't collide with HP4
  // (`IIII[\x04|\x05]\0`), HP6 (`IIII\x06\0`) or any earlier prefix. And
  // `PhaseOne` (`IIII.waR`, `:840`) is LATER than Kodak in `%Main`, so
  // `Kodak9` correctly out-ranks it (its position here, before the Pentax/
  // PhaseOne arms below, preserves that).
  //
  // Per-arm gate type is annotated inline: SIG-ONLY (no make/model),
  // MAKE+SIG, MAKE+MODEL, MODEL+SIG, or MAKE.

  // Kodak1a — MAKE+SIG (`MakerNotes.pm:254-262`):
  // `Make=~/^EASTMAN KODAK/ and valPt=~/^KDK INFO/`. NotIFD, BE, Start+8.
  if make_eastman_kodak_uc(make) && starts_with(blob, b"KDK INFO") {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:259`)
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:260`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:256`)
    );
  }
  // Kodak1b — MAKE+SIG (`MakerNotes.pm:263-271`):
  // `Make=~/^EASTMAN KODAK/ and valPt=~/^KDK/`. NotIFD, LE, Start+8.
  if make_eastman_kodak_uc(make) && starts_with(blob, b"KDK") {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:269`)
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:270`
      true,                                        // `NotIFD => 1` (`MakerNotes.pm:266`)
    );
  }
  // Kodak2 — SIG-ONLY (`MakerNotes.pm:273-285`, "used by various Kodak, HP,
  // Pentax and Minolta models"): `valPt=~/^.{8}Eastman Kodak/s or
  // valPt=~/^\x01\0[\0\x01]\0\0\0\x04\0[a-zA-Z]{4}/`. NO Make/Model gate —
  // fires for ANY make. NotIFD, BE, no Start/Base. (`Kodak::Type2` table is
  // the deferred long-tail; the directives here are exact.)
  if is_kodak2_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0, // no `Start` directive
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:283`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:280`)
    );
  }
  // Kodak3 — MAKE+SIG (`MakerNotes.pm:286-300`): `Make=~/^EASTMAN KODAK/ and
  // valPt=~/^(?!MM|II).{12}\x07/s and valPt!~/^(MM|II|AOC)/`. NotIFD, BE.
  if make_eastman_kodak_uc(make) && is_kodak3_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:298`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:295`)
    );
  }
  // Kodak4 — MAKE+SIG (`MakerNotes.pm:301-313`): `Make=~/^Eastman Kodak/
  // (TITLE case) and valPt=~/^.{41}JPG/s and valPt!~/^(MM|II|AOC)/`. NotIFD,
  // BE.
  if make_eastman_kodak_tc(make) && is_kodak4_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:311`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:308`)
    );
  }
  // Kodak5 — MAKE + (MODEL or SIG) (`MakerNotes.pm:314-327`):
  // `Make=~/^EASTMAN KODAK/ and (Model=~/CX(4200|4230|4300|4310|6200|6230)/
  //  or valPt=~/^\0(\x1a\x18|\x3a\x08|\x59\xf8|\x14\x80)\0/)`. NotIFD, BE.
  if make_eastman_kodak_uc(make) && (model_matches_kodak5(model) || is_kodak5_sig(blob)) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:325`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:322`)
    );
  }
  // Kodak6a — MAKE+MODEL (`MakerNotes.pm:328-339`):
  // `Make=~/^EASTMAN KODAK/ and Model=~/DX3215/`. NotIFD, BE.
  if make_eastman_kodak_uc(make) && model_contains(model, "DX3215") {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:337`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:334`)
    );
  }
  // Kodak6b — MAKE+MODEL (`MakerNotes.pm:340-351`):
  // `Make=~/^EASTMAN KODAK/ and Model=~/DX3700/`. NotIFD, LE.
  if make_eastman_kodak_uc(make) && model_contains(model, "DX3700") {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:349`
      true,                                        // `NotIFD => 1` (`MakerNotes.pm:346`)
    );
  }
  // Kodak7 — MAKE+SIG (`MakerNotes.pm:352-366`): `Make=~/Kodak/i and
  // valPt=~/^[CK][A-Z\d]{3} ?[A-Z\d]{1,2}\d{2}[A-Z\d]\d{4}[ \0]/` (a
  // serial-number shape). NotIFD, LE.
  if make_matches_kodak(make) && is_kodak7_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:364`
      true,                                        // `NotIFD => 1` (`MakerNotes.pm:361`)
    );
  }
  // Kodak8a — MAKE+SIG (`MakerNotes.pm:367-381`): `Make=~/Kodak/i and
  // (valPt=~/^\0[\x02-\x7f]..\0[\x01-\x0c]\0\0/s or
  //  valPt=~/^[\x02-\x7f]\0..[\x01-\x0c]\0..\0\0/s)` (IFD-shaped). IFD
  // (no NotIFD), Unknown order, no Start/Base.
  if make_matches_kodak(make) && is_kodak8a_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown, // `MakerNotes.pm:379`
      false,
    );
  }
  // Kodak8b — MAKE+SIG (`MakerNotes.pm:382-399`): `Make=~/Kodak/i and
  // valPt=~/^MM\0\x2a\0\0\0\x08\0.\0\0/` (PixPro AZ251/AZ361/AZ262/AZ521).
  // IFD, BE, Start+8, Base $start-8. (`ProcessKodakPatch` 2-byte-count
  // patch is deferred — the directive set is exact.)
  if make_matches_kodak(make) && is_kodak8b_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8,                                        // `Start => '$valuePtr + 8'` (`MakerNotes.pm:396`)
      BaseRule::RelativeToStart(-8),            // `Base => '$start - 8'` (`MakerNotes.pm:397`)
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:395`
      false,
    );
  }
  // Kodak8c — MAKE+SIG (`MakerNotes.pm:400-414`): `Make=~/Kodak/i and
  // valPt=~/^(MM\0\x2a\0\0\0\x08|II\x2a\0\x08\0\0\0)/` (TIFF-shaped). IFD,
  // Unknown order, Start+8, Base $start-8.
  if make_matches_kodak(make) && is_kodak8c_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:411`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:412`)
      ChildByteOrder::Unknown,       // `MakerNotes.pm:410`
      false,
    );
  }
  // Kodak9 — SIG-ONLY (`MakerNotes.pm:415-424`):
  // `valPt=~m{^IIII[\x02\x03]\0.{14}\d{4}/\d{2}/\d{2} }s`. NO Make/Model gate
  // — fires for ANY make. NotIFD, LE, no Start/Base.
  if is_kodak9_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:422`
      true,                                        // `NotIFD => 1` (`MakerNotes.pm:419`)
    );
  }
  // Kodak10 — MAKE+SIG (`MakerNotes.pm:425-440`): `Make=~/Kodak/i and
  // valPt=~/^(MM\0[\x02-\x7f]|II[\x02-\x7f]\0)/` (byte-order indicator then
  // IFD). IFD, Unknown order, Start+2, no Base.
  if make_matches_kodak(make) && is_kodak10_sig(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      2, // `Start => '$valuePtr + 2'` (`MakerNotes.pm:438`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown, // `MakerNotes.pm:437`
      false,
    );
  }
  // Kodak11 — MODEL+SIG (`MakerNotes.pm:441-455`): `Model=~/(Kodak|PixPro)/i
  // and valPt=~/^II\x2a\0\x08\0\0\0.\0\0\0/s` (PixPro S-1; Make is "JK
  // Imaging, Ltd." so this keys on Model). IFD, LE, Start+8, Base $start-8.
  if model_matches_kodak(model) && is_kodak11_le_ifd(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:453`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:454`)
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:452`
      false,
    );
  }
  // Kodak12 — MODEL+SIG (`MakerNotes.pm:457-471`): `Model=~/(Kodak|PixPro)/i
  // and valPt=~/^MM\0\x2a\0\0\0\x08\0\0\0./s` (PixPro AZ901). IFD, BE,
  // Start+8, Base $start-8.
  if model_matches_kodak(model) && is_kodak12_be_ifd(blob) {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      8,                                        // `Start => '$valuePtr + 8'` (`MakerNotes.pm:469`)
      BaseRule::RelativeToStart(-8),            // `Base => '$start - 8'` (`MakerNotes.pm:470`)
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:468`
      false,
    );
  }
  // KodakUnknown — MAKE (`MakerNotes.pm:473-481`): `Make=~/Kodak/i and
  // valPt!~/^AOC\0/`. NotIFD, BE, no Start/Base. This is the make-keyed
  // FALLBACK for Kodak bodies whose blob matched none of the arms above.
  // The `!AOC\0` exclusion lets a Kodak-made body carrying a Pentax `AOC\0`
  // blob fall THROUGH to the Pentax `AOC\0` arm below (`MakerNotes.pm:762`).
  if make_matches_kodak(make) && !starts_with(blob, b"AOC\x00") {
    return DetectedMakerNote::new(
      Vendor::Kodak,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Big), // `MakerNotes.pm:479`
      true,                                     // `NotIFD => 1` (`MakerNotes.pm:476`)
    );
  }

  // ----- Kyocera — `MakerNoteKyocera` (`MakerNotes.pm:483-492`).
  // `$$valPt =~ /^KYOCERA/`.
  if starts_with(blob, b"KYOCERA") {
    return DetectedMakerNote::new(
      Vendor::Kyocera,
      22,                           // `Start => '$valuePtr + 22'` (`MakerNotes.pm:488`)
      BaseRule::RelativeToStart(2), // `Base => '$start + 2'` (`MakerNotes.pm:489`)
      ChildByteOrder::Unknown,
      false,
    )
    .with_entry_based(); // `EntryBased => 1` (`MakerNotes.pm:490`)
  }

  // ----- Minolta2 — `MakerNoteMinolta2` (`MakerNotes.pm:505-516`).
  // `$$valPt =~ /^(MINOL|CAMER)\0/ and $$self{OlympusCAMER} = 1`. The
  // `OlympusCAMER = 1` is an ASSIGNMENT (always true), so this arm is
  // SIGNATURE-ONLY — NO Make gate. It must fire for ANY make (the DiMAGE
  // E323/E500 and "some models of Mustek, Pentax, Ricoh and Vivitar"
  // carry these prefixes — `MakerNotes.pm:506-507`). Tested BEFORE the
  // Make-gated Minolta arms below; that is faithful because `MakerNoteMinolta`
  // (`:495`) excludes `^(MINOL|CAMER|…)` via its negative lookahead, so a
  // Minolta-make body with these prefixes lands here in bundled too.
  // (Bundled routes to `Olympus::Main` — the bodies are Olympus-encoded;
  // Phase 1 keeps the dispatch vendor as Minolta and surfaces the offset.)
  if starts_with(blob, b"MINOL\x00") || starts_with(blob, b"CAMER\x00") {
    return DetectedMakerNote::new(
      Vendor::Minolta,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:513`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Minolta / Minolta3 — Make-gated (`MakerNotes.pm:494-503` /
  // `:517-526`). Both require `$$self{Make}=~/^(Konica Minolta|Minolta)/i`.
  if make_starts_with_ci(make, "Konica Minolta") || make_starts_with_ci(make, "Minolta") {
    // Generic Minolta — `MakerNoteMinolta` (`MakerNotes.pm:494-503`). Its
    // positive Make gate carries a negative blob lookahead (`:498`):
    // `$$valPt !~ /^(MINOL|CAMER|MLY0|KC|\+M\+M|\xd7)/`. So a Minolta-make blob
    // whose value does NOT start with one of those six prefixes lands here
    // (`Minolta::Main`, `ByteOrder => 'Unknown'`).
    if !minolta_excluded_prefix(blob) {
      return DetectedMakerNote::new(
        Vendor::Minolta,
        0,
        BaseRule::Inherit,
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Minolta3 — `MakerNoteMinolta3` (`MakerNotes.pm:517-526`): `Binary => 1`,
    // `Notes => 'not EXIF-based'`. Its Condition (`:523`) is MAKE-ONLY —
    // `$$self{Make} =~ /^(Konica Minolta|Minolta)/i`. The `/^MLY0/`, `/^KC/`,
    // `/^+M+M/`, `/^\xd7/` lines above it (`:518-521`) are example NOTES, NOT
    // the condition. So EVERY Minolta-make blob excluded from generic Minolta
    // by the bare-prefix lookahead reaches Minolta3 and is treated as
    // binary/NotIFD — not just those four documented prefixes. `MINOL\0`/
    // `CAMER\0` returned earlier via Minolta2; the remainder (`MLY0`/`KC`/
    // `+M+M`/`\xd7` AND bare `MINOL`/`CAMER` without a trailing NUL) fall here.
    return DetectedMakerNote::new(
      Vendor::Minolta,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true,
    );
  }

  // ----- Motorola — `MakerNoteMotorola` (`MakerNotes.pm:528-535`).
  // `$$valPt=~/^MOT\0/`.
  if starts_with(blob, b"MOT\x00") {
    return DetectedMakerNote::new(
      Vendor::Motorola,
      8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:532`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:533`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Older Nikon — `MakerNoteNikon2` (`MakerNotes.pm:537-545`).
  // `$$valPt=~/^Nikon\x00\x01/`.
  if starts_with(blob, b"Nikon\x00\x01") {
    return DetectedMakerNote::new(
      Vendor::Nikon,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:543`)
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:544`
      false,
    );
  }

  // ----- Headerless Nikon — `MakerNoteNikon3` (`MakerNotes.pm:546-554`).
  // `$$self{Make}=~/^NIKON/i`.
  if make_starts_with_ci(make, "NIKON") {
    return DetectedMakerNote::new(
      Vendor::Nikon,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown, // `MakerNotes.pm:553` ("most are little-endian, but D1 is big")
      false,
    );
  }

  // ----- Nintendo — `MakerNoteNintendo` (`MakerNotes.pm:556-563`).
  // `$$self{Make} eq "Nintendo"`.
  if make_eq(make, "Nintendo") {
    return DetectedMakerNote::new(
      Vendor::Nintendo,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Olympus OLD — `MakerNoteOlympus` (`MakerNotes.pm:565-576`).
  // `$$valPt =~ /^(OLYMP|EPSON)\0/`.
  if starts_with(blob, b"OLYMP\x00") || starts_with(blob, b"EPSON\x00") {
    return DetectedMakerNote::new(
      Vendor::Olympus,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:573`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Olympus new — `MakerNoteOlympus2` (`MakerNotes.pm:577-587`).
  // `$$valPt =~ /^OLYMPUS\0/`.
  if starts_with(blob, b"OLYMPUS\x00") {
    return DetectedMakerNote::new(
      Vendor::Olympus,
      12,                             // `Start => '$valuePtr + 12'` (`MakerNotes.pm:583`)
      BaseRule::RelativeToStart(-12), // `Base => '$start - 12'` (`MakerNotes.pm:584`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- OM SYSTEM — `MakerNoteOlympus3` (`MakerNotes.pm:588-598`).
  // `$$valPt =~ /^OM SYSTEM\0/`.
  if starts_with(blob, b"OM SYSTEM\x00") {
    return DetectedMakerNote::new(
      Vendor::Olympus,
      16,                             // `Start => '$valuePtr + 16'` (`MakerNotes.pm:594`)
      BaseRule::RelativeToStart(-16), // `Base => '$start - 16'` (`MakerNotes.pm:595`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Leica family — eight variants `MakerNoteLeica`..`Leica10`
  // (`MakerNotes.pm:599-731`). Phase 1 collapses to `Vendor::Leica` and
  // detects the most distinctive signatures; deferred long-tail per-variant
  // routing comes later.
  //
  // Leica1 — `$$self{Make} eq "LEICA"`, `MakerNotes.pm:600-608`
  if make_eq(make, "LEICA") {
    return DetectedMakerNote::new(
      Vendor::Leica,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:606`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }
  // Leica10 — `$$valPt =~ /^LEICA CAMERA AG\0/`, `MakerNotes.pm:723-730`
  if starts_with(blob, b"LEICA CAMERA AG\x00") {
    return DetectedMakerNote::new(
      Vendor::Leica,
      18, // `Start => '$valuePtr + 18'` (`MakerNotes.pm:728`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }
  // Leica2 / Leica4 / Leica5 / Leica7 / Leica8 / Leica9 — all share the
  // `LEICA` prefix but carry DIFFERENT `Base` directives, discriminated by
  // bytes 5..8 (the `\0\0\0` / `0` / `\0<v>\0` / `\0\x02\xff` headers). The
  // collapsed-to-one-arm port previously gave `$start - 8` to ALL of them,
  // which is wrong for Leica2 (`$start`), Leica8 and Leica9 (no `Base` →
  // inherit). The sub-arms below are in EXACT `%Main` order (Leica2 `:611`,
  // Leica4 `:639`, Leica5 `:650`, Leica7 `:690`, Leica8 `:703`, Leica9
  // `:714`); the VENDOR stays `Vendor::Leica` (per-table fan-out deferred).
  // `MakerNoteLeica6` (`:666`, the S2/M-Typ240/S-Typ006 `LeicaTrailer`
  // case) has NO signature — its JPEG-trailer special-casing
  // (`ProcessLeicaTrailer`) is a documented deferred item, so an S2/Typ240
  // body with a non-`LEICA` blob falls to the Leica3 arm below as in the
  // pre-existing port. There is NO generic `LEICA`-prefix fallback: a
  // `LEICA…` blob matching none of these sub-headers falls THROUGH (the
  // Leica3 `!^LEICA` guard rejects it → Unknown), faithful to bundled.
  if starts_with(blob, b"LEICA") {
    let b6 = blob.get(5).copied();
    let b7 = blob.get(6).copied();
    let b8 = blob.get(7).copied();
    let ag_make = make_starts_with(make, "Leica Camera AG");
    // Leica2 (`MakerNotes.pm:611-623`): `Make=~/^Leica Camera AG/ and
    // valPt=~/^LEICA\0\0\0/`. `Base => '$start'` (`:621`), Start+8.
    if ag_make && b6 == Some(0x00) && b7 == Some(0x00) && b8 == Some(0x00) {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                     // `Start => '$valuePtr + 8'` (`MakerNotes.pm:620`)
        BaseRule::StartItself, // `Base => '$start'` (`MakerNotes.pm:621`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica4 (`MakerNotes.pm:639-647`): `Make=~/^Leica Camera AG/ and
    // valPt=~/^LEICA0/` (byte 5 = ASCII '0' = 0x30). `Base => '$start - 8'`.
    if ag_make && b6 == Some(b'0') {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:644`)
        BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:645`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica5 (`MakerNotes.pm:650-663`): SIG-ONLY
    // `valPt=~/^LEICA\0[\x01\x04\x05\x06\x07\x10\x1a]\0/`. `Base => '$start - 8'`.
    if b6 == Some(0x00)
      && matches!(b7, Some(0x01 | 0x04 | 0x05 | 0x06 | 0x07 | 0x10 | 0x1a))
      && b8 == Some(0x00)
    {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:660`)
        BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:661`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica6 (`MakerNotes.pm:666-688`): Make+Model gated, NO valPt signature —
    // `Make eq 'Leica Camera AG' and Model in {S2, LEICA M (Typ 240), LEICA S
    // (Typ 006)}` (`:671-673`). MUST precede Leica7 in `%Main` order
    // (`:666` < `:690`): the S2/M-Typ240/S-Typ006 bodies use the SAME
    // `LEICA\0\x02\xff` header as Leica7 (the M Monochrom Typ 246), but Leica6
    // takes NO `Base` (its offsets are fixed up by `ProcessLeicaTrailer` /
    // `LeicaTrailer`, `:675-687`) whereas Leica7 takes `Base => '-$base'`.
    // Without this arm those three real bodies fell to Leica7 below and got the
    // WRONG (negative/absolute) base (Codex R8). The condition carries no valPt
    // term, so a non-`LEICA` blob for these models is handled after Leica3 below
    // (such a blob never enters this `LEICA`-prefixed block). Make is `eq`
    // (exact), not the `/^Leica Camera AG/` prefix the other Leica arms use.
    if make_eq(make, "Leica Camera AG")
      && (model_eq(model, "S2")
        || model_eq(model, "LEICA M (Typ 240)")
        || model_eq(model, "LEICA S (Typ 006)"))
    {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                 // `Start => '$valuePtr + 8'` (`MakerNotes.pm:679`)
        BaseRule::Inherit, // NO `Base` line (`:677-687`) — LeicaTrailer fixups apply elsewhere
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica7 (`MakerNotes.pm:690-701`): SIG-ONLY `valPt=~/^LEICA\0\x02\xff/`.
    // `Base => '-$base'` (`:699`) — the ONLY `NegativeOfBase` in the module.
    // Reached only by the M Monochrom (Typ 246): the S2/M240/S006 models that
    // share this header returned via the Leica6 arm above.
    if b6 == Some(0x00) && b7 == Some(0x02) && b8 == Some(0xff) {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                        // `Start => '$valuePtr + 8'` (`MakerNotes.pm:697`)
        BaseRule::NegativeOfBase, // `Base => '-$base'` (`MakerNotes.pm:699`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica8 (`MakerNotes.pm:703-712`): SIG-ONLY
    // `valPt=~/^LEICA\0[\x08\x09\x0a]\0/`. NO `Base` directive → inherit.
    if b6 == Some(0x00) && matches!(b7, Some(0x08 | 0x09 | 0x0a)) && b8 == Some(0x00) {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                 // `Start => '$valuePtr + 8'` (`MakerNotes.pm:709`)
        BaseRule::Inherit, // no `Base` line (`MakerNotes.pm:707-711`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Leica9 (`MakerNotes.pm:714-721`): `Make=~/^Leica Camera AG/ and
    // valPt=~/^LEICA\0\x02\0/`. NO `Base` directive → inherit.
    if ag_make && b6 == Some(0x00) && b7 == Some(0x02) && b8 == Some(0x00) {
      return DetectedMakerNote::new(
        Vendor::Leica,
        8,                 // `Start => '$valuePtr + 8'` (`MakerNotes.pm:719`)
        BaseRule::Inherit, // no `Base` line (`MakerNotes.pm:717-720`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // No generic LEICA fallback — an unmatched `LEICA…` blob falls through
    // (faithful: bundled has no catch-all LEICA arm; Leica3 below rejects
    // it via `valPt !~ /^LEICA/`).
  }
  // Leica3 — `MakerNotes.pm:626-637`. Condition (`:629-630`):
  // `$$self{Make} =~ /^Leica Camera AG/ and $$valPt !~ /^LEICA/ and
  //  $$self{Model} ne "S2" and $$self{Model} ne "LEICA M (Typ 240)"`.
  // The `$$valPt !~ /^LEICA/` negative blob guard (`:629`) is LOAD-BEARING: a
  // `Leica Camera AG` body whose blob starts `LEICA…` but matches NONE of the
  // Leica2/4/5/6/7/8/9 sub-headers above must NOT be captured here — it falls
  // THROUGH to the Unknown catch-all (bundled has no generic `LEICA`-prefix
  // arm). Without the guard the Rust gate is BROADER than Perl (Codex R4).
  // The Model `ne "S2"` / `ne "LEICA M (Typ 240)"` exclusions (`:630`) keep a
  // non-`LEICA`-blob S2 / M-Typ240 body OFF this arm so the make-only Leica6
  // fallback just below claims it — faithful to `%Main` order (Leica3 `:626`
  // precedes Leica6 `:666`). Leica3 does NOT exclude S-Typ006, so a
  // non-`LEICA`-blob S006 body DOES land here (Codex R8).
  if make_starts_with(make, "Leica Camera AG")
    && !starts_with(blob, b"LEICA")
    && !model_eq(model, "S2")
    && !model_eq(model, "LEICA M (Typ 240)")
  {
    return DetectedMakerNote::new(
      Vendor::Leica,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:634`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }
  // Leica6 fallback (`MakerNotes.pm:666-688`) for a NON-`LEICA` blob. Leica6 is
  // make+model gated with NO valPt term, so an S2 / M-Typ240 body whose blob
  // does NOT start `LEICA` (excluded from Leica3 just above, and never entering
  // the `LEICA`-prefixed block) still lands on Leica6 in `%Main` order. The
  // common `LEICA\0\x02\xff` case is handled by the in-block Leica6 arm; an
  // S-Typ006 body with a non-`LEICA` blob matched Leica3 above (faithful to
  // `:626` < `:666`). Make is `eq` (exact), matching `:672`.
  if make_eq(make, "Leica Camera AG")
    && (model_eq(model, "S2") || model_eq(model, "LEICA M (Typ 240)"))
  {
    return DetectedMakerNote::new(
      Vendor::Leica,
      8,                 // `Start => '$valuePtr + 8'` (`MakerNotes.pm:679`)
      BaseRule::Inherit, // NO `Base` line (`:677-687`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Panasonic primary — `MakerNotePanasonic` (`MakerNotes.pm:732-740`).
  // `$$valPt=~/^Panasonic/ and $$self{Model} ne "DC-FT7"`.
  if starts_with(blob, b"Panasonic") && !model_eq(model, "DC-FT7") {
    return DetectedMakerNote::new(
      Vendor::Panasonic,
      12, // `Start => '$valuePtr + 12'` (`MakerNotes.pm:738`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Panasonic 2 (MKE) — `MakerNotePanasonic2` (`MakerNotes.pm:742-749`).
  if make_starts_with(make, "Panasonic") && starts_with(blob, b"MKE") {
    return DetectedMakerNote::new(
      Vendor::Panasonic,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little), // `MakerNotes.pm:748`
      false,
    );
  }

  // ----- Panasonic 3 (DC-FT7) — `MakerNotePanasonic3` (`MakerNotes.pm:751-760`).
  if starts_with(blob, b"Panasonic") {
    return DetectedMakerNote::new(
      Vendor::Panasonic,
      12,                    // `Start => '$valuePtr + 12'` (`MakerNotes.pm:757`)
      BaseRule::Literal(12), // `Base => 12` (literal absolute! `MakerNotes.pm:758`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Pentax primary — `MakerNotePentax` (`MakerNotes.pm:762-779`).
  // `$$valPt=~/^AOC\0/ and $$self{Model} !~ /^PENTAX Optio ?[34]30RS\s*$/`.
  if starts_with(blob, b"AOC\x00") && !is_pentax_optio_rs(model) {
    return DetectedMakerNote::new(
      Vendor::Pentax,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown, // no explicit order
      false,
    )
    .with_fix_base(); // `FixBase => 1` (`MakerNotes.pm:777`)
  }

  // ----- Pentax 5 (PENTAX \0) — `MakerNotePentax5` (`MakerNotes.pm:817-827`).
  // `$$valPt=~/^PENTAX \0/`.
  if starts_with(blob, b"PENTAX \x00") {
    return DetectedMakerNote::new(
      Vendor::Pentax,
      10,                             // `Start => '$valuePtr + 10'` (`MakerNotes.pm:824`)
      BaseRule::RelativeToStart(-10), // `Base => '$start - 10'` (`MakerNotes.pm:825`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Pentax 6 (S1) — `MakerNotePentax6` (`MakerNotes.pm:829-838`).
  // `$$valPt=~/^S1\0{6}\x0c\0{3}/`.
  if starts_with(blob, b"S1\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00") {
    return DetectedMakerNote::new(
      Vendor::Pentax,
      12,                             // `Start => '$valuePtr + 12'` (`MakerNotes.pm:835`)
      BaseRule::RelativeToStart(-12), // `Base => '$start - 12'` (`MakerNotes.pm:836`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Pentax 4 — `MakerNotePentax4` (`MakerNotes.pm:805-815`).
  // `$$self{Make}=~/^PENTAX/ and $$valPt=~/^\d{3}/` ; `NotIFD => 1`.
  if make_starts_with(make, "PENTAX") && starts_with_digits(blob, 3) {
    return DetectedMakerNote::new(
      Vendor::Pentax,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little),
      true,
    );
  }

  // ----- Pentax 2 / 3 (Asahi) — `MakerNotePentax2`/`Pentax3`
  // (`MakerNotes.pm:781-803`). Both carry `FixBase => 1` (`:789`/`:801`).
  if make_starts_with(make, "Asahi") {
    return DetectedMakerNote::new(
      Vendor::Pentax,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    )
    .with_fix_base(); // `FixBase => 1` (`MakerNotes.pm:789`/`:801`)
  }

  // ----- PhaseOne — `MakerNotePhaseOne` (`MakerNotes.pm:840-852`).
  // `$$valPt =~ /^(IIII.waR|MMMMRaw.)/s` ; `NotIFD => 1`.
  if blob.len() >= 8
    && ((&blob[..4] == b"IIII" && &blob[5..8] == b"waR")
      || (&blob[..4] == b"MMMM" && &blob[4..7] == b"Raw"))
  {
    return DetectedMakerNote::new(
      Vendor::PhaseOne,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true, // `NotIFD => 1`
    );
  }

  // ----- Reconyx family — `MakerNotes.pm:854-895`. Five variants; each
  // has a distinct prefix. Phase 1 collapses to `Vendor::Reconyx`.
  //
  // HyperFire (`MakerNotes.pm:856-859`) is `^\x01\xf1([\x02\x03]\x00)?`
  // BUT only selected if the OPTIONAL group `([\x02\x03]\x00)` actually
  // matched (`$1`) OR `$$self{Make} eq "RECONYX"`. So a bare `\x01\xf1`
  // with no `[\x02\x03]\x00` continuation is HyperFire only when Make is
  // exactly "RECONYX". The four `RECONYX*` prefixes are unconditional.
  if is_reconyx_hyperfire(blob, make)
    || starts_with(blob, b"RECONYXUF\x00") // UltraFire (`MakerNotes.pm:867`)
    || starts_with(blob, b"RECONYXH2\x00") // HyperFire2 (`MakerNotes.pm:875`)
    || starts_with(blob, b"RECONYXMF\x00") // MicroFire (`MakerNotes.pm:883`)
    || starts_with(blob, b"RECONYXHF4K\x00")
  // HyperFire4K (`MakerNotes.pm:891`)
  {
    return DetectedMakerNote::new(
      Vendor::Reconyx,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Explicit(ByteOrder::Little),
      true,
    );
  }

  // ----- Ricoh + Pentax (RICOH GR III etc.) — `MakerNoteRicohPentax`
  // (`MakerNotes.pm:897-906`). `$$valPt=~/^RICOH\0(II|MM)/`.
  if blob.len() >= 8 && &blob[..6] == b"RICOH\x00" && (&blob[6..8] == b"II" || &blob[6..8] == b"MM")
  {
    return DetectedMakerNote::new(
      Vendor::Ricoh,
      8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:903`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:904`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Ricoh family — `MakerNoteRicoh` / `MakerNoteRicoh2` /
  // `MakerNoteRicohText` (`MakerNotes.pm:908-948`). Ricoh + Ricoh2 gate on
  // `$$self{Make} =~ /^(PENTAX )?RICOH/`; `MakerNoteRicohText` (`:943`)
  // gates on the NARROWER `$$self{Make}=~/^RICOH/` (NO `PENTAX ` prefix),
  // so a `PENTAX RICOH` body that fails the structural Ricoh/Ricoh2 arms
  // must NOT be caught by the text fallback — it falls through to Unknown.
  if make_matches_ricoh(make) {
    // Ricoh2 FIRST — `MakerNoteRicoh2` (`MakerNotes.pm:924-939`): selected
    // when `$$self{Model} eq 'RICOH WG-M1'` OR the blob matches the two
    // padded-IFD patterns `MM\0\x2a\0\0\0\x08\0.\0\0` /
    // `II\x2a\0\x08\0\0\0.\0\0\0` (the `.` is any byte at offset 8). These
    // are exactly the shapes the `MakerNoteRicoh` positive arm EXCLUDES via
    // its negative lookahead (`MakerNotes.pm:914`) + `Model ne 'RICOH
    // WG-M1'` (`:915`), so testing Ricoh2 first is observationally faithful.
    if model_eq(model, "RICOH WG-M1") || is_ricoh2_padded_ifd(blob) {
      return DetectedMakerNote::new(
        Vendor::Ricoh,
        8,                             // `Start => '$valuePtr + 8'` (`MakerNotes.pm:935`)
        BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:936`)
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Ricoh — `MakerNoteRicoh` (`MakerNotes.pm:908-921`):
    // `$$valPt =~ /^(Ricoh|      |MM\0\x2a|II\x2a\0)/i`. The `/i` flag makes
    // the alpha-bearing `Ricoh` literal CASE-INSENSITIVE — real Caplio RR1/
    // RR120/RDC-i500 bodies begin with uppercase `RICOH\0…`, so a CS
    // `starts_with(blob, b"Ricoh")` would miss them and wrongly fall to the
    // `RicohText` fallback (body_offset=0, not_ifd) instead of Ricoh
    // (body_offset=8, IFD) — Codex R5. The three binary alternatives (six
    // spaces, `MM\0\x2a`, `II\x2a\0`) carry no ASCII letters, so `/i` is a
    // no-op for them and they stay EXACT.
    if starts_with_ci(blob, b"Ricoh")
      || starts_with(blob, b"      ")
      || starts_with(blob, b"MM\x00\x2a")
      || starts_with(blob, b"II\x2a\x00")
    {
      return DetectedMakerNote::new(
        Vendor::Ricoh,
        8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:919`)
        BaseRule::Inherit,
        ChildByteOrder::Unknown,
        false,
      );
    }
    // Ricoh text — `MakerNoteRicohText` (`MakerNotes.pm:941-948`):
    // `$$self{Make}=~/^RICOH/`. Catch-all for bare-`RICOH`-made bodies that
    // fail the structural prefix tests. A `PENTAX RICOH` make does NOT
    // match `^RICOH`, so it is NOT caught here (faithful — bundled lets it
    // fall through to the Unknown arms).
    if make_starts_with(make, "RICOH") {
      return DetectedMakerNote::new(
        Vendor::Ricoh,
        0,
        BaseRule::Inherit,
        ChildByteOrder::Unknown,
        true,
      );
    }
  }

  // ----- Samsung 1a/1b — `STMN…` (`MakerNotes.pm:950-963`).
  // Samsung1a (`:951-956`): `$$valPt =~ /^STMN\d{3}.\0{4}/s` → `Binary => 1`
  // (Phase 1 models as `NotIFD`). Samsung1b (`:957-963`): the fallback
  // `^STMN\d{3}` → a `SubDirectory` (`Samsung::Main`), so it is an IFD —
  // `not_ifd = false`. Both require THREE digits after `STMN` (a bare
  // `STMN` without digits matches NEITHER and must fall through). The two
  // share `Vendor::Samsung` + no `Start`/`Base`/`ByteOrder`; only the
  // `not_ifd` flag differs.
  if starts_with(blob, b"STMN") && blob.len() >= 7 && blob[4..7].iter().all(u8::is_ascii_digit) {
    // Samsung1a: `STMN \d{3} . \0{4}` — byte 7 is the `.` (any), bytes
    // 8..12 are four NULs (`/s` makes `.` match NUL too). 12 bytes.
    let is_1a = blob.len() >= 12 && blob[8..12].iter().all(|&b| b == 0x00);
    return DetectedMakerNote::new(
      Vendor::Samsung,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      is_1a, // Samsung1a → Binary/NotIFD; Samsung1b → SubDirectory (IFD).
    );
  }

  // ----- Samsung 2 — `MakerNoteSamsung2` (`MakerNotes.pm:965-979`).
  // `uc $$self{Make} eq 'SAMSUNG' and ($$self{TIFF_TYPE} eq 'SRW' or
  //  $$valPt=~/^(\0.\0\x01\0\x07\0{3}\x04|.\0\x01\0\x07\0\x04\0{3})0100/s)`.
  // It is NOT a bare Make test: a SAMSUNG body whose blob is neither an
  // SRW raw NOR the EXIF-format magic must FALL THROUGH (Codex R3) — e.g.
  // to the Sanyo/Sony/etc. arms below or the Unknown catch-all. The SRW
  // clause reads the threaded `tiff_type`; when the caller can't supply it
  // (`None`), only the magic clause fires (the documented Phase-1 gap).
  if make_eq_ci_upper(make, "SAMSUNG") && (tiff_type == Some("SRW") || is_samsung2_sig(blob)) {
    return DetectedMakerNote::new(
      Vendor::Samsung,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    )
    .with_fix_base(); // `FixBase => 1` (`MakerNotes.pm:977`)
  }

  // ----- Sanyo family — `MakerNoteSanyo` / `MakerNoteSanyoC4` /
  // `MakerNoteSanyoPatch` (`MakerNotes.pm:981-1014`).
  // `$$self{Make}=~/^SANYO/`. The `Start => '$valuePtr + 8'` is common
  // across all three; they split by Model: SanyoC4 (Model `^C4\b`) sets
  // `FixBase => 1` (`MakerNotes.pm:1000`); SanyoPatch (the J/S catch-all)
  // sets `FixOffsets` (`MakerNotes.pm:1013`) — DEFERRED (not modelled).
  if make_starts_with(make, "SANYO") {
    let detected = DetectedMakerNote::new(
      Vendor::Sanyo,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:988`/`:999`/`:1011`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
    // SanyoC4: Model `^C4\b` ⇒ `FixBase => 1` (`MakerNotes.pm:995-1000`).
    if model_matches_sanyo_c4(model) {
      return detected.with_fix_base();
    }
    return detected;
  }

  // ----- Sigma / Foveon — `MakerNoteSigma` (`MakerNotes.pm:1016-1029`).
  // `$$self{Make}=~/^(SIGMA|FOVEON)/i`.
  if make_starts_with_ci(make, "SIGMA") || make_starts_with_ci(make, "FOVEON") {
    return DetectedMakerNote::new(
      Vendor::Sigma,
      10, // `Start => '$valuePtr + 10'` (`MakerNotes.pm:1027`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony PRIMARY — `MakerNoteSony` (`MakerNotes.pm:1031-1041`).
  // `$$valPt=~/^(SONY (DSC|CAM|MOBILE)|\0\0SONY PIC\0|VHAB     \0)/`.
  // The regex requires a SINGLE space between `SONY` and the token, then
  // NO trailing space — so `SONY DSC\0…` (NUL, no trailing space) must
  // match here (Start = `$valuePtr + 12`), NOT fall through to Sony5.
  if starts_with(blob, b"SONY DSC")
    || starts_with(blob, b"SONY CAM")
    || starts_with(blob, b"SONY MOBILE")
    || sony_tf1_prefix(blob)
    || starts_with(blob, b"VHAB     \x00")
  {
    return DetectedMakerNote::new(
      Vendor::Sony,
      12, // `Start => '$valuePtr + 12'` (`MakerNotes.pm:1039`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony 2 (PI) — `MakerNoteSony2` (`MakerNotes.pm:1043-1052`).
  // (Cross-routes to Olympus::Main + sets `OlympusCAMER` — Phase 1 keeps
  // the dispatch vendor as Sony.)
  if starts_with(blob, b"SONY PI\x00") {
    return DetectedMakerNote::new(
      Vendor::Sony,
      12, // `Start => '$valuePtr + 12'` (`MakerNotes.pm:1049`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony 3 (PREMI) — `MakerNoteSony3` (`MakerNotes.pm:1053-1062`).
  if starts_with(blob, b"PREMI\x00") {
    return DetectedMakerNote::new(
      Vendor::Sony,
      8, // `Start => '$valuePtr + 8'` (`MakerNotes.pm:1059`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony 4 (SONY PIC) — `MakerNoteSony4` (`MakerNotes.pm:1063-1068`).
  // No Start/Base/ByteOrder directives.
  if starts_with(blob, b"SONY PIC\x00") {
    return DetectedMakerNote::new(
      Vendor::Sony,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony 5 (DSLR/SR2/ARW) — `MakerNoteSony5` (`MakerNotes.pm:1069-1080`).
  // `($$self{Make}=~/^SONY/ or ($$self{Make}=~/^HASSELBLAD/ and
  //   $$self{Model}=~/^(HV|Stellar|Lusso|Lunar)/)) and $$valPt!~/^\x01\x00/`.
  if (make_starts_with(make, "SONY")
    || (make_starts_with(make, "HASSELBLAD") && is_hasselblad_sony(model)))
    && !starts_with(blob, b"\x01\x00")
  {
    return DetectedMakerNote::new(
      Vendor::Sony,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:1078`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony Ericsson — `MakerNoteSonyEricsson` (`MakerNotes.pm:1082-1090`).
  // `$$valPt =~ /^SEMC MS\0/`. Tested AFTER Sony5 to match `%Main` order
  // (Sony5 `:1070` precedes SonyEricsson `:1083`): a `SEMC MS\0` blob whose
  // Make matches `/^SONY/` (case-sensitive) is claimed by Sony5 first in
  // bundled. Real Sony Ericsson bodies report Make `"Sony Ericsson"` (mixed
  // case), which does NOT match `/^SONY/`, so they reach this arm in both.
  if starts_with(blob, b"SEMC MS\x00") {
    return DetectedMakerNote::new(
      Vendor::Sony,
      20,                            // `Start => '$valuePtr + 20'` (`MakerNotes.pm:1087`)
      BaseRule::RelativeToStart(-8), // `Base => '$start - 8'` (`MakerNotes.pm:1088`)
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Sony SRF — `MakerNoteSonySRF` (`MakerNotes.pm:1092-1099`).
  // `$$self{Make}=~/^SONY/` (NO Hasselblad clause, NO `\x01\x00` lookahead).
  // Sony5 above already consumed the non-`\x01\x00` SONY case, so this arm
  // catches the `\x01\x00` SONY blobs (the SRF raw header). A Hasselblad-
  // rebadge `\x01\x00` body matches NEITHER Sony5 (excluded by the
  // lookahead) NOR SonySRF (requires `Make=~/^SONY/`) and falls through to
  // the Unknown catch-all below — faithful to bundled.
  if make_starts_with(make, "SONY") {
    return DetectedMakerNote::new(
      Vendor::Sony,
      0, // `Start => '$valuePtr'` (`MakerNotes.pm:1097`)
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      false,
    );
  }

  // ----- Unknown text — `MakerNoteUnknownText` (`MakerNotes.pm:1101-1108`).
  // `$$valPt =~ /^[\x09\x0d\x0a\x20-\x7e]+\0*$/` — a non-empty run of
  // printable/whitespace ASCII followed by optional NUL padding. Routes
  // to `Vendor::Unknown`, `NotIFD => 1` (it has no `SubDirectory`/IFD —
  // it's a plain text value). Tested BEFORE the LSI1 binary arm to match
  // bundled order.
  if is_unknown_text(blob) {
    return DetectedMakerNote::new(
      Vendor::Unknown,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true, // not an IFD — a text blob
    );
  }

  // ----- LSI1 — `MakerNoteUnknownBinary` (`MakerNotes.pm:1109-1114`).
  // `$$valPt =~ /^LSI1\0/`. Routes to `Unknown` (no decode).
  if starts_with(blob, b"LSI1\x00") {
    return DetectedMakerNote::new(
      Vendor::Unknown,
      0,
      BaseRule::Inherit,
      ChildByteOrder::Unknown,
      true,
    );
  }

  // ----- The catch-all — `MakerNoteUnknown` (`MakerNotes.pm:1117-1126`).
  // `FixBase => 2; ProcessProc => \&ProcessUnknownOrPreview`. Phase 1
  // captures the `FixBase` flag (the heuristic + `ProcessProc` are
  // deferred); Phase 2+ may attempt a generic IFD probe.
  DetectedMakerNote::new(
    Vendor::Unknown,
    0,
    BaseRule::Inherit,
    ChildByteOrder::Unknown,
    false,
  )
  .with_fix_base() // `FixBase => 2` (`MakerNotes.pm:1124`)
}

// =============================================================================
// Helpers — byte-prefix / string predicates equivalent to the bundled regexes
// =============================================================================

/// `$$valPt =~ /^bytes/` — `true` if `blob` starts with `prefix`.
#[inline]
fn starts_with(blob: &[u8], prefix: &[u8]) -> bool {
  blob.len() >= prefix.len() && &blob[..prefix.len()] == prefix
}

/// `$$valPt =~ /^bytes/i` — case-INSENSITIVE byte-prefix match, the faithful
/// equivalent of a `/i`-flagged blob regex. The ONLY signature regex in
/// `%Main` that carries `/i` on an alpha-bearing literal is `MakerNoteRicoh`
/// (`MakerNotes.pm:913` `/^(Ricoh|…)/i`), so this is the lone blob-sig arm
/// that needs it. Perl's `/i` folds ASCII case only (the maker-note literals
/// are pure ASCII); `eq_ignore_ascii_case` is the exact, panic-free mirror.
#[inline]
fn starts_with_ci(blob: &[u8], prefix: &[u8]) -> bool {
  blob.len() >= prefix.len() && blob[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// `$$valPt =~ /^...\@AMBA/` — the Ambarella signature (`MakerNotes.pm:101`
/// negative-lookahead `^(...\@AMBA|DJI)`). Three arbitrary bytes followed
/// by `@AMBA`.
#[inline]
fn ambarella_at_amba(blob: &[u8]) -> bool {
  blob.len() >= 8 && &blob[3..8] == b"@AMBA"
}

/// `$$valPt =~ /^(MINOL|CAMER|MLY0|KC|\+M\+M|\xd7)/` — the negative-lookahead
/// blob set that `MakerNoteMinolta` excludes (`MakerNotes.pm:498`). A literal
/// mirror of the Perl alternation: a blob with ANY of these prefixes must NOT
/// reach the generic Minolta arm (it is handled by Minolta2/Minolta3 above, or
/// falls through to Unknown for the `MINOL`/`CAMER`-without-NUL case).
#[inline]
fn minolta_excluded_prefix(blob: &[u8]) -> bool {
  starts_with(blob, b"MINOL")
    || starts_with(blob, b"CAMER")
    || starts_with(blob, b"MLY0")
    || starts_with(blob, b"KC")
    || starts_with(blob, b"+M+M")
    || starts_with(blob, b"\xd7")
}

/// `$$valPt =~ /^\0\0SONY PIC\0/` — Sony TF1 (`MakerNotes.pm:1034`
/// comment).
#[inline]
fn sony_tf1_prefix(blob: &[u8]) -> bool {
  blob.len() >= 11 && &blob[..2] == b"\x00\x00" && &blob[2..10] == b"SONY PIC" && blob[10] == 0
}

/// `$$valPt =~ /^\d{3}/` — three ASCII digits at the start (Pentax4).
#[inline]
fn starts_with_digits(blob: &[u8], n: usize) -> bool {
  blob.len() >= n && blob[..n].iter().all(|b| b.is_ascii_digit())
}

/// `$$self{Make} =~ /^prefix/` — `true` if `make` is `Some` and starts
/// with `prefix` (case-sensitive). `None` is `false`.
#[inline]
fn make_starts_with(make: Option<&str>, prefix: &str) -> bool {
  matches!(make, Some(m) if m.starts_with(prefix))
}

/// `$$self{Make} =~ /^prefix/i` — case-insensitive ASCII prefix match.
///
/// Compares on BYTES (`str::as_bytes`), never on a `&str` slice: IFD0
/// `Make`/`Model` are lossy-decoded (`from_utf8_lossy`), so a malformed
/// EXIF can yield valid multi-byte UTF-8 (e.g. U+FFFD = 3 bytes). Slicing
/// the `&str` at the byte index `prefix.len()` could fall mid-codepoint
/// and panic ("byte index N is not a char boundary"). The bundled regex
/// prefixes are pure ASCII, so a byte-level `eq_ignore_ascii_case` on the
/// leading `prefix.len()` bytes is the faithful, panic-free equivalent.
#[inline]
fn make_starts_with_ci(make: Option<&str>, prefix: &str) -> bool {
  match make {
    Some(m) => {
      let mb = m.as_bytes();
      let pb = prefix.as_bytes();
      mb.len() >= pb.len() && mb[..pb.len()].eq_ignore_ascii_case(pb)
    }
    None => false,
  }
}

/// `$$self{Make} eq "Foo"`.
#[inline]
fn make_eq(make: Option<&str>, target: &str) -> bool {
  matches!(make, Some(m) if m == target)
}

/// `uc $$self{Make} eq "FOO"` (case-insensitive equality).
#[inline]
fn make_eq_ci_upper(make: Option<&str>, target_upper: &str) -> bool {
  matches!(make, Some(m) if m.eq_ignore_ascii_case(target_upper))
}

/// `$$self{Model} eq "Foo"`.
#[inline]
fn model_eq(model: Option<&str>, target: &str) -> bool {
  matches!(model, Some(m) if m == target)
}

/// `$$self{Model}=~/^PENTAX Optio ?[34]30RS\s*$/`. The exact pattern
/// bundled uses in `MakerNotePentax` (`MakerNotes.pm:768`) — only
/// `MakerNotePentax3` reaches via the Asahi Make + `AOC\0` body.
/// Implementation: a literal-prefix + a small digit set + an optional
/// whitespace tail.
#[inline]
fn is_pentax_optio_rs(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  // `^PENTAX Optio` prefix; the bundled ` ?` (optional space) after
  // "Optio" is consumed by the `head` space-strip below.
  let Some(stripped) = m.strip_prefix("PENTAX Optio") else {
    return false;
  };
  // The `?[34]30RS\s*$` part — an optional space, then first char `3` or
  // `4`, then `30RS`, then trailing whitespace.
  let bytes = stripped.as_bytes();
  // Strip the single optional leading space (the `Optio ?` of the regex).
  let head = if bytes.first() == Some(&b' ') {
    &bytes[1..]
  } else {
    bytes
  };
  if head.len() < 5 {
    return false;
  }
  let is_first = matches!(head[0], b'3' | b'4');
  if !is_first || &head[1..5] != b"30RS" {
    return false;
  }
  // Trailing `\s*` — any/no whitespace.
  head[5..].iter().all(|b| b.is_ascii_whitespace())
}

/// `$$self{Make} =~ /Kodak/i` — the case-insensitive Make test used by the
/// `Kodak7`/`Kodak8a`/`Kodak8b`/`Kodak8c`/`Kodak10` + `MakerNoteKodakUnknown`
/// arms (`MakerNotes.pm:358`/`:372`/`:389`/`:404`/`:431`/`:475`). Substring,
/// case-insensitive (the regex is unanchored: `/Kodak/i`).
#[inline]
fn make_matches_kodak(make: Option<&str>) -> bool {
  matches!(make, Some(m) if contains_ascii_ci(m, "kodak"))
}

/// `$$self{Make} =~ /^EASTMAN KODAK/` — the UPPERCASE, case-SENSITIVE,
/// start-anchored Make test used by `Kodak1a`/`1b`/`3`/`5`/`6a`/`6b`
/// (`MakerNotes.pm:255`/`:265`/`:291`/`:317`/`:331`/`:343`). Distinct from
/// [`make_matches_kodak`] (which is `/Kodak/i`): these arms only fire for a
/// body whose Make literally begins "EASTMAN KODAK" — real Eastman Kodak
/// bodies report `Make => "EASTMAN KODAK COMPANY"`.
#[inline]
fn make_eastman_kodak_uc(make: Option<&str>) -> bool {
  make_starts_with(make, "EASTMAN KODAK")
}

/// `$$self{Make} =~ /^Eastman Kodak/` — the TITLE-case, case-SENSITIVE,
/// start-anchored Make test used ONLY by `Kodak4` (`MakerNotes.pm:304`).
/// Bundled deliberately spells this arm's prefix in title case (the other
/// `Make`-keyed Kodak arms use the uppercase `^EASTMAN KODAK`).
#[inline]
fn make_eastman_kodak_tc(make: Option<&str>) -> bool {
  make_starts_with(make, "Eastman Kodak")
}

/// `MakerNoteKodak2` signature (`MakerNotes.pm:276-279`):
/// `$$valPt =~ /^.{8}Eastman Kodak/s or
///  $$valPt =~ /^\x01\0[\0\x01]\0\0\0\x04\0[a-zA-Z]{4}/`.
/// Branch A: 8 arbitrary bytes (the `/s` makes `.` match NUL too) then the
/// literal "Eastman Kodak" at offset 8. Branch B: a fixed 9-byte header
/// `\x01\0[\0\x01]\0\0\0\x04\0` then 4 ASCII letters.
#[inline]
fn is_kodak2_sig(blob: &[u8]) -> bool {
  // Branch A: `^.{8}Eastman Kodak`.
  let branch_a = blob.len() >= 21 && &blob[8..21] == b"Eastman Kodak";
  // Branch B: `^\x01\0[\0\x01]\0\0\0\x04\0[a-zA-Z]{4}` — byte0=\x01, byte1=\0,
  // byte2 in {\0,\x01}, bytes 3..8 = \0\0\0\x04\0, then 4 ASCII letters
  // (bytes 8..12). 12 bytes total.
  let branch_b = blob.len() >= 12
    && blob[0] == 0x01
    && blob[1] == 0x00
    && (blob[2] == 0x00 || blob[2] == 0x01)
    && &blob[3..8] == b"\x00\x00\x00\x04\x00"
    && blob[8..12].iter().all(u8::is_ascii_alphabetic);
  branch_a || branch_b
}

/// `MakerNoteKodak3` signature (`MakerNotes.pm:292-293`):
/// `$$valPt =~ /^(?!MM|II).{12}\x07/s and $$valPt !~ /^(MM|II|AOC)/`.
/// The blob must NOT start with `MM`, `II`, or `AOC`, and must have a `\x07`
/// byte at offset 12 (the `.{12}` with `/s` is 12 arbitrary bytes incl. NUL).
#[inline]
fn is_kodak3_sig(blob: &[u8]) -> bool {
  if starts_with(blob, b"MM") || starts_with(blob, b"II") || starts_with(blob, b"AOC") {
    return false;
  }
  blob.len() >= 13 && blob[12] == 0x07
}

/// `MakerNoteKodak4` signature (`MakerNotes.pm:305-306`):
/// `$$valPt =~ /^.{41}JPG/s and $$valPt !~ /^(MM|II|AOC)/`.
/// 41 arbitrary bytes then the literal "JPG" at offset 41, and the blob must
/// not start with `MM`/`II`/`AOC`.
#[inline]
fn is_kodak4_sig(blob: &[u8]) -> bool {
  if starts_with(blob, b"MM") || starts_with(blob, b"II") || starts_with(blob, b"AOC") {
    return false;
  }
  blob.len() >= 44 && &blob[41..44] == b"JPG"
}

/// `MakerNoteKodak5` MODEL test (`MakerNotes.pm:318`):
/// `$$self{Model} =~ /CX(4200|4230|4300|4310|6200|6230)/` — unanchored
/// substring of `CX` followed by one of the six four-digit model numbers.
#[inline]
fn model_matches_kodak5(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  const SUFFIXES: [&str; 6] = ["4200", "4230", "4300", "4310", "6200", "6230"];
  let hb = m.as_bytes();
  // Find each "CX" occurrence; check the following 4 bytes against the set.
  let mut i = 0usize;
  while i + 6 <= hb.len() {
    if &hb[i..i + 2] == b"CX" {
      let tail = &hb[i + 2..i + 6];
      if SUFFIXES.iter().any(|s| s.as_bytes() == tail) {
        return true;
      }
    }
    i += 1;
  }
  false
}

/// `MakerNoteKodak5` SIGNATURE branch (`MakerNotes.pm:320`):
/// `$$valPt =~ /^\0(\x1a\x18|\x3a\x08|\x59\xf8|\x14\x80)\0/` — byte0 = NUL,
/// a two-byte tag at offset 1, then a NUL at offset 3.
#[inline]
fn is_kodak5_sig(blob: &[u8]) -> bool {
  if blob.len() < 4 || blob[0] != 0x00 || blob[3] != 0x00 {
    return false;
  }
  matches!(
    &blob[1..3],
    b"\x1a\x18" | b"\x3a\x08" | b"\x59\xf8" | b"\x14\x80"
  )
}

/// `MakerNoteKodak7` signature (`MakerNotes.pm:359`):
/// `$$valPt =~ /^[CK][A-Z\d]{3} ?[A-Z\d]{1,2}\d{2}[A-Z\d]\d{4}[ \0]/` — a
/// serial-number shape. The regex is variable-length (the optional space ` ?`
/// and the `{1,2}` quantifier), so this matcher tries the 4 length variants
/// (space×{0,1} × group-of-{1,2}) and accepts if any anchored match succeeds.
fn is_kodak7_sig(blob: &[u8]) -> bool {
  // `[CK]`
  if blob.first().is_none_or(|&b| b != b'C' && b != b'K') {
    return false;
  }
  let upper_or_digit = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
  // `[A-Z\d]{3}` at offset 1..4.
  if blob.len() < 4 || !blob[1..4].iter().all(|&b| upper_or_digit(b)) {
    return false;
  }
  // ` ?` then `[A-Z\d]{1,2}\d{2}[A-Z\d]\d{4}[ \0]`. Try with/without the
  // optional space and with the group as 1 or 2 chars; first anchored hit
  // wins (faithful to the regex engine's leftmost-match).
  for space in [1usize, 0] {
    for group in [2usize, 1] {
      // Offsets after the `[CK][A-Z\d]{3}` head (4 bytes):
      let mut p = 4 + space;
      // Optional-space byte must be a space when present.
      if space == 1 && (blob.len() <= 4 || blob[4] != b' ') {
        continue;
      }
      // `[A-Z\d]{group}`
      if blob.len() < p + group || !blob[p..p + group].iter().all(|&b| upper_or_digit(b)) {
        continue;
      }
      p += group;
      // `\d{2}`
      if blob.len() < p + 2 || !blob[p..p + 2].iter().all(u8::is_ascii_digit) {
        continue;
      }
      p += 2;
      // `[A-Z\d]`
      if blob.len() <= p || !upper_or_digit(blob[p]) {
        continue;
      }
      p += 1;
      // `\d{4}`
      if blob.len() < p + 4 || !blob[p..p + 4].iter().all(u8::is_ascii_digit) {
        continue;
      }
      p += 4;
      // `[ \0]`
      if blob.len() > p && (blob[p] == b' ' || blob[p] == 0x00) {
        return true;
      }
    }
  }
  false
}

/// `MakerNoteKodak8a` signature (`MakerNotes.pm:373-374`):
/// `$$valPt =~ /^\0[\x02-\x7f]..\0[\x01-\x0c]\0\0/s or
///  $$valPt =~ /^[\x02-\x7f]\0..[\x01-\x0c]\0..\0\0/s` — two IFD-shaped
/// headers (a plausible entry count + first-entry format/count probe).
#[inline]
fn is_kodak8a_sig(blob: &[u8]) -> bool {
  // Branch 1: `\0 [\x02-\x7f] . . \0 [\x01-\x0c] \0 \0` (8 bytes).
  let b1 = blob.len() >= 8
    && blob[0] == 0x00
    && (0x02..=0x7f).contains(&blob[1])
    && blob[4] == 0x00
    && (0x01..=0x0c).contains(&blob[5])
    && blob[6] == 0x00
    && blob[7] == 0x00;
  // Branch 2: `[\x02-\x7f] \0 . . [\x01-\x0c] \0 . . \0 \0` (10 bytes).
  let b2 = blob.len() >= 10
    && (0x02..=0x7f).contains(&blob[0])
    && blob[1] == 0x00
    && (0x01..=0x0c).contains(&blob[4])
    && blob[5] == 0x00
    && blob[8] == 0x00
    && blob[9] == 0x00;
  b1 || b2
}

/// `MakerNoteKodak8b` signature (`MakerNotes.pm:390`):
/// `$$valPt =~ /^MM\0\x2a\0\0\0\x08\0.\0\0/` — the BE padded-IFD header
/// (byte 8 = NUL, byte 9 = any, bytes 10-11 = NUL). 12 bytes.
#[inline]
fn is_kodak8b_sig(blob: &[u8]) -> bool {
  blob.len() >= 12
    && &blob[..8] == b"MM\x00\x2a\x00\x00\x00\x08"
    && blob[8] == 0x00
    && blob[10] == 0x00
    && blob[11] == 0x00
}

/// `MakerNoteKodak8c` signature (`MakerNotes.pm:405`):
/// `$$valPt =~ /^(MM\0\x2a\0\0\0\x08|II\x2a\0\x08\0\0\0)/` — either TIFF
/// magic + the 8-byte IFD-offset header. 8 bytes.
#[inline]
fn is_kodak8c_sig(blob: &[u8]) -> bool {
  starts_with(blob, b"MM\x00\x2a\x00\x00\x00\x08")
    || starts_with(blob, b"II\x2a\x00\x08\x00\x00\x00")
}

/// `MakerNoteKodak9` signature (`MakerNotes.pm:418`):
/// `$$valPt =~ m{^IIII[\x02\x03]\0.{14}\d{4}/\d{2}/\d{2} }s`. SIGNATURE-ONLY:
/// `IIII`, a model byte `\x02`/`\x03`, a NUL, 14 arbitrary bytes (incl. NUL
/// via `/s`), then a `YYYY/MM/DD ` date (4 digits, `/`, 2 digits, `/`, 2
/// digits, a trailing space). 31 bytes total.
#[inline]
fn is_kodak9_sig(blob: &[u8]) -> bool {
  if blob.len() < 31 || &blob[..4] != b"IIII" {
    return false;
  }
  if (blob[4] != 0x02 && blob[4] != 0x03) || blob[5] != 0x00 {
    return false;
  }
  // bytes 6..20 are the `.{14}` wildcard run (any bytes). The date field:
  blob[20..24].iter().all(u8::is_ascii_digit)
    && blob[24] == b'/'
    && blob[25..27].iter().all(u8::is_ascii_digit)
    && blob[27] == b'/'
    && blob[28..30].iter().all(u8::is_ascii_digit)
    && blob[30] == b' '
}

/// `MakerNoteKodak10` signature (`MakerNotes.pm:432`):
/// `$$valPt =~ /^(MM\0[\x02-\x7f]|II[\x02-\x7f]\0)/` — a byte-order indicator
/// (`MM`/`II`) immediately followed by the IFD entry count. 4 bytes.
#[inline]
fn is_kodak10_sig(blob: &[u8]) -> bool {
  if blob.len() < 4 {
    return false;
  }
  // BE: `MM \0 [\x02-\x7f]`.
  let be = &blob[..3] == b"MM\x00" && (0x02..=0x7f).contains(&blob[3]);
  // LE: `II [\x02-\x7f] \0`.
  let le = &blob[..2] == b"II" && (0x02..=0x7f).contains(&blob[2]) && blob[3] == 0x00;
  be || le
}

/// `$$self{Model} =~ /NEEDLE/` — an UNANCHORED, case-SENSITIVE Model
/// substring test (`MakerNoteKodak6a` `DX3215`, `Kodak6b` `DX3700`,
/// `MakerNotes.pm:332`/`:344`).
#[inline]
fn model_contains(model: Option<&str>, needle: &str) -> bool {
  matches!(model, Some(m) if m.contains(needle))
}

/// `$$self{Model} =~ /(Kodak|PixPro)/i` — the MODEL-keyed Kodak detection
/// used ONLY by `MakerNoteKodak11`/`Kodak12` (`MakerNotes.pm:446`/`:462`).
/// Those arms key on the Model (not the Make) because JK Imaging PixPro
/// bodies report `Make => "JK Imaging, Ltd."` while the Model carries
/// "Kodak"/"PixPro" (`MakerNotes.pm:444`/`:460`). Case-insensitive
/// substring, both tokens.
#[inline]
fn model_matches_kodak(model: Option<&str>) -> bool {
  matches!(model, Some(m) if contains_ascii_ci(m, "kodak") || contains_ascii_ci(m, "pixpro"))
}

/// `MakerNoteKodak11` blob signature (`MakerNotes.pm:447`):
/// `$$valPt =~ /^II\x2a\0\x08\0\0\0.\0\0\0/s` — the little-endian
/// 4-byte-entry-count padded IFD header (the `.` at offset 8 is ANY byte
/// via `/s`). 12 bytes total.
#[inline]
fn is_kodak11_le_ifd(blob: &[u8]) -> bool {
  blob.len() >= 12 && &blob[..8] == b"II\x2a\x00\x08\x00\x00\x00" && &blob[9..12] == b"\x00\x00\x00"
}

/// `MakerNoteKodak12` blob signature (`MakerNotes.pm:463`):
/// `$$valPt =~ /^MM\0\x2a\0\0\0\x08\0\0\0./s` — the big-endian
/// 4-byte-entry-count padded IFD header (the `.` at offset 11 is ANY byte
/// via `/s`). 12 bytes total.
#[inline]
fn is_kodak12_be_ifd(blob: &[u8]) -> bool {
  blob.len() >= 12 && &blob[..11] == b"MM\x00\x2a\x00\x00\x00\x08\x00\x00\x00"
}

/// `$$self{Make} =~ /^(PENTAX )?RICOH/`.
#[inline]
fn make_matches_ricoh(make: Option<&str>) -> bool {
  match make {
    Some(m) => m.starts_with("RICOH") || m.starts_with("PENTAX RICOH"),
    None => false,
  }
}

/// `$$self{Model}=~/^(HV|Stellar|Lusso|Lunar)/` — the Hasselblad
/// rebadged-Sony models routed to `MakerNoteSony5` (`MakerNotes.pm:1074`).
#[inline]
fn is_hasselblad_sony(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  m.starts_with("HV")
    || m.starts_with("Stellar")
    || m.starts_with("Lusso")
    || m.starts_with("Lunar")
}

/// `$$self{Model}=~/^C4\b/` — the SanyoC4 model carve-out
/// (`MakerNotes.pm:995`). The `\b` word-boundary means `C4` is followed
/// by a non-word character (or end of string); `C40` would NOT match.
#[inline]
fn model_matches_sanyo_c4(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  let Some(rest) = m.strip_prefix("C4") else {
    return false;
  };
  // `\b` after `C4`: end-of-string, or the next char is not a word char
  // (`[A-Za-z0-9_]`). `C4` (`4` is a word char) → boundary requires the
  // following char to be a non-word char.
  match rest.bytes().next() {
    None => true,
    Some(b) => !(b.is_ascii_alphanumeric() || b == b'_'),
  }
}

/// `MakerNoteSamsung2` EXIF-format magic (`MakerNotes.pm:970`):
/// `$$valPt=~/^(\0.\0\x01\0\x07\0{3}\x04|.\0\x01\0\x07\0\x04\0{3})0100/s`.
/// Both alternatives are a 10-byte one-entry TIFF IFD prologue (tag,
/// `format=7` "undefined", `count=4`) followed by the 4-byte ASCII version
/// `"0100"` at offset 10 — 14 bytes total. Branch A is the big-endian
/// layout (`\0.\0\x01\0\x07\0\0\0\x04`); branch B the little-endian
/// (`.\0\x01\0\x07\0\x04\0\0\0`). The `.` (any byte, `/s`) is the low/high
/// byte of the entry's tag id.
#[inline]
fn is_samsung2_sig(blob: &[u8]) -> bool {
  if blob.len() < 14 || &blob[10..14] != b"0100" {
    return false;
  }
  // Branch A (BE): `\0 . \0 \x01 \0 \x07 \0 \0 \0 \x04`.
  let branch_a = blob[0] == 0x00
    && blob[2] == 0x00
    && blob[3] == 0x01
    && blob[4] == 0x00
    && blob[5] == 0x07
    && &blob[6..10] == b"\x00\x00\x00\x04";
  // Branch B (LE): `. \0 \x01 \0 \x07 \0 \x04 \0 \0 \0`.
  let branch_b = blob[1] == 0x00
    && blob[2] == 0x01
    && blob[3] == 0x00
    && blob[4] == 0x07
    && blob[5] == 0x00
    && blob[6] == 0x04
    && &blob[7..10] == b"\x00\x00\x00";
  branch_a || branch_b
}

/// `MakerNoteReconyxHyperFire` selection (`MakerNotes.pm:856-859`):
/// `$$valPt =~ /^\x01\xf1([\x02\x03]\x00)?/ and ($1 or $$self{Make} eq
/// "RECONYX")`. The `\x01\xf1` prefix is required; the optional group
/// `[\x02\x03]\x00` (a model byte `\x02`/`\x03` then `\x00`) selects the
/// entry when it matches, otherwise selection needs `Make eq "RECONYX"`.
#[inline]
fn is_reconyx_hyperfire(blob: &[u8], make: Option<&str>) -> bool {
  if !starts_with(blob, b"\x01\xf1") {
    return false;
  }
  // The optional `([\x02\x03]\x00)` group — `$1` is set iff it matched.
  let group_matched = blob.len() >= 4 && (blob[2] == 0x02 || blob[2] == 0x03) && blob[3] == 0x00;
  group_matched || make_eq(make, "RECONYX")
}

/// `MakerNoteRicoh2` blob patterns (`MakerNotes.pm:931`):
/// `$$valPt =~ /^(MM\0\x2a\0\0\0\x08\0.\0\0|II\x2a\0\x08\0\0\0.\0\0\0)/s`
/// — the two big/little-endian padded-IFD headers (the `.` is ANY single
/// byte at offset 8, including NUL, via the `/s` flag). 12 bytes total.
#[inline]
fn is_ricoh2_padded_ifd(blob: &[u8]) -> bool {
  if blob.len() < 12 {
    return false;
  }
  // BE `MM\0\x2a\0\0\0\x08\0.\0\0`: bytes 0..8 = `MM\0\x2a\0\0\0\x08`,
  // byte 8 = `\0`, byte 9 = wildcard (`.`), bytes 10..12 = `\0\0`.
  let be =
    &blob[..8] == b"MM\x00\x2a\x00\x00\x00\x08" && blob[8] == 0x00 && &blob[10..12] == b"\x00\x00";
  // LE `II\x2a\0\x08\0\0\0.\0\0\0`: bytes 0..8 = `II\x2a\0\x08\0\0\0`,
  // byte 8 = wildcard (`.`), bytes 9..12 = `\0\0\0`.
  let le = &blob[..8] == b"II\x2a\x00\x08\x00\x00\x00" && &blob[9..12] == b"\x00\x00\x00";
  be || le
}

/// `MakerNoteUnknownText` (`MakerNotes.pm:1103`):
/// `$$valPt =~ /^[\x09\x0d\x0a\x20-\x7e]+\0*$/` — a NON-EMPTY run of
/// printable/whitespace ASCII (TAB, LF, CR, or `0x20..=0x7e`), then zero
/// or more trailing NULs, anchored to the end of the blob.
#[inline]
fn is_unknown_text(blob: &[u8]) -> bool {
  // First NUL position (the boundary between the printable run and the
  // optional NUL padding). `find` over bytes.
  let first_nul = blob.iter().position(|&b| b == 0x00).unwrap_or(blob.len());
  let (head, tail) = blob.split_at(first_nul);
  // `[...]+` is one-or-more: the printable run must be non-empty.
  if head.is_empty() {
    return false;
  }
  // Every byte of the head must be in the printable/whitespace set.
  if !head
    .iter()
    .all(|&b| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
  {
    return false;
  }
  // `\0*$` — everything from the first NUL to the end must be NUL.
  tail.iter().all(|&b| b == 0x00)
}

/// Substring case-insensitive (ASCII) — `haystack.to_lowercase().contains(needle)` without alloc.
#[inline]
fn contains_ascii_ci(haystack: &str, needle_lower: &str) -> bool {
  if needle_lower.is_empty() {
    return true;
  }
  let nb = needle_lower.as_bytes();
  let hb = haystack.as_bytes();
  if hb.len() < nb.len() {
    return false;
  }
  for window_start in 0..=(hb.len() - nb.len()) {
    if hb[window_start..window_start + nb.len()]
      .iter()
      .zip(nb.iter())
      .all(|(h, n)| h.to_ascii_lowercase() == *n)
    {
      return true;
    }
  }
  false
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Apple iOS — the canonical signature dispatch.
  /// (`MakerNotes.pm:38-46`)
  #[test]
  fn apple_signature_dispatches() {
    let blob = b"Apple iOS\x00\x00\x01MMrest_of_the_ifd_data";
    let d = dispatch(blob, Some("Apple"), Some("iPhone 13"), None);
    assert!(d.vendor().is_apple());
    assert_eq!(d.body_offset(), 14);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-14));
    assert!(d.byte_order().is_unknown());
    assert!(!d.is_not_ifd());
  }

  /// Canon — no signature; Make-only dispatch.
  /// (`MakerNotes.pm:60-68`)
  #[test]
  fn canon_make_only_dispatches() {
    // The blob has NO Canon prefix; Canon starts directly with the IFD.
    let blob = &[0x01, 0x00, 0x00, 0x00, 0x04, 0x00][..];
    let d = dispatch(blob, Some("Canon"), Some("EOS R5"), None);
    assert!(d.vendor().is_canon());
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_inherit());
    assert!(d.byte_order().is_unknown());
  }

  /// Sony primary (DSC) — `SONY DSC \0` (`MakerNotes.pm:1036`).
  #[test]
  fn sony_dsc_signature_dispatches() {
    let blob = b"SONY DSC \x00rest_of_the_data";
    let d = dispatch(blob, Some("SONY"), Some("DSC-RX100"), None);
    assert!(d.vendor().is_sony());
    assert_eq!(d.body_offset(), 12);
    assert!(d.base_rule().is_inherit());
  }

  /// Finding 2: Sony primary regex `/^SONY (DSC|CAM|MOBILE)/` requires NO
  /// trailing space after the token. `SONY DSC\0…` (NUL immediately after
  /// "DSC", no trailing space) must dispatch to `MakerNoteSony`
  /// (`MakerNotes.pm:1036`, `Start => '$valuePtr + 12'`) — NOT fall through
  /// to Sony5 (`Start => '$valuePtr'`, body_offset 0).
  #[test]
  fn sony_dsc_no_trailing_space_dispatches_to_primary() {
    let blob = b"SONY DSC\x00rest_of_the_data";
    let d = dispatch(blob, Some("SONY"), Some("DSC-W830"), None);
    assert!(d.vendor().is_sony());
    assert_eq!(
      d.body_offset(),
      12,
      "SONY DSC\\0 must hit Sony primary (offset 12), not Sony5 (offset 0)"
    );
    assert!(d.base_rule().is_inherit());
    assert!(d.byte_order().is_unknown());
  }

  /// Sony primary CAM / MOBILE prefixes (`MakerNotes.pm:1036`) — also no
  /// required trailing space.
  #[test]
  fn sony_cam_and_mobile_prefixes_dispatch_to_primary() {
    let cam = dispatch(b"SONY CAM\x00data", Some("SONY"), None, None);
    assert!(cam.vendor().is_sony());
    assert_eq!(cam.body_offset(), 12);

    let mobile = dispatch(b"SONY MOBILE\x00data", Some("SONY"), None, None);
    assert!(mobile.vendor().is_sony());
    assert_eq!(mobile.body_offset(), 12);
  }

  /// Sony 5 — `MakerNoteSony5` `$$self{Make}=~/^SONY/` and blob does NOT
  /// start with `\x01\x00` (`MakerNotes.pm:1071-1080`).
  #[test]
  fn sony_make_only_dispatches() {
    let blob = b"\x00\x00ifd_data_no_known_prefix";
    let d = dispatch(blob, Some("SONY"), None, None);
    assert!(d.vendor().is_sony());
    assert_eq!(d.body_offset(), 0);
  }

  /// Panasonic primary — `Panasonic` prefix (`MakerNotes.pm:732-740`).
  #[test]
  fn panasonic_signature_dispatches() {
    let blob = b"Panasonic\x00\x00\x00rest";
    let d = dispatch(blob, Some("Panasonic"), Some("DC-S5"), None);
    assert!(d.vendor().is_panasonic());
    assert_eq!(d.body_offset(), 12);
  }

  /// Panasonic DC-FT7 — same signature but routes to `MakerNotePanasonic3`
  /// (`Base => 12` LITERAL, `MakerNotes.pm:751-760`).
  #[test]
  fn panasonic_dc_ft7_routes_to_phase3() {
    let blob = b"Panasonic\x00\x00\x00rest";
    let d = dispatch(blob, Some("Panasonic"), Some("DC-FT7"), None);
    assert!(d.vendor().is_panasonic());
    assert_eq!(d.body_offset(), 12);
    assert_eq!(d.base_rule(), BaseRule::Literal(12));
  }

  /// DJI — `$$self{Make} eq "DJI"` (`MakerNotes.pm:99-106`).
  #[test]
  fn dji_make_only_dispatches() {
    let blob = b"\x01\x00\x00\x00ifd_data";
    let d = dispatch(blob, Some("DJI"), None, None);
    assert!(d.vendor().is_dji());
  }

  /// DJI Info — `[ae_dbg_info:` prefix (`MakerNotes.pm:93-97`).
  #[test]
  fn dji_info_signature_dispatches_not_ifd() {
    let blob = b"[ae_dbg_info: some debug text]";
    let d = dispatch(blob, Some("DJI"), None, None);
    assert!(d.vendor().is_dji());
    assert!(d.is_not_ifd());
  }

  /// Nikon takes precedence over Apple — `MakerNotes.pm:50-58` (the
  /// ordering note: Nikon Capture NX can write Nikon MakerNotes into
  /// JPEGs from any camera model).
  #[test]
  fn nikon_signature_precedes_apple() {
    let blob = b"Nikon\x00\x02\x10\x00\x00\x00MM\x00\x2arest";
    // The Make is "Apple" but the SIGNATURE says Nikon — bundled tests
    // Nikon FIRST.
    let d = dispatch(blob, Some("Apple"), Some("iPhone"), None);
    assert!(d.vendor().is_nikon());
    assert_eq!(d.body_offset(), 18);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Pentax — `AOC\0` signature (`MakerNotes.pm:762-779`).
  #[test]
  fn pentax_aoc_signature_dispatches() {
    let blob = b"AOC\x00\x00\x01MM";
    let d = dispatch(blob, Some("PENTAX"), Some("K-1"), None);
    assert!(d.vendor().is_pentax());
    assert_eq!(d.body_offset(), 0);
  }

  /// PENTAX 5 — `PENTAX \0` (`MakerNotes.pm:817-827`).
  #[test]
  fn pentax5_signature_dispatches_with_offset() {
    let blob = b"PENTAX \x00rest_of_the_blob_with_ifd";
    let d = dispatch(blob, Some("PENTAX"), Some("Q"), None);
    assert!(d.vendor().is_pentax());
    assert_eq!(d.body_offset(), 10);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-10));
  }

  /// Olympus — `OLYMP\0` (`MakerNotes.pm:565-576`).
  #[test]
  fn olympus_signature_dispatches() {
    let blob = b"OLYMP\x00\x00\x00rest";
    let d = dispatch(blob, Some("OLYMPUS"), Some("E-M1"), None);
    assert!(d.vendor().is_olympus());
    assert_eq!(d.body_offset(), 8);
  }

  /// Olympus 2 — `OLYMPUS\0` (`MakerNotes.pm:577-587`).
  #[test]
  fn olympus2_signature_dispatches() {
    let blob = b"OLYMPUS\x00II\x2a\x00rest";
    let d = dispatch(blob, Some("OLYMPUS"), Some("E-M1"), None);
    assert!(d.vendor().is_olympus());
    assert_eq!(d.body_offset(), 12);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-12));
  }

  /// Olympus 3 / OM SYSTEM — `OM SYSTEM\0` (`MakerNotes.pm:588-598`).
  #[test]
  fn om_system_signature_dispatches() {
    let blob = b"OM SYSTEM\x00MM\x00\x2arest";
    let d = dispatch(blob, Some("OM Digital Solutions"), Some("OM-1"), None);
    assert!(d.vendor().is_olympus());
    assert_eq!(d.body_offset(), 16);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-16));
  }

  /// FujiFilm — `FUJIFILM` (`MakerNotes.pm:118-134`). Fuji has NO `Start`
  /// directive: `OffsetPt => '$valuePtr+8'` (`:128`) reads a 4-byte IFD
  /// pointer at offset 8, it does NOT skip 8 bytes. So `offset_pt==Some(8)`
  /// and `body_offset==0`. LittleEndian explicit, `Base => '$start'`.
  #[test]
  fn fujifilm_signature_dispatches() {
    let blob = b"FUJIFILMrest_of_the_ifd_data";
    let d = dispatch(blob, Some("FUJIFILM"), Some("X-T4"), None);
    assert!(d.vendor().is_fuji());
    assert_eq!(d.offset_pt(), Some(8));
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_start_itself());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// GENERALE (GE-made Fuji) shares the Fuji `OffsetPt`/`body_offset`
  /// shape (`MakerNotes.pm:124` `^(FUJIFILM|GENERALE)`).
  #[test]
  fn fujifilm_generale_signature_dispatches() {
    let blob = b"GENERALErest_of_the_ifd_data";
    let d = dispatch(blob, Some("GE"), None, None);
    assert!(d.vendor().is_fuji());
    assert_eq!(d.offset_pt(), Some(8));
    assert_eq!(d.body_offset(), 0);
  }

  /// Leica — Make-based dispatch (`MakerNotes.pm:600-608`).
  #[test]
  fn leica_make_only_dispatches() {
    let blob = b"\x01\x00ifd_no_signature";
    let d = dispatch(blob, Some("LEICA"), Some("M (Typ 240)"), None);
    assert!(d.vendor().is_leica());
    assert_eq!(d.body_offset(), 8);
  }

  /// Leica7 — `LEICA\0\x02\xff` (`MakerNotes.pm:689-701`) uses
  /// `NegativeOfBase` — the ONLY case in the bundled module.
  #[test]
  fn leica7_uses_negative_of_base() {
    let blob = b"LEICA\x00\x02\xffrest_of_the_data";
    let d = dispatch(blob, Some("Leica Camera AG"), Some("M Monochrom"), None);
    assert!(d.vendor().is_leica());
    assert!(d.base_rule().is_negative_of_base());
  }

  /// PhaseOne IIQ — `IIII.waR` (`MakerNotes.pm:840-852`). `NotIFD => 1`.
  #[test]
  fn phaseone_signature_dispatches_not_ifd() {
    let blob = b"IIIITwaRrest_of_the_phaseone_blob";
    let d = dispatch(blob, Some("Phase One"), None, None);
    assert_eq!(d.vendor(), Vendor::PhaseOne);
    assert!(d.is_not_ifd());
  }

  /// Casio2 — `QVC\0` (`MakerNotes.pm:81-91`).
  #[test]
  fn casio2_qvc_dispatches() {
    let blob = b"QVC\x00\x00\x00rest";
    let d = dispatch(blob, Some("CASIO"), None, None);
    assert!(d.vendor().is_casio());
    assert_eq!(d.body_offset(), 6);
  }

  /// Motorola — `MOT\0` (`MakerNotes.pm:528-535`).
  #[test]
  fn motorola_signature_dispatches() {
    let blob = b"MOT\x00rest_of_the_ifd_data";
    let d = dispatch(blob, Some("Motorola"), Some("DROID"), None);
    assert_eq!(d.vendor(), Vendor::Motorola);
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Reconyx UltraFire — `RECONYXUF\0` (`MakerNotes.pm:866-871`).
  #[test]
  fn reconyx_signature_dispatches_not_ifd() {
    let blob = b"RECONYXUF\x00rest";
    let d = dispatch(blob, Some("RECONYX"), None, None);
    assert_eq!(d.vendor(), Vendor::Reconyx);
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// Sony Ericsson — `SEMC MS\0` (`MakerNotes.pm:1082-1090`).
  #[test]
  fn sony_ericsson_signature_dispatches() {
    let blob = b"SEMC MS\x00rest_of_the_data";
    let d = dispatch(blob, Some("Sony Ericsson"), None, None);
    assert!(d.vendor().is_sony());
    assert_eq!(d.body_offset(), 20);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// The catch-all — no signature, no recognized Make → `Vendor::Unknown`
  /// (`MakerNotes.pm:1117-1126`).
  #[test]
  fn unknown_makernote_routes_to_unknown() {
    let blob = b"some-random-bytes-no-known-signature";
    let d = dispatch(blob, Some("RandomVendor"), Some("RandomModel"), None);
    assert!(d.vendor().is_unknown());
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_inherit());
  }

  /// The catch-all when there is NO Make at all (degenerate file).
  #[test]
  fn no_make_no_signature_routes_to_unknown() {
    let blob = b"\x00\x01\x02\x03";
    let d = dispatch(blob, None, None, None);
    assert!(d.vendor().is_unknown());
  }

  /// LSI1 — `MakerNoteUnknownBinary` (`MakerNotes.pm:1109-1114`). Routes
  /// to `Unknown` (no vendor) and marks `NotIFD`.
  #[test]
  fn lsi1_signature_routes_to_unknown_not_ifd() {
    let blob = b"LSI1\x00rest";
    let d = dispatch(blob, Some("UnknownVendor"), None, None);
    assert!(d.vendor().is_unknown());
    assert!(d.is_not_ifd());
  }

  /// HP6 — `IIII\x06\0` (`MakerNotes.pm:215-224`). `NotIFD => 1`,
  /// `LittleEndian` explicit.
  #[test]
  fn hp6_signature_dispatches() {
    let blob = b"IIII\x06\x00rest_of_the_data";
    let d = dispatch(blob, Some("Hewlett-Packard"), Some("PhotoSmart M425"), None);
    assert_eq!(d.vendor(), Vendor::Hp);
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// Kyocera — `KYOCERA` prefix (`MakerNotes.pm:483-492`).
  #[test]
  fn kyocera_signature_dispatches() {
    let blob = b"KYOCERArest_of_the_kyocera_blob";
    let d = dispatch(blob, Some("KYOCERA"), None, None);
    assert_eq!(d.vendor(), Vendor::Kyocera);
    assert_eq!(d.body_offset(), 22);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(2));
  }

  /// Hasselblad pure-Make dispatch (`MakerNotes.pm:169-182`).
  #[test]
  fn hasselblad_pure_make_dispatches() {
    let blob = b"\x00\x01ifd";
    let d = dispatch(blob, Some("Hasselblad"), Some("H6D-100c"), None);
    assert_eq!(d.vendor(), Vendor::Hasselblad);
  }

  /// Sigma — `$$self{Make}=~/^(SIGMA|FOVEON)/i` (`MakerNotes.pm:1016-1029`).
  #[test]
  fn sigma_make_dispatches() {
    let blob = b"SIGMA\x00\x00\x00\x01rest";
    let d = dispatch(blob, Some("SIGMA"), Some("fp L"), None);
    assert_eq!(d.vendor(), Vendor::Sigma);
    assert_eq!(d.body_offset(), 10);
  }

  /// FOVEON Make (case-insensitive) — same Sigma dispatch
  /// (`MakerNotes.pm:1019` `/^(SIGMA|FOVEON)/i`).
  #[test]
  fn foveon_make_dispatches_to_sigma() {
    let blob = b"FOVEON\x00rest";
    let d = dispatch(blob, Some("foveon"), Some("SD1"), None);
    assert_eq!(d.vendor(), Vendor::Sigma);
  }

  /// Vendor::status — the phase tagging surface.
  #[test]
  fn vendor_status_buckets() {
    use super::super::vendor::VendorStatus;
    assert_eq!(Vendor::Apple.status(), VendorStatus::Phase2);
    assert_eq!(Vendor::Canon.status(), VendorStatus::Phase2);
    assert_eq!(Vendor::Sony.status(), VendorStatus::Phase3);
    assert_eq!(Vendor::Panasonic.status(), VendorStatus::Phase3);
    assert_eq!(Vendor::GoPro.status(), VendorStatus::Phase4);
    assert_eq!(Vendor::Dji.status(), VendorStatus::Phase4);
    assert_eq!(Vendor::Nikon.status(), VendorStatus::Deferred);
    assert_eq!(Vendor::Unknown.status(), VendorStatus::Unknown);
    assert!(Vendor::Apple.status().is_scheduled());
    assert!(Vendor::Nikon.status().is_deferred());
    assert!(Vendor::Unknown.status().is_unknown());
  }

  /// Phase-tagging predicates surface every vendor's status correctly.
  #[test]
  fn signature_based_predicate() {
    // Canon / GoPro / Unknown are make-only (no signature).
    assert!(!Vendor::Canon.is_signature_based());
    assert!(!Vendor::GoPro.is_signature_based());
    assert!(!Vendor::Unknown.is_signature_based());
    // The rest are signature-bearing.
    assert!(Vendor::Apple.is_signature_based());
    assert!(Vendor::Sony.is_signature_based());
    assert!(Vendor::Panasonic.is_signature_based());
  }

  /// `ChildByteOrder` predicates.
  #[test]
  fn child_byte_order_predicates() {
    assert!(ChildByteOrder::Unknown.is_unknown());
    assert!(!ChildByteOrder::Unknown.is_explicit());
    assert_eq!(ChildByteOrder::Unknown.explicit(), None);
    let be = ChildByteOrder::Explicit(ByteOrder::Big);
    assert!(be.is_explicit());
    assert!(!be.is_unknown());
    assert_eq!(be.explicit(), Some(ByteOrder::Big));
    assert_eq!(be.as_str(), "MM");
  }

  /// `BaseRule` predicates / accessors.
  #[test]
  fn base_rule_predicates() {
    assert!(BaseRule::Inherit.is_inherit());
    assert!(BaseRule::StartItself.is_start_itself());
    assert!(BaseRule::NegativeOfBase.is_negative_of_base());
    let r = BaseRule::RelativeToStart(-14);
    assert!(r.is_relative_to_start());
    assert_eq!(r.relative_delta(), Some(-14));
    assert_eq!(BaseRule::Inherit.relative_delta(), None);
  }

  /// Empty blob falls through to the catch-all (NOT a panic).
  #[test]
  fn empty_blob_is_unknown() {
    let d = dispatch(&[], None, None, None);
    assert!(d.vendor().is_unknown());
  }

  /// A very short blob (< signature length) still falls through cleanly.
  #[test]
  fn very_short_blob_does_not_panic() {
    // "Ap" — too short for "Apple iOS\0".
    let d = dispatch(b"Ap", Some("Apple"), None, None);
    assert!(d.vendor().is_unknown());
  }

  /// JVC text — Make + body double-condition (`MakerNotes.pm:245-251`).
  #[test]
  fn jvc_text_signature_double_condition() {
    let blob = b"VER:1.0.0\n";
    let d = dispatch(blob, Some("JVC"), None, None);
    assert_eq!(d.vendor(), Vendor::Jvc);
    assert!(d.is_not_ifd());
  }

  /// JVC binary — `JVC ` prefix wins regardless of Make
  /// (`MakerNotes.pm:236-243` has signature-only condition).
  #[test]
  fn jvc_binary_signature_dispatches() {
    let blob = b"JVC \x01\x00rest";
    let d = dispatch(blob, None, None, None);
    assert_eq!(d.vendor(), Vendor::Jvc);
    assert_eq!(d.body_offset(), 4);
  }

  /// Empty Make + signature still resolves (Make is checked only for
  /// vendors that need it).
  #[test]
  fn no_make_with_signature_resolves() {
    let blob = b"Apple iOS\x00\x00\x01MM";
    let d = dispatch(blob, None, None, None);
    assert!(d.vendor().is_apple());
  }

  // ----- Finding 1: Kodak `AOC\0` falls through to Pentax; generic Kodak
  // is `MakerNoteKodakUnknown` (NotIFD + BigEndian).

  /// A Kodak-made body with the `AOC\0` Pentax signature must NOT be
  /// consumed by the Kodak block (`MakerNotes.pm:475` `$$valPt!~/^AOC\0/`)
  /// — it falls through to the Pentax `AOC\0` arm (`MakerNotes.pm:762-779`).
  #[test]
  fn kodak_make_with_aoc_blob_falls_through_to_pentax() {
    let blob = b"AOC\x00\x00\x01MMrest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("DX7590 ZOOM"),
      None,
    );
    assert!(d.vendor().is_pentax(), "got {:?}", d.vendor());
    assert!(d.fix_base()); // Pentax primary sets FixBase
  }

  /// Generic Kodak (non-KDK, non-AOC) is `MakerNoteKodakUnknown`
  /// (`MakerNotes.pm:474-481`): `NotIFD => 1`, explicit BigEndian.
  #[test]
  fn kodak_unknown_is_not_ifd_big_endian() {
    let blob = b"\x00\x01\x02\x03not-a-kdk-or-aoc-blob";
    let d = dispatch(blob, Some("Kodak"), Some("Z990"), None);
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  // ----- Finding 2: Ricoh2 carve-out.

  /// Ricoh2 by Model — `RICOH WG-M1` routes to Ricoh2
  /// (`MakerNotes.pm:924-939`): `body_offset=8`, `Base => '$start - 8'`.
  #[test]
  fn ricoh2_wg_m1_model_dispatches() {
    let blob = b"\x00\x01ifd_body_no_prefix";
    let d = dispatch(blob, Some("RICOH"), Some("RICOH WG-M1"), None);
    assert!(d.vendor().is_ricoh());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Ricoh2 by blob — the BE padded-IFD pattern
  /// `MM\0\x2a\0\0\0\x08\0.\0\0` (`MakerNotes.pm:931`) routes to Ricoh2.
  #[test]
  fn ricoh2_be_padded_ifd_dispatches() {
    // MM \0 \x2a \0 \0 \0 \x08 \0 <wild=0x05> \0 \0  (12 bytes)
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x05\x00\x00rest";
    let d = dispatch(blob, Some("PENTAX RICOH"), Some("XG-1"), None);
    assert!(d.vendor().is_ricoh());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Ricoh2 by blob — the LE padded-IFD pattern
  /// `II\x2a\0\x08\0\0\0.\0\0\0` (`MakerNotes.pm:931`) routes to Ricoh2.
  #[test]
  fn ricoh2_le_padded_ifd_dispatches() {
    // II \x2a \0 \x08 \0 \0 \0 <wild=0x07> \0 \0 \0  (12 bytes)
    let blob = b"II\x2a\x00\x08\x00\x00\x00\x07\x00\x00\x00rest";
    let d = dispatch(blob, Some("RICOH"), Some("HZ15"), None);
    assert!(d.vendor().is_ricoh());
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// A plain Ricoh `MM\0\x2a` (NOT the padded-IFD Ricoh2 shape) still
  /// routes to the `MakerNoteRicoh` positive arm (`MakerNotes.pm:919`,
  /// `Base` inherited).
  #[test]
  fn ricoh_plain_mm_prefix_is_not_ricoh2() {
    // MM\0\x2a then a NON-Ricoh2 continuation (byte 7 != 0x08).
    let blob = b"MM\x00\x2a\x00\x00\x00\x01ifd";
    let d = dispatch(blob, Some("RICOH"), Some("GR II"), None);
    assert!(d.vendor().is_ricoh());
    assert_eq!(d.body_offset(), 8);
    assert!(d.base_rule().is_inherit()); // Ricoh, NOT Ricoh2
  }

  // ----- Finding 4: Panasonic3 + Hasselblad literal Base.

  /// Panasonic3 (DC-FT7) — `Base => 12` is a LITERAL
  /// (`MakerNotes.pm:758`), captured as `BaseRule::Literal(12)`.
  #[test]
  fn panasonic3_base_is_literal() {
    let blob = b"Panasonic\x00\x00\x00rest";
    let d = dispatch(blob, Some("Panasonic"), Some("DC-FT7"), None);
    assert!(d.vendor().is_panasonic());
    assert_eq!(d.body_offset(), 12);
    assert_eq!(d.base_rule(), BaseRule::Literal(12));
    assert!(d.base_rule().is_literal());
    assert_eq!(d.base_rule().literal(), Some(12));
  }

  /// Hasselblad — `Base => 0` is a LITERAL (`MakerNotes.pm:176`),
  /// captured as `BaseRule::Literal(0)` (not `Inherit`).
  #[test]
  fn hasselblad_base_is_literal_zero() {
    let blob = b"\x00\x01ifd";
    let d = dispatch(blob, Some("Hasselblad"), Some("H6D-100c"), None);
    assert_eq!(d.vendor(), Vendor::Hasselblad);
    assert_eq!(d.base_rule(), BaseRule::Literal(0));
  }

  // ----- Finding 5: Reconyx HyperFire guard.

  /// Bare `\x01\xf1` (no `[\x02\x03]\x00` group) is HyperFire ONLY when
  /// `Make eq "RECONYX"` (`MakerNotes.pm:856-859`).
  #[test]
  fn reconyx_bare_prefix_requires_make() {
    let blob = b"\x01\xf1\x10\x20rest"; // byte2 not in {0x02,0x03}
    // With RECONYX make → HyperFire.
    let d = dispatch(blob, Some("RECONYX"), None, None);
    assert_eq!(d.vendor(), Vendor::Reconyx);
    assert!(d.is_not_ifd());
    // Without RECONYX make → NOT Reconyx (falls through).
    let d2 = dispatch(blob, Some("SomeoneElse"), None, None);
    assert_ne!(d2.vendor(), Vendor::Reconyx);
  }

  /// `\x01\xf1` followed by the optional `[\x02\x03]\x00` group matches
  /// HyperFire regardless of Make (`$1` is set).
  #[test]
  fn reconyx_with_group_matches_without_make() {
    let blob = b"\x01\xf1\x02\x00rest";
    let d = dispatch(blob, Some("NotReconyx"), None, None);
    assert_eq!(d.vendor(), Vendor::Reconyx);
  }

  // ----- Finding 6: Unknown text catch-all.

  /// Printable-ASCII blob with trailing NULs → `MakerNoteUnknownText`
  /// (`MakerNotes.pm:1101-1108`): `Vendor::Unknown`, `NotIFD => 1`.
  #[test]
  fn unknown_text_blob_dispatches() {
    let blob = b"Ver1.00 some text\x00\x00";
    let d = dispatch(blob, Some("NoSuchVendor"), None, None);
    assert!(d.vendor().is_unknown());
    assert!(d.is_not_ifd());
  }

  /// A blob with a non-printable byte is NOT text — falls through to the
  /// binary `MakerNoteUnknown` catch-all (NotIFD stays false).
  #[test]
  fn unknown_text_rejects_non_printable() {
    let blob = b"text\x01more"; // 0x01 is not in the printable set
    let d = dispatch(blob, Some("NoSuchVendor"), None, None);
    assert!(d.vendor().is_unknown());
    assert!(!d.is_not_ifd()); // binary catch-all, not the text arm
  }

  /// An all-NUL blob is NOT text (the printable run must be non-empty,
  /// `[...]+`).
  #[test]
  fn unknown_text_rejects_all_nul() {
    let blob = b"\x00\x00\x00\x00";
    let d = dispatch(blob, Some("NoSuchVendor"), None, None);
    assert!(d.vendor().is_unknown());
    assert!(!d.is_not_ifd());
  }

  // ----- Finding 7: FixBase / EntryBased flags.

  /// FixBase flag is captured for the vendors bundled marks `FixBase`.
  #[test]
  fn fix_base_flag_is_captured() {
    // Casio2 (`MakerNotes.pm:90`).
    assert!(dispatch(b"QVC\x00rest", Some("CASIO"), None, None).fix_base());
    // GE (`MakerNotes.pm:141`).
    assert!(dispatch(b"GE\x00\x00rest", Some("General Imaging"), None, None).fix_base());
    // Pentax primary (`MakerNotes.pm:777`).
    assert!(dispatch(b"AOC\x00rest", Some("PENTAX"), Some("K-1"), None).fix_base());
    // Pentax2/3 Asahi (`MakerNotes.pm:789`/`:801`).
    assert!(dispatch(b"\x00\x01ifd", Some("Asahi Optical Co.,Ltd."), None, None).fix_base());
    // Samsung2 (`MakerNotes.pm:977`).
    assert!(dispatch(b"\x00\x01ifd", Some("SAMSUNG"), None, None).fix_base());
    // SanyoC4 — Model `^C4\b` (`MakerNotes.pm:1000`).
    assert!(dispatch(b"SANYO\x00ifd", Some("SANYO"), Some("C4"), None).fix_base());
    // The Unknown catch-all (`MakerNotes.pm:1124` `FixBase => 2`).
    assert!(dispatch(b"\xde\xad\xbe\xef", Some("Nobody"), None, None).fix_base());
  }

  /// FixBase is NOT set for vendors bundled does not mark (e.g. plain
  /// Sanyo with a non-C4 model, or Canon).
  #[test]
  fn fix_base_flag_absent_when_not_marked() {
    // Plain Sanyo (Model not C4) — `MakerNoteSanyo` has no FixBase.
    assert!(!dispatch(b"SANYO\x00ifd", Some("SANYO"), Some("VPC-S1"), None).fix_base());
    // SanyoC4 word-boundary: "C40" must NOT match `^C4\b`.
    assert!(!dispatch(b"SANYO\x00ifd", Some("SANYO"), Some("C40"), None).fix_base());
    // Canon — no FixBase.
    assert!(!dispatch(b"\x00\x01ifd", Some("Canon"), Some("EOS R5"), None).fix_base());
  }

  /// EntryBased flag is captured for Kyocera (`MakerNotes.pm:490`).
  #[test]
  fn entry_based_flag_is_captured() {
    let d = dispatch(b"KYOCERArest_of_blob", Some("KYOCERA"), None, None);
    assert!(d.entry_based());
    // Non-Kyocera vendors leave it false.
    assert!(!dispatch(b"\x00\x01ifd", Some("Canon"), None, None).entry_based());
  }

  // ----- Finding 8: Sony5 / SonySRF / Hasselblad-rebadge `\x01\x00`.

  /// `Make="SONY"` + `\x01\x00` blob: Sony5 is excluded by its
  /// `$$valPt!~/^\x01\x00/` lookahead, so `MakerNoteSonySRF`
  /// (`MakerNotes.pm:1092-1099`, `Make=~/^SONY/`) catches it → Sony.
  #[test]
  fn sony_srf_x0100_blob_dispatches_to_sony() {
    let blob = b"\x01\x00rest_of_srf_header";
    let d = dispatch(blob, Some("SONY"), Some("DSC-R1"), None);
    assert!(d.vendor().is_sony());
    assert_eq!(d.body_offset(), 0);
  }

  /// A Hasselblad-rebadged-Sony body that IS `\x01\x00` matches NEITHER
  /// Sony5 (lookahead) NOR SonySRF (requires `Make=~/^SONY/`, but Make is
  /// HASSELBLAD) → falls through to `Vendor::Unknown`.
  #[test]
  fn hasselblad_rebadge_x0100_routes_to_unknown() {
    let blob = b"\x01\x00rest_of_data";
    let d = dispatch(blob, Some("HASSELBLAD"), Some("Stellar"), None);
    assert!(
      d.vendor().is_unknown(),
      "Hasselblad \\x01\\x00 is neither Sony5 nor SonySRF, got {:?}",
      d.vendor()
    );
  }

  /// A Hasselblad-rebadged-Sony body that is NOT `\x01\x00` matches Sony5
  /// (`MakerNotes.pm:1073-1074`) → Sony.
  #[test]
  fn hasselblad_rebadge_non_x0100_dispatches_to_sony() {
    let blob = b"\x00\x05ifd_body";
    let d = dispatch(blob, Some("HASSELBLAD"), Some("Lunar"), None);
    assert!(d.vendor().is_sony());
  }

  // ----- Finding 1 (HIGH): hostile-input UTF-8 panic in the case-insensitive
  // Make prefix helpers. IFD0 Make/Model are `from_utf8_lossy`-decoded, so a
  // malformed EXIF can yield valid MULTI-BYTE UTF-8 (U+FFFD = 3 bytes each).
  // The old helpers sliced the `&str` at the byte index `prefix.len()`, which
  // could fall mid-codepoint → panic ("byte index N is not a char boundary").
  // The fix matches on `as_bytes()`. These tests must NOT panic.

  /// A Make of invalid bytes that `from_utf8_lossy`-decode to repeated U+FFFD
  /// (each 3 bytes) — the case-insensitive prefix helpers run during dispatch
  /// (e.g. `make_starts_with_ci(make, "CASIO"/"NIKON"/"SIGMA"/…)`). Byte index
  /// 5 (`"NIKON".len()`) lands MID-codepoint in such a string; the old `&str`
  /// slice panicked. Dispatch must instead return cleanly.
  #[test]
  fn ci_make_prefix_helpers_no_panic_on_non_ascii_make() {
    // 0xFF/0xFE/0xFD are invalid UTF-8 → each becomes U+FFFD (3 bytes).
    let lossy = String::from_utf8_lossy(&[0xff, 0xfe, 0xfd, 0xff, 0xfe]).into_owned();
    // Codepoint boundaries are at 0,3,6,9,12 — so byte index 5
    // ("NIKON".len()) and others are NOT char boundaries.
    let blob = b"\x00\x01\x02\x03some-makernote-body";
    let d = dispatch(blob, Some(lossy.as_str()), Some(lossy.as_str()), None);
    // No panic; an unrecognized vendor falls to the catch-all.
    assert!(d.vendor().is_unknown());
  }

  /// Same hostile non-ASCII Make/Model paired with a recognized SIGNATURE
  /// blob: the signature arms run first, but the later CI Make helpers
  /// (Minolta/Nikon3/Sigma/Casio) must still be reachable without panic for
  /// blobs that bypass the early signature arms. Drive a blob that reaches
  /// the make-keyed CI tail.
  #[test]
  fn ci_make_prefix_helpers_no_panic_mid_codepoint_index() {
    // A 1-byte-prefix mismatch is not enough; build a string whose every
    // codepoint boundary avoids the prefix lengths we test against
    // ("CASIO"=5, "NIKON"=5, "SIGMA"=5, "FOVEON"=6, "Minolta"=7, …).
    let lossy = String::from_utf8_lossy(&[0xc0, 0x80, 0xff, 0xfe, 0xfd, 0xfc]).into_owned();
    let blob = b"\xde\xad\xbe\xef-not-a-signature";
    // Must not panic regardless of which CI helper indexes the string.
    let d = dispatch(blob, Some(lossy.as_str()), None, None);
    assert!(d.vendor().is_unknown());
  }

  /// The CI prefix helper still matches correctly after the bytes-based
  /// rewrite (regression guard): a normal ASCII `Minolta` / `nikon` /
  /// `sigma` Make dispatches to the right vendor. These three arms ARE
  /// case-insensitive in bundled (`/^NIKON/i` `:550`, `/^(Konica
  /// Minolta|Minolta)/i` `:497`, `/^(SIGMA|FOVEON)/i` `:1019`).
  #[test]
  fn ci_make_prefix_still_matches_ascii() {
    // Lowercase `nikon` → Nikon3 (`/^NIKON/i`, `MakerNotes.pm:546-554`).
    let d = dispatch(b"\x00\x01ifd", Some("nikon corporation"), None, None);
    assert!(d.vendor().is_nikon());
    // Mixed-case `Konica Minolta` → Minolta (`/^(Konica Minolta|Minolta)/i`).
    let d2 = dispatch(b"\x00\x01ifd", Some("KONICA MINOLTA"), None, None);
    assert!(d2.vendor().is_minolta());
    // Lowercase `sigma` → Sigma (`/^(SIGMA|FOVEON)/i`, `MakerNotes.pm:1019`).
    let d3 = dispatch(b"\x00\x01ifd", Some("sigma corporation"), None, None);
    assert!(d3.vendor().is_sigma());
  }

  /// Casio's Make anchor is case-SENSITIVE in bundled (`/^CASIO/`, NO `/i`,
  /// `MakerNotes.pm:75`), unlike the `/i` arms above. A faithful port must
  /// match uppercase `CASIO…` but NOT a lowercase `casio…` Make — a CI gate
  /// would be BROADER than Perl. (Codex R4 class sweep: Make-anchor case
  /// fidelity.)
  #[test]
  fn casio_make_anchor_is_case_sensitive() {
    // Uppercase Make → Casio (`MakerNoteCasio`, the no-signature IFD arm).
    let d = dispatch(b"\x00\x01ifd", Some("CASIO COMPUTER CO.,LTD."), None, None);
    assert!(d.vendor().is_casio(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 0);
    // Lowercase Make → NOT Casio in Perl (`/^CASIO/` is case-sensitive). With
    // no other matching arm it falls through to the Unknown catch-all.
    let d2 = dispatch(b"\x00\x01ifd", Some("casio computer co.,ltd."), None, None);
    assert!(
      !d2.vendor().is_casio(),
      "lowercase `casio` must NOT match the case-sensitive /^CASIO/ anchor, got {:?}",
      d2.vendor()
    );
    assert!(d2.vendor().is_unknown(), "got {:?}", d2.vendor());
    // The Casio2 SIGNATURE arm (`QVC\0`/`DCI\0`) is independent of Make case
    // and still fires (it is a `$$valPt` test, `MakerNotes.pm:85`).
    let d3 = dispatch(
      b"QVC\x00\x00\x00rest",
      Some("casio computer co.,ltd."),
      None,
      None,
    );
    assert!(d3.vendor().is_casio(), "got {:?}", d3.vendor());
    assert_eq!(d3.body_offset(), 6);
  }

  // ----- Finding 3 (MEDIUM): Kodak PixPro MODEL-keyed dispatch. Kodak11/12
  // (`MakerNotes.pm:441-471`) key on `Model=~/(Kodak|PixPro)/i`, NOT Make,
  // because PixPro bodies report `Make => "JK Imaging, Ltd."`.

  /// A PixPro body (Make NOT containing "Kodak") with the Kodak11 LE
  /// padded-IFD signature `II\x2a\0\x08\0\0\0.\0\0\0` (`MakerNotes.pm:447`)
  /// dispatches to the Kodak arm: `body_offset=8`, `Base => '$start - 8'`,
  /// LittleEndian (`MakerNotes.pm:452-454`).
  #[test]
  fn kodak11_pixpro_model_le_dispatches() {
    // II \x2a \0 \x08 \0 \0 \0 <wild=0x09> \0 \0 \0  (12 bytes)
    let blob = b"II\x2a\x00\x08\x00\x00\x00\x09\x00\x00\x00rest";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("PIXPRO S-1"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
    assert!(!d.is_not_ifd());
  }

  /// A PixPro body with the Kodak12 BE padded-IFD signature
  /// `MM\0\x2a\0\0\0\x08\0\0\0.` (`MakerNotes.pm:463`) dispatches to Kodak:
  /// `body_offset=8`, `Base => '$start - 8'`, BigEndian
  /// (`MakerNotes.pm:468-470`).
  #[test]
  fn kodak12_pixpro_model_be_dispatches() {
    // MM \0 \x2a \0 \0 \0 \x08 \0 \0 \0 <wild=0x05>  (12 bytes)
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x00\x00\x05rest";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("PIXPRO AZ901"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
    assert!(!d.is_not_ifd());
  }

  /// Model contains "Kodak" (case-insensitive) — same MODEL-keyed reach
  /// (`MakerNotes.pm:446` `/(Kodak|PixPro)/i`).
  #[test]
  fn kodak11_model_kodak_token_dispatches() {
    let blob = b"II\x2a\x00\x08\x00\x00\x00\x01\x00\x00\x00rest";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("Kodak PIXPRO"), None);
    assert!(d.vendor().is_kodak());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// A PixPro body whose blob is NEITHER Kodak11/12 NOR `AOC\0` and whose
  /// Make is NOT "Kodak" must fall THROUGH to the generic catch-all
  /// (`KodakUnknown` is Make-keyed; Kodak11/12 need the II/MM signature).
  #[test]
  fn pixpro_model_without_signature_falls_through() {
    let blob = b"\x00\x01\x02\x03random-body-no-kodak-signature";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("PIXPRO FZ43"), None);
    // No Make-keyed KodakUnknown (Make is JK Imaging) → Unknown catch-all.
    assert!(d.vendor().is_unknown(), "got {:?}", d.vendor());
  }

  /// A PixPro body (Make NOT Kodak) with an `AOC\0` blob: fails Kodak11/12
  /// (their II/MM signatures) and `KodakUnknown` (Make-keyed), so it reaches
  /// the Pentax `AOC\0` arm (`MakerNotes.pm:762-779`) — faithful fall-through.
  #[test]
  fn pixpro_model_with_aoc_blob_falls_through_to_pentax() {
    let blob = b"AOC\x00\x00\x01MMrest";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("PIXPRO S-1"), None);
    assert!(d.vendor().is_pentax(), "got {:?}", d.vendor());
    assert!(d.fix_base());
  }

  /// A Make-keyed Kodak body with an `II\x2a` padded-IFD blob and a Model
  /// that ALSO matches (Kodak) still resolves to the Kodak11 directives
  /// (regression guard that the Make-keyed entry doesn't shadow Kodak11).
  #[test]
  fn make_kodak_with_kodak11_signature_dispatches() {
    let blob = b"II\x2a\x00\x08\x00\x00\x00\x02\x00\x00\x00rest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("Kodak PIXPRO AZ522"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  // ----- Codex R2 (MEDIUM): the signature-only Kodak arms (`Kodak2`,
  // `Kodak9`) must fire on the data SIGNATURE regardless of Make/Model.
  // Previously the whole Kodak block was gated on `Make=~/Kodak/i ||
  // Model=~/.../`, which hid these from HP/Pentax/Minolta bodies carrying a
  // Kodak2/Kodak9-shaped blob (`MakerNotes.pm:274` "used by various Kodak,
  // HP, Pentax and Minolta models").

  /// Kodak2 branch B (`MakerNotes.pm:278`) — the 9-byte
  /// `\x01\0[\0\x01]\0\0\0\x04\0` + 4-letter header — fires for a NON-Kodak
  /// Make (Hewlett-Packard) and carries the Kodak2 directives from
  /// `MakerNotes.pm:280-284`: NotIFD, BigEndian, no Start/Base.
  #[test]
  fn kodak2_signature_fires_for_non_kodak_make_hp() {
    // \x01 \0 \x01 \0 \0 \0 \x04 \0 then "ABCD" (4 letters) then padding.
    let blob = b"\x01\x00\x01\x00\x00\x00\x04\x00ABCDrest_of_blob";
    let d = dispatch(blob, Some("Hewlett-Packard"), Some("PhotoSmart R837"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_inherit());
  }

  /// Kodak2 branch A (`MakerNotes.pm:277`) — 8 arbitrary bytes then the
  /// literal "Eastman Kodak" at offset 8 — fires for a NON-Kodak Make
  /// (PENTAX). The 8-byte prefix here is NUL-filled (not `AOC\0`).
  #[test]
  fn kodak2_eastman_kodak_at_offset8_fires_for_pentax_make() {
    let blob = b"\x00\x00\x00\x00\x00\x00\x00\x00Eastman Kodak DC blob";
    let d = dispatch(blob, Some("PENTAX"), Some("Optio 50"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak9 (`MakerNotes.pm:418`) — the `IIII[\x02\x03]\0` + date header —
  /// fires for a NON-Kodak Make (Minolta). NotIFD, LittleEndian (`:419-422`).
  /// (`Make="Minolta"` would otherwise hit the Minolta block, which is LATER
  /// in `%Main`; the signature-only Kodak9 out-ranks it.)
  #[test]
  fn kodak9_signature_fires_for_non_kodak_make_minolta() {
    // IIII \x02 \0 <14 bytes> 2021/01/02<space>  (31 bytes, then padding)
    let blob = b"IIII\x02\x00xxxxxxxxxxxxxx2021/01/02 trailing";
    assert!(blob.len() >= 31);
    let d = dispatch(blob, Some("Minolta"), Some("DiMAGE X"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
    assert_eq!(d.body_offset(), 0);
  }

  /// Kodak9 with `\x03` model byte (the other accepted value) + no Make at
  /// all — still fires (purely signature-driven).
  #[test]
  fn kodak9_signature_fires_with_no_make() {
    let blob = b"IIII\x03\x00abcdefghijklmn1999/12/31 xyz";
    let d = dispatch(blob, None, None, None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
  }

  /// Kodak9 must NOT collide with HP4/HP6 (earlier `IIII…` arms): an
  /// `IIII\x06\0…` blob is HP6 (`MakerNotes.pm:217`), NOT Kodak9 (Kodak9's
  /// model byte is `\x02`/`\x03`, not `\x06`).
  #[test]
  fn kodak9_does_not_steal_hp6_iiii_blob() {
    let blob = b"IIII\x06\x00rest_of_the_data";
    let d = dispatch(blob, Some("Hewlett-Packard"), Some("PhotoSmart M425"), None);
    assert_eq!(d.vendor(), Vendor::Hp);
    assert!(d.is_not_ifd());
  }

  /// A bare `\x01\xf1`-style or short non-Kodak blob with a non-Kodak Make
  /// must NOT be mis-dispatched to Kodak just because the block is now
  /// ungated: a random non-signature blob + non-Kodak Make → Unknown.
  #[test]
  fn non_kodak_make_random_blob_not_misdispatched_to_kodak() {
    let blob = b"\xaa\xbb\xcc\xdd-no-kodak-signature-here";
    let d = dispatch(blob, Some("Hewlett-Packard"), Some("PhotoSmart R837"), None);
    assert!(!d.vendor().is_kodak(), "got {:?}", d.vendor());
  }

  // ----- Codex R2: the make-keyed Kodak sub-tree (`Kodak1a`..`Kodak10`,
  // `KodakUnknown`) ported faithfully, each with its own directives.

  /// Kodak1a — `Make=~/^EASTMAN KODAK/ and valPt=~/^KDK INFO/`
  /// (`MakerNotes.pm:254-262`): NotIFD, BigEndian, Start+8.
  #[test]
  fn kodak1a_kdk_info_dispatches() {
    let blob = b"KDK INFO\x00\x01\x02the_kodak_blob";
    let d = dispatch(blob, Some("EASTMAN KODAK COMPANY"), Some("DC4800"), None);
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak1b — `Make=~/^EASTMAN KODAK/ and valPt=~/^KDK/` (NOT `KDK INFO`)
  /// (`MakerNotes.pm:263-271`): NotIFD, LittleEndian, Start+8.
  #[test]
  fn kodak1b_kdk_dispatches_little_endian() {
    let blob = b"KDK\x00\x01\x02\x03\x04\x05the_blob";
    let d = dispatch(blob, Some("EASTMAN KODAK COMPANY"), Some("DC280"), None);
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// The `^EASTMAN KODAK` arms are case-SENSITIVE + anchored: a `KDK INFO`
  /// blob with Make = "Kodak" (matches `/Kodak/i` but NOT `/^EASTMAN KODAK/`)
  /// skips Kodak1a/1b and falls to the make-keyed `KodakUnknown`
  /// (`MakerNotes.pm:475`): NotIFD, BigEndian, body_offset 0 (NO Start+8).
  #[test]
  fn kdk_blob_with_plain_kodak_make_is_kodak_unknown_not_kodak1() {
    let blob = b"KDK INFO\x00\x01\x02the_blob";
    let d = dispatch(blob, Some("Kodak"), Some("Z990"), None);
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    // KodakUnknown has no Start directive → body_offset 0 (Kodak1a is +8).
    assert_eq!(d.body_offset(), 0);
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak6a — `Make=~/^EASTMAN KODAK/ and Model=~/DX3215/`
  /// (`MakerNotes.pm:328-339`): NotIFD, BigEndian.
  #[test]
  fn kodak6a_dx3215_model_dispatches_big_endian() {
    let blob = b"\x10\x20\x30\x40-some-binary-kodak-body";
    let d = dispatch(
      blob,
      Some("EASTMAN KODAK COMPANY"),
      Some("KODAK DX3215 DIGITAL CAMERA"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak6b — `Make=~/^EASTMAN KODAK/ and Model=~/DX3700/`
  /// (`MakerNotes.pm:340-351`): NotIFD, LittleEndian.
  #[test]
  fn kodak6b_dx3700_model_dispatches_little_endian() {
    let blob = b"\x10\x20\x30\x40-some-binary-kodak-body";
    let d = dispatch(
      blob,
      Some("EASTMAN KODAK COMPANY"),
      Some("KODAK DX3700 DIGITAL CAMERA"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// Kodak5 — `Make=~/^EASTMAN KODAK/` + Model `CX4200` (the MODEL branch,
  /// `MakerNotes.pm:318`): NotIFD, BigEndian.
  #[test]
  fn kodak5_cx_model_dispatches() {
    let blob = b"\x00\x10\x20\x30-binary-body";
    let d = dispatch(
      blob,
      Some("EASTMAN KODAK COMPANY"),
      Some("KODAK CX4200 DIGITAL CAMERA"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak5 — the SIGNATURE branch `^\0(\x1a\x18|…)\0` (`MakerNotes.pm:320`)
  /// still needs `Make=~/^EASTMAN KODAK/` (Kodak5 is MAKE+sig, not sig-only).
  #[test]
  fn kodak5_signature_branch_requires_eastman_kodak_make() {
    let blob = b"\x00\x1a\x18\x00rest_of_body";
    // With EASTMAN KODAK make → Kodak5.
    let d = dispatch(
      blob,
      Some("EASTMAN KODAK COMPANY"),
      Some("Unknown Model"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
    // Without EASTMAN KODAK make (and no other Kodak signature) → NOT Kodak.
    let d2 = dispatch(blob, Some("Canon"), Some("Unknown Model"), None);
    assert!(!d2.vendor().is_kodak(), "got {:?}", d2.vendor());
  }

  /// Kodak7 — `Make=~/Kodak/i and valPt=~serial-number` (`MakerNotes.pm:359`):
  /// NotIFD, LittleEndian. Serial like "K1234 AB12C3456 " (then a space).
  #[test]
  fn kodak7_serial_number_signature_dispatches() {
    // [CK]=K, [A-Z\d]{3}=123, space, [A-Z\d]{1,2}=AB, \d{2}=12, [A-Z\d]=C,
    // \d{4}=3456, [ \0]=space.
    let blob = b"K123 AB12C3456 rest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("DX7590 ZOOM"),
      None,
    );
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Little));
  }

  /// Kodak8a — `Make=~/Kodak/i` + IFD-shaped header (`MakerNotes.pm:373`
  /// branch 1): IFD (NOT NotIFD), Unknown byte order, body_offset 0.
  #[test]
  fn kodak8a_ifd_shaped_dispatches_as_ifd() {
    // Branch 1: \0 [\x02-\x7f] . . \0 [\x01-\x0c] \0 \0
    let blob = b"\x00\x05\xaa\xbb\x00\x03\x00\x00rest";
    let d = dispatch(blob, Some("Eastman Kodak Company"), Some("Z1015 IS"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(!d.is_not_ifd(), "Kodak8a is an IFD (no NotIFD)");
    assert!(d.byte_order().is_unknown());
    assert_eq!(d.body_offset(), 0);
  }

  /// Kodak8b — `Make=~/Kodak/i` + `MM\0\x2a\0\0\0\x08\0.\0\0`
  /// (`MakerNotes.pm:390`): IFD, BigEndian, Start+8, Base $start-8.
  #[test]
  fn kodak8b_be_padded_ifd_dispatches() {
    // MM \0 \x2a \0 \0 \0 \x08 \0 <wild=0x09> \0 \0  (12 bytes)
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x09\x00\x00rest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("PIXPRO AZ251"),
      None,
    );
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(!d.is_not_ifd());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
  }

  /// Kodak8c — `Make=~/Kodak/i` + `II\x2a\0\x08\0\0\0` (the LE TIFF magic
  /// branch, `MakerNotes.pm:405`): IFD, Unknown byte order, Start+8,
  /// Base $start-8. (A Make-keyed Kodak body — NOT a PixPro Model — so this
  /// out-ranks Kodak11/12, which are Model-keyed.)
  #[test]
  fn kodak8c_le_tiff_magic_dispatches_unknown_order() {
    // II \x2a \0 \x08 \0 \0 \0 then NON-Kodak11 continuation (byte8 != all-0).
    let blob = b"II\x2a\x00\x08\x00\x00\x00\x05\x06\x07\x08rest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("EasyShare Z981"),
      None,
    );
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(!d.is_not_ifd());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    assert!(d.byte_order().is_unknown(), "Kodak8c is Unknown order");
  }

  /// Kodak10 — `Make=~/Kodak/i` + `II[\x02-\x7f]\0` (`MakerNotes.pm:432`):
  /// IFD, Unknown order, Start+2, no Base.
  #[test]
  fn kodak10_byte_order_indicator_dispatches_start2() {
    // II <count=0x05> \0  (byte-order indicator then IFD count)
    let blob = b"II\x05\x00rest_of_the_ifd_body";
    let d = dispatch(blob, Some("Eastman Kodak Company"), Some("DC4800"), None);
    assert!(d.vendor().is_kodak(), "got {:?}", d.vendor());
    assert!(!d.is_not_ifd());
    assert_eq!(d.body_offset(), 2);
    assert!(d.base_rule().is_inherit());
    assert!(d.byte_order().is_unknown());
  }

  /// Ordering: Kodak8b (BE explicit, Start+8) out-ranks Kodak8c (Unknown
  /// order) for a blob that matches BOTH (`MM\0\x2a\0\0\0\x08\0.\0\0` is a
  /// subset of `MM\0\x2a\0\0\0\x08`). Kodak8b is listed first in `%Main`.
  #[test]
  fn kodak8b_outranks_kodak8c_for_overlapping_blob() {
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x09\x00\x00rest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("PIXPRO AZ361"),
      None,
    );
    // Kodak8b → BigEndian explicit (not Kodak8c's Unknown).
    assert_eq!(d.byte_order().explicit(), Some(ByteOrder::Big));
    assert_eq!(d.body_offset(), 8);
  }

  /// Ordering: for an EASTMAN KODAK body whose Model ALSO contains "Kodak",
  /// an `MM\0\x2a\0\0\0\x08\0\0\0.` blob hits Kodak8c (Make-keyed, listed
  /// BEFORE Kodak12) → Unknown order, NOT Kodak12's BigEndian. Faithful to
  /// `%Main` (Kodak8c `:400` precedes Kodak12 `:457`).
  #[test]
  fn kodak8c_outranks_kodak12_for_eastman_kodak_body() {
    // MM \0 \x2a \0 \0 \0 \x08 \0 \0 \0 <wild=0x05>  (Kodak12-shaped, but also
    // matches Kodak8c's 8-byte prefix).
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x00\x00\x05rest";
    let d = dispatch(
      blob,
      Some("EASTMAN KODAK COMPANY"),
      Some("KODAK PIXPRO clone"),
      None,
    );
    assert!(d.vendor().is_kodak());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    // Kodak8c is Unknown order; Kodak12 would be BigEndian — 8c wins.
    assert!(
      d.byte_order().is_unknown(),
      "Kodak8c (Make-keyed, earlier) must out-rank Kodak12, got {:?}",
      d.byte_order()
    );
  }

  /// A PixPro body (Make = "JK Imaging, Ltd.", NOT `/Kodak/i`) with the same
  /// `MM\0\x2a\0\0\0\x08\0\0\0.` blob skips Kodak8a/8b/8c (all Make-keyed on
  /// `/Kodak/i`) and reaches Kodak12 (Model-keyed) → BigEndian explicit.
  #[test]
  fn pixpro_mm_blob_reaches_kodak12_not_kodak8c() {
    let blob = b"MM\x00\x2a\x00\x00\x00\x08\x00\x00\x00\x05rest";
    let d = dispatch(blob, Some("JK Imaging, Ltd."), Some("PIXPRO AZ901"), None);
    assert!(d.vendor().is_kodak());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
    assert_eq!(
      d.byte_order().explicit(),
      Some(ByteOrder::Big),
      "PixPro Make is not /Kodak/i, so Kodak8c is skipped → Kodak12 (BE)"
    );
  }

  /// Regression: the existing `AOC\0` → Pentax fall-through still holds for a
  /// Kodak-made body (`KodakUnknown` excludes `^AOC\0`, `MakerNotes.pm:475`).
  #[test]
  fn r2_kodak_make_with_aoc_still_falls_through_to_pentax() {
    let blob = b"AOC\x00\x00\x01MMrest";
    let d = dispatch(
      blob,
      Some("Eastman Kodak Company"),
      Some("DX7590 ZOOM"),
      None,
    );
    assert!(d.vendor().is_pentax(), "got {:?}", d.vendor());
    assert!(d.fix_base());
  }

  // ----- Codex R3 (MEDIUM): Samsung2 must NOT be a bare Make test.
  // `MakerNoteSamsung2` (`MakerNotes.pm:965-979`) requires
  // `uc Make eq 'SAMSUNG' and (TIFF_TYPE eq 'SRW' or <EXIF-format magic>)`.

  /// A SAMSUNG body whose blob is NEITHER an SRW raw NOR the EXIF-format
  /// magic must FALL THROUGH past Samsung2 (R3). With no later SAMSUNG arm
  /// and a non-signature blob it lands on the Unknown catch-all.
  #[test]
  fn samsung2_non_matching_blob_falls_through() {
    let blob = b"\x00\x01\x02\x03not-an-srw-and-no-samsung2-magic";
    let d = dispatch(blob, Some("SAMSUNG"), Some("NX500"), None);
    assert!(
      d.vendor().is_unknown(),
      "SAMSUNG + non-magic + no SRW must not be captured as Samsung, got {:?}",
      d.vendor()
    );
    // (It lands on `MakerNoteUnknown`, whose own `FixBase => 2`
    // (`MakerNotes.pm:1124`) sets the flag — that is the catch-all's
    // directive, not Samsung2's. The load-bearing assertion is the vendor.)
  }

  /// Samsung2 EXIF-format magic — BRANCH A (big-endian one-entry IFD,
  /// `MakerNotes.pm:970` `\0.\0\x01\0\x07\0{3}\x04` + `"0100"`). Matches for
  /// a SAMSUNG body even with `tiff_type = None`. Directives: no Start/Base,
  /// Unknown order, `FixBase => 1` (`:977`).
  #[test]
  fn samsung2_magic_branch_a_dispatches() {
    // \0 <tag=0x12> \0 \x01 \0 \x07 \0 \0 \0 \x04 '0' '1' '0' '0'
    let blob = b"\x00\x12\x00\x01\x00\x07\x00\x00\x00\x040100rest";
    let d = dispatch(blob, Some("SAMSUNG"), Some("EX2F"), None);
    assert!(d.vendor().is_samsung(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_inherit());
    assert!(d.byte_order().is_unknown());
    assert!(d.fix_base());
  }

  /// Samsung2 EXIF-format magic — BRANCH B (little-endian one-entry IFD,
  /// `MakerNotes.pm:970` `.\0\x01\0\x07\0\x04\0{3}` + `"0100"`).
  #[test]
  fn samsung2_magic_branch_b_dispatches() {
    // <tag=0x01> \0 \x01 \0 \x07 \0 \x04 \0 \0 \0 '0' '1' '0' '0'
    let blob = b"\x01\x00\x01\x00\x07\x00\x04\x00\x00\x000100rest";
    let d = dispatch(blob, Some("samsung"), None, None);
    assert!(d.vendor().is_samsung(), "got {:?}", d.vendor());
    assert!(d.fix_base());
  }

  /// Samsung2 SRW clause — a SAMSUNG body with `tiff_type = Some("SRW")`
  /// matches even when the blob has NO magic (`MakerNotes.pm:969`). This is
  /// the clause the integration hook will satisfy once it threads the
  /// container's `TIFF_TYPE`.
  #[test]
  fn samsung2_srw_tiff_type_dispatches_without_magic() {
    let blob = b"\x00\x01\x02\x03no-magic-but-this-is-an-srw-raw";
    let d = dispatch(blob, Some("SAMSUNG"), Some("NX1"), Some("SRW"));
    assert!(d.vendor().is_samsung(), "got {:?}", d.vendor());
    assert!(d.fix_base());
  }

  /// Samsung2 is gated on Make: a `tiff_type = Some("SRW")` with a NON-Samsung
  /// Make must NOT hit Samsung2 (the `uc Make eq 'SAMSUNG'` clause).
  #[test]
  fn samsung2_srw_with_non_samsung_make_does_not_match() {
    let blob = b"\x00\x01\x02\x03random";
    let d = dispatch(blob, Some("Canon"), Some("EOS R5"), Some("SRW"));
    assert!(!d.vendor().is_samsung(), "got {:?}", d.vendor());
  }

  /// A SAMSUNG body carrying the `STMN` Samsung1 signature still hits the
  /// EARLIER Samsung1a/1b arm (regression: Samsung2's tightening must not
  /// disturb Samsung1 ordering, `MakerNotes.pm:950` precedes `:965`).
  #[test]
  fn samsung_stmn_still_precedes_samsung2() {
    let blob = b"STMN1234\x00\x00\x00\x00rest";
    let d = dispatch(blob, Some("SAMSUNG"), Some("Digimax"), None);
    assert!(d.vendor().is_samsung());
  }

  // ----- CLASS SWEEP — Minolta2 is SIGNATURE-ONLY (`MakerNotes.pm:505-516`):
  // `valPt=~/^(MINOL|CAMER)\0/` with `OlympusCAMER = 1` (an assignment), NO
  // Make gate. The previous port nested it under the Minolta Make check, so
  // a non-Minolta body with these prefixes was wrongly missed (narrower than
  // Perl, the R1-Sony class).

  /// `MINOL\0` with a NON-Minolta Make (e.g. a Mustek/Pentax/Ricoh/Vivitar
  /// rebadge) must still hit Minolta2 → `Vendor::Minolta`, Start+8.
  #[test]
  fn minolta2_minol_signature_fires_for_non_minolta_make() {
    let blob = b"MINOL\x00\x00\x00ifd_body_here";
    let d = dispatch(blob, Some("Mustek"), Some("Some DiMAGE clone"), None);
    assert!(d.vendor().is_minolta(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(d.base_rule().is_inherit());
    assert!(!d.is_not_ifd());
  }

  /// `CAMER\0` with NO Make at all also hits Minolta2 (purely signature).
  #[test]
  fn minolta2_camer_signature_fires_with_no_make() {
    let blob = b"CAMER\x00\x01\x02ifd_body";
    let d = dispatch(blob, None, None, None);
    assert!(d.vendor().is_minolta(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
  }

  /// A Konica-Minolta body whose blob is `MINOL\0` still hits Minolta2
  /// (`MakerNoteMinolta` excludes the prefix via its lookahead) — same as
  /// before, regression guard.
  #[test]
  fn minolta2_minol_still_fires_for_minolta_make() {
    let blob = b"MINOL\x00\x00\x00ifd";
    let d = dispatch(blob, Some("Konica Minolta"), Some("DiMAGE E323"), None);
    assert!(d.vendor().is_minolta());
    assert_eq!(d.body_offset(), 8);
  }

  /// Minolta3 binary prefixes (`MLY0`/`KC`/`+M+M`/`\xd7`) still require the
  /// Minolta Make (`MakerNotes.pm:523`) and set `NotIFD` — unchanged.
  #[test]
  fn minolta3_binary_prefixes_require_minolta_make() {
    let d = dispatch(b"MLY0rest", Some("Minolta"), Some("DiMAGE G400"), None);
    assert!(d.vendor().is_minolta());
    assert!(d.is_not_ifd());
    // A non-Minolta Make with the same prefix is NOT Minolta3 (it has no
    // signature-only arm) → falls through.
    let d2 = dispatch(b"MLY0rest", Some("Canon"), None, None);
    assert!(!d2.vendor().is_minolta(), "got {:?}", d2.vendor());
  }

  /// Generic Minolta (Make-gated, non-prefixed blob) is unchanged: Start 0,
  /// Unknown order, not NotIFD (`MakerNotes.pm:494-503`).
  #[test]
  fn minolta_generic_make_dispatch_unchanged() {
    let d = dispatch(b"\x00\x01ifd", Some("KONICA MINOLTA"), Some("A2"), None);
    assert!(d.vendor().is_minolta());
    assert_eq!(d.body_offset(), 0);
    assert!(!d.is_not_ifd());
  }

  /// Codex R7 class sweep (Minolta3 is MAKE-ONLY): `MakerNoteMinolta`
  /// (`MakerNotes.pm:494-503`) carries `$$valPt !~ /^(MINOL|CAMER|MLY0|KC|
  /// \+M\+M|\xd7)/` (`:498`), and `MakerNoteMinolta3` (`:517-526`) is gated
  /// ONLY on `$$self{Make} =~ /^(Konica Minolta|Minolta)/i` (`:523`, `Binary
  /// => 1`). A `Konica Minolta`/`Minolta` body whose blob starts `MINOL` or
  /// `CAMER` but WITHOUT the trailing NUL matches NEITHER generic Minolta
  /// (excluded by the lookahead) NOR Minolta2 (needs `\0`) — but it DOES match
  /// the make-only Minolta3, so it must dispatch as `Vendor::Minolta` with
  /// `not_ifd=true` (binary). (R4 wrongly read Minolta3's example-prefix NOTES
  /// as its condition and dropped these blobs to Unknown.)
  #[test]
  fn minolta_bare_minol_prefix_without_nul_hits_minolta3_binary() {
    // `MINOL` then a NON-NUL byte (0x41 = 'A'): not `MINOL\0` (Minolta2), not a
    // documented Minolta3 prefix, excluded from generic Minolta by `:498` — but
    // make-only Minolta3 catches it as binary/NotIFD.
    let blob = b"MINOLArest_not_a_minolta2_or_minolta3_blob";
    let d = dispatch(blob, Some("Konica Minolta"), Some("DiMAGE oddball"), None);
    assert!(
      d.vendor().is_minolta(),
      "MINOL-without-NUL hits make-only Minolta3 (`:523`), got {:?}",
      d.vendor()
    );
    assert!(d.is_not_ifd(), "Minolta3 is `Binary => 1` (`:524`)");
    // Same for a bare `CAMER` (non-NUL) prefix.
    let blob2 = b"CAMERXrest_no_trailing_nul";
    let d2 = dispatch(blob2, Some("Minolta"), None, None);
    assert!(
      d2.vendor().is_minolta(),
      "CAMER-without-NUL hits make-only Minolta3, got {:?}",
      d2.vendor()
    );
    assert!(d2.is_not_ifd(), "Minolta3 is `Binary => 1` (`:524`)");
  }

  /// Regression: the proper `MINOL\0`/`CAMER\0` blobs STILL hit Minolta2
  /// (`MakerNotes.pm:508-516`, Start+8) even for a Minolta make — the new
  /// guard only affects the generic arm, and Minolta2 is tested earlier.
  #[test]
  fn minolta2_proper_minol_nul_still_dispatches_for_minolta_make() {
    let d = dispatch(b"MINOL\x00\x00\x00ifd", Some("Konica Minolta"), None, None);
    assert!(d.vendor().is_minolta());
    assert_eq!(d.body_offset(), 8);
    assert!(!d.is_not_ifd());
  }

  // ----- CLASS SWEEP — Leica per-variant `Base` directives. The collapsed
  // LEICA-prefix arm previously gave `$start - 8` to every LEICA blob; the
  // faithful directives differ (`MakerNotes.pm:611-721`).

  /// Leica2 (M8, `MakerNotes.pm:611-623`): `Make=~/^Leica Camera AG/ and
  /// LEICA\0\0\0` → `Base => '$start'` (StartItself), NOT `$start - 8`.
  #[test]
  fn leica2_m8_base_is_start_itself() {
    let blob = b"LEICA\x00\x00\x00ifd_body_of_the_m8";
    let d = dispatch(
      blob,
      Some("Leica Camera AG"),
      Some("M8 Digital Camera"),
      None,
    );
    assert!(d.vendor().is_leica(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(
      d.base_rule().is_start_itself(),
      "Leica2 Base is $start, got {:?}",
      d.base_rule()
    );
  }

  /// Leica4 (M9, `MakerNotes.pm:639-647`): `Make=~/^Leica Camera AG/ and
  /// LEICA0` (byte 5 = '0') → `Base => '$start - 8'`, Start+8.
  #[test]
  fn leica4_m9_base_is_relative_minus8() {
    // "LEICA0\x03\0" per the bundled comment.
    let blob = b"LEICA0\x03\x00ifd_of_the_m9";
    let d = dispatch(blob, Some("Leica Camera AG"), Some("M9"), None);
    assert!(d.vendor().is_leica());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Leica5 (X1, `MakerNotes.pm:650-663`): SIG-ONLY
  /// `LEICA\0[\x01\x04\x05\x06\x07\x10\x1a]\0` → `Base => '$start - 8'`.
  /// Fires regardless of Make.
  #[test]
  fn leica5_x_series_sig_only_base_minus8() {
    let blob = b"LEICA\x00\x01\x00ifd_of_the_x1";
    let d = dispatch(blob, Some("LEICA CAMERA AG"), Some("X1"), None);
    assert!(d.vendor().is_leica());
    assert_eq!(d.body_offset(), 8);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Leica7 (M Monochrom Typ 246, `MakerNotes.pm:690-701`): SIG-ONLY
  /// `LEICA\0\x02\xff` → `Base => '-$base'` (NegativeOfBase). Unchanged but
  /// re-checked after the discrimination rewrite.
  #[test]
  fn leica7_negative_of_base_still_holds() {
    let blob = b"LEICA\x00\x02\xffrest_of_the_data";
    let d = dispatch(
      blob,
      Some("Leica Camera AG"),
      Some("M Monochrom Typ 246"),
      None,
    );
    assert!(d.vendor().is_leica());
    assert!(d.base_rule().is_negative_of_base());
  }

  /// Codex R8 (real-input): `MakerNoteLeica6` (`MakerNotes.pm:666-688`) is
  /// Make+Model gated and PRECEDES Leica7 (`:690`) in `%Main`. The S2,
  /// `LEICA M (Typ 240)` and `LEICA S (Typ 006)` bodies share Leica7's
  /// `LEICA\0\x02\xff` header but must take Leica6's NO-`Base` directive
  /// (`LeicaTrailer` fixups, `:675-687`), NOT Leica7's `Base => '-$base'`.
  /// Before the fix they fell through to Leica7 and got the wrong base.
  #[test]
  fn leica6_typ_models_take_no_base_not_leica7() {
    for model in ["S2", "LEICA M (Typ 240)", "LEICA S (Typ 006)"] {
      let blob = b"LEICA\x00\x02\xffrest_of_the_trailer_body";
      let d = dispatch(blob, Some("Leica Camera AG"), Some(model), None);
      assert!(d.vendor().is_leica(), "{}: got {:?}", model, d.vendor());
      assert_eq!(d.body_offset(), 8, "{}: Leica6 Start+8", model);
      assert!(
        d.base_rule().is_inherit(),
        "{}: Leica6 has NO Base (LeicaTrailer), got {:?}",
        model,
        d.base_rule()
      );
      assert!(
        !d.base_rule().is_negative_of_base(),
        "{}: must NOT take Leica7's -$base",
        model
      );
    }
  }

  /// Leica6 (`:666-688`) carries NO valPt term, so an S2 / `LEICA M (Typ 240)`
  /// body whose maker-note blob does NOT start `LEICA` (e.g. not yet loaded) is
  /// excluded from Leica3 (`:630`) and claimed by the make-only Leica6 fallback
  /// — faithful to `%Main` order (Leica3 `:626` < Leica6 `:666`).
  #[test]
  fn leica6_non_leica_blob_s2_m240_fallback() {
    for model in ["S2", "LEICA M (Typ 240)"] {
      let blob = b"\x00\x08ifd_body_no_leica_prefix";
      let d = dispatch(blob, Some("Leica Camera AG"), Some(model), None);
      assert!(d.vendor().is_leica(), "{}: got {:?}", model, d.vendor());
      assert_eq!(d.body_offset(), 8, "{}: Leica6 Start+8", model);
      assert!(d.base_rule().is_inherit(), "{}: Leica6 no Base", model);
    }
  }

  /// Faithful `%Main` ordering subtlety: Leica3 (`:626`) does NOT exclude
  /// `LEICA S (Typ 006)` (only S2 / M-Typ240 at `:630`), and precedes Leica6
  /// (`:666`). So an S-Typ006 body with a NON-`LEICA` blob lands on Leica3
  /// (`Start => '$valuePtr'`, offset 0), NOT the Leica6 fallback — unlike S2 /
  /// M-Typ240 above.
  #[test]
  fn leica3_claims_non_leica_s006_before_leica6() {
    let blob = b"\x00\x08ifd_body_no_leica_prefix";
    let d = dispatch(
      blob,
      Some("Leica Camera AG"),
      Some("LEICA S (Typ 006)"),
      None,
    );
    assert!(d.vendor().is_leica(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 0, "Leica3 Start => $valuePtr (offset 0)");
    assert!(d.base_rule().is_inherit());
  }

  /// Leica8 (Q Typ 116 / SL / CL, `MakerNotes.pm:703-712`): SIG-ONLY
  /// `LEICA\0[\x08\x09\x0a]\0` → NO `Base` directive → `Inherit`, NOT
  /// `$start - 8`.
  #[test]
  fn leica8_q_series_base_is_inherit() {
    let blob = b"LEICA\x00\x08\x00ifd_of_the_q";
    let d = dispatch(
      blob,
      Some("LEICA CAMERA AG"),
      Some("LEICA Q (Typ 116)"),
      None,
    );
    assert!(d.vendor().is_leica(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(
      d.base_rule().is_inherit(),
      "Leica8 has no Base directive → inherit, got {:?}",
      d.base_rule()
    );
  }

  /// Leica9 (M10/S, `MakerNotes.pm:714-721`): `Make=~/^Leica Camera AG/ and
  /// LEICA\0\x02\0` → NO `Base` directive → `Inherit`. Note the byte-7 value
  /// `\0` distinguishes it from Leica7's `\xff`.
  #[test]
  fn leica9_m10_base_is_inherit() {
    let blob = b"LEICA\x00\x02\x00ifd_of_the_m10";
    let d = dispatch(blob, Some("Leica Camera AG"), Some("LEICA M10"), None);
    assert!(d.vendor().is_leica(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(d.base_rule().is_inherit(), "got {:?}", d.base_rule());
  }

  /// A `LEICA…` blob matching NONE of the discriminated sub-headers (and not
  /// the `Make eq "LEICA"` / `LEICA CAMERA AG\0` arms) falls THROUGH —
  /// bundled has no generic LEICA fallback. E.g. `LEICA\0\x0b\0` with a
  /// non-`Leica Camera AG` Make → Unknown.
  #[test]
  fn leica_unmatched_prefix_falls_through() {
    let blob = b"LEICA\x00\x0b\x00not-a-known-leica-header";
    let d = dispatch(blob, Some("SomeRebadge"), None, None);
    assert!(
      d.vendor().is_unknown(),
      "unmatched LEICA prefix must fall through, got {:?}",
      d.vendor()
    );
  }

  /// Codex R4 (MEDIUM, real-input): the Leica3 `$$valPt !~ /^LEICA/` negative
  /// blob guard (`MakerNotes.pm:629`). A `Make = "Leica Camera AG"` body whose
  /// blob starts `LEICA…` but matches NONE of the Leica2/4/5/7/8/9 sub-headers
  /// must NOT be captured as Leica3 — it falls THROUGH to the Unknown
  /// catch-all (bundled has no generic `LEICA`-prefix arm). Before the fix the
  /// Rust Leica3 arm gated on Make ONLY and wrongly claimed it.
  #[test]
  fn leica3_make_with_unmatched_leica_blob_falls_through() {
    // `LEICA\0\x0b\0…` — byte 6 = 0x0b is not a Leica2/4/5/7/8/9 discriminator
    // (Leica5 set is {01,04,05,06,07,10,1a}; Leica7/9 need 02; Leica4 needs
    // '0'; Leica2 needs \0\0\0). So no sub-header matches.
    let blob = b"LEICA\x00\x0b\x00rest_of_an_unknown_leica_blob";
    let d = dispatch(
      blob,
      Some("Leica Camera AG"),
      Some("Some R-series body"),
      None,
    );
    assert!(
      d.vendor().is_unknown(),
      "Leica Camera AG + unmatched LEICA blob must fall through (valPt !~ /^LEICA/), got {:?}",
      d.vendor()
    );
  }

  /// The Leica3 arm STILL fires for a `Make = "Leica Camera AG"` body whose
  /// blob does NOT start with `LEICA` (the R8/R9 IFD case, `MakerNotes.pm:
  /// 626-636`): `Start => '$valuePtr'` (offset 0), Unknown order, inherit base.
  /// Regression guard that the new negative guard didn't over-narrow.
  #[test]
  fn leica3_non_leica_blob_still_dispatches() {
    let blob = b"\x00\x05ifd_body_of_an_r9_no_leica_prefix";
    let d = dispatch(blob, Some("Leica Camera AG"), Some("R9 Digital"), None);
    assert!(d.vendor().is_leica(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 0);
    assert!(d.base_rule().is_inherit());
    assert!(d.byte_order().is_unknown());
  }

  /// Leica1 (`Make eq "LEICA"`, `MakerNotes.pm:600-608`) and Leica10
  /// (`LEICA CAMERA AG\0`, `:723-730`) are unchanged by the rewrite.
  #[test]
  fn leica1_and_leica10_unchanged() {
    let d1 = dispatch(b"\x01\x00ifd", Some("LEICA"), Some("R8"), None);
    assert!(d1.vendor().is_leica());
    assert_eq!(d1.body_offset(), 8);
    assert!(d1.base_rule().is_inherit());

    let d10 = dispatch(
      b"LEICA CAMERA AG\x00rest",
      Some("LEICA CAMERA AG"),
      Some("D-Lux 7"),
      None,
    );
    assert!(d10.vendor().is_leica());
    assert_eq!(d10.body_offset(), 18);
    assert!(d10.base_rule().is_inherit());
  }

  // ----- CLASS SWEEP — Samsung1a vs Samsung1b `not_ifd`. Samsung1a
  // (`STMN\d{3}.\0{4}`) is `Binary` → NotIFD; Samsung1b (`STMN\d{3}`) is a
  // `SubDirectory` → IFD (`MakerNotes.pm:950-963`).

  /// Samsung1a — `STMN` + 3 digits + 1 byte + 4 NULs → NotIFD.
  #[test]
  fn samsung1a_is_not_ifd() {
    // STMN 123 <byte=0x09> \0\0\0\0
    let blob = b"STMN123\x09\x00\x00\x00\x00trailing";
    let d = dispatch(blob, Some("Samsung Techwin"), Some("Digimax"), None);
    assert!(d.vendor().is_samsung());
    assert!(d.is_not_ifd(), "Samsung1a (Binary) is NotIFD");
  }

  /// Samsung1b — `STMN` + 3 digits but WITHOUT the `.\0{4}` tail → a
  /// SubDirectory, so NOT NotIFD (the previous port marked all STMN blobs
  /// NotIFD).
  #[test]
  fn samsung1b_is_ifd_not_notifd() {
    // STMN 123 then a NON-(byte+4NUL) continuation (no 4 NULs at 8..12).
    let blob = b"STMN123\x01\x02\x03\x04\x05ifd_body";
    let d = dispatch(blob, Some("Samsung Techwin"), Some("Digimax"), None);
    assert!(d.vendor().is_samsung());
    assert!(
      !d.is_not_ifd(),
      "Samsung1b is a SubDirectory (IFD), not NotIFD"
    );
  }

  /// A bare `STMN` with NO three digits matches NEITHER Samsung1a nor 1b and
  /// must fall through (the regex requires `\d{3}`).
  #[test]
  fn stmn_without_digits_falls_through() {
    let blob = b"STMNxyz-not-digits";
    let d = dispatch(blob, Some("NoSuchVendor"), None, None);
    assert!(!d.vendor().is_samsung(), "got {:?}", d.vendor());
  }

  // ----- CLASS SWEEP — RicohText is NARROWER than Ricoh/Ricoh2 on Make:
  // `MakerNoteRicohText` is `^RICOH` (NOT `^(PENTAX )?RICOH`,
  // `MakerNotes.pm:943`).

  /// A `PENTAX RICOH` body whose blob fails the structural Ricoh/Ricoh2
  /// arms must NOT be captured by the text fallback (which is `^RICOH`
  /// only) — it falls through to Unknown.
  #[test]
  fn pentax_ricoh_text_fallback_does_not_capture() {
    let blob = b"some-non-structural-ricoh-text-blob";
    let d = dispatch(
      blob,
      Some("PENTAX RICOH IMAGING COMPANY"),
      Some("WG-50"),
      None,
    );
    assert!(
      d.vendor().is_unknown(),
      "PENTAX RICOH text fallback is ^RICOH only, got {:?}",
      d.vendor()
    );
  }

  /// A bare `RICOH` body with a non-structural blob DOES hit RicohText
  /// (`^RICOH`) → `Vendor::Ricoh`, NotIFD (`MakerNotes.pm:942-948`).
  #[test]
  fn bare_ricoh_text_fallback_dispatches() {
    let blob = b"Rdc-text-style-ricoh-blob";
    let d = dispatch(blob, Some("RICOH"), Some("Caplio"), None);
    assert!(d.vendor().is_ricoh(), "got {:?}", d.vendor());
    assert!(d.is_not_ifd());
  }

  /// A `PENTAX RICOH` body with the structural `Ricoh` prefix still hits the
  /// Ricoh positive arm (regression — only the TEXT fallback is narrowed).
  #[test]
  fn pentax_ricoh_structural_prefix_still_dispatches() {
    let blob = b"Ricohifd_body_here";
    let d = dispatch(
      blob,
      Some("PENTAX RICOH IMAGING COMPANY"),
      Some("GR II"),
      None,
    );
    assert!(d.vendor().is_ricoh(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
  }

  // ----- CLASS SWEEP — Sony5 precedes SonyEricsson in `%Main` (`:1070` <
  // `:1083`). The port now tests Sony5 first.

  /// A `SEMC MS\0` blob with a real Sony Ericsson Make (`"Sony Ericsson"`,
  /// mixed case — NOT `/^SONY/`) reaches SonyEricsson in both Perl and the
  /// port: Start+20, `Base => '$start - 8'` (`MakerNotes.pm:1087-1088`).
  #[test]
  fn sony_ericsson_real_make_still_dispatches() {
    let blob = b"SEMC MS\x00rest_of_the_data";
    let d = dispatch(blob, Some("Sony Ericsson"), Some("K800i"), None);
    assert!(d.vendor().is_sony());
    assert_eq!(d.body_offset(), 20);
    assert_eq!(d.base_rule(), BaseRule::RelativeToStart(-8));
  }

  /// Ordering fidelity: a `SEMC MS\0` blob whose Make matches `/^SONY/`
  /// (uppercase) is claimed by Sony5 FIRST (`%Main` order), so it gets
  /// Sony5's `Start => '$valuePtr'` (offset 0), NOT SonyEricsson's offset 20.
  #[test]
  fn sony5_outranks_sony_ericsson_for_uppercase_sony_make() {
    let blob = b"SEMC MS\x00rest_of_the_data";
    let d = dispatch(blob, Some("SONY"), Some("DSLR-A700"), None);
    assert!(d.vendor().is_sony());
    assert_eq!(
      d.body_offset(),
      0,
      "Sony5 (%Main :1070) out-ranks SonyEricsson (:1083) for /^SONY/ Make"
    );
  }

  // ===========================================================================
  // CASE-SENSITIVITY CLASS SWEEP — the `/i` dimension across `%Main`.
  //
  // `%Main` carries exactly one `/i`-flagged BLOB signature on an alpha-bearing
  // literal: `MakerNoteRicoh` (`MakerNotes.pm:913` `/^(Ricoh|…)/i`). Every
  // other blob regex with ASCII letters is case-SENSITIVE. The MAKE/MODEL
  // anchors that carry `/i` are: Nikon3 (`:550`), Minolta/Minolta3 (`:497`/
  // `:523`), Sigma (`:1019`), Kodak7-10 + KodakUnknown (`/Kodak/i`), Kodak11/12
  // (`/(Kodak|PixPro)/i`) and Samsung2 (`uc … eq`). The rest are case-SENSITIVE
  // (`^Canon`, `^CASIO`, FLIR, JVCText, `^Asahi`, `^PENTAX`, `^(PENTAX )?RICOH`,
  // RicohText `^RICOH`, `^SANYO`, `^SONY`, and the `eq` arms). These tests lock
  // each dimension so a future refactor cannot silently flip CI↔CS.
  // ===========================================================================

  /// Codex R5 [MEDIUM real-input] — the `MakerNoteRicoh` blob regex
  /// `/^(Ricoh|…)/i` (`MakerNotes.pm:913`) is case-INSENSITIVE on the
  /// `Ricoh` literal. A real Caplio RR1/RR120/RDC-i500 body begins with
  /// UPPERCASE `RICOH\0…` (not `Ricoh`), so it MUST hit the Ricoh arm
  /// (`Vendor::Ricoh`, `body_offset == 8`, IFD), NOT fall through to the
  /// `RicohText` fallback (`body_offset == 0`, `not_ifd`). The trailing
  /// byte after `RICOH\0` is `\x02` (NOT `II`/`MM`), so `MakerNoteRicohPentax`
  /// (`:900`, `/^RICOH\0(II|MM)/`, no `/i`) does not claim it first.
  #[test]
  fn ricoh_uppercase_blob_prefix_hits_ricoh_arm_ci() {
    let blob = b"RICOH\x00\x02\x01rest_of_the_caplio_ifd";
    let d = dispatch(blob, Some("RICOH"), Some("Caplio RR120"), None);
    assert!(
      d.vendor().is_ricoh(),
      "uppercase RICOH\\0 must hit Ricoh (CI /i), got {:?}",
      d.vendor()
    );
    assert_eq!(
      d.body_offset(),
      8,
      "Ricoh arm body_offset is 8 (IFD), not RicohText's 0"
    );
    assert!(
      !d.is_not_ifd(),
      "Ricoh arm is an IFD; RicohText (the wrong target) would be NotIFD"
    );
    assert!(d.base_rule().is_inherit());
  }

  /// `MakerNoteRicoh` `/i` also folds mixed/lowercase `ricoh`. A `ricoh\0…`
  /// blob (lowercase) with a `RICOH` make hits the same Ricoh arm.
  #[test]
  fn ricoh_lowercase_blob_prefix_hits_ricoh_arm_ci() {
    let blob = b"ricoh\x00\x02\x01rest_of_the_ifd";
    let d = dispatch(blob, Some("RICOH"), Some("Caplio R50"), None);
    assert!(d.vendor().is_ricoh(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(!d.is_not_ifd());
  }

  /// Faithfulness floor: the original mixed-case `Ricoh\0…` (the literal
  /// exactly as written in the regex) still routes to the Ricoh arm — the
  /// CI widening did not break the pre-existing match.
  #[test]
  fn ricoh_titlecase_blob_prefix_still_hits_ricoh_arm() {
    let blob = b"Ricoh\x00\x02\x01rest_of_the_ifd";
    let d = dispatch(blob, Some("PENTAX RICOH"), Some("GR"), None);
    assert!(d.vendor().is_ricoh(), "got {:?}", d.vendor());
    assert_eq!(d.body_offset(), 8);
    assert!(!d.is_not_ifd());
  }

  /// The Ricoh `/i` applies ONLY to the alpha-bearing `Ricoh` alternative.
  /// A blob whose only "match" would require case-folding a NON-prefix
  /// (e.g. `RICOX…`, where byte 4 differs) must NOT hit the Ricoh arm; with
  /// a bare `RICOH` make it falls to the case-sensitive RicohText fallback
  /// (`^RICOH`) instead — proving the CI is a prefix fold, not a substring.
  #[test]
  fn ricoh_ci_is_prefix_only_non_match_falls_to_text() {
    let blob = b"RICOX-not-a-ricoh-prefix";
    let d = dispatch(blob, Some("RICOH"), Some("Caplio"), None);
    assert!(
      d.vendor().is_ricoh(),
      "RicohText catch-all, got {:?}",
      d.vendor()
    );
    assert!(
      d.is_not_ifd(),
      "no structural Ricoh prefix matched → RicohText (NotIFD)"
    );
    assert_eq!(d.body_offset(), 0);
  }

  /// `MakerNoteRicohText` Make anchor is `/^RICOH/` — case-SENSITIVE (NO
  /// `/i`, `MakerNotes.pm:943`). A lowercase `ricoh` Make with a
  /// non-structural blob must NOT be captured; it falls through to Unknown.
  /// (Real Ricoh bodies report uppercase `RICOH`, so this is the faithful
  /// CS gate — a CI gate here would be BROADER than Perl.)
  #[test]
  fn ricoh_text_make_anchor_is_case_sensitive() {
    let blob = b"some-non-structural-text-blob";
    let d = dispatch(blob, Some("ricoh"), Some("whatever"), None);
    assert!(
      d.vendor().is_unknown(),
      "lowercase `ricoh` make must NOT hit CS RicohText `^RICOH`, got {:?}",
      d.vendor()
    );
  }

  // NOTE: the MAKE-anchor `/i` dimension (Nikon3 `/^NIKON/i`, Minolta/Minolta3
  // `/i`, Sigma `/^(SIGMA|FOVEON)/i`, Casio's case-SENSITIVE `/^CASIO/`) is
  // already locked by the R4 class-sweep block above
  // (`ci_make_prefix_still_matches_ascii` + `casio_make_anchor_is_case_sensitive`).
  // The tests below extend the sweep to the dimensions R4 did NOT cover: the
  // single BLOB-signature `/i` (Ricoh, above) plus the two non-prefix make
  // anchors — Kodak's CI *substring* `/Kodak/i` and Samsung2's CI *equality*
  // `uc … eq 'SAMSUNG'` — and the CS `^Canon` prefix.

  /// Kodak Make anchor `/Kodak/i` (`MakerNotes.pm:475` KodakUnknown, etc.) is
  /// case-INSENSITIVE AND unanchored (substring). A mixed-case `kodak`
  /// substring in the make hits the KodakUnknown fallback (`Vendor::Kodak`,
  /// NotIFD) when the blob is not `AOC\0` and matches no earlier Kodak arm.
  #[test]
  fn kodak_make_anchor_is_case_insensitive_substring() {
    // Blob is a non-IFD, non-AOC, non-signature shape so it falls to
    // KodakUnknown (the make-keyed `/Kodak/i` fallback).
    let blob = b"\xff\xfe-unstructured-kodak-blob";
    let d = dispatch(blob, Some("Eastman kodak company"), Some("Z740"), None);
    assert!(
      d.vendor().is_kodak(),
      "/Kodak/i is CI substring, got {:?}",
      d.vendor()
    );
    assert!(d.is_not_ifd(), "KodakUnknown is NotIFD");
  }

  /// Samsung2 Make anchor `uc $$self{Make} eq 'SAMSUNG'` (`MakerNotes.pm:969`)
  /// is case-INSENSITIVE equality. A mixed-case `Samsung` make + the EXIF-
  /// format magic hits `MakerNoteSamsung2` (`Vendor::Samsung`, FixBase).
  #[test]
  fn samsung2_make_anchor_is_case_insensitive_equality() {
    // The branch-B (LE) EXIF-format magic: `.\0\x01\0\x07\0\x04\0\0\0` then
    // ASCII `"0100"` at offset 10 (14 bytes).
    let blob = b"\x01\x00\x01\x00\x07\x00\x04\x00\x00\x000100rest";
    let d = dispatch(blob, Some("Samsung"), Some("NX300"), None);
    assert!(
      d.vendor().is_samsung(),
      "uc Make eq 'SAMSUNG' is CI, got {:?}",
      d.vendor()
    );
    assert!(d.fix_base());
  }

  /// Canon Make anchor `/^Canon/` (`MakerNotes.pm:63`) is case-SENSITIVE. A
  /// lowercase `canon` make must NOT hit `MakerNoteCanon` — faithful CS.
  #[test]
  fn canon_make_anchor_is_case_sensitive() {
    let blob = b"\x01\x00\x00\x00\x04\x00";
    let d = dispatch(blob, Some("canon"), Some("EOS"), None);
    assert!(
      !d.vendor().is_canon(),
      "lowercase `canon` must NOT hit CS Canon `^Canon`, got {:?}",
      d.vendor()
    );
  }
}
