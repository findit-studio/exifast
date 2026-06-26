//! PARITY CHECKPOINT for the sink-layer removal.
//!
//! Proves that an independently-assembled **typed serde document** — the
//! orchestration tags lifted off [`exifast::parser::extract_info`] PLUS the
//! format tags from `serde_json::to_value(&`[`exifast::Rendered`]`)` — is, for
//! EVERY active conformance fixture in BOTH `-j` (PrintConv) and `-n` (numeric)
//! modes, value-equivalent to the engine document [`extract_info`] produces AND
//! the committed bundled-ExifTool golden.
//!
//! After the sink layer was deleted, `extract_info` IS the typed-serde path
//! (`detect → parse → serde-render`), so the "vs `extract_info`" arm is now a
//! self-consistency check (the document assembled via the public
//! [`exifast::Rendered`] serde wrapper matches the engine's own serde render);
//! the "vs golden" arm remains the load-bearing conformance check. Kept as a
//! standalone harness because it exercises the public `Rendered` serde view +
//! the `parse_bytes`-style candidate loop independently of the engine entry.
//!
//! ## What the typed serde document is
//!
//! `extract_info` detects the file type, runs the parse (yielding a complete
//! typed `AnyMeta` incl. chains), emits the orchestration tags
//! (`ExifTool:ExifToolVersion`, `SourceFile`, the `File:*` triplet), and
//! serde-renders the whole thing. This harness assembles an EQUIVALENT document
//! by:
//!
//!   1. Lifting the orchestration tags (`ExifTool:*` + `File:*`) and the
//!      warnings/errors (incl. the post-loop finalization `Error`) off the
//!      engine document ([`extract_info`], itself §4-conformant) — these are
//!      the engine's responsibility, OUTSIDE the per-format typed Meta.
//!   2. Serde-rendering the typed `AnyMeta` for the FORMAT tags via
//!      `serde_json::to_value(&Rendered::new(&meta, print_conv))` — the public
//!      typed serde view.
//!   3. Merging into the single `[{ … }]` document with `%noDups` first-wins
//!      (orchestration keys are inserted first, so they win over any
//!      coincident typed key — though typed Metas never emit `File:*`).
//!
//! ## Excluded fixtures
//!
//! `AIFF_id3.aif` is NOT one of the 121 active conformance fixtures: the AIFF
//! `ID3 ` SubDirectory dispatch (AIFF.pm:202) is a deliberate Phase-2 forward
//! item that the ENGINE path also does not implement (the `ID3 ` chunk is
//! recognized then silently skipped — see the `#[ignore]`-d
//! `aiff_id3_chunk_subdirectory_dispatch_deferred_conformance` test). The
//! typed path matches the engine path there (both lack ID3); both diverge only
//! from the golden. It is therefore excluded from this 121-fixture checkpoint,
//! exactly as it is excluded from `conformance.rs`.
//!
//! `flash_xmp_livexml.flv` is similarly excluded: Flash.pm:243-246 dispatches
//! the `liveXML` AMF key through `Image::ExifTool::XMP::Main` (FORMATS.md row
//! 15 XMP infra, 6693 LOC, Phase-3+). Both the engine and typed paths surface
//! the deferral as `ExifTool:Warning: "XMP SubDirectory dispatch deferred
//! (Phase-3+)"`; the bundled golden additionally carries `XMP-*:*` tags we
//! cannot synthesize without the XMP parser. Pinned by the `#[ignore]`-d
//! `flash_xmp_livexml_subdirectory_deferred_conformance` test. Codex PR #32 R6.
//!
//! The QuickTime SP3 timed-metadata fixtures (`QuickTime_mebx_gps.mov`,
//! `QuickTime_mebx_float.mov`, `QuickTime_mebx_keys.mov`,
//! `QuickTime_mebx_livephoto.mov`, `QuickTime_mebx_smartstyle.mov`,
//! `QuickTime_mebx_detface.mov`, `QuickTime_gps_kenwood.mov`,
//! `QuickTime_gps0.mov`, `QuickTime_gsen.mov`)
//! are NOT in this set: `Image::ExifTool::QuickTime::Stream` is gated behind
//! the bundled `ExtractEmbedded` (`-ee`) option, which `tools/gen_golden.sh`
//! never passes — so those fixtures carry only an `-ee`-captured
//! `<f>.ee.json` golden (no standard `<f>.json` / `<f>.n.json`) and are
//! exercised by the dedicated `tests/quicktime_stream.rs` harness instead.
//! The both-standard-goldens [`active_fixtures`] filter skips them
//! automatically.
//!
//! Gated on `feature = "json"`: imports the `json`-gated `jsondiff` +
//! `serde_json` rendering of `Rendered`.
#![cfg(feature = "json")]

use exifast::{
  filetype::detection_candidates,
  format_parser::{Rendered, SharedFlags, any_parser_for},
  jsondiff::json_equivalent_strict as json_equivalent,
  parser::extract_info,
};

/// Fixtures excluded from the active conformance set — known
/// formally-accept-deferred residuals (NOT silent metadata losses;
/// see docs/tracking.md and the per-fixture `#[ignore]` conformance
/// tests).
///
/// - `AIFF_id3.aif` — AIFF ID3-chunk SubDirectory (forward item in both
///   the engine and typed paths; see module docs).
/// - `FLAC.ogg` — Ogg-FLAC transport (R3 F2 fallback; the `\x7fFLAC`
///   packet handler `numFlac` accumulator + FLAC sub-stream re-dispatch
///   is not yet ported). The METADATA_BLOCK_PICTURE half of R3 F2 IS
///   fixed (see `tests/conformance.rs::ogg_metadata_block_picture_conformance`).
/// - `flash_xmp_livexml.flv` — Codex PR #32 R6: Flash.pm:243-246
///   dispatches the `liveXML` AMF key through `Image::ExifTool::XMP::Main`
///   (FORMATS.md row 15 XMP infra, 6693 LOC, Phase-3+). Bundled emits
///   `XMP-*:*` tags via XMP::ProcessXMP; exifast surfaces the deferral as
///   `ExifTool:Warning: "XMP SubDirectory dispatch deferred (Phase-3+)"`
///   so the gap is visible (see `src/formats/flash.rs::
///   is_xmp_subdirectory_dispatch`). Pinned by
///   `tests/conformance.rs::flash_xmp_livexml_subdirectory_deferred_conformance`
///   (#[ignore]d).
/// - `Exif_makernote.tif` — the Exif port captures the MakerNote (0x927c)
///   raw bytes but DEFERS vendor parsing to the MakerNotes wave; bundled
///   `perl exiftool` emits an `ExifTool:Warning` (or MakerNotes:* tags for
///   a recognized vendor) the exifast Exif port does not. 4-surface
///   accept-defer (see `tests/conformance.rs::
///   exif_makernote_subdirectory_deferred_conformance`, the
///   `SubDirKind::MakerNote` code comment, and docs/tracking.md).
/// (The QuickTime `camm` / `mebx` / Sony `rtmd` timed-metadata fixtures are
/// now ALL ACTIVE: R13 implements `Track<N>:MetaFormat` (the `stsd` 4-char
/// sample-description code) subsystem-wide at the structural trak-parse layer,
/// which was their SOLE remaining no-`ee` `.json`/`.n.json` divergence. With
/// that gap closed every one is byte-exact end-to-end — writer path AND
/// typed-serde path — and is exercised both here and, byte-exact incl.
/// `MetaFormat`, by `tests/timed_metadata_conformance.rs`.)
const NOT_ACTIVE: &[&str] = &[
  // (#345/#211 `QuickTime_gopro_hero6_gpmf.mp4` was here too but is now ACTIVE:
  // its three goldens are regenerated conventioned via the
  // `gen_golden.sh QuickTime_gopro_hero6_gpmf.mp4` arm and exifast emits the
  // full real `gpmd` timed-GPS/sensor `Doc<N>` block — Accelerometer/Gyroscope
  // binary placeholders, the camera-vision streams FaceNumbers/FaceDetected/
  // ISOSpeeds/ExposureTimes/ColorTemperatures/WhiteBalanceRGB/CameraTemperature,
  // the GPS5 scalars, and the Track5 `fdsc` identity — byte-exact vs bundled
  // ExifTool 13.59. The base `.json`/`.n.json` are byte-exact in
  // `conformance.rs::quicktime_gopro_hero6_gpmf_conformance`; the `-ee` `.ee.json`
  // in `timed_metadata_conformance.rs::gopro_hero6_gpmd_ee_byte_exact`.)
  // (#122 `MP4_parrot_anafi.mp4` (Parrot Anafi drone) was here too but is now
  // ACTIVE: its `mett` metadata track carries no per-sample timed telemetry that
  // bundled 13.59 surfaces (`-ee` == base), so the conventioned base goldens —
  // which exclude the unported subsystems by name (the QuickTime-embedded XMP
  // packet, the `udta/meta`(`mdir`) ItemList/`ilst` atoms + `HandlerVendorID`,
  // the `meta`(`mdta`) Keys, `AudioKeys:Balance`, the `UserData:LocationInformation`
  // struct, and the GPSCoordinates-derived `Composite:GPS*`; see the
  // `tools/gen_golden.sh` arm) — are byte-exact, see
  // `conformance.rs::mp4_parrot_anafi_conformance`.)
  // (#138 `MP4_viofo_a119_gps.mp4` was here too but is now ACTIVE — the #348
  // dual-`hdlr` per-track Handler dedup landed, so its no-`ee` `.json`/`.n.json`
  // are byte-exact, see `conformance.rs::mp4_viofo_a119_gps_conformance`.)
  // (#130 MISB KLV M2TS was here too but is now ACTIVE: this fixture's PMT
  // declares only a type-0x1b H.264 stream — no type-0x15 packetized-metadata
  // PID — and the file carries no SMPTE/MISB universal label, so bundled
  // ExifTool 13.59 decodes no MISB tags and exifast already matches it byte-exact.)
  // (#318/#311 FOUR of the five additional Pentax body fixtures (k1/k3/k5_ii/kp)
  // were here too but are now ACTIVE: the #379 body-agnostic sub-tables
  // (model-gated by `is_k3_mark_iii`/`is_af_points_in_focus_excluded`/
  // `is_body_voltage`/…) decode them byte-exact vs bundled 13.59 — the full Pentax
  // tag set proven on `JPEG_pentax_ks2.jpg`, across the per-body MakerNote variant
  // branches and both byte orders (k1/k3/kp/k70 little-endian; k5_ii BIG-endian),
  // see `conformance.rs::jpeg_pentax_{k1,k3,k5_ii,kp,k70}_conformance`. Their
  // goldens drop the same cross-cutting deferred subsystems as KS-2 minus the
  // body-absent `Composite:DateTimeCreated`, PLUS only unimplemented `Pentax:*`
  // leaves, see `FIXTURE_EXCLUDED_KEYS`. The FIFTH body — `JPEG_pentax_k70.jpg` —
  // activated on #380 (the `1/60` `rational64u` ExposureTime now rounds via
  // `RoundFloat($num/$den, 10)`, so its core EXIF/Composite values match bundled).)
  "AIFF_id3.aif",
  "FLAC.ogg",
  "flash_xmp_livexml.flv",
  "Exif_makernote.tif",
  // The REAL Sony FX3 `.mp4` (#76) carries paired `.json` / `.n.json` goldens
  // but is accept-deferred from the active byte-exact set. The QuickTime
  // container phase-1 port now emits its `vide`/`soun` `stsd` sample-description
  // + `hdlr` HandlerDescription; the residual no-`ee` divergence is the `tapt`
  // `TrackProperty`, the `tref` `ContentDescribes`, the `vmhd`
  // GraphicsMode/OpColor, the `stts`-derived `VideoFrameRate`, and the
  // `TimeZone` (later container phases). The rtmd PAYLOAD proof
  // (FNumber/ExposureTime/ISO/… byte-exact, the `parse_stsz` fixed-size-`stsz`
  // fix) is pinned at `-ee` in `tests/timed_metadata_conformance.rs`
  // (`sony_fx3_rtmd_mp4_*`), with the residual tags + the past-EOF
  // `Track3:Warning` excluded there.
  "QuickTime_sony_fx3_rtmd.mp4",
  // `QuickTime_insta360_real.insv` (the real OneRS capture, #91) — the
  // Insta360 trailer decode is byte-exact (see
  // `tests/timed_metadata_conformance.rs::insta360_real_oners_insv_byte_exact`).
  // The QuickTime container ports now emit its `vide`/`soun` `stsd`
  // sample-description + HandlerDescription (phase 1) and the `vmhd`
  // GraphicsMode/OpColor + `gmhd`/`gmin` `Gen*` (phase 4); the residual QuickTime
  // *container* gap (NOT Insta360) is the `pasp` PixelAspectRatio, the
  // `stts`-derived `VideoFrameRate`, and the 470-sample timed-`text` track's
  // per-sample `SampleTime`/`SampleDuration`. So it is accept-deferred here (the
  // conformance test excludes exactly those tails and is byte-exact on
  // everything else).
  "QuickTime_insta360_real.insv",
  // The #285 round-2 real-device fixtures (#109/#92/#100) — dropped with
  // goldens + #[ignore]d conformance tests pending their ports (DJI MakerNote/
  // MPF/JFIF thermal for the M3T RJPEG, XMP-GPano for the Insta360 equirect).
  // Their no-ee .json carries tags exifast does not yet emit, so accept-deferred
  // here until each port lands (then they move to active).
  // `DJI_Matrice30T.jpg` (#114) is now ACTIVE — the JFIF/MPF/DJI-thermal port
  // landed (`src/exif/jpeg_app.rs`), byte-exact at both `-j`/`-n` (see
  // `tests/conformance.rs::dji_matrice30t_conformance`).
  // (#100 `QuickTime_rove_r2_4k.MP4` was here too but is now ACTIVE — the #348
  // dual-`hdlr` per-track Handler dedup + the `©fmt`/`©inf` UserData atoms landed,
  // so its no-`ee` `.json`/`.n.json` are byte-exact, see
  // `conformance.rs::quicktime_rove_r2_4k_conformance`.)
  "DJI_M3T_thermal.RJPEG",
  "Insta360ONE_equirectangular.jpg",
  // (`MP4_blackvue_dr770x.mp4` (#362/#213) is now ACTIVE — the BlackVue DR770X
  // PittaSoft port landed: the top-level `free`/`%QuickTime::Pittasoft`
  // SubDirectory (Copyright/StartTime/OriginalFileName + PreviewImage/GPSLog
  // binary placeholders + the no-`ee` first-record TimeCode/Accelerometer from
  // `3gf `) and the audio `chan` `%QuickTime::ChannelLayout` (LayoutFlags/
  // AudioChannelTypes/NumChannelDescriptions). Its no-`ee` `.json`/`.n.json` are
  // byte-exact (the ported Composites kept; `System:all` excluded), see
  // `conformance.rs::mp4_blackvue_dr770x_conformance`. No `.ee.*` golden — `-ee`
  // surfaces no timed metadata for this file.)
  // (`MPEG2_TS_pruveeo_d90.ts` (#138/#129) is now ACTIVE — the M2TS LIGOGPSINFO
  // dashcam timed-GPS port landed: its no-`ee` `.json`/`.n.json` are byte-exact
  // (M2TS/H264 only; Composite-excluded per the QuickTime/MPEG precedent) and
  // the `-ee` LIGO GPS is pinned in
  // `tests/timed_metadata_conformance.rs::pruveeo_d90_ligogps_ee_byte_exact`.)
  // `CanonRaw_ctmd.cr3` (the REAL minimal CRX still-RAW, #81 phase 2) — the
  // Canon CTMD `Priority => 0` dedup fix (the `ExposureInfo` `FNumber 3.5` /
  // `ExposureTime 1/80` win over the `ShotInfo` `Priority => 0` re-dispatch) is
  // byte-exact at `-ee` (see
  // `tests/timed_metadata_conformance.rs::canon_ctmd_real_cr3_priority_dedup_byte_exact`).
  // Its no-`ee` `.json`/`.n.json` are accept-deferred: bundled extracts the FULL
  // CTMD metadata WITHOUT `-ee` for a still-image RAW (145 keys), but exifast
  // gates CTMD behind `-ee` (a separate QuickTime-container item) and at no-`ee`
  // emits only the structural moov/track scalars + the `Track1:Warning`
  // ExtractEmbedded hint. The #81 proof is pinned at `-ee`, not the no-`ee` path.
  "CanonRaw_ctmd.cr3",
  // `DNG_preview_image.dng` (#352/#353) — the #331-P2 PreviewImage fixture set's
  // DNG member. Its IFD0→SubIFD (0x014a) carries `SubfileType=1` + StripOffsets/
  // StripByteCounts; the P2 PreviewImage gating is CORRECT (the DNG must — and
  // does — emit NO PreviewImage, since 0x0111 takes the plain `StripOffsets` arm,
  // `Exif.pm:639-653`). But exifast does not yet WALK the classic-TIFF `SubIFD`
  // pointer, so it cannot emit the SubIFD's
  // SubfileType/ImageWidth/ImageHeight/StripOffsets/StripByteCounts and the full
  // `-G1` golden is not byte-exact. Accept-deferred to #352 (the SubIFD walk);
  // the CR2 + ARW members of this set ARE active (the IFD0:PreviewImage proof).
  "DNG_preview_image.dng",
  // (The two Pentax PEF fixtures #393/#401 — K-3 Mark III + *ist D — are now
  // ACTIVE: #393 ported their MakerNote variants byte-exact, so they moved out of
  // NOT_ACTIVE into the active set with per-fixture FIXTURE_EXCLUDED_KEYS for the
  // non-MakerNote residuals.)
  // The `Sony_ILME-FX3_real.ARW` raw is now ACTIVE: the `%Sony::Main` ENCRYPTED
  // sub-table tower for the FX3 body is FULLY PORTED — the `Decipher`
  // substitution cipher + the model/version-dispatched ProcessBinaryData tables
  // (`Tag9050c`/`Tag9400c`/`Tag9401`(ISOInfo)/`Tag9402`/`Tag9406`/`Tag940c`/
  // `Tag9416` + the plain `Tag202a`) emit every `Sony:*` exposure/AF/lens/
  // battery/ISO leaf, and the five dependent `Composite:*` (LensID/BlueBalance/
  // RedBalance/CFAPattern/FocusDistance2) now compute byte-exact (with the
  // FocalLength35efl/ScaleFactor35efl pair). It moves into the active set with a
  // per-fixture `FIXTURE_EXCLUDED_KEYS` entry for the lone `XMP-xmp:Rating`
  // residual (the IFD0 `0x02bc` ApplicationNotes XMP routing is a separate
  // cross-cutting subsystem — see `conformance.rs::sony_arw_real_sr2_and_subifd_conformance`).
  //
  // The two OLDER Sony ARW raws (`SLT-A33` / `DSLR-A200`) stay accept-deferred:
  // their core EXIF/SubIFD + the ENTIRE SR2 subsystem (the `DNGPrivateData`
  // 0xc634 → `%Sony::SR2Private` descent, the `Decrypt` LFSR, and the decrypted
  // `%Sony::SR2SubIFD` + `%Sony::SR2DataIFD` walks — `SR2:*`/`SR2SubIFD:*`/
  // `SR2DataIFD*:ColorMode`) ARE byte-exact in BOTH `-j` and `-n`, as are their
  // Sony ARW `SubIFD:*` raw tags, the `Compression => 'Sony ARW Compressed'`
  // (32767), the IFD2 `JpgFromRaw*`, and the `IsImageData` placeholders. Their
  // RESIDUAL is the OLDER-body `%Sony::Main` sub-table tower (A33: `CameraInfo3`/
  // `AFInfo`(AFStatus grid)/`CameraSettings3`/`ExtraInfo3`/`MoreInfo`/`Tag900b`
  // — ~101 leaves; A200: `CameraSettings`/`CameraInfoA200` — ~72 leaves) which
  // emit the remaining `Sony:*` exposure/AF/lens leaves + the dependent
  // `Composite:*`; A200 ADDITIONALLY needs the `%MinoltaRaw::Main` MRW port (22
  // `MinoltaRaw:*`, which also overrides its `Composite:ImageSize`/`Megapixels`).
  // Those OLDER sub-table towers are a separate faithful campaign.
  "Sony_SLT-A33_real.ARW",
  "Sony_DSLR-A200_real.ARW",
];

/// ACTIVE fixtures that emit a tag whose VALUE diverges from bundled because a
/// dependent subsystem is deferred — the tag is dropped from BOTH the
/// typed-serde/writer output AND the golden (the golden keeps the matching `-x`
/// in `tools/gen_golden.sh`, exifast emits a diverging value, so a golden-only
/// `-x` would leave exifast's extra). Mirrors `conformance.rs::check_excluding`
/// + `timed_metadata_conformance.rs::drop_keys`. Each entry is
/// `(fixture, &[FULLY-QUALIFIED "Family1:Name" keys])`.
///
/// - `MP4_parrot_anafi.mp4` (#361): exifast emits the XMP-derived
///   `Composite:GPSAltitude` (byte-exact vs bundled for an XMP-only file), but
///   bundled's anafi `Composite:GPS*` come from the unported
///   `%QuickTime::Composite` `GPSCoordinates`/`LocationInformation` tables
///   (QuickTime.pm:8668-8728) which OVERRIDE the XMP one — the same port-wide
///   GPS-composite deferral the GoPro/SP2 arms carry. So the seven exact
///   `Composite:GPS*` keys are dropped here while that table is unported (every
///   other anafi tag — the 33 newly-decoded XMP/ItemList/Keys/AudioKeys/
///   LocationInformation/HandlerVendorID tags included — is byte-exact). The
///   distinct `XMP-exif:GPS*` tags are NOT excluded (exact-key matching, not a
///   `:tail` suffix), so the embedded-XMP GPS byte-exactness is verified here.
/// - `MP4_movie_keys.mov` (#361 R7): the crafted movie-level `keys` fixture's
///   `\xa9xyz` ⇒ `Keys:GPSCoordinates` seeds the unported `%QuickTime::Composite`
///   table (QuickTime.pm:8668) that bundled uses to synthesize
///   `Composite:GPSLatitude`/`Longitude`/`GPSPosition` — the same port-wide GPS-
///   composite deferral. exifast emits none, so those three are dropped here
///   (every Keys/ItemList/UserData tag + the ported ImageSize/Megapixels/
///   AvgBitrate/Rotation Composites stay byte-exact).
const FIXTURE_EXCLUDED_KEYS: &[(&str, &[&str])] = &[
  (
    "MP4_parrot_anafi.mp4",
    &[
      "Composite:GPSAltitude",
      "Composite:GPSAltitudeRef",
      "Composite:GPSLatitude",
      "Composite:GPSLatitudeRef",
      "Composite:GPSLongitude",
      "Composite:GPSLongitudeRef",
      "Composite:GPSPosition",
    ],
  ),
  (
    "MP4_movie_keys.mov",
    &[
      "Composite:GPSLatitude",
      "Composite:GPSLongitude",
      "Composite:GPSPosition",
    ],
  ),
  // #311 — the K-S2. #381 ported the four cross-cutting Composites/IFD
  // (`Composite:Flash`/`LensID`/`DateTimeCreated` + `PrintIM:PrintIMVersion`) —
  // now emitted byte-exact, so they are NO LONGER excluded. The sole remaining
  // deferral is the `tiff:YCbCrSubSampling` `RawJoin`. Mirrors `conformance.rs::
  // jpeg_pentax_ks2_conformance`. The golden keeps the faithful 13.59 dump.
  ("JPEG_pentax_ks2.jpg", &["XMP-tiff:YCbCrSubSampling"]),
  // #311/#318 — the 5 additional Pentax body fixtures. #311 ported the per-body
  // multi-model Main conditional branches: the `/(K-1|645Z)\b/` + `/(K-3|KP)\b/`
  // AFPointSelected (0x000e) model point-hashes, the count-2 ExposureCompensation
  // (0x0016), the `%Pentax::BatteryInfo` BodyBatteryVoltage3/4 (K-5 II), and the
  // `%Pentax::AFPointInfo` (0x0245) subdir (NumAFPoints + AFPointsInFocus/Selected/
  // Special via `DecodeAFPoints`) — all now emitted byte-exact, no longer excluded.
  // The remaining exclusions are `XMP-tiff:YCbCrSubSampling` PLUS the NON-#311
  // per-body `Pentax:*` residuals the port does not yet emit (Contrast* /
  // ISOAutoMinSpeed / ShutterType / SkinToneCorrection Main leaves; the `0x0243
  // PixelShiftInfo`, `0x03ff TempInfo` and K-5-II `$count`/offset SubDirectory
  // variants) — deferred, NOT mis-decoded (exifast emits nothing, the golden keeps
  // the bundled value). These lists MIRROR EXACTLY the per-fixture `*_DEFERRED`
  // consts in `conformance.rs::jpeg_pentax_{k1,k3,k5_ii,k70,kp}_conformance` (see
  // the detailed rationale there).
  (
    "JPEG_pentax_k1.jpg",
    &[
      "XMP-tiff:YCbCrSubSampling",
      "Pentax:ContrastHighlight",
      "Pentax:ContrastHighlightShadowAdj",
      "Pentax:ContrastShadow",
      "Pentax:ISOAutoMinSpeed",
      "Pentax:PixelShiftResolution",
      "Pentax:ShutterType",
      "Pentax:SkinToneCorrection",
    ],
  ),
  (
    "JPEG_pentax_k3.jpg",
    &[
      "XMP-tiff:YCbCrSubSampling",
      "Pentax:ContrastHighlight",
      "Pentax:ContrastHighlightShadowAdj",
      "Pentax:ContrastShadow",
      "Pentax:ISOAutoMinSpeed",
      "Pentax:SensorTemperature",
      "Pentax:SensorTemperature2",
    ],
  ),
  (
    "JPEG_pentax_k5_ii.jpg",
    &[
      "XMP-tiff:YCbCrSubSampling",
      "Pentax:CameraOrientation",
      "Pentax:CameraTemperature4",
      "Pentax:CameraTemperature5",
      "Pentax:ContrastHighlight",
      "Pentax:ContrastHighlightShadowAdj",
      "Pentax:ContrastShadow",
      "Pentax:FocusRangeIndex",
      "Pentax:ISOAuto",
      "Pentax:ISOAutoMinSpeed",
      "Pentax:LensFocalLength",
      "Pentax:LevelIndicator",
      "Pentax:LinkAEToAFPoint",
      "Pentax:MaxAperture",
      "Pentax:MinFocusDistance",
      "Pentax:NominalMaxAperture",
      "Pentax:NominalMinAperture",
      "Pentax:PreviewImageStart",
      "Pentax:SensitivitySteps",
      "Pentax:SensorSize",
      "Pentax:SensorTemperature",
      "Pentax:SensorTemperature2",
      "Pentax:WB_RGGBLevelsCloudy",
      "Pentax:WB_RGGBLevelsDaylight",
      "Pentax:WB_RGGBLevelsFlash",
      "Pentax:WB_RGGBLevelsFluorescentD",
      "Pentax:WB_RGGBLevelsFluorescentL",
      "Pentax:WB_RGGBLevelsFluorescentN",
      "Pentax:WB_RGGBLevelsFluorescentW",
      "Pentax:WB_RGGBLevelsShade",
      "Pentax:WB_RGGBLevelsTungsten",
      "Pentax:WB_RGGBLevelsUserSelected",
    ],
  ),
  // `JPEG_pentax_k70.jpg` (#311/#318) — ACTIVATED by #380. The CORE
  // `ExifIFD:ExposureTime` / `Composite:ShutterSpeed` / `Composite:LightValue`
  // now match bundled byte-exact (`Conv::ExposureTime` rounds the `1/60`
  // `rational64u` quotient via `RoundFloat($num/$den, 10)`, exactly as ExifTool's
  // `GetRational64u` reader), so they are NO LONGER excluded — only unimplemented
  // Pentax leaves remain (mirrors `conformance.rs::K70_DEFERRED`).
  (
    "JPEG_pentax_k70.jpg",
    &[
      "XMP-tiff:YCbCrSubSampling",
      "Pentax:ContrastHighlight",
      "Pentax:ContrastHighlightShadowAdj",
      "Pentax:ContrastShadow",
      "Pentax:PixelShiftResolution",
      "Pentax:ShutterType",
      "Pentax:SkinToneCorrection",
    ],
  ),
  (
    "JPEG_pentax_kp.jpg",
    &[
      "XMP-tiff:YCbCrSubSampling",
      "Pentax:ContrastHighlight",
      "Pentax:ContrastHighlightShadowAdj",
      "Pentax:ContrastShadow",
      "Pentax:ISOAutoMinSpeed",
      "Pentax:PixelShiftResolution",
      "Pentax:ShutterType",
      "Pentax:SkinToneCorrection",
    ],
  ),
  // #393 — the K-3 Mark III PEF. The K-3III MakerNote variants are ported
  // byte-exact; the residuals are the NON-MakerNote container tags (the unported
  // `ExifIFD:CFAPattern`; the PEF IFD2 JpgFromRaw raw-image chain — bundled
  // `IFD2:JpgFromRaw*` vs the port's `IFD2:ThumbnailOffset/Length` +
  // `ExifTool:Warning`, dropped from both; the deferred `Pentax:PreviewImage`/
  // `PreviewImageStart` IsOffset binary). MIRRORS `conformance.rs::
  // pef_pentax_k3_mark_iii_conformance`'s `K3III_PEF_DEFERRED`.
  (
    "PEF_pentax_k3_mark_iii.pef",
    &[
      "ExifIFD:CFAPattern",
      "IFD2:JpgFromRaw",
      "IFD2:JpgFromRawStart",
      "IFD2:JpgFromRawLength",
      "IFD2:ThumbnailOffset",
      "IFD2:ThumbnailLength",
      "ExifTool:Warning",
      "Pentax:PreviewImage",
      "Pentax:PreviewImageStart",
    ],
  ),
  // #393 — the *ist D PEF. The OLD-format MakerNote is ported byte-exact; the
  // residuals are `Composite:LensID` (the camera Composite subsystem, deferred
  // port-wide), the unported `ExifIFD:CFAPattern`, and the
  // `Pentax:PreviewImage`/`PreviewImageStart`/`ToneCurve` IsOffset/binary leaves.
  // MIRRORS `conformance.rs::pef_pentax_istd_conformance`'s `ISTD_PEF_DEFERRED`.
  (
    "PEF_pentax_istd.pef",
    &[
      "Composite:LensID",
      "ExifIFD:CFAPattern",
      "Pentax:PreviewImage",
      "Pentax:PreviewImageStart",
      "Pentax:ToneCurve",
    ],
  ),
  // #205 — the PNG raw-profile-XMP diagnostics walk-order fixture. The invalid
  // `eXIf` chunk (whose body is neither `II`/`MM`/`\0`) makes bundled emit a
  // `PNG:eXIf = (Binary data 17 bytes, …)` placeholder the PNG port suppresses
  // (the pre-existing eXIf-suppression deferral — exifast decodes EXIF blocks,
  // not the raw-chunk binary placeholder). Dropped from BOTH sides; the document
  // FIRST-`ExifTool:Warning` ORDER (the earlier XMP `XMP is double UTF-encoded`,
  // not the later `Invalid eXIf chunk`) is what this fixture pins. Mirrors
  // `conformance.rs::png_rawprofile_xmp_conformance`'s `check_excluding`.
  ("PNG_rawprofile_xmp_warnorder.png", &["PNG:eXIf"]),
  // #180 — the post-`IEND` Trailer family-1 group fixture. The trailer `iCCP`
  // chunk's corrupt zlib stream makes bundled emit a deferred `Trailer:ICC_Profile
  // = (Binary data 1 bytes, …)` placeholder (the still-compressed body) that the
  // PNG port suppresses (no ICC_Profile sub-port). Dropped from BOTH sides; the
  // group-scoped `Trailer:Warning = Error inflating iCCP` (the #180 fix) and the
  // `Trailer:ProfileName` are what this fixture pins. Mirrors
  // `conformance.rs::png_crafted_input_hardening_conformance`'s `check_excluding`.
  ("PNG_trailer_iccp_warn.png", &["Trailer:ICC_Profile"]),
  // #178-item1 — the nested-zXIf inner-inflate fixture. The doubly-compressed
  // `zxIf` makes bundled emit a `PNG:zxIf = <err>` placeholder the PNG port
  // suppresses (the pre-existing eXIf/zxIf-suppression deferral). Dropped from
  // BOTH sides; the `Error inflating zxIf` warning text (the #178-item1 fix, vs
  // the prior `Invalid zxIf chunk`) is what this fixture pins. Mirrors
  // `conformance.rs::png_crafted_input_hardening_conformance`'s `check_excluding`.
  ("PNG_nested_zxif.png", &["PNG:zxIf"]),
  // The `Sony_ILME-FX3_real.ARW` raw is now active (its `%Sony::Main` encrypted
  // sub-table tower is fully ported — see the `NOT_ACTIVE` note). The lone
  // residual is `XMP-xmp:Rating` (= 0) from the IFD0 `0x02bc` ApplicationNotes
  // XMP packet: exifast routes embedded XMP to the shared `ProcessXMP` parser
  // only from the JPEG `APP1` marker walk, not the TIFF/raw `0x02bc`
  // SubDirectory (a separate cross-cutting subsystem deferred to its own
  // campaign). Dropped from BOTH sides; the `Sony:Rating` (= 0) MakerNote leaf
  // IS emitted. Mirrors `conformance.rs::sony_arw_real_sr2_and_subifd_conformance`'s
  // `FX3_DEFERRED`.
  ("Sony_ILME-FX3_real.ARW", &["XMP-xmp:Rating"]),
];

/// The fully-qualified `Family1:Name` keys to drop for `fixture` (empty when
/// none).
fn excluded_keys_for(fixture: &str) -> &'static [&'static str] {
  FIXTURE_EXCLUDED_KEYS
    .iter()
    .find(|(f, _)| *f == fixture)
    .map_or(&[], |(_, keys)| *keys)
}

/// Strip a set of FULLY-QUALIFIED keys (exact `Family1:Name`) from every object
/// in a `-j -G1`/`-n` JSON document. A no-op when `exact_keys` is empty.
/// Matching is EXACT (not an `:tail` suffix) so excluding
/// `Composite:GPSAltitude` does NOT also strip the distinct `XMP-exif:GPSAltitude`.
fn drop_keys(doc: &str, exact_keys: &[&str]) -> String {
  if exact_keys.is_empty() {
    return doc.to_string();
  }
  let mut v: serde_json::Value = serde_json::from_str(doc).expect("valid JSON document");
  if let Some(arr) = v.as_array_mut() {
    for el in arr {
      if let Some(obj) = el.as_object_mut() {
        obj.retain(|k, _| !exact_keys.iter().any(|t| k == t));
      }
    }
  }
  serde_json::to_string(&v).expect("re-serialize document")
}

/// Expected count of ACTIVE conformance fixtures (every `tests/fixtures/<f>`
/// with paired `.json` + `.n.json` goldens, minus [`NOT_ACTIVE`]). Bumped per
/// Codex round; see the long comment block in
/// [`typed_serde_path_equals_writer_path_and_golden_all_337`] for the history.
///
/// Post-rebase (lib/plist golden-migration onto main): main's 275 ACTIVE
/// fixtures PLUS the 52 ACTIVE PLIST fixtures from this branch = 327. The
/// PLIST chronology's running `… → 283` figure is relative to lib/plist's
/// older fork base; the absolute total against the live golden directory is
/// 327 (`275 + 52`).
///
/// Golden-v2 Phase C (`[minor]`/`[x$n]` diagnostics): +2 — `ID3_dup_short_frame.mp3`
/// (the ` [x2]` multi-warning count) + `Exif_excessive_count.tif` (the `[Minor]`
/// ignorable-2 prefix). 341 → 343.
///
/// Post-rebase (lib/m2ts golden-migration onto golden-v2 main): main's 343
/// ACTIVE fixtures PLUS the single ACTIVE M2TS fixture (`M2TS.mts`) from this
/// branch = 344.
///
/// GoPro Codex R7/F1 (multi-moov GPMF walk): +1 —
/// `QuickTime_multimoov_gpmf.mov`, a synthetic two-`moov` `.mov` whose GoPro
/// `udta/GPMF` lives ONLY in the LATER `moov` (the first-match
/// `find_top_level_box` dropped it; `for_each_moov_gpmf` now walks every
/// `moov`). 344 → 345.
///
/// GoPro Codex R12-A (full %GoPro::GPMF default-visible set): +1 —
/// `QuickTime_gopro_gpmf.mov`, a synthetic `moov/udta/GPMF` exercising a broad
/// slice of the ~95 newly-emitted GoPro tags (sensor-stream `Binary`
/// placeholders, hash/regex/suffix PrintConvs, AddUnits, ValueConv-folded). The
/// moov/udta/GPMF path emits WITHOUT `-ee`, so it carries standard `.json` /
/// `.n.json` goldens. 345 → 346.
///
/// GoPro Codex R13 (generic complex-`?` non-numeric columns): +1 —
/// `QuickTime_gopro_scen.mov`, a synthetic `moov/udta/GPMF` whose `SCEN`
/// (SceneClassification, `TYPE=Ff`) complex record carries an embedded `F`
/// FourCC column the pre-R13 numeric-only decoder dropped. 346 → 347.
///
/// Post-rebase (lib/xmp onto the gopro-merged main, 347 ACTIVE): the XMP
/// fixtures (chronicled below) stack on top of gopro's 3. The XMP figures
/// below are relative to the pre-gopro 344 base; the XMP branch adds 49 active
/// fixtures, so the absolute live total is `347 + 49 = 396`.
///
/// Post-rebase (lib/xmp golden-migration onto main): main's 344 ACTIVE
/// fixtures PLUS the 31 ACTIVE XMP fixtures from this branch = 375. The XMP
/// chronology's running `… → 180` figure is relative to lib/xmp's older fork
/// base (952a3fe, pre-golden-v2); the absolute total against the live golden
/// directory is 375 (`344 + 31`).
///
/// XMP Codex R1 fidelity fixes: +2 — `XMP_comment_multiline.xmp` (the
/// non-dotall `s/<!--.*?-->//g` leaf comment-strip: multiline comments
/// PRESERVED, single-line stripped, on BOTH the rdf:Description and
/// `$wasComment` scalar paths) + `XMP_cdata_unclosed.xmp` (the CDATA un-escape
/// requires a COMPLETE `<![CDATA[ … ]]>` pair; an unclosed marker falls back to
/// whole-value `UnescapeXML`). 375 → 377.
///
/// 377 → 378 after Codex R2 (XMP attribute-scan recovery): added
/// `XMP_attr_junk.xmp` — a junk token (`junk`) sits between `xmlns:dc="…"` and
/// the shorthand `dc:title="Lost"` attribute. ExifTool's COMMON-branch
/// attribute regex `/(\S+?)\s*=\s*(['"])/g` (XMP.pm:3887) is UNANCHORED + `/g`,
/// so the junk is SKIPPED and `dc:title`/`dc:format` still extract; the
/// pre-fix `iter_attrs` `break`-on-malformed dropped both. Pins the unanchored
/// left-to-right recovery scan.
///
/// 381 → 383 after Codex R4: `XMP_exif_printconv.xmp` (R4-A — cross-module
/// `PrintConv => \%Image::ExifTool::Exif::{compression,
/// photometricInterpretation,lightSource}` now render the label, not the raw
/// int) + `XMP_et_qual.xmp` (R4-B — `et:desc`/`prt`/`val` qualifier
/// suppression, XMP.pm:4202, emits the `et:prt` value).
///
/// 383 → 385 after Codex R5 (two value-divergence fixes; the broad
/// non-camera XMP table tail is deferred to issue #190): added
/// `XMP_aux_neutraldensity.xmp` (R5-1 — the Lightroom AUX tags after
/// `LensDistortInfo`, XMP.pm:2641-2658; `aux:NeutralDensityFactor="1/2"` now
/// stays verbatim instead of `ConvertRational`'d to `0.5`) +
/// `XMP_thumbnail.xmp` (R5-2 — the `xmp:Thumbnails`/`xmp:PageInfo` structs,
/// XMP.pm:1062/1068; the `xmpGImg:image` base64 field decodes to the
/// `(Binary data N bytes, …)` placeholder instead of the literal base64).
///
/// 385 → 387 after Codex R6 (two `DecodeBase64` refinements): added
/// `XMP_thumbnail_partial.xmp` (R6-A — the `xmpGImg:image` PARTIAL base64
/// `aGVsb` decodes via ExifTool's uuencode `unpack('u')` chunk math to 30
/// bytes, NOT the 3-byte standard-base64 prefix `hel`) +
/// `XMP_thumbnail_datatype.xmp` (R6-B — a `xmpGImg:image rdf:datatype="base64"`
/// is DOUBLE-decoded: the datatype `DecodeBase64` yields `"hello"`, then the
/// field `ValueConv => DecodeBase64` runs on it ⇒ 43 bytes, XMP.pm:3645-3647 +
/// 367-371).
///
/// 387 → 390 after Codex R8 (two verified findings): the F1 GPS-altitude-sign
/// projection fix adds `XMP_gps_belowsea.xmp` (`GPSAltitudeRef=1` ⇒ the domain
/// projects `-35`, the JSON tag stays the unsigned `35`) +
/// `XMP_gps_abovesea.xmp` (the `ref=0` positive control); the F2 parse-error
/// `$et->Warn` fix adds `XMP_no_closing_tag.xmp` (`XMP format error (no closing
/// tag for dc:title)` — the one error class whose oracle carries no ` [x$n]`
/// count, so it is byte-identical). The F2 CDATA/comment fixtures
/// (`XMP_missing_cdata_term.xmp`, `XMP_missing_comment_term.xmp`) are
/// deliberately golden-LESS — their oracle appends ` [x2]` (an XMP+PLIST
/// dual-process artifact the single-parse port does not reproduce) — so they
/// are covered by the `xmp_parse_error_warnings_emitted` unit test instead and
/// do NOT count as active conformance fixtures.
///
/// 390 → 391: the R8 adjacent Warn-site fix (XMP.pm:3914-3915) adds
/// `XMP_uri_fixed.xmp` — a `dc` URI missing its trailing slash trips the
/// trailing-slash patch, raising `[minor] Fixed incorrect URI for xmlns:dc`
/// while still extracting `XMP-dc:Title`. Default-reachable + single warning, so
/// byte-identical.
///
/// 391 → 392: R9 (XMP.pm:3911 one-slash repair) adds `XMP_uri_double_slash.xmp`
/// — `xmlns:exif=…/exif/1.0//` drops ONE slash to the known `exif` URI, raising
/// `[minor] Fixed incorrect URI for xmlns:exif` + extracting `XMP-exif:GPS*`.
///
/// 392 → 393: R10 (single-item `List` domain projection) adds `XMP_iso_seq.xmp`
/// — a one-item `exif:ISOSpeedRatings` `rdf:Seq`; the JSON stays the faithful
/// `XMP-exif:ISO: [100]` (ExifTool keeps the list) while `domain_numeric` now
/// descends the single-element list so `capture.iso() == Some(100)`.
/// (Absolute live total against the gopro-merged base: `347 + 49 = 396`.)
///
/// 396 → 402: the xtask-generated full XMP table (Phase-1 Task 7) adds 6
/// representative new-tag fixtures exercising namespaces / tags the hand XMP
/// table did not cover (`XMP_gen_crs` camera-raw-settings + a generated
/// value-MAP label, `XMP_gen_lr` Lightroom, `XMP_gen_xmpmm` media-management,
/// `XMP_gen_covered_extra` exif/exifEX fallback + Name remaps,
/// `XMP_gen_phf_map` the 2143-row phf value-map, `XMP_gen_unported` the
/// `P::Unported` faithful raw passthrough). Every PRE-EXISTING golden stays
/// byte-identical (the additive invariant); exhaustive per-tag coverage of all
/// ~4262 generated tags is a tracked follow-up.
///
/// 403 → 405: the `--kind exif` table-codegen Step B turns on the binary-EXIF
/// coverage gap — `%Exif::Main` leaf tags the camera-relevant hand subset
/// dropped, now emitted via the generated shadow. Two crafted standalone-TIFF
/// fixtures pin the new tags byte-identically to bundled 13.59:
/// `Exif_gap_tags.tif` (the plain / `Binary => 1` / declarative-HASH-PrintConv
/// tags + `AmbientTemperature`'s `"$val C"`) and `Exif_composite_exposure.tif`
/// (`CompositeImageExposureTimes`' bespoke undef-decode with the int16u-count
/// carve-out at element indices 7/8). Unlike the prior additive chunks these
/// LEGITIMATELY change output where the gap tags appear — but only NEW fixtures
/// carry them, so every PRE-EXISTING golden stays byte-identical.
///
/// 405 → 407: a Codex follow-up to Step B adds two edge-case fixtures for the
/// two NEW code-valued convs. `Exif_composite_exposure_edge.tif` pins
/// `CompositeImageExposureTimes`' `RawConv`→`PrintConv` TOKEN pipeline — a
/// `2/19` rational (the `%.10g`-rounded token `0.1052631579` → `"1/9"`, not the
/// unrounded `"1/10"`) and a `0/0` rational (the word `undef`, not `NaN`).
/// `Exif_ambient_multi.tif` pins `AmbientTemperature`'s `"$val C"` over a
/// MALFORMED count>1 value (`"23.5 -5 C"`, the full space-joined value, not the
/// first element). Both additive — every PRE-EXISTING golden stays
/// byte-identical.
///
/// 407 → 408: a Codex R2 follow-up adds a WRONG-on-disk-format fixture pinning
/// that the 0x9400 `"$val C"` PrintConv is not gated on the declared format — it
/// runs on the post-`ReadValue` string. `Exif_ambient_wrongfmt.tif` (`undef`-
/// typed 0x9400 `-5.5` → `"-5.5 C"` / `-5.5`, the `Bytes` shape
/// `value_space_joined` omits). Additive — every PRE-EXISTING golden stays
/// byte-identical. (The companion WRONG-format 0xa462
/// `Exif_composite_exposure_wrongfmt.tif` was re-added at 411 → 413 once #198
/// closed; see below.)
///
/// 408 → 411: a Codex R3 follow-up adds three SINGLE-element `0xa462`
/// `CompositeImageExposureTimes` fixtures — all `undef`-typed (the real-camera
/// path) — pinning the single-element JSON TYPE (the R3 fix routes a one-token
/// decode through `emit_gated_number`, so a numeric token is a BARE NUMBER, not
/// a quoted string):
///   * `Exif_composite_exposure_single_number.tif` (`undef` 1/2 → `0.5`, a
///     bare JSON number in BOTH modes);
///   * `Exif_composite_exposure_single_undef.tif` (`undef` 0/0 → the word
///     `undef`, a quoted STRING in both modes — out of the number gate);
///   * `Exif_composite_exposure_single_fraction.tif` (`undef` 1/250 → `-j`
///     PrintExposureTime `"1/250"` a string, `-n` token `0.004` a number — the
///     PER-TOKEN, PER-MODE gating case).
/// All additive — every PRE-EXISTING golden stays byte-identical.
///
/// 411 → 413: Contract A (#198) re-adds the two WRONG-on-disk-format 0xa462
/// fixtures — now that the conv byte-walks `$val` for ANY shape via
/// `RawValue::val_bytes()` (no longer `Format`-gated):
///   * `Exif_composite_exposure_wrongfmt.tif` (`string` "ABCDEFGH" → one
///     rational64u ≈ 0.9420 → `-j` `0.9` / `-n` `0.9420322801`);
///   * `Exif_composite_exposure_wrongfmt_highbit.tif` (the R4 lossy-bytes case:
///     `string` `\x80..\x87` invalid-UTF-8 → byte-walks the ORIGINAL bytes
///     (A1's `RawValue::Text.raw`), one rational64u ≈ 0.9697 → `-j` `1` / `-n`
///     `0.9696978699`).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 414 → 415: issue #179 adds one crafted PNG raw-profile fixture pinning the
/// new ImageMagick `Raw profile type xmp` content decode (`PNG.pm:746` →
/// `ProcessProfile` → `ProcessDirectory(XMP::Main)` = `ProcessXMP`, the packet
/// routed through the ported XMP module):
///   * `PNG_rawprofile_xmp.png` (1x1 RGB + a `tEXt` `Raw profile type xmp`
///     carrying `XMP-x`/`XMP-dc`/`XMP-xmp`/`XMP-exif` tags; golden drops
///     `Composite:*` — the PNG port has no Composite subsystem).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 415 → 416: a NONCANONICAL companion fixture pinning the faithful
/// `pack('H*')` odd-nibble PAD (vs a truncating decode):
///   * `PNG_rawprofile_xmp_oddnibble.png` (same XMP payload but the hex body has
///     a dangling odd nibble; Perl `pack('H*')` pads it to a trailing `\xa0`
///     byte after the XMP packet end, declared length set to match ⇒ same XMP
///     tags, NO wrong-size warning — `PNG.pm:1169`).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 416 → 425: QuickTime SP2 (rebased onto main) adds 9 `QuickTime_sp2*`
/// fixtures exercising the `moov/udta` camera atoms + `moov/meta` Keys/ItemList
/// + meta `hdlr` walk. `QuickTime_sp2.mov` is the happy-path baseline (the
/// `©mak`/`©mod`/`©swr`/`©nam`/`©day`/`©xyz`/`©cmt` `udta` atoms, the
/// `make`/`model`/`software`/`creationdate`/`location.ISO6709` Keys, and the
/// `moov/meta` HandlerType); `_badgps` (non-coordinate `©xyz` → faithful
/// `ConvertISO6709` pass-through), `_iso6709long` (long-fractional decimal ISO
/// 6709 → `($n+0)` f64 num­ification), `_infgps` (non-finite `inf inf -inf` →
/// titlecase `Inf`/`NaN` DMS) cover the GPS-string convs; `_ilst_before_keys`
/// (`ilst` ahead of `keys` ⇒ ZERO `Keys:*`, single-pass `ProcessKeys`),
/// `_macroman` (lang-0 MacRoman `©nam` → `Café Clip`), `_meta_handlerclass`
/// (`moov/meta/hdlr` ComponentType `mhlr` → `HandlerClass`), `_udta_camid` (the
/// non-`©` camera-identity sweep + duplicate-tag `Avoid` priority), and
/// `_android` (`com.android.*` full-key Keys fallback) cover the verified Codex
/// `moov/meta` findings. Every PRE-EXISTING golden stays byte-identical (only
/// the GoPro `moov/udta` fixtures carry a direct `moov/udta`, holding only
/// `GPMF` — no `©`-atom/Keys — so SP2 emits nothing there).
///
/// 425 → 427: QuickTime SP2 Part-2 (the conv-less camera-atom codegen +
/// hand-ported code-valued atoms) adds 2 fixtures. `QuickTime_sp2_gopro.mov`
/// exercises the `udta` conv-less map (`GoPr`/`LENS`/`FOV\0`/`©mal`/`©gpt`/
/// `©gyw`/`©grl`) + the code-valued `CAME`/`MUID` (`unpack("H*")` hex);
/// `QuickTime_sp2_keys_direction.mov` exercises the Keys conv-less map
/// (`direction.facing`/`direction.motion`) + the code-valued
/// `com.android.capture.fps` (float `data` atom) / `samsung.android.utc_offset`.
///
/// 427 → 428: QuickTime SP2 Part-3 trailing-empty-atom fix adds
/// `QuickTime_sp2_trailing_empty.mov` — a `moov/udta` holding a valid `©mak`
/// (`Make`) FOLLOWED BY a BARE size-8 (header-only, zero-body) `CAME` atom.
/// ExifTool's `ProcessMOV` `last if $dataPos >= $dirEnd` (QuickTime.pm:10597,
/// "ignores last value if 0 bytes") fires on the `©mak` advance, so the
/// trailing 0-byte `CAME` is NEVER read ⇒ the golden carries `UserData:Make`
/// but NO `UserData:SerialNumberHash`. Pins `walk_atoms`' valid-bare-trailing
/// skip (verified vs bundled 13.59).
///
/// 428 → 432: the QuickTime SP2 conv-less data-atom / international-text decode
/// fix adds 4 crafted fixtures (built by `tools/gen_quicktime_sp2_decode_fixtures.py`,
/// goldens pinned against bundled 13.59) exercising the full `ProcessMOV` decode
/// branches the real camera fixtures never reach:
///   - `QuickTime_sp2_ilst_binary.mov` — a Keys conv-less `data` atom with a
///     BINARY flag (`0x00`, len 3 ⇒ no `QuickTimeFormat`) ⇒
///     `Keys:CameraDirection` = `(Binary data 3 bytes, ...)` (the binary
///     scalar-ref branch, QuickTime.pm:10411-10414);
///   - `QuickTime_sp2_ilst_numeric.mov` — a Keys conv-less `data` atom with a
///     NUMERIC flag (`0x16` int16u, len 2) ⇒ `Keys:CameraDirection` = `300` (a
///     JSON number via `QuickTimeFormat`, QuickTime.pm:10402-10409);
///   - `QuickTime_sp2_itext_empty_first.mov` — a `©nam` (`Title`) whose EMPTY
///     first international-text entry is followed by a valid one ⇒ the empty
///     entry is skipped and `UserData:Title` = `Hi` (the `next if not $len`
///     continuation, QuickTime.pm:10483);
///   - `QuickTime_sp2_itext_empty_only.mov` — a `©nam` whose ONLY entry is empty
///     ⇒ NO `UserData:Title` (no `udta` tag at all).
///
/// 432 → 436: the conv-less `0x17`/`0x18` float/double branch is NOT length-gated
/// (`QuickTimeFormat` returns the format from the flag alone), so `ReadValue` with
/// an undef count (ExifTool.pm:6296-6331) reads `int(len/elem)` values. 4 crafted
/// fixtures pin every shape against bundled 13.59:
///   - `QuickTime_sp2_ilst_float_short.mov` — flag `0x17`, 2-byte payload (< one
///     float) ⇒ `ReadValue` `return ''` ⇒ `Keys:CameraDirection` = `""` (an empty
///     string, NOT the binary placeholder, NOT dropped);
///   - `QuickTime_sp2_ilst_float_single.mov` — flag `0x17`, one float `1.5` ⇒
///     `Keys:CameraDirection` = `1.5` (a single JSON number);
///   - `QuickTime_sp2_ilst_float_multi.mov` — flag `0x17`, two floats `1.5 2.5` ⇒
///     `Keys:CameraDirection` = `"1.5 2.5"` (the space-joined string);
///   - `QuickTime_sp2_ilst_double_multi.mov` — flag `0x18`, two doubles ⇒
///     `Keys:CameraDirection` = `"1.5 2.5"`.
///
/// 436 → 440: the QuickTime SP2 conv-less-Keys faithfulness refactor routes EVERY
/// conv-less identity key (`Make`/`Model`/`Software`/`Android*`) through the SAME
/// `data`-atom cascade as `direction.facing` (QuickTime.pm:10387-10416), so a
/// non-default format flag on them no longer drops/truncates (the prior per-key
/// typed paths handled only one flavor). 4 crafted fixtures pin the rerouted
/// atoms on the OLD-dropped flavors, each against bundled 13.59:
///   - `QuickTime_sp2_keys_make_numeric.mov` — `com.apple.quicktime.make` with a
///     NUMERIC flag (`0x16` int16u, len 2) ⇒ `Keys:Make` = `300` (a JSON number;
///     the OLD typed-string Make path dropped a non-string flag);
///   - `QuickTime_sp2_keys_fps_string.mov` — `com.android.capture.fps` with a
///     UTF-8 STRING flag (`0x01`, `"29.97"`) ⇒ `Keys:AndroidCaptureFPS` = the
///     string `29.97` (the OLD typed-float path dropped a string flag);
///   - `QuickTime_sp2_keys_fps_short.mov` — `com.android.capture.fps` flag `0x17`,
///     2-byte payload (< one float) ⇒ `Keys:AndroidCaptureFPS` = `""` (an empty
///     string, NOT dropped);
///   - `QuickTime_sp2_keys_fps_multi.mov` — `com.android.capture.fps` flag `0x17`,
///     two floats ⇒ `Keys:AndroidCaptureFPS` = `"1.5 2.5"` (space-joined; the OLD
///     typed-float path read only the first element).
///
/// 440 → 444: the ValueConv-BEARING Keys atoms (`creationdate` ⇒ `ConvertXMPDate`,
/// `location.ISO6709` ⇒ `ConvertISO6709`) also receive the pre-ValueConv value for
/// ANY flag (string → decoded, numeric → number, else → raw bytes — NOT the binary
/// placeholder, which needs no ValueConv), and the ValueConv passes a non-date /
/// non-ISO6709 value through, so they ALWAYS emit. 4 crafted fixtures pin the
/// flavors the OLD `ilst_data_string`-only arms DROPPED, each vs bundled 13.59:
///   - `QuickTime_sp2_keys_cdate_numeric.mov` — `creationdate` NUMERIC flag (`0x16`
///     300) ⇒ `Keys:CreationDate` = the bare number `300` (date conv passthrough);
///   - `QuickTime_sp2_keys_cdate_binary.mov` — `creationdate` BINARY flag (`0x00`)
///     with non-date raw bytes ⇒ `Keys:CreationDate` = the raw string;
///   - `QuickTime_sp2_keys_loc_numeric.mov` — `location.ISO6709` NUMERIC flag
///     (`0x16` 300) ⇒ `Keys:GPSCoordinates` = `"300 deg 0' 0.00\" N, "`;
///   - `QuickTime_sp2_keys_loc_binary.mov` — `location.ISO6709` BINARY flag
///     (`0x00`) with raw ISO6709 bytes ⇒ parsed `Keys:GPSCoordinates` coordinates.
///
/// 444 → 447: the no-`ee` faithfulness path (Task 10) adds `.json`/`.n.json`
/// goldens for the QuickTime timed-metadata fixtures. Three enter the active set
/// — `QuickTime_moov_gps.mov`, `QuickTime_gps_kenwood.mov`,
/// `QuickTime_frea_rexing17b.mov` — whose moov-`gps `-box / `GPS `-Kenwood /
/// freeGPS-scan sources are fully `-ee`-gated (no no-`ee` warning, no no-`ee`
/// GPS) and which exifast already matches byte-for-byte. Two timed fixtures
/// (`QuickTime_mebx_gps.mov`, `QuickTime_camm.mov` — `MetaFormat` gap) stay
/// accept-deferred in [`NOT_ACTIVE`].
///
/// 447 → 448: Task 10b adds the per-sample [`GpsOrigin`] marker, so
/// `QuickTime_gps0.mov` becomes ACTIVE — at no-`ee` it now emits the FIRST
/// top-level-`gps0`-box fix + the document `ExifTool:Warning` byte-exactly (the
/// `-ee`-only sources stay gated), matching its `.json`/`.n.json` goldens.
///
/// 448 → 449: the `gsen` accelerometer-only fix. `Process_gsen`/`Process_3gf`
/// open a `Doc<N>` + `HandleTag` `Accelerometer`/`TimeCode` per record with NO
/// coordinate pair, so the shared emitter now gates on `has_emittable_data`
/// (not `has_coordinates`); `QuickTime_gsen.mov` becomes ACTIVE — at no-`ee` it
/// emits the FIRST `gsen` record's `QuickTime:Accelerometer` + the document
/// `ExifTool:Warning` byte-exactly, matching its `.json`/`.n.json` goldens. The
/// GPS sources are unaffected (`has_emittable_data == has_coordinates`).
///
/// 449 → 481: R13 `Track<N>:MetaFormat` (the `stsd` 4cc) — the SOLE remaining
/// no-`ee` `.json`/`.n.json` gap for the whole `camm`/`mebx`/Sony-`rtmd`
/// timed-metadata subsystem. With it emitted at the structural trak-parse layer,
/// the 31 previously-deferred timed fixtures (5 `mebx`, 13 `camm`, 13 Sony
/// `rtmd`) become ACTIVE, PLUS the new degenerate-WhiteBalance/DateTime
/// `QuickTime_sony_rtmd_wbdt.mov` (+1) = +32 net (449 + 32 = 481), plus
/// `QuickTime_sony_rtmd_multistsd.mov` + `QuickTime_sony_rtmd_multistsd8.mov`
/// (+2, the multi-entry-stsd last-wins fixtures — 16-byte and undersized-8-byte
/// last entries, both decoded as camm) = 483. `QuickTime_sony_rtmd_badutf8.mov`
/// (+1, the invalid-UTF8 string fixture — `decode_string` routes
/// malformed pre-NUL bytes through the engine's faithful `fix_utf8`, one ASCII
/// `?` per bad byte, so the tag is PRESENT not dropped) = 484. Every one is
/// byte-exact end-to-end with NO exclusion.
///
/// 484 → 485: the Canon CTMD timed-metadata fixture
/// `QuickTime_canon_ctmd.mov` (T3+T4). Like the Sony `rtmd` fixtures it is a
/// `meta`-handler `CTMD` trak whose per-sample emission is fully `-ee`-gated;
/// at no-`ee` it emits the structural `Track1:MetaFormat` (`CTMD`) + the
/// document `ExifTool:Warning` byte-exactly, matching its `.json`/`.n.json`
/// goldens.
///
/// 485 → 490: the five Canon CTMD fixtures —
/// `QuickTime_canon_ctmd_rational.mov` (rational32u `-n` %.7g precision),
/// `QuickTime_canon_ctmd_warn_{short,trunc,residue}.mov` (the three ProcessCTMD
/// `Doc<N>:Track<N>:Warning`s) and `QuickTime_canon_ctmd_shortts.mov` (the
/// short-`TimeStamp` partial unpack + RawConv warnings). All are `-ee`-gated
/// `CTMD` traks, so at no-`ee` each emits only the structural `MetaFormat` + the
/// document `ExifTool:Warning`, byte-exact vs its `.json`/`.n.json` goldens.
///
/// 490 → 491: the Canon CTMD `ExifInfo7/8/9` re-dispatch fixture
/// `QuickTime_canon_ctmd_exifinfo.mov` (#82) — a type-7 record whose
/// `ProcessExifInfo` payload carries a `0x8769` ExifIFD (ExposureTime + ISO) and
/// a `0x927c` MakerNoteCanon (CanonFirmwareVersion) embedded TIFF, re-dispatched
/// into the Exif / Canon-MakerNote walkers. The `-ee` goldens pin the bundled
/// re-stamped groups (`EXIF:ExifIFD` / `MakerNotes:Track<N>` /
/// `File:Track<N>` ExifByteOrder); at no-`ee` it emits only the structural
/// `MetaFormat` + the document `ExifTool:Warning`, byte-exact vs its
/// `.json`/`.n.json` goldens.
///
/// 492 → 494: the bad-embedded-TIFF diagnostics fixtures
/// `QuickTime_canon_ctmd_badexif.mov` (a type-7 `0x8769` block with a valid
/// header but a bad IFD0 offset ⇒ `Track1:ExifByteOrder` + the non-minor `Bad
/// ExifIFD directory`) and `QuickTime_canon_ctmd_badmn.mov` (the `0x927c`
/// MakerNote counterpart ⇒ the MINOR `[minor] Bad MakerNotes directory`, no
/// ExifByteOrder). At no-`ee` both emit only the structural `MetaFormat` + the
/// document `ExifTool:Warning`, byte-exact vs their `.json`/`.n.json` goldens.
///
/// 494 → 496: the Canon CTMD fixtures —
/// `QuickTime_canon_ctmd_badmn_nested.mov` (a type-7 `0x927c` block whose
/// readable IFD0 carries a bogus `0x8769` pointer that `Canon::Main` never
/// follows ⇒ `CanonFirmwareVersion` decodes, NO spurious nested `Bad ExifIFD
/// directory`) and `QuickTime_canon_ctmd_partialdup.mov` (a full type-5
/// ExposureInfo followed by an 8-byte then a 4-byte type-5 ⇒ per-field
/// duplicate merge: FNumber 5.6 / ExposureTime 1/250 / ISO 12800). Both are
/// `-ee`-gated `CTMD` traks, so at no-`ee` each emits only the structural
/// `MetaFormat` + the document `ExifTool:Warning`, byte-exact vs its
/// `.json`/`.n.json` goldens.
///
/// 496 → 497: the Canon CTMD nested-sub-IFD fixture
/// `QuickTime_canon_ctmd_exifinfo_nested.mov` — a type-7 `0x8769` ExifIFD block
/// whose IFD0 carries ExposureTime + ISO AND a `0xa005` InteropOffset → a nested
/// InteropIFD (`InteropIndex` "R98"). The `0x8769` re-dispatch keeps the nested
/// sub-IFD's DirName intact (`EXIF:InteropIFD:InteropIndex`, NOT collapsed to
/// `ExifIFD`) while the top-level IFD0 tags stay `EXIF:ExifIFD`. An `-ee`-gated
/// `CTMD` trak, so at no-`ee` it emits only the structural `MetaFormat` + the
/// document `ExifTool:Warning`, byte-exact vs its `.json`/`.n.json` goldens.
///
/// 497 → 498: the Canon CTMD `0x8769`-Model-hand-off fixture
/// `QuickTime_canon_ctmd_exifinfo_model.mov` — a type-7 sample whose `0x8769`
/// ExifIFD IFD0 `Model` ("Canon EOS R5") sets `$$self{Model}`, followed by a
/// `0x927c` MakerNoteCanon whose `Canon::ShotInfo` decode keys the MODEL-
/// CONDITIONAL `CameraTemperature` on it (Doc1 "30 C"), plus a SECOND `0x927c`-only
/// sample proving `$$self{Model}` is sticky across CTMD samples (Doc2 "72 C").
/// An `-ee`-gated `CTMD` trak, so at no-`ee` it emits only the structural
/// `MetaFormat` + the document `ExifTool:Warning`, byte-exact vs its
/// `.json`/`.n.json` goldens.
///
/// 498 → 501: three Canon CTMD crafted-edge fixtures (all `-ee`-gated
/// `CTMD` traks, no-`ee` emitting only the structural `MetaFormat` + the document
/// `ExifTool:Warning`):
/// - `QuickTime_canon_ctmd_exifinfo_dupmodel.mov` (R6-1) — a `0x8769` ExifIFD
///   IFD0 with TWO `Model` tags (non-EOS then "Canon EOS R5"); the LAST (EOS)
///   wins `$$self{Model}` (Exif.pm:599 `$$self{Model} = $val` each time), so the
///   following `0x927c` `Canon::ShotInfo` `CameraTemperature` fires ("30 C").
/// - `QuickTime_canon_ctmd_badmnval.mov` (R6-2) — a `0x927c` MakerNoteCanon IFD0
///   whose `CanonFirmwareVersion` value pointer is past EOF ⇒ `[minor] Bad offset
///   for MakerNotes CanonFirmwareVersion`.
/// - `QuickTime_canon_ctmd_badmnsusp.mov` (R6-2) — the same with an in-bounds
///   directory-overlapping pointer ⇒ `[minor] Suspicious MakerNotes offset for
///   CanonFirmwareVersion`.
/// - The IFD-validation crafted edges (`+8`): a `0x927c` suspect offset
///   with a `0`-byte (`…_badmnsusp_tail0`) and `2`-byte (`…_tail2`) IFD tail (the
///   R8 case — `Suspicious MakerNotes offset` now fires alongside the emission
///   skip); the illegal `1`-/`3`-byte tails (`…_badmn_tail1`/`…_tail3` ⇒ NON-minor
///   `Illegal MakerNotes directory size`); a bad-format entry 0 (`…_badmnfmt0`)
///   and entry 1 (`…_badmnfmt1`); a count-overflow (`…_badmnsize` ⇒ `Invalid
///   size`); and the `0x8769` no-RAF `Bad offset for ExifIFD` + later-entry-survives
///   case (`…_badexifval`).
/// - The ProcessExif edges (`+5`): the `$warnCount > 10`
///   directory abort on the `0x927c` MakerNote (`…_warnmany_mn` — a later valid
///   entry is suppressed) and the `0x8769` ExifIFD (`…_warnmany_exif`); plus the
///   removal of the synthetic zero-entry / `>1024` directory rejects — a ZERO-entry
///   `1`/`3`-byte-tail MakerNote (`…_badmn_zero_tail1`/`…_tail3` ⇒ `Illegal
///   MakerNotes directory size (0 entries)`) and a `>1024`-entry in-bounds
///   directory that is fully WALKED (`…_mn_manyentries`).
///
/// 514 → 515 after the Insta360 INSV/INSP trailer faithful `-ee` emission
/// (lib/insta360): added `QuickTime_insta360.mp4` — a crafted minimal MP4
/// carrying an Insta360 file-end trailer (identity 0x101 + accelerometer
/// 0x300 + videotimestamp 0x600 + exposure 0x400 + GPS 0x700). Its standard
/// `.json` / `.n.json` goldens (no-`-ee`) carry ONLY the always-on `[minor]
/// Insta360 trailer at offset …` warning (`ProcessInsta360` runs under `-ee`,
/// so no timed records surface at no-`-ee`); the `-ee` `.ee.json` / `.ee.g3.json`
/// goldens (the Doc<N> emission) are pinned by `tests/timed_metadata_conformance.rs`.
///
/// 515 → 516 after the Insta360 bad-size trailer fix (lib/insta360): added
/// `QuickTime_insta360_badtrailer.mp4` — the valid fixture with `trailerLen`
/// overwritten to exceed the file size (QuickTimeStream.pl:3277). Its goldens
/// carry ONLY the always-on `[minor] Insta360 trailer at offset …` positional
/// warning with the WRAPPED (negative→unsigned) offset `0xfffffffffffffc18`;
/// ExifTool suppresses the "Bad Insta360 trailer size" warning via priority-0
/// first-wins, and no trailer records surface.
///
/// 517 → 518 after the Insta360 non-multiple fixed-stride fix (lib/insta360):
/// added `QuickTime_insta360_badstride.mp4` — a valid trailer with a 0x400
/// (len 17) and a 0x600 (len 9) record whose lengths are NOT multiples of their
/// fixed stride (QuickTimeStream.pl:3355-3357), alongside a valid 0x700 GPS fix
/// + 0x101 identity. Its no-`-ee` `.json`/`.n.json` goldens carry ONLY the
/// positional `[minor] Insta360 trailer at offset …` warning; the `-ee`
/// `.ee.json`/`.ee.g3.json` goldens (the GPS fix + identity + the FIRST
/// group-scoped `Insta360:Warning "Unexpected Insta360 record 0x600 length"`,
/// and NO ExposureTime/VideoTimeStamp/TimeCode rows) are pinned by
/// `tests/timed_metadata_conformance.rs`.
///
/// 518 → 519 after the Insta360 linked-list trailer-discovery fix (lib/insta360):
/// added `QuickTime_insta360_chained.mp4` — the SAME valid Insta360 trailer
/// followed by an (empty) LigoGPS trailer (`&&&&` + a BE u32 length), so the
/// Insta360 trailer is NOT the final block. ExifTool's `IdentifyTrailers`
/// (QuickTime.pm:9897-9926) walks the trailers BACKWARD from EOF, steps past the
/// LigoGPS block, and STILL finds + fully decodes the Insta360 trailer. exifast
/// does not extract LigoGPS, so the output is byte-IDENTICAL to the standalone
/// `QuickTime_insta360.mp4`: its no-`-ee` `.json`/`.n.json` goldens carry the
/// full Insta360 identity + the positional `[minor] Insta360 trailer at offset
/// 0x8c (442 bytes)` warning; the `-ee` `.ee.*` goldens (the full GPS/exposure/
/// videotime/accel rows + identity) are pinned by
/// `tests/timed_metadata_conformance.rs`.
///
/// 519 → 520 after the Insta360 atom-spans-trailer fix (lib/insta360): added
/// `QuickTime_insta360_atomspan.mp4` — a `moov` whose DECLARED size spans into
/// the Insta360 trailer (but stays within the file). ExifTool walks top-level
/// atoms by declared size (QuickTime.pm:10597-10602): the over-large moov is
/// read in full, its buffer's trailing trailer bytes parse as a contained
/// `SE12` atom whose huge size overruns ⇒ `Truncated 'SE12' data at offset
/// 0x8c`; after the moov the cursor is past the trailer start, so the trailer
/// is SKIPPED (:10656) and NO Insta360 metadata is extracted. Its `.json`/
/// `.n.json` goldens carry exactly that warning + the mvhd-derived QuickTime
/// tags + no Insta360 tags.
///
/// 520 → 521 after the Insta360 short-0x300 fix (lib/insta360, R8): added
/// `QuickTime_insta360_short300.mp4` — a 0x300 accelerometer record with a
/// 10-byte body (a multiple of NEITHER 20 nor 56) followed by a 0x700 GPS fix +
/// 0x101 identity. The QuickTimeStream.pl:3340 else-branch stride probe is
/// `$raf->Read($buff, 20)` against the FILE (not the record body), so with
/// records after the 0x300 the probe reads past the short body, succeeds, and
/// the 10-byte record's non-multiple length raises `Unexpected Insta360 record
/// 0x300 length` (NOT a silent skip). Its `.json`/`.n.json` goldens carry only
/// the positional `[minor] Insta360 trailer …` warning + the mvhd-derived
/// QuickTime tags; the `-ee` `.ee.*` goldens (the GPS fix + identity + that
/// warning) are pinned by `tests/timed_metadata_conformance.rs`.
/// 521 → 525 after the recent real-fixture conformance merges added paired
/// `.json`+`.n.json` goldens without bumping this count: `Pentax.jpg` (#264),
/// `Pentax.avi` (#265), `DJIPhantom4.jpg` (#272) + one prior. Each new active
/// fixture must bump this constant (the per-PR convention above).
/// 525 → 530 after the #266 real-device-fixture batch merged four conformance
/// PRs, each adding paired `.json`+`.n.json` goldens for ALL-ACTIVE fixtures
/// (each routes through the golden-migrated `Taggable` engine, so the
/// typed-serde path equals the writer path byte-for-byte): `SamsungNX500.srw`
/// (#276, +1); the three SP4 brand-detection fixtures `AVIF_sample.avif`,
/// `HEIF_C001_msf1.heic`, `ISOBMFF_iso5_brand.mp4` (#151/#277, +3); and
/// `QuickTime_gopro_gpmf.mp4` (#127/#278, +1). (The sequential squash-merges of
/// these PRs landed a stale 528 — only the brand +3 — silently dropping
/// Samsung's and GoPro's +1 each; corrected to 530 here.)
/// 530 → 531 after `DJI_Matrice30T.jpg` (#114) activated — the JFIF/MPF/DJI
/// thermal port (`src/exif/jpeg_app.rs`) made it byte-exact, so it moves out of
/// [`NOT_ACTIVE`] into the active set.
/// 531 → 532 after `QuickTime_gopro_hero8_gpmf.mp4` activated — QuickTime
/// container phase 7 emits the last two no-`ee` residual `stts`-derived frame
/// rates (`Track1:VideoFrameRate`, `Track3:PlaybackFrameRate`), making the
/// no-`ee` `.json`/`.n.json` byte-exact, so it moves out of [`NOT_ACTIVE`].
/// 532 → 533 after `RIFF.webp` activated — the WEBP container chunk port
/// (`src/formats/riff.rs` VP8X/VP8/VP8L/ALPH + the embedded EXIF/XMP seam, #153/
/// #160) emits the 1x1 Extended-WEBP dimensions/flags, the embedded IFD0 EXIF
/// (via the shared `ProcessTIFF` parser), and the XMP-x/XMP-dc tags
/// byte-identically, so it enters the active set.
/// 533 → 536 after the three malformed-WEBP metadata fixtures
/// (`RIFF_webp_improper_exif.webp`, `RIFF_webp_incorrect_xmp.webp`,
/// `RIFF_webp_multi_meta.webp`, #153 Codex R1) activated — they pin the
/// byte-exact `[minor]` `Improper EXIF header` / `Incorrect XMP tag ID`
/// warnings and the repeated-chunk ordered-replay tag retention.
/// 536 → 537 after `MPEG2_TS_pruveeo_d90.ts` (#138/#129) activated — the M2TS
/// LIGOGPSINFO dashcam timed-GPS port landed (`src/formats/m2ts.rs`), whose
/// no-`ee` `.json`/`.n.json` (M2TS/H264, Composite-excluded) are byte-exact.
/// 537 → 538 after `M2TS_h264_mdpm.mts` (#304) activated — the crafted 2-frame
/// AVCHD H.264 SEI/MDPM fixture (mode-aware per-frame `-ee` MDPM, the AVCHD
/// timed GPS / DateTimeOriginal). Its no-`ee` `.json`/`.n.json` carry only the
/// FIRST frame's MDPM (the `GotNAL06` latch suppresses later SEI at no-`ee`),
/// byte-exact (M2TS/H264/GPS, Composite-excluded).
/// 538 → 539 after `QuickTime_stsd_fixed_field_bleed.mov` (#302) activated — the
/// crafted 3-entry `vide` `stsd` whose non-last entry's `BitDepth` bleeds into
/// the next entry's bytes (`Track1:BitDepth 48879`), pinning the faithful
/// whole-box ProcessHybrid fixed-field read. Its `.json`/`.n.json`
/// (QuickTime, `System:*`/`Composite:*` excluded) are byte-exact.
/// 539 → 540 after `CR2_imagesize.cr2` (#133 Finding 2) activated — the crafted
/// CR2 (TIFF-base Canon RAW) whose IFD0 `ImageWidth` differs from
/// `ExifImageWidth`. exifast DEFERS all composites for the CR2/IIQ/EIP/Canon-1D-
/// RAW subtypes (the `Composite:ImageSize` `TIFF_TYPE` branch is unavailable to
/// the post-pass), so its `.json`/`.n.json` (`System:*`/`Composite:*` excluded)
/// are byte-exact with NO Composite.
///
/// 540 → 541 after #133 PR 5 (full video Composite activation): the timed
/// fixture `QuickTime_gps0_oor0.mov` gained the `.n.json` it was missing (every
/// other gps0/camm/sony_rtmd timed fixture already had one), so it now pairs
/// `.json` + `.n.json` and enters the active set like its siblings — byte-exact
/// (its `Composite:GPSPosition` is the unported timed-GPS deferral, excluded at
/// regen, so the typed-serde path matches the writer + golden).
/// 541 → 543 after #100 (FMAS / Wolfbox `gpmd` dashcam GPS fixtures): the two
/// crafted `gpmd`-MetaFormat fixtures `QuickTime_fmas_n2s.mov` (Vantrue N2S) and
/// `QuickTime_wolfbox_redtiger_f9.mov` (Redtiger F9 4K) pair `.json` + `.n.json`
/// and are FULLY byte-exact at no-`ee` (the only timed tags there are
/// `Track1:MetaFormat` + the `[minor]` `Track1:Warning`; the GPS is `-ee`-only,
/// pinned in `timed_metadata_conformance.rs`). `Composite:GPSPosition` is the
/// unported timed-GPS deferral, excluded at regen, so the typed-serde path
/// matches the writer + golden.
/// 543 → 544 after the #100 follow-up `QuickTime_fmas_empty_then_valid.mov`: a
/// two-sample `gpmd` stream (a matched-but-empty FMAS sample followed by a valid
/// one) pinning the per-MATCHED-sample `Doc<N>`/timing — the matched-empty sample
/// opens `Doc1` (so the valid one is `Doc2`) and `-ee -G1` keeps the FIRST
/// sample's `SampleTime "0 s"`. Pairs `.json` + `.n.json` and is FULLY byte-exact
/// at no-`ee` (only `Track1:MetaFormat` plus the `[minor]` `Track1:Warning`; the
/// GPS and the `Doc<N>` timing are `-ee`-only, pinned in
/// `timed_metadata_conformance.rs`). `Composite:GPSPosition` is the unported
/// timed-GPS deferral, excluded at regen.
/// 544 → 548 after #104/#102 (the four `Process_text` dashcam text-GPS
/// fixtures): `QuickTime_text_mini0806.mov` (Mini 0806), `_roadhawk.mov`
/// (Roadhawk), `_thinkware.mov` (Thinkware) and `_dji_telemetry.mov` (DJI
/// telemetry) — single `text`-HandlerType timed-text samples. Each pairs `.json`
/// + `.n.json` and is FULLY byte-exact at no-`ee` (the only timed tags there are
/// the structural `Track1:HandlerType`/`OtherFormat` + the `[minor]`
/// `Track1:Warning`; the decoded GPS + text extras are `-ee`-only, pinned in
/// `timed_metadata_conformance.rs`). `Composite:GPSPosition` is the unported
/// timed-GPS deferral, excluded at regen.
/// 548 → 549 after the #104 R2 structural fix `QuickTime_text_empty_then_valid.mov`:
/// a two-sample `text` stream — a ZERO-LENGTH length-prefixed sample (the `next if
/// $size == 2` shape) followed by a valid Mini-0806 sample — pinning the
/// per-text-sample-timing class close. `FoundSomething` opens `Doc1` for the empty
/// sample BEFORE the `next` / `Process_text`, so the valid sample is `Doc2` and
/// `-ee -G1` keeps the FIRST (empty) sample's `SampleTime "0 s"`. Pairs `.json` +
/// `.n.json` and is FULLY byte-exact at no-`ee` (only `Track1:HandlerType`/
/// `OtherFormat` + the `[minor]` `Track1:Warning`; the `Doc<N>` timing is `-ee`-only,
/// pinned in `timed_metadata_conformance.rs`). `Composite:GPSPosition` is the
/// unported timed-GPS deferral, excluded at regen.
/// 549 → 550 after the #240 BigTIFF SubIFD-recursion fixture `BigTIFF_subifd.btf`:
/// a CRAFTED BigTIFF (version 43, 8-byte offsets) whose IFD0 carries an ExifOffset
/// (→ ExifIFD: ExposureTime/FNumber/ISO/ExifVersion) AND a GPSInfo SubIFD pointer,
/// pinning `ProcessBigIFD`'s `$$tagInfo{SubIFD}` recursion — the child IFDs reuse
/// the inherited `%Exif::Main` and group under the POINTER tag (`ExifOffset:ISO`;
/// the GPSInfo child's 0x0001/0x0002 → `GPSInfo:InteropIndex`/`InteropVersion`, NOT
/// `%GPS::Main`). Pairs `.json` + `.n.json`, byte-exact in both modes.
/// 550 → 551 after the #240 round-2 fixture `BigTIFF_subifd_multi.btf`: a CRAFTED
/// BigTIFF pinning that `ProcessBigIFD` recurses EVERY SubIFD offset (`split ' ',
/// $val`, `BigTIFF.pm:184`), not just the first — an ExifOffset `LONG8` count=2
/// pointer → `ExifOffset:ISO` (400) + the `$i`-suffixed `ExifOffset1:ISO` (800) —
/// AND an ASCII-numeric GPSInfo pointer (`split` numifies the `string` "180") →
/// `GPSInfo:InteropIndex` reusing `%Exif::Main`. ISO-only children ⇒ no Composite.
/// Pairs `.json` + `.n.json`, byte-exact in both modes.
/// 551 → 552 after the #240 round-2 follow-up fixture `BigTIFF_subifd_exp.btf`
/// (the Codex [medium] finding): a CRAFTED BigTIFF whose GPSInfo (0x8825) SubIFD
/// pointer is the ASCII STRING `"1e3"`, the GPS child IFD placed at byte 1000.
/// Pins `ProcessBigIFD`'s FULL Perl numeric coercion of the `split ' ', $val`
/// offset token (`0 + "1e3" == 1000`, NOT the digit-prefix-only 1) — ground-
/// truthed: bundled recurses the child at byte 1000 → `GPSInfo:InteropIndex`
/// ("Unknown (N)" / "N") + `InteropVersion` ("37 48 30") reusing `%Exif::Main`.
/// GPS-only child ⇒ no Composite. Pairs `.json` + `.n.json`, byte-exact in both.
/// 552 → 554 after the #328 Kingslim per-sample-timing fixtures
/// `QuickTime_gpmd_kingslim_pure.mov` + `QuickTime_gpmd_kingslim_fmas_mixed.mov`
/// (the `gpmd` Kingslim timing-`Doc<N>`-ahead-of-LigoGPS port + the
/// `SET_GROUP1`-cleared `Track<N>`→`QuickTime` group flip). Both are `gpmd`-handler
/// `.mov`s that are fully `-ee`-gated, so their no-`ee` `.json`/`.n.json` carry
/// only the structural moov/track scalars + `Track1:MetaFormat "gpmd"` + the
/// `[minor]` ExtractEmbedded `Track1:Warning` (byte-exact); the `-ee` Doc sequence
/// is pinned in `tests/timed_metadata_conformance.rs`.
/// 554 → 556 after the two #328 round-2 [medium] fixtures
/// `QuickTime_gpmd_kingslim_fmas_valid.mov` (Finding 1) +
/// `QuickTime_gpmd_kingslim_noligo_fmas.mov` (Finding 2). Finding 1's fixture is a
/// Kingslim (LigoGPS) sample followed by a VALID FMAS sample that decodes a REAL
/// GPS fix — proving the `SET_GROUP1`-cleared `Track<N>`→`QuickTime` flip reaches
/// a DECODED fix (the FMAS sample's GPS + timing ride `Doc3:QuickTime`, not
/// `Track1`), not only the matched-empty markers. Finding 2's fixture is a
/// Kingslim Condition-match whose `ProcessLigoGPS` decodes NOTHING (the
/// `LIGOGPSINFO` block is present but the record is unparseable), so the
/// `delete $$et{SET_GROUP1}` never runs: the FOLLOWING valid FMAS sample is
/// `Doc2:Track1` (no LigoGPS doc consumed, NO QuickTime flip), proving the flag
/// flips only AFTER LigoGPS actually emitted. Both are fully `-ee`-gated
/// `gpmd`-handler `.mov`s (no-`ee` `.json`/`.n.json` = structural scalars + the
/// `[minor]` EEWarn, byte-exact); the `-ee` group behavior is pinned in
/// `tests/timed_metadata_conformance.rs`.
/// 557 → 558 after `SamsungNX1.srw` (#210) activated — the REAL Samsung NX1 raw
/// whose goldens are regenerated conventioned (System tags dropped) via the
/// `gen_golden.sh SamsungNX1.srw` arm (the SAME SubIFD/SubIFD1 + MakerNote-
/// Composite exclusions as the NX500 arm). exifast emits its full Type2 surface
/// — all 45 `Samsung:*` leaves (incl. the 16 decrypted #242 Crypt rows), the
/// 8-tag PreviewIFD, and the 8 ported EXIF+lens Composites — byte-exact vs
/// bundled in BOTH `.json` and `.n.json`. The Type2 port (#210 leaf + #242
/// PreviewIFD/Crypt) needed NO gap-closing: the NX1 shares the identical 45-tag
/// table with the already-active NX500 (different camera/lens/firmware values,
/// e.g. `LensType` = "Samsung NX 16-50mm F2-2.8 S ED OIS", a populated
/// `CameraTemperature` = "0.7513126037 C").
/// 558 → 560 after the #331-P2 PreviewImage fixtures (#352/#353):
/// `CR2_preview_image.cr2` (IFD0 0x0111/0x0117 → `IFD0:PreviewImage` for a CR2)
/// and `ARW_preview_image.arw` (IFD0 0x0201/0x0202 → `IFD0:PreviewImage` for an
/// ARW) both activate byte-exact — the IFD0:PreviewImage proof of the `DataTag`
/// P2 wiring. The set's `DNG_preview_image.dng` is NOT_ACTIVE (its SubIFD walk is
/// deferred to #352), so the bump is +2 (not +3).
///
/// 560 → 562 after `MP4_viofo_a119_gps.mp4` (#138) + `QuickTime_rove_r2_4k.MP4`
/// (#100) activated — the #348 dual-`hdlr` per-track Handler dedup (the FINAL
/// `trak`'s `minf/hdlr` data handler owns the bare `Track<N>:Handler*` key,
/// every earlier `trak` keeps its `mdia/hdlr` media handler; the MP4→M4A
/// FileType decision keys on the file-global `HasHandler` set) makes both dashcam
/// MP4s' no-`ee` `.json`/`.n.json` byte-exact; rove also needed the `©fmt`/`©inf`
/// (Format/Information) conv-less `udta` atoms (NOVATEK chipset).
///
/// 562 → 563 after `QuickTime_gopro_hero6_gpmf.mp4` (#211) activated — its raw
/// 13.55 goldens are regenerated conventioned (`-G1 -x System:all`, the
/// `Composite:GPS*` drops) and exifast's `gpmd`/`fdsc` GPMF emission (the typed
/// `GoProTag` surface + generic-tag table) matches the full real timed block
/// byte-exact, the same emission path the active hero8 fixture already exercises.
///
/// 563 → 564 after `MP4_parrot_anafi.mp4` (#122) activated — its raw 13.55
/// goldens are regenerated conventioned (the `tools/gen_golden.sh` arm dropping
/// the unported XMP/ItemList(+`HandlerVendorID`)/Keys/AudioKeys/
/// `UserData:LocationInformation`/`Composite:GPS*` subsystems by name) and
/// exifast's QuickTime/Track structure + `udta` Parrot `Make`/`Model` + ported
/// ImageSize/Megapixels/AvgBitrate/Rotation Composites match the residual
/// byte-exact. The `mett` metadata track surfaces no per-sample timed telemetry
/// in bundled 13.59 (`-ee` == base), so there is no `.ee.*` golden.
///
/// 564 → 565 after `MP4_audiokeys_mute.mp4` (#361 R4) activated — a crafted
/// audio-only MP4 pinning the `%QuickTime::AudioKeys` resolution (`Mute`'s int8u
/// `Off`/`On` PrintConv + the unknown-key DERIVE path for `Make`/`Creationdate`/
/// `AcmeTotallyBogusZzz`); byte-exact at both `-j` and `-n` (only `System:all`
/// excluded — the ported `Composite:AvgBitrate` is verified). (`MP4_audiokeys_mute.mp4`
/// is later EXTENDED in place by #361 R7 with two raw-`0xA9` ItemList ids — no
/// new fixture, the count is unchanged by that extension.)
///
/// 565 → 566 after `MP4_movie_keys.mov` (#361 R7) activated — a crafted
/// movie-level `moov/meta`(`mdta`) `keys` fixture pinning the GENERIC
/// `%QuickTime::Keys` ProcessKeys order: the unknown-key DERIVE
/// (`Keys:AcmeTotallyBogusZzz` — the movie-level [high] fix) plus the raw-`0xA9`
/// cross-table (`Keys:ContentCreateDate` from `\xa9day`, `Keys:GPSCoordinates`
/// from `\xa9xyz`) and `Keys:Make` (`manu` UserData). Byte-exact at `-j`/`-n`;
/// the 3 `Composite:GPS*` are the unported `%QuickTime::Composite` deferral.
///
/// 566 → 567 after `MP4_blackvue_dr770x.mp4` (#362) activated — the REAL
/// BlackVue DR770X dashcam (PittaSoft): the top-level `free`/`%QuickTime::
/// Pittasoft` SubDirectory (Copyright/StartTime/OriginalFileName + the
/// PreviewImage/GPSLog binary placeholders + the no-`ee` first-record
/// TimeCode/Accelerometer from `3gf `) and the audio `chan` `%QuickTime::
/// ChannelLayout` (LayoutFlags/AudioChannelTypes/NumChannelDescriptions),
/// byte-exact at `-j`/`-n` with the no-`ee` `EEWarn`. The ported Composites are
/// kept; `System:all` is the sole exclusion.
///
/// 567 → 573 after ALL FIVE additional Pentax body fixtures (#311/#318) activated
/// — `JPEG_pentax_{k1,k3,k5_ii,kp,k70}.jpg`. The #379 body-agnostic Pentax
/// sub-tables decode them byte-exact vs bundled 13.59 (the full set proven on
/// `JPEG_pentax_ks2.jpg`), across the per-body MakerNote variant branches and both
/// byte orders (k1/k3/kp/k70 little-endian; k5_ii BIG-endian). Each drops only the
/// KS-2 cross-cutting deferrals (minus the body-absent `Composite:DateTimeCreated`)
/// PLUS unimplemented `Pentax:*` leaves — NO core-EXIF values. The FIFTH body,
/// `JPEG_pentax_k70.jpg`, activated on #380 (572 → 573): its non-clean `1/60`
/// `rational64u` ExposureTime now rounds via `RoundFloat($num/$den, 10)` (exactly
/// as ExifTool's `GetRational64u` reader), so the CORE `ExifIFD:ExposureTime` /
/// `Composite:ShutterSpeed` / `Composite:LightValue` match bundled byte-exact.
///
/// 573 → 574 after `TIFF_jpgfromraw.tif` (#331-P2 / #352): the crafted
/// SubIFD2:JpgFromRaw verifier. A minimal little-endian TIFF whose IFD0 0x014a
/// SubIFD pointer carries THREE offsets (descended as `SubIFD`/`SubIFD1`/
/// `SubIFD2` via the new classic-TIFF multi-offset SubIFD walk); SubIFD2's
/// `SubfileType=1` + `Compression=7` + 0x0111/0x0117 resolve to
/// `JpgFromRawStart`/`JpgFromRawLength` and drive the synthetic
/// `SubIFD2:JpgFromRaw = (Binary data 4 bytes, …)` through the EXIF DataTag
/// channel (`Exif.pm:673-684`/`:769-778`), byte-exact at `-j`/`-n` vs bundled
/// 13.59. SubIFD0's plain `StripOffsets`/`StripByteCounts` (no Compression) emit
/// NO DataTag — the SubIFD-context StripOffsets path P1 could not reach. The
/// ported `Composite:ImageSize`/`Megapixels` are KEPT (TIFF is not a
/// RAW-ImageSize subtype); `System:all` is the sole exclusion.
///
/// 574 → 575 after `BigTIFF_jpegpreview.btf`: the BigTIFF counterpart of the
/// `TIFF_jpgfromraw.tif` verifier, pinning that a BigTIFF does NOT take the
/// `PreviewImage`/`JpgFromRaw` arms. A crafted little-endian BigTIFF (version 43)
/// whose IFD0 carries the SAME JPEG-preview shape (`SubfileType=1` +
/// `Compression=7` + 0x0111/0x0117) keeps the DEFAULT `IFD0:StripOffsets`/
/// `IFD0:StripByteCounts` arm — `ProcessBTF` `return 1`s before
/// `$$self{TIFF_TYPE}` is set (`ExifTool.pm:8668`/`:8715`), so `TIFF_TYPE == ''`
/// and the `/^(DNG|TIFF)$/` gate is false. Byte-exact at `-j`/`-n` vs bundled
/// 13.59; no `Composite:*` (IFD0-only, no FNumber/ExposureTime).
///
/// 575 → 576 after `PNG_rawprofile_xmp_warnorder.png` (#205): a malformed `Raw
/// profile type xmp` chunk (double-UTF packet → `XMP is double UTF-encoded`)
/// positioned BEFORE a later bad `eXIf` (→ `Invalid eXIf chunk`). Pins that the
/// PNG port now drains each document `ExifTool:Warning` at its chunk-walk
/// position (the unified `PngMeta::diag_order` replay) so the EARLIER XMP
/// warning wins first-occurrence — the typed-serde path matches the writer +
/// golden (`PNG:eXIf` is the sole dropped key, the eXIf-suppression deferral).
///
/// 576 → 577 after `Exif_make_invalid_utf8.tif` (#200): a crafted big-endian
/// TIFF whose IFD0 `Make` holds INVALID UTF-8 (`A` + valid `é` + `B` + `0xFF` +
/// `C` + `0xFE` + `D`). Pins that the EXIF `string` decode applies ExifTool's
/// `FixUTF8` (each invalid byte → `?`, NOT the U+FFFD `from_utf8_lossy` would
/// emit); byte-exact at `-j`/`-n` vs bundled 13.59 (`"IFD0:Make": "AéB?C?D"`).
///
/// 577 → 579 after the #200 round-2 `ConvertExifText` fixtures
/// (`Exif_usercomment_invalid_utf8.tif` +
/// `Exif_gps_processingmethod_invalid_utf8.tif`): the R1 fix routed only the
/// TIFF `string`/`utf8` decode through `FixUTF8`, leaving the `undef`-format
/// EXIF-text path (`UserComment` 0x9286 / `GPSProcessingMethod` 0x001b, both
/// via `exif::exiftext::convert_exif_text`) on `from_utf8_lossy` → U+FFFD.
/// These crafted TIFFs pin that the `ConvertExifText` ASCII-prefix payload now
/// applies `FixUTF8` too — bundled 13.59 `"ExifIFD:UserComment": "AéB?C?D"` /
/// `"GPS:GPSProcessingMethod": "A?B?C"`, byte-exact at `-j`/`-n`.
///
/// 579 → 580 after `QuickTime_camm_2track_dupwarn.mov` (#215): two `camm` `trak`s
/// whose lone samples EACH raise `Unknown camm record type 0`, pinning ExifTool's
/// FILE-GLOBAL `WAS_WARNED` (`ExifTool.pm` `sub Warn`) — the same warning TEXT
/// across the two tracks collapses to ONE `Track1:Warning "… [x2]"` (the first
/// occurrence's group + the file-wide count), NOT one `Warning` per track. No
/// GPS/per-sample payload at the default `-j`, so `Composite:AvgBitrate` is the
/// sole synthesized Composite (KEPT); `System:all` is the sole exclusion.
///
/// 580 → 581 after `QuickTime_camm_2track_distinct_collision.mov` (#215-R1): the
/// DISTINCT-then-repeat case — Track1 raises A ("Unknown camm record type 0") and
/// B ("Truncated camm record 5"), Track2 repeats B. Pins that `WAS_WARNED` is set
/// at WARN-TIME (file-global, INDEPENDENT of the per-track `-G1` `Warning` slot):
/// B is recorded when Track1 raises it even though that track's slot already
/// holds A, so Track2's B is a repeat (no spurious `Track2:Warning`). Like the
/// dup-warn fixture, the default `-j` carries no per-sample payload, so
/// `Composite:AvgBitrate` is the sole synthesized Composite; `System:all` the
/// sole exclusion.
///
/// 581 → 583 (#201) adds two WRONG-on-disk-format `ComponentsConfiguration`
/// (0x9101) fixtures. Unlike the 0xa462/0x9400 `$val` byte-walks, 0x9101 carries
/// a `Format => 'int8u'` READ override (`Exif.pm:2298`) so ExifTool re-reads the
/// raw value bytes as `int(size/1)` int8u ELEMENTS regardless of the declared
/// format — the per-byte PrintConv sees the raw bytes one-per-element:
///   * `Exif_componentsconfig_wrongfmt.tif` (`int16u[2]` `0x0102 0x0300` →
///     on-disk bytes `01 02 03 00` → int8u re-read `1 2 3 0` → `-j`
///     "Y, Cb, Cr, -" / `-n` "1 2 3 0"; the discriminating shape a
///     `val_bytes()` walk would mis-render as "258 768");
///   * `Exif_componentsconfig_wrongfmt_err.tif` (`int8u[4]` `7 99 0 1`, codes
///     7/99 un-hashed → the `OTHER` sub's `"Err ($_)"` → `-j`
///     "Err (7), Err (99), -, Y" / `-n` "7 99 0 1").
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 583 → 585 (#201 R2) adds two SHORT 0x9101 fixtures the four-byte values above
/// do not exercise: under `-n` ExifTool emits the post-`ReadValue` raw SCALAR, so
/// a SINGLETON is a BARE JSON number (the EscapeJSON number gate) while a COUNT>1
/// value space-joins to a quoted string. (The pre-R2 `-n` arm unconditionally
/// joined + `write_str`, emitting the singleton as the STRING "1".)
///   * `Exif_componentsconfig_singleton.tif` (`int8u[1]` code `1` → `-j` "Y" /
///     `-n` `1`, a bare number — the discriminating shape);
///   * `Exif_componentsconfig_pair.tif` (`int8u[2]` codes `1 2` → `-j` "Y, Cb" /
///     `-n` "1 2", the count==2 boundary — still a space-joined quoted string).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 585 → 587 (#180 + #178-item1, PNG crafted-input hardening) adds two minimal
/// 1x1 malformed PNGs whose only variation is a decode-error edge (the default
/// well-formed PNG path is unaffected):
///   * `PNG_trailer_iccp_warn.png` — a post-`IEND` TRAILER `iCCP` chunk with a
///     corrupt zlib stream: the `Error inflating iCCP` warning is raised under
///     `$$et{SET_GROUP1} = 'Trailer'` (`PNG.pm:1484`) so it surfaces as the
///     `Trailer:Warning` TAG (#180); the trailer-entry `Trailer data after PNG
///     IEND chunk` stays the document `[minor] ExifTool:Warning`.
///   * `PNG_nested_zxif.png` — a `zxIf` whose inflated buffer is itself a
///     degenerate `\0`-typed (still "compressed") block: bundled re-enters
///     `ProcessPNG_eXIf` and inflates AGAIN ⇒ `Error inflating zxIf` (the port
///     bounded-recurses the inner inflate, #178-item1) rather than the prior
///     `Invalid zxIf chunk`.
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 587 → 588 (#180 round 2, PNG TRAILER diagnostic re-scoping) adds one minimal
/// 1x1 PNG with a post-`IEND` TRAILER `Raw profile type xmp` chunk:
///   * `PNG_trailer_xmp_warn.png` — the trailing embedded-XMP sub-Meta's `XMP is
///     double UTF-encoded` `$et->Warn` is re-scoped to the `Trailer` family-1
///     group (`PNG.pm:1484`, mirroring the Warning arm) so it does NOT leak as a
///     stray doc-level `ExifTool:Warning` (priority-0 first-wins then suppresses
///     it behind the earlier `Trailer:Warning`), while the decoded
///     `XMP-dc:Format` keeps its EXPLICIT `XMP-dc` family-1 group (NOT `Trailer`,
///     the `$grps[1] or …` short-circuit). No dropped keys (a plain golden).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 588 → 590 (#393) activates the two real-device Pentax PEF raw fixtures whose
/// `K-3 Mark III` / `*ist D` MakerNote variants are now ported byte-exact (the
/// `%BatteryInfo`/`%AFInfo` K-3III re-layouts, `%AFInfoK3III` (0x040c),
/// `%FaceInfoK3III` (0x040b), `%PixelShiftInfo` (0x0243), `%TempInfo` (0x03ff), the
/// `%LensInfo`-old (*istD) → `%LensData`, `0x003c AFPointsInFocus`, and the
/// per-body Main scalars). The conformance arms exclude only the non-MakerNote
/// container residuals (CFAPattern / the PEF IFD2 JpgFromRaw chain / IsOffset
/// binary previews), see `conformance.rs::pef_pentax_{k3_mark_iii,istd}_conformance`.
///
/// 590 → 592 (#399) adds two crafted wrong-format EXIF byte-conv fixtures, each a
/// plain golden (no dropped keys):
///   * `Exif_gps_versionid_undef.tif` — `GPSVersionID` (0x0000) as `undef[4]`
///     `02 03 00 00`. ExifTool reads the on-disk format (GPSVersionID has no
///     `Format =>` override), so the value is the NUL-stripped raw bytes
///     ("\u0002\u0003"), NOT re-read as int8u and NOT the binary placeholder.
///   * `Exif_filesource_sigma.tif` — `FileSource` (0xa300) as the literal Sigma
///     `undef[4]` `03 00 00 00`, hitting the dedicated PrintConv string key
///     `"\3\0\0\0" => 'Sigma Digital Camera'` (`Exif.pm:2820`).
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 592 → 594 (#399 follow-up, Codex [medium]) adds two crafted NUL-split-UTF-8
/// fixtures pinning ExifTool's `EscapeJSON` ORDER (NUL-delete `exiftool:3820`
/// BEFORE `FixUTF8` `exiftool:3824`) on the raw-byte render paths, each a plain
/// golden:
///   * `Exif_gps_versionid_nulsplit.tif` — `GPSVersionID` (0x0000) `undef[4]`
///     `C2 00 A9 00`: the NUL between `C2` and `A9` SPLITS a 2-byte sequence;
///     NUL-strip-THEN-FixUTF8 reassembles `C2 A9` → "©" (bundled 13.59, both
///     `-j`/`-n`), where the pre-fix FixUTF8-first order emitted "??".
///   * `Exif_filesource_nulsplit.tif` — the same `C2 00 A9 00` on the non-Sigma
///     multi-byte `FileSource` HASH-miss path → "Unknown (©)" / "©".
/// Additive — every PRE-EXISTING golden stays byte-identical.
///
/// 594 → 597 (#399 follow-up R2, Codex [medium]) adds three crafted NUL-split
/// fixtures pinning the FULL `EscapeJSON` CLASSIFY order — the value is classified
/// against the boolean/number gate AS-IS (the ORIGINAL, WITH NULs) BEFORE
/// `tr/\0//d` (`exiftool:3805-3810` precede `:3820`), so a value whose NUL strip
/// PRODUCES a number/boolean lexeme is still a QUOTED string. Each a plain golden:
///   * `Exif_gps_versionid_nulnum.tif` — `GPSVersionID` (0x0000) `undef[4]`
///     `31 00 32 00` (`"1\02\0"`): NUL-strip → `12`, but the NUL-bearing original
///     fails the number gate ⇒ quoted `"12"` (NOT bare `12`), both `-j`/`-n`.
///   * `Exif_gps_versionid_nulbool.tif` — `GPSVersionID` (0x0000) `undef[8]`
///     `74 00 72 00 75 00 65 00` (`"t\0r\0u\0e\0"`): NUL-strip → `true`, but the
///     NUL-bearing original fails the boolean gate ⇒ quoted `"true"` (NOT bare
///     `true`), both `-j`/`-n`.
///   * `Exif_filesource_nulnum.tif` — the same `31 00 32 00` on the `FileSource`
///     HASH-miss path → "Unknown (12)" / quoted "12".
/// 598 → 599 (#142, the Apple `iDOT` private PNG vendor chunk) adds
/// `PNG_idot.png` — a crafted minimal 1x1 RGB PNG whose only vendor chunk is
/// `iDOT` (`AppleDataOffsets`, `Binary => 1`, NO SubDirectory, `PNG.pm:331-342`),
/// emitting the `PNG:AppleDataOffsets` `(Binary data 28 bytes …)` placeholder
/// (plus the ported `Composite:ImageSize`/`Megapixels`).
/// 599 → 600 (#142 Codex F2, the `gdAT` gain-map chunk) adds `PNG_gdat.png` —
/// the same minimal shape with `gdAT` (`GainMapImage`, `Binary => 1`,
/// `Groups => { 2 => 'Preview' }`, NO SubDirectory, `PNG.pm:374-378`), emitting
/// the `PNG:GainMapImage` `(Binary data 20 bytes …)` placeholder. The remaining
/// four PNG private chunks (`caBX`-JUMBF / `cpIp`-FlashPix / `meTa`-XML /
/// `seAl`-SEAL) dispatch into large SubDirectory subsystems exifast lacks and
/// stay deferred. Additive — every PRE-EXISTING golden stays byte-identical.
/// 600 → 602 (#142 Codex [medium], the per-group `iDOT`/`gdAT` fix) adds
/// `PNG_idot_trailer.png` + `PNG_gdat_trailer.png` — each a minimal 1x1 RGB PNG
/// carrying the vendor chunk BOTH pre-`IEND` (→ `PNG:AppleDataOffsets` /
/// `PNG:GainMapImage`) AND as a post-`IEND` TRAILER chunk
/// (→ `Trailer:AppleDataOffsets` / `Trailer:GainMapImage`, `PNG.pm:1484`).
/// Bundled emits BOTH placeholders + the document `[minor] Trailer data after
/// PNG IEND chunk` warning; exifast now emits all of them, so a PLAIN compare
/// (no `FIXTURE_EXCLUDED_KEYS`). Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 602 → 605 (#154, the faithfully-craftable RIFF (AVI) `JUNK` variants) adds
/// `AVI_textjunk.avi` (`RIFF:TextJunk`), `AVI_pentaxjunk.avi`
/// (`MakerNotes:Pentax:Model` via `%Pentax::Junk`) + `AVI_pentaxjunk2.avi`
/// (`%Pentax::Junk2` + `Composite:Aperture`) — crafted minimal AVIs (`RIFF.pm:442-492`).
/// The Olympus/Ricoh/Lucas JUNK variants (vendor subsystems) + CasioJunk (needs a
/// real EX-S600 AVI) stay deferred. Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 605 → 606 (#141, the animated-PNG `acTL` Animation Control chunk) adds
/// `PNG_apng.png` — a minimal 1x1 RGB APNG carrying `acTL`
/// (`AnimationControl`, `PNG.pm:766-782`): `PNG:AnimationFrames` +
/// `PNG:AnimationPlays` (`0` ⇒ `"inf"` under `-j`), and the
/// `OverrideFileType("APNG", undef, "PNG")` promotion (`File:FileType` →
/// `APNG`, `MIMEType` → `image/apng`, `FileTypeExtension` → `png`/`PNG`). The
/// per-frame `fcTL`/`fdAT` chunks have no bundled table and emit nothing.
/// Additive — every PRE-EXISTING golden stays byte-identical.
/// 606 → 609 (#158, the faithfully-craftable RIFF (AVI) `strd` StreamData
/// variants) adds `AVI_strd_zora.avi` (`RIFF:VendorName` — Samsung PL90,
/// `RIFF.pm:1270`), `AVI_strd_casi.avi` (`Casio:Software` via `%Casio::AVI`,
/// `RIFF.pm:1266-1269` / `Casio.pm:2006-2015`) + `AVI_strd_unknown.avi`
/// (`RIFF:UnknownData` — the `unknown` fallback, `RIFF.pm:1271-1275`) — crafted
/// minimal AVIs whose `LIST_strl` carries a single `strd` chunk
/// (`ProcessStreamData`, `RIFF.pm:1699-1748`). The Canon `AVIF` variant
/// (headerless-IFD0 `Exif::Main` re-dispatch + `Base`/offset mechanics, needs a
/// real Canon AVIF) stays deferred. Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 609 → 611 (#158 Codex [medium], the MULTI-stream `strd` fix) adds
/// `AVI_strd_multi.avi` — a two-`LIST_strl` AVI whose `strd` chunks are
/// DIFFERENT variants (`XVND…` unknown ⇒ `RIFF:UnknownData`, then `Zora…` ⇒
/// `RIFF:VendorName`): bundled runs `ProcessStreamData` per stream so BOTH
/// leaves emit, where the old single-slot capture dropped the second — and
/// `AVI_strd_dup.avi` — two SAME-variant `Zora…` `strd` chunks rendering to the
/// same `RIFF:VendorName`, pinning the `TagMap` last-wins duplicate resolution
/// (`"ZoraSECOND"`) against bundled 13.59. Additive — every PRE-EXISTING golden
/// (incl. the three single-`strd` fixtures) stays byte-identical.
/// 611 → 612 (#115, the DJI `ae_dbg_info` bracketed-string debug MakerNote)
/// adds `DJI_ae_dbg_info.tif` — a crafted minimal TIFF whose 0x927C value is a
/// `[key:val]…` bracket run (NOT an IFD), routed by `MakerNotes.pm:93-97`
/// (`^\[ae_dbg_info:/`, `NotIFD => 1`) to `%DJI::Info` / `ProcessDJIInfo`
/// (`DJI.pm:74-95`/:960-983). Pins the named-key renames (ae_dbg_info →
/// `DJI:AEDebugInfo`, awb_dbg_info → `DJI:AWBDebugInfo`, GimbalDegree(Y,P,R) →
/// `DJI:GimbalDegree`, sensor_id → `DJI:SensorID`, …) plus the `MakeTagInfo`
/// synthesis for an unknown key (some_unknown_tag → `DJI:Some_Unknown_Tag`,
/// `ExifTool.pm:9312-9317`). `%DJI::Info` has no Conv, so `-j`/`-n` are
/// identical. Additive — every PRE-EXISTING golden stays byte-identical.
/// 612 → 613 (#123, the Parrot ARCore phone-camera `mett` subtable) adds
/// `QuickTime_parrot_arcore.mp4` — a crafted minimal Parrot `mett` track whose
/// `stsd` MetaType is `application/arcore-accel` (the ARCore branch,
/// Parrot.pm:60-83 → the `ARCoreAccel` ProcessBinaryData subtable,
/// Parrot.pm:663-693). The base (no-`ee`) golden carries the `Track1:Warning`
/// ExtractEmbedded hint + the ported `Composite:AvgBitrate`; the `-ee` goldens
/// pin `Track1:Accelerometer` (a `%.15g`-joined float triple, one collapsed
/// `-G1` value / per-`Doc<N>` at `-G3`). Additive — every PRE-EXISTING golden
/// stays byte-identical.
/// 613 → 615 (#123 follow-up, the MALFORMED ARCore `mett` warning paths) adds
/// `QuickTime_parrot_arcore_trunc.mp4` (one TRUNCATED-float sample — the partial
/// `Accelerometer` + the NON-minor `RawConv … uninitialized value` Warning, both
/// at `-ee`) and `QuickTime_parrot_arcore_overflow.mp4` (one OVERFLOW TLV — a
/// WARNING-ONLY sample emitting only the MINOR `[minor] Unexpected length for
/// application/arcore-accel record` Warning, no vector). The base (no-`ee`)
/// goldens carry the `Track1:Warning` ExtractEmbedded hint + `Composite:
/// AvgBitrate` (same shape as the well-formed fixture); the `-ee` warning truth
/// is pinned in `timed_metadata_conformance`. Additive — every PRE-EXISTING
/// golden stays byte-identical.
/// 615 → 617 (#123 follow-up, the INTRA-SAMPLE ordering class) adds
/// `QuickTime_parrot_arcore_valid_overflow.mp4` (ONE sample = a full-vector valid
/// TLV THEN an overflow TLV ⇒ `Accelerometer` BEFORE the overflow `Warning` in
/// walk order) and `QuickTime_parrot_arcore_trunc_overflow.mp4` (ONE sample = a
/// truncated TLV — RawConv Warning + partial vector — THEN an overflow TLV ⇒ the
/// RawConv `Warning`, then `Accelerometer`, with the later distinct overflow
/// `Warning` suppressed by the `(Doc1,Track1,Warning)` priority-0 first-wins).
/// The base (no-`ee`) goldens carry the `Track1:Warning` ExtractEmbedded hint +
/// `Composite:AvgBitrate`; the `-ee` walk-order truth is pinned in
/// `timed_metadata_conformance`. Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 617 → 618 (#123 Codex [medium], the no-entry-vs-entry-undef MetaType
/// tri-state) adds `QuickTime_parrot_arcore_dup_stsd.mp4` — the base ARCore
/// `mett` track (one valid `application/arcore-accel` `stsd` entry) with a
/// SECOND, EMPTY duplicate `stsd` box (entry count 0) appended in the same
/// `stbl`. ExifTool's `ProcessSampleDesc` runs the per-entry `MetaType` RawConv
/// ONLY inside its `for ($i=0; $i<$num; ++$i)` loop, so the zero-count second
/// `stsd` makes NO assignment and bundled 13.59 RETAINS
/// `Track1:MetaType = application/arcore-accel` + STILL emits the three
/// `Track1:Accelerometer` vectors at `-ee` (byte-identical to the base arcore
/// goldens modulo SourceFile). The base (no-`ee`) golden carries the
/// `Track1:Warning` ExtractEmbedded hint + `Track1:MetaType` +
/// `Composite:AvgBitrate`. Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 621 → 622 (#150 GeoTiff Codex round, the BigTIFF GeoTiff path) adds
/// `GeoTiff_bigtiff.tif` — a crafted minimal little-endian BigTIFF (`0x002B`,
/// 8-byte offsets) carrying the `GeoTiff_mini` GeoKey blocks. A BigTIFF never
/// runs `ProcessGeoTiff` (`DoProcessTIFF`'s `0x2b` arm `return 1`s at
/// `ExifTool.pm:8668`, before the `:8740` call), so it emits NO `GeoTiff:*`
/// keys; the three `Binary => 1` block tags survive as `IFD0:GeoTiffDirectory`/
/// `DoubleParams`/`AsciiParams` `(Binary data N bytes …)` placeholders (50/9/7).
/// Additive — every PRE-EXISTING golden stays byte-identical.
/// 622 → 623 (#428 Codex round, the BigTIFF ColorMap path) adds
/// `BigTIFF_colormap.tif` — a crafted minimal little-endian BigTIFF (`0x002B`,
/// 8-byte offsets) carrying an IFD0 `ColorMap` (0x0140) `int16u[12]` palette.
/// A BigTIFF does NOT apply the classic `'binary'`/`undef` `Format` override, so
/// `ProcessBigIFD` reads the on-disk `int16u` and the `Binary => 1` placeholder
/// reports `length(join(' ', @vals))` (43 bytes) — NOT the classic undef-reshape
/// byte count (the 1536 of `GeoTiff.tif`, which stays unchanged). Additive —
/// every PRE-EXISTING golden stays byte-identical.
/// 623 → 624 (#422 RIFF repeated-`JUNK` last-wins) adds
/// `AVI_pentaxjunk2_dup.avi` — the `AVI_pentaxjunk2.avi` base with a SECOND
/// `PentaxJunk2` `JUNK` chunk (a different `Model`/`DateTime`) appended at the
/// top level. ExifTool re-runs the matched SubDirectory on EVERY `JUNK` chunk,
/// so the later chunk's `Pentax:*` leaves last-wins via the normal
/// `Priority => 1` tag-overwrite — bundled 13.59 keeps `Model = Optio RZ99`
/// (the second chunk). Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 624 → 625 (#422 Codex [high], the PARTIAL repeated-`JUNK` per-leaf union)
/// adds `AVI_pentaxjunk2_partial.avi` — a FULL `PentaxJunk2` chunk (Make=PENTAX,
/// Model="Optio RZ18", FNumber 28/10, DateTime 2014) followed by a SHORTER
/// same-signature `PentaxJunk2` (44 bytes — only the `Make`="RICOH " leaf @ 0x12
/// is in range; Model/FNumber/DateTime @ 0x2c/0x5e/0x83/0x9d are past the chunk
/// end). ExifTool replays the SubDirectory per chunk and the `TagMap` dedups PER
/// LEAF, so bundled 13.59 keeps the first chunk's Model/FNumber/DateTime1/2 (the
/// short chunk emits none) while the later `Make` wins — the case the
/// pre-fix whole-payload OVERWRITE dropped, now fixed by the ordered-Vec +
/// replay-all dispatch. Additive — every PRE-EXISTING golden stays
/// byte-identical.
/// 625 → 628 (#143 MNG/JNG sub-table port) adds the three crafted PNG-sibling
/// fixtures `MNG_mhdr.mng` (the `MHDR` MNGHeader sub-table incl. the
/// SimplicityProfile `0x%.8x` hand-port), `JNG_jhdr.jng` (the `JHDR` JNGHeader
/// sub-table + its int->label PrintConvs), and `MNG_chunks.mng` (a kitchen-sink
/// covering all 17 `%MNG::*` `ProcessBinaryData` sub-tables, the DISC/DROP/SEEK
/// inline ValueConvs, the 6 `Binary => 1` placeholders, and `pHYg` → the shared
/// `PNG-pHYs` decoder). The `\x8aMNG`/`\x8bJNG` signature gate (`PNG.pm:63-64`)
/// drives the `%MNG::Main` chunk-table fallback (`PNG.pm:1655`); a plain PNG is
/// unaffected (the fallback is reached only for an MNG/JNG container), so every
/// PRE-EXISTING PNG golden stays byte-identical.
/// 628 → 629 (#143 Codex Finding 2 — post-`MEND` MNG trailer group) adds
/// `MNG_trailer.mng`: an MNG (`MHDR`+`MEND`) with one trailing `BACK` chunk
/// after the `MEND` end chunk. The walker's trailer mode (`PNG.pm:1484`
/// `SET_GROUP1 = 'Trailer'`) emits that leaf under family-1 `Trailer`
/// (`Trailer:BackgroundColor`), distinct from the main `MNG:*` (the
/// `(doc, family1, name)` dedup key). Additive — every PRE-EXISTING golden
/// (incl. the three R1 MNG/JNG fixtures + all PNG goldens) stays byte-identical.
/// 629 → 630 (#143 — realistic mixed-MNG composite regression guard) adds
/// `MNG_embedded_ihdr.mng`: an MNG whose header `MHDR` (160x120) is followed by
/// an embedded PNG `IHDR` chunk (320x240). `ProcessPNG` resolves a chunk
/// against `%PNG::Main` before the `%MNG::Main` fallback (`PNG.pm:1653-1656`),
/// so `MHDR`→`MNG:ImageWidth=160` and `IHDR`→`PNG:ImageWidth=320` are BOTH
/// emitted; the equal-priority `Composite:ImageSize` keeps the LAST-walked
/// `IHDR` ⇒ `320x240`, byte-for-byte matching bundled. Additive — every
/// PRE-EXISTING golden (the four R1/R2 MNG/JNG fixtures + all PNG goldens) stays
/// byte-identical (no code change). The crafted three-equal-producer Case-A
/// composite-priority divergence is tracked separately as #436.
/// 630 → 631 (#434 — Pentax RIFF cross-source walk-order replay) adds
/// `AVI_pentaxjunk2_before_hydt.avi`: a full `PentaxJunk2` `JUNK` (`FNumber`
/// 2.8) placed BEFORE the real `Pentax.avi` `LIST_hydt` MakerNote (hymn
/// `FNumber` 0.0). `RiffMeta::tags` now replays a SINGLE walk-ordered
/// `pentax_events` list (the MakerNote + the `JUNK` records together) so the
/// `TagMap` resolves the lone overlapping leaf (`Pentax:FNumber`) in true RIFF
/// walk order; bundled keeps `2.8` here because the hymn `FNumber` is
/// `Priority => 0` (now threaded through the MakerNote replay). Additive —
/// every PRE-EXISTING golden (`Pentax.avi`, the `AVI_pentaxjunk*` set) stays
/// byte-identical (the realistic/JUNK-only/hydt-only cases keep their order).
/// 631 → 634 (#142 JUMBF / C2PA, Phase 1: the PNG `caBX` box-structure
/// subsystem) adds three crafted caBX-PNG fixtures: `PNG_cabx_jumbf.png`
/// (`jumb`->`jumd` with the JSON type-UUID + label "c2pa.test" — the `JUMDType`
/// `(json)` PrintConv split + `JUMDLabel`), `PNG_cabx_binary.png` (`jumb`->`jumd`
/// raw-UUID + `bfdb`/`bidb` — the raw `JUMDType`, `Jpeg2000:BinaryDataType`, and
/// the `bidb` byte-count placeholder), and `PNG_cabx_label_rename.png`
/// (`jumb`->`jumd`(label) + `bfdb`/`c2sh` — the JUMBFLabel rename to
/// `Jpeg2000:C2PAAssertions{Type,Salt}`). Each carries ONLY structure + binary
/// boxes (no `json`/`cbor` CONTENT, whose decoders are Phases 2-3), so exifast
/// matches bundled byte-exact. Additive — every PRE-EXISTING golden (all PNG +
/// the five MNG/JNG fixtures) stays byte-identical (`caBX` only fires for a
/// `caBX` chunk).
/// 634 → 635 (#142 JUMBF / C2PA, Phase 2: the `json` content decoder,
/// `JSON::Main` / `ProcessJSON`) adds one crafted caBX-PNG fixture
/// `PNG_cabx_json.png` (`jumb`->`jumd`(label "c2pa.test") + `json{...}` — a
/// representative C2PA-ish document flattened to `JSON:*` tags: the top-level
/// keys legalized + the C2PA-case hack, a nested object as a `-struct` Map,
/// arrays of scalars/objects, and the bare-number / bare-boolean / quoted-`null`
/// / quoted-19-digit `EscapeJSON` gate). The three Phase-1 caBX fixtures carry a
/// `jumd` whose type-UUID is the `(json)` UUID but NO `json` CONTENT box, so
/// their goldens are UNCHANGED by Phase 2 (only the new fixture emits `JSON:*`).
/// 635 → 636 (#142 JUMBF / C2PA, Phase 3: the `cbor` content decoder,
/// `CBOR::Main` / `ProcessCBOR`, the FINAL phase) adds one crafted caBX-PNG
/// fixture `PNG_cabx_cbor.png` (`jumb`->`jumd`(label "c2pa.test", `(cbor)` UUID)
/// + `cbor{...}` — a representative C2PA-ish CBOR document flattened to `CBOR:*`
/// tags: text + predefined keys (`dc:title`->`Title`), a native int / the
/// faithful `-1*num` negative quirk (`-7`->`-6`) / a quoted-19-digit int, a
/// byte string + COSE_Sign1 tag(18) as the `(Binary data …)` placeholder, a
/// nested `-struct` Map (nested negative + placeholder + preserved empty `[]`),
/// arrays of scalars/maps, a double + the buggy half-float, true/false/null, a
/// tag-0 `ConvertXMPDate` string, and the C2PA-case hack. The `cbor` tags emit
/// under family-0 `JUMBF` / family-1 `CBOR`; the JUMBFLabel rename does NOT fire
/// (`cbor` lacks `BlockExtract`). No prior golden changes (`cbor` only fires for
/// a `cbor` content box).
///
/// 636 → 637: the `Sony_ILME-FX3_real.ARW` raw GRADUATES out of `NOT_ACTIVE`
/// into the active set — its `%Sony::Main` encrypted sub-table tower is fully
/// ported (the `Decipher` cipher + `Tag9050c`/`Tag9400c`/`Tag9401`(ISOInfo)/
/// `Tag9402`/`Tag9406`/`Tag940c`/`Tag9416`/`Tag202a` ProcessBinaryData tables +
/// the five dependent `Composite:*`), with a single `FIXTURE_EXCLUDED_KEYS`
/// entry for the `XMP-xmp:Rating` IFD0-`0x02bc`-XMP residual.
const EXPECTED_ACTIVE_FIXTURES: usize = 637;

/// Every `tests/fixtures/<f>` that has both `tests/golden/<f>.json` and
/// `tests/golden/<f>.n.json`, MINUS the [`NOT_ACTIVE`] formally-accept-
/// deferred residuals — i.e. the active conformance fixtures.
fn active_fixtures() -> Vec<String> {
  let root = env!("CARGO_MANIFEST_DIR");
  let mut out = Vec::new();
  for entry in std::fs::read_dir(format!("{root}/tests/fixtures")).expect("read fixtures dir") {
    let entry = entry.expect("dir entry");
    if !entry.file_type().expect("file type").is_file() {
      continue;
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    if NOT_ACTIVE.contains(&name.as_str()) {
      continue;
    }
    let j = format!("{root}/tests/golden/{name}.json");
    let n = format!("{root}/tests/golden/{name}.n.json");
    if std::path::Path::new(&j).is_file() && std::path::Path::new(&n).is_file() {
      out.push(name);
    }
  }
  out.sort();
  out
}

/// Resolve the typed parser the SAME way `extract_info` does — walk the
/// detection candidates in `ExtractInfo` loop order; the first whose
/// `any_parser_for` is `Some` AND whose `parse_any` returns `Ok(Some(meta))`
/// wins. Returns `None` when no typed parser accepts (rejected/finalization-
/// only fixtures — e.g. `bad.ogg`, where the golden's tags come from
/// finalization, not a Meta). Mirrors `parse_bytes`' candidate loop.
fn typed_parse<'a>(fixture: &str, data: &'a [u8]) -> Option<exifast::AnyMeta<'a>> {
  let ext = exifast::filetype::file_ext_for_name(fixture);
  let ext_ref = ext.as_deref();
  let mut shared = SharedFlags::new();
  for cand in detection_candidates(fixture, data) {
    let ft = cand.file_type();
    // Mirror the engine's XMP→PLIST content-sniff route (see
    // `parser::extract_info`): bundled reaches a UTF-8-BOM XML plist via
    // `ProcessXMP`'s `<plist>` relabel (XMP.pm:4385). The ported standalone XMP
    // parser REJECTS a `<plist>`-rooted document (`Ok(None)`), so the
    // BOM-prefixed XML `<plist>` candidate (detected as XMP) is relabeled to
    // `PLIST` and dispatched to `ProcessPlist`. A genuine XMP sidecar does NOT
    // satisfy `xml_content_is_plist`, so it stays `XMP`. Keeping this in sync
    // keeps the independent parity loop value-equivalent to the engine writer
    // path.
    let ft = if ft == "XMP" && exifast::formats::plist::xml_content_is_plist(data) {
      "PLIST"
    } else {
      ft
    };
    let Some(parser) = any_parser_for(ft) else {
      continue;
    };
    // `cand.header_skip()` threads the unknown-leading-header byte count for
    // the terminal JPEG/TIFF candidate (`0` for ordinary candidates) — same
    // dispatch the engine's `extract_info` runs.
    match parser.parse_any(
      data,
      &mut shared,
      ext_ref,
      cand.header_skip(),
      Some(cand.parent_type()),
      // No-`ee` parity oracle (mirrors `extract_info`'s default render mode).
      false,
    ) {
      Some(meta) => return Some(meta),
      None => shared = SharedFlags::new(),
    }
  }
  None
}

/// Build the typed SERDE document for `fixture` in the given mode: lift the
/// orchestration tags + warnings/errors off the engine writer, serde-render
/// the typed `AnyMeta` for the format tags, and merge into the `[{ … }]`
/// document with `%noDups` first-wins. Returns the JSON string.
fn typed_serde_document(fixture: &str, data: &[u8], print_on: bool) -> String {
  use serde_json::{Map, Value};

  let mut obj: Map<String, Value> = Map::new();
  obj.insert("SourceFile".into(), Value::String(fixture.to_string()));

  // (1) Orchestration tags (`ExifTool:*` + `File:*`) + warnings/errors lifted
  // off the authoritative engine writer. These are the engine's
  // responsibility OUTSIDE the typed Meta in BOTH designs. We lift them as
  // rendered JSON values by round-tripping the engine's own document and
  // copying only the orchestration/diagnostic keys — this keeps their exact
  // rendered form (e.g. `ExifTool:ExifToolVersion` as the bare number 13.58).
  let engine_doc = extract_info(fixture, data, print_on);
  let engine_parsed: Value = serde_json::from_str(&engine_doc).expect("engine doc is valid JSON");
  let engine_obj = engine_parsed[0]
    .as_object()
    .expect("engine doc is a single-object array");
  for (key, value) in engine_obj {
    if key == "SourceFile" {
      continue; // already inserted first
    }
    let is_orchestration = key.starts_with("ExifTool:")
      || key.starts_with("File:")
      || key == "ExifTool:Warning"
      || key == "ExifTool:Error";
    if is_orchestration && !obj.contains_key(key) {
      obj.insert(key.clone(), value.clone());
    }
  }

  // (2) Format tags via the typed SERDE path — `serde_json::to_value` over the
  // `Rendered` wrapper (the actual Stage-2 output mechanism).
  if let Some(meta) = typed_parse(fixture, data) {
    let rendered = serde_json::to_value(Rendered::new(&meta, print_on))
      .expect("Rendered serialization is infallible");
    if let Value::Object(format_map) = rendered {
      for (key, value) in format_map {
        // `%noDups` first-wins: orchestration keys (inserted above) win.
        obj.entry(key).or_insert(value);
      }
    }
  }

  Value::Array(vec![Value::Object(obj)]).to_string()
}

#[test]
fn typed_serde_path_equals_writer_path_and_golden_all_337() {
  // 121 → 124 after F2 (Codex adversarial): added MPC + WavPack chain
  // fixtures (mpc_with_id3v2_prefix.mpc, mpc_with_apev2_trailer.mpc,
  // wavpack_with_apev2_trailer.wv). These exercise the ID3-prefix /
  // APE-trailer chains the previous typed dispatch silently dropped.
  // 124 → 125 after R3 F1 (Codex adversarial): added
  // `ogg_id3_prefixed.ogg` to exercise the OGG ID3-prefix chain.
  // 125 → 126 after R3 F2 (Codex adversarial): added `Opus.opus` (the
  // bundled t/images fixture) to exercise the `METADATA_BLOCK_PICTURE`
  // Vorbis-comment SubDirectory hop into `%FLAC::Picture` (FLAC.pm:84-
  // 134). The other R3 F2 fixture (`FLAC.ogg`, Ogg-FLAC transport) is
  // formally accept-deferred — see `NOT_ACTIVE`.
  // 126 → 127 after FORMATS.md row 23 lib/matroska: added `Matroska.mkv`
  // (bundled t/images fixture, 507 bytes) to exercise the EBML walker +
  // tag-table dispatch ported in `src/formats/matroska.rs`.
  // 127 → 131 after PR #31 Round-1 findings (F1, F2, F3, F5): added
  // `Matroska_simpletag.mkv`, `Matroska_unknown_segment.mkv`,
  // `Matroska_cluster_skip.mkv`, `Matroska_attachment.mkv` — synthetic
  // adversarial fixtures exercising SimpleTag/StdTag mapping,
  // unknown-size Segment, default Cluster-stop, and binary-placeholder
  // emission (see `tests/conformance.rs::matroska_*_conformance`).
  // 131 → 133 after PR #31 Round-2 finding (DateUTC subsecond loss):
  // added `Matroska_subsecond_date.mkv` (positive raw_ns with non-zero
  // nanosecond remainder) and `Matroska_negative_subsecond_date.mkv`
  // (pre-2001 raw_ns < 0 exercising both the EBML 8-byte signed-decode
  // f64 promotion loss and the $frac < 0 correction branch). Both
  // verify the new `convert_matroska_date` faithful transliteration of
  // `Matroska.pm:1184-1198` + `ExifTool.pm:6773-6800` fractional branch.
  // 136 → 137 after PR #31 R4 finding F1 (Codex adversarial): added
  // `Matroska_chapters.mkv` exercising ChapterTimeStart/ChapterTimeEnd
  // (Matroska.pm:580-592 unsigned-ns → /1e9 → ConvertDuration), the
  // ChapterDisplay (ID 0) traversal fix, and the `Chapter<n>` family-1
  // group attribution (Matroska.pm:1117-1119 chapterNum counter).
  // 137 → 138 after PR #31 R4 finding F2 (Codex adversarial): added
  // `Matroska_track_targeted_tag.mkv` exercising the
  // TagTrackUID → Track<N> group override (Matroska.pm:1207-1216
  // %trackNum map populated from TrackUID inside TrackEntry, looked up
  // at TagTrackUID time to switch SET_GROUP1 for the enclosing Tag).
  // 138 → 139 after PR #31 R5 finding (Codex adversarial): added
  // `Matroska_simpletag_duplicates.mkv` exercising last-wins overwrite
  // semantics on SimpleTag children (Matroska.pm:1226 `$$struct{$tagName}
  // = $val` is plain Perl hash assignment) AND TagDefault absorbed-not-
  // emitted (Matroska.pm:1224-1226 routes ALL leaves into struct when
  // active; Matroska.pm:929 explicitly drops TagDefault at flush).
  // 139 → 141 after the Real (RM/RA) port (FORMATS.md row 19): added
  // the bundled `Real.rm` (chunk-walk + RJMD footer + ID3v1) and
  // `Real.ra` (RealAudio V4 codec table) fixtures.
  // 128 → 130 after Codex R1 F2 (PR #33): added 2 adversarial Real
  // fixtures pinning the ID3v1-trailer fidelity gap (empty Title
  // preserved as `""`; sparse Genre byte 192 preserved verbatim).
  // 130 → 132 after Codex R1 F1 (PR #33): added 2 adversarial Real
  // fixtures pinning the MIME-override branch (1-stream audio MIME
  // ⇒ override fires; 2 populated streams ⇒ no override). The 2
  // empty-MIME F1 variants (1empty, 2_empty_audio) live in fixtures/
  // for unit tests only — bundled emits a Perl-interpreter-level
  // `Condition FileInfoLen2: Use of uninitialized value` warning that
  // this Rust port does not (and should not) replicate, so they
  // cannot be value-equivalent at the JSON surface.
  // 132 → 133 after Codex R2 (PR #33): added 1 adversarial Real fixture
  // (`real_synth_embedded_nul_mime.rm`) pinning the bundled first-NUL
  // truncation (ReadValue at ExifTool.pm:6300 + Real.pm:643) on
  // `Format => 'string[$val{10}]'` StreamMimeType. Without the fix,
  // an embedded NUL leaks through both `Real-MDPR:StreamMimeType` AND
  // the single-stream `File:MIMEType` override.
  // 146 → 149 after the PR #33 Copilot RAM/RPM fix: added 3 Metafile
  // fixtures (`real_synth_ram_pnm.ram`, `real_synth_rpm_pnm.rpm`,
  // `real_synth_metafile_http_accept.ram`) pinning the Real.pm:533-555
  // Metafile branch — the RAM-vs-RPM extension discrimination, the
  // `^[a-z]{3,4}://` URL/text split, and the `http`-line acceptance gate.
  // 126 → 127 after wave-a-flash: added `Flash.flv` (FORMATS.md row 18,
  // bundled FLV fixture with audio/video bit-stream + AMF onMetaData).
  // 127 → 135 after Codex R1 Flash F1/F2 fixes: added 8 synthetic FLVs
  // exercising AMF strict-array heterogeneous emission (strings/bools/
  // dates/mixed) + per-AMF-type truncation warning paths (double/string/
  // date/array).
  // 135 → 136 after Codex R2/F3 fix: added `flash_f3_unsupported.flv`
  // — bundled emits `Flash:Duration` + the `AMF AMF3data record not
  // yet supported` warning; the prior `ReadResult::Truncated`
  // discriminant collision let the top-level walker silently pop the
  // unsupported diagnostic.
  // 136 → 137 after Codex R2/F2 fix: added `flash_f2_nested_array.flv`
  // — bundled emits `OuterArr: [[1,2],99]` (nested strict-array
  // preserved as nested JSON list); prior shape returned
  // `AmfValue::StrictArray` from `read_value` without consuming the
  // nested array's count+payload, leaving the cursor mid-array.
  // 137 → 139 after Codex R2/F1 verification pin: added
  // `flash_f1_double_first.flv` and `flash_f1_struct_first.flv` —
  // bundled WALKS PAST a non-string scalar at rec=0 and walks the
  // children of a struct at rec=0 inline (Flash.pm:442's
  // `unless ($isStruct{$type})` SKIPS the gate for any struct; the
  // `else` arm at lines 448-452 is verbose-only for non-string
  // non-struct rec=0 — NO `last`). The original Codex R2/F1 framing
  // suggested bundled rejects in both cases, but empirical bundled
  // output contradicts. Current Rust walker already matches bundled;
  // these fixtures PIN the walk-past behaviour so a future
  // regression would fail conformance.
  // 139 → 140 after Codex R3/F1: added `flash_amf_scalars.flv`
  // (onMetaData mixed-array carrying five AMF scalar shapes —
  // null/undef/unsupported emit `""`, reference emits the u16 numeric
  // value, control double emits 7.5 — per Flash.pm:403-409).
  // 140 → 141 after Codex R3/F2: added `flash_array_with_empties.flv`
  // (strict-array `[null, undef, ref(3), double(4)]` emits
  // `["","",3,4]` per Flash.pm:417-422 `push @vals, $v unless
  // $isStruct{$t}`).
  // 141 → 142 after Codex R3/F3: added `flash_top_strict_array.flv`
  // (top-level 0x0a between onMetaData and a mixed-array — bundled
  // walks past the lone strict-array per Flash.pm:410-426 reached
  // from the outer record loop, then emits the mixed-array's
  // `goodKey: 7.5`).
  // 142 → 143 after Codex R4/F2 fix: added
  // `flash_f4_nested_array_prefix.flv` (nested strict-array recursion
  // MUST carry the per-index prefix per Flash.pm:415-418's
  // `$$dirInfo{StructName} = $structName . $i if defined $structName`
  // applied BEFORE recursive ProcessMeta — prior shape passed the outer
  // struct_name unchanged into the nested array walk, collapsing
  // `outerArr[1][0].name` and `outerArr[0][0].name` to the same
  // `OuterArr0Name` tag under first-wins).
  // 143 → 144 after Codex R4/F1 fix: added
  // `flash_f4_array_abort_sibling.flv` (struct walker MUST abort on a
  // failed child array — bundled Flash.pm:382-386's `last Record unless
  // defined $t and defined $v` aborts the entire struct walk, dropping
  // the sibling AFTER the failed array; prior shape unconditionally
  // continued and emitted the sibling).
  // 144 → 145 after Codex R5 verification pin (FALSE POSITIVE): added
  // `flash_f5_array_struct_abort.flv` — bundled does NOT abort the
  // strict-array element loop when a STRUCT element's child is
  // unsupported. Flash.pm:340's `$val = ''` (struct branch dummy) keeps
  // `$val` DEFINED across the inner pair-loop's `last Record`, so the
  // inner ProcessMeta returns `(0x03, '')` (not `(undef, undef)`); the
  // outer array loop's line 420 `last Record unless defined $v` does
  // NOT fire — cursor desync continues at i+1 and bundled emits the
  // misparsed array value `[1.25e-308]` (the next bytes happen to read
  // as a double). Current Rust walker already matches bundled; this
  // fixture PINS the struct-element-failure-does-NOT-propagate-abort
  // behaviour so a future regression would fail conformance.
  // 145 → 146 after Codex R7: added `flash_nested_livexml.flv`. The R6
  // XMP-deferral gate `(Meta && raw_key == "liveXML")` was too broad —
  // it dropped a NESTED `foo.liveXML` with the XMP-deferral warning,
  // even though bundled emits the nested case as a plain auto-add
  // scalar `Flash:FooLiveXML`. Fix narrows the gate to
  // `struct_name.is_empty()` (the TOP-LEVEL un-prefixed case — the
  // only shape that reaches the Meta `liveXML` SubDirectory in
  // bundled). The original top-level fixture (`flash_xmp_livexml.flv`)
  // stays `#[ignore]`-d in `NOT_ACTIVE` (R6 accept-deferral).
  // 146 → 148 after Codex R8: added `flash_empty_key_livexml.flv` AND
  // `flash_toplevel_array_objects.flv`. R7's `is_empty()` gate collapsed
  // Perl's `undef $structName` (top-level / no struct in effect) with
  // a DEFINED empty string `Some("")` (e.g. child under an empty-key
  // parent), and Flash.pm:380 + Flash.pm:418 gate on `defined`, not on
  // length-zero. Two adversarial branches uncovered:
  //   * R8/F1 — `flash_empty_key_livexml.flv`: an empty-key object
  //     containing `liveXML` MUST emit `Flash:LiveXML` (the prefix
  //     branch's `"" . ucfirst("liveXML") = "LiveXML"` auto-adds via
  //     resolve_emit MISS), NOT trigger the XMP-deferral. Pre-R8 the
  //     empty `struct_name` collapsed to the top-level branch and the
  //     value was silently dropped.
  //   * R8/F2 — `flash_toplevel_array_objects.flv`: a top-level
  //     strict-array containing object elements. Bundled does NOT
  //     append the array index per Flash.pm:418's `if defined
  //     $structName` (undef at top level → no append) — bundled emits
  //     `Flash:Name` last-wins (collision intentional). Pre-R8 the
  //     `format!("{struct_name}{i}")` site appended `0`/`1` even when
  //     `struct_name` was the empty/None sentinel, manufacturing
  //     `Flash:0Name`/`Flash:1Name` tags bundled never emits.
  //   Fix changes the walker's `struct_name: &str` to
  //   `Option<&str>` throughout, distinguishing Perl undef (`None`)
  //   from defined empty (`Some("")`), and gates BOTH the
  //   XMP-deferral check AND the array-index append on the `defined`
  //   condition. See `src/formats/flash.rs::is_xmp_subdirectory_dispatch`
  //   and `walk_pairs` doc comments.
  // 148 → 149 after Codex R9/F1: added
  // `flash_keyed_array_truncated_count.flv`. Pre-R9
  // `collect_array_items` returned silent `None` when `*pos + 4 >
  // data.len()` at the strict-array count read; the keyed-value caller
  // dropped bundled's `"Truncated AMF record 0xa"` (Flash.pm:455).
  // Fix introduces `ArrayOutcome::TruncatedCount` so the keyed-value
  // caller (`walk_array` from `walk_pairs`) can push the bundled-
  // faithful warning while the top-level caller stays silent under
  // bundled's $val-from-prior-records rule.
  // 149 → 151 after Codex R9/F2: added
  // `flash_typed_object_truncated_name.flv` (top-level) and
  // `flash_array_typed_object_truncated_name.flv` (nested-in-array).
  // Pre-R9 `skip_struct_intro` returned silent `bool` for typed-object
  // (0x10) name-payload overrun; both top-level and nested-in-array
  // call sites dropped bundled's `"Truncated typedObject record"`
  // (Flash.pm:353). Fix splits the typed-object name parsing into a
  // dedicated `consume_struct_intro` helper that returns an
  // `IntroOutcome` enum and pushes the exact bundled warning text on
  // the payload-overrun path (NOT on the length-truncation path —
  // bundled's $val='' from line 340 keeps that silent).
  // 151 → 153 after Codex R10: added
  // `flash_array_typed_object_truncated_length.flv` and
  // `flash_array_mixed_array_truncated_top_index.flv`. R9/F2 introduced
  // silent `IntroOutcome::Truncated` returns for 0x10 name-LENGTH /
  // 0x08 top-index, but the strict-array element caller
  // (`collect_array_items`) wrapped every `Truncated` with a
  // `"Truncated AMF record 0xa"` push — converting bundled's silent
  // paths into user-visible warnings at the array frame. Fix: enrich
  // `IntroOutcome::Truncated` with `IntroTruncReason` and route the
  // silent reasons to abort-without-push; the typedObject-name-overrun
  // path stays at helper-pushes-warning + caller-no-push (was
  // helper-pushes + caller-also-pushes pre-R10).
  // — rebased onto main post-#33: the counts above are each
  //   branch's own running history; the merged total reconciles
  //   to 149 (main after #31 Matroska + #33 Real) + 27 (lib/flash) = 176.
  // 176 → 178 after Codex R11: added `flash_array_struct_intro_trunc_continues.flv`
  // (R11/F1 — a struct-introducer truncation on a NON-LAST strict-array
  // element must NOT abort the element loop early: bundled's `$val=''`
  // dummy keeps the inner ProcessMeta's return DEFINED, so the loop
  // continues and a later EOF raises `Truncated AMF record 0xa`) and
  // `flash_amf_date_zero_sentinel.flv` (R11/F2 — an AMF date of 0
  // milliseconds must format as ExifTool's `0000:00:00 00:00:00`
  // zero-time sentinel + AMF tz suffix, NOT `1970:01:01 00:00:00...`).
  // 178 → 180 after Codex R12: added `flash_duration_strict_array.flv`
  // (R12/F1 — a known Flash tag with a PrintConv, AMF-encoded as a
  // strict-array, must apply the tag PrintConv per element: `duration`
  // → `["1.50 s","0:01:01"]` under `-j`, raw `[1.5,61]` under `-n`) and
  // `flash_amf_date_pre1000.flv` (R12/F2 — a pre-1000 AMF date must
  // space-pad the year per ExifTool's `sprintf %4d`: Unix second
  // -30641760000 → `" 999:01:01 00:00:00.000000+00:00"`, NOT a
  // zero-padded `"0999:..."`).
  // 180 → 183 after Codex R13: added `flash_duration_nested_array.flv`
  // (R13/F1 — a NESTED strict-array element of a known-PrintConv tag
  // stays raw: `duration` → `[[1.5,61]]`, not `[["1.50 s","0:01:01"]]`),
  // `flash_audio_encoding_reserved.flv` (R13/F2 — a hash-PrintConv MISS
  // renders `Unknown (9)` under -j, raw `9` under -n), and
  // `flash_audio_tail_truncated.flv` (R13/F3 — an audio packet whose
  // declared payload is truncated after the first config byte still
  // emits all four audio tags with no warning).
  // 183 → 184 after Codex R14: added `flash_duration_mixed_nested.flv`
  // (R14/F1 — the owning tag conversion is applied ONCE PER TOP-LEVEL
  // element: `duration` = `[1.5, [2,3], 61]` → `["1.50 s",[2,3],"0:01:01"]`
  // under -j and `[1.5,[2,3],61]` under -n — scalars convert, the nested
  // arrayref passes through raw with no recursive descent). The arithmetic
  // *datarate / FrameRate nested-arrayref case is NOT fixtured: bundled
  // coerces the arrayref to a non-deterministic memory address (no stable
  // golden); covered by the `collect_array_items_mul_1000_*` unit test.
  // 184 → 185 after Codex R15: added `flash_creationdate_strict_array.flv`
  // (R15/F1 — the owning tag STRING ValueConv `$val=~s/\s+$//` is applied
  // per top-level array element: `creationdate` = `["A   ","B\t "]` →
  // `["A","B"]` under BOTH -j and -n. The nested-arrayref string stays raw,
  // covered by the `collect_array_items_trim_ws_*` unit test).
  // 185 → 186 after Codex R16: added `flash_r16_nested_struct_abort.flv`
  // (R16/F1 — a STRUCT-VALUED child whose object body starts with an
  // unsupported AMF3 marker (`00 00 11`) must NOT abort the PARENT pair
  // walk: Flash.pm:340's `$val=''` struct dummy keeps the child's
  // ProcessMeta return `(0x03, '')` defined, so the outer line 386
  // check passes and line 387 `next if $isStruct{$t}` continues — the
  // parent sibling `after=9` IS emitted. Pre-fix the Rust struct-child
  // branch propagated `WalkOutcome::Abort`, silently dropping
  // `Flash:After`).
  // 186 → 187 after Codex R17: added
  // `flash_r17_struct_child_trunc_intro.flv` (R17/F1 — a struct-valued
  // child whose `0x08` mixed-array introducer is itself truncated
  // (`08 00 05`, a 4-byte top-index needs 4 bytes) must NOT enter the
  // child pair loop: Flash.pm:342's `last if $pos+4>$dirLen` exits the
  // struct branch BEFORE the `for(;;)` loop, returning `(0x08,'')`.
  // The parent `obj` object loop then surfaces `Truncated object
  // record` FIRST, the grandparent mixedArray `Truncated mixedArray
  // record` SECOND. Pre-fix the Rust struct-child branch always called
  // `walk_pairs` even for a truncated introducer, pushing `Truncated
  // mixedArray record` first and inverting the warning order / JSON
  // first-wins result).
  // 187 → 188 after Codex R18/F1: added `flash_amf_bad_utf8.flv`
  // (an onMetaData mixed-array whose AMF string (0x02), long-string
  // (0x0c) and XML (0x0f) values each carry the invalid-UTF-8 run
  // `41 ff 42`). Bundled keeps the raw bytes and applies
  // `XMP::FixUTF8` at JSON emit (exiftool:3822 → XMP.pm:2948-2972),
  // rendering `Flash:BadStr/BadLong/BadXml = "A?B"` in both -j and -n.
  // Pre-fix the string-like AMF arms decoded via
  // `String::from_utf8_lossy`, materializing U+FFFD and failing the
  // jsondiff gate; the fix routes every payload-derived AMF string
  // through `crate::convert::fix_utf8` (the faithful FixUTF8
  // transliteration).
  // 188 → 190 after Codex R19/F1: added `flash_amf_string_conv.flv`
  // (scalar) and `flash_amf_string_conv_array.flv` (strict-array). Bundled
  // `GetValue` (ExifTool.pm:3519-3656) applies a tag's ValueConv/PrintConv
  // to `$val` whether AMF carried it as a number (0x00) or a numeric string
  // (0x02/0x0c/0x0f) — Perl numeric coercion turns `"65.8"` into 65.8 inside
  // an arithmetic ValueConv. Pre-fix the AMF-string arm only trimmed
  // `creationdate` and stored the raw string, so numeric fields encoded as
  // AMF strings skipped their conversion (`audiodatarate "65.8"` → bundled
  // `"65.8 kbps"`/`65800`; the port emitted the unconverted `"65.8"`). Fix
  // (`emit_resolved` + `emit_entry` + `collect_array_items` +
  // `flash_list_item_with_pc`): `mul_1000` strings are Perl-coerced and
  // numified to a double (then ConvertBitrate/RoundInt apply); the
  // no-ValueConv-with-PrintConv tags (duration/starttime ConvertDuration,
  // framerate RoundMilli) apply their PrintConv to the string at `-j` emit
  // (ConvertDuration honours the `IsFloat` guard incl. comma-decimal;
  // RoundMilli uses raw arithmetic coercion). The coercion rule
  // (leading-numeric-prefix → number via `convert::perl_str_to_f64`, else 0)
  // is pinned against the bundled oracle in BOTH `-j` and `-n`. The strict-
  // array path mirrors the same per-top-level-element conversion.
  // 190 → 192 after Codex R20/F1: added `flash_amf_nonfinite_inf.flv`
  // (all four numeric fields = `inf`) and `flash_amf_nonfinite_nan.flv`
  // (`NaN`/`Inf`/`-inf`/`nan`). Perl's `Perl_my_atof` coerces the IEEE
  // non-finite spellings (`inf`/`nan`/`infinity`/`1.#INF`, any case + sign)
  // to `±Inf`/`NaN`; the `$val * 1000` ValueConv then carries the non-finite
  // into `ConvertBitrate`/`int($val+0.5)` (audio/video/total) — all of which
  // `IsFloat`-reject it and pass through, stringifying to Perl's titlecase
  // `Inf`/`-Inf`/`NaN` in BOTH `-j` and `-n`. `framerate` (no ValueConv) keeps
  // its raw AMF string under `-n` (lowercase `inf`/`nan` as authored) and runs
  // `int($val*1000+0.5)/1000` under `-j` (→ titlecase). Pre-fix
  // `perl_str_to_f64` returned `0.0` for every non-finite spelling (the
  // ValueConv tags became `0`/`0 bps`) and `ConvertBitrate`/`ConvertDuration`
  // emitted Rust's lowercase `inf`/`-inf`. Both pinned here vs the bundled
  // oracle.
  // 149 → 150 after the QuickTime port Sub-Port 1 (the box/atom walker +
  // core structural atoms): added the synthetic `QuickTime_sp1.mov`
  // fixture exercising `ftyp` + `moov`(`mvhd` + 2 `trak`s) + `mdat`. The
  // real bundled `QuickTime.mov`/`QuickTime.m4a` fixtures land in a later
  // sub-port (see `docs/tracking.md`).
  // 150 → 153 after PR #38 Codex R1 findings F2/F4/F5: added three
  // synthetic adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_v1tkhd.mov` (version-1 tkhd ImageWidth/Height at offsets
  // 88/92, F2), `QuickTime_moov_order.mov` (trak-before-mvhd ⇒ final-
  // TimeScale durationInfo, F4-refuted), `QuickTime_nested_size0.mov`
  // (contained size-0 terminator drops the trailing trak, F5).
  // 153 → 158 after PR #38 Codex R2 findings F1/F2/F3/F4: added five
  // synthetic adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_zerodate.mov` (raw-0 mvhd/tkhd/mdhd dates ⇒ "0000:00:00
  // 00:00:00" sentinel, not dropped, R2/F1), `QuickTime_m4a.mov` +
  // `QuickTime_m4v.mov` (ftyp-derived MIME audio/mp4 + video/x-m4v carried
  // through finalization, R2/F2), `QuickTime_zerotimescale.mov` (TimeScale=0
  // ⇒ Duration/TrackDuration emit the bare raw value, R2/F3),
  // `QuickTime_maclang.mov` (Macintosh MediaLanguageCode 12 ⇒ ttLang
  // PrintConv "ar", -n raw 12, R2/F4).
  // 158 → 160 after PR #38 Codex R3 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_matrixfrac.mov` (a FRACTIONAL mvhd MatrixStructure exercising
  // GetFixed32s' 5-dp rounding + Perl `%.15g` ⇒ "2e-05 0 0 0 2e-05 0 0 0
  // 1.220703125e-09", R3/F1) and `QuickTime_multimoov.mov` (TWO top-level
  // moovs; the second's mvhd overwrites the GLOBAL TimeScale to 300, so the
  // first track's TrackDuration converts as 1200/300 = 4 against the FINAL
  // TimeScale, R3/F2).
  // 160 → 162 after PR #38 Codex R4 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_size0_moov.mov` (ftyp + a TOP-LEVEL size-0 `moov` whose `mvhd`
  // payload is NOT decoded — ExifTool prints "extends to end of file" and
  // STOPS, QuickTime.pm:10044-10056 — so ONLY the ftyp tags survive, R4/F1)
  // and `QuickTime_multimoov_tracks.mov` (TWO top-level moovs each with one
  // `trak`; ExifTool's `$track` counter is a `my` local of each moov's
  // ProcessMOV call so it RESETS per moov ⇒ BOTH are `Track1`, and the second
  // collapses on the family-1 collision in default JSON — no `Track2`, R4/F2).
  // 162 → 164 after PR #38 Codex R5 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_multimoov_tracksdistinct.mov` (TWO top-level moovs both numbering
  // their lone `trak` as `Track1` but carrying DISTINCT tags — moov1 a bare
  // `tkhd` with TrackID, moov2 a bare `mdhd`/`hdlr` with MediaTimeScale/
  // MediaDuration/HandlerType; ExifTool's `%noDups` first-wins is per rendered
  // tag KEY not per group, so BOTH sets of `Track1:*` tags survive, R5/F1) and
  // `QuickTime_size0_mdat_first.mov` (a file whose VERY FIRST top-level atom is
  // `size == 0, type = mdat`; the first-atom gate keys on the 4-byte type
  // regardless of size ⇒ FileType MOV + MediaDataSize/Offset then `last`,
  // QuickTime.pm:9984/10044-10056, R5/F2).
  // 164 → 167 after PR #38 Codex R6 findings F1/F2: added three synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_multimoov_movdur.mov` (TWO top-level moovs; moov1's `mvhd` has
  // Duration=3000 under TimeScale=600, moov2's SHORT `mvhd` carries only
  // TimeScale=300 with NO Duration ⇒ movie `Duration` = 3000/300 = "10.00 s" —
  // the `%durationInfo` ValueConv runs at OUTPUT against the FINAL global
  // TimeScale and an absent field in the later `mvhd` does NOT erase the
  // earlier count, R6/F1), `QuickTime_trunc_ftyp.mov` (a 12-byte file whose
  // first `ftyp` declares size 100; the format is gated on the 4-byte `$tag`
  // alone ⇒ accepted, FileType MP4 default + a `Truncated 'ftyp' data`
  // warning, R6/F2) and `QuickTime_overrun_mdat.mov` (a 12-byte file whose
  // first `mdat` declares size 100 ⇒ FileType MOV + MediaDataSize=92 +
  // MediaDataOffset=8 from the DECLARED size + a `Truncated 'mdat' data at
  // offset 0x0` warning, R6/F2).
  // 167 → 171 after PR #38 Codex R7 findings F1/F2: added four synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_dupmdhd.mov` (a `moov/trak/mdia` with a FULL `mdhd`
  // TimeScale=600/Duration=1200 followed by a SHORT `mdhd` carrying only
  // TimeScale=300 ⇒ `Track1:MediaDuration = "2.00 s"` is NOT erased by the
  // later absent Duration while `MediaTimeScale = 300` is last-wins, R7/F1),
  // `QuickTime_nested_trunc_mvhd.mov` (a truncated `mvhd` inside `moov` ⇒
  // `ExifTool:Warning = "Truncated 'mvhd' data (missing 88 bytes)"` — a
  // contained `TruncatedAtom` now surfaces the warning instead of breaking
  // silently, R7/F2), `QuickTime_nested_trunc_tkhd.mov` (a truncated `tkhd`
  // inside `moov/trak` ⇒ `Track1:Warning`, the warning attaches to the
  // current family-1 group, R7/F2) and `QuickTime_nested_trunc_mdhd.mov` (a
  // truncated `mdhd` three levels deep in `moov/trak/mdia` ⇒ `Track1:Warning`,
  // R7/F2).
  // 171 → 175 after PR #38 Codex R8 findings F1/F2: added four synthetic
  // adversarial QuickTime fixtures verified vs bundled, pinning the
  // first-atom size/header malformation class-sweep —
  // `QuickTime_invalid_size.mov` (an 8-byte `00000004 ftyp`: a `size < 8`
  // first atom ⇒ FileType MOV + `ExifTool:Warning = "Invalid atom size"`,
  // R8/F1), `QuickTime_trunc_ext_hdr.mov` (a 12-byte `size==1 ftyp` whose
  // 8-byte extended-size header is truncated ⇒ FileType MOV + `Truncated atom
  // header`, R8/F1), `QuickTime_short_ftyp.mov` (an 8-byte `size==8 ftyp`
  // whose RAW 32-bit size is `< 12` ⇒ `else { SetFileType() }` ⇒ MOV, not the
  // MP4 default, R8/F1) and `QuickTime_ext_ftyp.mov` (an extended-size `ftyp`
  // with the `isom` brand: the `$size >= 12` gate sees the RAW 32-bit
  // `size == 1` so it FAILS ⇒ MOV, even though the brand alone would resolve
  // to MP4, R8/F1). R8/F2 — a lowercase `pict` first atom is now a recognized
  // MOV magic atom (`is_known_top_level` += `pict`, −`meta`) — is pinned by
  // the `lowercase_pict_first_atom_accepted_as_mov` /
  // `meta_first_atom_is_rejected` unit tests (a `pict` conformance fixture
  // would force the SP2-scope `Binary` `PreviewPICT` payload tag).
  // 175 → 178 after PR #38 Codex R9 findings F1/F2: added three synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_ftyp_first_qt.mov` (a `ftyp` `isom` major + `qt  ` in the FIRST
  // compatible-brand slot ⇒ FileType MP4: the `^.{8}(.{4})+(qt  )` regex needs
  // a NON-first compatible-brand slot, so a first-slot `qt  ` does not
  // override the MP4 default, R9/F1), `QuickTime_nested_invalid_mvhd.mov` (a
  // `moov` containing an `mvhd` with declared `size == 4` ⇒ `ExifTool:Warning
  // = "Invalid atom size"`: a contained `Malformed` header now surfaces the
  // bundled `$warnStr` instead of `walk_atoms` breaking silently, R9/F2) and
  // `QuickTime_nested_invalid_tkhd.mov` (a `tkhd` with invalid `size == 4`
  // inside `moov/trak` ⇒ `Track1:Warning = "Invalid atom size"`, R9/F2).
  // 178 → 179 after PR #38 Codex R10 finding F1: added the synthetic
  // adversarial QuickTime fixture `QuickTime_m4a_isom_override.mov` (an `ftyp`
  // `isom` MAJOR brand + a lone `soun`-handler track and NO `vide` handler ⇒
  // bundled ExifTool's post-walk `OverrideFileType('M4A','audio/mp4')` flips
  // the MP4-resolved type to `File:FileType=M4A` / `File:FileTypeExtension=m4a`
  // / `File:MIMEType=audio/mp4` while `QuickTime:MajorBrand` keeps the `isom`
  // PrintConv — the audio-only `.m4a` real-world-file case,
  // QuickTime.pm:10619-10624, verified vs bundled 13.58, R10/F1). R10/F2 — the
  // mvhd/tkhd/mdhd Hooks widen on a TRUTHY version (not strictly `== 1`) — is
  // crafted-input-only (v2+ atoms are undefined by the MP4 spec), so it adds
  // NO fixture; the existing v0/v1 fixtures stay byte-exact green.
  // 179 → 180 after PR #38 Codex R11 finding F1: added the QuickTime fixture
  // `QuickTime_useext_glv.glv` — the BYTE-IDENTICAL twin of
  // `QuickTime_m4a_isom_override.mov` but named `.glv`. The `%useExt` rule
  // (QuickTime.pm:240 `( GLV => 'MP4' )`, applied at QuickTime.pm:10006-10007)
  // promotes the ftyp-derived MP4 to GLV BEFORE the post-walk MP4→M4A override
  // (gated on `FileType eq 'MP4'`), so the same audio-only bytes yield
  // `File:FileType=GLV` / `File:FileTypeExtension=glv` / `File:MIMEType=video/mp4`
  // as `.glv` vs `M4A` as `.mov` (verified vs bundled 13.58, R11/F1). The
  // `%useExt` table has exactly this one entry, so no other fixture is needed.
  // 180 → 182 after PR #38 Codex R12 finding F1 [REAL-INPUT]: added two
  // synthetic adversarial QuickTime fixtures verified vs bundled, pinning the
  // default `LargeFileSupport => 1` (ExifTool.pm:1167) 64-bit extended-size
  // handling — `QuickTime_mdat64_moov.mov` (`ftyp` + a `size == 1` 64-bit
  // `mdat` that FITS + a trailing `moov`; the walker skips the 64-bit `mdat`
  // by its declared size and REACHES the trailing `moov` ⇒ full
  // Duration/TimeScale/dates/MatrixStructure/NextTrackID — the real >2GB-video
  // shape, QuickTime.pm:10062-10074) and `QuickTime_mdat64_large.mov` (a
  // `size == 1` `mdat` declaring 0x80000010, i.e. `lo > 0x7fffffff` — PARSED,
  // not rejected: MediaDataSize=2147483648 from the DECLARED 64-bit size +
  // `Truncated 'mdat' data at offset 0x14`, NOT the dead `LargeFileSupport not
  // enabled` branch the port emitted before the fix, R12/F1).
  // — after FORMATS.md row 24 lib/mxf: added `MXF.mxf` (bundled
  // t/images fixture, 7510 bytes) exercising the KLV walker + BER length
  // decoder + Primer local-id→UL map + local-set walker + the MXF-specific
  // value decoders + `Track<N>` group attribution ported in
  // `src/formats/mxf.rs`.
  // after Codex R1/F1: added `MXF_MultiDescriptor.mxf` (synthetic,
  // 2426 bytes) — a multi-essence MXF whose audio descriptors are reachable
  // ONLY through the hidden `MultipleDescriptor.FileDescriptors` /
  // `SourcePackage.PackageTracks` StrongReference edges, exercising the
  // complete structural-edge subset of `TAG_TABLE`.
  // after Codex R2/F1: added `MXF_BomBE.mxf` + `MXF_BomLE.mxf`
  // (each MXF.mxf with its UTF-16 `ApplicationName`/`TrackName` values
  // rewritten to carry a `FE FF` / `FF FE` byte-order mark, byte-length
  // preserved) — pinning `Charset.pm:203-206` BOM handling in the UTF-16
  // decoder: a BE BOM is stripped (not preserved as U+FEFF) and a LE BOM is
  // stripped AND the remainder decoded little-endian (not garbled).
  // after Codex R3/F1: added `MXF_DupDurationFF.mxf` (synthetic, two
  // same-InstanceUID `TimecodeComponent` sets — earlier valid `Duration`,
  // later all-`0xff`) — pinning that MXF.pm:98's `%duration` RawConv-`undef`
  // drop is a NON-entry (ExifTool.pm:9493 + MXF.pm:2666 `next unless $key`),
  // so the dropped value never participates in the reverse-order duplicate
  // pass and the earlier valid `Duration` survives.
  // after Codex R4/F1: added `MXF_Utf16EmbeddedNul.mxf` (`MXF.mxf`
  // with the UTF-16 `ApplicationName` `ExifTool` rewritten to `E\0ifTool` —
  // an in-band NUL followed by non-zero stale text) — pinning that
  // `Charset.pm:326`'s `Recompose` runs `s/\0.*//s` and TRUNCATES the UTF-8
  // output at the first NUL, so the oracle emits `"E"` (not `"EifTool"`).
  // ----- PR #36 / FORMATS.md rows 13-14 (Exif+GPS) ----------------------
  // The chronology below is from the lib/exif-gps branch (forked before
  // Flash/MXF/QuickTime landed in main, so its `139 → 149` collapses Real's
  // multi-step chain into one recap). The post-recap `149 → ...` lines
  // document the Exif/JPEG fixture additions; the active-count assertion
  // below was recomputed post-rebase to the actual fixture-count total
  // (main's Flash/MXF/QuickTime fixtures PLUS the Exif/JPEG additions).
  // 149 → 151 after FORMATS.md rows 13-14 lib/exif-gps: added the two
  // synthetic standalone-TIFF fixtures `Exif.tif` (IFD0 + ExifIFD + IFD1
  // chain — the camera-tag IFD machinery) and `ExifGPS.tif` (IFD0 + GPS
  // sub-IFD — the GPS coordinate ValueConv). The MakerNote-bearing
  // `Exif_makernote.tif` is formally accept-deferred — see `NOT_ACTIVE`.
  // 151 → 155 after PR #36 Codex R1 (F1/F2/F3): four adversarial
  // standalone-TIFFs — `Exif_badoffset_low.tif` (out-of-line value
  // offset < 8 ⇒ `Suspicious … offset` warning + tag dropped),
  // `Exif_badoffset_eof.tif` (offset + size past EOF ⇒ `Error reading
  // value …` warning + tag dropped), `Exif_truncated_ifd.tif` (IFD0
  // declares more entries than the file holds ⇒ `Bad IFD0 directory`
  // and the whole directory aborts), `Exif_focallength35.tif`
  // (FocalLengthIn35mmFormat 0xa405 — the no-decimal `"$val mm"`
  // PrintConv, distinct from FocalLength 0x920a's `sprintf("%.1f mm")`).
  // 155 → 161 after PR #36 Codex R2 (F1/F2/F3): six adversarial
  // standalone-TIFFs — `Exif_badformat_entry0.tif` (entry-0 bad format
  // code ⇒ `Bad format (99) for IFD0 entry 0` + directory abort),
  // `Exif_illegal_ifd0_size.tif` / `Exif_illegal_subifd_size.tif`
  // (`$bytesFromEnd` ∈ {1,3} ⇒ `Illegal … directory size (n entries)`
  // + abort, at IFD0 and a GPS sub-IFD), `Exif_gps_baddir.tif` (GPS
  // pointer past EOF ⇒ `Bad GPS directory`), `Exif_gps_badoffset.tif` /
  // `Exif_gps_eofoverrun.tif` (GPS-IFD warning tag names resolved
  // against `%GPS::Main` — 0x0002 = GPSLatitude, not InteropVersion).
  // 161 → 163 after PR #36 Codex R3 (F1/F2): two adversarial standalone-
  // TIFFs — `Exif_badformat_ifd1.tif` (entry-0 bad format in IFD0 with a
  // valid IFD1 next-IFD pointer ⇒ the `return 0` abort suppresses IFD1
  // too — no `IFD1:*` tags), `Exif_gps_proctext.tif`
  // (GPSProcessingMethod/GPSAreaInformation with the `ASCII\0\0\0` charset
  // prefix ⇒ `ConvertExifText` strips the prefix and decodes the text).
  // 163 → 164 after PR #36 Codex R4 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_unicode.tif` (big-endian TIFF carrying UTF-16LE `UNICODE\0`
  // GPSProcessingMethod with NO BOM + GPSAreaInformation with an LE BOM ⇒
  // `ConvertExifText`'s `Decode(...,'UTF16','Unknown')` seeds the order from
  // `GetByteOrder()` then flips on the Charset.pm distribution heuristic, so
  // both decode to ASCII text rather than mojibake).
  // 164 → 167 after PR #36 Codex R5 (F1): three adversarial standalone-TIFFs
  // exercising ExifIFD `UserComment` (0x9286), which is `Format => 'undef'` +
  // `RawConv => ConvertExifText` (Exif.pm:2497-2507) — the SAME RawConv the
  // GPS text tags use, but in the ExifIFD and WITHOUT the `gps` feature.
  // `Exif_usercomment_ascii.tif` (`ASCII\0\0\0` prefix ⇒ "Hello World", was
  // wrongly `Conv::None` ⇒ binary placeholder), `Exif_usercomment_unicode.tif`
  // (MM TIFF, `UNICODE\0` + UTF-16LE no-BOM ⇒ heuristic flip ⇒ "MANUAL"),
  // `Exif_usercomment_bom.tif` (MM TIFF, `UNICODE\0` + LE BOM ⇒ BOM pins LE
  // order ⇒ "Tokyo"). The `ConvertExifText` impl moved out of the gps-only
  // module into `exif::exiftext` (feature = "exif") so UserComment decodes
  // without `gps`.
  // 167 → 169 after PR #36 Codex R6 (F1): two adversarial standalone-TIFFs —
  // `Exif_usercomment_string.tif` / `Exif_usercomment_int8u.tif` — an ExifIFD
  // UserComment (0x9286) whose ON-DISK format code is `string` (2) / `int8u`
  // (1), the documented mis-writers (Exif.pm:2499). ExifTool's `Format =>
  // 'undef'` (Exif.pm:2500) is a READ-side override applied BEFORE `ReadValue`
  // (Exif.pm:6729-6744): it forces the value through `undef` so the on-disk
  // bytes are not NUL-trimmed, then `ConvertExifText` strips the 8-byte
  // `ASCII\0\0\0` prefix ⇒ "Hello World". Without it the `string` decode
  // truncates at the first NUL to "ASCII". The fix adds `tables::
  // format_override` (the `$$tagInfo{Format}` lookup) applied in the IFD
  // walker before `read_value`, keyed on `Format` (UserComment) not `Writable`
  // (GPS text tags carry only `Writable => 'undef'`, so a `string`-on-disk GPS
  // text tag IS NUL-trimmed by bundled — the contrast pins the scoping).
  // 169 → 170 after PR #36 Codex R7 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_datestamp.tif` — a GPS sub-IFD GPSDateStamp (0x001d) whose
  // ON-DISK format is `string` (2) but whose bytes use `\0` separators
  // (`2024\0 05\0 22\0`, the Casio EX-H20G variant, GPS.pm:312). The GPS table
  // sets `Format => 'undef'` (GPS.pm:312), a READ-side override (Exif.pm:6729-
  // 6744) that forces the undef re-read so the interior NULs survive ⇒ the
  // RawConv strips only the trailing run and `ExifDate` re-separates to
  // "2024:05:22". The R6 fix gated the override off for ALL GPS entries; R7
  // resolves it per-table (`gps::format_override(0x001d)` → `Format::Undef`),
  // honoring 0x001d while keeping the GPS text tags 0x001b/0x001c (only
  // `Writable => 'undef'`, no `Format`) NUL-trimmed exactly as bundled does.
  // 170 → 171 after PR #36 Codex R8 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_wrongfmt.tif` — an IFD0 GPSInfo pointer (0x8825) mis-encoded as
  // `string[4]` instead of an integer. GPSInfo carries `Flags => 'SubIFD'`
  // (Exif.pm:2134), so the offset-integrality check (Exif.pm:6747) warns
  // `Wrong format (string) for IFD0 0x8825 GPSInfo` and `next`-skips the entry
  // in default mode — the GPS sub-IFD is NOT walked. Pins the fix for a
  // silently-swallowed pointer (the would-be GPS IFD at the encoded offset is
  // never reached, so no GPS:* leaks); IFD0:Orientation still emits.
  // 171 → 172 after PR #36 Codex R9 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_int32s.tif` — an IFD0 GPSInfo pointer (0x8825) encoded as
  // `int32s` (format 9, a SIGNED integer) with a POSITIVE offset. `%intFormat`
  // (Exif.pm:125-136) lists `int32s => 9`, so the signed format passes the
  // offset-integrality gate (Exif.pm:6747) WITHOUT a warning and the pointer
  // is used as `Start => '$val'` — the GPS sub-IFD IS walked. Pins the fix for
  // the SubIFD-pointer extraction accepting `RawValue::I64` (not only `U64`);
  // bundled emits `GPS:GPSVersionID` = "2.3.0.0".
  // 172 → 173 after PR #36 Codex R10 (F1): one synthetic standalone-TIFF —
  // `Exif_multipage.tif` — a three-deep next-IFD chain IFD0 -> IFD1 -> IFD2.
  // ExifTool's `Multi` trailing-directory scan (Exif.pm:7202-7232) is a
  // `for (;;)` loop that re-reads `Get32u($dataPt, $dirEnd)` and increments
  // the directory number after each trailing IFD (`DirName .= $ifdNum + 1`,
  // Exif.pm:7215-7216). The R10 bug stopped the walker after IFD1 because
  // `walk_one_ifd` returned the next pointer only for `IfdKind::Ifd0`; the
  // fix follows the chain for `IfdKind::Ifd0 | IfdKind::Trailing(_)` and
  // numbers each trailing IFD (`Trailing(n)` → family-1 group `IFDn`), so
  // bundled's `IFD2:Compression` / `IFD2:Software` / `IFD2:Orientation` are
  // emitted.
  // 173 → 174 after PR #36 Codex R11 (F1): one synthetic standalone-TIFF —
  // `Exif_manyifd.tif` — a 66-deep next-IFD chain IFD0 -> ... -> IFD65.
  // ExifTool's `Multi` trailing-directory scan is an UNCAPPED `for (;;)`
  // loop (Exif.pm:7211). The R11 bug capped `walk_ifd_chain` at `0..MAX_IFDS`
  // (64) — counting IFD0, so IFD64/IFD65 were silently dropped from a valid
  // multipage TIFF. The fix removes the fixed cap (the seen-offset reprocess
  // guard keeps the `loop {}` finite) and widens `IfdKind::Trailing` to `u16`
  // so `IFDn` numbers past 64; bundled's `IFD64:Software` / `IFD65:Software`
  // are emitted.
  // 174 → 175 after PR #36 Codex R12 (F1): one synthetic standalone-TIFF —
  // `Exif_ifd65536.tif` — a 65537-deep next-IFD chain IFD0 -> ... -> IFD65536.
  // ExifTool numbers each trailing IFD with plain Perl arithmetic
  // `DirName .= $ifdNum + 1` (Exif.pm:7215-7216) — uncapped. The R12/F1 bug
  // stored the trailing-IFD number in a `u16` advanced with `saturating_add`,
  // so past IFD65535 it pinned at 65535 and mislabeled IFD65536 as IFD65535
  // (overwriting the real IFD65535 tags). The fix widens `IfdKind::Trailing`
  // to `u32` with an unsaturating `+ 1` and a 13-byte `IfdName` buffer, so
  // bundled's distinct `IFD65535:Software` / `IFD65536:Software` are emitted.
  // 175 → 176 after PR #36 Codex R12 (F2): one synthetic standalone-TIFF —
  // `Exif_gps_after_interop.tif` — IFD0's GPSInfo (0x8825) and ExifIFD's
  // InteropOffset (0xa005) BOTH point at one shared sub-IFD. ExifTool's
  // `%PROCESSED` reprocess guard (ExifTool.pm:9050-9061) is gated on
  // `$$dirInfo{DirLen}` being non-zero; IFD-pointer SubDirectories carry
  // `DirLen => 0`, so the guard never fires and ExifTool reprocesses the
  // shared offset as GPS (the Windows Phone 7.5 O/S bug, ExifTool.pm:9059).
  // The R12/F2 bug rejected any previously seen IFD offset, dropping all
  // GPS tags. The fix tracks each seen offset WITH its owning `IfdKind` and
  // allows the GPS-after-InteropIFD reprocess; the shared dir carries only
  // GPS IDs absent from `%InteropIFD` (GPSVersionID/GPSSatellites/
  // GPSMapDatum) so bundled's `GPS:*` tags emit with no Interop/Composite
  // golden noise.
  // 176 → 177 after PR #36 Codex R13 (F1): one synthetic standalone-TIFF —
  // `Exif_gps_shared_pointer.tif` — IFD0's ExifOffset (0x8769) AND GPSInfo
  // (0x8825) BOTH point at one shared sub-IFD. This is the GENERAL form of
  // the R12/F2 pointer-collision: ExifTool's `%PROCESSED` guard is gated on
  // a non-zero `DirLen` (ExifTool.pm:9052) and a standalone TIFF's
  // IFD-pointer SubDirectories carry `DirLen 0` (Exif.pm:7020-7026 resets
  // `$size` for an out-of-buffer subdirectory start), so the guard is
  // SKIPPED for EVERY IFD-pointer subdirectory — ExifTool reprocesses any
  // shared offset, not just GPS-after-InteropIFD. The R12/F2 carve-out
  // admitted only GPS-after-InteropIFD, so the GPS pass over an
  // ExifIFD-owned offset returned `None` and every GPS tag was dropped. The
  // re-modelled guard records only chain IFDs (IFD0/Trailing) in the
  // seen-offset loop breaker and reprocesses IFD-pointer subdirectory
  // revisits, rejecting only a true ancestor cycle (active recursion path).
  // Bundled emits `ExifIFD:Orientation` AND `GPS:GPSVersionID`, no warning.
  // 177 → 178 after PR #36 Codex R14 (F1): one adversarial standalone-TIFF —
  // `Exif_eofoverrun_chain.tif` — IFD0 entry 1 is an out-of-line value
  // (Software) whose `offset + size` runs past EOF, with a VALID entry 2
  // (Orientation) AFTER it AND a non-zero next-IFD pointer to a structurally
  // valid IFD1. A standalone TIFF carries a RAF (`DoProcessTIFF` sets
  // `RAF => $raf`, ExifTool.pm:8717; `ProcessExif` reads it, Exif.pm:6289),
  // so the out-of-line read takes the `if ($raf)` path (Exif.pm:6552); the
  // past-EOF `$raf->Read` fails (Exif.pm:6593) ⇒ `Error reading value for
  // IFD0 entry 1, ID 0x0131 Software` (Exif.pm:6594) ⇒ `return 0 unless
  // $inMakerNotes or $htmlDump or $truncOK` (Exif.pm:6602) — the WHOLE
  // directory aborts BEFORE the line-7202 trailing-IFD scan. The R14/F1 bug
  // recorded the warning but returned `true` (continue), so `IFD0:Orientation`
  // and the IFD1:* tags leaked. The fix returns `false` (abort) from
  // `walk_entry` on the EOF read-failure branch; the MakerNotes/truncOK
  // exemption never applies (this walker defers MakerNote parsing and emits
  // no TruncateOK tag). Bundled emits ONLY `IFD0:Make` + the warning.
  // 178 → 179 after PR #36 Codex R15 (F1): one standalone-TIFF —
  // `Exif_trailing_space.tif` — whose IFD0 Make/Model/Software/Artist and
  // ExifIFD SubSecTime* fields are space-padded; bundled trims the trailing
  // whitespace (`RawConv s/\s+$//`) / trailing spaces (`ValueConv s/ +$//`) in
  // both -j and -n, so the port must too (else duplicate camera/software
  // facets). Exif.pm:585/599/906/925 + 2543/2552/2560.
  // 179 → 180 after PR #36 Codex R16 (F1): the REAL camera-JPEG fixture
  // `ExifGPS.jpg` (bundled `t/images/GPS.jpg`) — the JPEG container front-end
  // (`src/exif/jpeg.rs`) walks the markers, dispatches the `APP1` `Exif\0\0`
  // segment to ProcessTIFF → ProcessExif (ExifTool.pm:7736-7783), and the
  // typed `ExifMeta` carries the full IFD0/ExifIFD/GPS/IFD1 set. This is the
  // first real-input (non-synthetic) Exif fixture and the core product
  // capability (camera photos read their Make/Model/DateTime/GPS).
  // 180 → 182 after PR #36 Codex R17: two JPEG-container fixtures.
  //  - `JPEG_malformed_app1_exif.jpg` (R17/F1) — a valid JPEG whose `APP1`
  //    `Exif\0\0` block is NOT a valid TIFF; bundled `ProcessJPEG`
  //    `SetFileType`s it `JPEG` (ExifTool.pm:7304) regardless of the Exif arm
  //    and `Warn`s `Malformed APP1 EXIF segment` (ExifTool.pm:7783). The JPEG
  //    container is ACCEPTED — never mis-rejected into a finalization error.
  //  - `JPEG_two_app1_exif.jpg` (R17/F2) — a JPEG with two INDEPENDENT `APP1`
  //    Exif blocks (each a self-contained `Exif\0\0II\x2a\0` TIFF); the marker
  //    walk continues after the first (ExifTool.pm:7821 `next`) so both
  //    contribute tags (`IFD0:Make` from block 1, `IFD0:Model` from block 2).
  // 182 → 183 after PR #36 Codex R18 (F2): `JPEG_unknown_header.jpg` — a
  // valid JPEG behind a 4-byte unknown leading header. The file-type
  // detector's terminal JPEG candidate carries a non-zero `header_skip`
  // (`ExifTool.pm:3026-3034`); the Exif dispatch slices `bytes` at that offset
  // and rebases the embedded Exif `Base` by it. Pre-fix the candidate was
  // detected then mis-rejected into a finalization error.
  // 265 → 266 after PR #68 (TIFF standalone container): `Exif_pagecount.tif`
  // — a two-page TIFF whose IFDs carry `SubfileType` (0x00fe) values (IFD0=0
  // full-resolution, IFD1=2 single page of multi-page) that trip the bundled
  // `MultiPage` flag and the synthesized `File:PageCount` (ExifTool.pm:
  // 8756-8757). Pins the PageCount `RawConv` tracker + the standalone-TIFF
  // emit gate; embedded TIFF blocks (PNG `eXIf`, JPEG `APP1`) suppress the
  // emit (`TIFF_TYPE == 'TIFF'`).
  // 266 → 267 after #162 Codex R1 (TIFF subtype PageCount gate):
  // `Exif_pagecount.dng` — the SAME multi-page bytes under a TIFF-rooted SUBTYPE
  // extension. Bundled detects `FileType = DNG`, `TIFF_TYPE = DNG`, so it emits
  // NO `File:PageCount` (ExifTool.pm:8767) while still extracting every IFD tag.
  // Pins the standalone-TIFF arm gating PageCount on the candidate `Parent`
  // (not a hard-coded `true`).
  // 267 → 268 after the Canon CRW (CIFF) container — Phase 1:
  // `CanonRaw_min.crw` — a HAND-CRAFTED minimal CIFF heap (the real
  // `t/images/CanonRaw.crw` emits ~25 camera `Composite:*` tags + XMP this
  // port cannot emit, so it cannot be a byte-exact fixture). The crafted heap
  // exercises the `ProcessCRW` header validate + the recursive
  // `ProcessCanonRaw` HEAP walker (nested auto-subdirectory + value-in-dir
  // record) + the `CanonRaw::Main` scalar records (`Make`/`Model`/`FileFormat`
  // PrintHex/`CanonModelID` `%canonModelID`/…), DELIBERATELY excluding every
  // Composite-trigger combo so the bundled `-G1 -j`/`-n` goldens carry ONLY
  // File:/CanonRaw: keys.
  // 268 → 270 after the Canon CRW completion (`CanonRaw::Main` remaining scalar
  // + structural records, `Canon::SensorInfo` + `Canon::ColorBalance`):
  // `CanonRaw_records.crw` (the rest of the scalar table — TargetImageType/
  // RecordID/FileNumber/UserComment/CanonFileDescription/MeasuredEV/
  // SerialNumber/ColorTemperature/ColorSpace — plus the TimeStamp/DecoderTable/
  // RawJpgInfo structural sub-tables + a Canon::SensorInfo sub-table) and
  // `CanonRaw_colorbalance.crw` (the Canon::ColorBalance WB_RGGBLevels quads).
  // Both are CRAFTED Composite-free CIFF heaps (verified via `perl exiftool
  // -G1 -j` to carry only File:/CanonRaw:/Canon: keys).
  // 270 → 271 after porting the omitted `CanonRaw::Main` binary sub-tables
  // (the Codex CRW finding): `CanonRaw_omitted_records.crw` — a CRAFTED
  // Composite-free CIFF heap exercising `ExposureInfo` (0x1818 →
  // ExposureCompensation; ShutterSpeedValue/ApertureValue are unit-tested,
  // omitted here as ANY emitted ApertureValue/ShutterSpeedValue would
  // synthesize a `Composite:Aperture`/`Composite:ShutterSpeed`), `FlashInfo`
  // (0x1813 → FlashGuideNumber/FlashThreshold), `WhiteSample` (0x1030 → the
  // WhiteSample* positions + the `int16u[4]` `BlackLevels`, gated on the
  // `Canon::Validate` length check), AND a `TimeStamp` (0x180e) with a
  // FRACTIONAL `TimeZoneCode` (19800 ⇒ 5.5 via the FLOAT `$val/3600`). Verified
  // via `perl exiftool -G1 -j`/`-n` to carry only File:/CanonRaw: keys.
  // 271 → 272 after the CRW SubDirectory read-gate fix (`CanonRaw.pm:707-709`:
  // a record whose tag has a `SubDirectory` is read REGARDLESS of size):
  // `CanonRaw_whitesample_big.crw` — a CRAFTED Composite-free CIFF heap whose
  // `WhiteSample` (0x1030) block is 600 bytes (> the 512 read threshold), with
  // the named fields up front and a 482-byte arbitrary "encrypted" tail
  // (`CanonRaw.pm:598`). Before the fix the 600-byte block was dropped to a
  // `(Binary data 600 bytes)` placeholder, losing every WhiteSample named tag;
  // the oracle (and now the port) read the full block. The golden CONTAINS the
  // WhiteSample* + `BlackLevels` tags, proving the >512 SubDirectory block was
  // read. Verified via `perl exiftool -G1 -j`/`-n` to carry only File:/
  // CanonRaw: keys.
  // 272 → 273 after the FINAL CRW coverage gap (the remaining `CanonRaw::Main`
  // scalar tags + the omitted NAMED no-conv records): `CanonRaw_scalars.crw` —
  // a CRAFTED Composite-free CIFF heap carrying `ShutterReleaseMethod` (0x1010,
  // PrintConv), `ShutterReleaseTiming` (0x1011, PrintConv), `ReleaseSetting`
  // (0x1016, no conv), `SelfTimerTime` (0x1806, `$val/1000` ValueConv + `"$val
  // s"` PrintConv), `TargetDistanceSetting` (0x1807, `Format => 'float'` +
  // `"$val mm"` PrintConv), plus `NullRecord` (0x0000, int8u[]), `FreeBytes`
  // (0x0001, `Binary => 1` placeholder), and `CanonColorInfo1`/`CanonColorInfo2`
  // (0x0032/0x102c, the NAMED no-conv `%crwTagFormat{tagType}` arrays). Verified
  // via `perl exiftool 13.59 -G1 -j`/`-n` to carry only File:/CanonRaw: keys.
  // This completes the `%CanonRaw::Main` record coverage.
  // 273 → 275 after the CRW value-in-directory + zero-length edge-case coverage
  // (Codex CRW R4): `CanonRaw_valueindir.crw` — a CRAFTED Composite-free CIFF
  // heap whose 5 R3 scalars + `BaseISO` are stored inline via `valueInDir`
  // (`CanonRaw.pm:692-699`) plus an inline `CanonColorInfo2` array record (the
  // `valueInDir` forced `$count = 1` ⇒ the bare first word `11`, not the 4-word
  // array). `CanonRaw_zerolen.crw` — a CRAFTED Composite-free CIFF heap whose
  // NAMED no-conv ARRAY records (`NullRecord`/`CanonColorInfo1`/`CanonColorInfo2`)
  // are each zero-length ⇒ `""` (`ReadValue` `$count == 0`, `ExifTool.pm:6296`)
  // and whose binary LEAVES (`RawData`/`FreeBytes`) are zero-length ⇒ the
  // `(Binary data 0 bytes …)` placeholder. Both verified via `perl exiftool
  // 13.59 -G1 -j`/`-n` to carry only File:/CanonRaw: keys.
  //
  // ----- FORMATS.md row 12b (PLIST, binary + XML) — lib/plist -----------
  // The PLIST chronology below is from the lib/plist branch (forked before the
  // Exif/PNG/MakerNotes waves landed in main); its running `149 → … → 283`
  // counts are RELATIVE to that older base. The post-rebase ACTIVE total is
  // main's 275 PLUS the PLIST ACTIVE fixtures (the absolute figure pinned by
  // `EXPECTED_ACTIVE_FIXTURES` below, recomputed against the live golden dir).
  // 149 → 151 after FORMATS.md row 12b lib/plist: added `PLIST-bin.plist`
  // + `PLIST-xml.plist` (bundled t/images fixtures, 351 / 795 bytes) —
  // the binary `bplist00` decoder and the XML-plist element scanner, both
  // flattening nested `<dict>` keys into `parent/child` tags.
  // 151 → 154 after Codex R1 (lib/plist): added 3 adversarial PLIST
  // fixtures pinning F1 (XML array-of-dict recursion), F2 (binary array
  // typed-value preservation), and F3 (binary Tag-prefix guard).
  // 154 → 157 after Codex R2 (lib/plist): added 3 adversarial PLIST
  // fixtures — `plist_synth_bin_date.plist` (R2 F1: the faithful binary
  // `<date>` localtime branch, golden pinned `TZ=UTC`),
  // `plist_synth_xml_short_keys.plist` (R2 F3: XML-path `AddTagToTable`
  // Tag-prefix normalization), and `plist_synth_bin_array_of_dict.plist`
  // (R2 F4: binary array-of-dict child-tag extraction). The 4th R2 fixture
  // `plist_aae_compressed.aae` (R2 F2) is formally accept-deferred — listed
  // in `NOT_ACTIVE`, NOT counted here.
  // 157 → 162 after Codex R3 (lib/plist): added 5 adversarial PLIST
  // fixtures — `plist_synth_xml_static_table.plist` +
  // `plist_synth_xml_gps_longitude.plist` (R3 F1: the `%PLIST::Main` static
  // table — fixed Name, DateTimeOriginal ValueConv, Duration/GPS ToDMS
  // PrintConv), `plist_synth_bin_uint64.plist` (R3 F2: an unsigned `Get64u`
  // integer above `i64::MAX`), `plist_synth_bin_nested_array_dict.plist`
  // (R3 F3: dict child tags at every nested-array level), and
  // `plist_synth_bin_frac_date.plist` (R3 F4: fractional binary-date
  // rounding).
  // 162 → 168 after Codex R4 (lib/plist): added 6 adversarial PLIST
  // fixtures for the two ConvertUnixTime fractional-rounding fixes —
  // R4 F1 (binary `<date>` half-to-EVEN rounding, ExifTool.pm:6783):
  // `plist_synth_bin_halfeven_date_half.plist` (exact `.5` ⇒ no carry,
  // the bug `f64::round()` got wrong), `…_halfup.plist` (just past the
  // tie ⇒ carry) and `…_neghalf.plist` (negative half ⇒ floor); and
  // R4 F2 (MODD `DateTimeOriginal` ValueConv passing the FLOAT into
  // ConvertUnixTime, PLIST.pm:73): `plist_synth_xml_frac_dto_pos.plist`,
  // `…_half.plist` and `…_neg.plist` (positive / half / negative
  // fractional days — the prior port truncated to i64 before converting).
  // 168 → 171 after Codex R5 (lib/plist): added 3 adversarial PLIST
  // fixtures — `plist_synth_xml_modd_content.xml` (R5 F1: the
  // `XMLFileType=ModdXML` content override → `OverrideFileType('MODD')`,
  // gated on `FILE_TYPE eq 'XMP'` via the `.xml`-family extension), and
  // `plist_synth_xml_nested_scalar_array.plist` +
  // `plist_synth_xml_nested_array_of_dict.plist` (R5 F2: nested XML `<array>`
  // recursion — scalars stored under the bare key, dicts accruing one empty
  // key-slot per array level, ⇒ `XML:Outer` and `XML:TopInner`).
  // 171 → 174 after Codex R6 (lib/plist event-stream rework): added 3
  // adversarial PLIST fixtures — `plist_synth_xml_mixed_array.plist` (R6 F2:
  // a heterogeneous XML `<array>` of dict + scalar members — the sticky
  // `@keys` event state so a scalar after a dict inherits the dict's last key
  // ⇒ `XML:TopFoo="B"` not `XML:Top="B"`), `plist_synth_xml_empty_containers
  // .plist` (R6 F3: empty `<dict/>`/`<array/>` surface as `XML:<Tag>=""`), and
  // `plist_synth_xml_modd_array.xml` (R6 F1: an array-emitted top-level
  // `XMLFileType=ModdXML` still drives the MODD override).
  // 174 → 179 after Codex R7 (lib/plist): added 5 adversarial PLIST
  // fixtures — `plist_synth_bin_uid5.plist` / `…_uid9.plist` /
  // `…_uid16.plist` (R7 F1: binary type-8 UID widths `%readProc` does NOT
  // cover — 5/9 bytes ⇒ a `0x…` hex string, 16 bytes ⇒ an ASF GUID via
  // `ASF::GetGUID`, PLIST.pm:286-290); and `plist_synth_xml_comment_fake
  // _root.plist` + `plist_synth_xml_comment_in_container.plist` (R7 F2:
  // token-aware XML tag scan — a commented fake `<plist>` does not shadow
  // the real root, and a `<!-- <array> -->` inside a container does not
  // mis-balance the nesting depth).
  // 179 → 182 after Codex R8 (lib/plist): added 3 adversarial PLIST
  // fixtures — `plist_synth_xml_scalar_comment.plist` (R8 F1: an XML
  // comment inside a scalar value is stripped via the XMP.pm `wasComment`
  // close-scan signal ⇒ `XML:Title="foobar"`), `plist_synth_xml_data_ws
  // _hex.plist` (R8 F2: a whitespace-wrapped `<data>` payload fails the
  // direct `/^[0-9a-f]+$/` hex test and decodes via Base64), and
  // `plist_synth_xml_slowmotion_flags.plist` (R8 F3: the slowMotion
  // `*Flags` BITMASK `PrintConv` — `DecodeBits` prints `Valid` / `Valid,
  // Has been rounded`).
  // 182 → 184 after Codex R9 (lib/plist): added 2 adversarial PLIST
  // fixtures — `plist_synth_xml_multiline_comment.plist` (R9 F1: the
  // XMP.pm:4181 `s/<!--.*?-->//g` has NO `/s` flag, so the regex `.` does
  // not cross a newline — a MULTILINE `<!--…-->` run is preserved verbatim
  // while a single-line one is stripped, in both a scalar value and a
  // `<key>`), and `plist_synth_xml_slowmotion_flags_string.plist` (R9 F2:
  // the slowMotion `*Flags` BITMASK `PrintConv` runs `DecodeBits` over a
  // `<string>` leaf too — `"3"` ⇒ `Valid, Has been rounded`, `"abc"`
  // numifies to 0 ⇒ `(none)`).
  // 184 → 187 after Codex R10 (lib/plist): added 3 adversarial PLIST
  // fixtures — `plist_synth_xml_comment_non_ascii.plist` (R10 F1: the
  // XMP.pm:4181 `s/<!--.*?-->//g` byte-walk must not panic on a non-ASCII
  // char inside an inline single-line comment — `<!-- café -->` in a
  // `<key>` and `<!-- résumé -->` in a `<string>` are stripped ⇒
  // `XML:Title="foobar"`); and `plist_synth_xml_slowmotion_flags_exponent
  // .plist` + `…_overflow.plist` (R10 F2: the slowMotion `*Flags`
  // `DecodeBits` numifies each word the Perl `&` way — `1e2`/`-1e2` honour
  // the exponent ⇒ 100/-100, `18446744073709551615`/`9e99` stay exact /
  // saturate ⇒ every low-32 bit set, where a digit-only `i64` scan got
  // `1` / `0`).
  // 187 → 189 after Codex R11 (lib/plist): added 2 adversarial PLIST fixtures
  // for the content-override-keyed-on-EXACT-RAW-tag-ID fixes —
  // `plist_synth_xml_xmlfiletype_collide.xml` (R11 F1: the colliding raw key
  // `xMLFileType` generates the SAME emitted name `XMLFileType` but its raw ID
  // differs ⇒ the `XMLFileType` RawConv is absent and NO `OverrideFileType`
  // fires ⇒ `File:FileType=PLIST` with `XML:XMLFileType=ModdXML`), and
  // `plist_synth_xml_aae_override.xml` (R11 F2: the `%plistType` AAE override
  // `OverrideFileType($plistType{adjustmentBaseVersion})` = AAE, PLIST.pm:42/
  // :225 — an ACTIVE non-compressed `.xml` plist ⇒ `File:FileType=AAE`,
  // `File:MIMEType=application/vnd.apple.photos`; distinct from the
  // extension-typed `plist_aae_compressed.aae` in `NOT_ACTIVE`).
  // 189 → 190 after Codex R12 F1 (lib/plist): added
  // `plist_synth_xml_utf8bom.plist` — a valid XML plist carrying a leading
  // UTF-8 BOM (`EF BB BF`). Bundled reaches it via the XMP path (the XMP
  // `%magicNumber` accepts the BOM that the PLIST `%magicNumber` does not,
  // ExifTool.pm:1045 vs :1015; `ProcessXMP` then content-sniffs `<plist>`
  // and routes to `PLIST::FoundTag`, XMP.pm:4349/4385). The port's `parse_inner`
  // now skips the BOM at the XML gate and the engine routes a BOM-prefixed XML
  // `<plist>` candidate (detected as XMP) to `ProcessPlist` ⇒ `File:FileType=
  // PLIST`, `application/xml`, with nested-dict key flattening intact.
  // 190 → 191 after Codex R14 F1 (lib/plist): added `plist_trunc_bin.plist` —
  // a truncated `bplist00` (8-byte magic, no trailer). Bundled recognizes the
  // magic (PLIST.pm:480) and emits the family-1 `PLIST:Error` (PLIST.pm:485-486
  // inside `SET_GROUP1='PLIST'`, :484) while finalizing as PLIST
  // (`application/x-plist`, :483/:489); the pre-fix port dropped it to
  // `Ok(None)`. The whole binary-decode-failure class maps to this same error
  // at the `decode_binary` chokepoint (oracle-verified for the trailer / topObj
  // / intSize / offset-table modes).
  // 191 → 193 after Codex R15 F1 (lib/plist): added 2 adversarial PLIST
  // fixtures for the binary type-4 `data` size threshold — PLIST.pm:300
  // (`if ($size < 1000000 or $et->Options('Binary'))`) reads a binary `data`
  // payload only below 1 000 000 bytes; at or above it PLIST.pm:302-303 stores
  // a length-only `"Binary data $size bytes"` placeholder WITHOUT a
  // `$raf->Read` (the `else` branch — also not bounds-checked).
  // `plist_synth_bin_data_boundary.plist` claims a data object AT exactly
  // 1 000 000 bytes and `plist_synth_bin_data_oversize.plist` claims one at
  // 2 000 000; both render `(Binary data N bytes...)` with the TRUE `N`. The
  // port now stores a length-only `PlistLeaf::DataLen` instead of copying the
  // multi-MB payload (the pre-fix `dec.data.get(..).to_vec()` both allocated
  // and — for these truncated fixtures — dropped the tag on the out-of-range
  // slice). The whole >= 1 000 000 class maps to this same length-only path.
  // 193 → 196 after Codex R17 F1 (lib/plist): added 3 adversarial PLIST
  // fixtures for the XML-leaf raw-scalar class-sweep — PLIST.pm's XML path
  // (`FoundTag`, PLIST.pm:171-186) never type-parses NOR canonicalizes a leaf:
  // it stores the UNESCAPED scalar text verbatim. `plist_synth_xml_real_
  // nonfinite.plist` has `<real>inf</real>` / `<real>-inf</real>` / `<real>nan
  // </real>` — the pre-fix port `parse::<f64>()`'d these to a NON-FINITE `f64`
  // and later serialized the titlecase Perl-NV string (`Inf` / `-Inf` / `NaN`),
  // a VALUE change vs the oracle's verbatim `"inf"` / `"-inf"` / `"nan"`.
  // `plist_synth_xml_integer_real_raw.plist` covers `<real>`/`<integer>`
  // raw-text preservation (`<real>1.50</real>` keeps its trailing zero,
  // `<integer>007</integer>` keeps its leading zero, `0x10` / `1.4e2` /
  // `" 3.0 "` stay verbatim). `plist_synth_xml_date_raw.plist` covers the
  // `<date>` leaf: PLIST.pm:180-181 runs `ConvertXMPDate($val)` on the raw
  // untrimmed scalar (XMP.pm:4178-4181 trims only an `rdf:Description` prop) —
  // the pre-fix port's extra `.trim()` made a whitespace-wrapped `<date>` body
  // match `ConvertXMPDate`'s anchored regex and get rewritten, changing the
  // VALUE; the fix drops the trim so `<date> … </date>` passes through raw.
  // The whole XML-leaf class now stores `PlistValue::Str`/`::Date` from the
  // verbatim body and parses on demand ONLY for a `%PLIST::Main` static
  // `ValueConv`/`PrintConv` (`leaf_numeric`, gated on Perl's `IsFloat`). The
  // binary decoder is unaffected — a binary type-1/2 object IS genuinely typed
  // (PLIST.pm:271-274).
  // 278 → 283 after Codex R20 (lib/plist round 1) — 3 real-input value-parity
  // findings each adding ACTIVE fixtures:
  //   R20 F1: `plist_aae_compressed.aae` UN-ignored (CompressedPLIST sub-
  //     directory, PLIST.pm:142-146/228-241): `adjustmentData` is now in
  //     `PLIST_MAIN` (was deliberately ABSENT). XML walker intercepts
  //     `<data>` under raw key `adjustmentData`, decodes Base64, then routes
  //     through `process_compressed_plist`: `bplist00`-prefixed payloads
  //     short-circuit inflate (PLIST.pm:228); otherwise `miniz_oxide::
  //     inflate::decompress_to_vec` (RAW DEFLATE, matches `IO::Uncompress::
  //     RawInflate`). Inflated bytes re-enter `decode_binary`; tags carry
  //     `group_override = Some("PLIST")` so the family-1 group switches mid-
  //     walk (PLIST.pm:484 `SET_GROUP1='PLIST'`).
  //   R20 F2: `plist_synth_ucs2be_legacy.plist` ADDED — `\xfe\xff\x00`-magic
  //     legacy plist (PLIST.pm:494-499). Bundled emits `ExifTool:Error:
  //     "Old PLIST format currently not supported"` with NO `File:FileType`
  //     triplet (the UCS-2BE branch never calls `SetFileType`). Port routes
  //     at the `finalization_error` seam — `ProcessPlist::parse` rejects the
  //     body, the engine candidate loop exhausts, and finalization short-
  //     circuits the `File format error` arm.
  //   R20 F3: 3 binary-dict consecutive-duplicate-key fixtures —
  //     `plist_synth_bin_dup_consec.plist` (root dict `{a,a,b}` ⇒
  //     `PLIST:TagA=[v1,v2], PLIST:TagB=v3`), `…_nested.plist` (nested dict
  //     under dict, `{x:{a,a}, b}` ⇒ `PLIST:XA=[v1,v2], PLIST:TagB=v3`), and
  //     `…_nonconsec.plist` (negative case `{a,b,a}` ⇒ TagMap last-wins,
  //     `PLIST:TagA=v3, PLIST:TagB=v2`). `walk_tree`'s Dict branch now
  //     routes pairs through a scratch buffer + `fold_consecutive_lists`,
  //     faithful to PLIST.pm:362-378 `LastPListTag`/`LIST_TAGS`.
  // ----- FORMATS.md row 26 (RIFF / AVI) ---------------------------------
  // 327 → 328 after FORMATS.md row 26 lib/riff: added `RIFF.avi` (bundled
  // t/images fixture, 1262 bytes, Canon MotionJPEG 2003 AVI) exercising
  // the RIFF/AVI walker + sub-tables (Info / Hdrl / Stream / AVIHeader /
  // StreamHeader / AudioFormat + inline BMP-strf VideoFormat) ported in
  // `src/formats/riff.rs`. Golden-migrated onto the `Taggable`/`Project`
  // engine during the rebase onto golden main.
  // 328 → 332 after the Codex R1 audit fixes (4 crafted WAVs):
  //   * `RIFF_wav_extensible.wav` — full `%audioEncoding` (`0xfffe`
  //     "Extensible", RIFF.pm:333);
  //   * `RIFF_info_latin1.wav` — default `'Latin'`/cp1252 INFO decode
  //     (RIFF.pm:1788/1829);
  //   * `RIFF_info_casio.wav` — `ISFT` Casio embedded-NUL + `ICRD` date
  //     ValueConvs (RIFF.pm:853/873);
  //   * `RIFF_truncated_fmt.wav` — truncated-chunk guard + corruption
  //     warning (RIFF.pm:2150/2216).
  // 332 → 334 after the Codex R2 audit fixes (2 crafted WAVs):
  //   * `RIFF_cset_info.wav` — CSET binary SubDirectory (`CodePage`/
  //     `CountryCode`/`LanguageCode`/`Dialect`, RIFF.pm:1063-1073) + the
  //     `Unsupported character set (1252)` warning (ExifTool.pm:6359-6363) +
  //     the raw-byte `?` rendering (`FixUTF8`, NOT U+FFFD): `IART`
  //     `Caf\xe9\xff Test` ⇒ `"Caf?? Test"`;
  //   * `RIFF_info_movieid.wav` — the remaining `%RIFF::Info` entries +
  //     conversions: `TITL`/`YEAR`/`COMM` (MovieID), `TLEN` (`$val/1000` +
  //     `"$val s"`), `TCOD`/`TCDO` (`$val*1e-7` + `ConvertTimecode`), `STAT`
  //     (list PrintConv), `DTIM` (FILETIME → `ConvertUnixTime`), `IAS1`/`IBSU`
  //     (Morgan), `DISP`/`TRCK` (Sound Forge) — RIFF.pm:897-1000.
  // 334 → 335 after the Codex R3 audit fix (1 crafted WAV):
  //   * `RIFF_cset0_info.wav` — CSET `CodePage=0` falls back to the default
  //     `'Latin'` charset (RIFF.pm:1784-1789 truthiness gate: `$$et{CodePage}`
  //     of `0` is FALSY ⇒ `$charset = 'Latin'`), so `IART=Caf\xe9` decodes
  //     through cp1252 to `"Café"` with NO `ExifTool:Warning` — exactly like
  //     no CSET at all. Distinguishes 0 (Latin) from a non-zero unsupported
  //     code page (raw passthrough + warning, the `RIFF_cset_info.wav` case).
  // 335 → 336 after the Codex R4 audit fix (1 crafted WAV):
  //   * `RIFF_cset_reset_info.wav` — a REPEATED CSET: `CodePage=1252` THEN
  //     `CodePage=0` THEN `IART=Caf\xe9`. The `CodePage` RawConv overwrites
  //     `$$et{CodePage}` on EVERY CSET (RIFF.pm:1067-1069) and the gate uses
  //     the LATEST value (RIFF.pm:1784-1789), so the trailing `0` RESETS the
  //     prior `Raw(1252)` back to Latin: `IART` decodes through cp1252 to
  //     `"Café"`, `RIFF:CodePage=0`, NO `ExifTool:Warning` (the R3 fix only
  //     assigned on the non-zero CSET, leaving a stale `Raw(1252)` → `Caf?` +
  //     warning; R4 assigns on EVERY CSET).
  // 336 → 339 after Golden-v2 Phase B.1.5 (group-scoped `<group>:Warning`
  // tags + the Matroska/MXF dropped-warning + illegal-float-Duration fixes):
  // added 3 crafted fixtures —
  //   * `Matroska_illegal_float_size.mkv` — the `Illegal float size`
  //     group-scoped `Info:Warning` TAG (Matroska.pm:1179) + the
  //     undef→ValueConv `Info:Duration: 0` leaf (NOT `NaN`);
  //   * `Matroska_truncated_header.mkv` — the document `ExifTool:Warning`
  //     `Truncated Matroska header` (Matroska.pm:1006) with NO `File:*`
  //     triplet (`return 1` before `SetFileType`);
  //   * `MXF_bad_array.mxf` — the group-scoped `MXF:Warning`
  //     `Bad array or batch size` (MXF.pm:2528, under `SET_GROUP1 = 'MXF'`).
  // 339 → 341 after Golden-v2 Phase B R1 (group-scoped `<group>:Warning` tags
  // moved IN-STREAM + the priority-0 `Warning`/`Error` first-wins dedup):
  // added 2 crafted MKV fixtures pinning a `$et->Warn` `Info:Warning` colliding
  // with a real same-group SimpleTag `Warning` —
  //   * `Matroska_warning_collision.mkv` — illegal-float Duration (diagnostic)
  //     WALK-FIRST, then the SimpleTag ⇒ survivor `"Illegal float size (3)"`;
  //   * `Matroska_warning_collision_rev.mkv` — SimpleTag WALK-FIRST, then the
  //     illegal-float Duration ⇒ survivor `"from-simpletag"` (the case the
  //     pre-fix run_diagnostics-last path got wrong).
  // (Group-scoped `<group>:Warning`/`<group>:Error` are now emitted IN-STREAM
  // as ordinary TAGs by each format's `tags()` — like QuickTime's
  // `Track<N>:Warning` — so the typed-serde path matches the writer + golden;
  // only DOCUMENT-level `ExifTool:Warning`/`:Error` still ride `run_diagnostics`.)
  // ----- FORMATS.md row 25 (M2TS / AVCHD) -------------------------------
  // 343 → 344 after FORMATS.md row 25 lib/m2ts (rebased onto golden-v2 main):
  // added `M2TS.mts` (bundled `t/images/M2TS.mts`, a Canon AVCHD camcorder
  // file). Exercises the MPEG-2 TS / BDAV packet walker (probe + PAT/PMT/PES
  // demux), the AC-3 descriptor + PES sample-rate decode, and the M2TS → H.264
  // PES-payload forward into the existing `H264::ParseH264Video` port
  // (M2TS.pm:343-345). Golden-migrated onto the `Taggable`/`Project` engine
  // (the M2TS Meta emits its own `M2TS:*` / `AC3:*` tags and chains the nested
  // H.264 sub-Meta's `tags()` stream).
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = active_fixtures();
  assert_eq!(
    fixtures.len(),
    EXPECTED_ACTIVE_FIXTURES,
    "expected exactly the {EXPECTED_ACTIVE_FIXTURES} active conformance fixtures, found {}: {:?}",
    fixtures.len(),
    fixtures
  );

  let mut failures: Vec<String> = Vec::new();

  for fixture in &fixtures {
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
    let golden_j = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.json: {e}"));
    let golden_n = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.n.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.n.json: {e}"));

    // Tags whose value diverges from bundled under a deferred subsystem are
    // dropped from BOTH sides (the golden keeps the matching `-x`); see
    // [`FIXTURE_EXCLUDED_KEYS`]. Empty for the vast majority of fixtures.
    let excluded = excluded_keys_for(fixture);

    for (mode, print_on, golden) in [("j", true, &golden_j), ("n", false, &golden_n)] {
      let typed = drop_keys(&typed_serde_document(fixture, &data, print_on), excluded);
      let writer = drop_keys(&extract_info(fixture, &data, print_on), excluded);
      let golden = drop_keys(golden, excluded);

      // typed serde == writer path.
      if let Err(e) = json_equivalent(&typed, &writer) {
        failures.push(format!(
          "[{mode}] {fixture}: typed-serde != writer-path: {}\n  typed:  {typed}\n  writer: {writer}",
          e.message()
        ));
      }
      // typed serde == golden.
      if let Err(e) = json_equivalent(&typed, &golden) {
        failures.push(format!(
          "[{mode}] {fixture}: typed-serde != golden: {}\n  typed:  {typed}\n  golden: {golden}",
          e.message()
        ));
      }
    }
  }

  assert!(
    failures.is_empty(),
    "STAGE-1 PARITY CHECKPOINT failed for {} case(s):\n{}",
    failures.len(),
    failures.join("\n")
  );

  eprintln!(
    "=== STAGE-1 PARITY CHECKPOINT: typed-serde == writer == golden for all {} fixtures, both -j and -n ===",
    fixtures.len()
  );
}
