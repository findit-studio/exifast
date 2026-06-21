#!/usr/bin/env bash
# Regenerate golden JSON for one fixture using the bundled Perl ExifTool.
# Usage: tools/gen_golden.sh <fixture-name-relative-to-tests/fixtures>
#
# Env:
#   EXIFTOOL    path to the `exiftool` Perl script
#               (default: <repo>/../exiftool/exiftool — the sibling checkout)
#   GOLDEN_DIR  directory to write <fix>.json / <fix>.n.json into
#               (default: <repo>/tests/golden)
#   EXCLUDE     extra `-x …` exclusions applied to EVERY run (see below)
#   EE          when set to a non-empty value, ALSO emit the timed-metadata
#               (`ExtractEmbedded`/`-ee`) oracle goldens for this fixture:
#                 <fix>.ee.json     (`-ee`, family-1 groups — same COMMON flags)
#                 <fix>.ee.g3.json  (`-ee -G3:1`, adds the `Doc<N>:` family-3
#                                    document axis for per-fix timed samples)
#               This is PURELY ADDITIVE: the `.ee.*` goldens are not part of the
#               both-standard-goldens active conformance set (which requires
#               BOTH `<fix>.json` AND `<fix>.n.json`); they pin the bundled
#               `-ee` truth for the QuickTime timed-metadata (GPS) stream, which
#               the default (non-`-ee`) runs never reach. The default path is
#               UNCHANGED when EE is unset/empty.
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: $0 <fixture-name>" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Default ExifTool is anchored to the repo (the sibling checkout), NOT the
# caller's CWD, so the script works regardless of where it is invoked from.
EXIFTOOL="${EXIFTOOL:-$ROOT/../exiftool/exiftool}"
FIX="$1"
FIXDIR="$ROOT/tests/fixtures"
SRC="$FIXDIR/$FIX"
OUTDIR="${GOLDEN_DIR:-$ROOT/tests/golden}"
OUT="$OUTDIR/$FIX.json"
OUT_N="$OUTDIR/$FIX.n.json"

command -v perl >/dev/null 2>&1 || {
  echo "perl not found (needed to run ExifTool)" >&2; exit 1; }
[ -f "$EXIFTOOL" ] || {
  echo "ExifTool not found: $EXIFTOOL (set \$EXIFTOOL to the exiftool script)" >&2
  exit 1; }
[ -f "$SRC" ] || { echo "fixture not found: $SRC" >&2; exit 1; }
# Canonicalize EXIFTOOL to an absolute path: it is invoked from $FIXDIR
# below, so a CWD-relative value would otherwise fail to resolve.
EXIFTOOL="$(cd "$(dirname "$EXIFTOOL")" && pwd)/$(basename "$EXIFTOOL")"
mkdir -p "$OUTDIR"

# Stable output: drop filesystem-dependent tags, force C locale & UTC.
# NOTE: `Composite:*` is NOT excluded globally here — several formats (FLAC,
# APE, AIFF) legitimately emit ported Composite tags (e.g. Composite:Duration)
# that their goldens MUST retain. Composite is excluded only per-fixture, via
# the `EXCLUDE` mechanism below (for QuickTime/Matroska/MPEG, whose Composite
# tables are a deferred Phase-2 forward item) and auto-applied for the XMP
# fixtures (which synthesize Composite:* this XMP-only port does not emit).
COMMON=(-j -G1 -struct -api QuickTimeUTC=1 \
        --FileName --Directory --FileSize --FileModifyDate \
        --FileAccessDate --FileInodeChangeDate --FilePermissions)

# Optional standard exclusions, applied verbatim to BOTH the -j and -n runs.
# Formats whose bundled output carries engine-synthesized `Composite:*` or
# filesystem `System:*` tags (deferred per the Phase-2 forward items) pass
# `EXCLUDE="-x System:all -x Composite:all"` so the regeneration is
# reproducible (e.g. QuickTime, Matroska). Defaults to nothing — formats
# whose goldens legitimately carry Composite tags (e.g. FLAC) regenerate
# unchanged.
# shellcheck disable=SC2206  # intentional word-splitting of the exclusion list
EXCLUDE_ARR=(${EXCLUDE:-})

# XMP fixtures synthesize `Composite:*` tags (Composite:GPSPosition, …) that
# the XMP-only port does not emit, so their goldens must drop Composite. Auto-
# apply the exclusion for any XMP fixture (name starts with `XMP`) so it cannot
# be forgotten on regen; non-XMP fixtures are unaffected and keep their ported
# Composite tags. (Idempotent if the caller already passed it via EXCLUDE.)
case "$FIX" in
  # The XMP-GPS-altitude fixtures (#133 PR 2): the `Composite:GPSAltitude` def
  # `Desire`s the XMP altitude/ref pair (GPS.pm:406), so exifast emits
  # `Composite:GPSAltitude` from the embedded `XMP-exif:GPSAltitude`/`…Ref`
  # (byte-matching bundled). The XMP-only ref composites bundled ALSO synthesizes
  # (`Composite:GPSLatitudeRef`/`GPSLongitudeRef`/`GPSPosition`) are NOT ported,
  # so drop ONLY those three (NOT `Composite:all` — that would also drop the
  # ported `GPSAltitude`). Must precede the generic `XMP*` arm (first match wins).
  XMP_gps_abovesea.xmp | XMP_gps_belowsea.xmp)
    EXCLUDE_ARR+=(-x Composite:GPSLatitudeRef -x Composite:GPSLongitudeRef \
                  -x Composite:GPSPosition) ;;
  # XMP_rational_plus.xmp (#133 PR 4): exifast builds the ported `Composite:
  # Aperture` from the embedded `XMP-exif:FNumber` (XMP is allow-listed — a single
  # Main document) AND now `Composite:FocalLength35efl` from `XMP-exif:FocalLength`
  # ("50.0 mm" → `ToFloat` prefix 50 → "50.0 mm"; no ScaleFactor, so the focal-only
  # PrintConv branch). No lens exclusion left. Must precede the generic `XMP*` arm.
  XMP_rational_plus.xmp)
    : ;;
  # XMP.xmp (#133 PR 3/4): exifast builds the ported Tier-A `Composite:ImageSize`/
  # `Megapixels` (from the bare-name `XMP-tiff:ImageWidth`/`Height`) + `Aperture`/
  # `ShutterSpeed` (from `XMP-exif:FNumber`/`ExposureTime`). It does NOT build the
  # GPS-coordinate composites (the `Composite:GPSLatitude`/`Longitude` defs
  # require the family-0 `GPS` group, not `XMP-exif`), so there are none here.
  # The lens chain stays EXCLUDED (PR 4): this fixture's `Make=Canon` AND its
  # bundled `Composite:ScaleFactor35efl` (6.0836…) is computed via the Canon
  # `CalcSensorDiag` branch (Exif.pm:5464 — CalcSensorDiag returns 7.112 from the
  # Canon FocalPlaneX/YResolution rationals `2272000/224`, `1704000/168`), which
  # the composite post-pass cannot reach (no `TAG_EXTRA{Rational}` handle); the
  # generic path would give a WRONG 12.17. So `ScaleFactor35efl` is DEFERRED and
  # its derived composites (`CircleOfConfusion`/`FOV`/`FocalLength35efl`/
  # `HyperfocalDistance`) stay excluded with it. Drop only the unported lens/
  # MakerNote Composites by name (NOT `Composite:all`). Precede the generic `XMP*`.
  XMP.xmp)
    EXCLUDE_ARR+=(-x Composite:ScaleFactor35efl -x Composite:Flash \
                  -x Composite:CircleOfConfusion -x Composite:FOV \
                  -x Composite:FocalLength35efl -x Composite:HyperfocalDistance) ;;
  XMP*) EXCLUDE_ARR+=(-x Composite:all) ;;
  # The PNG raw-profile fixtures (#179): #133 PR 5 flips PNG into the Composite
  # allow-list, so exifast NOW emits `Composite:ImageSize`/`Megapixels` (from the
  # IHDR dimensions), byte-matching bundled. They are no longer excluded — the
  # decoded profile content (`XMP-*`) PLUS the two ported Composites are compared.
  PNG_rawprofile_*) : ;;
  # ── #133 PR 5 video/container Composite arms ─────────────────────────────────
  # The full-video-activation fixtures keep their ported Composites
  # (ImageSize/Megapixels/AvgBitrate/Rotation/Duration + the GPS-group SubDoc
  # GPS) and drop ONLY the unported ones BY NAME (never `Composite:all`), plus
  # the non-Composite port deferrals each golden already excluded before this PR.
  #
  # The UNPORTED Composites dropped here:
  #  * the QuickTime `GPSCoordinates`-derived `Composite:GPSLatitude`/`Longitude`/
  #    `GPSAltitude`/`GPSAltitudeRef` (+ the dependent `GPSPosition`) — a separate
  #    QuickTime.pm:8668 Composite table (`Require => 'QuickTime:GPSCoordinates'`,
  #    split " ") this PR does not port; exifast emits none, so they are dropped;
  #  * MakerNote-derived `Composite:LensID` (Pentax AVI), `Composite:DateTimeOriginal`
  #    (Red R3D) — unported MakerNote/format composites.
  #
  # `ISOBMFF_iso5_brand.mp4`: the `mvex/mehd` `MovieFragmentSequence` container
  # tag stays unported; the ported `ImageSize`/`Megapixels` are kept.
  ISOBMFF_iso5_brand.mp4) EXCLUDE_ARR+=(-x MovieFragmentSequence) ;;
  # `Pentax.avi`: the Pentax-AVI MakerNote tail tags + `Composite:LensID` are
  # unported (the AVI Pentax MakerNote subset); the ported ImageSize/Megapixels/
  # Duration are kept.
  Pentax.avi)
    EXCLUDE_ARR+=(-x Composite:LensID -x Pentax:AEMeteringMode2 -x Pentax:AEWhiteBalance \
                  -x Pentax:Artist -x Pentax:Copyright -x Pentax:CrossProcess \
                  -x Pentax:ExtenderStatus -x Pentax:FirmwareVersion -x Pentax:HighLowKeyAdj \
                  -x Pentax:Hue -x Pentax:LevelIndicator -x Pentax:MonochromeFilterEffect \
                  -x Pentax:MonochromeToning -x Pentax:SerialNumber) ;;
  # `QuickTime_gopro_gpmf.mp4`: the QuickTime GPSCoordinates Composites (the
  # `LocationInformation`-derived GPS) + the udta atoms this port does not decode
  # (`ItemList:all` = ©too Encoder, `UserData:all` = LocationInformation) + the
  # MOVIE-LEVEL `1QuickTime:HandlerType`/`HandlerVendorID` (the `1` prefix is
  # ExifTool's family-1 qualifier — drops ONLY the moov-level "Metadata" handler
  # exifast does not emit, KEEPING the `Track<N>:HandlerType` it does). The ported
  # ImageSize/Megapixels/AvgBitrate/Rotation are kept.
  QuickTime_gopro_gpmf.mp4)
    EXCLUDE_ARR+=(-x Composite:GPSAltitude -x Composite:GPSAltitudeRef \
                  -x Composite:GPSLatitude -x Composite:GPSLongitude -x Composite:GPSPosition \
                  -x ItemList:all -x UserData:all \
                  -x 1QuickTime:HandlerType -x 1QuickTime:HandlerVendorID) ;;
  # The SP2 `Keys`/`UserData` GPSCoordinates fixtures: ExifTool's QuickTime
  # GPSCoordinates Composites (GPSLatitude/Longitude/Altitude/AltitudeRef/Position)
  # are unported; the ported ImageSize/Megapixels/AvgBitrate/Rotation are kept.
  QuickTime_sp2.mov | QuickTime_sp2_badgps.mov | QuickTime_sp2_ilst_before_keys.mov | \
  QuickTime_sp2_infgps.mov | QuickTime_sp2_iso6709long.mov | QuickTime_sp2_macroman.mov | \
  QuickTime_sp2_meta_handlerclass.mov | QuickTime_sp2_keys_loc_binary.mov | \
  QuickTime_sp2_keys_loc_numeric.mov)
    EXCLUDE_ARR+=(-x Composite:GPSAltitude -x Composite:GPSAltitudeRef \
                  -x Composite:GPSLatitude -x Composite:GPSLongitude -x Composite:GPSPosition) ;;
  # `Red.r3d`: the unported `Composite:DateTimeOriginal` (Red's RawConv-assembled
  # composite); the ported ImageSize/Megapixels are kept.
  Red.r3d) EXCLUDE_ARR+=(-x Composite:DateTimeOriginal) ;;
  # `RIFF.avi`: the AVI-embedded XMP packet is unported (the AVI `_PMX` chunk
  # XMP decode); the ported Composites are kept.
  RIFF.avi)
    EXCLUDE_ARR+=(-x XMP-dc:Creator -x XMP-x:XMPToolkit -x XMP-xmp:MetadataDate \
                  -x XMP-xmpDM:Album -x XMP-xmpDM:AltTapeName) ;;
  # ── Timed-GPS `Composite:GPSPosition` deferral (camm / mebx / freeGPS / insta360
  # / gopro gpmd) ──────────────────────────────────────────────────────────────
  # These tracks emit their per-sample GPS as family-1 `Track<N>` / movie-level
  # `QuickTime` tags (family-2 `Location`), NOT the family-1 `GPS` group the
  # ported `%GPS::Composite` `GPSLatitude`/`GPSLongitude` SubDoc defs require — so
  # exifast builds no per-doc `Composite:GPSLatitude`/`Longitude` for them, hence
  # no Main `Composite:GPSPosition` (which `Require`s those). Bundled DOES
  # synthesize `Composite:GPSPosition` for them (its GPS-group Composite matches
  # the timed GPS via family-2 `Location`), an unported timed-GPS-Composite path.
  # The Sony rtmd `Doc<N>:Composite:GPS*` (family-0 `Sony`) + the still/EXIF GPS
  # Composites ARE ported; only this non-Sony timed/moov GPSPosition is dropped.
  # The ported `AvgBitrate`/`ImageSize`/`Megapixels`/`Rotation` are kept.
  QuickTime_camm.mov | QuickTime_camm_2track.mov | QuickTime_camm_gps_warn.mov | \
  QuickTime_camm_motion_gps.mov | QuickTime_camm_multipkt.mov | QuickTime_camm_warn_gps.mov | \
  QuickTime_frea_rexing17b.mov | QuickTime_gopro_hero8_gpmf.mp4 | QuickTime_gps0.mov | \
  QuickTime_gps0_oor0.mov | QuickTime_gps_kenwood.mov | QuickTime_insta360.mp4 | \
  QuickTime_insta360_badstride.mp4 | QuickTime_insta360_chained.mp4 | \
  QuickTime_insta360_short300.mp4 | QuickTime_mebx_camm.mov | QuickTime_moov_gps.mov | \
  QuickTime_fmas_n2s.mov | QuickTime_wolfbox_redtiger_f9.mov | \
  QuickTime_fmas_empty_then_valid.mov | \
  QuickTime_text_mini0806.mov | QuickTime_text_roadhawk.mov | \
  QuickTime_text_thinkware.mov | QuickTime_text_dji_telemetry.mov | \
  QuickTime_text_empty_then_valid.mov | \
  MPEG2_TS_pruveeo_d90.ts)
    EXCLUDE_ARR+=(-x Composite:GPSPosition) ;;
  # `QuickTime_mebx_gps.mov`: a crafted single-`mebx`-GPS fixture — bundled builds
  # the per-doc `Composite:GPSLatitude` (and no GPSPosition, a single coordinate);
  # the unported timed `Composite:GPSLatitude`/`GPSLongitude` are dropped.
  QuickTime_mebx_gps.mov)
    EXCLUDE_ARR+=(-x Composite:GPSLatitude -x Composite:GPSLongitude) ;;
  # `_multistsd`/`_multistsd8`: the sample decodes as the camm DECOY (family-1
  # `Track1`, not the family-0 `Sony` rtmd), so its GPS is the unported timed-GPS
  # path ⇒ no `Composite:GPSPosition` (same as the camm/mebx deferral above).
  # (The crafted edges where exifast EMITS a diverging Composite —
  # `_coordzero`/`_nonfinite`/`_zerolen`/`_shortnum` GPS+Aperture, the Canon
  # `exifinfo` LightValue — are dropped from BOTH sides by the TEST's `excluded`
  # arg, not here, since a golden-only `-x` would still leave exifast's extra.)
  QuickTime_sony_rtmd_multistsd.mov | QuickTime_sony_rtmd_multistsd8.mov)
    EXCLUDE_ARR+=(-x Composite:GPSPosition) ;;
  # The EXIF / still-QuickTime fixtures (#133 PR 3): exifast emits the ported
  # Tier-A EXIF Composites (`ImageSize`/`Megapixels`/`ShutterSpeed`/`Aperture`/
  # `SubSecDateTimeOriginal`/`SubSecCreateDate`/`SubSecModifyDate`, Exif.pm) plus
  # the PR-2 GPS Composites, but NOT the still-deferred LENS/MakerNote composites
  # (`FocalLength35efl`/`CircleOfConfusion`/`FOV`/`HyperfocalDistance`/`DOF`/
  # `LightValue`/`ScaleFactor35efl` — the lens subsystem, #133 PR 4 — and the
  # MakerNote-derived `LensID`/`LensSpec`/`AutoFocus`/`RedBalance`/`BlueBalance`/
  # `AvgBitrate`). So these goldens KEEP the ported Composites and drop ONLY the
  # unported ones BY NAME (never `Composite:all`), byte-matching exifast — PLUS
  # any non-Composite port deferrals each golden already excluded (the IPTC/
  # XMP JPEG segments for `ExifGPS.jpg`/`DJIPhantom4.jpg`; the codec-config
  # property atoms for `HEIF`/`AVIF`). `IFD1:ThumbnailImage` is NO LONGER
  # excluded — #331 emits it via the EXIF `DataTag` channel (the IFD1
  # ThumbnailOffset/ThumbnailLength pair → the `(Binary data N bytes …)`
  # placeholder), byte-matching bundled. `ExifGPS.tif` carries only GPS
  # Composites + no deferred segments → default path (no arm).
  ExifGPS.jpg)
    EXCLUDE_ARR+=(-x IPTC:all -x File:CurrentIPTCDigest) ;;
  # PR 4: the full lens chain now builds (DJI, NOT Canon — the simple
  # `$foc35/$focal` ScaleFactor path: 20/3.61 = 5.54016620498615). Only the
  # non-Composite port deferrals remain.
  DJIPhantom4.jpg)
    EXCLUDE_ARR+=(-x XMP:all) ;;
  # NEW PR-3 arms (these relied on a regen-time `EXCLUDE` env before — now baked
  # in so `tools/gen_golden.sh <fix>` reproduces them with no env). Each drops
  # only the unported lens/MakerNote Composites by name.
  # NikonD2Hs also drops the non-Composite `PreviewIFD:all` / `ExifIFD:CFAPattern`
  # the port defers (these were in its `EXCLUDE` env). `IFD1:ThumbnailImage` is
  # NOW emitted via the #331 EXIF `DataTag` channel (no longer excluded).
  # PR 4: the full lens chain now builds (NIKON, NOT Canon — the simple
  # `$foc35/$focal` ScaleFactor path: 75/50 = 1.5). The MakerNote-derived
  # Composites (BlueBalance/RedBalance/AutoFocus/LensID/LensSpec) + the non-
  # Composite port deferrals remain.
  NikonD2Hs.jpg)
    EXCLUDE_ARR+=(-x PreviewIFD:all -x ExifIFD:CFAPattern \
                  -x Composite:BlueBalance -x Composite:RedBalance \
                  -x Composite:AutoFocus -x Composite:LensID -x Composite:LensSpec) ;;
  # Pentax also drops `Pentax:PreviewImageStart`/`PreviewImage` (IsOffset binary
  # extraction, unported) + `PrintIM:PrintIMVersion`. `IFD1:ThumbnailImage` is
  # NOW emitted via the #331 EXIF `DataTag` channel (no longer excluded; the
  # Pentax:PreviewImage IsOffset binary stays deferred — P2/P3 of #331).
  # PR 4: the full lens chain now builds (PENTAX, NOT Canon — the simple
  # `$foc35/$focal` ScaleFactor path: 15/10 = 1.5). The MakerNote `Composite:
  # LensID` + the non-Composite port deferrals remain.
  Pentax.jpg)
    EXCLUDE_ARR+=(-x Pentax:PreviewImageStart -x Pentax:PreviewImage \
                  -x PrintIM:PrintIMVersion \
                  -x Composite:LensID) ;;
  # DJI_Matrice30T.jpg: PR 4's full lens chain builds (DJI, NOT Canon — the
  # simple `$foc35/$focal` ScaleFactor path: 40/9.1 = 4.3956043956044), no
  # `Composite:LightValue` (its ISO/aperture combo yields no LV in bundled), and
  # its ONLY former exclusion `IFD1:ThumbnailImage` is NOW emitted via the #331
  # EXIF `DataTag` channel. With no remaining port deferral it takes the default
  # path (NO arm) — its golden KEEPS the ThumbnailImage line.
  # The synthesized standalone-EXIF fixtures (#133 PR 3): exifast builds the
  # ported Tier-A Composites (Exif.tif → Aperture/ShutterSpeed; Exif_trailing_
  # space.tif → SubSecDateTimeOriginal) — EXIF is allow-listed. They KEEP those
  # and drop the unported lens Composites by name (Exif.tif's FocalLength35efl/
  # LightValue/LensID). `System:all` (the former env exclusion) is preserved.
  # PR 4: exifast now builds `Composite:FocalLength35efl` ("50.0 mm" — focal-only,
  # no ScaleFactor) and `Composite:LightValue` (11.3) for this Canon TIFF. Its
  # `Composite:ScaleFactor35efl` is NOT built (Make=Canon, no FocalLengthIn35mm
  # format, and the Canon `CalcSensorDiag` branch is unported + bundled emits
  # none anyway — no FocalPlane resolution), so no ScaleFactor-derived composites
  # exist to exclude. Only the unported MakerNote `Composite:LensID` is dropped.
  Exif.tif)
    EXCLUDE_ARR+=(-x System:all -x Composite:LensID) ;;
  Exif_trailing_space.tif)
    EXCLUDE_ARR+=(-x System:all) ;;
  # HEIF/AVIF stills: fold the documented codec-config `EXCLUDE` env into the arm
  # (so it is reproducible). AVIF emits only the ported ImageSize + Megapixels;
  # HEIC also emits the now-ported `Composite:AvgBitrate` (#133 PR 5 — the
  # `mdat`-bitrate composite: the SUM of all three `mdat` sizes / Duration,
  # `50.2 Mbps`), so it is NO LONGER excluded (the only remaining drops are the
  # codec-config property atoms the port does not decode).
  HEIF_C001_msf1.heic)
    EXCLUDE_ARR+=(-x System:all -x Copy1:HandlerType -x ImageSpatialExtent \
                  -x HEVCConfigurationVersion -x GeneralProfileSpace \
                  -x GeneralTierFlag -x GeneralProfileIDC \
                  -x GenProfileCompatibilityFlags -x ConstraintIndicatorFlags \
                  -x GeneralLevelIDC -x MinSpatialSegmentationIDC \
                  -x ParallelismType -x ChromaFormat -x BitDepthLuma \
                  -x BitDepthChroma -x AverageFrameRate -x ConstantFrameRate \
                  -x NumTemporalLayers -x TemporalIDNested) ;;
  AVIF_sample.avif)
    EXCLUDE_ARR+=(-x System:all -x HandlerType -x HandlerDescription \
                  -x PixelAspectRatio -x ImageSpatialExtent -x ImagePixelDepth \
                  -x AV1ConfigurationVersion -x ChromaFormat \
                  -x ChromaSamplePosition) ;;
  # SamsungNX500.srw (#133 PR 4): exifast now builds the ported EXIF + lens
  # Composite chain (`Aperture`/`ShutterSpeed`/`ScaleFactor35efl` [SAMSUNG, NOT
  # Canon — the simple `$foc35/$focal` path: 69/45 = 1.5] / `CircleOfConfusion`/
  # `FOV`/`FocalLength35efl`/`HyperfocalDistance`/`LightValue`). Dropped by name:
  #  * the MakerNote-derived Composites (`LensID`/`WB_RGGBLevels`/`RedBalance`/
  #    `BlueBalance`/`CFAPattern`), unported;
  #  * `ImageSize`/`Megapixels` — their `Require`d `ImageWidth`/`ImageHeight` live
  #    in the SRW `SubIFD1` (`6496x4336`), which exifast DEFERS (`-x SubIFD1:all`),
  #    so exifast has no bare `ImageWidth` to build them (it carries only
  #    `ExifIFD:ExifImageWidth`, a `Desire`). A documented sub-IFD deferral.
  # (NOT `-x Composite:all`, which the conformance `EXCLUDE` env previously used.)
  # #242: the `0x0035 PreviewIFD` Nikon-PreviewIFD sub-IFD is now WALKED — its 8
  # tags (SubfileType/XResolution/YResolution/ResolutionUnit/PreviewImageStart/
  # PreviewImageLength/YCbCrPositioning + the PreviewImage blob via the DataTag
  # channel) emit byte-exact, so `-x PreviewIFD:all` is REMOVED. The raw SRW image
  # sub-IFDs `SubIFD:all`/`SubIFD1:all` stay deferred (the raw strips + the
  # embedded JpgFromRaw JPEG, not walked).
  SamsungNX500.srw)
    EXCLUDE_ARR+=(-x SubIFD:all -x SubIFD1:all \
                  -x Composite:LensID -x Composite:WB_RGGBLevels \
                  -x Composite:RedBalance -x Composite:BlueBalance \
                  -x Composite:CFAPattern -x Composite:ImageSize \
                  -x Composite:Megapixels) ;;
  # The crafted CR2 ImageSize-deferral fixture (#133 Finding 2): a CR2 whose
  # `Composite:ImageSize` would (faithfully) use `ExifImageWidth`/`Height` via
  # the `$$self{TIFF_TYPE} =~ /^(CR2|Canon 1D RAW|IIQ|EIP)$/` branch (Exif.pm:
  # 4759). exifast's Composite post-pass has no `TIFF_TYPE` handle, so it DEFERS
  # ALL composites for those RAW subtypes (option b) rather than emit a wrong
  # `ImageWidth`-based size. Drop `Composite:all` so the golden matches exifast's
  # (Composite-less) output; the test asserts NO `Composite:ImageSize` is built.
  # `System:all` excludes the filesystem tags as for the other synthetic TIFFs.
  CR2_imagesize.cr2)
    EXCLUDE_ARR+=(-x System:all -x Composite:all) ;;
esac

# Run from the fixtures dir and pass only the basename so the embedded
# `SourceFile` is a stable, environment-independent relative path
# (e.g. "AAC.aac") instead of a machine-specific absolute path that
# would make the committed goldens non-portable.
# `${EXCLUDE_ARR[@]+...}` guards the expansion so an EMPTY exclusion array
# (the common case — e.g. FLAC has no exclusions) does not trip `set -u`
# "unbound variable" on the bash 3.2 shipped with macOS.
( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" ${EXCLUDE_ARR[@]+"${EXCLUDE_ARR[@]}"}    "$FIX" ) > "$OUT"
( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" ${EXCLUDE_ARR[@]+"${EXCLUDE_ARR[@]}"} -n "$FIX" ) > "$OUT_N"
echo "wrote $OUT and $OUT_N"

# --- EE (ExtractEmbedded) timed-metadata oracle goldens ---------------------
# Opt-in via `EE=1`. ADDITIVE: writes `<fix>.ee.json` (family-1 groups, same
# COMMON flags + `-ee`) and `<fix>.ee.g3.json` (`-ee -G3:1` → `Doc<N>:` family-3
# document axis). `-G1` from COMMON and `-G3:1` coexist (verified): the g3 run
# emits `Doc<N>:QuickTime:GPS…` (family-3 ∘ family-1), so no array tweak is
# needed. Same `${EXCLUDE_ARR[@]+…}` guard for bash-3.2 `set -u` safety.
if [ -n "${EE:-}" ]; then
  OUT_EE="$OUTDIR/$FIX.ee.json"
  OUT_EE_G3="$OUTDIR/$FIX.ee.g3.json"
  ( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" ${EXCLUDE_ARR[@]+"${EXCLUDE_ARR[@]}"} -ee        "$FIX" ) > "$OUT_EE"
  ( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" ${EXCLUDE_ARR[@]+"${EXCLUDE_ARR[@]}"} -ee -G3:1 "$FIX" ) > "$OUT_EE_G3"
  echo "wrote $OUT_EE and $OUT_EE_G3"
fi

# --- EE + `-n` (numeric / no-PrintConv) timed-metadata oracle golden ---------
# Opt-in via `EE_N=1` (SEPARATE from `EE=1` so a plain EE regen does not mint an
# `<fix>.ee.n.json` for every EE fixture — only the fixtures whose test pins the
# `-ee -n` axis carry one). Writes `<fix>.ee.n.json` (`-ee -n`, the family-1
# `-G1` axis from COMMON). This pins the tags whose `%QuickTime::Stream` PrintConv
# is DISABLED under `-n` — e.g. the DJI `Distance` (`"$val m"` → raw `87.336`) and
# `VerticalSpeed` (`"$val m/s"` → raw `0.00`) — distinct from the `-j` `.ee.json`.
if [ -n "${EE_N:-}" ]; then
  OUT_EE_N="$OUTDIR/$FIX.ee.n.json"
  ( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" ${EXCLUDE_ARR[@]+"${EXCLUDE_ARR[@]}"} -ee -n "$FIX" ) > "$OUT_EE_N"
  echo "wrote $OUT_EE_N"
fi
