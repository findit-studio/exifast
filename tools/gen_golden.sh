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
  # XMP_rational_plus.xmp (#133 PR 3): exifast builds the ported `Composite:
  # Aperture` from the embedded `XMP-exif:FNumber` (XMP is allow-listed — a single
  # Main document); the unported `Composite:FocalLength35efl` (lens, PR 4) is
  # dropped by name. Must precede the generic `XMP*` arm (first match wins).
  XMP_rational_plus.xmp)
    EXCLUDE_ARR+=(-x Composite:FocalLength35efl) ;;
  # XMP.xmp (#133 PR 3): exifast builds the ported Tier-A `Composite:ImageSize`/
  # `Megapixels` (from the bare-name `XMP-tiff:ImageWidth`/`Height`) + `Aperture`/
  # `ShutterSpeed` (from `XMP-exif:FNumber`/`ExposureTime`). It does NOT build the
  # GPS-coordinate composites (the `Composite:GPSLatitude`/`Longitude` defs
  # require the family-0 `GPS` group, not `XMP-exif`), so there are none here.
  # Drop only the unported lens/MakerNote Composites by name (NOT `Composite:all`,
  # which the generic `XMP*` arm applies). Must precede the generic `XMP*` arm.
  XMP.xmp)
    EXCLUDE_ARR+=(-x Composite:ScaleFactor35efl -x Composite:Flash \
                  -x Composite:CircleOfConfusion -x Composite:FOV \
                  -x Composite:FocalLength35efl -x Composite:HyperfocalDistance) ;;
  XMP*) EXCLUDE_ARR+=(-x Composite:all) ;;
  # The PNG raw-profile fixtures (#179) carry the engine-synthesized
  # `Composite:ImageSize`/`Megapixels` (from the IHDR dimensions) that the PNG
  # port does not emit (it has no Composite subsystem). Drop Composite so the
  # decoded profile content (`XMP-*`) is what the golden compares.
  PNG_rawprofile_*) EXCLUDE_ARR+=(-x Composite:all) ;;
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
  # Thumbnail/XMP JPEG segments for `ExifGPS.jpg`/`DJIPhantom4.jpg`; the codec-
  # config property atoms for `HEIF`/`AVIF`). `ExifGPS.tif` carries only GPS
  # Composites + no deferred segments → default path (no arm).
  ExifGPS.jpg)
    EXCLUDE_ARR+=(-x IPTC:all -x File:CurrentIPTCDigest -x IFD1:ThumbnailImage \
                  -x Composite:FocalLength35efl) ;;
  DJIPhantom4.jpg)
    EXCLUDE_ARR+=(-x XMP:all -x IFD1:ThumbnailImage \
                  -x Composite:CircleOfConfusion -x Composite:FOV \
                  -x Composite:FocalLength35efl -x Composite:HyperfocalDistance \
                  -x Composite:LightValue -x Composite:ScaleFactor35efl) ;;
  # NEW PR-3 arms (these relied on a regen-time `EXCLUDE` env before — now baked
  # in so `tools/gen_golden.sh <fix>` reproduces them with no env). Each drops
  # only the unported lens/MakerNote Composites by name.
  # NikonD2Hs also drops the non-Composite `PreviewIFD:all` / `IFD1:ThumbnailImage`
  # / `ExifIFD:CFAPattern` the port defers (these were in its `EXCLUDE` env).
  NikonD2Hs.jpg)
    EXCLUDE_ARR+=(-x PreviewIFD:all -x IFD1:ThumbnailImage -x ExifIFD:CFAPattern \
                  -x Composite:BlueBalance -x Composite:RedBalance \
                  -x Composite:AutoFocus -x Composite:LensID -x Composite:LensSpec \
                  -x Composite:ScaleFactor35efl -x Composite:CircleOfConfusion \
                  -x Composite:DOF -x Composite:FOV -x Composite:FocalLength35efl \
                  -x Composite:HyperfocalDistance -x Composite:LightValue) ;;
  # Pentax also drops `Pentax:PreviewImageStart`/`PreviewImage` (IsOffset binary
  # extraction, unported) + `IFD1:ThumbnailImage` + `PrintIM:PrintIMVersion`
  # (the same gaps the Nikon golden excludes) — all were in its `EXCLUDE` env.
  Pentax.jpg)
    EXCLUDE_ARR+=(-x Pentax:PreviewImageStart -x Pentax:PreviewImage \
                  -x IFD1:ThumbnailImage -x PrintIM:PrintIMVersion \
                  -x Composite:LensID -x Composite:ScaleFactor35efl \
                  -x Composite:CircleOfConfusion -x Composite:FOV \
                  -x Composite:FocalLength35efl -x Composite:HyperfocalDistance \
                  -x Composite:LightValue) ;;
  # DJI_Matrice30T also drops `IFD1:ThumbnailImage` (was in its `EXCLUDE` env).
  DJI_Matrice30T.jpg)
    EXCLUDE_ARR+=(-x IFD1:ThumbnailImage \
                  -x Composite:ScaleFactor35efl -x Composite:CircleOfConfusion \
                  -x Composite:DOF -x Composite:FOV -x Composite:FocalLength35efl \
                  -x Composite:HyperfocalDistance) ;;
  # The synthesized standalone-EXIF fixtures (#133 PR 3): exifast builds the
  # ported Tier-A Composites (Exif.tif → Aperture/ShutterSpeed; Exif_trailing_
  # space.tif → SubSecDateTimeOriginal) — EXIF is allow-listed. They KEEP those
  # and drop the unported lens Composites by name (Exif.tif's FocalLength35efl/
  # LightValue/LensID). `System:all` (the former env exclusion) is preserved.
  Exif.tif)
    EXCLUDE_ARR+=(-x System:all -x Composite:FocalLength35efl \
                  -x Composite:LightValue -x Composite:LensID) ;;
  Exif_trailing_space.tif)
    EXCLUDE_ARR+=(-x System:all) ;;
  # HEIF/AVIF stills: fold the documented codec-config `EXCLUDE` env into the arm
  # (so it is reproducible) and replace the former `-x Composite:all` with the
  # specific unported-Composite drops. AVIF emits only the ported ImageSize +
  # Megapixels (no Composite drop needed); HEIC also emits `Composite:AvgBitrate`
  # (the `mdat`-bitrate composite, unported) which is dropped.
  HEIF_C001_msf1.heic)
    EXCLUDE_ARR+=(-x System:all -x Copy1:HandlerType -x ImageSpatialExtent \
                  -x HEVCConfigurationVersion -x GeneralProfileSpace \
                  -x GeneralTierFlag -x GeneralProfileIDC \
                  -x GenProfileCompatibilityFlags -x ConstraintIndicatorFlags \
                  -x GeneralLevelIDC -x MinSpatialSegmentationIDC \
                  -x ParallelismType -x ChromaFormat -x BitDepthLuma \
                  -x BitDepthChroma -x AverageFrameRate -x ConstantFrameRate \
                  -x NumTemporalLayers -x TemporalIDNested \
                  -x Composite:AvgBitrate) ;;
  AVIF_sample.avif)
    EXCLUDE_ARR+=(-x System:all -x HandlerType -x HandlerDescription \
                  -x PixelAspectRatio -x ImageSpatialExtent -x ImagePixelDepth \
                  -x AV1ConfigurationVersion -x ChromaFormat \
                  -x ChromaSamplePosition) ;;
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
