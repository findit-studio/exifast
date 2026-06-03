#!/usr/bin/env bash
# Regenerate golden JSON for one fixture using the bundled Perl ExifTool.
# Usage: tools/gen_golden.sh <fixture-name-relative-to-tests/fixtures>
#
# Env:
#   EXIFTOOL    path to the `exiftool` Perl script
#               (default: <repo>/../exiftool/exiftool — the sibling checkout)
#   GOLDEN_DIR  directory to write <fix>.json / <fix>.n.json into
#               (default: <repo>/tests/golden)
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
  XMP*) EXCLUDE_ARR+=(-x Composite:all) ;;
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
