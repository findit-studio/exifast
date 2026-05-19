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
COMMON=(-j -G1 -struct -api QuickTimeUTC=1 \
        --FileName --Directory --FileSize --FileModifyDate \
        --FileAccessDate --FileInodeChangeDate --FilePermissions)

# Run from the fixtures dir and pass only the basename so the embedded
# `SourceFile` is a stable, environment-independent relative path
# (e.g. "AAC.aac") instead of a machine-specific absolute path that
# would make the committed goldens non-portable.
( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}"    "$FIX" ) > "$OUT"
( cd "$FIXDIR" && LC_ALL=C TZ=UTC perl "$EXIFTOOL" "${COMMON[@]}" -n "$FIX" ) > "$OUT_N"
echo "wrote $OUT and $OUT_N"
