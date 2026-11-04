#!/usr/bin/env bash
# Preserve the known-good LOCAL release candidate so Pi deploy can roll back.
# Creates a local git tag (NOT pushed) and a tarball under deployment/raspberry-pi/rc-snapshots/.
# Does not modify ML/trust/policy code. Does not push to GitHub.
#
# Usage (from repo root on the Mac):
#   ./deployment/raspberry-pi/scripts/preserve_local_rc.sh
#   ./deployment/raspberry-pi/scripts/preserve_local_rc.sh rc-local-20261104
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

TAG="${1:-rc-local-$(date -u +%Y%m%d)}"
SNAP_DIR="$ROOT/deployment/raspberry-pi/rc-snapshots"
mkdir -p "$SNAP_DIR"

HEAD=$(git rev-parse HEAD)
SHORT=$(git rev-parse --short HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "Preserving local RC"
echo "  branch=$BRANCH"
echo "  head=$HEAD"
echo "  tag=$TAG (local only — will NOT push)"

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Tag $TAG already exists locally: $(git rev-parse "$TAG")"
else
  git tag -a "$TAG" -m "Known-good local release candidate before physical Pi deploy. head=$SHORT"
  echo "Created annotated tag $TAG"
fi

MANIFEST="$SNAP_DIR/${TAG}-manifest.txt"
{
  echo "tag=$TAG"
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "branch=$BRANCH"
  echo "head=$HEAD"
  echo "short=$SHORT"
  echo
  echo "== status (may include uncommitted RC fixes) =="
  git status -sb
  echo
  echo "== key paths =="
  echo "docs/LOCAL_PARITY_REPORT.md"
  echo "deployment/raspberry-pi/"
  echo "lab/"
  echo "trustedge/"
  echo "deploy/"
} >"$MANIFEST"

ARCHIVE="$SNAP_DIR/${TAG}.tar.gz"
# Snapshot working tree including uncommitted known-good fixes (exclude secrets/venv).
# BSD tar on macOS: multiple --exclude flags; no ** globs.
tar -czf "$ARCHIVE" \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='.pytest_cache' \
  --exclude='lab/.env' \
  --exclude='lab/.env.token' \
  --exclude='lab/.admin.password' \
  --exclude='lab/.operator.password' \
  --exclude='lab/.viewer.password' \
  --exclude='*.sqlite' \
  --exclude='*.sqlite-shm' \
  --exclude='*.sqlite-wal' \
  --exclude='rc-snapshots' \
  -C "$ROOT" \
  trustedge lab deploy deployment docs tests pyproject.toml README.md

echo "Wrote $MANIFEST"
echo "Wrote $ARCHIVE ($(du -h "$ARCHIVE" | awk '{print $1}'))"
echo
echo "Rollback reminders:"
echo "  git checkout $TAG          # tagged commit only"
echo "  # or extract: tar -xzf $ARCHIVE -C /path/to/restore"
echo "  # NEVER: git push --tags   (user forbids remote publish for this step)"
echo "Done."
