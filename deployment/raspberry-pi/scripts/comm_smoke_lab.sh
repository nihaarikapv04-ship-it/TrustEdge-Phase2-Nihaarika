#!/usr/bin/env bash
# Wrapper: run lab container communication tests (from repo root or lab/).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
exec "$REPO/lab/scripts/comm_smoke_test.sh"
