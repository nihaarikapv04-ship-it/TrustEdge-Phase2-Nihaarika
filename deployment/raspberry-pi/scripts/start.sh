#!/usr/bin/env bash
# Safe startup for native Pi gateway (does NOT modify host networking itself —
# assumes trustedge-network.service already applied reviewed nft/sysctl artifacts).
set -euo pipefail

ROOT="${TRUSTEDGE_ROOT:-/opt/trustedge}"
ENV_FILE="${TRUSTEDGE_ENV:-/etc/trustedge.env}"
CONFIG="${TRUSTEDGE_CONFIG:-/etc/trustedge/gateway.json}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

if [[ ${#TRUSTEDGE_API_TOKEN} -lt 24 ]]; then
  echo "TRUSTEDGE_API_TOKEN must be ≥24 characters" >&2
  exit 1
fi

"$ROOT/.venv/bin/python" -m trustedge.hardware check --config "$CONFIG"
exec "$ROOT/.venv/bin/python" -m trustedge --config "$CONFIG"
