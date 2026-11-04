#!/usr/bin/env bash
# Post-install validation on the Pi (read-only checks + local API probe).
# Optionally runs host_preflight.sh for DOCKER-USER / forwarding / nft / NAT / bridges.
set -euo pipefail
ENV_FILE="${TRUSTEDGE_ENV:-/etc/trustedge.env}"
CONFIG="${TRUSTEDGE_CONFIG:-/etc/trustedge/gateway.json}"
ROOT="${TRUSTEDGE_ROOT:-/opt/trustedge}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE=prod
RUN_HOST=1

for arg in "$@"; do
  case "$arg" in
    --lab) MODE=lab ;;
    --prod) MODE=prod ;;
    --skip-host) RUN_HOST=0 ;;
    -h|--help)
      echo "Usage: validate.sh [--prod|--lab] [--skip-host]"
      exit 0
      ;;
  esac
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

if [[ "$RUN_HOST" -eq 1 && -x "$SCRIPT_DIR/host_preflight.sh" ]]; then
  echo "== host preflight ($MODE) =="
  "$SCRIPT_DIR/host_preflight.sh" "--$MODE" || true
  echo
fi

echo "== hardware preflight =="
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  "$ROOT/.venv/bin/python" -m trustedge.hardware check --config "$CONFIG"
else
  echo "WARN: $ROOT/.venv missing — skip hardware check" >&2
fi

echo "== service =="
systemctl is-active trustedge.service
systemctl is-active trustedge-network.service || true
systemctl is-active nftables.service || true
systemctl is-active dnsmasq.service || true

echo "== nft tables =="
nft list table inet trustedge >/dev/null
nft list table ip trustedge_nat >/dev/null || true
if nft list table ip trustedge_nat 2>/dev/null | grep -q masquerade; then
  echo "NAT masquerade: present"
else
  echo "WARN: masquerade not visible in trustedge_nat" >&2
fi

echo "== IP forwarding =="
echo "net.ipv4.ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"

echo "== database =="
DB="${TRUSTEDGE_DATABASE:-/var/lib/trustedge/gateway.sqlite}"
if [[ -f "$DB" ]]; then
  ls -la "$DB"
else
  echo "WARN: database file not found at $DB (fresh install OK)" >&2
  ls -la /var/lib/trustedge 2>/dev/null || true
fi

echo "== API (loopback) =="
code=$(curl -s -o /tmp/te_status.json -w '%{http_code}' \
  -H "Authorization: Bearer ${TRUSTEDGE_API_TOKEN}" \
  "http://127.0.0.1:${TRUSTEDGE_API_PORT:-8080}/status" || true)
echo "HTTP $code"
test "$code" = "200"
python3 -c 'import json; d=json.load(open("/tmp/te_status.json")); assert d.get("ready") is True, d; print("ready", d["ready"], "devices", len(d.get("devices") or []))'

echo "Validation OK"
