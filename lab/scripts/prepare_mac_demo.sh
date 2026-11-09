#!/usr/bin/env bash
# Prepare the local Docker lab for a ~50-minute baseline learning demonstration.
# Does NOT delete volumes, databases, or trained models.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/lab"
cd "$LAB"

if [[ ! -f .env ]]; then
  echo "Missing lab/.env — copy from deployment docs / existing secrets first." >&2
  exit 1
fi

# Ensure 60s windows for a ~50 minute × 50-window demo (Pi-like cadence).
if grep -q '^TRUSTEDGE_WINDOW_SECONDS=' .env; then
  sed -i.bak 's/^TRUSTEDGE_WINDOW_SECONDS=.*/TRUSTEDGE_WINDOW_SECONDS=60/' .env
else
  printf '\nTRUSTEDGE_WINDOW_SECONDS=60\n' >> .env
fi
echo "[demo] TRUSTEDGE_WINDOW_SECONDS=60 (approx 50 minutes for 50 valid windows)"

echo "[demo] Volume preservation: using existing named volume lab-db (compose up without -v)."
docker volume inspect lab_lab-db >/dev/null 2>&1 && echo "[demo] lab_lab-db present" || echo "[demo] lab_lab-db will be created on first up"

echo "[demo] Starting lab (no volume wipe)…"
docker compose -f docker-compose.yml up -d

echo "[demo] Waiting for firewall health…"
for _ in $(seq 1 60); do
  st=$(docker inspect -f '{{.State.Health.Status}}' trustedge-lab-firewall 2>/dev/null || echo missing)
  [[ "$st" == healthy ]] && break
  sleep 2
done
docker inspect -f 'firewall={{.State.Health.Status}}' trustedge-lab-firewall

set -a
# shellcheck disable=SC1091
source .env
set +a
export TRUSTEDGE_LAB_URL="${TRUSTEDGE_LAB_URL:-http://127.0.0.1:8080}"

echo "[demo] Enrolling five lab devices (idempotent)…"
bash scripts/enroll_lab_devices.sh

echo "[demo] Checking device traffic generators are running…"
for c in trustedge-lab-laptop trustedge-lab-iot-camera trustedge-lab-iot-thermostat trustedge-lab-phone trustedge-lab-printer; do
  docker inspect -f "$c={{.State.Status}}" "$c"
done

echo
echo "Dashboard:  $TRUSTEDGE_LAB_URL/"
echo "Login:      use the operator (or admin) credentials from lab/.env — do not commit or paste them."
echo "Learning:   Overview → Baseline Learning card (auto-refreshes ~15s)."
echo "Attacks:    unlocked only when status is COMPLETE (5/5 lab devices at 50/50)."
echo
echo "Explicit fresh rebaseline (destroys learned models for that device only):"
echo "  POST /p1/devices/<ip>/rebaseline  (operator JWT) — do this only if you intentionally want a new 50-window run."
echo "Never run: docker compose down -v"
echo "[demo] Ready."
