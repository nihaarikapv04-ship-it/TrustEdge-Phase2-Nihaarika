#!/usr/bin/env bash
# Enroll Phase 1 lab device IPs into the Phase 2 gateway (CAUTIOUS + expected destinations).
set -euo pipefail

BASE="${TRUSTEDGE_LAB_URL:-http://127.0.0.1:8080}"
TOKEN="${TRUSTEDGE_API_TOKEN:?set TRUSTEDGE_API_TOKEN}"
AUTH="Authorization: Bearer ${TOKEN}"
DEST='["172.21.0.10","172.21.0.11"]'

echo "[enroll] Waiting for ${BASE}/status ..."
for _ in $(seq 1 60); do
  if curl -sf -H "$AUTH" "$BASE/status" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf -H "$AUTH" "$BASE/status" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("ready=", d.get("ready"), "mode=", d.get("mode"))'

enroll() {
  local ip="$1" name="$2" dtype="$3"
  echo "[enroll] ${name} (${ip}, ${dtype})"
  code=$(curl -s -o /tmp/te-enroll.json -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"ip\":\"${ip}\",\"name\":\"${name}\",\"destinations\":${DEST},\"device_type\":\"${dtype}\"}" \
    "$BASE/devices" || true)
  if [[ "$code" == "201" ]]; then
    echo "  registered"
  elif [[ "$code" == "400" ]] && grep -q 'already registered' /tmp/te-enroll.json 2>/dev/null; then
    echo "  already present"
  else
    echo "  failed HTTP ${code}: $(cat /tmp/te-enroll.json 2>/dev/null || true)" >&2
    exit 1
  fi
}

enroll 172.20.0.10 "Studio laptop" laptop
enroll 172.20.0.11 "Living room camera" iot-camera
enroll 172.20.0.12 "Hallway thermostat" iot-thermo
enroll 172.20.0.13 "Guest phone" smartphone
enroll 172.20.0.14 "Office printer" printer

echo "[enroll] Current status:"
curl -sf -H "$AUTH" "$BASE/status" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("ready=", d.get("ready"), "mode=", d.get("mode"), "capture=", d.get("capture"))
for x in d.get("devices", []):
    print(" ", x["ip"], x["name"], x["desired_tier"]+"/"+x["applied_tier"], "trust="+str(x["trust"]))
'
