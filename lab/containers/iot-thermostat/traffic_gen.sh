#!/bin/bash
set -euo pipefail
GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
SINK="${TRUSTEDGE_SINK_IP:-172.21.0.11}"
# shellcheck source=/dev/null
source /ensure_gateway.sh
echo "[iot-thermostat] Starting telemetry simulation (window-filling cadence)..."
while true; do
    if [ -f /tmp/trustedge_pause ]; then
        sleep 1
        continue
    fi
    TEMP=$((RANDOM % 10 + 20))
    HUMIDITY=$((RANDOM % 20 + 40))
    curl -sk --max-time 5 -X POST "http://${SINK}/telemetry" \
         -H "Content-Type: application/json" \
         -d "{\"temp\": $TEMP, \"humidity\": $HUMIDITY, \"device\": \"thermostat-01\"}" \
         > /dev/null 2>&1 || true
    curl -sk --max-time 5 -X POST "http://${SINK}/telemetry" \
         -H "Content-Type: application/json" \
         -d "{\"temp\": $TEMP, \"humidity\": $HUMIDITY, \"device\": \"thermostat-01\"}" \
         > /dev/null 2>&1 || true
    sleep 2
done
