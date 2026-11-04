#!/bin/bash
set -euo pipefail
GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
SINK="${TRUSTEDGE_SINK_IP:-172.21.0.11}"
WEB="${TRUSTEDGE_WEBSERVER_IP:-172.21.0.10}"
# shellcheck source=/dev/null
source /ensure_gateway.sh
echo "[printer] Starting activity simulation (window-filling cadence)..."
while true; do
    if [ -f /tmp/trustedge_pause ]; then
        sleep 1
        continue
    fi
    curl -sk --max-time 5 "http://${SINK}/ping" > /dev/null 2>&1 || true
    curl -sk --max-time 5 "http://${WEB}/" > /dev/null 2>&1 || true
    sleep 2
done
