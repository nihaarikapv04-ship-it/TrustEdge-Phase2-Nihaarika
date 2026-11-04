#!/bin/bash
set -euo pipefail
GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
WEB="${TRUSTEDGE_WEBSERVER_IP:-172.21.0.10}"
# shellcheck source=/dev/null
source /ensure_gateway.sh
echo "[phone] Starting burst traffic simulation..."
while true; do
    if [ -f /tmp/trustedge_pause ]; then
        sleep 1
        continue
    fi
    BURST=$((RANDOM % 3 + 3))
    for i in $(seq 1 $BURST); do
        curl -sk --max-time 5 "http://${WEB}" > /dev/null 2>&1 || true
        sleep 1
    done
    IDLE=$((RANDOM % 10 + 8))
    sleep $IDLE
done
