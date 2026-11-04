#!/bin/bash
set -euo pipefail
GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
WEB="${TRUSTEDGE_WEBSERVER_IP:-172.21.0.10}"
# shellcheck source=/dev/null
source /ensure_gateway.sh
echo "[laptop] Starting normal browsing traffic simulation..."
TARGETS=("http://${WEB}" "http://${WEB}/index.html" "http://${WEB}/about")
while true; do
    TARGET=${TARGETS[$RANDOM % ${#TARGETS[@]}]}
    curl -sk --max-time 5 "$TARGET" > /dev/null 2>&1 || true
    DELAY=$((RANDOM % 6 + 5))
    sleep $DELAY
done
