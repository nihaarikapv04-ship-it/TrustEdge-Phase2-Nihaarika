#!/bin/bash
set -euo pipefail
GW="${TRUSTEDGE_GATEWAY_IP:-172.20.0.2}"
SINK="${TRUSTEDGE_SINK_IP:-172.21.0.11}"
# shellcheck source=/dev/null
source /ensure_gateway.sh
echo "[iot-camera] Starting periodic upload simulation..."
while true; do
    if [ -f /tmp/trustedge_pause ]; then
        sleep 1
        continue
    fi
    python3 -c "import os; open('/tmp/payload.bin','wb').write(os.urandom(51200))"
    curl -sk --max-time 10 -X POST "http://${SINK}/upload" \
         -H "Content-Type: application/octet-stream" \
         --data-binary @/tmp/payload.bin > /dev/null 2>&1 || true
    sleep 10
done
