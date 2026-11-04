#!/bin/bash
echo "[printer] Setting default route via firewall..."
ip route replace default via 172.20.0.2 2>/dev/null || true
echo "[printer] Starting low-activity simulation..."
while true; do
    curl -sk --max-time 5 "http://172.21.0.11/ping" > /dev/null 2>&1
    sleep 300
done