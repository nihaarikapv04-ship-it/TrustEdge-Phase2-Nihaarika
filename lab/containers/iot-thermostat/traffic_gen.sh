#!/bin/bash
echo "[iot-thermostat] Setting default route via firewall..."
ip route replace default via 172.20.0.2 2>/dev/null || true
echo "[iot-thermostat] Starting telemetry simulation..."
while true; do
    TEMP=$((RANDOM % 10 + 20))
    HUMIDITY=$((RANDOM % 20 + 40))
    curl -sk --max-time 5 -X POST http://172.21.0.11/telemetry \
         -H "Content-Type: application/json" \
         -d "{\"temp\": $TEMP, \"humidity\": $HUMIDITY, \"device\": \"thermostat-01\"}" \
         > /dev/null 2>&1
    sleep 30
done
```

---

**`containers/phone/Dockerfile`**
```
FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY traffic_gen.sh /traffic_gen.sh
RUN chmod +x /traffic_gen.sh
CMD ["/traffic_gen.sh"]