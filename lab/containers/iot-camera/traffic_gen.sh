#!/bin/bash
echo "[iot-camera] Setting default route via firewall..."
ip route replace default via 172.20.0.2 2>/dev/null || true
echo "[iot-camera] Starting periodic upload simulation..."
while true; do
    python3 -c "import os; open('/tmp/payload.bin','wb').write(os.urandom(51200))"
    curl -sk --max-time 10 -X POST http://172.21.0.11/upload \
         -H "Content-Type: application/octet-stream" \
         --data-binary @/tmp/payload.bin > /dev/null 2>&1
    sleep 10
done
```

---

**`containers/iot-thermostat/Dockerfile`**
```
FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY traffic_gen.sh /traffic_gen.sh
RUN chmod +x /traffic_gen.sh
CMD ["/traffic_gen.sh"]