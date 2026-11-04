#!/bin/bash
echo "[phone] Setting default route via firewall..."
ip route replace default via 172.20.0.2 2>/dev/null || true
echo "[phone] Starting burst traffic simulation..."
while true; do
    BURST=$((RANDOM % 3 + 3))
    for i in $(seq 1 $BURST); do
        curl -sk --max-time 5 "http://172.21.0.10" > /dev/null 2>&1
        sleep 1
    done
    IDLE=$((RANDOM % 10 + 8))
    sleep $IDLE
done
```

---

**`containers/printer/Dockerfile`**
```
FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY traffic_gen.sh /traffic_gen.sh
RUN chmod +x /traffic_gen.sh
CMD ["/traffic_gen.sh"]