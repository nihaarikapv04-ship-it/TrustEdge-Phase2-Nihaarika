#!/bin/bash
echo "[laptop] Setting default route via firewall..."
ip route replace default via 172.20.0.2 2>/dev/null || true
echo "[laptop] Starting normal browsing traffic simulation..."
TARGETS=("http://172.21.0.10" "http://172.21.0.10/index.html" "http://172.21.0.10/about")
while true; do
    TARGET=${TARGETS[$RANDOM % ${#TARGETS[@]}]}
    curl -sk --max-time 5 "$TARGET" > /dev/null 2>&1
    DELAY=$((RANDOM % 6 + 5))
    sleep $DELAY
done
```

---

**`containers/iot-camera/Dockerfile`**
```
FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY traffic_gen.sh /traffic_gen.sh
RUN chmod +x /traffic_gen.sh
CMD ["/traffic_gen.sh"]