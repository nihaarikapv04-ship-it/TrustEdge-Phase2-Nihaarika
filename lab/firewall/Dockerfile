# Phase 2 gateway image for the local Docker Compose lab.
# Pi deployment remains native Python/systemd (see docs/PI_DEPLOYMENT.md).
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    libpcap0.8 \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/trustedge
COPY pyproject.toml README.md ./
COPY trustedge ./trustedge
RUN pip install --no-cache-dir .

COPY lab/firewall/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /var/lib/trustedge

ENV TRUSTEDGE_LAB_BIND=1 \
    TRUSTEDGE_BIND=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 8080
CMD ["/entrypoint.sh"]
