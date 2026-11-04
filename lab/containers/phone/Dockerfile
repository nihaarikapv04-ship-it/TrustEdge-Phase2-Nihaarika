FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl iproute2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY traffic_gen.sh /traffic_gen.sh
RUN chmod +x /traffic_gen.sh
CMD ["/traffic_gen.sh"]